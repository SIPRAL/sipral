// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A hundred calls through a real proxy and a real PBX at once, rather than
//! one call between two stacks this file also runs.
//!
//! Every other flow in this table proves one call is right. Two real
//! backends answer it: `server` "asterisk" places straight at Asterisk, no
//! proxy in front of it, the same reasoning `scripts/lab.sh asterisk` gives;
//! "kamailio" places at Kamailio instead, which this lab's own
//! `interop/kamailio/kamailio.cfg` forwards to FreeSWITCH and nowhere
//! else — there is no route from Kamailio to Asterisk in this lab, so "a
//! hundred calls through a real proxy and PBX" is two separate runs here,
//! not one, and `scripts/lab.sh volume` reports both. Either way it is a
//! real server bridging a real channel a hundred times over, against this
//! end's own hundred RTP sessions run on one thread the way
//! `crates/sipral-ffi`'s own load test runs two hundred, in-process, on
//! four. What this end costs doing it — its own process's CPU and peak
//! memory — is read from outside this binary, by `scripts/lab.sh`'s own
//! `/usr/bin/time -v` around it, because nothing in this crate counts its
//! own allocations the way `crates/sipral-ffi`'s load test's own allocator
//! does; the number that comes back is this process's, signalling and media
//! together, not `sipral`'s alone.
//!
//! Placed a `SIPRAL_VOLUME_STAGGER_MS` apart, the way a dialler places them
//! rather than a flood — [`STAGGER`] unless told otherwise — held on the
//! tone for `SIPRAL_VOLUME_HOLD_MS` once every call that came up has started
//! its media, then hung up together. What is reported is how many came up,
//! how long each took from being placed to its own first frame, and how
//! many failed and why; the far end's own count of channels at the busiest
//! moment, read over its console the way `scripts/lab.sh`'s other steps
//! already do, is `scripts/lab.sh`'s own to print beside it — asking the
//! server what it thinks it is carrying is worth more than this end
//! guessing from its own count of calls still up.

use std::env;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::{
    CallEndReason, CallHandle, CallMedia, Event, MediaConfig, MediaEvent, OutgoingCall, StatusCode,
    UaEvent,
};

use crate::{Endpoint, catalog, place_call, run_folded, uri};

/// The tone extension every ordinary flow in this table dials — Asterisk's
/// own `interop/asterisk/extensions.conf`, or FreeSWITCH's
/// `interop/freeswitch/lab.xml`, whichever `server` is reached.
const EXTENSION: &str = "9000";

/// This flow's own endpoint identity. Listed in `main.rs`'s
/// `tests::endpoint_identity_constants_are_distinct`.
pub(crate) const SEED: u8 = 248;
pub(crate) const MEDIA_SEED: u8 = 250;

/// How long a call is given to come up and start its media before it counts
/// as a failure of its own.
const PATIENCE: Duration = Duration::from_secs(30);

/// How long the hangups are waited for.
const ENDING: Duration = Duration::from_secs(15);

/// The default gap between two calls being placed.
const STAGGER: Duration = Duration::from_millis(50);

fn sized(name: &str, fallback: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|text| text.parse().ok())
        .filter(|count| *count > 0)
        .unwrap_or(fallback)
}

#[allow(clippy::struct_excessive_bools)]
struct Leg {
    call: Option<CallHandle>,
    placed_at: Option<Instant>,
    started: Option<Instant>,
    /// A 2xx arrived: the far end answered this call, rather than only
    /// promising early media in a provisional response.
    confirmed: bool,
    /// The far end refused this call before answering it with a `5xx` to the
    /// INVITE (see [`is_load_refusal`]). Seen when a server sheds load harder
    /// than leaving the call in early media: at a `50 ms` stagger FreeSWITCH
    /// answers 500 rather than ring. Counted apart, not as this end ending a
    /// live call.
    refused: bool,
    /// The stall watchdog fired before the far end answered and nothing has
    /// arrived since. The watchdog fires once per silence, so a call answered
    /// while still silent gets no second event; [`Leg::why_failed`] judges it.
    silent: bool,
    ended: bool,
    failure: Option<String>,
}

impl Leg {
    const fn new() -> Self {
        Self {
            call: None,
            placed_at: None,
            started: None,
            confirmed: false,
            refused: false,
            silent: false,
            ended: false,
            failure: None,
        }
    }

    /// Why this leg failed, if it did. Besides a failure recorded as it
    /// happened, a call the far end answered while the stream it promised
    /// in early media was still silent, and that stayed silent to the end,
    /// stalled as surely as one that went quiet after the answer.
    fn why_failed(&self) -> Option<&str> {
        self.failure
            .as_deref()
            .or_else(|| (self.confirmed && self.silent).then_some("the stream stalled"))
    }

    /// This leg has had its chance and will not change state on its own: it
    /// started media, or failed, or the far end refused it. A leg that is not
    /// settled is one still expected to come up, which the hold waits for and
    /// which counts against the patience as one that never started its media.
    fn settled(&self) -> bool {
        self.started.is_some() || self.failure.is_some() || self.refused
    }

    /// Record a stall the watchdog reported.
    ///
    /// A stall on a call the far end answered is a real media defect: the
    /// stream carried audio and then stopped. A stall on a call that was
    /// never answered is a different thing — the far end sent a `183` that
    /// promised early media, opened a session for it, and then sent no RTP at
    /// all before this end gave up and cancelled. That is the far end
    /// declining to complete the call, seen most often when a server sheds
    /// load under a volume of calls placed faster than it will set them up;
    /// it is counted as unanswered, not as a stream that stalled, so the
    /// summary does not blame this end's media for the server's own throttle.
    fn note_stall(&mut self) {
        if self.confirmed {
            self.failure
                .get_or_insert_with(|| "the stream stalled".to_owned());
        } else {
            self.silent = true;
        }
    }

    /// Record that packets are arriving again after a stall.
    fn note_resumed(&mut self) {
        self.silent = false;
    }
}

/// Whether a call's end is the far end declining it under load: refused
/// before it was answered, with a `5xx`, the class RFC 3261 §21.5 gives a
/// server that has itself failed to carry out a valid request. A `4xx` says
/// the request itself was wrong (§21.4) — a `488` to this end's offer, say —
/// and a `6xx` that no server will take it (§21.6); neither is load, and
/// either still fails the run.
fn is_load_refusal(reason: CallEndReason, status: Option<StatusCode>) -> bool {
    reason == CallEndReason::Refused && status.is_some_and(|status| status.get() / 100 == 5)
}

/// Register once, place `SIPRAL_VOLUME_CALLS` calls to the tone extension
/// through the proxy, hold them together, hang up together, and report.
///
/// # Errors
/// The first condition that did not hold, the way every other flow here
/// reports; a leg's own failure is folded into the summary rather than
/// stopping the others; this only errs on something that makes the whole
/// run untrustworthy — registration itself failing, or nothing ever coming
/// up at all.
#[allow(clippy::too_many_lines)]
pub(crate) fn run(
    server: &str,
    remote: SocketAddr,
    user: &str,
    pass: &str,
) -> Result<String, String> {
    let count = usize::try_from(sized("SIPRAL_VOLUME_CALLS", 100)).unwrap_or(100);
    let stagger = Duration::from_millis(sized(
        "SIPRAL_VOLUME_STAGGER_MS",
        u64::try_from(STAGGER.as_millis()).unwrap_or(50),
    ));
    let hold = Duration::from_millis(sized("SIPRAL_VOLUME_HOLD_MS", 5_000));

    let bind_addr = SocketAddr::new(crate::route_to(remote), 0);
    let now = Instant::now();
    let mut endpoint = Endpoint::bind(
        run_folded([SEED; 32]),
        run_folded([MEDIA_SEED; 32]),
        bind_addr,
        catalog(),
        now,
    )
    .map_err(|error| format!("cannot bind: {error}"))?;
    let account = endpoint.account(user, pass, server, remote)?;
    let target = uri(&format!("sip:{EXTENSION}@{server}"))?;

    println!("  volume: {count} calls to {EXTENSION}, {stagger:?} apart, held {hold:?}");

    let _ = endpoint.agent.register(account, now);
    let mut registered = false;
    let mut legs: Vec<Leg> = (0..count).map(|_| Leg::new()).collect();
    let mut next_place = 0_usize;
    let mut next_place_at = now;
    let began = Instant::now();
    let mut all_started_at: Option<Instant> = None;
    let mut hung_up: Option<Instant> = None;

    loop {
        let now = Instant::now();
        for event in endpoint.pump(now) {
            match event {
                Event::Signalling(UaEvent::Registered { .. }) => registered = true,
                Event::Signalling(UaEvent::CallConfirmed { call, .. }) => {
                    if let Some(leg) = legs.iter_mut().find(|leg| leg.call == Some(call)) {
                        leg.confirmed = true;
                    }
                }
                Event::Signalling(UaEvent::CallEnded {
                    call,
                    reason,
                    status,
                    ..
                }) => {
                    if let Some(leg) = legs.iter_mut().find(|leg| leg.call == Some(call)) {
                        leg.ended = true;
                        if hung_up.is_none() && leg.failure.is_none() {
                            if !leg.confirmed && is_load_refusal(reason, status) {
                                // the far end refused a call it had never
                                // answered, as a server that could not take
                                // it: a decline at setup, the harder edge of
                                // the same load-shedding that leaves other
                                // calls in early media — not this end dropping
                                // a call that was up.
                                leg.refused = true;
                            } else {
                                leg.failure = Some(format!(
                                    "ended before it was told to: {reason:?}{}",
                                    status
                                        .map(|status| format!(" ({status})"))
                                        .unwrap_or_default()
                                ));
                            }
                        }
                    }
                }
                Event::Media {
                    call,
                    event: MediaEvent::Started { .. },
                } => {
                    if let Some(leg) = legs.iter_mut().find(|leg| leg.call == Some(call)) {
                        leg.started = Some(now);
                    }
                }
                Event::Media {
                    call,
                    event: MediaEvent::Stalled { .. },
                } => {
                    if let Some(leg) = legs.iter_mut().find(|leg| leg.call == Some(call)) {
                        leg.note_stall();
                    }
                }
                Event::Media {
                    call,
                    event: MediaEvent::Resumed { .. },
                } => {
                    if let Some(leg) = legs.iter_mut().find(|leg| leg.call == Some(call)) {
                        leg.note_resumed();
                    }
                }
                _ => {}
            }
        }

        if registered
            && now >= next_place_at
            && let Some(leg) = legs.get_mut(next_place)
        {
            let media = CallMedia::new(catalog(), MediaConfig::default());
            let outgoing = OutgoingCall::new(target.clone()).to_address(endpoint.transport, remote);
            match place_call(&mut endpoint, account, outgoing, media, remote, now) {
                Ok(handle) => {
                    leg.call = Some(handle);
                    leg.placed_at = Some(now);
                }
                Err(why) => leg.failure = Some(format!("not placed: {why}")),
            }
            next_place += 1;
            next_place_at = now + stagger;
        }
        if next_place >= count
            && registered
            && legs
                .iter()
                .all(|leg| leg.call.is_some() || leg.failure.is_some())
            && now > began + PATIENCE
        {
            // every leg that was ever going to start has had its chance — bar
            // one the far end refused before it could, which is the far end's
            // own answer and already accounted for, not a call whose media
            // never came up.
            for leg in &mut legs {
                if leg.call.is_some() && !leg.settled() {
                    leg.failure = Some("never started media".to_owned());
                }
            }
        }
        if !registered && now > began + PATIENCE {
            return Err("never registered".to_owned());
        }

        endpoint.run_media(now);
        endpoint.timers(now);

        if hung_up.is_none() {
            // A refused leg has had its answer from the far end and will never
            // start media; it counts as settled so the hold begins once every
            // other leg has, rather than waiting the full patience out for a
            // call that is already over.
            let every_leg_settled = legs.iter().all(Leg::settled);
            if every_leg_settled && all_started_at.is_none() {
                all_started_at = Some(now);
            }
            if let Some(since) = all_started_at
                && now >= since + hold
            {
                for leg in &legs {
                    if let Some(call) = leg.call {
                        let _ = endpoint.agent.hangup(call, now);
                    }
                }
                hung_up = Some(now);
            }
        }

        if let Some(at) = hung_up
            && (legs.iter().all(|leg| leg.ended || leg.call.is_none()) || now > at + ENDING)
        {
            break;
        }
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    let _ = endpoint.agent.unregister(account, Instant::now());
    verdict(&legs)
}

/// `p` in `[0, 100]` of a sorted list.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let last = sorted.len() - 1;
    let rank = (last as f64 * p / 100.0).round() as usize;
    sorted.get(rank.min(last)).copied().unwrap_or_default()
}

fn verdict(legs: &[Leg]) -> Result<String, String> {
    use std::fmt::Write as _;
    // The setup time is measured over answered calls: for a call the far end
    // only ever promised early media on and never answered, "how long to its
    // first frame" is a question about a frame that never came.
    let mut setups: Vec<Duration> = legs
        .iter()
        .filter(|leg| leg.confirmed)
        .filter_map(|leg| Some(leg.started?.saturating_duration_since(leg.placed_at?)))
        .collect();
    setups.sort();
    let answered = legs.iter().filter(|leg| leg.confirmed).count();
    // Placed, reached early media, but never answered and never a real failure
    // of its own: the far end left it in a provisional response and sent no
    // RTP, then this end cancelled it. See [`Leg::note_stall`].
    let in_early_media = legs
        .iter()
        .filter(|leg| !leg.confirmed && !leg.refused && leg.why_failed().is_none())
        .count();
    // Refused at setup, the harder edge of the same load-shedding.
    let refused = legs.iter().filter(|leg| leg.refused).count();
    let failed: Vec<&str> = legs.iter().filter_map(Leg::why_failed).collect();
    let mut left = String::new();
    if in_early_media > 0 {
        let _ = write!(
            left,
            "; {in_early_media} the far end left in early media, never answered"
        );
    }
    if refused > 0 {
        let _ = write!(left, "; {refused} the far end refused under load");
    }
    let said = format!(
        "   ({answered} of {} answered{left}; setup min {:.0} ms, p50 {:.0} ms, p90 {:.0} ms, max {:.0} ms)",
        legs.len(),
        percentile(&setups, 0.0).as_secs_f64() * 1e3,
        percentile(&setups, 50.0).as_secs_f64() * 1e3,
        percentile(&setups, 90.0).as_secs_f64() * 1e3,
        percentile(&setups, 100.0).as_secs_f64() * 1e3,
    );
    if !failed.is_empty() {
        Err(format!(
            "{} of {} failed: {}{said}",
            failed.len(),
            legs.len(),
            failed.first().unwrap_or(&"")
        ))
    } else if answered == 0 {
        // Nothing answered at all is the run itself being untrustworthy, the
        // way this flow's own doc says it errs; a shortfall the far end
        // explains by shedding load is not.
        Err(format!("nothing answered{said}"))
    } else {
        Ok(said)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use sipral::{CallEndReason, StatusCode};

    use super::{Leg, is_load_refusal, percentile, verdict};

    #[test]
    fn percentile_reads_off_the_sorted_list() {
        let sorted: Vec<Duration> = [10, 20, 30, 40]
            .iter()
            .map(|ms| Duration::from_millis(*ms))
            .collect();
        assert_eq!(percentile(&sorted, 0.0), Duration::from_millis(10));
        assert_eq!(percentile(&sorted, 100.0), Duration::from_millis(40));
    }

    fn answered() -> Leg {
        let now = Instant::now();
        let mut leg = Leg::new();
        leg.placed_at = Some(now);
        leg.started = Some(now + Duration::from_millis(11));
        leg.confirmed = true;
        leg
    }

    /// A call the far end only ever gave a `183` for, opened an early-media
    /// session for, and then never answered: the state the throttled calls in
    /// `scripts/lab.sh volume` are left in.
    fn early_media_only() -> Leg {
        let now = Instant::now();
        let mut leg = Leg::new();
        leg.placed_at = Some(now);
        leg.started = Some(now + Duration::from_millis(11));
        leg
    }

    #[test]
    fn a_stall_on_an_answered_call_is_a_failure() {
        let mut leg = answered();
        leg.note_stall();
        assert_eq!(leg.failure.as_deref(), Some("the stream stalled"));
    }

    #[test]
    fn a_stall_on_a_call_never_answered_is_not_a_failure() {
        // The far end promised early media and sent none; the watchdog fires,
        // but this is the far end declining the call, not this end's media
        // stalling. Without this distinction the whole run fails whenever a
        // server sheds load under the volume.
        let mut leg = early_media_only();
        leg.note_stall();
        assert_eq!(leg.failure, None);
    }

    #[test]
    fn calls_the_far_end_never_answered_do_not_fail_the_run() {
        let mut legs: Vec<Leg> = (0..97).map(|_| answered()).collect();
        for _ in 0..3 {
            let mut leg = early_media_only();
            leg.note_stall();
            legs.push(leg);
        }
        let said = verdict(&legs).expect("a shortfall the far end explains must not fail the run");
        assert!(said.contains("97 of 100 answered"), "{said}");
        assert!(said.contains("3 the far end left in early media"), "{said}");
    }

    #[test]
    fn a_refused_leg_is_settled_and_never_counted_as_not_started() {
        // The loop waits on unsettled legs to come up and, past its patience,
        // fails one still not started as "never started media". A refused leg
        // has had the far end's answer and will never start, so it must count
        // as settled — otherwise the run stalls the whole patience out and
        // then blames the far end's refusal on this end's media.
        let mut leg = early_media_only();
        leg.started = None;
        assert!(!leg.settled());
        leg.refused = true;
        assert!(leg.settled());
    }

    #[test]
    fn calls_the_far_end_refused_at_setup_do_not_fail_the_run() {
        // At a 50 ms stagger FreeSWITCH answers 500 rather than ring; a call
        // refused before it was ever answered is the server declining under the
        // offered rate, not this end ending a call that was up.
        let mut legs: Vec<Leg> = (0..52).map(|_| answered()).collect();
        for _ in 0..48 {
            let mut leg = early_media_only();
            leg.refused = true;
            legs.push(leg);
        }
        let said = verdict(&legs).expect("refusals under load must not fail the run");
        assert!(said.contains("52 of 100 answered"), "{said}");
        assert!(said.contains("48 the far end refused under load"), "{said}");
    }

    #[test]
    fn a_real_stall_after_answer_still_fails() {
        let mut legs: Vec<Leg> = (0..99).map(|_| answered()).collect();
        let mut broken = answered();
        broken.note_stall();
        legs.push(broken);
        let why = verdict(&legs).expect_err("a stall after answer is a real defect");
        assert!(why.contains("the stream stalled"), "{why}");
    }

    #[test]
    fn a_call_answered_into_the_silence_of_its_early_media_still_fails() {
        // The watchdog fires once per silence: a stall in early media is not
        // raised again when the far end then answers, so an answered call
        // that never carries a packet would pass unless the earlier stall
        // is remembered.
        let mut legs: Vec<Leg> = (0..99).map(|_| answered()).collect();
        let mut silent = early_media_only();
        silent.note_stall();
        silent.confirmed = true;
        legs.push(silent);
        let why = verdict(&legs).expect_err("an answered call that never carried audio stalled");
        assert!(why.contains("the stream stalled"), "{why}");
    }

    #[test]
    fn a_call_answered_after_its_early_media_stalled_passes_once_audio_comes() {
        let mut leg = early_media_only();
        leg.note_stall();
        leg.confirmed = true;
        leg.note_resumed();
        assert_eq!(leg.why_failed(), None);
    }

    #[test]
    fn only_a_server_failure_counts_as_refused_under_load() {
        let status = |code| StatusCode::new(code).ok();
        assert!(is_load_refusal(CallEndReason::Refused, status(500)));
        assert!(is_load_refusal(CallEndReason::Refused, status(503)));
        // this end's offer or request was wrong, or nowhere takes the call:
        // those are not load and must still fail the run
        assert!(!is_load_refusal(CallEndReason::Refused, status(488)));
        assert!(!is_load_refusal(CallEndReason::Refused, status(403)));
        assert!(!is_load_refusal(CallEndReason::Refused, status(603)));
        assert!(!is_load_refusal(CallEndReason::Refused, None));
        assert!(!is_load_refusal(CallEndReason::Unreachable, status(503)));
    }

    #[test]
    fn nothing_answered_is_untrustworthy() {
        let legs: Vec<Leg> = (0..100).map(|_| early_media_only()).collect();
        assert!(verdict(&legs).is_err());
    }
}
