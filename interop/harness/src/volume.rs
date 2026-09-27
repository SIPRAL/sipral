// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A hundred calls through a real proxy and PBX at once, rather than one
//! call between two stacks this file also runs.
//!
//! Every other flow in this table proves one call is right. Kamailio
//! forwards each one it is given without holding it up — `crate::fork`'s
//! own module doc says what it does hold up, and it is a different user —
//! so nothing here proves the proxy scales; it is Asterisk on the other end
//! that has to answer a hundred `Dial()`s into `Local/9002@lab`'s own tone
//! at once; a real PBX bridging a real channel a hundred times over,
//! against this end's own hundred RTP sessions run on one thread the way
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
//! many failed and why; Asterisk's own count of channels at the busiest
//! moment, read over its console the way `scripts/lab.sh`'s other steps
//! already do, is `scripts/lab.sh`'s own to print beside it — asking
//! Asterisk what it thinks it is carrying is worth more than this end
//! guessing from its own count of calls still up.

use std::env;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::{CallHandle, CallMedia, Event, MediaConfig, MediaEvent, OutgoingCall, UaEvent};

use crate::{Endpoint, catalog, place_call, run_folded, uri};

/// The tone extension every ordinary flow in this table dials
/// (`interop/asterisk/extensions.conf`), through the proxy.
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

struct Leg {
    call: Option<CallHandle>,
    placed_at: Option<Instant>,
    started: Option<Instant>,
    ended: bool,
    failure: Option<String>,
}

impl Leg {
    const fn new() -> Self {
        Self {
            call: None,
            placed_at: None,
            started: None,
            ended: false,
            failure: None,
        }
    }
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
                Event::Signalling(UaEvent::CallEnded {
                    call,
                    reason,
                    status,
                    ..
                }) => {
                    if let Some(leg) = legs.iter_mut().find(|leg| leg.call == Some(call)) {
                        leg.ended = true;
                        if hung_up.is_none() && leg.failure.is_none() {
                            leg.failure = Some(format!(
                                "ended before it was told to: {reason:?}{}",
                                status
                                    .map(|status| format!(" ({status})"))
                                    .unwrap_or_default()
                            ));
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
                        leg.failure.get_or_insert_with(|| "the stream stalled".to_owned());
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
        if next_place >= count && registered && legs.iter().all(|leg| leg.call.is_some() || leg.failure.is_some()) && now > began + PATIENCE {
            // every leg that was ever going to start has had its chance
            for leg in &mut legs {
                if leg.call.is_some() && leg.started.is_none() && leg.failure.is_none() {
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
            let every_leg_settled = legs
                .iter()
                .all(|leg| leg.started.is_some() || leg.failure.is_some());
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
#[allow(clippy::cast_precision_loss, clippy::cast_sign_loss, clippy::cast_possible_truncation)]
fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let last = sorted.len() - 1;
    let rank = (last as f64 * p / 100.0).round() as usize;
    sorted.get(rank.min(last)).copied().unwrap_or_default()
}

fn verdict(legs: &[Leg]) -> Result<String, String> {
    let mut setups: Vec<Duration> = legs
        .iter()
        .filter_map(|leg| Some(leg.started?.saturating_duration_since(leg.placed_at?)))
        .collect();
    setups.sort();
    let failed: Vec<&str> = legs
        .iter()
        .filter_map(|leg| leg.failure.as_deref())
        .collect();
    let said = format!(
        "   ({} of {} up; setup min {:.0} ms, p50 {:.0} ms, p90 {:.0} ms, max {:.0} ms)",
        setups.len(),
        legs.len(),
        percentile(&setups, 0.0).as_secs_f64() * 1e3,
        percentile(&setups, 50.0).as_secs_f64() * 1e3,
        percentile(&setups, 90.0).as_secs_f64() * 1e3,
        percentile(&setups, 100.0).as_secs_f64() * 1e3,
    );
    if failed.is_empty() {
        Ok(said)
    } else {
        Err(format!(
            "{} of {} failed: {}{said}",
            failed.len(),
            legs.len(),
            failed.first().unwrap_or(&"")
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::percentile;

    #[test]
    fn percentile_reads_off_the_sorted_list() {
        let sorted: Vec<Duration> = [10, 20, 30, 40].iter().map(|ms| Duration::from_millis(*ms)).collect();
        assert_eq!(percentile(&sorted, 0.0), Duration::from_millis(10));
        assert_eq!(percentile(&sorted, 100.0), Duration::from_millis(40));
    }
}
