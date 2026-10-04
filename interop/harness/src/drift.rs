// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! An hour on one call, and what the jitter buffer did to keep two clocks
//! together for all of it.
//!
//! Every other flow in this table lasts seconds, and a clock that is a few
//! hundred parts per million off does nothing in seconds: at 250 ppm a call
//! is one frame out after eighty seconds and forty-five frames out after an
//! hour. What absorbs that in a call is the de-jitter buffer
//! (`docs/05-media.md`): it drops a frame in a pause when audio piles up and
//! invents one in a pause when it runs short, and it counts both. So this
//! holds calls up for an hour — `SIPRAL_DRIFT_MS`, sixty minutes unless it
//! says otherwise — and prints, every `SIPRAL_DRIFT_REPORT_MS`, what the
//! buffer has done and how deep it is.
//!
//! # A skew of a known size
//!
//! Both ends of a call in this lab run on one host, and read one clock, so a
//! call here drifts by nothing at all. What is measured against nothing
//! proves nothing, so the drift is made: six calls to Asterisk's echo
//! extension (9008, which sends back exactly what it is sent, as it arrives)
//! run at once, identical except for the earpiece. One plays on a clock
//! `SIPRAL_DRIFT_PPM` fast, one on a clock that much slow, and one on the
//! true clock the microphone and the network run on
//! (`crate::audio::Media::skew_playout`), and each of the three twice: once
//! taking one frame at each device callback, and once taking two at a time,
//! as a 40 ms device period on 20 ms packets does
//! (`crate::audio::Media::earpiece_frames`), whose second pull of each pair
//! is the one that finds the queue short. The echo comes back at the pace it
//! was sent, which is the far end's clock as far as the receiving buffer can
//! tell, so each call's buffer faces exactly the skew its earpiece was
//! given, and the two with none are the controls.
//!
//! What the buffer did is then turned back into a skew and set beside the
//! one it was given: every frame the earpiece played that did not arrive is
//! one it invented — stretched in a pause, concealed, or played as silence
//! because the buffer had run dry — and every frame that arrived and was not
//! played was dropped in a pause, discarded late, or is still sitting in the
//! buffer. Over the frames played, that balance is the ratio between the two
//! clocks, in parts per million. Which of those ways it took is printed
//! beside it, since the ear hears them differently: a frame stretched into a
//! pause is inaudible, and a buffer that runs dry plays a frame of silence
//! wherever it happens to be, a word included.
//!
//! # What fails it
//!
//! Whatever the skew: a call that ended before the hour was up, one the
//! stack reported stalled, and a report in which a call played fewer than
//! half the audible frames its tone should have given it, which is audio
//! that stopped. A call whose measured skew at the end is further than
//! [`TOLERANCE`] from the one it was given, the controls included: a count
//! that does not add up is a frame going somewhere nothing here can see. And
//! a report in which the frames the earpiece played as silence and the
//! frames the stack counted for it differ by more than the run of silence
//! that can be in progress when a report falls: every frame the listener
//! lost that way is one the application must be able to read. The stack
//! counts it one of two ways -- an under-run (`Quality::underruns`, the C
//! ABI's `frames_underrun`), the earpiece asking before the next packet
//! arrived, or a packet lost on the way with nothing behind it to conceal
//! it from (`Quality::silenced`), which only a lossy link gives.
//!
//! Up to [`ABSORBED_PPM`], a skew any device runs at with room over, the
//! buffer has to absorb the drift where nobody hears it: a report in which a
//! call's buffer held more than [`MAX_DELAY`] fails — a buffer that grows
//! without bound passes that within minutes — and so does a call whose
//! buffer ran dry in the middle of the tone, however well its count
//! balances, since that is the drift absorbed as a gap the ear hears.
//!
//! Past it the skew is no device's clock but a stream played at the wrong
//! rate, which no buffer absorbs inaudibly: the fast earpiece runs dry and
//! the slow one piles up. There the flow asks that the call degrade the way
//! the product says it does (`docs/05-media.md`) rather than that it not
//! degrade. Bounded: no buffer deeper than its own ring, [`RING`], and none
//! deeper than [`MAX_DELAY`] without the stack's own score for the call
//! falling under half. Reported: every frame run dry counted, as above, and
//! a call that ran dry on a twentieth of its frames or more said to be
//! suffering by the stack at some report. The tone may be cut; how often is
//! printed.

use std::env;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::{
    AccountId, CallHandle, CallMedia, Event, MediaConfig, MediaEvent, OutgoingCall, Quality,
    UNAVAILABLE, UaEvent,
};

use crate::audio::{Heard, Media};
use crate::{Endpoint, catalog, place_call, quality, run_folded, uri};

/// `interop/asterisk/extensions.conf`'s echo: `Answer(); Echo();`.
const ECHO_EXTENSION: &str = "9008";

/// How long the calls take to come up before that is a failure.
const PATIENCE: Duration = Duration::from_secs(30);

/// How long the hangups are waited for.
const ENDING: Duration = Duration::from_secs(10);

/// How long after audio starts the balance is first taken: long enough for
/// every buffer to have filled to its target and played from it.
const SETTLE: Duration = Duration::from_secs(10);

/// The deepest a buffer may be at any report of a skew a device runs at. A
/// lab link adds well under a frame of jitter, so a buffer at its target
/// sits at a few frames; one that is not correcting a 250 ppm skew passes
/// this in under twenty minutes.
const MAX_DELAY: Duration = Duration::from_millis(250);

/// The deepest a buffer may ever be: its own ring, the hundred packets
/// `sipral_rtp::BufferConfig::new` gives a call, and a frame. Past a skew any
/// device runs at, a slow earpiece's buffer fills to this and throws out
/// the oldest for overflow, which RFC 3611's discard rate and the stack's
/// score both see.
const RING: Duration = Duration::from_millis(2_020);

/// The widest skew the buffer is held to absorbing without a gap: twice the
/// widest a device's clock may be off by and meet its bus's specification
/// (USB 2.0 §7.1.11, ±0.25 % at full speed; ±500 ppm at high speed), and
/// hundreds of times what any clock measured for `docs/19-numbers.md` ran
/// at. The crate's own simulation of this flow runs dry nowhere up to
/// 10 000 ppm, either callback length.
const ABSORBED_PPM: u32 = 5_000;

/// The share of frames played as nothing at which the stack must have said
/// a call is suffering: `sipral::StreamStatistics::is_suffering`'s own five
/// per cent.
const SUFFERING: f64 = 0.05;

/// How far the skew any call measures at the end may be from the one it was
/// given, as a fraction of the run's skew. The measure counts whole frames,
/// so over an hour at 250 ppm one frame either way is two per cent of the
/// answer; the rest is the room a buffer has to be a frame or two from its
/// target when the call ends.
const TOLERANCE: f64 = 0.25;

/// A frame, at the pace every flow here sends at.
const FRAME: Duration = Duration::from_millis(20);

/// The share of frames the tone sounds in: 1200 ms on, 600 off
/// (`crate::audio`'s own cadence).
const AUDIBLE_SHARE: f64 = 1200.0 / 1800.0;

/// The frames each earpiece takes at a callback: one, and two at once.
const CALLBACKS: [u32; 2] = [1, 2];

/// This flow's own endpoint identity, folded with the run's own entropy
/// before anything binds with it (`run_folded`, `main.rs`). Listed in
/// `main.rs`'s `tests::endpoint_identity_constants_are_distinct` alongside
/// every other step's, so a value reused here or added later fails that
/// test rather than a live run.
pub(crate) const SEED: u8 = 239;
pub(crate) const MEDIA_SEED: u8 = 241;

fn millis_from(name: &str, fallback: u64) -> Duration {
    Duration::from_millis(
        env::var(name)
            .ok()
            .and_then(|text| text.parse().ok())
            .unwrap_or(fallback),
    )
}

/// One call, the skew its earpiece runs at, and what it looked like at the
/// last report.
struct Leg {
    /// Parts per million asked for.
    asked: i32,
    /// Frames its earpiece takes at each callback.
    frames: u32,
    /// And the parts per million actually run, which whole nanoseconds of
    /// pace make a hundredth off.
    skew: f64,
    call: Option<CallHandle>,
    started: bool,
    ended: bool,
    /// What the buffer said when audio first ran, which the balance is
    /// counted from.
    first: Option<(Quality, Heard)>,
    /// And at the report before this one, for the interval's own figures.
    last: Option<(Quality, Heard)>,
    /// Whether the stack said the call was suffering at any report.
    suffered: bool,
    /// Session refreshes (RFC 4028) and anything else that changed the
    /// session while it ran.
    changes: u32,
    stalls: u32,
    failures: Vec<String>,
}

impl Leg {
    const fn new(asked: i32, frames: u32) -> Self {
        Self {
            asked,
            frames,
            skew: 0.0,
            call: None,
            started: false,
            ended: false,
            first: None,
            last: None,
            suffered: false,
            changes: 0,
            stalls: 0,
            failures: Vec::new(),
        }
    }

    /// What its report lines and failures are headed with.
    fn name(&self) -> String {
        format!("{:+} ppm x{}", self.asked, self.frames)
    }
}

/// Register, place the six calls, hold them for the length asked, report
/// as it goes, and judge.
///
/// # Errors
/// The first condition that did not hold, per call, the way every other flow
/// here reports.
#[allow(clippy::too_many_lines)]
pub(crate) fn run(
    server: &str,
    remote: SocketAddr,
    user: &str,
    pass: &str,
) -> Result<String, String> {
    let length = millis_from("SIPRAL_DRIFT_MS", 3_600_000);
    let every = millis_from("SIPRAL_DRIFT_REPORT_MS", 300_000).max(FRAME);
    let ppm: i32 = env::var("SIPRAL_DRIFT_PPM")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(250);
    let stressed = ppm.unsigned_abs() > ABSORBED_PPM;

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
    let target = uri(&format!("sip:{ECHO_EXTENSION}@{server}"))?;
    let mut legs = legs(ppm);
    announce(legs.len(), length, every, ppm, stressed);

    let _ = endpoint.agent.register(account, now);
    let mut registered = false;
    let mut placed = false;
    let mut running_since: Option<Instant> = None;
    let mut next_report = now;
    let mut hung_up: Option<Instant> = None;
    let began = Instant::now();

    loop {
        let now = Instant::now();
        for event in endpoint.pump(now) {
            if matches!(event, Event::Signalling(UaEvent::Registered { .. })) {
                registered = true;
            }
            observe(&event, &mut legs, hung_up.is_some());
        }
        if registered && !placed {
            placed = true;
            for leg in &mut legs {
                place(&mut endpoint, account, &target, remote, leg, now);
            }
        }
        endpoint.run_media(now);
        endpoint.timers(now);

        match running_since {
            None if legs.iter().all(|leg| leg.started) => {
                running_since = Some(now);
                next_report = now + every;
            }
            None if now > began + PATIENCE => return Err(not_up(registered, &legs)),
            Some(since) if hung_up.is_none() => {
                // what the buffer did while it filled for the first time is
                // not drift, so the balance is counted from once it has
                if now >= since + SETTLE && legs.iter().any(|leg| leg.first.is_none()) {
                    for leg in &mut legs {
                        let taken = snapshot(&mut endpoint, leg, now);
                        leg.first = taken;
                        leg.last = taken;
                    }
                }
                if now >= next_report {
                    next_report += every;
                    for leg in &mut legs {
                        report(&mut endpoint, leg, since, every, now, stressed);
                    }
                }
                if now >= since + length || legs.iter().any(|leg| leg.ended) {
                    // the last word, unless a report has only just been
                    // given — a length that is a whole number of intervals
                    // would otherwise print the same lines twice
                    let reported = next_report.checked_sub(every).unwrap_or(since);
                    let stale = now.saturating_duration_since(reported) > Duration::from_secs(1);
                    for leg in &mut legs {
                        if stale {
                            report(&mut endpoint, leg, since, every, now, stressed);
                        }
                        if let Some(call) = leg.call {
                            let _ = endpoint.agent.hangup(call, now);
                        }
                    }
                    hung_up = Some(now);
                }
            }
            _ => {}
        }

        if let Some(at) = hung_up
            && (legs.iter().all(|leg| leg.ended) || now > at + ENDING)
        {
            break;
        }
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    let gate_reports: Vec<Option<quality::Report>> = legs
        .iter()
        .map(|leg| {
            leg.call
                .and_then(|call| endpoint.media.get(&call))
                .and_then(Media::quality_report)
        })
        .collect();
    crate::join::give_back(&mut endpoint, account);
    verdict(
        &legs,
        ppm,
        running_since.map(|since| hung_up.unwrap_or(since) - since),
        stressed,
        &gate_reports,
    )
}

/// The six calls: slow, true and fast, each taking one frame and two at a
/// callback.
fn legs(ppm: i32) -> Vec<Leg> {
    CALLBACKS
        .iter()
        .flat_map(|&frames| [-ppm, 0, ppm].map(|asked| Leg::new(asked, frames)))
        .collect()
}

/// What the run is about to do, and how it will be judged.
fn announce(calls: usize, length: Duration, every: Duration, ppm: i32, stressed: bool) {
    println!(
        "  drift: {calls} calls to {ECHO_EXTENSION} for {} min, earpieces at -{ppm}, 0 and \
         +{ppm} ppm taking one frame and two at a callback, a report every {} s{}",
        length.as_secs() / 60,
        every.as_secs(),
        if stressed {
            format!(
                "; past the {ABSORBED_PPM} ppm any device runs at, judged on staying bounded and \
                 saying so rather than on never running dry"
            )
        } else {
            String::new()
        }
    );
}

/// What had happened by the time the calls should all have been up.
fn not_up(registered: bool, legs: &[Leg]) -> String {
    let each: Vec<String> = legs
        .iter()
        .map(|leg| {
            format!(
                "{} placed {} started {}",
                leg.name(),
                leg.call.is_some(),
                leg.started
            )
        })
        .collect();
    format!(
        "the calls never all came up: registered {registered}, {}",
        each.join(", ")
    )
}

fn place(
    endpoint: &mut Endpoint,
    account: AccountId,
    target: &sipral::Uri,
    remote: SocketAddr,
    leg: &mut Leg,
    now: Instant,
) {
    let media = CallMedia::new(catalog(), MediaConfig::default());
    let outgoing = OutgoingCall::new(target.clone()).to_address(endpoint.transport, remote);
    match place_call(endpoint, account, outgoing, media, remote, now) {
        Ok(call) => {
            if let Some(media) = endpoint.media.get_mut(&call) {
                leg.skew = media.skew_playout(leg.asked);
                media.earpiece_frames(leg.frames);
            }
            leg.call = Some(call);
        }
        Err(why) => leg.failures.push(format!("not placed: {why}")),
    }
}

fn observe(event: &Event, legs: &mut [Leg], hanging_up: bool) {
    let call = match event {
        Event::Signalling(
            UaEvent::CallEnded { call, .. } | UaEvent::SessionChanged { call, .. },
        )
        | Event::Media { call, .. } => *call,
        _ => return,
    };
    let Some(leg) = legs.iter_mut().find(|leg| leg.call == Some(call)) else {
        return;
    };
    match event {
        Event::Signalling(UaEvent::CallEnded { reason, status, .. }) => {
            leg.ended = true;
            if !hanging_up {
                leg.failures.push(format!(
                    "the call ended before the hour was up: {reason:?}{}",
                    status
                        .map(|status| format!(" ({status})"))
                        .unwrap_or_default()
                ));
            }
        }
        Event::Signalling(UaEvent::SessionChanged { .. }) => leg.changes += 1,
        Event::Media {
            event: MediaEvent::Started { .. },
            ..
        } => leg.started = true,
        Event::Media {
            event: MediaEvent::Stalled { .. },
            ..
        } => leg.stalls += 1,
        _ => {}
    }
}

/// The buffer's own count and this end's, together, as they are now.
fn snapshot(endpoint: &mut Endpoint, leg: &Leg, now: Instant) -> Option<(Quality, Heard)> {
    let call = leg.call?;
    let quality = endpoint.engine.session(call)?.statistics(now).quality;
    let heard = endpoint.media.get(&call)?.heard();
    Some((quality, heard))
}

/// Frames the earpiece played that never arrived, less frames that arrived
/// and were never played, from `first` to `now`: what the buffer did about
/// the two clocks, whichever way it did it.
///
/// Played is what the earpiece took. What it took that did not arrive was
/// stretched into a pause or concealed — both reach the earpiece as
/// [`sipral::Playback::Concealed`] — or played as silence because the buffer
/// had run dry, and all of it is counted as the earpiece took it: the
/// buffer's own loss count also holds sequence numbers it skipped without
/// playing anything for them, which would count a gap twice. What arrived
/// and was not taken was dropped from a pause, came too late, was pushed
/// out, or is still in the buffer — the change in its delay, a frame per
/// frame of it.
fn balance(first: &(Quality, Heard), now: &(Quality, Heard)) -> i64 {
    let delta = |later: u64, earlier: u64| {
        i64::try_from(later).unwrap_or(i64::MAX) - i64::try_from(earlier).unwrap_or(i64::MAX)
    };
    let (q0, h0) = first;
    let (q1, h1) = now;
    let invented = delta(u64::from(h1.concealed), u64::from(h0.concealed))
        + delta(u64::from(h1.silent), u64::from(h0.silent));
    let thrown = delta(q1.shrunk, q0.shrunk)
        + delta(q1.discarded_late, q0.discarded_late)
        + delta(q1.discarded_overflow, q0.discarded_overflow);
    let frame = i64::try_from(FRAME.as_micros()).unwrap_or(1);
    let held = (i64::try_from(q1.delay.as_micros()).unwrap_or(0)
        - i64::try_from(q0.delay.as_micros()).unwrap_or(0))
        / frame;
    invented - thrown - held
}

/// The skew `balance` comes to, in parts per million: the ratio of the
/// earpiece's clock to the far end's, less one. The earpiece's clock counted
/// the frames played; the far end's counted those played less the balance,
/// which is the frames that arrived.
#[allow(clippy::cast_precision_loss)]
fn measured(first: &(Quality, Heard), now: &(Quality, Heard)) -> f64 {
    let played = i64::from(now.1.played.saturating_sub(first.1.played));
    let balance = balance(first, now);
    let arrived = (played - balance).max(1);
    balance as f64 * 1e6 / arrived as f64
}

/// The frames of silence the earpiece played from `first` to `now` that
/// the stack did not count, or the other way about, past what a run of
/// silence still going on when either was taken accounts for: the stack
/// settles a run only once the packet after it is played. A frame of
/// silence is counted one of two ways: an under-run
/// ([`Quality::underruns`]), the buffer having nothing to play because the
/// earpiece asked early, or a packet lost on the way with nothing behind it
/// to conceal it from ([`Quality::silenced`]) -- a lossy link gives the
/// second as well as the first, and a clean one only the first.
fn uncounted(first: &(Quality, Heard), now: &(Quality, Heard)) -> Option<String> {
    let heard = u64::from(now.1.silent.saturating_sub(first.1.silent));
    let underruns = now.0.underruns.saturating_sub(first.0.underruns);
    let silenced = now.0.silenced.saturating_sub(first.0.silenced);
    let counted = underruns.saturating_add(silenced);
    (heard.abs_diff(counted) > u64::from(now.1.longest_silence)).then(|| {
        format!(
            "the earpiece played {heard} frames as silence and the stack counted {underruns} \
             under-runs and {silenced} lost frames heard as silence"
        )
    })
}

/// One line for one call: the interval's own figures and the call's so far,
/// and what in them fails it.
#[allow(clippy::cast_precision_loss)]
fn report(
    endpoint: &mut Endpoint,
    leg: &mut Leg,
    since: Instant,
    every: Duration,
    now: Instant,
    stressed: bool,
) {
    let (Some(first), Some(last)) = (leg.first, leg.last) else {
        return;
    };
    let Some(taken) = snapshot(endpoint, leg, now) else {
        return;
    };
    let Some(statistics) = leg
        .call
        .and_then(|call| endpoint.engine.session(call))
        .map(|session| session.statistics(now))
    else {
        return;
    };
    let (quality, heard) = taken;
    let (_, before) = last;
    let elapsed = now.saturating_duration_since(since);
    let played = heard.played.saturating_sub(before.played);
    let audible = heard.audible.saturating_sub(before.audible);
    let expected = f64::from(played) * AUDIBLE_SHARE;
    let minutes = elapsed.as_secs() / 60;
    let seconds = elapsed.as_secs() % 60;
    let score = statistics.score();
    let suffering = statistics.is_suffering();
    leg.suffered |= suffering;
    let mut line = format!(
        "  drift {:>14} {minutes:3}:{seconds:02}  delay {:3} ms of {:3} ms, jitter {} ms; \
         shrunk {}, stretched {}, ran dry {} ({} in the tone, {} under-runs and {} lost \
         counted), concealed {}, \
         late {}, overflow {}; played {}, audible {} of {:.0} due; measured {:+.1} ppm; \
         score {score:.0}{}",
        leg.name(),
        quality.delay.as_millis(),
        quality.target_delay.as_millis(),
        quality.jitter.as_millis(),
        quality.shrunk.saturating_sub(first.0.shrunk),
        quality.stretched.saturating_sub(first.0.stretched),
        heard.silent.saturating_sub(first.1.silent),
        heard.cut.saturating_sub(first.1.cut),
        quality.underruns.saturating_sub(first.0.underruns),
        quality.silenced.saturating_sub(first.0.silenced),
        heard
            .concealed
            .saturating_sub(first.1.concealed)
            .saturating_sub(
                u32::try_from(quality.stretched.saturating_sub(first.0.stretched))
                    .unwrap_or(u32::MAX),
            ),
        quality
            .discarded_late
            .saturating_sub(first.0.discarded_late),
        quality
            .discarded_overflow
            .saturating_sub(first.0.discarded_overflow),
        heard.played.saturating_sub(first.1.played),
        audible,
        expected,
        measured(&first, &taken),
        if suffering { ", suffering" } else { "" },
    );
    if let Some(block) = statistics.voip_metrics
        && block.mos_lq != UNAVAILABLE
    {
        let _ = write!(
            line,
            "; R {}, MOS-LQ {}.{}",
            block.r_factor,
            block.mos_lq / 10,
            block.mos_lq % 10
        );
    }
    println!("{line}");

    let at = format!("at {minutes}:{seconds:02}");
    let held = quality.delay.as_millis();
    if quality.delay > RING || (!stressed && quality.delay > MAX_DELAY) {
        leg.failures.push(format!("{at} the buffer held {held} ms"));
    } else if quality.delay > MAX_DELAY && score >= 50.0 {
        leg.failures.push(format!(
            "{at} the buffer held {held} ms and the stack still scored the call {score:.0}"
        ));
    }
    // a report that falls just after the last one — the final one, when the
    // length is a whole number of intervals — has too few frames to judge
    if played >= u32::try_from(every.as_millis() / FRAME.as_millis() / 2).unwrap_or(u32::MAX)
        && f64::from(audible) < expected / 2.0
    {
        leg.failures.push(format!(
            "{at} only {audible} of {expected:.0} frames were audible"
        ));
    }
    if let Some(why) = uncounted(&first, &taken) {
        leg.failures.push(format!("{at} {why}"));
    }
    leg.last = Some(taken);
}

/// Whether every call held, heard and measured what it should have. `ppm`
/// is the skew the run was given, and [`TOLERANCE`] of it is how far any of
/// the six — the controls included — may measure from its own. `stressed`
/// is a skew past [`ABSORBED_PPM`], where a tone cut off is what the product
/// does and a call running dry unreported is what fails. `gate_reports` is
/// what the audio quality gate found on each leg's own call, `None` on a
/// run `SIPRAL_AUDIO_GATE` never engaged for (the ordinary `drift` word)
/// and `Some` on one that did (`scripts/lab.sh drift-netem`): a leg's own
/// audio can hold up by every count above and still have clicked at a
/// concealment splice or measured too noisy to trust, which only the gate
/// would catch.
#[allow(clippy::cast_precision_loss)]
fn verdict(
    legs: &[Leg],
    ppm: i32,
    ran: Option<Duration>,
    stressed: bool,
    gate_reports: &[Option<quality::Report>],
) -> Result<String, String> {
    let ran = ran.unwrap_or_default();
    let allowed = f64::from(ppm.unsigned_abs()) * TOLERANCE;
    let mut failed = Vec::new();
    let mut said = format!("   ({} min", ran.as_secs() / 60);
    for (leg, gate) in legs.iter().zip(gate_reports) {
        let mut failures = leg.failures.clone();
        if let Some(report) = gate {
            let _ = write!(said, "; audio gate: {}", report.summary());
            if let Err(why) = report.verdict() {
                failures.push(why);
            }
        }
        let result = if let (Some(first), Some(last)) = (leg.first, leg.last) {
            let skew = measured(&first, &last);
            if (skew - leg.skew).abs() > allowed {
                failures.push(format!(
                    "measured {skew:+.1} ppm against the {:+.1} it was given",
                    leg.skew
                ));
            }
            let cut = last.1.cut.saturating_sub(first.1.cut);
            if cut > 0 && !stressed {
                failures.push(format!(
                    "the tone was cut off {cut} times by a buffer that ran dry"
                ));
            }
            let dry = last.1.silent.saturating_sub(first.1.silent);
            let played = last.1.played.saturating_sub(first.1.played).max(1);
            if f64::from(dry) >= f64::from(played) * SUFFERING && !leg.suffered {
                failures.push(format!(
                    "ran dry on {dry} of {played} frames and the stack never said the call was \
                     suffering"
                ));
            }
            format!(
                "{} given, {skew:+.1} measured, {} frames balanced of which {dry} ran dry, \
                 {cut} in the tone",
                leg.name(),
                balance(&first, &last),
            )
        } else {
            failures.push("no audio ever ran".to_owned());
            format!("{} given, nothing measured", leg.name())
        };
        if leg.stalls > 0 {
            failures.push(format!(
                "the stack said the audio stalled {} times",
                leg.stalls
            ));
        }
        let _ = write!(
            said,
            "; {result}, {} session change(s), {} stall(s)",
            leg.changes, leg.stalls
        );
        for failure in failures {
            failed.push(format!("{}: {failure}", leg.name()));
        }
    }
    said.push(')');
    if failed.is_empty() {
        Ok(said)
    } else {
        Err(format!("{}{said}", failed.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sipral::Quality;

    use super::{FRAME, Leg, balance, measured, quality, uncounted, verdict};
    use crate::audio::Heard;

    fn at(stretched: u64, shrunk: u64, delay: Duration, played: u32) -> (Quality, Heard) {
        let quality = Quality {
            stretched,
            shrunk,
            delay,
            ..Quality::default()
        };
        // a stretched pause reaches the earpiece as a concealed frame
        let heard = Heard {
            played,
            concealed: u32::try_from(stretched).unwrap_or(u32::MAX),
            ..Heard::default()
        };
        (quality, heard)
    }

    /// Five seconds of the far end's audio lost: the buffer runs dry and
    /// plays silence through it, then skips the sequence numbers it never
    /// got, which its own loss count records. Those are the same 250 frames,
    /// and they count once.
    #[test]
    fn a_gap_played_as_silence_counts_once() {
        let start = at(0, 0, FRAME, 0);
        let (mut quality, mut heard) = at(0, 0, FRAME, 2_500);
        quality.lost = 250;
        heard.silent = 250;
        assert_eq!(balance(&start, &(quality, heard)), 250);
    }

    /// A fast earpiece that the buffer kept up with by stretching reads as
    /// the skew it was given, and a slow one kept level by shrinking reads
    /// as its negative.
    #[test]
    fn stretching_reads_as_a_fast_earpiece_and_shrinking_as_a_slow_one() {
        let start = at(0, 0, FRAME * 3, 0);
        let fast = at(45, 0, FRAME * 3, 180_045);
        assert!((measured(&start, &fast) - 250.0).abs() < 0.01);
        let slow = at(0, 45, FRAME * 3, 179_955);
        assert!((measured(&start, &slow) + 250.0).abs() < 0.01);
    }

    /// Frames the buffer took on or gave up rather than stretched or shrank
    /// count as well: a slow earpiece whose buffer merely grew by two frames
    /// has absorbed two frames of the drift, not none.
    #[test]
    fn a_buffer_that_grew_counts_what_it_holds() {
        let start = at(0, 0, FRAME * 3, 0);
        let grown = at(0, 10, FRAME * 5, 100_000);
        assert_eq!(balance(&start, &grown), -12);
    }

    /// A fast earpiece whose buffer ran dry rather than stretched still
    /// reads as fast: a frame of silence where no packet was due is a frame
    /// it played that never arrived.
    #[test]
    fn a_buffer_that_ran_dry_counts_the_silence_it_played() {
        let start = at(0, 0, FRAME, 0);
        let (quality, mut heard) = at(0, 0, FRAME, 100_025);
        heard.silent = 25;
        assert_eq!(balance(&start, &(quality, heard)), 25);
        assert!((measured(&start, &(quality, heard)) - 250.0).abs() < 0.01);
    }

    /// A skew is the ratio of the two clocks, so an earpiece 5 % fast plays
    /// 105 frames for every 100 that arrive: five in 105 were invented, and
    /// that is 50 000 ppm of the frames that arrived, not of those played.
    #[test]
    fn a_large_skew_reads_as_the_ratio_of_the_two_clocks() {
        let start = at(0, 0, FRAME, 0);
        let fast = at(50, 0, FRAME, 1_050);
        assert!((measured(&start, &fast) - 50_000.0).abs() < 0.01);
        let slow = at(0, 50, FRAME, 950);
        assert!((measured(&start, &slow) + 50_000.0).abs() < 0.01);
    }

    /// A control call whose skew balanced and whose audio never stopped,
    /// from a run given `ppm` either side of it.
    fn control(silent: u32, cut: u32) -> Leg {
        let start = at(0, 0, FRAME, 0);
        let (quality, mut heard) = at(0, 0, FRAME, 9_000);
        heard.silent = silent;
        heard.cut = cut;
        let mut leg = Leg::new(0, 1);
        leg.first = Some(start);
        leg.last = Some((quality, heard));
        leg
    }

    /// Frames played as silence in a pause are the buffer catching up, and
    /// nobody hears them: they are within the tolerance, and they pass.
    #[test]
    fn silence_where_the_tone_paused_passes() {
        assert!(verdict(&[control(3, 0)], 2_000, Some(FRAME * 9_000), false, &[None]).is_ok());
    }

    /// The same frames of silence in the middle of the tone are gaps in the
    /// audio, however well the count of them balances.
    #[test]
    fn silence_that_cut_the_tone_off_fails() {
        let verdict = verdict(&[control(3, 3)], 2_000, Some(FRAME * 9_000), false, &[None]);
        let why = verdict.expect_err("the tone was cut three times");
        assert!(why.contains("cut off 3 times"), "{why}");
    }

    /// Past a skew any device runs at, a tone cut off is what the product
    /// does, and passes; a call that ran dry on a tenth of its frames and
    /// that the stack never called suffering is a degradation nobody could
    /// read, and fails.
    #[test]
    fn a_stressed_call_may_be_cut_but_not_unreported() {
        let mut said = control(900, 400);
        said.suffered = true;
        assert!(verdict(&[said], 500_000, Some(FRAME * 9_000), true, &[None]).is_ok());
        let unsaid = control(900, 400);
        let why = verdict(&[unsaid], 500_000, Some(FRAME * 9_000), true, &[None])
            .expect_err("never said it was suffering");
        assert!(why.contains("never said"), "{why}");
        assert!(!why.contains("cut off"), "{why}");
    }

    /// Every frame the earpiece played as silence is one the stack counts as
    /// an under-run, give or take the run that may be going on when a report
    /// falls; more than that either way is a frame the application cannot
    /// read.
    #[test]
    fn silence_the_stack_did_not_count_fails() {
        let start = at(0, 0, FRAME, 0);
        let (mut quality, mut heard) = at(0, 0, FRAME, 9_000);
        heard.silent = 40;
        heard.longest_silence = 3;
        quality.underruns = 38;
        assert_eq!(uncounted(&start, &(quality, heard)), None);
        quality.underruns = 30;
        let why = uncounted(&start, &(quality, heard)).expect("ten frames went uncounted");
        assert!(
            why.contains("played 40") && why.contains("counted 30 under-runs"),
            "{why}"
        );
    }

    /// Over a lossy link part of the silence is packets lost on the way
    /// with nothing behind them to conceal them from, which the stack counts
    /// apart from the under-runs: the two together are what the earpiece
    /// played as silence, and neither alone is (`scripts/lab.sh
    /// drift-netem` under `lossy`, where 12 frames of silence were 3
    /// under-runs).
    #[test]
    fn silence_for_a_lost_packet_is_counted_beside_the_under_runs() {
        let start = at(0, 0, FRAME, 0);
        let (mut quality, mut heard) = at(0, 0, FRAME, 9_000);
        heard.silent = 12;
        heard.longest_silence = 2;
        quality.underruns = 3;
        quality.silenced = 9;
        assert_eq!(uncounted(&start, &(quality, heard)), None);
        quality.silenced = 0;
        let why = uncounted(&start, &(quality, heard)).expect("nine frames went uncounted");
        assert!(why.contains("played 12"), "{why}");
    }

    /// A call the stack itself said had stopped receiving audio fails, even
    /// when the frames it missed happen to balance.
    #[test]
    fn a_stalled_call_fails() {
        let mut leg = control(0, 0);
        leg.stalls = 1;
        let verdict = verdict(&[leg], 2_000, Some(FRAME * 9_000), false, &[None]);
        let why = verdict.expect_err("the stream stalled");
        assert!(why.contains("stalled"), "{why}");
    }

    /// A leg that balanced its skew, was never cut and never stalled still
    /// fails when the audio quality gate — engaged only under
    /// `scripts/lab.sh drift-netem` — clicked at a concealment splice: a
    /// count of frames balancing is not the same claim as a waveform
    /// nothing heard a click in.
    #[test]
    fn a_gate_failure_fails_the_leg_even_when_every_count_balances() {
        let report = quality::Report {
            segments: 100,
            mean_seg_snr_db: 20.0,
            clicks: 1,
            edges_checked: 4,
            ..quality::Report::default()
        };
        let verdict = verdict(
            &[control(0, 0)],
            2_000,
            Some(FRAME * 9_000),
            false,
            &[Some(report)],
        );
        let why = verdict.expect_err("the gate found a click");
        assert!(why.contains("1 of 4"), "{why}");
    }

    /// A leg the gate never ran on — `SIPRAL_AUDIO_GATE` unset, the ordinary
    /// `drift` word — prints nothing about it and is judged the same as
    /// before the gate existed.
    #[test]
    fn a_leg_with_no_gate_report_is_judged_without_it() {
        let said = verdict(&[control(0, 0)], 2_000, Some(FRAME * 9_000), false, &[None])
            .expect("no gate, nothing else wrong");
        assert!(!said.contains("audio gate"), "{said}");
    }
}
