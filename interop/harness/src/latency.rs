// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The delay from this end's own microphone to its own earpiece, on a call
//! to Asterisk's echo.
//!
//! There is no far end in this lab to put a second clock or a second
//! microphone at, so what is measured is a round trip rather than one leg:
//! a marker frame, full scale rather than the tone (`crate::audio::Media`'s
//! own `MARK_AMPLITUDE`), goes out in place of whatever this end would
//! otherwise have sent, and the same call's own playback watches for its
//! echo. The lab's own path is stated here rather than assumed away: this
//! is capture, encode, network, Asterisk's `Echo()`, network, jitter buffer,
//! decode and playback, twice each but Asterisk's own turnaround, and one
//! way is that halved. Halving assumes the two directions cost the same,
//! which a lab on one host with one link is the closest thing here to being
//! able to say.
//!
//! # Three stages, not one
//!
//! A round trip is a single number; what it is spent on is three, and only
//! one of them is `sipral`'s own to ask for directly:
//!
//! - **Framing** — [`crate::audio::Mark::capture_wait`] — the wait from the
//!   marker's own instant to the next twenty-millisecond tick that actually
//!   carries it, the same wait a real device's own buffering would cost.
//! - **Jitter buffer** — [`crate::audio::Mark::buffer_target`] — the
//!   playout buffer's own target delay the instant the echo came back
//!   (`sipral::MediaSession::statistics`), the deliberate hold this end
//!   chose before playing what arrived.
//! - **Network** — everything else: the round trip less the two above, so
//!   it also carries whatever Asterisk's own `Echo()` costs and the wait
//!   for this end's own next playback tick, neither of which this lab can
//!   tell apart from the wire.
//!
//! Framing and the buffer are each read once, off the return leg, because
//! this call only decodes once: Asterisk's echo is not asked to be silent
//! about what it received, so nothing here re-frames a second time on the
//! way out beyond the one wait `capture_wait` already counts.
//!
//! # What fails it
//!
//! The call never coming up, more than half the markers sent never coming
//! back — a network this lossy is not what a delay figure is worth reading
//! against — or the stack reporting the stream stalled.

use std::env;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::{CallHandle, CallMedia, Event, MediaConfig, MediaEvent, OutgoingCall, UaEvent};

use crate::audio::Mark;
use crate::{Endpoint, catalog, place_call, run_folded, uri};

/// `interop/asterisk/extensions.conf`'s echo, the same one `crate::drift`
/// uses.
const ECHO_EXTENSION: &str = "9008";

/// This flow's own endpoint identity, folded with the run's own entropy the
/// same way every other flow's is. Listed in `main.rs`'s
/// `tests::endpoint_identity_constants_are_distinct`.
pub(crate) const SEED: u8 = 244;
pub(crate) const MEDIA_SEED: u8 = 246;

/// How long the call is given to come up.
const PATIENCE: Duration = Duration::from_secs(30);

/// How long after audio starts the first marker is sent: long enough for
/// the buffer to have filled to its target, so the first few marks are not
/// measuring the fill rather than the steady state.
const SETTLE: Duration = Duration::from_secs(5);

/// How long a marker is given to come back before it counts as lost.
const MARK_TIMEOUT: Duration = Duration::from_secs(2);

/// How long the hangup is waited for.
const ENDING: Duration = Duration::from_secs(10);

fn millis_from(name: &str, fallback: u64) -> Duration {
    Duration::from_millis(
        env::var(name)
            .ok()
            .and_then(|text| text.parse().ok())
            .unwrap_or(fallback),
    )
}

/// Register, place the call, mark it every interval for the length asked,
/// hang up, and report the round trips' own distribution.
///
/// # Errors
/// The first condition that did not hold, the way every other flow here
/// reports.
#[allow(clippy::too_many_lines)]
pub(crate) fn run(
    server: &str,
    remote: SocketAddr,
    user: &str,
    pass: &str,
) -> Result<String, String> {
    let length = millis_from("SIPRAL_LATENCY_MS", 120_000);
    let every = millis_from("SIPRAL_LATENCY_MARK_MS", 2_000).max(MARK_TIMEOUT);

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

    println!(
        "  latency: one call to {ECHO_EXTENSION}, a marker every {} s for {} s",
        every.as_secs(),
        length.as_secs()
    );

    let _ = endpoint.agent.register(account, now);
    let mut registered = false;
    let mut call: Option<CallHandle> = None;
    let mut started = false;
    let mut stalls = 0_u32;
    let mut running_since: Option<Instant> = None;
    let mut next_mark = now;
    let mut armed_at: Option<Instant> = None;
    let mut marks: Vec<Mark> = Vec::new();
    let mut lost = 0_u32;
    let mut hung_up: Option<Instant> = None;
    let mut ended = false;
    let began = Instant::now();

    loop {
        let now = Instant::now();
        for event in endpoint.pump(now) {
            match event {
                Event::Signalling(UaEvent::Registered { .. }) => registered = true,
                Event::Signalling(UaEvent::CallEnded { .. }) => ended = true,
                Event::Media {
                    event: MediaEvent::Started { .. },
                    ..
                } => started = true,
                Event::Media {
                    event: MediaEvent::Stalled { .. },
                    ..
                } => stalls += 1,
                _ => {}
            }
        }
        if registered && call.is_none() {
            let media = CallMedia::new(catalog(), MediaConfig::default());
            let outgoing = OutgoingCall::new(target.clone()).to_address(endpoint.transport, remote);
            match place_call(&mut endpoint, account, outgoing, media, remote, now) {
                Ok(handle) => call = Some(handle),
                Err(why) => return Err(format!("not placed: {why}")),
            }
        }
        if call.is_none() && now > began + PATIENCE {
            return Err(format!("never registered (registered {registered})"));
        }
        endpoint.run_media(now);
        endpoint.timers(now);

        if let Some(handle) = call {
            match running_since {
                None if started => {
                    running_since = Some(now);
                    next_mark = now + SETTLE;
                }
                None if now > began + PATIENCE => {
                    return Err("the call never started media".to_owned());
                }
                Some(since) if hung_up.is_none() => {
                    let before = marks.len();
                    if let Some(media) = endpoint.media.get_mut(&handle) {
                        marks.extend(media.take_marks());
                    }
                    if marks.len() > before {
                        // the mark this armed just came back: nothing to
                        // time out any more
                        armed_at = None;
                    }
                    if let Some(armed) = armed_at
                        && now > armed + MARK_TIMEOUT
                    {
                        lost += 1;
                        armed_at = None;
                    }
                    if now >= next_mark && armed_at.is_none() {
                        if let Some(media) = endpoint.media.get_mut(&handle) {
                            media.arm_mark(now);
                            armed_at = Some(now);
                        }
                        next_mark += every;
                    }
                    if now >= since + length {
                        let _ = endpoint.agent.hangup(handle, now);
                        hung_up = Some(now);
                    }
                }
                _ => {}
            }
        }

        if let Some(at) = hung_up
            && (ended || now > at + ENDING)
        {
            break;
        }
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    if let Some(handle) = call
        && let Some(media) = endpoint.media.get_mut(&handle)
    {
        let before = marks.len();
        marks.extend(media.take_marks());
        if marks.len() > before {
            armed_at = None;
        }
    }
    if armed_at.is_some() {
        // the last marker armed near the end of the run, its echo neither
        // back nor timed out when the calls came down: counted lost rather
        // than left out of the total this run says it sent
        lost += 1;
    }
    let _ = endpoint.agent.unregister(account, Instant::now());

    if stalls > 0 {
        return Err(format!("the stack said the audio stalled {stalls} time(s)"));
    }
    let sent = u32::try_from(marks.len())
        .unwrap_or(u32::MAX)
        .saturating_add(lost);
    if sent == 0 {
        return Err("no marker ever went out".to_owned());
    }
    if lost * 2 > sent {
        return Err(format!(
            "{lost} of {sent} markers never came back, too many to trust a delay figure"
        ));
    }
    Ok(summary(&marks, lost, sent))
}

/// Sorted, `p` in `[0, 100]`.
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

fn mean(durations: impl Iterator<Item = Duration> + Clone) -> Duration {
    let count = durations.clone().count();
    if count == 0 {
        return Duration::ZERO;
    }
    let total: Duration = durations.sum();
    total / u32::try_from(count).unwrap_or(1)
}

/// The round trips' own distribution, halved into a one-way figure, and the
/// three stages that add up to it. Printed whether or not the run passed,
/// the way every other flow's own numbers are.
fn summary(marks: &[Mark], lost: u32, sent: u32) -> String {
    let mut round_trips: Vec<Duration> = marks.iter().map(|mark| mark.round_trip).collect();
    round_trips.sort();
    let one_way: Vec<Duration> = round_trips.iter().map(|rt| *rt / 2).collect();
    let framing = mean(marks.iter().map(|mark| mark.capture_wait));
    let buffer = mean(marks.iter().map(|mark| mark.buffer_target));
    let one_way_mean = mean(one_way.iter().copied());
    let network = one_way_mean
        .checked_sub(framing)
        .and_then(|left| left.checked_sub(buffer))
        .unwrap_or(Duration::ZERO);
    format!(
        "   ({} of {} markers back, {} lost; one way: min {:.1} ms, p50 {:.1} ms, p90 {:.1} ms, \
         max {:.1} ms, mean {:.1} ms; framing {:.1} ms, jitter buffer {:.1} ms, network {:.1} ms)",
        marks.len(),
        sent,
        lost,
        percentile(&one_way, 0.0).as_secs_f64() * 1e3,
        percentile(&one_way, 50.0).as_secs_f64() * 1e3,
        percentile(&one_way, 90.0).as_secs_f64() * 1e3,
        percentile(&one_way, 100.0).as_secs_f64() * 1e3,
        one_way_mean.as_secs_f64() * 1e3,
        framing.as_secs_f64() * 1e3,
        buffer.as_secs_f64() * 1e3,
        network.as_secs_f64() * 1e3,
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Mark, percentile, summary};

    fn mark(round_trip_ms: u64, capture_wait_ms: u64, buffer_ms: u64) -> Mark {
        Mark {
            capture_wait: Duration::from_millis(capture_wait_ms),
            round_trip: Duration::from_millis(round_trip_ms),
            buffer_target: Duration::from_millis(buffer_ms),
        }
    }

    /// The median of an odd count is the middle one; of an even count, this
    /// takes the nearest rank rather than interpolating, which is close
    /// enough for a lab's own report and never invents a value nothing
    /// measured.
    #[test]
    fn percentile_reads_off_the_sorted_list() {
        let sorted: Vec<Duration> = [10, 20, 30, 40, 50]
            .iter()
            .map(|ms| Duration::from_millis(*ms))
            .collect();
        assert_eq!(percentile(&sorted, 0.0), Duration::from_millis(10));
        assert_eq!(percentile(&sorted, 50.0), Duration::from_millis(30));
        assert_eq!(percentile(&sorted, 100.0), Duration::from_millis(50));
    }

    /// The three stages a summary prints have to add back to the one-way
    /// figure they were split from, or the accounting is lying about where
    /// the time went.
    #[test]
    fn the_three_stages_add_up_to_the_one_way_delay() {
        let marks = vec![mark(100, 10, 20), mark(100, 10, 20)];
        let said = summary(&marks, 0, 2);
        // 100 ms round trip halves to 50 ms; 10 ms framing and 20 ms buffer
        // leave 20 ms of network
        assert!(said.contains("mean 50.0 ms"), "{said}");
        assert!(said.contains("framing 10.0 ms"), "{said}");
        assert!(said.contains("jitter buffer 20.0 ms"), "{said}");
        assert!(said.contains("network 20.0 ms"), "{said}");
    }

    /// A network stage that would come out negative — framing and the
    /// buffer together outweighing the one-way figure they were read
    /// against — is clamped rather than printed as a delay nothing can be
    /// less than zero of.
    #[test]
    fn network_never_reads_negative() {
        let marks = vec![mark(20, 10, 20)];
        let said = summary(&marks, 0, 1);
        assert!(said.contains("network 0.0 ms"), "{said}");
    }
}
