// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Two calls to the lab, joined locally, and what that has to look like on
//! the wire for the claim to be checked from here rather than taken on
//! trust.
//!
//! `sipral::MediaEngine::join` and `sipral::MediaEngine::mix` are what this
//! flow exists to exercise against a real peer: everything about them is
//! already proven deterministically in `crates/sipral/src/tests.rs`, against
//! two sessions this repository also wrote both ends of. What that cannot
//! prove is a real codec payload from a real PBX, on a real socket, with real
//! jitter, decoded and re-mixed and sent on in time — which is what every
//! other flow in this table exists to catch and this one is no exception.
//!
//! # The two calls
//!
//! One placed to `TONE_EXTENSION` (9000, `interop/asterisk/extensions.conf`'s
//! own cadenced tone — the same extension `Flow::Call` dials), and one to
//! `ECHO_EXTENSION` (9008, added for this flow alone: `Answer(); Echo();`,
//! which says nothing on its own and sends back only whatever it is sent).
//! Both calls are placed and answered exactly as every other flow's is, then
//! [`sipral::MediaEngine::join`] pairs them and the driving loop switches from
//! `Endpoint::run_media`'s ordinary per-call `capture`/`playback` to
//! [`sipral::MediaEngine::mix`], a call at a time, with this end's own
//! microphone silent throughout — what crosses is only what one call's far
//! end sent the other.
//!
//! # What "reaches the other" has to mean without decoding anything
//!
//! This harness reaches `sipral` through the facade and nothing else
//! (`docs/11-testing.md`'s "through the facade, not around it"), so it does
//! not carry a second G.711 decoder to read the payload it is about to send —
//! that is exactly the second codec pipeline the harness once carried and
//! gave up. What it *can*
//! read, because `sipral::MediaEngine::mix` already decodes it through the
//! same facade, is `local_out`: the frame this end's own loudspeaker would be
//! given, which is the tone extension's audio and the echo extension's audio
//! mixed together, in plain PCM.
//!
//! The echo extension only ever plays back what this end sent it, and this
//! end sent it nothing but a half-scale copy of the tone extension's own
//! decoded audio (the microphone stayed silent). So a `local_out` frame that
//! is audible while the tone extension's own cadence says it should currently
//! be silent (`crate::audio::in_spurt`, timed from the moment that call was
//! confirmed) cannot be the tone extension's own contribution — the only
//! thing left that could have produced it is the echo extension playing back
//! what this end's own local mix had sent it moments before, which is to say
//! the tone call's audio, having crossed to the echo call's wire and back.
//! That is the claim this flow checks, and it checks it from a signal this
//! harness decoded itself, on its own sockets, through the same
//! `sipral::MediaEngine` a real application links.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::{CallHandle, CallMedia, Event, MediaConfig, MediaEvent, OutgoingCall, UaEvent};

use crate::audio::{AUDIBLE, in_spurt, loudness};
use crate::{Endpoint, catalog, place_call, run_folded, uri};

/// How long the flow may take before it is a failure.
const PATIENCE: Duration = Duration::from_secs(30);

/// How long the binding's removal is waited for once both calls are over.
/// The registrar on this network answers in milliseconds; this only bounds a
/// lab where it does not.
const UNREGISTER_PATIENCE: Duration = Duration::from_secs(2);

/// How long both calls run joined, driving the mix. Long enough for several
/// turns of the tone extension's own cadence
/// (`crate::audio::SPURT`/`crate::audio::PAUSE`, 1200 ms/600 ms) to have
/// crossed to the echo extension and come back at least once.
const DWELL: Duration = Duration::from_secs(6);

/// The pace a frame is due at, matching `sipral::CodecCatalog`'s default
/// packetisation — the same pace `crate::audio::Media` sends at.
const PACE: Duration = Duration::from_millis(20);

/// `interop/asterisk/extensions.conf`'s own cadenced tone, the one
/// `Flow::Call` dials too.
const TONE_EXTENSION: &str = "9000";

/// `interop/asterisk/extensions.conf`'s echo extension, added for this flow:
/// `Answer(); Echo();`. Silent on its own, and sends back only what it is
/// sent.
const ECHO_EXTENSION: &str = "9008";

/// How many frames audible during the tone extension's own predicted silence
/// have to be seen before the crossing counts as proven rather than a fluke
/// — a hundred milliseconds' worth, which a single stray concealment frame or
/// a moment of network jitter does not reach on its own.
const CROSSED_THRESHOLD: u32 = 5;

/// This flow's own endpoint identity, folded with the run's own entropy
/// before anything binds with it (`run_folded`, `main.rs`). Listed in
/// `main.rs`'s `tests::endpoint_identity_constants_are_distinct` alongside
/// every other step's, so a value reused here or added later fails that
/// test rather than a live run.
pub(crate) const SEED: u8 = 151;
pub(crate) const MEDIA_SEED: u8 = 163;

/// One call this flow placed, and what it has told this end so far.
#[derive(Debug, Default)]
struct Leg {
    /// Set once, whether or not placing it actually worked — a call that
    /// failed to place is not retried, the same as every other flow in this
    /// table places its own call once and lets `PATIENCE` name the failure.
    attempted: bool,
    call: Option<CallHandle>,
    confirmed_at: Option<Instant>,
    media_started: bool,
    /// The call's own `UaEvent::CallEnded` has arrived. What the loop waits
    /// for before it judges anything: a call with no session yet looks the
    /// same as one whose session has gone, and the first is where every call
    /// starts.
    ended: bool,
}

/// Register one account, place both calls, join them, and drive the mix long
/// enough to see one call's tone come back by way of the other.
///
/// # Errors
/// Anything that stops the two calls from being placed, answered, joined and
/// driven long enough to prove the crossing — named as the first condition
/// that did not hold, the same shape every other flow in this table reports.
pub(crate) fn run(
    server: &str,
    remote: SocketAddr,
    user: &str,
    pass: &str,
) -> Result<String, String> {
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

    let mut tone_leg = Leg::default();
    let mut echo_leg = Leg::default();
    let mut asked_to_register = false;
    let mut registered = false;
    let mut joined = false;
    let mut joined_at = None;
    let mut mixed_frames: u32 = 0;
    let mut crossed_frames: u32 = 0;
    let mut next_frame = now;

    let tone_target = uri(&format!("sip:{TONE_EXTENSION}@{server}"))?;
    let echo_target = uri(&format!("sip:{ECHO_EXTENSION}@{server}"))?;

    let started = Instant::now();
    loop {
        let now = Instant::now();
        if now > started + PATIENCE {
            return Err(format!(
                "the join never finished: registered {registered}, \
                 tone call placed {}, confirmed {}, media {}; \
                 echo call placed {}, confirmed {}, media {}; joined {joined}, \
                 {mixed_frames} frame(s) mixed, {crossed_frames} crossed",
                tone_leg.call.is_some(),
                tone_leg.confirmed_at.is_some(),
                tone_leg.media_started,
                echo_leg.call.is_some(),
                echo_leg.confirmed_at.is_some(),
                echo_leg.media_started,
            ));
        }

        for event in endpoint.pump(now) {
            if matches!(event, Event::Signalling(UaEvent::Registered { .. })) {
                registered = true;
            }
            on_event(&event, &mut tone_leg, &mut echo_leg, now);
        }

        if !asked_to_register {
            asked_to_register = true;
            let _ = endpoint.agent.register(account, now);
        }

        if registered && !tone_leg.attempted {
            tone_leg.attempted = true;
            tone_leg.call = place(&mut endpoint, account, tone_target.clone(), remote, now).ok();
        }
        if registered && !echo_leg.attempted {
            echo_leg.attempted = true;
            echo_leg.call = place(&mut endpoint, account, echo_target.clone(), remote, now).ok();
        }

        if !joined
            && let (Some(a), Some(b)) = (tone_leg.call, echo_leg.call)
            && tone_leg.media_started
            && echo_leg.media_started
        {
            endpoint
                .engine
                .join(a, b)
                .map_err(|error| format!("the calls would not join: {error}"))?;
            joined = true;
            // the dwell is read from the moment the pair actually starts
            // crossing audio; the tone extension's own cadence is read from
            // when the tone call itself confirmed (`tone_leg.confirmed_at`,
            // set once and never moved), since that is when Asterisk's own
            // Playtones() started counting, not when the echo call happened
            // to catch up and let this end join the two
            joined_at = Some(now);
            next_frame = now;
        }

        if joined && let (Some(a), Some(b)) = (tone_leg.call, echo_leg.call) {
            let since_joined = now.saturating_duration_since(joined_at.unwrap_or(now));
            let cadence = now.saturating_duration_since(tone_leg.confirmed_at.unwrap_or(now));
            if since_joined >= DWELL {
                let _ = endpoint.engine.leave(a);
                let _ = endpoint.agent.hangup(a, now);
                let _ = endpoint.agent.hangup(b, now);
            } else {
                while now >= next_frame {
                    if let Some((mixed, crossed)) = mix_one(&mut endpoint, a, b, cadence, now) {
                        mixed_frames = mixed_frames.saturating_add(u32::from(mixed));
                        crossed_frames = crossed_frames.saturating_add(u32::from(crossed));
                    }
                    next_frame += PACE;
                }
            }
        } else {
            endpoint.run_media(now);
        }
        endpoint.timers(now);

        // both calls over, or one that could not even be placed: whichever
        // it is, the verdict names it
        let over = |leg: &Leg| leg.ended || (leg.attempted && leg.call.is_none());
        if over(&tone_leg) && over(&echo_leg) {
            break;
        }
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    give_back(&mut endpoint, account);
    verdict(&tone_leg, &echo_leg, joined, mixed_frames, crossed_frames)
}

/// Give the binding back, the way every other flow gives its own back, and
/// wait a moment for the registrar to agree. Left in place, it names a port
/// nobody listens on any more for the rest of its lifetime, and the next flow
/// to register the same account shares the account with it: the lab's MESSAGE
/// echo, sent to every contact, went to this one and not to the flow waiting
/// for it.
///
/// `crate::pipewire` gives its own binding back the same way.
pub(crate) fn give_back(endpoint: &mut Endpoint, account: sipral::AccountId) {
    let _ = endpoint.agent.unregister(account, Instant::now());
    let until = Instant::now() + UNREGISTER_PATIENCE;
    loop {
        let now = Instant::now();
        let agreed = endpoint
            .pump(now)
            .iter()
            .any(|event| matches!(event, Event::Signalling(UaEvent::Unregistered { .. })));
        endpoint.timers(now);
        if agreed || now > until {
            endpoint.flush();
            return;
        }
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

fn place(
    endpoint: &mut Endpoint,
    account: sipral::AccountId,
    target: sipral::Uri,
    remote: SocketAddr,
    now: Instant,
) -> Result<CallHandle, String> {
    let media = CallMedia::new(catalog(), MediaConfig::default());
    let outgoing = OutgoingCall::new(target).to_address(endpoint.transport, remote);
    place_call(endpoint, account, outgoing, media, remote, now)
}

/// Whichever of the two legs `call` belongs to, if either.
fn leg_of<'a>(
    call: CallHandle,
    tone_leg: &'a mut Leg,
    echo_leg: &'a mut Leg,
) -> Option<&'a mut Leg> {
    if tone_leg.call == Some(call) {
        Some(tone_leg)
    } else if echo_leg.call == Some(call) {
        Some(echo_leg)
    } else {
        None
    }
}

fn on_event(event: &Event, tone_leg: &mut Leg, echo_leg: &mut Leg, now: Instant) {
    match *event {
        Event::Signalling(UaEvent::CallConfirmed { call, .. }) => {
            if let Some(leg) = leg_of(call, tone_leg, echo_leg) {
                leg.confirmed_at = Some(now);
            }
        }
        Event::Signalling(UaEvent::CallEnded { call, .. }) => {
            if let Some(leg) = leg_of(call, tone_leg, echo_leg) {
                leg.ended = true;
            }
        }
        Event::Media {
            call,
            event: MediaEvent::Started { .. },
        } => {
            if let Some(leg) = leg_of(call, tone_leg, echo_leg) {
                leg.media_started = true;
            }
        }
        _ => {}
    }
}

/// One frame of the joined pair: read whatever arrived on either socket,
/// mix through the facade, and send what each far end is owed.
///
/// Returns `None` for a frame the mix itself refused — a codec that would
/// not cut it, which nothing in this flow's own audio produces — and
/// otherwise says whether a frame went out at all and whether it counted
/// towards [`CROSSED_THRESHOLD`]: audible, in `local_out`, while `cadence` —
/// elapsed since the tone call confirmed — says the tone extension's own
/// cadence should currently be silent. See this module's own documentation
/// for why that can only be the echo extension playing back what this end
/// had just relayed to it.
fn mix_one(
    endpoint: &mut Endpoint,
    tone_call: CallHandle,
    echo_call: CallHandle,
    cadence: Duration,
    now: Instant,
) -> Option<(bool, bool)> {
    if let Some(mut session) = endpoint.engine.session(tone_call)
        && let Some(media) = endpoint.media.get_mut(&tone_call)
    {
        media.receive_into(&mut session, now);
    }
    if let Some(mut session) = endpoint.engine.session(echo_call)
        && let Some(media) = endpoint.media.get_mut(&echo_call)
    {
        media.receive_into(&mut session, now);
    }

    let frame = endpoint.engine.session(tone_call)?.frame_samples();
    let silence = vec![0_i16; frame];
    let mut local_out = vec![0_i16; frame];
    let outcome = endpoint
        .engine
        .mix(tone_call, &silence, &mut local_out, now)
        .ok()?;

    if let (Some((destination, payload)), Some(media)) =
        (&outcome.to_a, endpoint.media.get(&tone_call))
    {
        media.send(*destination, payload);
    }
    if let (Some((destination, payload)), Some(media)) =
        (&outcome.to_b, endpoint.media.get(&echo_call))
    {
        media.send(*destination, payload);
    }

    let crossed = !in_spurt(cadence) && loudness(&local_out) >= AUDIBLE;
    Some((true, crossed))
}

fn verdict(
    tone_leg: &Leg,
    echo_leg: &Leg,
    joined: bool,
    mixed_frames: u32,
    crossed_frames: u32,
) -> Result<String, String> {
    if tone_leg.call.is_none() || echo_leg.call.is_none() {
        return Err("one of the two calls was never placed".to_owned());
    }
    if !tone_leg.media_started || !echo_leg.media_started {
        return Err("one of the two calls never got media on it".to_owned());
    }
    if !joined {
        return Err("the two calls never joined".to_owned());
    }
    if mixed_frames == 0 {
        return Err("joined, but no frame was ever mixed".to_owned());
    }
    if crossed_frames < CROSSED_THRESHOLD {
        return Err(format!(
            "joined and mixed {mixed_frames} frame(s), but only {crossed_frames} were audible \
             while the tone extension's own cadence said it should be silent — the tone extension's \
             own audio, not a relay through the echo extension, may be all that was heard"
        ));
    }
    Ok(format!(
        "   ({mixed_frames} frame(s) mixed, {crossed_frames} carried the tone extension's audio \
         back by way of the echo extension while the tone extension itself was silent)"
    ))
}
