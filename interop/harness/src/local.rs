// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Two of this harness's own endpoints, dialling each other directly over
//! real loopback sockets — no registrar, because there is none to run here.
//!
//! `crates/sipral/src/tests.rs` already proves the facade's own join between
//! two stacks, byte for byte, with no socket under either of them. What that
//! cannot catch is a fault in what *this* crate adds on top of the facade:
//! `Endpoint`'s own SIP loop, and `audio::Media`'s own RTP one — binding a
//! real `UdpSocket`, reading it non-blockingly, pacing a tone against a real
//! clock. This is that other half, run locally because the real lab is not
//! reachable from every machine this builds on. How Kamailio, OpenSIPS,
//! FreeSWITCH and Asterisk take each flow is still `scripts/lab.sh`'s to say.
//!
//! Named `dialling`/`answering` throughout rather than `caller`/`callee`: the
//! two read too much alike for `clippy::similar_names`, which this workspace
//! denies.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use sipral::{
    Account, CallHandle, CallMedia, Codec, DigitSource, Direction, DtmfInfoForm, Event,
    MediaConfig, MediaEvent, OutgoingCall, UaEvent, Uri,
};

use crate::{Endpoint, Fact, Flow, Script, Step, catalog, catalog_for, place_call};

const LOOPBACK: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
const PATIENCE: Duration = Duration::from_secs(10);

fn endpoint(seed: u8) -> Endpoint {
    Endpoint::bind(
        [seed; 32],
        [seed ^ 0x5a; 32],
        SocketAddr::new(LOOPBACK, 0),
        catalog(),
        Instant::now(),
    )
    .expect("binding on loopback")
}

/// An account this end never registers — placing and answering both work
/// without one being registered — kept only so `UserAgent` has one to
/// compute a real `Contact` from. A 2xx answered with no account behind the
/// call carries an empty `Contact`, which RFC 3261 §12.1.1 needs to be real
/// for the far end to have anywhere to send the dialog's next request, and a
/// dialler that gets an empty one drops the response rather than completing
/// a dialog it cannot reach.
fn local_account(endpoint: &Endpoint, name: &str) -> Account {
    Account::new(
        Uri::parse_str(&format!("sip:{name}@127.0.0.1")).expect("a URI"),
        Uri::parse_str("sip:127.0.0.1").expect("a URI"),
        Uri::parse_str(&format!("sip:{name}@{}", endpoint.local)).expect("a URI"),
        endpoint.transport,
        endpoint.local,
    )
}

/// Answer whatever comes in, on a socket this call's own media opens first.
///
/// `route_to` only reads the far end's address to pick which local interface
/// answers it, and on loopback that is `127.0.0.1` whatever the port is, so
/// a fixed address here says the same thing the real one would.
fn answer_everything(endpoint: &mut Endpoint, event: &Event, now: Instant) {
    let elsewhere = SocketAddr::new(LOOPBACK, 1);
    if let Event::Signalling(UaEvent::IncomingCall { call, .. }) = event
        && let Ok(local) = endpoint.open_media(*call, elsewhere, now)
    {
        let _ = endpoint
            .engine
            .answer(&mut endpoint.agent, *call, local, now);
    }
}

/// Whether either side has heard the call confirmed.
fn confirmed(events: &[Event]) -> bool {
    events
        .iter()
        .any(|event| matches!(event, Event::Signalling(UaEvent::CallConfirmed { .. })))
}

fn call_ended(events: &[Event]) -> bool {
    events
        .iter()
        .any(|event| matches!(event, Event::Signalling(UaEvent::CallEnded { .. })))
}

/// Whether a session change was agreed, held or not.
fn session_changed(events: &[Event]) -> bool {
    events
        .iter()
        .any(|event| matches!(event, Event::Signalling(UaEvent::SessionChanged { .. })))
}

/// One round of both endpoints: pump, answer anything that came in, run
/// media, and read the sockets. Returns what each side saw.
fn round(
    dialling: &mut Endpoint,
    answering: &mut Endpoint,
    now: Instant,
) -> (Vec<Event>, Vec<Event>) {
    let dialled = dialling.pump(now);
    let answered = answering.pump(now);
    for event in &answered {
        answer_everything(answering, event, now);
    }
    dialling.run_media(now);
    answering.run_media(now);
    dialling.timers(now);
    answering.timers(now);
    dialling.read_sip(now);
    answering.read_sip(now);
    (dialled, answered)
}

/// Round both endpoints until `until` says stop, or `PATIENCE` runs out —
/// whichever comes first, panicking with `what` on the timeout.
fn round_until(
    dialling: &mut Endpoint,
    answering: &mut Endpoint,
    what: &str,
    mut until: impl FnMut(&[Event], &[Event]) -> bool,
) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        let (dialled, answered) = round(dialling, answering, Instant::now());
        if until(&dialled, &answered) {
            return;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    panic!("{what}");
}

/// Place a call from `dialling` straight at `target`'s address — no
/// registrar, since a direct call needs none.
fn dial(dialling: &mut Endpoint, target: SocketAddr) -> CallHandle {
    let account = dialling
        .agent
        .add_account(local_account(dialling, "dialling"));
    let uri = Uri::parse_str(&format!("sip:answering@{target}")).expect("a URI");
    let outgoing = OutgoingCall::new(uri).to_address(dialling.transport, target);
    let media = CallMedia::new(catalog(), MediaConfig::default());
    place_call(dialling, account, outgoing, media, target, Instant::now()).expect("the INVITE goes")
}

/// A call placed straight at an address connects, carries audio each way
/// over real sockets, and ends cleanly.
#[test]
fn a_direct_call_between_two_of_this_harnesss_own_endpoints_carries_audio() {
    let mut dialling = endpoint(201);
    let mut answering = endpoint(202);
    let _account = answering
        .agent
        .add_account(local_account(&answering, "answering"));
    let call = dial(&mut dialling, answering.local);

    round_until(
        &mut dialling,
        &mut answering,
        "the call never connected over real loopback sockets",
        |dialled, answered| confirmed(dialled) || confirmed(answered),
    );

    // several frames each way: past RFC 3550 A.1's probation on both sides
    let mut heard_audible = 0_u32;
    for _ in 0..40 {
        round(&mut dialling, &mut answering, Instant::now());
        if let Some(answering_call) = answering.engine.active().next() {
            heard_audible += u32::from(
                answering
                    .media
                    .get(&answering_call)
                    .is_some_and(|media| media.heard().audible > 0),
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        heard_audible > 0,
        "no frame decoded on the far end's own real socket ever measured as the tone"
    );

    let _ = dialling.agent.hangup(call, Instant::now());
    let (mut near_ended, mut far_ended) = (false, false);
    round_until(
        &mut dialling,
        &mut answering,
        "the BYE never reached both real sockets",
        |dialled, answered| {
            near_ended |= call_ended(dialled);
            far_ended |= call_ended(answered);
            near_ended && far_ended
        },
    );
}

/// 8.3.11's `Flow::DtmfInfo`, the one piece of it this crate can check
/// without the real lab: a digit sent by `UserAgent::send_dtmf_info` reaches
/// the far end over a real socket and is reported as the same
/// `MediaEvent::DigitReceived` an RFC 4733 one is, told apart by
/// `DigitSource::Info` — not as a `UaEvent::DtmfReceived` of its own, which
/// the facade folds in rather than forwards (see `sipral::Event`'s own
/// module doc). How Asterisk's own dialplan takes it and names it back is
/// `interop/asterisk`'s to say, and only the real lab confirms that half.
#[test]
fn a_digit_sent_by_info_reaches_the_far_end_over_real_loopback_sockets() {
    let mut dialling = endpoint(203);
    let mut answering = endpoint(204);
    let _account = answering
        .agent
        .add_account(local_account(&answering, "answering"));
    let call = dial(&mut dialling, answering.local);

    round_until(
        &mut dialling,
        &mut answering,
        "the call never connected over real loopback sockets",
        |dialled, answered| confirmed(dialled) || confirmed(answered),
    );

    dialling
        .agent
        .send_dtmf_info(call, "7", DtmfInfoForm::Relay, 0, Instant::now())
        .expect("the INFO goes");

    let mut heard = None;
    round_until(
        &mut dialling,
        &mut answering,
        "the digit never reached the far end over real loopback sockets",
        |_, answered| {
            heard = answered.iter().find_map(|event| match event {
                Event::Media {
                    event: MediaEvent::DigitReceived { digit, source, .. },
                    ..
                } => Some((*digit, *source)),
                _ => None,
            });
            heard.is_some()
        },
    );
    assert_eq!(heard, Some((Some('7'), DigitSource::Info)));
}

/// `Flow::HoldCodecChange`'s own mechanism, in full, over real sockets: a
/// call is held, `sipral::MediaEngine::change_codecs` moves it onto another
/// codec while it stays held — the running session carried onto it rather
/// than left in place — and `UserAgent::resume` takes it off hold on the new
/// list rather than the one it was placed with. How Asterisk itself takes
/// the two re-offers is the lab's to say.
#[test]
fn a_held_call_changes_codec_and_the_resume_keeps_the_new_one() {
    let mut dialling = endpoint(211);
    let mut answering = endpoint(212);
    let _account = answering
        .agent
        .add_account(local_account(&answering, "answering"));
    let call = dial(&mut dialling, answering.local);

    round_until(
        &mut dialling,
        &mut answering,
        "the call never connected over real loopback sockets",
        |dialled, answered| confirmed(dialled) || confirmed(answered),
    );
    let before = dialling
        .engine
        .session(call)
        .map(|session| session.codec())
        .expect("the dialling side has media on a call that is up");
    assert_ne!(before, Codec::Pcma, "already on the codec the change names");

    dialling
        .agent
        .hold(call, Instant::now())
        .expect("the hold goes");
    round_until(
        &mut dialling,
        &mut answering,
        "the hold was never agreed",
        |dialled, _| session_changed(dialled),
    );

    dialling
        .engine
        .change_codecs(&mut dialling.agent, call, &["PCMA"], Instant::now())
        .expect("the change goes");
    round_until(
        &mut dialling,
        &mut answering,
        "the change was never agreed",
        |dialled, _| session_changed(dialled),
    );
    assert_eq!(
        dialling.engine.session(call).map(|session| session.codec()),
        Some(Codec::Pcma),
        "the change was agreed, but the codec never moved"
    );
    assert_eq!(
        dialling.agent.hold_state(call).map(|hold| hold.local),
        Some(true),
        "the codec change took the call off hold"
    );

    dialling
        .agent
        .resume(call, Instant::now())
        .expect("the resume goes");
    round_until(
        &mut dialling,
        &mut answering,
        "the resume was never agreed",
        |dialled, _| session_changed(dialled),
    );
    let session = dialling.engine.session(call).expect("media");
    assert_eq!(session.codec(), Codec::Pcma, "the resume went back");
    assert_eq!(session.direction(), Direction::SendRecv);
    drop(session);

    let _ = dialling.agent.hangup(call, Instant::now());
}

/// Whether either side's call finished its DTLS-SRTP handshake.
fn secured(events: &[Event]) -> bool {
    events.iter().any(|event| {
        matches!(
            event,
            Event::Media {
                event: MediaEvent::Secured { .. },
                ..
            }
        )
    })
}

/// Every media failure either side reported, as text.
fn media_failures(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Media {
                event: MediaEvent::Failed(error),
                ..
            } => Some(error.to_string()),
            _ => None,
        })
        .collect()
}

/// How much audible audio each side has heard on its one call.
fn audible(dialling: &Endpoint, answering: &Endpoint) -> (u32, u32) {
    let on = |endpoint: &Endpoint| {
        endpoint
            .media
            .values()
            .map(|media| media.heard().audible)
            .max()
            .unwrap_or(0)
    };
    (on(dialling), on(answering))
}

/// Let the tone run for a second or so, failing on any media failure.
fn talk(dialling: &mut Endpoint, answering: &mut Endpoint, failed: &mut Vec<String>) {
    for _ in 0..60 {
        let (dialled, answered) = round(dialling, answering, Instant::now());
        failed.extend(media_failures(&dialled));
        failed.extend(media_failures(&answered));
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `Flow::Dtls` between two of this crate's own endpoints: a call keyed by a
/// handshake whose records cross real sockets through `Endpoint::run_media`,
/// heard, held, resumed and heard again. What only the real lab can say is
/// how Asterisk answers the two re-offers; that the records get out at all,
/// and that a hold between two conforming ends leaves the association where
/// it was, is said here.
#[test]
fn a_dtls_call_is_keyed_over_real_sockets_and_heard_again_after_a_hold() {
    let keyed = |seed: u8| {
        Endpoint::bind(
            [seed; 32],
            [seed ^ 0x5a; 32],
            SocketAddr::new(LOOPBACK, 0),
            catalog_for(Flow::Dtls),
            Instant::now(),
        )
        .expect("binding on loopback")
    };
    let mut dialling = keyed(221);
    let mut answering = keyed(222);
    let _account = answering
        .agent
        .add_account(local_account(&answering, "answering"));
    let account = dialling
        .agent
        .add_account(local_account(&dialling, "dialling"));
    let target = answering.local;
    let uri = Uri::parse_str(&format!("sip:answering@{target}")).expect("a URI");
    let outgoing = OutgoingCall::new(uri).to_address(dialling.transport, target);
    let media = CallMedia::new(catalog_for(Flow::Dtls), MediaConfig::default());
    let call = place_call(
        &mut dialling,
        account,
        outgoing,
        media,
        target,
        Instant::now(),
    )
    .expect("the INVITE goes");

    let mut failed = Vec::new();
    let (mut near, mut far) = (false, false);
    round_until(
        &mut dialling,
        &mut answering,
        "the handshake never keyed both ends over real loopback sockets",
        |dialled, answered| {
            near |= secured(dialled);
            far |= secured(answered);
            near && far
        },
    );
    talk(&mut dialling, &mut answering, &mut failed);
    let before = audible(&dialling, &answering);
    assert!(
        before.0 > 0 && before.1 > 0,
        "keyed, and the tone never came through: {before:?}"
    );

    for (what, held) in [("hold", true), ("resume", false)] {
        let asked = if held {
            dialling.agent.hold(call, Instant::now())
        } else {
            dialling.agent.resume(call, Instant::now())
        };
        asked.unwrap_or_else(|error| panic!("the {what} did not go: {error}"));
        round_until(
            &mut dialling,
            &mut answering,
            &format!("the {what} was never agreed"),
            |dialled, answered| {
                failed.extend(media_failures(dialled));
                failed.extend(media_failures(answered));
                session_changed(dialled)
            },
        );
    }
    talk(&mut dialling, &mut answering, &mut failed);
    assert!(failed.is_empty(), "media failed: {failed:?}");
    let after = audible(&dialling, &answering);
    assert!(
        after.0 > before.0 && after.1 > before.1,
        "nothing more was heard after the resume: {before:?} then {after:?}"
    );
    let session = dialling.engine.session(call).expect("media");
    assert!(session.is_encrypted());
    assert_eq!(session.direction(), Direction::SendRecv);
    drop(session);

    let _ = dialling.agent.hangup(call, Instant::now());
}

/// The origin a description arrived with, if it parses.
fn origin_of(body: &[u8]) -> Option<sipral_core::sdp::Origin> {
    sipral_core::sdp::parse(body)
        .ok()
        .map(|description| description.origin)
}

/// One re-offer `Flow::HoldCodecChange` sends, and how it is sent.
type Offer = fn(&mut Endpoint, CallHandle);

/// RFC 3264 §8: "When issuing an offer that modifies the session, the "o="
/// line of the new SDP MUST be identical to that in the previous SDP, except
/// that the version in the origin field MUST increment by one from the
/// previous SDP." `Flow::HoldCodecChange` sends two such offers after the
/// hold — the codec change and the resume — so the far end has to see the
/// session id, the user name and the address the call already had on all
/// three, and a version one past the last on each.
#[test]
fn a_codec_change_keeps_the_origin_line_the_call_already_had() {
    let mut dialling = endpoint(251);
    let mut answering = endpoint(252);
    let _account = answering
        .agent
        .add_account(local_account(&answering, "answering"));
    let call = dial(&mut dialling, answering.local);

    // every origin the answering side was handed, in the order it was handed
    let mut origins = Vec::new();
    let mut note = |answered: &[Event]| {
        for event in answered {
            let body = match event {
                Event::Signalling(UaEvent::IncomingCall { request, .. }) => {
                    Some(request.as_raw().body().to_vec())
                }
                Event::Signalling(UaEvent::SessionChanged {
                    remote: Some(remote),
                    ..
                }) => Some(remote.to_vec()),
                _ => None,
            };
            if let Some(origin) = body.as_deref().and_then(origin_of)
                && origins.last() != Some(&origin)
            {
                origins.push(origin);
            }
        }
    };

    round_until(
        &mut dialling,
        &mut answering,
        "the call never connected over real loopback sockets",
        |dialled, answered| {
            note(answered);
            confirmed(dialled)
        },
    );
    // the flow's own three offers, in its own order, each agreed before the
    // next goes
    let offers: [(&str, Offer); 3] = [
        ("the hold", |end, call| {
            end.agent.hold(call, Instant::now()).expect("the hold goes");
        }),
        ("the change", |end, call| {
            end.engine
                .change_codecs(&mut end.agent, call, &["PCMA"], Instant::now())
                .expect("the change goes");
        }),
        ("the resume", |end, call| {
            end.agent
                .resume(call, Instant::now())
                .expect("the resume goes");
        }),
    ];
    for (what, offer) in offers {
        offer(&mut dialling, call);
        round_until(
            &mut dialling,
            &mut answering,
            &format!("{what} was never agreed"),
            |dialled, answered| {
                note(answered);
                session_changed(dialled)
            },
        );
    }

    let [placed, later @ ..] = origins.as_slice() else {
        panic!("the far end saw no offer at all");
    };
    assert_eq!(
        later.len(),
        3,
        "expected the hold, the change and the resume after the offer, and the far end saw \
         {origins:#?}"
    );
    let mut previous = placed;
    for (what, origin) in ["the hold", "the change", "the resume"]
        .into_iter()
        .zip(later)
    {
        assert_eq!(
            (&origin.username, origin.session_id, &origin.address),
            (&placed.username, placed.session_id, &placed.address),
            "{what} moved the o= line the call was placed with"
        );
        assert_eq!(
            origin.version,
            previous.version + 1,
            "{what}'s version is not one past the one before it"
        );
        previous = origin;
    }

    let _ = dialling.agent.hangup(call, Instant::now());
}

/// `MediaSession::playback` is one frame of the device's time per call, which
/// is what lets the jitter buffer hold a delay at all. The loop that drives it
/// turns whenever a socket has something or a few milliseconds have passed —
/// far more often than every twenty — and a frame taken on every turn drains
/// the buffer as fast as packets arrive, so the result line's `delay`,
/// `shrunk` and `stretched` describe the loop rather than the path, and the
/// blackout profile's question, whether the delay recovers after the gap, has
/// nothing left to measure.
#[test]
fn playback_takes_one_frame_per_frame_of_time_however_often_the_loop_turns() {
    let mut dialling = endpoint(241);
    let mut answering = endpoint(242);
    let _account = answering
        .agent
        .add_account(local_account(&answering, "answering"));
    let call = dial(&mut dialling, answering.local);
    round_until(
        &mut dialling,
        &mut answering,
        "the call never connected over real loopback sockets",
        |dialled, _| confirmed(dialled),
    );
    // both ways, long enough for the answering side's buffer to be playing
    for _ in 0..20 {
        round(&mut dialling, &mut answering, Instant::now());
        std::thread::sleep(Duration::from_millis(20));
    }
    let answering_call = answering
        .engine
        .active()
        .next()
        .expect("the answering side has media");
    let audible = |endpoint: &Endpoint| {
        endpoint
            .media
            .get(&answering_call)
            .map(|media| media.heard().audible)
            .unwrap_or_default()
    };

    // one more turn of the answering side's own, so that everything it has
    // played so far is behind this instant and the budget below starts here
    let since = Instant::now();
    answering.run_media(since);
    let before = audible(&answering);

    // ten frames of tone land at once, as a network that held them delivers
    let mut burst = Vec::new();
    {
        let mut session = dialling
            .engine
            .session(call)
            .expect("the dialling side's media");
        let mut samples = vec![0_i16; session.frame_samples()];
        let mut phase = 0_u32;
        let rate = session.sample_rate();
        for _ in 0..10 {
            crate::audio::tone(&mut samples, &mut phase, rate);
            if let Ok(Some(datagram)) = session.capture(&samples, Instant::now()) {
                burst.push((datagram.destination, datagram.payload.to_vec()));
            }
        }
    }
    assert_eq!(burst.len(), 10, "every frame of the burst encodes");
    let socket = dialling
        .media
        .get(&call)
        .expect("the dialling side's socket");
    for (destination, payload) in &burst {
        socket.send(*destination, payload);
    }

    // the answering loop turning every millisecond or so, for forty of them
    while since.elapsed() < Duration::from_millis(40) {
        answering.run_media(Instant::now());
        std::thread::sleep(Duration::from_millis(1));
    }
    let elapsed = since.elapsed();
    let played = audible(&answering).saturating_sub(before);
    let due = u32::try_from(elapsed.as_millis() / 20 + 1).unwrap_or(u32::MAX);
    assert!(
        played <= due,
        "{played} frames of tone played in {elapsed:?}, where a device takes {due}"
    );
}

/// A call's RTP socket is bound before the call is placed, because the offer
/// has to name its port, and a real far end takes its time to answer: auth
/// challenges, ringing, a person. None of that is time a microphone was
/// running, so the call's first turn of media sends the frame that is due
/// now, not every frame that would have been due since the socket was bound —
/// a burst the far end's buffer has to swallow at the start of every call,
/// and a `sent` count that measures the setup rather than the call.
#[test]
fn the_first_turn_of_a_calls_media_does_not_send_a_burst_for_the_setup_time() {
    let mut dialling = endpoint(231);
    let mut answering = endpoint(232);
    let _account = answering
        .agent
        .add_account(local_account(&answering, "answering"));
    let call = dial(&mut dialling, answering.local);

    // a far end that takes a while to answer, as every real one does
    std::thread::sleep(Duration::from_millis(400));
    round_until(
        &mut dialling,
        &mut answering,
        "the call never connected over real loopback sockets",
        |dialled, _| confirmed(dialled),
    );

    let sent = dialling
        .media
        .get(&call)
        .map(|media| media.heard().sent)
        .unwrap_or_default();
    assert!(
        (1..=2).contains(&sent),
        "the call's first turn of media put {sent} frames on the wire at once"
    );
}

/// The result line's `lost`, `late`, `jitter`, `delay`, `shrunk` and
/// `stretched` are read once the flow is over, and every flow that passes is
/// over because its call ended — at which point `sipral::MediaEngine` has
/// already let the session go. What the call's media cost is still there, in
/// the `MediaEvent::Ended` that closed it; a result line read from the engine
/// afterwards has nothing to read and silently prints none of it.
#[test]
fn the_result_line_still_has_the_calls_quality_once_the_call_has_ended() {
    let mut dialling = endpoint(221);
    let mut answering = endpoint(222);
    let _account = answering
        .agent
        .add_account(local_account(&answering, "answering"));
    let call = dial(&mut dialling, answering.local);
    let account = dialling
        .agent
        .add_account(local_account(&dialling, "scripted"));
    let mut script = Script::new(
        Flow::Call,
        account,
        "answering",
        "elsewhere",
        "127.0.0.1",
        answering.local,
        Instant::now(),
    );
    script.call = Some(call);
    // already placed, so nothing the script's own advance does moves it on
    script.step = Step::Placing;

    let mut hung_up = false;
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline && script.step != Step::Done {
        let now = Instant::now();
        let (dialled, _) = round(&mut dialling, &mut answering, now);
        for event in &dialled {
            script.on_event(&mut dialling, event, now);
        }
        if !hung_up
            && script.seen.has(Fact::Up)
            && dialling
                .media
                .get(&call)
                .is_some_and(|media| media.heard().received > 10)
        {
            hung_up = true;
            dialling.agent.hangup(call, now).expect("the BYE goes");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(hung_up, "no audio ever arrived to hang up on");
    assert!(script.seen.has(Fact::Over), "the call never ended");

    let quality = script.quality(&mut dialling, Instant::now());
    assert!(
        quality.is_some_and(|quality| quality.received > 0),
        "the call carried audio and ended, and the result line has no quality to print: \
         {quality:?}"
    );
}
