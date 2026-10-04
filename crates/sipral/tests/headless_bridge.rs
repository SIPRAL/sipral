// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! In-process proof that `sipral::HeadlessSession` carries real audio, real
//! voice activity, a real digit and real call state across a real call.
//!
//! Two stacks on loopback, the same shape as
//! `crates/sipral/examples/headless-agent.rs`'s own test: a plain facade
//! caller places the call, plays a tone once it is up, dials a digit, then
//! holds the call and resumes it — two re-INVITEs, which must reach the
//! agent as two changes and never as a second `answered` — and the other
//! end answers it with a `HeadlessSession` driven directly against
//! `sipral::MediaSession` — no socket, no `sipral-headless` wire framing, the
//! in-process path `docs/07-headless.md#real-media` describes. What a socket
//! path would frame as bytes is read here as plain Rust values instead:
//! `HeadlessSession::hear`/`speak` for audio, `sipral::call_state_of` for
//! this call's `UaEvent`s and `sipral::dtmf_received_of` for the digit.
//!
//! Only builds with the `headless` feature, which brings in `sipral-headless`
//! and everything this test names from it.

#![cfg(feature = "headless")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

#[path = "../examples/common/media_socket.rs"]
mod media_socket;
#[path = "../examples/common/udp_endpoint.rs"]
mod udp_endpoint;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use sipral::{
    Account, CallHandle, CodecCatalog, DEFAULT_DIGIT, Digit, EndpointConfig, Event, MediaConfig,
    MediaEngine, MediaEvent, OutgoingCall, UaEvent, Uri, UserAgent, WallClock,
};
use sipral_headless::{AudioConfig, CallStateKind, DtmfReceived, SampleRate};

use udp_endpoint::Endpoint;

/// How often the agent side's own media tick runs, matching
/// `media_socket::PACE` — the two are independent constants rather than one
/// shared, since the agent side paces itself by hand instead of through
/// `MediaSocket::turn`, on purpose: that closure shape has no seam for
/// `HeadlessSession::hear`/`speak` to sit in, and the whole point of this
/// test is to drive them for real.
const PACE: Duration = Duration::from_millis(20);

const TONE: i16 = 12_000;
const WARM_UP_FRAMES: u32 = 5;

/// Run more than once before giving up, for the reason
/// `headless-agent.rs`'s own test gives: a real UDP send can sit long enough
/// in the kernel's queue on a busy machine that RFC 3550's own source
/// probation reads the gap as a lost stream.
#[test]
fn an_in_process_headless_session_hears_a_tone_and_a_digit_and_answers_with_audio() {
    let mut last_failure = String::new();
    for _ in 0..3 {
        match one_call() {
            Ok(()) => return,
            Err(reason) => last_failure = reason,
        }
    }
    panic!("{last_failure}");
}

/// G.711 only, matching `headless-agent.rs`'s own test: each sample is coded
/// on its own rather than perceptually, so a tone survives the round trip
/// recognisably, which is all this test reads.
fn codecs() -> CodecCatalog {
    CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("both are always in this build")
}

/// One event off the agent's own SIP stack: `call_state_of` against it
/// first (for this test's one call, or the call about to become it), then
/// this test's own setup — opening the `HeadlessSession` and answering on
/// `IncomingCall`, and reading a dialled digit through `dtmf_received_of` on
/// `MediaEvent::DigitReceived`.
#[allow(clippy::too_many_arguments)]
fn handle_agent_event(
    agent_endpoint: &mut Endpoint,
    agent_rtp_addr: SocketAddr,
    event: &Event,
    turn: Instant,
    headless: &mut Option<sipral::HeadlessSession>,
    agent_call: &mut Option<CallHandle>,
    agent_up: &mut bool,
    heard_digit: &mut Option<DtmfReceived>,
    saw_ringing: &mut bool,
    answered: &mut u32,
    changes: &mut u32,
) {
    if let Event::Signalling(sig) = event
        && let Some((call, state)) = sipral::call_state_of(sig)
        && agent_call.is_none_or(|known| known == call)
    {
        match state {
            CallStateKind::Ringing => *saw_ringing = true,
            CallStateKind::Answered => {
                *answered += 1;
                *agent_up = true;
            }
            CallStateKind::Ended { .. } => {}
        }
    }
    // a hold or a resume from the caller: handed to the session the way
    // `docs/07-headless.md` says to hand every `Changed`, same rate or not
    if let Event::Media {
        call,
        event: MediaEvent::Changed { codec, .. },
    } = event
        && agent_call.is_some_and(|known| known == *call)
        && let Some(session) = headless.as_mut()
    {
        *changes += 1;
        session
            .set_codec_rate(codec.sample_rate())
            .expect("G.711 again, at the rate it had");
    }
    match event {
        Event::Signalling(UaEvent::IncomingCall { call, .. }) => {
            let call = *call;
            let session = sipral::HeadlessSession::open(
                "call-1".to_owned(),
                AudioConfig::new(SampleRate::Hz16000),
                8_000,
                50,
                50,
            )
            .expect("eight to sixteen kilohertz bridges fine");
            *headless = Some(session);
            *agent_call = Some(call);
            agent_endpoint
                .engine
                .answer(&mut agent_endpoint.agent, call, agent_rtp_addr, turn)
                .expect("this build's own offer is always answerable");
        }
        Event::Media {
            event: MediaEvent::DigitReceived { digit, held, .. },
            ..
        } => {
            *heard_digit = sipral::dtmf_received_of("call-1".to_owned(), *digit, *held);
        }
        _ => {}
    }
}

/// One tick of the agent's own call: drain whatever RTP arrived, and, once
/// a media tick is due, hear the caller's audio, echo it straight back —
/// exactly as a trivial agent connected over the wire protocol would relay
/// it, by copying bytes between the two queues — and speak whatever that
/// produced.
fn drive_agent_call(
    agent_rtp: &UdpSocket,
    agent_inbox: &mut [u8],
    media: &mut sipral::MediaSession,
    session: &mut sipral::HeadlessSession,
    agent_up: bool,
    next_tick: &mut Instant,
    turn: Instant,
) {
    while let Ok((length, from)) = agent_rtp.recv_from(agent_inbox) {
        let datagram = agent_inbox.get_mut(..length).unwrap_or_default();
        let _ = media.receive(datagram, from, turn);
    }
    if !agent_up || turn < *next_tick {
        return;
    }
    *next_tick += PACE;
    let frame = media.frame_samples();
    let mut decoded = vec![0_i16; frame];
    let _ = media.playback(&mut decoded);
    let _ = session.hear(&decoded);

    while let Some(bytes) = session.protocol_mut().pop_capture() {
        let _ = session.protocol_mut().push_playback(bytes);
    }

    if let Ok(Some(datagram)) = session.speak(media, turn) {
        let _ = agent_rtp.send_to(datagram.payload, datagram.destination);
    }
}

/// One tick of the caller's own call: notice once it is confirmed, dial the
/// digit the instant it is, and — while up — play the tone through
/// `MediaSocket::turn` and keep whatever it heard back.
fn drive_caller_call(
    caller_endpoint: &mut Endpoint,
    call: CallHandle,
    turn: Instant,
    up: &mut bool,
    dtmf_sent: &mut bool,
    frames_sent: &mut u32,
    heard: &mut Vec<i16>,
) {
    for event in caller_endpoint.pump(turn) {
        if matches!(
            event,
            Event::Signalling(UaEvent::CallConfirmed { call: this, .. }) if this == call
        ) {
            *up = true;
        }
    }
    if *up && !*dtmf_sent {
        if let Some(mut session) = caller_endpoint.engine.session(call) {
            session
                .send_dtmf(
                    Digit::from_char('5').expect("a keypad digit"),
                    DEFAULT_DIGIT,
                )
                .expect("this call negotiated named events");
        }
        *dtmf_sent = true;
    }
    if !*up {
        return;
    }
    caller_endpoint.run_media(turn, |this, media, session, now| {
        if this != call {
            return;
        }
        media.turn(
            session,
            now,
            |room| {
                *frames_sent += 1;
                if *frames_sent >= WARM_UP_FRAMES {
                    room.fill(TONE);
                } else {
                    room.fill(0);
                }
            },
            |room| heard.extend_from_slice(room),
        );
    });
}

/// Both stacks, bound on loopback, with the caller's own call already placed
/// at the agent — everything `one_call` needs before it can start driving
/// either side's tick.
fn setup(now: Instant) -> (Endpoint, Endpoint, CallHandle, UdpSocket) {
    let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

    let mut agent_endpoint = Endpoint::bind(
        loopback,
        UserAgent::new(EndpointConfig::default(), [0x31; 32]).unwrap(),
        MediaEngine::new(
            codecs(),
            MediaConfig::default(),
            WallClock::from_unix(now, 0, 0),
            [0x32; 32],
        ),
        now,
    )
    .unwrap();
    let agent_identity = Uri::parse_str(&format!("sip:agent@{}", agent_endpoint.local)).unwrap();
    agent_endpoint.add_account(Account::unregistered(
        agent_identity.clone(),
        agent_identity,
        agent_endpoint.transport,
        agent_endpoint.local,
    ));

    let mut caller_endpoint = Endpoint::bind(
        loopback,
        UserAgent::new(EndpointConfig::default(), [0x41; 32]).unwrap(),
        MediaEngine::new(
            codecs(),
            MediaConfig::default(),
            WallClock::from_unix(now, 0, 0),
            [0x42; 32],
        ),
        now,
    )
    .unwrap();
    let aor = Uri::parse_str("sip:caller@invalid.example").unwrap();
    let contact = Uri::parse_str(&format!("sip:caller@{}", caller_endpoint.local)).unwrap();
    let account = caller_endpoint.add_account(Account::unregistered(
        aor,
        contact,
        caller_endpoint.transport,
        agent_endpoint.local,
    ));
    let target = Uri::parse_str(&format!("sip:agent@{}", agent_endpoint.local)).unwrap();
    let outgoing =
        OutgoingCall::new(target).to_address(caller_endpoint.transport, agent_endpoint.local);
    let call = udp_endpoint::place(&mut caller_endpoint, account, outgoing, now).unwrap();

    // The agent's own RTP socket, bound and driven by hand rather than
    // through `MediaSocket`: see `PACE`'s own doc for why.
    let agent_rtp = UdpSocket::bind(loopback).unwrap();
    agent_rtp.set_nonblocking(true).unwrap();

    (agent_endpoint, caller_endpoint, call, agent_rtp)
}

fn one_call() -> Result<(), String> {
    let now = Instant::now();
    let (mut agent_endpoint, mut caller_endpoint, call, agent_rtp) = setup(now);
    let agent_rtp_addr = agent_rtp.local_addr().unwrap();
    let mut agent_inbox = [0_u8; 2_048];
    let mut agent_next_tick = now;

    let mut headless: Option<sipral::HeadlessSession> = None;
    let mut agent_call: Option<CallHandle> = None;
    let mut agent_up = false;
    let mut heard_digit: Option<DtmfReceived> = None;
    let mut saw_ringing = false;
    let mut answered = 0_u32;
    let mut changes = 0_u32;

    let mut dtmf_sent = false;
    let mut frames_sent = 0_u32;
    let mut heard: Vec<i16> = Vec::new();
    let mut up = false;
    let (mut held, mut resumed) = (false, false);

    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && !(resumed && changes >= 2) {
        let turn = Instant::now();
        // the tone and the digit through, the caller holds and then resumes:
        // two re-INVITEs, each a `Changed` at the agent and neither a second
        // `answered` on its wire
        let echoed = heard.iter().any(|sample| sample.abs() > 1_000);
        if up && echoed && heard_digit.is_some() && !held {
            caller_endpoint.agent.hold(call, turn).expect("the hold");
            held = true;
        }
        if held && changes >= 1 && !resumed {
            caller_endpoint
                .agent
                .resume(call, turn)
                .expect("the resume");
            resumed = true;
        }

        for event in agent_endpoint.pump(turn) {
            handle_agent_event(
                &mut agent_endpoint,
                agent_rtp_addr,
                &event,
                turn,
                &mut headless,
                &mut agent_call,
                &mut agent_up,
                &mut heard_digit,
                &mut saw_ringing,
                &mut answered,
                &mut changes,
            );
        }

        if let (Some(call), Some(session)) = (agent_call, headless.as_mut())
            && let Some(mut media) = agent_endpoint.engine.session(call)
        {
            drive_agent_call(
                &agent_rtp,
                &mut agent_inbox,
                &mut media,
                session,
                agent_up,
                &mut agent_next_tick,
                turn,
            );
        }
        agent_endpoint.timers(turn);
        let agent_read = agent_endpoint.read_sip(turn);

        drive_caller_call(
            &mut caller_endpoint,
            call,
            turn,
            &mut up,
            &mut dtmf_sent,
            &mut frames_sent,
            &mut heard,
        );
        caller_endpoint.timers(turn);
        let caller_read = caller_endpoint.read_sip(turn);
        if !agent_read && !caller_read {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    verdict(&Seen {
        up,
        saw_ringing,
        answered,
        changes,
        heard,
        digit: heard_digit,
    })
}

/// What one run of [`one_call`] saw, on both sides, for [`verdict`].
struct Seen {
    up: bool,
    saw_ringing: bool,
    answered: u32,
    changes: u32,
    heard: Vec<i16>,
    digit: Option<DtmfReceived>,
}

fn verdict(seen: &Seen) -> Result<(), String> {
    let Seen {
        up,
        saw_ringing,
        answered,
        changes,
        heard,
        digit,
    } = seen;
    if !up {
        return Err("the call never reached CallConfirmed on the caller side".to_owned());
    }
    if !saw_ringing || *answered == 0 {
        return Err(format!(
            "call_state_of did not see both transitions on real UaEvents: ringing={saw_ringing} answered={answered}"
        ));
    }
    if *changes < 2 {
        return Err(format!(
            "the hold and the resume reached the agent as {changes} Changed events, not two"
        ));
    }
    if *answered != 1 {
        return Err(format!(
            "call_state_of reported the call answered {answered} times across a hold and a resume"
        ));
    }
    if !heard.iter().any(|sample| sample.abs() > 1_000) {
        return Err(format!(
            "nothing came back louder than silence in {} samples \
             -- the in-process HeadlessSession did not echo the tone",
            heard.len()
        ));
    }
    let Some(digit) = digit else {
        return Err(
            "dtmf_received_of never produced a digit from a real DigitReceived event".to_owned(),
        );
    };
    if digit.digit.get() != '5' {
        return Err(format!("wrong digit: {:?}", digit.digit.get()));
    }
    Ok(())
}
