// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The SIP and RTP half of a socket-framed voice agent: answers whatever
//! calls it, and carries the audio, the voice activity, the DTMF and the
//! call state across a TCP socket in `sipral-headless`'s own wire protocol,
//! for a separate agent process to read and write —
//! `docs/07-headless.md#real-media` is the design this binary is.
//!
//! This is the application side: it owns the SIP dialog, the RTP session and
//! the socket. `crates/sipral-headless/examples/agent.rs` is the other side
//! — a minimal reference agent that answers with an echo and a digit,
//! depending on nothing but `sipral-headless` itself, the way a real agent
//! process depends on nothing but that crate and whatever speech model it
//! wraps.
//!
//! Simplified from what `sipral_headless::SessionRegistry` can actually
//! carry: one call at a time, one TCP connection, accepted once at startup
//! before the SIP side comes up — the shape the interop lab's own flow
//! needs and no more. The protocol has nothing against more than one of
//! either; this binary just does not build it.
//!
//! The call's own RTP is driven by hand, on a raw `UdpSocket`, rather than
//! through `common/media_socket.rs`'s shared `MediaSocket::turn`: that
//! helper hands an application two closures, one for what it captures and
//! one for what it heard, and both of them need `&mut` access to the same
//! `HeadlessSession` here — one to fill a frame from its queue, the other to
//! queue what was just decoded. Two closures each holding their own
//! exclusive borrow of the same session cannot coexist as one call's
//! arguments, so this binary paces its own tick instead, the same twenty
//! milliseconds apart.
//!
//! ```text
//! cargo run --example headless-socket-agent --features headless -- \
//!     --host 127.0.0.1 --port 5070 --socket 0.0.0.0:7001
//! ```
//!
//! The socket's own audio is fixed at 16 kHz; the codec catalogue is G.711
//! only, so every call is 8 kHz regardless of which law is chosen, and
//! `HeadlessSession` resamples between the two both ways — proving that seam
//! rather than assuming the two rates happen to agree.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

#[path = "common/entropy.rs"]
mod entropy;
// `udp_endpoint.rs` itself names `crate::media_socket::MediaSocket` in its
// own `Endpoint`, even though this binary never calls `MediaSocket::turn` —
// see this file's own doc comment for why.
#[path = "common/media_socket.rs"]
mod media_socket;
#[path = "common/udp_endpoint.rs"]
mod udp_endpoint;

use std::env;
use std::io::Write as _;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::ops::ControlFlow;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use sipral::{
    Account, CallHandle, CodecCatalog, EndpointConfig, Event, MediaConfig, MediaEngine, MediaEvent,
    StatusCode, UaEvent, Uri, UserAgent, WallClock,
};
use sipral_headless::{
    AudioConfig, CallState, CallStateKind, ControlMessage, Decoded, Decoder, IncomingCall,
    SampleRate, SessionOpen, VoiceActivity, encode_audio, encode_control,
};

use udp_endpoint::Endpoint;

/// This socket's own audio: independent of the codec any call negotiates —
/// `docs/07-headless.md`'s whole point — and fixed here rather than
/// negotiated with the agent, which this simplified binary does not do.
fn session_audio() -> AudioConfig {
    AudioConfig::new(SampleRate::Hz16000)
}

/// G.711 only, both laws 8 kHz: this binary always knows a call's codec rate
/// without waiting for the negotiation to settle, which is what lets it open
/// a `HeadlessSession` in the same tick `IncomingCall` arrives in.
fn codecs() -> CodecCatalog {
    CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("both are always in this build")
}

const CODEC_RATE: u32 = 8_000;
const PACE: Duration = Duration::from_millis(20);

fn args() -> (std::net::IpAddr, u16, SocketAddr) {
    let mut host = std::net::IpAddr::from([127, 0, 0, 1]);
    let mut port = 5070_u16;
    let mut socket = SocketAddr::from(([0, 0, 0, 0], 7001));
    let mut it = env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--host" => {
                if let Some(v) = it.next().and_then(|t| t.parse().ok()) {
                    host = v;
                }
            }
            "--port" => {
                if let Some(v) = it.next().and_then(|t| t.parse().ok()) {
                    port = v;
                }
            }
            "--socket" => {
                if let Some(v) = it.next().and_then(|t| t.parse().ok()) {
                    socket = v;
                }
            }
            _ => {}
        }
    }
    (host, port, socket)
}

/// One complete message read off the agent's own socket.
enum FromAgent {
    Audio(Vec<u8>),
    Control(ControlMessage),
}

/// Reads the agent's socket on a thread of its own, so the main loop never
/// blocks on it: SIP, RTP and the socket all move at their own pace, and a
/// slow or silent agent must not stall a call's signalling.
fn read_agent(mut stream: TcpStream) -> Receiver<FromAgent> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut decoder = Decoder::new(session_audio()).expect("the fixed session audio is valid");
        let mut buf = [0_u8; 4_096];
        loop {
            let read = match std::io::Read::read(&mut stream, &mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            decoder.push(buf.get(..read).unwrap_or_default());
            loop {
                match decoder.next_message() {
                    Ok(Some(Decoded::Audio(payload))) => {
                        if tx.send(FromAgent::Audio(payload.to_vec())).is_err() {
                            return;
                        }
                    }
                    Ok(Some(Decoded::Control(message))) => {
                        if tx.send(FromAgent::Control(message)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => break,
                    // a malformed frame ends the connection; there is no way
                    // to resynchronise to a length that lied
                    Err(_) => return,
                }
            }
        }
    });
    rx
}

/// One call's socket-side state: its own RTP socket, the `HeadlessSession`
/// that resamples and queues its audio, and the wire's own call id.
struct Bridge {
    call: CallHandle,
    call_id: String,
    rtp: UdpSocket,
    session: sipral::HeadlessSession,
    /// Set the moment `UaEvent::CallEnded` arrives, which — `MediaEngine`'s
    /// own event order — is always before the `MediaEvent::Ended` that
    /// carries this call's final statistics. Kept rather than clearing
    /// `bridge` straight away, so that later event still finds a `call_id`
    /// to report against; `bridge` itself is only cleared once that arrives.
    ended: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (host, port, socket_addr) = args();
    let now = Instant::now();
    let agent = UserAgent::new(EndpointConfig::default(), entropy::seed()?)?;
    let engine = MediaEngine::new(
        codecs(),
        MediaConfig::default(),
        WallClock::from_unix(now, 0, 0),
        entropy::seed()?,
    );
    let mut endpoint = Endpoint::bind(SocketAddr::new(host, port), agent, engine, now)?;
    let identity = Uri::parse_str(&format!("sip:agent@{}", endpoint.local))?;
    endpoint.add_account(Account::unregistered(
        identity.clone(),
        identity,
        endpoint.transport,
        endpoint.local,
    ));
    println!(
        "listening on {}; dial sip:agent@{}",
        endpoint.local, endpoint.local
    );

    println!("waiting for the agent to connect on {socket_addr}");
    let listener = TcpListener::bind(socket_addr)?;
    let (mut socket, from) = listener.accept()?;
    println!("agent connected from {from}");
    let reader = read_agent(socket.try_clone()?);

    let mut bridge: Option<Bridge> = None;
    let mut agent_up = false;
    let mut next_tick = now;
    let mut out = Vec::new();

    loop {
        let turn = Instant::now();

        for event in endpoint.pump(turn) {
            handle_event(
                &mut endpoint,
                &mut bridge,
                &mut agent_up,
                &mut out,
                &event,
                turn,
            );
        }

        if drain_agent(&reader, &mut endpoint, &mut bridge, turn).is_break() {
            println!("the agent's socket closed");
            return Ok(());
        }

        if let Some(active) = bridge.as_mut()
            && let Some(mut media) = endpoint.engine.session(active.call)
        {
            drive_bridge(active, &mut media, agent_up, &mut next_tick, &mut out, turn);
        }

        if !out.is_empty() {
            let _ = socket.write_all(&out);
            out.clear();
        }

        endpoint.timers(turn);
        if !endpoint.read_sip(turn) {
            thread::sleep(Duration::from_millis(5));
        }
    }
}

/// Everything the agent's own socket had queued: audio goes straight onto
/// this call's playback queue, `Hangup` ends the call, `DtmfSend` dials a
/// digit. `ControlFlow::Break` once the socket has closed for good.
fn drain_agent(
    reader: &Receiver<FromAgent>,
    endpoint: &mut Endpoint,
    bridge: &mut Option<Bridge>,
    turn: Instant,
) -> ControlFlow<()> {
    loop {
        match reader.try_recv() {
            Ok(FromAgent::Audio(payload)) => {
                if let Some(active) = bridge.as_mut() {
                    let _ = active.session.protocol_mut().push_playback(payload);
                }
            }
            Ok(FromAgent::Control(ControlMessage::Hangup(msg))) => {
                if let Some(active) = bridge.as_ref().filter(|b| b.call_id == msg.call_id) {
                    let _ = endpoint.agent.hangup(active.call, turn);
                }
            }
            Ok(FromAgent::Control(ControlMessage::DtmfSend(msg))) => {
                if let Some(active) = bridge.as_ref().filter(|b| b.call_id == msg.call_id)
                    && let Some(mut media) = endpoint.engine.session(active.call)
                {
                    let duration = msg.duration_ms.map_or(sipral::DEFAULT_DIGIT, |ms| {
                        Duration::from_millis(u64::from(ms))
                    });
                    let _ = sipral::send_digit(&mut media, msg.digit, duration);
                }
            }
            Ok(FromAgent::Control(_)) => {}
            Err(TryRecvError::Empty) => return ControlFlow::Continue(()),
            Err(TryRecvError::Disconnected) => return ControlFlow::Break(()),
        }
    }
}

/// One call's own RTP for this tick: whatever arrived goes to `media`, and —
/// once a media tick is due — the caller's decoded audio is heard, its
/// voice activity and whatever the queue had ready are written to `out` as
/// wire frames, and whatever the agent had queued for playback is sent as
/// the next RTP packet.
fn drive_bridge(
    active: &mut Bridge,
    media: &mut sipral::MediaSession,
    agent_up: bool,
    next_tick: &mut Instant,
    out: &mut Vec<u8>,
    turn: Instant,
) {
    if active.ended {
        return;
    }
    let mut inbox = [0_u8; 2_048];
    while let Ok((length, from)) = active.rtp.recv_from(&mut inbox) {
        let datagram = inbox.get_mut(..length).unwrap_or_default();
        let _ = media.receive(datagram, from, turn);
    }
    if !agent_up || turn < *next_tick {
        return;
    }
    *next_tick += PACE;
    let frame = media.frame_samples();
    let mut decoded = vec![0_i16; frame];
    let _ = media.playback(&mut decoded);
    if let Some(speaking) = active.session.hear(&decoded) {
        let _ = encode_control(
            &ControlMessage::VoiceActivity(VoiceActivity {
                call_id: active.call_id.clone(),
                speaking,
            }),
            out,
        );
    }
    while let Some(bytes) = active.session.protocol_mut().pop_capture() {
        let _ = encode_audio(session_audio(), &bytes, out);
    }
    if let Ok(Some(datagram)) = active.session.speak(media, turn) {
        let _ = active.rtp.send_to(datagram.payload, datagram.destination);
    }
}

/// Takes an incoming call: its own RTP socket and `HeadlessSession`, the
/// session's opening and the caller on the wire, then the answer.
fn open_bridge(
    endpoint: &mut Endpoint,
    bridge: &mut Option<Bridge>,
    out: &mut Vec<u8>,
    call: CallHandle,
    now: Instant,
) {
    let Ok(rtp) = UdpSocket::bind((endpoint.local.ip(), 0)) else {
        return;
    };
    if rtp.set_nonblocking(true).is_err() {
        return;
    }
    let Ok(local) = rtp.local_addr() else {
        return;
    };
    let call_id = format!("{call:?}");
    let Ok(session) =
        sipral::HeadlessSession::open(call_id.clone(), session_audio(), CODEC_RATE, 50, 50)
    else {
        return;
    };
    *bridge = Some(Bridge {
        call,
        call_id: call_id.clone(),
        rtp,
        session,
        ended: false,
    });
    let _ = encode_control(
        &ControlMessage::SessionOpen(SessionOpen::new(session_audio().sample_rate())),
        out,
    );
    // Who is calling comes out of the INVITE's own `From`, read while the
    // call is still known to the agent.
    let identity = endpoint.agent.call_identity(call);
    let caller = identity.as_ref().map_or_else(String::new, |who| {
        String::from_utf8_lossy(&who.from_uri).into_owned()
    });
    let display_name = identity
        .as_ref()
        .map(|who| String::from_utf8_lossy(&who.from_display).into_owned())
        .filter(|name| !name.is_empty());
    let _ = encode_control(
        &ControlMessage::IncomingCall(IncomingCall {
            call_id: call_id.clone(),
            caller,
            display_name,
        }),
        out,
    );
    if endpoint
        .engine
        .answer(&mut endpoint.agent, call, local, now)
        .is_ok()
    {
        println!("answered {call_id}");
    }
}

fn handle_event(
    endpoint: &mut Endpoint,
    bridge: &mut Option<Bridge>,
    agent_up: &mut bool,
    out: &mut Vec<u8>,
    event: &Event,
    now: Instant,
) {
    if let Event::Signalling(sig) = event
        && let Some(active) = bridge.as_ref()
        && let Some((call, state)) = sipral::call_state_of(sig)
        && call == active.call
    {
        if matches!(state, CallStateKind::Answered) {
            *agent_up = true;
        }
        let _ = encode_control(
            &ControlMessage::CallState(CallState {
                call_id: active.call_id.clone(),
                state,
            }),
            out,
        );
    }
    match event {
        Event::Signalling(UaEvent::IncomingCall { call, .. })
            if bridge.as_ref().is_none_or(|b| b.ended) =>
        {
            open_bridge(endpoint, bridge, out, *call, now);
        }
        // A second call while one is already bridged: this binary only
        // ever drives one `Bridge` at a time (its own doc comment says so),
        // so it declines rather than leaving the caller ringing forever.
        Event::Signalling(UaEvent::IncomingCall { call, .. }) => {
            let _ = endpoint.agent.reject(*call, StatusCode::BUSY_HERE, now);
        }
        // Only the bridged call's own end stops its audio: the call refused
        // just above ends too, and its end is not this one's.
        Event::Signalling(UaEvent::CallEnded { call, .. }) => {
            if let Some(active) = bridge.as_mut().filter(|b| b.call == *call) {
                active.ended = true;
                *agent_up = false;
            }
        }
        Event::Media {
            call,
            event: MediaEvent::DigitReceived { digit, held, .. },
        } => {
            if let Some(active) = bridge.as_ref().filter(|b| b.call == *call)
                && let Some(received) =
                    sipral::dtmf_received_of(active.call_id.clone(), *digit, *held)
            {
                println!("dtmf {}", received.digit.get());
                let _ = encode_control(&ControlMessage::DtmfReceived(received), out);
            }
        }
        Event::Media {
            call,
            event: MediaEvent::Ended(stats),
        } => {
            if bridge.as_ref().is_some_and(|b| b.call == *call)
                && let Some(active) = bridge.take()
            {
                println!(
                    "ended {}: packets_received={} packets_sent={}",
                    active.call_id, stats.quality.received, stats.packets_sent
                );
            }
        }
        _ => {}
    }
}
