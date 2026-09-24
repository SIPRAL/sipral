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
//! Dialled directly as above, or reached through a server it registers with
//! — `--register user@domain --registrar ip:port --pass secret` — which is
//! how the interop lab runs it behind Asterisk.
//!
//! `--ice-lite` answers as an ICE-lite endpoint (`sipral::IcePolicy::Lite`,
//! `docs/06-nat.md`): the deployment for a server with a public address, and
//! the one a full-ICE peer such as a WebRTC gateway needs before it will send
//! it any audio. The candidate is the media socket's own address, or
//! `--public ip` for a server behind a one-to-one NAT, where that is the
//! address the NAT forwards unchanged to this host. Once the peer nominates
//! a pair it prints `path chosen <local> -> <remote>`.
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

use std::collections::VecDeque;
use std::env;
use std::io::Write as _;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use sipral::{
    Account, CallHandle, CallMedia, CodecCatalog, Credentials, EndpointConfig, Event, IcePolicy,
    MediaConfig, MediaEngine, MediaError, MediaEvent, StatusCode, UaEvent, Uri, UserAgent,
    WallClock,
};
use sipral_core::msg::HeaderName;
use sipral_headless::{
    AudioConfig, CallState, CallStateKind, ControlMessage, DecodeError, Decoded, Decoder,
    ErrorCode, ErrorMessage, HEADER_LEN, IncomingCall, SampleRate, SessionOpen, VoiceActivity,
    encode_audio, encode_control,
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

/// Writes the writer thread may have under way at once, beyond what the
/// kernel's own send buffer already holds. Past that the agent is not
/// reading, and what it has not taken waits here, turn by turn, in order.
const WRITES_IN_FLIGHT: usize = 4;

/// Turns of the caller's audio held for an agent that is not reading — one
/// second at the twenty milliseconds a turn — past which the oldest turn's
/// audio is the one that goes, the policy the capture queue itself keeps.
const MOST_AUDIO_TURNS: usize = 50;

/// Control bytes held back for an agent that has stopped reading, past which
/// it is taken for gone. Control is never dropped the way audio is: a missed
/// `CallState` or `VoiceActivity` is a lie about the call, not a gap in it.
const MOST_HELD: usize = 64 * 1_024;

/// How much of the caller's address and display name reach the agent, each.
/// Both come off an INVITE a stranger wrote, and the `IncomingCall` carrying
/// them has to fit `sipral_headless::MAX_CONTROL_PAYLOAD` even when every
/// byte of both is one JSON escapes six times over.
const IDENTITY_BYTES: usize = 512;

/// The `Retry-After` on a call refused for want of an RTP port: long enough
/// for one to come free, short enough that a caller who waits it out finds
/// the agent answering again.
const RETRY_AFTER_SECONDS: &[u8] = b"5";

/// Where to register, for an application reached through a server rather
/// than dialled directly: `--register user@domain --registrar ip:port
/// --pass secret`, the way an agent sits behind a PBX.
struct Registration {
    user: String,
    domain: String,
    registrar: SocketAddr,
    pass: String,
}

/// How a call is answered: the codecs, and — with `--ice-lite` — as an
/// ICE-lite endpoint, advertised at the socket's address or at `--public`.
struct Answering {
    catalog: CodecCatalog,
    public: Option<std::net::IpAddr>,
}

impl Answering {
    /// What one call is answered with, on the media socket bound at `local`.
    /// A one-to-one NAT keeps the port, so the public address takes the
    /// socket's own.
    fn media(&self, local: SocketAddr) -> CallMedia {
        let media = CallMedia::new(self.catalog.clone(), MediaConfig::default());
        match self.public {
            Some(ip) => media.public_address(SocketAddr::new(ip, local.port())),
            None => media,
        }
    }
}

struct Args {
    host: std::net::IpAddr,
    port: u16,
    socket: SocketAddr,
    registration: Option<Registration>,
    answering: Answering,
}

fn args() -> Args {
    let mut host = std::net::IpAddr::from([127, 0, 0, 1]);
    let mut port = 5070_u16;
    let mut socket = SocketAddr::from(([0, 0, 0, 0], 7001));
    let mut register: Option<(String, String)> = None;
    let mut registrar: Option<SocketAddr> = None;
    let mut pass = String::new();
    let mut ice_lite = false;
    let mut public = None;
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
            "--register" => {
                register = it.next().and_then(|t| {
                    t.split_once('@')
                        .map(|(user, domain)| (user.to_owned(), domain.to_owned()))
                });
            }
            "--registrar" => registrar = it.next().and_then(|t| t.parse().ok()),
            "--pass" => pass = it.next().unwrap_or_default(),
            "--ice-lite" => ice_lite = true,
            "--public" => public = it.next().and_then(|t| t.parse().ok()),
            _ => {}
        }
    }
    let catalog = if ice_lite {
        codecs().with_ice(IcePolicy::Lite)
    } else {
        codecs()
    };
    let registration = register
        .zip(registrar)
        .map(|((user, domain), registrar)| Registration {
            user,
            domain,
            registrar,
            pass,
        });
    Args {
        host,
        port,
        socket,
        registration,
        answering: Answering { catalog, public },
    }
}

/// One complete message read off the agent's own socket.
enum FromAgent {
    Audio(Vec<u8>),
    Control(ControlMessage),
    /// A whole frame that was refused — audio of the wrong size, a control
    /// message that did not decode — which the stream reads on past, and
    /// which the agent is told about on the error channel.
    Refused(DecodeError),
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
                let message = match decoder.next_message() {
                    Ok(Some(Decoded::Audio(payload))) => FromAgent::Audio(payload.to_vec()),
                    Ok(Some(Decoded::Control(message))) => FromAgent::Control(message),
                    Ok(None) => break,
                    // a length that lied ends the connection: there is no
                    // way to know where the frame it announced ends
                    Err(error) if error.is_final() => return,
                    Err(error) => FromAgent::Refused(error),
                };
                if tx.send(message).is_err() {
                    return;
                }
            }
        }
    });
    rx
}

/// One turn's wire frames for the agent, in the order the turn produced
/// them: control first — whatever signalling, the agent's own messages and
/// this turn's voice activity gave rise to — then the caller's audio.
#[derive(Default)]
struct Turn {
    control: Vec<u8>,
    audio: Vec<u8>,
}

/// The agent's socket, written from a thread of its own for the same reason
/// it is read from one: an agent that stops reading fills the kernel's send
/// buffer, and a write that blocks there would stall every call's SIP and
/// RTP behind it.
struct ToAgent {
    writes: Sender<Vec<u8>>,
    /// Writes handed to the thread and not finished yet.
    in_flight: Arc<AtomicUsize>,
    /// Turns the writer had no room for yet, oldest first. Kept as turns
    /// rather than bytes so that the order between a `VoiceActivity` and the
    /// frames around it survives an agent falling behind, and so that the
    /// audio can still be told apart from the control and dropped alone.
    held: VecDeque<Turn>,
    /// Frames of the caller's audio dropped here, oldest first, for an
    /// agent that was not reading.
    audio_dropped: u64,
}

impl ToAgent {
    fn spawn(mut stream: TcpStream) -> Self {
        let (writes, pending) = mpsc::channel::<Vec<u8>>();
        let in_flight = Arc::new(AtomicUsize::new(0));
        let finished = Arc::clone(&in_flight);
        thread::spawn(move || {
            for bytes in pending {
                if stream.write_all(&bytes).is_err() {
                    return;
                }
                finished.fetch_sub(1, Ordering::AcqRel);
            }
        });
        Self {
            writes,
            in_flight,
            held: VecDeque::new(),
            audio_dropped: 0,
        }
    }

    /// Queues `turn` behind whatever is held and hands the writer as much as
    /// it has room for. `Break` once the writer is gone or the agent has left
    /// more control unread than [`MOST_HELD`].
    fn send(&mut self, turn: Turn) -> ControlFlow<()> {
        if !turn.control.is_empty() || !turn.audio.is_empty() {
            self.held.push_back(turn);
        }
        let frame = usize::from(session_audio().frame_bytes().unwrap_or(0)) + HEADER_LEN;
        let mut with_audio = self.held.iter().filter(|t| !t.audio.is_empty()).count();
        for turn in &mut self.held {
            if with_audio <= MOST_AUDIO_TURNS {
                break;
            }
            if !turn.audio.is_empty() {
                let frames = turn.audio.len() / frame.max(1);
                self.audio_dropped = self
                    .audio_dropped
                    .saturating_add(u64::try_from(frames).unwrap_or(u64::MAX));
                turn.audio.clear();
                with_audio -= 1;
            }
        }
        if self.held.iter().map(|t| t.control.len()).sum::<usize>() > MOST_HELD {
            return ControlFlow::Break(());
        }
        while self.in_flight.load(Ordering::Acquire) < WRITES_IN_FLIGHT
            && let Some(Turn { mut control, audio }) = self.held.pop_front()
        {
            control.extend_from_slice(&audio);
            self.in_flight.fetch_add(1, Ordering::AcqRel);
            if self.writes.send(control).is_err() {
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    }
}

/// `text`, cut to at most `most` bytes on a character boundary.
fn bounded(mut text: String, most: usize) -> String {
    if text.len() > most {
        let mut end = most;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
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
    let Args {
        host,
        port,
        socket: socket_addr,
        registration,
        answering,
    } = args();
    let now = Instant::now();
    let agent = UserAgent::new(EndpointConfig::default(), entropy::seed()?)?;
    let engine = MediaEngine::new(
        codecs(),
        MediaConfig::default(),
        WallClock::from_unix(now, 0, 0),
        entropy::seed()?,
    );
    let mut endpoint = Endpoint::bind(SocketAddr::new(host, port), agent, engine, now)?;
    if let Some(registration) = &registration {
        let aor = Uri::parse_str(&format!(
            "sip:{}@{}",
            registration.user, registration.domain
        ))?;
        let registrar = Uri::parse_str(&format!("sip:{}", registration.domain))?;
        let contact = Uri::parse_str(&format!("sip:{}@{}", registration.user, endpoint.local))?;
        let account = endpoint.add_account(
            Account::new(
                aor,
                registrar,
                contact,
                endpoint.transport,
                registration.registrar,
            )
            .credentials(Credentials::new(&registration.user, &registration.pass)),
        );
        endpoint.agent.register(account, now)?;
        println!(
            "listening on {}; registering {}@{} at {}",
            endpoint.local, registration.user, registration.domain, registration.registrar
        );
    } else {
        // Still one account, never registered, so the `Contact` on a call it
        // answers is a real address (`headless-agent.rs` says why).
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
    }

    println!("waiting for the agent to connect on {socket_addr}");
    let listener = TcpListener::bind(socket_addr)?;
    let (socket, from) = listener.accept()?;
    println!("agent connected from {from}");
    let reader = read_agent(socket.try_clone()?);
    let mut to_agent = ToAgent::spawn(socket);

    let mut bridge: Option<Bridge> = None;
    let mut agent_up = false;
    let mut next_tick = now;

    loop {
        let turn = Instant::now();
        let mut out = Turn::default();

        for event in endpoint.pump(turn) {
            handle_event(
                &mut endpoint,
                &mut bridge,
                &mut agent_up,
                &mut out.control,
                &event,
                (turn, to_agent.audio_dropped, &answering),
            );
        }

        if drain_agent(&reader, &mut endpoint, &mut bridge, &mut out.control, turn).is_break() {
            println!("the agent's socket closed");
            return Ok(());
        }

        if let Some(active) = bridge.as_mut()
            && let Some(mut media) = endpoint.engine.session(active.call)
        {
            drive_bridge(active, &mut media, agent_up, &mut next_tick, &mut out, turn);
        }

        if to_agent.send(out).is_break() {
            println!("the agent stopped reading its socket");
            return Ok(());
        }

        endpoint.timers(turn);
        if !endpoint.read_sip(turn) {
            thread::sleep(Duration::from_millis(5));
        }
    }
}

/// Everything the agent's own socket had queued: audio goes straight onto
/// this call's playback queue, `BargeIn` empties it, `Hangup` ends the call,
/// `DtmfSend` dials a digit, and a frame that was refused is reported back
/// on the error channel. `ControlFlow::Break` once the socket has closed for
/// good.
fn drain_agent(
    reader: &Receiver<FromAgent>,
    endpoint: &mut Endpoint,
    bridge: &mut Option<Bridge>,
    out: &mut Vec<u8>,
    turn: Instant,
) -> ControlFlow<()> {
    loop {
        match reader.try_recv() {
            Ok(FromAgent::Audio(payload)) => {
                if let Some(active) = bridge.as_mut() {
                    let _ = active.session.protocol_mut().push_playback(payload);
                }
            }
            Ok(FromAgent::Refused(error)) => {
                let code = match error {
                    DecodeError::Audio(_) => ErrorCode::InvalidAudioFrame,
                    _ => ErrorCode::ProtocolViolation,
                };
                let _ = encode_control(
                    &ControlMessage::Error(ErrorMessage {
                        call_id: None,
                        code,
                        message: error.to_string(),
                    }),
                    out,
                );
            }
            Ok(FromAgent::Control(ControlMessage::BargeIn(msg))) => {
                if let Some(active) = bridge.as_mut().filter(|b| b.call_id == msg.call_id) {
                    active.session.protocol_mut().barge_in();
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
    out: &mut Turn,
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
    // the session's own datagrams — an ICE-lite end's answers to the peer's
    // checks among them — go out on the same socket, whatever the tick
    while let Some(datagram) = media.poll_transmit(turn) {
        let _ = active.rtp.send_to(datagram.payload, datagram.destination);
    }
    if !agent_up || turn < *next_tick {
        return;
    }
    // More than a tick behind — the first tick of a call answered long after
    // the loop began, or a turn that stalled — starts the cadence again from
    // now. Catching up instead would run every missed tick back to back:
    // RTP out several times faster than real time, and the far end's audio
    // pulled out of its jitter buffer just as fast.
    *next_tick = if turn.saturating_duration_since(*next_tick) > PACE {
        turn + PACE
    } else {
        *next_tick + PACE
    };
    let frame = media.frame_samples();
    let mut decoded = vec![0_i16; frame];
    let _ = media.playback(&mut decoded);
    if let Some(speaking) = active.session.hear(&decoded) {
        let _ = encode_control(
            &ControlMessage::VoiceActivity(VoiceActivity {
                call_id: active.call_id.clone(),
                speaking,
            }),
            &mut out.control,
        );
    }
    while let Some(bytes) = active.session.protocol_mut().pop_capture() {
        let _ = encode_audio(session_audio(), &bytes, &mut out.audio);
    }
    if let Ok(Some(datagram)) = active.session.speak(media, turn) {
        let _ = active.rtp.send_to(datagram.payload, datagram.destination);
    }
}

/// A fresh, non-blocking RTP socket on `ip`, and the address it is bound to.
fn bind_rtp(ip: std::net::IpAddr) -> std::io::Result<(UdpSocket, SocketAddr)> {
    let rtp = UdpSocket::bind((ip, 0))?;
    rtp.set_nonblocking(true)?;
    let local = rtp.local_addr()?;
    Ok((rtp, local))
}

/// Turns a call away that this binary could not take, rather than leaving it
/// ringing until the caller gives up, and tells the agent why on the error
/// channel: `status` goes to the caller, the reason to the agent and to
/// standard output.
fn refuse_call(
    endpoint: &mut Endpoint,
    out: &mut Vec<u8>,
    (call, call_id): (CallHandle, &str),
    status: StatusCode,
    why: &str,
    now: Instant,
) {
    if status == StatusCode::SERVICE_UNAVAILABLE {
        let _ = endpoint
            .agent
            .respond_with_headers(call, &[(HeaderName::RetryAfter, RETRY_AFTER_SECONDS)]);
    }
    let refused = endpoint.agent.reject(call, status, now);
    let message = match refused {
        Ok(()) => format!("{why}; the call was refused with {}", status.get()),
        Err(error) => format!("{why}; refusing the call failed too: {error}"),
    };
    println!("{call_id}: {message}");
    let _ = encode_control(
        &ControlMessage::Error(ErrorMessage {
            call_id: Some(call_id.to_owned()),
            code: ErrorCode::Internal,
            message,
        }),
        out,
    );
}

/// Takes an incoming call: its own RTP socket and `HeadlessSession`, the
/// session's opening and the caller on the wire, then the answer.
///
/// A call this binary cannot take is refused at once, whichever step it
/// failed at, and the agent hears why — before, each of them returned and
/// left the call ringing, answered by nobody and refused by nobody.
fn open_bridge(
    endpoint: &mut Endpoint,
    bridge: &mut Option<Bridge>,
    out: &mut Vec<u8>,
    (call, answering): (CallHandle, &Answering),
    now: Instant,
) {
    let call_id = format!("{call:?}");
    // No port to carry the call's audio on is a shortage of this host's, not
    // a fault in the call: §21.5.4's 503, with a Retry-After, so that a
    // server in front of several agents tries another one (RFC 3263 §4.3)
    // and a caller that retries this one waits for a port to come free.
    let (rtp, local) = match bind_rtp(endpoint.local.ip()) {
        Ok(bound) => bound,
        Err(error) => {
            let why = format!("no RTP socket for the call's audio: {error}");
            refuse_call(
                endpoint,
                out,
                (call, &call_id),
                StatusCode::SERVICE_UNAVAILABLE,
                &why,
                now,
            );
            return;
        }
    };
    // The socket's own audio against the codec's rate: fixed in this binary,
    // so a refusal here is this binary's own fault — §21.5.1's 500.
    let session =
        match sipral::HeadlessSession::open(call_id.clone(), session_audio(), CODEC_RATE, 50, 50) {
            Ok(session) => session,
            Err(error) => {
                let why = format!("the call's audio cannot be bridged: {error}");
                refuse_call(
                    endpoint,
                    out,
                    (call, &call_id),
                    StatusCode::SERVER_ERROR,
                    &why,
                    now,
                );
                return;
            }
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
    // call is still known to the agent, and cut to what the socket carries.
    let identity = endpoint.agent.call_identity(call);
    let caller = identity.as_ref().map_or_else(String::new, |who| {
        bounded(
            String::from_utf8_lossy(&who.from_uri).into_owned(),
            IDENTITY_BYTES,
        )
    });
    let display_name = identity
        .as_ref()
        .map(|who| {
            bounded(
                String::from_utf8_lossy(&who.from_display).into_owned(),
                IDENTITY_BYTES,
            )
        })
        .filter(|name| !name.is_empty());
    let _ = encode_control(
        &ControlMessage::IncomingCall(IncomingCall {
            call_id: call_id.clone(),
            caller,
            display_name,
        }),
        out,
    );
    match endpoint.engine.answer_with(
        &mut endpoint.agent,
        call,
        local,
        answering.media(local),
        now,
    ) {
        Ok(()) => println!("answered {call_id}"),
        // the engine sent nothing: an offer that cannot be answered is
        // RFC 3261 §21.4.26's 488, and anything else this end's own 500
        Err(error) => {
            let status = match error {
                MediaError::Description(_)
                | MediaError::NoCommonCodec
                | MediaError::UnknownPayload { .. }
                | MediaError::NoDtlsSrtp
                | MediaError::SrtpRequired => StatusCode::NOT_ACCEPTABLE_HERE,
                _ => StatusCode::SERVER_ERROR,
            };
            let why = format!("the call cannot be answered: {error}");
            refuse_call(endpoint, out, (call, &call_id), status, &why, now);
        }
    }
}

fn handle_event(
    endpoint: &mut Endpoint,
    bridge: &mut Option<Bridge>,
    agent_up: &mut bool,
    out: &mut Vec<u8>,
    event: &Event,
    (now, audio_dropped, answering): (Instant, u64, &Answering),
) {
    match event {
        Event::Signalling(UaEvent::IncomingCall { call, .. })
            if bridge.as_ref().is_none_or(|b| b.ended) =>
        {
            open_bridge(endpoint, bridge, out, (*call, answering), now);
        }
        Event::Media {
            event: MediaEvent::PathChosen { local, remote },
            ..
        } => println!("path chosen {local} -> {remote}"),
        Event::Media {
            event: MediaEvent::Failed(error),
            ..
        } => println!("media failed: {error}"),
        // A second call while one is already bridged: this binary only
        // ever drives one `Bridge` at a time (its own doc comment says so),
        // so it declines rather than leaving the caller ringing forever.
        Event::Signalling(UaEvent::IncomingCall { call, .. }) => {
            let _ = endpoint.agent.reject(*call, StatusCode::BUSY_HERE, now);
        }
        Event::Signalling(UaEvent::Registered { .. }) => println!("registered"),
        Event::Signalling(UaEvent::RegistrationFailed { reason, status, .. }) => {
            println!("registration failed: {reason} ({status:?})");
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
                // audio the agent did not read: dropped on this call's capture
                // queue, or held for the socket until newer turns pushed it
                // out — the second counted since the agent connected
                println!(
                    "ended {}: packets_received={} packets_sent={} capture_dropped={} audio_dropped={}",
                    active.call_id,
                    stats.quality.received,
                    stats.packets_sent,
                    active.session.protocol().capture_dropped(),
                    audio_dropped
                );
            }
        }
        _ => {}
    }
    // After the bridge above has had its chance to open, so that a call's own
    // `IncomingCall` finds it and reaches the wire as `ringing`: only the
    // bridged call's own transitions are reported, under its own id.
    if let Event::Signalling(sig) = event
        && let Some((call, state)) = sipral::call_state_of(sig)
        && let Some(active) = bridge.as_mut().filter(|b| b.call == call)
    {
        let protocol = active.session.protocol_mut();
        let _ = match state {
            CallStateKind::Ringing => Ok(()),
            CallStateKind::Answered => {
                *agent_up = true;
                protocol.answer()
            }
            CallStateKind::Ended { .. } => protocol.hangup(),
        };
        let _ = encode_control(
            &ControlMessage::CallState(CallState {
                call_id: active.call_id.clone(),
                state,
            }),
            out,
        );
    }
}
