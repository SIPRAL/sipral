// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The SIP and RTP half of a socket-framed voice agent: it answers every call and carries audio,
//! voice activity, DTMF and call state over TCP in `sipral-headless`'s wire protocol, for a
//! separate agent process. The design is `docs/07-headless.md#real-media`.
//!
//! This is the application side, owning the SIP dialog, the RTP session and the socket.
//! `crates/sipral-headless/examples/agent.rs` is the other side: a minimal reference agent that
//! echoes and sends a digit, depending only on `sipral-headless`.
//!
//! Simpler than what `sipral_headless::SessionRegistry` supports: one call at a time, one TCP
//! connection accepted at startup before SIP comes up, which is what the interop lab needs.
//!
//! RTP is driven by hand instead of through `common/media_socket.rs`'s `MediaSocket::turn`, whose
//! two closures would both need `&mut` access to the same `HeadlessSession`. So this binary paces
//! its own 20 ms tick, and takes from `MediaSocket` only the sockets: RTP on an even port with the
//! next one held for RTCP (RFC 3550 §11), given up when the call muxes RTCP (RFC 5761). RTCP
//! reports go out from whichever port the call's plan names, and an ended call's BYE (RFC 3550
//! §6.6) from the socket it was the call's.
//!
//! ```text
//! cargo run --example headless-socket-agent --features headless -- \
//!     --host 127.0.0.1 --port 5070 --socket 0.0.0.0:7001
//! ```
//!
//! Dial it directly as above, or have it register with `--register user@domain --registrar ip:port
//! --pass secret`, as the interop lab does behind Asterisk.
//!
//! `--ice-lite` answers as an ICE-lite endpoint (`sipral::IcePolicy::Lite`, `docs/06-nat.md`), for
//! a server with a public address talking to a full-ICE peer such as a WebRTC gateway. The
//! candidate is the media socket's address, or `--public ip` behind a one-to-one NAT. When the peer
//! nominates a pair it prints `path chosen <local> -> <remote>`.
//!
//! Socket audio is fixed at 16 kHz and the catalogue is G.711 only (8 kHz), so `HeadlessSession`
//! always resamples both ways, exercising that path.
//!
//! `--timings` prints two lines per call with wall-clock microseconds since the Unix epoch: `timing
//! invite <call> <us>` when the INVITE reaches this binary, and `timing first-rtp <call> <us>` when
//! the first RTP packet with agent audio leaves. The agent example's `--timings` prints the other
//! halves; `scripts/soak.sh latency` pairs them (`docs/19-numbers.md`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

#[path = "common/entropy.rs"]
mod entropy;
// `udp_endpoint.rs` names `crate::media_socket::MediaSocket` in its `Endpoint`, although this
// binary never calls `MediaSocket::turn`
#[path = "common/media_socket.rs"]
mod media_socket;
#[path = "common/udp_endpoint.rs"]
mod udp_endpoint;
#[path = "common/wall_clock.rs"]
mod wall_clock;

use std::collections::VecDeque;
use std::env;
use std::io::Write as _;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sipral::{
    Account, CallHandle, CallMedia, CodecCatalog, Credentials, EndpointConfig, Event, IcePolicy,
    MediaConfig, MediaEngine, MediaError, MediaEvent, StatusCode, UaEvent, Uri, UserAgent,
};
use sipral_core::msg::HeaderName;
use sipral_headless::{
    AudioConfig, CallState, CallStateKind, ControlMessage, DecodeError, Decoded, Decoder,
    ErrorCode, ErrorMessage, HEADER_LEN, IncomingCall, SampleRate, SessionOpen, VoiceActivity,
    encode_audio, encode_control,
};

use media_socket::MediaSocket;
use udp_endpoint::Endpoint;

/// Socket audio format: independent of the call's codec (the point of `docs/07-headless.md`), fixed
/// rather than negotiated in this simplified binary.
fn session_audio() -> AudioConfig {
    AudioConfig::new(SampleRate::Hz16000)
}

/// G.711 only, both laws at 8 kHz, so the codec rate is known before negotiation settles and a
/// `HeadlessSession` can open on `IncomingCall`.
fn codecs() -> CodecCatalog {
    CodecCatalog::with_order(&["PCMU", "PCMA"]).expect("both are always in this build")
}

const CODEC_RATE: u32 = 8_000;
const PACE: Duration = Duration::from_millis(20);

/// Writes the writer thread may have in progress beyond the kernel send buffer. Beyond that the
/// agent is not reading, and turns wait here in order.
const WRITES_IN_FLIGHT: usize = 4;

/// Turns of caller audio held for an agent that is not reading (one second at 20 ms per turn); then
/// the oldest audio is dropped, as the capture queue does.
const MOST_AUDIO_TURNS: usize = 50;

/// Control bytes held for an agent that stopped reading before it is considered gone. Control is
/// never dropped like audio: a missed `CallState` or `VoiceActivity` misrepresents the call.
const MOST_HELD: usize = 64 * 1_024;

/// Maximum bytes of the caller's address and display name passed to the agent, each. Both come from
/// a stranger's INVITE, and `IncomingCall` must fit `sipral_headless::MAX_CONTROL_PAYLOAD` even if
/// JSON escapes every byte sixfold.
const IDENTITY_BYTES: usize = 512;

/// `Retry-After` when refusing a call for lack of an RTP port: long enough for one to free up,
/// short enough that a waiting caller gets through.
const RETRY_AFTER_SECONDS: &[u8] = b"5";

/// Registration for an agent behind a PBX: `--register user@domain --registrar ip:port --pass
/// secret`.
struct Registration {
    user: String,
    domain: String,
    registrar: SocketAddr,
    pass: String,
}

/// How calls are answered: the codecs and, with `--ice-lite`, as an ICE-lite endpoint advertised at
/// the socket's address or `--public`.
struct Answering {
    catalog: CodecCatalog,
    public: Option<std::net::IpAddr>,
    /// `--timings`: print the instants the latency figures use.
    timings: bool,
}

/// Wall-clock microseconds since the Unix epoch, the clock this process and a local agent both
/// read.
fn epoch_us() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_micros())
}

impl Answering {
    /// What one call is answered with on the media socket at `local`. A one-to-one NAT keeps the
    /// port, so the public address uses the socket's.
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
    let mut timings = false;
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
            "--timings" => timings = true,
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
        answering: Answering {
            catalog,
            public,
            timings,
        },
    }
}

/// One complete message read off the agent's own socket.
enum FromAgent {
    Audio(Vec<u8>),
    Control(ControlMessage),
    /// A complete frame that was refused (wrong audio size, undecodable control). The stream
    /// continues past it and the agent is told on the error channel.
    Refused(DecodeError),
}

/// Read the agent's socket on its own thread so a slow or silent agent never stalls SIP or RTP.
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
                    // a wrong length ends the connection: there is no way to find the frame's end
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

/// One turn's frames for the agent, in order: control first (signalling, agent messages, voice
/// activity), then caller audio.
#[derive(Default)]
struct Turn {
    control: Vec<u8>,
    audio: Vec<u8>,
}

/// Writes to the agent's socket on their own thread: an agent that stops reading fills the send
/// buffer, and a blocking write would stall every call's SIP and RTP.
struct ToAgent {
    writes: Sender<Vec<u8>>,
    /// Writes handed to the thread and not finished yet.
    in_flight: Arc<AtomicUsize>,
    /// Turns the writer had no room for, oldest first. Kept as turns, not bytes, so `VoiceActivity`
    /// stays ordered with its frames and audio can be dropped without dropping control.
    held: VecDeque<Turn>,
    /// Caller audio frames dropped here, oldest first, because the agent was not reading.
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

    /// Queue `turn` behind held ones and hand the writer what fits. `Break` once the writer is gone
    /// or more than [`MOST_HELD`] control bytes are unread.
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

/// One call's socket-side state: its RTP and RTCP sockets, the `HeadlessSession` that resamples and
/// queues audio, and the wire call id.
struct Bridge {
    call: CallHandle,
    call_id: String,
    media: MediaSocket,
    session: sipral::HeadlessSession,
    /// RTCP reports sent for this call while it was up (RFC 3550 §6.4), the BYE not among them.
    rtcp_sent: u64,
    /// Set on `UaEvent::CallEnded`, which `MediaEngine` always reports before the
    /// `MediaEvent::Ended` with final statistics. `bridge` is cleared only after that, so it still
    /// has a `call_id` to report against.
    ended: bool,
    /// The agent has sent audio for this call, and the next packet carries it.
    agent_spoke: bool,
    /// Whether the first packet with agent audio is still to be timed: `Some(false)` until then,
    /// `None` without `--timings`.
    first_rtp_timed: Option<bool>,
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
        wall_clock::at(now),
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
        // one unregistered account, so the `Contact` in answers is a real address (see
        // `headless-agent.rs`)
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
    // the sockets of calls that ended this turn, kept until their RTCP BYE has gone
    let mut parting: Vec<(CallHandle, MediaSocket)> = Vec::new();
    let mut agent_up = false;
    let mut next_tick = now;

    loop {
        let turn = Instant::now();
        let mut out = Turn::default();

        for event in endpoint.pump(turn) {
            handle_event(
                &mut endpoint,
                (&mut bridge, &mut parting),
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
        send_rtcp(&mut endpoint, bridge.as_mut(), &mut parting, turn);

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

/// Handle everything queued from the agent: audio to the playback queue, `BargeIn` empties it,
/// `Hangup` ends the call, `DtmfSend` dials, refused frames are reported on the error channel.
/// `ControlFlow::Break` once the socket closed.
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
                if let Some(active) = bridge.as_mut()
                    && active.session.protocol_mut().push_playback(payload).is_ok()
                {
                    active.agent_spoke = true;
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

/// The call's RTCP reports, due on the session's own schedule (RFC 3550 §6.2), and the BYE of a
/// call that ended this turn from the socket that was its own (§6.6). A goodbye whose socket is
/// already gone is let go rather than left queued in the engine.
fn send_rtcp(
    endpoint: &mut Endpoint,
    bridge: Option<&mut Bridge>,
    parting: &mut Vec<(CallHandle, MediaSocket)>,
    turn: Instant,
) {
    let mut bridge = bridge.filter(|b| !b.ended);
    while let Some((call, destination, payload)) = endpoint.engine.poll_rtcp(turn) {
        if let Some(active) = bridge.as_deref_mut().filter(|b| b.call == call) {
            active.media.send_rtcp(destination, &payload);
            active.rtcp_sent += 1;
        }
    }
    while let Some((call, destination, payload)) = endpoint.engine.poll_farewell() {
        if let Some((_, media)) = parting.iter().find(|(gone, _)| *gone == call) {
            media.send_rtcp(destination, &payload);
        }
    }
    parting.clear();
}

/// One call's media for this tick: incoming RTP and RTCP go to `media`; when a media tick is due,
/// decoded caller audio is heard, voice activity and ready frames are written to `out`, and queued
/// agent audio is sent as the next RTP packet.
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
    // also adopts the RTCP port once the plan names one, or lets the held one go when muxed
    active.media.receive(media, turn);
    // session datagrams (including ICE-lite check answers) go out on the RTP socket on every tick
    while let Some(datagram) = media.poll_transmit(turn) {
        active.media.send(datagram.destination, datagram.payload);
    }
    if !agent_up || turn < *next_tick {
        return;
    }
    // more than a tick behind (first tick of a late call, or a stall) restarts the cadence;
    // catching up would burst RTP and drain the far end's jitter buffer
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
    let carries_agent = active.agent_spoke;
    if let Ok(Some(datagram)) = active.session.speak(media, turn) {
        active.media.send(datagram.destination, datagram.payload);
    } else {
        return;
    }
    if carries_agent && active.first_rtp_timed == Some(false) {
        active.first_rtp_timed = Some(true);
        println!("timing first-rtp {} {}", active.call_id, epoch_us());
    }
}

/// A fresh RTP socket with its RTCP port held, and the address the SDP names: `ip`, the address
/// SIP is reached at, and the socket's port.
fn bind_media(ip: std::net::IpAddr, now: Instant) -> std::io::Result<(MediaSocket, SocketAddr)> {
    let media = MediaSocket::bind(now)?;
    let local = SocketAddr::new(ip, media.port()?);
    Ok((media, local))
}

/// Refuse a call this binary cannot take instead of leaving it ringing: `status` to the caller, the
/// reason to the agent's error channel and stdout.
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

/// Take an incoming call: RTP socket, `HeadlessSession`, session opening and caller sent on the
/// wire, then the answer.
///
/// Any failed step refuses the call at once and tells the agent why, instead of leaving it ringing
/// unanswered.
fn open_bridge(
    endpoint: &mut Endpoint,
    bridge: &mut Option<Bridge>,
    out: &mut Vec<u8>,
    (call, answering): (CallHandle, &Answering),
    now: Instant,
) {
    let call_id = format!("{call:?}");
    // no RTP port is this host's shortage, not the call's fault: 503 (§21.5.4) with Retry-After, so
    // a front server tries another agent (RFC 3263 §4.3) and a retrying caller waits
    let (media, local) = match bind_media(endpoint.local.ip(), now) {
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
    // the socket rate is fixed here, so a failure is this binary's own: 500 (§21.5.1)
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
        media,
        session,
        rtcp_sent: 0,
        ended: false,
        agent_spoke: false,
        first_rtp_timed: answering.timings.then_some(false),
    });
    let _ = encode_control(
        &ControlMessage::SessionOpen(SessionOpen::new(session_audio().sample_rate())),
        out,
    );
    // caller identity from the INVITE's `From`, read while the call is still known, truncated to
    // what the socket carries
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
        // nothing was sent: an unanswerable offer gets 488 (RFC 3261 §21.4.26), anything else 500
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
    (bridge, parting): (&mut Option<Bridge>, &mut Vec<(CallHandle, MediaSocket)>),
    agent_up: &mut bool,
    out: &mut Vec<u8>,
    event: &Event,
    (now, audio_dropped, answering): (Instant, u64, &Answering),
) {
    match event {
        Event::Signalling(UaEvent::IncomingCall { call, .. })
            if bridge.as_ref().is_none_or(|b| b.ended) =>
        {
            if answering.timings {
                println!("timing invite {call:?} {}", epoch_us());
            }
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
        // one bridged call at a time: decline a second one rather than leave it ringing
        Event::Signalling(UaEvent::IncomingCall { call, .. }) => {
            let _ = endpoint.agent.reject(*call, StatusCode::BUSY_HERE, now);
        }
        Event::Signalling(UaEvent::Registered { .. }) => println!("registered"),
        Event::Signalling(UaEvent::RegistrationFailed { reason, status, .. }) => {
            println!("registration failed: {reason} ({status:?})");
        }
        // only the bridged call's end stops its audio; the refused call above ends too
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
                // agent audio unread: dropped from the capture queue, or pushed out of the socket
                // queue by newer turns; the latter counted since the agent connected
                println!(
                    "ended {}: packets_received={} packets_sent={} rtcp_sent={} round_trip_ms={} \
                     capture_dropped={} audio_dropped={}",
                    active.call_id,
                    stats.quality.received,
                    stats.packets_sent,
                    active.rtcp_sent,
                    stats
                        .round_trip
                        .map_or_else(|| "none".to_owned(), |rtt| rtt.as_millis().to_string()),
                    active.session.protocol().capture_dropped(),
                    audio_dropped
                );
                parting.push((active.call, active.media));
            }
        }
        _ => {}
    }
    // after the bridge had its chance to open, so the call's `IncomingCall` reaches the wire as
    // `ringing`; only the bridged call's transitions are reported
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
