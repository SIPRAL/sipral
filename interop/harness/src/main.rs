// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Drives the `sipral` facade against the container lab and judges each flow.
//!
//! Every other test in this workspace runs the stack against a peer written in
//! the same file, or against a second copy of itself. Both prove it is
//! consistent; neither proves it is interoperable, because our idea of what a
//! registrar sends is our idea. This one talks to Kamailio, FreeSWITCH and
//! Asterisk as they ship, and the failures it finds are the ones that would
//! otherwise be found by a customer.
//!
//! Pass and fail are decided before the run, not looked at afterwards. Each
//! flow states what has to be true; a flow that is partly right is a failure
//! with the failing condition named, and the process exits non-zero so that
//! whoever ran `scripts/lab.sh` does not have to read the log to know.
//!
//! # Through the facade, not around it
//!
//! Until 8.5.1 this crate carried its own RTP session, its own codec pair and
//! its own DTMF sender — a second media join, written for the lab and used
//! nowhere else. `sipral::MediaEngine` and `sipral::MediaSession` are that
//! join now, for RTP, codecs, DTMF and SRTP alike; what is left here is what
//! any application still has to write for itself, because the facade owns
//! neither a socket nor a device: bind one, feed it datagrams, and drive the
//! loop. `crate::audio` is that remainder for the media socket;
//! [`Endpoint`] is it for the SIP one.

// tests say what they mean; the no-panic discipline is for what ships
#![cfg_attr(
    test,
    allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )
)]

mod audio;
#[cfg(test)]
mod local;
mod pair;

use std::collections::HashMap;
use std::env;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sipral::{
    Account, AccountId, CallHandle, CallMedia, CallState, Codec, CodecCatalog, Credentials,
    DEFAULT_DIGIT, Digit, DtmfInfoForm, EndpointConfig, Event, Input, MediaConfig, MediaEngine,
    MediaEvent, OutgoingCall, Quality, SrtpPolicy, StreamStatistics, TransportId,
    TransportProtocol, UaError, UaEvent, Uri, UserAgent, WallClock,
};
use sipral_core::msg::{HeaderName, OwnedMessage};
use sipral_core::sdp::{Connection, Direction, Origin, SessionDescription};

use crate::audio::Media;

/// How long any one flow may take before it is a failure. Every step in these
/// flows is a round trip on a loopback bridge; a whole flow that needs more
/// than this has not gone slowly, it has gone wrong.
///
/// Both this and [`dwell`] are overridable, and one impairment profile needs
/// it: a link that disappears for eight seconds cannot be measured on a call
/// that lasts two.
fn patience() -> Duration {
    seconds_from("SIPRAL_PATIENCE_MS", 20_000)
}

/// How long a plain call stays up before it is hung up. Long enough for a
/// hundred frames each way, which is enough to tell a tone coming back from a
/// line that is merely open.
fn dwell() -> Duration {
    seconds_from("SIPRAL_DWELL_MS", 2_000)
}

fn seconds_from(name: &str, fallback: u64) -> Duration {
    Duration::from_millis(
        env::var(name)
            .ok()
            .and_then(|text| text.parse().ok())
            .unwrap_or(fallback),
    )
}

/// How long to wait for the far end to become transferable before asking
/// anyway.
///
/// A REFER sent the instant the dialog confirms reaches Asterisk before it has
/// put the channel into a bridge, and a transfer of a channel that is in no
/// bridge is answered `202` and then reported `400` in the sipfrag. Measured
/// on the lab's own Asterisk: the REFER was processed and the 400 sent 271
/// microseconds before the channel joined the bridge. Nothing is wrong with
/// the REFER — no phone sends one that fast, because a person has to press the
/// key. What proves the far end is bridged is audio arriving from it, so that
/// is what is waited for; this is only the cap, so that a server which sends
/// no audio still gets the REFER and the flow reports the transfer's own
/// outcome rather than a timeout.
const SETTLE: Duration = Duration::from_secs(1);

/// The digit `Flow::Dtmf4733` sends and expects back.
const TEST_DIGIT: Digit = Digit::Number(5);

/// The codec order this harness offers, chosen by `SIPRAL_CODEC`.
///
/// Both laws, because offering one is not what a client does — the first real
/// PBX this stack met allows A-law only, which is the ordinary European
/// default, and answered 488 to an offer that carried only mu-law.
/// `sipral::CodecCatalog::new` would already put G.722 first in this build,
/// since Opus is off (see `Cargo.toml`) and `Codec::ALL` lists it first among
/// what is left — so the ordinary flows name their own order rather than
/// taking the default, and `SIPRAL_CODEC=g722` names a different one instead
/// of turning a flag on: every lab server here takes G.722 too, and folding
/// it into the ordinary offer would silently change what the other flows have
/// been proving for days.
fn catalog() -> CodecCatalog {
    let order: &[&str] = match env::var("SIPRAL_CODEC").as_deref() {
        Ok("g722") => &["G722", "PCMU", "PCMA"],
        _ => &["PCMU", "PCMA"],
    };
    // both orders name codecs this build always has, once each, so the only
    // way `with_order` refuses is a name misspelled right here; the fallback
    // exists so this stays a `CodecCatalog` and not a `panic!` and is never
    // actually taken
    CodecCatalog::with_order(order).unwrap_or_else(|_| CodecCatalog::new())
}

/// What `flow` places its call with: [`catalog`] for every flow except
/// [`Flow::Srtp`], which is refused rather than answered plainly if the
/// far end's own offer turns out not to carry a key — the whole point of
/// the flow is that this call runs under SDES or does not run at all.
fn catalog_for(flow: Flow) -> CodecCatalog {
    match flow {
        Flow::Srtp => catalog().with_srtp(SrtpPolicy::Required),
        _ => catalog(),
    }
}

fn main() -> ExitCode {
    let server = env::args().nth(1).unwrap_or_else(|| "kamailio".to_owned());
    let port: u16 = env::args()
        .nth(2)
        .and_then(|text| text.parse().ok())
        .unwrap_or(5060);
    let extension = env::args().nth(3).unwrap_or_else(|| "9000".to_owned());
    let other = env::args().nth(4).unwrap_or_else(|| "9001".to_owned());

    // the lab's own account unless something else is named. A real server is
    // reached with real credentials, and those do not belong in a repository
    // that becomes public
    let user = env::var("SIPRAL_USER").unwrap_or_else(|_| "labuser".to_owned());
    let pass = env::var("SIPRAL_PASS").unwrap_or_else(|_| "labpass".to_owned());
    // the SDES endpoint's own identity (see interop/asterisk's own endpoint
    // config): a separate account so the plain `labuser` endpoint the other
    // five flows use is untouched by it
    let srtp_user = env::var("SIPRAL_USER_SRTP").unwrap_or_else(|_| "labuser-srtp".to_owned());
    let srtp_pass = env::var("SIPRAL_PASS_SRTP").unwrap_or_else(|_| pass.clone());
    // the endpoint 8.3.11 added for INFO's own dtmf_mode (interop/asterisk's
    // `labuser-infodtmf`), kept apart from `labuser` for the same reason the
    // SDES one is
    let infodtmf_user =
        env::var("SIPRAL_USER_INFODTMF").unwrap_or_else(|_| "labuser-infodtmf".to_owned());
    let infodtmf_pass = env::var("SIPRAL_PASS_INFODTMF").unwrap_or_else(|_| pass.clone());
    let wanted = env::var("SIPRAL_FLOWS").unwrap_or_default();

    let Some(remote) = resolve(&server, port) else {
        println!("cannot resolve {server}:{port}");
        return ExitCode::FAILURE;
    };
    println!("lab: {server}:{port} at {remote}, extension {extension}, as {user}");

    let mut flows = vec![
        Flow::Register,
        Flow::Call,
        Flow::Hold,
        Flow::Blind,
        Flow::Attended,
    ];
    // this lab's own SDES endpoint and codec-change dialplan exist only on
    // Asterisk; see `docs/11-testing.md` for why they are not on FreeSWITCH
    // or through the proxy. The DTMF check runs there too, for now: the digit
    // Asterisk names back never came back through the proxy from FreeSWITCH,
    // and a flow is not run where it is known not to pass until the reason is
    // found
    if server == "asterisk" {
        flows.push(Flow::Dtmf4733);
        flows.push(Flow::DtmfInfo);
        flows.push(Flow::Srtp);
        flows.push(Flow::HoldCodecChange);
    }

    let mut failures = 0;
    for flow in flows {
        if !wanted.is_empty() && !wanted.split(',').any(|name| name.trim() == flow.key()) {
            continue;
        }
        let (this_user, this_pass) = match flow {
            Flow::Srtp => (srtp_user.as_str(), srtp_pass.as_str()),
            Flow::DtmfInfo => (infodtmf_user.as_str(), infodtmf_pass.as_str()),
            _ => (user.as_str(), pass.as_str()),
        };
        match run(
            flow, &server, remote, &extension, &other, this_user, this_pass,
        ) {
            Ok(media) => println!("  pass  {}{media}", flow.name()),
            Err(why) => {
                println!("  FAIL  {} — {why}", flow.name());
                failures += 1;
            }
        }
    }
    // only when a second account is named: it needs two registrations on the
    // same server, and one of them has to have been left with a wide codec list
    if let (Ok(wide_user), Ok(wide_pass)) =
        (env::var("SIPRAL_USER_WIDE"), env::var("SIPRAL_PASS_WIDE"))
        && (wanted.is_empty() || wanted.split(',').any(|name| name.trim() == "inbound"))
    {
        match pair::run(&server, remote, &wide_user, &wide_pass, &user, &pass) {
            Ok(said) => println!("  pass  inbound, narrowed{said}"),
            Err(why) => {
                println!("  FAIL  inbound, narrowed — {why}");
                failures += 1;
            }
        }
    }

    if failures == 0 {
        println!("every flow passed");
        return ExitCode::SUCCESS;
    }
    println!("{failures} flow(s) failed");
    ExitCode::FAILURE
}

/// One scripted exchange, with what has to be true for it to have passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    /// A binding taken, and given back.
    Register,
    /// A call placed, answered, and hung up.
    Call,
    /// The same, put on hold and taken off it again.
    Hold,
    /// A call handed to somebody else without asking them first (RFC 3515).
    Blind,
    /// A call handed over after speaking to the person taking it, so the
    /// REFER names the dialog to replace (RFC 3891).
    Attended,
    /// A digit sent as an RFC 4733 named telephone event, echoed back by the
    /// lab's own dialplan (interop/asterisk/extensions.conf,
    /// interop/freeswitch/lab.xml) so this end can tell the exact digit
    /// crossed rather than merely that something did.
    Dtmf4733,
    /// The same digit, sent as a SIP INFO instead (8.3.11), against
    /// Asterisk's own `labuser-infodtmf` endpoint (interop/asterisk's own
    /// endpoint config) so `SendDTMF()`'s own echo goes back over INFO too
    /// and this end's receiving half is exercised against a real peer as
    /// well as its sending one.
    DtmfInfo,
    /// A call placed with SDES required, against the lab's own SRTP endpoint
    /// (interop/asterisk's own `labuser-srtp`).
    Srtp,
    /// A hold whose resume re-offers a narrower codec list than the call
    /// held on (the 8.2.1 case), so the far end's own answer names a
    /// different codec than it did during the hold.
    HoldCodecChange,
}

impl Flow {
    const fn name(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Call => "call",
            Self::Hold => "hold and resume",
            Self::Blind => "blind transfer",
            Self::Attended => "attended transfer",
            Self::Dtmf4733 => "DTMF, RFC 4733",
            Self::DtmfInfo => "DTMF, SIP INFO",
            Self::Srtp => "SRTP",
            Self::HoldCodecChange => "hold with a codec change",
        }
    }

    /// The name `SIPRAL_FLOWS` selects it by.
    const fn key(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Call => "call",
            Self::Hold => "hold",
            Self::Blind => "blind",
            Self::Attended => "attended",
            Self::Dtmf4733 => "dtmf",
            Self::DtmfInfo => "dtmfinfo",
            Self::Srtp => "srtp",
            Self::HoldCodecChange => "holdcodec",
        }
    }
}

/// One thing that happened. A set of these rather than a pile of flags,
/// because the verdict is read off them at the end and a flag that can be set
/// twice is a flag that can lie.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Fact {
    Registered,
    Unregistered,
    Ringing,
    Up,
    Held,
    Resumed,
    /// The second call of an attended transfer is up.
    Consulted,
    /// The far end reported the transfer under way, in a sipfrag.
    Transferring,
    /// And reported it finished, with a status that says it worked.
    Transferred,
    /// The digit this end sent came back named the same way, on the same
    /// call.
    DigitConfirmed,
    /// `Flow::DtmfInfo`'s own INFO reached a final answer that says the far
    /// end took it.
    DigitSent,
    /// The session negotiated SDES and is actually running under it.
    Encrypted,
    /// The codec running after the resume differs from the one running
    /// during the hold.
    CodecChanged,
    /// We asked for the call to end, rather than watching it end by itself.
    Ours,
    Over,
}

/// What the run has seen. The conditions are read off this at the end, so that
/// a flow which did three of four things is a failure naming the fourth rather
/// than a pass.
#[derive(Debug, Default)]
struct Seen {
    facts: std::collections::HashSet<Fact>,
    refused: Option<String>,
}

impl Seen {
    fn saw(&mut self, fact: Fact) {
        self.facts.insert(fact);
    }

    fn has(&self, fact: Fact) -> bool {
        self.facts.contains(&fact)
    }
}

/// A user agent and a media engine with real sockets under them.
///
/// This is the whole of what replaces `sipral_ua::Runtime` here:
/// `MediaEngine::poll_event` is the one place events may be drained from —
/// its own documentation says so — so the reference loop's own drain, which
/// knows nothing of media, cannot sit in front of it. What is left is small:
/// one SIP socket, one RTP socket per call with a session running on it, and
/// a loop that flushes, drains, plays, and reads.
struct Endpoint {
    agent: UserAgent,
    engine: MediaEngine,
    sip: UdpSocket,
    local: SocketAddr,
    transport: TransportId,
    /// One RTP socket per call that has media, opened before the call is
    /// placed or answered so its port can go in the offer or the answer.
    media: HashMap<CallHandle, Media>,
    /// The `o=` line this end last described each call with, read off the
    /// `UaEvent::SessionChanged` that reported it, for the one offer the
    /// harness writes itself (`reoffer_onto`): RFC 3264 §8 has an offer that
    /// modifies a session keep that line identical but for the version.
    origins: HashMap<CallHandle, Origin>,
    /// The SIP socket's own read buffer, kept here rather than on the stack
    /// of [`Endpoint::read_sip`], which every one of this loop's turns calls.
    sip_inbox: Vec<u8>,
}

impl Endpoint {
    /// Bind the SIP socket, start a user agent on it, and open a media
    /// engine that will offer `catalog`.
    ///
    /// # Errors
    /// Whatever binding the socket or starting the user agent returns.
    fn bind(
        seed: [u8; 32],
        media_seed: [u8; 32],
        bind_addr: SocketAddr,
        catalog: CodecCatalog,
        now: Instant,
    ) -> Result<Self, String> {
        let sip = UdpSocket::bind(bind_addr).map_err(|error| format!("cannot bind: {error}"))?;
        sip.set_nonblocking(true)
            .map_err(|error| format!("cannot make the SIP socket non-blocking: {error}"))?;
        let local = sip
            .local_addr()
            .map_err(|error| format!("the SIP socket has no address: {error}"))?;
        let transport = TransportId(1);
        let mut agent = UserAgent::new(EndpointConfig::default(), seed)
            .map_err(|error| format!("cannot start a user agent: {error}"))?;
        agent
            .receive(
                Input::TransportBound {
                    transport,
                    protocol: TransportProtocol::Udp,
                    local,
                    remote: None,
                },
                now,
            )
            .map_err(|error| format!("cannot bind the transport: {error}"))?;
        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let engine = MediaEngine::new(
            catalog,
            MediaConfig::default(),
            WallClock::from_unix(now, unix_seconds, 0),
            media_seed,
        );
        Ok(Self {
            agent,
            engine,
            sip,
            local,
            transport,
            media: HashMap::new(),
            origins: HashMap::new(),
            sip_inbox: vec![0_u8; 65_535],
        })
    }

    fn account(
        &mut self,
        user: &str,
        pass: &str,
        server: &str,
        remote: SocketAddr,
    ) -> Result<AccountId, String> {
        let aor = uri(&format!("sip:{user}@{server}"))?;
        let registrar = uri(&format!("sip:{server}"))?;
        let contact = uri(&format!("sip:{user}@{}", advertised(self.local, remote)))?;
        Ok(self.agent.add_account(
            Account::new(aor, registrar, contact, self.transport, remote)
                .credentials(Credentials::new(user, pass))
                .expires(Duration::from_secs(300)),
        ))
    }

    /// Bind a fresh RTP socket for a call about to be placed or answered, and
    /// say where the offer or the answer should send media.
    fn open_media(
        &mut self,
        call: CallHandle,
        remote: SocketAddr,
        now: Instant,
    ) -> Result<SocketAddr, String> {
        let media = Media::bind(now)?;
        let port = media.port()?;
        self.media.insert(call, media);
        Ok(SocketAddr::new(route_to(remote), port))
    }

    /// Write what is waiting, and drain every event the engine has — which
    /// drains the agent too, since [`MediaEngine::poll_event`]'s own
    /// documentation makes it the one place that may. Returned rather than
    /// handed to a callback, so this is the same pump for `main`'s flow
    /// script and `pair`'s two roles, which react to events differently.
    fn pump(&mut self, now: Instant) -> Vec<Event> {
        self.flush();
        let mut events = Vec::new();
        while let Some(event) = self.engine.poll_event(&mut self.agent, now) {
            if let Event::Signalling(UaEvent::SessionChanged {
                call,
                local: Some(local),
                ..
            }) = &event
                && let Ok(described) = sipral_core::sdp::parse(local)
            {
                self.origins.insert(*call, described.origin);
            }
            events.push(event);
        }
        events
    }

    /// Write every SIP message the agent has queued.
    fn flush(&mut self) {
        while let Some(transmit) = self.agent.poll_transmit() {
            let _ = self.sip.send_to(&transmit.payload, transmit.destination);
        }
    }

    /// Run every active call's media for one tick, and carry whatever the
    /// engine had queued to send on its behalf.
    fn run_media(&mut self, now: Instant) {
        for call in self.engine.active().collect::<Vec<_>>() {
            let Some(mut session) = self.engine.session(call) else {
                continue;
            };
            if let Some(media) = self.media.get_mut(&call) {
                media.turn(&mut session, now);
            }
        }
        while let Some((call, destination, payload)) = self.engine.poll_rtcp(now) {
            if let Some(media) = self.media.get(&call) {
                media.send(destination, &payload);
            }
        }
        while let Some((call, destination, payload)) = self.engine.poll_farewell() {
            if let Some(media) = self.media.get(&call) {
                media.send(destination, &payload);
            }
        }
    }

    fn timers(&mut self, now: Instant) {
        self.engine.handle_timeout(now);
        self.agent.handle_timeout(now);
    }

    /// Read whatever SIP datagrams have arrived, non-blockingly. `true` when
    /// at least one did.
    fn read_sip(&mut self, now: Instant) -> bool {
        let mut arrived = false;
        loop {
            match self.sip.recv_from(&mut self.sip_inbox) {
                Ok((length, from)) => {
                    arrived = true;
                    let data = self.sip_inbox.get(..length).unwrap_or_default();
                    let _ = self.agent.receive(
                        Input::Datagram {
                            transport: self.transport,
                            remote: from,
                            local: self.local,
                            data,
                        },
                        now,
                    );
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        arrived
    }
}

/// Round the loop until the script is done or `deadline` passes.
fn drive(endpoint: &mut Endpoint, script: &mut Script, deadline: Instant) {
    loop {
        let now = Instant::now();
        for event in endpoint.pump(now) {
            script.on_event(endpoint, &event, now);
        }
        endpoint.run_media(now);
        endpoint.timers(now);
        script.on_tick(endpoint, now);
        if script.step == Step::Done || now > deadline {
            // the event that finished the flow has usually just queued its
            // last request — the binding given back, or a BYE — and nothing
            // after this loop is left to write it out
            endpoint.flush();
            return;
        }
        // no reader thread here, unlike `sipral_ua::Runtime`: this loop is
        // its own, and a short sleep after a quiet read is what keeps it from
        // spinning a whole core for the twenty seconds patience() allows
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

struct Script {
    flow: Flow,
    account: AccountId,
    extension: String,
    /// Who a transfer hands the call to.
    other: String,
    server: String,
    remote: SocketAddr,
    started: Instant,
    seen: Seen,
    call: Option<CallHandle>,
    /// The second leg of an attended transfer.
    consulted: Option<CallHandle>,
    /// What the primary call settled on when it first came up, kept so
    /// `Flow::HoldCodecChange` can tell whether the resume actually moved it.
    original_codec: Option<Codec>,
    /// What the primary call's media cost, from the `MediaEvent::Ended` that
    /// closed it: by the time a flow is judged its call has usually ended, and
    /// the engine has let the session go with it.
    ended: Option<StreamStatistics>,
    step: Step,
    asked: bool,
    /// When to hang up a call that is only there to carry audio or a digit.
    listen_until: Option<Instant>,
    /// When to stop waiting for the far end to be worth handing over.
    settled_by: Option<Instant>,
}

/// Where the script is. One value rather than a pile of flags, because the
/// order matters and a flag can be set twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Registering,
    Placing,
    Talking,
    /// Up, and waiting for the far end to be worth handing over.
    Settling,
    Holding,
    Resuming,
    /// `Flow::HoldCodecChange`'s own resume: a re-offer naming a narrower
    /// catalogue than the one the call held on.
    Reoffering,
    /// `Flow::Dtmf4733`: a digit is on its way, or has gone, and this end is
    /// waiting to hear it named back.
    Dialling,
    Consulting,
    Transferring,
    Ending,
    Done,
}

impl Script {
    /// A flow about to start: nothing registered, nothing placed.
    fn new(
        flow: Flow,
        account: AccountId,
        extension: &str,
        other: &str,
        server: &str,
        remote: SocketAddr,
        now: Instant,
    ) -> Self {
        Self {
            flow,
            account,
            extension: extension.to_owned(),
            other: other.to_owned(),
            server: server.to_owned(),
            remote,
            started: now,
            seen: Seen::default(),
            call: None,
            consulted: None,
            original_codec: None,
            ended: None,
            step: Step::Registering,
            asked: false,
            listen_until: None,
            settled_by: None,
        }
    }

    fn on_event(&mut self, endpoint: &mut Endpoint, event: &Event, now: Instant) {
        match event {
            Event::Signalling(signalling) => self.on_signalling(endpoint, signalling, now),
            Event::Media { call, event } => self.on_media(endpoint, *call, event, now),
            // `sipral::Event` is `#[non_exhaustive]`; a variant this harness
            // has never heard of is one it has nothing to judge either
            _ => (),
        }
    }

    fn on_signalling(&mut self, endpoint: &mut Endpoint, event: &UaEvent, now: Instant) {
        match event {
            UaEvent::Registered { .. } => {
                self.seen.saw(Fact::Registered);
                self.advance(endpoint, now);
            }
            UaEvent::Unregistered { .. } => {
                self.seen.saw(Fact::Unregistered);
                self.step = Step::Done;
            }
            UaEvent::RegistrationFailed { reason, status, .. } => {
                self.seen.refused = Some(match status {
                    Some(status) => format!("{reason} ({})", status.get()),
                    None => reason.to_string(),
                });
                self.step = Step::Done;
            }
            UaEvent::CallProgress {
                state: CallState::Ringing | CallState::EarlyMedia,
                ..
            } => self.seen.saw(Fact::Ringing),
            UaEvent::CallConfirmed { call, .. } => {
                if Some(*call) == self.consulted {
                    self.seen.saw(Fact::Consulted);
                } else {
                    self.seen.saw(Fact::Up);
                }
                self.advance(endpoint, now);
            }
            UaEvent::TransferProgress { .. } => self.seen.saw(Fact::Transferring),
            UaEvent::TransferDone { status, .. } => {
                if status.is_success() {
                    self.seen.saw(Fact::Transferred);
                } else {
                    self.seen.refused = Some(format!("the transfer ended {}", status.get()));
                }
                self.advance(endpoint, now);
            }
            UaEvent::DtmfSent { status, .. } => {
                if status.is_success() {
                    self.seen.saw(Fact::DigitSent);
                } else {
                    self.seen.refused = Some(format!("the INFO was answered {}", status.get()));
                }
            }
            UaEvent::SessionChanged { hold, .. } => {
                if hold.local {
                    self.seen.saw(Fact::Held);
                } else if self.seen.has(Fact::Held) {
                    self.seen.saw(Fact::Resumed);
                }
                self.advance(endpoint, now);
            }
            UaEvent::CallEnded {
                reason,
                status,
                response,
                ..
            } => {
                self.seen.saw(Fact::Over);
                if !self.seen.has(Fact::Up) {
                    self.seen.refused = Some(match status {
                        // a refusal usually says why in the reason phrase or a
                        // Warning, and the number alone sends you guessing
                        Some(status) => {
                            format!(
                                "{reason} ({}{})",
                                status.get(),
                                explained(response.as_ref())
                            )
                        }
                        None => reason.to_string(),
                    });
                }
                self.finish(endpoint, now);
            }
            _ => (),
        }
    }

    fn on_media(
        &mut self,
        endpoint: &mut Endpoint,
        call: CallHandle,
        event: &MediaEvent,
        now: Instant,
    ) {
        match *event {
            MediaEvent::Started { codec, .. } if Some(call) == self.call => {
                self.original_codec.get_or_insert(codec);
                if self.flow == Flow::Srtp
                    && endpoint
                        .engine
                        .session(call)
                        .is_some_and(|session| session.is_encrypted())
                {
                    self.seen.saw(Fact::Encrypted);
                }
            }
            MediaEvent::Changed {
                codec,
                direction: Direction::SendRecv,
            } if Some(call) == self.call
                && self.flow == Flow::HoldCodecChange
                && self.seen.has(Fact::Held) =>
            {
                // `Flow::HoldCodecChange`'s own resume, and only its: it goes
                // through `reoffer_onto`, whose `UserAgent::reoffer` keeps
                // whatever `UaEvent::SessionChanged.hold.local` already was
                // rather than reading the direction back out of the SDP it
                // was just handed — the ordinary hold and resume write that
                // flag themselves and need none of this. What the far end's
                // answer actually settled the stream's direction to is
                // `sipral::MediaSession`'s own, carried on this same event,
                // so that is what stands for "resumed" here instead — and,
                // as in the ordinary hold flow, only once the hold was agreed:
                // a change to flowing both ways before it is not a resume,
                // and a codec that moved then is not the resume's change
                self.seen.saw(Fact::Resumed);
                if self.original_codec.is_some_and(|was| was != codec) {
                    self.seen.saw(Fact::CodecChanged);
                }
            }
            MediaEvent::DigitReceived { digit, .. }
                if Some(call) == self.call && digit == Some(TEST_DIGIT.as_char()) =>
            {
                self.seen.saw(Fact::DigitConfirmed);
                self.hang_up(endpoint, now);
            }
            MediaEvent::Ended(statistics) if Some(call) == self.call => {
                self.ended = Some(statistics);
            }
            _ => (),
        }
    }

    fn on_tick(&mut self, endpoint: &mut Endpoint, now: Instant) {
        // once, not once per tick inside some window: the loop turns as fast
        // as the socket lets it, and a window let a single flow open a dozen
        // REGISTER transactions before the first answer came back
        if !self.asked {
            self.asked = true;
            let asked = endpoint.agent.register(self.account, now);
            self.tried("register", asked);
        }
        if self.listen_until.is_some_and(|due| now >= due) {
            self.listen_until = None;
            self.hang_up(endpoint, now);
        }
        // audio coming back is the far end saying it has bridged the call to
        // something, which is what makes it transferable
        if let Some(due) = self.settled_by
            && (self.heard(endpoint).received > 0 || now >= due)
        {
            self.settled_by = None;
            self.advance(endpoint, now);
        }
        if self.step == Step::Done || now > self.started + patience() {
            self.step = Step::Done;
        }
    }

    /// The next thing this flow does, once the last one has happened.
    fn advance(&mut self, endpoint: &mut Endpoint, now: Instant) {
        match self.step {
            Step::Registering if self.flow == Flow::Register => {
                self.step = Step::Done;
                let _ = endpoint.agent.unregister(self.account, now);
                self.step = Step::Ending;
            }
            Step::Registering => {
                self.step = Step::Placing;
                let media = CallMedia::new(catalog_for(self.flow), MediaConfig::default());
                let extension = self.call_extension();
                match self.place_at(endpoint, &extension, media, now) {
                    Ok(call) => self.call = Some(call),
                    Err(error) => {
                        self.seen.refused = Some(format!("call: {error}"));
                        self.step = Step::Ending;
                    }
                }
                self.step = Step::Talking;
            }
            Step::Talking if self.flow == Flow::Hold || self.flow == Flow::HoldCodecChange => {
                self.step = Step::Holding;
                if let Some(call) = self.call {
                    let asked = endpoint.agent.hold(call, now);
                    self.tried("hold", asked);
                }
            }
            Step::Holding if self.flow == Flow::Hold => {
                self.step = Step::Resuming;
                if let Some(call) = self.call {
                    let asked = endpoint.agent.resume(call, now);
                    self.tried("resume", asked);
                }
            }
            Step::Holding => {
                // Flow::HoldCodecChange: resume onto a narrower list than the
                // call held on, in one re-INVITE
                self.step = Step::Reoffering;
                if let Some(call) = self.call {
                    let asked = reoffer_onto(endpoint, call, &["PCMA"], now);
                    self.tried("resume with a codec change", asked);
                }
            }
            // not straight into the REFER: see SETTLE. The attended flow needs
            // no such wait, because placing the second leg is itself the delay
            Step::Talking if self.flow == Flow::Blind => {
                self.step = Step::Settling;
                self.settled_by = Some(now + SETTLE);
            }
            Step::Settling => {
                self.step = Step::Transferring;
                if let (Some(call), Some(target)) = (self.call, self.target()) {
                    let asked = endpoint.agent.transfer(call, &target, now);
                    self.tried("transfer", asked);
                }
            }
            Step::Talking if self.flow == Flow::Attended => {
                self.step = Step::Consulting;
                let other = self.other.clone();
                let media = CallMedia::new(catalog(), MediaConfig::default());
                match self.place_at(endpoint, &other, media, now) {
                    Ok(second) => self.consulted = Some(second),
                    Err(error) => {
                        self.seen.refused = Some(format!("consult: {error}"));
                        self.step = Step::Done;
                    }
                }
            }
            // the second leg is up, so there is somebody to hand the call to
            Step::Consulting => {
                self.step = Step::Transferring;
                if let (Some(call), Some(other)) = (self.call, self.consulted) {
                    let asked = endpoint.agent.transfer_to(call, other, now);
                    self.tried("attended transfer", asked);
                }
            }
            // a plain call is the one that carries the tone, so it waits
            Step::Talking if self.flow == Flow::Call || self.flow == Flow::Srtp => {
                self.listen_until = Some(now + dwell());
            }
            Step::Talking if self.flow == Flow::Dtmf4733 => {
                self.step = Step::Dialling;
                let dialled = self
                    .call
                    .and_then(|call| endpoint.engine.session(call))
                    .map(|mut session| session.dial(&TEST_DIGIT.to_string(), DEFAULT_DIGIT));
                if let Some(Err(error)) = dialled {
                    self.seen.refused = Some(format!("dial: {error}"));
                    self.step = Step::Ending;
                }
                // whichever answers first: the digit named back, or the timer
                self.listen_until = Some(now + dwell() + Duration::from_secs(2));
            }
            Step::Talking if self.flow == Flow::DtmfInfo => self.send_dtmf_by_info(endpoint, now),
            Step::Talking
            | Step::Resuming
            | Step::Reoffering
            | Step::Dialling
            | Step::Transferring => {
                self.hang_up(endpoint, now);
            }
            Step::Placing | Step::Ending | Step::Done => (),
        }
    }

    /// `Flow::DtmfInfo`'s own `Step::Talking`: send the test digit by INFO
    /// instead of `Flow::Dtmf4733`'s media, and wait for it to be named back
    /// the same way that flow does. Factored out of `advance` so that arm
    /// does not push it past `clippy::too_many_lines`.
    fn send_dtmf_by_info(&mut self, endpoint: &mut Endpoint, now: Instant) {
        self.step = Step::Dialling;
        if let Some(call) = self.call {
            let asked = endpoint.agent.send_dtmf_info(
                call,
                TEST_DIGIT.as_char(),
                DtmfInfoForm::Relay,
                0,
                now,
            );
            self.tried("send dtmf by info", asked);
        }
        // whichever answers first: the digit named back, or the timer
        self.listen_until = Some(now + dwell() + Duration::from_secs(2));
    }

    /// Ask the stack for something, and remember it if it says no.
    ///
    /// Swallowing these is how a flow ends up reporting that the far end never
    /// answered, when the truth is that nothing was ever sent.
    fn tried(&mut self, what: &str, outcome: Result<(), UaError>) {
        if let Err(error) = outcome {
            self.seen.refused = Some(format!("{what}: {error}"));
            self.step = Step::Ending;
        }
    }

    /// Who a transfer hands the call to.
    fn target(&self) -> Option<Uri> {
        Uri::parse_str(&format!("sip:{}@{}", self.other, self.server)).ok()
    }

    /// The extension this flow's primary call dials — `self.extension`
    /// (9000 unless told otherwise) for every flow except the three that need
    /// a dialplan entry of their own: `Flow::Dtmf4733` and `Flow::DtmfInfo`
    /// (interop/asterisk and interop/freeswitch both add 9003 for the first;
    /// only Asterisk runs the second, over its own `labuser-infodtmf`
    /// endpoint) and `Flow::Srtp` (9004, Asterisk only — see
    /// `interop/asterisk/extensions.conf`).
    fn call_extension(&self) -> String {
        match self.flow {
            Flow::Dtmf4733 | Flow::DtmfInfo => "9003".to_owned(),
            Flow::Srtp => "9004".to_owned(),
            _ => self.extension.clone(),
        }
    }

    /// Place a call to `extension` on this flow's own server and account,
    /// with `media`'s catalogue — the primary leg and an attended transfer's
    /// consultation leg are both exactly this, so the two arms in
    /// [`Script::advance`] that place one share it.
    fn place_at(
        &self,
        endpoint: &mut Endpoint,
        extension: &str,
        media: CallMedia,
        now: Instant,
    ) -> Result<CallHandle, String> {
        let target = uri(&format!("sip:{extension}@{}", self.server))?;
        let placing = OutgoingCall::new(target).to_address(endpoint.transport, self.remote);
        place_call(endpoint, self.account, placing, media, self.remote, now)
    }

    /// The primary call's own `Quality`, for the result line: what the call
    /// ended on, or what it is doing now if it is still up.
    fn quality(&self, endpoint: &mut Endpoint, now: Instant) -> Option<Quality> {
        if let Some(ended) = self.ended {
            return Some(ended.quality);
        }
        self.call
            .and_then(|call| endpoint.engine.session(call))
            .map(|session| session.statistics(now).quality)
    }

    fn heard(&self, endpoint: &Endpoint) -> audio::Heard {
        self.call
            .and_then(|call| endpoint.media.get(&call))
            .map(Media::heard)
            .unwrap_or_default()
    }

    fn hang_up(&mut self, endpoint: &mut Endpoint, now: Instant) {
        if self.step == Step::Ending || self.step == Step::Done {
            return;
        }
        self.step = Step::Ending;
        if let Some(call) = self.call {
            self.seen.saw(Fact::Ours);
            let _ = endpoint.agent.hangup(call, now);
        }
    }

    fn finish(&mut self, endpoint: &mut Endpoint, now: Instant) {
        let _ = endpoint.agent.unregister(self.account, now);
        self.step = Step::Done;
    }

    /// What this flow said it would prove.
    ///
    /// `heard` is this flow's own tally of its primary call's audio, and
    /// `require_audio` is whether `SIPRAL_REQUIRE_AUDIO` asked for any of it
    /// to have come back. The caller reads the environment, so the judgement
    /// itself does not.
    fn verdict(&self, heard: audio::Heard, require_audio: bool) -> Result<(), String> {
        if let Some(ref why) = self.seen.refused {
            return Err(why.clone());
        }
        let owed: &[(Fact, &str)] = match self.flow {
            Flow::Register => &[
                (Fact::Registered, "no binding was granted"),
                (Fact::Unregistered, "the binding was not given back"),
            ],
            // Ours, and before Over: a far end that answers and hangs up half a
            // millisecond later satisfies "connected" and "ended" without the
            // call ever having been one
            Flow::Call | Flow::Srtp => {
                const CALL: &[(Fact, &str)] = &[
                    (Fact::Registered, "no binding was granted"),
                    (Fact::Up, "the call did not connect"),
                    (Fact::Ours, "the far end ended the call before we asked"),
                    (Fact::Over, "the call did not end"),
                ];
                CALL
            }
            Flow::Hold => &[
                (Fact::Registered, "no binding was granted"),
                (Fact::Up, "the call did not connect"),
                (Fact::Held, "the hold was not agreed"),
                (Fact::Resumed, "the resume was not agreed"),
                (Fact::Ours, "the far end ended the call before we asked"),
                (Fact::Over, "the call did not end"),
            ],
            // No Ours: a transfer that worked is a call this end is not in
            // any more, and the far end is right to hang it up. And no
            // Transferring either — RFC 3515 §2.4.4 asks for a 100 Trying
            // first only when there is something to wait for, and FreeSWITCH
            // sends one NOTIFY, terminated, carrying the final status
            Flow::Blind => &[
                (Fact::Registered, "no binding was granted"),
                (Fact::Up, "the call did not connect"),
                (Fact::Transferred, "the transfer did not complete"),
                (Fact::Over, "the call did not end"),
            ],
            Flow::Attended => &[
                (Fact::Registered, "no binding was granted"),
                (Fact::Up, "the call did not connect"),
                (Fact::Consulted, "the consultation call did not connect"),
                (Fact::Transferred, "the transfer did not complete"),
                (Fact::Over, "the call did not end"),
            ],
            Flow::Dtmf4733 => &[
                (Fact::Registered, "no binding was granted"),
                (Fact::Up, "the call did not connect"),
                (
                    Fact::DigitConfirmed,
                    "the digit sent never came back named the same way",
                ),
                (Fact::Ours, "the far end ended the call before we asked"),
                (Fact::Over, "the call did not end"),
            ],
            Flow::DtmfInfo => &[
                (Fact::Registered, "no binding was granted"),
                (Fact::Up, "the call did not connect"),
                (Fact::DigitSent, "the INFO was never answered with success"),
                (
                    Fact::DigitConfirmed,
                    "the digit sent by INFO never came back named the same way",
                ),
                (Fact::Ours, "the far end ended the call before we asked"),
                (Fact::Over, "the call did not end"),
            ],
            Flow::HoldCodecChange => &[
                (Fact::Registered, "no binding was granted"),
                (Fact::Up, "the call did not connect"),
                (Fact::Held, "the hold was not agreed"),
                (Fact::Resumed, "the resume was not agreed"),
                (
                    Fact::CodecChanged,
                    "the codec after the resume was the same one the call held on",
                ),
                (Fact::Ours, "the far end ended the call before we asked"),
                (Fact::Over, "the call did not end"),
            ],
        };
        for (fact, why) in owed {
            if !self.seen.has(*fact) {
                return Err((*why).to_owned());
            }
        }
        if self.flow == Flow::Srtp && !self.seen.has(Fact::Encrypted) {
            return Err("the call connected but never ran under SDES".to_owned());
        }
        // Audio is asked for only when something is known to send it back, and
        // only of the calls that dwell on the tone: the others hang up as soon
        // as what they came to prove has happened. The SRTP call dwells on the
        // same tone, and a stream that agreed a key and never decrypted a frame
        // is the failure that flow exists to find.
        if (self.flow == Flow::Call || self.flow == Flow::Srtp)
            && require_audio
            && heard.audible == 0
        {
            return Err(format!(
                "nothing audible came back: {} sent, {} received, {} refused",
                heard.sent, heard.received, heard.refused
            ));
        }
        Ok(())
    }
}

/// Place a call with `media`'s catalogue, opening this call's own RTP socket
/// first so its port can go in the offer.
///
/// Shared between `main`'s flow script, which places both legs of an
/// attended transfer this way, and `pair`'s caller.
pub(crate) fn place_call(
    endpoint: &mut Endpoint,
    account: AccountId,
    outgoing: OutgoingCall,
    media: CallMedia,
    remote: SocketAddr,
    now: Instant,
) -> Result<CallHandle, String> {
    // a call handle is only minted by `place_with`, and the socket has to
    // exist before that call, so it is opened against a handle nothing has
    // been placed on yet and moved once the real one is known
    let placeholder = Media::bind(now)?;
    let port = placeholder.port()?;
    let local = SocketAddr::new(route_to(remote), port);
    let call = endpoint
        .engine
        .place_with(&mut endpoint.agent, account, outgoing, local, media, now)
        .map_err(|error| error.to_string())?;
    endpoint.media.insert(call, placeholder);
    Ok(call)
}

/// Change a live call onto `order`'s catalogue, in one re-INVITE.
///
/// `sipral::MediaEngine` writes an application's offers for
/// [`MediaEngine::place_with`], [`MediaEngine::ring_with`] and
/// [`MediaEngine::answer_with`], but has no equivalent for an application
/// asking to re-offer a live call on a catalogue of its own choosing —
/// [`UserAgent::hold`] and [`UserAgent::resume`] keep the one already
/// negotiated. `UserAgent::reoffer`'s own documentation names exactly this
/// case ("a codec change ... anything else the application decides") and
/// says writing hold and resume by hand is how the direction attributes get
/// wrong; a plain `SendRecv` list is neither of those, so this is that
/// sanctioned seam, not a second offer-writer for the ordinary flows. The
/// media consequence — a live codec change, statistics carried across it, an
/// SRTP context re-keyed if one is running — is still entirely
/// [`sipral::MediaEngine::poll_event`]'s: this only writes the bytes that
/// tell it to.
///
/// The `o=` line is the one this end last described the call with, version
/// and all, and `UserAgent::reoffer` moves the version on by one: RFC 3264 §8
/// has an offer that modifies a session keep that line identical to the
/// previous one but for a version one higher. So a call has to have been
/// described once through a `UaEvent::SessionChanged` first — the hold that
/// comes before this in `Flow::HoldCodecChange` is that — and one that has
/// not is [`UaError::NoSession`].
fn reoffer_onto(
    endpoint: &mut Endpoint,
    call: CallHandle,
    order: &[&str],
    now: Instant,
) -> Result<(), UaError> {
    let Some(address) = endpoint
        .media
        .get(&call)
        .and_then(|media| media.port().ok())
        .map(|port| SocketAddr::new(route_to(endpoint.local), port))
    else {
        return Err(UaError::NoSuchCall);
    };
    let Some(origin) = endpoint.origins.get(&call).cloned() else {
        return Err(UaError::NoSession);
    };
    let catalog = CodecCatalog::with_order(order).unwrap_or_else(|_| catalog());
    let offer = catalog
        .capabilities()
        .offer("audio", address.port(), Direction::SendRecv);
    let mut description = SessionDescription::new(origin, Connection::new(address.ip()));
    description.media.push(offer);
    endpoint.agent.reoffer(call, &description.to_bytes(), now)
}

/// The address that reaches the lab, not a wildcard. What this is given is
/// what goes into every `Via`, and RFC 3261 §18.1.1 makes sent-by the place
/// a response is sent to; `0.0.0.0` names no such place. Asterisk forgave
/// it because it answers to `rport`, and that is exactly why it went
/// unnoticed — a carrier that reads the Via instead will not.
fn run(
    flow: Flow,
    server: &str,
    remote: SocketAddr,
    extension: &str,
    other: &str,
    user: &str,
    pass: &str,
) -> Result<String, String> {
    let bind_addr = SocketAddr::new(route_to(remote), 0);
    let now = Instant::now();
    let mut endpoint = Endpoint::bind(seed(flow), media_seed(flow), bind_addr, catalog(), now)?;
    let account = endpoint.account(user, pass, server, remote)?;

    let mut script = Script::new(flow, account, extension, other, server, remote, now);

    drive(&mut endpoint, &mut script, now + patience());
    let heard = script.heard(&endpoint);
    script.verdict(heard, env::var("SIPRAL_REQUIRE_AUDIO").is_ok())?;

    if heard.sent == 0 {
        return Ok(String::new());
    }
    let mut said = format!(
        "   ({} sent, {} back, {} audible, {} refused",
        heard.sent, heard.received, heard.audible, heard.refused
    );
    // the session's own account of the path, which is the only thing that
    // says anything under an impaired network: how much never arrived, how
    // late the rest was, and how much had to be invented
    if let Some(quality) = script.quality(&mut endpoint, Instant::now()) {
        use std::fmt::Write as _;
        let _ = write!(
            said,
            "; lost {}, late {}, jitter {}ms, delay {}ms of {}ms, \
             shrunk {}, stretched {}",
            quality.lost,
            quality.discarded_late,
            quality.jitter.as_millis(),
            quality.delay.as_millis(),
            quality.target_delay.as_millis(),
            quality.shrunk,
            quality.stretched
        );
    }
    said.push(')');
    Ok(said)
}

/// The address to put in `Contact`, which is the one the far end can reach.
///
/// Binding to a wildcard gives back `0.0.0.0`, and a registrar told to send
/// calls there will send them nowhere. The address that reaches the lab is the
/// one on the route to it.
pub(crate) fn advertised(local: SocketAddr, remote: SocketAddr) -> SocketAddr {
    if local.ip().is_unspecified() {
        return SocketAddr::new(route_to(remote), local.port());
    }
    local
}

/// Which of this host's addresses a datagram to `remote` would leave from.
pub(crate) fn route_to(remote: SocketAddr) -> std::net::IpAddr {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect(remote)?;
            socket.local_addr()
        })
        .map_or(std::net::IpAddr::from([127, 0, 0, 1]), |address| {
            address.ip()
        })
}

/// What a refusal said about itself, beyond its number.
fn explained(response: Option<&OwnedMessage>) -> String {
    let Some(response) = response else {
        return String::new();
    };
    let raw = response.as_raw();
    let mut said = String::new();
    if let Some(reason) = raw.reason() {
        said.push(' ');
        said.push_str(&String::from_utf8_lossy(reason));
    }
    if let Some(warning) = HeaderName::from_bytes(b"Warning").and_then(|name| raw.header(name)) {
        said.push_str(" — ");
        said.push_str(&String::from_utf8_lossy(warning));
    }
    said
}

fn resolve(host: &str, port: u16) -> Option<SocketAddr> {
    std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
        .ok()?
        .next()
}

pub(crate) fn uri(text: &str) -> Result<Uri, String> {
    Uri::parse_str(text).map_err(|_| format!("{text} is not a URI"))
}

/// A different signalling seed per flow, so that two runs never mint the same
/// branch.
const fn seed(flow: Flow) -> [u8; 32] {
    match flow {
        Flow::Register => [17; 32],
        Flow::Call => [29; 32],
        Flow::Hold => [41; 32],
        Flow::Blind => [53; 32],
        Flow::Attended => [67; 32],
        Flow::Dtmf4733 => [79; 32],
        Flow::DtmfInfo => [97; 32],
        Flow::Srtp => [83; 32],
        Flow::HoldCodecChange => [89; 32],
    }
}

/// A media seed independent of the signalling one — `MediaEngine::new`'s own
/// requirement, so that a recording of this run's signalling never carries
/// the means to derive whatever key an SRTP flow drew.
const fn media_seed(flow: Flow) -> [u8; 32] {
    match flow {
        Flow::Register => [117; 32],
        Flow::Call => [129; 32],
        Flow::Hold => [141; 32],
        Flow::Blind => [153; 32],
        Flow::Attended => [167; 32],
        Flow::Dtmf4733 => [179; 32],
        Flow::DtmfInfo => [197; 32],
        Flow::Srtp => [183; 32],
        Flow::HoldCodecChange => [189; 32],
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::time::{Duration, Instant};

    use sipral::{CallMedia, Codec, Direction, Event, MediaConfig, MediaEvent, OutgoingCall};

    use super::{Endpoint, Fact, Flow, Script, Step, catalog, drive, media_seed, place_call, seed};
    use crate::audio::Heard;

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    /// A registrar that grants every binding and a far end that answers every
    /// INVITE busy, on one loopback socket, until `until`. Returns every
    /// request it was sent, in the order they came.
    fn busy_registrar(socket: &UdpSocket, until: Instant) -> Vec<String> {
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("a read timeout");
        let mut seen = Vec::new();
        let mut inbox = vec![0_u8; 65_535];
        while Instant::now() < until {
            let Ok((length, from)) = socket.recv_from(&mut inbox) else {
                continue;
            };
            let request = String::from_utf8_lossy(&inbox[..length]).into_owned();
            let method = request.split(' ').next().unwrap_or_default().to_owned();
            let status = match method.as_str() {
                "REGISTER" => "200 OK",
                "INVITE" => "486 Busy Here",
                _ => {
                    seen.push(request);
                    continue;
                }
            };
            let mut response = format!("SIP/2.0 {status}\r\n");
            for header in request.lines() {
                let name = header
                    .split(':')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase();
                match name.as_str() {
                    "via" | "from" | "call-id" | "cseq" => {
                        response.push_str(header);
                        response.push_str("\r\n");
                    }
                    "to" => {
                        response.push_str(header);
                        response.push_str(";tag=lab\r\n");
                    }
                    "contact" if method == "REGISTER" => {
                        let uri = header
                            .split_once('<')
                            .and_then(|(_, rest)| rest.split_once('>'))
                            .map(|(uri, _)| uri)
                            .unwrap_or_default();
                        response.push_str("Contact: <");
                        response.push_str(uri);
                        response.push_str(">;expires=300\r\n");
                    }
                    _ => {}
                }
            }
            if method == "REGISTER" {
                response.push_str("Expires: 300\r\n");
            }
            response.push_str("Content-Length: 0\r\n\r\n");
            let _ = socket.send_to(response.as_bytes(), from);
            seen.push(request);
        }
        seen
    }

    /// `Flow::HoldCodecChange` reads its resume off the media's own direction,
    /// and the ordinary hold flow only counts a resume that follows a hold. A
    /// session that changes to flowing both ways before any hold was agreed —
    /// a far end that moved its media address, a re-INVITE of its own — is
    /// not the resume, and a codec that moved then is not the change this
    /// flow's resume asked for; counting either lets the flow pass on
    /// something that happened before the hold did.
    #[test]
    fn a_change_that_flows_both_ways_before_the_hold_is_not_the_resume() {
        let far_end = UdpSocket::bind(SocketAddr::new(LOOPBACK, 0)).expect("a far end");
        let remote = far_end.local_addr().expect("bound");
        let (mut endpoint, mut script) = scripted(Flow::HoldCodecChange, remote);
        let target = super::uri("sip:9000@127.0.0.1").expect("a URI");
        let outgoing = OutgoingCall::new(target).to_address(endpoint.transport, remote);
        let media = CallMedia::new(catalog(), MediaConfig::default());
        let call = place_call(
            &mut endpoint,
            script.account,
            outgoing,
            media,
            remote,
            Instant::now(),
        )
        .expect("a call handle");
        script.call = Some(call);
        script.original_codec = Some(Codec::Pcmu);

        let both_ways_on_another_codec = Event::Media {
            call,
            event: MediaEvent::Changed {
                codec: Codec::Pcma,
                direction: Direction::SendRecv,
            },
        };
        script.on_event(&mut endpoint, &both_ways_on_another_codec, Instant::now());
        assert!(
            !script.seen.has(Fact::Resumed),
            "a change before any hold counted as the resume"
        );
        assert!(
            !script.seen.has(Fact::CodecChanged),
            "a codec that moved before any hold counted as the resume's change"
        );

        script.seen.saw(Fact::Held);
        script.on_event(&mut endpoint, &both_ways_on_another_codec, Instant::now());
        assert!(
            script.seen.has(Fact::Resumed) && script.seen.has(Fact::CodecChanged),
            "the same change after the hold is the resume, onto another codec"
        );
    }

    /// A flow ends in the same event that queues its last request — a call
    /// that ends gives its binding back from `Script::finish` — and `drive`
    /// used to stop the moment the script said it was done, before anything
    /// else wrote the queue out. The binding then sat on the registrar until
    /// it expired: six of them from one run against Asterisk, whose lab
    /// endpoint allows ten, so a second run inside five minutes had its
    /// REGISTERs refused.
    #[test]
    fn a_flow_whose_call_ends_still_gives_its_binding_back() {
        let registrar = UdpSocket::bind(SocketAddr::new(LOOPBACK, 0)).expect("a registrar socket");
        let remote = registrar.local_addr().expect("bound");
        let (mut endpoint, mut script) = scripted(Flow::Call, remote);
        let until = Instant::now() + Duration::from_millis(2_500);
        let server = std::thread::spawn(move || busy_registrar(&registrar, until));

        drive(
            &mut endpoint,
            &mut script,
            Instant::now() + Duration::from_secs(2),
        );
        let requests = server.join().expect("the registrar's own thread");
        let methods: Vec<&str> = requests
            .iter()
            .filter_map(|request| request.split(' ').next())
            .collect();

        assert!(
            script.seen.has(Fact::Registered),
            "the binding was never granted: {methods:?}"
        );
        assert!(
            script.step == Step::Done && script.seen.has(Fact::Over),
            "the call was never refused: {methods:?}"
        );
        let invite = methods
            .iter()
            .position(|method| *method == "INVITE")
            .expect("an INVITE went out");
        assert!(
            methods[invite..].contains(&"REGISTER"),
            "the flow ended without giving its binding back: {methods:?}"
        );
    }

    /// An endpoint on loopback and a script for `flow` on it, built the way
    /// `run` builds them, against a far end at `remote`.
    pub(crate) fn scripted(flow: Flow, remote: SocketAddr) -> (Endpoint, Script) {
        let now = Instant::now();
        let mut endpoint = Endpoint::bind(
            seed(flow),
            media_seed(flow),
            SocketAddr::new(LOOPBACK, 0),
            catalog(),
            now,
        )
        .expect("binding on loopback");
        let account = endpoint
            .account("labuser", "labpass", "127.0.0.1", remote)
            .expect("an account");
        let script = Script::new(flow, account, "9000", "9001", "127.0.0.1", remote, now);
        (endpoint, script)
    }

    /// Every fact a call that dwells owes, so that the only thing left for
    /// the verdict to judge is the audio.
    fn a_call_that_did_everything_but_carry_audio(flow: Flow) -> Script {
        let (_endpoint, mut script) = scripted(flow, SocketAddr::new(LOOPBACK, 5060));
        for fact in [
            Fact::Registered,
            Fact::Up,
            Fact::Ours,
            Fact::Over,
            Fact::Encrypted,
        ] {
            script.seen.saw(fact);
        }
        script
    }

    /// `scripts/lab.sh` sets `SIPRAL_REQUIRE_AUDIO`, and every impairment
    /// profile's "audio survived it" rests on it: a call that connected and
    /// ended with nothing audible coming back is a failure, not a pass. The
    /// SRTP flow dwells on the same tone the plain call does, and a stream
    /// that negotiated SDES but never decrypted a frame is exactly what it
    /// exists to catch.
    #[test]
    fn a_call_that_heard_nothing_fails_when_audio_is_required() {
        let silent = Heard {
            sent: 100,
            received: 0,
            audible: 0,
            refused: 3,
        };
        for flow in [Flow::Call, Flow::Srtp] {
            let script = a_call_that_did_everything_but_carry_audio(flow);
            let verdict = script.verdict(silent, true);
            assert!(
                verdict
                    .as_ref()
                    .is_err_and(|why| why.contains("nothing audible came back")),
                "{flow:?} passed with nothing audible: {verdict:?}"
            );
            assert_eq!(
                script.verdict(silent, false),
                Ok(()),
                "{flow:?} failed on audio nobody asked for"
            );
            let heard = Heard {
                audible: 40,
                ..silent
            };
            assert_eq!(
                script.verdict(heard, true),
                Ok(()),
                "{flow:?} failed although the tone came back"
            );
        }
    }
}
