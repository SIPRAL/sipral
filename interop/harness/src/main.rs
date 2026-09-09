// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Drives `sipral-ua` against the container lab and judges each flow.
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

mod media;
mod pair;

use std::env;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::msg::{HeaderName, OwnedMessage};
use sipral_core::sdp;

use crate::media::Media;
use sipral_ua::{
    Account, AccountId, CallHandle, CallState, Control, Credentials, EndpointConfig, Handler,
    OutgoingCall, Runtime, UaError, UaEvent, Uri, UserAgent,
};

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

/// The offer the harness makes: G.711, both laws, one stream.
///
/// Both, because offering one is not what a client does. The lab's servers
/// were configured here and all of them took mu-law; the first real PBX this
/// met allows A-law only, which is the ordinary European default, and answered
/// 488. `sipral-media` has had both laws since the day it was written — only
/// the offer was narrow.
const OFFER: &str = "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\n\
t=0 0\r\nm=audio {port} RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n";

/// The same offer with G.722 first, for `SIPRAL_CODEC=g722`.
///
/// Not the default, and deliberately: every lab server takes G.722, so adding
/// it to the ordinary offer would silently change what the ten flows have been
/// proving for days. Asked for by name, it puts the wideband codec through the
/// same ten flows against real software, which is the only thing that can say
/// the codec is right on the wire rather than right against itself.
///
/// The clock rate on the `a=rtpmap` line is 8000 and the codec samples at
/// 16000. That is not a mistake here: RFC 3551 §4.5.2 fixes it, "for
/// historical reasons", and a peer that sees 16000 refuses the stream.
const OFFER_WIDEBAND: &str = "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\n\
t=0 0\r\nm=audio {port} RTP/AVP 9 0 8\r\na=rtpmap:9 G722/8000\r\n\
a=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n";

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
    let wanted = env::var("SIPRAL_FLOWS").unwrap_or_default();

    let Some(remote) = resolve(&server, port) else {
        println!("cannot resolve {server}:{port}");
        return ExitCode::FAILURE;
    };
    println!("lab: {server}:{port} at {remote}, extension {extension}, as {user}");

    let mut failures = 0;
    for flow in [
        Flow::Register,
        Flow::Call,
        Flow::Hold,
        Flow::Blind,
        Flow::Attended,
    ] {
        if !wanted.is_empty() && !wanted.split(',').any(|name| name.trim() == flow.key()) {
            continue;
        }
        match run(flow, &server, remote, &extension, &other, &user, &pass) {
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
}

impl Flow {
    const fn name(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Call => "call",
            Self::Hold => "hold and resume",
            Self::Blind => "blind transfer",
            Self::Attended => "attended transfer",
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

struct Script {
    flow: Flow,
    account: AccountId,
    extension: String,
    /// Who a transfer hands the call to.
    other: String,
    server: String,
    /// The address to write into the offer, which is the one the far end can
    /// answer to. Binding to a wildcard gives back 0.0.0.0, and `c=IN IP4
    /// 0.0.0.0` is not an address at all — RFC 3264 §8.4 makes it hold. The
    /// lab tolerated it and every call there was connecting to a black hole;
    /// a real Asterisk answers 488.
    local: SocketAddr,
    started: Instant,
    seen: Seen,
    call: Option<CallHandle>,
    /// The second leg of an attended transfer.
    consulted: Option<CallHandle>,
    step: Step,
    asked: bool,
    /// The socket, the RTP session and the tone.
    media: Media,
    /// What we offered, kept so the answer can be read against it.
    offer: Option<String>,
    /// When to hang up a call that is only there to carry audio.
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
    Consulting,
    Transferring,
    Ending,
    Done,
}

impl Handler for Script {
    fn on_event(&mut self, agent: &mut UserAgent, event: UaEvent, now: Instant) {
        match event {
            UaEvent::Registered { .. } => {
                self.seen.saw(Fact::Registered);
                self.advance(agent, now);
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
            UaEvent::CallConfirmed {
                call, ref response, ..
            } => {
                if Some(call) == self.consulted {
                    self.seen.saw(Fact::Consulted);
                } else {
                    self.seen.saw(Fact::Up);
                    self.open_media(response.as_ref(), now);
                }
                self.advance(agent, now);
            }
            UaEvent::TransferProgress { .. } => self.seen.saw(Fact::Transferring),
            UaEvent::TransferDone { status, .. } => {
                if status.is_success() {
                    self.seen.saw(Fact::Transferred);
                } else {
                    self.seen.refused = Some(format!("the transfer ended {}", status.get()));
                }
                self.advance(agent, now);
            }
            UaEvent::SessionChanged { hold, .. } => {
                if hold.local {
                    self.seen.saw(Fact::Held);
                } else if self.seen.has(Fact::Held) {
                    self.seen.saw(Fact::Resumed);
                }
                self.advance(agent, now);
            }
            UaEvent::CallEnded {
                reason,
                status,
                ref response,
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
                self.finish(agent, now);
            }
            _ => (),
        }
    }

    fn on_tick(&mut self, agent: &mut UserAgent, now: Instant) -> Control {
        // once, not once per tick inside some window: the loop turns as fast as
        // the socket lets it, and a window let a single flow open a dozen
        // REGISTER transactions before the first answer came back
        if !self.asked {
            self.asked = true;
            let asked = agent.register(self.account, now);
            self.tried("register", asked);
        }
        self.media.turn(now);
        if self.listen_until.is_some_and(|due| now >= due) {
            self.listen_until = None;
            self.hang_up(agent, now);
        }
        // audio coming back is the far end saying it has bridged the call to
        // something, which is what makes it transferable
        if let Some(due) = self.settled_by
            && (self.media.heard().received > 0 || now >= due)
        {
            self.settled_by = None;
            self.advance(agent, now);
        }
        if self.step == Step::Done || now > self.started + patience() {
            return Control::Stop;
        }
        Control::Continue
    }
}

impl Script {
    /// The next thing this flow does, once the last one has happened.
    fn advance(&mut self, agent: &mut UserAgent, now: Instant) {
        match self.step {
            Step::Registering if self.flow == Flow::Register => {
                self.step = Step::Done;
                let _ = agent.unregister(self.account, now);
                self.step = Step::Ending;
            }
            Step::Registering => {
                self.step = Step::Placing;
                let target = format!("sip:{}@{}", self.extension, self.server);
                let Ok(target) = Uri::parse_str(&target) else {
                    self.step = Step::Done;
                    return;
                };
                let offer = self.offer();
                let placing =
                    OutgoingCall::new(target).offer(Arc::from(offer.clone().into_bytes()));
                self.offer = Some(offer);
                match agent.call(self.account, &placing, now) {
                    Ok(call) => self.call = Some(call),
                    Err(_) => self.step = Step::Done,
                }
                self.step = Step::Talking;
            }
            Step::Talking if self.flow == Flow::Hold => {
                self.step = Step::Holding;
                if let Some(call) = self.call {
                    let asked = agent.hold(call, now);
                    self.tried("hold", asked);
                }
            }
            Step::Holding => {
                self.step = Step::Resuming;
                if let Some(call) = self.call {
                    let asked = agent.resume(call, now);
                    self.tried("resume", asked);
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
                    let asked = agent.transfer(call, &target, now);
                    self.tried("transfer", asked);
                }
            }
            Step::Talking if self.flow == Flow::Attended => {
                self.step = Step::Consulting;
                let offer = self.offer();
                if let (Some(call), Some(target)) = (self.call, self.target()) {
                    let placing = OutgoingCall::new(target).offer(Arc::from(offer.into_bytes()));
                    match agent.consult(call, &placing, now) {
                        Ok(second) => self.consulted = Some(second),
                        Err(_) => self.step = Step::Done,
                    }
                }
            }
            // the second leg is up, so there is somebody to hand the call to
            Step::Consulting => {
                self.step = Step::Transferring;
                if let (Some(call), Some(other)) = (self.call, self.consulted) {
                    let asked = agent.transfer_to(call, other, now);
                    self.tried("attended transfer", asked);
                }
            }
            // a plain call is the one that carries the tone, so it waits
            Step::Talking if self.flow == Flow::Call => {
                self.listen_until = Some(now + dwell());
            }
            Step::Talking | Step::Resuming | Step::Transferring => self.hang_up(agent, now),
            Step::Placing | Step::Ending | Step::Done => (),
        }
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

    /// The offer this flow makes, naming the port the RTP socket really has.
    fn offer(&self) -> String {
        let template = match env::var("SIPRAL_CODEC").as_deref() {
            Ok("g722") => OFFER_WIDEBAND,
            _ => OFFER,
        };
        template
            .replace("{ip}", &self.local.ip().to_string())
            .replace("{port}", &self.media.port().unwrap_or(0).to_string())
    }

    /// Read the answer against our offer and start the media.
    ///
    /// This is the first thing outside sipral-core's own tests to put a real
    /// answer through `media_plan`, which is the whole point of the seam.
    fn open_media(&mut self, response: Option<&OwnedMessage>, now: Instant) {
        let (Some(response), Some(offer)) = (response, self.offer.as_ref()) else {
            return;
        };
        let body = response.as_raw().body();
        if body.is_empty() {
            return;
        }
        let (Ok(ours), Ok(theirs)) = (sdp::parse(offer.as_bytes()), sdp::parse(body)) else {
            return;
        };
        if let Ok(Some(plan)) = ours.media_plan(&theirs, 0) {
            self.media.start(&plan, 0x5149_5241, now);
        }
    }

    fn hang_up(&mut self, agent: &mut UserAgent, now: Instant) {
        self.step = Step::Ending;
        if let Some(call) = self.call {
            self.seen.saw(Fact::Ours);
            let _ = agent.hangup(call, now);
        }
    }

    fn finish(&mut self, agent: &mut UserAgent, now: Instant) {
        let _ = agent.unregister(self.account, now);
        self.step = Step::Done;
    }

    /// What this flow said it would prove.
    fn verdict(&self) -> Result<(), String> {
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
            Flow::Call => &[
                (Fact::Registered, "no binding was granted"),
                (Fact::Up, "the call did not connect"),
                (Fact::Ours, "the far end ended the call before we asked"),
                (Fact::Over, "the call did not end"),
            ],
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
        };
        for (fact, why) in owed {
            if !self.seen.has(*fact) {
                return Err((*why).to_owned());
            }
        }
        // Audio is asked for only when something is known to echo. A tone sent
        // into a call that plays a recording comes back as the recording, and
        // "sound arrived" would then say nothing about what we sent.
        let heard = self.media.heard();
        // and only of the plain call, which is the one that dwells: the others
        // hang up as soon as what they came to prove has happened
        if self.flow == Flow::Call
            && std::env::var("SIPRAL_REQUIRE_AUDIO").is_ok()
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

fn run(
    flow: Flow,
    server: &str,
    remote: SocketAddr,
    extension: &str,
    other: &str,
    user: &str,
    pass: &str,
) -> Result<String, String> {
    // The address that reaches the lab, not a wildcard. What this is given is
    // what goes into every `Via`, and RFC 3261 §18.1.1 makes sent-by the place
    // a response is sent to; `0.0.0.0` names no such place. Asterisk forgave
    // it because it answers to `rport`, and that is exactly why it went
    // unnoticed — a carrier that reads the Via instead will not.
    let bind = SocketAddr::new(route_to(remote), 0);
    let media = Media::bind(Instant::now())?;
    let mut runtime = Runtime::bind(EndpointConfig::default(), seed(flow), bind)
        .map_err(|error| format!("cannot bind: {error}"))?;
    let local = runtime.local();
    let transport = runtime.transport();

    let aor = uri(&format!("sip:{user}@{server}"))?;
    let registrar = uri(&format!("sip:{server}"))?;
    let contact = uri(&format!("sip:{user}@{}", advertised(local, remote)))?;
    let account = runtime.agent().add_account(
        Account::new(aor, registrar, contact, transport, remote)
            .credentials(Credentials::new(user, pass))
            .expires(Duration::from_secs(300)),
    );

    let mut script = Script {
        flow,
        account,
        extension: extension.to_owned(),
        other: other.to_owned(),
        server: server.to_owned(),
        local: advertised(local, remote),
        started: Instant::now(),
        seen: Seen::default(),
        call: None,
        consulted: None,
        step: Step::Registering,
        asked: false,
        media,
        offer: None,
        listen_until: None,
        settled_by: None,
    };
    runtime
        .run(&mut script)
        .map_err(|error| format!("the loop stopped: {error}"))?;
    script.verdict()?;
    let heard = script.media.heard();
    if heard.sent == 0 {
        return Ok(String::new());
    }
    let mut said = format!(
        "   ({} sent, {} back, {} audible, {} refused",
        heard.sent, heard.received, heard.audible, heard.refused
    );
    // the buffer's own account of the path, which is the only thing that says
    // anything under an impaired network: how much never arrived, how late the
    // rest was, and how much had to be invented
    if let Some(quality) = script.media.quality() {
        use std::fmt::Write as _;
        let _ = write!(
            said,
            "; lost {}, late {}, jitter {}ms, delay {}ms",
            quality.lost,
            quality.discarded_late,
            quality.jitter.as_millis(),
            quality.delay.as_millis()
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
fn route_to(remote: SocketAddr) -> std::net::IpAddr {
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

/// A different seed per flow, so that two runs never mint the same branch.
const fn seed(flow: Flow) -> [u8; 32] {
    match flow {
        Flow::Register => [17; 32],
        Flow::Call => [29; 32],
        Flow::Hold => [41; 32],
        Flow::Blind => [53; 32],
        Flow::Attended => [67; 32],
    }
}
