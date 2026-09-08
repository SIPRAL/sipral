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
//! with the failing condition named, and the process exits non-zero so that CI
//! does not have to read the log to know.

use std::env;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_ua::{
    Account, AccountId, CallHandle, CallState, Control, Credentials, EndpointConfig, Handler,
    OutgoingCall, Runtime, UaEvent, Uri, UserAgent,
};

/// How long any one flow may take before it is a failure. Every step in these
/// flows is a round trip on a loopback bridge; a whole flow that needs more
/// than this has not gone slowly, it has gone wrong.
const PATIENCE: Duration = Duration::from_secs(20);

/// The offer the harness makes. G.711 mu-law, one stream, because that is what
/// phase one negotiates and what every server in the lab accepts.
const OFFER: &str = "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\n\
t=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";

fn main() -> ExitCode {
    let server = env::args().nth(1).unwrap_or_else(|| "kamailio".to_owned());
    let port: u16 = env::args()
        .nth(2)
        .and_then(|text| text.parse().ok())
        .unwrap_or(5060);
    let extension = env::args().nth(3).unwrap_or_else(|| "9000".to_owned());
    let other = env::args().nth(4).unwrap_or_else(|| "9001".to_owned());

    let Some(remote) = resolve(&server, port) else {
        println!("cannot resolve {server}:{port}");
        return ExitCode::FAILURE;
    };
    println!("lab: {server}:{port} at {remote}, extension {extension}");

    let mut failures = 0;
    for flow in [
        Flow::Register,
        Flow::Call,
        Flow::Hold,
        Flow::Blind,
        Flow::Attended,
    ] {
        match run(flow, &server, remote, &extension, &other) {
            Ok(()) => println!("  pass  {}", flow.name()),
            Err(why) => {
                println!("  FAIL  {} — {why}", flow.name());
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
    local: SocketAddr,
    started: Instant,
    seen: Seen,
    call: Option<CallHandle>,
    /// The second leg of an attended transfer.
    consulted: Option<CallHandle>,
    step: Step,
    asked: bool,
}

/// Where the script is. One value rather than a pile of flags, because the
/// order matters and a flag can be set twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Registering,
    Placing,
    Talking,
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
            UaEvent::CallConfirmed { call, .. } => {
                if Some(call) == self.consulted {
                    self.seen.saw(Fact::Consulted);
                } else {
                    self.seen.saw(Fact::Up);
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
            UaEvent::CallEnded { reason, status, .. } => {
                self.seen.saw(Fact::Over);
                if !self.seen.has(Fact::Up) {
                    self.seen.refused = Some(match status {
                        Some(status) => format!("{reason} ({})", status.get()),
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
            let _ = agent.register(self.account, now);
        }
        if self.step == Step::Done || now > self.started + PATIENCE {
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
                let offer = OFFER.replace("{ip}", &self.local.ip().to_string());
                let placing = OutgoingCall::new(target).offer(Arc::from(offer.into_bytes()));
                match agent.call(self.account, &placing, now) {
                    Ok(call) => self.call = Some(call),
                    Err(_) => self.step = Step::Done,
                }
                self.step = Step::Talking;
            }
            Step::Talking if self.flow == Flow::Hold => {
                self.step = Step::Holding;
                if let Some(call) = self.call {
                    let _ = agent.hold(call, now);
                }
            }
            Step::Holding => {
                self.step = Step::Resuming;
                if let Some(call) = self.call {
                    let _ = agent.resume(call, now);
                }
            }
            Step::Talking if self.flow == Flow::Blind => {
                self.step = Step::Transferring;
                if let (Some(call), Some(target)) = (self.call, self.target()) {
                    let _ = agent.transfer(call, &target, now);
                }
            }
            Step::Talking if self.flow == Flow::Attended => {
                self.step = Step::Consulting;
                let offer = OFFER.replace("{ip}", &self.local.ip().to_string());
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
                    let _ = agent.transfer_to(call, other, now);
                }
            }
            Step::Talking | Step::Resuming | Step::Transferring => self.hang_up(agent, now),
            Step::Placing | Step::Ending | Step::Done => (),
        }
    }

    /// Who a transfer hands the call to.
    fn target(&self) -> Option<Uri> {
        Uri::parse_str(&format!("sip:{}@{}", self.other, self.server)).ok()
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
            // no Ours here: a transfer that worked is a call this end is not
            // in any more, and the far end is right to hang it up
            Flow::Blind => &[
                (Fact::Registered, "no binding was granted"),
                (Fact::Up, "the call did not connect"),
                (
                    Fact::Transferring,
                    "the far end never said it was transferring",
                ),
                (Fact::Transferred, "the transfer did not complete"),
                (Fact::Over, "the call did not end"),
            ],
            Flow::Attended => &[
                (Fact::Registered, "no binding was granted"),
                (Fact::Up, "the call did not connect"),
                (Fact::Consulted, "the consultation call did not connect"),
                (
                    Fact::Transferring,
                    "the far end never said it was transferring",
                ),
                (Fact::Transferred, "the transfer did not complete"),
                (Fact::Over, "the call did not end"),
            ],
        };
        for (fact, why) in owed {
            if !self.seen.has(*fact) {
                return Err((*why).to_owned());
            }
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
) -> Result<(), String> {
    let bind: SocketAddr = "0.0.0.0:0"
        .parse()
        .map_err(|_| "cannot parse the bind address".to_owned())?;
    let mut runtime = Runtime::bind(EndpointConfig::default(), seed(flow), bind)
        .map_err(|error| format!("cannot bind: {error}"))?;
    let local = runtime.local();
    let transport = runtime.transport();

    let aor = uri(&format!("sip:labuser@{server}"))?;
    let registrar = uri(&format!("sip:{server}"))?;
    let contact = uri(&format!("sip:labuser@{}", advertised(local, remote)))?;
    let account = runtime.agent().add_account(
        Account::new(aor, registrar, contact, transport, remote)
            .credentials(Credentials::new("labuser", "labpass"))
            .expires(Duration::from_secs(300)),
    );

    let mut script = Script {
        flow,
        account,
        extension: extension.to_owned(),
        other: other.to_owned(),
        server: server.to_owned(),
        local,
        started: Instant::now(),
        seen: Seen::default(),
        call: None,
        consulted: None,
        step: Step::Registering,
        asked: false,
    };
    runtime
        .run(&mut script)
        .map_err(|error| format!("the loop stopped: {error}"))?;
    script.verdict()
}

/// The address to put in `Contact`, which is the one the far end can reach.
///
/// Binding to a wildcard gives back `0.0.0.0`, and a registrar told to send
/// calls there will send them nowhere. The address that reaches the lab is the
/// one on the route to it.
fn advertised(local: SocketAddr, remote: SocketAddr) -> SocketAddr {
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

fn resolve(host: &str, port: u16) -> Option<SocketAddr> {
    std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
        .ok()?
        .next()
}

fn uri(text: &str) -> Result<Uri, String> {
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
