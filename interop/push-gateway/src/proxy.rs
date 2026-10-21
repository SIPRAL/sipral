// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The proxy half of RFC 8599, without a socket or a clock of its own.
//!
//! Everything arrives through [`Gateway::on_datagram`], [`Gateway::on_push`]
//! and [`Gateway::on_tick`], with the time passed in, and everything leaves as
//! an [`Action`]: a datagram to send, a push to ask for, a line to print. The
//! tests drive it with messages written out by hand and a clock moved by
//! hand; `main.rs` drives it with a UDP socket and threads that talk to the
//! notification services.
//!
//! It stands in front of one PBX and plays two roles at once:
//!
//! - **the RFC 8599 proxy.** A REGISTER whose `Contact` carries `pn-provider`
//!   is answered for as §5.6.1 says -- `+sip.pns` added to the request and to
//!   the 2xx, `+sip.pnsreg` when the device asked for it, `+sip.pnspurr` with
//!   a PURR of its own (§6.2.1), 423 for a binding too short to be woken
//!   for, 555 when told no other proxy could push. An INVITE or a MESSAGE for
//!   such a binding is held in the SIP Request Push Bucket while the device
//!   is pushed (§5.2, §5.6.2), and forwarded once the device's refresh has
//!   been answered 2xx, or answered 480 when the bucket timer runs out or the
//!   push fails. A request inside a dialog whose target carries a PURR is
//!   held the same way (§6.2.3). Before a binding lapses the device is pushed
//!   to refresh it (§5.5).
//! - **an edge proxy for a PBX that knows nothing of it.** The PBX is told
//!   the device is here: the `Contact` of a REGISTER that asks for push is
//!   given this proxy's address, keeping every URI parameter, so a PBX with
//!   or without `rewrite_contact`, with or without `Path` (RFC 3327) sends
//!   the device's calls here, `pn-*` and all, and the 2xx is given the
//!   device's own `Contact` back. Every other `Contact` a device sends --
//!   on an INVITE, on its 200 -- is given this proxy's address too, with the
//!   device's own host and the address it really sent from in one parameter
//!   (`sipral-gw`), so what the PBX sends inside a dialog reaches the device
//!   behind any NAT and through any rewrite, and this proxy keeps no dialog
//!   state to do it. Everything a device sends goes to the PBX.
//!
//! It is the lab's, and it is stateful enough for the lab: one PBX, one UDP
//! socket, everything in memory and lost on a restart, no TLS (§13 asks for
//! TLS, or signalling secured some other way, wherever this runs for real),
//! no forking, no DNS beyond the PBX's own name.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::push::{PushKind, PushOutcome, PushRequest};
use crate::sip::{ContactValue, Message, SipUri, Via, equivalent, hostport, stamp_received};

/// How long a REGISTER, a forwarded non-INVITE or a final answer this proxy
/// gave is remembered: 64·T1 (RFC 3261 §17.1.2.2).
const TRANSACTION: Duration = Duration::from_secs(32);

/// How long where an INVITE went is remembered, for its CANCEL and its
/// retransmissions: Timer C's floor (RFC 3261 §16.6).
const INVITE_TRANSACTION: Duration = Duration::from_secs(180);

/// How long before a binding lapses the device is pushed to refresh it, and
/// the least `+sip.pnsreg` this proxy asks of a device that wakes itself:
/// §5.5 recommends at least 120 seconds, and §5.6.1.1 asks for more than 120.
const REFRESH_LEAD: Duration = Duration::from_secs(120);
const PNSREG_LEAD: u32 = 121;

/// How long one PURR is handed out before another is minted (§6.2.1:
/// "periodically", against fingerprinting). The old ones keep working
/// for as long as the binding does.
const PURR_LIFETIME: Duration = Duration::from_secs(3600);

/// The URI parameter a device's own address travels in.
const FLOW_PARAM: &str = "sipral-gw";

/// One notification service this proxy can push through, and which
/// `pn-param` it accepts for it.
#[derive(Clone, Debug)]
pub(crate) struct Service {
    /// `pn-provider`: `apns`, `fcm`.
    pub(crate) provider: String,
    /// What `pn-param` has to be.
    pub(crate) param: ParamRule,
}

/// What a service needs of `pn-param` (§10, §11).
#[derive(Clone, Debug)]
pub(crate) enum ParamRule {
    /// APNs: `<Team ID>.<bundle>.voip`, the team the key belongs to when one
    /// is named. The topic has to be a VoIP one, since a VoIP push is the
    /// only kind sent (`PushKind::allowed_on`).
    Apns {
        /// The team, when a key names one.
        team: Option<String>,
    },
    /// FCM: the project the service account belongs to, when one is named.
    Fcm {
        /// The project ID.
        project: Option<String>,
    },
}

impl Service {
    /// Whether this service can push to a device registered with `param`.
    fn accepts(&self, param: Option<&str>) -> bool {
        match (&self.param, param) {
            (ParamRule::Apns { team }, Some(param)) => {
                let Some((named, topic)) = param.split_once('.') else {
                    return false;
                };
                let bundle = topic.strip_suffix(".voip").unwrap_or_default();
                !named.is_empty()
                    && !bundle.is_empty()
                    && team.as_deref().is_none_or(|team| team == named)
            }
            (ParamRule::Fcm { project }, Some(param)) => {
                !param.is_empty() && project.as_deref().is_none_or(|project| project == param)
            }
            (_, None) => false,
        }
    }
}

/// How the proxy is set up.
#[derive(Clone, Debug)]
pub(crate) struct Config {
    /// The address the PBX and the devices reach this proxy at.
    pub(crate) own: SocketAddr,
    /// The PBX: the registrar, and where everything a device sends goes.
    pub(crate) pbx: SocketAddr,
    /// The services this proxy pushes through.
    pub(crate) services: Vec<Service>,
    /// The bucket timer for an INVITE.
    pub(crate) invite_bucket: Duration,
    /// The bucket timer for anything else. It has to answer before the
    /// sender's own Timer F, 32 s, with room for the answer to travel
    /// (§5.6.2, RFC 4320).
    pub(crate) other_bucket: Duration,
    /// The shortest binding accepted for push: one that lapses before the
    /// device could be woken to refresh it is too short (§5.6.1.1).
    pub(crate) min_expires: u32,
    /// Whether this proxy knows no other one on the path could push, which
    /// is what allows a 555 (§5.6.1.1, §5.6.1.2).
    pub(crate) only_push_proxy: bool,
    /// Secret bytes for the branches and the PURRs this proxy mints.
    pub(crate) secret: [u8; 32],
}

/// What the proxy wants done.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Send these bytes there.
    Send {
        /// Where.
        to: SocketAddr,
        /// What.
        bytes: Vec<u8>,
    },
    /// Ask a notification service for this push.
    Push(PushRequest),
    /// A line for whoever is watching.
    Note(String),
}

/// A binding's push identity: what §5.3 compares.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PnKey {
    provider: String,
    prid: String,
    param: Option<String>,
}

impl PnKey {
    fn of(uri: &SipUri) -> Option<Self> {
        let prid = uri.param("pn-prid").filter(|prid| !prid.is_empty())?;
        Some(Self {
            provider: uri.param("pn-provider")?.to_ascii_lowercase(),
            prid,
            param: uri.param("pn-param"),
        })
    }

    /// The token, shortened for a log line: enough to tell two apart.
    fn short(&self) -> String {
        let shown: String = self.prid.chars().take(8).collect();
        format!("{} {shown}…", self.provider)
    }
}

/// A device this proxy has heard register for push.
#[derive(Clone, Debug)]
struct Binding {
    /// The `Contact` URI the device registered, as it wrote it.
    device_contact: String,
    /// The same, as the PBX holds it: at this proxy's address.
    held_as: String,
    /// Where its last REGISTER came from.
    flow: SocketAddr,
    expires_at: Instant,
    refresh_asked: bool,
    purr: String,
    purr_minted: Instant,
}

/// One `Contact` of a REGISTER this proxy is answering for.
#[derive(Clone, Debug)]
struct Registering {
    key: Option<PnKey>,
    device_contact: String,
    held_as: String,
    wakes_itself: bool,
}

/// A REGISTER forwarded and not yet answered.
#[derive(Clone, Debug)]
struct RegisterTxn {
    contacts: Vec<Registering>,
    indicated: BTreeSet<String>,
    query: bool,
    flow: SocketAddr,
    at: Instant,
}

/// What a request is held for: a binding, through its push identity.
#[derive(Clone, Debug)]
struct Held {
    push_id: u64,
    key: PnKey,
    /// The request as it will be forwarded, Request-URI aside.
    request: Message,
    /// The Request-URI it goes with: `None` to use the binding's newest
    /// `Contact`, `Some` for a request inside a dialog, whose target stays.
    target: Option<String>,
    txn: TxnKey,
    from: SocketAddr,
    deadline: Instant,
}

/// A server transaction, as RFC 3261 §17.2.3 matches one.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TxnKey {
    branch: String,
    sent_by: String,
    method: String,
}

impl TxnKey {
    /// The transaction of `request`; a CANCEL and an ACK are matched to the
    /// INVITE's.
    fn of(request: &Message) -> Option<Self> {
        let via = Via::parse(request.first("Via")?)?;
        let method = match request.method()? {
            "CANCEL" | "ACK" => "INVITE",
            other => other,
        };
        Some(Self {
            branch: via.branch,
            sent_by: via.sent_by,
            method: method.to_owned(),
        })
    }
}

/// Bytes sent once, and sent again when the same request arrives again.
#[derive(Clone, Debug)]
struct Sent {
    to: SocketAddr,
    bytes: Vec<u8>,
    /// The Request-URI it went with, which a CANCEL has to repeat.
    target: String,
    until: Instant,
}

/// The proxy.
pub(crate) struct Gateway {
    config: Config,
    bindings: HashMap<PnKey, Binding>,
    registers: HashMap<String, RegisterTxn>,
    held: Vec<Held>,
    forwarded: HashMap<TxnKey, Sent>,
    answered: HashMap<TxnKey, Sent>,
    purrs: HashMap<String, PnKey>,
    counter: u64,
}

impl Gateway {
    /// A proxy with nothing registered.
    pub(crate) fn new(config: Config) -> Self {
        Self {
            config,
            bindings: HashMap::new(),
            registers: HashMap::new(),
            held: Vec::new(),
            forwarded: HashMap::new(),
            answered: HashMap::new(),
            purrs: HashMap::new(),
            counter: 0,
        }
    }

    /// A datagram arrived from `from`.
    pub(crate) fn on_datagram(
        &mut self,
        from: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> Vec<Action> {
        let mut out = Vec::new();
        let Some(message) = Message::parse(data) else {
            return out;
        };
        if !message.is_request() {
            self.response(message, from, now, &mut out);
        } else if from == self.config.pbx {
            self.pbx_request(message, from, now, &mut out);
        } else {
            self.device_request(message, from, now, &mut out);
        }
        out
    }

    /// A notification service answered push `id`.
    pub(crate) fn on_push(&mut self, id: u64, outcome: &PushOutcome, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        match outcome {
            PushOutcome::Accepted(what) => {
                out.push(Action::Note(format!("push {id} accepted ({what})")));
            }
            PushOutcome::Failed(why) => {
                out.push(Action::Note(format!("push {id} failed: {why}")));
                // §5.6.2: "the proxy MUST remove the SIP request from the
                // bucket and send an error response"
                let failed: Vec<Held> = self.take_held(|held| held.push_id == id);
                for held in failed {
                    self.refuse_held(&held, now, "the push failed", &mut out);
                }
            }
        }
        out
    }

    /// Time passed: bucket timers, bindings lapsing, refresh pushes.
    pub(crate) fn on_tick(&mut self, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        let expired = self.take_held(|held| held.deadline <= now);
        for held in expired {
            self.refuse_held(&held, now, "the bucket timer ran out", &mut out);
        }
        self.forwarded.retain(|_, sent| sent.until > now);
        self.answered.retain(|_, sent| sent.until > now);
        self.registers
            .retain(|_, txn| now.duration_since(txn.at) < TRANSACTION);

        let mut lapsed = Vec::new();
        let mut refresh = Vec::new();
        for (key, binding) in &mut self.bindings {
            if binding.expires_at <= now {
                lapsed.push(key.clone());
            } else if !binding.refresh_asked
                && binding.expires_at.saturating_duration_since(now) <= REFRESH_LEAD
                && PushKind::Refresh.allowed_on(&key.provider)
            {
                binding.refresh_asked = true;
                refresh.push(key.clone());
            }
        }
        for key in lapsed {
            // §5.5: no push for a binding that has expired
            self.forget(&key);
            out.push(Action::Note(format!("binding {} lapsed", key.short())));
        }
        for key in refresh {
            let id = self.next();
            out.push(Action::Note(format!(
                "binding {} lapses within {} s: push {id} to refresh it",
                key.short(),
                REFRESH_LEAD.as_secs()
            )));
            out.push(Action::Push(PushRequest {
                id,
                provider: key.provider.clone(),
                prid: key.prid.clone(),
                param: key.param.clone(),
                kind: PushKind::Refresh,
                caller: None,
                name: None,
                call_id: None,
            }));
        }
        out
    }

    /// How many requests are in the bucket.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.held.len()
    }

    fn next(&mut self) -> u64 {
        self.counter += 1;
        self.counter
    }

    fn digest(&self, parts: &[&str]) -> String {
        let mut input = self.config.secret.to_vec();
        for part in parts {
            input.extend_from_slice(part.as_bytes());
            input.push(0);
        }
        let hash = ring::digest::digest(&ring::digest::SHA256, &input);
        let mut out = String::new();
        for byte in hash.as_ref().iter().take(12) {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// The branch this proxy forwards a request on: the same for every
    /// retransmission of it and for the CANCEL and the ACK of an INVITE,
    /// different for every other transaction (RFC 3261 §16.11).
    fn branch(&self, txn: &TxnKey) -> String {
        format!(
            "z9hG4bK-sgw-{}",
            self.digest(&[&txn.branch, &txn.sent_by, &txn.method])
        )
    }

    fn own_via(&self, txn: &TxnKey) -> String {
        format!(
            "SIP/2.0/UDP {};branch={};rport",
            hostport(self.config.own),
            self.branch(txn)
        )
    }

    fn own_uri(&self) -> String {
        format!("sip:{};lr", hostport(self.config.own))
    }

    /// Whether a URI names this proxy.
    fn is_own(&self, uri: &SipUri) -> bool {
        uri.address() == Some(self.config.own)
    }

    /// Every line the same, so the lab can read them.
    fn reply(
        &mut self,
        request: &Message,
        to: SocketAddr,
        code: u16,
        reason: &str,
        extra: &[(&str, String)],
        out: &mut Vec<Action>,
    ) -> Vec<u8> {
        let mut response = if code == 100 {
            // a 100 is hop by hop and carries no tag (RFC 3261 §8.2.6.1)
            let mut trying = request.response(code, reason, "");
            let original = request.first("To").unwrap_or_default().to_owned();
            trying.map_values("To", |_| original.clone());
            trying
        } else {
            let tag = format!("sgw{}", self.next());
            request.response(code, reason, &tag)
        };
        for (name, value) in extra {
            response.push_back(name, value.clone());
        }
        let bytes = response.to_bytes();
        out.push(Action::Send {
            to,
            bytes: bytes.clone(),
        });
        bytes
    }

    /// RFC 3261 §16.3 and §16.4 on a request that arrived: `received` and
    /// `rport` on its `Via`, `Max-Forwards` counted down, this proxy's own
    /// `Route` taken off. `false` when it was answered instead.
    fn prepare(&mut self, request: &mut Message, from: SocketAddr, out: &mut Vec<Action>) -> bool {
        if let Some(top) = request.take_first("Via") {
            request.push_front("Via", stamp_received(&top, from));
        } else {
            return false;
        }
        let forwards = request
            .first("Max-Forwards")
            .and_then(|value| value.trim().parse::<u32>().ok())
            .unwrap_or(70);
        if forwards == 0 {
            self.reply(request, from, 483, "Too Many Hops", &[], out);
            return false;
        }
        request.headers.retain(|(name, _)| name != "Max-Forwards");
        request.push_back("Max-Forwards", (forwards - 1).to_string());
        if let Some(route) = request.first("Route")
            && let Some(route) = ContactValue::parse(route)
            && let Some(uri) = SipUri::parse(&route.uri)
            && self.is_own(&uri)
        {
            request.take_first("Route");
        }
        true
    }

    /// A `Contact` URI a device wrote, at this proxy's address, carrying the
    /// device's own host and the address it sent from.
    fn encode_flow(&self, uri: &SipUri, flow: SocketAddr) -> SipUri {
        let original = match uri.port {
            Some(port) => format!("{}:{port}", uri.host),
            None => uri.host.clone(),
        };
        let mut moved = uri.moved_to(self.config.own);
        moved.set_param(FLOW_PARAM, &format!("{original}~{}", hostport(flow)));
        moved
    }

    /// The other way: the device's own URI, and where to send to reach it.
    fn decode_flow(uri: &SipUri) -> Option<(SipUri, SocketAddr)> {
        let carried = uri.param(FLOW_PARAM)?;
        let (original, flow) = carried.split_once('~')?;
        let flow: SocketAddr = flow.parse().ok()?;
        let mut restored = uri.clone();
        restored.remove_param(FLOW_PARAM);
        // `host`, `host:port`, `[v6]` or `[v6]:port`
        let (host, port) = match original.rfind(']') {
            Some(close) => {
                let (host, rest) = original.split_at(close + 1);
                (host, rest.strip_prefix(':'))
            }
            None => match original.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (original, None),
            },
        };
        host.clone_into(&mut restored.host);
        restored.port = match port {
            Some(port) => Some(port.parse().ok()?),
            None => None,
        };
        Some((restored, flow))
    }

    /// Every `Contact` of a message from a device given this proxy's address.
    fn rewrite_contacts(&self, message: &mut Message, flow: SocketAddr) {
        message.map_values("Contact", |value| {
            let Some(mut contact) = ContactValue::parse(value) else {
                return value.to_owned();
            };
            let Some(uri) = SipUri::parse(&contact.uri) else {
                return value.to_owned();
            };
            if self.is_own(&uri) {
                return value.to_owned();
            }
            contact.uri = self.encode_flow(&uri, flow).render();
            contact.render()
        });
    }

    // -- from a device ---------------------------------------------------

    fn device_request(
        &mut self,
        mut request: Message,
        from: SocketAddr,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        if !self.prepare(&mut request, from, out) {
            return;
        }
        let Some(txn) = TxnKey::of(&request) else {
            return;
        };
        if request.method() == Some("REGISTER") {
            self.register(request, from, &txn, now, out);
            return;
        }
        // §6.2.2: a dialog this device opens with a PURR of ours in its
        // `Contact` keeps this proxy on its route
        let purr_named = request.all("Contact").any(|value| {
            ContactValue::parse(value)
                .and_then(|contact| SipUri::parse(&contact.uri))
                .and_then(|uri| uri.param("pn-purr"))
                .is_some_and(|purr| self.purrs.contains_key(&purr))
        });
        if purr_named && request.to_tag().is_none() {
            request.push_front("Record-Route", format!("<{}>", self.own_uri()));
        }
        self.rewrite_contacts(&mut request, from);
        request.push_front("Via", self.own_via(&txn));
        out.push(Action::Send {
            to: self.config.pbx,
            bytes: request.to_bytes(),
        });
    }

    // §5.6.1.1 and §5.6.1.2 side by side, which is how they differ
    #[allow(clippy::too_many_lines)]
    fn register(
        &mut self,
        mut request: Message,
        from: SocketAddr,
        txn: &TxnKey,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        // §5.6.1.1: another proxy nearer the device already said it pushes
        let pushed_by_another = request
            .all("Feature-Caps")
            .any(|value| value.to_ascii_lowercase().contains("+sip.pns="));
        let header_expires = request
            .first("Expires")
            .and_then(|value| value.trim().parse::<u32>().ok());
        let mut contacts = Vec::new();
        let mut indicated = BTreeSet::new();
        let mut query = false;
        let mut rewritten = Vec::new();
        for value in request.all("Contact") {
            let Some(contact) = ContactValue::parse(value) else {
                rewritten.push(value.to_owned());
                continue;
            };
            let Some(uri) = SipUri::parse(&contact.uri) else {
                rewritten.push(value.to_owned());
                continue;
            };
            if pushed_by_another || !uri.has_param("pn-provider") {
                rewritten.push(value.to_owned());
                continue;
            }
            let provider = uri
                .param("pn-provider")
                .unwrap_or_default()
                .to_ascii_lowercase();
            let param = uri.param("pn-param");
            let service = self
                .config
                .services
                .iter()
                .find(|service| service.provider == provider)
                .cloned();
            let key = PnKey::of(&uri);
            let expires = contact
                .param("expires")
                .and_then(|value| value.parse::<u32>().ok())
                .or(header_expires)
                .unwrap_or(3600);
            if key.is_some() {
                // §5.6.1.1: a device asking for pushes
                if !service
                    .as_ref()
                    .is_some_and(|service| service.accepts(param.as_deref()))
                {
                    if self.config.only_push_proxy {
                        out.push(Action::Note(format!(
                            "REGISTER asks for {provider} pushes this proxy cannot send: 555"
                        )));
                        self.reply(
                            &request,
                            from,
                            555,
                            "Push Notification Service Not Supported",
                            &[],
                            out,
                        );
                        return;
                    }
                    rewritten.push(value.to_owned());
                    continue;
                }
                if expires != 0 && expires < self.config.min_expires {
                    out.push(Action::Note(format!(
                        "REGISTER for {expires} s is too short to be woken for: 423"
                    )));
                    self.reply(
                        &request,
                        from,
                        423,
                        "Interval Too Brief",
                        &[("Min-Expires", self.config.min_expires.to_string())],
                        out,
                    );
                    return;
                }
                indicated.insert(provider.clone());
            } else {
                // §5.6.1.2: a query, or a binding being removed (§4.1.2)
                query = true;
                if provider.is_empty() {
                    for service in &self.config.services {
                        indicated.insert(service.provider.clone());
                    }
                    rewritten.push(value.to_owned());
                    continue;
                }
                if service.is_none() {
                    if self.config.only_push_proxy {
                        out.push(Action::Note(format!(
                            "REGISTER asks about {provider}, which this proxy cannot send: 555"
                        )));
                        self.reply(
                            &request,
                            from,
                            555,
                            "Push Notification Service Not Supported",
                            &[],
                            out,
                        );
                        return;
                    }
                    rewritten.push(value.to_owned());
                    continue;
                }
                indicated.insert(provider.clone());
                if expires != 0 {
                    // only asking: the binding is the device's own, as it
                    // would be without this proxy
                    rewritten.push(value.to_owned());
                    continue;
                }
            }
            let held_as = uri.moved_to(self.config.own).render();
            let mut moved = contact.clone();
            moved.uri.clone_from(&held_as);
            rewritten.push(moved.render());
            contacts.push(Registering {
                key,
                device_contact: contact.uri.clone(),
                held_as,
                wakes_itself: contact.has_param("+sip.pnsreg"),
            });
        }
        request.headers.retain(|(name, _)| name != "Contact");
        for value in rewritten {
            request.push_back("Contact", value);
        }
        for provider in &indicated {
            request.push_back("Feature-Caps", format!("*;+sip.pns=\"{provider}\""));
        }
        if !indicated.is_empty() || !contacts.is_empty() {
            let named: Vec<&str> = indicated.iter().map(String::as_str).collect();
            out.push(Action::Note(format!(
                "REGISTER from {} {}: +sip.pns for {} added",
                hostport(from),
                if query { "asks" } else { "asks for pushes" },
                named.join(", ")
            )));
            let branch = self.branch(txn);
            self.registers.insert(
                branch,
                RegisterTxn {
                    contacts,
                    indicated,
                    query,
                    flow: from,
                    at: now,
                },
            );
        }
        request.push_front("Via", self.own_via(txn));
        out.push(Action::Send {
            to: self.config.pbx,
            bytes: request.to_bytes(),
        });
    }

    // -- from the PBX ----------------------------------------------------

    // every way a request from the PBX can go, in the order they are tried
    #[allow(clippy::too_many_lines)]
    fn pbx_request(
        &mut self,
        mut request: Message,
        from: SocketAddr,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let Some(txn) = TxnKey::of(&request) else {
            return;
        };
        let method = request.method().unwrap_or_default().to_owned();
        // the same request again: answered the same way
        if method != "CANCEL" && method != "ACK" {
            if self.held.iter().any(|held| held.txn == txn) {
                if method == "INVITE" {
                    self.reply(&request, from, 100, "Trying", &[], out);
                }
                return;
            }
            if let Some(sent) = self.answered.get(&txn) {
                out.push(Action::Send {
                    to: sent.to,
                    bytes: sent.bytes.clone(),
                });
                return;
            }
            if let Some(sent) = self.forwarded.get(&txn) {
                out.push(Action::Send {
                    to: sent.to,
                    bytes: sent.bytes.clone(),
                });
                return;
            }
        }
        if !self.prepare(&mut request, from, out) {
            return;
        }
        if method == "CANCEL" {
            self.cancel(&request, &txn, from, now, out);
            return;
        }
        if method == "ACK" && self.answered.contains_key(&txn) {
            // the ACK for a final answer this proxy gave
            return;
        }
        let Some(uri) = request.request_uri().and_then(SipUri::parse) else {
            self.reply(&request, from, 416, "Unsupported URI Scheme", &[], out);
            return;
        };
        let initial = request.to_tag().is_none();

        // a target this proxy wrote: a device's own `Contact`, with the
        // address it is reached at
        if self.is_own(&uri)
            && let Some((target, flow)) = Self::decode_flow(&uri)
        {
            if !initial
                && let Some(purr) = target.param("pn-purr")
                && let Some(key) = self.purrs.get(&purr).cloned()
                && self.bindings.contains_key(&key)
                && PushKind::Dialog.allowed_on(&key.provider)
            {
                self.hold(
                    request,
                    Some(target.render()),
                    key,
                    PushKind::Dialog,
                    txn,
                    from,
                    now,
                    out,
                );
                return;
            }
            self.forward(request, &target.render(), flow, &txn, false, now, out);
            return;
        }

        // a target a REGISTER through this proxy named: §5.6.2
        if let Some(key) = PnKey::of(&uri) {
            let Some(binding) = self.bindings.get(&key).cloned() else {
                out.push(Action::Note(format!(
                    "{method} for {}, which never registered here: 480",
                    key.short()
                )));
                let bytes = self.reply(&request, from, 480, "Temporarily Unavailable", &[], out);
                self.remember_answer(txn, from, bytes, now);
                return;
            };
            let kind = match method.as_str() {
                "INVITE" => Some(PushKind::Call),
                "MESSAGE" => Some(PushKind::Message),
                _ => None,
            };
            if initial && let Some(kind) = kind {
                if kind.allowed_on(&key.provider) {
                    self.hold(request, None, key, kind, txn, from, now, out);
                    return;
                }
                out.push(Action::Note(format!(
                    "{method} for {}: {} carries no {} wake-up, so it goes straight to the device",
                    key.short(),
                    key.provider,
                    kind.word()
                )));
            }
            self.forward(
                request,
                &binding.device_contact,
                binding.flow,
                &txn,
                initial,
                now,
                out,
            );
            return;
        }

        // anything else this proxy can route by address alone
        if let Some(address) = uri.address()
            && !self.is_own(&uri)
        {
            let target = uri.render();
            self.forward(request, &target, address, &txn, false, now, out);
            return;
        }
        if method != "ACK" {
            self.reply(&request, from, 404, "Not Found", &[], out);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn hold(
        &mut self,
        mut request: Message,
        target: Option<String>,
        key: PnKey,
        kind: PushKind,
        txn: TxnKey,
        from: SocketAddr,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let id = self.next();
        let method = request.method().unwrap_or_default().to_owned();
        if method == "INVITE" {
            self.reply(&request, from, 100, "Trying", &[], out);
        }
        let bucket = if method == "INVITE" {
            self.config.invite_bucket
        } else {
            self.config.other_bucket
        };
        out.push(Action::Note(format!(
            "{method} for {} held in the bucket for {} ms: push {id} ({})",
            key.short(),
            bucket.as_millis(),
            kind.word()
        )));
        out.push(Action::Push(PushRequest {
            id,
            provider: key.provider.clone(),
            prid: key.prid.clone(),
            param: key.param.clone(),
            kind,
            caller: request.caller_uri(),
            name: request.caller_name(),
            call_id: request.first("Call-ID").map(str::to_owned),
        }));
        // §6.2.2: this proxy minted a PURR for the binding, so it stays on
        // the route of a dialog the request opens
        if target.is_none() && request.to_tag().is_none() {
            request.push_front("Record-Route", format!("<{}>", self.own_uri()));
        }
        self.held.push(Held {
            push_id: id,
            key,
            request,
            target,
            txn,
            from,
            deadline: now + bucket,
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn forward(
        &mut self,
        mut request: Message,
        target: &str,
        to: SocketAddr,
        txn: &TxnKey,
        record_route: bool,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        request.set_request_uri(target);
        if record_route {
            request.push_front("Record-Route", format!("<{}>", self.own_uri()));
        }
        request.push_front("Via", self.own_via(txn));
        let bytes = request.to_bytes();
        let until = now
            + if txn.method == "INVITE" {
                INVITE_TRANSACTION
            } else {
                TRANSACTION
            };
        if request.method() != Some("ACK") {
            self.forwarded.insert(
                txn.clone(),
                Sent {
                    to,
                    bytes: bytes.clone(),
                    target: target.to_owned(),
                    until,
                },
            );
        }
        out.push(Action::Send { to, bytes });
    }

    fn cancel(
        &mut self,
        request: &Message,
        txn: &TxnKey,
        from: SocketAddr,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let held = self.take_held(|held| held.txn == *txn);
        if let Some(held) = held.into_iter().next() {
            // the caller gave up while the device was being woken
            self.reply(request, from, 200, "OK", &[], out);
            let bytes = self.reply(
                &held.request,
                held.from,
                487,
                "Request Terminated",
                &[],
                out,
            );
            self.remember_answer(held.txn.clone(), held.from, bytes, now);
            out.push(Action::Note(format!(
                "CANCEL for the held INVITE for {}: 487, out of the bucket",
                held.key.short()
            )));
            return;
        }
        if let Some(sent) = self.forwarded.get(txn).cloned() {
            let mut forward = request.clone();
            forward.set_request_uri(&sent.target);
            forward.push_front("Via", self.own_via(txn));
            out.push(Action::Send {
                to: sent.to,
                bytes: forward.to_bytes(),
            });
            return;
        }
        self.reply(
            request,
            from,
            481,
            "Call/Transaction Does Not Exist",
            &[],
            out,
        );
    }

    fn remember_answer(&mut self, txn: TxnKey, to: SocketAddr, bytes: Vec<u8>, now: Instant) {
        self.answered.insert(
            txn,
            Sent {
                to,
                bytes,
                target: String::new(),
                until: now + TRANSACTION,
            },
        );
    }

    fn take_held(&mut self, mut which: impl FnMut(&Held) -> bool) -> Vec<Held> {
        let mut taken = Vec::new();
        let mut kept = Vec::new();
        for held in self.held.drain(..) {
            if which(&held) {
                taken.push(held);
            } else {
                kept.push(held);
            }
        }
        self.held = kept;
        taken
    }

    /// §5.6.2's error response: 480, RECOMMENDED among two.
    fn refuse_held(&mut self, held: &Held, now: Instant, why: &str, out: &mut Vec<Action>) {
        let method = held.request.method().unwrap_or_default().to_owned();
        out.push(Action::Note(format!(
            "{why}: 480 to the held {method} for {}",
            held.key.short()
        )));
        let bytes = self.reply(
            &held.request,
            held.from,
            480,
            "Temporarily Unavailable",
            &[],
            out,
        );
        self.remember_answer(held.txn.clone(), held.from, bytes, now);
    }

    fn forget(&mut self, key: &PnKey) {
        self.bindings.remove(key);
        self.purrs.retain(|_, named| named != key);
    }

    // -- responses ---------------------------------------------------------

    fn response(
        &mut self,
        mut response: Message,
        from: SocketAddr,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let Some(top) = response.first("Via").and_then(Via::parse) else {
            return;
        };
        if top.sent_by != hostport(self.config.own) {
            return;
        }
        response.take_first("Via");
        if response.method() == Some("REGISTER")
            && let Some(txn) = self.registers.get(&top.branch).cloned()
        {
            if response.status().unwrap_or_default() >= 200 {
                self.registers.remove(&top.branch);
            }
            self.registered(&mut response, &txn, now, out);
        }
        if from != self.config.pbx {
            self.rewrite_contacts(&mut response, from);
        }
        let Some(next) = response.first("Via").and_then(Via::parse) else {
            return;
        };
        let Some(to) = next.reply_to else {
            return;
        };
        out.push(Action::Send {
            to,
            bytes: response.to_bytes(),
        });
    }

    /// §5.6.1 and §5.6.2 on the registrar's answer.
    // §5.6.1 and §5.6.2 in the order the RFC gives them, kept in one place
    #[allow(clippy::too_many_lines)]
    fn registered(
        &mut self,
        response: &mut Message,
        txn: &RegisterTxn,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        let status = response.status().unwrap_or_default();
        if status < 200 {
            return;
        }
        if status >= 300 {
            if status == 401 || status == 407 {
                // §5.6.2: the device will send the REGISTER again, answered;
                // what is held waits for that one
                return;
            }
            for registering in &txn.contacts {
                if let Some(key) = &registering.key {
                    let refused = self.take_held(|held| held.key == *key);
                    for held in refused {
                        self.refuse_held(
                            &held,
                            now,
                            &format!("the REGISTER was refused {status}"),
                            out,
                        );
                    }
                }
            }
            return;
        }

        let header_expires = response
            .first("Expires")
            .and_then(|value| value.trim().parse::<u32>().ok());
        let listed: Vec<ContactValue> = response
            .all("Contact")
            .filter_map(ContactValue::parse)
            .collect();
        let mut caps: Vec<String> = Vec::new();
        let mut woken: Vec<PnKey> = Vec::new();
        for registering in &txn.contacts {
            let granted = listed
                .iter()
                .find(|contact| equivalent(&contact.uri, &registering.held_as))
                .map_or(0, |contact| {
                    contact
                        .param("expires")
                        .and_then(|value| value.parse::<u32>().ok())
                        .or(header_expires)
                        .unwrap_or(0)
                });
            let Some(key) = &registering.key else {
                if granted == 0 {
                    // a removal (§4.1.2): every binding the PBX held under
                    // this URI is gone with it
                    let gone: Vec<PnKey> = self
                        .bindings
                        .iter()
                        .filter(|(_, binding)| equivalent(&binding.held_as, &registering.held_as))
                        .map(|(key, _)| key.clone())
                        .collect();
                    for key in gone {
                        self.forget(&key);
                        out.push(Action::Note(format!("binding {} removed", key.short())));
                    }
                }
                continue;
            };
            if granted == 0 {
                self.forget(key);
                out.push(Action::Note(format!("binding {} removed", key.short())));
                continue;
            }
            if granted < self.config.min_expires {
                // §5.6.1.1: the registrar's interval is too short to wake
                // the device for; the 2xx goes on without the indicator
                out.push(Action::Note(format!(
                    "the registrar granted {} only {granted} s: no pushes for it",
                    key.short()
                )));
                continue;
            }
            let fresh_purr = self
                .bindings
                .get(key)
                .is_none_or(|binding| now.duration_since(binding.purr_minted) >= PURR_LIFETIME);
            let purr = if fresh_purr {
                let count = self.next().to_string();
                let purr = self.digest(&["purr", &count]);
                self.purrs.insert(purr.clone(), key.clone());
                purr
            } else {
                self.bindings
                    .get(key)
                    .map(|binding| binding.purr.clone())
                    .unwrap_or_default()
            };
            let purr_minted = if fresh_purr {
                now
            } else {
                self.bindings
                    .get(key)
                    .map_or(now, |binding| binding.purr_minted)
            };
            self.bindings.insert(
                key.clone(),
                Binding {
                    device_contact: registering.device_contact.clone(),
                    held_as: registering.held_as.clone(),
                    flow: txn.flow,
                    expires_at: now + Duration::from_secs(u64::from(granted)),
                    refresh_asked: false,
                    purr: purr.clone(),
                    purr_minted,
                },
            );
            let mut cap = format!("*;+sip.pns=\"{}\"", key.provider);
            if registering.wakes_itself {
                let _ = write!(cap, ";+sip.pnsreg=\"{PNSREG_LEAD}\"");
            }
            let _ = write!(cap, ";+sip.pnspurr=\"{purr}\"");
            caps.push(cap);
            out.push(Action::Note(format!(
                "binding {} registered for {granted} s, reached at {}",
                key.short(),
                hostport(txn.flow)
            )));
            woken.push(key.clone());
        }
        if txn.query {
            for provider in &txn.indicated {
                if !caps
                    .iter()
                    .any(|cap| cap.contains(&format!("\"{provider}\"")))
                {
                    caps.push(format!("*;+sip.pns=\"{provider}\""));
                }
            }
        }
        // the device's own `Contact`s back in place of the ones the PBX holds
        response.map_values("Contact", |value| {
            let Some(mut contact) = ContactValue::parse(value) else {
                return value.to_owned();
            };
            match txn
                .contacts
                .iter()
                .find(|registering| equivalent(&registering.held_as, &contact.uri))
            {
                Some(registering) => {
                    contact.uri.clone_from(&registering.device_contact);
                    contact.render()
                }
                None => value.to_owned(),
            }
        });
        for cap in caps {
            response.push_back("Feature-Caps", cap);
        }
        // §5.6.2: what was held for these bindings goes to the device now
        for key in woken {
            let Some(binding) = self.bindings.get(&key).cloned() else {
                continue;
            };
            let released = self.take_held(|held| held.key == key);
            for held in released {
                let method = held.request.method().unwrap_or_default().to_owned();
                let target = held
                    .target
                    .clone()
                    .unwrap_or_else(|| binding.device_contact.clone());
                out.push(Action::Note(format!(
                    "the refresh for {} was accepted: the held {method} goes to {}",
                    key.short(),
                    hostport(binding.flow)
                )));
                self.forward(
                    held.request,
                    &target,
                    binding.flow,
                    &held.txn,
                    false,
                    now,
                    out,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests;
