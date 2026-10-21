// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A laptop moving between two networks behind one NAT, against a registrar
//! that writes the source address into the `Contact`s it is sent.
//!
//! Asterisk's `rewrite_contact`, on by default for FreePBX extensions behind
//! a NAT, rewrites a REGISTER's `Contact` (18.9 and 22.10 the first one), and
//! a removal is rewritten like any other: an old `Contact` sent with
//! `expires=0` from the new socket can name the new binding. The registrar
//! here rewrites them all, the worst case: with `remove_existing` and one
//! contact allowed, a REGISTER that both adds the new address and removes the
//! old one leaves nothing bound, and the 200 that says so lists no `Contact`.
//!
//! The application's part is what a platform notification sets off: the SIP
//! socket bound at the new address, the change reported, the account pointed
//! at the new socket, and a STUN answer about that socket a moment later.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, parse};

use crate::account::{Account, AccountId};
use crate::agent::UserAgent;
use crate::event::{RegistrationState, UaEvent};
use crate::subscription::{Subscribe, SubscriptionEnd, SubscriptionHandle, SubscriptionState};
use crate::{EndpointConfig, Input, Link, Network, Recovery, TransportId, TransportProtocol, Uri};

const UDP: TransportId = TransportId(1);

/// The cable, before the move.
fn cable() -> SocketAddr {
    "192.168.3.233:5060".parse().expect("an address")
}

/// The Wi-Fi, after it.
fn wifi() -> SocketAddr {
    "192.168.3.105:5060".parse().expect("an address")
}

/// What the NAT showed the registrar before the move.
fn mapped_before() -> SocketAddr {
    "80.97.52.1:1344".parse().expect("an address")
}

/// And after.
fn mapped_after() -> SocketAddr {
    "80.97.52.1:1343".parse().expect("an address")
}

fn pbx() -> SocketAddr {
    "198.51.100.20:5060".parse().expect("an address")
}

fn uri(text: &str) -> Uri {
    Uri::parse_str(text).expect("a URI")
}

fn network(at: SocketAddr, interface: &str, link: Link) -> Network {
    Network::new(link).address(at.ip()).interface(interface)
}

fn header(bytes: &[u8], name: HeaderName<'_>) -> String {
    let mut scratch = ParseScratch::new();
    let message = parse(bytes, &mut scratch, ParseMode::Lenient).expect("a message");
    String::from_utf8_lossy(message.header(name).unwrap_or_default()).into_owned()
}

/// A response echoing what §8.2.6.2 requires, plus `extra`.
fn reply(request: &[u8], status: &str, to_tag: Option<&str>, extra: &str) -> Vec<u8> {
    let mut to = header(request, HeaderName::To);
    if let Some(tag) = to_tag
        && !to.contains(";tag=")
    {
        to.push_str(";tag=");
        to.push_str(tag);
    }
    format!(
        "SIP/2.0 {status}\r\nVia: {}\r\nFrom: {}\r\nTo: {to}\r\nCall-ID: {}\r\nCSeq: {}\r\n\
{extra}Content-Length: 0\r\n\r\n",
        header(request, HeaderName::Via),
        header(request, HeaderName::From),
        header(request, HeaderName::CallId),
        header(request, HeaderName::CSeq),
    )
    .into_bytes()
}

/// The entries of a `Contact` field, each as written, with whether it asks
/// for removal.
fn entries(contact: &str) -> Vec<(String, bool)> {
    contact
        .split(", ")
        .map(|entry| {
            let uri = entry
                .split_once('<')
                .and_then(|(_, rest)| rest.split_once('>'))
                .map_or(entry, |(uri, _)| uri);
            (uri.to_owned(), entry.contains(";expires=0"))
        })
        .collect()
}

/// `sip:user@host:port` with the host and port replaced by `source`.
fn rewritten(uri: &str, source: SocketAddr) -> String {
    let user = uri
        .split_once(':')
        .and_then(|(_, rest)| rest.split_once('@'))
        .map_or("", |(user, _)| user);
    format!("sip:{user}@{source}")
}

/// Asterisk's registrar as FreePBX configures an extension behind a
/// NAT: `rewrite_contact=yes`, `remove_existing=yes`, `max_contacts=1`.
///
/// Every `Contact` is rewritten to the request's source before anything else
/// is done with it, then each is applied in the order written: harsher than
/// Asterisk 18.9 and 22.10, which rewrite the first.
struct Rewriting {
    bindings: Vec<String>,
    /// Whether the 200 lists what is bound, as RFC 3261 §10.3 step 8 says.
    echoes: bool,
}

impl Rewriting {
    const fn new() -> Self {
        Self {
            bindings: Vec::new(),
            echoes: true,
        }
    }

    fn register(&mut self, request: &[u8], source: SocketAddr) -> Vec<u8> {
        let all_go = header(request, HeaderName::Expires) == "0";
        for (uri, removal) in entries(&header(request, HeaderName::Contact)) {
            let uri = rewritten(&uri, source);
            if removal || all_go {
                self.bindings.retain(|bound| *bound != uri);
            } else {
                self.bindings.clear();
                self.bindings.push(uri);
            }
        }
        let mut extra = String::new();
        if self.echoes {
            for bound in &self.bindings {
                extra.push_str("Contact: <");
                extra.push_str(bound);
                extra.push_str(">;expires=3600\r\n");
            }
        }
        extra.push_str("Expires: 3600\r\n");
        reply(request, "200 OK", None, &extra)
    }
}

/// A NOTIFY that opens or carries on the dialog a SUBSCRIBE asked for.
fn notification(subscribe: &[u8], cseq: u32, state: &str) -> Vec<u8> {
    let target = header(subscribe, HeaderName::Contact);
    let target = target.trim_start_matches('<').trim_end_matches('>');
    format!(
        "NOTIFY {target} SIP/2.0\r\nVia: SIP/2.0/UDP {}:5060;branch=z9hG4bKpbx{cseq}x{}\r\n\
Max-Forwards: 70\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {cseq} NOTIFY\r\n\
Contact: <sip:130@{}>\r\nEvent: presence\r\nSubscription-State: {state}\r\n\
Content-Length: 0\r\n\r\n",
        pbx().ip(),
        header(subscribe, HeaderName::CallId).len(),
        tagged(&header(subscribe, HeaderName::To)),
        header(subscribe, HeaderName::From),
        header(subscribe, HeaderName::CallId),
        pbx(),
    )
    .into_bytes()
}

/// The PBX's end of a subscription dialog: its tag, added once.
fn tagged(to: &str) -> String {
    if to.contains(";tag=") {
        to.to_owned()
    } else {
        format!("{to};tag=pbx")
    }
}

/// The stack, the PBX it talks to, and where the stack's socket is now.
struct Desk {
    agent: UserAgent,
    pbx: Rewriting,
    account: AccountId,
    local: SocketAddr,
    source: SocketAddr,
    /// The NOTIFY CSeq the PBX uses next, per subscription dialog.
    notify_cseq: u32,
    seen: Vec<UaEvent>,
    subscribes: usize,
}

impl Desk {
    fn new(now: Instant) -> Self {
        let mut agent = UserAgent::new(EndpointConfig::default(), [21; 32]).unwrap();
        agent
            .receive(
                Input::TransportBound {
                    transport: UDP,
                    protocol: TransportProtocol::Udp,
                    local: cable(),
                    remote: None,
                },
                now,
            )
            .expect("binding the socket");
        let account = agent.add_account(Account::new(
            uri("sip:130@example.com"),
            uri("sip:example.com"),
            uri(&format!("sip:130@{}", mapped_before())),
            UDP,
            pbx(),
        ));
        Self {
            agent,
            pbx: Rewriting::new(),
            account,
            local: cable(),
            source: mapped_before(),
            notify_cseq: 1,
            seen: Vec::new(),
            subscribes: 0,
        }
    }

    fn deliver(&mut self, bytes: &[u8], now: Instant) {
        self.agent
            .receive(
                Input::Datagram {
                    transport: UDP,
                    remote: pbx(),
                    local: self.local,
                    data: bytes,
                },
                now,
            )
            .expect("a datagram the agent reads");
    }

    /// Answer everything the stack sent, as the PBX does, until it is quiet.
    fn exchange(&mut self, now: Instant) {
        loop {
            let mut out = Vec::new();
            while let Some(transmit) = self.agent.poll_transmit() {
                assert_eq!(transmit.destination, pbx(), "sent somewhere else");
                out.push(transmit.payload.to_vec());
            }
            self.seen
                .extend(std::iter::from_fn(|| self.agent.poll_event()));
            if out.is_empty() {
                return;
            }
            for request in out {
                if request.starts_with(b"REGISTER ") {
                    let answer = self.pbx.register(&request, self.source);
                    self.deliver(&answer, now);
                } else if request.starts_with(b"SUBSCRIBE ") {
                    self.subscribes += 1;
                    let answer = reply(&request, "200 OK", Some("pbx"), "Expires: 600\r\n");
                    self.deliver(&answer, now);
                    // a refresh is notified too (RFC 6665 §4.2.1.2)
                    let notify = notification(&request, self.notify_cseq, "active;expires=600");
                    self.notify_cseq += 1;
                    self.deliver(&notify, now);
                }
            }
        }
    }

    /// The machine moves from the cable to the Wi-Fi: what the application
    /// does on the platform's notification, in the order it does it.
    fn move_to_wifi(&mut self, now: Instant) -> Recovery {
        self.agent
            .receive(
                Input::TransportBound {
                    transport: UDP,
                    protocol: TransportProtocol::Udp,
                    local: wifi(),
                    remote: None,
                },
                now,
            )
            .expect("binding the new socket");
        self.local = wifi();
        self.source = mapped_after();
        let recovery = self.agent.network_changed(
            &network(cable(), "en6", Link::Wired),
            &network(wifi(), "en0", Link::Wifi),
            now,
        );
        self.agent
            .rebind(
                self.account,
                UDP,
                pbx(),
                &uri(&format!("sip:130@{}", wifi())),
                now,
            )
            .expect("the account is there");
        recovery
    }

    /// STUN answers about the new socket.
    fn learn_mapping(&mut self, now: Instant) {
        let moved = self.agent.readdress(UDP, wifi(), mapped_after(), now);
        assert_eq!(moved, 1, "the account names the new socket");
    }

    fn ended(&self) -> Vec<(SubscriptionHandle, SubscriptionEnd)> {
        self.seen
            .iter()
            .filter_map(|event| match *event {
                UaEvent::SubscriptionEnded {
                    subscription,
                    reason,
                    ..
                } => Some((subscription, reason)),
                _ => None,
            })
            .collect()
    }

    /// Every deadline up to `until`, answered as it comes.
    fn run_until(&mut self, mut now: Instant, until: Instant) {
        while let Some(due) = self.agent.poll_timeout() {
            if due > until {
                break;
            }
            now = due.max(now);
            self.agent.handle_timeout(now);
            self.exchange(now);
        }
    }
}

fn registered_desk(now: Instant) -> Desk {
    let mut desk = Desk::new(now);
    desk.agent.register(desk.account, now).expect("a REGISTER");
    desk.exchange(now);
    assert_eq!(
        desk.agent.registration_state(desk.account),
        Some(RegistrationState::Registered)
    );
    assert_eq!(desk.pbx.bindings, [format!("sip:130@{}", mapped_before())]);
    desk
}

#[test]
fn a_move_behind_a_rewriting_registrar_leaves_the_new_binding_standing() {
    let t0 = Instant::now();
    let mut desk = registered_desk(t0);

    assert_eq!(desk.move_to_wifi(t0), Recovery::Rebuild);
    desk.exchange(t0);
    desk.learn_mapping(t0);
    desk.exchange(t0);

    assert_eq!(
        desk.pbx.bindings,
        [format!("sip:130@{}", mapped_after())],
        "the registrar is left with nothing to send calls to"
    );
    assert_eq!(
        desk.agent.registration_state(desk.account),
        Some(RegistrationState::Registered)
    );
}

/// What the stack wrote, drained, unanswered.
fn written(desk: &mut Desk) -> Vec<Vec<u8>> {
    std::iter::from_fn(|| desk.agent.poll_transmit())
        .map(|transmit| transmit.payload.to_vec())
        .collect()
}

#[test]
fn a_contact_the_registrar_holds_under_another_address_is_not_taken_back() {
    // the REGISTER from the new socket was answered with the source address
    // in place of the one sent: removing what was sent would name that
    let t0 = Instant::now();
    let mut desk = registered_desk(t0);
    desk.move_to_wifi(t0);
    desk.exchange(t0);
    assert_eq!(desk.pbx.bindings, [format!("sip:130@{}", mapped_after())]);

    desk.learn_mapping(t0);
    let out = written(&mut desk);
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(
        header(&out[0], HeaderName::Contact),
        format!("<sip:130@{}>", mapped_after()),
        "the new address alone, with nothing asked to go"
    );
}

#[test]
fn an_old_contact_not_yet_answered_for_is_withdrawn_on_its_own_before_the_add() {
    // STUN answers before the registrar does: nothing says yet how the
    // address being left is held, so it is removed, alone, and first
    let t0 = Instant::now();
    let mut desk = registered_desk(t0);
    desk.move_to_wifi(t0);
    let unanswered = written(&mut desk);
    assert!(
        unanswered
            .iter()
            .any(|bytes| bytes.starts_with(b"REGISTER "))
    );
    desk.seen.clear();

    desk.learn_mapping(t0);
    let mut out = written(&mut desk);
    assert_eq!(out.len(), 1, "one request at a time");
    let withdrawal = out.pop().unwrap_or_default();
    assert!(withdrawal.starts_with(b"REGISTER "));
    assert_eq!(
        header(&withdrawal, HeaderName::Contact),
        format!("<sip:130@{}>;expires=0", wifi()),
        "only the address being left, so a registrar that rewrites it cannot \
         take the new binding with it"
    );

    let answer = desk.pbx.register(&withdrawal, desk.source);
    desk.deliver(&answer, t0);
    let mut out = Vec::new();
    while let Some(transmit) = desk.agent.poll_transmit() {
        out.push(transmit.payload.to_vec());
    }
    let adding = out.pop().unwrap_or_default();
    assert!(adding.starts_with(b"REGISTER "));
    assert_eq!(
        header(&adding, HeaderName::Contact),
        format!("<sip:130@{}>", mapped_after())
    );
    let withdrawn_cseq = header(&withdrawal, HeaderName::CSeq);
    let adding_cseq = header(&adding, HeaderName::CSeq);
    assert!(
        withdrawn_cseq
            .split(' ')
            .next()
            .and_then(|n| n.parse::<u32>().ok())
            < adding_cseq
                .split(' ')
                .next()
                .and_then(|n| n.parse::<u32>().ok()),
        "{withdrawn_cseq} then {adding_cseq}: §10.2 orders them by CSeq"
    );
    desk.seen
        .extend(std::iter::from_fn(|| desk.agent.poll_event()));
    assert!(
        !desk
            .seen
            .iter()
            .any(|event| matches!(*event, UaEvent::Registered { .. })),
        "the withdrawal is not the binding: {:?}",
        desk.seen
    );
}

#[test]
fn a_registrar_that_lists_no_contact_is_asked_again_before_registered_is_said() {
    let t0 = Instant::now();
    let mut desk = Desk::new(t0);
    desk.agent.register(desk.account, t0).expect("a REGISTER");
    let first = desk
        .agent
        .poll_transmit()
        .expect("the REGISTER")
        .payload
        .to_vec();
    // a 200 whose Contact list is empty: nothing was kept (§10.2.4)
    desk.deliver(&reply(&first, "200 OK", None, "Expires: 3600\r\n"), t0);
    assert_ne!(
        desk.agent.registration_state(desk.account),
        Some(RegistrationState::Registered)
    );
    let again = desk
        .agent
        .poll_transmit()
        .expect("asked again at once")
        .payload
        .to_vec();
    assert!(again.starts_with(b"REGISTER "));
    let answer = desk.pbx.register(&again, desk.source);
    desk.deliver(&answer, t0);
    assert_eq!(
        desk.agent.registration_state(desk.account),
        Some(RegistrationState::Registered)
    );
}

#[test]
fn a_registrar_that_never_lists_contacts_is_believed_the_second_time() {
    let t0 = Instant::now();
    let mut desk = Desk::new(t0);
    desk.pbx.echoes = false;
    desk.agent.register(desk.account, t0).expect("a REGISTER");
    desk.exchange(t0);
    assert_eq!(
        desk.agent.registration_state(desk.account),
        Some(RegistrationState::Registered),
        "a registrar that does not echo still keeps the binding"
    );
    let registers = desk
        .seen
        .iter()
        .filter(|event| matches!(**event, UaEvent::Registered { .. }))
        .count();
    assert_eq!(registers, 1);

    // and its refreshes are not doubled for ever
    desk.seen.clear();
    let mut sent = 0;
    while let Some(now) = desk.agent.poll_timeout() {
        if now > t0 + Duration::from_secs(3_700) {
            break;
        }
        desk.agent.handle_timeout(now);
        while let Some(transmit) = desk.agent.poll_transmit() {
            if transmit.payload.starts_with(b"REGISTER ") {
                sent += 1;
                let answer = desk.pbx.register(&transmit.payload, desk.source);
                desk.deliver(&answer, now);
            }
        }
    }
    assert_eq!(sent, 1, "one refresh in the hour");
}

#[test]
fn subscriptions_carry_on_at_the_new_address_after_a_move() {
    let t0 = Instant::now();
    let mut desk = registered_desk(t0);
    let watched: Vec<SubscriptionHandle> = (0..3)
        .map(|n| {
            desk.agent
                .subscribe(
                    desk.account,
                    &Subscribe::new(uri(&format!("sip:20{n}@example.com")), "presence"),
                    t0,
                )
                .expect("a SUBSCRIBE")
        })
        .collect();
    desk.exchange(t0);
    for handle in &watched {
        assert_eq!(
            desk.agent.subscription_state(*handle),
            Some(SubscriptionState::Active)
        );
    }
    desk.subscribes = 0;

    let moved = t0 + Duration::from_secs(5);
    desk.move_to_wifi(moved);
    desk.exchange(moved);
    desk.learn_mapping(moved);
    desk.exchange(moved);
    assert!(
        desk.subscribes >= watched.len(),
        "each subscription is made again from the new address"
    );

    // two of their lifetimes on, every one still alive
    desk.run_until(moved, moved + Duration::from_secs(1_300));
    assert_eq!(desk.ended(), [], "{:?}", desk.seen);
    for handle in &watched {
        assert_eq!(
            desk.agent.subscription_state(*handle),
            Some(SubscriptionState::Active)
        );
    }
}
