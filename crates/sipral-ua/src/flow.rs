// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! An account on a connection of its own, to its own server.
//!
//! One stack can hold an account registered over UDP with one PBX and
//! another over TLS with a second: every account names the transport its
//! requests go out on and the server they go to, and the calls it places
//! keep that flow for every request inside them, since a dialog keeps the
//! flow its INVITE went out on (`sipral_core::endpoint`'s resolve module).
//! What a connection adds is that it has to exist first, and that this crate
//! opens no socket. An account made with [`Account::on_stream`] says which
//! protocol its connection speaks, and this module asks the application for
//! one to the account's server — [`Event::TransportWanted`], the event RFC
//! 3261 §18.1.1 already raises when a request outgrows a datagram — and
//! adopts whatever transport the application binds to that address, under
//! any number it likes.
//!
//! **When it asks.** When the account's REGISTER is about to go and no
//! connection to its server is bound, and for an account that never
//! registers, once when it is added. The REGISTER waits, as one waits for a
//! lookup; [`crate::oversize::STREAM_WAIT`] after the question it is given up
//! as unreachable and retried after the back-off any registration that found
//! nobody gets (RFC 5626 §4.5), and the retry asks again. A connection that
//! closes or fails is asked for again by the next REGISTER, and at once for
//! an account that never registers.
//!
//! **What it adopts.** A transport of the account's protocol bound to the
//! account's server — connected to that address, or an unconnected one of
//! that protocol — whenever one is bound, so a connection the application
//! opened before the account was added is used as it stands.
//!
//! [`Account::on_stream`]: crate::Account::on_stream

use std::time::Instant;

use sipral_core::endpoint::{Event, TransportId};

use crate::account::AccountId;
use crate::agent::UserAgent;
use crate::event::{RegistrationState, UaEvent};
use crate::oversize::STREAM_WAIT;

/// Whether an account's requests can go now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Flow {
    /// On the transport it names, which is bound.
    Ready,
    /// A connection was asked for and has not been bound yet; wait until
    /// `until`.
    Asked { until: Instant },
    /// A connection was asked for [`STREAM_WAIT`] ago and none came.
    NotComing,
}

impl UserAgent {
    /// Where `account`'s requests stand: on a transport that is bound, or
    /// waiting for the connection it was made to have. Adopts a connection
    /// that is bound, and asks for one that is not.
    pub(crate) fn account_flow(&mut self, account: AccountId, now: Instant) -> Flow {
        let Some(config) = self.accounts.get(&account) else {
            return Flow::Ready;
        };
        let Some(protocol) = config.own_stream else {
            return Flow::Ready;
        };
        // a server still being looked up has no address to connect to; the
        // lookup is what this waits for first
        if !config.located {
            return Flow::Ready;
        }
        let server = config.remote;
        if let Some(found) = self.endpoint.transport_to(protocol, server) {
            if let Some(config) = self.accounts.get_mut(&account) {
                config.transport = found;
            }
            self.flows_wanted.remove(&account);
            return Flow::Ready;
        }
        match self.flows_wanted.get(&account).copied() {
            Some(asked) if now < asked + STREAM_WAIT => Flow::Asked {
                until: asked + STREAM_WAIT,
            },
            Some(_) => {
                self.flows_wanted.remove(&account);
                Flow::NotComing
            }
            None => {
                self.flows_wanted.insert(account, now);
                self.events
                    .push_back(UaEvent::Unclaimed(Event::TransportWanted {
                        protocol,
                        destination: server,
                        request_bytes: 0,
                        limit_bytes: 0,
                    }));
                Flow::Asked {
                    until: now + STREAM_WAIT,
                }
            }
        }
    }

    /// A REGISTER for `account` that has to wait for its connection: held
    /// until the connection is bound or the wait runs out.
    pub(crate) fn register_waits_for_flow(
        &mut self,
        account: AccountId,
        unregistering: bool,
        now: Instant,
    ) -> Result<bool, crate::UaError> {
        match self.account_flow(account, now) {
            Flow::Ready => Ok(false),
            Flow::Asked { until } => {
                if let Some(reg) = self.registrations.get_mut(&account)
                    && reg.transaction.is_none()
                {
                    reg.due = Some(until);
                    if !unregistering {
                        reg.state = RegistrationState::Registering;
                    }
                }
                Ok(true)
            }
            Flow::NotComing => Err(crate::UaError::Send(
                sipral_core::endpoint::SendError::NeedsStreamTransport,
            )),
        }
    }

    /// A transport was bound: every account waiting for a connection to the
    /// address it reaches takes it, and a REGISTER that was waiting goes.
    pub(crate) fn adopt_flows(&mut self, now: Instant) {
        let waiting: Vec<AccountId> = self.flows_wanted.keys().copied().collect();
        for account in waiting {
            if self.account_flow(account, now) != Flow::Ready {
                continue;
            }
            let held = self.registrations.get(&account).is_some_and(|reg| {
                reg.transaction.is_none()
                    && matches!(
                        reg.state,
                        RegistrationState::Registering | RegistrationState::Retrying
                    )
            });
            if held {
                let unregistering = self
                    .registrations
                    .get(&account)
                    .is_some_and(|reg| reg.unregistering);
                if let Err(error) = self.send_register(account, unregistering, now) {
                    self.register_unsent(account, &error, now);
                }
            }
        }
    }

    /// A transport closed or failed: an account whose connection it was asks
    /// for another — at once when it never registers, and with its next
    /// REGISTER otherwise.
    pub(crate) fn flow_lost(&mut self, transport: TransportId) {
        for (account, config) in &self.accounts {
            if config.own_stream.is_some() && config.transport == transport {
                self.flows_wanted.remove(account);
                self.flows_lost.push(*account);
            }
        }
    }

    /// Ask for the connection of every account that never registers and has
    /// none: once when it is added, and again when the one it had is lost.
    /// Run at the end of every round of work.
    pub(crate) fn settle_flows(&mut self, now: Instant) {
        let fresh: Vec<AccountId> = self
            .accounts
            .iter()
            .filter(|(id, config)| {
                config.own_stream.is_some()
                    && config.registrar.is_none()
                    && config.located
                    && (!self.flows_asked.contains(id) || self.flows_lost.contains(id))
            })
            .map(|(id, _)| *id)
            .collect();
        self.flows_lost.clear();
        for account in fresh {
            self.flows_asked.insert(account);
            let _ = self.account_flow(account, now);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use sipral_core::endpoint::{Event, Input, TransportErrorKind, TransportId, TransportProtocol};
    use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, parse};

    use crate::account::{Account, AccountId};
    use crate::agent::UserAgent;
    use crate::call::OutgoingCall;
    use crate::event::UaEvent;
    use crate::{EndpointConfig, Uri};

    const UDP: TransportId = TransportId(1);
    const TLS: TransportId = TransportId(7);

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn uri(text: &str) -> Uri {
        Uri::parse_str(text).unwrap()
    }

    fn local() -> SocketAddr {
        addr("192.0.2.1:5060")
    }

    fn tls_local() -> SocketAddr {
        addr("192.0.2.1:50123")
    }

    /// The PBX on UDP.
    fn first() -> SocketAddr {
        addr("198.51.100.10:5060")
    }

    /// The one on TLS.
    fn second() -> SocketAddr {
        addr("203.0.113.20:5061")
    }

    fn bound_udp(seed: u8, now: Instant) -> UserAgent {
        let mut agent = UserAgent::new(EndpointConfig::default(), [seed; 32]).unwrap();
        agent
            .receive(
                Input::TransportBound {
                    transport: UDP,
                    protocol: TransportProtocol::Udp,
                    local: local(),
                    remote: None,
                },
                now,
            )
            .unwrap();
        agent
    }

    fn bind_stream(agent: &mut UserAgent, protocol: TransportProtocol, now: Instant) {
        agent
            .receive(
                Input::TransportBound {
                    transport: TLS,
                    protocol,
                    local: tls_local(),
                    remote: Some(second()),
                },
                now,
            )
            .unwrap();
    }

    /// An agent with the stack's UDP transport bound, an account on it with
    /// the first PBX and another, with the same user, on TLS with the second.
    fn two_lines(now: Instant) -> (UserAgent, AccountId, AccountId) {
        let mut agent = bound_udp(41, now);
        let on_udp = agent.add_account(Account::new(
            uri("sip:100@first.example.com"),
            uri("sip:first.example.com"),
            uri("sip:100@192.0.2.1:5060"),
            UDP,
            first(),
        ));
        let on_tls = agent.add_account(
            Account::new(
                uri("sip:100@second.example.com"),
                uri("sips:second.example.com"),
                uri("sips:100@192.0.2.1:50123;transport=tls"),
                UDP,
                second(),
            )
            .on_stream(TransportProtocol::Tls),
        );
        (agent, on_udp, on_tls)
    }

    struct Sent {
        transport: TransportId,
        destination: SocketAddr,
        bytes: Vec<u8>,
    }

    fn drain(agent: &mut UserAgent) -> (Vec<Sent>, Vec<UaEvent>) {
        let mut sent = Vec::new();
        while let Some(transmit) = agent.poll_transmit() {
            sent.push(Sent {
                transport: transmit.transport,
                destination: transmit.destination,
                bytes: transmit.payload.to_vec(),
            });
        }
        let mut events = Vec::new();
        while let Some(event) = agent.poll_event() {
            events.push(event);
        }
        (sent, events)
    }

    fn header(bytes: &[u8], name: HeaderName<'_>) -> Vec<u8> {
        let mut scratch = ParseScratch::new();
        let message = parse(bytes, &mut scratch, ParseMode::Lenient).unwrap();
        message.header(name).unwrap_or_default().to_vec()
    }

    /// A 200 for `request`, its `To` tagged and `contact` in its `Contact`.
    fn ok_for(request: &[u8], contact: &str) -> Vec<u8> {
        let mut out = b"SIP/2.0 200 OK\r\n".to_vec();
        let mut to = header(request, HeaderName::To);
        to.extend_from_slice(b";tag=pbx");
        for (name, value) in [
            ("Via", header(request, HeaderName::Via)),
            ("From", header(request, HeaderName::From)),
            ("To", to),
            ("Call-ID", header(request, HeaderName::CallId)),
            ("CSeq", header(request, HeaderName::CSeq)),
            ("Contact", contact.as_bytes().to_vec()),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"Expires: 3600\r\nContent-Length: 0\r\n\r\n");
        out
    }

    fn invite(request_uri: &str, call_id: &str, via: &str) -> Vec<u8> {
        format!(
            "INVITE {request_uri} SIP/2.0\r\nVia: {via};branch=z9hG4bK{call_id}\r\n\
             Max-Forwards: 70\r\nFrom: <sip:200@example.net>;tag=a{call_id}\r\n\
             To: <{request_uri}>\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\n\
             Contact: <sip:200@example.net>\r\nContent-Length: 0\r\n\r\n"
        )
        .into_bytes()
    }

    fn incoming_account(events: &[UaEvent]) -> Option<AccountId> {
        events.iter().find_map(|event| match event {
            UaEvent::IncomingCall { account, .. } => Some(*account),
            _ => None,
        })?
    }

    fn wanted(events: &[UaEvent]) -> Vec<(TransportProtocol, SocketAddr)> {
        events
            .iter()
            .filter_map(|event| match event {
                UaEvent::Unclaimed(Event::TransportWanted {
                    protocol,
                    destination,
                    ..
                }) => Some((*protocol, *destination)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn an_account_on_tls_asks_for_its_connection_and_registers_over_it() {
        let t0 = Instant::now();
        let (mut agent, on_udp, on_tls) = two_lines(t0);
        agent.register(on_udp, t0).unwrap();
        agent.register(on_tls, t0).unwrap();
        let (sent, events) = drain(&mut agent);
        assert_eq!(sent.len(), 1, "only the UDP account's REGISTER goes");
        assert_eq!((sent[0].transport, sent[0].destination), (UDP, first()));
        assert_eq!(wanted(&events), [(TransportProtocol::Tls, second())]);

        // the application connects, and binds the connection under a number
        // of its own
        bind_stream(&mut agent, TransportProtocol::Tls, t0);
        let (sent, _) = drain(&mut agent);
        assert_eq!(sent.len(), 1);
        assert!(
            sent[0]
                .bytes
                .starts_with(b"REGISTER sips:second.example.com")
        );
        assert_eq!((sent[0].transport, sent[0].destination), (TLS, second()));
        assert!(
            String::from_utf8_lossy(&header(&sent[0].bytes, HeaderName::Via))
                .starts_with("SIP/2.0/TLS"),
            "the Via says what it went over"
        );
    }

    #[test]
    fn a_call_before_the_connection_is_refused_and_nothing_goes_over_udp() {
        let t0 = Instant::now();
        let (mut agent, _, on_tls) = two_lines(t0);
        let refused = agent.call(
            on_tls,
            &OutgoingCall::new(uri("sips:300@second.example.com")),
            t0,
        );
        assert!(
            matches!(
                refused,
                Err(crate::UaError::Send(
                    sipral_core::endpoint::SendError::UnknownTransport
                ))
            ),
            "{refused:?}"
        );
        let (sent, _) = drain(&mut agent);
        assert!(sent.is_empty(), "nothing over the stack's UDP transport");
    }

    #[test]
    fn a_registration_whose_connection_never_comes_fails_and_asks_again() {
        let t0 = Instant::now();
        let (mut agent, _, on_tls) = two_lines(t0);
        agent.register(on_tls, t0).unwrap();
        let _ = drain(&mut agent);
        let mut now = t0;
        let mut failed = false;
        let mut asked_again = false;
        while let Some(due) = agent.poll_timeout() {
            if due > t0 + Duration::from_secs(120) {
                break;
            }
            now = due.max(now);
            agent.handle_timeout(now);
            let (sent, events) = drain(&mut agent);
            assert!(sent.iter().all(|one| one.transport == UDP));
            failed |= events
                .iter()
                .any(|event| matches!(event, UaEvent::RegistrationFailed { .. }));
            asked_again |= failed && !wanted(&events).is_empty();
        }
        assert!(failed, "given up as unreachable once the wait ran out");
        assert!(asked_again, "the retry asks for the connection again");
    }

    fn over_tls(agent: &mut UserAgent, bytes: &[u8], now: Instant) -> Vec<UaEvent> {
        agent
            .receive(
                Input::StreamData {
                    transport: TLS,
                    data: bytes,
                },
                now,
            )
            .unwrap();
        drain(agent).1
    }

    fn over_udp(agent: &mut UserAgent, bytes: &[u8], now: Instant) -> Vec<UaEvent> {
        agent
            .receive(
                Input::Datagram {
                    transport: UDP,
                    remote: first(),
                    local: local(),
                    data: bytes,
                },
                now,
            )
            .unwrap();
        drain(agent).1
    }

    /// Both lines registered, the TLS one over a connection bound before
    /// its REGISTER went.
    fn registered_lines(now: Instant) -> (UserAgent, AccountId, AccountId) {
        let (mut agent, on_udp, on_tls) = two_lines(now);
        bind_stream(&mut agent, TransportProtocol::Tls, now);
        agent.register(on_udp, now).unwrap();
        agent.register(on_tls, now).unwrap();
        let (sent, _) = drain(&mut agent);
        assert_eq!(sent.len(), 2, "a connection bound first is used at once");
        for register in &sent {
            let contact = header(&register.bytes, HeaderName::Contact);
            let ok = ok_for(&register.bytes, &String::from_utf8_lossy(&contact));
            if register.transport == TLS {
                over_tls(&mut agent, &ok, now);
            } else {
                over_udp(&mut agent, &ok, now);
            }
        }
        (agent, on_udp, on_tls)
    }

    #[test]
    fn requests_on_each_flow_reach_their_own_account() {
        let t0 = Instant::now();
        let (mut agent, on_udp, on_tls) = registered_lines(t0);
        // both PBXs call user 100, each at the contact its account gave
        let tls = invite(
            "sips:100@192.0.2.1:50123;transport=tls",
            "on-tls",
            "SIP/2.0/TLS 203.0.113.20:5061",
        );
        assert_eq!(
            incoming_account(&over_tls(&mut agent, &tls, t0)),
            Some(on_tls)
        );
        let udp = invite(
            "sip:100@192.0.2.1:5060",
            "on-udp",
            "SIP/2.0/UDP 198.51.100.10:5060",
        );
        assert_eq!(
            incoming_account(&over_udp(&mut agent, &udp, t0)),
            Some(on_udp)
        );
        // a PBX that rewrote the host still names the user: the flow says
        // which line, where the URI alone names neither
        let rewritten = invite(
            "sip:100@10.9.8.7:5060",
            "rewritten",
            "SIP/2.0/TLS 203.0.113.20:5061",
        );
        assert_eq!(
            incoming_account(&over_tls(&mut agent, &rewritten, t0)),
            Some(on_tls)
        );
    }

    #[test]
    fn a_call_keeps_its_accounts_flow_for_every_request_inside_it() {
        let t0 = Instant::now();
        let (mut agent, _, on_tls) = registered_lines(t0);
        let call = agent
            .call(
                on_tls,
                &OutgoingCall::new(uri("sips:300@second.example.com")),
                t0,
            )
            .unwrap();
        let (sent, _) = drain(&mut agent);
        let placed = sent
            .iter()
            .find(|one| one.bytes.starts_with(b"INVITE "))
            .unwrap();
        assert_eq!((placed.transport, placed.destination), (TLS, second()));
        let answer = ok_for(&placed.bytes, "<sips:300@203.0.113.20:5061;transport=tls>");
        over_tls(&mut agent, &answer, t0);
        agent.hangup(call, t0).unwrap();
        let (sent, _) = drain(&mut agent);
        let bye = sent
            .iter()
            .find(|one| one.bytes.starts_with(b"BYE "))
            .expect("a BYE");
        assert_eq!((bye.transport, bye.destination), (TLS, second()));
    }

    #[test]
    fn an_account_that_never_registers_asks_once_and_again_after_a_loss() {
        let t0 = Instant::now();
        let mut agent = bound_udp(43, t0);
        agent.add_account(
            Account::unregistered(
                uri("sip:trunk@second.example.com"),
                uri("sip:trunk@192.0.2.1:50123;transport=tcp"),
                UDP,
                second(),
            )
            .on_stream(TransportProtocol::Tcp),
        );
        agent.handle_timeout(t0);
        let (_, events) = drain(&mut agent);
        assert_eq!(
            wanted(&events),
            [(TransportProtocol::Tcp, second())],
            "asked once when added"
        );
        agent.handle_timeout(t0);
        let (_, events) = drain(&mut agent);
        assert!(wanted(&events).is_empty(), "and not again while it waits");
        bind_stream(&mut agent, TransportProtocol::Tcp, t0);
        let _ = drain(&mut agent);
        agent
            .receive(
                Input::TransportFailed {
                    transport: TLS,
                    error: TransportErrorKind::ConnectionReset,
                },
                t0,
            )
            .unwrap();
        let (_, events) = drain(&mut agent);
        assert_eq!(
            wanted(&events),
            [(TransportProtocol::Tcp, second())],
            "a lost connection is asked for again"
        );
    }
}
