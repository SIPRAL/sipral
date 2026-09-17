// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Where a dialog's requests go, and who decides it (RFC 3261 §8.1.2,
//! §12.2.1.1, RFC 3263).
//!
//! §12.2.1.1 sends an in-dialog request to "the address of the server",
//! computed from the topmost `Route` value or the Request-URI by the RFC 3263
//! procedures — NAPTR, then SRV, then A. None of that happens here: it is I/O,
//! it needs a resolver, and the platform has a better one than a protocol
//! library would.
//!
//! What the endpoint does instead is what the same section explicitly allows:
//! "they allow the request to be sent to an alternate address (such as a
//! default outbound proxy not represented in the route set)". A dialog keeps
//! the flow its first message travelled on — the address the INVITE went to
//! and the 2xx came back from — which is both the best address known and the
//! only one that survives the NAT nearly every softphone sits behind.
//!
//! And it says so. When the next hop a dialog names is not the address its
//! requests are going to, [`Event::ResolveNeeded`] reports the host, and a
//! caller that has a resolver can answer with [`Endpoint::resolved`]. Ignoring
//! it is a legitimate choice and the common one; answering it is what a proxy
//! or a server-side deployment wants.
//!
//! A NAPTR or SRV answer, unlike an A lookup, names a transport as well as an
//! address (§4.1) and may name several addresses to try in order (§4.3), so
//! [`Endpoint::resolved`] takes both: the protocol travels with the flow it
//! sets, and the addresses after the one it takes are kept, and tried in
//! turn on this endpoint's own transport failures and timeouts, rather than
//! handed back for the caller to retry by itself.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use super::driver::Endpoint;
use super::event::Event;
use super::table::Flow;
use super::transport::{Host, TransportProtocol};
use crate::msg::Uri;
use crate::transaction::{AnyTransactionId, DialogId, NonInviteClient, TransactionId};

impl Endpoint {
    /// Ask again when a response or request just applied moved the remote
    /// target (§12.2.1.2, §12.2.2's target refresh).
    ///
    /// `ask_to_resolve` runs once at dialog creation, and nothing else moves
    /// the flow a dialog's requests go out on — `Dialog::on_response` and
    /// `Dialog::on_request` are pure, sans-I/O mutations with no access to it.
    /// `before` is the remote target as it read just before the call that may
    /// have changed it; comparing strings rather than `Uri`s is deliberate,
    /// since `Uri` has no `PartialEq` that answers this question. `None`
    /// means the dialog was already gone and there is nothing to compare.
    pub(super) fn resolve_if_target_moved(&mut self, dialog: DialogId, before: Option<&str>) {
        let Some(before) = before else {
            return;
        };
        let moved = self
            .dialogs
            .get(dialog)
            .is_some_and(|held| held.remote_target().as_str() != before);
        if moved {
            self.ask_to_resolve(dialog);
        }
    }

    /// Point a dialog's requests at an address that was resolved outside, on
    /// the transport RFC 3263 §4.1 says the lookup named.
    ///
    /// `protocol` is `None` when the caller has none to report — an A lookup
    /// with nothing upstream of it, as the reference loop does — and then the
    /// flow keeps speaking whatever it already spoke; `Some` is what a NAPTR
    /// or SRV answer carries, and may name a protocol the dialog was not
    /// using.
    ///
    /// A protocol is only ever *found*, never opened: this layer does not own
    /// a socket, so a transport nothing has bound for it is not something it
    /// can invent. The addresses are walked in the order they were handed in
    /// and the first one this endpoint already has an open transport of the
    /// wanted protocol for is taken (RFC 3263 §4.3's "first server"); the ones
    /// after it are kept rather than discarded, for this endpoint to try in
    /// turn, on its own, if this one goes on to fail. An address before it
    /// that named a protocol nothing here speaks is not tried again either —
    /// it is simply not one "that can be used" today, and answering
    /// [`Event::ResolveNeeded`] again after opening the transport it asked for
    /// is how it gets another chance. When not one of the addresses can be
    /// used this way, or the dialog has already ended, nothing changes: the
    /// flow stands exactly as it did before this was called.
    ///
    /// There is no `now` here on purpose. Every other call that changes the
    /// endpoint takes the time because something it does is timed; this one
    /// only writes down an address.
    pub fn resolved(
        &mut self,
        dialog: DialogId,
        addresses: &[SocketAddr],
        protocol: Option<TransportProtocol>,
    ) {
        let Some(flow) = self.dialogs.flow(dialog) else {
            return;
        };
        let wanted = protocol.unwrap_or(flow.protocol);
        let mut rest = addresses.iter().copied();
        let Some((transport, destination)) = rest
            .by_ref()
            .find_map(|address| Some((self.transports.speaking_to(wanted, address)?, address)))
        else {
            return;
        };
        self.dialogs.set_flow(
            dialog,
            Flow {
                transport,
                destination,
                protocol: wanted,
                ..flow
            },
        );
        self.dialogs.set_failover(dialog, rest.collect());
    }

    /// The flow a request just failed on gets the next address
    /// [`Endpoint::resolved`] kept for it, if there is one this endpoint has a
    /// transport for.
    ///
    /// RFC 3263 §4.3: "if the transport in the first server proved to be
    /// unusable, then the client SHOULD retry the request... [with] a
    /// different server". "Unusable" is what a transport failure or a timeout
    /// says — nothing came back, or nothing could be sent — never a refusal
    /// the far end signed: a 404 from the address this reached is an answer
    /// from the right server, and moving to a different one would be asking
    /// it the wrong question.
    ///
    /// Called only where a dialog stands to lose nothing else by staying
    /// open — an in-dialog request that timed out or hit a dead transport,
    /// not a re-INVITE, whose own failure already ends the dialog
    /// (§12.2.1.2, [`super::reinvite`]) before there is anywhere left to
    /// retry it. `flow` is the one the failed request went out on: a dialog
    /// that has since moved past it, because another request on the same
    /// flow already triggered this, is not moved a second time by a late
    /// report about the first.
    pub(super) fn failover(&mut self, dialog: DialogId, flow: Flow) {
        if self.dialogs.flow(dialog) != Some(flow) {
            return;
        }
        while let Some(address) = self.dialogs.take_failover(dialog) {
            if let Some(transport) = self.transports.speaking_to(flow.protocol, address) {
                self.dialogs.set_flow(
                    dialog,
                    Flow {
                        transport,
                        destination: address,
                        ..flow
                    },
                );
                return;
            }
        }
    }

    /// [`Endpoint::failover`], for a non-INVITE client transaction that was
    /// sent inside a dialog.
    ///
    /// A transaction started outside one — a REGISTER, an OPTIONS this end
    /// sent out of the blue — is never given to [`Endpoint::remember_dialog`],
    /// so this is a no-op for it, exactly as it should be: nothing here ever
    /// gave such a request a resolved answer to fail over from.
    pub(super) fn failover_in_dialog(&mut self, id: TransactionId<NonInviteClient>, flow: Flow) {
        if let Some(dialog) = self.dialog_of(AnyTransactionId::NonInviteClient(id)) {
            self.failover(dialog, flow);
        }
    }

    /// Say what a dialog's next hop is, if it is not where its requests are
    /// already going.
    ///
    /// Called when the dialog is created, and again whenever a target
    /// refresh moves its remote target. A name always asks, because nothing
    /// here can tell whether it resolves to the address in hand.
    ///
    /// A literal address is not applied here either, and that is the whole of
    /// the decision this function makes. The flow a dialog keeps is the one
    /// its first message travelled on, which is the only address that
    /// survives the NAT nearly every softphone sits behind; the literal
    /// address in a `Contact` from behind one is private and unreachable, and
    /// that is the ordinary case rather than the exotic one. Nothing here can
    /// tell it from a far end that genuinely moved. So the event goes out and
    /// the flow stands until the caller answers with
    /// [`Endpoint::resolved`], which is what that event is for.
    pub(super) fn ask_to_resolve(&mut self, dialog: DialogId) {
        let (Some(flow), Some(target)) = (
            self.dialogs.flow(dialog),
            self.dialogs.get(dialog).map(next_hop),
        ) else {
            return;
        };
        if points_at(&target, flow) {
            return;
        }
        let Some(sip) = target.sip() else {
            return;
        };
        self.push(Event::ResolveNeeded {
            dialog,
            host: target_host(&sip),
            port: sip.port,
            protocol: protocol_of(&target),
        });
    }
}

/// RFC 3263 §4: "the TARGET is the maddr parameter of the URI, if present, and
/// the host portion of the URI if not."
///
/// A `Route` value with a `maddr` names the proxy the request has to travel
/// through; resolving its host instead sends the request to a different
/// machine that happens to be named in the same URI. The response path applies
/// the same rule to a `Via` in `via.rs`, and the two must not disagree.
fn target_host(sip: &crate::msg::SipUriRef<'_>) -> Host {
    let Some(maddr) = sip.maddr() else {
        return Host::from_ref(sip.host);
    };
    // §19.1.1 brackets an IPv6 literal wherever it appears in a URI
    maddr
        .trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .map_or_else(|_| Host::Name(Arc::from(maddr)), Host::Ip)
}

/// The URI whose address a request in this dialog would be sent to
/// (§12.2.1.1): the first hop of the route set, or the remote target when
/// there is none.
fn next_hop(dialog: &crate::dialog::Dialog) -> Uri {
    dialog
        .route_set()
        .first()
        .unwrap_or_else(|| dialog.remote_target())
        .clone()
}

/// Whether the flow already points at what the URI names.
///
/// A host name never counts: resolving it is exactly what this layer cannot
/// do, so it cannot know that the name and the address agree.
fn points_at(target: &Uri, flow: Flow) -> bool {
    let Some(sip) = target.sip() else {
        return false;
    };
    let Some(address) = target_host(&sip).ip() else {
        return false;
    };
    let port = sip
        .port
        .unwrap_or_else(|| flow.protocol.default_port().unwrap_or(5060));
    SocketAddr::new(address, port) == flow.destination
}

/// The transport a URI asks for, when it asks for one.
///
/// §19.1.1's `transport` parameter, and the `sips` scheme, which RFC 3263 §4.2
/// resolves to TLS when nothing else says otherwise.
fn protocol_of(target: &Uri) -> Option<TransportProtocol> {
    if let Some(named) = target
        .param("transport")
        .and_then(|value| TransportProtocol::from_token(value.as_bytes()))
    {
        return Some(named);
    }
    target.is_secure().then_some(TransportProtocol::Tls)
}

#[cfg(test)]
mod tests {
    use super::{points_at, protocol_of, target_host};
    use crate::endpoint::table::Flow;
    use crate::endpoint::{TransportId, TransportProtocol};
    use crate::msg::Uri;
    use std::net::{IpAddr, SocketAddr};

    fn flow(destination: &str, protocol: TransportProtocol) -> Flow {
        Flow {
            transport: TransportId(1),
            destination: destination.parse::<SocketAddr>().unwrap(),
            source: None,
            protocol,
        }
    }

    fn uri(text: &str) -> Uri {
        Uri::parse_str(text).unwrap()
    }

    #[test]
    fn an_address_that_matches_needs_no_resolving() {
        assert!(points_at(
            &uri("sip:bob@192.0.2.9:5060"),
            flow("192.0.2.9:5060", TransportProtocol::Udp)
        ));
        // the default port is the transport's
        assert!(points_at(
            &uri("sip:bob@192.0.2.9"),
            flow("192.0.2.9:5060", TransportProtocol::Udp)
        ));
        assert!(points_at(
            &uri("sips:bob@192.0.2.9"),
            flow("192.0.2.9:5061", TransportProtocol::Tls)
        ));
    }

    #[test]
    fn an_address_that_differs_is_worth_reporting() {
        assert!(!points_at(
            &uri("sip:bob@198.51.100.7"),
            flow("192.0.2.9:5060", TransportProtocol::Udp)
        ));
        assert!(!points_at(
            &uri("sip:bob@192.0.2.9:5080"),
            flow("192.0.2.9:5060", TransportProtocol::Udp)
        ));
    }

    #[test]
    fn a_name_always_asks_because_nothing_here_can_resolve_it() {
        assert!(!points_at(
            &uri("sip:bob@example.com"),
            flow("192.0.2.9:5060", TransportProtocol::Udp)
        ));
    }

    #[test]
    fn a_maddr_is_the_target_and_the_host_is_not() {
        // RFC 3263 4: "the TARGET is the maddr parameter of the URI, if
        // present, and the host portion of the URI if not". A Route value with
        // a maddr names the proxy to travel through, and resolving its host
        // sends the request somewhere else entirely
        assert_eq!(
            target_host(&uri("sip:p1.example.com;maddr=192.0.2.9").sip().unwrap()).ip(),
            Some("192.0.2.9".parse::<IpAddr>().unwrap())
        );
        assert!(points_at(
            &uri("sip:p1.example.com;maddr=192.0.2.9"),
            flow("192.0.2.9:5060", TransportProtocol::Udp)
        ));
        assert!(
            !points_at(
                &uri("sip:192.0.2.9;maddr=198.51.100.7"),
                flow("192.0.2.9:5060", TransportProtocol::Udp)
            ),
            "the host is not where this one goes"
        );
        // 19.1.1 brackets an IPv6 literal wherever it appears in a URI
        assert_eq!(
            target_host(&uri("sip:p1.example.com;maddr=[2001:db8::1]").sip().unwrap()).ip(),
            Some("2001:db8::1".parse::<IpAddr>().unwrap())
        );
        // a maddr that is a name needs the resolver the caller owns
        assert_eq!(
            target_host(&uri("sip:192.0.2.9;maddr=sip.example.net").sip().unwrap()).ip(),
            None
        );
    }

    #[test]
    fn a_uri_that_is_not_sip_names_no_hostport_to_compare() {
        assert!(!points_at(
            &uri("tel:+12015550123"),
            flow("192.0.2.9:5060", TransportProtocol::Udp)
        ));
    }

    #[test]
    fn the_transport_a_uri_asks_for_is_read_off_it() {
        assert_eq!(
            protocol_of(&uri("sip:bob@example.com;transport=tcp")),
            Some(TransportProtocol::Tcp)
        );
        assert_eq!(
            protocol_of(&uri("sips:bob@example.com")),
            Some(TransportProtocol::Tls),
            "a sips URI resolves to TLS unless told otherwise"
        );
        assert_eq!(protocol_of(&uri("sip:bob@example.com")), None);
    }
}
