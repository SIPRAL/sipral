// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Where a dialog's requests go (RFC 3261 §8.1.2, §12.2.1.1, RFC 3263).
//!
//! RFC 3263 resolution (NAPTR, SRV, A) is I/O and stays with the caller.
//! §12.2.1.1 allows sending to "an alternate address", so a dialog keeps the
//! flow its first message used: the only address that survives NAT.
//! When the next hop differs, [`Event::ResolveNeeded`] reports it, and a
//! caller with a resolver answers through [`Endpoint::resolved`]. NAPTR/SRV
//! answers carry a transport (§4.1) and several ordered addresses (§4.3);
//! the spare ones are kept for failover on this endpoint's own failures.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use super::driver::Endpoint;
use super::event::Event;
use super::table::Flow;
use super::transport::{Host, TransportProtocol};
use crate::msg::Uri;
use crate::transaction::{AnyTransactionId, DialogId, NonInviteClient, TransactionId};

impl Endpoint {
    /// Ask again when a target refresh moved the remote target (§12.2.1.2,
    /// §12.2.2). `before` is the target as a string, since `Uri` has no
    /// usable `PartialEq`; `None` means the dialog was already gone.
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

    /// Point a dialog's requests at an address resolved outside, on the
    /// transport RFC 3263 §4.1 says the lookup named.
    ///
    /// `protocol` is `None` for a bare A lookup; the flow keeps its protocol.
    /// A transport is only found, never opened: the first address with an open
    /// transport of that protocol wins (§4.3 "first server") and the rest are
    /// kept for failover. If none is usable or the dialog ended, nothing changes.
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

    /// Move a failed flow to the next address [`Endpoint::resolved`] kept.
    ///
    /// RFC 3263 §4.3: retry "a different server" only when the transport proved
    /// unusable (failure or timeout). A signed refusal such as 404 came from the
    /// right server. Not used for a re-INVITE, whose failure ends the dialog
    /// (§12.2.1.2). A flow the dialog already left is not moved twice.
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

    /// [`Endpoint::failover`] for an in-dialog non-INVITE client transaction.
    /// Out-of-dialog requests are never in [`Endpoint::remember_dialog`], so
    /// this is a no-op for them.
    pub(super) fn failover_in_dialog(&mut self, id: TransactionId<NonInviteClient>, flow: Flow) {
        if let Some(dialog) = self.dialog_of(AnyTransactionId::NonInviteClient(id)) {
            self.failover(dialog, flow);
        }
    }

    /// Report a dialog's next hop when its requests are not already going there.
    ///
    /// A name always asks. A literal address is not applied either: a private
    /// `Contact` behind NAT is the common case and looks the same as a far end
    /// that really moved, so the flow stands until [`Endpoint::resolved`].
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
/// the host portion of the URI if not." `via.rs` applies the same rule.
pub(super) fn target_host(sip: &crate::msg::SipUriRef<'_>) -> Host {
    let Some(maddr) = sip.maddr() else {
        return Host::from_ref(sip.host);
    };
    // §19.1.1 brackets an IPv6 literal wherever it appears in a URI
    maddr
        .trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .map_or_else(|_| Host::Name(Arc::from(maddr)), Host::Ip)
}

/// The URI a request in this dialog goes to (§12.2.1.1): the first route,
/// else the remote target.
fn next_hop(dialog: &crate::dialog::Dialog) -> Uri {
    dialog
        .route_set()
        .first()
        .unwrap_or_else(|| dialog.remote_target())
        .clone()
}

/// Whether the flow already points at the URI. A host name never does,
/// since nothing here can resolve it.
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

/// The transport a URI asks for: §19.1.1 `transport`, or TLS for `sips`
/// (RFC 3263 §4.2).
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
        // RFC 3263 §4: the maddr is the target, not the host
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
