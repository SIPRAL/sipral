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

use std::net::{IpAddr, SocketAddr};

use super::driver::Endpoint;
use super::event::Event;
use super::table::Flow;
use super::transport::{Host, TransportProtocol};
use crate::msg::{HostRef, Uri};
use crate::transaction::DialogId;

impl Endpoint {
    /// Point a dialog's requests at an address that was resolved outside.
    ///
    /// The first address that can be used is taken; the rest are the caller's
    /// to retry with, since which of several SRV targets is reachable is
    /// something only an attempt can answer. An answer for a dialog that has
    /// ended is dropped.
    ///
    /// There is no `now` here on purpose. Every other call that changes the
    /// endpoint takes the time because something it does is timed; this one
    /// only writes down an address.
    pub fn resolved(&mut self, dialog: DialogId, addresses: &[SocketAddr]) {
        let (Some(flow), Some(&destination)) = (self.dialogs.flow(dialog), addresses.first())
        else {
            return;
        };
        self.dialogs.set_flow(
            dialog,
            Flow {
                destination,
                ..flow
            },
        );
    }

    /// Say what a dialog's next hop is, if it is not where its requests are
    /// already going.
    ///
    /// Called once, when the dialog is created. A name always asks, because
    /// nothing here can tell whether it resolves to the address in hand.
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
            host: Host::from_ref(sip.host),
            port: sip.port,
            protocol: protocol_of(&target),
        });
    }
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
    let address = match sip.host {
        HostRef::Ipv4(addr) => IpAddr::V4(addr),
        HostRef::Ipv6(addr) => IpAddr::V6(addr),
        HostRef::Name(_) => return false,
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
    use super::{points_at, protocol_of};
    use crate::endpoint::table::Flow;
    use crate::endpoint::{TransportId, TransportProtocol};
    use crate::msg::Uri;
    use std::net::SocketAddr;

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
