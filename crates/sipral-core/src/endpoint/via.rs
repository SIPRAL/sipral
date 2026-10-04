// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Writing the `Via` we put on, and reading the one that came back.
//!
//! Three rules live here, and each of them decides whether an answer ever
//! arrives.
//!
//! **What we write.** `sent-by` is the address the far end has to answer to,
//! so it is the address the caller advertised for the transport rather than
//! anything read off a socket (§18.1.1). The branch carries the `z9hG4bK`
//! cookie of §8.1.1.7, without which the far end matches us the pre-3261 way.
//! `;rport` goes on every request (RFC 3581 §3), because the alternative is
//! not receiving responses from behind the NAT nearly every softphone sits
//! behind, and a server that has never heard of RFC 3581 ignores it.
//!
//! **What we discard.** §18.1.2: a response whose top `Via` does not name us
//! is not ours, and is dropped before the transaction layer sees it.
//!
//! **Where a response goes.** §18.2.2 and RFC 3581 §4 read as a list of
//! cases, and for a user agent answering a request they collapse into one
//! sentence: *the response goes back to the address the request came from.*
//! The reasoning is worth writing down, because the collapse looks like a
//! shortcut and is not. §18.2.1 makes a server add a `received` parameter
//! whenever the `sent-by` host is a name, or an address that differs from the
//! packet source; RFC 3581 §4 makes it add one unconditionally when `rport`
//! is present. So in every case where `sent-by` disagrees with the source, the
//! response is sent to the source; and in the one case where they agree, the
//! source *is* `sent-by`. Only the port is still open: `rport` answers with
//! the source port, and without it the port is the one in `sent-by`.
//!
//! This stack never rewrites an arriving message to add those parameters — it
//! reads the source address and the `Via` together and gets the same answer,
//! which is cheaper and keeps the received bytes exactly as they arrived.

use std::net::{IpAddr, SocketAddr};

use super::transport::TransportProtocol;
use crate::msg::{HostRef, Rport, ViaRef};

/// The `Via` value for a request we are about to send.
pub(crate) fn local_via(
    protocol: TransportProtocol,
    local: SocketAddr,
    branch: &[u8],
    request_rport: bool,
) -> Box<[u8]> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(b"SIP/2.0/");
    out.extend_from_slice(protocol.as_str().as_bytes());
    out.push(b' ');
    // Display for SocketAddr is the sent-by grammar already: an IPv6 literal
    // in brackets, the port after a colon
    out.extend_from_slice(local.to_string().as_bytes());
    out.extend_from_slice(b";branch=");
    out.extend_from_slice(branch);
    if request_rport {
        out.extend_from_slice(b";rport");
    }
    out.into_boxed_slice()
}

/// Whether a response's top `Via` names this endpoint (§18.1.2).
///
/// "If the value does not match, the response MUST be discarded." The
/// parameters the far end added — `received`, `rport` — are not part of the
/// comparison: `sent-by` is what we wrote and what has to come back.
pub(crate) fn is_ours(via: &ViaRef<'_>, local: SocketAddr, protocol: TransportProtocol) -> bool {
    if !via.transport.eq_ignore_ascii_case(protocol.as_str()) {
        return false;
    }
    let host_matches = match via.host {
        HostRef::Ipv4(addr) => IpAddr::V4(addr) == local.ip(),
        HostRef::Ipv6(addr) => IpAddr::V6(addr) == local.ip(),
        // we never write a name into our own sent-by, so one coming back is
        // somebody else's Via
        HostRef::Name(_) => false,
    };
    host_matches && via.port.unwrap_or_else(|| default_port(protocol)) == local.port()
}

/// Where the response to a request that arrived from `source` has to go.
///
/// `None` means the top `Via` asked for something this layer cannot do on its
/// own — a `maddr` naming a host rather than an address — and the caller has
/// to resolve it.
pub(crate) fn response_destination(
    via: &ViaRef<'_>,
    source: SocketAddr,
    protocol: TransportProtocol,
) -> Option<SocketAddr> {
    // "If the sent-protocol is a reliable transport protocol ... the response
    // MUST be sent using the existing connection to the source of the
    // original request", which is the connection this arrived on
    if protocol.is_reliable() {
        return Some(source);
    }

    // "if the Via header field value contains a maddr parameter, the response
    // MUST be forwarded to the address listed there, using the port indicated
    // in sent-by, or port 5060 if none is present"
    if let Some(maddr) = via.maddr() {
        let literal = core::str::from_utf8(&maddr)
            .ok()
            .and_then(|text| text.trim_matches(['[', ']']).parse::<IpAddr>().ok());
        // a maddr that is a name needs the resolver the caller owns; there is
        // no answer to give here
        return literal.map(|addr| SocketAddr::new(addr, via.port.unwrap_or(5060)));
    }

    // RFC 3581 4: "the response MUST be sent to the IP address listed in the
    // received parameter, and the port in the rport parameter" — both of
    // which are the source of the request, since we are the server that
    // would have written them
    if matches!(via.rport(), Ok(Rport::Requested | Rport::Given(_))) {
        return Some(source);
    }

    // Everything left over: the address is the source either way, because a
    // sent-by that disagreed with it earned a received parameter and one that
    // agreed is the source. The port is sent-by's.
    Some(SocketAddr::new(
        source.ip(),
        via.port.unwrap_or_else(|| default_port(protocol)),
    ))
}

/// The port to assume when `sent-by` gives none. 5060 for the transports
/// that have no default of their own, since that is what §18.1.1 leaves.
fn default_port(protocol: TransportProtocol) -> u16 {
    protocol.default_port().unwrap_or(5060)
}

#[cfg(test)]
mod tests {
    use super::{is_ours, local_via, response_destination};
    use crate::endpoint::TransportProtocol;
    use crate::msg::ViaRef;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn via(value: &str) -> ViaRef<'_> {
        ViaRef::parse(value.as_bytes()).unwrap()
    }

    #[test]
    fn a_via_we_write_carries_the_cookie_and_asks_for_rport() {
        let value = local_via(
            TransportProtocol::Udp,
            addr("192.0.2.1:5060"),
            b"z9hG4bKabc",
            true,
        );
        assert_eq!(
            &*value,
            b"SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKabc;rport"
        );
    }

    #[test]
    fn rport_is_left_off_when_it_was_turned_off() {
        let value = local_via(
            TransportProtocol::Tls,
            addr("192.0.2.1:5061"),
            b"z9hG4bKabc",
            false,
        );
        assert_eq!(&*value, b"SIP/2.0/TLS 192.0.2.1:5061;branch=z9hG4bKabc");
    }

    #[test]
    fn an_ipv6_sent_by_wears_its_brackets() {
        let value = local_via(
            TransportProtocol::Udp,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5060),
            b"z9hG4bK1",
            false,
        );
        assert_eq!(&*value, b"SIP/2.0/UDP [::1]:5060;branch=z9hG4bK1");
    }

    #[test]
    fn a_response_addressed_to_somebody_else_is_not_ours() {
        // 18.1.2: "If the value does not match, the response MUST be discarded"
        let local = addr("192.0.2.1:5060");
        assert!(is_ours(
            &via("SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1"),
            local,
            TransportProtocol::Udp
        ));
        assert!(!is_ours(
            &via("SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK1"),
            local,
            TransportProtocol::Udp
        ));
        assert!(!is_ours(
            &via("SIP/2.0/UDP 192.0.2.1:5070;branch=z9hG4bK1"),
            local,
            TransportProtocol::Udp
        ));
        assert!(!is_ours(
            &via("SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK1"),
            local,
            TransportProtocol::Udp
        ));
    }

    #[test]
    fn the_parameters_the_far_end_added_are_not_part_of_the_comparison() {
        let local = addr("192.0.2.1:5060");
        assert!(is_ours(
            &via("SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1;received=198.51.100.7;rport=41234"),
            local,
            TransportProtocol::Udp
        ));
    }

    #[test]
    fn a_missing_port_means_the_default_for_the_transport() {
        assert!(is_ours(
            &via("SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1"),
            addr("192.0.2.1:5060"),
            TransportProtocol::Udp
        ));
        assert!(is_ours(
            &via("SIP/2.0/TLS 192.0.2.1;branch=z9hG4bK1"),
            addr("192.0.2.1:5061"),
            TransportProtocol::Tls
        ));
    }

    #[test]
    fn a_name_in_our_own_sent_by_is_somebody_elses_via() {
        assert!(!is_ours(
            &via("SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK1"),
            addr("192.0.2.1:5060"),
            TransportProtocol::Udp
        ));
    }

    #[test]
    fn on_a_reliable_transport_the_response_goes_back_down_the_connection() {
        let source = addr("198.51.100.7:41234");
        assert_eq!(
            response_destination(
                &via("SIP/2.0/TCP alice.example.com:5060;branch=z9hG4bK1"),
                source,
                TransportProtocol::Tcp
            ),
            Some(source)
        );
    }

    #[test]
    fn rport_sends_the_response_to_the_port_the_request_came_from() {
        // the case the whole extension exists for: the NAT rewrote the port,
        // and 5060 in sent-by is where nothing is listening
        let source = addr("198.51.100.7:41234");
        assert_eq!(
            response_destination(
                &via("SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bK1;rport"),
                source,
                TransportProtocol::Udp
            ),
            Some(source)
        );
    }

    #[test]
    fn without_rport_the_address_is_still_the_source_and_the_port_is_sent_bys() {
        // 18.2.1 makes a server add received whenever sent-by disagrees with
        // the source, so the address is the source in every case
        let source = addr("198.51.100.7:41234");
        assert_eq!(
            response_destination(
                &via("SIP/2.0/UDP 192.168.1.5:5062;branch=z9hG4bK1"),
                source,
                TransportProtocol::Udp
            ),
            Some(addr("198.51.100.7:5062"))
        );
    }

    #[test]
    fn a_sent_by_with_no_port_answers_on_the_default() {
        let source = addr("198.51.100.7:41234");
        assert_eq!(
            response_destination(
                &via("SIP/2.0/UDP alice.example.com;branch=z9hG4bK1"),
                source,
                TransportProtocol::Udp
            ),
            Some(addr("198.51.100.7:5060"))
        );
    }

    #[test]
    fn an_maddr_takes_the_response_where_it_says() {
        let source = addr("198.51.100.7:41234");
        assert_eq!(
            response_destination(
                &via("SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1;maddr=224.0.1.75"),
                source,
                TransportProtocol::Udp
            ),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(224, 0, 1, 75)),
                5060
            ))
        );
    }

    #[test]
    fn an_maddr_that_is_a_name_is_left_to_the_caller() {
        // resolving it is I/O, and a response is not worth a round trip of it
        // inside a layer that has no resolver
        let source = addr("198.51.100.7:41234");
        assert_eq!(
            response_destination(
                &via("SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1;maddr=mcast.example.com"),
                source,
                TransportProtocol::Udp
            ),
            None
        );
    }
}
