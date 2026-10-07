// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Writing our `Via` and reading the one that comes back.
//!
//! `sent-by` is the address the caller advertised (§18.1.1), the branch has
//! the `z9hG4bK` cookie (§8.1.1.7), and `;rport` goes on every request
//! (RFC 3581 §3) so responses get back through NAT. A response whose top
//! `Via` is not ours is dropped (§18.1.2).
//!
//! For a UA, §18.2.2 and RFC 3581 §4 collapse to "send the response to the
//! request's source address". A server adds `received` whenever `sent-by`
//! differs from the source (§18.2.1), and always with `rport`, so the address
//! is always the source. Only the port depends on `rport`. We read the source
//! and `Via` together instead of rewriting the message.

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
    // SocketAddr's Display already matches the sent-by grammar
    via_with(
        protocol,
        local.to_string().as_bytes(),
        branch,
        request_rport,
    )
}

/// The `Via` for a transport that advertises a name, such as a WebSocket
/// `.invalid` host (RFC 7118 Appendix B.1), written without a port.
pub(crate) fn named_via(
    protocol: TransportProtocol,
    name: &str,
    branch: &[u8],
    request_rport: bool,
) -> Box<[u8]> {
    via_with(protocol, name.as_bytes(), branch, request_rport)
}

fn via_with(
    protocol: TransportProtocol,
    sent_by: &[u8],
    branch: &[u8],
    request_rport: bool,
) -> Box<[u8]> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(b"SIP/2.0/");
    out.extend_from_slice(protocol.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(sent_by);
    out.extend_from_slice(b";branch=");
    out.extend_from_slice(branch);
    if request_rport {
        out.extend_from_slice(b";rport");
    }
    out.into_boxed_slice()
}

/// Whether a response's top `Via` names this endpoint (§18.1.2). Parameters
/// the far end added (`received`, `rport`) are ignored.
pub(crate) fn is_ours(via: &ViaRef<'_>, local: SocketAddr, protocol: TransportProtocol) -> bool {
    if !via.transport.eq_ignore_ascii_case(protocol.as_str()) {
        return false;
    }
    let host_matches = match via.host {
        HostRef::Ipv4(addr) => IpAddr::V4(addr) == local.ip(),
        HostRef::Ipv6(addr) => IpAddr::V6(addr) == local.ip(),
        // we never write a name into our own sent-by
        HostRef::Name(_) => false,
    };
    host_matches && via.port.unwrap_or_else(|| default_port(protocol)) == local.port()
}

/// [`is_ours`] for a named `sent-by`: case-insensitive host (§19.1.4), no port.
pub(crate) fn is_ours_named(via: &ViaRef<'_>, name: &str, protocol: TransportProtocol) -> bool {
    if !via.transport.eq_ignore_ascii_case(protocol.as_str()) {
        return false;
    }
    match via.host {
        HostRef::Name(host) => host.eq_ignore_ascii_case(name) && via.port.is_none(),
        HostRef::Ipv4(_) | HostRef::Ipv6(_) => false,
    }
}

/// Where the response to a request from `source` goes. `None` when a
/// `maddr` names a host the caller must resolve.
pub(crate) fn response_destination(
    via: &ViaRef<'_>,
    source: SocketAddr,
    protocol: TransportProtocol,
) -> Option<SocketAddr> {
    // §18.2.2: reliable transport, reuse the connection the request came on
    if protocol.is_reliable() {
        return Some(source);
    }

    // §18.2.2: maddr wins, with the sent-by port or 5060
    if let Some(maddr) = via.maddr() {
        let literal = core::str::from_utf8(&maddr)
            .ok()
            .and_then(|text| text.trim_matches(['[', ']']).parse::<IpAddr>().ok());
        return literal.map(|addr| SocketAddr::new(addr, via.port.unwrap_or(5060)));
    }

    // RFC 3581 §4: received and rport would both be the source
    if matches!(via.rport(), Ok(Rport::Requested | Rport::Given(_))) {
        return Some(source);
    }

    // otherwise: the source address with sent-by's port
    Some(SocketAddr::new(
        source.ip(),
        via.port.unwrap_or_else(|| default_port(protocol)),
    ))
}

/// The port to assume when `sent-by` gives none (5060 if the transport has
/// no default, per §18.1.1).
fn default_port(protocol: TransportProtocol) -> u16 {
    protocol.default_port().unwrap_or(5060)
}

#[cfg(test)]
mod tests {
    use super::{is_ours, is_ours_named, local_via, named_via, response_destination};
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
        // §18.1.2
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
    fn a_named_sent_by_is_written_without_a_port_and_recognised_coming_back() {
        let name = "df7jal23ls0d.invalid";
        let value = named_via(TransportProtocol::Ws, name, b"z9hG4bK1", true);
        assert_eq!(
            &*value,
            b"SIP/2.0/WS df7jal23ls0d.invalid;branch=z9hG4bK1;rport"
        );
        assert!(is_ours_named(
            &via("SIP/2.0/WS DF7JAL23LS0D.invalid;branch=z9hG4bK1;received=192.0.2.4"),
            name,
            TransportProtocol::Ws
        ));
        for other in [
            "SIP/2.0/WSS df7jal23ls0d.invalid;branch=z9hG4bK1",
            "SIP/2.0/WS other.invalid;branch=z9hG4bK1",
            "SIP/2.0/WS df7jal23ls0d.invalid:80;branch=z9hG4bK1",
            "SIP/2.0/WS 192.0.2.1;branch=z9hG4bK1",
        ] {
            assert!(
                !is_ours_named(&via(other), name, TransportProtocol::Ws),
                "{other}"
            );
        }
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
        // the NAT rewrote the port; nothing listens on sent-by's 5060
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
        // §18.2.1: received is added whenever sent-by disagrees with the source
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
