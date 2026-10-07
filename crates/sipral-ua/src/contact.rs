// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Which address a `Contact` names, and the same `Contact` naming another.
//!
//! What [`UserAgent::readdress`](crate::UserAgent::readdress) needs to move an
//! account from the address its socket is bound to onto the one a NAT shows
//! the world, without touching anything else the application wrote into it.

use std::net::{IpAddr, SocketAddr};

use sipral_core::endpoint::TransportProtocol;
use sipral_core::msg::{Uri, UriScheme};

/// `<sip:address>`, with the `transport` parameter a stream or a WebSocket
/// needs, for a call that arrived for no account and so has no configured
/// `Contact` of its own.
///
/// §12.1.1 requires a `Contact` on dialog-creating responses; the arrival
/// address is the only one this end is sure of. Without `transport`, a far
/// end on TCP or TLS would fall back to UDP (§19.1.2).
pub(crate) fn contact_for_arrival(address: SocketAddr, protocol: TransportProtocol) -> Box<[u8]> {
    // the `transport-param` tokens are the `Via` ones in lower case: `tcp`
    // and `tls` in §25.1, `ws` and `wss` in RFC 7118 §5.2
    let parameter = if protocol == TransportProtocol::Udp {
        String::new()
    } else {
        format!(";transport={}", protocol.as_str().to_ascii_lowercase())
    };
    format!("<sip:{address}{parameter}>")
        .into_bytes()
        .into_boxed_slice()
}

/// `contact` with its host and port replaced by `address`, or `None` for a
/// URI that is not `sip:` or `sips:`.
///
/// User part, parameters and headers stay as written. IPv6 is bracketed
/// (RFC 3261 §25.1 `hostport`).
pub(crate) fn contact_at(contact: &Uri, address: SocketAddr) -> Option<Uri> {
    let text = contact.as_str();
    let (start, end) = hostport_span(text)?;
    let mut rewritten = String::with_capacity(text.len() + 8);
    rewritten.push_str(text.get(..start)?);
    rewritten.push_str(&address.to_string());
    rewritten.push_str(text.get(end..)?);
    Uri::parse_str(&rewritten).ok()
}

/// `contact` with its host and port replaced by `name`, and the `transport`
/// parameter `protocol` needs added when it has none, or `None` for a URI
/// that is not `sip:` or `sips:`.
///
/// What a WebSocket client registers (RFC 7118 Appendix B.1 and §8's
/// example): `sip:alice@df7jal23ls0d.invalid;transport=ws`. The user part,
/// the other parameters and the headers stay as written.
pub(crate) fn contact_on_name(
    contact: &Uri,
    name: &str,
    protocol: TransportProtocol,
) -> Option<Uri> {
    let text = contact.as_str();
    let (start, end) = hostport_span(text)?;
    let tail = text.get(end..)?;
    let parameters = tail.get(..tail.find('?').unwrap_or(tail.len()))?;
    let has_transport = parameters.split(';').any(|parameter| {
        parameter
            .split('=')
            .next()
            .is_some_and(|key| key.trim().eq_ignore_ascii_case("transport"))
    });
    let mut rewritten = String::with_capacity(text.len() + name.len() + 16);
    rewritten.push_str(text.get(..start)?);
    rewritten.push_str(name);
    if !has_transport {
        rewritten.push_str(";transport=");
        rewritten.push_str(&protocol.as_str().to_ascii_lowercase());
    }
    rewritten.push_str(tail);
    Uri::parse_str(&rewritten).ok()
}

/// Whether `contact`'s host is an IP literal, whatever its port.
pub(crate) fn contact_names_an_address(contact: &Uri) -> bool {
    if contact.sip().is_none() {
        return false;
    }
    let Some((start, end)) = hostport_span(contact.as_str()) else {
        return false;
    };
    let Some(hostport) = contact.as_str().get(start..end) else {
        return false;
    };
    let host = match hostport.rfind(':') {
        Some(colon) if !hostport.ends_with(']') => hostport.get(..colon).unwrap_or(hostport),
        _ => hostport,
    };
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok()
}

/// Whether `contact` names `address`: the same IP literal, and the same port
/// or no port where `address` has the one RFC 3261 §19.1.2 makes the default
/// for the scheme.
///
/// A contact with a name or another address was chosen on purpose and is
/// never rewritten.
pub(crate) fn contact_names(contact: &Uri, address: SocketAddr) -> bool {
    let Some(sip) = contact.sip() else {
        return false;
    };
    let Some((start, end)) = hostport_span(contact.as_str()) else {
        return false;
    };
    let Some(hostport) = contact.as_str().get(start..end) else {
        return false;
    };
    let host = match hostport.rfind(':') {
        Some(colon) if !hostport.ends_with(']') => hostport.get(..colon).unwrap_or(hostport),
        _ => hostport,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let Ok(ip) = host.parse::<IpAddr>() else {
        return false;
    };
    let default = if matches!(sip.scheme, UriScheme::Sips) {
        5061
    } else {
        5060
    };
    ip == address.ip() && sip.port.unwrap_or(default) == address.port()
}

/// Where the `hostport` of a `sip:` or `sips:` URI begins and ends, in bytes.
///
/// Same cuts as the parser (RFC 3261 §19.1.1).
fn hostport_span(text: &str) -> Option<(usize, usize)> {
    let colon = text.find(':')?;
    let scheme = text.get(..colon)?;
    if !scheme.eq_ignore_ascii_case("sip") && !scheme.eq_ignore_ascii_case("sips") {
        return None;
    }
    let after_scheme = colon + 1;
    let rest = text.get(after_scheme..)?;
    let start = after_scheme + rest.find('@').map_or(0, |at| at + 1);
    let tail = text.get(start..)?;
    let before_headers = tail.find('?').unwrap_or(tail.len());
    let end = start
        + tail
            .get(..before_headers)?
            .find(';')
            .unwrap_or(before_headers);
    (end > start).then_some((start, end))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use sipral_core::endpoint::TransportProtocol;
    use sipral_core::msg::Uri;

    use super::{contact_at, contact_for_arrival, contact_names, contact_on_name};

    fn uri(text: &str) -> Uri {
        Uri::parse_str(text).expect("a URI")
    }

    #[test]
    fn a_websocket_contact_names_the_invalid_host_and_says_how_it_is_reached() {
        let named = |text: &str| {
            contact_on_name(&uri(text), "df7jal23ls0d.invalid", TransportProtocol::Ws)
                .expect("a sip URI")
                .as_str()
                .to_owned()
        };
        assert_eq!(
            named("sip:alice@192.0.2.10:40000"),
            "sip:alice@df7jal23ls0d.invalid;transport=ws"
        );
        assert_eq!(
            named("sip:alice@192.0.2.10:40000;ob?X-Hint=1"),
            "sip:alice@df7jal23ls0d.invalid;transport=ws;ob?X-Hint=1"
        );
        assert_eq!(
            named("sip:alice@192.0.2.10;Transport=WS;ob"),
            "sip:alice@df7jal23ls0d.invalid;Transport=WS;ob"
        );
        assert!(
            contact_on_name(&uri("tel:+15551234567"), "x.invalid", TransportProtocol::Ws).is_none()
        );
    }

    fn at(text: &str) -> SocketAddr {
        text.parse().expect("an address")
    }

    #[test]
    fn a_contact_moves_to_the_public_address_and_keeps_everything_else() {
        let contact = uri("sip:alice@192.168.1.10:5060;transport=udp;ob?X-Hint=1");
        let moved = contact_at(&contact, at("203.0.113.7:41000")).expect("a sip URI");
        assert_eq!(
            moved.as_str(),
            "sip:alice@203.0.113.7:41000;transport=udp;ob?X-Hint=1"
        );
    }

    #[test]
    fn a_contact_with_no_user_part_or_port_moves_too() {
        let moved = contact_at(&uri("sip:192.168.1.10"), at("203.0.113.7:5062")).expect("sip");
        assert_eq!(moved.as_str(), "sip:203.0.113.7:5062");
        let moved = contact_at(
            &uri("sips:bob@[2001:db8::1]:5061"),
            at("[2001:db8::9]:6000"),
        )
        .expect("sips");
        assert_eq!(moved.as_str(), "sips:bob@[2001:db8::9]:6000");
    }

    #[test]
    fn a_contact_for_an_arrival_names_the_address_and_how_it_was_reached() {
        let cases = [
            (
                "192.0.2.1:5060",
                TransportProtocol::Udp,
                "<sip:192.0.2.1:5060>",
            ),
            (
                "192.0.2.1:5060",
                TransportProtocol::Tcp,
                "<sip:192.0.2.1:5060;transport=tcp>",
            ),
            (
                "[2001:db8::1]:5061",
                TransportProtocol::Tls,
                "<sip:[2001:db8::1]:5061;transport=tls>",
            ),
            (
                "192.0.2.1:8443",
                TransportProtocol::Wss,
                "<sip:192.0.2.1:8443;transport=wss>",
            ),
        ];
        for (address, protocol, expected) in cases {
            let written = contact_for_arrival(at(address), protocol);
            assert_eq!(
                String::from_utf8_lossy(&written),
                expected,
                "{address} over {protocol:?}"
            );
            // and it reads back as the URI it says it is
            let inner = written
                .get(1..written.len() - 1)
                .expect("the brackets are there");
            assert!(Uri::parse(inner).is_ok(), "{expected}");
        }
    }

    #[test]
    fn a_uri_that_is_not_sip_is_not_rewritten() {
        assert!(contact_at(&uri("tel:+15551234567"), at("203.0.113.7:5060")).is_none());
    }

    #[test]
    fn a_contact_names_an_address_only_by_its_own_literal_and_port() {
        let local = at("192.168.1.10:5060");
        assert!(contact_names(&uri("sip:alice@192.168.1.10:5060"), local));
        assert!(
            contact_names(&uri("sip:alice@192.168.1.10"), local),
            "no port is the scheme's default, and 5060 is sip's"
        );
        assert!(!contact_names(&uri("sips:alice@192.168.1.10"), local));
        assert!(!contact_names(&uri("sip:alice@192.168.1.11:5060"), local));
        assert!(!contact_names(
            &uri("sip:alice@phone.example.com:5060"),
            local
        ));
        assert!(contact_names(
            &uri("sip:alice@[2001:db8::1]:5070"),
            at("[2001:db8::1]:5070")
        ));
    }
}
