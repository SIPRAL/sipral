// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Never handing a far end an address it cannot reach.
//!
//! A socket bound to `127.0.0.1` would put loopback in `Contact` and `c=`:
//! the remote registrar accepts it, and then no request or audio ever
//! arrives, with no error.
//!
//! A loopback address (RFC 1122 §3.2.1.3 `127/8`, RFC 4291 §2.5.3 `::1`)
//! advertised to a non-loopback peer is refused with
//! [`UaError::UnreachableAddress`] before anything is sent; so is an
//! unspecified address in a `Contact`. Loopback-to-loopback is fine, and so is
//! `c=0.0.0.0` (the RFC 2543 hold).
//!
//! Advertise the interface toward the peer instead (`sipral::route_to`), or
//! the public address STUN found.

use std::net::{IpAddr, SocketAddr};

use sipral_core::msg::{HostRef, Uri};
use sipral_core::sdp::SessionDescription;

use crate::error::UaError;

/// Whether `advertised` reaches this end from `peer`: not when it is loopback
/// and the peer is not. IPv4-mapped IPv6 is read as IPv4 on either side.
fn loopback_to_elsewhere(advertised: IpAddr, peer: IpAddr) -> bool {
    advertised.to_canonical().is_loopback() && !peer.to_canonical().is_loopback()
}

/// The address a URI names, when its host is a literal one.
fn literal(uri: &Uri) -> Option<IpAddr> {
    match uri.sip()?.host {
        HostRef::Ipv4(address) => Some(IpAddr::V4(address)),
        HostRef::Ipv6(address) => Some(IpAddr::V6(address)),
        HostRef::Name(_) => None,
    }
}

/// Refuse a `Contact` naming `contact` that `peer` would be handed and could
/// not reach this end at.
///
/// # Errors
/// [`UaError::UnreachableAddress`].
pub(crate) fn check_contact(contact: &Uri, peer: SocketAddr) -> Result<(), UaError> {
    match literal(contact) {
        Some(advertised)
            if advertised.to_canonical().is_unspecified()
                || loopback_to_elsewhere(advertised, peer.ip()) =>
        {
            Err(UaError::UnreachableAddress {
                advertised,
                peer: peer.ip(),
            })
        }
        _ => Ok(()),
    }
}

/// [`check_contact`], for a `Contact` field value as it goes on the wire:
/// `<uri>;params`, or a bare URI.
///
/// # Errors
/// [`UaError::UnreachableAddress`].
pub(crate) fn check_contact_value(value: &[u8], peer: SocketAddr) -> Result<(), UaError> {
    let text = String::from_utf8_lossy(value);
    let inner = text
        .split_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .map_or(&*text, |(uri, _)| uri);
    match Uri::parse_str(inner.trim()) {
        Ok(uri) => check_contact(&uri, peer),
        Err(_) => Ok(()),
    }
}

/// Refuse a session description with a loopback connection address, at
/// session level or on any stream, that `peer` could not reach.
///
/// # Errors
/// [`UaError::UnreachableAddress`].
pub(crate) fn check_description(
    description: &SessionDescription,
    peer: SocketAddr,
) -> Result<(), UaError> {
    let addresses = description
        .connection
        .iter()
        .chain(
            description
                .media
                .iter()
                .filter_map(|media| media.connection.as_ref()),
        )
        .filter_map(sipral_core::sdp::Connection::ip);
    for advertised in addresses {
        if loopback_to_elsewhere(advertised, peer.ip()) {
            return Err(UaError::UnreachableAddress {
                advertised,
                peer: peer.ip(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{check_contact, check_contact_value, check_description};
    use crate::UaError;
    use sipral_core::msg::Uri;
    use sipral_core::sdp;
    use std::net::SocketAddr;

    fn uri(text: &str) -> Uri {
        Uri::parse_str(text).unwrap()
    }

    fn at(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn described(connection: &str) -> sdp::SessionDescription {
        let text = format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 {connection}\r\nt=0 0\r\n\
             m=audio 4000 RTP/AVP 0\r\n"
        );
        sdp::parse(text.as_bytes()).unwrap()
    }

    #[test]
    fn loopback_goes_only_to_loopback() {
        let pbx = at("192.0.2.9:5060");
        assert_eq!(
            check_contact(&uri("sip:alice@127.0.0.1:5060"), pbx),
            Err(UaError::UnreachableAddress {
                advertised: "127.0.0.1".parse().unwrap(),
                peer: pbx.ip(),
            })
        );
        assert!(check_contact(&uri("sip:alice@127.0.0.1:5060"), at("127.0.0.1:5060")).is_ok());
        assert!(check_contact(&uri("sip:alice@[::1]"), at("[2001:db8::9]:5060")).is_err());
        assert!(check_contact(&uri("sip:alice@0.0.0.0"), at("127.0.0.1:5060")).is_err());
        assert!(check_contact(&uri("sip:alice@192.0.2.1"), pbx).is_ok());
        assert!(check_contact(&uri("sip:alice@host.example.com"), pbx).is_ok());
        assert!(
            check_contact_value(b"<sip:alice@127.0.0.2:5062;ob>;+sip.instance=\"x\"", pbx).is_err()
        );
    }

    #[test]
    fn a_description_on_loopback_is_refused_and_an_old_hold_is_not() {
        let pbx = at("192.0.2.9:5060");
        assert!(check_description(&described("127.0.0.1"), pbx).is_err());
        assert!(check_description(&described("127.0.0.1"), at("127.0.0.1:5060")).is_ok());
        assert!(check_description(&described("0.0.0.0"), pbx).is_ok());
        assert!(check_description(&described("192.0.2.1"), pbx).is_ok());
    }

    /// `::ffff:127.0.0.1` is loopback, on either side.
    #[test]
    fn an_ipv4_mapped_loopback_is_loopback_on_either_side() {
        let pbx = at("192.0.2.9:5060");
        assert!(check_contact(&uri("sip:alice@[::ffff:127.0.0.1]:5060"), pbx).is_err());
        assert!(check_contact(&uri("sip:alice@[::ffff:0.0.0.0]"), pbx).is_err());
        assert!(
            check_contact(
                &uri("sip:alice@127.0.0.1:5060"),
                at("[::ffff:127.0.0.1]:5060")
            )
            .is_ok(),
            "a peer on this machine, reported by a dual-stack socket"
        );
        assert!(check_description(&described("127.0.0.1"), at("[::ffff:127.0.0.1]:5060")).is_ok());
        assert!(check_contact(&uri("sip:alice@[::ffff:192.0.2.1]"), pbx).is_ok());
    }

    use crate::event::{RegistrationFailure, UaEvent};
    use crate::tests::{
        OFFER, account, agent, deliver, events, incoming_invite, registrar, transmits,
    };
    use crate::{Account, OutgoingCall, TransportId};
    use std::sync::Arc;
    use std::time::Instant;

    const ON_LOOPBACK: &[u8] = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\n\
t=0 0\r\nm=audio 49170 RTP/AVP 0\r\n";

    fn on_loopback() -> Account {
        Account::new(
            uri("sip:alice@example.com"),
            uri("sip:example.com"),
            uri("sip:alice@127.0.0.1:5060"),
            TransportId(1),
            registrar(),
        )
    }

    #[test]
    fn a_register_with_a_loopback_contact_to_a_registrar_elsewhere_is_refused_unsent() {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(on_loopback());
        assert_eq!(
            agent.register(id, t0),
            Err(UaError::UnreachableAddress {
                advertised: "127.0.0.1".parse().unwrap(),
                peer: registrar().ip(),
            })
        );
        assert!(transmits(&mut agent).is_empty(), "nothing went");

        let fine = agent.add_account(account());
        agent
            .register(fine, t0)
            .expect("a routable contact registers");
    }

    #[test]
    fn a_register_released_by_a_lookup_stops_for_good_on_a_loopback_contact() {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(Account::located(
            uri("sip:alice@example.com"),
            uri("sip:192.0.2.9"),
            uri("sip:alice@127.0.0.1"),
            TransportId(1),
        ));
        agent
            .register(id, t0)
            .expect("waits for nothing: a numeric host");
        assert!(transmits(&mut agent).is_empty());
        let failed = events(&mut agent)
            .into_iter()
            .find_map(|event| match event {
                UaEvent::RegistrationFailed {
                    reason, retry_in, ..
                } => Some((reason, retry_in)),
                _ => None,
            });
        assert_eq!(
            failed,
            Some((RegistrationFailure::UnreachableContact, None))
        );
    }

    #[test]
    fn a_call_offering_loopback_media_to_a_peer_elsewhere_is_refused_unsent() {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(account());
        let outgoing = OutgoingCall::new(uri("sip:bob@example.com")).offer(Arc::from(ON_LOOPBACK));
        assert!(matches!(
            agent.call(id, &outgoing, t0),
            Err(UaError::UnreachableAddress { .. })
        ));
        assert!(transmits(&mut agent).is_empty());

        let loopback = agent.add_account(on_loopback());
        let plain = OutgoingCall::new(uri("sip:bob@example.com"));
        assert!(
            matches!(
                agent.call(loopback, &plain, t0),
                Err(UaError::UnreachableAddress { .. })
            ),
            "the Contact of the INVITE too"
        );
        assert!(transmits(&mut agent).is_empty());
    }

    #[test]
    fn an_answer_on_loopback_to_a_caller_elsewhere_is_refused_and_can_be_given_again() {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let _ = agent.add_account(account());
        deliver(&mut agent, &incoming_invite("lo1", Some(OFFER)), t0);
        let _ = transmits(&mut agent);
        let call = events(&mut agent)
            .into_iter()
            .find_map(|event| match event {
                UaEvent::IncomingCall { call, .. } => Some(call),
                _ => None,
            })
            .expect("a call");
        assert!(matches!(
            agent.ring(call, Some(Arc::from(ON_LOOPBACK)), t0),
            Err(UaError::UnreachableAddress { .. })
        ));
        assert!(matches!(
            agent.answer(call, Some(Arc::from(ON_LOOPBACK)), t0),
            Err(UaError::UnreachableAddress { .. })
        ));
        assert!(transmits(&mut agent).is_empty(), "no 183 and no 200");
        agent
            .answer(call, Some(Arc::from(OFFER)), t0)
            .expect("a routable answer goes");
        assert!(
            transmits(&mut agent)
                .iter()
                .any(|bytes| bytes.starts_with(b"SIP/2.0 200 "))
        );
    }
}
