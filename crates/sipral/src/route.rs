// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Which of this machine's addresses a peer can reach it at.
//!
//! A socket bound to the wildcard address has no address to advertise, and
//! one bound to `127.0.0.1` has one nobody else can use. The address a
//! `Contact` and a `c=` line should carry is the one the operating system
//! sends from toward the peer: the address of the interface its route leaves
//! on. [`route_to`] asks for exactly that, the way every platform allows
//! without privileges: a UDP socket, connected to the peer — which for a
//! datagram socket sends nothing, and only fixes the destination, so the
//! kernel picks the route and the source address (RFC 1122 §3.3.4.3 has the
//! source chosen from the outgoing interface) — then asked for its own
//! address, and closed.
//!
//! It is the one call in this crate that touches a socket, and it touches
//! nothing the application owns: the socket is its own, bound to an
//! ephemeral port and dropped before it returns. [`advertised_address`] is
//! the policy on top: a wildcard bind takes the route's address, a loopback
//! bind is refused toward anything that is not loopback, and nothing is ever
//! silently advertised on loopback to a peer on another machine — the user
//! agent refuses that too, where it writes the address
//! (`sipral_ua::advertise`).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

/// Why [`advertised_address`] has no address to give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdvertiseError {
    /// The socket is bound to a loopback address, or the only route to the
    /// peer leaves on one, and the peer is not a loopback address: whatever
    /// this end advertised, the peer could not reach it. Bind to the address
    /// of the interface that routes to the peer, or to the wildcard address
    /// and let [`advertised_address`] find it.
    Loopback {
        /// The address that would have been advertised.
        local: IpAddr,
        /// The peer it would have been advertised to.
        peer: IpAddr,
    },
    /// The operating system has no route to the peer at all.
    NoRoute(io::ErrorKind),
}

impl core::fmt::Display for AdvertiseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Loopback { local, peer } => write!(
                f,
                "{local} is a loopback address {peer} cannot reach this end at: bind to the \
                 address of the interface that routes to it"
            ),
            Self::NoRoute(kind) => write!(f, "no route to the peer: {kind}"),
        }
    }
}

impl core::error::Error for AdvertiseError {}

/// The local address the operating system sends from toward `peer`, found
/// without sending anything.
///
/// # Errors
/// Whatever the operating system says when it has no route to `peer`, or
/// cannot open a datagram socket of `peer`'s family.
pub fn route_to(peer: SocketAddr) -> io::Result<IpAddr> {
    let wildcard: IpAddr = match peer {
        SocketAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        SocketAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    let socket = UdpSocket::bind(SocketAddr::new(wildcard, 0))?;
    socket.connect(peer)?;
    Ok(socket.local_addr()?.ip())
}

/// The address to advertise, in a `Contact` or a `c=` line, for a socket
/// bound at `bound` whose traffic goes to `peer`.
///
/// A socket bound to a specific address advertises it, unless it is a
/// loopback address and `peer` is not. A socket bound to the wildcard
/// address advertises the address of the route toward `peer`
/// ([`route_to`]), with its own port. `peer` is the registrar for the
/// signalling socket and the far end, or the registrar when the far end is
/// not known yet, for a media socket.
///
/// # Errors
/// [`AdvertiseError::Loopback`] when the address would be a loopback one and
/// `peer` is not; [`AdvertiseError::NoRoute`] when there is no route to
/// `peer` to take an address from.
pub fn advertised_address(
    bound: SocketAddr,
    peer: SocketAddr,
) -> Result<SocketAddr, AdvertiseError> {
    advertised_with(bound, peer, route_to)
}

/// [`advertised_address`], with the route lookup handed in.
fn advertised_with(
    bound: SocketAddr,
    peer: SocketAddr,
    route: impl FnOnce(SocketAddr) -> io::Result<IpAddr>,
) -> Result<SocketAddr, AdvertiseError> {
    // an IPv4-mapped IPv6 address is read as the IPv4 address it carries
    let local = if bound.ip().to_canonical().is_unspecified() {
        route(peer).map_err(|error| AdvertiseError::NoRoute(error.kind()))?
    } else {
        bound.ip()
    };
    if local.to_canonical().is_loopback() && !peer.ip().to_canonical().is_loopback() {
        return Err(AdvertiseError::Loopback {
            local,
            peer: peer.ip(),
        });
    }
    Ok(SocketAddr::new(local, bound.port()))
}

#[cfg(test)]
mod tests {
    use super::{AdvertiseError, advertised_address, advertised_with, route_to};
    use std::io;
    use std::net::{IpAddr, SocketAddr};

    fn at(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn the_route_to_a_loopback_peer_leaves_on_loopback_and_sends_nothing() {
        // a peer that is listening would see a datagram if one went
        let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            route_to(listener.local_addr().unwrap()).unwrap(),
            ip("127.0.0.1")
        );
        let mut buffer = [0_u8; 16];
        assert_eq!(
            listener
                .recv_from(&mut buffer)
                .map_err(|error| error.kind())
                .err(),
            Some(io::ErrorKind::WouldBlock),
            "nothing arrived"
        );
        assert_eq!(
            advertised_address(at("0.0.0.0:5060"), listener.local_addr().unwrap()),
            Ok(at("127.0.0.1:5060"))
        );
    }

    #[test]
    fn a_wildcard_bind_advertises_the_address_of_the_route_toward_the_peer() {
        let advertised = advertised_with(at("0.0.0.0:5070"), at("192.0.2.9:5060"), |peer| {
            assert_eq!(peer, at("192.0.2.9:5060"));
            Ok(ip("198.51.100.23"))
        });
        assert_eq!(advertised, Ok(at("198.51.100.23:5070")));
    }

    #[test]
    fn loopback_is_never_advertised_to_a_peer_on_another_machine() {
        // the trial: bindHost left at its default, a silent call
        assert_eq!(
            advertised_address(at("127.0.0.1:5060"), at("192.0.2.9:5060")),
            Err(AdvertiseError::Loopback {
                local: ip("127.0.0.1"),
                peer: ip("192.0.2.9"),
            })
        );
        // a machine whose only route is loopback has nothing to advertise
        assert_eq!(
            advertised_with(at("0.0.0.0:5060"), at("192.0.2.9:5060"), |_| Ok(ip(
                "127.0.0.1"
            ))),
            Err(AdvertiseError::Loopback {
                local: ip("127.0.0.1"),
                peer: ip("192.0.2.9"),
            })
        );
        assert_eq!(
            advertised_with(at("[::]:5060"), at("[2001:db8::9]:5060"), |_| Err(
                io::ErrorKind::NetworkUnreachable.into()
            )),
            Err(AdvertiseError::NoRoute(io::ErrorKind::NetworkUnreachable))
        );
    }

    /// A dual-stack socket writes an IPv4 address mapped into IPv6:
    /// `::ffff:127.0.0.1` is loopback, whichever side it is on.
    #[test]
    fn an_ipv4_mapped_loopback_is_loopback_on_either_side() {
        assert_eq!(
            advertised_address(at("[::ffff:127.0.0.1]:5060"), at("192.0.2.9:5060")),
            Err(AdvertiseError::Loopback {
                local: ip("::ffff:127.0.0.1"),
                peer: ip("192.0.2.9"),
            })
        );
        assert_eq!(
            advertised_address(at("127.0.0.1:5060"), at("[::ffff:127.0.0.1]:5060")),
            Ok(at("127.0.0.1:5060"))
        );
    }

    #[test]
    fn a_specific_address_is_advertised_as_bound() {
        assert_eq!(
            advertised_address(at("192.0.2.1:5060"), at("192.0.2.9:5060")),
            Ok(at("192.0.2.1:5060"))
        );
        assert_eq!(
            advertised_address(at("127.0.0.1:5060"), at("127.0.0.1:5080")),
            Ok(at("127.0.0.1:5060"))
        );
    }
}
