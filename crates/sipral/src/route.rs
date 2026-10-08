// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Which of this machine's addresses a peer can reach it at.
//!
//! A wildcard bind has no address to advertise, and `127.0.0.1` is useless to others. `Contact` and
//! `c=` should carry the address the OS sends from toward the peer. [`route_to`] finds it without
//! privileges: it connects a UDP socket to the peer (which sends nothing for a datagram socket,
//! only fixes the route and source address, RFC 1122 §3.3.4.3), reads its local address, and closes
//! it.
//!
//! The only socket this crate touches, and it is its own, on an ephemeral port, dropped before
//! returning. [`advertised_address`] adds the policy: a wildcard bind takes the route's address, a
//! loopback bind is refused toward a non-loopback peer, and loopback is never silently advertised
//! to another machine (the user agent also refuses it, in `sipral_ua::advertise`).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

/// Why [`advertised_address`] has no address to give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdvertiseError {
    /// The bind address, or the only route to the peer, is loopback while the peer is not, so the
    /// peer could not reach anything advertised. Bind to the interface that routes to the peer, or
    /// to the wildcard and let [`advertised_address`] find it.
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
/// A connected socket can still report the wildcard as its local address: on macOS under load,
/// roughly one connect in 1,500 does. That answer names no interface, so the route is asked
/// again on a fresh socket, up to eight times.
///
/// # Errors
/// Whatever the operating system says when it has no route to `peer`, or
/// cannot open a datagram socket of `peer`'s family; [`io::ErrorKind::AddrNotAvailable`] when
/// every answer was the wildcard.
pub fn route_to(peer: SocketAddr) -> io::Result<IpAddr> {
    let wildcard: IpAddr = match peer {
        SocketAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        SocketAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    settled(|| {
        let socket = UdpSocket::bind(SocketAddr::new(wildcard, 0))?;
        socket.connect(peer)?;
        Ok(socket.local_addr()?.ip())
    })
}

/// How many times [`route_to`] asks before giving up on a wildcard answer.
const ROUTE_ASKS: usize = 8;

/// The first answer from `ask` that names an address; an error from `ask` ends the asking.
fn settled(mut ask: impl FnMut() -> io::Result<IpAddr>) -> io::Result<IpAddr> {
    for _ in 0..ROUTE_ASKS {
        let local = ask()?;
        if !local.to_canonical().is_unspecified() {
            return Ok(local);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "the route's source address stayed unspecified",
    ))
}

/// The address to advertise in `Contact` or `c=` for a socket bound at `bound` talking to `peer`.
///
/// A specific bind advertises itself, unless it is loopback and `peer` is not. A wildcard bind
/// advertises the route's address toward `peer` ([`route_to`]) with its own port. `peer` is the
/// registrar for the signalling socket, and the far end (or the registrar if unknown) for a media
/// socket.
///
/// # Errors
///
/// [`AdvertiseError::Loopback`] when the address would be loopback and `peer` is not;
/// [`AdvertiseError::NoRoute`] when there is no route to `peer`.
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
    use super::{
        AdvertiseError, ROUTE_ASKS, advertised_address, advertised_with, route_to, settled,
    };
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
        // a listening peer would see any datagram sent
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

    /// Seen on macOS under load: a connected socket reporting `0.0.0.0` as its local address. It
    /// was advertised as is, in `Contact` and `c=`, and an ICE agent refused it as a host.
    #[test]
    fn a_wildcard_answer_from_the_route_is_asked_again() {
        let mut answers = vec![ip("0.0.0.0"), ip("::"), ip("198.51.100.23")].into_iter();
        let mut asked = 0;
        let settled_on = settled(|| {
            asked += 1;
            Ok(answers.next().unwrap())
        });
        assert_eq!(settled_on.unwrap(), ip("198.51.100.23"));
        assert_eq!(asked, 3);

        let mut asked = 0;
        let never = settled(|| {
            asked += 1;
            Ok(ip("::ffff:0.0.0.0"))
        });
        assert_eq!(
            never.map_err(|error| error.kind()),
            Err(io::ErrorKind::AddrNotAvailable)
        );
        assert_eq!(asked, ROUTE_ASKS);

        let mut asked = 0;
        let refused = settled(|| {
            asked += 1;
            Err(io::ErrorKind::NetworkUnreachable.into())
        });
        assert_eq!(
            refused.map_err(|error| error.kind()),
            Err(io::ErrorKind::NetworkUnreachable)
        );
        assert_eq!(asked, 1, "no route is an answer, not a wildcard");
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
        // the trial: bindHost left at its default gave a silent call
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

    /// A dual-stack socket reports IPv4 as mapped IPv6: `::ffff:127.0.0.1` is loopback on either
    /// side.
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
