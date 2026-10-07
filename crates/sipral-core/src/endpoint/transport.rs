// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What a transport is to a stack that never opens one.
//!
//! The socket belongs to the caller. A transport here is an identifier, a
//! protocol and two addresses. Reliability decides which timers exist
//! (RFC 3261 §17); framing decides how bytes become messages (§18.3).
//!
//! WebSocket frames hold one message each (RFC 7118 §4.2), so they are fed in
//! as datagrams. The WebSocket itself lives in `sipral_ua::websocket`, which
//! names the `.invalid` host with [`super::Endpoint::advertise_name`].

use core::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::msg::HostRef;

/// A transport the caller opened, named by the caller.
///
/// The number is never interpreted here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransportId(pub u32);

impl fmt::Display for TransportId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transport {}", self.0)
    }
}

/// How bytes get to the far end.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum TransportProtocol {
    /// RFC 3261 §18. One message per datagram, and everything retransmits.
    Udp,
    /// A byte stream framed on `Content-Length` (§18.3).
    Tcp,
    /// TLS over TCP.
    Tls,
    /// RFC 7118 over a plain WebSocket. One message per frame.
    Ws,
    /// RFC 7118 over a WebSocket on TLS.
    Wss,
}

impl TransportProtocol {
    /// The `sent-protocol` transport token, as it is written in a `Via`.
    ///
    /// Upper case, as in RFC 3261 §25.1 and RFC 7118 §5.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Tls => "TLS",
            Self::Ws => "WS",
            Self::Wss => "WSS",
        }
    }

    /// Read a transport token, from a `Via` or from a URI's `transport`
    /// parameter.
    ///
    /// Case-insensitive (§7.3.1).
    #[must_use]
    pub fn from_token(token: &[u8]) -> Option<Self> {
        [Self::Udp, Self::Tcp, Self::Tls, Self::Ws, Self::Wss]
            .into_iter()
            .find(|candidate| token.eq_ignore_ascii_case(candidate.as_str().as_bytes()))
    }

    /// Whether the transport delivers for us, so nothing retransmits
    /// (RFC 3261 §17 timers A, D, E, G, I, J, K).
    #[must_use]
    pub const fn is_reliable(self) -> bool {
        !matches!(self, Self::Udp)
    }

    /// Whether messages arrive as a byte stream that has to be framed on
    /// `Content-Length` (§18.3).
    ///
    /// False for WebSocket, which is already framed (RFC 7118 §4.2).
    #[must_use]
    pub const fn is_stream(self) -> bool {
        matches!(self, Self::Tcp | Self::Tls)
    }

    /// Whether the transport is the one a `sips:` URI asks for.
    #[must_use]
    pub const fn is_secure(self) -> bool {
        matches!(self, Self::Tls | Self::Wss)
    }

    /// The port to use when a URI or a `sent-by` gives none.
    ///
    /// RFC 3261 §18.1.1. None for WebSocket.
    #[must_use]
    pub const fn default_port(self) -> Option<u16> {
        match self {
            Self::Udp | Self::Tcp => Some(5060),
            Self::Tls => Some(5061),
            Self::Ws | Self::Wss => None,
        }
    }
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A host, kept rather than borrowed.
///
/// The caller resolves names (RFC 3263), so a host outlives its message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Host {
    /// A domain name, in the case it was written in.
    Name(Arc<str>),
    /// A literal address, which needs no resolving.
    Ip(IpAddr),
}

impl Host {
    /// Keep a host that was parsed out of a message.
    #[must_use]
    pub fn from_ref(host: HostRef<'_>) -> Self {
        match host {
            HostRef::Name(name) => Self::Name(Arc::from(name)),
            HostRef::Ipv4(addr) => Self::Ip(IpAddr::V4(addr)),
            HostRef::Ipv6(addr) => Self::Ip(IpAddr::V6(addr)),
        }
    }

    /// The address, when the host is a literal one.
    #[must_use]
    pub const fn ip(&self) -> Option<IpAddr> {
        match *self {
            Self::Ip(addr) => Some(addr),
            Self::Name(_) => None,
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Name(ref name) => f.write_str(name),
            Self::Ip(IpAddr::V4(addr)) => write!(f, "{addr}"),
            // brackets everywhere but a Via's `received` (§19.1.1)
            Self::Ip(IpAddr::V6(addr)) => write!(f, "[{addr}]"),
        }
    }
}

/// Something that happened to a transport, on its way in.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Input<'a> {
    /// One message in one packet. Also how a WebSocket frame is fed in.
    ///
    /// The response goes out from `local` (RFC 3581 §4).
    Datagram {
        /// Which transport it came in on.
        transport: TransportId,
        /// Where it came from.
        remote: SocketAddr,
        /// Where it arrived.
        local: SocketAddr,
        /// The packet, whole.
        data: &'a [u8],
    },
    /// Bytes off a stream transport, in any chunking (§18.3).
    StreamData {
        /// Which connection they came in on.
        transport: TransportId,
        /// The bytes, not necessarily a whole message and possibly several.
        data: &'a [u8],
    },
    /// The far end closed, or the connection broke after it had been open.
    StreamClosed {
        /// Which connection.
        transport: TransportId,
    },
    /// A transport is open and may be written to.
    ///
    /// `local` goes into the `Via`, so a wildcard bind must name a reachable
    /// address here.
    TransportBound {
        /// The name the caller will use for it from now on.
        transport: TransportId,
        /// What it speaks.
        protocol: TransportProtocol,
        /// The address to advertise as `sent-by`.
        local: SocketAddr,
        /// The far end, for a connection.
        remote: Option<SocketAddr>,
    },
    /// A transport failed, and whatever was written to it did not arrive.
    TransportFailed {
        /// Which transport.
        transport: TransportId,
        /// What went wrong, in as much detail as the caller has.
        error: TransportErrorKind,
    },
}

impl Input<'_> {
    /// Which transport this is about.
    #[must_use]
    pub const fn transport(&self) -> TransportId {
        match *self {
            Self::Datagram { transport, .. }
            | Self::StreamData { transport, .. }
            | Self::StreamClosed { transport }
            | Self::TransportBound { transport, .. }
            | Self::TransportFailed { transport, .. } => transport,
        }
    }
}

/// Bytes the caller has to put on a transport.
///
/// The payload is shared because a retransmission is the identical datagram
/// (§17.1.1.2).
#[derive(Clone, Debug)]
pub struct Transmit {
    /// Which transport to write to.
    pub transport: TransportId,
    /// Where to send it. A connected transport ignores it.
    pub destination: SocketAddr,
    /// Which of the transport's local addresses to send from, when it has
    /// more than one.
    ///
    /// Set for responses (RFC 3581 §4); `None` means the transport's own.
    pub source: Option<SocketAddr>,
    /// The bytes.
    pub payload: Arc<[u8]>,
    /// What the transport speaks; may differ after the §18.1.1 switch.
    pub protocol: TransportProtocol,
}

/// Why a transport could not deliver.
///
/// Coarse on purpose: the reaction is the same for all (RFC 3261 §17).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportErrorKind {
    /// Nothing is listening at the far end.
    ConnectionRefused,
    /// An established connection was reset.
    ConnectionReset,
    /// No route, or an ICMP unreachable.
    Unreachable,
    /// The connection attempt or the write timed out.
    TimedOut,
    /// The connection was closed and cannot be written to again.
    Closed,
    /// Anything else the caller could not classify.
    Other,
}

impl fmt::Display for TransportErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::ConnectionRefused => "connection refused",
            Self::ConnectionReset => "connection reset",
            Self::Unreachable => "destination unreachable",
            Self::TimedOut => "timed out",
            Self::Closed => "connection closed",
            Self::Other => "transport error",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Host, Input, TransportErrorKind, TransportId, TransportProtocol};
    use crate::msg::HostRef;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    const fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port)
    }

    #[test]
    fn a_transport_is_named_by_whoever_opened_it() {
        assert_eq!(TransportId(4).to_string(), "transport 4");
        assert!(TransportId(1) < TransportId(2));
    }

    #[test]
    fn the_transport_tokens_are_the_ones_that_go_into_a_via() {
        assert_eq!(TransportProtocol::Udp.as_str(), "UDP");
        assert_eq!(TransportProtocol::Tls.to_string(), "TLS");
        assert_eq!(TransportProtocol::Wss.as_str(), "WSS");
    }

    #[test]
    fn a_transport_token_is_read_in_any_case() {
        assert_eq!(
            TransportProtocol::from_token(b"udp"),
            Some(TransportProtocol::Udp)
        );
        assert_eq!(
            TransportProtocol::from_token(b"TCP"),
            Some(TransportProtocol::Tcp)
        );
        assert_eq!(
            TransportProtocol::from_token(b"WsS"),
            Some(TransportProtocol::Wss)
        );
        assert_eq!(TransportProtocol::from_token(b"sctp"), None);
        assert_eq!(TransportProtocol::from_token(b""), None);
    }

    #[test]
    fn reliability_is_what_the_timers_are_keyed_on() {
        assert!(!TransportProtocol::Udp.is_reliable());
        for reliable in [
            TransportProtocol::Tcp,
            TransportProtocol::Tls,
            TransportProtocol::Ws,
            TransportProtocol::Wss,
        ] {
            assert!(reliable.is_reliable(), "{reliable} should be reliable");
        }
    }

    #[test]
    fn only_tcp_and_tls_need_framing() {
        // RFC 7118 §4.2: one SIP message per WebSocket message
        assert!(TransportProtocol::Tcp.is_stream());
        assert!(TransportProtocol::Tls.is_stream());
        assert!(!TransportProtocol::Udp.is_stream());
        assert!(!TransportProtocol::Ws.is_stream());
        assert!(!TransportProtocol::Wss.is_stream());
    }

    #[test]
    fn the_secure_transports_are_the_ones_a_sips_uri_asks_for() {
        assert!(TransportProtocol::Tls.is_secure());
        assert!(TransportProtocol::Wss.is_secure());
        assert!(!TransportProtocol::Tcp.is_secure());
        assert!(!TransportProtocol::Ws.is_secure());
    }

    #[test]
    fn the_default_ports_are_the_ones_in_18_1_1_and_websocket_has_none() {
        assert_eq!(TransportProtocol::Udp.default_port(), Some(5060));
        assert_eq!(TransportProtocol::Tcp.default_port(), Some(5060));
        assert_eq!(TransportProtocol::Tls.default_port(), Some(5061));
        assert_eq!(TransportProtocol::Ws.default_port(), None);
        assert_eq!(TransportProtocol::Wss.default_port(), None);
    }

    #[test]
    fn a_host_kept_from_a_message_writes_itself_back_the_way_it_arrived() {
        assert_eq!(
            Host::from_ref(HostRef::Name("Biloxi.example.com")).to_string(),
            "Biloxi.example.com"
        );
        assert_eq!(
            Host::from_ref(HostRef::Ipv4(Ipv4Addr::new(192, 0, 2, 4))).to_string(),
            "192.0.2.4"
        );
        assert_eq!(
            Host::from_ref(HostRef::Ipv6(Ipv6Addr::LOCALHOST)).to_string(),
            "[::1]"
        );
    }

    #[test]
    fn a_literal_host_needs_no_resolving_and_a_name_does() {
        assert_eq!(
            Host::from_ref(HostRef::Ipv4(Ipv4Addr::new(192, 0, 2, 4))).ip(),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4)))
        );
        assert_eq!(Host::from_ref(HostRef::Name("example.com")).ip(), None);
    }

    #[test]
    fn every_input_says_which_transport_it_is_about() {
        let cases = [
            Input::Datagram {
                transport: TransportId(1),
                remote: addr(5060),
                local: addr(5061),
                data: b"",
            },
            Input::StreamData {
                transport: TransportId(2),
                data: b"",
            },
            Input::StreamClosed {
                transport: TransportId(3),
            },
            Input::TransportBound {
                transport: TransportId(4),
                protocol: TransportProtocol::Tcp,
                local: addr(5060),
                remote: None,
            },
            Input::TransportFailed {
                transport: TransportId(5),
                error: TransportErrorKind::ConnectionReset,
            },
        ];
        for (expected, input) in (1..).zip(cases.iter()) {
            assert_eq!(input.transport(), TransportId(expected));
        }
    }

    #[test]
    fn a_transport_error_reads_as_a_sentence() {
        assert_eq!(
            TransportErrorKind::ConnectionRefused.to_string(),
            "connection refused"
        );
        assert_eq!(TransportErrorKind::Other.to_string(), "transport error");
    }
}
