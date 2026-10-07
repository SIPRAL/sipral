// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The transports the caller has opened: protocol, local address (for
//! `sent-by`), and on a byte stream a framer, since RFC 3261 §18.3 makes
//! `Content-Length` the only message boundary.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use super::transport::{Transmit, TransportId, TransportProtocol};
use crate::msg::{Limits, StreamFramer};
use crate::transaction::TimerHandle;

/// Where a message goes, and where it goes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Flow {
    pub(crate) transport: TransportId,
    /// The address to write to, kept on connected transports too for logging.
    pub(crate) destination: SocketAddr,
    /// The local address a request arrived on, for responses that must leave
    /// from it (RFC 3581 §4). `None` on a flow we started.
    pub(crate) source: Option<SocketAddr>,
    pub(crate) protocol: TransportProtocol,
}

impl Flow {
    pub(crate) fn transmit(&self, payload: Arc<[u8]>) -> Transmit {
        Transmit {
            transport: self.transport,
            destination: self.destination,
            source: self.source,
            payload,
            protocol: self.protocol,
        }
    }
}

/// One open transport.
#[derive(Debug)]
pub(crate) struct Bound {
    pub(crate) protocol: TransportProtocol,
    /// The address to advertise as `sent-by`.
    pub(crate) local: SocketAddr,
    pub(crate) remote: Option<SocketAddr>,
    /// A `sent-by` name overriding `local`, such as a WebSocket `.invalid` host
    /// (RFC 7118 Appendix B.1). Cleared by every bind.
    pub(crate) sent_by: Option<Box<str>>,
    pub(crate) framer: Option<StreamFramer>,
    /// The keep-alive deadline, cancelled when the connection goes.
    pub(crate) keepalive: Option<TimerHandle>,
    /// Pong deadline after a ping (RFC 5626 §4.4.1).
    pub(crate) pong: Option<TimerHandle>,
    /// Whether the far end has answered a ping at least once. RFC 5626 §4.4:
    /// without outbound, only a pong already seen justifies expecting one.
    /// Until then pings still go (RFC 3261 §7.5) with no deadline.
    pub(crate) answers_pings: bool,
}

/// Every transport the caller has told the endpoint about.
#[derive(Debug, Default)]
pub(crate) struct Transports {
    /// Ordered, so "any TCP transport" is deterministic.
    open: BTreeMap<TransportId, Bound>,
}

impl Transports {
    pub(crate) const fn new() -> Self {
        Self {
            open: BTreeMap::new(),
        }
    }

    /// Take a transport the caller has opened. Reusing an id replaces the entry,
    /// which is returned because it owns timer handles only the caller can cancel.
    #[must_use = "the entry that was replaced owns the keepalive and pong timer handles"]
    pub(crate) fn bind(
        &mut self,
        transport: TransportId,
        protocol: TransportProtocol,
        local: SocketAddr,
        remote: Option<SocketAddr>,
        limits: Limits,
    ) -> Option<Bound> {
        self.open.insert(
            transport,
            Bound {
                protocol,
                local,
                remote,
                sent_by: None,
                framer: protocol
                    .is_stream()
                    .then(|| StreamFramer::with_limits(limits)),
                keepalive: None,
                pong: None,
                answers_pings: false,
            },
        )
    }

    pub(crate) fn unbind(&mut self, transport: TransportId) -> Option<Bound> {
        self.open.remove(&transport)
    }

    /// The local address of the open transport with the lowest number.
    pub(crate) fn any_local(&self) -> Option<SocketAddr> {
        self.open.values().next().map(|bound| bound.local)
    }

    pub(crate) fn get(&self, transport: TransportId) -> Option<&Bound> {
        self.open.get(&transport)
    }

    pub(crate) fn get_mut(&mut self, transport: TransportId) -> Option<&mut Bound> {
        self.open.get_mut(&transport)
    }

    /// A transport speaking `protocol` that can reach `destination` (used for
    /// the §18.1.1 switch to a stream). The destination is part of the search:
    /// a connected stream to another peer cannot carry this, and filtering after
    /// picking would keep asking the caller for a transport it already opened.
    pub(crate) fn speaking_to(
        &self,
        protocol: TransportProtocol,
        destination: SocketAddr,
    ) -> Option<TransportId> {
        self.open
            .iter()
            .find(|(_, bound)| {
                bound.protocol == protocol
                    && bound.remote.is_none_or(|remote| remote == destination)
            })
            .map(|(id, _)| *id)
    }

    /// Every byte stream still lacking a keep-alive timer (RFC 5626 §4.4.1:
    /// connection-oriented only).
    pub(crate) fn streams_without_keepalive(&self) -> Vec<TransportId> {
        self.open
            .iter()
            .filter(|(_, bound)| bound.protocol.is_stream() && bound.keepalive.is_none())
            .map(|(id, _)| *id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{Bound, TransportId, TransportProtocol, Transports};
    use crate::msg::Limits;
    use crate::transaction::Timers;
    use std::net::SocketAddr;
    use std::time::Instant;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn bind(table: &mut Transports, id: u32, protocol: TransportProtocol) -> Option<Bound> {
        table.bind(
            TransportId(id),
            protocol,
            addr("192.0.2.1:5060"),
            None,
            Limits::DEFAULT,
        )
    }

    #[test]
    fn a_datagram_transport_gets_no_framer_and_a_stream_does() {
        let mut table = Transports::new();
        bind(&mut table, 1, TransportProtocol::Udp);
        bind(&mut table, 2, TransportProtocol::Tcp);
        assert!(table.get(TransportId(1)).unwrap().framer.is_none());
        assert!(table.get(TransportId(2)).unwrap().framer.is_some());
    }

    #[test]
    fn a_websocket_transport_gets_no_framer_either() {
        // RFC 7118 §4.2: one SIP message per WebSocket message
        let mut table = Transports::new();
        bind(&mut table, 1, TransportProtocol::Wss);
        assert!(table.get(TransportId(1)).unwrap().framer.is_none());
    }

    #[test]
    fn binding_the_same_name_twice_replaces_what_was_there() {
        let mut table = Transports::new();
        bind(&mut table, 1, TransportProtocol::Tcp);
        table
            .get_mut(TransportId(1))
            .unwrap()
            .framer
            .as_mut()
            .unwrap()
            .push(b"INVITE sip:")
            .unwrap();
        assert_eq!(
            table
                .get(TransportId(1))
                .unwrap()
                .framer
                .as_ref()
                .unwrap()
                .pending(),
            11
        );

        // the replaced entry comes back with its timer handles
        let mut timers = Timers::<()>::new();
        let armed = timers.schedule(Instant::now(), ());
        table.get_mut(TransportId(1)).unwrap().pong = Some(armed);
        let replaced = bind(&mut table, 1, TransportProtocol::Tcp).expect("what was there");
        assert_eq!(replaced.pong, Some(armed));
        assert_eq!(
            table
                .get(TransportId(1))
                .unwrap()
                .framer
                .as_ref()
                .unwrap()
                .pending(),
            0
        );
        assert_eq!(table.get(TransportId(1)).unwrap().pong, None);
    }

    #[test]
    fn a_transport_that_was_unbound_is_gone() {
        let mut table = Transports::new();
        bind(&mut table, 1, TransportProtocol::Udp);
        assert!(table.unbind(TransportId(1)).is_some());
        assert!(table.get(TransportId(1)).is_none());
        assert!(table.unbind(TransportId(1)).is_none());
    }

    #[test]
    fn the_switch_to_a_stream_asks_for_a_transport_that_speaks_one() {
        let mut table = Transports::new();
        let anywhere = addr("198.51.100.9:5060");
        bind(&mut table, 3, TransportProtocol::Udp);
        assert_eq!(table.speaking_to(TransportProtocol::Tcp, anywhere), None);
        bind(&mut table, 5, TransportProtocol::Tcp);
        bind(&mut table, 7, TransportProtocol::Tcp);
        assert_eq!(
            table.speaking_to(TransportProtocol::Tcp, anywhere),
            Some(TransportId(5))
        );
        assert_eq!(
            table.speaking_to(TransportProtocol::Tcp, anywhere),
            Some(TransportId(5))
        );
    }

    #[test]
    fn a_stream_connected_somewhere_else_is_not_the_one_to_use() {
        // regression: a stream connected to the registrar used to hide all others
        let mut table = Transports::new();
        let registrar = addr("198.51.100.9:5060");
        let far_end = addr("203.0.113.4:5060");
        assert!(
            table
                .bind(
                    TransportId(1),
                    TransportProtocol::Tcp,
                    addr("192.0.2.1:5060"),
                    Some(registrar),
                    Limits::DEFAULT,
                )
                .is_none(),
            "nothing was bound under this id yet"
        );
        assert_eq!(
            table.speaking_to(TransportProtocol::Tcp, registrar),
            Some(TransportId(1))
        );
        assert_eq!(table.speaking_to(TransportProtocol::Tcp, far_end), None);

        assert!(
            table
                .bind(
                    TransportId(2),
                    TransportProtocol::Tcp,
                    addr("192.0.2.1:5060"),
                    Some(far_end),
                    Limits::DEFAULT,
                )
                .is_none(),
            "nor under this one"
        );
        assert_eq!(
            table.speaking_to(TransportProtocol::Tcp, far_end),
            Some(TransportId(2))
        );
        assert_eq!(
            table.speaking_to(TransportProtocol::Tcp, registrar),
            Some(TransportId(1))
        );
    }

    #[test]
    fn only_byte_streams_are_offered_a_keepalive() {
        let mut table = Transports::new();
        bind(&mut table, 1, TransportProtocol::Udp);
        bind(&mut table, 2, TransportProtocol::Tcp);
        bind(&mut table, 3, TransportProtocol::Tls);
        assert_eq!(
            table.streams_without_keepalive(),
            vec![TransportId(2), TransportId(3)]
        );

        table.get_mut(TransportId(2)).unwrap().keepalive =
            Some(Timers::<()>::new().schedule(Instant::now(), ()));
        assert_eq!(table.streams_without_keepalive(), vec![TransportId(3)]);
    }
}
