// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The transports the caller has opened, and what the endpoint remembers
//! about each.
//!
//! Three things per transport, and each earns its place. The protocol,
//! because everything the RFCs make conditional on the transport is derived
//! from it. The local address, because that is what goes into `sent-by` and
//! the caller is the only one who knows which of its addresses the far end
//! can reach. And, on a byte stream, a framer: RFC 3261 §18.3 makes
//! `Content-Length` the only way to find where a message ends, and a read off
//! a socket has no relationship to a message boundary.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use super::transport::{Transmit, TransportId, TransportProtocol};
use crate::msg::{Limits, StreamFramer};
use crate::transaction::TimerHandle;

/// Where a message goes, and where it goes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Flow {
    /// The transport to write to.
    pub(crate) transport: TransportId,
    /// The address to write to. A connected transport has only one, and
    /// carries it anyway so that a log line says where a message went.
    pub(crate) destination: SocketAddr,
    /// The local address a request arrived on, for the responses that have to
    /// go back out of it (RFC 3581 §4). `None` on a flow we started.
    pub(crate) source: Option<SocketAddr>,
    /// What that transport speaks.
    pub(crate) protocol: TransportProtocol,
}

impl Flow {
    /// The bytes, addressed.
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
    /// What it speaks.
    pub(crate) protocol: TransportProtocol,
    /// The address to advertise as `sent-by`.
    pub(crate) local: SocketAddr,
    /// The far end, for a connection.
    pub(crate) remote: Option<SocketAddr>,
    /// Reassembly, on a byte stream only.
    pub(crate) framer: Option<StreamFramer>,
    /// The keep-alive scheduled for this connection, so that losing the
    /// connection can take its deadline down with it rather than leaving one
    /// to fire on a transport that is gone.
    pub(crate) keepalive: Option<TimerHandle>,
    /// When the pong for a ping already sent stops being late and starts
    /// meaning the flow is dead (RFC 5626 §4.4.1). Armed by the ping, cancelled
    /// by the answer.
    pub(crate) pong: Option<TimerHandle>,
    /// Whether the far end has answered a ping on this connection at least
    /// once. RFC 5626 §4.4: a UA that did not register with outbound "cannot
    /// expect a CRLF in response (a \"pong\") unless the UA has an explicit
    /// indication that CRLF keep-alives are supported", and a pong already
    /// received is that indication. Until then the pings go (RFC 3261 §7.5
    /// allows them on any stream) and no deadline hangs on their answer.
    pub(crate) answers_pings: bool,
}

/// Every transport the caller has told the endpoint about.
#[derive(Debug, Default)]
pub(crate) struct Transports {
    /// Ordered rather than hashed, so that "any transport speaking TCP"
    /// answers with the same one twice running and a test can assert on it.
    open: BTreeMap<TransportId, Bound>,
}

impl Transports {
    /// An endpoint with no transports yet.
    pub(crate) const fn new() -> Self {
        Self {
            open: BTreeMap::new(),
        }
    }

    /// Take a transport the caller has opened.
    ///
    /// Binding an identifier that is already in use replaces what was there:
    /// the caller has reused the name, and the bytes half-read on the old
    /// connection belong to a connection that is gone.
    ///
    /// The entry that was replaced is handed back rather than dropped. It
    /// carries the keep-alive and pong timer handles of the connection that
    /// is gone, and only the caller holds the schedule they were hung on.
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
                framer: protocol
                    .is_stream()
                    .then(|| StreamFramer::with_limits(limits)),
                keepalive: None,
                pong: None,
                answers_pings: false,
            },
        )
    }

    /// Forget a transport that has closed or failed.
    pub(crate) fn unbind(&mut self, transport: TransportId) -> Option<Bound> {
        self.open.remove(&transport)
    }

    /// The local address of the open transport with the lowest number.
    pub(crate) fn any_local(&self) -> Option<SocketAddr> {
        self.open.values().next().map(|bound| bound.local)
    }

    /// What is known about a transport.
    pub(crate) fn get(&self, transport: TransportId) -> Option<&Bound> {
        self.open.get(&transport)
    }

    /// What is known about a transport, mutably.
    pub(crate) fn get_mut(&mut self, transport: TransportId) -> Option<&mut Bound> {
        self.open.get_mut(&transport)
    }

    /// A transport speaking `protocol` that can carry a message to
    /// `destination`, if the caller has opened one.
    ///
    /// Used for the §18.1.1 switch away from a datagram: a request that has
    /// grown too large has to leave over something congestion controlled, and
    /// this is where the endpoint finds out whether it can.
    ///
    /// The destination is part of the question, not a filter applied to the
    /// answer. A byte stream is connected, so one bound to a different far
    /// end cannot carry this; picking a transport first and rejecting it
    /// afterwards would report that nothing speaks the protocol whenever some
    /// other connection happened to be opened earlier, and a caller that
    /// opens what is asked for would then be asked for it again, forever. An
    /// unconnected stream transport (`remote` is `None`) can reach anywhere.
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

    /// Every open transport that needs a keep-alive timer, which is every
    /// byte stream (RFC 5626 §4.4.1: "MUST only be used with connection
    /// oriented transports").
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
        // one message per datagram, so there is nothing to reassemble
        let mut table = Transports::new();
        bind(&mut table, 1, TransportProtocol::Udp);
        bind(&mut table, 2, TransportProtocol::Tcp);
        assert!(table.get(TransportId(1)).unwrap().framer.is_none());
        assert!(table.get(TransportId(2)).unwrap().framer.is_some());
    }

    #[test]
    fn a_websocket_transport_gets_no_framer_either() {
        // RFC 7118 4.2 puts exactly one SIP message in each WebSocket message
        let mut table = Transports::new();
        bind(&mut table, 1, TransportProtocol::Wss);
        assert!(table.get(TransportId(1)).unwrap().framer.is_none());
    }

    #[test]
    fn binding_the_same_name_twice_replaces_what_was_there() {
        // the caller reused the identifier, so the bytes half-read on the old
        // connection belong to a connection that no longer exists
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

        // and what was there comes back, because it owns the two timer
        // handles and only the driver holds the schedule they are on
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
        // neither is connected, so either would carry this; the same one
        // twice running, so a test can assert on it
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
        // The failure this guards against is not theoretical: one connected
        // stream to a registrar used to hide every other stream, because the
        // lowest id was picked first and only then measured against the
        // destination. A request to anyone else then reported that nothing
        // speaks TCP, however many connections were open, and a caller that
        // opened what was asked for was asked for it again.
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
