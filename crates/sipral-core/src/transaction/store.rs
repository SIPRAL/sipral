// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The store that owns the four machines.
//!
//! Until now each machine existed on its own: a caller fed it a message and
//! read back what it wanted done. This is what holds them — one arena per
//! kind, so a handle is typed by machine and a slot is never shared between
//! two of them, plus the two indexes of RFC 3261 §17.1.3 and §17.2.3 that turn
//! an arriving message into the transaction it belongs to.
//!
//! Each transaction also remembers its flow: which transport, to what address,
//! over what protocol. §18.2.2 requires exactly that of a server — "this
//! requires the server transport to maintain an association between server
//! transactions and transport connections" — and a client needs it for the
//! same reason, so that a retransmission goes back out where the original
//! went.
//!
//! Deadlines are not indexed. Every other timer in this stack is set once and
//! fires once, and lives in a [`super::timer::Timers`] queue; a transaction's
//! deadline moves on nearly every message it sees, so an index would spend
//! more time being cancelled and rebuilt than it would ever save. What is
//! scanned is the live transactions of one endpoint, which for a user agent is
//! tens.

use std::collections::HashMap;
use std::time::Instant;

use super::effect::Effects;
use super::handle::{
    AnyTransactionId, InviteClient, InviteServer, NonInviteClient, NonInviteServer, TransactionId,
};
use super::invite_client::InviteClientMachine;
use super::invite_server::InviteServerMachine;
use super::matching::{ClientKey, ServerKey};
use super::non_invite_client::NonInviteClientMachine;
use super::non_invite_server::NonInviteServerMachine;
use super::slab::Slab;
use super::timer::TimerConfig;
use crate::endpoint::{Flow, TransportId};
use crate::msg::{HeaderError, OwnedMessage, RawMessage};

/// A transaction we started: the machine, where its messages go, and the key
/// it is indexed by. The machine owns the request, since it is the thing that
/// retransmits it.
#[derive(Debug)]
pub(crate) struct ClientEntry<M> {
    /// The state machine.
    pub(crate) machine: M,
    /// Where this transaction's messages go.
    pub(crate) flow: Flow,
    key: ClientKey,
}

/// A transaction somebody else started.
///
/// The request is kept here rather than in the machine because this is the
/// side that has to answer it: every response is built from the request per
/// §8.2.6.2, and the user may send several.
#[derive(Debug)]
pub(crate) struct ServerEntry<M> {
    /// The state machine.
    pub(crate) machine: M,
    /// Where the responses go (§18.2.2, RFC 3581 §4).
    pub(crate) flow: Flow,
    /// The request that created it.
    pub(crate) request: OwnedMessage,
    key: ServerKey,
}

/// A client transaction, whichever machine it runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Client {
    /// An INVITE client transaction.
    Invite(TransactionId<InviteClient>),
    /// A non-INVITE client transaction.
    NonInvite(TransactionId<NonInviteClient>),
}

/// A server transaction, whichever machine it runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Server {
    /// An INVITE server transaction.
    Invite(TransactionId<InviteServer>),
    /// A non-INVITE server transaction.
    NonInvite(TransactionId<NonInviteServer>),
}

impl From<Client> for AnyTransactionId {
    fn from(client: Client) -> Self {
        match client {
            Client::Invite(id) => Self::InviteClient(id),
            Client::NonInvite(id) => Self::NonInviteClient(id),
        }
    }
}

impl From<Server> for AnyTransactionId {
    fn from(server: Server) -> Self {
        match server {
            Server::Invite(id) => Self::InviteServer(id),
            Server::NonInvite(id) => Self::NonInviteServer(id),
        }
    }
}

/// Every live transaction of one endpoint.
#[derive(Debug)]
pub(crate) struct Transactions {
    invite_clients: Slab<ClientEntry<InviteClientMachine>>,
    non_invite_clients: Slab<ClientEntry<NonInviteClientMachine>>,
    invite_servers: Slab<ServerEntry<InviteServerMachine>>,
    non_invite_servers: Slab<ServerEntry<NonInviteServerMachine>>,
    clients: HashMap<ClientKey, Client>,
    servers: HashMap<ServerKey, Server>,
}

impl Transactions {
    /// An endpoint with nothing in flight.
    pub(crate) fn new() -> Self {
        Self {
            invite_clients: Slab::new(),
            non_invite_clients: Slab::new(),
            invite_servers: Slab::new(),
            non_invite_servers: Slab::new(),
            clients: HashMap::new(),
            servers: HashMap::new(),
        }
    }

    /// How many transactions are live, over all four kinds.
    pub(crate) fn len(&self) -> usize {
        self.invite_clients.len()
            + self.non_invite_clients.len()
            + self.invite_servers.len()
            + self.non_invite_servers.len()
    }

    /// How many of them somebody else started, which is the half a peer
    /// decides the size of.
    pub(crate) fn servers_len(&self) -> usize {
        self.invite_servers.len() + self.non_invite_servers.len()
    }

    /// Send an INVITE.
    ///
    /// # Errors
    /// [`HeaderError`] when the request has no `Via` branch to be keyed on.
    pub(crate) fn start_invite_client(
        &mut self,
        request: OwnedMessage,
        flow: Flow,
        config: TimerConfig,
        now: Instant,
    ) -> Result<(TransactionId<InviteClient>, Effects), HeaderError> {
        let key = ClientKey::for_request(&request.as_raw())?;
        let (machine, effects) =
            InviteClientMachine::start(request, flow.protocol.is_reliable(), config, now);
        let raw = self.invite_clients.insert(ClientEntry {
            machine,
            flow,
            key: key.clone(),
        });
        let id = TransactionId::new(raw);
        self.clients.insert(key, Client::Invite(id));
        Ok((id, effects))
    }

    /// Send a request that is not an INVITE.
    ///
    /// # Errors
    /// [`HeaderError`] when the request has no `Via` branch to be keyed on.
    pub(crate) fn start_non_invite_client(
        &mut self,
        request: OwnedMessage,
        flow: Flow,
        config: TimerConfig,
        now: Instant,
    ) -> Result<(TransactionId<NonInviteClient>, Effects), HeaderError> {
        let key = ClientKey::for_request(&request.as_raw())?;
        let (machine, effects) =
            NonInviteClientMachine::start(request, flow.protocol.is_reliable(), config, now);
        let raw = self.non_invite_clients.insert(ClientEntry {
            machine,
            flow,
            key: key.clone(),
        });
        let id = TransactionId::new(raw);
        self.clients.insert(key, Client::NonInvite(id));
        Ok((id, effects))
    }

    /// Take an INVITE that arrived. The 100 Trying comes back in the effects.
    ///
    /// # Errors
    /// [`HeaderError`] when a field the §17.2.3 key is built from is missing.
    pub(crate) fn start_invite_server(
        &mut self,
        request: &RawMessage<'_>,
        flow: Flow,
        config: TimerConfig,
        now: Instant,
    ) -> Result<(TransactionId<InviteServer>, Effects), HeaderError> {
        let key = ServerKey::for_request(request)?;
        let (machine, effects) =
            InviteServerMachine::start(request, flow.protocol.is_reliable(), config, now);
        let raw = self.invite_servers.insert(ServerEntry {
            machine,
            flow,
            request: request.to_owned(),
            key: key.clone(),
        });
        let id = TransactionId::new(raw);
        self.servers.insert(key, Server::Invite(id));
        Ok((id, effects))
    }

    /// Take a request that is not an INVITE. Nothing goes out: what to answer
    /// is the user's decision.
    ///
    /// # Errors
    /// [`HeaderError`] when a field the §17.2.3 key is built from is missing.
    pub(crate) fn start_non_invite_server(
        &mut self,
        request: &RawMessage<'_>,
        flow: Flow,
        config: TimerConfig,
    ) -> Result<TransactionId<NonInviteServer>, HeaderError> {
        let key = ServerKey::for_request(request)?;
        let machine = NonInviteServerMachine::start(flow.protocol.is_reliable(), config);
        let raw = self.non_invite_servers.insert(ServerEntry {
            machine,
            flow,
            request: request.to_owned(),
            key: key.clone(),
        });
        let id = TransactionId::new(raw);
        self.servers.insert(key, Server::NonInvite(id));
        Ok(id)
    }

    /// The client transaction a response belongs to (§17.1.3).
    pub(crate) fn client_for(&self, response: &RawMessage<'_>) -> Option<Client> {
        let key = ClientKey::for_response(response).ok()?;
        self.clients.get(&key).copied()
    }

    /// The server transaction a request belongs to (§17.2.3).
    ///
    /// An ACK is keyed as the INVITE it answers, which is what puts it on the
    /// transaction that sent the response being acknowledged.
    pub(crate) fn server_for(&self, request: &RawMessage<'_>) -> Option<Server> {
        let key = ServerKey::for_request(request).ok()?;
        self.servers.get(&key).copied()
    }

    /// Every transaction with a deadline at or before `now`, in no particular
    /// order. Cleared and refilled, so the caller can keep one buffer.
    pub(crate) fn due(&self, now: Instant, out: &mut Vec<AnyTransactionId>) {
        out.clear();
        for (raw, entry) in self.invite_clients.iter() {
            if entry.machine.next_deadline().is_some_and(|at| at <= now) {
                out.push(AnyTransactionId::InviteClient(TransactionId::new(raw)));
            }
        }
        for (raw, entry) in self.non_invite_clients.iter() {
            if entry.machine.next_deadline().is_some_and(|at| at <= now) {
                out.push(AnyTransactionId::NonInviteClient(TransactionId::new(raw)));
            }
        }
        for (raw, entry) in self.invite_servers.iter() {
            if entry.machine.next_deadline().is_some_and(|at| at <= now) {
                out.push(AnyTransactionId::InviteServer(TransactionId::new(raw)));
            }
        }
        for (raw, entry) in self.non_invite_servers.iter() {
            if entry.machine.next_deadline().is_some_and(|at| at <= now) {
                out.push(AnyTransactionId::NonInviteServer(TransactionId::new(raw)));
            }
        }
    }

    /// The server transaction indexed under this key, if there is one.
    ///
    /// Used for the one lookup that is not a message's own key: §9.2 matches
    /// a CANCEL to the INVITE it cancels.
    pub(crate) fn server_by_key(&self, key: &ServerKey) -> Option<Server> {
        self.servers.get(key).copied()
    }

    /// Every transaction whose messages went out over `transport`.
    pub(crate) fn on_transport(&self, transport: TransportId, out: &mut Vec<AnyTransactionId>) {
        out.clear();
        for (raw, entry) in self.invite_clients.iter() {
            if entry.flow.transport == transport {
                out.push(AnyTransactionId::InviteClient(TransactionId::new(raw)));
            }
        }
        for (raw, entry) in self.non_invite_clients.iter() {
            if entry.flow.transport == transport {
                out.push(AnyTransactionId::NonInviteClient(TransactionId::new(raw)));
            }
        }
        for (raw, entry) in self.invite_servers.iter() {
            if entry.flow.transport == transport {
                out.push(AnyTransactionId::InviteServer(TransactionId::new(raw)));
            }
        }
        for (raw, entry) in self.non_invite_servers.iter() {
            if entry.flow.transport == transport {
                out.push(AnyTransactionId::NonInviteServer(TransactionId::new(raw)));
            }
        }
    }

    /// When something in here next needs the clock.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        let clients = self
            .invite_clients
            .iter()
            .filter_map(|(_, entry)| entry.machine.next_deadline());
        let non_invite_clients = self
            .non_invite_clients
            .iter()
            .filter_map(|(_, entry)| entry.machine.next_deadline());
        let servers = self
            .invite_servers
            .iter()
            .filter_map(|(_, entry)| entry.machine.next_deadline());
        let non_invite_servers = self
            .non_invite_servers
            .iter()
            .filter_map(|(_, entry)| entry.machine.next_deadline());
        clients
            .chain(non_invite_clients)
            .chain(servers)
            .chain(non_invite_servers)
            .min()
    }
}

/// The four arenas, reached by typed handle.
///
/// Written as a macro because the four are the same code with four types in
/// it, and four hand-written copies would drift the moment one of them gained
/// a line.
macro_rules! access {
    ($($get:ident, $get_mut:ident, $drop:ident => $slab:ident, $entry:ident, $machine:ty, $kind:ty, $index:ident;)*) => {
        impl Transactions {
            $(
                /// The transaction, if this handle is still the one that slot
                /// answers to.
                pub(crate) fn $get(&self, id: TransactionId<$kind>) -> Option<&$entry<$machine>> {
                    self.$slab.get(id.raw)
                }

                /// The transaction, mutably.
                pub(crate) fn $get_mut(
                    &mut self,
                    id: TransactionId<$kind>,
                ) -> Option<&mut $entry<$machine>> {
                    self.$slab.get_mut(id.raw)
                }

                /// Retire the transaction and its index entry.
                ///
                /// The generation advances, so every copy of the handle stops
                /// matching — including the one a late retransmission is
                /// holding.
                pub(crate) fn $drop(&mut self, id: TransactionId<$kind>) {
                    if let Some(entry) = self.$slab.remove(id.raw) {
                        self.$index.remove(&entry.key);
                    }
                }
            )*
        }
    };
}

access! {
    invite_client, invite_client_mut, drop_invite_client
        => invite_clients, ClientEntry, InviteClientMachine, InviteClient, clients;
    non_invite_client, non_invite_client_mut, drop_non_invite_client
        => non_invite_clients, ClientEntry, NonInviteClientMachine, NonInviteClient, clients;
    invite_server, invite_server_mut, drop_invite_server
        => invite_servers, ServerEntry, InviteServerMachine, InviteServer, servers;
    non_invite_server, non_invite_server_mut, drop_non_invite_server
        => non_invite_servers, ServerEntry, NonInviteServerMachine, NonInviteServer, servers;
}

#[cfg(test)]
mod tests {
    use super::{Client, Server, Transactions};
    use crate::endpoint::{Flow, TransportId, TransportProtocol};
    use crate::msg::{
        Method, OwnedMessage, ParseMode, ParseScratch, RequestBuilder, ResponseBuilder, StatusCode,
        parse,
    };
    use crate::transaction::{AnyTransactionId, NonInviteClientState, TimerConfig};
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    fn flow(transport: u32) -> Flow {
        Flow {
            transport: TransportId(transport),
            destination: "192.0.2.9:5060".parse::<SocketAddr>().unwrap(),
            source: None,
            protocol: TransportProtocol::Udp,
        }
    }

    fn request(method: Method<'_>, branch: &[u8]) -> OwnedMessage {
        let via = {
            let mut value = b"SIP/2.0/UDP 192.0.2.1:5060;branch=".to_vec();
            value.extend_from_slice(branch);
            value
        };
        RequestBuilder::new(method, b"sip:bob@example.com")
            .via(&via)
            .from(b"<sip:alice@example.com>;tag=1")
            .to(b"<sip:bob@example.com>")
            .call_id(b"a84b4c76e66710")
            .cseq(1)
            .max_forwards(70)
            .build()
            .unwrap()
    }

    fn response_to(request: &OwnedMessage, status: u16) -> OwnedMessage {
        let raw = request.as_raw();
        ResponseBuilder::for_request(&raw, StatusCode::new(status).unwrap())
            .to_tag(b"remote")
            .build()
            .unwrap()
    }

    fn with<T>(message: &OwnedMessage, f: impl FnOnce(&crate::msg::RawMessage<'_>) -> T) -> T {
        let mut scratch = ParseScratch::new();
        let bytes = message.bytes();
        let parsed = parse(&bytes, &mut scratch, ParseMode::Lenient).unwrap();
        f(&parsed)
    }

    #[test]
    fn a_response_finds_the_transaction_that_sent_the_request() {
        let mut store = Transactions::new();
        let now = Instant::now();
        let options = request(Method::Options, b"z9hG4bK1");
        let (id, effects) = store
            .start_non_invite_client(options.clone(), flow(1), TimerConfig::DEFAULT, now)
            .unwrap();
        assert!(effects.send.is_some(), "the request should have gone out");

        let ok = response_to(&options, 200);
        let found = with(&ok, |raw| store.client_for(raw));
        assert_eq!(found, Some(Client::NonInvite(id)));
    }

    #[test]
    fn a_response_for_a_branch_nobody_sent_finds_nothing() {
        let mut store = Transactions::new();
        let now = Instant::now();
        let sent = request(Method::Options, b"z9hG4bK1");
        store
            .start_non_invite_client(sent, flow(1), TimerConfig::DEFAULT, now)
            .unwrap();

        let stray = response_to(&request(Method::Options, b"z9hG4bK9"), 200);
        assert_eq!(with(&stray, |raw| store.client_for(raw)), None);
    }

    #[test]
    fn an_invite_and_its_cancel_are_two_transactions_on_one_branch() {
        // 17.1.3: the CSeq method is in the key because a CANCEL borrows the
        // branch of the request it cancels
        let mut store = Transactions::new();
        let now = Instant::now();
        let invite = request(Method::Invite, b"z9hG4bK1");
        let cancel = request(Method::Cancel, b"z9hG4bK1");
        let (invite_id, _) = store
            .start_invite_client(invite.clone(), flow(1), TimerConfig::DEFAULT, now)
            .unwrap();
        let (cancel_id, _) = store
            .start_non_invite_client(cancel.clone(), flow(1), TimerConfig::DEFAULT, now)
            .unwrap();

        let for_invite = response_to(&invite, 180);
        let for_cancel = response_to(&cancel, 200);
        assert_eq!(
            with(&for_invite, |raw| store.client_for(raw)),
            Some(Client::Invite(invite_id))
        );
        assert_eq!(
            with(&for_cancel, |raw| store.client_for(raw)),
            Some(Client::NonInvite(cancel_id))
        );
    }

    #[test]
    fn a_retired_handle_answers_to_nothing_and_takes_its_index_entry_with_it() {
        let mut store = Transactions::new();
        let now = Instant::now();
        let options = request(Method::Options, b"z9hG4bK1");
        let (id, _) = store
            .start_non_invite_client(options.clone(), flow(1), TimerConfig::DEFAULT, now)
            .unwrap();
        assert_eq!(store.len(), 1);

        store.drop_non_invite_client(id);
        assert_eq!(store.len(), 0);
        assert!(store.non_invite_client(id).is_none());
        let ok = response_to(&options, 200);
        assert_eq!(with(&ok, |raw| store.client_for(raw)), None);
    }

    #[test]
    fn an_arriving_request_finds_its_server_transaction_and_an_ack_finds_the_invite() {
        let mut store = Transactions::new();
        let now = Instant::now();
        let invite = request(Method::Invite, b"z9hG4bK1");
        let id = with(&invite, |raw| {
            store
                .start_invite_server(raw, flow(1), TimerConfig::DEFAULT, now)
                .unwrap()
                .0
        });

        assert_eq!(
            with(&invite, |raw| store.server_for(raw)),
            Some(Server::Invite(id))
        );
        // an ACK is keyed as the INVITE it answers
        let ack = request(Method::Ack, b"z9hG4bK1");
        assert_eq!(
            with(&ack, |raw| store.server_for(raw)),
            Some(Server::Invite(id))
        );
    }

    #[test]
    fn the_earliest_deadline_of_all_four_arenas_is_the_one_reported() {
        let mut store = Transactions::new();
        let now = Instant::now();
        let slow = TimerConfig {
            t1: Duration::from_secs(1),
            ..TimerConfig::DEFAULT
        };
        let fast = TimerConfig {
            t1: Duration::from_millis(10),
            ..TimerConfig::DEFAULT
        };
        store
            .start_non_invite_client(request(Method::Options, b"z9hG4bK1"), flow(1), slow, now)
            .unwrap();
        store
            .start_invite_client(request(Method::Invite, b"z9hG4bK2"), flow(1), fast, now)
            .unwrap();

        // timer A on the second one, at 10 ms, beats timer E on the first
        assert_eq!(store.next_deadline(), Some(now + Duration::from_millis(10)));
    }

    #[test]
    fn nothing_is_due_before_its_deadline() {
        let mut store = Transactions::new();
        let now = Instant::now();
        let (id, _) = store
            .start_non_invite_client(
                request(Method::Options, b"z9hG4bK1"),
                flow(1),
                TimerConfig::DEFAULT,
                now,
            )
            .unwrap();

        let mut due = Vec::new();
        store.due(now, &mut due);
        assert!(due.is_empty());
        store.due(now + Duration::from_millis(500), &mut due);
        assert_eq!(due, vec![AnyTransactionId::NonInviteClient(id)]);
    }

    #[test]
    fn a_failed_transport_finds_everything_that_went_out_over_it() {
        let mut store = Transactions::new();
        let now = Instant::now();
        let (first, _) = store
            .start_non_invite_client(
                request(Method::Options, b"z9hG4bK1"),
                flow(1),
                TimerConfig::DEFAULT,
                now,
            )
            .unwrap();
        store
            .start_non_invite_client(
                request(Method::Options, b"z9hG4bK2"),
                flow(2),
                TimerConfig::DEFAULT,
                now,
            )
            .unwrap();

        let mut hit = Vec::new();
        store.on_transport(TransportId(1), &mut hit);
        assert_eq!(hit, vec![AnyTransactionId::NonInviteClient(first)]);
    }

    #[test]
    fn the_machine_reached_through_a_handle_is_the_one_that_was_started() {
        let mut store = Transactions::new();
        let now = Instant::now();
        let (id, _) = store
            .start_non_invite_client(
                request(Method::Options, b"z9hG4bK1"),
                flow(7),
                TimerConfig::DEFAULT,
                now,
            )
            .unwrap();

        let entry = store.non_invite_client(id).unwrap();
        assert_eq!(entry.machine.state(), NonInviteClientState::Trying);
        assert_eq!(entry.flow, flow(7));
    }

    #[test]
    fn a_request_with_no_branch_cannot_be_keyed_and_is_refused() {
        let mut store = Transactions::new();
        let now = Instant::now();
        let no_branch = RequestBuilder::new(Method::Options, b"sip:bob@example.com")
            .via(b"SIP/2.0/UDP 192.0.2.1:5060")
            .from(b"<sip:alice@example.com>;tag=1")
            .to(b"<sip:bob@example.com>")
            .call_id(b"a84b4c76e66710")
            .cseq(1)
            .max_forwards(70)
            .build()
            .unwrap();
        assert!(
            store
                .start_non_invite_client(no_branch, flow(1), TimerConfig::DEFAULT, now)
                .is_err()
        );
        assert_eq!(store.len(), 0);
    }
}
