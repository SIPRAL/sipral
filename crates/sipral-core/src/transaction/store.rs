// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The store that owns the four machines.
//!
//! One arena per kind, so handles are typed and slots never shared, plus the
//! two indexes of RFC 3261 §17.1.3 and §17.2.3 that map an arriving message to
//! its transaction.
//!
//! Each transaction remembers its flow (transport, address, protocol). §18.2.2
//! requires it of a server ("an association between server transactions and
//! transport connections"), and a client needs it so a retransmission leaves
//! where the original did.
//!
//! Deadlines are not indexed. A transaction's deadline moves on nearly every
//! message, so an index would cost more than it saves; one-shot timers live in
//! a [`super::timer::Timers`] queue instead. Finding the next deadline visits
//! each slot once, and `handle_timeout` sweeps at most twice. Vacated slots
//! are visited too (arenas never shrink), so the cost follows the peak number
//! of live transactions. `endpoint::store_tests` checks that bound with ten
//! thousand of them.

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
use crate::msg::{HeaderError, OwnedMessage, RawMessage, Uri};

/// A transaction we started: the machine (which owns and retransmits the
/// request), where its messages go, and its index key.
#[derive(Debug)]
pub(crate) struct ClientEntry<M> {
    /// The state machine.
    pub(crate) machine: M,
    /// Where this transaction's messages go.
    pub(crate) flow: Flow,
    /// How many times its request, or its ACK for a refusal, went out again.
    pub(crate) retransmitted: u32,
    key: ClientKey,
}

/// A transaction somebody else started.
///
/// The request is kept here, not in the machine, because every response is
/// built from it (§8.2.6.2) and the user may send several.
#[derive(Debug)]
pub(crate) struct ServerEntry<M> {
    /// The state machine.
    pub(crate) machine: M,
    /// Where the responses go (§18.2.2, RFC 3581 §4).
    pub(crate) flow: Flow,
    /// The request that created it.
    pub(crate) request: OwnedMessage,
    /// How many times a response it already sent has gone out again.
    pub(crate) retransmitted: u32,
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

/// §8.2.2.2's three fields: `From` tag (case-insensitive, §7.3.1), `Call-ID`
/// and `CSeq` number and method (as is, §20.8, §20.16). Every server
/// transaction is indexed by one, whatever its method.
type MergeKey = (Box<[u8]>, Box<[u8]>, u32, Box<[u8]>);

/// The key `request` would be found under in the merge index, when it carries
/// the fields one needs.
fn merge_key(request: &RawMessage<'_>) -> Option<MergeKey> {
    let from_tag = request.from().ok()?.tag()?;
    let call_id = request.call_id().ok()?;
    let cseq = request.cseq().ok()?;
    let lowered: Box<[u8]> = from_tag.iter().map(u8::to_ascii_lowercase).collect();
    Some((
        lowered,
        call_id.into(),
        cseq.seq,
        cseq.method.as_str().as_bytes().into(),
    ))
}

/// The line a request was sent to: its Request-URI as it arrived. Empty when
/// there is none; such a message never reaches the index.
fn line_of(request: &RawMessage<'_>) -> Box<[u8]> {
    request.request_uri_bytes().unwrap_or_default().into()
}

/// Whether two Request-URIs name the same line: same bytes, or equivalent per
/// RFC 3261 §19.1.4. An unparseable URI only matches its own bytes.
///
/// Only asked of transactions already sharing the merge key, usually one, so
/// the parse is cheap.
fn same_line(held: &[u8], arrived: &[u8]) -> bool {
    held == arrived
        || matches!(
            (Uri::parse(held), Uri::parse(arrived)),
            (Ok(held), Ok(arrived)) if held.equivalent(&arrived)
        )
}

/// Take `request`'s place in the merge index.
fn remember_merge_key(merge: &mut HashMap<MergeKey, Vec<Box<[u8]>>>, request: &RawMessage<'_>) {
    if let Some(key) = merge_key(request) {
        merge.entry(key).or_default().push(line_of(request));
    }
}

/// Give back the place `request` held in the merge index.
fn forget_merge_key(merge: &mut HashMap<MergeKey, Vec<Box<[u8]>>>, request: &OwnedMessage) {
    let raw = request.as_raw();
    let Some(key) = merge_key(&raw) else {
        return;
    };
    let line = line_of(&raw);
    if let Some(lines) = merge.get_mut(&key) {
        if let Some(at) = lines.iter().position(|held| *held == line) {
            lines.swap_remove(at);
        }
        if lines.is_empty() {
            merge.remove(&key);
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
    /// The Request-URI of every live server transaction, grouped by (`From`
    /// tag, `Call-ID`, `CSeq`): RFC 3261 §8.2.2.2's merged-request check. Not
    /// handles, since the check only asks whether one exists on this line.
    /// Shrunk by [`Transactions::release_invite_merge`] and
    /// [`Transactions::release_non_invite_merge`], so it is bounded like the
    /// server arenas.
    merge: HashMap<MergeKey, Vec<Box<[u8]>>>,
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
            merge: HashMap::new(),
        }
    }

    /// How many transactions are live, over all four kinds.
    pub(crate) fn len(&self) -> usize {
        self.invite_clients.len()
            + self.non_invite_clients.len()
            + self.invite_servers.len()
            + self.non_invite_servers.len()
    }

    /// How many of them somebody else started: the half a peer controls.
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
            retransmitted: 0,
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
            retransmitted: 0,
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
            retransmitted: 0,
            key: key.clone(),
        });
        let id = TransactionId::new(raw);
        self.servers.insert(key, Server::Invite(id));
        remember_merge_key(&mut self.merge, request);
        Ok((id, effects))
    }

    /// Take a request that is not an INVITE. Nothing goes out: the answer is
    /// the user's decision.
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
            retransmitted: 0,
            key: key.clone(),
        });
        let id = TransactionId::new(raw);
        self.servers.insert(key, Server::NonInvite(id));
        remember_merge_key(&mut self.merge, request);
        Ok(id)
    }

    /// Count one more retransmission against a transaction, if it is live.
    pub(crate) fn count_retransmission(&mut self, id: AnyTransactionId) {
        let counted = match id {
            AnyTransactionId::InviteClient(id) => self
                .invite_clients
                .get_mut(id.raw)
                .map(|entry| &mut entry.retransmitted),
            AnyTransactionId::NonInviteClient(id) => self
                .non_invite_clients
                .get_mut(id.raw)
                .map(|entry| &mut entry.retransmitted),
            AnyTransactionId::InviteServer(id) => self
                .invite_servers
                .get_mut(id.raw)
                .map(|entry| &mut entry.retransmitted),
            AnyTransactionId::NonInviteServer(id) => self
                .non_invite_servers
                .get_mut(id.raw)
                .map(|entry| &mut entry.retransmitted),
        };
        if let Some(counted) = counted {
            *counted = counted.saturating_add(1);
        }
    }

    /// How many retransmissions a live transaction has made.
    pub(crate) fn retransmissions(&self, id: AnyTransactionId) -> Option<u32> {
        match id {
            AnyTransactionId::InviteClient(id) => self
                .invite_clients
                .get(id.raw)
                .map(|entry| entry.retransmitted),
            AnyTransactionId::NonInviteClient(id) => self
                .non_invite_clients
                .get(id.raw)
                .map(|entry| entry.retransmitted),
            AnyTransactionId::InviteServer(id) => self
                .invite_servers
                .get(id.raw)
                .map(|entry| entry.retransmitted),
            AnyTransactionId::NonInviteServer(id) => self
                .non_invite_servers
                .get(id.raw)
                .map(|entry| entry.retransmitted),
        }
    }

    /// Whether a client transaction already runs under this request's key.
    ///
    /// The index holds one per key; a second would steal the first one's
    /// responses and leave it retransmitting until its timer gave up.
    pub(crate) fn has_client_for(&self, request: &RawMessage<'_>) -> bool {
        ClientKey::for_request(request).is_ok_and(|key| self.clients.contains_key(&key))
    }

    /// The client transaction a response belongs to (§17.1.3).
    pub(crate) fn client_for(&self, response: &RawMessage<'_>) -> Option<Client> {
        let key = ClientKey::for_response(response).ok()?;
        self.clients.get(&key).copied()
    }

    /// The server transaction a request belongs to (§17.2.3).
    ///
    /// An ACK is keyed as the INVITE it answers. A legacy ACK that finds
    /// nothing is looked up again with its To tag, where a re-INVITE would be
    /// ([`ServerKey::with_ack_to_tag`]).
    pub(crate) fn server_for(&self, request: &RawMessage<'_>) -> Option<Server> {
        let key = ServerKey::for_request(request).ok()?;
        if let Some(found) = self.servers.get(&key) {
            return Some(*found);
        }
        let tagged = key.with_ack_to_tag(request)?;
        self.servers.get(&tagged).copied()
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

    /// Whether `request` is a merged request (RFC 3261 §8.2.2.2): no To tag,
    /// and its From tag, `Call-ID` and `CSeq` already belong to a running
    /// server transaction under a branch that does not match it (§17.2.3),
    /// sent to the same line. Usually a fork arriving twice.
    ///
    /// The line is the Request-URI, compared by §19.1.4. One stack with
    /// several accounts is several UASes: a proxy forking to two of their
    /// contacts rewrites the Request-URI to each (§16.6), and each line is
    /// asked. Two copies to the same line: the second is refused.
    ///
    /// Called only after [`Transactions::server_for`] found nothing and before
    /// a transaction is created, so a hit is always a different transaction.
    /// A hash lookup, since every new request asks it.
    pub(crate) fn merged_with(&self, request: &RawMessage<'_>) -> bool {
        let untagged = request.to().is_ok_and(|to| to.tag().is_none());
        if !untagged {
            return false;
        }
        let Some(lines) = merge_key(request).and_then(|key| self.merge.get(&key)) else {
            return false;
        };
        let arrived = request.request_uri_bytes().unwrap_or_default();
        lines.iter().any(|held| same_line(held, arrived))
    }

    /// Give a retiring INVITE server transaction's §8.2.2.2 merge entry back.
    /// A no-op once the id no longer resolves, so call it before
    /// [`Transactions::drop_invite_server`].
    pub(crate) fn release_invite_merge(&mut self, id: TransactionId<InviteServer>) {
        if let Some(entry) = self.invite_servers.get(id.raw) {
            forget_merge_key(&mut self.merge, &entry.request);
        }
    }

    /// The same for a non-INVITE server transaction, called before
    /// [`Transactions::drop_non_invite_server`].
    pub(crate) fn release_non_invite_merge(&mut self, id: TransactionId<NonInviteServer>) {
        if let Some(entry) = self.non_invite_servers.get(id.raw) {
            forget_merge_key(&mut self.merge, &entry.request);
        }
    }

    /// The server transaction a CANCEL is aimed at (§9.2), if any.
    ///
    /// An INVITE is found through the index (the CANCEL's branch and sent-by,
    /// method taken as INVITE). Other methods are found by visiting the
    /// non-INVITE server slots, since the CANCEL does not name the method; the
    /// same cost as finding the next deadline.
    pub(crate) fn cancelled_by(&self, cancel: &RawMessage<'_>) -> Option<Server> {
        let key = ServerKey::for_cancelled(cancel).ok()?;
        if let Some(found) = self.servers.get(&key) {
            return Some(*found);
        }
        self.non_invite_servers
            .iter()
            .find(|(_, entry)| entry.key.is_cancelled_by(&key))
            .map(|(raw, _)| Server::NonInvite(TransactionId::new(raw)))
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

/// The four arenas, reached by typed handle. A macro so the four copies
/// cannot drift.
macro_rules! access {
    ($($get:ident, $get_mut:ident, $drop:ident => $slab:ident, $entry:ident, $machine:ty, $kind:ty, $index:ident;)*) => {
        impl Transactions {
            $(
                /// The transaction, if this handle still matches its slot.
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

                /// Retire the transaction and its index entry. Every copy of
                /// the handle stops matching.
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
        // 17.1.3: the CSeq method is in the key because a CANCEL shares the
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
    fn a_legacy_ack_finds_the_re_invite_it_acknowledges() {
        // §17.2.3 matches a legacy ACK by "the To tag of the response sent by
        // the server transaction", which for a re-INVITE is its own To tag
        let reinvite = b"INVITE sip:bob@192.0.2.9 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=0ae4be1c\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>;tag=bobs\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 2 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let ack = b"ACK sip:bob@192.0.2.9 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=0ae4be1c\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>;tag=bobs\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 2 ACK\r\n\
Content-Length: 0\r\n\
\r\n";
        let mut store = Transactions::new();
        let now = Instant::now();
        let mut scratch = ParseScratch::new();
        let parsed = parse(reinvite, &mut scratch, ParseMode::Strict).unwrap();
        let (id, _) = store
            .start_invite_server(&parsed, flow(1), TimerConfig::DEFAULT, now)
            .unwrap();

        let mut scratch = ParseScratch::new();
        let acked = parse(ack, &mut scratch, ParseMode::Strict).unwrap();
        assert_eq!(
            store.server_for(&acked),
            Some(Server::Invite(id)),
            "the ACK for a refused legacy re-INVITE has to reach its transaction, \
             or timer G retransmits the refusal until timer H"
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
