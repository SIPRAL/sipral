// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! An in-memory network for driving agents against each other.
//!
//! NATs with the mapping and filtering behaviours RFC 4787 names, a STUN
//! server, a TURN server that relays by indication or by channel, a fixed
//! delay on every hop, loss drawn from a seeded generator, and a clock that
//! jumps straight to the next thing that is due. Nothing here is clever; it is
//! small enough to read, and thirty simulated seconds of consent checks cost a
//! few milliseconds.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::ice::{ComponentId, IceAgent, IceEvent, LiteAgent, Received, StreamId};
use crate::stun::address::decode_xor;
use crate::stun::{AttributeType, Class, Message, MessageBuilder, Method, TransactionId};
use crate::turn::{ChannelData, ChannelNumber, Transport, method};

pub(super) const STUN_SERVER: &str = "203.0.113.200:3478";
pub(super) const TURN_SERVER: &str = "203.0.113.201:3478";
const RELAY_IP: &str = "203.0.113.202";

pub(super) fn address(text: &str) -> SocketAddr {
    text.parse().expect("a socket address")
}

/// How a NAT picks the external port for an outbound packet (RFC 4787 §4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mapping {
    /// One external port per internal socket, whoever it talks to.
    EndpointIndependent,
    /// A new external port per destination address and port: the symmetric
    /// NAT.
    AddressAndPortDependent,
}

/// Which inbound packets a NAT lets through a mapping (RFC 4787 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Filtering {
    /// Only from an address the mapping has sent to.
    AddressDependent,
    /// Only from an address and port the mapping has sent to.
    AddressAndPortDependent,
}

struct Binding {
    internal: SocketAddr,
    external: u16,
    destination: Option<SocketAddr>,
    contacted: Vec<SocketAddr>,
}

struct Nat {
    public: IpAddr,
    mapping: Mapping,
    filtering: Filtering,
    bindings: Vec<Binding>,
    next_port: u16,
}

impl Nat {
    fn outbound(&mut self, internal: SocketAddr, destination: SocketAddr) -> SocketAddr {
        let mapping = self.mapping;
        let found = self.bindings.iter().position(|binding| {
            binding.internal == internal
                && (mapping == Mapping::EndpointIndependent
                    || binding.destination == Some(destination))
        });
        let index = found.unwrap_or_else(|| {
            self.bindings.push(Binding {
                internal,
                external: self.next_port,
                destination: Some(destination),
                contacted: Vec::new(),
            });
            self.next_port += 1;
            self.bindings.len() - 1
        });
        let binding = &mut self.bindings[index];
        if !binding.contacted.contains(&destination) {
            binding.contacted.push(destination);
        }
        SocketAddr::new(self.public, binding.external)
    }

    fn inbound(&self, port: u16, from: SocketAddr) -> Option<SocketAddr> {
        let binding = self
            .bindings
            .iter()
            .find(|binding| binding.external == port)?;
        let allowed = match self.filtering {
            Filtering::AddressDependent => {
                binding.contacted.iter().any(|seen| seen.ip() == from.ip())
            }
            Filtering::AddressAndPortDependent => binding.contacted.contains(&from),
        };
        allowed.then_some(binding.internal)
    }
}

/// A datagram between two transport addresses.
#[derive(Clone, Debug)]
pub(super) struct Packet {
    pub(super) source: SocketAddr,
    pub(super) destination: SocketAddr,
    pub(super) data: Vec<u8>,
}

/// A full agent on the network.
pub(super) struct Peer {
    pub(super) agent: IceAgent,
    pub(super) stream: StreamId,
    pub(super) sockets: Vec<SocketAddr>,
    nat: Option<usize>,
    seed: u8,
    next_id: u32,
    pub(super) events: Vec<(Instant, IceEvent)>,
    pub(super) received: Vec<Vec<u8>>,
}

impl Peer {
    /// Transaction ids as a caller would draw them: distinct, and different
    /// for every peer.
    pub(super) fn feed(&mut self) {
        while self.agent.transaction_ids_wanted() > 0 {
            self.next_id = self.next_id.wrapping_add(1);
            let mut bytes = [0_u8; 12];
            bytes[..4].copy_from_slice(&self.next_id.wrapping_mul(0x9e37_79b9).to_be_bytes());
            bytes[4] = self.seed;
            bytes[8..].copy_from_slice(&self.next_id.to_be_bytes());
            self.agent.supply_transaction_id(TransactionId::new(bytes));
        }
    }

    pub(super) fn saw(&self, wanted: impl Fn(&IceEvent) -> bool) -> bool {
        self.events.iter().any(|(_, event)| wanted(event))
    }

    pub(super) fn when(&self, wanted: impl Fn(&IceEvent) -> bool) -> Option<Instant> {
        self.events
            .iter()
            .find(|(_, event)| wanted(event))
            .map(|(at, _)| *at)
    }
}

/// A lite agent on a public address.
pub(super) struct LitePeer {
    pub(super) agent: LiteAgent,
    socket: SocketAddr,
    outbox: Vec<Packet>,
}

pub(super) enum Node {
    Full(Box<Peer>),
    Lite(LitePeer),
}

pub(super) struct RelayAllocation {
    client: SocketAddr,
    pub(super) relayed: SocketAddr,
    permissions: Vec<IpAddr>,
    pub(super) channels: Vec<(ChannelNumber, SocketAddr)>,
}

/// A TURN server that believes whoever asks: authentication is the TURN
/// client's own tests' business, and relaying is what this one is for.
pub(super) struct TurnRelay {
    address: SocketAddr,
    relay_ip: IpAddr,
    next_port: u16,
    next_id: u32,
    pub(super) allocations: Vec<RelayAllocation>,
}

impl TurnRelay {
    fn on_client(&mut self, from: SocketAddr, data: &[u8]) -> Vec<Packet> {
        if data
            .first()
            .is_some_and(|byte| (0x40..=0x4f).contains(byte))
        {
            return self.channel_from_client(from, data);
        }
        let Ok(message) = Message::parse(data) else {
            return Vec::new();
        };
        let id = message.transaction_id();
        let server = self.address;
        match (message.class(), message.method()) {
            (Class::Request, method::ALLOCATE) => self.allocate(from, &message),
            (Class::Request, method::REFRESH) => {
                let lifetime = message
                    .find(AttributeType::LIFETIME)
                    .and_then(|value| <[u8; 4]>::try_from(value).ok())
                    .map_or(600, u32::from_be_bytes);
                if lifetime == 0 {
                    self.allocations.retain(|entry| entry.client != from);
                }
                success(server, from, &message, |builder| {
                    builder.add_u32(AttributeType::LIFETIME, lifetime).unwrap();
                })
            }
            (Class::Request, method::CREATE_PERMISSION) => {
                let peers: Vec<IpAddr> = message
                    .find_all(AttributeType::XOR_PEER_ADDRESS)
                    .filter_map(|value| decode_xor(value, id))
                    .map(|peer| peer.ip())
                    .collect();
                if let Some(entry) = self.allocations.iter_mut().find(|e| e.client == from) {
                    for peer in peers {
                        if !entry.permissions.contains(&peer) {
                            entry.permissions.push(peer);
                        }
                    }
                }
                success(server, from, &message, |_| {})
            }
            (Class::Request, method::CHANNEL_BIND) => {
                let number = message
                    .find(AttributeType::CHANNEL_NUMBER)
                    .and_then(|value| value.get(..2))
                    .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
                    .and_then(ChannelNumber::new);
                let peer = message
                    .find(AttributeType::XOR_PEER_ADDRESS)
                    .and_then(|value| decode_xor(value, id));
                if let (Some(number), Some(peer), Some(entry)) = (
                    number,
                    peer,
                    self.allocations.iter_mut().find(|e| e.client == from),
                ) {
                    entry.channels.retain(|(_, bound)| *bound != peer);
                    entry.channels.push((number, peer));
                    if !entry.permissions.contains(&peer.ip()) {
                        entry.permissions.push(peer.ip());
                    }
                }
                success(server, from, &message, |_| {})
            }
            (Class::Indication, method::SEND) => self.relay_send(from, &message),
            (Class::Request, Method::BINDING) => success(server, from, &message, |builder| {
                builder
                    .add_xor_address(AttributeType::XOR_MAPPED_ADDRESS, from)
                    .unwrap();
            }),
            _ => Vec::new(),
        }
    }

    fn allocate(&mut self, from: SocketAddr, message: &Message<'_>) -> Vec<Packet> {
        let relayed =
            if let Some(existing) = self.allocations.iter().find(|entry| entry.client == from) {
                existing.relayed
            } else {
                let relayed = SocketAddr::new(self.relay_ip, self.next_port);
                self.next_port += 1;
                self.allocations.push(RelayAllocation {
                    client: from,
                    relayed,
                    permissions: Vec::new(),
                    channels: Vec::new(),
                });
                relayed
            };
        success(self.address, from, message, |builder| {
            builder
                .add_xor_address(AttributeType::XOR_RELAYED_ADDRESS, relayed)
                .unwrap();
            builder
                .add_xor_address(AttributeType::XOR_MAPPED_ADDRESS, from)
                .unwrap();
            builder.add_u32(AttributeType::LIFETIME, 600).unwrap();
        })
    }

    fn relay_send(&self, from: SocketAddr, message: &Message<'_>) -> Vec<Packet> {
        let peer = message
            .find(AttributeType::XOR_PEER_ADDRESS)
            .and_then(|value| decode_xor(value, message.transaction_id()));
        let payload = message.find(AttributeType::DATA);
        let Some(entry) = self.allocations.iter().find(|e| e.client == from) else {
            return Vec::new();
        };
        match (peer, payload) {
            (Some(peer), Some(payload)) if entry.permissions.contains(&peer.ip()) => {
                vec![Packet {
                    source: entry.relayed,
                    destination: peer,
                    data: payload.to_vec(),
                }]
            }
            _ => Vec::new(),
        }
    }

    fn channel_from_client(&self, from: SocketAddr, data: &[u8]) -> Vec<Packet> {
        let Ok(frame) = ChannelData::parse_frame(data) else {
            return Vec::new();
        };
        let Some(entry) = self.allocations.iter().find(|e| e.client == from) else {
            return Vec::new();
        };
        let Some((_, peer)) = entry
            .channels
            .iter()
            .find(|(number, _)| *number == frame.channel())
        else {
            return Vec::new();
        };
        vec![Packet {
            source: entry.relayed,
            destination: *peer,
            data: frame.data().to_vec(),
        }]
    }

    fn on_relayed(&mut self, from: SocketAddr, to: SocketAddr, data: &[u8]) -> Vec<Packet> {
        let Some(entry) = self.allocations.iter().find(|e| e.relayed == to) else {
            return Vec::new();
        };
        if !entry.permissions.contains(&from.ip()) {
            return Vec::new();
        }
        let client = entry.client;
        if let Some((number, _)) = entry.channels.iter().find(|(_, peer)| *peer == from) {
            let mut frame = Vec::new();
            ChannelData::encode(*number, data, Transport::Udp, &mut frame).unwrap();
            return vec![Packet {
                source: self.address,
                destination: client,
                data: frame,
            }];
        }
        self.next_id += 1;
        let mut bytes = [0xd0_u8; 12];
        bytes[8..].copy_from_slice(&self.next_id.to_be_bytes());
        let mut builder =
            MessageBuilder::new(Class::Indication, method::DATA, TransactionId::new(bytes));
        builder
            .add_xor_address(AttributeType::XOR_PEER_ADDRESS, from)
            .unwrap();
        builder.add(AttributeType::DATA, data).unwrap();
        vec![Packet {
            source: self.address,
            destination: client,
            data: builder.finish(),
        }]
    }
}

fn success(
    server: SocketAddr,
    to: SocketAddr,
    request: &Message<'_>,
    fill: impl FnOnce(&mut MessageBuilder),
) -> Vec<Packet> {
    let mut builder =
        MessageBuilder::new(Class::Success, request.method(), request.transaction_id());
    fill(&mut builder);
    builder.add_fingerprint().unwrap();
    vec![Packet {
        source: server,
        destination: to,
        data: builder.finish(),
    }]
}

pub(super) struct Network {
    pub(super) now: Instant,
    pub(super) nodes: Vec<Node>,
    nats: Vec<Nat>,
    pub(super) turn: TurnRelay,
    in_flight: Vec<(Instant, u64, Packet)>,
    sequence: u64,
    latency: Duration,
    loss_percent: u64,
    rng: u64,
    /// Drop every packet from now on.
    pub(super) cut: bool,
    /// Keep a copy of every packet an agent sends.
    pub(super) capture: bool,
    pub(super) captured: Vec<Packet>,
    /// How many packets the loss has taken.
    pub(super) dropped: usize,
}

impl Network {
    pub(super) fn new(seed: u64) -> Self {
        Self {
            now: Instant::now(),
            nodes: Vec::new(),
            nats: Vec::new(),
            turn: TurnRelay {
                address: address(TURN_SERVER),
                relay_ip: RELAY_IP.parse().expect("an address"),
                next_port: 50_000,
                next_id: 0,
                allocations: Vec::new(),
            },
            in_flight: Vec::new(),
            sequence: 0,
            latency: Duration::from_millis(10),
            loss_percent: 0,
            rng: seed | 1,
            cut: false,
            capture: false,
            captured: Vec::new(),
            dropped: 0,
        }
    }

    pub(super) fn add_nat(
        &mut self,
        public: &str,
        mapping: Mapping,
        filtering: Filtering,
    ) -> usize {
        self.nats.push(Nat {
            public: public.parse().expect("an address"),
            mapping,
            filtering,
            bindings: Vec::new(),
            next_port: 40_000,
        });
        self.nats.len() - 1
    }

    pub(super) fn add_full(
        &mut self,
        agent: IceAgent,
        stream: StreamId,
        sockets: &[SocketAddr],
        nat: Option<usize>,
    ) -> usize {
        let seed = u8::try_from(self.nodes.len() + 1).unwrap();
        self.nodes.push(Node::Full(Box::new(Peer {
            agent,
            stream,
            sockets: sockets.to_vec(),
            nat,
            seed,
            next_id: 0,
            events: Vec::new(),
            received: Vec::new(),
        })));
        self.nodes.len() - 1
    }

    pub(super) fn add_lite(&mut self, agent: LiteAgent, socket: SocketAddr) -> usize {
        self.nodes.push(Node::Lite(LitePeer {
            agent,
            socket,
            outbox: Vec::new(),
        }));
        self.nodes.len() - 1
    }

    pub(super) fn set_loss(&mut self, percent: u64) {
        self.loss_percent = percent;
    }

    pub(super) fn peer(&self, index: usize) -> &Peer {
        match &self.nodes[index] {
            Node::Full(peer) => peer,
            Node::Lite(_) => panic!("node {index} is a lite agent"),
        }
    }

    pub(super) fn peer_mut(&mut self, index: usize) -> &mut Peer {
        match &mut self.nodes[index] {
            Node::Full(peer) => peer,
            Node::Lite(_) => panic!("node {index} is a lite agent"),
        }
    }

    pub(super) fn lite(&self, index: usize) -> &LitePeer {
        match &self.nodes[index] {
            Node::Lite(lite) => lite,
            Node::Full(_) => panic!("node {index} is a full agent"),
        }
    }

    /// Run until `done` holds or `limit` of simulated time has passed.
    pub(super) fn run_until(&mut self, limit: Duration, done: impl Fn(&Self) -> bool) -> bool {
        let end = self.now + limit;
        loop {
            self.settle();
            if done(self) {
                return true;
            }
            if self.now >= end {
                return false;
            }
            let next = self.next_time().map_or(end, |at| at.min(end));
            self.now = if next > self.now {
                next
            } else {
                self.now + Duration::from_millis(1)
            };
        }
    }

    pub(super) fn run_for(&mut self, duration: Duration) {
        self.run_until(duration, |_| false);
    }

    /// Put application data an agent routed on the wire, through its NAT.
    pub(super) fn send_from(
        &mut self,
        index: usize,
        source: SocketAddr,
        destination: SocketAddr,
        data: Vec<u8>,
    ) {
        let nat = self.peer(index).nat;
        self.emit(
            nat,
            Packet {
                source,
                destination,
                data,
            },
        );
    }

    /// Hand a datagram straight to the agent that owns `socket`, as if it had
    /// arrived from `from`, and let the network carry whatever follows.
    pub(super) fn inject(&mut self, socket: SocketAddr, from: SocketAddr, data: &[u8]) {
        let now = self.now;
        for node in &mut self.nodes {
            if let Node::Full(peer) = node
                && peer.sockets.contains(&socket)
            {
                peer.feed();
                if let Received::Data { range, .. } =
                    peer.agent.handle_datagram(socket, from, data, now)
                {
                    peer.received.push(data[range].to_vec());
                }
            }
        }
        self.settle();
    }

    fn settle(&mut self) {
        for _ in 0..200 {
            let pumped = self.pump();
            let delivered = self.deliver_due();
            let fired = self.fire_timeouts();
            if !(pumped || delivered || fired) {
                return;
            }
        }
    }

    fn pump(&mut self) -> bool {
        let now = self.now;
        let mut outgoing = Vec::new();
        for node in &mut self.nodes {
            match node {
                Node::Full(peer) => {
                    peer.feed();
                    while let Some(transmit) = peer.agent.poll_transmit() {
                        outgoing.push((
                            peer.nat,
                            Packet {
                                source: transmit.source,
                                destination: transmit.destination,
                                data: transmit.data,
                            },
                        ));
                    }
                    while let Some(event) = peer.agent.poll_event() {
                        peer.events.push((now, event));
                    }
                }
                Node::Lite(lite) => {
                    outgoing.extend(lite.outbox.drain(..).map(|packet| (None, packet)));
                }
            }
        }
        let busy = !outgoing.is_empty();
        for (nat, packet) in outgoing {
            if self.capture {
                self.captured.push(packet.clone());
            }
            self.emit(nat, packet);
        }
        busy
    }

    fn emit(&mut self, nat: Option<usize>, mut packet: Packet) {
        if let Some(nat) = nat {
            packet.source = self.nats[nat].outbound(packet.source, packet.destination);
        }
        if self.cut || self.lose() {
            return;
        }
        self.sequence += 1;
        self.in_flight
            .push((self.now + self.latency, self.sequence, packet));
    }

    fn lose(&mut self) -> bool {
        if self.loss_percent == 0 {
            return false;
        }
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        let lost = self.rng % 100 < self.loss_percent;
        if lost {
            self.dropped += 1;
        }
        lost
    }

    fn deliver_due(&mut self) -> bool {
        let now = self.now;
        let (mut due, kept): (Vec<_>, Vec<_>) =
            self.in_flight.drain(..).partition(|(at, _, _)| *at <= now);
        self.in_flight = kept;
        due.sort_by_key(|(at, sequence, _)| (*at, *sequence));
        let busy = !due.is_empty();
        for (_, _, packet) in due {
            self.route(packet);
        }
        busy
    }

    fn route(&mut self, packet: Packet) {
        let Packet {
            source,
            destination,
            data,
        } = packet;
        if destination == address(STUN_SERVER) {
            if let Ok(message) = Message::parse(&data)
                && message.class() == Class::Request
            {
                let replies = success(destination, source, &message, |builder| {
                    builder
                        .add_xor_address(AttributeType::XOR_MAPPED_ADDRESS, source)
                        .unwrap();
                });
                for reply in replies {
                    self.emit(None, reply);
                }
            }
            return;
        }
        if destination == self.turn.address {
            for reply in self.turn.on_client(source, &data) {
                self.emit(None, reply);
            }
            return;
        }
        if destination.ip() == self.turn.relay_ip {
            for onward in self.turn.on_relayed(source, destination, &data) {
                self.emit(None, onward);
            }
            return;
        }
        if let Some(nat) = self
            .nats
            .iter()
            .position(|nat| nat.public == destination.ip())
        {
            if let Some(internal) = self.nats[nat].inbound(destination.port(), source) {
                self.deliver(internal, source, &data, Some(nat));
            }
            return;
        }
        self.deliver(destination, source, &data, None);
    }

    /// Hand a datagram to the node that owns the socket, provided that node
    /// sits where the packet arrived: behind this NAT, or on the open
    /// Internet. A private address is not reachable from anywhere else.
    fn deliver(&mut self, socket: SocketAddr, from: SocketAddr, data: &[u8], nat: Option<usize>) {
        let now = self.now;
        for node in &mut self.nodes {
            match node {
                Node::Full(peer) if peer.nat == nat && peer.sockets.contains(&socket) => {
                    peer.feed();
                    if let Received::Data { range, .. } =
                        peer.agent.handle_datagram(socket, from, data, now)
                    {
                        peer.received.push(data[range].to_vec());
                    }
                    return;
                }
                Node::Lite(lite) if nat.is_none() && lite.socket == socket => {
                    if let Some(reply) =
                        lite.agent
                            .handle_binding_request(ComponentId::RTP, socket, from, data)
                    {
                        lite.outbox.push(Packet {
                            source: socket,
                            destination: from,
                            data: reply,
                        });
                    }
                    return;
                }
                _ => {}
            }
        }
    }

    fn fire_timeouts(&mut self) -> bool {
        let now = self.now;
        let mut busy = false;
        for node in &mut self.nodes {
            if let Node::Full(peer) = node
                && peer
                    .agent
                    .deadline()
                    .is_some_and(|deadline| deadline <= now)
            {
                peer.feed();
                peer.agent.handle_timeout(now);
                busy = true;
            }
        }
        busy
    }

    fn next_time(&self) -> Option<Instant> {
        let packets = self.in_flight.iter().map(|(at, _, _)| *at).min();
        let deadlines = self
            .nodes
            .iter()
            .filter_map(|node| match node {
                Node::Full(peer) => peer.agent.deadline(),
                Node::Lite(_) => None,
            })
            .min();
        [packets, deadlines].into_iter().flatten().min()
    }
}
