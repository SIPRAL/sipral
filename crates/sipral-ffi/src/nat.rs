// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Behind a NAT: where this end's sockets appear from, asked of a STUN
//! server, and put where the far end reads it.
//!
//! Off unless `sipral_stack_config_t::nat` is [`SipralNat::Stun`]. Then the
//! stack keeps one Binding transaction (RFC 8489) per socket against the
//! `stun_server` the configuration names, and the answers go to the two
//! places a far end with no NAT helper acts on:
//!
//! - **The signalling socket's** goes into the `Contact` of every account on
//!   that transport whose `Contact` names the socket's own address, and an
//!   account holding a binding registers it at once. It is asked again every
//!   twenty-five seconds for as long as the stack lives, which is what keeps
//!   the mapping open through minutes of idle signalling, and an answer that
//!   comes back different moves the accounts again. Nothing about this path
//!   asks anything new of the application: the requests leave through
//!   [`sipral_stack_poll_transmit`](crate::transport::sipral_stack_poll_transmit)
//!   on that transport, and the answers come back through
//!   [`sipral_stack_receive_datagram`](crate::transport::sipral_stack_receive_datagram)
//!   like anything else arriving on the socket.
//! - **A media socket's** goes into the `c=` and `m=` lines of the call that
//!   is placed, rung or answered on it. A media socket is the application's
//!   and is bound for one call, so the application names it with
//!   [`sipral_stack_nat_map`] before that call, sends what
//!   [`sipral_stack_poll_stun`] hands back from it, and hands in what arrives
//!   on it with [`sipral_stack_receive_stun`] until the answer is in.
//!
//! [`SipralEventKind::NatMapping`](crate::event::SipralEventKind::NatMapping)
//! says what each socket learned, and when a signalling socket's mapping
//! moved. `docs/06-nat.md` has the reasons for each of these choices, and
//! `docs/08-ffi.md` the order an application calls them in.

#[cfg(feature = "stun")]
use std::collections::{HashMap, VecDeque};
use std::ffi::c_char;
use std::net::SocketAddr;
#[cfg(feature = "stun")]
use std::sync::Arc;
use std::time::Instant;

use sipral_core::endpoint::{Transmit, TransportId, TransportProtocol};

use crate::abi::{codes, record};
use crate::error::{Fail, entry, fail};
use crate::event::SipralEvent;
use crate::handle::SipralHandle;
use crate::stack::{SipralStackConfig, StackState, with_stack, with_stack_at};
use crate::status::SipralStatus;
use crate::text::text;
#[cfg(feature = "stun")]
use crate::transport::write_address;
use crate::transport::{SipralTransmit, arrived, optional_address, prepare};
use crate::versioned::{read_versioned, write_versioned};

codes! {
    /// What a stack does about a NAT in front of it. Names for
    /// `sipral_stack_config_t::nat`.
    ///
    /// Zero is not one of them: it means this build's own built-in default,
    /// which is [`SipralNat::Off`]. `docs/06-nat.md` says why that is the
    /// default and what `rport` and symmetric RTP already carry without it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralNat: u32 {
        /// Ask nobody. Every address this stack writes is the one the
        /// application gave it.
        Off = 1,
        /// Ask the STUN server `sipral_stack_config_t::stun_server` names
        /// where each socket appears from, and write that instead: the
        /// signalling socket's in the `Contact`, a media socket's in `c=` and
        /// `m=`.
        ///
        /// `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
        /// `SIPRAL_FEATURE_STUN`.
        Stun = 2,
    }
}

codes! {
    /// What a socket's mapping came to. Names for
    /// `sipral_nat_event_t::mapping`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralNatMapping: u32 {
        /// The first answer: the socket appears at `public`.
        Learned = 1,
        /// A later answer about a signalling socket named another address:
        /// the NAT let the mapping go and made a new one, or the network
        /// under the socket changed. `previous` is what it was.
        Moved = 2,
        /// The server did not answer, in five and a half seconds, or refused.
        /// The socket is described by its own address, exactly as it would
        /// have been with `SIPRAL_NAT_OFF`; a signalling socket asks again at
        /// its next refresh.
        Unanswered = 3,
    }
}

record! {
    /// What a [`SipralEventKind::NatMapping`](crate::event::SipralEventKind::NatMapping)
    /// carries.
    ///
    /// The three addresses are `host:port`, not NUL-terminated, and the
    /// library's: valid for as long as the callback runs.
    #[derive(Clone, Copy)]
    pub struct SipralNatEvent {
        /// A [`SipralNatMapping`].
        pub mapping: u32,
        /// Nonzero for a signalling socket — a transport of this stack's —
        /// and zero for a media socket [`sipral_stack_nat_map`] named.
        pub signalling: u32,
        /// The transport, when `signalling` is nonzero: `SIPRAL_TRANSPORT_MAIN`
        /// or a number `sipral_stack_transport_bind` bound. Zero otherwise,
        /// which is not a transport here.
        pub transport: u32,
        /// How many accounts' `Contact` moved to `public` because of this —
        /// each one that holds a binding, or is getting one, has registered it
        /// already. Zero for a media socket, and for an answer no account's
        /// `Contact` named the socket in.
        pub accounts: u32,
        /// The socket, as the application named it.
        pub local: *const c_char,
        /// How many bytes of it.
        pub local_len: usize,
        /// Where the server saw it: the public address. Empty for
        /// `SIPRAL_NAT_MAPPING_UNANSWERED`.
        pub mapped: *const c_char,
        /// How many bytes of it.
        pub mapped_len: usize,
        /// What it was before, for `SIPRAL_NAT_MAPPING_MOVED`. Empty
        /// otherwise.
        pub previous: *const c_char,
        /// How many bytes of it.
        pub previous_len: usize,
    }
}

/// The server a stack's configuration asks, or `None` for one that asks
/// nobody.
///
/// # Safety
///
/// `config.stun_server` must be readable for `config.stun_server_len` bytes.
pub(crate) unsafe fn configured(config: &SipralStackConfig) -> Result<Option<SocketAddr>, Fail> {
    let server = unsafe { text(config.stun_server, config.stun_server_len, "stun_server") }?;
    match (config.nat, server) {
        (0 | 1, None) => Ok(None),
        (0 | 1, Some(_)) => Err(fail(
            SipralStatus::InvalidArgument,
            "stun_server names a server and nat does not ask one: set nat to SIPRAL_NAT_STUN, or \
             leave stun_server out",
        )),
        (2, None) => Err(fail(
            SipralStatus::InvalidArgument,
            "nat is SIPRAL_NAT_STUN and stun_server names no server to ask",
        )),
        (2, Some(server)) => {
            let Ok(address) = server.parse::<SocketAddr>() else {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    format!(
                        "stun_server is {server:?}, which is not an address and a port; \
                         resolving a name is the application's, as it is for registrar_address"
                    ),
                ));
            };
            supported(address)
        }
        (other, _) => Err(fail(
            SipralStatus::InvalidArgument,
            format!("nat is {other}, and nat is 0 for the default, 1 for off or 2 for STUN"),
        )),
    }
}

#[cfg(feature = "stun")]
#[allow(clippy::unnecessary_wraps)]
const fn supported(server: SocketAddr) -> Result<Option<SocketAddr>, Fail> {
    Ok(Some(server))
}

#[cfg(not(feature = "stun"))]
fn supported(_server: SocketAddr) -> Result<Option<SocketAddr>, Fail> {
    Err(fail(
        SipralStatus::NotSupported,
        "nat names STUN and this build has none: SIPRAL_FEATURE_STUN is clear in \
         sipral_capabilities",
    ))
}

/// A stack's side of STUN: nothing at all unless its configuration asked.
#[cfg(feature = "stun")]
#[derive(Default)]
pub(crate) struct Nat {
    active: Option<Active>,
}

/// Without the feature there is no stack's side of STUN to hold, only the
/// answers a stack that asks nobody gives, so the type has no values.
#[cfg(not(feature = "stun"))]
pub(crate) enum Nat {}

/// Everything a stack that asks keeps.
#[cfg(feature = "stun")]
struct Active {
    mappings: sipral::Mappings,
    /// The signalling sockets being kept mapped, by address, and the
    /// transport each one is.
    signalling: HashMap<SocketAddr, TransportId>,
    /// Requests for a signalling socket, on their way out through
    /// `sipral_stack_poll_transmit`.
    signalling_out: VecDeque<Transmit>,
    /// Requests for a media socket, on their way out through
    /// [`sipral_stack_poll_stun`].
    media_out: VecDeque<sipral::StunDatagram>,
}

/// The text one event's three addresses are read from, and the event.
pub(crate) type Raised = (SipralEvent, String);

#[cfg(feature = "stun")]
impl Nat {
    /// Start asking, when the configuration named a server: the signalling
    /// socket the stack was created with is the first one kept mapped.
    pub(crate) fn start(
        state: &mut StackState,
        server: Option<SocketAddr>,
        transport: TransportId,
        protocol: TransportProtocol,
        local: SocketAddr,
        now: Instant,
    ) {
        let Some(server) = server else {
            return;
        };
        let mappings = state.engine.mappings(server);
        state.nat.active = Some(Active {
            mappings,
            signalling: HashMap::new(),
            signalling_out: VecDeque::new(),
            media_out: VecDeque::new(),
        });
        Self::bound(state, transport, protocol, local, now);
    }

    /// A transport was bound, or bound again: a datagram one is kept
    /// mapped from its address, and whatever it was mapped from before is
    /// let go. Bound again at the same address, it is asked again at once.
    ///
    /// Only a datagram transport. A connection's far end already sees this
    /// end's mapping and answers along it, which is `rport` and RFC 5626's
    /// flow, and a STUN request over UDP would describe a different binding
    /// from the one the connection is using.
    pub(crate) fn bound(
        state: &mut StackState,
        transport: TransportId,
        protocol: TransportProtocol,
        local: SocketAddr,
        now: Instant,
    ) {
        let Some(active) = state.nat.active.as_mut() else {
            return;
        };
        let before: Vec<SocketAddr> = active
            .signalling
            .iter()
            .filter(|(address, id)| **id == transport && **address != local)
            .map(|(address, _)| *address)
            .collect();
        for address in before {
            active.signalling.remove(&address);
            active.mappings.forget(address);
        }
        if protocol != TransportProtocol::Udp {
            if active.signalling.get(&local) == Some(&transport) {
                active.signalling.remove(&local);
                active.mappings.forget(local);
            }
            return;
        }
        // bound again at the same address is what an application says after
        // a network change, when the last answer is the one thing most
        // likely to be wrong: it is asked again now rather than at the next
        // refresh
        if active.signalling.insert(local, transport) == Some(transport) {
            active.mappings.ask_again(local, now);
        } else {
            active.mappings.map(local, sipral::Keep::Refreshed, now);
        }
        active.sort();
    }

    /// The next request for a signalling socket, for
    /// `sipral_stack_poll_transmit` to hand out before anything the user
    /// agent wrote.
    pub(crate) fn poll_signalling(state: &mut StackState) -> Option<Transmit> {
        let active = state.nat.active.as_mut()?;
        active.sort();
        active.signalling_out.pop_front()
    }

    /// The socket a datagram handed in on `transport` arrived on, as far as
    /// its STUN answer goes: the one that transport is kept mapped from.
    ///
    /// A datagram transport is one socket, and its number says which one
    /// more surely than `to` does: an application that hands in a second
    /// transport's datagrams by number alone leaves `to` meaning the address
    /// the stack was created with, and the answer then has to reach the
    /// transaction it answers rather than the main socket's. `arrived_on`
    /// for a transport that is not kept mapped.
    pub(crate) fn socket_of(
        state: &StackState,
        transport: TransportId,
        arrived_on: SocketAddr,
    ) -> SocketAddr {
        state
            .nat
            .active
            .as_ref()
            .and_then(|active| {
                active
                    .signalling
                    .iter()
                    .find(|(_, id)| **id == transport)
                    .map(|(address, _)| *address)
            })
            .unwrap_or(arrived_on)
    }

    /// Whether a datagram that arrived on `local` from `from` was the STUN
    /// server's answer, which nothing else then reads.
    pub(crate) fn intercept(
        state: &mut StackState,
        local: SocketAddr,
        from: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> bool {
        let Some(active) = state.nat.active.as_mut() else {
            return false;
        };
        let taken = active.mappings.receive(local, from, data, now);
        active.sort();
        taken
    }

    /// Time passes for every transaction.
    pub(crate) fn handle_timeout(state: &mut StackState, now: Instant) {
        if let Some(active) = state.nat.active.as_mut() {
            active.mappings.handle_timeout(now);
            active.sort();
        }
    }

    /// When a transaction next has something to do.
    pub(crate) fn poll_timeout(state: &StackState) -> Option<Instant> {
        state
            .nat
            .active
            .as_ref()
            .and_then(|active| active.mappings.poll_timeout())
    }

    /// What was learned since the last poll, as events, with every account
    /// already moved onto what a signalling socket learned.
    pub(crate) fn drain(state: &mut StackState, stack: SipralHandle, now: Instant) -> Vec<Raised> {
        let Some(active) = state.nat.active.as_mut() else {
            return Vec::new();
        };
        // taken out first, with the transport each socket is, so that moving
        // the accounts below can have the user agent to itself
        let mut learned_all = Vec::new();
        while let Some(learned) = active.mappings.poll_event() {
            let local = match learned {
                sipral::MappingEvent::Learned { local, .. }
                | sipral::MappingEvent::Moved { local, .. }
                | sipral::MappingEvent::Unanswered { local, .. } => local,
            };
            learned_all.push((learned, active.signalling.get(&local).copied()));
        }
        let mut raised = Vec::new();
        for (learned, transport) in learned_all {
            let (local, mapping, public, previous) = match learned {
                sipral::MappingEvent::Learned { local, public } => {
                    (local, SipralNatMapping::Learned, Some(public), None)
                }
                sipral::MappingEvent::Moved {
                    local,
                    previous,
                    public,
                } => (local, SipralNatMapping::Moved, Some(public), Some(previous)),
                sipral::MappingEvent::Unanswered { local, .. } => {
                    (local, SipralNatMapping::Unanswered, None, None)
                }
            };
            // what the accounts' `Contact` names now: the socket itself the
            // first time, and the address the last answer gave after that
            let from = previous.unwrap_or(local);
            let accounts = match (transport, public) {
                (Some(transport), Some(public)) => state
                    .agent
                    .readdress(transport, from, public, now)
                    .unwrap_or(0),
                _ => 0,
            };
            raised.push(event(
                stack, mapping, transport, accounts, local, public, previous,
            ));
        }
        raised
    }

    /// An account was added, or given a new `Contact`: when the signalling
    /// socket it names has already been answered, the `Contact` moves now
    /// rather than at the next answer that differs, which may never come.
    pub(crate) fn contacts_changed(state: &mut StackState, now: Instant) {
        let Some(active) = state.nat.active.as_ref() else {
            return;
        };
        let answered: Vec<(SocketAddr, TransportId, SocketAddr)> = active
            .signalling
            .iter()
            .filter_map(|(local, transport)| {
                Some((*local, *transport, active.mappings.public(*local)?))
            })
            .collect();
        for (local, transport, public) in answered {
            // an account that was never asked to register sends nothing
            // here, so the only error possible is one no account added a
            // moment ago can be the cause of
            let _moved = state.agent.readdress(transport, local, public, now);
        }
    }

    /// Where a call on the media socket `local` is described as being.
    ///
    /// `None` for a stack that asks nobody, a socket nobody named, and a
    /// socket whose server never answered — all three described by the
    /// socket's own address. A socket still being asked about is refused:
    /// the answer is at most five and a half seconds away, and a description
    /// written now would name an address nobody outside can reach.
    pub(crate) fn public_for(
        state: &StackState,
        local: SocketAddr,
    ) -> Result<Option<SocketAddr>, Fail> {
        let Some(active) = state.nat.active.as_ref() else {
            return Ok(None);
        };
        match active.mappings.state(local) {
            Some(sipral::MappingState::Mapped(public)) => Ok(Some(public)),
            Some(sipral::MappingState::Asking) => Err(fail(
                SipralStatus::WrongState,
                format!(
                    "the STUN server has not answered for {local} yet: wait for \
                     SIPRAL_EVENT_KIND_NAT_MAPPING about it, which arrives within five and a \
                     half seconds either way"
                ),
            )),
            Some(sipral::MappingState::Unmapped) | None => Ok(None),
        }
    }

    /// A call was described on `local`, and the mapping is spent: the next
    /// call on the same socket is mapped again, since nothing kept this one
    /// open in between.
    pub(crate) fn spent(state: &mut StackState, local: SocketAddr) {
        if let Some(active) = state.nat.active.as_mut()
            && !active.signalling.contains_key(&local)
        {
            active.mappings.forget(local);
            active.media_out.retain(|request| request.local != local);
        }
    }

    fn map_media(state: &mut StackState, local: SocketAddr, now: Instant) -> Result<(), Fail> {
        let Some(active) = state.nat.active.as_mut() else {
            return Err(not_asking());
        };
        if active.signalling.contains_key(&local) {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!(
                    "{local} is a signalling socket of this stack's, and is already kept mapped \
                     for as long as it is bound"
                ),
            ));
        }
        active.mappings.map(local, sipral::Keep::Once, now);
        active.sort();
        Ok(())
    }

    fn take_media(
        state: &mut StackState,
        room: usize,
    ) -> Result<Option<sipral::StunDatagram>, usize> {
        let Some(active) = state.nat.active.as_mut() else {
            return Ok(None);
        };
        active.sort();
        match active.media_out.front() {
            Some(front) if front.payload.len() > room => Err(front.payload.len()),
            Some(_) => Ok(active.media_out.pop_front()),
            None => Ok(None),
        }
    }

    fn receive_media(
        state: &mut StackState,
        local: SocketAddr,
        from: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> Result<(), Fail> {
        if state.nat.active.is_none() {
            return Err(not_asking());
        }
        if Self::intercept(state, local, from, data, now) {
            return Ok(());
        }
        Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "not an answer from the STUN server this stack asks, for a socket it asked about: \
                 from {from}, on {local}"
            ),
        ))
    }
}

#[cfg(feature = "stun")]
impl Active {
    /// Move what the transactions wrote into the queue of the path it
    /// leaves by: the transport's own, for a signalling socket, and
    /// [`sipral_stack_poll_stun`]'s for a media one.
    fn sort(&mut self) {
        while let Some(request) = self.mappings.poll_transmit() {
            match self.signalling.get(&request.local) {
                Some(transport) => self.signalling_out.push_back(Transmit {
                    transport: *transport,
                    destination: request.destination,
                    source: None,
                    payload: Arc::from(request.payload),
                    protocol: TransportProtocol::Udp,
                }),
                None => self.media_out.push_back(request),
            }
        }
    }
}

/// Without the feature a stack never asks, since `nat` naming STUN is refused
/// when it is created, and every one of these is the answer for a stack that
/// does not.
#[cfg(not(feature = "stun"))]
impl Nat {
    pub(crate) const fn start(
        _state: &mut StackState,
        _server: Option<SocketAddr>,
        _transport: TransportId,
        _protocol: TransportProtocol,
        _local: SocketAddr,
        _now: Instant,
    ) {
    }

    pub(crate) const fn bound(
        _state: &mut StackState,
        _transport: TransportId,
        _protocol: TransportProtocol,
        _local: SocketAddr,
        _now: Instant,
    ) {
    }

    pub(crate) const fn poll_signalling(_state: &mut StackState) -> Option<Transmit> {
        None
    }

    pub(crate) const fn socket_of(
        _state: &StackState,
        _transport: TransportId,
        arrived_on: SocketAddr,
    ) -> SocketAddr {
        arrived_on
    }

    pub(crate) const fn intercept(
        _state: &mut StackState,
        _local: SocketAddr,
        _from: SocketAddr,
        _data: &[u8],
        _now: Instant,
    ) -> bool {
        false
    }

    pub(crate) const fn handle_timeout(_state: &mut StackState, _now: Instant) {}

    pub(crate) const fn poll_timeout(_state: &StackState) -> Option<Instant> {
        None
    }

    pub(crate) const fn drain(
        _state: &mut StackState,
        _stack: SipralHandle,
        _now: Instant,
    ) -> Vec<Raised> {
        Vec::new()
    }

    pub(crate) const fn contacts_changed(_state: &mut StackState, _now: Instant) {}

    #[allow(clippy::unnecessary_wraps)]
    pub(crate) const fn public_for(
        _state: &StackState,
        _local: SocketAddr,
    ) -> Result<Option<SocketAddr>, Fail> {
        Ok(None)
    }

    pub(crate) const fn spent(_state: &mut StackState, _local: SocketAddr) {}

    fn map_media(_state: &mut StackState, _local: SocketAddr, _now: Instant) -> Result<(), Fail> {
        Err(not_asking())
    }

    #[allow(clippy::unnecessary_wraps)]
    const fn take_media(_state: &mut StackState, _room: usize) -> Result<Option<Never>, usize> {
        Ok(None)
    }

    fn receive_media(
        _state: &mut StackState,
        _local: SocketAddr,
        _from: SocketAddr,
        _data: &[u8],
        _now: Instant,
    ) -> Result<(), Fail> {
        Err(not_asking())
    }
}

/// What a build without the feature has in the queue it never fills.
#[cfg(not(feature = "stun"))]
enum Never {}

fn not_asking() -> Fail {
    fail(
        SipralStatus::WrongState,
        "this stack asks no STUN server: it was created with nat other than SIPRAL_NAT_STUN",
    )
}

/// One event, and the text its three addresses point into.
///
/// The addresses are written into one string, one after another, and the
/// event points at the three pieces: the string's bytes live on the heap
/// and stay where they are however often the delivery holding it moves.
#[cfg(feature = "stun")]
fn event(
    stack: SipralHandle,
    mapping: SipralNatMapping,
    transport: Option<TransportId>,
    accounts: usize,
    local: SocketAddr,
    public: Option<SocketAddr>,
    previous: Option<SocketAddr>,
) -> Raised {
    let local = local.to_string();
    let public = public
        .map(|address| address.to_string())
        .unwrap_or_default();
    let previous = previous
        .map(|address| address.to_string())
        .unwrap_or_default();
    let text = format!("{local}{public}{previous}");
    let base = text.as_ptr().cast::<c_char>();
    let piece = |offset: usize, len: usize| -> *const c_char {
        if len == 0 {
            std::ptr::null()
        } else {
            base.wrapping_add(offset)
        }
    };
    let payload = SipralNatEvent {
        mapping: mapping as u32,
        signalling: u32::from(transport.is_some()),
        transport: transport.map_or(0, |id| id.0),
        accounts: u32::try_from(accounts).unwrap_or(u32::MAX),
        local: piece(0, local.len()),
        local_len: local.len(),
        mapped: piece(local.len(), public.len()),
        mapped_len: public.len(),
        previous: piece(local.len() + public.len(), previous.len()),
        previous_len: previous.len(),
    };
    (crate::event::nat_mapping(stack, payload), text)
}

entry! {
    /// Ask where a media socket appears from, before a call is described
    /// on it.
    ///
    /// `local` is the address the socket is bound to, as `host:port` — the
    /// same text the call's `media_address` will be. The request is waiting
    /// in [`sipral_stack_poll_stun`] when this returns, the answer goes in
    /// through [`sipral_stack_receive_stun`], and
    /// `SIPRAL_EVENT_KIND_NAT_MAPPING` says what it came to, within five and
    /// a half seconds whatever the server does. From then on a call placed,
    /// rung or answered with that `media_address` is described by the public
    /// address, and asks for `a=rtcp-mux`, since one mapping describes one
    /// port. Placing one before the answer is `SIPRAL_STATUS_WRONG_STATE`.
    ///
    /// The mapping is spent by the call it describes. A socket used for a
    /// second call is named here again — nothing kept the first answer true
    /// in between.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` on a stack created without
    /// `SIPRAL_NAT_STUN`, and `SIPRAL_STATUS_INVALID_ARGUMENT` for a
    /// signalling socket of the stack's own, which is kept mapped already.
    ///
    /// # Safety
    ///
    /// `local` must be readable for `local_len` bytes.
    fn sipral_stack_nat_map(
        stack: SipralHandle,
        local: *const c_char,
        local_len: usize,
        now_ms: u64,
    ) {
        let local = unsafe { crate::media::address(local, local_len, "local") }?;
        with_stack_at(stack, now_ms, |state, now| Nat::map_media(state, local, now))
    }
}

entry! {
    /// Take the next STUN request a media socket has to send.
    ///
    /// The same record and the same rules as `sipral_stack_poll_transmit`,
    /// on a queue of its own: loop until `len` comes back zero, after every
    /// [`sipral_stack_nat_map`], every [`sipral_stack_receive_stun`] and
    /// every `sipral_stack_poll`, since the stack retransmits a request
    /// nobody answered. `source` is always written, and it is the socket to
    /// send from — the whole point is the address the server sees it come
    /// from, so sending it from any other socket learns the wrong one.
    /// `transport` is zero and names nothing here, and `protocol` is UDP.
    ///
    /// # Safety
    ///
    /// `transmit` must point at a `sipral_transmit_t` whose `size` member says
    /// how long it is and whose buffers are writable for the capacities beside
    /// them.
    fn sipral_stack_poll_stun(stack: SipralHandle, transmit: *mut SipralTransmit) {
        let mut out = unsafe { read_versioned(transmit) }?;
        prepare(&mut out)?;
        let taken = with_stack(stack, |state| Ok(Nat::take_media(state, out.capacity)))?;
        let request = match taken {
            Ok(request) => request,
            Err(needed) => {
                out.len = needed;
                unsafe { write_versioned(transmit, out) }?;
                return Err(fail(
                    SipralStatus::BufferTooSmall,
                    format!(
                        "the request is {needed} bytes and there is room for {}; it is still \
                         here, and the next call with room for it takes it",
                        out.capacity
                    ),
                ));
            }
        };
        #[cfg(feature = "stun")]
        if let Some(request) = request {
            unsafe { put(&mut out, &request) }?;
        }
        #[cfg(not(feature = "stun"))]
        if let Some(never) = request {
            match never {}
        }
        unsafe { write_versioned(transmit, out) }
    }
}

/// Put one request in the caller's buffers.
///
/// # Safety
///
/// The buffers in `transmit` must be writable for the capacities beside them,
/// which `prepare` has already been asked about, and the payload must fit.
#[cfg(feature = "stun")]
unsafe fn put(transmit: &mut SipralTransmit, request: &sipral::StunDatagram) -> Result<(), Fail> {
    if !request.payload.is_empty() {
        unsafe {
            std::ptr::copy_nonoverlapping(
                request.payload.as_ptr(),
                transmit.data,
                request.payload.len(),
            );
        }
    }
    transmit.len = request.payload.len();
    transmit.transport = 0;
    transmit.protocol = crate::stack::SipralTransport::Udp as u32;
    transmit.destination_len = unsafe {
        write_address(
            transmit.destination,
            Some(request.destination),
            "the destination",
        )
    }?;
    transmit.source_len = unsafe {
        write_address(
            transmit.source,
            Some(request.local),
            "the socket to send from",
        )
    }?;
    Ok(())
}

entry! {
    /// Hand over a datagram that arrived on a media socket
    /// [`sipral_stack_nat_map`] named, before a call has media on it.
    ///
    /// `to` is the socket it arrived on, as `local` was given there; `from`
    /// is where it came from. `SIPRAL_STATUS_OK` when it was the STUN
    /// server's answer, which is then the stack's and nobody else's;
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for anything else — early media from
    /// a far end, a datagram from a stranger, an answer from any address but
    /// the server's — which costs that one datagram and nothing more. Only
    /// the server's own address is believed, and only an answer to a request
    /// this stack sent: that is the whole defence against a forged answer
    /// naming an address of the attacker's choosing as this end's own.
    ///
    /// # Safety
    ///
    /// `data` must be readable for `len` bytes, `from` for `from_len`, and
    /// `to` for `to_len`.
    fn sipral_stack_receive_stun(
        stack: SipralHandle,
        data: *const u8,
        len: usize,
        from: *const c_char,
        from_len: usize,
        to: *const c_char,
        to_len: usize,
        now_ms: u64,
    ) {
        let datagram = unsafe { arrived(data, len, "a datagram") }?;
        let from = unsafe { crate::media::address(from, from_len, "from") }?;
        let Some(to) = (unsafe { optional_address(to, to_len, "to") })? else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "to names the socket the datagram arrived on, and a media socket has no default",
            ));
        };
        with_stack_at(stack, now_ms, |state, now| {
            Nat::receive_media(state, to, from, datagram, now)
        })
    }
}

#[cfg(all(test, feature = "stun"))]
mod tests {
    use std::cell::RefCell;
    use std::ffi::{CStr, c_char, c_void};
    use std::net::{IpAddr, SocketAddr};
    use std::ptr;

    use super::{
        SipralNat, SipralNatMapping, sipral_stack_nat_map, sipral_stack_poll_stun,
        sipral_stack_receive_stun,
    };
    use crate::account::sipral_account_register;
    use crate::account::tests::account_config;
    use crate::call::tests::{as_text, managed_config, place};
    use crate::error::last_error_text;
    use crate::event::{SipralEvent, SipralEventKind};
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::media::SIPRAL_ADDRESS_BYTES;
    use crate::stack::SipralStackConfig;
    use crate::stack::tests::{BIND, Observed, config, create, poll, record};
    use crate::status::SipralStatus;
    use crate::transport::{
        SIPRAL_MESSAGE_BYTES, SIPRAL_TRANSPORT_MAIN, SipralTransmit, sipral_stack_poll_transmit,
        sipral_stack_receive_datagram,
    };

    const SERVER: &str = "198.51.100.1:3478";
    const MEDIA: &str = crate::call::tests::MEDIA;
    /// What the NAT in front of these tests shows the world for the SIP
    /// socket, and for the media one.
    const SIP_PUBLIC: &str = "203.0.113.7:41000";
    const MEDIA_PUBLIC: &str = "203.0.113.7:41002";

    /// What one `SIPRAL_EVENT_KIND_NAT_MAPPING` said, copied out inside the
    /// callback, the only time its pointers are good.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Mapped {
        mapping: u32,
        signalling: u32,
        transport: u32,
        accounts: u32,
        local: String,
        public: String,
        previous: String,
    }

    thread_local! {
        static MAPPED: RefCell<Vec<Mapped>> = const { RefCell::new(Vec::new()) };
    }

    fn piece(pointer: *const c_char, len: usize) -> String {
        if pointer.is_null() {
            return String::new();
        }
        let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), len) };
        String::from_utf8_lossy(bytes).into_owned()
    }

    unsafe extern "C" fn listen(event: *const SipralEvent, user_data: *mut c_void) {
        let seen = unsafe { &*event };
        if seen.kind == SipralEventKind::NatMapping {
            let payload = unsafe { seen.payload.nat };
            let mapped = Mapped {
                mapping: payload.mapping,
                signalling: payload.signalling,
                transport: payload.transport,
                accounts: payload.accounts,
                local: piece(payload.local, payload.local_len),
                public: piece(payload.mapped, payload.mapped_len),
                previous: piece(payload.previous, payload.previous_len),
            };
            MAPPED.with(|all| all.borrow_mut().push(mapped));
        }
        unsafe { record(event, user_data) };
    }

    fn mapped() -> Vec<Mapped> {
        MAPPED.with(|all| std::mem::take(&mut *all.borrow_mut()))
    }

    fn asking(observed: &mut Observed) -> SipralStackConfig {
        let mut settings = config(listen, observed);
        settings.nat = SipralNat::Stun as u32;
        (settings.stun_server, settings.stun_server_len) = as_text(SERVER);
        let (codecs, codecs_len) = as_text("PCMU");
        settings.codecs = codecs;
        settings.codecs_len = codecs_len;
        settings
    }

    fn asking_stack(observed: &mut Observed) -> SipralHandle {
        let _ = mapped();
        let (status, handle) = create(&asking(observed));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        handle
    }

    /// A STUN server's success response to `request`, written out from RFC
    /// 8489 §5 and §14.2 rather than with this tree's own builder: the
    /// request's own transaction id, and `seen` in an XOR-MAPPED-ADDRESS.
    fn answer(request: &[u8], seen: &str) -> Vec<u8> {
        const COOKIE: u32 = 0x2112_a442;
        let seen: SocketAddr = seen.parse().expect("an address");
        let IpAddr::V4(ip) = seen.ip() else {
            panic!("these tests are IPv4");
        };
        let mut out = vec![0x01, 0x01, 0x00, 0x0c];
        out.extend_from_slice(&COOKIE.to_be_bytes());
        out.extend_from_slice(request.get(8..20).expect("a whole STUN header"));
        out.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
        let port = seen.port() ^ u16::try_from(COOKIE >> 16).expect("sixteen bits");
        out.extend_from_slice(&port.to_be_bytes());
        out.extend_from_slice(&(u32::from(ip) ^ COOKIE).to_be_bytes());
        out
    }

    fn is_stun(bytes: &[u8]) -> bool {
        bytes.len() >= 20 && bytes.get(4..8) == Some(&[0x21, 0x12, 0xa4, 0x42][..])
    }

    /// One transmit record's worth of the caller's own buffers.
    struct Buffers {
        data: Vec<u8>,
        destination: [c_char; SIPRAL_ADDRESS_BYTES],
        source: [c_char; SIPRAL_ADDRESS_BYTES],
    }

    impl Buffers {
        fn new() -> Self {
            Self {
                data: vec![0; SIPRAL_MESSAGE_BYTES],
                destination: [0; SIPRAL_ADDRESS_BYTES],
                source: [0; SIPRAL_ADDRESS_BYTES],
            }
        }

        fn transmit(&mut self) -> SipralTransmit {
            SipralTransmit {
                size: size_of::<SipralTransmit>(),
                transport: u32::MAX,
                protocol: u32::MAX,
                data: self.data.as_mut_ptr(),
                capacity: self.data.len(),
                len: 0,
                destination: self.destination.as_mut_ptr(),
                destination_capacity: self.destination.len(),
                destination_len: 0,
                source: self.source.as_mut_ptr(),
                source_capacity: self.source.len(),
                source_len: 0,
            }
        }

        /// The message, where it goes, and where from.
        fn taken(&self, transmit: &SipralTransmit) -> (Vec<u8>, String, String) {
            let text = |buffer: &[c_char]| {
                unsafe { CStr::from_ptr(buffer.as_ptr()) }
                    .to_string_lossy()
                    .into_owned()
            };
            (
                self.data.get(..transmit.len).unwrap_or_default().to_vec(),
                text(&self.destination),
                text(&self.source),
            )
        }
    }

    /// Everything `sipral_stack_poll_transmit` hands out, with where it goes.
    fn signalling_out(stack: SipralHandle) -> Vec<(Vec<u8>, String)> {
        let mut buffers = Buffers::new();
        let mut all = Vec::new();
        loop {
            let mut transmit = buffers.transmit();
            let status = unsafe { sipral_stack_poll_transmit(stack, &raw mut transmit) };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            if transmit.len == 0 {
                return all;
            }
            assert_eq!(transmit.transport, SIPRAL_TRANSPORT_MAIN);
            let (message, destination, _) = buffers.taken(&transmit);
            all.push((message, destination));
        }
    }

    /// Everything `sipral_stack_poll_stun` hands out: the request, where it
    /// goes, and the socket it has to leave from.
    fn stun_out(stack: SipralHandle) -> Vec<(Vec<u8>, String, String)> {
        let mut buffers = Buffers::new();
        let mut all = Vec::new();
        loop {
            let mut transmit = buffers.transmit();
            let status = unsafe { sipral_stack_poll_stun(stack, &raw mut transmit) };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            if transmit.len == 0 {
                return all;
            }
            assert_eq!(transmit.transport, 0);
            all.push(buffers.taken(&transmit));
        }
    }

    fn from_server(stack: SipralHandle, data: &[u8], now_ms: u64) -> SipralStatus {
        unsafe {
            sipral_stack_receive_datagram(
                stack,
                SIPRAL_TRANSPORT_MAIN,
                data.as_ptr(),
                data.len(),
                SERVER.as_ptr().cast::<c_char>(),
                SERVER.len(),
                ptr::null(),
                0,
                now_ms,
            )
        }
    }

    fn on_media_socket(stack: SipralHandle, data: &[u8], from: &str, now_ms: u64) -> SipralStatus {
        unsafe {
            sipral_stack_receive_stun(
                stack,
                data.as_ptr(),
                data.len(),
                from.as_ptr().cast::<c_char>(),
                from.len(),
                MEDIA.as_ptr().cast::<c_char>(),
                MEDIA.len(),
                now_ms,
            )
        }
    }

    fn map_media(stack: SipralHandle, now_ms: u64) -> SipralStatus {
        unsafe { sipral_stack_nat_map(stack, MEDIA.as_ptr().cast::<c_char>(), MEDIA.len(), now_ms) }
    }

    fn account_on(stack: SipralHandle) -> SipralHandle {
        let settings = account_config();
        let mut account = SIPRAL_HANDLE_NONE;
        let status = unsafe {
            crate::account::sipral_account_add(stack, ptr::from_ref(&settings), &raw mut account)
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        account
    }

    fn header(message: &[u8], name: &str) -> Option<String> {
        String::from_utf8_lossy(message)
            .split("\r\n")
            .find_map(|line| line.strip_prefix(&format!("{name}: ")).map(str::to_owned))
    }

    #[test]
    fn stun_needs_a_server_and_a_server_needs_stun() {
        let mut observed = Observed::default();
        let mut settings = asking(&mut observed);
        settings.stun_server = ptr::null();
        settings.stun_server_len = 0;
        assert_eq!(create(&settings).0, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("names no server"));

        let mut settings = asking(&mut observed);
        settings.nat = SipralNat::Off as u32;
        assert_eq!(create(&settings).0, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("nat does not ask one"));

        let mut settings = asking(&mut observed);
        (settings.stun_server, settings.stun_server_len) = as_text("stun.example.net:3478");
        assert_eq!(create(&settings).0, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("not an address"));

        let mut settings = asking(&mut observed);
        settings.nat = 3;
        assert_eq!(create(&settings).0, SipralStatus::InvalidArgument);
    }

    #[test]
    fn the_signalling_socket_is_asked_and_its_answer_moves_the_account_onto_it() {
        let mut observed = Observed::default();
        let stack = asking_stack(&mut observed);
        let account = account_on(stack);
        assert_eq!(
            unsafe { sipral_account_register(stack, account, 10) },
            SipralStatus::Ok
        );

        // the Binding request goes first, to the server, on the SIP socket's
        // own transport; the REGISTER sent before any answer came back still
        // names the socket's own address
        let out = signalling_out(stack);
        assert_eq!(out.len(), 2, "{out:?}");
        assert!(is_stun(&out[0].0));
        assert_eq!(out[0].1, SERVER);
        assert_eq!(
            header(&out[1].0, "Contact").as_deref(),
            Some("<sip:alice@192.0.2.10:5060>")
        );

        assert_eq!(
            from_server(stack, &answer(&out[0].0, SIP_PUBLIC), 20),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let _ = poll(stack, 20);
        assert_eq!(
            mapped(),
            vec![Mapped {
                mapping: SipralNatMapping::Learned as u32,
                signalling: 1,
                transport: SIPRAL_TRANSPORT_MAIN,
                accounts: 1,
                local: BIND.to_owned(),
                public: SIP_PUBLIC.to_owned(),
                previous: String::new(),
            }]
        );
        // and the registrar is told at once, without waiting for a refresh
        let out = signalling_out(stack);
        let register = out
            .iter()
            .find(|(message, _)| message.starts_with(b"REGISTER "))
            .expect("a REGISTER went out with the new Contact");
        assert_eq!(
            header(&register.0, "Contact").as_deref(),
            Some("<sip:alice@203.0.113.7:41000>")
        );
    }

    #[test]
    fn an_account_added_after_the_answer_starts_on_the_public_address() {
        let mut observed = Observed::default();
        let stack = asking_stack(&mut observed);
        let out = signalling_out(stack);
        assert_eq!(
            from_server(stack, &answer(&out[0].0, SIP_PUBLIC), 5),
            SipralStatus::Ok
        );
        let _ = poll(stack, 5);
        assert_eq!(mapped()[0].accounts, 0, "no account was there to move");

        let account = account_on(stack);
        assert_eq!(
            unsafe { sipral_account_register(stack, account, 10) },
            SipralStatus::Ok
        );
        let out = signalling_out(stack);
        assert_eq!(
            header(&out.last().expect("the REGISTER").0, "Contact").as_deref(),
            Some("<sip:alice@203.0.113.7:41000>")
        );
    }

    #[test]
    fn a_media_socket_is_mapped_before_its_call_and_the_offer_names_what_the_server_saw() {
        let mut observed = Observed::default();
        let stack = asking_stack(&mut observed);
        let account = account_on(stack);
        let _ = signalling_out(stack);

        assert_eq!(map_media(stack, 10), SipralStatus::Ok);
        let out = stun_out(stack);
        assert_eq!(out.len(), 1);
        assert!(is_stun(&out[0].0));
        assert_eq!(out[0].1, SERVER);
        assert_eq!(
            out[0].2, MEDIA,
            "sent from any other socket it asks the wrong question"
        );

        // before the answer, a call on the socket would name an address
        // nobody outside can reach, so it is refused rather than written
        let (status, _) = place(stack, account, &managed_config(), 20);
        assert_eq!(status, SipralStatus::WrongState);
        assert!(last_error_text().contains("has not answered"));

        // only the server is believed
        let forged = answer(&out[0].0, "198.51.100.66:9");
        assert_eq!(
            on_media_socket(stack, &forged, "198.51.100.66:3478", 30),
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            on_media_socket(stack, &answer(&out[0].0, MEDIA_PUBLIC), SERVER, 30),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let _ = poll(stack, 30);
        let said = mapped();
        assert_eq!(said.len(), 1);
        assert_eq!(said[0].signalling, 0);
        assert_eq!(said[0].local, MEDIA);
        assert_eq!(said[0].public, MEDIA_PUBLIC);

        let (status, _) = place(stack, account, &managed_config(), 40);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let out = signalling_out(stack);
        let invite = out
            .iter()
            .find(|(message, _)| message.starts_with(b"INVITE "))
            .expect("the INVITE");
        let text = String::from_utf8_lossy(&invite.0).into_owned();
        assert!(text.contains("c=IN IP4 203.0.113.7\r\n"), "{text}");
        assert!(text.contains("m=audio 41002 "), "{text}");
        assert!(text.contains("a=rtcp-mux\r\n"), "{text}");

        // the answer was spent by the call it described
        let (status, _) = place(stack, account, &managed_config(), 50);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let out = signalling_out(stack);
        let second = out
            .iter()
            .find(|(message, _)| message.starts_with(b"INVITE "))
            .expect("the second INVITE");
        assert!(
            String::from_utf8_lossy(&second.0).contains("c=IN IP4 192.0.2.10\r\n"),
            "a socket nobody asked about again is described by its own address"
        );
    }

    #[test]
    fn a_media_socket_the_server_never_answers_for_is_described_by_its_own_address() {
        let mut observed = Observed::default();
        let stack = asking_stack(&mut observed);
        let account = account_on(stack);
        assert_eq!(map_media(stack, 0), SipralStatus::Ok);
        let mut sent = stun_out(stack).len();
        let mut now = 0;
        while mapped().is_empty() && now < 10_000 {
            now += 250;
            let _ = poll(stack, now);
            sent += stun_out(stack).len();
            let _ = signalling_out(stack);
        }
        assert_eq!(sent, 4, "four requests, then it stops");
        assert!(now <= 6_000, "gave up at {now} ms");
        let (status, _) = place(stack, account, &managed_config(), now);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let out = signalling_out(stack);
        let invite = out
            .iter()
            .find(|(message, _)| message.starts_with(b"INVITE "))
            .expect("the INVITE");
        assert!(String::from_utf8_lossy(&invite.0).contains("m=audio 40000 "));
    }

    #[test]
    fn a_stack_that_asks_nobody_has_nothing_to_map() {
        let mut observed = Observed::default();
        let (status, stack) = create(&config(record, &mut observed));
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!(map_media(stack, 0), SipralStatus::WrongState);
        assert!(stun_out(stack).is_empty());
        assert_eq!(
            on_media_socket(stack, b"\x01\x01\x00\x00", SERVER, 0),
            SipralStatus::WrongState
        );
        assert!(
            signalling_out(stack).is_empty(),
            "no STUN request goes out on a stack that was not asked for one"
        );
    }

    #[test]
    fn a_second_datagram_transport_is_mapped_by_its_own_answer() {
        // a transport of the application's own beside the main one, whose
        // datagrams are handed in by transport number alone, the way every
        // SIP message on it is: the answer is that transport's socket's, and
        // nobody else's
        const SECOND: u32 = 2;
        const SECOND_AT: &str = "192.0.2.10:5070";
        let mut observed = Observed::default();
        let stack = asking_stack(&mut observed);
        let _ = signalling_out(stack);
        let status = unsafe {
            crate::transport::sipral_stack_transport_bind(
                stack,
                SECOND,
                crate::stack::SipralTransport::Udp as u32,
                SECOND_AT.as_ptr().cast::<c_char>(),
                SECOND_AT.len(),
                ptr::null(),
                0,
                10,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());

        let mut buffers = Buffers::new();
        let mut transmit = buffers.transmit();
        let status = unsafe { sipral_stack_poll_transmit(stack, &raw mut transmit) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(
            transmit.transport, SECOND,
            "it leaves by the transport it asks about"
        );
        let (request, destination, _) = buffers.taken(&transmit);
        assert!(is_stun(&request));
        assert_eq!(destination, SERVER);

        let reply = answer(&request, "203.0.113.7:41070");
        let status = unsafe {
            sipral_stack_receive_datagram(
                stack,
                SECOND,
                reply.as_ptr(),
                reply.len(),
                SERVER.as_ptr().cast::<c_char>(),
                SERVER.len(),
                ptr::null(),
                0,
                20,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let _ = poll(stack, 20);
        assert_eq!(
            mapped(),
            vec![Mapped {
                mapping: SipralNatMapping::Learned as u32,
                signalling: 1,
                transport: SECOND,
                accounts: 0,
                local: SECOND_AT.to_owned(),
                public: "203.0.113.7:41070".to_owned(),
                previous: String::new(),
            }]
        );
    }

    #[test]
    fn a_media_socket_named_again_waits_for_its_new_answer_and_hears_it() {
        let mut observed = Observed::default();
        let stack = asking_stack(&mut observed);
        let account = account_on(stack);
        let _ = signalling_out(stack);
        assert_eq!(map_media(stack, 10), SipralStatus::Ok);
        let out = stun_out(stack);
        assert_eq!(
            on_media_socket(stack, &answer(&out[0].0, MEDIA_PUBLIC), SERVER, 20),
            SipralStatus::Ok
        );
        let _ = poll(stack, 20);
        assert_eq!(mapped().len(), 1);

        // named again before any call used the answer: the same answer comes
        // back, and the application waiting for the event still gets one
        assert_eq!(map_media(stack, 30), SipralStatus::Ok);
        let (status, _) = place(stack, account, &managed_config(), 35);
        assert_eq!(
            status,
            SipralStatus::WrongState,
            "the old answer is not lent to a call while the new one is asked"
        );
        let out = stun_out(stack);
        assert_eq!(out.len(), 1);
        assert_eq!(
            on_media_socket(stack, &answer(&out[0].0, MEDIA_PUBLIC), SERVER, 40),
            SipralStatus::Ok
        );
        let _ = poll(stack, 40);
        let said = mapped();
        assert_eq!(said.len(), 1, "{said:?}");
        assert_eq!(said[0].mapping, SipralNatMapping::Learned as u32);
        assert_eq!(said[0].public, MEDIA_PUBLIC);
    }

    #[test]
    fn the_signalling_socket_is_not_a_media_socket_to_map() {
        let mut observed = Observed::default();
        let stack = asking_stack(&mut observed);
        let status =
            unsafe { sipral_stack_nat_map(stack, BIND.as_ptr().cast::<c_char>(), BIND.len(), 0) };
        assert_eq!(status, SipralStatus::InvalidArgument);
    }
}
