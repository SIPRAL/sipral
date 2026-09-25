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
//!   on it with [`sipral_stack_receive_stun`] until the call is placed on it:
//!   the socket is asked again every twenty-five seconds while it waits.
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
        /// A later answer named another address: the NAT let the mapping go
        /// and made a new one, or the network under the socket changed.
        /// `previous` is what it was. About a signalling socket, or a media
        /// socket still waiting for its call.
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

codes! {
    /// What a media socket's relay came to. Names for
    /// `sipral_nat_relay_event_t::outcome`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralNatRelay: u32 {
        /// The TURN server allocated a relay for the socket: `relayed` is
        /// the address it relays from. A call placed, rung or answered on
        /// the socket from now on offers it as its relayed ICE candidate.
        Allocated = 1,
        /// There is no relay for the socket: the server refused (`code` says
        /// with what), did not answer in thirty-nine and a half seconds, or
        /// took back an allocation it had made. A call on the socket goes
        /// without one, and ICE finds what path it can on the rest.
        Failed = 2,
    }
}

record! {
    /// What a [`SipralEventKind::NatRelay`](crate::event::SipralEventKind::NatRelay)
    /// carries.
    ///
    /// The addresses and the reason are text, not NUL-terminated, and the
    /// library's: valid for as long as the callback runs. Nothing of the
    /// credential is in any of them.
    #[derive(Clone, Copy)]
    pub struct SipralNatRelayEvent {
        /// A [`SipralNatRelay`].
        pub outcome: u32,
        /// For `SIPRAL_NAT_RELAY_FAILED`, the STUN error code the server
        /// refused with — 401 for a credential it does not accept, 486 for a
        /// user at its allocation quota, 508 for a server with nothing left —
        /// and zero when there was none: no answer at all, or an answer this
        /// end could not accept. Zero for `SIPRAL_NAT_RELAY_ALLOCATED`.
        pub code: u32,
        /// The media socket, as `sipral_stack_nat_map` named it.
        pub local: *const c_char,
        /// How many bytes of it.
        pub local_len: usize,
        /// The relayed address, `host:port`. Empty for
        /// `SIPRAL_NAT_RELAY_FAILED`.
        pub relayed: *const c_char,
        /// How many bytes of it.
        pub relayed_len: usize,
        /// Where the server saw the socket from, when it said. Empty
        /// otherwise.
        pub mapped: *const c_char,
        /// How many bytes of it.
        pub mapped_len: usize,
        /// Why there is no relay, in English, for a log. Empty for
        /// `SIPRAL_NAT_RELAY_ALLOCATED`.
        pub reason: *const c_char,
        /// How many bytes of it.
        pub reason_len: usize,
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

/// The TURN server a stack's configuration names, and the credential it
/// knows this end by — or `None` for a stack that names none.
///
/// The two strings are the caller's, borrowed for as long as the
/// configuration is: [`Nat::start`] copies them into the one place they are
/// kept, whose password is overwritten when it is dropped, and nothing else
/// holds a copy.
///
/// # Safety
///
/// `config.turn_server`, `config.turn_username` and `config.turn_password`
/// must each be readable for the length beside it.
pub(crate) unsafe fn turn_configured<'a>(
    config: &SipralStackConfig,
) -> Result<Option<Turn<'a>>, Fail> {
    let server = unsafe { text(config.turn_server, config.turn_server_len, "turn_server") }?;
    let username = unsafe {
        text(
            config.turn_username,
            config.turn_username_len,
            "turn_username",
        )
    }?;
    // read as bytes and checked here rather than by `text`, whose refusal
    // names the offset of what it refused: a password's shape is not
    // something an error text should describe
    let password = unsafe {
        crate::text::bytes(
            config.turn_password.cast::<u8>(),
            config.turn_password_len,
            "turn_password",
        )
    }?;
    let Some(server) = server else {
        return if username.is_some() || password.is_some() {
            Err(fail(
                SipralStatus::InvalidArgument,
                "turn_username or turn_password is set and turn_server names no server to use \
                 them with",
            ))
        } else {
            Ok(None)
        };
    };
    if config.nat != SipralNat::Stun as u32 {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "turn_server names a server and nat is not SIPRAL_NAT_STUN: a relay is allocated for \
             the media sockets sipral_stack_nat_map names, which is SIPRAL_NAT_STUN's",
        ));
    }
    let Ok(address) = server.parse::<SocketAddr>() else {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "turn_server is {server:?}, which is not an address and a port; resolving a name \
                 is the application's, as it is for stun_server"
            ),
        ));
    };
    let password = password.and_then(|raw| std::str::from_utf8(raw).ok());
    let (Some(username), Some(password)) = (username, password) else {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "turn_server needs turn_username and turn_password, the password as UTF-8: a TURN \
             server that relays for anyone is one somebody else is already using",
        ));
    };
    relaying(Turn {
        server: address,
        username,
        password,
    })
}

/// The relay a call described on a media socket takes: a
/// [`sipral::Relay`], in a build with ICE to use one, and a type with no
/// values in a build without.
#[cfg(feature = "ice")]
pub(crate) type HeldRelay = Option<sipral::Relay>;

/// The relay a call described on a media socket takes: never one, without
/// ICE.
#[cfg(not(feature = "ice"))]
pub(crate) type HeldRelay = Option<core::convert::Infallible>;

/// A TURN server and the credential it knows this end by, borrowed from the
/// caller's configuration.
#[derive(Clone, Copy)]
// read only where there is STUN to name media sockets with and ICE to hand
// a relay to: a build without either refuses the configuration first
#[cfg_attr(not(all(feature = "stun", feature = "ice")), allow(dead_code))]
pub(crate) struct Turn<'a> {
    server: SocketAddr,
    username: &'a str,
    password: &'a str,
}

#[cfg(feature = "ice")]
#[allow(clippy::unnecessary_wraps)]
const fn relaying(turn: Turn<'_>) -> Result<Option<Turn<'_>>, Fail> {
    Ok(Some(turn))
}

#[cfg(not(feature = "ice"))]
fn relaying(_turn: Turn<'_>) -> Result<Option<Turn<'_>>, Fail> {
    Err(fail(
        SipralStatus::NotSupported,
        "turn_server names a relay and this build has no ICE to use one with: \
         SIPRAL_FEATURE_ICE is clear in sipral_capabilities",
    ))
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
    /// The relays on the TURN server the configuration named, one per
    /// media socket, until each is handed to its call.
    #[cfg(feature = "ice")]
    relays: Option<sipral::Relays>,
    /// Requests for the TURN server, on their way out through
    /// [`sipral_stack_poll_stun`] after the STUN ones. Not superseded the
    /// way a Binding request is: an Allocate after its 401 is a different
    /// request, not a newer copy of the first.
    #[cfg(feature = "ice")]
    relay_out: VecDeque<sipral::StunDatagram>,
}

/// The text one event's three addresses are read from, and the event.
pub(crate) type Raised = (SipralEvent, String);

#[cfg(feature = "stun")]
impl Nat {
    /// Start asking, when the configuration named a server: the signalling
    /// socket the stack was created with is the first one kept mapped. With
    /// a TURN server named too, every media socket named later is given a
    /// relay on it as well.
    pub(crate) fn start(
        state: &mut StackState,
        server: Option<SocketAddr>,
        turn: Option<Turn<'_>>,
        transport: TransportId,
        protocol: TransportProtocol,
        local: SocketAddr,
        now: Instant,
    ) {
        let Some(server) = server else {
            return;
        };
        let mappings = state.engine.mappings(server);
        #[cfg(feature = "ice")]
        let relays = turn.map(|turn| {
            state
                .engine
                .relays(turn.server, turn.username, turn.password)
        });
        #[cfg(not(feature = "ice"))]
        let _ = turn;
        state.nat.active = Some(Active {
            mappings,
            signalling: HashMap::new(),
            signalling_out: VecDeque::new(),
            media_out: VecDeque::new(),
            #[cfg(feature = "ice")]
            relays,
            #[cfg(feature = "ice")]
            relay_out: VecDeque::new(),
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
        // the relays first: a coturn is usually the STUN server too, from
        // the same address, and `Mappings` takes whatever its server sends
        // on a socket it asked about. `Relays` leaves Binding answers alone
        #[cfg(feature = "ice")]
        let relayed = active
            .relays
            .as_mut()
            .is_some_and(|relays| relays.receive(local, from, data, now));
        #[cfg(not(feature = "ice"))]
        let relayed = false;
        let taken = relayed || active.mappings.receive(local, from, data, now);
        active.sort();
        taken
    }

    /// Time passes for every transaction.
    pub(crate) fn handle_timeout(state: &mut StackState, now: Instant) {
        if let Some(active) = state.nat.active.as_mut() {
            active.mappings.handle_timeout(now);
            #[cfg(feature = "ice")]
            if let Some(relays) = active.relays.as_mut() {
                relays.handle_timeout(now);
            }
            active.sort();
        }
    }

    /// When a transaction next has something to do.
    pub(crate) fn poll_timeout(state: &StackState) -> Option<Instant> {
        let active = state.nat.active.as_ref()?;
        #[cfg(feature = "ice")]
        let relays = active
            .relays
            .as_ref()
            .and_then(sipral::Relays::poll_timeout);
        #[cfg(not(feature = "ice"))]
        let relays = None;
        [active.mappings.poll_timeout(), relays]
            .into_iter()
            .flatten()
            .min()
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
            // every account moved is counted, a REGISTER that could not
            // leave included: its `Contact` names `public` either way, and
            // the registration's own event says it is owed again
            let accounts = match (transport, public) {
                (Some(transport), Some(public)) => {
                    state.agent.readdress(transport, from, public, now)
                }
                _ => 0,
            };
            raised.push(event(
                stack, mapping, transport, accounts, local, public, previous,
            ));
        }
        #[cfg(feature = "ice")]
        if let Some(relays) = state
            .nat
            .active
            .as_mut()
            .and_then(|active| active.relays.as_mut())
        {
            while let Some(said) = relays.poll_event() {
                raised.push(relay_event(stack, said));
            }
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
            // how many moved is the NAT_MAPPING event's to say, and there is
            // no event here: nothing was learned, an account was added
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

    /// The relay a call described on the media socket `local` takes, which
    /// is then the call's: the relayed ICE candidate (see
    /// [`sipral::CallMedia::relay`]).
    ///
    /// `None` for a stack with no TURN server, a socket nobody named, and a
    /// socket the server gave no relay — described without one, and ICE
    /// finds what path it can. A socket still waiting for its relay is
    /// refused, for the reason [`Nat::public_for`] refuses one still waiting
    /// for its mapping.
    #[cfg(feature = "ice")]
    pub(crate) fn relay_for(state: &mut StackState, local: SocketAddr) -> Result<HeldRelay, Fail> {
        let Some(relays) = state
            .nat
            .active
            .as_mut()
            .and_then(|active| active.relays.as_mut())
        else {
            return Ok(None);
        };
        if relays.pending(local) {
            return Err(fail(
                SipralStatus::WrongState,
                format!(
                    "the TURN server has not answered for {local} yet: wait for \
                     SIPRAL_EVENT_KIND_NAT_RELAY about it"
                ),
            ));
        }
        Ok(relays.take(local))
    }

    /// Without ICE no relay was ever allocated, so there is none to take.
    #[cfg(not(feature = "ice"))]
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) const fn relay_for(
        _state: &mut StackState,
        _local: SocketAddr,
    ) -> Result<HeldRelay, Fail> {
        Ok(None)
    }

    /// A call was described on `local`, and the mapping is spent: the next
    /// call on the same socket is mapped again, since nothing kept this one
    /// open in between. A relay the call did not take — a call already
    /// described when it rang — goes back to the server.
    pub(crate) fn spent(state: &mut StackState, local: SocketAddr, now: Instant) {
        if let Some(active) = state.nat.active.as_mut()
            && !active.signalling.contains_key(&local)
        {
            active.mappings.forget(local);
            active.media_out.retain(|request| request.local != local);
            #[cfg(feature = "ice")]
            if let Some(relays) = active.relays.as_mut() {
                relays.release(local, now);
            }
            active.sort();
        }
        #[cfg(not(feature = "ice"))]
        let _ = now;
    }

    /// Relays the engine handed back from descriptions that were refused go
    /// back onto their sockets, kept alive for the next call there: nothing
    /// that named them left, so they are exactly as good as before they were
    /// taken.
    #[cfg(feature = "ice")]
    pub(crate) fn take_back(state: &mut StackState, now: Instant) {
        while let Some(relay) = state.engine.poll_returned_relay() {
            // a stack with no TURN server took no relay to be handed back
            if let Some(active) = state.nat.active.as_mut()
                && let Some(relays) = active.relays.as_mut()
            {
                relays.put_back(relay, now);
                active.sort();
            }
        }
    }

    /// Without ICE no relay was ever taken.
    #[cfg(not(feature = "ice"))]
    pub(crate) const fn take_back(_state: &mut StackState, _now: Instant) {}

    /// A media socket named with [`sipral_stack_nat_map`] that will carry no
    /// call after all: it is no longer kept mapped, and its relay goes back
    /// to the server.
    fn unmap(state: &mut StackState, local: SocketAddr, now: Instant) -> Result<(), Fail> {
        let Some(active) = state.nat.active.as_mut() else {
            return Err(not_asking());
        };
        if active.signalling.contains_key(&local) {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!(
                    "{local} is a signalling socket of this stack's, and is kept mapped for as \
                     long as it is bound"
                ),
            ));
        }
        // what the socket's relay still had queued asks for what nobody
        // wants now: an Allocate not yet sent allocates nothing, and a
        // keepalive or a refresh keeps nothing. Only while the socket is
        // still named: once a call was described on it, what waits there is
        // that call's
        #[cfg(feature = "ice")]
        if active.mappings.state(local).is_some() {
            active.relay_out.retain(|queued| queued.local != local);
        }
        Self::spent(state, local, now);
        Ok(())
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
        #[cfg(feature = "ice")]
        if let Some(relays) = active.relays.as_mut() {
            relays.allocate(local, now);
        }
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
        // a call described on a socket with its relay, and still waiting for
        // the session whose media handle would carry what its agent sends:
        // the keepalives and the refresh leave by the queue the socket's
        // relay used before the call, from the same socket, to the same server
        #[cfg(feature = "ice")]
        while let Some((_, datagram)) = state.engine.poll_waiting_transmit() {
            active.relay_out.push_back(sipral::StunDatagram {
                local: datagram.local,
                destination: datagram.destination,
                payload: datagram.payload,
            });
        }
        #[cfg(feature = "ice")]
        let queue = if active.media_out.is_empty() {
            &mut active.relay_out
        } else {
            &mut active.media_out
        };
        #[cfg(not(feature = "ice"))]
        let queue = &mut active.media_out;
        match queue.front() {
            Some(front) if front.payload.len() > room => Err(front.payload.len()),
            Some(_) => Ok(queue.pop_front()),
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
        // then the call described on the socket, which the application has
        // no media handle for yet: the answers to what its relay sent through
        // `sipral_stack_poll_stun`, its refresh above all, which keeps the
        // allocation for a phone that rings longer than its lifetime; and the
        // far end's first connectivity checks, which start with its answer
        // and would otherwise be lost to the call's agent
        if state.engine.receive_early(local, from, data, now) {
            return Ok(());
        }
        Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "not an answer from the STUN or TURN server this stack asks, for a socket it \
                 asked about, nor anything the call on that socket takes: from {from}, on {local}"
            ),
        ))
    }
}

#[cfg(feature = "stun")]
impl Active {
    /// Move what the transactions wrote into the queue of the path it
    /// leaves by: the transport's own, for a signalling socket, and
    /// [`sipral_stack_poll_stun`]'s for a media one.
    ///
    /// A media socket waits in that queue with one request at most: the
    /// newest is the retransmission or the refresh that supersedes what is
    /// there, and an application that leaves the queue alone while a socket
    /// waits minutes for its call is owed that one, not a backlog of them.
    fn sort(&mut self) {
        while let Some(request) = self.mappings.poll_transmit() {
            if let Some(transport) = self.signalling.get(&request.local) {
                self.signalling_out.push_back(Transmit {
                    transport: *transport,
                    destination: request.destination,
                    source: None,
                    payload: Arc::from(request.payload),
                    protocol: TransportProtocol::Udp,
                });
            } else {
                self.media_out
                    .retain(|queued| queued.local != request.local);
                self.media_out.push_back(request);
            }
        }
        #[cfg(feature = "ice")]
        if let Some(relays) = self.relays.as_mut() {
            while let Some(request) = relays.poll_transmit() {
                self.relay_out.push_back(sipral::StunDatagram {
                    local: request.local,
                    destination: request.destination,
                    payload: request.payload,
                });
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
        _turn: Option<Turn<'_>>,
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

    pub(crate) const fn spent(_state: &mut StackState, _local: SocketAddr, _now: Instant) {}

    /// Without STUN no relay was ever taken, so none comes back.
    pub(crate) const fn take_back(_state: &mut StackState, _now: Instant) {}

    fn unmap(_state: &mut StackState, _local: SocketAddr, _now: Instant) -> Result<(), Fail> {
        Err(not_asking())
    }

    /// Without STUN a stack names no media socket, so none has a relay.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) const fn relay_for(
        _state: &mut StackState,
        _local: SocketAddr,
    ) -> Result<HeldRelay, Fail> {
        Ok(None)
    }

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

/// One relay event, and the text its addresses and reason point into, laid
/// out the way [`event`] lays out a mapping's.
#[cfg(all(feature = "stun", feature = "ice"))]
fn relay_event(stack: SipralHandle, said: sipral::RelayEvent) -> Raised {
    let (outcome, code, local, relayed, mapped, reason) = match said {
        sipral::RelayEvent::Allocated {
            local,
            relayed,
            mapped,
        } => (
            SipralNatRelay::Allocated,
            0,
            local,
            relayed.to_string(),
            mapped
                .map(|address| address.to_string())
                .unwrap_or_default(),
            String::new(),
        ),
        sipral::RelayEvent::Failed { local, failure } => (
            SipralNatRelay::Failed,
            refusal_code(failure),
            local,
            String::new(),
            String::new(),
            failure.to_string(),
        ),
    };
    let local = local.to_string();
    let text = format!("{local}{relayed}{mapped}{reason}");
    let base = text.as_ptr().cast::<c_char>();
    let piece = |offset: usize, len: usize| -> *const c_char {
        if len == 0 {
            std::ptr::null()
        } else {
            base.wrapping_add(offset)
        }
    };
    let at_mapped = local.len() + relayed.len();
    let payload = SipralNatRelayEvent {
        outcome: outcome as u32,
        code,
        local: piece(0, local.len()),
        local_len: local.len(),
        relayed: piece(local.len(), relayed.len()),
        relayed_len: relayed.len(),
        mapped: piece(at_mapped, mapped.len()),
        mapped_len: mapped.len(),
        reason: piece(at_mapped + mapped.len(), reason.len()),
        reason_len: reason.len(),
    };
    (crate::event::nat_relay(stack, payload), text)
}

/// The STUN error code a relay failure stands for, or zero for a failure no
/// server answered with (RFC 8656 §19, RFC 8489 §14.8).
#[cfg(all(feature = "stun", feature = "ice"))]
fn refusal_code(failure: sipral::TurnFailure) -> u32 {
    use sipral::TurnFailure;
    match failure {
        TurnFailure::Alternate(_) => 300,
        TurnFailure::Forbidden => 403,
        TurnFailure::Unauthenticated => 401,
        TurnFailure::UnknownAttribute => 420,
        TurnFailure::AllocationMismatch => 437,
        TurnFailure::AddressFamilyNotSupported => 440,
        TurnFailure::WrongCredentials => 441,
        TurnFailure::UnsupportedTransport => 442,
        TurnFailure::PeerAddressFamilyMismatch => 443,
        TurnFailure::QuotaReached => 486,
        TurnFailure::InsufficientCapacity => 508,
        TurnFailure::Rejected { code } => u32::from(code),
        TurnFailure::TimedOut
        | TurnFailure::IntegrityViolated
        | TurnFailure::StaleNonceLoop
        | TurnFailure::BidDown
        | TurnFailure::UnsupportedPasswordAlgorithm
        | TurnFailure::Malformed
        | TurnFailure::FamilyMismatch
        | TurnFailure::ChannelOutOfSync
        | TurnFailure::Oversized => 0,
    }
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
    /// Until that call, the socket is asked again every twenty-five seconds,
    /// as the signalling socket is: nothing else crosses its NAT binding
    /// while it waits, and an answer minutes old names a mapping the NAT may
    /// have let go. Keep sending what `sipral_stack_poll_stun` hands out for
    /// it and handing in what arrives; an answer that differs is
    /// `SIPRAL_NAT_MAPPING_MOVED`, and the call is described by it. At most
    /// one request per socket waits in the queue.
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
    /// Say that a media socket [`sipral_stack_nat_map`] named will carry no
    /// call after all, and give back what the stack keeps for it.
    ///
    /// Its mapping is no longer asked again every twenty-five seconds, and a
    /// request for it still waiting in [`sipral_stack_poll_stun`] is
    /// dropped. With a TURN server configured, its relay goes back to the
    /// server: a Refresh with a lifetime of zero (RFC 8656 §8), waiting in
    /// [`sipral_stack_poll_stun`] when this returns, to be sent from the
    /// socket like everything else there. A socket whose Allocate was sent
    /// and not answered yet asks nothing more, but the server may have
    /// allocated all the same: the answer, handed in through
    /// [`sipral_stack_receive_stun`] as before, is taken for up to the forty
    /// seconds the request would have waited, and an allocation it reports
    /// is given back the same way. Without this the stack keeps the
    /// allocation refreshed for as long as it lives, and after
    /// `sipral_stack_destroy`, which sends nothing, the server holds it — a
    /// port and a share of the account's quota — until its lifetime runs
    /// out, up to ten minutes later.
    ///
    /// For a socket the application closes, a call it decides not to place,
    /// and every socket still named before the stack is destroyed. A socket
    /// a call was placed, rung or answered on has already been spent by that
    /// call, whose relay goes back when the call ends; naming it here, or a
    /// socket never named, does nothing. To be named again the socket goes
    /// through [`sipral_stack_nat_map`] from the start.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` on a stack created without
    /// `SIPRAL_NAT_STUN`, and `SIPRAL_STATUS_INVALID_ARGUMENT` for a
    /// signalling socket of the stack's own, which is kept mapped for as long
    /// as it is bound.
    ///
    /// # Safety
    ///
    /// `local` must be readable for `local_len` bytes.
    fn sipral_stack_nat_unmap(
        stack: SipralHandle,
        local: *const c_char,
        local_len: usize,
        now_ms: u64,
    ) {
        let local = unsafe { crate::media::address(local, local_len, "local") }?;
        with_stack_at(stack, now_ms, |state, now| Nat::unmap(state, local, now))
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
    /// A call placed, rung or answered on a socket with its relay sends
    /// through here too, for as long as it has no media handle: the Binding
    /// indications that keep the NAT binding towards the TURN server open
    /// while the phone rings, and the refresh that keeps the allocation past
    /// its lifetime less a minute — nine minutes with coturn's default. From
    /// the media handle on they leave through `sipral_media_poll_transmit`
    /// with the rest of the call's media path.
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
    /// That includes a call already placed, rung or answered on the socket,
    /// until its media handle exists: everything arriving on the socket
    /// still comes in here, and the call takes what is its own. The TURN
    /// server's answers to what a call with a relay sent through
    /// [`sipral_stack_poll_stun`] — a refresh left unanswered loses the
    /// relay. The far end's first connectivity checks on a call using ICE,
    /// which start with its answer and can arrive before the 200 is read:
    /// one signed with the password the call's description gave out is kept,
    /// the newest sixteen for the socket, and answered by the call's agent
    /// when its session opens (RFC 8445 §7.3) — unless it waited longer than
    /// 39.5 seconds, the far end's transaction for it, or its call ended
    /// first, when it is dropped. And once the session is open, in
    /// the poll between `SIPRAL_EVENT_KIND_MEDIA_STARTED` and
    /// `sipral_call_media`, anything at all, which goes to the session as
    /// through `sipral_media_receive`. From the media handle on, the socket's
    /// datagrams go to `sipral_media_receive` instead.
    ///
    /// `to` is the socket it arrived on, as `local` was given there; `from`
    /// is where it came from. `SIPRAL_STATUS_OK` when it was the STUN
    /// server's answer, which is then the stack's and nobody else's, or the
    /// call's as above; `SIPRAL_STATUS_INVALID_ARGUMENT` for anything else —
    /// early media before the session opens, a datagram from a stranger, a
    /// check nobody can authenticate, an answer from any address but the
    /// server's, a datagram the session dropped — which costs that one
    /// datagram and nothing more. Only the server's own address is believed,
    /// and only an answer to a request this stack sent: that is the whole
    /// defence against a forged answer naming an address of the attacker's
    /// choosing as this end's own.
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

    #[cfg(feature = "ice")]
    use super::SipralNatRelay;
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
        #[cfg(feature = "ice")]
        if seen.kind == SipralEventKind::NatRelay {
            let payload = unsafe { seen.payload.relay };
            let relayed = RelaySaid {
                outcome: payload.outcome,
                code: payload.code,
                local: piece(payload.local, payload.local_len),
                relayed: piece(payload.relayed, payload.relayed_len),
                mapped: piece(payload.mapped, payload.mapped_len),
                reason: piece(payload.reason, payload.reason_len),
            };
            RELAYED.with(|all| all.borrow_mut().push(relayed));
        }
        unsafe { record(event, user_data) };
    }

    /// What one `SIPRAL_EVENT_KIND_NAT_RELAY` said, copied out inside the
    /// callback.
    #[cfg(feature = "ice")]
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RelaySaid {
        outcome: u32,
        code: u32,
        local: String,
        relayed: String,
        mapped: String,
        reason: String,
    }

    #[cfg(feature = "ice")]
    thread_local! {
        static RELAYED: RefCell<Vec<RelaySaid>> = const { RefCell::new(Vec::new()) };
    }

    #[cfg(feature = "ice")]
    fn relayed() -> Vec<RelaySaid> {
        RELAYED.with(|all| std::mem::take(&mut *all.borrow_mut()))
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
        // and the registrar is told at once, without waiting for a refresh,
        // and told to drop the private binding the first REGISTER left it
        let out = signalling_out(stack);
        let register = out
            .iter()
            .find(|(message, _)| message.starts_with(b"REGISTER "))
            .expect("a REGISTER went out with the new Contact");
        assert_eq!(
            header(&register.0, "Contact").as_deref(),
            Some("<sip:alice@203.0.113.7:41000>, <sip:alice@192.0.2.10:5060>;expires=0")
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
    fn a_media_socket_mapped_long_before_its_call_is_described_by_a_fresh_answer() {
        // mapped when the last call ended, placed ten minutes later: the
        // stack asks again while the socket waits, holds at most one request
        // for it however long the application leaves the queue alone, and the
        // call names what the latest answer said
        let mut observed = Observed::default();
        let stack = asking_stack(&mut observed);
        let account = account_on(stack);
        let _ = signalling_out(stack);
        assert_eq!(map_media(stack, 10), SipralStatus::Ok);
        let first = stun_out(stack);
        assert_eq!(
            on_media_socket(stack, &answer(&first[0].0, MEDIA_PUBLIC), SERVER, 30),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let _ = poll(stack, 30);
        let _ = mapped();

        // ten minutes of an application that polls the stack and never the
        // STUN queue: one request is waiting at the end, not two dozen
        let mut now = 30;
        while now < 600_000 {
            now += 1_000;
            let _ = poll(stack, now);
            let _ = signalling_out(stack);
        }
        let waiting = stun_out(stack);
        assert_eq!(
            waiting.len(),
            1,
            "an application that never polled is owed one request, not a backlog"
        );
        assert_eq!(waiting[0].2, MEDIA);

        // and one that does send it hears the next refresh, whose answer is
        // a mapping the NAT made again somewhere else
        let request = loop {
            now += 1_000;
            let _ = poll(stack, now);
            let _ = signalling_out(stack);
            if let Some(request) = stun_out(stack).pop() {
                break request;
            }
            assert!(now < 700_000, "the socket was never asked again");
        };
        assert_eq!(
            on_media_socket(stack, &answer(&request.0, "203.0.113.7:52002"), SERVER, now),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let _ = poll(stack, now);
        let said: Vec<Mapped> = mapped()
            .into_iter()
            .filter(|said| said.local == MEDIA)
            .collect();
        assert_eq!(said.len(), 1, "{said:?}");
        assert_eq!(said[0].mapping, SipralNatMapping::Moved as u32);
        assert_eq!(said[0].signalling, 0);
        assert_eq!(said[0].previous, MEDIA_PUBLIC);
        assert_eq!(said[0].public, "203.0.113.7:52002");

        let (status, _) = place(stack, account, &managed_config(), now);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let out = signalling_out(stack);
        let invite = out
            .iter()
            .find(|(message, _)| message.starts_with(b"INVITE "))
            .expect("the INVITE");
        assert!(String::from_utf8_lossy(&invite.0).contains("m=audio 52002 "));
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

    /// Where the TURN server relays the media socket from, in these tests.
    #[cfg(feature = "ice")]
    const RELAYED_AT: &str = "198.51.100.1:50000";

    /// A stack that asks `SERVER` for mappings and for relays, as one coturn
    /// answering both usually is.
    #[cfg(feature = "ice")]
    fn relaying(observed: &mut Observed) -> SipralStackConfig {
        let mut settings = asking(observed);
        (settings.turn_server, settings.turn_server_len) = as_text(SERVER);
        (settings.turn_username, settings.turn_username_len) = as_text("alice");
        (settings.turn_password, settings.turn_password_len) = as_text("correct horse");
        settings
    }

    /// A TURN server's success response to `request`, written out from RFC
    /// 8656 §7.3 and RFC 8489 §14.2: the request's own method and id, and
    /// for an Allocate the relayed address, the mapped one and ten minutes.
    #[cfg(feature = "ice")]
    fn turn_answer(request: &[u8], relayed: &str, seen: &str) -> Vec<u8> {
        const COOKIE: u32 = 0x2112_a442;
        let xor = |kind: u16, address: &str| -> Vec<u8> {
            let address: SocketAddr = address.parse().expect("an address");
            let IpAddr::V4(ip) = address.ip() else {
                panic!("these tests are IPv4");
            };
            let mut out = kind.to_be_bytes().to_vec();
            out.extend_from_slice(&[0x00, 0x08, 0x00, 0x01]);
            let port = address.port() ^ u16::try_from(COOKIE >> 16).expect("sixteen bits");
            out.extend_from_slice(&port.to_be_bytes());
            out.extend_from_slice(&(u32::from(ip) ^ COOKIE).to_be_bytes());
            out
        };
        let method = u16::from_be_bytes([request[0], request[1]]) & 0x3eef;
        let mut body = Vec::new();
        if method == 0x0003 {
            body.extend(xor(0x0016, relayed));
            body.extend(xor(0x0020, seen));
        }
        // an Allocate and a Refresh are both answered with the lifetime
        // granted, ten minutes (RFC 8656 §7.3, §8)
        if method == 0x0003 || method == 0x0004 {
            body.extend_from_slice(&[0x00, 0x0d, 0x00, 0x04]);
            body.extend_from_slice(&600_u32.to_be_bytes());
        }
        let mut out = (method | 0x0100).to_be_bytes().to_vec();
        out.extend_from_slice(&u16::try_from(body.len()).expect("short").to_be_bytes());
        out.extend_from_slice(request.get(4..20).expect("a whole STUN header"));
        out.extend(body);
        out
    }

    /// Whether `request` is a TURN Allocate (RFC 8656 §7.1).
    #[cfg(feature = "ice")]
    fn is_allocate(request: &[u8]) -> bool {
        is_stun(request) && request.get(..2) == Some(&[0x00, 0x03][..])
    }

    #[cfg(feature = "ice")]
    #[test]
    fn a_turn_server_needs_stun_and_a_credential() {
        let mut observed = Observed::default();
        let mut no_stun = relaying(&mut observed);
        no_stun.nat = SipralNat::Off as u32;
        (no_stun.stun_server, no_stun.stun_server_len) = (ptr::null(), 0);
        assert_eq!(create(&no_stun).0, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("SIPRAL_NAT_STUN"));

        let mut no_password = relaying(&mut observed);
        (no_password.turn_password, no_password.turn_password_len) = (ptr::null(), 0);
        assert_eq!(create(&no_password).0, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("turn_password"));

        let mut no_server = relaying(&mut observed);
        (no_server.turn_server, no_server.turn_server_len) = (ptr::null(), 0);
        assert_eq!(create(&no_server).0, SipralStatus::InvalidArgument);

        let mut named = relaying(&mut observed);
        (named.turn_server, named.turn_server_len) = as_text("turn.example.com:3478");
        assert_eq!(create(&named).0, SipralStatus::InvalidArgument);
        // and the password is in none of what was said about any of them
        assert!(!last_error_text().contains("correct horse"));
    }

    #[cfg(feature = "ice")]
    #[test]
    fn a_media_socket_gets_a_relay_and_the_call_on_it_offers_it_as_a_candidate() {
        let mut observed = Observed::default();
        let _ = mapped();
        let _ = relayed();
        let (status, stack) = create(&relaying(&mut observed));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let account = account_on(stack);
        let _ = signalling_out(stack);
        let _ = poll(stack, 5);
        let _ = mapped();

        assert_eq!(map_media(stack, 10), SipralStatus::Ok);
        let out = stun_out(stack);
        assert_eq!(out.len(), 2, "a Binding request and an Allocate");
        assert!(!is_allocate(&out[0].0));
        assert!(is_allocate(&out[1].0));
        assert_eq!(out[1].1, SERVER);
        assert_eq!(out[1].2, MEDIA);

        // the STUN answer alone is not enough: the relay is on its way
        assert_eq!(
            on_media_socket(stack, &answer(&out[0].0, MEDIA_PUBLIC), SERVER, 20),
            SipralStatus::Ok
        );
        let _ = poll(stack, 20);
        let mut ice = managed_config();
        ice.ice = crate::media::SipralIce::Offered as u32;
        let (status, _) = place(stack, account, &ice, 25);
        assert_eq!(status, SipralStatus::WrongState);
        assert!(last_error_text().contains("TURN server has not answered"));

        // the same server answers both, and each answer reaches its own
        assert_eq!(
            on_media_socket(
                stack,
                &turn_answer(&out[1].0, RELAYED_AT, MEDIA_PUBLIC),
                SERVER,
                30
            ),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let _ = poll(stack, 30);
        let said = relayed();
        assert_eq!(
            said,
            vec![RelaySaid {
                outcome: SipralNatRelay::Allocated as u32,
                code: 0,
                local: MEDIA.to_owned(),
                relayed: RELAYED_AT.to_owned(),
                mapped: MEDIA_PUBLIC.to_owned(),
                reason: String::new(),
            }]
        );

        let (status, _) = place(stack, account, &ice, 40);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let out = signalling_out(stack);
        let invite = out
            .iter()
            .find(|(message, _)| message.starts_with(b"INVITE "))
            .expect("the INVITE");
        let text = String::from_utf8_lossy(&invite.0).into_owned();
        assert!(
            text.contains("198.51.100.1 50000 typ relay raddr 203.0.113.7 rport 41002"),
            "{text}"
        );
        assert!(text.contains("c=IN IP4 203.0.113.7\r\n"), "{text}");
    }

    #[cfg(feature = "ice")]
    #[test]
    fn a_relay_the_server_refused_is_said_with_its_code_and_no_credential() {
        let mut observed = Observed::default();
        let _ = relayed();
        let (status, stack) = create(&relaying(&mut observed));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(map_media(stack, 10), SipralStatus::Ok);
        let out = stun_out(stack);
        let allocate = &out[1].0;
        // 486, Allocation Quota Reached (RFC 8656 §19), with no credential
        // asked for first: the error class of the Allocate method
        let mut refusal = vec![0x01, 0x13, 0x00, 0x08];
        refusal.extend_from_slice(allocate.get(4..20).expect("a whole header"));
        refusal.extend_from_slice(&[0x00, 0x09, 0x00, 0x04, 0x00, 0x00, 0x04, 86]);
        assert_eq!(
            on_media_socket(stack, &refusal, SERVER, 20),
            SipralStatus::Ok
        );
        let _ = poll(stack, 20);
        let said = relayed();
        assert_eq!(said.len(), 1, "{said:?}");
        assert_eq!(said[0].outcome, SipralNatRelay::Failed as u32);
        assert_eq!(said[0].code, 486);
        assert!(said[0].relayed.is_empty());
        assert!(!said[0].reason.is_empty());
        assert!(!said[0].reason.contains("correct horse"));
    }

    /// The lifetime a TURN Refresh request asks for (RFC 8656 §7.2, §18.2),
    /// or `None` for a message that is not one.
    #[cfg(feature = "ice")]
    fn refresh_lifetime(message: &[u8]) -> Option<u32> {
        if message.get(..2) != Some(&[0x00, 0x04][..]) {
            return None;
        }
        let mut at = 20;
        while let Some(head) = message.get(at..at + 4) {
            let kind = u16::from_be_bytes([head[0], head[1]]);
            let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
            if kind == 0x000d {
                let value = message.get(at + 4..at + 8)?;
                return Some(u32::from_be_bytes(value.try_into().ok()?));
            }
            at += 4 + len.div_ceil(4) * 4;
        }
        None
    }

    /// A relay allocated for a socket whose call was described when it rang
    /// is not that call's: answering on the socket spends it, and it goes
    /// back to the server rather than being kept alive for a call that will
    /// never take it.
    #[cfg(feature = "ice")]
    #[test]
    fn a_relay_the_call_on_its_socket_does_not_take_goes_back_when_the_socket_is_spent() {
        let mut observed = Observed::default();
        let _ = mapped();
        let _ = relayed();
        let (status, stack) = create(&relaying(&mut observed));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let _account = account_on(stack);
        crate::call::tests::deliver(stack, &crate::call::tests::invitation(), 1_000);
        let _ = poll(stack, 1_000);
        let call = crate::call::tests::called(&observed);
        let _ = signalling_out(stack);
        let ring = crate::call::tests::ring_media_config();
        assert_eq!(
            unsafe {
                crate::call::sipral_call_ring_media(stack, call, ptr::from_ref(&ring), 1_100)
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );

        // the socket named after the ring, and given a relay
        assert_eq!(map_media(stack, 1_200), SipralStatus::Ok);
        let out = stun_out(stack);
        assert_eq!(out.len(), 2, "a Binding request and an Allocate");
        let _ = on_media_socket(stack, &answer(&out[0].0, MEDIA_PUBLIC), SERVER, 1_210);
        let _ = on_media_socket(
            stack,
            &turn_answer(&out[1].0, RELAYED_AT, MEDIA_PUBLIC),
            SERVER,
            1_210,
        );
        let _ = poll(stack, 1_210);
        assert_eq!(relayed().len(), 1, "the relay was allocated");

        assert_eq!(
            unsafe {
                crate::call::sipral_call_answer_media(
                    stack,
                    call,
                    MEDIA.as_ptr().cast::<c_char>(),
                    MEDIA.len(),
                    1_300,
                )
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let out = stun_out(stack);
        assert!(
            out.iter().any(|(request, destination, source)| {
                refresh_lifetime(request) == Some(0) && destination == SERVER && source == MEDIA
            }),
            "the relay nobody took was kept: {:?}",
            out.iter()
                .map(|(request, ..)| refresh_lifetime(request))
                .collect::<Vec<_>>()
        );
    }

    /// A transfer refused for a mistake in its configuration is still there
    /// to take, and so is the socket's relay: nothing was placed, so nothing
    /// may have been spent.
    #[cfg(feature = "ice")]
    #[test]
    fn a_transfer_refused_for_its_configuration_leaves_the_relay_for_the_one_taken_after() {
        let mut observed = Observed::default();
        let _ = mapped();
        let _ = relayed();
        let (status, stack) = create(&relaying(&mut observed));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let _account = account_on(stack);
        let call = crate::call::tests::ready_for_a_transfer(&mut observed, stack);

        assert_eq!(map_media(stack, 1_210), SipralStatus::Ok);
        let out = stun_out(stack);
        assert_eq!(out.len(), 2, "a Binding request and an Allocate");
        let _ = on_media_socket(stack, &answer(&out[0].0, MEDIA_PUBLIC), SERVER, 1_220);
        let _ = on_media_socket(
            stack,
            &turn_answer(&out[1].0, RELAYED_AT, MEDIA_PUBLIC),
            SERVER,
            1_220,
        );
        let _ = poll(stack, 1_220);
        assert_eq!(relayed().len(), 1, "the relay was allocated");

        let mut refused = crate::call::tests::managed_transfer_config();
        refused.ice = crate::media::SipralIce::Offered as u32;
        (refused.destination, refused.destination_len) = as_text("not an address");
        let (status, _, _) = crate::call::tests::accept_transfer(stack, call, &refused);
        assert_eq!(status, SipralStatus::InvalidArgument);

        let mut taken = crate::call::tests::managed_transfer_config();
        taken.ice = crate::media::SipralIce::Offered as u32;
        let (status, _, invite) = crate::call::tests::accept_transfer(stack, call, &taken);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let text = String::from_utf8_lossy(&invite).into_owned();
        assert!(
            text.contains("198.51.100.1 50000 typ relay"),
            "the relay was lost to the refusal: {text}"
        );
    }

    /// `MEDIA` named on `stack`, and both its STUN answer and its relay
    /// given, at `now_ms`.
    #[cfg(feature = "ice")]
    fn relay_on_the_socket(stack: SipralHandle, now_ms: u64) {
        assert_eq!(map_media(stack, now_ms), SipralStatus::Ok);
        let out = stun_out(stack);
        assert_eq!(out.len(), 2, "a Binding request and an Allocate");
        let _ = on_media_socket(stack, &answer(&out[0].0, MEDIA_PUBLIC), SERVER, now_ms);
        let _ = on_media_socket(
            stack,
            &turn_answer(&out[1].0, RELAYED_AT, MEDIA_PUBLIC),
            SERVER,
            now_ms,
        );
        let _ = poll(stack, now_ms);
        let said = relayed();
        assert_eq!(said.len(), 1, "the relay was allocated: {said:?}");
    }

    fn unmap(stack: SipralHandle, local: &str, now_ms: u64) -> SipralStatus {
        unsafe {
            super::sipral_stack_nat_unmap(
                stack,
                local.as_ptr().cast::<c_char>(),
                local.len(),
                now_ms,
            )
        }
    }

    /// A socket named and then not used gives its relay back when the
    /// application says so, and is kept alive no longer.
    #[cfg(feature = "ice")]
    #[test]
    fn a_socket_that_will_carry_no_call_gives_its_relay_back_when_unmapped() {
        let mut observed = Observed::default();
        let _ = mapped();
        let _ = relayed();
        let (status, stack) = create(&relaying(&mut observed));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let _ = signalling_out(stack);
        relay_on_the_socket(stack, 10);

        assert_eq!(
            unmap(stack, MEDIA, 20),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let out = stun_out(stack);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(
            refresh_lifetime(&out[0].0),
            Some(0),
            "a Refresh of lifetime 0"
        );
        assert_eq!((out[0].1.as_str(), out[0].2.as_str()), (SERVER, MEDIA));

        // and nothing more is sent for it: no Binding request every
        // twenty-five seconds, no keepalive towards the TURN server
        for at in [30_000, 60_000, 600_000] {
            let _ = poll(stack, at);
            let out = stun_out(stack);
            assert!(out.is_empty(), "at {at} ms: {out:?}");
        }
        // named again, it is asked about from the start
        assert_eq!(unmap(stack, MEDIA, 600_010), SipralStatus::Ok);
        assert!(
            stun_out(stack).is_empty(),
            "nothing named, nothing given back"
        );
        assert_eq!(map_media(stack, 600_020), SipralStatus::Ok);
        assert_eq!(
            stun_out(stack).len(),
            2,
            "a Binding request and an Allocate"
        );
    }

    /// A socket unmapped while its Allocate is still on its way: the server
    /// allocates all the same when the request reaches it, and the answer is
    /// what says so, so the relay goes back when that answer arrives rather
    /// than being held on the server for its whole lifetime.
    #[cfg(feature = "ice")]
    #[test]
    fn a_socket_unmapped_before_its_relay_is_answered_gives_it_back_on_the_answer() {
        let mut observed = Observed::default();
        let _ = mapped();
        let _ = relayed();
        let (status, stack) = create(&relaying(&mut observed));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let _ = signalling_out(stack);
        assert_eq!(map_media(stack, 10), SipralStatus::Ok);
        let out = stun_out(stack);
        assert_eq!(out.len(), 2, "a Binding request and an Allocate");
        let allocate = out
            .iter()
            .find(|(request, ..)| is_allocate(request))
            .expect("the Allocate")
            .0
            .clone();

        assert_eq!(unmap(stack, MEDIA, 20), SipralStatus::Ok);
        assert!(stun_out(stack).is_empty(), "nothing allocated yet");
        assert_eq!(
            on_media_socket(
                stack,
                &turn_answer(&allocate, RELAYED_AT, MEDIA_PUBLIC),
                SERVER,
                30
            ),
            SipralStatus::Ok,
            "the server's answer is the stack's: {}",
            last_error_text()
        );
        let out = stun_out(stack);
        assert!(
            out.iter().any(|(request, destination, source)| {
                refresh_lifetime(request) == Some(0) && destination == SERVER && source == MEDIA
            }),
            "the allocation the answer names was left on the server: {out:?}"
        );
        let _ = poll(stack, 40);
        assert!(relayed().is_empty(), "a socket unmapped hears nothing more");
        // and nothing more is sent for it
        for at in [30_000, 60_000, 600_000] {
            let _ = poll(stack, at);
            assert!(stun_out(stack).is_empty(), "at {at} ms");
        }

        // named and unmapped before anything was taken out to send: nothing
        // at all leaves for it, the Allocate included
        assert_eq!(map_media(stack, 600_010), SipralStatus::Ok);
        assert_eq!(unmap(stack, MEDIA, 600_020), SipralStatus::Ok);
        assert!(stun_out(stack).is_empty(), "a request nobody wants went");
    }

    /// Unmapping the socket a call is ringing on touches nothing of the
    /// call's: its relay is the call's, kept alive and given back when the
    /// call ends, and unmapping after that is as harmless.
    #[cfg(feature = "ice")]
    #[test]
    fn unmapping_the_socket_of_a_call_leaves_the_call_its_relay() {
        let mut observed = Observed::default();
        let _ = mapped();
        let _ = relayed();
        let (status, stack) = create(&relaying(&mut observed));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let account = account_on(stack);
        let _ = signalling_out(stack);
        relay_on_the_socket(stack, 10);
        let mut ice = managed_config();
        ice.ice = crate::media::SipralIce::Offered as u32;
        let (status, call) = place(stack, account, &ice, 20);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = signalling_out(stack)
            .into_iter()
            .find(|(message, _)| message.starts_with(b"INVITE "))
            .expect("the INVITE")
            .0;
        crate::call::tests::deliver(stack, &crate::call::tests::ringing(&invite), 30);
        // a keepalive of the call's waits in the queue when the socket is
        // unmapped: asked for with no room to take it, it stays there
        let _ = poll(stack, 15_100);
        let _ = signalling_out(stack);
        let mut buffers = Buffers::new();
        let mut cramped = buffers.transmit();
        cramped.capacity = 4;
        assert_ne!(
            unsafe { sipral_stack_poll_stun(stack, &raw mut cramped) },
            SipralStatus::Ok,
            "a keepalive fits in four bytes"
        );
        assert_eq!(unmap(stack, MEDIA, 15_110), SipralStatus::Ok);
        let out = stun_out(stack);
        assert!(
            out.iter()
                .any(|(request, ..)| request.get(..2) == Some(&[0x00, 0x11][..])),
            "the call's keepalive was dropped: {out:?}"
        );
        assert!(
            out.iter()
                .all(|(request, ..)| refresh_lifetime(request) != Some(0)),
            "the call's relay was given back under it: {out:?}"
        );

        crate::call::tests::deliver(
            stack,
            &crate::call::tests::answered_with(&invite, 486, "Busy Here"),
            20_000,
        );
        let _ = poll(stack, 20_000);
        let mut buffers = crate::media::tests::Buffers::new();
        let mut given_back = 0;
        loop {
            let mut from_call = SIPRAL_HANDLE_NONE;
            let mut packet = buffers.packet();
            let status = unsafe {
                crate::media::sipral_stack_poll_farewell(stack, &raw mut from_call, &raw mut packet)
            };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            if packet.len == 0 {
                break;
            }
            assert_eq!(from_call, call);
            let (payload, destination) = buffers.taken(&packet);
            if destination == SERVER && refresh_lifetime(&payload) == Some(0) {
                given_back += 1;
            }
        }
        assert_eq!(given_back, 1, "given back once, by the call");
        assert_eq!(unmap(stack, MEDIA, 20_010), SipralStatus::Ok);
        let _ = poll(stack, 20_020);
        assert!(stun_out(stack).is_empty(), "nothing given back twice");
    }

    #[test]
    fn unmapping_needs_a_stack_that_asks_and_a_media_socket() {
        let mut observed = Observed::default();
        let (status, quiet) = create(&config(record, &mut observed));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(unmap(quiet, MEDIA, 10), SipralStatus::WrongState);

        let (status, stack) = create(&asking(&mut observed));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(unmap(stack, BIND, 10), SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("signalling socket"));
        assert_eq!(
            unmap(stack, "not an address", 10),
            SipralStatus::InvalidArgument
        );
    }

    /// A transfer the user agent refuses after the relay went into its offer
    /// — a `Replaces` among its headers is the REFER's to give — sent
    /// nothing that named the relay, and the relay goes back onto the socket
    /// for the transfer taken after.
    #[cfg(feature = "ice")]
    #[test]
    fn a_transfer_the_user_agent_refuses_leaves_the_relay_for_the_one_taken_after() {
        let mut observed = Observed::default();
        let _ = mapped();
        let _ = relayed();
        let (status, stack) = create(&relaying(&mut observed));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let _account = account_on(stack);
        let call = crate::call::tests::ready_for_a_transfer(&mut observed, stack);
        relay_on_the_socket(stack, 1_210);

        let (name, name_len) = as_text("Replaces");
        let (value, value_len) = as_text("other@192.0.2.1;to-tag=x;from-tag=y");
        let replacing = [crate::header::SipralHeader {
            name,
            name_len,
            value,
            value_len,
        }];
        let mut refused = crate::call::tests::managed_transfer_config();
        refused.ice = crate::media::SipralIce::Offered as u32;
        refused.headers = replacing.as_ptr();
        refused.headers_len = replacing.len();
        let (status, _, invite) = crate::call::tests::accept_transfer(stack, call, &refused);
        assert_eq!(
            status,
            SipralStatus::InvalidArgument,
            "{}",
            last_error_text()
        );
        assert!(invite.is_empty(), "nothing named the relay");
        assert!(
            stun_out(stack)
                .iter()
                .all(|(request, ..)| refresh_lifetime(request) != Some(0)),
            "the relay was deleted rather than kept"
        );

        let mut taken = crate::call::tests::managed_transfer_config();
        taken.ice = crate::media::SipralIce::Offered as u32;
        let (status, _, invite) = crate::call::tests::accept_transfer(stack, call, &taken);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let text = String::from_utf8_lossy(&invite).into_owned();
        assert!(
            text.contains("198.51.100.1 50000 typ relay"),
            "the relay was lost to the refusal: {text}"
        );
    }

    /// A second ring on a call already rung is refused, and the relay the
    /// socket was given for it goes back onto the socket.
    #[cfg(feature = "ice")]
    #[test]
    fn a_ring_refused_leaves_the_relay_on_its_socket() {
        let mut observed = Observed::default();
        let _ = mapped();
        let _ = relayed();
        let (status, stack) = create(&relaying(&mut observed));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let _account = account_on(stack);
        crate::call::tests::deliver(stack, &crate::call::tests::invitation(), 1_000);
        let _ = poll(stack, 1_000);
        let call = crate::call::tests::called(&observed);
        let _ = signalling_out(stack);
        let ring = crate::call::tests::ring_media_config();
        assert_eq!(
            unsafe {
                crate::call::sipral_call_ring_media(stack, call, ptr::from_ref(&ring), 1_100)
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        relay_on_the_socket(stack, 1_200);

        let mut again = crate::call::tests::ring_media_config();
        again.ice = crate::media::SipralIce::Offered as u32;
        assert_eq!(
            unsafe {
                crate::call::sipral_call_ring_media(stack, call, ptr::from_ref(&again), 1_300)
            },
            SipralStatus::WrongState
        );
        // still the socket's: kept alive, and given back when it is unmapped
        let _ = poll(stack, 30_000);
        let out = stun_out(stack);
        assert!(
            out.iter()
                .any(|(request, destination, _)| is_stun(request) && destination == SERVER),
            "no keepalive for a relay the refusal dropped: {out:?}"
        );
        assert_eq!(unmap(stack, MEDIA, 30_010), SipralStatus::Ok);
        let out = stun_out(stack);
        assert!(
            out.iter()
                .any(|(request, ..)| refresh_lifetime(request) == Some(0)),
            "{out:?}"
        );
    }

    /// A relayed call that rings for a long time: until its media handle
    /// exists, what its agent sends leaves through `sipral_stack_poll_stun`,
    /// and the server's answers come back through
    /// `sipral_stack_receive_stun`, so the allocation is refreshed and not
    /// lost nine minutes in.
    #[cfg(feature = "ice")]
    #[test]
    fn a_relayed_call_that_rings_for_ten_minutes_keeps_its_relay() {
        let mut observed = Observed::default();
        let _ = mapped();
        let _ = relayed();
        let (status, stack) = create(&relaying(&mut observed));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let account = account_on(stack);
        let _ = signalling_out(stack);
        relay_on_the_socket(stack, 10);
        let mut ice = managed_config();
        ice.ice = crate::media::SipralIce::Offered as u32;
        let (status, call) = place(stack, account, &ice, 20);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = signalling_out(stack)
            .into_iter()
            .find(|(message, _)| message.starts_with(b"INVITE "))
            .expect("the INVITE")
            .0;
        crate::call::tests::deliver(stack, &crate::call::tests::ringing(&invite), 30);
        let _ = poll(stack, 30);

        let mut keepalives = 0;
        let mut refreshes = 0;
        let mut at = 30;
        while at < 660_000 {
            at += 5_000;
            let _ = poll(stack, at);
            let _ = signalling_out(stack);
            for (request, destination, source) in stun_out(stack) {
                assert_eq!((destination.as_str(), source.as_str()), (SERVER, MEDIA));
                match request.get(..2) {
                    // a Binding indication
                    Some([0x00, 0x11]) => keepalives += 1,
                    Some([0x00, 0x04]) => {
                        refreshes += 1;
                        assert_eq!(
                            on_media_socket(
                                stack,
                                &turn_answer(&request, RELAYED_AT, MEDIA_PUBLIC),
                                SERVER,
                                at
                            ),
                            SipralStatus::Ok,
                            "the refresh's answer has no way in: {}",
                            last_error_text()
                        );
                    }
                    _ => {}
                }
            }
        }
        assert!(
            keepalives >= 20,
            "{keepalives} keepalives in eleven minutes"
        );
        assert!(refreshes >= 1, "the allocation was never refreshed");
        assert!(relayed().is_empty(), "nothing about the relay was said");

        // and it is still the call's to give back when the far end refuses
        crate::call::tests::deliver(
            stack,
            &crate::call::tests::answered_with(&invite, 486, "Busy Here"),
            at,
        );
        let _ = poll(stack, at);
        let mut buffers = crate::media::tests::Buffers::new();
        let mut given_back = false;
        loop {
            let mut from_call = SIPRAL_HANDLE_NONE;
            let mut packet = buffers.packet();
            let status = unsafe {
                crate::media::sipral_stack_poll_farewell(stack, &raw mut from_call, &raw mut packet)
            };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            if packet.len == 0 {
                break;
            }
            assert_eq!(from_call, call);
            let (payload, destination) = buffers.taken(&packet);
            given_back |= destination == SERVER && refresh_lifetime(&payload) == Some(0);
        }
        assert!(given_back, "the relay was lost while the phone rang");
    }

    /// The same ring, driven only by the deadline `sipral_stack_poll` names,
    /// as an application that sleeps until then does: every keepalive
    /// leaves within its fifteen seconds of the last, and the refresh before
    /// the allocation's ten minutes are up.
    #[cfg(feature = "ice")]
    #[test]
    fn a_ringing_call_is_woken_in_time_for_its_keepalives_and_its_refresh() {
        let mut observed = Observed::default();
        let _ = mapped();
        let _ = relayed();
        let (status, stack) = create(&relaying(&mut observed));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let account = account_on(stack);
        let _ = signalling_out(stack);
        relay_on_the_socket(stack, 10);
        let mut ice = managed_config();
        ice.ice = crate::media::SipralIce::Offered as u32;
        let (status, _call) = place(stack, account, &ice, 20);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = signalling_out(stack)
            .into_iter()
            .find(|(message, _)| message.starts_with(b"INVITE "))
            .expect("the INVITE")
            .0;
        crate::call::tests::deliver(stack, &crate::call::tests::ringing(&invite), 30);

        let mut at = 30;
        let mut last_to_server = 10;
        let mut refreshed_at = Vec::new();
        while at < 1_300_000 {
            let result = poll(stack, at);
            let _ = signalling_out(stack);
            for (request, destination, source) in stun_out(stack) {
                assert_eq!((destination.as_str(), source.as_str()), (SERVER, MEDIA));
                assert!(
                    at - last_to_server <= 15_050,
                    "nothing went to the TURN server between {last_to_server} and {at} ms"
                );
                last_to_server = at;
                if request.get(..2) == Some(&[0x00, 0x04][..]) {
                    refreshed_at.push(at);
                    assert_eq!(
                        on_media_socket(
                            stack,
                            &turn_answer(&request, RELAYED_AT, MEDIA_PUBLIC),
                            SERVER,
                            at
                        ),
                        SipralStatus::Ok,
                        "{}",
                        last_error_text()
                    );
                }
            }
            assert_eq!(result.has_deadline, 1, "nothing to wake for at {at} ms");
            at += result.next_poll_in_ms.max(1);
        }
        assert!(
            refreshed_at.len() >= 2,
            "the allocation is refreshed every nine minutes: {refreshed_at:?}"
        );
        // allocated at 10 ms for ten minutes, and refreshed a minute before
        // they are up
        assert!(
            (530_000..=540_100).contains(&refreshed_at[0]),
            "the first refresh left at {refreshed_at:?} ms"
        );
    }

    /// The far end's ICE credentials, in the answer below and in every check
    /// it sends.
    #[cfg(feature = "ice")]
    const PEER_UFRAG: &str = "farend";
    #[cfg(feature = "ice")]
    const PEER_PWD: &str = "farendpasswordfarendpassword";
    /// The far end's one candidate, which is also where its checks come from.
    #[cfg(feature = "ice")]
    const PEER_CHECKS_FROM: &str = crate::call::tests::PEER_MEDIA;

    /// An answer that agrees to ICE: the far end's credentials, `a=rtcp-mux`
    /// back, and one host candidate that is also its default destination.
    #[cfg(feature = "ice")]
    fn ice_answer() -> Vec<u8> {
        format!(
            "v=0\r\n\
             o=bob 1 1 IN IP4 203.0.113.5\r\n\
             s=-\r\n\
             c=IN IP4 203.0.113.5\r\n\
             t=0 0\r\n\
             m=audio 41000 RTP/AVP 0\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=rtcp-mux\r\n\
             a=ice-ufrag:{PEER_UFRAG}\r\n\
             a=ice-pwd:{PEER_PWD}\r\n\
             a=candidate:1 1 UDP 2130706431 203.0.113.5 41000 typ host\r\n\
             a=sendrecv\r\n"
        )
        .into_bytes()
    }

    /// The value of one `a=` attribute in a message's description.
    #[cfg(feature = "ice")]
    fn attribute(message: &str, name: &str) -> String {
        message
            .split("\r\n")
            .find_map(|line| line.strip_prefix(&format!("a={name}:")))
            .unwrap_or_else(|| panic!("no a={name} in {message}"))
            .to_owned()
    }

    /// The far end's connectivity check towards this end's socket (RFC 8445
    /// §7.2.2): `USERNAME` is this end's fragment, a colon and the far end's,
    /// and it is signed with the password this end's offer gave out.
    #[cfg(feature = "ice")]
    fn check(ufrag: &str, pwd: &str, id: [u8; 12]) -> Vec<u8> {
        signed_check(ufrag, Some(pwd), id)
    }

    /// The same check, signed with `pwd` when there is one and with nothing
    /// at all when there is not.
    #[cfg(feature = "ice")]
    fn signed_check(ufrag: &str, pwd: Option<&str>, id: [u8; 12]) -> Vec<u8> {
        use sipral_nat::stun::{AttributeType, Class, MessageBuilder, Method, TransactionId};
        let mut builder =
            MessageBuilder::new(Class::Request, Method::BINDING, TransactionId::new(id));
        builder
            .add(
                AttributeType::USERNAME,
                format!("{ufrag}:{PEER_UFRAG}").as_bytes(),
            )
            .expect("room for USERNAME");
        builder
            .add_u32(AttributeType::PRIORITY, 0x6e00_01ff)
            .expect("room for PRIORITY");
        builder
            .add_u64(AttributeType::ICE_CONTROLLED, 7)
            .expect("room for ICE-CONTROLLED");
        if let Some(pwd) = pwd {
            builder
                .add_message_integrity(pwd.as_bytes())
                .expect("room for MESSAGE-INTEGRITY");
        }
        builder.add_fingerprint().expect("room for FINGERPRINT");
        builder.finish()
    }

    /// A stack that asks, a mapping for the media socket, and a call placed
    /// on it that offers ICE: the stack, the call, the INVITE, and this end's
    /// ICE fragment and password as the INVITE gave them out.
    #[cfg(feature = "ice")]
    fn ice_call(observed: &mut Observed) -> (SipralHandle, SipralHandle, Vec<u8>, String, String) {
        let stack = asking_stack(observed);
        let account = account_on(stack);
        let _ = signalling_out(stack);
        assert_eq!(map_media(stack, 10), SipralStatus::Ok);
        let out = stun_out(stack);
        assert_eq!(
            on_media_socket(stack, &answer(&out[0].0, MEDIA_PUBLIC), SERVER, 20),
            SipralStatus::Ok
        );
        let _ = poll(stack, 20);
        let _ = mapped();
        let (call, invite, ufrag, pwd) = place_ice(stack, account, 30);
        (stack, call, invite, ufrag, pwd)
    }

    /// A call that offers ICE, placed on the mapped media socket at `now_ms`:
    /// the call, its INVITE, and the ICE fragment and password it gave out.
    #[cfg(feature = "ice")]
    fn place_ice(
        stack: SipralHandle,
        account: SipralHandle,
        now_ms: u64,
    ) -> (SipralHandle, Vec<u8>, String, String) {
        let mut offering = managed_config();
        offering.ice = crate::media::SipralIce::Offered as u32;
        let (status, call) = place(stack, account, &offering, now_ms);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = signalling_out(stack)
            .into_iter()
            .find(|(message, _)| message.starts_with(b"INVITE "))
            .expect("the INVITE")
            .0;
        let text = String::from_utf8_lossy(&invite).into_owned();
        let ufrag = attribute(&text, "ice-ufrag");
        let pwd = attribute(&text, "ice-pwd");
        (call, invite, ufrag, pwd)
    }

    /// Everything `sipral_media_poll_transmit` hands out, with where it goes.
    #[cfg(feature = "ice")]
    fn media_out(media: SipralHandle, now_ms: u64) -> Vec<(Vec<u8>, String)> {
        let mut data = vec![0_u8; crate::media::SIPRAL_MEDIA_PACKET_BYTES];
        let mut destination: [c_char; SIPRAL_ADDRESS_BYTES] = [0; SIPRAL_ADDRESS_BYTES];
        let mut all = Vec::new();
        loop {
            let mut packet = crate::media::SipralMediaPacket {
                size: size_of::<crate::media::SipralMediaPacket>(),
                data: data.as_mut_ptr(),
                capacity: data.len(),
                len: 0,
                destination: destination.as_mut_ptr(),
                destination_capacity: destination.len(),
                destination_len: 0,
            };
            let status =
                unsafe { crate::media::sipral_media_poll_transmit(media, now_ms, &raw mut packet) };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            if packet.len == 0 {
                return all;
            }
            let to = unsafe { CStr::from_ptr(destination.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            all.push((data.get(..packet.len).unwrap_or_default().to_vec(), to));
        }
    }

    /// Everything the call's media handle hands out over the third of a
    /// second from `from_ms`, the stack polled every twenty milliseconds the
    /// way a loop polls it: a triggered check waits for its turn on the
    /// pacing timer.
    #[cfg(feature = "ice")]
    fn media_over(
        stack: SipralHandle,
        media: SipralHandle,
        from_ms: u64,
    ) -> Vec<(Vec<u8>, String)> {
        let mut sent = media_out(media, from_ms);
        for at in (from_ms..from_ms + 340).step_by(20) {
            let _ = poll(stack, at);
            sent.extend(media_out(media, at));
        }
        sent
    }

    /// The media handle of a call whose session has opened.
    #[cfg(feature = "ice")]
    fn media_of(stack: SipralHandle, call: SipralHandle) -> SipralHandle {
        let mut media = SIPRAL_HANDLE_NONE;
        let status = unsafe { crate::media::sipral_call_media(stack, call, &raw mut media) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        media
    }

    /// Whether `sent` holds this end's answer to the check `id`, a Binding
    /// success response (RFC 8489 §6.3.1), sent back where the check came
    /// from; and whether it holds a check of this end's own towards there,
    /// the triggered check RFC 8445 §7.3.1.4 runs on the same pair.
    #[cfg(feature = "ice")]
    fn answered_and_triggered(sent: &[(Vec<u8>, String)], id: [u8; 12]) -> (bool, bool) {
        let answered = sent.iter().any(|(message, to)| {
            to == PEER_CHECKS_FROM
                && message.get(..2) == Some(&[0x01, 0x01][..])
                && message.get(8..20) == Some(&id[..])
        });
        let triggered = sent.iter().any(|(message, to)| {
            to == PEER_CHECKS_FROM && message.get(..2) == Some(&[0x00, 0x01][..])
        });
        (answered, triggered)
    }

    /// How many answers `sent` holds to the check `id`, of any kind: a
    /// success, or the refusal an agent sends a check it cannot
    /// authenticate.
    #[cfg(feature = "ice")]
    fn answers_to(sent: &[(Vec<u8>, String)], id: [u8; 12]) -> usize {
        sent.iter()
            .filter(|(message, _)| {
                matches!(message.get(..2), Some([0x01, 0x01 | 0x11]))
                    && message.get(8..20) == Some(&id[..])
            })
            .count()
    }

    /// The far end starts checking the moment it sends its answer, and its
    /// first checks can reach this end's socket before the 200 does. The
    /// application has no media handle to give them to, and hands them in
    /// here, as it hands in everything that arrives on the socket until then:
    /// the stack keeps each one it can authenticate for the call described
    /// on that socket, and the call's agent answers it and checks back once
    /// its session opens (RFC 8445 §7.3), rather than the pair waiting for
    /// the far end's next retransmission while early audio is refused.
    #[cfg(feature = "ice")]
    #[test]
    fn a_check_that_arrives_before_the_answer_is_answered_once_the_call_has_media() {
        let mut observed = Observed::default();
        let (stack, call, invite, ufrag, pwd) = ice_call(&mut observed);

        // signed with any other password, it is nobody's: refused, and kept
        // for no call
        let forged = check(&ufrag, "notthepasswordthisendgaveout", [9; 12]);
        assert_eq!(
            on_media_socket(stack, &forged, PEER_CHECKS_FROM, 40),
            SipralStatus::InvalidArgument
        );
        // and so is one signed with nothing at all, and one signed with the
        // call's password that names some other fragment than the call's
        let unsigned = signed_check(&ufrag, None, [10; 12]);
        assert_eq!(
            on_media_socket(stack, &unsigned, PEER_CHECKS_FROM, 40),
            SipralStatus::InvalidArgument
        );
        let misnamed = check("notthisendsfragment", &pwd, [11; 12]);
        assert_eq!(
            on_media_socket(stack, &misnamed, PEER_CHECKS_FROM, 40),
            SipralStatus::InvalidArgument
        );
        let early = [7_u8; 12];
        assert_eq!(
            on_media_socket(stack, &check(&ufrag, &pwd, early), PEER_CHECKS_FROM, 40),
            SipralStatus::Ok,
            "a check for the call on this socket: {}",
            last_error_text()
        );

        crate::call::tests::deliver(
            stack,
            &crate::call::tests::accepted(&invite, &ice_answer(), true),
            50,
        );
        let _ = poll(stack, 50);
        let media = media_of(stack, call);
        let sent = media_over(stack, media, 50);
        assert_eq!(
            answered_and_triggered(&sent, early),
            (true, true),
            "the check kept before the answer reached the call's agent: {sent:?}"
        );
        for refused in [[9; 12], [10; 12], [11; 12]] {
            assert_eq!(
                answers_to(&sent, refused),
                0,
                "a check nobody could authenticate was kept after all: {sent:?}"
            );
        }
    }

    /// The checks kept for a call with no session are the newest sixteen: one
    /// more pushes out the oldest, which the far end has most likely sent
    /// again or given up on, rather than being refused itself.
    #[cfg(feature = "ice")]
    #[test]
    fn the_newest_sixteen_checks_are_kept_for_the_call() {
        let mut observed = Observed::default();
        let (stack, call, invite, ufrag, pwd) = ice_call(&mut observed);
        for id in 1..=20_u8 {
            assert_eq!(
                on_media_socket(stack, &check(&ufrag, &pwd, [id; 12]), PEER_CHECKS_FROM, 40),
                SipralStatus::Ok,
                "check {id}: {}",
                last_error_text()
            );
        }
        crate::call::tests::deliver(
            stack,
            &crate::call::tests::accepted(&invite, &ice_answer(), true),
            50,
        );
        let _ = poll(stack, 50);
        let media = media_of(stack, call);
        let sent = media_over(stack, media, 50);
        let answered: Vec<u8> = (1..=20_u8)
            .filter(|id| answers_to(&sent, [*id; 12]) > 0)
            .collect();
        assert_eq!(answered, (5..=20).collect::<Vec<u8>>(), "{sent:?}");
    }

    /// The far end retransmits a check it has no answer to under the same
    /// transaction id (RFC 8489 §6.2.1): kept, the copy takes the place of
    /// the one it repeats, so it pushes out no other check and is answered
    /// once.
    #[cfg(feature = "ice")]
    #[test]
    fn a_retransmitted_check_is_kept_once() {
        let mut observed = Observed::default();
        let (stack, call, invite, ufrag, pwd) = ice_call(&mut observed);
        for id in [
            1, 2, 2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16_u8,
        ] {
            assert_eq!(
                on_media_socket(stack, &check(&ufrag, &pwd, [id; 12]), PEER_CHECKS_FROM, 40),
                SipralStatus::Ok,
                "check {id}: {}",
                last_error_text()
            );
        }
        crate::call::tests::deliver(
            stack,
            &crate::call::tests::accepted(&invite, &ice_answer(), true),
            50,
        );
        let _ = poll(stack, 50);
        let media = media_of(stack, call);
        let sent = media_over(stack, media, 50);
        let answers: Vec<usize> = (1..=16_u8).map(|id| answers_to(&sent, [id; 12])).collect();
        assert_eq!(answers, vec![1; 16], "{sent:?}");
    }

    /// A check kept for longer than the far end's transaction for it lasts
    /// is not answered when the session finally opens: the far end gave up
    /// on it 39.5 seconds after sending it (RFC 8489 §6.2.1). One that
    /// arrived recently still is.
    #[cfg(feature = "ice")]
    #[test]
    fn a_check_kept_past_its_transaction_is_dropped_rather_than_answered() {
        let mut observed = Observed::default();
        let (stack, call, invite, ufrag, pwd) = ice_call(&mut observed);
        crate::call::tests::deliver(stack, &crate::call::tests::ringing(&invite), 35);
        let _ = poll(stack, 35);
        assert_eq!(
            on_media_socket(stack, &check(&ufrag, &pwd, [1; 12]), PEER_CHECKS_FROM, 40),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        for at in (5_000..40_000).step_by(5_000) {
            let _ = poll(stack, at);
            let _ = signalling_out(stack);
            let _ = stun_out(stack);
        }
        assert_eq!(
            on_media_socket(
                stack,
                &check(&ufrag, &pwd, [2; 12]),
                PEER_CHECKS_FROM,
                39_500
            ),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        crate::call::tests::deliver(
            stack,
            &crate::call::tests::accepted(&invite, &ice_answer(), true),
            39_550,
        );
        let _ = poll(stack, 39_550);
        let media = media_of(stack, call);
        let sent = media_over(stack, media, 39_550);
        assert_eq!(
            (answers_to(&sent, [1; 12]), answers_to(&sent, [2; 12])),
            (0, 1),
            "{sent:?}"
        );
    }

    /// A call that ends before its session opens takes what was kept for it
    /// along: the next call on the same socket answers none of it, and a
    /// check for the call that ended is refused like any stranger's.
    #[cfg(feature = "ice")]
    #[test]
    fn checks_kept_for_a_call_that_ended_go_with_it() {
        let mut observed = Observed::default();
        let (stack, _, invite, ufrag, pwd) = ice_call(&mut observed);
        assert_eq!(
            on_media_socket(stack, &check(&ufrag, &pwd, [3; 12]), PEER_CHECKS_FROM, 40),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        crate::call::tests::deliver(
            stack,
            &crate::call::tests::answered_with(&invite, 486, "Busy Here"),
            45,
        );
        let _ = poll(stack, 45);
        let _ = signalling_out(stack);
        assert_eq!(
            on_media_socket(stack, &check(&ufrag, &pwd, [4; 12]), PEER_CHECKS_FROM, 50),
            SipralStatus::InvalidArgument,
            "a check for a call that has ended was taken"
        );

        let account = account_on(stack);
        let _ = signalling_out(stack);
        let (next, next_invite, _, _) = place_ice(stack, account, 60);
        crate::call::tests::deliver(
            stack,
            &crate::call::tests::accepted(&next_invite, &ice_answer(), true),
            70,
        );
        let _ = poll(stack, 70);
        let media = media_of(stack, next);
        let sent = media_over(stack, media, 70);
        assert!(
            !sent
                .iter()
                .any(|(message, _)| message.get(8..20) == Some(&[3; 12][..])),
            "a check kept for the call that ended reached the next one: {sent:?}"
        );
    }

    /// A call that ends after its session opened answers nothing more
    /// either: what arrives on its socket is refused.
    #[cfg(feature = "ice")]
    #[test]
    fn a_check_for_a_call_that_hung_up_is_refused() {
        let mut observed = Observed::default();
        let (stack, call, invite, ufrag, pwd) = ice_call(&mut observed);
        crate::call::tests::deliver(
            stack,
            &crate::call::tests::accepted(&invite, &ice_answer(), true),
            50,
        );
        let _ = poll(stack, 50);
        let _ = signalling_out(stack);
        assert_eq!(
            on_media_socket(stack, &check(&ufrag, &pwd, [5; 12]), PEER_CHECKS_FROM, 60),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        crate::call::tests::hangup(stack, call, 70);
        assert_eq!(
            on_media_socket(stack, &check(&ufrag, &pwd, [6; 12]), PEER_CHECKS_FROM, 80),
            SipralStatus::InvalidArgument,
            "a check for a call that has ended was taken"
        );
    }

    /// Between the session opening and the application taking its media
    /// handle — the poll that raised `SIPRAL_EVENT_KIND_MEDIA_STARTED` and
    /// the `sipral_call_media` after it — what arrives on the socket still
    /// comes in here, and the call's session takes it.
    #[cfg(feature = "ice")]
    #[test]
    fn a_check_that_arrives_before_the_media_handle_is_answered_through_it() {
        let mut observed = Observed::default();
        let (stack, call, invite, ufrag, pwd) = ice_call(&mut observed);
        crate::call::tests::deliver(
            stack,
            &crate::call::tests::accepted(&invite, &ice_answer(), true),
            50,
        );
        let _ = poll(stack, 50);

        let early = [5_u8; 12];
        assert_eq!(
            on_media_socket(stack, &check(&ufrag, &pwd, early), PEER_CHECKS_FROM, 60),
            SipralStatus::Ok,
            "a check for the call whose session is open: {}",
            last_error_text()
        );
        let media = media_of(stack, call);
        let sent = media_over(stack, media, 60);
        assert_eq!(
            answered_and_triggered(&sent, early),
            (true, true),
            "the check reached the call's agent: {sent:?}"
        );
    }
}
