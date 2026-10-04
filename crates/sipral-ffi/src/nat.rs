// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
//!
//! A TURN server reached over TCP or TLS (`turn_transport`) is reached over
//! a connection the application opens, one per media socket, the way it
//! opens a SIP stream: [`SipralEventKind::TurnStream`](crate::event::SipralEventKind::TurnStream)
//! asks for it, [`sipral_stack_turn_connected`] says it is open,
//! [`sipral_stack_turn_receive`] hands in what it carried and
//! [`sipral_stack_turn_closed`] says it has gone. What is written on it comes
//! out of the queues a datagram for the server would, marked with the
//! protocol to write it on.

#[cfg(all(feature = "stun", feature = "ice"))]
use std::collections::HashSet;
#[cfg(feature = "stun")]
use std::collections::{HashMap, VecDeque};
use std::ffi::c_char;
use std::net::SocketAddr;
#[cfg(feature = "stun")]
use std::sync::Arc;
use std::time::Instant;

#[cfg(feature = "ice")]
use sipral::TurnTransport;
use sipral_core::endpoint::{Transmit, TransportId, TransportProtocol};

use crate::abi::{Number, codes, record};
use crate::error::{Fail, entry, fail};
use crate::event::SipralEvent;
use crate::handle::SipralHandle;
use crate::stack::{SipralStackConfig, SipralTransport, StackState, with_stack, with_stack_at};
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
        pub mapping: Number<SipralNatMapping>,
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
        pub outcome: Number<SipralNatRelay>,
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

codes! {
    /// What a media socket's connection to the TURN server is to do. Names
    /// for `sipral_turn_stream_event_t::state`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralTurnStream: u32 {
        /// Open a connection from the media socket `local` to the TURN
        /// server at `server`, over `protocol` — TCP, or TLS with the
        /// server's certificate checked by the platform's own stack — and
        /// say so with `sipral_stack_turn_connected` once it is open, or
        /// `sipral_stack_turn_closed` if it cannot be. The socket's relay is
        /// allocated over it; a call on the socket before that answers
        /// `SIPRAL_STATUS_WRONG_STATE`.
        Open = 1,
        /// Nothing more will be written for the connection from `local`:
        /// its relay was given back or lost, or the call it carried has
        /// ended. Write what the queues still hold for it —
        /// `sipral_stack_poll_farewell` and `sipral_stack_poll_stun` — and
        /// close it.
        Close = 2,
    }
}

record! {
    /// What a [`SipralEventKind::TurnStream`](crate::event::SipralEventKind::TurnStream)
    /// carries.
    ///
    /// The addresses are text, not NUL-terminated, and the library's: valid
    /// for as long as the callback runs.
    #[derive(Clone, Copy)]
    pub struct SipralTurnStreamEvent {
        /// A [`SipralTurnStream`].
        pub state: Number<SipralTurnStream>,
        /// What to open, as a `SipralTransport`: `SIPRAL_TRANSPORT_TCP` or
        /// `SIPRAL_TRANSPORT_TLS`, what `turn_transport` named.
        pub protocol: Number<SipralTransport>,
        /// The media socket, as `sipral_stack_nat_map` named it: the
        /// connection's own name in the three calls that take one.
        pub local: *const c_char,
        /// How many bytes of it.
        pub local_len: usize,
        /// The TURN server, `host:port`, as `turn_server` named it.
        pub server: *const c_char,
        /// How many bytes of it.
        pub server_len: usize,
    }
}

codes! {
    /// What happened to the STUN servers a stack asks. Names for
    /// `sipral_stun_server_event_t::state`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralStunServerState: u32 {
        /// The server in use is another one now: `previous` failed and
        /// `server`, the next in the list, took over; a refresh found
        /// `server`, earlier in the list, answering again; or
        /// `sipral_stack_stun_servers` named another list.
        Changed = 1,
        /// Every server in the list has failed and each is backing off:
        /// `server` is the last one that did. The sockets keep what they
        /// learned, or are described by their own address, and a
        /// signalling socket's refresh goes on asking. Said once until a
        /// server answers again.
        AllFailed = 2,
    }
}

record! {
    /// What a [`SipralEventKind::StunServer`](crate::event::SipralEventKind::StunServer)
    /// carries.
    ///
    /// The addresses are `host:port`, not NUL-terminated, and the library's:
    /// valid for as long as the callback runs.
    #[derive(Clone, Copy)]
    pub struct SipralStunServerEvent {
        /// A [`SipralStunServerState`].
        pub state: Number<SipralStunServerState>,
        /// For `SIPRAL_STUN_SERVER_STATE_CHANGED`, the server in use now; for
        /// `SIPRAL_STUN_SERVER_STATE_ALL_FAILED`, the last one that failed.
        pub server: *const c_char,
        /// How many bytes of it.
        pub server_len: usize,
        /// For `SIPRAL_STUN_SERVER_STATE_CHANGED`, the server that was in use.
        /// Empty otherwise.
        pub previous: *const c_char,
        /// How many bytes of it.
        pub previous_len: usize,
    }
}

/// The STUN servers a stack asks, in order: the first, and the ones turned
/// to when it fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StunServers {
    first: SocketAddr,
    rest: Vec<SocketAddr>,
}

/// A list of `host:port` addresses separated by commas, as `name` names
/// it: an address each, not a name, since resolving one is the
/// application's, and no entry empty.
///
/// # Safety
///
/// `list` must be readable for `len` bytes.
unsafe fn addresses(
    list: *const c_char,
    len: usize,
    name: &'static str,
) -> Result<Vec<SocketAddr>, Fail> {
    let Some(list) = (unsafe { text(list, len, name) })? else {
        return Ok(Vec::new());
    };
    list.split(',')
        .enumerate()
        .map(|(at, entry)| {
            entry.trim().parse::<SocketAddr>().map_err(|_| {
                fail(
                    SipralStatus::InvalidArgument,
                    format!(
                        "{name} entry {at} is {entry:?}, which is not an address and a port; the \
                         list is host:port addresses separated by commas, and resolving a name is \
                         the application's"
                    ),
                )
            })
        })
        .collect()
}

/// The servers a stack's configuration asks, or `None` for one that asks
/// nobody.
///
/// # Safety
///
/// `config.stun_server` must be readable for `config.stun_server_len` bytes,
/// and `config.stun_fallbacks` for `config.stun_fallbacks_len`.
pub(crate) unsafe fn configured(config: &SipralStackConfig) -> Result<Option<StunServers>, Fail> {
    let server = unsafe { text(config.stun_server, config.stun_server_len, "stun_server") }?;
    let rest = unsafe {
        addresses(
            config.stun_fallbacks,
            config.stun_fallbacks_len,
            "stun_fallbacks",
        )
    }?;
    if !rest.is_empty() && server.is_none() {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "stun_fallbacks names servers to turn to and stun_server names none to turn from: \
             the first server goes in stun_server",
        ));
    }
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
            supported(StunServers {
                first: address,
                rest,
            })
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
    let transport = match config.turn_transport {
        0 | 1 => TurnTransport::Udp,
        2 => TurnTransport::Tcp,
        3 => TurnTransport::Tls,
        other => {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!(
                    "turn_transport is {other}, and a TURN server is reached over \
                     SIPRAL_TRANSPORT_UDP, SIPRAL_TRANSPORT_TCP or SIPRAL_TRANSPORT_TLS \
                     (RFC 8656 §3.1), or zero for UDP"
                ),
            ));
        }
    };
    let Some(server) = server else {
        return if username.is_some() || password.is_some() || config.turn_transport != 0 {
            Err(fail(
                SipralStatus::InvalidArgument,
                "turn_username, turn_password or turn_transport is set and turn_server names no \
                 server to use them with",
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
        transport,
        username,
        password,
    })
}

/// How a relay reaches its TURN server, for a build with no ICE to relay for:
/// the configuration naming one is refused before this is read.
#[cfg(not(feature = "ice"))]
#[derive(Clone, Copy)]
pub(crate) enum TurnTransport {
    Udp,
    Tcp,
    Tls,
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
    transport: TurnTransport,
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
fn supported(servers: StunServers) -> Result<Option<StunServers>, Fail> {
    Ok(Some(servers))
}

#[cfg(not(feature = "stun"))]
fn supported(_servers: StunServers) -> Result<Option<StunServers>, Fail> {
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
    relay_out: VecDeque<sipral::RelayDatagram>,
    /// Over TCP or TLS, where each media socket's connection to the TURN
    /// server stands.
    #[cfg(feature = "ice")]
    streams: Streams,
}

/// The connections a stack whose TURN server is reached over TCP or TLS has
/// asked the application for, one per media socket.
#[cfg(all(feature = "stun", feature = "ice"))]
#[derive(Default)]
struct Streams {
    /// Asked for, and not open yet: no Allocate has gone.
    connecting: HashSet<SocketAddr>,
    /// Open, and carrying a relay being made or kept for the socket, or the
    /// relay of a call described there.
    open: HashSet<SocketAddr>,
    /// Open, and the relay on it taken by the call described on the socket:
    /// closed when no call is described there any more.
    carried: HashSet<SocketAddr>,
    /// What to tell the application, in order.
    said: VecDeque<(SipralTurnStream, SocketAddr)>,
    /// Sockets whose connection closed before it opened: their relay is
    /// `SIPRAL_NAT_RELAY_FAILED` without the server ever having been asked.
    lost: VecDeque<SocketAddr>,
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
        servers: Option<StunServers>,
        turn: Option<Turn<'_>>,
        transport: TransportId,
        protocol: TransportProtocol,
        local: SocketAddr,
        now: Instant,
    ) {
        let Some(servers) = servers else {
            return;
        };
        let mappings = state.engine.mappings(servers.first).fallbacks(servers.rest);
        #[cfg(feature = "ice")]
        let relays = turn.map(|turn| {
            state
                .engine
                .relays(turn.server, turn.username, turn.password)
                .over(turn.transport)
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
            #[cfg(feature = "ice")]
            streams: Streams::default(),
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
            let transport = match learned {
                sipral::MappingEvent::Learned { local, .. }
                | sipral::MappingEvent::Moved { local, .. }
                | sipral::MappingEvent::Unanswered { local, .. } => {
                    active.signalling.get(&local).copied()
                }
                sipral::MappingEvent::ServerChanged { .. }
                | sipral::MappingEvent::ServersFailed { .. } => None,
            };
            learned_all.push((learned, transport));
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
                sipral::MappingEvent::ServerChanged { previous, server } => {
                    raised.push(server_event(
                        stack,
                        SipralStunServerState::Changed,
                        server,
                        Some(previous),
                    ));
                    continue;
                }
                sipral::MappingEvent::ServersFailed { last } => {
                    raised.push(server_event(
                        stack,
                        SipralStunServerState::AllFailed,
                        last,
                        None,
                    ));
                    continue;
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
        Self::drain_relays(state, stack, &mut raised);
        raised
    }

    /// What the relays and their connections came to since the last poll.
    #[cfg(feature = "ice")]
    fn drain_relays(state: &mut StackState, stack: SipralHandle, raised: &mut Vec<Raised>) {
        let engine = &state.engine;
        let Some(active) = state.nat.active.as_mut() else {
            return;
        };
        let Some(relays) = active.relays.as_mut() else {
            return;
        };
        let server = relays.server();
        let protocol = protocol_of(relays.transport());
        let streams = &mut active.streams;
        while let Some(local) = streams.lost.pop_front() {
            raised.push(relay_event(
                stack,
                sipral::RelayEvent::Failed {
                    local,
                    failure: sipral::TurnFailure::ConnectionLost,
                },
            ));
        }
        while let Some(said) = relays.poll_event() {
            // a relay lost or refused leaves its connection nothing to carry
            if let sipral::RelayEvent::Failed { local, .. } = said
                && streams.open.remove(&local)
            {
                streams.said.push_back((SipralTurnStream::Close, local));
            }
            raised.push(relay_event(stack, said));
        }
        // and a call's: once no call is described on the socket, its
        // farewells are queued and nothing more will be written there
        let done: Vec<SocketAddr> = streams
            .carried
            .iter()
            .filter(|local| !engine.describes(**local))
            .copied()
            .collect();
        for local in done {
            streams.carried.remove(&local);
            if streams.open.remove(&local) {
                streams.said.push_back((SipralTurnStream::Close, local));
            }
        }
        while let Some((said, local)) = streams.said.pop_front() {
            raised.push(stream_event(stack, said, protocol, local, server));
        }
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
        let Some(active) = state.nat.active.as_mut() else {
            return Ok(None);
        };
        if active.streams.connecting.contains(&local) {
            return Err(fail(
                SipralStatus::WrongState,
                format!(
                    "the connection to the TURN server for {local} is not open yet: open the one \
                     SIPRAL_EVENT_KIND_TURN_STREAM asked for and say so with \
                     sipral_stack_turn_connected, or sipral_stack_turn_closed if it cannot be"
                ),
            ));
        }
        let Some(relays) = active.relays.as_mut() else {
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
                let kept = relays.holds(local);
                relays.release(local, now);
                // the connection goes on for the relay a call took from it,
                // and has nothing left to carry once the one nobody took has
                // gone back
                let streams = &mut active.streams;
                if streams.connecting.remove(&local) {
                    streams.said.push_back((SipralTurnStream::Close, local));
                } else if streams.open.contains(&local) {
                    if kept {
                        streams.open.remove(&local);
                        streams.said.push_back((SipralTurnStream::Close, local));
                    } else {
                        streams.carried.insert(local);
                    }
                }
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

    /// Ask `servers` from now on, on a running stack; `None` to ask nobody.
    ///
    /// A stack already asking keeps every socket and asks each one again of
    /// the new list at once. A stack that asked nobody starts on its main
    /// transport, exactly as if it had been created with these servers.
    /// Asking nobody any more moves every account's `Contact` back to its
    /// socket's own address — each one that holds a binding registers it —
    /// and forgets every media socket named; refused while a TURN server is
    /// configured, whose relays are made on the media sockets STUN names.
    fn replace_servers(
        state: &mut StackState,
        servers: Option<StunServers>,
        now: Instant,
    ) -> Result<(), Fail> {
        match (servers, state.nat.active.as_mut()) {
            (Some(servers), Some(active)) => {
                active
                    .mappings
                    .set_servers(servers.first, servers.rest, now);
                active.sort();
                Ok(())
            }
            (Some(servers), None) => {
                let (local, protocol) = (state.local, state.speaks.protocol());
                Self::start(
                    state,
                    Some(servers),
                    None,
                    crate::stack::TRANSPORT,
                    protocol,
                    local,
                    now,
                );
                Self::contacts_changed(state, now);
                Ok(())
            }
            (None, None) => Ok(()),
            (None, Some(active)) => {
                #[cfg(feature = "ice")]
                if active.relays.is_some() {
                    return Err(fail(
                        SipralStatus::InvalidArgument,
                        "this stack has a TURN server, and its relays are made on the media \
                         sockets STUN names: a stack that relays keeps asking STUN",
                    ));
                }
                let back: Vec<(TransportId, SocketAddr, SocketAddr)> = active
                    .signalling
                    .iter()
                    .filter_map(|(local, transport)| {
                        Some((*transport, active.mappings.public(*local)?, *local))
                    })
                    .collect();
                state.nat.active = None;
                for (transport, public, local) in back {
                    // how many moved is nobody's to report: no event says a
                    // mapping was forgotten, the registrations say they are
                    // owed again
                    let _moved = state.agent.readdress(transport, public, local, now);
                }
                Ok(())
            }
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
        #[cfg(feature = "ice")]
        if let Some(relays) = active.relays.as_mut() {
            let streams = &mut active.streams;
            if !relays.transport().is_stream() || streams.open.contains(&local) {
                relays.allocate(local, now);
            } else if streams.connecting.insert(local) {
                // the Allocate waits for the connection it is made on
                streams.said.push_back((SipralTurnStream::Open, local));
            }
        }
        active.sort();
        Ok(())
    }

    /// The connection a socket's relay is made over is open: its Allocate
    /// goes.
    #[cfg(feature = "ice")]
    fn connected(state: &mut StackState, local: SocketAddr, now: Instant) -> Result<(), Fail> {
        let Some(active) = state.nat.active.as_mut() else {
            return Err(not_asking());
        };
        if !active.streams.connecting.remove(&local) {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!(
                    "no connection to the TURN server was asked for {local}: \
                     SIPRAL_EVENT_KIND_TURN_STREAM says which, and only on a stack whose \
                     turn_transport is TCP or TLS"
                ),
            ));
        }
        active.streams.open.insert(local);
        if let Some(relays) = active.relays.as_mut() {
            relays.allocate(local, now);
        }
        active.sort();
        Ok(())
    }

    /// What a socket's connection to the TURN server carried: for the relay
    /// being made or kept for it, or for the call that took the relay.
    #[cfg(feature = "ice")]
    fn stream_received(
        state: &mut StackState,
        local: SocketAddr,
        bytes: &[u8],
        now: Instant,
    ) -> Result<(), Fail> {
        let Some(active) = state.nat.active.as_mut() else {
            return Err(not_asking());
        };
        if !active.streams.open.contains(&local) {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!(
                    "{local} has no open connection to the TURN server: none was asked for, it \
                     was never said to be connected, or it has closed"
                ),
            ));
        }
        let taken = match active.relays.as_mut() {
            Some(relays) => relays.receive_stream(local, bytes, now),
            None => Ok(false),
        };
        active.sort();
        let taken = match taken {
            Ok(true) => Ok(true),
            Ok(false) => state.engine.receive_stream(local, bytes, now),
            Err(error) => Err(error),
        };
        match taken {
            Ok(_) => Ok(()),
            Err(error) => {
                // lost with its relay: the relay's failure is raised as
                // usual, and no SIPRAL_TURN_STREAM_CLOSE, since this answer
                // already says to close it
                if let Some(active) = state.nat.active.as_mut() {
                    active.streams.open.remove(&local);
                    active.streams.carried.remove(&local);
                }
                state.engine.stream_closed(local, now);
                Err(fail(
                    SipralStatus::StreamBroken,
                    format!(
                        "the connection from {local} to the TURN server carried {error}, and no \
                         TURN message starts that way: close it; its relay is lost"
                    ),
                ))
            }
        }
    }

    /// A socket's connection to the TURN server closed, or could not be
    /// opened.
    #[cfg(feature = "ice")]
    fn stream_gone(state: &mut StackState, local: SocketAddr, now: Instant) -> Result<(), Fail> {
        let Some(active) = state.nat.active.as_mut() else {
            return Err(not_asking());
        };
        let streams = &mut active.streams;
        if streams.connecting.remove(&local) {
            streams.lost.push_back(local);
            return Ok(());
        }
        streams.carried.remove(&local);
        if streams.open.remove(&local) {
            if let Some(relays) = active.relays.as_mut() {
                relays.stream_closed(local, now);
            }
            active.relay_out.retain(|queued| queued.local != local);
            state.engine.stream_closed(local, now);
        }
        Ok(())
    }

    fn take_media(state: &mut StackState, room: usize) -> Result<Option<Outgoing>, usize> {
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
            active.relay_out.push_back(datagram);
        }
        if let Some(front) = active.media_out.front() {
            if front.payload.len() > room {
                return Err(front.payload.len());
            }
            return Ok(active.media_out.pop_front().map(|request| Outgoing {
                local: request.local,
                destination: request.destination,
                payload: request.payload,
                protocol: crate::stack::SipralTransport::Udp as u32,
            }));
        }
        #[cfg(feature = "ice")]
        if let Some(front) = active.relay_out.front() {
            if front.payload.len() > room {
                return Err(front.payload.len());
            }
            return Ok(active.relay_out.pop_front().map(|request| Outgoing {
                local: request.local,
                destination: request.destination,
                payload: request.payload,
                protocol: protocol_of(request.transport),
            }));
        }
        Ok(None)
    }

    fn receive_media(
        state: &mut StackState,
        local: SocketAddr,
        from: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> Result<(), Fail> {
        if state.nat.active.is_none() {
            // a stack that asks nobody still has the branches of a forked
            // call to hand a shared socket's datagrams to
            if state.engine.receive_early(local, from, data, now) {
                return Ok(());
            }
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
                self.relay_out.push_back(request);
            }
        }
    }
}

/// One request for a media socket to send, and what to send it over.
#[cfg(feature = "stun")]
struct Outgoing {
    local: SocketAddr,
    destination: SocketAddr,
    payload: Vec<u8>,
    /// A `SipralTransport`: UDP for a datagram from `local`, TCP or TLS for
    /// `local`'s connection to the TURN server.
    protocol: u32,
}

/// The `SipralTransport` bytes for a TURN server go out over.
#[cfg(feature = "ice")]
pub(crate) const fn protocol_of(transport: TurnTransport) -> u32 {
    crate::stack::SipralTransport::named(match transport {
        TurnTransport::Tcp => TransportProtocol::Tcp,
        TurnTransport::Tls => TransportProtocol::Tls,
        TurnTransport::Udp => TransportProtocol::Udp,
    })
}

/// Without the feature a stack never asks, since `nat` naming STUN is refused
/// when it is created, and every one of these is the answer for a stack that
/// does not.
#[cfg(not(feature = "stun"))]
impl Nat {
    pub(crate) fn start(
        _state: &mut StackState,
        _servers: Option<StunServers>,
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

    /// Asking nobody is what a stack without STUN already does; asking
    /// anybody is what it cannot.
    fn replace_servers(
        _state: &mut StackState,
        servers: Option<StunServers>,
        _now: Instant,
    ) -> Result<(), Fail> {
        match servers {
            Some(servers) => supported(servers).map(|_| ()),
            None => Ok(()),
        }
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

/// One event about the STUN servers, laid out the way [`event`] lays out a
/// mapping's.
#[cfg(feature = "stun")]
fn server_event(
    stack: SipralHandle,
    state: SipralStunServerState,
    server: SocketAddr,
    previous: Option<SocketAddr>,
) -> Raised {
    let server = server.to_string();
    let previous = previous
        .map(|address| address.to_string())
        .unwrap_or_default();
    let text = format!("{server}{previous}");
    let base = text.as_ptr().cast::<c_char>();
    let payload = SipralStunServerEvent {
        state: state as u32,
        server: base,
        server_len: server.len(),
        previous: if previous.is_empty() {
            std::ptr::null()
        } else {
            base.wrapping_add(server.len())
        },
        previous_len: previous.len(),
    };
    (crate::event::stun_server(stack, payload), text)
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

/// One connection event, and the text its two addresses point into.
#[cfg(all(feature = "stun", feature = "ice"))]
fn stream_event(
    stack: SipralHandle,
    said: SipralTurnStream,
    protocol: u32,
    local: SocketAddr,
    server: SocketAddr,
) -> Raised {
    let local = local.to_string();
    let server = server.to_string();
    let text = format!("{local}{server}");
    let base = text.as_ptr().cast::<c_char>();
    let payload = SipralTurnStreamEvent {
        state: said as u32,
        protocol,
        local: base,
        local_len: local.len(),
        server: base.wrapping_add(local.len()),
        server_len: server.len(),
    };
    (crate::event::turn_stream(stack, payload), text)
}

/// The STUN error code a relay failure stands for, or zero for a failure no
/// server answered with (RFC 8656 §19, RFC 8489 §14.8): what a relay event
/// carries, and what a path a relay refused or lost does.
#[cfg(feature = "ice")]
pub(crate) fn refusal_code(failure: sipral::TurnFailure) -> u32 {
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
        | TurnFailure::Oversized
        | TurnFailure::ConnectionLost => 0,
    }
}

entry! {
    /// Ask these STUN servers from now on, without creating the stack again.
    ///
    /// `servers` is `host:port` addresses separated by commas, in order of
    /// preference: the first is what `stun_server` would have named, the
    /// rest what `stun_fallbacks` would. On a stack that asks already, every
    /// socket it keeps mapped is asked again of the new list at once, and
    /// what each one learned stands until the new server answers —
    /// `SIPRAL_EVENT_KIND_STUN_SERVER` says the server in use moved, and
    /// `SIPRAL_EVENT_KIND_NAT_MAPPING` what the new one answers. A server
    /// kept from the old list keeps its back-off. On a stack created with
    /// `SIPRAL_NAT_OFF` the main transport starts being kept mapped, as it
    /// would have been with `SIPRAL_NAT_STUN`; a further datagram transport
    /// joins it the next time it is bound with
    /// `sipral_stack_transport_bind`.
    ///
    /// An empty list — `servers_len` zero — asks nobody any more: every
    /// account whose `Contact` a STUN answer moved goes back to the socket's
    /// own address and registers it, every media socket named is forgotten,
    /// and a call is described by its socket's own address from then on.
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for that on a stack with a TURN
    /// server, whose relays ride on the media sockets STUN names, and for an
    /// entry that is not an address and a port. `SIPRAL_STATUS_NOT_SUPPORTED`
    /// for a list in a build without `SIPRAL_FEATURE_STUN`.
    ///
    /// # Safety
    ///
    /// `servers` must be readable for `servers_len` bytes.
    fn sipral_stack_stun_servers(
        stack: SipralHandle,
        servers: *const c_char,
        servers_len: usize,
        now_ms: u64,
    ) {
        let mut list = unsafe { addresses(servers, servers_len, "servers") }?.into_iter();
        let servers = list.next().map(|first| StunServers {
            first,
            rest: list.collect(),
        });
        with_stack_at(stack, now_ms, |state, now| {
            Nat::replace_servers(state, servers, now)
        })
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
    /// Say that the TCP or TLS connection a
    /// `SIPRAL_EVENT_KIND_TURN_STREAM` of state `SIPRAL_TURN_STREAM_OPEN`
    /// asked for is open — for TLS, that the handshake has finished and the
    /// server's certificate was checked against the name the application
    /// configured, by the platform's own TLS stack, as for SIP over TLS.
    ///
    /// The socket's Allocate is waiting in [`sipral_stack_poll_stun`] when
    /// this returns, marked with the connection's `protocol`, to be written
    /// on it; the answer comes back through [`sipral_stack_turn_receive`],
    /// and `SIPRAL_EVENT_KIND_NAT_RELAY` says what the server gave, exactly
    /// as over UDP.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for a socket no connection was asked
    /// for, and `SIPRAL_STATUS_WRONG_STATE` on a stack created without
    /// `SIPRAL_NAT_STUN`.
    ///
    /// # Safety
    ///
    /// `local` must be readable for `local_len` bytes.
    fn sipral_stack_turn_connected(
        stack: SipralHandle,
        local: *const c_char,
        local_len: usize,
        now_ms: u64,
    ) {
        let local = unsafe { crate::media::address(local, local_len, "local") }?;
        #[cfg(all(feature = "stun", feature = "ice"))]
        {
            with_stack_at(stack, now_ms, |state, now| Nat::connected(state, local, now))
        }
        #[cfg(not(all(feature = "stun", feature = "ice")))]
        {
            let _ = (stack, local, now_ms);
            Err(no_turn_streams())
        }
    }
}

entry! {
    /// Hand over bytes read off a media socket's TCP or TLS connection to
    /// the TURN server, in whatever pieces the connection delivered them.
    ///
    /// The messages in them are put back together here (RFC 8656 §12.5)
    /// and each goes where a datagram from the server would: to the relay
    /// being made or kept for the socket, or, once a call has taken it, to
    /// that call — its agent while it waits for its session, and then its
    /// media, as through `sipral_media_receive`, audio included. So the
    /// connection is read here for as long as it is open, media handle or
    /// not, and what the call owes the far end in reply comes out of
    /// `sipral_media_poll_transmit` as it always does.
    ///
    /// `SIPRAL_STATUS_STREAM_BROKEN` when the connection carried something
    /// no TURN message starts with, which nothing in a stream can recover
    /// from: close it. The socket's relay is lost with it —
    /// `SIPRAL_NAT_RELAY_FAILED` for one still waiting for its call — and no
    /// `SIPRAL_TURN_STREAM_CLOSE` follows. `SIPRAL_STATUS_INVALID_ARGUMENT`
    /// for a socket with no open connection.
    ///
    /// # Safety
    ///
    /// `local` must be readable for `local_len` bytes, and `data` for `len`.
    fn sipral_stack_turn_receive(
        stack: SipralHandle,
        local: *const c_char,
        local_len: usize,
        data: *const u8,
        len: usize,
        now_ms: u64,
    ) {
        let bytes = unsafe { arrived(data, len, "the bytes") }?;
        let local = unsafe { crate::media::address(local, local_len, "local") }?;
        #[cfg(all(feature = "stun", feature = "ice"))]
        {
            with_stack_at(stack, now_ms, |state, now| {
                Nat::stream_received(state, local, bytes, now)
            })
        }
        #[cfg(not(all(feature = "stun", feature = "ice")))]
        {
            let _ = (stack, local, bytes, now_ms);
            Err(no_turn_streams())
        }
    }
}

entry! {
    /// Say that a media socket's connection to the TURN server closed, or
    /// could not be opened at all.
    ///
    /// The server knew the socket's allocation by that connection (RFC 8656
    /// §3.2), so the relay went with it: one still being made is
    /// `SIPRAL_NAT_RELAY_FAILED` at the next poll, and a call on the socket
    /// goes without it; a call that had taken it keeps the paths ICE found
    /// that need none, and loses the one through it when its consent runs
    /// out (RFC 7675). Naming the socket again with `sipral_stack_nat_map`
    /// asks for a new connection. `SIPRAL_STATUS_OK` for a connection the
    /// stack had already let go.
    ///
    /// # Safety
    ///
    /// `local` must be readable for `local_len` bytes.
    fn sipral_stack_turn_closed(
        stack: SipralHandle,
        local: *const c_char,
        local_len: usize,
        now_ms: u64,
    ) {
        let local = unsafe { crate::media::address(local, local_len, "local") }?;
        #[cfg(all(feature = "stun", feature = "ice"))]
        {
            with_stack_at(stack, now_ms, |state, now| Nat::stream_gone(state, local, now))
        }
        #[cfg(not(all(feature = "stun", feature = "ice")))]
        {
            let _ = (stack, local, now_ms);
            Err(no_turn_streams())
        }
    }
}

/// What the three connection calls answer in a build that has no relay to
/// carry over one.
#[cfg(not(all(feature = "stun", feature = "ice")))]
fn no_turn_streams() -> Fail {
    fail(
        SipralStatus::NotSupported,
        "this build has no ICE, so no relay to reach over a connection: \
         SIPRAL_FEATURE_TURN_STREAM is clear in sipral_capabilities",
    )
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
    /// `transport` is zero and names nothing here. `protocol` is UDP for a
    /// datagram; on a stack whose `turn_transport` is TCP or TLS, what is for
    /// the TURN server says that instead, and is written, as it is, on the
    /// connection from `source` that `SIPRAL_EVENT_KIND_TURN_STREAM` asked
    /// for — never sent as a datagram.
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
unsafe fn put(transmit: &mut SipralTransmit, request: &Outgoing) -> Result<(), Fail> {
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
    transmit.protocol = request.protocol;
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
    /// datagrams go to `sipral_media_receive` instead — except on a socket
    /// the branches of a forked call share (`keep_all_forks`), whose
    /// datagrams keep coming here for as long as the branches last: one
    /// offer described them all on the one socket, and each datagram goes to
    /// the branch that claims it, by the ICE fragment a check names, the
    /// check an answer answers, or the address its media comes from (RFC
    /// 8839 §7.3). That much a stack that asks no server takes too; anything
    /// else it refuses with `SIPRAL_STATUS_WRONG_STATE`.
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

    use super::{
        SipralNat, SipralNatMapping, sipral_stack_nat_map, sipral_stack_poll_stun,
        sipral_stack_receive_stun,
    };
    #[cfg(feature = "ice")]
    use super::{
        SipralNatRelay, SipralTurnStream, sipral_stack_turn_closed, sipral_stack_turn_connected,
        sipral_stack_turn_receive,
    };
    use crate::account::sipral_account_register;
    use crate::account::tests::account_config;
    use crate::call::tests::{as_text, managed_config, place};
    use crate::error::last_error_text;
    use crate::event::{SipralEvent, SipralEventKind};
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::media::SIPRAL_ADDRESS_BYTES;
    use crate::stack::tests::{BIND, Observed, config, create, poll, record};
    use crate::stack::{SipralStackConfig, sipral_stack_destroy};
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
        if seen.kind == SipralEventKind::StunServer {
            let payload = unsafe { seen.payload.stun_server };
            let said = ServerSaid {
                state: payload.state,
                server: piece(payload.server, payload.server_len),
                previous: piece(payload.previous, payload.previous_len),
            };
            SERVERS.with(|all| all.borrow_mut().push(said));
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
        #[cfg(feature = "ice")]
        if seen.kind == SipralEventKind::TurnStream {
            let payload = unsafe { seen.payload.turn_stream };
            let said = StreamSaid {
                state: payload.state,
                protocol: payload.protocol,
                local: piece(payload.local, payload.local_len),
                server: piece(payload.server, payload.server_len),
            };
            STREAMS.with(|all| all.borrow_mut().push(said));
        }
        unsafe { record(event, user_data) };
    }

    /// What one `SIPRAL_EVENT_KIND_TURN_STREAM` said, copied out inside the
    /// callback.
    #[cfg(feature = "ice")]
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct StreamSaid {
        state: u32,
        protocol: u32,
        local: String,
        server: String,
    }

    #[cfg(feature = "ice")]
    thread_local! {
        static STREAMS: RefCell<Vec<StreamSaid>> = const { RefCell::new(Vec::new()) };
    }

    #[cfg(feature = "ice")]
    fn streams() -> Vec<StreamSaid> {
        STREAMS.with(|all| std::mem::take(&mut *all.borrow_mut()))
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

    /// What one `SIPRAL_EVENT_KIND_STUN_SERVER` said, copied out inside the
    /// callback.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ServerSaid {
        state: u32,
        server: String,
        previous: String,
    }

    thread_local! {
        static SERVERS: RefCell<Vec<ServerSaid>> = const { RefCell::new(Vec::new()) };
    }

    fn servers_said() -> Vec<ServerSaid> {
        SERVERS.with(|all| std::mem::take(&mut *all.borrow_mut()))
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

    // -- more than one server, and a list replaced while running ------------

    const SECOND: &str = "198.51.100.2:3478";
    const THIRD: &str = "198.51.100.3:3478";

    fn from_address(stack: SipralHandle, data: &[u8], from: &str, now_ms: u64) -> SipralStatus {
        unsafe {
            sipral_stack_receive_datagram(
                stack,
                SIPRAL_TRANSPORT_MAIN,
                data.as_ptr(),
                data.len(),
                from.as_ptr().cast::<c_char>(),
                from.len(),
                ptr::null(),
                0,
                now_ms,
            )
        }
    }

    /// Poll every tenth of a second from `from_ms` to `to_ms`, and gather
    /// what the signalling socket was given to send.
    fn run_signalling(stack: SipralHandle, from_ms: u64, to_ms: u64) -> Vec<(Vec<u8>, String)> {
        let mut all = Vec::new();
        let mut now = from_ms;
        while now <= to_ms {
            let _ = poll(stack, now);
            all.extend(signalling_out(stack));
            now += 100;
        }
        all
    }

    fn set_servers(stack: SipralHandle, list: &str, now_ms: u64) -> SipralStatus {
        unsafe {
            super::sipral_stack_stun_servers(
                stack,
                list.as_ptr().cast::<c_char>(),
                list.len(),
                now_ms,
            )
        }
    }

    #[test]
    fn a_dead_first_server_hands_the_signalling_socket_to_the_next_and_says_so() {
        let mut observed = Observed::default();
        let _ = servers_said();
        let mut settings = asking(&mut observed);
        let fallbacks = format!("{SECOND}, {THIRD}");
        (settings.stun_fallbacks, settings.stun_fallbacks_len) = as_text(&fallbacks);
        let (status, stack) = create(&settings);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let account = account_on(stack);
        assert_eq!(
            unsafe { sipral_account_register(stack, account, 10) },
            SipralStatus::Ok
        );

        let out = run_signalling(stack, 10, 6_000);
        let asked: Vec<&str> = out
            .iter()
            .filter(|(message, _)| is_stun(message))
            .map(|(_, to)| to.as_str())
            .collect();
        assert_eq!(
            asked,
            vec![SERVER, SERVER, SERVER, SERVER, SECOND],
            "four to the first, and the second asked the moment the first is given up on"
        );
        assert_eq!(
            servers_said(),
            vec![ServerSaid {
                state: super::SipralStunServerState::Changed as u32,
                server: SECOND.to_owned(),
                previous: SERVER.to_owned(),
            }]
        );
        let request = out
            .iter()
            .rev()
            .find(|(message, to)| is_stun(message) && to == SECOND)
            .map(|(message, _)| message.clone())
            .expect("a request to the second server");
        assert_eq!(
            from_address(stack, &answer(&request, SIP_PUBLIC), SECOND, 6_000),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let _ = poll(stack, 6_000);
        let learned = mapped();
        assert_eq!(learned.len(), 1, "{learned:?}");
        assert_eq!(learned[0].mapping, SipralNatMapping::Learned as u32);
        assert_eq!(learned[0].public, SIP_PUBLIC);
        assert_eq!(
            learned[0].accounts, 1,
            "the account moved onto what it said"
        );
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }

    #[test]
    fn every_server_failing_is_said_once() {
        let mut observed = Observed::default();
        let _ = servers_said();
        let mut settings = asking(&mut observed);
        (settings.stun_fallbacks, settings.stun_fallbacks_len) = as_text(SECOND);
        let (status, stack) = create(&settings);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let _ = run_signalling(stack, 10, 12_000);
        assert_eq!(
            servers_said(),
            vec![
                ServerSaid {
                    state: super::SipralStunServerState::Changed as u32,
                    server: SECOND.to_owned(),
                    previous: SERVER.to_owned(),
                },
                ServerSaid {
                    state: super::SipralStunServerState::AllFailed as u32,
                    server: SECOND.to_owned(),
                    previous: String::new(),
                },
            ]
        );
        let said = mapped();
        assert_eq!(said.len(), 1, "{said:?}");
        assert_eq!(said[0].mapping, SipralNatMapping::Unanswered as u32);
        // the refreshes go on, and the silence is not announced again
        let _ = run_signalling(stack, 12_100, 70_000);
        assert!(servers_said().is_empty());
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }

    #[test]
    fn fallbacks_are_addresses_and_stand_behind_a_server() {
        let mut observed = Observed::default();
        let mut settings = asking(&mut observed);
        (settings.stun_fallbacks, settings.stun_fallbacks_len) =
            as_text("198.51.100.2:3478,stun.example.net:3478");
        assert_eq!(create(&settings).0, SipralStatus::InvalidArgument);
        let said = last_error_text();
        assert!(said.contains("stun_fallbacks entry 1"), "{said}");

        let mut settings = asking(&mut observed);
        (settings.stun_fallbacks, settings.stun_fallbacks_len) = as_text("198.51.100.2:3478,");
        assert_eq!(
            create(&settings).0,
            SipralStatus::InvalidArgument,
            "an empty entry is a list written wrong, not one fewer server"
        );

        let mut settings = asking(&mut observed);
        settings.stun_server = ptr::null();
        settings.stun_server_len = 0;
        (settings.stun_fallbacks, settings.stun_fallbacks_len) = as_text(SECOND);
        assert_eq!(create(&settings).0, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("names none to turn from"));

        let mut settings = config(listen, &mut observed);
        (settings.stun_fallbacks, settings.stun_fallbacks_len) = as_text(SECOND);
        assert_eq!(
            create(&settings).0,
            SipralStatus::InvalidArgument,
            "a list nothing would ask is a setting nothing reads"
        );
    }

    #[test]
    fn the_servers_are_replaced_on_a_running_stack_and_asked_at_once() {
        let mut observed = Observed::default();
        let _ = servers_said();
        let (stack, _) = behind_the_nat(&mut observed, |_| {});
        let _ = mapped();

        assert_eq!(
            set_servers(stack, THIRD, 100),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let out = signalling_out(stack);
        assert_eq!(out.len(), 1, "not at the next refresh: now. {out:?}");
        assert!(is_stun(&out[0].0));
        assert_eq!(out[0].1, THIRD);
        assert_eq!(
            from_address(stack, &answer(&out[0].0, "203.0.113.7:52000"), THIRD, 120),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let _ = poll(stack, 120);
        assert_eq!(
            servers_said(),
            vec![ServerSaid {
                state: super::SipralStunServerState::Changed as u32,
                server: THIRD.to_owned(),
                previous: SERVER.to_owned(),
            }]
        );
        let said = mapped();
        assert_eq!(said.len(), 1, "{said:?}");
        assert_eq!(said[0].mapping, SipralNatMapping::Moved as u32);
        assert_eq!(said[0].public, "203.0.113.7:52000");
        let register = signalling_out(stack)
            .into_iter()
            .find(|(message, _)| message.starts_with(b"REGISTER "))
            .expect("the account registered where the new server says it is");
        assert!(
            header(&register.0, "Contact")
                .is_some_and(|contact| contact.starts_with("<sip:alice@203.0.113.7:52000>")),
            "{:?}",
            header(&register.0, "Contact")
        );
        assert_eq!(
            set_servers(stack, "not-an-address", 130),
            SipralStatus::InvalidArgument
        );
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }

    #[test]
    fn stun_starts_on_a_stack_created_without_it() {
        let mut observed = Observed::default();
        let _ = mapped();
        let (status, stack) = create(&config(listen, &mut observed));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let account = account_on(stack);
        assert_eq!(
            unsafe { sipral_account_register(stack, account, 10) },
            SipralStatus::Ok
        );
        let _ = signalling_out(stack);
        assert_eq!(
            map_media(stack, 20),
            SipralStatus::WrongState,
            "nobody is asked yet"
        );

        assert_eq!(
            set_servers(stack, SERVER, 30),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let out = signalling_out(stack);
        let request = out
            .iter()
            .find(|(message, to)| is_stun(message) && to == SERVER)
            .map(|(message, _)| message.clone())
            .expect("the main transport is asked about at once");
        assert_eq!(
            from_server(stack, &answer(&request, SIP_PUBLIC), 40),
            SipralStatus::Ok
        );
        let _ = poll(stack, 40);
        let said = mapped();
        assert_eq!(said.len(), 1, "{said:?}");
        assert_eq!(said[0].accounts, 1, "the account registering moved onto it");
        assert_eq!(
            map_media(stack, 50),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }

    #[test]
    fn asking_nobody_any_more_puts_every_contact_back_on_its_socket() {
        let mut observed = Observed::default();
        let (stack, _) = behind_the_nat(&mut observed, |_| {});
        assert_eq!(
            set_servers(stack, "", 100),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let register = signalling_out(stack)
            .into_iter()
            .find(|(message, _)| message.starts_with(b"REGISTER "))
            .expect("the account registered its own address again");
        assert!(
            header(&register.0, "Contact")
                .is_some_and(|contact| contact.starts_with("<sip:alice@192.0.2.10:5060>")),
            "{:?}",
            header(&register.0, "Contact")
        );
        assert_eq!(map_media(stack, 110), SipralStatus::WrongState);
        let out = run_signalling(stack, 120, 60_000);
        assert!(
            !out.iter().any(|(message, _)| is_stun(message)),
            "nothing asked any more"
        );
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }

    /// A stack configured with `configure`, an account registered on it and
    /// moved onto [`SIP_PUBLIC`] by the STUN answer, its REGISTER there
    /// granted: what the registrar keep-alive tests start from. Answers the
    /// stack and the registrar's address.
    fn behind_the_nat(
        observed: &mut Observed,
        configure: impl FnOnce(&mut SipralStackConfig),
    ) -> (SipralHandle, String) {
        let _ = mapped();
        let mut settings = asking(observed);
        configure(&mut settings);
        let (status, stack) = create(&settings);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let account = account_on(stack);
        assert_eq!(
            unsafe { sipral_account_register(stack, account, 10) },
            SipralStatus::Ok
        );
        let out = signalling_out(stack);
        assert_eq!(
            from_server(stack, &answer(&out[0].0, SIP_PUBLIC), 20),
            SipralStatus::Ok
        );
        let _ = poll(stack, 20);
        let (register, registrar) = signalling_out(stack)
            .into_iter()
            .rev()
            .find(|(message, _)| message.starts_with(b"REGISTER "))
            .expect("the REGISTER naming the public address");
        let mut granted = b"SIP/2.0 200 OK\r\n".to_vec();
        for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
            let value = header(&register, name).expect("a field to copy");
            granted.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        granted.extend_from_slice(
            b"Contact: <sip:alice@203.0.113.7:41000>\r\nExpires: 3600\r\nContent-Length: 0\r\n\r\n",
        );
        let status = unsafe {
            sipral_stack_receive_datagram(
                stack,
                SIPRAL_TRANSPORT_MAIN,
                granted.as_ptr(),
                granted.len(),
                registrar.as_ptr().cast::<c_char>(),
                registrar.len(),
                ptr::null(),
                0,
                30,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let _ = poll(stack, 30);
        let _ = signalling_out(stack);
        (stack, registrar)
    }

    /// How many keep-alives went to `registrar` between `from_ms` and
    /// `until_ms`, polling once a second as an application that sleeps until
    /// the stack's next deadline would, at worst, more often.
    fn keepalives_to(stack: SipralHandle, registrar: &str, from_ms: u64, until_ms: u64) -> usize {
        let mut count = 0;
        let mut now = from_ms;
        while now <= until_ms {
            let _ = poll(stack, now);
            count += signalling_out(stack)
                .iter()
                .filter(|(message, destination)| {
                    message.as_slice() == b"\r\n\r\n" && destination == registrar
                })
                .count();
            now += 1_000;
        }
        count
    }

    /// The lab's failure: behind an address-and-port-filtering NAT, a call
    /// 330 s after the REGISTER never arrived, because nothing but the STUN
    /// refresh left the socket in between and it went to the STUN server.
    /// Behind a NAT the stack now keeps the registrar's own flow open, by
    /// default, every 20 to 25 seconds.
    #[test]
    fn an_account_behind_the_nat_keeps_its_registrars_flow_open() {
        let mut observed = Observed::default();
        let (stack, registrar) = behind_the_nat(&mut observed, |_| {});
        let sent = keepalives_to(stack, &registrar, 1_000, 330_000);
        assert!((13..=17).contains(&sent), "{sent} keep-alives in 330 s");
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }

    #[test]
    fn the_registrar_keepalive_follows_its_setting_and_stops_while_suspended() {
        let mut observed = Observed::default();
        let (stack, registrar) = behind_the_nat(&mut observed, |settings| {
            settings.registrar_keepalive_ms = 10_000;
        });
        let sent = keepalives_to(stack, &registrar, 1_000, 101_000);
        assert!((10..=12).contains(&sent), "{sent} keep-alives in 100 s");

        // a phone going to sleep is woken by a push, not by a process that
        // is not running
        let mut report = crate::lifecycle::SipralSuspending {
            size: size_of::<crate::lifecycle::SipralSuspending>(),
            unverified: 0,
            subscriptions: 0,
            calls: 0,
        };
        assert_eq!(
            unsafe { crate::lifecycle::sipral_stack_suspending(stack, 102_000, &raw mut report) },
            SipralStatus::Ok
        );
        assert_eq!(keepalives_to(stack, &registrar, 103_000, 300_000), 0);
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);

        let mut observed = Observed::default();
        let (stack, registrar) = behind_the_nat(&mut observed, |settings| {
            settings.registrar_keepalive = crate::media::SipralToggle::Off as u32;
        });
        assert_eq!(keepalives_to(stack, &registrar, 1_000, 120_000), 0);
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
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

    /// The half a phone does not start: a registrar with no NAT helper sends
    /// the INVITE to the `Contact` it holds, which after STUN is the public
    /// address, and writes the same address in `To`. The call has to be
    /// recognised as the account's, and answered through
    /// `sipral_call_answer_media` — what the Kotlin and Swift layers call —
    /// with that address in the 2xx's own `Contact` as well as in `c=`: the
    /// ACK, and every request the far end sends in the dialog, go where the
    /// `Contact` says (RFC 3261 §12.1.2: the far end, as UAC, sets its remote
    /// target from this response's `Contact`), and the address the INVITE
    /// arrived on is one nobody outside can reach.
    #[test]
    fn a_call_to_the_public_contact_is_the_accounts_and_is_answered_from_it() {
        let mut observed = Observed::default();
        let stack = asking_stack(&mut observed);
        let account = account_on(stack);
        assert_eq!(
            unsafe { sipral_account_register(stack, account, 10) },
            SipralStatus::Ok
        );
        let out = signalling_out(stack);
        assert_eq!(
            from_server(stack, &answer(&out[0].0, SIP_PUBLIC), 20),
            SipralStatus::Ok
        );
        let _ = poll(stack, 20);
        assert_eq!(mapped()[0].accounts, 1, "the account moved");
        let _ = signalling_out(stack);

        let invite = String::from_utf8_lossy(&crate::call::tests::invitation())
            .replace(
                "INVITE sip:alice@192.0.2.10:5060 ",
                &format!("INVITE sip:alice@{SIP_PUBLIC} "),
            )
            .replace("To: <sip:alice@example.com>", "To: <sip:alice@203.0.113.7>");
        crate::call::tests::deliver(stack, invite.as_bytes(), 1_000);
        let _ = poll(stack, 1_000);
        let call = crate::call::tests::called(&observed);
        let (named_account, _) = observed
            .named
            .iter()
            .zip(observed.events.iter())
            .find(|(_, event)| event.1 == SipralEventKind::IncomingCall)
            .map(|(named, _)| *named)
            .expect("the incoming call was reported");
        assert_eq!(named_account, account, "the INVITE is the account's");
        let _ = signalling_out(stack);

        assert_eq!(map_media(stack, 1_100), SipralStatus::Ok);
        let out = stun_out(stack);
        assert_eq!(
            on_media_socket(stack, &answer(&out[0].0, MEDIA_PUBLIC), SERVER, 1_110),
            SipralStatus::Ok
        );
        let _ = poll(stack, 1_110);
        assert_eq!(
            unsafe {
                crate::call::sipral_call_answer_media(
                    stack,
                    call,
                    MEDIA.as_ptr().cast::<c_char>(),
                    MEDIA.len(),
                    1_200,
                )
            },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let out = signalling_out(stack);
        let ok = out
            .iter()
            .find(|(message, _)| message.starts_with(b"SIP/2.0 200 "))
            .expect("the 200 OK went out");
        assert_eq!(
            header(&ok.0, "Contact").as_deref(),
            Some("<sip:alice@203.0.113.7:41000>")
        );
        let text = String::from_utf8_lossy(&ok.0).into_owned();
        assert!(text.contains("c=IN IP4 203.0.113.7\r\n"), "{text}");
        assert!(text.contains("m=audio 41002 "), "{text}");
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

    /// A stack that asks nobody still takes a datagram for a call described
    /// on the socket it arrived on: the loop that hands a socket the
    /// branches of a forked call share to `sipral_stack_receive_stun` needs
    /// no STUN server to do it. A datagram for no call is still refused as
    /// before.
    #[test]
    fn a_stack_that_asks_nobody_still_hands_a_calls_datagrams_to_the_call() {
        let mut observed = Observed::default();
        let (stack, _call) = crate::call::tests::media_call(&mut observed);
        let peer = crate::call::tests::PEER_MEDIA;
        let rtp = |sequence: u16| {
            let mut out = vec![0x80, 0x00];
            out.extend_from_slice(&sequence.to_be_bytes());
            out.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
            out.extend_from_slice(&0xDEAD_BEEF_u32.to_be_bytes());
            out.extend_from_slice(&[0xFF; 160]);
            out
        };
        // RFC 3550 A.1 wants two packets in a row before a source is
        // believed, so the first is the session's and dropped by it
        let _ = on_media_socket(stack, &rtp(1), peer, 2_000);
        assert_eq!(
            on_media_socket(stack, &rtp(2), peer, 2_020),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            on_media_socket(stack, b"\x01\x01\x00\x00", SERVER, 2_040),
            SipralStatus::WrongState
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
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

    /// Everything `sipral_stack_poll_stun` hands out, each with the protocol
    /// it is marked to go over.
    #[cfg(feature = "ice")]
    fn stun_out_marked(stack: SipralHandle) -> Vec<(Vec<u8>, String, String, u32)> {
        let mut buffers = Buffers::new();
        let mut all = Vec::new();
        loop {
            let mut transmit = buffers.transmit();
            let status = unsafe { sipral_stack_poll_stun(stack, &raw mut transmit) };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            if transmit.len == 0 {
                return all;
            }
            let (message, destination, source) = buffers.taken(&transmit);
            all.push((message, destination, source, transmit.protocol));
        }
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

    #[cfg(feature = "ice")]
    const UDP: u32 = crate::stack::SipralTransport::Udp as u32;
    #[cfg(feature = "ice")]
    const TCP: u32 = crate::stack::SipralTransport::Tcp as u32;
    #[cfg(feature = "ice")]
    const TLS: u32 = crate::stack::SipralTransport::Tls as u32;

    /// A stack whose TURN server is reached over `protocol`.
    #[cfg(feature = "ice")]
    fn relaying_over(observed: &mut Observed, protocol: u32) -> SipralStackConfig {
        let mut settings = relaying(observed);
        settings.turn_transport = protocol;
        settings
    }

    #[cfg(feature = "ice")]
    fn turn_connected(stack: SipralHandle, now_ms: u64) -> SipralStatus {
        unsafe {
            sipral_stack_turn_connected(stack, MEDIA.as_ptr().cast::<c_char>(), MEDIA.len(), now_ms)
        }
    }

    #[cfg(feature = "ice")]
    fn turn_receive(stack: SipralHandle, bytes: &[u8], now_ms: u64) -> SipralStatus {
        unsafe {
            sipral_stack_turn_receive(
                stack,
                MEDIA.as_ptr().cast::<c_char>(),
                MEDIA.len(),
                bytes.as_ptr(),
                bytes.len(),
                now_ms,
            )
        }
    }

    #[cfg(feature = "ice")]
    fn turn_closed(stack: SipralHandle, now_ms: u64) -> SipralStatus {
        unsafe {
            sipral_stack_turn_closed(stack, MEDIA.as_ptr().cast::<c_char>(), MEDIA.len(), now_ms)
        }
    }

    /// A stack over `protocol`, its media socket named and mapped, and the
    /// connection it asked for said to be open: the stack and the account,
    /// with the Allocate that went on the connection.
    #[cfg(feature = "ice")]
    fn connected_stack(
        observed: &mut Observed,
        protocol: u32,
    ) -> (SipralHandle, SipralHandle, Vec<u8>) {
        let _ = mapped();
        let _ = relayed();
        let _ = streams();
        let (status, stack) = create(&relaying_over(observed, protocol));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let account = account_on(stack);
        let _ = signalling_out(stack);
        let _ = poll(stack, 5);
        let _ = mapped();
        assert_eq!(map_media(stack, 10), SipralStatus::Ok);
        let out = stun_out_marked(stack);
        assert_eq!(
            out.len(),
            1,
            "the Binding request, and no Allocate before the connection"
        );
        assert!(!is_allocate(&out[0].0));
        assert_eq!(
            out[0].3, UDP,
            "the mapping is the socket's own, asked over UDP"
        );
        assert_eq!(
            on_media_socket(stack, &answer(&out[0].0, MEDIA_PUBLIC), SERVER, 12),
            SipralStatus::Ok
        );
        let _ = poll(stack, 12);
        assert_eq!(
            streams(),
            vec![StreamSaid {
                state: SipralTurnStream::Open as u32,
                protocol,
                local: MEDIA.to_owned(),
                server: SERVER.to_owned(),
            }]
        );
        assert_eq!(
            turn_connected(stack, 15),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let out = stun_out_marked(stack);
        assert_eq!(out.len(), 1, "{out:?}");
        let (allocate, destination, source, marked) = out.into_iter().next().expect("one");
        assert!(is_allocate(&allocate));
        assert_eq!(
            (destination.as_str(), source.as_str(), marked),
            (SERVER, MEDIA, protocol)
        );
        (stack, account, allocate)
    }

    #[cfg(feature = "ice")]
    #[test]
    fn a_turn_transport_needs_a_turn_server_and_is_one_of_three() {
        let mut observed = Observed::default();
        let mut no_server = asking(&mut observed);
        no_server.turn_transport = TCP;
        assert_eq!(create(&no_server).0, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("turn_transport"));
        let mut websocket = relaying(&mut observed);
        websocket.turn_transport = crate::stack::SipralTransport::Ws as u32;
        assert_eq!(create(&websocket).0, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("turn_transport"));
        for fine in [0, UDP, TCP, TLS] {
            assert_eq!(
                create(&relaying_over(&mut observed, fine)).0,
                SipralStatus::Ok,
                "{fine}: {}",
                last_error_text()
            );
        }
    }

    /// Over TCP nothing about the relay is a datagram: the Allocate waits for
    /// the connection, goes on it, is answered on it in whatever pieces, and
    /// the call that takes the relay writes its permission and its checks
    /// through it, and gives it back on it when it ends — after which the
    /// connection has nothing left to carry, and the application is told to
    /// close it.
    #[cfg(feature = "ice")]
    #[test]
    fn a_relay_over_tcp_is_made_on_its_connection_and_the_call_carries_it_there() {
        let mut observed = Observed::default();
        let (stack, account, allocate) = connected_stack(&mut observed, TCP);
        let reply = turn_answer(&allocate, RELAYED_AT, "203.0.113.7:52000");
        // the server answers on the connection, and the same answer in a
        // datagram from its address allocates nothing
        let _ = on_media_socket(stack, &reply, SERVER, 20);
        let _ = poll(stack, 20);
        assert!(relayed().is_empty(), "a datagram was believed");
        for piece in reply.chunks(7) {
            assert_eq!(
                turn_receive(stack, piece, 20),
                SipralStatus::Ok,
                "{}",
                last_error_text()
            );
        }
        let _ = poll(stack, 20);
        assert_eq!(
            relayed(),
            vec![RelaySaid {
                outcome: SipralNatRelay::Allocated as u32,
                code: 0,
                local: MEDIA.to_owned(),
                relayed: RELAYED_AT.to_owned(),
                // the connection's own mapping says nothing about the socket
                mapped: String::new(),
                reason: String::new(),
            }]
        );

        let (call, invite, _, _) = place_ice(stack, account, 30);
        let text = String::from_utf8_lossy(&invite).into_owned();
        assert!(text.contains("198.51.100.1 50000 typ relay"), "{text}");
        // the connection's own mapping is no candidate of the socket's
        assert!(!text.contains("52000 typ srflx"), "{text}");
        assert!(text.contains("c=IN IP4 203.0.113.7\r\n"), "{text}");
        crate::call::tests::deliver(
            stack,
            &crate::call::tests::accepted(&invite, &ice_answer(), true),
            50,
        );
        let _ = poll(stack, 50);
        let media = media_of(stack, call);
        let mut sent = Vec::new();
        for at in (50..400).step_by(20) {
            let _ = poll(stack, at);
            sent.extend(media_out_marked(media, at));
        }
        assert!(
            sent.iter().any(|(message, to, marked)| {
                *marked == TCP && to == SERVER && message.get(..2) == Some(&[0x00, 0x08][..])
            }),
            "the permission for the far end went on the connection: {sent:?}"
        );
        assert!(
            !sent
                .iter()
                .any(|(_, to, marked)| to == SERVER && *marked != TCP),
            "a datagram to a server reached over TCP: {sent:?}"
        );
        assert!(
            sent.iter()
                .any(|(_, to, marked)| *marked == UDP && to == PEER_CHECKS_FROM),
            "and the host pair is checked from the socket as ever: {sent:?}"
        );

        assert_eq!(
            unsafe { crate::call::sipral_call_hangup(stack, call, 500) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let _ = streams();
        let _ = poll(stack, 500);
        let given_back: Vec<(Vec<u8>, String, u32)> = farewells_marked(stack)
            .into_iter()
            .filter(|(message, ..)| refresh_lifetime(message) == Some(0))
            .collect();
        assert_eq!(given_back.len(), 1, "{given_back:?}");
        assert_eq!((given_back[0].1.as_str(), given_back[0].2), (SERVER, TCP));
        assert_eq!(
            streams(),
            vec![StreamSaid {
                state: SipralTurnStream::Close as u32,
                protocol: TCP,
                local: MEDIA.to_owned(),
                server: SERVER.to_owned(),
            }],
            "nothing more for the connection once the call is gone"
        );
    }

    #[cfg(feature = "ice")]
    #[test]
    fn a_connection_that_never_opens_leaves_the_socket_without_a_relay() {
        let mut observed = Observed::default();
        let _ = relayed();
        let _ = streams();
        let (status, stack) = create(&relaying_over(&mut observed, TLS));
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let account = account_on(stack);
        let _ = signalling_out(stack);
        assert_eq!(map_media(stack, 10), SipralStatus::Ok);
        let out = stun_out_marked(stack);
        let _ = on_media_socket(stack, &answer(&out[0].0, MEDIA_PUBLIC), SERVER, 12);
        let _ = poll(stack, 12);
        assert_eq!(streams().len(), 1);
        let mut offering = managed_config();
        offering.ice = crate::media::SipralIce::Offered as u32;
        assert_eq!(
            place(stack, account, &offering, 13).0,
            SipralStatus::WrongState
        );
        assert!(last_error_text().contains("sipral_stack_turn_connected"));

        assert_eq!(turn_closed(stack, 14), SipralStatus::Ok);
        let _ = poll(stack, 14);
        let said = relayed();
        assert_eq!(said.len(), 1, "{said:?}");
        assert_eq!(said[0].outcome, SipralNatRelay::Failed as u32);
        assert_eq!(said[0].code, 0);
        assert!(said[0].reason.contains("connection"), "{}", said[0].reason);
        assert!(streams().is_empty(), "the application closed it already");
        assert!(stun_out_marked(stack).is_empty(), "no Allocate goes");
        assert_eq!(turn_connected(stack, 15), SipralStatus::InvalidArgument);
        let (status, _) = place(stack, account, &offering, 16);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    }

    #[cfg(feature = "ice")]
    #[test]
    fn a_connection_that_stops_making_sense_is_broken_and_its_relay_lost() {
        let mut observed = Observed::default();
        let (stack, _, _) = connected_stack(&mut observed, TCP);
        assert_eq!(
            turn_receive(stack, &[22, 0xfe, 0xfd, 0, 0, 0, 0, 0], 20),
            SipralStatus::StreamBroken
        );
        assert!(last_error_text().contains("close it"));
        let _ = poll(stack, 20);
        let said = relayed();
        assert_eq!(said.len(), 1, "{said:?}");
        assert_eq!(said[0].outcome, SipralNatRelay::Failed as u32);
        assert!(streams().is_empty(), "the answer already said to close it");
        assert_eq!(
            turn_receive(stack, &[0x40, 0, 0, 0], 21),
            SipralStatus::InvalidArgument,
            "nothing is open there any more"
        );
    }

    #[cfg(feature = "ice")]
    #[test]
    fn unmapping_gives_the_relay_back_on_its_connection_and_closes_it() {
        let mut observed = Observed::default();
        let (stack, _, allocate) = connected_stack(&mut observed, TLS);
        let reply = turn_answer(&allocate, RELAYED_AT, MEDIA_PUBLIC);
        assert_eq!(turn_receive(stack, &reply, 20), SipralStatus::Ok);
        let _ = poll(stack, 20);
        assert_eq!(relayed().len(), 1);
        assert_eq!(unmap(stack, MEDIA, 30), SipralStatus::Ok);
        let out = stun_out_marked(stack);
        assert!(
            out.iter().any(|(request, destination, source, marked)| {
                refresh_lifetime(request) == Some(0)
                    && destination == SERVER
                    && source == MEDIA
                    && *marked == TLS
            }),
            "{out:?}"
        );
        let _ = poll(stack, 30);
        assert_eq!(
            streams(),
            vec![StreamSaid {
                state: SipralTurnStream::Close as u32,
                protocol: TLS,
                local: MEDIA.to_owned(),
                server: SERVER.to_owned(),
            }]
        );
    }

    /// Everything a call's media handle hands out, with where it goes and
    /// what over.
    #[cfg(feature = "ice")]
    fn media_out_marked(media: SipralHandle, now_ms: u64) -> Vec<(Vec<u8>, String, u32)> {
        let mut data = vec![0_u8; crate::media::SIPRAL_MEDIA_PACKET_BYTES];
        let mut destination: [c_char; SIPRAL_ADDRESS_BYTES] = [0; SIPRAL_ADDRESS_BYTES];
        let mut all = Vec::new();
        loop {
            let mut packet = crate::media::SipralMediaPacket {
                reserved: 0,
                size: size_of::<crate::media::SipralMediaPacket>(),
                data: data.as_mut_ptr(),
                capacity: data.len(),
                len: 0,
                destination: destination.as_mut_ptr(),
                destination_capacity: destination.len(),
                destination_len: 0,
                protocol: u32::MAX,
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
            all.push((
                data.get(..packet.len).unwrap_or_default().to_vec(),
                to,
                packet.protocol,
            ));
        }
    }

    /// Everything `sipral_stack_poll_farewell` hands out, with where it goes
    /// and what over.
    #[cfg(feature = "ice")]
    fn farewells_marked(stack: SipralHandle) -> Vec<(Vec<u8>, String, u32)> {
        let mut data = vec![0_u8; crate::media::SIPRAL_MEDIA_PACKET_BYTES];
        let mut destination: [c_char; SIPRAL_ADDRESS_BYTES] = [0; SIPRAL_ADDRESS_BYTES];
        let mut all = Vec::new();
        loop {
            let mut packet = crate::media::SipralMediaPacket {
                reserved: 0,
                size: size_of::<crate::media::SipralMediaPacket>(),
                data: data.as_mut_ptr(),
                capacity: data.len(),
                len: 0,
                destination: destination.as_mut_ptr(),
                destination_capacity: destination.len(),
                destination_len: 0,
                protocol: u32::MAX,
            };
            let mut call = SIPRAL_HANDLE_NONE;
            let status = unsafe {
                crate::media::sipral_stack_poll_farewell(stack, &raw mut call, &raw mut packet)
            };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            if packet.len == 0 {
                return all;
            }
            let to = unsafe { CStr::from_ptr(destination.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            all.push((
                data.get(..packet.len).unwrap_or_default().to_vec(),
                to,
                packet.protocol,
            ));
        }
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
                reserved: 0,
                size: size_of::<crate::media::SipralMediaPacket>(),
                data: data.as_mut_ptr(),
                capacity: data.len(),
                len: 0,
                destination: destination.as_mut_ptr(),
                destination_capacity: destination.len(),
                destination_len: 0,
                protocol: u32::MAX,
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

    /// A full peer's offer: its credentials, `a=rtcp-mux`, and one host
    /// candidate that is also where its checks come from. No `a=ice-lite`.
    #[cfg(feature = "ice")]
    fn full_offer() -> Vec<u8> {
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

    /// The full peer's check towards a lite end: it is the controlling side
    /// (RFC 8445 §6.1.1), and it nominates with `USE-CANDIDATE` (§8.1.1).
    #[cfg(feature = "ice")]
    fn nominating_check(ufrag: &str, pwd: &str, id: [u8; 12]) -> Vec<u8> {
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
            .add_u64(AttributeType::ICE_CONTROLLING, 7)
            .expect("room for ICE-CONTROLLING");
        builder
            .add(AttributeType::USE_CANDIDATE, &[])
            .expect("room for USE-CANDIDATE");
        builder
            .add_message_integrity(pwd.as_bytes())
            .expect("room for MESSAGE-INTEGRITY");
        builder.add_fingerprint().expect("room for FINGERPRINT");
        builder.finish()
    }

    /// `SIPRAL_ICE_LITE` through this ABI (RFC 8445 §2.5): a stack whose
    /// calls are lite answers a full peer's offer with `a=ice-lite` and the
    /// one host candidate its media socket is, answers the peer's checks
    /// without ever checking back — a lite end sends none — and puts the call
    /// on the pair the peer nominates, which `SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN`
    /// reports as it does for a full agent.
    #[cfg(feature = "ice")]
    #[test]
    fn a_lite_stack_answers_a_full_offer_and_takes_the_pair_the_peer_nominates() {
        let mut observed = Observed::default();
        let (stack, _) = crate::call::tests::media_line(&mut observed, |config| {
            config.ice = crate::media::SipralIce::Lite as u32;
        });
        let offer = full_offer();
        let mut invite = b"INVITE sip:alice@192.0.2.10:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-lite-in\r\n\
Max-Forwards: 70\r\n\
From: <sip:gateway@example.com>;tag=gateway\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: lite-in@203.0.113.5\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:gateway@203.0.113.5:5060>\r\n\
Content-Type: application/sdp\r\n"
            .to_vec();
        invite.extend_from_slice(format!("Content-Length: {}\r\n\r\n", offer.len()).as_bytes());
        invite.extend_from_slice(&offer);
        crate::call::tests::deliver(stack, &invite, 10);
        let _ = poll(stack, 10);
        let call = crate::call::tests::called(&observed);
        let _ = signalling_out(stack);

        let (media_address, media_address_len) = as_text(MEDIA);
        let status = unsafe {
            crate::call::sipral_call_answer_media(stack, call, media_address, media_address_len, 20)
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let ok = signalling_out(stack)
            .into_iter()
            .find(|(message, _)| message.starts_with(b"SIP/2.0 200 "))
            .expect("the 200")
            .0;
        let text = String::from_utf8_lossy(&ok).into_owned();
        assert!(text.contains("a=ice-lite\r\n"), "RFC 8839 §5.3: {text}");
        let candidates: Vec<&str> = text
            .split("\r\n")
            .filter(|line| line.starts_with("a=candidate:"))
            .collect();
        assert_eq!(candidates.len(), 1, "one host candidate: {candidates:?}");
        assert!(
            candidates[0].ends_with("192.0.2.10 40000 typ host"),
            "{candidates:?}"
        );
        let ufrag = attribute(&text, "ice-ufrag");
        let pwd = attribute(&text, "ice-pwd");

        crate::call::tests::deliver(stack, &crate::call::tests::acknowledged(&ok), 30);
        let _ = poll(stack, 30);
        let media = media_of(stack, call);

        let nominated = [4_u8; 12];
        let mut datagram = nominating_check(&ufrag, &pwd, nominated);
        let mut arrival = u32::MAX;
        let status = unsafe {
            crate::media::sipral_media_receive(
                media,
                datagram.as_mut_ptr(),
                datagram.len(),
                PEER_CHECKS_FROM.as_ptr().cast::<c_char>(),
                PEER_CHECKS_FROM.len(),
                40,
                &raw mut arrival,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let sent = media_over(stack, media, 40);
        assert_eq!(
            answered_and_triggered(&sent, nominated),
            (true, false),
            "answered, and never checked back: a lite end sends no checks: {sent:?}"
        );
        assert!(
            observed.kinds().contains(&SipralEventKind::MediaPathChosen),
            "the pair the peer nominated carries the call: {:?}",
            observed.kinds()
        );
    }

    /// A call placed with ICE and answered with it: the stack, the call,
    /// its media handle and the fragment its INVITE gave out.
    #[cfg(feature = "ice")]
    fn answered_ice_call(
        observed: &mut Observed,
    ) -> (SipralHandle, SipralHandle, SipralHandle, String) {
        let (stack, call, invite, ufrag, _) = ice_call(observed);
        crate::call::tests::deliver(
            stack,
            &crate::call::tests::accepted(&invite, &ice_answer(), true),
            50,
        );
        let _ = poll(stack, 50);
        let media = media_of(stack, call);
        (stack, call, media, ufrag)
    }

    /// One path, by index, with room for both its addresses.
    #[cfg(feature = "ice")]
    fn path_at(
        media: SipralHandle,
        index: usize,
    ) -> (
        SipralStatus,
        crate::media::SipralPathCandidate,
        String,
        String,
    ) {
        let mut local: [c_char; SIPRAL_ADDRESS_BYTES] = [0; SIPRAL_ADDRESS_BYTES];
        let mut remote: [c_char; SIPRAL_ADDRESS_BYTES] = [0; SIPRAL_ADDRESS_BYTES];
        let mut path = crate::media::SipralPathCandidate {
            reserved: 0,
            size: size_of::<crate::media::SipralPathCandidate>(),
            priority: 0,
            kind: 0,
            outcome: 0,
            code: 0,
            local_kind: 0,
            remote_kind: 0,
            local: local.as_mut_ptr(),
            local_capacity: local.len(),
            local_len: 0,
            remote: remote.as_mut_ptr(),
            remote_capacity: remote.len(),
            remote_len: 0,
        };
        let status =
            unsafe { crate::media::sipral_media_path_candidate_at(media, index, &raw mut path) };
        let text = |buffer: &[c_char; SIPRAL_ADDRESS_BYTES]| {
            unsafe { CStr::from_ptr(buffer.as_ptr()) }
                .to_string_lossy()
                .into_owned()
        };
        (status, path, text(&local), text(&remote))
    }

    /// D5's path half over the ABI: the pairs the call's agent formed, each
    /// between the addresses the two descriptions named, and what became of
    /// each — here, nothing yet, since nothing has answered a check.
    #[cfg(feature = "ice")]
    #[test]
    fn a_call_says_which_paths_its_agent_tried_and_what_became_of_each() {
        use crate::media::{
            SipralCandidateKind, SipralPathKind, SipralPathOutcome,
            sipral_media_path_candidate_count,
        };

        let mut observed = Observed::default();
        let (stack, _, media, _) = answered_ice_call(&mut observed);
        let mut count = usize::MAX;
        assert_eq!(
            unsafe { sipral_media_path_candidate_count(media, &raw mut count) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert!(count >= 1, "the agent paired nothing");
        let mut locals = Vec::new();
        for index in 0..count {
            let (status, path, local, remote) = path_at(media, index);
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            assert_eq!(path.kind, SipralPathKind::Pair as u32);
            assert_eq!(path.outcome, SipralPathOutcome::Waiting as u32);
            assert_eq!(path.code, 0);
            assert_eq!(remote, PEER_CHECKS_FROM);
            assert_eq!(path.remote_kind, SipralCandidateKind::Host as u32);
            assert_eq!(path.local_len, local.len());
            assert!(path.priority > 0);
            locals.push((local, path.local_kind));
        }
        // a reflexive candidate is paired as its base (RFC 8445 §6.1.2.4),
        // so every pair leaves from the socket itself
        assert!(
            locals
                .iter()
                .all(|(local, kind)| local == MEDIA && *kind == SipralCandidateKind::Host as u32),
            "{locals:?}"
        );
        // past the end, and an address buffer with no room, are refused
        // before anything is written
        let (past, ..) = path_at(media, count);
        assert_eq!(past, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains(&count.to_string()));
        let mut cramped: [c_char; 8] = [0; 8];
        let mut path = crate::media::SipralPathCandidate {
            reserved: 0,
            size: size_of::<crate::media::SipralPathCandidate>(),
            priority: 0,
            kind: 0,
            outcome: 0,
            code: 0,
            local_kind: 0,
            remote_kind: 0,
            local: cramped.as_mut_ptr(),
            local_capacity: cramped.len(),
            local_len: 0,
            remote: ptr::null_mut(),
            remote_capacity: 0,
            remote_len: 0,
        };
        assert_eq!(
            unsafe { crate::media::sipral_media_path_candidate_at(media, 0, &raw mut path) },
            SipralStatus::BufferTooSmall
        );
        path.size =
            <crate::media::SipralPathCandidate as crate::versioned::Versioned>::MIN_SIZE - 1;
        assert_eq!(
            unsafe { crate::media::sipral_media_path_candidate_at(media, 0, &raw mut path) },
            SipralStatus::UnsupportedVersion
        );
        assert_eq!(
            unsafe { sipral_media_path_candidate_count(media, ptr::null_mut()) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// A pair that lost, over the ABI: the far end refused this end's check,
    /// and the list says so, with the STUN code it refused with.
    #[cfg(feature = "ice")]
    #[test]
    fn a_pair_the_far_end_refused_says_so_with_its_code() {
        use crate::media::{SipralPathOutcome, sipral_media_receive};
        use sipral_nat::stun::{Class, Message, MessageBuilder, Method};

        let mut observed = Observed::default();
        let (stack, _, media, _) = answered_ice_call(&mut observed);
        // this end's check towards the far end, answered with a 400 signed
        // with the password the far end's answer gave out (RFC 8445
        // §7.2.5.2.4): the pair has failed, and says why
        let sent = media_over(stack, media, 60);
        let check = sent
            .iter()
            .filter(|(_, to)| to == PEER_CHECKS_FROM)
            .filter_map(|(message, _)| Message::parse(message).ok())
            .find(|message| message.class() == Class::Request)
            .map(|message| message.transaction_id())
            .expect("a check towards the far end");
        let mut builder = MessageBuilder::new(Class::Error, Method::BINDING, check);
        builder
            .add_error_code(400, b"no")
            .expect("room for ERROR-CODE");
        builder
            .add_message_integrity(PEER_PWD.as_bytes())
            .expect("room for MESSAGE-INTEGRITY");
        builder.add_fingerprint().expect("room for FINGERPRINT");
        let mut refusal = builder.finish();
        let status = unsafe {
            sipral_media_receive(
                media,
                refusal.as_mut_ptr(),
                refusal.len(),
                PEER_CHECKS_FROM.as_ptr().cast::<c_char>(),
                PEER_CHECKS_FROM.len(),
                420,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let (status, path, _, remote) = path_at(media, 0);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(remote, PEER_CHECKS_FROM);
        assert_eq!(path.outcome, SipralPathOutcome::Refused as u32);
        assert_eq!(path.code, 400);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// A restart this end starts, over the ABI: the call goes out again as a
    /// re-offer whose credentials are not the ones the first offer gave out
    /// (RFC 8839 §4.4.1.1.1), and a second one is refused while the first is
    /// on its way.
    #[cfg(feature = "ice")]
    #[test]
    fn a_restart_this_end_starts_goes_out_with_new_credentials() {
        use crate::call::sipral_call_restart_ice;

        let mut observed = Observed::default();
        let (stack, call, _, ufrag) = answered_ice_call(&mut observed);
        let _ = signalling_out(stack);
        assert_eq!(
            unsafe { sipral_call_restart_ice(stack, call, 60) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let reoffer = signalling_out(stack)
            .into_iter()
            .find(|(message, _)| message.starts_with(b"INVITE "))
            .expect("the re-offer")
            .0;
        let text = String::from_utf8_lossy(&reoffer).into_owned();
        assert_ne!(attribute(&text, "ice-ufrag"), ufrag);
        assert!(text.contains("a=candidate:"), "{text}");
        assert_eq!(
            unsafe { sipral_call_restart_ice(stack, call, 70) },
            SipralStatus::WrongState,
            "a second restart went while the first was on its way"
        );
        assert_eq!(
            unsafe { sipral_call_restart_ice(stack, SIPRAL_HANDLE_NONE, 70) },
            SipralStatus::InvalidHandle
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// A call running no ICE agent has nothing to restart, and says so
    /// rather than sending an offer.
    #[cfg(feature = "ice")]
    #[test]
    fn a_restart_asked_of_a_call_without_ice_is_the_wrong_state() {
        let mut observed = Observed::default();
        let (stack, call) = crate::call::tests::media_call(&mut observed);
        assert_eq!(
            unsafe { crate::call::sipral_call_restart_ice(stack, call, 2_000) },
            SipralStatus::WrongState
        );
        assert!(
            last_error_text().contains("no ICE agent"),
            "{}",
            last_error_text()
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }
}
