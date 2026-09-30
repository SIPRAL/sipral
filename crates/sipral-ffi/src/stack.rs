// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A stack: made, polled, destroyed — and the rules a binding author will
//! otherwise have to guess.
//!
//! Everything the library has to tell the application arrives on one callback,
//! and the callback runs inside [`sipral_stack_poll`] and nowhere else. That
//! is the whole reason poll exists. A stack that called back from a thread of
//! its own would make every binding reason about which thread it is on, and
//! Swift, .NET, Kotlin and Python each answer that question differently; a stack that
//! calls back only where it was polled has nothing to answer.
//!
//! The clock arrives the same way. Nothing here reads one — except once, at
//! creation, to have an origin for the milliseconds the caller counts from —
//! because the layers below own no time either: the caller says what time it
//! is on every call that can put something on the wire, and a clock that goes
//! backwards by more than `CLOCK_SLACK_MS` is a caller bug reported as one
//! rather than a timer that never fires. Not further back than that, because
//! signalling may run on any thread and `now_ms` is read from whichever one
//! called last: two threads reading one clock do not agree to the
//! millisecond, and a reading a little behind the one before it is that and
//! not a caller mistake. Refusing anything moves nothing — the check runs
//! before the work the caller asked for, and the clock only ever advances
//! once that work has actually succeeded, so a call refused for an unrelated
//! reason (a bad handle, a bad argument) leaves it exactly where it was.
//!
//! # May one stack be used from two threads at once?
//!
//! For signalling, one thread at a time. A stack may be used from *any*
//! thread, and from a different thread on every call, but a call that arrives
//! while another thread is inside gets `SIPRAL_STATUS_BUSY` and does nothing.
//! It does not block, and it does not queue.
//!
//! That is the conservative answer, and it is chosen because it is the one
//! that stays true. A library that promised safe concurrent signalling would
//! owe that promise to every future member of every future state; one that
//! blocked would owe the caller a guarantee about how long. Busy costs a
//! binding one lock it was going to take anyway, and what keeps it rare is how
//! little the stack's lock is held for: the work of the call that took it, and
//! never the callback or a frame of audio. A binding that meets Busy has met a
//! second thread that really was inside at that moment.
//!
//! A call's media is outside this answer on purpose. It is reached through a
//! handle of its own ([`crate::media`]), each call's session has a lock of its
//! own, and no media entry point takes this one — so the thread that carries a
//! call's audio never waits on signalling, on the callback or on another call.
//!
//! The other way round is refused. Code run inside a frame of a call — a
//! processor — that calls into that call's stack gets `SIPRAL_STATUS_BUSY`,
//! even with nobody else inside: the stack's work can need the session the
//! frame is holding, and a thread that waited for it would be waiting for
//! itself, with this lock held.
//!
//! # May the library be re-entered from inside the event callback?
//!
//! Yes. A poll does the stack's work under the lock, takes what the stack has
//! to say out into a queue that owns everything the events point at, and lets
//! the lock go before it delivers the first one. Nothing is held while the
//! callback runs, so answering an event with a request, minting a call's media
//! handle or polling again from inside it is an ordinary call.
//!
//! The queue is the stack's rather than one poll's, and one poll at a time
//! delivers from it. A poll made from inside the callback, or from another
//! thread while one is delivering, does the stack's work and leaves what it
//! raised to the delivery already under way, so events arrive in the order
//! they were raised and never on two threads at once. Such a poll returns
//! before its own events are heard. And because the whole poll runs before the
//! first event is read, an event can describe something the stack has since
//! moved past: a call that ended inside the same poll has a stale handle by
//! the time its first event arrives.
//!
//! One delivery pass hands over only what was already queued when it began.
//! Anything posted while it runs — from another thread, or from the callback
//! itself — waits in the queue rather than being pulled into the same pass,
//! and the pass returns once it has delivered what it started with: nothing
//! here keeps a thread inside `sipral_stack_poll` for longer than that one
//! batch, however long other threads go on posting behind it. The next poll
//! on this stack, even one that raises nothing of its own, is what picks up
//! whatever was left, and the poll whose pass left it says that poll is due
//! now: `has_deadline` set and `next_poll_in_ms` zero, so a caller that waits
//! for input or for the deadline polls again at once instead of leaving the
//! events until a datagram or a timer wakes it.
//!
//! The queue itself holds at most `OUTBOX_CEILING` events at once. A poll
//! that finds it already full drops the events it would have added instead
//! of growing the queue further or waiting for room — signalling must answer
//! every call it is asked whatever the application's callback is doing — and
//! counts what it dropped in `sipral_counters_t::events_dropped`, appended at
//! that struct's tail so a caller who has never heard of it still reads
//! every counter that existed before it did.
//!
//! [`sipral_stack_destroy`] works from inside the callback as it always has.
//! It takes nothing but the handle table, and the poll that is delivering
//! holds its share of the stack until it returns, so the rest of its pass is
//! still delivered and a binding whose event handler is where its object gets
//! disposed does not need a queue of deferred frees to be correct. What was
//! posted while that pass ran is freed with the stack rather than delivered:
//! no poll can follow a destroy to take it.
//!
//! Everything that names no stack — the last error, the status and event-kind
//! names, the ABI version — is callable from anywhere at any time, including
//! from inside the callback and from any number of threads.

use std::collections::{HashMap, VecDeque};
use std::ffi::{c_char, c_void};
use std::net::SocketAddr;
use std::ptr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::{Duration, Instant};

use sipral::{Event, MediaConfig, MediaEngine, MediaEvent, WallClock};
use sipral_core::endpoint::{EndpointConfig, Input, Transmit, TransportId, TransportProtocol};
use sipral_core::transaction::{DialogId, TimerConfig};
use sipral_ua::{
    AccountId, AnnouncementId, CallHandle, CallIdentity, SubscriptionHandle, UaEvent, UserAgent,
};

use crate::abi::{Number, codes, record};
use crate::audio::{SipralAudio, SipralAudioActivation, SipralAudioTransmitCallback};
use crate::error::{Fail, entry, fail};
use crate::event::{SipralEvent, SipralEventCallback, Vocabulary};
use crate::handle::{
    HandleTable, Kind, Refused, SIPRAL_HANDLE_NONE, STACK_TAGS, SipralHandle, StackTag, StackTags,
};
use crate::inband::SipralDtmfDetection;
use crate::media::{
    SipralIce, SipralSrtp, SipralStreamStats, SipralToggle, catalog_of, ice_policy, media_failed,
    srtp_policy, stream_stats, toggle_of, toggled,
};
use crate::names::Names;
use crate::nat::SipralNat;
use crate::status::SipralStatus;
use crate::text::{bytes, required_text, text};
use crate::versioned::{Versioned, declared_size, read_versioned, write_versioned};

static STACKS: HandleTable<StackEntry> = HandleTable::new(Kind::Stack);

/// The tags every stack in this process mints its handles with, one each.
static TAGS: StackTags = StackTags::new();

/// Thirty-two bytes, which is what the endpoint derives every branch
/// parameter, tag and `Call-ID` from.
const SEED_BYTES: usize = 32;

/// The one transport a stack is bound to. Nothing here opens it.
///
/// Published to C as `SIPRAL_TRANSPORT_MAIN`, in [`crate::transport`], which is
/// also where the reason a stack has exactly one is written down.
pub(crate) const TRANSPORT: TransportId = TransportId(0);

/// How far behind this stack's last reading of the caller's clock a
/// signalling call may be and still be honoured.
///
/// Signalling may run on any thread, and each carries its own reading of the
/// same clock rather than sharing one: two of them a few milliseconds apart
/// is ordinary drift, not a caller that lost track of time. A media entry
/// point does not check against this at all — see `crate::media` — because
/// it never touches `polled_at_ms` in the first place; this is the tolerance
/// for the calls that do.
const CLOCK_SLACK_MS: u64 = 50;

/// How soon a poll that found the audio engine held by another thread asks
/// to be called again, so that the engine's news waits one short beat
/// rather than until whatever the stack's own next deadline is.
const AUDIO_BUSY_RETRY: Duration = Duration::from_millis(20);

codes! {
    /// What a stack speaks. Names for `sipral_stack_config_t::transport`.
    ///
    /// Zero is not one of them: a stack is told what it is speaking, because
    /// guessing wrong in the direction of the plainest transport is how a caller
    /// that meant TLS ends up on the wire in the clear.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralTransport: u32 {
        /// UDP.
        Udp = 1,
        /// TCP.
        Tcp = 2,
        /// TLS over TCP.
        Tls = 3,
        /// WebSocket.
        Ws = 4,
        /// WebSocket over TLS.
        Wss = 5,
    }
}

impl SipralTransport {
    /// What the layers below call it.
    pub(crate) const fn protocol(self) -> TransportProtocol {
        match self {
            Self::Udp => TransportProtocol::Udp,
            Self::Tcp => TransportProtocol::Tcp,
            Self::Tls => TransportProtocol::Tls,
            Self::Ws => TransportProtocol::Ws,
            Self::Wss => TransportProtocol::Wss,
        }
    }

    /// The number this ABI gives a protocol, or zero for one it has no number
    /// for — which is the same zero a caller who filled nothing in leaves.
    pub(crate) const fn named(protocol: TransportProtocol) -> u32 {
        match protocol {
            TransportProtocol::Udp => Self::Udp as u32,
            TransportProtocol::Tcp => Self::Tcp as u32,
            TransportProtocol::Tls => Self::Tls as u32,
            TransportProtocol::Ws => Self::Ws as u32,
            TransportProtocol::Wss => Self::Wss as u32,
            // the layer below has grown a transport this ABI has no number for,
            // and saying nothing beats picking one that is wrong
            _ => 0,
        }
    }
}

/// Every transport a stack has bound: [`SIPRAL_TRANSPORT_MAIN`], from the
/// moment the stack is created, and whatever
/// [`crate::transport::sipral_stack_transport_bind`] has added since.
///
/// Grows only, for the stack's whole life. `TransportId` documents itself, one
/// crate down, as "a transport the caller opened, named by the caller" — the
/// endpoint never interprets the number — so the numbers beyond
/// [`SIPRAL_TRANSPORT_MAIN`](crate::transport::SIPRAL_TRANSPORT_MAIN) are the
/// caller's own to choose, the same way `sipral_account_config_t::transport`
/// and `sipral_call_config_t::transport` are read straight through to here
/// with no translation. A transport that failed or whose stream closed is
/// retired one layer down — nothing can be sent on it until it is bound again
/// — which is a fact about whether it may be written to, not about whether
/// its number still names something: the whole point of remembering it here
/// is that `sipral_stack_transport_bind` can bring the very same one back.
pub(crate) struct Transports(HashMap<u32, TransportProtocol>);

impl Transports {
    /// A table with only the main transport in it, speaking what the stack
    /// was created to speak.
    fn new(main: TransportProtocol) -> Self {
        let mut entries = HashMap::new();
        entries.insert(TRANSPORT.0, main);
        Self(entries)
    }

    /// What a number names, or `None` for one this stack has never bound.
    pub(crate) fn resolve(&self, id: u32) -> Option<TransportId> {
        self.0.contains_key(&id).then_some(TransportId(id))
    }

    /// What a transport already bound speaks, or `None` for one that is not.
    pub(crate) fn protocol_of(&self, id: u32) -> Option<TransportProtocol> {
        self.0.get(&id).copied()
    }

    /// How many transports this stack has bound.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Every transport bound, by number, lowest first.
    pub(crate) fn listed(&self) -> Vec<(u32, TransportProtocol)> {
        let mut listed: Vec<(u32, TransportProtocol)> = self
            .0
            .iter()
            .map(|(id, protocol)| (*id, *protocol))
            .collect();
        listed.sort_unstable_by_key(|(id, _)| *id);
        listed
    }

    /// Record a transport as bound: the first time under a number, this is
    /// what mints the entry; every time after, the number already named this
    /// same protocol, so nothing here moves.
    pub(crate) fn record(&mut self, id: u32, protocol: TransportProtocol) {
        self.0.entry(id).or_insert(protocol);
    }
}

record! {
    /// What a stack is created with.
    ///
    /// Set `size` to `sizeof(sipral_stack_config_t)` and zero the rest before
    /// filling anything in. Five members have to be filled: the callback, the
    /// transport, the address this end is reachable at, the entropy, and the
    /// media seed, which must differ from the entropy. Nothing here can be
    /// guessed on the caller's behalf.
    #[derive(Clone, Copy)]
    pub struct SipralStackConfig {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// Where events go. Required: a stack with nowhere to report to is a
        /// stack whose failures are invisible.
        pub event_callback: SipralEventCallback,
        /// Handed back to the callback untouched. The library never reads it.
        pub event_user_data: *mut c_void,
        /// A [`SipralTransport`].
        pub transport: Number<SipralTransport>,
        /// The address the far end reaches this one at, as `host:port`, UTF-8 and
        /// not NUL-terminated.
        ///
        /// It goes in every `Via`, so it is the address a response has to come
        /// back to rather than whatever a wildcard socket was bound to. Nothing
        /// here opens a socket or resolves a name.
        pub bind_address: *const c_char,
        /// How many bytes of it.
        pub bind_address_len: usize,
        /// What to put in `User-Agent` on every request this stack originates —
        /// REGISTER and INVITE — or null for none.
        ///
        /// Not on responses, and not on a request sent inside a dialog: those are
        /// written a layer below this one, which has no opinion about product
        /// names. The field is optional on every method — §20 Table 3 marks it `o`
        /// throughout — so a message that goes out without it is still well formed.
        pub user_agent: *const c_char,
        /// How many bytes of it.
        pub user_agent_len: usize,
        /// Thirty-two bytes of entropy, from the platform's own generator.
        ///
        /// Every branch parameter, tag and `Call-ID` is derived from it, and
        /// §19.3 wants a tag unguessable — cryptographically random, not a
        /// counter or a clock. Two stacks must never be given the same bytes.
        ///
        /// Not the media keys: those come from `media_seed`, and the reason
        /// they are a separate draw is that a replay recording carries this
        /// one in clear.
        pub entropy: *const u8,
        /// How many bytes of it. Thirty-two.
        pub entropy_len: usize,
        /// T1 in milliseconds, or zero for the 500 ms of §17.1.1.1.
        ///
        /// In force on every transport: 64·T1 is how long a transaction has to
        /// finish, whether or not anything retransmits.
        pub timer_t1_ms: u64,
        /// T2 in milliseconds, or zero for four seconds.
        ///
        /// The cap on the doubling that starts at T1, and therefore only a figure
        /// on a transport that retransmits. Setting it on anything but UDP is
        /// `SIPRAL_STATUS_INVALID_ARGUMENT` rather than a value nothing reads.
        pub timer_t2_ms: u64,
        /// T4 in milliseconds, or zero for five seconds.
        ///
        /// How long a message lingers in the network, which is what timers I and K
        /// wait out. Zero on a transport that delivers for us, so it is refused
        /// there the same way T2 is.
        pub timer_t4_ms: u64,
        /// The codecs to offer, in the order to offer them: their names, separated
        /// by commas, as UTF-8 and not NUL-terminated. Null for everything this
        /// build contains, quality first.
        ///
        /// A4. The order is the whole of the negotiation's outcome — RFC 3264 §6.1
        /// has the peer's preference decide among what both ends list — and it is
        /// configured per site rather than fixed, because a carrier that bills by
        /// the minute wants the narrowband codec first and a company on its own
        /// network wants the wideband one.
        ///
        /// A name this build has no encoder for is `SIPRAL_STATUS_NOT_SUPPORTED`
        /// here, with the names it does have in the last error. It is never taken
        /// and ignored: a setting that is accepted and then quietly dropped is the
        /// failure neither end can see.
        pub codecs: *const c_char,
        /// How many bytes of it.
        pub codecs_len: usize,
        /// How long a frame is, in milliseconds, or zero for twenty.
        ///
        /// Twenty is what every peer expects and what every codec here cuts
        /// cleanly. Opus has a fixed set of frame durations and encodes nothing
        /// else, so an interval it has no size for is refused while Opus is one of
        /// the codecs offered.
        pub frame_ms: u32,
        /// Whether to offer RFC 4733 named events, as a `SipralToggle`. On by
        /// default: a phone that cannot send a digit cannot navigate a menu.
        pub offer_dtmf: Number<SipralToggle>,
        /// Whether to ask for RFC 5761 multiplexing, as a `SipralToggle`.
        ///
        /// Off by default. §5.1.1 only permits it where both ends asked, and the
        /// equipment this stack is deployed against does not; asking unasked costs
        /// a line in every offer and buys a port on the calls where nobody answers.
        pub offer_rtcp_mux: Number<SipralToggle>,
        /// Whether to stop sending during silence, as a `SipralToggle`.
        ///
        /// Off by default. It halves the bandwidth of a call in which one person is
        /// listening, and it costs the far end's own stall watchdog a reason to
        /// fire — this stack sends no comfort noise of its own to say the silence
        /// is deliberate, so a gap looks the same from there as a stream that died.
        pub silence_suppression: Number<SipralToggle>,
        /// Whether inbound audio that stops is reported, as a `SipralToggle`. On by
        /// default; this is B5.
        pub media_stall_watchdog: Number<SipralToggle>,
        /// How long inbound audio may stop before that is reported, in
        /// milliseconds, or zero for this build's own figure.
        ///
        /// Setting it with the watchdog switched off is
        /// `SIPRAL_STATUS_INVALID_ARGUMENT` rather than a value nothing reads.
        pub media_stall_ms: u64,
        /// What the wall clock read when the stack was created, as seconds since
        /// 1 January 1970, or zero.
        ///
        /// The one number a stack that reads no clock cannot work out: RFC 3550
        /// §6.4.1 has a sender report carry "the wall clock time when this report
        /// was sent", and a monotonic instant is not one. Zero means the reports
        /// take the wall clock `sipral_stack_stir` gives in `unix_seconds`, from
        /// the moment it is given, and count from the Unix epoch until then:
        /// the round trip the far end computes is a difference, not an
        /// absolute, but the correlation of this call's media with anything
        /// else's is not.
        pub media_clock_unix_seconds: u64,
        /// Thirty-two more bytes of entropy, for the media keys, and **not
        /// the same bytes as `entropy`**.
        ///
        /// Every SRTP master key this stack offers or answers with is derived
        /// from these and from nothing else. They are a second draw rather
        /// than a slice of the first because a replay recording writes
        /// `entropy` into the file in clear: one generator for both would put
        /// every key the stack will ever offer into every recording it makes.
        ///
        /// Handing the same bytes twice is refused rather than accepted
        /// quietly. This is the only place in the library that can see both.
        pub media_seed: *const u8,
        /// How many bytes of it. Thirty-two.
        pub media_seed_len: usize,
        /// What every call on this stack does about SRTP unless
        /// `sipral_call_config_t::srtp` says otherwise for it: a
        /// `SipralSrtp`, or zero for this build's own built-in default, which
        /// is `SIPRAL_SRTP_NOT_OFFERED` — nothing here offers encryption
        /// until it is asked to. Any other value is
        /// `SIPRAL_STATUS_INVALID_ARGUMENT`, and nothing is built.
        pub srtp: Number<SipralSrtp>,
        /// What every call on this stack does about ICE unless
        /// `sipral_call_config_t::ice` says otherwise for it: a `SipralIce`,
        /// or zero for this build's own built-in default, which is
        /// `SIPRAL_ICE_OFF` — nothing here offers ICE until it is asked to,
        /// for the reason `docs/06-nat.md` tabulates. Any other value is
        /// `SIPRAL_STATUS_INVALID_ARGUMENT`, and nothing is built.
        pub ice: Number<SipralIce>,
        /// What this stack does about a NAT in front of it: a `SipralNat`, or
        /// zero for this build's own built-in default, which is
        /// `SIPRAL_NAT_OFF`. `SIPRAL_NAT_STUN` asks `stun_server` where each
        /// socket appears from and writes the answer where a far end reads
        /// it — see `docs/06-nat.md`. Any other value is
        /// `SIPRAL_STATUS_INVALID_ARGUMENT`, and nothing is built.
        pub nat: Number<SipralNat>,
        /// The STUN server `SIPRAL_NAT_STUN` asks, as `host:port`: an
        /// address, not a name, since resolving one is the application's.
        /// Required with `SIPRAL_NAT_STUN` and refused without it, since a
        /// server nothing asks is a setting nothing reads. Copied; the
        /// caller's buffer is its own again when this returns.
        pub stun_server: *const c_char,
        /// How many bytes of it.
        pub stun_server_len: usize,
        /// Whether G.729's Annex B — silence compression: SID frames and
        /// nothing in a pause, and the comfort noise both ends make from
        /// them — is allowed on this stack's calls, as a `SipralToggle`. On
        /// by default, which is what `G729` means with no parameter (RFC
        /// 4856 §2.1.9): an offer says `annexb=yes`, and an answer says
        /// `yes` only where the offer allowed it. Off, both say `annexb=no`,
        /// which RFC 3551 §4.5.6 makes the far end's cue to send no SID
        /// frames, and this end sends none either. A per-call codec order
        /// keeps the stack's setting. Nothing changes for a call that does
        /// not run G.729, so the setting is taken whatever `codecs` names:
        /// a call's own order may name G.729 when the stack's does not.
        pub g729_annex_b: Number<SipralToggle>,
        /// A TURN server (RFC 8656) to allocate a relay on for every media
        /// socket `sipral_stack_nat_map` names, as `host:port`: an address,
        /// not a name. The relay becomes the relayed ICE candidate of the call
        /// placed, rung or answered on that socket — the path of last resort,
        /// used only when no cheaper pair answers — and goes back to the
        /// server when the call ends. See `docs/06-nat.md`.
        ///
        /// Optional, and only with `SIPRAL_NAT_STUN`, since it rides on the
        /// same media-socket calls; it may be the same address as
        /// `stun_server`. `turn_username` and `turn_password` are then
        /// required: a TURN server that hands out relays to anyone is one
        /// somebody else is already using. `SIPRAL_STATUS_NOT_SUPPORTED` in
        /// a build without `SIPRAL_FEATURE_ICE`, which is the only thing that
        /// can use a relay. Copied; the caller's buffer is its own again when
        /// this returns.
        pub turn_server: *const c_char,
        /// How many bytes of it.
        pub turn_server_len: usize,
        /// The user name of the long-term credential the TURN server knows
        /// this end by (RFC 8489 §9.2).
        pub turn_username: *const c_char,
        /// How many bytes of it.
        pub turn_username_len: usize,
        /// Its password. Copied into memory that is overwritten when the
        /// stack is destroyed, and never written to a log, an event or an
        /// error text.
        pub turn_password: *const c_char,
        /// How many bytes of it.
        pub turn_password_len: usize,
        /// Whether a REFER outside any dialog — somebody asking this end to
        /// place a call it is not in, which is what click-to-dial from a
        /// switchboard or a CRM sends (RFC 3515 §4.1) — reaches the
        /// application, as a `SipralToggle`. **Off by default**, and then
        /// every one is refused 403 before anything reads it: a peer that can
        /// make a phone dial is a peer that can make it dial a premium-rate
        /// number, and this stack authenticates no peer to tell the two
        /// apart. On, each one is screened as an INVITE is and then raised as
        /// `SIPRAL_EVENT_KIND_REFERRAL`, and the application takes it with
        /// `sipral_call_accept_transfer` or refuses it with
        /// `sipral_call_reject_transfer`, one request at a time.
        pub referrals: Number<SipralToggle>,
        /// Whether an account behind a NAT keeps its registrar's UDP flow
        /// open, as a `SipralToggle`. **On by default.** An account is
        /// behind a NAT when `SIPRAL_NAT_STUN`'s answer about the signalling
        /// socket named an address that is not the socket's own; each such
        /// account on a UDP transport then sends a double CRLF, alone in a
        /// datagram, to its registrar every `registrar_keepalive_ms`, while
        /// its registration holds a binding or is getting one. A NAT that
        /// filters by address and port (RFC 4787 §5) lets the registrar's
        /// INVITE in only while it remembers this end sending to it, and the
        /// STUN refresh goes to the STUN server; without this, a call that
        /// arrives minutes after the REGISTER is dropped at the NAT.
        /// Registrars ignore the datagram (RFC 3261 §7.5). Nothing is sent
        /// while the stack is suspended (`sipral_stack_suspending`), for a
        /// stack with `SIPRAL_NAT_OFF`, or for an account STUN found on its
        /// own address; `docs/06-nat.md` has the reasons.
        pub registrar_keepalive: Number<SipralToggle>,
        /// How often, in milliseconds, or zero for twenty-five seconds (RFC
        /// 5626 §4.4.2's interval for UDP). Each interval is drawn between
        /// 80% and 100% of it. From 1 000 to 120 000 — past two minutes a
        /// NAT that keeps to RFC 4787 REQ-5 may already have let the flow go
        /// — and anything else is `SIPRAL_STATUS_INVALID_ARGUMENT`, as is a
        /// figure with `registrar_keepalive` off, a value nothing would read.
        pub registrar_keepalive_ms: u64,
        /// How every media socket reaches `turn_server`, as a
        /// `SipralTransport`: `SIPRAL_TRANSPORT_UDP`, or zero for it;
        /// `SIPRAL_TRANSPORT_TCP` for the network that blocks UDP outright;
        /// `SIPRAL_TRANSPORT_TLS` for the one that lets one port out — 5349
        /// is TURN's (RFC 8656 §4.1) — or for an application that wants the
        /// server's certificate checked. The relay speaks UDP to the peer
        /// whichever it is (§3.1). Over TCP or TLS the application opens a
        /// connection per media socket when `SIPRAL_EVENT_KIND_TURN_STREAM`
        /// asks, with the platform's own TLS as it does for SIP. Anything
        /// else, or a value other than zero with no `turn_server`, is
        /// `SIPRAL_STATUS_INVALID_ARGUMENT`.
        pub turn_transport: Number<SipralTransport>,
        /// Who pumps this stack's audio: a `SipralAudio`. Zero, and
        /// `SIPRAL_AUDIO_APPLICATION`, is the application, through
        /// `sipral_media_capture` and `sipral_media_playback`, as every
        /// stack was before this member existed. `SIPRAL_AUDIO_DEVICE` has
        /// the library open the platform's devices and pump every managed
        /// call itself — see the `sipral_audio_*` entry points — and needs
        /// `audio_transmit_callback`. `SIPRAL_STATUS_NOT_SUPPORTED` on a
        /// platform this build has no backend for, which
        /// `SIPRAL_FEATURE_AUDIO_DEVICE` says first.
        pub audio: Number<SipralAudio>,
        /// When the devices are opened, in device mode: a
        /// `SipralAudioActivation`, or zero for
        /// `SIPRAL_AUDIO_ACTIVATION_AUTOMATIC`.
        pub audio_activation: Number<SipralAudioActivation>,
        /// Where the packets the engine encodes go, in device mode: called
        /// on the engine's thread with one `sipral_audio_transmit_t` per
        /// packet, to be sent from the call's media socket. Required with
        /// `SIPRAL_AUDIO_DEVICE`, ignored otherwise.
        pub audio_transmit_callback: SipralAudioTransmitCallback,
        /// Handed back to `audio_transmit_callback` unread.
        pub audio_transmit_user_data: *mut c_void,
        /// How long a platform call about the devices may block before the
        /// engine reports it as stuck, in milliseconds; zero for the
        /// engine's own default of three seconds. A driver that has stopped
        /// answering is answered `SIPRAL_STATUS_DEVICE_TIMED_OUT`, on a
        /// thread the engine walks away from, rather than waited for.
        pub audio_probe_ms: u64,
        /// The rate the devices are asked to run at, in device mode; zero
        /// for 48000. Every call is resampled between its own rate and
        /// this one, and a platform that answers with another rate is
        /// taken at its word.
        pub audio_device_rate_hz: u32,
        /// The most calls this stack holds at once, in either direction, or
        /// zero for 128: a softphone's ceiling, well past what one person
        /// can hold and well short of what a flood would make it keep. A
        /// call counts from its INVITE on — one that arrives from the
        /// moment it is let in, one placed here from the moment it is sent
        /// — until it ends or is refused.
        ///
        /// An INVITE that arrives past it is answered `503 Service
        /// Unavailable` before it rings, with no `Retry-After`: RFC 3261
        /// §21.5.4 has the client try another server either way, and a
        /// `Retry-After` would also have a proxy send this stack nothing at
        /// all for that long, every call refused for one too many. A
        /// call placed past it is `SIPRAL_STATUS_LIMIT_REACHED` and nothing
        /// goes out. A media server built on this library raises it to what
        /// its machine can carry; `docs/19-numbers.md` has what one costs.
        pub max_dialogs: u32,
        /// The most requests from other ends this stack works on at once —
        /// its server transactions, RFC 3261 §17.2 — or zero for 256. Past
        /// it a request that would start another is answered `503` at once,
        /// statelessly and with no `Retry-After`, and every one already
        /// under way is still answered. A request inside a call is held to
        /// that call's own share instead, and a BYE never is.
        pub max_server_transactions: u32,
        /// D1: how many decisions each call's diagnostic record keeps, or
        /// zero for 64. Past it the oldest go and the record counts them.
        pub diagnostic_decisions: u32,
        /// D1: how many calls have a diagnostic record at once, or zero for
        /// 32; the endpoint's own record is kept besides them. Past it the
        /// record written longest ago goes, and the stack counts it. Neither
        /// of the two refuses anything: they bound what the records cost, a
        /// quarter of a megabyte at the defaults. Every decision written
        /// looks through the records for its call, so this one is best kept
        /// in the hundreds even on a stack holding thousands of calls: the
        /// calls a support case is about are the ones written most recently.
        pub diagnostic_records: u32,
        /// When a call listens for keypad digits in the far end's audio, as a
        /// [`SipralDtmfDetection`]: zero
        /// on exactly the calls that negotiated no telephone event, which is
        /// when such a far end has no other way to send one.
        /// `sipral_call_dtmf_detection` changes it for one call.
        ///
        /// Here rather than after `rtp_port_max`, where it was appended: six
        /// four-byte members in a row keep the struct free of padding at its
        /// end on a 64-bit target and on 32-bit ARM alike.
        pub dtmf_detection: Number<SipralDtmfDetection>,
        /// The STUN servers to turn to, in this order, when `stun_server`
        /// fails: `host:port` addresses separated by commas, not names.
        /// Optional, and only beside a `stun_server`. A server fails when it
        /// does not answer in five and a half seconds, or answers without an
        /// address; every socket asking it moves to the next one at once,
        /// and the one that failed is passed over for thirty seconds, then
        /// twice as long each time it fails again, up to ten minutes. Only a
        /// signalling socket's refresh goes back to a better server once its
        /// time is up, so a call waiting for its media socket's address is
        /// never spent on finding out. `SIPRAL_EVENT_KIND_STUN_SERVER` says
        /// when the server in use moves, and when every one has failed.
        /// Copied; the caller's buffer is its own again when this returns.
        pub stun_fallbacks: *const c_char,
        /// How many bytes of it.
        pub stun_fallbacks_len: usize,
        /// The lowest port of the range this stack hands RTP ports out of
        /// (`sipral_stack_rtp_port_reserve`), or zero with `rtp_port_max`
        /// for no range: the application picks every media port itself.
        ///
        /// RTP takes an even port and its RTCP the odd one above it (RFC 3550
        /// §11), so an odd `rtp_port_min` starts at the port above it and an
        /// even `rtp_port_max` is never handed out. A range that holds no
        /// such pair, one given upside down, or one bound given without the
        /// other is `SIPRAL_STATUS_INVALID_ARGUMENT`.
        pub rtp_port_min: u32,
        /// The highest port of that range, or zero with `rtp_port_min`.
        pub rtp_port_max: u32,
        /// The SRTP suites every call on this stack offers and accepts,
        /// unless its account names its own
        /// (`sipral_account_config_t::srtp_suites`): the names RFC 4568
        /// section 6.2 and RFC 7714 section 14.2 give them, separated by
        /// commas, most preferred first. Null for this build's own order
        /// (ABI 0.34).
        ///
        /// An SDES offer names these, in this order, and an answer takes
        /// the offerer's first that is among them; a DTLS-SRTP handshake
        /// offers the ones with a protection profile. Every `a=crypto` line
        /// is in the INVITE, so past two or three suites an offer over UDP
        /// needs a stream (RFC 3261 section 18.1.1). A name this library
        /// does not run, or one named twice, is
        /// `SIPRAL_STATUS_INVALID_ARGUMENT`.
        pub srtp_suites: *const c_char,
        /// How many bytes of it.
        pub srtp_suites_len: usize,
        /// The MTU of the path toward the server, in bytes, when the
        /// deployment knows it; zero for unknown (ABI 0.34). RFC 3261
        /// section 18.1.1 moves a request to a stream when it comes within
        /// 200 bytes of the MTU, and with the MTU unknown past 1300 bytes: a
        /// path known to carry more lets a larger request stay on UDP. Under
        /// 576 is `SIPRAL_STATUS_INVALID_ARGUMENT` — an IPv4 host must take
        /// that much (RFC 791).
        pub path_mtu: u32,
        /// The largest request to send over UDP anyway, once no stream to
        /// its server can be had, in bytes; zero for never (ABI 0.34).
        ///
        /// **A deliberate deviation from RFC 3261 section 18.1.1**, for a
        /// server that takes SIP over UDP alone: such a PBX answers nothing
        /// to a request it cannot receive over a stream, and takes a
        /// 1,444-byte INVITE over UDP from every other phone on its network.
        /// A request past the section's line asks for a stream as always
        /// (`SIPRAL_EVENT_KIND_TRANSPORT_WANTED`); once the application says
        /// none is coming (`sipral_stack_transport_failed` on the number it
        /// was going to bind) or the wait runs out, what was waiting goes
        /// over UDP up to this size, and each such request is written to the
        /// call's diagnostic record as `transport.kept.datagram` with its
        /// size and this limit. A stream bound later is preferred again. A
        /// request past this size ends as it would without it. At most
        /// 65 507, what one UDP datagram carries over IPv4; a figure not past
        /// the section's own line changes nothing.
        pub datagram_without_stream_bytes: u32,
        /// A salt the application keeps for the installation, keying the
        /// pseudonyms this stack's log and state text write for users,
        /// numbers and addresses, so that the same value has the same
        /// pseudonym in every run and two runs' traces compare line by line
        /// (ABI 0.34). At least 16 bytes, drawn once from the platform's
        /// generator; null for pseudonyms keyed from `media_seed`, which are
        /// fresh every run. It is a secret like a key: whoever holds it can
        /// test a guessed address against a pseudonym. Copied.
        pub pseudonym_salt: *const u8,
        /// How many bytes of it.
        pub pseudonym_salt_len: usize,
        /// A `SipralToggle`: whether the log's trace writes SIP messages
        /// whole, with the peer they went to, instead of pseudonymised; off
        /// by default (ABI 0.34). For a diagnosis only: every user, display
        /// name, number and address is then written as it went on the wire.
        /// What is never written, in either mode, is a credential or a key:
        /// every `Authorization` and `Proxy-Authorization` value, every
        /// `a=crypto` `inline:` key, every `k=` key and every `a=key-mgmt`
        /// payload is taken out first. `sipral_stack_diagnostic_trace`
        /// turns it on and off while the stack runs.
        pub diagnostic_trace: Number<SipralToggle>,
        /// Zero.
        pub reserved: u32,
    }
}

// Safety: the trait's contract. Plain data, no invariant between the members,
// and all-zero is a valid value of each: a null function pointer is `None`, a
// null user pointer is a user pointer the library never reads anyway, and a
// zero length beside a null pointer is how a caller says it has nothing to
// give. A zeroed struct is refused, but it is refused by reading it, not by
// being undefined.
unsafe impl Versioned for SipralStackConfig {
    const NAME: &'static str = "sipral_stack_config";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralStackConfig, rtp_port_max);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// What one call to [`sipral_stack_poll`] did.
    ///
    /// Set `size` to `sizeof(sipral_poll_result_t)` before the call.
    #[derive(Clone, Copy)]
    pub struct SipralPollResult {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// Events handed to the callback during this poll.
        pub events_delivered: usize,
        /// Events the stack raised that this ABI has no word for yet.
        ///
        /// Counted rather than delivered: an event carrying nothing a binding can
        /// act on is noise, and a number that is not zero is the honest measure of
        /// how far this vocabulary is behind the stack's.
        pub events_unclaimed: usize,
        /// Bytes the stack produced and this build had nowhere to send.
        ///
        /// Zero since `sipral_stack_poll_transmit` gave them somewhere to go: what the stack
        /// writes waits in it until `sipral_stack_poll_transmit` takes it, and a
        /// poll no longer empties the queue on its way past. The member stays
        /// because a released one always does, and because a build that has to drop
        /// a message again would have somewhere to say so.
        pub transmits_discarded: usize,
        /// Whether there is a deadline at all. Zero means nothing is scheduled and
        /// the next poll can wait for input.
        pub has_deadline: u32,
        /// How long from `now_ms` until the stack has something to do, when
        /// `has_deadline` says there is one. Zero means it is already due.
        pub next_poll_in_ms: u64,
    }
}

// Safety: integers, and zero is a valid value of each.
unsafe impl Versioned for SipralPollResult {
    const NAME: &'static str = "sipral_poll_result";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralPollResult, next_poll_in_ms);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// What a stack is actually running with.
    ///
    /// A configuration call that answers `SIPRAL_STATUS_OK` has applied what it was
    /// given, and this is where the caller reads back what that came to. It matters
    /// because a zero in the config means "the default": a caller that left the
    /// timers alone has no other way to learn which figures it is retransmitting
    /// on, and one that set them has no other way to be sure.
    ///
    /// Set `size` to `sizeof(sipral_stack_settings_t)` before the call.
    #[derive(Clone, Copy)]
    pub struct SipralStackSettings {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// The [`SipralTransport`] this stack speaks.
        pub transport: Number<SipralTransport>,
        /// Whether this stack retransmits anything itself.
        ///
        /// Zero on a transport that delivers for us, which is every one but UDP.
        /// The two timers that only exist to pace a retransmission read as their
        /// defaults there, and mean nothing.
        pub retransmits: u32,
        /// T1 in milliseconds, with the default filled in.
        pub timer_t1_ms: u64,
        /// T2 in milliseconds, with the default filled in.
        pub timer_t2_ms: u64,
        /// T4 in milliseconds, with the default filled in.
        pub timer_t4_ms: u64,
        /// How many codecs this stack offers. `sipral_stack_codec_order` says
        /// which, and in what order.
        pub codec_count: usize,
        /// How long a frame is, with the default filled in.
        pub frame_ms: u32,
        /// Whether named events are offered, as a `SipralToggle`. Never the
        /// default value: this says what the setting came to, not what was passed.
        pub offer_dtmf: Number<SipralToggle>,
        /// Whether RTCP multiplexing is asked for, as a `SipralToggle`.
        pub offer_rtcp_mux: Number<SipralToggle>,
        /// Whether sending stops during silence, as a `SipralToggle`.
        pub silence_suppression: Number<SipralToggle>,
        /// How long inbound audio may stop before it is reported, with the default
        /// filled in. Zero when the watchdog is off, which is the one case where
        /// there is no figure to give.
        pub media_stall_ms: u64,
        /// Whether G.729's Annex B is allowed, as a `SipralToggle`, with the
        /// default filled in.
        pub g729_annex_b: Number<SipralToggle>,
        /// Whether a REFER outside any dialog reaches the application, as a
        /// `SipralToggle`, with the default — off — filled in.
        pub referrals: Number<SipralToggle>,
        /// How often an account behind a NAT sends to its registrar, in
        /// milliseconds, with the default filled in. Zero when
        /// `registrar_keepalive` was turned off, which is the one case where
        /// there is no figure to give.
        pub registrar_keepalive_ms: u64,
        /// The most calls the stack holds at once, with the default filled
        /// in.
        pub max_dialogs: u32,
        /// The most server transactions it works on at once, with the
        /// default filled in.
        pub max_server_transactions: u32,
        /// How many decisions a diagnostic record keeps, with the default
        /// filled in.
        pub diagnostic_decisions: u32,
        /// How many diagnostic records the stack keeps, with the default
        /// filled in.
        pub diagnostic_records: u32,
        /// The RTP port range, as given; both zero for none.
        pub rtp_port_min: u32,
        /// See `rtp_port_min`.
        pub rtp_port_max: u32,
        /// The path MTU as given, zero for unknown (ABI 0.34).
        pub path_mtu: u32,
        /// The largest request sent over UDP once no stream is coming, as
        /// given; zero for never (ABI 0.34).
        pub datagram_without_stream_bytes: u32,
    }
}

// Safety: integers, and zero is a valid value of each.
unsafe impl Versioned for SipralStackSettings {
    const NAME: &'static str = "sipral_stack_settings";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralStackSettings, rtp_port_max);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// How many deliveries [`Outbox::waiting`] holds before the rest of a poll's
/// own events are dropped rather than queued behind them.
///
/// A callback that is slow, or blocked, does not stop other threads from
/// posting behind it — signalling on this stack still has to answer every
/// call it is asked, and posting must never be one that waits — so without a
/// ceiling the queue is exactly as large as a stuck callback and a determined
/// poster can make it. Four thousand and ninety-six is a call's worth of
/// events six hundred times over: nothing in this crate's own test suite ever
/// raises more than a handful in one poll, a media event or a call event is a
/// few hundred bytes at most, and a stack pinned open by a callback that
/// never returns has a worse problem than which of its events gets to keep
/// growing a queue for it.
const OUTBOX_CEILING: usize = 4096;

/// How many RTCP goodbyes [`StackState::farewells`] holds before the oldest
/// is dropped to make room for one that just arrived.
///
/// Nothing here reads this queue unless the application calls
/// [`crate::media::sipral_stack_poll_farewell`], so one that never does — a
/// binding built against a header from before that entry point existed,
/// among others — would otherwise keep every ended call's goodbye for as
/// long as the stack lives. A stale goodbye is worth less than a recent one:
/// RFC 3550 §6.6 has it tell a far end still holding the dialog open that
/// this participant is gone, and a far end waiting on one that never
/// arrives times its own dialog out regardless of how long this queue would
/// have kept it. Two hundred fifty-six is a call ending every second for
/// over four minutes before the application has looked once, which is a
/// caller that has stopped polling rather than one running a few seconds
/// behind.
pub(crate) const FAREWELL_CEILING: usize = 256;

/// One stack.
///
/// Its lock is taken without waiting, which is what makes a call from a second
/// thread an error code instead of a wait. The outbox beside it is how what a
/// poll raised reaches the callback once that lock has been let go.
struct StackEntry {
    state: Mutex<StackState>,
    outbox: Mutex<Outbox>,
    /// Where the engine's log lines wait for the thread that lets the stack
    /// go (`crate::log`). The same log the state and the engine hold.
    log: sipral::Log,
    /// What [`crate::log::sipral_stack_state_text`] reads when the stack is busy,
    /// and the last refusals it reports, behind a lock of its own so that
    /// reading them never waits on signalling.
    watch: Mutex<crate::log::Watch>,
    /// The audio engine, reachable without the state's lock: a level meter
    /// polled from a window must not answer `SIPRAL_STATUS_BUSY` because
    /// signalling is busy.
    audio: Option<crate::audio::Shared>,
}

impl StackEntry {
    /// Queue what one poll raised behind whatever is still waiting, up to
    /// [`OUTBOX_CEILING`], and say whether the poll that raised it is the one
    /// to deliver and how many of its own events had no room.
    ///
    /// Called with the stack still held, so two polls queue in the order they
    /// ran. One poll delivers at a time: a poll that arrives while another is
    /// delivering — from inside that one's callback, or on a thread of its
    /// own — leaves its events to it, which is what keeps them in order and
    /// the callback on one thread. Whatever does not fit is dropped rather
    /// than waited for room, which is what keeps this from ever blocking the
    /// thread that is signalling.
    fn post(&self, raised: Vec<Delivery>) -> (bool, usize) {
        let mut outbox = self.outbox();
        let room = OUTBOX_CEILING.saturating_sub(outbox.waiting.len());
        let dropped = raised.len().saturating_sub(room);
        outbox.waiting.extend(raised.into_iter().take(room));
        if outbox.delivering {
            return (false, dropped);
        }
        outbox.delivering = true;
        (true, dropped)
    }

    /// Hand what was waiting to the callback, one event at a time and with
    /// nothing held while it runs, and say how many that was and whether
    /// anything is still waiting behind it.
    ///
    /// Only what was already there when this pass began. A pass that kept
    /// pulling in whatever arrived while it ran could be held open for as
    /// long as other threads kept posting, which is what let one slow
    /// callback grow the queue without bound; anything posted during this
    /// pass is still in [`Outbox::waiting`] when it returns, and clearing
    /// `delivering` here — not part way through, only once — is what lets the
    /// very next poll on this stack, even one that raised nothing of its own,
    /// notice it is not being delivered and take it instead.
    fn deliver(&self, speaker: Speaker) -> (usize, bool) {
        let mut batch = {
            let mut outbox = self.outbox();
            std::mem::take(&mut outbox.waiting)
        };
        let mut delivered = 0_usize;
        while let Some(delivery) = batch.pop_front() {
            unsafe { (speaker.callback)(ptr::from_ref(&delivery.event), speaker.user_data) };
            delivered = delivered.saturating_add(1);
        }
        let mut outbox = self.outbox();
        outbox.delivering = false;
        // read under the same lock that stops the delivery: a poll that posts
        // after this finds nobody delivering and delivers its own, and one that
        // posted before it is what this pass reports as left behind
        (delivered, !outbox.waiting.is_empty())
    }

    fn watch(&self) -> MutexGuard<'_, crate::log::Watch> {
        // a queue of sentences and a copy of a text, whole between statements
        self.watch.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What every entry point does once it has let the stack go: remember a
    /// refusal for the state snapshot and log it, then hand the log's queue
    /// to its callback — with nothing held, which is the whole point of
    /// doing it here.
    fn let_go<R>(&self, done: &Result<R, Fail>, at_ms: u64, now: Instant) {
        if let Err(failure) = done {
            self.watch().refused(at_ms, failure);
            self.log.line(sipral::LogLevel::Debug, "api", now, || {
                format!("refused, {:?}: {}", failure.status, failure.message())
            });
        }
        let _ = self.log.flush();
    }

    fn outbox(&self) -> MutexGuard<'_, Outbox> {
        // a panic was caught while this was held, and what is behind it is a
        // queue and a flag, whole between statements
        self.outbox.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What polls have taken out of one stack and not yet delivered.
#[derive(Default)]
struct Outbox {
    waiting: VecDeque<Delivery>,
    /// Whether a poll is delivering them now.
    delivering: bool,
}

/// Where a stack's events go, copied out while the stack is held so that
/// they can be delivered once it is not.
#[derive(Clone, Copy)]
struct Speaker {
    callback: unsafe extern "C" fn(event: *const SipralEvent, user_data: *mut c_void),
    user_data: *mut c_void,
}

/// One event on its way to the callback, with what its pointers point into.
///
/// An event is translated while the stack is held and read after the lock is
/// gone, so nothing it points at may be borrowed from the stack or from a
/// local of the poll that raised it. Every pointer in it points into one of
/// the four owners beside it, and all four reach their bytes through a
/// reference count or a heap buffer, which stay where they are when a
/// delivery is moved into the outbox and out of it again.
struct Delivery {
    event: SipralEvent,
    /// Never read: the signalling event the message, the descriptions and the
    /// transfer target in `event` are borrowed from.
    _raised: Option<Arc<UaEvent>>,
    /// Never read: the sentence a media event points at.
    _reason: Option<String>,
    /// Never read: the record a statistics event points at.
    _record: Option<Arc<SipralStreamStats>>,
    /// Never read: the From, To and Call-ID a call event points at. Kept here
    /// rather than trusted to still be in `StackState::identities` by the
    /// time this is delivered, because a call event reporting the end of a
    /// call arrives after that map has already forgotten it.
    _identity: Option<Arc<CallIdentity>>,
}

impl Delivery {
    /// An event that points at nothing.
    // the event is moved into the delivery that owns it from here on
    #[allow(clippy::large_types_passed_by_value)]
    const fn bare(event: SipralEvent) -> Self {
        Self {
            event,
            _raised: None,
            _reason: None,
            _record: None,
            _identity: None,
        }
    }
}

// Safety: the pointers in `event` point into the four owners beside it and
// nowhere else, and each of those may move to another thread and be read from
// one: a `String` and a record of plain numbers can, and `UaEvent` and the
// `CallIdentity` behind the `Arc` are `Send` and `Sync` — asserted just below,
// so a member that ever stops being either fails the build here rather than
// making this a lie. A delivery is read by one thread, the one delivering it,
// and dropped by that thread.
unsafe impl Send for Delivery {}

const _: () = {
    const fn crosses_threads<T: Send + Sync>() {}
    crosses_threads::<UaEvent>();
    crosses_threads::<CallIdentity>();
};

/// Everything one stack is.
pub(crate) struct StackState {
    callback: unsafe extern "C" fn(event: *const SipralEvent, user_data: *mut c_void),
    user_data: *mut c_void,
    pub(crate) agent: UserAgent,
    /// Signalling joined to media. It drains the user agent, which is why
    /// nothing here polls that directly: an event taken from underneath the
    /// engine is an event the engine needed in order to know a call was
    /// answered, and the failure looks like a call that rings and is silent.
    pub(crate) engine: MediaEngine,
    /// The calls whose media this stack writes the descriptions for.
    ///
    /// Kept here rather than asked of the engine because it is this ABI's
    /// question, not the engine's: it decides which re-offers the application
    /// is asked to answer and which the stack has already answered for it.
    managed: Vec<CallHandle>,
    /// The tag every handle this stack mints carries.
    ///
    /// Held here rather than beside the stack's handle so that it is given back
    /// when the last share of this state goes, not when the stack is destroyed:
    /// a poll that destroyed its own stack from the callback is still delivering,
    /// and can still name a call, and a tag handed to a new stack before that
    /// poll returned would start the new stack below a handle the old one had
    /// yet to mint. Nothing reads it; holding it is the whole of its job.
    pub(crate) tag: StackTag,
    pub(crate) accounts: Names<AccountId>,
    pub(crate) calls: Names<CallHandle>,
    /// Every subscription this stack has handed a handle out for, including
    /// the ones that appeared by themselves: RFC 6665 §4.1.4 lets one
    /// SUBSCRIBE be answered by two notifiers, and the sibling is named here
    /// when its event is translated rather than when a call asked for it.
    pub(crate) subscriptions: Names<SubscriptionHandle>,
    /// Every MESSAGE this stack has sent and not yet reported the final
    /// answer for. Removed the moment `SIPRAL_EVENT_KIND_MESSAGE_SENT` is
    /// raised about it, the same as the layer below removes its own record.
    pub(crate) messages: Names<sipral_ua::MessageHandle>,
    /// Every call a push announced and no INVITE has answered yet.
    pub(crate) announcements: Names<AnnouncementId>,
    /// Every dialog this stack has asked the application to resolve a next
    /// hop for. Named rather than inserted when the event is translated, so
    /// that a dialog asking again on every target refresh keeps the handle it
    /// was first given, and forgotten with the call it belonged to. A dialog
    /// that is not a call's — a subscription's — stays named until the stack
    /// is destroyed, which is one row and is what the alternative, a lookup
    /// `sipral-ua` does not publish, would cost a public method to avoid.
    pub(crate) dialogs: Names<DialogId>,
    /// Who is on every call this stack still knows: the `From` and `To` of
    /// the request that opened it, fixed since. Read once, at that moment,
    /// because by the time a call has ended the layer below has already let
    /// it go and has nothing left to ask.
    pub(crate) identities: HashMap<CallHandle, Arc<CallIdentity>>,
    /// Every transport this stack has bound: the table `transport` on
    /// `sipral_account_config_t` and `sipral_call_config_t` is read against,
    /// and the one [`crate::transport::sipral_stack_transport_bind`] grows.
    pub(crate) transports: Transports,
    /// What that transport speaks, kept so the settings can be read back and so
    /// that binding it again cannot change it.
    pub(crate) speaks: SipralTransport,
    /// The address it advertises, which is what a datagram fed in without one
    /// is taken to have arrived on.
    pub(crate) local: SocketAddr,
    /// A message taken from the agent that did not fit the caller's buffer.
    ///
    /// It is offered again, before anything queued behind it. A message the
    /// stack has committed to is not this ABI's to drop, and the buffer it did
    /// not fit is a fact about the caller rather than about the message.
    pub(crate) held: Option<Transmit>,
    /// The figures the endpoint was built with, kept for the same reason: the
    /// endpoint holds them and does not hand them out.
    timers: TimerConfig,
    /// What the media settings came to, for the same reason again.
    media: MediaConfig,
    /// What goes in `User-Agent`, when the caller wanted one.
    pub(crate) user_agent: Option<Box<[u8]>>,
    /// The RTCP goodbyes `MediaEngine::poll_farewell` produced, gathered here
    /// during a poll — one call handle at a time, resolved through
    /// [`StackState::calls`] — because by the time an application asks for
    /// one the call it belonged to may already be forgotten there. Drained by
    /// [`crate::media::sipral_stack_poll_farewell`], and held to at most
    /// [`FAREWELL_CEILING`].
    pub(crate) farewells: VecDeque<(SipralHandle, SocketAddr, Vec<u8>, u32)>,
    /// How many events a poll raised and then had nowhere to queue, because
    /// [`OUTBOX_CEILING`] was already reached. Reported at the tail of
    /// `sipral_counters_t`.
    pub(crate) events_dropped: u64,
    /// How many farewells were dropped, oldest first, to keep
    /// [`StackState::farewells`] at [`FAREWELL_CEILING`]. Reported beside
    /// `events_dropped` in `sipral_counters_t`.
    pub(crate) farewells_dropped: u64,
    /// What `now_ms` of zero means. Read once, from the only clock this
    /// library ever looks at, and never compared with a later reading.
    origin: Instant,
    /// The last time the caller said it was, so that a clock going backwards
    /// is caught where it happens.
    polled_at_ms: u64,
    /// Whether the first poll has said the stack is running.
    started: bool,
    /// What it asks a STUN server, when its configuration said to. A build
    /// without the feature never asks, and has nothing to keep.
    #[cfg(feature = "stun")]
    pub(crate) nat: crate::nat::Nat,
    /// The built-in audio engine, on a stack created in device mode. Shared
    /// with the stack's entry so that the `sipral_audio_*` entry points
    /// reach it without this state's lock.
    pub(crate) audio: Option<crate::audio::Shared>,
    /// The caller's clock as the engine's pump reads it: what
    /// `StackState::advance` writes on every poll.
    clock: Arc<crate::audio::Clock>,
    /// Whether `media_clock_unix_seconds` gave the engine a wall clock. A
    /// stack created without one dates its sender reports by the first that
    /// `sipral_stack_stir` pairs with a `now_ms`.
    #[cfg(feature = "stir")]
    pub(crate) media_clock: bool,
    /// This stack's log, shared with the engine and the entry: lines are
    /// queued while the stack is held and delivered once it is not.
    pub(crate) log: sipral::Log,
    /// What the log's and the state snapshot's pseudonyms are keyed with
    /// (`crate::log::pseudonym_key`).
    pseudonyms: Box<[u8]>,
    /// Transports retired since the last poll, each raised by it as
    /// `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` before anything else it has.
    pub(crate) lost: Vec<crate::transport::Lost>,
    /// The local conferences made on this stack, by handle: whose changes
    /// each poll raises, and whose members no pair and no second conference
    /// may take.
    pub(crate) conferences: Vec<(SipralHandle, crate::local_conference::Shared)>,
}

// Safety: the user pointer is the caller's and is only ever handed back to
// the caller's own callback, on whichever thread the caller polls from. What
// it points at, and where it may be touched, is the caller's arrangement; the
// library reads none of it. Everything else in here is `Send` on its own.
unsafe impl Send for StackState {}

/// The caller's clock, as an instant the layers below can use: `now_ms`
/// milliseconds after `origin`.
pub(crate) fn instant_at(origin: Instant, now_ms: u64) -> Result<Instant, Fail> {
    origin
        .checked_add(Duration::from_millis(now_ms))
        .ok_or_else(|| {
            fail(
                SipralStatus::InvalidArgument,
                format!("now_ms is {now_ms}, which is further ahead than a clock reaches"),
            )
        })
}

impl StackState {
    /// The caller's clock, as an instant the layers below can use.
    pub(crate) fn instant(&self, now_ms: u64) -> Result<Instant, Fail> {
        instant_at(self.origin, now_ms)
    }

    /// The latest time this stack has been told, for work an entry point
    /// that takes no clock of its own sets off.
    pub(crate) fn last_instant(&self) -> Instant {
        instant_at(self.origin, self.polled_at_ms).unwrap_or(self.origin)
    }

    /// The latest `now_ms` this stack has been told.
    pub(crate) const fn polled_at_ms(&self) -> u64 {
        self.polled_at_ms
    }

    /// The key this stack's pseudonyms are made with.
    pub(crate) fn pseudonym_key(&self) -> &[u8] {
        &self.pseudonyms
    }

    /// What `now_ms` of zero means on this stack, for a media handle that
    /// has to read the same clock without reaching the stack again.
    pub(crate) const fn origin(&self) -> Instant {
        self.origin
    }

    /// The instant `now_ms` names, refusing one more than [`CLOCK_SLACK_MS`]
    /// behind this stack's last reading — without moving that reading.
    ///
    /// Moving it is [`Self::commit_clock`]'s job, and it is deliberately a
    /// second step: this only says whether `now_ms` is one the caller might
    /// reasonably have read from the stack's clock, and every other reason a
    /// call can fail is checked after this returns, so the clock must not
    /// move until the whole call has actually succeeded.
    fn checked_instant(&self, now_ms: u64) -> Result<Instant, Fail> {
        let floor = self.polled_at_ms.saturating_sub(CLOCK_SLACK_MS);
        if now_ms < floor {
            return Err(fail(
                SipralStatus::ClockBehind,
                format!(
                    "now_ms is {now_ms}, more than {CLOCK_SLACK_MS} ms behind this stack's last \
                     reading of {}; two threads reading one clock can disagree by a little, but \
                     not by that much",
                    self.polled_at_ms
                ),
            ));
        }
        self.instant(now_ms)
    }

    /// Record that this stack has been used at `now_ms`. Never moves
    /// backward: a reading accepted because it was within the slack leaves
    /// the high-water mark exactly where a later thread's reading already put
    /// it.
    fn commit_clock(&mut self, now_ms: u64) {
        self.polled_at_ms = self.polled_at_ms.max(now_ms);
    }

    /// Move the stack's clock to `now_ms` and commit it immediately, refusing
    /// one more than the slack behind.
    ///
    /// Only [`sipral_stack_poll`] calls this directly: everything it still
    /// does after reading the clock cannot fail, so validating and committing
    /// in one step costs it nothing. Every other signalling entry point goes
    /// through [`with_stack_at`], which commits only once the call it wraps
    /// has actually succeeded.
    pub(crate) fn advance(&mut self, now_ms: u64) -> Result<Instant, Fail> {
        let now = self.checked_instant(now_ms)?;
        self.commit_clock(now_ms);
        self.clock.polled(now_ms);
        Ok(now)
    }

    /// What a call on this stack opens its session with, unless
    /// `sipral_call_place` was asked to override the catalogue for it.
    ///
    /// Cloned rather than borrowed, because the one caller of this —
    /// `sipral_call_place`'s per-call SRTP override — pairs it with a
    /// catalogue of its own to build the `CallMedia` `MediaEngine::place_with`
    /// takes, and that bundle owns both halves.
    pub(crate) fn media_config(&self) -> MediaConfig {
        self.media.clone()
    }

    /// Say that this stack writes the descriptions for a call.
    pub(crate) fn manage(&mut self, call: CallHandle) {
        if !self.manages(call) {
            self.managed.push(call);
        }
    }

    /// Whether it does.
    pub(crate) fn manages(&self, call: CallHandle) -> bool {
        self.managed.contains(&call)
    }

    fn unmanage(&mut self, call: CallHandle) {
        self.managed.retain(|managed| *managed != call);
    }

    /// Say who is on a call, once, when it is placed or arrives.
    pub(crate) fn record_identity(&mut self, call: CallHandle, identity: CallIdentity) {
        self.identities.insert(call, Arc::new(identity));
    }

    /// The same, for an identity the layer below has already read and shared.
    fn record_shared_identity(&mut self, call: CallHandle, identity: Arc<CallIdentity>) {
        self.identities.insert(call, identity);
    }
}

pub(crate) fn handle_failed(refused: Refused) -> Fail {
    match refused {
        Refused::Gone => fail(refused.status(), "what the handle named is gone"),
        Refused::NotOurs => fail(refused.status(), "not a handle from this library"),
        Refused::OtherStack => fail(
            refused.status(),
            "the handle was minted by another stack, and a handle names something only on the \
             stack that minted it",
        ),
        Refused::WrongKind(found) => fail(
            refused.status(),
            format!(
                "this handle names {}, and that is not what was asked for here",
                found.noun()
            ),
        ),
    }
}

/// Do something to a stack, or say why not.
///
/// The one way in. Every entry point that names a stack goes through here, so
/// the two rules at the top of this module hold for all of them at once
/// rather than one function at a time.
pub(crate) fn with_stack<R>(
    stack: SipralHandle,
    act: impl FnOnce(&mut StackState) -> Result<R, Fail>,
) -> Result<R, Fail> {
    let entry = entry_of(stack)?;
    let (done, at_ms, now) = {
        let mut held = lock(&entry)?;
        let done = act(&mut held);
        (done, held.polled_at_ms, held.last_instant())
    };
    entry.let_go(&done, at_ms, now);
    done
}

/// The text [`crate::log::sipral_stack_state_text`] copies out: taken now when the
/// stack is free, the last one a poll kept when it is not. Never waits.
pub(crate) fn state_text(stack: SipralHandle) -> Result<String, Fail> {
    let entry = STACKS.get(stack).map_err(handle_failed)?;
    let held = match entry.state.try_lock() {
        Ok(state) => Some(state),
        Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
        Err(TryLockError::WouldBlock) => None,
    };
    let mut watch = entry.watch();
    Ok(crate::log::snapshot_of(stack, held.as_deref(), &mut watch))
}

/// The stack a handle names, for an entry point about to take its lock.
///
/// Refused to a thread that is inside a frame of a call on this stack: the
/// stack's work can need that call's session, which the same thread is
/// holding, and it would wait for itself with the stack's lock held and every
/// other thread shut out behind it.
fn entry_of(stack: SipralHandle) -> Result<Arc<StackEntry>, Fail> {
    if crate::media::inside_media_of(stack) {
        return Err(inside_media());
    }
    STACKS.get(stack).map_err(handle_failed)
}

/// The audio engine of the stack a handle names, without the stack's lock:
/// `None` on a stack in application mode.
pub(crate) fn audio_of(stack: SipralHandle) -> Result<Option<crate::audio::Shared>, Fail> {
    let entry = STACKS.get(stack).map_err(handle_failed)?;
    Ok(entry.audio.clone())
}

fn inside_media() -> Fail {
    fail(
        SipralStatus::Busy,
        "this thread is inside a frame of a call on this stack, and the stack's work may need that \
         call's media: call into the stack once the frame is done",
    )
}

/// The same, for something that happens at a time the caller names.
///
/// The clock is validated before `act` runs and committed only after it
/// succeeds: a call refused for a reason `act` finds — a stale handle, a bad
/// argument, the wrong state — leaves `now_ms` unrecorded, exactly as if it
/// had never been asked. Only a call this stack actually goes through moves
/// its clock.
pub(crate) fn with_stack_at<R>(
    stack: SipralHandle,
    now_ms: u64,
    act: impl FnOnce(&mut StackState, Instant) -> Result<R, Fail>,
) -> Result<R, Fail> {
    with_stack(stack, |state| {
        let now = state.checked_instant(now_ms)?;
        let done = act(state, now)?;
        state.commit_clock(now_ms);
        Ok(done)
    })
}

fn lock(entry: &Arc<StackEntry>) -> Result<MutexGuard<'_, StackState>, Fail> {
    match entry.state.try_lock() {
        Ok(state) => Ok(state),
        // a panic was caught while this stack was held; what is behind the
        // lock is whole between statements
        Err(TryLockError::Poisoned(poisoned)) => Ok(poisoned.into_inner()),
        Err(TryLockError::WouldBlock) => Err(fail(
            SipralStatus::Busy,
            "this stack is in use by a call on another thread",
        )),
    }
}

pub(crate) fn transport_of(value: u32) -> Result<SipralTransport, Fail> {
    match value {
        1 => Ok(SipralTransport::Udp),
        2 => Ok(SipralTransport::Tcp),
        3 => Ok(SipralTransport::Tls),
        4 => Ok(SipralTransport::Ws),
        5 => Ok(SipralTransport::Wss),
        0 => Err(fail(
            SipralStatus::InvalidArgument,
            "a stack has to be told which transport it is speaking",
        )),
        other => Err(fail(
            SipralStatus::InvalidArgument,
            format!("{other} is not a transport this library speaks"),
        )),
    }
}

/// A duration a caller gave in milliseconds, or the default it left at zero.
fn interval(millis: u64, default: Duration) -> Duration {
    if millis == 0 {
        default
    } else {
        Duration::from_millis(millis)
    }
}

/// The figures this stack runs its timers on, or which of them it was given
/// nothing to do with.
///
/// T2 caps the doubling that starts at T1, and T4 is how long the machines wait
/// out a message that may still be in flight. RFC 3261 §17 arms neither on a
/// transport that delivers for us: timers E and G are never set, and I and K
/// are zero. So a caller that sets one of those on a stream is configuring a
/// subsystem this stack does not have, and the only honest answers are to say
/// so here or to lie about it later. A T2 below T1 is the same failure one step
/// in: the cap is already reached at the first attempt, so T1 is the value that
/// disappears.
fn timers_for(
    protocol: TransportProtocol,
    config: &SipralStackConfig,
) -> Result<TimerConfig, Fail> {
    if protocol.is_reliable() {
        let idle = [
            ("timer_t2_ms", config.timer_t2_ms),
            ("timer_t4_ms", config.timer_t4_ms),
        ]
        .into_iter()
        .find(|(_, millis)| *millis != 0);
        if let Some((name, millis)) = idle {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!(
                    "{name} is {millis} and this stack speaks {}, which retransmits nothing, so \
                     the timer it paces is never armed",
                    protocol.as_str()
                ),
            ));
        }
    }

    let timers = TimerConfig {
        t1: interval(config.timer_t1_ms, TimerConfig::DEFAULT.t1),
        t2: interval(config.timer_t2_ms, TimerConfig::DEFAULT.t2),
        t4: interval(config.timer_t4_ms, TimerConfig::DEFAULT.t4),
    };
    if timers.t2 < timers.t1 {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "timer_t2_ms is {} and timer_t1_ms is {}, and T2 caps the interval T1 doubles \
                 from, so a T2 below it is a T1 nothing would ever use",
                timers.t2.as_millis(),
                timers.t1.as_millis()
            ),
        ));
    }
    Ok(timers)
}

/// The four ceilings a stack is created with, each zero for the endpoint's
/// own default. Every figure a `u32` can carry is taken: what one costs is a
/// question for the machine, not for this check.
fn limits_for(endpoint: &mut EndpointConfig, config: &SipralStackConfig) {
    let given = |value: u32, default: usize| {
        if value == 0 {
            default
        } else {
            usize::try_from(value).unwrap_or(usize::MAX)
        }
    };
    endpoint.max_dialogs = given(config.max_dialogs, endpoint.max_dialogs);
    endpoint.max_server_transactions = given(
        config.max_server_transactions,
        endpoint.max_server_transactions,
    );
    endpoint.diagnostics.max_decisions = given(
        config.diagnostic_decisions,
        endpoint.diagnostics.max_decisions,
    );
    endpoint.diagnostics.max_records =
        given(config.diagnostic_records, endpoint.diagnostics.max_records);
}

/// The smallest datagram an IPv4 host must take whole (RFC 791), and so the
/// smallest path MTU a deployment can say it has.
const MIN_PATH_MTU: u32 = 576;

/// The most one UDP datagram carries over IPv4: 65 535 less the IP and UDP
/// headers.
const MAX_UDP_PAYLOAD: u32 = 65_507;

/// What the stack is told of its path to the server, and of a server that
/// takes UDP alone: the two figures RFC 3261 section 18.1.1's line is drawn
/// from, each zero for the endpoint's own default.
fn datagrams_for(endpoint: &mut EndpointConfig, config: &SipralStackConfig) -> Result<(), Fail> {
    match config.path_mtu {
        0 => {}
        mtu if mtu < MIN_PATH_MTU => {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!(
                    "path_mtu is {mtu}, and no IPv4 path carries less than {MIN_PATH_MTU} bytes \
                     (RFC 791)"
                ),
            ));
        }
        mtu => endpoint.datagram_limit.path_mtu = Some(mtu),
    }
    match config.datagram_without_stream_bytes {
        0 => {}
        bytes if bytes > MAX_UDP_PAYLOAD => {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!(
                    "datagram_without_stream_bytes is {bytes}, and one UDP datagram carries at \
                     most {MAX_UDP_PAYLOAD}"
                ),
            ));
        }
        bytes => endpoint.datagram_limit.without_stream_bytes = Some(bytes),
    }
    Ok(())
}

/// A count as the caller reads one: saturating, since a figure past what a
/// `u32` holds was never one a caller could have given.
fn count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// What the user agent is told of the configuration's policies: whether it
/// takes a REFER from outside any dialog, and how often an account behind a
/// NAT sends to its registrar, or that it never does.
fn agent_policy(
    agent: &mut UserAgent,
    config: &SipralStackConfig,
    now: Instant,
) -> Result<(), Fail> {
    agent.allow_referrals(toggled(config.referrals, "referrals", false)?);
    agent
        .keep_registrar_flows_alive(registrar_keepalive(config)?, now)
        .map_err(|error| {
            fail(
                SipralStatus::InvalidArgument,
                format!("registrar_keepalive_ms: {error}"),
            )
        })
}

/// How often an account behind a NAT sends to its registrar, or `None` for
/// never. Shaped like the stall watchdog below: a figure given with the
/// keep-alive switched off is one nothing reads, and is said to be so.
fn registrar_keepalive(config: &SipralStackConfig) -> Result<Option<Duration>, Fail> {
    let keeping = toggled(config.registrar_keepalive, "registrar_keepalive", true)?;
    match (keeping, config.registrar_keepalive_ms) {
        (false, 0) => Ok(None),
        (false, millis) => Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "registrar_keepalive_ms is {millis} and registrar_keepalive is off, so the \
                 interval it sets is one nothing reads"
            ),
        )),
        (true, 0) => Ok(Some(sipral_ua::keepalive::DEFAULT_KEEPALIVE)),
        (true, millis) => Ok(Some(Duration::from_millis(millis))),
    }
}

/// How this stack's media behaves, or which of its settings it was given
/// nothing to do with.
///
/// The watchdog is the same shape as the timers above: an interval set while
/// the thing that reads it is switched off is a value nothing will ever look
/// at, and the only honest answers are to say so here or to lie about it later.
fn media_for(config: &SipralStackConfig) -> Result<MediaConfig, Fail> {
    let watching = toggled(config.media_stall_watchdog, "media_stall_watchdog", true)?;
    if !watching && config.media_stall_ms != 0 {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "media_stall_ms is {} and media_stall_watchdog is off, so the threshold it sets \
                 is one nothing reads",
                config.media_stall_ms
            ),
        ));
    }
    let default = MediaConfig::default();
    let stall_after = match (watching, config.media_stall_ms) {
        (false, _) => None,
        (true, 0) => default.stall_after,
        (true, millis) => Some(Duration::from_millis(millis)),
    };
    Ok(MediaConfig {
        stall_after,
        silence_suppression: toggled(config.silence_suppression, "silence_suppression", false)?,
        dtmf_detection: crate::inband::detection_of(config.dtmf_detection, "dtmf_detection")?,
        ..default
    })
}

/// The media engine a stack runs with: what it offers, how it behaves, and the
/// one wall-clock reading its reports need.
///
/// # Safety
///
/// Every pointer in `config` must be readable for the length beside it.
unsafe fn engine_for(
    config: &SipralStackConfig,
    media: MediaConfig,
    origin: Instant,
    media_seed: [u8; SEED_BYTES],
) -> Result<MediaEngine, Fail> {
    let named = unsafe { text(config.codecs, config.codecs_len, "codecs") }?;
    let suites = crate::security::srtp_suites(unsafe {
        text(config.srtp_suites, config.srtp_suites_len, "srtp_suites")
    }?)?;
    let mut catalog = catalog_of(
        named,
        config.frame_ms,
        toggled(config.offer_dtmf, "offer_dtmf", true)?,
        toggled(config.offer_rtcp_mux, "offer_rtcp_mux", false)?,
        srtp_policy(config.srtp, "srtp")?,
        ice_policy(config.ice, "ice")?,
        toggled(config.g729_annex_b, "g729_annex_b", true)?,
    )?;
    if let Some(suites) = suites {
        catalog = catalog
            .with_srtp_suites(&suites)
            .map_err(|error| media_failed(&error))?;
    }
    let clock = WallClock::from_unix(origin, config.media_clock_unix_seconds, 0);
    Ok(MediaEngine::new(catalog, media, clock, media_seed))
}

entry! {
    /// Create a stack, and write its handle to `out_stack`.
    ///
    /// The handle is written only if this returns `SIPRAL_STATUS_OK`. A stack
    /// that is created must be destroyed with [`sipral_stack_destroy`].
    ///
    /// A process holds 256 stacks at once. The next is
    /// `SIPRAL_STATUS_EXHAUSTED` until one of them is destroyed and no poll is
    /// still running on it.
    ///
    /// # Safety
    ///
    /// `config` must point at a `sipral_stack_config_t` whose `size` member
    /// says how long it is, with every pointer in it readable for the length
    /// beside it, and `out_stack` at one `sipral_handle_t`.
    fn sipral_stack_create(config: *const SipralStackConfig, out_stack: *mut SipralHandle) {
        if out_stack.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_stack is null"));
        }
        let handle = unsafe { create_on(&TAGS, config) }?;
        unsafe { out_stack.write(handle) };
        Ok(())
    }
}

/// Everything [`sipral_stack_create`] does but write the handle, with the tag
/// drawn from `tags`.
///
/// The tags are passed in rather than reached for so that a test can hold a set
/// of its own. Which tag a stack gets, and whether any is left, are otherwise
/// decided by every other test creating stacks in the same process at the same
/// moment.
///
/// # Safety
///
/// `config` as [`sipral_stack_create`] takes it.
#[expect(
    clippy::too_many_lines,
    reason = "one configuration read in one place, in the order its members are declared"
)]
pub(crate) unsafe fn create_on(
    tags: &'static StackTags,
    config: *const SipralStackConfig,
) -> Result<SipralHandle, Fail> {
    let config = unsafe { read_versioned(config) }?;
    let Some(callback) = config.event_callback else {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "a stack needs an event callback",
        ));
    };
    let speaks = transport_of(config.transport)?;
    let bound =
        unsafe { required_text(config.bind_address, config.bind_address_len, "bind_address") }?;
    let Ok(local) = bound.parse::<SocketAddr>() else {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!("bind_address is {bound:?}, which is not an address and a port"),
        ));
    };
    let named = unsafe { text(config.user_agent, config.user_agent_len, "user_agent") }?;
    let (seed, media_seed) = unsafe { seeds_of(&config) }?;

    let timers = timers_for(speaks.protocol(), &config)?;
    let media = media_for(&config)?;
    let rtp_ports = rtp_ports_of(&config)?;
    let stun_server = unsafe { crate::nat::configured(&config) }?;
    // borrowed from the caller until `Nat::start` below copies it into the
    // one place it is kept
    let turn_server = unsafe { crate::nat::turn_configured(&config) }?;
    let mut endpoint = EndpointConfig::default();
    endpoint.timers = timers;
    limits_for(&mut endpoint, &config);
    datagrams_for(&mut endpoint, &config)?;
    let salt = unsafe {
        bytes(
            config.pseudonym_salt,
            config.pseudonym_salt_len,
            "pseudonym_salt",
        )
    }?;
    let diagnostic = toggled(config.diagnostic_trace, "diagnostic_trace", false)?;

    let origin = Instant::now();
    let clock = crate::audio::Clock::new(origin);
    let audio = unsafe { crate::audio::configured(&config, &clock) }?;
    let mut engine = unsafe { engine_for(&config, media.clone(), origin, media_seed) }?;
    engine.set_rtp_ports(rtp_ports);
    let pseudonyms = match salt {
        Some(salt) => sipral::pseudonym_key(salt).map_err(|error| {
            fail(
                SipralStatus::InvalidArgument,
                format!("pseudonym_salt: {error}"),
            )
        })?,
        None => crate::log::pseudonym_key(&media_seed),
    };
    let log = crate::log::log_for(&pseudonyms);
    log.set_diagnostic(diagnostic);
    engine.set_log(log.clone());
    let mut agent = UserAgent::new(endpoint, seed)
        .map_err(|error| fail(SipralStatus::InvalidArgument, error.to_string()))?;
    agent_policy(&mut agent, &config, origin)?;
    // the socket is the caller's; what the stack is told is the address
    // the far end will answer to, which is what goes in every Via
    let bound = agent.receive(
        Input::TransportBound {
            transport: TRANSPORT,
            protocol: speaks.protocol(),
            local,
            remote: None,
        },
        origin,
    );
    if bound.is_err() {
        return Err(fail(
            SipralStatus::InvalidArgument,
            "the transport could not be bound",
        ));
    }

    let tag = tags.lease().map_err(|status| {
        fail(
            status,
            format!(
                "no stack tag is free: a process has {STACK_TAGS}, and a stack holds one from its \
                 creation until it is destroyed and no poll is still running on it"
            ),
        )
    })?;
    let stamp = tag.tag();
    let mut state = StackState {
        callback,
        user_data: config.event_user_data,
        agent,
        engine,
        managed: Vec::new(),
        accounts: Names::new(&tag, Kind::Account),
        calls: Names::new(&tag, Kind::Call),
        subscriptions: Names::new(&tag, Kind::Subscription),
        messages: Names::new(&tag, Kind::Message),
        announcements: Names::new(&tag, Kind::Announcement),
        dialogs: Names::new(&tag, Kind::Dialog),
        identities: HashMap::new(),
        tag,
        transports: Transports::new(speaks.protocol()),
        speaks,
        local,
        held: None,
        timers,
        media,
        user_agent: named.map(|name| Box::from(name.as_bytes())),
        farewells: VecDeque::new(),
        events_dropped: 0,
        farewells_dropped: 0,
        origin,
        polled_at_ms: 0,
        started: false,
        #[cfg(feature = "stun")]
        nat: crate::nat::Nat::default(),
        audio: audio.clone(),
        clock,
        #[cfg(feature = "stir")]
        media_clock: config.media_clock_unix_seconds != 0,
        log: log.clone(),
        pseudonyms: pseudonyms.into_boxed_slice(),
        lost: Vec::new(),
        conferences: Vec::new(),
    };
    // the main transport is the first signalling socket kept mapped; its
    // first request is waiting in `sipral_stack_poll_transmit` from here on
    crate::nat::Nat::start(
        &mut state,
        stun_server,
        turn_server,
        TRANSPORT,
        speaks.protocol(),
        local,
        origin,
    );
    let entry = StackEntry {
        state: Mutex::new(state),
        outbox: Mutex::new(Outbox::default()),
        log,
        watch: Mutex::new(crate::log::Watch::default()),
        audio,
    };
    STACKS
        .insert(stamp, entry)
        .map_err(|status| fail(status, "no room for another stack"))
}

/// The RTP port range a configuration names, or `None` for none.
fn rtp_ports_of(config: &SipralStackConfig) -> Result<Option<sipral::RtpPorts>, Fail> {
    let port = |value: u32, member: &str| {
        u16::try_from(value).map_err(|_| {
            fail(
                SipralStatus::InvalidArgument,
                format!("{member} is {value}, and a port is at most 65535"),
            )
        })
    };
    match (config.rtp_port_min, config.rtp_port_max) {
        (0, 0) => Ok(None),
        (0, _) | (_, 0) => Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "rtp_port_min is {} and rtp_port_max is {}: a range needs both ends, or neither \
                 for none",
                config.rtp_port_min, config.rtp_port_max
            ),
        )),
        (min, max) => sipral::RtpPorts::new(port(min, "rtp_port_min")?, port(max, "rtp_port_max")?)
            .map(Some)
            .map_err(|error| fail(SipralStatus::InvalidArgument, error.to_string())),
    }
}

/// Refuse a call's media described at a port the stack's RTP range does not
/// hand out: odd, or outside it. With no range, every port is the
/// application's to choose.
pub(crate) fn media_port_allowed(state: &StackState, local: SocketAddr) -> Result<(), Fail> {
    match state.engine.rtp_ports() {
        Some(range) if !range.holds(local.port()) => Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "the media address's port is {}, and this stack's RTP range {}..{} hands out \
                 only even ports with the odd port above them inside it; \
                 sipral_stack_rtp_port_reserve gives one",
                local.port(),
                range.min(),
                range.max()
            ),
        )),
        _ => Ok(()),
    }
}

/// The signalling seed and the media seed a configuration hands over, each
/// thirty-two bytes and never the same bytes twice.
///
/// # Safety
///
/// `config.entropy` and `config.media_seed` must be readable for the lengths
/// beside them.
unsafe fn seeds_of(
    config: &SipralStackConfig,
) -> Result<([u8; SEED_BYTES], [u8; SEED_BYTES]), Fail> {
    let seed = seed_from(
        unsafe { bytes(config.entropy, config.entropy_len, "entropy") }?,
        "entropy",
    )?;
    let media_seed = seed_from(
        unsafe { bytes(config.media_seed, config.media_seed_len, "media_seed") }?,
        "media_seed",
    )?;
    if media_seed == seed {
        // The one check that has to live here: nowhere else can see both.
        // Sharing them undoes the separation silently — every message
        // still looks right, and every SRTP key is derivable from a
        // recording that was meant to carry none.
        return Err(fail(
            SipralStatus::InvalidArgument,
            "media_seed is the same as entropy; they must be two independent draws, because a \
             replay recording carries entropy in clear and must not permit deriving a key"
                .to_owned(),
        ));
    }
    Ok((seed, media_seed))
}

fn seed_from(entropy: Option<&[u8]>, member: &str) -> Result<[u8; SEED_BYTES], Fail> {
    let supplied = entropy.unwrap_or_default();
    <[u8; SEED_BYTES]>::try_from(supplied).map_err(|_| {
        fail(
            SipralStatus::InvalidArgument,
            format!(
                "{member} is {} bytes and a stack needs exactly {SEED_BYTES}, from the platform's \
                 own generator",
                supplied.len()
            ),
        )
    })
}

entry! {
    /// Read back what a stack is running with.
    ///
    /// Every value here was either given at creation or defaulted there, and
    /// none of it changes afterwards. It is the other half of a configuration
    /// call that answered `SIPRAL_STATUS_OK`: the call says the value was
    /// taken, this says what it came to.
    ///
    /// # Safety
    ///
    /// `out_settings` must point at a `sipral_stack_settings_t` whose `size`
    /// member says how long it is.
    fn sipral_stack_settings(stack: SipralHandle, out_settings: *mut SipralStackSettings) {
        // checked before the handle is even looked up, so a caller that got
        // its size wrong is told that rather than something about the stack
        unsafe { declared_size(out_settings.cast_const()) }?;
        let settings = with_stack(stack, |state| {
            let limits = *state.agent.endpoint().config();
            let catalog = state.engine.catalog();
            Ok(SipralStackSettings {
                size: size_of::<SipralStackSettings>(),
                transport: state.speaks as u32,
                retransmits: u32::from(!state.speaks.protocol().is_reliable()),
                timer_t1_ms: millis(state.timers.t1),
                timer_t2_ms: millis(state.timers.t2),
                timer_t4_ms: millis(state.timers.t4),
                codec_count: catalog.codecs().len(),
                frame_ms: catalog.frame_length(),
                offer_dtmf: toggle_of(catalog.capabilities().dtmf),
                offer_rtcp_mux: toggle_of(catalog.capabilities().rtcp_mux),
                silence_suppression: toggle_of(state.media.silence_suppression),
                media_stall_ms: state.media.stall_after.map_or(0, millis),
                g729_annex_b: toggle_of(catalog.g729_annex_b()),
                referrals: toggle_of(state.agent.allows_referrals()),
                registrar_keepalive_ms: state.agent.registrar_keepalive().map_or(0, millis),
                max_dialogs: count(limits.max_dialogs),
                max_server_transactions: count(limits.max_server_transactions),
                diagnostic_decisions: count(limits.diagnostics.max_decisions),
                diagnostic_records: count(limits.diagnostics.max_records),
                rtp_port_min: state
                    .engine
                    .rtp_ports()
                    .map_or(0, |range| u32::from(range.min())),
                rtp_port_max: state
                    .engine
                    .rtp_ports()
                    .map_or(0, |range| u32::from(range.max())),
                path_mtu: limits.datagram_limit.path_mtu.unwrap_or(0),
                datagram_without_stream_bytes: limits
                    .datagram_limit
                    .without_stream_bytes
                    .unwrap_or(0),
            })
        })?;
        unsafe { write_versioned(out_settings, settings) }?;
        Ok(())
    }
}

/// A configured interval as the caller counts one. Saturating rather than
/// wrapping: an interval too long to count in milliseconds is one no timer of
/// this stack's was built from.
fn millis(interval: Duration) -> u64 {
    u64::try_from(interval.as_millis()).unwrap_or(u64::MAX)
}

entry! {
    /// Destroy a stack.
    ///
    /// The handle is dead the moment this returns, and a second destroy is
    /// `SIPRAL_STATUS_STALE_HANDLE` rather than a corrupted heap. Called from
    /// inside the callback it is still safe: what the poll is holding stays
    /// alive until that poll returns. Called from inside a frame of one of its
    /// calls — a processor — it is `SIPRAL_STATUS_BUSY` and nothing is freed,
    /// because freeing the stack ends that call's media and the frame is
    /// holding it. No account is de-registered and no call is hung up; a stack
    /// that has to leave politely does that first.
    ///
    /// Nothing is sent, either: the stack owns no socket. A relay on a TURN
    /// server is given back only by a Refresh this end sends, so one still
    /// held at this point stays allocated on the server until its lifetime
    /// runs out, up to ten minutes later. To leave none behind, hang up every
    /// call, poll until each has ended and send what
    /// `sipral_stack_poll_farewell` hands out, call
    /// `sipral_stack_nat_unmap` for every media socket still named and send
    /// what `sipral_stack_poll_stun` hands out, and destroy after that.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    fn sipral_stack_destroy(stack: SipralHandle) {
        if crate::media::inside_media_of(stack) {
            return Err(inside_media());
        }
        if crate::audio::inside_transmit() {
            return Err(fail(
                SipralStatus::Busy,
                "this thread is the audio engine's, inside the audio transmit callback, and \
                 destroying a stack from there would wait for this very thread to finish: \
                 destroy it from another thread",
            ));
        }
        // dropping the last share of the entry here is what frees it; a poll
        // running on another thread holds one of its own until it is done
        STACKS.remove(stack).map_err(handle_failed)?;
        Ok(())
    }
}

entry! {
    /// Let the stack do its work, and deliver what it has to say.
    ///
    /// `now_ms` is the caller's monotonic clock in milliseconds. It must not
    /// fall more than fifty milliseconds behind the last one this stack saw —
    /// signalling may be called from any thread, and two of them reading the
    /// same clock a moment apart is not a caller mistake — and a jump further
    /// back than that is `SIPRAL_STATUS_CLOCK_BEHIND` with nothing delivered.
    ///
    /// The event callback is called from inside this function, on this
    /// thread, and with nothing held: the stack's work is done and its lock
    /// let go before the first event is handed over, so the callback may call
    /// back into the library, this stack included. A poll that finds another
    /// poll of the same stack already delivering — which is what a poll from
    /// inside the callback always finds — does the stack's work and leaves its
    /// events to that one, so they arrive in the order they were raised and
    /// never on two threads at once.
    ///
    /// `result` may be null for a caller that does not want the counts.
    ///
    /// A poll is also where the stack writes: a retransmission falls due, a
    /// registration is refreshed, a transaction gives up and says so. What it
    /// wrote is taken with `sipral_stack_poll_transmit`, which is drained after
    /// every poll and left alone by the next one — see `docs/08-ffi.md`,
    /// "Signalling across the boundary", for the loop in full.
    ///
    /// # Safety
    ///
    /// `result` must be null or point at a `sipral_poll_result_t` whose `size`
    /// member says how long it is.
    fn sipral_stack_poll(stack: SipralHandle, now_ms: u64, result: *mut SipralPollResult) {
        // checked before the handle is even looked up, so a caller that got
        // its size wrong is told that rather than something about the stack,
        // and before the clock moves, so a refusal here leaves it untouched
        if !result.is_null() {
            unsafe { declared_size(result.cast_const()) }?;
        }
        // held until this poll returns, delivery included, so a stack
        // destroyed from inside its own callback is freed afterwards rather
        // than underneath the queue being read
        let entry = entry_of(stack)?;
        let (mut counted, speaker) = {
            let mut state = lock(&entry)?;
            let now = state.advance(now_ms)?;
            let mut raised = Vec::new();
            let counted = run(stack, &mut state, now, &mut raised);
            if !raised.is_empty() {
                // something changed: what `sipral_stack_state_text` hands out
                // while another thread holds the stack is brought up to date
                entry.watch().refresh(stack, &state);
            }
            // posted with the stack still held, so that a poll on another
            // thread cannot queue what it raised in front of this
            let (should_deliver, dropped) = entry.post(raised);
            state.events_dropped = state
                .events_dropped
                .saturating_add(u64::try_from(dropped).unwrap_or(u64::MAX));
            let speaker = should_deliver.then_some(Speaker {
                callback: state.callback,
                user_data: state.user_data,
            });
            (counted, speaker)
        };
        if let Some(speaker) = speaker {
            let (delivered, left_waiting) = entry.deliver(speaker);
            counted.events_delivered = delivered;
            if left_waiting {
                // what arrived during the pass is the next poll's to deliver,
                // and that poll is due now, not when a timer or a datagram
                // next happens to wake the caller
                counted.has_deadline = 1;
                counted.next_poll_in_ms = 0;
            }
        }
        // the log's lines after the events, with nothing held
        let _ = entry.log.flush();

        if !result.is_null() {
            unsafe { write_versioned(result, counted) }?;
        }
        Ok(())
    }
}

/// One poll: time passes, and what the stack has to say is taken out of it.
///
/// `events_delivered` is left at zero for whichever poll delivers to fill in,
/// which is this one or one already under way.
fn run(
    stack: SipralHandle,
    state: &mut StackState,
    now: Instant,
    raised: &mut Vec<Delivery>,
) -> SipralPollResult {
    state.agent.handle_timeout(now);
    state.engine.handle_timeout(now);
    crate::nat::Nat::handle_timeout(state, now);

    let mut unclaimed = 0_usize;
    if !state.started {
        state.started = true;
        raised.push(Delivery::bare(crate::event::started(stack)));
    }
    // the cause before its effects: a transport lost is said before the
    // registrations and calls that failed with it
    for lost in std::mem::take(&mut state.lost) {
        let (event, text) = lost.raised(stack);
        raised.push(Delivery {
            event,
            _raised: None,
            _reason: Some(text),
            _record: None,
            _identity: None,
        });
    }
    drain(stack, state, now, raised, &mut unclaimed);
    // after the engine's, so that a REGISTER an answer moved the accounts to
    // follows every event the poll already had about them
    for (event, text) in crate::nat::Nat::drain(state, stack, now) {
        raised.push(Delivery {
            event,
            _raised: None,
            _reason: Some(text),
            _record: None,
            _identity: None,
        });
    }
    // the audio engine's own news: a device gone, a default moved, a role
    // reopened. Its lock is only tried, after the engine's events above have
    // been translated: a `sipral_audio_*` call on another thread holds it for
    // as long as the platform takes to answer about its devices — up to
    // `audio_probe_ms` — and a poll that waited for it would hold this
    // stack's lock all that while, turning every signalling call on every
    // other thread into SIPRAL_STATUS_BUSY. A busy engine is serviced by the
    // next poll, which is asked for soon.
    let mut audio_busy = false;
    if let Some(audio) = state.audio.clone() {
        let held = match audio.try_lock() {
            Ok(engine) => Some(engine),
            Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => None,
        };
        if let Some(mut engine) = held {
            engine.service();
            while let Some(event) = engine.poll_event() {
                raised.push(Delivery::bare(crate::event::audio_changed(
                    stack,
                    crate::audio::event_of(event),
                )));
            }
        } else {
            audio_busy = true;
        }
    }
    // what the local conferences did since the last poll: members that
    // joined and left, who is talking, a recording that stopped
    for event in crate::local_conference::drain(state, stack) {
        raised.push(Delivery::bare(event));
    }

    let deadline = [
        state.agent.poll_timeout(),
        state.engine.poll_timeout(),
        crate::nat::Nat::poll_timeout(state),
        audio_busy.then(|| now + AUDIO_BUSY_RETRY),
    ]
    .into_iter()
    .flatten()
    .min();
    SipralPollResult {
        size: size_of::<SipralPollResult>(),
        events_delivered: 0,
        events_unclaimed: unclaimed,
        transmits_discarded: 0,
        has_deadline: u32::from(deadline.is_some()),
        next_poll_in_ms: deadline.map_or(0, |at| {
            u64::try_from(at.saturating_duration_since(now).as_millis()).unwrap_or(u64::MAX)
        }),
    }
}

/// Take everything the engine has, translated for the callback.
///
/// Calls that ended are forgotten at the end rather than as their news is
/// translated: the media of a call is reported after the signalling that ended
/// it, and a handle retired in between would leave the last word about a call
/// naming nothing. What `MediaEngine::poll_farewell` produced for them is
/// gathered here too, addressed to the same handle before it is forgotten,
/// since the goodbye and the handle both outlive the call by exactly the same
/// margin and neither is reachable again after this function returns.
fn drain(
    stack: SipralHandle,
    state: &mut StackState,
    now: Instant,
    raised: &mut Vec<Delivery>,
    unclaimed: &mut usize,
) {
    let mut ended: Vec<CallHandle> = Vec::new();
    let mut messages_sent: Vec<sipral_ua::MessageHandle> = Vec::new();
    let mut lapsed: Vec<CallHandle> = Vec::new();
    while let Some(event) = state.engine.poll_event(&mut state.agent, now) {
        match event {
            Event::Signalling(said) => {
                // read out of the INVITE this event carries, before the event
                // itself is translated, since it is the first to report who is
                // on the line. Not asked of the layer below: a CANCEL that
                // arrived before this poll has already made it forget the call
                // The layer below read it behind the account's trust gate
                // (RFC 3325 §8), which only it can apply
                if let UaEvent::IncomingCall {
                    call,
                    ref request,
                    ref identity,
                    ..
                } = said
                    && let Some(identity) = identity
                        .clone()
                        .or_else(|| CallIdentity::of_request(request).map(Arc::new))
                {
                    state.record_shared_identity(call, identity);
                }
                if let UaEvent::CallForked { call, sibling } = said {
                    // one INVITE opened every early dialog among them, so a
                    // branch answers to the same From, To and Call-ID as the
                    // parent it was forked from, read before either had one
                    if let Some(identity) = state.identities.get(&call).cloned() {
                        state.identities.insert(sibling, identity);
                    }
                    if state.manages(call) {
                        // the branch was offered exactly what its parent was,
                        // and the engine has already given it a stream of its
                        // own
                        state.manage(sibling);
                    }
                }
                if let UaEvent::CallEnded { call, .. } = said {
                    ended.push(call);
                }
                if let UaEvent::MessageSent { message, .. } = said {
                    messages_sent.push(message);
                }
                if let UaEvent::ReferralLapsed { referral, .. } = said {
                    lapsed.push(referral);
                }
                signalling(stack, state, said, raised, unclaimed);
            }
            Event::Media { call, event } => {
                // in device mode a call's session is the engine's to pump
                // from the moment its media starts to the moment it ends
                if let Some(audio) = state.audio.clone() {
                    match event {
                        MediaEvent::Started { .. } => {
                            if let (Some(share), Ok(handle)) =
                                (state.engine.share(call), state.calls.name_of(call))
                            {
                                let _ = audio
                                    .lock()
                                    .unwrap_or_else(PoisonError::into_inner)
                                    .attach(handle, Box::new(share));
                            }
                        }
                        MediaEvent::Ended(_) => {
                            if let Ok(handle) = state.calls.name_of(call) {
                                audio
                                    .lock()
                                    .unwrap_or_else(PoisonError::into_inner)
                                    .detach(handle);
                            }
                        }
                        _ => {}
                    }
                }
                media(stack, state, call, &event, raised, unclaimed);
            }
            // the facade is free to grow a vocabulary faster than this ABI,
            // and a number counted is more honest than a kind invented
            _ => *unclaimed = unclaimed.saturating_add(1),
        }
    }
    // one call's own release pushes at most one of these, synchronously,
    // inside the very `poll_event` call above that returned its `CallEnded`
    // — so by the time this loop runs every goodbye this poll is ever going
    // to see is already here, still naming a call `calls` has not forgotten
    // yet
    while let Some((call, destination, payload)) = state.engine.poll_farewell() {
        let protocol = SipralTransport::Udp as u32;
        farewell(state, call, destination, payload, protocol);
    }
    // what a call gives back on its relay's connection to the TURN server:
    // the same queue, marked with what to write it on
    #[cfg(feature = "ice")]
    while let Some((call, bytes)) = state.engine.poll_turn_stream() {
        let protocol = crate::nat::protocol_of(bytes.transport);
        farewell(state, call, bytes.destination, bytes.payload, protocol);
    }
    for call in ended {
        if let Some(dialog) = state.agent.call_dialog(call) {
            state.dialogs.forget(dialog);
        }
        state.calls.forget(call);
        state.unmanage(call);
        // the delivery already queued for this call's own ending keeps its
        // own share of this alive; forgetting it here only stops a later
        // event from finding it, which there is not going to be one of
        state.identities.remove(&call);
    }
    // MessageSent is the last word about a send, so the handle is retired the
    // same way a call's is: after its own event is already translated and
    // queued, which is the only place it still needed to be found
    for message in messages_sent {
        state.messages.forget(message);
    }
    // and a referral nobody answered: its lapse is the last word about it
    for referral in lapsed {
        state.calls.forget(referral);
    }
}

/// Queue one of `call`'s farewells for `sipral_stack_poll_farewell`.
fn farewell(
    state: &mut StackState,
    call: CallHandle,
    destination: SocketAddr,
    payload: Vec<u8>,
    protocol: u32,
) {
    let handle = state.calls.name_of(call).unwrap_or(SIPRAL_HANDLE_NONE);
    if state.farewells.len() >= FAREWELL_CEILING {
        // the oldest goodbye is worth less than the one that just
        // arrived — see FAREWELL_CEILING
        state.farewells.pop_front();
        state.farewells_dropped = state.farewells_dropped.saturating_add(1);
    }
    state
        .farewells
        .push_back((handle, destination, payload, protocol));
}

fn signalling(
    stack: SipralHandle,
    state: &mut StackState,
    said: UaEvent,
    raised: &mut Vec<Delivery>,
    unclaimed: &mut usize,
) {
    // a re-offer on a call this stack describes has already been answered by
    // the engine, inside the poll that produced this. Handing it to the
    // application would be asking for an answer that is already on the wire,
    // and the application hears the outcome as a media event instead.
    if let UaEvent::Reoffer { call, .. } = said
        && state.manages(call)
    {
        return;
    }
    // RFC 5626 §4.4.1: a flow that used to answer its pings stopped, and the
    // endpoint has retired the transport. That is what
    // `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` says of a transport, so it is said
    // that way: the application holds the socket, and until it hears this it
    // keeps a connection the stack will never write to again, and does not
    // open another when the stack asks for one to the same place.
    if let UaEvent::Unclaimed(sipral_core::endpoint::Event::FlowFailed { transport }) = said {
        let lost = crate::transport::Lost {
            transport: transport.0,
            protocol: state
                .transports
                .protocol_of(transport.0)
                .map_or(0, crate::stack::SipralTransport::named),
            error: crate::transport::SipralTransportError::TimedOut,
            tls: crate::transport::SipralTlsFailure::None,
            detail: String::from(
                "no answer to a keep-alive ping within ten seconds (RFC 5626 section 4.4.1)",
            ),
        };
        let (event, text) = lost.raised(stack);
        raised.push(Delivery {
            event,
            _raised: None,
            _reason: Some(text),
            _record: None,
            _identity: None,
        });
        return;
    }
    // built before `said` moves behind the `Arc`, and for the same reason a
    // media reason is built in `media` below: a `SocketAddr` has no bytes of
    // its own to point at, so this is what the event's pointer needs kept
    // alive once the borrow below has gone
    let destination = crate::event::text_to_point_at(&said);
    // shared rather than owned outright, so that the bytes the translation
    // points into stay where they are however often the delivery moves
    let said = Arc::new(said);
    let mut known = Vocabulary {
        stack,
        agent: &state.agent,
        accounts: &mut state.accounts,
        calls: &mut state.calls,
        subscriptions: &mut state.subscriptions,
        messages: &mut state.messages,
        announcements: &mut state.announcements,
        dialogs: &mut state.dialogs,
        identities: &state.identities,
        raised_identity: None,
    };
    let Some(event) = crate::event::translate(&mut known, &said, destination.as_deref()) else {
        *unclaimed = unclaimed.saturating_add(1);
        return;
    };
    raised.push(Delivery {
        event,
        _raised: Some(said),
        _reason: destination,
        _record: None,
        _identity: known.raised_identity,
    });
}

fn media(
    stack: SipralHandle,
    state: &mut StackState,
    call: CallHandle,
    said: &MediaEvent,
    raised: &mut Vec<Delivery>,
    unclaimed: &mut usize,
) {
    // neither of these can be borrowed from the event: a sentence has to be
    // formatted and a record converted before either has a shape C can read,
    // and both travel with the delivery because they are read after this poll
    // has let the stack go
    let reason = crate::event::media_reason(said);
    // the call's stream as its encryption report has it now, for the kinds
    // that carry it; read before the vocabulary borrows the stack
    let encryption = state
        .engine
        .encryption(call)
        .and_then(|report| report.first().copied());
    let record = match *said {
        MediaEvent::Ended(ref cost) => Some(Arc::new(stream_stats(cost))),
        _ => None,
    };
    let mut known = Vocabulary {
        stack,
        agent: &state.agent,
        accounts: &mut state.accounts,
        calls: &mut state.calls,
        subscriptions: &mut state.subscriptions,
        messages: &mut state.messages,
        announcements: &mut state.announcements,
        dialogs: &mut state.dialogs,
        identities: &state.identities,
        raised_identity: None,
    };
    let Some(event) = crate::event::media(
        &mut known,
        call,
        said,
        reason.as_deref(),
        record.as_deref(),
        encryption.as_ref(),
    ) else {
        *unclaimed = unclaimed.saturating_add(1);
        return;
    };
    raised.push(Delivery {
        event,
        _raised: None,
        _reason: reason,
        _record: record,
        _identity: None,
    });
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        Delivery, OUTBOX_CEILING, SipralPollResult, SipralStackConfig, SipralStackSettings,
        SipralTransport, Speaker, StackEntry, create_on, entry_of, sipral_stack_create,
        sipral_stack_destroy, sipral_stack_poll, sipral_stack_settings, with_stack,
    };
    use crate::error::{guard, last_error_text};
    use crate::event::{SipralEvent, SipralEventKind};
    use crate::handle::{SIPRAL_HANDLE_NONE, STACK_TAGS, SipralHandle, StackTags, split};
    use crate::media::SipralToggle;
    use crate::status::SipralStatus;
    use sipral::Codec;
    use std::cell::{Cell, RefCell};
    use std::ffi::{c_char, c_void};
    use std::ptr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub(crate) const BIND: &str = "192.0.2.10:5060";
    pub(crate) const SEED: [u8; 32] = [7; 32];
    /// The media seed a test stack runs with: a different draw, because the
    /// library refuses the same bytes twice and is right to.
    pub(crate) const MEDIA_SEED: [u8; 32] = [23; 32];

    /// One member of the config, named as a caller's header names it, and the
    /// way to put a value in it.
    type Setting = (&'static str, fn(&mut SipralStackConfig));

    /// What a media event said, copied out while the callback is still running.
    ///
    /// The pointers in an event are the library's and are valid for exactly
    /// that long, so this is also what tests that promise.
    #[derive(Clone, Debug)]
    pub(crate) struct Heard {
        pub(crate) kind: SipralEventKind,
        pub(crate) call: SipralHandle,
        pub(crate) codec: u32,
        pub(crate) direction: u32,
        pub(crate) silent_for_ms: u64,
        pub(crate) recorded_ms: u64,
        pub(crate) fault: u32,
        pub(crate) reason: String,
        pub(crate) statistics: Option<crate::media::SipralStreamStats>,
        pub(crate) digit: u32,
        pub(crate) event_code: u32,
        pub(crate) held_ms: u64,
        pub(crate) source: u32,
    }

    /// What one call event said about who is on it, copied out while the
    /// callback is still running.
    ///
    /// The pointers in an event are the library's and are valid for exactly
    /// that long, so this is also what tests that promise.
    #[derive(Clone, Debug)]
    pub(crate) struct Seen {
        pub(crate) kind: SipralEventKind,
        pub(crate) call: SipralHandle,
        pub(crate) from_uri: Vec<u8>,
        pub(crate) from_display: Vec<u8>,
        pub(crate) to_uri: Vec<u8>,
        pub(crate) call_id: Vec<u8>,
        pub(crate) status_code: u32,
        pub(crate) digit: u32,
        pub(crate) cause_sip: u32,
        pub(crate) cause_q850: u32,
        pub(crate) cause_text: Vec<u8>,
        pub(crate) identity_trusted: u32,
        pub(crate) asserted_uri: Vec<u8>,
        pub(crate) asserted_display: Vec<u8>,
        pub(crate) verstat: u32,
        pub(crate) privacy: u32,
        pub(crate) diverted_from: Vec<u8>,
        pub(crate) diversion_reason: Vec<u8>,
        pub(crate) diversion_count: u32,
        pub(crate) history_count: u32,
        pub(crate) answer_mode: u32,
        pub(crate) answer_mode_required: u32,
        pub(crate) has_answer_after: u32,
        pub(crate) answer_after_ms: u64,
        pub(crate) ring_source: u32,
        pub(crate) alert_info: Vec<u8>,
    }

    /// What a caller of the C API would keep behind its user pointer.
    #[derive(Default)]
    pub(crate) struct Observed {
        pub(crate) events: Vec<(SipralHandle, SipralEventKind, usize)>,
        /// The handles the events named, in order.
        pub(crate) named: Vec<(SipralHandle, SipralHandle)>,
        /// What every media event carried.
        pub(crate) media: Vec<Heard>,
        /// Who every call event said was on the call, in the order the events
        /// arrived.
        pub(crate) calls: Vec<Seen>,
        /// What every subscription event carried, in the order they arrived.
        pub(crate) subscriptions: Vec<Watched>,
        /// What every resolve request carried, in the order they arrived.
        pub(crate) resolves: Vec<Asked>,
        /// What every referral event carried, in the order they arrived.
        pub(crate) referrals: Vec<Referring>,
        /// What every audio-devices event carried: change, origin, role and
        /// device, in the order they arrived.
        pub(crate) audio: Vec<(u32, u32, u32, u32)>,
        /// What every progress event carried: what, tone, verdict, reason and
        /// when, in the order they arrived.
        pub(crate) progress: Vec<(u32, u32, u32, u32, u64)>,
        /// What every conference, text and presence event carried, in the
        /// order they arrived.
        pub(crate) protocols: Vec<Told>,
        /// What every transport-failed event carried: transport, protocol,
        /// error, TLS reason and detail, in the order they arrived.
        pub(crate) transports_lost: Vec<(u32, u32, u32, u32, String)>,
        /// What every local conference event carried, in the order they
        /// arrived.
        pub(crate) local_conferences: Vec<crate::local_conference::SipralLocalConferenceEvent>,
        /// What every lookup, location and failed location carried, in the
        /// order they arrived.
        pub(crate) locating: Vec<crate::locate::tests::Locating>,
        /// Filled by the callbacks that call back into the library.
        reentrant_status: Option<SipralStatus>,
        destroy_status: Option<SipralStatus>,
        /// What creating a stack from inside the callback answered, and the
        /// handle it wrote.
        created_inside: Option<(SipralStatus, SipralHandle)>,
    }

    impl Observed {
        pub(crate) fn kinds(&self) -> Vec<SipralEventKind> {
            self.events.iter().map(|event| event.1).collect()
        }

        /// The media events of one kind, in the order they arrived.
        pub(crate) fn of(&self, kind: SipralEventKind) -> Vec<Heard> {
            self.media
                .iter()
                .filter(|heard| heard.kind == kind)
                .cloned()
                .collect()
        }

        /// Every call event that named `call`, in the order they arrived.
        pub(crate) fn identities_of(&self, call: SipralHandle) -> Vec<Seen> {
            self.calls
                .iter()
                .filter(|seen| seen.call == call)
                .cloned()
                .collect()
        }
    }

    const fn is_media(kind: SipralEventKind) -> bool {
        matches!(
            kind,
            SipralEventKind::MediaStarted
                | SipralEventKind::MediaChanged
                | SipralEventKind::MediaStalled
                | SipralEventKind::MediaResumed
                | SipralEventKind::MediaFailed
                | SipralEventKind::MediaStatistics
                | SipralEventKind::RecordingStopped
                | SipralEventKind::DigitReceived
                | SipralEventKind::MediaUnjoined
                | SipralEventKind::InBandDigit
        )
    }

    const fn is_call_kind(kind: SipralEventKind) -> bool {
        matches!(
            kind,
            SipralEventKind::IncomingCall
                | SipralEventKind::CallProgress
                | SipralEventKind::CallForked
                | SipralEventKind::CallConfirmed
                | SipralEventKind::SessionChanged
                | SipralEventKind::SessionOffered
                | SipralEventKind::SessionChangeFailed
                | SipralEventKind::CallReplaced
                | SipralEventKind::CallEnded
                | SipralEventKind::DtmfSent
                | SipralEventKind::CallAddressWanted
        )
    }

    /// What one media event said, read the way a binding would: out of the
    /// union arm the kind names, before the callback returns.
    unsafe fn heard(event: &SipralEvent) -> Heard {
        let payload = unsafe { event.payload.media };
        let reason = if payload.reason.is_null() {
            String::new()
        } else {
            let bytes = unsafe {
                std::slice::from_raw_parts(payload.reason.cast::<u8>(), payload.reason_len)
            };
            String::from_utf8_lossy(bytes).into_owned()
        };
        Heard {
            kind: event.kind,
            call: event.call,
            codec: payload.codec,
            direction: payload.direction,
            silent_for_ms: payload.silent_for_ms,
            recorded_ms: payload.recorded_ms,
            fault: payload.fault,
            reason,
            statistics: if payload.statistics.is_null() {
                None
            } else {
                Some(unsafe { *payload.statistics })
            },
            digit: payload.digit,
            event_code: payload.event_code,
            held_ms: payload.held_ms,
            source: payload.source,
        }
    }

    /// A pointer and a length an event carries, copied while both are good
    /// for reading: empty for the null-and-zero this ABI uses for absent.
    fn owned(pointer: *const u8, len: usize) -> Vec<u8> {
        if pointer.is_null() {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(pointer, len) }.to_vec()
        }
    }

    /// What one call event said about who is on it, read the way a binding
    /// would: out of the union arm the kind names, before the callback
    /// returns.
    unsafe fn seen(event: &SipralEvent) -> Seen {
        let payload = unsafe { event.payload.call };
        Seen {
            kind: event.kind,
            call: event.call,
            from_uri: owned(payload.from_uri, payload.from_uri_len),
            from_display: owned(payload.from_display, payload.from_display_len),
            to_uri: owned(payload.to_uri, payload.to_uri_len),
            call_id: owned(payload.call_id, payload.call_id_len),
            status_code: payload.status_code,
            digit: payload.digit,
            cause_sip: payload.cause_sip,
            cause_q850: payload.cause_q850,
            cause_text: owned(payload.cause_text, payload.cause_text_len),
            identity_trusted: payload.identity_trusted,
            asserted_uri: owned(payload.asserted_uri, payload.asserted_uri_len),
            asserted_display: owned(payload.asserted_display, payload.asserted_display_len),
            verstat: payload.verstat,
            privacy: payload.privacy,
            diverted_from: owned(payload.diverted_from, payload.diverted_from_len),
            diversion_reason: owned(payload.diversion_reason, payload.diversion_reason_len),
            diversion_count: payload.diversion_count,
            history_count: payload.history_count,
            answer_mode: payload.answer_mode,
            answer_mode_required: payload.answer_mode_required,
            has_answer_after: payload.has_answer_after,
            answer_after_ms: payload.answer_after_ms,
            ring_source: payload.ring_source,
            alert_info: owned(payload.alert_info, payload.alert_info_len),
        }
    }

    /// What one subscription event said, read inside the callback the way an
    /// application reads it: the payload belongs to the library and is gone
    /// the moment this returns.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Watched {
        pub(crate) kind: SipralEventKind,
        pub(crate) subscription: SipralHandle,
        pub(crate) state: u32,
        pub(crate) reason: u32,
        pub(crate) status_code: u32,
        pub(crate) has_dialog_info: u32,
        pub(crate) expires_ms: u64,
        pub(crate) retry_in_ms: u64,
        pub(crate) forked_from: SipralHandle,
        /// How long until the next refresh, in milliseconds.
        pub(crate) refresh_in_ms: u64,
        /// How many bytes of NOTIFY, or of a refusal, came with it.
        pub(crate) message_len: usize,
    }

    /// What one conference, text or presence event said, copied out while
    /// its pointers are still the library's to read. Each kind fills the
    /// members its arm has and leaves the rest at their defaults.
    #[derive(Clone, Debug, Default)]
    pub(crate) struct Told {
        pub(crate) kind: Option<SipralEventKind>,
        pub(crate) account: SipralHandle,
        pub(crate) call: SipralHandle,
        pub(crate) subscription: SipralHandle,
        pub(crate) update: u32,
        pub(crate) version: u32,
        pub(crate) users: u32,
        pub(crate) text: String,
        pub(crate) missing: u32,
        pub(crate) presence_kind: u32,
        pub(crate) basic: u32,
        pub(crate) activity: u32,
        pub(crate) entity: String,
        pub(crate) note: Option<String>,
        pub(crate) publication_state: u32,
        pub(crate) failure: u32,
        pub(crate) status_code: u32,
        pub(crate) expires_ms: u64,
        pub(crate) refresh_in_ms: u64,
    }

    /// The conference, text or presence arm of one event's payload.
    ///
    /// # Safety
    ///
    /// `event` must be one of the three kinds that fill those arms in.
    unsafe fn told(event: &SipralEvent) -> Told {
        let text = |pointer: *const c_char, len: usize| {
            (!pointer.is_null()).then(|| {
                let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), len) };
                String::from_utf8_lossy(bytes).into_owned()
            })
        };
        let mut out = Told {
            kind: Some(event.kind),
            account: event.account,
            call: event.call,
            ..Told::default()
        };
        match event.kind {
            SipralEventKind::ConferenceChanged => {
                let payload = unsafe { event.payload.conference };
                out.subscription = payload.subscription;
                out.update = payload.update;
                out.version = payload.version;
                out.users = payload.users;
            }
            SipralEventKind::TextReceived => {
                let payload = unsafe { event.payload.text };
                out.text = text(payload.text, payload.text_len).unwrap_or_default();
                out.missing = payload.missing;
            }
            _ => {
                let payload = unsafe { event.payload.presence };
                out.subscription = payload.subscription;
                out.presence_kind = payload.kind;
                out.basic = payload.basic;
                out.activity = payload.activity;
                out.entity = text(payload.entity, payload.entity_len).unwrap_or_default();
                out.note = text(payload.note, payload.note_len);
                out.publication_state = payload.publication_state;
                out.failure = payload.failure;
                out.status_code = payload.status_code;
                out.expires_ms = payload.expires_ms;
                out.refresh_in_ms = payload.refresh_in_ms;
            }
        }
        out
    }

    /// What one `SIPRAL_EVENT_KIND_RESOLVE_NEEDED` said, copied out while its
    /// pointers are still the library's to read.
    #[derive(Clone, Debug)]
    pub(crate) struct Asked {
        pub(crate) dialog: SipralHandle,
        pub(crate) host: String,
        pub(crate) port: u32,
        pub(crate) protocol: u32,
    }

    /// The resolve arm of one event's payload.
    ///
    /// # Safety
    ///
    /// `event` must be the kind that fills that arm in.
    unsafe fn asked(event: &SipralEvent) -> Asked {
        let payload = unsafe { event.payload.resolve };
        let host = if payload.host.is_null() {
            String::new()
        } else {
            let bytes =
                unsafe { std::slice::from_raw_parts(payload.host.cast::<u8>(), payload.host_len) };
            String::from_utf8_lossy(bytes).into_owned()
        };
        Asked {
            dialog: payload.dialog,
            host,
            port: payload.port,
            protocol: payload.protocol,
        }
    }

    /// What one `SIPRAL_EVENT_KIND_REFERRAL` said, copied out while its
    /// pointers are still the library's to read.
    #[derive(Clone, Debug)]
    pub(crate) struct Referring {
        pub(crate) account: SipralHandle,
        pub(crate) referral: SipralHandle,
        pub(crate) status_code: u32,
        pub(crate) attended: u32,
        pub(crate) target: String,
        pub(crate) referred_by: Option<String>,
        pub(crate) message_len: usize,
    }

    /// The referral arm of one event's payload.
    ///
    /// # Safety
    ///
    /// `event` must be the kind that fills that arm in.
    unsafe fn referred(event: &SipralEvent) -> Referring {
        let payload = unsafe { event.payload.referral };
        let text = |pointer: *const c_char, len: usize| {
            (!pointer.is_null()).then(|| {
                let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), len) };
                String::from_utf8_lossy(bytes).into_owned()
            })
        };
        Referring {
            account: event.account,
            referral: event.call,
            status_code: payload.status_code,
            attended: payload.attended,
            target: text(payload.target, payload.target_len).unwrap_or_default(),
            referred_by: text(payload.referred_by, payload.referred_by_len),
            message_len: event.message_len,
        }
    }

    /// The subscription arm of one event's payload.
    ///
    /// # Safety
    ///
    /// `event` must be one of the two kinds that fill that arm in.
    unsafe fn watched(event: &SipralEvent) -> Watched {
        let payload = unsafe { event.payload.subscription };
        Watched {
            kind: event.kind,
            subscription: payload.subscription,
            state: payload.state,
            reason: payload.reason,
            status_code: payload.status_code,
            has_dialog_info: payload.has_dialog_info,
            expires_ms: payload.expires_ms,
            retry_in_ms: payload.retry_in_ms,
            forked_from: payload.forked_from,
            refresh_in_ms: payload.refresh_in_ms,
            message_len: event.message_len,
        }
    }

    pub(crate) unsafe extern "C" fn record(event: *const SipralEvent, user_data: *mut c_void) {
        let observed = unsafe { &mut *user_data.cast::<Observed>() };
        let event = unsafe { &*event };
        observed.events.push((event.stack, event.kind, event.size));
        observed.named.push((event.account, event.call));
        if is_media(event.kind) {
            let heard = unsafe { heard(event) };
            observed.media.push(heard);
        }
        if is_call_kind(event.kind) {
            let seen = unsafe { seen(event) };
            observed.calls.push(seen);
        }
        if matches!(
            event.kind,
            SipralEventKind::SubscriptionChanged | SipralEventKind::Notified
        ) {
            let watched = unsafe { watched(event) };
            observed.subscriptions.push(watched);
        }
        if event.kind == SipralEventKind::ResolveNeeded {
            let asked = unsafe { asked(event) };
            observed.resolves.push(asked);
        }
        if event.kind == SipralEventKind::Referral {
            let referred = unsafe { referred(event) };
            observed.referrals.push(referred);
        }
        if matches!(
            event.kind,
            SipralEventKind::ConferenceChanged
                | SipralEventKind::TextReceived
                | SipralEventKind::PresenceChanged
        ) {
            let told = unsafe { told(event) };
            observed.protocols.push(told);
        }
        if event.kind == SipralEventKind::AudioDevicesChanged {
            let audio = unsafe { event.payload.audio };
            observed
                .audio
                .push((audio.change, audio.origin, audio.role, audio.device));
        }
        if event.kind == SipralEventKind::ProgressDetected {
            let heard = unsafe { event.payload.progress };
            observed.progress.push((
                heard.what,
                heard.tone,
                heard.verdict,
                heard.reason,
                heard.at_ms,
            ));
        }
        if event.kind == SipralEventKind::LocalConferenceChanged {
            observed
                .local_conferences
                .push(unsafe { event.payload.local_conference });
        }
        if matches!(
            event.kind,
            SipralEventKind::LookupWanted
                | SipralEventKind::Located
                | SipralEventKind::LocateFailed
        ) {
            observed
                .locating
                .push(unsafe { crate::locate::tests::locating(event) });
        }
        if event.kind == SipralEventKind::TransportFailed {
            let lost = unsafe { event.payload.transport_failed };
            let detail = if lost.detail.is_null() {
                String::new()
            } else {
                let bytes = unsafe {
                    std::slice::from_raw_parts(lost.detail.cast::<u8>(), lost.detail_len)
                };
                String::from_utf8_lossy(bytes).into_owned()
            };
            observed.transports_lost.push((
                lost.transport,
                lost.protocol,
                lost.error,
                lost.tls,
                detail,
            ));
        }
    }

    unsafe extern "C" fn poll_again(event: *const SipralEvent, user_data: *mut c_void) {
        let observed = unsafe { &mut *user_data.cast::<Observed>() };
        let event = unsafe { &*event };
        observed.events.push((event.stack, event.kind, event.size));
        observed.reentrant_status =
            Some(unsafe { sipral_stack_poll(event.stack, 0, ptr::null_mut()) });
    }

    /// Call in from a thread that is not the one holding the stack.
    ///
    /// Spawning and joining inside the callback is what makes the race
    /// deterministic: the other thread runs while this one is provably still
    /// inside the poll.
    unsafe extern "C" fn poll_from_another_thread(
        event: *const SipralEvent,
        user_data: *mut c_void,
    ) {
        let observed = unsafe { &mut *user_data.cast::<Observed>() };
        let event = unsafe { &*event };
        observed.events.push((event.stack, event.kind, event.size));
        let held = event.stack;
        observed.reentrant_status = Some(
            std::thread::spawn(move || unsafe { sipral_stack_poll(held, 0, ptr::null_mut()) })
                .join()
                .expect("the thread finished"),
        );
    }

    unsafe extern "C" fn destroy_from_inside(event: *const SipralEvent, user_data: *mut c_void) {
        let observed = unsafe { &mut *user_data.cast::<Observed>() };
        let event = unsafe { &*event };
        observed.events.push((event.stack, event.kind, event.size));
        observed.destroy_status = Some(unsafe { sipral_stack_destroy(event.stack) });
    }

    pub(crate) fn config(
        callback: unsafe extern "C" fn(*const SipralEvent, *mut c_void),
        observed: &mut Observed,
    ) -> SipralStackConfig {
        SipralStackConfig {
            size: size_of::<SipralStackConfig>(),
            event_callback: Some(callback),
            event_user_data: ptr::from_mut(observed).cast::<c_void>(),
            transport: SipralTransport::Udp as u32,
            bind_address: BIND.as_ptr().cast::<c_char>(),
            bind_address_len: BIND.len(),
            user_agent: ptr::null(),
            user_agent_len: 0,
            entropy: SEED.as_ptr(),
            entropy_len: SEED.len(),
            media_seed: MEDIA_SEED.as_ptr(),
            media_seed_len: MEDIA_SEED.len(),
            timer_t1_ms: 0,
            timer_t2_ms: 0,
            timer_t4_ms: 0,
            audio: 0,
            audio_activation: 0,
            audio_transmit_callback: None,
            audio_transmit_user_data: ptr::null_mut(),
            audio_probe_ms: 0,
            audio_device_rate_hz: 0,
            stun_fallbacks: ptr::null(),
            stun_fallbacks_len: 0,
            codecs: ptr::null(),
            codecs_len: 0,
            frame_ms: 0,
            offer_dtmf: 0,
            offer_rtcp_mux: 0,
            silence_suppression: 0,
            media_stall_watchdog: 0,
            media_stall_ms: 0,
            media_clock_unix_seconds: 0,
            srtp: 0,
            ice: 0,
            nat: 0,
            stun_server: ptr::null(),
            stun_server_len: 0,
            g729_annex_b: 0,
            turn_server: ptr::null(),
            turn_server_len: 0,
            turn_username: ptr::null(),
            turn_username_len: 0,
            turn_password: ptr::null(),
            turn_password_len: 0,
            referrals: 0,
            registrar_keepalive: 0,
            registrar_keepalive_ms: 0,
            turn_transport: 0,
            max_dialogs: 0,
            max_server_transactions: 0,
            diagnostic_decisions: 0,
            diagnostic_records: 0,
            rtp_port_min: 0,
            rtp_port_max: 0,
            srtp_suites: ptr::null(),
            srtp_suites_len: 0,
            path_mtu: 0,
            datagram_without_stream_bytes: 0,
            pseudonym_salt: ptr::null(),
            pseudonym_salt_len: 0,
            diagnostic_trace: 0,
            reserved: 0,
            dtmf_detection: 0,
        }
    }

    pub(crate) fn create(config: &SipralStackConfig) -> (SipralStatus, SipralHandle) {
        let mut handle = SIPRAL_HANDLE_NONE;
        let status = unsafe { sipral_stack_create(ptr::from_ref(config), &raw mut handle) };
        (status, handle)
    }

    /// A stack with a callback that only writes down what it was given.
    pub(crate) fn stack(observed: &mut Observed) -> SipralHandle {
        let config = config(record, observed);
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::Ok);
        handle
    }

    /// Create a stack with its tag drawn from a set the test holds, answered
    /// the way C is: a status, and the sentence in the last error.
    pub(crate) fn create_with(
        tags: &'static StackTags,
        config: &SipralStackConfig,
    ) -> (SipralStatus, SipralHandle) {
        let mut handle = SIPRAL_HANDLE_NONE;
        let status = guard(|| {
            handle = unsafe { create_on(tags, ptr::from_ref(config)) }?;
            Ok(())
        });
        (status, handle)
    }

    /// The same as [`stack`], on a set of tags the test holds.
    pub(crate) fn stack_on(tags: &'static StackTags, observed: &mut Observed) -> SipralHandle {
        let config = config(record, observed);
        let (status, handle) = create_with(tags, &config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        handle
    }

    fn tag_of(handle: SipralHandle) -> u8 {
        split(handle).expect("a handle").tag
    }

    pub(crate) fn poll_result() -> SipralPollResult {
        SipralPollResult {
            size: size_of::<SipralPollResult>(),
            events_delivered: usize::MAX,
            events_unclaimed: usize::MAX,
            transmits_discarded: usize::MAX,
            has_deadline: u32::MAX,
            next_poll_in_ms: u64::MAX,
        }
    }

    /// Poll, and hand back what it counted.
    pub(crate) fn poll(handle: SipralHandle, now_ms: u64) -> SipralPollResult {
        let mut result = poll_result();
        let status = unsafe { sipral_stack_poll(handle, now_ms, &raw mut result) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        result
    }

    #[test]
    fn a_stack_is_created_and_destroyed() {
        let mut observed = Observed::default();
        let (status, handle) = create(&config(record, &mut observed));
        assert_eq!(status, SipralStatus::Ok);
        assert_ne!(handle, SIPRAL_HANDLE_NONE);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_null_config_is_a_bad_argument() {
        let mut handle = SIPRAL_HANDLE_NONE;
        let status = unsafe { sipral_stack_create(ptr::null(), &raw mut handle) };
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(handle, SIPRAL_HANDLE_NONE, "nothing was written");
    }

    #[test]
    fn a_null_out_parameter_is_a_bad_argument() {
        let mut observed = Observed::default();
        let config = config(record, &mut observed);
        let status = unsafe { sipral_stack_create(ptr::from_ref(&config), ptr::null_mut()) };
        assert_eq!(status, SipralStatus::InvalidArgument);
    }

    #[test]
    fn a_config_that_declares_the_wrong_size_is_refused() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        // below the pinned minimum rather than `size_of::<SipralStackConfig>() -
        // 1`: once the struct grows past that minimum, a size one short of
        // the *current* build is a perfectly good caller compiled against an
        // older header, not the wrong size this test means
        config.size = <SipralStackConfig as crate::versioned::Versioned>::MIN_SIZE - 1;
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::UnsupportedVersion);
        assert_eq!(handle, SIPRAL_HANDLE_NONE);

        config.size = 0;
        let (status, _) = create(&config);
        assert_eq!(status, SipralStatus::UnsupportedVersion);
    }

    /// A `sipral_stack_config_t` that ends where the first header's did,
    /// before `srtp`, comes from an ABI before the freeze. `ice`, `audio` and
    /// `max_dialogs` were each appended in the tail padding of a length a
    /// caller of that time declared, so they would be read from whatever that
    /// caller's stack held there; the struct is refused instead.
    #[test]
    fn a_config_from_before_the_freeze_is_refused() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        config.size = std::mem::offset_of!(SipralStackConfig, srtp);
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::UnsupportedVersion);
        assert_eq!(handle, SIPRAL_HANDLE_NONE);
    }

    #[test]
    fn a_config_from_a_newer_header_is_taken_as_far_as_this_build_knows() {
        #[repr(C)]
        struct Newer {
            head: SipralStackConfig,
            added: u64,
        }
        let mut observed = Observed::default();
        let mut newer = Newer {
            head: config(record, &mut observed),
            added: 0,
        };
        newer.head.size = size_of::<Newer>();
        let mut handle = SIPRAL_HANDLE_NONE;
        let status = unsafe {
            sipral_stack_create(
                (&raw const newer).cast::<SipralStackConfig>(),
                &raw mut handle,
            )
        };
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

        newer.added = 1;
        let status = unsafe {
            sipral_stack_create(
                (&raw const newer).cast::<SipralStackConfig>(),
                &raw mut handle,
            )
        };
        assert_eq!(
            status,
            SipralStatus::NotSupported,
            "a member this build would ignore is not ignored quietly, and the answer is about \
             the member rather than about the size, which is a shape this build works with"
        );
    }

    fn settings() -> SipralStackSettings {
        SipralStackSettings {
            size: size_of::<SipralStackSettings>(),
            transport: u32::MAX,
            retransmits: u32::MAX,
            timer_t1_ms: u64::MAX,
            timer_t2_ms: u64::MAX,
            timer_t4_ms: u64::MAX,
            codec_count: usize::MAX,
            frame_ms: u32::MAX,
            offer_dtmf: u32::MAX,
            offer_rtcp_mux: u32::MAX,
            silence_suppression: u32::MAX,
            media_stall_ms: u64::MAX,
            g729_annex_b: u32::MAX,
            referrals: u32::MAX,
            registrar_keepalive_ms: u64::MAX,
            max_dialogs: u32::MAX,
            max_server_transactions: u32::MAX,
            diagnostic_decisions: u32::MAX,
            diagnostic_records: u32::MAX,
            rtp_port_min: u32::MAX,
            rtp_port_max: u32::MAX,
            path_mtu: u32::MAX,
            datagram_without_stream_bytes: u32::MAX,
        }
    }

    fn read_settings(handle: SipralHandle) -> SipralStackSettings {
        let mut out = settings();
        let status = unsafe { sipral_stack_settings(handle, &raw mut out) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        out
    }

    #[test]
    fn a_stack_reads_back_the_figures_it_is_running_on() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let read = read_settings(handle);
        assert_eq!(read.size, size_of::<SipralStackSettings>());
        assert_eq!(read.transport, SipralTransport::Udp as u32);
        assert_eq!(read.retransmits, 1);
        assert_eq!(read.timer_t1_ms, 500, "the default, not the zero given");
        assert_eq!(read.timer_t2_ms, 4_000);
        assert_eq!(read.timer_t4_ms, 5_000);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The two figures §18.1.1's line is drawn from read back as given, and
    /// one no path or datagram could have is refused.
    #[test]
    fn the_datagram_figures_read_back_as_given_and_impossible_ones_are_refused() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let read = read_settings(handle);
        assert_eq!((read.path_mtu, read.datagram_without_stream_bytes), (0, 0));
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

        let mut observed = Observed::default();
        let mut given = config(record, &mut observed);
        given.path_mtu = 1_500;
        given.datagram_without_stream_bytes = 1_800;
        let (status, handle) = create(&given);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let read = read_settings(handle);
        assert_eq!(
            (read.path_mtu, read.datagram_without_stream_bytes),
            (1_500, 1_800)
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

        for (mtu, without) in [(575, 0), (0, 65_508)] {
            let mut observed = Observed::default();
            let mut wrong = config(record, &mut observed);
            wrong.path_mtu = mtu;
            wrong.datagram_without_stream_bytes = without;
            assert_eq!(
                create(&wrong).0,
                SipralStatus::InvalidArgument,
                "{mtu} {without}"
            );
        }
    }

    /// The suites a stack names are the ones every call of it offers, in
    /// that order; a suite this library does not run is refused.
    #[test]
    fn the_stack_srtp_suites_are_what_its_calls_offer() {
        let suites = "AES_256_CM_HMAC_SHA1_80,AES_CM_128_HMAC_SHA1_80";
        let mut observed = Observed::default();
        let (handle, account) = crate::call::tests::media_line(&mut observed, |config| {
            config.srtp = crate::media::SipralSrtp::Offered as u32;
            config.srtp_suites = suites.as_ptr().cast();
            config.srtp_suites_len = suites.len();
        });
        let (status, _) =
            crate::call::tests::place(handle, account, &crate::call::tests::managed_config(), 0);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = String::from_utf8(crate::call::tests::one(handle)).expect("UTF-8");
        let offered: Vec<&str> = invite
            .lines()
            .filter_map(|line| line.strip_prefix("a=crypto:"))
            .map(|line| line.split(' ').nth(1).unwrap_or(""))
            .collect();
        assert_eq!(
            offered,
            ["AES_256_CM_HMAC_SHA1_80", "AES_CM_128_HMAC_SHA1_80"]
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

        let mut observed = Observed::default();
        let mut wrong = config(record, &mut observed);
        let unknown = "AES_CM_128_HMAC_SHA1_80,NULL_HMAC_SHA1_80";
        wrong.srtp_suites = unknown.as_ptr().cast();
        wrong.srtp_suites_len = unknown.len();
        assert_eq!(create(&wrong).0, SipralStatus::InvalidArgument);
        assert!(
            last_error_text().contains("srtp_suites"),
            "{}",
            last_error_text()
        );
    }

    /// Best effort offers SDES on the plain profile, which a server that
    /// does no SRTP takes rather than refuses.
    #[test]
    fn best_effort_offers_its_keys_on_the_plain_profile() {
        let mut observed = Observed::default();
        let (handle, account) = crate::call::tests::media_line(&mut observed, |config| {
            config.srtp = crate::media::SipralSrtp::BestEffort as u32;
        });
        let (status, _) =
            crate::call::tests::place(handle, account, &crate::call::tests::managed_config(), 0);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = String::from_utf8(crate::call::tests::one(handle)).expect("UTF-8");
        assert!(invite.contains(" RTP/AVP "), "{invite}");
        assert!(invite.contains("a=crypto:"), "{invite}");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A REFER outside any dialog reaches nobody unless the stack was made
    /// to take them, and the setting reads back as what it came to.
    #[test]
    fn referrals_are_off_unless_asked_for_and_read_back_as_they_came_to() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(read_settings(handle).referrals, SipralToggle::Off as u32);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

        let mut observed = Observed::default();
        let mut on = config(record, &mut observed);
        on.referrals = SipralToggle::On as u32;
        let (status, handle) = create(&on);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(read_settings(handle).referrals, SipralToggle::On as u32);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

        let mut observed = Observed::default();
        let mut wrong = config(record, &mut observed);
        wrong.referrals = 3;
        assert_eq!(create(&wrong).0, SipralStatus::InvalidArgument);
    }

    /// The registrar keep-alive is on at twenty-five seconds unless told
    /// otherwise, an interval of the caller's own is taken and read back, off
    /// reads back as zero, and a figure out of range or given with it off is
    /// refused.
    #[test]
    fn the_registrar_keepalive_is_on_by_default_and_reads_back_as_it_came_to() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(read_settings(handle).registrar_keepalive_ms, 25_000);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

        let mut observed = Observed::default();
        let mut every = config(record, &mut observed);
        every.registrar_keepalive_ms = 15_000;
        let (status, handle) = create(&every);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(read_settings(handle).registrar_keepalive_ms, 15_000);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

        let mut observed = Observed::default();
        let mut off = config(record, &mut observed);
        off.registrar_keepalive = SipralToggle::Off as u32;
        let (status, handle) = create(&off);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(read_settings(handle).registrar_keepalive_ms, 0);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

        for (toggle, millis) in [
            (SipralToggle::Off as u32, 25_000),
            (0, 999),
            (0, 120_001),
            (3, 0),
        ] {
            let mut observed = Observed::default();
            let mut wrong = config(record, &mut observed);
            wrong.registrar_keepalive = toggle;
            wrong.registrar_keepalive_ms = millis;
            assert_eq!(
                create(&wrong).0,
                SipralStatus::InvalidArgument,
                "{toggle} {millis}"
            );
        }
    }

    /// The four ceilings read back as the defaults when left at zero, and as
    /// what was given otherwise.
    #[test]
    fn the_limits_read_back_as_they_came_to() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let read = read_settings(handle);
        assert_eq!(read.max_dialogs, 128);
        assert_eq!(read.max_server_transactions, 256);
        assert_eq!(read.diagnostic_decisions, 64);
        assert_eq!(read.diagnostic_records, 32);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

        let mut observed = Observed::default();
        let mut raised = config(record, &mut observed);
        raised.max_dialogs = 10_000;
        raised.max_server_transactions = 20_000;
        raised.diagnostic_decisions = 8;
        raised.diagnostic_records = 4;
        let (status, handle) = create(&raised);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let read = read_settings(handle);
        assert_eq!(read.max_dialogs, 10_000);
        assert_eq!(read.max_server_transactions, 20_000);
        assert_eq!(read.diagnostic_decisions, 8);
        assert_eq!(read.diagnostic_records, 4);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_timer_that_was_set_reads_back_as_the_one_that_was_set() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        config.timer_t1_ms = 1_200;
        config.timer_t2_ms = 9_000;
        config.timer_t4_ms = 7_000;
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let read = read_settings(handle);
        assert_eq!(read.timer_t1_ms, 1_200);
        assert_eq!(read.timer_t2_ms, 9_000);
        assert_eq!(read.timer_t4_ms, 7_000);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// B2: a setting that a neighbouring value has disabled is refused where it
    /// is set. T2 caps a retransmission interval and T4 waits one out, and RFC
    /// 3261 §17 arms neither on a transport that delivers for us — so on
    /// anything but UDP both would be values nothing ever reads.
    #[test]
    fn a_timer_the_transport_never_arms_is_refused_rather_than_taken_and_ignored() {
        let stream = [
            SipralTransport::Tcp,
            SipralTransport::Tls,
            SipralTransport::Ws,
            SipralTransport::Wss,
        ];
        let idle: [Setting; 2] = [
            ("timer_t2_ms", |config| config.timer_t2_ms = 6_000),
            ("timer_t4_ms", |config| config.timer_t4_ms = 6_000),
        ];
        for protocol in stream {
            for (which, set) in idle {
                let mut observed = Observed::default();
                let mut config = config(record, &mut observed);
                config.transport = protocol as u32;
                set(&mut config);
                let (status, handle) = create(&config);
                assert_eq!(
                    status,
                    SipralStatus::InvalidArgument,
                    "{which} on {protocol:?} was taken"
                );
                assert_eq!(handle, SIPRAL_HANDLE_NONE);
                let message = last_error_text();
                assert!(
                    message.contains(which) && message.contains(protocol.protocol().as_str()),
                    "the message names neither the setting nor the transport: {message}"
                );
            }
        }
    }

    #[test]
    fn the_same_timers_are_taken_on_the_transport_that_does_arm_them() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        config.transport = SipralTransport::Udp as u32;
        config.timer_t2_ms = 6_000;
        config.timer_t4_ms = 6_000;
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_stack_that_retransmits_nothing_says_so_rather_than_leaving_it_to_be_inferred() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        config.transport = SipralTransport::Tls as u32;
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::Ok);
        let read = read_settings(handle);
        assert_eq!(read.transport, SipralTransport::Tls as u32);
        assert_eq!(read.retransmits, 0);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The other half of the same requirement: T1 is the interval T2 caps, so a
    /// T2 below it is a T1 that is discarded at the first retransmission.
    #[test]
    fn a_cap_below_the_interval_it_caps_is_refused() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        config.timer_t1_ms = 2_000;
        config.timer_t2_ms = 1_000;
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(handle, SIPRAL_HANDLE_NONE);
        let message = last_error_text();
        assert!(
            message.contains("2000") && message.contains("1000"),
            "the message names neither figure: {message}"
        );

        config.timer_t2_ms = 2_000;
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::Ok, "a cap it just reaches is a cap");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A T1 raised past the default T2 is the same mistake made by leaving the
    /// other value alone, and it is caught for the same reason.
    #[test]
    fn a_t1_raised_past_a_default_t2_is_caught_too() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        config.timer_t1_ms = 5_000;
        assert_eq!(create(&config).0, SipralStatus::InvalidArgument);
    }

    /// The media half of the same promise: a call that answered
    /// `SIPRAL_STATUS_OK` applied what it was given, and this is where the
    /// caller reads what that came to. The three settings that are booleans
    /// read back as on or off, never as the zero that means "nothing was said".
    #[test]
    fn a_stack_reads_back_the_media_settings_it_is_running_on() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let read = read_settings(handle);
        assert_eq!(
            read.codec_count,
            Codec::ALL
                .iter()
                .filter(|codec| codec.offered_by_default())
                .count(),
            "everything this build offers when nothing was named: all it \
             contains but G.729"
        );
        assert_eq!(read.frame_ms, 20, "the default, not the zero given");
        assert_eq!(read.offer_dtmf, SipralToggle::On as u32);
        assert_eq!(read.offer_rtcp_mux, SipralToggle::Off as u32);
        assert_eq!(read.silence_suppression, SipralToggle::Off as u32);
        assert_eq!(read.media_stall_ms, 10_000, "the default watchdog");
        assert_eq!(
            read.g729_annex_b,
            SipralToggle::On as u32,
            "RFC 4856 §2.1.9: G729 with no parameter allows Annex B"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_media_setting_that_was_set_reads_back_as_the_one_that_was_set() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        let codecs = "PCMA,PCMU";
        config.codecs = codecs.as_ptr().cast::<c_char>();
        config.codecs_len = codecs.len();
        config.frame_ms = 30;
        config.offer_dtmf = SipralToggle::Off as u32;
        config.offer_rtcp_mux = SipralToggle::On as u32;
        config.silence_suppression = SipralToggle::On as u32;
        config.media_stall_ms = 2_500;
        config.g729_annex_b = SipralToggle::Off as u32;
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let read = read_settings(handle);
        assert_eq!(read.codec_count, 2);
        assert_eq!(read.frame_ms, 30);
        assert_eq!(read.offer_dtmf, SipralToggle::Off as u32);
        assert_eq!(read.offer_rtcp_mux, SipralToggle::On as u32);
        assert_eq!(read.silence_suppression, SipralToggle::On as u32);
        assert_eq!(read.media_stall_ms, 2_500);
        assert_eq!(read.g729_annex_b, SipralToggle::Off as u32);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A4's rule at the boundary a caller actually crosses: a codec this build
    /// cannot encode is refused at creation, with the status that means the
    /// build is missing something rather than the one that means try again.
    #[test]
    fn a_codec_this_build_cannot_encode_stops_the_stack_from_being_made() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        let absent = "PCMU,G723";
        config.codecs = absent.as_ptr().cast::<c_char>();
        config.codecs_len = absent.len();
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::NotSupported);
        assert_eq!(handle, SIPRAL_HANDLE_NONE);
        let message = last_error_text();
        assert!(
            message.contains("G723") && message.contains("PCMA"),
            "the message names neither what was asked for nor what there is: {message}"
        );
    }

    #[test]
    fn every_named_srtp_value_is_taken_and_anything_else_builds_nothing() {
        let handshake = [
            crate::media::SipralSrtp::Dtls as u32,
            crate::media::SipralSrtp::DtlsRequired as u32,
            crate::media::SipralSrtp::DtlsOrSdes as u32,
        ];
        let mut taken = vec![
            0,
            crate::media::SipralSrtp::NotOffered as u32,
            crate::media::SipralSrtp::Offered as u32,
            crate::media::SipralSrtp::Required as u32,
            crate::media::SipralSrtp::BestEffort as u32,
        ];
        if cfg!(feature = "dtls") {
            taken.extend(handshake);
        }
        for value in taken {
            let mut observed = Observed::default();
            let mut config = config(record, &mut observed);
            config.srtp = value;
            let (status, handle) = create(&config);
            assert_eq!(status, SipralStatus::Ok, "{value}: {}", last_error_text());
            assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        }

        // a build without the handshake refuses every value that names it,
        // rather than build a stack that places the calls in the clear
        for value in handshake.into_iter().filter(|_| !cfg!(feature = "dtls")) {
            let mut observed = Observed::default();
            let mut config = config(record, &mut observed);
            config.srtp = value;
            let (status, handle) = create(&config);
            assert_eq!(status, SipralStatus::NotSupported, "{value}");
            assert_eq!(handle, SIPRAL_HANDLE_NONE, "{value}: nothing was built");
        }

        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        config.srtp = 8;
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(handle, SIPRAL_HANDLE_NONE, "nothing was built");
    }

    #[test]
    fn a_watchdog_that_is_switched_off_leaves_no_threshold_to_read_back() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        config.media_stall_watchdog = SipralToggle::Off as u32;
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(read_settings(handle).media_stall_ms, 0);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn the_settings_of_a_stack_that_is_gone_cannot_be_read() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        let mut out = settings();
        assert_eq!(
            unsafe { sipral_stack_settings(handle, &raw mut out) },
            SipralStatus::StaleHandle
        );
        assert_eq!(out.transport, u32::MAX, "nothing was written");
    }

    #[test]
    fn a_settings_struct_that_is_null_or_the_wrong_size_is_refused() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(
            unsafe { sipral_stack_settings(handle, ptr::null_mut()) },
            SipralStatus::InvalidArgument
        );
        // shorter than the first published length: no header ever declared
        // one this short, so it is no version of the struct at all
        let mut out = settings();
        out.size = <crate::stack::SipralStackSettings as crate::versioned::Versioned>::MIN_SIZE - 1;
        assert_eq!(
            unsafe { sipral_stack_settings(handle, &raw mut out) },
            SipralStatus::UnsupportedVersion
        );
        assert_eq!(out.transport, u32::MAX, "nothing was written");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The size is checked before the handle is even looked up: a stack that
    /// was never created and a settings struct too short to be any version of
    /// this one both fail, and the size is the one this answers with.
    #[test]
    fn a_settings_struct_shorter_than_its_min_size_is_unsupported_version_even_for_an_invalid_handle()
     {
        let mut out = settings();
        out.size = <crate::stack::SipralStackSettings as crate::versioned::Versioned>::MIN_SIZE - 1;
        assert_eq!(
            unsafe { sipral_stack_settings(SIPRAL_HANDLE_NONE, &raw mut out) },
            SipralStatus::UnsupportedVersion
        );
    }

    #[test]
    fn a_stack_without_a_callback_is_refused() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        config.event_callback = None;
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(handle, SIPRAL_HANDLE_NONE);
    }

    #[test]
    fn a_stack_that_was_not_told_its_transport_is_refused() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        config.transport = 0;
        assert_eq!(create(&config).0, SipralStatus::InvalidArgument);
        config.transport = 99;
        assert_eq!(create(&config).0, SipralStatus::InvalidArgument);
    }

    #[test]
    fn every_transport_this_library_names_is_one_it_takes() {
        let all = [
            SipralTransport::Udp,
            SipralTransport::Tcp,
            SipralTransport::Tls,
            SipralTransport::Ws,
            SipralTransport::Wss,
        ];
        for protocol in all {
            let mut observed = Observed::default();
            let mut config = config(record, &mut observed);
            config.transport = protocol as u32;
            let (status, handle) = create(&config);
            assert_eq!(status, SipralStatus::Ok, "{protocol:?}");
            assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        }
    }

    #[test]
    fn an_address_that_is_not_one_is_refused_and_says_what_it_was_given() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        let nonsense = "example.com";
        config.bind_address = nonsense.as_ptr().cast::<c_char>();
        config.bind_address_len = nonsense.len();
        assert_eq!(create(&config).0, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("example.com"));

        config.bind_address = ptr::null();
        config.bind_address_len = 0;
        assert_eq!(create(&config).0, SipralStatus::InvalidArgument);
    }

    #[test]
    fn an_ipv6_address_is_an_address() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        let bind = "[2001:db8::1]:5060";
        config.bind_address = bind.as_ptr().cast::<c_char>();
        config.bind_address_len = bind.len();
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_stack_with_the_wrong_amount_of_entropy_is_refused() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        config.entropy_len = 31;
        assert_eq!(create(&config).0, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("31"));

        config.entropy = ptr::null();
        config.entropy_len = 0;
        assert_eq!(create(&config).0, SipralStatus::InvalidArgument);
    }

    /// RFC 3261 §8.1.1.7 (Via) only requires the branch parameter to be
    /// unique across space and time; the "cryptographically random"
    /// requirement the entropy field's doc leans on is §19.3, Tags. The
    /// needle is assembled at runtime so this test does not just match its
    /// own assertion.
    #[test]
    fn the_entropy_doc_cites_tags_not_via_for_unguessability() {
        // the needle spans a line break, and a Windows checkout puts a CR in
        // front of it
        let source = include_str!("stack.rs").replace("\r\n", "\n");
        let section = '\u{a7}';
        assert!(
            source.contains(&format!("{section}19.3 wants a tag unguessable")),
            "the cryptographic-randomness requirement is in §19.3, not §8.1.1.7"
        );
    }

    #[test]
    fn a_user_agent_string_that_would_smuggle_a_header_is_refused() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        let hostile = "sipral\r\nContact: <sip:elsewhere@example.net>";
        config.user_agent = hostile.as_ptr().cast::<c_char>();
        config.user_agent_len = hostile.len();
        assert_eq!(create(&config).0, SipralStatus::InvalidArgument);
    }

    #[test]
    fn the_first_poll_says_the_stack_is_running_and_the_second_says_nothing() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);

        let result = poll(handle, 1_000);
        assert_eq!(result.events_delivered, 1);
        assert_eq!(result.size, size_of::<SipralPollResult>());

        let result = poll(handle, 1_001);
        assert_eq!(result.events_delivered, 0);

        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        assert_eq!(
            observed.events,
            vec![(handle, SipralEventKind::Started, size_of::<SipralEvent>())]
        );
    }

    #[test]
    fn a_stack_with_nothing_to_do_has_no_deadline() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let result = poll(handle, 0);
        assert_eq!(result.has_deadline, 0);
        assert_eq!(result.next_poll_in_ms, 0);
        assert_eq!(result.transmits_discarded, 0);
        assert_eq!(result.events_unclaimed, 0);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn poll_takes_a_null_result_from_a_caller_that_does_not_want_the_count() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 0, ptr::null_mut()) },
            SipralStatus::Ok
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        assert_eq!(observed.events.len(), 1);
    }

    #[test]
    fn a_result_struct_of_the_wrong_size_costs_no_events() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);

        let mut result = poll_result();
        result.size = size_of::<SipralPollResult>() - 1;
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 0, &raw mut result) },
            SipralStatus::UnsupportedVersion
        );
        assert!(observed.events.is_empty(), "nothing was delivered");

        let result = poll(handle, 0);
        assert_eq!(result.events_delivered, 1, "the event was still waiting");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The size is checked before the handle is even looked up: a stack that
    /// was never created and a result struct too short to be any version of
    /// this one both fail, and the size is the one this answers with.
    #[test]
    fn a_result_struct_shorter_than_its_min_size_is_unsupported_version_even_for_an_invalid_handle()
    {
        let mut result = poll_result();
        result.size = <crate::stack::SipralPollResult as crate::versioned::Versioned>::MIN_SIZE - 1;
        assert_eq!(
            unsafe { sipral_stack_poll(SIPRAL_HANDLE_NONE, 0, &raw mut result) },
            SipralStatus::UnsupportedVersion
        );
    }

    #[test]
    fn fifty_ms_behind_is_accepted_and_fifty_one_is_refused_and_says_by_how_much() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 5_000, ptr::null_mut()) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 4_950, ptr::null_mut()) },
            SipralStatus::Ok,
            "fifty milliseconds behind is two threads reading one clock, not a caller bug"
        );
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 4_949, ptr::null_mut()) },
            SipralStatus::ClockBehind,
            "fifty-one milliseconds behind is"
        );
        let message = last_error_text();
        assert!(
            message.contains("4949") && message.contains("5000"),
            "the message names neither instant: {message}"
        );
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 5_000, ptr::null_mut()) },
            SipralStatus::Ok,
            "the accepted reading behind it did not drag the watermark down"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The failure this guards against: `sipral_stack_poll` used to advance
    /// the clock before checking `result`'s declared size, so a caller with a
    /// too-short struct lost the clock along with the call.
    #[test]
    fn a_call_refused_for_a_bad_argument_leaves_the_clock_where_it_was() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(poll(handle, 1_000).events_delivered, 1);

        // no call was ever minted with this handle: refused for a reason that
        // has nothing to do with the clock, at a now_ms far ahead of the last
        // one this stack saw
        assert_eq!(
            unsafe { crate::call::sipral_call_hangup(handle, SIPRAL_HANDLE_NONE, 9_000) },
            SipralStatus::InvalidHandle
        );

        // had the refused call moved the clock to 9_000 anyway, this would
        // now be more than the slack behind it and refused for that instead
        assert_eq!(
            poll(handle, 1_010).events_delivered,
            0,
            "{}",
            last_error_text()
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_clock_as_far_ahead_as_it_counts_is_answered_rather_than_overflowing() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        // adding half a billion years to an instant is a panic on a platform
        // whose clock is narrow enough, and a panic here would be a status
        // code the caller cannot recover from
        let status = unsafe { sipral_stack_poll(handle, u64::MAX, ptr::null_mut()) };
        assert!(
            status == SipralStatus::Ok || status == SipralStatus::InvalidArgument,
            "an instant that far ahead answered {status:?}"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn polling_a_stack_that_was_never_created_is_an_invalid_handle() {
        assert_eq!(
            unsafe { sipral_stack_poll(SIPRAL_HANDLE_NONE, 0, ptr::null_mut()) },
            SipralStatus::InvalidHandle
        );
        assert_eq!(
            unsafe { sipral_stack_destroy(SIPRAL_HANDLE_NONE) },
            SipralStatus::InvalidHandle
        );
    }

    #[test]
    fn polling_a_destroyed_stack_is_a_stale_handle() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 0, ptr::null_mut()) },
            SipralStatus::StaleHandle
        );
        assert!(observed.events.is_empty());
    }

    #[test]
    fn destroying_a_stack_twice_is_a_stale_handle() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        assert_eq!(
            unsafe { sipral_stack_destroy(handle) },
            SipralStatus::StaleHandle
        );
    }

    /// Nothing is held while the callback runs, so calling back into the
    /// stack from inside it is an ordinary call: neither refused nor a
    /// deadlock.
    #[test]
    fn calling_back_into_a_stack_from_its_own_callback_is_an_ordinary_call() {
        let mut observed = Observed::default();
        let (status, handle) = create(&config(poll_again, &mut observed));
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 0, ptr::null_mut()) },
            SipralStatus::Ok
        );
        assert_eq!(
            observed.reentrant_status,
            Some(SipralStatus::Ok),
            "the poll made from inside the callback was refused: {}",
            last_error_text()
        );
        assert!(
            last_error_text().is_empty(),
            "both polls succeeded, so nothing is this thread's last error"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// The half of the promise a binding author will actually hit: any thread
    /// may call, one at a time, and the one that arrives while another is
    /// inside gets a status rather than a wait, a deadlock or a fault.
    #[test]
    fn a_second_thread_calling_in_while_the_stack_is_held_is_told_so() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let refused =
            super::with_stack(handle, |_| {
                // the stack is held for as long as this runs, which is the whole
                // of the window its lock is still held for
                Ok(std::thread::spawn(move || unsafe {
                    sipral_stack_poll(handle, 0, ptr::null_mut())
                })
                .join()
                .expect("the thread finished"))
            })
            .expect("the stack is live");
        assert_eq!(refused, SipralStatus::Busy);
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 0, ptr::null_mut()) },
            SipralStatus::Ok,
            "and the stack is free again once the first call is done"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// While the callback runs the stack is not held, so a second thread that
    /// polls at that moment is not refused either.
    #[test]
    fn a_second_thread_polling_while_the_callback_runs_is_not_refused() {
        let mut observed = Observed::default();
        let (status, handle) = create(&config(poll_from_another_thread, &mut observed));
        assert_eq!(status, SipralStatus::Ok);
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 0, ptr::null_mut()) },
            SipralStatus::Ok
        );
        assert_eq!(observed.reentrant_status, Some(SipralStatus::Ok));
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// What a callback that polls from inside itself saw. Cells, because the
    /// callback may be entered again while an earlier call of it is still
    /// running, and two mutable borrows of one value would be a test that is
    /// unsound in exactly the case it exists to catch.
    #[derive(Default)]
    struct Nested {
        depth: Cell<usize>,
        deepest: Cell<usize>,
        account: Cell<SipralHandle>,
        kinds: RefCell<Vec<SipralEventKind>>,
        registered: Cell<Option<SipralStatus>>,
        inner: Cell<Option<(SipralStatus, usize)>>,
    }

    /// On the first event, register an account — which raises an event of its
    /// own on the next poll — and poll again from inside the callback.
    unsafe extern "C" fn register_and_poll_from_inside(
        event: *const SipralEvent,
        user_data: *mut c_void,
    ) {
        let nested = unsafe { &*user_data.cast::<Nested>() };
        let event = unsafe { &*event };
        nested.depth.set(nested.depth.get().saturating_add(1));
        nested
            .deepest
            .set(nested.deepest.get().max(nested.depth.get()));
        nested.kinds.borrow_mut().push(event.kind);
        if event.kind == SipralEventKind::Started {
            nested.registered.set(Some(unsafe {
                crate::account::sipral_account_register(event.stack, nested.account.get(), 0)
            }));
            let mut inner = poll_result();
            let status = unsafe { sipral_stack_poll(event.stack, 0, &raw mut inner) };
            nested.inner.set(Some((status, inner.events_delivered)));
        }
        nested.depth.set(nested.depth.get().saturating_sub(1));
    }

    /// A poll from inside the callback does the stack's work and leaves what
    /// it raised to the delivery already under way, which now means the
    /// *next* pass rather than the rest of this one (task 8.4.21): delivered
    /// into this one instead, the new event would reach the callback before
    /// the one it is still handling had returned, and there is no bound left
    /// on how long this pass could keep finding one more thing to deliver.
    #[test]
    fn what_a_poll_from_inside_the_callback_raises_waits_for_the_next_pass() {
        let mut observed = Observed::default();
        let nested = Nested::default();
        let (handle, account) = crate::call::tests::media_line(&mut observed, |config| {
            config.event_callback = Some(register_and_poll_from_inside);
            config.event_user_data = ptr::from_ref(&nested).cast_mut().cast::<c_void>();
        });
        nested.account.set(account);

        let result = poll(handle, 0);
        assert_eq!(nested.registered.get(), Some(SipralStatus::Ok));
        assert_eq!(
            nested.inner.get(),
            Some((SipralStatus::Ok, 0)),
            "the inner poll delivered nothing of its own: the outer pass was already delivering"
        );
        assert_eq!(
            nested.deepest.get(),
            1,
            "the callback was entered again before it had returned"
        );
        assert_eq!(
            *nested.kinds.borrow(),
            [SipralEventKind::Started],
            "the pass already under way delivers only what it began with"
        );
        assert_eq!(
            result.events_delivered, 1,
            "what the inner poll raised was left queued, not folded into this pass"
        );

        // the next poll on this stack raises nothing of its own and is still
        // the one that notices the registration change left waiting
        let result = poll(handle, 1);
        assert_eq!(
            *nested.kinds.borrow(),
            [
                SipralEventKind::Started,
                SipralEventKind::RegistrationChanged
            ]
        );
        assert_eq!(result.events_delivered, 1);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A pass that returns with events still queued behind it says the next
    /// poll is already due. Otherwise a caller that waits for input or for the
    /// deadline, which is the loop `crate::transport` spells out, leaves those
    /// events where they are until a datagram or a timer happens to arrive.
    #[test]
    fn a_pass_that_leaves_events_waiting_says_the_next_poll_is_already_due() {
        let mut observed = Observed::default();
        let nested = Nested::default();
        let (handle, account) = crate::call::tests::media_line(&mut observed, |config| {
            config.event_callback = Some(register_and_poll_from_inside);
            config.event_user_data = ptr::from_ref(&nested).cast_mut().cast::<c_void>();
        });
        nested.account.set(account);

        let result = poll(handle, 0);
        assert_eq!(
            result.events_delivered, 1,
            "the registration change was left for the next pass"
        );
        assert_eq!(
            (result.has_deadline, result.next_poll_in_ms),
            (1, 0),
            "an event is waiting, so the next poll is due now"
        );

        let result = poll(handle, 0);
        assert_eq!(result.events_delivered, 1, "and that poll delivers it");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    #[test]
    fn a_stack_destroyed_from_inside_its_own_callback_survives_the_poll() {
        let mut observed = Observed::default();
        let (status, handle) = create(&config(destroy_from_inside, &mut observed));
        assert_eq!(status, SipralStatus::Ok);
        let mut result = poll_result();
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 0, &raw mut result) },
            SipralStatus::Ok
        );
        assert_eq!(observed.destroy_status, Some(SipralStatus::Ok));
        assert_eq!(result.events_delivered, 1);
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 1, ptr::null_mut()) },
            SipralStatus::StaleHandle
        );
        assert_eq!(
            unsafe { sipral_stack_destroy(handle) },
            SipralStatus::StaleHandle
        );
    }

    #[test]
    fn two_stacks_do_not_share_a_thing() {
        let mut first_observed = Observed::default();
        let mut second_observed = Observed::default();
        let first = stack(&mut first_observed);
        let second = stack(&mut second_observed);
        assert_ne!(first, second);

        assert_eq!(
            unsafe { sipral_stack_poll(first, 0, ptr::null_mut()) },
            SipralStatus::Ok
        );
        assert_eq!(unsafe { sipral_stack_destroy(first) }, SipralStatus::Ok);
        assert_eq!(
            unsafe { sipral_stack_poll(second, 0, ptr::null_mut()) },
            SipralStatus::Ok,
            "destroying one stack leaves the other alone"
        );
        assert_eq!(unsafe { sipral_stack_destroy(second) }, SipralStatus::Ok);
        assert_eq!(first_observed.events.len(), 1);
        assert_eq!(second_observed.events.len(), 1);
        assert_eq!(
            first_observed.events.first().map(|event| event.0),
            Some(first)
        );
        assert_eq!(
            second_observed.events.first().map(|event| event.0),
            Some(second)
        );
    }

    #[test]
    fn a_stack_can_be_polled_from_another_thread_than_the_one_that_made_it() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let polled = std::thread::spawn(move || unsafe {
            sipral_stack_poll(handle, 1_000, ptr::null_mut())
        })
        .join()
        .expect("the thread finished");
        assert_eq!(polled, SipralStatus::Ok);
        assert_eq!(
            unsafe { sipral_stack_poll(handle, 900, ptr::null_mut()) },
            SipralStatus::ClockBehind,
            "the clock is the stack's, not the thread's -- a hundred milliseconds is well past \
             the slack two threads reading it are allowed"
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        assert_eq!(observed.events.len(), 1);
    }

    #[test]
    fn the_event_says_which_stack_it_is_about() {
        let mut first_observed = Observed::default();
        let mut second_observed = Observed::default();
        let first = stack(&mut first_observed);
        let second = stack(&mut second_observed);
        assert_eq!(
            unsafe { sipral_stack_poll(second, 0, ptr::null_mut()) },
            SipralStatus::Ok
        );
        assert!(first_observed.events.is_empty());
        assert_eq!(
            second_observed.events,
            vec![(second, SipralEventKind::Started, size_of::<SipralEvent>())]
        );
        assert_eq!(unsafe { sipral_stack_destroy(first) }, SipralStatus::Ok);
        assert_eq!(unsafe { sipral_stack_destroy(second) }, SipralStatus::Ok);
    }

    #[test]
    fn what_the_stack_holds_can_move_between_threads() {
        const fn moves<T: Send>() {}
        moves::<sipral_ua::UserAgent>();
        // every call's session is inside the engine, and `StackState` asserts
        // `Send` for all of it; this is what keeps that assertion honest now
        // that a session is also reached from the threads carrying its audio
        moves::<sipral::MediaEngine>();
    }

    #[test]
    fn a_stack_handle_carries_the_tag_its_stack_mints_with() {
        let mut first_observed = Observed::default();
        let mut second_observed = Observed::default();
        let first = stack(&mut first_observed);
        let second = stack(&mut second_observed);
        assert_ne!(tag_of(first), tag_of(second), "two live stacks share a tag");
        assert_eq!(unsafe { sipral_stack_destroy(first) }, SipralStatus::Ok);
        assert_eq!(unsafe { sipral_stack_destroy(second) }, SipralStatus::Ok);
    }

    #[test]
    fn the_stack_after_the_last_tag_is_refused_until_one_is_destroyed() {
        static FULL: StackTags = StackTags::new();
        let mut observed = Observed::default();
        let config = config(record, &mut observed);
        let mut live: Vec<SipralHandle> = (0..STACK_TAGS)
            .map(|_| {
                let (status, handle) = create_with(&FULL, &config);
                assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
                handle
            })
            .collect();

        let (status, refused) = create_with(&FULL, &config);
        assert_eq!(status, SipralStatus::Exhausted);
        assert_eq!(refused, SIPRAL_HANDLE_NONE, "nothing was written");
        let message = last_error_text();
        assert!(
            message.contains(&STACK_TAGS.to_string()),
            "the message does not say what the limit is: {message}"
        );

        let destroyed = live.swap_remove(7);
        assert_eq!(unsafe { sipral_stack_destroy(destroyed) }, SipralStatus::Ok);
        let (status, again) = create_with(&FULL, &config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(tag_of(again), tag_of(destroyed), "the tag it freed");
        live.push(again);
        for handle in live {
            assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
        }
    }

    /// The tags the test below creates its stacks on, reachable from its
    /// callback.
    static INSIDE: StackTags = StackTags::new();

    unsafe extern "C" fn destroy_then_create_from_inside(
        event: *const SipralEvent,
        user_data: *mut c_void,
    ) {
        let observed = unsafe { &mut *user_data.cast::<Observed>() };
        let event = unsafe { &*event };
        observed.events.push((event.stack, event.kind, event.size));
        observed.destroy_status = Some(unsafe { sipral_stack_destroy(event.stack) });
        let config = config(record, observed);
        observed.created_inside = Some(create_with(&INSIDE, &config));
    }

    /// A stack destroyed from inside its own callback is still being polled,
    /// and that poll can still mint. Its tag stays with it until the poll
    /// returns, so no stack created in the meantime starts below a handle it
    /// has yet to hand out.
    #[test]
    fn a_stack_destroyed_from_inside_its_callback_keeps_its_tag_until_the_poll_returns() {
        let mut observed = Observed::default();
        let config = config(destroy_then_create_from_inside, &mut observed);
        let (status, held) = create_with(&INSIDE, &config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(
            unsafe { sipral_stack_poll(held, 0, ptr::null_mut()) },
            SipralStatus::Ok
        );
        assert_eq!(observed.destroy_status, Some(SipralStatus::Ok));
        let (status, inside) = observed.created_inside.expect("the callback ran");
        assert_eq!(status, SipralStatus::Ok);
        assert_ne!(
            tag_of(inside),
            tag_of(held),
            "the tag was handed on while its stack was still being polled"
        );

        let (status, after) = create_with(&INSIDE, &config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(
            tag_of(after),
            tag_of(held),
            "the tag came back once the poll returned"
        );
        assert_eq!(unsafe { sipral_stack_destroy(inside) }, SipralStatus::Ok);
        assert_eq!(unsafe { sipral_stack_destroy(after) }, SipralStatus::Ok);
    }

    // -- the outbox ceiling, and one bounded delivery pass (task 8.4.21) -----

    /// A poll that finds the outbox already at its ceiling — standing in for
    /// one behind a callback that has not returned — drops what it raised
    /// instead of growing the queue, and says so where `sipral_stack_counters`
    /// reads it.
    #[test]
    fn a_poll_that_finds_the_outbox_at_the_ceiling_drops_its_own_event_and_counts_it() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let entry = entry_of(handle).expect("the stack exists");

        // filled directly, bypassing signalling: nothing here has to raise
        // four thousand and ninety-six real events to prove the queue turns
        // the excess away once it is full
        let filler: Vec<Delivery> = (0..OUTBOX_CEILING)
            .map(|_| Delivery::bare(crate::event::started(handle)))
            .collect();
        let (delivering, dropped) = entry.post(filler);
        assert!(delivering, "nobody else was delivering yet");
        assert_eq!(dropped, 0, "exactly the ceiling fits");

        // the first poll a fresh stack ever gets always raises its own
        // "started" event by itself, and that is what has nowhere to go now
        let result = poll(handle, 0);
        assert_eq!(
            result.events_delivered, 0,
            "the pass already under way owns delivery, not this poll"
        );
        let after =
            with_stack(handle, |state| Ok(state.events_dropped)).expect("the stack is live");
        assert_eq!(after, 1, "the poll's own event had no room and was counted");

        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A callback whose body floods the same stack from a second, real
    /// thread — joined before the callback returns, the same shape
    /// `poll_from_another_thread` above uses to make the race deterministic
    /// — and records what that thread's own post reported.
    struct Flooded {
        entry: Arc<StackEntry>,
        stack: SipralHandle,
        dropped: AtomicUsize,
        /// `1` if the flood found nobody delivering and became the deliverer
        /// itself, which would mean it was folded into the pass already under
        /// way rather than left for the next one.
        joined_this_pass: AtomicUsize,
    }

    unsafe extern "C" fn flood_from_another_thread(
        _event: *const SipralEvent,
        user_data: *mut c_void,
    ) {
        let flooded = unsafe { &*user_data.cast::<Flooded>() };
        let entry = Arc::clone(&flooded.entry);
        let flood: Vec<Delivery> = (0..8)
            .map(|_| Delivery::bare(crate::event::started(flooded.stack)))
            .collect();
        let (should_deliver, dropped) = std::thread::spawn(move || entry.post(flood))
            .join()
            .expect("the thread finished");
        flooded.dropped.store(dropped, Ordering::SeqCst);
        flooded
            .joined_this_pass
            .store(usize::from(should_deliver), Ordering::SeqCst);
    }

    /// The fix for the thread that used to be held for as long as other
    /// threads kept posting: a pass hands over only what was there when it
    /// began, and whatever a second thread posts while it runs — even from
    /// inside the very callback this pass is calling — waits for the next
    /// one instead of being folded into this one.
    #[test]
    fn a_delivery_pass_leaves_what_arrives_during_it_for_the_next_pass() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let entry = entry_of(handle).expect("the stack exists");

        // one event to open a pass on
        let (should_deliver, dropped) =
            entry.post(vec![Delivery::bare(crate::event::started(handle))]);
        assert!(should_deliver);
        assert_eq!(dropped, 0);

        let flooded = Flooded {
            entry: Arc::clone(&entry),
            stack: handle,
            dropped: AtomicUsize::new(usize::MAX),
            joined_this_pass: AtomicUsize::new(usize::MAX),
        };
        let speaker = Speaker {
            callback: flood_from_another_thread,
            user_data: ptr::from_ref(&flooded).cast::<c_void>().cast_mut(),
        };
        let (delivered, left_waiting) = entry.deliver(speaker);

        assert_eq!(delivered, 1, "only what was waiting when this pass began");
        assert!(left_waiting, "and it says the flood is still waiting");
        assert_eq!(
            flooded.joined_this_pass.load(Ordering::SeqCst),
            0,
            "the flood found this pass already delivering, and left its events \
             to it rather than becoming a deliverer of its own"
        );
        assert_eq!(
            flooded.dropped.load(Ordering::SeqCst),
            0,
            "eight events is nowhere near the ceiling"
        );

        let outbox = entry.outbox();
        assert_eq!(outbox.waiting.len(), 8, "left for the next pass");
        assert!(
            !outbox.delivering,
            "cleared once this pass returned, so the next poll notices and takes it"
        );
        drop(outbox);

        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }
}
