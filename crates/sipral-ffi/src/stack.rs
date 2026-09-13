// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A stack: made, polled, destroyed — and the rules a binding author will
//! otherwise have to guess.
//!
//! Everything the library has to tell the application arrives on one callback,
//! and the callback runs inside [`sipral_stack_poll`] and nowhere else. That
//! is the whole reason poll exists. A stack that called back from a thread of
//! its own would make every binding reason about which thread it is on, and
//! Swift, .NET and Kotlin each answer that question differently; a stack that
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
//! [`sipral_stack_destroy`] works from inside the callback as it always has.
//! It takes nothing but the handle table, and the poll that is delivering
//! holds its share of the stack until it returns, so the rest of the queue is
//! still delivered and a binding whose event handler is where its object gets
//! disposed does not need a queue of deferred frees to be correct.
//!
//! Everything that names no stack — the last error, the status and event-kind
//! names, the ABI version — is callable from anywhere at any time, including
//! from inside the callback and from any number of threads.

use std::collections::VecDeque;
use std::ffi::{c_char, c_void};
use std::net::SocketAddr;
use std::ptr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::{Duration, Instant};

use sipral::{Event, MediaConfig, MediaEngine, MediaEvent, WallClock};
use sipral_core::endpoint::{EndpointConfig, Input, Transmit, TransportId, TransportProtocol};
use sipral_core::transaction::TimerConfig;
use sipral_ua::{AccountId, CallHandle, UaEvent, UserAgent};

use crate::abi::{codes, record};
use crate::error::{Fail, entry, fail};
use crate::event::{SipralEvent, SipralEventCallback, Vocabulary};
use crate::handle::{HandleTable, Kind, Refused, STACK_TAGS, SipralHandle, StackTag, StackTags};
use crate::media::{SipralStreamStats, catalog_of, stream_stats, toggle_of, toggled};
use crate::names::Names;
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
const TRANSPORT: TransportId = TransportId(0);

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

record! {
    /// What a stack is created with.
    ///
    /// Set `size` to `sizeof(sipral_stack_config_t)` and zero the rest before
    /// filling anything in. Four members have to be filled: the callback, the
    /// transport, the address this end is reachable at, and the entropy. Nothing
    /// here can be guessed on the caller's behalf.
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
        pub transport: u32,
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
        pub offer_dtmf: u32,
        /// Whether to ask for RFC 5761 multiplexing, as a `SipralToggle`.
        ///
        /// Off by default. §5.1.1 only permits it where both ends asked, and the
        /// equipment this stack is deployed against does not; asking unasked costs
        /// a line in every offer and buys a port on the calls where nobody answers.
        pub offer_rtcp_mux: u32,
        /// Whether to stop sending during silence, as a `SipralToggle`.
        ///
        /// Off by default. It halves the bandwidth of a call in which one person is
        /// listening, and it costs the far end's own stall watchdog a reason to
        /// fire — this stack sends no comfort noise of its own to say the silence
        /// is deliberate, so a gap looks the same from there as a stream that died.
        pub silence_suppression: u32,
        /// Whether inbound audio that stops is reported, as a `SipralToggle`. On by
        /// default; this is B5.
        pub media_stall_watchdog: u32,
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
        /// count from the Unix epoch, which costs nothing a caller is likely to
        /// miss — the round trip the far end computes is a difference, not an
        /// absolute — and costs the correlation of this call's media with anything
        /// else's.
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
    const MIN_SIZE: usize = crate::versioned::min_size::STACK_CONFIG;

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
        /// Zero since [`crate::transport`] gave them somewhere to go: what the stack
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
    const MIN_SIZE: usize = crate::versioned::min_size::POLL_RESULT;

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
        pub transport: u32,
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
        pub offer_dtmf: u32,
        /// Whether RTCP multiplexing is asked for, as a `SipralToggle`.
        pub offer_rtcp_mux: u32,
        /// Whether sending stops during silence, as a `SipralToggle`.
        pub silence_suppression: u32,
        /// How long inbound audio may stop before it is reported, with the default
        /// filled in. Zero when the watchdog is off, which is the one case where
        /// there is no figure to give.
        pub media_stall_ms: u64,
    }
}

// Safety: integers, and zero is a valid value of each.
unsafe impl Versioned for SipralStackSettings {
    const NAME: &'static str = "sipral_stack_settings";
    const MIN_SIZE: usize = crate::versioned::min_size::STACK_SETTINGS;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// One stack.
///
/// Its lock is taken without waiting, which is what makes a call from a second
/// thread an error code instead of a wait. The outbox beside it is how what a
/// poll raised reaches the callback once that lock has been let go.
struct StackEntry {
    state: Mutex<StackState>,
    outbox: Mutex<Outbox>,
}

impl StackEntry {
    /// Queue what one poll raised behind whatever is still waiting, and say
    /// whether the poll that raised it is the one to deliver.
    ///
    /// Called with the stack still held, so two polls queue in the order they
    /// ran. One poll delivers at a time: a poll that arrives while another is
    /// delivering — from inside that one's callback, or on a thread of its
    /// own — leaves its events to it, which is what keeps them in order and
    /// the callback on one thread.
    fn post(&self, raised: Vec<Delivery>) -> bool {
        let mut outbox = self.outbox();
        outbox.waiting.extend(raised);
        if outbox.delivering {
            return false;
        }
        outbox.delivering = true;
        true
    }

    /// Hand what is waiting to the callback one event at a time, with nothing
    /// held while it runs, until nothing is left; and say how many that was.
    fn deliver(&self, speaker: Speaker) -> usize {
        let mut delivered = 0_usize;
        loop {
            let next = {
                let mut outbox = self.outbox();
                let next = outbox.waiting.pop_front();
                // cleared under the same lock that found the queue empty, so
                // a poll that posts a moment later finds nobody delivering and
                // delivers its own
                if next.is_none() {
                    outbox.delivering = false;
                }
                next
            };
            let Some(delivery) = next else {
                return delivered;
            };
            unsafe { (speaker.callback)(ptr::from_ref(&delivery.event), speaker.user_data) };
            delivered = delivered.saturating_add(1);
        }
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
/// the three owners beside it, and all three reach their bytes through a
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
}

impl Delivery {
    /// An event that points at nothing.
    const fn bare(event: SipralEvent) -> Self {
        Self {
            event,
            _raised: None,
            _reason: None,
            _record: None,
        }
    }
}

// Safety: the pointers in `event` point into the three owners beside it and
// nowhere else, and each of those may move to another thread and be read from
// one: a `String` and a record of plain numbers can, and `UaEvent` is `Send`
// and `Sync` — asserted just below, so a member that ever stops being either
// fails the build here rather than making this a lie. A delivery is read by
// one thread, the one delivering it, and dropped by that thread.
unsafe impl Send for Delivery {}

const _: () = {
    const fn crosses_threads<T: Send + Sync>() {}
    crosses_threads::<UaEvent>();
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
    /// The transport every account and every call uses. There is one.
    pub(crate) transport: TransportId,
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
    /// What `now_ms` of zero means. Read once, from the only clock this
    /// library ever looks at, and never compared with a later reading.
    origin: Instant,
    /// The last time the caller said it was, so that a clock going backwards
    /// is caught where it happens.
    polled_at_ms: u64,
    /// Whether the first poll has said the stack is running.
    started: bool,
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
                SipralStatus::InvalidArgument,
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
        Ok(now)
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
    let mut held = lock(&entry)?;
    act(&mut held)
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

fn transport_of(value: u32) -> Result<SipralTransport, Fail> {
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
    let catalog = catalog_of(
        named,
        config.frame_ms,
        toggled(config.offer_dtmf, "offer_dtmf", true)?,
        toggled(config.offer_rtcp_mux, "offer_rtcp_mux", false)?,
    )?;
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

    let timers = timers_for(speaks.protocol(), &config)?;
    let media = media_for(&config)?;
    let mut endpoint = EndpointConfig::default();
    endpoint.timers = timers;

    let origin = Instant::now();
    let engine = unsafe { engine_for(&config, media.clone(), origin, media_seed) }?;
    let mut agent = UserAgent::new(endpoint, seed);
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
    let entry = StackEntry {
        state: Mutex::new(StackState {
            callback,
            user_data: config.event_user_data,
            agent,
            engine,
            managed: Vec::new(),
            accounts: Names::new(&tag, Kind::Account),
            calls: Names::new(&tag, Kind::Call),
            tag,
            transport: TRANSPORT,
            speaks,
            local,
            held: None,
            timers,
            media,
            user_agent: named.map(|name| Box::from(name.as_bytes())),
            origin,
            polled_at_ms: 0,
            started: false,
        }),
        outbox: Mutex::new(Outbox::default()),
    };
    STACKS
        .insert(stamp, entry)
        .map_err(|status| fail(status, "no room for another stack"))
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
    /// # Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    fn sipral_stack_destroy(stack: SipralHandle) {
        if crate::media::inside_media_of(stack) {
            return Err(inside_media());
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
    /// back than that is `SIPRAL_STATUS_INVALID_ARGUMENT` with nothing
    /// delivered.
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
    /// every poll and left alone by the next one — see [`crate::transport`] for
    /// the loop in full.
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
            // posted with the stack still held, so that a poll on another
            // thread cannot queue what it raised in front of this
            let speaker = entry.post(raised).then_some(Speaker {
                callback: state.callback,
                user_data: state.user_data,
            });
            (counted, speaker)
        };
        if let Some(speaker) = speaker {
            counted.events_delivered = entry.deliver(speaker);
        }

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

    let mut unclaimed = 0_usize;
    if !state.started {
        state.started = true;
        raised.push(Delivery::bare(crate::event::started(stack)));
    }
    drain(stack, state, now, raised, &mut unclaimed);

    let deadline = match (state.agent.poll_timeout(), state.engine.poll_timeout()) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (left, right) => left.or(right),
    };
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
/// naming nothing.
fn drain(
    stack: SipralHandle,
    state: &mut StackState,
    now: Instant,
    raised: &mut Vec<Delivery>,
    unclaimed: &mut usize,
) {
    let mut ended: Vec<CallHandle> = Vec::new();
    while let Some(event) = state.engine.poll_event(&mut state.agent, now) {
        match event {
            Event::Signalling(said) => {
                if let UaEvent::CallEnded { call, .. } = said {
                    ended.push(call);
                }
                if let UaEvent::CallForked { call, sibling } = said
                    && state.manages(call)
                {
                    // the branch was offered exactly what its parent was, and
                    // the engine has already given it a stream of its own
                    state.manage(sibling);
                }
                signalling(stack, state, said, raised, unclaimed);
            }
            Event::Media { call, event } => media(stack, state, call, &event, raised, unclaimed),
            // the facade is free to grow a vocabulary faster than this ABI,
            // and a number counted is more honest than a kind invented
            _ => *unclaimed = unclaimed.saturating_add(1),
        }
    }
    for call in ended {
        state.calls.forget(call);
        state.unmanage(call);
    }
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
    // shared rather than owned outright, so that the bytes the translation
    // points into stay where they are however often the delivery moves
    let said = Arc::new(said);
    let mut known = Vocabulary {
        stack,
        agent: &state.agent,
        accounts: &mut state.accounts,
        calls: &mut state.calls,
    };
    let Some(event) = crate::event::translate(&mut known, &said) else {
        *unclaimed = unclaimed.saturating_add(1);
        return;
    };
    raised.push(Delivery {
        event,
        _raised: Some(said),
        _reason: None,
        _record: None,
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
    let record = match *said {
        MediaEvent::Ended(ref cost) => Some(Arc::new(stream_stats(cost))),
        _ => None,
    };
    let mut known = Vocabulary {
        stack,
        agent: &state.agent,
        accounts: &mut state.accounts,
        calls: &mut state.calls,
    };
    let Some(event) =
        crate::event::media(&mut known, call, said, reason.as_deref(), record.as_deref())
    else {
        *unclaimed = unclaimed.saturating_add(1);
        return;
    };
    raised.push(Delivery {
        event,
        _raised: None,
        _reason: reason,
        _record: record,
    });
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        SipralPollResult, SipralStackConfig, SipralStackSettings, SipralTransport, create_on,
        sipral_stack_create, sipral_stack_destroy, sipral_stack_poll, sipral_stack_settings,
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
    }

    /// What a caller of the C API would keep behind its user pointer.
    #[derive(Default)]
    pub(crate) struct Observed {
        pub(crate) events: Vec<(SipralHandle, SipralEventKind, usize)>,
        /// The handles the events named, in order.
        pub(crate) named: Vec<(SipralHandle, SipralHandle)>,
        /// What every media event carried.
        pub(crate) media: Vec<Heard>,
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
            codecs: ptr::null(),
            codecs_len: 0,
            frame_ms: 0,
            offer_dtmf: 0,
            offer_rtcp_mux: 0,
            silence_suppression: 0,
            media_stall_watchdog: 0,
            media_stall_ms: 0,
            media_clock_unix_seconds: 0,
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
        config.size = size_of::<SipralStackConfig>() - 1;
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::UnsupportedVersion);
        assert_eq!(handle, SIPRAL_HANDLE_NONE);

        config.size = 0;
        let (status, _) = create(&config);
        assert_eq!(status, SipralStatus::UnsupportedVersion);
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
            Codec::ALL.len(),
            "everything this build contains"
        );
        assert_eq!(read.frame_ms, 20, "the default, not the zero given");
        assert_eq!(read.offer_dtmf, SipralToggle::On as u32);
        assert_eq!(read.offer_rtcp_mux, SipralToggle::Off as u32);
        assert_eq!(read.silence_suppression, SipralToggle::Off as u32);
        assert_eq!(read.media_stall_ms, 10_000, "the default watchdog");
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
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let read = read_settings(handle);
        assert_eq!(read.codec_count, 2);
        assert_eq!(read.frame_ms, 30);
        assert_eq!(read.offer_dtmf, SipralToggle::Off as u32);
        assert_eq!(read.offer_rtcp_mux, SipralToggle::On as u32);
        assert_eq!(read.silence_suppression, SipralToggle::On as u32);
        assert_eq!(read.media_stall_ms, 2_500);
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A4's rule at the boundary a caller actually crosses: a codec this build
    /// cannot encode is refused at creation, with the status that means the
    /// build is missing something rather than the one that means try again.
    #[test]
    fn a_codec_this_build_cannot_encode_stops_the_stack_from_being_made() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        let absent = "PCMU,G729";
        config.codecs = absent.as_ptr().cast::<c_char>();
        config.codecs_len = absent.len();
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::NotSupported);
        assert_eq!(handle, SIPRAL_HANDLE_NONE);
        let message = last_error_text();
        assert!(
            message.contains("G729") && message.contains("PCMA"),
            "the message names neither what was asked for nor what there is: {message}"
        );
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
        let mut out = settings();
        out.size = size_of::<SipralStackSettings>() - 1;
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
        out.size = crate::versioned::min_size::STACK_SETTINGS - 1;
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
        result.size = crate::versioned::min_size::POLL_RESULT - 1;
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
            SipralStatus::InvalidArgument,
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
    /// it raised to the delivery already under way. Delivered there instead,
    /// the new event would reach the callback before the one it is still
    /// handling had returned, and ahead of anything else still queued.
    #[test]
    fn what_a_poll_from_inside_the_callback_raises_waits_its_turn() {
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
            "the inner poll delivered its own events"
        );
        assert_eq!(
            nested.deepest.get(),
            1,
            "the callback was entered again before it had returned"
        );
        assert_eq!(
            *nested.kinds.borrow(),
            [
                SipralEventKind::Started,
                SipralEventKind::RegistrationChanged
            ]
        );
        assert_eq!(
            result.events_delivered, 2,
            "the outer poll delivered what the inner one raised"
        );
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
            SipralStatus::InvalidArgument,
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
}
