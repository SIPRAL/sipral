// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A stack: made, polled, destroyed.
//!
//! Everything the library tells the application arrives on one callback, which
//! runs inside [`sipral_stack_poll`] and nowhere else. The caller passes the time
//! on every call that can put something on the wire; a clock more than
//! `CLOCK_SLACK_MS` behind is refused, and it advances only when a call succeeds.
//!
//! # May one stack be used from two threads at once?
//!
//! For signalling, one thread at a time, from any thread. A call that arrives
//! while another is inside gets `SIPRAL_STATUS_BUSY`: it neither blocks nor
//! queues. Media has its own handle and lock ([`crate::media`]). A processor
//! inside a frame that calls into its call's stack also gets Busy, since the
//! stack can need the session the frame holds.
//!
//! # May the library be re-entered from inside the event callback?
//!
//! Yes. A poll queues its events and lets the lock go before delivering. One
//! poll at a time delivers; a nested or concurrent poll leaves its events to the
//! delivery under way, so order holds and events never arrive on two threads.
//! A pass delivers only what was queued when it began, and if it leaves some it
//! sets `has_deadline` with `next_poll_in_ms` zero. The queue holds at most
//! `OUTBOX_CEILING` events; beyond that a poll drops its own and counts them in
//! `sipral_counters_t::events_dropped`. [`sipral_stack_destroy`] works from
//! inside the callback; the current pass still completes.
//!
//! Everything that names no stack is callable from anywhere, any time.

use std::collections::{HashMap, VecDeque};
use std::ffi::{c_char, c_void};
use std::net::SocketAddr;
use std::ptr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::{Duration, Instant};

use sipral::{Event, HeldAudio, MediaConfig, MediaEngine, MediaEvent, WallClock};
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
    SipralIce, SipralSrtp, SipralSrtpSuite, SipralStreamStats, SipralToggle, catalog_of,
    ice_policy, media_failed, srtp_policy, stream_stats, toggle_of, toggled,
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
/// Published to C as `SIPRAL_TRANSPORT_MAIN`, in [`crate::transport`].
pub(crate) const TRANSPORT: TransportId = TransportId(0);

/// How far behind the last clock reading a signalling call may be: threads
/// reading one clock drift by a few milliseconds.
const CLOCK_SLACK_MS: u64 = 50;

/// How soon a poll that found the audio engine held by another thread, or
/// still opening devices, asks to be called again.
const AUDIO_BUSY_RETRY: Duration = Duration::from_millis(20);

/// A call the audio engine is to take up, with its session, or let go of.
enum AudioOp {
    Attach(SipralHandle, sipral::SessionShare),
    Detach(SipralHandle),
}

codes! {
    /// What a stack speaks. Names for `sipral_stack_config_t::transport`. Zero is
    /// not one, so a caller who meant TLS is never put on the wire in the clear.
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

    /// The number this ABI gives a protocol, or zero for one it has none for.
    pub(crate) const fn named(protocol: TransportProtocol) -> u32 {
        match protocol {
            TransportProtocol::Udp => Self::Udp as u32,
            TransportProtocol::Tcp => Self::Tcp as u32,
            TransportProtocol::Tls => Self::Tls as u32,
            TransportProtocol::Ws => Self::Ws as u32,
            TransportProtocol::Wss => Self::Wss as u32,
            // a transport this ABI has no number for yet
            _ => 0,
        }
    }
}

/// Every transport a stack has bound, from [`SIPRAL_TRANSPORT_MAIN`] on. Grows
/// only, so `sipral_stack_transport_bind` can bring a failed one back.
pub(crate) struct Transports(HashMap<u32, TransportProtocol>);

impl Transports {
    /// A table with only the main transport in it.
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

    /// Record a transport as bound; a known number keeps its protocol.
    pub(crate) fn record(&mut self, id: u32, protocol: TransportProtocol) {
        self.0.entry(id).or_insert(protocol);
    }
}

record! {
    /// What a stack is created with. Set `size` to `sizeof(sipral_stack_config_t)`
    /// and zero the rest first. Required: the callback, the transport, the reachable
    /// address, the entropy, and a media seed different from the entropy.
    #[derive(Clone, Copy)]
    pub struct SipralStackConfig {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// Where events go. Required.
        pub event_callback: SipralEventCallback,
        /// Handed back to the callback untouched. The library never reads it.
        pub event_user_data: *mut c_void,
        /// A [`SipralTransport`].
        pub transport: Number<SipralTransport>,
        /// The address the far end reaches this one at, as `host:port`, UTF-8 and
        /// not NUL-terminated. It goes in every `Via`.
        pub bind_address: *const c_char,
        /// How many bytes of it.
        pub bind_address_len: usize,
        /// `User-Agent` for every REGISTER and INVITE this stack originates, or null
        /// for none (optional per §20 Table 3).
        pub user_agent: *const c_char,
        /// How many bytes of it.
        pub user_agent_len: usize,
        /// Thirty-two bytes from the platform's generator. Every branch, tag and
        /// `Call-ID` derives from it, and §19.3 wants a tag unguessable. Never
        /// shared between stacks. Media keys come from `media_seed`.
        pub entropy: *const u8,
        /// How many bytes of it. Thirty-two.
        pub entropy_len: usize,
        /// T1 in milliseconds, or zero for the 500 ms of §17.1.1.1.
        pub timer_t1_ms: u64,
        /// T2 in milliseconds, or zero for four seconds. UDP only; set on another
        /// transport it is `SIPRAL_STATUS_INVALID_ARGUMENT`.
        pub timer_t2_ms: u64,
        /// T4 in milliseconds, or zero for five seconds. UDP only, like T2.
        pub timer_t4_ms: u64,
        /// The codecs to offer, in order (A4, RFC 3264 §6.1): comma-separated names,
        /// UTF-8, not NUL-terminated; null for every codec built in. An unknown name is
        /// `SIPRAL_STATUS_NOT_SUPPORTED`, with the known names in the last error.
        pub codecs: *const c_char,
        /// How many bytes of it.
        pub codecs_len: usize,
        /// Frame length in milliseconds, or zero for twenty. Must suit Opus if offered.
        pub frame_ms: u32,
        /// Whether to offer RFC 4733 named events, as a `SipralToggle`. On by default.
        pub offer_dtmf: Number<SipralToggle>,
        /// Whether to ask for RFC 5761 multiplexing (§5.1.1), as a `SipralToggle`.
        /// Off by default.
        pub offer_rtcp_mux: Number<SipralToggle>,
        /// Whether to stop sending during silence, as a `SipralToggle`. Off by
        /// default: with no comfort noise, the gap looks like a dead stream.
        pub silence_suppression: Number<SipralToggle>,
        /// Whether inbound audio that stops is reported (B5), as a `SipralToggle`.
        /// On by default.
        pub media_stall_watchdog: Number<SipralToggle>,
        /// How long inbound audio may stop before it is reported, in milliseconds,
        /// or zero for the default. Refused with the watchdog off.
        pub media_stall_ms: u64,
        /// The wall clock at creation, in seconds since the Unix epoch, for RFC 3550
        /// §6.4.1 sender reports; zero to wait for `sipral_stack_stir`'s `unix_seconds`.
        pub media_clock_unix_seconds: u64,
        /// Thirty-two more bytes for the media keys, **not the same bytes as
        /// `entropy`**, which recordings write in clear. The same bytes are refused.
        pub media_seed: *const u8,
        /// How many bytes of it. Thirty-two.
        pub media_seed_len: usize,
        /// Default SRTP for every call: a `SipralSrtp`, or zero for
        /// `SIPRAL_SRTP_NOT_OFFERED`. `sipral_call_config_t::srtp` overrides it.
        pub srtp: Number<SipralSrtp>,
        /// Default ICE for every call: a `SipralIce`, or zero for `SIPRAL_ICE_OFF`
        /// (`docs/06-nat.md`). `sipral_call_config_t::ice` overrides it.
        pub ice: Number<SipralIce>,
        /// A `SipralNat`, or zero for `SIPRAL_NAT_OFF`. `SIPRAL_NAT_STUN` asks
        /// `stun_server` where each socket appears from (`docs/06-nat.md`).
        pub nat: Number<SipralNat>,
        /// The STUN server, as a `host:port` address. Required with and only with
        /// `SIPRAL_NAT_STUN`. Copied.
        pub stun_server: *const c_char,
        /// How many bytes of it.
        pub stun_server_len: usize,
        /// Whether G.729 Annex B is allowed, as a `SipralToggle`. On by default (RFC
        /// 4856 §2.1.9); off, SDP says `annexb=no` (RFC 3551 §4.5.6).
        pub g729_annex_b: Number<SipralToggle>,
        /// A TURN server (RFC 8656), as `host:port`, to relay every media socket
        /// `sipral_stack_nat_map` names (`docs/06-nat.md`). Only with `SIPRAL_NAT_STUN`,
        /// needs `turn_username` and `turn_password`, and `SIPRAL_FEATURE_ICE`. Copied.
        pub turn_server: *const c_char,
        /// How many bytes of it.
        pub turn_server_len: usize,
        /// The TURN long-term credential's user name (RFC 8489 §9.2).
        pub turn_username: *const c_char,
        /// How many bytes of it.
        pub turn_username_len: usize,
        /// Its password. Copied, wiped at destroy, never logged.
        pub turn_password: *const c_char,
        /// How many bytes of it.
        pub turn_password_len: usize,
        /// Whether an out-of-dialog REFER (RFC 3515 §4.1) reaches the application, as
        /// a `SipralToggle`. **Off by default**: each is refused 403, since an
        /// unauthenticated peer could make the phone dial anywhere. On, each is raised
        /// as `SIPRAL_EVENT_KIND_REFERRAL`.
        pub referrals: Number<SipralToggle>,
        /// Whether an account behind a NAT sends a double CRLF to its registrar every
        /// `registrar_keepalive_ms` over UDP, as a `SipralToggle`. **On by default.**
        /// Without it an address-and-port filtering NAT (RFC 4787 §5) drops a later
        /// INVITE; registrars ignore it (RFC 3261 §7.5). See `docs/06-nat.md`.
        pub registrar_keepalive: Number<SipralToggle>,
        /// Keep-alive interval in milliseconds, or zero for 25 s (RFC 5626 §4.4.2),
        /// jittered to 80-100%. From 1 000 to 120 000 (RFC 4787 REQ-5), and only with
        /// `registrar_keepalive` on.
        pub registrar_keepalive_ms: u64,
        /// How media sockets reach `turn_server`, as a `SipralTransport`: UDP (or
        /// zero), TCP, or TLS (RFC 8656 §4.1). Over TCP or TLS the application opens a
        /// connection when `SIPRAL_EVENT_KIND_TURN_STREAM` asks.
        pub turn_transport: Number<SipralTransport>,
        /// Who pumps audio, as a `SipralAudio`: zero or `SIPRAL_AUDIO_APPLICATION`
        /// for the application; `SIPRAL_AUDIO_DEVICE` for the library, which needs
        /// `audio_transmit_callback` and `SIPRAL_FEATURE_AUDIO_DEVICE`.
        pub audio: Number<SipralAudio>,
        /// When devices open in device mode: a `SipralAudioActivation`, or zero for
        /// `SIPRAL_AUDIO_ACTIVATION_AUTOMATIC`.
        pub audio_activation: Number<SipralAudioActivation>,
        /// Device mode: receives each encoded packet on the engine's thread.
        /// Required with `SIPRAL_AUDIO_DEVICE`.
        pub audio_transmit_callback: SipralAudioTransmitCallback,
        /// Handed back to `audio_transmit_callback` unread.
        pub audio_transmit_user_data: *mut c_void,
        /// How long a device call may block before `SIPRAL_STATUS_DEVICE_TIMED_OUT`,
        /// in milliseconds; zero for three seconds.
        pub audio_probe_ms: u64,
        /// The device rate in device mode; zero for 48000.
        pub audio_device_rate_hz: u32,
        /// The most calls at once, either direction, or zero for 128. Past it an
        /// INVITE gets `503` with `Retry-After: 2` (RFC 3261 §21.5.4), and a placed
        /// call is `SIPRAL_STATUS_LIMIT_REACHED`. See `docs/19-numbers.md`.
        pub max_dialogs: u32,
        /// The most server transactions (RFC 3261 §17.2) at once, or zero for 256;
        /// past it a stateless `503`. A BYE is never refused.
        pub max_server_transactions: u32,
        /// D1: how many decisions each diagnostic record keeps, or zero for 64.
        pub diagnostic_decisions: u32,
        /// D1: how many calls have a diagnostic record at once, or zero for 32; the
        /// oldest is dropped and counted.
        pub diagnostic_records: u32,
        /// When a call listens for in-band keypad digits, as a
        /// [`SipralDtmfDetection`]; zero for calls with no telephone event. Placed
        /// here to avoid tail padding.
        pub dtmf_detection: Number<SipralDtmfDetection>,
        /// Fallback STUN servers, comma-separated `host:port`, tried in order when
        /// `stun_server` fails; a failed one is skipped from 30 s up to ten minutes.
        /// Only with `stun_server`. Copied.
        pub stun_fallbacks: *const c_char,
        /// How many bytes of it.
        pub stun_fallbacks_len: usize,
        /// The lowest RTP port handed out (`sipral_stack_rtp_port_reserve`), or zero
        /// with `rtp_port_max` for none. Even ports only (RFC 3550 §11).
        pub rtp_port_min: u32,
        /// The highest port of that range, or zero with `rtp_port_min`.
        pub rtp_port_max: u32,
        /// The SRTP suites calls offer and accept unless the account names its own:
        /// names from RFC 4568 section 6.2 and RFC 7714 section 14.2, comma-separated,
        /// preferred first; null for the build's order.
        pub srtp_suites: *const c_char,
        /// How many bytes of it.
        pub srtp_suites_len: usize,
        /// The path MTU in bytes, or zero for unknown (RFC 3261 section 18.1.1).
        /// At least 576 (RFC 791).
        pub path_mtu: u32,
        /// Largest request sent over UDP once no stream can be had, in bytes; zero
        /// for never. **A deliberate deviation from RFC 3261 section 18.1.1**, for
        /// UDP-only servers. At most 65 507.
        pub datagram_without_stream_bytes: u32,
        /// A per-installation salt (at least 16 bytes) so pseudonyms match across
        /// runs; null keys them from `media_seed`. Secret. Copied.
        pub pseudonym_salt: *const u8,
        /// How many bytes of it.
        pub pseudonym_salt_len: usize,
        /// A `SipralToggle`: whether the trace writes SIP messages unpseudonymised;
        /// off by default. Credentials and keys are always removed.
        pub diagnostic_trace: Number<SipralToggle>,
        /// Zero.
        pub reserved: u32,
        /// A `SipralToggle`: whether device mode uses the platform's echo
        /// cancellation; on by default.
        pub system_echo_cancellation: Number<SipralToggle>,
        /// Zero.
        pub reserved_35: u32,
        /// A [`SipralHeldAudio`]: what a held party is sent (RFC 3264 §8.4). Zero
        /// is silence.
        pub held_audio: Number<SipralHeldAudio>,
        /// Zero.
        pub reserved_36: u32,
    }
}

codes! {
    /// What a held party is sent: `sipral_stack_config_t::held_audio`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralHeldAudio: u32 {
        /// Silence, in either mode.
        Default = 0,
        /// Silence.
        Silence = 1,
        /// The frames the application hands over, as they are.
        Application = 2,
    }
}

/// What `held_audio` asks for, in either mode.
fn held_audio_of(held_audio: u32) -> Result<HeldAudio, Fail> {
    match held_audio {
        0 | 1 => Ok(HeldAudio::Silence),
        2 => Ok(HeldAudio::Captured),
        other => Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "held_audio is {other}, and what a held party is sent is 0 or 1 for \
                 silence, or 2 for the application's frames"
            ),
        )),
    }
}

// Safety: plain data, and all-zero is a valid value of every member.
unsafe impl Versioned for SipralStackConfig {
    const NAME: &'static str = "sipral_stack_config";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralStackConfig, rtp_port_max);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// What one call to [`sipral_stack_poll`] did. Set `size` first.
    #[derive(Clone, Copy)]
    pub struct SipralPollResult {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// Events handed to the callback during this poll.
        pub events_delivered: usize,
        /// Events this ABI has no word for yet. Counted, not delivered.
        pub events_unclaimed: usize,
        /// Bytes this build had nowhere to send; zero, kept for ABI stability.
        pub transmits_discarded: usize,
        /// Whether there is a deadline. Zero: wait for input.
        pub has_deadline: u32,
        /// Milliseconds from `now_ms` until the stack is due. Zero: due now.
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
    /// What a stack is running with, defaults filled in. Set `size` first.
    #[derive(Clone, Copy)]
    pub struct SipralStackSettings {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// The [`SipralTransport`] this stack speaks.
        pub transport: Number<SipralTransport>,
        /// Whether this stack retransmits; zero on every transport but UDP.
        pub retransmits: u32,
        /// T1 in milliseconds, with the default filled in.
        pub timer_t1_ms: u64,
        /// T2 in milliseconds, with the default filled in.
        pub timer_t2_ms: u64,
        /// T4 in milliseconds, with the default filled in.
        pub timer_t4_ms: u64,
        /// How many codecs this stack offers (`sipral_stack_codec_order`).
        pub codec_count: usize,
        /// How long a frame is, with the default filled in.
        pub frame_ms: u32,
        /// Whether named events are offered, as a `SipralToggle`.
        pub offer_dtmf: Number<SipralToggle>,
        /// Whether RTCP multiplexing is asked for, as a `SipralToggle`.
        pub offer_rtcp_mux: Number<SipralToggle>,
        /// Whether sending stops during silence, as a `SipralToggle`.
        pub silence_suppression: Number<SipralToggle>,
        /// The media stall interval in milliseconds; zero when the watchdog is off.
        pub media_stall_ms: u64,
        /// Whether G.729 Annex B is allowed, as a `SipralToggle`.
        pub g729_annex_b: Number<SipralToggle>,
        /// Whether an out-of-dialog REFER reaches the application, as a `SipralToggle`.
        pub referrals: Number<SipralToggle>,
        /// The registrar keep-alive in milliseconds; zero when off.
        pub registrar_keepalive_ms: u64,
        /// The most calls the stack holds at once.
        pub max_dialogs: u32,
        /// The most server transactions at once.
        pub max_server_transactions: u32,
        /// How many decisions a diagnostic record keeps.
        pub diagnostic_decisions: u32,
        /// How many diagnostic records the stack keeps.
        pub diagnostic_records: u32,
        /// The RTP port range, as given; both zero for none.
        pub rtp_port_min: u32,
        /// See `rtp_port_min`.
        pub rtp_port_max: u32,
        /// The path MTU as given, zero for unknown (ABI 0.34).
        pub path_mtu: u32,
        /// The largest request sent over UDP once no stream is coming; zero for never.
        pub datagram_without_stream_bytes: u32,
        /// How many SRTP suites calls use by default (`sipral_stack_srtp_suite_order`).
        pub srtp_suite_count: u32,
        /// A `SipralToggle`: whether a `pseudonym_salt` was given. Never the salt.
        pub pseudonym_salted: Number<SipralToggle>,
        /// A `SipralToggle`: whether the trace writes whole messages now.
        pub diagnostic_trace: Number<SipralToggle>,
        /// A `SipralToggle`: whether the platform's echo cancellation is asked for.
        pub system_echo_cancellation: Number<SipralToggle>,
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

/// How many deliveries [`Outbox::waiting`] holds. Posting never waits, so
/// without this a stuck callback grows the queue without bound.
const OUTBOX_CEILING: usize = 4096;

/// How many RTCP goodbyes [`StackState::farewells`] holds; the oldest goes
/// first. A stale one is worth little (RFC 3550 §6.6).
pub(crate) const FAREWELL_CEILING: usize = 256;

/// Config only `sipral_stack_settings` reads back.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Asked {
    /// Whether a pseudonym salt was given.
    pub(crate) salted: bool,
    /// Whether device mode asks for the platform's echo cancellation.
    pub(crate) echo_cancellation: bool,
}

/// One stack. Its lock is only tried, never waited on.
struct StackEntry {
    state: Mutex<StackState>,
    outbox: Mutex<Outbox>,
    /// Log lines waiting for the thread that releases the stack (`crate::log`).
    log: sipral::Log,
    /// What [`crate::log::sipral_stack_state_text`] reads while the stack is busy,
    /// behind its own lock.
    watch: Mutex<crate::log::Watch>,
    /// The audio engine, reachable without the state's lock.
    audio: Option<crate::audio::Shared>,
}

impl StackEntry {
    /// Queue a poll's events, up to [`OUTBOX_CEILING`]; return whether this poll
    /// delivers and how many were dropped. Called with the stack held.
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

    /// Deliver what was queued when the pass began, with nothing held; return how
    /// many and whether more waits.
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
        // same lock as `post`: a later poll finds nobody delivering
        (delivered, !outbox.waiting.is_empty())
    }

    fn watch(&self) -> MutexGuard<'_, crate::log::Watch> {
        // a queue of sentences and a copy of a text, whole between statements
        self.watch.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// After release: record a refusal, then flush the log with nothing held.
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
        // a panic was caught while held; the queue is whole between statements
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

/// Where a stack's events go, copied out for delivery after release.
#[derive(Clone, Copy)]
struct Speaker {
    callback: unsafe extern "C" fn(event: *const SipralEvent, user_data: *mut c_void),
    user_data: *mut c_void,
}

/// One event on its way to the callback. Read after the lock is gone, so its
/// pointers point only into the owners beside it.
struct Delivery {
    event: SipralEvent,
    /// Never read: what `event` borrows from.
    _raised: Option<Arc<UaEvent>>,
    /// Never read: the sentence a media event points at.
    _reason: Option<String>,
    /// Never read: the record a statistics event points at.
    _record: Option<Arc<SipralStreamStats>>,
    /// Never read: the identity a call event points at, which
    /// `StackState::identities` may already have dropped.
    _identity: Option<Arc<CallIdentity>>,
}

impl Delivery {
    /// An event that points at nothing.
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

// Safety: `event` points only into owners that are `Send` and `Sync`
// (asserted below), and one thread reads and drops it.
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
    /// Signalling joined to media. It drains the user agent; nothing else may.
    pub(crate) engine: MediaEngine,
    /// The calls whose media this stack describes.
    managed: Vec<CallHandle>,
    /// The tag this stack's handles carry, freed with the last share of state.
    pub(crate) tag: StackTag,
    pub(crate) accounts: Names<AccountId>,
    pub(crate) calls: Names<CallHandle>,
    /// Every subscription handed a handle, forks included (RFC 6665 §4.1.4).
    pub(crate) subscriptions: Names<SubscriptionHandle>,
    /// MESSAGEs sent whose final answer is not yet reported.
    pub(crate) messages: Names<sipral_ua::MessageHandle>,
    /// Every call a push announced and no INVITE has answered yet.
    pub(crate) announcements: Names<AnnouncementId>,
    /// Dialogs the application was asked to resolve a next hop for.
    pub(crate) dialogs: Names<DialogId>,
    /// The `From` and `To` of every known call, read when it opened.
    pub(crate) identities: HashMap<CallHandle, Arc<CallIdentity>>,
    /// Every transport this stack has bound.
    pub(crate) transports: Transports,
    /// What the main transport speaks.
    pub(crate) speaks: SipralTransport,
    /// The address it advertises.
    pub(crate) local: SocketAddr,
    /// A message that did not fit the caller's buffer, offered again first.
    pub(crate) held: Option<Transmit>,
    /// The figures the endpoint was built with.
    timers: TimerConfig,
    /// What the media settings came to, for the same reason again.
    media: MediaConfig,
    /// What goes in `User-Agent`, when the caller wanted one.
    pub(crate) user_agent: Option<Box<[u8]>>,
    /// RTCP goodbyes, resolved during the poll and drained by
    /// [`crate::media::sipral_stack_poll_farewell`]; at most [`FAREWELL_CEILING`].
    pub(crate) farewells: VecDeque<(SipralHandle, SocketAddr, Vec<u8>, u32)>,
    /// Events dropped at [`OUTBOX_CEILING`].
    pub(crate) events_dropped: u64,
    /// Goodbyes dropped at [`FAREWELL_CEILING`].
    pub(crate) farewells_dropped: u64,
    /// What `now_ms` of zero means. Read once.
    origin: Instant,
    /// The last time the caller gave.
    polled_at_ms: u64,
    /// Whether the first poll has said the stack is running.
    started: bool,
    /// What it asks a STUN server, when configured.
    #[cfg(feature = "stun")]
    pub(crate) nat: crate::nat::Nat,
    /// The built-in audio engine, in device mode.
    pub(crate) audio: Option<crate::audio::Shared>,
    /// Calls the audio engine is to take up or drop, waiting for a free engine.
    audio_backlog: Vec<AudioOp>,
    /// The caller's clock as the engine's pump reads it.
    clock: Arc<crate::audio::Clock>,
    /// Whether `media_clock_unix_seconds` gave the engine a wall clock.
    #[cfg(feature = "stir")]
    pub(crate) media_clock: bool,
    /// This stack's log, shared with the engine and the entry.
    pub(crate) log: sipral::Log,
    /// What the configuration asked for that only the settings read back.
    pub(crate) asked: Asked,
    /// The pseudonym key (`crate::log::pseudonym_key`), wiped on drop.
    pseudonyms: sipral::PseudonymKey,
    /// Transports retired since the last poll, reported first.
    pub(crate) lost: Vec<crate::transport::Lost>,
    /// The local conferences made on this stack, by handle.
    pub(crate) conferences: Vec<(SipralHandle, crate::local_conference::Shared)>,
    /// The network tests under way (`crate::network_test`).
    pub(crate) tests: crate::network_test::Tests,
}

// Safety: the user pointer is only handed back to the caller's callback;
// the rest is `Send`.
unsafe impl Send for StackState {}

/// `now_ms` as an instant after `origin`.
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

    /// The latest time this stack has been told.
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

    /// What `now_ms` of zero means on this stack.
    pub(crate) const fn origin(&self) -> Instant {
        self.origin
    }

    /// The instant `now_ms` names, refused past [`CLOCK_SLACK_MS`] behind, without
    /// moving the clock ([`Self::commit_clock`] does, once the call succeeds).
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

    /// Record that this stack has been used at `now_ms`. Never moves backward.
    fn commit_clock(&mut self, now_ms: u64) {
        self.polled_at_ms = self.polled_at_ms.max(now_ms);
    }

    /// Validate and commit at once; only [`sipral_stack_poll`] uses this, other
    /// entry points go through [`with_stack_at`].
    pub(crate) fn advance(&mut self, now_ms: u64) -> Result<Instant, Fail> {
        let now = self.checked_instant(now_ms)?;
        self.commit_clock(now_ms);
        self.clock.polled(now_ms);
        Ok(now)
    }

    /// What a call opens its session with, unless `sipral_call_place` overrides it.
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

/// Do something to a stack, or say why not. Every entry point goes through here.
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

/// The text [`crate::log::sipral_stack_state_text`] copies out. Never waits.
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

/// The stack a handle names. Refused inside a frame of one of its calls,
/// which would deadlock on the session.
fn entry_of(stack: SipralHandle) -> Result<Arc<StackEntry>, Fail> {
    if crate::media::inside_media_of(stack) {
        return Err(inside_media());
    }
    STACKS.get(stack).map_err(handle_failed)
}

/// The audio engine of a stack, without its lock; `None` in application mode.
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

/// The same, at the caller's time; the clock commits only if `act` succeeds.
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
        // a panic was caught while held; the state is whole between statements
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

/// The timer figures. RFC 3261 §17 arms neither T2 nor T4 on a reliable
/// transport, so setting them there is refused, as is a T2 below T1.
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

/// The four ceilings, each zero for the endpoint's default.
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

/// The smallest datagram an IPv4 host must take whole (RFC 791).
const MIN_PATH_MTU: u32 = 576;

/// 65 535 less the IP and UDP headers.
const MAX_UDP_PAYLOAD: u32 = 65_507;

/// The two figures RFC 3261 section 18.1.1 draws its line from.
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

/// A count as the caller reads one, saturating.
fn count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// The user agent's policies: out-of-dialog REFER, registrar keep-alive.
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

/// The registrar keep-alive, or `None`. A figure with it off is refused.
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

/// How this stack's media behaves. A stall interval with the watchdog off is
/// refused.
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
        held_audio: held_audio_of(config.held_audio)?,
        ..default
    })
}

/// The media engine a stack runs with.
///
/// # Safety
///
/// Every pointer in `config` must be readable for the length beside it.
unsafe fn engine_for(
    config: &SipralStackConfig,
    media: MediaConfig,
    origin: Instant,
    media_seed: &[u8; SEED_BYTES],
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
    Ok(MediaEngine::new(catalog, media, clock, *media_seed))
}

entry! {
    /// Create a stack, and write its handle to `out_stack`.
    ///
    /// The handle is written only on `SIPRAL_STATUS_OK` and must be freed with
    /// [`sipral_stack_destroy`]. A process holds 256 stacks; the next is
    /// `SIPRAL_STATUS_EXHAUSTED` until one is destroyed and no poll still runs on it.
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

/// Everything [`sipral_stack_create`] does but write the handle, with tags
/// from `tags`.
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
    let salted = salt.is_some();
    let echo_cancellation = toggled(
        config.system_echo_cancellation,
        "system_echo_cancellation",
        true,
    )?;

    let origin = Instant::now();
    let clock = crate::audio::Clock::new(origin);
    let audio = unsafe { crate::audio::configured(&config, &clock) }?;
    let mut engine = unsafe { engine_for(&config, media.clone(), origin, &media_seed) }?;
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
    let mut agent = UserAgent::new(endpoint, *seed)
        .map_err(|error| fail(SipralStatus::InvalidArgument, error.to_string()))?;
    agent_policy(&mut agent, &config, origin)?;
    // the far end answers to the advertised address, not the socket's
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
        audio_backlog: Vec::new(),
        clock,
        #[cfg(feature = "stir")]
        media_clock: config.media_clock_unix_seconds != 0,
        log: log.clone(),
        asked: Asked {
            salted,
            echo_cancellation,
        },
        pseudonyms,
        lost: Vec::new(),
        conferences: Vec::new(),
        tests: crate::network_test::Tests::default(),
    };
    // the main transport's first request now waits in `sipral_stack_poll_transmit`
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

/// Refuse media at a port outside the RTP range or odd. No range: any port.
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

/// The signalling and media seeds, never equal, wiped on drop.
///
/// # Safety
///
/// `config.entropy` and `config.media_seed` must be readable for the lengths
/// beside them.
unsafe fn seeds_of(config: &SipralStackConfig) -> Result<(Seed, Seed), Fail> {
    let seed = seed_from(
        unsafe { bytes(config.entropy, config.entropy_len, "entropy") }?,
        "entropy",
    )?;
    let media_seed = seed_from(
        unsafe { bytes(config.media_seed, config.media_seed_len, "media_seed") }?,
        "media_seed",
    )?;
    if media_seed == seed {
        // only here are both visible; equal seeds would expose every SRTP key
        return Err(fail(
            SipralStatus::InvalidArgument,
            "media_seed is the same as entropy; they must be two independent draws, because what \
             is drawn from entropy goes on the wire in clear and must not permit deriving a key"
                .to_owned(),
        ));
    }
    Ok((seed, media_seed))
}

/// A seed as [`seeds_of`] holds it.
type Seed = zeroize::Zeroizing<[u8; SEED_BYTES]>;

fn seed_from(entropy: Option<&[u8]>, member: &str) -> Result<Seed, Fail> {
    let supplied = entropy.unwrap_or_default();
    <[u8; SEED_BYTES]>::try_from(supplied).map(Seed::new).map_err(|_| {
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
    /// Read back what a stack is running with, defaults filled in.
    ///
    /// # Safety
    ///
    /// `out_settings` must point at a `sipral_stack_settings_t` whose `size`
    /// member says how long it is.
    fn sipral_stack_settings(stack: SipralHandle, out_settings: *mut SipralStackSettings) {
        // size before handle, so a wrong size is the error reported
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
                srtp_suite_count: u32::try_from(catalog.srtp_suites_in_force().len())
                    .unwrap_or(u32::MAX),
                pseudonym_salted: toggle_of(state.asked.salted),
                diagnostic_trace: toggle_of(state.log.diagnostic()),
                system_echo_cancellation: toggle_of(state.audio.as_ref().map_or(
                    state.asked.echo_cancellation,
                    |audio| {
                        audio
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .system_echo_cancellation()
                    },
                )),
            })
        })?;
        unsafe { write_versioned(out_settings, settings) }?;
        Ok(())
    }
}

entry! {
    /// The SRTP suites calls use by default, in order, as `sipral_srtp_suite_t`
    /// numbers. `out_count` always receives the total; too small a capacity is
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL`.
    ///
    /// # Safety
    ///
    /// `out_suites` must be writable for `capacity` `uint32_t` or null with a
    /// capacity of zero, and `out_count` must point at one `size_t` or be null.
    fn sipral_stack_srtp_suite_order(
        stack: SipralHandle,
        out_suites: *mut Number<SipralSrtpSuite>,
        capacity: usize,
        out_count: *mut usize,
    ) {
        if out_suites.is_null() && capacity != 0 {
            return Err(fail(SipralStatus::InvalidArgument, "out_suites is null"));
        }
        let order = with_stack(stack, |state| {
            Ok(state
                .engine
                .catalog()
                .srtp_suites_in_force()
                .into_iter()
                .map(|suite| crate::event::suite_of(suite) as u32)
                .collect::<Vec<u32>>())
        })?;
        if !out_count.is_null() {
            unsafe { out_count.write(order.len()) };
        }
        if capacity < order.len() {
            return Err(fail(
                SipralStatus::BufferTooSmall,
                format!(
                    "this stack runs {} SRTP suites and there is room for {capacity}",
                    order.len()
                ),
            ));
        }
        if !order.is_empty() {
            unsafe { std::ptr::copy_nonoverlapping(order.as_ptr(), out_suites, order.len()) };
        }
        Ok(())
    }
}

/// An interval in milliseconds, saturating.
fn millis(interval: Duration) -> u64 {
    u64::try_from(interval.as_millis()).unwrap_or(u64::MAX)
}

entry! {
    /// Destroy a stack. The handle is dead on return; a second destroy is
    /// `SIPRAL_STATUS_STALE_HANDLE`. Safe inside the callback. Inside a frame of one
    /// of its calls it is `SIPRAL_STATUS_BUSY`. Nothing is sent: hang up, unmap and
    /// send what `sipral_stack_poll_farewell` and `sipral_stack_poll_stun` give
    /// first, or TURN relays linger up to ten minutes.
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
        // a running poll holds its own share until it is done
        STACKS.remove(stack).map_err(handle_failed)?;
        Ok(())
    }
}

entry! {
    /// Let the stack do its work, and deliver what it has to say.
    ///
    /// `now_ms` is the caller's monotonic clock in milliseconds; more than fifty
    /// behind is `SIPRAL_STATUS_CLOCK_BEHIND`. The callback runs inside this call,
    /// on this thread, with nothing held. `result` may be null. Drain
    /// `sipral_stack_poll_transmit` after every poll (`docs/08-ffi.md`).
    ///
    /// # Safety
    ///
    /// `result` must be null or point at a `sipral_poll_result_t` whose `size`
    /// member says how long it is.
    fn sipral_stack_poll(stack: SipralHandle, now_ms: u64, result: *mut SipralPollResult) {
        // before the handle and the clock, so a refusal moves nothing
        if !result.is_null() {
            unsafe { declared_size(result.cast_const()) }?;
        }
        // held through delivery, so a destroy from the callback frees afterwards
        let entry = entry_of(stack)?;
        let (mut counted, speaker) = {
            let mut state = lock(&entry)?;
            let now = state.advance(now_ms)?;
            let mut raised = Vec::new();
            let counted = run(stack, &mut state, now, &mut raised);
            if !raised.is_empty() {
                entry.watch().refresh(stack, &state);
            }
            // posted while held, so polls queue in order
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
                // what arrived during the pass is due now
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

/// One poll. `events_delivered` is left for whichever poll delivers.
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
    // a lost transport before the failures it caused
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
    // after the engine's events, so a REGISTER follows them
    for (event, text) in crate::nat::Nat::drain(state, stack, now) {
        raised.push(Delivery {
            event,
            _raised: None,
            _reason: Some(text),
            _record: None,
            _identity: None,
        });
    }
    for (event, text) in crate::network_test::service(state, stack, now) {
        raised.push(Delivery {
            event,
            _raised: None,
            _reason: Some(text),
            _record: None,
            _identity: None,
        });
    }
    // audio engine news. Only tried: a `sipral_audio_*` call may hold it up to
    // `audio_probe_ms`, and waiting would make every other thread BUSY.
    let mut audio_busy = false;
    if let Some(audio) = state.audio.clone() {
        let held = match audio.try_lock() {
            Ok(engine) => Some(engine),
            Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => None,
        };
        if let Some(mut engine) = held {
            for op in std::mem::take(&mut state.audio_backlog) {
                match op {
                    AudioOp::Attach(handle, share) => {
                        let _ = engine.attach(handle, Box::new(share));
                    }
                    AudioOp::Detach(handle) => {
                        engine.detach(handle);
                        // its own gain, mute and meter go with it
                        engine.forget_call(handle);
                    }
                }
            }
            engine.service();
            while let Some(event) = engine.poll_event() {
                raised.push(Delivery::bare(crate::event::audio_changed(
                    stack,
                    crate::audio::event_of(event),
                )));
            }
            audio_busy = engine.is_opening();
        } else {
            audio_busy = true;
        }
    }
    for event in crate::local_conference::drain(state, stack) {
        raised.push(Delivery::bare(event));
    }

    let deadline = [
        state.agent.poll_timeout(),
        state.engine.poll_timeout(),
        crate::nat::Nat::poll_timeout(state),
        state.tests.poll_timeout(),
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

/// Take everything the engine has, translated. Ended calls are forgotten
/// last, since their media is reported after the signalling that ended them.
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
                // read before translation: a CANCEL may already have made the layer below
                // forget the call, which applied the trust gate (RFC 3325 §8)
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
                    // a forked branch shares its parent's From, To and Call-ID
                    if let Some(identity) = state.identities.get(&call).cloned() {
                        state.identities.insert(sibling, identity);
                    }
                    if state.manages(call) {
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
                // a network test's OPTIONS is reported in the test's own event
                if let UaEvent::ServerProbed { probe, outcome, .. } = said {
                    state.tests.server_probed(probe, outcome);
                    continue;
                }
                signalling(stack, state, said, raised, unclaimed);
            }
            Event::Media { call, event } => {
                // in device mode the engine pumps the session; handed over below
                if state.audio.is_some() {
                    match event {
                        MediaEvent::Started { .. } => {
                            if let (Some(share), Ok(handle)) =
                                (state.engine.share(call), state.calls.name_of(call))
                            {
                                state.audio_backlog.push(AudioOp::Attach(handle, share));
                            }
                        }
                        MediaEvent::Ended(_) => {
                            if let Ok(handle) = state.calls.name_of(call) {
                                state.audio_backlog.push(AudioOp::Detach(handle));
                            }
                        }
                        _ => {}
                    }
                }
                media(stack, state, call, &event, raised, unclaimed);
            }
            _ => *unclaimed = unclaimed.saturating_add(1),
        }
    }
    // every goodbye of this poll is here while `calls` still names it
    while let Some((call, destination, payload)) = state.engine.poll_farewell() {
        let protocol = SipralTransport::Udp as u32;
        farewell(state, call, destination, payload, protocol);
    }
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
        state.identities.remove(&call);
    }
    // retired after its own event is queued
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
    // already answered by the engine; reported as a media event
    if let UaEvent::Reoffer { call, .. } = said
        && state.manages(call)
    {
        return;
    }
    // RFC 5626 §4.4.1: a flow stopped answering and its transport was retired
    if let UaEvent::Unclaimed(sipral_core::endpoint::Event::FlowFailed { transport }) = said {
        // a WebSocket the stack runs says why it gave up, in its own words
        let (error, detail) = match state.agent.websocket_failure(transport) {
            Some((kind, why)) => (crate::transport::error_of(kind), String::from(why)),
            None => (
                crate::transport::SipralTransportError::TimedOut,
                String::from(
                    "no answer to a keep-alive ping within ten seconds (RFC 5626 section 4.4.1)",
                ),
            ),
        };
        let lost = crate::transport::Lost {
            transport: transport.0,
            protocol: state
                .transports
                .protocol_of(transport.0)
                .map_or(0, crate::stack::SipralTransport::named),
            error,
            tls: crate::transport::SipralTlsFailure::None,
            detail,
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
    // a `SocketAddr` has no bytes to point at
    let destination = crate::event::text_to_point_at(&said);
    // shared so the bytes the translation points into never move
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
    // formatted here, kept with the delivery
    let reason = crate::event::media_reason(said);
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
    /// The media seed of a test stack; it must differ from the entropy.
    pub(crate) const MEDIA_SEED: [u8; 32] = [23; 32];

    /// A config member, named as the header names it, and its setter.
    type Setting = (&'static str, fn(&mut SipralStackConfig));

    /// What a media event said, copied inside the callback.
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

    /// Who a call event said is on the call, copied inside the callback.
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
        /// Who every call event said was on the call.
        pub(crate) calls: Vec<Seen>,
        /// What every subscription event carried, in the order they arrived.
        pub(crate) subscriptions: Vec<Watched>,
        /// What every resolve request carried, in the order they arrived.
        pub(crate) resolves: Vec<Asked>,
        /// What every referral event carried, in the order they arrived.
        pub(crate) referrals: Vec<Referring>,
        /// Every audio-devices event: change, origin, role, device.
        pub(crate) audio: Vec<(u32, u32, u32, u32)>,
        /// Every progress event: what, tone, verdict, reason, when.
        pub(crate) progress: Vec<(u32, u32, u32, u32, u64)>,
        /// Every conference, text and presence event.
        pub(crate) protocols: Vec<Told>,
        /// Every transport-failed event: transport, protocol, error, TLS reason, detail.
        pub(crate) transports_lost: Vec<(u32, u32, u32, u32, String)>,
        /// Every local conference event.
        pub(crate) local_conferences: Vec<crate::local_conference::SipralLocalConferenceEvent>,
        /// Every lookup, location and failed location.
        pub(crate) locating: Vec<crate::locate::tests::Locating>,
        /// Filled by the callbacks that call back into the library.
        reentrant_status: Option<SipralStatus>,
        destroy_status: Option<SipralStatus>,
        /// What creating a stack from inside the callback answered.
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

    /// One media event, read from its union arm inside the callback.
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

    /// A pointer and length copied; empty for null-and-zero.
    fn owned(pointer: *const u8, len: usize) -> Vec<u8> {
        if pointer.is_null() {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(pointer, len) }.to_vec()
        }
    }

    /// One call event's identity, read from its union arm inside the callback.
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

    /// One subscription event, read inside the callback.
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

    /// One conference, text or presence event, copied inside the callback.
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

    /// One `SIPRAL_EVENT_KIND_RESOLVE_NEEDED`, copied inside the callback.
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

    /// One `SIPRAL_EVENT_KIND_REFERRAL`, copied inside the callback.
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

    /// Call in from a thread that is not the one holding the stack. Spawned and
    /// joined inside the callback, so the race is deterministic.
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
            system_echo_cancellation: 0,
            reserved_35: 0,
            held_audio: 0,
            reserved_36: 0,
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

    /// Create a stack on the test's own tags; status plus last error.
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
        // below the pinned minimum, not merely an older header's size
        config.size = <SipralStackConfig as crate::versioned::Versioned>::MIN_SIZE - 1;
        let (status, handle) = create(&config);
        assert_eq!(status, SipralStatus::UnsupportedVersion);
        assert_eq!(handle, SIPRAL_HANDLE_NONE);

        config.size = 0;
        let (status, _) = create(&config);
        assert_eq!(status, SipralStatus::UnsupportedVersion);
    }

    /// A config ending before `srtp` predates the freeze and is refused.
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
            srtp_suite_count: u32::MAX,
            pseudonym_salted: u32::MAX,
            diagnostic_trace: u32::MAX,
            system_echo_cancellation: u32::MAX,
        }
    }

    fn suite_order(handle: SipralHandle) -> Vec<u32> {
        let mut count = usize::MAX;
        let status = unsafe {
            super::sipral_stack_srtp_suite_order(handle, ptr::null_mut(), 0, &raw mut count)
        };
        assert_eq!(
            status,
            SipralStatus::BufferTooSmall,
            "{}",
            last_error_text()
        );
        let mut suites = vec![u32::MAX; count];
        let status = unsafe {
            super::sipral_stack_srtp_suite_order(
                handle,
                suites.as_mut_ptr(),
                suites.len(),
                &raw mut count,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        suites
    }

    /// The 0.34 settings read back: suites, salt given, trace, echo canceller.
    #[test]
    fn the_suites_the_salt_the_trace_and_the_echo_switch_read_back() {
        use crate::media::SipralSrtpSuite;
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let read = read_settings(handle);
        assert_eq!(read.pseudonym_salted, SipralToggle::Off as u32);
        assert_eq!(read.diagnostic_trace, SipralToggle::Off as u32);
        assert_eq!(read.system_echo_cancellation, SipralToggle::On as u32);
        let built_in = suite_order(handle);
        assert_eq!(built_in.len(), read.srtp_suite_count as usize);
        assert!(
            built_in.contains(&(SipralSrtpSuite::AesCm80 as u32)),
            "{built_in:?}"
        );
        assert_eq!(
            unsafe { crate::log::sipral_stack_diagnostic_trace(handle, SipralToggle::On as u32) },
            SipralStatus::Ok
        );
        assert_eq!(
            read_settings(handle).diagnostic_trace,
            SipralToggle::On as u32
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

        let suites = "AES_256_CM_HMAC_SHA1_80,AES_CM_128_HMAC_SHA1_32";
        let salt = [0x5a_u8; 16];
        let mut observed = Observed::default();
        let mut given = config(record, &mut observed);
        given.srtp_suites = suites.as_ptr().cast();
        given.srtp_suites_len = suites.len();
        given.pseudonym_salt = salt.as_ptr();
        given.pseudonym_salt_len = salt.len();
        given.system_echo_cancellation = SipralToggle::Off as u32;
        let (status, handle) = create(&given);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let read = read_settings(handle);
        assert_eq!(read.pseudonym_salted, SipralToggle::On as u32);
        assert_eq!(read.system_echo_cancellation, SipralToggle::Off as u32);
        assert_eq!(read.srtp_suite_count, 2);
        assert_eq!(
            suite_order(handle),
            [
                SipralSrtpSuite::Aes256Cm80 as u32,
                SipralSrtpSuite::AesCm32 as u32
            ]
        );
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

        let mut observed = Observed::default();
        let mut wrong = config(record, &mut observed);
        wrong.system_echo_cancellation = 3;
        assert_eq!(create(&wrong).0, SipralStatus::InvalidArgument);
    }

    /// Without a salt, pseudonyms use a one-way key from the media seed.
    #[test]
    fn the_pseudonym_key_is_derived_from_the_media_seed_and_does_not_hold_it() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let key = with_stack(handle, |state| {
            let held: &sipral::PseudonymKey = &state.pseudonyms;
            Ok(held.to_vec())
        })
        .expect("the stack is live");
        assert_eq!(key.len(), 32);
        assert!(
            !key.windows(8)
                .any(|run| MEDIA_SEED.windows(8).any(|seed| seed == run)),
            "the pseudonym key carries a run of the media seed: {key:?}"
        );
        let mut labelled = MEDIA_SEED.to_vec();
        labelled.extend_from_slice(b"sipral log and state pseudonyms");
        assert_ne!(key, labelled);
        assert_eq!(key, sipral::derived_pseudonym_key(&MEDIA_SEED).to_vec());
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
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

    /// §18.1.1's two figures read back; impossible ones are refused.
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

    /// A stack's suites are offered in order; an unknown one is refused.
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

    /// Best effort offers SDES on the plain profile.
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

    /// An out-of-dialog REFER is refused unless enabled.
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

    /// Registrar keep-alive: default, custom, off, and refused figures.
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

    /// The four ceilings read back as defaults or as given.
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

    /// B2: T2 and T4 are refused on a reliable transport (RFC 3261 §17).
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

    /// A T2 below T1 is refused.
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

    /// A T1 above the default T2 is refused too.
    #[test]
    fn a_t1_raised_past_a_default_t2_is_caught_too() {
        let mut observed = Observed::default();
        let mut config = config(record, &mut observed);
        config.timer_t1_ms = 5_000;
        assert_eq!(create(&config).0, SipralStatus::InvalidArgument);
    }

    /// The media settings read back as applied; toggles never read zero.
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

    /// A4: an unbuildable codec is refused with `SIPRAL_STATUS_NOT_SUPPORTED`.
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

        // without the handshake, refuse rather than place calls in the clear
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
        // shorter than any published length
        let mut out = settings();
        out.size = <crate::stack::SipralStackSettings as crate::versioned::Versioned>::MIN_SIZE - 1;
        assert_eq!(
            unsafe { sipral_stack_settings(handle, &raw mut out) },
            SipralStatus::UnsupportedVersion
        );
        assert_eq!(out.transport, u32::MAX, "nothing was written");
        assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
    }

    /// A settings struct too short is refused before the handle is looked up.
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

    /// RFC 3261 §8.1.1.7 asks a unique branch; §19.3 asks random tags. The needle
    /// is built at runtime so the test does not match itself.
    #[test]
    fn the_entropy_doc_cites_tags_not_via_for_unguessability() {
        // a Windows checkout has CRLF
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

    /// A result struct too short is refused before the handle is looked up.
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

    /// A refused poll does not advance the clock.
    #[test]
    fn a_call_refused_for_a_bad_argument_leaves_the_clock_where_it_was() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        assert_eq!(poll(handle, 1_000).events_delivered, 1);

        // refused for a stale handle, far ahead of the clock
        assert_eq!(
            unsafe { crate::call::sipral_call_hangup(handle, SIPRAL_HANDLE_NONE, 9_000) },
            SipralStatus::InvalidHandle
        );

        // would be behind the slack if the refused call had moved the clock
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
        // must not panic on a platform with a narrow clock
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

    /// Calling back into the stack from the callback is an ordinary call.
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

    /// A second thread inside gets a status, not a wait or a fault.
    #[test]
    fn a_second_thread_calling_in_while_the_stack_is_held_is_told_so() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let refused =
            super::with_stack(handle, |_| {
                // the stack is held for as long as this runs
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

    /// While the callback runs the stack is free for another thread.
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

    /// What a re-entering callback saw. Cells, since it may be re-entered.
    #[derive(Default)]
    struct Nested {
        depth: Cell<usize>,
        deepest: Cell<usize>,
        account: Cell<SipralHandle>,
        kinds: RefCell<Vec<SipralEventKind>>,
        registered: Cell<Option<SipralStatus>>,
        inner: Cell<Option<(SipralStatus, usize)>>,
    }

    /// On the first event, register an account and poll from inside.
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

    /// A nested poll's events go to the next pass, not this one.
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

        // a poll with nothing of its own still delivers what was left
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

    /// A pass that leaves events says the next poll is due now.
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

    /// `held_audio` defaults to silence in every mode.
    #[test]
    fn a_held_party_is_sent_silence_unless_the_application_is_named() {
        use super::SipralHeldAudio;
        use sipral::HeldAudio;
        let of = |held: SipralHeldAudio| super::held_audio_of(held as u32).ok();
        assert_eq!(of(SipralHeldAudio::Default), Some(HeldAudio::Silence));
        assert_eq!(of(SipralHeldAudio::Silence), Some(HeldAudio::Silence));
        assert_eq!(of(SipralHeldAudio::Application), Some(HeldAudio::Captured));
        assert!(super::held_audio_of(3).is_err());
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
        // keeps `StackState`'s `Send` assertion honest
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

    /// The tags the test below uses, reachable from its callback.
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

    /// A stack destroyed from its callback keeps its tag until the poll returns.
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

    /// A full outbox drops a poll's events and counts them.
    #[test]
    fn a_poll_that_finds_the_outbox_at_the_ceiling_drops_its_own_event_and_counts_it() {
        let mut observed = Observed::default();
        let handle = stack(&mut observed);
        let entry = entry_of(handle).expect("the stack exists");

        // filled directly instead of raising 4096 real events
        let filler: Vec<Delivery> = (0..OUTBOX_CEILING)
            .map(|_| Delivery::bare(crate::event::started(handle)))
            .collect();
        let (delivering, dropped) = entry.post(filler);
        assert!(delivering, "nobody else was delivering yet");
        assert_eq!(dropped, 0, "exactly the ceiling fits");

        // a fresh stack's first poll raises "started", which has nowhere to go
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

    /// A callback that floods the stack from a joined second thread.
    struct Flooded {
        entry: Arc<StackEntry>,
        stack: SipralHandle,
        dropped: AtomicUsize,
        /// `1` if the flood became the deliverer, i.e. joined this pass.
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

    /// A pass delivers only what was queued when it began.
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
