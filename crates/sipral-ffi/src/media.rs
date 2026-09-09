// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Audio across the boundary: what this build can encode, what a call agreed,
//! what it is costing, and the four calls that carry the packets.
//!
//! Until this module existed the C ABI carried signalling alone, and an
//! application on the other side of it had to parse its own descriptions, run
//! its own RTP and reach its own conclusions about a bad call. What it could
//! not do was any of that *with* the stack: a softphone written against this
//! library was a softphone that had to bring a second one.
//!
//! # What crosses, and what does not
//!
//! No socket and no device, here as everywhere else in this tree. The
//! application reads a datagram and hands it over
//! ([`sipral_call_media_receive`]); it takes a frame of PCM and gives it to
//! whichever device layer it linked ([`sipral_call_playback`]); it takes one
//! from the microphone and gets a datagram back ([`sipral_call_capture`]); and
//! it asks for the control traffic that is due ([`sipral_stack_poll_rtcp`]).
//! Four calls, and between them the whole media path.
//!
//! Samples are 16-bit, one channel, at [`SipralMediaInfo::sample_rate`], and a
//! frame is exactly [`SipralMediaInfo::frame_samples`] of them. That is the
//! rate the codec hears at and not the one the RTP clock counts in; for G.722
//! those two differ by a factor of two, which is the mistake this ABI exists to
//! make impossible to write.
//!
//! # Which calls have media
//!
//! The ones this stack was asked to manage: placed with `media_address` set in
//! `sipral_call_config_t`, or answered with `sipral_call_answer_media`. A call
//! placed with a description of the caller's own is a call this stack describes
//! nothing for, and every entry point here answers
//! `SIPRAL_STATUS_WRONG_STATE` for it rather than inventing a stream. The two
//! ways of placing a call are exclusive on purpose: two descriptions of one
//! session is one too many.
//!
//! # Addresses
//!
//! As text, `host:port`, UTF-8 and length-delimited, which is how every other
//! address in this ABI crosses. A packet-per-frame conversion is a rounding
//! error next to the encoder that produced the frame, and one shape for every
//! address is worth more than the microseconds.

use std::ffi::c_char;
use std::net::SocketAddr;
use std::slice;
use std::time::{Duration, Instant};

use sipral::{
    Arrival, Codec, CodecCatalog, Direction, MediaError, MediaSession, Playback, RtcpPlan,
    StreamStatistics,
};
use sipral_core::sdp::SdpError;

use crate::error::{Fail, entry, fail};
use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
use crate::stack::{StackState, handle_failed, with_stack, with_stack_at};
use crate::status::SipralStatus;
use crate::text::required_text;
use crate::versioned::{Versioned, read_versioned, write_versioned};

/// The buffer a caller has to bring for one outgoing packet.
///
/// Not a path MTU — RTP does not discover one — but the bound the session
/// itself builds against, so a payload larger than this is a payload no codec
/// in this build produces. It is checked before anything is encoded, because a
/// frame that was encoded and then had nowhere to go is a frame lost from a
/// stream whose timestamps have already moved past it.
pub const SIPRAL_MEDIA_PACKET_BYTES: usize = 1_500;

/// Room enough for any address this ABI writes, the NUL included:
/// `[2001:db8:0000:0000:0000:0000:0000:0001]:65535` and a byte to spare.
pub const SIPRAL_ADDRESS_BYTES: usize = 64;

/// The three answers a setting can give in a struct that starts out zeroed.
///
/// A boolean cannot carry them. Zero is what a caller who filled nothing in
/// leaves behind, so a plain `0`/`1` setting has no way to say "off" that is
/// not also "I said nothing", and the difference is the whole of B2: the
/// library must not turn a control off because the caller never touched it.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SipralToggle {
    /// Nothing was said; whatever this build defaults to.
    Default = 0,
    /// On.
    On = 1,
    /// Off.
    Off = 2,
}

/// One codec this build contains. Names for every member that says which.
///
/// A value here means there is an encoder and a decoder behind it. That is
/// what makes the enumeration worth reporting to a settings screen at all: a
/// list of names the build cannot produce is a list of controls that do
/// nothing.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SipralCodec {
    /// No codec: the call has none, or the event is not about one.
    Unknown = 0,
    /// G.711 mu-law, payload type 0.
    Pcmu = 1,
    /// G.711 A-law, payload type 8.
    Pcma = 2,
    /// G.722, wideband at the price of a narrowband stream.
    G722 = 3,
    /// Opus.
    Opus = 4,
}

/// Which way audio may flow, as seen from here. Names for every `direction`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SipralDirection {
    /// Not negotiated.
    Unknown = 0,
    /// Both ways.
    SendRecv = 1,
    /// This end sends and does not receive, which is what holding the far end
    /// looks like from here.
    SendOnly = 2,
    /// This end receives and does not send.
    RecvOnly = 3,
    /// Neither way, and the stream stays in the session.
    Inactive = 4,
}

/// Where control traffic goes. Names for [`SipralMediaInfo::rtcp`].
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SipralRtcp {
    /// Not negotiated.
    Unknown = 0,
    /// One port carries both (RFC 5761), which happens only where both ends
    /// asked for it.
    Muxed = 1,
    /// A port of its own at each end.
    SeparatePort = 2,
    /// None at all: the peer said it is not using RTCP.
    Off = 3,
}

/// Why media failed. Names for `sipral_media_event_t::fault`.
///
/// The sentence beside it says which case of the kind it was; this is the part
/// a machine acts on, and the two are never the same thing.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SipralMediaFault {
    /// Nothing failed.
    None = 0,
    /// The negotiation settled on something this build cannot encode or
    /// decode, which means the peer answered with a format that was not in the
    /// offer.
    UnsupportedCodec = 1,
    /// The two descriptions agree on nothing that can carry audio.
    NoCommonCodec = 2,
    /// One end refused the stream with a port of zero. The call is up and
    /// carries no audio, which is a thing a peer is allowed to want.
    StreamRefused = 3,
    /// There is no session description to work from.
    NoDescription = 4,
    /// A description could not be read.
    BadDescription = 5,
    /// The recording stopped writing: the disk filled, the file went away.
    Recording = 6,
    /// The codec refused a frame.
    Codec = 7,
    /// Something else the layer below reported and this ABI has no word for.
    Other = 8,
}

/// What a datagram handed to [`sipral_call_media_receive`] turned out to be.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SipralArrival {
    /// Something this ABI has no word for.
    Unknown = 0,
    /// Audio, held for playout.
    Queued = 1,
    /// Audio that was not used: malformed, late, duplicated, from the wrong
    /// address, or on a payload type nobody negotiated. The counters in
    /// [`SipralStreamStats`] say which, over the call.
    Dropped = 2,
    /// A reception or sender report, folded into the statistics.
    Control = 3,
    /// The far end says it is leaving the session (RFC 3550 §6.6). Audio will
    /// stop; the call has not ended until signalling says so.
    Goodbye = 4,
    /// Control traffic that was not believed: from the wrong address, or not a
    /// well-formed compound packet.
    ControlRefused = 5,
}

/// Where the frame [`sipral_call_playback`] just produced came from.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SipralPlayback {
    /// Something this ABI has no word for.
    Unknown = 0,
    /// A packet the far end sent.
    Packet = 1,
    /// One it sent and this end did not get, filled in by the concealment.
    Concealed = 2,
    /// Comfort noise, from an RFC 3389 payload the far end sent instead of
    /// audio.
    ComfortNoise = 3,
    /// Nothing was due: the buffer is still filling, or the far end has
    /// stopped.
    Silence = 4,
}

/// One codec this build contains.
///
/// Set `size` to `sizeof(sipral_codec_info_t)` before the call.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SipralCodecInfo {
    /// How many bytes of this struct the library filled in.
    pub size: usize,
    /// A [`SipralCodec`].
    pub codec: u32,
    /// The RTP timestamp clock, in hertz, which is what goes on the
    /// `a=rtpmap` line.
    pub clock_rate: u32,
    /// The rate the codec actually hears at, which is what the samples crossing
    /// this ABI are in. G.722's two differ, and RFC 3551 §4.5.2 says so.
    pub sample_rate: u32,
    /// The payload type RFC 3551 table 4 assigns it, when it has one.
    pub static_payload_type: u32,
    /// Whether it has one. Opus does not: it is newer than the table and
    /// always travels as a dynamic type.
    pub has_static_payload_type: u32,
}

// Safety: integers, no invariant between them, and zero is a valid value of
// each — a zeroed one reads as the codec that is not a codec.
unsafe impl Versioned for SipralCodecInfo {
    const NAME: &'static str = "sipral_codec_info";
    const MIN_SIZE: usize = size_of::<Self>();

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// What one call's media settled on, and what it is doing now.
///
/// A4's reporting half and as much of D5 as this stack knows: the codec that
/// was agreed, the number it travels under, and the shape of the stream around
/// it. What is deliberately not here is why each other candidate lost —
/// RFC 3264 §6.1 leaves that decision with the peer, and a reason invented on
/// this side would be a reason nobody can act on.
///
/// Set `size` to `sizeof(sipral_media_info_t)` before the call.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SipralMediaInfo {
    /// How many bytes of this struct the library filled in.
    pub size: usize,
    /// A [`SipralCodec`]: what the two ends agreed on.
    pub codec: u32,
    /// The payload type on the wire. It is the offer's own number and not
    /// necessarily ours: a peer that numbers Opus 111 has said what we say
    /// with 96.
    pub payload_type: u32,
    /// The RTP timestamp clock, in hertz.
    pub clock_rate: u32,
    /// The rate the samples crossing this ABI are at.
    pub sample_rate: u32,
    /// How long a frame is, in milliseconds.
    pub frame_ms: u32,
    /// Samples in one frame: exactly what [`sipral_call_playback`] fills and
    /// what [`sipral_call_capture`] wants.
    pub frame_samples: usize,
    /// A [`SipralDirection`].
    pub direction: u32,
    /// Whether this end is meant to be sending. Zero while it holds the far
    /// end, or while the far end has refused to receive.
    pub sending: u32,
    /// Whether this end is meant to be receiving.
    pub receiving: u32,
    /// Whether RFC 4733 named events were agreed.
    pub has_dtmf: u32,
    /// The payload type they travel under, when they were.
    pub dtmf_payload_type: u32,
    /// A [`SipralRtcp`].
    pub rtcp: u32,
    /// Whether the stream is keyed.
    pub secured: u32,
    /// Whether a recording is running on this call.
    pub recording: u32,
    /// How much audio it has taken.
    pub recorded_ms: u64,
    /// Whether the watchdog currently considers inbound audio stopped.
    pub stalled: u32,
}

// Safety: integers, no invariant between them, and zero is a valid value of
// each.
unsafe impl Versioned for SipralMediaInfo {
    const NAME: &'static str = "sipral_media_info";
    const MIN_SIZE: usize = size_of::<Self>();

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// What one call's media has cost, and what it is costing now.
///
/// A6. Cheap enough to read at the frame rate of a user interface — everything
/// in it is already counted and nothing walks a history — and complete enough
/// to keep as the record of a call, which is the same struct delivered with
/// `SIPRAL_EVENT_KIND_MEDIA_STATISTICS` when the call ends.
///
/// The three delays are in microseconds and not milliseconds. Jitter on a
/// healthy call is a fraction of a millisecond, and a figure that reads zero
/// whenever things are going well is a figure nobody looks at twice.
///
/// Set `size` to `sizeof(sipral_stream_stats_t)` before the call.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SipralStreamStats {
    /// How many bytes of this struct the library filled in.
    pub size: usize,
    /// A [`SipralCodec`]: what the call settled on, which is the first thing
    /// anybody looking at a bad call wants to know.
    pub codec: u32,
    /// Whether a round-trip time is known. Zero until a report has come back,
    /// which on a short call may be never: the first one is deliberately
    /// delayed (RFC 3550 §6.2) and a peer that sends no RTCP never provides
    /// one.
    pub has_round_trip: u32,
    /// The round trip, from RTCP.
    pub round_trip_us: u64,
    /// Packets this end has put on the wire.
    pub packets_sent: u64,
    /// Payload octets in them, not counting headers.
    pub octets_sent: u64,
    /// Packets taken in and held for playout.
    pub packets_received: u64,
    /// Sequence numbers that came due with nothing in them.
    pub packets_lost: u64,
    /// Packets that arrived behind the playout point.
    pub packets_late: u64,
    /// Packets thrown out of the window before they could be played.
    pub packets_overflowed: u64,
    /// Packets whose sequence number was already held.
    pub packets_duplicated: u64,
    /// Packets accepted after a higher sequence number had already arrived.
    pub packets_reordered: u64,
    /// Frames dropped in a pause to bring the delay down. Deliberate, and
    /// inaudible when the pause is real.
    pub frames_shrunk: u64,
    /// Frames the concealment was asked to invent in a pause to push the delay
    /// up.
    pub frames_stretched: u64,
    /// How far behind the newest packet the playout point is: the delay the
    /// far end's voice is actually suffering.
    pub delay_us: u64,
    /// What the buffer is aiming at, from the arrival times it has seen.
    pub target_delay_us: u64,
    /// Interarrival jitter, the smoothed mean deviation of transit time
    /// (RFC 3550 §6.4.1).
    pub jitter_us: u64,
    /// Frames concealed as a fraction of frames played, over the last ten
    /// seconds or so. The counters above say what the call has cost; this says
    /// whether it is bad right now.
    pub loss_rate: f32,
    /// One number for a bar on a screen: a hundred for a call with nothing
    /// wrong with it, zero for one nobody can hold. Not a mean opinion score,
    /// and deliberately not shaped like one.
    pub score: f32,
    /// Whether the numbers say this call is in trouble now.
    pub suffering: u32,
    /// How long since a packet last arrived. A live call sits at one frame.
    pub silent_for_ms: u64,
}

// Safety: integers and two floats, no invariant between them, and zero is a
// valid value of each.
unsafe impl Versioned for SipralStreamStats {
    const NAME: &'static str = "sipral_stream_stats";
    const MIN_SIZE: usize = size_of::<Self>();

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// One datagram on its way out, written into the caller's own buffers.
///
/// The caller fills in `size`, the two pointers and the two capacities; the
/// library fills in the two lengths and the bytes. A `len` of zero means there
/// was nothing to send, which on a capture is an ordinary answer: this end may
/// be holding the far end, or silence suppression may have swallowed the frame.
///
/// Both buffers are checked before anything is produced. A packet that was
/// built and then had nowhere to go would be a packet missing from a stream
/// whose timestamps had already moved past it.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SipralMediaPacket {
    /// `sizeof` this struct, as the caller's header declares it.
    pub size: usize,
    /// Where to write the packet. At least [`SIPRAL_MEDIA_PACKET_BYTES`].
    pub data: *mut u8,
    /// How much room `data` has.
    pub capacity: usize,
    /// How much was written. Zero means there was nothing to send.
    pub len: usize,
    /// Where to write the destination, as `host:port` with a trailing NUL. Null
    /// with a capacity of zero for a caller that does not want it.
    pub destination: *mut c_char,
    /// How much room `destination` has. At least [`SIPRAL_ADDRESS_BYTES`] when
    /// it is not null.
    pub destination_capacity: usize,
    /// How many bytes of it were written, the NUL not counted.
    pub destination_len: usize,
}

// Safety: plain data with no invariant between the members. The two pointers
// are the caller's own buffers, as in every other struct here, and all-zero is
// a caller that brought no buffers — which is refused by reading it, not by
// being undefined.
unsafe impl Versioned for SipralMediaPacket {
    const NAME: &'static str = "sipral_media_packet";
    const MIN_SIZE: usize = size_of::<Self>();

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

// -- what the layers below are called up here --------------------------------

/// The name this ABI gives a codec.
pub(crate) const fn named_codec(codec: Codec) -> SipralCodec {
    match codec {
        Codec::Pcmu => SipralCodec::Pcmu,
        Codec::Pcma => SipralCodec::Pcma,
        Codec::G722 => SipralCodec::G722,
        Codec::Opus => SipralCodec::Opus,
        // the layer below has grown a codec this ABI has no number for, and
        // saying so beats picking one that is wrong
        _ => SipralCodec::Unknown,
    }
}

/// The name this ABI gives a direction.
pub(crate) const fn direction_of(direction: Direction) -> SipralDirection {
    match direction {
        Direction::SendRecv => SipralDirection::SendRecv,
        Direction::SendOnly => SipralDirection::SendOnly,
        Direction::RecvOnly => SipralDirection::RecvOnly,
        Direction::Inactive => SipralDirection::Inactive,
    }
}

/// Which kind of failure a media error is.
pub(crate) fn fault_of(error: &MediaError) -> SipralMediaFault {
    match *error {
        MediaError::UnsupportedCodec { .. } | MediaError::UnknownPayload { .. } => {
            SipralMediaFault::UnsupportedCodec
        }
        // two descriptions that settled on no codec is the same failure said
        // one layer down, and it is the one an application acts on
        MediaError::NoCommonCodec | MediaError::Description(SdpError::NoCodec { .. }) => {
            SipralMediaFault::NoCommonCodec
        }
        MediaError::StreamRefused => SipralMediaFault::StreamRefused,
        MediaError::NoDescription => SipralMediaFault::NoDescription,
        MediaError::Description(_) => SipralMediaFault::BadDescription,
        MediaError::Recording(_) | MediaError::NotRecording | MediaError::AlreadyRecording => {
            SipralMediaFault::Recording
        }
        MediaError::Codec(_) => SipralMediaFault::Codec,
        _ => SipralMediaFault::Other,
    }
}

/// Why the media layer would not do it.
///
/// The sentence comes from the error itself, which already names the codec, the
/// interval or the file that was the problem. Only the code is decided here.
pub(crate) fn media_failed(error: &MediaError) -> Fail {
    let status = match *error {
        // the value is right and there is nothing in this build behind it,
        // which is the one case SIPRAL_STATUS_NOT_SUPPORTED exists for. A call
        // that negotiated no telephone event type is the same shape: the key
        // is a real key and this call has nowhere to put it
        MediaError::UnsupportedCodec { .. }
        | MediaError::UnknownPayload { .. }
        | MediaError::NoDtmf => SipralStatus::NotSupported,
        // a value that would be taken if it were corrected, which for a
        // recording means the path the file system refused
        MediaError::NoCodecs
        | MediaError::BadFrameLength { .. }
        | MediaError::Description(_)
        | MediaError::Codec(_)
        | MediaError::Recording(_)
        | MediaError::DigitTooShort { .. }
        | MediaError::UnknownDigit { .. }
        | MediaError::RenderDelayTooLong { .. } => SipralStatus::InvalidArgument,
        MediaError::TooManyDigits => SipralStatus::Exhausted,
        MediaError::NoSuchCall
        | MediaError::NoDescription
        | MediaError::NotRecording
        | MediaError::AlreadyRecording
        | MediaError::NoCommonCodec
        | MediaError::StreamRefused => SipralStatus::WrongState,
        MediaError::PacketTooLong { .. } => SipralStatus::BufferTooSmall,
        MediaError::Signalling(ref refused) => return crate::call::ua_failed(refused),
        _ => SipralStatus::NotSent,
    };
    fail(status, error.to_string())
}

/// The C shape of a statistics record.
pub(crate) fn stream_stats(record: &StreamStatistics) -> SipralStreamStats {
    let quality = record.quality;
    SipralStreamStats {
        size: size_of::<SipralStreamStats>(),
        codec: named_codec(record.codec) as u32,
        has_round_trip: u32::from(record.round_trip.is_some()),
        round_trip_us: record.round_trip.map_or(0, micros),
        packets_sent: record.packets_sent,
        octets_sent: record.octets_sent,
        packets_received: quality.received,
        packets_lost: quality.lost,
        packets_late: quality.discarded_late,
        packets_overflowed: quality.discarded_overflow,
        packets_duplicated: quality.duplicates,
        packets_reordered: quality.reordered,
        frames_shrunk: quality.shrunk,
        frames_stretched: quality.stretched,
        delay_us: micros(quality.delay),
        target_delay_us: micros(quality.target_delay),
        jitter_us: micros(quality.jitter),
        loss_rate: quality.loss_rate,
        score: record.score(),
        suffering: u32::from(record.is_suffering()),
        silent_for_ms: millis(record.silent_for),
    }
}

/// Saturating rather than wrapping: an interval too long to count is one
/// nothing here measured.
fn micros(span: Duration) -> u64 {
    u64::try_from(span.as_micros()).unwrap_or(u64::MAX)
}

fn millis(span: Duration) -> u64 {
    u64::try_from(span.as_millis()).unwrap_or(u64::MAX)
}

/// A setting that can be on, off, or left to this build.
pub(crate) fn toggled(value: u32, name: &'static str, default: bool) -> Result<bool, Fail> {
    match value {
        0 => Ok(default),
        1 => Ok(true),
        2 => Ok(false),
        other => Err(fail(
            SipralStatus::InvalidArgument,
            format!("{name} is {other}, and a setting is 0 for the default, 1 for on or 2 for off"),
        )),
    }
}

/// What that setting came to, for a caller reading its settings back.
pub(crate) const fn toggle_of(value: bool) -> u32 {
    if value {
        SipralToggle::On as u32
    } else {
        SipralToggle::Off as u32
    }
}

/// The catalogue a stack was asked for: an order, a frame length, and the two
/// things an offer says about itself.
///
/// A name this build has no encoder for is refused here, where the caller still
/// knows which string it passed, rather than ignored later where nothing can
/// tell it happened.
pub(crate) fn catalog_of(
    order: Option<&str>,
    frame_ms: u32,
    dtmf: bool,
    rtcp_mux: bool,
) -> Result<CodecCatalog, Fail> {
    let mut catalog = match order {
        Some(list) => ordered(list)?,
        None => CodecCatalog::new(),
    };
    if frame_ms != 0 {
        catalog = catalog
            .with_frame_length(frame_ms)
            .map_err(|error| media_failed(&error))?;
    }
    Ok(catalog.with_dtmf(dtmf).with_rtcp_mux(rtcp_mux))
}

/// The codec order a caller wrote, as a catalogue.
fn ordered(list: &str) -> Result<CodecCatalog, Fail> {
    let named: Vec<&str> = list.split(',').map(str::trim).collect();
    if let Some(empty) = named.iter().position(|name| name.is_empty()) {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!("codecs names nothing at position {empty}, so the list has a stray comma"),
        ));
    }
    // a duplicate would put one payload type on the m= line twice, and the
    // answer to it is a corrected list rather than a different build, so it is
    // told apart from a codec that is genuinely absent
    for (index, name) in named.iter().enumerate() {
        if named
            .iter()
            .take(index)
            .any(|earlier| earlier.eq_ignore_ascii_case(name))
        {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("codecs names {name} twice, and an offer lists each format once"),
            ));
        }
    }
    CodecCatalog::with_order(&named).map_err(|error| media_failed(&error))
}

// -- reaching one call's media -----------------------------------------------

/// Do something with one call's media, or say why there is none.
fn with_session<R>(
    stack: SipralHandle,
    call: SipralHandle,
    act: impl FnOnce(&mut MediaSession) -> Result<R, Fail>,
) -> Result<R, Fail> {
    with_stack(stack, |state| act(session_of(state, call)?))
}

/// The same, at a time the caller names, for the calls that put something on
/// the wire.
fn with_session_at<R>(
    stack: SipralHandle,
    call: SipralHandle,
    now_ms: u64,
    act: impl FnOnce(&mut MediaSession, Instant) -> Result<R, Fail>,
) -> Result<R, Fail> {
    with_stack_at(stack, now_ms, |state, now| {
        act(session_of(state, call)?, now)
    })
}

pub(crate) fn session_of(
    state: &mut StackState,
    call: SipralHandle,
) -> Result<&mut MediaSession, Fail> {
    let id = state.calls.get(call).map_err(handle_failed)?;
    state.engine.session(id).ok_or_else(|| {
        fail(
            SipralStatus::WrongState,
            "this call has no media: it was not placed or answered with a media address of its \
             own, or its negotiation has not settled yet",
        )
    })
}

// -- what this build contains ------------------------------------------------

entry! {
    /// The name of a codec, as a static NUL-terminated string, or null for a
    /// number this build has no codec for.
    ///
    /// It is spelled as IANA registered it, which is also how it goes on an
    /// `a=rtpmap` line. The string belongs to the library and lives as long as
    /// it is loaded.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns, and is safe to call from any thread.
    fn sipral_codec_name(codec: u32) -> *const c_char, on_panic = std::ptr::null(), {
        match codec {
            1 => c"PCMU".as_ptr(),
            2 => c"PCMA".as_ptr(),
            3 => c"G722".as_ptr(),
            4 => c"opus".as_ptr(),
            _ => std::ptr::null(),
        }
    }
}

entry! {
    /// How many codecs this build contains.
    ///
    /// A compile-time fact, and the reason A4 starts here rather than at a
    /// configuration: no setting can add a codec that was not linked.
    ///
    /// # Safety
    ///
    /// `out_count` must point at one `size_t`.
    fn sipral_codec_count(out_count: *mut usize) {
        if out_count.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_count is null"));
        }
        unsafe { out_count.write(Codec::ALL.len()) };
        Ok(())
    }
}

entry! {
    /// One of them, by index, from zero to what `sipral_codec_count` said.
    ///
    /// The order is this build's own preference, quality first, which is what
    /// is offered when nobody has said otherwise.
    ///
    /// # Safety
    ///
    /// `out_info` must point at a `sipral_codec_info_t` whose `size` member
    /// says how long it is.
    fn sipral_codec_at(index: usize, out_info: *mut SipralCodecInfo) {
        let Some(codec) = Codec::ALL.get(index).copied() else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("there is no codec {index}; this build has {}", Codec::ALL.len()),
            ));
        };
        let info = SipralCodecInfo {
            size: size_of::<SipralCodecInfo>(),
            codec: named_codec(codec) as u32,
            clock_rate: codec.clock_rate(),
            sample_rate: codec.sample_rate(),
            static_payload_type: u32::from(codec.static_payload().unwrap_or(0)),
            has_static_payload_type: u32::from(codec.static_payload().is_some()),
        };
        unsafe { write_versioned(out_info, info) }
    }
}

entry! {
    /// The codecs this stack offers, in the order it offers them.
    ///
    /// The other half of the configuration: `codecs` in
    /// `sipral_stack_config_t` says what to offer, and this says what that came
    /// to. `out_count` always receives the number there are, so a caller that
    /// passes a capacity of zero and a null buffer learns how much room to
    /// bring and gets `SIPRAL_STATUS_BUFFER_TOO_SMALL`.
    ///
    /// # Safety
    ///
    /// `out_codecs` must be writable for `capacity` `uint32_t` or null with a
    /// capacity of zero, and `out_count` must point at one `size_t` or be null.
    fn sipral_stack_codec_order(
        stack: SipralHandle,
        out_codecs: *mut u32,
        capacity: usize,
        out_count: *mut usize,
    ) {
        if out_codecs.is_null() && capacity != 0 {
            return Err(fail(SipralStatus::InvalidArgument, "out_codecs is null"));
        }
        let order = with_stack(stack, |state| {
            Ok(state
                .engine
                .catalog()
                .codecs()
                .iter()
                .map(|codec| named_codec(*codec) as u32)
                .collect::<Vec<u32>>())
        })?;
        if !out_count.is_null() {
            unsafe { out_count.write(order.len()) };
        }
        if capacity < order.len() {
            return Err(fail(
                SipralStatus::BufferTooSmall,
                format!("this stack offers {} codecs and there is room for {capacity}", order.len()),
            ));
        }
        // the capacity reaches the length, so a non-empty order has a buffer
        unsafe { std::ptr::copy_nonoverlapping(order.as_ptr(), out_codecs, order.len()) };
        Ok(())
    }
}

// -- what one call agreed, and what it cost ----------------------------------

entry! {
    /// What one call's media settled on.
    ///
    /// # Safety
    ///
    /// `out_info` must point at a `sipral_media_info_t` whose `size` member
    /// says how long it is.
    fn sipral_call_media_info(
        stack: SipralHandle,
        call: SipralHandle,
        out_info: *mut SipralMediaInfo,
    ) {
        let info = with_session(stack, call, |session| {
            // checked before it is filled in, so a caller that got its size
            // wrong is told that and not something about the call
            unsafe { crate::versioned::declared_size(out_info.cast_const()) }?;
            Ok(media_info(session))
        })?;
        unsafe { write_versioned(out_info, info) }
    }
}

fn media_info(session: &MediaSession) -> SipralMediaInfo {
    let plan = session.plan();
    SipralMediaInfo {
        size: size_of::<SipralMediaInfo>(),
        codec: named_codec(session.codec()) as u32,
        payload_type: u32::from(plan.codec.payload()),
        clock_rate: plan.codec.clock_rate(),
        sample_rate: session.sample_rate(),
        frame_ms: session.frame_length(),
        frame_samples: session.frame_samples(),
        direction: direction_of(session.direction()) as u32,
        sending: u32::from(session.is_sending()),
        receiving: u32::from(session.is_receiving()),
        has_dtmf: u32::from(plan.dtmf.is_some()),
        dtmf_payload_type: u32::from(plan.dtmf.unwrap_or(0)),
        rtcp: rtcp_of(plan.rtcp) as u32,
        secured: u32::from(plan.keying.is_some()),
        recording: u32::from(session.is_recording()),
        recorded_ms: session.recorded().map_or(0, millis),
        stalled: u32::from(session.is_stalled()),
    }
}

const fn rtcp_of(plan: RtcpPlan) -> SipralRtcp {
    match plan {
        RtcpPlan::Muxed => SipralRtcp::Muxed,
        RtcpPlan::SeparatePort { .. } => SipralRtcp::SeparatePort,
        RtcpPlan::Off => SipralRtcp::Off,
    }
}

entry! {
    /// What one call's media has cost, and what it is costing now.
    ///
    /// A6's live half. `now_ms` is the caller's monotonic clock, as everywhere
    /// else, because "how long since a packet arrived" is a question about the
    /// present and nothing here reads a clock to answer it. Unlike
    /// `sipral_stack_poll`, this does not move the stack's own clock: it is
    /// read at the frame rate of a user interface, often from the thread that
    /// draws one, and a reading a millisecond behind the last poll is not a
    /// caller bug.
    ///
    /// The end-of-call record arrives instead as
    /// `SIPRAL_EVENT_KIND_MEDIA_STATISTICS`, because by then the stream is
    /// gone and there is nothing left here to ask.
    ///
    /// # Safety
    ///
    /// `out_stats` must point at a `sipral_stream_stats_t` whose `size` member
    /// says how long it is.
    fn sipral_call_statistics(
        stack: SipralHandle,
        call: SipralHandle,
        now_ms: u64,
        out_stats: *mut SipralStreamStats,
    ) {
        let stats = with_stack(stack, |state| {
            unsafe { crate::versioned::declared_size(out_stats.cast_const()) }?;
            // `instant` rather than `advance`: reading does not move the
            // stack's clock, so a figure taken a millisecond behind the last
            // poll is not refused for going backwards
            let now = state.instant(now_ms)?;
            let session = session_of(state, call)?;
            Ok(stream_stats(&session.statistics(now)))
        })?;
        unsafe { write_versioned(out_stats, stats) }
    }
}

// -- the packets -------------------------------------------------------------

entry! {
    /// Take a datagram off the media socket.
    ///
    /// One entry point for both sockets: RTP and RTCP are told apart by
    /// RFC 5761 §4's rule on the payload type field, so a caller that put both
    /// on one socket does not have to sort them, and one that did not can hand
    /// over whichever arrived.
    ///
    /// `data` is written through. A secured stream is opened in place, and a
    /// caller that needs the ciphertext afterwards keeps its own copy.
    ///
    /// `out_arrival` may be null for a caller that does not want to know what
    /// the datagram turned out to be.
    ///
    /// # Safety
    ///
    /// `data` must be readable and writable for `len` bytes, `from` readable
    /// for `from_len`, and `out_arrival` must point at one `uint32_t` or be
    /// null.
    fn sipral_call_media_receive(
        stack: SipralHandle,
        call: SipralHandle,
        data: *mut u8,
        len: usize,
        from: *const c_char,
        from_len: usize,
        now_ms: u64,
        out_arrival: *mut u32,
    ) {
        if data.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "data is null"));
        }
        if len == 0 || len > SIPRAL_MEDIA_PACKET_BYTES {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("data says it is {len} bytes, and a datagram is 1 to {SIPRAL_MEDIA_PACKET_BYTES}"),
            ));
        }
        let peer = unsafe { address(from, from_len, "from") }?;
        let arrival = with_session_at(stack, call, now_ms, |session, now| {
            let datagram = unsafe { slice::from_raw_parts_mut(data, len) };
            Ok(session.receive(datagram, peer, now))
        })?;
        if !out_arrival.is_null() {
            unsafe { out_arrival.write(arrival_of(arrival) as u32) };
        }
        Ok(())
    }
}

const fn arrival_of(arrival: Arrival) -> SipralArrival {
    match arrival {
        Arrival::Queued => SipralArrival::Queued,
        Arrival::Dropped(_) => SipralArrival::Dropped,
        Arrival::Control => SipralArrival::Control,
        Arrival::Goodbye => SipralArrival::Goodbye,
        Arrival::ControlRefused => SipralArrival::ControlRefused,
        _ => SipralArrival::Unknown,
    }
}

entry! {
    /// Take the frame that is due for the earpiece, and say where it came from.
    ///
    /// Exactly `sipral_media_info_t::frame_samples` samples are written, and a
    /// smaller buffer is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with the number
    /// needed in `out_written`. Every source fills the frame, concealment and
    /// silence included: a device handed nothing for one frame plays whatever
    /// was in its buffer last, and that is a far worse sound than the one being
    /// concealed.
    ///
    /// # Safety
    ///
    /// `samples` must be writable for `capacity` `int16_t`, `out_written` must
    /// point at one `size_t` or be null, and `out_source` at one `uint32_t` or
    /// be null.
    fn sipral_call_playback(
        stack: SipralHandle,
        call: SipralHandle,
        samples: *mut i16,
        capacity: usize,
        out_written: *mut usize,
        out_source: *mut u32,
    ) {
        if samples.is_null() && capacity != 0 {
            return Err(fail(SipralStatus::InvalidArgument, "samples is null"));
        }
        let played = with_session(stack, call, |session| {
            let frame = session.frame_samples();
            if !out_written.is_null() {
                unsafe { out_written.write(frame) };
            }
            if capacity < frame {
                return Err(fail(
                    SipralStatus::BufferTooSmall,
                    format!("a frame is {frame} samples and there is room for {capacity}"),
                ));
            }
            // the capacity reaches the frame, so the buffer is not null
            let out = unsafe { slice::from_raw_parts_mut(samples, frame) };
            Ok(session.playback(out))
        })?;
        if !out_source.is_null() {
            unsafe { out_source.write(playback_of(played) as u32) };
        }
        Ok(())
    }
}

const fn playback_of(played: Playback) -> SipralPlayback {
    match played {
        Playback::Packet => SipralPlayback::Packet,
        Playback::Concealed => SipralPlayback::Concealed,
        Playback::ComfortNoise => SipralPlayback::ComfortNoise,
        Playback::Silence => SipralPlayback::Silence,
        _ => SipralPlayback::Unknown,
    }
}

entry! {
    /// Put one frame from the microphone on the wire.
    ///
    /// `sample_count` is `sipral_media_info_t::frame_samples` and nothing else:
    /// a codec cuts one frame at one length, and half a frame encoded as a
    /// whole one is what a peer hears as a stutter.
    ///
    /// A `len` of zero in the packet means the frame was deliberately not sent:
    /// this end is holding the far end, or silence suppression swallowed it.
    /// The RTP timestamp moves by a frame either way, because RFC 3550 §5.1
    /// makes it a measure of time rather than of packets.
    ///
    /// # Safety
    ///
    /// `samples` must be readable for `sample_count` `int16_t`, and `packet`
    /// must point at a `sipral_media_packet_t` whose `size` member says how
    /// long it is and whose buffers are writable for the capacities beside
    /// them.
    fn sipral_call_capture(
        stack: SipralHandle,
        call: SipralHandle,
        samples: *const i16,
        sample_count: usize,
        packet: *mut SipralMediaPacket,
    ) {
        let mut out = unsafe { read_versioned(packet) }?;
        prepare(&mut out)?;
        if samples.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "samples is null"));
        }
        with_session(stack, call, |session| {
            let frame = session.frame_samples();
            if sample_count != frame {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    format!("a frame of this call is {frame} samples and {sample_count} were given"),
                ));
            }
            let taken = unsafe { slice::from_raw_parts(samples, frame) };
            let sent = session.capture(taken).map_err(|error| media_failed(&error))?;
            match sent {
                Some(datagram) => unsafe { put(&mut out, datagram.destination, datagram.payload) },
                None => Ok(()),
            }
        })?;
        unsafe { write_versioned(packet, out) }
    }
}

entry! {
    /// The control traffic that is due, for whichever call is due one.
    ///
    /// One at a time, like every other poll here: a caller loops until the
    /// packet comes back with a `len` of zero. `out_call` names the call it
    /// belongs to, and therefore the socket it goes out on.
    ///
    /// RFC 3550 §6.3 decides when. Call this whenever `sipral_stack_poll`
    /// reports a deadline and whenever a frame goes out; on a call that
    /// negotiated no RTCP it answers zero for ever.
    ///
    /// # Safety
    ///
    /// `out_call` must point at one `sipral_handle_t` or be null, and `packet`
    /// at a `sipral_media_packet_t` as [`sipral_call_capture`] describes.
    fn sipral_stack_poll_rtcp(
        stack: SipralHandle,
        now_ms: u64,
        out_call: *mut SipralHandle,
        packet: *mut SipralMediaPacket,
    ) {
        let mut out = unsafe { read_versioned(packet) }?;
        prepare(&mut out)?;
        let named = with_stack_at(stack, now_ms, |state, now| {
            let Some((call, datagram)) = state.engine.poll_rtcp(now) else {
                return Ok(SIPRAL_HANDLE_NONE);
            };
            unsafe { put(&mut out, datagram.destination, datagram.payload) }?;
            Ok(state.calls.name_of(call).unwrap_or(SIPRAL_HANDLE_NONE))
        })?;
        if !out_call.is_null() {
            unsafe { out_call.write(named) };
        }
        unsafe { write_versioned(packet, out) }
    }
}

/// Check the caller brought buffers big enough for anything this can produce,
/// and empty the two lengths it is about to fill in.
///
/// Asked before anything is built, so that a packet is never made and then
/// dropped for want of somewhere to put it. The lengths are cleared here for
/// the same reason the buffers are checked here: they are the library's to
/// write, and whatever the caller left in them must never read as a packet that
/// was produced.
fn prepare(packet: &mut SipralMediaPacket) -> Result<(), Fail> {
    packet.len = 0;
    packet.destination_len = 0;
    if packet.data.is_null() || packet.capacity < SIPRAL_MEDIA_PACKET_BYTES {
        return Err(fail(
            SipralStatus::BufferTooSmall,
            format!(
                "a packet buffer is at least {SIPRAL_MEDIA_PACKET_BYTES} bytes and there is room \
                 for {}",
                packet.capacity
            ),
        ));
    }
    if !packet.destination.is_null() && packet.destination_capacity < SIPRAL_ADDRESS_BYTES {
        return Err(fail(
            SipralStatus::BufferTooSmall,
            format!(
                "an address buffer is at least {SIPRAL_ADDRESS_BYTES} bytes and there is room for \
                 {}",
                packet.destination_capacity
            ),
        ));
    }
    Ok(())
}

/// Put one datagram in the caller's buffers.
///
/// # Safety
///
/// The buffers in `packet` must be writable for the capacities beside them,
/// which [`prepare`] has already been asked about.
unsafe fn put(
    packet: &mut SipralMediaPacket,
    destination: SocketAddr,
    payload: &[u8],
) -> Result<(), Fail> {
    unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), packet.data, payload.len()) };
    packet.len = payload.len();
    if packet.destination.is_null() {
        return Ok(());
    }
    let written = destination.to_string();
    if written.len() >= SIPRAL_ADDRESS_BYTES {
        // an address longer than the room this ABI promises cannot happen: the
        // longest a socket address prints as is a bracketed IPv6 and a port
        return Err(fail(
            SipralStatus::BufferTooSmall,
            format!("the destination prints as {} bytes", written.len()),
        ));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            written.as_ptr().cast::<c_char>(),
            packet.destination,
            written.len(),
        );
        packet.destination.add(written.len()).write(0);
    }
    packet.destination_len = written.len();
    Ok(())
}

/// An address a caller supplied, as one.
///
/// # Safety
///
/// `pointer` must be readable for `len` bytes.
pub(crate) unsafe fn address(
    pointer: *const c_char,
    len: usize,
    name: &'static str,
) -> Result<SocketAddr, Fail> {
    let written = unsafe { required_text(pointer, len, name) }?;
    written.parse::<SocketAddr>().map_err(|_| {
        fail(
            SipralStatus::InvalidArgument,
            format!("{name} is {written:?}, which is not an address and a port"),
        )
    })
}

// -- dialling ----------------------------------------------------------------

/// Put a whole dial string in the media, as named telephone events.
///
/// Reached from [`sipral_call_send_dtmf`](crate::call), which chooses between
/// this and the two INFO bodies.
pub(crate) fn dial_in_media(
    state: &mut StackState,
    call: sipral_ua::CallHandle,
    keys: &str,
    length: Duration,
) -> Result<(), Fail> {
    let session = state.engine.session(call).ok_or_else(|| {
        fail(
            SipralStatus::WrongState,
            "this call has no media to put a digit in: it was not placed or answered with a media \
             address of its own, or its negotiation has not settled yet",
        )
    })?;
    session
        .dial(keys, length)
        .map(|_| ())
        .map_err(|error| media_failed(&error))
}

entry! {
    /// Whether a digit is going out or waiting to, and how many have not
    /// started yet.
    ///
    /// Either out parameter may be null. A user interface that greys out the
    /// keypad while a number is being sent wants the first; one that shows how
    /// much of a pasted number is left wants the second.
    ///
    /// # Safety
    ///
    /// `out_dialling` must point at one `uint32_t` or be null, and
    /// `out_waiting` at one `size_t` or be null.
    fn sipral_call_dialling(
        stack: SipralHandle,
        call: SipralHandle,
        out_dialling: *mut u32,
        out_waiting: *mut usize,
    ) {
        let (busy, waiting) = with_session(stack, call, |session| {
            Ok((session.is_dialling(), session.digits_waiting()))
        })?;
        if !out_dialling.is_null() {
            unsafe { out_dialling.write(u32::from(busy)) };
        }
        if !out_waiting.is_null() {
            unsafe { out_waiting.write(waiting) };
        }
        Ok(())
    }
}

entry! {
    /// Drop everything queued and stop the digit going out.
    ///
    /// The digit in flight gets no closing packet, which is right for a call
    /// whose media is being taken away: there is nowhere left to send one.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns.
    fn sipral_call_stop_dialling(stack: SipralHandle, call: SipralHandle) {
        with_session(stack, call, |session| {
            session.stop_dialling();
            Ok(())
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::toggled;
    use super::{
        Codec, SIPRAL_ADDRESS_BYTES, SIPRAL_MEDIA_PACKET_BYTES, SipralArrival, SipralCodec,
        SipralCodecInfo, SipralDirection, SipralMediaFault, SipralMediaInfo, SipralMediaPacket,
        SipralPlayback, SipralRtcp, SipralStreamStats, SipralToggle, catalog_of, media_failed,
        named_codec, ordered, sipral_call_capture, sipral_call_media_info,
        sipral_call_media_receive, sipral_call_playback, sipral_call_statistics, sipral_codec_at,
        sipral_codec_count, sipral_codec_name, sipral_stack_codec_order, sipral_stack_poll_rtcp,
    };
    use crate::call::tests::{
        PEER_MEDIA, connected, hangup, media_call, media_call_refused, media_call_tuned, media_line,
    };
    use crate::error::last_error_text;
    use crate::event::SipralEventKind;
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::stack::tests::Observed;
    use crate::status::SipralStatus;
    use sipral::MediaError;
    use std::ffi::{CStr, c_char};
    use std::net::SocketAddr;
    use std::ptr;

    /// Samples in one frame of the codec every media fixture negotiates:
    /// G.711 at eight kilohertz, twenty milliseconds.
    pub(crate) const FRAME: usize = 160;

    /// An order naming two of the four this build contains, to read back.
    const ORDER: &str = "G722,PCMA";

    /// One RTP packet of mu-law from the far end: version two, payload type
    /// zero, and a source of its own.
    fn rtp(sequence: u16, timestamp: u32) -> Vec<u8> {
        let mut out = vec![0x80, 0x00];
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&timestamp.to_be_bytes());
        out.extend_from_slice(&0xDEAD_BEEF_u32.to_be_bytes());
        out.extend_from_slice(&[0xFF; FRAME]);
        out
    }

    /// A media info struct with nothing in it, so that a call that writes
    /// nothing can be told from one that wrote zeroes.
    pub(crate) fn media_info_zeroed() -> SipralMediaInfo {
        SipralMediaInfo {
            size: size_of::<SipralMediaInfo>(),
            codec: u32::MAX,
            payload_type: u32::MAX,
            clock_rate: u32::MAX,
            sample_rate: u32::MAX,
            frame_ms: u32::MAX,
            frame_samples: usize::MAX,
            direction: u32::MAX,
            sending: u32::MAX,
            receiving: u32::MAX,
            has_dtmf: u32::MAX,
            dtmf_payload_type: u32::MAX,
            rtcp: u32::MAX,
            secured: u32::MAX,
            recording: u32::MAX,
            recorded_ms: u64::MAX,
            stalled: u32::MAX,
        }
    }

    /// Buffers big enough for anything this build produces, as the ABI asks.
    pub(crate) struct Buffers {
        packet: [u8; SIPRAL_MEDIA_PACKET_BYTES],
        address: [c_char; SIPRAL_ADDRESS_BYTES],
    }

    impl Buffers {
        pub(crate) fn new() -> Self {
            Self {
                packet: [0; SIPRAL_MEDIA_PACKET_BYTES],
                address: [0; SIPRAL_ADDRESS_BYTES],
            }
        }

        pub(crate) fn packet(&mut self) -> SipralMediaPacket {
            SipralMediaPacket {
                size: size_of::<SipralMediaPacket>(),
                data: self.packet.as_mut_ptr(),
                capacity: self.packet.len(),
                len: usize::MAX,
                destination: self.address.as_mut_ptr(),
                destination_capacity: self.address.len(),
                destination_len: usize::MAX,
            }
        }

        /// What was written, and where it was going.
        pub(crate) fn taken(&self, packet: &SipralMediaPacket) -> (Vec<u8>, String) {
            let payload = self.packet[..packet.len].to_vec();
            let written = unsafe { CStr::from_ptr(self.address.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            (payload, written)
        }
    }

    /// Take the frame that is due for the earpiece.
    pub(crate) fn play_one(stack: SipralHandle, call: SipralHandle) -> SipralPlayback {
        let mut samples = [0_i16; FRAME];
        let mut written = 0_usize;
        let mut source = u32::MAX;
        let status = unsafe {
            sipral_call_playback(
                stack,
                call,
                samples.as_mut_ptr(),
                samples.len(),
                &raw mut written,
                &raw mut source,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(written, FRAME);
        match source {
            1 => SipralPlayback::Packet,
            2 => SipralPlayback::Concealed,
            3 => SipralPlayback::ComfortNoise,
            4 => SipralPlayback::Silence,
            _ => SipralPlayback::Unknown,
        }
    }

    /// Put one frame on the wire, and say how long the packet was.
    pub(crate) fn capture_one(stack: SipralHandle, call: SipralHandle, samples: &[i16]) -> usize {
        let mut buffers = Buffers::new();
        let mut packet = buffers.packet();
        let status = unsafe {
            sipral_call_capture(
                stack,
                call,
                samples.as_ptr(),
                samples.len(),
                &raw mut packet,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        packet.len
    }

    pub(crate) fn media_info(stack: SipralHandle, call: SipralHandle) -> SipralMediaInfo {
        let mut info = media_info_zeroed();
        let status = unsafe { sipral_call_media_info(stack, call, &raw mut info) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        info
    }

    pub(crate) fn statistics(
        stack: SipralHandle,
        call: SipralHandle,
        now_ms: u64,
    ) -> SipralStreamStats {
        let mut read = empty_stats();
        let status = unsafe { sipral_call_statistics(stack, call, now_ms, &raw mut read) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        read
    }

    pub(crate) fn empty_stats() -> SipralStreamStats {
        SipralStreamStats {
            size: size_of::<SipralStreamStats>(),
            codec: u32::MAX,
            has_round_trip: u32::MAX,
            round_trip_us: u64::MAX,
            packets_sent: u64::MAX,
            octets_sent: u64::MAX,
            packets_received: u64::MAX,
            packets_lost: u64::MAX,
            packets_late: u64::MAX,
            packets_overflowed: u64::MAX,
            packets_duplicated: u64::MAX,
            packets_reordered: u64::MAX,
            frames_shrunk: u64::MAX,
            frames_stretched: u64::MAX,
            delay_us: u64::MAX,
            target_delay_us: u64::MAX,
            jitter_us: u64::MAX,
            loss_rate: -1.0,
            score: -1.0,
            suffering: u32::MAX,
            silent_for_ms: u64::MAX,
        }
    }

    /// Hand a datagram to a call as if it had arrived on the media socket.
    pub(crate) fn arrive(
        stack: SipralHandle,
        call: SipralHandle,
        datagram: &mut [u8],
        from: &str,
        now_ms: u64,
    ) -> SipralArrival {
        let mut arrival = u32::MAX;
        let status = unsafe {
            sipral_call_media_receive(
                stack,
                call,
                datagram.as_mut_ptr(),
                datagram.len(),
                from.as_ptr().cast::<c_char>(),
                from.len(),
                now_ms,
                &raw mut arrival,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        match arrival {
            1 => SipralArrival::Queued,
            2 => SipralArrival::Dropped,
            3 => SipralArrival::Control,
            4 => SipralArrival::Goodbye,
            5 => SipralArrival::ControlRefused,
            _ => SipralArrival::Unknown,
        }
    }

    fn name(codec: u32) -> Option<String> {
        let pointer = unsafe { sipral_codec_name(codec) };
        if pointer.is_null() {
            return None;
        }
        Some(
            unsafe { CStr::from_ptr(pointer) }
                .to_string_lossy()
                .into_owned(),
        )
    }

    /// The names are written out rather than derived, so this is what says the
    /// two agree. A name that drifted from the one on the `a=rtpmap` line would
    /// be a settings screen naming a codec no peer has heard of.
    #[test]
    fn every_codec_is_named_the_way_it_goes_on_the_wire() {
        for codec in Codec::ALL {
            let number = named_codec(codec) as u32;
            assert_eq!(
                name(number).as_deref(),
                Some(codec.encoding_name()),
                "{codec:?} is named differently here and on the wire"
            );
        }
    }

    #[test]
    fn the_codec_numbers_are_where_they_were_published() {
        assert_eq!(SipralCodec::Unknown as u32, 0);
        assert_eq!(SipralCodec::Pcmu as u32, 1);
        assert_eq!(SipralCodec::Pcma as u32, 2);
        assert_eq!(SipralCodec::G722 as u32, 3);
        assert_eq!(SipralCodec::Opus as u32, 4);
        assert_eq!(name(0), None, "no codec is zero");
        assert_eq!(name(5), None);
        assert_eq!(name(u32::MAX), None);
    }

    #[test]
    fn nothing_that_means_absent_shares_a_number_with_something_that_does_not() {
        assert_eq!(SipralCodec::Unknown as u32, 0);
        assert_eq!(SipralDirection::Unknown as u32, 0);
        assert_eq!(SipralRtcp::Unknown as u32, 0);
        assert_eq!(SipralMediaFault::None as u32, 0);
        assert_eq!(SipralToggle::Default as u32, 0);
    }

    #[test]
    fn the_build_enumerates_what_it_contains() {
        let mut count = 0_usize;
        assert_eq!(
            unsafe { sipral_codec_count(&raw mut count) },
            SipralStatus::Ok
        );
        assert_eq!(count, Codec::ALL.len());

        let mut seen = Vec::new();
        for index in 0..count {
            let mut info = SipralCodecInfo {
                size: size_of::<SipralCodecInfo>(),
                codec: u32::MAX,
                clock_rate: u32::MAX,
                sample_rate: u32::MAX,
                static_payload_type: u32::MAX,
                has_static_payload_type: u32::MAX,
            };
            assert_eq!(
                unsafe { sipral_codec_at(index, &raw mut info) },
                SipralStatus::Ok
            );
            assert!(name(info.codec).is_some());
            seen.push(info);
        }
        assert_eq!(seen.len(), Codec::ALL.len());
        let wideband = seen
            .iter()
            .find(|info| info.codec == SipralCodec::G722 as u32)
            .expect("this build contains G.722");
        assert_eq!(wideband.clock_rate, 8_000, "what the rtpmap line says");
        assert_eq!(wideband.sample_rate, 16_000, "what it hears at");
        assert_eq!(wideband.has_static_payload_type, 1);
        assert_eq!(wideband.static_payload_type, 9);

        let opus = seen
            .iter()
            .find(|info| info.codec == SipralCodec::Opus as u32)
            .expect("this build contains Opus");
        assert_eq!(opus.has_static_payload_type, 0);
        assert_eq!(opus.static_payload_type, 0);
    }

    #[test]
    fn there_is_no_codec_past_the_end() {
        let mut info = SipralCodecInfo {
            size: size_of::<SipralCodecInfo>(),
            codec: u32::MAX,
            clock_rate: 0,
            sample_rate: 0,
            static_payload_type: 0,
            has_static_payload_type: 0,
        };
        assert_eq!(
            unsafe { sipral_codec_at(Codec::ALL.len(), &raw mut info) },
            SipralStatus::InvalidArgument
        );
        assert_eq!(info.codec, u32::MAX, "nothing was written");
        assert_eq!(
            unsafe { sipral_codec_at(0, ptr::null_mut()) },
            SipralStatus::InvalidArgument
        );
    }

    /// A4's rule, and the one that costs months when it is broken: a codec
    /// order naming something this build cannot encode is refused where it is
    /// set, with the status that means "there is nothing here behind that
    /// value" rather than the one that means "try a different value".
    #[test]
    fn a_codec_this_build_has_no_encoder_for_is_refused_where_it_is_set() {
        let refused = ordered("PCMA,G729").expect_err("G.729 is not in this build");
        assert_eq!(refused.status, SipralStatus::NotSupported);

        let refused = ordered("speex").expect_err("nor is Speex");
        assert_eq!(refused.status, SipralStatus::NotSupported);
    }

    /// A duplicate is a different mistake and gets a different answer: a
    /// corrected list would be taken, so it is an argument that was wrong
    /// rather than a build that is missing something.
    #[test]
    fn a_codec_named_twice_is_an_argument_that_was_wrong() {
        let refused = ordered("PCMU,pcmu").expect_err("one format is listed once");
        assert_eq!(refused.status, SipralStatus::InvalidArgument);

        let refused = ordered("PCMU,,PCMA").expect_err("a stray comma names nothing");
        assert_eq!(refused.status, SipralStatus::InvalidArgument);
    }

    #[test]
    fn an_order_that_names_what_this_build_has_is_taken_in_that_order() {
        let catalog = ordered(" opus , PCMA ").expect("both are in this build");
        assert_eq!(catalog.codecs(), [Codec::Opus, Codec::Pcma]);
    }

    #[test]
    fn a_frame_length_no_codec_in_the_order_cuts_is_refused() {
        let refused = catalog_of(Some("opus"), 7, true, false)
            .expect_err("Opus has a fixed set of frame durations");
        assert_eq!(refused.status, SipralStatus::InvalidArgument);

        let taken = catalog_of(Some("PCMU"), 7, true, false)
            .expect("G.711 cuts a whole number of samples at any millisecond");
        assert_eq!(taken.frame_length(), 7);
    }

    #[test]
    fn a_setting_says_nothing_by_being_zero() {
        assert_eq!(toggled(0, "dtmf", true).ok(), Some(true));
        assert_eq!(toggled(0, "dtmf", false).ok(), Some(false));
        assert_eq!(toggled(1, "dtmf", false).ok(), Some(true));
        assert_eq!(toggled(2, "dtmf", true).ok(), Some(false));
        let refused = toggled(3, "dtmf", true).expect_err("three is not an answer");
        assert_eq!(refused.status, SipralStatus::InvalidArgument);
    }

    #[test]
    fn every_media_failure_has_a_code_a_machine_can_switch_on() {
        let cases = [
            (
                MediaError::unsupported("G729"),
                SipralStatus::NotSupported,
                SipralMediaFault::UnsupportedCodec,
            ),
            (
                MediaError::NoCommonCodec,
                SipralStatus::WrongState,
                SipralMediaFault::NoCommonCodec,
            ),
            (
                MediaError::StreamRefused,
                SipralStatus::WrongState,
                SipralMediaFault::StreamRefused,
            ),
            (
                MediaError::NotRecording,
                SipralStatus::WrongState,
                SipralMediaFault::Recording,
            ),
            (
                MediaError::AlreadyRecording,
                SipralStatus::WrongState,
                SipralMediaFault::Recording,
            ),
            (
                MediaError::BadFrameLength { millis: 7 },
                SipralStatus::InvalidArgument,
                SipralMediaFault::Other,
            ),
        ];
        for (error, status, fault) in cases {
            assert_eq!(media_failed(&error).status, status, "{error}");
            assert_eq!(super::fault_of(&error), fault, "{error}");
        }
    }

    // -- what a live call says about itself ----------------------------------

    /// A4's reporting half: what the two ends actually agreed, read off a call
    /// that is up.
    #[test]
    fn a_call_reports_what_it_negotiated() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let info = media_info(stack, call);
        assert_eq!(info.codec, SipralCodec::Pcmu as u32);
        assert_eq!(info.payload_type, 0, "the number on the wire");
        assert_eq!(info.clock_rate, 8_000);
        assert_eq!(info.sample_rate, 8_000);
        assert_eq!(info.frame_ms, 20);
        assert_eq!(info.frame_samples, FRAME);
        assert_eq!(info.direction, SipralDirection::SendRecv as u32);
        assert_eq!(info.sending, 1);
        assert_eq!(info.receiving, 1);
        assert_eq!(info.rtcp, SipralRtcp::SeparatePort as u32);
        assert_eq!(info.secured, 0);
        assert_eq!(info.recording, 0);
        assert_eq!(info.stalled, 0);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// The event that says audio started carries the same answer, so an
    /// application that only listens does not have to ask.
    #[test]
    fn the_event_that_starts_the_audio_names_the_codec_too() {
        let mut observed = Observed::default();
        let (stack, _) = media_call(&mut observed);
        let started = observed.of(SipralEventKind::MediaStarted);
        assert_eq!(started.len(), 1, "{:?}", observed.kinds());
        let heard = started.first().expect("one media started event");
        assert_eq!(heard.codec, SipralCodec::Pcmu as u32);
        assert_eq!(heard.direction, SipralDirection::SendRecv as u32);
        assert_eq!(heard.fault, SipralMediaFault::None as u32);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// The codec order a stack was given is the one it reads back, which is the
    /// other half of a setting that was accepted rather than ignored.
    #[test]
    fn the_order_a_stack_was_given_is_the_order_it_offers() {
        let mut observed = Observed::default();
        let (stack, _) = media_line(&mut observed, |config| {
            config.codecs = ORDER.as_ptr().cast::<c_char>();
            config.codecs_len = ORDER.len();
        });
        let mut order = [u32::MAX; 4];
        let mut count = 0_usize;
        let status = unsafe {
            sipral_stack_codec_order(stack, order.as_mut_ptr(), order.len(), &raw mut count)
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(count, 2);
        assert_eq!(
            &order[..2],
            [SipralCodec::G722 as u32, SipralCodec::Pcma as u32]
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn asking_for_the_order_with_no_room_says_how_much_is_needed() {
        let mut observed = Observed::default();
        let (stack, _) = media_line(&mut observed, |_| {});
        let mut count = 0_usize;
        let status = unsafe { sipral_stack_codec_order(stack, ptr::null_mut(), 0, &raw mut count) };
        assert_eq!(status, SipralStatus::BufferTooSmall);
        assert_eq!(count, 1, "the fixture offers one codec");
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    // -- what the call cost ---------------------------------------------------

    /// A6's live half. A call with nothing wrong with it reads a hundred, and
    /// the counters move with what actually crossed the boundary.
    #[test]
    fn the_statistics_count_what_went_out_and_what_came_in() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);

        let idle = statistics(stack, call, 1_100);
        assert_eq!(idle.codec, SipralCodec::Pcmu as u32);
        assert_eq!(idle.packets_sent, 0);
        assert_eq!(idle.packets_received, 0);
        assert_eq!(idle.has_round_trip, 0, "no report has come back");
        assert!((idle.score - 100.0).abs() < 0.1, "read {}", idle.score);
        assert_eq!(idle.suffering, 0);

        for _ in 0..5 {
            assert_eq!(capture_one(stack, call, &[2_000; FRAME]), FRAME + 12);
        }
        for (index, sequence) in (100..104_u16).enumerate() {
            let mut packet = rtp(sequence, 8_000 + u32::try_from(index).unwrap_or(0) * 160);
            arrive(stack, call, &mut packet, PEER_MEDIA, 1_100);
        }

        let after = statistics(stack, call, 1_200);
        assert_eq!(after.packets_sent, 5);
        assert_eq!(
            after.octets_sent,
            5 * FRAME as u64,
            "payload octets, not the headers in front of them"
        );
        assert!(
            after.packets_received >= 2,
            "nothing was taken in: {}",
            after.packets_received
        );
        assert_eq!(after.silent_for_ms, 100, "since the last one arrived");
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// A6's other half: the record has to survive the call it is about. The
    /// stream is gone by the time this arrives, so the numbers travel in the
    /// event rather than behind a lookup that would now fail.
    #[test]
    fn the_end_of_call_record_arrives_after_the_call_that_it_is_about() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        for _ in 0..3 {
            capture_one(stack, call, &[1_000; FRAME]);
        }
        hangup(stack, call, 5_000);

        let kinds = observed.kinds();
        let ended = kinds
            .iter()
            .position(|kind| *kind == SipralEventKind::CallEnded)
            .expect("the call ended");
        let record = kinds
            .iter()
            .position(|kind| *kind == SipralEventKind::MediaStatistics)
            .expect("and said what it cost");
        assert!(ended < record, "the last word came before the news");

        let heard = observed.of(SipralEventKind::MediaStatistics);
        let stats = heard
            .first()
            .and_then(|heard| heard.statistics)
            .expect("the record travels with the event");
        assert_eq!(stats.codec, SipralCodec::Pcmu as u32);
        assert_eq!(stats.packets_sent, 3);
        assert_eq!(stats.size, size_of::<SipralStreamStats>());
        assert_eq!(
            heard.first().map(|heard| heard.call),
            Some(call),
            "the last word about a call has to name the call, so the handle is retired after the \
             record rather than with the news that ended it"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_call_this_stack_describes_nothing_for_has_no_media_to_ask_about() {
        let mut observed = Observed::default();
        let (stack, call) = connected(&mut observed);
        let mut stats = empty_stats();
        assert_eq!(
            unsafe { sipral_call_statistics(stack, call, 2_000, &raw mut stats) },
            SipralStatus::WrongState
        );
        assert_eq!(stats.packets_sent, u64::MAX, "nothing was written");
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    // -- the watchdog ---------------------------------------------------------

    /// B5: media that stops while signalling stays happy, and the recovery
    /// that follows it.
    #[test]
    fn media_that_stops_is_reported_and_so_is_its_return() {
        let mut observed = Observed::default();
        let (stack, call) = media_call_tuned(&mut observed, |config| {
            config.media_stall_ms = 400;
        });
        crate::stack::tests::poll(stack, 1_300);
        assert!(
            observed.of(SipralEventKind::MediaStalled).is_empty(),
            "too early to be a stall"
        );

        crate::stack::tests::poll(stack, 1_600);
        let stalled = observed.of(SipralEventKind::MediaStalled);
        assert_eq!(stalled.len(), 1, "{:?}", observed.kinds());
        assert!(
            stalled
                .first()
                .is_some_and(|heard| heard.silent_for_ms >= 400),
            "the event does not say how long: {stalled:?}"
        );
        assert_eq!(media_info(stack, call).stalled, 1);

        // RFC 3550 A.1 keeps a new source on probation until it has sent two
        // in a row, so one packet is not yet audio arriving
        for (index, sequence) in (200..203_u16).enumerate() {
            let mut packet = rtp(sequence, 16_000 + u32::try_from(index).unwrap_or(0) * 160);
            arrive(stack, call, &mut packet, PEER_MEDIA, 1_700);
        }
        crate::stack::tests::poll(stack, 1_700);
        let resumed = observed.of(SipralEventKind::MediaResumed);
        assert_eq!(resumed.len(), 1, "{:?}", observed.kinds());
        assert!(
            resumed
                .first()
                .is_some_and(|heard| heard.silent_for_ms >= 400),
            "the recovery does not say how long the gap was: {resumed:?}"
        );
        assert_eq!(media_info(stack, call).stalled, 0);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// The watchdog is a setting, and one that a neighbouring value has
    /// switched off does not quietly take a threshold nothing will read.
    #[test]
    fn a_stall_threshold_with_the_watchdog_off_is_refused() {
        let mut observed = Observed::default();
        let mut config = crate::stack::tests::config(crate::stack::tests::record, &mut observed);
        config.media_stall_watchdog = SipralToggle::Off as u32;
        config.media_stall_ms = 400;
        let (status, handle) = crate::stack::tests::create(&config);
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(handle, SIPRAL_HANDLE_NONE);
        assert!(last_error_text().contains("media_stall_watchdog"));
    }

    // -- and why -------------------------------------------------------------

    /// D5's failing half: an answer naming a format nobody offered leaves the
    /// call up and says, in a code and in a sentence, exactly what happened.
    #[test]
    fn a_negotiation_that_settles_on_nothing_says_which_failure_it_was() {
        let mut observed = Observed::default();
        let (stack, call) = media_call_refused(&mut observed);
        let failed = observed.of(SipralEventKind::MediaFailed);
        assert_eq!(failed.len(), 1, "{:?}", observed.kinds());
        let heard = failed.first().expect("one failure");
        assert_eq!(heard.fault, SipralMediaFault::NoCommonCodec as u32);
        assert!(
            !heard.reason.is_empty(),
            "a code without a sentence is a code nobody can act on"
        );
        assert!(
            observed.kinds().contains(&SipralEventKind::CallConfirmed),
            "the call itself is untouched"
        );
        let mut info = SipralMediaInfo {
            size: size_of::<SipralMediaInfo>(),
            ..media_info_zeroed()
        };
        assert_eq!(
            unsafe { sipral_call_media_info(stack, call, &raw mut info) },
            SipralStatus::WrongState,
            "and there is no stream to describe"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    // -- the packets ---------------------------------------------------------

    #[test]
    fn a_captured_frame_comes_back_addressed_to_where_the_audio_goes() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let mut buffers = Buffers::new();
        let mut packet = buffers.packet();
        let samples = [3_000_i16; FRAME];
        let status = unsafe {
            sipral_call_capture(
                stack,
                call,
                samples.as_ptr(),
                samples.len(),
                &raw mut packet,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let (payload, destination) = buffers.taken(&packet);
        assert_eq!(payload.len(), FRAME + 12, "twelve octets of RTP header");
        assert_eq!(
            payload.first().copied(),
            Some(0x80),
            "version two, no marker"
        );
        assert_eq!(payload.get(1).copied(), Some(0x00), "payload type zero");
        assert_eq!(destination, PEER_MEDIA);
        assert_eq!(packet.destination_len, destination.len());
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// Half a frame encoded as a whole one is what a peer hears as a stutter,
    /// so the length is checked rather than trusted.
    #[test]
    fn a_frame_of_the_wrong_length_is_refused_before_it_is_encoded() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let mut buffers = Buffers::new();
        let mut packet = buffers.packet();
        let short = [0_i16; 80];
        let status = unsafe {
            sipral_call_capture(stack, call, short.as_ptr(), short.len(), &raw mut packet)
        };
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("160"));
        assert_eq!(
            statistics(stack, call, 1_100).packets_sent,
            0,
            "and nothing went out"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// A buffer too small is answered before anything is built, so the frame is
    /// not lost from a stream whose timestamps have already moved past it.
    #[test]
    fn a_packet_buffer_too_small_costs_no_audio() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let mut small = [0_u8; 64];
        let mut packet = SipralMediaPacket {
            size: size_of::<SipralMediaPacket>(),
            data: small.as_mut_ptr(),
            capacity: small.len(),
            len: usize::MAX,
            destination: ptr::null_mut(),
            destination_capacity: 0,
            destination_len: 0,
        };
        let samples = [1_000_i16; FRAME];
        let status = unsafe {
            sipral_call_capture(
                stack,
                call,
                samples.as_ptr(),
                samples.len(),
                &raw mut packet,
            )
        };
        assert_eq!(status, SipralStatus::BufferTooSmall);
        assert_eq!(
            statistics(stack, call, 1_100).packets_sent,
            0,
            "the frame was not encoded and thrown away"
        );
        assert_eq!(capture_one(stack, call, &samples), FRAME + 12);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// Every source fills the frame, silence included: a device handed nothing
    /// plays whatever was in its buffer last.
    #[test]
    fn playback_fills_the_frame_even_when_nothing_has_arrived() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        assert_eq!(play_one(stack, call), SipralPlayback::Silence);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_buffer_shorter_than_a_frame_says_how_many_samples_it_needed() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let mut samples = [0_i16; 80];
        let mut written = 0_usize;
        let status = unsafe {
            sipral_call_playback(
                stack,
                call,
                samples.as_mut_ptr(),
                samples.len(),
                &raw mut written,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, SipralStatus::BufferTooSmall);
        assert_eq!(written, FRAME);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// The control traffic RFC 3550 §6.3 schedules, addressed to the port the
    /// negotiation put it on rather than to the media port.
    #[test]
    fn the_report_that_becomes_due_comes_out_addressed_to_the_control_port() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let mut buffers = Buffers::new();
        let mut packet = buffers.packet();
        let mut named = SIPRAL_HANDLE_NONE;

        let mut due = None;
        for tick in 1..=120_u64 {
            packet = buffers.packet();
            let status = unsafe {
                sipral_stack_poll_rtcp(stack, 1_100 + tick * 500, &raw mut named, &raw mut packet)
            };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            if packet.len != 0 {
                due = Some(tick);
                break;
            }
        }
        assert!(due.is_some(), "no report in a minute of call");
        assert_eq!(named, call, "the report says which socket it goes out on");
        let (payload, destination) = buffers.taken(&packet);
        assert_eq!(
            payload.first().map(|byte| byte >> 6),
            Some(2),
            "version two"
        );
        assert!(
            matches!(payload.get(1).copied(), Some(200 | 201)),
            "RFC 3550 §6.1 opens a compound packet with a sender or a reception \
             report, and this one opens with {:?}",
            payload.get(1)
        );
        assert_eq!(
            destination, "203.0.113.5:41001",
            "the port after the media one, which is where §6.3 puts it"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// The two buffer sizes this ABI promises are the ones the layers below
    /// actually need. A packet bound that drifted below what a session builds
    /// would be a caller told to bring a buffer that is one octet short of the
    /// largest Opus frame.
    #[test]
    fn the_promised_buffers_hold_what_this_build_produces() {
        for codec in Codec::ALL {
            // twelve octets of RTP header in front of the largest payload
            let largest = codec.max_payload(60) + 12;
            assert!(
                largest <= SIPRAL_MEDIA_PACKET_BYTES,
                "{codec:?} can produce {largest} bytes"
            );
        }
        let longest: SocketAddr = "[2001:db8:1234:5678:9abc:def0:1234:5678]:65535"
            .parse()
            .expect("an address");
        assert!(longest.to_string().len() < SIPRAL_ADDRESS_BYTES);
    }
}
