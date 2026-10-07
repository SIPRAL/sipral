// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Audio across the boundary: what this build can encode, what a call agreed,
//! what it is costing, and the four calls that carry the packets.
//!
//! No socket and no device: the application hands in datagrams
//! ([`sipral_media_receive`]), pulls PCM for its speaker ([`sipral_media_playback`]),
//! pushes microphone PCM and gets a datagram back ([`sipral_media_capture`]), and
//! asks for due control traffic ([`sipral_media_poll_rtcp`]).
//!
//! Every entry point takes a media handle from [`sipral_call_media`] and never the
//! stack's lock. Each call's session has its own lock, so a call's audio thread
//! never waits on signalling, the event callback or another call. See
//! `docs/08-ffi.md`.
//!
//! Samples are 16-bit mono at [`SipralMediaInfo::sample_rate`], a frame exactly
//! [`SipralMediaInfo::frame_samples`] of them. That is the codec's rate, not the
//! RTP clock's; for G.722 they differ by a factor of two.
//!
//! Only calls this stack manages have media: placed with `media_address` in
//! `sipral_call_config_t`, or answered with `sipral_call_answer_media`. Any other
//! call answers `SIPRAL_STATUS_WRONG_STATE` here.
//!
//! Addresses cross as UTF-8 `host:port` text, length-delimited, like every other
//! address in this ABI.

use std::cell::RefCell;
use std::ffi::{c_char, c_void};
use std::net::SocketAddr;
use std::ptr;
use std::slice;
use std::time::{Duration, Instant};

use sipral::{
    Arrival, Codec, CodecCandidate, CodecCatalog, CodecOutcome, Direction, IcePolicy, MediaError,
    MediaSession, Playback, Processor, RtcpPlan, SessionShare, SessionUnavailable, SrtpPolicy,
    StreamStatistics, UNAVAILABLE, mix_two,
};
use sipral_core::sdp::SdpError;

use crate::abi::{Number, alias, codes, constants, record};
use crate::error::{Fail, entry, fail};
use crate::handle::{HandleTable, Kind, SipralHandle};
use crate::stack::{SipralTransport, StackState, handle_failed, instant_at, with_stack};
use crate::status::SipralStatus;
use crate::text::required_text;
use crate::versioned::{Versioned, read_versioned, write_versioned};

constants! {
    /// The buffer a caller has to bring for one outgoing packet.
    ///
    /// The bound the session builds against, not a path MTU. Checked before
    /// anything is encoded, so a frame is never encoded and then lost.
    pub const SIPRAL_MEDIA_PACKET_BYTES: usize = 1_500;

    /// The bound for an incoming datagram that RFC 5761 §4 classifies as control.
    ///
    /// Compound RTCP from a peer may exceed the media bound (RFC 3550 sets no
    /// limit). Everything else still gets [`SIPRAL_MEDIA_PACKET_BYTES`]; outgoing
    /// RTCP always fits the media bound.
    pub const SIPRAL_MEDIA_RTCP_BYTES: usize = 8_192;

    /// Room enough for any address this ABI writes, the NUL included:
    /// `[2001:db8:0000:0000:0000:0000:0000:0001]:65535` and a byte to spare.
    pub const SIPRAL_ADDRESS_BYTES: usize = 64;
}

codes! {
    /// The three answers a setting can give in a struct that starts out zeroed.
    ///
    /// Not a boolean: zero must mean "unset", so the library never turns a
    /// control off because the caller left it zeroed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralToggle: u32 {
        /// Nothing was said; whatever this build defaults to.
        Default = 0,
        /// On.
        On = 1,
        /// Off.
        Off = 2,
    }
}

codes! {
    /// What a call or a stack says about SRTP. Names for
    /// `sipral_stack_config_t::srtp` (the stack's default) and
    /// `sipral_call_config_t::srtp` (a per-call override).
    ///
    /// Zero means "unset": on the stack, the built-in default
    /// [`SipralSrtp::NotOffered`]; on a call, the stack's setting.
    /// `docs/05-media.md` details each value.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralSrtp: u32 {
        /// Do not offer it, but answer an offer on the secure profile with keys.
        NotOffered = 1,
        /// Offer it, and answer a plain offer plainly.
        Offered = 2,
        /// Offer it, and let no stream on this call carry audio unencrypted.
        Required = 3,
        /// Offer DTLS-SRTP (RFC 5764) on `UDP/TLS/RTP/SAVP`, and answer a plain
        /// offer plainly.
        ///
        /// The key never travels in the body, so this is sound over a readable
        /// SIP transport. Costs a round trip of silence at call start. The
        /// application **must** drain [`sipral_media_poll_transmit`], or the
        /// call is up, silent, and reports no error.
        ///
        /// `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
        /// `SIPRAL_FEATURE_DTLS_SRTP`.
        Dtls = 4,
        /// Offer DTLS-SRTP and allow no other keying, including an answer
        /// carrying `a=crypto`.
        DtlsRequired = 5,
        /// DTLS-SRTP with SDES fallback, never unencrypted. The offer is one
        /// `RTP/SAVP` stream with both fingerprint and crypto lines; the answer
        /// decides. An incoming offer is answered the way it was keyed; a plain
        /// one is refused with 488.
        ///
        /// `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
        /// `SIPRAL_FEATURE_DTLS_SRTP`.
        DtlsOrSdes = 6,
        /// Offer SDES on plain `RTP/AVP` ("SRTP optional"): encrypted when the
        /// answer takes an `a=crypto` line, plain otherwise. For servers that
        /// reject `RTP/SAVP` with 488. Not standard (RFC 4568 defines the
        /// attribute for secure profiles). An incoming `RTP/AVP` offer with a
        /// usable line is answered with a key, anything else as `Offered`.
        BestEffort = 7,
    }
}

codes! {
    /// What a call or a stack says about ICE. Names for
    /// `sipral_stack_config_t::ice` (the stack's default) and
    /// `sipral_call_config_t::ice` (a per-call override).
    ///
    /// Zero means "unset": on the stack, the built-in default
    /// [`SipralIce::Off`]; on a call, the stack's setting.
    ///
    /// A call that offers ICE also asks for RFC 5761 multiplexing, whatever
    /// `offer_rtcp_mux` says: this ABI names one address per stream.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralIce: u32 {
        /// Do not offer it, and do not answer a peer that does. The default;
        /// `docs/06-nat.md` says why.
        Off = 1,
        /// Offer it, and use it against a peer that offers it back.
        ///
        /// A peer without ICE gets the call on the signalled address and
        /// symmetric RTP. The application **must** drain
        /// [`sipral_media_poll_transmit`], or no path is ever chosen.
        ///
        /// `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
        /// `SIPRAL_FEATURE_ICE`.
        Offered = 2,
        /// Offer it, and let no stream carry audio on a path ICE did not check.
        ///
        /// A peer that fails ICE ends the call's media with
        /// `SIPRAL_EVENT_KIND_MEDIA_FAILED` instead of falling back.
        Required = 3,
        /// Be an ICE-lite endpoint (RFC 8445 §2.5): `a=ice-lite`, one host
        /// candidate, answer a full peer's checks, use the pair it nominates.
        ///
        /// **Only for a server reachable at the address it advertises** (its
        /// own, or a one-to-one NAT's via `sipral_stack_nat_map`); never for a
        /// softphone. RFC 8445 Appendix A: lite "will not function when a lite
        /// implementation is placed behind a NAT". A peer with no ICE, or lite
        /// itself, gets the signalled address. The application still drains
        /// `sipral_media_poll_transmit` for check answers.
        ///
        /// `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
        /// `SIPRAL_FEATURE_ICE`.
        Lite = 4,
    }
}

codes! {
    /// One codec this ABI has a number for.
    ///
    /// Values are permanent. Whether this build contains a codec is answered by
    /// `SIPRAL_FEATURE_*` and `sipral_codec_at`, not by this list.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralCodec: u32 {
        /// No codec: the call has none, or the event is not about one.
        Unknown = 0,
        /// G.711 mu-law, payload type 0.
        Pcmu = 1,
        /// G.711 A-law, payload type 8.
        Pcma = 2,
        /// G.722, wideband at the price of a narrowband stream.
        G722 = 3,
        /// Opus. Declared in every build; presence is `SIPRAL_FEATURE_OPUS`.
        Opus = 4,
        /// G.729 Annex A, payload type 18. Offered only when a codec order names
        /// `G729`; offers `annexb=yes`, answers with the offer's `annexb`.
        G729 = 5,
        /// L16 at 8 kHz mono, dynamic payload type `L16/8000`. Offered only
        /// when a codec order names it.
        L16Narrowband = 6,
        /// L16 at 16 kHz mono, `L16/16000`. Offered only when a codec order
        /// names it.
        L16Wideband = 7,
    }
}

codes! {
    /// What became of one codec this call's catalogue could have used. Names
    /// for [`SipralCodecCandidate::outcome`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralCodecOutcome: u32 {
        /// Not an outcome: unknown to this ABI, or the struct was never filled.
        Unknown = 0,
        /// What the call agreed on. Exactly one candidate carries it, the same
        /// codec as `sipral_media_info_t::codec`.
        Chosen = 1,
        /// The far end's description did not name it.
        NotNamed = 2,
        /// The far end named it and this end had something better: the codec
        /// in `outranked_by` came first in this call's order.
        Outranked = 3,
    }
}

codes! {
    /// Whether a [`SipralPathCandidate`] is a candidate pair or a relay.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralPathKind: u32 {
        /// Not a kind: the struct was never filled in.
        Unknown = 0,
        /// A candidate pair the call's ICE checklist held (RFC 8445
        /// §6.1.2).
        Pair = 1,
        /// An allocation on a TURN server the call's agent held (RFC 8656).
        Relay = 2,
    }
}

codes! {
    /// The kind of an ICE candidate (RFC 8445 §5.1.1). Names for
    /// [`SipralPathCandidate::local_kind`] and `remote_kind`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralCandidateKind: u32 {
        /// Not known: a relay's server, which is no candidate, or the far
        /// end of a pair a lite end took from a nomination and never learned
        /// the kind of.
        Unknown = 0,
        /// An address a socket of the host's own is bound to.
        Host = 1,
        /// The address a NAT maps the host's socket to, as a STUN or TURN
        /// server saw it.
        ServerReflexive = 2,
        /// An address a connectivity check revealed (RFC 8445 §7.3.1.3).
        PeerReflexive = 3,
        /// An address on a TURN server that relays for the host.
        Relayed = 4,
    }
}

codes! {
    /// What became of one path a call's ICE agent tried. Names for
    /// [`SipralPathCandidate::outcome`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralPathOutcome: u32 {
        /// Not an outcome: unknown to this ABI, or the struct was never filled.
        Unknown = 0,
        /// The path the call's media takes: the selected pair (RFC 8445
        /// §8.1.2), or the relay it runs through.
        Selected = 1,
        /// A pair whose check succeeded, with nothing selected yet.
        Valid = 2,
        /// Nothing has decided it yet: a pair frozen, waiting its turn or
        /// with its check on the wire; a relay still being allocated.
        Waiting = 3,
        /// A pair whose check succeeded, with a pair of higher priority
        /// selected over it.
        Outranked = 4,
        /// A pair another was nominated ahead of: its check had not finished
        /// when the selection took it off the checklist (RFC 8445 §8.1.2),
        /// or it succeeded after a lower one was nominated.
        NominatedElsewhere = 5,
        /// A pair whose check was never answered (RFC 8489 §6.2.1).
        TimedOut = 6,
        /// A pair the far end refused; `code` is the STUN error code (RFC
        /// 8445 §7.2.5.2.4).
        Refused = 7,
        /// A pair whose answer came from an address other than the one its
        /// check went to (RFC 8445 §7.2.5.2.1): a NAT between rewriting it.
        NotSymmetric = 8,
        /// A pair whose answer named no address to form a valid pair from.
        Unusable = 9,
        /// A relayed pair the relay would not let the far end through for,
        /// or a relay whose allocation the server refused; `code` is the
        /// TURN server's error code, zero when it gave none (RFC 8656 §9,
        /// §7.3).
        RelayRefused = 10,
        /// A pair never checked: the pair limit discarded it (RFC 8445
        /// §6.1.2.5), or its checklist ended before its turn came.
        NotChecked = 11,
        /// A relay held, that no selected pair runs through — or none yet.
        Held = 12,
        /// A relay given back: ICE concluded on a pair that does not use it
        /// (RFC 8445 §8.3.1), or this branch of a forked call let go of it.
        Released = 13,
        /// A relay the server took back; `code` is its error code, zero when
        /// a refresh went unanswered (RFC 8656 §8).
        Lost = 14,
    }
}

codes! {
    /// Which way audio may flow, as seen from here. Names for every `direction`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralDirection: u32 {
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
}

codes! {
    /// Where control traffic goes. Names for [`SipralMediaInfo::rtcp`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralRtcp: u32 {
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
}

codes! {
    /// Why media failed, for a machine to act on. Names for
    /// `sipral_media_event_t::fault`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralMediaFault: u32 {
        /// Nothing failed.
        None = 0,
        /// The peer answered with a format this build cannot encode or decode.
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
        /// ICE could not carry this call: the far end described none this
        /// stack could use and the policy was `SIPRAL_ICE_REQUIRED`, the far
        /// end took `a=rtcp-mux` out of an answer to an ICE offer, or consent
        /// to send on the pair that was chosen was withdrawn part-way through
        /// (RFC 7675 §5). Signalling is still sound; an application may fall
        /// back to a non-ICE profile.
        Ice = 9,
        /// The SRTP policy refused the far end's description: a plain answer
        /// (hung up with `Reason` 488) or a plain re-offer (refused with 488,
        /// old keys kept).
        SecurityPolicy = 10,
    }
}

codes! {
    /// What a datagram handed to [`sipral_media_receive`] turned out to be.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralArrival: u32 {
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
        /// A DTLS-SRTP handshake record, taken. Drain
        /// [`sipral_media_poll_transmit`] for the reply.
        Handshake = 6,
        /// Arrived on an encrypted call before its keys exist; usually a peer
        /// that sends as soon as its half of the handshake ends.
        NotKeyed = 7,
    }
}

codes! {
    /// The SRTP transform a call is running. Names for
    /// `sipral_media_event_t::suite`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralSrtpSuite: u32 {
        /// No transform: the event is not about one, or the call is not
        /// encrypted.
        Unknown = 0,
        /// `AES_CM_128_HMAC_SHA1_80`, the one every implementation has.
        AesCm80 = 1,
        /// `AES_CM_128_HMAC_SHA1_32`, the same cipher with a shorter tag.
        AesCm32 = 2,
        /// `F8_128_HMAC_SHA1_80`, which is what 3GPP asks for. Reachable by
        /// SDES only; RFC 5764 §4.1.2 defines no DTLS-SRTP profile for it.
        AesF8 = 3,
        /// `AES_256_CM_HMAC_SHA1_80` (RFC 6188). SDES only.
        Aes256Cm80 = 4,
        /// `AES_256_CM_HMAC_SHA1_32` (RFC 6188). SDES only.
        Aes256Cm32 = 5,
        /// `AEAD_AES_128_GCM` (RFC 7714). DTLS-SRTP profile 0x0007.
        AeadAes128Gcm = 6,
        /// `AEAD_AES_256_GCM` (RFC 7714). DTLS-SRTP profile 0x0008, preferred
        /// between two ends of this stack.
        AeadAes256Gcm = 7,
    }
}

codes! {
    /// Where the frame [`sipral_media_playback`] just produced came from.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralPlayback: u32 {
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
}

record! {
    /// One codec this build contains.
    ///
    /// Set `size` to `sizeof(sipral_codec_info_t)` before the call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralCodecInfo {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// A [`SipralCodec`].
        pub codec: Number<SipralCodec>,
        /// The RTP timestamp clock, in hertz, which is what goes on the
        /// `a=rtpmap` line.
        pub clock_rate: u32,
        /// The codec's own rate, which the samples crossing this ABI use. G.722's
        /// differs from its clock (RFC 3551 §4.5.2).
        pub sample_rate: u32,
        /// The payload type RFC 3551 table 4 assigns it, when it has one.
        pub static_payload_type: u32,
        /// Whether it has one. Opus does not.
        pub has_static_payload_type: u32,
        /// Zero. Pads to the alignment so later members start past this
        /// header's length. Written zero, never read.
        pub reserved: u32,
    }
}

// Safety: integers with no invariant between them; zero is valid for each.
unsafe impl Versioned for SipralCodecInfo {
    const NAME: &'static str = "sipral_codec_info";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralCodecInfo, reserved);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// One codec this call could have used, and what became of it.
    ///
    /// Set `size` to `sizeof(sipral_codec_candidate_t)` before the call.
    ///
    /// Recorded when the negotiation decided, never recomputed.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralCodecCandidate {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// A [`SipralCodec`]: the candidate itself.
        pub codec: Number<SipralCodec>,
        /// A [`SipralCodecOutcome`]: what became of it.
        pub outcome: Number<SipralCodecOutcome>,
        /// A [`SipralCodec`]: what beat it, when `outcome` is
        /// `SIPRAL_CODEC_OUTCOME_OUTRANKED`; `SIPRAL_CODEC_UNKNOWN` otherwise.
        pub outranked_by: Number<SipralCodec>,
        /// Zero. Pads to the alignment so later members start past this
        /// header's length. Written zero, never read.
        pub reserved: u32,
    }
}

// Safety: integers with no invariant between them; zero is valid for each.
unsafe impl Versioned for SipralCodecCandidate {
    const NAME: &'static str = "sipral_codec_candidate";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralCodecCandidate, reserved);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// One path a call's ICE agent tried — a candidate pair it checked, or a
    /// relay it held — and what became of it, with its two addresses written
    /// into the caller's own buffers.
    ///
    /// The caller fills in `size`, the two pointers and the two capacities;
    /// the library fills in the rest. Null with capacity zero skips an address.
    /// Recorded as each outcome happened, since RFC 8445 §8.1.2 drops losing
    /// pairs from the checklist on selection.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralPathCandidate {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// The pair's priority (RFC 8445 §6.1.2.3), as this end's role
        /// computes it; zero for a relay.
        pub priority: u64,
        /// A [`SipralPathKind`].
        pub kind: Number<SipralPathKind>,
        /// A [`SipralPathOutcome`].
        pub outcome: Number<SipralPathOutcome>,
        /// For `SIPRAL_PATH_OUTCOME_REFUSED`, the STUN error code the far end
        /// answered with; for `SIPRAL_PATH_OUTCOME_RELAY_REFUSED` and
        /// `SIPRAL_PATH_OUTCOME_LOST`, the TURN server's, zero when it gave
        /// none. Zero otherwise.
        pub code: u32,
        /// A [`SipralCandidateKind`]: what `local` is.
        pub local_kind: Number<SipralCandidateKind>,
        /// A [`SipralCandidateKind`]: what `remote` is, when it is a
        /// candidate at all.
        pub remote_kind: Number<SipralCandidateKind>,
        /// Zero. Keeps the layout identical on 32- and 64-bit targets. Written
        /// zero, never read.
        pub reserved: u32,
        /// Where to write the local address, `host:port` with a trailing NUL:
        /// for a pair, the candidate its checks left from; for a relay, the
        /// relayed address.
        pub local: *mut c_char,
        /// How much room `local` has. At least [`SIPRAL_ADDRESS_BYTES`] when
        /// it is not null.
        pub local_capacity: usize,
        /// How many bytes of it were written, the NUL not counted. Zero for
        /// a relay that has no relayed address.
        pub local_len: usize,
        /// Where to write the far address, `host:port` with a trailing NUL:
        /// for a pair, the far end's candidate; for a relay, the TURN
        /// server.
        pub remote: *mut c_char,
        /// How much room `remote` has. At least [`SIPRAL_ADDRESS_BYTES`]
        /// when it is not null.
        pub remote_capacity: usize,
        /// How many bytes of it were written, the NUL not counted.
        pub remote_len: usize,
    }
}

// Safety: plain data, no invariant between members; the pointers are the
// caller's buffers, and all-zero wants neither address.
unsafe impl Versioned for SipralPathCandidate {
    const NAME: &'static str = "sipral_path_candidate";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralPathCandidate, remote_len);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// What one call's media settled on, and what it is doing now.
    ///
    /// Set `size` to `sizeof(sipral_media_info_t)` before the call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralMediaInfo {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// A [`SipralCodec`]: what the two ends agreed on.
        pub codec: Number<SipralCodec>,
        /// The payload type on the wire: the offer's number, not necessarily
        /// ours.
        pub payload_type: u32,
        /// The RTP timestamp clock, in hertz.
        pub clock_rate: u32,
        /// The rate the samples crossing this ABI are at: the codec's, or the
        /// one [`sipral_media_set_app_rate`] chose.
        pub sample_rate: u32,
        /// How long a frame is, in milliseconds.
        pub frame_ms: u32,
        /// Samples in one frame: exactly what [`sipral_media_playback`] fills and
        /// what [`sipral_media_capture`] wants, at `sample_rate`.
        pub frame_samples: usize,
        /// A [`SipralDirection`].
        pub direction: Number<SipralDirection>,
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
        pub rtcp: Number<SipralRtcp>,
        /// Whether the stream is keyed.
        pub secured: u32,
        /// Whether a recording is running on this call.
        pub recording: u32,
        /// How much audio it has taken.
        pub recorded_ms: u64,
        /// Whether the watchdog currently considers inbound audio stopped.
        pub stalled: u32,
        /// Whether the call agreed a real-time text stream (RFC 4103), which
        /// `sipral_media_send_text` writes to.
        pub has_text: u32,
        /// Whether the audio stream runs RTP/AVPF (RFC 4585): both ends named
        /// a feedback profile.
        pub feedback: u32,
        /// Whether both ends agreed Generic NACKs (`a=rtcp-fb:* nack`), so
        /// that a gap in what arrives is asked for again.
        pub generic_nack: u32,
        /// Whether both ends agreed reduced-size RTCP (RFC 5506,
        /// `a=rtcp-rsize`).
        pub reduced_size: u32,
        /// Zero. Pads to the alignment so later members start past this
        /// header's length. Written zero, never read.
        pub reserved: u32,
    }
}

// Safety: integers, no invariant between them, and zero is a valid value of
// each.
unsafe impl Versioned for SipralMediaInfo {
    const NAME: &'static str = "sipral_media_info";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralMediaInfo, reserved);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// What one call's media has cost, and what it is costing now.
    ///
    /// Cheap enough to read at UI frame rate. The same struct arrives with
    /// `SIPRAL_EVENT_KIND_MEDIA_STATISTICS` when the call ends. Delays are in
    /// microseconds, since healthy jitter is below a millisecond.
    ///
    /// Set `size` to `sizeof(sipral_stream_stats_t)` before the call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralStreamStats {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// A [`SipralCodec`]: what the call settled on.
        pub codec: Number<SipralCodec>,
        /// Whether a round-trip time is known. Zero until a report comes back,
        /// which may be never (RFC 3550 §6.2 delays the first one).
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
        /// Frames dropped in a pause to bring the delay down.
        pub frames_shrunk: u64,
        /// Frames concealment invented in a pause to push the delay up.
        pub frames_stretched: u64,
        /// How far behind the newest packet the playout point is.
        pub delay_us: u64,
        /// What the buffer is aiming at, from the arrival times it has seen.
        pub target_delay_us: u64,
        /// Interarrival jitter, the smoothed mean deviation of transit time
        /// (RFC 3550 §6.4.1).
        pub jitter_us: u64,
        /// Frames concealed as a fraction of frames played, over about the last
        /// ten seconds.
        pub loss_rate: f32,
        /// 100 for a flawless call, 0 for an unusable one. Not a MOS.
        pub score: f32,
        /// Whether the numbers say this call is in trouble now.
        pub suffering: u32,
        /// How long since a packet last arrived. A live call sits at one frame.
        pub silent_for_ms: u64,
        /// Whether an RFC 3611 VoIP Metrics report is available. Every `voip_*`
        /// member is meaningless while this is zero.
        pub has_voip_metrics: u32,
        /// RFC 3611 SS4.7.1's loss rate, as its own 256ths (multiply by
        /// 100 and divide by 256 for a percentage).
        pub voip_loss_rate_256: u32,
        /// RFC 3611 SS4.7.1's discard rate, as its own 256ths.
        pub voip_discard_rate_256: u32,
        /// RFC 3611 SS4.7.2's burst density, as its own 256ths.
        pub voip_burst_density_256: u32,
        /// RFC 3611 SS4.7.2's mean burst duration.
        pub voip_burst_duration_us: u64,
        /// RFC 3611 SS4.7.2's gap density, as its own 256ths.
        pub voip_gap_density_256: u32,
        /// RFC 3611 SS4.7.2's mean gap duration.
        pub voip_gap_duration_us: u64,
        /// RFC 3611 SS4.7.2's `Gmin`, the burst/gap threshold, fixed per stream.
        pub voip_gmin: u32,
        /// RFC 3611 SS4.7.3's end-system delay. Always zero: it needs the
        /// sending side's delay, which this end cannot see.
        pub voip_end_system_delay_us: u64,
        /// RFC 3611 SS4.7.7's nominal jitter buffer delay.
        pub voip_jitter_buffer_nominal_us: u64,
        /// RFC 3611 SS4.7.7's current maximum jitter buffer delay.
        pub voip_jitter_buffer_maximum_us: u64,
        /// RFC 3611 SS4.7.7's absolute maximum jitter buffer delay.
        pub voip_jitter_buffer_abs_max_us: u64,
        /// Whether `voip_r_factor` is available: zero when ITU-T G.113 has no
        /// `Ie`/`Bpl` for the codec (RFC 3611 SS4.7.5's `127` sentinel).
        pub has_voip_r_factor: u32,
        /// RFC 3611 SS4.7.5's R factor, `0..=100`.
        pub voip_r_factor: u32,
        /// Whether `voip_mos_lq_x10` is available, for the same reason as
        /// `has_voip_r_factor`.
        pub has_voip_mos_lq: u32,
        /// RFC 3611 SS4.7.5's estimated listening-quality MOS, in tenths
        /// (`14..=50`).
        pub voip_mos_lq_x10: u32,
        /// Whether `voip_mos_cq_x10` is available, for the same reason.
        pub has_voip_mos_cq: u32,
        /// RFC 3611 SS4.7.5's estimated conversational-quality MOS, in
        /// tenths.
        pub voip_mos_cq_x10: u32,
        /// Frames played empty because the jitter buffer ran dry while the far
        /// end was still sending. Not lost packets (`packets_lost`), so the
        /// `voip_*` rates miss it (RFC 3611 SS4.7.1 counts packets);
        /// `loss_rate`, `score` and `suffering` include it.
        pub frames_underrun: u64,
        /// Whether the stream runs RTP/AVPF (RFC 4585). The counts below stay
        /// zero otherwise.
        pub feedback: u32,
        /// The `trr-int` both ends agreed: the least time between two
        /// regular reports, in milliseconds. Zero for none.
        pub trr_interval_ms: u32,
        /// Generic NACKs this end sent, each asking for one or more packets.
        pub nacks_sent: u64,
        /// The packets those NACKs asked for.
        pub packets_nacked: u64,
        /// Generic NACKs the far end sent.
        pub nacks_received: u64,
        /// The packets those asked this end for.
        pub packets_asked_for: u64,
        /// Early RTCP packets this end sent.
        pub early_packets: u64,
        /// Reduced-size RTCP packets this end sent (RFC 5506).
        pub reduced_size_packets: u64,
        /// Feedback held back for lack of RTCP bandwidth.
        pub feedback_suppressed: u64,
    }
}

// Safety: integers and two floats, no invariant; zero is valid for each.
unsafe impl Versioned for SipralStreamStats {
    const NAME: &'static str = "sipral_stream_stats";
    const PIN: crate::versioned::Pin =
        crate::versioned::pin!(SipralStreamStats, feedback_suppressed);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// One datagram on its way out, written into the caller's own buffers.
    ///
    /// The caller fills in `size`, the two pointers and the two capacities; the
    /// library fills in the two lengths and the bytes. A `len` of zero means
    /// nothing to send (held, or silence suppression). Both buffers are checked
    /// before anything is produced.
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
        /// What to send it over, as a `SipralTransport`. `SIPRAL_TRANSPORT_UDP`
        /// is a datagram from the media socket. With a TURN server over TCP or
        /// TLS (`turn_transport`), relayed traffic says so, `destination` is the
        /// server, and the bytes go in order on that connection, never as a
        /// datagram.
        pub protocol: Number<SipralTransport>,
        /// Zero. Pads to the alignment so later members start past this
        /// header's length. Set zero on input; written zero, never read.
        pub reserved: u32,
    }
}

// Safety: plain data, no invariant between members; the pointers are the
// caller's buffers, and all-zero is refused when read, not undefined.
unsafe impl Versioned for SipralMediaPacket {
    const NAME: &'static str = "sipral_media_packet";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralMediaPacket, reserved);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// The name this ABI gives a codec.
pub(crate) const fn named_codec(codec: Codec) -> SipralCodec {
    // Asked of the value, not a `cfg` on this crate's `opus` feature: the facade
    // may link Opus while this crate's feature is off.
    if codec.is_opus() {
        return SipralCodec::Opus;
    }
    match codec {
        Codec::Pcmu => SipralCodec::Pcmu,
        Codec::Pcma => SipralCodec::Pcma,
        Codec::G722 => SipralCodec::G722,
        Codec::G729 => SipralCodec::G729,
        Codec::L16Narrowband => SipralCodec::L16Narrowband,
        Codec::L16Wideband => SipralCodec::L16Wideband,
        // a codec this ABI has no number for yet
        _ => SipralCodec::Unknown,
    }
}

/// Whether this build's catalogue contains the codec this ABI numbers
/// `named` — what `sipral_codec_at` enumerates, asked by number.
fn linked(named: SipralCodec) -> bool {
    Codec::ALL.iter().any(|codec| named_codec(*codec) == named)
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
    // asked of the value, not a `cfg`, as in `named_codec`
    if error.is_codec() {
        return SipralMediaFault::Codec;
    }
    match *error {
        MediaError::UnsupportedCodec { .. } | MediaError::UnknownPayload { .. } => {
            SipralMediaFault::UnsupportedCodec
        }
        MediaError::NoCommonCodec | MediaError::Description(SdpError::NoCodec { .. }) => {
            SipralMediaFault::NoCommonCodec
        }
        MediaError::StreamRefused => SipralMediaFault::StreamRefused,
        MediaError::NoDescription => SipralMediaFault::NoDescription,
        MediaError::Description(_) => SipralMediaFault::BadDescription,
        MediaError::Recording(_)
        | MediaError::NotRecording
        | MediaError::AlreadyRecording
        | MediaError::RecordingRate { .. }
        | MediaError::RecordingBitrate { .. } => SipralMediaFault::Recording,
        #[cfg(feature = "ice")]
        MediaError::Ice(_)
        | MediaError::IceRequired
        | MediaError::IceNeedsRtcpMux
        | MediaError::IcePathLost => SipralMediaFault::Ice,
        MediaError::SrtpRequired => SipralMediaFault::SecurityPolicy,
        _ => SipralMediaFault::Other,
    }
}

/// Why the media layer would not do it. The message comes from the error; only
/// the status is decided here.
pub(crate) fn media_failed(error: &MediaError) -> Fail {
    // asked of the value, not a `cfg`; see `fault_of`
    if error.is_codec() {
        return fail(SipralStatus::InvalidArgument, error.to_string());
    }
    let status = match *error {
        MediaError::UnsupportedCodec { .. } | MediaError::UnknownPayload { .. } => {
            SipralStatus::NotSupported
        }
        // a write failure (disk full, volume gone); a bad path is refused earlier
        MediaError::Recording(_) => SipralStatus::RecordingFailed,
        // a value that would be taken if it were corrected
        MediaError::NoCodecs
        | MediaError::BadFrameLength { .. }
        | MediaError::Description(_)
        | MediaError::RecordingRate { .. }
        | MediaError::RecordingBitrate { .. }
        | MediaError::ApplicationRate { .. }
        | MediaError::ConsentTone(_)
        | MediaError::DigitTooShort { .. }
        | MediaError::DigitTooLong { .. }
        | MediaError::UnknownDigit { .. }
        | MediaError::RenderDelayTooLong { .. }
        | MediaError::NoSrtpSuite
        | MediaError::SameCall => SipralStatus::InvalidArgument,
        // a limit reached; the text buffer drains at the far end's pace
        MediaError::TooManyDigits
        | MediaError::NoPayloadType
        | MediaError::TextBufferFull { .. } => SipralStatus::Exhausted,
        MediaError::NoSuchCall
        | MediaError::NoDescription
        | MediaError::NotRecording
        | MediaError::AlreadyRecording
        | MediaError::NoCommonCodec
        | MediaError::StreamRefused
        | MediaError::AlreadyJoined
        | MediaError::NotJoined
        | MediaError::JoinIncompatible => SipralStatus::WrongState,
        MediaError::PacketTooLong { .. } => SipralStatus::BufferTooSmall,
        MediaError::SrtpRequired => SipralStatus::SecurityPolicy,
        MediaError::NoText => SipralStatus::NotNegotiated,
        MediaError::Signalling(ref refused) => return crate::call::ua_failed(refused),
        _ => SipralStatus::NotSent,
    };
    fail(status, error.to_string())
}

/// The C shape of a statistics record.
pub(crate) fn stream_stats(record: &StreamStatistics) -> SipralStreamStats {
    let quality = record.quality;
    let voip = record.voip_metrics;
    let counts = record.feedback_counts;
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
        has_voip_metrics: u32::from(voip.is_some()),
        voip_loss_rate_256: voip.map_or(0, |block| u32::from(block.loss_rate)),
        voip_discard_rate_256: voip.map_or(0, |block| u32::from(block.discard_rate)),
        voip_burst_density_256: voip.map_or(0, |block| u32::from(block.burst_density)),
        voip_burst_duration_us: voip.map_or(0, |block| ms_to_us(block.burst_duration_ms)),
        voip_gap_density_256: voip.map_or(0, |block| u32::from(block.gap_density)),
        voip_gap_duration_us: voip.map_or(0, |block| ms_to_us(block.gap_duration_ms)),
        voip_gmin: voip.map_or(0, |block| u32::from(block.gmin)),
        voip_end_system_delay_us: voip.map_or(0, |block| ms_to_us(block.end_system_delay_ms)),
        voip_jitter_buffer_nominal_us: voip.map_or(0, |block| ms_to_us(block.jb_nominal_ms)),
        voip_jitter_buffer_maximum_us: voip.map_or(0, |block| ms_to_us(block.jb_maximum_ms)),
        voip_jitter_buffer_abs_max_us: voip.map_or(0, |block| ms_to_us(block.jb_abs_max_ms)),
        has_voip_r_factor: u32::from(voip.is_some_and(|block| block.r_factor != UNAVAILABLE)),
        voip_r_factor: voip.map_or(0, |block| u32::from(block.r_factor)),
        has_voip_mos_lq: u32::from(voip.is_some_and(|block| block.mos_lq != UNAVAILABLE)),
        voip_mos_lq_x10: voip.map_or(0, |block| u32::from(block.mos_lq)),
        has_voip_mos_cq: u32::from(voip.is_some_and(|block| block.mos_cq != UNAVAILABLE)),
        voip_mos_cq_x10: voip.map_or(0, |block| u32::from(block.mos_cq)),
        frames_underrun: quality.underruns,
        feedback: u32::from(record.feedback.is_some()),
        trr_interval_ms: record.feedback.map_or(0, |agreed| {
            u32::try_from(agreed.trr_interval.as_millis()).unwrap_or(u32::MAX)
        }),
        nacks_sent: counts.nacks_sent,
        packets_nacked: counts.packets_nacked,
        nacks_received: counts.nacks_received,
        packets_asked_for: counts.packets_asked_for,
        early_packets: counts.early_packets,
        reduced_size_packets: counts.reduced_size_packets,
        feedback_suppressed: counts.suppressed,
    }
}

fn ms_to_us(ms: u16) -> u64 {
    u64::from(ms).saturating_mul(1_000)
}

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

/// A `sipral_stack_config_t::srtp` or `sipral_call_config_t::srtp` value, as a
/// [`SrtpPolicy`]; `None` for zero, which each struct resolves its own way.
pub(crate) fn srtp_policy(value: u32, name: &'static str) -> Result<Option<SrtpPolicy>, Fail> {
    match value {
        0 => Ok(None),
        1 => Ok(Some(SrtpPolicy::NotOffered)),
        2 => Ok(Some(SrtpPolicy::Offered)),
        3 => Ok(Some(SrtpPolicy::Required)),
        // without the feature these are refused, never downgraded to plain
        #[cfg(feature = "dtls")]
        4 => Ok(Some(SrtpPolicy::DtlsOffered)),
        #[cfg(feature = "dtls")]
        5 => Ok(Some(SrtpPolicy::DtlsRequired)),
        #[cfg(feature = "dtls")]
        6 => Ok(Some(SrtpPolicy::DtlsOrSdes)),
        7 => Ok(Some(SrtpPolicy::BestEffort)),
        #[cfg(not(feature = "dtls"))]
        4..=6 => Err(fail(
            SipralStatus::NotSupported,
            format!(
                "{name} names DTLS-SRTP and this build has none: SIPRAL_FEATURE_DTLS_SRTP is \
                 clear in sipral_capabilities"
            ),
        )),
        other => Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "{name} is {other}, and srtp is 0 to leave it unspecified, 1 for not offered, 2 \
                 for offered, 3 for required, 4 for DTLS-SRTP, 5 for DTLS-SRTP required, 6 for \
                 DTLS-SRTP falling back to SDES or 7 for SDES offered on RTP/AVP"
            ),
        )),
    }
}

/// A `sipral_stack_config_t::ice` or `sipral_call_config_t::ice` value, as an
/// [`IcePolicy`] the caller actually named — `None` for the zero that means
/// "unspecified", which the two structs resolve differently, exactly as
/// [`srtp_policy`] describes.
///
/// # Errors
///
/// `SIPRAL_STATUS_NOT_SUPPORTED` for a policy this build has no agent to
/// honour, and `SIPRAL_STATUS_INVALID_ARGUMENT` for a value that names none
/// of them.
pub(crate) fn ice_policy(value: u32, name: &'static str) -> Result<Option<IcePolicy>, Fail> {
    match value {
        0 => Ok(None),
        1 => Ok(Some(IcePolicy::Off)),
        // without the feature these are refused, never run on an unchecked path
        #[cfg(feature = "ice")]
        2 => Ok(Some(IcePolicy::Offered)),
        #[cfg(feature = "ice")]
        3 => Ok(Some(IcePolicy::Required)),
        #[cfg(feature = "ice")]
        4 => Ok(Some(IcePolicy::Lite)),
        #[cfg(not(feature = "ice"))]
        2..=4 => Err(fail(
            SipralStatus::NotSupported,
            format!(
                "{name} names ICE and this build has none: SIPRAL_FEATURE_ICE is clear in \
                 sipral_capabilities"
            ),
        )),
        other => Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "{name} is {other}, and ice is 0 to leave it unspecified, 1 for off, 2 for \
                 offered, 3 for required or 4 for lite"
            ),
        )),
    }
}

/// The catalogue a stack was asked for. A codec name this build lacks is
/// refused here, not ignored later.
pub(crate) fn catalog_of(
    order: Option<&str>,
    frame_ms: u32,
    dtmf: bool,
    rtcp_mux: bool,
    srtp: Option<SrtpPolicy>,
    ice: Option<IcePolicy>,
    g729_annex_b: bool,
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
    if let Some(policy) = srtp {
        catalog = catalog.with_srtp(policy);
    }
    if let Some(policy) = ice {
        catalog = catalog.with_ice(policy);
    }
    Ok(catalog
        .with_dtmf(dtmf)
        .with_rtcp_mux(rtcp_mux)
        .with_g729_annex_b(g729_annex_b))
}

fn ordered(list: &str) -> Result<CodecCatalog, Fail> {
    CodecCatalog::with_order(&names_in(list)?).map_err(|error| media_failed(&error))
}

/// The codec names a caller wrote, checked for empty and duplicate entries.
/// Separate from [`ordered`] because a call's order is read before the stack
/// is locked.
pub(crate) fn names_in(list: &str) -> Result<Vec<&str>, Fail> {
    let named: Vec<&str> = list.split(',').map(str::trim).collect();
    if let Some(empty) = named.iter().position(|name| name.is_empty()) {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!("codecs names nothing at position {empty}, so the list has a stray comma"),
        ));
    }
    // a duplicate would put one payload type on the m= line twice
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
    Ok(named)
}

/// Every media handle this process has handed out. Its lock is held for an
/// index and a reference count, never for a frame.
static MEDIA: HandleTable<MediaEntry> = HandleTable::new(Kind::Media);

/// What a media handle names.
pub(crate) struct MediaEntry {
    share: SessionShare,
    /// The minting stack, which a thread inside this media may not call into.
    stack: SipralHandle,
    /// The minting stack's clock origin, copied so media never touches it.
    origin: Instant,
    /// Whether the stack runs in device mode (the engine pumps frames).
    device: bool,
}

impl MediaEntry {
    /// The caller's clock on the minting stack's origin. Not checked against
    /// the last poll: media threads read the clock apart from the poller.
    pub(crate) fn instant(&self, now_ms: u64) -> Result<Instant, Fail> {
        instant_at(self.origin, now_ms)
    }
}

/// Do something with one call's media, or say why not. Takes only the
/// session's own lock, never the stack's.
pub(crate) fn with_media<R>(
    media: SipralHandle,
    act: impl FnOnce(&mut MediaSession, &MediaEntry) -> Result<R, Fail>,
) -> Result<R, Fail> {
    let entry = MEDIA.get(media).map_err(handle_failed)?;
    refuse_from_inside_a_frame()?;
    let _inside = Inside::enter(entry.stack);
    match entry.share.with(|session| act(session, &entry)) {
        Ok(done) => done,
        Err(SessionUnavailable::Reentered) => Err(fail(
            SipralStatus::Busy,
            "this thread is already inside this call's media, further down its own call stack",
        )),
        Err(_) => Err(fail(
            SipralStatus::WrongState,
            "this call's media has ended: the call is over or its stack was destroyed, and all \
             that is left to do with the handle is release it",
        )),
    }
}

/// Do something with two calls' media at once, for [`sipral_media_mix`].
///
/// Locks the numerically smaller handle first, so two threads mixing the
/// same pair in swapped order cannot deadlock.
fn with_media_pair<R>(
    media_a: SipralHandle,
    media_b: SipralHandle,
    act: impl FnOnce(&mut MediaSession, &mut MediaSession) -> Result<R, Fail>,
) -> Result<R, Fail> {
    let entry_a = MEDIA.get(media_a).map_err(handle_failed)?;
    let entry_b = MEDIA.get(media_b).map_err(handle_failed)?;
    refuse_from_inside_a_frame()?;
    let _inside_a = Inside::enter(entry_a.stack);
    let _inside_b = Inside::enter(entry_b.stack);
    if media_a <= media_b {
        entry_a
            .share
            .with(|session_a| -> Result<R, Fail> {
                entry_b
                    .share
                    .with(|session_b| act(session_a, session_b))
                    .map_err(media_unavailable)?
            })
            .map_err(media_unavailable)?
    } else {
        entry_b
            .share
            .with(|session_b| -> Result<R, Fail> {
                entry_a
                    .share
                    .with(|session_a| act(session_a, session_b))
                    .map_err(media_unavailable)?
            })
            .map_err(media_unavailable)?
    }
}

/// The same [`Fail`] [`with_media`] gives when a [`SessionShare`] is
/// unavailable.
fn media_unavailable(error: SessionUnavailable) -> Fail {
    match error {
        SessionUnavailable::Reentered => fail(
            SipralStatus::Busy,
            "this thread is already inside this call's media, further down its own call stack",
        ),
        _ => fail(
            SipralStatus::WrongState,
            "this call's media has ended: the call is over or its stack was destroyed, and all \
             that is left to do with the handle is release it",
        ),
    }
}

/// Refuse a media entry point called from inside any call's frame on this
/// thread (a processor, or a local conference's tick). Refusing every handle,
/// not just the frame's own, rules out two processors deadlocking across calls.
fn refuse_from_inside_a_frame() -> Result<(), Fail> {
    if INSIDE.with_borrow(Vec::is_empty) {
        return Ok(());
    }
    Err(fail(
        SipralStatus::Busy,
        "this thread is inside a frame of a call's media (a processor, or a local conference's \
         tick), and a media entry point called from there could wait on a frame that is waiting \
         on this one; call it once the frame has returned",
    ))
}

thread_local! {
    /// The stacks whose calls' media this thread is working on, innermost last.
    static INSIDE: RefCell<Vec<SipralHandle>> = const { RefCell::new(Vec::new()) };
}

/// This thread's mark on a stack while it works on one of its calls' media.
pub(crate) struct Inside {
    stack: SipralHandle,
}

impl Inside {
    /// Mark this thread as inside `stack`'s media (or a conference's tick,
    /// by the conference handle) until dropped.
    pub(crate) fn enter(stack: SipralHandle) -> Self {
        INSIDE.with_borrow_mut(|inside| inside.push(stack));
        Self { stack }
    }
}

impl Drop for Inside {
    fn drop(&mut self) {
        INSIDE.with_borrow_mut(|inside| {
            if let Some(at) = inside.iter().rposition(|stack| *stack == self.stack) {
                inside.remove(at);
            }
        });
    }
}

/// Whether this thread is inside a frame of a call on `stack`.
pub(crate) fn inside_media_of(stack: SipralHandle) -> bool {
    INSIDE.with_borrow(|inside| inside.contains(&stack))
}

/// Why a call has no media to name.
pub(crate) fn no_media() -> Fail {
    fail(
        SipralStatus::WrongState,
        "this call has no media: it was not placed or answered with a media address of its own, \
         or its negotiation has not settled yet",
    )
}

entry! {
    /// A handle on one call's media, written to `out_media`.
    ///
    /// Mint it once negotiation settles (`SIPRAL_EVENT_KIND_MEDIA_STARTED`,
    /// callback included) and pass it to every `sipral_media_` entry point.
    /// None of those takes the stack's lock.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for a call with no media. Written only on
    /// `SIPRAL_STATUS_OK`.
    ///
    /// The handle outlives the call: after the call ends or the stack is
    /// destroyed, media entry points answer `SIPRAL_STATUS_WRONG_STATE`. Hold,
    /// resume and codec changes keep it valid. Each handle is released once with
    /// `sipral_media_release`; asking twice gives two.
    ///
    /// # Safety
    ///
    /// `out_media` must point at one `sipral_handle_t`.
    fn sipral_call_media(stack: SipralHandle, call: SipralHandle, out_media: *mut SipralHandle) {
        if out_media.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_media is null"));
        }
        // the stack's tag lets a misplaced handle be refused by name
        let (entry, tag) = with_stack(stack, |state| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let share = state.engine.share(id).ok_or_else(no_media)?;
            let entry = MediaEntry {
                share,
                stack,
                origin: state.origin(),
                device: state.audio.is_some(),
            };
            Ok((entry, state.tag.tag()))
        })?;
        let handle = MEDIA
            .insert(tag, entry)
            .map_err(|status| fail(status, "no room for another media handle"))?;
        unsafe { out_media.write(handle) };
        Ok(())
    }
}

entry! {
    /// Let a media handle go.
    ///
    /// Valid whether or not the call or stack still exists. The session is not
    /// touched; releasing mid-call stops nothing. A second release is
    /// `SIPRAL_STATUS_STALE_HANDLE`.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    fn sipral_media_release(media: SipralHandle) {
        MEDIA.remove(media).map_err(handle_failed)?;
        Ok(())
    }
}

entry! {
    /// The name of a codec, as a static NUL-terminated string, or null for a
    /// number this build has no codec for.
    ///
    /// Spelled as IANA registered it; L16 carries its rate (`L16/8000`,
    /// `L16/16000`), as in a codec order. Owned by the library, valid while
    /// it is loaded.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns, and is safe to call from any thread.
    fn sipral_codec_name(codec: Number<SipralCodec>) -> *const c_char, on_panic = std::ptr::null(), {
        match codec {
            1 => c"PCMU".as_ptr(),
            2 => c"PCMA".as_ptr(),
            3 => c"G722".as_ptr(),
            // the catalogue, not this crate's feature, says whether Opus is linked
            4 if linked(SipralCodec::Opus) => c"opus".as_ptr(),
            5 => c"G729".as_ptr(),
            6 => c"L16/8000".as_ptr(),
            7 => c"L16/16000".as_ptr(),
            _ => std::ptr::null(),
        }
    }
}

entry! {
    /// How many codecs this build contains, fixed at compile time.
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
    /// In this build's preference order, the default offer; G.729 comes last
    /// and is offered only when a codec order names it.
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
            reserved: 0,
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
    /// What `sipral_stack_config_t::codecs` came to. `out_count` always gets
    /// the total; a short buffer (or null with zero capacity) gets
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL`.
    ///
    /// # Safety
    ///
    /// `out_codecs` must be writable for `capacity` `uint32_t` or null with a
    /// capacity of zero, and `out_count` must point at one `size_t` or be null.
    fn sipral_stack_codec_order(
        stack: SipralHandle,
        out_codecs: *mut Number<SipralCodec>,
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
        // capacity covers the length, so a non-empty order has a buffer
        if !order.is_empty() {
            unsafe { std::ptr::copy_nonoverlapping(order.as_ptr(), out_codecs, order.len()) };
        }
        Ok(())
    }
}

entry! {
    /// What one call's media settled on.
    ///
    /// # Safety
    ///
    /// `out_info` must point at a `sipral_media_info_t` whose `size` member
    /// says how long it is.
    fn sipral_media_info(media: SipralHandle, out_info: *mut SipralMediaInfo) {
        // size first, so a wrong size is reported before anything about the call
        unsafe { crate::versioned::declared_size(out_info.cast_const()) }?;
        let info = with_media(media, |session, _| Ok(media_info(session)))?;
        unsafe { write_versioned(out_info, info) }
    }
}

entry! {
    /// How many codecs were in the running on this call.
    ///
    /// This call's catalogue: the stack's order unless
    /// `sipral_call_config_t::codecs` named another. Zero is a valid answer.
    ///
    /// # Safety
    ///
    /// `out_count` must point at one `size_t`.
    fn sipral_media_codec_candidate_count(media: SipralHandle, out_count: *mut usize) {
        if out_count.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_count is null"));
        }
        let count = with_media(media, |session, _| Ok(session.codec_candidates().len()))?;
        unsafe { out_count.write(count) };
        Ok(())
    }
}

entry! {
    /// One of them, by index, from zero to what
    /// `sipral_media_codec_candidate_count` said, in this call's own order.
    ///
    /// An index past the end is `SIPRAL_STATUS_INVALID_ARGUMENT`.
    ///
    /// # Safety
    ///
    /// `out_candidate` must point at a `sipral_codec_candidate_t` whose `size`
    /// member says how long it is.
    fn sipral_media_codec_candidate_at(
        media: SipralHandle,
        index: usize,
        out_candidate: *mut SipralCodecCandidate,
    ) {
        // size first, so a wrong size is reported before anything about the call
        unsafe { crate::versioned::declared_size(out_candidate.cast_const()) }?;
        let candidate = with_media(media, |session, _| {
            let candidates = session.codec_candidates();
            let Some(candidate) = candidates.get(index) else {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    format!(
                        "there is no candidate {index}; this call had {} in the running",
                        candidates.len()
                    ),
                ));
            };
            Ok(candidate_of(candidate))
        })?;
        unsafe { write_versioned(out_candidate, candidate) }
    }
}

entry! {
    /// How many paths this call's ICE agent tried: every candidate pair its
    /// checklist held, then every relay it held.
    ///
    /// Zero for a call not using ICE. A restart (RFC 8445 §9) starts the list
    /// again.
    ///
    /// # Safety
    ///
    /// `out_count` must point at one `size_t`.
    fn sipral_media_path_candidate_count(media: SipralHandle, out_count: *mut usize) {
        if out_count.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_count is null"));
        }
        let count = with_media(media, |session, _| Ok(paths_of(session).len()))?;
        unsafe { out_count.write(count) };
        Ok(())
    }
}

entry! {
    /// One of them, by index, from zero to what
    /// `sipral_media_path_candidate_count` said: the pairs in the order the
    /// checklist took them in, then the relays.
    ///
    /// An index past the end is `SIPRAL_STATUS_INVALID_ARGUMENT`; an address
    /// buffer smaller than `SIPRAL_ADDRESS_BYTES` is
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL`, before anything is written.
    ///
    /// # Safety
    ///
    /// `out_candidate` must point at a `sipral_path_candidate_t` whose `size`
    /// member says how long it is, and its two address buffers, when not
    /// null, must be writable for the capacities beside them.
    fn sipral_media_path_candidate_at(
        media: SipralHandle,
        index: usize,
        out_candidate: *mut SipralPathCandidate,
    ) {
        let mut out = unsafe { read_versioned(out_candidate.cast_const()) }?;
        for (pointer, capacity, name) in [
            (out.local, out.local_capacity, "local"),
            (out.remote, out.remote_capacity, "remote"),
        ] {
            if !pointer.is_null() && capacity < SIPRAL_ADDRESS_BYTES {
                return Err(fail(
                    SipralStatus::BufferTooSmall,
                    format!(
                        "an address buffer is at least {SIPRAL_ADDRESS_BYTES} bytes and {name} \
                         has room for {capacity}"
                    ),
                ));
            }
        }
        let (numbers, local, remote) = with_media(media, |session, _| {
            let paths = paths_of(session);
            let count = paths.len();
            paths.into_iter().nth(index).ok_or_else(|| {
                fail(
                    SipralStatus::InvalidArgument,
                    format!("there is no path {index}; this call's agent tried {count}"),
                )
            })
        })?;
        out.priority = numbers.priority;
        out.kind = numbers.kind;
        out.outcome = numbers.outcome;
        out.code = numbers.code;
        out.local_kind = numbers.local_kind;
        out.remote_kind = numbers.remote_kind;
        out.local_len = unsafe { crate::transport::write_address(out.local, local, "local") }?;
        out.remote_len =
            unsafe { crate::transport::write_address(out.remote, remote, "remote") }?;
        unsafe { write_versioned(out_candidate, out) }
    }
}

/// Every path a call's agent tried, with its two addresses.
#[cfg(feature = "ice")]
fn paths_of(
    session: &MediaSession,
) -> Vec<(SipralPathCandidate, Option<SocketAddr>, Option<SocketAddr>)> {
    use sipral::{CandidateKind, PathKind, PathOutcome};

    let kind_of = |kind: CandidateKind| match kind {
        CandidateKind::Host => SipralCandidateKind::Host,
        CandidateKind::ServerReflexive => SipralCandidateKind::ServerReflexive,
        CandidateKind::PeerReflexive => SipralCandidateKind::PeerReflexive,
        CandidateKind::Relayed => SipralCandidateKind::Relayed,
    };
    session
        .path_candidates()
        .into_iter()
        .map(|path| {
            let (outcome, code) = match path.outcome {
                PathOutcome::Selected => (SipralPathOutcome::Selected, 0),
                PathOutcome::Valid => (SipralPathOutcome::Valid, 0),
                PathOutcome::Waiting => (SipralPathOutcome::Waiting, 0),
                PathOutcome::Outranked => (SipralPathOutcome::Outranked, 0),
                PathOutcome::NominatedElsewhere => (SipralPathOutcome::NominatedElsewhere, 0),
                PathOutcome::TimedOut => (SipralPathOutcome::TimedOut, 0),
                PathOutcome::Refused(code) => (SipralPathOutcome::Refused, u32::from(code)),
                PathOutcome::NotSymmetric => (SipralPathOutcome::NotSymmetric, 0),
                PathOutcome::Unusable => (SipralPathOutcome::Unusable, 0),
                PathOutcome::RelayRefused(why) => (
                    SipralPathOutcome::RelayRefused,
                    crate::nat::refusal_code(why),
                ),
                PathOutcome::NotChecked => (SipralPathOutcome::NotChecked, 0),
                PathOutcome::Held => (SipralPathOutcome::Held, 0),
                PathOutcome::Released => (SipralPathOutcome::Released, 0),
                PathOutcome::Lost(why) => (SipralPathOutcome::Lost, crate::nat::refusal_code(why)),
                // an outcome this ABI has no number for yet
                _ => (SipralPathOutcome::Unknown, 0),
            };
            let numbers = SipralPathCandidate {
                reserved: 0,
                size: size_of::<SipralPathCandidate>(),
                priority: path.priority,
                kind: match path.kind {
                    PathKind::Pair => SipralPathKind::Pair,
                    PathKind::Relay => SipralPathKind::Relay,
                } as u32,
                outcome: outcome as u32,
                code,
                local_kind: kind_of(path.local_kind) as u32,
                remote_kind: path
                    .remote_kind
                    .map_or(SipralCandidateKind::Unknown, kind_of)
                    as u32,
                local: ptr::null_mut(),
                local_capacity: 0,
                local_len: 0,
                remote: ptr::null_mut(),
                remote_capacity: 0,
                remote_len: 0,
            };
            (numbers, path.local, Some(path.remote))
        })
        .collect()
}

#[cfg(not(feature = "ice"))]
fn paths_of(
    _session: &MediaSession,
) -> Vec<(SipralPathCandidate, Option<SocketAddr>, Option<SocketAddr>)> {
    Vec::new()
}

fn candidate_of(candidate: &CodecCandidate) -> SipralCodecCandidate {
    let (outcome, outranked_by) = match &candidate.outcome {
        CodecOutcome::Chosen => (SipralCodecOutcome::Chosen, SipralCodec::Unknown),
        CodecOutcome::NotNamed => (SipralCodecOutcome::NotNamed, SipralCodec::Unknown),
        CodecOutcome::Outranked(winner) => (SipralCodecOutcome::Outranked, named_codec(*winner)),
        _ => (SipralCodecOutcome::Unknown, SipralCodec::Unknown),
    };
    SipralCodecCandidate {
        reserved: 0,
        size: size_of::<SipralCodecCandidate>(),
        codec: named_codec(candidate.codec) as u32,
        outcome: outcome as u32,
        outranked_by: outranked_by as u32,
    }
}

fn media_info(session: &MediaSession) -> SipralMediaInfo {
    let plan = session.plan();
    let feedback = session.feedback();
    SipralMediaInfo {
        reserved: 0,
        size: size_of::<SipralMediaInfo>(),
        codec: named_codec(session.codec()) as u32,
        payload_type: u32::from(plan.codec.payload()),
        clock_rate: plan.codec.clock_rate(),
        sample_rate: session.application_rate(),
        frame_ms: session.frame_length(),
        frame_samples: session.application_frame_samples(),
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
        has_text: u32::from(session.has_text()),
        feedback: u32::from(feedback.is_some()),
        generic_nack: u32::from(feedback.is_some_and(|agreed| agreed.generic_nack)),
        reduced_size: u32::from(feedback.is_some_and(|agreed| agreed.reduced_size)),
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
    /// `now_ms` is the caller's monotonic clock; it does not move the stack's
    /// clock. The end-of-call record arrives as
    /// `SIPRAL_EVENT_KIND_MEDIA_STATISTICS`; by then this answers
    /// `SIPRAL_STATUS_WRONG_STATE`.
    ///
    /// # Safety
    ///
    /// `out_stats` must point at a `sipral_stream_stats_t` whose `size` member
    /// says how long it is.
    fn sipral_media_statistics(
        media: SipralHandle,
        now_ms: u64,
        out_stats: *mut SipralStreamStats,
    ) {
        // size first, so a wrong size is reported before anything about the call
        unsafe { crate::versioned::declared_size(out_stats.cast_const()) }?;
        let stats = with_media(media, |session, entry| {
            let now = entry.instant(now_ms)?;
            Ok(stream_stats(&session.statistics(now)))
        })?;
        unsafe { write_versioned(out_stats, stats) }
    }
}

entry! {
    /// Take a datagram off the media socket.
    ///
    /// RTP and RTCP are told apart by RFC 5761 §4, so either socket's traffic
    /// goes here.
    ///
    /// `data` is decrypted in place; keep a copy if the ciphertext is needed.
    /// `out_arrival` may be null. `now_ms` is the arrival time on the stack's
    /// clock and moves nothing.
    ///
    /// # Safety
    ///
    /// `data` must be readable and writable for `len` bytes, `from` readable
    /// for `from_len`, and `out_arrival` must point at one `uint32_t` or be
    /// null.
    fn sipral_media_receive(
        media: SipralHandle,
        data: *mut u8,
        len: usize,
        from: *const c_char,
        from_len: usize,
        now_ms: u64,
        out_arrival: *mut Number<SipralArrival>,
    ) {
        if data.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "data is null"));
        }
        let bound = if len >= 2 && is_control(unsafe { data.add(1).read() }) {
            SIPRAL_MEDIA_RTCP_BYTES
        } else {
            SIPRAL_MEDIA_PACKET_BYTES
        };
        if len == 0 || len > bound {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("data says it is {len} bytes, and a datagram is 1 to {bound}"),
            ));
        }
        let peer = unsafe { address(from, from_len, "from") }?;
        let arrival = with_media(media, |session, entry| {
            let now = entry.instant(now_ms)?;
            let datagram = unsafe { slice::from_raw_parts_mut(data, len) };
            Ok(session.receive(datagram, peer, now))
        })?;
        if !out_arrival.is_null() {
            unsafe { out_arrival.write(arrival_of(arrival) as u32) };
        }
        Ok(())
    }
}

/// Whether the second byte of a datagram says control, by RFC 5761 §4
/// (64 to 95 after the marker bit). Only picks the size bound; the session
/// classifies again itself.
const fn is_control(second: u8) -> bool {
    matches!(second & 0x7f, 64..=95)
}

const fn arrival_of(arrival: Arrival) -> SipralArrival {
    match arrival {
        Arrival::Queued => SipralArrival::Queued,
        Arrival::Dropped(_) => SipralArrival::Dropped,
        Arrival::Control => SipralArrival::Control,
        Arrival::Goodbye => SipralArrival::Goodbye,
        Arrival::ControlRefused => SipralArrival::ControlRefused,
        #[cfg(feature = "dtls")]
        Arrival::Handshake => SipralArrival::Handshake,
        Arrival::NotKeyed => SipralArrival::NotKeyed,
        _ => SipralArrival::Unknown,
    }
}

entry! {
    /// Take the frame that is due for the earpiece, and say where it came from.
    ///
    /// Exactly `sipral_media_info_t::frame_samples` samples are written, and a
    /// smaller buffer is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with the number
    /// needed in `out_written`. Every source fills the whole frame, silence
    /// included.
    ///
    /// # Safety
    ///
    /// `samples` must be writable for `capacity` `int16_t`, `out_written` must
    /// point at one `size_t` or be null, and `out_source` at one `uint32_t` or
    /// be null.
    fn sipral_media_playback(
        media: SipralHandle,
        samples: *mut i16,
        capacity: usize,
        out_written: *mut usize,
        out_source: *mut Number<SipralPlayback>,
    ) {
        if samples.is_null() && capacity != 0 {
            return Err(fail(SipralStatus::InvalidArgument, "samples is null"));
        }
        let played = with_media(media, |session, _| {
            let frame = session.application_frame_samples();
            if !out_written.is_null() {
                unsafe { out_written.write(frame) };
            }
            if capacity < frame {
                return Err(fail(
                    SipralStatus::BufferTooSmall,
                    format!("a frame is {frame} samples and there is room for {capacity}"),
                ));
            }
            // capacity covers the frame, so the buffer is not null
            let out = unsafe { slice::from_raw_parts_mut(samples, frame) };
            Ok(session.playback_at_application_rate(out))
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
    /// `sample_count` must equal `sipral_media_info_t::frame_samples`.
    ///
    /// A packet `len` of zero means the frame was deliberately not sent: held
    /// by the far end, suppressed as silence, or ICE has no path yet. The RTP
    /// timestamp still advances in the first two cases (RFC 3550 §5.1); in the
    /// third nothing is encoded. While this end holds the far end, silence
    /// goes out instead of the microphone.
    ///
    /// `now_ms` moves nothing; it tells ICE traffic went out on the chosen pair
    /// (RFC 8445 §11 keepalives).
    ///
    /// # Safety
    ///
    /// `samples` must be readable for `sample_count` `int16_t`, and `packet`
    /// must point at a `sipral_media_packet_t` whose `size` member says how
    /// long it is and whose buffers are writable for the capacities beside
    /// them.
    fn sipral_media_capture(
        media: SipralHandle,
        now_ms: u64,
        samples: *const i16,
        sample_count: usize,
        packet: *mut SipralMediaPacket,
    ) {
        let mut out = unsafe { read_versioned(packet) }?;
        prepare(&mut out)?;
        if samples.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "samples is null"));
        }
        with_media(media, |session, entry| {
            let now = entry.instant(now_ms)?;
            let frame = session.application_frame_samples();
            if sample_count != frame {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    format!("a frame of this call is {frame} samples and {sample_count} were given"),
                ));
            }
            let taken = unsafe { slice::from_raw_parts(samples, frame) };
            let sent = session
                .capture_at_application_rate(taken, now)
                .map_err(|error| media_failed(&error))?;
            match sent {
                Some(datagram) => unsafe { put_datagram(&mut out, &datagram) },
                None => Ok(()),
            }
        })?;
        unsafe { write_versioned(packet, out) }
    }
}

entry! {
    /// Choose the rate this call's frames cross the boundary at in
    /// application mode: what `sipral_media_playback` fills and what
    /// `sipral_media_capture` takes, whatever rate the codec runs at.
    ///
    /// `hz` is 8000, 16000, 24000 or 48000; 0 (the start) is the codec's rate.
    /// The frame keeps its duration (20 ms at 24 kHz is 480 samples), and
    /// `sipral_media_info_t::sample_rate`/`frame_samples` follow at once. The
    /// library resamples both ways and follows codec renegotiation; processors,
    /// recordings and detectors stay at the codec's rate.
    ///
    /// Any other rate is `SIPRAL_STATUS_INVALID_ARGUMENT`, setting unchanged.
    /// `SIPRAL_STATUS_WRONG_STATE` in device mode. `sipral_media_mix` refuses
    /// a pair while either call has its own rate.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns.
    fn sipral_media_set_app_rate(media: SipralHandle, hz: u32) {
        with_media(media, |session, entry| {
            if entry.device {
                return Err(fail(
                    SipralStatus::WrongState,
                    "this stack runs its audio in device mode, where the audio engine and not \
                     the application takes the call's frames",
                ));
            }
            let hertz = (hz != 0).then_some(hz);
            session
                .set_application_rate(hertz)
                .map_err(|error| media_failed(&error))
        })
    }
}

record! {
    /// What [`SipralProcessorCallback`] is handed for one call: an ordinary
    /// frame to process, or a request to forget what has been learned.
    ///
    /// Library-owned, passed as a `const` pointer. Read `size` first; read
    /// nothing after the callback returns, since the buffers are borrowed.
    #[derive(Clone, Copy)]
    pub struct SipralProcessorFrame {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// 0 for an ordinary frame; 1 to forget learned state (device or codec
        /// change). When 1, all three buffers are null and lengths zero.
        pub reset: u32,
        /// The frame just captured from the microphone. Null on reset.
        pub near_end: *const i16,
        /// Samples in `near_end`; always equal to `far_end_len` and `out_len`.
        /// 0 on reset.
        pub near_end_len: usize,
        /// The far-end audio played over the same span as `near_end`. Null on
        /// reset.
        pub far_end: *const i16,
        /// Samples in `far_end`. 0 on reset.
        pub far_end_len: usize,
        /// Where the callback writes the replacement for `near_end`; every
        /// sample must be written. Null on reset.
        pub out: *mut i16,
        /// Samples `out` holds, all of which must be written. 0 on reset.
        pub out_len: usize,
    }
}

alias! {
    /// Echo cancellation, gain control or noise suppression, run over one
    /// frame, or told to forget what it has learned — [`SipralProcessorFrame`]
    /// says which. Installed with [`sipral_media_attach_processor`].
    ///
    /// **It runs with this call's media locked** (see
    /// [`sipral_media_attach_processor`]): it must not call into the media
    /// handle it was attached through, on any thread, and must not unwind.
    ///
    /// `frame` and what it points at are library-owned, valid only during the
    /// call.
    pub type SipralProcessorCallback = fn(
        frame: *const SipralProcessorFrame,
        user_data: *mut c_void,
    );
}

/// A [`Processor`] backed by one C callback.
///
/// # Safety
///
/// `callback` follows [`SipralProcessorCallback`]'s contract (no unwinding;
/// re-entry is refused by the handle's guard). `user_data` is only handed
/// back to it.
struct CProcessor {
    callback: unsafe extern "C" fn(frame: *const SipralProcessorFrame, user_data: *mut c_void),
    user_data: *mut c_void,
    /// The callback's output buffer, resized when the frame length changes.
    out: Vec<i16>,
}

// Safety: see the struct's own doc comment above.
unsafe impl Send for CProcessor {}

impl Processor for CProcessor {
    fn process(&mut self, near_end: &mut [i16], reference: &[i16]) {
        if self.out.len() != near_end.len() {
            self.out.clear();
            self.out.resize(near_end.len(), 0);
        }
        let frame = SipralProcessorFrame {
            size: size_of::<SipralProcessorFrame>(),
            reset: 0,
            near_end: near_end.as_ptr(),
            near_end_len: near_end.len(),
            far_end: reference.as_ptr(),
            far_end_len: near_end.len(),
            out: self.out.as_mut_ptr(),
            out_len: near_end.len(),
        };
        // Safety: `near_end`, `reference` and `self.out` each hold
        // `near_end.len()` samples for this call; `frame` lives across it.
        unsafe { (self.callback)(&raw const frame, self.user_data) };
        near_end.copy_from_slice(&self.out);
    }

    fn reset(&mut self) {
        let frame = SipralProcessorFrame {
            size: size_of::<SipralProcessorFrame>(),
            reset: 1,
            near_end: ptr::null(),
            near_end_len: 0,
            far_end: ptr::null(),
            far_end_len: 0,
            out: ptr::null_mut(),
            out_len: 0,
        };
        // Safety: as in `process`; only `frame` itself is passed.
        unsafe { (self.callback)(&raw const frame, self.user_data) };
    }
}

entry! {
    /// Run `callback` over every captured frame, against the far-end audio
    /// played a render delay earlier: the seam for echo cancellation, gain
    /// control and noise suppression (`docs/05-media.md`).
    ///
    /// Replaces any previous processor and its learned state. Attaching
    /// mid-call costs a fresh adaptation.
    ///
    /// **`callback` runs with this call's media locked**, unlike the event
    /// callback: inside [`sipral_media_playback`], inside
    /// [`sipral_media_capture`], and with [`SipralProcessorFrame`]'s `reset`
    /// set on a device or codec change, on the thread that called in. **From
    /// inside it, call nothing on any media handle or this call's stack**:
    /// such calls answer `SIPRAL_STATUS_BUSY`. This rules out two processors
    /// deadlocking across calls. It must not unwind.
    ///
    /// `user_data` is handed back untouched and must outlive the last call,
    /// which ends when `sipral_media_detach_processor` or
    /// `sipral_media_release` returns.
    ///
    /// # Safety
    ///
    /// `callback` is called on whichever thread calls
    /// [`sipral_media_playback`] or [`sipral_media_capture`] on this call,
    /// for as long as the processor stays attached, and `user_data` has to
    /// outlive the last such call.
    fn sipral_media_attach_processor(
        media: SipralHandle,
        callback: SipralProcessorCallback,
        user_data: *mut c_void,
    ) {
        let Some(callback) = callback else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "callback is null: there is nothing to attach",
            ));
        };
        with_media(media, |session, _| {
            session.attach_processor(Box::new(CProcessor {
                callback,
                user_data,
                out: Vec::new(),
            }));
            Ok(())
        })
    }
}

entry! {
    /// Stop running the processor [`sipral_media_attach_processor`] attached,
    /// if there was one.
    ///
    /// `out_was_attached`, when not null, gets 1 if one was detached, else 0.
    /// Once this returns, `callback` is not called again and `user_data` may
    /// be freed.
    ///
    /// # Safety
    ///
    /// `out_was_attached` must point at one `uint32_t` or be null.
    fn sipral_media_detach_processor(media: SipralHandle, out_was_attached: *mut u32) {
        let was_attached = with_media(media, |session, _| Ok(session.detach_processor()))?;
        if !out_was_attached.is_null() {
            unsafe { out_was_attached.write(u32::from(was_attached)) };
        }
        Ok(())
    }
}

entry! {
    /// Forget the echo path, the noise floor and the gain the attached
    /// processor has learned, keeping the processor itself attached.
    ///
    /// For a device change. Calls the [`sipral_media_attach_processor`]
    /// callback with [`SipralProcessorFrame`]'s `reset` set.
    ///
    /// `out_was_attached`, when not null, gets 1 if a processor exists, else 0.
    ///
    /// # Safety
    ///
    /// `out_was_attached` must point at one `uint32_t` or be null.
    fn sipral_media_reset_processor(media: SipralHandle, out_was_attached: *mut u32) {
        let was_attached = with_media(media, |session, _| Ok(session.reset_processor()))?;
        if !out_was_attached.is_null() {
            unsafe { out_was_attached.write(u32::from(was_attached)) };
        }
        Ok(())
    }
}

entry! {
    /// One frame of a two-call local conference: decode both far ends, mix
    /// what each of the three parties is owed, and send the two far-end frames.
    ///
    /// `sipral_call_join` must already have paired the calls. Not checked here,
    /// since that would take the stack's lock every frame.
    ///
    /// `mic` (`mic_count`) is this end's frame; `local` (`local_count`) gets
    /// what this end's speaker is owed. Both are
    /// `sipral_media_info_t::frame_samples`. `packet_a`/`packet_b` are filled
    /// as by `sipral_media_capture`, each with `mic` mixed with the other far
    /// end; recordings keep the same.
    ///
    /// Drive a joined pair from one thread. Concurrent mixes of the same pair
    /// serialize without deadlock, but calling `sipral_media_playback` or
    /// `sipral_media_capture` on either call meanwhile is a second driver.
    ///
    /// # Safety
    ///
    /// `mic` must be readable for `mic_count` `int16_t` and `local` writable
    /// for `local_count` `int16_t`, the two must not overlap, and
    /// `packet_a` and `packet_b` must each point at a
    /// `sipral_media_packet_t` as `sipral_media_capture` describes.
    fn sipral_media_mix(
        media_a: SipralHandle,
        media_b: SipralHandle,
        now_ms: u64,
        mic: *const i16,
        mic_count: usize,
        local: *mut i16,
        local_count: usize,
        packet_a: *mut SipralMediaPacket,
        packet_b: *mut SipralMediaPacket,
    ) {
        let mut out_a = unsafe { read_versioned(packet_a) }?;
        let mut out_b = unsafe { read_versioned(packet_b) }?;
        prepare(&mut out_a)?;
        prepare(&mut out_b)?;
        if mic.is_null() && mic_count != 0 {
            return Err(fail(SipralStatus::InvalidArgument, "mic is null"));
        }
        if local.is_null() && local_count != 0 {
            return Err(fail(SipralStatus::InvalidArgument, "local is null"));
        }
        let origin = MEDIA.get(media_a).map_err(handle_failed)?.origin;
        let now = instant_at(origin, now_ms)?;
        // never build a slice over null, even empty; (NULL, 0) passes the checks
        let taken: &[i16] = if mic_count == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(mic, mic_count) }
        };
        let room: &mut [i16] = if local_count == 0 {
            &mut []
        } else {
            unsafe { slice::from_raw_parts_mut(local, local_count) }
        };
        let outcome = with_media_pair(media_a, media_b, |session_a, session_b| {
            if [&*session_a, &*session_b]
                .iter()
                .any(|session| session.application_rate() != session.sample_rate())
            {
                return Err(fail(
                    SipralStatus::WrongState,
                    "a pair is mixed at its codec's rate, and one of these calls has an \
                     application rate of its own: set it back to 0, or mix the calls in a local \
                     conference, which takes any rate",
                ));
            }
            let frame = session_a.frame_samples();
            if session_b.frame_samples() != frame || mic_count != frame || local_count != frame {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    format!(
                        "a frame of this pair is {frame} samples, mic was {mic_count} and local \
                         {local_count}, or the two calls no longer agree on a frame length"
                    ),
                ));
            }
            mix_two(session_a, session_b, taken, room, now).map_err(|error| media_failed(&error))
        })?;
        if let Some((destination, payload)) = outcome.to_a {
            #[cfg(feature = "ice")]
            let protocol = crate::nat::protocol_of(outcome.via_a);
            #[cfg(not(feature = "ice"))]
            let protocol = crate::stack::SipralTransport::Udp as u32;
            unsafe { put(&mut out_a, destination, &payload, protocol) }?;
        }
        if let Some((destination, payload)) = outcome.to_b {
            #[cfg(feature = "ice")]
            let protocol = crate::nat::protocol_of(outcome.via_b);
            #[cfg(not(feature = "ice"))]
            let protocol = crate::stack::SipralTransport::Udp as u32;
            unsafe { put(&mut out_b, destination, &payload, protocol) }?;
        }
        unsafe { write_versioned(packet_a, out_a) }?;
        unsafe { write_versioned(packet_b, out_b) }
    }
}

entry! {
    /// The control traffic this call has due.
    ///
    /// A `len` of zero means nothing is due. RFC 3550 §6.3 decides when; at
    /// most one report is due at a time.
    ///
    /// Call it after every outgoing frame, and at each `sipral_stack_poll`
    /// deadline while not capturing. Always zero without negotiated RTCP.
    /// `now_ms` moves nothing.
    ///
    /// # Safety
    ///
    /// `packet` must point at a `sipral_media_packet_t` as
    /// [`sipral_media_capture`] describes.
    fn sipral_media_poll_rtcp(media: SipralHandle, now_ms: u64, packet: *mut SipralMediaPacket) {
        let mut out = unsafe { read_versioned(packet) }?;
        prepare(&mut out)?;
        with_media(media, |session, entry| {
            let now = entry.instant(now_ms)?;
            match session.poll_rtcp(now) {
                Some(datagram) => unsafe { put_datagram(&mut out, &datagram) },
                None => Ok(()),
            }
        })?;
        unsafe { write_versioned(packet, out) }
    }
}

entry! {
    /// A datagram this call owes the far end that is neither audio nor a
    /// report: DTLS-SRTP handshake records and ICE checks.
    ///
    /// A `len` of zero means nothing is due; always so on a call without a
    /// handshake or ICE, at the cost of one comparison.
    ///
    /// **Drain it to empty** after every `sipral_media_receive` that answered
    /// `SIPRAL_ARRIVAL_HANDSHAKE` and at every `sipral_stack_poll` deadline.
    /// Otherwise the call connects, carries no audio, and reports nothing for
    /// the two minutes until it gives up. `now_ms` moves nothing.
    ///
    /// # Safety
    ///
    /// `packet` must point at a `sipral_media_packet_t` as
    /// [`sipral_media_capture`] describes.
    fn sipral_media_poll_transmit(media: SipralHandle, now_ms: u64, packet: *mut SipralMediaPacket) {
        let mut out = unsafe { read_versioned(packet) }?;
        prepare(&mut out)?;
        with_media(media, |session, entry| {
            #[cfg_attr(
                not(any(feature = "dtls", feature = "ice")),
                allow(clippy::let_underscore_untyped)
            )]
            let now = entry.instant(now_ms)?;
            #[cfg(any(feature = "dtls", feature = "ice"))]
            match session.poll_transmit(now) {
                Some(datagram) => unsafe { put_datagram(&mut out, &datagram) },
                None => Ok(()),
            }
            #[cfg(not(any(feature = "dtls", feature = "ice")))]
            {
                let _ = (session, now);
                Ok(())
            }
        })?;
        unsafe { write_versioned(packet, out) }
    }
}

entry! {
    /// The RTCP goodbye of a call whose media has ended.
    ///
    /// The RFC 3550 §6.3.7 BYE is built when the session stops, after the
    /// media handle stops working, so it is polled from the stack.
    ///
    /// `out_call` gets the call it belonged to, or `SIPRAL_HANDLE_NONE` when
    /// nothing was waiting. The call is over; the handle only says which media
    /// socket to send from.
    ///
    /// One at a time: after each `sipral_stack_poll` that delivered
    /// `SIPRAL_EVENT_KIND_CALL_ENDED`, call until `packet` has `len` zero.
    ///
    /// A TURN relay (`turn_server`) is given back here too: the zero-lifetime
    /// Refresh of RFC 8656 §8, to the TURN server, from the same socket. It is
    /// queued at call end, or earlier when the call does not use the relay, so
    /// polling after every `sipral_stack_poll` releases it sooner.
    ///
    /// # Safety
    ///
    /// `out_call` must point at one `sipral_handle_t`, and `packet` at a
    /// `sipral_media_packet_t` as [`sipral_media_capture`] describes.
    fn sipral_stack_poll_farewell(
        stack: SipralHandle,
        out_call: *mut SipralHandle,
        packet: *mut SipralMediaPacket,
    ) {
        if out_call.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_call is null"));
        }
        let mut out = unsafe { read_versioned(packet) }?;
        prepare(&mut out)?;
        let call = with_stack(stack, |state| {
            let Some((call, destination, payload, protocol)) = state.farewells.pop_front() else {
                return Ok(crate::handle::SIPRAL_HANDLE_NONE);
            };
            unsafe { put(&mut out, destination, &payload, protocol) }?;
            Ok(call)
        })?;
        unsafe { out_call.write(call) };
        unsafe { write_versioned(packet, out) }
    }
}

/// Check the caller's buffers before anything is built, and clear the output
/// lengths so stale values never read as a packet.
pub(crate) fn prepare(packet: &mut SipralMediaPacket) -> Result<(), Fail> {
    packet.len = 0;
    packet.destination_len = 0;
    packet.protocol = crate::stack::SipralTransport::Udp as u32;
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

/// Put one session datagram in the caller's buffers, with its transport.
///
/// # Safety
///
/// As [`put`].
pub(crate) unsafe fn put_datagram(
    packet: &mut SipralMediaPacket,
    datagram: &sipral::Datagram<'_>,
) -> Result<(), Fail> {
    #[cfg(feature = "ice")]
    let protocol = crate::nat::protocol_of(datagram.transport);
    #[cfg(not(feature = "ice"))]
    let protocol = crate::stack::SipralTransport::Udp as u32;
    unsafe { put(packet, datagram.destination, datagram.payload, protocol) }
}

/// Put one datagram in the caller's buffers.
///
/// DTLS, ICE and TURN-wrapped datagrams are built outside the
/// [`SIPRAL_MEDIA_PACKET_BYTES`] bound, so the length is checked here: too
/// long is `SIPRAL_STATUS_BUFFER_TOO_SMALL` and nothing is written.
///
/// # Safety
///
/// The buffers in `packet` must be writable for the capacities beside them,
/// which [`prepare`] has already been asked about.
pub(crate) unsafe fn put(
    packet: &mut SipralMediaPacket,
    destination: SocketAddr,
    payload: &[u8],
    protocol: u32,
) -> Result<(), Fail> {
    if payload.len() > packet.capacity {
        return Err(fail(
            SipralStatus::BufferTooSmall,
            format!(
                "a datagram of {} bytes is waiting and the packet buffer has room for {}",
                payload.len(),
                packet.capacity
            ),
        ));
    }
    unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), packet.data, payload.len()) };
    packet.len = payload.len();
    packet.protocol = protocol;
    if packet.destination.is_null() {
        return Ok(());
    }
    let written = destination.to_string();
    if written.len() >= SIPRAL_ADDRESS_BYTES {
        // unreachable: a bracketed IPv6 and port fit
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

/// Put a dial string in the media: as telephone events, or as in-band tones
/// when none were negotiated or `in_band` asks. Reached from
/// [`sipral_call_send_dtmf`](crate::call).
pub(crate) fn dial_in_media(
    state: &mut StackState,
    call: sipral_ua::CallHandle,
    keys: &str,
    length: Duration,
    in_band: bool,
) -> Result<(), Fail> {
    // the one media operation reached through the stack: media versus INFO is
    // a call decision
    let mut session = state.engine.session(call).ok_or_else(|| {
        fail(
            SipralStatus::WrongState,
            "this call has no media to put a digit in: it was not placed or answered with a media \
             address of its own, or its negotiation has not settled yet",
        )
    })?;
    let dialled = if in_band {
        session.dial_in_band(keys, length)
    } else {
        session.dial(keys, length)
    };
    dialled.map(|_| ()).map_err(|error| media_failed(&error))
}

entry! {
    /// Whether a digit is going out or waiting to, and how many have not
    /// started yet.
    ///
    /// Either out parameter may be null.
    ///
    /// # Safety
    ///
    /// `out_dialling` must point at one `uint32_t` or be null, and
    /// `out_waiting` at one `size_t` or be null.
    fn sipral_media_dialling(
        media: SipralHandle,
        out_dialling: *mut u32,
        out_waiting: *mut usize,
    ) {
        let (busy, waiting) = with_media(media, |session, _| {
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
    /// The digit in flight gets no closing packet.
    ///
    /// # Safety
    ///
    /// Reads no memory the caller owns.
    fn sipral_media_stop_dialling(media: SipralHandle) {
        with_media(media, |session, _| {
            session.stop_dialling();
            Ok(())
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::toggled;
    use super::{
        CProcessor, Codec, SIPRAL_ADDRESS_BYTES, SIPRAL_MEDIA_PACKET_BYTES, SipralArrival,
        SipralCodec, SipralCodecCandidate, SipralCodecInfo, SipralCodecOutcome, SipralDirection,
        SipralMediaFault, SipralMediaInfo, SipralMediaPacket, SipralPlayback, SipralProcessorFrame,
        SipralRtcp, SipralSrtp, SipralStreamStats, SipralToggle, catalog_of, media_failed,
        named_codec, ordered, sipral_call_media, sipral_codec_at, sipral_codec_count,
        sipral_codec_name, sipral_media_capture, sipral_media_codec_candidate_at,
        sipral_media_codec_candidate_count, sipral_media_dialling, sipral_media_info,
        sipral_media_mix, sipral_media_playback, sipral_media_poll_rtcp, sipral_media_receive,
        sipral_media_release, sipral_media_statistics, sipral_media_stop_dialling,
        sipral_stack_codec_order, sipral_stack_poll_farewell, srtp_policy,
    };
    use crate::call::tests::{
        ANSWER, PEER_MEDIA, SECOND_PEER_MEDIA, accepted, account_on, connected, deliver, hangup,
        managed_config, media_call, media_call_offering, media_call_pair, media_call_refused,
        media_call_tuned, media_line, one, place, sent,
    };
    use crate::call::{sipral_call_join, sipral_call_leave};
    use crate::error::last_error_text;
    use crate::event::{SipralEvent, SipralEventKind};
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::stack::tests::Observed;
    use crate::status::SipralStatus;
    use sipral::{Capabilities, MediaError, Processor, SrtpPolicy};
    use std::ffi::{CStr, c_char, c_void};
    use std::net::SocketAddr;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::{Duration, Instant};

    /// One G.711 frame: 20 ms at 8 kHz.
    pub(crate) const FRAME: usize = 160;

    const ORDER: &str = "G722,PCMA";

    /// The far end's answer to an Opus-only offer; RFC 7587 §7 requires the
    /// `/2` channel count.
    pub(crate) const OPUS_ANSWER: &[u8] = b"v=0\r\n\
o=bob 1 1 IN IP4 203.0.113.5\r\n\
s=-\r\n\
c=IN IP4 203.0.113.5\r\n\
t=0 0\r\n\
m=audio 41000 RTP/AVP 96\r\n\
a=rtpmap:96 opus/48000/2\r\n\
a=sendrecv\r\n";

    /// The same for G.722, whose clock is half its rate (RFC 3551 §4.5.2).
    const WIDEBAND_ANSWER: &[u8] = b"v=0\r\n\
o=bob 1 1 IN IP4 203.0.113.5\r\n\
s=-\r\n\
c=IN IP4 203.0.113.5\r\n\
t=0 0\r\n\
m=audio 41000 RTP/AVP 9\r\n\
a=rtpmap:9 G722/8000\r\n\
a=sendrecv\r\n";

    /// One mu-law RTP packet from the far end.
    pub(crate) fn rtp(sequence: u16, timestamp: u32) -> Vec<u8> {
        let mut out = vec![0x80, 0x00];
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&timestamp.to_be_bytes());
        out.extend_from_slice(&0xDEAD_BEEF_u32.to_be_bytes());
        out.extend_from_slice(&[0xFF; FRAME]);
        out
    }

    /// Filled with sentinels, so an unwritten struct differs from zeroes.
    pub(crate) fn media_info_zeroed() -> SipralMediaInfo {
        SipralMediaInfo {
            reserved: 0,
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
            has_text: u32::MAX,
            feedback: u32::MAX,
            generic_nack: u32::MAX,
            reduced_size: u32::MAX,
        }
    }

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
                reserved: 0,
                size: size_of::<SipralMediaPacket>(),
                data: self.packet.as_mut_ptr(),
                capacity: self.packet.len(),
                len: usize::MAX,
                destination: self.address.as_mut_ptr(),
                destination_capacity: self.address.len(),
                destination_len: usize::MAX,
                protocol: u32::MAX,
            }
        }

        pub(crate) fn taken(&self, packet: &SipralMediaPacket) -> (Vec<u8>, String) {
            let payload = self.packet[..packet.len].to_vec();
            let written = unsafe { CStr::from_ptr(self.address.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            (payload, written)
        }
    }

    pub(crate) fn media_of(stack: SipralHandle, call: SipralHandle) -> SipralHandle {
        let mut media = SIPRAL_HANDLE_NONE;
        let status = unsafe { sipral_call_media(stack, call, &raw mut media) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_ne!(media, SIPRAL_HANDLE_NONE);
        media
    }

    pub(crate) fn release(media: SipralHandle) {
        assert_eq!(
            unsafe { sipral_media_release(media) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
    }

    pub(crate) fn play_one(media: SipralHandle) -> SipralPlayback {
        let mut samples = [0_i16; FRAME];
        let mut written = 0_usize;
        let mut source = u32::MAX;
        let status = unsafe {
            sipral_media_playback(
                media,
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

    /// Capture one frame; returns the packet length.
    pub(crate) fn capture_one(media: SipralHandle, samples: &[i16]) -> usize {
        let mut buffers = Buffers::new();
        let mut packet = buffers.packet();
        let status = unsafe {
            sipral_media_capture(media, 0, samples.as_ptr(), samples.len(), &raw mut packet)
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        packet.len
    }

    pub(crate) fn media_info(media: SipralHandle) -> SipralMediaInfo {
        let mut info = media_info_zeroed();
        let status = unsafe { sipral_media_info(media, &raw mut info) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        info
    }

    pub(crate) fn statistics(media: SipralHandle, now_ms: u64) -> SipralStreamStats {
        let mut read = empty_stats();
        let status = unsafe { sipral_media_statistics(media, now_ms, &raw mut read) };
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
            has_voip_metrics: u32::MAX,
            voip_loss_rate_256: u32::MAX,
            voip_discard_rate_256: u32::MAX,
            voip_burst_density_256: u32::MAX,
            voip_burst_duration_us: u64::MAX,
            voip_gap_density_256: u32::MAX,
            voip_gap_duration_us: u64::MAX,
            voip_gmin: u32::MAX,
            voip_end_system_delay_us: u64::MAX,
            voip_jitter_buffer_nominal_us: u64::MAX,
            voip_jitter_buffer_maximum_us: u64::MAX,
            voip_jitter_buffer_abs_max_us: u64::MAX,
            has_voip_r_factor: u32::MAX,
            voip_r_factor: u32::MAX,
            has_voip_mos_lq: u32::MAX,
            voip_mos_lq_x10: u32::MAX,
            has_voip_mos_cq: u32::MAX,
            voip_mos_cq_x10: u32::MAX,
            frames_underrun: u64::MAX,
            feedback: u32::MAX,
            trr_interval_ms: u32::MAX,
            nacks_sent: u64::MAX,
            packets_nacked: u64::MAX,
            nacks_received: u64::MAX,
            packets_asked_for: u64::MAX,
            early_packets: u64::MAX,
            reduced_size_packets: u64::MAX,
            feedback_suppressed: u64::MAX,
        }
    }

    pub(crate) fn arrive(
        media: SipralHandle,
        datagram: &mut [u8],
        from: &str,
        now_ms: u64,
    ) -> SipralArrival {
        let mut arrival = u32::MAX;
        let status = unsafe {
            sipral_media_receive(
                media,
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

    /// The names are written out by hand; this keeps them in step with the wire.
    #[test]
    fn every_codec_is_named_the_way_it_goes_on_the_wire() {
        for codec in Codec::ALL {
            let number = named_codec(codec) as u32;
            assert_eq!(
                name(number).as_deref(),
                Some(codec.name()),
                "{codec:?} is named differently here and in a codec order"
            );
            assert!(codec.name().starts_with(codec.encoding_name()));
        }
    }

    #[test]
    fn the_codec_numbers_are_where_they_were_published() {
        assert_eq!(SipralCodec::Unknown as u32, 0);
        assert_eq!(SipralCodec::Pcmu as u32, 1);
        assert_eq!(SipralCodec::Pcma as u32, 2);
        assert_eq!(SipralCodec::G722 as u32, 3);
        assert_eq!(
            SipralCodec::Opus as u32,
            4,
            "the number is the ABI and stays whether or not the codec is here"
        );
        assert_eq!(
            name(SipralCodec::Opus as u32).is_some(),
            Capabilities::of_this_build().opus,
            "the number is published in every build and the name is the \
             catalogue's: null where this build linked no Opus"
        );
        assert_eq!(SipralCodec::G729 as u32, 5);
        assert_eq!(
            name(SipralCodec::G729 as u32).as_deref(),
            Some("G729"),
            "written in-tree, so in every build"
        );
        assert_eq!(SipralCodec::L16Narrowband as u32, 6);
        assert_eq!(SipralCodec::L16Wideband as u32, 7);
        assert_eq!(name(6).as_deref(), Some("L16/8000"));
        assert_eq!(name(7).as_deref(), Some("L16/16000"));
        assert_eq!(name(0), None, "no codec is zero");
        assert_eq!(name(8), None);
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
                reserved: 0,
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
            .find(|info| info.codec == SipralCodec::Opus as u32);
        assert_eq!(
            opus.is_some(),
            Capabilities::of_this_build().opus,
            "the enumeration and the build disagree about Opus"
        );
        if let Some(opus) = opus {
            assert_eq!(opus.has_static_payload_type, 0);
            assert_eq!(opus.static_payload_type, 0);
        }
    }

    #[test]
    fn there_is_no_codec_past_the_end() {
        let mut info = SipralCodecInfo {
            reserved: 0,
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
        let refused = ordered("PCMA,G723").expect_err("G.723.1 is not in this build");
        assert_eq!(refused.status, SipralStatus::NotSupported);

        let refused = ordered("speex").expect_err("nor is Speex");
        assert_eq!(refused.status, SipralStatus::NotSupported);
    }

    #[test]
    fn a_codec_named_twice_is_an_argument_that_was_wrong() {
        let refused = ordered("PCMU,pcmu").expect_err("one format is listed once");
        assert_eq!(refused.status, SipralStatus::InvalidArgument);

        let refused = ordered("PCMU,,PCMA").expect_err("a stray comma names nothing");
        assert_eq!(refused.status, SipralStatus::InvalidArgument);
    }

    #[test]
    fn an_order_that_names_what_this_build_has_is_taken_in_that_order() {
        let catalog = ordered(" G722 , PCMA ").expect("both are in this build");
        assert_eq!(catalog.codecs(), [Codec::G722, Codec::Pcma]);
    }

    /// Branches on the catalogue, not this crate's `opus` feature, which can be
    /// off over a facade that linked Opus.
    #[test]
    fn an_order_that_names_opus_follows_the_catalogue() {
        let asked = ordered(" opus , PCMA ");
        if Capabilities::of_this_build().opus {
            let named: Vec<&str> = asked
                .expect("both are in this build")
                .codecs()
                .iter()
                .map(|codec| codec.encoding_name())
                .collect();
            assert_eq!(named, ["opus", "PCMA"]);
        } else {
            let refused = asked.expect_err("this build has no Opus");
            assert_eq!(refused.status, SipralStatus::NotSupported);
        }
    }

    /// Opus cannot cut 7 ms; without Opus the name itself is refused first.
    #[test]
    fn an_order_naming_a_codec_that_cannot_cut_the_frame_length_is_refused() {
        let refused = catalog_of(Some("opus"), 7, true, false, None, None, true)
            .expect_err("no build here cuts a seven-millisecond Opus frame");
        assert_eq!(
            refused.status,
            if Capabilities::of_this_build().opus {
                SipralStatus::InvalidArgument
            } else {
                SipralStatus::NotSupported
            }
        );
    }

    #[test]
    fn a_frame_length_every_codec_in_the_order_cuts_is_taken() {
        let taken = catalog_of(Some("PCMU"), 7, true, false, None, None, true)
            .expect("G.711 cuts a whole number of samples at any millisecond");
        assert_eq!(taken.frame_length(), 7);
    }

    #[test]
    fn srtp_policy_reads_the_three_named_values_and_zero_as_unspecified() {
        assert_eq!(srtp_policy(0, "srtp").expect("zero is valid"), None);
        assert_eq!(
            srtp_policy(SipralSrtp::NotOffered as u32, "srtp").expect("named"),
            Some(SrtpPolicy::NotOffered)
        );
        assert_eq!(
            srtp_policy(SipralSrtp::Offered as u32, "srtp").expect("named"),
            Some(SrtpPolicy::Offered)
        );
        assert_eq!(
            srtp_policy(SipralSrtp::Required as u32, "srtp").expect("named"),
            Some(SrtpPolicy::Required)
        );
        assert_eq!(
            srtp_policy(SipralSrtp::BestEffort as u32, "srtp").expect("named"),
            Some(SrtpPolicy::BestEffort)
        );
    }

    #[test]
    fn srtp_policy_refuses_anything_else() {
        let refused = srtp_policy(8, "srtp").expect_err("8 names no policy");
        assert_eq!(refused.status, SipralStatus::InvalidArgument);
    }

    #[test]
    fn catalog_of_applies_srtp_only_when_one_was_named() {
        let default =
            catalog_of(None, 0, true, false, None, None, true).expect("a plain catalogue");
        assert_eq!(default.srtp(), SrtpPolicy::default());

        let required = catalog_of(None, 0, true, false, Some(SrtpPolicy::Required), None, true)
            .expect("a catalogue");
        assert_eq!(required.srtp(), SrtpPolicy::Required);
    }

    /// Carried even without G.729 in the order: a call's order may name it.
    #[test]
    fn catalog_of_carries_annex_b_either_way() {
        for order in [Some("G729"), Some("PCMU"), None] {
            for allowed in [true, false] {
                let catalog =
                    catalog_of(order, 0, true, false, None, None, allowed).expect("a catalogue");
                assert_eq!(catalog.g729_annex_b(), allowed, "{order:?}");
            }
        }
    }

    /// The top codec's encoder gets half a frame. Only Opus refuses it, so a
    /// build without Opus produces no codec error at all.
    #[test]
    fn the_codecs_own_refusal_is_answered_before_the_table() {
        let opus = Capabilities::of_this_build().opus;
        let (order, answer) = if opus {
            ("opus", OPUS_ANSWER)
        } else {
            ("G722", WIDEBAND_ANSWER)
        };
        let mut observed = Observed::default();
        let (stack, call) = media_call_offering(&mut observed, order, answer);
        let media = media_of(stack, call);
        assert_eq!(
            media_info(media).codec,
            named_codec(Codec::ALL[0]) as u32,
            "the call did not settle on the codec at the top of this build"
        );

        let refused = super::with_media(media, |session, _| {
            // loud, so silence suppression does not swallow it
            Ok(session
                .capture(
                    &vec![8_000_i16; session.frame_samples() / 2],
                    Instant::now(),
                )
                .err())
        })
        .expect("the call has media");

        assert_eq!(
            refused.is_some(),
            opus,
            "Opus is the only codec here with an opinion about a frame it \
             did not expect"
        );
        let Some(error) = refused else { return };
        assert!(error.is_codec(), "{error}");
        assert_eq!(super::fault_of(&error), SipralMediaFault::Codec);
        assert_eq!(
            media_failed(&error).status,
            SipralStatus::InvalidArgument,
            "the same frame at the length the call agreed would be taken, \
             so it is the argument that was wrong and not the build"
        );
        hangup(stack, call, 2_000);
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
                MediaError::unsupported("G723"),
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
            (
                MediaError::Recording(std::io::ErrorKind::StorageFull),
                SipralStatus::RecordingFailed,
                SipralMediaFault::Recording,
            ),
            (
                MediaError::RecordingRate { hertz: 44_100 },
                SipralStatus::InvalidArgument,
                SipralMediaFault::Recording,
            ),
            (
                MediaError::RecordingBitrate { bits_per_second: 1 },
                SipralStatus::InvalidArgument,
                SipralMediaFault::Recording,
            ),
            (
                MediaError::ConsentTone("frequency_hz is outside 300 to 3400"),
                SipralStatus::InvalidArgument,
                SipralMediaFault::Other,
            ),
        ];
        for (error, status, fault) in cases {
            assert_eq!(media_failed(&error).status, status, "{error}");
            assert_eq!(super::fault_of(&error), fault, "{error}");
        }
    }

    #[test]
    fn a_call_reports_what_it_negotiated() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let info = media_info(media_of(stack, call));
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

    /// Names two of three offered formats, giving all three outcomes at once.
    const TWO_FORMATS: &[u8] = b"v=0\r\n\
o=bob 1 1 IN IP4 203.0.113.5\r\n\
s=-\r\n\
c=IN IP4 203.0.113.5\r\n\
t=0 0\r\n\
m=audio 41000 RTP/AVP 8 9\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=rtpmap:9 G722/8000\r\n\
a=sendrecv\r\n";

    fn candidate_count(media: SipralHandle) -> usize {
        let mut count = usize::MAX;
        let status = unsafe { sipral_media_codec_candidate_count(media, &raw mut count) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        count
    }

    fn candidate_zeroed() -> SipralCodecCandidate {
        SipralCodecCandidate {
            reserved: 0,
            size: size_of::<SipralCodecCandidate>(),
            codec: u32::MAX,
            outcome: u32::MAX,
            outranked_by: u32::MAX,
        }
    }

    fn candidate_at(media: SipralHandle, index: usize) -> SipralCodecCandidate {
        let mut candidate = candidate_zeroed();
        let status = unsafe { sipral_media_codec_candidate_at(media, index, &raw mut candidate) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        candidate
    }

    #[test]
    fn every_codec_this_call_could_have_used_says_what_became_of_it() {
        let mut observed = Observed::default();
        let (stack, call) = media_call_offering(&mut observed, "PCMU,PCMA,G722", TWO_FORMATS);
        let media = media_of(stack, call);

        assert_eq!(candidate_count(media), 3, "one entry per codec offered");

        let never = candidate_at(media, 0);
        assert_eq!(never.codec, SipralCodec::Pcmu as u32);
        assert_eq!(never.outcome, SipralCodecOutcome::NotNamed as u32);
        assert_eq!(
            never.outranked_by,
            SipralCodec::Unknown as u32,
            "nothing beat a codec that was never named"
        );

        let won = candidate_at(media, 1);
        assert_eq!(won.codec, SipralCodec::Pcma as u32);
        assert_eq!(won.outcome, SipralCodecOutcome::Chosen as u32);
        assert_eq!(won.outranked_by, SipralCodec::Unknown as u32);

        let beaten = candidate_at(media, 2);
        assert_eq!(beaten.codec, SipralCodec::G722 as u32);
        assert_eq!(beaten.outcome, SipralCodecOutcome::Outranked as u32);
        assert_eq!(
            beaten.outranked_by,
            SipralCodec::Pcma as u32,
            "the answer does not say what beat it"
        );

        assert_eq!(won.codec, media_info(media).codec);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn the_candidates_are_the_calls_own_order_not_the_stacks() {
        let mut observed = Observed::default();
        let (stack, call) = media_call_offering(&mut observed, "PCMA", TWO_FORMATS);
        let media = media_of(stack, call);
        assert_eq!(candidate_count(media), 1);
        let only = candidate_at(media, 0);
        assert_eq!(only.codec, SipralCodec::Pcma as u32);
        assert_eq!(only.outcome, SipralCodecOutcome::Chosen as u32);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_candidate_index_past_the_end_says_how_many_there_are() {
        let mut observed = Observed::default();
        let (stack, call) = media_call_offering(&mut observed, "PCMU,PCMA", ANSWER);
        let media = media_of(stack, call);
        let mut candidate = candidate_zeroed();
        assert_eq!(
            unsafe { sipral_media_codec_candidate_at(media, 2, &raw mut candidate) },
            SipralStatus::InvalidArgument
        );
        let said = last_error_text();
        assert!(said.contains('2') && said.contains("had 2"), "{said}");
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// The size is checked before the handle.
    #[test]
    fn a_candidate_struct_shorter_than_its_min_size_is_unsupported_version() {
        let mut candidate = candidate_zeroed();
        candidate.size =
            <crate::media::SipralCodecCandidate as crate::versioned::Versioned>::MIN_SIZE - 1;
        assert_eq!(
            unsafe { sipral_media_codec_candidate_at(SIPRAL_HANDLE_NONE, 0, &raw mut candidate) },
            SipralStatus::UnsupportedVersion
        );
    }

    #[test]
    fn a_null_candidate_count_is_invalid_argument() {
        assert_eq!(
            unsafe { sipral_media_codec_candidate_count(SIPRAL_HANDLE_NONE, ptr::null_mut()) },
            SipralStatus::InvalidArgument
        );
    }

    /// The size is checked before the handle.
    #[test]
    fn a_media_info_struct_shorter_than_its_min_size_is_unsupported_version_even_for_an_invalid_handle()
     {
        let mut info = media_info_zeroed();
        info.size = <crate::media::SipralMediaInfo as crate::versioned::Versioned>::MIN_SIZE - 1;
        assert_eq!(
            unsafe { sipral_media_info(SIPRAL_HANDLE_NONE, &raw mut info) },
            SipralStatus::UnsupportedVersion
        );
    }

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

    /// 2 KB is past the media bound and inside the RTCP bound: as control it
    /// reaches the session (RFC 5761 §4), as media it is refused by length.
    #[test]
    fn a_long_report_is_read_and_a_long_media_packet_is_not() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);

        let mut report = vec![0_u8; 2_000];
        report[0] = 0x80;
        report[1] = 201; // RFC 3550 §6.4.2: a receiver report
        assert_eq!(
            arrive(media, &mut report, PEER_MEDIA, 1_100),
            SipralArrival::ControlRefused,
            "the length was not what refused it"
        );

        let mut oversized = rtp(1, 160);
        oversized.resize(2_000, 0xFF);
        let refused = unsafe {
            sipral_media_receive(
                media,
                oversized.as_mut_ptr(),
                oversized.len(),
                PEER_MEDIA.as_ptr().cast::<c_char>(),
                PEER_MEDIA.len(),
                1_100,
                ptr::null_mut(),
            )
        };
        assert_eq!(refused, SipralStatus::InvalidArgument);
        assert!(
            last_error_text().contains(&SIPRAL_MEDIA_PACKET_BYTES.to_string()),
            "the refusal names the control bound: {}",
            last_error_text()
        );

        assert_eq!(unsafe { sipral_media_release(media) }, SipralStatus::Ok);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn the_statistics_count_what_went_out_and_what_came_in() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);

        let idle = statistics(media, 1_100);
        assert_eq!(idle.codec, SipralCodec::Pcmu as u32);
        assert_eq!(idle.packets_sent, 0);
        assert_eq!(idle.packets_received, 0);
        assert_eq!(idle.has_round_trip, 0, "no report has come back");
        assert!((idle.score - 100.0).abs() < 0.1, "read {}", idle.score);
        assert_eq!(idle.suffering, 0);

        for _ in 0..5 {
            assert_eq!(capture_one(media, &[2_000; FRAME]), FRAME + 12);
        }
        for (index, sequence) in (100..104_u16).enumerate() {
            let mut packet = rtp(sequence, 8_000 + u32::try_from(index).unwrap_or(0) * 160);
            arrive(media, &mut packet, PEER_MEDIA, 1_100);
        }

        let after = statistics(media, 1_200);
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

    /// Exactly the silent frames between the last packet played and the next
    /// one on the far end's clock count as `frames_underrun`.
    #[test]
    fn frames_played_as_nothing_while_the_far_end_talked_are_counted_as_under_runs() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        let timestamp = |sequence: u16| 8_000 + u32::from(sequence - 100) * 160;
        // each on time, so there is no jitter
        let due = |sequence: u16| 1_100 + u64::from(sequence - 100) * 20;

        for sequence in 100..104_u16 {
            let mut packet = rtp(sequence, timestamp(sequence));
            arrive(media, &mut packet, PEER_MEDIA, due(sequence));
        }
        let mut played = 0;
        let mut dry = 0;
        for _ in 0..10 {
            match play_one(media) {
                SipralPlayback::Packet => played += 1,
                SipralPlayback::Silence if played > 0 => dry += 1,
                _ => {}
            }
        }
        // one may be dropped to shorten a pause
        assert!(played >= 3, "only {played} of four packets played");
        assert!(dry > 0, "the earpiece never ran ahead of the far end");
        assert_eq!(
            statistics(media, due(103)).frames_underrun,
            0,
            "nothing says yet whether that silence was the far end's pause"
        );

        // the far end's clock ran on unbroken, so the silence was underrun
        for sequence in 104..110_u16 {
            let mut packet = rtp(sequence, timestamp(sequence));
            arrive(media, &mut packet, PEER_MEDIA, due(sequence));
        }
        loop {
            match play_one(media) {
                SipralPlayback::Packet => break,
                SipralPlayback::Silence if dry < 30 => dry += 1,
                other => panic!("{other:?} after {dry} frames of silence"),
            }
        }
        let stats = statistics(media, due(110));
        assert_eq!(stats.frames_underrun, dry);
        assert_eq!(stats.packets_lost, 0, "nothing was lost on the way");
        assert!(
            stats.loss_rate > 0.0 && stats.suffering == 1,
            "the silence counts where the call's quality is read: loss rate {}, suffering {}",
            stats.loss_rate,
            stats.suffering
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// Media reads the clock through its handle, so lagging the stack's last
    /// poll is not an error.
    #[test]
    fn a_datagram_read_on_a_clock_behind_the_stacks_own_is_not_refused() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);

        crate::stack::tests::poll(stack, 50_000);

        // RFC 3550 A.1 probation: only the last of these is queued
        let mut arrival = SipralArrival::Unknown;
        for (index, sequence) in (1..4_u16).enumerate() {
            let mut packet = rtp(sequence, u32::try_from(index).unwrap_or(0) * 160);
            arrival = arrive(media, &mut packet, PEER_MEDIA, 1_100);
        }
        assert_eq!(
            arrival,
            SipralArrival::Queued,
            "a datagram read on a clock behind the stack's own was refused instead of taken"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// An older media reading leaves the stack's clock untouched.
    #[test]
    fn a_media_call_with_an_older_now_ms_does_not_refuse_the_next_signalling_call() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);

        // the stack is at 1_100; media never checks against it
        let stats = statistics(media, 100);
        assert_eq!(
            stats.codec,
            SipralCodec::Pcmu as u32,
            "the reading was answered"
        );

        let mut result = crate::stack::tests::poll_result();
        let polled = unsafe { crate::stack::sipral_stack_poll(stack, 1_101, &raw mut result) };
        assert_eq!(polled, SipralStatus::Ok, "{}", last_error_text());

        hangup(stack, call, 1_200);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// The size is checked before the handle.
    #[test]
    fn a_stream_stats_struct_shorter_than_its_min_size_is_unsupported_version_even_for_an_invalid_handle()
     {
        let mut stats = empty_stats();
        stats.size = <crate::media::SipralStreamStats as crate::versioned::Versioned>::MIN_SIZE - 1;
        assert_eq!(
            unsafe { sipral_media_statistics(SIPRAL_HANDLE_NONE, 0, &raw mut stats) },
            SipralStatus::UnsupportedVersion
        );
    }

    /// The size is checked before the handle, for frames and reports alike.
    #[test]
    fn a_media_packet_struct_shorter_than_its_min_size_is_unsupported_version_even_for_an_invalid_handle()
     {
        let samples = [0_i16; FRAME];
        let mut buffers = Buffers::new();
        let mut packet = buffers.packet();
        packet.size =
            <crate::media::SipralMediaPacket as crate::versioned::Versioned>::MIN_SIZE - 1;
        assert_eq!(
            unsafe {
                sipral_media_capture(
                    SIPRAL_HANDLE_NONE,
                    0,
                    samples.as_ptr(),
                    samples.len(),
                    &raw mut packet,
                )
            },
            SipralStatus::UnsupportedVersion,
            "sipral_media_capture"
        );
        assert_eq!(
            unsafe { sipral_media_poll_rtcp(SIPRAL_HANDLE_NONE, 0, &raw mut packet) },
            SipralStatus::UnsupportedVersion,
            "sipral_media_poll_rtcp"
        );
    }

    /// The stream is gone by then, so the numbers travel in the event.
    #[test]
    fn the_end_of_call_record_arrives_after_the_call_that_it_is_about() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        for _ in 0..3 {
            capture_one(media, &[1_000; FRAME]);
        }
        release(media);
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
        let mut media = SIPRAL_HANDLE_NONE;
        assert_eq!(
            unsafe { sipral_call_media(stack, call, &raw mut media) },
            SipralStatus::WrongState
        );
        assert_eq!(media, SIPRAL_HANDLE_NONE, "nothing was written");
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn media_that_stops_is_reported_and_so_is_its_return() {
        let mut observed = Observed::default();
        let (stack, call) = media_call_tuned(&mut observed, |config| {
            config.media_stall_ms = 400;
        });
        let media = media_of(stack, call);
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
        assert_eq!(media_info(media).stalled, 1);

        // RFC 3550 A.1 probation needs two in a row
        for (index, sequence) in (200..203_u16).enumerate() {
            let mut packet = rtp(sequence, 16_000 + u32::try_from(index).unwrap_or(0) * 160);
            arrive(media, &mut packet, PEER_MEDIA, 1_700);
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
        assert_eq!(media_info(media).stalled, 0);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

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
        let mut media = SIPRAL_HANDLE_NONE;
        assert_eq!(
            unsafe { sipral_call_media(stack, call, &raw mut media) },
            SipralStatus::WrongState,
            "and there is no stream to hand out a handle for"
        );
        assert_eq!(media, SIPRAL_HANDLE_NONE);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_captured_frame_comes_back_addressed_to_where_the_audio_goes() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        let mut buffers = Buffers::new();
        let mut packet = buffers.packet();
        let samples = [3_000_i16; FRAME];
        let status = unsafe {
            sipral_media_capture(media, 0, samples.as_ptr(), samples.len(), &raw mut packet)
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

    #[test]
    fn join_leave_and_mix_move_a_frame_between_two_calls_on_one_stack() {
        let mut observed = Observed::default();
        let (stack, call_a, call_b) = media_call_pair(&mut observed);
        let mut media_a = SIPRAL_HANDLE_NONE;
        let mut media_b = SIPRAL_HANDLE_NONE;
        assert_eq!(
            unsafe { sipral_call_media(stack, call_a, &raw mut media_a) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_call_media(stack, call_b, &raw mut media_b) },
            SipralStatus::Ok
        );

        assert_eq!(
            unsafe { sipral_call_join(stack, call_a, call_a) },
            SipralStatus::InvalidArgument,
            "a call cannot be joined to itself"
        );
        assert_eq!(
            unsafe { sipral_call_join(stack, call_a, call_b) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        assert_eq!(
            unsafe { sipral_call_join(stack, call_a, call_b) },
            SipralStatus::WrongState,
            "a call already joined refuses a second pairing"
        );

        let samples = [1_000_i16; FRAME];
        let mut local = [0_i16; FRAME];
        let mut buffers_a = Buffers::new();
        let mut buffers_b = Buffers::new();
        let mut packet_a = buffers_a.packet();
        let mut packet_b = buffers_b.packet();
        let status = unsafe {
            sipral_media_mix(
                media_a,
                media_b,
                0,
                samples.as_ptr(),
                samples.len(),
                local.as_mut_ptr(),
                local.len(),
                &raw mut packet_a,
                &raw mut packet_b,
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let (payload_a, destination_a) = buffers_a.taken(&packet_a);
        let (payload_b, destination_b) = buffers_b.taken(&packet_b);
        assert_eq!(payload_a.len(), FRAME + 12, "twelve octets of RTP header");
        assert_eq!(payload_b.len(), FRAME + 12, "twelve octets of RTP header");
        assert_eq!(destination_a, PEER_MEDIA, "call a's own far end");
        assert_eq!(destination_b, SECOND_PEER_MEDIA, "call b's own far end");

        assert_eq!(
            unsafe { sipral_call_leave(stack, call_a) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_call_leave(stack, call_a) },
            SipralStatus::WrongState,
            "a call already left has nothing more to leave"
        );

        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// A slice over null would abort a debug build before any answer.
    #[test]
    fn a_mix_given_no_samples_at_all_is_answered_rather_than_sliced() {
        let mut observed = Observed::default();
        let (stack, call_a, call_b) = media_call_pair(&mut observed);
        let mut media_a = SIPRAL_HANDLE_NONE;
        let mut media_b = SIPRAL_HANDLE_NONE;
        assert_eq!(
            unsafe { sipral_call_media(stack, call_a, &raw mut media_a) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_call_media(stack, call_b, &raw mut media_b) },
            SipralStatus::Ok
        );
        let mut buffers_a = Buffers::new();
        let mut buffers_b = Buffers::new();
        let mut packet_a = buffers_a.packet();
        let mut packet_b = buffers_b.packet();
        let status = unsafe {
            sipral_media_mix(
                media_a,
                media_b,
                0,
                ptr::null(),
                0,
                ptr::null_mut(),
                0,
                &raw mut packet_a,
                &raw mut packet_b,
            )
        };
        assert_eq!(
            status,
            SipralStatus::InvalidArgument,
            "{}",
            last_error_text()
        );
        assert!(
            last_error_text().contains("mic was 0"),
            "{}",
            last_error_text()
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// The facade half (`MediaEvent::Unjoined`) is tested in
    /// `crates/sipral/src/tests.rs`; this covers the ABI translation.
    #[test]
    fn a_call_that_hangs_up_while_joined_tells_the_survivor_over_the_abi() {
        let mut observed = Observed::default();
        let (stack, call_a, call_b) = media_call_pair(&mut observed);
        let mut media_a = SIPRAL_HANDLE_NONE;
        assert_eq!(
            unsafe { sipral_call_media(stack, call_a, &raw mut media_a) },
            SipralStatus::Ok
        );
        assert_eq!(
            unsafe { sipral_call_join(stack, call_a, call_b) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );

        hangup(stack, call_b, 3_000);

        assert!(
            observed
                .of(SipralEventKind::MediaUnjoined)
                .iter()
                .any(|heard| heard.call == call_a),
            "call a was never told its partner was gone: {:?}",
            observed.kinds()
        );

        let samples = [1_000_i16; FRAME];
        let mut buffers = Buffers::new();
        let mut packet = buffers.packet();
        assert_eq!(
            unsafe {
                sipral_media_capture(
                    media_a,
                    3_100,
                    samples.as_ptr(),
                    samples.len(),
                    &raw mut packet,
                )
            },
            SipralStatus::Ok,
            "call a's own media did not survive its partner: {}",
            last_error_text()
        );

        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_frame_of_the_wrong_length_is_refused_before_it_is_encoded() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        let mut buffers = Buffers::new();
        let mut packet = buffers.packet();
        let short = [0_i16; 80];
        let status =
            unsafe { sipral_media_capture(media, 0, short.as_ptr(), short.len(), &raw mut packet) };
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("160"));
        assert_eq!(
            statistics(media, 1_100).packets_sent,
            0,
            "and nothing went out"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_packet_buffer_too_small_costs_no_audio() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        let mut small = [0_u8; 64];
        let mut packet = SipralMediaPacket {
            reserved: 0,
            size: size_of::<SipralMediaPacket>(),
            data: small.as_mut_ptr(),
            capacity: small.len(),
            len: usize::MAX,
            destination: ptr::null_mut(),
            destination_capacity: 0,
            destination_len: 0,
            protocol: u32::MAX,
        };
        let samples = [1_000_i16; FRAME];
        let status = unsafe {
            sipral_media_capture(media, 0, samples.as_ptr(), samples.len(), &raw mut packet)
        };
        assert_eq!(status, SipralStatus::BufferTooSmall);
        assert_eq!(
            statistics(media, 1_100).packets_sent,
            0,
            "the frame was not encoded and thrown away"
        );
        assert_eq!(capture_one(media, &samples), FRAME + 12);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn playback_fills_the_frame_even_when_nothing_has_arrived() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        assert_eq!(play_one(media_of(stack, call)), SipralPlayback::Silence);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_buffer_shorter_than_a_frame_says_how_many_samples_it_needed() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        let mut samples = [0_i16; 80];
        let mut written = 0_usize;
        let status = unsafe {
            sipral_media_playback(
                media,
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

    /// RFC 3550 §6.3 reports go to the negotiated control port.
    #[test]
    fn the_report_that_becomes_due_comes_out_addressed_to_the_control_port() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        let mut buffers = Buffers::new();
        let mut packet = buffers.packet();

        let mut due = None;
        for tick in 1..=120_u64 {
            packet = buffers.packet();
            let status =
                unsafe { sipral_media_poll_rtcp(media, 1_100 + tick * 500, &raw mut packet) };
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            if packet.len != 0 {
                due = Some(tick);
                break;
            }
        }
        assert!(due.is_some(), "no report in a minute of call");
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

    #[test]
    fn the_promised_buffers_hold_what_this_build_produces() {
        for codec in Codec::ALL {
            // RTP header plus the largest payload at the longest allowed frame
            let millis = (1..=60).rev().find(|ms| codec.fits(*ms)).unwrap_or(0);
            let largest = codec.max_payload(millis) + 12;
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

    #[test]
    fn a_media_handle_whose_call_has_ended_says_so_and_is_released_once() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        let other = media_of(stack, call);
        assert_ne!(media, other, "asking twice gives two handles");
        release(other);
        assert_eq!(
            play_one(media),
            SipralPlayback::Silence,
            "releasing one handle stops nothing but that handle"
        );

        hangup(stack, call, 5_000);

        let mut samples = [0x5A5A_i16; FRAME];
        let mut written = usize::MAX;
        let mut buffers = Buffers::new();
        let mut packet = buffers.packet();
        let mut info = media_info_zeroed();
        let mut stats = empty_stats();
        let mut datagram = rtp(1, 160);
        let mut dialling = u32::MAX;
        let ended = [
            ("playback", unsafe {
                sipral_media_playback(
                    media,
                    samples.as_mut_ptr(),
                    samples.len(),
                    &raw mut written,
                    ptr::null_mut(),
                )
            }),
            ("capture", unsafe {
                sipral_media_capture(media, 0, samples.as_ptr(), samples.len(), &raw mut packet)
            }),
            ("receive", unsafe {
                sipral_media_receive(
                    media,
                    datagram.as_mut_ptr(),
                    datagram.len(),
                    PEER_MEDIA.as_ptr().cast::<c_char>(),
                    PEER_MEDIA.len(),
                    6_000,
                    ptr::null_mut(),
                )
            }),
            ("poll_rtcp", unsafe {
                sipral_media_poll_rtcp(media, 6_000, &raw mut packet)
            }),
            ("info", unsafe { sipral_media_info(media, &raw mut info) }),
            ("statistics", unsafe {
                sipral_media_statistics(media, 6_000, &raw mut stats)
            }),
            ("dialling", unsafe {
                sipral_media_dialling(media, &raw mut dialling, ptr::null_mut())
            }),
            ("stop_dialling", unsafe {
                sipral_media_stop_dialling(media)
            }),
        ];
        for (name, status) in ended {
            assert_eq!(
                status,
                SipralStatus::WrongState,
                "sipral_media_{name} on a call that ended"
            );
        }
        assert!(last_error_text().contains("ended"), "{}", last_error_text());
        assert_eq!(written, usize::MAX, "nothing was written");
        assert_eq!(samples[0], 0x5A5A, "not even silence");
        assert_eq!(info.codec, u32::MAX);
        assert_eq!(stats.packets_sent, u64::MAX);
        assert_eq!(dialling, u32::MAX);

        release(media);
        assert_eq!(
            unsafe { sipral_media_release(media) },
            SipralStatus::StaleHandle
        );
        assert_eq!(
            unsafe { sipral_media_stop_dialling(media) },
            SipralStatus::StaleHandle,
            "a released handle is stale rather than ended"
        );
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_media_handle_outlives_its_stack_and_says_so() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
        let mut samples = [0_i16; FRAME];
        assert_eq!(
            unsafe {
                sipral_media_playback(
                    media,
                    samples.as_mut_ptr(),
                    samples.len(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            },
            SipralStatus::WrongState
        );
        release(media);
    }

    static MINTED: AtomicI32 = AtomicI32::new(-1);
    static PLAYED: AtomicI32 = AtomicI32::new(-1);
    static PLAYED_WROTE: AtomicUsize = AtomicUsize::new(usize::MAX);

    /// On media start, mints the handle inside the callback while another
    /// thread asks for a frame.
    unsafe extern "C" fn mint_and_play_from_the_callback(
        event: *const SipralEvent,
        user_data: *mut c_void,
    ) {
        unsafe { crate::stack::tests::record(event, user_data) };
        let event = unsafe { &*event };
        if event.kind != SipralEventKind::MediaStarted {
            return;
        }
        let mut media = SIPRAL_HANDLE_NONE;
        let minted = unsafe { sipral_call_media(event.stack, event.call, &raw mut media) };
        MINTED.store(minted as i32, Ordering::SeqCst);
        let (played, wrote) = std::thread::spawn(move || {
            let mut samples = [0x5A5A_i16; FRAME];
            let mut written = usize::MAX;
            let status = unsafe {
                sipral_media_playback(
                    media,
                    samples.as_mut_ptr(),
                    samples.len(),
                    &raw mut written,
                    ptr::null_mut(),
                )
            };
            (status as i32, written)
        })
        .join()
        .unwrap_or((-2, usize::MAX));
        PLAYED.store(played, Ordering::SeqCst);
        PLAYED_WROTE.store(wrote, Ordering::SeqCst);
        let _ = unsafe { sipral_media_release(media) };
    }

    #[test]
    fn a_callback_that_mints_the_media_handle_while_a_frame_is_due_is_not_refused() {
        let mut observed = Observed::default();
        let (stack, _call) = media_call_tuned(&mut observed, |config| {
            config.event_callback = Some(mint_and_play_from_the_callback);
        });
        assert_eq!(
            MINTED.load(Ordering::SeqCst),
            SipralStatus::Ok as i32,
            "minting the media handle from inside the callback was refused"
        );
        assert_eq!(
            PLAYED.load(Ordering::SeqCst),
            SipralStatus::Ok as i32,
            "the device thread was refused its frame while the poll thread was in the callback"
        );
        assert_eq!(PLAYED_WROTE.load(Ordering::SeqCst), FRAME);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// A processor that asks for a frame from inside the frame it processes.
    struct ReachesBack {
        media: SipralHandle,
        heard: Arc<Mutex<Option<SipralStatus>>>,
    }

    impl Processor for ReachesBack {
        fn process(&mut self, _near_end: &mut [i16], _reference: &[i16]) {
            let mut samples = [0_i16; FRAME];
            let status = unsafe {
                sipral_media_playback(
                    self.media,
                    samples.as_mut_ptr(),
                    samples.len(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if let Ok(mut heard) = self.heard.lock() {
                *heard = Some(status);
            }
        }

        fn reset(&mut self) {}
    }

    #[test]
    fn a_thread_that_reaches_back_into_the_media_it_is_inside_is_told_so() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        let heard = Arc::new(Mutex::new(None));
        let processor = ReachesBack {
            media,
            heard: Arc::clone(&heard),
        };
        super::with_media(media, |session, _| {
            session.attach_processor(Box::new(processor));
            Ok(())
        })
        .expect("the call has media");

        // on its own thread, so a self-wait fails instead of hanging
        let (done, finished) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buffers = Buffers::new();
            let mut packet = buffers.packet();
            let samples = [1_000_i16; FRAME];
            let status = unsafe {
                sipral_media_capture(media, 0, samples.as_ptr(), samples.len(), &raw mut packet)
            };
            let _ = done.send(status);
        });
        let captured = finished
            .recv_timeout(Duration::from_secs(10))
            .expect("the capture never came back: the processor's call waited for itself");
        assert_eq!(captured, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(
            *heard.lock().expect("what the processor heard"),
            Some(SipralStatus::Busy)
        );
        release(media);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// A processor that hangs up, polls and destroys its own stack from
    /// inside its frame.
    struct ReachesTheStack {
        stack: SipralHandle,
        call: SipralHandle,
        heard: Arc<Mutex<Vec<(&'static str, SipralStatus)>>>,
    }

    impl Processor for ReachesTheStack {
        fn process(&mut self, _near_end: &mut [i16], _reference: &[i16]) {
            let hung_up = unsafe { crate::call::sipral_call_hangup(self.stack, self.call, 1_200) };
            let polled =
                unsafe { crate::stack::sipral_stack_poll(self.stack, 1_200, ptr::null_mut()) };
            let destroyed = unsafe { crate::stack::sipral_stack_destroy(self.stack) };
            if let Ok(mut heard) = self.heard.lock() {
                heard.extend([
                    ("hangup", hung_up),
                    ("poll", polled),
                    ("destroy", destroyed),
                ]);
            }
        }

        fn reset(&mut self) {}
    }

    #[test]
    fn a_processor_that_calls_into_its_own_stack_is_told_so() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        let heard = Arc::new(Mutex::new(Vec::new()));
        let processor = ReachesTheStack {
            stack,
            call,
            heard: Arc::clone(&heard),
        };
        super::with_media(media, |session, _| {
            session.attach_processor(Box::new(processor));
            Ok(())
        })
        .expect("the call has media");

        let (done, finished) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buffers = Buffers::new();
            let mut packet = buffers.packet();
            let samples = [1_000_i16; FRAME];
            let status = unsafe {
                sipral_media_capture(media, 0, samples.as_ptr(), samples.len(), &raw mut packet)
            };
            let _ = done.send(status);
        });
        let captured = finished.recv_timeout(Duration::from_secs(10)).expect(
            "the capture never came back: the processor's call into the stack waited for itself",
        );
        assert_eq!(captured, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(
            *heard.lock().expect("what the processor heard"),
            [
                ("hangup", SipralStatus::Busy),
                ("poll", SipralStatus::Busy),
                ("destroy", SipralStatus::Busy),
            ]
        );
        crate::stack::tests::poll(stack, 1_300);
        assert!(
            observed.of(SipralEventKind::CallEnded).is_empty(),
            "the call was hung up from inside its own frame"
        );
        assert_eq!(
            play_one(media),
            SipralPlayback::Silence,
            "the call's media is still running"
        );
        release(media);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok,
            "and the stack is still there, and still usable"
        );
    }

    /// Writes `near_end` doubled into `out`.
    unsafe extern "C" fn doubles_into_out(
        frame: *const SipralProcessorFrame,
        _user_data: *mut c_void,
    ) {
        // Safety: `CProcessor::process` upholds `SipralProcessorCallback`'s contract.
        let frame = unsafe { &*frame };
        let near = unsafe { std::slice::from_raw_parts(frame.near_end, frame.near_end_len) };
        let out = unsafe { std::slice::from_raw_parts_mut(frame.out, frame.out_len) };
        for (slot, &sample) in out.iter_mut().zip(near) {
            *slot = sample.wrapping_mul(2);
        }
    }

    /// The only test covering [`CProcessor`]'s copy-back of `out` into the
    /// caller's frame; `bindings/c/smoke.c` checks only what is handed in.
    #[test]
    fn the_c_callback_s_frame_replaces_what_was_captured() {
        let mut processor = CProcessor {
            callback: doubles_into_out,
            user_data: ptr::null_mut(),
            out: Vec::new(),
        };
        let mut near_end = [10_i16, -20, 32_767];
        let reference = [0_i16; 3];
        processor.process(&mut near_end, &reference);
        assert_eq!(
            near_end,
            [20, -40, -2], // 32_767_i16.wrapping_mul(2)
            "the callback's own frame never reached the caller's buffer"
        );
    }

    #[test]
    fn a_datagram_longer_than_the_packet_buffer_is_refused_and_nothing_is_written() {
        let mut room = [0xAA_u8; 16];
        // Safety: every member of the struct is valid when zero
        let mut packet: SipralMediaPacket = unsafe { std::mem::zeroed() };
        packet.size = size_of::<SipralMediaPacket>();
        packet.data = room.as_mut_ptr();
        packet.capacity = 8;
        let destination = SocketAddr::from(([192, 0, 2, 1], 4_000));
        let put = unsafe { super::put(&mut packet, destination, &[1_u8; 12], 0) };
        let failure = put.expect_err("twelve bytes do not fit in eight");
        assert_eq!(failure.status, SipralStatus::BufferTooSmall);
        assert!(
            failure.message().contains("12 bytes"),
            "{}",
            failure.message()
        );
        assert_eq!(room, [0xAA; 16], "nothing was written");
        assert_eq!(packet.len, 0);
    }

    /// Inside any frame every media handle is busy; once it ends, served again.
    #[test]
    fn a_media_handle_called_from_inside_a_frame_is_busy_whichever_call_it_names() {
        let mut observed = Observed::default();
        let (stack, call) = media_call_offering(&mut observed, "PCMU,PCMA,G722", TWO_FORMATS);
        let media = media_of(stack, call);
        {
            let _frame_of_another_call = super::Inside::enter(SipralHandle::MAX);
            let mut info = media_info_zeroed();
            let status = unsafe { sipral_media_info(media, &raw mut info) };
            assert_eq!(status, SipralStatus::Busy, "{}", last_error_text());
        }
        let _ = media_info(media);
        assert_eq!(unsafe { sipral_media_release(media) }, SipralStatus::Ok);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// Off while the fixture builds the call.
    static SLOW: AtomicBool = AtomicBool::new(false);

    /// An event handler that takes 50 ms per event.
    unsafe extern "C" fn fifty_milliseconds(event: *const SipralEvent, user_data: *mut c_void) {
        unsafe { crate::stack::tests::record(event, user_data) };
        if SLOW.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Ten seconds: one thread polls with a slow callback and feeds packets,
    /// another plays a frame every 20 ms. No frame may be refused.
    #[test]
    fn a_frame_every_twenty_milliseconds_is_never_refused_while_a_slow_callback_runs() {
        const FRAMES: usize = 500;
        let mut observed = Observed::default();
        let (stack, call) = media_call_tuned(&mut observed, |config| {
            config.event_callback = Some(fifty_milliseconds);
        });
        let media = media_of(stack, call);
        SLOW.store(true, Ordering::SeqCst);

        let stop = Arc::new(AtomicBool::new(false));
        let signalling = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let started = Instant::now();
                let mut refused = Vec::new();
                let mut delivered = 0_usize;
                let mut sequence = 1_u16;
                while !stop.load(Ordering::SeqCst) {
                    let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(0);
                    let now_ms = 2_000 + elapsed;
                    // gives the slow callback an event
                    let account = account_on(stack);
                    let registered =
                        unsafe { crate::account::sipral_account_register(stack, account, now_ms) };
                    let mut packet = rtp(sequence, u32::from(sequence) * 160);
                    sequence = sequence.wrapping_add(1);
                    let received = unsafe {
                        sipral_media_receive(
                            media,
                            packet.as_mut_ptr(),
                            packet.len(),
                            PEER_MEDIA.as_ptr().cast::<c_char>(),
                            PEER_MEDIA.len(),
                            now_ms,
                            ptr::null_mut(),
                        )
                    };
                    let mut result = crate::stack::tests::poll_result();
                    let polled =
                        unsafe { crate::stack::sipral_stack_poll(stack, now_ms, &raw mut result) };
                    delivered = delivered.saturating_add(result.events_delivered);
                    let removed = unsafe { crate::account::sipral_account_remove(stack, account) };
                    let _ = sent(stack);
                    for (what, status) in [
                        ("register", registered),
                        ("receive", received),
                        ("poll", polled),
                        ("remove", removed),
                    ] {
                        if status != SipralStatus::Ok {
                            refused.push((what, status));
                        }
                    }
                }
                (refused, delivered)
            })
        };

        let mut refused = Vec::new();
        let mut short = 0_usize;
        for _ in 0..FRAMES {
            let mut samples = [0_i16; FRAME];
            let mut written = 0_usize;
            let status = unsafe {
                sipral_media_playback(
                    media,
                    samples.as_mut_ptr(),
                    samples.len(),
                    &raw mut written,
                    ptr::null_mut(),
                )
            };
            if status != SipralStatus::Ok {
                refused.push(status);
            }
            if written != FRAME {
                short = short.saturating_add(1);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        stop.store(true, Ordering::SeqCst);
        let (signalling_refused, delivered) = signalling.join().expect("the poll thread finished");
        SLOW.store(false, Ordering::SeqCst);

        assert!(
            refused.is_empty(),
            "{} of {FRAMES} frames were refused: {refused:?}",
            refused.len()
        );
        assert_eq!(short, 0, "{short} of {FRAMES} frames came back short");
        assert!(
            signalling_refused.is_empty(),
            "the poll thread was refused: {signalling_refused:?}"
        );
        assert!(
            delivered >= 50,
            "only {delivered} events reached the callback, so it was not slow for most of the run"
        );
        release(media);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// The first SSRC in the RTCP BYE (RFC 3550 §6.4.2, type 203) of a
    /// compound packet, walking sub-packets by their length in 32-bit words.
    fn first_bye_ssrc(compound: &[u8]) -> Option<u32> {
        const BYE: u8 = 203;
        let mut rest = compound;
        while rest.len() >= 4 {
            let words = u16::from_be_bytes([*rest.get(2)?, *rest.get(3)?]);
            let length = usize::from(words).saturating_add(1).saturating_mul(4);
            let packet = rest.get(..length)?;
            let header = *packet.first()?;
            if header >> 6 == 2 && packet.get(1).copied() == Some(BYE) && (header & 0x1f) > 0 {
                return Some(u32::from_be_bytes(packet.get(4..8)?.try_into().ok()?));
            }
            rest = rest.get(length..)?;
        }
        None
    }

    /// The RFC 3550 §6.3.7 BYE, to the RTCP port, naming this call's SSRC.
    #[test]
    fn a_call_that_ends_with_media_running_leaves_exactly_one_farewell() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);

        // the SSRC as the far end sees it
        let mut buffers = Buffers::new();
        let mut packet = buffers.packet();
        let status = unsafe {
            sipral_media_capture(media, 0, [0_i16; FRAME].as_ptr(), FRAME, &raw mut packet)
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let (rtp, _) = buffers.taken(&packet);
        let ssrc = u32::from_be_bytes(
            rtp.get(8..12)
                .and_then(|bytes| bytes.try_into().ok())
                .expect("a full RTP header"),
        );

        hangup(stack, call, 5_000);

        let mut out_call = SIPRAL_HANDLE_NONE;
        let mut farewell_buffers = Buffers::new();
        let mut farewell = farewell_buffers.packet();
        let status =
            unsafe { sipral_stack_poll_farewell(stack, &raw mut out_call, &raw mut farewell) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_ne!(out_call, SIPRAL_HANDLE_NONE, "the call it belonged to");
        assert_ne!(farewell.len, 0, "the call's session owed a goodbye");
        let (bye, destination) = farewell_buffers.taken(&farewell);
        assert_eq!(
            destination, "203.0.113.5:41001",
            "the far end's RTCP port, one past its media one"
        );
        assert_eq!(
            first_bye_ssrc(&bye),
            Some(ssrc),
            "the goodbye should name this call's own SSRC: {bye:02x?}"
        );

        let mut second_call = SIPRAL_HANDLE_NONE;
        let mut second = farewell_buffers.packet();
        let status =
            unsafe { sipral_stack_poll_farewell(stack, &raw mut second_call, &raw mut second) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(second.len, 0, "only one goodbye was owed");
        assert_eq!(second_call, SIPRAL_HANDLE_NONE);

        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// Unpolled farewells are capped at `FAREWELL_CEILING`; the oldest is
    /// dropped and counted in `farewells_dropped`.
    #[test]
    fn a_queue_of_farewells_past_its_ceiling_drops_the_oldest_and_counts_it() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |_| {});

        let mut first_call = SIPRAL_HANDLE_NONE;
        let mut second_call = SIPRAL_HANDLE_NONE;
        let mut now = 1_000;
        // one past the ceiling, never polled
        for i in 0..=crate::stack::FAREWELL_CEILING {
            let (status, call) = place(handle, account, &managed_config(), now);
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            let invite = one(handle);
            deliver(handle, &accepted(&invite, ANSWER, true), now + 100);
            crate::stack::tests::poll(handle, now + 100);
            let _ = sent(handle);
            match i {
                0 => first_call = call,
                1 => second_call = call,
                _ => {}
            }
            hangup(handle, call, now + 200);
            now += 1_000;
        }

        crate::stack::with_stack(handle, |state| {
            assert_eq!(
                state.farewells.len(),
                crate::stack::FAREWELL_CEILING,
                "the queue should sit at its ceiling rather than grow past it"
            );
            assert_eq!(
                state.farewells_dropped, 1,
                "exactly one farewell arrived past a queue already at the ceiling"
            );
            assert!(
                state
                    .farewells
                    .iter()
                    .all(|(named, ..)| *named != first_call),
                "the first call's own goodbye should be the one that was dropped"
            );
            assert_eq!(
                state.farewells.front().map(|(named, ..)| *named),
                Some(second_call),
                "the oldest surviving goodbye should be the second call's"
            );
            Ok(())
        })
        .expect("the stack is live");

        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_stack_that_never_ran_media_has_no_farewell() {
        let mut observed = Observed::default();
        let handle = crate::stack::tests::stack(&mut observed);

        let mut out_call = SIPRAL_HANDLE_NONE;
        let mut buffers = Buffers::new();
        let mut packet = buffers.packet();
        let status =
            unsafe { sipral_stack_poll_farewell(handle, &raw mut out_call, &raw mut packet) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(packet.len, 0);
        assert_eq!(out_call, SIPRAL_HANDLE_NONE);

        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_null_out_call_is_a_bad_argument() {
        let mut observed = Observed::default();
        let handle = crate::stack::tests::stack(&mut observed);
        let mut buffers = Buffers::new();
        let mut packet = buffers.packet();
        let status =
            unsafe { sipral_stack_poll_farewell(handle, ptr::null_mut(), &raw mut packet) };
        assert_eq!(status, SipralStatus::InvalidArgument);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    /// An answer taking all feedback: RTP/AVPF (RFC 4585), Generic NACKs and
    /// reduced-size RTCP (RFC 5506).
    const FEEDBACK_ANSWER: &[u8] = b"v=0\r\n\
o=bob 1 1 IN IP4 203.0.113.5\r\n\
s=-\r\n\
c=IN IP4 203.0.113.5\r\n\
t=0 0\r\n\
m=audio 41000 RTP/AVPF 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtcp-fb:* nack\r\n\
a=rtcp-rsize\r\n\
a=sendrecv\r\n";

    /// Returns the stack, the call and the offer.
    fn feedback_call(
        observed: &mut Observed,
        feedback: u32,
        answer: &[u8],
    ) -> (SipralHandle, SipralHandle, String) {
        let (handle, account) = media_line(observed, |_| {});
        let mut config = managed_config();
        config.feedback = feedback;
        let (status, call) = place(handle, account, &config, 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let invite = one(handle);
        deliver(handle, &accepted(&invite, answer, true), 1_100);
        crate::stack::tests::poll(handle, 1_100);
        let _ = sent(handle);
        let offer = String::from_utf8_lossy(&invite).into_owned();
        (handle, call, offer)
    }

    #[test]
    fn a_call_that_asks_for_feedback_offers_avpf_and_reports_what_was_agreed() {
        let mut observed = Observed::default();
        let (handle, call, offer) =
            feedback_call(&mut observed, SipralToggle::On as u32, FEEDBACK_ANSWER);
        assert!(offer.contains("m=audio 40000 RTP/AVPF 0"), "{offer}");
        assert!(offer.contains("a=rtcp-fb:* nack"), "{offer}");
        assert!(offer.contains("a=rtcp-rsize"), "{offer}");
        let media = media_of(handle, call);
        let info = media_info(media);
        assert_eq!(
            (info.feedback, info.generic_nack, info.reduced_size),
            (1, 1, 1)
        );
        let stats = statistics(media, 1_200);
        assert_eq!(stats.feedback, 1);
        assert_eq!(stats.nacks_sent, 0);
        assert_eq!(stats.feedback_suppressed, 0);
        release(media);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }

    #[test]
    fn a_call_that_does_not_ask_offers_plain_rtp_and_runs_no_feedback() {
        for feedback in [SipralToggle::Default as u32, SipralToggle::Off as u32] {
            let mut observed = Observed::default();
            let (handle, call, offer) = feedback_call(&mut observed, feedback, ANSWER);
            assert!(offer.contains("m=audio 40000 RTP/AVP 0"), "{offer}");
            assert!(!offer.contains("rtcp-fb"), "{offer}");
            let media = media_of(handle, call);
            let info = media_info(media);
            assert_eq!(
                (info.feedback, info.generic_nack, info.reduced_size),
                (0, 0, 0)
            );
            let stats = statistics(media, 1_200);
            assert_eq!((stats.feedback, stats.trr_interval_ms), (0, 0));
            release(media);
            assert_eq!(
                unsafe { crate::stack::sipral_stack_destroy(handle) },
                SipralStatus::Ok
            );
        }
    }

    #[test]
    fn a_feedback_setting_that_is_not_one_is_refused() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |_| {});
        let mut config = managed_config();
        config.feedback = 3;
        assert_eq!(
            place(handle, account, &config, 1_000).0,
            SipralStatus::InvalidArgument
        );
        assert!(sent(handle).is_empty(), "nothing went out");
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(handle) },
            SipralStatus::Ok
        );
    }
}
