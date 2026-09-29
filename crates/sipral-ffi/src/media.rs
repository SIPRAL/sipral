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
//! application reads a datagram and hands it over ([`sipral_media_receive`]);
//! it takes a frame of PCM and gives it to whichever device layer it linked
//! ([`sipral_media_playback`]); it takes one from the microphone and gets a
//! datagram back ([`sipral_media_capture`]); and it asks for the control
//! traffic that is due ([`sipral_media_poll_rtcp`]). Four calls, and between
//! them the whole media path.
//!
//! # A handle of its own
//!
//! All four, and every other entry point that works on one call's media, take
//! a media handle from [`sipral_call_media`] rather than the stack and the
//! call, and none of them takes the stack's lock. Each call's session has a
//! lock of its own, which waits for a frame in progress on that call and for
//! nothing else, so the thread that carries a call's audio is never refused a
//! frame because signalling, the event callback or another call is busy. The
//! reasoning, and what the handle answers once its call is gone, is in
//! `docs/08-ffi.md`.
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

use crate::abi::{alias, codes, constants, record};
use crate::error::{Fail, entry, fail};
use crate::handle::{HandleTable, Kind, SipralHandle};
use crate::stack::{StackState, handle_failed, instant_at, with_stack};
use crate::status::SipralStatus;
use crate::text::required_text;
use crate::versioned::{Versioned, read_versioned, write_versioned};

constants! {
    /// The buffer a caller has to bring for one outgoing packet.
    ///
    /// Not a path MTU — RTP does not discover one — but the bound the session
    /// itself builds against, so a payload larger than this is a payload no
    /// codec in this build produces. It is checked before anything is encoded,
    /// because a frame that was encoded and then had nowhere to go is a frame
    /// lost from a stream whose timestamps have already moved past it.
    pub const SIPRAL_MEDIA_PACKET_BYTES: usize = 1_500;

    /// The bound a datagram of control gets instead, on the way in.
    ///
    /// RTCP is compound: one report packet carries a sender or receiver report
    /// for every source being heard, then the source description, then whatever
    /// extended reports the session agreed on. A call between two ends stays
    /// far inside the media bound, but nothing in RFC 3550 says it has to, and
    /// what arrives is the peer's arithmetic rather than ours. So the media
    /// bound stops being the reason a report is refused: an arriving datagram
    /// that RFC 5761 §4 says is control gets this one, and everything else
    /// still gets [`SIPRAL_MEDIA_PACKET_BYTES`]. It bounds the read, so it is
    /// still a bound: a caller that says a megabyte is still refused.
    ///
    /// Sending is unchanged — what this stack builds is its own arithmetic, and
    /// it fits in the media bound.
    pub const SIPRAL_MEDIA_RTCP_BYTES: usize = 8_192;

    /// Room enough for any address this ABI writes, the NUL included:
    /// `[2001:db8:0000:0000:0000:0000:0000:0001]:65535` and a byte to spare.
    pub const SIPRAL_ADDRESS_BYTES: usize = 64;
}

codes! {
    /// The three answers a setting can give in a struct that starts out zeroed.
    ///
    /// A boolean cannot carry them. Zero is what a caller who filled nothing in
    /// leaves behind, so a plain `0`/`1` setting has no way to say "off" that is
    /// not also "I said nothing", and the difference is the whole of B2: the
    /// library must not turn a control off because the caller never touched it.
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
    /// Zero is not one of them, and it is not the same absence on the two
    /// structs: on the stack it means this build's own built-in default
    /// (`SrtpPolicy::default()`, which is [`SipralSrtp::NotOffered`]); on a
    /// call it means the stack's own setting, whatever that came to. The three
    /// values mean exactly what `sipral::SrtpPolicy`'s three variants mean —
    /// see there for what each writes and what each answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralSrtp: u32 {
        /// [`SrtpPolicy::NotOffered`]: do not offer it, but answer an offer
        /// that arrives on the secure profile with keys anyway.
        NotOffered = 1,
        /// [`SrtpPolicy::Offered`]: offer it, and answer a plain offer
        /// plainly.
        Offered = 2,
        /// [`SrtpPolicy::Required`]: offer it, and let no stream on this call
        /// carry audio unencrypted.
        Required = 3,
        /// [`SrtpPolicy::DtlsOffered`]: offer DTLS-SRTP (RFC 5764) on
        /// `UDP/TLS/RTP/SAVP`, and answer a plain offer plainly.
        ///
        /// What `Offered` is for SDES, with the difference that matters: the
        /// key never travels in the body, so this is the one policy here that
        /// is sound over a SIP transport somebody else can read. The cost is
        /// a round trip of silence at the start of every call while the
        /// handshake runs, and an application that names it **must** drain
        /// [`sipral_media_poll_transmit`] — a handshake whose records never
        /// leave is a call that is up, silent, and reports no error.
        ///
        /// `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
        /// `SIPRAL_FEATURE_DTLS_SRTP`.
        Dtls = 4,
        /// [`SrtpPolicy::DtlsRequired`]: offer DTLS-SRTP, and let no stream on
        /// this call carry audio any other way — an answer carrying
        /// `a=crypto` included, since that key travelled in a body this
        /// policy exists to avoid trusting.
        DtlsRequired = 5,
        /// [`SrtpPolicy::DtlsOrSdes`]: DTLS-SRTP, falling back to SDES for a
        /// peer that has no DTLS, and never unencrypted. The offer is one
        /// `RTP/SAVP` stream carrying both the fingerprint and the crypto
        /// lines, and the answer decides which keys the call; an offer that
        /// arrives is answered the way it was keyed, and a plain one is
        /// refused with 488. ABI 0.31.
        ///
        /// `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
        /// `SIPRAL_FEATURE_DTLS_SRTP`.
        DtlsOrSdes = 6,
    }
}

codes! {
    /// What a call or a stack says about ICE. Names for
    /// `sipral_stack_config_t::ice` (the stack's default) and
    /// `sipral_call_config_t::ice` (a per-call override).
    ///
    /// Zero is not one of them, and it is not the same absence on the two
    /// structs: on the stack it means this build's own built-in default
    /// (`IcePolicy::default()`, which is [`SipralIce::Off`]); on a call it
    /// means the stack's own setting, whatever that came to.
    ///
    /// A call that offers ICE also asks for RFC 5761 multiplexing, whatever
    /// `offer_rtcp_mux` says, because an ICE stream with a second component
    /// needs a second address and this ABI names one.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralIce: u32 {
        /// [`IcePolicy::Off`]: do not offer it, and do not answer a peer that
        /// does. The default, and `docs/06-nat.md` says why at length.
        Off = 1,
        /// [`IcePolicy::Offered`]: offer it, and use it against a peer that
        /// offers it back.
        ///
        /// A peer that does not — an Asterisk with `ice_support=no`, which is
        /// its default — is answered without it and the call runs on the
        /// signalled address and symmetric RTP, exactly as it would have. An
        /// application that names this **must** drain
        /// [`sipral_media_poll_transmit`]: a check that never leaves is a
        /// call that never chooses a path.
        ///
        /// `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
        /// `SIPRAL_FEATURE_ICE`.
        Offered = 2,
        /// [`IcePolicy::Required`]: offer it, and let no stream on this call
        /// carry audio on a path ICE did not check.
        ///
        /// Each of the three ways a peer can fail to do ICE ends the call's
        /// media with `SIPRAL_EVENT_KIND_MEDIA_FAILED` instead of falling
        /// back. That is the whole difference between this and `Offered`.
        Required = 3,
        /// [`IcePolicy::Lite`]: be an ICE-lite endpoint (RFC 8445 §2.5) —
        /// write `a=ice-lite` and one host candidate, answer the checks a
        /// full peer sends, and put the audio on the pair it nominates.
        ///
        /// **Only for a server reachable at the address it advertises**: the
        /// media socket's own, or the public address a one-to-one NAT in
        /// front of it forwards (`sipral_stack_nat_map`'s mapping, when that
        /// is what STUN reports). A WebRTC gateway or any other full-ICE peer
        /// calling a voice agent in a data centre is the case it is for. RFC
        /// 8445 Appendix A says ICE "will not function when a lite
        /// implementation is placed behind a NAT", and a peer told this end
        /// is lite stops doing the work that would have found another path —
        /// so a softphone never names it. A peer that does no ICE, or is lite
        /// itself, gets the call on the signalled address, as under
        /// `Offered`; the application drains `sipral_media_poll_transmit`
        /// for the answers to the checks exactly as it does for a full
        /// agent's.
        ///
        /// `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
        /// `SIPRAL_FEATURE_ICE`.
        Lite = 4,
    }
}

codes! {
    /// One codec this ABI has a number for. Names for every member that says
    /// which.
    ///
    /// A value here is permanent, and that is all it is: a number that has left
    /// this header is spent for good, so a binding compiled against one keeps
    /// working whatever a later build contains. Whether *this* build can produce
    /// the codec is a different question, and `SIPRAL_FEATURE_*` together with
    /// `sipral_codec_at` are what answer it. A settings screen that offers this
    /// list unfiltered is a settings screen with controls that do nothing, which
    /// is the mistake `sipral_capabilities` exists to prevent.
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
        /// Opus. Declared in every build, whether or not this one linked
        /// libopus, for the reason the enumeration above gives. Whether the
        /// codec is here is `SIPRAL_FEATURE_OPUS` and the list
        /// `sipral_codec_at` enumerates, never the presence of this name.
        Opus = 4,
        /// G.729 with Annex A, payload type 18: eight kilobits of narrowband
        /// speech. In every build and in no default offer: a call offers it
        /// only when a codec order names `G729`. It offers `annexb=yes`,
        /// answers with the offer's `annexb`, and uses Annex B's silence
        /// compression where both descriptions allow it.
        G729 = 5,
    }
}

codes! {
    /// What became of one codec this call's catalogue could have used. Names
    /// for [`SipralCodecCandidate::outcome`].
    ///
    /// D5's codec half: a negotiation that ends in G.711 when the site
    /// configured Opus is a support call, and the answer to it is a list
    /// saying which of the two things happened — the far end never named
    /// Opus, or it named it and something ahead of it in this end's order
    /// won.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralCodecOutcome: u32 {
        /// Not an outcome: either the candidate is from a build this ABI has
        /// no number for, or the struct was never filled in.
        Unknown = 0,
        /// This is what the call agreed on. Exactly one candidate carries it,
        /// and it names the same codec as `sipral_media_info_t::codec`.
        Chosen = 1,
        /// The far end's description did not name it, so it was never in the
        /// running. The commonest answer, and the one that says the question
        /// is about the far end's configuration rather than this one's.
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
    ///
    /// D5's transport and NAT half: a call that ended up relayed when a
    /// direct path was expected, or found no path at all, is a support call,
    /// and the answer to it is which of these happened to each pair.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralPathOutcome: u32 {
        /// Not an outcome: either the path is from a build this ABI has no
        /// number for, or the struct was never filled in.
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
    /// Why media failed. Names for `sipral_media_event_t::fault`.
    ///
    /// The sentence beside it says which case of the kind it was; this is the part
    /// a machine acts on, and the two are never the same thing.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralMediaFault: u32 {
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
        /// ICE could not carry this call: the far end described none this
        /// stack could use and the policy was `SIPRAL_ICE_REQUIRED`, the far
        /// end took `a=rtcp-mux` out of an answer to an ICE offer, or consent
        /// to send on the pair that was chosen was withdrawn part-way through
        /// (RFC 7675 §5).
        ///
        /// A code of its own because it is the one an application can act on
        /// differently: the call is up and the signalling is sound, and what
        /// changed is only that no path could be checked. A deployment with a
        /// non-ICE profile to fall back to falls back here.
        Ice = 9,
        /// The call's SRTP policy refused what the far end described: a plain
        /// answer to a call that requires SRTP, which this end then hangs up
        /// with a `Reason` of 488, or a plain re-offer inside one, refused
        /// with 488 and the call left on the keys it had. ABI 0.31.
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
        /// A record of the DTLS-SRTP handshake that keys this call, which has
        /// been taken. Whatever it owes the far end in reply is waiting in
        /// [`sipral_media_poll_transmit`], and this is the signal to drain it.
        Handshake = 6,
        /// Something arrived on a call that agreed to be encrypted and has no
        /// keys yet, so there was nothing to verify it with. The ordinary way
        /// this happens is a peer that starts sending the moment its own half
        /// of the handshake finishes, which is before ours does.
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
        /// `AES_256_CM_HMAC_SHA1_80` (RFC 6188): `AesCm80` with a 256-bit
        /// key. Reachable by SDES only, like `AesF8`: no DTLS-SRTP profile
        /// names it.
        Aes256Cm80 = 4,
        /// `AES_256_CM_HMAC_SHA1_32` (RFC 6188): `AesCm32` with a 256-bit
        /// key. SDES only, as `Aes256Cm80`.
        Aes256Cm32 = 5,
        /// `AEAD_AES_128_GCM` (RFC 7714): AES-GCM, one transform for both
        /// confidentiality and integrity. DTLS-SRTP profile 0x0007.
        AeadAes128Gcm = 6,
        /// `AEAD_AES_256_GCM` (RFC 7714): the same with a 256-bit key, and
        /// what two ends of this stack settle on over DTLS-SRTP. Profile
        /// 0x0008.
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
}

// Safety: integers, no invariant between them, and zero is a valid value of
// each — a zeroed one reads as the codec that is not a codec.
unsafe impl Versioned for SipralCodecInfo {
    const NAME: &'static str = "sipral_codec_info";
    const MIN_SIZE: usize = crate::versioned::min_size::CODEC_INFO;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// One codec this call could have used, and what became of it.
    ///
    /// Set `size` to `sizeof(sipral_codec_candidate_t)` before the call.
    ///
    /// The list is what the negotiation itself decided, kept from the moment
    /// it decided it. It is not worked out again when it is asked for, because
    /// a second run against a description that has since been renegotiated
    /// would disagree with the first in exactly the case somebody is
    /// debugging.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralCodecCandidate {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// A [`SipralCodec`]: the candidate itself.
        pub codec: u32,
        /// A [`SipralCodecOutcome`]: what became of it.
        pub outcome: u32,
        /// A [`SipralCodec`]: what beat it, when `outcome` is
        /// `SIPRAL_CODEC_OUTCOME_OUTRANKED`. `SIPRAL_CODEC_UNKNOWN`
        /// otherwise, because nothing beat a codec that was never named and
        /// nothing beat the one that won.
        pub outranked_by: u32,
    }
}

// Safety: integers, no invariant between them, and zero is a valid value of
// each — a zeroed one reads as the codec that is not a codec, with the outcome
// that is not an outcome.
unsafe impl Versioned for SipralCodecCandidate {
    const NAME: &'static str = "sipral_codec_candidate";
    const MIN_SIZE: usize = crate::versioned::min_size::CODEC_CANDIDATE;

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
    /// the library fills in the rest. A pointer left null with a capacity of
    /// zero is an address the caller does not want. Written down by the
    /// agent as each outcome happened, never worked out again when it is
    /// asked for: RFC 8445 §8.1.2 takes the losing pairs off the checklist
    /// the moment one is selected.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralPathCandidate {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// The pair's priority (RFC 8445 §6.1.2.3), as this end's role
        /// computes it; zero for a relay.
        pub priority: u64,
        /// A [`SipralPathKind`].
        pub kind: u32,
        /// A [`SipralPathOutcome`].
        pub outcome: u32,
        /// For `SIPRAL_PATH_OUTCOME_REFUSED`, the STUN error code the far end
        /// answered with; for `SIPRAL_PATH_OUTCOME_RELAY_REFUSED` and
        /// `SIPRAL_PATH_OUTCOME_LOST`, the TURN server's, zero when it gave
        /// none. Zero otherwise.
        pub code: u32,
        /// A [`SipralCandidateKind`]: what `local` is.
        pub local_kind: u32,
        /// A [`SipralCandidateKind`]: what `remote` is, when it is a
        /// candidate at all.
        pub remote_kind: u32,
        /// Where to write the local address, `host:port` with a trailing
        /// NUL: for a pair, the candidate its checks left from — the host
        /// candidate, or the relayed one; for a relay, the relayed address.
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

// Safety: plain data with no invariant between the members. The two
// pointers are the caller's own buffers, as in `SipralMediaPacket`, and
// all-zero is a caller that wants neither address.
unsafe impl Versioned for SipralPathCandidate {
    const NAME: &'static str = "sipral_path_candidate";
    const MIN_SIZE: usize = crate::versioned::min_size::PATH_CANDIDATE;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// What one call's media settled on, and what it is doing now.
    ///
    /// A4's reporting half and as much of D5 as this stack knows: the codec that
    /// was agreed, the number it travels under, and the shape of the stream around
    /// it. What is deliberately not here is why each other candidate lost —
    /// RFC 3264 §6.1 leaves that decision with the peer, and a reason invented on
    /// this side would be a reason nobody can act on.
    ///
    /// Set `size` to `sizeof(sipral_media_info_t)` before the call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralMediaInfo {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// A [`SipralCodec`]: what the two ends agreed on.
        pub codec: u32,
        /// The payload type on the wire. It is the offer's own number and not
        /// necessarily ours: the two ends pick their own numbers for a format
        /// with no static one, so a peer that numbers it 111 has said what we
        /// say with 96.
        pub payload_type: u32,
        /// The RTP timestamp clock, in hertz.
        pub clock_rate: u32,
        /// The rate the samples crossing this ABI are at.
        pub sample_rate: u32,
        /// How long a frame is, in milliseconds.
        pub frame_ms: u32,
        /// Samples in one frame: exactly what [`sipral_media_playback`] fills and
        /// what [`sipral_media_capture`] wants.
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
}

// Safety: integers, no invariant between them, and zero is a valid value of
// each.
unsafe impl Versioned for SipralMediaInfo {
    const NAME: &'static str = "sipral_media_info";
    const MIN_SIZE: usize = crate::versioned::min_size::MEDIA_INFO;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
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
        /// Whether an RFC 3611 VoIP Metrics report is available at all —
        /// zero until this stream has identified a source to report on.
        /// Every `voip_*` member below is meaningless while this is zero.
        ///
        /// Appended at the tail (task 8.6.9); the pinned `MIN_SIZE` is
        /// unmoved, and what a caller built before these members existed
        /// never sent reads them all as zero, this one included.
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
        /// RFC 3611 SS4.7.2's `Gmin`: the burst/gap classification
        /// threshold this stream's jitter buffer used, fixed for the
        /// stream's whole life.
        pub voip_gmin: u32,
        /// RFC 3611 SS4.7.3's end-system delay. Zero for every build of
        /// this stack today: SS4.7.3 defines it as the sending side's own
        /// accumulation and encoding delay added to the receiving side's,
        /// and nothing here has visibility into the sending side's half.
        pub voip_end_system_delay_us: u64,
        /// RFC 3611 SS4.7.7's nominal jitter buffer delay.
        pub voip_jitter_buffer_nominal_us: u64,
        /// RFC 3611 SS4.7.7's current maximum jitter buffer delay.
        pub voip_jitter_buffer_maximum_us: u64,
        /// RFC 3611 SS4.7.7's absolute maximum jitter buffer delay.
        pub voip_jitter_buffer_abs_max_us: u64,
        /// Whether `voip_r_factor` is available: zero when the active
        /// codec is one ITU-T G.113 tabulates no `Ie`/`Bpl` for (RFC 3611
        /// SS4.7.5's own `127` "unavailable" sentinel).
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
        /// Frames played as nothing because the jitter buffer had run dry
        /// while the far end was still sending: the earpiece asked for audio
        /// before it had arrived, and heard silence or comfort noise in its
        /// place, wherever that fell. A frame the far end never sent, in its
        /// own pause, is not one, and nor is a packet lost on the way, which
        /// is `packets_lost`. No packet is lost or discarded by it, so none of
        /// the `voip_*` rates above sees it (RFC 3611 SS4.7.1 counts packets);
        /// `loss_rate`, `score` and `suffering` do.
        ///
        /// Appended at the tail; the pinned `MIN_SIZE` is unmoved, and a
        /// caller built before it existed never reads it.
        pub frames_underrun: u64,
    }
}

// Safety: integers and two floats, no invariant between them, and zero is a
// valid value of each.
unsafe impl Versioned for SipralStreamStats {
    const NAME: &'static str = "sipral_stream_stats";
    const MIN_SIZE: usize = crate::versioned::min_size::STREAM_STATS;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
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
        /// What to send it over, as a `SipralTransport`.
        /// `SIPRAL_TRANSPORT_UDP` is a datagram from the call's media socket,
        /// which is everything unless the stack reaches its TURN server over
        /// TCP or TLS (`turn_transport`); then what goes through the relay
        /// says that instead, `destination` is the server, and the bytes are
        /// written, as they are and in order, on the media socket's
        /// connection to it — never sent as a datagram.
        ///
        /// Appended at the tail (task 8.5.5); the pinned `MIN_SIZE` is
        /// unmoved.
        pub protocol: u32,
    }
}

// Safety: plain data with no invariant between the members. The two pointers
// are the caller's own buffers, as in every other struct here, and all-zero is
// a caller that brought no buffers — which is refused by reading it, not by
// being undefined.
unsafe impl Versioned for SipralMediaPacket {
    const NAME: &'static str = "sipral_media_packet";
    const MIN_SIZE: usize = crate::versioned::min_size::MEDIA_PACKET;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

// -- what the layers below are called up here --------------------------------

/// The name this ABI gives a codec.
pub(crate) const fn named_codec(codec: Codec) -> SipralCodec {
    // Opus asked of the value and not of a `cfg` on this crate's own `opus`
    // feature: features are per-crate and additive, so that arm would go
    // missing in a build of this crate whose facade did link the codec, and
    // every answer below would then be wrong about a codec the build can
    // negotiate. `Codec::is_opus` is the catalogue's own answer.
    if codec.is_opus() {
        return SipralCodec::Opus;
    }
    match codec {
        Codec::Pcmu => SipralCodec::Pcmu,
        Codec::Pcma => SipralCodec::Pcma,
        Codec::G722 => SipralCodec::G722,
        Codec::G729 => SipralCodec::G729,
        // the layer below has grown a codec this ABI has no number for, and
        // saying so beats picking one that is wrong
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
    // asked of the value for the same reason `named_codec` asks it: the
    // variant exists only where Opus does, and an arm under this crate's own
    // `opus` would go missing in a build whose facade linked the codec, so a
    // refusal that has a code of its own would leave as `Other`
    if error.is_codec() {
        return SipralMediaFault::Codec;
    }
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
        // a recording that a codec change ended is reported as a recording
        // that ended, not as "something this ABI has no word for": what the
        // application does about it is what it does about any of the others
        MediaError::Recording(_)
        | MediaError::NotRecording
        | MediaError::AlreadyRecording
        | MediaError::CodecChanged => SipralMediaFault::Recording,
        #[cfg(feature = "ice")]
        MediaError::Ice(_)
        | MediaError::IceRequired
        | MediaError::IceNeedsRtcpMux
        | MediaError::IcePathLost => SipralMediaFault::Ice,
        MediaError::SrtpRequired => SipralMediaFault::SecurityPolicy,
        _ => SipralMediaFault::Other,
    }
}

/// Why the media layer would not do it.
///
/// The sentence comes from the error itself, which already names the codec, the
/// interval or the file that was the problem. Only the code is decided here.
pub(crate) fn media_failed(error: &MediaError) -> Fail {
    // the codec's own refusal, asked of the value and not of a `cfg` — see
    // `fault_of`. It is a value that would be taken if it were corrected,
    // which is what the two arms below it are
    if error.is_codec() {
        return fail(SipralStatus::InvalidArgument, error.to_string());
    }
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
        | MediaError::Recording(_)
        | MediaError::DigitTooShort { .. }
        | MediaError::DigitTooLong { .. }
        | MediaError::UnknownDigit { .. }
        | MediaError::RenderDelayTooLong { .. }
        | MediaError::NoSrtpSuite
        | MediaError::SameCall => SipralStatus::InvalidArgument,
        // the numbers a session can bind ran out, which a corrected value
        // does not fix and a different build does not either
        MediaError::TooManyDigits | MediaError::NoPayloadType => SipralStatus::Exhausted,
        MediaError::NoSuchCall
        | MediaError::NoDescription
        | MediaError::NotRecording
        | MediaError::AlreadyRecording
        | MediaError::CodecChanged
        | MediaError::NoCommonCodec
        | MediaError::StreamRefused
        | MediaError::AlreadyJoined
        | MediaError::NotJoined
        | MediaError::JoinIncompatible => SipralStatus::WrongState,
        MediaError::PacketTooLong { .. } => SipralStatus::BufferTooSmall,
        // the call was refused, with 488, by the policy it was answered under
        MediaError::SrtpRequired => SipralStatus::SecurityPolicy,
        MediaError::Signalling(ref refused) => return crate::call::ua_failed(refused),
        _ => SipralStatus::NotSent,
    };
    fail(status, error.to_string())
}

/// The C shape of a statistics record.
pub(crate) fn stream_stats(record: &StreamStatistics) -> SipralStreamStats {
    let quality = record.quality;
    let voip = record.voip_metrics;
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
    }
}

/// A `u16` of milliseconds as microseconds, for the delay members that
/// match the rest of this struct's unit rather than RFC 3611's own.
fn ms_to_us(ms: u16) -> u64 {
    u64::from(ms).saturating_mul(1_000)
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

/// A `sipral_stack_config_t::srtp` or `sipral_call_config_t::srtp` value, as a
/// [`SrtpPolicy`] the caller actually named — `None` for the zero that means
/// "unspecified", which the two structs resolve differently: the stack's own
/// built-in default on one, the stack's own setting on the other. Neither
/// meaning is decided here, only the value itself.
pub(crate) fn srtp_policy(value: u32, name: &'static str) -> Result<Option<SrtpPolicy>, Fail> {
    match value {
        0 => Ok(None),
        1 => Ok(Some(SrtpPolicy::NotOffered)),
        2 => Ok(Some(SrtpPolicy::Offered)),
        3 => Ok(Some(SrtpPolicy::Required)),
        // the numbers are in the header of every build, because a value that
        // has left it is spent; what a build without the feature has is no
        // handshake to honour them with, and saying so is better than placing
        // the unencrypted call the policy was chosen to prevent
        #[cfg(feature = "dtls")]
        4 => Ok(Some(SrtpPolicy::DtlsOffered)),
        #[cfg(feature = "dtls")]
        5 => Ok(Some(SrtpPolicy::DtlsRequired)),
        #[cfg(feature = "dtls")]
        6 => Ok(Some(SrtpPolicy::DtlsOrSdes)),
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
                 for offered, 3 for required, 4 for DTLS-SRTP, 5 for DTLS-SRTP required or 6 \
                 for DTLS-SRTP falling back to SDES"
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
        // the numbers are in the header of every build, because a value that
        // has left it is spent; what a build without the feature has is no
        // agent to honour them with, and saying so is better than placing the
        // call on an unchecked path the policy was chosen to avoid
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

/// The catalogue a stack was asked for: an order, a frame length, what an
/// offer says about itself, what it says about SRTP and about ICE, and
/// whether G.729's Annex B is allowed.
///
/// A name this build has no encoder for is refused here, where the caller still
/// knows which string it passed, rather than ignored later where nothing can
/// tell it happened.
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

/// The codec order a caller wrote, as a catalogue.
fn ordered(list: &str) -> Result<CodecCatalog, Fail> {
    CodecCatalog::with_order(&names_in(list)?).map_err(|error| media_failed(&error))
}

/// The codec names a caller wrote, as a list, checked for the two faults that
/// are the list's own rather than any one name's.
///
/// Separate from [`ordered`] because a call names its order on a structure
/// that is read before the stack is locked, and the catalogue it becomes can
/// only be derived from the stack's own once it is. The names are checked at
/// the first of those two moments, where the caller still knows which string
/// it passed.
pub(crate) fn names_in(list: &str) -> Result<Vec<&str>, Fail> {
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
    Ok(named)
}

// -- reaching one call's media -----------------------------------------------

/// Every media handle this process has handed out.
///
/// One table for the process, as the stacks have: a handle is a number, and a
/// number has to be looked up somewhere. Its lock is held for an index and a
/// reference count, never for a frame and never while anything else is waited
/// for.
static MEDIA: HandleTable<MediaEntry> = HandleTable::new(Kind::Media);

/// What a media handle names.
pub(crate) struct MediaEntry {
    /// The call's session, for as long as the call has one.
    share: SessionShare,
    /// The stack that minted the handle, which a thread inside this call's
    /// media is kept from calling into.
    stack: SipralHandle,
    /// What `now_ms` of zero means on the stack that minted the handle, kept
    /// here because that stack is exactly what a media entry point does not
    /// touch.
    origin: Instant,
}

impl MediaEntry {
    /// The caller's clock, as the stack that minted this handle reads it.
    ///
    /// Neither checked against the stack's last reading nor written back to
    /// it: a media entry point runs on a thread that reads the clock apart
    /// from the one that polls, and a reading a millisecond behind the last
    /// poll is not a caller bug.
    fn instant(&self, now_ms: u64) -> Result<Instant, Fail> {
        instant_at(self.origin, now_ms)
    }
}

/// Do something with one call's media, or say why not.
///
/// The one way in for every entry point that takes a media handle, and the
/// reason none of them reaches a stack: the table hands over the entry, the
/// session's own lock is taken — waiting for a thread that is in the middle of
/// a frame on this call, and for nothing else — and that is all.
pub(crate) fn with_media<R>(
    media: SipralHandle,
    act: impl FnOnce(&mut MediaSession, &MediaEntry) -> Result<R, Fail>,
) -> Result<R, Fail> {
    let entry = MEDIA.get(media).map_err(handle_failed)?;
    let _inside = Inside::enter(entry.stack);
    match entry.share.with(|session| act(session, &entry)) {
        Ok(done) => done,
        Err(SessionUnavailable::Reentered) => Err(fail(
            SipralStatus::Busy,
            "this thread is already inside this call's media, further down its own call stack",
        )),
        // ended, and whatever the layer below one day adds beside it: either
        // way there is no session here to act on
        Err(_) => Err(fail(
            SipralStatus::WrongState,
            "this call's media has ended: the call is over or its stack was destroyed, and all \
             that is left to do with the handle is release it",
        )),
    }
}

/// Do something with two calls' media at once, for [`sipral_media_mix`]
/// alone: every other entry point here touches one call's session, and this
/// is the one place two must be held together, because a mixed frame cannot
/// be built from either alone.
///
/// Locked in a fixed order — whichever handle is numerically smaller,
/// regardless of which one `media_a`/`media_b` names first — so that two
/// threads mixing the same pair with the arguments swapped wait for each
/// other rather than deadlocking against each other, which two independent
/// per-session locks taken in whatever order the caller happened to name
/// them would otherwise invite.
fn with_media_pair<R>(
    media_a: SipralHandle,
    media_b: SipralHandle,
    act: impl FnOnce(&mut MediaSession, &mut MediaSession) -> Result<R, Fail>,
) -> Result<R, Fail> {
    let entry_a = MEDIA.get(media_a).map_err(handle_failed)?;
    let entry_b = MEDIA.get(media_b).map_err(handle_failed)?;
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

/// Why a [`SessionShare`] did not reach its session, as the same [`Fail`]
/// [`with_media`] itself turns it into.
fn media_unavailable(error: SessionUnavailable) -> Fail {
    match error {
        SessionUnavailable::Reentered => fail(
            SipralStatus::Busy,
            "this thread is already inside this call's media, further down its own call stack",
        ),
        // ended, and whatever the layer below one day adds beside it: either
        // way there is no session here to act on
        _ => fail(
            SipralStatus::WrongState,
            "this call's media has ended: the call is over or its stack was destroyed, and all \
             that is left to do with the handle is release it",
        ),
    }
}

thread_local! {
    /// The stacks whose calls' media this thread is working on, innermost last.
    static INSIDE: RefCell<Vec<SipralHandle>> = const { RefCell::new(Vec::new()) };
}

/// This thread's mark on a stack, for as long as it is working on the media
/// of one of that stack's calls.
struct Inside {
    stack: SipralHandle,
}

impl Inside {
    fn enter(stack: SipralHandle) -> Self {
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

/// Whether this thread is inside a frame of a call on `stack` — which only
/// code run during that frame, such as a processor, can be when it calls into
/// the library.
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
    /// Mint it once the call's negotiation has settled —
    /// `SIPRAL_EVENT_KIND_MEDIA_STARTED` is the moment, and minting from inside
    /// that event's callback is allowed — and hand it to every `sipral_media_`
    /// entry point in place of the stack and the call. None of those takes the
    /// stack's lock, which is the point: the thread that carries a call's audio
    /// is never refused a frame because signalling, the event callback or
    /// another call is busy.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for a call with no media: one placed with a
    /// description of the caller's own, or one whose negotiation has not
    /// settled. The handle is written only if this returns `SIPRAL_STATUS_OK`.
    ///
    /// The handle outlives the call. Once the call ends, or its stack is
    /// destroyed, every media entry point answers `SIPRAL_STATUS_WRONG_STATE`
    /// on it; a hold, a resume or a change of codec keeps it working. Each
    /// handle minted is released once with `sipral_media_release`, and asking
    /// twice for the same call gives two.
    ///
    /// # Safety
    ///
    /// `out_media` must point at one `sipral_handle_t`.
    fn sipral_call_media(stack: SipralHandle, call: SipralHandle, out_media: *mut SipralHandle) {
        if out_media.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_media is null"));
        }
        // stamped with its stack's tag like every other handle a stack mints,
        // so a media handle is refused by name when handed to the wrong place
        let (entry, tag) = with_stack(stack, |state| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            let share = state.engine.share(id).ok_or_else(no_media)?;
            let entry = MediaEntry {
                share,
                stack,
                origin: state.origin(),
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
    /// Its one matching free, whether or not its call is still up and whether
    /// or not its stack still exists. The session is not touched: it belongs to
    /// the call and ends when the call does, so releasing a handle mid-call
    /// stops nothing but the handle. A handle released twice is
    /// `SIPRAL_STATUS_STALE_HANDLE` the second time.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    fn sipral_media_release(media: SipralHandle) {
        MEDIA.remove(media).map_err(handle_failed)?;
        Ok(())
    }
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
            // the number stays in the enumeration whether or not this build
            // linked the codec; the name is what the build has, which the
            // catalogue says and no feature of this crate's does
            4 if linked(SipralCodec::Opus) => c"opus".as_ptr(),
            5 => c"G729".as_ptr(),
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
    /// is offered when nobody has said otherwise — all of it but G.729, which
    /// is listed last and offered only where a codec order names it.
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
    fn sipral_media_info(media: SipralHandle, out_info: *mut SipralMediaInfo) {
        // checked before the handle is even looked up, so a caller that got
        // its size wrong is told that rather than something about the call
        unsafe { crate::versioned::declared_size(out_info.cast_const()) }?;
        let info = with_media(media, |session, _| Ok(media_info(session)))?;
        unsafe { write_versioned(out_info, info) }
    }
}

entry! {
    /// How many codecs were in the running on this call.
    ///
    /// This call's own catalogue, which is the stack's order unless
    /// `sipral_call_config_t::codecs` named another. Zero is an answer, not a
    /// failure: a call negotiated from a description with no media line in it
    /// had nothing in the running at all.
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
    /// D5 in one place: what this end offered, what the far end named, and
    /// which of the two ran out first. An index past the end is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` naming how many there are.
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
        // checked before the handle is even looked up, so a caller that got
        // its size wrong is told that rather than something about the call
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
    /// Zero is an answer, not a failure: a call not using ICE has one path,
    /// the address its description named, and nothing here to explain. A
    /// restart (RFC 8445 §9) starts the list again with the new session.
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
    /// D5's transport and NAT half, beside `sipral_media_codec_candidate_at`:
    /// which path the media took, and for every other one whether its check
    /// went unanswered, the far end refused it, the answer came back from
    /// elsewhere, the relay would not let the far end through, or it worked
    /// and lost to a better one. An index past the end is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` naming how many there are; an address
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

/// Every path a call's agent tried, as the numbers this ABI has for it and
/// the two addresses to write beside them.
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
                // the layer below has grown an outcome this ABI has no number
                // for, and saying so beats picking one that is wrong
                _ => (SipralPathOutcome::Unknown, 0),
            };
            let numbers = SipralPathCandidate {
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

/// Without the agent there is no path to explain.
#[cfg(not(feature = "ice"))]
fn paths_of(
    _session: &MediaSession,
) -> Vec<(SipralPathCandidate, Option<SocketAddr>, Option<SocketAddr>)> {
    Vec::new()
}

/// What the negotiation recorded about one codec, as the numbers this ABI has
/// for it.
fn candidate_of(candidate: &CodecCandidate) -> SipralCodecCandidate {
    let (outcome, outranked_by) = match &candidate.outcome {
        CodecOutcome::Chosen => (SipralCodecOutcome::Chosen, SipralCodec::Unknown),
        CodecOutcome::NotNamed => (SipralCodecOutcome::NotNamed, SipralCodec::Unknown),
        CodecOutcome::Outranked(winner) => (SipralCodecOutcome::Outranked, named_codec(*winner)),
        // the layer below has grown an outcome this ABI has no number for,
        // and saying so beats picking one that is wrong
        _ => (SipralCodecOutcome::Unknown, SipralCodec::Unknown),
    };
    SipralCodecCandidate {
        size: size_of::<SipralCodecCandidate>(),
        codec: named_codec(candidate.codec) as u32,
        outcome: outcome as u32,
        outranked_by: outranked_by as u32,
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
    /// present and nothing here reads a clock to answer it. Like every media
    /// entry point, this does not move the stack's own clock: it is read at the
    /// frame rate of a user interface, often from the thread that draws one,
    /// and a reading a millisecond behind the last poll is not a caller bug.
    ///
    /// The end-of-call record arrives instead as
    /// `SIPRAL_EVENT_KIND_MEDIA_STATISTICS`, because by then the stream is
    /// gone and this answers `SIPRAL_STATUS_WRONG_STATE`.
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
        // checked before the handle is even looked up, so a caller that got
        // its size wrong is told that rather than something about the call
        unsafe { crate::versioned::declared_size(out_stats.cast_const()) }?;
        let stats = with_media(media, |session, entry| {
            let now = entry.instant(now_ms)?;
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
    /// `now_ms` is when it arrived, on the stack's clock. Reading it here moves
    /// nothing: the network thread and the poll thread read that clock apart,
    /// and a datagram a millisecond behind the last poll is not refused.
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
        out_arrival: *mut u32,
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

/// Whether the second byte of a datagram says control, by RFC 5761 §4.
///
/// The field is the payload type with the marker bit above it in RTP, and the
/// packet type in RTCP; 64 to 95 are the numbers RTP never uses and RTCP
/// always does, which is what lets the two share a socket. Read here only to
/// pick which bound the datagram is held to — the session tells them apart
/// again for itself, and disagreeing with it would only mean a report is read
/// as media a moment later.
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
    fn sipral_media_playback(
        media: SipralHandle,
        samples: *mut i16,
        capacity: usize,
        out_written: *mut usize,
        out_source: *mut u32,
    ) {
        if samples.is_null() && capacity != 0 {
            return Err(fail(SipralStatus::InvalidArgument, "samples is null"));
        }
        let played = with_media(media, |session, _| {
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
    /// this end is holding the far end, silence suppression swallowed it, or
    /// ICE has not chosen a path for this call yet. The RTP timestamp moves by
    /// a frame in the first two cases, because RFC 3550 §5.1 makes it a
    /// measure of time rather than of packets; in the third nothing is
    /// encoded at all, since there is no packet for the timestamp to belong
    /// to and a codec that carries state would have moved it for nothing.
    ///
    /// `now_ms` is read as the stack reads it and moves nothing, as with every
    /// media entry point. It is what tells ICE that traffic went out on the
    /// pair it chose, which is what RFC 8445 §11 lets it stop sending
    /// keepalives for.
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
            let frame = session.frame_samples();
            if sample_count != frame {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    format!("a frame of this call is {frame} samples and {sample_count} were given"),
                ));
            }
            let taken = unsafe { slice::from_raw_parts(samples, frame) };
            let sent = session
                .capture(taken, now)
                .map_err(|error| media_failed(&error))?;
            match sent {
                Some(datagram) => unsafe { put_datagram(&mut out, &datagram) },
                None => Ok(()),
            }
        })?;
        unsafe { write_versioned(packet, out) }
    }
}

record! {
    /// What [`SipralProcessorCallback`] is handed for one call: an ordinary
    /// frame to process, or a request to forget what has been learned.
    ///
    /// Filled by the library and handed to the callback as a `const`
    /// pointer, the same shape [`crate::screening::SipralScreenRequest`] is:
    /// read `size` before anything past it, and read nothing once the
    /// callback has returned — `near_end`, `far_end` and `out` borrow from
    /// buffers that belong to this one call and are not this ABI's to keep
    /// alive a moment longer.
    #[derive(Clone, Copy)]
    pub struct SipralProcessorFrame {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// 0 for an ordinary frame; 1 for a request to forget whatever state
        /// the processor holds — a device change or a codec change mid-call
        /// asks for this, and `near_end`, `far_end` and `out`, with the three
        /// lengths beside them, are all null and zero when it is set.
        pub reset: u32,
        /// The frame just captured from the microphone. Null when `reset` is
        /// set.
        pub near_end: *const i16,
        /// How many samples `near_end` is. Always the same number as
        /// `far_end_len` and `out_len` — carried three times, once beside
        /// each buffer, because that is the one buffer each binding marshals
        /// on its own. 0 when `reset` is set.
        pub near_end_len: usize,
        /// The far-end audio rendered to the loudspeaker over the same span
        /// of time as `near_end`, the same length. Null when `reset` is set.
        pub far_end: *const i16,
        /// How many samples `far_end` is. See `near_end_len`. 0 when `reset`
        /// is set.
        pub far_end_len: usize,
        /// Where the callback writes the frame that replaces `near_end` —
        /// every sample of it, since what is not written is read back as
        /// whatever was there before. Null when `reset` is set, since there
        /// is nothing to write.
        pub out: *mut i16,
        /// How many samples `out` has room for, which is also how many the
        /// callback has to write. See `near_end_len`. 0 when `reset` is set.
        pub out_len: usize,
    }
}

alias! {
    /// Echo cancellation, gain control or noise suppression, run over one
    /// frame, or told to forget what it has learned — [`SipralProcessorFrame`]
    /// says which. Installed with [`sipral_call_attach_processor`].
    ///
    /// **It runs with this call's media locked**, which is the opposite of
    /// [`crate::event::SipralEventCallback`] and the reason
    /// [`sipral_call_attach_processor`]'s own doc comment says so before it
    /// says anything else — read it there. In consequence: **this callback
    /// must not call back into the media handle it was attached through**,
    /// on this thread or on any other. It must not unwind, for the same
    /// reason nothing in this ABI may.
    ///
    /// `frame` and everything it points at belong to the library and are
    /// valid for the duration of this one call and no longer.
    pub type SipralProcessorCallback = fn(
        frame: *const SipralProcessorFrame,
        user_data: *mut c_void,
    );
}

/// A [`Processor`] that hands both operations [`SipralProcessorFrame`] can
/// mean to one C callback.
///
/// # Safety
///
/// `callback` is the caller's own function, called under the contract
/// [`SipralProcessorCallback`]'s doc comment states: it must not unwind, and
/// it must not call back into the media handle this was attached through,
/// enforced by that handle's own re-entry guard rather than by anything
/// here. `user_data` is the caller's own pointer, read by nothing here and
/// only ever handed back to the same callback it arrived with.
struct CProcessor {
    callback: unsafe extern "C" fn(frame: *const SipralProcessorFrame, user_data: *mut c_void),
    user_data: *mut c_void,
    /// Where the callback writes the frame it hands back, sized to the last
    /// frame seen — which changes when a codec change gives this call a
    /// different frame length, and never otherwise.
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
        // Safety: `near_end` and `reference` are each `near_end.len()`
        // samples, readable for the length of this call; `self.out` was just
        // sized to the same length and is writable for it. `frame` is read
        // by the callback for the duration of this one call, under
        // `SipralProcessorCallback`'s contract.
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
        // Safety: as in `process` above; there is nothing beyond `frame`
        // itself for the callback to read or write this time.
        unsafe { (self.callback)(&raw const frame, self.user_data) };
    }
}

entry! {
    /// Run `process` over every frame captured on this call, against the
    /// far-end audio this call played [`MediaSession::render_delay`] earlier
    /// — echo cancellation, gain control and noise suppression are all this
    /// one seam, and `docs/05-media.md` says why.
    ///
    /// What was attached before is dropped, along with the echo path it had
    /// learned. Attaching mid-call is allowed and costs the first few hundred
    /// milliseconds of a fresh adaptation, the same price a call pays at its
    /// start.
    ///
    /// **`process` runs with this call's media locked**, the same as
    /// [`crate::screening::SipralScreenCallback`] and unlike
    /// [`crate::event::SipralEventCallback`]: it is called from inside
    /// [`sipral_media_playback`] (to learn what the loudspeaker was just
    /// given) and inside [`sipral_media_capture`] (to run the frame just
    /// captured), and — with [`SipralProcessorFrame`]'s `reset` set — whenever
    /// this call's media forgets what it has learned, a device change or a
    /// codec change mid-call. All three run on whichever thread called the
    /// entry point that triggered them. In consequence, **it must not call
    /// back into the media handle it was attached through**, on this thread
    /// or on any other — doing so does not deadlock, since every media entry
    /// point takes its session's lock without waiting and answers
    /// `SIPRAL_STATUS_BUSY` rather than block, but it is refused outright
    /// rather than relied on. A *different* call's media, or this stack's
    /// own entry points, are unaffected. It must not unwind: a panic that
    /// reached C across this boundary would take the host process with it,
    /// the same rule every callback in this ABI is held to.
    ///
    /// `user_data` is handed back to `process` untouched on every call, read
    /// by nothing here, and has to outlive the last one — which the caller
    /// who installed it is the one to know is over:
    /// `sipral_call_detach_processor` or the call ending are the two ways.
    ///
    /// # Safety
    ///
    /// `process` is called on whichever thread calls
    /// [`sipral_media_playback`] or [`sipral_media_capture`] on this call,
    /// for as long as the processor stays attached, and `user_data` has to
    /// outlive the last such call.
    fn sipral_call_attach_processor(
        media: SipralHandle,
        process: SipralProcessorCallback,
        user_data: *mut c_void,
    ) {
        let Some(callback) = process else {
            return Err(fail(
                SipralStatus::InvalidArgument,
                "process is null: there is nothing to attach",
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
    /// Stop running the processor [`sipral_call_attach_processor`] attached,
    /// if there was one.
    ///
    /// `out_was_attached`, when not null, says whether there was one to stop:
    /// 1 if a processor was attached and is now detached, 0 if there was
    /// none. The frames the application hands over reach the encoder
    /// untouched again from the next one, and the loudspeaker history kept
    /// for it is released. Once this returns, `process` is not called again
    /// for this attachment — the moment `user_data` may be freed.
    ///
    /// # Safety
    ///
    /// `out_was_attached` must point at one `uint32_t` or be null.
    fn sipral_call_detach_processor(media: SipralHandle, out_was_attached: *mut u32) {
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
    /// What a device change asks for: the estimate was built for a different
    /// loudspeaker and a different microphone, and carrying it forward makes
    /// the processor fight it for a while instead of adapting cleanly. Calls
    /// the `process` given to [`sipral_call_attach_processor`] with
    /// [`SipralProcessorFrame`]'s `reset` set.
    ///
    /// `out_was_attached`, when not null, says whether there was a processor
    /// to reset: 1 if there was, 0 if there was none.
    ///
    /// # Safety
    ///
    /// `out_was_attached` must point at one `uint32_t` or be null.
    fn sipral_call_reset_processor(media: SipralHandle, out_was_attached: *mut u32) {
        let was_attached = with_media(media, |session, _| Ok(session.reset_processor()))?;
        if !out_was_attached.is_null() {
            unsafe { out_was_attached.write(u32::from(was_attached)) };
        }
        Ok(())
    }
}

entry! {
    /// One frame of a local conference of two calls: decode what `media_a`'s
    /// and `media_b`'s far ends each sent, mix what each of the three
    /// parties — the two far ends and this end — is owed, and send the two
    /// frames the far ends are owed.
    ///
    /// `sipral_call_join` must already have paired the two calls these two
    /// handles belong to. Nothing here checks that itself: checking it would
    /// mean taking the stack's lock on every frame, which is exactly what a
    /// media handle exists to avoid, so this mixes whatever two handles it is
    /// given — the same trust every other `sipral_media_` entry point places
    /// in the caller having minted the handle from a call worth acting on.
    ///
    /// `mic` is this end's own frame, `mic_count` long; `local` is filled
    /// with what this end's own loudspeaker is owed, `local_count` long. Both
    /// are `sipral_media_info_t::frame_samples` on a call this pair actually
    /// agreed on — `sipral_call_join` already made that the same on both.
    /// `packet_a` and `packet_b` are filled the way `sipral_media_capture`
    /// fills one, each with what its own call's far end is now owed: `mic`
    /// mixed with the *other* far end's frame rather than `mic` alone, which
    /// is also what each call's own recording keeps if one is running.
    ///
    /// Drive a joined pair from one thread, one frame at a time. The two
    /// sessions are locked together for the length of the call, in a fixed
    /// order that does not depend on which handle is named first, so a
    /// second `sipral_media_mix` on the same pair waits for this one rather
    /// than deadlocking against it — but a thread still calling
    /// `sipral_media_playback`/`sipral_media_capture` on either call alone at
    /// the same time is a second driver this mix does not know about.
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
        let taken = unsafe { slice::from_raw_parts(mic, mic_count) };
        let room = unsafe { slice::from_raw_parts_mut(local, local_count) };
        let outcome = with_media_pair(media_a, media_b, |session_a, session_b| {
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
    /// A `len` of zero in the packet means nothing is due yet. RFC 3550 §6.3
    /// decides when, and at most one report is due at a time, so one call per
    /// frame is enough.
    ///
    /// It asks one call rather than the whole stack, so the thread that sends
    /// a call's audio sends its reports too, on the same socket and without
    /// reaching the stack: call it after every frame that goes out, and
    /// whenever `sipral_stack_poll` reports a deadline while a call is not
    /// capturing. On a call that negotiated no RTCP it answers zero for ever.
    ///
    /// `now_ms` is read as the stack reads it and moves nothing, as with every
    /// media entry point.
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
    /// report: today, a record of the DTLS-SRTP handshake that keys it.
    ///
    /// A `len` of zero means nothing is due. On a call that is not keyed by a
    /// handshake — every call in a build without `SIPRAL_FEATURE_DTLS_SRTP`,
    /// and every SDES or plain call in a build with it — that is the answer
    /// for ever, and calling this costs one comparison.
    ///
    /// **Drain it to empty**, in a loop, after every `sipral_media_receive`
    /// that answered `SIPRAL_ARRIVAL_HANDSHAKE` and at every deadline
    /// `sipral_stack_poll` names. A handshake whose records never leave is a
    /// ClientHello that never goes out: the call rings, answers, carries no
    /// audio in either direction, and reports nothing wrong for the two
    /// minutes it takes to give up. That is the one failure this entry point
    /// exists to prevent, and there is no way to notice it from the outside.
    ///
    /// `now_ms` is read as the stack reads it and moves nothing, as with every
    /// media entry point.
    ///
    /// # Safety
    ///
    /// `packet` must point at a `sipral_media_packet_t` as
    /// [`sipral_media_capture`] describes.
    fn sipral_media_poll_transmit(media: SipralHandle, now_ms: u64, packet: *mut SipralMediaPacket) {
        let mut out = unsafe { read_versioned(packet) }?;
        prepare(&mut out)?;
        with_media(media, |session, entry| {
            // the clock is read and checked like every other entry point's,
            // so that a caller which drives this one alone still cannot walk
            // a stack's time backwards
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
    /// The RTCP goodbye of a call whose media has ended (task 8.4.21).
    ///
    /// `MediaEngine::release` builds the BYE RFC 3550 §6.3.7 owes the far end
    /// the moment a call's session stops, but by then the call's media
    /// handle is already gone — every `sipral_media_` entry point on it
    /// answers `SIPRAL_STATUS_WRONG_STATE` — so this is a stack-level call
    /// instead, the one place left that still knows the goodbye belonged to
    /// that call.
    ///
    /// `out_call` is written with the handle of the call the goodbye
    /// belonged to — `SIPRAL_HANDLE_NONE` when nothing was waiting. The
    /// call itself is already over; the handle is there only so the
    /// application knows which media socket to send the datagram from, since
    /// it owns that socket and this ABI never did. Passing it to any other
    /// entry point answers whatever a stale handle of its kind already
    /// answers.
    ///
    /// One at a time, like every other poll in this crate: call it after
    /// every `sipral_stack_poll` that delivered `SIPRAL_EVENT_KIND_CALL_ENDED`
    /// for a call this stack was running media on, and keep calling until
    /// `out_packet` comes back with a `len` of zero. A call whose media never
    /// ran leaves nothing here, but for one thing.
    ///
    /// A call given a relay on a TURN server (`turn_server` on the stack's
    /// configuration) gives it back through here too: the Refresh with a
    /// lifetime of zero that RFC 8656 §8 deletes an allocation with,
    /// addressed to the TURN server, from the same socket. It is queued when
    /// the call ends, whether or not its media ever ran, and earlier when the
    /// call turns out not to use the relay at all — its ICE policy is off, or
    /// the far end answered without ICE — so polling here after every
    /// `sipral_stack_poll`, not only the ones that ended a call, gives the
    /// relay back sooner.
    ///
    /// # Safety
    ///
    /// `out_call` must point at one `sipral_handle_t`, and `out_packet` at a
    /// `sipral_media_packet_t` as [`sipral_media_capture`] describes.
    fn sipral_stack_poll_farewell(
        stack: SipralHandle,
        out_call: *mut SipralHandle,
        out_packet: *mut SipralMediaPacket,
    ) {
        if out_call.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_call is null"));
        }
        let mut out = unsafe { read_versioned(out_packet) }?;
        prepare(&mut out)?;
        let call = with_stack(stack, |state| {
            let Some((call, destination, payload, protocol)) = state.farewells.pop_front() else {
                return Ok(crate::handle::SIPRAL_HANDLE_NONE);
            };
            unsafe { put(&mut out, destination, &payload, protocol) }?;
            Ok(call)
        })?;
        unsafe { out_call.write(call) };
        unsafe { write_versioned(out_packet, out) }
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

/// Put one datagram a session produced in the caller's buffers, with what
/// to send it over.
///
/// # Safety
///
/// As [`put`].
unsafe fn put_datagram(
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
/// # Safety
///
/// The buffers in `packet` must be writable for the capacities beside them,
/// which [`prepare`] has already been asked about.
unsafe fn put(
    packet: &mut SipralMediaPacket,
    destination: SocketAddr,
    payload: &[u8],
    protocol: u32,
) -> Result<(), Fail> {
    unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), packet.data, payload.len()) };
    packet.len = payload.len();
    packet.protocol = protocol;
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
    // the one media operation reached through the stack, because choosing
    // between the media and an INFO is a question about the call; it waits
    // for a frame in progress on this call like any other holder
    let mut session = state.engine.session(call).ok_or_else(|| {
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
    /// The digit in flight gets no closing packet, which is right for a call
    /// whose media is being taken away: there is nowhere left to send one.
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

    /// Samples in one frame of the codec every media fixture negotiates:
    /// G.711 at eight kilohertz, twenty milliseconds.
    pub(crate) const FRAME: usize = 160;

    /// An order naming two of the four this build contains, to read back.
    const ORDER: &str = "G722,PCMA";

    /// What the far end answers an offer of Opus alone with: the dynamic
    /// payload type this build's offer put it on, and the channel count RFC
    /// 7587 §7 makes every Opus line carry whatever is really being sent.
    const OPUS_ANSWER: &[u8] = b"v=0\r\n\
o=bob 1 1 IN IP4 203.0.113.5\r\n\
s=-\r\n\
c=IN IP4 203.0.113.5\r\n\
t=0 0\r\n\
m=audio 41000 RTP/AVP 96\r\n\
a=rtpmap:96 opus/48000/2\r\n\
a=sendrecv\r\n";

    /// The same for G.722, which is the codec at the top of a build that has
    /// no Opus. Its static type, and the clock rate RFC 3551 §4.5.2 fixes at
    /// half the rate it hears at.
    const WIDEBAND_ANSWER: &[u8] = b"v=0\r\n\
o=bob 1 1 IN IP4 203.0.113.5\r\n\
s=-\r\n\
c=IN IP4 203.0.113.5\r\n\
t=0 0\r\n\
m=audio 41000 RTP/AVP 9\r\n\
a=rtpmap:9 G722/8000\r\n\
a=sendrecv\r\n";

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
                protocol: u32::MAX,
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

    /// The media handle of a call that has audio, minted the way a binding
    /// mints it on `SIPRAL_EVENT_KIND_MEDIA_STARTED`.
    pub(crate) fn media_of(stack: SipralHandle, call: SipralHandle) -> SipralHandle {
        let mut media = SIPRAL_HANDLE_NONE;
        let status = unsafe { sipral_call_media(stack, call, &raw mut media) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_ne!(media, SIPRAL_HANDLE_NONE);
        media
    }

    /// Let a media handle go, as every one that is minted has to be.
    pub(crate) fn release(media: SipralHandle) {
        assert_eq!(
            unsafe { sipral_media_release(media) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
    }

    /// Take the frame that is due for the earpiece.
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

    /// Put one frame on the wire, and say how long the packet was.
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
        }
    }

    /// Hand a datagram to a call as if it had arrived on the media socket.
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
        assert_eq!(name(0), None, "no codec is zero");
        assert_eq!(name(6), None);
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
        let catalog = ordered(" G722 , PCMA ").expect("both are in this build");
        assert_eq!(catalog.codecs(), [Codec::G722, Codec::Pcma]);
    }

    /// Where Opus was linked an order naming it is taken, and where it was
    /// not it is refused where it is set, by name, like any other codec this
    /// build has no encoder for. That is the whole of what a build without
    /// Opus does differently: no special error, no silent substitution.
    ///
    /// One test rather than a `cfg`-ed pair, because the two halves are told
    /// apart by the catalogue and not by this crate's `opus` feature: that
    /// feature is this crate's own, and a build with it off can sit on a
    /// facade that linked the codec, which would run whichever half of a
    /// pair was the wrong one.
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

    /// Seven milliseconds is a frame Opus has no size for, so an order that
    /// names it is refused — and where the codec was never linked the same
    /// order is refused one step earlier, by name, before any frame length
    /// is looked at. Both configurations refuse, which is what the name
    /// says; only the reason differs, and each one is asserted.
    ///
    /// Told apart by the catalogue rather than by a `cfg` on this crate's
    /// `opus` feature, for the reason
    /// `an_order_that_names_opus_follows_the_catalogue` gives.
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

    /// The other half: a frame length every codec in the order can cut is
    /// taken, in every build. G.711 cuts at any whole millisecond, so this
    /// one says the refusal above is the codec's opinion and not a limit on
    /// the setting itself.
    #[test]
    fn a_frame_length_every_codec_in_the_order_cuts_is_taken() {
        let taken = catalog_of(Some("PCMU"), 7, true, false, None, None, true)
            .expect("G.711 cuts a whole number of samples at any millisecond");
        assert_eq!(taken.frame_length(), 7);
    }

    /// Zero is unspecified rather than a fourth policy, and the three named
    /// values are `sipral::SrtpPolicy`'s three, in the same order this ABI
    /// gives them numbers.
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
    }

    #[test]
    fn srtp_policy_refuses_anything_else() {
        let refused = srtp_policy(7, "srtp").expect_err("7 names no policy");
        assert_eq!(refused.status, SipralStatus::InvalidArgument);
    }

    /// What reaches the facade: `catalog_of` leaves the catalogue's own
    /// default alone for `None`, and calls `with_srtp` for `Some`, which is
    /// the one door this ABI has into `sipral::SrtpPolicy`.
    #[test]
    fn catalog_of_applies_srtp_only_when_one_was_named() {
        let default =
            catalog_of(None, 0, true, false, None, None, true).expect("a plain catalogue");
        assert_eq!(default.srtp(), SrtpPolicy::default());

        let required = catalog_of(None, 0, true, false, Some(SrtpPolicy::Required), None, true)
            .expect("a catalogue");
        assert_eq!(required.srtp(), SrtpPolicy::Required);
    }

    /// The Annex B knob reaches the catalogue, on an order that names G.729
    /// and one that does not alike: a call's own order may name it later.
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

    /// The codec's own refusal: the one media error both answers to the C
    /// side decide before they reach their tables, and the one this crate
    /// may write no `cfg` about, because `sipral-ffi` with its own `opus`
    /// off over a facade that linked the codec is a build somebody can
    /// compile.
    ///
    /// Produced the way it is really produced rather than assembled here:
    /// the encoder of the codec at the top of this build's catalogue is
    /// handed half a frame. Opus encodes one length and refuses every other,
    /// and the three written codecs cut whatever they are given — so a build
    /// without Opus produces nothing here at all, which is the other half of
    /// what this asserts and what says those two answers are unreachable
    /// there rather than merely untested.
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
            // loud, so that nothing on the way down mistakes it for silence
            // and swallows the frame before the encoder sees it
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

    /// A far end that names two of the three formats this end offered, so
    /// that one negotiation produces all three outcomes at once.
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

    /// D5, the codec half: the list names every codec this call could have
    /// used and what became of each. The far end named two of the three, so
    /// all three answers are in one negotiation — the one that won, the one
    /// it beat, and the one that was never in the running at all.
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

        // and the one that won is the one the call is actually using, which
        // is what makes this list an explanation of that number rather than a
        // second opinion about it
        assert_eq!(won.codec, media_info(media).codec);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// The list is this call's own catalogue, so a call that named its own
    /// order has exactly that order in it and nothing the stack offers
    /// besides.
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

    /// An index past the end names how many there are, the way every other
    /// indexed reader in this ABI does.
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

    /// And the size is checked before the handle is looked up, the same way
    /// `sipral_media_info` checks it, so a caller that got its header wrong
    /// is told that rather than something about the call.
    #[test]
    fn a_candidate_struct_shorter_than_its_min_size_is_unsupported_version() {
        let mut candidate = candidate_zeroed();
        candidate.size = crate::versioned::min_size::CODEC_CANDIDATE - 1;
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

    /// The size is checked before the handle is even looked up: a media
    /// handle nothing minted and an info struct too short to be any version
    /// of this one both fail, and the size is the one this answers with.
    #[test]
    fn a_media_info_struct_shorter_than_its_min_size_is_unsupported_version_even_for_an_invalid_handle()
     {
        let mut info = media_info_zeroed();
        info.size = crate::versioned::min_size::MEDIA_INFO - 1;
        assert_eq!(
            unsafe { sipral_media_info(SIPRAL_HANDLE_NONE, &raw mut info) },
            SipralStatus::UnsupportedVersion
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

    /// A compound report is held to the control bound and media to the media
    /// one, and the two are told apart by RFC 5761 §4 before either is read.
    ///
    /// Two kilobytes is past `SIPRAL_MEDIA_PACKET_BYTES` and inside
    /// `SIPRAL_MEDIA_RTCP_BYTES`. As control it reaches the session, which
    /// refuses it for what it is rather than for how long it is; as media it
    /// never gets that far. The difference is the whole of the change: a report
    /// a peer built larger than this end builds one used to be an argument
    /// error, which says the caller did something wrong when the caller only
    /// handed over what arrived.
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

    // -- what the call cost ---------------------------------------------------

    /// A6's live half. A call with nothing wrong with it reads a hundred, and
    /// the counters move with what actually crossed the boundary.
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

    /// An earpiece that asks for frames faster than the far end sends them
    /// runs the buffer dry, and plays silence where the far end was still
    /// talking. The frames it played that way are counted where the C
    /// caller reads the call's quality, as `frames_underrun`, and they are
    /// the frames of silence between the last packet played and the next
    /// one on the far end's clock, no more.
    #[test]
    fn frames_played_as_nothing_while_the_far_end_talked_are_counted_as_under_runs() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        let timestamp = |sequence: u16| 8_000 + u32::from(sequence - 100) * 160;
        // each on time for its timestamp, so the path has no jitter to
        // blame and the buffer's target stays where a clean path puts it
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
        // one of the four may go to shortening the far end's pause, since
        // what the mu-law silence decodes to is a pause
        assert!(played >= 3, "only {played} of four packets played");
        assert!(dry > 0, "the earpiece never ran ahead of the far end");
        assert_eq!(
            statistics(media, due(103)).frames_underrun,
            0,
            "nothing says yet whether that silence was the far end's pause"
        );

        // the far end's clock ran on unbroken: the silence was its words,
        // and so is whatever the buffer waits out before it plays again
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

    /// A media entry point reads the caller's clock through the handle it was
    /// minted with, not through the stack, so a stack that has since been
    /// polled far ahead does not make a media reading that lags behind it a
    /// caller bug. Before the media handle existed, `sipral_call_media_receive`
    /// resolved through the stack and so refused exactly this: a `now_ms`
    /// behind the stack's own last-polled time was `SIPRAL_STATUS_INVALID_ARGUMENT`.
    #[test]
    fn a_datagram_read_on_a_clock_behind_the_stacks_own_is_not_refused() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);

        // the poll thread's clock runs far ahead of the network thread's
        crate::stack::tests::poll(stack, 50_000);

        // RFC 3550 A.1 keeps a new source on probation until it has sent two
        // in a row, so only the last of these is audio arriving rather than
        // held for probation
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

    /// The other half of the same guarantee: an older reading is not only
    /// accepted where it was asked, it also leaves the stack's own clock
    /// exactly where signalling put it, so the very next poll is not refused
    /// as if the media call had dragged the watermark backward.
    #[test]
    fn a_media_call_with_an_older_now_ms_does_not_refuse_the_next_signalling_call() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);

        // the stack's own clock is already at 1_100 from bringing the call
        // up; a reading forty times further behind than the slack this
        // stack's own signalling gets is answered anyway, because a media
        // entry point never checks against that clock at all
        let stats = statistics(media, 100);
        assert_eq!(
            stats.codec,
            SipralCodec::Pcmu as u32,
            "the reading was answered"
        );

        // and signalling picks up exactly where it left off: a normal next
        // poll is not refused as more than the slack behind some watermark
        // the media call never touched
        let mut result = crate::stack::tests::poll_result();
        let polled = unsafe { crate::stack::sipral_stack_poll(stack, 1_101, &raw mut result) };
        assert_eq!(polled, SipralStatus::Ok, "{}", last_error_text());

        hangup(stack, call, 1_200);
        assert_eq!(
            unsafe { crate::stack::sipral_stack_destroy(stack) },
            SipralStatus::Ok
        );
    }

    /// The size is checked before the handle is even looked up: a media
    /// handle nothing minted and a stats struct too short to be any version
    /// of this one both fail, and the size is the one this answers with.
    #[test]
    fn a_stream_stats_struct_shorter_than_its_min_size_is_unsupported_version_even_for_an_invalid_handle()
     {
        let mut stats = empty_stats();
        stats.size = crate::versioned::min_size::STREAM_STATS - 1;
        assert_eq!(
            unsafe { sipral_media_statistics(SIPRAL_HANDLE_NONE, 0, &raw mut stats) },
            SipralStatus::UnsupportedVersion
        );
    }

    /// The size is checked before the handle is even looked up: a media
    /// handle nothing minted and a packet struct too short to be any version
    /// of this one both fail, and the size is the one this answers with — on
    /// the way out with a frame and on the way out with a report alike.
    #[test]
    fn a_media_packet_struct_shorter_than_its_min_size_is_unsupported_version_even_for_an_invalid_handle()
     {
        let samples = [0_i16; FRAME];
        let mut buffers = Buffers::new();
        let mut packet = buffers.packet();
        packet.size = crate::versioned::min_size::MEDIA_PACKET - 1;
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

    /// A6's other half: the record has to survive the call it is about. The
    /// stream is gone by the time this arrives, so the numbers travel in the
    /// event rather than behind a lookup that would now fail.
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

    // -- the watchdog ---------------------------------------------------------

    /// B5: media that stops while signalling stays happy, and the recovery
    /// that follows it.
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

        // RFC 3550 A.1 keeps a new source on probation until it has sent two
        // in a row, so one packet is not yet audio arriving
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

    // -- the packets ---------------------------------------------------------

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

    /// `sipral_call_join` refuses a call joined to itself and a second
    /// pairing of a call already in one; `sipral_media_mix` then moves one
    /// frame between the two calls' own far ends; and `sipral_call_leave`
    /// refuses a call that has already left.
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

    /// A call that hangs up while joined tells its former partner over the C
    /// ABI too — `SIPRAL_EVENT_KIND_MEDIA_UNJOINED`, naming the call that is
    /// still up — and that survivor keeps carrying its own audio directly,
    /// exactly as an unjoined call always has.
    /// `crates/sipral/src/tests.rs` already proves the facade's own half of
    /// this (`MediaEvent::Unjoined`); this proves the translation across the
    /// boundary does not silently drop it.
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

    /// Half a frame encoded as a whole one is what a peer hears as a stutter,
    /// so the length is checked rather than trusted.
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

    /// A buffer too small is answered before anything is built, so the frame is
    /// not lost from a stream whose timestamps have already moved past it.
    #[test]
    fn a_packet_buffer_too_small_costs_no_audio() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        let mut small = [0_u8; 64];
        let mut packet = SipralMediaPacket {
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

    /// Every source fills the frame, silence included: a device handed nothing
    /// plays whatever was in its buffer last.
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

    /// The control traffic RFC 3550 §6.3 schedules, addressed to the port the
    /// negotiation put it on rather than to the media port.
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

    // -- a handle of its own -------------------------------------------------

    /// A media handle outlives its call, and says so: every entry point that
    /// takes one answers that the media has ended, rather than acting on a
    /// stream that has already said goodbye, and the handle is still released
    /// exactly once.
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

    /// The same when the stack goes first: destroying it ends every call's
    /// media, and a handle says so rather than keeping a stream running for a
    /// stack that no longer exists.
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

    /// A binding's own event handler. On the news that audio has started it
    /// mints the call's media handle from inside the callback, and a device
    /// thread asks for the frame that is due while the poll thread is still in
    /// here.
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

    /// The re-entry this change exists for, and B5's glitch from the audit that
    /// found it: a callback that answers an event by calling into the library
    /// is not refused, and neither is the audio thread that wants its frame at
    /// the same moment.
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

    /// A processor that asks for the frame that is due from inside the frame it
    /// is processing: the one way a thread arrives at a call's media it is
    /// already inside.
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

    /// Re-entry on one session is the only thing a media entry point answers
    /// `SIPRAL_STATUS_BUSY` for, and it is answered rather than left as a
    /// thread waiting for itself.
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

        // on a thread of its own, so that a capture waiting for itself is a
        // test that fails rather than a run that never ends
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

    /// A processor that reaches its own call through the stack instead: it
    /// hangs the call up, polls the stack and destroys it, all from inside the
    /// frame it is processing. Each of those can need the very session the
    /// frame is holding.
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

    /// The same re-entry, through the stack: a thread inside a call's media
    /// that calls into that call's stack is answered, as it was when a frame
    /// held the stack's lock, rather than left waiting for a session it is
    /// itself holding — with the stack's own lock held the whole time, so that
    /// every other thread would be refused for ever after.
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

    /// The callback for [`the_c_callback_s_frame_replaces_what_was_captured`]:
    /// writes a value derived from, but distinguishable from, `near_end` into
    /// `out` — a real callback's whole reason to exist, and exactly what
    /// [`CProcessor::process`] has to carry back into the caller's own frame
    /// once this returns.
    unsafe extern "C" fn doubles_into_out(
        frame: *const SipralProcessorFrame,
        _user_data: *mut c_void,
    ) {
        // Safety: the caller of this test-only callback (`CProcessor::process`,
        // below) upholds the same contract `SipralProcessorCallback` documents.
        let frame = unsafe { &*frame };
        let near = unsafe { std::slice::from_raw_parts(frame.near_end, frame.near_end_len) };
        let out = unsafe { std::slice::from_raw_parts_mut(frame.out, frame.out_len) };
        for (slot, &sample) in out.iter_mut().zip(near) {
            *slot = sample.wrapping_mul(2);
        }
    }

    /// [`CProcessor`] hands the C callback a frame to fill and has to carry
    /// what it wrote back into the caller's own buffer once the callback
    /// returns — the one step `bindings/c/smoke.c`'s own processor test never
    /// actually checks, since it only asserts on what the callback was
    /// *handed*, not on what a caller sees afterwards. Breaking the copy-back
    /// in `CProcessor::process` (commenting out
    /// `near_end.copy_from_slice(&self.out)`) leaves this test the only one
    /// in the workspace that fails.
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

    /// Whether the slow callback below sleeps: off while the fixture builds
    /// the call, so that setting up is not the slow part of the test.
    static SLOW: AtomicBool = AtomicBool::new(false);

    /// A binding's event handler that takes its time: fifty milliseconds for
    /// every event, which is a user interface thread in a layout pass or a log
    /// line going to a busy disk.
    unsafe extern "C" fn fifty_milliseconds(event: *const SipralEvent, user_data: *mut c_void) {
        unsafe { crate::stack::tests::record(event, user_data) };
        if SLOW.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// B5 for ten seconds. One thread polls a stack whose callback takes fifty
    /// milliseconds over every event, and hands the same call's packets over as
    /// a network thread would; another asks for a frame every twenty
    /// milliseconds, as a device does. While the stack's lock was held across
    /// the callback and the media path took that lock, a frame that fell due
    /// during a callback was refused. None may be now.
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
                    // an event for the slow callback to sit on: an account that
                    // starts registering, taken away again once that is said
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

    // -- the goodbye a call's media owes when it ends (task 8.4.21) ----------

    /// The first SSRC named in the one RTCP BYE (RFC 3550 §6.4.2, packet type
    /// 203) inside a compound packet — enough to check what
    /// `sipral_stack_poll_farewell` handed over against the session's own
    /// wire output, without a second RTCP parser: a compound packet is
    /// nothing but concatenated fixed-header sub-packets, each stating its
    /// own length in 32-bit words, and that much is universal to every one of
    /// them.
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

    /// A call whose media is running leaves exactly one farewell when it
    /// ends: the RTCP BYE RFC 3550 §6.3.7 owes the far end, addressed to its
    /// RTCP port and naming this call's own SSRC, readable only through the
    /// stack once the call's media handle has already gone.
    #[test]
    fn a_call_that_ends_with_media_running_leaves_exactly_one_farewell() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);

        // this call's own SSRC, read off one outgoing RTP packet rather than
        // reached for directly: the packet is what the far end actually sees
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

        // and nothing after it
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

    /// An application that never calls `sipral_stack_poll_farewell` — a
    /// binding built against a header from before that entry point existed,
    /// among others — does not keep every ended call's goodbye for as long
    /// as the stack lives: past `FAREWELL_CEILING` the oldest is dropped, and
    /// each drop is counted in `farewells_dropped` (task 8.4.21).
    #[test]
    fn a_queue_of_farewells_past_its_ceiling_drops_the_oldest_and_counts_it() {
        let mut observed = Observed::default();
        let (handle, account) = media_line(&mut observed, |_| {});

        let mut first_call = SIPRAL_HANDLE_NONE;
        let mut second_call = SIPRAL_HANDLE_NONE;
        let mut now = 1_000;
        // one call's worth of farewells past the ceiling, ended one at a
        // time and none of them ever polled
        for i in 0..=crate::stack::FAREWELL_CEILING {
            let (status, call) = place(handle, account, &managed_config(), now);
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            let invite = one(handle);
            deliver(handle, &accepted(&invite, ANSWER, true), now + 100);
            crate::stack::tests::poll(handle, now + 100);
            // the ACK the answer produced, which is not this test's to keep
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

    /// A stack that never ran any call's media has nothing queued for it.
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
}
