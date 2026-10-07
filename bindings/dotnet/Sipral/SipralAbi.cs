// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Printed from the declarations in crates/sipral-ffi by tools/abi-gen.
// Do not edit: `cargo run -p sipral-abi-gen` writes it again, and
// `scripts/check.sh` fails when what is committed is not what came out.

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Sipral;

/// <summary>
/// The result of a call across the C ABI.
///
/// The numbers are ABI: stable for the major version, new ones only at the
/// end. 17 is reserved forever and never returned.
///
/// Typed `int32_t`: zero is success, failures are positive, none negative.
/// Read an unknown status from a newer library as a failure.
/// </summary>
public enum SipralStatus : int
{
    /// <summary>
    /// The call did what it was asked to.
    /// </summary>
    Ok = 0,
    /// <summary>
    /// A pointer was null where one is required, a length disagreed with what
    /// it describes, or a value was outside what the call accepts.
    /// </summary>
    InvalidArgument = 1,
    /// <summary>
    /// The handle never came from this library, or it came from a stack
    /// other than the one it was used with.
    /// </summary>
    InvalidHandle = 2,
    /// <summary>
    /// The handle came from this library and what it named is gone: a use
    /// after free, or a second free.
    /// </summary>
    StaleHandle = 3,
    /// <summary>
    /// A versioned struct declared a size this build cannot work with, or a
    /// binding asked for an ABI this library does not provide.
    /// </summary>
    UnsupportedVersion = 4,
    /// <summary>
    /// The buffer supplied is too small. The length needed has been written to
    /// the out parameter, and nothing was written to the buffer.
    /// </summary>
    BufferTooSmall = 5,
    /// <summary>
    /// The object is already in use by another call, including one further
    /// down the same call stack. Nothing was done, and nothing blocked.
    /// </summary>
    Busy = 6,
    /// <summary>
    /// No room: an object table is full, the RTP port range is spent, or a
    /// call's queue (DTMF, payload types, real-time text) is full. Nothing
    /// was done; the last error says which. `SIPRAL_STATUS_LIMIT_REACHED`
    /// is the application's own ceiling.
    /// </summary>
    Exhausted = 7,
    /// <summary>
    /// A panic was caught at the boundary. The call did not finish; the last
    /// error carries the panic's message.
    /// </summary>
    Panic = 8,
    /// <summary>
    /// Not possible in the object's current state, e.g. answering a call
    /// this end placed, or DTMF before there is a dialog.
    /// </summary>
    WrongState = 9,
    /// <summary>
    /// The request could not be assembled or handed to a transport. Nothing
    /// went out, and the call did not change.
    /// </summary>
    NotSent = 10,
    /// <summary>
    /// The value is valid in this ABI but this build has no code for it.
    /// Nothing was applied, and retrying will not help. Unlike
    /// SipralStatus.InvalidArgument, the value is not wrong; unlike
    /// SipralStatus.UnsupportedVersion, it is not about struct shape.
    /// Exists so that nothing is ever silently accepted and ignored.
    /// </summary>
    NotSupported = 11,
    /// <summary>
    /// A byte stream carried something that starts no known message. A
    /// stream has no resync point: close the connection. The last error
    /// says what was lost.
    /// </summary>
    StreamBroken = 12,
    /// <summary>
    /// An audio device id the engine never listed. Refused before any
    /// platform call; `sipral_audio_device_at` lists the ids.
    /// </summary>
    NoSuchDevice = 13,
    /// <summary>
    /// The audio device cannot serve: no channels in that direction,
    /// unplugged, or the platform refused it. The last error says which.
    /// </summary>
    DeviceUnusable = 14,
    /// <summary>
    /// The platform did not answer about its audio devices within
    /// `sipral_stack_config_t::audio_probe_ms`. Nothing was done.
    /// </summary>
    DeviceTimedOut = 15,
    /// <summary>
    /// The stack already holds or awaits `sipral_stack_config_t::max_dialogs`
    /// calls. Nothing went out. An ended call makes room; a higher limit
    /// needs a new stack.
    /// </summary>
    LimitReached = 16,
    /// <summary>
    /// Refused by the security policy (ABI 0.31): unencrypted audio where
    /// SRTP is required, or a policy weaker than the account's. A refused
    /// INVITE was answered 488; an outgoing call never left.
    /// </summary>
    SecurityPolicy = 18,
    /// <summary>
    /// The recording file would not take a write (disk full, volume gone).
    /// A bad path is `SIPRAL_STATUS_INVALID_ARGUMENT` instead. The recording
    /// stopped; the file holds audio up to the last checkpoint.
    /// </summary>
    RecordingFailed = 19,
    /// <summary>
    /// The call never negotiated this, e.g. text on a call with no `m=text`
    /// stream. Only a new accepted offer changes it.
    /// </summary>
    NotNegotiated = 20,
    /// <summary>
    /// The far end's Contact never carried `isfocus` (RFC 4579 §4.1), so
    /// there is no conference to name or subscribe to.
    /// </summary>
    NotAFocus = 21,
    /// <summary>
    /// The transport has failed or closed and was not bound again. Nothing
    /// went out. Reconnect, call `sipral_stack_transport_bind`, retry.
    /// </summary>
    TransportDown = 22,
    /// <summary>
    /// A local conference would not take the call (ABI 0.32): full, the
    /// call is already conferenced or joined with `sipral_call_join`, or its
    /// codec rate is not mixed. The last error says which.
    /// </summary>
    ConferenceRefused = 23,
    /// <summary>
    /// `now_ms` was more than 50 ms behind the last reading this stack saw
    /// (ABI 0.33). Nothing was done and the clock did not move; read the
    /// clock again and retry. Repeated, it means the clock went backwards.
    /// </summary>
    ClockBehind = 24,
    /// <summary>
    /// The TLS certificate's SHA-256 fingerprint differs from
    /// `sipral_account_config_t::tls_pin_sha256` (ABI 0.34). Refuse the
    /// handshake (`docs/22-tls.md`).
    /// </summary>
    CertificateRefused = 25,
    /// <summary>
    /// About to advertise an address the peer cannot reach (ABI 0.34):
    /// loopback to a remote peer, or the unspecified address in a `Contact`.
    /// Nothing was sent; the last error names both addresses.
    /// `sipral_advertised_address` finds the right one.
    /// </summary>
    UnreachableAddress = 26,
}

/// <summary>
/// What a stack speaks. Names for `sipral_stack_config_t::transport`. Zero is
/// not one, so a caller who meant TLS is never put on the wire in the clear.
/// </summary>
public enum SipralTransport : uint
{
    /// <summary>
    /// UDP.
    /// </summary>
    Udp = 1,
    /// <summary>
    /// TCP.
    /// </summary>
    Tcp = 2,
    /// <summary>
    /// TLS over TCP.
    /// </summary>
    Tls = 3,
    /// <summary>
    /// WebSocket.
    /// </summary>
    Ws = 4,
    /// <summary>
    /// WebSocket over TLS.
    /// </summary>
    Wss = 5,
}

/// <summary>
/// Why a transport could not deliver. Names for sipral_stack_transport_failed's `error`.
///
/// Coarse on purpose: a client transaction terminates on every one of these (§17); the
/// detail belongs in the caller's log.
/// </summary>
public enum SipralTransportError : uint
{
    /// <summary>
    /// Anything the caller could not classify.
    /// </summary>
    Other = 0,
    /// <summary>
    /// Nothing is listening at the far end.
    /// </summary>
    ConnectionRefused = 1,
    /// <summary>
    /// An established connection was reset.
    /// </summary>
    ConnectionReset = 2,
    /// <summary>
    /// No route, or an ICMP unreachable.
    /// </summary>
    Unreachable = 3,
    /// <summary>
    /// The connection attempt or the write timed out.
    /// </summary>
    TimedOut = 4,
    /// <summary>
    /// The connection was closed and cannot be written to again.
    /// </summary>
    Closed = 5,
}

/// <summary>
/// Why a TLS connection was refused, as the platform's TLS library said it. Names for
/// `sipral_transport_failure_t::tls` and `sipral_transport_failed_event_t::tls`.
///
/// Sipral links no TLS library (`docs/22-tls.md`); the stack only carries the application's
/// classification. A connection never answered is `SIPRAL_TRANSPORT_ERROR_CONNECTION_REFUSED`
/// with this left at none.
/// </summary>
public enum SipralTlsFailure : uint
{
    /// <summary>
    /// Not a TLS failure, or one the application could not classify.
    /// </summary>
    None = 0,
    /// <summary>
    /// No trusted authority: self-signed, an unprovided private CA, or not the pinned one.
    /// </summary>
    Untrusted = 1,
    /// <summary>
    /// The certificate is trusted and names another server.
    /// </summary>
    NameMismatch = 2,
    /// <summary>
    /// The certificate has expired, or is not valid yet.
    /// </summary>
    Expired = 3,
    /// <summary>
    /// The handshake failed: no common version or cipher, a server alert, or no TLS there.
    /// </summary>
    HandshakeRefused = 4,
}

/// <summary>
/// The three answers a setting can give in a struct that starts out zeroed.
///
/// Not a boolean: zero must mean "unset", so the library never turns a
/// control off because the caller left it zeroed.
/// </summary>
public enum SipralToggle : uint
{
    /// <summary>
    /// Nothing was said; whatever this build defaults to.
    /// </summary>
    Default = 0,
    /// <summary>
    /// On.
    /// </summary>
    On = 1,
    /// <summary>
    /// Off.
    /// </summary>
    Off = 2,
}

/// <summary>
/// What a call or a stack says about SRTP. Names for
/// `sipral_stack_config_t::srtp` (the stack's default) and
/// `sipral_call_config_t::srtp` (a per-call override).
///
/// Zero means "unset": on the stack, the built-in default
/// SipralSrtp.NotOffered; on a call, the stack's setting.
/// `docs/05-media.md` details each value.
/// </summary>
public enum SipralSrtp : uint
{
    /// <summary>
    /// Do not offer it, but answer an offer on the secure profile with keys.
    /// </summary>
    NotOffered = 1,
    /// <summary>
    /// Offer it, and answer a plain offer plainly.
    /// </summary>
    Offered = 2,
    /// <summary>
    /// Offer it, and let no stream on this call carry audio unencrypted.
    /// </summary>
    Required = 3,
    /// <summary>
    /// Offer DTLS-SRTP (RFC 5764) on `UDP/TLS/RTP/SAVP`, and answer a plain
    /// offer plainly.
    ///
    /// The key never travels in the body, so this is sound over a readable
    /// SIP transport. Costs a round trip of silence at call start. The
    /// application **must** drain sipral_media_poll_transmit, or the
    /// call is up, silent, and reports no error.
    ///
    /// `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
    /// `SIPRAL_FEATURE_DTLS_SRTP`.
    /// </summary>
    Dtls = 4,
    /// <summary>
    /// Offer DTLS-SRTP and allow no other keying, including an answer
    /// carrying `a=crypto`.
    /// </summary>
    DtlsRequired = 5,
    /// <summary>
    /// DTLS-SRTP with SDES fallback, never unencrypted. The offer is one
    /// `RTP/SAVP` stream with both fingerprint and crypto lines; the answer
    /// decides. An incoming offer is answered the way it was keyed; a plain
    /// one is refused with 488.
    ///
    /// `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
    /// `SIPRAL_FEATURE_DTLS_SRTP`.
    /// </summary>
    DtlsOrSdes = 6,
    /// <summary>
    /// Offer SDES on plain `RTP/AVP` ("SRTP optional"): encrypted when the
    /// answer takes an `a=crypto` line, plain otherwise. For servers that
    /// reject `RTP/SAVP` with 488. Not standard (RFC 4568 defines the
    /// attribute for secure profiles). An incoming `RTP/AVP` offer with a
    /// usable line is answered with a key, anything else as `Offered`.
    /// </summary>
    BestEffort = 7,
}

/// <summary>
/// What a call or a stack says about ICE. Names for
/// `sipral_stack_config_t::ice` (the stack's default) and
/// `sipral_call_config_t::ice` (a per-call override).
///
/// Zero means "unset": on the stack, the built-in default
/// SipralIce.Off; on a call, the stack's setting.
///
/// A call that offers ICE also asks for RFC 5761 multiplexing, whatever
/// `offer_rtcp_mux` says: this ABI names one address per stream.
/// </summary>
public enum SipralIce : uint
{
    /// <summary>
    /// Do not offer it, and do not answer a peer that does. The default;
    /// `docs/06-nat.md` says why.
    /// </summary>
    Off = 1,
    /// <summary>
    /// Offer it, and use it against a peer that offers it back.
    ///
    /// A peer without ICE gets the call on the signalled address and
    /// symmetric RTP. The application **must** drain
    /// sipral_media_poll_transmit, or no path is ever chosen.
    ///
    /// `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
    /// `SIPRAL_FEATURE_ICE`.
    /// </summary>
    Offered = 2,
    /// <summary>
    /// Offer it, and let no stream carry audio on a path ICE did not check.
    ///
    /// A peer that fails ICE ends the call's media with
    /// `SIPRAL_EVENT_KIND_MEDIA_FAILED` instead of falling back.
    /// </summary>
    Required = 3,
    /// <summary>
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
    /// </summary>
    Lite = 4,
}

/// <summary>
/// One codec this ABI has a number for.
///
/// Values are permanent. Whether this build contains a codec is answered by
/// `SIPRAL_FEATURE_*` and `sipral_codec_at`, not by this list.
/// </summary>
public enum SipralCodec : uint
{
    /// <summary>
    /// No codec: the call has none, or the event is not about one.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// G.711 mu-law, payload type 0.
    /// </summary>
    Pcmu = 1,
    /// <summary>
    /// G.711 A-law, payload type 8.
    /// </summary>
    Pcma = 2,
    /// <summary>
    /// G.722, wideband at the price of a narrowband stream.
    /// </summary>
    G722 = 3,
    /// <summary>
    /// Opus. Declared in every build; presence is `SIPRAL_FEATURE_OPUS`.
    /// </summary>
    Opus = 4,
    /// <summary>
    /// G.729 Annex A, payload type 18. Offered only when a codec order names
    /// `G729`; offers `annexb=yes`, answers with the offer's `annexb`.
    /// </summary>
    G729 = 5,
    /// <summary>
    /// L16 at 8 kHz mono, dynamic payload type `L16/8000`. Offered only
    /// when a codec order names it.
    /// </summary>
    L16Narrowband = 6,
    /// <summary>
    /// L16 at 16 kHz mono, `L16/16000`. Offered only when a codec order
    /// names it.
    /// </summary>
    L16Wideband = 7,
}

/// <summary>
/// What became of one codec this call's catalogue could have used. Names
/// for SipralCodecCandidate.Outcome.
/// </summary>
public enum SipralCodecOutcome : uint
{
    /// <summary>
    /// Not an outcome: unknown to this ABI, or the struct was never filled.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// What the call agreed on. Exactly one candidate carries it, the same
    /// codec as `sipral_media_info_t::codec`.
    /// </summary>
    Chosen = 1,
    /// <summary>
    /// The far end's description did not name it.
    /// </summary>
    NotNamed = 2,
    /// <summary>
    /// The far end named it and this end had something better: the codec
    /// in `outranked_by` came first in this call's order.
    /// </summary>
    Outranked = 3,
}

/// <summary>
/// Whether a SipralPathCandidate is a candidate pair or a relay.
/// </summary>
public enum SipralPathKind : uint
{
    /// <summary>
    /// Not a kind: the struct was never filled in.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// A candidate pair the call's ICE checklist held (RFC 8445
    /// §6.1.2).
    /// </summary>
    Pair = 1,
    /// <summary>
    /// An allocation on a TURN server the call's agent held (RFC 8656).
    /// </summary>
    Relay = 2,
}

/// <summary>
/// The kind of an ICE candidate (RFC 8445 §5.1.1). Names for
/// SipralPathCandidate.LocalKind and `remote_kind`.
/// </summary>
public enum SipralCandidateKind : uint
{
    /// <summary>
    /// Not known: a relay's server, which is no candidate, or the far
    /// end of a pair a lite end took from a nomination and never learned
    /// the kind of.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// An address a socket of the host's own is bound to.
    /// </summary>
    Host = 1,
    /// <summary>
    /// The address a NAT maps the host's socket to, as a STUN or TURN
    /// server saw it.
    /// </summary>
    ServerReflexive = 2,
    /// <summary>
    /// An address a connectivity check revealed (RFC 8445 §7.3.1.3).
    /// </summary>
    PeerReflexive = 3,
    /// <summary>
    /// An address on a TURN server that relays for the host.
    /// </summary>
    Relayed = 4,
}

/// <summary>
/// What became of one path a call's ICE agent tried. Names for
/// SipralPathCandidate.Outcome.
/// </summary>
public enum SipralPathOutcome : uint
{
    /// <summary>
    /// Not an outcome: unknown to this ABI, or the struct was never filled.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// The path the call's media takes: the selected pair (RFC 8445
    /// §8.1.2), or the relay it runs through.
    /// </summary>
    Selected = 1,
    /// <summary>
    /// A pair whose check succeeded, with nothing selected yet.
    /// </summary>
    Valid = 2,
    /// <summary>
    /// Nothing has decided it yet: a pair frozen, waiting its turn or
    /// with its check on the wire; a relay still being allocated.
    /// </summary>
    Waiting = 3,
    /// <summary>
    /// A pair whose check succeeded, with a pair of higher priority
    /// selected over it.
    /// </summary>
    Outranked = 4,
    /// <summary>
    /// A pair another was nominated ahead of: its check had not finished
    /// when the selection took it off the checklist (RFC 8445 §8.1.2),
    /// or it succeeded after a lower one was nominated.
    /// </summary>
    NominatedElsewhere = 5,
    /// <summary>
    /// A pair whose check was never answered (RFC 8489 §6.2.1).
    /// </summary>
    TimedOut = 6,
    /// <summary>
    /// A pair the far end refused; `code` is the STUN error code (RFC
    /// 8445 §7.2.5.2.4).
    /// </summary>
    Refused = 7,
    /// <summary>
    /// A pair whose answer came from an address other than the one its
    /// check went to (RFC 8445 §7.2.5.2.1): a NAT between rewriting it.
    /// </summary>
    NotSymmetric = 8,
    /// <summary>
    /// A pair whose answer named no address to form a valid pair from.
    /// </summary>
    Unusable = 9,
    /// <summary>
    /// A relayed pair the relay would not let the far end through for,
    /// or a relay whose allocation the server refused; `code` is the
    /// TURN server's error code, zero when it gave none (RFC 8656 §9,
    /// §7.3).
    /// </summary>
    RelayRefused = 10,
    /// <summary>
    /// A pair never checked: the pair limit discarded it (RFC 8445
    /// §6.1.2.5), or its checklist ended before its turn came.
    /// </summary>
    NotChecked = 11,
    /// <summary>
    /// A relay held, that no selected pair runs through — or none yet.
    /// </summary>
    Held = 12,
    /// <summary>
    /// A relay given back: ICE concluded on a pair that does not use it
    /// (RFC 8445 §8.3.1), or this branch of a forked call let go of it.
    /// </summary>
    Released = 13,
    /// <summary>
    /// A relay the server took back; `code` is its error code, zero when
    /// a refresh went unanswered (RFC 8656 §8).
    /// </summary>
    Lost = 14,
}

/// <summary>
/// Which way audio may flow, as seen from here. Names for every `direction`.
/// </summary>
public enum SipralDirection : uint
{
    /// <summary>
    /// Not negotiated.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// Both ways.
    /// </summary>
    SendRecv = 1,
    /// <summary>
    /// This end sends and does not receive, which is what holding the far end
    /// looks like from here.
    /// </summary>
    SendOnly = 2,
    /// <summary>
    /// This end receives and does not send.
    /// </summary>
    RecvOnly = 3,
    /// <summary>
    /// Neither way, and the stream stays in the session.
    /// </summary>
    Inactive = 4,
}

/// <summary>
/// Where control traffic goes. Names for SipralMediaInfo.Rtcp.
/// </summary>
public enum SipralRtcp : uint
{
    /// <summary>
    /// Not negotiated.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// One port carries both (RFC 5761), which happens only where both ends
    /// asked for it.
    /// </summary>
    Muxed = 1,
    /// <summary>
    /// A port of its own at each end.
    /// </summary>
    SeparatePort = 2,
    /// <summary>
    /// None at all: the peer said it is not using RTCP.
    /// </summary>
    Off = 3,
}

/// <summary>
/// Why media failed, for a machine to act on. Names for
/// `sipral_media_event_t::fault`.
/// </summary>
public enum SipralMediaFault : uint
{
    /// <summary>
    /// Nothing failed.
    /// </summary>
    None = 0,
    /// <summary>
    /// The peer answered with a format this build cannot encode or decode.
    /// </summary>
    UnsupportedCodec = 1,
    /// <summary>
    /// The two descriptions agree on nothing that can carry audio.
    /// </summary>
    NoCommonCodec = 2,
    /// <summary>
    /// One end refused the stream with a port of zero. The call is up and
    /// carries no audio, which is a thing a peer is allowed to want.
    /// </summary>
    StreamRefused = 3,
    /// <summary>
    /// There is no session description to work from.
    /// </summary>
    NoDescription = 4,
    /// <summary>
    /// A description could not be read.
    /// </summary>
    BadDescription = 5,
    /// <summary>
    /// The recording stopped writing: the disk filled, the file went away.
    /// </summary>
    Recording = 6,
    /// <summary>
    /// The codec refused a frame.
    /// </summary>
    Codec = 7,
    /// <summary>
    /// Something else the layer below reported and this ABI has no word for.
    /// </summary>
    Other = 8,
    /// <summary>
    /// ICE could not carry this call: the far end described none this
    /// stack could use and the policy was `SIPRAL_ICE_REQUIRED`, the far
    /// end took `a=rtcp-mux` out of an answer to an ICE offer, or consent
    /// to send on the pair that was chosen was withdrawn part-way through
    /// (RFC 7675 §5). Signalling is still sound; an application may fall
    /// back to a non-ICE profile.
    /// </summary>
    Ice = 9,
    /// <summary>
    /// The SRTP policy refused the far end's description: a plain answer
    /// (hung up with `Reason` 488) or a plain re-offer (refused with 488,
    /// old keys kept).
    /// </summary>
    SecurityPolicy = 10,
}

/// <summary>
/// What a datagram handed to sipral_media_receive turned out to be.
/// </summary>
public enum SipralArrival : uint
{
    /// <summary>
    /// Something this ABI has no word for.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// Audio, held for playout.
    /// </summary>
    Queued = 1,
    /// <summary>
    /// Audio that was not used: malformed, late, duplicated, from the wrong
    /// address, or on a payload type nobody negotiated. The counters in
    /// SipralStreamStats say which, over the call.
    /// </summary>
    Dropped = 2,
    /// <summary>
    /// A reception or sender report, folded into the statistics.
    /// </summary>
    Control = 3,
    /// <summary>
    /// The far end says it is leaving the session (RFC 3550 §6.6). Audio will
    /// stop; the call has not ended until signalling says so.
    /// </summary>
    Goodbye = 4,
    /// <summary>
    /// Control traffic that was not believed: from the wrong address, or not a
    /// well-formed compound packet.
    /// </summary>
    ControlRefused = 5,
    /// <summary>
    /// A DTLS-SRTP handshake record, taken. Drain
    /// sipral_media_poll_transmit for the reply.
    /// </summary>
    Handshake = 6,
    /// <summary>
    /// Arrived on an encrypted call before its keys exist; usually a peer
    /// that sends as soon as its half of the handshake ends.
    /// </summary>
    NotKeyed = 7,
}

/// <summary>
/// The SRTP transform a call is running. Names for
/// `sipral_media_event_t::suite`.
/// </summary>
public enum SipralSrtpSuite : uint
{
    /// <summary>
    /// No transform: the event is not about one, or the call is not
    /// encrypted.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// `AES_CM_128_HMAC_SHA1_80`, the one every implementation has.
    /// </summary>
    AesCm80 = 1,
    /// <summary>
    /// `AES_CM_128_HMAC_SHA1_32`, the same cipher with a shorter tag.
    /// </summary>
    AesCm32 = 2,
    /// <summary>
    /// `F8_128_HMAC_SHA1_80`, which is what 3GPP asks for. Reachable by
    /// SDES only; RFC 5764 §4.1.2 defines no DTLS-SRTP profile for it.
    /// </summary>
    AesF8 = 3,
    /// <summary>
    /// `AES_256_CM_HMAC_SHA1_80` (RFC 6188). SDES only.
    /// </summary>
    Aes256Cm80 = 4,
    /// <summary>
    /// `AES_256_CM_HMAC_SHA1_32` (RFC 6188). SDES only.
    /// </summary>
    Aes256Cm32 = 5,
    /// <summary>
    /// `AEAD_AES_128_GCM` (RFC 7714). DTLS-SRTP profile 0x0007.
    /// </summary>
    AeadAes128Gcm = 6,
    /// <summary>
    /// `AEAD_AES_256_GCM` (RFC 7714). DTLS-SRTP profile 0x0008, preferred
    /// between two ends of this stack.
    /// </summary>
    AeadAes256Gcm = 7,
}

/// <summary>
/// Where the frame sipral_media_playback just produced came from.
/// </summary>
public enum SipralPlayback : uint
{
    /// <summary>
    /// Something this ABI has no word for.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// A packet the far end sent.
    /// </summary>
    Packet = 1,
    /// <summary>
    /// One it sent and this end did not get, filled in by the concealment.
    /// </summary>
    Concealed = 2,
    /// <summary>
    /// Comfort noise, from an RFC 3389 payload the far end sent instead of
    /// audio.
    /// </summary>
    ComfortNoise = 3,
    /// <summary>
    /// Nothing was due: the buffer is still filling, or the far end has
    /// stopped.
    /// </summary>
    Silence = 4,
}

/// <summary>
/// Which way a digit goes to the far end: sipral_call_send_dtmf's `via`. Chosen per
/// send, since it is a fact about the peer, and a peer ignores an unsupported one silently.
/// </summary>
public enum SipralDtmf : uint
{
    /// <summary>
    /// In the media, as an RFC 4733 telephone event: the one to reach for, carried end to
    /// end and surviving transcoding. One, not zero: zero is an unfilled field, refused.
    /// </summary>
    Rtp = 1,
    /// <summary>
    /// An INFO per digit carrying `application/dtmf-relay`, which states the
    /// signal and how long it was held.
    /// </summary>
    InfoRelay = 2,
    /// <summary>
    /// An INFO per digit carrying `application/dtmf`, whose whole body is the
    /// character. Some switches take only this one.
    /// </summary>
    InfoPlain = 3,
    /// <summary>
    /// In the media, as the key's two tones written into the audio in place of the microphone,
    /// for a far end that listens only to the audio. `SIPRAL_DTMF_RTP` falls back to this on a
    /// call with no telephone event.
    /// </summary>
    InBand = 4,
}

/// <summary>
/// What an event is about. Numbers are only ever added; a binding must
/// ignore a kind it does not know.
/// Numbers already spent on features this build does not have:
/// - 16: held for the set of audio devices changed (A2), which shipped as 43 in the wave that allocated its number; spent all the same
/// - 44: held for a second audio device event, which the audio engine did not need; spent all the same
/// </summary>
public enum SipralEventKind : uint
{
    /// <summary>
    /// The stack is running on this thread: the first event, delivered
    /// once by the first poll.
    /// </summary>
    Started = 1,
    /// <summary>
    /// A registration moved. `payload.registration` says how, and
    /// `account` says whose.
    /// </summary>
    RegistrationChanged = 2,
    /// <summary>
    /// Somebody is calling. Answer, ring, or reject it.
    /// </summary>
    IncomingCall = 3,
    /// <summary>
    /// A call this end placed is getting somewhere short of an answer.
    /// </summary>
    CallProgress = 4,
    /// <summary>
    /// A proxy forked the INVITE and a second phone is ringing.
    /// `payload.call.other` is the branch that has just appeared.
    /// </summary>
    CallForked = 5,
    /// <summary>
    /// The call is up.
    /// </summary>
    CallConfirmed = 6,
    /// <summary>
    /// The session inside a live call changed: a hold, a resume, or an offer
    /// either end made and had accepted.
    /// </summary>
    SessionChanged = 7,
    /// <summary>
    /// The far end offered a change this stack has no policy for. The
    /// transaction is held open: answer it or refuse it, or the call ends.
    /// </summary>
    SessionOffered = 8,
    /// <summary>
    /// A change this end offered was refused. The session stands as it was.
    /// </summary>
    SessionChangeFailed = 9,
    /// <summary>
    /// The far end asked this one to call somebody else.
    /// </summary>
    TransferRequested = 10,
    /// <summary>
    /// A transfer this end asked for is under way.
    /// </summary>
    TransferProgress = 11,
    /// <summary>
    /// And how it ended: the far end's final status, a 2xx hanging this
    /// call up. A refused REFER (RFC 3515 §2.4.2) ends here with its status,
    /// a timeout as 408, a transport failure as 503; the call stays up.
    /// </summary>
    TransferDone = 12,
    /// <summary>
    /// A call arrived carrying a `Replaces` and took over one already up.
    /// `payload.call.other` is the one being replaced.
    /// </summary>
    CallReplaced = 13,
    /// <summary>
    /// The call is over; its handle is stale from here on. `message` is
    /// the refusal, or the far end's BYE or CANCEL, or null.
    /// </summary>
    CallEnded = 14,
    /// <summary>
    /// A1. A subscription moved: asked for, granted, on probation,
    /// retrying, or ended. `payload.subscription` says which and where it
    /// is, `reason` why it is not live. Not sent per refresh or per NOTIFY.
    /// </summary>
    SubscriptionChanged = 15,
    /// <summary>
    /// A6. What one call's media cost, once, after
    /// `SIPRAL_EVENT_KIND_CALL_ENDED`. `payload.media.statistics` points
    /// at the record, library-owned and valid for the callback.
    /// </summary>
    MediaStatistics = 17,
    /// <summary>
    /// B1. A request grew too large for a datagram (RFC 3261 §18.1.1) and
    /// no stream transport is open to its destination; it was refused with
    /// `SIPRAL_STATUS_NOT_SENT`. `payload.transport_wanted` says where.
    /// Bind with
    /// sipral_stack_transport_bind
    /// and ask again.
    /// </summary>
    TransportWanted = 18,
    /// <summary>
    /// B5. No media has arrived for longer than the configured threshold.
    /// `payload.media.silent_for_ms` says how long. The call is left up.
    /// </summary>
    MediaStalled = 19,
    /// <summary>
    /// C2. A call a push announced never arrived: the device woke and
    /// refreshed, and no INVITE followed. `payload.announce` says which
    /// announcement and how long it was waited for.
    /// </summary>
    AnnouncedCallMissing = 20,
    /// <summary>
    /// A4, D5. Audio is running; `payload.media.codec` is the agreed codec.
    /// Mint the media handle now with `sipral_call_media`.
    /// </summary>
    MediaStarted = 21,
    /// <summary>
    /// The session changed under a live call: a hold, a resume, a peer that
    /// moved its media address, or a re-negotiation onto another codec.
    /// </summary>
    MediaChanged = 22,
    /// <summary>
    /// Packets are arriving again. `payload.media.silent_for_ms` says how long
    /// the gap turned out to be.
    /// </summary>
    MediaResumed = 23,
    /// <summary>
    /// Media could not be started or could not be kept. The call itself is
    /// untouched; `payload.media.fault` and `payload.media.reason` say why.
    /// </summary>
    MediaFailed = 24,
    /// <summary>
    /// A recording stopped on its own (disk full, file gone).
    /// `payload.media.recorded_ms` says how much was written.
    /// </summary>
    RecordingStopped = 25,
    /// <summary>
    /// The far end pressed a key (RFC 4733 event, or INFO with
    /// `application/dtmf-relay` or `application/dtmf`), one per press.
    /// `payload.media` gives `digit`, `event_code`, `held_ms` and `source`.
    /// `held_ms` zero means no duration or `Duration=0`, not told apart.
    /// </summary>
    DigitReceived = 26,
    /// <summary>
    /// An INFO from `sipral_call_send_dtmf` got a final answer:
    /// `payload.call.digit` and `payload.call.status_code` (415: try the
    /// other INFO form). An unsendable queued digit reports 503 and stops
    /// the rest.
    /// </summary>
    DtmfSent = 27,
    /// <summary>
    /// The lifecycle ladder settled: a path proved again, or every rung
    /// failed. `payload.recovery` says which (`docs/16-lifecycle.md`).
    /// </summary>
    Recovery = 28,
    /// <summary>
    /// A dialog's next hop is a name to resolve (RFC 3263 §4 TARGET).
    /// Answer with
    /// sipral_stack_resolved
    /// and `payload.resolve.dialog`. **Ignoring it is fine**: the dialog
    /// keeps its first flow (§8.1.2), which survives a NAT.
    /// </summary>
    ResolveNeeded = 29,
    /// <summary>
    /// A1. A notification arrived and was answered; the NOTIFY is in
    /// `message`. `payload.subscription.has_dialog_info` says the body was
    /// readable dialog-info, read via
    /// sipral_subscription_dialog_count.
    /// An unreadable body arrives with it zero; the old picture is kept.
    /// </summary>
    Notified = 30,
    /// <summary>
    /// C2. The INVITE for a call a push announced arrived (RFC 8599),
    /// queued just before its SipralEventKind.IncomingCall.
    /// `payload.announce.announcement` is now spent:
    /// `sipral_announcement_forget` answers `SIPRAL_STATUS_WRONG_STATE`.
    /// </summary>
    CallAnnounced = 31,
    /// <summary>
    /// The DTLS-SRTP handshake finished and audio can move (RFC 5764).
    /// `payload.media.suite` is the chosen transform. SDES calls never
    /// raise it; a failed handshake raises `SIPRAL_EVENT_KIND_MEDIA_FAILED`
    /// and leaves the call up.
    /// </summary>
    MediaSecured = 32,
    /// <summary>
    /// ICE chose this call's media path (RFC 8445 §8.1.1), and audio can
    /// move; again if a higher-priority pair replaces it. Addresses are not
    /// carried: each outgoing packet names its destination. Never raised
    /// without ICE (default `SIPRAL_ICE_OFF`).
    /// </summary>
    MediaPathChosen = 33,
    /// <summary>
    /// A MESSAGE arrived (RFC 3428 §7) and was answered 200.
    /// `payload.message` carries the body; `call` is set if it was in-dialog.
    /// </summary>
    MessageReceived = 34,
    /// <summary>
    /// A MESSAGE from `sipral_account_message` got its final answer:
    /// `payload.message.status_code` (408/503 for timeout or transport).
    /// </summary>
    MessageSent = 35,
    /// <summary>
    /// A `message-summary` NOTIFY reported a mailbox (RFC 3842 §3.9);
    /// `payload.message` has the `voice-message` counts.
    /// </summary>
    MessagesWaiting = 36,
    /// <summary>
    /// The RFC 6035 quality report PUBLISH was attempted once, after
    /// `SIPRAL_EVENT_KIND_CALL_ENDED`, if `quality_report_uri` was set.
    /// `payload.media.quality_report_sent` says it left, not that it landed.
    /// </summary>
    QualityReportSent = 37,
    /// <summary>
    /// The call this one was joined to ended. `call` is the survivor and
    /// carries on unjoined, fed directly rather than by `sipral_media_mix`.
    /// </summary>
    MediaUnjoined = 38,
    /// <summary>
    /// A STUN server reported, moved or never answered for a socket
    /// (RFC 8489). Only with `SIPRAL_NAT_STUN`. `payload.nat` says which.
    /// Signalling sockets are already re-registered; a media socket from
    /// `sipral_stack_nat_map` is now usable for calls (before, that is
    /// `SIPRAL_STATUS_WRONG_STATE`). `account`, `call`: none.
    /// </summary>
    NatMapping = 39,
    /// <summary>
    /// A TURN server allocated a relay for a `sipral_stack_nat_map` socket,
    /// or gave none (RFC 8656). Only with a `turn_server`. `payload.relay`
    /// says which; once allocated, calls may use it (before, that is
    /// `SIPRAL_STATUS_WRONG_STATE`). `account`, `call`: none.
    /// </summary>
    NatRelay = 40,
    /// <summary>
    /// An out-of-dialog REFER asks this end to place a call (RFC 3515),
    /// with `sipral_stack_config_t::referrals` on. `call` is the referral's
    /// handle, taken only by `sipral_call_accept_transfer` (202, places the
    /// call) or `sipral_call_reject_transfer`; either spends it. `account`
    /// is the line, `message` the REFER, `payload.referral` the target.
    /// **The application decides each time**: `referred_by` is unverified.
    /// If left unanswered, raised again with only `status_code` set, and
    /// the handle is stale.
    /// </summary>
    Referral = 41,
    /// <summary>
    /// A media socket's TCP/TLS connection to a TURN server
    /// (`turn_transport`, RFC 8656 §3.1) is to be opened or closed.
    /// `payload.turn_stream` says which. On `SIPRAL_TURN_STREAM_OPEN`, open
    /// it (TLS checked against the server name), then call
    /// `sipral_stack_turn_connected`, `sipral_stack_turn_receive` and
    /// `sipral_stack_turn_closed`. On `SIPRAL_TURN_STREAM_CLOSE`, flush and
    /// close. `account`, `call`: none.
    /// </summary>
    TurnStream = 42,
    /// <summary>
    /// The audio engine's devices moved (with `SIPRAL_AUDIO_DEVICE`).
    /// `payload.audio` says what and whether the system or the engine did
    /// it. `account`, `call`: none.
    /// </summary>
    AudioDevicesChanged = 43,
    /// <summary>
    /// The network changed and this call's media address is gone. Raised
    /// per call by `sipral_stack_network_changed` on
    /// `SIPRAL_RECOVERY_REBUILD`: after `sipral_account_rebind`, pass a new
    /// socket address to `sipral_call_media_readdress`.
    /// </summary>
    CallAddressWanted = 45,
    /// <summary>
    /// The STUN server in use changed, or all failed
    /// (`payload.stun_server`). A server fails after 5.5 s and is skipped
    /// for 30 s, doubling up to ten minutes. Sockets move on by themselves.
    /// `account`, `call`: none.
    /// </summary>
    StunServer = 46,
    /// <summary>
    /// Caller verification (RFC 8224, RFC 8588); `payload.verification`.
    /// `CERTIFICATE_WANTED`: fetch `certificate_url` and pass it (or
    /// nothing) to `sipral_call_stir_certificate`; the call waits.
    /// `VERIFIED`: the verdict, just before the call's
    /// `SIPRAL_EVENT_KIND_INCOMING_CALL`, or with `refused` set before its
    /// `SIPRAL_EVENT_KIND_CALL_ENDED`. `message` is the INVITE.
    /// </summary>
    CallerVerification = 47,
    /// <summary>
    /// A keypad digit heard as tones (with DTMF detection enabled), once
    /// per press. A press also sent as a named event is reported once as
    /// `SIPRAL_EVENT_KIND_DIGIT_RECEIVED`; tones alone wait 250 ms.
    /// </summary>
    InBandDigit = 48,
    /// <summary>
    /// What `sipral_call_detect_progress` heard: a progress tone, the
    /// special information tone, who answered, or a machine's beep
    /// (`payload.progress`).
    /// </summary>
    ProgressDetected = 49,
    /// <summary>
    /// A `conference` subscription's picture changed or the conference
    /// ended (RFC 4575 §4.6); `payload.conference`. Read the picture with
    /// `sipral_subscription_conference`. Out-of-order documents raise
    /// nothing; after a loss the stack asks for full state.
    /// </summary>
    ConferenceChanged = 50,
    /// <summary>
    /// Real-time text from the far end (RFC 4103), in order, UTF-8 in
    /// `payload.text`: BACKSPACE erases, U+2028 is a new line, BELL alerts,
    /// U+FFFD marks each unrecovered lost block (§5.3), counted in `missing`.
    /// </summary>
    TextReceived = 51,
    /// <summary>
    /// Presence moved: a `presence` subscription's PIDF (RFC 3856), or this
    /// account's publication (RFC 3903). `payload.presence.kind` says
    /// which.
    /// </summary>
    PresenceChanged = 52,
    /// <summary>
    /// A signalling transport stopped: reported failed or closed, bad
    /// stream bytes, or a keep-alive unanswered for ten seconds (RFC 5626
    /// §4.4.1). `payload.transport_failed` says why. Until
    /// `sipral_stack_transport_bind` restores it, requests get
    /// `SIPRAL_STATUS_TRANSPORT_DOWN`. `account`, `call`: none.
    /// </summary>
    TransportFailed = 53,
    /// <summary>
    /// A local conference changed: membership, talkers, or recording
    /// (`payload.local_conference`). `account`, `call`: none.
    /// </summary>
    LocalConferenceChanged = 54,
    /// <summary>
    /// A DNS lookup is wanted to locate an account's server (RFC 3263).
    /// Pass every answer, failures included, to `sipral_account_looked_up`.
    /// </summary>
    LookupWanted = 55,
    /// <summary>
    /// An account's server was located: `payload.locate.targets`, the
    /// address in use first.
    /// </summary>
    Located = 56,
    /// <summary>
    /// Locating an account's server failed; `retry_in_ms` says when it
    /// retries. An earlier address stays in use.
    /// </summary>
    LocateFailed = 57,
    /// <summary>
    /// A challenge was not answered because it came from outside the
    /// account's protection domain (RFC 3261 §22.1): an answer would feed
    /// an offline password guess. `payload.challenge` says who and why.
    /// </summary>
    ChallengeDeclined = 58,
    /// <summary>
    /// The account's server wants an OAuth 2.0 token (RFC 8898) and has
    /// none acceptable. Check `payload.token.authz_server` against trusted
    /// servers (§2.1.1), then pass a token to
    /// `sipral_account_set_access_token`.
    /// </summary>
    TokenRequired = 59,
    /// <summary>
    /// A `sipral_stack_network_test` finished; `payload.network_test`.
    /// </summary>
    NetworkTest = 60,
}

/// <summary>
/// Where a registration is. Names for `sipral_registration_event_t::state`.
/// </summary>
public enum SipralRegistrationState : uint
{
    /// <summary>
    /// The account is gone, or has never been asked about.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// Configured and not registered. Nothing has been sent.
    /// </summary>
    Idle = 1,
    /// <summary>
    /// A REGISTER is in flight and there is no binding yet.
    /// </summary>
    Registering = 2,
    /// <summary>
    /// The registrar holds a binding.
    /// </summary>
    Registered = 3,
    /// <summary>
    /// A refresh is in flight. The binding stands until it is answered.
    /// </summary>
    Refreshing = 4,
    /// <summary>
    /// Something recoverable went wrong and the next attempt is scheduled.
    /// </summary>
    Retrying = 5,
    /// <summary>
    /// The binding was given up on purpose.
    /// </summary>
    Unregistered = 6,
    /// <summary>
    /// The registrar refused in a way that trying again cannot fix.
    /// </summary>
    Failed = 7,
    /// <summary>
    /// A binding a registrar granted, over a transport since suspended or
    /// lost, which nothing has proved since.
    ///
    /// A monotonic clock does not advance while a machine sleeps, so after
    /// sleep every binding would otherwise look valid. Do not show the line
    /// as ready in this state.
    /// </summary>
    Unverified = 8,
    /// <summary>
    /// A binding read back from a snapshot rather than granted in this
    /// process. It has not been proved either.
    /// </summary>
    Restored = 9,
    /// <summary>
    /// The account has no registrar and never registers (a trunk that
    /// knows this end by address). `sipral_account_register` refuses it.
    /// </summary>
    NotRegistering = 10,
}

/// <summary>
/// Why a registration is not live. Names for
/// `sipral_registration_event_t::failure`.
/// </summary>
public enum SipralRegistrationFailure : uint
{
    /// <summary>
    /// Nothing failed.
    /// </summary>
    None = 0,
    /// <summary>
    /// The registrar refused, and will refuse the same request again.
    /// </summary>
    Rejected = 1,
    /// <summary>
    /// The password was wrong, or there was none to answer with.
    /// </summary>
    BadCredentials = 2,
    /// <summary>
    /// The registrar is not answering, or says it cannot serve this now.
    /// </summary>
    Unreachable = 3,
    /// <summary>
    /// The registrar moved. Following it needs an address, which is the
    /// caller's to resolve.
    /// </summary>
    Redirected = 4,
    /// <summary>
    /// The account's `Contact` is unreachable for the registrar (loopback
    /// or unspecified); nothing was sent. Fix with `sipral_account_rebind`.
    /// </summary>
    UnreachableContact = 5,
}

/// <summary>
/// Where a call is. Names for `sipral_call_event_t::state`, and what
/// `sipral_call_state` writes.
/// </summary>
public enum SipralCallState : uint
{
    /// <summary>
    /// The call is gone, or has never been asked about.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// The INVITE has gone and nothing has come back.
    /// </summary>
    Calling = 1,
    /// <summary>
    /// Somebody is calling and this end has not answered.
    /// </summary>
    Incoming = 2,
    /// <summary>
    /// The far end is ringing, or this end said it is.
    /// </summary>
    Ringing = 3,
    /// <summary>
    /// There is audio before anybody answered.
    /// </summary>
    EarlyMedia = 4,
    /// <summary>
    /// Up.
    /// </summary>
    Confirmed = 5,
    /// <summary>
    /// Up, in order to be transferred: the second leg of an attended transfer.
    /// </summary>
    Consulting = 6,
    /// <summary>
    /// A CANCEL or a BYE has gone and is not answered yet.
    /// </summary>
    Terminating = 7,
    /// <summary>
    /// Over.
    /// </summary>
    Terminated = 8,
}

/// <summary>
/// Why a call is over. Names for `sipral_call_event_t::end_reason`.
/// </summary>
public enum SipralCallEndReason : uint
{
    /// <summary>
    /// The call is not over.
    /// </summary>
    None = 0,
    /// <summary>
    /// This end hung up.
    /// </summary>
    LocalHangup = 1,
    /// <summary>
    /// The far end hung up.
    /// </summary>
    RemoteHangup = 2,
    /// <summary>
    /// The far end refused it: busy, declined, not found.
    /// </summary>
    Refused = 3,
    /// <summary>
    /// Given up before it was answered, from either end.
    /// </summary>
    Cancelled = 4,
    /// <summary>
    /// Nothing came back, or the transport died.
    /// </summary>
    Unreachable = 5,
    /// <summary>
    /// Another branch of the same fork was kept and this one was not.
    /// </summary>
    ForkLost = 6,
    /// <summary>
    /// The branch was still ringing when the answer window closed.
    /// </summary>
    Abandoned = 7,
    /// <summary>
    /// The session timer ran out and no refresh arrived.
    /// </summary>
    Expired = 8,
}

/// <summary>
/// Which way a digit arrived. Names for `sipral_media_event_t::source`.
/// </summary>
public enum SipralDigitSource : uint
{
    /// <summary>
    /// RFC 4733: a named telephone event in the RTP stream.
    /// </summary>
    Rtp = 0,
    /// <summary>
    /// RFC 3261's INFO method (RFC 6086), carrying `application/dtmf-relay`
    /// or `application/dtmf`.
    /// </summary>
    Info = 1,
    /// <summary>
    /// The two tones themselves, heard in the far end's audio, for
    /// SipralEventKind.InBandDigit.
    /// </summary>
    InBand = 2,
}

/// <summary>
/// What a SipralEventKind.Recovery reports, for
/// `payload.recovery.state`.
/// </summary>
public enum SipralRecoveryOutcome : uint
{
    /// <summary>
    /// Never written by this build.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// A registrar answered again: what was distrusted is proved.
    /// </summary>
    Running = 1,
    /// <summary>
    /// Every rung was climbed and none of them worked.
    /// </summary>
    GaveUp = 2,
}

/// <summary>
/// The last rung tried before giving up, for `payload.recovery.rung`.
/// </summary>
public enum SipralRecoveryRung : uint
{
    /// <summary>
    /// The ladder did not give up.
    /// </summary>
    None = 0,
    /// <summary>
    /// Nothing was believed any more, and nothing was sent.
    /// </summary>
    Distrust = 1,
    /// <summary>
    /// A REGISTER, and a re-SUBSCRIBE for what was demoted alongside it,
    /// went out or could not.
    /// </summary>
    Reregister = 2,
    /// <summary>
    /// The application was asked for a transport.
    /// </summary>
    WantTransport = 3,
    /// <summary>
    /// The application was asked for an address.
    /// </summary>
    WantAddress = 4,
}

/// <summary>
/// Why a recovery ladder gave up, for SipralEventKind.Recovery's
/// `payload.recovery.reason`.
/// </summary>
public enum SipralRecoveryFailure : uint
{
    /// <summary>
    /// The ladder did not give up.
    /// </summary>
    None = 0,
    /// <summary>
    /// Every REGISTER that could be sent was sent and none of them was
    /// answered.
    /// </summary>
    Unreachable = 1,
    /// <summary>
    /// A transport was asked for and the application did not bind one.
    /// </summary>
    NoTransport = 2,
    /// <summary>
    /// An address was asked for and the application did not supply one.
    /// </summary>
    Unresolved = 3,
}

/// <summary>
/// What kind of link the application is on: `from_link` and `to_link` on
/// sipral_stack_network_changed.
///
/// Only SipralLink.Down changes what is done. The rest makes a change
/// of kind over an unchanged address (a tunnel, Wi-Fi to cellular) visible.
/// </summary>
public enum SipralLink : uint
{
    /// <summary>
    /// There is no usable interface.
    /// </summary>
    Down = 0,
    /// <summary>
    /// Cable.
    /// </summary>
    Wired = 1,
    /// <summary>
    /// Wireless local network.
    /// </summary>
    Wifi = 2,
    /// <summary>
    /// A mobile network.
    /// </summary>
    Cellular = 3,
    /// <summary>
    /// A tunnel over one of the others.
    /// </summary>
    Tunnel = 4,
}

/// <summary>
/// What a change of network is worth doing about:
/// sipral_stack_network_changed's `out_recovery`. Returned directly, so
/// a laptop flipping access points gets SipralRecovery.Nothing without
/// reading an event or sending a REGISTER.
/// </summary>
public enum SipralRecovery : uint
{
    /// <summary>
    /// Never written by this build.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// Nothing this stack uses is different; nothing is done or sent.
    /// </summary>
    Nothing = 1,
    /// <summary>
    /// The address stands, so the transports do; what is upstream may not.
    /// </summary>
    Reregister = 2,
    /// <summary>
    /// A wake: the existing transport is tried first, a new one asked for
    /// only if it is dead. Started by sipral_stack_resumed, never
    /// returned here.
    /// </summary>
    Reprove = 3,
    /// <summary>
    /// The address is gone; the application must open a transport again.
    /// </summary>
    Rebuild = 4,
    /// <summary>
    /// Packets can leave and names cannot be turned into addresses.
    /// </summary>
    Resolve = 5,
    /// <summary>
    /// There is no interface. Nothing is tried until there is one.
    /// </summary>
    Detach = 6,
}

/// <summary>
/// What a stack does about a NAT in front of it. Names for
/// `sipral_stack_config_t::nat`. Zero means the built-in default, SipralNat.Off.
/// </summary>
public enum SipralNat : uint
{
    /// <summary>
    /// Ask nobody: every address written is the one the application gave.
    /// </summary>
    Off = 1,
    /// <summary>
    /// Ask `stun_server` where each socket appears from and write that instead.
    /// `SIPRAL_STATUS_NOT_SUPPORTED` without `SIPRAL_FEATURE_STUN`.
    /// </summary>
    Stun = 2,
}

/// <summary>
/// What a socket's mapping came to. Names for `sipral_nat_event_t::mapping`.
/// </summary>
public enum SipralNatMapping : uint
{
    /// <summary>
    /// The first answer: the socket appears at `public`.
    /// </summary>
    Learned = 1,
    /// <summary>
    /// A later answer named another address; `previous` is the old one. Signalling socket, or a
    /// media socket still waiting for its call.
    /// </summary>
    Moved = 2,
    /// <summary>
    /// No answer within five and a half seconds, or refused. The socket is described by its own
    /// address; a signalling socket asks again at its next refresh.
    /// </summary>
    Unanswered = 3,
}

/// <summary>
/// What a media socket's relay came to. Names for `sipral_nat_relay_event_t::outcome`.
/// </summary>
public enum SipralNatRelay : uint
{
    /// <summary>
    /// The relay exists at `relayed`; later calls on the socket offer it as an ICE candidate.
    /// </summary>
    Allocated = 1,
    /// <summary>
    /// No relay: refused (see `code`), no answer in 39.5 seconds, or allocation lost. Calls on
    /// the socket go without one.
    /// </summary>
    Failed = 2,
}

/// <summary>
/// What to do with a media socket's TURN connection. Names for
/// `sipral_turn_stream_event_t::state`.
/// </summary>
public enum SipralTurnStream : uint
{
    /// <summary>
    /// Open a connection from `local` to `server` over `protocol` (TLS verified by the
    /// platform), then call `sipral_stack_turn_connected`, or `sipral_stack_turn_closed` on failure. Calls
    /// on the socket before that answer `SIPRAL_STATUS_WRONG_STATE`.
    /// </summary>
    Open = 1,
    /// <summary>
    /// Nothing more will be written for `local`: flush `sipral_stack_poll_farewell` and
    /// `sipral_stack_poll_stun` for it, then close it.
    /// </summary>
    Close = 2,
}

/// <summary>
/// What happened to the STUN servers. Names for `sipral_stun_server_event_t::state`.
/// </summary>
public enum SipralStunServerState : uint
{
    /// <summary>
    /// Another server is in use now: failover, an earlier one answering again, or a new list.
    /// </summary>
    Changed = 1,
    /// <summary>
    /// Every server failed and is backing off; `server` is the last. Sockets keep what they
    /// learned. Said once until a server answers again.
    /// </summary>
    AllFailed = 2,
}

/// <summary>
/// Where a subscription is: `sipral_subscription_event_t::state` and
/// sipral_subscription_state's `out_state`.
/// </summary>
public enum SipralSubscriptionState : uint
{
    /// <summary>
    /// The handle names nothing: never minted here, or ended and let go.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// A SUBSCRIBE is on its way and nothing has answered it yet.
    /// </summary>
    Requesting = 1,
    /// <summary>
    /// The notifier has not decided (RFC 6665 §4.1.3 `pending`); nothing
    /// is known until SipralSubscriptionState.Active.
    /// </summary>
    Pending = 2,
    /// <summary>
    /// Granted, and notifications are arriving.
    /// </summary>
    Active = 3,
    /// <summary>
    /// Not live, and a fresh attempt is scheduled (§4.1.2.2: new
    /// `Call-ID` and `From` tag). The handle stays valid across both.
    /// </summary>
    Retrying = 4,
    /// <summary>
    /// Over, nothing more coming. The handle names nothing from here on.
    /// </summary>
    Ended = 5,
}

/// <summary>
/// Why a subscription is not live: `sipral_subscription_event_t::reason`.
///
/// Zero unless SipralSubscriptionState.Retrying or
/// SipralSubscriptionState.Ended. The first eight are the `reason` of
/// `Subscription-State: terminated` (RFC 6665 §4.1.3); the rest happened
/// here.
/// </summary>
public enum SipralSubscriptionEnd : uint
{
    /// <summary>
    /// Never written by this build.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// `deactivated`: the notifier wants it started again at once.
    /// </summary>
    Deactivated = 1,
    /// <summary>
    /// `probation`: started again, but not immediately.
    /// </summary>
    Probation = 2,
    /// <summary>
    /// `rejected`: the notifier will not serve it; do not ask again.
    /// </summary>
    Rejected = 3,
    /// <summary>
    /// `timeout`: it ran out rather than being refreshed.
    /// </summary>
    Timeout = 4,
    /// <summary>
    /// `giveup`: the notifier could not decide and stopped trying.
    /// </summary>
    GaveUp = 5,
    /// <summary>
    /// `noresource`: what was being watched does not exist any more.
    /// </summary>
    NoResource = 6,
    /// <summary>
    /// `invariant`: the watched thing cannot change.
    /// </summary>
    Invariant = 7,
    /// <summary>
    /// `terminated` with no reason parameter at all.
    /// </summary>
    Unstated = 8,
    /// <summary>
    /// This end gave it up with sipral_subscription_end. Wins over
    /// the notifier's closing reason.
    /// </summary>
    Unsubscribed = 9,
    /// <summary>
    /// The notifier answered 489: it does not know this event package.
    /// </summary>
    BadEvent = 10,
    /// <summary>
    /// Refused with a status a retry cannot fix.
    /// </summary>
    Refused = 11,
    /// <summary>
    /// Redirected; this stack does not follow redirects for SUBSCRIBE.
    /// </summary>
    Redirected = 12,
    /// <summary>
    /// Nothing answered: the notifier could not be reached at all.
    /// </summary>
    Unreachable = 13,
    /// <summary>
    /// Answered, but the first NOTIFY never came (§4.1.2.4's timer N,
    /// 64·T1).
    /// </summary>
    NoNotify = 14,
    /// <summary>
    /// What the notifier granted ran out with no refresh answered.
    /// </summary>
    Expired = 15,
}

/// <summary>
/// What one watched dialog is doing, and what a lamp shows:
/// `sipral_watched_dialog_t::phase` and sipral_subscription_lamp's
/// `out_phase`. RFC 4235 §3.7.1's states, ranked as §3.7.2 ranks them.
/// </summary>
public enum SipralDialogPhase : uint
{
    /// <summary>
    /// No dialog, or all terminated: an idle lamp.
    /// </summary>
    Idle = 0,
    /// <summary>
    /// A request went out and nothing has answered.
    /// </summary>
    Trying = 1,
    /// <summary>
    /// Something answered without ringing yet.
    /// </summary>
    Proceeding = 2,
    /// <summary>
    /// Ringing.
    /// </summary>
    Early = 3,
    /// <summary>
    /// A call is up.
    /// </summary>
    Confirmed = 4,
    /// <summary>
    /// This dialog is over. Never sipral_subscription_lamp's answer,
    /// which is SipralDialogPhase.Idle then.
    /// </summary>
    Terminated = 5,
    /// <summary>
    /// The notifier named a state this build has no number for.
    /// </summary>
    Unknown = 6,
}

/// <summary>
/// Which end started a watched dialog: `sipral_watched_dialog_t::direction`.
/// </summary>
public enum SipralDialogDirection : uint
{
    /// <summary>
    /// The notifier did not say.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// The watched end placed the call.
    /// </summary>
    Locally = 1,
    /// <summary>
    /// The watched end was called.
    /// </summary>
    Remotely = 2,
}

/// <summary>
/// How a watched dialog ended: `sipral_watched_dialog_t::ended`, zero
/// while it has not.
/// </summary>
public enum SipralDialogEnded : uint
{
    /// <summary>
    /// It has not ended, or the notifier did not say how.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// The caller gave up before it was answered.
    /// </summary>
    Cancelled = 1,
    /// <summary>
    /// The called end refused it.
    /// </summary>
    Rejected = 2,
    /// <summary>
    /// A `Replaces` took it over.
    /// </summary>
    Replaced = 3,
    /// <summary>
    /// The watched end hung up.
    /// </summary>
    LocalBye = 4,
    /// <summary>
    /// The far end hung up.
    /// </summary>
    RemoteBye = 5,
    /// <summary>
    /// Something went wrong with it.
    /// </summary>
    Error = 6,
    /// <summary>
    /// Nothing answered in time.
    /// </summary>
    Timeout = 7,
}

/// <summary>
/// Which text sipral_subscription_dialog_text reads. Each is what the
/// notifier wrote, unparsed.
/// </summary>
public enum SipralDialogText : uint
{
    /// <summary>
    /// Never asked for.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// The notifier's own id for this dialog.
    /// </summary>
    Id = 1,
    /// <summary>
    /// The dialog's `Call-ID`, when the notifier sent one.
    /// </summary>
    CallId = 2,
    /// <summary>
    /// Who the watched end is, as a URI.
    /// </summary>
    LocalIdentity = 3,
    /// <summary>
    /// And the display name beside it.
    /// </summary>
    LocalDisplay = 4,
    /// <summary>
    /// Who the other end is, as a URI: what a lamp shows when ringing.
    /// </summary>
    RemoteIdentity = 5,
    /// <summary>
    /// And the display name beside it.
    /// </summary>
    RemoteDisplay = 6,
    /// <summary>
    /// Where requests for the watched end would be sent.
    /// </summary>
    LocalTarget = 7,
    /// <summary>
    /// And for the other end.
    /// </summary>
    RemoteTarget = 8,
}

/// <summary>
/// Who pumps a stack's audio: `sipral_stack_config_t::audio`.
///
/// Zero is application mode, so a configuration written against an
/// earlier header keeps pumping its own frames.
/// </summary>
public enum SipralAudio : uint
{
    /// <summary>
    /// The application opens the devices and pumps frames through
    /// `sipral_media_capture` and `sipral_media_playback`.
    /// </summary>
    Application = 0,
    /// <summary>
    /// The library opens the devices and pumps every managed call; the
    /// packets reach the application through `audio_transmit_callback`.
    /// `SIPRAL_STATUS_NOT_SUPPORTED` without a backend for the platform,
    /// as `SIPRAL_FEATURE_AUDIO_DEVICE` says.
    /// </summary>
    Device = 1,
}

/// <summary>
/// When the devices are opened, in device mode:
/// `sipral_stack_config_t::audio_activation`.
/// </summary>
public enum SipralAudioActivation : uint
{
    /// <summary>
    /// With the first managed call's media or ring; closed with the last.
    /// </summary>
    Automatic = 0,
    /// <summary>
    /// Only between `sipral_audio_activate` and `sipral_audio_deactivate`:
    /// for CallKit and the telecom framework, which own the audio session.
    /// </summary>
    Manual = 1,
}

/// <summary>
/// What a device is used for.
/// </summary>
public enum SipralAudioRole : uint
{
    /// <summary>
    /// The call's microphone.
    /// </summary>
    Microphone = 1,
    /// <summary>
    /// The call's loudspeaker or earpiece.
    /// </summary>
    Speaker = 2,
    /// <summary>
    /// Where an incoming call is announced, which may differ from where
    /// it is answered.
    /// </summary>
    Ringer = 3,
}

/// <summary>
/// Which way audio flows, for gain, mute and the meter.
/// </summary>
public enum SipralAudioDirection : uint
{
    /// <summary>
    /// From the microphone. Its gain is the microphone gain.
    /// </summary>
    Input = 1,
    /// <summary>
    /// To the loudspeaker. Its gain is the volume.
    /// </summary>
    Output = 2,
}

/// <summary>
/// What changed, on `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED`.
/// </summary>
public enum SipralAudioChange : uint
{
    /// <summary>
    /// A device arrived or left. Every valid id stays valid: a device
    /// that left keeps its row, marked absent.
    /// </summary>
    ListChanged = 1,
    /// <summary>
    /// The system's default for `direction` moved. A role on a chosen
    /// device stays; one on the system's route follows with
    /// `SIPRAL_AUDIO_CHANGE_REOPENED`.
    /// </summary>
    DefaultChanged = 2,
    /// <summary>
    /// `role` is on `device` because `sipral_audio_select` said so.
    /// </summary>
    Selected = 3,
    /// <summary>
    /// The device `role` ran on went away; the reopen is reported apart.
    /// </summary>
    Lost = 4,
    /// <summary>
    /// `role` is running on `device` again.
    /// </summary>
    Reopened = 5,
    /// <summary>
    /// `role` could not be opened on anything; that direction is
    /// silence until a device arrives.
    /// </summary>
    Unavailable = 6,
}

/// <summary>
/// Who made a change. An application must not answer either by
/// re-applying its own choice.
/// </summary>
public enum SipralAudioOrigin : uint
{
    /// <summary>
    /// The operating system, or a person at a socket.
    /// </summary>
    System = 1,
    /// <summary>
    /// The engine.
    /// </summary>
    Engine = 2,
}

/// <summary>
/// The verdict a terminating network reached on the caller's number
/// (3GPP TS 24.229's `verstat`, the mark STIR/SHAKEN leaves). Names for
/// `sipral_call_event_t::verstat`.
/// </summary>
public enum SipralVerstat : uint
{
    /// <summary>
    /// Nothing said, or said by a peer the account does not trust.
    /// </summary>
    None = 0,
    /// <summary>
    /// `TN-Validation-Passed`.
    /// </summary>
    Passed = 1,
    /// <summary>
    /// `TN-Validation-Failed`.
    /// </summary>
    Failed = 2,
    /// <summary>
    /// `No-TN-Validation`.
    /// </summary>
    NotValidated = 3,
    /// <summary>
    /// Some other value.
    /// </summary>
    Other = 4,
}

/// <summary>
/// `Answer-Mode` and `Priv-Answer-Mode` (RFC 5373 §3). Names for
/// `sipral_call_event_t::answer_mode` and `priv_answer_mode`.
/// </summary>
public enum SipralAnswerMode : uint
{
    /// <summary>
    /// The INVITE carried no such field.
    /// </summary>
    None = 0,
    /// <summary>
    /// `Manual`: wait for the user.
    /// </summary>
    Manual = 1,
    /// <summary>
    /// `Auto`: answer without waiting for the user.
    /// </summary>
    Auto = 2,
    /// <summary>
    /// Any other value, which RFC 5373 has ignored.
    /// </summary>
    Other = 3,
}

/// <summary>
/// Where the ring says the caller is. Names for
/// `sipral_call_event_t::ring_source`.
/// </summary>
public enum SipralRingSource : uint
{
    /// <summary>
    /// Nothing said.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// Another extension of the same switch.
    /// </summary>
    Internal = 1,
    /// <summary>
    /// The outside world.
    /// </summary>
    External = 2,
}

/// <summary>
/// Which list, and which piece of each entry, sipral_call_identity_count
/// and sipral_call_identity_text are asked about.
/// </summary>
public enum SipralIdentityText : uint
{
    /// <summary>
    /// Never asked for.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// `P-Asserted-Identity`: the URI of each asserted party.
    /// </summary>
    Asserted = 1,
    /// <summary>
    /// And each one's display name.
    /// </summary>
    AssertedDisplay = 2,
    /// <summary>
    /// `Remote-Party-ID`: the URI of each party named.
    /// </summary>
    RemoteParty = 3,
    /// <summary>
    /// And each one's display name.
    /// </summary>
    RemotePartyDisplay = 4,
    /// <summary>
    /// `Diversion`, most recent first: who the call was diverted from.
    /// </summary>
    Diversion = 5,
    /// <summary>
    /// And the display name beside it.
    /// </summary>
    DiversionDisplay = 6,
    /// <summary>
    /// And why: `no-answer`, `user-busy`, `unconditional` and the rest.
    /// </summary>
    DiversionReason = 7,
    /// <summary>
    /// `History-Info`: the URI of each target the request was sent to.
    /// </summary>
    History = 8,
    /// <summary>
    /// And each entry's `index`.
    /// </summary>
    HistoryIndex = 9,
    /// <summary>
    /// Every `Alert-Info` URI.
    /// </summary>
    AlertInfo = 10,
    /// <summary>
    /// Every `info=` value on `Alert-Info`.
    /// </summary>
    AlertName = 11,
    /// <summary>
    /// The canonical calling number a valid PASSporT was found for
    /// (RFC 8224 §6.2): one entry, or none. ABI 0.31.
    /// </summary>
    VerifiedOrig = 12,
    /// <summary>
    /// Its origination identifier (RFC 8588 §5), a UUID.
    /// </summary>
    VerifiedOrigid = 13,
    /// <summary>
    /// The URL of the certificate it was verified against, or that could
    /// not be had.
    /// </summary>
    VerificationCertificate = 14,
    /// <summary>
    /// Why it did not verify, in words, for a log.
    /// </summary>
    VerificationDetail = 15,
}

/// <summary>
/// How an account's calls ask for a session timer (RFC 4028). Names for
/// `sipral_account_config_t::session_timer`.
/// </summary>
public enum SipralSessionTimer : uint
{
    /// <summary>
    /// The stack's default: thirty minutes, RFC 4028 §4's recommendation.
    /// </summary>
    Default = 0,
    /// <summary>
    /// Ask for none. A far end that insists on one is still honoured.
    /// </summary>
    Off = 1,
    /// <summary>
    /// Ask for `session_interval_seconds`, at least 90 (§5's floor).
    /// </summary>
    Interval = 2,
}

/// <summary>
/// Log verbosity, for sipral_stack_log and SipralLogRecord.Level.
/// Each level includes the ones below it.
/// </summary>
public enum SipralLogLevel : uint
{
    /// <summary>
    /// The log is off; the initial state.
    /// </summary>
    Off = 0,
    /// <summary>
    /// A failure the application is likely to notice.
    /// </summary>
    Error = 1,
    /// <summary>
    /// Something worked around or about to matter: a registration
    /// refused, audio that stopped arriving.
    /// </summary>
    Warn = 2,
    /// <summary>
    /// Operator-level: registrations, calls arriving, confirmed or ending,
    /// media starting.
    /// </summary>
    Info = 3,
    /// <summary>
    /// Every event raised, every diagnostic decision, every refused ABI call.
    /// </summary>
    Debug = 4,
    /// <summary>
    /// Every SIP message in and out, whole and redacted.
    /// </summary>
    Trace = 5,
}

/// <summary>
/// How a stream's SRTP keys were exchanged
/// (`sipral_stream_encryption_t::key_exchange`, `sipral_media_event_t::key_exchange`).
/// </summary>
public enum SipralKeyExchange : uint
{
    /// <summary>
    /// None: the stream is not encrypted, or the event is not about one.
    /// </summary>
    None = 0,
    /// <summary>
    /// In the SDP (RFC 4568 `a=crypto`): as protected as the signalling.
    /// </summary>
    Sdes = 1,
    /// <summary>
    /// DTLS on the media path (RFC 5764), checked against the signalled
    /// fingerprint.
    /// </summary>
    Dtls = 2,
}

/// <summary>
/// What a stream carries. Names for `sipral_stream_encryption_t::media`.
/// </summary>
public enum SipralMediaKind : uint
{
    /// <summary>
    /// Something this ABI has no word for.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// `m=audio`.
    /// </summary>
    Audio = 1,
}

/// <summary>
/// What an account does with incoming `Identity` header fields
/// (RFC 8224 §6.2). Values of `sipral_account_config_t::stir_verification`.
/// </summary>
public enum SipralStirVerification : uint
{
    /// <summary>
    /// This build's default, which is `REPORT`.
    /// </summary>
    Default = 0,
    /// <summary>
    /// Verify nothing.
    /// </summary>
    Off = 1,
    /// <summary>
    /// Verify, report the verdict, deliver every call. Active only once
    /// the stack has trust anchors (`sipral_stack_stir`).
    /// </summary>
    Report = 2,
    /// <summary>
    /// Verify and refuse what does not verify (RFC 8224 §6.2.2): 428 no
    /// `Identity`, 436 certificate unavailable, 437 untrusted, 438 bad
    /// signature, 403 "Stale Date". Active even with no anchors, where
    /// nothing verifies.
    /// </summary>
    Strict = 3,
}

/// <summary>
/// SHAKEN attestation level (RFC 8588 §4), for
/// `sipral_account_config_t::stir_attestation` and the verdict fields.
/// </summary>
public enum SipralAttestation : uint
{
    /// <summary>
    /// None said: on an account, full attestation; on a verdict, a
    /// PASSporT with no SHAKEN claims, or no valid one.
    /// </summary>
    None = 0,
    /// <summary>
    /// Full: the signer knows the caller and that the number is theirs.
    /// </summary>
    A = 1,
    /// <summary>
    /// Partial: the signer knows the caller, not the number.
    /// </summary>
    B = 2,
    /// <summary>
    /// Gateway: the signer knows only where the call entered its network.
    /// </summary>
    C = 3,
}

/// <summary>
/// What a verification came to (`sipral_verification_event_t::outcome`,
/// `sipral_call_event_t::verification`).
/// </summary>
public enum SipralVerificationOutcome : uint
{
    /// <summary>
    /// Nothing verified: the account does not verify, or no anchors.
    /// </summary>
    None = 0,
    /// <summary>
    /// Signed by a certificate with authority over the calling number,
    /// fresh, for the numbers the request names.
    /// </summary>
    Valid = 1,
    /// <summary>
    /// One was there and does not hold: `failure` says why.
    /// </summary>
    Invalid = 2,
    /// <summary>
    /// Nothing to verify: no `Identity`, or only unsupported extensions.
    /// </summary>
    Absent = 3,
}

/// <summary>
/// Why a verification did not hold (`sipral_verification_event_t::failure`,
/// `sipral_call_event_t::verification_failure`).
/// </summary>
public enum SipralVerificationFailure : uint
{
    /// <summary>
    /// Nothing failed.
    /// </summary>
    None = 0,
    /// <summary>
    /// No `Identity` header field.
    /// </summary>
    NoIdentity = 1,
    /// <summary>
    /// Only ones naming a `ppt` this end does not support.
    /// </summary>
    UnsupportedPpt = 2,
    /// <summary>
    /// The header field or its PASSporT is not well formed.
    /// </summary>
    Malformed = 3,
    /// <summary>
    /// Signed with an algorithm other than ES256.
    /// </summary>
    UnsupportedAlgorithm = 4,
    /// <summary>
    /// `iat` outside the freshness window.
    /// </summary>
    Stale = 5,
    /// <summary>
    /// The certificate could not be fetched, or did not arrive in time.
    /// </summary>
    CertificateUnavailable = 6,
    /// <summary>
    /// What the `info` URL yielded is not a chain this end can read.
    /// </summary>
    CertificateUnreadable = 7,
    /// <summary>
    /// The chain leads to no trust anchor.
    /// </summary>
    Untrusted = 8,
    /// <summary>
    /// A certificate in it is outside its validity period.
    /// </summary>
    Expired = 9,
    /// <summary>
    /// The chain breaks a rule of path validation.
    /// </summary>
    InvalidChain = 10,
    /// <summary>
    /// The signature does not verify.
    /// </summary>
    BadSignature = 11,
    /// <summary>
    /// The certificate has no authority over the calling number.
    /// </summary>
    NumberNotCovered = 12,
    /// <summary>
    /// Signed for another calling number than the request names.
    /// </summary>
    OrigMismatch = 13,
    /// <summary>
    /// Signed for another called number.
    /// </summary>
    DestMismatch = 14,
}

/// <summary>
/// Which half of a verification an event reports
/// (`sipral_verification_event_t::stage`).
/// </summary>
public enum SipralVerificationStage : uint
{
    /// <summary>
    /// Never sent.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// Fetch the certificate at `certificate_url` and pass it to
    /// `sipral_call_stir_certificate` (or nothing, if unavailable). The
    /// call waits unannounced until then or `certificate_wait_ms`.
    /// </summary>
    CertificateWanted = 1,
    /// <summary>
    /// The verdict. `SIPRAL_EVENT_KIND_INCOMING_CALL` follows, or
    /// `SIPRAL_EVENT_KIND_CALL_ENDED` when `refused` is set.
    /// </summary>
    Verified = 2,
}

/// <summary>
/// What a SipralEventKind.ProgressDetected heard. Names for
/// `sipral_progress_event_t::what`.
/// </summary>
public enum SipralProgressKind : uint
{
    /// <summary>
    /// Never written by this build.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// A call-progress tone: `tone`, and `at_ms` when its first burst began.
    /// </summary>
    Tone = 1,
    /// <summary>
    /// The special information tone (the call failed): `sit_hz_*` and
    /// `sit_ms_*` as measured, `at_ms` when the first began.
    /// </summary>
    SpecialInformation = 2,
    /// <summary>
    /// Who answered: `verdict`, `reason`, `at_ms` after answer,
    /// `initial_silence_ms`, `greeting_ms` and `words`.
    /// </summary>
    AnsweredBy = 3,
    /// <summary>
    /// A machine's record beep: `frequency_hz`, `length_ms`, and `at_ms`
    /// when it ended, after answer.
    /// </summary>
    Beep = 4,
}

/// <summary>
/// A call-progress tone. Names for `sipral_progress_event_t::tone`.
/// </summary>
public enum SipralProgressTone : uint
{
    /// <summary>
    /// Not a tone, or one this build has no name for.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// The exchange is ready for digits.
    /// </summary>
    Dial = 1,
    /// <summary>
    /// The far end is being alerted.
    /// </summary>
    Ringback = 2,
    /// <summary>
    /// The far end is busy.
    /// </summary>
    Busy = 3,
    /// <summary>
    /// The network is congested: congestion, or reorder.
    /// </summary>
    Congestion = 4,
    /// <summary>
    /// A second call is waiting.
    /// </summary>
    CallWaiting = 5,
    /// <summary>
    /// The special information tone.
    /// </summary>
    SpecialInformation = 6,
}

/// <summary>
/// Who answered. Names for `sipral_progress_event_t::verdict`.
/// </summary>
public enum SipralAmdVerdict : uint
{
    /// <summary>
    /// Not a verdict.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// A person.
    /// </summary>
    Human = 1,
    /// <summary>
    /// An answering machine or a voice mailbox.
    /// </summary>
    Machine = 2,
    /// <summary>
    /// The evidence does not say.
    /// </summary>
    NotSure = 3,
}

/// <summary>
/// Which rule decided who answered. Names for
/// `sipral_progress_event_t::reason`.
/// </summary>
public enum SipralAmdReason : uint
{
    /// <summary>
    /// Not a verdict.
    /// </summary>
    None = 0,
    /// <summary>
    /// A short greeting, then silence: somebody said hello and waits.
    /// </summary>
    ShortGreeting = 1,
    /// <summary>
    /// More words than a person answers with.
    /// </summary>
    TooManyWords = 2,
    /// <summary>
    /// A greeting longer than a person gives.
    /// </summary>
    LongGreeting = 3,
    /// <summary>
    /// Nobody spoke.
    /// </summary>
    InitialSilence = 4,
    /// <summary>
    /// No rule decided in the time allowed.
    /// </summary>
    Timeout = 5,
}

/// <summary>
/// When a call listens for keypad digits in the far end's audio. Names
/// for `sipral_stack_config_t::dtmf_detection` and
/// sipral_call_dtmf_detection's `mode`.
/// </summary>
public enum SipralDtmfDetection : uint
{
    /// <summary>
    /// Only when no telephone event was negotiated, since the far end
    /// then has no other way to send a digit.
    /// </summary>
    Auto = 0,
    /// <summary>
    /// Never. Digits arrive only as RFC 4733 events or by INFO.
    /// </summary>
    Off = 1,
    /// <summary>
    /// On every call. A press the far end sends both as an event and in
    /// the audio is reported once, as the event.
    /// </summary>
    Always = 2,
}

/// <summary>
/// Whose call-progress tones to listen for. Names for
/// `sipral_progress_config_t::region`.
/// </summary>
public enum SipralToneRegion : uint
{
    /// <summary>
    /// The 425 Hz tones common to the CEPT administrations.
    /// </summary>
    Europe = 0,
    /// <summary>
    /// The United States and Canada.
    /// </summary>
    NorthAmerica = 1,
    /// <summary>
    /// The United Kingdom.
    /// </summary>
    UnitedKingdom = 2,
}

/// <summary>
/// The file format of a recording. Names for
/// `sipral_recording_options_t::format`.
/// </summary>
public enum SipralRecordingFormat : uint
{
    /// <summary>
    /// Sixteen-bit PCM in RIFF/WAVE, becoming RF64 past four gibibytes.
    /// </summary>
    Wav = 0,
    /// <summary>
    /// Opus in Ogg (RFC 7845), where `SIPRAL_FEATURE_OPUS` says the build
    /// has the encoder; `SIPRAL_STATUS_NOT_SUPPORTED` where it does not.
    /// </summary>
    OggOpus = 1,
}

/// <summary>
/// How the two directions of a call share a recording. Names for
/// `sipral_recording_options_t::layout`.
/// </summary>
public enum SipralRecordingLayout : uint
{
    /// <summary>
    /// One channel: both directions, each at half level, summed.
    /// </summary>
    Mixed = 0,
    /// <summary>
    /// Two channels: this end on the left, the far end on the right.
    /// </summary>
    Stereo = 1,
}

/// <summary>
/// What one conference document did. Names for
/// `sipral_conference_event_t::update`.
/// </summary>
public enum SipralConferenceUpdate : uint
{
    /// <summary>
    /// Never written by this build.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// It was merged into the picture.
    /// </summary>
    Applied = 1,
    /// <summary>
    /// Deleted by the focus; the subscription ends (RFC 4575 §4.6).
    /// </summary>
    Ended = 2,
}

/// <summary>
/// Where one endpoint of a conference is (RFC 4575 §5.7.2). Names for
/// `sipral_conference_user_t::status`.
/// </summary>
public enum SipralEndpointStatus : uint
{
    /// <summary>
    /// Absent or not in the schema.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// `pending`: waiting for policy or for the focus.
    /// </summary>
    Pending = 1,
    /// <summary>
    /// `dialing-out`: the focus is calling it.
    /// </summary>
    DialingOut = 2,
    /// <summary>
    /// `dialing-in`: it is calling the focus.
    /// </summary>
    DialingIn = 3,
    /// <summary>
    /// `alerting`: it is ringing.
    /// </summary>
    Alerting = 4,
    /// <summary>
    /// `on-hold`.
    /// </summary>
    OnHold = 5,
    /// <summary>
    /// `connected`: it is in the conference.
    /// </summary>
    Connected = 6,
    /// <summary>
    /// `muted-via-focus`: in, and muted by the focus.
    /// </summary>
    MutedViaFocus = 7,
    /// <summary>
    /// `disconnecting`.
    /// </summary>
    Disconnecting = 8,
    /// <summary>
    /// `disconnected`: it has left.
    /// </summary>
    Disconnected = 9,
}

/// <summary>
/// Which text sipral_subscription_conference_text reads, as the focus
/// wrote it. The first three ignore `index`; the rest are about that user.
/// </summary>
public enum SipralConferenceText : uint
{
    /// <summary>
    /// Never asked for.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// The conference's URI, the `entity` of `conference-info`.
    /// </summary>
    Entity = 1,
    /// <summary>
    /// Its `subject`.
    /// </summary>
    Subject = 2,
    /// <summary>
    /// Its `display-text`.
    /// </summary>
    DisplayText = 3,
    /// <summary>
    /// A user's `entity`: the address of record it takes part as.
    /// </summary>
    UserEntity = 4,
    /// <summary>
    /// A user's `display-text`.
    /// </summary>
    UserDisplayText = 5,
    /// <summary>
    /// The `entity` of a user's first endpoint: the device it is on.
    /// </summary>
    UserEndpoint = 6,
}

/// <summary>
/// What a SipralEventKind.PresenceChanged is about.
/// Names for `sipral_presence_event_t::kind`.
/// </summary>
public enum SipralPresenceKind : uint
{
    /// <summary>
    /// Never written by this build.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// A `presence` subscription was told about the presentity.
    /// </summary>
    Watched = 1,
    /// <summary>
    /// This account's own published presence moved.
    /// </summary>
    Publication = 2,
}

/// <summary>
/// PIDF's `basic` (RFC 3863 §4.1.4). Names for `sipral_presence_t::basic`
/// and `sipral_presence_event_t::basic`.
/// </summary>
public enum SipralBasic : uint
{
    /// <summary>
    /// Not said. A document published with this is refused, since
    /// §4.1.3 wants one.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// Reachable.
    /// </summary>
    Open = 1,
    /// <summary>
    /// Not reachable.
    /// </summary>
    Closed = 2,
}

/// <summary>
/// What the person behind a presentity is doing: the RPID activities
/// (RFC 4480 §3.2) phones show. Names for `sipral_presence_t::activity`
/// and `sipral_presence_event_t::activity`.
/// </summary>
public enum SipralActivity : uint
{
    /// <summary>
    /// None said. Published, the document carries no person at all.
    /// </summary>
    None = 0,
    /// <summary>
    /// `away`.
    /// </summary>
    Away = 1,
    /// <summary>
    /// `busy`.
    /// </summary>
    Busy = 2,
    /// <summary>
    /// `on-the-phone`.
    /// </summary>
    OnThePhone = 3,
    /// <summary>
    /// `meeting`.
    /// </summary>
    Meeting = 4,
    /// <summary>
    /// `vacation`.
    /// </summary>
    Vacation = 5,
    /// <summary>
    /// Another activity, which this ABI has no number for.
    /// </summary>
    Other = 6,
}

/// <summary>
/// What became of this account's published presence. Names for
/// `sipral_presence_event_t::publication_state`.
/// </summary>
public enum SipralPublicationState : uint
{
    /// <summary>
    /// Not a publication event.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// The compositor holds it: published, modified or refreshed.
    /// </summary>
    Published = 1,
    /// <summary>
    /// It was taken away (`sipral_account_unpublish_presence`).
    /// </summary>
    Removed = 2,
    /// <summary>
    /// Its lifetime ran out with no refresh; the next publish starts it
    /// afresh.
    /// </summary>
    Expired = 3,
    /// <summary>
    /// The compositor refused, or never answered.
    /// </summary>
    Failed = 4,
}

/// <summary>
/// Why a publication failed. Names for `sipral_presence_event_t::failure`.
/// </summary>
public enum SipralPublishFailure : uint
{
    /// <summary>
    /// Nothing failed.
    /// </summary>
    None = 0,
    /// <summary>
    /// 489: the compositor does not know the `presence` package. Nothing
    /// more is sent.
    /// </summary>
    BadEvent = 1,
    /// <summary>
    /// 423 with no `Min-Expires` this stack could meet.
    /// </summary>
    IntervalTooBrief = 2,
    /// <summary>
    /// A 2xx without the `SIP-ETag` every one must carry.
    /// </summary>
    NoEntityTag = 3,
    /// <summary>
    /// Any other refusal, a challenge nothing could answer among them;
    /// `status_code` says which.
    /// </summary>
    Refused = 4,
    /// <summary>
    /// No answer at all.
    /// </summary>
    Unreachable = 5,
}

/// <summary>
/// What a `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED` reports
/// (`sipral_local_conference_event_t::change`).
/// </summary>
public enum SipralLocalConferenceChange : uint
{
    /// <summary>
    /// Never written by this build.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// `member` joined (a call, or this end at creation).
    /// </summary>
    Joined = 1,
    /// <summary>
    /// `member` left, for the reason `departure` gives.
    /// </summary>
    Left = 2,
    /// <summary>
    /// The talkers changed: see `talkers`, `loudest` and
    /// `sipral_local_conference_talker_at`.
    /// </summary>
    Talkers = 3,
    /// <summary>
    /// The recording stopped because the file refused a write; it holds
    /// audio up to its last checkpoint.
    /// </summary>
    RecordingStopped = 4,
}

/// <summary>
/// Why a member left (`sipral_local_conference_event_t::departure`).
/// </summary>
public enum SipralDeparture : uint
{
    /// <summary>
    /// Nobody left.
    /// </summary>
    None = 0,
    /// <summary>
    /// `sipral_local_conference_remove` took it out.
    /// </summary>
    Removed = 1,
    /// <summary>
    /// Its call's media ended.
    /// </summary>
    Ended = 2,
    /// <summary>
    /// Its call moved to a codec the conference cannot mix.
    /// </summary>
    Incompatible = 3,
}

/// <summary>
/// Which kind of DNS record a lookup asks for. Names for
/// `sipral_locate_event_t::record` and `sipral_account_looked_up`'s
/// `record`.
/// </summary>
public enum SipralDnsRecordType : uint
{
    /// <summary>
    /// Not a lookup: the value on a `SIPRAL_EVENT_KIND_LOCATED` or a
    /// `SIPRAL_EVENT_KIND_LOCATE_FAILED`.
    /// </summary>
    None = 0,
    /// <summary>
    /// RFC 3403: which services a domain offers, and under which names.
    /// </summary>
    Naptr = 1,
    /// <summary>
    /// RFC 2782: which hosts, at which ports, serve one service.
    /// </summary>
    Srv = 2,
    /// <summary>
    /// An IPv4 address.
    /// </summary>
    A = 3,
    /// <summary>
    /// An IPv6 address.
    /// </summary>
    Aaaa = 4,
}

/// <summary>
/// What the application's resolver said to a lookup. Names for
/// `sipral_account_looked_up`'s `answer`.
/// </summary>
public enum SipralDnsAnswer : uint
{
    /// <summary>
    /// The records it returned, in `records`. None at all reads as
    /// `SIPRAL_DNS_ANSWER_NOTHING`.
    /// </summary>
    Records = 1,
    /// <summary>
    /// No record of that kind, or no such name. Also the answer from a
    /// resolver that cannot ask for that kind (NAPTR, SRV).
    /// </summary>
    Nothing = 2,
    /// <summary>
    /// The resolver could not answer: no server reachable, a timeout, a
    /// server failure.
    /// </summary>
    Failed = 3,
}

/// <summary>
/// Why a lookup of an account's server named no address. Names for
/// `sipral_locate_event_t::failure`.
/// </summary>
public enum SipralLocateFailure : uint
{
    /// <summary>
    /// Nothing failed.
    /// </summary>
    None = 0,
    /// <summary>
    /// The DNS named no reachable address: no record, or an SRV target
    /// of `.`.
    /// </summary>
    NotFound = 1,
    /// <summary>
    /// The resolver failed on every lookup that could give an address.
    /// </summary>
    Unanswered = 2,
    /// <summary>
    /// The transport has no RFC 3263 procedure (WebSocket); only a
    /// numeric host or a host with a port works.
    /// </summary>
    Unsupported = 3,
}

/// <summary>
/// Why an account's password did not answer a challenge. Names for
/// `sipral_challenge_event_t::refusal`.
/// </summary>
public enum SipralChallengeRefusal : uint
{
    /// <summary>
    /// Never written by this build.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// The challenge came from beyond the account's own server.
    /// </summary>
    NotTheAccountsServer = 1,
    /// <summary>
    /// The account's server asked for a realm not the account's (e.g. a
    /// proxy relaying a far end's challenge).
    /// </summary>
    NotTheAccountsRealm = 2,
}

/// <summary>
/// What the server said was wrong with the token (RFC 6750 §3.1).
/// </summary>
public enum SipralTokenError : uint
{
    /// <summary>
    /// The server named no error: no token was offered yet.
    /// </summary>
    None = 0,
    /// <summary>
    /// `invalid_request`: the request was malformed.
    /// </summary>
    InvalidRequest = 1,
    /// <summary>
    /// `invalid_token`: the token is expired, revoked, malformed or
    /// otherwise invalid. A new one is needed.
    /// </summary>
    InvalidToken = 2,
    /// <summary>
    /// `insufficient_scope`: the token does not cover what was asked;
    /// `scope` says what would.
    /// </summary>
    InsufficientScope = 3,
    /// <summary>
    /// `invalid_scope`.
    /// </summary>
    InvalidScope = 4,
    /// <summary>
    /// Another code, as written in `error_code`.
    /// </summary>
    Other = 5,
}

/// <summary>
/// What a network test, or one part of it, comes to. Names for
/// `sipral_network_test_event_t::verdict` and `echo_verdict`.
/// </summary>
public enum SipralNetworkVerdict : uint
{
    /// <summary>
    /// Nothing was tested.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// Calls should work and sound right.
    /// </summary>
    Good = 1,
    /// <summary>
    /// Calls should work, perhaps not everywhere or at best quality.
    /// </summary>
    Acceptable = 2,
    /// <summary>
    /// Calls are likely to fail or to sound bad.
    /// </summary>
    Poor = 3,
}

/// <summary>
/// Whether a part of a network test was tried, and how it went. Names
/// for `sipral_network_test_event_t::stun`, `turn` and `echo`.
/// </summary>
public enum SipralNetworkProbe : uint
{
    /// <summary>
    /// Not part of this test.
    /// </summary>
    NotTested = 0,
    /// <summary>
    /// The server answered; for the echo, audio came back and was measured.
    /// </summary>
    Succeeded = 1,
    /// <summary>
    /// It did not.
    /// </summary>
    Failed = 2,
}

/// <summary>
/// What a STUN answer says about the NAT in front of this end. Names for
/// `sipral_network_test_event_t::nat`. Approximate: says nothing about
/// filtering (RFC 4787).
/// </summary>
public enum SipralNatKind : uint
{
    /// <summary>
    /// No answer to read.
    /// </summary>
    Unknown = 0,
    /// <summary>
    /// No translation: the server saw the socket's own address.
    /// </summary>
    Open = 1,
    /// <summary>
    /// The address was translated and the port kept.
    /// </summary>
    PortPreserved = 2,
    /// <summary>
    /// The port was changed too.
    /// </summary>
    PortChanged = 3,
}

/// <summary>
/// What the account's server did with the test's `OPTIONS`. Names for
/// `sipral_network_test_event_t::server`.
/// </summary>
public enum SipralServerReach : uint
{
    /// <summary>
    /// Not part of this test.
    /// </summary>
    NotTested = 0,
    /// <summary>
    /// Any final answer; see `server_status` and `server_round_trip_ms`.
    /// </summary>
    Answered = 1,
    /// <summary>
    /// No answer before the request, or the test, timed out.
    /// </summary>
    TimedOut = 2,
    /// <summary>
    /// The transport refused the request or failed under it.
    /// </summary>
    TransportFailed = 3,
}

/// <summary>
/// What a held party is sent: `sipral_stack_config_t::held_audio`.
/// </summary>
public enum SipralHeldAudio : uint
{
    /// <summary>
    /// Silence, in either mode.
    /// </summary>
    Default = 0,
    /// <summary>
    /// Silence.
    /// </summary>
    Silence = 1,
    /// <summary>
    /// The frames the application hands over, as they are.
    /// </summary>
    Application = 2,
}

/// <summary>
/// The one callback a stack has.
///
/// Called inside `sipral_stack_poll` on its thread, never concurrently
/// for one stack. Must not unwind. May call back into the library
/// (`docs/08-ffi.md`, "The shape").
///
/// Hand it over as a function pointer: keep the delegate alive for as
/// long as the stack is, and pass Marshal.GetFunctionPointerForDelegate.
/// </summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void SipralEventCallback(IntPtr @event, IntPtr userData);

/// <summary>
/// The screening policy: called once per INVITE, before it has any
/// effect. Installed with sipral_stack_screen.
///
/// **It runs with the stack's lock held** (see the module docs), unlike
/// SipralEventCallback. **It must
/// not call back into the stack it was given**, from any thread; such a
/// call is answered `SIPRAL_STATUS_BUSY`. Another stack is fine. It must
/// not unwind across the boundary.
///
/// `request` and what it points at are valid for this call only.
///
/// **The answer is a SIP status code.** `SIPRAL_SCREEN_ACCEPT` (200) lets
/// the INVITE through as if no policy were installed. 400 to 699 refuses
/// with that status. Anything else refuses with 500: zero (a listener that
/// threw), a 1xx (would leave the transaction open), another 2xx, or a 3xx
/// (no `Contact` to redirect to).
///
/// Hand it over as a function pointer: keep the delegate alive for as
/// long as the stack is, and pass Marshal.GetFunctionPointerForDelegate.
/// </summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate uint SipralScreenCallback(IntPtr request, IntPtr userData);

/// <summary>
/// Echo cancellation, gain control or noise suppression, run over one
/// frame, or told to forget what it has learned — SipralProcessorFrame
/// says which. Installed with sipral_media_attach_processor.
///
/// **It runs with this call's media locked** (see
/// sipral_media_attach_processor): it must not call into the media
/// handle it was attached through, on any thread, and must not unwind.
///
/// `frame` and what it points at are library-owned, valid only during the
/// call.
///
/// Hand it over as a function pointer: keep the delegate alive for as
/// long as the stack is, and pass Marshal.GetFunctionPointerForDelegate.
/// </summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void SipralProcessorCallback(IntPtr frame, IntPtr userData);

/// <summary>
/// Where the packets the engine encodes go: the application's, called
/// on the engine's thread with one `sipral_audio_transmit_t` per packet.
///
/// Hand it over as a function pointer: keep the delegate alive for as
/// long as the stack is, and pass Marshal.GetFunctionPointerForDelegate.
/// </summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void SipralAudioTransmitCallback(IntPtr transmit, IntPtr userData);

/// <summary>
/// Where a stack's log lines go. Installed with
/// sipral_stack_log.
///
/// Called on the thread that just finished a call into this stack, with
/// nothing held, so it may call back into the library. One line at a
/// time, never on two threads at once. It must not unwind.
///
/// `record` and what it points at are valid for this call only.
///
/// Hand it over as a function pointer: keep the delegate alive for as
/// long as the stack is, and pass Marshal.GetFunctionPointerForDelegate.
/// </summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void SipralLogCallback(IntPtr record, IntPtr userData);

/// <summary>
/// The version of the ABI this library provides.
///
/// Set `size` to `sizeof(sipral_abi_version_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralAbiVersion
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// Nothing built against another major version will work.
    /// </summary>
    public uint Major;
    /// <summary>
    /// A build with a higher minor has everything a lower one had.
    /// </summary>
    public uint Minor;
    /// <summary>
    /// A fix that changed no declaration.
    /// </summary>
    public uint Patch;
    /// <summary>
    /// Zero. Pads to alignment so later members never land in padding.
    /// </summary>
    public uint Reserved;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralAbiVersion Sized()
    {
        var value = default(SipralAbiVersion);
        value.Size = (nuint)Marshal.SizeOf<SipralAbiVersion>();
        return value;
    }
}

/// <summary>
/// What this build can do: codecs, signalling transports, optional features.
///
/// Not configuration: `sipral_stack_settings` answers what a stack has on.
///
/// Set `size` to `sizeof(sipral_capabilities_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralCapabilities
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// How many codecs this build contains (same as `sipral_codec_count`).
    /// </summary>
    public nuint CodecCount;
    /// <summary>
    /// Transports for signalling, as `SIPRAL_TRANSPORT_BIT_*` bits.
    /// </summary>
    public uint Transports;
    /// <summary>
    /// Compiled-in features, as `SIPRAL_FEATURE_*` bits.
    /// </summary>
    public uint Features;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralCapabilities Sized()
    {
        var value = default(SipralCapabilities);
        value.Size = (nuint)Marshal.SizeOf<SipralCapabilities>();
        return value;
    }
}

/// <summary>
/// D3's flat set of health counters for one stack, since it was created.
/// All monotonic except the gauge `active_calls`. Set `size` to
/// `sizeof(sipral_counters_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralCounters
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// A REGISTER went out, counted once per attempt including a retry.
    /// </summary>
    public ulong RegistrationsAttempted;
    /// <summary>
    /// The registrar granted a binding.
    /// </summary>
    public ulong RegistrationsSucceeded;
    /// <summary>
    /// The registrar refused, and will refuse the same request again.
    /// </summary>
    public ulong RegistrationsFailedRejected;
    /// <summary>
    /// The password was wrong, or there was none to answer a challenge with.
    /// </summary>
    public ulong RegistrationsFailedBadCredentials;
    /// <summary>
    /// The registrar did not answer, or said it could not serve this now.
    /// </summary>
    public ulong RegistrationsFailedUnreachable;
    /// <summary>
    /// The registrar moved.
    /// </summary>
    public ulong RegistrationsFailedRedirected;
    /// <summary>
    /// This end hung up.
    /// </summary>
    public ulong CallsEndedLocalHangup;
    /// <summary>
    /// The far end hung up.
    /// </summary>
    public ulong CallsEndedRemoteHangup;
    /// <summary>
    /// The far end refused it: busy, declined, not found.
    /// </summary>
    public ulong CallsEndedRefused;
    /// <summary>
    /// Given up before it was answered, from either end.
    /// </summary>
    public ulong CallsEndedCancelled;
    /// <summary>
    /// Nothing came back, or the transport died.
    /// </summary>
    public ulong CallsEndedUnreachable;
    /// <summary>
    /// Another branch of the same fork was kept and this one was not.
    /// </summary>
    public ulong CallsEndedForkLost;
    /// <summary>
    /// The branch was still ringing when the answer window closed.
    /// </summary>
    public ulong CallsEndedAbandoned;
    /// <summary>
    /// The session timer ran out and no refresh arrived.
    /// </summary>
    public ulong CallsEndedExpired;
    /// <summary>
    /// Inbound audio stopped past the threshold while signalling was fine (B5).
    /// </summary>
    public ulong MediaGaps;
    /// <summary>
    /// Jitter buffer shrink or stretch adjustments.
    /// </summary>
    public ulong JitterBufferEvents;
    /// <summary>
    /// A request too big for a datagram with no stream to its destination,
    /// so one was requested (RFC 3261 §18.1.1, B1). Reuse of an existing
    /// connection does not count.
    /// </summary>
    public ulong StreamTransportWanted;
    /// <summary>
    /// Calls with media running now; the only gauge.
    /// </summary>
    public ulong ActiveCalls;
    /// <summary>
    /// Events dropped because the outbox was at its ceiling (task 8.4.21).
    /// </summary>
    public ulong EventsDropped;
    /// <summary>
    /// RTCP goodbyes dropped, oldest first, because
    /// `sipral_stack_poll_farewell` was not keeping up.
    /// </summary>
    public ulong FarewellsDropped;
    /// <summary>
    /// INVITEs a `sipral_stack_screen` policy refused (A8, D7).
    /// </summary>
    public ulong ScreenedRefusedByPolicy;
    /// <summary>
    /// INVITEs refused for exceeding `sipral_stack_invite_limit`.
    /// </summary>
    public ulong ScreenedRefusedByRate;
    /// <summary>
    /// INVITEs refused because every tracked-source seat was taken: a
    /// flood from many addresses.
    /// </summary>
    public ulong ScreenedRefusedByCrowding;
    /// <summary>
    /// INVITEs refused 403 for an unauthorised Replaces (RFC 3891 §3).
    /// </summary>
    public ulong ScreenedRefusedByReplaces;
    /// <summary>
    /// Requests resent by RFC 3261 timers A and E, plus ACKs resent for a
    /// repeated 2xx. UDP only; a rising value means packet loss.
    /// </summary>
    public ulong RequestsRetransmitted;
    /// <summary>
    /// Responses resent: timer G, reliable provisional timer, and repeats
    /// for a retransmitted request.
    /// </summary>
    public ulong ResponsesRetransmitted;
    /// <summary>
    /// Transactions ended by timers B, F, H and L, or an unPRACKed
    /// reliable provisional response.
    /// </summary>
    public ulong TransactionsTimedOut;
    /// <summary>
    /// Requests answered `503` because the stack was at
    /// `max_server_transactions`, or an INVITE was at `max_dialogs`.
    /// </summary>
    public ulong RequestsRefusedAtLimit;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralCounters Sized()
    {
        var value = default(SipralCounters);
        value.Size = (nuint)Marshal.SizeOf<SipralCounters>();
        return value;
    }
}

/// <summary>
/// What a stack is created with. Set `size` to `sizeof(sipral_stack_config_t)`
/// and zero the rest first. Required: the callback, the transport, the reachable
/// address, the entropy, and a media seed different from the entropy.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralStackConfig
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// Where events go. Required.
    /// </summary>
    public IntPtr EventCallback;
    /// <summary>
    /// Handed back to the callback untouched. The library never reads it.
    /// </summary>
    public IntPtr EventUserData;
    /// <summary>
    /// A SipralTransport.
    /// </summary>
    public uint Transport;
    /// <summary>
    /// The address the far end reaches this one at, as `host:port`, UTF-8 and
    /// not NUL-terminated. It goes in every `Via`.
    /// </summary>
    public IntPtr BindAddress;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint BindAddressLen;
    /// <summary>
    /// `User-Agent` for every REGISTER and INVITE this stack originates, or null
    /// for none (optional per §20 Table 3).
    /// </summary>
    public IntPtr UserAgent;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint UserAgentLen;
    /// <summary>
    /// Thirty-two bytes from the platform's generator. Every branch, tag and
    /// `Call-ID` derives from it, and §19.3 wants a tag unguessable. Never
    /// shared between stacks. Media keys come from `media_seed`.
    /// </summary>
    public IntPtr Entropy;
    /// <summary>
    /// How many bytes of it. Thirty-two.
    /// </summary>
    public nuint EntropyLen;
    /// <summary>
    /// T1 in milliseconds, or zero for the 500 ms of §17.1.1.1.
    /// </summary>
    public ulong TimerT1Ms;
    /// <summary>
    /// T2 in milliseconds, or zero for four seconds. UDP only; set on another
    /// transport it is `SIPRAL_STATUS_INVALID_ARGUMENT`.
    /// </summary>
    public ulong TimerT2Ms;
    /// <summary>
    /// T4 in milliseconds, or zero for five seconds. UDP only, like T2.
    /// </summary>
    public ulong TimerT4Ms;
    /// <summary>
    /// The codecs to offer, in order (A4, RFC 3264 §6.1): comma-separated names,
    /// UTF-8, not NUL-terminated; null for every codec built in. An unknown name is
    /// `SIPRAL_STATUS_NOT_SUPPORTED`, with the known names in the last error.
    /// </summary>
    public IntPtr Codecs;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint CodecsLen;
    /// <summary>
    /// Frame length in milliseconds, or zero for twenty. Must suit Opus if offered.
    /// </summary>
    public uint FrameMs;
    /// <summary>
    /// Whether to offer RFC 4733 named events, as a `SipralToggle`. On by default.
    /// </summary>
    public uint OfferDtmf;
    /// <summary>
    /// Whether to ask for RFC 5761 multiplexing (§5.1.1), as a `SipralToggle`.
    /// Off by default.
    /// </summary>
    public uint OfferRtcpMux;
    /// <summary>
    /// Whether to stop sending during silence, as a `SipralToggle`. Off by
    /// default: with no comfort noise, the gap looks like a dead stream.
    /// </summary>
    public uint SilenceSuppression;
    /// <summary>
    /// Whether inbound audio that stops is reported (B5), as a `SipralToggle`.
    /// On by default.
    /// </summary>
    public uint MediaStallWatchdog;
    /// <summary>
    /// How long inbound audio may stop before it is reported, in milliseconds,
    /// or zero for the default. Refused with the watchdog off.
    /// </summary>
    public ulong MediaStallMs;
    /// <summary>
    /// The wall clock at creation, in seconds since the Unix epoch, for RFC 3550
    /// §6.4.1 sender reports; zero to wait for `sipral_stack_stir`'s `unix_seconds`.
    /// </summary>
    public ulong MediaClockUnixSeconds;
    /// <summary>
    /// Thirty-two more bytes for the media keys, **not the same bytes as
    /// `entropy`**, which recordings write in clear. The same bytes are refused.
    /// </summary>
    public IntPtr MediaSeed;
    /// <summary>
    /// How many bytes of it. Thirty-two.
    /// </summary>
    public nuint MediaSeedLen;
    /// <summary>
    /// Default SRTP for every call: a `SipralSrtp`, or zero for
    /// `SIPRAL_SRTP_NOT_OFFERED`. `sipral_call_config_t::srtp` overrides it.
    /// </summary>
    public uint Srtp;
    /// <summary>
    /// Default ICE for every call: a `SipralIce`, or zero for `SIPRAL_ICE_OFF`
    /// (`docs/06-nat.md`). `sipral_call_config_t::ice` overrides it.
    /// </summary>
    public uint Ice;
    /// <summary>
    /// A `SipralNat`, or zero for `SIPRAL_NAT_OFF`. `SIPRAL_NAT_STUN` asks
    /// `stun_server` where each socket appears from (`docs/06-nat.md`).
    /// </summary>
    public uint Nat;
    /// <summary>
    /// The STUN server, as a `host:port` address. Required with and only with
    /// `SIPRAL_NAT_STUN`. Copied.
    /// </summary>
    public IntPtr StunServer;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint StunServerLen;
    /// <summary>
    /// Whether G.729 Annex B is allowed, as a `SipralToggle`. On by default (RFC
    /// 4856 §2.1.9); off, SDP says `annexb=no` (RFC 3551 §4.5.6).
    /// </summary>
    public uint G729AnnexB;
    /// <summary>
    /// A TURN server (RFC 8656), as `host:port`, to relay every media socket
    /// `sipral_stack_nat_map` names (`docs/06-nat.md`). Only with `SIPRAL_NAT_STUN`,
    /// needs `turn_username` and `turn_password`, and `SIPRAL_FEATURE_ICE`. Copied.
    /// </summary>
    public IntPtr TurnServer;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint TurnServerLen;
    /// <summary>
    /// The TURN long-term credential's user name (RFC 8489 §9.2).
    /// </summary>
    public IntPtr TurnUsername;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint TurnUsernameLen;
    /// <summary>
    /// Its password. Copied, wiped at destroy, never logged.
    /// </summary>
    public IntPtr TurnPassword;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint TurnPasswordLen;
    /// <summary>
    /// Whether an out-of-dialog REFER (RFC 3515 §4.1) reaches the application, as
    /// a `SipralToggle`. **Off by default**: each is refused 403, since an
    /// unauthenticated peer could make the phone dial anywhere. On, each is raised
    /// as `SIPRAL_EVENT_KIND_REFERRAL`.
    /// </summary>
    public uint Referrals;
    /// <summary>
    /// Whether an account behind a NAT sends a double CRLF to its registrar every
    /// `registrar_keepalive_ms` over UDP, as a `SipralToggle`. **On by default.**
    /// Without it an address-and-port filtering NAT (RFC 4787 §5) drops a later
    /// INVITE; registrars ignore it (RFC 3261 §7.5). See `docs/06-nat.md`.
    /// </summary>
    public uint RegistrarKeepalive;
    /// <summary>
    /// Keep-alive interval in milliseconds, or zero for 25 s (RFC 5626 §4.4.2),
    /// jittered to 80-100%. From 1 000 to 120 000 (RFC 4787 REQ-5), and only with
    /// `registrar_keepalive` on.
    /// </summary>
    public ulong RegistrarKeepaliveMs;
    /// <summary>
    /// How media sockets reach `turn_server`, as a `SipralTransport`: UDP (or
    /// zero), TCP, or TLS (RFC 8656 §4.1). Over TCP or TLS the application opens a
    /// connection when `SIPRAL_EVENT_KIND_TURN_STREAM` asks.
    /// </summary>
    public uint TurnTransport;
    /// <summary>
    /// Who pumps audio, as a `SipralAudio`: zero or `SIPRAL_AUDIO_APPLICATION`
    /// for the application; `SIPRAL_AUDIO_DEVICE` for the library, which needs
    /// `audio_transmit_callback` and `SIPRAL_FEATURE_AUDIO_DEVICE`.
    /// </summary>
    public uint Audio;
    /// <summary>
    /// When devices open in device mode: a `SipralAudioActivation`, or zero for
    /// `SIPRAL_AUDIO_ACTIVATION_AUTOMATIC`.
    /// </summary>
    public uint AudioActivation;
    /// <summary>
    /// Device mode: receives each encoded packet on the engine's thread.
    /// Required with `SIPRAL_AUDIO_DEVICE`.
    /// </summary>
    public IntPtr AudioTransmitCallback;
    /// <summary>
    /// Handed back to `audio_transmit_callback` unread.
    /// </summary>
    public IntPtr AudioTransmitUserData;
    /// <summary>
    /// How long a device call may block before `SIPRAL_STATUS_DEVICE_TIMED_OUT`,
    /// in milliseconds; zero for three seconds.
    /// </summary>
    public ulong AudioProbeMs;
    /// <summary>
    /// The device rate in device mode; zero for 48000.
    /// </summary>
    public uint AudioDeviceRateHz;
    /// <summary>
    /// The most calls at once, either direction, or zero for 128. Past it an
    /// INVITE gets `503` with `Retry-After: 2` (RFC 3261 §21.5.4), and a placed
    /// call is `SIPRAL_STATUS_LIMIT_REACHED`. See `docs/19-numbers.md`.
    /// </summary>
    public uint MaxDialogs;
    /// <summary>
    /// The most server transactions (RFC 3261 §17.2) at once, or zero for 256;
    /// past it a stateless `503`. A BYE is never refused.
    /// </summary>
    public uint MaxServerTransactions;
    /// <summary>
    /// D1: how many decisions each diagnostic record keeps, or zero for 64.
    /// </summary>
    public uint DiagnosticDecisions;
    /// <summary>
    /// D1: how many calls have a diagnostic record at once, or zero for 32; the
    /// oldest is dropped and counted.
    /// </summary>
    public uint DiagnosticRecords;
    /// <summary>
    /// When a call listens for in-band keypad digits, as a
    /// SipralDtmfDetection; zero for calls with no telephone event. Placed
    /// here to avoid tail padding.
    /// </summary>
    public uint DtmfDetection;
    /// <summary>
    /// Fallback STUN servers, comma-separated `host:port`, tried in order when
    /// `stun_server` fails; a failed one is skipped from 30 s up to ten minutes.
    /// Only with `stun_server`. Copied.
    /// </summary>
    public IntPtr StunFallbacks;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint StunFallbacksLen;
    /// <summary>
    /// The lowest RTP port handed out (`sipral_stack_rtp_port_reserve`), or zero
    /// with `rtp_port_max` for none. Even ports only (RFC 3550 §11).
    /// </summary>
    public uint RtpPortMin;
    /// <summary>
    /// The highest port of that range, or zero with `rtp_port_min`.
    /// </summary>
    public uint RtpPortMax;
    /// <summary>
    /// The SRTP suites calls offer and accept unless the account names its own:
    /// names from RFC 4568 section 6.2 and RFC 7714 section 14.2, comma-separated,
    /// preferred first; null for the build's order.
    /// </summary>
    public IntPtr SrtpSuites;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint SrtpSuitesLen;
    /// <summary>
    /// The path MTU in bytes, or zero for unknown (RFC 3261 section 18.1.1).
    /// At least 576 (RFC 791).
    /// </summary>
    public uint PathMtu;
    /// <summary>
    /// Largest request sent over UDP once no stream can be had, in bytes; zero
    /// for never. **A deliberate deviation from RFC 3261 section 18.1.1**, for
    /// UDP-only servers. At most 65 507.
    /// </summary>
    public uint DatagramWithoutStreamBytes;
    /// <summary>
    /// A per-installation salt (at least 16 bytes) so pseudonyms match across
    /// runs; null keys them from `media_seed`. Secret. Copied.
    /// </summary>
    public IntPtr PseudonymSalt;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint PseudonymSaltLen;
    /// <summary>
    /// A `SipralToggle`: whether the trace writes SIP messages unpseudonymised;
    /// off by default. Credentials and keys are always removed.
    /// </summary>
    public uint DiagnosticTrace;
    /// <summary>
    /// Zero.
    /// </summary>
    public uint Reserved;
    /// <summary>
    /// A `SipralToggle`: whether device mode uses the platform's echo
    /// cancellation; on by default.
    /// </summary>
    public uint SystemEchoCancellation;
    /// <summary>
    /// Zero.
    /// </summary>
    public uint Reserved35;
    /// <summary>
    /// A SipralHeldAudio: what a held party is sent (RFC 3264 §8.4). Zero
    /// is silence.
    /// </summary>
    public uint HeldAudio;
    /// <summary>
    /// Zero.
    /// </summary>
    public uint Reserved36;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralStackConfig Sized()
    {
        var value = default(SipralStackConfig);
        value.Size = (nuint)Marshal.SizeOf<SipralStackConfig>();
        return value;
    }
}

/// <summary>
/// What one call to sipral_stack_poll did. Set `size` first.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralPollResult
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// Events handed to the callback during this poll.
    /// </summary>
    public nuint EventsDelivered;
    /// <summary>
    /// Events this ABI has no word for yet. Counted, not delivered.
    /// </summary>
    public nuint EventsUnclaimed;
    /// <summary>
    /// Bytes this build had nowhere to send; zero, kept for ABI stability.
    /// </summary>
    public nuint TransmitsDiscarded;
    /// <summary>
    /// Whether there is a deadline. Zero: wait for input.
    /// </summary>
    public uint HasDeadline;
    /// <summary>
    /// Milliseconds from `now_ms` until the stack is due. Zero: due now.
    /// </summary>
    public ulong NextPollInMs;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralPollResult Sized()
    {
        var value = default(SipralPollResult);
        value.Size = (nuint)Marshal.SizeOf<SipralPollResult>();
        return value;
    }
}

/// <summary>
/// What a stack is running with, defaults filled in. Set `size` first.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralStackSettings
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// The SipralTransport this stack speaks.
    /// </summary>
    public uint Transport;
    /// <summary>
    /// Whether this stack retransmits; zero on every transport but UDP.
    /// </summary>
    public uint Retransmits;
    /// <summary>
    /// T1 in milliseconds, with the default filled in.
    /// </summary>
    public ulong TimerT1Ms;
    /// <summary>
    /// T2 in milliseconds, with the default filled in.
    /// </summary>
    public ulong TimerT2Ms;
    /// <summary>
    /// T4 in milliseconds, with the default filled in.
    /// </summary>
    public ulong TimerT4Ms;
    /// <summary>
    /// How many codecs this stack offers (`sipral_stack_codec_order`).
    /// </summary>
    public nuint CodecCount;
    /// <summary>
    /// How long a frame is, with the default filled in.
    /// </summary>
    public uint FrameMs;
    /// <summary>
    /// Whether named events are offered, as a `SipralToggle`.
    /// </summary>
    public uint OfferDtmf;
    /// <summary>
    /// Whether RTCP multiplexing is asked for, as a `SipralToggle`.
    /// </summary>
    public uint OfferRtcpMux;
    /// <summary>
    /// Whether sending stops during silence, as a `SipralToggle`.
    /// </summary>
    public uint SilenceSuppression;
    /// <summary>
    /// The media stall interval in milliseconds; zero when the watchdog is off.
    /// </summary>
    public ulong MediaStallMs;
    /// <summary>
    /// Whether G.729 Annex B is allowed, as a `SipralToggle`.
    /// </summary>
    public uint G729AnnexB;
    /// <summary>
    /// Whether an out-of-dialog REFER reaches the application, as a `SipralToggle`.
    /// </summary>
    public uint Referrals;
    /// <summary>
    /// The registrar keep-alive in milliseconds; zero when off.
    /// </summary>
    public ulong RegistrarKeepaliveMs;
    /// <summary>
    /// The most calls the stack holds at once.
    /// </summary>
    public uint MaxDialogs;
    /// <summary>
    /// The most server transactions at once.
    /// </summary>
    public uint MaxServerTransactions;
    /// <summary>
    /// How many decisions a diagnostic record keeps.
    /// </summary>
    public uint DiagnosticDecisions;
    /// <summary>
    /// How many diagnostic records the stack keeps.
    /// </summary>
    public uint DiagnosticRecords;
    /// <summary>
    /// The RTP port range, as given; both zero for none.
    /// </summary>
    public uint RtpPortMin;
    /// <summary>
    /// See `rtp_port_min`.
    /// </summary>
    public uint RtpPortMax;
    /// <summary>
    /// The path MTU as given, zero for unknown (ABI 0.34).
    /// </summary>
    public uint PathMtu;
    /// <summary>
    /// The largest request sent over UDP once no stream is coming; zero for never.
    /// </summary>
    public uint DatagramWithoutStreamBytes;
    /// <summary>
    /// How many SRTP suites calls use by default (`sipral_stack_srtp_suite_order`).
    /// </summary>
    public uint SrtpSuiteCount;
    /// <summary>
    /// A `SipralToggle`: whether a `pseudonym_salt` was given. Never the salt.
    /// </summary>
    public uint PseudonymSalted;
    /// <summary>
    /// A `SipralToggle`: whether the trace writes whole messages now.
    /// </summary>
    public uint DiagnosticTrace;
    /// <summary>
    /// A `SipralToggle`: whether the platform's echo cancellation is asked for.
    /// </summary>
    public uint SystemEchoCancellation;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralStackSettings Sized()
    {
        var value = default(SipralStackSettings);
        value.Size = (nuint)Marshal.SizeOf<SipralStackSettings>();
        return value;
    }
}

/// <summary>
/// One header field an application hands over: a name and a value, UTF-8,
/// neither NUL-terminated.
///
/// No `size` member: it is an array element, so it never grows.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralHeader
{
    /// <summary>
    /// The field name, `X-Conversation-Id`. A compact form is the field it
    /// abbreviates.
    /// </summary>
    public IntPtr Name;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint NameLen;
    /// <summary>
    /// The value, as it goes on the line after the colon. Null or empty
    /// for a field with an empty value.
    /// </summary>
    public IntPtr Value;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ValueLen;
}

/// <summary>
/// What an account is configured with. Set `size` to
/// `sizeof(sipral_account_config_t)` and zero the rest first.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralAccountConfig
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// The address of record, `sip:alice@example.com`. UTF-8, not
    /// NUL-terminated.
    /// </summary>
    public IntPtr Aor;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint AorLen;
    /// <summary>
    /// Where the REGISTER is addressed, `sip:example.com`, no user part.
    /// A `registrar_len` of zero makes a trunk that never registers: its
    /// state stays `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING`, and
    /// `sipral_account_register` refuses it.
    /// </summary>
    public IntPtr Registrar;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint RegistrarLen;
    /// <summary>
    /// Where this endpoint can be reached, as it goes in `Contact`.
    /// </summary>
    public IntPtr Contact;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ContactLen;
    /// <summary>
    /// Where this account's requests go, as `host:port`: the registrar, or
    /// the outbound proxy for an account with no registrar. Calls without
    /// a destination go here too. Required unless `server_uri` is given;
    /// an address, not a name.
    /// </summary>
    public IntPtr RegistrarAddress;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint RegistrarAddressLen;
    /// <summary>
    /// The display name that goes in `From`, or null for none.
    /// </summary>
    public IntPtr DisplayName;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint DisplayNameLen;
    /// <summary>
    /// The user name to answer a challenge with, or null for none.
    /// </summary>
    public IntPtr AuthUser;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint AuthUserLen;
    /// <summary>
    /// The password that goes with it, copied.
    /// </summary>
    public IntPtr AuthPassword;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint AuthPasswordLen;
    /// <summary>
    /// The `+sip.instance` URN of RFC 5626 §4.1, or null for none.
    /// </summary>
    public IntPtr InstanceId;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint InstanceIdLen;
    /// <summary>
    /// How long a binding to ask for, or zero for an hour.
    ///
    /// Above 2³²−1 is refused (§20.19 `delta-seconds`). The registrar's
    /// grant wins, and is read back in
    /// `sipral_registration_event_t::expires_ms`.
    /// </summary>
    public ulong ExpiresSeconds;
    /// <summary>
    /// Header fields for every REGISTER of this account, in order, or null.
    ///
    /// Checked on add as `sipral_call_config_t::headers` is: `Expires` is
    /// the stack's (`expires_seconds`), `Supported` the application's (for
    /// GRUU). Refused for an account with no registrar.
    /// </summary>
    public IntPtr Headers;
    /// <summary>
    /// How many elements `headers` has.
    /// </summary>
    public nuint HeadersLen;
    /// <summary>
    /// The transport for this account's REGISTER and requests:
    /// SIPRAL_TRANSPORT_MAIN
    /// for zero, or a number
    /// sipral_stack_transport_bind
    /// has bound. An unbound number is `SIPRAL_STATUS_INVALID_ARGUMENT`.
    /// </summary>
    public uint Transport;
    /// <summary>
    /// The push service to be woken through, by registered name: `apns`,
    /// `fcm`, `webpush` (RFC 8599 §4.1.1). Null for no push.
    ///
    /// The push parameters go only on this account's REGISTER `Contact`
    /// (§4.1): on an INVITE `pn-prid` would let the far end wake this
    /// device at will. De-registration leaves the identifier out (§4.1.2).
    /// </summary>
    public IntPtr PushProvider;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint PushProviderLen;
    /// <summary>
    /// The device token the service issued. Required with
    /// `push_provider`, and refused without it. Percent-escaped where SIP
    /// needs it (§8.7): APNs tokens carry `=`, Web Push ids are URLs.
    /// </summary>
    public IntPtr PushPrid;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint PushPridLen;
    /// <summary>
    /// The extra value a service needs: the bundle for Apple, the sender
    /// for Firebase. Optional; §4.1.1 lets the service decide.
    /// </summary>
    public IntPtr PushParam;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint PushParamLen;
    /// <summary>
    /// Nonzero when this device can refresh its binding without a push,
    /// declared with `+sip.pnsreg` (§4.1.4). Only the application knows:
    /// a suspended process runs no timer, and a false claim stops the
    /// registrar's wake-ups.
    /// </summary>
    public uint PushWakesItself;
    /// <summary>
    /// Where end-of-call quality reports go (RFC 6035 over PUBLISH, RFC
    /// 3903), or null for none.
    /// </summary>
    public IntPtr QualityReportUri;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint QualityReportUriLen;
    /// <summary>
    /// A SipralSessionTimer: how this account's calls ask for a
    /// session timer (RFC 4028). Zero is the default, thirty minutes.
    /// </summary>
    public uint SessionTimer;
    /// <summary>
    /// The interval to ask for under `SIPRAL_SESSION_TIMER_INTERVAL`, in
    /// seconds: at least 90, RFC 4028 §5's floor. Read for nothing else.
    /// </summary>
    public ulong SessionIntervalSeconds;
    /// <summary>
    /// `SIPRAL_PRIVACY_*` bits: place every call anonymously (RFC 3323).
    /// `From` becomes `"Anonymous" &lt;sip:anonymous@anonymous.invalid&gt;`,
    /// `Privacy` carries the bits, and `P-Asserted-Identity` goes only to
    /// a peer in `trusted_peers`. Zero asks for none.
    /// </summary>
    public uint Privacy;
    /// <summary>
    /// Trusted peers (RFC 3325's trust domain), comma-separated IP
    /// addresses. Only their asserted identity is read
    /// (`sipral_call_event_t::asserted_uri`). Once any are named, calls to
    /// other peers carry no `P-Asserted-Identity` or `P-Preferred-Identity`.
    /// Null trusts nobody.
    /// </summary>
    public IntPtr TrustedPeers;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint TrustedPeersLen;
    /// <summary>
    /// A `SipralSrtp` over the stack's `srtp`, or zero for the stack's.
    /// A call may be stricter, never looser
    /// (`SIPRAL_STATUS_SECURITY_POLICY`); an INVITE it cannot meet gets
    /// 488.
    /// </summary>
    public uint Srtp;
    /// <summary>
    /// The SRTP suites, most preferred first, comma-separated, as RFC 4568
    /// §6.2 and RFC 7714 §14.2 name them:
    /// `AEAD_AES_256_GCM,AES_CM_128_HMAC_SHA1_80`. Used for SDES and the
    /// DTLS-SRTP profiles; GCM only if named. Null for this build's own.
    /// Each line goes in the INVITE: more than two or three need a stream
    /// transport.
    /// </summary>
    public IntPtr SrtpSuites;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint SrtpSuitesLen;
    /// <summary>
    /// A `SipralStirVerification`: what to do with received `Identity`
    /// fields (RFC 8224 §6.2). Zero reports, once `sipral_stack_stir` gave
    /// trust anchors.
    /// </summary>
    public uint StirVerification;
    /// <summary>
    /// The P-256 key this account signs calls with (RFC 8224 §6.1): the
    /// bare 32-octet scalar, or `EC PRIVATE KEY` / `PRIVATE KEY` in DER or
    /// PEM. Null signs nothing. Needs the wall clock from
    /// `sipral_stack_stir`, else `SIPRAL_STATUS_WRONG_STATE`.
    /// </summary>
    public IntPtr StirKey;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint StirKeyLen;
    /// <summary>
    /// Where the chain for `stir_key` is published (`x5u` and `info`).
    /// Required with `stir_key`, and only with it.
    /// </summary>
    public IntPtr StirCertificateUrl;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint StirCertificateUrlLen;
    /// <summary>
    /// The number this account signs as, canonicalised by RFC 8224 §8.3's
    /// first step, or null for `aor`'s user part.
    /// </summary>
    public IntPtr StirOrig;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint StirOrigLen;
    /// <summary>
    /// The origination id every signed call claims (RFC 8588 §5), a UUID,
    /// or null for one the stack draws.
    /// </summary>
    public IntPtr StirOrigid;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint StirOrigidLen;
    /// <summary>
    /// A `SipralAttestation` (RFC 8588 §4); zero is full, `A`.
    /// </summary>
    public uint StirAttestation;
    /// <summary>
    /// A `SipralToggle`: whether an encrypted call may be recorded
    /// (`sipral_call_record_to`) in the clear. Off by default: copies go as
    /// SRTP with SDES keys (RFC 4568), and a stream the server refuses
    /// that way gets nothing (RFC 7866 §12.2).
    ///
    /// Sixty-four bits wide so it starts past an older layout's trailing
    /// padding, which old callers may leave unwritten.
    /// </summary>
    public ulong RecordingInClear;
    /// <summary>
    /// How often, in milliseconds, to keep the flow to the registrar (or
    /// outbound proxy) open regardless of STUN; zero defers to
    /// `sipral_stack_config_t::registrar_keepalive`.
    ///
    /// For a NAT that forgets UDP flows before the REGISTER refresh. UDP
    /// sends a lone double CRLF (RFC 3261 §7.5); TCP and TLS ping at this
    /// interval (RFC 5626 §4.4.1). Jittered to 80-100%. From 1 000 to
    /// 120 000, else `SIPRAL_STATUS_INVALID_ARGUMENT`.
    /// </summary>
    public ulong KeepaliveMs;
    /// <summary>
    /// The server as a URI whose host RFC 3263 locates
    /// (`sip:pbx.example.com`, `sips:example.com:5061`), in place of
    /// `registrar_address`: exactly one is given. The registrar, or the
    /// outbound proxy for an account that does not register.
    ///
    /// Lookups go to the application's resolver via
    /// `SIPRAL_EVENT_KIND_LOOKUP_WANTED` and `sipral_account_looked_up`;
    /// ordering, SRV ranking and fallback are the stack's. The first
    /// REGISTER waits for the first answer; a call before it with no
    /// destination is `SIPRAL_STATUS_WRONG_STATE`. An out-of-dialog
    /// request that times out, fails its transport or gets 503 moves to
    /// the next address (§4.3). The name is looked up again when the TTL
    /// runs out or recovery asks. A port skips SRV; a numeric host asks
    /// nothing.
    /// </summary>
    public IntPtr ServerUri;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ServerUriLen;
    /// <summary>
    /// The SHA-256 fingerprint of the one TLS certificate this account
    /// trusts, for a self-signed PBX: 64 hex digits, any case, colons and
    /// spaces ignored, bare or after `sha256 Fingerprint=` (openssl),
    /// `sha-256 ` (RFC 8122) or `SHA256=`, any case. Anything else is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT`. Null for none.
    ///
    /// The application's verifier asks `sipral_account_check_certificate`;
    /// with a pin the fingerprint is the whole verdict (`docs/22-tls.md`).
    /// </summary>
    public IntPtr TlsPinSha256;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint TlsPinSha256Len;
    /// <summary>
    /// A `SipralToggle`: ask NAPTR before SRV for `server_uri`'s domain
    /// (RFC 3263 §4.1). Off by default; refused without `server_uri`.
    /// </summary>
    public uint ServerNaptr;
    /// <summary>
    /// Zero.
    /// </summary>
    public uint Reserved;
    /// <summary>
    /// A SipralTransport: the protocol of a connection of this
    /// account's own to its server, which the application opens, or zero.
    ///
    /// For an account on TCP or TLS beside one on the stack's UDP, in one
    /// stack. With TCP, TLS, WS or WSS the stack raises
    /// `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` with the protocol and address
    /// (`request_bytes` and `limit_bytes` zero); the account then uses
    /// whatever transport of that protocol the application binds there with
    /// `sipral_stack_transport_bind`, including one bound before. Until
    /// then the REGISTER waits; after ten seconds it fails as unreachable
    /// and the retry asks again. A non-registering account asks on add;
    /// any account asks again when the connection fails or closes. A call
    /// before the bind is `SIPRAL_STATUS_TRANSPORT_DOWN`. In-call requests
    /// keep their INVITE's connection, and requests arriving on it match
    /// this account first. `SIPRAL_TRANSPORT_UDP` only describes
    /// `transport`.
    /// </summary>
    public uint StreamProtocol;
    /// <summary>
    /// Zero.
    /// </summary>
    public uint Reserved35;
    /// <summary>
    /// The realms the password answers, one per line (a realm may hold a
    /// comma, never a line break), or null for the default.
    ///
    /// The password answers only the account's own server (RFC 3261
    /// §22.1). By default that is the realms of the server's first
    /// challenge and of every REGISTER challenge; a proxy relaying a far
    /// end's 401 gets nothing, and `SIPRAL_EVENT_KIND_CHALLENGE_DECLINED`
    /// says so. When calls are challenged under a realm REGISTERs never
    /// see (an SBC or proxy with its own realm), name all of them here.
    /// Empty lines are skipped; realms compare exactly (§22.1).
    /// </summary>
    public IntPtr Realms;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint RealmsLen;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralAccountConfig Sized()
    {
        var value = default(SipralAccountConfig);
        value.Size = (nuint)Marshal.SizeOf<SipralAccountConfig>();
        return value;
    }
}

/// <summary>
/// What a call is placed with.
///
/// Set `size` to `sizeof(sipral_call_config_t)` and zero the rest before filling it in.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralCallConfig
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// Who to call, as a URI. UTF-8, not NUL-terminated.
    /// </summary>
    public IntPtr Target;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint TargetLen;
    /// <summary>
    /// The session description to offer, for a call whose audio the application runs.
    /// Exactly one of this and `media_address` is set.
    /// </summary>
    public IntPtr Sdp;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint SdpLen;
    /// <summary>
    /// Where to send the INVITE, as `host:port`, or null for where the account registers
    /// (the outbound proxy of a registered line).
    /// </summary>
    public IntPtr Destination;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint DestinationLen;
    /// <summary>
    /// Nonzero keeps every branch a proxy forks the INVITE into. Zero keeps the first that
    /// answers and hangs up the rest.
    /// </summary>
    public uint KeepAllForks;
    /// <summary>
    /// Where this end receives media, as `host:port`, for a call whose audio this stack runs.
    ///
    /// Set, the offer is written from this stack's codec order and the call gets a media
    /// session the `sipral_media_*` entry points reach. Null: set `sdp` instead.
    /// </summary>
    public IntPtr MediaAddress;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint MediaAddressLen;
    /// <summary>
    /// Header fields to put on the INVITE, in order, or null for none.
    ///
    /// Each is checked first: the name a token, the value one line, and not a field the
    /// stack writes itself (`docs/04-ua.md`; `User-Agent` too when
    /// `sipral_stack_config_t::user_agent` is set). A refusal is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` naming the element, and no call.
    /// </summary>
    public IntPtr Headers;
    /// <summary>
    /// How many elements `headers` has.
    /// </summary>
    public nuint HeadersLen;
    /// <summary>
    /// What this call does about SRTP, overriding `sipral_stack_config_t::srtp`: a
    /// `SipralSrtp`, or zero for the stack's setting. Any other value is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT`. Read only with `media_address` set.
    /// </summary>
    public uint Srtp;
    /// <summary>
    /// Which transport the INVITE goes out on, read only with `destination`:
    /// SIPRAL_TRANSPORT_MAIN for zero, or a
    /// number sipral_stack_transport_bind
    /// has bound. Nonzero with `destination` null is `SIPRAL_STATUS_INVALID_ARGUMENT`.
    /// </summary>
    public uint Transport;
    /// <summary>
    /// What this call offers and in what order, overriding `sipral_stack_config_t::codecs`:
    /// codec names separated by commas, as `sipral_codec_info_t::name` spells them, UTF-8,
    /// not NUL-terminated. Null for the stack's order.
    ///
    /// The rest of the stack's catalogue (frame length, events, multiplexing, SRTP) is kept.
    /// An unknown name, a repeated name or a stray comma is `SIPRAL_STATUS_INVALID_ARGUMENT`.
    /// Applied only with `media_address` set, but the names are checked either way.
    /// </summary>
    public IntPtr Codecs;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint CodecsLen;
    /// <summary>
    /// What this call does about ICE, overriding `sipral_stack_config_t::ice`: a `SipralIce`,
    /// or zero for the stack's setting. Any other value is `SIPRAL_STATUS_INVALID_ARGUMENT`.
    /// Read only with `media_address` set.
    /// </summary>
    public uint Ice;
    /// <summary>
    /// Where this call's real-time text arrives (RFC 4103), as `host:port` of a second
    /// socket the application bound, not NUL-terminated; null for no text. Set, the
    /// description carries an `m=text` stream for T.140 with redundancy, carried by
    /// `sipral_media_send_text`, `sipral_media_poll_text` and `sipral_media_receive_text`.
    ///
    /// Read only with `media_address`. Not offered with SRTP, DTLS-SRTP or ICE: the text
    /// stream has no key or candidates of its own, and clear text beside encrypted audio is
    /// worse.
    /// </summary>
    public IntPtr TextAddress;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint TextAddressLen;
    /// <summary>
    /// Whether this call asks for RTCP feedback: a `SipralToggle`. On offers RTP/AVPF
    /// (RFC 4585) with Generic NACKs and reduced-size RTCP (RFC 5506). Off by default,
    /// because a far end that knows only RTP/AVP refuses the profile. Read only with
    /// `media_address`. An offer on a feedback profile is answered on it regardless
    /// (RFC 4585 §4.1); the NACKs and reduced-size RTCP are agreed only when this is on.
    /// </summary>
    public uint Feedback;
    /// <summary>
    /// Nonzero to say this end is the focus of a conference (RFC 4579
    /// §3.3): `isfocus` goes on the Contact of every message this call
    /// sends from here on.
    /// </summary>
    public uint Focus;
    /// <summary>
    /// Nonzero to follow a 3xx to its `Contact` targets (RFC 3261 §8.1.3.4), most preferred
    /// first, as new INVITEs of the same call. Not followed: a target already tried, a 380, a
    /// 6xx, a forked call, past eight redirections. Zero (default) ends the call with
    /// `SIPRAL_EVENT_KIND_CALL_ENDED` carrying the 3xx status and readable `Contact` addresses.
    /// Added in ABI 1.2.
    /// </summary>
    public uint FollowRedirects;
    /// <summary>
    /// Zero. Pads the struct to a multiple of its alignment, so a member a later version
    /// appends never lands in padding. The library reads nothing from it.
    /// </summary>
    public uint Reserved;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralCallConfig Sized()
    {
        var value = default(SipralCallConfig);
        value.Size = (nuint)Marshal.SizeOf<SipralCallConfig>();
        return value;
    }
}

/// <summary>
/// One codec this build contains.
///
/// Set `size` to `sizeof(sipral_codec_info_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralCodecInfo
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// A SipralCodec.
    /// </summary>
    public uint Codec;
    /// <summary>
    /// The RTP timestamp clock, in hertz, which is what goes on the
    /// `a=rtpmap` line.
    /// </summary>
    public uint ClockRate;
    /// <summary>
    /// The codec's own rate, which the samples crossing this ABI use. G.722's
    /// differs from its clock (RFC 3551 §4.5.2).
    /// </summary>
    public uint SampleRate;
    /// <summary>
    /// The payload type RFC 3551 table 4 assigns it, when it has one.
    /// </summary>
    public uint StaticPayloadType;
    /// <summary>
    /// Whether it has one. Opus does not.
    /// </summary>
    public uint HasStaticPayloadType;
    /// <summary>
    /// Zero. Pads to the alignment so later members start past this
    /// header's length. Written zero, never read.
    /// </summary>
    public uint Reserved;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralCodecInfo Sized()
    {
        var value = default(SipralCodecInfo);
        value.Size = (nuint)Marshal.SizeOf<SipralCodecInfo>();
        return value;
    }
}

/// <summary>
/// One codec this call could have used, and what became of it.
///
/// Set `size` to `sizeof(sipral_codec_candidate_t)` before the call.
///
/// Recorded when the negotiation decided, never recomputed.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralCodecCandidate
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// A SipralCodec: the candidate itself.
    /// </summary>
    public uint Codec;
    /// <summary>
    /// A SipralCodecOutcome: what became of it.
    /// </summary>
    public uint Outcome;
    /// <summary>
    /// A SipralCodec: what beat it, when `outcome` is
    /// `SIPRAL_CODEC_OUTCOME_OUTRANKED`; `SIPRAL_CODEC_UNKNOWN` otherwise.
    /// </summary>
    public uint OutrankedBy;
    /// <summary>
    /// Zero. Pads to the alignment so later members start past this
    /// header's length. Written zero, never read.
    /// </summary>
    public uint Reserved;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralCodecCandidate Sized()
    {
        var value = default(SipralCodecCandidate);
        value.Size = (nuint)Marshal.SizeOf<SipralCodecCandidate>();
        return value;
    }
}

/// <summary>
/// One path a call's ICE agent tried — a candidate pair it checked, or a
/// relay it held — and what became of it, with its two addresses written
/// into the caller's own buffers.
///
/// The caller fills in `size`, the two pointers and the two capacities;
/// the library fills in the rest. Null with capacity zero skips an address.
/// Recorded as each outcome happened, since RFC 8445 §8.1.2 drops losing
/// pairs from the checklist on selection.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralPathCandidate
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// The pair's priority (RFC 8445 §6.1.2.3), as this end's role
    /// computes it; zero for a relay.
    /// </summary>
    public ulong Priority;
    /// <summary>
    /// A SipralPathKind.
    /// </summary>
    public uint Kind;
    /// <summary>
    /// A SipralPathOutcome.
    /// </summary>
    public uint Outcome;
    /// <summary>
    /// For `SIPRAL_PATH_OUTCOME_REFUSED`, the STUN error code the far end
    /// answered with; for `SIPRAL_PATH_OUTCOME_RELAY_REFUSED` and
    /// `SIPRAL_PATH_OUTCOME_LOST`, the TURN server's, zero when it gave
    /// none. Zero otherwise.
    /// </summary>
    public uint Code;
    /// <summary>
    /// A SipralCandidateKind: what `local` is.
    /// </summary>
    public uint LocalKind;
    /// <summary>
    /// A SipralCandidateKind: what `remote` is, when it is a
    /// candidate at all.
    /// </summary>
    public uint RemoteKind;
    /// <summary>
    /// Zero. Keeps the layout identical on 32- and 64-bit targets. Written
    /// zero, never read.
    /// </summary>
    public uint Reserved;
    /// <summary>
    /// Where to write the local address, `host:port` with a trailing NUL:
    /// for a pair, the candidate its checks left from; for a relay, the
    /// relayed address.
    /// </summary>
    public IntPtr Local;
    /// <summary>
    /// How much room `local` has. At least SIPRAL_ADDRESS_BYTES when
    /// it is not null.
    /// </summary>
    public nuint LocalCapacity;
    /// <summary>
    /// How many bytes of it were written, the NUL not counted. Zero for
    /// a relay that has no relayed address.
    /// </summary>
    public nuint LocalLen;
    /// <summary>
    /// Where to write the far address, `host:port` with a trailing NUL:
    /// for a pair, the far end's candidate; for a relay, the TURN
    /// server.
    /// </summary>
    public IntPtr Remote;
    /// <summary>
    /// How much room `remote` has. At least SIPRAL_ADDRESS_BYTES
    /// when it is not null.
    /// </summary>
    public nuint RemoteCapacity;
    /// <summary>
    /// How many bytes of it were written, the NUL not counted.
    /// </summary>
    public nuint RemoteLen;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralPathCandidate Sized()
    {
        var value = default(SipralPathCandidate);
        value.Size = (nuint)Marshal.SizeOf<SipralPathCandidate>();
        return value;
    }
}

/// <summary>
/// What one call's media settled on, and what it is doing now.
///
/// Set `size` to `sizeof(sipral_media_info_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralMediaInfo
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// A SipralCodec: what the two ends agreed on.
    /// </summary>
    public uint Codec;
    /// <summary>
    /// The payload type on the wire: the offer's number, not necessarily
    /// ours.
    /// </summary>
    public uint PayloadType;
    /// <summary>
    /// The RTP timestamp clock, in hertz.
    /// </summary>
    public uint ClockRate;
    /// <summary>
    /// The rate the samples crossing this ABI are at: the codec's, or the
    /// one sipral_media_set_app_rate chose.
    /// </summary>
    public uint SampleRate;
    /// <summary>
    /// How long a frame is, in milliseconds.
    /// </summary>
    public uint FrameMs;
    /// <summary>
    /// Samples in one frame: exactly what sipral_media_playback fills and
    /// what sipral_media_capture wants, at `sample_rate`.
    /// </summary>
    public nuint FrameSamples;
    /// <summary>
    /// A SipralDirection.
    /// </summary>
    public uint Direction;
    /// <summary>
    /// Whether this end is meant to be sending. Zero while it holds the far
    /// end, or while the far end has refused to receive.
    /// </summary>
    public uint Sending;
    /// <summary>
    /// Whether this end is meant to be receiving.
    /// </summary>
    public uint Receiving;
    /// <summary>
    /// Whether RFC 4733 named events were agreed.
    /// </summary>
    public uint HasDtmf;
    /// <summary>
    /// The payload type they travel under, when they were.
    /// </summary>
    public uint DtmfPayloadType;
    /// <summary>
    /// A SipralRtcp.
    /// </summary>
    public uint Rtcp;
    /// <summary>
    /// Whether the stream is keyed.
    /// </summary>
    public uint Secured;
    /// <summary>
    /// Whether a recording is running on this call.
    /// </summary>
    public uint Recording;
    /// <summary>
    /// How much audio it has taken.
    /// </summary>
    public ulong RecordedMs;
    /// <summary>
    /// Whether the watchdog currently considers inbound audio stopped.
    /// </summary>
    public uint Stalled;
    /// <summary>
    /// Whether the call agreed a real-time text stream (RFC 4103), which
    /// `sipral_media_send_text` writes to.
    /// </summary>
    public uint HasText;
    /// <summary>
    /// Whether the audio stream runs RTP/AVPF (RFC 4585): both ends named
    /// a feedback profile.
    /// </summary>
    public uint Feedback;
    /// <summary>
    /// Whether both ends agreed Generic NACKs (`a=rtcp-fb:* nack`), so
    /// that a gap in what arrives is asked for again.
    /// </summary>
    public uint GenericNack;
    /// <summary>
    /// Whether both ends agreed reduced-size RTCP (RFC 5506,
    /// `a=rtcp-rsize`).
    /// </summary>
    public uint ReducedSize;
    /// <summary>
    /// Zero. Pads to the alignment so later members start past this
    /// header's length. Written zero, never read.
    /// </summary>
    public uint Reserved;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralMediaInfo Sized()
    {
        var value = default(SipralMediaInfo);
        value.Size = (nuint)Marshal.SizeOf<SipralMediaInfo>();
        return value;
    }
}

/// <summary>
/// What one call's media has cost, and what it is costing now.
///
/// Cheap enough to read at UI frame rate. The same struct arrives with
/// `SIPRAL_EVENT_KIND_MEDIA_STATISTICS` when the call ends. Delays are in
/// microseconds, since healthy jitter is below a millisecond.
///
/// Set `size` to `sizeof(sipral_stream_stats_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralStreamStats
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// A SipralCodec: what the call settled on.
    /// </summary>
    public uint Codec;
    /// <summary>
    /// Whether a round-trip time is known. Zero until a report comes back,
    /// which may be never (RFC 3550 §6.2 delays the first one).
    /// </summary>
    public uint HasRoundTrip;
    /// <summary>
    /// The round trip, from RTCP.
    /// </summary>
    public ulong RoundTripUs;
    /// <summary>
    /// Packets this end has put on the wire.
    /// </summary>
    public ulong PacketsSent;
    /// <summary>
    /// Payload octets in them, not counting headers.
    /// </summary>
    public ulong OctetsSent;
    /// <summary>
    /// Packets taken in and held for playout.
    /// </summary>
    public ulong PacketsReceived;
    /// <summary>
    /// Sequence numbers that came due with nothing in them.
    /// </summary>
    public ulong PacketsLost;
    /// <summary>
    /// Packets that arrived behind the playout point.
    /// </summary>
    public ulong PacketsLate;
    /// <summary>
    /// Packets thrown out of the window before they could be played.
    /// </summary>
    public ulong PacketsOverflowed;
    /// <summary>
    /// Packets whose sequence number was already held.
    /// </summary>
    public ulong PacketsDuplicated;
    /// <summary>
    /// Packets accepted after a higher sequence number had already arrived.
    /// </summary>
    public ulong PacketsReordered;
    /// <summary>
    /// Frames dropped in a pause to bring the delay down.
    /// </summary>
    public ulong FramesShrunk;
    /// <summary>
    /// Frames concealment invented in a pause to push the delay up.
    /// </summary>
    public ulong FramesStretched;
    /// <summary>
    /// How far behind the newest packet the playout point is.
    /// </summary>
    public ulong DelayUs;
    /// <summary>
    /// What the buffer is aiming at, from the arrival times it has seen.
    /// </summary>
    public ulong TargetDelayUs;
    /// <summary>
    /// Interarrival jitter, the smoothed mean deviation of transit time
    /// (RFC 3550 §6.4.1).
    /// </summary>
    public ulong JitterUs;
    /// <summary>
    /// Frames concealed as a fraction of frames played, over about the last
    /// ten seconds.
    /// </summary>
    public float LossRate;
    /// <summary>
    /// 100 for a flawless call, 0 for an unusable one. Not a MOS.
    /// </summary>
    public float Score;
    /// <summary>
    /// Whether the numbers say this call is in trouble now.
    /// </summary>
    public uint Suffering;
    /// <summary>
    /// How long since a packet last arrived. A live call sits at one frame.
    /// </summary>
    public ulong SilentForMs;
    /// <summary>
    /// Whether an RFC 3611 VoIP Metrics report is available. Every `voip_*`
    /// member is meaningless while this is zero.
    /// </summary>
    public uint HasVoipMetrics;
    /// <summary>
    /// RFC 3611 SS4.7.1's loss rate, as its own 256ths (multiply by
    /// 100 and divide by 256 for a percentage).
    /// </summary>
    public uint VoipLossRate256;
    /// <summary>
    /// RFC 3611 SS4.7.1's discard rate, as its own 256ths.
    /// </summary>
    public uint VoipDiscardRate256;
    /// <summary>
    /// RFC 3611 SS4.7.2's burst density, as its own 256ths.
    /// </summary>
    public uint VoipBurstDensity256;
    /// <summary>
    /// RFC 3611 SS4.7.2's mean burst duration.
    /// </summary>
    public ulong VoipBurstDurationUs;
    /// <summary>
    /// RFC 3611 SS4.7.2's gap density, as its own 256ths.
    /// </summary>
    public uint VoipGapDensity256;
    /// <summary>
    /// RFC 3611 SS4.7.2's mean gap duration.
    /// </summary>
    public ulong VoipGapDurationUs;
    /// <summary>
    /// RFC 3611 SS4.7.2's `Gmin`, the burst/gap threshold, fixed per stream.
    /// </summary>
    public uint VoipGmin;
    /// <summary>
    /// RFC 3611 SS4.7.3's end-system delay. Always zero: it needs the
    /// sending side's delay, which this end cannot see.
    /// </summary>
    public ulong VoipEndSystemDelayUs;
    /// <summary>
    /// RFC 3611 SS4.7.7's nominal jitter buffer delay.
    /// </summary>
    public ulong VoipJitterBufferNominalUs;
    /// <summary>
    /// RFC 3611 SS4.7.7's current maximum jitter buffer delay.
    /// </summary>
    public ulong VoipJitterBufferMaximumUs;
    /// <summary>
    /// RFC 3611 SS4.7.7's absolute maximum jitter buffer delay.
    /// </summary>
    public ulong VoipJitterBufferAbsMaxUs;
    /// <summary>
    /// Whether `voip_r_factor` is available: zero when ITU-T G.113 has no
    /// `Ie`/`Bpl` for the codec (RFC 3611 SS4.7.5's `127` sentinel).
    /// </summary>
    public uint HasVoipRFactor;
    /// <summary>
    /// RFC 3611 SS4.7.5's R factor, `0..=100`.
    /// </summary>
    public uint VoipRFactor;
    /// <summary>
    /// Whether `voip_mos_lq_x10` is available, for the same reason as
    /// `has_voip_r_factor`.
    /// </summary>
    public uint HasVoipMosLq;
    /// <summary>
    /// RFC 3611 SS4.7.5's estimated listening-quality MOS, in tenths
    /// (`14..=50`).
    /// </summary>
    public uint VoipMosLqX10;
    /// <summary>
    /// Whether `voip_mos_cq_x10` is available, for the same reason.
    /// </summary>
    public uint HasVoipMosCq;
    /// <summary>
    /// RFC 3611 SS4.7.5's estimated conversational-quality MOS, in
    /// tenths.
    /// </summary>
    public uint VoipMosCqX10;
    /// <summary>
    /// Frames played empty because the jitter buffer ran dry while the far
    /// end was still sending. Not lost packets (`packets_lost`), so the
    /// `voip_*` rates miss it (RFC 3611 SS4.7.1 counts packets);
    /// `loss_rate`, `score` and `suffering` include it.
    /// </summary>
    public ulong FramesUnderrun;
    /// <summary>
    /// Whether the stream runs RTP/AVPF (RFC 4585). The counts below stay
    /// zero otherwise.
    /// </summary>
    public uint Feedback;
    /// <summary>
    /// The `trr-int` both ends agreed: the least time between two
    /// regular reports, in milliseconds. Zero for none.
    /// </summary>
    public uint TrrIntervalMs;
    /// <summary>
    /// Generic NACKs this end sent, each asking for one or more packets.
    /// </summary>
    public ulong NacksSent;
    /// <summary>
    /// The packets those NACKs asked for.
    /// </summary>
    public ulong PacketsNacked;
    /// <summary>
    /// Generic NACKs the far end sent.
    /// </summary>
    public ulong NacksReceived;
    /// <summary>
    /// The packets those asked this end for.
    /// </summary>
    public ulong PacketsAskedFor;
    /// <summary>
    /// Early RTCP packets this end sent.
    /// </summary>
    public ulong EarlyPackets;
    /// <summary>
    /// Reduced-size RTCP packets this end sent (RFC 5506).
    /// </summary>
    public ulong ReducedSizePackets;
    /// <summary>
    /// Feedback held back for lack of RTCP bandwidth.
    /// </summary>
    public ulong FeedbackSuppressed;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralStreamStats Sized()
    {
        var value = default(SipralStreamStats);
        value.Size = (nuint)Marshal.SizeOf<SipralStreamStats>();
        return value;
    }
}

/// <summary>
/// One datagram on its way out, written into the caller's own buffers.
///
/// The caller fills in `size`, the two pointers and the two capacities; the
/// library fills in the two lengths and the bytes. A `len` of zero means
/// nothing to send (held, or silence suppression). Both buffers are checked
/// before anything is produced.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralMediaPacket
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// Where to write the packet. At least SIPRAL_MEDIA_PACKET_BYTES.
    /// </summary>
    public IntPtr Data;
    /// <summary>
    /// How much room `data` has.
    /// </summary>
    public nuint Capacity;
    /// <summary>
    /// How much was written. Zero means there was nothing to send.
    /// </summary>
    public nuint Len;
    /// <summary>
    /// Where to write the destination, as `host:port` with a trailing NUL. Null
    /// with a capacity of zero for a caller that does not want it.
    /// </summary>
    public IntPtr Destination;
    /// <summary>
    /// How much room `destination` has. At least SIPRAL_ADDRESS_BYTES when
    /// it is not null.
    /// </summary>
    public nuint DestinationCapacity;
    /// <summary>
    /// How many bytes of it were written, the NUL not counted.
    /// </summary>
    public nuint DestinationLen;
    /// <summary>
    /// What to send it over, as a `SipralTransport`. `SIPRAL_TRANSPORT_UDP`
    /// is a datagram from the media socket. With a TURN server over TCP or
    /// TLS (`turn_transport`), relayed traffic says so, `destination` is the
    /// server, and the bytes go in order on that connection, never as a
    /// datagram.
    /// </summary>
    public uint Protocol;
    /// <summary>
    /// Zero. Pads to the alignment so later members start past this
    /// header's length. Set zero on input; written zero, never read.
    /// </summary>
    public uint Reserved;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralMediaPacket Sized()
    {
        var value = default(SipralMediaPacket);
        value.Size = (nuint)Marshal.SizeOf<SipralMediaPacket>();
        return value;
    }
}

/// <summary>
/// What SipralProcessorCallback is handed for one call: an ordinary
/// frame to process, or a request to forget what has been learned.
///
/// Library-owned, passed as a `const` pointer. Read `size` first; read
/// nothing after the callback returns, since the buffers are borrowed.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralProcessorFrame
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// 0 for an ordinary frame; 1 to forget learned state (device or codec
    /// change). When 1, all three buffers are null and lengths zero.
    /// </summary>
    public uint Reset;
    /// <summary>
    /// The frame just captured from the microphone. Null on reset.
    /// </summary>
    public IntPtr NearEnd;
    /// <summary>
    /// Samples in `near_end`; always equal to `far_end_len` and `out_len`.
    /// 0 on reset.
    /// </summary>
    public nuint NearEndLen;
    /// <summary>
    /// The far-end audio played over the same span as `near_end`. Null on
    /// reset.
    /// </summary>
    public IntPtr FarEnd;
    /// <summary>
    /// Samples in `far_end`. 0 on reset.
    /// </summary>
    public nuint FarEndLen;
    /// <summary>
    /// Where the callback writes the replacement for `near_end`; every
    /// sample must be written. Null on reset.
    /// </summary>
    public IntPtr Out;
    /// <summary>
    /// Samples `out` holds, all of which must be written. 0 on reset.
    /// </summary>
    public nuint OutLen;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralProcessorFrame Sized()
    {
        var value = default(SipralProcessorFrame);
        value.Size = (nuint)Marshal.SizeOf<SipralProcessorFrame>();
        return value;
    }
}

/// <summary>
/// One message on its way out, written into the caller's own buffers.
///
/// The caller fills `size`, the three pointers and the three capacities; the library fills
/// the rest. A `len` of zero means nothing to send, which ends the draining loop. Address
/// buffers are checked before a message is taken. A payload buffer too small leaves the
/// message queued and offered again: a committed message is never dropped.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralTransmit
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// Which transport to write to: SIPRAL_TRANSPORT_MAIN, or a number
    /// sipral_stack_transport_bind bound for the owning account or call.
    /// </summary>
    public uint Transport;
    /// <summary>
    /// What that transport speaks, as a `SipralTransport`. Per message, since §18.1.1
    /// can move a request onto a stream. Zero for a protocol with no ABI number.
    /// </summary>
    public uint Protocol;
    /// <summary>
    /// Where to write the message. Nothing is written unless all of it fits.
    /// </summary>
    public IntPtr Data;
    /// <summary>
    /// How much room `data` has.
    /// </summary>
    public nuint Capacity;
    /// <summary>
    /// How much was written, or after `SIPRAL_STATUS_BUFFER_TOO_SMALL`, how much is needed.
    /// </summary>
    public nuint Len;
    /// <summary>
    /// Where to write the destination, `host:port` with a trailing NUL. Null with capacity zero
    /// for a connected socket.
    /// </summary>
    public IntPtr Destination;
    /// <summary>
    /// Room in `destination`: at least SIPRAL_ADDRESS_BYTES when not null.
    /// </summary>
    public nuint DestinationCapacity;
    /// <summary>
    /// How many bytes of it were written, the NUL not counted.
    /// </summary>
    public nuint DestinationLen;
    /// <summary>
    /// Where to write the address to send *from*, in the same shape. RFC 3581 §4: a response
    /// leaves from the address its request arrived on, which a wildcard listener cannot tell.
    /// `source_len` zero means the transport's own address.
    /// </summary>
    public IntPtr Source;
    /// <summary>
    /// Room in `source`: at least SIPRAL_ADDRESS_BYTES when not null.
    /// </summary>
    public nuint SourceCapacity;
    /// <summary>
    /// How many bytes of it were written, the NUL not counted.
    /// </summary>
    public nuint SourceLen;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralTransmit Sized()
    {
        var value = default(SipralTransmit);
        value.Size = (nuint)Marshal.SizeOf<SipralTransmit>();
        return value;
    }
}

/// <summary>
/// A failed transport and why, for sipral_stack_transport_failed_with. All caller-filled;
/// `detail` is the platform's own optional sentence, passed through unparsed.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralTransportFailure
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// Which transport: SIPRAL_TRANSPORT_MAIN or a bound number.
    /// </summary>
    public uint Transport;
    /// <summary>
    /// A SipralTransportError.
    /// </summary>
    public uint Error;
    /// <summary>
    /// A SipralTlsFailure; `SIPRAL_TLS_FAILURE_NONE` unless TLS refused.
    /// </summary>
    public uint Tls;
    /// <summary>
    /// The platform's words, not NUL-terminated. Null with length zero for none.
    /// </summary>
    public IntPtr Detail;
    /// <summary>
    /// How many bytes of it; at most SIPRAL_TRANSPORT_DETAIL_BYTES.
    /// </summary>
    public nuint DetailLen;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralTransportFailure Sized()
    {
        var value = default(SipralTransportFailure);
        value.Size = (nuint)Marshal.SizeOf<SipralTransportFailure>();
        return value;
    }
}

/// <summary>
/// What a SipralEventKind.RegistrationChanged carries.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralRegistrationEvent
{
    /// <summary>
    /// A SipralRegistrationState.
    /// </summary>
    public uint State;
    /// <summary>
    /// A SipralRegistrationFailure, zero when nothing failed.
    /// </summary>
    public uint Failure;
    /// <summary>
    /// The status the registrar answered with, or zero when none arrived.
    /// </summary>
    public uint StatusCode;
    /// <summary>
    /// The binding's granted lifetime, zero unless it is live.
    /// </summary>
    public ulong ExpiresMs;
    /// <summary>
    /// How long until the refresh, zero unless one is scheduled.
    /// </summary>
    public ulong RefreshInMs;
    /// <summary>
    /// How long until the next attempt; meaningful only while retrying.
    /// </summary>
    public ulong RetryInMs;
}

/// <summary>
/// What every call event carries. Members that do not apply are zero,
/// and zero always means absent.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralCallEvent
{
    /// <summary>
    /// A SipralCallState.
    /// </summary>
    public uint State;
    /// <summary>
    /// A SipralCallEndReason, zero while the call is alive.
    /// </summary>
    public uint EndReason;
    /// <summary>
    /// The status a response carried, or zero.
    /// </summary>
    public uint StatusCode;
    /// <summary>
    /// The other call this event is also about: the sibling of a fork, or the
    /// call that was replaced. SIPRAL_HANDLE_NONE otherwise.
    /// </summary>
    public ulong Other;
    /// <summary>
    /// Whether this end has asked the far end to stop sending.
    /// </summary>
    public uint HeldHere;
    /// <summary>
    /// Whether the far end has asked this one to.
    /// </summary>
    public uint HeldThere;
    /// <summary>
    /// What this end is describing, and how long it is.
    /// </summary>
    public IntPtr LocalSdp;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint LocalSdpLen;
    /// <summary>
    /// And what the far end is.
    /// </summary>
    public IntPtr RemoteSdp;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint RemoteSdpLen;
    /// <summary>
    /// When a refused session change goes out again by itself, zero when it is
    /// not going to.
    /// </summary>
    public ulong RetryInMs;
    /// <summary>
    /// The creating request's `From` URI, as written, without brackets or
    /// header parameters. Null and zero when unavailable.
    /// </summary>
    public IntPtr FromUri;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint FromUriLen;
    /// <summary>
    /// That `From`'s display name, quotes and backslash escapes resolved
    /// (RFC 3261 §25.1). Null and zero when the header named none.
    /// </summary>
    public IntPtr FromDisplay;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint FromDisplayLen;
    /// <summary>
    /// The `To` URI of the request that created this call, as written in
    /// the header.
    /// </summary>
    public IntPtr ToUri;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ToUriLen;
    /// <summary>
    /// The `Call-ID` of the request that created this call.
    /// </summary>
    public IntPtr CallId;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint CallIdLen;
    /// <summary>
    /// The digit an INFO this end sent named, for
    /// SipralEventKind.DtmfSent. Zero for every other kind.
    /// </summary>
    public uint Digit;
    /// <summary>
    /// For SipralEventKind.CallEnded: the SIP cause in the far end's
    /// `Reason` (RFC 3326). 200 on a CANCEL means answered elsewhere.
    /// </summary>
    public uint CauseSip;
    /// <summary>
    /// The Q.850 cause from `Reason` (16 normal, 17 busy), or zero.
    /// </summary>
    public uint CauseQ850;
    /// <summary>
    /// The `text` of the first `Reason` value, unquoted. Null and zero
    /// when there was none.
    /// </summary>
    public IntPtr CauseText;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint CauseTextLen;
    /// <summary>
    /// Whether an incoming INVITE came from a `trusted_peers` peer. If not,
    /// the asserted identity and `verstat` are empty (RFC 3325 §8).
    /// </summary>
    public uint IdentityTrusted;
    /// <summary>
    /// The first `P-Asserted-Identity`, else a `Remote-Party-ID`, as
    /// written. Null and zero when none.
    /// </summary>
    public IntPtr AssertedUri;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint AssertedUriLen;
    /// <summary>
    /// That identity's display name. Null and zero when it named none.
    /// </summary>
    public IntPtr AssertedDisplay;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint AssertedDisplayLen;
    /// <summary>
    /// A SipralVerstat: what the
    /// network concluded about the caller's number.
    /// </summary>
    public uint Verstat;
    /// <summary>
    /// The `SIPRAL_PRIVACY_*` bits the caller's `Privacy` asked for.
    /// </summary>
    public uint Privacy;
    /// <summary>
    /// The top-most `Diversion` (RFC 5806), as written. Null and zero
    /// when none.
    /// </summary>
    public IntPtr DivertedFrom;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint DivertedFromLen;
    /// <summary>
    /// Why: its `reason`. Null and zero when none.
    /// </summary>
    public IntPtr DiversionReason;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint DiversionReasonLen;
    /// <summary>
    /// How many `Diversion` values the INVITE carried.
    /// </summary>
    public uint DiversionCount;
    /// <summary>
    /// How many `History-Info` entries it carried.
    /// </summary>
    public uint HistoryCount;
    /// <summary>
    /// A SipralAnswerMode: the
    /// INVITE's `Answer-Mode` (RFC 5373).
    /// </summary>
    public uint AnswerMode;
    /// <summary>
    /// Whether that field said `;require`: the caller would rather the
    /// call be refused, with a 403, than answered any other way.
    /// </summary>
    public uint AnswerModeRequired;
    /// <summary>
    /// The same for `Priv-Answer-Mode`, which RFC 5373 §4.2 holds to a
    /// stricter policy.
    /// </summary>
    public uint PrivAnswerMode;
    /// <summary>
    /// Whether that field said `;require`.
    /// </summary>
    public uint PrivAnswerModeRequired;
    /// <summary>
    /// Whether the call asked to be auto-answered after `answer_after_ms`
    /// (`Answer-Mode: Auto`, `answer-after`, `info=alert-autoanswer`).
    /// </summary>
    public uint HasAnswerAfter;
    /// <summary>
    /// After how long, when `has_answer_after` is set.
    /// </summary>
    public ulong AnswerAfterMs;
    /// <summary>
    /// A SipralRingSource: whether
    /// the ring says the caller is internal or external.
    /// </summary>
    public uint RingSource;
    /// <summary>
    /// The first `Alert-Info` URI, without the angle brackets. Null and
    /// zero when none. `sipral_call_identity_text` reads the rest.
    /// </summary>
    public IntPtr AlertInfo;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint AlertInfoLen;
    /// <summary>
    /// A SipralVerificationOutcome: this stack's own verdict (RFC 8224
    /// §6.2), unlike the network's `verstat`. Zero when not verified.
    /// </summary>
    public uint Verification;
    /// <summary>
    /// A SipralAttestation: the
    /// level a valid SHAKEN PASSporT claimed.
    /// </summary>
    public uint Attestation;
    /// <summary>
    /// A SipralVerificationFailure: why the verdict did not hold.
    /// </summary>
    public uint VerificationFailure;
}

/// <summary>
/// What a transfer event carries.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralTransferEvent
{
    /// <summary>
    /// What the far end's own call is doing, or zero.
    /// </summary>
    public uint StatusCode;
    /// <summary>
    /// Whether the request named a dialog to replace, which is what makes a
    /// transfer attended rather than blind.
    /// </summary>
    public uint Attended;
    /// <summary>
    /// Who to call, as UTF-8. Not NUL-terminated.
    /// </summary>
    public IntPtr Target;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint TargetLen;
}

/// <summary>
/// What a media event carries. Members that do not apply are zero or null.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralMediaEvent
{
    /// <summary>
    /// A SipralCodec: what the negotiation
    /// settled on, zero where the event is not about a codec.
    /// </summary>
    public uint Codec;
    /// <summary>
    /// A SipralDirection: which way audio
    /// may flow, as seen from here.
    /// </summary>
    public uint Direction;
    /// <summary>
    /// How long the stream has been silent, for a stall and for its recovery.
    /// </summary>
    public ulong SilentForMs;
    /// <summary>
    /// How much audio reached the file, for a recording that stopped by
    /// itself.
    /// </summary>
    public ulong RecordedMs;
    /// <summary>
    /// A SipralMediaFault, zero when
    /// nothing failed.
    /// </summary>
    public uint Fault;
    /// <summary>
    /// The sentence behind `fault`, as UTF-8. Not NUL-terminated, and null
    /// when nothing failed.
    /// </summary>
    public IntPtr Reason;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ReasonLen;
    /// <summary>
    /// What the stream cost, for the kind that carries it, and null for every
    /// other. It belongs to the library and lives as long as the callback.
    /// </summary>
    public IntPtr Statistics;
    /// <summary>
    /// The key the far end pressed, as its character, and zero for an event
    /// no keypad has a key for.
    /// </summary>
    public uint Digit;
    /// <summary>
    /// The RFC 4733 event code behind `digit`. Codes at and above sixteen are
    /// real events that are not keys.
    /// </summary>
    public uint EventCode;
    /// <summary>
    /// How long the key was held. Zero for no duration or `Duration=0`.
    /// </summary>
    public ulong HeldMs;
    /// <summary>
    /// A SipralSrtpSuite, for SipralEventKind.MediaSecured and the
    /// encryption report.
    /// </summary>
    public uint Suite;
    /// <summary>
    /// A SipralDigitSource: which of the two ways this stack accepts a
    /// digit reported this one, for SipralEventKind.DigitReceived.
    /// </summary>
    public uint Source;
    /// <summary>
    /// Whether the RFC 6035 PUBLISH left this end, for
    /// SipralEventKind.QualityReportSent.
    /// </summary>
    public uint QualityReportSent;
    /// <summary>
    /// A SipralKeyExchange, on the start, change and secure kinds.
    /// </summary>
    public uint KeyExchange;
    /// <summary>
    /// Whether the stream is encrypted now; zero until a DTLS-SRTP
    /// handshake ends.
    /// </summary>
    public uint Encrypted;
    /// <summary>
    /// Whether DTLS-SRTP checked the far end's certificate against the
    /// fingerprint. Never for SDES.
    /// </summary>
    public uint Authenticated;
}

/// <summary>
/// What a SipralEventKind.Recovery carries.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralRecoveryEvent
{
    /// <summary>
    /// A SipralRecoveryOutcome.
    /// </summary>
    public uint State;
    /// <summary>
    /// A SipralRecoveryRung: the last rung tried. Zero unless `state`
    /// is SipralRecoveryOutcome.GaveUp.
    /// </summary>
    public uint Rung;
    /// <summary>
    /// A SipralRecoveryFailure. Zero unless `state` is
    /// SipralRecoveryOutcome.GaveUp.
    /// </summary>
    public uint Reason;
    /// <summary>
    /// Bindings the ladder never proved. Meaningful only when `state` is
    /// SipralRecoveryOutcome.GaveUp.
    /// </summary>
    public uint Unverified;
}

/// <summary>
/// What a SipralEventKind.TransportWanted carries: a request RFC
/// 3261 §18.1.1 kept off a datagram, with no stream open for it.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralTransportWantedEvent
{
    /// <summary>
    /// What to open, as a SipralTransport; zero for an unknown one.
    /// </summary>
    public uint Protocol;
    /// <summary>
    /// Where to, as `host:port`. Not NUL-terminated.
    /// </summary>
    public IntPtr Destination;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint DestinationLen;
    /// <summary>
    /// The request's size in bytes, as it would go on the wire.
    /// </summary>
    public nuint RequestBytes;
    /// <summary>
    /// The largest size that fits a datagram: path MTU less the §18.1.1
    /// headroom, or 1300 when the MTU is unknown.
    /// </summary>
    public uint LimitBytes;
}

/// <summary>
/// What a SipralEventKind.SubscriptionChanged and a
/// SipralEventKind.Notified carry.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralSubscriptionEvent
{
    /// <summary>
    /// Which subscription, minted by `sipral_account_subscribe` or by this
    /// ABI for a fork sibling.
    /// </summary>
    public ulong Subscription;
    /// <summary>
    /// A SipralSubscriptionState.
    /// </summary>
    public uint State;
    /// <summary>
    /// A SipralSubscriptionEnd:
    /// why it is not live. Zero while it is.
    /// </summary>
    public uint Reason;
    /// <summary>
    /// The SIP status a response gave for it, when one did. Zero
    /// otherwise.
    /// </summary>
    public uint StatusCode;
    /// <summary>
    /// Whether the notification carried readable dialog state. Zero on
    /// every kind but SipralEventKind.Notified.
    /// </summary>
    public uint HasDialogInfo;
    /// <summary>
    /// What the notifier granted, in milliseconds. Zero until one has.
    /// </summary>
    public ulong ExpiresMs;
    /// <summary>
    /// How long until this stack refreshes it, in milliseconds.
    /// </summary>
    public ulong RefreshInMs;
    /// <summary>
    /// How long until the next attempt, in milliseconds, when the state
    /// is `SIPRAL_SUBSCRIPTION_STATE_RETRYING`. Zero otherwise.
    /// </summary>
    public ulong RetryInMs;
    /// <summary>
    /// The subscription this one forked from (RFC 6665 §4.1.4), or
    /// `SIPRAL_HANDLE_NONE`. A sibling is a full subscription (RFC 4235
    /// §3.9: one per device).
    /// </summary>
    public ulong ForkedFrom;
}

/// <summary>
/// What a SipralEventKind.CallAnnounced and a
/// SipralEventKind.AnnouncedCallMissing carry.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralAnnounceEvent
{
    /// <summary>
    /// Which announcement, minted by `sipral_account_announce`. Stale once
    /// either of these two events has been raised about it.
    /// </summary>
    public ulong Announcement;
    /// <summary>
    /// How long the call was waited for, in milliseconds. Meaningful only
    /// on SipralEventKind.AnnouncedCallMissing.
    /// </summary>
    public ulong WaitedMs;
}

/// <summary>
/// What a SipralEventKind.ResolveNeeded carries: the name a dialog's
/// next hop is written as, and the handle an answer takes.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralResolveEvent
{
    /// <summary>
    /// The handle
    /// sipral_stack_resolved
    /// takes; stale once the dialog ends.
    /// </summary>
    public ulong Dialog;
    /// <summary>
    /// The host as the URI spells it; IPv6 literals keep brackets (RFC
    /// 3261 §19.1.1). Not NUL-terminated.
    /// </summary>
    public IntPtr Host;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint HostLen;
    /// <summary>
    /// The URI's port, or zero for none. Zero is not 5060: an SRV answer
    /// carries its own port (RFC 3263 §4.2).
    /// </summary>
    public uint Port;
    /// <summary>
    /// The transport named, as a SipralTransport, or zero, leaving
    /// §4.1's NAPTR step to the caller.
    /// </summary>
    public uint Protocol;
}

/// <summary>
/// What the three message kinds carry; inapplicable members are zero.
/// `content_type` and `body` point into `sipral_event_t::message`.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralMessageEvent
{
    /// <summary>
    /// SipralEventKind.MessageSent: which send; stale after this.
    /// </summary>
    public ulong Message;
    /// <summary>
    /// SipralEventKind.MessagesWaiting: which subscription reported
    /// it. SIPRAL_HANDLE_NONE on the other kinds.
    /// </summary>
    public ulong Subscription;
    /// <summary>
    /// SipralEventKind.MessageSent: the final status. Zero on the
    /// other two kinds.
    /// </summary>
    public uint StatusCode;
    /// <summary>
    /// SipralEventKind.MessageReceived: the body's `Content-Type`, as
    /// written. Null on the other kinds and for an empty MESSAGE.
    /// </summary>
    public IntPtr ContentType;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ContentTypeLen;
    /// <summary>
    /// SipralEventKind.MessageReceived: the body. Null the same as
    /// `content_type`.
    /// </summary>
    public IntPtr Body;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint BodyLen;
    /// <summary>
    /// SipralEventKind.MessagesWaiting: RFC 3842 §3.5's status
    /// line, 1 for `yes` and 0 for `no`.
    /// </summary>
    public uint Waiting;
    /// <summary>
    /// SipralEventKind.MessagesWaiting: new `voice-message` messages
    /// (RFC 3458 §6.2). Zero when the body had no such line.
    /// </summary>
    public uint NewMessages;
    /// <summary>
    /// The same, old.
    /// </summary>
    public uint OldMessages;
    /// <summary>
    /// New messages flagged urgent.
    /// </summary>
    public uint UrgentNewMessages;
    /// <summary>
    /// Old messages flagged urgent.
    /// </summary>
    public uint UrgentOldMessages;
    /// <summary>
    /// SipralEventKind.MessagesWaiting: `Message-Account`, when sent
    /// (RFC 3842 §3.5). Null otherwise.
    /// </summary>
    public IntPtr MessageAccount;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint MessageAccountLen;
}

/// <summary>
/// What a SipralEventKind.NatMapping carries.
/// The addresses are `host:port`, not NUL-terminated, valid only during the callback.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralNatEvent
{
    /// <summary>
    /// A SipralNatMapping.
    /// </summary>
    public uint Mapping;
    /// <summary>
    /// Nonzero for a signalling socket, zero for a media socket.
    /// </summary>
    public uint Signalling;
    /// <summary>
    /// The transport, when `signalling` is nonzero; zero otherwise.
    /// </summary>
    public uint Transport;
    /// <summary>
    /// How many accounts' `Contact` moved to `public`; bound ones have registered it already.
    /// </summary>
    public uint Accounts;
    /// <summary>
    /// The socket, as the application named it.
    /// </summary>
    public IntPtr Local;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint LocalLen;
    /// <summary>
    /// The public address. Empty for `SIPRAL_NAT_MAPPING_UNANSWERED`.
    /// </summary>
    public IntPtr Mapped;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint MappedLen;
    /// <summary>
    /// The old address, for `SIPRAL_NAT_MAPPING_MOVED`. Empty otherwise.
    /// </summary>
    public IntPtr Previous;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint PreviousLen;
}

/// <summary>
/// What a SipralEventKind.NatRelay carries.
/// Text is not NUL-terminated, valid only during the callback, and holds no credential.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralNatRelayEvent
{
    /// <summary>
    /// A SipralNatRelay.
    /// </summary>
    public uint Outcome;
    /// <summary>
    /// For `SIPRAL_NAT_RELAY_FAILED`, the STUN error code (401 bad credential, 486 quota, 508
    /// no capacity), or zero when there was no usable answer. Zero for `ALLOCATED`.
    /// </summary>
    public uint Code;
    /// <summary>
    /// The media socket, as `sipral_stack_nat_map` named it.
    /// </summary>
    public IntPtr Local;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint LocalLen;
    /// <summary>
    /// The relayed `host:port`. Empty for `SIPRAL_NAT_RELAY_FAILED`.
    /// </summary>
    public IntPtr Relayed;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint RelayedLen;
    /// <summary>
    /// Where the server saw the socket from, when it said. Empty otherwise.
    /// </summary>
    public IntPtr Mapped;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint MappedLen;
    /// <summary>
    /// Why there is no relay, in English. Empty for `SIPRAL_NAT_RELAY_ALLOCATED`.
    /// </summary>
    public IntPtr Reason;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ReasonLen;
}

/// <summary>
/// What a SipralEventKind.Referral carries: a REFER outside any
/// dialog, or the word that one lapsed.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralReferralEvent
{
    /// <summary>
    /// Zero while the referral waits. On the lapse event, the status the
    /// stack answered (408), and every other member is zero or null.
    /// </summary>
    public uint StatusCode;
    /// <summary>
    /// Whether `Refer-To` named a dialog to replace (RFC 3891): an
    /// attended transfer.
    /// </summary>
    public uint Attended;
    /// <summary>
    /// Who to call, as UTF-8. Not NUL-terminated.
    /// </summary>
    public IntPtr Target;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint TargetLen;
    /// <summary>
    /// Its `Referred-By` (RFC 3892), UTF-8, unverified. Null when absent or
    /// repeated (§2.1). Not NUL-terminated.
    /// </summary>
    public IntPtr ReferredBy;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ReferredByLen;
}

/// <summary>
/// What a SipralEventKind.TurnStream carries.
/// Addresses are not NUL-terminated, valid only during the callback.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralTurnStreamEvent
{
    /// <summary>
    /// A SipralTurnStream.
    /// </summary>
    public uint State;
    /// <summary>
    /// `SIPRAL_TRANSPORT_TCP` or `SIPRAL_TRANSPORT_TLS`, as `turn_transport` named.
    /// </summary>
    public uint Protocol;
    /// <summary>
    /// The media socket; the connection's name in the calls that take one.
    /// </summary>
    public IntPtr Local;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint LocalLen;
    /// <summary>
    /// The TURN server, `host:port`, as `turn_server` named it.
    /// </summary>
    public IntPtr Server;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ServerLen;
}

/// <summary>
/// What `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED` carries.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralAudioEvent
{
    /// <summary>
    /// A `SipralAudioChange`.
    /// </summary>
    public uint Change;
    /// <summary>
    /// A `SipralAudioOrigin`.
    /// </summary>
    public uint Origin;
    /// <summary>
    /// A `SipralAudioRole`, for a change about one role; zero otherwise.
    /// </summary>
    public uint Role;
    /// <summary>
    /// A `SipralAudioDirection`, for `SIPRAL_AUDIO_CHANGE_DEFAULT_CHANGED`;
    /// zero otherwise.
    /// </summary>
    public uint Direction;
    /// <summary>
    /// The device the change is about, or zero.
    /// </summary>
    public uint Device;
}

/// <summary>
/// What a SipralEventKind.StunServer carries.
/// Addresses are not NUL-terminated, valid only during the callback.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralStunServerEvent
{
    /// <summary>
    /// A SipralStunServerState.
    /// </summary>
    public uint State;
    /// <summary>
    /// The server in use now (`CHANGED`) or the last that failed (`ALL_FAILED`).
    /// </summary>
    public IntPtr Server;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ServerLen;
    /// <summary>
    /// For `CHANGED`, the previous server. Empty otherwise.
    /// </summary>
    public IntPtr Previous;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint PreviousLen;
}

/// <summary>
/// What a SipralEventKind.CallerVerification carries: one half of
/// the verification of who is calling (RFC 8224 §6.2).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralVerificationEvent
{
    /// <summary>
    /// A SipralVerificationStage:
    /// the certificate is wanted, or the verdict is in.
    /// </summary>
    public uint Stage;
    /// <summary>
    /// A SipralVerificationOutcome,
    /// for a verdict.
    /// </summary>
    public uint Outcome;
    /// <summary>
    /// A SipralVerificationFailure:
    /// why it did not hold.
    /// </summary>
    public uint Failure;
    /// <summary>
    /// A SipralAttestation: the
    /// level a valid SHAKEN PASSporT claimed.
    /// </summary>
    public uint Attestation;
    /// <summary>
    /// A SipralVerstat: the `verstat`
    /// this verdict comes to (3GPP TS 24.229).
    /// </summary>
    public uint Verstat;
    /// <summary>
    /// The response RFC 8224 §6.2.2 prescribes for the failure, zero for
    /// a valid one. Sent only when `refused` is set.
    /// </summary>
    public uint ResponseCode;
    /// <summary>
    /// Whether the call was refused with it, which only a strict account
    /// does.
    /// </summary>
    public uint Refused;
    /// <summary>
    /// The certificate URL: to fetch, or that was verified. UTF-8, not
    /// NUL-terminated; null and zero when none.
    /// </summary>
    public IntPtr CertificateUrl;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint CertificateUrlLen;
    /// <summary>
    /// The calling number a valid PASSporT was signed for, canonical.
    /// </summary>
    public IntPtr Orig;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint OrigLen;
    /// <summary>
    /// The origination identifier a valid SHAKEN PASSporT claimed (RFC
    /// 8588 §5), a UUID.
    /// </summary>
    public IntPtr Origid;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint OrigidLen;
    /// <summary>
    /// Why it did not hold, in more words than `failure`, for a log.
    /// </summary>
    public IntPtr Detail;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint DetailLen;
}

/// <summary>
/// What a SipralEventKind.ProgressDetected carries. `what` says
/// which of the other members mean anything; the rest are zero.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralProgressEvent
{
    /// <summary>
    /// A SipralProgressKind.
    /// </summary>
    public uint What;
    /// <summary>
    /// A SipralProgressTone, for a tone.
    /// </summary>
    public uint Tone;
    /// <summary>
    /// A SipralAmdVerdict, for who answered.
    /// </summary>
    public uint Verdict;
    /// <summary>
    /// A SipralAmdReason, for who answered.
    /// </summary>
    public uint Reason;
    /// <summary>
    /// When, in milliseconds: the tone's first burst, or after answer.
    /// </summary>
    public ulong AtMs;
    /// <summary>
    /// How long after answer the first word began, or the silence if
    /// nobody spoke.
    /// </summary>
    public ulong InitialSilenceMs;
    /// <summary>
    /// From the first word's start to the last word's end.
    /// </summary>
    public ulong GreetingMs;
    /// <summary>
    /// How many words were heard.
    /// </summary>
    public uint Words;
    /// <summary>
    /// The beep's frequency, in hertz, as measured.
    /// </summary>
    public uint FrequencyHz;
    /// <summary>
    /// How long the beep sounded.
    /// </summary>
    public ulong LengthMs;
    /// <summary>
    /// The special information tone's first frequency, as measured.
    /// </summary>
    public uint SitHz1;
    /// <summary>
    /// Its second.
    /// </summary>
    public uint SitHz2;
    /// <summary>
    /// Its third.
    /// </summary>
    public uint SitHz3;
    /// <summary>
    /// How long the first sounded.
    /// </summary>
    public uint SitMs1;
    /// <summary>
    /// The second.
    /// </summary>
    public uint SitMs2;
    /// <summary>
    /// The third.
    /// </summary>
    public uint SitMs3;
}

/// <summary>
/// What a SipralEventKind.ConferenceChanged carries.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralConferenceEvent
{
    /// <summary>
    /// Which subscription.
    /// </summary>
    public ulong Subscription;
    /// <summary>
    /// A SipralConferenceUpdate.
    /// </summary>
    public uint Update;
    /// <summary>
    /// The current document version; zero once ended.
    /// </summary>
    public uint Version;
    /// <summary>
    /// How many users the picture holds.
    /// </summary>
    public uint Users;
}

/// <summary>
/// What a SipralEventKind.TextReceived carries; the
/// text is valid during the callback.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralTextEvent
{
    /// <summary>
    /// What the far end typed, UTF-8, not NUL-terminated.
    /// </summary>
    public IntPtr Text;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint TextLen;
    /// <summary>
    /// Unrecoverable lost blocks, each marked in `text` by U+FFFD.
    /// </summary>
    public uint Missing;
}

/// <summary>
/// What a SipralEventKind.PresenceChanged carries. The
/// text is valid only during the callback.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralPresenceEvent
{
    /// <summary>
    /// A SipralPresenceKind.
    /// </summary>
    public uint Kind;
    /// <summary>
    /// SipralPresenceKind.Watched: which subscription;
    /// `SIPRAL_HANDLE_NONE` for a publication.
    /// </summary>
    public ulong Subscription;
    /// <summary>
    /// SipralPresenceKind.Watched: a SipralBasic, open when any
    /// of the presentity's tuples is open.
    /// </summary>
    public uint Basic;
    /// <summary>
    /// SipralPresenceKind.Watched: a SipralActivity, the first
    /// the person listed.
    /// </summary>
    public uint Activity;
    /// <summary>
    /// SipralPresenceKind.Watched: the presentity, as the document
    /// named it. Not NUL-terminated.
    /// </summary>
    public IntPtr Entity;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint EntityLen;
    /// <summary>
    /// SipralPresenceKind.Watched: the first note, the document's
    /// own or else a tuple's. Null when there is none.
    /// </summary>
    public IntPtr Note;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint NoteLen;
    /// <summary>
    /// SipralPresenceKind.Publication: a SipralPublicationState.
    /// </summary>
    public uint PublicationState;
    /// <summary>
    /// SipralPresenceKind.Publication: a SipralPublishFailure
    /// when the state is SipralPublicationState.Failed.
    /// </summary>
    public uint Failure;
    /// <summary>
    /// SipralPresenceKind.Publication: the status the compositor
    /// answered with, when one did.
    /// </summary>
    public uint StatusCode;
    /// <summary>
    /// SipralPresenceKind.Publication: the lifetime granted, in
    /// milliseconds, when it was published.
    /// </summary>
    public ulong ExpiresMs;
    /// <summary>
    /// SipralPresenceKind.Publication: how long until the stack
    /// refreshes it, in milliseconds.
    /// </summary>
    public ulong RefreshInMs;
}

/// <summary>
/// `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`: a signalling transport stopped carrying traffic.
/// The text is the library's, valid during the callback.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralTransportFailedEvent
{
    /// <summary>
    /// Which transport: SIPRAL_TRANSPORT_MAIN or a bound number.
    /// </summary>
    public uint Transport;
    /// <summary>
    /// What it spoke, as a `SipralTransport`.
    /// </summary>
    public uint Protocol;
    /// <summary>
    /// A SipralTransportError; `SIPRAL_TRANSPORT_ERROR_CLOSED` for a closed connection.
    /// </summary>
    public uint Error;
    /// <summary>
    /// A SipralTlsFailure, when TLS refused.
    /// </summary>
    public uint Tls;
    /// <summary>
    /// The platform's sentence as handed over. Null with length zero for none.
    /// </summary>
    public IntPtr Detail;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint DetailLen;
}

/// <summary>
/// What a `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED` carries.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralLocalConferenceEvent
{
    /// <summary>
    /// The conference.
    /// </summary>
    public ulong Conference;
    /// <summary>
    /// A SipralLocalConferenceChange.
    /// </summary>
    public uint Change;
    /// <summary>
    /// A SipralDeparture, for `SIPRAL_LOCAL_CONFERENCE_CHANGE_LEFT`.
    /// </summary>
    public uint Departure;
    /// <summary>
    /// Who joined or left (a call, or the conference handle for this end);
    /// `SIPRAL_HANDLE_NONE` otherwise.
    /// </summary>
    public ulong Member;
    /// <summary>
    /// Members now, this end included.
    /// </summary>
    public uint Members;
    /// <summary>
    /// Members talking now.
    /// </summary>
    public uint Talkers;
    /// <summary>
    /// The loudest of them, or `SIPRAL_HANDLE_NONE`.
    /// </summary>
    public ulong Loudest;
}

/// <summary>
/// What a SipralEventKind.LookupWanted,
/// a SipralEventKind.Located
/// and a SipralEventKind.LocateFailed
/// carry, the account being `sipral_event_t::account`.
///
/// A member meaningless on a kind is zero or null. Every pointer is the
/// library's, valid for the duration of the callback.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralLocateEvent
{
    /// <summary>
    /// A SipralDnsRecordType: what to ask `name` for, on a lookup.
    /// </summary>
    public uint Record;
    /// <summary>
    /// A SipralLocateFailure: why a lookup named no address.
    /// </summary>
    public uint Failure;
    /// <summary>
    /// The name to ask, on a lookup: `_sip._udp.example.com`, or a
    /// host. Handed back to sipral_account_looked_up with the answer.
    /// UTF-8, not NUL-terminated.
    /// </summary>
    public IntPtr Name;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint NameLen;
    /// <summary>
    /// Every located address, comma-separated `host:port`, in RFC 3263
    /// section 4.3 order, the one in use first. UTF-8, not NUL-terminated.
    /// </summary>
    public IntPtr Targets;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint TargetsLen;
    /// <summary>
    /// Milliseconds until the retry after a failure; an earlier address
    /// stays in use meanwhile.
    /// </summary>
    public ulong RetryInMs;
}

/// <summary>
/// What a SipralEventKind.ChallengeDeclined carries: who asked for
/// the account's password, and why it was not given.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralChallengeEvent
{
    /// <summary>
    /// A SipralChallengeRefusal.
    /// </summary>
    public uint Refusal;
    /// <summary>
    /// Where the challenged request went, as `host:port`. Not
    /// NUL-terminated.
    /// </summary>
    public IntPtr Server;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ServerLen;
    /// <summary>
    /// The challenged realms, separated by line feeds (a realm may hold a
    /// comma, never a line break). UTF-8, not NUL-terminated.
    /// </summary>
    public IntPtr Realms;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint RealmsLen;
}

/// <summary>
/// What a SipralEventKind.TokenRequired carries (RFC 8898 §4).
/// Texts are UTF-8, not NUL-terminated, empty when absent.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralTokenEvent
{
    /// <summary>
    /// A SipralTokenError.
    /// </summary>
    public uint Error;
    /// <summary>
    /// A `SipralToggle`: on for a proxy's 407, off for a 401.
    /// </summary>
    public uint Proxy;
    /// <summary>
    /// Where the challenged request went, as `host:port`.
    /// </summary>
    public IntPtr Server;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ServerLen;
    /// <summary>
    /// The protection domain, empty when the challenge named none.
    /// </summary>
    public IntPtr Realm;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint RealmLen;
    /// <summary>
    /// The scope the token has to carry: space-separated strings the
    /// authorization server defines (RFC 6749 §3.3).
    /// </summary>
    public IntPtr Scope;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ScopeLen;
    /// <summary>
    /// The authorization server: an `https` URI, or empty if it was not one.
    /// </summary>
    public IntPtr AuthzServer;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint AuthzServerLen;
    /// <summary>
    /// The `error` code as the server wrote it, for `Other`.
    /// </summary>
    public IntPtr ErrorCode;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ErrorCodeLen;
}

/// <summary>
/// What a SipralEventKind.NetworkTest
/// carries (ABI 1.2). The event's `account` and `call` are the probed
/// account and the echo call. The addresses are `host:port`, not
/// NUL-terminated, owned by the library, valid during the callback.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralNetworkTestEvent
{
    /// <summary>
    /// The number sipral_stack_network_test gave the test.
    /// </summary>
    public uint Test;
    /// <summary>
    /// A SipralNetworkVerdict: the worst of the parts tested.
    /// </summary>
    public uint Verdict;
    /// <summary>
    /// A SipralNetworkProbe: whether a STUN server answered.
    /// </summary>
    public uint Stun;
    /// <summary>
    /// A SipralNatKind, from that answer.
    /// </summary>
    public uint Nat;
    /// <summary>
    /// A SipralNetworkProbe: whether a TURN relay was allocated.
    /// </summary>
    public uint Turn;
    /// <summary>
    /// A `SipralTransport` the TURN server was reached over, or zero.
    /// </summary>
    public uint TurnProtocol;
    /// <summary>
    /// A SipralServerReach.
    /// </summary>
    public uint Server;
    /// <summary>
    /// The status the server answered with, or zero.
    /// </summary>
    public uint ServerStatus;
    /// <summary>
    /// From sending the `OPTIONS` to its answer, in milliseconds.
    /// </summary>
    public uint ServerRoundTripMs;
    /// <summary>
    /// A SipralNetworkProbe: whether echo audio came back.
    /// </summary>
    public uint Echo;
    /// <summary>
    /// A SipralNetworkVerdict for the echo alone.
    /// </summary>
    public uint EchoVerdict;
    /// <summary>
    /// Packets lost or too late to play, as a percentage of those due.
    /// </summary>
    public float LossPercent;
    /// <summary>
    /// Interarrival jitter (RFC 3550 §6.4.1), in milliseconds.
    /// </summary>
    public float JitterMs;
    /// <summary>
    /// Nonzero when RTCP brought a round trip back in time.
    /// </summary>
    public uint HasRoundTrip;
    /// <summary>
    /// That round trip, in milliseconds.
    /// </summary>
    public uint RoundTripMs;
    /// <summary>
    /// Half the round trip plus jitter buffer delay, in milliseconds.
    /// </summary>
    public uint OneWayDelayMs;
    /// <summary>
    /// G.107's transmission rating R, 0 to 100, for concealed G.711.
    /// </summary>
    public uint RFactor;
    /// <summary>
    /// Conversational MOS estimated from R, 1.0 to 4.5.
    /// </summary>
    public float Mos;
    /// <summary>
    /// The socket the STUN answer was about.
    /// </summary>
    public IntPtr Local;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint LocalLen;
    /// <summary>
    /// Where the STUN server saw it. Empty without an answer.
    /// </summary>
    public IntPtr Mapped;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint MappedLen;
}

/// <summary>
/// The arm of an event that its kind names. The rest of the union is
/// zeroed, so members appended later read as zero.
/// </summary>
[StructLayout(LayoutKind.Explicit)]
public struct SipralEventPayload
{
    /// <summary>
    /// For SipralEventKind.RegistrationChanged.
    /// </summary>
    [FieldOffset(0)]
    public SipralRegistrationEvent Registration;
    /// <summary>
    /// For every call kind.
    /// </summary>
    [FieldOffset(0)]
    public SipralCallEvent Call;
    /// <summary>
    /// For the three transfer kinds.
    /// </summary>
    [FieldOffset(0)]
    public SipralTransferEvent Transfer;
    /// <summary>
    /// For every media kind.
    /// </summary>
    [FieldOffset(0)]
    public SipralMediaEvent Media;
    /// <summary>
    /// For SipralEventKind.Recovery.
    /// </summary>
    [FieldOffset(0)]
    public SipralRecoveryEvent Recovery;
    /// <summary>
    /// For SipralEventKind.TransportWanted.
    /// </summary>
    [FieldOffset(0)]
    public SipralTransportWantedEvent TransportWanted;
    /// <summary>
    /// For SipralEventKind.SubscriptionChanged and
    /// SipralEventKind.Notified.
    /// </summary>
    [FieldOffset(0)]
    public SipralSubscriptionEvent Subscription;
    /// <summary>
    /// For SipralEventKind.CallAnnounced and
    /// SipralEventKind.AnnouncedCallMissing.
    /// </summary>
    [FieldOffset(0)]
    public SipralAnnounceEvent Announce;
    /// <summary>
    /// For SipralEventKind.ResolveNeeded.
    /// </summary>
    [FieldOffset(0)]
    public SipralResolveEvent Resolve;
    /// <summary>
    /// For the three message kinds.
    /// </summary>
    [FieldOffset(0)]
    public SipralMessageEvent Message;
    /// <summary>
    /// For SipralEventKind.NatMapping.
    /// </summary>
    [FieldOffset(0)]
    public SipralNatEvent Nat;
    /// <summary>
    /// For SipralEventKind.NatRelay.
    /// </summary>
    [FieldOffset(0)]
    public SipralNatRelayEvent Relay;
    /// <summary>
    /// For SipralEventKind.Referral.
    /// </summary>
    [FieldOffset(0)]
    public SipralReferralEvent Referral;
    /// <summary>
    /// For SipralEventKind.TurnStream.
    /// </summary>
    [FieldOffset(0)]
    public SipralTurnStreamEvent TurnStream;
    /// <summary>
    /// For SipralEventKind.AudioDevicesChanged.
    /// </summary>
    [FieldOffset(0)]
    public SipralAudioEvent Audio;
    /// <summary>
    /// For SipralEventKind.StunServer.
    /// </summary>
    [FieldOffset(0)]
    public SipralStunServerEvent StunServer;
    /// <summary>
    /// For SipralEventKind.CallerVerification.
    /// </summary>
    [FieldOffset(0)]
    public SipralVerificationEvent Verification;
    /// <summary>
    /// For SipralEventKind.ProgressDetected.
    /// </summary>
    [FieldOffset(0)]
    public SipralProgressEvent Progress;
    /// <summary>
    /// For SipralEventKind.ConferenceChanged.
    /// </summary>
    [FieldOffset(0)]
    public SipralConferenceEvent Conference;
    /// <summary>
    /// For SipralEventKind.TextReceived.
    /// </summary>
    [FieldOffset(0)]
    public SipralTextEvent Text;
    /// <summary>
    /// For SipralEventKind.PresenceChanged.
    /// </summary>
    [FieldOffset(0)]
    public SipralPresenceEvent Presence;
    /// <summary>
    /// For SipralEventKind.TransportFailed.
    /// </summary>
    [FieldOffset(0)]
    public SipralTransportFailedEvent TransportFailed;
    /// <summary>
    /// For SipralEventKind.LocalConferenceChanged.
    /// </summary>
    [FieldOffset(0)]
    public SipralLocalConferenceEvent LocalConference;
    /// <summary>
    /// For SipralEventKind.LookupWanted, SipralEventKind.Located
    /// and SipralEventKind.LocateFailed.
    /// </summary>
    [FieldOffset(0)]
    public SipralLocateEvent Locate;
    /// <summary>
    /// For SipralEventKind.ChallengeDeclined.
    /// </summary>
    [FieldOffset(0)]
    public SipralChallengeEvent Challenge;
    /// <summary>
    /// For SipralEventKind.TokenRequired.
    /// </summary>
    [FieldOffset(0)]
    public SipralTokenEvent Token;
    /// <summary>
    /// For SipralEventKind.NetworkTest.
    /// </summary>
    [FieldOffset(0)]
    public SipralNetworkTestEvent NetworkTest;
}

/// <summary>
/// Something the library has to tell the application.
///
/// Library-owned, valid for the callback only. Read no further than
/// `size`; the union stays last so growth only extends the tail.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralEvent
{
    /// <summary>
    /// How many bytes of this struct are meaningful.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// The stack it is about.
    /// </summary>
    public ulong Stack;
    /// <summary>
    /// What it is.
    /// </summary>
    public SipralEventKind Kind;
    /// <summary>
    /// The account it is about, or SIPRAL_HANDLE_NONE.
    /// </summary>
    public ulong Account;
    /// <summary>
    /// The call it is about, or SIPRAL_HANDLE_NONE.
    /// </summary>
    public ulong Call;
    /// <summary>
    /// The SIP message behind it, whole and unparsed, or null.
    /// </summary>
    public IntPtr Message;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint MessageLen;
    /// <summary>
    /// The arm SipralEvent.Kind names.
    /// </summary>
    public SipralEventPayload Payload;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralEvent Sized()
    {
        var value = default(SipralEvent);
        value.Size = (nuint)Marshal.SizeOf<SipralEvent>();
        return value;
    }
}

/// <summary>
/// What was standing when sipral_stack_suspending was called. Set
/// `size` to `sizeof(sipral_suspending_t)` first.
///
/// Counts only: no allocation in the suspend window. All of it is past
/// tense when read, and nothing was sent about any of it.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralSuspending
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// Bindings that read as live and do not any more.
    /// </summary>
    public nuint Unverified;
    /// <summary>
    /// Subscriptions whose last notification stopped being evidence.
    /// </summary>
    public nuint Subscriptions;
    /// <summary>
    /// Calls that were up, left untouched: hanging up because the machine
    /// blinked is worse than learning later that a call is gone.
    /// </summary>
    public nuint Calls;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralSuspending Sized()
    {
        var value = default(SipralSuspending);
        value.Size = (nuint)Marshal.SizeOf<SipralSuspending>();
        return value;
    }
}

/// <summary>
/// What SipralScreenCallback reads about one INVITE, before it has
/// had any effect.
///
/// Read `size` first, like SipralEvent. `message` and
/// `source` borrow from a request still being processed: read nothing after
/// the callback returns.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralScreenRequest
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// The stack the INVITE arrived on.
    /// </summary>
    public ulong Stack;
    /// <summary>
    /// The far end of the bytes, as `host:port`. Null and zero for a byte
    /// stream bound without naming its far end.
    /// </summary>
    public IntPtr Source;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint SourceLen;
    /// <summary>
    /// The INVITE, whole and unparsed; `sipral_message_header` and its
    /// companions read headers out of it.
    /// </summary>
    public IntPtr Message;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint MessageLen;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralScreenRequest Sized()
    {
        var value = default(SipralScreenRequest);
        value.Size = (nuint)Marshal.SizeOf<SipralScreenRequest>();
        return value;
    }
}

/// <summary>
/// What to watch, and how. Handed to sipral_account_subscribe. Set
/// `size` to `sizeof(sipral_subscribe_config_t)`; all but `target` and
/// `package` may be zero.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralSubscribeConfig
{
    /// <summary>
    /// How long this struct is, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// What to watch, as a SIP URI: `sip:2001@pbx.example.com`.
    /// </summary>
    public IntPtr Target;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint TargetLen;
    /// <summary>
    /// The event package token: `dialog` for a busy lamp field (RFC 4235
    /// §3.1), `message-summary` (RFC 3842 §3), `presence` (RFC 3856 §6.1).
    /// Sent exactly as written, since §8.2.1 compares it byte for byte.
    /// </summary>
    public IntPtr Package;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint PackageLen;
    /// <summary>
    /// The `Accept` value, when the package's default body type is not
    /// wanted. Null sends none, which means the default (§3.1.3); a wrong
    /// one gets 406 (§4.1.2.1), so nothing is guessed.
    /// </summary>
    public IntPtr Accept;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint AcceptLen;
    /// <summary>
    /// Seconds to ask for, or zero for one hour. The notifier's grant wins
    /// (§3.1.1), and the refresh follows the grant.
    /// </summary>
    public uint ExpiresSeconds;
    /// <summary>
    /// Where to send the SUBSCRIBE, as `host:port`, or null for where the
    /// account registers (the outbound proxy, which keeps NAT working).
    /// </summary>
    public IntPtr Destination;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint DestinationLen;
    /// <summary>
    /// The transport, read only with `destination`, as
    /// `sipral_call_config_t::transport` is. Nonzero without `destination`
    /// is `SIPRAL_STATUS_INVALID_ARGUMENT`.
    /// </summary>
    public uint Transport;
    /// <summary>
    /// Zero. Pads the struct to a multiple of its alignment, so a member
    /// appended later never lands in padding. Never read.
    /// </summary>
    public uint Reserved;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralSubscribeConfig Sized()
    {
        var value = default(SipralSubscribeConfig);
        value.Size = (nuint)Marshal.SizeOf<SipralSubscribeConfig>();
        return value;
    }
}

/// <summary>
/// One dialog a `dialog` subscription was told about. Its text is read
/// with sipral_subscription_dialog_text, so no pointer can dangle.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralWatchedDialog
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// A SipralDialogPhase.
    /// </summary>
    public uint Phase;
    /// <summary>
    /// A SipralDialogDirection.
    /// </summary>
    public uint Direction;
    /// <summary>
    /// A SipralDialogEnded, and zero while the dialog has not.
    /// </summary>
    public uint Ended;
    /// <summary>
    /// The SIP status behind how it ended, or zero.
    /// </summary>
    public uint StatusCode;
    /// <summary>
    /// How long it has been up, in milliseconds, or zero.
    /// </summary>
    public ulong DurationMs;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralWatchedDialog Sized()
    {
        var value = default(SipralWatchedDialog);
        value.Size = (nuint)Marshal.SizeOf<SipralWatchedDialog>();
        return value;
    }
}

/// <summary>
/// What the registrar said about push, in the 2xx to a REGISTER that
/// asked for it (RFC 8599 §8.2).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralPushEcho
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// Whether the network promised pushes of the requested type. Zero
    /// means not promised (§4.1.1): do not suspend relying on a push.
    /// </summary>
    public uint Accepted;
    /// <summary>
    /// Whether `refresh_lead_ms` was sent at all.
    /// </summary>
    public uint HasRefreshLead;
    /// <summary>
    /// How long before expiry the network wants a refresh, from
    /// `sip.pnsreg` (§4.1.4), in milliseconds; zero when not sent.
    /// </summary>
    public ulong RefreshLeadMs;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralPushEcho Sized()
    {
        var value = default(SipralPushEcho);
        value.Size = (nuint)Marshal.SizeOf<SipralPushEcho>();
        return value;
    }
}

/// <summary>
/// One device, as `sipral_audio_device_at` fills it in. Set `size` to
/// `sizeof(sipral_audio_device_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralAudioDevice
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// The engine's name for the device: stable across refreshes, never
    /// reused, never zero. What `sipral_audio_select` takes.
    /// </summary>
    public uint Id;
    /// <summary>
    /// Channels it captures; zero for a device that is no microphone.
    /// </summary>
    public uint InputChannels;
    /// <summary>
    /// How many channels it plays; zero likewise.
    /// </summary>
    public uint OutputChannels;
    /// <summary>
    /// One when the system records from it by default.
    /// </summary>
    public uint DefaultInput;
    /// <summary>
    /// One when the system plays to it by default.
    /// </summary>
    public uint DefaultOutput;
    /// <summary>
    /// One when the last refresh found it. An absent device keeps its row
    /// and id, so a saved selection still names something.
    /// </summary>
    public uint Present;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralAudioDevice Sized()
    {
        var value = default(SipralAudioDevice);
        value.Size = (nuint)Marshal.SizeOf<SipralAudioDevice>();
        return value;
    }
}

/// <summary>
/// What the engine is doing, as `sipral_audio_info` fills it in. Set
/// `size` to `sizeof(sipral_audio_info_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralAudioInfo
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// One while the devices are open and the pump is running.
    /// </summary>
    public uint Active;
    /// <summary>
    /// One when the platform's own processing sits behind the microphone:
    /// the voice-processing unit on macOS and iOS, a communications stream
    /// on Windows (a virtual cable cancels nothing). For echo removal
    /// regardless, attach a processor per call; the engine tells each
    /// managed call `render_delay_ms` itself, after every device change.
    /// </summary>
    public uint SystemEchoCancellation;
    /// <summary>
    /// The loudspeaker-to-microphone delay the devices report, in
    /// milliseconds.
    /// </summary>
    public ulong RenderDelayMs;
    /// <summary>
    /// The rate the microphone runs at, or zero when it is not open.
    /// </summary>
    public uint MicrophoneRateHz;
    /// <summary>
    /// The rate the loudspeaker runs at, or zero when it is not open.
    /// </summary>
    public uint SpeakerRateHz;
    /// <summary>
    /// The device the microphone is running on, or zero.
    /// </summary>
    public uint Microphone;
    /// <summary>
    /// The device the loudspeaker is running on, or zero.
    /// </summary>
    public uint Speaker;
    /// <summary>
    /// The device the ringer is running on, or zero when the ring goes
    /// through the loudspeaker.
    /// </summary>
    public uint Ringer;
    /// <summary>
    /// Zero. Pads the struct to a multiple of its alignment, so a member
    /// appended later never lands in padding. Written zero, never read.
    /// </summary>
    public uint Reserved;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralAudioInfo Sized()
    {
        var value = default(SipralAudioInfo);
        value.Size = (nuint)Marshal.SizeOf<SipralAudioInfo>();
        return value;
    }
}

/// <summary>
/// One packet the engine encoded, handed to
/// `sipral_stack_config_t::audio_transmit_callback`: send it from the
/// call's media socket and return.
///
/// Read `size` before anything past it, and nothing once the callback
/// returns. The callback runs on the engine's thread, once per frame per
/// call; it may call the media entry points and must not destroy the stack.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralAudioTransmit
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// The call whose socket this leaves from.
    /// </summary>
    public ulong Call;
    /// <summary>
    /// A `SipralTransport`: UDP is a datagram from the media socket; TCP
    /// and TLS are bytes to write in order on the socket's TURN connection.
    /// </summary>
    public uint Protocol;
    /// <summary>
    /// Zero. Keeps later members at the same offsets on 32- and 64-bit
    /// targets. Written zero, never read.
    /// </summary>
    public uint Reserved;
    /// <summary>
    /// Where to send it, `host:port`, UTF-8 and not NUL-terminated.
    /// </summary>
    public IntPtr Destination;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint DestinationLen;
    /// <summary>
    /// The octets.
    /// </summary>
    public IntPtr Payload;
    /// <summary>
    /// How many of them.
    /// </summary>
    public nuint PayloadLen;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralAudioTransmit Sized()
    {
        var value = default(SipralAudioTransmit);
        value.Size = (nuint)Marshal.SizeOf<SipralAudioTransmit>();
        return value;
    }
}

/// <summary>
/// One log line, as SipralLogCallback reads it.
///
/// Read `size` first, and nothing after the callback returns: the strings
/// live for the call only.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralLogRecord
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// The stack the line is about.
    /// </summary>
    public ulong Stack;
    /// <summary>
    /// A `SipralLogLevel`, never `SIPRAL_LOG_LEVEL_OFF`.
    /// </summary>
    public uint Level;
    /// <summary>
    /// Which part of the stack wrote it — `registration`, `call`,
    /// `media`, `decision`, `sip`, `api` — as UTF-8, not NUL-terminated.
    /// </summary>
    public IntPtr Target;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint TargetLen;
    /// <summary>
    /// The line, already redacted, as UTF-8, not NUL-terminated. A
    /// `SIPRAL_LOG_LEVEL_TRACE` line holding a whole message has line
    /// breaks in it.
    /// </summary>
    public IntPtr Message;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint MessageLen;
    /// <summary>
    /// Lines dropped by the rate limit or queue since the previous line.
    /// </summary>
    public ulong Suppressed;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralLogRecord Sized()
    {
        var value = default(SipralLogRecord);
        value.Size = (nuint)Marshal.SizeOf<SipralLogRecord>();
        return value;
    }
}

/// <summary>
/// How a stack verifies the callers of the calls its accounts receive.
///
/// Set `size` to `sizeof(sipral_stir_config_t)` and zero the rest first.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralStirConfig
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// Trust anchors (in SHAKEN, the STI-PA roots), PEM or DER,
    /// concatenated. Null and zero for none: reporting accounts then verify
    /// nothing.
    /// </summary>
    public IntPtr Anchors;
    /// <summary>
    /// How many bytes of them.
    /// </summary>
    public nuint AnchorsLen;
    /// <summary>
    /// Allowed `iat` skew either way, in seconds; zero for 60 (RFC 8224 §6.2).
    /// </summary>
    public ulong FreshnessSeconds;
    /// <summary>
    /// How long a call waits for `sipral_call_stir_certificate`, in ms,
    /// before the certificate counts as unavailable; zero for 4000.
    /// </summary>
    public ulong CertificateWaitMs;
    /// <summary>
    /// The wall clock at `now_ms`, in Unix seconds, or zero to keep the
    /// previous one. The first call must set it. Not taken from
    /// `sipral_stack_config_t::media_clock_unix_seconds`, which has no
    /// `now_ms`. A stack with no media clock also dates RTCP sender reports
    /// by it.
    /// </summary>
    public ulong UnixSeconds;
    /// <summary>
    /// A `SipralToggle`: whether a TNAuthList service provider code
    /// (RFC 8226 §9) covers every calling number. Off by default; a SHAKEN
    /// deployment, whose certificates carry codes, turns it on. ABI 0.32.
    /// </summary>
    public uint AcceptServiceProviderCodes;
    /// <summary>
    /// Zero. Pads the struct to its alignment so an appended member starts
    /// past the declared length. Never read.
    /// </summary>
    public uint Reserved;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralStirConfig Sized()
    {
        var value = default(SipralStirConfig);
        value.Size = (nuint)Marshal.SizeOf<SipralStirConfig>();
        return value;
    }
}

/// <summary>
/// How one stream of a call is protected.
///
/// Set `size` to `sizeof(sipral_stream_encryption_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralStreamEncryption
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// A SipralMediaKind: what the stream carries.
    /// </summary>
    public uint Media;
    /// <summary>
    /// Whether it is encrypted now. Zero while waiting for its keys.
    /// </summary>
    public uint Encrypted;
    /// <summary>
    /// A SipralKeyExchange: how its keys were exchanged.
    /// </summary>
    public uint KeyExchange;
    /// <summary>
    /// A SipralSrtpSuite: the transform it runs, once it runs one.
    /// </summary>
    public uint Suite;
    /// <summary>
    /// Whether the key exchange authenticated the far end: set for
    /// DTLS-SRTP after a handshake matching the fingerprint; never for
    /// SDES, which is only as authentic as the signalling.
    /// </summary>
    public uint Authenticated;
    /// <summary>
    /// Agreed to be encrypted and still waiting for keys.
    /// </summary>
    public uint AwaitingKeys;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralStreamEncryption Sized()
    {
        var value = default(SipralStreamEncryption);
        value.Size = (nuint)Marshal.SizeOf<SipralStreamEncryption>();
        return value;
    }
}

/// <summary>
/// How sipral_call_detect_progress listens. A zero member is its
/// default. Set `size` to `sizeof(sipral_progress_config_t)`.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralProgressConfig
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// A `SipralToggle`: on (the default) listens with what follows,
    /// off stops listening and reads nothing else.
    /// </summary>
    public uint Listen;
    /// <summary>
    /// A SipralToneRegion. Europe by default.
    /// </summary>
    public uint Region;
    /// <summary>
    /// A `SipralToggle`: whether to decide who answered. On by default.
    /// </summary>
    public uint AnsweringMachine;
    /// <summary>
    /// A `SipralToggle`: whether to listen for the beep after a verdict
    /// of a machine. On by default.
    /// </summary>
    public uint Beep;
    /// <summary>
    /// How long after the verdict to listen for the beep. Thirty
    /// seconds by default.
    /// </summary>
    public uint BeepWindowMs;
    /// <summary>
    /// The longest silence after answer before the verdict is not sure.
    /// 3000 by default.
    /// </summary>
    public uint MaxInitialSilenceMs;
    /// <summary>
    /// The longest greeting a person gives. 1600 by default.
    /// </summary>
    public uint MaxGreetingMs;
    /// <summary>
    /// The silence after a greeting that says a person is waiting. 700
    /// by default.
    /// </summary>
    public uint SilenceAfterGreetingMs;
    /// <summary>
    /// The most words a person's greeting has. 4 by default.
    /// </summary>
    public uint MaxWords;
    /// <summary>
    /// The shortest run of speech that is a word. 120 by default.
    /// </summary>
    public uint MinWordMs;
    /// <summary>
    /// The shortest silence that separates two words. 60 by default.
    /// </summary>
    public uint MinWordGapMs;
    /// <summary>
    /// The longest the decision may take, from answer. 6000 by default.
    /// </summary>
    public uint MaxDecisionMs;
    /// <summary>
    /// How far above the noise floor a frame must be to be speech, in
    /// dB. 6 by default.
    /// </summary>
    public uint MinSpeechAboveFloorDb;
    /// <summary>
    /// The shortest beep. 120 by default.
    /// </summary>
    public uint BeepMinMs;
    /// <summary>
    /// The longest beep: anything held longer is a tone, not a beep.
    /// This build's own default unless set.
    /// </summary>
    public uint BeepMaxMs;
    /// <summary>
    /// How many whole cycles of a repeating cadence are heard before the
    /// tone is reported, from one to four. One by default.
    /// </summary>
    public uint ToneCycles;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralProgressConfig Sized()
    {
        var value = default(SipralProgressConfig);
        value.Size = (nuint)Marshal.SizeOf<SipralProgressConfig>();
        return value;
    }
}

/// <summary>
/// The beep sipral_call_consent_tone plays. A zero member is its
/// default. Set `size` to `sizeof(sipral_consent_tone_t)`.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralConsentTone
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// A `SipralToggle`: on (the default) beeps as what follows says,
    /// off plays no tone and reads nothing else.
    /// </summary>
    public uint Enabled;
    /// <summary>
    /// Its frequency, from 300 to 3400 Hz. 1400 by default.
    /// </summary>
    public uint FrequencyHz;
    /// <summary>
    /// How far below 0 dBm0 it sounds, from 3 to 40 dB: 18 is a beep at
    /// −18 dBm0, the default.
    /// </summary>
    public uint AttenuationDb;
    /// <summary>
    /// How long each beep lasts, from 50 to 2000 ms. 200 by default.
    /// </summary>
    public uint LengthMs;
    /// <summary>
    /// How often it repeats, start to start: longer than a beep and at
    /// most ten minutes. Fifteen seconds by default.
    /// </summary>
    public uint IntervalMs;
    /// <summary>
    /// A `SipralToggle`: whether this end hears it too. On by default.
    /// </summary>
    public uint Local;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralConsentTone Sized()
    {
        var value = default(SipralConsentTone);
        value.Size = (nuint)Marshal.SizeOf<SipralConsentTone>();
        return value;
    }
}

/// <summary>
/// How sipral_media_record_start_with writes a recording. Zero in
/// every member but `size` is sipral_media_record_start's file.
///
/// Set `size` to `sizeof(sipral_recording_options_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralRecordingOptions
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// A SipralRecordingFormat.
    /// </summary>
    public uint Format;
    /// <summary>
    /// A SipralRecordingLayout.
    /// </summary>
    public uint Layout;
    /// <summary>
    /// The rate the file is written at, in hertz, or zero for the rate the
    /// call's codec hears at when the recording starts (48 kHz for Ogg
    /// Opus on a call at a rate Opus does not take). WAV takes 8000 to
    /// 48000; Ogg Opus takes 8000, 12000, 16000, 24000 and 48000.
    /// </summary>
    public uint SampleRate;
    /// <summary>
    /// An Ogg Opus recording's bitrate in bits a second, all channels
    /// together, or zero for libopus's own choice. Not read for WAV.
    /// </summary>
    public uint Bitrate;
    /// <summary>
    /// How often, in milliseconds, what has been written is made to
    /// survive a crash, or zero for every five seconds.
    /// </summary>
    public uint CheckpointMs;
    /// <summary>
    /// Zero; never read. Pads the struct to its alignment so a member added
    /// later never lands in padding of an older caller's struct.
    /// </summary>
    public uint Reserved;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralRecordingOptions Sized()
    {
        var value = default(SipralRecordingOptions);
        value.Size = (nuint)Marshal.SizeOf<SipralRecordingOptions>();
        return value;
    }
}

/// <summary>
/// A conference as a `conference` subscription holds it, read with
/// sipral_subscription_conference.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralConference
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// The version of the last document merged.
    /// </summary>
    public uint Version;
    /// <summary>
    /// Users held, indexed by sipral_subscription_conference_user_at.
    /// </summary>
    public uint Users;
    /// <summary>
    /// Whether `user-count` was sent; it may differ from `users`.
    /// </summary>
    public uint HasUserCount;
    /// <summary>
    /// That count, when it said.
    /// </summary>
    public uint UserCount;
    /// <summary>
    /// `active`: 1 true, 2 false, 0 not said.
    /// </summary>
    public uint Active;
    /// <summary>
    /// Its `locked`, the same way.
    /// </summary>
    public uint Locked;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralConference Sized()
    {
        var value = default(SipralConference);
        value.Size = (nuint)Marshal.SizeOf<SipralConference>();
        return value;
    }
}

/// <summary>
/// One user of a conference, read with
/// sipral_subscription_conference_user_at; its text is read with
/// sipral_subscription_conference_text.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralConferenceUser
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// How many endpoints (devices) the user joined from.
    /// </summary>
    public uint Endpoints;
    /// <summary>
    /// A SipralEndpointStatus of the first endpoint.
    /// </summary>
    public uint Status;
    /// <summary>
    /// Media streams of the first endpoint.
    /// </summary>
    public uint Media;
    /// <summary>
    /// Zero. Pads to alignment so later members never land in padding.
    /// </summary>
    public uint Reserved;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralConferenceUser Sized()
    {
        var value = default(SipralConferenceUser);
        value.Size = (nuint)Marshal.SizeOf<SipralConferenceUser>();
        return value;
    }
}

/// <summary>
/// This account's presence for sipral_account_publish_presence. Set
/// `size` to `sizeof(sipral_presence_t)` and zero the rest first.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralPresence
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// A SipralBasic, open or closed. Required.
    /// </summary>
    public uint Basic;
    /// <summary>
    /// A SipralActivity; SipralActivity.None publishes no
    /// person at all. SipralActivity.Other is refused: there is no
    /// name to publish it under.
    /// </summary>
    public uint Activity;
    /// <summary>
    /// A note a buddy list shows beside the name, UTF-8 and not
    /// NUL-terminated, or null for none.
    /// </summary>
    public IntPtr Note;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint NoteLen;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralPresence Sized()
    {
        var value = default(SipralPresence);
        value.Size = (nuint)Marshal.SizeOf<SipralPresence>();
        return value;
    }
}

/// <summary>
/// Where a call is recorded, as sipral_call_record_to takes it.
///
/// Set `size` to `sizeof(sipral_record_config_t)` and zero the rest
/// before filling anything in.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralRecordConfig
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// The recording server's URI. Required, not NUL-terminated.
    /// </summary>
    public IntPtr Server;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ServerLen;
    /// <summary>
    /// `host:port` to send the INVITE to; null for the account's route.
    /// </summary>
    public IntPtr Destination;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint DestinationLen;
    /// <summary>
    /// The transport for `destination`, as in
    /// `sipral_call_config_t::transport`; read only with `destination`.
    /// </summary>
    public uint Transport;
    /// <summary>
    /// Required bound socket, `host:port`, for this end's audio (label `1`).
    /// </summary>
    public IntPtr ThisEnd;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ThisEndLen;
    /// <summary>
    /// Required distinct socket for the far end's audio (label `2`).
    /// </summary>
    public IntPtr FarEnd;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint FarEndLen;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralRecordConfig Sized()
    {
        var value = default(SipralRecordConfig);
        value.Size = (nuint)Marshal.SizeOf<SipralRecordConfig>();
        return value;
    }
}

/// <summary>
/// How `sipral_local_conference_create` makes a conference. All zero but
/// `size`: sixteen members, this end in, 16 kHz.
///
/// Set `size` to `sizeof(sipral_local_conference_config_t)` first.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralLocalConferenceConfig
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// Most members at once, this end included; zero for 16, at most 1024.
    /// </summary>
    public uint MaxMembers;
    /// <summary>
    /// A `SipralToggle`: whether this end takes part. On unless
    /// `SIPRAL_TOGGLE_OFF`; without it the conference only bridges calls.
    /// </summary>
    public uint Local;
    /// <summary>
    /// This end's frame rate in application mode, in Hz: 8000, 16000,
    /// 32000 or 48000, zero for 16000. A tick is 20 ms of it. In device
    /// mode the engine converts the devices to it.
    /// </summary>
    public uint SampleRate;
    /// <summary>
    /// Zero. Pads the struct to its alignment so an appended member starts
    /// past the declared length. Never read.
    /// </summary>
    public uint Reserved;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralLocalConferenceConfig Sized()
    {
        var value = default(SipralLocalConferenceConfig);
        value.Size = (nuint)Marshal.SizeOf<SipralLocalConferenceConfig>();
        return value;
    }
}

/// <summary>
/// A conference as it stands: `sipral_local_conference_info`.
///
/// Set `size` to `sizeof(sipral_local_conference_info_t)` first.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralLocalConferenceInfo
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// Members, this end included.
    /// </summary>
    public uint Members;
    /// <summary>
    /// The most it holds.
    /// </summary>
    public uint Capacity;
    /// <summary>
    /// Members talking in the last tick.
    /// </summary>
    public uint Talkers;
    /// <summary>
    /// 1 when this end takes part.
    /// </summary>
    public uint Local;
    /// <summary>
    /// The rate of this end's frames, in hertz.
    /// </summary>
    public uint SampleRate;
    /// <summary>
    /// Samples in one of this end's frames: twenty milliseconds.
    /// </summary>
    public uint FrameSamples;
    /// <summary>
    /// 1 while the conference is being recorded.
    /// </summary>
    public uint Recording;
    /// <summary>
    /// Recorded so far, while recording.
    /// </summary>
    public ulong RecordedMs;
    /// <summary>
    /// Packets dropped because nobody polled for them in time.
    /// </summary>
    public ulong PacketsDropped;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralLocalConferenceInfo Sized()
    {
        var value = default(SipralLocalConferenceInfo);
        value.Size = (nuint)Marshal.SizeOf<SipralLocalConferenceInfo>();
        return value;
    }
}

/// <summary>
/// One member of a conference: `sipral_local_conference_member_at`.
///
/// Set `size` to `sizeof(sipral_local_conference_member_t)` first.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralLocalConferenceMember
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// The call, or the conference's own handle for this end.
    /// </summary>
    public ulong Member;
    /// <summary>
    /// 1 when it was talking in the last tick, muted or not.
    /// </summary>
    public uint Talking;
    /// <summary>
    /// 1 when nobody hears it.
    /// </summary>
    public uint MutedInput;
    /// <summary>
    /// 1 when it hears nothing.
    /// </summary>
    public uint MutedOutput;
    /// <summary>
    /// Level of what it says, in `sipral_audio_set_gain` steps (256 = unity).
    /// </summary>
    public uint GainInput;
    /// <summary>
    /// The level of what it hears, in the same steps.
    /// </summary>
    public uint GainOutput;
    /// <summary>
    /// Zero. Pads the struct to its alignment so an appended member starts
    /// past the declared length. Written as zero, never read.
    /// </summary>
    public uint Reserved;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralLocalConferenceMember Sized()
    {
        var value = default(SipralLocalConferenceMember);
        value.Size = (nuint)Marshal.SizeOf<SipralLocalConferenceMember>();
        return value;
    }
}

/// <summary>
/// What sipral_account_check_certificate found: whether the account's
/// pin decided, and what the certificate's dates say.
///
/// Set `size` to `sizeof(sipral_pinned_certificate_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralPinnedCertificate
{
    /// <summary>
    /// How many bytes of this struct the library filled in.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// The certificate's `notBefore`, in seconds since 1 January 1970,
    /// or zero when its DER could not be read that far.
    /// </summary>
    public ulong NotBefore;
    /// <summary>
    /// Its `notAfter`, the same way.
    /// </summary>
    public ulong NotAfter;
    /// <summary>
    /// One: pinned and matching, accept. Zero: no pin, platform checks apply.
    /// </summary>
    public uint Pinned;
    /// <summary>
    /// One when past `not_after`. Still accepted (a lapsed self-signed PBX
    /// would go silent); worth a warning.
    /// </summary>
    public uint Expired;
    /// <summary>
    /// One when before `not_before`. Still accepted.
    /// </summary>
    public uint NotYetValid;
    /// <summary>
    /// Zero.
    /// </summary>
    public uint Reserved;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralPinnedCertificate Sized()
    {
        var value = default(SipralPinnedCertificate);
        value.Size = (nuint)Marshal.SizeOf<SipralPinnedCertificate>();
        return value;
    }
}

/// <summary>
/// What sipral_stack_network_test tests. Zero in any member but
/// `size` leaves that part out or takes its default.
///
/// Set `size` to `sizeof(sipral_network_test_config_t)` before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SipralNetworkTestConfig
{
    /// <summary>
    /// `sizeof` this struct, as the caller's header declares it.
    /// </summary>
    public nuint Size;
    /// <summary>
    /// The account whose server to probe, or `SIPRAL_HANDLE_NONE`.
    /// </summary>
    public ulong Account;
    /// <summary>
    /// A UDP socket the application bound for the test, `host:port`, not
    /// NUL-terminated; null for the signalling socket only and no relay.
    /// </summary>
    public IntPtr ProbeSocket;
    /// <summary>
    /// How many bytes of it.
    /// </summary>
    public nuint ProbeSocketLen;
    /// <summary>
    /// A call to an echo service, hung up by the test, or `SIPRAL_HANDLE_NONE`.
    /// </summary>
    public ulong EchoCall;
    /// <summary>
    /// How long the echo is measured. 8000 by default.
    /// </summary>
    public uint EchoMs;
    /// <summary>
    /// Test deadline, 30000 by default; a part silent by then failed.
    /// </summary>
    public uint TimeoutMs;

    /// <summary>A zeroed one with its size filled in, which is
    /// what every struct here has to be handed over as.</summary>
    public static SipralNetworkTestConfig Sized()
    {
        var value = default(SipralNetworkTestConfig);
        value.Size = (nuint)Marshal.SizeOf<SipralNetworkTestConfig>();
        return value;
    }
}

/// <summary>
/// A list of SipralHeader as the array the library reads, for the length of
/// one call. Every piece of text in every element is copied into one
/// buffer, the records point into it, and both are pinned until Dispose,
/// which the wrapper that made this runs as the call returns or throws.
/// The count the library is given is the list's own, and an empty piece
/// of text crosses as a null pointer with a length of zero.
/// </summary>
internal sealed class SipralHeaderArray : IDisposable
{
    private GCHandle bytesPinned;
    private GCHandle recordsPinned;

    internal SipralHeaderArray((string Name, string Value)[]? list)
    {
        if (list is null || list.Length == 0)
        {
            return;
        }

        var parts = new byte[checked(list.Length * 2)][];
        for (var index = 0; index < list.Length; index++)
        {
            parts[index * 2 + 0] = Encoding.UTF8.GetBytes(list[index].Name);
            parts[index * 2 + 1] = Encoding.UTF8.GetBytes(list[index].Value);
        }

        var total = 0;
        foreach (var part in parts)
        {
            total = checked(total + part.Length);
        }

        var bytes = new byte[total];
        var records = new SipralHeader[list.Length];
        var at = 0;
        for (var index = 0; index < list.Length; index++)
        {
            Buffer.BlockCopy(parts[index * 2 + 0], 0, bytes, at, parts[index * 2 + 0].Length);
            records[index].NameLen = (nuint)parts[index * 2 + 0].Length;
            at += parts[index * 2 + 0].Length;
            Buffer.BlockCopy(parts[index * 2 + 1], 0, bytes, at, parts[index * 2 + 1].Length);
            records[index].ValueLen = (nuint)parts[index * 2 + 1].Length;
            at += parts[index * 2 + 1].Length;
        }

        bytesPinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try
        {
            recordsPinned = GCHandle.Alloc(records, GCHandleType.Pinned);
        }
        catch
        {
            bytesPinned.Free();
            throw;
        }

        var start = bytesPinned.AddrOfPinnedObject();
        at = 0;
        for (var index = 0; index < records.Length; index++)
        {
            records[index].Name = records[index].NameLen == 0 ? IntPtr.Zero : start + at;
            at += (int)records[index].NameLen;
            records[index].Value = records[index].ValueLen == 0 ? IntPtr.Zero : start + at;
            at += (int)records[index].ValueLen;
        }

        Address = recordsPinned.AddrOfPinnedObject();
        Count = (nuint)records.Length;
    }

    /// <summary>Where the first record is, or zero for no list.</summary>
    internal IntPtr Address { get; }

    /// <summary>How many records there are, which is how long the list
    /// is.</summary>
    internal nuint Count { get; }

    /// <summary>Let go of the buffer and the records.</summary>
    public void Dispose()
    {
        if (recordsPinned.IsAllocated)
        {
            recordsPinned.Free();
        }

        if (bytesPinned.IsAllocated)
        {
            bytesPinned.Free();
        }
    }
}

/// <summary>What a call across the boundary answered, when it did not
/// answer Ok. The message is the calling thread's last error, read
/// before anything else on this thread could replace it.</summary>
public sealed class SipralException : Exception
{
    internal SipralException(SipralStatus status, string message)
        : base(message.Length == 0 ? status.ToString() : $"{status}: {message}")
    {
        Status = status;
    }

    /// <summary>The code C would have switched on.</summary>
    public SipralStatus Status { get; }
}

/// <summary>
/// The ABI as the runtime calls it. Every pointer is written as an
/// array or as in, ref or out, so nothing here needs an unsafe block
/// and the runtime pins what it passes. An array of records is the
/// one IntPtr: the wrapper pins the records and the text they point
/// at itself, for the length of the call.
/// </summary>
internal static class NativeMethods
{
    /// <summary>What the native library is called, before the
    /// platform puts its own prefix and suffix on it.</summary>
    internal const string Library = "sipral_ffi";

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_last_error_message(sbyte[] buffer, nuint capacity, out nuint needed);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern IntPtr sipral_status_name(int status);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_abi_version(ref SipralAbiVersion outVersion);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_abi_check(uint major, uint minor);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_abi_struct_size(sbyte[] name, nuint nameLen, out nuint size);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_abi_versioned_count(out nuint count);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_capabilities(ref SipralCapabilities outCapabilities);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_create(in SipralStackConfig config, out ulong stack);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_settings(ulong stack, ref SipralStackSettings outSettings);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_destroy(ulong stack);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_poll(ulong stack, ulong nowMs, ref SipralPollResult result);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_counters(ulong stack, ref SipralCounters outCounters);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_screen(ulong stack, IntPtr callback, IntPtr userData);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_invite_limit(ulong stack, ulong everyMs, uint burst);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_subscribe(ulong stack, ulong account, in SipralSubscribeConfig config, out ulong subscription, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_subscription_end(ulong stack, ulong subscription, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_subscription_state(ulong stack, ulong subscription, out uint state);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_subscription_lamp(ulong stack, ulong subscription, out uint phase);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_subscription_dialog_count(ulong stack, ulong subscription, out nuint count);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_subscription_dialog_at(ulong stack, ulong subscription, nuint index, ref SipralWatchedDialog outDialog);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_subscription_dialog_text(ulong stack, ulong subscription, nuint index, uint which, sbyte[] buffer, nuint capacity, out nuint needed);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_message(ulong stack, ulong account, sbyte[] target, nuint targetLen, sbyte[] contentType, nuint contentTypeLen, byte[] body, nuint bodyLen, out ulong message, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_announce(ulong stack, ulong account, sbyte[] caller, nuint callerLen, out ulong announcement, out ulong call, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_refresh_binding(ulong stack, ulong account, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_announcement_forget(ulong stack, ulong announcement);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_push_echo(ulong stack, ulong account, ref SipralPushEcho outEcho);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_add(ulong stack, in SipralAccountConfig config, out ulong account);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_remove(ulong stack, ulong account);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_register(ulong stack, ulong account, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_unregister(ulong stack, ulong account, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_registration_state(ulong stack, ulong account, out uint state);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_set_access_token(ulong stack, ulong account, sbyte[] token, nuint tokenLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_network_test(ulong stack, in SipralNetworkTestConfig config, ulong nowMs, out uint test);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_place(ulong stack, ulong account, in SipralCallConfig config, out ulong call, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_ring(ulong stack, ulong call, byte[] sdp, nuint sdpLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_ring_media(ulong stack, ulong call, in SipralCallConfig config, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_answer(ulong stack, ulong call, byte[] sdp, nuint sdpLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_answer_media(ulong stack, ulong call, sbyte[] mediaAddress, nuint mediaAddressLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_answer_with(ulong stack, ulong call, in SipralCallConfig config, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_reject(ulong stack, ulong call, uint code, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_hangup(ulong stack, ulong call, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_set_headers(ulong stack, ulong call, IntPtr headers, nuint headersLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_hold(ulong stack, ulong call, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_resume(ulong stack, ulong call, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_change_codecs(ulong stack, ulong call, sbyte[] codecs, nuint codecsLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_restart_ice(ulong stack, ulong call, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_media_readdress(ulong stack, ulong call, sbyte[] mediaAddress, nuint mediaAddressLen, sbyte[] publicAddress, nuint publicAddressLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_hangup_for(ulong stack, ulong call, uint sipCause, uint q850Cause, sbyte[] text, nuint textLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_redirect(ulong stack, ulong call, uint statusCode, sbyte[] targets, nuint targetsLen, sbyte[] reason, nuint reasonLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_identity_count(ulong stack, ulong call, uint which, out nuint count);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_identity_text(ulong stack, ulong call, nuint index, uint which, sbyte[] buffer, nuint capacity, out nuint needed);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_join(ulong stack, ulong callA, ulong callB);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_leave(ulong stack, ulong call);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_accept_session(ulong stack, ulong call, byte[] sdp, nuint sdpLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_reject_session(ulong stack, ulong call, uint code, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_send_dtmf(ulong stack, ulong call, sbyte[] digits, nuint digitsLen, uint via, uint durationMs, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_transfer(ulong stack, ulong call, sbyte[] target, nuint targetLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_consult(ulong stack, ulong call, in SipralCallConfig config, out ulong consultation, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_transfer_to(ulong stack, ulong call, ulong other, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_accept_transfer(ulong stack, ulong call, in SipralCallConfig config, out ulong placed, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_reject_transfer(ulong stack, ulong call, uint code, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_accept_transfer_placed(ulong stack, ulong call, ulong placed, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_state(ulong stack, ulong call, out uint state);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_hold_state(ulong stack, ulong call, out uint here, out uint there);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern IntPtr sipral_codec_name(uint codec);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_codec_count(out nuint count);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_codec_at(nuint index, ref SipralCodecInfo outInfo);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_codec_order(ulong stack, uint[] outCodecs, nuint capacity, out nuint count);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_media(ulong stack, ulong call, out ulong media);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_release(ulong media);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_info(ulong media, ref SipralMediaInfo outInfo);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_codec_candidate_count(ulong media, out nuint count);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_codec_candidate_at(ulong media, nuint index, ref SipralCodecCandidate outCandidate);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_path_candidate_count(ulong media, out nuint count);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_path_candidate_at(ulong media, nuint index, ref SipralPathCandidate outCandidate);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_statistics(ulong media, ulong nowMs, ref SipralStreamStats outStats);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_receive(ulong media, byte[] data, nuint len, sbyte[] from, nuint fromLen, ulong nowMs, out uint arrival);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_playback(ulong media, short[] samples, nuint capacity, out nuint written, out uint source);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_capture(ulong media, ulong nowMs, short[] samples, nuint sampleCount, ref SipralMediaPacket packet);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_set_app_rate(ulong media, uint hz);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_attach_processor(ulong media, IntPtr callback, IntPtr userData);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_detach_processor(ulong media, out uint wasAttached);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_reset_processor(ulong media, out uint wasAttached);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_mix(ulong mediaA, ulong mediaB, ulong nowMs, short[] mic, nuint micCount, short[] local, nuint localCount, ref SipralMediaPacket packetA, ref SipralMediaPacket packetB);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_poll_rtcp(ulong media, ulong nowMs, ref SipralMediaPacket packet);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_poll_transmit(ulong media, ulong nowMs, ref SipralMediaPacket packet);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_poll_farewell(ulong stack, out ulong call, ref SipralMediaPacket packet);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_dialling(ulong media, out uint dialling, out nuint waiting);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_stop_dialling(ulong media);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_record_start(ulong media, sbyte[] path, nuint pathLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_record_stop(ulong media);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_record_state(ulong media, out uint recording, out ulong recordedMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_poll_transmit(ulong stack, ref SipralTransmit transmit);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_receive_datagram(ulong stack, uint transport, byte[] data, nuint len, sbyte[] from, nuint fromLen, sbyte[] to, nuint toLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_receive_stream(ulong stack, uint transport, byte[] data, nuint len, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_transport_bind(ulong stack, uint transport, uint protocol, sbyte[] local, nuint localLen, sbyte[] remote, nuint remoteLen, ulong nowMs, out uint transportId);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_transport_failed(ulong stack, uint transport, uint error, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_transport_failed_with(ulong stack, in SipralTransportFailure failure, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_stream_closed(ulong stack, uint transport, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_stun_servers(ulong stack, sbyte[] servers, nuint serversLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_nat_map(ulong stack, sbyte[] local, nuint localLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_nat_unmap(ulong stack, sbyte[] local, nuint localLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_poll_stun(ulong stack, ref SipralTransmit transmit);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_receive_stun(ulong stack, byte[] data, nuint len, sbyte[] from, nuint fromLen, sbyte[] to, nuint toLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_turn_connected(ulong stack, sbyte[] local, nuint localLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_turn_receive(ulong stack, sbyte[] local, nuint localLen, byte[] data, nuint len, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_turn_closed(ulong stack, sbyte[] local, nuint localLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern IntPtr sipral_event_kind_name(uint kind);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_message_header_count(byte[] message, nuint messageLen, sbyte[] name, nuint nameLen, out nuint count);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_message_header(byte[] message, nuint messageLen, sbyte[] name, nuint nameLen, nuint index, out nuint offset, out nuint len);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_message_header_element_count(byte[] message, nuint messageLen, sbyte[] name, nuint nameLen, out nuint count);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_message_header_element(byte[] message, nuint messageLen, sbyte[] name, nuint nameLen, nuint index, out nuint offset, out nuint len);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_suspending(ulong stack, ulong nowMs, ref SipralSuspending outReport);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_resumed(ulong stack, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_network_changed(ulong stack, uint fromLink, sbyte[] fromAddress, nuint fromAddressLen, sbyte[] fromInterface, nuint fromInterfaceLen, uint fromResolves, uint toLink, sbyte[] toAddress, nuint toAddressLen, sbyte[] toInterface, nuint toInterfaceLen, uint toResolves, ulong nowMs, out uint recovery);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_interface_lost(ulong stack, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_name_resolution_lost(ulong stack, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_rebind(ulong stack, ulong account, uint transport, sbyte[] remote, nuint remoteLen, sbyte[] contact, nuint contactLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_cold_start(ulong stack, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_freeze(ulong stack, ulong account, byte[] buffer, nuint capacity, out nuint len, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_thaw(ulong stack, ulong account, byte[] snapshot, nuint snapshotLen, ulong asleepMs, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_time_to_ready(ulong stack, ulong account, out uint hasValue, out ulong ms);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_resolved(ulong stack, ulong dialog, sbyte[] addresses, nuint addressesLen, uint protocol);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_retarget(ulong stack, ulong account, sbyte[] registrarAddress, nuint registrarAddressLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_record_json(ulong stack, ulong call, sbyte[] buffer, nuint capacity, out nuint needed);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_diagnostics_json(ulong stack, sbyte[] buffer, nuint capacity, out nuint needed);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_subscription_conference(ulong stack, ulong subscription, ref SipralConference outConference);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_subscription_conference_user_at(ulong stack, ulong subscription, nuint index, ref SipralConferenceUser outUser);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_subscription_conference_text(ulong stack, ulong subscription, nuint index, uint which, sbyte[] buffer, nuint capacity, out nuint needed);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_set_focus(ulong stack, ulong call, uint focus);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_conference_uri(ulong stack, ulong call, sbyte[] buffer, nuint capacity, out nuint needed);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_subscribe_conference(ulong stack, ulong call, out ulong subscription, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_publish_presence(ulong stack, ulong account, in SipralPresence presence, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_unpublish_presence(ulong stack, ulong account, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_send_text(ulong media, sbyte[] text, nuint textLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_poll_text(ulong media, ulong nowMs, ref SipralMediaPacket packet);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_receive_text(ulong media, byte[] data, nuint len, sbyte[] from, nuint fromLen, ulong nowMs, out uint taken);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_record_to(ulong stack, ulong call, in SipralRecordConfig config, out ulong recording, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_stop_recording_to(ulong stack, ulong call, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_poll_recording(ulong media, ref SipralMediaPacket packet, out uint farEnd);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_recording_start(ulong stack, sbyte[] note, nuint noteLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_recording_stop(ulong stack, sbyte[] buffer, nuint capacity, out nuint needed);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_refresh(ulong stack, out nuint count);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_device_count(ulong stack, out nuint count);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_device_at(ulong stack, nuint index, ref SipralAudioDevice outDevice, sbyte[] buffer, nuint capacity, out nuint needed);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_select(ulong stack, uint role, uint device);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_selection(ulong stack, uint role, out uint selected, out uint running);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_set_gain(ulong stack, uint direction, uint gain);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_gain(ulong stack, uint direction, out uint gain);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_set_muted(ulong stack, uint direction, uint muted);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_muted(ulong stack, uint direction, out uint muted);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_level(ulong stack, uint direction, out uint peak);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_activate(ulong stack);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_deactivate(ulong stack);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_ring(ulong stack, short[] samples, nuint sampleCount, uint sampleRateHz, uint looped);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_stop_ringing(ulong stack);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_info(ulong stack, ref SipralAudioInfo outInfo);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_set_system_echo_cancellation(ulong stack, uint on);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_log(ulong stack, uint level, IntPtr callback, IntPtr userData);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_state_text(ulong stack, sbyte[] buffer, nuint capacity, out nuint needed);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_rtp_port_reserve(ulong stack, out uint port);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_rtp_port_release(ulong stack, uint port);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_stir(ulong stack, in SipralStirConfig config, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_stir_certificate(ulong stack, ulong call, byte[] chain, nuint chainLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_encryption_count(ulong media, out nuint count);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_encryption_at(ulong media, nuint index, ref SipralStreamEncryption outStream);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_dtmf_detection(ulong stack, ulong call, uint mode);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_detect_progress(ulong stack, ulong call, in SipralProgressConfig config);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_call_consent_tone(ulong stack, ulong call, in SipralConsentTone tone);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_media_record_start_with(ulong media, sbyte[] path, nuint pathLen, in SipralRecordingOptions options);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_local_conference_create(ulong stack, in SipralLocalConferenceConfig config, out ulong conference);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_local_conference_destroy(ulong conference);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_local_conference_add(ulong conference, ulong call);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_local_conference_remove(ulong conference, ulong call);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_local_conference_set_muted(ulong conference, ulong member, uint direction, uint muted);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_local_conference_set_gain(ulong conference, ulong member, uint direction, uint gain);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_local_conference_info(ulong conference, ref SipralLocalConferenceInfo outInfo);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_local_conference_member_at(ulong conference, nuint index, ref SipralLocalConferenceMember outMember);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_local_conference_talker_at(ulong conference, nuint index, out ulong member);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_local_conference_tick(ulong conference, ulong nowMs, short[] mic, nuint micCount, short[] speaker, nuint capacity, out nuint written);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_local_conference_poll_transmit(ulong conference, out ulong call, ref SipralMediaPacket packet);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_local_conference_record_start(ulong conference, sbyte[] path, nuint pathLen, in SipralRecordingOptions options);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_local_conference_record_stop(ulong conference);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_looked_up(ulong stack, ulong account, sbyte[] name, nuint nameLen, uint record, uint answer, sbyte[] records, nuint recordsLen, ulong nowMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_account_check_certificate(ulong stack, ulong account, byte[] certificate, nuint certificateLen, ulong unixSeconds, ref SipralPinnedCertificate outPinned);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_advertised_address(sbyte[] bound, nuint boundLen, sbyte[] peer, nuint peerLen, sbyte[] buffer, nuint capacity, out nuint needed);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_diagnostic_trace(ulong stack, uint on);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_stack_srtp_suite_order(ulong stack, uint[] outSuites, nuint capacity, out nuint count);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_call_set_gain(ulong stack, ulong call, uint direction, uint gain);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_call_gain(ulong stack, ulong call, uint direction, out uint gain);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_call_set_muted(ulong stack, ulong call, uint direction, uint muted);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_call_muted(ulong stack, ulong call, uint direction, out uint muted);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    internal static extern SipralStatus sipral_audio_call_level(ulong stack, ulong call, uint direction, out uint peak);

}

/// <summary>Everything the library does, with the C conventions read
/// off it.</summary>
public static partial class Sipral
{
    /// <summary>
    /// Whatever has to happen before the first call reaches the
    /// native library: finding it, for a layer that knows where to
    /// look. Run first by the static constructor, so a caller whose
    /// first use of the library is this class is served as one
    /// whose first use is anything else; with no body written
    /// anywhere, the compiler drops the call.
    /// </summary>
    static partial void BeforeLoad();

    /// <summary>
    /// Fails fast, before any of the rest of this class can be used,
    /// if the native library loaded under this assembly cannot serve
    /// the ABI it was generated against. A static constructor is
    /// guaranteed by the runtime to run before this type's first use,
    /// which is the closest a managed assembly has to "at load"
    /// without asking every caller to remember it themselves.
    ///
    /// The runtime wraps what a static constructor throws, so a
    /// mismatch does not arrive as a SipralException: the first use
    /// of this class throws TypeInitializationException, whose
    /// InnerException is the SipralException naming both versions,
    /// and every later use throws that TypeInitializationException
    /// again without running the check a second time.
    /// </summary>
    static Sipral()
    {
        BeforeLoad();
        AbiCheck(AbiVersionMajor, AbiVersionMinor);
    }

    /// <summary>
    /// The value no live handle ever takes.
    /// </summary>
    public const ulong HandleNone = 0;

    /// <summary>
    /// The ABI's major version. Nothing published against one major works
    /// against another; within one, a binding built against a minor works
    /// against a library at that minor or any later one.
    /// </summary>
    public const uint AbiVersionMajor = 1;

    /// <summary>
    /// The ABI's minor version, raised by anything the header gains. Rules:
    /// Versioning section of `docs/08-ffi.md`.
    /// </summary>
    public const uint AbiVersionMinor = 2;

    /// <summary>
    /// The ABI's patch version, raised by a fix that changes no declaration.
    /// </summary>
    public const uint AbiVersionPatch = 0;

    /// <summary>
    /// Bits of SipralCapabilities.Transports. A transport this ABI has no
    /// bit for yet reads as absent.
    ///
    /// Derived from SipralTransport's numbers (`1 &lt;&lt; (value - 1)`), so the
    /// two numberings never have to be kept in step by hand.
    /// </summary>
    public const uint TransportBitUdp = 1;

    /// <summary>
    /// See SIPRAL_TRANSPORT_BIT_UDP.
    /// </summary>
    public const uint TransportBitTcp = 2;

    /// <summary>
    /// See SIPRAL_TRANSPORT_BIT_UDP.
    /// </summary>
    public const uint TransportBitTls = 4;

    /// <summary>
    /// See SIPRAL_TRANSPORT_BIT_UDP.
    /// </summary>
    public const uint TransportBitWs = 8;

    /// <summary>
    /// See SIPRAL_TRANSPORT_BIT_UDP.
    /// </summary>
    public const uint TransportBitWss = 16;

    /// <summary>
    /// Bits of SipralCapabilities.Features.
    /// </summary>
    public const uint FeatureDtmf = 1;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF.
    /// </summary>
    public const uint FeatureRtcpMux = 2;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF.
    /// </summary>
    public const uint FeatureRecording = 4;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF.
    /// </summary>
    public const uint FeatureMediaStallWatchdog = 8;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF.
    /// </summary>
    public const uint FeatureSrtp = 16;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. RFC 6665 subscriptions and the
    /// dialog-state package a busy lamp field is built on, reached with
    /// sipral_account_subscribe.
    /// </summary>
    public const uint FeatureSubscriptions = 32;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. Opus is behind a compile-time feature
    /// (libopus is licensed, not written here). Set from the codec catalogue,
    /// not from a crate feature flag. `SIPRAL_CODEC_OPUS` keeps its number either way.
    /// </summary>
    public const uint FeatureOpus = 64;

    /// <summary>
    /// DTLS-SRTP (RFC 5764): media keys come from a handshake on the media path.
    ///
    /// Behind a compile-time feature. `SIPRAL_SRTP_DTLS` and
    /// `SIPRAL_SRTP_DTLS_REQUIRED` keep their numbers in a build without it and
    /// answer `SIPRAL_STATUS_NOT_SUPPORTED` there, never an unencrypted call.
    ///
    /// An application that sets one of those policies must also drain
    /// `sipral_media_poll_transmit`; see there.
    /// </summary>
    public const uint FeatureDtlsSrtp = 128;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. ICE in the full role (RFC 8445), with
    /// consent freshness (RFC 7675) and the SDP attributes of RFC 8839.
    ///
    /// Behind a compile-time feature and off by policy (`docs/06-nat.md`).
    /// `SIPRAL_ICE_OFFERED` and `SIPRAL_ICE_REQUIRED` keep their numbers in a
    /// build without it and answer `SIPRAL_STATUS_NOT_SUPPORTED` there.
    ///
    /// An application that sets one of those policies must also drain
    /// `sipral_media_poll_transmit`; see there.
    /// </summary>
    public const uint FeatureIce = 256;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. STUN (RFC 8489): a stack created with
    /// `SIPRAL_NAT_STUN` learns its public address and writes it in `Contact`,
    /// `c=` and `m=`. Without the feature, `SIPRAL_NAT_STUN` answers
    /// `SIPRAL_STATUS_NOT_SUPPORTED`.
    /// </summary>
    public const uint FeatureStun = 512;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. A TURN server over TCP or TLS
    /// (RFC 8656 §3.1): `sipral_stack_config_t::turn_transport` and
    /// `SIPRAL_EVENT_KIND_TURN_STREAM`. Comes with `SIPRAL_FEATURE_ICE`;
    /// without it a non-UDP `turn_transport` answers `SIPRAL_STATUS_NOT_SUPPORTED`.
    /// </summary>
    public const uint FeatureTurnStream = 1024;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. The built-in audio engine
    /// (`sipral_stack_config_t::audio` = `SIPRAL_AUDIO_DEVICE`, and the
    /// `sipral_audio_*` entry points). Clear where there is no backend (Linux,
    /// Android below API 28); `SIPRAL_AUDIO_DEVICE` then answers
    /// `SIPRAL_STATUS_NOT_SUPPORTED`. On Android it is the phone's answer, read
    /// at call time. This crate's own answer: the engine is not under the facade.
    /// </summary>
    public const uint FeatureAudioDevice = 2048;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. Caller identity on every call event:
    /// asserted identity behind `trusted_peers` (RFC 3325), `verstat`,
    /// `Privacy`, `Diversion`, `History-Info`, `Answer-Mode`, `Alert-Info`;
    /// end causes (RFC 3326) and `sipral_call_hangup_for`;
    /// `sipral_call_redirect`; an account's `privacy` and `session_timer`.
    /// </summary>
    public const uint FeatureCallerIdentity = 4096;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. A call follows a network change:
    /// `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED` and `sipral_call_media_readdress`.
    /// </summary>
    public const uint FeatureCallReaddress = 8192;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. The redacted, rate-limited log callback
    /// (`sipral_stack_log`) and the state snapshot (`sipral_stack_state_text`).
    /// Set in every build.
    /// </summary>
    public const uint FeatureLogging = 16384;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. Stack ceilings (`max_dialogs`,
    /// `max_server_transactions`, `diagnostic_decisions`, `diagnostic_records`),
    /// `SIPRAL_STATUS_LIMIT_REACHED`, and the counters in `sipral_counters_t`.
    /// </summary>
    public const uint FeatureLimits = 32768;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. STIR/SHAKEN (RFC 8224, RFC 8588): signing
    /// (`stir_key`, `stir_certificate_url`) and verification
    /// (`sipral_stack_stir`, `SIPRAL_EVENT_KIND_CALLER_VERIFICATION`,
    /// `sipral_call_stir_certificate`). Behind a compile-time feature, on by default.
    /// </summary>
    public const uint FeatureStir = 65536;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. SRTP policy and suites per account,
    /// `SIPRAL_SRTP_DTLS_OR_SDES`, `SIPRAL_STATUS_SECURITY_POLICY`, and
    /// `sipral_media_encryption_at`.
    /// </summary>
    public const uint FeatureSrtpPolicy = 131072;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. In-band signals: DTMF detection
    /// (`sipral_stack_config_t::dtmf_detection`, `sipral_call_dtmf_detection`,
    /// `SIPRAL_EVENT_KIND_IN_BAND_DIGIT`) and generation (`SIPRAL_DTMF_IN_BAND`),
    /// progress and answering-machine detection (`sipral_call_detect_progress`,
    /// `SIPRAL_EVENT_KIND_PROGRESS_DETECTED`), and `sipral_call_consent_tone`.
    /// </summary>
    public const uint FeatureInBandSignals = 262144;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. Recording formats
    /// (`sipral_media_record_start_with`): mixed or stereo, WAV/RF64,
    /// checkpointed, Ogg Opus with SIPRAL_FEATURE_OPUS; and L16 at 8 and 16 kHz.
    /// </summary>
    public const uint FeatureRecordingFormats = 524288;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. SIPREC (RFC 7866): `sipral_call_record_to`
    /// and `sipral_media_poll_recording`.
    /// </summary>
    public const uint FeatureSiprec = 1048576;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. Conference package (RFC 4575,
    /// `sipral_subscription_conference`), focus `isfocus` (RFC 4579,
    /// `sipral_call_conference_uri`), presence publish (RFC 3903) and watch (RFC 3856).
    /// </summary>
    public const uint FeatureConference = 2097152;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. Real-time text (RFC 4103): `text_address`,
    /// `sipral_media_send_text`, `SIPRAL_EVENT_KIND_TEXT_RECEIVED`.
    /// </summary>
    public const uint FeatureRealtimeText = 4194304;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. RTP/AVPF with Generic NACK and reduced-size
    /// RTCP (RFC 4585, RFC 5506): `feedback`, reported in `sipral_media_info_t`.
    /// </summary>
    public const uint FeatureRtcpFeedback = 8388608;

    /// <summary>
    /// See SIPRAL_FEATURE_DTMF. A local conference of calls on any codec
    /// and rate: `sipral_local_conference_create`,
    /// `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED`.
    /// </summary>
    public const uint FeatureLocalConference = 16777216;

    /// <summary>
    /// The buffer a caller has to bring for one outgoing packet.
    ///
    /// The bound the session builds against, not a path MTU. Checked before
    /// anything is encoded, so a frame is never encoded and then lost.
    /// </summary>
    public const nuint MediaPacketBytes = 1500;

    /// <summary>
    /// The bound for an incoming datagram that RFC 5761 §4 classifies as control.
    ///
    /// Compound RTCP from a peer may exceed the media bound (RFC 3550 sets no
    /// limit). Everything else still gets SIPRAL_MEDIA_PACKET_BYTES; outgoing
    /// RTCP always fits the media bound.
    /// </summary>
    public const nuint MediaRtcpBytes = 8192;

    /// <summary>
    /// Room enough for any address this ABI writes, the NUL included:
    /// `[2001:db8:0000:0000:0000:0000:0000:0001]:65535` and a byte to spare.
    /// </summary>
    public const nuint AddressBytes = 64;

    /// <summary>
    /// The transport a stack is created with.
    ///
    /// Never removed from the table; failure stops it, sipral_stack_transport_bind restores
    /// it. Zero in `sipral_account_config_t::transport` and `sipral_call_config_t::transport`
    /// means this one.
    /// </summary>
    public const uint TransportMain = 0;

    /// <summary>
    /// The largest message that crosses in either direction.
    ///
    /// Bounds the parser's work against a hostile peer. Size stream read buffers to this; about
    /// 1500 bytes suffices on a datagram socket.
    /// </summary>
    public const nuint MessageBytes = 65535;

    /// <summary>
    /// The longest `sipral_transport_failure_t::detail` accepted. Longer is refused, not cut.
    /// </summary>
    public const nuint TransportDetailBytes = 1024;

    /// <summary>
    /// The answer that lets an INVITE through.
    ///
    /// Any other answer refuses. Acceptance is 200, not zero, because zero is
    /// what a binding returns when the listener threw, or what an unfilled
    /// answer leaves; neither may admit a call.
    /// </summary>
    public const uint ScreenAccept = 200;

    /// <summary>
    /// The default burst: ten INVITEs from one address at once.
    ///
    /// With SIPRAL_INVITE_LIMIT_EVERY_MS, the floor every stack starts with.
    /// An INVITE past it is answered 480 and counted in
    /// `sipral_counters_t::screened_refused_by_rate`; no event is raised.
    /// </summary>
    public const uint InviteLimitBurst = 10;

    /// <summary>
    /// The default interval: one more INVITE every two seconds.
    /// </summary>
    public const ulong InviteLimitEveryMs = 2000;

    /// <summary>
    /// The voice-agent preset's burst: 128 at once.
    ///
    /// For a headless service taking every call from one trunk or proxy. Use
    /// with SIPRAL_INVITE_LIMIT_VOICE_AGENT_EVERY_MS. Equal to the default
    /// `max_dialogs`, so a rush hits that ceiling (503) before the rate.
    /// </summary>
    public const uint InviteLimitVoiceAgentBurst = 128;

    /// <summary>
    /// The voice-agent preset's interval: one more INVITE every 50 ms.
    /// </summary>
    public const ulong InviteLimitVoiceAgentEveryMs = 50;

    /// <summary>
    /// Bits of `sipral_call_event_t::privacy` and of
    /// `sipral_account_config_t::privacy` (RFC 3323 §4.2): `header`, obscure
    /// the fields that could identify the caller.
    /// </summary>
    public const uint PrivacyHeader = 1;

    /// <summary>
    /// `session`: hide the session description from the far end.
    /// </summary>
    public const uint PrivacySession = 2;

    /// <summary>
    /// `user`: user-level privacy.
    /// </summary>
    public const uint PrivacyUser = 4;

    /// <summary>
    /// `id` (RFC 3325 §9.3): keep the asserted identity inside the trust
    /// domain. What "withhold my number" asks for.
    /// </summary>
    public const uint PrivacyId = 8;

    /// <summary>
    /// `critical`: fail the call rather than go without the privacy asked
    /// for.
    /// </summary>
    public const uint PrivacyCritical = 16;

    /// <summary>
    /// `none`: no privacy, stated. Read only; an account asks for none by
    /// leaving every bit clear.
    /// </summary>
    public const uint PrivacyNone = 32;

    /// <summary>
    /// The longest text sipral_stack_state_text writes, NUL included; a
    /// buffer this size always fits.
    /// </summary>
    public const nuint StateTextMax = 16384;

    /// <summary>
    /// Every struct and union the header declares, with how long tools/abi-gen
    /// worked it out to be on each of the three layouts the ABI ships for:
    /// 64-bit pointers (p64), then 32-bit pointers with 64-bit integers aligned
    /// to four (p32a4, i386) and to eight (p32a8, ARM and Windows x86). A size
    /// test holds this binding's own layout of each record, and the library's
    /// answer from sipral_abi_struct_size, to the number for the layout it runs
    /// on; bindings/c/abi-layout.c holds a C compiler to all three.
    /// </summary>
    public static (string Name, int Marshalled, int P64, int P32A4, int P32A8)[] RecordLayouts() => new[]
    {
        ("sipral_abi_version_t", Marshal.SizeOf<SipralAbiVersion>(), 24, 20, 20),
        ("sipral_capabilities_t", Marshal.SizeOf<SipralCapabilities>(), 24, 16, 16),
        ("sipral_counters_t", Marshal.SizeOf<SipralCounters>(), 232, 228, 232),
        ("sipral_stack_config_t", Marshal.SizeOf<SipralStackConfig>(), 432, 296, 304),
        ("sipral_poll_result_t", Marshal.SizeOf<SipralPollResult>(), 48, 28, 32),
        ("sipral_stack_settings_t", Marshal.SizeOf<SipralStackSettings>(), 136, 128, 136),
        ("sipral_header_t", Marshal.SizeOf<SipralHeader>(), 32, 16, 16),
        ("sipral_account_config_t", Marshal.SizeOf<SipralAccountConfig>(), 464, 256, 264),
        ("sipral_call_config_t", Marshal.SizeOf<SipralCallConfig>(), 160, 92, 92),
        ("sipral_codec_info_t", Marshal.SizeOf<SipralCodecInfo>(), 32, 28, 28),
        ("sipral_codec_candidate_t", Marshal.SizeOf<SipralCodecCandidate>(), 24, 20, 20),
        ("sipral_path_candidate_t", Marshal.SizeOf<SipralPathCandidate>(), 88, 60, 64),
        ("sipral_media_info_t", Marshal.SizeOf<SipralMediaInfo>(), 104, 92, 96),
        ("sipral_stream_stats_t", Marshal.SizeOf<SipralStreamStats>(), 328, 312, 328),
        ("sipral_media_packet_t", Marshal.SizeOf<SipralMediaPacket>(), 64, 36, 36),
        ("sipral_processor_frame_t", Marshal.SizeOf<SipralProcessorFrame>(), 64, 32, 32),
        ("sipral_transmit_t", Marshal.SizeOf<SipralTransmit>(), 88, 48, 48),
        ("sipral_transport_failure_t", Marshal.SizeOf<SipralTransportFailure>(), 40, 24, 24),
        ("sipral_registration_event_t", Marshal.SizeOf<SipralRegistrationEvent>(), 40, 36, 40),
        ("sipral_call_event_t", Marshal.SizeOf<SipralCallEvent>(), 328, 208, 216),
        ("sipral_transfer_event_t", Marshal.SizeOf<SipralTransferEvent>(), 24, 16, 16),
        ("sipral_media_event_t", Marshal.SizeOf<SipralMediaEvent>(), 96, 80, 80),
        ("sipral_recovery_event_t", Marshal.SizeOf<SipralRecoveryEvent>(), 16, 16, 16),
        ("sipral_transport_wanted_event_t", Marshal.SizeOf<SipralTransportWantedEvent>(), 40, 20, 20),
        ("sipral_subscription_event_t", Marshal.SizeOf<SipralSubscriptionEvent>(), 56, 56, 56),
        ("sipral_announce_event_t", Marshal.SizeOf<SipralAnnounceEvent>(), 16, 16, 16),
        ("sipral_resolve_event_t", Marshal.SizeOf<SipralResolveEvent>(), 32, 24, 24),
        ("sipral_message_event_t", Marshal.SizeOf<SipralMessageEvent>(), 96, 64, 64),
        ("sipral_nat_event_t", Marshal.SizeOf<SipralNatEvent>(), 64, 40, 40),
        ("sipral_nat_relay_event_t", Marshal.SizeOf<SipralNatRelayEvent>(), 72, 40, 40),
        ("sipral_referral_event_t", Marshal.SizeOf<SipralReferralEvent>(), 40, 24, 24),
        ("sipral_turn_stream_event_t", Marshal.SizeOf<SipralTurnStreamEvent>(), 40, 24, 24),
        ("sipral_audio_event_t", Marshal.SizeOf<SipralAudioEvent>(), 20, 20, 20),
        ("sipral_stun_server_event_t", Marshal.SizeOf<SipralStunServerEvent>(), 40, 20, 20),
        ("sipral_verification_event_t", Marshal.SizeOf<SipralVerificationEvent>(), 96, 60, 60),
        ("sipral_progress_event_t", Marshal.SizeOf<SipralProgressEvent>(), 80, 80, 80),
        ("sipral_conference_event_t", Marshal.SizeOf<SipralConferenceEvent>(), 24, 20, 24),
        ("sipral_text_event_t", Marshal.SizeOf<SipralTextEvent>(), 24, 12, 12),
        ("sipral_presence_event_t", Marshal.SizeOf<SipralPresenceEvent>(), 88, 64, 72),
        ("sipral_transport_failed_event_t", Marshal.SizeOf<SipralTransportFailedEvent>(), 32, 24, 24),
        ("sipral_local_conference_event_t", Marshal.SizeOf<SipralLocalConferenceEvent>(), 40, 40, 40),
        ("sipral_locate_event_t", Marshal.SizeOf<SipralLocateEvent>(), 48, 32, 32),
        ("sipral_challenge_event_t", Marshal.SizeOf<SipralChallengeEvent>(), 40, 20, 20),
        ("sipral_token_event_t", Marshal.SizeOf<SipralTokenEvent>(), 88, 48, 48),
        ("sipral_network_test_event_t", Marshal.SizeOf<SipralNetworkTestEvent>(), 104, 88, 88),
        ("sipral_event_payload_t", Marshal.SizeOf<SipralEventPayload>(), 328, 208, 216),
        ("sipral_event_t", Marshal.SizeOf<SipralEvent>(), 384, 248, 264),
        ("sipral_suspending_t", Marshal.SizeOf<SipralSuspending>(), 32, 16, 16),
        ("sipral_screen_request_t", Marshal.SizeOf<SipralScreenRequest>(), 48, 28, 32),
        ("sipral_subscribe_config_t", Marshal.SizeOf<SipralSubscribeConfig>(), 88, 48, 48),
        ("sipral_watched_dialog_t", Marshal.SizeOf<SipralWatchedDialog>(), 32, 28, 32),
        ("sipral_push_echo_t", Marshal.SizeOf<SipralPushEcho>(), 24, 20, 24),
        ("sipral_audio_device_t", Marshal.SizeOf<SipralAudioDevice>(), 32, 28, 28),
        ("sipral_audio_info_t", Marshal.SizeOf<SipralAudioInfo>(), 48, 44, 48),
        ("sipral_audio_transmit_t", Marshal.SizeOf<SipralAudioTransmit>(), 56, 36, 40),
        ("sipral_log_record_t", Marshal.SizeOf<SipralLogRecord>(), 64, 40, 48),
        ("sipral_stir_config_t", Marshal.SizeOf<SipralStirConfig>(), 56, 44, 48),
        ("sipral_stream_encryption_t", Marshal.SizeOf<SipralStreamEncryption>(), 32, 28, 28),
        ("sipral_progress_config_t", Marshal.SizeOf<SipralProgressConfig>(), 72, 68, 68),
        ("sipral_consent_tone_t", Marshal.SizeOf<SipralConsentTone>(), 32, 28, 28),
        ("sipral_recording_options_t", Marshal.SizeOf<SipralRecordingOptions>(), 32, 28, 28),
        ("sipral_conference_t", Marshal.SizeOf<SipralConference>(), 32, 28, 28),
        ("sipral_conference_user_t", Marshal.SizeOf<SipralConferenceUser>(), 24, 20, 20),
        ("sipral_presence_t", Marshal.SizeOf<SipralPresence>(), 32, 20, 20),
        ("sipral_record_config_t", Marshal.SizeOf<SipralRecordConfig>(), 80, 40, 40),
        ("sipral_local_conference_config_t", Marshal.SizeOf<SipralLocalConferenceConfig>(), 24, 20, 20),
        ("sipral_local_conference_info_t", Marshal.SizeOf<SipralLocalConferenceInfo>(), 56, 48, 48),
        ("sipral_local_conference_member_t", Marshal.SizeOf<SipralLocalConferenceMember>(), 40, 36, 40),
        ("sipral_pinned_certificate_t", Marshal.SizeOf<SipralPinnedCertificate>(), 40, 36, 40),
        ("sipral_network_test_config_t", Marshal.SizeOf<SipralNetworkTestConfig>(), 48, 36, 40),
    };

    /// <summary>The calling thread's last error, or an empty string
    /// when it has none. Read the way C reads it: ask for the
    /// length, then for the bytes.</summary>
    public static string LastErrorMessage()
    {
        NativeMethods.sipral_last_error_message(Array.Empty<sbyte>(), 0, out var needed);
        if (needed <= 1)
        {
            return string.Empty;
        }

        var buffer = new sbyte[(int)needed];
        var status = NativeMethods.sipral_last_error_message(buffer, needed, out _);
        if (status != SipralStatus.Ok)
        {
            return string.Empty;
        }

        var bytes = new byte[buffer.Length];
        Buffer.BlockCopy(buffer, 0, bytes, 0, buffer.Length);
        var end = Array.IndexOf(bytes, (byte)0);
        return Encoding.UTF8.GetString(bytes, 0, end < 0 ? bytes.Length : end);
    }

    /// <summary>Turn a status into an exception, and nothing into
    /// nothing.</summary>
    internal static void Check(SipralStatus status)
    {
        if (status == SipralStatus.Ok)
        {
            return;
        }

        throw new SipralException(status, LastErrorMessage());
    }

    /// <summary>
    /// The short name of a status code, as a static NUL-terminated string, or
    /// null for a number that is not a status code.
    ///
    /// The string belongs to the library and lives as long as it is loaded.
    /// It is meant for a log line; the last error is the sentence for a human.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns, and is safe to call from any thread.
    /// </summary>
    public static string? StatusName(int status) =>
        Marshal.PtrToStringUTF8(NativeMethods.sipral_status_name(status));

    /// <summary>
    /// Report the ABI version this library provides.
    ///
    /// Safety
    ///
    /// `out_version` must point at a `sipral_abi_version_t` whose `size`
    /// member says how long it is.
    /// </summary>
    public static SipralAbiVersion AbiVersion()
    {
        var version = SipralAbiVersion.Sized();
        Check(NativeMethods.sipral_abi_version(ref version));
        return version;
    }

    /// <summary>
    /// Whether this library can serve a binding generated against
    /// `major`.`minor`: same major and a minor no later than this library's.
    /// Called once at load, before anything else.
    ///
    /// `SIPRAL_STATUS_UNSUPPORTED_VERSION` otherwise, with a last error naming
    /// both versions. The patch never changes a declaration, so it is not asked.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns, and is safe to call from any thread.
    /// </summary>
    public static void AbiCheck(uint major, uint minor)
    {
        Check(NativeMethods.sipral_abi_check(major, minor));
    }

    /// <summary>
    /// How many bytes this build compiled one of the ABI's structs to.
    ///
    /// `name` is the header's type name, e.g. `sipral_stack_config_t`. An
    /// unknown name is `SIPRAL_STATUS_INVALID_ARGUMENT`. Lets a binding detect
    /// a header mismatch at load.
    ///
    /// Safety
    ///
    /// `name` must be readable for `name_len` bytes, and `out_size` must
    /// point at one `size_t`.
    /// </summary>
    public static nuint AbiStructSize(string name)
    {
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var nameSigned = new sbyte[nameBytes.Length];
        Buffer.BlockCopy(nameBytes, 0, nameSigned, 0, nameBytes.Length);
        Check(NativeMethods.sipral_abi_struct_size(nameSigned, (nuint)nameSigned.Length, out var size));
        return size;
    }

    /// <summary>
    /// How many of the ABI's structs carry a `size` member.
    /// Compare it with the caller's own list of structs, so a struct added to
    /// the ABI is not missed by `sipral_abi_struct_size` checks.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    /// </summary>
    public static nuint AbiVersionedCount()
    {
        Check(NativeMethods.sipral_abi_versioned_count(out var count));
        return count;
    }

    /// <summary>
    /// What this build of the library can do, in one call.
    ///
    /// Answers the same before and after any stack exists. Safe from any
    /// thread, including the event callback.
    ///
    /// Safety
    ///
    /// `out_capabilities` must point at a `sipral_capabilities_t` whose
    /// `size` member says how long it is.
    /// </summary>
    public static SipralCapabilities Capabilities()
    {
        var capabilities = SipralCapabilities.Sized();
        Check(NativeMethods.sipral_capabilities(ref capabilities));
        return capabilities;
    }

    /// <summary>
    /// Create a stack, and write its handle to `out_stack`.
    ///
    /// The handle is written only on `SIPRAL_STATUS_OK` and must be freed with
    /// sipral_stack_destroy. A process holds 256 stacks; the next is
    /// `SIPRAL_STATUS_EXHAUSTED` until one is destroyed and no poll still runs on it.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_stack_config_t` whose `size` member
    /// says how long it is, with every pointer in it readable for the length
    /// beside it, and `out_stack` at one `sipral_handle_t`.
    /// </summary>
    public static ulong StackCreate(in SipralStackConfig config)
    {
        Check(NativeMethods.sipral_stack_create(in config, out var stack));
        return stack;
    }

    /// <summary>
    /// Read back what a stack is running with, defaults filled in.
    ///
    /// Safety
    ///
    /// `out_settings` must point at a `sipral_stack_settings_t` whose `size`
    /// member says how long it is.
    /// </summary>
    public static SipralStackSettings StackSettings(ulong stack)
    {
        var settings = SipralStackSettings.Sized();
        Check(NativeMethods.sipral_stack_settings(stack, ref settings));
        return settings;
    }

    /// <summary>
    /// Destroy a stack. The handle is dead on return; a second destroy is
    /// `SIPRAL_STATUS_STALE_HANDLE`. Safe inside the callback. Inside a frame of one
    /// of its calls it is `SIPRAL_STATUS_BUSY`. Nothing is sent: hang up, unmap and
    /// send what `sipral_stack_poll_farewell` and `sipral_stack_poll_stun` give
    /// first, or TURN relays linger up to ten minutes.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    /// </summary>
    public static void StackDestroy(ulong stack)
    {
        Check(NativeMethods.sipral_stack_destroy(stack));
    }

    /// <summary>
    /// Let the stack do its work, and deliver what it has to say.
    ///
    /// `now_ms` is the caller's monotonic clock in milliseconds; more than fifty
    /// behind is `SIPRAL_STATUS_CLOCK_BEHIND`. The callback runs inside this call,
    /// on this thread, with nothing held. `result` may be null. Drain
    /// `sipral_stack_poll_transmit` after every poll (`docs/08-ffi.md`).
    ///
    /// Safety
    ///
    /// `result` must be null or point at a `sipral_poll_result_t` whose `size`
    /// member says how long it is.
    /// </summary>
    public static SipralPollResult StackPoll(ulong stack, ulong nowMs)
    {
        var result = SipralPollResult.Sized();
        Check(NativeMethods.sipral_stack_poll(stack, nowMs, ref result));
        return result;
    }

    /// <summary>
    /// D3's health counters for one stack, since it was created.
    /// One struct copy, cheap enough to sample on a timer.
    ///
    /// Safety
    ///
    /// `out_counters` must point at a `sipral_counters_t` whose `size` member
    /// says how long it is.
    /// </summary>
    public static SipralCounters StackCounters(ulong stack)
    {
        var counters = SipralCounters.Sized();
        Check(NativeMethods.sipral_stack_counters(stack, ref counters));
        return counters;
    }

    /// <summary>
    /// Install, replace, or remove the screening policy for one stack.
    ///
    /// Every INVITE that passes sipral_stack_invite_limit reaches this
    /// callback before ringing, before `SIPRAL_EVENT_KIND_INCOMING_CALL` and
    /// before a call handle exists. A refused INVITE gets the named status
    /// (500 if it does not refuse) and is forgotten: no event, no handle. One
    /// answered `SIPRAL_SCREEN_ACCEPT` arrives as with no policy.
    ///
    /// `NULL` removes the policy. A second call replaces the first, on this
    /// stack only.
    ///
    /// The no re-entry and no unwind rules are on SipralScreenCallback.
    ///
    /// Safety
    ///
    /// `callback`, when not null, is called on whichever thread is feeding
    /// this stack bytes, while the policy is installed. `user_data` is handed
    /// back untouched and never read here.
    ///
    /// **`user_data` must outlive the last call, which may come after
    /// `sipral_stack_destroy` returns:** a receive already running on another
    /// thread holds its own share of the stack and still asks the policy. Free
    /// it once no thread is inside this stack. Replacing or removing the
    /// policy takes the lock, so once it returns the old callback is not asked
    /// again.
    /// </summary>
    public static void StackScreen(ulong stack, IntPtr callback, IntPtr userData)
    {
        Check(NativeMethods.sipral_stack_screen(stack, callback, userData));
    }

    /// <summary>
    /// How fast one source address may offer this stack an INVITE (A8).
    ///
    /// `burst` calls from one address pass at once; one more is earned every
    /// `every_ms` (see Rate). The default is ten, then one every 2000 ms;
    /// loose because most legitimate calls come from the registrar's address.
    ///
    /// A zero `burst` or zero `every_ms` is `SIPRAL_STATUS_INVALID_ARGUMENT`
    /// and changes nothing: one admits no call, the other never limits.
    ///
    /// The floor is checked before sipral_stack_screen's policy: a source
    /// past it never reaches the callback and is counted in
    /// `screened_refused_by_rate` or `screened_refused_by_crowding`.
    ///
    /// **It counts by source address.** An INVITE on a byte stream bound
    /// without a far end has no address and always passes to the policy (where
    /// SipralScreenRequest.Source is null). Naming `remote` in
    /// `sipral_stack_transport_bind` puts a stream under this floor.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    /// </summary>
    public static void StackInviteLimit(ulong stack, ulong everyMs, uint burst)
    {
        Check(NativeMethods.sipral_stack_invite_limit(stack, everyMs, burst));
    }

    /// <summary>
    /// Watch something at the far end.
    ///
    /// One SUBSCRIBE is queued on `account`'s transport and address, and the
    /// handle names the subscription until it ends.
    /// `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` reports each step. It
    /// refreshes and retries recoverable failures under the same handle;
    /// sipral_subscription_end or an end with no retry finishes it.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_subscribe_config_t` whose `size`
    /// member says how long it is, with every pointer in it readable for the
    /// length beside it. `out_subscription` must point at one
    /// `sipral_handle_t`.
    /// </summary>
    public static ulong AccountSubscribe(ulong stack, ulong account, in SipralSubscribeConfig config, ulong nowMs)
    {
        Check(NativeMethods.sipral_account_subscribe(stack, account, in config, out var subscription, nowMs));
        return subscription;
    }

    /// <summary>
    /// Give a subscription up with `Expires: 0` (§4.1.2.3).
    ///
    /// It stays live until the closing NOTIFY completes (§4.4.1);
    /// `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` with
    /// `SIPRAL_SUBSCRIPTION_END_UNSUBSCRIBED` says when. Without a dialog yet
    /// it ends at once. The handle is usable until that event.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    /// </summary>
    public static void SubscriptionEnd(ulong stack, ulong subscription, ulong nowMs)
    {
        Check(NativeMethods.sipral_subscription_end(stack, subscription, nowMs));
    }

    /// <summary>
    /// Where a subscription is, without waiting for its next event.
    /// SipralSubscriptionState.Unknown, with `SIPRAL_STATUS_OK`, for a
    /// handle that names nothing, as an ended one does.
    ///
    /// Safety
    ///
    /// `out_state` must point at one `uint32_t`.
    /// </summary>
    public static uint SubscriptionState(ulong stack, ulong subscription)
    {
        Check(NativeMethods.sipral_subscription_state(stack, subscription, out var state));
        return state;
    }

    /// <summary>
    /// What a lamp for this subscription should show: RFC 4235 §3.7.2's
    /// virtual state machine over every known dialog, ringing beating
    /// settled, SipralDialogPhase.Idle once all ended. The dialog
    /// functions below give the detail.
    ///
    /// `SIPRAL_STATUS_NOT_SUPPORTED` for a subscription with no dialog state:
    /// another package, or not live (its last notification is stale).
    ///
    /// Safety
    ///
    /// `out_phase` must point at one `uint32_t`.
    /// </summary>
    public static uint SubscriptionLamp(ulong stack, ulong subscription)
    {
        Check(NativeMethods.sipral_subscription_lamp(stack, subscription, out var phase));
        return phase;
    }

    /// <summary>
    /// How many dialogs this subscription has been told about, in order first
    /// heard. Indexes hold only until the next notification, which drops
    /// ended dialogs; read again on each
    /// SIPRAL_EVENT_KIND_NOTIFIED.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    /// </summary>
    public static nuint SubscriptionDialogCount(ulong stack, ulong subscription)
    {
        Check(NativeMethods.sipral_subscription_dialog_count(stack, subscription, out var count));
        return count;
    }

    /// <summary>
    /// One of them, by index.
    ///
    /// Safety
    ///
    /// `out_dialog` must point at a `sipral_watched_dialog_t` whose `size`
    /// member says how long it is.
    /// </summary>
    public static SipralWatchedDialog SubscriptionDialogAt(ulong stack, ulong subscription, nuint index)
    {
        var dialog = SipralWatchedDialog.Sized();
        Check(NativeMethods.sipral_subscription_dialog_at(stack, subscription, index, ref dialog));
        return dialog;
    }

    /// <summary>
    /// A piece of text about one of them, copied into the caller's buffer.
    ///
    /// `out_needed` always receives the size with the trailing NUL; ask with
    /// `capacity` zero, then with room. Too small a buffer is
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL`, nothing written. A piece the notifier
    /// did not send is just the NUL.
    ///
    /// Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// capacity of zero, and `out_needed` must point at one `size_t` or be
    /// null.
    /// </summary>
    public static nuint SubscriptionDialogText(ulong stack, ulong subscription, nuint index, uint which, sbyte[] buffer)
    {
        Check(NativeMethods.sipral_subscription_dialog_text(stack, subscription, index, which, buffer, (nuint)buffer.Length, out var needed));
        return needed;
    }

    /// <summary>
    /// Send an instant message outside any dialog (RFC 3428 §3).
    ///
    /// The handle written back names the send until
    /// `SIPRAL_EVENT_KIND_MESSAGE_SENT` reports its outcome, even a transport
    /// failure. `body` is taken as raw bytes.
    ///
    /// Safety
    ///
    /// `target` and `content_type` must be readable for their lengths, and
    /// UTF-8. `body` must be readable for `body_len` bytes, or null with a
    /// length of zero. `out_message` must point at one `sipral_handle_t`.
    /// </summary>
    public static ulong AccountMessage(ulong stack, ulong account, string target, string contentType, byte[] body, ulong nowMs)
    {
        var targetBytes = Encoding.UTF8.GetBytes(target);
        var targetSigned = new sbyte[targetBytes.Length];
        Buffer.BlockCopy(targetBytes, 0, targetSigned, 0, targetBytes.Length);
        var contentTypeBytes = Encoding.UTF8.GetBytes(contentType);
        var contentTypeSigned = new sbyte[contentTypeBytes.Length];
        Buffer.BlockCopy(contentTypeBytes, 0, contentTypeSigned, 0, contentTypeBytes.Length);
        Check(NativeMethods.sipral_account_message(stack, account, targetSigned, (nuint)targetSigned.Length, contentTypeSigned, (nuint)contentTypeSigned.Length, body, (nuint)body.Length, out var message, nowMs));
        return message;
    }

    /// <summary>
    /// A call is expected on this account, announced by a push (C2).
    ///
    /// `caller` is the SIP URI the push named. The binding is refreshed at
    /// once (§4.1.3); with no transport bound yet, the REGISTER goes when one
    /// is. Without a registrar, only the matching happens.
    ///
    /// Exactly one of the two outputs names something:
    ///
    /// - `out_announcement` when nothing arrived yet. The matching INVITE
    ///   raises `SIPRAL_EVENT_KIND_CALL_ANNOUNCED` right before its
    ///   `SIPRAL_EVENT_KIND_INCOMING_CALL`, or
    ///   `SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING` if none comes.
    /// - `out_call` when the INVITE beat the push. If the incoming-call event
    ///   was already delivered, this is the only report of the match.
    ///
    /// Safety
    ///
    /// `caller` must be readable for `caller_len` bytes, and each of
    /// `out_announcement` and `out_call` must point at one `sipral_handle_t`.
    /// </summary>
    public static (ulong Announcement, ulong Call) AccountAnnounce(ulong stack, ulong account, string caller, ulong nowMs)
    {
        var callerBytes = Encoding.UTF8.GetBytes(caller);
        var callerSigned = new sbyte[callerBytes.Length];
        Buffer.BlockCopy(callerBytes, 0, callerSigned, 0, callerBytes.Length);
        Check(NativeMethods.sipral_account_announce(stack, account, callerSigned, (nuint)callerSigned.Length, out var announcement, out var call, nowMs));
        return (announcement, call);
    }

    /// <summary>
    /// Refresh the binding now, without announcing anything (C3).
    ///
    /// For a proxy's periodic wake-up (RFC 8599 §5.5). A push proves the path
    /// works, so any back-off from an earlier outage is dropped.
    ///
    /// `SIPRAL_STATUS_OK` without sending when a REGISTER is in flight or the
    /// failure is permanent (retrying a refused password locks accounts out).
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for an account that never registers.
    /// With no transport bound yet the failure is reported, and the refresh
    /// goes out once one is.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    /// </summary>
    public static void AccountRefreshBinding(ulong stack, ulong account, ulong nowMs)
    {
        Check(NativeMethods.sipral_account_refresh_binding(stack, account, nowMs));
    }

    /// <summary>
    /// Stop expecting an announced call. `SIPRAL_STATUS_WRONG_STATE` when it
    /// was already fulfilled or expired; the event and this call can cross.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    /// </summary>
    public static void AnnouncementForget(ulong stack, ulong announcement)
    {
        Check(NativeMethods.sipral_announcement_forget(stack, announcement));
    }

    /// <summary>
    /// What the registrar said about push in its 2xx to REGISTER.
    /// `SIPRAL_STATUS_NOT_SUPPORTED` when the account did not ask for push or
    /// has no standing binding.
    ///
    /// Safety
    ///
    /// `out_echo` must point at a `sipral_push_echo_t` whose `size` member
    /// says how long it is.
    /// </summary>
    public static SipralPushEcho AccountPushEcho(ulong stack, ulong account)
    {
        var echo = SipralPushEcho.Sized();
        Check(NativeMethods.sipral_account_push_echo(stack, account, ref echo));
        return echo;
    }

    /// <summary>
    /// Configure an account and write its handle to `out_account`. Nothing is
    /// sent. It lives until sipral_account_remove or the stack's end.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_account_config_t` whose `size` member
    /// says how long it is, with every pointer in it readable for the length
    /// beside it, and `out_account` at one `sipral_handle_t`.
    /// </summary>
    public static ulong AccountAdd(ulong stack, in SipralAccountConfig config, (string Name, string Value)[]? configHeaders)
    {
        using var configHeadersArray = new SipralHeaderArray(configHeaders);
        var configValue = config;
        configValue.Headers = configHeadersArray.Address;
        configValue.HeadersLen = configHeadersArray.Count;
        Check(NativeMethods.sipral_account_add(stack, in configValue, out var account));
        return account;
    }

    /// <summary>
    /// Forget an account and everything scheduled for it. Nothing is sent: its
    /// registrar may be unreachable. Call sipral_account_unregister first
    /// to give the binding up.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void AccountRemove(ulong stack, ulong account)
    {
        Check(NativeMethods.sipral_account_remove(stack, account));
    }

    /// <summary>
    /// Register, and keep the binding alive until told otherwise.
    ///
    /// Refreshes, credential retries and back-off happen on their own until
    /// sipral_account_unregister or a refusal retrying cannot fix. Each
    /// step arrives as `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED`. An account
    /// with no registrar gets `SIPRAL_STATUS_INVALID_ARGUMENT`, nothing sent.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void AccountRegister(ulong stack, ulong account, ulong nowMs)
    {
        Check(NativeMethods.sipral_account_register(stack, account, nowMs));
    }

    /// <summary>
    /// Give the binding up: a REGISTER with `Expires: 0` (§10.2.2).
    ///
    /// Only this device's binding: `Contact: *` would remove every binding of
    /// the address of record. An account with no registrar is refused as
    /// `sipral_account_register` refuses it.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void AccountUnregister(ulong stack, ulong account, ulong nowMs)
    {
        Check(NativeMethods.sipral_account_unregister(stack, account, nowMs));
    }

    /// <summary>
    /// Where an account's registration is, as a `SipralRegistrationState`;
    /// always `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING` with no registrar.
    ///
    /// Safety
    ///
    /// `out_state` must point at one `uint32_t`.
    /// </summary>
    public static uint AccountRegistrationState(ulong stack, ulong account)
    {
        Check(NativeMethods.sipral_account_registration_state(stack, account, out var state));
        return state;
    }

    /// <summary>
    /// Give an account the OAuth 2.0 access token its server asked for
    /// (RFC 8898), replacing any it had. A `token_len` of zero removes it; a
    /// password stays.
    ///
    /// Answers `SIPRAL_EVENT_KIND_TOKEN_REQUIRED`, or renews ahead of expiry.
    /// From the next request, a `Bearer` challenge from the account's own
    /// server (and every request its cached challenge covers) gets
    /// `Authorization: Bearer &lt;token&gt;` (RFC 6750 §2.1); with `Digest` and
    /// `Bearer` offered for one realm, the token answers. A refused token is
    /// never resent. Nothing is sent now; a registration that failed for want
    /// of a token restarts with `sipral_account_register`.
    ///
    /// The application fetches tokens. The token is copied, kept out of logs
    /// and diagnostics, and wiped when replaced. A token that is not RFC 6750
    /// §2.1's `b64token` is `SIPRAL_STATUS_INVALID_ARGUMENT`, nothing changed,
    /// the error not describing it.
    ///
    /// Safety
    ///
    /// `token` must be readable for `token_len` bytes, or be null with a
    /// length of zero.
    /// </summary>
    public static void AccountSetAccessToken(ulong stack, ulong account, string token)
    {
        var tokenBytes = Encoding.UTF8.GetBytes(token);
        var tokenSigned = new sbyte[tokenBytes.Length];
        Buffer.BlockCopy(tokenBytes, 0, tokenSigned, 0, tokenBytes.Length);
        Check(NativeMethods.sipral_account_set_access_token(stack, account, tokenSigned, (nuint)tokenSigned.Length));
    }

    /// <summary>
    /// Test the network before a call: STUN, TURN, the account's server and,
    /// with an echo call, the audio path (ABI 1.2). The result arrives from a
    /// later `sipral_stack_poll` as `SIPRAL_EVENT_KIND_NETWORK_TEST` carrying
    /// `*out_test`. Tests may run side by side.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for a `probe_socket` without a STUN server
    /// or an account not located yet; `SIPRAL_STATUS_INVALID_ARGUMENT` for a
    /// `probe_socket` that is not an address or is a signalling socket.
    /// Nothing starts when anything is refused.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_network_test_config_t` whose `size`
    /// member says how long it is, with `probe_socket` readable for
    /// `probe_socket_len` bytes; `out_test` must point at one `uint32_t`.
    /// </summary>
    public static uint StackNetworkTest(ulong stack, in SipralNetworkTestConfig config, ulong nowMs)
    {
        Check(NativeMethods.sipral_stack_network_test(stack, in config, nowMs, out var test));
        return test;
    }

    /// <summary>
    /// Place a call, and write its handle to `out_call`.
    ///
    /// The handle exists before any dialog, so the INVITE can be hung up while in flight.
    /// Branches a proxy forks get their own handles (`SIPRAL_EVENT_KIND_CALL_FORKED`).
    ///
    /// With `media_address` set the stack writes the offer and runs the audio:
    /// `SIPRAL_EVENT_KIND_MEDIA_STARTED` says when, and `sipral_media_*` carry the packets.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_call_config_t` whose `size` member says how long it is,
    /// with every pointer in it readable for the length beside it, and `out_call` at one
    /// `sipral_handle_t`.
    /// </summary>
    public static ulong CallPlace(ulong stack, ulong account, in SipralCallConfig config, (string Name, string Value)[]? configHeaders, ulong nowMs)
    {
        using var configHeadersArray = new SipralHeaderArray(configHeaders);
        var configValue = config;
        configValue.Headers = configHeadersArray.Address;
        configValue.HeadersLen = configHeadersArray.Count;
        Check(NativeMethods.sipral_call_place(stack, account, in configValue, out var call, nowMs));
        return call;
    }

    /// <summary>
    /// Say a call that came in is ringing.
    ///
    /// A description makes it a 183 rather than a 180, since a 180 with a body is ambiguous.
    ///
    /// Safety
    ///
    /// `sdp` must be null or readable for `sdp_len` bytes.
    /// </summary>
    public static void CallRing(ulong stack, ulong call, byte[] sdp, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_ring(stack, call, sdp, (nuint)sdp.Length, nowMs));
    }

    /// <summary>
    /// Say a call that came in is ringing, with this stack running the audio before anybody
    /// answers.
    ///
    /// The answer to the INVITE's offer is written from this stack's codec order against
    /// `config.media_address`, and the session opens at once: the far end hears what the
    /// application plays. `SIPRAL_EVENT_KIND_MEDIA_STARTED` follows. `config.srtp` and
    /// `config.codecs` override the stack's for this call, and `sipral_call_answer_media` keeps
    /// what was settled here; it is the only way an incoming call chooses its own SRTP policy.
    ///
    /// `sipral_call_answer_media` then reuses this session and description. What its 200 OK
    /// carries follows RFC 3262 §5 and RFC 6337 §3.1.1, by whether the 183 went out reliably
    /// (`docs/05-media.md`, "Ringing with media").
    ///
    /// Setting `target`, `sdp`, `destination`, `transport`, `keep_all_forks` or `headers` is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` naming it. `SIPRAL_STATUS_WRONG_STATE`, with nothing
    /// sent: an INVITE with no offer (RFC 3261 §13.2.1, RFC 6337 §3.1.2); a second call of this;
    /// a call after a `sipral_call_ring` that sent the application's own description
    /// (RFC 3261 §13.2.1, RFC 6337 §3.1.1).
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_call_config_t` whose `size` member says how long it is,
    /// with `media_address` readable for `media_address_len` bytes.
    /// </summary>
    public static void CallRingMedia(ulong stack, ulong call, in SipralCallConfig config, (string Name, string Value)[]? configHeaders, ulong nowMs)
    {
        using var configHeadersArray = new SipralHeaderArray(configHeaders);
        var configValue = config;
        configValue.Headers = configHeadersArray.Address;
        configValue.HeadersLen = configHeadersArray.Count;
        Check(NativeMethods.sipral_call_ring_media(stack, call, in configValue, nowMs));
    }

    /// <summary>
    /// Answer a call that came in with `sdp`, the answer to the INVITE's offer (required).
    ///
    /// Safety
    ///
    /// `sdp` must be readable for `sdp_len` bytes.
    /// </summary>
    public static void CallAnswer(ulong stack, ulong call, byte[] sdp, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_answer(stack, call, sdp, (nuint)sdp.Length, nowMs));
    }

    /// <summary>
    /// Answer a call that came in, and let this stack run its audio.
    ///
    /// The answer is written from this stack's codec order against `media_address`.
    /// `SIPRAL_EVENT_KIND_MEDIA_STARTED` follows once the stream is open.
    ///
    /// On a call `sipral_call_ring_media` already rang, the 183's description and session
    /// stand and `media_address` must still parse but is unused. The 200 OK repeats that
    /// description if the 183 went unreliably and carries none if reliably (RFC 6337 §3.1.1).
    ///
    /// Safety
    ///
    /// `media_address` must be readable for `media_address_len` bytes.
    /// </summary>
    public static void CallAnswerMedia(ulong stack, ulong call, string mediaAddress, ulong nowMs)
    {
        var mediaAddressBytes = Encoding.UTF8.GetBytes(mediaAddress);
        var mediaAddressSigned = new sbyte[mediaAddressBytes.Length];
        Buffer.BlockCopy(mediaAddressBytes, 0, mediaAddressSigned, 0, mediaAddressBytes.Length);
        Check(NativeMethods.sipral_call_answer_media(stack, call, mediaAddressSigned, (nuint)mediaAddressSigned.Length, nowMs));
    }

    /// <summary>
    /// Answer a call that came in with media this stack describes, from `config`:
    /// `sipral_call_answer_media` with the members `sipral_call_ring_media` reads. Any other
    /// member set is `SIPRAL_STATUS_INVALID_ARGUMENT` naming it. On a call already rung with
    /// media, only `focus` changes anything.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_call_config_t` whose `size` member says how long it is,
    /// with every pointer in it readable for the length beside it.
    /// </summary>
    public static void CallAnswerWith(ulong stack, ulong call, in SipralCallConfig config, (string Name, string Value)[]? configHeaders, ulong nowMs)
    {
        using var configHeadersArray = new SipralHeaderArray(configHeaders);
        var configValue = config;
        configValue.Headers = configHeadersArray.Address;
        configValue.HeadersLen = configHeadersArray.Count;
        Check(NativeMethods.sipral_call_answer_with(stack, call, in configValue, nowMs));
    }

    /// <summary>
    /// Refuse a call that came in with a response code of your choosing: 486 for a line in use,
    /// 603 for a person who declines. A proxy acts differently on each.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallReject(ulong stack, ulong call, uint code, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_reject(stack, call, code, nowMs));
    }

    /// <summary>
    /// Hang up, whatever the call is doing: CANCEL before an answer, BYE after, a refusal for
    /// an unanswered incoming call. A call already ending is left alone.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallHangup(ulong stack, ulong call, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_hangup(stack, call, nowMs));
    }

    /// <summary>
    /// Set the header fields that go on what this call sends at the application's request,
    /// until set again.
    ///
    /// They go on the responses of `sipral_call_ring`, `sipral_call_answer`,
    /// `sipral_call_answer_media` and `sipral_call_reject`, the refusal or BYE of
    /// `sipral_call_hangup`, and the re-INVITE or UPDATE of `sipral_call_hold` and
    /// `sipral_call_resume`. Kept across them. Never on a CANCEL (a proxy replaces it) or on
    /// what the stack sends by itself.
    ///
    /// Replaces the previous set whole; `headers_len` zero clears it. Each field is checked as
    /// on `sipral_call_config_t::headers`; a refusal names the element and keeps the old set.
    ///
    /// Safety
    ///
    /// `headers` must be null with `headers_len` zero, or readable for `headers_len` elements,
    /// each with a name and a value readable for the lengths beside them.
    /// </summary>
    public static void CallSetHeaders(ulong stack, ulong call, (string Name, string Value)[] headers)
    {
        using var headersArray = new SipralHeaderArray(headers);
        Check(NativeMethods.sipral_call_set_headers(stack, call, headersArray.Address, headersArray.Count));
    }

    /// <summary>
    /// Put a call on hold (RFC 3264 §8.4).
    ///
    /// The stack writes the description: the negotiated one with every direction changed. A
    /// hold already in place or on its way sends nothing and succeeds.
    ///
    /// While another session change runs, it succeeds and waits until that is over
    /// (RFC 3261 §14.1); the outcome arrives as `SIPRAL_EVENT_KIND_SESSION_CHANGED` or
    /// `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED`. Only the last state asked for waits, so a
    /// resume asked for while a hold is still on its way goes after it. One still waiting
    /// when the call ends is never sent.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallHold(ulong stack, ulong call, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_hold(stack, call, nowMs));
    }

    /// <summary>
    /// Take it off hold. Each stream returns to its previous direction (a receive-only one stays
    /// receive-only), and waits for a running change as `sipral_call_hold` does.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallResume(ulong stack, ulong call, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_resume(stack, call, nowMs));
    }

    /// <summary>
    /// Offer a call again on another list of codecs (RFC 3264 §8.3.2).
    ///
    /// `codecs` is as `sipral_call_config_t::codecs`. Only the codecs change: address, keys,
    /// fingerprint and ICE credentials are offered as they are, and a held call stays held. A
    /// dynamic payload type keeps its codec; a new codec gets an unused number.
    ///
    /// The list becomes the call's once accepted; `SIPRAL_EVENT_KIND_MEDIA_CHANGED` names the
    /// codec settled on. A refusal arrives as `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED`.
    ///
    /// For a call placed or answered with `media_address`. `SIPRAL_STATUS_NOT_SUPPORTED`: a name
    /// with no codec in this build. `SIPRAL_STATUS_INVALID_ARGUMENT`: an empty list, a repeated
    /// name or a stray comma. `SIPRAL_STATUS_WRONG_STATE`: no stack-written description, none
    /// agreed yet, a refused stream, an early call whose far end never listed UPDATE, or
    /// another change on its way. `SIPRAL_STATUS_EXHAUSTED`: no dynamic payload type left.
    ///
    /// Safety
    ///
    /// `codecs` must be readable for `codecs_len` bytes.
    /// </summary>
    public static void CallChangeCodecs(ulong stack, ulong call, string codecs, ulong nowMs)
    {
        var codecsBytes = Encoding.UTF8.GetBytes(codecs);
        var codecsSigned = new sbyte[codecsBytes.Length];
        Buffer.BlockCopy(codecsBytes, 0, codecsSigned, 0, codecsBytes.Length);
        Check(NativeMethods.sipral_call_change_codecs(stack, call, codecsSigned, (nuint)codecsSigned.Length, nowMs));
    }

    /// <summary>
    /// Restart ICE on a call (RFC 8445 §9): offer it again with new credentials and check every
    /// pair again once the far end answers.
    ///
    /// The last description is offered again with new `ice-ufrag` and `ice-pwd`
    /// (RFC 8839 §4.4.1.1.1), the candidates still held, and the same role. Nothing reaches the
    /// agent until the far end accepts (§4.4). The old pair carries audio meanwhile, and the new
    /// selection arrives as `SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN`. A refusal arrives as
    /// `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED` and leaves ICE as it was.
    ///
    /// The remedy for lost consent (`SIPRAL_MEDIA_FAULT_ICE`) and a local network change. For a
    /// call placed or answered with `media_address`. `SIPRAL_STATUS_WRONG_STATE`: no
    /// stack-written description, no ICE agent, no description yet, or another change on its
    /// way. `SIPRAL_STATUS_NOT_SUPPORTED` from a build without ICE.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallRestartIce(ulong stack, ulong call, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_restart_ice(stack, call, nowMs));
    }

    /// <summary>
    /// Describe a call's media at a socket the application bound on a new network and offer it
    /// to the far end (RFC 3264 §8.3.1), as `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED` asks.
    ///
    /// `media_address` is the new socket, `host:port`; `public_address` is where it appears
    /// from outside, or null with length zero. The re-INVITE moves only `c=` and the `m=` port,
    /// and carries the account's current `Contact`, so `sipral_account_rebind` goes first. The
    /// new socket is the call's whatever the answer: `SIPRAL_EVENT_KIND_SESSION_CHANGED` and
    /// `SIPRAL_EVENT_KIND_MEDIA_CHANGED`, or `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED`.
    ///
    /// For a call placed or answered with `media_address`. `SIPRAL_STATUS_WRONG_STATE`: no
    /// stack-written description, a session running ICE (moved by a restart instead), no
    /// description yet, or another change on its way.
    ///
    /// Safety
    ///
    /// `media_address` must be readable for `media_address_len` bytes, and `public_address` for
    /// `public_address_len` bytes or null with a length of zero.
    /// </summary>
    public static void CallMediaReaddress(ulong stack, ulong call, string mediaAddress, string publicAddress, ulong nowMs)
    {
        var mediaAddressBytes = Encoding.UTF8.GetBytes(mediaAddress);
        var mediaAddressSigned = new sbyte[mediaAddressBytes.Length];
        Buffer.BlockCopy(mediaAddressBytes, 0, mediaAddressSigned, 0, mediaAddressBytes.Length);
        var publicAddressBytes = Encoding.UTF8.GetBytes(publicAddress);
        var publicAddressSigned = new sbyte[publicAddressBytes.Length];
        Buffer.BlockCopy(publicAddressBytes, 0, publicAddressSigned, 0, publicAddressBytes.Length);
        Check(NativeMethods.sipral_call_media_readdress(stack, call, mediaAddressSigned, (nuint)mediaAddressSigned.Length, publicAddressSigned, (nuint)publicAddressSigned.Length, nowMs));
    }

    /// <summary>
    /// End a call and say why (RFC 3326): what `sipral_call_hangup` does, with
    /// a `Reason` on the BYE or the CANCEL it turns into.
    ///
    /// `sip_cause` (SIP status) and `q850_cause` (Q.850) are each zero for none;
    /// neither is a plain hangup. `text` goes on the first value written. On
    /// refusing an unanswered incoming call only the Q.850 value goes
    /// (RFC 6432).
    ///
    /// Safety
    ///
    /// `text` must be readable for `text_len` bytes or null with a length of
    /// zero.
    /// </summary>
    public static void CallHangupFor(ulong stack, ulong call, uint sipCause, uint q850Cause, string text, ulong nowMs)
    {
        var textBytes = Encoding.UTF8.GetBytes(text);
        var textSigned = new sbyte[textBytes.Length];
        Buffer.BlockCopy(textBytes, 0, textSigned, 0, textBytes.Length);
        Check(NativeMethods.sipral_call_hangup_for(stack, call, sipCause, q850Cause, textSigned, (nuint)textSigned.Length, nowMs));
    }

    /// <summary>
    /// Answer a call that came in with a 3xx: somewhere else to try
    /// (RFC 3261 §21.3), and why (RFC 5806).
    ///
    /// `status_code` is 300 to 399. `targets` is comma-separated URIs in
    /// preference order, required except for 380. `reason`, when given, adds a
    /// `Diversion` with that reason token naming the called address.
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for a bad status or target;
    /// `SIPRAL_STATUS_WRONG_STATE` for a call not waiting to be answered.
    ///
    /// Safety
    ///
    /// `targets` must be readable for `targets_len` bytes and `reason` for
    /// `reason_len` bytes, each or null with a length of zero.
    /// </summary>
    public static void CallRedirect(ulong stack, ulong call, uint statusCode, string targets, string reason, ulong nowMs)
    {
        var targetsBytes = Encoding.UTF8.GetBytes(targets);
        var targetsSigned = new sbyte[targetsBytes.Length];
        Buffer.BlockCopy(targetsBytes, 0, targetsSigned, 0, targetsBytes.Length);
        var reasonBytes = Encoding.UTF8.GetBytes(reason);
        var reasonSigned = new sbyte[reasonBytes.Length];
        Buffer.BlockCopy(reasonBytes, 0, reasonSigned, 0, reasonBytes.Length);
        Check(NativeMethods.sipral_call_redirect(stack, call, statusCode, targetsSigned, (nuint)targetsSigned.Length, reasonSigned, (nuint)reasonSigned.Length, nowMs));
    }

    /// <summary>
    /// How many entries one of a call's identity lists has. Every piece of an
    /// entry gives the same count. Read once from the INVITE; zero for a call
    /// this end placed.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    /// </summary>
    public static nuint CallIdentityCount(ulong stack, ulong call, uint which)
    {
        Check(NativeMethods.sipral_call_identity_count(stack, call, which, out var count));
        return count;
    }

    /// <summary>
    /// One piece of one entry of a call's identity lists, copied into the
    /// caller's buffer with a trailing NUL.
    ///
    /// `out_needed` always receives the bytes needed including the NUL; ask
    /// with `capacity` zero, then again with room. Too small is
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL` with nothing written. A missing piece
    /// is just the NUL. An index past the end is `SIPRAL_STATUS_INVALID_ARGUMENT`.
    ///
    /// Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or null with a capacity
    /// of zero, and `out_needed` must point at one `size_t` or be null.
    /// </summary>
    public static nuint CallIdentityText(ulong stack, ulong call, nuint index, uint which, sbyte[] buffer)
    {
        Check(NativeMethods.sipral_call_identity_text(stack, call, index, which, buffer, (nuint)buffer.Length, out var needed));
        return needed;
    }

    /// <summary>
    /// Join two active calls into a local three-way conference: each far end hears the other
    /// and this end's microphone, mixed. sipral_media_mix
    /// drives it one frame at a time; this only records the pairing.
    ///
    /// No SIP conference: neither far end is told. Both calls need running media and the same
    /// sample rate and frame length, since nothing resamples.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for `call_a == call_b`; `SIPRAL_STATUS_WRONG_STATE` for a
    /// call with no running session, one already joined, or mismatched rate or frame length.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallJoin(ulong stack, ulong callA, ulong callB)
    {
        Check(NativeMethods.sipral_call_join(stack, callA, callB));
    }

    /// <summary>
    /// Take `call` back out of its pair. Neither session is touched; each call carries its own
    /// audio again. `SIPRAL_STATUS_WRONG_STATE` for a call not joined.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallLeave(ulong stack, ulong call)
    {
        Check(NativeMethods.sipral_call_leave(stack, call));
    }

    /// <summary>
    /// Accept a change the far end offered (`SIPRAL_EVENT_KIND_SESSION_OFFERED`).
    ///
    /// `sdp`, the answer, is required (RFC 3264 §5): null or empty is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` and the request still waits. An unanswered re-INVITE
    /// ends the call, so this or sipral_call_reject_session must follow the event. An offer
    /// in a PRACK (RFC 3262 §5) is answered the same way, in the PRACK's 2xx.
    ///
    /// Only for a call the application describes; a stack-described call answers its own
    /// re-offers, so this is `SIPRAL_STATUS_WRONG_STATE` there.
    ///
    /// Safety
    ///
    /// `sdp` must be null or readable for `sdp_len` bytes.
    /// </summary>
    public static void CallAcceptSession(ulong stack, ulong call, byte[] sdp, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_accept_session(stack, call, sdp, (nuint)sdp.Length, nowMs));
    }

    /// <summary>
    /// Refuse one instead; the session stands as it was (§14.1). 488 Not Acceptable Here says
    /// the description was the problem. Only for a call the application describes.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallRejectSession(ulong stack, ulong call, uint code, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_reject_session(stack, call, code, nowMs));
    }

    /// <summary>
    /// Send DTMF on a call that is up, in the form the far end takes.
    ///
    /// `digits` are `0`-`9`, `*`, `#` and `A`-`D`, the sixteen events of
    /// RFC 4733 §3.2, in the order they were pressed. The whole string is checked first: one
    /// bad character sends nothing. `duration_ms` is each tone's length, or zero for 100 ms.
    ///
    /// `via` is a SipralDtmf. `SIPRAL_DTMF_RTP` puts the digits in the media, replacing the
    /// audio while they last, queued. The INFO forms send one request per digit, each after the
    /// previous one's final answer, since UDP may reorder overlapping transactions. A refusal,
    /// timeout or transport failure ends the sequence: `SIPRAL_EVENT_KIND_DTMF_SENT` names that
    /// digit, and the rest are discarded unreported. Digits handed over meanwhile queue behind.
    /// A call holds at most sixty-four INFO digits, the one in flight included; a string past
    /// that is refused whole with `SIPRAL_STATUS_INVALID_ARGUMENT`.
    ///
    /// `SIPRAL_DTMF_RTP` without a negotiated telephone event writes the tones into the audio,
    /// as `SIPRAL_DTMF_IN_BAND` always does. The media forms are `SIPRAL_STATUS_WRONG_STATE`
    /// before there is media, the INFO forms before there is a dialog.
    ///
    /// Safety
    ///
    /// `digits` must be readable for `digits_len` bytes.
    /// </summary>
    public static void CallSendDtmf(ulong stack, ulong call, string digits, uint via, uint durationMs, ulong nowMs)
    {
        var digitsBytes = Encoding.UTF8.GetBytes(digits);
        var digitsSigned = new sbyte[digitsBytes.Length];
        Buffer.BlockCopy(digitsBytes, 0, digitsSigned, 0, digitsBytes.Length);
        Check(NativeMethods.sipral_call_send_dtmf(stack, call, digitsSigned, (nuint)digitsSigned.Length, via, durationMs, nowMs));
    }

    /// <summary>
    /// Ask the far end to call somebody else, and hang up when it has (RFC 3515).
    ///
    /// A blind transfer. This end stays in the call until the transfer succeeds, so a failed
    /// transfer does not lose the call. Progress arrives as `SIPRAL_EVENT_KIND_TRANSFER_PROGRESS`,
    /// then `SIPRAL_EVENT_KIND_TRANSFER_DONE`.
    ///
    /// Safety
    ///
    /// `target` must be readable for `target_len` bytes.
    /// </summary>
    public static void CallTransfer(ulong stack, ulong call, string target, ulong nowMs)
    {
        var targetBytes = Encoding.UTF8.GetBytes(target);
        var targetSigned = new sbyte[targetBytes.Length];
        Buffer.BlockCopy(targetBytes, 0, targetSigned, 0, targetBytes.Length);
        Check(NativeMethods.sipral_call_transfer(stack, call, targetSigned, (nuint)targetSigned.Length, nowMs));
    }

    /// <summary>
    /// Call the transfer target, and write the new call's handle to `out_consultation`.
    ///
    /// The consultation leg of an attended transfer; sipral_call_transfer_to follows.
    /// Holding `call` first is the application's choice. `media_address` is
    /// `SIPRAL_STATUS_NOT_SUPPORTED` here: place the consultation with `sdp` and run its audio.
    ///
    /// Safety
    ///
    /// As sipral_call_place.
    /// </summary>
    public static ulong CallConsult(ulong stack, ulong call, in SipralCallConfig config, (string Name, string Value)[]? configHeaders, ulong nowMs)
    {
        using var configHeadersArray = new SipralHeaderArray(configHeaders);
        var configValue = config;
        configValue.Headers = configHeadersArray.Address;
        configValue.HeadersLen = configHeadersArray.Count;
        Check(NativeMethods.sipral_call_consult(stack, call, in configValue, out var consultation, nowMs));
        return consultation;
    }

    /// <summary>
    /// Hand `call` to the far end of `other` (RFC 3891): the attended half of a transfer, where
    /// `other` is normally the consultation call. Any call that is up may be named.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallTransferTo(ulong stack, ulong call, ulong other, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_transfer_to(stack, call, other, nowMs));
    }

    /// <summary>
    /// Take a transfer that was asked for, place the call it names as sipral_call_place
    /// does, and write its handle to `out_placed`.
    ///
    /// `config.target` set is `SIPRAL_STATUS_INVALID_ARGUMENT`: the REFER names the target.
    /// Every other member means what it means on `sipral_call_place`. `Replaces` or
    /// `Referred-By` among `headers` is `SIPRAL_STATUS_INVALID_ARGUMENT` with the transfer still
    /// waiting: the INVITE takes both from the REFER. Neither `sdp` nor `media_address` is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT`, as on `sipral_call_place`.
    ///
    /// `call` may be a referral's handle (`SIPRAL_EVENT_KIND_REFERRAL`, a REFER outside any
    /// dialog), placed from the account the event names. Its handle is stale once the REFER is
    /// answered; one refused before anything was sent is still there to take.
    ///
    /// A call that cannot be sent after the 202 ends the subscription with RFC 3515 §2.4.5's
    /// 503, and this answers `SIPRAL_STATUS_NOT_SENT`.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_call_config_t` whose `size` member says how long it is,
    /// with every pointer in it readable for the length beside it, and `out_placed` at one
    /// `sipral_handle_t`.
    /// </summary>
    public static ulong CallAcceptTransfer(ulong stack, ulong call, in SipralCallConfig config, (string Name, string Value)[]? configHeaders, ulong nowMs)
    {
        using var configHeadersArray = new SipralHeaderArray(configHeaders);
        var configValue = config;
        configValue.Headers = configHeadersArray.Address;
        configValue.HeadersLen = configHeadersArray.Count;
        Check(NativeMethods.sipral_call_accept_transfer(stack, call, in configValue, out var placed, nowMs));
        return placed;
    }

    /// <summary>
    /// Refuse one instead.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallRejectTransfer(ulong stack, ulong call, uint code, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_reject_transfer(stack, call, code, nowMs));
    }

    /// <summary>
    /// Take a transfer asked for inside `call` with a call the application placed itself,
    /// `placed`, and report that call's progress to the far end as if the REFER had placed it
    /// (ABI 1.2).
    ///
    /// For an application that reaches the target its own way, such as a bridge. The REFER is
    /// answered 202 (RFC 3515 §2.4.2); `placed` then reports each provisional status in a
    /// NOTIFY (§2.4.5), and its final status ends the subscription (§2.4.7). A `placed` already
    /// up is reported with a 200 at once. Ending `call` stays the application's.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when nothing waits on `call` (a referral's handle included),
    /// or `placed` is `call`, is over, or already reports to another REFER. A refusal leaves the
    /// REFER waiting.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallAcceptTransferPlaced(ulong stack, ulong call, ulong placed, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_accept_transfer_placed(stack, call, placed, nowMs));
    }

    /// <summary>
    /// Where a call is, as a `SipralCallState`.
    ///
    /// A call that is over answers `SIPRAL_CALL_STATE_TERMINATED` until the poll delivering
    /// `SIPRAL_EVENT_KIND_CALL_ENDED` retires its handle, then `SIPRAL_STATUS_STALE_HANDLE`. A
    /// referral's handle is `SIPRAL_STATUS_WRONG_STATE`: there is no call yet.
    ///
    /// Safety
    ///
    /// `out_state` must point at one `uint32_t`.
    /// </summary>
    public static uint CallState(ulong stack, ulong call)
    {
        Check(NativeMethods.sipral_call_state(stack, call, out var state));
        return state;
    }

    /// <summary>
    /// Which way a call is held: `out_here` when this end asked the far end to stop sending,
    /// `out_there` when the far end asked. Either may be null.
    ///
    /// Safety
    ///
    /// `out_here` and `out_there` must each be null or point at one `uint32_t`.
    /// </summary>
    public static (uint Here, uint There) CallHoldState(ulong stack, ulong call)
    {
        Check(NativeMethods.sipral_call_hold_state(stack, call, out var here, out var there));
        return (here, there);
    }

    /// <summary>
    /// The name of a codec, as a static NUL-terminated string, or null for a
    /// number this build has no codec for.
    ///
    /// Spelled as IANA registered it; L16 carries its rate (`L16/8000`,
    /// `L16/16000`), as in a codec order. Owned by the library, valid while
    /// it is loaded.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns, and is safe to call from any thread.
    /// </summary>
    public static string? CodecName(uint codec) =>
        Marshal.PtrToStringUTF8(NativeMethods.sipral_codec_name(codec));

    /// <summary>
    /// How many codecs this build contains, fixed at compile time.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    /// </summary>
    public static nuint CodecCount()
    {
        Check(NativeMethods.sipral_codec_count(out var count));
        return count;
    }

    /// <summary>
    /// One of them, by index, from zero to what `sipral_codec_count` said.
    ///
    /// In this build's preference order, the default offer; G.729 comes last
    /// and is offered only when a codec order names it.
    ///
    /// Safety
    ///
    /// `out_info` must point at a `sipral_codec_info_t` whose `size` member
    /// says how long it is.
    /// </summary>
    public static SipralCodecInfo CodecAt(nuint index)
    {
        var info = SipralCodecInfo.Sized();
        Check(NativeMethods.sipral_codec_at(index, ref info));
        return info;
    }

    /// <summary>
    /// The codecs this stack offers, in the order it offers them.
    ///
    /// What `sipral_stack_config_t::codecs` came to. `out_count` always gets
    /// the total; a short buffer (or null with zero capacity) gets
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL`.
    ///
    /// Safety
    ///
    /// `out_codecs` must be writable for `capacity` `uint32_t` or null with a
    /// capacity of zero, and `out_count` must point at one `size_t` or be null.
    /// </summary>
    public static nuint StackCodecOrder(ulong stack, uint[] outCodecs)
    {
        Check(NativeMethods.sipral_stack_codec_order(stack, outCodecs, (nuint)outCodecs.Length, out var count));
        return count;
    }

    /// <summary>
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
    /// Safety
    ///
    /// `out_media` must point at one `sipral_handle_t`.
    /// </summary>
    public static ulong CallMedia(ulong stack, ulong call)
    {
        Check(NativeMethods.sipral_call_media(stack, call, out var media));
        return media;
    }

    /// <summary>
    /// Let a media handle go.
    ///
    /// Valid whether or not the call or stack still exists. The session is not
    /// touched; releasing mid-call stops nothing. A second release is
    /// `SIPRAL_STATUS_STALE_HANDLE`.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    /// </summary>
    public static void MediaRelease(ulong media)
    {
        Check(NativeMethods.sipral_media_release(media));
    }

    /// <summary>
    /// What one call's media settled on.
    ///
    /// Safety
    ///
    /// `out_info` must point at a `sipral_media_info_t` whose `size` member
    /// says how long it is.
    /// </summary>
    public static SipralMediaInfo MediaInfo(ulong media)
    {
        var info = SipralMediaInfo.Sized();
        Check(NativeMethods.sipral_media_info(media, ref info));
        return info;
    }

    /// <summary>
    /// How many codecs were in the running on this call.
    ///
    /// This call's catalogue: the stack's order unless
    /// `sipral_call_config_t::codecs` named another. Zero is a valid answer.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    /// </summary>
    public static nuint MediaCodecCandidateCount(ulong media)
    {
        Check(NativeMethods.sipral_media_codec_candidate_count(media, out var count));
        return count;
    }

    /// <summary>
    /// One of them, by index, from zero to what
    /// `sipral_media_codec_candidate_count` said, in this call's own order.
    ///
    /// An index past the end is `SIPRAL_STATUS_INVALID_ARGUMENT`.
    ///
    /// Safety
    ///
    /// `out_candidate` must point at a `sipral_codec_candidate_t` whose `size`
    /// member says how long it is.
    /// </summary>
    public static SipralCodecCandidate MediaCodecCandidateAt(ulong media, nuint index)
    {
        var candidate = SipralCodecCandidate.Sized();
        Check(NativeMethods.sipral_media_codec_candidate_at(media, index, ref candidate));
        return candidate;
    }

    /// <summary>
    /// How many paths this call's ICE agent tried: every candidate pair its
    /// checklist held, then every relay it held.
    ///
    /// Zero for a call not using ICE. A restart (RFC 8445 §9) starts the list
    /// again.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    /// </summary>
    public static nuint MediaPathCandidateCount(ulong media)
    {
        Check(NativeMethods.sipral_media_path_candidate_count(media, out var count));
        return count;
    }

    /// <summary>
    /// One of them, by index, from zero to what
    /// `sipral_media_path_candidate_count` said: the pairs in the order the
    /// checklist took them in, then the relays.
    ///
    /// An index past the end is `SIPRAL_STATUS_INVALID_ARGUMENT`; an address
    /// buffer smaller than `SIPRAL_ADDRESS_BYTES` is
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL`, before anything is written.
    ///
    /// Safety
    ///
    /// `out_candidate` must point at a `sipral_path_candidate_t` whose `size`
    /// member says how long it is, and its two address buffers, when not
    /// null, must be writable for the capacities beside them.
    /// </summary>
    public static void MediaPathCandidateAt(ulong media, nuint index, ref SipralPathCandidate outCandidate)
    {
        Check(NativeMethods.sipral_media_path_candidate_at(media, index, ref outCandidate));
    }

    /// <summary>
    /// What one call's media has cost, and what it is costing now.
    ///
    /// `now_ms` is the caller's monotonic clock; it does not move the stack's
    /// clock. The end-of-call record arrives as
    /// `SIPRAL_EVENT_KIND_MEDIA_STATISTICS`; by then this answers
    /// `SIPRAL_STATUS_WRONG_STATE`.
    ///
    /// Safety
    ///
    /// `out_stats` must point at a `sipral_stream_stats_t` whose `size` member
    /// says how long it is.
    /// </summary>
    public static SipralStreamStats MediaStatistics(ulong media, ulong nowMs)
    {
        var stats = SipralStreamStats.Sized();
        Check(NativeMethods.sipral_media_statistics(media, nowMs, ref stats));
        return stats;
    }

    /// <summary>
    /// Take a datagram off the media socket.
    ///
    /// RTP and RTCP are told apart by RFC 5761 §4, so either socket's traffic
    /// goes here.
    ///
    /// `data` is decrypted in place; keep a copy if the ciphertext is needed.
    /// `out_arrival` may be null. `now_ms` is the arrival time on the stack's
    /// clock and moves nothing.
    ///
    /// Safety
    ///
    /// `data` must be readable and writable for `len` bytes, `from` readable
    /// for `from_len`, and `out_arrival` must point at one `uint32_t` or be
    /// null.
    /// </summary>
    public static uint MediaReceive(ulong media, byte[] data, string from, ulong nowMs)
    {
        var fromBytes = Encoding.UTF8.GetBytes(from);
        var fromSigned = new sbyte[fromBytes.Length];
        Buffer.BlockCopy(fromBytes, 0, fromSigned, 0, fromBytes.Length);
        Check(NativeMethods.sipral_media_receive(media, data, (nuint)data.Length, fromSigned, (nuint)fromSigned.Length, nowMs, out var arrival));
        return arrival;
    }

    /// <summary>
    /// Take the frame that is due for the earpiece, and say where it came from.
    ///
    /// Exactly `sipral_media_info_t::frame_samples` samples are written, and a
    /// smaller buffer is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with the number
    /// needed in `out_written`. Every source fills the whole frame, silence
    /// included.
    ///
    /// Safety
    ///
    /// `samples` must be writable for `capacity` `int16_t`, `out_written` must
    /// point at one `size_t` or be null, and `out_source` at one `uint32_t` or
    /// be null.
    /// </summary>
    public static (nuint Written, uint Source) MediaPlayback(ulong media, short[] samples)
    {
        Check(NativeMethods.sipral_media_playback(media, samples, (nuint)samples.Length, out var written, out var source));
        return (written, source);
    }

    /// <summary>
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
    /// Safety
    ///
    /// `samples` must be readable for `sample_count` `int16_t`, and `packet`
    /// must point at a `sipral_media_packet_t` whose `size` member says how
    /// long it is and whose buffers are writable for the capacities beside
    /// them.
    /// </summary>
    public static void MediaCapture(ulong media, ulong nowMs, short[] samples, ref SipralMediaPacket packet)
    {
        Check(NativeMethods.sipral_media_capture(media, nowMs, samples, (nuint)samples.Length, ref packet));
    }

    /// <summary>
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
    /// Safety
    ///
    /// Reads no memory the caller owns.
    /// </summary>
    public static void MediaSetAppRate(ulong media, uint hz)
    {
        Check(NativeMethods.sipral_media_set_app_rate(media, hz));
    }

    /// <summary>
    /// Run `callback` over every captured frame, against the far-end audio
    /// played a render delay earlier: the seam for echo cancellation, gain
    /// control and noise suppression (`docs/05-media.md`).
    ///
    /// Replaces any previous processor and its learned state. Attaching
    /// mid-call costs a fresh adaptation.
    ///
    /// **`callback` runs with this call's media locked**, unlike the event
    /// callback: inside sipral_media_playback, inside
    /// sipral_media_capture, and with SipralProcessorFrame's `reset`
    /// set on a device or codec change, on the thread that called in. **From
    /// inside it, call nothing on any media handle or this call's stack**:
    /// such calls answer `SIPRAL_STATUS_BUSY`. This rules out two processors
    /// deadlocking across calls. It must not unwind.
    ///
    /// `user_data` is handed back untouched and must outlive the last call,
    /// which ends when `sipral_media_detach_processor` or
    /// `sipral_media_release` returns.
    ///
    /// Safety
    ///
    /// `callback` is called on whichever thread calls
    /// sipral_media_playback or sipral_media_capture on this call,
    /// for as long as the processor stays attached, and `user_data` has to
    /// outlive the last such call.
    /// </summary>
    public static void MediaAttachProcessor(ulong media, IntPtr callback, IntPtr userData)
    {
        Check(NativeMethods.sipral_media_attach_processor(media, callback, userData));
    }

    /// <summary>
    /// Stop running the processor sipral_media_attach_processor attached,
    /// if there was one.
    ///
    /// `out_was_attached`, when not null, gets 1 if one was detached, else 0.
    /// Once this returns, `callback` is not called again and `user_data` may
    /// be freed.
    ///
    /// Safety
    ///
    /// `out_was_attached` must point at one `uint32_t` or be null.
    /// </summary>
    public static uint MediaDetachProcessor(ulong media)
    {
        Check(NativeMethods.sipral_media_detach_processor(media, out var wasAttached));
        return wasAttached;
    }

    /// <summary>
    /// Forget the echo path, the noise floor and the gain the attached
    /// processor has learned, keeping the processor itself attached.
    ///
    /// For a device change. Calls the sipral_media_attach_processor
    /// callback with SipralProcessorFrame's `reset` set.
    ///
    /// `out_was_attached`, when not null, gets 1 if a processor exists, else 0.
    ///
    /// Safety
    ///
    /// `out_was_attached` must point at one `uint32_t` or be null.
    /// </summary>
    public static uint MediaResetProcessor(ulong media)
    {
        Check(NativeMethods.sipral_media_reset_processor(media, out var wasAttached));
        return wasAttached;
    }

    /// <summary>
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
    /// Safety
    ///
    /// `mic` must be readable for `mic_count` `int16_t` and `local` writable
    /// for `local_count` `int16_t`, the two must not overlap, and
    /// `packet_a` and `packet_b` must each point at a
    /// `sipral_media_packet_t` as `sipral_media_capture` describes.
    /// </summary>
    public static void MediaMix(ulong mediaA, ulong mediaB, ulong nowMs, short[] mic, short[] local, ref SipralMediaPacket packetA, ref SipralMediaPacket packetB)
    {
        Check(NativeMethods.sipral_media_mix(mediaA, mediaB, nowMs, mic, (nuint)mic.Length, local, (nuint)local.Length, ref packetA, ref packetB));
    }

    /// <summary>
    /// The control traffic this call has due.
    ///
    /// A `len` of zero means nothing is due. RFC 3550 §6.3 decides when; at
    /// most one report is due at a time.
    ///
    /// Call it after every outgoing frame, and at each `sipral_stack_poll`
    /// deadline while not capturing. Always zero without negotiated RTCP.
    /// `now_ms` moves nothing.
    ///
    /// Safety
    ///
    /// `packet` must point at a `sipral_media_packet_t` as
    /// sipral_media_capture describes.
    /// </summary>
    public static void MediaPollRtcp(ulong media, ulong nowMs, ref SipralMediaPacket packet)
    {
        Check(NativeMethods.sipral_media_poll_rtcp(media, nowMs, ref packet));
    }

    /// <summary>
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
    /// Safety
    ///
    /// `packet` must point at a `sipral_media_packet_t` as
    /// sipral_media_capture describes.
    /// </summary>
    public static void MediaPollTransmit(ulong media, ulong nowMs, ref SipralMediaPacket packet)
    {
        Check(NativeMethods.sipral_media_poll_transmit(media, nowMs, ref packet));
    }

    /// <summary>
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
    /// Safety
    ///
    /// `out_call` must point at one `sipral_handle_t`, and `packet` at a
    /// `sipral_media_packet_t` as sipral_media_capture describes.
    /// </summary>
    public static ulong StackPollFarewell(ulong stack, ref SipralMediaPacket packet)
    {
        Check(NativeMethods.sipral_stack_poll_farewell(stack, out var call, ref packet));
        return call;
    }

    /// <summary>
    /// Whether a digit is going out or waiting to, and how many have not
    /// started yet.
    ///
    /// Either out parameter may be null.
    ///
    /// Safety
    ///
    /// `out_dialling` must point at one `uint32_t` or be null, and
    /// `out_waiting` at one `size_t` or be null.
    /// </summary>
    public static (uint Dialling, nuint Waiting) MediaDialling(ulong media)
    {
        Check(NativeMethods.sipral_media_dialling(media, out var dialling, out var waiting));
        return (dialling, waiting);
    }

    /// <summary>
    /// Drop everything queued and stop the digit going out.
    ///
    /// The digit in flight gets no closing packet.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    /// </summary>
    public static void MediaStopDialling(ulong media)
    {
        Check(NativeMethods.sipral_media_stop_dialling(media));
    }

    /// <summary>
    /// Start recording this call to `path`: both directions mixed, as WAVE.
    /// Each start makes a new file.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when the media has ended or a recording is
    /// already running. `SIPRAL_STATUS_INVALID_ARGUMENT` when the file system
    /// refuses the path, with its reason in the last error. The file is created
    /// with this call's media held, so only this call's audio waits on it.
    ///
    /// Safety
    ///
    /// `path` must be readable for `path_len` bytes.
    /// </summary>
    public static void MediaRecordStart(ulong media, string path)
    {
        var pathBytes = Encoding.UTF8.GetBytes(path);
        var pathSigned = new sbyte[pathBytes.Length];
        Buffer.BlockCopy(pathBytes, 0, pathSigned, 0, pathBytes.Length);
        Check(NativeMethods.sipral_media_record_start(media, pathSigned, (nuint)pathSigned.Length));
    }

    /// <summary>
    /// Stop the recording and close the file.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when nothing is being recorded. On failure
    /// the file holds all the audio but zero header lengths.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    /// </summary>
    public static void MediaRecordStop(ulong media)
    {
        Check(NativeMethods.sipral_media_record_stop(media));
    }

    /// <summary>
    /// Whether a recording is running on this call, and how much audio it has
    /// taken (audio only, not the header). Either out parameter may be null.
    ///
    /// Safety
    ///
    /// `out_recording` must point at one `uint32_t` or be null, and
    /// `out_recorded_ms` at one `uint64_t` or be null.
    /// </summary>
    public static (uint Recording, ulong RecordedMs) MediaRecordState(ulong media)
    {
        Check(NativeMethods.sipral_media_record_state(media, out var recording, out var recordedMs));
        return (recording, recordedMs);
    }

    /// <summary>
    /// Take the next message the stack wants written.
    ///
    /// Loop until `len` is zero, after every `sipral_stack_poll` and every call that hands bytes
    /// in. A message longer than `capacity` is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with the needed
    /// length in `len` and is kept for the next call, ahead of the queue; a null `data` with
    /// capacity zero thus asks for the length.
    ///
    /// Safety
    ///
    /// `transmit` must point at a `sipral_transmit_t` whose `size` member says how long it is and
    /// whose buffers are writable for the capacities beside them.
    /// </summary>
    public static void StackPollTransmit(ulong stack, ref SipralTransmit transmit)
    {
        Check(NativeMethods.sipral_stack_poll_transmit(stack, ref transmit));
    }

    /// <summary>
    /// Hand over one datagram, whole, with its source.
    ///
    /// `from` is the far end as `host:port`. `to` is the receiving address, which the response
    /// leaves from (RFC 3581 §4); length zero means the stack's creation address. Frames from a
    /// WebSocket the application runs come here too (RFC 7118 §4.2).
    ///
    /// Non-SIP bytes are `SIPRAL_STATUS_INVALID_ARGUMENT` with the parse error as last error;
    /// only that packet is lost.
    ///
    /// Safety
    ///
    /// `data` must be readable for `len` bytes, `from` for `from_len`, and `to` for `to_len`.
    /// </summary>
    public static void StackReceiveDatagram(ulong stack, uint transport, byte[] data, string from, string to, ulong nowMs)
    {
        var fromBytes = Encoding.UTF8.GetBytes(from);
        var fromSigned = new sbyte[fromBytes.Length];
        Buffer.BlockCopy(fromBytes, 0, fromSigned, 0, fromBytes.Length);
        var toBytes = Encoding.UTF8.GetBytes(to);
        var toSigned = new sbyte[toBytes.Length];
        Buffer.BlockCopy(toBytes, 0, toSigned, 0, toBytes.Length);
        Check(NativeMethods.sipral_stack_receive_datagram(stack, transport, data, (nuint)data.Length, fromSigned, (nuint)fromSigned.Length, toSigned, (nuint)toSigned.Length, nowMs));
    }

    /// <summary>
    /// Hand over bytes read off a connection, in whatever sizes the reads came in.
    ///
    /// A fragment of the `Content-Length` framing (§18.3): may hold several messages or none. A
    /// stack-run WebSocket's handshake and frames come here too. Unreadable framing cannot be
    /// resynchronised: the transport is retired before `SIPRAL_STATUS_INVALID_ARGUMENT` returns;
    /// close the socket. A zero-byte read is sipral_stack_stream_closed, not this.
    ///
    /// Safety
    ///
    /// `data` must be readable for `len` bytes.
    /// </summary>
    public static void StackReceiveStream(ulong stack, uint transport, byte[] data, ulong nowMs)
    {
        Check(NativeMethods.sipral_stack_receive_stream(stack, transport, data, (nuint)data.Length, nowMs));
    }

    /// <summary>
    /// Say that a transport is open: the main one again, or a new one.
    ///
    /// The way back after sipral_stack_transport_failed and the way new transports enter the
    /// table. `transport` is SIPRAL_TRANSPORT_MAIN or any caller-chosen number; a known one
    /// is rebound, an unknown one opened. `out_transport_id`, if not null, receives the same
    /// number.
    ///
    /// `protocol` is a SipralTransport. On rebind, zero keeps the current
    /// protocol and anything different is `SIPRAL_STATUS_INVALID_ARGUMENT`: switching it under
    /// running RFC 3261 §17 timers is not allowed. Opening a new transport requires a protocol.
    ///
    /// `local` is the address the far end reaches, `host:port`. `remote` names a connection's far
    /// end, is refused on a datagram transport, and length zero omits it. On WS/WSS, `remote`
    /// makes the stack run the WebSocket: the handshake comes out of
    /// sipral_stack_poll_transmit and reads go to sipral_stack_receive_stream.
    ///
    /// After a
    /// SipralEventKind.TransportWanted,
    /// binding what it named and asking again sends the request on the new stream.
    ///
    /// Safety
    ///
    /// `local` must be readable for `local_len` bytes, `remote` for `remote_len`, and
    /// `out_transport_id`, when it is not null, must point at one `uint32_t`.
    /// </summary>
    public static uint StackTransportBind(ulong stack, uint transport, uint protocol, string local, string remote, ulong nowMs)
    {
        var localBytes = Encoding.UTF8.GetBytes(local);
        var localSigned = new sbyte[localBytes.Length];
        Buffer.BlockCopy(localBytes, 0, localSigned, 0, localBytes.Length);
        var remoteBytes = Encoding.UTF8.GetBytes(remote);
        var remoteSigned = new sbyte[remoteBytes.Length];
        Buffer.BlockCopy(remoteBytes, 0, remoteSigned, 0, remoteBytes.Length);
        Check(NativeMethods.sipral_stack_transport_bind(stack, transport, protocol, localSigned, (nuint)localSigned.Length, remoteSigned, (nuint)remoteSigned.Length, nowMs, out var transportId));
        return transportId;
    }

    /// <summary>
    /// Say that a transport failed and what was written to it did not arrive.
    ///
    /// The transport is retired: its transactions fail now, effects are reported on the next
    /// `sipral_stack_poll`, and nothing is sent until sipral_stack_transport_bind. Not for one
    /// refused `sendto`: retiring the socket over an ICMP unreachable drops healthy calls.
    ///
    /// Also answers a `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` the application could not honour:
    /// on the number it would have bound, waiting requests stop waiting (RFC 3261 §18.1.1:
    /// trimmed into a datagram if it fits, else ended with 513). A never-bound number is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` when nothing waits.
    ///
    /// The next poll raises `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` before the effects.
    /// sipral_stack_transport_failed_with adds the TLS reason.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    /// </summary>
    public static void StackTransportFailed(ulong stack, uint transport, uint error, ulong nowMs)
    {
        Check(NativeMethods.sipral_stack_transport_failed(stack, transport, error, nowMs));
    }

    /// <summary>
    /// Say that a transport failed, with the TLS library's reason.
    ///
    /// Does what sipral_stack_transport_failed does, and carries `failure-&gt;tls` and
    /// `failure-&gt;detail` to `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`. A connection that failed before
    /// any handshake belongs here too. A transport already down is not retired again but the
    /// event is still raised, so each failed reconnect is reported.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT`, retiring nothing, for a TLS reason on a non-TLS/WSS
    /// transport, or a detail over SIPRAL_TRANSPORT_DETAIL_BYTES or not UTF-8.
    ///
    /// Safety
    ///
    /// `failure` must point at a `sipral_transport_failure_t` whose `size` member says how long
    /// it is, and its `detail` must be readable for `detail_len` bytes.
    /// </summary>
    public static void StackTransportFailedWith(ulong stack, in SipralTransportFailure failure, ulong nowMs)
    {
        Check(NativeMethods.sipral_stack_transport_failed_with(stack, in failure, nowMs));
    }

    /// <summary>
    /// Say that a connection closed: the far end left, or a read returned zero.
    ///
    /// Retires like sipral_stack_transport_failed, but kept separate so an orderly close is
    /// distinguishable in logs. The event says `SIPRAL_TRANSPORT_ERROR_CLOSED`.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    /// </summary>
    public static void StackStreamClosed(ulong stack, uint transport, ulong nowMs)
    {
        Check(NativeMethods.sipral_stack_stream_closed(stack, transport, nowMs));
    }

    /// <summary>
    /// Replace the STUN server list without recreating the stack.
    ///
    /// `servers` is comma-separated `host:port` in order of preference. Every mapped socket is
    /// asked again at once and keeps its answer until the new server replies; servers kept from
    /// the old list keep their back-off. On a `SIPRAL_NAT_OFF` stack the main transport starts
    /// being mapped; further datagram transports join at their next `sipral_stack_transport_bind`.
    ///
    /// An empty list stops asking: `Contact`s move back to socket addresses and re-register, and
    /// named media sockets are forgotten. `SIPRAL_STATUS_INVALID_ARGUMENT` for that with a TURN
    /// server configured, or for a bad entry. `SIPRAL_STATUS_NOT_SUPPORTED` for a list without
    /// `SIPRAL_FEATURE_STUN`.
    ///
    /// Safety
    ///
    /// `servers` must be readable for `servers_len` bytes.
    /// </summary>
    public static void StackStunServers(ulong stack, string servers, ulong nowMs)
    {
        var serversBytes = Encoding.UTF8.GetBytes(servers);
        var serversSigned = new sbyte[serversBytes.Length];
        Buffer.BlockCopy(serversBytes, 0, serversSigned, 0, serversBytes.Length);
        Check(NativeMethods.sipral_stack_stun_servers(stack, serversSigned, (nuint)serversSigned.Length, nowMs));
    }

    /// <summary>
    /// Ask where a media socket appears from, before a call is described on it.
    ///
    /// `local` is the bound `host:port`, the same text as the call's `media_address`. The request
    /// waits in sipral_stack_poll_stun; hand the answer to sipral_stack_receive_stun.
    /// `SIPRAL_EVENT_KIND_NAT_MAPPING` reports within 5.5 seconds. A call on that
    /// `media_address` is then described by the public address and asks for `a=rtcp-mux`.
    /// Placing one before the answer is `SIPRAL_STATUS_WRONG_STATE`.
    ///
    /// Until the call, the socket is asked again every twenty-five seconds to keep the NAT
    /// binding alive; keep draining the queue. At most one request per socket waits there. The
    /// call spends the mapping: name the socket again for a second call.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` without `SIPRAL_NAT_STUN`; `SIPRAL_STATUS_INVALID_ARGUMENT`
    /// for one of the stack's own signalling sockets.
    ///
    /// Safety
    ///
    /// `local` must be readable for `local_len` bytes.
    /// </summary>
    public static void StackNatMap(ulong stack, string local, ulong nowMs)
    {
        var localBytes = Encoding.UTF8.GetBytes(local);
        var localSigned = new sbyte[localBytes.Length];
        Buffer.BlockCopy(localBytes, 0, localSigned, 0, localBytes.Length);
        Check(NativeMethods.sipral_stack_nat_map(stack, localSigned, (nuint)localSigned.Length, nowMs));
    }

    /// <summary>
    /// Say that a media socket sipral_stack_nat_map named will carry no call, and release it.
    ///
    /// Its refreshes stop and a waiting request is dropped. A TURN relay is released with a
    /// Refresh of lifetime zero (RFC 8656 §8), waiting in sipral_stack_poll_stun. If its
    /// Allocate is still unanswered, a late answer is accepted through
    /// sipral_stack_receive_stun for up to forty seconds and released the same way. Without
    /// this call the server holds the allocation until its lifetime expires, up to ten minutes
    /// after `sipral_stack_destroy`.
    ///
    /// Use it for a closed socket, a call not placed, and every named socket before destroy. A
    /// socket already used by a call, or never named, is a no-op.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` without `SIPRAL_NAT_STUN`; `SIPRAL_STATUS_INVALID_ARGUMENT`
    /// for one of the stack's own signalling sockets.
    ///
    /// Safety
    ///
    /// `local` must be readable for `local_len` bytes.
    /// </summary>
    public static void StackNatUnmap(ulong stack, string local, ulong nowMs)
    {
        var localBytes = Encoding.UTF8.GetBytes(local);
        var localSigned = new sbyte[localBytes.Length];
        Buffer.BlockCopy(localBytes, 0, localSigned, 0, localBytes.Length);
        Check(NativeMethods.sipral_stack_nat_unmap(stack, localSigned, (nuint)localSigned.Length, nowMs));
    }

    /// <summary>
    /// Take the next STUN request a media socket has to send.
    ///
    /// Same record and rules as `sipral_stack_poll_transmit`, on its own queue: loop until `len`
    /// is zero after every sipral_stack_nat_map, sipral_stack_receive_stun and
    /// `sipral_stack_poll`. Send from `source` exactly: the server reports the address it sees.
    /// `transport` is zero. `protocol` is UDP for a datagram, or TCP/TLS for bytes to write on
    /// the TURN connection from `source`.
    ///
    /// A call on a relayed socket also sends here until it has a media handle: Binding
    /// indications keeping the NAT open and the allocation refresh. After that they leave via
    /// `sipral_media_poll_transmit`.
    ///
    /// Safety
    ///
    /// `transmit` must point at a `sipral_transmit_t` whose `size` member says how long it is
    /// and whose buffers are writable for the capacities beside them.
    /// </summary>
    public static void StackPollStun(ulong stack, ref SipralTransmit transmit)
    {
        Check(NativeMethods.sipral_stack_poll_stun(stack, ref transmit));
    }

    /// <summary>
    /// Hand over a datagram that arrived on a media socket sipral_stack_nat_map named,
    /// before a call has media on it.
    ///
    /// Everything arriving on the socket comes here until the call's media handle exists:
    /// - TURN answers to what the call's relay sent (an unanswered refresh loses the relay);
    /// - the far end's early ICE checks: those signed with this call's password are kept, the
    ///   newest sixteen, and answered when the session opens (RFC 8445 §7.3), unless older than
    ///   39.5 seconds or the call ended;
    /// - between `SIPRAL_EVENT_KIND_MEDIA_STARTED` and `sipral_call_media`, anything, as through
    ///   `sipral_media_receive`.
    ///
    /// A socket shared by forked branches (`keep_all_forks`) keeps coming here; each datagram goes
    /// to the branch matching its ICE fragment, transaction or source (RFC 8839 §7.3). A stack
    /// without STUN accepts only that and returns `SIPRAL_STATUS_WRONG_STATE` otherwise.
    ///
    /// `to` is the receiving socket as named, `from` the sender. `SIPRAL_STATUS_OK` when taken;
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for anything else, dropping only that datagram. Only
    /// answers from the server's own address to this stack's own requests are believed: that is
    /// the defence against a forged mapping.
    ///
    /// Safety
    ///
    /// `data` must be readable for `len` bytes, `from` for `from_len`, and `to` for `to_len`.
    /// </summary>
    public static void StackReceiveStun(ulong stack, byte[] data, string from, string to, ulong nowMs)
    {
        var fromBytes = Encoding.UTF8.GetBytes(from);
        var fromSigned = new sbyte[fromBytes.Length];
        Buffer.BlockCopy(fromBytes, 0, fromSigned, 0, fromBytes.Length);
        var toBytes = Encoding.UTF8.GetBytes(to);
        var toSigned = new sbyte[toBytes.Length];
        Buffer.BlockCopy(toBytes, 0, toSigned, 0, toBytes.Length);
        Check(NativeMethods.sipral_stack_receive_stun(stack, data, (nuint)data.Length, fromSigned, (nuint)fromSigned.Length, toSigned, (nuint)toSigned.Length, nowMs));
    }

    /// <summary>
    /// Say that the connection a `SIPRAL_TURN_STREAM_OPEN` asked for is open (for TLS, with the
    /// handshake done and the certificate checked by the platform).
    ///
    /// The socket's Allocate then waits in sipral_stack_poll_stun marked with `protocol`;
    /// the answer comes back through sipral_stack_turn_receive.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for a socket with no requested connection,
    /// `SIPRAL_STATUS_WRONG_STATE` without `SIPRAL_NAT_STUN`.
    ///
    /// Safety
    ///
    /// `local` must be readable for `local_len` bytes.
    /// </summary>
    public static void StackTurnConnected(ulong stack, string local, ulong nowMs)
    {
        var localBytes = Encoding.UTF8.GetBytes(local);
        var localSigned = new sbyte[localBytes.Length];
        Buffer.BlockCopy(localBytes, 0, localSigned, 0, localBytes.Length);
        Check(NativeMethods.sipral_stack_turn_connected(stack, localSigned, (nuint)localSigned.Length, nowMs));
    }

    /// <summary>
    /// Hand over bytes read from a media socket's TURN connection, in any chunking.
    ///
    /// Messages are reassembled (RFC 8656 §12.5) and routed like a datagram from the server: to
    /// the socket's relay, or to the call holding it (agent or media, audio included). Read the
    /// connection for as long as it is open; replies leave through `sipral_media_poll_transmit`.
    ///
    /// `SIPRAL_STATUS_STREAM_BROKEN` when the bytes are not TURN framing: close the connection.
    /// The relay is lost with it and no `SIPRAL_TURN_STREAM_CLOSE` follows.
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for a socket with no open connection.
    ///
    /// Safety
    ///
    /// `local` must be readable for `local_len` bytes, and `data` for `len`.
    /// </summary>
    public static void StackTurnReceive(ulong stack, string local, byte[] data, ulong nowMs)
    {
        var localBytes = Encoding.UTF8.GetBytes(local);
        var localSigned = new sbyte[localBytes.Length];
        Buffer.BlockCopy(localBytes, 0, localSigned, 0, localBytes.Length);
        Check(NativeMethods.sipral_stack_turn_receive(stack, localSigned, (nuint)localSigned.Length, data, (nuint)data.Length, nowMs));
    }

    /// <summary>
    /// Say that a media socket's TURN connection closed, or could not be opened.
    ///
    /// The allocation was tied to the connection (RFC 8656 §3.2), so the relay is gone: one in
    /// progress becomes `SIPRAL_NAT_RELAY_FAILED`; a call using it loses that path when consent
    /// expires (RFC 7675). Name the socket again to get a new connection. `SIPRAL_STATUS_OK` for
    /// a connection already released.
    ///
    /// Safety
    ///
    /// `local` must be readable for `local_len` bytes.
    /// </summary>
    public static void StackTurnClosed(ulong stack, string local, ulong nowMs)
    {
        var localBytes = Encoding.UTF8.GetBytes(local);
        var localSigned = new sbyte[localBytes.Length];
        Buffer.BlockCopy(localBytes, 0, localSigned, 0, localBytes.Length);
        Check(NativeMethods.sipral_stack_turn_closed(stack, localSigned, (nuint)localSigned.Length, nowMs));
    }

    /// <summary>
    /// The short name of an event kind, as a static NUL-terminated
    /// string, or null for a number this build has no kind for
    /// (reserved numbers included).
    ///
    /// The string belongs to the library and lives as long as it is
    /// loaded.
    ///
    /// Safety
    ///
    /// Reads no caller memory; safe from any thread.
    /// </summary>
    public static string? EventKindName(uint kind) =>
        Marshal.PtrToStringUTF8(NativeMethods.sipral_event_kind_name(kind));

    /// <summary>
    /// How many lines a header field is on, in a whole SIP message.
    ///
    /// The name is case-insensitive and a compact form equals its long form
    /// (RFC 3261 §7.3.3). An absent field counts zero, not a failure.
    ///
    /// Safety
    ///
    /// `message` must be readable for `message_len` bytes and `name` for
    /// `name_len`, and `out_count` must point at one `size_t`.
    /// </summary>
    public static nuint MessageHeaderCount(byte[] message, string name)
    {
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var nameSigned = new sbyte[nameBytes.Length];
        Buffer.BlockCopy(nameBytes, 0, nameSigned, 0, nameBytes.Length);
        Check(NativeMethods.sipral_message_header_count(message, (nuint)message.Length, nameSigned, (nuint)nameSigned.Length, out var count));
        return count;
    }

    /// <summary>
    /// Where one line of a header field is, in a whole SIP message.
    ///
    /// `index` is in arrival order, below `sipral_message_header_count`, else
    /// `SIPRAL_STATUS_INVALID_ARGUMENT`. `out_offset` and `out_len` locate the
    /// value inside `message`, trimmed, line folds kept. For single list values
    /// use `sipral_message_header_element`.
    ///
    /// Safety
    ///
    /// As `sipral_message_header_count`, with `out_offset` and `out_len` each
    /// pointing at one `size_t`.
    /// </summary>
    public static (nuint Offset, nuint Len) MessageHeader(byte[] message, string name, nuint index)
    {
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var nameSigned = new sbyte[nameBytes.Length];
        Buffer.BlockCopy(nameBytes, 0, nameSigned, 0, nameBytes.Length);
        Check(NativeMethods.sipral_message_header(message, (nuint)message.Length, nameSigned, (nuint)nameSigned.Length, index, out var offset, out var len));
        return (offset, len);
    }

    /// <summary>
    /// How many values a field whose value is a comma-separated list holds,
    /// across every line it is on.
    ///
    /// Per RFC 3261 §7.3.1 one line with commas equals several lines, so this
    /// splits at commas outside quotes and angle brackets. Only for list
    /// fields (`Diversion`, `Contact`...); a `Date` would split wrongly.
    ///
    /// Safety
    ///
    /// As `sipral_message_header_count`.
    /// </summary>
    public static nuint MessageHeaderElementCount(byte[] message, string name)
    {
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var nameSigned = new sbyte[nameBytes.Length];
        Buffer.BlockCopy(nameBytes, 0, nameSigned, 0, nameBytes.Length);
        Check(NativeMethods.sipral_message_header_element_count(message, (nuint)message.Length, nameSigned, (nuint)nameSigned.Length, out var count));
        return count;
    }

    /// <summary>
    /// Where one value of a list field is, across every line the field is on.
    ///
    /// `index` is below `sipral_message_header_element_count`. Otherwise as
    /// `sipral_message_header`.
    ///
    /// Safety
    ///
    /// As `sipral_message_header`.
    /// </summary>
    public static (nuint Offset, nuint Len) MessageHeaderElement(byte[] message, string name, nuint index)
    {
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var nameSigned = new sbyte[nameBytes.Length];
        Buffer.BlockCopy(nameBytes, 0, nameSigned, 0, nameBytes.Length);
        Check(NativeMethods.sipral_message_header_element(message, (nuint)message.Length, nameSigned, (nuint)nameSigned.Length, index, out var offset, out var len));
        return (offset, len);
    }

    /// <summary>
    /// The operating system says this process stops shortly.
    ///
    /// Synchronous, bounded by accounts and subscriptions, infallible. Nothing
    /// is sent (`docs/16-lifecycle.md` says why de-registering here is wrong)
    /// and nothing stays scheduled. Calls are left as they are. `out_report`
    /// receives the counts.
    ///
    /// Safety
    ///
    /// `out_report` must point at a `sipral_suspending_t` whose `size` member
    /// says how long it is.
    /// </summary>
    public static SipralSuspending StackSuspending(ulong stack, ulong nowMs)
    {
        var report = SipralSuspending.Sized();
        Check(NativeMethods.sipral_stack_suspending(stack, nowMs, ref report));
        return report;
    }

    /// <summary>
    /// The process is awake again.
    ///
    /// An unmeasurable time passed and any transport may be dead. Beliefs are
    /// dropped and proved again, on the existing transport first (most wakes
    /// are short); sipral_account_rebind supplies a new one when asked.
    /// Safe without a matching sipral_stack_suspending: some platforms
    /// only notify on the way back.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    /// </summary>
    public static void StackResumed(ulong stack, ulong nowMs)
    {
        Check(NativeMethods.sipral_stack_resumed(stack, nowMs));
    }

    /// <summary>
    /// The network changed; before and after are described.
    ///
    /// `*_link` is a SipralLink. `*_address` is the local address the
    /// transports are bound to, an IP literal without port; a change
    /// invalidates every transport and binding. `*_interface` is the
    /// platform's interface id, only compared, since two networks can hand out
    /// the same address. `*_resolves` says whether names resolve there, the
    /// one failure that looks healthy. Address and interface may be null with
    /// zero length.
    ///
    /// `out_recovery`, which may be null, receives a SipralRecovery.
    /// Cheap enough to call on every notification: usually the answer is
    /// `SIPRAL_RECOVERY_NOTHING` and nothing happens.
    ///
    /// Safety
    ///
    /// Every address and interface pointer must be readable for the length
    /// beside it or null with a length of zero, and `out_recovery` must point
    /// at one `uint32_t` or be null.
    /// </summary>
    public static uint StackNetworkChanged(ulong stack, uint fromLink, string fromAddress, string fromInterface, uint fromResolves, uint toLink, string toAddress, string toInterface, uint toResolves, ulong nowMs)
    {
        var fromAddressBytes = Encoding.UTF8.GetBytes(fromAddress);
        var fromAddressSigned = new sbyte[fromAddressBytes.Length];
        Buffer.BlockCopy(fromAddressBytes, 0, fromAddressSigned, 0, fromAddressBytes.Length);
        var fromInterfaceBytes = Encoding.UTF8.GetBytes(fromInterface);
        var fromInterfaceSigned = new sbyte[fromInterfaceBytes.Length];
        Buffer.BlockCopy(fromInterfaceBytes, 0, fromInterfaceSigned, 0, fromInterfaceBytes.Length);
        var toAddressBytes = Encoding.UTF8.GetBytes(toAddress);
        var toAddressSigned = new sbyte[toAddressBytes.Length];
        Buffer.BlockCopy(toAddressBytes, 0, toAddressSigned, 0, toAddressBytes.Length);
        var toInterfaceBytes = Encoding.UTF8.GetBytes(toInterface);
        var toInterfaceSigned = new sbyte[toInterfaceBytes.Length];
        Buffer.BlockCopy(toInterfaceBytes, 0, toInterfaceSigned, 0, toInterfaceBytes.Length);
        Check(NativeMethods.sipral_stack_network_changed(stack, fromLink, fromAddressSigned, (nuint)fromAddressSigned.Length, fromInterfaceSigned, (nuint)fromInterfaceSigned.Length, fromResolves, toLink, toAddressSigned, (nuint)toAddressSigned.Length, toInterfaceSigned, (nuint)toInterfaceSigned.Length, toResolves, nowMs, out var recovery));
        return recovery;
    }

    /// <summary>
    /// There is no usable interface. Nothing is tried or scheduled until
    /// sipral_stack_network_changed reports one back; the opposite of
    /// sipral_stack_name_resolution_lost.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    /// </summary>
    public static void StackInterfaceLost(ulong stack, ulong nowMs)
    {
        Check(NativeMethods.sipral_stack_interface_lost(stack, nowMs));
    }

    /// <summary>
    /// Names no longer become addresses.
    ///
    /// Everything looks healthy while every address learned from a name may
    /// be wrong. Bindings whose registrar is a name stop being trusted; ones
    /// aimed at a literal address keep running.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    /// </summary>
    public static void StackNameResolutionLost(ulong stack, ulong nowMs)
    {
        Check(NativeMethods.sipral_stack_name_resolution_lost(stack, nowMs));
    }

    /// <summary>
    /// Point an account at a transport and an address again.
    ///
    /// `remote` is where its requests go, `host:port`. `contact` is required:
    /// after an address change the old one is unreachable, and keeping it
    /// would register a binding that receives nothing.
    ///
    /// `transport` must already exist:
    /// SIPRAL_TRANSPORT_MAIN or
    /// one sipral_stack_transport_bind
    /// bound; anything else is `SIPRAL_STATUS_INVALID_ARGUMENT`. This does not
    /// open one.
    ///
    /// When recovery is waiting for it, the next rung runs at once instead of
    /// waiting out the back-off. Otherwise the account is still repointed and
    /// the next REGISTER uses it.
    ///
    /// Safety
    ///
    /// `remote` must be readable for `remote_len` bytes and `contact` for
    /// `contact_len` bytes.
    /// </summary>
    public static void AccountRebind(ulong stack, ulong account, uint transport, string remote, string contact, ulong nowMs)
    {
        var remoteBytes = Encoding.UTF8.GetBytes(remote);
        var remoteSigned = new sbyte[remoteBytes.Length];
        Buffer.BlockCopy(remoteBytes, 0, remoteSigned, 0, remoteBytes.Length);
        var contactBytes = Encoding.UTF8.GetBytes(contact);
        var contactSigned = new sbyte[contactBytes.Length];
        Buffer.BlockCopy(contactBytes, 0, contactSigned, 0, contactBytes.Length);
        Check(NativeMethods.sipral_account_rebind(stack, account, transport, remoteSigned, (nuint)remoteSigned.Length, contactSigned, (nuint)contactSigned.Length, nowMs));
    }

    /// <summary>
    /// Mark the process start, the zero of sipral_account_time_to_ready.
    ///
    /// Only the application knows the moment its users wait from. Each call
    /// clears and restarts every account's measurement.
    /// Safety
    ///
    /// Safe to call with any handle value.
    /// </summary>
    public static void StackColdStart(ulong stack, ulong nowMs)
    {
        Check(NativeMethods.sipral_stack_cold_start(stack, nowMs));
    }

    /// <summary>
    /// Write an account's registration down, so a later start can carry it
    /// on without a full handshake.
    ///
    /// `out_len` always receives the size; a null `buffer` with `capacity`
    /// zero asks for it and gets `SIPRAL_STATUS_BUFFER_TOO_SMALL`. Nothing is
    /// written to a short buffer.
    ///
    /// **The bytes are opaque; parsing them is not part of this ABI.** They are
    /// versioned and a build reads only its known layouts. Storing and
    /// protecting them is the application's: they name an address of record.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when there is nothing to keep: never
    /// registered, never will, failed, or given up. The clock is read, not
    /// moved, so a snapshot on the way into suspend cannot reject a later
    /// `now_ms`.
    /// Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// `capacity` of zero, and `out_len` must point at one `size_t` or be
    /// null.
    /// </summary>
    public static nuint AccountFreeze(ulong stack, ulong account, byte[] buffer, ulong nowMs)
    {
        Check(NativeMethods.sipral_account_freeze(stack, account, buffer, (nuint)buffer.Length, out var len, nowMs));
        return len;
    }

    /// <summary>
    /// Read one back, on an account that was added and has not registered.
    ///
    /// `asleep_ms` is how long the snapshot sat unused: only the application
    /// knows, since no wall clock is read here and instants die with the
    /// process. The binding keeps what it had left, less that.
    ///
    /// The account comes up
    /// SIPRAL_REGISTRATION_STATE_RESTORED,
    /// not registered, until the refresh this books confirms it.
    ///
    /// Refused with the account unchanged: `SIPRAL_STATUS_UNSUPPORTED_VERSION`
    /// for bytes a newer build wrote, `SIPRAL_STATUS_NOT_SUPPORTED` for an
    /// account that does not register, `SIPRAL_STATUS_INVALID_ARGUMENT` for
    /// bytes that are not a snapshot, are damaged, or belong to another
    /// address of record (which would register somebody else).
    ///
    /// Safety
    ///
    /// `snapshot` must be readable for `snapshot_len` bytes.
    /// </summary>
    public static void AccountThaw(ulong stack, ulong account, byte[] snapshot, ulong asleepMs, ulong nowMs)
    {
        Check(NativeMethods.sipral_account_thaw(stack, account, snapshot, (nuint)snapshot.Length, asleepMs, nowMs));
    }

    /// <summary>
    /// How long this account took to become reachable, from
    /// sipral_stack_cold_start. A queue's ring timeout must exceed it, or
    /// a waking phone is always skipped.
    ///
    /// `out_has_value` and `out_ms` are zero until there is an answer: before
    /// registration, for an account that never registers, or with no cold
    /// start declared. Zero with `out_has_value` set is a real answer.
    ///
    /// Safety
    ///
    /// `out_has_value` must point at one `uint32_t` and `out_ms` at one
    /// `uint64_t`.
    /// </summary>
    public static (uint HasValue, ulong Ms) AccountTimeToReady(ulong stack, ulong account)
    {
        Check(NativeMethods.sipral_account_time_to_ready(stack, account, out var hasValue, out var ms));
        return (hasValue, ms);
    }

    /// <summary>
    /// Say where a dialog's next hop actually is.
    ///
    /// The answer to
    /// SIPRAL_EVENT_KIND_RESOLVE_NEEDED,
    /// with `dialog` the handle that event carried. `addresses` is
    /// comma-separated `host:port` in RFC 3263 §4.3 priority order: the first
    /// one with an open transport of the wanted protocol is taken, the rest
    /// are kept for failover.
    ///
    /// `protocol` is a SipralTransport when the lookup named one (NAPTR,
    /// SRV), or zero to keep the flow's protocol. It is never opened: an
    /// address on an unbound protocol is passed over; answer again after
    /// sipral_stack_transport_bind.
    ///
    /// `SIPRAL_STATUS_OK` with nothing changed when no address is reachable.
    /// `SIPRAL_STATUS_STALE_HANDLE` for a dialog that has ended. No `now_ms`:
    /// nothing here is timed.
    ///
    /// Safety
    ///
    /// `addresses` must be readable for `addresses_len` bytes.
    /// </summary>
    public static void StackResolved(ulong stack, ulong dialog, string addresses, uint protocol)
    {
        var addressesBytes = Encoding.UTF8.GetBytes(addresses);
        var addressesSigned = new sbyte[addressesBytes.Length];
        Buffer.BlockCopy(addressesBytes, 0, addressesSigned, 0, addressesBytes.Length);
        Check(NativeMethods.sipral_stack_resolved(stack, dialog, addressesSigned, (nuint)addressesSigned.Length, protocol));
    }

    /// <summary>
    /// Point an account's registration at another address.
    ///
    /// For a registrar with several targets. The binding's `Call-ID`,
    /// sequence and credentials are kept, so the registrar sees the same
    /// device continuing. A REGISTER in flight or booked is superseded at
    /// once; retargeting to the current address is `SIPRAL_STATUS_OK` and
    /// sends nothing.
    ///
    /// `registrar_address` is `host:port`, not a name.
    /// `SIPRAL_STATUS_NOT_SUPPORTED` for an account with no registrar.
    ///
    /// Safety
    ///
    /// `registrar_address` must be readable for `registrar_address_len`
    /// bytes.
    /// </summary>
    public static void AccountRetarget(ulong stack, ulong account, string registrarAddress, ulong nowMs)
    {
        var registrarAddressBytes = Encoding.UTF8.GetBytes(registrarAddress);
        var registrarAddressSigned = new sbyte[registrarAddressBytes.Length];
        Buffer.BlockCopy(registrarAddressBytes, 0, registrarAddressSigned, 0, registrarAddressBytes.Length);
        Check(NativeMethods.sipral_account_retarget(stack, account, registrarAddressSigned, (nuint)registrarAddressSigned.Length, nowMs));
    }

    /// <summary>
    /// Copy one call's diagnostic record into `buffer`, as the JSON
    /// `docs/14-diagnostics.md` describes.
    ///
    /// Readable during the call and after it, until the record is evicted
    /// (`sipral_stack_config_t::diagnostic_records` are kept, 32 when zero).
    /// An evicted or still empty record answers `SIPRAL_STATUS_OK` with `{}`.
    ///
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
    /// document, with the length needed in `out_needed`.
    ///
    /// Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// capacity of zero, and `out_needed` must point at one `size_t` or be null.
    /// </summary>
    public static nuint CallRecordJson(ulong stack, ulong call, sbyte[] buffer)
    {
        Check(NativeMethods.sipral_call_record_json(stack, call, buffer, (nuint)buffer.Length, out var needed));
        return needed;
    }

    /// <summary>
    /// Copy the whole diagnostic document into `buffer`: what a bug report
    /// carries, as the JSON `docs/14-diagnostics.md` describes.
    ///
    /// The endpoint's own record (decisions outside any call), then one record
    /// per call still held, and the count of evicted records.
    ///
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
    /// document, with the length needed in `out_needed`.
    ///
    /// Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// capacity of zero, and `out_needed` must point at one `size_t` or be null.
    /// </summary>
    public static nuint StackDiagnosticsJson(ulong stack, sbyte[] buffer)
    {
        Check(NativeMethods.sipral_stack_diagnostics_json(stack, buffer, (nuint)buffer.Length, out var needed));
        return needed;
    }

    /// <summary>
    /// What a `conference` subscription holds about the conference as a
    /// whole (RFC 4575 §5.5). `SIPRAL_STATUS_NOT_SUPPORTED` when it holds
    /// none: another package, no document yet, or not live.
    ///
    /// Safety
    ///
    /// `out_conference` must point at a `sipral_conference_t` whose `size`
    /// member says how long it is.
    /// </summary>
    public static SipralConference SubscriptionConference(ulong stack, ulong subscription)
    {
        var conference = SipralConference.Sized();
        Check(NativeMethods.sipral_subscription_conference(stack, subscription, ref conference));
        return conference;
    }

    /// <summary>
    /// One user of the conference, by index, in the order the focus first
    /// named them. The index is stable only until the next
    /// `SIPRAL_EVENT_KIND_CONFERENCE_CHANGED`.
    ///
    /// Safety
    ///
    /// `out_user` must point at a `sipral_conference_user_t` whose `size`
    /// member says how long it is.
    /// </summary>
    public static SipralConferenceUser SubscriptionConferenceUserAt(ulong stack, ulong subscription, nuint index)
    {
        var user = SipralConferenceUser.Sized();
        Check(NativeMethods.sipral_subscription_conference_user_at(stack, subscription, index, ref user));
        return user;
    }

    /// <summary>
    /// Text about the conference or a user, as `which` (a
    /// SipralConferenceText) and `index` say. `out_needed` gets the bytes
    /// needed including the NUL; a small buffer is
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL` with nothing written; absent text is
    /// just the NUL.
    ///
    /// Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// capacity of zero, and `out_needed` must point at one `size_t` or be
    /// null.
    /// </summary>
    public static nuint SubscriptionConferenceText(ulong stack, ulong subscription, nuint index, uint which, sbyte[] buffer)
    {
        Check(NativeMethods.sipral_subscription_conference_text(stack, subscription, index, which, buffer, (nuint)buffer.Length, out var needed));
        return needed;
    }

    /// <summary>
    /// Put (`focus` 1) or remove (0) `isfocus` on this call's `Contact` from
    /// the next message on (RFC 4579 §4.2): the answer, or the next re-INVITE
    /// or UPDATE on an established call.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    /// </summary>
    public static void CallSetFocus(ulong stack, ulong call, uint focus)
    {
        Check(NativeMethods.sipral_call_set_focus(stack, call, focus));
    }

    /// <summary>
    /// The conference URI when the far end's `Contact` has `isfocus` (RFC 4579
    /// §4.2), copied as `sipral_subscription_conference_text` copies.
    /// `SIPRAL_STATUS_NOT_A_FOCUS` otherwise.
    ///
    /// Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// capacity of zero, and `out_needed` must point at one `size_t` or be
    /// null.
    /// </summary>
    public static nuint CallConferenceUri(ulong stack, ulong call, sbyte[] buffer)
    {
        Check(NativeMethods.sipral_call_conference_uri(stack, call, buffer, (nuint)buffer.Length, out var needed));
        return needed;
    }

    /// <summary>
    /// Subscribe to the conference package of the call's focus (RFC 4579
    /// §3.4), outside the call's dialog, from the call's account. The
    /// subscription outlives the call. `SIPRAL_STATUS_NOT_A_FOCUS` when the
    /// far end is not a focus.
    ///
    /// Safety
    ///
    /// `out_subscription` must point at one `sipral_handle_t`.
    /// </summary>
    public static ulong CallSubscribeConference(ulong stack, ulong call, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_subscribe_conference(stack, call, out var subscription, nowMs));
        return subscription;
    }

    /// <summary>
    /// Publish this account's presence (RFC 3903, RFC 3856 §6.2). Later calls
    /// modify the same publication; the stack refreshes it until
    /// sipral_account_unpublish_presence.
    ///
    /// The PUBLISH is only queued on return; the outcome arrives as
    /// `SIPRAL_EVENT_KIND_PRESENCE_CHANGED` with `SIPRAL_PRESENCE_KIND_PUBLICATION`.
    ///
    /// Safety
    ///
    /// `presence` must point at a `sipral_presence_t` whose `size` member
    /// says how long it is, with its pointer readable for the length beside
    /// it.
    /// </summary>
    public static void AccountPublishPresence(ulong stack, ulong account, in SipralPresence presence, ulong nowMs)
    {
        Check(NativeMethods.sipral_account_publish_presence(stack, account, in presence, nowMs));
    }

    /// <summary>
    /// Take this account's published presence away (RFC 3903 §4.5):
    /// `SIPRAL_PUBLICATION_STATE_REMOVED` says when it is gone.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for an account that has published none.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    /// </summary>
    public static void AccountUnpublishPresence(ulong stack, ulong account, ulong nowMs)
    {
        Check(NativeMethods.sipral_account_unpublish_presence(stack, account, nowMs));
    }

    /// <summary>
    /// Queue text the user typed for the far end, UTF-8.
    /// Sent every 300 ms within the far end's rate, with `red` redundancy
    /// when agreed. CR, LF or CR LF is a new line; U+0008 erases.
    ///
    /// `SIPRAL_STATUS_NOT_NEGOTIATED` without a text stream;
    /// `SIPRAL_STATUS_EXHAUSTED` when the queue is full (nothing queued).
    ///
    /// Safety
    ///
    /// `text` must be readable for `text_len` bytes.
    /// </summary>
    public static void MediaSendText(ulong media, string text)
    {
        var textBytes = Encoding.UTF8.GetBytes(text);
        var textSigned = new sbyte[textBytes.Length];
        Buffer.BlockCopy(textBytes, 0, textSigned, 0, textBytes.Length);
        Check(NativeMethods.sipral_media_send_text(media, textSigned, (nuint)textSigned.Length));
    }

    /// <summary>
    /// The next datagram due on the call's text socket.
    /// `len` zero means nothing due; poll again at the stack's deadline. Send
    /// from the `text_address` socket, not the audio one.
    ///
    /// Safety
    ///
    /// `packet` must point at a `sipral_media_packet_t` as
    /// `sipral_media_capture` describes.
    /// </summary>
    public static void MediaPollText(ulong media, ulong nowMs, ref SipralMediaPacket packet)
    {
        Check(NativeMethods.sipral_media_poll_text(media, nowMs, ref packet));
    }

    /// <summary>
    /// Take a datagram off the call's text socket.
    /// `out_taken` is 1 when it was this call's text, else 0 (not RTP, other
    /// payload type, not the latched source, or no text stream).
    ///
    /// Safety
    ///
    /// `data` must be readable for `len` bytes, `from` for `from_len`, and
    /// `out_taken` must point at one `uint32_t` or be null.
    /// </summary>
    public static uint MediaReceiveText(ulong media, byte[] data, string from, ulong nowMs)
    {
        var fromBytes = Encoding.UTF8.GetBytes(from);
        var fromSigned = new sbyte[fromBytes.Length];
        Buffer.BlockCopy(fromBytes, 0, fromSigned, 0, fromBytes.Length);
        Check(NativeMethods.sipral_media_receive_text(media, data, (nuint)data.Length, fromSigned, (nuint)fromSigned.Length, nowMs, out var taken));
        return taken;
    }

    /// <summary>
    /// Record a call to a recording server (RFC 7866), and write the
    /// recording session's handle to `out_recording`.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` before `SIPRAL_EVENT_KIND_MEDIA_STARTED`,
    /// for a call whose media this stack does not run, or one already
    /// recorded. Sent from the call's account; a stream transport when too
    /// large for UDP. Stopped by sipral_call_stop_recording_to,
    /// `sipral_call_hangup` on it, or the server hanging up.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_record_config_t` whose `size` member
    /// says how long it is, with every pointer in it readable for the length
    /// beside it, and `out_recording` at one `sipral_handle_t`.
    /// </summary>
    public static ulong CallRecordTo(ulong stack, ulong call, in SipralRecordConfig config, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_record_to(stack, call, in config, out var recording, nowMs));
        return recording;
    }

    /// <summary>
    /// Stop copies at once and hang up the recording session. `call` is the
    /// recorded call. `SIPRAL_STATUS_WRONG_STATE` when nothing records it.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallStopRecordingTo(ulong stack, ulong call, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_stop_recording_to(stack, call, nowMs));
    }

    /// <summary>
    /// The next copy of this call's audio for its recording server.
    /// `len` zero means none waiting. `out_far_end` is 0 to send from
    /// `this_end`, 1 from `far_end`. Drain every frame: copies older than a
    /// second are dropped, oldest first.
    ///
    /// Safety
    ///
    /// `packet` must point at a `sipral_media_packet_t` as
    /// `sipral_media_capture` describes, and `out_far_end` at one
    /// `uint32_t`.
    /// </summary>
    public static uint MediaPollRecording(ulong media, ref SipralMediaPacket packet)
    {
        Check(NativeMethods.sipral_media_poll_recording(media, ref packet, out var farEnd));
        return farEnd;
    }

    /// <summary>
    /// Start recording the signalling this stack is fed (`docs/18-replay.md`).
    /// Starting moves the stack onto a fresh seed derived one way from
    /// `entropy`; the recording carries that seed, never `entropy`, and
    /// stopping moves the stack on again. It records what arrives, never what
    /// this end sent.
    ///
    /// `note` is one line of prose for whoever opens the file later, or null
    /// for none.
    ///
    /// A running recording is replaced, not refused: nothing is written until
    /// `sipral_stack_recording_stop`.
    ///
    /// Safety
    ///
    /// `note` must be readable for `note_len` bytes or be null with a length
    /// of zero.
    /// </summary>
    public static void StackRecordingStart(ulong stack, string note)
    {
        var noteBytes = Encoding.UTF8.GetBytes(note);
        var noteSigned = new sbyte[noteBytes.Length];
        Buffer.BlockCopy(noteBytes, 0, noteSigned, 0, noteBytes.Length);
        Check(NativeMethods.sipral_stack_recording_start(stack, noteSigned, (nuint)noteSigned.Length));
    }

    /// <summary>
    /// Stop the recording sipral_stack_recording_start began, and copy
    /// the text of it into `buffer` (`docs/18-replay.md`).
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when no recording is running. Also
    /// `SIPRAL_STATUS_WRONG_STATE`, with the reason in the last error, when a
    /// message could not go in the text format (a non-text body); then nothing
    /// is produced, since a recording missing a message would replay differently.
    ///
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
    /// text, with the length needed in `out_needed`; asking again returns the
    /// same recording. Once copied out whole, the recording is gone from the stack.
    ///
    /// Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// capacity of zero, and `out_needed` must point at one `size_t` or be null.
    /// </summary>
    public static nuint StackRecordingStop(ulong stack, sbyte[] buffer)
    {
        Check(NativeMethods.sipral_stack_recording_stop(stack, buffer, (nuint)buffer.Length, out var needed));
        return needed;
    }

    /// <summary>
    /// Ask the platform for its devices and say how many the list holds.
    ///
    /// Known devices keep their ids; gone ones keep their rows, marked absent.
    /// For a settings screen, not polling: the engine refreshes on platform
    /// notices. `SIPRAL_STATUS_DEVICE_TIMED_OUT` past `audio_probe_ms`, with
    /// the list unchanged.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t` or be null.
    /// </summary>
    public static nuint AudioRefresh(ulong stack)
    {
        Check(NativeMethods.sipral_audio_refresh(stack, out var count));
        return count;
    }

    /// <summary>
    /// How many devices the list holds, present or not.
    ///
    /// The first read of a list asks the platform, so no refresh is needed.
    /// `SIPRAL_STATUS_DEVICE_TIMED_OUT` past `audio_probe_ms`; the next read
    /// asks again.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    /// </summary>
    public static nuint AudioDeviceCount(ulong stack)
    {
        Check(NativeMethods.sipral_audio_device_count(stack, out var count));
        return count;
    }

    /// <summary>
    /// The device at `index` in the list, and its name into `buffer`.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` past the end. The name is UTF-8 with a
    /// trailing NUL; `out_needed`, when not null, receives its length with the
    /// NUL. `SIPRAL_STATUS_BUFFER_TOO_SMALL` writes neither `buffer` nor
    /// `out_device`.
    ///
    /// Safety
    ///
    /// `out_device` must point at a `sipral_audio_device_t` whose `size`
    /// member says how long it is; `buffer` must be writable for `capacity`
    /// bytes or null with a capacity of zero; `out_needed` must point at one
    /// `size_t` or be null.
    /// </summary>
    public static (SipralAudioDevice Device, nuint Needed) AudioDeviceAt(ulong stack, nuint index, sbyte[] buffer)
    {
        var device = SipralAudioDevice.Sized();
        Check(NativeMethods.sipral_audio_device_at(stack, index, ref device, buffer, (nuint)buffer.Length, out var needed));
        return (device, needed);
    }

    /// <summary>
    /// Put a role on a device, or back on the system's route with a
    /// `device` of zero.
    ///
    /// Refused before any platform call, changing nothing:
    /// `SIPRAL_STATUS_NO_SUCH_DEVICE` for an unknown id,
    /// `SIPRAL_STATUS_DEVICE_UNUSABLE` for a device absent or without channels
    /// in the role's direction, `SIPRAL_STATUS_NOT_SUPPORTED` where the
    /// platform cannot separate the role (on macOS the microphone follows the
    /// system's input).
    ///
    /// While active the role reopens at once, keeping gain and mute, and
    /// `SIPRAL_AUDIO_CHANGE_SELECTED` follows. A chosen device that is
    /// unplugged stays the preference and is used again when it returns.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    /// </summary>
    public static void AudioSelect(ulong stack, uint role, uint device)
    {
        Check(NativeMethods.sipral_audio_select(stack, role, device));
    }

    /// <summary>
    /// What a role was asked to be on (zero: the system's route) and what it
    /// runs on (zero: not open). They differ while a chosen device is absent.
    ///
    /// Safety
    ///
    /// Each out parameter must point at one `uint32_t` or be null.
    /// </summary>
    public static (uint Selected, uint Running) AudioSelection(ulong stack, uint role)
    {
        Check(NativeMethods.sipral_audio_selection(stack, role, out var selected, out var running));
        return (selected, running);
    }

    /// <summary>
    /// Set the gain of one direction, fixed-point with 256 for unity, capped
    /// at 1024. Input is the microphone gain, output the volume. Applied to
    /// the frames, not the OS control, and kept across device changes.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    /// </summary>
    public static void AudioSetGain(ulong stack, uint direction, uint gain)
    {
        Check(NativeMethods.sipral_audio_set_gain(stack, direction, gain));
    }

    /// <summary>
    /// The gain of one direction, in the steps `sipral_audio_set_gain` takes.
    ///
    /// Safety
    ///
    /// `out_gain` must point at one `uint32_t`.
    /// </summary>
    public static uint AudioGain(ulong stack, uint direction)
    {
        Check(NativeMethods.sipral_audio_gain(stack, direction, out var gain));
        return gain;
    }

    /// <summary>
    /// Mute or unmute one direction, kept across device changes. A muted
    /// microphone sends silence, so the far end hears a stream, not a gap.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    /// </summary>
    public static void AudioSetMuted(ulong stack, uint direction, uint muted)
    {
        Check(NativeMethods.sipral_audio_set_muted(stack, direction, muted));
    }

    /// <summary>
    /// Whether one direction is muted: one or zero into `out_muted`.
    ///
    /// Safety
    ///
    /// `out_muted` must point at one `uint32_t`.
    /// </summary>
    public static uint AudioMuted(ulong stack, uint direction)
    {
        Check(NativeMethods.sipral_audio_muted(stack, direction, out var muted));
        return muted;
    }

    /// <summary>
    /// The meter of one direction: the peak sample of the last 100 ms, 0 to
    /// 32767, held one to two windows. Cheap to poll per frame; zero while
    /// nothing is open.
    ///
    /// Safety
    ///
    /// `out_peak` must point at one `uint32_t`.
    /// </summary>
    public static uint AudioLevel(ulong stack, uint direction)
    {
        Check(NativeMethods.sipral_audio_level(stack, direction, out var peak));
        return peak;
    }

    /// <summary>
    /// Open the devices and start the pump now. The only way under
    /// `SIPRAL_AUDIO_ACTIVATION_MANUAL`; early under automatic activation.
    /// `SIPRAL_STATUS_DEVICE_UNUSABLE` or `SIPRAL_STATUS_DEVICE_TIMED_OUT` for
    /// a direction that failed: the engine is still active, silent there.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    /// </summary>
    public static void AudioActivate(ulong stack)
    {
        Check(NativeMethods.sipral_audio_activate(stack));
    }

    /// <summary>
    /// Close the devices and stop the pump. The calls stay attached and get
    /// their audio back on the next activation.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    /// </summary>
    public static void AudioDeactivate(ulong stack)
    {
        Check(NativeMethods.sipral_audio_deactivate(stack));
    }

    /// <summary>
    /// Ring on the ringer's device (or the loudspeaker) until
    /// `sipral_audio_stop_ringing`, or once when `looped` is zero. Mono 16-bit
    /// samples at `sample_rate_hz`, copied before return. Under automatic
    /// activation a ring opens the devices.
    ///
    /// Safety
    ///
    /// `samples` must be readable for `sample_count` `int16_t`.
    /// </summary>
    public static void AudioRing(ulong stack, short[] samples, uint sampleRateHz, uint looped)
    {
        Check(NativeMethods.sipral_audio_ring(stack, samples, (nuint)samples.Length, sampleRateHz, looped));
    }

    /// <summary>
    /// Stop the ring. Under automatic activation, with no call up, the
    /// devices close with it.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    /// </summary>
    public static void AudioStopRinging(ulong stack)
    {
        Check(NativeMethods.sipral_audio_stop_ringing(stack));
    }

    /// <summary>
    /// What the engine is doing: whether it is active, whether the platform
    /// cancels echo, the delay a canceller needs, and where each role runs.
    ///
    /// Safety
    ///
    /// `out_info` must point at a `sipral_audio_info_t` whose `size` member
    /// says how long it is.
    /// </summary>
    public static SipralAudioInfo AudioInfo(ulong stack)
    {
        var info = SipralAudioInfo.Sized();
        Check(NativeMethods.sipral_audio_info(stack, ref info));
        return info;
    }

    /// <summary>
    /// Turn the platform's echo cancellation on or off on a running stack:
    /// `on` is a `SipralToggle`, and zero leaves it.
    ///
    /// Open devices are reopened at once with or without the platform
    /// processing, on the same devices with gain and mute, each reported as
    /// `SIPRAL_AUDIO_CHANGE_REOPENED`. A call hears a short gap; a refused
    /// direction is `SIPRAL_AUDIO_CHANGE_UNAVAILABLE`. Closed devices use it
    /// on the next open. `sipral_audio_info_t` says what the platform did.
    /// `SIPRAL_STATUS_WRONG_STATE` in application mode.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    /// </summary>
    public static void AudioSetSystemEchoCancellation(ulong stack, uint on)
    {
        Check(NativeMethods.sipral_audio_set_system_echo_cancellation(stack, on));
    }

    /// <summary>
    /// Send this stack's log to `callback`, at `level` and louder, or turn it
    /// off with `SIPRAL_LOG_LEVEL_OFF` or a null callback.
    ///
    /// Off by default and free when off. A second call replaces callback and
    /// level on this stack; queued lines go to the new callback. Turning off
    /// drops the queue. Details: `docs/17-observability.md`. A level above
    /// `SIPRAL_LOG_LEVEL_TRACE` is `SIPRAL_STATUS_INVALID_ARGUMENT`.
    ///
    /// Safety
    ///
    /// `callback`, when not null, is called inside later calls into this stack,
    /// after the stack is released (see SipralLogCallback). `user_data`
    /// must stay valid until the log is replaced or off and no thread is
    /// inside this stack.
    /// </summary>
    public static void StackLog(ulong stack, uint level, IntPtr callback, IntPtr userData)
    {
        Check(NativeMethods.sipral_stack_log(stack, level, callback, userData));
    }

    /// <summary>
    /// Copy a redacted snapshot of this stack into `buffer` for a crash
    /// report: accounts and registrations, calls and states, transports, media
    /// sessions, last refused calls, queues, RTP port range and counters. At
    /// most `SIPRAL_STATE_TEXT_MAX` bytes with the NUL.
    ///
    /// Safe from any thread and never waits. If another thread holds the
    /// stack, the last snapshot kept by a poll (at most once a second) is
    /// returned, and its first line says so. A media session busy on a frame
    /// is reported as busy.
    ///
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL`, with the length needed in `out_needed`,
    /// when it does not fit; `out_needed` may be null.
    ///
    /// Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// capacity of zero, and `out_needed` must point at one `size_t` or be null.
    /// </summary>
    public static nuint StackStateText(ulong stack, sbyte[] buffer)
    {
        Check(NativeMethods.sipral_stack_state_text(stack, buffer, (nuint)buffer.Length, out var needed));
        return needed;
    }

    /// <summary>
    /// Reserve a free even port from this stack's RTP range, with the odd
    /// port above it kept for RTCP, and write it to `out_port`.
    ///
    /// `SIPRAL_STATUS_EXHAUSTED` when every pair is taken (the last error
    /// gives the range size). `SIPRAL_STATUS_WRONG_STATE` without a range.
    ///
    /// Safety
    ///
    /// `out_port` must point at one `uint32_t`.
    /// </summary>
    public static uint StackRtpPortReserve(ulong stack)
    {
        Check(NativeMethods.sipral_stack_rtp_port_reserve(stack, out var port));
        return port;
    }

    /// <summary>
    /// Give back a reserved port no call used. A port a call took comes back
    /// by itself. `SIPRAL_STATUS_INVALID_ARGUMENT` for one not reserved,
    /// including a second release.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    /// </summary>
    public static void StackRtpPortRelease(ulong stack, uint port)
    {
        Check(NativeMethods.sipral_stack_rtp_port_release(stack, port));
    }

    /// <summary>
    /// Verify incoming callers against `config`'s trust anchors from now on
    /// (RFC 8224 §6.2).
    ///
    /// Replaces any earlier setting. Reporting accounts verify only with at
    /// least one anchor; `SIPRAL_STIR_VERIFICATION_STRICT` accounts always do.
    /// `config.unix_seconds` sets the wall clock at `now_ms`; zero keeps the
    /// previous one and is `SIPRAL_STATUS_WRONG_STATE` the first time. A stack
    /// whose accounts only sign also calls this, with no anchors.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for anchors that are not P-256
    /// certificates; `SIPRAL_STATUS_NOT_SUPPORTED` without `SIPRAL_FEATURE_STIR`.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_stir_config_t` whose `size` member
    /// says how long it is, with `anchors` readable for `anchors_len` bytes.
    /// </summary>
    public static void StackStir(ulong stack, in SipralStirConfig config, ulong nowMs)
    {
        Check(NativeMethods.sipral_stack_stir(stack, in config, nowMs));
    }

    /// <summary>
    /// The certificate chain for a call's `Identity`, fetched from the URL of
    /// `SIPRAL_VERIFICATION_STAGE_CERTIFICATE_WANTED`: PEM or DER, signing
    /// certificate first. Null and zero if it could not be fetched.
    ///
    /// The verdict is reached and the call delivered or refused before this
    /// returns; the events come from the next `sipral_stack_poll`.
    /// `SIPRAL_STATUS_STALE_HANDLE` for a call no longer waiting.
    ///
    /// Safety
    ///
    /// `chain` must be readable for `chain_len` bytes, or null with a length
    /// of zero.
    /// </summary>
    public static void CallStirCertificate(ulong stack, ulong call, byte[] chain, ulong nowMs)
    {
        Check(NativeMethods.sipral_call_stir_certificate(stack, call, chain, (nuint)chain.Length, nowMs));
    }

    /// <summary>
    /// How many streams one call's encryption report has (one audio stream).
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    /// </summary>
    public static nuint MediaEncryptionCount(ulong media)
    {
        Check(NativeMethods.sipral_media_encryption_count(media, out var count));
        return count;
    }

    /// <summary>
    /// How one stream of a call is protected now. An index past the end is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT`.
    ///
    /// Safety
    ///
    /// `out_stream` must point at a `sipral_stream_encryption_t` whose `size`
    /// member says how long it is.
    /// </summary>
    public static SipralStreamEncryption MediaEncryptionAt(ulong media, nuint index)
    {
        var stream = SipralStreamEncryption.Sized();
        Check(NativeMethods.sipral_media_encryption_at(media, index, ref stream));
        return stream;
    }

    /// <summary>
    /// Listen for keypad digits in the far-end audio as `mode` (a
    /// SipralDtmfDetection) says. `SIPRAL_STATUS_WRONG_STATE` if this
    /// stack does not run the call's media.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void CallDtmfDetection(ulong stack, ulong call, uint mode)
    {
        Check(NativeMethods.sipral_call_dtmf_detection(stack, call, mode));
    }

    /// <summary>
    /// Listen for call progress and decide who answered, as `config` says;
    /// `config.listen` off stops. Call right after `sipral_call_place`. Each
    /// finding is a `SIPRAL_EVENT_KIND_PROGRESS_DETECTED`.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` if this stack does not run the call's media;
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for a bad value, changing nothing.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_progress_config_t` whose `size`
    /// member says how long it is.
    /// </summary>
    public static void CallDetectProgress(ulong stack, ulong call, in SipralProgressConfig config)
    {
        Check(NativeMethods.sipral_call_detect_progress(stack, call, in config));
    }

    /// <summary>
    /// Beep while the call is recorded, as `tone` says; `tone.enabled` off
    /// silences it. Applies at once to a running recording.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` if this stack does not run the call's media;
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` naming the bad member, changing nothing.
    ///
    /// Safety
    ///
    /// `tone` must point at a `sipral_consent_tone_t` whose `size` member
    /// says how long it is.
    /// </summary>
    public static void CallConsentTone(ulong stack, ulong call, in SipralConsentTone tone)
    {
        Check(NativeMethods.sipral_call_consent_tone(stack, call, in tone));
    }

    /// <summary>
    /// Start recording this call to `path` as `options` say. With every option
    /// zero this is sipral_media_record_start.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for invalid options or a refused path;
    /// `SIPRAL_STATUS_NOT_SUPPORTED` for Ogg Opus in a build without Opus;
    /// `SIPRAL_STATUS_RECORDING_FAILED` when the header could not be written.
    ///
    /// Safety
    ///
    /// `path` must be readable for `path_len` bytes, and `options` must point
    /// at a `sipral_recording_options_t` whose `size` member says how long
    /// it is.
    /// </summary>
    public static void MediaRecordStartWith(ulong media, string path, in SipralRecordingOptions options)
    {
        var pathBytes = Encoding.UTF8.GetBytes(path);
        var pathSigned = new sbyte[pathBytes.Length];
        Buffer.BlockCopy(pathBytes, 0, pathSigned, 0, pathBytes.Length);
        Check(NativeMethods.sipral_media_record_start_with(media, pathSigned, (nuint)pathSigned.Length, in options));
    }

    /// <summary>
    /// Make a local conference on this stack, holding only this end if it
    /// takes part, and write its handle to `out_conference`.
    ///
    /// In device mode the engine carries it at once, opening the devices
    /// under automatic activation.
    ///
    /// `SIPRAL_STATUS_CONFERENCE_REFUSED` for a rate other than 8, 16, 32 or
    /// 48 kHz, or more than 1024 members.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_local_conference_config_t` whose
    /// `size` says how long it is, and `out_conference` at one `sipral_handle_t`.
    /// </summary>
    public static ulong LocalConferenceCreate(ulong stack, in SipralLocalConferenceConfig config)
    {
        Check(NativeMethods.sipral_local_conference_create(stack, in config, out var conference));
        return conference;
    }

    /// <summary>
    /// End a conference. Its calls carry their own audio again (in device
    /// mode the engine takes them back), a running recording is finished, and
    /// the handle is stale.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    /// </summary>
    public static void LocalConferenceDestroy(ulong conference)
    {
        Check(NativeMethods.sipral_local_conference_destroy(conference));
    }

    /// <summary>
    /// Add a call, from the next tick, at its codec's rate; its far end hears
    /// everybody but itself.
    ///
    /// The call needs running media. `SIPRAL_STATUS_CONFERENCE_REFUSED` when
    /// full, for a call already in a conference or joined with
    /// `sipral_call_join`, or for an unmixable codec (rate not 8, 16, 32 or
    /// 48 kHz, or frames over 60 ms).
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void LocalConferenceAdd(ulong conference, ulong call)
    {
        Check(NativeMethods.sipral_local_conference_add(conference, call));
    }

    /// <summary>
    /// Take a call out, from the next tick. Its media is the application's
    /// again (in device mode, the engine's).
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for a call that is not in it.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void LocalConferenceRemove(ulong conference, ulong call)
    {
        Check(NativeMethods.sipral_local_conference_remove(conference, call));
    }

    /// <summary>
    /// Mute or unmute one direction of a member from the next tick: input
    /// (others stop hearing it) or output (it stops hearing).
    /// `direction` is `SIPRAL_AUDIO_DIRECTION_INPUT` or `_OUTPUT`; `member` is a
    /// call in the conference, or the conference handle for this end.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for a member that is not in it.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void LocalConferenceSetMuted(ulong conference, ulong member, uint direction, uint muted)
    {
        Check(NativeMethods.sipral_local_conference_set_muted(conference, member, direction, muted));
    }

    /// <summary>
    /// Set one direction's level for a member, from the next tick, in
    /// `sipral_audio_set_gain` steps: 256 unity, 1024 at most. Input is what
    /// others hear of it; output is what it hears.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    /// </summary>
    public static void LocalConferenceSetGain(ulong conference, ulong member, uint direction, uint gain)
    {
        Check(NativeMethods.sipral_local_conference_set_gain(conference, member, direction, gain));
    }

    /// <summary>
    /// How the conference stands.
    ///
    /// Safety
    ///
    /// `out_info` must point at a `sipral_local_conference_info_t` whose
    /// `size` says how long it is.
    /// </summary>
    public static SipralLocalConferenceInfo LocalConferenceInfo(ulong conference)
    {
        var info = SipralLocalConferenceInfo.Sized();
        Check(NativeMethods.sipral_local_conference_info(conference, ref info));
        return info;
    }

    /// <summary>
    /// One member by index: this end first if it takes part, then calls in
    /// join order. Stable until the next join or leave.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for an index past the last member.
    ///
    /// Safety
    ///
    /// `out_member` must point at a `sipral_local_conference_member_t` whose
    /// `size` says how long it is.
    /// </summary>
    public static SipralLocalConferenceMember LocalConferenceMemberAt(ulong conference, nuint index)
    {
        var member = SipralLocalConferenceMember.Sized();
        Check(NativeMethods.sipral_local_conference_member_at(conference, index, ref member));
        return member;
    }

    /// <summary>
    /// Who talked in the last tick, loudest at index zero. Muted members are
    /// never listed.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` past the last talker (count in
    /// `sipral_local_conference_info_t::talkers`).
    ///
    /// Safety
    ///
    /// `out_member` must point at one `sipral_handle_t`.
    /// </summary>
    public static ulong LocalConferenceTalkerAt(ulong conference, nuint index)
    {
        Check(NativeMethods.sipral_local_conference_talker_at(conference, index, out var member));
        return member;
    }

    /// <summary>
    /// 20 ms of conference in application mode. `mic` is this end's frame,
    /// `sipral_local_conference_info_t::frame_samples` long; `speaker` gets
    /// what this end hears, same length, written to `out_written`. Without
    /// this end, `mic` may be null and `speaker` gets silence.
    ///
    /// Call every 20 ms from the audio thread, then drain
    /// `sipral_local_conference_poll_transmit`.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` in device mode;
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for a wrong frame length;
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL` for a short speaker buffer, with the
    /// length needed in `out_written`.
    ///
    /// Safety
    ///
    /// `mic` readable for `mic_count` `int16_t`, `speaker` writable for
    /// `capacity` `int16_t`, `out_written` one `size_t` or null.
    /// </summary>
    public static nuint LocalConferenceTick(ulong conference, ulong nowMs, short[] mic, short[] speaker)
    {
        Check(NativeMethods.sipral_local_conference_tick(conference, nowMs, mic, (nuint)mic.Length, speaker, (nuint)speaker.Length, out var written));
        return written;
    }

    /// <summary>
    /// The oldest packet a member's call owes its far end, in application
    /// mode. `out_call` names the call whose socket sends it; `packet` is
    /// filled as by `sipral_media_capture`. `len` zero with
    /// `SIPRAL_HANDLE_NONE` means nothing waits. Drain after every tick.
    ///
    /// Safety
    ///
    /// `out_call` must point at one `sipral_handle_t`, and `packet` at a
    /// `sipral_media_packet_t` as `sipral_media_capture` describes.
    /// </summary>
    public static ulong LocalConferencePollTransmit(ulong conference, ref SipralMediaPacket packet)
    {
        Check(NativeMethods.sipral_local_conference_poll_transmit(conference, out var call, ref packet));
        return call;
    }

    /// <summary>
    /// Record the whole conference mix to `path`, one channel, as `options`
    /// say (WAV or Ogg Opus, at the conference rate unless another is named).
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` if already recording;
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for stereo, unusable options or a
    /// refused path; `SIPRAL_STATUS_RECORDING_FAILED` if the header write fails.
    ///
    /// Safety
    ///
    /// `path` readable for `path_len` bytes; `options` a
    /// `sipral_recording_options_t` whose `size` says how long it is.
    /// </summary>
    public static void LocalConferenceRecordStart(ulong conference, string path, in SipralRecordingOptions options)
    {
        var pathBytes = Encoding.UTF8.GetBytes(path);
        var pathSigned = new sbyte[pathBytes.Length];
        Buffer.BlockCopy(pathBytes, 0, pathSigned, 0, pathBytes.Length);
        Check(NativeMethods.sipral_local_conference_record_start(conference, pathSigned, (nuint)pathSigned.Length, in options));
    }

    /// <summary>
    /// Stop recording the conference, and finish the file.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when nothing is being recorded.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    /// </summary>
    public static void LocalConferenceRecordStop(ulong conference)
    {
        Check(NativeMethods.sipral_local_conference_record_stop(conference));
    }

    /// <summary>
    /// Hand the resolver's answer to a
    /// SIPRAL_EVENT_KIND_LOOKUP_WANTED
    /// back to the account that asked.
    ///
    /// `name` and `record` are the event's; `answer` is a SipralDnsAnswer.
    /// With `SIPRAL_DNS_ANSWER_RECORDS`, `records` is comma-separated records,
    /// each space-separated: TTL in seconds, then zone-file data. A/AAAA:
    /// `300 192.0.2.40`; SRV: `300 10 60 5060 sip1.example.com`; NAPTR
    /// without the regexp: `300 10 50 S SIP+D2U _sip._udp.example.com`.
    /// Null or empty reads as `SIPRAL_DNS_ANSWER_NOTHING`.
    ///
    /// Answer every lookup, failures included: the procedure waits for each.
    /// An answer nothing waits for any more is `SIPRAL_STATUS_OK` and changes
    /// nothing.
    ///
    /// Safety
    ///
    /// `name` must be readable for `name_len` bytes and `records` for
    /// `records_len`.
    /// </summary>
    public static void AccountLookedUp(ulong stack, ulong account, string name, uint record, uint answer, string records, ulong nowMs)
    {
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var nameSigned = new sbyte[nameBytes.Length];
        Buffer.BlockCopy(nameBytes, 0, nameSigned, 0, nameBytes.Length);
        var recordsBytes = Encoding.UTF8.GetBytes(records);
        var recordsSigned = new sbyte[recordsBytes.Length];
        Buffer.BlockCopy(recordsBytes, 0, recordsSigned, 0, recordsBytes.Length);
        Check(NativeMethods.sipral_account_looked_up(stack, account, nameSigned, (nuint)nameSigned.Length, record, answer, recordsSigned, (nuint)recordsSigned.Length, nowMs));
    }

    /// <summary>
    /// Check the server's leaf certificate (DER) against the account's pin:
    /// SHA-256 over the bytes, constant-time. `unix_seconds` is used only for
    /// the reported dates.
    ///
    /// `SIPRAL_STATUS_OK` with `pinned` 1: accept. With `pinned` 0: no pin,
    /// platform checks decide. `SIPRAL_STATUS_CERTIFICATE_REFUSED`: refuse;
    /// nothing written.
    ///
    /// Safety
    ///
    /// `certificate` must be readable for `certificate_len` bytes, and
    /// `out_pinned` must point at a `sipral_pinned_certificate_t` whose
    /// `size` member says how long it is.
    /// </summary>
    public static SipralPinnedCertificate AccountCheckCertificate(ulong stack, ulong account, byte[] certificate, ulong unixSeconds)
    {
        var pinned = SipralPinnedCertificate.Sized();
        Check(NativeMethods.sipral_account_check_certificate(stack, account, certificate, (nuint)certificate.Length, unixSeconds, ref pinned));
        return pinned;
    }

    /// <summary>
    /// The `host:port` to advertise for a socket bound at `bound` whose
    /// traffic goes to `peer` (both `host:port` addresses, not names),
    /// NUL-terminated into `buffer`.
    ///
    /// A specific address is used as is; loopback toward a non-loopback
    /// `peer` is `SIPRAL_STATUS_UNREACHABLE_ADDRESS`. A wildcard bind uses
    /// the OS route toward `peer` (found without sending);
    /// `SIPRAL_STATUS_TRANSPORT_DOWN` when there is none. Any thread.
    /// `out_needed` gets the length with the NUL; `buffer` may be null with
    /// `capacity` zero; `SIPRAL_STATUS_BUFFER_TOO_SMALL` writes nothing.
    ///
    /// Safety
    ///
    /// `bound` and `peer` must be readable for their lengths, `buffer` must
    /// be writable for `capacity` bytes or be null with a capacity of zero,
    /// and `out_needed` must point at one `size_t` or be null.
    /// </summary>
    public static nuint AdvertisedAddress(string bound, string peer, sbyte[] buffer)
    {
        var boundBytes = Encoding.UTF8.GetBytes(bound);
        var boundSigned = new sbyte[boundBytes.Length];
        Buffer.BlockCopy(boundBytes, 0, boundSigned, 0, boundBytes.Length);
        var peerBytes = Encoding.UTF8.GetBytes(peer);
        var peerSigned = new sbyte[peerBytes.Length];
        Buffer.BlockCopy(peerBytes, 0, peerSigned, 0, peerBytes.Length);
        Check(NativeMethods.sipral_advertised_address(boundSigned, (nuint)boundSigned.Length, peerSigned, (nuint)peerSigned.Length, buffer, (nuint)buffer.Length, out var needed));
        return needed;
    }

    /// <summary>
    /// Turn the diagnostic trace on or off: `on` is a `SipralToggle`, zero
    /// leaves it (ABI 0.34).
    ///
    /// On, the trace level writes whole SIP messages with the peer and no
    /// pseudonyms, to compare runs. Credentials and keys are never written
    /// (list in `sipral_stack_config_t::diagnostic_trace`). Off, the trace is
    /// pseudonymised. Only applies at `SIPRAL_LOG_LEVEL_TRACE`.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    /// </summary>
    public static void StackDiagnosticTrace(ulong stack, uint on)
    {
        Check(NativeMethods.sipral_stack_diagnostic_trace(stack, on));
    }

    /// <summary>
    /// The SRTP suites calls use by default, in order, as `sipral_srtp_suite_t`
    /// numbers. `out_count` always receives the total; too small a capacity is
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL`.
    ///
    /// Safety
    ///
    /// `out_suites` must be writable for `capacity` `uint32_t` or null with a
    /// capacity of zero, and `out_count` must point at one `size_t` or be null.
    /// </summary>
    public static nuint StackSrtpSuiteOrder(ulong stack, uint[] outSuites)
    {
        Check(NativeMethods.sipral_stack_srtp_suite_order(stack, outSuites, (nuint)outSuites.Length, out var count));
        return count;
    }

    /// <summary>
    /// Set one call's own gain in one direction, on top of the stack's, in
    /// `sipral_audio_set_gain` steps. Input is what the microphone sends that
    /// call; output is how loud it plays. Kept through hold and conference,
    /// gone when the call ends.
    ///
    /// In a local conference it acts on the call's path, on top of the
    /// conference's member controls: input on what its far end hears, output
    /// on what it says into the conference.
    /// `SIPRAL_STATUS_WRONG_STATE` when the engine is not carrying the call's
    /// media: before it starts, after it ends, or in application mode.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    /// </summary>
    public static void AudioCallSetGain(ulong stack, ulong call, uint direction, uint gain)
    {
        Check(NativeMethods.sipral_audio_call_set_gain(stack, call, direction, gain));
    }

    /// <summary>
    /// One call's own gain in one direction, in `sipral_audio_set_gain` steps.
    ///
    /// Safety
    ///
    /// `out_gain` must point at one `uint32_t`.
    /// </summary>
    public static uint AudioCallGain(ulong stack, ulong call, uint direction)
    {
        Check(NativeMethods.sipral_audio_call_gain(stack, call, direction, out var gain));
        return gain;
    }

    /// <summary>
    /// Mute or unmute one call in one direction while other calls go on (a
    /// consultation). A muted direction sends silence. Kept, dropped and
    /// refused as `sipral_audio_call_set_gain` is, conference included.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    /// </summary>
    public static void AudioCallSetMuted(ulong stack, ulong call, uint direction, uint muted)
    {
        Check(NativeMethods.sipral_audio_call_set_muted(stack, call, direction, muted));
    }

    /// <summary>
    /// Whether one call is muted in one direction: one or zero.
    ///
    /// Safety
    ///
    /// `out_muted` must point at one `uint32_t`.
    /// </summary>
    public static uint AudioCallMuted(ulong stack, ulong call, uint direction)
    {
        Check(NativeMethods.sipral_audio_call_muted(stack, call, direction, out var muted));
        return muted;
    }

    /// <summary>
    /// One call's meter in one direction, after its own gain and mute: what
    /// `sipral_audio_level` reads, for one call of several.
    ///
    /// Safety
    ///
    /// `out_peak` must point at one `uint32_t`.
    /// </summary>
    public static uint AudioCallLevel(ulong stack, ulong call, uint direction)
    {
        Check(NativeMethods.sipral_audio_call_level(stack, call, direction, out var peak));
        return peak;
    }

}
