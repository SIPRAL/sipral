// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Printed from the declarations in crates/sipral-ffi by tools/abi-gen.
// Do not edit: `cargo run -p sipral-abi-gen` writes it again, and
// `scripts/check.sh` fails when what is committed is not what came out.

import CSipral

/// An opaque reference to something this library owns.
///
/// A number, not a pointer: nothing is read from it, and only this
/// library makes one. Zero is never a live handle.
///
/// An account or call handle is valid only on the stack that minted it;
/// on any other stack it is `SIPRAL_STATUS_INVALID_HANDLE`.
public typealias SipralHandle = sipral_handle_t

/// The result of a call across the C ABI.
///
/// The numbers are ABI: stable for the major version, new ones only at the
/// end. 17 is reserved forever and never returned.
///
/// Typed `int32_t`: zero is success, failures are positive, none negative.
/// Read an unknown status from a newer library as a failure.
public enum SipralStatus: Int32, Sendable {
    /// The call did what it was asked to.
    case ok = 0
    /// A pointer was null where one is required, a length disagreed with what
    /// it describes, or a value was outside what the call accepts.
    case invalidArgument = 1
    /// The handle never came from this library, or it came from a stack
    /// other than the one it was used with.
    case invalidHandle = 2
    /// The handle came from this library and what it named is gone: a use
    /// after free, or a second free.
    case staleHandle = 3
    /// A versioned struct declared a size this build cannot work with, or a
    /// binding asked for an ABI this library does not provide.
    case unsupportedVersion = 4
    /// The buffer supplied is too small. The length needed has been written to
    /// the out parameter, and nothing was written to the buffer.
    case bufferTooSmall = 5
    /// The object is already in use by another call, including one further
    /// down the same call stack. Nothing was done, and nothing blocked.
    case busy = 6
    /// No room: an object table is full, the RTP port range is spent, or a
    /// call's queue (DTMF, payload types, real-time text) is full. Nothing
    /// was done; the last error says which. `SIPRAL_STATUS_LIMIT_REACHED`
    /// is the application's own ceiling.
    case exhausted = 7
    /// A panic was caught at the boundary. The call did not finish; the last
    /// error carries the panic's message.
    case panic = 8
    /// Not possible in the object's current state, e.g. answering a call
    /// this end placed, or DTMF before there is a dialog.
    case wrongState = 9
    /// The request could not be assembled or handed to a transport. Nothing
    /// went out, and the call did not change.
    case notSent = 10
    /// The value is valid in this ABI but this build has no code for it.
    /// Nothing was applied, and retrying will not help. Unlike
    /// SipralStatus.invalidArgument, the value is not wrong; unlike
    /// SipralStatus.unsupportedVersion, it is not about struct shape.
    /// Exists so that nothing is ever silently accepted and ignored.
    case notSupported = 11
    /// A byte stream carried something that starts no known message. A
    /// stream has no resync point: close the connection. The last error
    /// says what was lost.
    case streamBroken = 12
    /// An audio device id the engine never listed. Refused before any
    /// platform call; `sipral_audio_device_at` lists the ids.
    case noSuchDevice = 13
    /// The audio device cannot serve: no channels in that direction,
    /// unplugged, or the platform refused it. The last error says which.
    case deviceUnusable = 14
    /// The platform did not answer about its audio devices within
    /// `sipral_stack_config_t::audio_probe_ms`. Nothing was done.
    case deviceTimedOut = 15
    /// The stack already holds or awaits `sipral_stack_config_t::max_dialogs`
    /// calls. Nothing went out. An ended call makes room; a higher limit
    /// needs a new stack.
    case limitReached = 16
    /// Refused by the security policy (ABI 0.31): unencrypted audio where
    /// SRTP is required, or a policy weaker than the account's. A refused
    /// INVITE was answered 488; an outgoing call never left.
    case securityPolicy = 18
    /// The recording file would not take a write (disk full, volume gone).
    /// A bad path is `SIPRAL_STATUS_INVALID_ARGUMENT` instead. The recording
    /// stopped; the file holds audio up to the last checkpoint.
    case recordingFailed = 19
    /// The call never negotiated this, e.g. text on a call with no `m=text`
    /// stream. Only a new accepted offer changes it.
    case notNegotiated = 20
    /// The far end's Contact never carried `isfocus` (RFC 4579 §4.1), so
    /// there is no conference to name or subscribe to.
    case notAFocus = 21
    /// The transport has failed or closed and was not bound again. Nothing
    /// went out. Reconnect, call `sipral_stack_transport_bind`, retry.
    case transportDown = 22
    /// A local conference would not take the call (ABI 0.32): full, the
    /// call is already conferenced or joined with `sipral_call_join`, or its
    /// codec rate is not mixed. The last error says which.
    case conferenceRefused = 23
    /// `now_ms` was more than 50 ms behind the last reading this stack saw
    /// (ABI 0.33). Nothing was done and the clock did not move; read the
    /// clock again and retry. Repeated, it means the clock went backwards.
    case clockBehind = 24
    /// The TLS certificate's SHA-256 fingerprint differs from
    /// `sipral_account_config_t::tls_pin_sha256` (ABI 0.34). Refuse the
    /// handshake (`docs/22-tls.md`).
    case certificateRefused = 25
    /// About to advertise an address the peer cannot reach (ABI 0.34):
    /// loopback to a remote peer, or the unspecified address in a `Contact`.
    /// Nothing was sent; the last error names both addresses.
    /// `sipral_advertised_address` finds the right one.
    case unreachableAddress = 26
}

/// What a stack speaks. Names for `sipral_stack_config_t::transport`. Zero is
/// not one, so a caller who meant TLS is never put on the wire in the clear.
public enum SipralTransport: UInt32, Sendable {
    /// UDP.
    case udp = 1
    /// TCP.
    case tcp = 2
    /// TLS over TCP.
    case tls = 3
    /// WebSocket.
    case ws = 4
    /// WebSocket over TLS.
    case wss = 5
}

/// Why a transport could not deliver. Names for sipral_stack_transport_failed's `error`.
///
/// Coarse on purpose: a client transaction terminates on every one of these (§17); the
/// detail belongs in the caller's log.
public enum SipralTransportError: UInt32, Sendable {
    /// Anything the caller could not classify.
    case other = 0
    /// Nothing is listening at the far end.
    case connectionRefused = 1
    /// An established connection was reset.
    case connectionReset = 2
    /// No route, or an ICMP unreachable.
    case unreachable = 3
    /// The connection attempt or the write timed out.
    case timedOut = 4
    /// The connection was closed and cannot be written to again.
    case closed = 5
}

/// Why a TLS connection was refused, as the platform's TLS library said it. Names for
/// `sipral_transport_failure_t::tls` and `sipral_transport_failed_event_t::tls`.
///
/// Sipral links no TLS library (`docs/22-tls.md`); the stack only carries the application's
/// classification. A connection never answered is `SIPRAL_TRANSPORT_ERROR_CONNECTION_REFUSED`
/// with this left at none.
public enum SipralTlsFailure: UInt32, Sendable {
    /// Not a TLS failure, or one the application could not classify.
    case none = 0
    /// No trusted authority: self-signed, an unprovided private CA, or not the pinned one.
    case untrusted = 1
    /// The certificate is trusted and names another server.
    case nameMismatch = 2
    /// The certificate has expired, or is not valid yet.
    case expired = 3
    /// The handshake failed: no common version or cipher, a server alert, or no TLS there.
    case handshakeRefused = 4
}

/// The three answers a setting can give in a struct that starts out zeroed.
///
/// Not a boolean: zero must mean "unset", so the library never turns a
/// control off because the caller left it zeroed.
public enum SipralToggle: UInt32, Sendable {
    /// Nothing was said; whatever this build defaults to.
    case `default` = 0
    /// On.
    case on = 1
    /// Off.
    case off = 2
}

/// What a call or a stack says about SRTP. Names for
/// `sipral_stack_config_t::srtp` (the stack's default) and
/// `sipral_call_config_t::srtp` (a per-call override).
///
/// Zero means "unset": on the stack, the built-in default
/// SipralSrtp.notOffered; on a call, the stack's setting.
/// `docs/05-media.md` details each value.
public enum SipralSrtp: UInt32, Sendable {
    /// Do not offer it, but answer an offer on the secure profile with keys.
    case notOffered = 1
    /// Offer it, and answer a plain offer plainly.
    case offered = 2
    /// Offer it, and let no stream on this call carry audio unencrypted.
    case required = 3
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
    case dtls = 4
    /// Offer DTLS-SRTP and allow no other keying, including an answer
    /// carrying `a=crypto`.
    case dtlsRequired = 5
    /// DTLS-SRTP with SDES fallback, never unencrypted. The offer is one
    /// `RTP/SAVP` stream with both fingerprint and crypto lines; the answer
    /// decides. An incoming offer is answered the way it was keyed; a plain
    /// one is refused with 488.
    ///
    /// `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
    /// `SIPRAL_FEATURE_DTLS_SRTP`.
    case dtlsOrSdes = 6
    /// Offer SDES on plain `RTP/AVP` ("SRTP optional"): encrypted when the
    /// answer takes an `a=crypto` line, plain otherwise. For servers that
    /// reject `RTP/SAVP` with 488. Not standard (RFC 4568 defines the
    /// attribute for secure profiles). An incoming `RTP/AVP` offer with a
    /// usable line is answered with a key, anything else as `Offered`.
    case bestEffort = 7
}

/// What a call or a stack says about ICE. Names for
/// `sipral_stack_config_t::ice` (the stack's default) and
/// `sipral_call_config_t::ice` (a per-call override).
///
/// Zero means "unset": on the stack, the built-in default
/// SipralIce.off; on a call, the stack's setting.
///
/// A call that offers ICE also asks for RFC 5761 multiplexing, whatever
/// `offer_rtcp_mux` says: this ABI names one address per stream.
public enum SipralIce: UInt32, Sendable {
    /// Do not offer it, and do not answer a peer that does. The default;
    /// `docs/06-nat.md` says why.
    case off = 1
    /// Offer it, and use it against a peer that offers it back.
    ///
    /// A peer without ICE gets the call on the signalled address and
    /// symmetric RTP. The application **must** drain
    /// sipral_media_poll_transmit, or no path is ever chosen.
    ///
    /// `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
    /// `SIPRAL_FEATURE_ICE`.
    case offered = 2
    /// Offer it, and let no stream carry audio on a path ICE did not check.
    ///
    /// A peer that fails ICE ends the call's media with
    /// `SIPRAL_EVENT_KIND_MEDIA_FAILED` instead of falling back.
    case required = 3
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
    case lite = 4
}

/// One codec this ABI has a number for.
///
/// Values are permanent. Whether this build contains a codec is answered by
/// `SIPRAL_FEATURE_*` and `sipral_codec_at`, not by this list.
public enum SipralCodec: UInt32, Sendable {
    /// No codec: the call has none, or the event is not about one.
    case unknown = 0
    /// G.711 mu-law, payload type 0.
    case pcmu = 1
    /// G.711 A-law, payload type 8.
    case pcma = 2
    /// G.722, wideband at the price of a narrowband stream.
    case g722 = 3
    /// Opus. Declared in every build; presence is `SIPRAL_FEATURE_OPUS`.
    case opus = 4
    /// G.729 Annex A, payload type 18. Offered only when a codec order names
    /// `G729`; offers `annexb=yes`, answers with the offer's `annexb`.
    case g729 = 5
    /// L16 at 8 kHz mono, dynamic payload type `L16/8000`. Offered only
    /// when a codec order names it.
    case l16Narrowband = 6
    /// L16 at 16 kHz mono, `L16/16000`. Offered only when a codec order
    /// names it.
    case l16Wideband = 7
}

/// What became of one codec this call's catalogue could have used. Names
/// for sipral_codec_candidate_t.outcome.
public enum SipralCodecOutcome: UInt32, Sendable {
    /// Not an outcome: unknown to this ABI, or the struct was never filled.
    case unknown = 0
    /// What the call agreed on. Exactly one candidate carries it, the same
    /// codec as `sipral_media_info_t::codec`.
    case chosen = 1
    /// The far end's description did not name it.
    case notNamed = 2
    /// The far end named it and this end had something better: the codec
    /// in `outranked_by` came first in this call's order.
    case outranked = 3
}

/// Whether a sipral_path_candidate_t is a candidate pair or a relay.
public enum SipralPathKind: UInt32, Sendable {
    /// Not a kind: the struct was never filled in.
    case unknown = 0
    /// A candidate pair the call's ICE checklist held (RFC 8445
    /// §6.1.2).
    case pair = 1
    /// An allocation on a TURN server the call's agent held (RFC 8656).
    case relay = 2
}

/// The kind of an ICE candidate (RFC 8445 §5.1.1). Names for
/// sipral_path_candidate_t.local_kind and `remote_kind`.
public enum SipralCandidateKind: UInt32, Sendable {
    /// Not known: a relay's server, which is no candidate, or the far
    /// end of a pair a lite end took from a nomination and never learned
    /// the kind of.
    case unknown = 0
    /// An address a socket of the host's own is bound to.
    case host = 1
    /// The address a NAT maps the host's socket to, as a STUN or TURN
    /// server saw it.
    case serverReflexive = 2
    /// An address a connectivity check revealed (RFC 8445 §7.3.1.3).
    case peerReflexive = 3
    /// An address on a TURN server that relays for the host.
    case relayed = 4
}

/// What became of one path a call's ICE agent tried. Names for
/// sipral_path_candidate_t.outcome.
public enum SipralPathOutcome: UInt32, Sendable {
    /// Not an outcome: unknown to this ABI, or the struct was never filled.
    case unknown = 0
    /// The path the call's media takes: the selected pair (RFC 8445
    /// §8.1.2), or the relay it runs through.
    case selected = 1
    /// A pair whose check succeeded, with nothing selected yet.
    case valid = 2
    /// Nothing has decided it yet: a pair frozen, waiting its turn or
    /// with its check on the wire; a relay still being allocated.
    case waiting = 3
    /// A pair whose check succeeded, with a pair of higher priority
    /// selected over it.
    case outranked = 4
    /// A pair another was nominated ahead of: its check had not finished
    /// when the selection took it off the checklist (RFC 8445 §8.1.2),
    /// or it succeeded after a lower one was nominated.
    case nominatedElsewhere = 5
    /// A pair whose check was never answered (RFC 8489 §6.2.1).
    case timedOut = 6
    /// A pair the far end refused; `code` is the STUN error code (RFC
    /// 8445 §7.2.5.2.4).
    case refused = 7
    /// A pair whose answer came from an address other than the one its
    /// check went to (RFC 8445 §7.2.5.2.1): a NAT between rewriting it.
    case notSymmetric = 8
    /// A pair whose answer named no address to form a valid pair from.
    case unusable = 9
    /// A relayed pair the relay would not let the far end through for,
    /// or a relay whose allocation the server refused; `code` is the
    /// TURN server's error code, zero when it gave none (RFC 8656 §9,
    /// §7.3).
    case relayRefused = 10
    /// A pair never checked: the pair limit discarded it (RFC 8445
    /// §6.1.2.5), or its checklist ended before its turn came.
    case notChecked = 11
    /// A relay held, that no selected pair runs through — or none yet.
    case held = 12
    /// A relay given back: ICE concluded on a pair that does not use it
    /// (RFC 8445 §8.3.1), or this branch of a forked call let go of it.
    case released = 13
    /// A relay the server took back; `code` is its error code, zero when
    /// a refresh went unanswered (RFC 8656 §8).
    case lost = 14
}

/// Which way audio may flow, as seen from here. Names for every `direction`.
public enum SipralDirection: UInt32, Sendable {
    /// Not negotiated.
    case unknown = 0
    /// Both ways.
    case sendRecv = 1
    /// This end sends and does not receive, which is what holding the far end
    /// looks like from here.
    case sendOnly = 2
    /// This end receives and does not send.
    case recvOnly = 3
    /// Neither way, and the stream stays in the session.
    case inactive = 4
}

/// Where control traffic goes. Names for sipral_media_info_t.rtcp.
public enum SipralRtcp: UInt32, Sendable {
    /// Not negotiated.
    case unknown = 0
    /// One port carries both (RFC 5761), which happens only where both ends
    /// asked for it.
    case muxed = 1
    /// A port of its own at each end.
    case separatePort = 2
    /// None at all: the peer said it is not using RTCP.
    case off = 3
}

/// Why media failed, for a machine to act on. Names for
/// `sipral_media_event_t::fault`.
public enum SipralMediaFault: UInt32, Sendable {
    /// Nothing failed.
    case none = 0
    /// The peer answered with a format this build cannot encode or decode.
    case unsupportedCodec = 1
    /// The two descriptions agree on nothing that can carry audio.
    case noCommonCodec = 2
    /// One end refused the stream with a port of zero. The call is up and
    /// carries no audio, which is a thing a peer is allowed to want.
    case streamRefused = 3
    /// There is no session description to work from.
    case noDescription = 4
    /// A description could not be read.
    case badDescription = 5
    /// The recording stopped writing: the disk filled, the file went away.
    case recording = 6
    /// The codec refused a frame.
    case codec = 7
    /// Something else the layer below reported and this ABI has no word for.
    case other = 8
    /// ICE could not carry this call: the far end described none this
    /// stack could use and the policy was `SIPRAL_ICE_REQUIRED`, the far
    /// end took `a=rtcp-mux` out of an answer to an ICE offer, or consent
    /// to send on the pair that was chosen was withdrawn part-way through
    /// (RFC 7675 §5). Signalling is still sound; an application may fall
    /// back to a non-ICE profile.
    case ice = 9
    /// The SRTP policy refused the far end's description: a plain answer
    /// (hung up with `Reason` 488) or a plain re-offer (refused with 488,
    /// old keys kept).
    case securityPolicy = 10
}

/// What a datagram handed to sipral_media_receive turned out to be.
public enum SipralArrival: UInt32, Sendable {
    /// Something this ABI has no word for.
    case unknown = 0
    /// Audio, held for playout.
    case queued = 1
    /// Audio that was not used: malformed, late, duplicated, from the wrong
    /// address, or on a payload type nobody negotiated. The counters in
    /// sipral_stream_stats_t say which, over the call.
    case dropped = 2
    /// A reception or sender report, folded into the statistics.
    case control = 3
    /// The far end says it is leaving the session (RFC 3550 §6.6). Audio will
    /// stop; the call has not ended until signalling says so.
    case goodbye = 4
    /// Control traffic that was not believed: from the wrong address, or not a
    /// well-formed compound packet.
    case controlRefused = 5
    /// A DTLS-SRTP handshake record, taken. Drain
    /// sipral_media_poll_transmit for the reply.
    case handshake = 6
    /// Arrived on an encrypted call before its keys exist; usually a peer
    /// that sends as soon as its half of the handshake ends.
    case notKeyed = 7
}

/// The SRTP transform a call is running. Names for
/// `sipral_media_event_t::suite`.
public enum SipralSrtpSuite: UInt32, Sendable {
    /// No transform: the event is not about one, or the call is not
    /// encrypted.
    case unknown = 0
    /// `AES_CM_128_HMAC_SHA1_80`, the one every implementation has.
    case aesCm80 = 1
    /// `AES_CM_128_HMAC_SHA1_32`, the same cipher with a shorter tag.
    case aesCm32 = 2
    /// `F8_128_HMAC_SHA1_80`, which is what 3GPP asks for. Reachable by
    /// SDES only; RFC 5764 §4.1.2 defines no DTLS-SRTP profile for it.
    case aesF8 = 3
    /// `AES_256_CM_HMAC_SHA1_80` (RFC 6188). SDES only.
    case aes256Cm80 = 4
    /// `AES_256_CM_HMAC_SHA1_32` (RFC 6188). SDES only.
    case aes256Cm32 = 5
    /// `AEAD_AES_128_GCM` (RFC 7714). DTLS-SRTP profile 0x0007.
    case aeadAes128Gcm = 6
    /// `AEAD_AES_256_GCM` (RFC 7714). DTLS-SRTP profile 0x0008, preferred
    /// between two ends of this stack.
    case aeadAes256Gcm = 7
}

/// Where the frame sipral_media_playback just produced came from.
public enum SipralPlayback: UInt32, Sendable {
    /// Something this ABI has no word for.
    case unknown = 0
    /// A packet the far end sent.
    case packet = 1
    /// One it sent and this end did not get, filled in by the concealment.
    case concealed = 2
    /// Comfort noise, from an RFC 3389 payload the far end sent instead of
    /// audio.
    case comfortNoise = 3
    /// Nothing was due: the buffer is still filling, or the far end has
    /// stopped.
    case silence = 4
}

/// Which way a digit goes to the far end: sipral_call_send_dtmf's `via`. Chosen per
/// send, since it is a fact about the peer, and a peer ignores an unsupported one silently.
public enum SipralDtmf: UInt32, Sendable {
    /// In the media, as an RFC 4733 telephone event: the one to reach for, carried end to
    /// end and surviving transcoding. One, not zero: zero is an unfilled field, refused.
    case rtp = 1
    /// An INFO per digit carrying `application/dtmf-relay`, which states the
    /// signal and how long it was held.
    case infoRelay = 2
    /// An INFO per digit carrying `application/dtmf`, whose whole body is the
    /// character. Some switches take only this one.
    case infoPlain = 3
    /// In the media, as the key's two tones written into the audio in place of the microphone,
    /// for a far end that listens only to the audio. `SIPRAL_DTMF_RTP` falls back to this on a
    /// call with no telephone event.
    case inBand = 4
}

/// What an event is about. Numbers are only ever added; a binding must
/// ignore a kind it does not know.
///
/// Numbers already spent on features this build does not have:
/// - 16: held for the set of audio devices changed (A2), which shipped as 43 in the wave that allocated its number; spent all the same
/// - 44: held for a second audio device event, which the audio engine did not need; spent all the same
public enum SipralEventKind: UInt32, Sendable {
    /// The stack is running on this thread: the first event, delivered
    /// once by the first poll.
    case started = 1
    /// A registration moved. `payload.registration` says how, and
    /// `account` says whose.
    case registrationChanged = 2
    /// Somebody is calling. Answer, ring, or reject it.
    case incomingCall = 3
    /// A call this end placed is getting somewhere short of an answer.
    case callProgress = 4
    /// A proxy forked the INVITE and a second phone is ringing.
    /// `payload.call.other` is the branch that has just appeared.
    case callForked = 5
    /// The call is up.
    case callConfirmed = 6
    /// The session inside a live call changed: a hold, a resume, or an offer
    /// either end made and had accepted.
    case sessionChanged = 7
    /// The far end offered a change this stack has no policy for. The
    /// transaction is held open: answer it or refuse it, or the call ends.
    case sessionOffered = 8
    /// A change this end offered was refused. The session stands as it was.
    case sessionChangeFailed = 9
    /// The far end asked this one to call somebody else.
    case transferRequested = 10
    /// A transfer this end asked for is under way.
    case transferProgress = 11
    /// And how it ended: the far end's final status, a 2xx hanging this
    /// call up. A refused REFER (RFC 3515 §2.4.2) ends here with its status,
    /// a timeout as 408, a transport failure as 503; the call stays up.
    case transferDone = 12
    /// A call arrived carrying a `Replaces` and took over one already up.
    /// `payload.call.other` is the one being replaced.
    case callReplaced = 13
    /// The call is over; its handle is stale from here on. `message` is
    /// the refusal, or the far end's BYE or CANCEL, or null.
    case callEnded = 14
    /// A1. A subscription moved: asked for, granted, on probation,
    /// retrying, or ended. `payload.subscription` says which and where it
    /// is, `reason` why it is not live. Not sent per refresh or per NOTIFY.
    case subscriptionChanged = 15
    /// A6. What one call's media cost, once, after
    /// `SIPRAL_EVENT_KIND_CALL_ENDED`. `payload.media.statistics` points
    /// at the record, library-owned and valid for the callback.
    case mediaStatistics = 17
    /// B1. A request grew too large for a datagram (RFC 3261 §18.1.1) and
    /// no stream transport is open to its destination; it was refused with
    /// `SIPRAL_STATUS_NOT_SENT`. `payload.transport_wanted` says where.
    /// Bind with
    /// sipral_stack_transport_bind
    /// and ask again.
    case transportWanted = 18
    /// B5. No media has arrived for longer than the configured threshold.
    /// `payload.media.silent_for_ms` says how long. The call is left up.
    case mediaStalled = 19
    /// C2. A call a push announced never arrived: the device woke and
    /// refreshed, and no INVITE followed. `payload.announce` says which
    /// announcement and how long it was waited for.
    case announcedCallMissing = 20
    /// A4, D5. Audio is running; `payload.media.codec` is the agreed codec.
    /// Mint the media handle now with `sipral_call_media`.
    case mediaStarted = 21
    /// The session changed under a live call: a hold, a resume, a peer that
    /// moved its media address, or a re-negotiation onto another codec.
    case mediaChanged = 22
    /// Packets are arriving again. `payload.media.silent_for_ms` says how long
    /// the gap turned out to be.
    case mediaResumed = 23
    /// Media could not be started or could not be kept. The call itself is
    /// untouched; `payload.media.fault` and `payload.media.reason` say why.
    case mediaFailed = 24
    /// A recording stopped on its own (disk full, file gone).
    /// `payload.media.recorded_ms` says how much was written.
    case recordingStopped = 25
    /// The far end pressed a key (RFC 4733 event, or INFO with
    /// `application/dtmf-relay` or `application/dtmf`), one per press.
    /// `payload.media` gives `digit`, `event_code`, `held_ms` and `source`.
    /// `held_ms` zero means no duration or `Duration=0`, not told apart.
    case digitReceived = 26
    /// An INFO from `sipral_call_send_dtmf` got a final answer:
    /// `payload.call.digit` and `payload.call.status_code` (415: try the
    /// other INFO form). An unsendable queued digit reports 503 and stops
    /// the rest.
    case dtmfSent = 27
    /// The lifecycle ladder settled: a path proved again, or every rung
    /// failed. `payload.recovery` says which (`docs/16-lifecycle.md`).
    case recovery = 28
    /// A dialog's next hop is a name to resolve (RFC 3263 §4 TARGET).
    /// Answer with
    /// sipral_stack_resolved
    /// and `payload.resolve.dialog`. **Ignoring it is fine**: the dialog
    /// keeps its first flow (§8.1.2), which survives a NAT.
    case resolveNeeded = 29
    /// A1. A notification arrived and was answered; the NOTIFY is in
    /// `message`. `payload.subscription.has_dialog_info` says the body was
    /// readable dialog-info, read via
    /// sipral_subscription_dialog_count.
    /// An unreadable body arrives with it zero; the old picture is kept.
    case notified = 30
    /// C2. The INVITE for a call a push announced arrived (RFC 8599),
    /// queued just before its SipralEventKind.incomingCall.
    /// `payload.announce.announcement` is now spent:
    /// `sipral_announcement_forget` answers `SIPRAL_STATUS_WRONG_STATE`.
    case callAnnounced = 31
    /// The DTLS-SRTP handshake finished and audio can move (RFC 5764).
    /// `payload.media.suite` is the chosen transform. SDES calls never
    /// raise it; a failed handshake raises `SIPRAL_EVENT_KIND_MEDIA_FAILED`
    /// and leaves the call up.
    case mediaSecured = 32
    /// ICE chose this call's media path (RFC 8445 §8.1.1), and audio can
    /// move; again if a higher-priority pair replaces it. Addresses are not
    /// carried: each outgoing packet names its destination. Never raised
    /// without ICE (default `SIPRAL_ICE_OFF`).
    case mediaPathChosen = 33
    /// A MESSAGE arrived (RFC 3428 §7) and was answered 200.
    /// `payload.message` carries the body; `call` is set if it was in-dialog.
    case messageReceived = 34
    /// A MESSAGE from `sipral_account_message` got its final answer:
    /// `payload.message.status_code` (408/503 for timeout or transport).
    case messageSent = 35
    /// A `message-summary` NOTIFY reported a mailbox (RFC 3842 §3.9);
    /// `payload.message` has the `voice-message` counts.
    case messagesWaiting = 36
    /// The RFC 6035 quality report PUBLISH was attempted once, after
    /// `SIPRAL_EVENT_KIND_CALL_ENDED`, if `quality_report_uri` was set.
    /// `payload.media.quality_report_sent` says it left, not that it landed.
    case qualityReportSent = 37
    /// The call this one was joined to ended. `call` is the survivor and
    /// carries on unjoined, fed directly rather than by `sipral_media_mix`.
    case mediaUnjoined = 38
    /// A STUN server reported, moved or never answered for a socket
    /// (RFC 8489). Only with `SIPRAL_NAT_STUN`. `payload.nat` says which.
    /// Signalling sockets are already re-registered; a media socket from
    /// `sipral_stack_nat_map` is now usable for calls (before, that is
    /// `SIPRAL_STATUS_WRONG_STATE`). `account`, `call`: none.
    case natMapping = 39
    /// A TURN server allocated a relay for a `sipral_stack_nat_map` socket,
    /// or gave none (RFC 8656). Only with a `turn_server`. `payload.relay`
    /// says which; once allocated, calls may use it (before, that is
    /// `SIPRAL_STATUS_WRONG_STATE`). `account`, `call`: none.
    case natRelay = 40
    /// An out-of-dialog REFER asks this end to place a call (RFC 3515),
    /// with `sipral_stack_config_t::referrals` on. `call` is the referral's
    /// handle, taken only by `sipral_call_accept_transfer` (202, places the
    /// call) or `sipral_call_reject_transfer`; either spends it. `account`
    /// is the line, `message` the REFER, `payload.referral` the target.
    /// **The application decides each time**: `referred_by` is unverified.
    /// If left unanswered, raised again with only `status_code` set, and
    /// the handle is stale.
    case referral = 41
    /// A media socket's TCP/TLS connection to a TURN server
    /// (`turn_transport`, RFC 8656 §3.1) is to be opened or closed.
    /// `payload.turn_stream` says which. On `SIPRAL_TURN_STREAM_OPEN`, open
    /// it (TLS checked against the server name), then call
    /// `sipral_stack_turn_connected`, `sipral_stack_turn_receive` and
    /// `sipral_stack_turn_closed`. On `SIPRAL_TURN_STREAM_CLOSE`, flush and
    /// close. `account`, `call`: none.
    case turnStream = 42
    /// The audio engine's devices moved (with `SIPRAL_AUDIO_DEVICE`).
    /// `payload.audio` says what and whether the system or the engine did
    /// it. `account`, `call`: none.
    case audioDevicesChanged = 43
    /// The network changed and this call's media address is gone. Raised
    /// per call by `sipral_stack_network_changed` on
    /// `SIPRAL_RECOVERY_REBUILD`: after `sipral_account_rebind`, pass a new
    /// socket address to `sipral_call_media_readdress`.
    case callAddressWanted = 45
    /// The STUN server in use changed, or all failed
    /// (`payload.stun_server`). A server fails after 5.5 s and is skipped
    /// for 30 s, doubling up to ten minutes. Sockets move on by themselves.
    /// `account`, `call`: none.
    case stunServer = 46
    /// Caller verification (RFC 8224, RFC 8588); `payload.verification`.
    /// `CERTIFICATE_WANTED`: fetch `certificate_url` and pass it (or
    /// nothing) to `sipral_call_stir_certificate`; the call waits.
    /// `VERIFIED`: the verdict, just before the call's
    /// `SIPRAL_EVENT_KIND_INCOMING_CALL`, or with `refused` set before its
    /// `SIPRAL_EVENT_KIND_CALL_ENDED`. `message` is the INVITE.
    case callerVerification = 47
    /// A keypad digit heard as tones (with DTMF detection enabled), once
    /// per press. A press also sent as a named event is reported once as
    /// `SIPRAL_EVENT_KIND_DIGIT_RECEIVED`; tones alone wait 250 ms.
    case inBandDigit = 48
    /// What `sipral_call_detect_progress` heard: a progress tone, the
    /// special information tone, who answered, or a machine's beep
    /// (`payload.progress`).
    case progressDetected = 49
    /// A `conference` subscription's picture changed or the conference
    /// ended (RFC 4575 §4.6); `payload.conference`. Read the picture with
    /// `sipral_subscription_conference`. Out-of-order documents raise
    /// nothing; after a loss the stack asks for full state.
    case conferenceChanged = 50
    /// Real-time text from the far end (RFC 4103), in order, UTF-8 in
    /// `payload.text`: BACKSPACE erases, U+2028 is a new line, BELL alerts,
    /// U+FFFD marks each unrecovered lost block (§5.3), counted in `missing`.
    case textReceived = 51
    /// Presence moved: a `presence` subscription's PIDF (RFC 3856), or this
    /// account's publication (RFC 3903). `payload.presence.kind` says
    /// which.
    case presenceChanged = 52
    /// A signalling transport stopped: reported failed or closed, bad
    /// stream bytes, or a keep-alive unanswered for ten seconds (RFC 5626
    /// §4.4.1). `payload.transport_failed` says why. Until
    /// `sipral_stack_transport_bind` restores it, requests get
    /// `SIPRAL_STATUS_TRANSPORT_DOWN`. `account`, `call`: none.
    case transportFailed = 53
    /// A local conference changed: membership, talkers, or recording
    /// (`payload.local_conference`). `account`, `call`: none.
    case localConferenceChanged = 54
    /// A DNS lookup is wanted to locate an account's server (RFC 3263).
    /// Pass every answer, failures included, to `sipral_account_looked_up`.
    case lookupWanted = 55
    /// An account's server was located: `payload.locate.targets`, the
    /// address in use first.
    case located = 56
    /// Locating an account's server failed; `retry_in_ms` says when it
    /// retries. An earlier address stays in use.
    case locateFailed = 57
    /// A challenge was not answered because it came from outside the
    /// account's protection domain (RFC 3261 §22.1): an answer would feed
    /// an offline password guess. `payload.challenge` says who and why.
    case challengeDeclined = 58
    /// The account's server wants an OAuth 2.0 token (RFC 8898) and has
    /// none acceptable. Check `payload.token.authz_server` against trusted
    /// servers (§2.1.1), then pass a token to
    /// `sipral_account_set_access_token`.
    case tokenRequired = 59
    /// A `sipral_stack_network_test` finished; `payload.network_test`.
    case networkTest = 60
}

/// Where a registration is. Names for `sipral_registration_event_t::state`.
public enum SipralRegistrationState: UInt32, Sendable {
    /// The account is gone, or has never been asked about.
    case unknown = 0
    /// Configured and not registered. Nothing has been sent.
    case idle = 1
    /// A REGISTER is in flight and there is no binding yet.
    case registering = 2
    /// The registrar holds a binding.
    case registered = 3
    /// A refresh is in flight. The binding stands until it is answered.
    case refreshing = 4
    /// Something recoverable went wrong and the next attempt is scheduled.
    case retrying = 5
    /// The binding was given up on purpose.
    case unregistered = 6
    /// The registrar refused in a way that trying again cannot fix.
    case failed = 7
    /// A binding a registrar granted, over a transport since suspended or
    /// lost, which nothing has proved since.
    ///
    /// A monotonic clock does not advance while a machine sleeps, so after
    /// sleep every binding would otherwise look valid. Do not show the line
    /// as ready in this state.
    case unverified = 8
    /// A binding read back from a snapshot rather than granted in this
    /// process. It has not been proved either.
    case restored = 9
    /// The account has no registrar and never registers (a trunk that
    /// knows this end by address). `sipral_account_register` refuses it.
    case notRegistering = 10
}

/// Why a registration is not live. Names for
/// `sipral_registration_event_t::failure`.
public enum SipralRegistrationFailure: UInt32, Sendable {
    /// Nothing failed.
    case none = 0
    /// The registrar refused, and will refuse the same request again.
    case rejected = 1
    /// The password was wrong, or there was none to answer with.
    case badCredentials = 2
    /// The registrar is not answering, or says it cannot serve this now.
    case unreachable = 3
    /// The registrar moved. Following it needs an address, which is the
    /// caller's to resolve.
    case redirected = 4
    /// The account's `Contact` is unreachable for the registrar (loopback
    /// or unspecified); nothing was sent. Fix with `sipral_account_rebind`.
    case unreachableContact = 5
}

/// Where a call is. Names for `sipral_call_event_t::state`, and what
/// `sipral_call_state` writes.
public enum SipralCallState: UInt32, Sendable {
    /// The call is gone, or has never been asked about.
    case unknown = 0
    /// The INVITE has gone and nothing has come back.
    case calling = 1
    /// Somebody is calling and this end has not answered.
    case incoming = 2
    /// The far end is ringing, or this end said it is.
    case ringing = 3
    /// There is audio before anybody answered.
    case earlyMedia = 4
    /// Up.
    case confirmed = 5
    /// Up, in order to be transferred: the second leg of an attended transfer.
    case consulting = 6
    /// A CANCEL or a BYE has gone and is not answered yet.
    case terminating = 7
    /// Over.
    case terminated = 8
}

/// Why a call is over. Names for `sipral_call_event_t::end_reason`.
public enum SipralCallEndReason: UInt32, Sendable {
    /// The call is not over.
    case none = 0
    /// This end hung up.
    case localHangup = 1
    /// The far end hung up.
    case remoteHangup = 2
    /// The far end refused it: busy, declined, not found.
    case refused = 3
    /// Given up before it was answered, from either end.
    case cancelled = 4
    /// Nothing came back, or the transport died.
    case unreachable = 5
    /// Another branch of the same fork was kept and this one was not.
    case forkLost = 6
    /// The branch was still ringing when the answer window closed.
    case abandoned = 7
    /// The session timer ran out and no refresh arrived.
    case expired = 8
}

/// Which way a digit arrived. Names for `sipral_media_event_t::source`.
public enum SipralDigitSource: UInt32, Sendable {
    /// RFC 4733: a named telephone event in the RTP stream.
    case rtp = 0
    /// RFC 3261's INFO method (RFC 6086), carrying `application/dtmf-relay`
    /// or `application/dtmf`.
    case info = 1
    /// The two tones themselves, heard in the far end's audio, for
    /// SipralEventKind.inBandDigit.
    case inBand = 2
}

/// What a SipralEventKind.recovery reports, for
/// `payload.recovery.state`.
public enum SipralRecoveryOutcome: UInt32, Sendable {
    /// Never written by this build.
    case unknown = 0
    /// A registrar answered again: what was distrusted is proved.
    case running = 1
    /// Every rung was climbed and none of them worked.
    case gaveUp = 2
}

/// The last rung tried before giving up, for `payload.recovery.rung`.
public enum SipralRecoveryRung: UInt32, Sendable {
    /// The ladder did not give up.
    case none = 0
    /// Nothing was believed any more, and nothing was sent.
    case distrust = 1
    /// A REGISTER, and a re-SUBSCRIBE for what was demoted alongside it,
    /// went out or could not.
    case reregister = 2
    /// The application was asked for a transport.
    case wantTransport = 3
    /// The application was asked for an address.
    case wantAddress = 4
}

/// Why a recovery ladder gave up, for SipralEventKind.recovery's
/// `payload.recovery.reason`.
public enum SipralRecoveryFailure: UInt32, Sendable {
    /// The ladder did not give up.
    case none = 0
    /// Every REGISTER that could be sent was sent and none of them was
    /// answered.
    case unreachable = 1
    /// A transport was asked for and the application did not bind one.
    case noTransport = 2
    /// An address was asked for and the application did not supply one.
    case unresolved = 3
}

/// What kind of link the application is on: `from_link` and `to_link` on
/// sipral_stack_network_changed.
///
/// Only SipralLink.down changes what is done. The rest makes a change
/// of kind over an unchanged address (a tunnel, Wi-Fi to cellular) visible.
public enum SipralLink: UInt32, Sendable {
    /// There is no usable interface.
    case down = 0
    /// Cable.
    case wired = 1
    /// Wireless local network.
    case wifi = 2
    /// A mobile network.
    case cellular = 3
    /// A tunnel over one of the others.
    case tunnel = 4
}

/// What a change of network is worth doing about:
/// sipral_stack_network_changed's `out_recovery`. Returned directly, so
/// a laptop flipping access points gets SipralRecovery.nothing without
/// reading an event or sending a REGISTER.
public enum SipralRecovery: UInt32, Sendable {
    /// Never written by this build.
    case unknown = 0
    /// Nothing this stack uses is different; nothing is done or sent.
    case nothing = 1
    /// The address stands, so the transports do; what is upstream may not.
    case reregister = 2
    /// A wake: the existing transport is tried first, a new one asked for
    /// only if it is dead. Started by sipral_stack_resumed, never
    /// returned here.
    case reprove = 3
    /// The address is gone; the application must open a transport again.
    case rebuild = 4
    /// Packets can leave and names cannot be turned into addresses.
    case resolve = 5
    /// There is no interface. Nothing is tried until there is one.
    case detach = 6
}

/// What a stack does about a NAT in front of it. Names for
/// `sipral_stack_config_t::nat`. Zero means the built-in default, SipralNat.off.
public enum SipralNat: UInt32, Sendable {
    /// Ask nobody: every address written is the one the application gave.
    case off = 1
    /// Ask `stun_server` where each socket appears from and write that instead.
    /// `SIPRAL_STATUS_NOT_SUPPORTED` without `SIPRAL_FEATURE_STUN`.
    case stun = 2
}

/// What a socket's mapping came to. Names for `sipral_nat_event_t::mapping`.
public enum SipralNatMapping: UInt32, Sendable {
    /// The first answer: the socket appears at `public`.
    case learned = 1
    /// A later answer named another address; `previous` is the old one. Signalling socket, or a
    /// media socket still waiting for its call.
    case moved = 2
    /// No answer within five and a half seconds, or refused. The socket is described by its own
    /// address; a signalling socket asks again at its next refresh.
    case unanswered = 3
}

/// What a media socket's relay came to. Names for `sipral_nat_relay_event_t::outcome`.
public enum SipralNatRelay: UInt32, Sendable {
    /// The relay exists at `relayed`; later calls on the socket offer it as an ICE candidate.
    case allocated = 1
    /// No relay: refused (see `code`), no answer in 39.5 seconds, or allocation lost. Calls on
    /// the socket go without one.
    case failed = 2
}

/// What to do with a media socket's TURN connection. Names for
/// `sipral_turn_stream_event_t::state`.
public enum SipralTurnStream: UInt32, Sendable {
    /// Open a connection from `local` to `server` over `protocol` (TLS verified by the
    /// platform), then call `sipral_stack_turn_connected`, or `sipral_stack_turn_closed` on failure. Calls
    /// on the socket before that answer `SIPRAL_STATUS_WRONG_STATE`.
    case open = 1
    /// Nothing more will be written for `local`: flush `sipral_stack_poll_farewell` and
    /// `sipral_stack_poll_stun` for it, then close it.
    case close = 2
}

/// What happened to the STUN servers. Names for `sipral_stun_server_event_t::state`.
public enum SipralStunServerState: UInt32, Sendable {
    /// Another server is in use now: failover, an earlier one answering again, or a new list.
    case changed = 1
    /// Every server failed and is backing off; `server` is the last. Sockets keep what they
    /// learned. Said once until a server answers again.
    case allFailed = 2
}

/// Where a subscription is: `sipral_subscription_event_t::state` and
/// sipral_subscription_state's `out_state`.
public enum SipralSubscriptionState: UInt32, Sendable {
    /// The handle names nothing: never minted here, or ended and let go.
    case unknown = 0
    /// A SUBSCRIBE is on its way and nothing has answered it yet.
    case requesting = 1
    /// The notifier has not decided (RFC 6665 §4.1.3 `pending`); nothing
    /// is known until SipralSubscriptionState.active.
    case pending = 2
    /// Granted, and notifications are arriving.
    case active = 3
    /// Not live, and a fresh attempt is scheduled (§4.1.2.2: new
    /// `Call-ID` and `From` tag). The handle stays valid across both.
    case retrying = 4
    /// Over, nothing more coming. The handle names nothing from here on.
    case ended = 5
}

/// Why a subscription is not live: `sipral_subscription_event_t::reason`.
///
/// Zero unless SipralSubscriptionState.retrying or
/// SipralSubscriptionState.ended. The first eight are the `reason` of
/// `Subscription-State: terminated` (RFC 6665 §4.1.3); the rest happened
/// here.
public enum SipralSubscriptionEnd: UInt32, Sendable {
    /// Never written by this build.
    case unknown = 0
    /// `deactivated`: the notifier wants it started again at once.
    case deactivated = 1
    /// `probation`: started again, but not immediately.
    case probation = 2
    /// `rejected`: the notifier will not serve it; do not ask again.
    case rejected = 3
    /// `timeout`: it ran out rather than being refreshed.
    case timeout = 4
    /// `giveup`: the notifier could not decide and stopped trying.
    case gaveUp = 5
    /// `noresource`: what was being watched does not exist any more.
    case noResource = 6
    /// `invariant`: the watched thing cannot change.
    case invariant = 7
    /// `terminated` with no reason parameter at all.
    case unstated = 8
    /// This end gave it up with sipral_subscription_end. Wins over
    /// the notifier's closing reason.
    case unsubscribed = 9
    /// The notifier answered 489: it does not know this event package.
    case badEvent = 10
    /// Refused with a status a retry cannot fix.
    case refused = 11
    /// Redirected; this stack does not follow redirects for SUBSCRIBE.
    case redirected = 12
    /// Nothing answered: the notifier could not be reached at all.
    case unreachable = 13
    /// Answered, but the first NOTIFY never came (§4.1.2.4's timer N,
    /// 64·T1).
    case noNotify = 14
    /// What the notifier granted ran out with no refresh answered.
    case expired = 15
}

/// What one watched dialog is doing, and what a lamp shows:
/// `sipral_watched_dialog_t::phase` and sipral_subscription_lamp's
/// `out_phase`. RFC 4235 §3.7.1's states, ranked as §3.7.2 ranks them.
public enum SipralDialogPhase: UInt32, Sendable {
    /// No dialog, or all terminated: an idle lamp.
    case idle = 0
    /// A request went out and nothing has answered.
    case trying = 1
    /// Something answered without ringing yet.
    case proceeding = 2
    /// Ringing.
    case early = 3
    /// A call is up.
    case confirmed = 4
    /// This dialog is over. Never sipral_subscription_lamp's answer,
    /// which is SipralDialogPhase.idle then.
    case terminated = 5
    /// The notifier named a state this build has no number for.
    case unknown = 6
}

/// Which end started a watched dialog: `sipral_watched_dialog_t::direction`.
public enum SipralDialogDirection: UInt32, Sendable {
    /// The notifier did not say.
    case unknown = 0
    /// The watched end placed the call.
    case locally = 1
    /// The watched end was called.
    case remotely = 2
}

/// How a watched dialog ended: `sipral_watched_dialog_t::ended`, zero
/// while it has not.
public enum SipralDialogEnded: UInt32, Sendable {
    /// It has not ended, or the notifier did not say how.
    case unknown = 0
    /// The caller gave up before it was answered.
    case cancelled = 1
    /// The called end refused it.
    case rejected = 2
    /// A `Replaces` took it over.
    case replaced = 3
    /// The watched end hung up.
    case localBye = 4
    /// The far end hung up.
    case remoteBye = 5
    /// Something went wrong with it.
    case error = 6
    /// Nothing answered in time.
    case timeout = 7
}

/// Which text sipral_subscription_dialog_text reads. Each is what the
/// notifier wrote, unparsed.
public enum SipralDialogText: UInt32, Sendable {
    /// Never asked for.
    case unknown = 0
    /// The notifier's own id for this dialog.
    case id = 1
    /// The dialog's `Call-ID`, when the notifier sent one.
    case callId = 2
    /// Who the watched end is, as a URI.
    case localIdentity = 3
    /// And the display name beside it.
    case localDisplay = 4
    /// Who the other end is, as a URI: what a lamp shows when ringing.
    case remoteIdentity = 5
    /// And the display name beside it.
    case remoteDisplay = 6
    /// Where requests for the watched end would be sent.
    case localTarget = 7
    /// And for the other end.
    case remoteTarget = 8
}

/// Who pumps a stack's audio: `sipral_stack_config_t::audio`.
///
/// Zero is application mode, so a configuration written against an
/// earlier header keeps pumping its own frames.
public enum SipralAudio: UInt32, Sendable {
    /// The application opens the devices and pumps frames through
    /// `sipral_media_capture` and `sipral_media_playback`.
    case application = 0
    /// The library opens the devices and pumps every managed call; the
    /// packets reach the application through `audio_transmit_callback`.
    /// `SIPRAL_STATUS_NOT_SUPPORTED` without a backend for the platform,
    /// as `SIPRAL_FEATURE_AUDIO_DEVICE` says.
    case device = 1
}

/// When the devices are opened, in device mode:
/// `sipral_stack_config_t::audio_activation`.
public enum SipralAudioActivation: UInt32, Sendable {
    /// With the first managed call's media or ring; closed with the last.
    case automatic = 0
    /// Only between `sipral_audio_activate` and `sipral_audio_deactivate`:
    /// for CallKit and the telecom framework, which own the audio session.
    case manual = 1
}

/// What a device is used for.
public enum SipralAudioRole: UInt32, Sendable {
    /// The call's microphone.
    case microphone = 1
    /// The call's loudspeaker or earpiece.
    case speaker = 2
    /// Where an incoming call is announced, which may differ from where
    /// it is answered.
    case ringer = 3
}

/// Which way audio flows, for gain, mute and the meter.
public enum SipralAudioDirection: UInt32, Sendable {
    /// From the microphone. Its gain is the microphone gain.
    case input = 1
    /// To the loudspeaker. Its gain is the volume.
    case output = 2
}

/// What changed, on `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED`.
public enum SipralAudioChange: UInt32, Sendable {
    /// A device arrived or left. Every valid id stays valid: a device
    /// that left keeps its row, marked absent.
    case listChanged = 1
    /// The system's default for `direction` moved. A role on a chosen
    /// device stays; one on the system's route follows with
    /// `SIPRAL_AUDIO_CHANGE_REOPENED`.
    case defaultChanged = 2
    /// `role` is on `device` because `sipral_audio_select` said so.
    case selected = 3
    /// The device `role` ran on went away; the reopen is reported apart.
    case lost = 4
    /// `role` is running on `device` again.
    case reopened = 5
    /// `role` could not be opened on anything; that direction is
    /// silence until a device arrives.
    case unavailable = 6
}

/// Who made a change. An application must not answer either by
/// re-applying its own choice.
public enum SipralAudioOrigin: UInt32, Sendable {
    /// The operating system, or a person at a socket.
    case system = 1
    /// The engine.
    case engine = 2
}

/// The verdict a terminating network reached on the caller's number
/// (3GPP TS 24.229's `verstat`, the mark STIR/SHAKEN leaves). Names for
/// `sipral_call_event_t::verstat`.
public enum SipralVerstat: UInt32, Sendable {
    /// Nothing said, or said by a peer the account does not trust.
    case none = 0
    /// `TN-Validation-Passed`.
    case passed = 1
    /// `TN-Validation-Failed`.
    case failed = 2
    /// `No-TN-Validation`.
    case notValidated = 3
    /// Some other value.
    case other = 4
}

/// `Answer-Mode` and `Priv-Answer-Mode` (RFC 5373 §3). Names for
/// `sipral_call_event_t::answer_mode` and `priv_answer_mode`.
public enum SipralAnswerMode: UInt32, Sendable {
    /// The INVITE carried no such field.
    case none = 0
    /// `Manual`: wait for the user.
    case manual = 1
    /// `Auto`: answer without waiting for the user.
    case auto = 2
    /// Any other value, which RFC 5373 has ignored.
    case other = 3
}

/// Where the ring says the caller is. Names for
/// `sipral_call_event_t::ring_source`.
public enum SipralRingSource: UInt32, Sendable {
    /// Nothing said.
    case unknown = 0
    /// Another extension of the same switch.
    case `internal` = 1
    /// The outside world.
    case external = 2
}

/// Which list, and which piece of each entry, sipral_call_identity_count
/// and sipral_call_identity_text are asked about.
public enum SipralIdentityText: UInt32, Sendable {
    /// Never asked for.
    case unknown = 0
    /// `P-Asserted-Identity`: the URI of each asserted party.
    case asserted = 1
    /// And each one's display name.
    case assertedDisplay = 2
    /// `Remote-Party-ID`: the URI of each party named.
    case remoteParty = 3
    /// And each one's display name.
    case remotePartyDisplay = 4
    /// `Diversion`, most recent first: who the call was diverted from.
    case diversion = 5
    /// And the display name beside it.
    case diversionDisplay = 6
    /// And why: `no-answer`, `user-busy`, `unconditional` and the rest.
    case diversionReason = 7
    /// `History-Info`: the URI of each target the request was sent to.
    case history = 8
    /// And each entry's `index`.
    case historyIndex = 9
    /// Every `Alert-Info` URI.
    case alertInfo = 10
    /// Every `info=` value on `Alert-Info`.
    case alertName = 11
    /// The canonical calling number a valid PASSporT was found for
    /// (RFC 8224 §6.2): one entry, or none. ABI 0.31.
    case verifiedOrig = 12
    /// Its origination identifier (RFC 8588 §5), a UUID.
    case verifiedOrigid = 13
    /// The URL of the certificate it was verified against, or that could
    /// not be had.
    case verificationCertificate = 14
    /// Why it did not verify, in words, for a log.
    case verificationDetail = 15
}

/// How an account's calls ask for a session timer (RFC 4028). Names for
/// `sipral_account_config_t::session_timer`.
public enum SipralSessionTimer: UInt32, Sendable {
    /// The stack's default: thirty minutes, RFC 4028 §4's recommendation.
    case `default` = 0
    /// Ask for none. A far end that insists on one is still honoured.
    case off = 1
    /// Ask for `session_interval_seconds`, at least 90 (§5's floor).
    case interval = 2
}

/// Log verbosity, for sipral_stack_log and sipral_log_record_t.level.
/// Each level includes the ones below it.
public enum SipralLogLevel: UInt32, Sendable {
    /// The log is off; the initial state.
    case off = 0
    /// A failure the application is likely to notice.
    case error = 1
    /// Something worked around or about to matter: a registration
    /// refused, audio that stopped arriving.
    case warn = 2
    /// Operator-level: registrations, calls arriving, confirmed or ending,
    /// media starting.
    case info = 3
    /// Every event raised, every diagnostic decision, every refused ABI call.
    case debug = 4
    /// Every SIP message in and out, whole and redacted.
    case trace = 5
}

/// How a stream's SRTP keys were exchanged
/// (`sipral_stream_encryption_t::key_exchange`, `sipral_media_event_t::key_exchange`).
public enum SipralKeyExchange: UInt32, Sendable {
    /// None: the stream is not encrypted, or the event is not about one.
    case none = 0
    /// In the SDP (RFC 4568 `a=crypto`): as protected as the signalling.
    case sdes = 1
    /// DTLS on the media path (RFC 5764), checked against the signalled
    /// fingerprint.
    case dtls = 2
}

/// What a stream carries. Names for `sipral_stream_encryption_t::media`.
public enum SipralMediaKind: UInt32, Sendable {
    /// Something this ABI has no word for.
    case unknown = 0
    /// `m=audio`.
    case audio = 1
}

/// What an account does with incoming `Identity` header fields
/// (RFC 8224 §6.2). Values of `sipral_account_config_t::stir_verification`.
public enum SipralStirVerification: UInt32, Sendable {
    /// This build's default, which is `REPORT`.
    case `default` = 0
    /// Verify nothing.
    case off = 1
    /// Verify, report the verdict, deliver every call. Active only once
    /// the stack has trust anchors (`sipral_stack_stir`).
    case report = 2
    /// Verify and refuse what does not verify (RFC 8224 §6.2.2): 428 no
    /// `Identity`, 436 certificate unavailable, 437 untrusted, 438 bad
    /// signature, 403 "Stale Date". Active even with no anchors, where
    /// nothing verifies.
    case strict = 3
}

/// SHAKEN attestation level (RFC 8588 §4), for
/// `sipral_account_config_t::stir_attestation` and the verdict fields.
public enum SipralAttestation: UInt32, Sendable {
    /// None said: on an account, full attestation; on a verdict, a
    /// PASSporT with no SHAKEN claims, or no valid one.
    case none = 0
    /// Full: the signer knows the caller and that the number is theirs.
    case a = 1
    /// Partial: the signer knows the caller, not the number.
    case b = 2
    /// Gateway: the signer knows only where the call entered its network.
    case c = 3
}

/// What a verification came to (`sipral_verification_event_t::outcome`,
/// `sipral_call_event_t::verification`).
public enum SipralVerificationOutcome: UInt32, Sendable {
    /// Nothing verified: the account does not verify, or no anchors.
    case none = 0
    /// Signed by a certificate with authority over the calling number,
    /// fresh, for the numbers the request names.
    case valid = 1
    /// One was there and does not hold: `failure` says why.
    case invalid = 2
    /// Nothing to verify: no `Identity`, or only unsupported extensions.
    case absent = 3
}

/// Why a verification did not hold (`sipral_verification_event_t::failure`,
/// `sipral_call_event_t::verification_failure`).
public enum SipralVerificationFailure: UInt32, Sendable {
    /// Nothing failed.
    case none = 0
    /// No `Identity` header field.
    case noIdentity = 1
    /// Only ones naming a `ppt` this end does not support.
    case unsupportedPpt = 2
    /// The header field or its PASSporT is not well formed.
    case malformed = 3
    /// Signed with an algorithm other than ES256.
    case unsupportedAlgorithm = 4
    /// `iat` outside the freshness window.
    case stale = 5
    /// The certificate could not be fetched, or did not arrive in time.
    case certificateUnavailable = 6
    /// What the `info` URL yielded is not a chain this end can read.
    case certificateUnreadable = 7
    /// The chain leads to no trust anchor.
    case untrusted = 8
    /// A certificate in it is outside its validity period.
    case expired = 9
    /// The chain breaks a rule of path validation.
    case invalidChain = 10
    /// The signature does not verify.
    case badSignature = 11
    /// The certificate has no authority over the calling number.
    case numberNotCovered = 12
    /// Signed for another calling number than the request names.
    case origMismatch = 13
    /// Signed for another called number.
    case destMismatch = 14
}

/// Which half of a verification an event reports
/// (`sipral_verification_event_t::stage`).
public enum SipralVerificationStage: UInt32, Sendable {
    /// Never sent.
    case unknown = 0
    /// Fetch the certificate at `certificate_url` and pass it to
    /// `sipral_call_stir_certificate` (or nothing, if unavailable). The
    /// call waits unannounced until then or `certificate_wait_ms`.
    case certificateWanted = 1
    /// The verdict. `SIPRAL_EVENT_KIND_INCOMING_CALL` follows, or
    /// `SIPRAL_EVENT_KIND_CALL_ENDED` when `refused` is set.
    case verified = 2
}

/// What a SipralEventKind.progressDetected heard. Names for
/// `sipral_progress_event_t::what`.
public enum SipralProgressKind: UInt32, Sendable {
    /// Never written by this build.
    case unknown = 0
    /// A call-progress tone: `tone`, and `at_ms` when its first burst began.
    case tone = 1
    /// The special information tone (the call failed): `sit_hz_*` and
    /// `sit_ms_*` as measured, `at_ms` when the first began.
    case specialInformation = 2
    /// Who answered: `verdict`, `reason`, `at_ms` after answer,
    /// `initial_silence_ms`, `greeting_ms` and `words`.
    case answeredBy = 3
    /// A machine's record beep: `frequency_hz`, `length_ms`, and `at_ms`
    /// when it ended, after answer.
    case beep = 4
}

/// A call-progress tone. Names for `sipral_progress_event_t::tone`.
public enum SipralProgressTone: UInt32, Sendable {
    /// Not a tone, or one this build has no name for.
    case unknown = 0
    /// The exchange is ready for digits.
    case dial = 1
    /// The far end is being alerted.
    case ringback = 2
    /// The far end is busy.
    case busy = 3
    /// The network is congested: congestion, or reorder.
    case congestion = 4
    /// A second call is waiting.
    case callWaiting = 5
    /// The special information tone.
    case specialInformation = 6
}

/// Who answered. Names for `sipral_progress_event_t::verdict`.
public enum SipralAmdVerdict: UInt32, Sendable {
    /// Not a verdict.
    case unknown = 0
    /// A person.
    case human = 1
    /// An answering machine or a voice mailbox.
    case machine = 2
    /// The evidence does not say.
    case notSure = 3
}

/// Which rule decided who answered. Names for
/// `sipral_progress_event_t::reason`.
public enum SipralAmdReason: UInt32, Sendable {
    /// Not a verdict.
    case none = 0
    /// A short greeting, then silence: somebody said hello and waits.
    case shortGreeting = 1
    /// More words than a person answers with.
    case tooManyWords = 2
    /// A greeting longer than a person gives.
    case longGreeting = 3
    /// Nobody spoke.
    case initialSilence = 4
    /// No rule decided in the time allowed.
    case timeout = 5
}

/// When a call listens for keypad digits in the far end's audio. Names
/// for `sipral_stack_config_t::dtmf_detection` and
/// sipral_call_dtmf_detection's `mode`.
public enum SipralDtmfDetection: UInt32, Sendable {
    /// Only when no telephone event was negotiated, since the far end
    /// then has no other way to send a digit.
    case auto = 0
    /// Never. Digits arrive only as RFC 4733 events or by INFO.
    case off = 1
    /// On every call. A press the far end sends both as an event and in
    /// the audio is reported once, as the event.
    case always = 2
}

/// Whose call-progress tones to listen for. Names for
/// `sipral_progress_config_t::region`.
public enum SipralToneRegion: UInt32, Sendable {
    /// The 425 Hz tones common to the CEPT administrations.
    case europe = 0
    /// The United States and Canada.
    case northAmerica = 1
    /// The United Kingdom.
    case unitedKingdom = 2
}

/// The file format of a recording. Names for
/// `sipral_recording_options_t::format`.
public enum SipralRecordingFormat: UInt32, Sendable {
    /// Sixteen-bit PCM in RIFF/WAVE, becoming RF64 past four gibibytes.
    case wav = 0
    /// Opus in Ogg (RFC 7845), where `SIPRAL_FEATURE_OPUS` says the build
    /// has the encoder; `SIPRAL_STATUS_NOT_SUPPORTED` where it does not.
    case oggOpus = 1
}

/// How the two directions of a call share a recording. Names for
/// `sipral_recording_options_t::layout`.
public enum SipralRecordingLayout: UInt32, Sendable {
    /// One channel: both directions, each at half level, summed.
    case mixed = 0
    /// Two channels: this end on the left, the far end on the right.
    case stereo = 1
}

/// What one conference document did. Names for
/// `sipral_conference_event_t::update`.
public enum SipralConferenceUpdate: UInt32, Sendable {
    /// Never written by this build.
    case unknown = 0
    /// It was merged into the picture.
    case applied = 1
    /// Deleted by the focus; the subscription ends (RFC 4575 §4.6).
    case ended = 2
}

/// Where one endpoint of a conference is (RFC 4575 §5.7.2). Names for
/// `sipral_conference_user_t::status`.
public enum SipralEndpointStatus: UInt32, Sendable {
    /// Absent or not in the schema.
    case unknown = 0
    /// `pending`: waiting for policy or for the focus.
    case pending = 1
    /// `dialing-out`: the focus is calling it.
    case dialingOut = 2
    /// `dialing-in`: it is calling the focus.
    case dialingIn = 3
    /// `alerting`: it is ringing.
    case alerting = 4
    /// `on-hold`.
    case onHold = 5
    /// `connected`: it is in the conference.
    case connected = 6
    /// `muted-via-focus`: in, and muted by the focus.
    case mutedViaFocus = 7
    /// `disconnecting`.
    case disconnecting = 8
    /// `disconnected`: it has left.
    case disconnected = 9
}

/// Which text sipral_subscription_conference_text reads, as the focus
/// wrote it. The first three ignore `index`; the rest are about that user.
public enum SipralConferenceText: UInt32, Sendable {
    /// Never asked for.
    case unknown = 0
    /// The conference's URI, the `entity` of `conference-info`.
    case entity = 1
    /// Its `subject`.
    case subject = 2
    /// Its `display-text`.
    case displayText = 3
    /// A user's `entity`: the address of record it takes part as.
    case userEntity = 4
    /// A user's `display-text`.
    case userDisplayText = 5
    /// The `entity` of a user's first endpoint: the device it is on.
    case userEndpoint = 6
}

/// What a SipralEventKind.presenceChanged is about.
/// Names for `sipral_presence_event_t::kind`.
public enum SipralPresenceKind: UInt32, Sendable {
    /// Never written by this build.
    case unknown = 0
    /// A `presence` subscription was told about the presentity.
    case watched = 1
    /// This account's own published presence moved.
    case publication = 2
}

/// PIDF's `basic` (RFC 3863 §4.1.4). Names for `sipral_presence_t::basic`
/// and `sipral_presence_event_t::basic`.
public enum SipralBasic: UInt32, Sendable {
    /// Not said. A document published with this is refused, since
    /// §4.1.3 wants one.
    case unknown = 0
    /// Reachable.
    case open = 1
    /// Not reachable.
    case closed = 2
}

/// What the person behind a presentity is doing: the RPID activities
/// (RFC 4480 §3.2) phones show. Names for `sipral_presence_t::activity`
/// and `sipral_presence_event_t::activity`.
public enum SipralActivity: UInt32, Sendable {
    /// None said. Published, the document carries no person at all.
    case none = 0
    /// `away`.
    case away = 1
    /// `busy`.
    case busy = 2
    /// `on-the-phone`.
    case onThePhone = 3
    /// `meeting`.
    case meeting = 4
    /// `vacation`.
    case vacation = 5
    /// Another activity, which this ABI has no number for.
    case other = 6
}

/// What became of this account's published presence. Names for
/// `sipral_presence_event_t::publication_state`.
public enum SipralPublicationState: UInt32, Sendable {
    /// Not a publication event.
    case unknown = 0
    /// The compositor holds it: published, modified or refreshed.
    case published = 1
    /// It was taken away (`sipral_account_unpublish_presence`).
    case removed = 2
    /// Its lifetime ran out with no refresh; the next publish starts it
    /// afresh.
    case expired = 3
    /// The compositor refused, or never answered.
    case failed = 4
}

/// Why a publication failed. Names for `sipral_presence_event_t::failure`.
public enum SipralPublishFailure: UInt32, Sendable {
    /// Nothing failed.
    case none = 0
    /// 489: the compositor does not know the `presence` package. Nothing
    /// more is sent.
    case badEvent = 1
    /// 423 with no `Min-Expires` this stack could meet.
    case intervalTooBrief = 2
    /// A 2xx without the `SIP-ETag` every one must carry.
    case noEntityTag = 3
    /// Any other refusal, a challenge nothing could answer among them;
    /// `status_code` says which.
    case refused = 4
    /// No answer at all.
    case unreachable = 5
}

/// What a `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED` reports
/// (`sipral_local_conference_event_t::change`).
public enum SipralLocalConferenceChange: UInt32, Sendable {
    /// Never written by this build.
    case unknown = 0
    /// `member` joined (a call, or this end at creation).
    case joined = 1
    /// `member` left, for the reason `departure` gives.
    case left = 2
    /// The talkers changed: see `talkers`, `loudest` and
    /// `sipral_local_conference_talker_at`.
    case talkers = 3
    /// The recording stopped because the file refused a write; it holds
    /// audio up to its last checkpoint.
    case recordingStopped = 4
}

/// Why a member left (`sipral_local_conference_event_t::departure`).
public enum SipralDeparture: UInt32, Sendable {
    /// Nobody left.
    case none = 0
    /// `sipral_local_conference_remove` took it out.
    case removed = 1
    /// Its call's media ended.
    case ended = 2
    /// Its call moved to a codec the conference cannot mix.
    case incompatible = 3
}

/// Which kind of DNS record a lookup asks for. Names for
/// `sipral_locate_event_t::record` and `sipral_account_looked_up`'s
/// `record`.
public enum SipralDnsRecordType: UInt32, Sendable {
    /// Not a lookup: the value on a `SIPRAL_EVENT_KIND_LOCATED` or a
    /// `SIPRAL_EVENT_KIND_LOCATE_FAILED`.
    case none = 0
    /// RFC 3403: which services a domain offers, and under which names.
    case naptr = 1
    /// RFC 2782: which hosts, at which ports, serve one service.
    case srv = 2
    /// An IPv4 address.
    case a = 3
    /// An IPv6 address.
    case aaaa = 4
}

/// What the application's resolver said to a lookup. Names for
/// `sipral_account_looked_up`'s `answer`.
public enum SipralDnsAnswer: UInt32, Sendable {
    /// The records it returned, in `records`. None at all reads as
    /// `SIPRAL_DNS_ANSWER_NOTHING`.
    case records = 1
    /// No record of that kind, or no such name. Also the answer from a
    /// resolver that cannot ask for that kind (NAPTR, SRV).
    case nothing = 2
    /// The resolver could not answer: no server reachable, a timeout, a
    /// server failure.
    case failed = 3
}

/// Why a lookup of an account's server named no address. Names for
/// `sipral_locate_event_t::failure`.
public enum SipralLocateFailure: UInt32, Sendable {
    /// Nothing failed.
    case none = 0
    /// The DNS named no reachable address: no record, or an SRV target
    /// of `.`.
    case notFound = 1
    /// The resolver failed on every lookup that could give an address.
    case unanswered = 2
    /// The transport has no RFC 3263 procedure (WebSocket); only a
    /// numeric host or a host with a port works.
    case unsupported = 3
}

/// Why an account's password did not answer a challenge. Names for
/// `sipral_challenge_event_t::refusal`.
public enum SipralChallengeRefusal: UInt32, Sendable {
    /// Never written by this build.
    case unknown = 0
    /// The challenge came from beyond the account's own server.
    case notTheAccountsServer = 1
    /// The account's server asked for a realm not the account's (e.g. a
    /// proxy relaying a far end's challenge).
    case notTheAccountsRealm = 2
}

/// What the server said was wrong with the token (RFC 6750 §3.1).
public enum SipralTokenError: UInt32, Sendable {
    /// The server named no error: no token was offered yet.
    case none = 0
    /// `invalid_request`: the request was malformed.
    case invalidRequest = 1
    /// `invalid_token`: the token is expired, revoked, malformed or
    /// otherwise invalid. A new one is needed.
    case invalidToken = 2
    /// `insufficient_scope`: the token does not cover what was asked;
    /// `scope` says what would.
    case insufficientScope = 3
    /// `invalid_scope`.
    case invalidScope = 4
    /// Another code, as written in `error_code`.
    case other = 5
}

/// What a network test, or one part of it, comes to. Names for
/// `sipral_network_test_event_t::verdict` and `echo_verdict`.
public enum SipralNetworkVerdict: UInt32, Sendable {
    /// Nothing was tested.
    case unknown = 0
    /// Calls should work and sound right.
    case good = 1
    /// Calls should work, perhaps not everywhere or at best quality.
    case acceptable = 2
    /// Calls are likely to fail or to sound bad.
    case poor = 3
}

/// Whether a part of a network test was tried, and how it went. Names
/// for `sipral_network_test_event_t::stun`, `turn` and `echo`.
public enum SipralNetworkProbe: UInt32, Sendable {
    /// Not part of this test.
    case notTested = 0
    /// The server answered; for the echo, audio came back and was measured.
    case succeeded = 1
    /// It did not.
    case failed = 2
}

/// What a STUN answer says about the NAT in front of this end. Names for
/// `sipral_network_test_event_t::nat`. Approximate: says nothing about
/// filtering (RFC 4787).
public enum SipralNatKind: UInt32, Sendable {
    /// No answer to read.
    case unknown = 0
    /// No translation: the server saw the socket's own address.
    case open = 1
    /// The address was translated and the port kept.
    case portPreserved = 2
    /// The port was changed too.
    case portChanged = 3
}

/// What the account's server did with the test's `OPTIONS`. Names for
/// `sipral_network_test_event_t::server`.
public enum SipralServerReach: UInt32, Sendable {
    /// Not part of this test.
    case notTested = 0
    /// Any final answer; see `server_status` and `server_round_trip_ms`.
    case answered = 1
    /// No answer before the request, or the test, timed out.
    case timedOut = 2
    /// The transport refused the request or failed under it.
    case transportFailed = 3
}

/// What a held party is sent: `sipral_stack_config_t::held_audio`.
public enum SipralHeldAudio: UInt32, Sendable {
    /// Silence, in either mode.
    case `default` = 0
    /// Silence.
    case silence = 1
    /// The frames the application hands over, as they are.
    case application = 2
}

/// What a call across the boundary answered, when it did not answer
/// `ok`. The message is the calling thread's last error, read before
/// anything else on this thread could replace it.
public struct SipralError: Error, CustomStringConvertible, Sendable {
    /// The number C would have switched on, whether or not this
    /// binding has a name for it.
    public let code: Int32
    /// Its name, or nil for a status a newer library returned that
    /// this binding was printed too early to know: a failure like
    /// any other, and not one it may be mistaken for.
    public let status: SipralStatus?
    /// The sentence that goes with it.
    public let message: String

    /// An error with a status this binding names.
    public init(status: SipralStatus, message: String) {
        self.init(code: status.rawValue, message: message)
    }

    /// An error with whatever number the library answered.
    public init(code: Int32, message: String) {
        self.code = code
        self.status = SipralStatus(rawValue: code)
        self.message = message
    }

    public var description: String {
        let name = status.map { "\($0)" } ?? "status \(code)"
        return message.isEmpty ? name : "\(name): \(message)"
    }
}

public extension sipral_abi_version_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_capabilities_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_counters_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_stack_config_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_poll_result_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_stack_settings_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_account_config_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_call_config_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_codec_info_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_codec_candidate_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_path_candidate_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_media_info_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_stream_stats_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_media_packet_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_processor_frame_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_transmit_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_transport_failure_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_event_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_suspending_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_screen_request_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_subscribe_config_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_watched_dialog_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_push_echo_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_audio_device_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_audio_info_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_audio_transmit_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_log_record_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_stir_config_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_stream_encryption_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_progress_config_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_consent_tone_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_recording_options_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_conference_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_conference_user_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_presence_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_record_config_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_local_conference_config_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_local_conference_info_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_local_conference_member_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_pinned_certificate_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

public extension sipral_network_test_config_t {
    /// A zeroed one with its size filled in, which is what every
    /// struct here has to be handed over as.
    static func sized() -> Self {
        var value = Self()
        value.size = MemoryLayout<Self>.size
        return value
    }
}

/// One header field an application hands over: a name and a value, UTF-8,
/// neither NUL-terminated.
///
/// No `size` member: it is an array element, so it never grows.
///
/// Built here and handed to C in a list. `withUnsafeArray` copies every
/// piece of text in every element into one buffer, points an array of
/// sipral_header_t into it and hands that array on for as long as one closure
/// runs, with the list's own count. An empty piece of text crosses as a
/// null pointer with a length of zero, and an empty list as a null
/// pointer with a count of zero.
public struct SipralHeader: Sendable {
    /// The field name, `X-Conversation-Id`. A compact form is the field it
    /// abbreviates.
    public var name: String
    /// The value, as it goes on the line after the colon. Null or empty
    /// for a field with an empty value.
    public var value: String

    public init(name: String, value: String) {
        self.name = name
        self.value = value
    }

    /// A list of them as the array of sipral_header_t C reads, for as long as
    /// `body` runs and no longer: every pointer in it points into a buffer
    /// that is gone when `body` returns.
    static func withUnsafeArray<Answer>(_ list: [SipralHeader], _ body: (UnsafeBufferPointer<sipral_header_t>) throws -> Answer) rethrows -> Answer {
        var run: [CChar] = []
        var lengths: [Int] = []
        for element in list {
            let nameBytes = element.name.utf8.map { CChar(bitPattern: $0) }
            run.append(contentsOf: nameBytes)
            lengths.append(nameBytes.count)
            let valueBytes = element.value.utf8.map { CChar(bitPattern: $0) }
            run.append(contentsOf: valueBytes)
            lengths.append(valueBytes.count)
        }
        return try run.withUnsafeBufferPointer { bytes -> Answer in
            var array: [sipral_header_t] = []
            var at = 0
            var part = 0
            for _ in list {
                var record = sipral_header_t()
                record.name = lengths[part] == 0 ? nil : bytes.baseAddress.map { $0 + at }
                record.name_len = lengths[part]
                at += lengths[part]
                part += 1
                record.value = lengths[part] == 0 ? nil : bytes.baseAddress.map { $0 + at }
                record.value_len = lengths[part]
                at += lengths[part]
                part += 1
                array.append(record)
            }
            if array.isEmpty {
                return try body(UnsafeBufferPointer(start: nil, count: 0))
            }
            return try array.withUnsafeBufferPointer(body)
        }
    }
}

/// Everything the library does, with the C conventions read off it.
///
/// Swift gives a namespace `enum` like this one no load hook: there is
/// no module initializer and nothing else the runtime guarantees to run
/// before first use, the way a static constructor does for the .NET
/// binding or an `init` block does for the Kotlin one. What Swift does
/// guarantee is narrower, and it is enough: a static stored property's
/// initializer runs at most once, and finishes before the first read of
/// it returns, on whichever thread reaches it first — the same promise
/// `dispatch_once` made in Objective-C. `abiMismatch` below is one such
/// property, and every call in this `enum` reads it, through
/// `ensureAbi`, before it does anything else. So the check runs the
/// first time this module is asked to do anything at all, on whichever
/// thread makes that first call — not at import, which Swift gives no
/// hook for, but before that first call reaches C, which is the promise
/// this makes instead.
///
/// Skipping it is not something a caller can do: there is no call here
/// that reaches C without going through `ensureAbi` first. The `size`
/// every struct here carries settles how long a struct is, not what is
/// in it: a header and a library that disagree about the order or the
/// meaning of members can still agree about the length, and then every
/// size rule passes while the library reads a pointer out of whatever
/// was put in its place. No entry point can catch that on its own,
/// because whether a pointer is readable is the caller's promise, not
/// something the library can check. This is what finds the
/// disagreement before anything is read, and a mismatch is what it
/// throws — a SipralError, from whichever call the application happens
/// to make first, not a warning that is easy to miss.
public enum Sipral {
    /// The value no live handle ever takes.
    public static let handleNone: SipralHandle = 0

    /// The ABI's major version. Nothing published against one major works
    /// against another; within one, a binding built against a minor works
    /// against a library at that minor or any later one.
    public static let abiVersionMajor: UInt32 = 1

    /// The ABI's minor version, raised by anything the header gains. Rules:
    /// Versioning section of `docs/08-ffi.md`.
    public static let abiVersionMinor: UInt32 = 2

    /// The ABI's patch version, raised by a fix that changes no declaration.
    public static let abiVersionPatch: UInt32 = 0

    /// Bits of sipral_capabilities_t.transports. A transport this ABI has no
    /// bit for yet reads as absent.
    ///
    /// Derived from SipralTransport's numbers (`1 << (value - 1)`), so the
    /// two numberings never have to be kept in step by hand.
    public static let transportBitUdp: UInt32 = 1

    /// See SIPRAL_TRANSPORT_BIT_UDP.
    public static let transportBitTcp: UInt32 = 2

    /// See SIPRAL_TRANSPORT_BIT_UDP.
    public static let transportBitTls: UInt32 = 4

    /// See SIPRAL_TRANSPORT_BIT_UDP.
    public static let transportBitWs: UInt32 = 8

    /// See SIPRAL_TRANSPORT_BIT_UDP.
    public static let transportBitWss: UInt32 = 16

    /// Bits of sipral_capabilities_t.features.
    public static let featureDtmf: UInt32 = 1

    /// See SIPRAL_FEATURE_DTMF.
    public static let featureRtcpMux: UInt32 = 2

    /// See SIPRAL_FEATURE_DTMF.
    public static let featureRecording: UInt32 = 4

    /// See SIPRAL_FEATURE_DTMF.
    public static let featureMediaStallWatchdog: UInt32 = 8

    /// See SIPRAL_FEATURE_DTMF.
    public static let featureSrtp: UInt32 = 16

    /// See SIPRAL_FEATURE_DTMF. RFC 6665 subscriptions and the
    /// dialog-state package a busy lamp field is built on, reached with
    /// sipral_account_subscribe.
    public static let featureSubscriptions: UInt32 = 32

    /// See SIPRAL_FEATURE_DTMF. Opus is behind a compile-time feature
    /// (libopus is licensed, not written here). Set from the codec catalogue,
    /// not from a crate feature flag. `SIPRAL_CODEC_OPUS` keeps its number either way.
    public static let featureOpus: UInt32 = 64

    /// DTLS-SRTP (RFC 5764): media keys come from a handshake on the media path.
    ///
    /// Behind a compile-time feature. `SIPRAL_SRTP_DTLS` and
    /// `SIPRAL_SRTP_DTLS_REQUIRED` keep their numbers in a build without it and
    /// answer `SIPRAL_STATUS_NOT_SUPPORTED` there, never an unencrypted call.
    ///
    /// An application that sets one of those policies must also drain
    /// `sipral_media_poll_transmit`; see there.
    public static let featureDtlsSrtp: UInt32 = 128

    /// See SIPRAL_FEATURE_DTMF. ICE in the full role (RFC 8445), with
    /// consent freshness (RFC 7675) and the SDP attributes of RFC 8839.
    ///
    /// Behind a compile-time feature and off by policy (`docs/06-nat.md`).
    /// `SIPRAL_ICE_OFFERED` and `SIPRAL_ICE_REQUIRED` keep their numbers in a
    /// build without it and answer `SIPRAL_STATUS_NOT_SUPPORTED` there.
    ///
    /// An application that sets one of those policies must also drain
    /// `sipral_media_poll_transmit`; see there.
    public static let featureIce: UInt32 = 256

    /// See SIPRAL_FEATURE_DTMF. STUN (RFC 8489): a stack created with
    /// `SIPRAL_NAT_STUN` learns its public address and writes it in `Contact`,
    /// `c=` and `m=`. Without the feature, `SIPRAL_NAT_STUN` answers
    /// `SIPRAL_STATUS_NOT_SUPPORTED`.
    public static let featureStun: UInt32 = 512

    /// See SIPRAL_FEATURE_DTMF. A TURN server over TCP or TLS
    /// (RFC 8656 §3.1): `sipral_stack_config_t::turn_transport` and
    /// `SIPRAL_EVENT_KIND_TURN_STREAM`. Comes with `SIPRAL_FEATURE_ICE`;
    /// without it a non-UDP `turn_transport` answers `SIPRAL_STATUS_NOT_SUPPORTED`.
    public static let featureTurnStream: UInt32 = 1024

    /// See SIPRAL_FEATURE_DTMF. The built-in audio engine
    /// (`sipral_stack_config_t::audio` = `SIPRAL_AUDIO_DEVICE`, and the
    /// `sipral_audio_*` entry points). Clear where there is no backend (Linux,
    /// Android below API 28); `SIPRAL_AUDIO_DEVICE` then answers
    /// `SIPRAL_STATUS_NOT_SUPPORTED`. On Android it is the phone's answer, read
    /// at call time. This crate's own answer: the engine is not under the facade.
    public static let featureAudioDevice: UInt32 = 2048

    /// See SIPRAL_FEATURE_DTMF. Caller identity on every call event:
    /// asserted identity behind `trusted_peers` (RFC 3325), `verstat`,
    /// `Privacy`, `Diversion`, `History-Info`, `Answer-Mode`, `Alert-Info`;
    /// end causes (RFC 3326) and `sipral_call_hangup_for`;
    /// `sipral_call_redirect`; an account's `privacy` and `session_timer`.
    public static let featureCallerIdentity: UInt32 = 4096

    /// See SIPRAL_FEATURE_DTMF. A call follows a network change:
    /// `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED` and `sipral_call_media_readdress`.
    public static let featureCallReaddress: UInt32 = 8192

    /// See SIPRAL_FEATURE_DTMF. The redacted, rate-limited log callback
    /// (`sipral_stack_log`) and the state snapshot (`sipral_stack_state_text`).
    /// Set in every build.
    public static let featureLogging: UInt32 = 16384

    /// See SIPRAL_FEATURE_DTMF. Stack ceilings (`max_dialogs`,
    /// `max_server_transactions`, `diagnostic_decisions`, `diagnostic_records`),
    /// `SIPRAL_STATUS_LIMIT_REACHED`, and the counters in `sipral_counters_t`.
    public static let featureLimits: UInt32 = 32768

    /// See SIPRAL_FEATURE_DTMF. STIR/SHAKEN (RFC 8224, RFC 8588): signing
    /// (`stir_key`, `stir_certificate_url`) and verification
    /// (`sipral_stack_stir`, `SIPRAL_EVENT_KIND_CALLER_VERIFICATION`,
    /// `sipral_call_stir_certificate`). Behind a compile-time feature, on by default.
    public static let featureStir: UInt32 = 65536

    /// See SIPRAL_FEATURE_DTMF. SRTP policy and suites per account,
    /// `SIPRAL_SRTP_DTLS_OR_SDES`, `SIPRAL_STATUS_SECURITY_POLICY`, and
    /// `sipral_media_encryption_at`.
    public static let featureSrtpPolicy: UInt32 = 131072

    /// See SIPRAL_FEATURE_DTMF. In-band signals: DTMF detection
    /// (`sipral_stack_config_t::dtmf_detection`, `sipral_call_dtmf_detection`,
    /// `SIPRAL_EVENT_KIND_IN_BAND_DIGIT`) and generation (`SIPRAL_DTMF_IN_BAND`),
    /// progress and answering-machine detection (`sipral_call_detect_progress`,
    /// `SIPRAL_EVENT_KIND_PROGRESS_DETECTED`), and `sipral_call_consent_tone`.
    public static let featureInBandSignals: UInt32 = 262144

    /// See SIPRAL_FEATURE_DTMF. Recording formats
    /// (`sipral_media_record_start_with`): mixed or stereo, WAV/RF64,
    /// checkpointed, Ogg Opus with SIPRAL_FEATURE_OPUS; and L16 at 8 and 16 kHz.
    public static let featureRecordingFormats: UInt32 = 524288

    /// See SIPRAL_FEATURE_DTMF. SIPREC (RFC 7866): `sipral_call_record_to`
    /// and `sipral_media_poll_recording`.
    public static let featureSiprec: UInt32 = 1048576

    /// See SIPRAL_FEATURE_DTMF. Conference package (RFC 4575,
    /// `sipral_subscription_conference`), focus `isfocus` (RFC 4579,
    /// `sipral_call_conference_uri`), presence publish (RFC 3903) and watch (RFC 3856).
    public static let featureConference: UInt32 = 2097152

    /// See SIPRAL_FEATURE_DTMF. Real-time text (RFC 4103): `text_address`,
    /// `sipral_media_send_text`, `SIPRAL_EVENT_KIND_TEXT_RECEIVED`.
    public static let featureRealtimeText: UInt32 = 4194304

    /// See SIPRAL_FEATURE_DTMF. RTP/AVPF with Generic NACK and reduced-size
    /// RTCP (RFC 4585, RFC 5506): `feedback`, reported in `sipral_media_info_t`.
    public static let featureRtcpFeedback: UInt32 = 8388608

    /// See SIPRAL_FEATURE_DTMF. A local conference of calls on any codec
    /// and rate: `sipral_local_conference_create`,
    /// `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED`.
    public static let featureLocalConference: UInt32 = 16777216

    /// The buffer a caller has to bring for one outgoing packet.
    ///
    /// The bound the session builds against, not a path MTU. Checked before
    /// anything is encoded, so a frame is never encoded and then lost.
    public static let mediaPacketBytes: Int = 1500

    /// The bound for an incoming datagram that RFC 5761 §4 classifies as control.
    ///
    /// Compound RTCP from a peer may exceed the media bound (RFC 3550 sets no
    /// limit). Everything else still gets SIPRAL_MEDIA_PACKET_BYTES; outgoing
    /// RTCP always fits the media bound.
    public static let mediaRtcpBytes: Int = 8192

    /// Room enough for any address this ABI writes, the NUL included:
    /// `[2001:db8:0000:0000:0000:0000:0000:0001]:65535` and a byte to spare.
    public static let addressBytes: Int = 64

    /// The transport a stack is created with.
    ///
    /// Never removed from the table; failure stops it, sipral_stack_transport_bind restores
    /// it. Zero in `sipral_account_config_t::transport` and `sipral_call_config_t::transport`
    /// means this one.
    public static let transportMain: UInt32 = 0

    /// The largest message that crosses in either direction.
    ///
    /// Bounds the parser's work against a hostile peer. Size stream read buffers to this; about
    /// 1500 bytes suffices on a datagram socket.
    public static let messageBytes: Int = 65535

    /// The longest `sipral_transport_failure_t::detail` accepted. Longer is refused, not cut.
    public static let transportDetailBytes: Int = 1024

    /// The answer that lets an INVITE through.
    ///
    /// Any other answer refuses. Acceptance is 200, not zero, because zero is
    /// what a binding returns when the listener threw, or what an unfilled
    /// answer leaves; neither may admit a call.
    public static let screenAccept: UInt32 = 200

    /// The default burst: ten INVITEs from one address at once.
    ///
    /// With SIPRAL_INVITE_LIMIT_EVERY_MS, the floor every stack starts with.
    /// An INVITE past it is answered 480 and counted in
    /// `sipral_counters_t::screened_refused_by_rate`; no event is raised.
    public static let inviteLimitBurst: UInt32 = 10

    /// The default interval: one more INVITE every two seconds.
    public static let inviteLimitEveryMs: UInt64 = 2000

    /// The voice-agent preset's burst: 128 at once.
    ///
    /// For a headless service taking every call from one trunk or proxy. Use
    /// with SIPRAL_INVITE_LIMIT_VOICE_AGENT_EVERY_MS. Equal to the default
    /// `max_dialogs`, so a rush hits that ceiling (503) before the rate.
    public static let inviteLimitVoiceAgentBurst: UInt32 = 128

    /// The voice-agent preset's interval: one more INVITE every 50 ms.
    public static let inviteLimitVoiceAgentEveryMs: UInt64 = 50

    /// Bits of `sipral_call_event_t::privacy` and of
    /// `sipral_account_config_t::privacy` (RFC 3323 §4.2): `header`, obscure
    /// the fields that could identify the caller.
    public static let privacyHeader: UInt32 = 1

    /// `session`: hide the session description from the far end.
    public static let privacySession: UInt32 = 2

    /// `user`: user-level privacy.
    public static let privacyUser: UInt32 = 4

    /// `id` (RFC 3325 §9.3): keep the asserted identity inside the trust
    /// domain. What "withhold my number" asks for.
    public static let privacyId: UInt32 = 8

    /// `critical`: fail the call rather than go without the privacy asked
    /// for.
    public static let privacyCritical: UInt32 = 16

    /// `none`: no privacy, stated. Read only; an account asks for none by
    /// leaving every bit clear.
    public static let privacyNone: UInt32 = 32

    /// The longest text sipral_stack_state_text writes, NUL included; a
    /// buffer this size always fits.
    public static let stateTextMax: Int = 16384

    /// The calling thread's last error, or an empty string when it
    /// has none. Read the way C reads it: ask for the length, then
    /// for the bytes.
    ///
    /// Not behind `ensureAbi`. This is what a mismatch's own message
    /// is read with, while `abiMismatch` is still being computed, and
    /// going through the check to reach it would be this property
    /// reading itself before it has a value.
    static func rawLastErrorMessage() -> String {
        var needed = 0
        _ = sipral_last_error_message(nil, 0, &needed)
        guard needed > 1 else { return "" }
        var buffer = [CChar](repeating: 0, count: needed)
        let status = buffer.withUnsafeMutableBufferPointer {
            sipral_last_error_message($0.baseAddress, $0.count, nil)
        }
        guard status == SIPRAL_STATUS_OK else { return "" }
        return String(cString: buffer)
    }

    /// The calling thread's last error, or an empty string when it
    /// has none.
    public static func lastErrorMessage() throws -> String {
        try ensureAbi()
        return rawLastErrorMessage()
    }

    /// Whether the library this binding loaded can serve the ABI this
    /// file was printed against, checked once. A static stored
    /// property's initializer in Swift runs at most once and
    /// finishes before the first read of it returns, on whichever
    /// thread reaches it first, which is what makes this safe to
    /// read from every one of them without a lock of its own.
    static let abiMismatch: SipralError? = {
        let status = sipral_abi_check(abiVersionMajor, abiVersionMinor)
        guard status != SIPRAL_STATUS_OK else { return nil }
        return SipralError(code: status, message: rawLastErrorMessage())
    }()

    /// Throws what `abiMismatch` found, if it found one. Every call
    /// below reaches this before it reaches C, so a binding loaded
    /// over the wrong library fails here, in whichever call the
    /// application happens to make first, rather than in whichever
    /// one first happens to disagree about a struct's layout.
    static func ensureAbi() throws {
        if let mismatch = abiMismatch {
            throw mismatch
        }
    }

    /// Turn a status into a thrown error, and nothing into nothing.
    static func check(_ status: sipral_status_t) throws {
        guard status != SIPRAL_STATUS_OK else { return }
        throw SipralError(code: status, message: rawLastErrorMessage())
    }

    /// Every struct and union the header declares, with how long tools/abi-gen
    /// worked it out to be on each of the three layouts the ABI ships for:
    /// 64-bit pointers (p64), then 32-bit pointers with 64-bit integers aligned
    /// to four (p32a4, i386) and to eight (p32a8, ARM and Windows x86). A size
    /// test holds this binding's own layout of each record, and the library's
    /// answer from sipral_abi_struct_size, to the number for the layout it runs
    /// on; bindings/c/abi-layout.c holds a C compiler to all three.
    public static let recordLayouts: [(name: String, imported: Int, p64: Int, p32a4: Int, p32a8: Int)] = [
        ("sipral_abi_version_t", MemoryLayout<sipral_abi_version_t>.size, 24, 20, 20),
        ("sipral_capabilities_t", MemoryLayout<sipral_capabilities_t>.size, 24, 16, 16),
        ("sipral_counters_t", MemoryLayout<sipral_counters_t>.size, 232, 228, 232),
        ("sipral_stack_config_t", MemoryLayout<sipral_stack_config_t>.size, 432, 296, 304),
        ("sipral_poll_result_t", MemoryLayout<sipral_poll_result_t>.size, 48, 28, 32),
        ("sipral_stack_settings_t", MemoryLayout<sipral_stack_settings_t>.size, 136, 128, 136),
        ("sipral_header_t", MemoryLayout<sipral_header_t>.size, 32, 16, 16),
        ("sipral_account_config_t", MemoryLayout<sipral_account_config_t>.size, 464, 256, 264),
        ("sipral_call_config_t", MemoryLayout<sipral_call_config_t>.size, 160, 92, 92),
        ("sipral_codec_info_t", MemoryLayout<sipral_codec_info_t>.size, 32, 28, 28),
        ("sipral_codec_candidate_t", MemoryLayout<sipral_codec_candidate_t>.size, 24, 20, 20),
        ("sipral_path_candidate_t", MemoryLayout<sipral_path_candidate_t>.size, 88, 60, 64),
        ("sipral_media_info_t", MemoryLayout<sipral_media_info_t>.size, 104, 92, 96),
        ("sipral_stream_stats_t", MemoryLayout<sipral_stream_stats_t>.size, 328, 312, 328),
        ("sipral_media_packet_t", MemoryLayout<sipral_media_packet_t>.size, 64, 36, 36),
        ("sipral_processor_frame_t", MemoryLayout<sipral_processor_frame_t>.size, 64, 32, 32),
        ("sipral_transmit_t", MemoryLayout<sipral_transmit_t>.size, 88, 48, 48),
        ("sipral_transport_failure_t", MemoryLayout<sipral_transport_failure_t>.size, 40, 24, 24),
        ("sipral_registration_event_t", MemoryLayout<sipral_registration_event_t>.size, 40, 36, 40),
        ("sipral_call_event_t", MemoryLayout<sipral_call_event_t>.size, 328, 208, 216),
        ("sipral_transfer_event_t", MemoryLayout<sipral_transfer_event_t>.size, 24, 16, 16),
        ("sipral_media_event_t", MemoryLayout<sipral_media_event_t>.size, 96, 80, 80),
        ("sipral_recovery_event_t", MemoryLayout<sipral_recovery_event_t>.size, 16, 16, 16),
        ("sipral_transport_wanted_event_t", MemoryLayout<sipral_transport_wanted_event_t>.size, 40, 20, 20),
        ("sipral_subscription_event_t", MemoryLayout<sipral_subscription_event_t>.size, 56, 56, 56),
        ("sipral_announce_event_t", MemoryLayout<sipral_announce_event_t>.size, 16, 16, 16),
        ("sipral_resolve_event_t", MemoryLayout<sipral_resolve_event_t>.size, 32, 24, 24),
        ("sipral_message_event_t", MemoryLayout<sipral_message_event_t>.size, 96, 64, 64),
        ("sipral_nat_event_t", MemoryLayout<sipral_nat_event_t>.size, 64, 40, 40),
        ("sipral_nat_relay_event_t", MemoryLayout<sipral_nat_relay_event_t>.size, 72, 40, 40),
        ("sipral_referral_event_t", MemoryLayout<sipral_referral_event_t>.size, 40, 24, 24),
        ("sipral_turn_stream_event_t", MemoryLayout<sipral_turn_stream_event_t>.size, 40, 24, 24),
        ("sipral_audio_event_t", MemoryLayout<sipral_audio_event_t>.size, 20, 20, 20),
        ("sipral_stun_server_event_t", MemoryLayout<sipral_stun_server_event_t>.size, 40, 20, 20),
        ("sipral_verification_event_t", MemoryLayout<sipral_verification_event_t>.size, 96, 60, 60),
        ("sipral_progress_event_t", MemoryLayout<sipral_progress_event_t>.size, 80, 80, 80),
        ("sipral_conference_event_t", MemoryLayout<sipral_conference_event_t>.size, 24, 20, 24),
        ("sipral_text_event_t", MemoryLayout<sipral_text_event_t>.size, 24, 12, 12),
        ("sipral_presence_event_t", MemoryLayout<sipral_presence_event_t>.size, 88, 64, 72),
        ("sipral_transport_failed_event_t", MemoryLayout<sipral_transport_failed_event_t>.size, 32, 24, 24),
        ("sipral_local_conference_event_t", MemoryLayout<sipral_local_conference_event_t>.size, 40, 40, 40),
        ("sipral_locate_event_t", MemoryLayout<sipral_locate_event_t>.size, 48, 32, 32),
        ("sipral_challenge_event_t", MemoryLayout<sipral_challenge_event_t>.size, 40, 20, 20),
        ("sipral_token_event_t", MemoryLayout<sipral_token_event_t>.size, 88, 48, 48),
        ("sipral_network_test_event_t", MemoryLayout<sipral_network_test_event_t>.size, 104, 88, 88),
        ("sipral_event_payload_t", MemoryLayout<sipral_event_payload_t>.size, 328, 208, 216),
        ("sipral_event_t", MemoryLayout<sipral_event_t>.size, 384, 248, 264),
        ("sipral_suspending_t", MemoryLayout<sipral_suspending_t>.size, 32, 16, 16),
        ("sipral_screen_request_t", MemoryLayout<sipral_screen_request_t>.size, 48, 28, 32),
        ("sipral_subscribe_config_t", MemoryLayout<sipral_subscribe_config_t>.size, 88, 48, 48),
        ("sipral_watched_dialog_t", MemoryLayout<sipral_watched_dialog_t>.size, 32, 28, 32),
        ("sipral_push_echo_t", MemoryLayout<sipral_push_echo_t>.size, 24, 20, 24),
        ("sipral_audio_device_t", MemoryLayout<sipral_audio_device_t>.size, 32, 28, 28),
        ("sipral_audio_info_t", MemoryLayout<sipral_audio_info_t>.size, 48, 44, 48),
        ("sipral_audio_transmit_t", MemoryLayout<sipral_audio_transmit_t>.size, 56, 36, 40),
        ("sipral_log_record_t", MemoryLayout<sipral_log_record_t>.size, 64, 40, 48),
        ("sipral_stir_config_t", MemoryLayout<sipral_stir_config_t>.size, 56, 44, 48),
        ("sipral_stream_encryption_t", MemoryLayout<sipral_stream_encryption_t>.size, 32, 28, 28),
        ("sipral_progress_config_t", MemoryLayout<sipral_progress_config_t>.size, 72, 68, 68),
        ("sipral_consent_tone_t", MemoryLayout<sipral_consent_tone_t>.size, 32, 28, 28),
        ("sipral_recording_options_t", MemoryLayout<sipral_recording_options_t>.size, 32, 28, 28),
        ("sipral_conference_t", MemoryLayout<sipral_conference_t>.size, 32, 28, 28),
        ("sipral_conference_user_t", MemoryLayout<sipral_conference_user_t>.size, 24, 20, 20),
        ("sipral_presence_t", MemoryLayout<sipral_presence_t>.size, 32, 20, 20),
        ("sipral_record_config_t", MemoryLayout<sipral_record_config_t>.size, 80, 40, 40),
        ("sipral_local_conference_config_t", MemoryLayout<sipral_local_conference_config_t>.size, 24, 20, 20),
        ("sipral_local_conference_info_t", MemoryLayout<sipral_local_conference_info_t>.size, 56, 48, 48),
        ("sipral_local_conference_member_t", MemoryLayout<sipral_local_conference_member_t>.size, 40, 36, 40),
        ("sipral_pinned_certificate_t", MemoryLayout<sipral_pinned_certificate_t>.size, 40, 36, 40),
        ("sipral_network_test_config_t", MemoryLayout<sipral_network_test_config_t>.size, 48, 36, 40),
    ]

    /// The short name of a status code, as a static NUL-terminated string, or
    /// null for a number that is not a status code.
    ///
    /// The string belongs to the library and lives as long as it is loaded.
    /// It is meant for a log line; the last error is the sentence for a human.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns, and is safe to call from any thread.
    public static func statusName(status: Int32) throws -> String? {
        try ensureAbi()
        guard let text = sipral_status_name(status) else { return nil }
        return String(cString: text)
    }

    /// Report the ABI version this library provides.
    ///
    /// Safety
    ///
    /// `out_version` must point at a `sipral_abi_version_t` whose `size`
    /// member says how long it is.
    public static func abiVersion() throws -> sipral_abi_version_t {
        try ensureAbi()
        var version = sipral_abi_version_t.sized()
        let status = sipral_abi_version(&version)
        try check(status)
        return version
    }

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
    public static func abiCheck(major: UInt32, minor: UInt32) throws {
        try ensureAbi()
        let status = sipral_abi_check(major, minor)
        try check(status)
    }

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
    public static func abiStructSize(name: String) throws -> Int {
        try ensureAbi()
        var size = Int()
        let status =
            Array(name.utf8).withUnsafeBufferPointer { raw0 in
                raw0.withMemoryRebound(to: CChar.self) { p0 in
                    sipral_abi_struct_size(p0.baseAddress, p0.count, &size)
                }
            }
        try check(status)
        return size
    }

    /// How many of the ABI's structs carry a `size` member.
    /// Compare it with the caller's own list of structs, so a struct added to
    /// the ABI is not missed by `sipral_abi_struct_size` checks.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    public static func abiVersionedCount() throws -> Int {
        try ensureAbi()
        var count = Int()
        let status = sipral_abi_versioned_count(&count)
        try check(status)
        return count
    }

    /// What this build of the library can do, in one call.
    ///
    /// Answers the same before and after any stack exists. Safe from any
    /// thread, including the event callback.
    ///
    /// Safety
    ///
    /// `out_capabilities` must point at a `sipral_capabilities_t` whose
    /// `size` member says how long it is.
    public static func capabilities() throws -> sipral_capabilities_t {
        try ensureAbi()
        var capabilities = sipral_capabilities_t.sized()
        let status = sipral_capabilities(&capabilities)
        try check(status)
        return capabilities
    }

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
    public static func stackCreate(config: sipral_stack_config_t) throws -> SipralHandle {
        try ensureAbi()
        var config = config
        var stack = SipralHandle()
        let status = sipral_stack_create(&config, &stack)
        try check(status)
        return stack
    }

    /// Read back what a stack is running with, defaults filled in.
    ///
    /// Safety
    ///
    /// `out_settings` must point at a `sipral_stack_settings_t` whose `size`
    /// member says how long it is.
    public static func stackSettings(stack: SipralHandle) throws -> sipral_stack_settings_t {
        try ensureAbi()
        var settings = sipral_stack_settings_t.sized()
        let status = sipral_stack_settings(stack, &settings)
        try check(status)
        return settings
    }

    /// Destroy a stack. The handle is dead on return; a second destroy is
    /// `SIPRAL_STATUS_STALE_HANDLE`. Safe inside the callback. Inside a frame of one
    /// of its calls it is `SIPRAL_STATUS_BUSY`. Nothing is sent: hang up, unmap and
    /// send what `sipral_stack_poll_farewell` and `sipral_stack_poll_stun` give
    /// first, or TURN relays linger up to ten minutes.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    public static func stackDestroy(stack: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_stack_destroy(stack)
        try check(status)
    }

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
    public static func stackPoll(stack: SipralHandle, nowMs: UInt64) throws -> sipral_poll_result_t {
        try ensureAbi()
        var result = sipral_poll_result_t.sized()
        let status = sipral_stack_poll(stack, nowMs, &result)
        try check(status)
        return result
    }

    /// D3's health counters for one stack, since it was created.
    /// One struct copy, cheap enough to sample on a timer.
    ///
    /// Safety
    ///
    /// `out_counters` must point at a `sipral_counters_t` whose `size` member
    /// says how long it is.
    public static func stackCounters(stack: SipralHandle) throws -> sipral_counters_t {
        try ensureAbi()
        var counters = sipral_counters_t.sized()
        let status = sipral_stack_counters(stack, &counters)
        try check(status)
        return counters
    }

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
    /// The no re-entry and no unwind rules are on sipral_screen_callback_t.
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
    public static func stackScreen(stack: SipralHandle, callback: sipral_screen_callback_t?, userData: UnsafeMutableRawPointer?) throws {
        try ensureAbi()
        let status = sipral_stack_screen(stack, callback, userData)
        try check(status)
    }

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
    /// sipral_screen_request_t.source is null). Naming `remote` in
    /// `sipral_stack_transport_bind` puts a stream under this floor.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func stackInviteLimit(stack: SipralHandle, everyMs: UInt64, burst: UInt32) throws {
        try ensureAbi()
        let status = sipral_stack_invite_limit(stack, everyMs, burst)
        try check(status)
    }

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
    public static func accountSubscribe(stack: SipralHandle, account: SipralHandle, config: sipral_subscribe_config_t, nowMs: UInt64) throws -> SipralHandle {
        try ensureAbi()
        var config = config
        var subscription = SipralHandle()
        let status = sipral_account_subscribe(stack, account, &config, &subscription, nowMs)
        try check(status)
        return subscription
    }

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
    public static func subscriptionEnd(stack: SipralHandle, subscription: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_subscription_end(stack, subscription, nowMs)
        try check(status)
    }

    /// Where a subscription is, without waiting for its next event.
    /// SipralSubscriptionState.unknown, with `SIPRAL_STATUS_OK`, for a
    /// handle that names nothing, as an ended one does.
    ///
    /// Safety
    ///
    /// `out_state` must point at one `uint32_t`.
    public static func subscriptionState(stack: SipralHandle, subscription: SipralHandle) throws -> UInt32 {
        try ensureAbi()
        var state = UInt32()
        let status = sipral_subscription_state(stack, subscription, &state)
        try check(status)
        return state
    }

    /// What a lamp for this subscription should show: RFC 4235 §3.7.2's
    /// virtual state machine over every known dialog, ringing beating
    /// settled, SipralDialogPhase.idle once all ended. The dialog
    /// functions below give the detail.
    ///
    /// `SIPRAL_STATUS_NOT_SUPPORTED` for a subscription with no dialog state:
    /// another package, or not live (its last notification is stale).
    ///
    /// Safety
    ///
    /// `out_phase` must point at one `uint32_t`.
    public static func subscriptionLamp(stack: SipralHandle, subscription: SipralHandle) throws -> UInt32 {
        try ensureAbi()
        var phase = UInt32()
        let status = sipral_subscription_lamp(stack, subscription, &phase)
        try check(status)
        return phase
    }

    /// How many dialogs this subscription has been told about, in order first
    /// heard. Indexes hold only until the next notification, which drops
    /// ended dialogs; read again on each
    /// SIPRAL_EVENT_KIND_NOTIFIED.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    public static func subscriptionDialogCount(stack: SipralHandle, subscription: SipralHandle) throws -> Int {
        try ensureAbi()
        var count = Int()
        let status = sipral_subscription_dialog_count(stack, subscription, &count)
        try check(status)
        return count
    }

    /// One of them, by index.
    ///
    /// Safety
    ///
    /// `out_dialog` must point at a `sipral_watched_dialog_t` whose `size`
    /// member says how long it is.
    public static func subscriptionDialogAt(stack: SipralHandle, subscription: SipralHandle, index: Int) throws -> sipral_watched_dialog_t {
        try ensureAbi()
        var dialog = sipral_watched_dialog_t.sized()
        let status = sipral_subscription_dialog_at(stack, subscription, index, &dialog)
        try check(status)
        return dialog
    }

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
    public static func subscriptionDialogText(stack: SipralHandle, subscription: SipralHandle, index: Int, which: UInt32, buffer: inout [CChar]) throws -> Int {
        try ensureAbi()
        var needed = Int()
        let status =
            buffer.withUnsafeMutableBufferPointer { p4 in
                sipral_subscription_dialog_text(stack, subscription, index, which, p4.baseAddress, p4.count, &needed)
            }
        try check(status)
        return needed
    }

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
    public static func accountMessage(stack: SipralHandle, account: SipralHandle, target: String, contentType: String, body: [UInt8], nowMs: UInt64) throws -> SipralHandle {
        try ensureAbi()
        var message = SipralHandle()
        let status =
            Array(target.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    Array(contentType.utf8).withUnsafeBufferPointer { raw3 in
                        raw3.withMemoryRebound(to: CChar.self) { p3 in
                            body.withUnsafeBufferPointer { p4 in
                                sipral_account_message(stack, account, p2.baseAddress, p2.count, p3.baseAddress, p3.count, p4.baseAddress, p4.count, &message, nowMs)
                            }
                        }
                    }
                }
            }
        try check(status)
        return message
    }

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
    public static func accountAnnounce(stack: SipralHandle, account: SipralHandle, caller: String, nowMs: UInt64) throws -> (announcement: SipralHandle, call: SipralHandle) {
        try ensureAbi()
        var announcement = SipralHandle()
        var call = SipralHandle()
        let status =
            Array(caller.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    sipral_account_announce(stack, account, p2.baseAddress, p2.count, &announcement, &call, nowMs)
                }
            }
        try check(status)
        return (announcement: announcement, call: call)
    }

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
    public static func accountRefreshBinding(stack: SipralHandle, account: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_account_refresh_binding(stack, account, nowMs)
        try check(status)
    }

    /// Stop expecting an announced call. `SIPRAL_STATUS_WRONG_STATE` when it
    /// was already fulfilled or expired; the event and this call can cross.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func announcementForget(stack: SipralHandle, announcement: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_announcement_forget(stack, announcement)
        try check(status)
    }

    /// What the registrar said about push in its 2xx to REGISTER.
    /// `SIPRAL_STATUS_NOT_SUPPORTED` when the account did not ask for push or
    /// has no standing binding.
    ///
    /// Safety
    ///
    /// `out_echo` must point at a `sipral_push_echo_t` whose `size` member
    /// says how long it is.
    public static func accountPushEcho(stack: SipralHandle, account: SipralHandle) throws -> sipral_push_echo_t {
        try ensureAbi()
        var echo = sipral_push_echo_t.sized()
        let status = sipral_account_push_echo(stack, account, &echo)
        try check(status)
        return echo
    }

    /// Configure an account and write its handle to `out_account`. Nothing is
    /// sent. It lives until sipral_account_remove or the stack's end.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_account_config_t` whose `size` member
    /// says how long it is, with every pointer in it readable for the length
    /// beside it, and `out_account` at one `sipral_handle_t`.
    public static func accountAdd(stack: SipralHandle, config: sipral_account_config_t, configHeaders: [SipralHeader]) throws -> SipralHandle {
        try ensureAbi()
        var config = config
        var account = SipralHandle()
        let status =
            SipralHeader.withUnsafeArray(configHeaders) { p1Headers -> sipral_status_t in
                config.headers = p1Headers.baseAddress
                config.headers_len = p1Headers.count
                return sipral_account_add(stack, &config, &account)
            }
        try check(status)
        return account
    }

    /// Forget an account and everything scheduled for it. Nothing is sent: its
    /// registrar may be unreachable. Call sipral_account_unregister first
    /// to give the binding up.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func accountRemove(stack: SipralHandle, account: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_account_remove(stack, account)
        try check(status)
    }

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
    public static func accountRegister(stack: SipralHandle, account: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_account_register(stack, account, nowMs)
        try check(status)
    }

    /// Give the binding up: a REGISTER with `Expires: 0` (§10.2.2).
    ///
    /// Only this device's binding: `Contact: *` would remove every binding of
    /// the address of record. An account with no registrar is refused as
    /// `sipral_account_register` refuses it.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func accountUnregister(stack: SipralHandle, account: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_account_unregister(stack, account, nowMs)
        try check(status)
    }

    /// Where an account's registration is, as a `SipralRegistrationState`;
    /// always `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING` with no registrar.
    ///
    /// Safety
    ///
    /// `out_state` must point at one `uint32_t`.
    public static func accountRegistrationState(stack: SipralHandle, account: SipralHandle) throws -> UInt32 {
        try ensureAbi()
        var state = UInt32()
        let status = sipral_account_registration_state(stack, account, &state)
        try check(status)
        return state
    }

    /// Give an account the OAuth 2.0 access token its server asked for
    /// (RFC 8898), replacing any it had. A `token_len` of zero removes it; a
    /// password stays.
    ///
    /// Answers `SIPRAL_EVENT_KIND_TOKEN_REQUIRED`, or renews ahead of expiry.
    /// From the next request, a `Bearer` challenge from the account's own
    /// server (and every request its cached challenge covers) gets
    /// `Authorization: Bearer <token>` (RFC 6750 §2.1); with `Digest` and
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
    public static func accountSetAccessToken(stack: SipralHandle, account: SipralHandle, token: String) throws {
        try ensureAbi()
        let status =
            Array(token.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    sipral_account_set_access_token(stack, account, p2.baseAddress, p2.count)
                }
            }
        try check(status)
    }

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
    public static func stackNetworkTest(stack: SipralHandle, config: sipral_network_test_config_t, nowMs: UInt64) throws -> UInt32 {
        try ensureAbi()
        var config = config
        var test = UInt32()
        let status = sipral_stack_network_test(stack, &config, nowMs, &test)
        try check(status)
        return test
    }

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
    public static func callPlace(stack: SipralHandle, account: SipralHandle, config: sipral_call_config_t, configHeaders: [SipralHeader], nowMs: UInt64) throws -> SipralHandle {
        try ensureAbi()
        var config = config
        var call = SipralHandle()
        let status =
            SipralHeader.withUnsafeArray(configHeaders) { p2Headers -> sipral_status_t in
                config.headers = p2Headers.baseAddress
                config.headers_len = p2Headers.count
                return sipral_call_place(stack, account, &config, &call, nowMs)
            }
        try check(status)
        return call
    }

    /// Say a call that came in is ringing.
    ///
    /// A description makes it a 183 rather than a 180, since a 180 with a body is ambiguous.
    ///
    /// Safety
    ///
    /// `sdp` must be null or readable for `sdp_len` bytes.
    public static func callRing(stack: SipralHandle, call: SipralHandle, sdp: [UInt8], nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            sdp.withUnsafeBufferPointer { p2 in
                sipral_call_ring(stack, call, p2.baseAddress, p2.count, nowMs)
            }
        try check(status)
    }

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
    public static func callRingMedia(stack: SipralHandle, call: SipralHandle, config: sipral_call_config_t, configHeaders: [SipralHeader], nowMs: UInt64) throws {
        try ensureAbi()
        var config = config
        let status =
            SipralHeader.withUnsafeArray(configHeaders) { p2Headers -> sipral_status_t in
                config.headers = p2Headers.baseAddress
                config.headers_len = p2Headers.count
                return sipral_call_ring_media(stack, call, &config, nowMs)
            }
        try check(status)
    }

    /// Answer a call that came in with `sdp`, the answer to the INVITE's offer (required).
    ///
    /// Safety
    ///
    /// `sdp` must be readable for `sdp_len` bytes.
    public static func callAnswer(stack: SipralHandle, call: SipralHandle, sdp: [UInt8], nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            sdp.withUnsafeBufferPointer { p2 in
                sipral_call_answer(stack, call, p2.baseAddress, p2.count, nowMs)
            }
        try check(status)
    }

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
    public static func callAnswerMedia(stack: SipralHandle, call: SipralHandle, mediaAddress: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(mediaAddress.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    sipral_call_answer_media(stack, call, p2.baseAddress, p2.count, nowMs)
                }
            }
        try check(status)
    }

    /// Answer a call that came in with media this stack describes, from `config`:
    /// `sipral_call_answer_media` with the members `sipral_call_ring_media` reads. Any other
    /// member set is `SIPRAL_STATUS_INVALID_ARGUMENT` naming it. On a call already rung with
    /// media, only `focus` changes anything.
    ///
    /// Safety
    ///
    /// `config` must point at a `sipral_call_config_t` whose `size` member says how long it is,
    /// with every pointer in it readable for the length beside it.
    public static func callAnswerWith(stack: SipralHandle, call: SipralHandle, config: sipral_call_config_t, configHeaders: [SipralHeader], nowMs: UInt64) throws {
        try ensureAbi()
        var config = config
        let status =
            SipralHeader.withUnsafeArray(configHeaders) { p2Headers -> sipral_status_t in
                config.headers = p2Headers.baseAddress
                config.headers_len = p2Headers.count
                return sipral_call_answer_with(stack, call, &config, nowMs)
            }
        try check(status)
    }

    /// Refuse a call that came in with a response code of your choosing: 486 for a line in use,
    /// 603 for a person who declines. A proxy acts differently on each.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callReject(stack: SipralHandle, call: SipralHandle, code: UInt32, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_call_reject(stack, call, code, nowMs)
        try check(status)
    }

    /// Hang up, whatever the call is doing: CANCEL before an answer, BYE after, a refusal for
    /// an unanswered incoming call. A call already ending is left alone.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callHangup(stack: SipralHandle, call: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_call_hangup(stack, call, nowMs)
        try check(status)
    }

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
    public static func callSetHeaders(stack: SipralHandle, call: SipralHandle, headers: [SipralHeader]) throws {
        try ensureAbi()
        let status =
            SipralHeader.withUnsafeArray(headers) { p2 in
                sipral_call_set_headers(stack, call, p2.baseAddress, p2.count)
            }
        try check(status)
    }

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
    public static func callHold(stack: SipralHandle, call: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_call_hold(stack, call, nowMs)
        try check(status)
    }

    /// Take it off hold. Each stream returns to its previous direction (a receive-only one stays
    /// receive-only), and waits for a running change as `sipral_call_hold` does.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callResume(stack: SipralHandle, call: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_call_resume(stack, call, nowMs)
        try check(status)
    }

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
    public static func callChangeCodecs(stack: SipralHandle, call: SipralHandle, codecs: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(codecs.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    sipral_call_change_codecs(stack, call, p2.baseAddress, p2.count, nowMs)
                }
            }
        try check(status)
    }

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
    public static func callRestartIce(stack: SipralHandle, call: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_call_restart_ice(stack, call, nowMs)
        try check(status)
    }

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
    public static func callMediaReaddress(stack: SipralHandle, call: SipralHandle, mediaAddress: String, publicAddress: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(mediaAddress.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    Array(publicAddress.utf8).withUnsafeBufferPointer { raw3 in
                        raw3.withMemoryRebound(to: CChar.self) { p3 in
                            sipral_call_media_readdress(stack, call, p2.baseAddress, p2.count, p3.baseAddress, p3.count, nowMs)
                        }
                    }
                }
            }
        try check(status)
    }

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
    public static func callHangupFor(stack: SipralHandle, call: SipralHandle, sipCause: UInt32, q850Cause: UInt32, text: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(text.utf8).withUnsafeBufferPointer { raw4 in
                raw4.withMemoryRebound(to: CChar.self) { p4 in
                    sipral_call_hangup_for(stack, call, sipCause, q850Cause, p4.baseAddress, p4.count, nowMs)
                }
            }
        try check(status)
    }

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
    public static func callRedirect(stack: SipralHandle, call: SipralHandle, statusCode: UInt32, targets: String, reason: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(targets.utf8).withUnsafeBufferPointer { raw3 in
                raw3.withMemoryRebound(to: CChar.self) { p3 in
                    Array(reason.utf8).withUnsafeBufferPointer { raw4 in
                        raw4.withMemoryRebound(to: CChar.self) { p4 in
                            sipral_call_redirect(stack, call, statusCode, p3.baseAddress, p3.count, p4.baseAddress, p4.count, nowMs)
                        }
                    }
                }
            }
        try check(status)
    }

    /// How many entries one of a call's identity lists has. Every piece of an
    /// entry gives the same count. Read once from the INVITE; zero for a call
    /// this end placed.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    public static func callIdentityCount(stack: SipralHandle, call: SipralHandle, which: UInt32) throws -> Int {
        try ensureAbi()
        var count = Int()
        let status = sipral_call_identity_count(stack, call, which, &count)
        try check(status)
        return count
    }

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
    public static func callIdentityText(stack: SipralHandle, call: SipralHandle, index: Int, which: UInt32, buffer: inout [CChar]) throws -> Int {
        try ensureAbi()
        var needed = Int()
        let status =
            buffer.withUnsafeMutableBufferPointer { p4 in
                sipral_call_identity_text(stack, call, index, which, p4.baseAddress, p4.count, &needed)
            }
        try check(status)
        return needed
    }

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
    public static func callJoin(stack: SipralHandle, callA: SipralHandle, callB: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_call_join(stack, callA, callB)
        try check(status)
    }

    /// Take `call` back out of its pair. Neither session is touched; each call carries its own
    /// audio again. `SIPRAL_STATUS_WRONG_STATE` for a call not joined.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callLeave(stack: SipralHandle, call: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_call_leave(stack, call)
        try check(status)
    }

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
    public static func callAcceptSession(stack: SipralHandle, call: SipralHandle, sdp: [UInt8], nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            sdp.withUnsafeBufferPointer { p2 in
                sipral_call_accept_session(stack, call, p2.baseAddress, p2.count, nowMs)
            }
        try check(status)
    }

    /// Refuse one instead; the session stands as it was (§14.1). 488 Not Acceptable Here says
    /// the description was the problem. Only for a call the application describes.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callRejectSession(stack: SipralHandle, call: SipralHandle, code: UInt32, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_call_reject_session(stack, call, code, nowMs)
        try check(status)
    }

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
    public static func callSendDtmf(stack: SipralHandle, call: SipralHandle, digits: String, via: UInt32, durationMs: UInt32, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(digits.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    sipral_call_send_dtmf(stack, call, p2.baseAddress, p2.count, via, durationMs, nowMs)
                }
            }
        try check(status)
    }

    /// Ask the far end to call somebody else, and hang up when it has (RFC 3515).
    ///
    /// A blind transfer. This end stays in the call until the transfer succeeds, so a failed
    /// transfer does not lose the call. Progress arrives as `SIPRAL_EVENT_KIND_TRANSFER_PROGRESS`,
    /// then `SIPRAL_EVENT_KIND_TRANSFER_DONE`.
    ///
    /// Safety
    ///
    /// `target` must be readable for `target_len` bytes.
    public static func callTransfer(stack: SipralHandle, call: SipralHandle, target: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(target.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    sipral_call_transfer(stack, call, p2.baseAddress, p2.count, nowMs)
                }
            }
        try check(status)
    }

    /// Call the transfer target, and write the new call's handle to `out_consultation`.
    ///
    /// The consultation leg of an attended transfer; sipral_call_transfer_to follows.
    /// Holding `call` first is the application's choice. `media_address` is
    /// `SIPRAL_STATUS_NOT_SUPPORTED` here: place the consultation with `sdp` and run its audio.
    ///
    /// Safety
    ///
    /// As sipral_call_place.
    public static func callConsult(stack: SipralHandle, call: SipralHandle, config: sipral_call_config_t, configHeaders: [SipralHeader], nowMs: UInt64) throws -> SipralHandle {
        try ensureAbi()
        var config = config
        var consultation = SipralHandle()
        let status =
            SipralHeader.withUnsafeArray(configHeaders) { p2Headers -> sipral_status_t in
                config.headers = p2Headers.baseAddress
                config.headers_len = p2Headers.count
                return sipral_call_consult(stack, call, &config, &consultation, nowMs)
            }
        try check(status)
        return consultation
    }

    /// Hand `call` to the far end of `other` (RFC 3891): the attended half of a transfer, where
    /// `other` is normally the consultation call. Any call that is up may be named.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callTransferTo(stack: SipralHandle, call: SipralHandle, other: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_call_transfer_to(stack, call, other, nowMs)
        try check(status)
    }

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
    public static func callAcceptTransfer(stack: SipralHandle, call: SipralHandle, config: sipral_call_config_t, configHeaders: [SipralHeader], nowMs: UInt64) throws -> SipralHandle {
        try ensureAbi()
        var config = config
        var placed = SipralHandle()
        let status =
            SipralHeader.withUnsafeArray(configHeaders) { p2Headers -> sipral_status_t in
                config.headers = p2Headers.baseAddress
                config.headers_len = p2Headers.count
                return sipral_call_accept_transfer(stack, call, &config, &placed, nowMs)
            }
        try check(status)
        return placed
    }

    /// Refuse one instead.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callRejectTransfer(stack: SipralHandle, call: SipralHandle, code: UInt32, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_call_reject_transfer(stack, call, code, nowMs)
        try check(status)
    }

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
    public static func callAcceptTransferPlaced(stack: SipralHandle, call: SipralHandle, placed: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_call_accept_transfer_placed(stack, call, placed, nowMs)
        try check(status)
    }

    /// Where a call is, as a `SipralCallState`.
    ///
    /// A call that is over answers `SIPRAL_CALL_STATE_TERMINATED` until the poll delivering
    /// `SIPRAL_EVENT_KIND_CALL_ENDED` retires its handle, then `SIPRAL_STATUS_STALE_HANDLE`. A
    /// referral's handle is `SIPRAL_STATUS_WRONG_STATE`: there is no call yet.
    ///
    /// Safety
    ///
    /// `out_state` must point at one `uint32_t`.
    public static func callState(stack: SipralHandle, call: SipralHandle) throws -> UInt32 {
        try ensureAbi()
        var state = UInt32()
        let status = sipral_call_state(stack, call, &state)
        try check(status)
        return state
    }

    /// Which way a call is held: `out_here` when this end asked the far end to stop sending,
    /// `out_there` when the far end asked. Either may be null.
    ///
    /// Safety
    ///
    /// `out_here` and `out_there` must each be null or point at one `uint32_t`.
    public static func callHoldState(stack: SipralHandle, call: SipralHandle) throws -> (here: UInt32, there: UInt32) {
        try ensureAbi()
        var here = UInt32()
        var there = UInt32()
        let status = sipral_call_hold_state(stack, call, &here, &there)
        try check(status)
        return (here: here, there: there)
    }

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
    public static func codecName(codec: UInt32) throws -> String? {
        try ensureAbi()
        guard let text = sipral_codec_name(codec) else { return nil }
        return String(cString: text)
    }

    /// How many codecs this build contains, fixed at compile time.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    public static func codecCount() throws -> Int {
        try ensureAbi()
        var count = Int()
        let status = sipral_codec_count(&count)
        try check(status)
        return count
    }

    /// One of them, by index, from zero to what `sipral_codec_count` said.
    ///
    /// In this build's preference order, the default offer; G.729 comes last
    /// and is offered only when a codec order names it.
    ///
    /// Safety
    ///
    /// `out_info` must point at a `sipral_codec_info_t` whose `size` member
    /// says how long it is.
    public static func codecAt(index: Int) throws -> sipral_codec_info_t {
        try ensureAbi()
        var info = sipral_codec_info_t.sized()
        let status = sipral_codec_at(index, &info)
        try check(status)
        return info
    }

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
    public static func stackCodecOrder(stack: SipralHandle, outCodecs: inout [UInt32]) throws -> Int {
        try ensureAbi()
        var count = Int()
        let status =
            outCodecs.withUnsafeMutableBufferPointer { p1 in
                sipral_stack_codec_order(stack, p1.baseAddress, p1.count, &count)
            }
        try check(status)
        return count
    }

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
    public static func callMedia(stack: SipralHandle, call: SipralHandle) throws -> SipralHandle {
        try ensureAbi()
        var media = SipralHandle()
        let status = sipral_call_media(stack, call, &media)
        try check(status)
        return media
    }

    /// Let a media handle go.
    ///
    /// Valid whether or not the call or stack still exists. The session is not
    /// touched; releasing mid-call stops nothing. A second release is
    /// `SIPRAL_STATUS_STALE_HANDLE`.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    public static func mediaRelease(media: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_media_release(media)
        try check(status)
    }

    /// What one call's media settled on.
    ///
    /// Safety
    ///
    /// `out_info` must point at a `sipral_media_info_t` whose `size` member
    /// says how long it is.
    public static func mediaInfo(media: SipralHandle) throws -> sipral_media_info_t {
        try ensureAbi()
        var info = sipral_media_info_t.sized()
        let status = sipral_media_info(media, &info)
        try check(status)
        return info
    }

    /// How many codecs were in the running on this call.
    ///
    /// This call's catalogue: the stack's order unless
    /// `sipral_call_config_t::codecs` named another. Zero is a valid answer.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    public static func mediaCodecCandidateCount(media: SipralHandle) throws -> Int {
        try ensureAbi()
        var count = Int()
        let status = sipral_media_codec_candidate_count(media, &count)
        try check(status)
        return count
    }

    /// One of them, by index, from zero to what
    /// `sipral_media_codec_candidate_count` said, in this call's own order.
    ///
    /// An index past the end is `SIPRAL_STATUS_INVALID_ARGUMENT`.
    ///
    /// Safety
    ///
    /// `out_candidate` must point at a `sipral_codec_candidate_t` whose `size`
    /// member says how long it is.
    public static func mediaCodecCandidateAt(media: SipralHandle, index: Int) throws -> sipral_codec_candidate_t {
        try ensureAbi()
        var candidate = sipral_codec_candidate_t.sized()
        let status = sipral_media_codec_candidate_at(media, index, &candidate)
        try check(status)
        return candidate
    }

    /// How many paths this call's ICE agent tried: every candidate pair its
    /// checklist held, then every relay it held.
    ///
    /// Zero for a call not using ICE. A restart (RFC 8445 §9) starts the list
    /// again.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    public static func mediaPathCandidateCount(media: SipralHandle) throws -> Int {
        try ensureAbi()
        var count = Int()
        let status = sipral_media_path_candidate_count(media, &count)
        try check(status)
        return count
    }

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
    public static func mediaPathCandidateAt(media: SipralHandle, index: Int, outCandidate: inout sipral_path_candidate_t) throws {
        try ensureAbi()
        let status = sipral_media_path_candidate_at(media, index, &outCandidate)
        try check(status)
    }

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
    public static func mediaStatistics(media: SipralHandle, nowMs: UInt64) throws -> sipral_stream_stats_t {
        try ensureAbi()
        var stats = sipral_stream_stats_t.sized()
        let status = sipral_media_statistics(media, nowMs, &stats)
        try check(status)
        return stats
    }

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
    public static func mediaReceive(media: SipralHandle, data: inout [UInt8], from: String, nowMs: UInt64) throws -> UInt32 {
        try ensureAbi()
        var arrival = UInt32()
        let status =
            data.withUnsafeMutableBufferPointer { p1 in
                Array(from.utf8).withUnsafeBufferPointer { raw2 in
                    raw2.withMemoryRebound(to: CChar.self) { p2 in
                        sipral_media_receive(media, p1.baseAddress, p1.count, p2.baseAddress, p2.count, nowMs, &arrival)
                    }
                }
            }
        try check(status)
        return arrival
    }

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
    public static func mediaPlayback(media: SipralHandle, samples: inout [Int16]) throws -> (written: Int, source: UInt32) {
        try ensureAbi()
        var written = Int()
        var source = UInt32()
        let status =
            samples.withUnsafeMutableBufferPointer { p1 in
                sipral_media_playback(media, p1.baseAddress, p1.count, &written, &source)
            }
        try check(status)
        return (written: written, source: source)
    }

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
    public static func mediaCapture(media: SipralHandle, nowMs: UInt64, samples: [Int16], packet: inout sipral_media_packet_t) throws {
        try ensureAbi()
        let status =
            samples.withUnsafeBufferPointer { p2 in
                sipral_media_capture(media, nowMs, p2.baseAddress, p2.count, &packet)
            }
        try check(status)
    }

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
    public static func mediaSetAppRate(media: SipralHandle, hz: UInt32) throws {
        try ensureAbi()
        let status = sipral_media_set_app_rate(media, hz)
        try check(status)
    }

    /// Run `callback` over every captured frame, against the far-end audio
    /// played a render delay earlier: the seam for echo cancellation, gain
    /// control and noise suppression (`docs/05-media.md`).
    ///
    /// Replaces any previous processor and its learned state. Attaching
    /// mid-call costs a fresh adaptation.
    ///
    /// **`callback` runs with this call's media locked**, unlike the event
    /// callback: inside sipral_media_playback, inside
    /// sipral_media_capture, and with sipral_processor_frame_t's `reset`
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
    public static func mediaAttachProcessor(media: SipralHandle, callback: sipral_processor_callback_t?, userData: UnsafeMutableRawPointer?) throws {
        try ensureAbi()
        let status = sipral_media_attach_processor(media, callback, userData)
        try check(status)
    }

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
    public static func mediaDetachProcessor(media: SipralHandle) throws -> UInt32 {
        try ensureAbi()
        var wasAttached = UInt32()
        let status = sipral_media_detach_processor(media, &wasAttached)
        try check(status)
        return wasAttached
    }

    /// Forget the echo path, the noise floor and the gain the attached
    /// processor has learned, keeping the processor itself attached.
    ///
    /// For a device change. Calls the sipral_media_attach_processor
    /// callback with sipral_processor_frame_t's `reset` set.
    ///
    /// `out_was_attached`, when not null, gets 1 if a processor exists, else 0.
    ///
    /// Safety
    ///
    /// `out_was_attached` must point at one `uint32_t` or be null.
    public static func mediaResetProcessor(media: SipralHandle) throws -> UInt32 {
        try ensureAbi()
        var wasAttached = UInt32()
        let status = sipral_media_reset_processor(media, &wasAttached)
        try check(status)
        return wasAttached
    }

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
    public static func mediaMix(mediaA: SipralHandle, mediaB: SipralHandle, nowMs: UInt64, mic: [Int16], local: inout [Int16], packetA: inout sipral_media_packet_t, packetB: inout sipral_media_packet_t) throws {
        try ensureAbi()
        let status =
            mic.withUnsafeBufferPointer { p3 in
                local.withUnsafeMutableBufferPointer { p4 in
                    sipral_media_mix(mediaA, mediaB, nowMs, p3.baseAddress, p3.count, p4.baseAddress, p4.count, &packetA, &packetB)
                }
            }
        try check(status)
    }

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
    public static func mediaPollRtcp(media: SipralHandle, nowMs: UInt64, packet: inout sipral_media_packet_t) throws {
        try ensureAbi()
        let status = sipral_media_poll_rtcp(media, nowMs, &packet)
        try check(status)
    }

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
    public static func mediaPollTransmit(media: SipralHandle, nowMs: UInt64, packet: inout sipral_media_packet_t) throws {
        try ensureAbi()
        let status = sipral_media_poll_transmit(media, nowMs, &packet)
        try check(status)
    }

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
    public static func stackPollFarewell(stack: SipralHandle, packet: inout sipral_media_packet_t) throws -> SipralHandle {
        try ensureAbi()
        var call = SipralHandle()
        let status = sipral_stack_poll_farewell(stack, &call, &packet)
        try check(status)
        return call
    }

    /// Whether a digit is going out or waiting to, and how many have not
    /// started yet.
    ///
    /// Either out parameter may be null.
    ///
    /// Safety
    ///
    /// `out_dialling` must point at one `uint32_t` or be null, and
    /// `out_waiting` at one `size_t` or be null.
    public static func mediaDialling(media: SipralHandle) throws -> (dialling: UInt32, waiting: Int) {
        try ensureAbi()
        var dialling = UInt32()
        var waiting = Int()
        let status = sipral_media_dialling(media, &dialling, &waiting)
        try check(status)
        return (dialling: dialling, waiting: waiting)
    }

    /// Drop everything queued and stop the digit going out.
    ///
    /// The digit in flight gets no closing packet.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    public static func mediaStopDialling(media: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_media_stop_dialling(media)
        try check(status)
    }

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
    public static func mediaRecordStart(media: SipralHandle, path: String) throws {
        try ensureAbi()
        let status =
            Array(path.utf8).withUnsafeBufferPointer { raw1 in
                raw1.withMemoryRebound(to: CChar.self) { p1 in
                    sipral_media_record_start(media, p1.baseAddress, p1.count)
                }
            }
        try check(status)
    }

    /// Stop the recording and close the file.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when nothing is being recorded. On failure
    /// the file holds all the audio but zero header lengths.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func mediaRecordStop(media: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_media_record_stop(media)
        try check(status)
    }

    /// Whether a recording is running on this call, and how much audio it has
    /// taken (audio only, not the header). Either out parameter may be null.
    ///
    /// Safety
    ///
    /// `out_recording` must point at one `uint32_t` or be null, and
    /// `out_recorded_ms` at one `uint64_t` or be null.
    public static func mediaRecordState(media: SipralHandle) throws -> (recording: UInt32, recordedMs: UInt64) {
        try ensureAbi()
        var recording = UInt32()
        var recordedMs = UInt64()
        let status = sipral_media_record_state(media, &recording, &recordedMs)
        try check(status)
        return (recording: recording, recordedMs: recordedMs)
    }

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
    public static func stackPollTransmit(stack: SipralHandle, transmit: inout sipral_transmit_t) throws {
        try ensureAbi()
        let status = sipral_stack_poll_transmit(stack, &transmit)
        try check(status)
    }

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
    public static func stackReceiveDatagram(stack: SipralHandle, transport: UInt32, data: [UInt8], from: String, to: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            data.withUnsafeBufferPointer { p2 in
                Array(from.utf8).withUnsafeBufferPointer { raw3 in
                    raw3.withMemoryRebound(to: CChar.self) { p3 in
                        Array(to.utf8).withUnsafeBufferPointer { raw4 in
                            raw4.withMemoryRebound(to: CChar.self) { p4 in
                                sipral_stack_receive_datagram(stack, transport, p2.baseAddress, p2.count, p3.baseAddress, p3.count, p4.baseAddress, p4.count, nowMs)
                            }
                        }
                    }
                }
            }
        try check(status)
    }

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
    public static func stackReceiveStream(stack: SipralHandle, transport: UInt32, data: [UInt8], nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            data.withUnsafeBufferPointer { p2 in
                sipral_stack_receive_stream(stack, transport, p2.baseAddress, p2.count, nowMs)
            }
        try check(status)
    }

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
    /// SipralEventKind.transportWanted,
    /// binding what it named and asking again sends the request on the new stream.
    ///
    /// Safety
    ///
    /// `local` must be readable for `local_len` bytes, `remote` for `remote_len`, and
    /// `out_transport_id`, when it is not null, must point at one `uint32_t`.
    public static func stackTransportBind(stack: SipralHandle, transport: UInt32, `protocol`: UInt32, local: String, remote: String, nowMs: UInt64) throws -> UInt32 {
        try ensureAbi()
        var transportId = UInt32()
        let status =
            Array(local.utf8).withUnsafeBufferPointer { raw3 in
                raw3.withMemoryRebound(to: CChar.self) { p3 in
                    Array(remote.utf8).withUnsafeBufferPointer { raw4 in
                        raw4.withMemoryRebound(to: CChar.self) { p4 in
                            sipral_stack_transport_bind(stack, transport, `protocol`, p3.baseAddress, p3.count, p4.baseAddress, p4.count, nowMs, &transportId)
                        }
                    }
                }
            }
        try check(status)
        return transportId
    }

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
    public static func stackTransportFailed(stack: SipralHandle, transport: UInt32, error: UInt32, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_stack_transport_failed(stack, transport, error, nowMs)
        try check(status)
    }

    /// Say that a transport failed, with the TLS library's reason.
    ///
    /// Does what sipral_stack_transport_failed does, and carries `failure->tls` and
    /// `failure->detail` to `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`. A connection that failed before
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
    public static func stackTransportFailedWith(stack: SipralHandle, failure: sipral_transport_failure_t, nowMs: UInt64) throws {
        try ensureAbi()
        var failure = failure
        let status = sipral_stack_transport_failed_with(stack, &failure, nowMs)
        try check(status)
    }

    /// Say that a connection closed: the far end left, or a read returned zero.
    ///
    /// Retires like sipral_stack_transport_failed, but kept separate so an orderly close is
    /// distinguishable in logs. The event says `SIPRAL_TRANSPORT_ERROR_CLOSED`.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value. Reads no memory the caller owns.
    public static func stackStreamClosed(stack: SipralHandle, transport: UInt32, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_stack_stream_closed(stack, transport, nowMs)
        try check(status)
    }

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
    public static func stackStunServers(stack: SipralHandle, servers: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(servers.utf8).withUnsafeBufferPointer { raw1 in
                raw1.withMemoryRebound(to: CChar.self) { p1 in
                    sipral_stack_stun_servers(stack, p1.baseAddress, p1.count, nowMs)
                }
            }
        try check(status)
    }

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
    public static func stackNatMap(stack: SipralHandle, local: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(local.utf8).withUnsafeBufferPointer { raw1 in
                raw1.withMemoryRebound(to: CChar.self) { p1 in
                    sipral_stack_nat_map(stack, p1.baseAddress, p1.count, nowMs)
                }
            }
        try check(status)
    }

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
    public static func stackNatUnmap(stack: SipralHandle, local: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(local.utf8).withUnsafeBufferPointer { raw1 in
                raw1.withMemoryRebound(to: CChar.self) { p1 in
                    sipral_stack_nat_unmap(stack, p1.baseAddress, p1.count, nowMs)
                }
            }
        try check(status)
    }

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
    public static func stackPollStun(stack: SipralHandle, transmit: inout sipral_transmit_t) throws {
        try ensureAbi()
        let status = sipral_stack_poll_stun(stack, &transmit)
        try check(status)
    }

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
    public static func stackReceiveStun(stack: SipralHandle, data: [UInt8], from: String, to: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            data.withUnsafeBufferPointer { p1 in
                Array(from.utf8).withUnsafeBufferPointer { raw2 in
                    raw2.withMemoryRebound(to: CChar.self) { p2 in
                        Array(to.utf8).withUnsafeBufferPointer { raw3 in
                            raw3.withMemoryRebound(to: CChar.self) { p3 in
                                sipral_stack_receive_stun(stack, p1.baseAddress, p1.count, p2.baseAddress, p2.count, p3.baseAddress, p3.count, nowMs)
                            }
                        }
                    }
                }
            }
        try check(status)
    }

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
    public static func stackTurnConnected(stack: SipralHandle, local: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(local.utf8).withUnsafeBufferPointer { raw1 in
                raw1.withMemoryRebound(to: CChar.self) { p1 in
                    sipral_stack_turn_connected(stack, p1.baseAddress, p1.count, nowMs)
                }
            }
        try check(status)
    }

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
    public static func stackTurnReceive(stack: SipralHandle, local: String, data: [UInt8], nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(local.utf8).withUnsafeBufferPointer { raw1 in
                raw1.withMemoryRebound(to: CChar.self) { p1 in
                    data.withUnsafeBufferPointer { p2 in
                        sipral_stack_turn_receive(stack, p1.baseAddress, p1.count, p2.baseAddress, p2.count, nowMs)
                    }
                }
            }
        try check(status)
    }

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
    public static func stackTurnClosed(stack: SipralHandle, local: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(local.utf8).withUnsafeBufferPointer { raw1 in
                raw1.withMemoryRebound(to: CChar.self) { p1 in
                    sipral_stack_turn_closed(stack, p1.baseAddress, p1.count, nowMs)
                }
            }
        try check(status)
    }

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
    public static func eventKindName(kind: UInt32) throws -> String? {
        try ensureAbi()
        guard let text = sipral_event_kind_name(kind) else { return nil }
        return String(cString: text)
    }

    /// How many lines a header field is on, in a whole SIP message.
    ///
    /// The name is case-insensitive and a compact form equals its long form
    /// (RFC 3261 §7.3.3). An absent field counts zero, not a failure.
    ///
    /// Safety
    ///
    /// `message` must be readable for `message_len` bytes and `name` for
    /// `name_len`, and `out_count` must point at one `size_t`.
    public static func messageHeaderCount(message: [UInt8], name: String) throws -> Int {
        try ensureAbi()
        var count = Int()
        let status =
            message.withUnsafeBufferPointer { p0 in
                Array(name.utf8).withUnsafeBufferPointer { raw1 in
                    raw1.withMemoryRebound(to: CChar.self) { p1 in
                        sipral_message_header_count(p0.baseAddress, p0.count, p1.baseAddress, p1.count, &count)
                    }
                }
            }
        try check(status)
        return count
    }

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
    public static func messageHeader(message: [UInt8], name: String, index: Int) throws -> (offset: Int, len: Int) {
        try ensureAbi()
        var offset = Int()
        var len = Int()
        let status =
            message.withUnsafeBufferPointer { p0 in
                Array(name.utf8).withUnsafeBufferPointer { raw1 in
                    raw1.withMemoryRebound(to: CChar.self) { p1 in
                        sipral_message_header(p0.baseAddress, p0.count, p1.baseAddress, p1.count, index, &offset, &len)
                    }
                }
            }
        try check(status)
        return (offset: offset, len: len)
    }

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
    public static func messageHeaderElementCount(message: [UInt8], name: String) throws -> Int {
        try ensureAbi()
        var count = Int()
        let status =
            message.withUnsafeBufferPointer { p0 in
                Array(name.utf8).withUnsafeBufferPointer { raw1 in
                    raw1.withMemoryRebound(to: CChar.self) { p1 in
                        sipral_message_header_element_count(p0.baseAddress, p0.count, p1.baseAddress, p1.count, &count)
                    }
                }
            }
        try check(status)
        return count
    }

    /// Where one value of a list field is, across every line the field is on.
    ///
    /// `index` is below `sipral_message_header_element_count`. Otherwise as
    /// `sipral_message_header`.
    ///
    /// Safety
    ///
    /// As `sipral_message_header`.
    public static func messageHeaderElement(message: [UInt8], name: String, index: Int) throws -> (offset: Int, len: Int) {
        try ensureAbi()
        var offset = Int()
        var len = Int()
        let status =
            message.withUnsafeBufferPointer { p0 in
                Array(name.utf8).withUnsafeBufferPointer { raw1 in
                    raw1.withMemoryRebound(to: CChar.self) { p1 in
                        sipral_message_header_element(p0.baseAddress, p0.count, p1.baseAddress, p1.count, index, &offset, &len)
                    }
                }
            }
        try check(status)
        return (offset: offset, len: len)
    }

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
    public static func stackSuspending(stack: SipralHandle, nowMs: UInt64) throws -> sipral_suspending_t {
        try ensureAbi()
        var report = sipral_suspending_t.sized()
        let status = sipral_stack_suspending(stack, nowMs, &report)
        try check(status)
        return report
    }

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
    public static func stackResumed(stack: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_stack_resumed(stack, nowMs)
        try check(status)
    }

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
    public static func stackNetworkChanged(stack: SipralHandle, fromLink: UInt32, fromAddress: String, fromInterface: String, fromResolves: UInt32, toLink: UInt32, toAddress: String, toInterface: String, toResolves: UInt32, nowMs: UInt64) throws -> UInt32 {
        try ensureAbi()
        var recovery = UInt32()
        let status =
            Array(fromAddress.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    Array(fromInterface.utf8).withUnsafeBufferPointer { raw3 in
                        raw3.withMemoryRebound(to: CChar.self) { p3 in
                            Array(toAddress.utf8).withUnsafeBufferPointer { raw6 in
                                raw6.withMemoryRebound(to: CChar.self) { p6 in
                                    Array(toInterface.utf8).withUnsafeBufferPointer { raw7 in
                                        raw7.withMemoryRebound(to: CChar.self) { p7 in
                                            sipral_stack_network_changed(stack, fromLink, p2.baseAddress, p2.count, p3.baseAddress, p3.count, fromResolves, toLink, p6.baseAddress, p6.count, p7.baseAddress, p7.count, toResolves, nowMs, &recovery)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        try check(status)
        return recovery
    }

    /// There is no usable interface. Nothing is tried or scheduled until
    /// sipral_stack_network_changed reports one back; the opposite of
    /// sipral_stack_name_resolution_lost.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func stackInterfaceLost(stack: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_stack_interface_lost(stack, nowMs)
        try check(status)
    }

    /// Names no longer become addresses.
    ///
    /// Everything looks healthy while every address learned from a name may
    /// be wrong. Bindings whose registrar is a name stop being trusted; ones
    /// aimed at a literal address keep running.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func stackNameResolutionLost(stack: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_stack_name_resolution_lost(stack, nowMs)
        try check(status)
    }

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
    public static func accountRebind(stack: SipralHandle, account: SipralHandle, transport: UInt32, remote: String, contact: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(remote.utf8).withUnsafeBufferPointer { raw3 in
                raw3.withMemoryRebound(to: CChar.self) { p3 in
                    Array(contact.utf8).withUnsafeBufferPointer { raw4 in
                        raw4.withMemoryRebound(to: CChar.self) { p4 in
                            sipral_account_rebind(stack, account, transport, p3.baseAddress, p3.count, p4.baseAddress, p4.count, nowMs)
                        }
                    }
                }
            }
        try check(status)
    }

    /// Mark the process start, the zero of sipral_account_time_to_ready.
    ///
    /// Only the application knows the moment its users wait from. Each call
    /// clears and restarts every account's measurement.
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func stackColdStart(stack: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_stack_cold_start(stack, nowMs)
        try check(status)
    }

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
    public static func accountFreeze(stack: SipralHandle, account: SipralHandle, buffer: inout [UInt8], nowMs: UInt64) throws -> Int {
        try ensureAbi()
        var len = Int()
        let status =
            buffer.withUnsafeMutableBufferPointer { p2 in
                sipral_account_freeze(stack, account, p2.baseAddress, p2.count, &len, nowMs)
            }
        try check(status)
        return len
    }

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
    public static func accountThaw(stack: SipralHandle, account: SipralHandle, snapshot: [UInt8], asleepMs: UInt64, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            snapshot.withUnsafeBufferPointer { p2 in
                sipral_account_thaw(stack, account, p2.baseAddress, p2.count, asleepMs, nowMs)
            }
        try check(status)
    }

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
    public static func accountTimeToReady(stack: SipralHandle, account: SipralHandle) throws -> (hasValue: UInt32, ms: UInt64) {
        try ensureAbi()
        var hasValue = UInt32()
        var ms = UInt64()
        let status = sipral_account_time_to_ready(stack, account, &hasValue, &ms)
        try check(status)
        return (hasValue: hasValue, ms: ms)
    }

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
    public static func stackResolved(stack: SipralHandle, dialog: SipralHandle, addresses: String, `protocol`: UInt32) throws {
        try ensureAbi()
        let status =
            Array(addresses.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    sipral_stack_resolved(stack, dialog, p2.baseAddress, p2.count, `protocol`)
                }
            }
        try check(status)
    }

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
    public static func accountRetarget(stack: SipralHandle, account: SipralHandle, registrarAddress: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(registrarAddress.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    sipral_account_retarget(stack, account, p2.baseAddress, p2.count, nowMs)
                }
            }
        try check(status)
    }

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
    public static func callRecordJson(stack: SipralHandle, call: SipralHandle, buffer: inout [CChar]) throws -> Int {
        try ensureAbi()
        var needed = Int()
        let status =
            buffer.withUnsafeMutableBufferPointer { p2 in
                sipral_call_record_json(stack, call, p2.baseAddress, p2.count, &needed)
            }
        try check(status)
        return needed
    }

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
    public static func stackDiagnosticsJson(stack: SipralHandle, buffer: inout [CChar]) throws -> Int {
        try ensureAbi()
        var needed = Int()
        let status =
            buffer.withUnsafeMutableBufferPointer { p1 in
                sipral_stack_diagnostics_json(stack, p1.baseAddress, p1.count, &needed)
            }
        try check(status)
        return needed
    }

    /// What a `conference` subscription holds about the conference as a
    /// whole (RFC 4575 §5.5). `SIPRAL_STATUS_NOT_SUPPORTED` when it holds
    /// none: another package, no document yet, or not live.
    ///
    /// Safety
    ///
    /// `out_conference` must point at a `sipral_conference_t` whose `size`
    /// member says how long it is.
    public static func subscriptionConference(stack: SipralHandle, subscription: SipralHandle) throws -> sipral_conference_t {
        try ensureAbi()
        var conference = sipral_conference_t.sized()
        let status = sipral_subscription_conference(stack, subscription, &conference)
        try check(status)
        return conference
    }

    /// One user of the conference, by index, in the order the focus first
    /// named them. The index is stable only until the next
    /// `SIPRAL_EVENT_KIND_CONFERENCE_CHANGED`.
    ///
    /// Safety
    ///
    /// `out_user` must point at a `sipral_conference_user_t` whose `size`
    /// member says how long it is.
    public static func subscriptionConferenceUserAt(stack: SipralHandle, subscription: SipralHandle, index: Int) throws -> sipral_conference_user_t {
        try ensureAbi()
        var user = sipral_conference_user_t.sized()
        let status = sipral_subscription_conference_user_at(stack, subscription, index, &user)
        try check(status)
        return user
    }

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
    public static func subscriptionConferenceText(stack: SipralHandle, subscription: SipralHandle, index: Int, which: UInt32, buffer: inout [CChar]) throws -> Int {
        try ensureAbi()
        var needed = Int()
        let status =
            buffer.withUnsafeMutableBufferPointer { p4 in
                sipral_subscription_conference_text(stack, subscription, index, which, p4.baseAddress, p4.count, &needed)
            }
        try check(status)
        return needed
    }

    /// Put (`focus` 1) or remove (0) `isfocus` on this call's `Contact` from
    /// the next message on (RFC 4579 §4.2): the answer, or the next re-INVITE
    /// or UPDATE on an established call.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func callSetFocus(stack: SipralHandle, call: SipralHandle, focus: UInt32) throws {
        try ensureAbi()
        let status = sipral_call_set_focus(stack, call, focus)
        try check(status)
    }

    /// The conference URI when the far end's `Contact` has `isfocus` (RFC 4579
    /// §4.2), copied as `sipral_subscription_conference_text` copies.
    /// `SIPRAL_STATUS_NOT_A_FOCUS` otherwise.
    ///
    /// Safety
    ///
    /// `buffer` must be writable for `capacity` bytes or be null with a
    /// capacity of zero, and `out_needed` must point at one `size_t` or be
    /// null.
    public static func callConferenceUri(stack: SipralHandle, call: SipralHandle, buffer: inout [CChar]) throws -> Int {
        try ensureAbi()
        var needed = Int()
        let status =
            buffer.withUnsafeMutableBufferPointer { p2 in
                sipral_call_conference_uri(stack, call, p2.baseAddress, p2.count, &needed)
            }
        try check(status)
        return needed
    }

    /// Subscribe to the conference package of the call's focus (RFC 4579
    /// §3.4), outside the call's dialog, from the call's account. The
    /// subscription outlives the call. `SIPRAL_STATUS_NOT_A_FOCUS` when the
    /// far end is not a focus.
    ///
    /// Safety
    ///
    /// `out_subscription` must point at one `sipral_handle_t`.
    public static func callSubscribeConference(stack: SipralHandle, call: SipralHandle, nowMs: UInt64) throws -> SipralHandle {
        try ensureAbi()
        var subscription = SipralHandle()
        let status = sipral_call_subscribe_conference(stack, call, &subscription, nowMs)
        try check(status)
        return subscription
    }

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
    public static func accountPublishPresence(stack: SipralHandle, account: SipralHandle, presence: sipral_presence_t, nowMs: UInt64) throws {
        try ensureAbi()
        var presence = presence
        let status = sipral_account_publish_presence(stack, account, &presence, nowMs)
        try check(status)
    }

    /// Take this account's published presence away (RFC 3903 §4.5):
    /// `SIPRAL_PUBLICATION_STATE_REMOVED` says when it is gone.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for an account that has published none.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func accountUnpublishPresence(stack: SipralHandle, account: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_account_unpublish_presence(stack, account, nowMs)
        try check(status)
    }

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
    public static func mediaSendText(media: SipralHandle, text: String) throws {
        try ensureAbi()
        let status =
            Array(text.utf8).withUnsafeBufferPointer { raw1 in
                raw1.withMemoryRebound(to: CChar.self) { p1 in
                    sipral_media_send_text(media, p1.baseAddress, p1.count)
                }
            }
        try check(status)
    }

    /// The next datagram due on the call's text socket.
    /// `len` zero means nothing due; poll again at the stack's deadline. Send
    /// from the `text_address` socket, not the audio one.
    ///
    /// Safety
    ///
    /// `packet` must point at a `sipral_media_packet_t` as
    /// `sipral_media_capture` describes.
    public static func mediaPollText(media: SipralHandle, nowMs: UInt64, packet: inout sipral_media_packet_t) throws {
        try ensureAbi()
        let status = sipral_media_poll_text(media, nowMs, &packet)
        try check(status)
    }

    /// Take a datagram off the call's text socket.
    /// `out_taken` is 1 when it was this call's text, else 0 (not RTP, other
    /// payload type, not the latched source, or no text stream).
    ///
    /// Safety
    ///
    /// `data` must be readable for `len` bytes, `from` for `from_len`, and
    /// `out_taken` must point at one `uint32_t` or be null.
    public static func mediaReceiveText(media: SipralHandle, data: [UInt8], from: String, nowMs: UInt64) throws -> UInt32 {
        try ensureAbi()
        var taken = UInt32()
        let status =
            data.withUnsafeBufferPointer { p1 in
                Array(from.utf8).withUnsafeBufferPointer { raw2 in
                    raw2.withMemoryRebound(to: CChar.self) { p2 in
                        sipral_media_receive_text(media, p1.baseAddress, p1.count, p2.baseAddress, p2.count, nowMs, &taken)
                    }
                }
            }
        try check(status)
        return taken
    }

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
    public static func callRecordTo(stack: SipralHandle, call: SipralHandle, config: sipral_record_config_t, nowMs: UInt64) throws -> SipralHandle {
        try ensureAbi()
        var config = config
        var recording = SipralHandle()
        let status = sipral_call_record_to(stack, call, &config, &recording, nowMs)
        try check(status)
        return recording
    }

    /// Stop copies at once and hang up the recording session. `call` is the
    /// recorded call. `SIPRAL_STATUS_WRONG_STATE` when nothing records it.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callStopRecordingTo(stack: SipralHandle, call: SipralHandle, nowMs: UInt64) throws {
        try ensureAbi()
        let status = sipral_call_stop_recording_to(stack, call, nowMs)
        try check(status)
    }

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
    public static func mediaPollRecording(media: SipralHandle, packet: inout sipral_media_packet_t) throws -> UInt32 {
        try ensureAbi()
        var farEnd = UInt32()
        let status = sipral_media_poll_recording(media, &packet, &farEnd)
        try check(status)
        return farEnd
    }

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
    public static func stackRecordingStart(stack: SipralHandle, note: String) throws {
        try ensureAbi()
        let status =
            Array(note.utf8).withUnsafeBufferPointer { raw1 in
                raw1.withMemoryRebound(to: CChar.self) { p1 in
                    sipral_stack_recording_start(stack, p1.baseAddress, p1.count)
                }
            }
        try check(status)
    }

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
    public static func stackRecordingStop(stack: SipralHandle, buffer: inout [CChar]) throws -> Int {
        try ensureAbi()
        var needed = Int()
        let status =
            buffer.withUnsafeMutableBufferPointer { p1 in
                sipral_stack_recording_stop(stack, p1.baseAddress, p1.count, &needed)
            }
        try check(status)
        return needed
    }

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
    public static func audioRefresh(stack: SipralHandle) throws -> Int {
        try ensureAbi()
        var count = Int()
        let status = sipral_audio_refresh(stack, &count)
        try check(status)
        return count
    }

    /// How many devices the list holds, present or not.
    ///
    /// The first read of a list asks the platform, so no refresh is needed.
    /// `SIPRAL_STATUS_DEVICE_TIMED_OUT` past `audio_probe_ms`; the next read
    /// asks again.
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    public static func audioDeviceCount(stack: SipralHandle) throws -> Int {
        try ensureAbi()
        var count = Int()
        let status = sipral_audio_device_count(stack, &count)
        try check(status)
        return count
    }

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
    public static func audioDeviceAt(stack: SipralHandle, index: Int, buffer: inout [CChar]) throws -> (device: sipral_audio_device_t, needed: Int) {
        try ensureAbi()
        var device = sipral_audio_device_t.sized()
        var needed = Int()
        let status =
            buffer.withUnsafeMutableBufferPointer { p3 in
                sipral_audio_device_at(stack, index, &device, p3.baseAddress, p3.count, &needed)
            }
        try check(status)
        return (device: device, needed: needed)
    }

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
    public static func audioSelect(stack: SipralHandle, role: UInt32, device: UInt32) throws {
        try ensureAbi()
        let status = sipral_audio_select(stack, role, device)
        try check(status)
    }

    /// What a role was asked to be on (zero: the system's route) and what it
    /// runs on (zero: not open). They differ while a chosen device is absent.
    ///
    /// Safety
    ///
    /// Each out parameter must point at one `uint32_t` or be null.
    public static func audioSelection(stack: SipralHandle, role: UInt32) throws -> (selected: UInt32, running: UInt32) {
        try ensureAbi()
        var selected = UInt32()
        var running = UInt32()
        let status = sipral_audio_selection(stack, role, &selected, &running)
        try check(status)
        return (selected: selected, running: running)
    }

    /// Set the gain of one direction, fixed-point with 256 for unity, capped
    /// at 1024. Input is the microphone gain, output the volume. Applied to
    /// the frames, not the OS control, and kept across device changes.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    public static func audioSetGain(stack: SipralHandle, direction: UInt32, gain: UInt32) throws {
        try ensureAbi()
        let status = sipral_audio_set_gain(stack, direction, gain)
        try check(status)
    }

    /// The gain of one direction, in the steps `sipral_audio_set_gain` takes.
    ///
    /// Safety
    ///
    /// `out_gain` must point at one `uint32_t`.
    public static func audioGain(stack: SipralHandle, direction: UInt32) throws -> UInt32 {
        try ensureAbi()
        var gain = UInt32()
        let status = sipral_audio_gain(stack, direction, &gain)
        try check(status)
        return gain
    }

    /// Mute or unmute one direction, kept across device changes. A muted
    /// microphone sends silence, so the far end hears a stream, not a gap.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    public static func audioSetMuted(stack: SipralHandle, direction: UInt32, muted: UInt32) throws {
        try ensureAbi()
        let status = sipral_audio_set_muted(stack, direction, muted)
        try check(status)
    }

    /// Whether one direction is muted: one or zero into `out_muted`.
    ///
    /// Safety
    ///
    /// `out_muted` must point at one `uint32_t`.
    public static func audioMuted(stack: SipralHandle, direction: UInt32) throws -> UInt32 {
        try ensureAbi()
        var muted = UInt32()
        let status = sipral_audio_muted(stack, direction, &muted)
        try check(status)
        return muted
    }

    /// The meter of one direction: the peak sample of the last 100 ms, 0 to
    /// 32767, held one to two windows. Cheap to poll per frame; zero while
    /// nothing is open.
    ///
    /// Safety
    ///
    /// `out_peak` must point at one `uint32_t`.
    public static func audioLevel(stack: SipralHandle, direction: UInt32) throws -> UInt32 {
        try ensureAbi()
        var peak = UInt32()
        let status = sipral_audio_level(stack, direction, &peak)
        try check(status)
        return peak
    }

    /// Open the devices and start the pump now. The only way under
    /// `SIPRAL_AUDIO_ACTIVATION_MANUAL`; early under automatic activation.
    /// `SIPRAL_STATUS_DEVICE_UNUSABLE` or `SIPRAL_STATUS_DEVICE_TIMED_OUT` for
    /// a direction that failed: the engine is still active, silent there.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    public static func audioActivate(stack: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_audio_activate(stack)
        try check(status)
    }

    /// Close the devices and stop the pump. The calls stay attached and get
    /// their audio back on the next activation.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    public static func audioDeactivate(stack: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_audio_deactivate(stack)
        try check(status)
    }

    /// Ring on the ringer's device (or the loudspeaker) until
    /// `sipral_audio_stop_ringing`, or once when `looped` is zero. Mono 16-bit
    /// samples at `sample_rate_hz`, copied before return. Under automatic
    /// activation a ring opens the devices.
    ///
    /// Safety
    ///
    /// `samples` must be readable for `sample_count` `int16_t`.
    public static func audioRing(stack: SipralHandle, samples: [Int16], sampleRateHz: UInt32, looped: UInt32) throws {
        try ensureAbi()
        let status =
            samples.withUnsafeBufferPointer { p1 in
                sipral_audio_ring(stack, p1.baseAddress, p1.count, sampleRateHz, looped)
            }
        try check(status)
    }

    /// Stop the ring. Under automatic activation, with no call up, the
    /// devices close with it.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    public static func audioStopRinging(stack: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_audio_stop_ringing(stack)
        try check(status)
    }

    /// What the engine is doing: whether it is active, whether the platform
    /// cancels echo, the delay a canceller needs, and where each role runs.
    ///
    /// Safety
    ///
    /// `out_info` must point at a `sipral_audio_info_t` whose `size` member
    /// says how long it is.
    public static func audioInfo(stack: SipralHandle) throws -> sipral_audio_info_t {
        try ensureAbi()
        var info = sipral_audio_info_t.sized()
        let status = sipral_audio_info(stack, &info)
        try check(status)
        return info
    }

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
    public static func audioSetSystemEchoCancellation(stack: SipralHandle, on: UInt32) throws {
        try ensureAbi()
        let status = sipral_audio_set_system_echo_cancellation(stack, on)
        try check(status)
    }

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
    /// after the stack is released (see sipral_log_callback_t). `user_data`
    /// must stay valid until the log is replaced or off and no thread is
    /// inside this stack.
    public static func stackLog(stack: SipralHandle, level: UInt32, callback: sipral_log_callback_t?, userData: UnsafeMutableRawPointer?) throws {
        try ensureAbi()
        let status = sipral_stack_log(stack, level, callback, userData)
        try check(status)
    }

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
    public static func stackStateText(stack: SipralHandle, buffer: inout [CChar]) throws -> Int {
        try ensureAbi()
        var needed = Int()
        let status =
            buffer.withUnsafeMutableBufferPointer { p1 in
                sipral_stack_state_text(stack, p1.baseAddress, p1.count, &needed)
            }
        try check(status)
        return needed
    }

    /// Reserve a free even port from this stack's RTP range, with the odd
    /// port above it kept for RTCP, and write it to `out_port`.
    ///
    /// `SIPRAL_STATUS_EXHAUSTED` when every pair is taken (the last error
    /// gives the range size). `SIPRAL_STATUS_WRONG_STATE` without a range.
    ///
    /// Safety
    ///
    /// `out_port` must point at one `uint32_t`.
    public static func stackRtpPortReserve(stack: SipralHandle) throws -> UInt32 {
        try ensureAbi()
        var port = UInt32()
        let status = sipral_stack_rtp_port_reserve(stack, &port)
        try check(status)
        return port
    }

    /// Give back a reserved port no call used. A port a call took comes back
    /// by itself. `SIPRAL_STATUS_INVALID_ARGUMENT` for one not reserved,
    /// including a second release.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func stackRtpPortRelease(stack: SipralHandle, port: UInt32) throws {
        try ensureAbi()
        let status = sipral_stack_rtp_port_release(stack, port)
        try check(status)
    }

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
    public static func stackStir(stack: SipralHandle, config: sipral_stir_config_t, nowMs: UInt64) throws {
        try ensureAbi()
        var config = config
        let status = sipral_stack_stir(stack, &config, nowMs)
        try check(status)
    }

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
    public static func callStirCertificate(stack: SipralHandle, call: SipralHandle, chain: [UInt8], nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            chain.withUnsafeBufferPointer { p2 in
                sipral_call_stir_certificate(stack, call, p2.baseAddress, p2.count, nowMs)
            }
        try check(status)
    }

    /// How many streams one call's encryption report has (one audio stream).
    ///
    /// Safety
    ///
    /// `out_count` must point at one `size_t`.
    public static func mediaEncryptionCount(media: SipralHandle) throws -> Int {
        try ensureAbi()
        var count = Int()
        let status = sipral_media_encryption_count(media, &count)
        try check(status)
        return count
    }

    /// How one stream of a call is protected now. An index past the end is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT`.
    ///
    /// Safety
    ///
    /// `out_stream` must point at a `sipral_stream_encryption_t` whose `size`
    /// member says how long it is.
    public static func mediaEncryptionAt(media: SipralHandle, index: Int) throws -> sipral_stream_encryption_t {
        try ensureAbi()
        var stream = sipral_stream_encryption_t.sized()
        let status = sipral_media_encryption_at(media, index, &stream)
        try check(status)
        return stream
    }

    /// Listen for keypad digits in the far-end audio as `mode` (a
    /// SipralDtmfDetection) says. `SIPRAL_STATUS_WRONG_STATE` if this
    /// stack does not run the call's media.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func callDtmfDetection(stack: SipralHandle, call: SipralHandle, mode: UInt32) throws {
        try ensureAbi()
        let status = sipral_call_dtmf_detection(stack, call, mode)
        try check(status)
    }

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
    public static func callDetectProgress(stack: SipralHandle, call: SipralHandle, config: sipral_progress_config_t) throws {
        try ensureAbi()
        var config = config
        let status = sipral_call_detect_progress(stack, call, &config)
        try check(status)
    }

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
    public static func callConsentTone(stack: SipralHandle, call: SipralHandle, tone: sipral_consent_tone_t) throws {
        try ensureAbi()
        var tone = tone
        let status = sipral_call_consent_tone(stack, call, &tone)
        try check(status)
    }

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
    public static func mediaRecordStartWith(media: SipralHandle, path: String, options: sipral_recording_options_t) throws {
        try ensureAbi()
        var options = options
        let status =
            Array(path.utf8).withUnsafeBufferPointer { raw1 in
                raw1.withMemoryRebound(to: CChar.self) { p1 in
                    sipral_media_record_start_with(media, p1.baseAddress, p1.count, &options)
                }
            }
        try check(status)
    }

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
    public static func localConferenceCreate(stack: SipralHandle, config: sipral_local_conference_config_t) throws -> SipralHandle {
        try ensureAbi()
        var config = config
        var conference = SipralHandle()
        let status = sipral_local_conference_create(stack, &config, &conference)
        try check(status)
        return conference
    }

    /// End a conference. Its calls carry their own audio again (in device
    /// mode the engine takes them back), a running recording is finished, and
    /// the handle is stale.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func localConferenceDestroy(conference: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_local_conference_destroy(conference)
        try check(status)
    }

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
    public static func localConferenceAdd(conference: SipralHandle, call: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_local_conference_add(conference, call)
        try check(status)
    }

    /// Take a call out, from the next tick. Its media is the application's
    /// again (in device mode, the engine's).
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for a call that is not in it.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func localConferenceRemove(conference: SipralHandle, call: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_local_conference_remove(conference, call)
        try check(status)
    }

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
    public static func localConferenceSetMuted(conference: SipralHandle, member: SipralHandle, direction: UInt32, muted: UInt32) throws {
        try ensureAbi()
        let status = sipral_local_conference_set_muted(conference, member, direction, muted)
        try check(status)
    }

    /// Set one direction's level for a member, from the next tick, in
    /// `sipral_audio_set_gain` steps: 256 unity, 1024 at most. Input is what
    /// others hear of it; output is what it hears.
    ///
    /// Safety
    ///
    /// Safe to call with any handle values.
    public static func localConferenceSetGain(conference: SipralHandle, member: SipralHandle, direction: UInt32, gain: UInt32) throws {
        try ensureAbi()
        let status = sipral_local_conference_set_gain(conference, member, direction, gain)
        try check(status)
    }

    /// How the conference stands.
    ///
    /// Safety
    ///
    /// `out_info` must point at a `sipral_local_conference_info_t` whose
    /// `size` says how long it is.
    public static func localConferenceInfo(conference: SipralHandle) throws -> sipral_local_conference_info_t {
        try ensureAbi()
        var info = sipral_local_conference_info_t.sized()
        let status = sipral_local_conference_info(conference, &info)
        try check(status)
        return info
    }

    /// One member by index: this end first if it takes part, then calls in
    /// join order. Stable until the next join or leave.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for an index past the last member.
    ///
    /// Safety
    ///
    /// `out_member` must point at a `sipral_local_conference_member_t` whose
    /// `size` says how long it is.
    public static func localConferenceMemberAt(conference: SipralHandle, index: Int) throws -> sipral_local_conference_member_t {
        try ensureAbi()
        var member = sipral_local_conference_member_t.sized()
        let status = sipral_local_conference_member_at(conference, index, &member)
        try check(status)
        return member
    }

    /// Who talked in the last tick, loudest at index zero. Muted members are
    /// never listed.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` past the last talker (count in
    /// `sipral_local_conference_info_t::talkers`).
    ///
    /// Safety
    ///
    /// `out_member` must point at one `sipral_handle_t`.
    public static func localConferenceTalkerAt(conference: SipralHandle, index: Int) throws -> SipralHandle {
        try ensureAbi()
        var member = SipralHandle()
        let status = sipral_local_conference_talker_at(conference, index, &member)
        try check(status)
        return member
    }

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
    public static func localConferenceTick(conference: SipralHandle, nowMs: UInt64, mic: [Int16], speaker: inout [Int16]) throws -> Int {
        try ensureAbi()
        var written = Int()
        let status =
            mic.withUnsafeBufferPointer { p2 in
                speaker.withUnsafeMutableBufferPointer { p3 in
                    sipral_local_conference_tick(conference, nowMs, p2.baseAddress, p2.count, p3.baseAddress, p3.count, &written)
                }
            }
        try check(status)
        return written
    }

    /// The oldest packet a member's call owes its far end, in application
    /// mode. `out_call` names the call whose socket sends it; `packet` is
    /// filled as by `sipral_media_capture`. `len` zero with
    /// `SIPRAL_HANDLE_NONE` means nothing waits. Drain after every tick.
    ///
    /// Safety
    ///
    /// `out_call` must point at one `sipral_handle_t`, and `packet` at a
    /// `sipral_media_packet_t` as `sipral_media_capture` describes.
    public static func localConferencePollTransmit(conference: SipralHandle, packet: inout sipral_media_packet_t) throws -> SipralHandle {
        try ensureAbi()
        var call = SipralHandle()
        let status = sipral_local_conference_poll_transmit(conference, &call, &packet)
        try check(status)
        return call
    }

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
    public static func localConferenceRecordStart(conference: SipralHandle, path: String, options: sipral_recording_options_t) throws {
        try ensureAbi()
        var options = options
        let status =
            Array(path.utf8).withUnsafeBufferPointer { raw1 in
                raw1.withMemoryRebound(to: CChar.self) { p1 in
                    sipral_local_conference_record_start(conference, p1.baseAddress, p1.count, &options)
                }
            }
        try check(status)
    }

    /// Stop recording the conference, and finish the file.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when nothing is being recorded.
    ///
    /// Safety
    ///
    /// Safe to call with any handle value.
    public static func localConferenceRecordStop(conference: SipralHandle) throws {
        try ensureAbi()
        let status = sipral_local_conference_record_stop(conference)
        try check(status)
    }

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
    public static func accountLookedUp(stack: SipralHandle, account: SipralHandle, name: String, record: UInt32, answer: UInt32, records: String, nowMs: UInt64) throws {
        try ensureAbi()
        let status =
            Array(name.utf8).withUnsafeBufferPointer { raw2 in
                raw2.withMemoryRebound(to: CChar.self) { p2 in
                    Array(records.utf8).withUnsafeBufferPointer { raw5 in
                        raw5.withMemoryRebound(to: CChar.self) { p5 in
                            sipral_account_looked_up(stack, account, p2.baseAddress, p2.count, record, answer, p5.baseAddress, p5.count, nowMs)
                        }
                    }
                }
            }
        try check(status)
    }

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
    public static func accountCheckCertificate(stack: SipralHandle, account: SipralHandle, certificate: [UInt8], unixSeconds: UInt64) throws -> sipral_pinned_certificate_t {
        try ensureAbi()
        var pinned = sipral_pinned_certificate_t.sized()
        let status =
            certificate.withUnsafeBufferPointer { p2 in
                sipral_account_check_certificate(stack, account, p2.baseAddress, p2.count, unixSeconds, &pinned)
            }
        try check(status)
        return pinned
    }

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
    public static func advertisedAddress(bound: String, peer: String, buffer: inout [CChar]) throws -> Int {
        try ensureAbi()
        var needed = Int()
        let status =
            Array(bound.utf8).withUnsafeBufferPointer { raw0 in
                raw0.withMemoryRebound(to: CChar.self) { p0 in
                    Array(peer.utf8).withUnsafeBufferPointer { raw1 in
                        raw1.withMemoryRebound(to: CChar.self) { p1 in
                            buffer.withUnsafeMutableBufferPointer { p2 in
                                sipral_advertised_address(p0.baseAddress, p0.count, p1.baseAddress, p1.count, p2.baseAddress, p2.count, &needed)
                            }
                        }
                    }
                }
            }
        try check(status)
        return needed
    }

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
    public static func stackDiagnosticTrace(stack: SipralHandle, on: UInt32) throws {
        try ensureAbi()
        let status = sipral_stack_diagnostic_trace(stack, on)
        try check(status)
    }

    /// The SRTP suites calls use by default, in order, as `sipral_srtp_suite_t`
    /// numbers. `out_count` always receives the total; too small a capacity is
    /// `SIPRAL_STATUS_BUFFER_TOO_SMALL`.
    ///
    /// Safety
    ///
    /// `out_suites` must be writable for `capacity` `uint32_t` or null with a
    /// capacity of zero, and `out_count` must point at one `size_t` or be null.
    public static func stackSrtpSuiteOrder(stack: SipralHandle, outSuites: inout [UInt32]) throws -> Int {
        try ensureAbi()
        var count = Int()
        let status =
            outSuites.withUnsafeMutableBufferPointer { p1 in
                sipral_stack_srtp_suite_order(stack, p1.baseAddress, p1.count, &count)
            }
        try check(status)
        return count
    }

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
    public static func audioCallSetGain(stack: SipralHandle, call: SipralHandle, direction: UInt32, gain: UInt32) throws {
        try ensureAbi()
        let status = sipral_audio_call_set_gain(stack, call, direction, gain)
        try check(status)
    }

    /// One call's own gain in one direction, in `sipral_audio_set_gain` steps.
    ///
    /// Safety
    ///
    /// `out_gain` must point at one `uint32_t`.
    public static func audioCallGain(stack: SipralHandle, call: SipralHandle, direction: UInt32) throws -> UInt32 {
        try ensureAbi()
        var gain = UInt32()
        let status = sipral_audio_call_gain(stack, call, direction, &gain)
        try check(status)
        return gain
    }

    /// Mute or unmute one call in one direction while other calls go on (a
    /// consultation). A muted direction sends silence. Kept, dropped and
    /// refused as `sipral_audio_call_set_gain` is, conference included.
    ///
    /// Safety
    ///
    /// Reads no memory the caller owns.
    public static func audioCallSetMuted(stack: SipralHandle, call: SipralHandle, direction: UInt32, muted: UInt32) throws {
        try ensureAbi()
        let status = sipral_audio_call_set_muted(stack, call, direction, muted)
        try check(status)
    }

    /// Whether one call is muted in one direction: one or zero.
    ///
    /// Safety
    ///
    /// `out_muted` must point at one `uint32_t`.
    public static func audioCallMuted(stack: SipralHandle, call: SipralHandle, direction: UInt32) throws -> UInt32 {
        try ensureAbi()
        var muted = UInt32()
        let status = sipral_audio_call_muted(stack, call, direction, &muted)
        try check(status)
        return muted
    }

    /// One call's meter in one direction, after its own gain and mute: what
    /// `sipral_audio_level` reads, for one call of several.
    ///
    /// Safety
    ///
    /// `out_peak` must point at one `uint32_t`.
    public static func audioCallLevel(stack: SipralHandle, call: SipralHandle, direction: UInt32) throws -> UInt32 {
        try ensureAbi()
        var peak = UInt32()
        let status = sipral_audio_call_level(stack, call, direction, &peak)
        try check(status)
        return peak
    }

}
