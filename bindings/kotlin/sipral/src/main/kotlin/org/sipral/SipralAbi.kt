// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Printed from the declarations in crates/sipral-ffi by tools/abi-gen.
// Do not edit: `cargo run -p sipral-abi-gen` writes it again, and
// `scripts/check.sh` fails when what is committed is not what came out.

package org.sipral

/**
 * The result of a call across the C ABI.
 *
 * The numbers are ABI: stable for the major version, new ones only at the
 * end. 17 is reserved forever and never returned.
 *
 * Typed `int32_t`: zero is success, failures are positive, none negative.
 * Read an unknown status from a newer library as a failure.
 */
enum class SipralStatus(val value: Int) {
    /**
     * The call did what it was asked to.
     */
    OK(0),
    /**
     * A pointer was null where one is required, a length disagreed with what
     * it describes, or a value was outside what the call accepts.
     */
    INVALID_ARGUMENT(1),
    /**
     * The handle never came from this library, or it came from a stack
     * other than the one it was used with.
     */
    INVALID_HANDLE(2),
    /**
     * The handle came from this library and what it named is gone: a use
     * after free, or a second free.
     */
    STALE_HANDLE(3),
    /**
     * A versioned struct declared a size this build cannot work with, or a
     * binding asked for an ABI this library does not provide.
     */
    UNSUPPORTED_VERSION(4),
    /**
     * The buffer supplied is too small. The length needed has been written to
     * the out parameter, and nothing was written to the buffer.
     */
    BUFFER_TOO_SMALL(5),
    /**
     * The object is already in use by another call, including one further
     * down the same call stack. Nothing was done, and nothing blocked.
     */
    BUSY(6),
    /**
     * No room: an object table is full, the RTP port range is spent, or a
     * call's queue (DTMF, payload types, real-time text) is full. Nothing
     * was done; the last error says which. `SIPRAL_STATUS_LIMIT_REACHED`
     * is the application's own ceiling.
     */
    EXHAUSTED(7),
    /**
     * A panic was caught at the boundary. The call did not finish; the last
     * error carries the panic's message.
     */
    PANIC(8),
    /**
     * Not possible in the object's current state, e.g. answering a call
     * this end placed, or DTMF before there is a dialog.
     */
    WRONG_STATE(9),
    /**
     * The request could not be assembled or handed to a transport. Nothing
     * went out, and the call did not change.
     */
    NOT_SENT(10),
    /**
     * The value is valid in this ABI but this build has no code for it.
     * Nothing was applied, and retrying will not help. Unlike
     * SipralStatus.INVALID_ARGUMENT, the value is not wrong; unlike
     * SipralStatus.UNSUPPORTED_VERSION, it is not about struct shape.
     * Exists so that nothing is ever silently accepted and ignored.
     */
    NOT_SUPPORTED(11),
    /**
     * A byte stream carried something that starts no known message. A
     * stream has no resync point: close the connection. The last error
     * says what was lost.
     */
    STREAM_BROKEN(12),
    /**
     * An audio device id the engine never listed. Refused before any
     * platform call; `sipral_audio_device_at` lists the ids.
     */
    NO_SUCH_DEVICE(13),
    /**
     * The audio device cannot serve: no channels in that direction,
     * unplugged, or the platform refused it. The last error says which.
     */
    DEVICE_UNUSABLE(14),
    /**
     * The platform did not answer about its audio devices within
     * `sipral_stack_config_t::audio_probe_ms`. Nothing was done.
     */
    DEVICE_TIMED_OUT(15),
    /**
     * The stack already holds or awaits `sipral_stack_config_t::max_dialogs`
     * calls. Nothing went out. An ended call makes room; a higher limit
     * needs a new stack.
     */
    LIMIT_REACHED(16),
    /**
     * Refused by the security policy (ABI 0.31): unencrypted audio where
     * SRTP is required, or a policy weaker than the account's. A refused
     * INVITE was answered 488; an outgoing call never left.
     */
    SECURITY_POLICY(18),
    /**
     * The recording file would not take a write (disk full, volume gone).
     * A bad path is `SIPRAL_STATUS_INVALID_ARGUMENT` instead. The recording
     * stopped; the file holds audio up to the last checkpoint.
     */
    RECORDING_FAILED(19),
    /**
     * The call never negotiated this, e.g. text on a call with no `m=text`
     * stream. Only a new accepted offer changes it.
     */
    NOT_NEGOTIATED(20),
    /**
     * The far end's Contact never carried `isfocus` (RFC 4579 §4.1), so
     * there is no conference to name or subscribe to.
     */
    NOT_A_FOCUS(21),
    /**
     * The transport has failed or closed and was not bound again. Nothing
     * went out. Reconnect, call `sipral_stack_transport_bind`, retry.
     */
    TRANSPORT_DOWN(22),
    /**
     * A local conference would not take the call (ABI 0.32): full, the
     * call is already conferenced or joined with `sipral_call_join`, or its
     * codec rate is not mixed. The last error says which.
     */
    CONFERENCE_REFUSED(23),
    /**
     * `now_ms` was more than 50 ms behind the last reading this stack saw
     * (ABI 0.33). Nothing was done and the clock did not move; read the
     * clock again and retry. Repeated, it means the clock went backwards.
     */
    CLOCK_BEHIND(24),
    /**
     * The TLS certificate's SHA-256 fingerprint differs from
     * `sipral_account_config_t::tls_pin_sha256` (ABI 0.34). Refuse the
     * handshake (`docs/22-tls.md`).
     */
    CERTIFICATE_REFUSED(25),
    /**
     * About to advertise an address the peer cannot reach (ABI 0.34):
     * loopback to a remote peer, or the unspecified address in a `Contact`.
     * Nothing was sent; the last error names both addresses.
     * `sipral_advertised_address` finds the right one.
     */
    UNREACHABLE_ADDRESS(26),
    ;

    companion object {
        fun of(value: Int): SipralStatus? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a stack speaks. Names for `sipral_stack_config_t::transport`. Zero is
 * not one, so a caller who meant TLS is never put on the wire in the clear.
 */
enum class SipralTransport(val value: Int) {
    /**
     * UDP.
     */
    UDP(1),
    /**
     * TCP.
     */
    TCP(2),
    /**
     * TLS over TCP.
     */
    TLS(3),
    /**
     * WebSocket.
     */
    WS(4),
    /**
     * WebSocket over TLS.
     */
    WSS(5),
    ;

    companion object {
        fun of(value: Int): SipralTransport? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Why a transport could not deliver. Names for sipral_stack_transport_failed's `error`.
 *
 * Coarse on purpose: a client transaction terminates on every one of these (§17); the
 * detail belongs in the caller's log.
 */
enum class SipralTransportError(val value: Int) {
    /**
     * Anything the caller could not classify.
     */
    OTHER(0),
    /**
     * Nothing is listening at the far end.
     */
    CONNECTION_REFUSED(1),
    /**
     * An established connection was reset.
     */
    CONNECTION_RESET(2),
    /**
     * No route, or an ICMP unreachable.
     */
    UNREACHABLE(3),
    /**
     * The connection attempt or the write timed out.
     */
    TIMED_OUT(4),
    /**
     * The connection was closed and cannot be written to again.
     */
    CLOSED(5),
    ;

    companion object {
        fun of(value: Int): SipralTransportError? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Why a TLS connection was refused, as the platform's TLS library said it. Names for
 * `sipral_transport_failure_t::tls` and `sipral_transport_failed_event_t::tls`.
 *
 * Sipral links no TLS library (`docs/22-tls.md`); the stack only carries the application's
 * classification. A connection never answered is `SIPRAL_TRANSPORT_ERROR_CONNECTION_REFUSED`
 * with this left at none.
 */
enum class SipralTlsFailure(val value: Int) {
    /**
     * Not a TLS failure, or one the application could not classify.
     */
    NONE(0),
    /**
     * No trusted authority: self-signed, an unprovided private CA, or not the pinned one.
     */
    UNTRUSTED(1),
    /**
     * The certificate is trusted and names another server.
     */
    NAME_MISMATCH(2),
    /**
     * The certificate has expired, or is not valid yet.
     */
    EXPIRED(3),
    /**
     * The handshake failed: no common version or cipher, a server alert, or no TLS there.
     */
    HANDSHAKE_REFUSED(4),
    ;

    companion object {
        fun of(value: Int): SipralTlsFailure? = entries.firstOrNull { it.value == value }
    }
}

/**
 * The three answers a setting can give in a struct that starts out zeroed.
 *
 * Not a boolean: zero must mean "unset", so the library never turns a
 * control off because the caller left it zeroed.
 */
enum class SipralToggle(val value: Int) {
    /**
     * Nothing was said; whatever this build defaults to.
     */
    DEFAULT(0),
    /**
     * On.
     */
    ON(1),
    /**
     * Off.
     */
    OFF(2),
    ;

    companion object {
        fun of(value: Int): SipralToggle? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a call or a stack says about SRTP. Names for
 * `sipral_stack_config_t::srtp` (the stack's default) and
 * `sipral_call_config_t::srtp` (a per-call override).
 *
 * Zero means "unset": on the stack, the built-in default
 * SipralSrtp.NOT_OFFERED; on a call, the stack's setting.
 * `docs/05-media.md` details each value.
 */
enum class SipralSrtp(val value: Int) {
    /**
     * Do not offer it, but answer an offer on the secure profile with keys.
     */
    NOT_OFFERED(1),
    /**
     * Offer it, and answer a plain offer plainly.
     */
    OFFERED(2),
    /**
     * Offer it, and let no stream on this call carry audio unencrypted.
     */
    REQUIRED(3),
    /**
     * Offer DTLS-SRTP (RFC 5764) on `UDP/TLS/RTP/SAVP`, and answer a plain
     * offer plainly.
     *
     * The key never travels in the body, so this is sound over a readable
     * SIP transport. Costs a round trip of silence at call start. The
     * application **must** drain sipral_media_poll_transmit, or the
     * call is up, silent, and reports no error.
     *
     * `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
     * `SIPRAL_FEATURE_DTLS_SRTP`.
     */
    DTLS(4),
    /**
     * Offer DTLS-SRTP and allow no other keying, including an answer
     * carrying `a=crypto`.
     */
    DTLS_REQUIRED(5),
    /**
     * DTLS-SRTP with SDES fallback, never unencrypted. The offer is one
     * `RTP/SAVP` stream with both fingerprint and crypto lines; the answer
     * decides. An incoming offer is answered the way it was keyed; a plain
     * one is refused with 488.
     *
     * `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
     * `SIPRAL_FEATURE_DTLS_SRTP`.
     */
    DTLS_OR_SDES(6),
    /**
     * Offer SDES on plain `RTP/AVP` ("SRTP optional"): encrypted when the
     * answer takes an `a=crypto` line, plain otherwise. For servers that
     * reject `RTP/SAVP` with 488. Not standard (RFC 4568 defines the
     * attribute for secure profiles). An incoming `RTP/AVP` offer with a
     * usable line is answered with a key, anything else as `Offered`.
     */
    BEST_EFFORT(7),
    ;

    companion object {
        fun of(value: Int): SipralSrtp? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a call or a stack says about ICE. Names for
 * `sipral_stack_config_t::ice` (the stack's default) and
 * `sipral_call_config_t::ice` (a per-call override).
 *
 * Zero means "unset": on the stack, the built-in default
 * SipralIce.OFF; on a call, the stack's setting.
 *
 * A call that offers ICE also asks for RFC 5761 multiplexing, whatever
 * `offer_rtcp_mux` says: this ABI names one address per stream.
 */
enum class SipralIce(val value: Int) {
    /**
     * Do not offer it, and do not answer a peer that does. The default;
     * `docs/06-nat.md` says why.
     */
    OFF(1),
    /**
     * Offer it, and use it against a peer that offers it back.
     *
     * A peer without ICE gets the call on the signalled address and
     * symmetric RTP. The application **must** drain
     * sipral_media_poll_transmit, or no path is ever chosen.
     *
     * `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
     * `SIPRAL_FEATURE_ICE`.
     */
    OFFERED(2),
    /**
     * Offer it, and let no stream carry audio on a path ICE did not check.
     *
     * A peer that fails ICE ends the call's media with
     * `SIPRAL_EVENT_KIND_MEDIA_FAILED` instead of falling back.
     */
    REQUIRED(3),
    /**
     * Be an ICE-lite endpoint (RFC 8445 §2.5): `a=ice-lite`, one host
     * candidate, answer a full peer's checks, use the pair it nominates.
     *
     * **Only for a server reachable at the address it advertises** (its
     * own, or a one-to-one NAT's via `sipral_stack_nat_map`); never for a
     * softphone. RFC 8445 Appendix A: lite "will not function when a lite
     * implementation is placed behind a NAT". A peer with no ICE, or lite
     * itself, gets the signalled address. The application still drains
     * `sipral_media_poll_transmit` for check answers.
     *
     * `SIPRAL_STATUS_NOT_SUPPORTED` in a build without
     * `SIPRAL_FEATURE_ICE`.
     */
    LITE(4),
    ;

    companion object {
        fun of(value: Int): SipralIce? = entries.firstOrNull { it.value == value }
    }
}

/**
 * One codec this ABI has a number for.
 *
 * Values are permanent. Whether this build contains a codec is answered by
 * `SIPRAL_FEATURE_*` and `sipral_codec_at`, not by this list.
 */
enum class SipralCodec(val value: Int) {
    /**
     * No codec: the call has none, or the event is not about one.
     */
    UNKNOWN(0),
    /**
     * G.711 mu-law, payload type 0.
     */
    PCMU(1),
    /**
     * G.711 A-law, payload type 8.
     */
    PCMA(2),
    /**
     * G.722, wideband at the price of a narrowband stream.
     */
    G722(3),
    /**
     * Opus. Declared in every build; presence is `SIPRAL_FEATURE_OPUS`.
     */
    OPUS(4),
    /**
     * G.729 Annex A, payload type 18. Offered only when a codec order names
     * `G729`; offers `annexb=yes`, answers with the offer's `annexb`.
     */
    G729(5),
    /**
     * L16 at 8 kHz mono, dynamic payload type `L16/8000`. Offered only
     * when a codec order names it.
     */
    L16_NARROWBAND(6),
    /**
     * L16 at 16 kHz mono, `L16/16000`. Offered only when a codec order
     * names it.
     */
    L16_WIDEBAND(7),
    ;

    companion object {
        fun of(value: Int): SipralCodec? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What became of one codec this call's catalogue could have used. Names
 * for SipralCodecCandidate.outcome.
 */
enum class SipralCodecOutcome(val value: Int) {
    /**
     * Not an outcome: unknown to this ABI, or the struct was never filled.
     */
    UNKNOWN(0),
    /**
     * What the call agreed on. Exactly one candidate carries it, the same
     * codec as `sipral_media_info_t::codec`.
     */
    CHOSEN(1),
    /**
     * The far end's description did not name it.
     */
    NOT_NAMED(2),
    /**
     * The far end named it and this end had something better: the codec
     * in `outranked_by` came first in this call's order.
     */
    OUTRANKED(3),
    ;

    companion object {
        fun of(value: Int): SipralCodecOutcome? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Whether a SipralPathCandidate is a candidate pair or a relay.
 */
enum class SipralPathKind(val value: Int) {
    /**
     * Not a kind: the struct was never filled in.
     */
    UNKNOWN(0),
    /**
     * A candidate pair the call's ICE checklist held (RFC 8445
     * §6.1.2).
     */
    PAIR(1),
    /**
     * An allocation on a TURN server the call's agent held (RFC 8656).
     */
    RELAY(2),
    ;

    companion object {
        fun of(value: Int): SipralPathKind? = entries.firstOrNull { it.value == value }
    }
}

/**
 * The kind of an ICE candidate (RFC 8445 §5.1.1). Names for
 * SipralPathCandidate.localKind and `remote_kind`.
 */
enum class SipralCandidateKind(val value: Int) {
    /**
     * Not known: a relay's server, which is no candidate, or the far
     * end of a pair a lite end took from a nomination and never learned
     * the kind of.
     */
    UNKNOWN(0),
    /**
     * An address a socket of the host's own is bound to.
     */
    HOST(1),
    /**
     * The address a NAT maps the host's socket to, as a STUN or TURN
     * server saw it.
     */
    SERVER_REFLEXIVE(2),
    /**
     * An address a connectivity check revealed (RFC 8445 §7.3.1.3).
     */
    PEER_REFLEXIVE(3),
    /**
     * An address on a TURN server that relays for the host.
     */
    RELAYED(4),
    ;

    companion object {
        fun of(value: Int): SipralCandidateKind? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What became of one path a call's ICE agent tried. Names for
 * SipralPathCandidate.outcome.
 */
enum class SipralPathOutcome(val value: Int) {
    /**
     * Not an outcome: unknown to this ABI, or the struct was never filled.
     */
    UNKNOWN(0),
    /**
     * The path the call's media takes: the selected pair (RFC 8445
     * §8.1.2), or the relay it runs through.
     */
    SELECTED(1),
    /**
     * A pair whose check succeeded, with nothing selected yet.
     */
    VALID(2),
    /**
     * Nothing has decided it yet: a pair frozen, waiting its turn or
     * with its check on the wire; a relay still being allocated.
     */
    WAITING(3),
    /**
     * A pair whose check succeeded, with a pair of higher priority
     * selected over it.
     */
    OUTRANKED(4),
    /**
     * A pair another was nominated ahead of: its check had not finished
     * when the selection took it off the checklist (RFC 8445 §8.1.2),
     * or it succeeded after a lower one was nominated.
     */
    NOMINATED_ELSEWHERE(5),
    /**
     * A pair whose check was never answered (RFC 8489 §6.2.1).
     */
    TIMED_OUT(6),
    /**
     * A pair the far end refused; `code` is the STUN error code (RFC
     * 8445 §7.2.5.2.4).
     */
    REFUSED(7),
    /**
     * A pair whose answer came from an address other than the one its
     * check went to (RFC 8445 §7.2.5.2.1): a NAT between rewriting it.
     */
    NOT_SYMMETRIC(8),
    /**
     * A pair whose answer named no address to form a valid pair from.
     */
    UNUSABLE(9),
    /**
     * A relayed pair the relay would not let the far end through for,
     * or a relay whose allocation the server refused; `code` is the
     * TURN server's error code, zero when it gave none (RFC 8656 §9,
     * §7.3).
     */
    RELAY_REFUSED(10),
    /**
     * A pair never checked: the pair limit discarded it (RFC 8445
     * §6.1.2.5), or its checklist ended before its turn came.
     */
    NOT_CHECKED(11),
    /**
     * A relay held, that no selected pair runs through — or none yet.
     */
    HELD(12),
    /**
     * A relay given back: ICE concluded on a pair that does not use it
     * (RFC 8445 §8.3.1), or this branch of a forked call let go of it.
     */
    RELEASED(13),
    /**
     * A relay the server took back; `code` is its error code, zero when
     * a refresh went unanswered (RFC 8656 §8).
     */
    LOST(14),
    ;

    companion object {
        fun of(value: Int): SipralPathOutcome? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Which way audio may flow, as seen from here. Names for every `direction`.
 */
enum class SipralDirection(val value: Int) {
    /**
     * Not negotiated.
     */
    UNKNOWN(0),
    /**
     * Both ways.
     */
    SEND_RECV(1),
    /**
     * This end sends and does not receive, which is what holding the far end
     * looks like from here.
     */
    SEND_ONLY(2),
    /**
     * This end receives and does not send.
     */
    RECV_ONLY(3),
    /**
     * Neither way, and the stream stays in the session.
     */
    INACTIVE(4),
    ;

    companion object {
        fun of(value: Int): SipralDirection? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Where control traffic goes. Names for SipralMediaInfo.rtcp.
 */
enum class SipralRtcp(val value: Int) {
    /**
     * Not negotiated.
     */
    UNKNOWN(0),
    /**
     * One port carries both (RFC 5761), which happens only where both ends
     * asked for it.
     */
    MUXED(1),
    /**
     * A port of its own at each end.
     */
    SEPARATE_PORT(2),
    /**
     * None at all: the peer said it is not using RTCP.
     */
    OFF(3),
    ;

    companion object {
        fun of(value: Int): SipralRtcp? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Why media failed, for a machine to act on. Names for
 * `sipral_media_event_t::fault`.
 */
enum class SipralMediaFault(val value: Int) {
    /**
     * Nothing failed.
     */
    NONE(0),
    /**
     * The peer answered with a format this build cannot encode or decode.
     */
    UNSUPPORTED_CODEC(1),
    /**
     * The two descriptions agree on nothing that can carry audio.
     */
    NO_COMMON_CODEC(2),
    /**
     * One end refused the stream with a port of zero. The call is up and
     * carries no audio, which is a thing a peer is allowed to want.
     */
    STREAM_REFUSED(3),
    /**
     * There is no session description to work from.
     */
    NO_DESCRIPTION(4),
    /**
     * A description could not be read.
     */
    BAD_DESCRIPTION(5),
    /**
     * The recording stopped writing: the disk filled, the file went away.
     */
    RECORDING(6),
    /**
     * The codec refused a frame.
     */
    CODEC(7),
    /**
     * Something else the layer below reported and this ABI has no word for.
     */
    OTHER(8),
    /**
     * ICE could not carry this call: the far end described none this
     * stack could use and the policy was `SIPRAL_ICE_REQUIRED`, the far
     * end took `a=rtcp-mux` out of an answer to an ICE offer, or consent
     * to send on the pair that was chosen was withdrawn part-way through
     * (RFC 7675 §5). Signalling is still sound; an application may fall
     * back to a non-ICE profile.
     */
    ICE(9),
    /**
     * The SRTP policy refused the far end's description: a plain answer
     * (hung up with `Reason` 488) or a plain re-offer (refused with 488,
     * old keys kept).
     */
    SECURITY_POLICY(10),
    ;

    companion object {
        fun of(value: Int): SipralMediaFault? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a datagram handed to sipral_media_receive turned out to be.
 */
enum class SipralArrival(val value: Int) {
    /**
     * Something this ABI has no word for.
     */
    UNKNOWN(0),
    /**
     * Audio, held for playout.
     */
    QUEUED(1),
    /**
     * Audio that was not used: malformed, late, duplicated, from the wrong
     * address, or on a payload type nobody negotiated. The counters in
     * SipralStreamStats say which, over the call.
     */
    DROPPED(2),
    /**
     * A reception or sender report, folded into the statistics.
     */
    CONTROL(3),
    /**
     * The far end says it is leaving the session (RFC 3550 §6.6). Audio will
     * stop; the call has not ended until signalling says so.
     */
    GOODBYE(4),
    /**
     * Control traffic that was not believed: from the wrong address, or not a
     * well-formed compound packet.
     */
    CONTROL_REFUSED(5),
    /**
     * A DTLS-SRTP handshake record, taken. Drain
     * sipral_media_poll_transmit for the reply.
     */
    HANDSHAKE(6),
    /**
     * Arrived on an encrypted call before its keys exist; usually a peer
     * that sends as soon as its half of the handshake ends.
     */
    NOT_KEYED(7),
    ;

    companion object {
        fun of(value: Int): SipralArrival? = entries.firstOrNull { it.value == value }
    }
}

/**
 * The SRTP transform a call is running. Names for
 * `sipral_media_event_t::suite`.
 */
enum class SipralSrtpSuite(val value: Int) {
    /**
     * No transform: the event is not about one, or the call is not
     * encrypted.
     */
    UNKNOWN(0),
    /**
     * `AES_CM_128_HMAC_SHA1_80`, the one every implementation has.
     */
    AES_CM80(1),
    /**
     * `AES_CM_128_HMAC_SHA1_32`, the same cipher with a shorter tag.
     */
    AES_CM32(2),
    /**
     * `F8_128_HMAC_SHA1_80`, which is what 3GPP asks for. Reachable by
     * SDES only; RFC 5764 §4.1.2 defines no DTLS-SRTP profile for it.
     */
    AES_F8(3),
    /**
     * `AES_256_CM_HMAC_SHA1_80` (RFC 6188). SDES only.
     */
    AES256_CM80(4),
    /**
     * `AES_256_CM_HMAC_SHA1_32` (RFC 6188). SDES only.
     */
    AES256_CM32(5),
    /**
     * `AEAD_AES_128_GCM` (RFC 7714). DTLS-SRTP profile 0x0007.
     */
    AEAD_AES128_GCM(6),
    /**
     * `AEAD_AES_256_GCM` (RFC 7714). DTLS-SRTP profile 0x0008, preferred
     * between two ends of this stack.
     */
    AEAD_AES256_GCM(7),
    ;

    companion object {
        fun of(value: Int): SipralSrtpSuite? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Where the frame sipral_media_playback just produced came from.
 */
enum class SipralPlayback(val value: Int) {
    /**
     * Something this ABI has no word for.
     */
    UNKNOWN(0),
    /**
     * A packet the far end sent.
     */
    PACKET(1),
    /**
     * One it sent and this end did not get, filled in by the concealment.
     */
    CONCEALED(2),
    /**
     * Comfort noise, from an RFC 3389 payload the far end sent instead of
     * audio.
     */
    COMFORT_NOISE(3),
    /**
     * Nothing was due: the buffer is still filling, or the far end has
     * stopped.
     */
    SILENCE(4),
    ;

    companion object {
        fun of(value: Int): SipralPlayback? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Which way a digit goes to the far end: sipral_call_send_dtmf's `via`. Chosen per
 * send, since it is a fact about the peer, and a peer ignores an unsupported one silently.
 */
enum class SipralDtmf(val value: Int) {
    /**
     * In the media, as an RFC 4733 telephone event: the one to reach for, carried end to
     * end and surviving transcoding. One, not zero: zero is an unfilled field, refused.
     */
    RTP(1),
    /**
     * An INFO per digit carrying `application/dtmf-relay`, which states the
     * signal and how long it was held.
     */
    INFO_RELAY(2),
    /**
     * An INFO per digit carrying `application/dtmf`, whose whole body is the
     * character. Some switches take only this one.
     */
    INFO_PLAIN(3),
    /**
     * In the media, as the key's two tones written into the audio in place of the microphone,
     * for a far end that listens only to the audio. `SIPRAL_DTMF_RTP` falls back to this on a
     * call with no telephone event.
     */
    IN_BAND(4),
    ;

    companion object {
        fun of(value: Int): SipralDtmf? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What an event is about. Numbers are only ever added; a binding must
 * ignore a kind it does not know.
 *
 * Numbers already spent on features this build does not have:
 * - 16: held for the set of audio devices changed (A2), which shipped as 43 in the wave that allocated its number; spent all the same
 * - 44: held for a second audio device event, which the audio engine did not need; spent all the same
 */
enum class SipralEventKind(val value: Int) {
    /**
     * The stack is running on this thread: the first event, delivered
     * once by the first poll.
     */
    STARTED(1),
    /**
     * A registration moved. `payload.registration` says how, and
     * `account` says whose.
     */
    REGISTRATION_CHANGED(2),
    /**
     * Somebody is calling. Answer, ring, or reject it.
     */
    INCOMING_CALL(3),
    /**
     * A call this end placed is getting somewhere short of an answer.
     */
    CALL_PROGRESS(4),
    /**
     * A proxy forked the INVITE and a second phone is ringing.
     * `payload.call.other` is the branch that has just appeared.
     */
    CALL_FORKED(5),
    /**
     * The call is up.
     */
    CALL_CONFIRMED(6),
    /**
     * The session inside a live call changed: a hold, a resume, or an offer
     * either end made and had accepted.
     */
    SESSION_CHANGED(7),
    /**
     * The far end offered a change this stack has no policy for. The
     * transaction is held open: answer it or refuse it, or the call ends.
     */
    SESSION_OFFERED(8),
    /**
     * A change this end offered was refused. The session stands as it was.
     */
    SESSION_CHANGE_FAILED(9),
    /**
     * The far end asked this one to call somebody else.
     */
    TRANSFER_REQUESTED(10),
    /**
     * A transfer this end asked for is under way.
     */
    TRANSFER_PROGRESS(11),
    /**
     * And how it ended: the far end's final status, a 2xx hanging this
     * call up. A refused REFER (RFC 3515 §2.4.2) ends here with its status,
     * a timeout as 408, a transport failure as 503; the call stays up.
     */
    TRANSFER_DONE(12),
    /**
     * A call arrived carrying a `Replaces` and took over one already up.
     * `payload.call.other` is the one being replaced.
     */
    CALL_REPLACED(13),
    /**
     * The call is over; its handle is stale from here on. `message` is
     * the refusal, or the far end's BYE or CANCEL, or null.
     */
    CALL_ENDED(14),
    /**
     * A1. A subscription moved: asked for, granted, on probation,
     * retrying, or ended. `payload.subscription` says which and where it
     * is, `reason` why it is not live. Not sent per refresh or per NOTIFY.
     */
    SUBSCRIPTION_CHANGED(15),
    /**
     * A6. What one call's media cost, once, after
     * `SIPRAL_EVENT_KIND_CALL_ENDED`. `payload.media.statistics` points
     * at the record, library-owned and valid for the callback.
     */
    MEDIA_STATISTICS(17),
    /**
     * B1. A request grew too large for a datagram (RFC 3261 §18.1.1) and
     * no stream transport is open to its destination; it was refused with
     * `SIPRAL_STATUS_NOT_SENT`. `payload.transport_wanted` says where.
     * Bind with
     * sipral_stack_transport_bind
     * and ask again.
     */
    TRANSPORT_WANTED(18),
    /**
     * B5. No media has arrived for longer than the configured threshold.
     * `payload.media.silent_for_ms` says how long. The call is left up.
     */
    MEDIA_STALLED(19),
    /**
     * C2. A call a push announced never arrived: the device woke and
     * refreshed, and no INVITE followed. `payload.announce` says which
     * announcement and how long it was waited for.
     */
    ANNOUNCED_CALL_MISSING(20),
    /**
     * A4, D5. Audio is running; `payload.media.codec` is the agreed codec.
     * Mint the media handle now with `sipral_call_media`.
     */
    MEDIA_STARTED(21),
    /**
     * The session changed under a live call: a hold, a resume, a peer that
     * moved its media address, or a re-negotiation onto another codec.
     */
    MEDIA_CHANGED(22),
    /**
     * Packets are arriving again. `payload.media.silent_for_ms` says how long
     * the gap turned out to be.
     */
    MEDIA_RESUMED(23),
    /**
     * Media could not be started or could not be kept. The call itself is
     * untouched; `payload.media.fault` and `payload.media.reason` say why.
     */
    MEDIA_FAILED(24),
    /**
     * A recording stopped on its own (disk full, file gone).
     * `payload.media.recorded_ms` says how much was written.
     */
    RECORDING_STOPPED(25),
    /**
     * The far end pressed a key (RFC 4733 event, or INFO with
     * `application/dtmf-relay` or `application/dtmf`), one per press.
     * `payload.media` gives `digit`, `event_code`, `held_ms` and `source`.
     * `held_ms` zero means no duration or `Duration=0`, not told apart.
     */
    DIGIT_RECEIVED(26),
    /**
     * An INFO from `sipral_call_send_dtmf` got a final answer:
     * `payload.call.digit` and `payload.call.status_code` (415: try the
     * other INFO form). An unsendable queued digit reports 503 and stops
     * the rest.
     */
    DTMF_SENT(27),
    /**
     * The lifecycle ladder settled: a path proved again, or every rung
     * failed. `payload.recovery` says which (`docs/16-lifecycle.md`).
     */
    RECOVERY(28),
    /**
     * A dialog's next hop is a name to resolve (RFC 3263 §4 TARGET).
     * Answer with
     * sipral_stack_resolved
     * and `payload.resolve.dialog`. **Ignoring it is fine**: the dialog
     * keeps its first flow (§8.1.2), which survives a NAT.
     */
    RESOLVE_NEEDED(29),
    /**
     * A1. A notification arrived and was answered; the NOTIFY is in
     * `message`. `payload.subscription.has_dialog_info` says the body was
     * readable dialog-info, read via
     * sipral_subscription_dialog_count.
     * An unreadable body arrives with it zero; the old picture is kept.
     */
    NOTIFIED(30),
    /**
     * C2. The INVITE for a call a push announced arrived (RFC 8599),
     * queued just before its SipralEventKind.INCOMING_CALL.
     * `payload.announce.announcement` is now spent:
     * `sipral_announcement_forget` answers `SIPRAL_STATUS_WRONG_STATE`.
     */
    CALL_ANNOUNCED(31),
    /**
     * The DTLS-SRTP handshake finished and audio can move (RFC 5764).
     * `payload.media.suite` is the chosen transform. SDES calls never
     * raise it; a failed handshake raises `SIPRAL_EVENT_KIND_MEDIA_FAILED`
     * and leaves the call up.
     */
    MEDIA_SECURED(32),
    /**
     * ICE chose this call's media path (RFC 8445 §8.1.1), and audio can
     * move; again if a higher-priority pair replaces it. Addresses are not
     * carried: each outgoing packet names its destination. Never raised
     * without ICE (default `SIPRAL_ICE_OFF`).
     */
    MEDIA_PATH_CHOSEN(33),
    /**
     * A MESSAGE arrived (RFC 3428 §7) and was answered 200.
     * `payload.message` carries the body; `call` is set if it was in-dialog.
     */
    MESSAGE_RECEIVED(34),
    /**
     * A MESSAGE from `sipral_account_message` got its final answer:
     * `payload.message.status_code` (408/503 for timeout or transport).
     */
    MESSAGE_SENT(35),
    /**
     * A `message-summary` NOTIFY reported a mailbox (RFC 3842 §3.9);
     * `payload.message` has the `voice-message` counts.
     */
    MESSAGES_WAITING(36),
    /**
     * The RFC 6035 quality report PUBLISH was attempted once, after
     * `SIPRAL_EVENT_KIND_CALL_ENDED`, if `quality_report_uri` was set.
     * `payload.media.quality_report_sent` says it left, not that it landed.
     */
    QUALITY_REPORT_SENT(37),
    /**
     * The call this one was joined to ended. `call` is the survivor and
     * carries on unjoined, fed directly rather than by `sipral_media_mix`.
     */
    MEDIA_UNJOINED(38),
    /**
     * A STUN server reported, moved or never answered for a socket
     * (RFC 8489). Only with `SIPRAL_NAT_STUN`. `payload.nat` says which.
     * Signalling sockets are already re-registered; a media socket from
     * `sipral_stack_nat_map` is now usable for calls (before, that is
     * `SIPRAL_STATUS_WRONG_STATE`). `account`, `call`: none.
     */
    NAT_MAPPING(39),
    /**
     * A TURN server allocated a relay for a `sipral_stack_nat_map` socket,
     * or gave none (RFC 8656). Only with a `turn_server`. `payload.relay`
     * says which; once allocated, calls may use it (before, that is
     * `SIPRAL_STATUS_WRONG_STATE`). `account`, `call`: none.
     */
    NAT_RELAY(40),
    /**
     * An out-of-dialog REFER asks this end to place a call (RFC 3515),
     * with `sipral_stack_config_t::referrals` on. `call` is the referral's
     * handle, taken only by `sipral_call_accept_transfer` (202, places the
     * call) or `sipral_call_reject_transfer`; either spends it. `account`
     * is the line, `message` the REFER, `payload.referral` the target.
     * **The application decides each time**: `referred_by` is unverified.
     * If left unanswered, raised again with only `status_code` set, and
     * the handle is stale.
     */
    REFERRAL(41),
    /**
     * A media socket's TCP/TLS connection to a TURN server
     * (`turn_transport`, RFC 8656 §3.1) is to be opened or closed.
     * `payload.turn_stream` says which. On `SIPRAL_TURN_STREAM_OPEN`, open
     * it (TLS checked against the server name), then call
     * `sipral_stack_turn_connected`, `sipral_stack_turn_receive` and
     * `sipral_stack_turn_closed`. On `SIPRAL_TURN_STREAM_CLOSE`, flush and
     * close. `account`, `call`: none.
     */
    TURN_STREAM(42),
    /**
     * The audio engine's devices moved (with `SIPRAL_AUDIO_DEVICE`).
     * `payload.audio` says what and whether the system or the engine did
     * it. `account`, `call`: none.
     */
    AUDIO_DEVICES_CHANGED(43),
    /**
     * The network changed and this call's media address is gone. Raised
     * per call by `sipral_stack_network_changed` on
     * `SIPRAL_RECOVERY_REBUILD`: after `sipral_account_rebind`, pass a new
     * socket address to `sipral_call_media_readdress`.
     */
    CALL_ADDRESS_WANTED(45),
    /**
     * The STUN server in use changed, or all failed
     * (`payload.stun_server`). A server fails after 5.5 s and is skipped
     * for 30 s, doubling up to ten minutes. Sockets move on by themselves.
     * `account`, `call`: none.
     */
    STUN_SERVER(46),
    /**
     * Caller verification (RFC 8224, RFC 8588); `payload.verification`.
     * `CERTIFICATE_WANTED`: fetch `certificate_url` and pass it (or
     * nothing) to `sipral_call_stir_certificate`; the call waits.
     * `VERIFIED`: the verdict, just before the call's
     * `SIPRAL_EVENT_KIND_INCOMING_CALL`, or with `refused` set before its
     * `SIPRAL_EVENT_KIND_CALL_ENDED`. `message` is the INVITE.
     */
    CALLER_VERIFICATION(47),
    /**
     * A keypad digit heard as tones (with DTMF detection enabled), once
     * per press. A press also sent as a named event is reported once as
     * `SIPRAL_EVENT_KIND_DIGIT_RECEIVED`; tones alone wait 250 ms.
     */
    IN_BAND_DIGIT(48),
    /**
     * What `sipral_call_detect_progress` heard: a progress tone, the
     * special information tone, who answered, or a machine's beep
     * (`payload.progress`).
     */
    PROGRESS_DETECTED(49),
    /**
     * A `conference` subscription's picture changed or the conference
     * ended (RFC 4575 §4.6); `payload.conference`. Read the picture with
     * `sipral_subscription_conference`. Out-of-order documents raise
     * nothing; after a loss the stack asks for full state.
     */
    CONFERENCE_CHANGED(50),
    /**
     * Real-time text from the far end (RFC 4103), in order, UTF-8 in
     * `payload.text`: BACKSPACE erases, U+2028 is a new line, BELL alerts,
     * U+FFFD marks each unrecovered lost block (§5.3), counted in `missing`.
     */
    TEXT_RECEIVED(51),
    /**
     * Presence moved: a `presence` subscription's PIDF (RFC 3856), or this
     * account's publication (RFC 3903). `payload.presence.kind` says
     * which.
     */
    PRESENCE_CHANGED(52),
    /**
     * A signalling transport stopped: reported failed or closed, bad
     * stream bytes, or a keep-alive unanswered for ten seconds (RFC 5626
     * §4.4.1). `payload.transport_failed` says why. Until
     * `sipral_stack_transport_bind` restores it, requests get
     * `SIPRAL_STATUS_TRANSPORT_DOWN`. `account`, `call`: none.
     */
    TRANSPORT_FAILED(53),
    /**
     * A local conference changed: membership, talkers, or recording
     * (`payload.local_conference`). `account`, `call`: none.
     */
    LOCAL_CONFERENCE_CHANGED(54),
    /**
     * A DNS lookup is wanted to locate an account's server (RFC 3263).
     * Pass every answer, failures included, to `sipral_account_looked_up`.
     */
    LOOKUP_WANTED(55),
    /**
     * An account's server was located: `payload.locate.targets`, the
     * address in use first.
     */
    LOCATED(56),
    /**
     * Locating an account's server failed; `retry_in_ms` says when it
     * retries. An earlier address stays in use.
     */
    LOCATE_FAILED(57),
    /**
     * A challenge was not answered because it came from outside the
     * account's protection domain (RFC 3261 §22.1): an answer would feed
     * an offline password guess. `payload.challenge` says who and why.
     */
    CHALLENGE_DECLINED(58),
    /**
     * The account's server wants an OAuth 2.0 token (RFC 8898) and has
     * none acceptable. Check `payload.token.authz_server` against trusted
     * servers (§2.1.1), then pass a token to
     * `sipral_account_set_access_token`.
     */
    TOKEN_REQUIRED(59),
    /**
     * A `sipral_stack_network_test` finished; `payload.network_test`.
     */
    NETWORK_TEST(60),
    ;

    companion object {
        fun of(value: Int): SipralEventKind? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Where a registration is. Names for `sipral_registration_event_t::state`.
 */
enum class SipralRegistrationState(val value: Int) {
    /**
     * The account is gone, or has never been asked about.
     */
    UNKNOWN(0),
    /**
     * Configured and not registered. Nothing has been sent.
     */
    IDLE(1),
    /**
     * A REGISTER is in flight and there is no binding yet.
     */
    REGISTERING(2),
    /**
     * The registrar holds a binding.
     */
    REGISTERED(3),
    /**
     * A refresh is in flight. The binding stands until it is answered.
     */
    REFRESHING(4),
    /**
     * Something recoverable went wrong and the next attempt is scheduled.
     */
    RETRYING(5),
    /**
     * The binding was given up on purpose.
     */
    UNREGISTERED(6),
    /**
     * The registrar refused in a way that trying again cannot fix.
     */
    FAILED(7),
    /**
     * A binding a registrar granted, over a transport since suspended or
     * lost, which nothing has proved since.
     *
     * A monotonic clock does not advance while a machine sleeps, so after
     * sleep every binding would otherwise look valid. Do not show the line
     * as ready in this state.
     */
    UNVERIFIED(8),
    /**
     * A binding read back from a snapshot rather than granted in this
     * process. It has not been proved either.
     */
    RESTORED(9),
    /**
     * The account has no registrar and never registers (a trunk that
     * knows this end by address). `sipral_account_register` refuses it.
     */
    NOT_REGISTERING(10),
    ;

    companion object {
        fun of(value: Int): SipralRegistrationState? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Why a registration is not live. Names for
 * `sipral_registration_event_t::failure`.
 */
enum class SipralRegistrationFailure(val value: Int) {
    /**
     * Nothing failed.
     */
    NONE(0),
    /**
     * The registrar refused, and will refuse the same request again.
     */
    REJECTED(1),
    /**
     * The password was wrong, or there was none to answer with.
     */
    BAD_CREDENTIALS(2),
    /**
     * The registrar is not answering, or says it cannot serve this now.
     */
    UNREACHABLE(3),
    /**
     * The registrar moved. Following it needs an address, which is the
     * caller's to resolve.
     */
    REDIRECTED(4),
    /**
     * The account's `Contact` is unreachable for the registrar (loopback
     * or unspecified); nothing was sent. Fix with `sipral_account_rebind`.
     */
    UNREACHABLE_CONTACT(5),
    ;

    companion object {
        fun of(value: Int): SipralRegistrationFailure? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Where a call is. Names for `sipral_call_event_t::state`, and what
 * `sipral_call_state` writes.
 */
enum class SipralCallState(val value: Int) {
    /**
     * The call is gone, or has never been asked about.
     */
    UNKNOWN(0),
    /**
     * The INVITE has gone and nothing has come back.
     */
    CALLING(1),
    /**
     * Somebody is calling and this end has not answered.
     */
    INCOMING(2),
    /**
     * The far end is ringing, or this end said it is.
     */
    RINGING(3),
    /**
     * There is audio before anybody answered.
     */
    EARLY_MEDIA(4),
    /**
     * Up.
     */
    CONFIRMED(5),
    /**
     * Up, in order to be transferred: the second leg of an attended transfer.
     */
    CONSULTING(6),
    /**
     * A CANCEL or a BYE has gone and is not answered yet.
     */
    TERMINATING(7),
    /**
     * Over.
     */
    TERMINATED(8),
    ;

    companion object {
        fun of(value: Int): SipralCallState? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Why a call is over. Names for `sipral_call_event_t::end_reason`.
 */
enum class SipralCallEndReason(val value: Int) {
    /**
     * The call is not over.
     */
    NONE(0),
    /**
     * This end hung up.
     */
    LOCAL_HANGUP(1),
    /**
     * The far end hung up.
     */
    REMOTE_HANGUP(2),
    /**
     * The far end refused it: busy, declined, not found.
     */
    REFUSED(3),
    /**
     * Given up before it was answered, from either end.
     */
    CANCELLED(4),
    /**
     * Nothing came back, or the transport died.
     */
    UNREACHABLE(5),
    /**
     * Another branch of the same fork was kept and this one was not.
     */
    FORK_LOST(6),
    /**
     * The branch was still ringing when the answer window closed.
     */
    ABANDONED(7),
    /**
     * The session timer ran out and no refresh arrived.
     */
    EXPIRED(8),
    ;

    companion object {
        fun of(value: Int): SipralCallEndReason? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Which way a digit arrived. Names for `sipral_media_event_t::source`.
 */
enum class SipralDigitSource(val value: Int) {
    /**
     * RFC 4733: a named telephone event in the RTP stream.
     */
    RTP(0),
    /**
     * RFC 3261's INFO method (RFC 6086), carrying `application/dtmf-relay`
     * or `application/dtmf`.
     */
    INFO(1),
    /**
     * The two tones themselves, heard in the far end's audio, for
     * SipralEventKind.IN_BAND_DIGIT.
     */
    IN_BAND(2),
    ;

    companion object {
        fun of(value: Int): SipralDigitSource? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a SipralEventKind.RECOVERY reports, for
 * `payload.recovery.state`.
 */
enum class SipralRecoveryOutcome(val value: Int) {
    /**
     * Never written by this build.
     */
    UNKNOWN(0),
    /**
     * A registrar answered again: what was distrusted is proved.
     */
    RUNNING(1),
    /**
     * Every rung was climbed and none of them worked.
     */
    GAVE_UP(2),
    ;

    companion object {
        fun of(value: Int): SipralRecoveryOutcome? = entries.firstOrNull { it.value == value }
    }
}

/**
 * The last rung tried before giving up, for `payload.recovery.rung`.
 */
enum class SipralRecoveryRung(val value: Int) {
    /**
     * The ladder did not give up.
     */
    NONE(0),
    /**
     * Nothing was believed any more, and nothing was sent.
     */
    DISTRUST(1),
    /**
     * A REGISTER, and a re-SUBSCRIBE for what was demoted alongside it,
     * went out or could not.
     */
    REREGISTER(2),
    /**
     * The application was asked for a transport.
     */
    WANT_TRANSPORT(3),
    /**
     * The application was asked for an address.
     */
    WANT_ADDRESS(4),
    ;

    companion object {
        fun of(value: Int): SipralRecoveryRung? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Why a recovery ladder gave up, for SipralEventKind.RECOVERY's
 * `payload.recovery.reason`.
 */
enum class SipralRecoveryFailure(val value: Int) {
    /**
     * The ladder did not give up.
     */
    NONE(0),
    /**
     * Every REGISTER that could be sent was sent and none of them was
     * answered.
     */
    UNREACHABLE(1),
    /**
     * A transport was asked for and the application did not bind one.
     */
    NO_TRANSPORT(2),
    /**
     * An address was asked for and the application did not supply one.
     */
    UNRESOLVED(3),
    ;

    companion object {
        fun of(value: Int): SipralRecoveryFailure? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What kind of link the application is on: `from_link` and `to_link` on
 * sipral_stack_network_changed.
 *
 * Only SipralLink.DOWN changes what is done. The rest makes a change
 * of kind over an unchanged address (a tunnel, Wi-Fi to cellular) visible.
 */
enum class SipralLink(val value: Int) {
    /**
     * There is no usable interface.
     */
    DOWN(0),
    /**
     * Cable.
     */
    WIRED(1),
    /**
     * Wireless local network.
     */
    WIFI(2),
    /**
     * A mobile network.
     */
    CELLULAR(3),
    /**
     * A tunnel over one of the others.
     */
    TUNNEL(4),
    ;

    companion object {
        fun of(value: Int): SipralLink? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a change of network is worth doing about:
 * sipral_stack_network_changed's `out_recovery`. Returned directly, so
 * a laptop flipping access points gets SipralRecovery.NOTHING without
 * reading an event or sending a REGISTER.
 */
enum class SipralRecovery(val value: Int) {
    /**
     * Never written by this build.
     */
    UNKNOWN(0),
    /**
     * Nothing this stack uses is different; nothing is done or sent.
     */
    NOTHING(1),
    /**
     * The address stands, so the transports do; what is upstream may not.
     */
    REREGISTER(2),
    /**
     * A wake: the existing transport is tried first, a new one asked for
     * only if it is dead. Started by sipral_stack_resumed, never
     * returned here.
     */
    REPROVE(3),
    /**
     * The address is gone; the application must open a transport again.
     */
    REBUILD(4),
    /**
     * Packets can leave and names cannot be turned into addresses.
     */
    RESOLVE(5),
    /**
     * There is no interface. Nothing is tried until there is one.
     */
    DETACH(6),
    ;

    companion object {
        fun of(value: Int): SipralRecovery? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a stack does about a NAT in front of it. Names for
 * `sipral_stack_config_t::nat`. Zero means the built-in default, SipralNat.OFF.
 */
enum class SipralNat(val value: Int) {
    /**
     * Ask nobody: every address written is the one the application gave.
     */
    OFF(1),
    /**
     * Ask `stun_server` where each socket appears from and write that instead.
     * `SIPRAL_STATUS_NOT_SUPPORTED` without `SIPRAL_FEATURE_STUN`.
     */
    STUN(2),
    ;

    companion object {
        fun of(value: Int): SipralNat? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a socket's mapping came to. Names for `sipral_nat_event_t::mapping`.
 */
enum class SipralNatMapping(val value: Int) {
    /**
     * The first answer: the socket appears at `public`.
     */
    LEARNED(1),
    /**
     * A later answer named another address; `previous` is the old one. Signalling socket, or a
     * media socket still waiting for its call.
     */
    MOVED(2),
    /**
     * No answer within five and a half seconds, or refused. The socket is described by its own
     * address; a signalling socket asks again at its next refresh.
     */
    UNANSWERED(3),
    ;

    companion object {
        fun of(value: Int): SipralNatMapping? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a media socket's relay came to. Names for `sipral_nat_relay_event_t::outcome`.
 */
enum class SipralNatRelay(val value: Int) {
    /**
     * The relay exists at `relayed`; later calls on the socket offer it as an ICE candidate.
     */
    ALLOCATED(1),
    /**
     * No relay: refused (see `code`), no answer in 39.5 seconds, or allocation lost. Calls on
     * the socket go without one.
     */
    FAILED(2),
    ;

    companion object {
        fun of(value: Int): SipralNatRelay? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What to do with a media socket's TURN connection. Names for
 * `sipral_turn_stream_event_t::state`.
 */
enum class SipralTurnStream(val value: Int) {
    /**
     * Open a connection from `local` to `server` over `protocol` (TLS verified by the
     * platform), then call `sipral_stack_turn_connected`, or `sipral_stack_turn_closed` on failure. Calls
     * on the socket before that answer `SIPRAL_STATUS_WRONG_STATE`.
     */
    OPEN(1),
    /**
     * Nothing more will be written for `local`: flush `sipral_stack_poll_farewell` and
     * `sipral_stack_poll_stun` for it, then close it.
     */
    CLOSE(2),
    ;

    companion object {
        fun of(value: Int): SipralTurnStream? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What happened to the STUN servers. Names for `sipral_stun_server_event_t::state`.
 */
enum class SipralStunServerState(val value: Int) {
    /**
     * Another server is in use now: failover, an earlier one answering again, or a new list.
     */
    CHANGED(1),
    /**
     * Every server failed and is backing off; `server` is the last. Sockets keep what they
     * learned. Said once until a server answers again.
     */
    ALL_FAILED(2),
    ;

    companion object {
        fun of(value: Int): SipralStunServerState? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Where a subscription is: `sipral_subscription_event_t::state` and
 * sipral_subscription_state's `out_state`.
 */
enum class SipralSubscriptionState(val value: Int) {
    /**
     * The handle names nothing: never minted here, or ended and let go.
     */
    UNKNOWN(0),
    /**
     * A SUBSCRIBE is on its way and nothing has answered it yet.
     */
    REQUESTING(1),
    /**
     * The notifier has not decided (RFC 6665 §4.1.3 `pending`); nothing
     * is known until SipralSubscriptionState.ACTIVE.
     */
    PENDING(2),
    /**
     * Granted, and notifications are arriving.
     */
    ACTIVE(3),
    /**
     * Not live, and a fresh attempt is scheduled (§4.1.2.2: new
     * `Call-ID` and `From` tag). The handle stays valid across both.
     */
    RETRYING(4),
    /**
     * Over, nothing more coming. The handle names nothing from here on.
     */
    ENDED(5),
    ;

    companion object {
        fun of(value: Int): SipralSubscriptionState? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Why a subscription is not live: `sipral_subscription_event_t::reason`.
 *
 * Zero unless SipralSubscriptionState.RETRYING or
 * SipralSubscriptionState.ENDED. The first eight are the `reason` of
 * `Subscription-State: terminated` (RFC 6665 §4.1.3); the rest happened
 * here.
 */
enum class SipralSubscriptionEnd(val value: Int) {
    /**
     * Never written by this build.
     */
    UNKNOWN(0),
    /**
     * `deactivated`: the notifier wants it started again at once.
     */
    DEACTIVATED(1),
    /**
     * `probation`: started again, but not immediately.
     */
    PROBATION(2),
    /**
     * `rejected`: the notifier will not serve it; do not ask again.
     */
    REJECTED(3),
    /**
     * `timeout`: it ran out rather than being refreshed.
     */
    TIMEOUT(4),
    /**
     * `giveup`: the notifier could not decide and stopped trying.
     */
    GAVE_UP(5),
    /**
     * `noresource`: what was being watched does not exist any more.
     */
    NO_RESOURCE(6),
    /**
     * `invariant`: the watched thing cannot change.
     */
    INVARIANT(7),
    /**
     * `terminated` with no reason parameter at all.
     */
    UNSTATED(8),
    /**
     * This end gave it up with sipral_subscription_end. Wins over
     * the notifier's closing reason.
     */
    UNSUBSCRIBED(9),
    /**
     * The notifier answered 489: it does not know this event package.
     */
    BAD_EVENT(10),
    /**
     * Refused with a status a retry cannot fix.
     */
    REFUSED(11),
    /**
     * Redirected; this stack does not follow redirects for SUBSCRIBE.
     */
    REDIRECTED(12),
    /**
     * Nothing answered: the notifier could not be reached at all.
     */
    UNREACHABLE(13),
    /**
     * Answered, but the first NOTIFY never came (§4.1.2.4's timer N,
     * 64·T1).
     */
    NO_NOTIFY(14),
    /**
     * What the notifier granted ran out with no refresh answered.
     */
    EXPIRED(15),
    ;

    companion object {
        fun of(value: Int): SipralSubscriptionEnd? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What one watched dialog is doing, and what a lamp shows:
 * `sipral_watched_dialog_t::phase` and sipral_subscription_lamp's
 * `out_phase`. RFC 4235 §3.7.1's states, ranked as §3.7.2 ranks them.
 */
enum class SipralDialogPhase(val value: Int) {
    /**
     * No dialog, or all terminated: an idle lamp.
     */
    IDLE(0),
    /**
     * A request went out and nothing has answered.
     */
    TRYING(1),
    /**
     * Something answered without ringing yet.
     */
    PROCEEDING(2),
    /**
     * Ringing.
     */
    EARLY(3),
    /**
     * A call is up.
     */
    CONFIRMED(4),
    /**
     * This dialog is over. Never sipral_subscription_lamp's answer,
     * which is SipralDialogPhase.IDLE then.
     */
    TERMINATED(5),
    /**
     * The notifier named a state this build has no number for.
     */
    UNKNOWN(6),
    ;

    companion object {
        fun of(value: Int): SipralDialogPhase? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Which end started a watched dialog: `sipral_watched_dialog_t::direction`.
 */
enum class SipralDialogDirection(val value: Int) {
    /**
     * The notifier did not say.
     */
    UNKNOWN(0),
    /**
     * The watched end placed the call.
     */
    LOCALLY(1),
    /**
     * The watched end was called.
     */
    REMOTELY(2),
    ;

    companion object {
        fun of(value: Int): SipralDialogDirection? = entries.firstOrNull { it.value == value }
    }
}

/**
 * How a watched dialog ended: `sipral_watched_dialog_t::ended`, zero
 * while it has not.
 */
enum class SipralDialogEnded(val value: Int) {
    /**
     * It has not ended, or the notifier did not say how.
     */
    UNKNOWN(0),
    /**
     * The caller gave up before it was answered.
     */
    CANCELLED(1),
    /**
     * The called end refused it.
     */
    REJECTED(2),
    /**
     * A `Replaces` took it over.
     */
    REPLACED(3),
    /**
     * The watched end hung up.
     */
    LOCAL_BYE(4),
    /**
     * The far end hung up.
     */
    REMOTE_BYE(5),
    /**
     * Something went wrong with it.
     */
    ERROR(6),
    /**
     * Nothing answered in time.
     */
    TIMEOUT(7),
    ;

    companion object {
        fun of(value: Int): SipralDialogEnded? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Which text sipral_subscription_dialog_text reads. Each is what the
 * notifier wrote, unparsed.
 */
enum class SipralDialogText(val value: Int) {
    /**
     * Never asked for.
     */
    UNKNOWN(0),
    /**
     * The notifier's own id for this dialog.
     */
    ID(1),
    /**
     * The dialog's `Call-ID`, when the notifier sent one.
     */
    CALL_ID(2),
    /**
     * Who the watched end is, as a URI.
     */
    LOCAL_IDENTITY(3),
    /**
     * And the display name beside it.
     */
    LOCAL_DISPLAY(4),
    /**
     * Who the other end is, as a URI: what a lamp shows when ringing.
     */
    REMOTE_IDENTITY(5),
    /**
     * And the display name beside it.
     */
    REMOTE_DISPLAY(6),
    /**
     * Where requests for the watched end would be sent.
     */
    LOCAL_TARGET(7),
    /**
     * And for the other end.
     */
    REMOTE_TARGET(8),
    ;

    companion object {
        fun of(value: Int): SipralDialogText? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Who pumps a stack's audio: `sipral_stack_config_t::audio`.
 *
 * Zero is application mode, so a configuration written against an
 * earlier header keeps pumping its own frames.
 */
enum class SipralAudio(val value: Int) {
    /**
     * The application opens the devices and pumps frames through
     * `sipral_media_capture` and `sipral_media_playback`.
     */
    APPLICATION(0),
    /**
     * The library opens the devices and pumps every managed call; the
     * packets reach the application through `audio_transmit_callback`.
     * `SIPRAL_STATUS_NOT_SUPPORTED` without a backend for the platform,
     * as `SIPRAL_FEATURE_AUDIO_DEVICE` says.
     */
    DEVICE(1),
    ;

    companion object {
        fun of(value: Int): SipralAudio? = entries.firstOrNull { it.value == value }
    }
}

/**
 * When the devices are opened, in device mode:
 * `sipral_stack_config_t::audio_activation`.
 */
enum class SipralAudioActivation(val value: Int) {
    /**
     * With the first managed call's media or ring; closed with the last.
     */
    AUTOMATIC(0),
    /**
     * Only between `sipral_audio_activate` and `sipral_audio_deactivate`:
     * for CallKit and the telecom framework, which own the audio session.
     */
    MANUAL(1),
    ;

    companion object {
        fun of(value: Int): SipralAudioActivation? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a device is used for.
 */
enum class SipralAudioRole(val value: Int) {
    /**
     * The call's microphone.
     */
    MICROPHONE(1),
    /**
     * The call's loudspeaker or earpiece.
     */
    SPEAKER(2),
    /**
     * Where an incoming call is announced, which may differ from where
     * it is answered.
     */
    RINGER(3),
    ;

    companion object {
        fun of(value: Int): SipralAudioRole? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Which way audio flows, for gain, mute and the meter.
 */
enum class SipralAudioDirection(val value: Int) {
    /**
     * From the microphone. Its gain is the microphone gain.
     */
    INPUT(1),
    /**
     * To the loudspeaker. Its gain is the volume.
     */
    OUTPUT(2),
    ;

    companion object {
        fun of(value: Int): SipralAudioDirection? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What changed, on `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED`.
 */
enum class SipralAudioChange(val value: Int) {
    /**
     * A device arrived or left. Every valid id stays valid: a device
     * that left keeps its row, marked absent.
     */
    LIST_CHANGED(1),
    /**
     * The system's default for `direction` moved. A role on a chosen
     * device stays; one on the system's route follows with
     * `SIPRAL_AUDIO_CHANGE_REOPENED`.
     */
    DEFAULT_CHANGED(2),
    /**
     * `role` is on `device` because `sipral_audio_select` said so.
     */
    SELECTED(3),
    /**
     * The device `role` ran on went away; the reopen is reported apart.
     */
    LOST(4),
    /**
     * `role` is running on `device` again.
     */
    REOPENED(5),
    /**
     * `role` could not be opened on anything; that direction is
     * silence until a device arrives.
     */
    UNAVAILABLE(6),
    ;

    companion object {
        fun of(value: Int): SipralAudioChange? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Who made a change. An application must not answer either by
 * re-applying its own choice.
 */
enum class SipralAudioOrigin(val value: Int) {
    /**
     * The operating system, or a person at a socket.
     */
    SYSTEM(1),
    /**
     * The engine.
     */
    ENGINE(2),
    ;

    companion object {
        fun of(value: Int): SipralAudioOrigin? = entries.firstOrNull { it.value == value }
    }
}

/**
 * The verdict a terminating network reached on the caller's number
 * (3GPP TS 24.229's `verstat`, the mark STIR/SHAKEN leaves). Names for
 * `sipral_call_event_t::verstat`.
 */
enum class SipralVerstat(val value: Int) {
    /**
     * Nothing said, or said by a peer the account does not trust.
     */
    NONE(0),
    /**
     * `TN-Validation-Passed`.
     */
    PASSED(1),
    /**
     * `TN-Validation-Failed`.
     */
    FAILED(2),
    /**
     * `No-TN-Validation`.
     */
    NOT_VALIDATED(3),
    /**
     * Some other value.
     */
    OTHER(4),
    ;

    companion object {
        fun of(value: Int): SipralVerstat? = entries.firstOrNull { it.value == value }
    }
}

/**
 * `Answer-Mode` and `Priv-Answer-Mode` (RFC 5373 §3). Names for
 * `sipral_call_event_t::answer_mode` and `priv_answer_mode`.
 */
enum class SipralAnswerMode(val value: Int) {
    /**
     * The INVITE carried no such field.
     */
    NONE(0),
    /**
     * `Manual`: wait for the user.
     */
    MANUAL(1),
    /**
     * `Auto`: answer without waiting for the user.
     */
    AUTO(2),
    /**
     * Any other value, which RFC 5373 has ignored.
     */
    OTHER(3),
    ;

    companion object {
        fun of(value: Int): SipralAnswerMode? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Where the ring says the caller is. Names for
 * `sipral_call_event_t::ring_source`.
 */
enum class SipralRingSource(val value: Int) {
    /**
     * Nothing said.
     */
    UNKNOWN(0),
    /**
     * Another extension of the same switch.
     */
    INTERNAL(1),
    /**
     * The outside world.
     */
    EXTERNAL(2),
    ;

    companion object {
        fun of(value: Int): SipralRingSource? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Which list, and which piece of each entry, sipral_call_identity_count
 * and sipral_call_identity_text are asked about.
 */
enum class SipralIdentityText(val value: Int) {
    /**
     * Never asked for.
     */
    UNKNOWN(0),
    /**
     * `P-Asserted-Identity`: the URI of each asserted party.
     */
    ASSERTED(1),
    /**
     * And each one's display name.
     */
    ASSERTED_DISPLAY(2),
    /**
     * `Remote-Party-ID`: the URI of each party named.
     */
    REMOTE_PARTY(3),
    /**
     * And each one's display name.
     */
    REMOTE_PARTY_DISPLAY(4),
    /**
     * `Diversion`, most recent first: who the call was diverted from.
     */
    DIVERSION(5),
    /**
     * And the display name beside it.
     */
    DIVERSION_DISPLAY(6),
    /**
     * And why: `no-answer`, `user-busy`, `unconditional` and the rest.
     */
    DIVERSION_REASON(7),
    /**
     * `History-Info`: the URI of each target the request was sent to.
     */
    HISTORY(8),
    /**
     * And each entry's `index`.
     */
    HISTORY_INDEX(9),
    /**
     * Every `Alert-Info` URI.
     */
    ALERT_INFO(10),
    /**
     * Every `info=` value on `Alert-Info`.
     */
    ALERT_NAME(11),
    /**
     * The canonical calling number a valid PASSporT was found for
     * (RFC 8224 §6.2): one entry, or none. ABI 0.31.
     */
    VERIFIED_ORIG(12),
    /**
     * Its origination identifier (RFC 8588 §5), a UUID.
     */
    VERIFIED_ORIGID(13),
    /**
     * The URL of the certificate it was verified against, or that could
     * not be had.
     */
    VERIFICATION_CERTIFICATE(14),
    /**
     * Why it did not verify, in words, for a log.
     */
    VERIFICATION_DETAIL(15),
    ;

    companion object {
        fun of(value: Int): SipralIdentityText? = entries.firstOrNull { it.value == value }
    }
}

/**
 * How an account's calls ask for a session timer (RFC 4028). Names for
 * `sipral_account_config_t::session_timer`.
 */
enum class SipralSessionTimer(val value: Int) {
    /**
     * The stack's default: thirty minutes, RFC 4028 §4's recommendation.
     */
    DEFAULT(0),
    /**
     * Ask for none. A far end that insists on one is still honoured.
     */
    OFF(1),
    /**
     * Ask for `session_interval_seconds`, at least 90 (§5's floor).
     */
    INTERVAL(2),
    ;

    companion object {
        fun of(value: Int): SipralSessionTimer? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Log verbosity, for sipral_stack_log and SipralLogRecord.level.
 * Each level includes the ones below it.
 */
enum class SipralLogLevel(val value: Int) {
    /**
     * The log is off; the initial state.
     */
    OFF(0),
    /**
     * A failure the application is likely to notice.
     */
    ERROR(1),
    /**
     * Something worked around or about to matter: a registration
     * refused, audio that stopped arriving.
     */
    WARN(2),
    /**
     * Operator-level: registrations, calls arriving, confirmed or ending,
     * media starting.
     */
    INFO(3),
    /**
     * Every event raised, every diagnostic decision, every refused ABI call.
     */
    DEBUG(4),
    /**
     * Every SIP message in and out, whole and redacted.
     */
    TRACE(5),
    ;

    companion object {
        fun of(value: Int): SipralLogLevel? = entries.firstOrNull { it.value == value }
    }
}

/**
 * How a stream's SRTP keys were exchanged
 * (`sipral_stream_encryption_t::key_exchange`, `sipral_media_event_t::key_exchange`).
 */
enum class SipralKeyExchange(val value: Int) {
    /**
     * None: the stream is not encrypted, or the event is not about one.
     */
    NONE(0),
    /**
     * In the SDP (RFC 4568 `a=crypto`): as protected as the signalling.
     */
    SDES(1),
    /**
     * DTLS on the media path (RFC 5764), checked against the signalled
     * fingerprint.
     */
    DTLS(2),
    ;

    companion object {
        fun of(value: Int): SipralKeyExchange? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a stream carries. Names for `sipral_stream_encryption_t::media`.
 */
enum class SipralMediaKind(val value: Int) {
    /**
     * Something this ABI has no word for.
     */
    UNKNOWN(0),
    /**
     * `m=audio`.
     */
    AUDIO(1),
    ;

    companion object {
        fun of(value: Int): SipralMediaKind? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What an account does with incoming `Identity` header fields
 * (RFC 8224 §6.2). Values of `sipral_account_config_t::stir_verification`.
 */
enum class SipralStirVerification(val value: Int) {
    /**
     * This build's default, which is `REPORT`.
     */
    DEFAULT(0),
    /**
     * Verify nothing.
     */
    OFF(1),
    /**
     * Verify, report the verdict, deliver every call. Active only once
     * the stack has trust anchors (`sipral_stack_stir`).
     */
    REPORT(2),
    /**
     * Verify and refuse what does not verify (RFC 8224 §6.2.2): 428 no
     * `Identity`, 436 certificate unavailable, 437 untrusted, 438 bad
     * signature, 403 "Stale Date". Active even with no anchors, where
     * nothing verifies.
     */
    STRICT(3),
    ;

    companion object {
        fun of(value: Int): SipralStirVerification? = entries.firstOrNull { it.value == value }
    }
}

/**
 * SHAKEN attestation level (RFC 8588 §4), for
 * `sipral_account_config_t::stir_attestation` and the verdict fields.
 */
enum class SipralAttestation(val value: Int) {
    /**
     * None said: on an account, full attestation; on a verdict, a
     * PASSporT with no SHAKEN claims, or no valid one.
     */
    NONE(0),
    /**
     * Full: the signer knows the caller and that the number is theirs.
     */
    A(1),
    /**
     * Partial: the signer knows the caller, not the number.
     */
    B(2),
    /**
     * Gateway: the signer knows only where the call entered its network.
     */
    C(3),
    ;

    companion object {
        fun of(value: Int): SipralAttestation? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a verification came to (`sipral_verification_event_t::outcome`,
 * `sipral_call_event_t::verification`).
 */
enum class SipralVerificationOutcome(val value: Int) {
    /**
     * Nothing verified: the account does not verify, or no anchors.
     */
    NONE(0),
    /**
     * Signed by a certificate with authority over the calling number,
     * fresh, for the numbers the request names.
     */
    VALID(1),
    /**
     * One was there and does not hold: `failure` says why.
     */
    INVALID(2),
    /**
     * Nothing to verify: no `Identity`, or only unsupported extensions.
     */
    ABSENT(3),
    ;

    companion object {
        fun of(value: Int): SipralVerificationOutcome? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Why a verification did not hold (`sipral_verification_event_t::failure`,
 * `sipral_call_event_t::verification_failure`).
 */
enum class SipralVerificationFailure(val value: Int) {
    /**
     * Nothing failed.
     */
    NONE(0),
    /**
     * No `Identity` header field.
     */
    NO_IDENTITY(1),
    /**
     * Only ones naming a `ppt` this end does not support.
     */
    UNSUPPORTED_PPT(2),
    /**
     * The header field or its PASSporT is not well formed.
     */
    MALFORMED(3),
    /**
     * Signed with an algorithm other than ES256.
     */
    UNSUPPORTED_ALGORITHM(4),
    /**
     * `iat` outside the freshness window.
     */
    STALE(5),
    /**
     * The certificate could not be fetched, or did not arrive in time.
     */
    CERTIFICATE_UNAVAILABLE(6),
    /**
     * What the `info` URL yielded is not a chain this end can read.
     */
    CERTIFICATE_UNREADABLE(7),
    /**
     * The chain leads to no trust anchor.
     */
    UNTRUSTED(8),
    /**
     * A certificate in it is outside its validity period.
     */
    EXPIRED(9),
    /**
     * The chain breaks a rule of path validation.
     */
    INVALID_CHAIN(10),
    /**
     * The signature does not verify.
     */
    BAD_SIGNATURE(11),
    /**
     * The certificate has no authority over the calling number.
     */
    NUMBER_NOT_COVERED(12),
    /**
     * Signed for another calling number than the request names.
     */
    ORIG_MISMATCH(13),
    /**
     * Signed for another called number.
     */
    DEST_MISMATCH(14),
    ;

    companion object {
        fun of(value: Int): SipralVerificationFailure? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Which half of a verification an event reports
 * (`sipral_verification_event_t::stage`).
 */
enum class SipralVerificationStage(val value: Int) {
    /**
     * Never sent.
     */
    UNKNOWN(0),
    /**
     * Fetch the certificate at `certificate_url` and pass it to
     * `sipral_call_stir_certificate` (or nothing, if unavailable). The
     * call waits unannounced until then or `certificate_wait_ms`.
     */
    CERTIFICATE_WANTED(1),
    /**
     * The verdict. `SIPRAL_EVENT_KIND_INCOMING_CALL` follows, or
     * `SIPRAL_EVENT_KIND_CALL_ENDED` when `refused` is set.
     */
    VERIFIED(2),
    ;

    companion object {
        fun of(value: Int): SipralVerificationStage? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a SipralEventKind.PROGRESS_DETECTED heard. Names for
 * `sipral_progress_event_t::what`.
 */
enum class SipralProgressKind(val value: Int) {
    /**
     * Never written by this build.
     */
    UNKNOWN(0),
    /**
     * A call-progress tone: `tone`, and `at_ms` when its first burst began.
     */
    TONE(1),
    /**
     * The special information tone (the call failed): `sit_hz_*` and
     * `sit_ms_*` as measured, `at_ms` when the first began.
     */
    SPECIAL_INFORMATION(2),
    /**
     * Who answered: `verdict`, `reason`, `at_ms` after answer,
     * `initial_silence_ms`, `greeting_ms` and `words`.
     */
    ANSWERED_BY(3),
    /**
     * A machine's record beep: `frequency_hz`, `length_ms`, and `at_ms`
     * when it ended, after answer.
     */
    BEEP(4),
    ;

    companion object {
        fun of(value: Int): SipralProgressKind? = entries.firstOrNull { it.value == value }
    }
}

/**
 * A call-progress tone. Names for `sipral_progress_event_t::tone`.
 */
enum class SipralProgressTone(val value: Int) {
    /**
     * Not a tone, or one this build has no name for.
     */
    UNKNOWN(0),
    /**
     * The exchange is ready for digits.
     */
    DIAL(1),
    /**
     * The far end is being alerted.
     */
    RINGBACK(2),
    /**
     * The far end is busy.
     */
    BUSY(3),
    /**
     * The network is congested: congestion, or reorder.
     */
    CONGESTION(4),
    /**
     * A second call is waiting.
     */
    CALL_WAITING(5),
    /**
     * The special information tone.
     */
    SPECIAL_INFORMATION(6),
    ;

    companion object {
        fun of(value: Int): SipralProgressTone? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Who answered. Names for `sipral_progress_event_t::verdict`.
 */
enum class SipralAmdVerdict(val value: Int) {
    /**
     * Not a verdict.
     */
    UNKNOWN(0),
    /**
     * A person.
     */
    HUMAN(1),
    /**
     * An answering machine or a voice mailbox.
     */
    MACHINE(2),
    /**
     * The evidence does not say.
     */
    NOT_SURE(3),
    ;

    companion object {
        fun of(value: Int): SipralAmdVerdict? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Which rule decided who answered. Names for
 * `sipral_progress_event_t::reason`.
 */
enum class SipralAmdReason(val value: Int) {
    /**
     * Not a verdict.
     */
    NONE(0),
    /**
     * A short greeting, then silence: somebody said hello and waits.
     */
    SHORT_GREETING(1),
    /**
     * More words than a person answers with.
     */
    TOO_MANY_WORDS(2),
    /**
     * A greeting longer than a person gives.
     */
    LONG_GREETING(3),
    /**
     * Nobody spoke.
     */
    INITIAL_SILENCE(4),
    /**
     * No rule decided in the time allowed.
     */
    TIMEOUT(5),
    ;

    companion object {
        fun of(value: Int): SipralAmdReason? = entries.firstOrNull { it.value == value }
    }
}

/**
 * When a call listens for keypad digits in the far end's audio. Names
 * for `sipral_stack_config_t::dtmf_detection` and
 * sipral_call_dtmf_detection's `mode`.
 */
enum class SipralDtmfDetection(val value: Int) {
    /**
     * Only when no telephone event was negotiated, since the far end
     * then has no other way to send a digit.
     */
    AUTO(0),
    /**
     * Never. Digits arrive only as RFC 4733 events or by INFO.
     */
    OFF(1),
    /**
     * On every call. A press the far end sends both as an event and in
     * the audio is reported once, as the event.
     */
    ALWAYS(2),
    ;

    companion object {
        fun of(value: Int): SipralDtmfDetection? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Whose call-progress tones to listen for. Names for
 * `sipral_progress_config_t::region`.
 */
enum class SipralToneRegion(val value: Int) {
    /**
     * The 425 Hz tones common to the CEPT administrations.
     */
    EUROPE(0),
    /**
     * The United States and Canada.
     */
    NORTH_AMERICA(1),
    /**
     * The United Kingdom.
     */
    UNITED_KINGDOM(2),
    ;

    companion object {
        fun of(value: Int): SipralToneRegion? = entries.firstOrNull { it.value == value }
    }
}

/**
 * The file format of a recording. Names for
 * `sipral_recording_options_t::format`.
 */
enum class SipralRecordingFormat(val value: Int) {
    /**
     * Sixteen-bit PCM in RIFF/WAVE, becoming RF64 past four gibibytes.
     */
    WAV(0),
    /**
     * Opus in Ogg (RFC 7845), where `SIPRAL_FEATURE_OPUS` says the build
     * has the encoder; `SIPRAL_STATUS_NOT_SUPPORTED` where it does not.
     */
    OGG_OPUS(1),
    ;

    companion object {
        fun of(value: Int): SipralRecordingFormat? = entries.firstOrNull { it.value == value }
    }
}

/**
 * How the two directions of a call share a recording. Names for
 * `sipral_recording_options_t::layout`.
 */
enum class SipralRecordingLayout(val value: Int) {
    /**
     * One channel: both directions, each at half level, summed.
     */
    MIXED(0),
    /**
     * Two channels: this end on the left, the far end on the right.
     */
    STEREO(1),
    ;

    companion object {
        fun of(value: Int): SipralRecordingLayout? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What one conference document did. Names for
 * `sipral_conference_event_t::update`.
 */
enum class SipralConferenceUpdate(val value: Int) {
    /**
     * Never written by this build.
     */
    UNKNOWN(0),
    /**
     * It was merged into the picture.
     */
    APPLIED(1),
    /**
     * Deleted by the focus; the subscription ends (RFC 4575 §4.6).
     */
    ENDED(2),
    ;

    companion object {
        fun of(value: Int): SipralConferenceUpdate? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Where one endpoint of a conference is (RFC 4575 §5.7.2). Names for
 * `sipral_conference_user_t::status`.
 */
enum class SipralEndpointStatus(val value: Int) {
    /**
     * Absent or not in the schema.
     */
    UNKNOWN(0),
    /**
     * `pending`: waiting for policy or for the focus.
     */
    PENDING(1),
    /**
     * `dialing-out`: the focus is calling it.
     */
    DIALING_OUT(2),
    /**
     * `dialing-in`: it is calling the focus.
     */
    DIALING_IN(3),
    /**
     * `alerting`: it is ringing.
     */
    ALERTING(4),
    /**
     * `on-hold`.
     */
    ON_HOLD(5),
    /**
     * `connected`: it is in the conference.
     */
    CONNECTED(6),
    /**
     * `muted-via-focus`: in, and muted by the focus.
     */
    MUTED_VIA_FOCUS(7),
    /**
     * `disconnecting`.
     */
    DISCONNECTING(8),
    /**
     * `disconnected`: it has left.
     */
    DISCONNECTED(9),
    ;

    companion object {
        fun of(value: Int): SipralEndpointStatus? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Which text sipral_subscription_conference_text reads, as the focus
 * wrote it. The first three ignore `index`; the rest are about that user.
 */
enum class SipralConferenceText(val value: Int) {
    /**
     * Never asked for.
     */
    UNKNOWN(0),
    /**
     * The conference's URI, the `entity` of `conference-info`.
     */
    ENTITY(1),
    /**
     * Its `subject`.
     */
    SUBJECT(2),
    /**
     * Its `display-text`.
     */
    DISPLAY_TEXT(3),
    /**
     * A user's `entity`: the address of record it takes part as.
     */
    USER_ENTITY(4),
    /**
     * A user's `display-text`.
     */
    USER_DISPLAY_TEXT(5),
    /**
     * The `entity` of a user's first endpoint: the device it is on.
     */
    USER_ENDPOINT(6),
    ;

    companion object {
        fun of(value: Int): SipralConferenceText? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a SipralEventKind.PRESENCE_CHANGED is about.
 * Names for `sipral_presence_event_t::kind`.
 */
enum class SipralPresenceKind(val value: Int) {
    /**
     * Never written by this build.
     */
    UNKNOWN(0),
    /**
     * A `presence` subscription was told about the presentity.
     */
    WATCHED(1),
    /**
     * This account's own published presence moved.
     */
    PUBLICATION(2),
    ;

    companion object {
        fun of(value: Int): SipralPresenceKind? = entries.firstOrNull { it.value == value }
    }
}

/**
 * PIDF's `basic` (RFC 3863 §4.1.4). Names for `sipral_presence_t::basic`
 * and `sipral_presence_event_t::basic`.
 */
enum class SipralBasic(val value: Int) {
    /**
     * Not said. A document published with this is refused, since
     * §4.1.3 wants one.
     */
    UNKNOWN(0),
    /**
     * Reachable.
     */
    OPEN(1),
    /**
     * Not reachable.
     */
    CLOSED(2),
    ;

    companion object {
        fun of(value: Int): SipralBasic? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What the person behind a presentity is doing: the RPID activities
 * (RFC 4480 §3.2) phones show. Names for `sipral_presence_t::activity`
 * and `sipral_presence_event_t::activity`.
 */
enum class SipralActivity(val value: Int) {
    /**
     * None said. Published, the document carries no person at all.
     */
    NONE(0),
    /**
     * `away`.
     */
    AWAY(1),
    /**
     * `busy`.
     */
    BUSY(2),
    /**
     * `on-the-phone`.
     */
    ON_THE_PHONE(3),
    /**
     * `meeting`.
     */
    MEETING(4),
    /**
     * `vacation`.
     */
    VACATION(5),
    /**
     * Another activity, which this ABI has no number for.
     */
    OTHER(6),
    ;

    companion object {
        fun of(value: Int): SipralActivity? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What became of this account's published presence. Names for
 * `sipral_presence_event_t::publication_state`.
 */
enum class SipralPublicationState(val value: Int) {
    /**
     * Not a publication event.
     */
    UNKNOWN(0),
    /**
     * The compositor holds it: published, modified or refreshed.
     */
    PUBLISHED(1),
    /**
     * It was taken away (`sipral_account_unpublish_presence`).
     */
    REMOVED(2),
    /**
     * Its lifetime ran out with no refresh; the next publish starts it
     * afresh.
     */
    EXPIRED(3),
    /**
     * The compositor refused, or never answered.
     */
    FAILED(4),
    ;

    companion object {
        fun of(value: Int): SipralPublicationState? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Why a publication failed. Names for `sipral_presence_event_t::failure`.
 */
enum class SipralPublishFailure(val value: Int) {
    /**
     * Nothing failed.
     */
    NONE(0),
    /**
     * 489: the compositor does not know the `presence` package. Nothing
     * more is sent.
     */
    BAD_EVENT(1),
    /**
     * 423 with no `Min-Expires` this stack could meet.
     */
    INTERVAL_TOO_BRIEF(2),
    /**
     * A 2xx without the `SIP-ETag` every one must carry.
     */
    NO_ENTITY_TAG(3),
    /**
     * Any other refusal, a challenge nothing could answer among them;
     * `status_code` says which.
     */
    REFUSED(4),
    /**
     * No answer at all.
     */
    UNREACHABLE(5),
    ;

    companion object {
        fun of(value: Int): SipralPublishFailure? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED` reports
 * (`sipral_local_conference_event_t::change`).
 */
enum class SipralLocalConferenceChange(val value: Int) {
    /**
     * Never written by this build.
     */
    UNKNOWN(0),
    /**
     * `member` joined (a call, or this end at creation).
     */
    JOINED(1),
    /**
     * `member` left, for the reason `departure` gives.
     */
    LEFT(2),
    /**
     * The talkers changed: see `talkers`, `loudest` and
     * `sipral_local_conference_talker_at`.
     */
    TALKERS(3),
    /**
     * The recording stopped because the file refused a write; it holds
     * audio up to its last checkpoint.
     */
    RECORDING_STOPPED(4),
    ;

    companion object {
        fun of(value: Int): SipralLocalConferenceChange? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Why a member left (`sipral_local_conference_event_t::departure`).
 */
enum class SipralDeparture(val value: Int) {
    /**
     * Nobody left.
     */
    NONE(0),
    /**
     * `sipral_local_conference_remove` took it out.
     */
    REMOVED(1),
    /**
     * Its call's media ended.
     */
    ENDED(2),
    /**
     * Its call moved to a codec the conference cannot mix.
     */
    INCOMPATIBLE(3),
    ;

    companion object {
        fun of(value: Int): SipralDeparture? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Which kind of DNS record a lookup asks for. Names for
 * `sipral_locate_event_t::record` and `sipral_account_looked_up`'s
 * `record`.
 */
enum class SipralDnsRecordType(val value: Int) {
    /**
     * Not a lookup: the value on a `SIPRAL_EVENT_KIND_LOCATED` or a
     * `SIPRAL_EVENT_KIND_LOCATE_FAILED`.
     */
    NONE(0),
    /**
     * RFC 3403: which services a domain offers, and under which names.
     */
    NAPTR(1),
    /**
     * RFC 2782: which hosts, at which ports, serve one service.
     */
    SRV(2),
    /**
     * An IPv4 address.
     */
    A(3),
    /**
     * An IPv6 address.
     */
    AAAA(4),
    ;

    companion object {
        fun of(value: Int): SipralDnsRecordType? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What the application's resolver said to a lookup. Names for
 * `sipral_account_looked_up`'s `answer`.
 */
enum class SipralDnsAnswer(val value: Int) {
    /**
     * The records it returned, in `records`. None at all reads as
     * `SIPRAL_DNS_ANSWER_NOTHING`.
     */
    RECORDS(1),
    /**
     * No record of that kind, or no such name. Also the answer from a
     * resolver that cannot ask for that kind (NAPTR, SRV).
     */
    NOTHING(2),
    /**
     * The resolver could not answer: no server reachable, a timeout, a
     * server failure.
     */
    FAILED(3),
    ;

    companion object {
        fun of(value: Int): SipralDnsAnswer? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Why a lookup of an account's server named no address. Names for
 * `sipral_locate_event_t::failure`.
 */
enum class SipralLocateFailure(val value: Int) {
    /**
     * Nothing failed.
     */
    NONE(0),
    /**
     * The DNS named no reachable address: no record, or an SRV target
     * of `.`.
     */
    NOT_FOUND(1),
    /**
     * The resolver failed on every lookup that could give an address.
     */
    UNANSWERED(2),
    /**
     * The transport has no RFC 3263 procedure (WebSocket); only a
     * numeric host or a host with a port works.
     */
    UNSUPPORTED(3),
    ;

    companion object {
        fun of(value: Int): SipralLocateFailure? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Why an account's password did not answer a challenge. Names for
 * `sipral_challenge_event_t::refusal`.
 */
enum class SipralChallengeRefusal(val value: Int) {
    /**
     * Never written by this build.
     */
    UNKNOWN(0),
    /**
     * The challenge came from beyond the account's own server.
     */
    NOT_THE_ACCOUNTS_SERVER(1),
    /**
     * The account's server asked for a realm not the account's (e.g. a
     * proxy relaying a far end's challenge).
     */
    NOT_THE_ACCOUNTS_REALM(2),
    ;

    companion object {
        fun of(value: Int): SipralChallengeRefusal? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What the server said was wrong with the token (RFC 6750 §3.1).
 */
enum class SipralTokenError(val value: Int) {
    /**
     * The server named no error: no token was offered yet.
     */
    NONE(0),
    /**
     * `invalid_request`: the request was malformed.
     */
    INVALID_REQUEST(1),
    /**
     * `invalid_token`: the token is expired, revoked, malformed or
     * otherwise invalid. A new one is needed.
     */
    INVALID_TOKEN(2),
    /**
     * `insufficient_scope`: the token does not cover what was asked;
     * `scope` says what would.
     */
    INSUFFICIENT_SCOPE(3),
    /**
     * `invalid_scope`.
     */
    INVALID_SCOPE(4),
    /**
     * Another code, as written in `error_code`.
     */
    OTHER(5),
    ;

    companion object {
        fun of(value: Int): SipralTokenError? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a network test, or one part of it, comes to. Names for
 * `sipral_network_test_event_t::verdict` and `echo_verdict`.
 */
enum class SipralNetworkVerdict(val value: Int) {
    /**
     * Nothing was tested.
     */
    UNKNOWN(0),
    /**
     * Calls should work and sound right.
     */
    GOOD(1),
    /**
     * Calls should work, perhaps not everywhere or at best quality.
     */
    ACCEPTABLE(2),
    /**
     * Calls are likely to fail or to sound bad.
     */
    POOR(3),
    ;

    companion object {
        fun of(value: Int): SipralNetworkVerdict? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Whether a part of a network test was tried, and how it went. Names
 * for `sipral_network_test_event_t::stun`, `turn` and `echo`.
 */
enum class SipralNetworkProbe(val value: Int) {
    /**
     * Not part of this test.
     */
    NOT_TESTED(0),
    /**
     * The server answered; for the echo, audio came back and was measured.
     */
    SUCCEEDED(1),
    /**
     * It did not.
     */
    FAILED(2),
    ;

    companion object {
        fun of(value: Int): SipralNetworkProbe? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a STUN answer says about the NAT in front of this end. Names for
 * `sipral_network_test_event_t::nat`. Approximate: says nothing about
 * filtering (RFC 4787).
 */
enum class SipralNatKind(val value: Int) {
    /**
     * No answer to read.
     */
    UNKNOWN(0),
    /**
     * No translation: the server saw the socket's own address.
     */
    OPEN(1),
    /**
     * The address was translated and the port kept.
     */
    PORT_PRESERVED(2),
    /**
     * The port was changed too.
     */
    PORT_CHANGED(3),
    ;

    companion object {
        fun of(value: Int): SipralNatKind? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What the account's server did with the test's `OPTIONS`. Names for
 * `sipral_network_test_event_t::server`.
 */
enum class SipralServerReach(val value: Int) {
    /**
     * Not part of this test.
     */
    NOT_TESTED(0),
    /**
     * Any final answer; see `server_status` and `server_round_trip_ms`.
     */
    ANSWERED(1),
    /**
     * No answer before the request, or the test, timed out.
     */
    TIMED_OUT(2),
    /**
     * The transport refused the request or failed under it.
     */
    TRANSPORT_FAILED(3),
    ;

    companion object {
        fun of(value: Int): SipralServerReach? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a held party is sent: `sipral_stack_config_t::held_audio`.
 */
enum class SipralHeldAudio(val value: Int) {
    /**
     * Silence, in either mode.
     */
    DEFAULT(0),
    /**
     * Silence.
     */
    SILENCE(1),
    /**
     * The frames the application hands over, as they are.
     */
    APPLICATION(2),
    ;

    companion object {
        fun of(value: Int): SipralHeldAudio? = entries.firstOrNull { it.value == value }
    }
}

/**
 * The version of the ABI this library provides.
 *
 * Set `size` to `sizeof(sipral_abi_version_t)` before the call.
 */
data class SipralAbiVersion(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * Nothing built against another major version will work.
     */
    val major: Long,
    /**
     * A build with a higher minor has everything a lower one had.
     */
    val minor: Long,
    /**
     * A fix that changed no declaration.
     */
    val patch: Long,
    /**
     * Zero. Pads to alignment so later members never land in padding.
     */
    val reserved: Long,
) {
    internal companion object {
        const val SLOTS: Int = 5

        fun of(slots: LongArray): SipralAbiVersion = SipralAbiVersion(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
            slots[4],
        )
    }
}

/**
 * What this build can do: codecs, signalling transports, optional features.
 *
 * Not configuration: `sipral_stack_settings` answers what a stack has on.
 *
 * Set `size` to `sizeof(sipral_capabilities_t)` before the call.
 */
data class SipralCapabilities(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * How many codecs this build contains (same as `sipral_codec_count`).
     */
    val codecCount: Long,
    /**
     * Transports for signalling, as `SIPRAL_TRANSPORT_BIT_*` bits.
     */
    val transports: Long,
    /**
     * Compiled-in features, as `SIPRAL_FEATURE_*` bits.
     */
    val features: Long,
) {
    internal companion object {
        const val SLOTS: Int = 4

        fun of(slots: LongArray): SipralCapabilities = SipralCapabilities(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
        )
    }
}

/**
 * D3's flat set of health counters for one stack, since it was created.
 * All monotonic except the gauge `active_calls`. Set `size` to
 * `sizeof(sipral_counters_t)` before the call.
 */
data class SipralCounters(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * A REGISTER went out, counted once per attempt including a retry.
     */
    val registrationsAttempted: Long,
    /**
     * The registrar granted a binding.
     */
    val registrationsSucceeded: Long,
    /**
     * The registrar refused, and will refuse the same request again.
     */
    val registrationsFailedRejected: Long,
    /**
     * The password was wrong, or there was none to answer a challenge with.
     */
    val registrationsFailedBadCredentials: Long,
    /**
     * The registrar did not answer, or said it could not serve this now.
     */
    val registrationsFailedUnreachable: Long,
    /**
     * The registrar moved.
     */
    val registrationsFailedRedirected: Long,
    /**
     * This end hung up.
     */
    val callsEndedLocalHangup: Long,
    /**
     * The far end hung up.
     */
    val callsEndedRemoteHangup: Long,
    /**
     * The far end refused it: busy, declined, not found.
     */
    val callsEndedRefused: Long,
    /**
     * Given up before it was answered, from either end.
     */
    val callsEndedCancelled: Long,
    /**
     * Nothing came back, or the transport died.
     */
    val callsEndedUnreachable: Long,
    /**
     * Another branch of the same fork was kept and this one was not.
     */
    val callsEndedForkLost: Long,
    /**
     * The branch was still ringing when the answer window closed.
     */
    val callsEndedAbandoned: Long,
    /**
     * The session timer ran out and no refresh arrived.
     */
    val callsEndedExpired: Long,
    /**
     * Inbound audio stopped past the threshold while signalling was fine (B5).
     */
    val mediaGaps: Long,
    /**
     * Jitter buffer shrink or stretch adjustments.
     */
    val jitterBufferEvents: Long,
    /**
     * A request too big for a datagram with no stream to its destination,
     * so one was requested (RFC 3261 §18.1.1, B1). Reuse of an existing
     * connection does not count.
     */
    val streamTransportWanted: Long,
    /**
     * Calls with media running now; the only gauge.
     */
    val activeCalls: Long,
    /**
     * Events dropped because the outbox was at its ceiling (task 8.4.21).
     */
    val eventsDropped: Long,
    /**
     * RTCP goodbyes dropped, oldest first, because
     * `sipral_stack_poll_farewell` was not keeping up.
     */
    val farewellsDropped: Long,
    /**
     * INVITEs a `sipral_stack_screen` policy refused (A8, D7).
     */
    val screenedRefusedByPolicy: Long,
    /**
     * INVITEs refused for exceeding `sipral_stack_invite_limit`.
     */
    val screenedRefusedByRate: Long,
    /**
     * INVITEs refused because every tracked-source seat was taken: a
     * flood from many addresses.
     */
    val screenedRefusedByCrowding: Long,
    /**
     * INVITEs refused 403 for an unauthorised Replaces (RFC 3891 §3).
     */
    val screenedRefusedByReplaces: Long,
    /**
     * Requests resent by RFC 3261 timers A and E, plus ACKs resent for a
     * repeated 2xx. UDP only; a rising value means packet loss.
     */
    val requestsRetransmitted: Long,
    /**
     * Responses resent: timer G, reliable provisional timer, and repeats
     * for a retransmitted request.
     */
    val responsesRetransmitted: Long,
    /**
     * Transactions ended by timers B, F, H and L, or an unPRACKed
     * reliable provisional response.
     */
    val transactionsTimedOut: Long,
    /**
     * Requests answered `503` because the stack was at
     * `max_server_transactions`, or an INVITE was at `max_dialogs`.
     */
    val requestsRefusedAtLimit: Long,
) {
    internal companion object {
        const val SLOTS: Int = 29

        fun of(slots: LongArray): SipralCounters = SipralCounters(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
            slots[4],
            slots[5],
            slots[6],
            slots[7],
            slots[8],
            slots[9],
            slots[10],
            slots[11],
            slots[12],
            slots[13],
            slots[14],
            slots[15],
            slots[16],
            slots[17],
            slots[18],
            slots[19],
            slots[20],
            slots[21],
            slots[22],
            slots[23],
            slots[24],
            slots[25],
            slots[26],
            slots[27],
            slots[28],
        )
    }
}

/**
 * What one call to sipral_stack_poll did. Set `size` first.
 */
data class SipralPollResult(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * Events handed to the callback during this poll.
     */
    val eventsDelivered: Long,
    /**
     * Events this ABI has no word for yet. Counted, not delivered.
     */
    val eventsUnclaimed: Long,
    /**
     * Bytes this build had nowhere to send; zero, kept for ABI stability.
     */
    val transmitsDiscarded: Long,
    /**
     * Whether there is a deadline. Zero: wait for input.
     */
    val hasDeadline: Long,
    /**
     * Milliseconds from `now_ms` until the stack is due. Zero: due now.
     */
    val nextPollInMs: Long,
) {
    internal companion object {
        const val SLOTS: Int = 6

        fun of(slots: LongArray): SipralPollResult = SipralPollResult(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
            slots[4],
            slots[5],
        )
    }
}

/**
 * What a stack is running with, defaults filled in. Set `size` first.
 */
data class SipralStackSettings(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * The SipralTransport this stack speaks.
     */
    val transport: Long,
    /**
     * Whether this stack retransmits; zero on every transport but UDP.
     */
    val retransmits: Long,
    /**
     * T1 in milliseconds, with the default filled in.
     */
    val timerT1Ms: Long,
    /**
     * T2 in milliseconds, with the default filled in.
     */
    val timerT2Ms: Long,
    /**
     * T4 in milliseconds, with the default filled in.
     */
    val timerT4Ms: Long,
    /**
     * How many codecs this stack offers (`sipral_stack_codec_order`).
     */
    val codecCount: Long,
    /**
     * How long a frame is, with the default filled in.
     */
    val frameMs: Long,
    /**
     * Whether named events are offered, as a `SipralToggle`.
     */
    val offerDtmf: Long,
    /**
     * Whether RTCP multiplexing is asked for, as a `SipralToggle`.
     */
    val offerRtcpMux: Long,
    /**
     * Whether sending stops during silence, as a `SipralToggle`.
     */
    val silenceSuppression: Long,
    /**
     * The media stall interval in milliseconds; zero when the watchdog is off.
     */
    val mediaStallMs: Long,
    /**
     * Whether G.729 Annex B is allowed, as a `SipralToggle`.
     */
    val g729AnnexB: Long,
    /**
     * Whether an out-of-dialog REFER reaches the application, as a `SipralToggle`.
     */
    val referrals: Long,
    /**
     * The registrar keep-alive in milliseconds; zero when off.
     */
    val registrarKeepaliveMs: Long,
    /**
     * The most calls the stack holds at once.
     */
    val maxDialogs: Long,
    /**
     * The most server transactions at once.
     */
    val maxServerTransactions: Long,
    /**
     * How many decisions a diagnostic record keeps.
     */
    val diagnosticDecisions: Long,
    /**
     * How many diagnostic records the stack keeps.
     */
    val diagnosticRecords: Long,
    /**
     * The RTP port range, as given; both zero for none.
     */
    val rtpPortMin: Long,
    /**
     * See `rtp_port_min`.
     */
    val rtpPortMax: Long,
    /**
     * The path MTU as given, zero for unknown (ABI 0.34).
     */
    val pathMtu: Long,
    /**
     * The largest request sent over UDP once no stream is coming; zero for never.
     */
    val datagramWithoutStreamBytes: Long,
    /**
     * How many SRTP suites calls use by default (`sipral_stack_srtp_suite_order`).
     */
    val srtpSuiteCount: Long,
    /**
     * A `SipralToggle`: whether a `pseudonym_salt` was given. Never the salt.
     */
    val pseudonymSalted: Long,
    /**
     * A `SipralToggle`: whether the trace writes whole messages now.
     */
    val diagnosticTrace: Long,
    /**
     * A `SipralToggle`: whether the platform's echo cancellation is asked for.
     */
    val systemEchoCancellation: Long,
) {
    internal companion object {
        const val SLOTS: Int = 27

        fun of(slots: LongArray): SipralStackSettings = SipralStackSettings(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
            slots[4],
            slots[5],
            slots[6],
            slots[7],
            slots[8],
            slots[9],
            slots[10],
            slots[11],
            slots[12],
            slots[13],
            slots[14],
            slots[15],
            slots[16],
            slots[17],
            slots[18],
            slots[19],
            slots[20],
            slots[21],
            slots[22],
            slots[23],
            slots[24],
            slots[25],
            slots[26],
        )
    }
}

/**
 * One codec this build contains.
 *
 * Set `size` to `sizeof(sipral_codec_info_t)` before the call.
 */
data class SipralCodecInfo(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * A SipralCodec.
     */
    val codec: Long,
    /**
     * The RTP timestamp clock, in hertz, which is what goes on the
     * `a=rtpmap` line.
     */
    val clockRate: Long,
    /**
     * The codec's own rate, which the samples crossing this ABI use. G.722's
     * differs from its clock (RFC 3551 §4.5.2).
     */
    val sampleRate: Long,
    /**
     * The payload type RFC 3551 table 4 assigns it, when it has one.
     */
    val staticPayloadType: Long,
    /**
     * Whether it has one. Opus does not.
     */
    val hasStaticPayloadType: Long,
    /**
     * Zero. Pads to the alignment so later members start past this
     * header's length. Written zero, never read.
     */
    val reserved: Long,
) {
    internal companion object {
        const val SLOTS: Int = 7

        fun of(slots: LongArray): SipralCodecInfo = SipralCodecInfo(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
            slots[4],
            slots[5],
            slots[6],
        )
    }
}

/**
 * One codec this call could have used, and what became of it.
 *
 * Set `size` to `sizeof(sipral_codec_candidate_t)` before the call.
 *
 * Recorded when the negotiation decided, never recomputed.
 */
data class SipralCodecCandidate(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * A SipralCodec: the candidate itself.
     */
    val codec: Long,
    /**
     * A SipralCodecOutcome: what became of it.
     */
    val outcome: Long,
    /**
     * A SipralCodec: what beat it, when `outcome` is
     * `SIPRAL_CODEC_OUTCOME_OUTRANKED`; `SIPRAL_CODEC_UNKNOWN` otherwise.
     */
    val outrankedBy: Long,
    /**
     * Zero. Pads to the alignment so later members start past this
     * header's length. Written zero, never read.
     */
    val reserved: Long,
) {
    internal companion object {
        const val SLOTS: Int = 5

        fun of(slots: LongArray): SipralCodecCandidate = SipralCodecCandidate(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
            slots[4],
        )
    }
}

/**
 * What one call's media settled on, and what it is doing now.
 *
 * Set `size` to `sizeof(sipral_media_info_t)` before the call.
 */
data class SipralMediaInfo(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * A SipralCodec: what the two ends agreed on.
     */
    val codec: Long,
    /**
     * The payload type on the wire: the offer's number, not necessarily
     * ours.
     */
    val payloadType: Long,
    /**
     * The RTP timestamp clock, in hertz.
     */
    val clockRate: Long,
    /**
     * The rate the samples crossing this ABI are at: the codec's, or the
     * one sipral_media_set_app_rate chose.
     */
    val sampleRate: Long,
    /**
     * How long a frame is, in milliseconds.
     */
    val frameMs: Long,
    /**
     * Samples in one frame: exactly what sipral_media_playback fills and
     * what sipral_media_capture wants, at `sample_rate`.
     */
    val frameSamples: Long,
    /**
     * A SipralDirection.
     */
    val direction: Long,
    /**
     * Whether this end is meant to be sending. Zero while it holds the far
     * end, or while the far end has refused to receive.
     */
    val sending: Long,
    /**
     * Whether this end is meant to be receiving.
     */
    val receiving: Long,
    /**
     * Whether RFC 4733 named events were agreed.
     */
    val hasDtmf: Long,
    /**
     * The payload type they travel under, when they were.
     */
    val dtmfPayloadType: Long,
    /**
     * A SipralRtcp.
     */
    val rtcp: Long,
    /**
     * Whether the stream is keyed.
     */
    val secured: Long,
    /**
     * Whether a recording is running on this call.
     */
    val recording: Long,
    /**
     * How much audio it has taken.
     */
    val recordedMs: Long,
    /**
     * Whether the watchdog currently considers inbound audio stopped.
     */
    val stalled: Long,
    /**
     * Whether the call agreed a real-time text stream (RFC 4103), which
     * `sipral_media_send_text` writes to.
     */
    val hasText: Long,
    /**
     * Whether the audio stream runs RTP/AVPF (RFC 4585): both ends named
     * a feedback profile.
     */
    val feedback: Long,
    /**
     * Whether both ends agreed Generic NACKs (`a=rtcp-fb:* nack`), so
     * that a gap in what arrives is asked for again.
     */
    val genericNack: Long,
    /**
     * Whether both ends agreed reduced-size RTCP (RFC 5506,
     * `a=rtcp-rsize`).
     */
    val reducedSize: Long,
    /**
     * Zero. Pads to the alignment so later members start past this
     * header's length. Written zero, never read.
     */
    val reserved: Long,
) {
    internal companion object {
        const val SLOTS: Int = 22

        fun of(slots: LongArray): SipralMediaInfo = SipralMediaInfo(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
            slots[4],
            slots[5],
            slots[6],
            slots[7],
            slots[8],
            slots[9],
            slots[10],
            slots[11],
            slots[12],
            slots[13],
            slots[14],
            slots[15],
            slots[16],
            slots[17],
            slots[18],
            slots[19],
            slots[20],
            slots[21],
        )
    }
}

/**
 * What one call's media has cost, and what it is costing now.
 *
 * Cheap enough to read at UI frame rate. The same struct arrives with
 * `SIPRAL_EVENT_KIND_MEDIA_STATISTICS` when the call ends. Delays are in
 * microseconds, since healthy jitter is below a millisecond.
 *
 * Set `size` to `sizeof(sipral_stream_stats_t)` before the call.
 */
data class SipralStreamStats(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * A SipralCodec: what the call settled on.
     */
    val codec: Long,
    /**
     * Whether a round-trip time is known. Zero until a report comes back,
     * which may be never (RFC 3550 §6.2 delays the first one).
     */
    val hasRoundTrip: Long,
    /**
     * The round trip, from RTCP.
     */
    val roundTripUs: Long,
    /**
     * Packets this end has put on the wire.
     */
    val packetsSent: Long,
    /**
     * Payload octets in them, not counting headers.
     */
    val octetsSent: Long,
    /**
     * Packets taken in and held for playout.
     */
    val packetsReceived: Long,
    /**
     * Sequence numbers that came due with nothing in them.
     */
    val packetsLost: Long,
    /**
     * Packets that arrived behind the playout point.
     */
    val packetsLate: Long,
    /**
     * Packets thrown out of the window before they could be played.
     */
    val packetsOverflowed: Long,
    /**
     * Packets whose sequence number was already held.
     */
    val packetsDuplicated: Long,
    /**
     * Packets accepted after a higher sequence number had already arrived.
     */
    val packetsReordered: Long,
    /**
     * Frames dropped in a pause to bring the delay down.
     */
    val framesShrunk: Long,
    /**
     * Frames concealment invented in a pause to push the delay up.
     */
    val framesStretched: Long,
    /**
     * How far behind the newest packet the playout point is.
     */
    val delayUs: Long,
    /**
     * What the buffer is aiming at, from the arrival times it has seen.
     */
    val targetDelayUs: Long,
    /**
     * Interarrival jitter, the smoothed mean deviation of transit time
     * (RFC 3550 §6.4.1).
     */
    val jitterUs: Long,
    /**
     * Frames concealed as a fraction of frames played, over about the last
     * ten seconds.
     */
    val lossRate: Float,
    /**
     * 100 for a flawless call, 0 for an unusable one. Not a MOS.
     */
    val score: Float,
    /**
     * Whether the numbers say this call is in trouble now.
     */
    val suffering: Long,
    /**
     * How long since a packet last arrived. A live call sits at one frame.
     */
    val silentForMs: Long,
    /**
     * Whether an RFC 3611 VoIP Metrics report is available. Every `voip_*`
     * member is meaningless while this is zero.
     */
    val hasVoipMetrics: Long,
    /**
     * RFC 3611 SS4.7.1's loss rate, as its own 256ths (multiply by
     * 100 and divide by 256 for a percentage).
     */
    val voipLossRate256: Long,
    /**
     * RFC 3611 SS4.7.1's discard rate, as its own 256ths.
     */
    val voipDiscardRate256: Long,
    /**
     * RFC 3611 SS4.7.2's burst density, as its own 256ths.
     */
    val voipBurstDensity256: Long,
    /**
     * RFC 3611 SS4.7.2's mean burst duration.
     */
    val voipBurstDurationUs: Long,
    /**
     * RFC 3611 SS4.7.2's gap density, as its own 256ths.
     */
    val voipGapDensity256: Long,
    /**
     * RFC 3611 SS4.7.2's mean gap duration.
     */
    val voipGapDurationUs: Long,
    /**
     * RFC 3611 SS4.7.2's `Gmin`, the burst/gap threshold, fixed per stream.
     */
    val voipGmin: Long,
    /**
     * RFC 3611 SS4.7.3's end-system delay. Always zero: it needs the
     * sending side's delay, which this end cannot see.
     */
    val voipEndSystemDelayUs: Long,
    /**
     * RFC 3611 SS4.7.7's nominal jitter buffer delay.
     */
    val voipJitterBufferNominalUs: Long,
    /**
     * RFC 3611 SS4.7.7's current maximum jitter buffer delay.
     */
    val voipJitterBufferMaximumUs: Long,
    /**
     * RFC 3611 SS4.7.7's absolute maximum jitter buffer delay.
     */
    val voipJitterBufferAbsMaxUs: Long,
    /**
     * Whether `voip_r_factor` is available: zero when ITU-T G.113 has no
     * `Ie`/`Bpl` for the codec (RFC 3611 SS4.7.5's `127` sentinel).
     */
    val hasVoipRFactor: Long,
    /**
     * RFC 3611 SS4.7.5's R factor, `0..=100`.
     */
    val voipRFactor: Long,
    /**
     * Whether `voip_mos_lq_x10` is available, for the same reason as
     * `has_voip_r_factor`.
     */
    val hasVoipMosLq: Long,
    /**
     * RFC 3611 SS4.7.5's estimated listening-quality MOS, in tenths
     * (`14..=50`).
     */
    val voipMosLqX10: Long,
    /**
     * Whether `voip_mos_cq_x10` is available, for the same reason.
     */
    val hasVoipMosCq: Long,
    /**
     * RFC 3611 SS4.7.5's estimated conversational-quality MOS, in
     * tenths.
     */
    val voipMosCqX10: Long,
    /**
     * Frames played empty because the jitter buffer ran dry while the far
     * end was still sending. Not lost packets (`packets_lost`), so the
     * `voip_*` rates miss it (RFC 3611 SS4.7.1 counts packets);
     * `loss_rate`, `score` and `suffering` include it.
     */
    val framesUnderrun: Long,
    /**
     * Whether the stream runs RTP/AVPF (RFC 4585). The counts below stay
     * zero otherwise.
     */
    val feedback: Long,
    /**
     * The `trr-int` both ends agreed: the least time between two
     * regular reports, in milliseconds. Zero for none.
     */
    val trrIntervalMs: Long,
    /**
     * Generic NACKs this end sent, each asking for one or more packets.
     */
    val nacksSent: Long,
    /**
     * The packets those NACKs asked for.
     */
    val packetsNacked: Long,
    /**
     * Generic NACKs the far end sent.
     */
    val nacksReceived: Long,
    /**
     * The packets those asked this end for.
     */
    val packetsAskedFor: Long,
    /**
     * Early RTCP packets this end sent.
     */
    val earlyPackets: Long,
    /**
     * Reduced-size RTCP packets this end sent (RFC 5506).
     */
    val reducedSizePackets: Long,
    /**
     * Feedback held back for lack of RTCP bandwidth.
     */
    val feedbackSuppressed: Long,
) {
    internal companion object {
        const val SLOTS: Int = 49

        fun of(slots: LongArray): SipralStreamStats = SipralStreamStats(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
            slots[4],
            slots[5],
            slots[6],
            slots[7],
            slots[8],
            slots[9],
            slots[10],
            slots[11],
            slots[12],
            slots[13],
            slots[14],
            slots[15],
            slots[16],
            Float.fromBits(slots[17].toInt()),
            Float.fromBits(slots[18].toInt()),
            slots[19],
            slots[20],
            slots[21],
            slots[22],
            slots[23],
            slots[24],
            slots[25],
            slots[26],
            slots[27],
            slots[28],
            slots[29],
            slots[30],
            slots[31],
            slots[32],
            slots[33],
            slots[34],
            slots[35],
            slots[36],
            slots[37],
            slots[38],
            slots[39],
            slots[40],
            slots[41],
            slots[42],
            slots[43],
            slots[44],
            slots[45],
            slots[46],
            slots[47],
            slots[48],
        )
    }
}

/**
 * What was standing when sipral_stack_suspending was called. Set
 * `size` to `sizeof(sipral_suspending_t)` first.
 *
 * Counts only: no allocation in the suspend window. All of it is past
 * tense when read, and nothing was sent about any of it.
 */
data class SipralSuspending(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * Bindings that read as live and do not any more.
     */
    val unverified: Long,
    /**
     * Subscriptions whose last notification stopped being evidence.
     */
    val subscriptions: Long,
    /**
     * Calls that were up, left untouched: hanging up because the machine
     * blinked is worse than learning later that a call is gone.
     */
    val calls: Long,
) {
    internal companion object {
        const val SLOTS: Int = 4

        fun of(slots: LongArray): SipralSuspending = SipralSuspending(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
        )
    }
}

/**
 * One dialog a `dialog` subscription was told about. Its text is read
 * with sipral_subscription_dialog_text, so no pointer can dangle.
 */
data class SipralWatchedDialog(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * A SipralDialogPhase.
     */
    val phase: Long,
    /**
     * A SipralDialogDirection.
     */
    val direction: Long,
    /**
     * A SipralDialogEnded, and zero while the dialog has not.
     */
    val ended: Long,
    /**
     * The SIP status behind how it ended, or zero.
     */
    val statusCode: Long,
    /**
     * How long it has been up, in milliseconds, or zero.
     */
    val durationMs: Long,
) {
    internal companion object {
        const val SLOTS: Int = 6

        fun of(slots: LongArray): SipralWatchedDialog = SipralWatchedDialog(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
            slots[4],
            slots[5],
        )
    }
}

/**
 * What the registrar said about push, in the 2xx to a REGISTER that
 * asked for it (RFC 8599 §8.2).
 */
data class SipralPushEcho(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * Whether the network promised pushes of the requested type. Zero
     * means not promised (§4.1.1): do not suspend relying on a push.
     */
    val accepted: Long,
    /**
     * Whether `refresh_lead_ms` was sent at all.
     */
    val hasRefreshLead: Long,
    /**
     * How long before expiry the network wants a refresh, from
     * `sip.pnsreg` (§4.1.4), in milliseconds; zero when not sent.
     */
    val refreshLeadMs: Long,
) {
    internal companion object {
        const val SLOTS: Int = 4

        fun of(slots: LongArray): SipralPushEcho = SipralPushEcho(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
        )
    }
}

/**
 * One device, as `sipral_audio_device_at` fills it in. Set `size` to
 * `sizeof(sipral_audio_device_t)` before the call.
 */
data class SipralAudioDevice(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * The engine's name for the device: stable across refreshes, never
     * reused, never zero. What `sipral_audio_select` takes.
     */
    val id: Long,
    /**
     * Channels it captures; zero for a device that is no microphone.
     */
    val inputChannels: Long,
    /**
     * How many channels it plays; zero likewise.
     */
    val outputChannels: Long,
    /**
     * One when the system records from it by default.
     */
    val defaultInput: Long,
    /**
     * One when the system plays to it by default.
     */
    val defaultOutput: Long,
    /**
     * One when the last refresh found it. An absent device keeps its row
     * and id, so a saved selection still names something.
     */
    val present: Long,
) {
    internal companion object {
        const val SLOTS: Int = 7

        fun of(slots: LongArray): SipralAudioDevice = SipralAudioDevice(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
            slots[4],
            slots[5],
            slots[6],
        )
    }
}

/**
 * What the engine is doing, as `sipral_audio_info` fills it in. Set
 * `size` to `sizeof(sipral_audio_info_t)` before the call.
 */
data class SipralAudioInfo(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * One while the devices are open and the pump is running.
     */
    val active: Long,
    /**
     * One when the platform's own processing sits behind the microphone:
     * the voice-processing unit on macOS and iOS, a communications stream
     * on Windows (a virtual cable cancels nothing). For echo removal
     * regardless, attach a processor per call; the engine tells each
     * managed call `render_delay_ms` itself, after every device change.
     */
    val systemEchoCancellation: Long,
    /**
     * The loudspeaker-to-microphone delay the devices report, in
     * milliseconds.
     */
    val renderDelayMs: Long,
    /**
     * The rate the microphone runs at, or zero when it is not open.
     */
    val microphoneRateHz: Long,
    /**
     * The rate the loudspeaker runs at, or zero when it is not open.
     */
    val speakerRateHz: Long,
    /**
     * The device the microphone is running on, or zero.
     */
    val microphone: Long,
    /**
     * The device the loudspeaker is running on, or zero.
     */
    val speaker: Long,
    /**
     * The device the ringer is running on, or zero when the ring goes
     * through the loudspeaker.
     */
    val ringer: Long,
    /**
     * Zero. Pads the struct to a multiple of its alignment, so a member
     * appended later never lands in padding. Written zero, never read.
     */
    val reserved: Long,
) {
    internal companion object {
        const val SLOTS: Int = 10

        fun of(slots: LongArray): SipralAudioInfo = SipralAudioInfo(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
            slots[4],
            slots[5],
            slots[6],
            slots[7],
            slots[8],
            slots[9],
        )
    }
}

/**
 * How one stream of a call is protected.
 *
 * Set `size` to `sizeof(sipral_stream_encryption_t)` before the call.
 */
data class SipralStreamEncryption(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * A SipralMediaKind: what the stream carries.
     */
    val media: Long,
    /**
     * Whether it is encrypted now. Zero while waiting for its keys.
     */
    val encrypted: Long,
    /**
     * A SipralKeyExchange: how its keys were exchanged.
     */
    val keyExchange: Long,
    /**
     * A SipralSrtpSuite: the transform it runs, once it runs one.
     */
    val suite: Long,
    /**
     * Whether the key exchange authenticated the far end: set for
     * DTLS-SRTP after a handshake matching the fingerprint; never for
     * SDES, which is only as authentic as the signalling.
     */
    val authenticated: Long,
    /**
     * Agreed to be encrypted and still waiting for keys.
     */
    val awaitingKeys: Long,
) {
    internal companion object {
        const val SLOTS: Int = 7

        fun of(slots: LongArray): SipralStreamEncryption = SipralStreamEncryption(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
            slots[4],
            slots[5],
            slots[6],
        )
    }
}

/**
 * A conference as a `conference` subscription holds it, read with
 * sipral_subscription_conference.
 */
data class SipralConference(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * The version of the last document merged.
     */
    val version: Long,
    /**
     * Users held, indexed by sipral_subscription_conference_user_at.
     */
    val users: Long,
    /**
     * Whether `user-count` was sent; it may differ from `users`.
     */
    val hasUserCount: Long,
    /**
     * That count, when it said.
     */
    val userCount: Long,
    /**
     * `active`: 1 true, 2 false, 0 not said.
     */
    val active: Long,
    /**
     * Its `locked`, the same way.
     */
    val locked: Long,
) {
    internal companion object {
        const val SLOTS: Int = 7

        fun of(slots: LongArray): SipralConference = SipralConference(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
            slots[4],
            slots[5],
            slots[6],
        )
    }
}

/**
 * One user of a conference, read with
 * sipral_subscription_conference_user_at; its text is read with
 * sipral_subscription_conference_text.
 */
data class SipralConferenceUser(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * How many endpoints (devices) the user joined from.
     */
    val endpoints: Long,
    /**
     * A SipralEndpointStatus of the first endpoint.
     */
    val status: Long,
    /**
     * Media streams of the first endpoint.
     */
    val media: Long,
    /**
     * Zero. Pads to alignment so later members never land in padding.
     */
    val reserved: Long,
) {
    internal companion object {
        const val SLOTS: Int = 5

        fun of(slots: LongArray): SipralConferenceUser = SipralConferenceUser(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
            slots[4],
        )
    }
}

/**
 * A conference as it stands: `sipral_local_conference_info`.
 *
 * Set `size` to `sizeof(sipral_local_conference_info_t)` first.
 */
data class SipralLocalConferenceInfo(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * Members, this end included.
     */
    val members: Long,
    /**
     * The most it holds.
     */
    val capacity: Long,
    /**
     * Members talking in the last tick.
     */
    val talkers: Long,
    /**
     * 1 when this end takes part.
     */
    val local: Long,
    /**
     * The rate of this end's frames, in hertz.
     */
    val sampleRate: Long,
    /**
     * Samples in one of this end's frames: twenty milliseconds.
     */
    val frameSamples: Long,
    /**
     * 1 while the conference is being recorded.
     */
    val recording: Long,
    /**
     * Recorded so far, while recording.
     */
    val recordedMs: Long,
    /**
     * Packets dropped because nobody polled for them in time.
     */
    val packetsDropped: Long,
) {
    internal companion object {
        const val SLOTS: Int = 10

        fun of(slots: LongArray): SipralLocalConferenceInfo = SipralLocalConferenceInfo(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
            slots[4],
            slots[5],
            slots[6],
            slots[7],
            slots[8],
            slots[9],
        )
    }
}

/**
 * One member of a conference: `sipral_local_conference_member_at`.
 *
 * Set `size` to `sizeof(sipral_local_conference_member_t)` first.
 */
data class SipralLocalConferenceMember(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * The call, or the conference's own handle for this end.
     */
    val member: Long,
    /**
     * 1 when it was talking in the last tick, muted or not.
     */
    val talking: Long,
    /**
     * 1 when nobody hears it.
     */
    val mutedInput: Long,
    /**
     * 1 when it hears nothing.
     */
    val mutedOutput: Long,
    /**
     * Level of what it says, in `sipral_audio_set_gain` steps (256 = unity).
     */
    val gainInput: Long,
    /**
     * The level of what it hears, in the same steps.
     */
    val gainOutput: Long,
    /**
     * Zero. Pads the struct to its alignment so an appended member starts
     * past the declared length. Written as zero, never read.
     */
    val reserved: Long,
) {
    internal companion object {
        const val SLOTS: Int = 8

        fun of(slots: LongArray): SipralLocalConferenceMember = SipralLocalConferenceMember(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
            slots[4],
            slots[5],
            slots[6],
            slots[7],
        )
    }
}

/**
 * What sipral_account_check_certificate found: whether the account's
 * pin decided, and what the certificate's dates say.
 *
 * Set `size` to `sizeof(sipral_pinned_certificate_t)` before the call.
 */
data class SipralPinnedCertificate(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * The certificate's `notBefore`, in seconds since 1 January 1970,
     * or zero when its DER could not be read that far.
     */
    val notBefore: Long,
    /**
     * Its `notAfter`, the same way.
     */
    val notAfter: Long,
    /**
     * One: pinned and matching, accept. Zero: no pin, platform checks apply.
     */
    val pinned: Long,
    /**
     * One when past `not_after`. Still accepted (a lapsed self-signed PBX
     * would go silent); worth a warning.
     */
    val expired: Long,
    /**
     * One when before `not_before`. Still accepted.
     */
    val notYetValid: Long,
    /**
     * Zero.
     */
    val reserved: Long,
) {
    internal companion object {
        const val SLOTS: Int = 7

        fun of(slots: LongArray): SipralPinnedCertificate = SipralPinnedCertificate(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
            slots[4],
            slots[5],
            slots[6],
        )
    }
}

/**
 * One header field an application hands over: a name and a value, UTF-8,
 * neither NUL-terminated.
 *
 * No `size` member: it is an array element, so it never grows.
 *
 * Handed over in a list, which the JNI shim makes into a C array for the
 * length of the call. `packed` copies every piece of text into one array of
 * UTF-8 first, and the shim checks every length against that array before
 * it points into it. An empty piece of text crosses as a null pointer with
 * a length of zero.
 */
class SipralHeader(
    /**
     * The field name, `X-Conversation-Id`. A compact form is the field it
     * abbreviates.
     */
    val name: String,
    /**
     * The value, as it goes on the line after the colon. Null or empty
     * for a field with an empty value.
     */
    val value: String,
) {
    internal companion object {
        /**
         * A list of them as the JNI shim takes it: every piece of text in
         * every element, in order, as one run of UTF-8, and how many bytes
         * each took, 2 to an element. A null list is two nulls, which the
         * shim reads as no elements.
         */
        fun packed(list: List<SipralHeader>?): Pair<ByteArray?, LongArray?> {
            if (list == null) {
                return Pair(null, null)
            }
            val run = java.io.ByteArrayOutputStream()
            val lengths = LongArray(Math.multiplyExact(list.size, 2))
            var part = 0
            for (element in list) {
                val nameBytes = element.name.toByteArray(Charsets.UTF_8)
                run.write(nameBytes, 0, nameBytes.size)
                lengths[part] = nameBytes.size.toLong()
                part += 1
                val valueBytes = element.value.toByteArray(Charsets.UTF_8)
                run.write(valueBytes, 0, valueBytes.size)
                lengths[part] = valueBytes.size.toLong()
                part += 1
            }
            return Pair(run.toByteArray(), lengths)
        }
    }
}

/**
 * What a stack is created with. Set `size` to `sizeof(sipral_stack_config_t)`
 * and zero the rest first. Required: the callback, the transport, the reachable
 * address, the entropy, and a media seed different from the entropy.
 *
 * Built here and copied into the C struct by the JNI shim, which sets the
 * size member itself: a field left at its default is the zero the struct
 * would have held.
 */
class SipralStackConfig(
    /**
     * Where events go. Required.
     */
    val eventListener: SipralEventListener? = null,
    /**
     * A SipralTransport.
     */
    val transport: Long = 0,
    /**
     * The address the far end reaches this one at, as `host:port`, UTF-8 and
     * not NUL-terminated. It goes in every `Via`.
     */
    val bindAddress: String? = null,
    /**
     * `User-Agent` for every REGISTER and INVITE this stack originates, or null
     * for none (optional per §20 Table 3).
     */
    val userAgent: String? = null,
    /**
     * Thirty-two bytes from the platform's generator. Every branch, tag and
     * `Call-ID` derives from it, and §19.3 wants a tag unguessable. Never
     * shared between stacks. Media keys come from `media_seed`.
     */
    val entropy: ByteArray? = null,
    /**
     * T1 in milliseconds, or zero for the 500 ms of §17.1.1.1.
     */
    val timerT1Ms: Long = 0,
    /**
     * T2 in milliseconds, or zero for four seconds. UDP only; set on another
     * transport it is `SIPRAL_STATUS_INVALID_ARGUMENT`.
     */
    val timerT2Ms: Long = 0,
    /**
     * T4 in milliseconds, or zero for five seconds. UDP only, like T2.
     */
    val timerT4Ms: Long = 0,
    /**
     * The codecs to offer, in order (A4, RFC 3264 §6.1): comma-separated names,
     * UTF-8, not NUL-terminated; null for every codec built in. An unknown name is
     * `SIPRAL_STATUS_NOT_SUPPORTED`, with the known names in the last error.
     */
    val codecs: String? = null,
    /**
     * Frame length in milliseconds, or zero for twenty. Must suit Opus if offered.
     */
    val frameMs: Long = 0,
    /**
     * Whether to offer RFC 4733 named events, as a `SipralToggle`. On by default.
     */
    val offerDtmf: Long = 0,
    /**
     * Whether to ask for RFC 5761 multiplexing (§5.1.1), as a `SipralToggle`.
     * Off by default.
     */
    val offerRtcpMux: Long = 0,
    /**
     * Whether to stop sending during silence, as a `SipralToggle`. Off by
     * default: with no comfort noise, the gap looks like a dead stream.
     */
    val silenceSuppression: Long = 0,
    /**
     * Whether inbound audio that stops is reported (B5), as a `SipralToggle`.
     * On by default.
     */
    val mediaStallWatchdog: Long = 0,
    /**
     * How long inbound audio may stop before it is reported, in milliseconds,
     * or zero for the default. Refused with the watchdog off.
     */
    val mediaStallMs: Long = 0,
    /**
     * The wall clock at creation, in seconds since the Unix epoch, for RFC 3550
     * §6.4.1 sender reports; zero to wait for `sipral_stack_stir`'s `unix_seconds`.
     */
    val mediaClockUnixSeconds: Long = 0,
    /**
     * Thirty-two more bytes for the media keys, **not the same bytes as
     * `entropy`**, which recordings write in clear. The same bytes are refused.
     */
    val mediaSeed: ByteArray? = null,
    /**
     * Default SRTP for every call: a `SipralSrtp`, or zero for
     * `SIPRAL_SRTP_NOT_OFFERED`. `sipral_call_config_t::srtp` overrides it.
     */
    val srtp: Long = 0,
    /**
     * Default ICE for every call: a `SipralIce`, or zero for `SIPRAL_ICE_OFF`
     * (`docs/06-nat.md`). `sipral_call_config_t::ice` overrides it.
     */
    val ice: Long = 0,
    /**
     * A `SipralNat`, or zero for `SIPRAL_NAT_OFF`. `SIPRAL_NAT_STUN` asks
     * `stun_server` where each socket appears from (`docs/06-nat.md`).
     */
    val nat: Long = 0,
    /**
     * The STUN server, as a `host:port` address. Required with and only with
     * `SIPRAL_NAT_STUN`. Copied.
     */
    val stunServer: String? = null,
    /**
     * Whether G.729 Annex B is allowed, as a `SipralToggle`. On by default (RFC
     * 4856 §2.1.9); off, SDP says `annexb=no` (RFC 3551 §4.5.6).
     */
    val g729AnnexB: Long = 0,
    /**
     * A TURN server (RFC 8656), as `host:port`, to relay every media socket
     * `sipral_stack_nat_map` names (`docs/06-nat.md`). Only with `SIPRAL_NAT_STUN`,
     * needs `turn_username` and `turn_password`, and `SIPRAL_FEATURE_ICE`. Copied.
     */
    val turnServer: String? = null,
    /**
     * The TURN long-term credential's user name (RFC 8489 §9.2).
     */
    val turnUsername: String? = null,
    /**
     * Its password. Copied, wiped at destroy, never logged.
     */
    val turnPassword: String? = null,
    /**
     * Whether an out-of-dialog REFER (RFC 3515 §4.1) reaches the application, as
     * a `SipralToggle`. **Off by default**: each is refused 403, since an
     * unauthenticated peer could make the phone dial anywhere. On, each is raised
     * as `SIPRAL_EVENT_KIND_REFERRAL`.
     */
    val referrals: Long = 0,
    /**
     * Whether an account behind a NAT sends a double CRLF to its registrar every
     * `registrar_keepalive_ms` over UDP, as a `SipralToggle`. **On by default.**
     * Without it an address-and-port filtering NAT (RFC 4787 §5) drops a later
     * INVITE; registrars ignore it (RFC 3261 §7.5). See `docs/06-nat.md`.
     */
    val registrarKeepalive: Long = 0,
    /**
     * Keep-alive interval in milliseconds, or zero for 25 s (RFC 5626 §4.4.2),
     * jittered to 80-100%. From 1 000 to 120 000 (RFC 4787 REQ-5), and only with
     * `registrar_keepalive` on.
     */
    val registrarKeepaliveMs: Long = 0,
    /**
     * How media sockets reach `turn_server`, as a `SipralTransport`: UDP (or
     * zero), TCP, or TLS (RFC 8656 §4.1). Over TCP or TLS the application opens a
     * connection when `SIPRAL_EVENT_KIND_TURN_STREAM` asks.
     */
    val turnTransport: Long = 0,
    /**
     * Who pumps audio, as a `SipralAudio`: zero or `SIPRAL_AUDIO_APPLICATION`
     * for the application; `SIPRAL_AUDIO_DEVICE` for the library, which needs
     * `audio_transmit_callback` and `SIPRAL_FEATURE_AUDIO_DEVICE`.
     */
    val audio: Long = 0,
    /**
     * When devices open in device mode: a `SipralAudioActivation`, or zero for
     * `SIPRAL_AUDIO_ACTIVATION_AUTOMATIC`.
     */
    val audioActivation: Long = 0,
    /**
     * Device mode: receives each encoded packet on the engine's thread.
     * Required with `SIPRAL_AUDIO_DEVICE`.
     */
    val audioTransmitListener: SipralAudioTransmitListener? = null,
    /**
     * How long a device call may block before `SIPRAL_STATUS_DEVICE_TIMED_OUT`,
     * in milliseconds; zero for three seconds.
     */
    val audioProbeMs: Long = 0,
    /**
     * The device rate in device mode; zero for 48000.
     */
    val audioDeviceRateHz: Long = 0,
    /**
     * The most calls at once, either direction, or zero for 128. Past it an
     * INVITE gets `503` with `Retry-After: 2` (RFC 3261 §21.5.4), and a placed
     * call is `SIPRAL_STATUS_LIMIT_REACHED`. See `docs/19-numbers.md`.
     */
    val maxDialogs: Long = 0,
    /**
     * The most server transactions (RFC 3261 §17.2) at once, or zero for 256;
     * past it a stateless `503`. A BYE is never refused.
     */
    val maxServerTransactions: Long = 0,
    /**
     * D1: how many decisions each diagnostic record keeps, or zero for 64.
     */
    val diagnosticDecisions: Long = 0,
    /**
     * D1: how many calls have a diagnostic record at once, or zero for 32; the
     * oldest is dropped and counted.
     */
    val diagnosticRecords: Long = 0,
    /**
     * When a call listens for in-band keypad digits, as a
     * SipralDtmfDetection; zero for calls with no telephone event. Placed
     * here to avoid tail padding.
     */
    val dtmfDetection: Long = 0,
    /**
     * Fallback STUN servers, comma-separated `host:port`, tried in order when
     * `stun_server` fails; a failed one is skipped from 30 s up to ten minutes.
     * Only with `stun_server`. Copied.
     */
    val stunFallbacks: String? = null,
    /**
     * The lowest RTP port handed out (`sipral_stack_rtp_port_reserve`), or zero
     * with `rtp_port_max` for none. Even ports only (RFC 3550 §11).
     */
    val rtpPortMin: Long = 0,
    /**
     * The highest port of that range, or zero with `rtp_port_min`.
     */
    val rtpPortMax: Long = 0,
    /**
     * The SRTP suites calls offer and accept unless the account names its own:
     * names from RFC 4568 section 6.2 and RFC 7714 section 14.2, comma-separated,
     * preferred first; null for the build's order.
     */
    val srtpSuites: String? = null,
    /**
     * The path MTU in bytes, or zero for unknown (RFC 3261 section 18.1.1).
     * At least 576 (RFC 791).
     */
    val pathMtu: Long = 0,
    /**
     * Largest request sent over UDP once no stream can be had, in bytes; zero
     * for never. **A deliberate deviation from RFC 3261 section 18.1.1**, for
     * UDP-only servers. At most 65 507.
     */
    val datagramWithoutStreamBytes: Long = 0,
    /**
     * A per-installation salt (at least 16 bytes) so pseudonyms match across
     * runs; null keys them from `media_seed`. Secret. Copied.
     */
    val pseudonymSalt: ByteArray? = null,
    /**
     * A `SipralToggle`: whether the trace writes SIP messages unpseudonymised;
     * off by default. Credentials and keys are always removed.
     */
    val diagnosticTrace: Long = 0,
    /**
     * Zero.
     */
    val reserved: Long = 0,
    /**
     * A `SipralToggle`: whether device mode uses the platform's echo
     * cancellation; on by default.
     */
    val systemEchoCancellation: Long = 0,
    /**
     * Zero.
     */
    val reserved35: Long = 0,
    /**
     * A SipralHeldAudio: what a held party is sent (RFC 3264 §8.4). Zero
     * is silence.
     */
    val heldAudio: Long = 0,
    /**
     * Zero.
     */
    val reserved36: Long = 0,
)

/**
 * What an account is configured with. Set `size` to
 * `sizeof(sipral_account_config_t)` and zero the rest first.
 *
 * Built here and copied into the C struct by the JNI shim, which sets the
 * size member itself: a field left at its default is the zero the struct
 * would have held.
 */
class SipralAccountConfig(
    /**
     * The address of record, `sip:alice@example.com`. UTF-8, not
     * NUL-terminated.
     */
    val aor: String? = null,
    /**
     * Where the REGISTER is addressed, `sip:example.com`, no user part.
     * A `registrar_len` of zero makes a trunk that never registers: its
     * state stays `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING`, and
     * `sipral_account_register` refuses it.
     */
    val registrar: String? = null,
    /**
     * Where this endpoint can be reached, as it goes in `Contact`.
     */
    val contact: String? = null,
    /**
     * Where this account's requests go, as `host:port`: the registrar, or
     * the outbound proxy for an account with no registrar. Calls without
     * a destination go here too. Required unless `server_uri` is given;
     * an address, not a name.
     */
    val registrarAddress: String? = null,
    /**
     * The display name that goes in `From`, or null for none.
     */
    val displayName: String? = null,
    /**
     * The user name to answer a challenge with, or null for none.
     */
    val authUser: String? = null,
    /**
     * The password that goes with it, copied.
     */
    val authPassword: String? = null,
    /**
     * The `+sip.instance` URN of RFC 5626 §4.1, or null for none.
     */
    val instanceId: String? = null,
    /**
     * How long a binding to ask for, or zero for an hour.
     *
     * Above 2³²−1 is refused (§20.19 `delta-seconds`). The registrar's
     * grant wins, and is read back in
     * `sipral_registration_event_t::expires_ms`.
     */
    val expiresSeconds: Long = 0,
    /**
     * Header fields for every REGISTER of this account, in order, or null.
     *
     * Checked on add as `sipral_call_config_t::headers` is: `Expires` is
     * the stack's (`expires_seconds`), `Supported` the application's (for
     * GRUU). Refused for an account with no registrar.
     */
    val headers: List<SipralHeader>? = null,
    /**
     * The transport for this account's REGISTER and requests:
     * SIPRAL_TRANSPORT_MAIN
     * for zero, or a number
     * sipral_stack_transport_bind
     * has bound. An unbound number is `SIPRAL_STATUS_INVALID_ARGUMENT`.
     */
    val transport: Long = 0,
    /**
     * The push service to be woken through, by registered name: `apns`,
     * `fcm`, `webpush` (RFC 8599 §4.1.1). Null for no push.
     *
     * The push parameters go only on this account's REGISTER `Contact`
     * (§4.1): on an INVITE `pn-prid` would let the far end wake this
     * device at will. De-registration leaves the identifier out (§4.1.2).
     */
    val pushProvider: String? = null,
    /**
     * The device token the service issued. Required with
     * `push_provider`, and refused without it. Percent-escaped where SIP
     * needs it (§8.7): APNs tokens carry `=`, Web Push ids are URLs.
     */
    val pushPrid: String? = null,
    /**
     * The extra value a service needs: the bundle for Apple, the sender
     * for Firebase. Optional; §4.1.1 lets the service decide.
     */
    val pushParam: String? = null,
    /**
     * Nonzero when this device can refresh its binding without a push,
     * declared with `+sip.pnsreg` (§4.1.4). Only the application knows:
     * a suspended process runs no timer, and a false claim stops the
     * registrar's wake-ups.
     */
    val pushWakesItself: Long = 0,
    /**
     * Where end-of-call quality reports go (RFC 6035 over PUBLISH, RFC
     * 3903), or null for none.
     */
    val qualityReportUri: String? = null,
    /**
     * A SipralSessionTimer: how this account's calls ask for a
     * session timer (RFC 4028). Zero is the default, thirty minutes.
     */
    val sessionTimer: Long = 0,
    /**
     * The interval to ask for under `SIPRAL_SESSION_TIMER_INTERVAL`, in
     * seconds: at least 90, RFC 4028 §5's floor. Read for nothing else.
     */
    val sessionIntervalSeconds: Long = 0,
    /**
     * `SIPRAL_PRIVACY_*` bits: place every call anonymously (RFC 3323).
     * `From` becomes `"Anonymous" <sip:anonymous@anonymous.invalid>`,
     * `Privacy` carries the bits, and `P-Asserted-Identity` goes only to
     * a peer in `trusted_peers`. Zero asks for none.
     */
    val privacy: Long = 0,
    /**
     * Trusted peers (RFC 3325's trust domain), comma-separated IP
     * addresses. Only their asserted identity is read
     * (`sipral_call_event_t::asserted_uri`). Once any are named, calls to
     * other peers carry no `P-Asserted-Identity` or `P-Preferred-Identity`.
     * Null trusts nobody.
     */
    val trustedPeers: String? = null,
    /**
     * A `SipralSrtp` over the stack's `srtp`, or zero for the stack's.
     * A call may be stricter, never looser
     * (`SIPRAL_STATUS_SECURITY_POLICY`); an INVITE it cannot meet gets
     * 488.
     */
    val srtp: Long = 0,
    /**
     * The SRTP suites, most preferred first, comma-separated, as RFC 4568
     * §6.2 and RFC 7714 §14.2 name them:
     * `AEAD_AES_256_GCM,AES_CM_128_HMAC_SHA1_80`. Used for SDES and the
     * DTLS-SRTP profiles; GCM only if named. Null for this build's own.
     * Each line goes in the INVITE: more than two or three need a stream
     * transport.
     */
    val srtpSuites: String? = null,
    /**
     * A `SipralStirVerification`: what to do with received `Identity`
     * fields (RFC 8224 §6.2). Zero reports, once `sipral_stack_stir` gave
     * trust anchors.
     */
    val stirVerification: Long = 0,
    /**
     * The P-256 key this account signs calls with (RFC 8224 §6.1): the
     * bare 32-octet scalar, or `EC PRIVATE KEY` / `PRIVATE KEY` in DER or
     * PEM. Null signs nothing. Needs the wall clock from
     * `sipral_stack_stir`, else `SIPRAL_STATUS_WRONG_STATE`.
     */
    val stirKey: ByteArray? = null,
    /**
     * Where the chain for `stir_key` is published (`x5u` and `info`).
     * Required with `stir_key`, and only with it.
     */
    val stirCertificateUrl: String? = null,
    /**
     * The number this account signs as, canonicalised by RFC 8224 §8.3's
     * first step, or null for `aor`'s user part.
     */
    val stirOrig: String? = null,
    /**
     * The origination id every signed call claims (RFC 8588 §5), a UUID,
     * or null for one the stack draws.
     */
    val stirOrigid: String? = null,
    /**
     * A `SipralAttestation` (RFC 8588 §4); zero is full, `A`.
     */
    val stirAttestation: Long = 0,
    /**
     * A `SipralToggle`: whether an encrypted call may be recorded
     * (`sipral_call_record_to`) in the clear. Off by default: copies go as
     * SRTP with SDES keys (RFC 4568), and a stream the server refuses
     * that way gets nothing (RFC 7866 §12.2).
     *
     * Sixty-four bits wide so it starts past an older layout's trailing
     * padding, which old callers may leave unwritten.
     */
    val recordingInClear: Long = 0,
    /**
     * How often, in milliseconds, to keep the flow to the registrar (or
     * outbound proxy) open regardless of STUN; zero defers to
     * `sipral_stack_config_t::registrar_keepalive`.
     *
     * For a NAT that forgets UDP flows before the REGISTER refresh. UDP
     * sends a lone double CRLF (RFC 3261 §7.5); TCP and TLS ping at this
     * interval (RFC 5626 §4.4.1). Jittered to 80-100%. From 1 000 to
     * 120 000, else `SIPRAL_STATUS_INVALID_ARGUMENT`.
     */
    val keepaliveMs: Long = 0,
    /**
     * The server as a URI whose host RFC 3263 locates
     * (`sip:pbx.example.com`, `sips:example.com:5061`), in place of
     * `registrar_address`: exactly one is given. The registrar, or the
     * outbound proxy for an account that does not register.
     *
     * Lookups go to the application's resolver via
     * `SIPRAL_EVENT_KIND_LOOKUP_WANTED` and `sipral_account_looked_up`;
     * ordering, SRV ranking and fallback are the stack's. The first
     * REGISTER waits for the first answer; a call before it with no
     * destination is `SIPRAL_STATUS_WRONG_STATE`. An out-of-dialog
     * request that times out, fails its transport or gets 503 moves to
     * the next address (§4.3). The name is looked up again when the TTL
     * runs out or recovery asks. A port skips SRV; a numeric host asks
     * nothing.
     */
    val serverUri: String? = null,
    /**
     * The SHA-256 fingerprint of the one TLS certificate this account
     * trusts, for a self-signed PBX: 64 hex digits, any case, colons and
     * spaces ignored, bare or after `sha256 Fingerprint=` (openssl),
     * `sha-256 ` (RFC 8122) or `SHA256=`, any case. Anything else is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`. Null for none.
     *
     * The application's verifier asks `sipral_account_check_certificate`;
     * with a pin the fingerprint is the whole verdict (`docs/22-tls.md`).
     */
    val tlsPinSha256: String? = null,
    /**
     * A `SipralToggle`: ask NAPTR before SRV for `server_uri`'s domain
     * (RFC 3263 §4.1). Off by default; refused without `server_uri`.
     */
    val serverNaptr: Long = 0,
    /**
     * Zero.
     */
    val reserved: Long = 0,
    /**
     * A SipralTransport: the protocol of a connection of this
     * account's own to its server, which the application opens, or zero.
     *
     * For an account on TCP or TLS beside one on the stack's UDP, in one
     * stack. With TCP, TLS, WS or WSS the stack raises
     * `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` with the protocol and address
     * (`request_bytes` and `limit_bytes` zero); the account then uses
     * whatever transport of that protocol the application binds there with
     * `sipral_stack_transport_bind`, including one bound before. Until
     * then the REGISTER waits; after ten seconds it fails as unreachable
     * and the retry asks again. A non-registering account asks on add;
     * any account asks again when the connection fails or closes. A call
     * before the bind is `SIPRAL_STATUS_TRANSPORT_DOWN`. In-call requests
     * keep their INVITE's connection, and requests arriving on it match
     * this account first. `SIPRAL_TRANSPORT_UDP` only describes
     * `transport`.
     */
    val streamProtocol: Long = 0,
    /**
     * Zero.
     */
    val reserved35: Long = 0,
    /**
     * The realms the password answers, one per line (a realm may hold a
     * comma, never a line break), or null for the default.
     *
     * The password answers only the account's own server (RFC 3261
     * §22.1). By default that is the realms of the server's first
     * challenge and of every REGISTER challenge; a proxy relaying a far
     * end's 401 gets nothing, and `SIPRAL_EVENT_KIND_CHALLENGE_DECLINED`
     * says so. When calls are challenged under a realm REGISTERs never
     * see (an SBC or proxy with its own realm), name all of them here.
     * Empty lines are skipped; realms compare exactly (§22.1).
     */
    val realms: String? = null,
    /**
     * The `Host` of the WebSocket handshake (RFC 6455 §4.1) when
     * `stream_protocol` is `SIPRAL_TRANSPORT_WS` or `_WSS`, as
     * `host[:port]`, or null for the server's address. ABI 1.2.
     */
    val websocketHost: String? = null,
    /**
     * The resource the handshake asks for, a path from `/` with any
     * query (`/ws`, `/sip?tenant=7`), no space or fragment, or null for
     * `/ws`. Refused with `SIPRAL_STATUS_INVALID_ARGUMENT` like a host
     * that cannot go in the request, and when `stream_protocol` is not a
     * WebSocket. ABI 1.2.
     */
    val websocketResource: String? = null,
)

/**
 * What a call is placed with.
 *
 * Set `size` to `sizeof(sipral_call_config_t)` and zero the rest before filling it in.
 *
 * Built here and copied into the C struct by the JNI shim, which sets the
 * size member itself: a field left at its default is the zero the struct
 * would have held.
 */
class SipralCallConfig(
    /**
     * Who to call, as a URI. UTF-8, not NUL-terminated.
     */
    val target: String? = null,
    /**
     * The session description to offer, for a call whose audio the application runs.
     * Exactly one of this and `media_address` is set.
     */
    val sdp: ByteArray? = null,
    /**
     * Where to send the INVITE, as `host:port`, or null for where the account registers
     * (the outbound proxy of a registered line).
     */
    val destination: String? = null,
    /**
     * Nonzero keeps every branch a proxy forks the INVITE into. Zero keeps the first that
     * answers and hangs up the rest.
     */
    val keepAllForks: Long = 0,
    /**
     * Where this end receives media, as `host:port`, for a call whose audio this stack runs.
     *
     * Set, the offer is written from this stack's codec order and the call gets a media
     * session the `sipral_media_*` entry points reach. Null: set `sdp` instead.
     */
    val mediaAddress: String? = null,
    /**
     * Header fields to put on the INVITE, in order, or null for none.
     *
     * Each is checked first: the name a token, the value one line, and not a field the
     * stack writes itself (`docs/04-ua.md`; `User-Agent` too when
     * `sipral_stack_config_t::user_agent` is set). A refusal is
     * `SIPRAL_STATUS_INVALID_ARGUMENT` naming the element, and no call.
     */
    val headers: List<SipralHeader>? = null,
    /**
     * What this call does about SRTP, overriding `sipral_stack_config_t::srtp`: a
     * `SipralSrtp`, or zero for the stack's setting. Any other value is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`. Read only with `media_address` set.
     */
    val srtp: Long = 0,
    /**
     * Which transport the INVITE goes out on, read only with `destination`:
     * SIPRAL_TRANSPORT_MAIN for zero, or a
     * number sipral_stack_transport_bind
     * has bound. Nonzero with `destination` null is `SIPRAL_STATUS_INVALID_ARGUMENT`.
     */
    val transport: Long = 0,
    /**
     * What this call offers and in what order, overriding `sipral_stack_config_t::codecs`:
     * codec names separated by commas, as `sipral_codec_info_t::name` spells them, UTF-8,
     * not NUL-terminated. Null for the stack's order.
     *
     * The rest of the stack's catalogue (frame length, events, multiplexing, SRTP) is kept.
     * An unknown name, a repeated name or a stray comma is `SIPRAL_STATUS_INVALID_ARGUMENT`.
     * Applied only with `media_address` set, but the names are checked either way.
     */
    val codecs: String? = null,
    /**
     * What this call does about ICE, overriding `sipral_stack_config_t::ice`: a `SipralIce`,
     * or zero for the stack's setting. Any other value is `SIPRAL_STATUS_INVALID_ARGUMENT`.
     * Read only with `media_address` set.
     */
    val ice: Long = 0,
    /**
     * Where this call's real-time text arrives (RFC 4103), as `host:port` of a second
     * socket the application bound, not NUL-terminated; null for no text. Set, the
     * description carries an `m=text` stream for T.140 with redundancy, carried by
     * `sipral_media_send_text`, `sipral_media_poll_text` and `sipral_media_receive_text`.
     *
     * Read only with `media_address`. Not offered with SRTP, DTLS-SRTP or ICE: the text
     * stream has no key or candidates of its own, and clear text beside encrypted audio is
     * worse.
     */
    val textAddress: String? = null,
    /**
     * Whether this call asks for RTCP feedback: a `SipralToggle`. On offers RTP/AVPF
     * (RFC 4585) with Generic NACKs and reduced-size RTCP (RFC 5506). Off by default,
     * because a far end that knows only RTP/AVP refuses the profile. Read only with
     * `media_address`. An offer on a feedback profile is answered on it regardless
     * (RFC 4585 §4.1); the NACKs and reduced-size RTCP are agreed only when this is on.
     */
    val feedback: Long = 0,
    /**
     * Nonzero to say this end is the focus of a conference (RFC 4579
     * §3.3): `isfocus` goes on the Contact of every message this call
     * sends from here on.
     */
    val focus: Long = 0,
    /**
     * Nonzero to follow a 3xx to its `Contact` targets (RFC 3261 §8.1.3.4), most preferred
     * first, as new INVITEs of the same call. Not followed: a target already tried, a 380, a
     * 6xx, a forked call, past eight redirections. Zero (default) ends the call with
     * `SIPRAL_EVENT_KIND_CALL_ENDED` carrying the 3xx status and readable `Contact` addresses.
     * Added in ABI 1.2.
     */
    val followRedirects: Long = 0,
    /**
     * Zero. Pads the struct to a multiple of its alignment, so a member a later version
     * appends never lands in padding. The library reads nothing from it.
     */
    val reserved: Long = 0,
)

/**
 * A failed transport and why, for sipral_stack_transport_failed_with. All caller-filled;
 * `detail` is the platform's own optional sentence, passed through unparsed.
 *
 * Built here and copied into the C struct by the JNI shim, which sets the
 * size member itself: a field left at its default is the zero the struct
 * would have held.
 */
class SipralTransportFailure(
    /**
     * Which transport: SIPRAL_TRANSPORT_MAIN or a bound number.
     */
    val transport: Long = 0,
    /**
     * A SipralTransportError.
     */
    val error: Long = 0,
    /**
     * A SipralTlsFailure; `SIPRAL_TLS_FAILURE_NONE` unless TLS refused.
     */
    val tls: Long = 0,
    /**
     * The platform's words, not NUL-terminated. Null with length zero for none.
     */
    val detail: String? = null,
)

/**
 * What to watch, and how. Handed to sipral_account_subscribe. Set
 * `size` to `sizeof(sipral_subscribe_config_t)`; all but `target` and
 * `package` may be zero.
 *
 * Built here and copied into the C struct by the JNI shim, which sets the
 * size member itself: a field left at its default is the zero the struct
 * would have held.
 */
class SipralSubscribeConfig(
    /**
     * What to watch, as a SIP URI: `sip:2001@pbx.example.com`.
     */
    val target: String? = null,
    /**
     * The event package token: `dialog` for a busy lamp field (RFC 4235
     * §3.1), `message-summary` (RFC 3842 §3), `presence` (RFC 3856 §6.1).
     * Sent exactly as written, since §8.2.1 compares it byte for byte.
     */
    val `package`: String? = null,
    /**
     * The `Accept` value, when the package's default body type is not
     * wanted. Null sends none, which means the default (§3.1.3); a wrong
     * one gets 406 (§4.1.2.1), so nothing is guessed.
     */
    val accept: String? = null,
    /**
     * Seconds to ask for, or zero for one hour. The notifier's grant wins
     * (§3.1.1), and the refresh follows the grant.
     */
    val expiresSeconds: Long = 0,
    /**
     * Where to send the SUBSCRIBE, as `host:port`, or null for where the
     * account registers (the outbound proxy, which keeps NAT working).
     */
    val destination: String? = null,
    /**
     * The transport, read only with `destination`, as
     * `sipral_call_config_t::transport` is. Nonzero without `destination`
     * is `SIPRAL_STATUS_INVALID_ARGUMENT`.
     */
    val transport: Long = 0,
    /**
     * Zero. Pads the struct to a multiple of its alignment, so a member
     * appended later never lands in padding. Never read.
     */
    val reserved: Long = 0,
)

/**
 * How a stack verifies the callers of the calls its accounts receive.
 *
 * Set `size` to `sizeof(sipral_stir_config_t)` and zero the rest first.
 *
 * Built here and copied into the C struct by the JNI shim, which sets the
 * size member itself: a field left at its default is the zero the struct
 * would have held.
 */
class SipralStirConfig(
    /**
     * Trust anchors (in SHAKEN, the STI-PA roots), PEM or DER,
     * concatenated. Null and zero for none: reporting accounts then verify
     * nothing.
     */
    val anchors: ByteArray? = null,
    /**
     * Allowed `iat` skew either way, in seconds; zero for 60 (RFC 8224 §6.2).
     */
    val freshnessSeconds: Long = 0,
    /**
     * How long a call waits for `sipral_call_stir_certificate`, in ms,
     * before the certificate counts as unavailable; zero for 4000.
     */
    val certificateWaitMs: Long = 0,
    /**
     * The wall clock at `now_ms`, in Unix seconds, or zero to keep the
     * previous one. The first call must set it. Not taken from
     * `sipral_stack_config_t::media_clock_unix_seconds`, which has no
     * `now_ms`. A stack with no media clock also dates RTCP sender reports
     * by it.
     */
    val unixSeconds: Long = 0,
    /**
     * A `SipralToggle`: whether a TNAuthList service provider code
     * (RFC 8226 §9) covers every calling number. Off by default; a SHAKEN
     * deployment, whose certificates carry codes, turns it on. ABI 0.32.
     */
    val acceptServiceProviderCodes: Long = 0,
    /**
     * Zero. Pads the struct to its alignment so an appended member starts
     * past the declared length. Never read.
     */
    val reserved: Long = 0,
)

/**
 * How sipral_call_detect_progress listens. A zero member is its
 * default. Set `size` to `sizeof(sipral_progress_config_t)`.
 *
 * Built here and copied into the C struct by the JNI shim, which sets the
 * size member itself: a field left at its default is the zero the struct
 * would have held.
 */
class SipralProgressConfig(
    /**
     * A `SipralToggle`: on (the default) listens with what follows,
     * off stops listening and reads nothing else.
     */
    val listen: Long = 0,
    /**
     * A SipralToneRegion. Europe by default.
     */
    val region: Long = 0,
    /**
     * A `SipralToggle`: whether to decide who answered. On by default.
     */
    val answeringMachine: Long = 0,
    /**
     * A `SipralToggle`: whether to listen for the beep after a verdict
     * of a machine. On by default.
     */
    val beep: Long = 0,
    /**
     * How long after the verdict to listen for the beep. Thirty
     * seconds by default.
     */
    val beepWindowMs: Long = 0,
    /**
     * The longest silence after answer before the verdict is not sure.
     * 3000 by default.
     */
    val maxInitialSilenceMs: Long = 0,
    /**
     * The longest greeting a person gives. 1600 by default.
     */
    val maxGreetingMs: Long = 0,
    /**
     * The silence after a greeting that says a person is waiting. 700
     * by default.
     */
    val silenceAfterGreetingMs: Long = 0,
    /**
     * The most words a person's greeting has. 4 by default.
     */
    val maxWords: Long = 0,
    /**
     * The shortest run of speech that is a word. 120 by default.
     */
    val minWordMs: Long = 0,
    /**
     * The shortest silence that separates two words. 60 by default.
     */
    val minWordGapMs: Long = 0,
    /**
     * The longest the decision may take, from answer. 6000 by default.
     */
    val maxDecisionMs: Long = 0,
    /**
     * How far above the noise floor a frame must be to be speech, in
     * dB. 6 by default.
     */
    val minSpeechAboveFloorDb: Long = 0,
    /**
     * The shortest beep. 120 by default.
     */
    val beepMinMs: Long = 0,
    /**
     * The longest beep: anything held longer is a tone, not a beep.
     * This build's own default unless set.
     */
    val beepMaxMs: Long = 0,
    /**
     * How many whole cycles of a repeating cadence are heard before the
     * tone is reported, from one to four. One by default.
     */
    val toneCycles: Long = 0,
)

/**
 * The beep sipral_call_consent_tone plays. A zero member is its
 * default. Set `size` to `sizeof(sipral_consent_tone_t)`.
 *
 * Built here and copied into the C struct by the JNI shim, which sets the
 * size member itself: a field left at its default is the zero the struct
 * would have held.
 */
class SipralConsentTone(
    /**
     * A `SipralToggle`: on (the default) beeps as what follows says,
     * off plays no tone and reads nothing else.
     */
    val enabled: Long = 0,
    /**
     * Its frequency, from 300 to 3400 Hz. 1400 by default.
     */
    val frequencyHz: Long = 0,
    /**
     * How far below 0 dBm0 it sounds, from 3 to 40 dB: 18 is a beep at
     * −18 dBm0, the default.
     */
    val attenuationDb: Long = 0,
    /**
     * How long each beep lasts, from 50 to 2000 ms. 200 by default.
     */
    val lengthMs: Long = 0,
    /**
     * How often it repeats, start to start: longer than a beep and at
     * most ten minutes. Fifteen seconds by default.
     */
    val intervalMs: Long = 0,
    /**
     * A `SipralToggle`: whether this end hears it too. On by default.
     */
    val local: Long = 0,
)

/**
 * How sipral_media_record_start_with writes a recording. Zero in
 * every member but `size` is sipral_media_record_start's file.
 *
 * Set `size` to `sizeof(sipral_recording_options_t)` before the call.
 *
 * Built here and copied into the C struct by the JNI shim, which sets the
 * size member itself: a field left at its default is the zero the struct
 * would have held.
 */
class SipralRecordingOptions(
    /**
     * A SipralRecordingFormat.
     */
    val format: Long = 0,
    /**
     * A SipralRecordingLayout.
     */
    val layout: Long = 0,
    /**
     * The rate the file is written at, in hertz, or zero for the rate the
     * call's codec hears at when the recording starts (48 kHz for Ogg
     * Opus on a call at a rate Opus does not take). WAV takes 8000 to
     * 48000; Ogg Opus takes 8000, 12000, 16000, 24000 and 48000.
     */
    val sampleRate: Long = 0,
    /**
     * An Ogg Opus recording's bitrate in bits a second, all channels
     * together, or zero for libopus's own choice. Not read for WAV.
     */
    val bitrate: Long = 0,
    /**
     * How often, in milliseconds, what has been written is made to
     * survive a crash, or zero for every five seconds.
     */
    val checkpointMs: Long = 0,
    /**
     * Zero; never read. Pads the struct to its alignment so a member added
     * later never lands in padding of an older caller's struct.
     */
    val reserved: Long = 0,
)

/**
 * This account's presence for sipral_account_publish_presence. Set
 * `size` to `sizeof(sipral_presence_t)` and zero the rest first.
 *
 * Built here and copied into the C struct by the JNI shim, which sets the
 * size member itself: a field left at its default is the zero the struct
 * would have held.
 */
class SipralPresence(
    /**
     * A SipralBasic, open or closed. Required.
     */
    val basic: Long = 0,
    /**
     * A SipralActivity; SipralActivity.NONE publishes no
     * person at all. SipralActivity.OTHER is refused: there is no
     * name to publish it under.
     */
    val activity: Long = 0,
    /**
     * A note a buddy list shows beside the name, UTF-8 and not
     * NUL-terminated, or null for none.
     */
    val note: String? = null,
)

/**
 * Where a call is recorded, as sipral_call_record_to takes it.
 *
 * Set `size` to `sizeof(sipral_record_config_t)` and zero the rest
 * before filling anything in.
 *
 * Built here and copied into the C struct by the JNI shim, which sets the
 * size member itself: a field left at its default is the zero the struct
 * would have held.
 */
class SipralRecordConfig(
    /**
     * The recording server's URI. Required, not NUL-terminated.
     */
    val server: String? = null,
    /**
     * `host:port` to send the INVITE to; null for the account's route.
     */
    val destination: String? = null,
    /**
     * The transport for `destination`, as in
     * `sipral_call_config_t::transport`; read only with `destination`.
     */
    val transport: Long = 0,
    /**
     * Required bound socket, `host:port`, for this end's audio (label `1`).
     */
    val thisEnd: String? = null,
    /**
     * Required distinct socket for the far end's audio (label `2`).
     */
    val farEnd: String? = null,
)

/**
 * How `sipral_local_conference_create` makes a conference. All zero but
 * `size`: sixteen members, this end in, 16 kHz.
 *
 * Set `size` to `sizeof(sipral_local_conference_config_t)` first.
 *
 * Built here and copied into the C struct by the JNI shim, which sets the
 * size member itself: a field left at its default is the zero the struct
 * would have held.
 */
class SipralLocalConferenceConfig(
    /**
     * Most members at once, this end included; zero for 16, at most 1024.
     */
    val maxMembers: Long = 0,
    /**
     * A `SipralToggle`: whether this end takes part. On unless
     * `SIPRAL_TOGGLE_OFF`; without it the conference only bridges calls.
     */
    val local: Long = 0,
    /**
     * This end's frame rate in application mode, in Hz: 8000, 16000,
     * 32000 or 48000, zero for 16000. A tick is 20 ms of it. In device
     * mode the engine converts the devices to it.
     */
    val sampleRate: Long = 0,
    /**
     * Zero. Pads the struct to its alignment so an appended member starts
     * past the declared length. Never read.
     */
    val reserved: Long = 0,
)

/**
 * What sipral_stack_network_test tests. Zero in any member but
 * `size` leaves that part out or takes its default.
 *
 * Set `size` to `sizeof(sipral_network_test_config_t)` before the call.
 *
 * Built here and copied into the C struct by the JNI shim, which sets the
 * size member itself: a field left at its default is the zero the struct
 * would have held.
 */
class SipralNetworkTestConfig(
    /**
     * The account whose server to probe, or `SIPRAL_HANDLE_NONE`.
     */
    val account: Long = 0,
    /**
     * A UDP socket the application bound for the test, `host:port`, not
     * NUL-terminated; null for the signalling socket only and no relay.
     */
    val probeSocket: String? = null,
    /**
     * A call to an echo service, hung up by the test, or `SIPRAL_HANDLE_NONE`.
     */
    val echoCall: Long = 0,
    /**
     * How long the echo is measured. 8000 by default.
     */
    val echoMs: Long = 0,
    /**
     * Test deadline, 30000 by default; a part silent by then failed.
     */
    val timeoutMs: Long = 0,
)

/**
 * Something the library has to tell the application.
 *
 * Library-owned, valid for the callback only. Read no further than
 * `size`; the union stays last so growth only extends the tail.
 *
 * `payload` carries every arm the union declares, every time: which one the
 * library actually wrote is named by `kind` alone, the same as it is in C,
 * Swift and C#. Reading another arm is defined -- it reads bytes the library
 * wrote for a different one -- and never a crash, but is not meaningful.
 */
/**
 * What a SipralEventKind.REGISTRATION_CHANGED carries.
 */
data class SipralRegistrationEvent(
    /**
     * A SipralRegistrationState.
     */
    val state: Long,
    /**
     * A SipralRegistrationFailure, zero when nothing failed.
     */
    val failure: Long,
    /**
     * The status the registrar answered with, or zero when none arrived.
     */
    val statusCode: Long,
    /**
     * The binding's granted lifetime, zero unless it is live.
     */
    val expiresMs: Long,
    /**
     * How long until the refresh, zero unless one is scheduled.
     */
    val refreshInMs: Long,
    /**
     * How long until the next attempt; meaningful only while retrying.
     */
    val retryInMs: Long,
)

/**
 * What every call event carries. Members that do not apply are zero,
 * and zero always means absent.
 */
data class SipralCallEvent(
    /**
     * A SipralCallState.
     */
    val state: Long,
    /**
     * A SipralCallEndReason, zero while the call is alive.
     */
    val endReason: Long,
    /**
     * The status a response carried, or zero.
     */
    val statusCode: Long,
    /**
     * The other call this event is also about: the sibling of a fork, or the
     * call that was replaced. SIPRAL_HANDLE_NONE otherwise.
     */
    val other: Long,
    /**
     * Whether this end has asked the far end to stop sending.
     */
    val heldHere: Long,
    /**
     * Whether the far end has asked this one to.
     */
    val heldThere: Long,
    /**
     * What this end is describing, and how long it is.
     */
    val localSdp: ByteArray?,
    /**
     * And what the far end is.
     */
    val remoteSdp: ByteArray?,
    /**
     * When a refused session change goes out again by itself, zero when it is
     * not going to.
     */
    val retryInMs: Long,
    /**
     * The creating request's `From` URI, as written, without brackets or
     * header parameters. Null and zero when unavailable.
     */
    val fromUri: ByteArray?,
    /**
     * That `From`'s display name, quotes and backslash escapes resolved
     * (RFC 3261 §25.1). Null and zero when the header named none.
     */
    val fromDisplay: ByteArray?,
    /**
     * The `To` URI of the request that created this call, as written in
     * the header.
     */
    val toUri: ByteArray?,
    /**
     * The `Call-ID` of the request that created this call.
     */
    val callId: ByteArray?,
    /**
     * The digit an INFO this end sent named, for
     * SipralEventKind.DTMF_SENT. Zero for every other kind.
     */
    val digit: Long,
    /**
     * For SipralEventKind.CALL_ENDED: the SIP cause in the far end's
     * `Reason` (RFC 3326). 200 on a CANCEL means answered elsewhere.
     */
    val causeSip: Long,
    /**
     * The Q.850 cause from `Reason` (16 normal, 17 busy), or zero.
     */
    val causeQ850: Long,
    /**
     * The `text` of the first `Reason` value, unquoted. Null and zero
     * when there was none.
     */
    val causeText: ByteArray?,
    /**
     * Whether an incoming INVITE came from a `trusted_peers` peer. If not,
     * the asserted identity and `verstat` are empty (RFC 3325 §8).
     */
    val identityTrusted: Long,
    /**
     * The first `P-Asserted-Identity`, else a `Remote-Party-ID`, as
     * written. Null and zero when none.
     */
    val assertedUri: ByteArray?,
    /**
     * That identity's display name. Null and zero when it named none.
     */
    val assertedDisplay: ByteArray?,
    /**
     * A SipralVerstat: what the
     * network concluded about the caller's number.
     */
    val verstat: Long,
    /**
     * The `SIPRAL_PRIVACY_*` bits the caller's `Privacy` asked for.
     */
    val privacy: Long,
    /**
     * The top-most `Diversion` (RFC 5806), as written. Null and zero
     * when none.
     */
    val divertedFrom: ByteArray?,
    /**
     * Why: its `reason`. Null and zero when none.
     */
    val diversionReason: ByteArray?,
    /**
     * How many `Diversion` values the INVITE carried.
     */
    val diversionCount: Long,
    /**
     * How many `History-Info` entries it carried.
     */
    val historyCount: Long,
    /**
     * A SipralAnswerMode: the
     * INVITE's `Answer-Mode` (RFC 5373).
     */
    val answerMode: Long,
    /**
     * Whether that field said `;require`: the caller would rather the
     * call be refused, with a 403, than answered any other way.
     */
    val answerModeRequired: Long,
    /**
     * The same for `Priv-Answer-Mode`, which RFC 5373 §4.2 holds to a
     * stricter policy.
     */
    val privAnswerMode: Long,
    /**
     * Whether that field said `;require`.
     */
    val privAnswerModeRequired: Long,
    /**
     * Whether the call asked to be auto-answered after `answer_after_ms`
     * (`Answer-Mode: Auto`, `answer-after`, `info=alert-autoanswer`).
     */
    val hasAnswerAfter: Long,
    /**
     * After how long, when `has_answer_after` is set.
     */
    val answerAfterMs: Long,
    /**
     * A SipralRingSource: whether
     * the ring says the caller is internal or external.
     */
    val ringSource: Long,
    /**
     * The first `Alert-Info` URI, without the angle brackets. Null and
     * zero when none. `sipral_call_identity_text` reads the rest.
     */
    val alertInfo: ByteArray?,
    /**
     * A SipralVerificationOutcome: this stack's own verdict (RFC 8224
     * §6.2), unlike the network's `verstat`. Zero when not verified.
     */
    val verification: Long,
    /**
     * A SipralAttestation: the
     * level a valid SHAKEN PASSporT claimed.
     */
    val attestation: Long,
    /**
     * A SipralVerificationFailure: why the verdict did not hold.
     */
    val verificationFailure: Long,
)

/**
 * What a transfer event carries.
 */
data class SipralTransferEvent(
    /**
     * What the far end's own call is doing, or zero.
     */
    val statusCode: Long,
    /**
     * Whether the request named a dialog to replace, which is what makes a
     * transfer attended rather than blind.
     */
    val attended: Long,
    /**
     * Who to call, as UTF-8. Not NUL-terminated.
     */
    val target: String?,
)

/**
 * What a media event carries. Members that do not apply are zero or null.
 */
data class SipralMediaEvent(
    /**
     * A SipralCodec: what the negotiation
     * settled on, zero where the event is not about a codec.
     */
    val codec: Long,
    /**
     * A SipralDirection: which way audio
     * may flow, as seen from here.
     */
    val direction: Long,
    /**
     * How long the stream has been silent, for a stall and for its recovery.
     */
    val silentForMs: Long,
    /**
     * How much audio reached the file, for a recording that stopped by
     * itself.
     */
    val recordedMs: Long,
    /**
     * A SipralMediaFault, zero when
     * nothing failed.
     */
    val fault: Long,
    /**
     * The sentence behind `fault`, as UTF-8. Not NUL-terminated, and null
     * when nothing failed.
     */
    val reason: String?,
    /**
     * What the stream cost, for the kind that carries it, and null for every
     * other. It belongs to the library and lives as long as the callback.
     */
    val statistics: SipralStreamStats?,
    /**
     * The key the far end pressed, as its character, and zero for an event
     * no keypad has a key for.
     */
    val digit: Long,
    /**
     * The RFC 4733 event code behind `digit`. Codes at and above sixteen are
     * real events that are not keys.
     */
    val eventCode: Long,
    /**
     * How long the key was held. Zero for no duration or `Duration=0`.
     */
    val heldMs: Long,
    /**
     * A SipralSrtpSuite, for SipralEventKind.MEDIA_SECURED and the
     * encryption report.
     */
    val suite: Long,
    /**
     * A SipralDigitSource: which of the two ways this stack accepts a
     * digit reported this one, for SipralEventKind.DIGIT_RECEIVED.
     */
    val source: Long,
    /**
     * Whether the RFC 6035 PUBLISH left this end, for
     * SipralEventKind.QUALITY_REPORT_SENT.
     */
    val qualityReportSent: Long,
    /**
     * A SipralKeyExchange, on the start, change and secure kinds.
     */
    val keyExchange: Long,
    /**
     * Whether the stream is encrypted now; zero until a DTLS-SRTP
     * handshake ends.
     */
    val encrypted: Long,
    /**
     * Whether DTLS-SRTP checked the far end's certificate against the
     * fingerprint. Never for SDES.
     */
    val authenticated: Long,
)

/**
 * What a SipralEventKind.RECOVERY carries.
 */
data class SipralRecoveryEvent(
    /**
     * A SipralRecoveryOutcome.
     */
    val state: Long,
    /**
     * A SipralRecoveryRung: the last rung tried. Zero unless `state`
     * is SipralRecoveryOutcome.GAVE_UP.
     */
    val rung: Long,
    /**
     * A SipralRecoveryFailure. Zero unless `state` is
     * SipralRecoveryOutcome.GAVE_UP.
     */
    val reason: Long,
    /**
     * Bindings the ladder never proved. Meaningful only when `state` is
     * SipralRecoveryOutcome.GAVE_UP.
     */
    val unverified: Long,
)

/**
 * What a SipralEventKind.TRANSPORT_WANTED carries: a request RFC
 * 3261 §18.1.1 kept off a datagram, with no stream open for it.
 */
data class SipralTransportWantedEvent(
    /**
     * What to open, as a SipralTransport; zero for an unknown one.
     */
    val protocol: Long,
    /**
     * Where to, as `host:port`. Not NUL-terminated.
     */
    val destination: String?,
    /**
     * The request's size in bytes, as it would go on the wire.
     */
    val requestBytes: Long,
    /**
     * The largest size that fits a datagram: path MTU less the §18.1.1
     * headroom, or 1300 when the MTU is unknown.
     */
    val limitBytes: Long,
)

/**
 * What a SipralEventKind.SUBSCRIPTION_CHANGED and a
 * SipralEventKind.NOTIFIED carry.
 */
data class SipralSubscriptionEvent(
    /**
     * Which subscription, minted by `sipral_account_subscribe` or by this
     * ABI for a fork sibling.
     */
    val subscription: Long,
    /**
     * A SipralSubscriptionState.
     */
    val state: Long,
    /**
     * A SipralSubscriptionEnd:
     * why it is not live. Zero while it is.
     */
    val reason: Long,
    /**
     * The SIP status a response gave for it, when one did. Zero
     * otherwise.
     */
    val statusCode: Long,
    /**
     * Whether the notification carried readable dialog state. Zero on
     * every kind but SipralEventKind.NOTIFIED.
     */
    val hasDialogInfo: Long,
    /**
     * What the notifier granted, in milliseconds. Zero until one has.
     */
    val expiresMs: Long,
    /**
     * How long until this stack refreshes it, in milliseconds.
     */
    val refreshInMs: Long,
    /**
     * How long until the next attempt, in milliseconds, when the state
     * is `SIPRAL_SUBSCRIPTION_STATE_RETRYING`. Zero otherwise.
     */
    val retryInMs: Long,
    /**
     * The subscription this one forked from (RFC 6665 §4.1.4), or
     * `SIPRAL_HANDLE_NONE`. A sibling is a full subscription (RFC 4235
     * §3.9: one per device).
     */
    val forkedFrom: Long,
)

/**
 * What a SipralEventKind.CALL_ANNOUNCED and a
 * SipralEventKind.ANNOUNCED_CALL_MISSING carry.
 */
data class SipralAnnounceEvent(
    /**
     * Which announcement, minted by `sipral_account_announce`. Stale once
     * either of these two events has been raised about it.
     */
    val announcement: Long,
    /**
     * How long the call was waited for, in milliseconds. Meaningful only
     * on SipralEventKind.ANNOUNCED_CALL_MISSING.
     */
    val waitedMs: Long,
)

/**
 * What a SipralEventKind.RESOLVE_NEEDED carries: the name a dialog's
 * next hop is written as, and the handle an answer takes.
 */
data class SipralResolveEvent(
    /**
     * The handle
     * sipral_stack_resolved
     * takes; stale once the dialog ends.
     */
    val dialog: Long,
    /**
     * The host as the URI spells it; IPv6 literals keep brackets (RFC
     * 3261 §19.1.1). Not NUL-terminated.
     */
    val host: String?,
    /**
     * The URI's port, or zero for none. Zero is not 5060: an SRV answer
     * carries its own port (RFC 3263 §4.2).
     */
    val port: Long,
    /**
     * The transport named, as a SipralTransport, or zero, leaving
     * §4.1's NAPTR step to the caller.
     */
    val protocol: Long,
)

/**
 * What the three message kinds carry; inapplicable members are zero.
 * `content_type` and `body` point into `sipral_event_t::message`.
 */
data class SipralMessageEvent(
    /**
     * SipralEventKind.MESSAGE_SENT: which send; stale after this.
     */
    val message: Long,
    /**
     * SipralEventKind.MESSAGES_WAITING: which subscription reported
     * it. SIPRAL_HANDLE_NONE on the other kinds.
     */
    val subscription: Long,
    /**
     * SipralEventKind.MESSAGE_SENT: the final status. Zero on the
     * other two kinds.
     */
    val statusCode: Long,
    /**
     * SipralEventKind.MESSAGE_RECEIVED: the body's `Content-Type`, as
     * written. Null on the other kinds and for an empty MESSAGE.
     */
    val contentType: String?,
    /**
     * SipralEventKind.MESSAGE_RECEIVED: the body. Null the same as
     * `content_type`.
     */
    val body: ByteArray?,
    /**
     * SipralEventKind.MESSAGES_WAITING: RFC 3842 §3.5's status
     * line, 1 for `yes` and 0 for `no`.
     */
    val waiting: Long,
    /**
     * SipralEventKind.MESSAGES_WAITING: new `voice-message` messages
     * (RFC 3458 §6.2). Zero when the body had no such line.
     */
    val newMessages: Long,
    /**
     * The same, old.
     */
    val oldMessages: Long,
    /**
     * New messages flagged urgent.
     */
    val urgentNewMessages: Long,
    /**
     * Old messages flagged urgent.
     */
    val urgentOldMessages: Long,
    /**
     * SipralEventKind.MESSAGES_WAITING: `Message-Account`, when sent
     * (RFC 3842 §3.5). Null otherwise.
     */
    val messageAccount: String?,
)

/**
 * What a SipralEventKind.NAT_MAPPING carries.
 * The addresses are `host:port`, not NUL-terminated, valid only during the callback.
 */
data class SipralNatEvent(
    /**
     * A SipralNatMapping.
     */
    val mapping: Long,
    /**
     * Nonzero for a signalling socket, zero for a media socket.
     */
    val signalling: Long,
    /**
     * The transport, when `signalling` is nonzero; zero otherwise.
     */
    val transport: Long,
    /**
     * How many accounts' `Contact` moved to `public`; bound ones have registered it already.
     */
    val accounts: Long,
    /**
     * The socket, as the application named it.
     */
    val local: String?,
    /**
     * The public address. Empty for `SIPRAL_NAT_MAPPING_UNANSWERED`.
     */
    val mapped: String?,
    /**
     * The old address, for `SIPRAL_NAT_MAPPING_MOVED`. Empty otherwise.
     */
    val previous: String?,
)

/**
 * What a SipralEventKind.NAT_RELAY carries.
 * Text is not NUL-terminated, valid only during the callback, and holds no credential.
 */
data class SipralNatRelayEvent(
    /**
     * A SipralNatRelay.
     */
    val outcome: Long,
    /**
     * For `SIPRAL_NAT_RELAY_FAILED`, the STUN error code (401 bad credential, 486 quota, 508
     * no capacity), or zero when there was no usable answer. Zero for `ALLOCATED`.
     */
    val code: Long,
    /**
     * The media socket, as `sipral_stack_nat_map` named it.
     */
    val local: String?,
    /**
     * The relayed `host:port`. Empty for `SIPRAL_NAT_RELAY_FAILED`.
     */
    val relayed: String?,
    /**
     * Where the server saw the socket from, when it said. Empty otherwise.
     */
    val mapped: String?,
    /**
     * Why there is no relay, in English. Empty for `SIPRAL_NAT_RELAY_ALLOCATED`.
     */
    val reason: String?,
)

/**
 * What a SipralEventKind.REFERRAL carries: a REFER outside any
 * dialog, or the word that one lapsed.
 */
data class SipralReferralEvent(
    /**
     * Zero while the referral waits. On the lapse event, the status the
     * stack answered (408), and every other member is zero or null.
     */
    val statusCode: Long,
    /**
     * Whether `Refer-To` named a dialog to replace (RFC 3891): an
     * attended transfer.
     */
    val attended: Long,
    /**
     * Who to call, as UTF-8. Not NUL-terminated.
     */
    val target: String?,
    /**
     * Its `Referred-By` (RFC 3892), UTF-8, unverified. Null when absent or
     * repeated (§2.1). Not NUL-terminated.
     */
    val referredBy: String?,
)

/**
 * What a SipralEventKind.TURN_STREAM carries.
 * Addresses are not NUL-terminated, valid only during the callback.
 */
data class SipralTurnStreamEvent(
    /**
     * A SipralTurnStream.
     */
    val state: Long,
    /**
     * `SIPRAL_TRANSPORT_TCP` or `SIPRAL_TRANSPORT_TLS`, as `turn_transport` named.
     */
    val protocol: Long,
    /**
     * The media socket; the connection's name in the calls that take one.
     */
    val local: String?,
    /**
     * The TURN server, `host:port`, as `turn_server` named it.
     */
    val server: String?,
)

/**
 * What `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED` carries.
 */
data class SipralAudioEvent(
    /**
     * A `SipralAudioChange`.
     */
    val change: Long,
    /**
     * A `SipralAudioOrigin`.
     */
    val origin: Long,
    /**
     * A `SipralAudioRole`, for a change about one role; zero otherwise.
     */
    val role: Long,
    /**
     * A `SipralAudioDirection`, for `SIPRAL_AUDIO_CHANGE_DEFAULT_CHANGED`;
     * zero otherwise.
     */
    val direction: Long,
    /**
     * The device the change is about, or zero.
     */
    val device: Long,
)

/**
 * What a SipralEventKind.STUN_SERVER carries.
 * Addresses are not NUL-terminated, valid only during the callback.
 */
data class SipralStunServerEvent(
    /**
     * A SipralStunServerState.
     */
    val state: Long,
    /**
     * The server in use now (`CHANGED`) or the last that failed (`ALL_FAILED`).
     */
    val server: String?,
    /**
     * For `CHANGED`, the previous server. Empty otherwise.
     */
    val previous: String?,
)

/**
 * What a SipralEventKind.CALLER_VERIFICATION carries: one half of
 * the verification of who is calling (RFC 8224 §6.2).
 */
data class SipralVerificationEvent(
    /**
     * A SipralVerificationStage:
     * the certificate is wanted, or the verdict is in.
     */
    val stage: Long,
    /**
     * A SipralVerificationOutcome,
     * for a verdict.
     */
    val outcome: Long,
    /**
     * A SipralVerificationFailure:
     * why it did not hold.
     */
    val failure: Long,
    /**
     * A SipralAttestation: the
     * level a valid SHAKEN PASSporT claimed.
     */
    val attestation: Long,
    /**
     * A SipralVerstat: the `verstat`
     * this verdict comes to (3GPP TS 24.229).
     */
    val verstat: Long,
    /**
     * The response RFC 8224 §6.2.2 prescribes for the failure, zero for
     * a valid one. Sent only when `refused` is set.
     */
    val responseCode: Long,
    /**
     * Whether the call was refused with it, which only a strict account
     * does.
     */
    val refused: Long,
    /**
     * The certificate URL: to fetch, or that was verified. UTF-8, not
     * NUL-terminated; null and zero when none.
     */
    val certificateUrl: String?,
    /**
     * The calling number a valid PASSporT was signed for, canonical.
     */
    val orig: String?,
    /**
     * The origination identifier a valid SHAKEN PASSporT claimed (RFC
     * 8588 §5), a UUID.
     */
    val origid: String?,
    /**
     * Why it did not hold, in more words than `failure`, for a log.
     */
    val detail: String?,
)

/**
 * What a SipralEventKind.PROGRESS_DETECTED carries. `what` says
 * which of the other members mean anything; the rest are zero.
 */
data class SipralProgressEvent(
    /**
     * A SipralProgressKind.
     */
    val what: Long,
    /**
     * A SipralProgressTone, for a tone.
     */
    val tone: Long,
    /**
     * A SipralAmdVerdict, for who answered.
     */
    val verdict: Long,
    /**
     * A SipralAmdReason, for who answered.
     */
    val reason: Long,
    /**
     * When, in milliseconds: the tone's first burst, or after answer.
     */
    val atMs: Long,
    /**
     * How long after answer the first word began, or the silence if
     * nobody spoke.
     */
    val initialSilenceMs: Long,
    /**
     * From the first word's start to the last word's end.
     */
    val greetingMs: Long,
    /**
     * How many words were heard.
     */
    val words: Long,
    /**
     * The beep's frequency, in hertz, as measured.
     */
    val frequencyHz: Long,
    /**
     * How long the beep sounded.
     */
    val lengthMs: Long,
    /**
     * The special information tone's first frequency, as measured.
     */
    val sitHz1: Long,
    /**
     * Its second.
     */
    val sitHz2: Long,
    /**
     * Its third.
     */
    val sitHz3: Long,
    /**
     * How long the first sounded.
     */
    val sitMs1: Long,
    /**
     * The second.
     */
    val sitMs2: Long,
    /**
     * The third.
     */
    val sitMs3: Long,
)

/**
 * What a SipralEventKind.CONFERENCE_CHANGED carries.
 */
data class SipralConferenceEvent(
    /**
     * Which subscription.
     */
    val subscription: Long,
    /**
     * A SipralConferenceUpdate.
     */
    val update: Long,
    /**
     * The current document version; zero once ended.
     */
    val version: Long,
    /**
     * How many users the picture holds.
     */
    val users: Long,
)

/**
 * What a SipralEventKind.TEXT_RECEIVED carries; the
 * text is valid during the callback.
 */
data class SipralTextEvent(
    /**
     * What the far end typed, UTF-8, not NUL-terminated.
     */
    val text: String?,
    /**
     * Unrecoverable lost blocks, each marked in `text` by U+FFFD.
     */
    val missing: Long,
)

/**
 * What a SipralEventKind.PRESENCE_CHANGED carries. The
 * text is valid only during the callback.
 */
data class SipralPresenceEvent(
    /**
     * A SipralPresenceKind.
     */
    val kind: Long,
    /**
     * SipralPresenceKind.WATCHED: which subscription;
     * `SIPRAL_HANDLE_NONE` for a publication.
     */
    val subscription: Long,
    /**
     * SipralPresenceKind.WATCHED: a SipralBasic, open when any
     * of the presentity's tuples is open.
     */
    val basic: Long,
    /**
     * SipralPresenceKind.WATCHED: a SipralActivity, the first
     * the person listed.
     */
    val activity: Long,
    /**
     * SipralPresenceKind.WATCHED: the presentity, as the document
     * named it. Not NUL-terminated.
     */
    val entity: String?,
    /**
     * SipralPresenceKind.WATCHED: the first note, the document's
     * own or else a tuple's. Null when there is none.
     */
    val note: String?,
    /**
     * SipralPresenceKind.PUBLICATION: a SipralPublicationState.
     */
    val publicationState: Long,
    /**
     * SipralPresenceKind.PUBLICATION: a SipralPublishFailure
     * when the state is SipralPublicationState.FAILED.
     */
    val failure: Long,
    /**
     * SipralPresenceKind.PUBLICATION: the status the compositor
     * answered with, when one did.
     */
    val statusCode: Long,
    /**
     * SipralPresenceKind.PUBLICATION: the lifetime granted, in
     * milliseconds, when it was published.
     */
    val expiresMs: Long,
    /**
     * SipralPresenceKind.PUBLICATION: how long until the stack
     * refreshes it, in milliseconds.
     */
    val refreshInMs: Long,
)

/**
 * `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`: a signalling transport stopped carrying traffic.
 * The text is the library's, valid during the callback.
 */
data class SipralTransportFailedEvent(
    /**
     * Which transport: SIPRAL_TRANSPORT_MAIN or a bound number.
     */
    val transport: Long,
    /**
     * What it spoke, as a `SipralTransport`.
     */
    val protocol: Long,
    /**
     * A SipralTransportError; `SIPRAL_TRANSPORT_ERROR_CLOSED` for a closed connection.
     */
    val error: Long,
    /**
     * A SipralTlsFailure, when TLS refused.
     */
    val tls: Long,
    /**
     * The platform's sentence as handed over. Null with length zero for none.
     */
    val detail: String?,
)

/**
 * What a `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED` carries.
 */
data class SipralLocalConferenceEvent(
    /**
     * The conference.
     */
    val conference: Long,
    /**
     * A SipralLocalConferenceChange.
     */
    val change: Long,
    /**
     * A SipralDeparture, for `SIPRAL_LOCAL_CONFERENCE_CHANGE_LEFT`.
     */
    val departure: Long,
    /**
     * Who joined or left (a call, or the conference handle for this end);
     * `SIPRAL_HANDLE_NONE` otherwise.
     */
    val member: Long,
    /**
     * Members now, this end included.
     */
    val members: Long,
    /**
     * Members talking now.
     */
    val talkers: Long,
    /**
     * The loudest of them, or `SIPRAL_HANDLE_NONE`.
     */
    val loudest: Long,
)

/**
 * What a SipralEventKind.LOOKUP_WANTED,
 * a SipralEventKind.LOCATED
 * and a SipralEventKind.LOCATE_FAILED
 * carry, the account being `sipral_event_t::account`.
 *
 * A member meaningless on a kind is zero or null. Every pointer is the
 * library's, valid for the duration of the callback.
 */
data class SipralLocateEvent(
    /**
     * A SipralDnsRecordType: what to ask `name` for, on a lookup.
     */
    val record: Long,
    /**
     * A SipralLocateFailure: why a lookup named no address.
     */
    val failure: Long,
    /**
     * The name to ask, on a lookup: `_sip._udp.example.com`, or a
     * host. Handed back to sipral_account_looked_up with the answer.
     * UTF-8, not NUL-terminated.
     */
    val name: String?,
    /**
     * Every located address, comma-separated `host:port`, in RFC 3263
     * section 4.3 order, the one in use first. UTF-8, not NUL-terminated.
     */
    val targets: String?,
    /**
     * Milliseconds until the retry after a failure; an earlier address
     * stays in use meanwhile.
     */
    val retryInMs: Long,
)

/**
 * What a SipralEventKind.CHALLENGE_DECLINED carries: who asked for
 * the account's password, and why it was not given.
 */
data class SipralChallengeEvent(
    /**
     * A SipralChallengeRefusal.
     */
    val refusal: Long,
    /**
     * Where the challenged request went, as `host:port`. Not
     * NUL-terminated.
     */
    val server: String?,
    /**
     * The challenged realms, separated by line feeds (a realm may hold a
     * comma, never a line break). UTF-8, not NUL-terminated.
     */
    val realms: String?,
)

/**
 * What a SipralEventKind.TOKEN_REQUIRED carries (RFC 8898 §4).
 * Texts are UTF-8, not NUL-terminated, empty when absent.
 */
data class SipralTokenEvent(
    /**
     * A SipralTokenError.
     */
    val error: Long,
    /**
     * A `SipralToggle`: on for a proxy's 407, off for a 401.
     */
    val proxy: Long,
    /**
     * Where the challenged request went, as `host:port`.
     */
    val server: String?,
    /**
     * The protection domain, empty when the challenge named none.
     */
    val realm: String?,
    /**
     * The scope the token has to carry: space-separated strings the
     * authorization server defines (RFC 6749 §3.3).
     */
    val scope: String?,
    /**
     * The authorization server: an `https` URI, or empty if it was not one.
     */
    val authzServer: String?,
    /**
     * The `error` code as the server wrote it, for `Other`.
     */
    val errorCode: String?,
)

/**
 * What a SipralEventKind.NETWORK_TEST
 * carries (ABI 1.2). The event's `account` and `call` are the probed
 * account and the echo call. The addresses are `host:port`, not
 * NUL-terminated, owned by the library, valid during the callback.
 */
data class SipralNetworkTestEvent(
    /**
     * The number sipral_stack_network_test gave the test.
     */
    val test: Long,
    /**
     * A SipralNetworkVerdict: the worst of the parts tested.
     */
    val verdict: Long,
    /**
     * A SipralNetworkProbe: whether a STUN server answered.
     */
    val stun: Long,
    /**
     * A SipralNatKind, from that answer.
     */
    val nat: Long,
    /**
     * A SipralNetworkProbe: whether a TURN relay was allocated.
     */
    val turn: Long,
    /**
     * A `SipralTransport` the TURN server was reached over, or zero.
     */
    val turnProtocol: Long,
    /**
     * A SipralServerReach.
     */
    val server: Long,
    /**
     * The status the server answered with, or zero.
     */
    val serverStatus: Long,
    /**
     * From sending the `OPTIONS` to its answer, in milliseconds.
     */
    val serverRoundTripMs: Long,
    /**
     * A SipralNetworkProbe: whether echo audio came back.
     */
    val echo: Long,
    /**
     * A SipralNetworkVerdict for the echo alone.
     */
    val echoVerdict: Long,
    /**
     * Packets lost or too late to play, as a percentage of those due.
     */
    val lossPercent: Double,
    /**
     * Interarrival jitter (RFC 3550 §6.4.1), in milliseconds.
     */
    val jitterMs: Double,
    /**
     * Nonzero when RTCP brought a round trip back in time.
     */
    val hasRoundTrip: Long,
    /**
     * That round trip, in milliseconds.
     */
    val roundTripMs: Long,
    /**
     * Half the round trip plus jitter buffer delay, in milliseconds.
     */
    val oneWayDelayMs: Long,
    /**
     * G.107's transmission rating R, 0 to 100, for concealed G.711.
     */
    val rFactor: Long,
    /**
     * Conversational MOS estimated from R, 1.0 to 4.5.
     */
    val mos: Double,
    /**
     * The socket the STUN answer was about.
     */
    val local: String?,
    /**
     * Where the STUN server saw it. Empty without an answer.
     */
    val mapped: String?,
)

/**
 * One of every arm [`SipralEventPayload`] declares, read back whole:
 * [`SipralEvent.payload`] builds one from every event, and which member of
 * it means something is named by [`SipralEvent.kind`] alone.
 */
class SipralEventPayload(
    /**
     * For SipralEventKind.REGISTRATION_CHANGED.
     */
    val registration: SipralRegistrationEvent,
    /**
     * For every call kind.
     */
    val call: SipralCallEvent,
    /**
     * For the three transfer kinds.
     */
    val transfer: SipralTransferEvent,
    /**
     * For every media kind.
     */
    val media: SipralMediaEvent,
    /**
     * For SipralEventKind.RECOVERY.
     */
    val recovery: SipralRecoveryEvent,
    /**
     * For SipralEventKind.TRANSPORT_WANTED.
     */
    val transportWanted: SipralTransportWantedEvent,
    /**
     * For SipralEventKind.SUBSCRIPTION_CHANGED and
     * SipralEventKind.NOTIFIED.
     */
    val subscription: SipralSubscriptionEvent,
    /**
     * For SipralEventKind.CALL_ANNOUNCED and
     * SipralEventKind.ANNOUNCED_CALL_MISSING.
     */
    val announce: SipralAnnounceEvent,
    /**
     * For SipralEventKind.RESOLVE_NEEDED.
     */
    val resolve: SipralResolveEvent,
    /**
     * For the three message kinds.
     */
    val message: SipralMessageEvent,
    /**
     * For SipralEventKind.NAT_MAPPING.
     */
    val nat: SipralNatEvent,
    /**
     * For SipralEventKind.NAT_RELAY.
     */
    val relay: SipralNatRelayEvent,
    /**
     * For SipralEventKind.REFERRAL.
     */
    val referral: SipralReferralEvent,
    /**
     * For SipralEventKind.TURN_STREAM.
     */
    val turnStream: SipralTurnStreamEvent,
    /**
     * For SipralEventKind.AUDIO_DEVICES_CHANGED.
     */
    val audio: SipralAudioEvent,
    /**
     * For SipralEventKind.STUN_SERVER.
     */
    val stunServer: SipralStunServerEvent,
    /**
     * For SipralEventKind.CALLER_VERIFICATION.
     */
    val verification: SipralVerificationEvent,
    /**
     * For SipralEventKind.PROGRESS_DETECTED.
     */
    val progress: SipralProgressEvent,
    /**
     * For SipralEventKind.CONFERENCE_CHANGED.
     */
    val conference: SipralConferenceEvent,
    /**
     * For SipralEventKind.TEXT_RECEIVED.
     */
    val text: SipralTextEvent,
    /**
     * For SipralEventKind.PRESENCE_CHANGED.
     */
    val presence: SipralPresenceEvent,
    /**
     * For SipralEventKind.TRANSPORT_FAILED.
     */
    val transportFailed: SipralTransportFailedEvent,
    /**
     * For SipralEventKind.LOCAL_CONFERENCE_CHANGED.
     */
    val localConference: SipralLocalConferenceEvent,
    /**
     * For SipralEventKind.LOOKUP_WANTED, SipralEventKind.LOCATED
     * and SipralEventKind.LOCATE_FAILED.
     */
    val locate: SipralLocateEvent,
    /**
     * For SipralEventKind.CHALLENGE_DECLINED.
     */
    val challenge: SipralChallengeEvent,
    /**
     * For SipralEventKind.TOKEN_REQUIRED.
     */
    val token: SipralTokenEvent,
    /**
     * For SipralEventKind.NETWORK_TEST.
     */
    val networkTest: SipralNetworkTestEvent,
)

class SipralEvent(
    /**
     * How many bytes of this struct are meaningful.
     */
    val size: Long,
    /**
     * The stack it is about.
     */
    val stack: Long,
    /**
     * What it is.
     */
    val kind: Long,
    /**
     * The account it is about, or SIPRAL_HANDLE_NONE.
     */
    val account: Long,
    /**
     * The call it is about, or SIPRAL_HANDLE_NONE.
     */
    val call: Long,
    /**
     * The SIP message behind it, whole and unparsed, or null.
     */
    val message: ByteArray?,
    /**
     * For SipralEventKind.REGISTRATION_CHANGED.
     */
    private val payloadRegistrationNumbers: LongArray? = null,
    /**
     * What this end is describing, and how long it is.
     */
    private val payloadCallLocalSdp: ByteArray? = null,
    /**
     * And what the far end is.
     */
    private val payloadCallRemoteSdp: ByteArray? = null,
    /**
     * The creating request's `From` URI, as written, without brackets or
     * header parameters. Null and zero when unavailable.
     */
    private val payloadCallFromUri: ByteArray? = null,
    /**
     * That `From`'s display name, quotes and backslash escapes resolved
     * (RFC 3261 §25.1). Null and zero when the header named none.
     */
    private val payloadCallFromDisplay: ByteArray? = null,
    /**
     * The `To` URI of the request that created this call, as written in
     * the header.
     */
    private val payloadCallToUri: ByteArray? = null,
    /**
     * The `Call-ID` of the request that created this call.
     */
    private val payloadCallCallId: ByteArray? = null,
    /**
     * The `text` of the first `Reason` value, unquoted. Null and zero
     * when there was none.
     */
    private val payloadCallCauseText: ByteArray? = null,
    /**
     * The first `P-Asserted-Identity`, else a `Remote-Party-ID`, as
     * written. Null and zero when none.
     */
    private val payloadCallAssertedUri: ByteArray? = null,
    /**
     * That identity's display name. Null and zero when it named none.
     */
    private val payloadCallAssertedDisplay: ByteArray? = null,
    /**
     * The top-most `Diversion` (RFC 5806), as written. Null and zero
     * when none.
     */
    private val payloadCallDivertedFrom: ByteArray? = null,
    /**
     * Why: its `reason`. Null and zero when none.
     */
    private val payloadCallDiversionReason: ByteArray? = null,
    /**
     * The first `Alert-Info` URI, without the angle brackets. Null and
     * zero when none. `sipral_call_identity_text` reads the rest.
     */
    private val payloadCallAlertInfo: ByteArray? = null,
    /**
     * For every call kind.
     */
    private val payloadCallNumbers: LongArray? = null,
    /**
     * Who to call, as UTF-8. Not NUL-terminated.
     */
    private val payloadTransferTarget: String? = null,
    /**
     * For the three transfer kinds.
     */
    private val payloadTransferNumbers: LongArray? = null,
    /**
     * The sentence behind `fault`, as UTF-8. Not NUL-terminated, and null
     * when nothing failed.
     */
    private val payloadMediaReason: String? = null,
    /**
     * What the stream cost, for the kind that carries it, and null for every
     * other. It belongs to the library and lives as long as the callback.
     */
    private val payloadMediaStatistics: LongArray? = null,
    /**
     * For every media kind.
     */
    private val payloadMediaNumbers: LongArray? = null,
    /**
     * For SipralEventKind.RECOVERY.
     */
    private val payloadRecoveryNumbers: LongArray? = null,
    /**
     * Where to, as `host:port`. Not NUL-terminated.
     */
    private val payloadTransportWantedDestination: String? = null,
    /**
     * For SipralEventKind.TRANSPORT_WANTED.
     */
    private val payloadTransportWantedNumbers: LongArray? = null,
    /**
     * For SipralEventKind.SUBSCRIPTION_CHANGED and
     * SipralEventKind.NOTIFIED.
     */
    private val payloadSubscriptionNumbers: LongArray? = null,
    /**
     * For SipralEventKind.CALL_ANNOUNCED and
     * SipralEventKind.ANNOUNCED_CALL_MISSING.
     */
    private val payloadAnnounceNumbers: LongArray? = null,
    /**
     * The host as the URI spells it; IPv6 literals keep brackets (RFC
     * 3261 §19.1.1). Not NUL-terminated.
     */
    private val payloadResolveHost: String? = null,
    /**
     * For SipralEventKind.RESOLVE_NEEDED.
     */
    private val payloadResolveNumbers: LongArray? = null,
    /**
     * SipralEventKind.MESSAGE_RECEIVED: the body's `Content-Type`, as
     * written. Null on the other kinds and for an empty MESSAGE.
     */
    private val payloadMessageContentType: String? = null,
    /**
     * SipralEventKind.MESSAGE_RECEIVED: the body. Null the same as
     * `content_type`.
     */
    private val payloadMessageBody: ByteArray? = null,
    /**
     * SipralEventKind.MESSAGES_WAITING: `Message-Account`, when sent
     * (RFC 3842 §3.5). Null otherwise.
     */
    private val payloadMessageMessageAccount: String? = null,
    /**
     * For the three message kinds.
     */
    private val payloadMessageNumbers: LongArray? = null,
    /**
     * The socket, as the application named it.
     */
    private val payloadNatLocal: String? = null,
    /**
     * The public address. Empty for `SIPRAL_NAT_MAPPING_UNANSWERED`.
     */
    private val payloadNatMapped: String? = null,
    /**
     * The old address, for `SIPRAL_NAT_MAPPING_MOVED`. Empty otherwise.
     */
    private val payloadNatPrevious: String? = null,
    /**
     * For SipralEventKind.NAT_MAPPING.
     */
    private val payloadNatNumbers: LongArray? = null,
    /**
     * The media socket, as `sipral_stack_nat_map` named it.
     */
    private val payloadRelayLocal: String? = null,
    /**
     * The relayed `host:port`. Empty for `SIPRAL_NAT_RELAY_FAILED`.
     */
    private val payloadRelayRelayed: String? = null,
    /**
     * Where the server saw the socket from, when it said. Empty otherwise.
     */
    private val payloadRelayMapped: String? = null,
    /**
     * Why there is no relay, in English. Empty for `SIPRAL_NAT_RELAY_ALLOCATED`.
     */
    private val payloadRelayReason: String? = null,
    /**
     * For SipralEventKind.NAT_RELAY.
     */
    private val payloadRelayNumbers: LongArray? = null,
    /**
     * Who to call, as UTF-8. Not NUL-terminated.
     */
    private val payloadReferralTarget: String? = null,
    /**
     * Its `Referred-By` (RFC 3892), UTF-8, unverified. Null when absent or
     * repeated (§2.1). Not NUL-terminated.
     */
    private val payloadReferralReferredBy: String? = null,
    /**
     * For SipralEventKind.REFERRAL.
     */
    private val payloadReferralNumbers: LongArray? = null,
    /**
     * The media socket; the connection's name in the calls that take one.
     */
    private val payloadTurnStreamLocal: String? = null,
    /**
     * The TURN server, `host:port`, as `turn_server` named it.
     */
    private val payloadTurnStreamServer: String? = null,
    /**
     * For SipralEventKind.TURN_STREAM.
     */
    private val payloadTurnStreamNumbers: LongArray? = null,
    /**
     * For SipralEventKind.AUDIO_DEVICES_CHANGED.
     */
    private val payloadAudioNumbers: LongArray? = null,
    /**
     * The server in use now (`CHANGED`) or the last that failed (`ALL_FAILED`).
     */
    private val payloadStunServerServer: String? = null,
    /**
     * For `CHANGED`, the previous server. Empty otherwise.
     */
    private val payloadStunServerPrevious: String? = null,
    /**
     * For SipralEventKind.STUN_SERVER.
     */
    private val payloadStunServerNumbers: LongArray? = null,
    /**
     * The certificate URL: to fetch, or that was verified. UTF-8, not
     * NUL-terminated; null and zero when none.
     */
    private val payloadVerificationCertificateUrl: String? = null,
    /**
     * The calling number a valid PASSporT was signed for, canonical.
     */
    private val payloadVerificationOrig: String? = null,
    /**
     * The origination identifier a valid SHAKEN PASSporT claimed (RFC
     * 8588 §5), a UUID.
     */
    private val payloadVerificationOrigid: String? = null,
    /**
     * Why it did not hold, in more words than `failure`, for a log.
     */
    private val payloadVerificationDetail: String? = null,
    /**
     * For SipralEventKind.CALLER_VERIFICATION.
     */
    private val payloadVerificationNumbers: LongArray? = null,
    /**
     * For SipralEventKind.PROGRESS_DETECTED.
     */
    private val payloadProgressNumbers: LongArray? = null,
    /**
     * For SipralEventKind.CONFERENCE_CHANGED.
     */
    private val payloadConferenceNumbers: LongArray? = null,
    /**
     * What the far end typed, UTF-8, not NUL-terminated.
     */
    private val payloadTextText: String? = null,
    /**
     * For SipralEventKind.TEXT_RECEIVED.
     */
    private val payloadTextNumbers: LongArray? = null,
    /**
     * SipralPresenceKind.WATCHED: the presentity, as the document
     * named it. Not NUL-terminated.
     */
    private val payloadPresenceEntity: String? = null,
    /**
     * SipralPresenceKind.WATCHED: the first note, the document's
     * own or else a tuple's. Null when there is none.
     */
    private val payloadPresenceNote: String? = null,
    /**
     * For SipralEventKind.PRESENCE_CHANGED.
     */
    private val payloadPresenceNumbers: LongArray? = null,
    /**
     * The platform's sentence as handed over. Null with length zero for none.
     */
    private val payloadTransportFailedDetail: String? = null,
    /**
     * For SipralEventKind.TRANSPORT_FAILED.
     */
    private val payloadTransportFailedNumbers: LongArray? = null,
    /**
     * For SipralEventKind.LOCAL_CONFERENCE_CHANGED.
     */
    private val payloadLocalConferenceNumbers: LongArray? = null,
    /**
     * The name to ask, on a lookup: `_sip._udp.example.com`, or a
     * host. Handed back to sipral_account_looked_up with the answer.
     * UTF-8, not NUL-terminated.
     */
    private val payloadLocateName: String? = null,
    /**
     * Every located address, comma-separated `host:port`, in RFC 3263
     * section 4.3 order, the one in use first. UTF-8, not NUL-terminated.
     */
    private val payloadLocateTargets: String? = null,
    /**
     * For SipralEventKind.LOOKUP_WANTED, SipralEventKind.LOCATED
     * and SipralEventKind.LOCATE_FAILED.
     */
    private val payloadLocateNumbers: LongArray? = null,
    /**
     * Where the challenged request went, as `host:port`. Not
     * NUL-terminated.
     */
    private val payloadChallengeServer: String? = null,
    /**
     * The challenged realms, separated by line feeds (a realm may hold a
     * comma, never a line break). UTF-8, not NUL-terminated.
     */
    private val payloadChallengeRealms: String? = null,
    /**
     * For SipralEventKind.CHALLENGE_DECLINED.
     */
    private val payloadChallengeNumbers: LongArray? = null,
    /**
     * Where the challenged request went, as `host:port`.
     */
    private val payloadTokenServer: String? = null,
    /**
     * The protection domain, empty when the challenge named none.
     */
    private val payloadTokenRealm: String? = null,
    /**
     * The scope the token has to carry: space-separated strings the
     * authorization server defines (RFC 6749 §3.3).
     */
    private val payloadTokenScope: String? = null,
    /**
     * The authorization server: an `https` URI, or empty if it was not one.
     */
    private val payloadTokenAuthzServer: String? = null,
    /**
     * The `error` code as the server wrote it, for `Other`.
     */
    private val payloadTokenErrorCode: String? = null,
    /**
     * For SipralEventKind.TOKEN_REQUIRED.
     */
    private val payloadTokenNumbers: LongArray? = null,
    /**
     * The socket the STUN answer was about.
     */
    private val payloadNetworkTestLocal: String? = null,
    /**
     * Where the STUN server saw it. Empty without an answer.
     */
    private val payloadNetworkTestMapped: String? = null,
    /**
     * For SipralEventKind.NETWORK_TEST.
     */
    private val payloadNetworkTestNumbers: LongArray? = null,
) {
    /** One of every arm [`SipralEventPayload`] declares; see its own documentation. */
    val payload: SipralEventPayload
        get() = SipralEventPayload(
            SipralRegistrationEvent((payloadRegistrationNumbers?.get(0) ?: 0L), (payloadRegistrationNumbers?.get(1) ?: 0L), (payloadRegistrationNumbers?.get(2) ?: 0L), (payloadRegistrationNumbers?.get(3) ?: 0L), (payloadRegistrationNumbers?.get(4) ?: 0L), (payloadRegistrationNumbers?.get(5) ?: 0L)),
            SipralCallEvent((payloadCallNumbers?.get(0) ?: 0L), (payloadCallNumbers?.get(1) ?: 0L), (payloadCallNumbers?.get(2) ?: 0L), (payloadCallNumbers?.get(3) ?: 0L), (payloadCallNumbers?.get(4) ?: 0L), (payloadCallNumbers?.get(5) ?: 0L), payloadCallLocalSdp, payloadCallRemoteSdp, (payloadCallNumbers?.get(6) ?: 0L), payloadCallFromUri, payloadCallFromDisplay, payloadCallToUri, payloadCallCallId, (payloadCallNumbers?.get(7) ?: 0L), (payloadCallNumbers?.get(8) ?: 0L), (payloadCallNumbers?.get(9) ?: 0L), payloadCallCauseText, (payloadCallNumbers?.get(10) ?: 0L), payloadCallAssertedUri, payloadCallAssertedDisplay, (payloadCallNumbers?.get(11) ?: 0L), (payloadCallNumbers?.get(12) ?: 0L), payloadCallDivertedFrom, payloadCallDiversionReason, (payloadCallNumbers?.get(13) ?: 0L), (payloadCallNumbers?.get(14) ?: 0L), (payloadCallNumbers?.get(15) ?: 0L), (payloadCallNumbers?.get(16) ?: 0L), (payloadCallNumbers?.get(17) ?: 0L), (payloadCallNumbers?.get(18) ?: 0L), (payloadCallNumbers?.get(19) ?: 0L), (payloadCallNumbers?.get(20) ?: 0L), (payloadCallNumbers?.get(21) ?: 0L), payloadCallAlertInfo, (payloadCallNumbers?.get(22) ?: 0L), (payloadCallNumbers?.get(23) ?: 0L), (payloadCallNumbers?.get(24) ?: 0L)),
            SipralTransferEvent((payloadTransferNumbers?.get(0) ?: 0L), (payloadTransferNumbers?.get(1) ?: 0L), payloadTransferTarget),
            SipralMediaEvent((payloadMediaNumbers?.get(0) ?: 0L), (payloadMediaNumbers?.get(1) ?: 0L), (payloadMediaNumbers?.get(2) ?: 0L), (payloadMediaNumbers?.get(3) ?: 0L), (payloadMediaNumbers?.get(4) ?: 0L), payloadMediaReason, payloadMediaStatistics?.let { SipralStreamStats.of(it) }, (payloadMediaNumbers?.get(5) ?: 0L), (payloadMediaNumbers?.get(6) ?: 0L), (payloadMediaNumbers?.get(7) ?: 0L), (payloadMediaNumbers?.get(8) ?: 0L), (payloadMediaNumbers?.get(9) ?: 0L), (payloadMediaNumbers?.get(10) ?: 0L), (payloadMediaNumbers?.get(11) ?: 0L), (payloadMediaNumbers?.get(12) ?: 0L), (payloadMediaNumbers?.get(13) ?: 0L)),
            SipralRecoveryEvent((payloadRecoveryNumbers?.get(0) ?: 0L), (payloadRecoveryNumbers?.get(1) ?: 0L), (payloadRecoveryNumbers?.get(2) ?: 0L), (payloadRecoveryNumbers?.get(3) ?: 0L)),
            SipralTransportWantedEvent((payloadTransportWantedNumbers?.get(0) ?: 0L), payloadTransportWantedDestination, (payloadTransportWantedNumbers?.get(1) ?: 0L), (payloadTransportWantedNumbers?.get(2) ?: 0L)),
            SipralSubscriptionEvent((payloadSubscriptionNumbers?.get(0) ?: 0L), (payloadSubscriptionNumbers?.get(1) ?: 0L), (payloadSubscriptionNumbers?.get(2) ?: 0L), (payloadSubscriptionNumbers?.get(3) ?: 0L), (payloadSubscriptionNumbers?.get(4) ?: 0L), (payloadSubscriptionNumbers?.get(5) ?: 0L), (payloadSubscriptionNumbers?.get(6) ?: 0L), (payloadSubscriptionNumbers?.get(7) ?: 0L), (payloadSubscriptionNumbers?.get(8) ?: 0L)),
            SipralAnnounceEvent((payloadAnnounceNumbers?.get(0) ?: 0L), (payloadAnnounceNumbers?.get(1) ?: 0L)),
            SipralResolveEvent((payloadResolveNumbers?.get(0) ?: 0L), payloadResolveHost, (payloadResolveNumbers?.get(1) ?: 0L), (payloadResolveNumbers?.get(2) ?: 0L)),
            SipralMessageEvent((payloadMessageNumbers?.get(0) ?: 0L), (payloadMessageNumbers?.get(1) ?: 0L), (payloadMessageNumbers?.get(2) ?: 0L), payloadMessageContentType, payloadMessageBody, (payloadMessageNumbers?.get(3) ?: 0L), (payloadMessageNumbers?.get(4) ?: 0L), (payloadMessageNumbers?.get(5) ?: 0L), (payloadMessageNumbers?.get(6) ?: 0L), (payloadMessageNumbers?.get(7) ?: 0L), payloadMessageMessageAccount),
            SipralNatEvent((payloadNatNumbers?.get(0) ?: 0L), (payloadNatNumbers?.get(1) ?: 0L), (payloadNatNumbers?.get(2) ?: 0L), (payloadNatNumbers?.get(3) ?: 0L), payloadNatLocal, payloadNatMapped, payloadNatPrevious),
            SipralNatRelayEvent((payloadRelayNumbers?.get(0) ?: 0L), (payloadRelayNumbers?.get(1) ?: 0L), payloadRelayLocal, payloadRelayRelayed, payloadRelayMapped, payloadRelayReason),
            SipralReferralEvent((payloadReferralNumbers?.get(0) ?: 0L), (payloadReferralNumbers?.get(1) ?: 0L), payloadReferralTarget, payloadReferralReferredBy),
            SipralTurnStreamEvent((payloadTurnStreamNumbers?.get(0) ?: 0L), (payloadTurnStreamNumbers?.get(1) ?: 0L), payloadTurnStreamLocal, payloadTurnStreamServer),
            SipralAudioEvent((payloadAudioNumbers?.get(0) ?: 0L), (payloadAudioNumbers?.get(1) ?: 0L), (payloadAudioNumbers?.get(2) ?: 0L), (payloadAudioNumbers?.get(3) ?: 0L), (payloadAudioNumbers?.get(4) ?: 0L)),
            SipralStunServerEvent((payloadStunServerNumbers?.get(0) ?: 0L), payloadStunServerServer, payloadStunServerPrevious),
            SipralVerificationEvent((payloadVerificationNumbers?.get(0) ?: 0L), (payloadVerificationNumbers?.get(1) ?: 0L), (payloadVerificationNumbers?.get(2) ?: 0L), (payloadVerificationNumbers?.get(3) ?: 0L), (payloadVerificationNumbers?.get(4) ?: 0L), (payloadVerificationNumbers?.get(5) ?: 0L), (payloadVerificationNumbers?.get(6) ?: 0L), payloadVerificationCertificateUrl, payloadVerificationOrig, payloadVerificationOrigid, payloadVerificationDetail),
            SipralProgressEvent((payloadProgressNumbers?.get(0) ?: 0L), (payloadProgressNumbers?.get(1) ?: 0L), (payloadProgressNumbers?.get(2) ?: 0L), (payloadProgressNumbers?.get(3) ?: 0L), (payloadProgressNumbers?.get(4) ?: 0L), (payloadProgressNumbers?.get(5) ?: 0L), (payloadProgressNumbers?.get(6) ?: 0L), (payloadProgressNumbers?.get(7) ?: 0L), (payloadProgressNumbers?.get(8) ?: 0L), (payloadProgressNumbers?.get(9) ?: 0L), (payloadProgressNumbers?.get(10) ?: 0L), (payloadProgressNumbers?.get(11) ?: 0L), (payloadProgressNumbers?.get(12) ?: 0L), (payloadProgressNumbers?.get(13) ?: 0L), (payloadProgressNumbers?.get(14) ?: 0L), (payloadProgressNumbers?.get(15) ?: 0L)),
            SipralConferenceEvent((payloadConferenceNumbers?.get(0) ?: 0L), (payloadConferenceNumbers?.get(1) ?: 0L), (payloadConferenceNumbers?.get(2) ?: 0L), (payloadConferenceNumbers?.get(3) ?: 0L)),
            SipralTextEvent(payloadTextText, (payloadTextNumbers?.get(0) ?: 0L)),
            SipralPresenceEvent((payloadPresenceNumbers?.get(0) ?: 0L), (payloadPresenceNumbers?.get(1) ?: 0L), (payloadPresenceNumbers?.get(2) ?: 0L), (payloadPresenceNumbers?.get(3) ?: 0L), payloadPresenceEntity, payloadPresenceNote, (payloadPresenceNumbers?.get(4) ?: 0L), (payloadPresenceNumbers?.get(5) ?: 0L), (payloadPresenceNumbers?.get(6) ?: 0L), (payloadPresenceNumbers?.get(7) ?: 0L), (payloadPresenceNumbers?.get(8) ?: 0L)),
            SipralTransportFailedEvent((payloadTransportFailedNumbers?.get(0) ?: 0L), (payloadTransportFailedNumbers?.get(1) ?: 0L), (payloadTransportFailedNumbers?.get(2) ?: 0L), (payloadTransportFailedNumbers?.get(3) ?: 0L), payloadTransportFailedDetail),
            SipralLocalConferenceEvent((payloadLocalConferenceNumbers?.get(0) ?: 0L), (payloadLocalConferenceNumbers?.get(1) ?: 0L), (payloadLocalConferenceNumbers?.get(2) ?: 0L), (payloadLocalConferenceNumbers?.get(3) ?: 0L), (payloadLocalConferenceNumbers?.get(4) ?: 0L), (payloadLocalConferenceNumbers?.get(5) ?: 0L), (payloadLocalConferenceNumbers?.get(6) ?: 0L)),
            SipralLocateEvent((payloadLocateNumbers?.get(0) ?: 0L), (payloadLocateNumbers?.get(1) ?: 0L), payloadLocateName, payloadLocateTargets, (payloadLocateNumbers?.get(2) ?: 0L)),
            SipralChallengeEvent((payloadChallengeNumbers?.get(0) ?: 0L), payloadChallengeServer, payloadChallengeRealms),
            SipralTokenEvent((payloadTokenNumbers?.get(0) ?: 0L), (payloadTokenNumbers?.get(1) ?: 0L), payloadTokenServer, payloadTokenRealm, payloadTokenScope, payloadTokenAuthzServer, payloadTokenErrorCode),
            SipralNetworkTestEvent((payloadNetworkTestNumbers?.get(0) ?: 0L), (payloadNetworkTestNumbers?.get(1) ?: 0L), (payloadNetworkTestNumbers?.get(2) ?: 0L), (payloadNetworkTestNumbers?.get(3) ?: 0L), (payloadNetworkTestNumbers?.get(4) ?: 0L), (payloadNetworkTestNumbers?.get(5) ?: 0L), (payloadNetworkTestNumbers?.get(6) ?: 0L), (payloadNetworkTestNumbers?.get(7) ?: 0L), (payloadNetworkTestNumbers?.get(8) ?: 0L), (payloadNetworkTestNumbers?.get(9) ?: 0L), (payloadNetworkTestNumbers?.get(10) ?: 0L), Double.fromBits(payloadNetworkTestNumbers?.get(11) ?: 0L), Double.fromBits(payloadNetworkTestNumbers?.get(12) ?: 0L), (payloadNetworkTestNumbers?.get(13) ?: 0L), (payloadNetworkTestNumbers?.get(14) ?: 0L), (payloadNetworkTestNumbers?.get(15) ?: 0L), (payloadNetworkTestNumbers?.get(16) ?: 0L), Double.fromBits(payloadNetworkTestNumbers?.get(17) ?: 0L), payloadNetworkTestLocal, payloadNetworkTestMapped),
        )
}

/**
 * The one callback a stack has.
 *
 * Called inside `sipral_stack_poll` on its thread, never concurrently
 * for one stack. Must not unwind. May call back into the library
 * (`docs/08-ffi.md`, "The shape").
 *
 * In Kotlin it is this interface, called on the thread that polls. The JNI
 * shim attaches that thread to the JVM for the length of the call when it
 * is not attached already. What a listener throws goes to that thread's
 * uncaught exception handler, and the poll carries on once the handler
 * returns. Android's default handler does not return: it ends the process.
 */
fun interface SipralEventListener {
    fun onEvent(event: SipralEvent)
}

/**
 * Every SipralEventListener a live handle was made with, under the key the JNI
 * shim hands back with each event. The native side holds no reference
 * to a listener at all: an event for a handle already destroyed finds
 * nothing here and goes nowhere.
 */
internal object SipralEventListeners {
    private val listening = HashMap<Long, SipralEventListener>()
    private val handles = HashMap<Long, Long>()
    private var last = 0L

    /** Keep a listener, and say what key the shim will hand it back under: zero for none. */
    fun register(listener: SipralEventListener?): Long {
        if (listener == null) {
            return 0
        }
        synchronized(this) {
            // the key crosses as a C pointer, which is 32 bits wide on half of Android
            check(last < Int.MAX_VALUE) { "every key a listener can be kept under has been handed out" }
            last += 1
            listening[last] = listener
            return last
        }
    }

    /** Tie a kept listener to the handle the call made, or let it go when the call failed. */
    fun made(key: Long, status: Int, handle: Long) {
        if (key == 0L) {
            return
        }
        synchronized(this) {
            if (status == SipralStatus.OK.value) {
                handles[handle] = key
            } else {
                listening.remove(key)
            }
        }
    }

    /** Let go of the listener a destroyed handle was left with. */
    fun gone(handle: Long) {
        synchronized(this) {
            val key = handles.remove(handle) ?: return
            listening.remove(key)
        }
    }

    /** Called by the JNI shim, once per event, on the thread that polls. */
    @JvmStatic
    fun deliver(key: Long, size: Long, stack: Long, kind: Long, account: Long, call: Long, message: ByteArray?, payloadRegistrationNumbers: LongArray?, payloadCallLocalSdp: ByteArray?, payloadCallRemoteSdp: ByteArray?, payloadCallFromUri: ByteArray?, payloadCallFromDisplay: ByteArray?, payloadCallToUri: ByteArray?, payloadCallCallId: ByteArray?, payloadCallCauseText: ByteArray?, payloadCallAssertedUri: ByteArray?, payloadCallAssertedDisplay: ByteArray?, payloadCallDivertedFrom: ByteArray?, payloadCallDiversionReason: ByteArray?, payloadCallAlertInfo: ByteArray?, payloadCallNumbers: LongArray?, payloadTransferTarget: ByteArray?, payloadTransferNumbers: LongArray?, payloadMediaReason: ByteArray?, payloadMediaStatistics: LongArray?, payloadMediaNumbers: LongArray?, payloadRecoveryNumbers: LongArray?, payloadTransportWantedDestination: ByteArray?, payloadTransportWantedNumbers: LongArray?, payloadSubscriptionNumbers: LongArray?, payloadAnnounceNumbers: LongArray?, payloadResolveHost: ByteArray?, payloadResolveNumbers: LongArray?, payloadMessageContentType: ByteArray?, payloadMessageBody: ByteArray?, payloadMessageMessageAccount: ByteArray?, payloadMessageNumbers: LongArray?, payloadNatLocal: ByteArray?, payloadNatMapped: ByteArray?, payloadNatPrevious: ByteArray?, payloadNatNumbers: LongArray?, payloadRelayLocal: ByteArray?, payloadRelayRelayed: ByteArray?, payloadRelayMapped: ByteArray?, payloadRelayReason: ByteArray?, payloadRelayNumbers: LongArray?, payloadReferralTarget: ByteArray?, payloadReferralReferredBy: ByteArray?, payloadReferralNumbers: LongArray?, payloadTurnStreamLocal: ByteArray?, payloadTurnStreamServer: ByteArray?, payloadTurnStreamNumbers: LongArray?, payloadAudioNumbers: LongArray?, payloadStunServerServer: ByteArray?, payloadStunServerPrevious: ByteArray?, payloadStunServerNumbers: LongArray?, payloadVerificationCertificateUrl: ByteArray?, payloadVerificationOrig: ByteArray?, payloadVerificationOrigid: ByteArray?, payloadVerificationDetail: ByteArray?, payloadVerificationNumbers: LongArray?, payloadProgressNumbers: LongArray?, payloadConferenceNumbers: LongArray?, payloadTextText: ByteArray?, payloadTextNumbers: LongArray?, payloadPresenceEntity: ByteArray?, payloadPresenceNote: ByteArray?, payloadPresenceNumbers: LongArray?, payloadTransportFailedDetail: ByteArray?, payloadTransportFailedNumbers: LongArray?, payloadLocalConferenceNumbers: LongArray?, payloadLocateName: ByteArray?, payloadLocateTargets: ByteArray?, payloadLocateNumbers: LongArray?, payloadChallengeServer: ByteArray?, payloadChallengeRealms: ByteArray?, payloadChallengeNumbers: LongArray?, payloadTokenServer: ByteArray?, payloadTokenRealm: ByteArray?, payloadTokenScope: ByteArray?, payloadTokenAuthzServer: ByteArray?, payloadTokenErrorCode: ByteArray?, payloadTokenNumbers: LongArray?, payloadNetworkTestLocal: ByteArray?, payloadNetworkTestMapped: ByteArray?, payloadNetworkTestNumbers: LongArray?) {
        val listener = synchronized(this) { listening[key] } ?: return
        try {
            listener.onEvent(SipralEvent(size, stack, kind, account, call, message, payloadRegistrationNumbers, payloadCallLocalSdp, payloadCallRemoteSdp, payloadCallFromUri, payloadCallFromDisplay, payloadCallToUri, payloadCallCallId, payloadCallCauseText, payloadCallAssertedUri, payloadCallAssertedDisplay, payloadCallDivertedFrom, payloadCallDiversionReason, payloadCallAlertInfo, payloadCallNumbers, payloadTransferTarget?.let { String(it, Charsets.UTF_8) }, payloadTransferNumbers, payloadMediaReason?.let { String(it, Charsets.UTF_8) }, payloadMediaStatistics, payloadMediaNumbers, payloadRecoveryNumbers, payloadTransportWantedDestination?.let { String(it, Charsets.UTF_8) }, payloadTransportWantedNumbers, payloadSubscriptionNumbers, payloadAnnounceNumbers, payloadResolveHost?.let { String(it, Charsets.UTF_8) }, payloadResolveNumbers, payloadMessageContentType?.let { String(it, Charsets.UTF_8) }, payloadMessageBody, payloadMessageMessageAccount?.let { String(it, Charsets.UTF_8) }, payloadMessageNumbers, payloadNatLocal?.let { String(it, Charsets.UTF_8) }, payloadNatMapped?.let { String(it, Charsets.UTF_8) }, payloadNatPrevious?.let { String(it, Charsets.UTF_8) }, payloadNatNumbers, payloadRelayLocal?.let { String(it, Charsets.UTF_8) }, payloadRelayRelayed?.let { String(it, Charsets.UTF_8) }, payloadRelayMapped?.let { String(it, Charsets.UTF_8) }, payloadRelayReason?.let { String(it, Charsets.UTF_8) }, payloadRelayNumbers, payloadReferralTarget?.let { String(it, Charsets.UTF_8) }, payloadReferralReferredBy?.let { String(it, Charsets.UTF_8) }, payloadReferralNumbers, payloadTurnStreamLocal?.let { String(it, Charsets.UTF_8) }, payloadTurnStreamServer?.let { String(it, Charsets.UTF_8) }, payloadTurnStreamNumbers, payloadAudioNumbers, payloadStunServerServer?.let { String(it, Charsets.UTF_8) }, payloadStunServerPrevious?.let { String(it, Charsets.UTF_8) }, payloadStunServerNumbers, payloadVerificationCertificateUrl?.let { String(it, Charsets.UTF_8) }, payloadVerificationOrig?.let { String(it, Charsets.UTF_8) }, payloadVerificationOrigid?.let { String(it, Charsets.UTF_8) }, payloadVerificationDetail?.let { String(it, Charsets.UTF_8) }, payloadVerificationNumbers, payloadProgressNumbers, payloadConferenceNumbers, payloadTextText?.let { String(it, Charsets.UTF_8) }, payloadTextNumbers, payloadPresenceEntity?.let { String(it, Charsets.UTF_8) }, payloadPresenceNote?.let { String(it, Charsets.UTF_8) }, payloadPresenceNumbers, payloadTransportFailedDetail?.let { String(it, Charsets.UTF_8) }, payloadTransportFailedNumbers, payloadLocalConferenceNumbers, payloadLocateName?.let { String(it, Charsets.UTF_8) }, payloadLocateTargets?.let { String(it, Charsets.UTF_8) }, payloadLocateNumbers, payloadChallengeServer?.let { String(it, Charsets.UTF_8) }, payloadChallengeRealms?.let { String(it, Charsets.UTF_8) }, payloadChallengeNumbers, payloadTokenServer?.let { String(it, Charsets.UTF_8) }, payloadTokenRealm?.let { String(it, Charsets.UTF_8) }, payloadTokenScope?.let { String(it, Charsets.UTF_8) }, payloadTokenAuthzServer?.let { String(it, Charsets.UTF_8) }, payloadTokenErrorCode?.let { String(it, Charsets.UTF_8) }, payloadTokenNumbers, payloadNetworkTestLocal?.let { String(it, Charsets.UTF_8) }, payloadNetworkTestMapped?.let { String(it, Charsets.UTF_8) }, payloadNetworkTestNumbers))
        } catch (failure: Throwable) {
            val thread = Thread.currentThread()
            thread.uncaughtExceptionHandler.uncaughtException(thread, failure)
        }
    }
}

/**
 * What SipralScreenCallback reads about one INVITE, before it has
 * had any effect.
 *
 * Read `size` first, like SipralEvent. `message` and
 * `source` borrow from a request still being processed: read nothing after
 * the callback returns.
 */
class SipralScreenRequest(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * The stack the INVITE arrived on.
     */
    val stack: Long,
    /**
     * The far end of the bytes, as `host:port`. Null and zero for a byte
     * stream bound without naming its far end.
     */
    val source: String?,
    /**
     * The INVITE, whole and unparsed; `sipral_message_header` and its
     * companions read headers out of it.
     */
    val message: ByteArray?,
)

/**
 * The screening policy: called once per INVITE, before it has any
 * effect. Installed with sipral_stack_screen.
 *
 * **It runs with the stack's lock held** (see the module docs), unlike
 * SipralEventCallback. **It must
 * not call back into the stack it was given**, from any thread; such a
 * call is answered `SIPRAL_STATUS_BUSY`. Another stack is fine. It must
 * not unwind across the boundary.
 *
 * `request` and what it points at are valid for this call only.
 *
 * **The answer is a SIP status code.** `SIPRAL_SCREEN_ACCEPT` (200) lets
 * the INVITE through as if no policy were installed. 400 to 699 refuses
 * with that status. Anything else refuses with 500: zero (a listener that
 * threw), a 1xx (would leave the transaction open), another 2xx, or a 3xx
 * (no `Contact` to redirect to).
 *
 * In Kotlin it is this interface, called on the thread that polls. The JNI
 * shim attaches that thread to the JVM for the length of the call when it
 * is not attached already. It answers with a Long, which the shim
 * hands the library back. What a listener throws is not delivered anywhere:
 * the shim clears it and answers as if this had returned zero, which is what
 * every answering listener here is defined to take as "no".
 */
fun interface SipralScreenListener {
    fun onRequest(request: SipralScreenRequest): Long
}

/**
 * Every SipralScreenListener a live handle was made with, under the key the JNI
 * shim hands back with each event. The native side holds no reference
 * to a listener at all: an event for a handle already destroyed finds
 * nothing here and goes nowhere.
 */
internal object SipralScreenListeners {
    private val listening = HashMap<Long, SipralScreenListener>()
    private val handles = HashMap<Long, Long>()
    private var last = 0L

    /** Keep a listener, and say what key the shim will hand it back under: zero for none. */
    fun register(listener: SipralScreenListener?): Long {
        if (listener == null) {
            return 0
        }
        synchronized(this) {
            // the key crosses as a C pointer, which is 32 bits wide on half of Android
            check(last < Int.MAX_VALUE) { "every key a listener can be kept under has been handed out" }
            last += 1
            listening[last] = listener
            return last
        }
    }

    /**
     * Hand a kept listener to a handle the caller already had, letting go of
     * whatever that handle held before it. A key of zero is the call that
     * removed the listener outright, and a call that failed leaves the handle
     * with what it had.
     */
    fun installed(key: Long, status: Int, handle: Long) {
        synchronized(this) {
            if (status != SipralStatus.OK.value) {
                listening.remove(key)
                return
            }
            val before = if (key == 0L) handles.remove(handle) else handles.put(handle, key)
            if (before != null) {
                listening.remove(before)
            }
        }
    }

    /** Let go of the listener a destroyed handle was left with. */
    fun gone(handle: Long) {
        synchronized(this) {
            val key = handles.remove(handle) ?: return
            listening.remove(key)
        }
    }

    /** Called by the JNI shim, once per event, on the thread that polls. */
    @JvmStatic
    fun deliver(key: Long, size: Long, stack: Long, source: ByteArray?, message: ByteArray?): Long {
        val listener = synchronized(this) { listening[key] } ?: return 0
        return listener.onRequest(SipralScreenRequest(size, stack, source?.let { String(it, Charsets.UTF_8) }, message))
    }
}

/**
 * What SipralProcessorCallback is handed for one call: an ordinary
 * frame to process, or a request to forget what has been learned.
 *
 * Library-owned, passed as a `const` pointer. Read `size` first; read
 * nothing after the callback returns, since the buffers are borrowed.
 */
class SipralProcessorFrame(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * 0 for an ordinary frame; 1 to forget learned state (device or codec
     * change). When 1, all three buffers are null and lengths zero.
     */
    val reset: Long,
    /**
     * The frame just captured from the microphone. Null on reset.
     */
    val nearEnd: ShortArray?,
    /**
     * The far-end audio played over the same span as `near_end`. Null on
     * reset.
     */
    val farEnd: ShortArray?,
    /**
     * Where the callback writes the replacement for `near_end`; every
     * sample must be written. Null on reset.
     */
    val out: ShortArray?,
)

/**
 * Echo cancellation, gain control or noise suppression, run over one
 * frame, or told to forget what it has learned — SipralProcessorFrame
 * says which. Installed with sipral_media_attach_processor.
 *
 * **It runs with this call's media locked** (see
 * sipral_media_attach_processor): it must not call into the media
 * handle it was attached through, on any thread, and must not unwind.
 *
 * `frame` and what it points at are library-owned, valid only during the
 * call.
 *
 * In Kotlin it is this interface, called on the thread that polls. The JNI
 * shim attaches that thread to the JVM for the length of the call when it
 * is not attached already. What a listener throws goes to that thread's
 * uncaught exception handler, and the poll carries on once the handler
 * returns. Android's default handler does not return: it ends the process.
 */
fun interface SipralProcessorListener {
    fun onFrame(frame: SipralProcessorFrame)
}

/**
 * Every SipralProcessorListener a live handle was made with, under the key the JNI
 * shim hands back with each event. The native side holds no reference
 * to a listener at all: an event for a handle already destroyed finds
 * nothing here and goes nowhere.
 */
internal object SipralProcessorListeners {
    private val listening = HashMap<Long, SipralProcessorListener>()
    private val handles = HashMap<Long, Long>()
    private var last = 0L

    /** Keep a listener, and say what key the shim will hand it back under: zero for none. */
    fun register(listener: SipralProcessorListener?): Long {
        if (listener == null) {
            return 0
        }
        synchronized(this) {
            // the key crosses as a C pointer, which is 32 bits wide on half of Android
            check(last < Int.MAX_VALUE) { "every key a listener can be kept under has been handed out" }
            last += 1
            listening[last] = listener
            return last
        }
    }

    /**
     * Hand a kept listener to a handle the caller already had, letting go of
     * whatever that handle held before it. A key of zero is the call that
     * removed the listener outright, and a call that failed leaves the handle
     * with what it had.
     */
    fun installed(key: Long, status: Int, handle: Long) {
        synchronized(this) {
            if (status != SipralStatus.OK.value) {
                listening.remove(key)
                return
            }
            val before = if (key == 0L) handles.remove(handle) else handles.put(handle, key)
            if (before != null) {
                listening.remove(before)
            }
        }
    }

    /** Let go of the listener a destroyed handle was left with. */
    fun gone(handle: Long) {
        synchronized(this) {
            val key = handles.remove(handle) ?: return
            listening.remove(key)
        }
    }

    /** Called by the JNI shim, once per event, on the thread that polls. */
    @JvmStatic
    fun deliver(key: Long, size: Long, reset: Long, nearEnd: ShortArray?, farEnd: ShortArray?, out: ShortArray?) {
        val listener = synchronized(this) { listening[key] } ?: return
        try {
            listener.onFrame(SipralProcessorFrame(size, reset, nearEnd, farEnd, out))
        } catch (failure: Throwable) {
            val thread = Thread.currentThread()
            thread.uncaughtExceptionHandler.uncaughtException(thread, failure)
        }
    }
}

/**
 * One packet the engine encoded, handed to
 * `sipral_stack_config_t::audio_transmit_callback`: send it from the
 * call's media socket and return.
 *
 * Read `size` before anything past it, and nothing once the callback
 * returns. The callback runs on the engine's thread, once per frame per
 * call; it may call the media entry points and must not destroy the stack.
 */
class SipralAudioTransmit(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * The call whose socket this leaves from.
     */
    val call: Long,
    /**
     * A `SipralTransport`: UDP is a datagram from the media socket; TCP
     * and TLS are bytes to write in order on the socket's TURN connection.
     */
    val protocol: Long,
    /**
     * Zero. Keeps later members at the same offsets on 32- and 64-bit
     * targets. Written zero, never read.
     */
    val reserved: Long,
    /**
     * Where to send it, `host:port`, UTF-8 and not NUL-terminated.
     */
    val destination: String?,
    /**
     * The octets.
     */
    val payload: ByteArray?,
)

/**
 * Where the packets the engine encodes go: the application's, called
 * on the engine's thread with one `sipral_audio_transmit_t` per packet.
 *
 * In Kotlin it is this interface, called on the thread that polls. The JNI
 * shim attaches that thread to the JVM for the length of the call when it
 * is not attached already. What a listener throws goes to that thread's
 * uncaught exception handler, and the poll carries on once the handler
 * returns. Android's default handler does not return: it ends the process.
 */
fun interface SipralAudioTransmitListener {
    fun onTransmit(transmit: SipralAudioTransmit)
}

/**
 * Every SipralAudioTransmitListener a live handle was made with, under the key the JNI
 * shim hands back with each event. The native side holds no reference
 * to a listener at all: an event for a handle already destroyed finds
 * nothing here and goes nowhere.
 */
internal object SipralAudioTransmitListeners {
    private val listening = HashMap<Long, SipralAudioTransmitListener>()
    private val handles = HashMap<Long, Long>()
    private var last = 0L

    /** Keep a listener, and say what key the shim will hand it back under: zero for none. */
    fun register(listener: SipralAudioTransmitListener?): Long {
        if (listener == null) {
            return 0
        }
        synchronized(this) {
            // the key crosses as a C pointer, which is 32 bits wide on half of Android
            check(last < Int.MAX_VALUE) { "every key a listener can be kept under has been handed out" }
            last += 1
            listening[last] = listener
            return last
        }
    }

    /** Tie a kept listener to the handle the call made, or let it go when the call failed. */
    fun made(key: Long, status: Int, handle: Long) {
        if (key == 0L) {
            return
        }
        synchronized(this) {
            if (status == SipralStatus.OK.value) {
                handles[handle] = key
            } else {
                listening.remove(key)
            }
        }
    }

    /** Let go of the listener a destroyed handle was left with. */
    fun gone(handle: Long) {
        synchronized(this) {
            val key = handles.remove(handle) ?: return
            listening.remove(key)
        }
    }

    /** Called by the JNI shim, once per event, on the thread that polls. */
    @JvmStatic
    fun deliver(key: Long, size: Long, call: Long, protocol: Long, reserved: Long, destination: ByteArray?, payload: ByteArray?) {
        val listener = synchronized(this) { listening[key] } ?: return
        try {
            listener.onTransmit(SipralAudioTransmit(size, call, protocol, reserved, destination?.let { String(it, Charsets.UTF_8) }, payload))
        } catch (failure: Throwable) {
            val thread = Thread.currentThread()
            thread.uncaughtExceptionHandler.uncaughtException(thread, failure)
        }
    }
}

/**
 * One log line, as SipralLogCallback reads it.
 *
 * Read `size` first, and nothing after the callback returns: the strings
 * live for the call only.
 */
class SipralLogRecord(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * The stack the line is about.
     */
    val stack: Long,
    /**
     * A `SipralLogLevel`, never `SIPRAL_LOG_LEVEL_OFF`.
     */
    val level: Long,
    /**
     * Which part of the stack wrote it — `registration`, `call`,
     * `media`, `decision`, `sip`, `api` — as UTF-8, not NUL-terminated.
     */
    val target: String?,
    /**
     * The line, already redacted, as UTF-8, not NUL-terminated. A
     * `SIPRAL_LOG_LEVEL_TRACE` line holding a whole message has line
     * breaks in it.
     */
    val message: String?,
    /**
     * Lines dropped by the rate limit or queue since the previous line.
     */
    val suppressed: Long,
)

/**
 * Where a stack's log lines go. Installed with
 * sipral_stack_log.
 *
 * Called on the thread that just finished a call into this stack, with
 * nothing held, so it may call back into the library. One line at a
 * time, never on two threads at once. It must not unwind.
 *
 * `record` and what it points at are valid for this call only.
 *
 * In Kotlin it is this interface, called on the thread that polls. The JNI
 * shim attaches that thread to the JVM for the length of the call when it
 * is not attached already. What a listener throws goes to that thread's
 * uncaught exception handler, and the poll carries on once the handler
 * returns. Android's default handler does not return: it ends the process.
 */
fun interface SipralLogListener {
    fun onRecord(record: SipralLogRecord)
}

/**
 * Every SipralLogListener a live handle was made with, under the key the JNI
 * shim hands back with each event. The native side holds no reference
 * to a listener at all: an event for a handle already destroyed finds
 * nothing here and goes nowhere.
 */
internal object SipralLogListeners {
    private val listening = HashMap<Long, SipralLogListener>()
    private val handles = HashMap<Long, Long>()
    private var last = 0L

    /** Keep a listener, and say what key the shim will hand it back under: zero for none. */
    fun register(listener: SipralLogListener?): Long {
        if (listener == null) {
            return 0
        }
        synchronized(this) {
            // the key crosses as a C pointer, which is 32 bits wide on half of Android
            check(last < Int.MAX_VALUE) { "every key a listener can be kept under has been handed out" }
            last += 1
            listening[last] = listener
            return last
        }
    }

    /**
     * Hand a kept listener to a handle the caller already had, letting go of
     * whatever that handle held before it. A key of zero is the call that
     * removed the listener outright, and a call that failed leaves the handle
     * with what it had.
     */
    fun installed(key: Long, status: Int, handle: Long) {
        synchronized(this) {
            if (status != SipralStatus.OK.value) {
                listening.remove(key)
                return
            }
            val before = if (key == 0L) handles.remove(handle) else handles.put(handle, key)
            if (before != null) {
                listening.remove(before)
            }
        }
    }

    /** Let go of the listener a destroyed handle was left with. */
    fun gone(handle: Long) {
        synchronized(this) {
            val key = handles.remove(handle) ?: return
            listening.remove(key)
        }
    }

    /** Called by the JNI shim, once per event, on the thread that polls. */
    @JvmStatic
    fun deliver(key: Long, size: Long, stack: Long, level: Long, target: ByteArray?, message: ByteArray?, suppressed: Long) {
        val listener = synchronized(this) { listening[key] } ?: return
        try {
            listener.onRecord(SipralLogRecord(size, stack, level, target?.let { String(it, Charsets.UTF_8) }, message?.let { String(it, Charsets.UTF_8) }, suppressed))
        } catch (failure: Throwable) {
            val thread = Thread.currentThread()
            thread.uncaughtExceptionHandler.uncaughtException(thread, failure)
        }
    }
}

/**
 * What a call across the boundary answered, when it did not answer
 * OK. The message is the calling thread's last error, read before
 * anything else on this thread could replace it.
 */
class SipralException(val status: SipralStatus?, message: String) :
    RuntimeException(if (message.isEmpty()) status.toString() else "$status: $message")

/**
 * The ABI as JNI declares it. Every integer crosses as a Long, every
 * struct the library fills in comes back in a LongArray, and every
 * struct a caller builds crosses one field at a time, so nothing here
 * depends on a field offset that the two Android pointer widths would
 * disagree about.
 */
internal object SipralNative {
    init {
        System.loadLibrary("sipral_jni")
        agree(1, 2)
    }

    /**
     * Throw unless the library that loaded serves a binding printed
     * against major.minor. Called once, as this object is initialised,
     * with the version this file was printed from, so a package whose
     * native library came from another build fails here with both
     * versions named rather than in whichever call first disagrees.
     */
    fun agree(major: Long, minor: Long) {
        val status = sipral_abi_check(major, minor)
        if (status != SipralStatus.OK.value) {
            throw SipralException(SipralStatus.of(status), Sipral.lastErrorMessage())
        }
    }

    external fun sipral_last_error_message(buffer: ByteArray, needed: LongArray): Int
    external fun sipral_status_name(status: Long): String?
    external fun sipral_abi_version(version: LongArray): Int
    external fun sipral_abi_check(major: Long, minor: Long): Int
    external fun sipral_abi_struct_size(name: ByteArray, size: LongArray): Int
    external fun sipral_abi_versioned_count(count: LongArray): Int
    external fun sipral_capabilities(capabilities: LongArray): Int
    external fun sipral_stack_create(configEventCallback: Long, configTransport: Long, configBindAddress: ByteArray?, configUserAgent: ByteArray?, configEntropy: ByteArray?, configTimerT1Ms: Long, configTimerT2Ms: Long, configTimerT4Ms: Long, configCodecs: ByteArray?, configFrameMs: Long, configOfferDtmf: Long, configOfferRtcpMux: Long, configSilenceSuppression: Long, configMediaStallWatchdog: Long, configMediaStallMs: Long, configMediaClockUnixSeconds: Long, configMediaSeed: ByteArray?, configSrtp: Long, configIce: Long, configNat: Long, configStunServer: ByteArray?, configG729AnnexB: Long, configTurnServer: ByteArray?, configTurnUsername: ByteArray?, configTurnPassword: ByteArray?, configReferrals: Long, configRegistrarKeepalive: Long, configRegistrarKeepaliveMs: Long, configTurnTransport: Long, configAudio: Long, configAudioActivation: Long, configAudioTransmitCallback: Long, configAudioProbeMs: Long, configAudioDeviceRateHz: Long, configMaxDialogs: Long, configMaxServerTransactions: Long, configDiagnosticDecisions: Long, configDiagnosticRecords: Long, configDtmfDetection: Long, configStunFallbacks: ByteArray?, configRtpPortMin: Long, configRtpPortMax: Long, configSrtpSuites: ByteArray?, configPathMtu: Long, configDatagramWithoutStreamBytes: Long, configPseudonymSalt: ByteArray?, configDiagnosticTrace: Long, configReserved: Long, configSystemEchoCancellation: Long, configReserved35: Long, configHeldAudio: Long, configReserved36: Long, stack: LongArray): Int
    external fun sipral_stack_settings(stack: Long, settings: LongArray): Int
    external fun sipral_stack_destroy(stack: Long): Int
    external fun sipral_stack_poll(stack: Long, nowMs: Long, result: LongArray): Int
    external fun sipral_stack_counters(stack: Long, counters: LongArray): Int
    external fun sipral_stack_screen(stack: Long, callback: Long): Int
    external fun sipral_stack_invite_limit(stack: Long, everyMs: Long, burst: Long): Int
    external fun sipral_account_subscribe(stack: Long, account: Long, configTarget: ByteArray?, configPackage: ByteArray?, configAccept: ByteArray?, configExpiresSeconds: Long, configDestination: ByteArray?, configTransport: Long, configReserved: Long, subscription: LongArray, nowMs: Long): Int
    external fun sipral_subscription_end(stack: Long, subscription: Long, nowMs: Long): Int
    external fun sipral_subscription_state(stack: Long, subscription: Long, state: LongArray): Int
    external fun sipral_subscription_lamp(stack: Long, subscription: Long, phase: LongArray): Int
    external fun sipral_subscription_dialog_count(stack: Long, subscription: Long, count: LongArray): Int
    external fun sipral_subscription_dialog_at(stack: Long, subscription: Long, index: Long, dialog: LongArray): Int
    external fun sipral_subscription_dialog_text(stack: Long, subscription: Long, index: Long, which: Long, buffer: ByteArray, needed: LongArray): Int
    external fun sipral_account_message(stack: Long, account: Long, target: ByteArray, contentType: ByteArray, body: ByteArray, message: LongArray, nowMs: Long): Int
    external fun sipral_account_announce(stack: Long, account: Long, caller: ByteArray, announcement: LongArray, call: LongArray, nowMs: Long): Int
    external fun sipral_account_refresh_binding(stack: Long, account: Long, nowMs: Long): Int
    external fun sipral_announcement_forget(stack: Long, announcement: Long): Int
    external fun sipral_account_push_echo(stack: Long, account: Long, echo: LongArray): Int
    external fun sipral_account_add(stack: Long, configAor: ByteArray?, configRegistrar: ByteArray?, configContact: ByteArray?, configRegistrarAddress: ByteArray?, configDisplayName: ByteArray?, configAuthUser: ByteArray?, configAuthPassword: ByteArray?, configInstanceId: ByteArray?, configExpiresSeconds: Long, configHeadersBytes: ByteArray?, configHeadersLengths: LongArray?, configTransport: Long, configPushProvider: ByteArray?, configPushPrid: ByteArray?, configPushParam: ByteArray?, configPushWakesItself: Long, configQualityReportUri: ByteArray?, configSessionTimer: Long, configSessionIntervalSeconds: Long, configPrivacy: Long, configTrustedPeers: ByteArray?, configSrtp: Long, configSrtpSuites: ByteArray?, configStirVerification: Long, configStirKey: ByteArray?, configStirCertificateUrl: ByteArray?, configStirOrig: ByteArray?, configStirOrigid: ByteArray?, configStirAttestation: Long, configRecordingInClear: Long, configKeepaliveMs: Long, configServerUri: ByteArray?, configTlsPinSha256: ByteArray?, configServerNaptr: Long, configReserved: Long, configStreamProtocol: Long, configReserved35: Long, configRealms: ByteArray?, configWebsocketHost: ByteArray?, configWebsocketResource: ByteArray?, account: LongArray): Int
    external fun sipral_account_remove(stack: Long, account: Long): Int
    external fun sipral_account_register(stack: Long, account: Long, nowMs: Long): Int
    external fun sipral_account_unregister(stack: Long, account: Long, nowMs: Long): Int
    external fun sipral_account_registration_state(stack: Long, account: Long, state: LongArray): Int
    external fun sipral_account_set_access_token(stack: Long, account: Long, token: ByteArray): Int
    external fun sipral_stack_network_test(stack: Long, configAccount: Long, configProbeSocket: ByteArray?, configEchoCall: Long, configEchoMs: Long, configTimeoutMs: Long, nowMs: Long, test: LongArray): Int
    external fun sipral_call_place(stack: Long, account: Long, configTarget: ByteArray?, configSdp: ByteArray?, configDestination: ByteArray?, configKeepAllForks: Long, configMediaAddress: ByteArray?, configHeadersBytes: ByteArray?, configHeadersLengths: LongArray?, configSrtp: Long, configTransport: Long, configCodecs: ByteArray?, configIce: Long, configTextAddress: ByteArray?, configFeedback: Long, configFocus: Long, configFollowRedirects: Long, configReserved: Long, call: LongArray, nowMs: Long): Int
    external fun sipral_call_ring(stack: Long, call: Long, sdp: ByteArray, nowMs: Long): Int
    external fun sipral_call_ring_media(stack: Long, call: Long, configTarget: ByteArray?, configSdp: ByteArray?, configDestination: ByteArray?, configKeepAllForks: Long, configMediaAddress: ByteArray?, configHeadersBytes: ByteArray?, configHeadersLengths: LongArray?, configSrtp: Long, configTransport: Long, configCodecs: ByteArray?, configIce: Long, configTextAddress: ByteArray?, configFeedback: Long, configFocus: Long, configFollowRedirects: Long, configReserved: Long, nowMs: Long): Int
    external fun sipral_call_answer(stack: Long, call: Long, sdp: ByteArray, nowMs: Long): Int
    external fun sipral_call_answer_media(stack: Long, call: Long, mediaAddress: ByteArray, nowMs: Long): Int
    external fun sipral_call_answer_with(stack: Long, call: Long, configTarget: ByteArray?, configSdp: ByteArray?, configDestination: ByteArray?, configKeepAllForks: Long, configMediaAddress: ByteArray?, configHeadersBytes: ByteArray?, configHeadersLengths: LongArray?, configSrtp: Long, configTransport: Long, configCodecs: ByteArray?, configIce: Long, configTextAddress: ByteArray?, configFeedback: Long, configFocus: Long, configFollowRedirects: Long, configReserved: Long, nowMs: Long): Int
    external fun sipral_call_reject(stack: Long, call: Long, code: Long, nowMs: Long): Int
    external fun sipral_call_hangup(stack: Long, call: Long, nowMs: Long): Int
    external fun sipral_call_set_headers(stack: Long, call: Long, headersBytes: ByteArray?, headersLengths: LongArray?): Int
    external fun sipral_call_hold(stack: Long, call: Long, nowMs: Long): Int
    external fun sipral_call_resume(stack: Long, call: Long, nowMs: Long): Int
    external fun sipral_call_change_codecs(stack: Long, call: Long, codecs: ByteArray, nowMs: Long): Int
    external fun sipral_call_restart_ice(stack: Long, call: Long, nowMs: Long): Int
    external fun sipral_call_media_readdress(stack: Long, call: Long, mediaAddress: ByteArray, publicAddress: ByteArray, nowMs: Long): Int
    external fun sipral_call_hangup_for(stack: Long, call: Long, sipCause: Long, q850Cause: Long, text: ByteArray, nowMs: Long): Int
    external fun sipral_call_redirect(stack: Long, call: Long, statusCode: Long, targets: ByteArray, reason: ByteArray, nowMs: Long): Int
    external fun sipral_call_identity_count(stack: Long, call: Long, which: Long, count: LongArray): Int
    external fun sipral_call_identity_text(stack: Long, call: Long, index: Long, which: Long, buffer: ByteArray, needed: LongArray): Int
    external fun sipral_call_join(stack: Long, callA: Long, callB: Long): Int
    external fun sipral_call_leave(stack: Long, call: Long): Int
    external fun sipral_call_accept_session(stack: Long, call: Long, sdp: ByteArray, nowMs: Long): Int
    external fun sipral_call_reject_session(stack: Long, call: Long, code: Long, nowMs: Long): Int
    external fun sipral_call_send_dtmf(stack: Long, call: Long, digits: ByteArray, via: Long, durationMs: Long, nowMs: Long): Int
    external fun sipral_call_transfer(stack: Long, call: Long, target: ByteArray, nowMs: Long): Int
    external fun sipral_call_consult(stack: Long, call: Long, configTarget: ByteArray?, configSdp: ByteArray?, configDestination: ByteArray?, configKeepAllForks: Long, configMediaAddress: ByteArray?, configHeadersBytes: ByteArray?, configHeadersLengths: LongArray?, configSrtp: Long, configTransport: Long, configCodecs: ByteArray?, configIce: Long, configTextAddress: ByteArray?, configFeedback: Long, configFocus: Long, configFollowRedirects: Long, configReserved: Long, consultation: LongArray, nowMs: Long): Int
    external fun sipral_call_transfer_to(stack: Long, call: Long, other: Long, nowMs: Long): Int
    external fun sipral_call_accept_transfer(stack: Long, call: Long, configTarget: ByteArray?, configSdp: ByteArray?, configDestination: ByteArray?, configKeepAllForks: Long, configMediaAddress: ByteArray?, configHeadersBytes: ByteArray?, configHeadersLengths: LongArray?, configSrtp: Long, configTransport: Long, configCodecs: ByteArray?, configIce: Long, configTextAddress: ByteArray?, configFeedback: Long, configFocus: Long, configFollowRedirects: Long, configReserved: Long, placed: LongArray, nowMs: Long): Int
    external fun sipral_call_reject_transfer(stack: Long, call: Long, code: Long, nowMs: Long): Int
    external fun sipral_call_accept_transfer_placed(stack: Long, call: Long, placed: Long, nowMs: Long): Int
    external fun sipral_call_state(stack: Long, call: Long, state: LongArray): Int
    external fun sipral_call_hold_state(stack: Long, call: Long, here: LongArray, there: LongArray): Int
    external fun sipral_codec_name(codec: Long): String?
    external fun sipral_codec_count(count: LongArray): Int
    external fun sipral_codec_at(index: Long, info: LongArray): Int
    external fun sipral_stack_codec_order(stack: Long, outCodecs: IntArray, count: LongArray): Int
    external fun sipral_call_media(stack: Long, call: Long, media: LongArray): Int
    external fun sipral_media_release(media: Long): Int
    external fun sipral_media_info(media: Long, info: LongArray): Int
    external fun sipral_media_codec_candidate_count(media: Long, count: LongArray): Int
    external fun sipral_media_codec_candidate_at(media: Long, index: Long, candidate: LongArray): Int
    external fun sipral_media_path_candidate_count(media: Long, count: LongArray): Int
    external fun sipral_media_path_candidate_at(media: Long, index: Long, outCandidate: Long): Int
    external fun sipral_media_statistics(media: Long, nowMs: Long, stats: LongArray): Int
    external fun sipral_media_receive(media: Long, data: ByteArray, from: ByteArray, nowMs: Long, arrival: LongArray): Int
    external fun sipral_media_playback(media: Long, samples: ShortArray, written: LongArray, source: LongArray): Int
    external fun sipral_media_capture(media: Long, nowMs: Long, samples: ShortArray, packet: Long): Int
    external fun sipral_media_set_app_rate(media: Long, hz: Long): Int
    external fun sipral_media_attach_processor(media: Long, callback: Long): Int
    external fun sipral_media_detach_processor(media: Long, wasAttached: LongArray): Int
    external fun sipral_media_reset_processor(media: Long, wasAttached: LongArray): Int
    external fun sipral_media_mix(mediaA: Long, mediaB: Long, nowMs: Long, mic: ShortArray, local: ShortArray, packetA: Long, packetB: Long): Int
    external fun sipral_media_poll_rtcp(media: Long, nowMs: Long, packet: Long): Int
    external fun sipral_media_poll_transmit(media: Long, nowMs: Long, packet: Long): Int
    external fun sipral_stack_poll_farewell(stack: Long, call: LongArray, packet: Long): Int
    external fun sipral_media_dialling(media: Long, dialling: LongArray, waiting: LongArray): Int
    external fun sipral_media_stop_dialling(media: Long): Int
    external fun sipral_media_record_start(media: Long, path: ByteArray): Int
    external fun sipral_media_record_stop(media: Long): Int
    external fun sipral_media_record_state(media: Long, recording: LongArray, recordedMs: LongArray): Int
    external fun sipral_stack_poll_transmit(stack: Long, transmit: Long): Int
    external fun sipral_stack_receive_datagram(stack: Long, transport: Long, data: ByteArray, from: ByteArray, to: ByteArray, nowMs: Long): Int
    external fun sipral_stack_receive_stream(stack: Long, transport: Long, data: ByteArray, nowMs: Long): Int
    external fun sipral_stack_transport_bind(stack: Long, transport: Long, protocol: Long, local: ByteArray, remote: ByteArray, nowMs: Long, transportId: LongArray): Int
    external fun sipral_stack_transport_failed(stack: Long, transport: Long, error: Long, nowMs: Long): Int
    external fun sipral_stack_transport_failed_with(stack: Long, failureTransport: Long, failureError: Long, failureTls: Long, failureDetail: ByteArray?, nowMs: Long): Int
    external fun sipral_stack_stream_closed(stack: Long, transport: Long, nowMs: Long): Int
    external fun sipral_stack_stun_servers(stack: Long, servers: ByteArray, nowMs: Long): Int
    external fun sipral_stack_nat_map(stack: Long, local: ByteArray, nowMs: Long): Int
    external fun sipral_stack_nat_unmap(stack: Long, local: ByteArray, nowMs: Long): Int
    external fun sipral_stack_poll_stun(stack: Long, transmit: Long): Int
    external fun sipral_stack_receive_stun(stack: Long, data: ByteArray, from: ByteArray, to: ByteArray, nowMs: Long): Int
    external fun sipral_stack_turn_connected(stack: Long, local: ByteArray, nowMs: Long): Int
    external fun sipral_stack_turn_receive(stack: Long, local: ByteArray, data: ByteArray, nowMs: Long): Int
    external fun sipral_stack_turn_closed(stack: Long, local: ByteArray, nowMs: Long): Int
    external fun sipral_event_kind_name(kind: Long): String?
    external fun sipral_message_header_count(message: ByteArray, name: ByteArray, count: LongArray): Int
    external fun sipral_message_header(message: ByteArray, name: ByteArray, index: Long, offset: LongArray, len: LongArray): Int
    external fun sipral_message_header_element_count(message: ByteArray, name: ByteArray, count: LongArray): Int
    external fun sipral_message_header_element(message: ByteArray, name: ByteArray, index: Long, offset: LongArray, len: LongArray): Int
    external fun sipral_stack_suspending(stack: Long, nowMs: Long, report: LongArray): Int
    external fun sipral_stack_resumed(stack: Long, nowMs: Long): Int
    external fun sipral_stack_network_changed(stack: Long, fromLink: Long, fromAddress: ByteArray, fromInterface: ByteArray, fromResolves: Long, toLink: Long, toAddress: ByteArray, toInterface: ByteArray, toResolves: Long, nowMs: Long, recovery: LongArray): Int
    external fun sipral_stack_interface_lost(stack: Long, nowMs: Long): Int
    external fun sipral_stack_name_resolution_lost(stack: Long, nowMs: Long): Int
    external fun sipral_account_rebind(stack: Long, account: Long, transport: Long, remote: ByteArray, contact: ByteArray, nowMs: Long): Int
    external fun sipral_stack_cold_start(stack: Long, nowMs: Long): Int
    external fun sipral_account_freeze(stack: Long, account: Long, buffer: ByteArray, len: LongArray, nowMs: Long): Int
    external fun sipral_account_thaw(stack: Long, account: Long, snapshot: ByteArray, asleepMs: Long, nowMs: Long): Int
    external fun sipral_account_time_to_ready(stack: Long, account: Long, hasValue: LongArray, ms: LongArray): Int
    external fun sipral_stack_resolved(stack: Long, dialog: Long, addresses: ByteArray, protocol: Long): Int
    external fun sipral_account_retarget(stack: Long, account: Long, registrarAddress: ByteArray, nowMs: Long): Int
    external fun sipral_call_record_json(stack: Long, call: Long, buffer: ByteArray, needed: LongArray): Int
    external fun sipral_stack_diagnostics_json(stack: Long, buffer: ByteArray, needed: LongArray): Int
    external fun sipral_subscription_conference(stack: Long, subscription: Long, conference: LongArray): Int
    external fun sipral_subscription_conference_user_at(stack: Long, subscription: Long, index: Long, user: LongArray): Int
    external fun sipral_subscription_conference_text(stack: Long, subscription: Long, index: Long, which: Long, buffer: ByteArray, needed: LongArray): Int
    external fun sipral_call_set_focus(stack: Long, call: Long, focus: Long): Int
    external fun sipral_call_conference_uri(stack: Long, call: Long, buffer: ByteArray, needed: LongArray): Int
    external fun sipral_call_subscribe_conference(stack: Long, call: Long, subscription: LongArray, nowMs: Long): Int
    external fun sipral_account_publish_presence(stack: Long, account: Long, presenceBasic: Long, presenceActivity: Long, presenceNote: ByteArray?, nowMs: Long): Int
    external fun sipral_account_unpublish_presence(stack: Long, account: Long, nowMs: Long): Int
    external fun sipral_media_send_text(media: Long, text: ByteArray): Int
    external fun sipral_media_poll_text(media: Long, nowMs: Long, packet: Long): Int
    external fun sipral_media_receive_text(media: Long, data: ByteArray, from: ByteArray, nowMs: Long, taken: LongArray): Int
    external fun sipral_call_record_to(stack: Long, call: Long, configServer: ByteArray?, configDestination: ByteArray?, configTransport: Long, configThisEnd: ByteArray?, configFarEnd: ByteArray?, recording: LongArray, nowMs: Long): Int
    external fun sipral_call_stop_recording_to(stack: Long, call: Long, nowMs: Long): Int
    external fun sipral_media_poll_recording(media: Long, packet: Long, farEnd: LongArray): Int
    external fun sipral_stack_recording_start(stack: Long, note: ByteArray): Int
    external fun sipral_stack_recording_stop(stack: Long, buffer: ByteArray, needed: LongArray): Int
    external fun sipral_audio_refresh(stack: Long, count: LongArray): Int
    external fun sipral_audio_device_count(stack: Long, count: LongArray): Int
    external fun sipral_audio_device_at(stack: Long, index: Long, device: LongArray, buffer: ByteArray, needed: LongArray): Int
    external fun sipral_audio_select(stack: Long, role: Long, device: Long): Int
    external fun sipral_audio_selection(stack: Long, role: Long, selected: LongArray, running: LongArray): Int
    external fun sipral_audio_set_gain(stack: Long, direction: Long, gain: Long): Int
    external fun sipral_audio_gain(stack: Long, direction: Long, gain: LongArray): Int
    external fun sipral_audio_set_muted(stack: Long, direction: Long, muted: Long): Int
    external fun sipral_audio_muted(stack: Long, direction: Long, muted: LongArray): Int
    external fun sipral_audio_level(stack: Long, direction: Long, peak: LongArray): Int
    external fun sipral_audio_activate(stack: Long): Int
    external fun sipral_audio_deactivate(stack: Long): Int
    external fun sipral_audio_ring(stack: Long, samples: ShortArray, sampleRateHz: Long, looped: Long): Int
    external fun sipral_audio_stop_ringing(stack: Long): Int
    external fun sipral_audio_info(stack: Long, info: LongArray): Int
    external fun sipral_audio_set_system_echo_cancellation(stack: Long, on: Long): Int
    external fun sipral_stack_log(stack: Long, level: Long, callback: Long): Int
    external fun sipral_stack_state_text(stack: Long, buffer: ByteArray, needed: LongArray): Int
    external fun sipral_stack_rtp_port_reserve(stack: Long, port: LongArray): Int
    external fun sipral_stack_rtp_port_release(stack: Long, port: Long): Int
    external fun sipral_stack_stir(stack: Long, configAnchors: ByteArray?, configFreshnessSeconds: Long, configCertificateWaitMs: Long, configUnixSeconds: Long, configAcceptServiceProviderCodes: Long, configReserved: Long, nowMs: Long): Int
    external fun sipral_call_stir_certificate(stack: Long, call: Long, chain: ByteArray, nowMs: Long): Int
    external fun sipral_media_encryption_count(media: Long, count: LongArray): Int
    external fun sipral_media_encryption_at(media: Long, index: Long, stream: LongArray): Int
    external fun sipral_call_dtmf_detection(stack: Long, call: Long, mode: Long): Int
    external fun sipral_call_detect_progress(stack: Long, call: Long, configListen: Long, configRegion: Long, configAnsweringMachine: Long, configBeep: Long, configBeepWindowMs: Long, configMaxInitialSilenceMs: Long, configMaxGreetingMs: Long, configSilenceAfterGreetingMs: Long, configMaxWords: Long, configMinWordMs: Long, configMinWordGapMs: Long, configMaxDecisionMs: Long, configMinSpeechAboveFloorDb: Long, configBeepMinMs: Long, configBeepMaxMs: Long, configToneCycles: Long): Int
    external fun sipral_call_consent_tone(stack: Long, call: Long, toneEnabled: Long, toneFrequencyHz: Long, toneAttenuationDb: Long, toneLengthMs: Long, toneIntervalMs: Long, toneLocal: Long): Int
    external fun sipral_media_record_start_with(media: Long, path: ByteArray, optionsFormat: Long, optionsLayout: Long, optionsSampleRate: Long, optionsBitrate: Long, optionsCheckpointMs: Long, optionsReserved: Long): Int
    external fun sipral_local_conference_create(stack: Long, configMaxMembers: Long, configLocal: Long, configSampleRate: Long, configReserved: Long, conference: LongArray): Int
    external fun sipral_local_conference_destroy(conference: Long): Int
    external fun sipral_local_conference_add(conference: Long, call: Long): Int
    external fun sipral_local_conference_remove(conference: Long, call: Long): Int
    external fun sipral_local_conference_set_muted(conference: Long, member: Long, direction: Long, muted: Long): Int
    external fun sipral_local_conference_set_gain(conference: Long, member: Long, direction: Long, gain: Long): Int
    external fun sipral_local_conference_info(conference: Long, info: LongArray): Int
    external fun sipral_local_conference_member_at(conference: Long, index: Long, member: LongArray): Int
    external fun sipral_local_conference_talker_at(conference: Long, index: Long, member: LongArray): Int
    external fun sipral_local_conference_tick(conference: Long, nowMs: Long, mic: ShortArray, speaker: ShortArray, written: LongArray): Int
    external fun sipral_local_conference_poll_transmit(conference: Long, call: LongArray, packet: Long): Int
    external fun sipral_local_conference_record_start(conference: Long, path: ByteArray, optionsFormat: Long, optionsLayout: Long, optionsSampleRate: Long, optionsBitrate: Long, optionsCheckpointMs: Long, optionsReserved: Long): Int
    external fun sipral_local_conference_record_stop(conference: Long): Int
    external fun sipral_account_looked_up(stack: Long, account: Long, name: ByteArray, record: Long, answer: Long, records: ByteArray, nowMs: Long): Int
    external fun sipral_account_check_certificate(stack: Long, account: Long, certificate: ByteArray, unixSeconds: Long, pinned: LongArray): Int
    external fun sipral_advertised_address(bound: ByteArray, peer: ByteArray, buffer: ByteArray, needed: LongArray): Int
    external fun sipral_stack_diagnostic_trace(stack: Long, on: Long): Int
    external fun sipral_stack_srtp_suite_order(stack: Long, outSuites: IntArray, count: LongArray): Int
    external fun sipral_audio_call_set_gain(stack: Long, call: Long, direction: Long, gain: Long): Int
    external fun sipral_audio_call_gain(stack: Long, call: Long, direction: Long, gain: LongArray): Int
    external fun sipral_audio_call_set_muted(stack: Long, call: Long, direction: Long, muted: Long): Int
    external fun sipral_audio_call_muted(stack: Long, call: Long, direction: Long, muted: LongArray): Int
    external fun sipral_audio_call_level(stack: Long, call: Long, direction: Long, peak: LongArray): Int
}

/** Everything the library does, with the C conventions read off it. */
object Sipral {
    /**
     * The value no live handle ever takes.
     */
    const val HANDLE_NONE: Long = 0

    /**
     * The ABI's major version. Nothing published against one major works
     * against another; within one, a binding built against a minor works
     * against a library at that minor or any later one.
     */
    const val ABI_VERSION_MAJOR: Long = 1

    /**
     * The ABI's minor version, raised by anything the header gains. Rules:
     * Versioning section of `docs/08-ffi.md`.
     */
    const val ABI_VERSION_MINOR: Long = 2

    /**
     * The ABI's patch version, raised by a fix that changes no declaration.
     */
    const val ABI_VERSION_PATCH: Long = 0

    /**
     * Bits of SipralCapabilities.transports. A transport this ABI has no
     * bit for yet reads as absent.
     *
     * Derived from SipralTransport's numbers (`1 << (value - 1)`), so the
     * two numberings never have to be kept in step by hand.
     */
    const val TRANSPORT_BIT_UDP: Long = 1

    /**
     * See SIPRAL_TRANSPORT_BIT_UDP.
     */
    const val TRANSPORT_BIT_TCP: Long = 2

    /**
     * See SIPRAL_TRANSPORT_BIT_UDP.
     */
    const val TRANSPORT_BIT_TLS: Long = 4

    /**
     * See SIPRAL_TRANSPORT_BIT_UDP.
     */
    const val TRANSPORT_BIT_WS: Long = 8

    /**
     * See SIPRAL_TRANSPORT_BIT_UDP.
     */
    const val TRANSPORT_BIT_WSS: Long = 16

    /**
     * Bits of SipralCapabilities.features.
     */
    const val FEATURE_DTMF: Long = 1

    /**
     * See SIPRAL_FEATURE_DTMF.
     */
    const val FEATURE_RTCP_MUX: Long = 2

    /**
     * See SIPRAL_FEATURE_DTMF.
     */
    const val FEATURE_RECORDING: Long = 4

    /**
     * See SIPRAL_FEATURE_DTMF.
     */
    const val FEATURE_MEDIA_STALL_WATCHDOG: Long = 8

    /**
     * See SIPRAL_FEATURE_DTMF.
     */
    const val FEATURE_SRTP: Long = 16

    /**
     * See SIPRAL_FEATURE_DTMF. RFC 6665 subscriptions and the
     * dialog-state package a busy lamp field is built on, reached with
     * sipral_account_subscribe.
     */
    const val FEATURE_SUBSCRIPTIONS: Long = 32

    /**
     * See SIPRAL_FEATURE_DTMF. Opus is behind a compile-time feature
     * (libopus is licensed, not written here). Set from the codec catalogue,
     * not from a crate feature flag. `SIPRAL_CODEC_OPUS` keeps its number either way.
     */
    const val FEATURE_OPUS: Long = 64

    /**
     * DTLS-SRTP (RFC 5764): media keys come from a handshake on the media path.
     *
     * Behind a compile-time feature. `SIPRAL_SRTP_DTLS` and
     * `SIPRAL_SRTP_DTLS_REQUIRED` keep their numbers in a build without it and
     * answer `SIPRAL_STATUS_NOT_SUPPORTED` there, never an unencrypted call.
     *
     * An application that sets one of those policies must also drain
     * `sipral_media_poll_transmit`; see there.
     */
    const val FEATURE_DTLS_SRTP: Long = 128

    /**
     * See SIPRAL_FEATURE_DTMF. ICE in the full role (RFC 8445), with
     * consent freshness (RFC 7675) and the SDP attributes of RFC 8839.
     *
     * Behind a compile-time feature and off by policy (`docs/06-nat.md`).
     * `SIPRAL_ICE_OFFERED` and `SIPRAL_ICE_REQUIRED` keep their numbers in a
     * build without it and answer `SIPRAL_STATUS_NOT_SUPPORTED` there.
     *
     * An application that sets one of those policies must also drain
     * `sipral_media_poll_transmit`; see there.
     */
    const val FEATURE_ICE: Long = 256

    /**
     * See SIPRAL_FEATURE_DTMF. STUN (RFC 8489): a stack created with
     * `SIPRAL_NAT_STUN` learns its public address and writes it in `Contact`,
     * `c=` and `m=`. Without the feature, `SIPRAL_NAT_STUN` answers
     * `SIPRAL_STATUS_NOT_SUPPORTED`.
     */
    const val FEATURE_STUN: Long = 512

    /**
     * See SIPRAL_FEATURE_DTMF. A TURN server over TCP or TLS
     * (RFC 8656 §3.1): `sipral_stack_config_t::turn_transport` and
     * `SIPRAL_EVENT_KIND_TURN_STREAM`. Comes with `SIPRAL_FEATURE_ICE`;
     * without it a non-UDP `turn_transport` answers `SIPRAL_STATUS_NOT_SUPPORTED`.
     */
    const val FEATURE_TURN_STREAM: Long = 1024

    /**
     * See SIPRAL_FEATURE_DTMF. The built-in audio engine
     * (`sipral_stack_config_t::audio` = `SIPRAL_AUDIO_DEVICE`, and the
     * `sipral_audio_*` entry points). Clear where there is no backend (Linux,
     * Android below API 28); `SIPRAL_AUDIO_DEVICE` then answers
     * `SIPRAL_STATUS_NOT_SUPPORTED`. On Android it is the phone's answer, read
     * at call time. This crate's own answer: the engine is not under the facade.
     */
    const val FEATURE_AUDIO_DEVICE: Long = 2048

    /**
     * See SIPRAL_FEATURE_DTMF. Caller identity on every call event:
     * asserted identity behind `trusted_peers` (RFC 3325), `verstat`,
     * `Privacy`, `Diversion`, `History-Info`, `Answer-Mode`, `Alert-Info`;
     * end causes (RFC 3326) and `sipral_call_hangup_for`;
     * `sipral_call_redirect`; an account's `privacy` and `session_timer`.
     */
    const val FEATURE_CALLER_IDENTITY: Long = 4096

    /**
     * See SIPRAL_FEATURE_DTMF. A call follows a network change:
     * `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED` and `sipral_call_media_readdress`.
     */
    const val FEATURE_CALL_READDRESS: Long = 8192

    /**
     * See SIPRAL_FEATURE_DTMF. The redacted, rate-limited log callback
     * (`sipral_stack_log`) and the state snapshot (`sipral_stack_state_text`).
     * Set in every build.
     */
    const val FEATURE_LOGGING: Long = 16384

    /**
     * See SIPRAL_FEATURE_DTMF. Stack ceilings (`max_dialogs`,
     * `max_server_transactions`, `diagnostic_decisions`, `diagnostic_records`),
     * `SIPRAL_STATUS_LIMIT_REACHED`, and the counters in `sipral_counters_t`.
     */
    const val FEATURE_LIMITS: Long = 32768

    /**
     * See SIPRAL_FEATURE_DTMF. STIR/SHAKEN (RFC 8224, RFC 8588): signing
     * (`stir_key`, `stir_certificate_url`) and verification
     * (`sipral_stack_stir`, `SIPRAL_EVENT_KIND_CALLER_VERIFICATION`,
     * `sipral_call_stir_certificate`). Behind a compile-time feature, on by default.
     */
    const val FEATURE_STIR: Long = 65536

    /**
     * See SIPRAL_FEATURE_DTMF. SRTP policy and suites per account,
     * `SIPRAL_SRTP_DTLS_OR_SDES`, `SIPRAL_STATUS_SECURITY_POLICY`, and
     * `sipral_media_encryption_at`.
     */
    const val FEATURE_SRTP_POLICY: Long = 131072

    /**
     * See SIPRAL_FEATURE_DTMF. In-band signals: DTMF detection
     * (`sipral_stack_config_t::dtmf_detection`, `sipral_call_dtmf_detection`,
     * `SIPRAL_EVENT_KIND_IN_BAND_DIGIT`) and generation (`SIPRAL_DTMF_IN_BAND`),
     * progress and answering-machine detection (`sipral_call_detect_progress`,
     * `SIPRAL_EVENT_KIND_PROGRESS_DETECTED`), and `sipral_call_consent_tone`.
     */
    const val FEATURE_IN_BAND_SIGNALS: Long = 262144

    /**
     * See SIPRAL_FEATURE_DTMF. Recording formats
     * (`sipral_media_record_start_with`): mixed or stereo, WAV/RF64,
     * checkpointed, Ogg Opus with SIPRAL_FEATURE_OPUS; and L16 at 8 and 16 kHz.
     */
    const val FEATURE_RECORDING_FORMATS: Long = 524288

    /**
     * See SIPRAL_FEATURE_DTMF. SIPREC (RFC 7866): `sipral_call_record_to`
     * and `sipral_media_poll_recording`.
     */
    const val FEATURE_SIPREC: Long = 1048576

    /**
     * See SIPRAL_FEATURE_DTMF. Conference package (RFC 4575,
     * `sipral_subscription_conference`), focus `isfocus` (RFC 4579,
     * `sipral_call_conference_uri`), presence publish (RFC 3903) and watch (RFC 3856).
     */
    const val FEATURE_CONFERENCE: Long = 2097152

    /**
     * See SIPRAL_FEATURE_DTMF. Real-time text (RFC 4103): `text_address`,
     * `sipral_media_send_text`, `SIPRAL_EVENT_KIND_TEXT_RECEIVED`.
     */
    const val FEATURE_REALTIME_TEXT: Long = 4194304

    /**
     * See SIPRAL_FEATURE_DTMF. RTP/AVPF with Generic NACK and reduced-size
     * RTCP (RFC 4585, RFC 5506): `feedback`, reported in `sipral_media_info_t`.
     */
    const val FEATURE_RTCP_FEEDBACK: Long = 8388608

    /**
     * See SIPRAL_FEATURE_DTMF. A local conference of calls on any codec
     * and rate: `sipral_local_conference_create`,
     * `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED`.
     */
    const val FEATURE_LOCAL_CONFERENCE: Long = 16777216

    /**
     * The buffer a caller has to bring for one outgoing packet.
     *
     * The bound the session builds against, not a path MTU. Checked before
     * anything is encoded, so a frame is never encoded and then lost.
     */
    const val MEDIA_PACKET_BYTES: Long = 1500

    /**
     * The bound for an incoming datagram that RFC 5761 §4 classifies as control.
     *
     * Compound RTCP from a peer may exceed the media bound (RFC 3550 sets no
     * limit). Everything else still gets SIPRAL_MEDIA_PACKET_BYTES; outgoing
     * RTCP always fits the media bound.
     */
    const val MEDIA_RTCP_BYTES: Long = 8192

    /**
     * Room enough for any address this ABI writes, the NUL included:
     * `[2001:db8:0000:0000:0000:0000:0000:0001]:65535` and a byte to spare.
     */
    const val ADDRESS_BYTES: Long = 64

    /**
     * The transport a stack is created with.
     *
     * Never removed from the table; failure stops it, sipral_stack_transport_bind restores
     * it. Zero in `sipral_account_config_t::transport` and `sipral_call_config_t::transport`
     * means this one.
     */
    const val TRANSPORT_MAIN: Long = 0

    /**
     * The largest message that crosses in either direction.
     *
     * Bounds the parser's work against a hostile peer. Size stream read buffers to this; about
     * 1500 bytes suffices on a datagram socket.
     */
    const val MESSAGE_BYTES: Long = 65535

    /**
     * The longest `sipral_transport_failure_t::detail` accepted. Longer is refused, not cut.
     */
    const val TRANSPORT_DETAIL_BYTES: Long = 1024

    /**
     * The answer that lets an INVITE through.
     *
     * Any other answer refuses. Acceptance is 200, not zero, because zero is
     * what a binding returns when the listener threw, or what an unfilled
     * answer leaves; neither may admit a call.
     */
    const val SCREEN_ACCEPT: Long = 200

    /**
     * The default burst: ten INVITEs from one address at once.
     *
     * With SIPRAL_INVITE_LIMIT_EVERY_MS, the floor every stack starts with.
     * An INVITE past it is answered 480 and counted in
     * `sipral_counters_t::screened_refused_by_rate`; no event is raised.
     */
    const val INVITE_LIMIT_BURST: Long = 10

    /**
     * The default interval: one more INVITE every two seconds.
     */
    const val INVITE_LIMIT_EVERY_MS: Long = 2000

    /**
     * The voice-agent preset's burst: 128 at once.
     *
     * For a headless service taking every call from one trunk or proxy. Use
     * with SIPRAL_INVITE_LIMIT_VOICE_AGENT_EVERY_MS. Equal to the default
     * `max_dialogs`, so a rush hits that ceiling (503) before the rate.
     */
    const val INVITE_LIMIT_VOICE_AGENT_BURST: Long = 128

    /**
     * The voice-agent preset's interval: one more INVITE every 50 ms.
     */
    const val INVITE_LIMIT_VOICE_AGENT_EVERY_MS: Long = 50

    /**
     * Bits of `sipral_call_event_t::privacy` and of
     * `sipral_account_config_t::privacy` (RFC 3323 §4.2): `header`, obscure
     * the fields that could identify the caller.
     */
    const val PRIVACY_HEADER: Long = 1

    /**
     * `session`: hide the session description from the far end.
     */
    const val PRIVACY_SESSION: Long = 2

    /**
     * `user`: user-level privacy.
     */
    const val PRIVACY_USER: Long = 4

    /**
     * `id` (RFC 3325 §9.3): keep the asserted identity inside the trust
     * domain. What "withhold my number" asks for.
     */
    const val PRIVACY_ID: Long = 8

    /**
     * `critical`: fail the call rather than go without the privacy asked
     * for.
     */
    const val PRIVACY_CRITICAL: Long = 16

    /**
     * `none`: no privacy, stated. Read only; an account asks for none by
     * leaving every bit clear.
     */
    const val PRIVACY_NONE: Long = 32

    /**
     * The longest text sipral_stack_state_text writes, NUL included; a
     * buffer this size always fits.
     */
    const val STATE_TEXT_MAX: Long = 16384

    /**
     * Every struct and union the header declares, with how long tools/abi-gen
     * worked it out to be on each of the three layouts the ABI ships for:
     * 64-bit pointers (p64), then 32-bit pointers with 64-bit integers aligned
     * to four (p32a4, i386) and to eight (p32a8, ARM and Windows x86). A size
     * test holds this binding's own layout of each record, and the library's
     * answer from sipral_abi_struct_size, to the number for the layout it runs
     * on; bindings/c/abi-layout.c holds a C compiler to all three.
     * The three numbers are p64, p32a4 and p32a8, in that order: this
     * binding lays nothing out itself, so what its size test holds to
     * them is the library's own answer.
     */
    val recordLayouts: Map<String, IntArray> = mapOf(
        "sipral_abi_version_t" to intArrayOf(24, 20, 20),
        "sipral_capabilities_t" to intArrayOf(24, 16, 16),
        "sipral_counters_t" to intArrayOf(232, 228, 232),
        "sipral_stack_config_t" to intArrayOf(432, 296, 304),
        "sipral_poll_result_t" to intArrayOf(48, 28, 32),
        "sipral_stack_settings_t" to intArrayOf(136, 128, 136),
        "sipral_header_t" to intArrayOf(32, 16, 16),
        "sipral_account_config_t" to intArrayOf(496, 272, 280),
        "sipral_call_config_t" to intArrayOf(160, 92, 92),
        "sipral_codec_info_t" to intArrayOf(32, 28, 28),
        "sipral_codec_candidate_t" to intArrayOf(24, 20, 20),
        "sipral_path_candidate_t" to intArrayOf(88, 60, 64),
        "sipral_media_info_t" to intArrayOf(104, 92, 96),
        "sipral_stream_stats_t" to intArrayOf(328, 312, 328),
        "sipral_media_packet_t" to intArrayOf(64, 36, 36),
        "sipral_processor_frame_t" to intArrayOf(64, 32, 32),
        "sipral_transmit_t" to intArrayOf(88, 48, 48),
        "sipral_transport_failure_t" to intArrayOf(40, 24, 24),
        "sipral_registration_event_t" to intArrayOf(40, 36, 40),
        "sipral_call_event_t" to intArrayOf(328, 208, 216),
        "sipral_transfer_event_t" to intArrayOf(24, 16, 16),
        "sipral_media_event_t" to intArrayOf(96, 80, 80),
        "sipral_recovery_event_t" to intArrayOf(16, 16, 16),
        "sipral_transport_wanted_event_t" to intArrayOf(40, 20, 20),
        "sipral_subscription_event_t" to intArrayOf(56, 56, 56),
        "sipral_announce_event_t" to intArrayOf(16, 16, 16),
        "sipral_resolve_event_t" to intArrayOf(32, 24, 24),
        "sipral_message_event_t" to intArrayOf(96, 64, 64),
        "sipral_nat_event_t" to intArrayOf(64, 40, 40),
        "sipral_nat_relay_event_t" to intArrayOf(72, 40, 40),
        "sipral_referral_event_t" to intArrayOf(40, 24, 24),
        "sipral_turn_stream_event_t" to intArrayOf(40, 24, 24),
        "sipral_audio_event_t" to intArrayOf(20, 20, 20),
        "sipral_stun_server_event_t" to intArrayOf(40, 20, 20),
        "sipral_verification_event_t" to intArrayOf(96, 60, 60),
        "sipral_progress_event_t" to intArrayOf(80, 80, 80),
        "sipral_conference_event_t" to intArrayOf(24, 20, 24),
        "sipral_text_event_t" to intArrayOf(24, 12, 12),
        "sipral_presence_event_t" to intArrayOf(88, 64, 72),
        "sipral_transport_failed_event_t" to intArrayOf(32, 24, 24),
        "sipral_local_conference_event_t" to intArrayOf(40, 40, 40),
        "sipral_locate_event_t" to intArrayOf(48, 32, 32),
        "sipral_challenge_event_t" to intArrayOf(40, 20, 20),
        "sipral_token_event_t" to intArrayOf(88, 48, 48),
        "sipral_network_test_event_t" to intArrayOf(104, 88, 88),
        "sipral_event_payload_t" to intArrayOf(328, 208, 216),
        "sipral_event_t" to intArrayOf(384, 248, 264),
        "sipral_suspending_t" to intArrayOf(32, 16, 16),
        "sipral_screen_request_t" to intArrayOf(48, 28, 32),
        "sipral_subscribe_config_t" to intArrayOf(88, 48, 48),
        "sipral_watched_dialog_t" to intArrayOf(32, 28, 32),
        "sipral_push_echo_t" to intArrayOf(24, 20, 24),
        "sipral_audio_device_t" to intArrayOf(32, 28, 28),
        "sipral_audio_info_t" to intArrayOf(48, 44, 48),
        "sipral_audio_transmit_t" to intArrayOf(56, 36, 40),
        "sipral_log_record_t" to intArrayOf(64, 40, 48),
        "sipral_stir_config_t" to intArrayOf(56, 44, 48),
        "sipral_stream_encryption_t" to intArrayOf(32, 28, 28),
        "sipral_progress_config_t" to intArrayOf(72, 68, 68),
        "sipral_consent_tone_t" to intArrayOf(32, 28, 28),
        "sipral_recording_options_t" to intArrayOf(32, 28, 28),
        "sipral_conference_t" to intArrayOf(32, 28, 28),
        "sipral_conference_user_t" to intArrayOf(24, 20, 20),
        "sipral_presence_t" to intArrayOf(32, 20, 20),
        "sipral_record_config_t" to intArrayOf(80, 40, 40),
        "sipral_local_conference_config_t" to intArrayOf(24, 20, 20),
        "sipral_local_conference_info_t" to intArrayOf(56, 48, 48),
        "sipral_local_conference_member_t" to intArrayOf(40, 36, 40),
        "sipral_pinned_certificate_t" to intArrayOf(40, 36, 40),
        "sipral_network_test_config_t" to intArrayOf(48, 36, 40),
    )

    /**
     * The calling thread's last error, or an empty string when it has
     * none. Read the way C reads it: ask for the length, then for the
     * bytes.
     */
    fun lastErrorMessage(): String {
        val needed = LongArray(1)
        SipralNative.sipral_last_error_message(ByteArray(0), needed)
        val room = needed[0].toInt()
        if (room <= 1) {
            return ""
        }
        val buffer = ByteArray(room)
        if (SipralNative.sipral_last_error_message(buffer, needed) != SipralStatus.OK.value) {
            return ""
        }
        val end = buffer.indexOf(0)
        return String(buffer, 0, if (end < 0) buffer.size else end, Charsets.UTF_8)
    }

    /** Turn a status into an exception, and nothing into nothing. */
    private fun check(status: Int) {
        if (status != SipralStatus.OK.value) {
            throw SipralException(SipralStatus.of(status), lastErrorMessage())
        }
    }

    /**
     * The short name of a status code, as a static NUL-terminated string, or
     * null for a number that is not a status code.
     *
     * The string belongs to the library and lives as long as it is loaded.
     * It is meant for a log line; the last error is the sentence for a human.
     *
     * Safety
     *
     * Reads no memory the caller owns, and is safe to call from any thread.
     */
    fun statusName(status: Long): String? =
        SipralNative.sipral_status_name(status)

    /**
     * Report the ABI version this library provides.
     *
     * Safety
     *
     * `out_version` must point at a `sipral_abi_version_t` whose `size`
     * member says how long it is.
     */
    fun abiVersion(): SipralAbiVersion {
        val versionSlots = LongArray(SipralAbiVersion.SLOTS)
        check(SipralNative.sipral_abi_version(versionSlots))
        return SipralAbiVersion.of(versionSlots)
    }

    /**
     * Whether this library can serve a binding generated against
     * `major`.`minor`: same major and a minor no later than this library's.
     * Called once at load, before anything else.
     *
     * `SIPRAL_STATUS_UNSUPPORTED_VERSION` otherwise, with a last error naming
     * both versions. The patch never changes a declaration, so it is not asked.
     *
     * Safety
     *
     * Reads no memory the caller owns, and is safe to call from any thread.
     */
    fun abiCheck(major: Long, minor: Long) {
        check(SipralNative.sipral_abi_check(major, minor))
    }

    /**
     * How many bytes this build compiled one of the ABI's structs to.
     *
     * `name` is the header's type name, e.g. `sipral_stack_config_t`. An
     * unknown name is `SIPRAL_STATUS_INVALID_ARGUMENT`. Lets a binding detect
     * a header mismatch at load.
     *
     * Safety
     *
     * `name` must be readable for `name_len` bytes, and `out_size` must
     * point at one `size_t`.
     */
    fun abiStructSize(name: String): Long {
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        val sizeSlot = LongArray(1)
        check(SipralNative.sipral_abi_struct_size(nameBytes, sizeSlot))
        return sizeSlot[0]
    }

    /**
     * How many of the ABI's structs carry a `size` member.
     * Compare it with the caller's own list of structs, so a struct added to
     * the ABI is not missed by `sipral_abi_struct_size` checks.
     *
     * Safety
     *
     * `out_count` must point at one `size_t`.
     */
    fun abiVersionedCount(): Long {
        val countSlot = LongArray(1)
        check(SipralNative.sipral_abi_versioned_count(countSlot))
        return countSlot[0]
    }

    /**
     * What this build of the library can do, in one call.
     *
     * Answers the same before and after any stack exists. Safe from any
     * thread, including the event callback.
     *
     * Safety
     *
     * `out_capabilities` must point at a `sipral_capabilities_t` whose
     * `size` member says how long it is.
     */
    fun capabilities(): SipralCapabilities {
        val capabilitiesSlots = LongArray(SipralCapabilities.SLOTS)
        check(SipralNative.sipral_capabilities(capabilitiesSlots))
        return SipralCapabilities.of(capabilitiesSlots)
    }

    /**
     * Create a stack, and write its handle to `out_stack`.
     *
     * The handle is written only on `SIPRAL_STATUS_OK` and must be freed with
     * sipral_stack_destroy. A process holds 256 stacks; the next is
     * `SIPRAL_STATUS_EXHAUSTED` until one is destroyed and no poll still runs on it.
     *
     * Safety
     *
     * `config` must point at a `sipral_stack_config_t` whose `size` member
     * says how long it is, with every pointer in it readable for the length
     * beside it, and `out_stack` at one `sipral_handle_t`.
     */
    fun stackCreate(config: SipralStackConfig): Long {
        val configBindAddress = config.bindAddress?.toByteArray(Charsets.UTF_8)
        val configUserAgent = config.userAgent?.toByteArray(Charsets.UTF_8)
        val configCodecs = config.codecs?.toByteArray(Charsets.UTF_8)
        val configStunServer = config.stunServer?.toByteArray(Charsets.UTF_8)
        val configTurnServer = config.turnServer?.toByteArray(Charsets.UTF_8)
        val configTurnUsername = config.turnUsername?.toByteArray(Charsets.UTF_8)
        val configTurnPassword = config.turnPassword?.toByteArray(Charsets.UTF_8)
        val configStunFallbacks = config.stunFallbacks?.toByteArray(Charsets.UTF_8)
        val configSrtpSuites = config.srtpSuites?.toByteArray(Charsets.UTF_8)
        val stackSlot = LongArray(1)
        val configEventCallback = SipralEventListeners.register(config.eventListener)
        val configAudioTransmitCallback = SipralAudioTransmitListeners.register(config.audioTransmitListener)
        var status = -1
        try {
            status = SipralNative.sipral_stack_create(configEventCallback, config.transport, configBindAddress, configUserAgent, config.entropy, config.timerT1Ms, config.timerT2Ms, config.timerT4Ms, configCodecs, config.frameMs, config.offerDtmf, config.offerRtcpMux, config.silenceSuppression, config.mediaStallWatchdog, config.mediaStallMs, config.mediaClockUnixSeconds, config.mediaSeed, config.srtp, config.ice, config.nat, configStunServer, config.g729AnnexB, configTurnServer, configTurnUsername, configTurnPassword, config.referrals, config.registrarKeepalive, config.registrarKeepaliveMs, config.turnTransport, config.audio, config.audioActivation, configAudioTransmitCallback, config.audioProbeMs, config.audioDeviceRateHz, config.maxDialogs, config.maxServerTransactions, config.diagnosticDecisions, config.diagnosticRecords, config.dtmfDetection, configStunFallbacks, config.rtpPortMin, config.rtpPortMax, configSrtpSuites, config.pathMtu, config.datagramWithoutStreamBytes, config.pseudonymSalt, config.diagnosticTrace, config.reserved, config.systemEchoCancellation, config.reserved35, config.heldAudio, config.reserved36, stackSlot)
        } finally {
            SipralEventListeners.made(configEventCallback, status, stackSlot[0])
            SipralAudioTransmitListeners.made(configAudioTransmitCallback, status, stackSlot[0])
        }
        check(status)
        return stackSlot[0]
    }

    /**
     * Read back what a stack is running with, defaults filled in.
     *
     * Safety
     *
     * `out_settings` must point at a `sipral_stack_settings_t` whose `size`
     * member says how long it is.
     */
    fun stackSettings(stack: Long): SipralStackSettings {
        val settingsSlots = LongArray(SipralStackSettings.SLOTS)
        check(SipralNative.sipral_stack_settings(stack, settingsSlots))
        return SipralStackSettings.of(settingsSlots)
    }

    /**
     * Destroy a stack. The handle is dead on return; a second destroy is
     * `SIPRAL_STATUS_STALE_HANDLE`. Safe inside the callback. Inside a frame of one
     * of its calls it is `SIPRAL_STATUS_BUSY`. Nothing is sent: hang up, unmap and
     * send what `sipral_stack_poll_farewell` and `sipral_stack_poll_stun` give
     * first, or TURN relays linger up to ten minutes.
     *
     * Safety
     *
     * Safe to call with any handle value. Reads no memory the caller owns.
     */
    fun stackDestroy(stack: Long) {
        val status = SipralNative.sipral_stack_destroy(stack)
        SipralEventListeners.gone(stack)
        SipralAudioTransmitListeners.gone(stack)
        SipralScreenListeners.gone(stack)
        SipralLogListeners.gone(stack)
        check(status)
    }

    /**
     * Let the stack do its work, and deliver what it has to say.
     *
     * `now_ms` is the caller's monotonic clock in milliseconds; more than fifty
     * behind is `SIPRAL_STATUS_CLOCK_BEHIND`. The callback runs inside this call,
     * on this thread, with nothing held. `result` may be null. Drain
     * `sipral_stack_poll_transmit` after every poll (`docs/08-ffi.md`).
     *
     * Safety
     *
     * `result` must be null or point at a `sipral_poll_result_t` whose `size`
     * member says how long it is.
     */
    fun stackPoll(stack: Long, nowMs: Long): SipralPollResult {
        val resultSlots = LongArray(SipralPollResult.SLOTS)
        check(SipralNative.sipral_stack_poll(stack, nowMs, resultSlots))
        return SipralPollResult.of(resultSlots)
    }

    /**
     * D3's health counters for one stack, since it was created.
     * One struct copy, cheap enough to sample on a timer.
     *
     * Safety
     *
     * `out_counters` must point at a `sipral_counters_t` whose `size` member
     * says how long it is.
     */
    fun stackCounters(stack: Long): SipralCounters {
        val countersSlots = LongArray(SipralCounters.SLOTS)
        check(SipralNative.sipral_stack_counters(stack, countersSlots))
        return SipralCounters.of(countersSlots)
    }

    /**
     * Install, replace, or remove the screening policy for one stack.
     *
     * Every INVITE that passes sipral_stack_invite_limit reaches this
     * callback before ringing, before `SIPRAL_EVENT_KIND_INCOMING_CALL` and
     * before a call handle exists. A refused INVITE gets the named status
     * (500 if it does not refuse) and is forgotten: no event, no handle. One
     * answered `SIPRAL_SCREEN_ACCEPT` arrives as with no policy.
     *
     * `NULL` removes the policy. A second call replaces the first, on this
     * stack only.
     *
     * The no re-entry and no unwind rules are on SipralScreenCallback.
     *
     * Safety
     *
     * `callback`, when not null, is called on whichever thread is feeding
     * this stack bytes, while the policy is installed. `user_data` is handed
     * back untouched and never read here.
     *
     * **`user_data` must outlive the last call, which may come after
     * `sipral_stack_destroy` returns:** a receive already running on another
     * thread holds its own share of the stack and still asks the policy. Free
     * it once no thread is inside this stack. Replacing or removing the
     * policy takes the lock, so once it returns the old callback is not asked
     * again.
     */
    fun stackScreen(stack: Long, listener: SipralScreenListener?) {
        // held across the call so that what SipralScreenListeners records and what
        // the library installed cannot disagree
        synchronized(SipralScreenListeners) {
            val callback = SipralScreenListeners.register(listener)
            var status = -1
            try {
                status = SipralNative.sipral_stack_screen(stack, callback)
            } finally {
                SipralScreenListeners.installed(callback, status, stack)
            }
            check(status)
        }
    }

    /**
     * How fast one source address may offer this stack an INVITE (A8).
     *
     * `burst` calls from one address pass at once; one more is earned every
     * `every_ms` (see Rate). The default is ten, then one every 2000 ms;
     * loose because most legitimate calls come from the registrar's address.
     *
     * A zero `burst` or zero `every_ms` is `SIPRAL_STATUS_INVALID_ARGUMENT`
     * and changes nothing: one admits no call, the other never limits.
     *
     * The floor is checked before sipral_stack_screen's policy: a source
     * past it never reaches the callback and is counted in
     * `screened_refused_by_rate` or `screened_refused_by_crowding`.
     *
     * **It counts by source address.** An INVITE on a byte stream bound
     * without a far end has no address and always passes to the policy (where
     * SipralScreenRequest.source is null). Naming `remote` in
     * `sipral_stack_transport_bind` puts a stream under this floor.
     *
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun stackInviteLimit(stack: Long, everyMs: Long, burst: Long) {
        check(SipralNative.sipral_stack_invite_limit(stack, everyMs, burst))
    }

    /**
     * Watch something at the far end.
     *
     * One SUBSCRIBE is queued on `account`'s transport and address, and the
     * handle names the subscription until it ends.
     * `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` reports each step. It
     * refreshes and retries recoverable failures under the same handle;
     * sipral_subscription_end or an end with no retry finishes it.
     *
     * Safety
     *
     * `config` must point at a `sipral_subscribe_config_t` whose `size`
     * member says how long it is, with every pointer in it readable for the
     * length beside it. `out_subscription` must point at one
     * `sipral_handle_t`.
     */
    fun accountSubscribe(stack: Long, account: Long, config: SipralSubscribeConfig, nowMs: Long): Long {
        val configTarget = config.target?.toByteArray(Charsets.UTF_8)
        val configPackage = config.`package`?.toByteArray(Charsets.UTF_8)
        val configAccept = config.accept?.toByteArray(Charsets.UTF_8)
        val configDestination = config.destination?.toByteArray(Charsets.UTF_8)
        val subscriptionSlot = LongArray(1)
        check(SipralNative.sipral_account_subscribe(stack, account, configTarget, configPackage, configAccept, config.expiresSeconds, configDestination, config.transport, config.reserved, subscriptionSlot, nowMs))
        return subscriptionSlot[0]
    }

    /**
     * Give a subscription up with `Expires: 0` (§4.1.2.3).
     *
     * It stays live until the closing NOTIFY completes (§4.4.1);
     * `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` with
     * `SIPRAL_SUBSCRIPTION_END_UNSUBSCRIBED` says when. Without a dialog yet
     * it ends at once. The handle is usable until that event.
     *
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun subscriptionEnd(stack: Long, subscription: Long, nowMs: Long) {
        check(SipralNative.sipral_subscription_end(stack, subscription, nowMs))
    }

    /**
     * Where a subscription is, without waiting for its next event.
     * SipralSubscriptionState.UNKNOWN, with `SIPRAL_STATUS_OK`, for a
     * handle that names nothing, as an ended one does.
     *
     * Safety
     *
     * `out_state` must point at one `uint32_t`.
     */
    fun subscriptionState(stack: Long, subscription: Long): Long {
        val stateSlot = LongArray(1)
        check(SipralNative.sipral_subscription_state(stack, subscription, stateSlot))
        return stateSlot[0]
    }

    /**
     * What a lamp for this subscription should show: RFC 4235 §3.7.2's
     * virtual state machine over every known dialog, ringing beating
     * settled, SipralDialogPhase.IDLE once all ended. The dialog
     * functions below give the detail.
     *
     * `SIPRAL_STATUS_NOT_SUPPORTED` for a subscription with no dialog state:
     * another package, or not live (its last notification is stale).
     *
     * Safety
     *
     * `out_phase` must point at one `uint32_t`.
     */
    fun subscriptionLamp(stack: Long, subscription: Long): Long {
        val phaseSlot = LongArray(1)
        check(SipralNative.sipral_subscription_lamp(stack, subscription, phaseSlot))
        return phaseSlot[0]
    }

    /**
     * How many dialogs this subscription has been told about, in order first
     * heard. Indexes hold only until the next notification, which drops
     * ended dialogs; read again on each
     * SIPRAL_EVENT_KIND_NOTIFIED.
     *
     * Safety
     *
     * `out_count` must point at one `size_t`.
     */
    fun subscriptionDialogCount(stack: Long, subscription: Long): Long {
        val countSlot = LongArray(1)
        check(SipralNative.sipral_subscription_dialog_count(stack, subscription, countSlot))
        return countSlot[0]
    }

    /**
     * One of them, by index.
     *
     * Safety
     *
     * `out_dialog` must point at a `sipral_watched_dialog_t` whose `size`
     * member says how long it is.
     */
    fun subscriptionDialogAt(stack: Long, subscription: Long, index: Long): SipralWatchedDialog {
        val dialogSlots = LongArray(SipralWatchedDialog.SLOTS)
        check(SipralNative.sipral_subscription_dialog_at(stack, subscription, index, dialogSlots))
        return SipralWatchedDialog.of(dialogSlots)
    }

    /**
     * A piece of text about one of them, copied into the caller's buffer.
     *
     * `out_needed` always receives the size with the trailing NUL; ask with
     * `capacity` zero, then with room. Too small a buffer is
     * `SIPRAL_STATUS_BUFFER_TOO_SMALL`, nothing written. A piece the notifier
     * did not send is just the NUL.
     *
     * Safety
     *
     * `buffer` must be writable for `capacity` bytes or be null with a
     * capacity of zero, and `out_needed` must point at one `size_t` or be
     * null.
     */
    fun subscriptionDialogText(stack: Long, subscription: Long, index: Long, which: Long, buffer: ByteArray): Long {
        val neededSlot = LongArray(1)
        check(SipralNative.sipral_subscription_dialog_text(stack, subscription, index, which, buffer, neededSlot))
        return neededSlot[0]
    }

    /**
     * Send an instant message outside any dialog (RFC 3428 §3).
     *
     * The handle written back names the send until
     * `SIPRAL_EVENT_KIND_MESSAGE_SENT` reports its outcome, even a transport
     * failure. `body` is taken as raw bytes.
     *
     * Safety
     *
     * `target` and `content_type` must be readable for their lengths, and
     * UTF-8. `body` must be readable for `body_len` bytes, or null with a
     * length of zero. `out_message` must point at one `sipral_handle_t`.
     */
    fun accountMessage(stack: Long, account: Long, target: String, contentType: String, body: ByteArray, nowMs: Long): Long {
        val targetBytes = target.toByteArray(Charsets.UTF_8)
        val contentTypeBytes = contentType.toByteArray(Charsets.UTF_8)
        val messageSlot = LongArray(1)
        check(SipralNative.sipral_account_message(stack, account, targetBytes, contentTypeBytes, body, messageSlot, nowMs))
        return messageSlot[0]
    }

    /**
     * A call is expected on this account, announced by a push (C2).
     *
     * `caller` is the SIP URI the push named. The binding is refreshed at
     * once (§4.1.3); with no transport bound yet, the REGISTER goes when one
     * is. Without a registrar, only the matching happens.
     *
     * Exactly one of the two outputs names something:
     *
     * - `out_announcement` when nothing arrived yet. The matching INVITE
     *   raises `SIPRAL_EVENT_KIND_CALL_ANNOUNCED` right before its
     *   `SIPRAL_EVENT_KIND_INCOMING_CALL`, or
     *   `SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING` if none comes.
     * - `out_call` when the INVITE beat the push. If the incoming-call event
     *   was already delivered, this is the only report of the match.
     *
     * Safety
     *
     * `caller` must be readable for `caller_len` bytes, and each of
     * `out_announcement` and `out_call` must point at one `sipral_handle_t`.
     */
    fun accountAnnounce(stack: Long, account: Long, caller: String, nowMs: Long): Pair<Long, Long> {
        val callerBytes = caller.toByteArray(Charsets.UTF_8)
        val announcementSlot = LongArray(1)
        val callSlot = LongArray(1)
        check(SipralNative.sipral_account_announce(stack, account, callerBytes, announcementSlot, callSlot, nowMs))
        return Pair(announcementSlot[0], callSlot[0])
    }

    /**
     * Refresh the binding now, without announcing anything (C3).
     *
     * For a proxy's periodic wake-up (RFC 8599 §5.5). A push proves the path
     * works, so any back-off from an earlier outage is dropped.
     *
     * `SIPRAL_STATUS_OK` without sending when a REGISTER is in flight or the
     * failure is permanent (retrying a refused password locks accounts out).
     * `SIPRAL_STATUS_INVALID_ARGUMENT` for an account that never registers.
     * With no transport bound yet the failure is reported, and the refresh
     * goes out once one is.
     *
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun accountRefreshBinding(stack: Long, account: Long, nowMs: Long) {
        check(SipralNative.sipral_account_refresh_binding(stack, account, nowMs))
    }

    /**
     * Stop expecting an announced call. `SIPRAL_STATUS_WRONG_STATE` when it
     * was already fulfilled or expired; the event and this call can cross.
     *
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun announcementForget(stack: Long, announcement: Long) {
        check(SipralNative.sipral_announcement_forget(stack, announcement))
    }

    /**
     * What the registrar said about push in its 2xx to REGISTER.
     * `SIPRAL_STATUS_NOT_SUPPORTED` when the account did not ask for push or
     * has no standing binding.
     *
     * Safety
     *
     * `out_echo` must point at a `sipral_push_echo_t` whose `size` member
     * says how long it is.
     */
    fun accountPushEcho(stack: Long, account: Long): SipralPushEcho {
        val echoSlots = LongArray(SipralPushEcho.SLOTS)
        check(SipralNative.sipral_account_push_echo(stack, account, echoSlots))
        return SipralPushEcho.of(echoSlots)
    }

    /**
     * Configure an account and write its handle to `out_account`. Nothing is
     * sent. It lives until sipral_account_remove or the stack's end.
     *
     * Safety
     *
     * `config` must point at a `sipral_account_config_t` whose `size` member
     * says how long it is, with every pointer in it readable for the length
     * beside it, and `out_account` at one `sipral_handle_t`.
     */
    fun accountAdd(stack: Long, config: SipralAccountConfig): Long {
        val configAor = config.aor?.toByteArray(Charsets.UTF_8)
        val configRegistrar = config.registrar?.toByteArray(Charsets.UTF_8)
        val configContact = config.contact?.toByteArray(Charsets.UTF_8)
        val configRegistrarAddress = config.registrarAddress?.toByteArray(Charsets.UTF_8)
        val configDisplayName = config.displayName?.toByteArray(Charsets.UTF_8)
        val configAuthUser = config.authUser?.toByteArray(Charsets.UTF_8)
        val configAuthPassword = config.authPassword?.toByteArray(Charsets.UTF_8)
        val configInstanceId = config.instanceId?.toByteArray(Charsets.UTF_8)
        val (configHeadersBytes, configHeadersLengths) = SipralHeader.packed(config.headers)
        val configPushProvider = config.pushProvider?.toByteArray(Charsets.UTF_8)
        val configPushPrid = config.pushPrid?.toByteArray(Charsets.UTF_8)
        val configPushParam = config.pushParam?.toByteArray(Charsets.UTF_8)
        val configQualityReportUri = config.qualityReportUri?.toByteArray(Charsets.UTF_8)
        val configTrustedPeers = config.trustedPeers?.toByteArray(Charsets.UTF_8)
        val configSrtpSuites = config.srtpSuites?.toByteArray(Charsets.UTF_8)
        val configStirCertificateUrl = config.stirCertificateUrl?.toByteArray(Charsets.UTF_8)
        val configStirOrig = config.stirOrig?.toByteArray(Charsets.UTF_8)
        val configStirOrigid = config.stirOrigid?.toByteArray(Charsets.UTF_8)
        val configServerUri = config.serverUri?.toByteArray(Charsets.UTF_8)
        val configTlsPinSha256 = config.tlsPinSha256?.toByteArray(Charsets.UTF_8)
        val configRealms = config.realms?.toByteArray(Charsets.UTF_8)
        val configWebsocketHost = config.websocketHost?.toByteArray(Charsets.UTF_8)
        val configWebsocketResource = config.websocketResource?.toByteArray(Charsets.UTF_8)
        val accountSlot = LongArray(1)
        check(SipralNative.sipral_account_add(stack, configAor, configRegistrar, configContact, configRegistrarAddress, configDisplayName, configAuthUser, configAuthPassword, configInstanceId, config.expiresSeconds, configHeadersBytes, configHeadersLengths, config.transport, configPushProvider, configPushPrid, configPushParam, config.pushWakesItself, configQualityReportUri, config.sessionTimer, config.sessionIntervalSeconds, config.privacy, configTrustedPeers, config.srtp, configSrtpSuites, config.stirVerification, config.stirKey, configStirCertificateUrl, configStirOrig, configStirOrigid, config.stirAttestation, config.recordingInClear, config.keepaliveMs, configServerUri, configTlsPinSha256, config.serverNaptr, config.reserved, config.streamProtocol, config.reserved35, configRealms, configWebsocketHost, configWebsocketResource, accountSlot))
        return accountSlot[0]
    }

    /**
     * Forget an account and everything scheduled for it. Nothing is sent: its
     * registrar may be unreachable. Call sipral_account_unregister first
     * to give the binding up.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun accountRemove(stack: Long, account: Long) {
        check(SipralNative.sipral_account_remove(stack, account))
    }

    /**
     * Register, and keep the binding alive until told otherwise.
     *
     * Refreshes, credential retries and back-off happen on their own until
     * sipral_account_unregister or a refusal retrying cannot fix. Each
     * step arrives as `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED`. An account
     * with no registrar gets `SIPRAL_STATUS_INVALID_ARGUMENT`, nothing sent.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun accountRegister(stack: Long, account: Long, nowMs: Long) {
        check(SipralNative.sipral_account_register(stack, account, nowMs))
    }

    /**
     * Give the binding up: a REGISTER with `Expires: 0` (§10.2.2).
     *
     * Only this device's binding: `Contact: *` would remove every binding of
     * the address of record. An account with no registrar is refused as
     * `sipral_account_register` refuses it.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun accountUnregister(stack: Long, account: Long, nowMs: Long) {
        check(SipralNative.sipral_account_unregister(stack, account, nowMs))
    }

    /**
     * Where an account's registration is, as a `SipralRegistrationState`;
     * always `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING` with no registrar.
     *
     * Safety
     *
     * `out_state` must point at one `uint32_t`.
     */
    fun accountRegistrationState(stack: Long, account: Long): Long {
        val stateSlot = LongArray(1)
        check(SipralNative.sipral_account_registration_state(stack, account, stateSlot))
        return stateSlot[0]
    }

    /**
     * Give an account the OAuth 2.0 access token its server asked for
     * (RFC 8898), replacing any it had. A `token_len` of zero removes it; a
     * password stays.
     *
     * Answers `SIPRAL_EVENT_KIND_TOKEN_REQUIRED`, or renews ahead of expiry.
     * From the next request, a `Bearer` challenge from the account's own
     * server (and every request its cached challenge covers) gets
     * `Authorization: Bearer <token>` (RFC 6750 §2.1); with `Digest` and
     * `Bearer` offered for one realm, the token answers. A refused token is
     * never resent. Nothing is sent now; a registration that failed for want
     * of a token restarts with `sipral_account_register`.
     *
     * The application fetches tokens. The token is copied, kept out of logs
     * and diagnostics, and wiped when replaced. A token that is not RFC 6750
     * §2.1's `b64token` is `SIPRAL_STATUS_INVALID_ARGUMENT`, nothing changed,
     * the error not describing it.
     *
     * Safety
     *
     * `token` must be readable for `token_len` bytes, or be null with a
     * length of zero.
     */
    fun accountSetAccessToken(stack: Long, account: Long, token: String) {
        val tokenBytes = token.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_account_set_access_token(stack, account, tokenBytes))
    }

    /**
     * Test the network before a call: STUN, TURN, the account's server and,
     * with an echo call, the audio path (ABI 1.2). The result arrives from a
     * later `sipral_stack_poll` as `SIPRAL_EVENT_KIND_NETWORK_TEST` carrying
     * `*out_test`. Tests may run side by side.
     *
     * `SIPRAL_STATUS_WRONG_STATE` for a `probe_socket` without a STUN server
     * or an account not located yet; `SIPRAL_STATUS_INVALID_ARGUMENT` for a
     * `probe_socket` that is not an address or is a signalling socket.
     * Nothing starts when anything is refused.
     *
     * Safety
     *
     * `config` must point at a `sipral_network_test_config_t` whose `size`
     * member says how long it is, with `probe_socket` readable for
     * `probe_socket_len` bytes; `out_test` must point at one `uint32_t`.
     */
    fun stackNetworkTest(stack: Long, config: SipralNetworkTestConfig, nowMs: Long): Long {
        val configProbeSocket = config.probeSocket?.toByteArray(Charsets.UTF_8)
        val testSlot = LongArray(1)
        check(SipralNative.sipral_stack_network_test(stack, config.account, configProbeSocket, config.echoCall, config.echoMs, config.timeoutMs, nowMs, testSlot))
        return testSlot[0]
    }

    /**
     * Place a call, and write its handle to `out_call`.
     *
     * The handle exists before any dialog, so the INVITE can be hung up while in flight.
     * Branches a proxy forks get their own handles (`SIPRAL_EVENT_KIND_CALL_FORKED`).
     *
     * With `media_address` set the stack writes the offer and runs the audio:
     * `SIPRAL_EVENT_KIND_MEDIA_STARTED` says when, and `sipral_media_*` carry the packets.
     *
     * Safety
     *
     * `config` must point at a `sipral_call_config_t` whose `size` member says how long it is,
     * with every pointer in it readable for the length beside it, and `out_call` at one
     * `sipral_handle_t`.
     */
    fun callPlace(stack: Long, account: Long, config: SipralCallConfig, nowMs: Long): Long {
        val configTarget = config.target?.toByteArray(Charsets.UTF_8)
        val configDestination = config.destination?.toByteArray(Charsets.UTF_8)
        val configMediaAddress = config.mediaAddress?.toByteArray(Charsets.UTF_8)
        val (configHeadersBytes, configHeadersLengths) = SipralHeader.packed(config.headers)
        val configCodecs = config.codecs?.toByteArray(Charsets.UTF_8)
        val configTextAddress = config.textAddress?.toByteArray(Charsets.UTF_8)
        val callSlot = LongArray(1)
        check(SipralNative.sipral_call_place(stack, account, configTarget, config.sdp, configDestination, config.keepAllForks, configMediaAddress, configHeadersBytes, configHeadersLengths, config.srtp, config.transport, configCodecs, config.ice, configTextAddress, config.feedback, config.focus, config.followRedirects, config.reserved, callSlot, nowMs))
        return callSlot[0]
    }

    /**
     * Say a call that came in is ringing.
     *
     * A description makes it a 183 rather than a 180, since a 180 with a body is ambiguous.
     *
     * Safety
     *
     * `sdp` must be null or readable for `sdp_len` bytes.
     */
    fun callRing(stack: Long, call: Long, sdp: ByteArray, nowMs: Long) {
        check(SipralNative.sipral_call_ring(stack, call, sdp, nowMs))
    }

    /**
     * Say a call that came in is ringing, with this stack running the audio before anybody
     * answers.
     *
     * The answer to the INVITE's offer is written from this stack's codec order against
     * `config.media_address`, and the session opens at once: the far end hears what the
     * application plays. `SIPRAL_EVENT_KIND_MEDIA_STARTED` follows. `config.srtp` and
     * `config.codecs` override the stack's for this call, and `sipral_call_answer_media` keeps
     * what was settled here; it is the only way an incoming call chooses its own SRTP policy.
     *
     * `sipral_call_answer_media` then reuses this session and description. What its 200 OK
     * carries follows RFC 3262 §5 and RFC 6337 §3.1.1, by whether the 183 went out reliably
     * (`docs/05-media.md`, "Ringing with media").
     *
     * Setting `target`, `sdp`, `destination`, `transport`, `keep_all_forks` or `headers` is
     * `SIPRAL_STATUS_INVALID_ARGUMENT` naming it. `SIPRAL_STATUS_WRONG_STATE`, with nothing
     * sent: an INVITE with no offer (RFC 3261 §13.2.1, RFC 6337 §3.1.2); a second call of this;
     * a call after a `sipral_call_ring` that sent the application's own description
     * (RFC 3261 §13.2.1, RFC 6337 §3.1.1).
     *
     * Safety
     *
     * `config` must point at a `sipral_call_config_t` whose `size` member says how long it is,
     * with `media_address` readable for `media_address_len` bytes.
     */
    fun callRingMedia(stack: Long, call: Long, config: SipralCallConfig, nowMs: Long) {
        val configTarget = config.target?.toByteArray(Charsets.UTF_8)
        val configDestination = config.destination?.toByteArray(Charsets.UTF_8)
        val configMediaAddress = config.mediaAddress?.toByteArray(Charsets.UTF_8)
        val (configHeadersBytes, configHeadersLengths) = SipralHeader.packed(config.headers)
        val configCodecs = config.codecs?.toByteArray(Charsets.UTF_8)
        val configTextAddress = config.textAddress?.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_call_ring_media(stack, call, configTarget, config.sdp, configDestination, config.keepAllForks, configMediaAddress, configHeadersBytes, configHeadersLengths, config.srtp, config.transport, configCodecs, config.ice, configTextAddress, config.feedback, config.focus, config.followRedirects, config.reserved, nowMs))
    }

    /**
     * Answer a call that came in with `sdp`, the answer to the INVITE's offer (required).
     *
     * Safety
     *
     * `sdp` must be readable for `sdp_len` bytes.
     */
    fun callAnswer(stack: Long, call: Long, sdp: ByteArray, nowMs: Long) {
        check(SipralNative.sipral_call_answer(stack, call, sdp, nowMs))
    }

    /**
     * Answer a call that came in, and let this stack run its audio.
     *
     * The answer is written from this stack's codec order against `media_address`.
     * `SIPRAL_EVENT_KIND_MEDIA_STARTED` follows once the stream is open.
     *
     * On a call `sipral_call_ring_media` already rang, the 183's description and session
     * stand and `media_address` must still parse but is unused. The 200 OK repeats that
     * description if the 183 went unreliably and carries none if reliably (RFC 6337 §3.1.1).
     *
     * Safety
     *
     * `media_address` must be readable for `media_address_len` bytes.
     */
    fun callAnswerMedia(stack: Long, call: Long, mediaAddress: String, nowMs: Long) {
        val mediaAddressBytes = mediaAddress.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_call_answer_media(stack, call, mediaAddressBytes, nowMs))
    }

    /**
     * Answer a call that came in with media this stack describes, from `config`:
     * `sipral_call_answer_media` with the members `sipral_call_ring_media` reads. Any other
     * member set is `SIPRAL_STATUS_INVALID_ARGUMENT` naming it. On a call already rung with
     * media, only `focus` changes anything.
     *
     * Safety
     *
     * `config` must point at a `sipral_call_config_t` whose `size` member says how long it is,
     * with every pointer in it readable for the length beside it.
     */
    fun callAnswerWith(stack: Long, call: Long, config: SipralCallConfig, nowMs: Long) {
        val configTarget = config.target?.toByteArray(Charsets.UTF_8)
        val configDestination = config.destination?.toByteArray(Charsets.UTF_8)
        val configMediaAddress = config.mediaAddress?.toByteArray(Charsets.UTF_8)
        val (configHeadersBytes, configHeadersLengths) = SipralHeader.packed(config.headers)
        val configCodecs = config.codecs?.toByteArray(Charsets.UTF_8)
        val configTextAddress = config.textAddress?.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_call_answer_with(stack, call, configTarget, config.sdp, configDestination, config.keepAllForks, configMediaAddress, configHeadersBytes, configHeadersLengths, config.srtp, config.transport, configCodecs, config.ice, configTextAddress, config.feedback, config.focus, config.followRedirects, config.reserved, nowMs))
    }

    /**
     * Refuse a call that came in with a response code of your choosing: 486 for a line in use,
     * 603 for a person who declines. A proxy acts differently on each.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callReject(stack: Long, call: Long, code: Long, nowMs: Long) {
        check(SipralNative.sipral_call_reject(stack, call, code, nowMs))
    }

    /**
     * Hang up, whatever the call is doing: CANCEL before an answer, BYE after, a refusal for
     * an unanswered incoming call. A call already ending is left alone.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callHangup(stack: Long, call: Long, nowMs: Long) {
        check(SipralNative.sipral_call_hangup(stack, call, nowMs))
    }

    /**
     * Set the header fields that go on what this call sends at the application's request,
     * until set again.
     *
     * They go on the responses of `sipral_call_ring`, `sipral_call_answer`,
     * `sipral_call_answer_media` and `sipral_call_reject`, the refusal or BYE of
     * `sipral_call_hangup`, and the re-INVITE or UPDATE of `sipral_call_hold` and
     * `sipral_call_resume`. Kept across them. Never on a CANCEL (a proxy replaces it) or on
     * what the stack sends by itself.
     *
     * Replaces the previous set whole; `headers_len` zero clears it. Each field is checked as
     * on `sipral_call_config_t::headers`; a refusal names the element and keeps the old set.
     *
     * Safety
     *
     * `headers` must be null with `headers_len` zero, or readable for `headers_len` elements,
     * each with a name and a value readable for the lengths beside them.
     */
    fun callSetHeaders(stack: Long, call: Long, headers: List<SipralHeader>) {
        val (headersBytes, headersLengths) = SipralHeader.packed(headers)
        check(SipralNative.sipral_call_set_headers(stack, call, headersBytes, headersLengths))
    }

    /**
     * Put a call on hold (RFC 3264 §8.4).
     *
     * The stack writes the description: the negotiated one with every direction changed. A
     * hold already in place or on its way sends nothing and succeeds.
     *
     * While another session change runs, it succeeds and waits until that is over
     * (RFC 3261 §14.1); the outcome arrives as `SIPRAL_EVENT_KIND_SESSION_CHANGED` or
     * `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED`. Only the last state asked for waits, so a
     * resume asked for while a hold is still on its way goes after it. One still waiting
     * when the call ends is never sent.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callHold(stack: Long, call: Long, nowMs: Long) {
        check(SipralNative.sipral_call_hold(stack, call, nowMs))
    }

    /**
     * Take it off hold. Each stream returns to its previous direction (a receive-only one stays
     * receive-only), and waits for a running change as `sipral_call_hold` does.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callResume(stack: Long, call: Long, nowMs: Long) {
        check(SipralNative.sipral_call_resume(stack, call, nowMs))
    }

    /**
     * Offer a call again on another list of codecs (RFC 3264 §8.3.2).
     *
     * `codecs` is as `sipral_call_config_t::codecs`. Only the codecs change: address, keys,
     * fingerprint and ICE credentials are offered as they are, and a held call stays held. A
     * dynamic payload type keeps its codec; a new codec gets an unused number.
     *
     * The list becomes the call's once accepted; `SIPRAL_EVENT_KIND_MEDIA_CHANGED` names the
     * codec settled on. A refusal arrives as `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED`.
     *
     * For a call placed or answered with `media_address`. `SIPRAL_STATUS_NOT_SUPPORTED`: a name
     * with no codec in this build. `SIPRAL_STATUS_INVALID_ARGUMENT`: an empty list, a repeated
     * name or a stray comma. `SIPRAL_STATUS_WRONG_STATE`: no stack-written description, none
     * agreed yet, a refused stream, an early call whose far end never listed UPDATE, or
     * another change on its way. `SIPRAL_STATUS_EXHAUSTED`: no dynamic payload type left.
     *
     * Safety
     *
     * `codecs` must be readable for `codecs_len` bytes.
     */
    fun callChangeCodecs(stack: Long, call: Long, codecs: String, nowMs: Long) {
        val codecsBytes = codecs.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_call_change_codecs(stack, call, codecsBytes, nowMs))
    }

    /**
     * Restart ICE on a call (RFC 8445 §9): offer it again with new credentials and check every
     * pair again once the far end answers.
     *
     * The last description is offered again with new `ice-ufrag` and `ice-pwd`
     * (RFC 8839 §4.4.1.1.1), the candidates still held, and the same role. Nothing reaches the
     * agent until the far end accepts (§4.4). The old pair carries audio meanwhile, and the new
     * selection arrives as `SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN`. A refusal arrives as
     * `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED` and leaves ICE as it was.
     *
     * The remedy for lost consent (`SIPRAL_MEDIA_FAULT_ICE`) and a local network change. For a
     * call placed or answered with `media_address`. `SIPRAL_STATUS_WRONG_STATE`: no
     * stack-written description, no ICE agent, no description yet, or another change on its
     * way. `SIPRAL_STATUS_NOT_SUPPORTED` from a build without ICE.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callRestartIce(stack: Long, call: Long, nowMs: Long) {
        check(SipralNative.sipral_call_restart_ice(stack, call, nowMs))
    }

    /**
     * Describe a call's media at a socket the application bound on a new network and offer it
     * to the far end (RFC 3264 §8.3.1), as `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED` asks.
     *
     * `media_address` is the new socket, `host:port`; `public_address` is where it appears
     * from outside, or null with length zero. The re-INVITE moves only `c=` and the `m=` port,
     * and carries the account's current `Contact`, so `sipral_account_rebind` goes first. The
     * new socket is the call's whatever the answer: `SIPRAL_EVENT_KIND_SESSION_CHANGED` and
     * `SIPRAL_EVENT_KIND_MEDIA_CHANGED`, or `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED`.
     *
     * For a call placed or answered with `media_address`. `SIPRAL_STATUS_WRONG_STATE`: no
     * stack-written description, a session running ICE (moved by a restart instead), no
     * description yet, or another change on its way.
     *
     * Safety
     *
     * `media_address` must be readable for `media_address_len` bytes, and `public_address` for
     * `public_address_len` bytes or null with a length of zero.
     */
    fun callMediaReaddress(stack: Long, call: Long, mediaAddress: String, publicAddress: String, nowMs: Long) {
        val mediaAddressBytes = mediaAddress.toByteArray(Charsets.UTF_8)
        val publicAddressBytes = publicAddress.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_call_media_readdress(stack, call, mediaAddressBytes, publicAddressBytes, nowMs))
    }

    /**
     * End a call and say why (RFC 3326): what `sipral_call_hangup` does, with
     * a `Reason` on the BYE or the CANCEL it turns into.
     *
     * `sip_cause` (SIP status) and `q850_cause` (Q.850) are each zero for none;
     * neither is a plain hangup. `text` goes on the first value written. On
     * refusing an unanswered incoming call only the Q.850 value goes
     * (RFC 6432).
     *
     * Safety
     *
     * `text` must be readable for `text_len` bytes or null with a length of
     * zero.
     */
    fun callHangupFor(stack: Long, call: Long, sipCause: Long, q850Cause: Long, text: String, nowMs: Long) {
        val textBytes = text.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_call_hangup_for(stack, call, sipCause, q850Cause, textBytes, nowMs))
    }

    /**
     * Answer a call that came in with a 3xx: somewhere else to try
     * (RFC 3261 §21.3), and why (RFC 5806).
     *
     * `status_code` is 300 to 399. `targets` is comma-separated URIs in
     * preference order, required except for 380. `reason`, when given, adds a
     * `Diversion` with that reason token naming the called address.
     * `SIPRAL_STATUS_INVALID_ARGUMENT` for a bad status or target;
     * `SIPRAL_STATUS_WRONG_STATE` for a call not waiting to be answered.
     *
     * Safety
     *
     * `targets` must be readable for `targets_len` bytes and `reason` for
     * `reason_len` bytes, each or null with a length of zero.
     */
    fun callRedirect(stack: Long, call: Long, statusCode: Long, targets: String, reason: String, nowMs: Long) {
        val targetsBytes = targets.toByteArray(Charsets.UTF_8)
        val reasonBytes = reason.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_call_redirect(stack, call, statusCode, targetsBytes, reasonBytes, nowMs))
    }

    /**
     * How many entries one of a call's identity lists has. Every piece of an
     * entry gives the same count. Read once from the INVITE; zero for a call
     * this end placed.
     *
     * Safety
     *
     * `out_count` must point at one `size_t`.
     */
    fun callIdentityCount(stack: Long, call: Long, which: Long): Long {
        val countSlot = LongArray(1)
        check(SipralNative.sipral_call_identity_count(stack, call, which, countSlot))
        return countSlot[0]
    }

    /**
     * One piece of one entry of a call's identity lists, copied into the
     * caller's buffer with a trailing NUL.
     *
     * `out_needed` always receives the bytes needed including the NUL; ask
     * with `capacity` zero, then again with room. Too small is
     * `SIPRAL_STATUS_BUFFER_TOO_SMALL` with nothing written. A missing piece
     * is just the NUL. An index past the end is `SIPRAL_STATUS_INVALID_ARGUMENT`.
     *
     * Safety
     *
     * `buffer` must be writable for `capacity` bytes or null with a capacity
     * of zero, and `out_needed` must point at one `size_t` or be null.
     */
    fun callIdentityText(stack: Long, call: Long, index: Long, which: Long, buffer: ByteArray): Long {
        val neededSlot = LongArray(1)
        check(SipralNative.sipral_call_identity_text(stack, call, index, which, buffer, neededSlot))
        return neededSlot[0]
    }

    /**
     * Join two active calls into a local three-way conference: each far end hears the other
     * and this end's microphone, mixed. sipral_media_mix
     * drives it one frame at a time; this only records the pairing.
     *
     * No SIP conference: neither far end is told. Both calls need running media and the same
     * sample rate and frame length, since nothing resamples.
     *
     * `SIPRAL_STATUS_INVALID_ARGUMENT` for `call_a == call_b`; `SIPRAL_STATUS_WRONG_STATE` for a
     * call with no running session, one already joined, or mismatched rate or frame length.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callJoin(stack: Long, callA: Long, callB: Long) {
        check(SipralNative.sipral_call_join(stack, callA, callB))
    }

    /**
     * Take `call` back out of its pair. Neither session is touched; each call carries its own
     * audio again. `SIPRAL_STATUS_WRONG_STATE` for a call not joined.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callLeave(stack: Long, call: Long) {
        check(SipralNative.sipral_call_leave(stack, call))
    }

    /**
     * Accept a change the far end offered (`SIPRAL_EVENT_KIND_SESSION_OFFERED`).
     *
     * `sdp`, the answer, is required (RFC 3264 §5): null or empty is
     * `SIPRAL_STATUS_INVALID_ARGUMENT` and the request still waits. An unanswered re-INVITE
     * ends the call, so this or sipral_call_reject_session must follow the event. An offer
     * in a PRACK (RFC 3262 §5) is answered the same way, in the PRACK's 2xx.
     *
     * Only for a call the application describes; a stack-described call answers its own
     * re-offers, so this is `SIPRAL_STATUS_WRONG_STATE` there.
     *
     * Safety
     *
     * `sdp` must be null or readable for `sdp_len` bytes.
     */
    fun callAcceptSession(stack: Long, call: Long, sdp: ByteArray, nowMs: Long) {
        check(SipralNative.sipral_call_accept_session(stack, call, sdp, nowMs))
    }

    /**
     * Refuse one instead; the session stands as it was (§14.1). 488 Not Acceptable Here says
     * the description was the problem. Only for a call the application describes.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callRejectSession(stack: Long, call: Long, code: Long, nowMs: Long) {
        check(SipralNative.sipral_call_reject_session(stack, call, code, nowMs))
    }

    /**
     * Send DTMF on a call that is up, in the form the far end takes.
     *
     * `digits` are `0`-`9`, `*`, `#` and `A`-`D`, the sixteen events of
     * RFC 4733 §3.2, in the order they were pressed. The whole string is checked first: one
     * bad character sends nothing. `duration_ms` is each tone's length, or zero for 100 ms.
     *
     * `via` is a SipralDtmf. `SIPRAL_DTMF_RTP` puts the digits in the media, replacing the
     * audio while they last, queued. The INFO forms send one request per digit, each after the
     * previous one's final answer, since UDP may reorder overlapping transactions. A refusal,
     * timeout or transport failure ends the sequence: `SIPRAL_EVENT_KIND_DTMF_SENT` names that
     * digit, and the rest are discarded unreported. Digits handed over meanwhile queue behind.
     * A call holds at most sixty-four INFO digits, the one in flight included; a string past
     * that is refused whole with `SIPRAL_STATUS_INVALID_ARGUMENT`.
     *
     * `SIPRAL_DTMF_RTP` without a negotiated telephone event writes the tones into the audio,
     * as `SIPRAL_DTMF_IN_BAND` always does. The media forms are `SIPRAL_STATUS_WRONG_STATE`
     * before there is media, the INFO forms before there is a dialog.
     *
     * Safety
     *
     * `digits` must be readable for `digits_len` bytes.
     */
    fun callSendDtmf(stack: Long, call: Long, digits: String, via: Long, durationMs: Long, nowMs: Long) {
        val digitsBytes = digits.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_call_send_dtmf(stack, call, digitsBytes, via, durationMs, nowMs))
    }

    /**
     * Ask the far end to call somebody else, and hang up when it has (RFC 3515).
     *
     * A blind transfer. This end stays in the call until the transfer succeeds, so a failed
     * transfer does not lose the call. Progress arrives as `SIPRAL_EVENT_KIND_TRANSFER_PROGRESS`,
     * then `SIPRAL_EVENT_KIND_TRANSFER_DONE`.
     *
     * Safety
     *
     * `target` must be readable for `target_len` bytes.
     */
    fun callTransfer(stack: Long, call: Long, target: String, nowMs: Long) {
        val targetBytes = target.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_call_transfer(stack, call, targetBytes, nowMs))
    }

    /**
     * Call the transfer target, and write the new call's handle to `out_consultation`.
     *
     * The consultation leg of an attended transfer; sipral_call_transfer_to follows.
     * Holding `call` first is the application's choice. `media_address` is
     * `SIPRAL_STATUS_NOT_SUPPORTED` here: place the consultation with `sdp` and run its audio.
     *
     * Safety
     *
     * As sipral_call_place.
     */
    fun callConsult(stack: Long, call: Long, config: SipralCallConfig, nowMs: Long): Long {
        val configTarget = config.target?.toByteArray(Charsets.UTF_8)
        val configDestination = config.destination?.toByteArray(Charsets.UTF_8)
        val configMediaAddress = config.mediaAddress?.toByteArray(Charsets.UTF_8)
        val (configHeadersBytes, configHeadersLengths) = SipralHeader.packed(config.headers)
        val configCodecs = config.codecs?.toByteArray(Charsets.UTF_8)
        val configTextAddress = config.textAddress?.toByteArray(Charsets.UTF_8)
        val consultationSlot = LongArray(1)
        check(SipralNative.sipral_call_consult(stack, call, configTarget, config.sdp, configDestination, config.keepAllForks, configMediaAddress, configHeadersBytes, configHeadersLengths, config.srtp, config.transport, configCodecs, config.ice, configTextAddress, config.feedback, config.focus, config.followRedirects, config.reserved, consultationSlot, nowMs))
        return consultationSlot[0]
    }

    /**
     * Hand `call` to the far end of `other` (RFC 3891): the attended half of a transfer, where
     * `other` is normally the consultation call. Any call that is up may be named.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callTransferTo(stack: Long, call: Long, other: Long, nowMs: Long) {
        check(SipralNative.sipral_call_transfer_to(stack, call, other, nowMs))
    }

    /**
     * Take a transfer that was asked for, place the call it names as sipral_call_place
     * does, and write its handle to `out_placed`.
     *
     * `config.target` set is `SIPRAL_STATUS_INVALID_ARGUMENT`: the REFER names the target.
     * Every other member means what it means on `sipral_call_place`. `Replaces` or
     * `Referred-By` among `headers` is `SIPRAL_STATUS_INVALID_ARGUMENT` with the transfer still
     * waiting: the INVITE takes both from the REFER. Neither `sdp` nor `media_address` is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`, as on `sipral_call_place`.
     *
     * `call` may be a referral's handle (`SIPRAL_EVENT_KIND_REFERRAL`, a REFER outside any
     * dialog), placed from the account the event names. Its handle is stale once the REFER is
     * answered; one refused before anything was sent is still there to take.
     *
     * A call that cannot be sent after the 202 ends the subscription with RFC 3515 §2.4.5's
     * 503, and this answers `SIPRAL_STATUS_NOT_SENT`.
     *
     * Safety
     *
     * `config` must point at a `sipral_call_config_t` whose `size` member says how long it is,
     * with every pointer in it readable for the length beside it, and `out_placed` at one
     * `sipral_handle_t`.
     */
    fun callAcceptTransfer(stack: Long, call: Long, config: SipralCallConfig, nowMs: Long): Long {
        val configTarget = config.target?.toByteArray(Charsets.UTF_8)
        val configDestination = config.destination?.toByteArray(Charsets.UTF_8)
        val configMediaAddress = config.mediaAddress?.toByteArray(Charsets.UTF_8)
        val (configHeadersBytes, configHeadersLengths) = SipralHeader.packed(config.headers)
        val configCodecs = config.codecs?.toByteArray(Charsets.UTF_8)
        val configTextAddress = config.textAddress?.toByteArray(Charsets.UTF_8)
        val placedSlot = LongArray(1)
        check(SipralNative.sipral_call_accept_transfer(stack, call, configTarget, config.sdp, configDestination, config.keepAllForks, configMediaAddress, configHeadersBytes, configHeadersLengths, config.srtp, config.transport, configCodecs, config.ice, configTextAddress, config.feedback, config.focus, config.followRedirects, config.reserved, placedSlot, nowMs))
        return placedSlot[0]
    }

    /**
     * Refuse one instead.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callRejectTransfer(stack: Long, call: Long, code: Long, nowMs: Long) {
        check(SipralNative.sipral_call_reject_transfer(stack, call, code, nowMs))
    }

    /**
     * Take a transfer asked for inside `call` with a call the application placed itself,
     * `placed`, and report that call's progress to the far end as if the REFER had placed it
     * (ABI 1.2).
     *
     * For an application that reaches the target its own way, such as a bridge. The REFER is
     * answered 202 (RFC 3515 §2.4.2); `placed` then reports each provisional status in a
     * NOTIFY (§2.4.5), and its final status ends the subscription (§2.4.7). A `placed` already
     * up is reported with a 200 at once. Ending `call` stays the application's.
     *
     * `SIPRAL_STATUS_WRONG_STATE` when nothing waits on `call` (a referral's handle included),
     * or `placed` is `call`, is over, or already reports to another REFER. A refusal leaves the
     * REFER waiting.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callAcceptTransferPlaced(stack: Long, call: Long, placed: Long, nowMs: Long) {
        check(SipralNative.sipral_call_accept_transfer_placed(stack, call, placed, nowMs))
    }

    /**
     * Where a call is, as a `SipralCallState`.
     *
     * A call that is over answers `SIPRAL_CALL_STATE_TERMINATED` until the poll delivering
     * `SIPRAL_EVENT_KIND_CALL_ENDED` retires its handle, then `SIPRAL_STATUS_STALE_HANDLE`. A
     * referral's handle is `SIPRAL_STATUS_WRONG_STATE`: there is no call yet.
     *
     * Safety
     *
     * `out_state` must point at one `uint32_t`.
     */
    fun callState(stack: Long, call: Long): Long {
        val stateSlot = LongArray(1)
        check(SipralNative.sipral_call_state(stack, call, stateSlot))
        return stateSlot[0]
    }

    /**
     * Which way a call is held: `out_here` when this end asked the far end to stop sending,
     * `out_there` when the far end asked. Either may be null.
     *
     * Safety
     *
     * `out_here` and `out_there` must each be null or point at one `uint32_t`.
     */
    fun callHoldState(stack: Long, call: Long): Pair<Long, Long> {
        val hereSlot = LongArray(1)
        val thereSlot = LongArray(1)
        check(SipralNative.sipral_call_hold_state(stack, call, hereSlot, thereSlot))
        return Pair(hereSlot[0], thereSlot[0])
    }

    /**
     * The name of a codec, as a static NUL-terminated string, or null for a
     * number this build has no codec for.
     *
     * Spelled as IANA registered it; L16 carries its rate (`L16/8000`,
     * `L16/16000`), as in a codec order. Owned by the library, valid while
     * it is loaded.
     *
     * Safety
     *
     * Reads no memory the caller owns, and is safe to call from any thread.
     */
    fun codecName(codec: Long): String? =
        SipralNative.sipral_codec_name(codec)

    /**
     * How many codecs this build contains, fixed at compile time.
     *
     * Safety
     *
     * `out_count` must point at one `size_t`.
     */
    fun codecCount(): Long {
        val countSlot = LongArray(1)
        check(SipralNative.sipral_codec_count(countSlot))
        return countSlot[0]
    }

    /**
     * One of them, by index, from zero to what `sipral_codec_count` said.
     *
     * In this build's preference order, the default offer; G.729 comes last
     * and is offered only when a codec order names it.
     *
     * Safety
     *
     * `out_info` must point at a `sipral_codec_info_t` whose `size` member
     * says how long it is.
     */
    fun codecAt(index: Long): SipralCodecInfo {
        val infoSlots = LongArray(SipralCodecInfo.SLOTS)
        check(SipralNative.sipral_codec_at(index, infoSlots))
        return SipralCodecInfo.of(infoSlots)
    }

    /**
     * The codecs this stack offers, in the order it offers them.
     *
     * What `sipral_stack_config_t::codecs` came to. `out_count` always gets
     * the total; a short buffer (or null with zero capacity) gets
     * `SIPRAL_STATUS_BUFFER_TOO_SMALL`.
     *
     * Safety
     *
     * `out_codecs` must be writable for `capacity` `uint32_t` or null with a
     * capacity of zero, and `out_count` must point at one `size_t` or be null.
     */
    fun stackCodecOrder(stack: Long, outCodecs: IntArray): Long {
        val countSlot = LongArray(1)
        check(SipralNative.sipral_stack_codec_order(stack, outCodecs, countSlot))
        return countSlot[0]
    }

    /**
     * A handle on one call's media, written to `out_media`.
     *
     * Mint it once negotiation settles (`SIPRAL_EVENT_KIND_MEDIA_STARTED`,
     * callback included) and pass it to every `sipral_media_` entry point.
     * None of those takes the stack's lock.
     *
     * `SIPRAL_STATUS_WRONG_STATE` for a call with no media. Written only on
     * `SIPRAL_STATUS_OK`.
     *
     * The handle outlives the call: after the call ends or the stack is
     * destroyed, media entry points answer `SIPRAL_STATUS_WRONG_STATE`. Hold,
     * resume and codec changes keep it valid. Each handle is released once with
     * `sipral_media_release`; asking twice gives two.
     *
     * Safety
     *
     * `out_media` must point at one `sipral_handle_t`.
     */
    fun callMedia(stack: Long, call: Long): Long {
        val mediaSlot = LongArray(1)
        check(SipralNative.sipral_call_media(stack, call, mediaSlot))
        return mediaSlot[0]
    }

    /**
     * Let a media handle go.
     *
     * Valid whether or not the call or stack still exists. The session is not
     * touched; releasing mid-call stops nothing. A second release is
     * `SIPRAL_STATUS_STALE_HANDLE`.
     *
     * Safety
     *
     * Safe to call with any handle value. Reads no memory the caller owns.
     */
    fun mediaRelease(media: Long) {
        val status = SipralNative.sipral_media_release(media)
        SipralProcessorListeners.gone(media)
        check(status)
    }

    /**
     * What one call's media settled on.
     *
     * Safety
     *
     * `out_info` must point at a `sipral_media_info_t` whose `size` member
     * says how long it is.
     */
    fun mediaInfo(media: Long): SipralMediaInfo {
        val infoSlots = LongArray(SipralMediaInfo.SLOTS)
        check(SipralNative.sipral_media_info(media, infoSlots))
        return SipralMediaInfo.of(infoSlots)
    }

    /**
     * How many codecs were in the running on this call.
     *
     * This call's catalogue: the stack's order unless
     * `sipral_call_config_t::codecs` named another. Zero is a valid answer.
     *
     * Safety
     *
     * `out_count` must point at one `size_t`.
     */
    fun mediaCodecCandidateCount(media: Long): Long {
        val countSlot = LongArray(1)
        check(SipralNative.sipral_media_codec_candidate_count(media, countSlot))
        return countSlot[0]
    }

    /**
     * One of them, by index, from zero to what
     * `sipral_media_codec_candidate_count` said, in this call's own order.
     *
     * An index past the end is `SIPRAL_STATUS_INVALID_ARGUMENT`.
     *
     * Safety
     *
     * `out_candidate` must point at a `sipral_codec_candidate_t` whose `size`
     * member says how long it is.
     */
    fun mediaCodecCandidateAt(media: Long, index: Long): SipralCodecCandidate {
        val candidateSlots = LongArray(SipralCodecCandidate.SLOTS)
        check(SipralNative.sipral_media_codec_candidate_at(media, index, candidateSlots))
        return SipralCodecCandidate.of(candidateSlots)
    }

    /**
     * How many paths this call's ICE agent tried: every candidate pair its
     * checklist held, then every relay it held.
     *
     * Zero for a call not using ICE. A restart (RFC 8445 §9) starts the list
     * again.
     *
     * Safety
     *
     * `out_count` must point at one `size_t`.
     */
    fun mediaPathCandidateCount(media: Long): Long {
        val countSlot = LongArray(1)
        check(SipralNative.sipral_media_path_candidate_count(media, countSlot))
        return countSlot[0]
    }

    /**
     * One of them, by index, from zero to what
     * `sipral_media_path_candidate_count` said: the pairs in the order the
     * checklist took them in, then the relays.
     *
     * An index past the end is `SIPRAL_STATUS_INVALID_ARGUMENT`; an address
     * buffer smaller than `SIPRAL_ADDRESS_BYTES` is
     * `SIPRAL_STATUS_BUFFER_TOO_SMALL`, before anything is written.
     *
     * Safety
     *
     * `out_candidate` must point at a `sipral_path_candidate_t` whose `size`
     * member says how long it is, and its two address buffers, when not
     * null, must be writable for the capacities beside them.
     */
    fun mediaPathCandidateAt(media: Long, index: Long, outCandidate: Long) {
        check(SipralNative.sipral_media_path_candidate_at(media, index, outCandidate))
    }

    /**
     * What one call's media has cost, and what it is costing now.
     *
     * `now_ms` is the caller's monotonic clock; it does not move the stack's
     * clock. The end-of-call record arrives as
     * `SIPRAL_EVENT_KIND_MEDIA_STATISTICS`; by then this answers
     * `SIPRAL_STATUS_WRONG_STATE`.
     *
     * Safety
     *
     * `out_stats` must point at a `sipral_stream_stats_t` whose `size` member
     * says how long it is.
     */
    fun mediaStatistics(media: Long, nowMs: Long): SipralStreamStats {
        val statsSlots = LongArray(SipralStreamStats.SLOTS)
        check(SipralNative.sipral_media_statistics(media, nowMs, statsSlots))
        return SipralStreamStats.of(statsSlots)
    }

    /**
     * Take a datagram off the media socket.
     *
     * RTP and RTCP are told apart by RFC 5761 §4, so either socket's traffic
     * goes here.
     *
     * `data` is decrypted in place; keep a copy if the ciphertext is needed.
     * `out_arrival` may be null. `now_ms` is the arrival time on the stack's
     * clock and moves nothing.
     *
     * Safety
     *
     * `data` must be readable and writable for `len` bytes, `from` readable
     * for `from_len`, and `out_arrival` must point at one `uint32_t` or be
     * null.
     */
    fun mediaReceive(media: Long, data: ByteArray, from: String, nowMs: Long): Long {
        val fromBytes = from.toByteArray(Charsets.UTF_8)
        val arrivalSlot = LongArray(1)
        check(SipralNative.sipral_media_receive(media, data, fromBytes, nowMs, arrivalSlot))
        return arrivalSlot[0]
    }

    /**
     * Take the frame that is due for the earpiece, and say where it came from.
     *
     * Exactly `sipral_media_info_t::frame_samples` samples are written, and a
     * smaller buffer is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with the number
     * needed in `out_written`. Every source fills the whole frame, silence
     * included.
     *
     * Safety
     *
     * `samples` must be writable for `capacity` `int16_t`, `out_written` must
     * point at one `size_t` or be null, and `out_source` at one `uint32_t` or
     * be null.
     */
    fun mediaPlayback(media: Long, samples: ShortArray): Pair<Long, Long> {
        val writtenSlot = LongArray(1)
        val sourceSlot = LongArray(1)
        check(SipralNative.sipral_media_playback(media, samples, writtenSlot, sourceSlot))
        return Pair(writtenSlot[0], sourceSlot[0])
    }

    /**
     * Put one frame from the microphone on the wire.
     *
     * `sample_count` must equal `sipral_media_info_t::frame_samples`.
     *
     * A packet `len` of zero means the frame was deliberately not sent: held
     * by the far end, suppressed as silence, or ICE has no path yet. The RTP
     * timestamp still advances in the first two cases (RFC 3550 §5.1); in the
     * third nothing is encoded. While this end holds the far end, silence
     * goes out instead of the microphone.
     *
     * `now_ms` moves nothing; it tells ICE traffic went out on the chosen pair
     * (RFC 8445 §11 keepalives).
     *
     * Safety
     *
     * `samples` must be readable for `sample_count` `int16_t`, and `packet`
     * must point at a `sipral_media_packet_t` whose `size` member says how
     * long it is and whose buffers are writable for the capacities beside
     * them.
     */
    fun mediaCapture(media: Long, nowMs: Long, samples: ShortArray, packet: Long) {
        check(SipralNative.sipral_media_capture(media, nowMs, samples, packet))
    }

    /**
     * Choose the rate this call's frames cross the boundary at in
     * application mode: what `sipral_media_playback` fills and what
     * `sipral_media_capture` takes, whatever rate the codec runs at.
     *
     * `hz` is 8000, 16000, 24000 or 48000; 0 (the start) is the codec's rate.
     * The frame keeps its duration (20 ms at 24 kHz is 480 samples), and
     * `sipral_media_info_t::sample_rate`/`frame_samples` follow at once. The
     * library resamples both ways and follows codec renegotiation; processors,
     * recordings and detectors stay at the codec's rate.
     *
     * Any other rate is `SIPRAL_STATUS_INVALID_ARGUMENT`, setting unchanged.
     * `SIPRAL_STATUS_WRONG_STATE` in device mode. `sipral_media_mix` refuses
     * a pair while either call has its own rate.
     *
     * Safety
     *
     * Reads no memory the caller owns.
     */
    fun mediaSetAppRate(media: Long, hz: Long) {
        check(SipralNative.sipral_media_set_app_rate(media, hz))
    }

    /**
     * Run `callback` over every captured frame, against the far-end audio
     * played a render delay earlier: the seam for echo cancellation, gain
     * control and noise suppression (`docs/05-media.md`).
     *
     * Replaces any previous processor and its learned state. Attaching
     * mid-call costs a fresh adaptation.
     *
     * **`callback` runs with this call's media locked**, unlike the event
     * callback: inside sipral_media_playback, inside
     * sipral_media_capture, and with SipralProcessorFrame's `reset`
     * set on a device or codec change, on the thread that called in. **From
     * inside it, call nothing on any media handle or this call's stack**:
     * such calls answer `SIPRAL_STATUS_BUSY`. This rules out two processors
     * deadlocking across calls. It must not unwind.
     *
     * `user_data` is handed back untouched and must outlive the last call,
     * which ends when `sipral_media_detach_processor` or
     * `sipral_media_release` returns.
     *
     * Safety
     *
     * `callback` is called on whichever thread calls
     * sipral_media_playback or sipral_media_capture on this call,
     * for as long as the processor stays attached, and `user_data` has to
     * outlive the last such call.
     */
    fun mediaAttachProcessor(media: Long, listener: SipralProcessorListener?) {
        // held across the call so that what SipralProcessorListeners records and what
        // the library installed cannot disagree
        synchronized(SipralProcessorListeners) {
            val callback = SipralProcessorListeners.register(listener)
            var status = -1
            try {
                status = SipralNative.sipral_media_attach_processor(media, callback)
            } finally {
                SipralProcessorListeners.installed(callback, status, media)
            }
            check(status)
        }
    }

    /**
     * Stop running the processor sipral_media_attach_processor attached,
     * if there was one.
     *
     * `out_was_attached`, when not null, gets 1 if one was detached, else 0.
     * Once this returns, `callback` is not called again and `user_data` may
     * be freed.
     *
     * Safety
     *
     * `out_was_attached` must point at one `uint32_t` or be null.
     */
    fun mediaDetachProcessor(media: Long): Long {
        val wasAttachedSlot = LongArray(1)
        check(SipralNative.sipral_media_detach_processor(media, wasAttachedSlot))
        return wasAttachedSlot[0]
    }

    /**
     * Forget the echo path, the noise floor and the gain the attached
     * processor has learned, keeping the processor itself attached.
     *
     * For a device change. Calls the sipral_media_attach_processor
     * callback with SipralProcessorFrame's `reset` set.
     *
     * `out_was_attached`, when not null, gets 1 if a processor exists, else 0.
     *
     * Safety
     *
     * `out_was_attached` must point at one `uint32_t` or be null.
     */
    fun mediaResetProcessor(media: Long): Long {
        val wasAttachedSlot = LongArray(1)
        check(SipralNative.sipral_media_reset_processor(media, wasAttachedSlot))
        return wasAttachedSlot[0]
    }

    /**
     * One frame of a two-call local conference: decode both far ends, mix
     * what each of the three parties is owed, and send the two far-end frames.
     *
     * `sipral_call_join` must already have paired the calls. Not checked here,
     * since that would take the stack's lock every frame.
     *
     * `mic` (`mic_count`) is this end's frame; `local` (`local_count`) gets
     * what this end's speaker is owed. Both are
     * `sipral_media_info_t::frame_samples`. `packet_a`/`packet_b` are filled
     * as by `sipral_media_capture`, each with `mic` mixed with the other far
     * end; recordings keep the same.
     *
     * Drive a joined pair from one thread. Concurrent mixes of the same pair
     * serialize without deadlock, but calling `sipral_media_playback` or
     * `sipral_media_capture` on either call meanwhile is a second driver.
     *
     * Safety
     *
     * `mic` must be readable for `mic_count` `int16_t` and `local` writable
     * for `local_count` `int16_t`, the two must not overlap, and
     * `packet_a` and `packet_b` must each point at a
     * `sipral_media_packet_t` as `sipral_media_capture` describes.
     */
    fun mediaMix(mediaA: Long, mediaB: Long, nowMs: Long, mic: ShortArray, local: ShortArray, packetA: Long, packetB: Long) {
        check(SipralNative.sipral_media_mix(mediaA, mediaB, nowMs, mic, local, packetA, packetB))
    }

    /**
     * The control traffic this call has due.
     *
     * A `len` of zero means nothing is due. RFC 3550 §6.3 decides when; at
     * most one report is due at a time.
     *
     * Call it after every outgoing frame, and at each `sipral_stack_poll`
     * deadline while not capturing. Always zero without negotiated RTCP.
     * `now_ms` moves nothing.
     *
     * Safety
     *
     * `packet` must point at a `sipral_media_packet_t` as
     * sipral_media_capture describes.
     */
    fun mediaPollRtcp(media: Long, nowMs: Long, packet: Long) {
        check(SipralNative.sipral_media_poll_rtcp(media, nowMs, packet))
    }

    /**
     * A datagram this call owes the far end that is neither audio nor a
     * report: DTLS-SRTP handshake records and ICE checks.
     *
     * A `len` of zero means nothing is due; always so on a call without a
     * handshake or ICE, at the cost of one comparison.
     *
     * **Drain it to empty** after every `sipral_media_receive` that answered
     * `SIPRAL_ARRIVAL_HANDSHAKE` and at every `sipral_stack_poll` deadline.
     * Otherwise the call connects, carries no audio, and reports nothing for
     * the two minutes until it gives up. `now_ms` moves nothing.
     *
     * Safety
     *
     * `packet` must point at a `sipral_media_packet_t` as
     * sipral_media_capture describes.
     */
    fun mediaPollTransmit(media: Long, nowMs: Long, packet: Long) {
        check(SipralNative.sipral_media_poll_transmit(media, nowMs, packet))
    }

    /**
     * The RTCP goodbye of a call whose media has ended.
     *
     * The RFC 3550 §6.3.7 BYE is built when the session stops, after the
     * media handle stops working, so it is polled from the stack.
     *
     * `out_call` gets the call it belonged to, or `SIPRAL_HANDLE_NONE` when
     * nothing was waiting. The call is over; the handle only says which media
     * socket to send from.
     *
     * One at a time: after each `sipral_stack_poll` that delivered
     * `SIPRAL_EVENT_KIND_CALL_ENDED`, call until `packet` has `len` zero.
     *
     * A TURN relay (`turn_server`) is given back here too: the zero-lifetime
     * Refresh of RFC 8656 §8, to the TURN server, from the same socket. It is
     * queued at call end, or earlier when the call does not use the relay, so
     * polling after every `sipral_stack_poll` releases it sooner.
     *
     * Safety
     *
     * `out_call` must point at one `sipral_handle_t`, and `packet` at a
     * `sipral_media_packet_t` as sipral_media_capture describes.
     */
    fun stackPollFarewell(stack: Long, packet: Long): Long {
        val callSlot = LongArray(1)
        check(SipralNative.sipral_stack_poll_farewell(stack, callSlot, packet))
        return callSlot[0]
    }

    /**
     * Whether a digit is going out or waiting to, and how many have not
     * started yet.
     *
     * Either out parameter may be null.
     *
     * Safety
     *
     * `out_dialling` must point at one `uint32_t` or be null, and
     * `out_waiting` at one `size_t` or be null.
     */
    fun mediaDialling(media: Long): Pair<Long, Long> {
        val diallingSlot = LongArray(1)
        val waitingSlot = LongArray(1)
        check(SipralNative.sipral_media_dialling(media, diallingSlot, waitingSlot))
        return Pair(diallingSlot[0], waitingSlot[0])
    }

    /**
     * Drop everything queued and stop the digit going out.
     *
     * The digit in flight gets no closing packet.
     *
     * Safety
     *
     * Reads no memory the caller owns.
     */
    fun mediaStopDialling(media: Long) {
        check(SipralNative.sipral_media_stop_dialling(media))
    }

    /**
     * Start recording this call to `path`: both directions mixed, as WAVE.
     * Each start makes a new file.
     *
     * `SIPRAL_STATUS_WRONG_STATE` when the media has ended or a recording is
     * already running. `SIPRAL_STATUS_INVALID_ARGUMENT` when the file system
     * refuses the path, with its reason in the last error. The file is created
     * with this call's media held, so only this call's audio waits on it.
     *
     * Safety
     *
     * `path` must be readable for `path_len` bytes.
     */
    fun mediaRecordStart(media: Long, path: String) {
        val pathBytes = path.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_media_record_start(media, pathBytes))
    }

    /**
     * Stop the recording and close the file.
     *
     * `SIPRAL_STATUS_WRONG_STATE` when nothing is being recorded. On failure
     * the file holds all the audio but zero header lengths.
     *
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun mediaRecordStop(media: Long) {
        check(SipralNative.sipral_media_record_stop(media))
    }

    /**
     * Whether a recording is running on this call, and how much audio it has
     * taken (audio only, not the header). Either out parameter may be null.
     *
     * Safety
     *
     * `out_recording` must point at one `uint32_t` or be null, and
     * `out_recorded_ms` at one `uint64_t` or be null.
     */
    fun mediaRecordState(media: Long): Pair<Long, Long> {
        val recordingSlot = LongArray(1)
        val recordedMsSlot = LongArray(1)
        check(SipralNative.sipral_media_record_state(media, recordingSlot, recordedMsSlot))
        return Pair(recordingSlot[0], recordedMsSlot[0])
    }

    /**
     * Take the next message the stack wants written.
     *
     * Loop until `len` is zero, after every `sipral_stack_poll` and every call that hands bytes
     * in. A message longer than `capacity` is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with the needed
     * length in `len` and is kept for the next call, ahead of the queue; a null `data` with
     * capacity zero thus asks for the length.
     *
     * Safety
     *
     * `transmit` must point at a `sipral_transmit_t` whose `size` member says how long it is and
     * whose buffers are writable for the capacities beside them.
     */
    fun stackPollTransmit(stack: Long, transmit: Long) {
        check(SipralNative.sipral_stack_poll_transmit(stack, transmit))
    }

    /**
     * Hand over one datagram, whole, with its source.
     *
     * `from` is the far end as `host:port`. `to` is the receiving address, which the response
     * leaves from (RFC 3581 §4); length zero means the stack's creation address. Frames from a
     * WebSocket the application runs come here too (RFC 7118 §4.2).
     *
     * Non-SIP bytes are `SIPRAL_STATUS_INVALID_ARGUMENT` with the parse error as last error;
     * only that packet is lost.
     *
     * Safety
     *
     * `data` must be readable for `len` bytes, `from` for `from_len`, and `to` for `to_len`.
     */
    fun stackReceiveDatagram(stack: Long, transport: Long, data: ByteArray, from: String, to: String, nowMs: Long) {
        val fromBytes = from.toByteArray(Charsets.UTF_8)
        val toBytes = to.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_stack_receive_datagram(stack, transport, data, fromBytes, toBytes, nowMs))
    }

    /**
     * Hand over bytes read off a connection, in whatever sizes the reads came in.
     *
     * A fragment of the `Content-Length` framing (§18.3): may hold several messages or none. A
     * stack-run WebSocket's handshake and frames come here too. Unreadable framing cannot be
     * resynchronised: the transport is retired before `SIPRAL_STATUS_INVALID_ARGUMENT` returns;
     * close the socket. A zero-byte read is sipral_stack_stream_closed, not this.
     *
     * Safety
     *
     * `data` must be readable for `len` bytes.
     */
    fun stackReceiveStream(stack: Long, transport: Long, data: ByteArray, nowMs: Long) {
        check(SipralNative.sipral_stack_receive_stream(stack, transport, data, nowMs))
    }

    /**
     * Say that a transport is open: the main one again, or a new one.
     *
     * The way back after sipral_stack_transport_failed and the way new transports enter the
     * table. `transport` is SIPRAL_TRANSPORT_MAIN or any caller-chosen number; a known one
     * is rebound, an unknown one opened. `out_transport_id`, if not null, receives the same
     * number.
     *
     * `protocol` is a SipralTransport. On rebind, zero keeps the current
     * protocol and anything different is `SIPRAL_STATUS_INVALID_ARGUMENT`: switching it under
     * running RFC 3261 §17 timers is not allowed. Opening a new transport requires a protocol.
     *
     * `local` is the address the far end reaches, `host:port`. `remote` names a connection's far
     * end, is refused on a datagram transport, and length zero omits it. On WS/WSS, `remote`
     * makes the stack run the WebSocket: the handshake comes out of
     * sipral_stack_poll_transmit and reads go to sipral_stack_receive_stream.
     *
     * After a
     * SipralEventKind.TRANSPORT_WANTED,
     * binding what it named and asking again sends the request on the new stream.
     *
     * Safety
     *
     * `local` must be readable for `local_len` bytes, `remote` for `remote_len`, and
     * `out_transport_id`, when it is not null, must point at one `uint32_t`.
     */
    fun stackTransportBind(stack: Long, transport: Long, protocol: Long, local: String, remote: String, nowMs: Long): Long {
        val localBytes = local.toByteArray(Charsets.UTF_8)
        val remoteBytes = remote.toByteArray(Charsets.UTF_8)
        val transportIdSlot = LongArray(1)
        check(SipralNative.sipral_stack_transport_bind(stack, transport, protocol, localBytes, remoteBytes, nowMs, transportIdSlot))
        return transportIdSlot[0]
    }

    /**
     * Say that a transport failed and what was written to it did not arrive.
     *
     * The transport is retired: its transactions fail now, effects are reported on the next
     * `sipral_stack_poll`, and nothing is sent until sipral_stack_transport_bind. Not for one
     * refused `sendto`: retiring the socket over an ICMP unreachable drops healthy calls.
     *
     * Also answers a `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` the application could not honour:
     * on the number it would have bound, waiting requests stop waiting (RFC 3261 §18.1.1:
     * trimmed into a datagram if it fits, else ended with 513). A never-bound number is
     * `SIPRAL_STATUS_INVALID_ARGUMENT` when nothing waits.
     *
     * The next poll raises `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` before the effects.
     * sipral_stack_transport_failed_with adds the TLS reason.
     *
     * Safety
     *
     * Safe to call with any handle value. Reads no memory the caller owns.
     */
    fun stackTransportFailed(stack: Long, transport: Long, error: Long, nowMs: Long) {
        check(SipralNative.sipral_stack_transport_failed(stack, transport, error, nowMs))
    }

    /**
     * Say that a transport failed, with the TLS library's reason.
     *
     * Does what sipral_stack_transport_failed does, and carries `failure->tls` and
     * `failure->detail` to `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`. A connection that failed before
     * any handshake belongs here too. A transport already down is not retired again but the
     * event is still raised, so each failed reconnect is reported.
     *
     * `SIPRAL_STATUS_INVALID_ARGUMENT`, retiring nothing, for a TLS reason on a non-TLS/WSS
     * transport, or a detail over SIPRAL_TRANSPORT_DETAIL_BYTES or not UTF-8.
     *
     * Safety
     *
     * `failure` must point at a `sipral_transport_failure_t` whose `size` member says how long
     * it is, and its `detail` must be readable for `detail_len` bytes.
     */
    fun stackTransportFailedWith(stack: Long, failure: SipralTransportFailure, nowMs: Long) {
        val failureDetail = failure.detail?.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_stack_transport_failed_with(stack, failure.transport, failure.error, failure.tls, failureDetail, nowMs))
    }

    /**
     * Say that a connection closed: the far end left, or a read returned zero.
     *
     * Retires like sipral_stack_transport_failed, but kept separate so an orderly close is
     * distinguishable in logs. The event says `SIPRAL_TRANSPORT_ERROR_CLOSED`.
     *
     * Safety
     *
     * Safe to call with any handle value. Reads no memory the caller owns.
     */
    fun stackStreamClosed(stack: Long, transport: Long, nowMs: Long) {
        check(SipralNative.sipral_stack_stream_closed(stack, transport, nowMs))
    }

    /**
     * Replace the STUN server list without recreating the stack.
     *
     * `servers` is comma-separated `host:port` in order of preference. Every mapped socket is
     * asked again at once and keeps its answer until the new server replies; servers kept from
     * the old list keep their back-off. On a `SIPRAL_NAT_OFF` stack the main transport starts
     * being mapped; further datagram transports join at their next `sipral_stack_transport_bind`.
     *
     * An empty list stops asking: `Contact`s move back to socket addresses and re-register, and
     * named media sockets are forgotten. `SIPRAL_STATUS_INVALID_ARGUMENT` for that with a TURN
     * server configured, or for a bad entry. `SIPRAL_STATUS_NOT_SUPPORTED` for a list without
     * `SIPRAL_FEATURE_STUN`.
     *
     * Safety
     *
     * `servers` must be readable for `servers_len` bytes.
     */
    fun stackStunServers(stack: Long, servers: String, nowMs: Long) {
        val serversBytes = servers.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_stack_stun_servers(stack, serversBytes, nowMs))
    }

    /**
     * Ask where a media socket appears from, before a call is described on it.
     *
     * `local` is the bound `host:port`, the same text as the call's `media_address`. The request
     * waits in sipral_stack_poll_stun; hand the answer to sipral_stack_receive_stun.
     * `SIPRAL_EVENT_KIND_NAT_MAPPING` reports within 5.5 seconds. A call on that
     * `media_address` is then described by the public address and asks for `a=rtcp-mux`.
     * Placing one before the answer is `SIPRAL_STATUS_WRONG_STATE`.
     *
     * Until the call, the socket is asked again every twenty-five seconds to keep the NAT
     * binding alive; keep draining the queue. At most one request per socket waits there. The
     * call spends the mapping: name the socket again for a second call.
     *
     * `SIPRAL_STATUS_WRONG_STATE` without `SIPRAL_NAT_STUN`; `SIPRAL_STATUS_INVALID_ARGUMENT`
     * for one of the stack's own signalling sockets.
     *
     * Safety
     *
     * `local` must be readable for `local_len` bytes.
     */
    fun stackNatMap(stack: Long, local: String, nowMs: Long) {
        val localBytes = local.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_stack_nat_map(stack, localBytes, nowMs))
    }

    /**
     * Say that a media socket sipral_stack_nat_map named will carry no call, and release it.
     *
     * Its refreshes stop and a waiting request is dropped. A TURN relay is released with a
     * Refresh of lifetime zero (RFC 8656 §8), waiting in sipral_stack_poll_stun. If its
     * Allocate is still unanswered, a late answer is accepted through
     * sipral_stack_receive_stun for up to forty seconds and released the same way. Without
     * this call the server holds the allocation until its lifetime expires, up to ten minutes
     * after `sipral_stack_destroy`.
     *
     * Use it for a closed socket, a call not placed, and every named socket before destroy. A
     * socket already used by a call, or never named, is a no-op.
     *
     * `SIPRAL_STATUS_WRONG_STATE` without `SIPRAL_NAT_STUN`; `SIPRAL_STATUS_INVALID_ARGUMENT`
     * for one of the stack's own signalling sockets.
     *
     * Safety
     *
     * `local` must be readable for `local_len` bytes.
     */
    fun stackNatUnmap(stack: Long, local: String, nowMs: Long) {
        val localBytes = local.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_stack_nat_unmap(stack, localBytes, nowMs))
    }

    /**
     * Take the next STUN request a media socket has to send.
     *
     * Same record and rules as `sipral_stack_poll_transmit`, on its own queue: loop until `len`
     * is zero after every sipral_stack_nat_map, sipral_stack_receive_stun and
     * `sipral_stack_poll`. Send from `source` exactly: the server reports the address it sees.
     * `transport` is zero. `protocol` is UDP for a datagram, or TCP/TLS for bytes to write on
     * the TURN connection from `source`.
     *
     * A call on a relayed socket also sends here until it has a media handle: Binding
     * indications keeping the NAT open and the allocation refresh. After that they leave via
     * `sipral_media_poll_transmit`.
     *
     * Safety
     *
     * `transmit` must point at a `sipral_transmit_t` whose `size` member says how long it is
     * and whose buffers are writable for the capacities beside them.
     */
    fun stackPollStun(stack: Long, transmit: Long) {
        check(SipralNative.sipral_stack_poll_stun(stack, transmit))
    }

    /**
     * Hand over a datagram that arrived on a media socket sipral_stack_nat_map named,
     * before a call has media on it.
     *
     * Everything arriving on the socket comes here until the call's media handle exists:
     * - TURN answers to what the call's relay sent (an unanswered refresh loses the relay);
     * - the far end's early ICE checks: those signed with this call's password are kept, the
     *   newest sixteen, and answered when the session opens (RFC 8445 §7.3), unless older than
     *   39.5 seconds or the call ended;
     * - between `SIPRAL_EVENT_KIND_MEDIA_STARTED` and `sipral_call_media`, anything, as through
     *   `sipral_media_receive`.
     *
     * A socket shared by forked branches (`keep_all_forks`) keeps coming here; each datagram goes
     * to the branch matching its ICE fragment, transaction or source (RFC 8839 §7.3). A stack
     * without STUN accepts only that and returns `SIPRAL_STATUS_WRONG_STATE` otherwise.
     *
     * `to` is the receiving socket as named, `from` the sender. `SIPRAL_STATUS_OK` when taken;
     * `SIPRAL_STATUS_INVALID_ARGUMENT` for anything else, dropping only that datagram. Only
     * answers from the server's own address to this stack's own requests are believed: that is
     * the defence against a forged mapping.
     *
     * Safety
     *
     * `data` must be readable for `len` bytes, `from` for `from_len`, and `to` for `to_len`.
     */
    fun stackReceiveStun(stack: Long, data: ByteArray, from: String, to: String, nowMs: Long) {
        val fromBytes = from.toByteArray(Charsets.UTF_8)
        val toBytes = to.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_stack_receive_stun(stack, data, fromBytes, toBytes, nowMs))
    }

    /**
     * Say that the connection a `SIPRAL_TURN_STREAM_OPEN` asked for is open (for TLS, with the
     * handshake done and the certificate checked by the platform).
     *
     * The socket's Allocate then waits in sipral_stack_poll_stun marked with `protocol`;
     * the answer comes back through sipral_stack_turn_receive.
     *
     * `SIPRAL_STATUS_INVALID_ARGUMENT` for a socket with no requested connection,
     * `SIPRAL_STATUS_WRONG_STATE` without `SIPRAL_NAT_STUN`.
     *
     * Safety
     *
     * `local` must be readable for `local_len` bytes.
     */
    fun stackTurnConnected(stack: Long, local: String, nowMs: Long) {
        val localBytes = local.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_stack_turn_connected(stack, localBytes, nowMs))
    }

    /**
     * Hand over bytes read from a media socket's TURN connection, in any chunking.
     *
     * Messages are reassembled (RFC 8656 §12.5) and routed like a datagram from the server: to
     * the socket's relay, or to the call holding it (agent or media, audio included). Read the
     * connection for as long as it is open; replies leave through `sipral_media_poll_transmit`.
     *
     * `SIPRAL_STATUS_STREAM_BROKEN` when the bytes are not TURN framing: close the connection.
     * The relay is lost with it and no `SIPRAL_TURN_STREAM_CLOSE` follows.
     * `SIPRAL_STATUS_INVALID_ARGUMENT` for a socket with no open connection.
     *
     * Safety
     *
     * `local` must be readable for `local_len` bytes, and `data` for `len`.
     */
    fun stackTurnReceive(stack: Long, local: String, data: ByteArray, nowMs: Long) {
        val localBytes = local.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_stack_turn_receive(stack, localBytes, data, nowMs))
    }

    /**
     * Say that a media socket's TURN connection closed, or could not be opened.
     *
     * The allocation was tied to the connection (RFC 8656 §3.2), so the relay is gone: one in
     * progress becomes `SIPRAL_NAT_RELAY_FAILED`; a call using it loses that path when consent
     * expires (RFC 7675). Name the socket again to get a new connection. `SIPRAL_STATUS_OK` for
     * a connection already released.
     *
     * Safety
     *
     * `local` must be readable for `local_len` bytes.
     */
    fun stackTurnClosed(stack: Long, local: String, nowMs: Long) {
        val localBytes = local.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_stack_turn_closed(stack, localBytes, nowMs))
    }

    /**
     * The short name of an event kind, as a static NUL-terminated
     * string, or null for a number this build has no kind for
     * (reserved numbers included).
     *
     * The string belongs to the library and lives as long as it is
     * loaded.
     *
     * Safety
     *
     * Reads no caller memory; safe from any thread.
     */
    fun eventKindName(kind: Long): String? =
        SipralNative.sipral_event_kind_name(kind)

    /**
     * How many lines a header field is on, in a whole SIP message.
     *
     * The name is case-insensitive and a compact form equals its long form
     * (RFC 3261 §7.3.3). An absent field counts zero, not a failure.
     *
     * Safety
     *
     * `message` must be readable for `message_len` bytes and `name` for
     * `name_len`, and `out_count` must point at one `size_t`.
     */
    fun messageHeaderCount(message: ByteArray, name: String): Long {
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        val countSlot = LongArray(1)
        check(SipralNative.sipral_message_header_count(message, nameBytes, countSlot))
        return countSlot[0]
    }

    /**
     * Where one line of a header field is, in a whole SIP message.
     *
     * `index` is in arrival order, below `sipral_message_header_count`, else
     * `SIPRAL_STATUS_INVALID_ARGUMENT`. `out_offset` and `out_len` locate the
     * value inside `message`, trimmed, line folds kept. For single list values
     * use `sipral_message_header_element`.
     *
     * Safety
     *
     * As `sipral_message_header_count`, with `out_offset` and `out_len` each
     * pointing at one `size_t`.
     */
    fun messageHeader(message: ByteArray, name: String, index: Long): Pair<Long, Long> {
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        val offsetSlot = LongArray(1)
        val lenSlot = LongArray(1)
        check(SipralNative.sipral_message_header(message, nameBytes, index, offsetSlot, lenSlot))
        return Pair(offsetSlot[0], lenSlot[0])
    }

    /**
     * How many values a field whose value is a comma-separated list holds,
     * across every line it is on.
     *
     * Per RFC 3261 §7.3.1 one line with commas equals several lines, so this
     * splits at commas outside quotes and angle brackets. Only for list
     * fields (`Diversion`, `Contact`...); a `Date` would split wrongly.
     *
     * Safety
     *
     * As `sipral_message_header_count`.
     */
    fun messageHeaderElementCount(message: ByteArray, name: String): Long {
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        val countSlot = LongArray(1)
        check(SipralNative.sipral_message_header_element_count(message, nameBytes, countSlot))
        return countSlot[0]
    }

    /**
     * Where one value of a list field is, across every line the field is on.
     *
     * `index` is below `sipral_message_header_element_count`. Otherwise as
     * `sipral_message_header`.
     *
     * Safety
     *
     * As `sipral_message_header`.
     */
    fun messageHeaderElement(message: ByteArray, name: String, index: Long): Pair<Long, Long> {
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        val offsetSlot = LongArray(1)
        val lenSlot = LongArray(1)
        check(SipralNative.sipral_message_header_element(message, nameBytes, index, offsetSlot, lenSlot))
        return Pair(offsetSlot[0], lenSlot[0])
    }

    /**
     * The operating system says this process stops shortly.
     *
     * Synchronous, bounded by accounts and subscriptions, infallible. Nothing
     * is sent (`docs/16-lifecycle.md` says why de-registering here is wrong)
     * and nothing stays scheduled. Calls are left as they are. `out_report`
     * receives the counts.
     *
     * Safety
     *
     * `out_report` must point at a `sipral_suspending_t` whose `size` member
     * says how long it is.
     */
    fun stackSuspending(stack: Long, nowMs: Long): SipralSuspending {
        val reportSlots = LongArray(SipralSuspending.SLOTS)
        check(SipralNative.sipral_stack_suspending(stack, nowMs, reportSlots))
        return SipralSuspending.of(reportSlots)
    }

    /**
     * The process is awake again.
     *
     * An unmeasurable time passed and any transport may be dead. Beliefs are
     * dropped and proved again, on the existing transport first (most wakes
     * are short); sipral_account_rebind supplies a new one when asked.
     * Safe without a matching sipral_stack_suspending: some platforms
     * only notify on the way back.
     *
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun stackResumed(stack: Long, nowMs: Long) {
        check(SipralNative.sipral_stack_resumed(stack, nowMs))
    }

    /**
     * The network changed; before and after are described.
     *
     * `*_link` is a SipralLink. `*_address` is the local address the
     * transports are bound to, an IP literal without port; a change
     * invalidates every transport and binding. `*_interface` is the
     * platform's interface id, only compared, since two networks can hand out
     * the same address. `*_resolves` says whether names resolve there, the
     * one failure that looks healthy. Address and interface may be null with
     * zero length.
     *
     * `out_recovery`, which may be null, receives a SipralRecovery.
     * Cheap enough to call on every notification: usually the answer is
     * `SIPRAL_RECOVERY_NOTHING` and nothing happens.
     *
     * Safety
     *
     * Every address and interface pointer must be readable for the length
     * beside it or null with a length of zero, and `out_recovery` must point
     * at one `uint32_t` or be null.
     */
    fun stackNetworkChanged(stack: Long, fromLink: Long, fromAddress: String, fromInterface: String, fromResolves: Long, toLink: Long, toAddress: String, toInterface: String, toResolves: Long, nowMs: Long): Long {
        val fromAddressBytes = fromAddress.toByteArray(Charsets.UTF_8)
        val fromInterfaceBytes = fromInterface.toByteArray(Charsets.UTF_8)
        val toAddressBytes = toAddress.toByteArray(Charsets.UTF_8)
        val toInterfaceBytes = toInterface.toByteArray(Charsets.UTF_8)
        val recoverySlot = LongArray(1)
        check(SipralNative.sipral_stack_network_changed(stack, fromLink, fromAddressBytes, fromInterfaceBytes, fromResolves, toLink, toAddressBytes, toInterfaceBytes, toResolves, nowMs, recoverySlot))
        return recoverySlot[0]
    }

    /**
     * There is no usable interface. Nothing is tried or scheduled until
     * sipral_stack_network_changed reports one back; the opposite of
     * sipral_stack_name_resolution_lost.
     *
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun stackInterfaceLost(stack: Long, nowMs: Long) {
        check(SipralNative.sipral_stack_interface_lost(stack, nowMs))
    }

    /**
     * Names no longer become addresses.
     *
     * Everything looks healthy while every address learned from a name may
     * be wrong. Bindings whose registrar is a name stop being trusted; ones
     * aimed at a literal address keep running.
     *
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun stackNameResolutionLost(stack: Long, nowMs: Long) {
        check(SipralNative.sipral_stack_name_resolution_lost(stack, nowMs))
    }

    /**
     * Point an account at a transport and an address again.
     *
     * `remote` is where its requests go, `host:port`. `contact` is required:
     * after an address change the old one is unreachable, and keeping it
     * would register a binding that receives nothing.
     *
     * `transport` must already exist:
     * SIPRAL_TRANSPORT_MAIN or
     * one sipral_stack_transport_bind
     * bound; anything else is `SIPRAL_STATUS_INVALID_ARGUMENT`. This does not
     * open one.
     *
     * When recovery is waiting for it, the next rung runs at once instead of
     * waiting out the back-off. Otherwise the account is still repointed and
     * the next REGISTER uses it.
     *
     * Safety
     *
     * `remote` must be readable for `remote_len` bytes and `contact` for
     * `contact_len` bytes.
     */
    fun accountRebind(stack: Long, account: Long, transport: Long, remote: String, contact: String, nowMs: Long) {
        val remoteBytes = remote.toByteArray(Charsets.UTF_8)
        val contactBytes = contact.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_account_rebind(stack, account, transport, remoteBytes, contactBytes, nowMs))
    }

    /**
     * Mark the process start, the zero of sipral_account_time_to_ready.
     *
     * Only the application knows the moment its users wait from. Each call
     * clears and restarts every account's measurement.
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun stackColdStart(stack: Long, nowMs: Long) {
        check(SipralNative.sipral_stack_cold_start(stack, nowMs))
    }

    /**
     * Write an account's registration down, so a later start can carry it
     * on without a full handshake.
     *
     * `out_len` always receives the size; a null `buffer` with `capacity`
     * zero asks for it and gets `SIPRAL_STATUS_BUFFER_TOO_SMALL`. Nothing is
     * written to a short buffer.
     *
     * **The bytes are opaque; parsing them is not part of this ABI.** They are
     * versioned and a build reads only its known layouts. Storing and
     * protecting them is the application's: they name an address of record.
     *
     * `SIPRAL_STATUS_WRONG_STATE` when there is nothing to keep: never
     * registered, never will, failed, or given up. The clock is read, not
     * moved, so a snapshot on the way into suspend cannot reject a later
     * `now_ms`.
     * Safety
     *
     * `buffer` must be writable for `capacity` bytes or be null with a
     * `capacity` of zero, and `out_len` must point at one `size_t` or be
     * null.
     */
    fun accountFreeze(stack: Long, account: Long, buffer: ByteArray, nowMs: Long): Long {
        val lenSlot = LongArray(1)
        check(SipralNative.sipral_account_freeze(stack, account, buffer, lenSlot, nowMs))
        return lenSlot[0]
    }

    /**
     * Read one back, on an account that was added and has not registered.
     *
     * `asleep_ms` is how long the snapshot sat unused: only the application
     * knows, since no wall clock is read here and instants die with the
     * process. The binding keeps what it had left, less that.
     *
     * The account comes up
     * SIPRAL_REGISTRATION_STATE_RESTORED,
     * not registered, until the refresh this books confirms it.
     *
     * Refused with the account unchanged: `SIPRAL_STATUS_UNSUPPORTED_VERSION`
     * for bytes a newer build wrote, `SIPRAL_STATUS_NOT_SUPPORTED` for an
     * account that does not register, `SIPRAL_STATUS_INVALID_ARGUMENT` for
     * bytes that are not a snapshot, are damaged, or belong to another
     * address of record (which would register somebody else).
     *
     * Safety
     *
     * `snapshot` must be readable for `snapshot_len` bytes.
     */
    fun accountThaw(stack: Long, account: Long, snapshot: ByteArray, asleepMs: Long, nowMs: Long) {
        check(SipralNative.sipral_account_thaw(stack, account, snapshot, asleepMs, nowMs))
    }

    /**
     * How long this account took to become reachable, from
     * sipral_stack_cold_start. A queue's ring timeout must exceed it, or
     * a waking phone is always skipped.
     *
     * `out_has_value` and `out_ms` are zero until there is an answer: before
     * registration, for an account that never registers, or with no cold
     * start declared. Zero with `out_has_value` set is a real answer.
     *
     * Safety
     *
     * `out_has_value` must point at one `uint32_t` and `out_ms` at one
     * `uint64_t`.
     */
    fun accountTimeToReady(stack: Long, account: Long): Pair<Long, Long> {
        val hasValueSlot = LongArray(1)
        val msSlot = LongArray(1)
        check(SipralNative.sipral_account_time_to_ready(stack, account, hasValueSlot, msSlot))
        return Pair(hasValueSlot[0], msSlot[0])
    }

    /**
     * Say where a dialog's next hop actually is.
     *
     * The answer to
     * SIPRAL_EVENT_KIND_RESOLVE_NEEDED,
     * with `dialog` the handle that event carried. `addresses` is
     * comma-separated `host:port` in RFC 3263 §4.3 priority order: the first
     * one with an open transport of the wanted protocol is taken, the rest
     * are kept for failover.
     *
     * `protocol` is a SipralTransport when the lookup named one (NAPTR,
     * SRV), or zero to keep the flow's protocol. It is never opened: an
     * address on an unbound protocol is passed over; answer again after
     * sipral_stack_transport_bind.
     *
     * `SIPRAL_STATUS_OK` with nothing changed when no address is reachable.
     * `SIPRAL_STATUS_STALE_HANDLE` for a dialog that has ended. No `now_ms`:
     * nothing here is timed.
     *
     * Safety
     *
     * `addresses` must be readable for `addresses_len` bytes.
     */
    fun stackResolved(stack: Long, dialog: Long, addresses: String, protocol: Long) {
        val addressesBytes = addresses.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_stack_resolved(stack, dialog, addressesBytes, protocol))
    }

    /**
     * Point an account's registration at another address.
     *
     * For a registrar with several targets. The binding's `Call-ID`,
     * sequence and credentials are kept, so the registrar sees the same
     * device continuing. A REGISTER in flight or booked is superseded at
     * once; retargeting to the current address is `SIPRAL_STATUS_OK` and
     * sends nothing.
     *
     * `registrar_address` is `host:port`, not a name.
     * `SIPRAL_STATUS_NOT_SUPPORTED` for an account with no registrar.
     *
     * Safety
     *
     * `registrar_address` must be readable for `registrar_address_len`
     * bytes.
     */
    fun accountRetarget(stack: Long, account: Long, registrarAddress: String, nowMs: Long) {
        val registrarAddressBytes = registrarAddress.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_account_retarget(stack, account, registrarAddressBytes, nowMs))
    }

    /**
     * Copy one call's diagnostic record into `buffer`, as the JSON
     * `docs/14-diagnostics.md` describes.
     *
     * Readable during the call and after it, until the record is evicted
     * (`sipral_stack_config_t::diagnostic_records` are kept, 32 when zero).
     * An evicted or still empty record answers `SIPRAL_STATUS_OK` with `{}`.
     *
     * `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
     * document, with the length needed in `out_needed`.
     *
     * Safety
     *
     * `buffer` must be writable for `capacity` bytes or be null with a
     * capacity of zero, and `out_needed` must point at one `size_t` or be null.
     */
    fun callRecordJson(stack: Long, call: Long, buffer: ByteArray): Long {
        val neededSlot = LongArray(1)
        check(SipralNative.sipral_call_record_json(stack, call, buffer, neededSlot))
        return neededSlot[0]
    }

    /**
     * Copy the whole diagnostic document into `buffer`: what a bug report
     * carries, as the JSON `docs/14-diagnostics.md` describes.
     *
     * The endpoint's own record (decisions outside any call), then one record
     * per call still held, and the count of evicted records.
     *
     * `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
     * document, with the length needed in `out_needed`.
     *
     * Safety
     *
     * `buffer` must be writable for `capacity` bytes or be null with a
     * capacity of zero, and `out_needed` must point at one `size_t` or be null.
     */
    fun stackDiagnosticsJson(stack: Long, buffer: ByteArray): Long {
        val neededSlot = LongArray(1)
        check(SipralNative.sipral_stack_diagnostics_json(stack, buffer, neededSlot))
        return neededSlot[0]
    }

    /**
     * What a `conference` subscription holds about the conference as a
     * whole (RFC 4575 §5.5). `SIPRAL_STATUS_NOT_SUPPORTED` when it holds
     * none: another package, no document yet, or not live.
     *
     * Safety
     *
     * `out_conference` must point at a `sipral_conference_t` whose `size`
     * member says how long it is.
     */
    fun subscriptionConference(stack: Long, subscription: Long): SipralConference {
        val conferenceSlots = LongArray(SipralConference.SLOTS)
        check(SipralNative.sipral_subscription_conference(stack, subscription, conferenceSlots))
        return SipralConference.of(conferenceSlots)
    }

    /**
     * One user of the conference, by index, in the order the focus first
     * named them. The index is stable only until the next
     * `SIPRAL_EVENT_KIND_CONFERENCE_CHANGED`.
     *
     * Safety
     *
     * `out_user` must point at a `sipral_conference_user_t` whose `size`
     * member says how long it is.
     */
    fun subscriptionConferenceUserAt(stack: Long, subscription: Long, index: Long): SipralConferenceUser {
        val userSlots = LongArray(SipralConferenceUser.SLOTS)
        check(SipralNative.sipral_subscription_conference_user_at(stack, subscription, index, userSlots))
        return SipralConferenceUser.of(userSlots)
    }

    /**
     * Text about the conference or a user, as `which` (a
     * SipralConferenceText) and `index` say. `out_needed` gets the bytes
     * needed including the NUL; a small buffer is
     * `SIPRAL_STATUS_BUFFER_TOO_SMALL` with nothing written; absent text is
     * just the NUL.
     *
     * Safety
     *
     * `buffer` must be writable for `capacity` bytes or be null with a
     * capacity of zero, and `out_needed` must point at one `size_t` or be
     * null.
     */
    fun subscriptionConferenceText(stack: Long, subscription: Long, index: Long, which: Long, buffer: ByteArray): Long {
        val neededSlot = LongArray(1)
        check(SipralNative.sipral_subscription_conference_text(stack, subscription, index, which, buffer, neededSlot))
        return neededSlot[0]
    }

    /**
     * Put (`focus` 1) or remove (0) `isfocus` on this call's `Contact` from
     * the next message on (RFC 4579 §4.2): the answer, or the next re-INVITE
     * or UPDATE on an established call.
     *
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun callSetFocus(stack: Long, call: Long, focus: Long) {
        check(SipralNative.sipral_call_set_focus(stack, call, focus))
    }

    /**
     * The conference URI when the far end's `Contact` has `isfocus` (RFC 4579
     * §4.2), copied as `sipral_subscription_conference_text` copies.
     * `SIPRAL_STATUS_NOT_A_FOCUS` otherwise.
     *
     * Safety
     *
     * `buffer` must be writable for `capacity` bytes or be null with a
     * capacity of zero, and `out_needed` must point at one `size_t` or be
     * null.
     */
    fun callConferenceUri(stack: Long, call: Long, buffer: ByteArray): Long {
        val neededSlot = LongArray(1)
        check(SipralNative.sipral_call_conference_uri(stack, call, buffer, neededSlot))
        return neededSlot[0]
    }

    /**
     * Subscribe to the conference package of the call's focus (RFC 4579
     * §3.4), outside the call's dialog, from the call's account. The
     * subscription outlives the call. `SIPRAL_STATUS_NOT_A_FOCUS` when the
     * far end is not a focus.
     *
     * Safety
     *
     * `out_subscription` must point at one `sipral_handle_t`.
     */
    fun callSubscribeConference(stack: Long, call: Long, nowMs: Long): Long {
        val subscriptionSlot = LongArray(1)
        check(SipralNative.sipral_call_subscribe_conference(stack, call, subscriptionSlot, nowMs))
        return subscriptionSlot[0]
    }

    /**
     * Publish this account's presence (RFC 3903, RFC 3856 §6.2). Later calls
     * modify the same publication; the stack refreshes it until
     * sipral_account_unpublish_presence.
     *
     * The PUBLISH is only queued on return; the outcome arrives as
     * `SIPRAL_EVENT_KIND_PRESENCE_CHANGED` with `SIPRAL_PRESENCE_KIND_PUBLICATION`.
     *
     * Safety
     *
     * `presence` must point at a `sipral_presence_t` whose `size` member
     * says how long it is, with its pointer readable for the length beside
     * it.
     */
    fun accountPublishPresence(stack: Long, account: Long, presence: SipralPresence, nowMs: Long) {
        val presenceNote = presence.note?.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_account_publish_presence(stack, account, presence.basic, presence.activity, presenceNote, nowMs))
    }

    /**
     * Take this account's published presence away (RFC 3903 §4.5):
     * `SIPRAL_PUBLICATION_STATE_REMOVED` says when it is gone.
     *
     * `SIPRAL_STATUS_WRONG_STATE` for an account that has published none.
     *
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun accountUnpublishPresence(stack: Long, account: Long, nowMs: Long) {
        check(SipralNative.sipral_account_unpublish_presence(stack, account, nowMs))
    }

    /**
     * Queue text the user typed for the far end, UTF-8.
     * Sent every 300 ms within the far end's rate, with `red` redundancy
     * when agreed. CR, LF or CR LF is a new line; U+0008 erases.
     *
     * `SIPRAL_STATUS_NOT_NEGOTIATED` without a text stream;
     * `SIPRAL_STATUS_EXHAUSTED` when the queue is full (nothing queued).
     *
     * Safety
     *
     * `text` must be readable for `text_len` bytes.
     */
    fun mediaSendText(media: Long, text: String) {
        val textBytes = text.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_media_send_text(media, textBytes))
    }

    /**
     * The next datagram due on the call's text socket.
     * `len` zero means nothing due; poll again at the stack's deadline. Send
     * from the `text_address` socket, not the audio one.
     *
     * Safety
     *
     * `packet` must point at a `sipral_media_packet_t` as
     * `sipral_media_capture` describes.
     */
    fun mediaPollText(media: Long, nowMs: Long, packet: Long) {
        check(SipralNative.sipral_media_poll_text(media, nowMs, packet))
    }

    /**
     * Take a datagram off the call's text socket.
     * `out_taken` is 1 when it was this call's text, else 0 (not RTP, other
     * payload type, not the latched source, or no text stream).
     *
     * Safety
     *
     * `data` must be readable for `len` bytes, `from` for `from_len`, and
     * `out_taken` must point at one `uint32_t` or be null.
     */
    fun mediaReceiveText(media: Long, data: ByteArray, from: String, nowMs: Long): Long {
        val fromBytes = from.toByteArray(Charsets.UTF_8)
        val takenSlot = LongArray(1)
        check(SipralNative.sipral_media_receive_text(media, data, fromBytes, nowMs, takenSlot))
        return takenSlot[0]
    }

    /**
     * Record a call to a recording server (RFC 7866), and write the
     * recording session's handle to `out_recording`.
     *
     * `SIPRAL_STATUS_WRONG_STATE` before `SIPRAL_EVENT_KIND_MEDIA_STARTED`,
     * for a call whose media this stack does not run, or one already
     * recorded. Sent from the call's account; a stream transport when too
     * large for UDP. Stopped by sipral_call_stop_recording_to,
     * `sipral_call_hangup` on it, or the server hanging up.
     *
     * Safety
     *
     * `config` must point at a `sipral_record_config_t` whose `size` member
     * says how long it is, with every pointer in it readable for the length
     * beside it, and `out_recording` at one `sipral_handle_t`.
     */
    fun callRecordTo(stack: Long, call: Long, config: SipralRecordConfig, nowMs: Long): Long {
        val configServer = config.server?.toByteArray(Charsets.UTF_8)
        val configDestination = config.destination?.toByteArray(Charsets.UTF_8)
        val configThisEnd = config.thisEnd?.toByteArray(Charsets.UTF_8)
        val configFarEnd = config.farEnd?.toByteArray(Charsets.UTF_8)
        val recordingSlot = LongArray(1)
        check(SipralNative.sipral_call_record_to(stack, call, configServer, configDestination, config.transport, configThisEnd, configFarEnd, recordingSlot, nowMs))
        return recordingSlot[0]
    }

    /**
     * Stop copies at once and hang up the recording session. `call` is the
     * recorded call. `SIPRAL_STATUS_WRONG_STATE` when nothing records it.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callStopRecordingTo(stack: Long, call: Long, nowMs: Long) {
        check(SipralNative.sipral_call_stop_recording_to(stack, call, nowMs))
    }

    /**
     * The next copy of this call's audio for its recording server.
     * `len` zero means none waiting. `out_far_end` is 0 to send from
     * `this_end`, 1 from `far_end`. Drain every frame: copies older than a
     * second are dropped, oldest first.
     *
     * Safety
     *
     * `packet` must point at a `sipral_media_packet_t` as
     * `sipral_media_capture` describes, and `out_far_end` at one
     * `uint32_t`.
     */
    fun mediaPollRecording(media: Long, packet: Long): Long {
        val farEndSlot = LongArray(1)
        check(SipralNative.sipral_media_poll_recording(media, packet, farEndSlot))
        return farEndSlot[0]
    }

    /**
     * Start recording the signalling this stack is fed (`docs/18-replay.md`).
     * Starting moves the stack onto a fresh seed derived one way from
     * `entropy`; the recording carries that seed, never `entropy`, and
     * stopping moves the stack on again. It records what arrives, never what
     * this end sent.
     *
     * `note` is one line of prose for whoever opens the file later, or null
     * for none.
     *
     * A running recording is replaced, not refused: nothing is written until
     * `sipral_stack_recording_stop`.
     *
     * Safety
     *
     * `note` must be readable for `note_len` bytes or be null with a length
     * of zero.
     */
    fun stackRecordingStart(stack: Long, note: String) {
        val noteBytes = note.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_stack_recording_start(stack, noteBytes))
    }

    /**
     * Stop the recording sipral_stack_recording_start began, and copy
     * the text of it into `buffer` (`docs/18-replay.md`).
     *
     * `SIPRAL_STATUS_WRONG_STATE` when no recording is running. Also
     * `SIPRAL_STATUS_WRONG_STATE`, with the reason in the last error, when a
     * message could not go in the text format (a non-text body); then nothing
     * is produced, since a recording missing a message would replay differently.
     *
     * `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
     * text, with the length needed in `out_needed`; asking again returns the
     * same recording. Once copied out whole, the recording is gone from the stack.
     *
     * Safety
     *
     * `buffer` must be writable for `capacity` bytes or be null with a
     * capacity of zero, and `out_needed` must point at one `size_t` or be null.
     */
    fun stackRecordingStop(stack: Long, buffer: ByteArray): Long {
        val neededSlot = LongArray(1)
        check(SipralNative.sipral_stack_recording_stop(stack, buffer, neededSlot))
        return neededSlot[0]
    }

    /**
     * Ask the platform for its devices and say how many the list holds.
     *
     * Known devices keep their ids; gone ones keep their rows, marked absent.
     * For a settings screen, not polling: the engine refreshes on platform
     * notices. `SIPRAL_STATUS_DEVICE_TIMED_OUT` past `audio_probe_ms`, with
     * the list unchanged.
     *
     * Safety
     *
     * `out_count` must point at one `size_t` or be null.
     */
    fun audioRefresh(stack: Long): Long {
        val countSlot = LongArray(1)
        check(SipralNative.sipral_audio_refresh(stack, countSlot))
        return countSlot[0]
    }

    /**
     * How many devices the list holds, present or not.
     *
     * The first read of a list asks the platform, so no refresh is needed.
     * `SIPRAL_STATUS_DEVICE_TIMED_OUT` past `audio_probe_ms`; the next read
     * asks again.
     *
     * Safety
     *
     * `out_count` must point at one `size_t`.
     */
    fun audioDeviceCount(stack: Long): Long {
        val countSlot = LongArray(1)
        check(SipralNative.sipral_audio_device_count(stack, countSlot))
        return countSlot[0]
    }

    /**
     * The device at `index` in the list, and its name into `buffer`.
     *
     * `SIPRAL_STATUS_INVALID_ARGUMENT` past the end. The name is UTF-8 with a
     * trailing NUL; `out_needed`, when not null, receives its length with the
     * NUL. `SIPRAL_STATUS_BUFFER_TOO_SMALL` writes neither `buffer` nor
     * `out_device`.
     *
     * Safety
     *
     * `out_device` must point at a `sipral_audio_device_t` whose `size`
     * member says how long it is; `buffer` must be writable for `capacity`
     * bytes or null with a capacity of zero; `out_needed` must point at one
     * `size_t` or be null.
     */
    fun audioDeviceAt(stack: Long, index: Long, buffer: ByteArray): Pair<SipralAudioDevice, Long> {
        val deviceSlots = LongArray(SipralAudioDevice.SLOTS)
        val neededSlot = LongArray(1)
        check(SipralNative.sipral_audio_device_at(stack, index, deviceSlots, buffer, neededSlot))
        return Pair(SipralAudioDevice.of(deviceSlots), neededSlot[0])
    }

    /**
     * Put a role on a device, or back on the system's route with a
     * `device` of zero.
     *
     * Refused before any platform call, changing nothing:
     * `SIPRAL_STATUS_NO_SUCH_DEVICE` for an unknown id,
     * `SIPRAL_STATUS_DEVICE_UNUSABLE` for a device absent or without channels
     * in the role's direction, `SIPRAL_STATUS_NOT_SUPPORTED` where the
     * platform cannot separate the role (on macOS the microphone follows the
     * system's input).
     *
     * While active the role reopens at once, keeping gain and mute, and
     * `SIPRAL_AUDIO_CHANGE_SELECTED` follows. A chosen device that is
     * unplugged stays the preference and is used again when it returns.
     *
     * Safety
     *
     * Reads no memory the caller owns.
     */
    fun audioSelect(stack: Long, role: Long, device: Long) {
        check(SipralNative.sipral_audio_select(stack, role, device))
    }

    /**
     * What a role was asked to be on (zero: the system's route) and what it
     * runs on (zero: not open). They differ while a chosen device is absent.
     *
     * Safety
     *
     * Each out parameter must point at one `uint32_t` or be null.
     */
    fun audioSelection(stack: Long, role: Long): Pair<Long, Long> {
        val selectedSlot = LongArray(1)
        val runningSlot = LongArray(1)
        check(SipralNative.sipral_audio_selection(stack, role, selectedSlot, runningSlot))
        return Pair(selectedSlot[0], runningSlot[0])
    }

    /**
     * Set the gain of one direction, fixed-point with 256 for unity, capped
     * at 1024. Input is the microphone gain, output the volume. Applied to
     * the frames, not the OS control, and kept across device changes.
     *
     * Safety
     *
     * Reads no memory the caller owns.
     */
    fun audioSetGain(stack: Long, direction: Long, gain: Long) {
        check(SipralNative.sipral_audio_set_gain(stack, direction, gain))
    }

    /**
     * The gain of one direction, in the steps `sipral_audio_set_gain` takes.
     *
     * Safety
     *
     * `out_gain` must point at one `uint32_t`.
     */
    fun audioGain(stack: Long, direction: Long): Long {
        val gainSlot = LongArray(1)
        check(SipralNative.sipral_audio_gain(stack, direction, gainSlot))
        return gainSlot[0]
    }

    /**
     * Mute or unmute one direction, kept across device changes. A muted
     * microphone sends silence, so the far end hears a stream, not a gap.
     *
     * Safety
     *
     * Reads no memory the caller owns.
     */
    fun audioSetMuted(stack: Long, direction: Long, muted: Long) {
        check(SipralNative.sipral_audio_set_muted(stack, direction, muted))
    }

    /**
     * Whether one direction is muted: one or zero into `out_muted`.
     *
     * Safety
     *
     * `out_muted` must point at one `uint32_t`.
     */
    fun audioMuted(stack: Long, direction: Long): Long {
        val mutedSlot = LongArray(1)
        check(SipralNative.sipral_audio_muted(stack, direction, mutedSlot))
        return mutedSlot[0]
    }

    /**
     * The meter of one direction: the peak sample of the last 100 ms, 0 to
     * 32767, held one to two windows. Cheap to poll per frame; zero while
     * nothing is open.
     *
     * Safety
     *
     * `out_peak` must point at one `uint32_t`.
     */
    fun audioLevel(stack: Long, direction: Long): Long {
        val peakSlot = LongArray(1)
        check(SipralNative.sipral_audio_level(stack, direction, peakSlot))
        return peakSlot[0]
    }

    /**
     * Open the devices and start the pump now. The only way under
     * `SIPRAL_AUDIO_ACTIVATION_MANUAL`; early under automatic activation.
     * `SIPRAL_STATUS_DEVICE_UNUSABLE` or `SIPRAL_STATUS_DEVICE_TIMED_OUT` for
     * a direction that failed: the engine is still active, silent there.
     *
     * Safety
     *
     * Reads no memory the caller owns.
     */
    fun audioActivate(stack: Long) {
        check(SipralNative.sipral_audio_activate(stack))
    }

    /**
     * Close the devices and stop the pump. The calls stay attached and get
     * their audio back on the next activation.
     *
     * Safety
     *
     * Reads no memory the caller owns.
     */
    fun audioDeactivate(stack: Long) {
        check(SipralNative.sipral_audio_deactivate(stack))
    }

    /**
     * Ring on the ringer's device (or the loudspeaker) until
     * `sipral_audio_stop_ringing`, or once when `looped` is zero. Mono 16-bit
     * samples at `sample_rate_hz`, copied before return. Under automatic
     * activation a ring opens the devices.
     *
     * Safety
     *
     * `samples` must be readable for `sample_count` `int16_t`.
     */
    fun audioRing(stack: Long, samples: ShortArray, sampleRateHz: Long, looped: Long) {
        check(SipralNative.sipral_audio_ring(stack, samples, sampleRateHz, looped))
    }

    /**
     * Stop the ring. Under automatic activation, with no call up, the
     * devices close with it.
     *
     * Safety
     *
     * Reads no memory the caller owns.
     */
    fun audioStopRinging(stack: Long) {
        check(SipralNative.sipral_audio_stop_ringing(stack))
    }

    /**
     * What the engine is doing: whether it is active, whether the platform
     * cancels echo, the delay a canceller needs, and where each role runs.
     *
     * Safety
     *
     * `out_info` must point at a `sipral_audio_info_t` whose `size` member
     * says how long it is.
     */
    fun audioInfo(stack: Long): SipralAudioInfo {
        val infoSlots = LongArray(SipralAudioInfo.SLOTS)
        check(SipralNative.sipral_audio_info(stack, infoSlots))
        return SipralAudioInfo.of(infoSlots)
    }

    /**
     * Turn the platform's echo cancellation on or off on a running stack:
     * `on` is a `SipralToggle`, and zero leaves it.
     *
     * Open devices are reopened at once with or without the platform
     * processing, on the same devices with gain and mute, each reported as
     * `SIPRAL_AUDIO_CHANGE_REOPENED`. A call hears a short gap; a refused
     * direction is `SIPRAL_AUDIO_CHANGE_UNAVAILABLE`. Closed devices use it
     * on the next open. `sipral_audio_info_t` says what the platform did.
     * `SIPRAL_STATUS_WRONG_STATE` in application mode.
     *
     * Safety
     *
     * Reads no memory the caller owns.
     */
    fun audioSetSystemEchoCancellation(stack: Long, on: Long) {
        check(SipralNative.sipral_audio_set_system_echo_cancellation(stack, on))
    }

    /**
     * Send this stack's log to `callback`, at `level` and louder, or turn it
     * off with `SIPRAL_LOG_LEVEL_OFF` or a null callback.
     *
     * Off by default and free when off. A second call replaces callback and
     * level on this stack; queued lines go to the new callback. Turning off
     * drops the queue. Details: `docs/17-observability.md`. A level above
     * `SIPRAL_LOG_LEVEL_TRACE` is `SIPRAL_STATUS_INVALID_ARGUMENT`.
     *
     * Safety
     *
     * `callback`, when not null, is called inside later calls into this stack,
     * after the stack is released (see SipralLogCallback). `user_data`
     * must stay valid until the log is replaced or off and no thread is
     * inside this stack.
     */
    fun stackLog(stack: Long, level: Long, listener: SipralLogListener?) {
        // held across the call so that what SipralLogListeners records and what
        // the library installed cannot disagree
        synchronized(SipralLogListeners) {
            val callback = SipralLogListeners.register(listener)
            var status = -1
            try {
                status = SipralNative.sipral_stack_log(stack, level, callback)
            } finally {
                SipralLogListeners.installed(callback, status, stack)
            }
            check(status)
        }
    }

    /**
     * Copy a redacted snapshot of this stack into `buffer` for a crash
     * report: accounts and registrations, calls and states, transports, media
     * sessions, last refused calls, queues, RTP port range and counters. At
     * most `SIPRAL_STATE_TEXT_MAX` bytes with the NUL.
     *
     * Safe from any thread and never waits. If another thread holds the
     * stack, the last snapshot kept by a poll (at most once a second) is
     * returned, and its first line says so. A media session busy on a frame
     * is reported as busy.
     *
     * `SIPRAL_STATUS_BUFFER_TOO_SMALL`, with the length needed in `out_needed`,
     * when it does not fit; `out_needed` may be null.
     *
     * Safety
     *
     * `buffer` must be writable for `capacity` bytes or be null with a
     * capacity of zero, and `out_needed` must point at one `size_t` or be null.
     */
    fun stackStateText(stack: Long, buffer: ByteArray): Long {
        val neededSlot = LongArray(1)
        check(SipralNative.sipral_stack_state_text(stack, buffer, neededSlot))
        return neededSlot[0]
    }

    /**
     * Reserve a free even port from this stack's RTP range, with the odd
     * port above it kept for RTCP, and write it to `out_port`.
     *
     * `SIPRAL_STATUS_EXHAUSTED` when every pair is taken (the last error
     * gives the range size). `SIPRAL_STATUS_WRONG_STATE` without a range.
     *
     * Safety
     *
     * `out_port` must point at one `uint32_t`.
     */
    fun stackRtpPortReserve(stack: Long): Long {
        val portSlot = LongArray(1)
        check(SipralNative.sipral_stack_rtp_port_reserve(stack, portSlot))
        return portSlot[0]
    }

    /**
     * Give back a reserved port no call used. A port a call took comes back
     * by itself. `SIPRAL_STATUS_INVALID_ARGUMENT` for one not reserved,
     * including a second release.
     *
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun stackRtpPortRelease(stack: Long, port: Long) {
        check(SipralNative.sipral_stack_rtp_port_release(stack, port))
    }

    /**
     * Verify incoming callers against `config`'s trust anchors from now on
     * (RFC 8224 §6.2).
     *
     * Replaces any earlier setting. Reporting accounts verify only with at
     * least one anchor; `SIPRAL_STIR_VERIFICATION_STRICT` accounts always do.
     * `config.unix_seconds` sets the wall clock at `now_ms`; zero keeps the
     * previous one and is `SIPRAL_STATUS_WRONG_STATE` the first time. A stack
     * whose accounts only sign also calls this, with no anchors.
     *
     * `SIPRAL_STATUS_INVALID_ARGUMENT` for anchors that are not P-256
     * certificates; `SIPRAL_STATUS_NOT_SUPPORTED` without `SIPRAL_FEATURE_STIR`.
     *
     * Safety
     *
     * `config` must point at a `sipral_stir_config_t` whose `size` member
     * says how long it is, with `anchors` readable for `anchors_len` bytes.
     */
    fun stackStir(stack: Long, config: SipralStirConfig, nowMs: Long) {
        check(SipralNative.sipral_stack_stir(stack, config.anchors, config.freshnessSeconds, config.certificateWaitMs, config.unixSeconds, config.acceptServiceProviderCodes, config.reserved, nowMs))
    }

    /**
     * The certificate chain for a call's `Identity`, fetched from the URL of
     * `SIPRAL_VERIFICATION_STAGE_CERTIFICATE_WANTED`: PEM or DER, signing
     * certificate first. Null and zero if it could not be fetched.
     *
     * The verdict is reached and the call delivered or refused before this
     * returns; the events come from the next `sipral_stack_poll`.
     * `SIPRAL_STATUS_STALE_HANDLE` for a call no longer waiting.
     *
     * Safety
     *
     * `chain` must be readable for `chain_len` bytes, or null with a length
     * of zero.
     */
    fun callStirCertificate(stack: Long, call: Long, chain: ByteArray, nowMs: Long) {
        check(SipralNative.sipral_call_stir_certificate(stack, call, chain, nowMs))
    }

    /**
     * How many streams one call's encryption report has (one audio stream).
     *
     * Safety
     *
     * `out_count` must point at one `size_t`.
     */
    fun mediaEncryptionCount(media: Long): Long {
        val countSlot = LongArray(1)
        check(SipralNative.sipral_media_encryption_count(media, countSlot))
        return countSlot[0]
    }

    /**
     * How one stream of a call is protected now. An index past the end is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`.
     *
     * Safety
     *
     * `out_stream` must point at a `sipral_stream_encryption_t` whose `size`
     * member says how long it is.
     */
    fun mediaEncryptionAt(media: Long, index: Long): SipralStreamEncryption {
        val streamSlots = LongArray(SipralStreamEncryption.SLOTS)
        check(SipralNative.sipral_media_encryption_at(media, index, streamSlots))
        return SipralStreamEncryption.of(streamSlots)
    }

    /**
     * Listen for keypad digits in the far-end audio as `mode` (a
     * SipralDtmfDetection) says. `SIPRAL_STATUS_WRONG_STATE` if this
     * stack does not run the call's media.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callDtmfDetection(stack: Long, call: Long, mode: Long) {
        check(SipralNative.sipral_call_dtmf_detection(stack, call, mode))
    }

    /**
     * Listen for call progress and decide who answered, as `config` says;
     * `config.listen` off stops. Call right after `sipral_call_place`. Each
     * finding is a `SIPRAL_EVENT_KIND_PROGRESS_DETECTED`.
     *
     * `SIPRAL_STATUS_WRONG_STATE` if this stack does not run the call's media;
     * `SIPRAL_STATUS_INVALID_ARGUMENT` for a bad value, changing nothing.
     *
     * Safety
     *
     * `config` must point at a `sipral_progress_config_t` whose `size`
     * member says how long it is.
     */
    fun callDetectProgress(stack: Long, call: Long, config: SipralProgressConfig) {
        check(SipralNative.sipral_call_detect_progress(stack, call, config.listen, config.region, config.answeringMachine, config.beep, config.beepWindowMs, config.maxInitialSilenceMs, config.maxGreetingMs, config.silenceAfterGreetingMs, config.maxWords, config.minWordMs, config.minWordGapMs, config.maxDecisionMs, config.minSpeechAboveFloorDb, config.beepMinMs, config.beepMaxMs, config.toneCycles))
    }

    /**
     * Beep while the call is recorded, as `tone` says; `tone.enabled` off
     * silences it. Applies at once to a running recording.
     *
     * `SIPRAL_STATUS_WRONG_STATE` if this stack does not run the call's media;
     * `SIPRAL_STATUS_INVALID_ARGUMENT` naming the bad member, changing nothing.
     *
     * Safety
     *
     * `tone` must point at a `sipral_consent_tone_t` whose `size` member
     * says how long it is.
     */
    fun callConsentTone(stack: Long, call: Long, tone: SipralConsentTone) {
        check(SipralNative.sipral_call_consent_tone(stack, call, tone.enabled, tone.frequencyHz, tone.attenuationDb, tone.lengthMs, tone.intervalMs, tone.local))
    }

    /**
     * Start recording this call to `path` as `options` say. With every option
     * zero this is sipral_media_record_start.
     *
     * `SIPRAL_STATUS_INVALID_ARGUMENT` for invalid options or a refused path;
     * `SIPRAL_STATUS_NOT_SUPPORTED` for Ogg Opus in a build without Opus;
     * `SIPRAL_STATUS_RECORDING_FAILED` when the header could not be written.
     *
     * Safety
     *
     * `path` must be readable for `path_len` bytes, and `options` must point
     * at a `sipral_recording_options_t` whose `size` member says how long
     * it is.
     */
    fun mediaRecordStartWith(media: Long, path: String, options: SipralRecordingOptions) {
        val pathBytes = path.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_media_record_start_with(media, pathBytes, options.format, options.layout, options.sampleRate, options.bitrate, options.checkpointMs, options.reserved))
    }

    /**
     * Make a local conference on this stack, holding only this end if it
     * takes part, and write its handle to `out_conference`.
     *
     * In device mode the engine carries it at once, opening the devices
     * under automatic activation.
     *
     * `SIPRAL_STATUS_CONFERENCE_REFUSED` for a rate other than 8, 16, 32 or
     * 48 kHz, or more than 1024 members.
     *
     * Safety
     *
     * `config` must point at a `sipral_local_conference_config_t` whose
     * `size` says how long it is, and `out_conference` at one `sipral_handle_t`.
     */
    fun localConferenceCreate(stack: Long, config: SipralLocalConferenceConfig): Long {
        val conferenceSlot = LongArray(1)
        check(SipralNative.sipral_local_conference_create(stack, config.maxMembers, config.local, config.sampleRate, config.reserved, conferenceSlot))
        return conferenceSlot[0]
    }

    /**
     * End a conference. Its calls carry their own audio again (in device
     * mode the engine takes them back), a running recording is finished, and
     * the handle is stale.
     *
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun localConferenceDestroy(conference: Long) {
        check(SipralNative.sipral_local_conference_destroy(conference))
    }

    /**
     * Add a call, from the next tick, at its codec's rate; its far end hears
     * everybody but itself.
     *
     * The call needs running media. `SIPRAL_STATUS_CONFERENCE_REFUSED` when
     * full, for a call already in a conference or joined with
     * `sipral_call_join`, or for an unmixable codec (rate not 8, 16, 32 or
     * 48 kHz, or frames over 60 ms).
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun localConferenceAdd(conference: Long, call: Long) {
        check(SipralNative.sipral_local_conference_add(conference, call))
    }

    /**
     * Take a call out, from the next tick. Its media is the application's
     * again (in device mode, the engine's).
     *
     * `SIPRAL_STATUS_WRONG_STATE` for a call that is not in it.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun localConferenceRemove(conference: Long, call: Long) {
        check(SipralNative.sipral_local_conference_remove(conference, call))
    }

    /**
     * Mute or unmute one direction of a member from the next tick: input
     * (others stop hearing it) or output (it stops hearing).
     * `direction` is `SIPRAL_AUDIO_DIRECTION_INPUT` or `_OUTPUT`; `member` is a
     * call in the conference, or the conference handle for this end.
     *
     * `SIPRAL_STATUS_WRONG_STATE` for a member that is not in it.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun localConferenceSetMuted(conference: Long, member: Long, direction: Long, muted: Long) {
        check(SipralNative.sipral_local_conference_set_muted(conference, member, direction, muted))
    }

    /**
     * Set one direction's level for a member, from the next tick, in
     * `sipral_audio_set_gain` steps: 256 unity, 1024 at most. Input is what
     * others hear of it; output is what it hears.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun localConferenceSetGain(conference: Long, member: Long, direction: Long, gain: Long) {
        check(SipralNative.sipral_local_conference_set_gain(conference, member, direction, gain))
    }

    /**
     * How the conference stands.
     *
     * Safety
     *
     * `out_info` must point at a `sipral_local_conference_info_t` whose
     * `size` says how long it is.
     */
    fun localConferenceInfo(conference: Long): SipralLocalConferenceInfo {
        val infoSlots = LongArray(SipralLocalConferenceInfo.SLOTS)
        check(SipralNative.sipral_local_conference_info(conference, infoSlots))
        return SipralLocalConferenceInfo.of(infoSlots)
    }

    /**
     * One member by index: this end first if it takes part, then calls in
     * join order. Stable until the next join or leave.
     *
     * `SIPRAL_STATUS_INVALID_ARGUMENT` for an index past the last member.
     *
     * Safety
     *
     * `out_member` must point at a `sipral_local_conference_member_t` whose
     * `size` says how long it is.
     */
    fun localConferenceMemberAt(conference: Long, index: Long): SipralLocalConferenceMember {
        val memberSlots = LongArray(SipralLocalConferenceMember.SLOTS)
        check(SipralNative.sipral_local_conference_member_at(conference, index, memberSlots))
        return SipralLocalConferenceMember.of(memberSlots)
    }

    /**
     * Who talked in the last tick, loudest at index zero. Muted members are
     * never listed.
     *
     * `SIPRAL_STATUS_INVALID_ARGUMENT` past the last talker (count in
     * `sipral_local_conference_info_t::talkers`).
     *
     * Safety
     *
     * `out_member` must point at one `sipral_handle_t`.
     */
    fun localConferenceTalkerAt(conference: Long, index: Long): Long {
        val memberSlot = LongArray(1)
        check(SipralNative.sipral_local_conference_talker_at(conference, index, memberSlot))
        return memberSlot[0]
    }

    /**
     * 20 ms of conference in application mode. `mic` is this end's frame,
     * `sipral_local_conference_info_t::frame_samples` long; `speaker` gets
     * what this end hears, same length, written to `out_written`. Without
     * this end, `mic` may be null and `speaker` gets silence.
     *
     * Call every 20 ms from the audio thread, then drain
     * `sipral_local_conference_poll_transmit`.
     *
     * `SIPRAL_STATUS_WRONG_STATE` in device mode;
     * `SIPRAL_STATUS_INVALID_ARGUMENT` for a wrong frame length;
     * `SIPRAL_STATUS_BUFFER_TOO_SMALL` for a short speaker buffer, with the
     * length needed in `out_written`.
     *
     * Safety
     *
     * `mic` readable for `mic_count` `int16_t`, `speaker` writable for
     * `capacity` `int16_t`, `out_written` one `size_t` or null.
     */
    fun localConferenceTick(conference: Long, nowMs: Long, mic: ShortArray, speaker: ShortArray): Long {
        val writtenSlot = LongArray(1)
        check(SipralNative.sipral_local_conference_tick(conference, nowMs, mic, speaker, writtenSlot))
        return writtenSlot[0]
    }

    /**
     * The oldest packet a member's call owes its far end, in application
     * mode. `out_call` names the call whose socket sends it; `packet` is
     * filled as by `sipral_media_capture`. `len` zero with
     * `SIPRAL_HANDLE_NONE` means nothing waits. Drain after every tick.
     *
     * Safety
     *
     * `out_call` must point at one `sipral_handle_t`, and `packet` at a
     * `sipral_media_packet_t` as `sipral_media_capture` describes.
     */
    fun localConferencePollTransmit(conference: Long, packet: Long): Long {
        val callSlot = LongArray(1)
        check(SipralNative.sipral_local_conference_poll_transmit(conference, callSlot, packet))
        return callSlot[0]
    }

    /**
     * Record the whole conference mix to `path`, one channel, as `options`
     * say (WAV or Ogg Opus, at the conference rate unless another is named).
     *
     * `SIPRAL_STATUS_WRONG_STATE` if already recording;
     * `SIPRAL_STATUS_INVALID_ARGUMENT` for stereo, unusable options or a
     * refused path; `SIPRAL_STATUS_RECORDING_FAILED` if the header write fails.
     *
     * Safety
     *
     * `path` readable for `path_len` bytes; `options` a
     * `sipral_recording_options_t` whose `size` says how long it is.
     */
    fun localConferenceRecordStart(conference: Long, path: String, options: SipralRecordingOptions) {
        val pathBytes = path.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_local_conference_record_start(conference, pathBytes, options.format, options.layout, options.sampleRate, options.bitrate, options.checkpointMs, options.reserved))
    }

    /**
     * Stop recording the conference, and finish the file.
     *
     * `SIPRAL_STATUS_WRONG_STATE` when nothing is being recorded.
     *
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun localConferenceRecordStop(conference: Long) {
        check(SipralNative.sipral_local_conference_record_stop(conference))
    }

    /**
     * Hand the resolver's answer to a
     * SIPRAL_EVENT_KIND_LOOKUP_WANTED
     * back to the account that asked.
     *
     * `name` and `record` are the event's; `answer` is a SipralDnsAnswer.
     * With `SIPRAL_DNS_ANSWER_RECORDS`, `records` is comma-separated records,
     * each space-separated: TTL in seconds, then zone-file data. A/AAAA:
     * `300 192.0.2.40`; SRV: `300 10 60 5060 sip1.example.com`; NAPTR
     * without the regexp: `300 10 50 S SIP+D2U _sip._udp.example.com`.
     * Null or empty reads as `SIPRAL_DNS_ANSWER_NOTHING`.
     *
     * Answer every lookup, failures included: the procedure waits for each.
     * An answer nothing waits for any more is `SIPRAL_STATUS_OK` and changes
     * nothing.
     *
     * Safety
     *
     * `name` must be readable for `name_len` bytes and `records` for
     * `records_len`.
     */
    fun accountLookedUp(stack: Long, account: Long, name: String, record: Long, answer: Long, records: String, nowMs: Long) {
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        val recordsBytes = records.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_account_looked_up(stack, account, nameBytes, record, answer, recordsBytes, nowMs))
    }

    /**
     * Check the server's leaf certificate (DER) against the account's pin:
     * SHA-256 over the bytes, constant-time. `unix_seconds` is used only for
     * the reported dates.
     *
     * `SIPRAL_STATUS_OK` with `pinned` 1: accept. With `pinned` 0: no pin,
     * platform checks decide. `SIPRAL_STATUS_CERTIFICATE_REFUSED`: refuse;
     * nothing written.
     *
     * Safety
     *
     * `certificate` must be readable for `certificate_len` bytes, and
     * `out_pinned` must point at a `sipral_pinned_certificate_t` whose
     * `size` member says how long it is.
     */
    fun accountCheckCertificate(stack: Long, account: Long, certificate: ByteArray, unixSeconds: Long): SipralPinnedCertificate {
        val pinnedSlots = LongArray(SipralPinnedCertificate.SLOTS)
        check(SipralNative.sipral_account_check_certificate(stack, account, certificate, unixSeconds, pinnedSlots))
        return SipralPinnedCertificate.of(pinnedSlots)
    }

    /**
     * The `host:port` to advertise for a socket bound at `bound` whose
     * traffic goes to `peer` (both `host:port` addresses, not names),
     * NUL-terminated into `buffer`.
     *
     * A specific address is used as is; loopback toward a non-loopback
     * `peer` is `SIPRAL_STATUS_UNREACHABLE_ADDRESS`. A wildcard bind uses
     * the OS route toward `peer` (found without sending);
     * `SIPRAL_STATUS_TRANSPORT_DOWN` when there is none. Any thread.
     * `out_needed` gets the length with the NUL; `buffer` may be null with
     * `capacity` zero; `SIPRAL_STATUS_BUFFER_TOO_SMALL` writes nothing.
     *
     * Safety
     *
     * `bound` and `peer` must be readable for their lengths, `buffer` must
     * be writable for `capacity` bytes or be null with a capacity of zero,
     * and `out_needed` must point at one `size_t` or be null.
     */
    fun advertisedAddress(bound: String, peer: String, buffer: ByteArray): Long {
        val boundBytes = bound.toByteArray(Charsets.UTF_8)
        val peerBytes = peer.toByteArray(Charsets.UTF_8)
        val neededSlot = LongArray(1)
        check(SipralNative.sipral_advertised_address(boundBytes, peerBytes, buffer, neededSlot))
        return neededSlot[0]
    }

    /**
     * Turn the diagnostic trace on or off: `on` is a `SipralToggle`, zero
     * leaves it (ABI 0.34).
     *
     * On, the trace level writes whole SIP messages with the peer and no
     * pseudonyms, to compare runs. Credentials and keys are never written
     * (list in `sipral_stack_config_t::diagnostic_trace`). Off, the trace is
     * pseudonymised. Only applies at `SIPRAL_LOG_LEVEL_TRACE`.
     *
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun stackDiagnosticTrace(stack: Long, on: Long) {
        check(SipralNative.sipral_stack_diagnostic_trace(stack, on))
    }

    /**
     * The SRTP suites calls use by default, in order, as `sipral_srtp_suite_t`
     * numbers. `out_count` always receives the total; too small a capacity is
     * `SIPRAL_STATUS_BUFFER_TOO_SMALL`.
     *
     * Safety
     *
     * `out_suites` must be writable for `capacity` `uint32_t` or null with a
     * capacity of zero, and `out_count` must point at one `size_t` or be null.
     */
    fun stackSrtpSuiteOrder(stack: Long, outSuites: IntArray): Long {
        val countSlot = LongArray(1)
        check(SipralNative.sipral_stack_srtp_suite_order(stack, outSuites, countSlot))
        return countSlot[0]
    }

    /**
     * Set one call's own gain in one direction, on top of the stack's, in
     * `sipral_audio_set_gain` steps. Input is what the microphone sends that
     * call; output is how loud it plays. Kept through hold and conference,
     * gone when the call ends.
     *
     * In a local conference it acts on the call's path, on top of the
     * conference's member controls: input on what its far end hears, output
     * on what it says into the conference.
     * `SIPRAL_STATUS_WRONG_STATE` when the engine is not carrying the call's
     * media: before it starts, after it ends, or in application mode.
     *
     * Safety
     *
     * Reads no memory the caller owns.
     */
    fun audioCallSetGain(stack: Long, call: Long, direction: Long, gain: Long) {
        check(SipralNative.sipral_audio_call_set_gain(stack, call, direction, gain))
    }

    /**
     * One call's own gain in one direction, in `sipral_audio_set_gain` steps.
     *
     * Safety
     *
     * `out_gain` must point at one `uint32_t`.
     */
    fun audioCallGain(stack: Long, call: Long, direction: Long): Long {
        val gainSlot = LongArray(1)
        check(SipralNative.sipral_audio_call_gain(stack, call, direction, gainSlot))
        return gainSlot[0]
    }

    /**
     * Mute or unmute one call in one direction while other calls go on (a
     * consultation). A muted direction sends silence. Kept, dropped and
     * refused as `sipral_audio_call_set_gain` is, conference included.
     *
     * Safety
     *
     * Reads no memory the caller owns.
     */
    fun audioCallSetMuted(stack: Long, call: Long, direction: Long, muted: Long) {
        check(SipralNative.sipral_audio_call_set_muted(stack, call, direction, muted))
    }

    /**
     * Whether one call is muted in one direction: one or zero.
     *
     * Safety
     *
     * `out_muted` must point at one `uint32_t`.
     */
    fun audioCallMuted(stack: Long, call: Long, direction: Long): Long {
        val mutedSlot = LongArray(1)
        check(SipralNative.sipral_audio_call_muted(stack, call, direction, mutedSlot))
        return mutedSlot[0]
    }

    /**
     * One call's meter in one direction, after its own gain and mute: what
     * `sipral_audio_level` reads, for one call of several.
     *
     * Safety
     *
     * `out_peak` must point at one `uint32_t`.
     */
    fun audioCallLevel(stack: Long, call: Long, direction: Long): Long {
        val peakSlot = LongArray(1)
        check(SipralNative.sipral_audio_call_level(stack, call, direction, peakSlot))
        return peakSlot[0]
    }

}
