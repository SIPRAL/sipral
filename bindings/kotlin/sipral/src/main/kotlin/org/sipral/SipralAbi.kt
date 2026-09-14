// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// Printed from the declarations in crates/sipral-ffi by tools/abi-gen.
// Do not edit: `cargo run -p sipral-abi-gen` writes it again, and
// `scripts/check.sh` fails when what is committed is not what came out.

package org.sipral

/**
 * The result of a call across the C ABI.
 *
 * The numbers are part of the ABI. A value keeps its meaning for the life of
 * the ABI's major version, and a new one is only ever added at the end.
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
     * The library has no room for another object of this kind.
     */
    EXHAUSTED(7),
    /**
     * A panic was caught at the boundary. The call did not finish, and the
     * last error carries whatever the panic said.
     */
    PANIC(8),
    /**
     * What was asked for cannot be done where the object is: answering a call
     * this end placed, holding one that is not up, sending DTMF before there
     * is a dialog to send it in. Not an argument that was wrong; a moment
     * that was.
     */
    WRONG_STATE(9),
    /**
     * The request could not be assembled or handed to a transport. Nothing
     * went out, and nothing about the call changed.
     */
    NOT_SENT(10),
    /**
     * The value is one this ABI has a word for and this build has no code
     * behind. Nothing was applied, and asking again will not change that.
     *
     * The third of the three answers a configuration call may give, and the
     * one that has to be told apart from the other two by a machine.
     * SipralStatus.INVALID_ARGUMENT says the value is wrong and a
     * corrected one would be taken; this says the value is right and there is
     * nothing here to take it. SipralStatus.UNSUPPORTED_VERSION is about
     * the shape of what crossed the boundary, not about what was set in it.
     *
     * It exists so that "accepted and ignored" is not a thing this library
     * can do. An application that gets it turns the control off, because the
     * control is genuinely dead in this build; one that gets a silence
     * instead ships a control that does nothing and finds out from a
     * customer.
     */
    NOT_SUPPORTED(11),
    ;

    companion object {
        fun of(value: Int): SipralStatus? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a stack speaks. Names for `sipral_stack_config_t::transport`.
 *
 * Zero is not one of them: a stack is told what it is speaking, because
 * guessing wrong in the direction of the plainest transport is how a caller
 * that meant TLS ends up on the wire in the clear.
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
 * Why a transport could not deliver. Names for
 * sipral_stack_transport_failed's `error`.
 *
 * Coarse on purpose, and it is the layer below that is coarse: a client
 * transaction informs its user and terminates on every one of these (§17), and
 * the detail belongs in the caller's log, where the real message still is.
 */
enum class SipralTransportError(val value: Int) {
    /**
     * Anything the caller could not classify. Zero, because a caller that
     * knows only that the write failed is telling the truth by saying nothing.
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
 * The three answers a setting can give in a struct that starts out zeroed.
 *
 * A boolean cannot carry them. Zero is what a caller who filled nothing in
 * leaves behind, so a plain `0`/`1` setting has no way to say "off" that is
 * not also "I said nothing", and the difference is the whole of B2: the
 * library must not turn a control off because the caller never touched it.
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
 * Zero is not one of them, and it is not the same absence on the two
 * structs: on the stack it means this build's own built-in default
 * (`SrtpPolicy::default()`, which is SipralSrtp.NOT_OFFERED); on a
 * call it means the stack's own setting, whatever that came to. The three
 * values mean exactly what `sipral::SrtpPolicy`'s three variants mean —
 * see there for what each writes and what each answers.
 */
enum class SipralSrtp(val value: Int) {
    /**
     * SrtpPolicy::NotOffered: do not offer it, but answer an offer
     * that arrives on the secure profile with keys anyway.
     */
    NOT_OFFERED(1),
    /**
     * SrtpPolicy::Offered: offer it, and answer a plain offer
     * plainly.
     */
    OFFERED(2),
    /**
     * SrtpPolicy::Required: offer it, and let no stream on this call
     * carry audio unencrypted.
     */
    REQUIRED(3),
    ;

    companion object {
        fun of(value: Int): SipralSrtp? = entries.firstOrNull { it.value == value }
    }
}

/**
 * One codec this ABI has a number for. Names for every member that says
 * which.
 *
 * A value here is permanent, and that is all it is: a number that has left
 * this header is spent for good, so a binding compiled against one keeps
 * working whatever a later build contains. Whether *this* build can produce
 * the codec is a different question, and `SIPRAL_FEATURE_*` together with
 * `sipral_codec_at` are what answer it. A settings screen that offers this
 * list unfiltered is a settings screen with controls that do nothing, which
 * is the mistake `sipral_capabilities` exists to prevent.
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
     * Opus. Declared in every build, whether or not this one linked
     * libopus, for the reason the enumeration above gives. Whether the
     * codec is here is `SIPRAL_FEATURE_OPUS` and the list
     * `sipral_codec_at` enumerates, never the presence of this name.
     */
    OPUS(4),
    ;

    companion object {
        fun of(value: Int): SipralCodec? = entries.firstOrNull { it.value == value }
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
 * Why media failed. Names for `sipral_media_event_t::fault`.
 *
 * The sentence beside it says which case of the kind it was; this is the part
 * a machine acts on, and the two are never the same thing.
 */
enum class SipralMediaFault(val value: Int) {
    /**
     * Nothing failed.
     */
    NONE(0),
    /**
     * The negotiation settled on something this build cannot encode or
     * decode, which means the peer answered with a format that was not in the
     * offer.
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
    ;

    companion object {
        fun of(value: Int): SipralArrival? = entries.firstOrNull { it.value == value }
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
 * Which way a digit goes to the far end. Names for
 * sipral_call_send_dtmf's `via`.
 *
 * The choice is per send, not per call, because it is a fact about the peer
 * rather than about this end, and the way to find out which one a peer takes
 * is to try. A carrier that ignores one of these ignores it silently.
 */
enum class SipralDtmf(val value: Int) {
    /**
     * In the media, as an RFC 4733 named telephone event. What to reach for:
     * it is the only one carried end to end by every gateway on the path, and
     * the only one whose timing survives transcoding.
     */
    RTP(0),
    /**
     * An INFO per digit carrying `application/dtmf-relay`, which states the
     * signal and how long it was held.
     */
    INFO_RELAY(1),
    /**
     * An INFO per digit carrying `application/dtmf`, whose whole body is the
     * character. Some switches take only this one.
     */
    INFO_PLAIN(2),
    ;

    companion object {
        fun of(value: Int): SipralDtmf? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What an event is about.
 *
 * The numbers are part of the ABI and are only ever added to. A binding
 * that meets a kind it does not know must ignore that event rather than
 * refuse it, which is what makes adding one safe.
 *
 * Numbers already spent on features this build does not have:
 * - 15: a subscription's state changed (A1)
 * - 16: the set of audio devices changed (A2)
 * - 18: a request was promoted to a stream transport (B1)
 * - 20: a call was announced and never arrived (C2)
 * - 27: a DTMF digit sent by SIP INFO was answered
 * - 28: the stack recovered from a suspension or a network change
 * - 29: the application is asked to resolve a destination
 */
enum class SipralEventKind(val value: Int) {
    /**
     * The stack is running on this thread.
     *
     * The first event on every stack, delivered by the first poll and never
     * again. A binding that has a callback to hand out, a queue to open or a
     * thread to name has somewhere definite to do it, before anything that
     * matters can arrive.
     */
    STARTED(1),
    /**
     * A registration moved: it went out, it took, it is being refreshed, it
     * was given up, or it failed. `payload.registration` says which, and
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
     * And how it ended.
     */
    TRANSFER_DONE(12),
    /**
     * A call arrived carrying a `Replaces` and took over one already up.
     * `payload.call.other` is the one being replaced.
     */
    CALL_REPLACED(13),
    /**
     * The call is over, and its handle is stale from here on.
     */
    CALL_ENDED(14),
    /**
     * What one call's media cost, delivered once, after
     * `SIPRAL_EVENT_KIND_CALL_ENDED`.
     *
     * A6's second consumer. `payload.media.statistics` points at the
     * completed record; it is the library's and lives as long as the callback
     * does. The stream is gone by the time this arrives, which is why the
     * numbers travel in the event rather than behind a lookup that would now
     * fail.
     */
    MEDIA_STATISTICS(17),
    /**
     * Nothing has arrived on the media path for longer than the configured
     * threshold, while signalling is perfectly happy.
     *
     * B5. `payload.media.silent_for_ms` says how long. The call is untouched:
     * whether to hang up over silence is a decision with a person on the other
     * end of it.
     */
    MEDIA_STALLED(19),
    /**
     * Audio is running: the negotiation settled and an RTP session is open.
     *
     * A4's reporting half and the first half of D5: `payload.media.codec` is
     * what the two ends agreed on. This is the moment to mint the call's
     * media handle with `sipral_call_media`, and `sipral_media_info` on it
     * says the rest.
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
     * A recording stopped on its own, part-way through: the disk filled, the
     * file went away, the volume was unmounted.
     *
     * Never an abort. `payload.media.recorded_ms` says how much audio reached
     * the file before it stopped, and the call carries on without it.
     */
    RECORDING_STOPPED(25),
    /**
     * The far end pressed a key (RFC 4733).
     *
     * One per keypress, not one per packet: a digit goes out as a run of
     * updates and then its closing packet three times, and the layer below
     * collapses them on the timestamp that identifies the event.
     * `payload.media.digit` is the character, `event_code` the number behind
     * it for the events no keypad has a key for, and `held_ms` how long it
     * lasted.
     */
    DIGIT_RECEIVED(26),
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
     * A binding a registrar really granted, over a transport that has since
     * been suspended or lost, which nothing has proved since.
     *
     * Not registered, because it is no longer evidence; not failed, because
     * nothing refused it. A monotonic clock does not advance while a machine
     * sleeps, so a stack that slept eight hours comes back believing eight
     * milliseconds passed and every binding still valid — this is the state
     * that says otherwise, and an application that shows a line as ready on
     * the strength of it will show it ready when it is not.
     */
    UNVERIFIED(8),
    /**
     * A binding read back from a snapshot rather than granted in this
     * process. It has not been proved either.
     */
    RESTORED(9),
    /**
     * The account was configured with no registrar and never registers:
     * a trunk that knows this end by its address. It starts here and
     * stays here, and `sipral_account_register` refuses it. Not idle,
     * which is one `sipral_account_register` away from a binding.
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
) {
    internal companion object {
        const val SLOTS: Int = 4

        fun of(slots: LongArray): SipralAbiVersion = SipralAbiVersion(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
        )
    }
}

/**
 * What this build of the library can do: codecs compiled in, transports
 * this ABI carries signalling over, and which optional features are
 * present.
 *
 * Nothing here is configuration — this answers "can this build ever do X",
 * never "is X turned on for this stack". `sipral_stack_settings` answers
 * that once a stack exists, and `sipral_codec_count` /
 * `sipral_stack_codec_order` already enumerate the codecs this reports only
 * the count of, so this does not repeat what they say.
 *
 * Set `size` to `sizeof(sipral_capabilities_t)` before the call.
 */
data class SipralCapabilities(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * How many codecs this build contains. `sipral_codec_count` gives the
     * same number; `sipral_codec_at` says which, and in what order they are
     * offered by default.
     */
    val codecCount: Long,
    /**
     * Which transports this build carries signalling over, as the bits
     * named `SIPRAL_TRANSPORT_BIT_*`.
     */
    val transports: Long,
    /**
     * Which optional features this build has compiled in, as the bits named
     * `SIPRAL_FEATURE_*`.
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
 *
 * Every member here is monotonic except `active_calls`, which is a gauge:
 * it can be read as smaller than an earlier reading, and none of the others
 * ever will be. Set `size` to `sizeof(sipral_counters_t)` before the call.
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
     * How many times inbound audio stopped for longer than the configured
     * threshold while signalling stayed healthy (B5).
     */
    val mediaGaps: Long,
    /**
     * How many times a call's jitter buffer had to shrink or stretch the
     * stream to keep its delay where it was aiming.
     */
    val jitterBufferEvents: Long,
    /**
     * How many times a request would not fit a datagram and there was no
     * stream to the destination to put it on, so the stack asked for one
     * (RFC 3261 §18.1.1, B1).
     *
     * A request promoted onto a connection that already existed does not
     * raise it; those are in the diagnostic record instead.
     */
    val streamTransportWanted: Long,
    /**
     * Calls with media running right now. The one gauge in this struct: it
     * moves both ways, and it is what every other member here is not.
     */
    val activeCalls: Long,
    /**
     * Events a poll raised and had nowhere to queue, because the
     * callback had not kept up and the outbox was already at its ceiling
     * (task 8.4.21). Appended here rather than woven in among the
     * others: it counts something about delivery itself rather than
     * about a call or a registration, and a build from before it existed
     * still reads every counter that did.
     */
    val eventsDropped: Long,
    /**
     * RTCP goodbyes dropped, oldest first, because the application had
     * not called `sipral_stack_poll_farewell` and the queue behind it
     * was already at its ceiling. Appended at the tail for the same
     * reason `events_dropped` was: a build from before this member
     * existed still reads every counter that did.
     */
    val farewellsDropped: Long,
) {
    internal companion object {
        const val SLOTS: Int = 21

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
        )
    }
}

/**
 * What one call to sipral_stack_poll did.
 *
 * Set `size` to `sizeof(sipral_poll_result_t)` before the call.
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
     * Events the stack raised that this ABI has no word for yet.
     *
     * Counted rather than delivered: an event carrying nothing a binding can
     * act on is noise, and a number that is not zero is the honest measure of
     * how far this vocabulary is behind the stack's.
     */
    val eventsUnclaimed: Long,
    /**
     * Bytes the stack produced and this build had nowhere to send.
     *
     * Zero since crate::transport gave them somewhere to go: what the stack
     * writes waits in it until `sipral_stack_poll_transmit` takes it, and a
     * poll no longer empties the queue on its way past. The member stays
     * because a released one always does, and because a build that has to drop
     * a message again would have somewhere to say so.
     */
    val transmitsDiscarded: Long,
    /**
     * Whether there is a deadline at all. Zero means nothing is scheduled and
     * the next poll can wait for input.
     */
    val hasDeadline: Long,
    /**
     * How long from `now_ms` until the stack has something to do, when
     * `has_deadline` says there is one. Zero means it is already due.
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
 * What a stack is actually running with.
 *
 * A configuration call that answers `SIPRAL_STATUS_OK` has applied what it was
 * given, and this is where the caller reads back what that came to. It matters
 * because a zero in the config means "the default": a caller that left the
 * timers alone has no other way to learn which figures it is retransmitting
 * on, and one that set them has no other way to be sure.
 *
 * Set `size` to `sizeof(sipral_stack_settings_t)` before the call.
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
     * Whether this stack retransmits anything itself.
     *
     * Zero on a transport that delivers for us, which is every one but UDP.
     * The two timers that only exist to pace a retransmission read as their
     * defaults there, and mean nothing.
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
     * How many codecs this stack offers. `sipral_stack_codec_order` says
     * which, and in what order.
     */
    val codecCount: Long,
    /**
     * How long a frame is, with the default filled in.
     */
    val frameMs: Long,
    /**
     * Whether named events are offered, as a `SipralToggle`. Never the
     * default value: this says what the setting came to, not what was passed.
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
     * How long inbound audio may stop before it is reported, with the default
     * filled in. Zero when the watchdog is off, which is the one case where
     * there is no figure to give.
     */
    val mediaStallMs: Long,
) {
    internal companion object {
        const val SLOTS: Int = 12

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
     * The rate the codec actually hears at, which is what the samples crossing
     * this ABI are in. G.722's two differ, and RFC 3551 §4.5.2 says so.
     */
    val sampleRate: Long,
    /**
     * The payload type RFC 3551 table 4 assigns it, when it has one.
     */
    val staticPayloadType: Long,
    /**
     * Whether it has one. Opus does not: it is newer than the table and
     * always travels as a dynamic type.
     */
    val hasStaticPayloadType: Long,
) {
    internal companion object {
        const val SLOTS: Int = 6

        fun of(slots: LongArray): SipralCodecInfo = SipralCodecInfo(
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
 * What one call's media settled on, and what it is doing now.
 *
 * A4's reporting half and as much of D5 as this stack knows: the codec that
 * was agreed, the number it travels under, and the shape of the stream around
 * it. What is deliberately not here is why each other candidate lost —
 * RFC 3264 §6.1 leaves that decision with the peer, and a reason invented on
 * this side would be a reason nobody can act on.
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
     * The payload type on the wire. It is the offer's own number and not
     * necessarily ours: the two ends pick their own numbers for a format
     * with no static one, so a peer that numbers it 111 has said what we
     * say with 96.
     */
    val payloadType: Long,
    /**
     * The RTP timestamp clock, in hertz.
     */
    val clockRate: Long,
    /**
     * The rate the samples crossing this ABI are at.
     */
    val sampleRate: Long,
    /**
     * How long a frame is, in milliseconds.
     */
    val frameMs: Long,
    /**
     * Samples in one frame: exactly what sipral_media_playback fills and
     * what sipral_media_capture wants.
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
) {
    internal companion object {
        const val SLOTS: Int = 17

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
        )
    }
}

/**
 * What one call's media has cost, and what it is costing now.
 *
 * A6. Cheap enough to read at the frame rate of a user interface — everything
 * in it is already counted and nothing walks a history — and complete enough
 * to keep as the record of a call, which is the same struct delivered with
 * `SIPRAL_EVENT_KIND_MEDIA_STATISTICS` when the call ends.
 *
 * The three delays are in microseconds and not milliseconds. Jitter on a
 * healthy call is a fraction of a millisecond, and a figure that reads zero
 * whenever things are going well is a figure nobody looks at twice.
 *
 * Set `size` to `sizeof(sipral_stream_stats_t)` before the call.
 */
data class SipralStreamStats(
    /**
     * How many bytes of this struct the library filled in.
     */
    val size: Long,
    /**
     * A SipralCodec: what the call settled on, which is the first thing
     * anybody looking at a bad call wants to know.
     */
    val codec: Long,
    /**
     * Whether a round-trip time is known. Zero until a report has come back,
     * which on a short call may be never: the first one is deliberately
     * delayed (RFC 3550 §6.2) and a peer that sends no RTCP never provides
     * one.
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
     * Frames dropped in a pause to bring the delay down. Deliberate, and
     * inaudible when the pause is real.
     */
    val framesShrunk: Long,
    /**
     * Frames the concealment was asked to invent in a pause to push the delay
     * up.
     */
    val framesStretched: Long,
    /**
     * How far behind the newest packet the playout point is: the delay the
     * far end's voice is actually suffering.
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
     * Frames concealed as a fraction of frames played, over the last ten
     * seconds or so. The counters above say what the call has cost; this says
     * whether it is bad right now.
     */
    val lossRate: Float,
    /**
     * One number for a bar on a screen: a hundred for a call with nothing
     * wrong with it, zero for one nobody can hold. Not a mean opinion score,
     * and deliberately not shaped like one.
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
) {
    internal companion object {
        const val SLOTS: Int = 21

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
        )
    }
}

/**
 * One header field an application hands over: a name and a value, UTF-8,
 * neither NUL-terminated.
 *
 * Always an element of an array whose length travels beside it, which is
 * why it carries no `size`: an array is strided by the length of its
 * element, so a member appended here would move every element after the
 * first. A header field is a name and a value, and this never grows.
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
 * What a stack is created with.
 *
 * Set `size` to `sizeof(sipral_stack_config_t)` and zero the rest before
 * filling anything in. Four members have to be filled: the callback, the
 * transport, the address this end is reachable at, and the entropy. Nothing
 * here can be guessed on the caller's behalf.
 *
 * Built here and copied into the C struct by the JNI shim, which sets the
 * size member itself: a field left at its default is the zero the struct
 * would have held.
 */
class SipralStackConfig(
    /**
     * Where events go. Required: a stack with nowhere to report to is a
     * stack whose failures are invisible.
     */
    val eventListener: SipralEventListener? = null,
    /**
     * A SipralTransport.
     */
    val transport: Long = 0,
    /**
     * The address the far end reaches this one at, as `host:port`, UTF-8 and
     * not NUL-terminated.
     *
     * It goes in every `Via`, so it is the address a response has to come
     * back to rather than whatever a wildcard socket was bound to. Nothing
     * here opens a socket or resolves a name.
     */
    val bindAddress: String? = null,
    /**
     * What to put in `User-Agent` on every request this stack originates —
     * REGISTER and INVITE — or null for none.
     *
     * Not on responses, and not on a request sent inside a dialog: those are
     * written a layer below this one, which has no opinion about product
     * names. The field is optional on every method — §20 Table 3 marks it `o`
     * throughout — so a message that goes out without it is still well formed.
     */
    val userAgent: String? = null,
    /**
     * Thirty-two bytes of entropy, from the platform's own generator.
     *
     * Every branch parameter, tag and `Call-ID` is derived from it, and
     * §19.3 wants a tag unguessable — cryptographically random, not a
     * counter or a clock. Two stacks must never be given the same bytes.
     *
     * Not the media keys: those come from `media_seed`, and the reason
     * they are a separate draw is that a replay recording carries this
     * one in clear.
     */
    val entropy: ByteArray? = null,
    /**
     * T1 in milliseconds, or zero for the 500 ms of §17.1.1.1.
     *
     * In force on every transport: 64·T1 is how long a transaction has to
     * finish, whether or not anything retransmits.
     */
    val timerT1Ms: Long = 0,
    /**
     * T2 in milliseconds, or zero for four seconds.
     *
     * The cap on the doubling that starts at T1, and therefore only a figure
     * on a transport that retransmits. Setting it on anything but UDP is
     * `SIPRAL_STATUS_INVALID_ARGUMENT` rather than a value nothing reads.
     */
    val timerT2Ms: Long = 0,
    /**
     * T4 in milliseconds, or zero for five seconds.
     *
     * How long a message lingers in the network, which is what timers I and K
     * wait out. Zero on a transport that delivers for us, so it is refused
     * there the same way T2 is.
     */
    val timerT4Ms: Long = 0,
    /**
     * The codecs to offer, in the order to offer them: their names, separated
     * by commas, as UTF-8 and not NUL-terminated. Null for everything this
     * build contains, quality first.
     *
     * A4. The order is the whole of the negotiation's outcome — RFC 3264 §6.1
     * has the peer's preference decide among what both ends list — and it is
     * configured per site rather than fixed, because a carrier that bills by
     * the minute wants the narrowband codec first and a company on its own
     * network wants the wideband one.
     *
     * A name this build has no encoder for is `SIPRAL_STATUS_NOT_SUPPORTED`
     * here, with the names it does have in the last error. It is never taken
     * and ignored: a setting that is accepted and then quietly dropped is the
     * failure neither end can see.
     */
    val codecs: String? = null,
    /**
     * How long a frame is, in milliseconds, or zero for twenty.
     *
     * Twenty is what every peer expects and what every codec here cuts
     * cleanly. Opus has a fixed set of frame durations and encodes nothing
     * else, so an interval it has no size for is refused while Opus is one of
     * the codecs offered.
     */
    val frameMs: Long = 0,
    /**
     * Whether to offer RFC 4733 named events, as a `SipralToggle`. On by
     * default: a phone that cannot send a digit cannot navigate a menu.
     */
    val offerDtmf: Long = 0,
    /**
     * Whether to ask for RFC 5761 multiplexing, as a `SipralToggle`.
     *
     * Off by default. §5.1.1 only permits it where both ends asked, and the
     * equipment this stack is deployed against does not; asking unasked costs
     * a line in every offer and buys a port on the calls where nobody answers.
     */
    val offerRtcpMux: Long = 0,
    /**
     * Whether to stop sending during silence, as a `SipralToggle`.
     *
     * Off by default. It halves the bandwidth of a call in which one person is
     * listening, and it costs the far end's own stall watchdog a reason to
     * fire — this stack sends no comfort noise of its own to say the silence
     * is deliberate, so a gap looks the same from there as a stream that died.
     */
    val silenceSuppression: Long = 0,
    /**
     * Whether inbound audio that stops is reported, as a `SipralToggle`. On by
     * default; this is B5.
     */
    val mediaStallWatchdog: Long = 0,
    /**
     * How long inbound audio may stop before that is reported, in
     * milliseconds, or zero for this build's own figure.
     *
     * Setting it with the watchdog switched off is
     * `SIPRAL_STATUS_INVALID_ARGUMENT` rather than a value nothing reads.
     */
    val mediaStallMs: Long = 0,
    /**
     * What the wall clock read when the stack was created, as seconds since
     * 1 January 1970, or zero.
     *
     * The one number a stack that reads no clock cannot work out: RFC 3550
     * §6.4.1 has a sender report carry "the wall clock time when this report
     * was sent", and a monotonic instant is not one. Zero means the reports
     * count from the Unix epoch, which costs nothing a caller is likely to
     * miss — the round trip the far end computes is a difference, not an
     * absolute — and costs the correlation of this call's media with anything
     * else's.
     */
    val mediaClockUnixSeconds: Long = 0,
    /**
     * Thirty-two more bytes of entropy, for the media keys, and **not
     * the same bytes as `entropy`**.
     *
     * Every SRTP master key this stack offers or answers with is derived
     * from these and from nothing else. They are a second draw rather
     * than a slice of the first because a replay recording writes
     * `entropy` into the file in clear: one generator for both would put
     * every key the stack will ever offer into every recording it makes.
     *
     * Handing the same bytes twice is refused rather than accepted
     * quietly. This is the only place in the library that can see both.
     */
    val mediaSeed: ByteArray? = null,
    /**
     * What every call on this stack does about SRTP unless
     * `sipral_call_config_t::srtp` says otherwise for it: a
     * `SipralSrtp`, or zero for this build's own built-in default, which
     * is `SIPRAL_SRTP_NOT_OFFERED` — nothing here offers encryption
     * until it is asked to. Any other value is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`, and nothing is built.
     */
    val srtp: Long = 0,
)

/**
 * What an account is configured with.
 *
 * Set `size` to `sizeof(sipral_account_config_t)` and zero the rest before
 * filling anything in.
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
     *
     * A `registrar_len` of zero makes an account that never registers: a
     * trunk that knows this end by the address its requests come from.
     * Its state is `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING` for as long
     * as it exists, and `sipral_account_register` refuses it.
     */
    val registrar: String? = null,
    /**
     * Where this endpoint can be reached, as it goes in `Contact`.
     */
    val contact: String? = null,
    /**
     * Where this account's requests go, as `host:port`: the registrar's
     * address for an account that registers, and the outbound proxy for
     * one configured with no registrar. A call that names no destination
     * of its own goes here either way, so it is required either way. An
     * address, not a name: RFC 3263 resolution is the caller's.
     */
    val registrarAddress: String? = null,
    /**
     * The display name that goes in `From`, or null for none.
     */
    val displayName: String? = null,
    /**
     * The user name to answer a challenge with, or null for an account that
     * answers none.
     */
    val authUser: String? = null,
    /**
     * The password that goes with it. Copied out of the caller's memory; what
     * happens to the caller's copy is the caller's.
     */
    val authPassword: String? = null,
    /**
     * The `+sip.instance` URN of RFC 5626 §4.1, or null for none.
     */
    val instanceId: String? = null,
    /**
     * How long a binding to ask for, or zero for an hour.
     *
     * A `delta-seconds`, so §20.19 bounds it at 2³²−1 and anything above that
     * is refused rather than sent as a number no registrar will read. What the
     * registrar grants wins over the request either way, and the granted
     * figure is what `sipral_registration_event_t::expires_ms` carries — that
     * is where the effective value is read back, not here.
     */
    val expiresSeconds: Long = 0,
    /**
     * Header fields to put on every REGISTER this account sends, in the
     * order given, or null for none.
     *
     * Checked when the account is added, as `sipral_call_config_t::headers`
     * is, against what the stack writes on a REGISTER: `Expires` is the
     * stack's there, because it is `expires_seconds`, and `Supported` is the
     * application's, because a registration asking for a GRUU has to say
     * so. Refused for an account with no registrar, which sends no REGISTER
     * to put them on.
     */
    val headers: List<SipralHeader>? = null,
)

/**
 * What a call is placed with.
 *
 * Set `size` to `sizeof(sipral_call_config_t)` and zero the rest before
 * filling anything in.
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
     * The session description to offer, for a call this stack manages no
     * audio for.
     *
     * Exactly one of this and `media_address` is set. Two descriptions of one
     * session is one too many, and neither is a call whose answer would have
     * to be written into the ACK.
     */
    val sdp: ByteArray? = null,
    /**
     * Where to send the INVITE, as `host:port`, or null to send it where the
     * account registers — which is the outbound proxy for a registered line,
     * and the reason a phone behind a NAT works at all.
     */
    val destination: String? = null,
    /**
     * Whether to keep every branch a proxy forks the INVITE into. Zero keeps
     * the first that answers and hangs up the rest, which is what a telephone
     * does.
     */
    val keepAllForks: Long = 0,
    /**
     * Where this end will receive media, as `host:port`, for a call this
     * stack describes and runs the audio of.
     *
     * The application owns the socket, so it is the only one that can say. Set
     * it and the offer is written from this stack's codec order, the answer is
     * read, and the call gets a media session that `crate::media` and
     * `crate::record` reach. Leave it null and set `sdp` instead for a call
     * where the application describes its own session and runs its own RTP.
     */
    val mediaAddress: String? = null,
    /**
     * Header fields to put on the INVITE, in the order given, or null for
     * none.
     *
     * Each is checked before anything is built: the name a token, the value
     * one line of text, and not a field the stack writes on a call itself.
     * Those are listed in `docs/04-ua.md` with the reason for each, and
     * `User-Agent` joins them when `sipral_stack_config_t::user_agent` is
     * set. A refusal is `SIPRAL_STATUS_INVALID_ARGUMENT` naming the element,
     * and no call.
     */
    val headers: List<SipralHeader>? = null,
    /**
     * What this call does about SRTP, overriding
     * `sipral_stack_config_t::srtp` for it: a `SipralSrtp`, or zero to
     * take the stack's own setting. Any other value is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`, and nothing is built.
     *
     * Read only for a call this stack describes the media of —
     * `media_address` set — and otherwise not this ABI's to act on: a
     * call placed with `sdp` is a session the application wrote, and
     * SRTP in it is the application's own line to write or not.
     */
    val srtp: Long = 0,
)

/**
 * Something the library has to tell the application.
 *
 * The pointer handed to the callback is the library's, and it is valid for
 * the duration of that call and no longer. `size` says how much of the
 * struct this build filled in, and a binding reads no further than that. The
 * union stays the last member for the same reason: an arm that grows grows
 * the tail, which is the one place a released struct may change.
 *
 * `payload` is not carried here. Which of its arms the library wrote is named
 * by another member, and nothing in the declarations says which value names
 * which arm, so this binding does not guess.
 */
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
     * The SIP message behind it, whole and unparsed, when there is one.
     *
     * A reason phrase, a `Retry-After`, the `Contact` of a redirect and the
     * caller's display name all live here and none of them is worth a member
     * of its own. Null when the event came from no single message.
     */
    val message: ByteArray?,
)

/**
 * The one callback a stack has.
 *
 * It is called from inside `sipral_stack_poll`, on the thread that called
 * it, with the `user_data` the stack was created with, and never on two
 * threads at once for one stack. It must not unwind. Nothing is held
 * while it runs, so it may call back into the library, the stack it was
 * given included: see crate::stack.
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

    /** Let go of the listener a destroyed handle was made with. */
    fun gone(handle: Long) {
        synchronized(this) {
            val key = handles.remove(handle) ?: return
            listening.remove(key)
        }
    }

    /** Called by the JNI shim, once per event, on the thread that polls. */
    @JvmStatic
    fun deliver(key: Long, size: Long, stack: Long, kind: Long, account: Long, call: Long, message: ByteArray?) {
        val listener = synchronized(this) { listening[key] } ?: return
        try {
            listener.onEvent(SipralEvent(size, stack, kind, account, call, message))
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
        agree(0, 9)
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

    external fun sipral_last_error_message(buffer: ByteArray, len: LongArray): Int
    external fun sipral_status_name(status: Long): String?
    external fun sipral_abi_version(version: LongArray): Int
    external fun sipral_abi_check(major: Long, minor: Long): Int
    external fun sipral_abi_struct_size(name: ByteArray, size: LongArray): Int
    external fun sipral_abi_versioned_count(count: LongArray): Int
    external fun sipral_capabilities(capabilities: LongArray): Int
    external fun sipral_stack_create(configEventCallback: Long, configTransport: Long, configBindAddress: ByteArray?, configUserAgent: ByteArray?, configEntropy: ByteArray?, configTimerT1Ms: Long, configTimerT2Ms: Long, configTimerT4Ms: Long, configCodecs: ByteArray?, configFrameMs: Long, configOfferDtmf: Long, configOfferRtcpMux: Long, configSilenceSuppression: Long, configMediaStallWatchdog: Long, configMediaStallMs: Long, configMediaClockUnixSeconds: Long, configMediaSeed: ByteArray?, configSrtp: Long, stack: LongArray): Int
    external fun sipral_stack_settings(stack: Long, settings: LongArray): Int
    external fun sipral_stack_destroy(stack: Long): Int
    external fun sipral_stack_poll(stack: Long, nowMs: Long, result: LongArray): Int
    external fun sipral_stack_counters(stack: Long, counters: LongArray): Int
    external fun sipral_account_add(stack: Long, configAor: ByteArray?, configRegistrar: ByteArray?, configContact: ByteArray?, configRegistrarAddress: ByteArray?, configDisplayName: ByteArray?, configAuthUser: ByteArray?, configAuthPassword: ByteArray?, configInstanceId: ByteArray?, configExpiresSeconds: Long, configHeadersBytes: ByteArray?, configHeadersLengths: LongArray?, account: LongArray): Int
    external fun sipral_account_remove(stack: Long, account: Long): Int
    external fun sipral_account_register(stack: Long, account: Long, nowMs: Long): Int
    external fun sipral_account_unregister(stack: Long, account: Long, nowMs: Long): Int
    external fun sipral_account_registration_state(stack: Long, account: Long, state: LongArray): Int
    external fun sipral_call_place(stack: Long, account: Long, configTarget: ByteArray?, configSdp: ByteArray?, configDestination: ByteArray?, configKeepAllForks: Long, configMediaAddress: ByteArray?, configHeadersBytes: ByteArray?, configHeadersLengths: LongArray?, configSrtp: Long, call: LongArray, nowMs: Long): Int
    external fun sipral_call_ring(stack: Long, call: Long, sdp: ByteArray, nowMs: Long): Int
    external fun sipral_call_ring_media(stack: Long, call: Long, configTarget: ByteArray?, configSdp: ByteArray?, configDestination: ByteArray?, configKeepAllForks: Long, configMediaAddress: ByteArray?, configHeadersBytes: ByteArray?, configHeadersLengths: LongArray?, configSrtp: Long, nowMs: Long): Int
    external fun sipral_call_answer(stack: Long, call: Long, sdp: ByteArray, nowMs: Long): Int
    external fun sipral_call_answer_media(stack: Long, call: Long, mediaAddress: ByteArray, nowMs: Long): Int
    external fun sipral_call_reject(stack: Long, call: Long, code: Long, nowMs: Long): Int
    external fun sipral_call_hangup(stack: Long, call: Long, nowMs: Long): Int
    external fun sipral_call_set_headers(stack: Long, call: Long, headersBytes: ByteArray?, headersLengths: LongArray?): Int
    external fun sipral_call_hold(stack: Long, call: Long, nowMs: Long): Int
    external fun sipral_call_resume(stack: Long, call: Long, nowMs: Long): Int
    external fun sipral_call_accept_session(stack: Long, call: Long, sdp: ByteArray, nowMs: Long): Int
    external fun sipral_call_reject_session(stack: Long, call: Long, code: Long, nowMs: Long): Int
    external fun sipral_call_send_dtmf(stack: Long, call: Long, digits: ByteArray, via: Long, durationMs: Long, nowMs: Long): Int
    external fun sipral_call_transfer(stack: Long, call: Long, target: ByteArray, nowMs: Long): Int
    external fun sipral_call_consult(stack: Long, call: Long, configTarget: ByteArray?, configSdp: ByteArray?, configDestination: ByteArray?, configKeepAllForks: Long, configMediaAddress: ByteArray?, configHeadersBytes: ByteArray?, configHeadersLengths: LongArray?, configSrtp: Long, consultation: LongArray, nowMs: Long): Int
    external fun sipral_call_transfer_to(stack: Long, call: Long, other: Long, nowMs: Long): Int
    external fun sipral_call_accept_transfer(stack: Long, call: Long, configTarget: ByteArray?, configSdp: ByteArray?, configDestination: ByteArray?, configKeepAllForks: Long, configMediaAddress: ByteArray?, configHeadersBytes: ByteArray?, configHeadersLengths: LongArray?, configSrtp: Long, placed: LongArray, nowMs: Long): Int
    external fun sipral_call_reject_transfer(stack: Long, call: Long, code: Long, nowMs: Long): Int
    external fun sipral_call_state(stack: Long, call: Long, state: LongArray): Int
    external fun sipral_call_hold_state(stack: Long, call: Long, here: LongArray, there: LongArray): Int
    external fun sipral_codec_name(codec: Long): String?
    external fun sipral_codec_count(count: LongArray): Int
    external fun sipral_codec_at(index: Long, info: LongArray): Int
    external fun sipral_stack_codec_order(stack: Long, outCodecs: IntArray, count: LongArray): Int
    external fun sipral_call_media(stack: Long, call: Long, media: LongArray): Int
    external fun sipral_media_release(media: Long): Int
    external fun sipral_media_info(media: Long, info: LongArray): Int
    external fun sipral_media_statistics(media: Long, nowMs: Long, stats: LongArray): Int
    external fun sipral_media_receive(media: Long, data: ByteArray, from: ByteArray, nowMs: Long, arrival: LongArray): Int
    external fun sipral_media_playback(media: Long, samples: ShortArray, written: LongArray, source: LongArray): Int
    external fun sipral_media_capture(media: Long, samples: ShortArray, packet: Long): Int
    external fun sipral_media_poll_rtcp(media: Long, nowMs: Long, packet: Long): Int
    external fun sipral_stack_poll_farewell(stack: Long, call: LongArray, outPacket: Long): Int
    external fun sipral_media_dialling(media: Long, dialling: LongArray, waiting: LongArray): Int
    external fun sipral_media_stop_dialling(media: Long): Int
    external fun sipral_media_record_start(media: Long, path: ByteArray): Int
    external fun sipral_media_record_stop(media: Long): Int
    external fun sipral_media_record_state(media: Long, recording: LongArray, recordedMs: LongArray): Int
    external fun sipral_stack_poll_transmit(stack: Long, transmit: Long): Int
    external fun sipral_stack_receive_datagram(stack: Long, transport: Long, data: ByteArray, from: ByteArray, to: ByteArray, nowMs: Long): Int
    external fun sipral_stack_receive_stream(stack: Long, transport: Long, data: ByteArray, nowMs: Long): Int
    external fun sipral_stack_transport_bind(stack: Long, transport: Long, local: ByteArray, remote: ByteArray, nowMs: Long): Int
    external fun sipral_stack_transport_failed(stack: Long, transport: Long, error: Long, nowMs: Long): Int
    external fun sipral_stack_stream_closed(stack: Long, transport: Long, nowMs: Long): Int
    external fun sipral_event_kind_name(kind: Long): String?
    external fun sipral_message_header_count(message: ByteArray, name: ByteArray, count: LongArray): Int
    external fun sipral_message_header(message: ByteArray, name: ByteArray, index: Long, offset: LongArray, len: LongArray): Int
    external fun sipral_message_header_element_count(message: ByteArray, name: ByteArray, count: LongArray): Int
    external fun sipral_message_header_element(message: ByteArray, name: ByteArray, index: Long, offset: LongArray, len: LongArray): Int
}

/** Everything the library does, with the C conventions read off it. */
object Sipral {
    /**
     * The value no live handle ever takes.
     */
    const val HANDLE_NONE: Long = 0

    /**
     * The ABI's major version. Nothing published against one major works
     * against another.
     */
    const val ABI_VERSION_MAJOR: Long = 0

    /**
     * The ABI's minor version, raised by anything the header gains —
     * everything the generator prints, and not only a function or a struct
     * member. `sipral_abi_check` compares the major and this one; the patch it
     * does not ask about. The
     * rule for all three numbers is the Versioning section of
     * `docs/08-ffi.md`, which is where the ABI contract is written down.
     */
    const val ABI_VERSION_MINOR: Long = 9

    /**
     * The ABI's patch version, raised by a fix that changes no declaration.
     */
    const val ABI_VERSION_PATCH: Long = 0

    /**
     * Bits of SipralCapabilities.transports. A caller checks
     * `capabilities.transports & SIPRAL_TRANSPORT_BIT_TLS != 0` rather than a
     * growing list of booleans, so a transport this ABI has not learned a bit
     * for yet reads as absent rather than refusing to compile against an
     * older header.
     *
     * Named after SipralTransport's own numbers (`1 << (value - 1)`), so
     * a transport added there in the future gets a bit here without the two
     * numbering schemes ever being asked to agree by hand.
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
     * See SIPRAL_FEATURE_DTMF, and the module documentation for why this
     * build never sets it.
     */
    const val FEATURE_SUBSCRIPTIONS: Long = 32

    /**
     * See SIPRAL_FEATURE_DTMF. Opus is behind a compile-time feature,
     * because libopus is the one part of the audio path that is licensed
     * rather than written, so a build meant for hardware can leave it out.
     * The bit is how an application finds out without having to enumerate
     * the codecs, and it is set from the catalogue this build offers rather
     * than from any crate's feature flag; `SIPRAL_CODEC_OPUS` keeps its
     * number either way, since a value that has left this header is spent
     * for good.
     */
    const val FEATURE_OPUS: Long = 64

    /**
     * The buffer a caller has to bring for one outgoing packet.
     *
     * Not a path MTU — RTP does not discover one — but the bound the session
     * itself builds against, so a payload larger than this is a payload no
     * codec in this build produces. It is checked before anything is encoded,
     * because a frame that was encoded and then had nowhere to go is a frame
     * lost from a stream whose timestamps have already moved past it.
     */
    const val MEDIA_PACKET_BYTES: Long = 1500

    /**
     * Room enough for any address this ABI writes, the NUL included:
     * `[2001:db8:0000:0000:0000:0000:0000:0001]:65535` and a byte to spare.
     */
    const val ADDRESS_BYTES: Long = 64

    /**
     * The transport a stack is created with, and the only one this build
     * binds.
     *
     * Named rather than assumed, so that the day a stack has two of them is a
     * day more numbers become valid and not a day this ABI grows a second way
     * to hand bytes over.
     */
    const val TRANSPORT_MAIN: Long = 0

    /**
     * The largest message that crosses in either direction.
     *
     * The bound the layer below parses to, which is what stops a hostile peer
     * from making the parser do unbounded work. A caller's read buffer wants
     * to be this big on a stream, where one read can hold the end of one
     * message and the start of another, and 1500 bytes or so on a datagram
     * socket, where anything larger was fragmented on the way.
     */
    const val MESSAGE_BYTES: Long = 65535

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
     * `major`.`minor`. Called once, at load, before anything else: by the
     * binding itself where its language gives it somewhere to call from, and
     * by the application where it does not. The Versioning section of
     * `docs/08-ffi.md` says which binding is which.
     *
     * `SIPRAL_STATUS_UNSUPPORTED_VERSION` when it cannot, with a last error
     * naming both versions, which is what the binding should put in the
     * exception it throws. The patch number is not asked for: it never
     * changes a declaration, so it cannot make two builds disagree.
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
     * `name` is what the header calls the type — `sipral_stack_config_t` —
     * as bytes and a length, the way every string crosses here. A name this
     * build has no struct for is `SIPRAL_STATUS_INVALID_ARGUMENT`, which is
     * the answer a caller holding somebody else's header gets.
     *
     * Nothing in the library needs asking: the `size` member a struct
     * carries settles a disagreement in the ordinary course of a call. This
     * is for finding out there is one before making it. A package built
     * against one header and loaded over a native library from another
     * shows up here as a `sizeof` that differs, in one call at load, rather
     * than in whichever member happened to move.
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
     *
     * The companion to `sipral_abi_struct_size`, and the part of the check a
     * caller cannot write for itself. A caller that compares lengths holds
     * a list of the structs it knows about, and the list is what goes
     * stale: a struct this ABI gained is one nobody thought to ask about,
     * and a length check that covers all but the newest still passes. Ask
     * for this number, compare it with the length of that list, and the day
     * the ABI grows another the caller is told.
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
     * Names no stack, and answers the same way before any stack is created
     * as after: a build's capabilities do not change while it runs. Safe to
     * call from any thread, at any time, including from inside the event
     * callback.
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
     * The handle is written only if this returns `SIPRAL_STATUS_OK`. A stack
     * that is created must be destroyed with sipral_stack_destroy.
     *
     * A process holds 256 stacks at once. The next is
     * `SIPRAL_STATUS_EXHAUSTED` until one of them is destroyed and no poll is
     * still running on it.
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
        val stackSlot = LongArray(1)
        val configEventCallback = SipralEventListeners.register(config.eventListener)
        var status = -1
        try {
            status = SipralNative.sipral_stack_create(configEventCallback, config.transport, configBindAddress, configUserAgent, config.entropy, config.timerT1Ms, config.timerT2Ms, config.timerT4Ms, configCodecs, config.frameMs, config.offerDtmf, config.offerRtcpMux, config.silenceSuppression, config.mediaStallWatchdog, config.mediaStallMs, config.mediaClockUnixSeconds, config.mediaSeed, config.srtp, stackSlot)
        } finally {
            SipralEventListeners.made(configEventCallback, status, stackSlot[0])
        }
        check(status)
        return stackSlot[0]
    }

    /**
     * Read back what a stack is running with.
     *
     * Every value here was either given at creation or defaulted there, and
     * none of it changes afterwards. It is the other half of a configuration
     * call that answered `SIPRAL_STATUS_OK`: the call says the value was
     * taken, this says what it came to.
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
     * Destroy a stack.
     *
     * The handle is dead the moment this returns, and a second destroy is
     * `SIPRAL_STATUS_STALE_HANDLE` rather than a corrupted heap. Called from
     * inside the callback it is still safe: what the poll is holding stays
     * alive until that poll returns. Called from inside a frame of one of its
     * calls — a processor — it is `SIPRAL_STATUS_BUSY` and nothing is freed,
     * because freeing the stack ends that call's media and the frame is
     * holding it. No account is de-registered and no call is hung up; a stack
     * that has to leave politely does that first.
     *
     * Safety
     *
     * Safe to call with any handle value. Reads no memory the caller owns.
     */
    fun stackDestroy(stack: Long) {
        val status = SipralNative.sipral_stack_destroy(stack)
        SipralEventListeners.gone(stack)
        check(status)
    }

    /**
     * Let the stack do its work, and deliver what it has to say.
     *
     * `now_ms` is the caller's monotonic clock in milliseconds. It must not
     * fall more than fifty milliseconds behind the last one this stack saw —
     * signalling may be called from any thread, and two of them reading the
     * same clock a moment apart is not a caller mistake — and a jump further
     * back than that is `SIPRAL_STATUS_INVALID_ARGUMENT` with nothing
     * delivered.
     *
     * The event callback is called from inside this function, on this
     * thread, and with nothing held: the stack's work is done and its lock
     * let go before the first event is handed over, so the callback may call
     * back into the library, this stack included. A poll that finds another
     * poll of the same stack already delivering — which is what a poll from
     * inside the callback always finds — does the stack's work and leaves its
     * events to that one, so they arrive in the order they were raised and
     * never on two threads at once.
     *
     * `result` may be null for a caller that does not want the counts.
     *
     * A poll is also where the stack writes: a retransmission falls due, a
     * registration is refreshed, a transaction gives up and says so. What it
     * wrote is taken with `sipral_stack_poll_transmit`, which is drained after
     * every poll and left alone by the next one — see crate::transport for
     * the loop in full.
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
     *
     * Cheap enough to sample on a timer and ship as telemetry: reading this
     * is one struct copy on top of the call itself, the same as
     * `sipral_media_statistics` and for the same reason — nothing here walks
     * the call table or a session to answer.
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
     * Configure an account, and write its handle to `out_account`.
     *
     * Nothing is sent. The account exists until sipral_account_remove or
     * until the stack is destroyed.
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
        val accountSlot = LongArray(1)
        check(SipralNative.sipral_account_add(stack, configAor, configRegistrar, configContact, configRegistrarAddress, configDisplayName, configAuthUser, configAuthPassword, configInstanceId, config.expiresSeconds, configHeadersBytes, configHeadersLengths, accountSlot))
        return accountSlot[0]
    }

    /**
     * Forget an account, and everything scheduled for it.
     *
     * Nothing is sent: an account being removed may be one whose registrar is
     * unreachable, and waiting on that is not this call's job. Give the
     * binding up politely with sipral_account_unregister first when it
     * matters.
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
     * Refreshes, credential retries and the back-off after an outage all
     * happen without another call. What stops them is
     * sipral_account_unregister, or a refusal that trying again cannot
     * fix. Every step of it arrives as a `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED`.
     *
     * An account configured with no registrar never registers, and this
     * answers `SIPRAL_STATUS_INVALID_ARGUMENT` for it with nothing sent.
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
     * Only this device's binding. A `Contact: *` would remove every binding
     * the address of record has, including the one belonging to the desk
     * phone somebody else is holding.
     *
     * An account configured with no registrar has no binding to give up, and
     * is refused the way `sipral_account_register` refuses it.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun accountUnregister(stack: Long, account: Long, nowMs: Long) {
        check(SipralNative.sipral_account_unregister(stack, account, nowMs))
    }

    /**
     * Where an account's registration is, as a `SipralRegistrationState`.
     *
     * An account configured with no registrar answers
     * `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING`, always.
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
     * Place a call, and write its handle to `out_call`.
     *
     * The handle exists from here on, before any dialog does, because there
     * has to be something to hang up with while the INVITE is still in
     * flight. A proxy that forks the INVITE gives the branches handles of
     * their own, reported as `SIPRAL_EVENT_KIND_CALL_FORKED`.
     *
     * With `media_address` set, the offer is this stack's to write and the
     * call gets audio of its own: `SIPRAL_EVENT_KIND_MEDIA_STARTED` says when,
     * and `crate::media` carries the packets from then on. `config.srtp`
     * overrides `sipral_stack_config_t::srtp` for such a call; it is read for
     * no other kind.
     *
     * Safety
     *
     * `config` must point at a `sipral_call_config_t` whose `size` member
     * says how long it is, with every pointer in it readable for the length
     * beside it, and `out_call` at one `sipral_handle_t`.
     */
    fun callPlace(stack: Long, account: Long, config: SipralCallConfig, nowMs: Long): Long {
        val configTarget = config.target?.toByteArray(Charsets.UTF_8)
        val configDestination = config.destination?.toByteArray(Charsets.UTF_8)
        val configMediaAddress = config.mediaAddress?.toByteArray(Charsets.UTF_8)
        val (configHeadersBytes, configHeadersLengths) = SipralHeader.packed(config.headers)
        val callSlot = LongArray(1)
        check(SipralNative.sipral_call_place(stack, account, configTarget, config.sdp, configDestination, config.keepAllForks, configMediaAddress, configHeadersBytes, configHeadersLengths, config.srtp, callSlot, nowMs))
        return callSlot[0]
    }

    /**
     * Say a call that came in is ringing.
     *
     * A description makes it a 183 Session Progress rather than a 180
     * Ringing, because 180 with a body is a contradiction the far end has to
     * guess at. Pass none for the ordinary case.
     *
     * Safety
     *
     * `sdp` must be null or readable for `sdp_len` bytes.
     */
    fun callRing(stack: Long, call: Long, sdp: ByteArray, nowMs: Long) {
        check(SipralNative.sipral_call_ring(stack, call, sdp, nowMs))
    }

    /**
     * Say a call that came in is ringing, with this stack running the audio
     * before anybody answers.
     *
     * The answer to the offer the INVITE carried is written from this
     * stack's codec order, against `config.media_address` — where this end
     * will receive media, which only the application can say because it owns
     * the socket — and the session opens on it there and then: the far end
     * hears whatever the application plays before anybody picks up.
     * `SIPRAL_EVENT_KIND_MEDIA_STARTED` follows.
     *
     * `config.srtp` overrides the stack's own SRTP policy for this call, the
     * same way it does on `sipral_call_place`; it is the one way an incoming
     * call can choose its own SRTP policy at all, since
     * `sipral_call_answer_media` reads no configuration of its own. Once
     * this has set it, `sipral_call_answer_media` keeps it: it is answering
     * a call that already has a catalogue, not choosing one.
     *
     * `sipral_call_answer_media` after this reuses the session and the
     * description written here rather than negotiating a second one. What
     * the 200 OK it sends carries then follows RFC 3262 §5 and RFC 6337
     * §3.1.1 exactly, from whether this call's 183 went out reliably — see
     * `docs/05-media.md`, "Ringing with media".
     *
     * Every other member of `config` — `target`, `sdp`, `destination`,
     * `keep_all_forks`, `headers` — names something a call to place would
     * need, and this call already exists; setting one of them is
     * `SIPRAL_STATUS_INVALID_ARGUMENT` naming it.
     *
     * An INVITE that carried no offer is `SIPRAL_STATUS_WRONG_STATE`, with
     * nothing sent: the offer this end would make instead belongs in no
     * provisional response this stack can follow up (RFC 3261 §13.2.1,
     * RFC 6337 §3.1.2).
     *
     * Calling this twice on one call is `SIPRAL_STATUS_WRONG_STATE`, and so is
     * calling it after a `sipral_call_ring` that sent a description of the
     * application's own: every description in the responses to one INVITE
     * has to be that same one (RFC 3261 §13.2.1, RFC 6337 §3.1.1). After a
     * `sipral_call_ring` that sent none, it is not.
     *
     * Safety
     *
     * `config` must point at a `sipral_call_config_t` whose `size` member
     * says how long it is, with `media_address` readable for
     * `media_address_len` bytes.
     */
    fun callRingMedia(stack: Long, call: Long, config: SipralCallConfig, nowMs: Long) {
        val configTarget = config.target?.toByteArray(Charsets.UTF_8)
        val configDestination = config.destination?.toByteArray(Charsets.UTF_8)
        val configMediaAddress = config.mediaAddress?.toByteArray(Charsets.UTF_8)
        val (configHeadersBytes, configHeadersLengths) = SipralHeader.packed(config.headers)
        check(SipralNative.sipral_call_ring_media(stack, call, configTarget, config.sdp, configDestination, config.keepAllForks, configMediaAddress, configHeadersBytes, configHeadersLengths, config.srtp, nowMs))
    }

    /**
     * Answer a call that came in.
     *
     * `sdp` is the answer to the offer the INVITE carried, and is required:
     * answering with nothing puts the offer on this end and the answer in the
     * far end's ACK, which this ABI has no way to hand back.
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
     * The answer to the offer the INVITE carried is written from this stack's
     * codec order, against `media_address` — where this end will receive
     * media, which only the application can say because it owns the socket.
     * `SIPRAL_EVENT_KIND_MEDIA_STARTED` follows once the stream is open.
     *
     * The other half of `sipral_call_place` with `media_address` set, and the
     * alternative to `sipral_call_answer`, which answers with a description
     * the application wrote and leaves the audio to it.
     *
     * On a call `sipral_call_ring_media` already rang, nothing is written and
     * no second session opens: the 183's description and session stand,
     * `SIPRAL_EVENT_KIND_MEDIA_STARTED` has already been reported, and
     * `media_address` must still be an address and a port but is not used.
     * The 200 OK repeats that description when the 183 went out unreliably and
     * carries none when it went out reliably (RFC 6337 §3.1.1).
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
     * Refuse a call that came in, with a response code of your choosing.
     *
     * 486 Busy Here for a line that is in use, 603 Decline for a person who
     * does not want to talk. The difference is what a proxy does next.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callReject(stack: Long, call: Long, code: Long, nowMs: Long) {
        check(SipralNative.sipral_call_reject(stack, call, code, nowMs))
    }

    /**
     * Hang up, whatever the call is doing.
     *
     * A CANCEL before it is answered, a BYE after, a refusal for one that
     * came in and has not been answered. A call that is already ending is
     * left alone rather than refused.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callHangup(stack: Long, call: Long, nowMs: Long) {
        check(SipralNative.sipral_call_hangup(stack, call, nowMs))
    }

    /**
     * Set the header fields that go on what this call sends at the
     * application's request, from now until they are set again.
     *
     * They go on the 180 or 183 from `sipral_call_ring`, the 200 from
     * `sipral_call_answer` and `sipral_call_answer_media`, the refusal from
     * `sipral_call_reject`, the refusal or the BYE that `sipral_call_hangup`
     * turns into, and the re-INVITE or UPDATE that `sipral_call_hold` and
     * `sipral_call_resume` send. Kept rather than spent on the first of those,
     * so that a field set before ringing is on the 200 as well. Never on a
     * CANCEL, which a proxy answers and replaces with its own, and never on
     * what the stack sends by itself: a session refresh, or the BYE for a 2xx
     * that was never acknowledged or for a fork that lost.
     *
     * Replaces what was set before, whole, and a `headers_len` of zero takes
     * every field off. Each field is checked first, as it is on
     * `sipral_call_config_t::headers`, and a refusal names the element, keeps
     * none of the new fields and leaves the old ones in place. Nothing is
     * sent.
     *
     * Safety
     *
     * `headers` must be null with `headers_len` zero, or readable for
     * `headers_len` elements, each with a name and a value readable for the
     * lengths beside them.
     */
    fun callSetHeaders(stack: Long, call: Long, headers: List<SipralHeader>) {
        val (headersBytes, headersLengths) = SipralHeader.packed(headers)
        check(SipralNative.sipral_call_set_headers(stack, call, headersBytes, headersLengths))
    }

    /**
     * Put a call on hold (RFC 3264 §8.4).
     *
     * The description is the stack's to write: the one already negotiated
     * with every stream's direction changed. Asking for a hold that is
     * already in place sends nothing and succeeds.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callHold(stack: Long, call: Long, nowMs: Long) {
        check(SipralNative.sipral_call_hold(stack, call, nowMs))
    }

    /**
     * Take it off hold again.
     *
     * Every stream goes back to the direction it had before, which is not
     * always both ways: one that was offered receive-only is resumed
     * receive-only.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callResume(stack: Long, call: Long, nowMs: Long) {
        check(SipralNative.sipral_call_resume(stack, call, nowMs))
    }

    /**
     * Accept a change the far end offered, reported as
     * `SIPRAL_EVENT_KIND_SESSION_OFFERED`.
     *
     * `sdp` is the answer to the offer it carried, and is left out only for a
     * request that carried none. A re-INVITE nobody answers is retransmitted
     * and then ends the call, so this or sipral_call_reject_session has
     * to follow that event.
     *
     * Only for a call the application describes. One this stack describes
     * answers its own re-offers, from the same codec order, before the poll
     * that saw the request returns — so the event never arrives and this is
     * `SIPRAL_STATUS_WRONG_STATE`.
     *
     * Safety
     *
     * `sdp` must be null or readable for `sdp_len` bytes.
     */
    fun callAcceptSession(stack: Long, call: Long, sdp: ByteArray, nowMs: Long) {
        check(SipralNative.sipral_call_accept_session(stack, call, sdp, nowMs))
    }

    /**
     * Refuse one instead. The session stands exactly as it was (§14.1).
     *
     * 488 Not Acceptable Here is the code that says the description was the
     * problem rather than the request.
     *
     * As with sipral_call_accept_session, only for a call the application
     * describes.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callRejectSession(stack: Long, call: Long, code: Long, nowMs: Long) {
        check(SipralNative.sipral_call_reject_session(stack, call, code, nowMs))
    }

    /**
     * Send DTMF on a call that is up, in whichever of the three forms the far
     * end takes.
     *
     * `digits` are `0` to `9`, `*`, `#` and `A` to `D`, the sixteen events of
     * RFC 4733 §3.2, in the order they were pressed. `duration_ms` is how long
     * each one lasts, or zero for the default.
     *
     * `via` is a SipralDtmf, and it is chosen per send rather than per
     * call: which form a peer accepts is a fact about the peer, and an
     * application that has just learned the answer for this one must not have
     * to tear the call down to act on it. `SIPRAL_DTMF_RTP` puts the digits in
     * the media, where they replace the audio for as long as they last and
     * queue behind each other; the two INFO forms put one request per digit in
     * the dialog.
     *
     * `SIPRAL_STATUS_NOT_SUPPORTED` from `SIPRAL_DTMF_RTP` on a call whose
     * negotiation settled on no telephone event payload type: the key is a
     * real key and this call has nowhere in the media to put it. The INFO
     * forms need a dialog rather than a negotiation, and answer
     * `SIPRAL_STATUS_WRONG_STATE` before there is one.
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
     * Ask the far end to call somebody else, and hang up when it has
     * (RFC 3515).
     *
     * A blind transfer: nobody consults the destination first. This end stays
     * in the call until the transfer has succeeded, because hanging up first
     * turns a transfer that failed into a call that vanished. Progress
     * arrives as `SIPRAL_EVENT_KIND_TRANSFER_PROGRESS` and then
     * `SIPRAL_EVENT_KIND_TRANSFER_DONE`.
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
     * Call the transfer target, so that there is somebody to hand the call
     * to, and write the new call's handle to `out_consultation`.
     *
     * The consultation leg of an attended transfer. It is answered like any
     * other call, and sipral_call_transfer_to is what follows. Putting
     * `call` on hold first is the application's: it is a session change, and
     * this stack does not make those uninvited.
     *
     * `media_address` is `SIPRAL_STATUS_NOT_SUPPORTED` here. The media engine
     * places and answers calls; it does not consult, and a consultation leg
     * registered with it by hand would be one it has described nothing for.
     * A consultation with audio is placed with `sdp` and run by the
     * application, as every call was before this stack carried media.
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
        val consultationSlot = LongArray(1)
        check(SipralNative.sipral_call_consult(stack, call, configTarget, config.sdp, configDestination, config.keepAllForks, configMediaAddress, configHeadersBytes, configHeadersLengths, config.srtp, consultationSlot, nowMs))
        return consultationSlot[0]
    }

    /**
     * Hand `call` to the far end of `other` (RFC 3891).
     *
     * The attended half of a transfer: `other` is normally the consultation
     * call, and the party at its far end replaces the call it already has
     * rather than answering a second one. Any call that is up may be named.
     *
     * Safety
     *
     * Safe to call with any handle values.
     */
    fun callTransferTo(stack: Long, call: Long, other: Long, nowMs: Long) {
        check(SipralNative.sipral_call_transfer_to(stack, call, other, nowMs))
    }

    /**
     * Take a transfer that was asked for, place the call it names the way
     * sipral_call_place places one, and write its handle to
     * `out_placed`.
     *
     * `config.target` is not read: the far end already said where this goes
     * when it asked for the transfer, and a target of the caller's own would
     * be a second one contradicting it — `SIPRAL_STATUS_INVALID_ARGUMENT`
     * naming it. Everything else in `config` means what it means on
     * `sipral_call_place`: `sdp` for a description the application wrote and
     * runs the audio of, `media_address` for one this stack writes and runs
     * (`config.srtp` overriding the stack's own policy for it, the same
     * way), `headers`, `destination` and `keep_all_forks` for the INVITE
     * this places. `Replaces` and `Referred-By` among `headers` are
     * `SIPRAL_STATUS_INVALID_ARGUMENT`, nothing sent and the transfer still
     * there to take: that INVITE takes both from the REFER. Giving neither
     * `sdp` nor `media_address` is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`, for the same reason it is on
     * `sipral_call_place`: the answer to an offerless INVITE has nowhere to
     * go but the ACK, and this ABI hands nothing back from there.
     *
     * Safety
     *
     * `config` must point at a `sipral_call_config_t` whose `size` member
     * says how long it is, with every pointer in it readable for the length
     * beside it, and `out_placed` at one `sipral_handle_t`.
     */
    fun callAcceptTransfer(stack: Long, call: Long, config: SipralCallConfig, nowMs: Long): Long {
        val configTarget = config.target?.toByteArray(Charsets.UTF_8)
        val configDestination = config.destination?.toByteArray(Charsets.UTF_8)
        val configMediaAddress = config.mediaAddress?.toByteArray(Charsets.UTF_8)
        val (configHeadersBytes, configHeadersLengths) = SipralHeader.packed(config.headers)
        val placedSlot = LongArray(1)
        check(SipralNative.sipral_call_accept_transfer(stack, call, configTarget, config.sdp, configDestination, config.keepAllForks, configMediaAddress, configHeadersBytes, configHeadersLengths, config.srtp, placedSlot, nowMs))
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
     * Where a call is, as a `SipralCallState`.
     *
     * A call that is over answers `SIPRAL_CALL_STATE_TERMINATED` until the
     * poll that delivers `SIPRAL_EVENT_KIND_CALL_ENDED` retires its handle, and
     * `SIPRAL_STATUS_STALE_HANDLE` after that.
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
     * Which way a call is held: `out_here` is set when this end asked the far
     * end to stop sending, `out_there` when the far end asked this one.
     * Either may be null.
     *
     * Safety
     *
     * `out_here` and `out_there` must each be null or point at one
     * `uint32_t`.
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
     * It is spelled as IANA registered it, which is also how it goes on an
     * `a=rtpmap` line. The string belongs to the library and lives as long as
     * it is loaded.
     *
     * Safety
     *
     * Reads no memory the caller owns, and is safe to call from any thread.
     */
    fun codecName(codec: Long): String? =
        SipralNative.sipral_codec_name(codec)

    /**
     * How many codecs this build contains.
     *
     * A compile-time fact, and the reason A4 starts here rather than at a
     * configuration: no setting can add a codec that was not linked.
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
     * The order is this build's own preference, quality first, which is what
     * is offered when nobody has said otherwise.
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
     * The other half of the configuration: `codecs` in
     * `sipral_stack_config_t` says what to offer, and this says what that came
     * to. `out_count` always receives the number there are, so a caller that
     * passes a capacity of zero and a null buffer learns how much room to
     * bring and gets `SIPRAL_STATUS_BUFFER_TOO_SMALL`.
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
     * Mint it once the call's negotiation has settled —
     * `SIPRAL_EVENT_KIND_MEDIA_STARTED` is the moment, and minting from inside
     * that event's callback is allowed — and hand it to every `sipral_media_`
     * entry point in place of the stack and the call. None of those takes the
     * stack's lock, which is the point: the thread that carries a call's audio
     * is never refused a frame because signalling, the event callback or
     * another call is busy.
     *
     * `SIPRAL_STATUS_WRONG_STATE` for a call with no media: one placed with a
     * description of the caller's own, or one whose negotiation has not
     * settled. The handle is written only if this returns `SIPRAL_STATUS_OK`.
     *
     * The handle outlives the call. Once the call ends, or its stack is
     * destroyed, every media entry point answers `SIPRAL_STATUS_WRONG_STATE`
     * on it; a hold, a resume or a change of codec keeps it working. Each
     * handle minted is released once with `sipral_media_release`, and asking
     * twice for the same call gives two.
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
     * Its one matching free, whether or not its call is still up and whether
     * or not its stack still exists. The session is not touched: it belongs to
     * the call and ends when the call does, so releasing a handle mid-call
     * stops nothing but the handle. A handle released twice is
     * `SIPRAL_STATUS_STALE_HANDLE` the second time.
     *
     * Safety
     *
     * Safe to call with any handle value. Reads no memory the caller owns.
     */
    fun mediaRelease(media: Long) {
        check(SipralNative.sipral_media_release(media))
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
     * What one call's media has cost, and what it is costing now.
     *
     * A6's live half. `now_ms` is the caller's monotonic clock, as everywhere
     * else, because "how long since a packet arrived" is a question about the
     * present and nothing here reads a clock to answer it. Like every media
     * entry point, this does not move the stack's own clock: it is read at the
     * frame rate of a user interface, often from the thread that draws one,
     * and a reading a millisecond behind the last poll is not a caller bug.
     *
     * The end-of-call record arrives instead as
     * `SIPRAL_EVENT_KIND_MEDIA_STATISTICS`, because by then the stream is
     * gone and this answers `SIPRAL_STATUS_WRONG_STATE`.
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
     * One entry point for both sockets: RTP and RTCP are told apart by
     * RFC 5761 §4's rule on the payload type field, so a caller that put both
     * on one socket does not have to sort them, and one that did not can hand
     * over whichever arrived.
     *
     * `data` is written through. A secured stream is opened in place, and a
     * caller that needs the ciphertext afterwards keeps its own copy.
     *
     * `out_arrival` may be null for a caller that does not want to know what
     * the datagram turned out to be.
     *
     * `now_ms` is when it arrived, on the stack's clock. Reading it here moves
     * nothing: the network thread and the poll thread read that clock apart,
     * and a datagram a millisecond behind the last poll is not refused.
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
     * needed in `out_written`. Every source fills the frame, concealment and
     * silence included: a device handed nothing for one frame plays whatever
     * was in its buffer last, and that is a far worse sound than the one being
     * concealed.
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
     * `sample_count` is `sipral_media_info_t::frame_samples` and nothing else:
     * a codec cuts one frame at one length, and half a frame encoded as a
     * whole one is what a peer hears as a stutter.
     *
     * A `len` of zero in the packet means the frame was deliberately not sent:
     * this end is holding the far end, or silence suppression swallowed it.
     * The RTP timestamp moves by a frame either way, because RFC 3550 §5.1
     * makes it a measure of time rather than of packets.
     *
     * Safety
     *
     * `samples` must be readable for `sample_count` `int16_t`, and `packet`
     * must point at a `sipral_media_packet_t` whose `size` member says how
     * long it is and whose buffers are writable for the capacities beside
     * them.
     */
    fun mediaCapture(media: Long, samples: ShortArray, packet: Long) {
        check(SipralNative.sipral_media_capture(media, samples, packet))
    }

    /**
     * The control traffic this call has due.
     *
     * A `len` of zero in the packet means nothing is due yet. RFC 3550 §6.3
     * decides when, and at most one report is due at a time, so one call per
     * frame is enough.
     *
     * It asks one call rather than the whole stack, so the thread that sends
     * a call's audio sends its reports too, on the same socket and without
     * reaching the stack: call it after every frame that goes out, and
     * whenever `sipral_stack_poll` reports a deadline while a call is not
     * capturing. On a call that negotiated no RTCP it answers zero for ever.
     *
     * `now_ms` is read as the stack reads it and moves nothing, as with every
     * media entry point.
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
     * The RTCP goodbye of a call whose media has ended (task 8.4.21).
     *
     * `MediaEngine::release` builds the BYE RFC 3550 §6.3.7 owes the far end
     * the moment a call's session stops, but by then the call's media
     * handle is already gone — every `sipral_media_` entry point on it
     * answers `SIPRAL_STATUS_WRONG_STATE` — so this is a stack-level call
     * instead, the one place left that still knows the goodbye belonged to
     * that call.
     *
     * `out_call` is written with the handle of the call the goodbye
     * belonged to — `SIPRAL_HANDLE_NONE` when nothing was waiting. The
     * call itself is already over; the handle is there only so the
     * application knows which media socket to send the datagram from, since
     * it owns that socket and this ABI never did. Passing it to any other
     * entry point answers whatever a stale handle of its kind already
     * answers.
     *
     * One at a time, like every other poll in this crate: call it after
     * every `sipral_stack_poll` that delivered `SIPRAL_EVENT_KIND_CALL_ENDED`
     * for a call this stack was running media on, and keep calling until
     * `out_packet` comes back with a `len` of zero. A call whose media never
     * ran leaves nothing here at all.
     *
     * Safety
     *
     * `out_call` must point at one `sipral_handle_t`, and `out_packet` at a
     * `sipral_media_packet_t` as sipral_media_capture describes.
     */
    fun stackPollFarewell(stack: Long, outPacket: Long): Long {
        val callSlot = LongArray(1)
        check(SipralNative.sipral_stack_poll_farewell(stack, callSlot, outPacket))
        return callSlot[0]
    }

    /**
     * Whether a digit is going out or waiting to, and how many have not
     * started yet.
     *
     * Either out parameter may be null. A user interface that greys out the
     * keypad while a number is being sent wants the first; one that shows how
     * much of a pasted number is left wants the second.
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
     * The digit in flight gets no closing packet, which is right for a call
     * whose media is being taken away: there is nowhere left to send one.
     *
     * Safety
     *
     * Reads no memory the caller owns.
     */
    fun mediaStopDialling(media: Long) {
        check(SipralNative.sipral_media_stop_dialling(media))
    }

    /**
     * Start recording this call to `path`.
     *
     * Both directions, mixed, as WAVE. It can be started and stopped as often
     * as the person on the phone presses the button, and each recording is a
     * file of its own: a path written to twice would have two headers in it.
     *
     * `SIPRAL_STATUS_WRONG_STATE` for a call whose media has ended and for one
     * already being recorded — two writers on one stream would interleave
     * frames into both files. `SIPRAL_STATUS_INVALID_ARGUMENT` when the file
     * system refuses the path, with what it said in the last error.
     *
     * The file is made with this call's media held, so this call's audio
     * waits for the file system to answer and no other call's does.
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
     * Stop it, and close the file.
     *
     * `SIPRAL_STATUS_WRONG_STATE` when nothing is being recorded. A failure
     * here leaves a file with all of the audio in it and zeroes in the two
     * header fields, which is recoverable and is said rather than hidden.
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
     * taken. Either out parameter may be null.
     *
     * The length is of the audio written, not of the file: the header in front
     * of it is not a recording of anything.
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
     * One at a time, like every other poll here: a caller loops until the
     * message comes back with a `len` of zero. Call it after every
     * `sipral_stack_poll` and after every call that hands bytes in, since both
     * are moments the stack writes at.
     *
     * A message longer than `capacity` is `SIPRAL_STATUS_BUFFER_TOO_SMALL` with
     * the length it needs in `len`, and it is *kept*: the next call with room
     * for it hands over that same message, before anything queued behind it. So
     * a caller that brought no buffer at all — a null `data` with a capacity of
     * zero — learns what to bring without losing the message it asked about.
     *
     * Safety
     *
     * `transmit` must point at a `sipral_transmit_t` whose `size` member says
     * how long it is and whose buffers are writable for the capacities beside
     * them.
     */
    fun stackPollTransmit(stack: Long, transmit: Long) {
        check(SipralNative.sipral_stack_poll_transmit(stack, transmit))
    }

    /**
     * Hand over one datagram, whole, and say where it came from.
     *
     * `from` is the far end, as `host:port`. `to` is the address the datagram
     * arrived on, which RFC 3581 §4 makes the address the response has to go
     * out from; null with a length of zero means the address this stack was
     * created with, which is the answer for a socket bound to one address.
     *
     * A WebSocket frame comes in here too: RFC 7118 §4.2 puts one SIP message
     * in each, so it arrives whole the way a datagram does.
     *
     * Bytes that are not a message are `SIPRAL_STATUS_INVALID_ARGUMENT` with
     * the parse error in the last error. That is an ordinary morning on a
     * public SIP port and costs exactly this one packet: log it and carry on.
     *
     * Safety
     *
     * `data` must be readable for `len` bytes, `from` for `from_len`, and `to`
     * for `to_len`.
     */
    fun stackReceiveDatagram(stack: Long, transport: Long, data: ByteArray, from: String, to: String, nowMs: Long) {
        val fromBytes = from.toByteArray(Charsets.UTF_8)
        val toBytes = to.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_stack_receive_datagram(stack, transport, data, fromBytes, toBytes, nowMs))
    }

    /**
     * Hand over bytes off a connection, in whatever sizes the reads came in.
     *
     * Not a message: a fragment of a framing the layer below reassembles on
     * `Content-Length` (§18.3), and one call may hold several messages, half of
     * one, or none at all. No addresses travel with it, because a connection
     * has one far end and it was named when the transport was bound.
     *
     * Framing that cannot be read is fatal to the connection, and unlike a
     * datagram it cannot be resynchronised: the transport is already retired by
     * the time this answers `SIPRAL_STATUS_INVALID_ARGUMENT`, and the socket
     * should be closed. A read of zero bytes is the far end closing, which is
     * sipral_stack_stream_closed and not this.
     *
     * Safety
     *
     * `data` must be readable for `len` bytes.
     */
    fun stackReceiveStream(stack: Long, transport: Long, data: ByteArray, nowMs: Long) {
        check(SipralNative.sipral_stack_receive_stream(stack, transport, data, nowMs))
    }

    /**
     * Say that a transport is open and may be written to.
     *
     * The one way back from sipral_stack_transport_failed, and the way a
     * stream stack names its far end: a connection that has just been made
     * knows its peer, and a stack created before the connect did not. It is
     * also how a socket re-opened on another address after the network moved
     * tells this stack what to put in its `Via` from now on — every message
     * after this one carries `local`, and the ones already in flight carry what
     * they were written with.
     *
     * `local` is the address the far end reaches this one at, as `host:port`.
     * `remote` is the far end of a connection, and is refused on a datagram
     * transport, which has many.
     *
     * The protocol is not an argument: a stack retransmits or does not
     * according to what it was created speaking, and a transport that changed
     * that underneath the timers would be a stack configured out of RFC 3261
     * §17 halfway through a call.
     *
     * Safety
     *
     * `local` must be readable for `local_len` bytes and `remote` for
     * `remote_len`.
     */
    fun stackTransportBind(stack: Long, transport: Long, local: String, remote: String, nowMs: Long) {
        val localBytes = local.toByteArray(Charsets.UTF_8)
        val remoteBytes = remote.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_stack_transport_bind(stack, transport, localBytes, remoteBytes, nowMs))
    }

    /**
     * Say that a transport failed, and that whatever was written to it did not
     * arrive.
     *
     * The transport is retired: every transaction waiting on it fails now, and
     * the calls and registrations behind them are reported on the next
     * `sipral_stack_poll` — nothing is delivered from inside this call, here as
     * everywhere else. Nothing can be sent until
     * sipral_stack_transport_bind brings one back.
     *
     * So this is not the call for one `sendto` that was refused. An ICMP
     * unreachable is one destination saying no, and a stack that retired its
     * socket over it would drop the calls that were fine. This is for the
     * socket that is over.
     *
     * Safety
     *
     * Safe to call with any handle value. Reads no memory the caller owns.
     */
    fun stackTransportFailed(stack: Long, transport: Long, error: Long, nowMs: Long) {
        check(SipralNative.sipral_stack_transport_failed(stack, transport, error, nowMs))
    }

    /**
     * Say that a connection closed: the far end went away, or a read returned
     * zero.
     *
     * The same retirement as sipral_stack_transport_failed, and a separate
     * call because it is a separate thing to have happened. An orderly close is
     * not an error the caller has to invent a kind for, and a stack that made it
     * one would have the two indistinguishable in a log for ever after.
     *
     * Safety
     *
     * Safe to call with any handle value. Reads no memory the caller owns.
     */
    fun stackStreamClosed(stack: Long, transport: Long, nowMs: Long) {
        check(SipralNative.sipral_stack_stream_closed(stack, transport, nowMs))
    }

    /**
     * The short name of an event kind, as a static NUL-terminated
     * string, or null for a number this build has no kind for.
     *
     * The string belongs to the library and lives as long as it is
     * loaded. A number that is reserved for a feature this build does
     * not have answers null, the same as one that was never spent: a
     * name for something that cannot arrive would be a name for
     * nothing.
     *
     * Safety
     *
     * Reads no memory the caller owns, and is safe to call from any
     * thread.
     */
    fun eventKindName(kind: Long): String? =
        SipralNative.sipral_event_kind_name(kind)

    /**
     * How many lines a header field is on, in a whole SIP message.
     *
     * The message is any SIP message in bytes: the one an event carries in
     * `sipral_event_t::message`, or one the application came by some other
     * way. The name is matched the way the parser matches it, without regard to
     * case, and a compact form and its long form are one field (RFC 3261
     * §7.3.3): `i` counts the `Call-ID` lines, and `Call-ID` counts a line
     * written `i:`. A field that is not there is a count of zero, not a
     * failure.
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
     * `index` counts from zero in the order the lines arrived, and has to be
     * below what `sipral_message_header_count` says for the same name: past it
     * is `SIPRAL_STATUS_INVALID_ARGUMENT`. `out_offset` and `out_len` then say
     * where the value sits inside `message`, trimmed at both ends and otherwise
     * as it arrived, a line fold included. An offset rather than a pointer,
     * because the bytes are the caller's, and a binding that copied them across
     * the boundary holds its own copy.
     *
     * One line of a field whose value is a comma-separated list may hold
     * several values; `sipral_message_header_element` reaches those.
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
     * RFC 3261 §7.3.1 makes two values on one line, with a comma between them,
     * and the same two values on two lines one and the same message, and a
     * proxy is free to turn either into the other. So this counts values
     * rather than lines, split at every comma that is not inside quotes or
     * angle brackets. Otherwise as `sipral_message_header_count`.
     *
     * Only for a field defined as a list: `P-Asserted-Identity`, `Diversion`,
     * `Contact`, `Supported`. Any other is split at a comma its value holds as
     * text, like the one in a `Date` or the ones between the parameters of a
     * challenge, and `sipral_message_header_count` is the call for it.
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
     * `index` counts values in the order they arrived, and has to be below what
     * `sipral_message_header_element_count` says for the same name. Otherwise
     * as `sipral_message_header`.
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

}
