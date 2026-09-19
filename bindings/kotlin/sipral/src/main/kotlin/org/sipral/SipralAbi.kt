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
 * What became of one codec this call's catalogue could have used. Names
 * for SipralCodecCandidate.outcome.
 *
 * D5's codec half: a negotiation that ends in G.711 when the site
 * configured Opus is a support call, and the answer to it is a list
 * saying which of the two things happened — the far end never named
 * Opus, or it named it and something ahead of it in this end's order
 * won.
 */
enum class SipralCodecOutcome(val value: Int) {
    /**
     * Not an outcome: either the candidate is from a build this ABI has
     * no number for, or the struct was never filled in.
     */
    UNKNOWN(0),
    /**
     * This is what the call agreed on. Exactly one candidate carries it,
     * and it names the same codec as `sipral_media_info_t::codec`.
     */
    CHOSEN(1),
    /**
     * The far end's description did not name it, so it was never in the
     * running. The commonest answer, and the one that says the question
     * is about the far end's configuration rather than this one's.
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
     *
     * It is one rather than zero on purpose. Zero is what a caller who
     * filled nothing in leaves behind, and the way a digit travels is the
     * one setting here that a peer can ignore in silence: a call that
     * meant INFO and sent nothing at all looks, from this end, exactly
     * like a call that sent it. So zero names no form and is refused.
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
 * - 16: the set of audio devices changed (A2)
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
     * A subscription moved: it was asked for, granted, put on probation,
     * scheduled for another attempt, or ended.
     *
     * A1. `payload.subscription` says which one and where it is now, and
     * `reason` why it is not live when it is not. Not sent on every
     * refresh — a lamp does not move because a refresh was scheduled —
     * and not sent for a notification arriving, which is
     * SipralEventKind.NOTIFIED instead.
     */
    SUBSCRIPTION_CHANGED(15),
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
     * A request grew too large for a datagram (RFC 3261 §18.1.1) and this
     * stack has no stream transport open to the destination it names.
     * `payload.transport_wanted` says where it was going, over what
     * protocol, and how it measured against the datagram it did not fit.
     *
     * B1. Answered with
     * sipral_stack_transport_bind:
     * once the application binds a transport to that destination, the
     * stack sends the request again by itself and this ABI raises
     * nothing further about it — there is no "it went" event, the same
     * way there is none for an ordinary request that fit the first time.
     */
    TRANSPORT_WANTED(18),
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
     * A call a push announced never arrived.
     *
     * C2, and not an error. A wake-up chain has a notification service,
     * a proxy, a bucket timer and a radio in it, and when a call does not
     * come through it this is the only place that says which end gave up:
     * the push was delivered, this device woke, refreshed its binding,
     * and no INVITE followed. `payload.announce` says which announcement
     * and how long it was waited for; the screen the application raised
     * can come down.
     */
    ANNOUNCED_CALL_MISSING(20),
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
     * The far end pressed a key: an RFC 4733 named telephone event, or an
     * INFO carrying `application/dtmf-relay` or `application/dtmf`.
     *
     * One per keypress, not one per packet: an RFC 4733 digit goes out as
     * a run of updates and then its closing packet three times, and the
     * layer below collapses them on the timestamp that identifies the
     * event; an INFO is one request. `payload.media.digit` is the
     * character, `event_code` the number behind it for the events no
     * keypad has a key for, `held_ms` how long it lasted, and `source`
     * a `SIPRAL_DIGIT_SOURCE` naming which of the two reported it.
     * `held_ms` zero means either of two different facts: an
     * `application/dtmf` INFO never carries a duration at all, and a
     * peer using the other form may have said `Duration=0` and held the
     * key for no time at all — this C ABI does not tell the two apart.
     */
    DIGIT_RECEIVED(26),
    /**
     * An INFO this end sent for `sipral_call_send_dtmf` reached a final
     * answer. `payload.call.digit` is the character and
     * `payload.call.status_code` what the far end answered — a 415 from
     * a switch that does not take this `Content-Type` included, so the
     * application learns which of the two INFO forms to try without
     * guessing from silence. A digit that waited behind another and whose
     * own INFO could then not be sent at all is reported the same way,
     * with 503: nothing reached the far end for that one, and no digit
     * after it is sent.
     */
    DTMF_SENT(27),
    /**
     * The lifecycle machine settled: a registrar answered again and
     * proved a path this stack had stopped believing in, or every rung
     * of a recovery ladder was climbed and none of them worked.
     * `payload.recovery` says which, and carries what the ladder that
     * got there actually knows. `crates/sipral-ffi/src/lifecycle.rs`
     * and `docs/16-lifecycle.md` are the ladder this reports on.
     */
    RECOVERY(28),
    /**
     * A notification arrived on a subscription, and has been answered.
     *
     * A1's other half. The NOTIFY is in `message`, whole and unparsed,
     * which is where every package this ABI has no reader for is read
     * from. `payload.subscription.has_dialog_info` says the body was
     * `application/dialog-info+xml` and could be read, and the picture it
     * updated is behind
     * sipral_subscription_dialog_count.
     * A body that could not be read arrives here all the same, with that
     * member zero and the request whole: a lamp showing what was last
     * known beats one showing what a malformed document happened to
     * contain.
     */
    NOTIFIED(30),
    /**
     * The INVITE for a call a push had already announced has arrived
     * (RFC 8599).
     *
     * C2's other half. Queued immediately before the
     * SipralEventKind.INCOMING_CALL naming the same call, and never
     * without one, so that an application reading its events in order
     * knows which screen the call belongs to before it is told there is a
     * call at all. That is the whole point: on a phone the ringing screen
     * exists first, and a stack that reports the INVITE without saying
     * which announcement it answers has made the application guess.
     *
     * `call` is the call, and `payload.announce.announcement` what
     * announced it. That announcement is spent: it is not waited for any
     * more, and `sipral_announcement_forget` on it answers
     * `SIPRAL_STATUS_WRONG_STATE` rather than taking a screen down twice.
     */
    CALL_ANNOUNCED(31),
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
 * Which of the two ways this stack accepts a digit reported the one
 * SipralEventKind.DIGIT_RECEIVED carries. Names for
 * `sipral_media_event_t::source`.
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
    ;

    companion object {
        fun of(value: Int): SipralDigitSource? = entries.firstOrNull { it.value == value }
    }
}

/**
 * What a SipralEventKind.RECOVERY reports happened, for
 * `payload.recovery.state`. Names for the two ways `sipral_ua`'s
 * lifecycle machine settles: a registrar answered again, or a recovery
 * ladder ran out of rungs.
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
 * The last rung a recovery ladder tried before it gave up, for
 * SipralEventKind.RECOVERY's `payload.recovery.rung`. Meaningful
 * only when `payload.recovery.state` is
 * SipralRecoveryOutcome.GAVE_UP. Names for `sipral_ua::Rung`, minus
 * Rung::GiveUp itself: `sipral_ua` reports the rung before it that
 * asked for something and went unanswered, not the give-up rung that
 * follows it.
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
 * `payload.recovery.reason`. Names for `sipral_ua::RecoveryFailure`.
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
 * What kind of link the application is on. Names for `from_link` and
 * `to_link` on sipral_stack_network_changed.
 *
 * Coarse on purpose: nothing here changes what is sent, and the one
 * value that changes what is *done* is SipralLink.DOWN. The rest is
 * carried so that a change of kind over an unchanged address — a tunnel
 * coming up, a phone moving from Wi-Fi to a mobile network that kept the
 * address — is visible as a change at all.
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
 * What a change of network is worth doing about. Names for
 * sipral_stack_network_changed's `out_recovery`.
 *
 * Returned from the call itself, so an application does not have to read
 * an event to find out whether anything happened: a laptop that flips
 * between two access points all day gets SipralRecovery.NOTHING
 * every time and never sends a REGISTER over it.
 */
enum class SipralRecovery(val value: Int) {
    /**
     * Never written by this build.
     */
    UNKNOWN(0),
    /**
     * Nothing this stack uses is different. Nothing is done and nothing
     * is sent.
     */
    NOTHING(1),
    /**
     * The address still stands, so the transports do. What is upstream
     * of it may not.
     */
    REREGISTER(2),
    /**
     * A wake: the transport already there is used first, and a new one
     * is asked for only once it turns out to be dead. Never returned by
     * this entry point; it is what sipral_stack_resumed starts.
     */
    REPROVE(3),
    /**
     * The address is gone. Everything bound to it is unusable and the
     * application has to open a transport again.
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
 * Where a subscription is. Names for
 * `sipral_subscription_event_t::state` and for
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
     * The notifier has it and has not decided. RFC 6665 §4.1.3's
     * `pending` is "insufficient policy information to grant or deny the
     * subscription yet", and nothing is known about the watched thing
     * until this becomes SipralSubscriptionState.ACTIVE.
     */
    PENDING(2),
    /**
     * Granted, and notifications are arriving.
     */
    ACTIVE(3),
    /**
     * Not live, and a fresh attempt is scheduled. The handle stays
     * valid: §4.1.2.2's new attempt is "an unrelated initial SUBSCRIBE
     * request with a freshly generated Call-ID and a new, unique From
     * tag", and this ABI keeps one name over both of them.
     */
    RETRYING(4),
    /**
     * Over, with nothing more coming. The handle names nothing from
     * here on.
     */
    ENDED(5),
    ;

    companion object {
        fun of(value: Int): SipralSubscriptionState? = entries.firstOrNull { it.value == value }
    }
}

/**
 * Why a subscription is not live. Names for
 * `sipral_subscription_event_t::reason`.
 *
 * Zero unless the state is SipralSubscriptionState.RETRYING or
 * SipralSubscriptionState.ENDED. The first nine are what a
 * `Subscription-State: terminated` said in its `reason` parameter (RFC
 * 6665 §4.1.3), and the rest are what happened here instead.
 */
enum class SipralSubscriptionEnd(val value: Int) {
    /**
     * Never written by this build.
     */
    UNKNOWN(0),
    /**
     * `deactivated`: the notifier wants this subscription started again
     * at once.
     */
    DEACTIVATED(1),
    /**
     * `probation`: started again, but not immediately.
     */
    PROBATION(2),
    /**
     * `rejected`: the notifier will not serve it, and asking again is
     * pointless.
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
     * `invariant`: the watched thing cannot change, so there is nothing
     * to notify about.
     */
    INVARIANT(7),
    /**
     * `terminated` with no reason parameter at all.
     */
    UNSTATED(8),
    /**
     * This end gave it up: sipral_subscription_end. It wins over
     * whatever the notifier's closing notification said its own reason
     * was, because the application asked for this one to stop and that
     * is the answer to why it is not live.
     */
    UNSUBSCRIBED(9),
    /**
     * The notifier answered 489: it does not know this event package.
     */
    BAD_EVENT(10),
    /**
     * The notifier refused the SUBSCRIBE with a status trying again
     * cannot fix.
     */
    REFUSED(11),
    /**
     * The SUBSCRIBE was redirected, and following a redirect for one is
     * not something this stack does by itself.
     */
    REDIRECTED(12),
    /**
     * Nothing answered: the notifier could not be reached at all.
     */
    UNREACHABLE(13),
    /**
     * The SUBSCRIBE was answered and the first NOTIFY never arrived
     * (§4.1.2.4's timer N, 64·T1).
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
 * What one watched dialog is doing, and what a lamp is lit from. Names
 * for `sipral_watched_dialog_t::phase` and for
 * sipral_subscription_lamp's `out_phase`.
 *
 * RFC 4235 §3.7.1's states, with the order they rank in for a lamp:
 * anything ringing beats anything settled, which is §3.7.2's virtual
 * state machine over every dialog of one resource.
 */
enum class SipralDialogPhase(val value: Int) {
    /**
     * Nothing is going on: no dialog, or every one of them terminated.
     * This is what an idle lamp shows.
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
     * which is SipralDialogPhase.IDLE when every dialog has ended.
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
 * Which end started a watched dialog. Names for
 * `sipral_watched_dialog_t::direction`.
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
 * How a watched dialog ended. Names for
 * `sipral_watched_dialog_t::ended`, and zero while it has not.
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
 * Which piece of text sipral_subscription_dialog_text is being asked
 * for.
 *
 * Every one of them is what the notifier wrote, unparsed: a display name
 * is whatever it put there, and an identity is a URI in the form it sent
 * it in.
 */
enum class SipralDialogText(val value: Int) {
    /**
     * Never asked for.
     */
    UNKNOWN(0),
    /**
     * The notifier's own name for this dialog, which is what it will
     * keep using for it.
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
     * Who the other end is, as a URI. This is the one a lamp shows
     * beside a ringing extension.
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
    /**
     * INVITEs a `sipral_stack_screen` policy refused (A8, D7).
     */
    val screenedRefusedByPolicy: Long,
    /**
     * INVITEs refused because their source was offering them faster
     * than `sipral_stack_invite_limit` allows.
     */
    val screenedRefusedByRate: Long,
    /**
     * INVITEs refused because every seat this stack keeps for a source
     * it is watching belonged to one still spending, and this source
     * could not be limited either — a flood from many addresses at
     * once rather than one calling too fast.
     */
    val screenedRefusedByCrowding: Long,
    /**
     * INVITEs refused 403 for naming a call they had no standing to
     * replace (RFC 3891 §3).
     */
    val screenedRefusedByReplaces: Long,
) {
    internal companion object {
        const val SLOTS: Int = 25

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
 * One codec this call could have used, and what became of it.
 *
 * Set `size` to `sizeof(sipral_codec_candidate_t)` before the call.
 *
 * The list is what the negotiation itself decided, kept from the moment
 * it decided it. It is not worked out again when it is asked for, because
 * a second run against a description that has since been renegotiated
 * would disagree with the first in exactly the case somebody is
 * debugging.
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
     * `SIPRAL_CODEC_OUTCOME_OUTRANKED`. `SIPRAL_CODEC_UNKNOWN`
     * otherwise, because nothing beat a codec that was never named and
     * nothing beat the one that won.
     */
    val outrankedBy: Long,
) {
    internal companion object {
        const val SLOTS: Int = 4

        fun of(slots: LongArray): SipralCodecCandidate = SipralCodecCandidate(
            slots[0],
            slots[1],
            slots[2],
            slots[3],
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
 * What was standing when the process was told it is about to stop
 * (sipral_stack_suspending's `out_report`).
 *
 * Set `size` to `sizeof(sipral_suspending_t)` before the call. Counts
 * and nothing else, because the window this is produced in is one where
 * an allocation that grows with the number of accounts is a cost with no
 * upper bound worth paying. Everything in it is already past tense by
 * the time it is read: the bindings have stopped being evidence, the
 * subscriptions have stopped being evidence, and nothing was sent about
 * either.
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
     * Calls that were up. Nothing was sent about them and nothing was
     * changed: a lid closing and opening again is seconds, and hanging
     * up a live call because the machine blinked is worse than finding
     * out a few seconds later that it is gone.
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
 * One dialog a `dialog` subscription has been told about, with the text
 * left behind: sipral_subscription_dialog_text reads that, because a
 * pointer into this library's own memory would be a pointer a caller
 * could outlive.
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
     * The SIP status behind how it ended, when the notifier sent one.
     * Zero otherwise.
     */
    val statusCode: Long,
    /**
     * How long it has been up, in milliseconds, when the notifier sent a
     * duration. Zero otherwise.
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
     * Whether the network said it will ask for notifications of the type
     * this account asked for. Zero means it did not say so, which §4.1.1
     * makes "MUST NOT assume they are coming" rather than "they are not":
     * an application that suspends itself on the strength of a push it
     * was never promised stops ringing.
     */
    val accepted: Long,
    /**
     * Whether `refresh_lead_ms` was sent at all.
     */
    val hasRefreshLead: Long,
    /**
     * How long before the binding lapses the network insists on seeing a
     * refresh, from a `sip.pnsreg` indicator (§4.1.4), in milliseconds.
     * Zero when the network sent none, which `has_refresh_lead` is how to
     * tell from a lead of zero.
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
    /**
     * Which transport this account's REGISTER and every request it
     * places go out on: SIPRAL_TRANSPORT_MAIN
     * for zero, which is what a caller that leaves this at zero already
     * gets, or a further number
     * sipral_stack_transport_bind
     * has bound. A number this stack has never bound is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`, naming it.
     *
     * Appended at the tail (task 8.4.10); the pinned `MIN_SIZE` is
     * unmoved, and what a caller built before this member existed never
     * sent reads as the zero that already means "the main transport".
     */
    val transport: Long = 0,
    /**
     * The push notification service to be woken through, as its
     * registered name: `apns`, `fcm`, `webpush` (RFC 8599 §4.1.1). Null
     * for an account that is not woken by push, which is every account on
     * a machine that does not suspend.
     *
     * These four go on the `Contact` of this account's REGISTER and on no
     * other request, ever: §4.1 says so because a `pn-prid` in the
     * `Contact` of an INVITE hands the far end a token that wakes this
     * device whenever it likes. The de-registration that gives the binding
     * up leaves the identifier out, which §4.1.2 also requires.
     */
    val pushProvider: String? = null,
    /**
     * The resource identifier the service issued for this installation —
     * the device token. Required when `push_provider` is given, and
     * refused without one.
     *
     * Whatever it holds is percent-escaped where the SIP grammar needs it
     * (§8.7), because an APNs token carries `=` and a Web Push identifier
     * is a whole URL.
     */
    val pushPrid: String? = null,
    /**
     * The extra value a service needs beside the identifier: the
     * application bundle for Apple, the sender for Firebase. §4.1.1 makes
     * it mandatory "if required for the specific PNS", so it is optional
     * here and the service decides.
     */
    val pushParam: String? = null,
    /**
     * Nonzero to say this device can send a binding refresh without being
     * woken by a push, which §4.1.4 makes it declare with a
     * `+sip.pnsreg` media feature tag.
     *
     * It is the application's fact and not this library's to guess: a
     * process the operating system has suspended has no timer that runs,
     * and one that claims otherwise gets a registrar that stops sending
     * the wake-ups the device is relying on.
     */
    val pushWakesItself: Long = 0,
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
    /**
     * Which transport the INVITE goes out on, read only together with
     * `destination`: SIPRAL_TRANSPORT_MAIN
     * for zero, or a further number
     * sipral_stack_transport_bind
     * has bound. Nonzero with `destination` null is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`: a call with no destination
     * override already goes out on its account's own transport, and
     * there is nothing to combine this with.
     *
     * Appended at the tail (task 8.4.10); the pinned `MIN_SIZE` is
     * unmoved.
     */
    val transport: Long = 0,
    /**
     * What this call offers and in what order, overriding
     * `sipral_stack_config_t::codecs` for it: codec names separated by
     * commas, as `sipral_codec_info_t::name` spells them, UTF-8 and not
     * NUL-terminated. Null for the stack's own order.
     *
     * Everything else the stack's catalogue carries — frame length,
     * named events, multiplexing, and SRTP where `srtp` here does not
     * override it — is kept, because a call that names its codecs has
     * said nothing about any of those. A name this build has no encoder
     * for, a name given twice, and a stray comma are each
     * `SIPRAL_STATUS_INVALID_ARGUMENT` naming what was wrong, and no
     * call.
     *
     * Read only for a call this stack describes the media of —
     * `media_address` set — for the reason `srtp` gives: a call placed
     * with `sdp` is a session the application wrote, and the order in it
     * is already the application's own. The names are still checked, so
     * that a caller who has one wrong learns it here either way.
     *
     * Appended at the tail (task 8.4.13); the pinned `MIN_SIZE` is
     * unmoved.
     */
    val codecs: String? = null,
)

/**
 * What to watch, and how. Handed to sipral_account_subscribe.
 *
 * Set `size` to `sizeof(sipral_subscribe_config_t)` before the call.
 * Everything but `target` and `package` may be left zero.
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
     * The event package, as the token that names it: `dialog` for a busy
     * lamp field (RFC 4235 §3.1), `message-summary` for message waiting
     * (RFC 3842 §3), `presence` (RFC 3856 §6.1).
     *
     * It goes out exactly as written here, because §8.2.1 compares it
     * byte for byte.
     */
    val `package`: String? = null,
    /**
     * The `Accept` value, when the package's default body type is not
     * the one wanted. Null sends no `Accept` at all, which §3.1.3 makes
     * the package's default — `application/dialog-info+xml` for
     * `dialog`.
     *
     * Sending the wrong one is worse than sending none: §4.1.2.1 has the
     * notifier answer 406 for a type it cannot generate, so nothing is
     * guessed on a caller's behalf.
     */
    val accept: String? = null,
    /**
     * How long to ask for, in seconds, or zero for this build's default
     * of one hour.
     *
     * What the notifier grants wins (§3.1.1: "The period of time in the
     * response is the one that defines the duration of the
     * subscription"), and the refresh is scheduled against that rather
     * than against this.
     */
    val expiresSeconds: Long = 0,
    /**
     * Where to send the SUBSCRIBE, as `host:port`, or null to send it
     * where the account registers — which is the outbound proxy for a
     * registered line, and the reason a phone behind a NAT is reachable
     * at all.
     */
    val destination: String? = null,
    /**
     * Which transport it goes out on, read only together with
     * `destination`, exactly as `sipral_call_config_t::transport` is.
     * Nonzero with `destination` null is
     * `SIPRAL_STATUS_INVALID_ARGUMENT`.
     */
    val transport: Long = 0,
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

    /** Let go of the listener a destroyed handle was left with. */
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
 * What SipralScreenCallback reads about one INVITE, before it has
 * had any effect at all.
 *
 * Filled by the library and handed to the callback as a `const`
 * pointer, the same shape crate::event::SipralEvent is: read `size`
 * before anything past it, and read nothing once the callback has
 * returned, since `message` — and `source`, when it is not null —
 * borrow from a request that is still in the middle of being processed
 * and are not this ABI's to keep alive a moment longer. The answer does
 * not travel in here: the callback returns it.
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
     * The far end of the bytes it arrived in, as `host:port` — the same
     * text form every address in this ABI takes. Null and zero for a
     * byte stream the application bound without naming its far end.
     */
    val source: String?,
    /**
     * The INVITE, whole and unparsed. `sipral_message_header` and its
     * three companions read any header out of these bytes the way they
     * read any other message this ABI hands over.
     */
    val message: ByteArray?,
)

/**
 * The screening policy: consulted once for every INVITE, before it has
 * any effect. Installed with crate::screening::sipral_stack_screen.
 *
 * **It runs with the stack's own lock held**, which is the opposite of
 * SipralEventCallback and is the
 * whole reason this type's module documentation exists — read it there.
 * In consequence: **this callback must not call back into the stack it
 * was given**, on this thread or on any other. Doing so does not
 * deadlock — every entry point that takes a stack takes its lock
 * without waiting and answers `SIPRAL_STATUS_BUSY` rather than block —
 * but it is refused outright rather than relied on, and a policy that
 * tries it gets an error code back instead of the call it wanted made.
 * A *different* stack is unaffected. It must not unwind, for the same
 * reason nothing in this ABI may: a panic that reached C across this
 * boundary would take the host process with it.
 *
 * `request` and everything it points at belong to the library and are
 * valid for the duration of this one call and no longer.
 *
 * **The answer is a SIP status code, and the numbers are chosen so that
 * no answer at all is a refusal.** `SIPRAL_SCREEN_ACCEPT` — 200 — lets
 * the INVITE through, exactly as it would arrive with no policy
 * installed. Anything else is a refusal, answered with that status when
 * that status refuses — 400 to 699 — and with 500 when it does not.
 *
 * Three ranges do not refuse, and each fails the same way. Zero is what
 * a binding hands back when the application's own listener threw and
 * the exception was caught at the boundary, and it is no status at all.
 * A 1xx is a provisional answer: it would leave the caller ringing at a
 * call this end has already forgotten, holding a server transaction
 * nothing here will ever answer. A 2xx that is not the one acceptance
 * is spelled with accepts nothing, and a 3xx redirects nowhere without
 * a `Contact` this ABI has no way to give it. So a policy whose answer
 * went missing does not let a stranger in on the strength of it, and a
 * policy that meant to refuse and named a number that cannot refuse is
 * a bug to fix rather than a reason to wave one through.
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
        agree(0, 16)
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
    external fun sipral_stack_screen(stack: Long, callback: Long): Int
    external fun sipral_stack_invite_limit(stack: Long, everyMs: Long, burst: Long): Int
    external fun sipral_account_subscribe(stack: Long, account: Long, configTarget: ByteArray?, configPackage: ByteArray?, configAccept: ByteArray?, configExpiresSeconds: Long, configDestination: ByteArray?, configTransport: Long, subscription: LongArray, nowMs: Long): Int
    external fun sipral_subscription_end(stack: Long, subscription: Long, nowMs: Long): Int
    external fun sipral_subscription_state(stack: Long, subscription: Long, state: LongArray): Int
    external fun sipral_subscription_lamp(stack: Long, subscription: Long, phase: LongArray): Int
    external fun sipral_subscription_dialog_count(stack: Long, subscription: Long, count: LongArray): Int
    external fun sipral_subscription_dialog_at(stack: Long, subscription: Long, index: Long, dialog: LongArray): Int
    external fun sipral_subscription_dialog_text(stack: Long, subscription: Long, index: Long, which: Long, buffer: ByteArray, needed: LongArray): Int
    external fun sipral_account_announce(stack: Long, account: Long, caller: ByteArray, announcement: LongArray, call: LongArray, nowMs: Long): Int
    external fun sipral_account_refresh_binding(stack: Long, account: Long, nowMs: Long): Int
    external fun sipral_announcement_forget(stack: Long, announcement: Long): Int
    external fun sipral_account_push_echo(stack: Long, account: Long, echo: LongArray): Int
    external fun sipral_account_add(stack: Long, configAor: ByteArray?, configRegistrar: ByteArray?, configContact: ByteArray?, configRegistrarAddress: ByteArray?, configDisplayName: ByteArray?, configAuthUser: ByteArray?, configAuthPassword: ByteArray?, configInstanceId: ByteArray?, configExpiresSeconds: Long, configHeadersBytes: ByteArray?, configHeadersLengths: LongArray?, configTransport: Long, configPushProvider: ByteArray?, configPushPrid: ByteArray?, configPushParam: ByteArray?, configPushWakesItself: Long, account: LongArray): Int
    external fun sipral_account_remove(stack: Long, account: Long): Int
    external fun sipral_account_register(stack: Long, account: Long, nowMs: Long): Int
    external fun sipral_account_unregister(stack: Long, account: Long, nowMs: Long): Int
    external fun sipral_account_registration_state(stack: Long, account: Long, state: LongArray): Int
    external fun sipral_call_place(stack: Long, account: Long, configTarget: ByteArray?, configSdp: ByteArray?, configDestination: ByteArray?, configKeepAllForks: Long, configMediaAddress: ByteArray?, configHeadersBytes: ByteArray?, configHeadersLengths: LongArray?, configSrtp: Long, configTransport: Long, configCodecs: ByteArray?, call: LongArray, nowMs: Long): Int
    external fun sipral_call_ring(stack: Long, call: Long, sdp: ByteArray, nowMs: Long): Int
    external fun sipral_call_ring_media(stack: Long, call: Long, configTarget: ByteArray?, configSdp: ByteArray?, configDestination: ByteArray?, configKeepAllForks: Long, configMediaAddress: ByteArray?, configHeadersBytes: ByteArray?, configHeadersLengths: LongArray?, configSrtp: Long, configTransport: Long, configCodecs: ByteArray?, nowMs: Long): Int
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
    external fun sipral_call_consult(stack: Long, call: Long, configTarget: ByteArray?, configSdp: ByteArray?, configDestination: ByteArray?, configKeepAllForks: Long, configMediaAddress: ByteArray?, configHeadersBytes: ByteArray?, configHeadersLengths: LongArray?, configSrtp: Long, configTransport: Long, configCodecs: ByteArray?, consultation: LongArray, nowMs: Long): Int
    external fun sipral_call_transfer_to(stack: Long, call: Long, other: Long, nowMs: Long): Int
    external fun sipral_call_accept_transfer(stack: Long, call: Long, configTarget: ByteArray?, configSdp: ByteArray?, configDestination: ByteArray?, configKeepAllForks: Long, configMediaAddress: ByteArray?, configHeadersBytes: ByteArray?, configHeadersLengths: LongArray?, configSrtp: Long, configTransport: Long, configCodecs: ByteArray?, placed: LongArray, nowMs: Long): Int
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
    external fun sipral_media_codec_candidate_count(media: Long, count: LongArray): Int
    external fun sipral_media_codec_candidate_at(media: Long, index: Long, candidate: LongArray): Int
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
    external fun sipral_stack_transport_bind(stack: Long, transport: Long, protocol: Long, local: ByteArray, remote: ByteArray, nowMs: Long, transportId: LongArray): Int
    external fun sipral_stack_transport_failed(stack: Long, transport: Long, error: Long, nowMs: Long): Int
    external fun sipral_stack_stream_closed(stack: Long, transport: Long, nowMs: Long): Int
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
    external fun sipral_call_record_json(stack: Long, call: Long, buffer: ByteArray, len: LongArray): Int
    external fun sipral_stack_diagnostics_json(stack: Long, buffer: ByteArray, len: LongArray): Int
    external fun sipral_stack_recording_start(stack: Long, note: ByteArray): Int
    external fun sipral_stack_recording_stop(stack: Long, buffer: ByteArray, len: LongArray): Int
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
    const val ABI_VERSION_MINOR: Long = 16

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
     * See SIPRAL_FEATURE_DTMF. RFC 6665 subscriptions and the
     * dialog-state package a busy lamp field is built on, reached with
     * sipral_account_subscribe.
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
     * The bound a datagram of control gets instead, on the way in.
     *
     * RTCP is compound: one report packet carries a sender or receiver report
     * for every source being heard, then the source description, then whatever
     * extended reports the session agreed on. A call between two ends stays
     * far inside the media bound, but nothing in RFC 3550 says it has to, and
     * what arrives is the peer's arithmetic rather than ours. So the media
     * bound stops being the reason a report is refused: an arriving datagram
     * that RFC 5761 §4 says is control gets this one, and everything else
     * still gets SIPRAL_MEDIA_PACKET_BYTES. It bounds the read, so it is
     * still a bound: a caller that says a megabyte is still refused.
     *
     * Sending is unchanged — what this stack builds is its own arithmetic, and
     * it fits in the media bound.
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
     * Never retired: sipral_stack_transport_failed and
     * sipral_stack_stream_closed can still stop it carrying traffic, and
     * sipral_stack_transport_bind is still what brings it back, exactly
     * as when this was the only number a stack had. Zero on
     * `sipral_account_config_t::transport` and `sipral_call_config_t::transport`
     * means this one, so a caller that never binds a second transport fills
     * neither in and gets exactly what it always got.
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
     * The answer that lets an INVITE through, and the reason it is a status
     * code rather than a flag.
     *
     * A policy answers with what it wants said: 200 to let the call arrive,
     * or the status to refuse it with. Making acceptance 200 rather than
     * zero is the whole safety property of this mechanism — zero is what a
     * binding hands back when the application's listener threw, and what a
     * caller who filled nothing in leaves behind, and neither of those may
     * mean "let the stranger in".
     */
    const val SCREEN_ACCEPT: Long = 200

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
        SipralScreenListeners.gone(stack)
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
     * Install, replace, or remove the screening policy for one stack.
     *
     * Every INVITE that survives sipral_stack_invite_limit reaches this
     * callback before anything else does: before ringing, before
     * `SIPRAL_EVENT_KIND_INCOMING_CALL`, before a call handle exists for
     * anybody to answer or reject. What the callback refuses is answered
     * with the SIP status it named — when that status refuses, and with 500
     * when it does not — and forgotten — no event, no handle,
     * nothing for the application to clean up — and what it takes, by
     * answering `SIPRAL_SCREEN_ACCEPT`, arrives exactly as it would with no
     * policy installed at all.
     *
     * `callback` given as `NULL` removes the policy: every INVITE reaches
     * the application again, the way it did before this was ever called.
     * Calling this a second time with a callback replaces the first outright,
     * on this stack alone — a different stack's policy, if it has one, is
     * untouched.
     *
     * The rule that the callback must not call back into this stack, and
     * must not unwind, is on SipralScreenCallback and is the reason
     * this module's own documentation exists; read it there before wiring
     * one up.
     *
     * Safety
     *
     * `callback`, when not null, is called on whichever thread is inside an
     * entry point that is feeding this stack bytes, for as long as the
     * policy stays installed. `user_data` is handed back to it untouched on
     * every call and read by nothing here.
     *
     * **Whatever `user_data` points at has to outlive the last call, and the
     * last call is not `sipral_stack_destroy` returning.** A destroy takes
     * this thread's share of the stack away; a receive already running on
     * another thread holds one of its own until it is done, and the policy
     * it is in the middle of asking is still asked. So the moment to free
     * what the pointer names is once no thread is inside this stack any
     * more, which is the application's own knowledge and not something this
     * ABI can answer. Replacing the policy, or removing it with `NULL`, has
     * the same shape: it takes the stack's lock, so it cannot run while a
     * policy is being asked, and once it returns the callback that was
     * there is not asked again.
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
     * `burst` calls from one address are let through at once; one more is
     * earned every `every_ms` after that. What either number means is
     * exactly what Rate already means by it — `sipral_stack_create`'s
     * default is ten at once and one every two thousand milliseconds,
     * loose on purpose, because in most deployments every legitimate call
     * arrives from the one address a phone registered with.
     *
     * A `burst` of zero, or an `every_ms` of zero, is
     * `SIPRAL_STATUS_INVALID_ARGUMENT` and changes nothing: the first admits
     * no call ever, the first or the one after a week of quiet, and the
     * second earns a token in no time, which is a limit that never limits —
     * Rate::unlimited is how the Rust API says that on purpose, and
     * there is deliberately no way to ask for it from C, since a deployment
     * that wants no floor at all can simply never call this.
     *
     * The floor is asked before sipral_stack_screen's own policy is: a
     * source that has exhausted it never reaches the callback at all, and is
     * counted in `sipral_counters_t::screened_refused_by_rate` or
     * `screened_refused_by_crowding`, never in `screened_refused_by_policy`.
     *
     * **It counts by source address, so it counts nothing it cannot name.**
     * An INVITE that arrived on a byte stream the application bound without
     * saying where the far end is has no address on it, and this floor lets
     * every one of those through to the policy — which is where a caller who
     * cannot identify a stream's far end has to decide, the same way
     * SipralScreenRequest.source being null is what it has to decide
     * on. Naming the far end in `sipral_stack_transport_bind`'s `remote` is
     * what puts a stream under this floor at all.
     *
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun stackInviteLimit(stack: Long, everyMs: Long, burst: Long) {
        check(SipralNative.sipral_stack_invite_limit(stack, everyMs, burst))
    }

    /**
     * Watch something at the far end (A1).
     *
     * One SUBSCRIBE goes out on `account`'s transport, to `account`'s
     * address, and the handle written back names the subscription from now
     * until it ends. Nothing has happened yet when this returns: the request
     * is in the transmit queue, and
     * `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` reports each step of what
     * becomes of it.
     *
     * A subscription refreshes itself for as long as it is live, at a
     * fraction of what the notifier granted, and starts a fresh one by itself
     * after something recoverable — both under this same handle. What ends
     * it for good is sipral_subscription_end, or an event saying it
     * ended with no retry, and the handle names nothing after that.
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
        check(SipralNative.sipral_account_subscribe(stack, account, configTarget, configPackage, configAccept, config.expiresSeconds, configDestination, config.transport, subscriptionSlot, nowMs))
        return subscriptionSlot[0]
    }

    /**
     * Give a subscription up.
     *
     * A SUBSCRIBE with `Expires: 0` (§4.1.2.3), and the subscription is not
     * over when this returns: §4.4.1 makes it live "until the NOTIFY
     * transaction with a `Subscription-State` of `terminated` completes", so
     * the closing notification is still answered and
     * `SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED` with
     * `SIPRAL_SUBSCRIPTION_END_UNSUBSCRIBED` says when it has. One that has
     * no dialog yet has nothing to send this in and ends at once.
     *
     * The handle stays usable until that event arrives, and names nothing
     * after it.
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
     *
     * SipralSubscriptionState.UNKNOWN for a handle that names nothing,
     * which is what a subscription that has ended leaves behind — and a
     * status of `SIPRAL_STATUS_OK` all the same, because "it is over" is an
     * answer to this question rather than a failure of it.
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
     * What a lamp for this subscription should show (A1).
     *
     * RFC 4235 §3.7.2's virtual state machine over every dialog the notifier
     * has told this subscription about: anything ringing beats anything
     * settled, and SipralDialogPhase.IDLE is what is left once they
     * have all ended. One call and one number, which is what a busy lamp
     * field is; sipral_subscription_dialog_count and the two after it
     * are for an application that wants to show who is on the call as well.
     *
     * `SIPRAL_STATUS_NOT_SUPPORTED` for a subscription that has no dialog
     * state at all — one to another package, or one that is not live, whose
     * last notification stopped being evidence the moment it stopped being
     * refreshed.
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
     * How many dialogs this subscription has been told about.
     *
     * They are in the order they were first heard of, and the index one has
     * here is stable only until the next notification arrives: a dialog that
     * ended is dropped from the table, and the numbering closes up behind
     * it. Read a dialog out in the same breath as the count, and read them
     * both again on the next
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
     * The same shape `sipral_last_error_message` has, and for the same
     * reason: the text belongs to the library and a pointer to it would be
     * one a caller could outlive. `out_needed` always receives the number of
     * bytes the text needs including the trailing NUL, so a caller that
     * brought nothing can ask with `capacity` zero and then ask again with
     * room. A buffer too small for the whole of it is
     * `SIPRAL_STATUS_BUFFER_TOO_SMALL` with nothing written to it.
     *
     * A piece the notifier did not send is one byte: the NUL.
     *
     * Safety
     *
     * `buffer` must be writable for `capacity` bytes, and `out_needed` must
     * point at one `size_t`.
     */
    fun subscriptionDialogText(stack: Long, subscription: Long, index: Long, which: Long, buffer: ByteArray): Long {
        val neededSlot = LongArray(1)
        check(SipralNative.sipral_subscription_dialog_text(stack, subscription, index, which, buffer, neededSlot))
        return neededSlot[0]
    }

    /**
     * A call is expected on this account, announced by a push (C2).
     *
     * `caller` is whoever the notification said is calling, as a SIP URI.
     * The binding is refreshed at once on whatever path exists — §4.1.3
     * makes that a MUST for a woken agent, and a transport the application
     * has not opened yet is the ordinary shape of a wake-up, so the REGISTER
     * is owed and goes the moment one is bound.
     *
     * Exactly one of the two values written back names something, and which
     * one is a race the caller cannot control:
     *
     * - `out_announcement` when nothing has arrived yet. The INVITE that
     *   matches will be reported as `SIPRAL_EVENT_KIND_CALL_ANNOUNCED`
     *   naming this announcement, immediately before the
     *   `SIPRAL_EVENT_KIND_INCOMING_CALL` for the same call; and
     *   `SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING` when none does.
     * - `out_call` when the INVITE beat the push. The screen just raised
     *   belongs to that call handle, and no announcement was recorded for it
     *   to answer. A `SIPRAL_EVENT_KIND_CALL_ANNOUNCED` still arrives for it
     *   when the incoming-call event has not been delivered yet, because the
     *   two are queued together and in that order; once it has, this return
     *   value is the only word about the match there will be.
     *
     * An account with no registrar has no binding to refresh, and for one of
     * those only the matching happens.
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
     * For the periodic wake-up a proxy sends to keep a suspended device's
     * binding alive (RFC 8599 §5.5). A push is evidence that the path to the
     * proxy is working, so a back-off earned by an earlier outage is not
     * what to wait for now and is dropped.
     *
     * Nothing is sent when a REGISTER is already in flight, which is already
     * the fastest path, or when the registration has failed in a way trying
     * again cannot fix — repeating a password that was refused is how an
     * account gets locked out, and a push does not change that. Both of those
     * are `SIPRAL_STATUS_OK`: the refresh was asked for and the answer is
     * that nothing needed sending.
     *
     * `SIPRAL_STATUS_INVALID_ARGUMENT` for an account that never registers,
     * which has no binding to refresh: it is the account that is wrong for
     * this call, not the build that is missing the feature. A send that could
     * not happen because no transport is bound yet is reported too, and is
     * not fatal: the refresh is remembered and goes out the moment one is.
     *
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun accountRefreshBinding(stack: Long, account: Long, nowMs: Long) {
        check(SipralNative.sipral_account_refresh_binding(stack, account, nowMs))
    }

    /**
     * Stop expecting an announced call.
     *
     * The user dismissed the screen, or the application decided the wake-up
     * was stale. `SIPRAL_STATUS_WRONG_STATE` when it had already been
     * fulfilled or had already expired, which is not a mistake: the event
     * that said so and this call can cross.
     *
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun announcementForget(stack: Long, announcement: Long) {
        check(SipralNative.sipral_announcement_forget(stack, announcement))
    }

    /**
     * What the registrar said about push, in the 2xx to the REGISTER that
     * asked for it.
     *
     * `SIPRAL_STATUS_NOT_SUPPORTED` when this account did not ask for push,
     * or when no binding it could have been said about is standing — none
     * granted yet, one given up, or one that has lapsed.
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
        val configPushProvider = config.pushProvider?.toByteArray(Charsets.UTF_8)
        val configPushPrid = config.pushPrid?.toByteArray(Charsets.UTF_8)
        val configPushParam = config.pushParam?.toByteArray(Charsets.UTF_8)
        val accountSlot = LongArray(1)
        check(SipralNative.sipral_account_add(stack, configAor, configRegistrar, configContact, configRegistrarAddress, configDisplayName, configAuthUser, configAuthPassword, configInstanceId, config.expiresSeconds, configHeadersBytes, configHeadersLengths, config.transport, configPushProvider, configPushPrid, configPushParam, config.pushWakesItself, accountSlot))
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
        val configCodecs = config.codecs?.toByteArray(Charsets.UTF_8)
        val callSlot = LongArray(1)
        check(SipralNative.sipral_call_place(stack, account, configTarget, config.sdp, configDestination, config.keepAllForks, configMediaAddress, configHeadersBytes, configHeadersLengths, config.srtp, config.transport, configCodecs, callSlot, nowMs))
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
     * `config.codecs` overrides the stack's codec order for this call in the
     * same way and for the same window: the answer written here is written
     * from it, and `sipral_call_answer_media` keeps what it settled.
     *
     * `sipral_call_answer_media` after this reuses the session and the
     * description written here rather than negotiating a second one. What
     * the 200 OK it sends carries then follows RFC 3262 §5 and RFC 6337
     * §3.1.1 exactly, from whether this call's 183 went out reliably — see
     * `docs/05-media.md`, "Ringing with media".
     *
     * Every other member of `config` — `target`, `sdp`, `destination`,
     * `transport`, `keep_all_forks`, `headers` — names something a call to
     * place would need, and this call already exists; setting one of them
     * is `SIPRAL_STATUS_INVALID_ARGUMENT` naming it.
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
        val configCodecs = config.codecs?.toByteArray(Charsets.UTF_8)
        check(SipralNative.sipral_call_ring_media(stack, call, configTarget, config.sdp, configDestination, config.keepAllForks, configMediaAddress, configHeadersBytes, configHeadersLengths, config.srtp, config.transport, configCodecs, nowMs))
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
     * RFC 4733 §3.2, in the order they were pressed, checked as a whole
     * before anything goes out: one character no keypad has, anywhere in the
     * string, sends nothing, not even the keys ahead of it. `duration_ms` is
     * how long each one lasts, or zero for the hundred milliseconds every
     * one of the three forms defaults to.
     *
     * `via` is a SipralDtmf, and it is chosen per send rather than per
     * call: which form a peer accepts is a fact about the peer, and an
     * application that has just learned the answer for this one must not have
     * to tear the call down to act on it. `SIPRAL_DTMF_RTP` puts the digits in
     * the media, where they replace the audio for as long as they last and
     * queue behind each other. The two INFO forms put one request per digit
     * in the dialog, but not all at once: over UDP, overlapping non-INVITE
     * transactions can arrive in any order, so the next digit's INFO waits
     * for the one before it to reach a final answer. A 2xx sends it; a
     * refusal, a timeout or a transport failure ends the sequence there
     * instead, and the digits still waiting are discarded rather than sent
     * out of order — the digit that ended it is what
     * `SIPRAL_EVENT_KIND_DTMF_SENT` names, and nothing is reported for the
     * ones it took down with it. Digits handed over while an INFO of this
     * call is still unanswered queue behind the ones already waiting, as the
     * media's do, rather than go out at once. A call holds at most sixty-four
     * INFO digits at once, the one in flight included; a string that would
     * take it past that is refused whole with `SIPRAL_STATUS_INVALID_ARGUMENT`,
     * the same as one with a character no keypad has, and nothing of it is
     * sent.
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
        val configCodecs = config.codecs?.toByteArray(Charsets.UTF_8)
        val consultationSlot = LongArray(1)
        check(SipralNative.sipral_call_consult(stack, call, configTarget, config.sdp, configDestination, config.keepAllForks, configMediaAddress, configHeadersBytes, configHeadersLengths, config.srtp, config.transport, configCodecs, consultationSlot, nowMs))
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
     * way), `headers`, `destination`, `transport` and `keep_all_forks` for
     * the INVITE this places. `Replaces` and `Referred-By` among `headers`
     * are `SIPRAL_STATUS_INVALID_ARGUMENT`, nothing sent and the transfer still
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
        val configCodecs = config.codecs?.toByteArray(Charsets.UTF_8)
        val placedSlot = LongArray(1)
        check(SipralNative.sipral_call_accept_transfer(stack, call, configTarget, config.sdp, configDestination, config.keepAllForks, configMediaAddress, configHeadersBytes, configHeadersLengths, config.srtp, config.transport, configCodecs, placedSlot, nowMs))
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
     * How many codecs were in the running on this call.
     *
     * This call's own catalogue, which is the stack's order unless
     * `sipral_call_config_t::codecs` named another. Zero is an answer, not a
     * failure: a call negotiated from a description with no media line in it
     * had nothing in the running at all.
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
     * D5 in one place: what this end offered, what the far end named, and
     * which of the two ran out first. An index past the end is
     * `SIPRAL_STATUS_INVALID_ARGUMENT` naming how many there are.
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
     * Say that a transport is open and may be written to — the main one
     * again, or a further one this stack has not had before.
     *
     * The one way back from sipral_stack_transport_failed, the way a
     * stream stack names its far end, and the way a further transport enters
     * the table at all. `transport` is SIPRAL_TRANSPORT_MAIN to (re)bind
     * the main one, or any other number: one this stack already has rebinds
     * it, and one it does not opens it — the number is the caller's own
     * choice, the same as `sipral_account_config_t::transport` and
     * `sipral_call_config_t::transport` read it. `out_transport_id` may be
     * null; when it is not, it receives that same number, which is where a
     * caller answering
     * SipralEventKind.TRANSPORT_WANTED
     * reads back the id it just gave one of those two configs.
     *
     * `protocol` is a crate::stack::SipralTransport.
     * Rebinding an existing transport takes zero to mean "whatever it
     * already speaks" and anything else has to agree with that or this is
     * `SIPRAL_STATUS_INVALID_ARGUMENT` — a stack retransmits or does not
     * according to what a transport was opened speaking, and changing that
     * underneath the timers would be a transport configured out of RFC 3261
     * §17 halfway through a call. Opening a new one needs a protocol to
     * speak, so zero there is the same refusal for the opposite reason:
     * nothing to fall back on.
     *
     * `local` is the address the far end reaches this one at, as `host:port`.
     * `remote` is the far end of a connection, and is refused on a datagram
     * transport, which has many.
     *
     * This is also how a request
     * SipralEventKind.TRANSPORT_WANTED
     * named gets to leave: once this returns `SIPRAL_STATUS_OK` for the
     * protocol and destination the event gave, the stack sends the request
     * again by itself on the next `sipral_stack_poll` — there is no further
     * event about that one request.
     *
     * Safety
     *
     * `local` must be readable for `local_len` bytes, `remote` for
     * `remote_len`, and `out_transport_id`, when it is not null, must point
     * at one `uint32_t`.
     */
    fun stackTransportBind(stack: Long, transport: Long, protocol: Long, local: String, remote: String, nowMs: Long): Long {
        val localBytes = local.toByteArray(Charsets.UTF_8)
        val remoteBytes = remote.toByteArray(Charsets.UTF_8)
        val transportIdSlot = LongArray(1)
        check(SipralNative.sipral_stack_transport_bind(stack, transport, protocol, localBytes, remoteBytes, nowMs, transportIdSlot))
        return transportIdSlot[0]
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

    /**
     * The operating system says this process stops shortly.
     *
     * Everything reached from here is synchronous, bounded by the number of
     * accounts and subscriptions, and cannot fail. Nothing is sent — see
     * `docs/16-lifecycle.md` for why a graceful de-registration is the wrong
     * thing to attempt in this window rather than the obvious one — and
     * nothing stays scheduled: a stack that is suspended and never resumed
     * has no deadline to fire and no work left behind.
     *
     * Calls that are up are left exactly as they are. A lid closing and
     * opening again is seconds, and hanging up a live call because the
     * machine blinked is worse than finding out a few seconds later that it
     * is gone.
     *
     * `out_report` receives what was found: bindings that stopped being
     * evidence, subscriptions whose last notification stopped being
     * evidence, and calls left untouched.
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
     * Arbitrary time has passed — arbitrary, not measurable, because the
     * clock this stack is driven by did not run while the machine was
     * suspended — and every transport may be dead. What was believed is
     * dropped and proved again: the transport already there is used first,
     * because most wakes are short and it still works, and
     * sipral_account_rebind is how the application hands over a new one
     * once this stack says it needs one.
     *
     * Safe to call without a matching sipral_stack_suspending. Some
     * platforms only notify on the way back.
     *
     * Safety
     *
     * Safe to call with any handle value.
     */
    fun stackResumed(stack: Long, nowMs: Long) {
        check(SipralNative.sipral_stack_resumed(stack, nowMs))
    }

    /**
     * The network is a different one, described before and after in as much
     * detail as the decision needs.
     *
     * `from_link`/`to_link` is a SipralLink. `*_address` is the local
     * address this stack's transports are bound to, as an IPv4 or IPv6
     * literal with no port — a change of it invalidates every transport and
     * every binding at once. `*_interface` is the platform's own identity
     * for the interface, never parsed and only ever compared to another one
     * of itself; two networks can hand out the same address, and a phone
     * that walks from one office to another gets away with it until a call
     * comes in. `*_resolves` is whether a name can become an address there,
     * because that is the one failure that leaves everything else looking
     * healthy. Any of the four address or interface arguments may be null
     * with a length of zero, for a fact the application has none to give.
     *
     * `out_recovery` receives what was decided, as a SipralRecovery, so
     * this is safe to call as often as the platform delivers the
     * notification — most of the time nothing this stack uses is different,
     * and `SIPRAL_RECOVERY_NOTHING` is the whole of what happens. It may be
     * null.
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
     * There is no usable interface.
     *
     * Distinct from sipral_stack_name_resolution_lost because the
     * recovery is the opposite one: with nothing that can leave, nothing is
     * tried and nothing is scheduled, which is the cheapest this stack ever
     * is. The way out is sipral_stack_network_changed, the notification
     * every platform delivers when an interface comes back.
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
     * The dangerous one: the interface is up and packets leave, so
     * everything reads healthy, while every address this stack learned from
     * a name may now stand for somewhere else. A binding whose registrar was
     * written as a name stops being evidence; one pointed at a literal
     * address never needed a resolver and is left running.
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
     * `remote` is the far end this account's requests go to now, as
     * `host:port`. `contact` is where this endpoint can be reached, as it
     * goes in `Contact`; it is not optional, because after a change of
     * address the old one names somewhere the far end cannot reach, and a
     * stack that let it stand would register a binding that silently
     * receives nothing.
     *
     * `transport` must be one this stack already has —
     * SIPRAL_TRANSPORT_MAIN or
     * a further one sipral_stack_transport_bind
     * has bound — and any other number is `SIPRAL_STATUS_INVALID_ARGUMENT`:
     * this call points an account at a transport, it does not open one.
     *
     * Safe to call whether or not this stack is waiting for it. When it is,
     * answering climbs the next rung at once rather than waiting out the
     * rest of the back-off — the application answering in milliseconds is
     * the normal case, and there is nothing to be gained by making a wake
     * take a further half minute. When it is not, this still repoints the
     * account, and the next REGISTER this stack sends for it — a refresh, or
     * the next rung of a ladder started afterwards — uses what was given
     * here.
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
     * Copy one call's diagnostic record into `buffer`, as the JSON
     * `docs/14-diagnostics.md` describes.
     *
     * Readable at any point in the call's life, and for as long after it as
     * the endpoint has not evicted the record to make room for a newer one —
     * `sipral_stack_config_t` has no member for the ceiling yet, so today
     * that is sipral_core::diag::RecordLimits::DEFAULT. A call whose
     * record has been evicted, or that has had nothing decided about it yet,
     * answers `SIPRAL_STATUS_OK` with `{}`: an empty record is still a
     * record, and refusing to read one that happens to be empty would make
     * a caller unable to tell "nothing yet" from "something went wrong".
     *
     * `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
     * document, with the length needed in `out_len`.
     *
     * Safety
     *
     * `buffer` must be writable for `capacity` bytes or be null with a
     * capacity of zero, and `out_len` must point at one `size_t` or be null.
     */
    fun callRecordJson(stack: Long, call: Long, buffer: ByteArray): Long {
        val lenSlot = LongArray(1)
        check(SipralNative.sipral_call_record_json(stack, call, buffer, lenSlot))
        return lenSlot[0]
    }

    /**
     * Copy the whole diagnostic document into `buffer`: what a bug report
     * carries, as the JSON `docs/14-diagnostics.md` describes.
     *
     * That is the endpoint's own record — everything decided outside any
     * call — and then one record per call still held, in the same document,
     * with the number of records evicted to make room. It is deliberately
     * the whole of it rather than the endpoint's half: a report that arrives
     * without the calls it is about answers nothing, and
     * sipral_call_record_json is already the way to ask about one call.
     *
     * `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
     * document, with the length needed in `out_len`.
     *
     * Safety
     *
     * `buffer` must be writable for `capacity` bytes or be null with a
     * capacity of zero, and `out_len` must point at one `size_t` or be null.
     */
    fun stackDiagnosticsJson(stack: Long, buffer: ByteArray): Long {
        val lenSlot = LongArray(1)
        check(SipralNative.sipral_stack_diagnostics_json(stack, buffer, lenSlot))
        return lenSlot[0]
    }

    /**
     * Start recording the signalling this stack is fed from here on
     * (`docs/18-replay.md`), with the same seed `sipral_stack_create` built
     * it with. Read crate::diagnostics before reaching for this: what it
     * records and what it deliberately never does is written down there
     * once rather than repeated at each of these three entry points.
     *
     * `note` is one line of prose for whoever opens the file later, or null
     * for none.
     *
     * A recording already running is replaced, not refused: see
     * crate::diagnostics for why that is the right answer here and the
     * wrong one for `sipral_media_record_start`.
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
     * `SIPRAL_STATUS_WRONG_STATE` when no recording is running, the same
     * answer `sipral_media_record_stop` gives for the same question about
     * an audio recording. `SIPRAL_STATUS_WRONG_STATE` again, with the reason
     * in the last error, when something this session was fed could not go
     * in the recording — a message with a body that is not text is the one
     * way that happens — in which case nothing is written to `buffer` and
     * the recording is not produced at all: a text format that quietly left
     * out the one message it could not spell would replay into a different
     * session and say nothing about it.
     *
     * `SIPRAL_STATUS_BUFFER_TOO_SMALL` when `buffer` cannot hold the whole
     * text, with the length needed in `out_len` — asking again with a bigger
     * buffer answers the same recording rather than stopping a new one,
     * so a caller that does not yet know how big a buffer to bring may ask
     * twice: once to be told, once to be handed the text. Once a call here
     * copies the whole of it out, the recording is gone from the stack, the
     * same as `sipral_last_error_message` empties the slot it reads on a
     * call that succeeds.
     *
     * Safety
     *
     * `buffer` must be writable for `capacity` bytes or be null with a
     * capacity of zero, and `out_len` must point at one `size_t` or be null.
     */
    fun stackRecordingStop(stack: Long, buffer: ByteArray): Long {
        val lenSlot = LongArray(1)
        check(SipralNative.sipral_stack_recording_stop(stack, buffer, lenSlot))
        return lenSlot[0]
    }

}
