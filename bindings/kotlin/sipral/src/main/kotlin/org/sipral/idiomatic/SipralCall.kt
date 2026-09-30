// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

package org.sipral.idiomatic

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.mapNotNull
import kotlinx.coroutines.withTimeout
import org.sipral.Sipral
import org.sipral.SipralCallConfig
import org.sipral.SipralCallEvent
import org.sipral.SipralRecordConfig
import org.sipral.SipralTextEvent
import org.sipral.SipralCallState
import org.sipral.SipralConsentTone
import org.sipral.SipralDtmfDetection
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralHeader
import org.sipral.SipralProgressConfig
import org.sipral.SipralProgressEvent
import org.sipral.SipralStatus
import org.sipral.SipralToggle
import org.sipral.SipralToneRegion

/**
 * A `sipral_handle_t` naming one call, and the actions it takes.
 *
 * Built by [SipralClient.placeCall] for one this stack placed, and by
 * [SipralClient.answerCall] for one that came in; either way it is
 * registered with its client before the caller ever sees it, so
 * [deliver] always has somewhere to put an event that names this call.
 */
class SipralCall internal constructor(
    val client: SipralClient,
    val handle: Long,
    /** The socket the call was placed or answered on: the call's until
     * [media] exists, [SipralMedia]'s from then on -- and whichever socket
     * [moveMedia] puts in its place. */
    private val mediaSocket: DatagramSocket,
    mediaAddress: String,
    /** The `SIPRAL_EVENT_KIND_INCOMING_CALL` payload this call was answered
     * from, for [identity] and [answering]; null for a call this end placed. */
    private val incoming: SipralCallEvent? = null,
    /** The socket this call's real-time text travels on, when it was placed
     * or answered with `text = true`: the call's until [media] exists, and
     * the media's from then on. */
    private val textSocket: DatagramSocket? = null,
) : AutoCloseable {
    /** The call's real-time text socket, as `host:port`, when it has one. */
    val textAddress: String? = textSocket?.let { formatAddress(it.localAddress.hostAddress, it.localPort) }

    /** The recording session copying this call to a recording server,
     * while one does. */
    @Volatile
    var recordingSession: SipralRecordingSession? = null
        private set

    /** The call's media socket, as `host:port`: the name
     * `sipral_stack_nat_map` gave it, and so of its connection to a TURN
     * server; after [moveMedia], the new one. */
    @Volatile
    internal var mediaAddress: String = mediaAddress
        private set
    /**
     * This call's audio, once `SIPRAL_EVENT_KIND_MEDIA_STARTED` has minted
     * it. Null before then and after the call has ended and [close] has
     * run.
     */
    @Volatile
    var media: SipralMedia? = null
        private set

    /** Set once `SIPRAL_EVENT_KIND_CALL_ENDED` has been delivered. */
    @Volatile
    var ended: Boolean = false
        private set

    // Guards every read-then-act on [media] that [close] and [deliver] each
    // do, and the [closing] flag [close] sets under it before doing
    // anything else. Without this, close() reading `media == null` and
    // deliver() minting one for the same MEDIA_STARTED race exactly the way
    // any check-then-act does: close() finds nothing to release and closes
    // the raw socket out from under deliver()'s still-running mint, which
    // then either throws (uncaught, since neither call site expects it) or
    // hands back a SipralMedia nothing ever closes -- a `sipral_call_media`
    // handle minted and never released, the one failure mode
    // docs/08-ffi.md's "Handles" section exists to rule out.
    private val mediaLock = Any()
    private var closing = false

    // A SharedFlow, not a Channel: a Channel is single-consumer, and an
    // application reasonably wants more than one concurrent reader of one
    // call's events -- a coroutine counting digits and another waiting for
    // the call to end, the way bindings/kotlin/examples/Agent.kt runs both
    // at once. Two concurrent collectors of one Channel-backed Flow race
    // for every element instead of each seeing all of them, which is a
    // silent, sporadic way to lose exactly the event a second collector was
    // waiting for.
    private val eventsFlow = MutableSharedFlow<SipralEvent>(
        replay = 0,
        extraBufferCapacity = 4096,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )

    /**
     * Every event this call's handle names, decoded whole, in order.
     *
     * Bounded at 4096 unread events per collector, `DROP_OLDEST`: a
     * collector more than 4096 events behind the poll thread silently loses
     * its oldest unread ones rather than block delivery or grow without
     * bound -- the same trade-off [SipralClient.events] documents, and for
     * the same reason. Keep per-event work in a `collect` short (as
     * [digits] and `Agent.kt`'s own handling both do).
     */
    val events: SharedFlow<SipralEvent> = eventsFlow

    /**
     * Every `SIPRAL_EVENT_KIND_DIGIT_RECEIVED` this call has heard. [digitOf]
     * reads the character off each one, an RFC 4733 (RTP) digit the same way
     * as either INFO form, off `event.payload.media.digit` -- the generated
     * JNI shim carries the whole payload union now, not only the head of the
     * event.
     */
    val digits: Flow<SipralEvent> = events.filter { it.kind == SipralEventKind.DIGIT_RECEIVED.value.toLong() }

    /**
     * The real-time text the far end types (RFC 4103): each
     * `SIPRAL_EVENT_KIND_TEXT_RECEIVED`'s [textOf], in order, for a call
     * placed or answered with `text = true` whose far end agreed a text
     * stream. The same rules as [events].
     */
    val text: Flow<SipralTextEvent> = events.mapNotNull { textOf(it) }

    /** `sipral_call_state`, read fresh -- not cached from the last event,
     * which a status query between events would otherwise miss. */
    val state: SipralCallState
        get() = SipralCallState.of(retryBusy { Sipral.callState(client.handle, handle) }.toInt())
            ?: SipralCallState.UNKNOWN

    /** `sipral_call_hold_state`: (this end holding the far end, the far end
     * holding this one). */
    val holdState: Pair<Boolean, Boolean>
        get() = retryBusy { Sipral.callHoldState(client.handle, handle) }
            .let { (here, there) -> (here != 0L) to (there != 0L) }

    /** Called by [SipralClient] on its own poll thread. Not for application
     * use. */
    internal fun deliver(event: SipralEvent) {
        if (event.kind == SipralEventKind.MEDIA_STARTED.value.toLong()) {
            synchronized(mediaLock) {
                if (media == null && !closing) {
                    // Behind a NAT the poll thread has been reading this
                    // socket for the stack until now; from the media handle
                    // on, SipralMedia does.
                    client.mediaSocketTaken(mediaAddress)
                    media = mintMedia()
                }
            }
        }
        if (event.kind == SipralEventKind.CALL_ENDED.value.toLong()) {
            ended = true
        }
        eventsFlow.tryEmit(event)
    }

    /**
     * `SipralMedia`'s own constructor mints through `sipral_call_media`,
     * unguarded by [retryBusy] the way every other signalling call in this
     * layer is, because minting normally runs from inside the poll thread's
     * own event callback (docs/08-ffi.md, "re-entry rules") where the
     * ordinary contention `retryBusy` waits out cannot arise on its own.
     * The one way it still can is a second thread's own signalling call --
     * [SipralCall.hangup] from [close], most often -- landing on the stack's
     * lock at the same moment, which is ordinary contention by the same
     * definition and deserves the same retry rather than a mint this method
     * lets escape uncaught out of the poll thread's own delivery loop. A
     * call that has ended in the meantime is not ordinary: `WRONG_STATE` or
     * `STALE_HANDLE` here means the session this event announced is already
     * gone, which [close] running concurrently already accounts for by way
     * of [closing], so there is nothing left to mint and null is the answer
     * rather than a throw.
     */
    private fun mintMedia(): SipralMedia? = try {
        SipralMedia(
            client, handle, mediaSocket, pumpsFrames = client.audioMode is SipralAudioMode.Application,
            textSocket = textSocket,
        )
    } catch (gone: SipralException) {
        if (gone.status == SipralStatus.WRONG_STATE || gone.status == SipralStatus.STALE_HANDLE) {
            null
        } else {
            throw gone
        }
    }

    // -- actions -------------------------------------------------------------

    /** `sipral_call_answer_media`: accept, with this stack running the
     * audio through the media socket this call already opened. */
    internal fun answer(address: String) {
        retryBusy { Sipral.callAnswerMedia(client.handle, handle, address, client.nowMs()) }
    }

    /** `sipral_call_answer_with`: accept as [answer] does, with the real-time
     * text socket this call holds, [codecs] in that order, `isfocus` when
     * [focus], and Generic NACKs and reduced-size RTCP when [feedback]. */
    internal fun answerWith(address: String, codecs: String?, focus: Boolean, feedback: Boolean) {
        val config = SipralCallConfig(
            mediaAddress = address,
            codecs = codecs,
            textAddress = textAddress,
            feedback = if (feedback) SipralToggle.ON.value.toLong() else 0L,
            focus = if (focus) 1L else 0L,
        )
        retryBusy { Sipral.callAnswerWith(client.handle, handle, config, client.nowMs()) }
    }

    // -- conferences ---------------------------------------------------------

    /**
     * `sipral_call_set_focus`: say (true) or stop saying that this end is
     * the focus of a conference the call belongs to (RFC 4579 §4.2):
     * `isfocus` on the `Contact` of every message the call sends from here
     * on -- the answer, for a call not answered yet, and the next re-INVITE
     * or UPDATE for one that is up.
     */
    fun setFocus(focus: Boolean) {
        retryBusy { Sipral.callSetFocus(client.handle, handle, if (focus) 1L else 0L) }
    }

    /** `sipral_call_conference_uri`: the conference this call belongs to,
     * when its far end said it is a focus (`isfocus` on its `Contact`), and
     * null when it said nothing of the kind. */
    fun conferenceUri(): String? = try {
        protocolText { buffer -> retryBusy { Sipral.callConferenceUri(client.handle, handle, buffer) } }
    } catch (none: SipralException) {
        if (none.status != SipralStatus.NOT_A_FOCUS) {
            throw none
        }
        null
    }

    /**
     * `sipral_call_subscribe_conference`: subscribe to the conference
     * package of this call's focus (RFC 4579 §3.4), from the call's own
     * account. The subscription outlives the call; each notification is a
     * `SIPRAL_EVENT_KIND_CONFERENCE_CHANGED`, and
     * [SipralSubscription.conference] reads the picture. `NOT_A_FOCUS` for a
     * call whose far end is not one.
     */
    fun subscribeConference(): SipralSubscription {
        val made = retryBusy { Sipral.callSubscribeConference(client.handle, handle, client.nowMs()) }
        return SipralSubscription(client, made, "conference")
    }

    // -- a recording server --------------------------------------------------

    /**
     * `sipral_call_record_to`: record this call to the recording server
     * [server] (SIPREC, RFC 7866). The recording session -- an INVITE with
     * `Require: siprec`, the metadata (RFC 7865) and one send-only stream per
     * party -- goes from the call's account: to [destination] (`host:port`)
     * over a TCP connection this client opens for it, or, with no
     * [destination], where the account sends -- which RFC 3261 does not let
     * an INVITE this large reach over UDP, so the client must then signal
     * over TCP or TLS. Two sockets are bound at [host] for the copies of the
     * audio. `WRONG_STATE` before `SIPRAL_EVENT_KIND_MEDIA_STARTED`, and for
     * a call already recorded.
     */
    fun recordTo(server: String, destination: String? = null, host: String = "127.0.0.1"): SipralRecordingSession {
        val current = synchronized(mediaLock) { media }
            ?: throw SipralException(SipralStatus.WRONG_STATE, "the call's media has not started")
        val thisEnd = DatagramSocket(InetSocketAddress(host, 0))
        val farEnd = try {
            DatagramSocket(InetSocketAddress(host, 0))
        } catch (refused: Exception) {
            thisEnd.close()
            throw refused
        }
        val thisEndAddress = formatAddress(thisEnd.localAddress.hostAddress, thisEnd.localPort)
        val farEndAddress = formatAddress(farEnd.localAddress.hostAddress, farEnd.localPort)
        var link: Long? = null
        val recording = try {
            link = destination?.let { client.openRecordingLink(it) }
            val config = SipralRecordConfig(
                server = server,
                destination = destination,
                transport = link ?: 0L,
                thisEnd = thisEndAddress,
                farEnd = farEndAddress,
            )
            retryBusy { Sipral.callRecordTo(client.handle, handle, config, client.nowMs()) }
        } catch (refused: Exception) {
            link?.let { client.closeRecordingLink(it) }
            thisEnd.close()
            farEnd.close()
            throw refused
        }
        current.copyRecording(thisEnd, farEnd)
        val session = SipralRecordingSession(recording, thisEndAddress, farEndAddress, this)
        recordingSession = session
        client.recordingStarted(recording, this, link)
        return session
    }

    /** `sipral_call_stop_recording_to`: stop recording this call to its
     * recording server; the recording session is hung up. */
    fun stopRecordingToServer() {
        retryBusy { Sipral.callStopRecordingTo(client.handle, handle, client.nowMs()) }
        recordingEnded()
    }

    /** The recording session is over, whoever ended it: the copies stop and
     * their sockets close. */
    internal fun recordingEnded() {
        recordingSession = null
        media?.stopCopyingRecording()
    }

    /** `sipral_call_reject`. */
    fun reject(code: Long = 486) {
        retryBusy { Sipral.callReject(client.handle, handle, code, client.nowMs()) }
    }

    /** `sipral_call_hangup`. */
    fun hangup() {
        retryBusy { Sipral.callHangup(client.handle, handle, client.nowMs()) }
    }

    /**
     * `sipral_call_hangup_for`: end the call as [hangup] does, and say why
     * with a `Reason` (RFC 3326) on the BYE, or on the CANCEL a call still
     * ringing turns into. A call that came in and was never answered is
     * refused with only the Q.850 value (RFC 6432): a SIP one would repeat
     * the refusal's own status.
     */
    fun hangup(reason: SipralHangupReason) {
        retryBusy {
            Sipral.callHangupFor(
                client.handle, handle, (reason.sipCause ?: 0).toLong(), (reason.q850Cause ?: 0).toLong(),
                reason.text ?: "", client.nowMs(),
            )
        }
    }

    /**
     * `sipral_call_redirect`: answer a call that came in, and is still
     * ringing, with a 3xx (RFC 3261 §21.3) naming where to try instead, in
     * order of preference -- 302 is call forwarding. [reason] --
     * `no-answer`, `user-busy`, `unconditional`, `deflection`,
     * `do-not-disturb` or any other token -- adds a `Diversion` (RFC 5806)
     * naming the address that was called.
     */
    fun redirect(targets: List<String>, status: Int = 302, reason: String? = null) {
        client.redirect(handle, targets, status, reason)
    }

    /** Who is calling, beyond the `From`: for a call that came in, what the
     * network asserted behind the account's trust gate, the caller's
     * `Privacy` and where the call was diverted from. Empty for a call this
     * end placed. */
    fun identity(): SipralCallerIdentity = IdentityReader.identity(client, handle, incoming)

    /** How a call that came in asked to be answered (RFC 5373) and rung
     * (`Alert-Info`). */
    fun answering(): SipralAnswering = IdentityReader.answering(client, handle, incoming)

    /**
     * Offer this call at a socket on the network the device is on now: what
     * `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED` asks for once
     * [SipralClient.networkChanged] has said the old one is gone.
     *
     * A socket is bound at [host] -- the new network's address,
     * [SipralClient.networkChanged]'s own by default -- asked where it
     * appears from when the client has a STUN server, and the call offered
     * there with `sipral_call_media_readdress`: a re-INVITE with only `c=`
     * and the port moved (RFC 3264 §8.3.1), carrying the account's new
     * `Contact`. The new socket carries the call from then on, whatever the
     * far end answers; the answer arrives as
     * `SIPRAL_EVENT_KIND_SESSION_CHANGED`, a refusal as
     * `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED`. A call under ICE is refused
     * with `WRONG_STATE`: [restartIce] moves it.
     */
    fun moveMedia(host: String? = null, port: Int = 0) {
        val bindOn = host ?: client.currentHost
        client.moving {
            val current = synchronized(mediaLock) { media }
                ?: throw SipralException(SipralStatus.WRONG_STATE, "the call has no media to move yet")
            val fresh = client.openMediaSocket(bindOn, port)
            val local = formatAddress(fresh.localAddress.hostAddress, fresh.localPort)
            try {
                val public = client.mapMovedSocket(fresh, local)
                retryBusy { Sipral.callMediaReaddress(client.handle, handle, local, public ?: "", client.nowMs()) }
            } catch (refused: Exception) {
                client.giveBackMediaSocket(fresh, local)
                throw refused
            }
            val old = mediaAddress
            client.mediaSocketTaken(local)
            client.forgetMapping(old)
            current.replaceSocket(fresh)
            mediaAddress = local
        }
    }

    /** `sipral_call_hold`. */
    fun hold() {
        retryBusy { Sipral.callHold(client.handle, handle, client.nowMs()) }
    }

    /** `sipral_call_resume`. */
    fun resume() {
        retryBusy { Sipral.callResume(client.handle, handle, client.nowMs()) }
    }

    /**
     * `sipral_call_restart_ice`: offer the call again with new ICE
     * credentials (RFC 8445 §9) and check every pair again once the far end
     * answers, while the path it has carries the audio. The new path arrives
     * as another `SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN`.
     */
    fun restartIce() {
        retryBusy { Sipral.callRestartIce(client.handle, handle, client.nowMs()) }
    }

    /** `sipral_call_set_headers`. */
    fun setHeaders(headers: List<SipralHeader>) {
        retryBusy { Sipral.callSetHeaders(client.handle, handle, headers) }
    }

    /** `sipral_call_send_dtmf`. `via` is a `SipralDtmf` value; RTP (1) is
     * the default and the one every gateway on the path carries end to end,
     * and sends the tones in the audio on a call that negotiated no
     * telephone event; `IN_BAND` (4) sends the tones on any call. */
    fun sendDtmf(digits: String, via: Long = 1, durationMs: Long = 100) {
        retryBusy { Sipral.callSendDtmf(client.handle, handle, digits, via, durationMs, client.nowMs()) }
    }

    /** `sipral_call_dtmf_detection`: when this call listens for digits in
     * the far end's audio. One heard there is a
     * `SIPRAL_EVENT_KIND_IN_BAND_DIGIT`, read with [digitOf] like any
     * other. */
    fun setDtmfDetection(mode: SipralDtmfDetection) {
        retryBusy { Sipral.callDtmfDetection(client.handle, handle, mode.value.toLong()) }
    }

    /**
     * `sipral_call_detect_progress`: listen for the network's tones, decide
     * who answered and listen for the machine's beep, as [options] say.
     * Call it straight after [SipralClient.placeCall], before the far end
     * answers; each thing heard is a `SIPRAL_EVENT_KIND_PROGRESS_DETECTED`,
     * read with [progressOf].
     */
    fun detectProgress(options: SipralProgressOptions = SipralProgressOptions()) {
        val config = SipralProgressConfig(
            listen = SipralToggle.ON.value.toLong(),
            region = options.region.value.toLong(),
            answeringMachine = toggleOf(options.answeringMachine),
            beep = toggleOf(options.beep),
            beepWindowMs = options.beepWindowMs,
            maxInitialSilenceMs = options.maxInitialSilenceMs,
            maxGreetingMs = options.maxGreetingMs,
            silenceAfterGreetingMs = options.silenceAfterGreetingMs,
            maxWords = options.maxWords,
            minWordMs = options.minWordMs,
            minWordGapMs = options.minWordGapMs,
            maxDecisionMs = options.maxDecisionMs,
            minSpeechAboveFloorDb = options.minSpeechAboveFloorDb,
            beepMinMs = options.beepMinMs,
            beepMaxMs = options.beepMaxMs,
            toneCycles = options.toneCycles,
        )
        retryBusy { Sipral.callDetectProgress(client.handle, handle, config) }
    }

    /** `sipral_call_detect_progress` with listening off. */
    fun stopProgress() {
        val config = SipralProgressConfig(listen = SipralToggle.OFF.value.toLong())
        retryBusy { Sipral.callDetectProgress(client.handle, handle, config) }
    }

    /** `sipral_call_consent_tone`: beep while this call is recorded, every
     * value left at zero the library's default (1400 Hz, 18 dB below 0 dBm0,
     * 200 ms every fifteen seconds); [local] has this end hear it too. */
    fun setConsentTone(
        frequencyHz: Long = 0,
        attenuationDb: Long = 0,
        lengthMs: Long = 0,
        intervalMs: Long = 0,
        local: Boolean = true,
    ) {
        val tone = SipralConsentTone(
            enabled = SipralToggle.ON.value.toLong(),
            frequencyHz = frequencyHz,
            attenuationDb = attenuationDb,
            lengthMs = lengthMs,
            intervalMs = intervalMs,
            local = toggleOf(local),
        )
        retryBusy { Sipral.callConsentTone(client.handle, handle, tone) }
    }

    /** `sipral_call_consent_tone` with the tone off. */
    fun clearConsentTone() {
        val tone = SipralConsentTone(enabled = SipralToggle.OFF.value.toLong())
        retryBusy { Sipral.callConsentTone(client.handle, handle, tone) }
    }

    /**
     * Suspend until this call reaches `CONFIRMED` or ends -- the ABI
     * completing through `SIPRAL_EVENT_KIND_CALL_CONFIRMED` /
     * `SIPRAL_EVENT_KIND_CALL_ENDED` rather than through `sipral_call_place`'s
     * own return, which only hands back the handle before anything has
     * happened on the wire.
     */
    suspend fun waitConfirmed(timeoutMs: Long = 30_000) {
        awaitEvent(
            timeoutMs,
            { ended || state == SipralCallState.CONFIRMED },
            SipralEventKind.CALL_CONFIRMED,
            SipralEventKind.CALL_ENDED,
        )
        if (ended) {
            throw IllegalStateException("call ${handle.toString(16)} ended before it was confirmed")
        }
    }

    /** Suspend until `SIPRAL_EVENT_KIND_CALL_ENDED` has been delivered. */
    suspend fun waitEnded(timeoutMs: Long = 30_000) {
        awaitEvent(timeoutMs, { ended }, SipralEventKind.CALL_ENDED)
    }

    /**
     * Suspend until [settled] holds or one of [kinds] is delivered. The
     * subscription is made before [settled] is read, never after: [events]
     * replays nothing, so an event delivered between reading the state and
     * subscribing would otherwise be missed, and the wait would run out
     * over a call that had long since moved on.
     */
    private suspend fun awaitEvent(timeoutMs: Long, settled: () -> Boolean, vararg kinds: SipralEventKind) {
        val wanted = kinds.map { it.value.toLong() }.toSet()
        withTimeout(timeoutMs) {
            coroutineScope {
                // Undispatched: the collector has subscribed by the time
                // async returns, before [settled] is asked.
                val seen = async(start = CoroutineStart.UNDISPATCHED) { events.first { it.kind in wanted } }
                if (settled()) {
                    seen.cancel()
                } else {
                    seen.await()
                }
            }
        }
    }

    /**
     * Hang up if this call is still up, release its media, forget it with
     * the client. Idempotent, and safe to call from a `finally` or from
     * `use { }` regardless of how the call ended.
     */
    override fun close() {
        // Claimed before anything else, and under the same lock [deliver]
        // mints media under: once this is true, a MEDIA_STARTED that
        // deliver() has not yet started handling mints nothing, and one it
        // is already in the middle of minting is still finished and handed
        // back below rather than raced past -- see [mediaLock]'s own note.
        synchronized(mediaLock) { closing = true }
        if (!ended) {
            try {
                hangup()
            } catch (_: Exception) {
                // best effort on the way out
            }
        }
        val current = synchronized(mediaLock) { media }
        if (current != null) {
            current.close()
        } else {
            client.giveBackMediaSocket(mediaSocket, mediaAddress)
            textSocket?.close()
        }
        client.forgetCall(handle)
    }

    /** Writes to this call's media socket: what `sipral_stack_poll_farewell`
     * hands [SipralClient] once signalling has already ended, and the
     * packets the library's engine encodes in device mode. Through [media]
     * once it exists, which owns the socket then. */
    internal fun sendOnMediaSocket(payload: ByteArray, address: InetSocketAddress) {
        val owner = media
        if (owner != null) {
            owner.sendTo(payload, address)
            return
        }
        try {
            mediaSocket.send(DatagramPacket(payload, payload.size, address))
        } catch (_: Exception) {
            // best effort: a socket already closed has nobody left to tell
        }
    }
}

/**
 * The key `SIPRAL_EVENT_KIND_DIGIT_RECEIVED` carries, off
 * `payload.media.digit`: an RFC 4733 (RTP) digit and either INFO form all
 * read the same way, since the library already tells the two apart and
 * writes the character either way (`payload.media.source` says which
 * reported it). Null for an RFC 4733 event code no keypad has a key for --
 * `payload.media.eventCode` is sixteen or above -- which is the only zero
 * `digit` reads as, since no key this ABI names is the null character.
 */
fun digitOf(event: SipralEvent): Char? {
    val digit = event.payload.media.digit
    return if (digit == 0L) null else digit.toInt().toChar()
}

/**
 * What a call told to listen heard, off `payload.progress` of a
 * `SIPRAL_EVENT_KIND_PROGRESS_DETECTED` -- a network's tone, who answered,
 * or the machine's beep, `what` saying which -- and null for any other
 * kind, whose bytes in that arm are another arm's.
 */
fun progressOf(event: SipralEvent): SipralProgressEvent? =
    if (event.kind == SipralEventKind.PROGRESS_DETECTED.value.toLong()) event.payload.progress else null

/** How [SipralCall.detectProgress] listens: the network's tones, whether
 * to decide who answered and whether to listen for the machine's beep, and
 * every limit of `sipral_progress_config_t`, each zero for the library's
 * default. */
data class SipralProgressOptions(
    val region: SipralToneRegion = SipralToneRegion.EUROPE,
    val answeringMachine: Boolean = true,
    val beep: Boolean = true,
    val beepWindowMs: Long = 0,
    val maxInitialSilenceMs: Long = 0,
    val maxGreetingMs: Long = 0,
    val silenceAfterGreetingMs: Long = 0,
    val maxWords: Long = 0,
    val minWordMs: Long = 0,
    val minWordGapMs: Long = 0,
    val maxDecisionMs: Long = 0,
    val minSpeechAboveFloorDb: Long = 0,
    val beepMinMs: Long = 0,
    val beepMaxMs: Long = 0,
    val toneCycles: Long = 0,
)

/** A `SipralToggle` saying yes or no. */
private fun toggleOf(on: Boolean): Long = (if (on) SipralToggle.ON else SipralToggle.OFF).value.toLong()
