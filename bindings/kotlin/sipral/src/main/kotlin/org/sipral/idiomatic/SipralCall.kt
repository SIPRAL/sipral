// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
import org.sipral.SipralStreamStats
import org.sipral.SipralToggle
import org.sipral.SipralToneRegion

/**
 * A `sipral_handle_t` naming one call, and the actions it takes.
 *
 * Built by [SipralClient.placeCall] or [SipralClient.answerCall], and
 * registered with its client before the caller sees it, so [deliver] always
 * has a target for an event naming this call.
 */
class SipralCall internal constructor(
    val client: SipralClient,
    val handle: Long,
    /** The socket the call was placed or answered on; [SipralMedia] owns it
     * once [media] exists. [moveMedia] replaces it. */
    private val mediaSocket: DatagramSocket,
    mediaAddress: String,
    /** The `SIPRAL_EVENT_KIND_INCOMING_CALL` payload this call was answered
     * from, for [identity] and [answering]; null for a call this end placed. */
    private val incoming: SipralCallEvent? = null,
    /** The real-time text socket, when placed or answered with `text = true`;
     * [SipralMedia] owns it once [media] exists. */
    private val textSocket: DatagramSocket? = null,
) : AutoCloseable {
    /** The call's real-time text socket, as `host:port`, when it has one. */
    val textAddress: String? = textSocket?.let { formatAddress(it.localAddress.hostAddress, it.localPort) }

    /** The recording session copying this call to a recording server,
     * while one does. */
    @Volatile
    var recordingSession: SipralRecordingSession? = null
        private set

    /** The media socket as `host:port`, the name `sipral_stack_nat_map` gave
     * it (and its TURN connection); after [moveMedia], the new one. */
    @Volatile
    internal var mediaAddress: String = mediaAddress
        private set
    /** This call's audio once `SIPRAL_EVENT_KIND_MEDIA_STARTED` minted it;
     * null before, and after the call ended and [close] ran. */
    @Volatile
    var media: SipralMedia? = null
        private set

    /** Set once `SIPRAL_EVENT_KIND_CALL_ENDED` has been delivered. */
    @Volatile
    var ended: Boolean = false
        private set

    /**
     * The final media statistics from `SIPRAL_EVENT_KIND_MEDIA_STATISTICS`,
     * which arrives right after `SIPRAL_EVENT_KIND_CALL_ENDED`. Null before
     * that, or when media never started.
     */
    @Volatile
    var finalStatistics: SipralStreamStats? = null
        private set

    // Guards the check-then-act on [media] in [close] and [deliver], and the
    // [closing] flag. Without it, close() can see `media == null` while
    // deliver() is minting for MEDIA_STARTED, close the socket under it, and
    // leak a `sipral_call_media` handle nothing releases (docs/08-ffi.md,
    // "Handles").
    private val mediaLock = Any()
    private var closing = false

    // A SharedFlow, not a Channel: a Channel's collectors race for elements,
    // and an application often runs two readers on one call (digits, and a
    // wait for the end), each of which must see every event.
    private val eventsFlow = MutableSharedFlow<SipralEvent>(
        replay = 0,
        extraBufferCapacity = 4096,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )

    /**
     * Every event this call's handle names, decoded whole, in order.
     *
     * Same bound as [SipralClient.events]: a collector more than 4096 events
     * behind silently loses the oldest. Keep per-event work short.
     */
    val events: SharedFlow<SipralEvent> = eventsFlow

    /**
     * Every `SIPRAL_EVENT_KIND_DIGIT_RECEIVED` this call heard; [digitOf]
     * reads the character, RFC 4733 and INFO alike.
     */
    val digits: Flow<SipralEvent> = events.filter { it.kind == SipralEventKind.DIGIT_RECEIVED.value.toLong() }

    /**
     * The real-time text the far end types (RFC 4103), as [textOf] of each
     * `SIPRAL_EVENT_KIND_TEXT_RECEIVED`, for a call with an agreed text
     * stream. Same rules as [events].
     */
    val text: Flow<SipralTextEvent> = events.mapNotNull { textOf(it) }

    /** `sipral_call_state`, read fresh rather than cached from the last
     * event. */
    val state: SipralCallState
        get() = SipralCallState.of(retryBusy { Sipral.callState(client.handle, handle) }.toInt())
            ?: SipralCallState.UNKNOWN

    /** `sipral_call_hold_state`: (this end holding the far end, the far end
     * holding this one). */
    val holdState: Pair<Boolean, Boolean>
        get() = retryBusy { Sipral.callHoldState(client.handle, handle) }
            .let { (here, there) -> (here != 0L) to (there != 0L) }

    /** Called by [SipralClient] on its poll thread. */
    internal fun deliver(event: SipralEvent) {
        if (event.kind == SipralEventKind.MEDIA_STARTED.value.toLong()) {
            synchronized(mediaLock) {
                if (media == null && !closing) {
                    // Behind a NAT the poll thread read this socket for the stack until now;
                    // from the media handle on, SipralMedia does.
                    client.mediaSocketTaken(mediaAddress)
                    media = mintMedia()
                }
            }
        }
        if (event.kind == SipralEventKind.CALL_ENDED.value.toLong()) {
            ended = true
        }
        val record = if (event.kind == SipralEventKind.MEDIA_STATISTICS.value.toLong()) event.payload.media.statistics else null
        if (record != null) {
            finalStatistics = record
            media?.endedWith(record)
        }
        eventsFlow.tryEmit(event)
    }

    /**
     * Mint through `sipral_call_media`, with [retryBusy]. Minting usually runs
     * inside the poll thread's event callback, where no contention arises on
     * its own, but another thread's call ([hangup] from [close]) can still
     * hold the stack's lock. `WRONG_STATE` or `STALE_HANDLE` means the call
     * already ended, which [closing] covers, so the answer is null rather than
     * a throw out of the poll loop.
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

    // Actions

    /** `sipral_call_answer_media`: accept, with this stack running the audio
     * on the call's media socket. */
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

    // Conferences

    /**
     * `sipral_call_set_focus`: say whether this end is the conference focus
     * (RFC 4579 §4.2), as `isfocus` on the `Contact` of every message from now
     * on: the answer if not yet answered, else the next re-INVITE or UPDATE.
     */
    fun setFocus(focus: Boolean) {
        retryBusy { Sipral.callSetFocus(client.handle, handle, if (focus) 1L else 0L) }
    }

    /** `sipral_call_conference_uri`: the conference this call belongs to when
     * the far end said it is a focus (`isfocus`), else null. */
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

    // A recording server

    /**
     * `sipral_call_record_to`: record this call to [server] (SIPREC, RFC
     * 7866). The recording session (INVITE with `Require: siprec`, RFC 7865
     * metadata, one send-only stream per party) goes from the call's account,
     * to [destination] (`host:port`) over a TCP connection opened for it.
     * With no [destination] it goes where the account sends, which RFC 3261
     * forbids over UDP at this size, so the client must signal over TCP or
     * TLS. Two sockets are bound at [host] for the audio copies.
     * `WRONG_STATE` before `SIPRAL_EVENT_KIND_MEDIA_STARTED`, or when already
     * recorded.
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
     * `sipral_call_hangup_for`: hang up with a `Reason` (RFC 3326) on the BYE,
     * or on the CANCEL of a ringing call. An unanswered incoming call is
     * refused with only the Q.850 value (RFC 6432), since a SIP one would
     * repeat the status.
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
     * `sipral_call_redirect`: answer a ringing incoming call with a 3xx (RFC
     * 3261 §21.3) naming where to try instead, in order; 302 is call
     * forwarding. [reason] adds a `Diversion` (RFC 5806) naming the called
     * address.
     */
    fun redirect(targets: List<String>, status: Int = 302, reason: String? = null) {
        client.redirect(handle, targets, status, reason)
    }

    /** Who is calling, beyond the `From`: what the network asserted past the
     * account's trust gate, the caller's `Privacy`, and diversions. Empty for
     * a call this end placed. */
    fun identity(): SipralCallerIdentity = IdentityReader.identity(client, handle, incoming)

    /** How a call that came in asked to be answered (RFC 5373) and rung
     * (`Alert-Info`). */
    fun answering(): SipralAnswering = IdentityReader.answering(client, handle, incoming)

    /**
     * Offer this call at a socket on the current network, as
     * `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED` asks after
     * [SipralClient.networkChanged].
     *
     * A socket is bound at [host] (default: the new network's address),
     * mapped via STUN if configured, and offered with
     * `sipral_call_media_readdress`: a re-INVITE moving only `c=` and the port
     * (RFC 3264 §8.3.1), with the account's new `Contact`. The new socket
     * carries the call whatever the far end answers; the answer arrives as
     * `SIPRAL_EVENT_KIND_SESSION_CHANGED`, a refusal as
     * `SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED`. Under ICE this throws
     * `WRONG_STATE`; use [restartIce].
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
     * `sipral_call_transfer`: blind transfer to [target] (RFC 3515). This end
     * stays in the call until the far end reports the new call up;
     * `SIPRAL_EVENT_KIND_TRANSFER_PROGRESS` then `TRANSFER_DONE` arrive on
     * [events], read with [transferOf].
     */
    fun transfer(target: String) {
        retryBusy { Sipral.callTransfer(client.handle, handle, target, client.nowMs()) }
    }

    /**
     * `sipral_call_restart_ice`: re-offer with new ICE credentials (RFC 8445
     * §9) and recheck every pair, while the current path keeps carrying audio.
     * The new path arrives as another `SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN`.
     */
    fun restartIce() {
        retryBusy { Sipral.callRestartIce(client.handle, handle, client.nowMs()) }
    }

    /** `sipral_call_set_headers`. */
    fun setHeaders(headers: List<SipralHeader>) {
        retryBusy { Sipral.callSetHeaders(client.handle, handle, headers) }
    }

    /** `sipral_call_send_dtmf`. `via` is a `SipralDtmf` value. RTP (1), the
     * default, survives every gateway and falls back to in-band tones on a
     * call without telephone-event; `IN_BAND` (4) always sends tones. */
    fun sendDtmf(digits: String, via: Long = 1, durationMs: Long = 100) {
        retryBusy { Sipral.callSendDtmf(client.handle, handle, digits, via, durationMs, client.nowMs()) }
    }

    /** `sipral_call_dtmf_detection`: when this call listens for digits in the
     * far end's audio. Each one is a `SIPRAL_EVENT_KIND_IN_BAND_DIGIT`, read
     * with [digitOf]. */
    fun setDtmfDetection(mode: SipralDtmfDetection) {
        retryBusy { Sipral.callDtmfDetection(client.handle, handle, mode.value.toLong()) }
    }

    /**
     * `sipral_call_detect_progress`: listen for network tones, answering
     * party and the machine's beep, as [options] say. Call it right after
     * [SipralClient.placeCall]; results arrive as
     * `SIPRAL_EVENT_KIND_PROGRESS_DETECTED`, read with [progressOf].
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
     * Suspend until this call is `CONFIRMED` or ends. `sipral_call_place`
     * returns only a handle; the outcome comes through
     * `SIPRAL_EVENT_KIND_CALL_CONFIRMED` or `CALL_ENDED`.
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
     * Suspend until [settled] holds or one of [kinds] is delivered. Subscribes
     * before reading [settled]: [events] replays nothing, so an event between
     * the read and the subscription would be missed.
     */
    private suspend fun awaitEvent(timeoutMs: Long, settled: () -> Boolean, vararg kinds: SipralEventKind) {
        val wanted = kinds.map { it.value.toLong() }.toSet()
        withTimeout(timeoutMs) {
            coroutineScope {
                // undispatched: subscribed before async returns
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
     * Hang up if still up, release the media, forget the call. Idempotent,
     * safe from `finally` or `use { }`.
     */
    override fun close() {
        // Claimed first, under the lock [deliver] mints under: a MEDIA_STARTED
        // not yet handled mints nothing, and one mid-mint is finished and
        // released below.
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

    /** Write to this call's media socket: farewells from
     * `sipral_stack_poll_farewell` after signalling ended, and device-mode
     * packets. Through [media] once it exists, as it owns the socket. */
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
 * The key a `SIPRAL_EVENT_KIND_DIGIT_RECEIVED` carries
 * (`payload.media.digit`), the same for RFC 4733 and INFO;
 * `payload.media.source` says which. Null for an RFC 4733 event code of 16
 * or above, which has no key.
 */
fun digitOf(event: SipralEvent): Char? {
    val digit = event.payload.media.digit
    return if (digit == 0L) null else digit.toInt().toChar()
}

/**
 * What a `SIPRAL_EVENT_KIND_PROGRESS_DETECTED` heard (`payload.progress`):
 * a tone, who answered, or the beep, per `what`. Null for any other kind.
 */
fun progressOf(event: SipralEvent): SipralProgressEvent? =
    if (event.kind == SipralEventKind.PROGRESS_DETECTED.value.toLong()) event.payload.progress else null

/** How [SipralCall.detectProgress] listens, with every limit of
 * `sipral_progress_config_t`; zero means the library's default. */
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
