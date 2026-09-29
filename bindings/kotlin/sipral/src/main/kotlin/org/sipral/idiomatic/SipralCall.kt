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
import kotlinx.coroutines.withTimeout
import org.sipral.Sipral
import org.sipral.SipralCallEvent
import org.sipral.SipralCallState
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralHeader
import org.sipral.SipralStatus

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
) : AutoCloseable {
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
        SipralMedia(client, handle, mediaSocket, pumpsFrames = client.audioMode is SipralAudioMode.Application)
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
     * the default and the one every gateway on the path carries end to end. */
    fun sendDtmf(digits: String, via: Long = 1, durationMs: Long = 100) {
        retryBusy { Sipral.callSendDtmf(client.handle, handle, digits, via, durationMs, client.nowMs()) }
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
