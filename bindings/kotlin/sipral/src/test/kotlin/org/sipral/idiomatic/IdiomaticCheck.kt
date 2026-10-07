// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Two stacks on loopback, one dialling the other directly (no registrar):
// answered, held, resumed, DTMF, real RTP throughout, hung up, then closed
// with events still queued. Run by scripts/check.sh against the shared
// library under -Xcheck:jni, beside BindingCheck.kt.

package org.sipral.idiomatic

import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.system.exitProcess
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.sipral.Sipral
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralStatus

fun main() {
    val said = try {
        runBlocking {
            everything() + "; " + natChecks() + "; " + referralChecks() + "; " + signallingChecks() + "; " +
                audioChecks() + "; " + loggingChecks() + "; " + securityChecks() + "; " + inBandChecks() + "; " +
                tlsSignallingChecks() + "; " + protocolsChecks() + "; " + localConferenceChecks() + "; " +
                datagramLimitChecks() + "; " + mediaMixChecks() + "; " + transferChecks() + "; " +
                reachabilityChecks() + "; " + challengeChecks() + "; " + appRateChecks()
        }
    } catch (failure: Throwable) {
        failure.printStackTrace()
        exitProcess(1)
    }
    println("kotlin idiomatic: $said")
    // exitProcess: a stray non-daemon thread from a linked library would keep
    // the JVM alive (see BindingCheck.kt)
    exitProcess(0)
}

/**
 * `sipral_media_mix` through the idiomatic_media.c shim; the generated
 * binding cannot call it. Handles naming nothing are refused in C, which
 * proves the shim forwards the call.
 */
private fun mediaMixChecks(): String {
    val packet = Sipral.MEDIA_PACKET_BYTES.toInt()
    val address = Sipral.ADDRESS_BYTES.toInt()
    val status = SipralMediaNative.mediaMix(
        Sipral.HANDLE_NONE, Sipral.HANDLE_NONE, 0, ShortArray(160), ShortArray(160),
        ByteArray(packet), ByteArray(address), LongArray(3),
        ByteArray(packet), ByteArray(address), LongArray(3),
    )
    assertEquals(SipralStatus.INVALID_HANDLE.value, status, Sipral.lastErrorMessage())
    return "sipral_media_mix reached through its shim"
}

private suspend fun everything(): String {
    val clientA = SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1")
    val clientB = SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1")
    try {
        val accountA = clientA.addAccount(
            aor = "sip:alice@example.invalid",
            registrarAddress = clientB.bindAddress,
        )
        val accountB = clientB.addAccount(
            aor = "sip:bob@example.invalid",
            registrarAddress = clientA.bindAddress,
        )

        // A call closed the instant it is placed, then MEDIA_STARTED handed to the
        // same internal `deliver` the poll thread uses, as a real race would land
        // it. `deliver` must see the call closing and mint nothing: no exception
        // on the poll thread, no orphaned `sipral_call_media` handle.
        //
        // Placed from clientB at clientA, opposite to the rest of the test, so its
        // INCOMING_CALL lands on clientA and cannot be confused with the one callA
        // below waits for on clientB.events.
        val raced = clientB.placeCall(accountB, target = "sip:alice@example.invalid")
        raced.close()
        raced.deliver(
            SipralEvent(
                size = 0,
                stack = clientB.handle,
                kind = SipralEventKind.MEDIA_STARTED.value.toLong(),
                account = 0,
                call = raced.handle,
                message = null,
            ),
        )
        assertEquals(null, raced.media, "a MEDIA_STARTED delivered after close() must mint nothing")

        // The payload union crosses JNI whole, one class per arm. A hand-built
        // event round-trips a field from each arm an application reads: a DTMF
        // digit, a registration state, a media codec. Each arm's numbers cross in
        // one array in declared order (media: codec first, digit sixth;
        // registration: state first).
        fun armNumbers(vararg set: Pair<Int, Long>) =
            LongArray(64).also { numbers -> set.forEach { (at, value) -> numbers[at] = value } }
        val digitEvent = SipralEvent(
            size = 0,
            stack = clientB.handle,
            kind = SipralEventKind.DIGIT_RECEIVED.value.toLong(),
            account = 0,
            call = 0,
            message = null,
            payloadMediaNumbers = armNumbers(5 to '#'.code.toLong()),
        )
        assertEquals('#', digitOf(digitEvent), "payload.media.digit did not round-trip")

        val registrationEvent = SipralEvent(
            size = 0,
            stack = clientA.handle,
            kind = SipralEventKind.REGISTRATION_CHANGED.value.toLong(),
            account = 0,
            call = 0,
            message = null,
            payloadRegistrationNumbers = armNumbers(0 to org.sipral.SipralRegistrationState.REGISTERED.value.toLong()),
        )
        assertEquals(
            org.sipral.SipralRegistrationState.REGISTERED,
            org.sipral.SipralRegistrationState.of(registrationEvent.payload.registration.state.toInt()),
            "payload.registration.state did not round-trip",
        )

        val mediaEvent = SipralEvent(
            size = 0,
            stack = clientA.handle,
            kind = SipralEventKind.MEDIA_STARTED.value.toLong(),
            account = 0,
            call = 0,
            message = null,
            payloadMediaNumbers = armNumbers(0 to org.sipral.SipralCodec.OPUS.value.toLong()),
        )
        assertEquals(
            org.sipral.SipralCodec.OPUS.value.toLong(),
            mediaEvent.payload.media.codec,
            "payload.media.codec did not round-trip",
        )

        // A SharedFlow never hands an already-emitted value to a late subscriber;
        // the real hazard is act-then-subscribe, which awaitNext fixes.
        run {
            val probe = MutableSharedFlow<SipralEvent>(
                replay = 0,
                extraBufferCapacity = 4096,
                onBufferOverflow = BufferOverflow.DROP_OLDEST,
            )
            fun incomingCallEvent(call: Long) = SipralEvent(
                size = 0,
                stack = 0,
                kind = SipralEventKind.INCOMING_CALL.value.toLong(),
                account = 0,
                call = call,
                message = null,
            )

            // 1) Emitted with no subscriber, then subscribed: never delivered.
            // replay = 0 decides where a new subscriber starts, buffer or not.
            probe.tryEmit(incomingCallEvent(call = 0x5EEDL))
            val stale = withTimeoutOrNull(200) {
                probe.first { it.kind == SipralEventKind.INCOMING_CALL.value.toLong() }
            }
            assertEquals(
                null,
                stale,
                "a SharedFlow(replay = 0) handed a pre-subscription value to a subscriber that started later",
            )

            // 2) The bug: act, then subscribe. The action's own event is lost and
            // first{} matches a later, unrelated one.
            probe.tryEmit(incomingCallEvent(call = 0x900DL)) // "our" event -- emitted before anything subscribes
            val wrong = coroutineScope {
                val matching = async(start = CoroutineStart.UNDISPATCHED) {
                    withTimeoutOrNull(200) { probe.first { it.kind == SipralEventKind.INCOMING_CALL.value.toLong() } }
                }
                probe.tryEmit(incomingCallEvent(call = 0xBADL)) // a probe's own, unrelated, later event
                matching.await()
            }
            assertEquals(
                0xBADL,
                wrong?.call,
                "acting before subscribing should miss our own event and match the probe's instead",
            )

            // 3) awaitNext subscribes first, so it matches our own event.
            val (_, right) = probe.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 200) {
                probe.tryEmit(incomingCallEvent(call = 0x900DL))
            }
            assertEquals(0x900DL, right.call, "awaitNext matched something other than the event its own action caused")
        }

        // Dialled directly at clientB through accountA's registrarAddress, no
        // registrar between them. awaitNext subscribes before placeCall: an INVITE
        // arriving before a later subscription would be missed, and the wait would
        // match the next INCOMING_CALL instead.
        val (callA, incoming) = clientB.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
            clientA.placeCall(accountA, target = "sip:bob@example.invalid")
        }
        val callB = clientB.answerCall(incoming)

        callA.waitConfirmed()
        callB.waitConfirmed()
        assertEquals(org.sipral.SipralCallState.CONFIRMED, callA.state)
        assertEquals(org.sipral.SipralCallState.CONFIRMED, callB.state)

        // Media started on both ends; each frame thread sends silence even
        // without sendAudio, so real RTP crosses loopback throughout.
        withTimeout(15_000) {
            while (callA.media == null || callB.media == null) {
                delay(20)
            }
        }
        val mediaA = assertNotNull(callA.media)
        val mediaB = assertNotNull(callB.media)

        // Give the frame threads several round trips to exchange real RTP.
        val mediaSince = System.nanoTime()
        delay(600)
        val statsA = mediaA.statistics()
        val statsB = mediaB.statistics()
        // frames_underrun crosses JNI in its own slot: never more than the frames
        // played since media started, and never a neighbouring field's value
        val framesSince = (System.nanoTime() - mediaSince) / 20_000_000 + 50
        for (stats in listOf(statsA, statsB)) {
            assertTrue(
                stats.framesUnderrun in 0..framesSince,
                "framesUnderrun ${stats.framesUnderrun} is not a count of frames played",
            )
        }
        assertTrue(statsA.packetsSent > 0, "callA's media never sent a frame")
        assertTrue(statsB.packetsSent > 0, "callB's media never sent a frame")
        assertTrue(statsA.packetsReceived > 0, "callA never heard callB's silence")
        assertTrue(statsB.packetsReceived > 0, "callB never heard callA's silence")

        // Hold and resume, read back with sipral_call_hold_state rather than from
        // a SESSION_CHANGED, to avoid racing a specific event.
        callA.hold()
        withTimeout(15_000) {
            while (!callA.holdState.first) {
                delay(20)
            }
        }
        assertTrue(callA.holdState.first, "callA never reports itself holding callB")
        callA.resume()
        withTimeout(15_000) {
            while (callA.holdState.first) {
                delay(20)
            }
        }
        assertTrue(!callA.holdState.first, "callA never reports itself off hold")

        // DTMF: three digits over RTP (RFC 4733), read back with digitOf.
        val digitsSeen = mutableListOf<Char>()
        coroutineScope {
            // undispatched: subscribed before the first digit is sent
            val collecting = launch(start = CoroutineStart.UNDISPATCHED) {
                callB.digits.collect { event -> digitOf(event)?.let { digitsSeen.add(it) } }
            }
            callA.sendDtmf("12#")
            withTimeout(15_000) {
                while (digitsSeen.size < 3) {
                    delay(20)
                }
            }
            collecting.cancel()
        }
        assertEquals(listOf('1', '2', '#'), digitsSeen, "sent \"12#\", read back $digitsSeen")

        // Hang up from one side; the other has to see CALL_ENDED too.
        callA.hangup()
        callA.waitEnded()
        callB.waitEnded()
        assertTrue(callA.ended)
        assertTrue(callB.ended)

        // The end-of-call record is kept on the call and answered by the media
        // once the library has nothing left.
        withTimeout(15_000) {
            while (callA.finalStatistics == null) {
                delay(20)
            }
        }
        val record = assertNotNull(callA.finalStatistics)
        assertTrue(record.packetsSent >= statsA.packetsSent, "the record counts less than was read before the end")
        val gone = assertFailsWith<SipralException> { Sipral.mediaStatistics(mediaA.handle, clientA.nowMs()) }
        assertEquals(SipralStatus.WRONG_STATE, gone.status)
        assertEquals(record.packetsSent, mediaA.statistics().packetsSent)

        // A released media handle is SIPRAL_STATUS_STALE_HANDLE afterwards: not a
        // crash and not ignored (docs/08-ffi.md, "Handles").
        val mediaHandleA = mediaA.handle
        callA.close()
        val staleMedia = assertFailsWith<SipralException> { Sipral.mediaInfo(mediaHandleA) }
        assertEquals(SipralStatus.STALE_HANDLE, staleMedia.status)
        callB.close()

        // Closing the client with events still buffered must not crash or touch
        // the handle again: the stack handle is stale afterwards too.
        val stackHandle = clientA.handle
        clientA.close()
        val staleStack = assertFailsWith<SipralException> { Sipral.stackPoll(stackHandle, clientA.nowMs()) }
        assertEquals(SipralStatus.STALE_HANDLE, staleStack.status)
        clientB.close()

        return "two SipralClients on loopback, a call placed, answered, confirmed, " +
            "${statsA.packetsSent + statsB.packetsSent} RTP packets exchanged while idle, " +
            "held and resumed, \"12#\" read back off the payload, hung up, both handles stale after close"
    } finally {
        // best effort: the success paths already closed both
        try {
            clientA.close()
        } catch (_: Exception) {
        }
        try {
            clientB.close()
        } catch (_: Exception) {
        }
    }
}
