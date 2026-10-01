// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// What an integrator does on the first afternoon with org.sipral.idiomatic:
// two stacks on loopback, one dialling the other directly (no registrar
// between them, `bindings/python/sipral/stack.py`'s own pattern), answered,
// held, resumed, sent DTMF, exchanging real RTP over real sockets the whole
// time because the media thread always has a frame to send, hung up, and
// checked for what closing while events are still queued does to a handle
// already released. Compiled and run by scripts/check.sh against the
// shared library, on a JVM under -Xcheck:jni, beside BindingCheck.kt.

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
                reachabilityChecks()
        }
    } catch (failure: Throwable) {
        failure.printStackTrace()
        exitProcess(1)
    }
    println("kotlin idiomatic: $said")
    // exitProcess rather than returning: the poll threads this test opened
    // are daemons, but a stray non-daemon one from a library it linked would
    // otherwise keep the JVM from exiting the way BindingCheck.kt already
    // notes for its own native thread.
    exitProcess(0)
}

/**
 * `sipral_media_mix` through the shim idiomatic_media.c gives it: the
 * generated binding hands its two packets over as bare addresses and had no
 * way to call it at all. Handles that name nothing reach C and are refused
 * there, which is what says the shim is there and hands the call through.
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

        // A call closed the instant it is placed, before anything has
        // negotiated -- close() has already taken the "no media yet, close
        // the raw socket" path by the time this returns. Then the exact
        // event the poll thread would still be free to deliver in a real
        // race, SIPRAL_EVENT_KIND_MEDIA_STARTED, is handed to the same
        // internal `deliver` the poll thread calls, landing after close()
        // the way a real race can land it: MEDIA_STARTED already read off
        // the wire on one thread while close() runs on another. Before this
        // was fixed, deliver() minted a SipralMedia over the already-closed
        // socket unconditionally, whose own init block
        // (`socket.soTimeout = 5`) threw a SocketException straight out of
        // deliver() -- uncaught, on what is the poll thread in real use --
        // and, whenever the mint itself won that race instead of the raw
        // socket check, left a `sipral_call_media` handle minted and
        // reachable from nowhere, since the SipralCall this raced was
        // already forgotten by its client. Now `deliver` sees the call is
        // closing and mints nothing, silently and safely.
        //
        // Placed from clientB at clientA -- the opposite direction from the
        // rest of this test -- so the real INVITE this sends and the real
        // INCOMING_CALL it raises land on clientA, not on clientB.events,
        // which callA below reads with an untargeted `awaitNext {
        // INCOMING_CALL }`. clientB.events aggregates every call clientB
        // ever handles, this raced one included, so placing it the same
        // direction as callA would put a second, unrelated INCOMING_CALL
        // producer on the exact flow that read is watching -- a real
        // ambiguity awaitNext's subscribe-before-act ordering does not
        // remove, since both events would then be genuinely emitted after
        // the subscription starts (see awaitNext's own KDoc: this has
        // nothing to do with a SharedFlow replaying a stale value, which it
        // never does, proven a few lines below). Routing this one away is
        // what actually rules the ambiguity out.
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

        // The payload union crosses whole now, flattened over JNI into
        // SipralEvent.payload -- one class per arm -- independent of
        // anything a real call does, so a hand-built event round-trips a
        // field of each of the three arms an application actually reads:
        // a DTMF digit, a registration state and a media codec. Each arm's
        // numbers cross in one array, in the arm's declared order: the media
        // arm's codec is its first number and its digit its sixth, the
        // registration arm's state its first.
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

        // A SharedFlow does not hand a stale, already-emitted value to a
        // subscriber that starts late -- proven directly, and the real
        // ordering bug an untargeted `events.first { it.kind == X }` still
        // has, demonstrated and then fixed with awaitNext: see the block
        // above the real network traffic starts, and awaitNext's own KDoc.
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

            // 1) Emitted with zero subscribers, then someone subscribes:
            // never delivered. Refutes "an event emitted before any
            // collector subscribed can still be handed to the first later
            // subscriber" outright -- replay = 0 governs where a fresh
            // subscriber's own read position starts, extraBufferCapacity
            // or not, and 4096 slots of it are sitting unused here.
            probe.tryEmit(incomingCallEvent(call = 0x5EEDL))
            val stale = withTimeoutOrNull(200) {
                probe.first { it.kind == SipralEventKind.INCOMING_CALL.value.toLong() }
            }
            assertEquals(
                null,
                stale,
                "a SharedFlow(replay = 0) handed a pre-subscription value to a subscriber that started later",
            )

            // 2) The real bug: act, *then* subscribe -- the order
            // `events.first { it.kind == X }` reaches for by hand. The
            // action's own event, emitted to nobody, is gone for good, and
            // first{} goes on to match the next event of that kind instead
            // -- a later, unrelated one, a probe call's among them.
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

            // 3) awaitNext subscribes first: our own event, emitted from
            // inside [action] once the subscription is live, is always
            // what it matches, never a later probe's.
            val (_, right) = probe.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 200) {
                probe.tryEmit(incomingCallEvent(call = 0x900DL))
            }
            assertEquals(0x900DL, right.call, "awaitNext matched something other than the event its own action caused")
        }

        // Placed directly at clientB, through accountA's own registrarAddress
        // acting as the outbound destination -- no registrar between them,
        // the same shape bindings/python's loopback tests use.
        //
        // awaitNext subscribes to clientB.events before placeCall ever
        // runs, not after: an INVITE that reached clientB in the gap
        // between placeCall returning and a subscription starting -- on a
        // loaded machine, it does -- would otherwise be missed outright,
        // and events.first { it.kind == X } would then wait for, and
        // wrongly match, whatever this client's *next* INCOMING_CALL turns
        // out to be, not a value the flow "still had" from before (a
        // SharedFlow with replay = 0 never keeps one for a subscriber that
        // starts late, proven above).
        val (callA, incoming) = clientB.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
            clientA.placeCall(accountA, target = "sip:bob@example.invalid")
        }
        val callB = clientB.answerCall(incoming)

        callA.waitConfirmed()
        callB.waitConfirmed()
        assertEquals(org.sipral.SipralCallState.CONFIRMED, callA.state)
        assertEquals(org.sipral.SipralCallState.CONFIRMED, callB.state)

        // Media started on both ends: SipralMedia was minted, and the frame
        // thread on each side captures silence and sends it even though
        // nothing ever called sendAudio, so real RTP crosses the loopback
        // socket the whole time this test runs.
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
        // frames_underrun crosses JNI in its own slot: a count of frames the
        // earpiece played as nothing, so never more than the frames a frame
        // thread can have played since the media started, and never a
        // neighbour's microseconds or rates read in its place
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

        // Hold and resume, read back through sipral_call_hold_state: a
        // direct query rather than the SESSION_CHANGED event's own
        // payload.call.heldHere/heldThere, since this only wants the state
        // and does not want to race a specific event arriving.
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

        // DTMF: three digits, RTP (RFC 4733) by default, read back by
        // character now that the payload union crosses -- digitOf reads
        // each one off payload.media.digit, an RFC 4733 digit the same way
        // as either INFO form.
        val digitsSeen = mutableListOf<Char>()
        coroutineScope {
            // Undispatched, so the collector is subscribed before the first
            // digit is sent rather than whenever the event loop reaches it.
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

        // The media handle is released on close, and using it afterward is
        // SIPRAL_STATUS_STALE_HANDLE -- not a crash, and not silently
        // ignored, which is the whole point of a handle in the first place
        // (docs/08-ffi.md, "Handles").
        val mediaHandleA = mediaA.handle
        callA.close()
        val staleMedia = assertFailsWith<SipralException> { Sipral.mediaInfo(mediaHandleA) }
        assertEquals(SipralStatus.STALE_HANDLE, staleMedia.status)
        callB.close()

        // Closing the client while its event flows may still hold buffered
        // events (both calls' `events`/`digits`, each a SharedFlow with
        // extraBufferCapacity = 4096 and DROP_OLDEST, never drained to
        // empty above) must not crash and must not touch the handle again:
        // the stack handle is stale afterward the same way the media
        // handle already was.
        val stackHandle = clientA.handle
        clientA.close()
        val staleStack = assertFailsWith<SipralException> { Sipral.stackPoll(stackHandle, clientA.nowMs()) }
        assertEquals(SipralStatus.STALE_HANDLE, staleStack.status)
        clientB.close()

        return "two SipralClients on loopback, a call placed, answered, confirmed, " +
            "${statsA.packetsSent + statsB.packetsSent} RTP packets exchanged while idle, " +
            "held and resumed, \"12#\" read back off the payload, hung up, both handles stale after close"
    } finally {
        // Best-effort: every path above that succeeds already closes both,
        // and a path that threw leaves nothing running past this test's own
        // process exit either way.
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
