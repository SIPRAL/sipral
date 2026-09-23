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

import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.system.exitProcess
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.sipral.Sipral
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralStatus

fun main() {
    val said = try {
        runBlocking { everything() }
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

private suspend fun everything(): String {
    val clientA = SipralClient.open(bindHost = "127.0.0.1")
    val clientB = SipralClient.open(bindHost = "127.0.0.1")
    try {
        val accountA = clientA.addAccount(
            aor = "sip:alice@example.invalid",
            registrarAddress = clientB.bindAddress,
        )
        val accountB = clientB.addAccount(
            aor = "sip:bob@example.invalid",
            registrarAddress = clientA.bindAddress,
        )

        // Placed directly at clientB, through accountA's own registrarAddress
        // acting as the outbound destination -- no registrar between them,
        // the same shape bindings/python's loopback tests use.
        val callA = clientA.placeCall(accountA, target = "sip:bob@example.invalid")

        val incoming = withTimeout(15_000) {
            clientB.events.first { it.kind == SipralEventKind.INCOMING_CALL.value.toLong() }
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
        delay(600)
        val statsA = mediaA.statistics()
        val statsB = mediaB.statistics()
        assertTrue(statsA.packetsSent > 0, "callA's media never sent a frame")
        assertTrue(statsB.packetsSent > 0, "callB's media never sent a frame")
        assertTrue(statsA.packetsReceived > 0, "callA never heard callB's silence")
        assertTrue(statsB.packetsReceived > 0, "callB never heard callA's silence")

        // Hold and resume, read back through sipral_call_hold_state rather
        // than guessed from an event whose payload this generation of the
        // binding does not carry.
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

        // DTMF: three digits, RTP (RFC 4733) by default. The generated
        // Kotlin/JNI shim forwards no event payload
        // (bindings/kotlin/README.md), so the digit itself cannot be read
        // back for this source -- see SipralCall.digits and digitOf's own
        // documentation -- but the three DIGIT_RECEIVED events themselves
        // are observable, which is what this checks.
        val digitsSeen = mutableListOf<org.sipral.SipralEvent>()
        coroutineScope {
            val collecting = launch { callB.digits.collect { digitsSeen.add(it) } }
            callA.sendDtmf("12#")
            withTimeout(15_000) {
                while (digitsSeen.size < 3) {
                    delay(20)
                }
            }
            collecting.cancel()
        }
        assertEquals(3, digitsSeen.size, "sent 3 DTMF digits, saw ${digitsSeen.size} DIGIT_RECEIVED events")

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

        // Closing the client while its event channels may still hold
        // buffered events (both calls' `events`/`digits` Flows are
        // unbounded Kotlin channels, never drained to empty above) must not
        // crash and must not touch the handle again: the stack handle is
        // stale afterward the same way the media handle already was.
        val stackHandle = clientA.handle
        clientA.close()
        val staleStack = assertFailsWith<SipralException> { Sipral.stackPoll(stackHandle, clientA.nowMs()) }
        assertEquals(SipralStatus.STALE_HANDLE, staleStack.status)
        clientB.close()

        return "two SipralClients on loopback, a call placed, answered, confirmed, " +
            "${statsA.packetsSent + statsB.packetsSent} RTP packets exchanged while idle, " +
            "held and resumed, 3 DTMF events observed, hung up, both handles stale after close"
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
