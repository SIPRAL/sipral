// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// The log, the state snapshot and the RTP port range through
// org.sipral.idiomatic -- the Kotlin counterpart of
// bindings/python/tests/test_logging.py. A handler that hears a refused call
// with nobody named in it and hears nothing once turned off; a state text for
// a crash report with the account in it and not the person; two clients on
// loopback whose call is carried on even media ports out of each one's
// range; and a range with no pair left that says so. Run by
// IdiomaticCheck.kt's main, under -Xcheck:jni.

package org.sipral.idiomatic

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.sipral.Sipral
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralLogLevel
import org.sipral.SipralNative
import org.sipral.SipralStatus

/** A call the stack refuses: a client with no RTP range has no port to
 * reserve. */
private fun refuse(client: SipralClient): Int =
    SipralNative.sipral_stack_rtp_port_reserve(client.handle, LongArray(1))

private fun aRefusedCallIsLoggedWithNobodyInIt(): String {
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
        assertTrue(Sipral.capabilities().features and Sipral.FEATURE_LOGGING != 0L, "the logging bit")
        val heard = CopyOnWriteArrayList<List<Any>>()
        val arrived = CountDownLatch(1)
        client.setLog(SipralLogLevel.DEBUG) { level, target, message, suppressed ->
            heard += listOf(level, target, message, suppressed)
            arrived.countDown()
        }
        assertEquals(SipralStatus.WRONG_STATE.value, refuse(client))
        assertTrue(arrived.await(10, TimeUnit.SECONDS), "the refusal was never logged")
        val (level, target, message, suppressed) = heard.first()
        assertEquals(SipralLogLevel.DEBUG, level)
        assertEquals("api", target)
        assertTrue((message as String).startsWith("refused, WrongState"), message)
        assertEquals(0L, suppressed)
        assertFalse(message.contains("127.0.0.1"), message)

        client.setLog(SipralLogLevel.OFF, null)
        val count = heard.size
        assertEquals(SipralStatus.WRONG_STATE.value, refuse(client))
        assertEquals(count, heard.size, "a log turned off says nothing")
    }
    return "a refused call is logged, redacted, and not once the log is off"
}

private fun theStateNamesTheAccountAndNotThePerson(): String {
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
        client.addAccount(aor = "sip:alice@example.invalid", registrarAddress = "127.0.0.1:5999")
        val text = client.state()
        for (expected in listOf("accounts: 1", "transports: 1", "counters: ")) {
            assertTrue(text.contains(expected), "$expected missing from:\n$text")
        }
        assertFalse(text.contains("alice"), text)
        assertFalse(text.contains("127.0.0.1"), text)
    }
    return "the state names the account and not the person"
}

private suspend fun aCallIsCarriedOnEvenPortsFromEachClientsRange(): String {
    val alice = SipralClient.open(
        audio = SipralAudioMode.Application, bindHost = "127.0.0.1", rtpPortMin = 46900, rtpPortMax = 46919,
    )
    val bob = SipralClient.open(
        audio = SipralAudioMode.Application, bindHost = "127.0.0.1", rtpPortMin = 47000, rtpPortMax = 47019,
    )
    try {
        val account = alice.addAccount(aor = "sip:alice@example.invalid", registrarAddress = bob.bindAddress)
        bob.addAccount(aor = "sip:bob@example.invalid", registrarAddress = alice.bindAddress)
        val (aliceCall, incoming) = bob.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
            alice.placeCall(account, target = "sip:bob@example.invalid")
        }
        val bobCall = bob.answerCall(incoming)
        withTimeout(15_000) {
            while (aliceCall.media == null || bobCall.media == null) {
                delay(20)
            }
        }
        for ((call, low, high) in listOf(Triple(aliceCall, 46900, 46919), Triple(bobCall, 47000, 47019))) {
            val port = parseHostPort(call.mediaAddress).port
            assertTrue(port in low until high && port % 2 == 0, "media on $port, outside $low..$high")
        }
        aliceCall.close()
        bobCall.close()
    } finally {
        alice.close()
        bob.close()
    }
    return "a call is carried on even ports from each client's range"
}

private fun aRangeWithNoPairLeftSaysSo(): String {
    SipralClient.open(
        audio = SipralAudioMode.Application, bindHost = "127.0.0.1", rtpPortMin = 47100, rtpPortMax = 47101,
    ).use { client ->
        client.openMediaSocket("127.0.0.1").use { first ->
            assertEquals(47100, first.localPort)
            val refused = assertFailsWith<SipralException> { client.openMediaSocket("127.0.0.1") }
            assertEquals(SipralStatus.EXHAUSTED, refused.status)
        }
    }
    return "a range with no pair left says so"
}

internal suspend fun loggingChecks(): String = listOf(
    aRefusedCallIsLoggedWithNobodyInIt(),
    theStateNamesTheAccountAndNotThePerson(),
    aCallIsCarriedOnEvenPortsFromEachClientsRange(),
    aRangeWithNoPairLeftSaysSo(),
).joinToString("; ")
