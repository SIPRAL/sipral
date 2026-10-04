// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
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

import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.logging.Handler
import java.util.logging.Level
import java.util.logging.LogRecord
import java.util.logging.Logger
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

/** Every record a `java.util.logging` logger passed on. */
private class Caught : Handler() {
    val records = CopyOnWriteArrayList<LogRecord>()
    val arrived = CountDownLatch(1)

    override fun publish(record: LogRecord) {
        records += record
        arrived.countDown()
    }

    override fun flush() {}

    override fun close() {}
}

/** The state text once it holds [expected]: a stack the poll thread held
 * when asked answers with the last snapshot a poll kept. */
private fun stateOnceSettled(client: SipralClient, expected: String): String {
    val deadline = System.currentTimeMillis() + 3_000
    var text = client.state()
    while (!text.contains(expected) && System.currentTimeMillis() < deadline) {
        Thread.sleep(50)
        text = client.state()
    }
    return text
}

private fun aLineReachesTheChildLoggerOfItsTarget(): String {
    val logger = Logger.getLogger("sipral-check-${System.nanoTime()}").apply {
        useParentHandlers = false
        level = Level.FINE
    }
    val caught = Caught()
    logger.addHandler(caught)
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
        client.logTo(logger)
        assertEquals(SipralStatus.WRONG_STATE.value, refuse(client))
        assertTrue(caught.arrived.await(10, TimeUnit.SECONDS), "the refusal never reached the logger")
        val record = caught.records.first()
        assertEquals("${logger.name}.api", record.loggerName)
        assertEquals(Level.FINE, record.level)
        assertTrue(record.message.startsWith("refused, WrongState"), record.message)
        val text = stateOnceSettled(client, "log: debug,")
        assertTrue(text.contains("log: debug,"), text)
    }
    return "a line reached the child logger of its target at FINE"
}

private fun theStackIsAsQuietAsTheLogger(): String {
    val logger = Logger.getLogger("sipral-check-${System.nanoTime()}").apply {
        useParentHandlers = false
        level = Level.INFO
    }
    val caught = Caught()
    logger.addHandler(caught)
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
        client.logTo(logger)
        assertEquals(SipralStatus.WRONG_STATE.value, refuse(client))
        assertTrue(caught.records.isEmpty(), "a debug line reached a logger at INFO")
        val text = stateOnceSettled(client, "log: info,")
        assertTrue(text.contains("log: info,"), text)
    }
    assertEquals(SipralLogLevel.TRACE, logLevelFor(Level.ALL))
    assertEquals(SipralLogLevel.OFF, logLevelFor(Level.OFF))
    assertEquals(Level.FINEST, julLevelOf(SipralLogLevel.TRACE))
    return "the stack logs no more than its logger keeps"
}

private fun aRequestNobodyAnswersIsCountedAsSentAgain(): String {
    DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { silent ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
            assertEquals(0L, client.counters().requestsRetransmitted)
            val account = client.addAccount(
                aor = "sip:alice@sipral.invalid",
                registrarAddress = "127.0.0.1:${silent.localPort}",
                registrar = "sip:sipral.invalid",
            )
            account.register()
            val deadline = System.currentTimeMillis() + 5_000
            while (client.counters().requestsRetransmitted == 0L && System.currentTimeMillis() < deadline) {
                Thread.sleep(100)
            }
            val counters = client.counters()
            assertTrue(counters.requestsRetransmitted > 0, "$counters")
            assertTrue(counters.registrationsAttempted > 0, "$counters")
            assertEquals(0L, counters.requestsRefusedAtLimit)
        }
    }
    return "a REGISTER nobody answered was counted as sent again"
}

internal suspend fun loggingChecks(): String = listOf(
    aLineReachesTheChildLoggerOfItsTarget(),
    theStackIsAsQuietAsTheLogger(),
    aRequestNobodyAnswersIsCountedAsSentAgain(),
    aRefusedCallIsLoggedWithNobodyInIt(),
    theStateNamesTheAccountAndNotThePerson(),
    aCallIsCarriedOnEvenPortsFromEachClientsRange(),
    aRangeWithNoPairLeftSaysSo(),
).joinToString("; ")
