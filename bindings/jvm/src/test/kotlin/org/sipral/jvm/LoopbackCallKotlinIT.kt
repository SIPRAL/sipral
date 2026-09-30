// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// Two stacks on loopback in one JVM, driven through org.sipral.idiomatic as
// a Kotlin server would: one calls the other directly, the other answers,
// RTP crosses both ways, digits go over, and one side hangs up. Run by
// failsafe against the packaged jar, so the natives come out of the jar.

package org.sipral.jvm

import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.sipral.SipralCallState
import org.sipral.SipralEventKind
import org.sipral.idiomatic.SipralAudioMode
import org.sipral.idiomatic.SipralClient
import org.sipral.idiomatic.awaitNext
import org.sipral.idiomatic.digitOf

class LoopbackCallKotlinIT {
    @Test
    fun aCallBetweenTwoStacksOnLoopback() = runBlocking {
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { alice ->
            SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { bob ->
                assertEquals(SipralNatives.currentPlatform(), SipralNatives.loaded())
                assertTrue(
                    SipralNatives::class.java.protectionDomain.codeSource.location.path.endsWith(".jar"),
                    "the binding was not loaded from the packaged jar",
                )

                val fromAlice = alice.addAccount(aor = "sip:alice@example.invalid", registrarAddress = bob.bindAddress)
                bob.addAccount(aor = "sip:bob@example.invalid", registrarAddress = alice.bindAddress)

                val (outgoing, incoming) = bob.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
                    alice.placeCall(fromAlice, target = "sip:bob@example.invalid")
                }
                val answered = bob.answerCall(incoming)
                outgoing.use { callA ->
                    answered.use { callB ->
                        callA.waitConfirmed(15_000)
                        callB.waitConfirmed(15_000)
                        assertSame(SipralCallState.CONFIRMED, callA.state)
                        assertSame(SipralCallState.CONFIRMED, callB.state)

                        withTimeout(15_000) {
                            while (callA.media == null || callB.media == null) {
                                delay(20)
                            }
                        }
                        val mediaA = checkNotNull(callA.media)
                        val mediaB = checkNotNull(callB.media)
                        withTimeout(15_000) {
                            while (mediaA.statistics().packetsReceived == 0L || mediaB.statistics().packetsReceived == 0L) {
                                delay(20)
                            }
                        }
                        assertTrue(mediaA.statistics().packetsSent > 0, "alice sent no RTP")
                        assertTrue(mediaB.statistics().packetsSent > 0, "bob sent no RTP")

                        val digits = mutableListOf<Char>()
                        coroutineScope {
                            val collecting = launch(start = CoroutineStart.UNDISPATCHED) {
                                callB.digits.collect { event -> digitOf(event)?.let { synchronized(digits) { digits.add(it) } } }
                            }
                            callA.sendDtmf("42#")
                            withTimeout(15_000) {
                                while (synchronized(digits) { digits.size } < 3) {
                                    delay(20)
                                }
                            }
                            collecting.cancel()
                        }
                        assertEquals(listOf('4', '2', '#'), digits)

                        callA.hangup()
                        callA.waitEnded(15_000)
                        callB.waitEnded(15_000)
                        assertTrue(callA.ended && callB.ended)
                    }
                }
            }
        }
    }
}
