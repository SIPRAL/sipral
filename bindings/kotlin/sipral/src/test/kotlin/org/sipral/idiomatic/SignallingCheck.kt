// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// ABI 0.29's signalling surface through org.sipral.idiomatic, between two
// clients on 127.0.0.1: why a call ended (RFC 3326) both ways, who is
// calling behind the trust gate (RFC 3325, 3323, 5806, 7044), how the call
// asked to be answered (RFC 5373, Alert-Info), a 3xx answer, the account's
// session timer, the SRTP suite a call is keyed with, and a call moved to a
// new socket after the network changed. Run by IdiomaticCheck.kt's main,
// under -Xcheck:jni.

package org.sipral.idiomatic

import kotlinx.coroutines.delay
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.sipral.SipralAnswerMode
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralHeader
import org.sipral.SipralLink
import org.sipral.SipralRecovery
import org.sipral.SipralRingSource
import org.sipral.SipralSrtp
import org.sipral.SipralSrtpSuite
import org.sipral.SipralStatus
import org.sipral.SipralVerstat

private class TwoClients(val alice: SipralClient, val bob: SipralClient, val aliceAccount: SipralAccount) : AutoCloseable {
    override fun close() {
        alice.close()
        bob.close()
    }
}

private fun pair(
    alicePrivacy: Set<SipralPrivacy> = emptySet(),
    aliceTrusts: List<String> = emptyList(),
    bobTrusts: List<String> = emptyList(),
    srtp: SipralSrtp? = null,
): TwoClients {
    val alice = SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", srtp = srtp)
    val bob = SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", srtp = srtp)
    val aliceAccount = alice.addAccount(
        aor = "sip:alice@sipral.invalid",
        registrarAddress = bob.bindAddress,
        privacy = alicePrivacy,
        trustedPeers = aliceTrusts,
    )
    bob.addAccount(aor = "sip:bob@sipral.invalid", registrarAddress = alice.bindAddress, trustedPeers = bobTrusts)
    return TwoClients(alice, bob, aliceAccount)
}

/** Alice's call to Bob, and the incoming event Bob read for it. */
private suspend fun ring(pair: TwoClients, headers: List<SipralHeader> = emptyList()): kotlin.Pair<SipralCall, SipralEvent> =
    pair.bob.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 10_000) {
        pair.alice.placeCall(pair.aliceAccount, "sip:bob@${pair.bob.bindAddress}", headers = headers)
    }

private suspend fun until(withinMs: Long, done: () -> Boolean): Boolean {
    val deadline = System.currentTimeMillis() + withinMs
    while (!done()) {
        if (System.currentTimeMillis() > deadline) return false
        delay(10)
    }
    return true
}

private suspend fun aHangupWithAReasonReachesTheFarEnd(): String {
    pair().use { pair ->
        val (placed, incoming) = ring(pair)
        placed.use {
            pair.bob.answerCall(incoming).use { taken ->
                placed.waitConfirmed(10_000)
                val (_, ended) = taken.events.awaitNext(SipralEventKind.CALL_ENDED, timeoutMs = 10_000) {
                    placed.hangup(SipralHangupReason.USER_BUSY)
                }
                assertEquals(SipralEndCause(sip = null, q850 = 17, text = null), endCauseOf(ended))
            }
        }
    }
    return "a BYE's Reason reached the far end's CALL_ENDED"
}

private suspend fun aCancelAsCompletedElsewhereIsNoMissedCall(): String {
    pair().use { pair ->
        val (placed, incoming) = ring(pair)
        placed.use {
            val (_, ended) = pair.bob.events.awaitNext(
                timeoutMs = 10_000,
                matches = { it.kind == SipralEventKind.CALL_ENDED.value.toLong() && it.call == incoming.call },
            ) { placed.hangup(SipralHangupReason.COMPLETED_ELSEWHERE) }
            val cause = assertNotNull(endCauseOf(ended), "the CANCEL carried no Reason")
            assertTrue(cause.completedElsewhere)
            assertEquals("Call completed elsewhere", cause.text)
        }
    }
    return "a CANCEL said the call was completed elsewhere"
}

private suspend fun aRingingCallIsSentElsewhere(): String {
    pair().use { pair ->
        val (placed, incoming) = ring(pair)
        placed.use {
            val refused = assertFailsWith<SipralException> {
                pair.bob.redirectCall(incoming, listOf("sip:carol@sipral.invalid"), status = 486)
            }
            assertEquals(SipralStatus.INVALID_ARGUMENT, refused.status)
            val (_, ended) = placed.events.awaitNext(SipralEventKind.CALL_ENDED, timeoutMs = 10_000) {
                pair.bob.redirectCall(
                    incoming, listOf("sip:carol@sipral.invalid", "sip:dave@sipral.invalid"), reason = "unconditional",
                )
            }
            assertEquals(302L, ended.payload.call.statusCode)
        }
    }
    return "a ringing call was sent elsewhere with a 302"
}

private suspend fun anAssertedIdentityIsReadOnlyFromATrustedPeer(): String {
    val headers = listOf(
        SipralHeader("P-Asserted-Identity", "\"Front Desk\" <sip:1000@sipral.invalid>"),
        SipralHeader("Diversion", "<sip:dave@sipral.invalid>;reason=unconditional;counter=1"),
        SipralHeader("History-Info", "<sip:bob@sipral.invalid>;index=1, <sip:carol@sipral.invalid>;index=1.1"),
    )
    for (trusted in listOf(true, false)) {
        pair(bobTrusts = if (trusted) listOf("127.0.0.1") else emptyList()).use { pair ->
            val (placed, incoming) = ring(pair, headers)
            placed.use {
                val identity = pair.bob.callerIdentity(incoming)
                assertEquals(trusted, identity.trusted)
                if (trusted) {
                    assertEquals(SipralParty("sip:1000@sipral.invalid", "Front Desk"), identity.asserted)
                    assertEquals(listOf("sip:1000@sipral.invalid"), identity.assertedParties.map { it.uri })
                } else {
                    assertNull(identity.asserted, "an untrusted peer's assertion is believed")
                    assertEquals(SipralVerstat.NONE, identity.verstat)
                }
                assertEquals(
                    listOf(SipralDiversion("sip:dave@sipral.invalid", null, "unconditional")),
                    identity.diversions,
                )
                assertEquals(1L, incoming.payload.call.diversionCount)
                assertEquals(
                    listOf("sip:bob@sipral.invalid", "sip:carol@sipral.invalid"),
                    identity.history.map { it.uri },
                )
                assertEquals(listOf("1", "1.1"), identity.history.map { it.index })
                pair.bob.answerCall(incoming).use { taken ->
                    assertEquals(identity, taken.identity(), "the call reads what its event did")
                }
            }
        }
    }
    return "an asserted identity was read from a trusted peer and left out from an untrusted one"
}

private suspend fun anAnonymousAccountWithholdsItsNumber(): String {
    pair(alicePrivacy = setOf(SipralPrivacy.ID), aliceTrusts = listOf("127.0.0.1"), bobTrusts = listOf("127.0.0.1"))
        .use { pair ->
            val (placed, incoming) = ring(pair)
            placed.use {
                assertEquals(
                    "sip:anonymous@anonymous.invalid",
                    incoming.payload.call.fromUri?.toString(Charsets.UTF_8),
                )
                val identity = pair.bob.callerIdentity(incoming)
                assertTrue(SipralPrivacy.ID in identity.privacy)
                assertEquals("sip:alice@sipral.invalid", identity.asserted?.uri)
            }
        }
    return "an anonymous account withheld its number and asserted it to a trusted peer"
}

private suspend fun howACallAskedToBeAnswered(): String {
    pair().use { pair ->
        val (placed, incoming) = ring(
            pair,
            listOf(SipralHeader("Answer-Mode", "Auto;require"), SipralHeader("Alert-Info", "<urn:alert:source:external>")),
        )
        placed.use {
            val answering = pair.bob.answering(incoming)
            assertEquals(SipralAnswerMode.AUTO, answering.mode)
            assertTrue(answering.modeRequired)
            assertNotNull(answering.answerAfterMs, "Answer-Mode: Auto asks to be answered without the person")
            assertEquals(SipralRingSource.EXTERNAL, answering.ringSource)
            assertEquals(listOf("urn:alert:source:external"), answering.alertInfo.map { it.uri })
        }
    }
    return "Answer-Mode and Alert-Info were read"
}

private suspend fun aSessionTimerIsAskedForAndOneTooShortRefused(): String {
    pair().use { pair ->
        val refused = assertFailsWith<SipralException> {
            pair.alice.addAccount(
                aor = "sip:short@sipral.invalid",
                registrarAddress = pair.bob.bindAddress,
                sessionTimer = SipralSessionTimerChoice.Interval(30),
            )
        }
        assertEquals(SipralStatus.INVALID_ARGUMENT, refused.status)
        val timed = pair.alice.addAccount(
            aor = "sip:timed@sipral.invalid",
            registrarAddress = pair.bob.bindAddress,
            sessionTimer = SipralSessionTimerChoice.Interval(120),
        )
        val (placed, incoming) = pair.bob.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 10_000) {
            pair.alice.placeCall(timed, "sip:bob@${pair.bob.bindAddress}")
        }
        placed.use {
            val invite = incoming.message?.toString(Charsets.UTF_8) ?: ""
            assertTrue(invite.contains("Session-Expires: 120"), invite)
        }
    }
    return "a session timer of 120 s was asked for and one of 30 s refused"
}

private suspend fun theSuiteASecuredCallRunsHasAName(): String {
    pair(srtp = SipralSrtp.DTLS_REQUIRED).use { pair ->
        val (placed, incoming) = ring(pair)
        placed.use {
            val (taken, secured) = placed.events.awaitNext(SipralEventKind.MEDIA_SECURED, timeoutMs = 10_000) {
                pair.bob.answerCall(incoming)
            }
            taken.use {
                val suite = assertNotNull(srtpSuiteOf(secured), "a suite this layer has no name for")
                assertNotEquals(SipralSrtpSuite.UNKNOWN, suite)
                return "a DTLS-SRTP call named its suite, $suite"
            }
        }
    }
}

private suspend fun aCallMovedAfterTheNetworkChangedIsHeardAtItsNewSocket(): String {
    pair().use { pair ->
        val (placed, incoming) = ring(pair)
        placed.use {
            pair.bob.answerCall(incoming).use { taken ->
                placed.waitConfirmed(10_000)
                assertTrue(until(5_000) { placed.media != null && taken.media?.remoteAddress != null })
                val media = assertNotNull(placed.media)
                val oldSignalling = pair.alice.bindAddress
                val oldMedia = media.localAddress

                val (recovery, wanted) = placed.events.awaitNext(
                    SipralEventKind.CALL_ADDRESS_WANTED,
                    timeoutMs = 10_000,
                ) {
                    pair.alice.networkChanged(SipralNetwork(SipralLink.WIRED, "127.0.0.1", interfaceName = "moved"))
                }
                assertEquals(SipralRecovery.REBUILD, recovery)
                assertEquals(placed.handle, wanted.call)
                assertNotEquals(oldSignalling, pair.alice.bindAddress, "the signalling socket stayed where it was")
                assertTrue(pair.aliceAccount.contact.contains(pair.alice.bindAddress))

                val (_, answered) = placed.events.awaitNext(
                    SipralEventKind.SESSION_CHANGED,
                    SipralEventKind.SESSION_CHANGE_FAILED,
                    timeoutMs = 10_000,
                ) { placed.moveMedia() }
                assertEquals(SipralEventKind.SESSION_CHANGED.value.toLong(), answered.kind)
                assertNotEquals(oldMedia, media.localAddress)

                val before = media.statistics().packetsReceived
                assertTrue(
                    until(3_000) { media.statistics().packetsReceived > before + 10 },
                    "the far end kept sending to the socket the call left",
                )
            }
        }
    }
    return "a call moved after the network changed was heard at its new socket"
}

private fun aRoamThatKeepsTheAddressMovesNothing(): String {
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
        val address = client.bindAddress
        assertEquals(SipralRecovery.NOTHING, client.networkChanged(SipralNetwork(SipralLink.WIRED, "127.0.0.1")))
        assertEquals(address, client.bindAddress)
    }
    return "a roam that kept the address moved nothing"
}

/** Everything above, for IdiomaticCheck.kt's main. */
internal suspend fun signallingChecks(): String = listOf(
    aHangupWithAReasonReachesTheFarEnd(),
    aCancelAsCompletedElsewhereIsNoMissedCall(),
    aRingingCallIsSentElsewhere(),
    anAssertedIdentityIsReadOnlyFromATrustedPeer(),
    anAnonymousAccountWithholdsItsNumber(),
    howACallAskedToBeAnswered(),
    aSessionTimerIsAskedForAndOneTooShortRefused(),
    theSuiteASecuredCallRunsHasAName(),
    aCallMovedAfterTheNetworkChangedIsHeardAtItsNewSocket(),
    aRoamThatKeepsTheAddressMovesNothing(),
).joinToString(", ")
