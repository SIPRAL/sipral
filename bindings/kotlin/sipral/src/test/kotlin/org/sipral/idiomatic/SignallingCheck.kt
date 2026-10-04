// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// ABI 0.29's signalling surface through org.sipral.idiomatic, between two
// clients on 127.0.0.1: why a call ended (RFC 3326) both ways, who is
// calling behind the trust gate (RFC 3325, 3323, 5806, 7044), how the call
// asked to be answered (RFC 5373, Alert-Info), a 3xx answer, the account's
// session timer, the SRTP suite a call is keyed with, and a call moved to a
// new socket after the network changed, the signalling port kept across
// such a change, and a clock reading the poll overtook retried. Run by
// IdiomaticCheck.kt's main, under -Xcheck:jni.

package org.sipral.idiomatic

import java.net.DatagramSocket
import java.net.InetAddress
import kotlinx.coroutines.delay
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
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
                assertEquals(oldSignalling, pair.alice.bindAddress, "the address and the port did not change, so neither did the socket's")
                assertTrue(pair.alice.keptSignallingPort)
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

/** The address the route to the rest of the world leaves from: this
 * machine's other address beside loopback, which these checks need. */
private fun otherAddress(): String {
    val host = routeHost("192.0.2.1:5060")
    check(host != "127.0.0.1") { "this machine has no address but loopback, and the port checks need one" }
    return host
}

private fun freePort(host: String): Int = DatagramSocket(0, InetAddress.getByName(host)).use { it.localPort }

/** The port the application chose survives a move to another address and
 * back, and with none chosen the port in use does. */
private fun theSignallingPortSurvivesAMoveToAnotherAddress(): String {
    val elsewhere = otherAddress()
    val chosen = freePort(elsewhere)
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", bindPort = chosen).use { client ->
        client.networkChanged(SipralNetwork(SipralLink.WIRED, elsewhere, interfaceName = "moved"))
        assertEquals("$elsewhere:$chosen", client.bindAddress)
        assertTrue(client.keptSignallingPort)
        client.networkChanged(SipralNetwork(SipralLink.WIRED, "127.0.0.1", interfaceName = "back"))
        assertEquals("127.0.0.1:$chosen", client.bindAddress)
    }
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
        val port = client.bindAddress.substringAfterLast(':')
        client.networkChanged(SipralNetwork(SipralLink.WIRED, "127.0.0.1", interfaceName = "moved"))
        assertEquals("127.0.0.1:$port", client.bindAddress)
        assertTrue(client.keptSignallingPort)
    }
    return "the signalling port survived a move to another address"
}

/** A port another socket holds at the new address is not fought over: the
 * system picks one, and the client says so. */
private fun aPortTakenAtTheNewAddressFallsBackAndSaysSo(): String {
    val elsewhere = otherAddress()
    DatagramSocket(0, InetAddress.getByName(elsewhere)).use { squatter ->
        val taken = squatter.localPort
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", bindPort = taken).use { client ->
            client.networkChanged(SipralNetwork(SipralLink.WIRED, elsewhere, interfaceName = "moved"))
            assertEquals(elsewhere, client.bindAddress.substringBeforeLast(':'))
            val now = client.bindAddress.substringAfterLast(':').toInt()
            assertNotEquals(taken, now)
            assertNotEquals(0, now)
            assertFalse(client.keptSignallingPort)
        }
    }
    return "a port taken at the new address fell back and said so"
}

/** A move to an address this machine lacks fails with the signalling
 * socket it had still open, so the next move keeps its port. */
private fun aMoveToAnAddressThisMachineLacksKeepsTheSocketItHad(): String {
    val elsewhere = otherAddress()
    SipralClient.open(audio = SipralAudioMode.Application).use { client ->
        val before = client.bindAddress
        val port = before.substringAfterLast(':')
        // TEST-NET-1 (RFC 5737): on no interface of this machine
        assertFailsWith<java.net.SocketException> {
            client.networkChanged(SipralNetwork(SipralLink.WIRED, "192.0.2.77", interfaceName = "gone"))
        }
        assertEquals(before, client.bindAddress)
        client.networkChanged(SipralNetwork(SipralLink.WIRED, elsewhere, interfaceName = "moved"))
        assertEquals("$elsewhere:$port", client.bindAddress)
        assertTrue(client.keptSignallingPort)
    }
    return "a move to an address this machine lacks kept the socket it had"
}

/** A client bound on every interface keeps picking its own address across
 * a move: its socket stays where it was, on its port, and what it advertises
 * is the route toward each account's server again rather than the address
 * the platform named, taken as fixed from then on. */
private fun aClientOnEveryInterfaceKeepsChoosingItsRouteAcrossAMove(): String {
    val elsewhere = otherAddress()
    SipralClient.open(audio = SipralAudioMode.Application).use { client ->
        val port = client.bindAddress.substringAfterLast(':')
        val away = client.addAccount(aor = "sip:alice@192.0.2.1", registrarAddress = "192.0.2.1:5060")
        assertEquals("$elsewhere:$port", client.bindAddress)

        client.networkChanged(SipralNetwork(SipralLink.WIRED, elsewhere, interfaceName = "moved"))
        val here = client.addAccount(aor = "sip:bob@127.0.0.1", registrarAddress = "127.0.0.1:5060")
        assertTrue(
            here.contact.contains("127.0.0.1:$port"),
            "an account added after the move is reached at the route toward its server: ${here.contact}",
        )

        client.networkChanged(SipralNetwork(SipralLink.WIRED, "127.0.0.1", interfaceName = "back"))
        assertEquals(
            "$elsewhere:$port", client.bindAddress,
            "the route toward the first account's server, not the address the platform named",
        )
        assertTrue(client.keptSignallingPort)
        assertTrue(away.contact.contains("$elsewhere:$port"), away.contact)
        assertTrue(here.contact.contains("127.0.0.1:$port"), here.contact)
    }
    return "a client on every interface kept choosing its route across a move"
}

/** A clock reading the poll thread overtook is read again, as a collision
 * with it is; anything else goes straight through. */
private fun aClockBehindIsRetriedLikeABusy(): String {
    for (status in listOf(SipralStatus.BUSY, SipralStatus.CLOCK_BEHIND)) {
        var attempts = 0
        val answer = retryBusy {
            attempts++
            if (attempts < 3) throw SipralException(status, "")
            attempts
        }
        assertEquals(3, answer, "$status was not retried")
    }
    var attempts = 0
    assertFailsWith<SipralException> {
        retryBusy {
            attempts++
            throw SipralException(SipralStatus.WRONG_STATE, "")
        }
    }
    assertEquals(1, attempts)
    return "a clock behind was retried like a busy"
}

/** Everything above, for IdiomaticCheck.kt's main. */
private fun aCallPlacedPastMaxDialogsIsRefused(): String {
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", maxDialogs = 1).use { alice ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { bob ->
            val account = alice.addAccount(aor = "sip:alice@sipral.invalid", registrarAddress = bob.bindAddress)
            alice.placeCall(account, "sip:bob@${bob.bindAddress}").use {
                val refused = assertFailsWith<SipralException> {
                    alice.placeCall(account, "sip:bob@${bob.bindAddress}")
                }
                assertEquals(SipralStatus.LIMIT_REACHED, refused.status)
            }
        }
    }
    return "a call past maxDialogs was refused"
}

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
    theSignallingPortSurvivesAMoveToAnotherAddress(),
    aPortTakenAtTheNewAddressFallsBackAndSaysSo(),
    aMoveToAnAddressThisMachineLacksKeepsTheSocketItHad(),
    aClientOnEveryInterfaceKeepsChoosingItsRouteAcrossAMove(),
    aClockBehindIsRetriedLikeABusy(),
    aCallPlacedPastMaxDialogsIsRefused(),
).joinToString(", ")
