// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// Whose challenge an account's password answers, and what a party this end
// holds is sent, through org.sipral.idiomatic: a declined challenge read
// back with its realms as a list, the realms an account names reaching the
// library one per line, and a held party hearing silence unless the client
// says the application's audio. Two clients on 127.0.0.1, run by
// IdiomaticCheck.kt's main under -Xcheck:jni.

package org.sipral.idiomatic

import kotlin.math.abs
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.sipral.SipralChallengeRefusal
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralHeldAudio
import org.sipral.SipralStatus

internal suspend fun challengeChecks(): String =
    listOf(
        aDeclinedChallengeIsReadWithItsRealms(),
        theRealmsReachTheLibraryOnePerLine(),
        aHeldPartyHearsSilenceUnlessTheClientSaysTheApplication(),
    ).joinToString("; ")

private fun aDeclinedChallengeIsReadWithItsRealms(): String {
    val event = SipralEvent(
        size = 0,
        stack = 0,
        kind = SipralEventKind.CHALLENGE_DECLINED.value.toLong(),
        account = 7,
        call = 0,
        message = null,
        payloadChallengeServer = "203.0.113.9:5060",
        payloadChallengeRealms = "sbc.example\ncallee, inc.",
        payloadChallengeNumbers = longArrayOf(SipralChallengeRefusal.NOT_THE_ACCOUNTS_REALM.value.toLong()),
    )
    val declined = assertNotNull(declinedChallengeOf(event))
    assertEquals(SipralChallengeRefusal.NOT_THE_ACCOUNTS_REALM, declined.refusal)
    assertEquals("203.0.113.9:5060", declined.server)
    assertEquals(listOf("sbc.example", "callee, inc."), declined.realms)
    val other = SipralEvent(
        size = 0,
        stack = 0,
        kind = SipralEventKind.CALL_ENDED.value.toLong(),
        account = 7,
        call = 0,
        message = null,
    )
    assertNull(declinedChallengeOf(other))
    return "a declined challenge read with its realms"
}

private fun theRealmsReachTheLibraryOnePerLine(): String {
    val client = SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1")
    try {
        client.addAccount(
            aor = "sip:alice@example.invalid", registrarAddress = "127.0.0.1:5060",
            authUser = "alice", authPassword = "open sesame", realms = listOf("registrar.example", "sbc, inc."),
        )
        val refused = assertFailsWith<SipralException> {
            client.addAccount(
                aor = "sip:bob@example.invalid", registrarAddress = "127.0.0.1:5060",
                realms = listOf("registrar.example", "sbc\texample"),
            )
        }
        assertEquals(SipralStatus.INVALID_ARGUMENT, refused.status)
    } finally {
        client.close()
    }
    return "the realms reach the library one per line"
}

/** The loudest sample the far end hears of a tone sent on a call held
 * from this end, on clients whose held audio is [heldAudio]. */
private suspend fun loudestHeardOnHold(heldAudio: SipralHeldAudio): Int {
    val clientA = SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", heldAudio = heldAudio)
    val clientB = SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", heldAudio = heldAudio)
    try {
        val accountA = clientA.addAccount(aor = "sip:alice@example.invalid", registrarAddress = clientB.bindAddress)
        clientB.addAccount(aor = "sip:bob@example.invalid", registrarAddress = clientA.bindAddress)
        val (callA, incoming) = clientB.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
            clientA.placeCall(accountA, target = "sip:bob@example.invalid")
        }
        val callB = clientB.answerCall(incoming)
        try {
            callA.waitConfirmed()
            callB.waitConfirmed()
            withTimeout(15_000) {
                while (callA.media == null || callB.media == null) {
                    delay(20)
                }
            }
            callA.hold()
            withTimeout(15_000) {
                while (!callA.holdState.first) {
                    delay(20)
                }
            }
            val mediaA = assertNotNull(callA.media)
            val mediaB = assertNotNull(callB.media)
            mediaA.sendAudio(ShortArray(mediaA.frameSamples * 40) { 8_000 })
            var loudest = 0
            withTimeoutOrNull(1_500) {
                mediaB.frames.collect { frame ->
                    for (sample in frame) {
                        loudest = maxOf(loudest, abs(sample.toInt()))
                    }
                }
            }
            return loudest
        } finally {
            callA.close()
            callB.close()
        }
    } finally {
        clientA.close()
        clientB.close()
    }
}

private suspend fun aHeldPartyHearsSilenceUnlessTheClientSaysTheApplication(): String {
    val byDefault = loudestHeardOnHold(SipralHeldAudio.DEFAULT)
    assertTrue(byDefault < 100, "the held party heard the application on a client told nothing: $byDefault")
    val application = loudestHeardOnHold(SipralHeldAudio.APPLICATION)
    assertTrue(application > 1_000, "the held party did not hear what the application sent: $application")
    return "a held party hears silence, or the application when told"
}
