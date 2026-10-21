// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// C3 through org.sipral.idiomatic (docs/15-mobile.md): a registration
// written down by one client and carried on by another, as a process killed
// in the background and started again by a push does. The second client's
// first REGISTER continues the first one's Call-ID and sequence number, the
// account reads RESTORED and never REGISTERED until the registrar answers,
// and the time to ready is measured from the declared cold start. Against
// ReachabilityCheck.kt's loopback registrar, run by IdiomaticCheck.kt's main
// under -Xcheck:jni.

package org.sipral.idiomatic

import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.delay
import org.sipral.SipralException
import org.sipral.SipralRegistrationState
import org.sipral.SipralStatus

private fun headerOf(name: String, message: String): String? =
    message.split("\r\n")
        .firstOrNull { it.lowercase().startsWith(name.lowercase() + ":") }
        ?.substringAfter(':')?.trim()

private suspend fun reaches(account: SipralAccount, state: SipralRegistrationState) {
    repeat(400) {
        if (account.registrationState == state) return
        delay(25)
    }
    throw AssertionError("the account never reached $state, it is ${account.registrationState}")
}

internal suspend fun freezeChecks(): String {
    val aor = "sip:alice@example.com"
    DatagramRegistrar().use { registrar ->
        val written = SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { first ->
            val account = first.addAccount(aor, registrar.address, registrar = "sip:example.com")
            val nothing = assertFailsWith<SipralException> { account.freeze() }
            assertEquals(SipralStatus.WRONG_STATE, nothing.status, "an account that never registered has nothing to keep")
            account.register()
            reaches(account, SipralRegistrationState.REGISTERED)
            assertNull(account.timeToReadyMs, "no cold start was declared on this client")
            account.freeze()
        }
        assertEquals("SPRG", String(written, 0, 4, Charsets.US_ASCII))
        val before = registrar.registers.last()

        val seqBefore = headerOf("CSeq", before)!!.substringBefore(' ').toLong()
        val seqAfter = SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { second ->
            second.coldStart()
            val other = second.addAccount("sip:bob@example.com", registrar.address, registrar = "sip:example.com")
            val stranger = assertFailsWith<SipralException> { other.thaw(written, 0) }
            assertEquals(SipralStatus.INVALID_ARGUMENT, stranger.status, "another address of record's snapshot")
            val damaged = written.copyOf(written.size - 1)
            val account = second.addAccount(aor, registrar.address, registrar = "sip:example.com")
            val cut = assertFailsWith<SipralException> { account.thaw(damaged, 0) }
            assertEquals(SipralStatus.INVALID_ARGUMENT, cut.status, "a snapshot one byte short")

            // asleep longer than the hour the registrar granted: the binding
            // has lapsed, so the refresh is booked for now
            val count = registrar.registers.size
            account.thaw(written, 3_700_000)
            assertTrue(account.wantsRegistration)
            val restored = account.registrationState
            assertTrue(
                restored == SipralRegistrationState.RESTORED || restored == SipralRegistrationState.REFRESHING ||
                    restored == SipralRegistrationState.REGISTERED,
                "thawed, the account reads $restored",
            )
            reaches(account, SipralRegistrationState.REGISTERED)
            val after = registrar.registers.drop(count).first()
            assertEquals(headerOf("Call-ID", before), headerOf("Call-ID", after), "the same Call-ID carried on")
            val continued = headerOf("CSeq", after)!!.substringBefore(' ').toLong()
            assertTrue(continued > seqBefore, "CSeq $continued continues after $seqBefore")
            val ready = assertNotNull(account.timeToReadyMs, "registered after a declared cold start")
            assertTrue(ready in 0..10_000, "time to ready $ready ms")
            continued
        }

        // Asleep a second: the binding still has most of its hour, so the
        // refresh is booked an hour on and the account stays RESTORED. A
        // process woken by a push confirms it now, with refreshBinding, and
        // that REGISTER carries the same binding on.
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { third ->
            third.coldStart()
            val account = third.addAccount(aor, registrar.address, registrar = "sip:example.com")
            account.thaw(written, 1_000)
            delay(300)
            assertEquals(SipralRegistrationState.RESTORED, account.registrationState, "nothing has confirmed it yet")
            assertNull(account.timeToReadyMs, "not ready until a registrar answers")
            val count = registrar.registers.size
            account.refreshBinding()
            reaches(account, SipralRegistrationState.REGISTERED)
            val refresh = registrar.registers.drop(count).first()
            assertEquals(headerOf("Call-ID", before), headerOf("Call-ID", refresh), "the refresh continues the binding")
            val ready = assertNotNull(account.timeToReadyMs)
            return "a registration frozen, thawed in another client, continued on its Call-ID " +
                "(CSeq $seqBefore then $seqAfter); thawed with time left, RESTORED until refreshBinding, " +
                "then ready ${ready} ms after the cold start; another address of record's and a damaged " +
                "snapshot refused"
        }
    }
}
