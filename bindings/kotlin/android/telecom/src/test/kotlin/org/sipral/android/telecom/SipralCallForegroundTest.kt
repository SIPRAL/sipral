// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// SipralCallForeground on a plain JVM against Android's stub jar: a context
// that records each startForegroundService and stopService, a bridge over
// recorders, and SipralCallService's onStartCommand stood in for by what it
// asks (entering). The service must hold a ringing call from its push's
// announcement, as phoneCall alone, until it is answered (then with the
// microphone), declined, cancelled by the caller or never arrives; and
// Android's rule that a service started for the foreground enters it before
// it stops must hold however soon the call ends.

package org.sipral.android.telecom

import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.idiomatic.SipralAnnounced
import org.sipral.telecom.SipCalls
import org.sipral.telecom.TelecomBridge
import org.sipral.telecom.TelecomCall
import org.sipral.telecom.TelecomDirection
import org.sipral.telecom.TelecomPhase
import org.sipral.telecom.TelecomPlatform
import org.testng.Assert.assertEquals
import org.testng.Assert.assertFalse
import org.testng.Assert.assertNotNull
import org.testng.Assert.assertNull
import org.testng.Assert.assertTrue
import org.testng.annotations.Test

class SipralCallForegroundTest {
    private class Sip : SipCalls, TelecomPlatform {
        val asked = CopyOnWriteArrayList<String>()

        override fun reportIncomingCall(id: String, caller: String, displayName: String?) {
            asked += "report $caller"
        }

        override fun placeOutgoingCall(id: String, target: String) {
            asked += "place-request $target"
        }

        override fun announce(account: Long, caller: String?, callId: String?): SipralAnnounced = SipralAnnounced.Waiting(1)
        override fun forgetAnnouncement(announcement: Long) {
            asked += "forget $announcement"
        }

        override fun ring(call: Long) {
            asked += "ring $call"
        }

        override fun answer(call: Long) {
            asked += "answer $call"
        }

        override fun reject(call: Long, code: Long) {
            asked += "reject $call $code"
        }

        override fun place(account: Long, target: String): Long = 0
        override fun hangup(call: Long) {
            asked += "hangup $call"
        }

        override fun hold(call: Long) = Unit
        override fun resume(call: Long) = Unit
        override fun sendDtmf(call: Long, digits: String) = Unit
        override fun holdState(call: Long): Pair<Boolean, Boolean> = false to false
        override fun release(call: Long) {
            asked += "release $call"
        }
    }

    /** The application's context: each start and stop of the service
     * recorded, a start refused while [refuse] is set, and the service's
     * `onStartCommand` run at once unless [deferred], when [service] runs
     * it. */
    private class Android : ContextWrapper(null) {
        val did = CopyOnWriteArrayList<String>()
        val entered = CopyOnWriteArrayList<SipralCallForeground.Shown?>()

        @Volatile
        var refuse = false

        @Volatile
        var deferred = false
        private var waiting = 0

        override fun getApplicationContext(): Context = this

        override fun startForegroundService(service: Intent?): ComponentName? {
            if (refuse) {
                did += "refused"
                throw IllegalStateException("startForegroundService() not allowed")
            }
            did += "start"
            synchronized(this) {
                if (deferred) {
                    waiting++
                    return null
                }
            }
            entered += SipralCallForeground.entering()
            return null
        }

        override fun stopService(name: Intent?): Boolean {
            did += "stop"
            return true
        }

        /** The `onStartCommand` of every start deferred so far. */
        fun service() {
            val count = synchronized(this) { waiting.also { waiting = 0 } }
            repeat(count) { entered += SipralCallForeground.entering() }
        }

        val starts: Int get() = did.count { it == "start" }
        val stops: Int get() = did.count { it == "stop" }
    }

    private class Rig : AutoCloseable {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val sip = Sip()
        val bridge = TelecomBridge(sip, sip)
        val android = Android()
        val reports = CopyOnWriteArrayList<String>()
        val following: Job = SipralCallForeground.follow(android, bridge, scope, { _, _, _ -> error("no notification here") }) {
            reports += it
        }

        init {
            // the first calls seen, none, stop whatever an earlier follower left
            waitFor { android.stops == 1 }
            android.did.clear()
        }

        fun invite(call: Long) {
            val invite = "INVITE sip:bob@example.invalid SIP/2.0\r\nFrom: \"Alice\" <sip:alice@example.invalid>;tag=1\r\n\r\n"
            bridge.onEvent(SipralEvent(0, 1, SipralEventKind.INCOMING_CALL.value.toLong(), ACCOUNT, call, invite.toByteArray()))
        }

        fun event(kind: SipralEventKind, call: Long, message: String? = null) {
            bridge.onEvent(SipralEvent(0, 1, kind.value.toLong(), ACCOUNT, call, message?.toByteArray()))
        }

        fun last(): SipralCallForeground.Shown = present(android.entered.last())

        override fun close() {
            android.deferred = false
            android.service()
            scope.cancel()
        }
    }

    private fun rig(test: Rig.() -> Unit) {
        Rig().use { it.test() }
    }

    @Test
    fun aPushedCallHoldsTheServiceFromItsAnnouncementAsAPhoneCallUntilItsInviteNeverComes() = rig {
        val id = bridge.pushArrived(ACCOUNT, "sip:alice@example.invalid")
        waitFor { android.starts == 1 }
        assertEquals(android.stops, 0)
        val shown = last()
        assertEquals(shown.call.id, id)
        assertEquals(shown.call.phase, TelecomPhase.RINGING)
        assertTrue(shown.call.announced)
        assertFalse(shown.microphone, "a ringing call is phoneCall alone")
        assertTrue(shown.stays)
        // the announcement's twenty seconds ran out in a process kept running
        event(SipralEventKind.ANNOUNCED_CALL_MISSING, 0)
        waitFor { android.stops == 1 }
        assertEquals(android.starts, 1)
        assertTrue(bridge.calls.value.none { it.phase != TelecomPhase.ENDED })
    }

    @Test
    fun aPushedCallAnsweredKeepsTheServiceAndAddsTheMicrophone() = rig {
        val id = bridge.pushArrived(ACCOUNT, "sip:alice@example.invalid")
        waitFor { android.starts == 1 }
        event(SipralEventKind.CALL_ANNOUNCED, INCOMING)
        invite(INCOMING)
        waitFor { bridge.callHandleOf(id) == INCOMING }
        Thread.sleep(50)
        assertEquals(android.starts, 1, "the INVITE arriving leaves the ringing call as it was")
        bridge.answer(id)
        assertTrue("answer $INCOMING" in sip.asked)
        event(SipralEventKind.CALL_CONFIRMED, INCOMING)
        waitFor { android.starts == 2 }
        assertEquals(android.stops, 0, "never let go between ringing and answered")
        assertEquals(last().call.phase, TelecomPhase.ACTIVE)
        assertTrue(last().microphone)
        event(SipralEventKind.CALL_ENDED, INCOMING)
        waitFor { android.stops == 1 }
    }

    @Test
    fun aCallTheCallerCancelsWhileItRingsLetsTheServiceGo() = rig {
        invite(INCOMING)
        waitFor { android.starts == 1 }
        assertEquals(last().call.phase, TelecomPhase.RINGING)
        assertFalse(last().microphone)
        event(SipralEventKind.CALL_ENDED, INCOMING, "SIP/2.0 487 Request Terminated\r\n\r\n")
        waitFor { android.stops == 1 }
        assertEquals(android.starts, 1)
    }

    @Test
    fun aDeclinedCallLetsTheServiceGoAtOnce() = rig {
        invite(INCOMING)
        waitFor { android.starts == 1 }
        bridge.reject(bridge.calls.value.single().id)
        assertTrue("reject $INCOMING 603" in sip.asked)
        waitFor { android.stops == 1 }
    }

    @Test
    fun aCallRingingBesideAnAnsweredOneLeavesTheServiceOnTheAnsweredOne() = rig {
        invite(INCOMING)
        waitFor { android.starts == 1 }
        val answered = bridge.calls.value.single().id
        bridge.answer(answered)
        event(SipralEventKind.CALL_CONFIRMED, INCOMING)
        waitFor { android.starts == 2 }
        invite(SECOND)
        waitFor { bridge.calls.value.size == 2 }
        Thread.sleep(50)
        assertEquals(android.starts, 2, "a second call ringing changes nothing the service shows")
        assertEquals(last().call.id, answered)
        assertTrue(last().microphone)
        event(SipralEventKind.CALL_ENDED, SECOND, "SIP/2.0 487 Request Terminated\r\n\r\n")
        event(SipralEventKind.CALL_ENDED, INCOMING)
        waitFor { android.stops == 1 }
    }

    @Test
    fun aCallEndedWhileItsServiceIsStartingLetsTheServiceEnterTheForegroundAndLeave() = rig {
        android.deferred = true
        invite(INCOMING)
        waitFor { android.starts == 1 }
        bridge.reject(bridge.calls.value.single().id)
        waitFor { bridge.calls.value.none { it.phase != TelecomPhase.ENDED } }
        Thread.sleep(50)
        assertEquals(android.stops, 0, "stopped before startForeground, Android would end the process")
        android.service()
        val shown = last()
        assertFalse(shown.stays, "it leaves once in the foreground")
        assertEquals(shown.call.phase, TelecomPhase.ENDED)
        assertFalse(shown.microphone)
    }

    @Test
    fun aStartAndroidRefusesIsReportedAndNotWaitedFor() = rig {
        android.refuse = true
        invite(INCOMING)
        waitFor { "refused" in android.did }
        // reported by the starting thread after the refusal is recorded
        waitFor { reports.any { it.startsWith("call service not started") } }
        android.refuse = false
        bridge.reject(bridge.calls.value.single().id)
        waitFor { android.stops == 1 }
    }

    @Test
    fun aFollowerCancelledWhileACallRingsStopsTheService() = rig {
        invite(INCOMING)
        waitFor { android.starts == 1 }
        following.cancel()
        waitFor { android.stops == 1 }
    }

    @Test
    fun theServiceIsHeldForAnAnsweredCallBeforeOneThatRings() {
        fun call(id: String, phase: TelecomPhase) =
            TelecomCall(id, TelecomDirection.INCOMING, ACCOUNT, "sip:alice@example.invalid", null, phase, 0, false, false)
        assertNull(SipralCallForeground.heldFor(emptyList()))
        assertNull(SipralCallForeground.heldFor(listOf(call("a", TelecomPhase.ENDED))))
        val ringing = present(SipralCallForeground.heldFor(listOf(call("a", TelecomPhase.RINGING))))
        assertEquals(ringing.call.id, "a")
        assertFalse(ringing.microphone)
        for (phase in listOf(TelecomPhase.REQUESTED, TelecomPhase.DIALING, TelecomPhase.ACTIVE, TelecomPhase.HELD)) {
            val held = present(SipralCallForeground.heldFor(listOf(call("a", TelecomPhase.RINGING), call("b", phase))))
            assertEquals(held.call.id, "b", "$phase")
            assertTrue(held.microphone, "$phase")
        }
    }
}

private const val ACCOUNT = 7L
private const val INCOMING = 5L
private const val SECOND = 6L

private fun <T> present(value: T?): T {
    assertNotNull(value)
    return value!!
}

private fun waitFor(condition: () -> Boolean) {
    val deadline = System.currentTimeMillis() + 5000
    while (!condition()) {
        assertTrue(System.currentTimeMillis() < deadline, "timed out")
        Thread.sleep(2)
    }
}
