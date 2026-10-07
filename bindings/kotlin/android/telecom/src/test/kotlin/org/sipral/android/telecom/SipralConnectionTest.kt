// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// SipralConnection on a plain JVM against Android's stub jar, every method
// returning its default (isReturnDefaultValues): what the connection tells
// the framework is invisible, but what the framework asks is not. Every
// callback for answering, rejecting, hanging up, holding or a digit must
// reach the bridge; one left to Connection's empty default leaves the call
// ringing on a screen nobody can clear.

package org.sipral.android.telecom

import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.emptyFlow
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.idiomatic.SipralAnnounced
import org.sipral.telecom.AudioDevice
import org.sipral.telecom.AudioPause
import org.sipral.telecom.AudioState
import org.sipral.telecom.AudioStreams
import org.sipral.telecom.CallAudio
import org.sipral.telecom.SipCalls
import org.sipral.telecom.TelecomBridge
import org.sipral.telecom.TelecomPhase
import org.sipral.telecom.TelecomPlatform
import org.testng.Assert.assertEquals
import org.testng.Assert.assertFalse
import org.testng.Assert.assertTrue
import org.testng.annotations.Test

class SipralConnectionTest {
    private class Recorder : SipCalls, TelecomPlatform {
        val asked = mutableListOf<String>()

        override fun reportIncomingCall(id: String, caller: String, displayName: String?) {
            asked += "report"
        }

        override fun placeOutgoingCall(id: String, target: String) {
            asked += "place-request"
        }

        override fun announce(account: Long, caller: String): SipralAnnounced = SipralAnnounced.Waiting(1)
        override fun forgetAnnouncement(announcement: Long) {
            asked += "forget $announcement"
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

        override fun hold(call: Long) {
            asked += "hold $call"
        }

        override fun resume(call: Long) {
            asked += "resume $call"
        }

        override fun sendDtmf(call: Long, digits: String) {
            asked += "dtmf $call $digits"
        }

        override fun holdState(call: Long): Pair<Boolean, Boolean> = false to false
        override fun release(call: Long) {
            asked += "release $call"
        }
    }

    private class Rig {
        val recorder = Recorder()
        val bridge = TelecomBridge(recorder, recorder)

        /** An INVITE for [call], its connection created, and still ringing. */
        fun ringing(call: Long): SipralConnection {
            val invite = "INVITE sip:bob@example.invalid SIP/2.0\r\nFrom: <sip:alice@example.invalid>;tag=1\r\n\r\n"
            bridge.onEvent(SipralEvent(0, 1, SipralEventKind.INCOMING_CALL.value.toLong(), 7, call, invite.toByteArray()))
            val id = bridge.calls.value.single { it.call == call }.id
            val connection = SipralConnection(id, bridge)
            bridge.connectionCreated(id, connection.port)
            return connection
        }

        fun confirmed(call: Long): SipralConnection {
            val connection = ringing(call)
            connection.onAnswer()
            bridge.onEvent(SipralEvent(0, 1, SipralEventKind.CALL_CONFIRMED.value.toLong(), 7, call, null))
            assertEquals(bridge.calls.value.single { it.call == call }.phase, TelecomPhase.ACTIVE)
            return connection
        }

        fun ended(call: Long): Boolean = bridge.calls.value.single { it.call == call }.phase == TelecomPhase.ENDED
    }

    @Test
    fun everyWayOfTurningACallAwayDeclinesIt() {
        val rig = Rig()
        rig.ringing(1).onReject()
        rig.ringing(2).onReject(android.telecom.Call.REJECT_REASON_DECLINED)
        rig.ringing(3).onReject("On my way")
        rig.ringing(4).onDisconnect()
        for (call in 1L..4L) {
            assertTrue("reject $call 603" in rig.recorder.asked, "call $call was not declined: ${rig.recorder.asked}")
            assertTrue(rig.ended(call), "call $call is still up: ${rig.bridge.calls.value}")
        }
    }

    @Test
    fun everyWayOfAnsweringAnswers() {
        val rig = Rig()
        rig.ringing(1).onAnswer()
        rig.ringing(2).onAnswer(0)
        assertTrue("answer 1" in rig.recorder.asked, rig.recorder.asked.toString())
        assertTrue("answer 2" in rig.recorder.asked, rig.recorder.asked.toString())
    }

    @Test
    fun aLiveCallIsHeldResumedSentADigitAndHungUp() {
        val rig = Rig()
        val connection = rig.confirmed(1)
        connection.onHold()
        connection.onUnhold()
        connection.onPlayDtmfTone('9')
        connection.onDisconnect()
        assertEquals(
            rig.recorder.asked.filter { !it.startsWith("report") && !it.startsWith("answer") },
            listOf("hold 1", "resume 1", "dtmf 1 9", "hangup 1"),
        )
        assertTrue(rig.ended(1))
    }

    @Test
    fun aHoldFromTheFrameworkHoldsAtOnce() {
        // Connection.onHold: a connection not STATE_HOLDING within two seconds is
        // disconnected, so held cannot wait for the re-INVITE's answer.
        val rig = Rig()
        val connection = rig.confirmed(1)
        connection.onHold()
        assertEquals(rig.bridge.calls.value.single().phase, TelecomPhase.HELD)
        connection.onUnhold()
        assertEquals(rig.bridge.calls.value.single().phase, TelecomPhase.ACTIVE)
    }

    @Test
    fun theFrameworksMuteIsReportedOnEveryRelease() {
        val rig = Rig()
        val connection = rig.confirmed(1)
        assertFalse(connection.muted.value)
        connection.onMuteStateChanged(true)
        assertTrue(connection.muted.value)
        connection.onMuteStateChanged(false)
        assertFalse(connection.muted.value)
    }

    @Test
    fun losingTheCallFocusLetsEveryCallsDeviceGoAndGainingItTakesThemBack() {
        val opened = AtomicInteger()
        val stopped = AtomicInteger()
        val closed = AtomicInteger()
        val device = AudioDevice { _, _ ->
            opened.incrementAndGet()
            object : AudioStreams {
                override val capturing = false
                override fun read(buffer: ShortArray) = 0
                override fun write(frame: ShortArray) = frame.size
                override fun interrupt() {
                    stopped.incrementAndGet()
                }
                override fun close() {
                    closed.incrementAndGet()
                }
            }
        }
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val audio = CallAudio("c1", device, 8000, 160, emptyFlow(), {}, scope)
        SipralTelecom.register(audio)
        try {
            audio.start()
            waitFor { audio.state.value == AudioState.RUNNING }
            val service = SipralConnectionService()
            service.onConnectionServiceFocusLost()
            // stopped before the service told the framework it released, and
            // released right after
            assertEquals(stopped.get(), 1)
            waitFor { closed.get() == 1 }
            assertEquals(audio.pauses.value, setOf(AudioPause.CALL_FOCUS_LOST))
            assertFalse(SipralTelecom.callFocus.value)
            service.onConnectionServiceFocusGained()
            waitFor { opened.get() == 2 && audio.state.value == AudioState.RUNNING }
            assertTrue(SipralTelecom.callFocus.value)
        } finally {
            SipralTelecom.unregister(audio)
            audio.close()
            scope.cancel()
        }
    }

    private fun waitFor(condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 5000
        while (!condition()) {
            assertTrue(System.currentTimeMillis() < deadline, "timed out")
            Thread.sleep(2)
        }
    }

    @Test
    fun anAbortedCallEnds() {
        val rig = Rig()
        rig.confirmed(1).onAbort()
        assertTrue("hangup 1" in rig.recorder.asked, rig.recorder.asked.toString())
        assertTrue(rig.ended(1))
    }
}
