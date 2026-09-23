// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// SipralConnection on a plain JVM, against the Android platform's stub jar
// with every method answering its default (testOptions.unitTests
// .isReturnDefaultValues): what the connection says to the framework cannot
// be observed there, but what the framework asks of it can. Every callback
// the framework may use to answer, turn away, hang up, hold or send a digit
// through has to reach the bridge -- one that is left to Connection's own
// empty default leaves the call ringing on a screen nobody can clear.

package org.sipral.android.telecom

import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.idiomatic.SipralAnnounced
import org.sipral.telecom.SipCalls
import org.sipral.telecom.TelecomBridge
import org.sipral.telecom.TelecomPhase
import org.sipral.telecom.TelecomPlatform
import org.testng.Assert.assertEquals
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
    fun anAbortedCallEnds() {
        val rig = Rig()
        rig.confirmed(1).onAbort()
        assertTrue("hangup 1" in rig.recorder.asked, rig.recorder.asked.toString())
        assertTrue(rig.ended(1))
    }
}
