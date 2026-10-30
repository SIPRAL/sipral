// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// CoreTelecomPlatform and SipralCoreCall on a plain JVM: CallsManager needs
// a device, so a recorder stands in for addCall, and another for the call's
// CallControlScope, which is an interface. What the bridge asks must reach
// the framework as the transaction the transactional API expects (answer
// for an incoming call's first activation, setActive otherwise), a request
// the framework already made must not be made back to it, and a refusal
// must leave the SIP side agreeing with the framework.

package org.sipral.android.telecom

import android.os.ParcelUuid
import android.telecom.DisconnectCause
import androidx.core.telecom.CallControlResult
import androidx.core.telecom.CallControlScope
import androidx.core.telecom.CallEndpointCompat
import androidx.core.telecom.CallException
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.runBlocking
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralStatus
import org.sipral.idiomatic.SipralAnnounced
import org.sipral.telecom.AudioRoute
import org.sipral.telecom.SipCalls
import org.sipral.telecom.TelecomBridge
import org.sipral.telecom.TelecomDisconnect
import org.sipral.telecom.TelecomPhase
import org.sipral.telecom.TelecomPlaceFailure
import org.testng.Assert.assertEquals
import org.testng.Assert.assertFalse
import org.testng.Assert.assertNull
import org.testng.Assert.assertTrue
import org.testng.annotations.Test

class CoreTelecomPlatformTest {
    private class Sip : SipCalls {
        val asked = CopyOnWriteArrayList<String>()

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

        /** What [place] throws, when it is to refuse. */
        @Volatile
        var placeRefusal: Exception? = null

        override fun place(account: Long, target: String): Long {
            asked += "place $target"
            placeRefusal?.let { throw it }
            return OUTGOING
        }

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

    /** One call's `CallControlScope`, recording each transaction and
     * refusing those named in [refuse]. */
    private class Control(parent: Job) : CallControlScope {
        val job = Job(parent)
        override val coroutineContext = job + Dispatchers.Default
        val asked = CopyOnWriteArrayList<String>()

        @Volatile
        var refuse: Set<String> = emptySet()

        /** Completed when the session ends, by a disconnect from either side. */
        val ended = CompletableDeferred<Unit>()
        val offered = MutableStateFlow<List<CallEndpointCompat>>(emptyList())
        val current = MutableStateFlow<CallEndpointCompat?>(null)
        val mute = MutableStateFlow(false)

        override fun getCallId(): ParcelUuid = ParcelUuid(UUID(0, 1))

        private fun result(name: String): CallControlResult {
            asked += name
            return if (name in refuse) {
                CallControlResult.Error(CallException.ERROR_CALL_CANNOT_BE_SET_TO_ACTIVE)
            } else {
                CallControlResult.Success()
            }
        }

        override suspend fun setActive() = result("setActive")
        override suspend fun setInactive() = result("setInactive")
        override suspend fun answer(callType: Int) = result("answer")
        override suspend fun disconnect(disconnectCause: DisconnectCause): CallControlResult {
            asked += "disconnect"
            ended.complete(Unit)
            return CallControlResult.Success()
        }

        override suspend fun requestEndpointChange(endpoint: CallEndpointCompat) = result("endpoint ${endpoint.name}")
        override val currentCallEndpoint: Flow<CallEndpointCompat> = current.filterNotNull()
        override val availableEndpoints: Flow<List<CallEndpointCompat>> = offered
        override val isMuted: Flow<Boolean> = mute
    }

    /** One `addCall`, with the callbacks the platform passed. */
    private class Added(
        val incoming: Boolean,
        val address: String,
        val onAnswer: suspend () -> Unit,
        val onDisconnect: suspend () -> Unit,
        val onSetActive: suspend () -> Unit,
        val onSetInactive: suspend () -> Unit,
        val control: Control,
    )

    private class Adder(private val parent: Job) : CallAdder {
        val added = CopyOnWriteArrayList<Added>()

        @Volatile
        var refuseAdding = false

        @Volatile
        var refuse: Set<String> = emptySet()

        override suspend fun add(
            incoming: Boolean,
            address: String,
            displayName: String,
            onAnswer: suspend () -> Unit,
            onDisconnect: suspend () -> Unit,
            onSetActive: suspend () -> Unit,
            onSetInactive: suspend () -> Unit,
            block: CallControlScope.() -> Unit,
        ) {
            if (refuseAdding) {
                throw CallException(CallException.ERROR_CALL_NOT_PERMITTED_AT_PRESENT_TIME)
            }
            val control = Control(parent)
            control.refuse = refuse
            added += Added(incoming, address, onAnswer, onDisconnect, onSetActive, onSetInactive, control)
            try {
                control.block()
                control.ended.await()
            } finally {
                control.job.cancel()
            }
        }
    }

    /** One platform, bridge and recorders, for one test. */
    private class Rig : AutoCloseable {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val sip = Sip()
        val adder = Adder(scope.coroutineContext[Job]!!)
        val reports = CopyOnWriteArrayList<String>()
        val platform = CoreTelecomPlatform(scope, adder) { reports += it }
        val bridge = TelecomBridge(platform, sip)
        val shown = CopyOnWriteArrayList<String>()

        init {
            platform.install(bridge) { id, _ -> shown += id }
        }

        override fun close() {
            scope.cancel()
        }

        fun invite(call: Long = INCOMING) {
            val invite = "INVITE sip:bob@example.invalid SIP/2.0\r\nFrom: \"Alice\" <sip:alice@example.invalid>;tag=1\r\n\r\n"
            bridge.onEvent(SipralEvent(0, 1, SipralEventKind.INCOMING_CALL.value.toLong(), ACCOUNT, call, invite.toByteArray()))
        }

        fun event(kind: SipralEventKind, call: Long) {
            bridge.onEvent(SipralEvent(0, 1, kind.value.toLong(), ACCOUNT, call, null))
        }

        fun phase(): TelecomPhase? = bridge.calls.value.singleOrNull()?.phase

        /** An incoming call, added and ringing. */
        fun ringing(): Added {
            invite()
            waitFor { adder.added.size == 1 && shown.size == 1 }
            return adder.added.single()
        }

        /** An outgoing call, added, placed and answered by the far end. */
        fun connected(): Pair<String, Added> {
            val id = bridge.placeCall(ACCOUNT, "sip:bob@example.invalid")
            waitFor { "place sip:bob@example.invalid" in sip.asked }
            event(SipralEventKind.CALL_CONFIRMED, OUTGOING)
            val added = adder.added.single()
            waitFor { "setActive" in added.control.asked }
            assertEquals(phase(), TelecomPhase.ACTIVE)
            return id to added
        }
    }

    private fun rig(test: Rig.() -> Unit) {
        Rig().use { it.test() }
    }

    @Test
    fun anOutgoingCallIsAddedThenPlacedThenSetActiveHeldResumedAndDisconnected() = rig {
        val (id, added) = connected()
        assertFalse(added.incoming)
        assertEquals(added.address, "sip:bob@example.invalid")
        bridge.hold(id)
        waitFor { "setInactive" in added.control.asked }
        bridge.unhold(id)
        waitFor { added.control.asked.count { it == "setActive" } == 2 }
        event(SipralEventKind.CALL_ENDED, OUTGOING)
        waitFor { added.control.ended.isCompleted && SipralTelecom.callRoutes.value[id] == null }
        assertEquals(added.control.asked, listOf("setActive", "setInactive", "setActive", "disconnect"))
        assertEquals(sip.asked, listOf("place sip:bob@example.invalid", "hold $OUTGOING", "resume $OUTGOING", "release $OUTGOING"))
        assertTrue(bridge.calls.value.isEmpty())
    }

    @Test
    fun anIncomingCallAnsweredInTheApplicationIsAnsweredInTheFramework() = rig {
        val added = ringing()
        assertTrue(added.incoming)
        assertEquals(phase(), TelecomPhase.RINGING)
        bridge.answer(bridge.calls.value.single().id)
        event(SipralEventKind.CALL_CONFIRMED, INCOMING)
        waitFor { "answer" in added.control.asked }
        assertEquals(added.control.asked, listOf("answer"))
        assertTrue("answer $INCOMING" in sip.asked)
    }

    @Test
    fun anIncomingCallRingsOnceTheFrameworkHasAddedIt() = rig {
        ringing()
        waitFor { "ring $INCOMING" in sip.asked }
        assertEquals(sip.asked.count { it.startsWith("ring") }, 1, sip.asked.toString())
    }

    @Test
    fun anAnswerFromTheFrameworkIsNotAnsweredBackToIt() = rig {
        // a watch or a car answered: the framework has the call active once the
        // callback returns
        val added = ringing()
        runBlockingCallback(added.onAnswer)
        assertTrue("answer $INCOMING" in sip.asked)
        event(SipralEventKind.CALL_CONFIRMED, INCOMING)
        assertEquals(phase(), TelecomPhase.ACTIVE)
        Thread.sleep(50)
        assertTrue(added.control.asked.isEmpty(), added.control.asked.toString())
    }

    @Test
    fun aDisconnectFromTheFrameworkWhileRingingDeclines() = rig {
        val added = ringing()
        runBlockingCallback(added.onDisconnect)
        added.control.ended.complete(Unit)
        assertTrue("reject $INCOMING 603" in sip.asked, sip.asked.toString())
        waitFor { bridge.calls.value.isEmpty() || phase() == TelecomPhase.ENDED }
        Thread.sleep(50)
        assertFalse("disconnect" in added.control.asked, "the framework ended it, and is not told again")
    }

    @Test
    fun aHoldFromTheFrameworkHoldsTheSipCallWithoutAskingTheFrameworkBack() = rig {
        val (_, added) = connected()
        runBlockingCallback(added.onSetInactive)
        assertEquals(phase(), TelecomPhase.HELD)
        runBlockingCallback(added.onSetActive)
        assertEquals(phase(), TelecomPhase.ACTIVE)
        Thread.sleep(50)
        assertEquals(added.control.asked, listOf("setActive"))
        assertEquals(sip.asked.filter { it.startsWith("hold") || it.startsWith("resume") }, listOf("hold $OUTGOING", "resume $OUTGOING"))
    }

    @Test
    fun aCallTheFrameworkWillNotAddIsRefused() = rig {
        adder.refuseAdding = true
        invite()
        waitFor { "reject $INCOMING 486" in sip.asked }
        assertTrue(reports.any { it.contains("not added") }, reports.toString())
        bridge.placeCall(ACCOUNT, "sip:bob@example.invalid")
        waitFor { bridge.calls.value.none { it.caller == "sip:bob@example.invalid" } }
        assertFalse(sip.asked.any { it.startsWith("place") }, "nothing is sent for a call the framework refused")
    }

    @Test
    fun aCallTheLibraryWillNotPlaceIsDisconnectedAndItsReasonHeard() = rig {
        val heard = CopyOnWriteArrayList<TelecomPlaceFailure>()
        bridge.placeFailed = { heard += it }
        sip.placeRefusal = SipralException(SipralStatus.INVALID_ARGUMENT, "the target is not a SIP or tel URI")
        val id = bridge.placeCall(ACCOUNT, "*43")
        waitFor { heard.isNotEmpty() && adder.added.singleOrNull()?.control?.ended?.isCompleted == true }
        assertEquals(heard.single().id, id)
        assertEquals(heard.single().target, "*43")
        assertEquals(heard.single().reason, "INVALID_ARGUMENT: the target is not a SIP or tel URI")
        assertEquals(adder.added.single().control.asked, listOf("disconnect"))
        assertTrue(bridge.calls.value.isEmpty())
    }

    @Test
    fun aRefusedAnswerEndsTheCallOnBothSides() = rig {
        adder.refuse = setOf("answer")
        val added = ringing()
        bridge.answer(bridge.calls.value.single().id)
        event(SipralEventKind.CALL_CONFIRMED, INCOMING)
        waitFor { "hangup $INCOMING" in sip.asked && "disconnect" in added.control.asked }
        assertTrue(reports.any { it.contains("active refused") }, reports.toString())
    }

    @Test
    fun aRefusedResumeHoldsTheSipCallAgain() = rig {
        val (id, added) = connected()
        bridge.hold(id)
        waitFor { "setInactive" in added.control.asked }
        added.control.refuse = setOf("setActive")
        bridge.unhold(id)
        // the bridge publishes once its entry point returns, after the SIP request
        waitFor { sip.asked.count { it == "hold $OUTGOING" } == 2 && phase() == TelecomPhase.HELD }
        Thread.sleep(50)
        assertEquals(added.control.asked, listOf("setActive", "setInactive", "setActive"))
    }

    @Test
    fun aSessionTornDownByTheFrameworkHangsUp() = rig {
        val (_, added) = connected()
        added.control.ended.complete(Unit)
        waitFor { "hangup $OUTGOING" in sip.asked }
        assertFalse("disconnect" in added.control.asked)
    }

    @Test
    fun routesAndMuteAreTheScopesAndARouteIsRequestedThroughIt() = rig {
        val (id, added) = connected()
        val earpiece = CallEndpointCompat("Earpiece", CallEndpointCompat.TYPE_EARPIECE, ParcelUuid(UUID(0, 2)))
        val speaker = CallEndpointCompat("Speaker", CallEndpointCompat.TYPE_SPEAKER, ParcelUuid(UUID(0, 3)))
        val headset = CallEndpointCompat("Headset", CallEndpointCompat.TYPE_BLUETOOTH, ParcelUuid(UUID(0, 4)))
        added.control.offered.value = listOf(earpiece, speaker, headset)
        added.control.current.value = earpiece
        waitFor { SipralTelecom.callRoutes.value[id]?.routes?.value?.size == 3 }
        val routes = SipralTelecom.callRoutes.value.getValue(id)
        assertEquals(routes.routes.value.map { it.kind }, listOf(AudioRoute.Kind.EARPIECE, AudioRoute.Kind.SPEAKER, AudioRoute.Kind.BLUETOOTH))
        waitFor { routes.route.value?.kind == AudioRoute.Kind.EARPIECE }
        routes.requestRoute(routes.routes.value[1])
        waitFor { "endpoint Speaker" in added.control.asked }
        added.control.current.value = speaker
        waitFor { routes.route.value?.kind == AudioRoute.Kind.SPEAKER }
        assertFalse(routes.muted.value)
        added.control.mute.value = true
        waitFor { routes.muted.value }
        event(SipralEventKind.CALL_ENDED, OUTGOING)
        waitFor { SipralTelecom.callRoutes.value[id] == null }
        assertNull(SipralTelecom.callRoutes.value[id])
    }

    @Test
    fun everyCauseIsOneTheTransactionalDisconnectTakes() {
        val allowed = setOf(DisconnectCause.LOCAL, DisconnectCause.REMOTE, DisconnectCause.REJECTED, DisconnectCause.MISSED)
        for (cause in TelecomDisconnect.entries) {
            assertTrue(disconnectCodeOf(cause) in allowed, "$cause")
        }
        assertEquals(disconnectCodeOf(TelecomDisconnect.REJECTED), DisconnectCause.REJECTED)
        assertEquals(disconnectCodeOf(TelecomDisconnect.MISSED), DisconnectCause.MISSED)
        assertEquals(disconnectCodeOf(TelecomDisconnect.BUSY), DisconnectCause.REMOTE)
    }

    @Test
    fun coreTelecomIsPreferredFromAndroid14() {
        assertEquals(SipralTelecomAdapter.preferred(26), SipralTelecomAdapter.CONNECTION_SERVICE)
        assertEquals(SipralTelecomAdapter.preferred(33), SipralTelecomAdapter.CONNECTION_SERVICE)
        assertEquals(SipralTelecomAdapter.preferred(34), SipralTelecomAdapter.CORE_TELECOM)
        assertEquals(SipralTelecomAdapter.preferred(37), SipralTelecomAdapter.CORE_TELECOM)
    }

}

private const val ACCOUNT = 7L
private const val INCOMING = 5L
private const val OUTGOING = 42L

/** A framework callback, run to its end as the framework would before its
 * five seconds are up. */
private fun runBlockingCallback(callback: suspend () -> Unit) {
    runBlocking { callback() }
}

private fun waitFor(condition: () -> Boolean) {
    val deadline = System.currentTimeMillis() + 5000
    while (!condition()) {
        assertTrue(System.currentTimeMillis() < deadline, "timed out")
        Thread.sleep(2)
    }
}
