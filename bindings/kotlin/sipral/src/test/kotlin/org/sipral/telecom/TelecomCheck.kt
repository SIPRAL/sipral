// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// The ConnectionService helper's logic, on a plain JVM with no Android in
// it: TelecomBridge driven through recording fakes of the telecom framework
// and of the SIP side, one sequence per race docs/15-mobile.md names, and
// then once more end to end over two real SipralClients on loopback --
// a push announced, the INVITE that follows matched to it, answered, held
// both ways, sent a digit and hung up, with only the telecom framework
// faked. Compiled and run by scripts/check.sh beside IdiomaticCheck.kt.

package org.sipral.telecom

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.system.exitProcess
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralStatus
import org.sipral.idiomatic.SipralAnnounced
import org.sipral.idiomatic.SipralClient

fun main() {
    val said = try {
        val fakes = fakeSequences()
        val real = runBlocking { overLoopback() }
        "$fakes; $real"
    } catch (failure: Throwable) {
        failure.printStackTrace()
        exitProcess(1)
    }
    println("kotlin telecom: $said")
    exitProcess(0)
}

// -- the fakes ------------------------------------------------------------

/** Everything every fake was asked, in one order, so that "reported before
 * announced" is a comparison of two indices. */
private class Log {
    val lines = mutableListOf<String>()

    @Synchronized
    fun add(line: String) {
        lines.add(line)
    }

    @Synchronized
    fun snapshot(): List<String> = lines.toList()

    fun indexOf(prefix: String): Int = snapshot().indexOfFirst { it.startsWith(prefix) }

    fun count(prefix: String): Int = snapshot().count { it.startsWith(prefix) }
}

private class FakePlatform(val log: Log) : TelecomPlatform {
    var bridge: TelecomBridge? = null
    val connections = mutableMapOf<String, FakeConnection>()

    /** What the framework does on a real device: create the connection
     * for the id it was given. Left to the test to call, since on a device
     * it happens later, on another thread. */
    fun create(id: String): FakeConnection {
        val connection = FakeConnection(id, log)
        connections[id] = connection
        bridge!!.connectionCreated(id, connection)
        return connection
    }

    /** The framework refusing every call, as Android does for an account
     * it does not know. */
    var refuse = false

    override fun reportIncomingCall(id: String, caller: String, displayName: String?) {
        log.add("report $id $caller")
        if (refuse) {
            throw SecurityException("no such PhoneAccount")
        }
    }

    override fun placeOutgoingCall(id: String, target: String) {
        log.add("place-request $id $target")
    }
}

private class FakeConnection(val id: String, val log: Log) : TelecomConnection {
    @Volatile var state = "new"

    @Volatile var farEndHolding = false

    @Volatile var cause: TelecomDisconnect? = null

    override fun setRinging() {
        state = "ringing"; log.add("conn $id ringing")
    }

    override fun setDialing() {
        state = "dialing"; log.add("conn $id dialing")
    }

    override fun setActive() {
        state = "active"; log.add("conn $id active")
    }

    override fun setOnHold() {
        state = "held"; log.add("conn $id held")
    }

    override fun setRemoteHold(held: Boolean) {
        farEndHolding = held; log.add("conn $id remote-hold $held")
    }

    override fun setDisconnected(cause: TelecomDisconnect) {
        state = "disconnected"; this.cause = cause; log.add("conn $id disconnected $cause")
    }
}

private class FakeSip(val log: Log) : SipCalls {
    var nextAnnounce: SipralAnnounced = SipralAnnounced.Waiting(100)
    var announceFails = false
    var forgetCrosses = false
    var nextCall = 500L
    var hold: Pair<Boolean, Boolean> = false to false

    override fun announce(account: Long, caller: String): SipralAnnounced {
        log.add("announce $account $caller")
        if (announceFails) {
            throw SipralException(SipralStatus.STALE_HANDLE, "no such account")
        }
        val answer = nextAnnounce
        if (answer is SipralAnnounced.Waiting) {
            nextAnnounce = SipralAnnounced.Waiting(answer.announcement + 1)
        }
        return answer
    }

    override fun forgetAnnouncement(announcement: Long) {
        log.add("forget $announcement")
        if (forgetCrosses) {
            throw SipralException(SipralStatus.WRONG_STATE, "already fulfilled")
        }
    }

    override fun answer(call: Long) = log.add("answer $call")
    override fun reject(call: Long, code: Long) = log.add("reject $call $code")
    override fun place(account: Long, target: String): Long {
        log.add("place $account $target")
        return nextCall++
    }

    override fun hangup(call: Long) = log.add("hangup $call")
    override fun hold(call: Long) = log.add("hold $call")
    override fun resume(call: Long) = log.add("resume $call")
    override fun sendDtmf(call: Long, digits: String) = log.add("dtmf $call $digits")
    override fun holdState(call: Long): Pair<Boolean, Boolean> = hold
    override fun release(call: Long) = log.add("release $call")
}

private class Rig {
    val log = Log()
    val platform = FakePlatform(log)
    val sip = FakeSip(log)
    private var ids = 0
    val bridge = TelecomBridge(platform, sip) { "c${++ids}" }.also { platform.bridge = it }
}

private const val ACCOUNT = 7L

private fun event(kind: SipralEventKind, call: Long = 0, account: Long = 0, message: String? = null) = SipralEvent(
    size = 0,
    stack = 1,
    kind = kind.value.toLong(),
    account = account,
    call = call,
    message = message?.toByteArray(Charsets.UTF_8),
)

private fun invite(from: String) =
    "INVITE sip:bob@example.invalid SIP/2.0\r\n" +
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n" +
        "From: $from;tag=1\r\n" +
        "To: <sip:bob@example.invalid>\r\n" +
        "Call-ID: a@192.0.2.1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"

/** The INVITE for [call], as the library queues it when it matched an
 * announcement: CALL_ANNOUNCED first, INCOMING_CALL straight after. */
private fun announcedInvite(bridge: TelecomBridge, call: Long, from: String) {
    bridge.onEvent(event(SipralEventKind.CALL_ANNOUNCED, call = call))
    bridge.onEvent(event(SipralEventKind.INCOMING_CALL, call = call, account = ACCOUNT, message = invite(from)))
}

private fun fakeSequences(): String {
    var ran = 0

    // C2 whole: reported before announced, the INVITE matched to the screen
    // already up rather than reported again, and every framework action
    // carried onto the call.
    Rig().run {
        val id = bridge.pushArrived(ACCOUNT, "sip:alice@example.invalid", "Alice")
        assertTrue(log.indexOf("report $id") in 0 until log.indexOf("announce $ACCOUNT"), "reported after announcing: ${log.snapshot()}")
        val conn = platform.create(id)
        assertEquals("ringing", conn.state)
        announcedInvite(bridge, 900, "\"Alice\" <sip:alice@example.invalid>")
        assertEquals(1, log.count("report"), "the matched INVITE was reported again: ${log.snapshot()}")
        assertEquals(900, bridge.callHandleOf(id))
        bridge.answer(id)
        assertTrue(log.count("answer 900") == 1)
        bridge.onEvent(event(SipralEventKind.CALL_CONFIRMED, call = 900))
        assertEquals("active", conn.state)
        bridge.hold(id)
        assertEquals(1, log.count("hold 900"))
        sip.hold = true to false
        bridge.onEvent(event(SipralEventKind.SESSION_CHANGED, call = 900))
        assertEquals("held", conn.state)
        bridge.unhold(id)
        sip.hold = false to true
        bridge.onEvent(event(SipralEventKind.SESSION_CHANGED, call = 900))
        assertEquals("active", conn.state)
        assertTrue(conn.farEndHolding, "the far end's hold was not passed on")
        sip.hold = false to false
        bridge.onEvent(event(SipralEventKind.SESSION_CHANGED, call = 900))
        assertFalse(conn.farEndHolding)
        bridge.playDtmf(id, '5')
        assertEquals(1, log.count("dtmf 900 5"))
        bridge.disconnect(id)
        assertEquals(1, log.count("hangup 900"))
        assertEquals(TelecomDisconnect.LOCAL, conn.cause)
        bridge.onEvent(event(SipralEventKind.CALL_ENDED, call = 900))
        assertEquals(1, log.count("release 900"))
        assertEquals(1, log.count("conn $id disconnected"), "the framework was told twice")
        assertTrue(bridge.calls.value.isEmpty())
        ran++
    }

    // Answered before the INVITE came: the answer is owed, and given the
    // moment the INVITE is matched.
    Rig().run {
        val id = bridge.pushArrived(ACCOUNT, "sip:alice@example.invalid")
        platform.create(id)
        bridge.answer(id)
        assertEquals(0, log.count("answer"))
        announcedInvite(bridge, 901, "<sip:alice@example.invalid>")
        assertEquals(1, log.count("answer 901"))
        ran++
    }

    // Two calls in quick succession: Carol's INVITE takes Carol's screen
    // even though Bob's was announced first, and Bob's is the one that is
    // missing when the window runs out.
    Rig().run {
        val bob = bridge.pushArrived(ACCOUNT, "sip:bob@example.invalid")
        val carol = bridge.pushArrived(ACCOUNT, "sip:carol@example.invalid")
        val bobConn = platform.create(bob)
        val carolConn = platform.create(carol)
        announcedInvite(bridge, 902, "Carol <sip:carol@EXAMPLE.invalid:5070;transport=udp>")
        assertEquals(902, bridge.callHandleOf(carol))
        assertEquals(0, bridge.callHandleOf(bob))
        bridge.onEvent(event(SipralEventKind.ANNOUNCED_CALL_MISSING))
        assertEquals(TelecomDisconnect.MISSED, bobConn.cause)
        assertEquals(null, carolConn.cause)
        assertEquals(listOf(carol), bridge.calls.value.map { it.id })
        assertEquals("Carol", bridge.calls.value.single().displayName)
        ran++
    }

    // The INVITE beat the push, and the bridge saw it first: one screen,
    // and the push's id is that screen's.
    Rig().run {
        bridge.onEvent(event(SipralEventKind.INCOMING_CALL, call = 903, account = ACCOUNT, message = invite("<sip:alice@example.invalid>")))
        assertEquals(1, log.count("report"))
        val first = bridge.calls.value.single().id
        sip.nextAnnounce = SipralAnnounced.Arrived(903)
        val pushed = bridge.pushArrived(ACCOUNT, "sip:alice@example.invalid")
        assertEquals(first, pushed)
        assertEquals(1, log.count("report"), "a second screen for a call already ringing: ${log.snapshot()}")
        assertEquals(1, log.count("announce"), "the library was not told about the push")
        ran++
    }

    // The INVITE beat the push, and the library saw it first: announce
    // answers Arrived, the push's screen is the call, and the INVITE that
    // reaches the bridge afterwards is not a second call.
    Rig().run {
        sip.nextAnnounce = SipralAnnounced.Arrived(904)
        val id = bridge.pushArrived(ACCOUNT, "sip:alice@example.invalid")
        assertEquals(904, bridge.callHandleOf(id))
        announcedInvite(bridge, 904, "<sip:alice@example.invalid>")
        assertEquals(1, log.count("report"))
        ran++
    }

    // Declined before the INVITE: the announcement is forgotten.
    Rig().run {
        val id = bridge.pushArrived(ACCOUNT, "sip:alice@example.invalid")
        val conn = platform.create(id)
        bridge.reject(id)
        assertEquals(1, log.count("forget 100"))
        assertEquals(TelecomDisconnect.REJECTED, conn.cause)
        assertTrue(bridge.calls.value.isEmpty())
        ran++
    }

    // Declined before the INVITE, but the INVITE was already matched: the
    // forget crosses it, and the INVITE is refused when it arrives rather
    // than reported as a call.
    Rig().run {
        sip.forgetCrosses = true
        val id = bridge.pushArrived(ACCOUNT, "sip:alice@example.invalid")
        platform.create(id)
        bridge.reject(id)
        announcedInvite(bridge, 905, "<sip:alice@example.invalid>")
        assertEquals(1, log.count("reject 905 603"))
        assertEquals(1, log.count("report"))
        bridge.onEvent(event(SipralEventKind.CALL_ENDED, call = 905))
        assertTrue(bridge.calls.value.isEmpty())
        ran++
    }

    // Outgoing: nothing is sent until the framework allows it, and a busy
    // far end says busy.
    Rig().run {
        val id = bridge.placeCall(ACCOUNT, "sip:dave@example.invalid")
        assertEquals(0, log.count("place $ACCOUNT"))
        val conn = platform.create(id)
        assertEquals(1, log.count("place $ACCOUNT sip:dave@example.invalid"))
        assertEquals("dialing", conn.state)
        val call = bridge.callHandleOf(id)
        bridge.onEvent(event(SipralEventKind.CALL_ENDED, call = call, message = "SIP/2.0 486 Busy Here\r\nContent-Length: 0\r\n\r\n"))
        assertEquals(TelecomDisconnect.BUSY, conn.cause)
        ran++
    }

    // The framework refused an incoming call: it is turned away as busy.
    Rig().run {
        bridge.onEvent(event(SipralEventKind.INCOMING_CALL, call = 906, account = ACCOUNT, message = invite("<sip:alice@example.invalid>")))
        bridge.connectionFailed(bridge.calls.value.single().id)
        assertEquals(1, log.count("reject 906 486"))
        ran++
    }

    // A caller who gave up before anybody answered is a missed call.
    Rig().run {
        bridge.onEvent(event(SipralEventKind.INCOMING_CALL, call = 907, account = ACCOUNT, message = invite("<sip:alice@example.invalid>")))
        val conn = platform.create(bridge.calls.value.single().id)
        bridge.onEvent(event(SipralEventKind.CALL_ENDED, call = 907))
        assertEquals(TelecomDisconnect.MISSED, conn.cause)
        ran++
    }

    // An announce that throws takes its screen down rather than leaving it
    // ringing for nothing.
    Rig().run {
        sip.announceFails = true
        val id = bridge.pushArrived(ACCOUNT, "sip:alice@example.invalid")
        assertTrue(bridge.calls.value.none { it.id == id })
        val late = platform.create(id)
        assertEquals(TelecomDisconnect.ERROR, late.cause)
        ran++
    }

    // The framework refuses the screen. A push handler hears why, and nothing
    // is announced; an INVITE nobody can see ring is turned away, without
    // the throw ending the event stream it arrived on.
    Rig().run {
        platform.refuse = true
        assertFailsWith<SecurityException> { bridge.pushArrived(ACCOUNT, "sip:alice@example.invalid") }
        assertEquals(0, log.count("announce"))
        assertTrue(bridge.calls.value.isEmpty())
        bridge.onEvent(event(SipralEventKind.INCOMING_CALL, call = 908, account = ACCOUNT, message = invite("<sip:alice@example.invalid>")))
        assertEquals(1, log.count("reject 908 486"))
        bridge.onEvent(event(SipralEventKind.CALL_ENDED, call = 908))
        assertTrue(bridge.calls.value.isEmpty())
        ran++
    }

    // The matching rule itself.
    assertTrue(sameCaller("sip:alice@example.invalid", "sip:alice@EXAMPLE.INVALID:5060;user=phone"))
    assertTrue(sameCaller("sip:al%69ce@example.invalid", "sips:alice@example.invalid"))
    assertTrue(sameCaller("sip:bob@[2001:db8::1]", "sip:bob@[2001:DB8:0::1]:5061"))
    assertFalse(sameCaller("sip:Alice@example.invalid", "sip:alice@example.invalid"))
    assertFalse(sameCaller("sip:alice@example.invalid", "sip:alice@example.test"))
    assertFalse(sameCaller("sip:alice@example.invalid", "sip:example.invalid"))
    assertTrue(sameCaller("tel:+15550100", "TEL:+15550100"))
    assertEquals(
        CallerId("sip:carol@example.invalid", null),
        callerOf("INVITE sip:x@example.invalid SIP/2.0\r\nf: sip:carol@example.invalid;tag=9\r\n\r\n".toByteArray()),
    )
    assertEquals(
        CallerId("sip:erin@example.invalid", "Erin Q"),
        callerOf("INVITE sip:x@example.invalid SIP/2.0\r\nFrom: \"Erin Q\"\r\n <sip:erin@example.invalid>;tag=2\r\n\r\n".toByteArray()),
    )
    assertEquals(486, statusOf("SIP/2.0 486 Busy Here\r\n\r\n".toByteArray()))
    assertEquals(0, statusOf(invite("<sip:a@example.invalid>").toByteArray()))
    ran++

    return "$ran sequences against fake telecom and SIP sides (push before INVITE, answer before INVITE, " +
        "two callers out of order, INVITE before push both ways, decline crossing a match, busy, refused, missed, " +
        "a framework that will not take the call)"
}

// -- the real thing, with only the telecom framework faked -----------------

/** Wait for [condition], and on a timeout say what every fake was asked,
 * which is most of what there is to know about where the sequence stopped. */
private suspend fun Log.waitFor(what: String, condition: () -> Boolean) {
    try {
        withTimeout(15_000) {
            while (!condition()) {
                delay(20)
            }
        }
    } catch (timeout: Exception) {
        throw AssertionError("timed out waiting for $what; the fakes were asked: ${snapshot()}", timeout)
    }
}

private suspend fun overLoopback(): String {
    val caller = SipralClient.open(bindHost = "127.0.0.1")
    val callee = SipralClient.open(bindHost = "127.0.0.1")
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    try {
        val alice = caller.addAccount(aor = "sip:alice@example.invalid", registrarAddress = callee.bindAddress)
        val bob = callee.addAccount(aor = "sip:bob@example.invalid", registrarAddress = caller.bindAddress)

        val log = Log()
        val platform = FakePlatform(log)
        val sip = IdiomaticSipCalls(callee, listOf(bob), mediaHost = "127.0.0.1")
        val bridge = TelecomBridge(platform, sip)
        platform.bridge = bridge
        bridge.collect(scope, callee.events)

        // A push for a call that will be declined before it arrives: the
        // library forgets the announcement, and nothing is left behind.
        val declined = bridge.pushArrived(bob.handle, "sip:carol@example.invalid")
        val declinedConn = platform.create(declined)
        bridge.reject(declined)
        assertEquals(TelecomDisconnect.REJECTED, declinedConn.cause)
        assertEquals(1, log.count("report"))

        // The push, then the INVITE it announced.
        val id = bridge.pushArrived(bob.handle, "sip:alice@example.invalid", "Alice")
        assertEquals(0L, bridge.callHandleOf(id), "the announce said the INVITE had already arrived")
        val conn = platform.create(id)
        val placed = caller.placeCall(alice, target = "sip:bob@example.invalid")
        log.waitFor("the INVITE to be matched to the push") { bridge.callHandleOf(id) != 0L }
        assertEquals(2, log.count("report"), "the matched INVITE was reported as a second call: ${log.snapshot()}")

        bridge.answer(id)
        placed.waitConfirmed(15_000)
        log.waitFor("the connection to go active") { conn.state == "active" }

        bridge.hold(id)
        log.waitFor("the connection to say held") { conn.state == "held" }
        assertTrue(placed.holdState.second, "the caller does not see itself held")
        bridge.unhold(id)
        log.waitFor("the connection to come off hold") { conn.state == "active" }

        placed.hold()
        log.waitFor("the far end's hold to reach the connection") { conn.farEndHolding }
        placed.resume()
        log.waitFor("the far end's resume to reach the connection") { !conn.farEndHolding }

        // Undispatched, so the subscription to the digits exists before the
        // digit is sent rather than whenever the dispatcher gets round to it.
        val digit = scope.async(start = CoroutineStart.UNDISPATCHED) { withTimeout(15_000) { placed.digits.first() } }
        bridge.playDtmf(id, '7')
        digit.await()

        bridge.disconnect(id)
        assertEquals(TelecomDisconnect.LOCAL, conn.cause)
        placed.waitEnded(15_000)
        log.waitFor("the bridge to let the call go") { bridge.calls.value.isEmpty() }
        assertNotEquals(0, log.count("conn $id active"))
        assertEquals(1, log.count("conn $id disconnected"))
        placed.close()

        return "over loopback, a push announced and its INVITE matched to the same screen, answered, " +
            "held and resumed from each end, a digit sent, hung up and let go"
    } finally {
        scope.cancel()
        try {
            caller.close()
        } catch (_: Exception) {
        }
        try {
            callee.close()
        } catch (_: Exception) {
        }
    }
}
