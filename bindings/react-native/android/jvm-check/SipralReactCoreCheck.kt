// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// The Android half of the React Native package, without React Native: three
// SipralReactCores on loopback, driven by the handles and options
// JavaScript would hand them, with every event read back as the flattened
// map the bridge would emit. A call placed, answered, held, resumed, sent
// digits, transferred to a third phone that answers, a second call turned
// away, and a client closed. Compiled with bindings/kotlin by
// scripts/check.sh and run on a JVM under -Xcheck:jni.

package org.sipral.reactnative.core

import java.util.Collections
import kotlin.system.exitProcess
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.sipral.idiomatic.SipralAudioMode

private class Phone(name: String) {
    val events: MutableList<Map<String, Any>> = Collections.synchronizedList(ArrayList())
    val core = SipralReactCore(emit = { events += it }, audio = { SipralAudioMode.Application })
    val address = core.open(SipralOpenOptions(bindHost = "127.0.0.1"))
    val aor = "sip:$name@sipral.invalid"

    /** The first event, from the [after]th on, that [matches] -- or a failure naming what was seen. */
    fun await(what: String, after: Int = 0, withinMs: Long = 15_000, matches: (Map<String, Any>) -> Boolean): Map<String, Any> {
        val deadline = System.currentTimeMillis() + withinMs
        while (System.currentTimeMillis() < deadline) {
            synchronized(events) { events.drop(after).firstOrNull(matches) }?.let { return it }
            Thread.sleep(10)
        }
        throw AssertionError("$aor never saw $what; saw ${synchronized(events) { events.map { it["kind"] } }}")
    }

    fun seen(): Int = events.size
}

private fun refusal(code: String, block: () -> Unit) {
    val refused = assertFailsWith<SipralRefusal> { block() }
    assertEquals(code, refused.code, refused.message)
}

private fun everything(): String {
    val alice = Phone("alice")
    val bob = Phone("bob")
    val carol = Phone("carol")
    try {
        refusal("wrongState") { alice.core.open(SipralOpenOptions(bindHost = "127.0.0.1")) }
        refusal("invalidArgument") { bob.core.addAccount(SipralAccountOptions(aor = "not a uri", registrarAddress = "x")) }
        val aliceLine = alice.core.addAccount(SipralAccountOptions(aor = alice.aor, registrarAddress = bob.address))
        bob.core.addAccount(SipralAccountOptions(aor = bob.aor, registrarAddress = carol.address))
        carol.core.addAccount(SipralAccountOptions(aor = carol.aor, registrarAddress = bob.address))
        refusal("invalidHandle") { alice.core.register("424242") }

        // Placed, rung, answered once.
        val toBob = alice.core.placeCall(aliceLine, "sip:bob@${bob.address}", destination = null, codecs = null)
        val rang = bob.await("the incoming call") { it["kind"] == "incomingCall" }
        val fromAlice = rang["call"] as String
        assertEquals(alice.aor, (rang["fromUri"] as String).removePrefix("<").removeSuffix(">").substringBefore(';'))
        assertEquals("incoming", rang["callState"])
        refusal("invalidHandle") { bob.core.hold(fromAlice) }
        bob.core.answer(fromAlice)
        refusal("wrongState") { bob.core.answer(fromAlice) }
        val confirmed = alice.await("the call confirmed") { it["kind"] == "callConfirmed" && it["call"] == toBob }
        assertEquals("confirmed", confirmed["callState"])

        // Held, resumed.
        var mark = alice.seen()
        alice.core.hold(toBob)
        alice.await("the hold", mark) { it["kind"] == "sessionChanged" && it["heldHere"] == true }
        mark = alice.seen()
        alice.core.resume(toBob)
        alice.await("the resume", mark) { it["kind"] == "sessionChanged" && it["heldHere"] == false }

        // Digits, read back one by one on Bob's side.
        mark = bob.seen()
        alice.core.sendDtmf(toBob, "5#")
        bob.await("the 5", mark) { it["kind"] == "digitReceived" && it["digit"] == "5" }
        bob.await("the #", mark) { it["kind"] == "digitReceived" && it["digit"] == "#" }
        refusal("invalidArgument") { alice.core.sendDtmf(toBob, "5x") }

        // A blind transfer, taken by Bob, answered by Carol, reported to Alice.
        val target = "sip:carol@${carol.address}"
        alice.core.transfer(toBob, target)
        val asked = bob.await("the transfer request") { it["kind"] == "transferRequested" }
        assertEquals(fromAlice, asked["call"])
        assertEquals(target, asked["target"])
        assertEquals(false, asked["attended"])
        val toCarol = bob.core.acceptTransfer(fromAlice)
        refusal("wrongState") { bob.core.acceptTransfer(fromAlice) }
        val ringing = carol.await("the transferred call") { it["kind"] == "incomingCall" }
        carol.core.answer(ringing["call"] as String)
        val done = alice.await("the transfer's outcome") { it["kind"] == "transferDone" && it["call"] == toBob }
        assertTrue((done["statusCode"] as Int) in 200..299, "the transfer ended ${done["statusCode"]}")

        // The transferred leg ends when the transfer has worked; its handle goes with it.
        val ended = alice.await("the transferred call's end") { it["kind"] == "callEnded" && it["call"] == toBob }
        assertEquals("localHangup", ended["endReason"])
        refusal("invalidHandle") { alice.core.hold(toBob) }
        bob.core.hangup(toCarol)
        carol.await("the end of the call Bob placed") { it["kind"] == "callEnded" }

        // A second call, turned away with a final response.
        val second = alice.core.placeCall(aliceLine, "sip:bob@${bob.address}", destination = null, codecs = null)
        mark = bob.seen()
        val again = bob.await("the second call", mark) { it["kind"] == "incomingCall" && it["call"] != fromAlice }
        bob.core.reject(again["call"] as String, 486)
        val refused = alice.await("the refusal") { it["kind"] == "callEnded" && it["call"] == second }
        assertEquals("refused", refused["endReason"])
        assertEquals(486, refused["statusCode"])

        // Every map is the spec's shape: a camel-case kind, handles as strings.
        for (event in alice.events.toList()) {
            val kind = event["kind"] as String
            assertTrue(kind.isNotEmpty() && kind[0].isLowerCase() && '_' !in kind, "kind $kind")
            assertTrue(event["call"] is String && event["account"] is String && event["kindName"] is String)
        }

        alice.core.close()
        refusal("closed") { alice.core.addAccount(SipralAccountOptions(aor = alice.aor, registrarAddress = bob.address)) }
        return "three cores on loopback: placed, answered, held and resumed, \"5#\" read back, " +
            "transferred to a third that answered (${done["statusCode"]}), a second call refused 486, closed"
    } finally {
        alice.core.close()
        bob.core.close()
        carol.core.close()
    }
}

/**
 * What ABI 0.34 brought to the module: a client opened with no address
 * advertises the route toward its server -- loopback here -- an account named
 * by a URI is located and the event flattened with where, the options reach
 * the library (an SRTP policy and a salt it refuses are refused), and the
 * diagnostic trace is turned on.
 */
private fun reachability(): String {
    val events: MutableList<Map<String, Any>> = Collections.synchronizedList(ArrayList())
    val core = SipralReactCore(emit = { events += it }, audio = { SipralAudioMode.Application })
    try {
        refusal("invalidArgument") { core.open(SipralOpenOptions(srtp = "sometimes")) }
        refusal("invalidArgument") { core.open(SipralOpenOptions(pseudonymSalt = "0g")) }
        refusal("invalidArgument") { core.open(SipralOpenOptions(pseudonymSalt = "0011")) }
        val address = core.open(
            SipralOpenOptions(
                srtp = "bestEffort", srtpSuites = "AES_CM_128_HMAC_SHA1_80", pathMtu = 1500,
                datagramWithoutStreamBytes = 4000, pseudonymSalt = "00112233445566778899aabbccddeeff",
                diagnosticTrace = false,
            ),
        )
        assertTrue(address.startsWith("127.0.0.1:"), address)
        core.setDiagnosticTrace(true)
        refusal("invalidArgument") { core.addAccount(SipralAccountOptions(aor = "sip:alice@sipral.invalid")) }
        val line = core.addAccount(
            SipralAccountOptions(
                aor = "sip:alice@sipral.invalid", registrar = "sip:sipral.invalid", serverUri = "sip:localhost:5999",
                keepaliveMs = 15_000,
            ),
        )
        core.register(line)
        val deadline = System.currentTimeMillis() + 10_000
        var located: Map<String, Any>? = null
        while (located == null && System.currentTimeMillis() < deadline) {
            located = synchronized(events) { events.firstOrNull { it["kind"] == "located" } }
            Thread.sleep(10)
        }
        val targets = (located ?: throw AssertionError("never located; saw ${events.map { it["kind"] }}"))["targets"] as String
        assertTrue("127.0.0.1:5999" in targets.split(','), targets)
        assertEquals(line, located["account"])
    } finally {
        core.close()
    }
    return "a core opened with no address advertises the route, an account named by a URI is located, " +
        "and the 0.34 options and the diagnostic trace reach the library"
}

fun main() {
    val said = try {
        everything() + "; " + reachability()
    } catch (failure: Throwable) {
        failure.printStackTrace()
        exitProcess(1)
    }
    println("react native core: $said")
    exitProcess(0)
}
