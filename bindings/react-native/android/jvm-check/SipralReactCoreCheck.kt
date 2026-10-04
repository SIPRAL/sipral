// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The Android half of the React Native package, without React Native: three
// SipralReactCores on loopback, driven by the handles and options
// JavaScript would hand them, with every event read back as the flattened
// map the bridge would emit. A call placed, answered, held, resumed, sent
// digits, transferred to a third phone that answers, a second call turned
// away, and a client closed. Compiled with bindings/kotlin by
// scripts/check.sh and run on a JVM under -Xcheck:jni.

package org.sipral.reactnative.core

import java.net.InetAddress
import java.net.ServerSocket
import java.util.Collections
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.sipral.Sipral
import org.sipral.SipralAudioActivation
import org.sipral.SipralChallengeRefusal
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.idiomatic.SipralAudioMode

private class Phone(name: String, mode: SipralAudioMode = SipralAudioMode.Application) {
    val events: MutableList<Map<String, Any>> = Collections.synchronizedList(ArrayList())
    val core = SipralReactCore(emit = { events += it }, audio = { mode })
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
        assertTrue(waitUntil { alice.core.keptCalls == 0 }, "a call that ended is still kept")

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

private fun waitUntil(withinMs: Long = 5_000, probe: () -> Boolean): Boolean {
    val deadline = System.currentTimeMillis() + withinMs
    while (!probe()) {
        if (System.currentTimeMillis() > deadline) {
            return false
        }
        Thread.sleep(10)
    }
    return true
}

private class Closed : AutoCloseable {
    @Volatile
    var closed = false

    override fun close() {
        closed = true
    }
}

/**
 * A call whose end went by before it was kept is closed, not kept; one kept
 * first is closed by its end; and the ends remembered for calls never kept
 * are bounded.
 */
private fun aCallThatEndedBeforeItWasKeptIsClosed(): String {
    val book = SipralCallBook<Closed>()
    val early = Closed()
    book.ended("1")
    assertFalse(book.keep("1", early, ended = false), "a call kept after its end")
    assertTrue(early.closed)
    assertEquals(0, book.size)

    val told = Closed()
    assertFalse(book.keep("2", told, ended = true))
    assertTrue(told.closed)

    val usual = Closed()
    assertTrue(book.keep("3", usual, ended = false))
    assertEquals(1, book.size)
    assertFalse(usual.closed)
    book.ended("3")
    assertTrue(usual.closed)
    assertEquals(0, book.size)

    for (never in 0 until SipralCallBook.REMEMBERED + 10) {
        book.ended("never-$never")
    }
    val oldest = Closed()
    assertTrue(book.keep("never-0", oldest, ended = false), "an end older than the bound was still remembered")
    val recent = Closed()
    assertFalse(book.keep("never-${SipralCallBook.REMEMBERED + 9}", recent, ended = false))
    book.closeAll()
    assertTrue(oldest.closed)
    return "a call that ended before it was kept was closed, and remembered ends are bounded"
}

/** ABI 0.35: an account on a TCP connection of its own, beside the UDP
 * socket, registers over a connection the core opened; a protocol that is
 * neither is refused; and the settings come back as the spec's
 * NativeSettings, the echo switch among them. */
private fun anAccountOnAConnectionOfItsOwnAndTheSettingsReadBack(): String {
    ServerSocket(0, 4, InetAddress.getLoopbackAddress()).use { registrar ->
        val register = CompletableFuture.supplyAsync {
            registrar.accept().use { connection ->
                connection.soTimeout = 10_000
                val held = StringBuilder()
                val buffer = ByteArray(4096)
                while (!held.contains("\r\n\r\n")) {
                    val read = connection.getInputStream().read(buffer)
                    if (read < 0) break
                    held.append(String(buffer, 0, read, Charsets.UTF_8))
                }
                held.toString()
            }
        }
        val core = SipralReactCore(emit = { }, audio = { SipralAudioMode.Application })
        try {
            core.open(
                SipralOpenOptions(
                    bindHost = "127.0.0.1", systemEchoCancellation = false,
                    srtpSuites = "AES_CM_128_HMAC_SHA1_32,AES_CM_128_HMAC_SHA1_80",
                ),
            )
            val address = "127.0.0.1:${registrar.localPort}"
            refusal("invalidArgument") {
                core.addAccount(SipralAccountOptions(aor = "sip:alice@sipral.invalid", registrarAddress = address, streamProtocol = "sctp"))
            }
            val line = core.addAccount(
                SipralAccountOptions(
                    aor = "sip:alice@sipral.invalid", registrar = "sip:sipral.invalid", registrarAddress = address,
                    streamProtocol = "tcp",
                ),
            )
            core.register(line)
            val message = register.get(10, TimeUnit.SECONDS)
            assertTrue(message.startsWith("REGISTER "), message)
            assertTrue("Via: SIP/2.0/TCP " in message, message)
            assertTrue(";transport=tcp" in message, message)
            val settings = core.settings()
            assertEquals("udp", settings["transport"])
            assertEquals("2,1", settings["srtpSuites"])
            assertEquals(false, settings["systemEchoCancellation"])
            assertEquals(false, settings["pseudonymSalted"])
            assertTrue((settings["codecCount"] as Int) > 0)
        } finally {
            core.close()
        }
    }
    return "an account on a TCP connection of its own registered over it, and the settings read back"
}

/** A call's own gain and mute through the core, on a client in device mode
 * whose devices stay closed under manual activation; a direction that is
 * neither is refused, and so is a core in application mode. */
private fun aCallsOwnAudioIsSetAndReadBack(): String {
    if (Sipral.capabilities().features and Sipral.FEATURE_AUDIO_DEVICE == 0L) {
        return "no audio engine in this build for a call's own audio"
    }
    val alice = Phone("alice", SipralAudioMode.Device(SipralAudioActivation.MANUAL))
    val bob = Phone("bob")
    try {
        val line = alice.core.addAccount(SipralAccountOptions(aor = alice.aor, registrarAddress = bob.address))
        bob.core.addAccount(SipralAccountOptions(aor = bob.aor, registrarAddress = alice.address))
        val call = alice.core.placeCall(line, "sip:bob@${bob.address}", destination = null, codecs = null)
        val rang = bob.await("the incoming call") { it["kind"] == "incomingCall" }
        val taken = rang["call"] as String
        bob.core.answer(taken)
        alice.await("the media") { it["kind"] == "mediaStarted" && it["call"] == call }
        assertTrue(
            waitUntil { runCatching { alice.core.setCallGain(call, "output", 0.5) }.isSuccess },
            "the engine never took the call's media",
        )
        alice.core.setCallMuted(call, "input", true)
        val output = alice.core.callAudio(call, "output")
        assertEquals(0.5, output["gain"])
        assertEquals(false, output["muted"])
        assertEquals(0.0, output["level"])
        assertEquals(true, alice.core.callAudio(call, "input")["muted"])
        refusal("invalidArgument") { alice.core.setCallMuted(call, "sideways", true) }
        refusal("notSupported") { bob.core.setCallGain(taken, "output", 1.0) }
    } finally {
        alice.core.close()
        bob.core.close()
    }
    return "a call's own gain and mute set and read back"
}

/** An action after the worker was shut down is rejected as closed rather
 * than thrown at its caller; the close itself runs after what was queued. */
/** The realms an account names and what a held party is sent reach the
 * library through the core, a value of neither the core knows refused before
 * it, and a declined challenge flattened with its refusal, server and realms. */
private fun theRealmsAndTheHeldAudioReachTheLibrary(): String {
    val refused = SipralReactCore(emit = { }, audio = { SipralAudioMode.Application })
    refusal("invalidArgument") {
        refused.open(SipralOpenOptions(bindHost = "127.0.0.1", heldAudio = "music"))
    }
    val core = SipralReactCore(emit = { }, audio = { SipralAudioMode.Application })
    try {
        core.open(SipralOpenOptions(bindHost = "127.0.0.1", heldAudio = "application"))
        core.addAccount(
            SipralAccountOptions(
                aor = "sip:alice@sipral.invalid", registrarAddress = "127.0.0.1:5060",
                authUser = "alice", authPassword = "open sesame", realms = "registrar.example\nsbc, inc.",
            ),
        )
        refusal("invalidArgument") {
            core.addAccount(
                SipralAccountOptions(
                    aor = "sip:bob@sipral.invalid", registrarAddress = "127.0.0.1:5060",
                    realms = "registrar.example\nsbc\texample",
                ),
            )
        }
    } finally {
        core.close()
    }
    val flat = SipralReactCore.flatten(
        SipralEvent(
            size = 0,
            stack = 0,
            kind = SipralEventKind.CHALLENGE_DECLINED.value.toLong(),
            account = 7,
            call = 0,
            message = null,
            payloadChallengeServer = "203.0.113.9:5060",
            payloadChallengeRealms = "sbc.example\ncallee, inc.",
            payloadChallengeNumbers = longArrayOf(SipralChallengeRefusal.NOT_THE_ACCOUNTS_REALM.value.toLong()),
        ),
    )
    assertEquals("challengeDeclined", flat["kind"])
    assertEquals("7", flat["account"])
    assertEquals("notTheAccountsRealm", flat["challengeRefusal"])
    assertEquals("203.0.113.9:5060", flat["challengeServer"])
    assertEquals("sbc.example\ncallee, inc.", flat["challengeRealms"])
    return "the realms and the held audio reached the library, and a declined challenge was flattened"
}

private fun aSettleAfterShutdownIsRejectedNotThrown(): String {
    val worker = SipralWorker("sipral-react-native-check")
    val outcomes = Collections.synchronizedList(ArrayList<String>())
    worker.settle({ outcomes += "resolved $it" }, { code, _, _ -> outcomes += "rejected $code" }) { "first" }
    worker.settle({ outcomes += "resolved $it" }, { code, _, _ -> outcomes += "rejected $code" }) {
        throw SipralRefusal("wrongState", "no")
    }
    worker.shutdown { outcomes += "closed" }
    worker.settle({ outcomes += "resolved $it" }, { code, _, _ -> outcomes += "rejected $code" }) { "late" }
    worker.shutdown { outcomes += "closed twice" }
    assertTrue(waitUntil { outcomes.size >= 4 }, "saw $outcomes")
    assertEquals("rejected closed", outcomes.first { it.startsWith("rejected c") })
    assertEquals(listOf("resolved first", "rejected wrongState", "closed"), outcomes.filter { it != "rejected closed" })
    return "a settle after the module was invalidated was rejected as closed"
}

/** maxDialogs reaches the library through the core: at a ceiling of one
 * call, a second placed while the first still rings is refused as
 * limitReached. */
private fun aCallPlacedPastMaxDialogsIsRefused(): String {
    val capped = SipralReactCore(emit = { }, audio = { SipralAudioMode.Application })
    val bob = Phone("bob")
    try {
        val address = capped.open(SipralOpenOptions(bindHost = "127.0.0.1", maxDialogs = 1))
        val line = capped.addAccount(SipralAccountOptions(aor = "sip:capped@sipral.invalid", registrarAddress = bob.address))
        bob.core.addAccount(SipralAccountOptions(aor = bob.aor, registrarAddress = address))
        capped.placeCall(line, "sip:bob@${bob.address}", destination = null, codecs = null)
        bob.await("the first call") { it["kind"] == "incomingCall" }
        refusal("limitReached") { capped.placeCall(line, "sip:bob@${bob.address}", destination = null, codecs = null) }
    } finally {
        capped.close()
        bob.core.close()
    }
    return "a call placed past maxDialogs was refused"
}

/** The check the Kotlin layer under this module makes at load keeps the 1.x
 * rule, and a refusal of it reaches JavaScript as `unsupportedVersion`
 * naming the caller's version: within this major every minor up to the
 * library's own is served -- a binding the library is newer than -- and a
 * later minor, another major or any 0.x is refused. */
private fun theAbiCheckKeepsTheOneXRule(): String {
    val library = Sipral.abiVersion()
    assertEquals(Sipral.ABI_VERSION_MAJOR, library.major)
    assertTrue(library.minor >= Sipral.ABI_VERSION_MINOR, "library minor ${library.minor}")
    for (minor in 0L..library.minor) {
        SipralReactCore.guarded { Sipral.abiCheck(library.major, minor) }
    }
    for ((major, minor) in listOf(library.major to library.minor + 1, library.major + 1 to 0L, 0L to 36L)) {
        val refused = assertFailsWith<SipralRefusal>("$major.$minor was served") {
            SipralReactCore.guarded { Sipral.abiCheck(major, minor) }
        }
        val sentence = refused.message.orEmpty()
        assertEquals("unsupportedVersion", refused.code, sentence)
        assertTrue(sentence.contains("$major.$minor"), sentence)
    }
    return "the ABI check served ${library.major}.0 to ${library.major}.${library.minor} and refused a later minor, " +
        "another major and 0.36"
}

fun main() {
    val said = try {
        everything() + "; " + reachability() + "; " + aCallThatEndedBeforeItWasKeptIsClosed() + "; " +
            aSettleAfterShutdownIsRejectedNotThrown() + "; " + anAccountOnAConnectionOfItsOwnAndTheSettingsReadBack() +
            "; " + aCallsOwnAudioIsSetAndReadBack() + "; " + theRealmsAndTheHeldAudioReachTheLibrary() + "; " +
            aCallPlacedPastMaxDialogsIsRefused() + "; " + theAbiCheckKeepsTheOneXRule()
    } catch (failure: Throwable) {
        failure.printStackTrace()
        exitProcess(1)
    }
    println("react native core: $said")
    exitProcess(0)
}
