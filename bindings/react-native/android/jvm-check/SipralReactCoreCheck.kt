// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The React Native package's Android half without React Native: three
// SipralReactCores on loopback, driven with the handles and options
// JavaScript would pass, every event read back as the bridge's map. A call
// placed, answered, held, resumed, sent digits, transferred to a third
// phone, a second call refused, a mailbox subscribed to and one told
// unasked, and a client closed. Built with
// bindings/kotlin by scripts/check.sh and run under -Xcheck:jni.

package org.sipral.reactnative.core

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.SocketAddress
import java.net.SocketTimeoutException
import java.util.Collections
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.sipral.Sipral
import org.sipral.SipralAudioActivation
import org.sipral.SipralChallengeRefusal
import org.sipral.SipralCodec
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralKeyExchange
import org.sipral.SipralNatKind
import org.sipral.SipralNetworkProbe
import org.sipral.SipralNetworkVerdict
import org.sipral.SipralServerReach
import org.sipral.SipralToggle
import org.sipral.SipralTokenError
import org.sipral.idiomatic.SipralAccountSecurity
import org.sipral.idiomatic.SipralAudioMode
import org.sipral.idiomatic.SipralClient
import org.sipral.idiomatic.awaitNext

private class Phone(
    name: String,
    mode: SipralAudioMode = SipralAudioMode.Application,
    host: String = "127.0.0.1",
    codecs: String? = null,
) {
    val events: MutableList<Map<String, Any>> = Collections.synchronizedList(ArrayList())
    val core = SipralReactCore(emit = { events += it }, audio = { mode })
    val address = core.open(SipralOpenOptions(bindHost = host, codecs = codecs))
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

        // A second call, rung, then turned away with a final response.
        val second = alice.core.placeCall(aliceLine, "sip:bob@${bob.address}", destination = null, codecs = null)
        mark = bob.seen()
        val again = bob.await("the second call", mark) { it["kind"] == "incomingCall" && it["call"] != fromAlice }
        bob.core.ring(again["call"] as String)
        alice.await("the 180") { it["kind"] == "callProgress" && it["call"] == second && it["statusCode"] == 180 }
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
 * A client opened with no address advertises the route toward its server
 * (loopback here), a URI-named account is located and the event flattened,
 * options reach the library (a bad SRTP policy or salt is refused), and
 * the diagnostic trace turns on.
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

/** An account on its own TCP connection beside the UDP socket registers
 * over a connection the core opened, with its instance and its own fields
 * on the REGISTER; another protocol is refused; settings come back as
 * NativeSettings, echo switch included. */
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
                    streamProtocol = "tcp", instanceId = "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
                    headers = "X-Push-Key:k-17\nX-Note:a: b",
                ),
            )
            core.register(line)
            val message = register.get(10, TimeUnit.SECONDS)
            assertTrue(message.startsWith("REGISTER "), message)
            assertTrue("Via: SIP/2.0/TCP " in message, message)
            assertTrue(";transport=tcp" in message, message)
            assertTrue("+sip.instance=\"<urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>\"" in message, message)
            assertTrue("\r\nX-Push-Key: k-17\r\n" in message, message)
            assertTrue("\r\nX-Note: a: b\r\n" in message, message)
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
    return "an account on a TCP connection of its own registered over it with its instance and fields, and the settings read back"
}

/** A call's own gain and mute through the core, in device mode with the
 * devices kept closed (manual activation); an unknown direction is
 * refused, as is a core in application mode. */
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

/** Echo cancellation switched through the core in device mode with the
 * devices closed, and read back from settings; application mode has no
 * devices to switch. */
private fun theEchoCancellationIsSwitchedAndReadBack(): String {
    val bob = Phone("bob")
    try {
        refusal("notSupported") { bob.core.setSystemEchoCancellation(false) }
    } finally {
        bob.core.close()
    }
    if (Sipral.capabilities().features and Sipral.FEATURE_AUDIO_DEVICE == 0L) {
        return "no audio engine in this build for the echo cancellation switch"
    }
    val alice = Phone("alice", SipralAudioMode.Device(SipralAudioActivation.MANUAL))
    try {
        alice.core.setSystemEchoCancellation(false)
        assertEquals(false, alice.core.settings()["systemEchoCancellation"])
        alice.core.setSystemEchoCancellation(true)
        assertEquals(true, alice.core.settings()["systemEchoCancellation"])
    } finally {
        alice.core.close()
    }
    return "the echo cancellation switched and read back"
}

/** A call's frame rate chosen through the core in application mode: 24
 * kHz is 480 samples per frame whatever the codec, other rates are refused,
 * and 0 restores the codec's. */
private fun theRateOfACallsFramesIsChosen(): String {
    val alice = Phone("alice")
    val bob = Phone("bob")
    try {
        val line = alice.core.addAccount(SipralAccountOptions(aor = alice.aor, registrarAddress = bob.address))
        bob.core.addAccount(SipralAccountOptions(aor = bob.aor, registrarAddress = alice.address))
        val call = alice.core.placeCall(line, "sip:bob@${bob.address}", destination = null, codecs = null)
        val rang = bob.await("the incoming call") { it["kind"] == "incomingCall" }
        bob.core.answer(rang["call"] as String)
        alice.await("the media") { it["kind"] == "mediaStarted" && it["call"] == call }
        assertTrue(
            waitUntil { runCatching { alice.core.setAppRate(call, 24_000) }.isSuccess },
            "the call's media never came up",
        )
        val chosen = alice.core.setAppRate(call, 24_000)
        assertEquals(24_000, chosen["sampleRate"])
        assertEquals(480, chosen["frameSamples"])
        refusal("invalidArgument") { alice.core.setAppRate(call, 44_100) }
        val codec = alice.core.setAppRate(call, 0)
        assertEquals((codec["sampleRate"] as Int) / 50, codec["frameSamples"])
    } finally {
        alice.core.close()
        bob.core.close()
    }
    return "the rate of a call's frames chosen and read back"
}

/** A call's own codecs through the core, checked at a plain client: placed
 * with PCMA,PCMU it settles on PCMA where the client order would pick Opus;
 * answered with PCMA,PCMU it drops the G.722 the offer put first, since an
 * answer keeps the offer's order. */
private fun aCallsOwnCodecsReachTheLibrary(): String {
    val pcma = SipralCodec.PCMA.value.toLong()
    val alice = Phone("alice")
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { bob ->
        try {
            val line = alice.core.addAccount(SipralAccountOptions(aor = alice.aor, registrarAddress = bob.bindAddress))
            bob.addAccount(aor = "sip:bob@sipral.invalid", registrarAddress = alice.address)
            val (_, incoming) = runBlocking {
                bob.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
                    alice.core.placeCall(line, "sip:bob@${bob.bindAddress}", destination = null, codecs = "PCMA,PCMU")
                }
            }
            bob.answerCall(incoming).use { answered ->
                assertTrue(waitUntil(15_000) { answered.media != null }, "the placed call's media never came up")
                assertEquals(pcma, answered.media!!.info().codec)
            }
        } finally {
            alice.core.close()
        }
    }
    val bob = Phone("bob")
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
        try {
            val line = client.addAccount(aor = "sip:alice@sipral.invalid", registrarAddress = bob.address)
            bob.core.addAccount(SipralAccountOptions(aor = bob.aor, registrarAddress = client.bindAddress))
            client.placeCall(line, target = "sip:bob@${bob.address}", codecs = "G722,PCMA,PCMU").use { placed ->
                val rang = bob.await("the incoming call") { it["kind"] == "incomingCall" }
                bob.core.answer(rang["call"] as String, codecs = "PCMA,PCMU")
                assertTrue(waitUntil(15_000) { placed.media != null }, "the answered call's media never came up")
                assertEquals(pcma, placed.media!!.info().codec)
            }
        } finally {
            bob.core.close()
        }
    }
    return "a call's own codecs settled on PCMA, placed and answered"
}

/** A non-loopback IPv4 address of this machine, since RFC 8445 §5.1.1.1
 * keeps loopback out of ICE's candidates. Nothing leaves the machine. */
private fun hostAddress(): String? = NetworkInterface.getNetworkInterfaces().asSequence()
    .filter { it.isUp && !it.isLoopback && !it.isPointToPoint && !it.isVirtual }
    .flatMap { it.inetAddresses.asSequence() }
    .firstOrNull { it is Inet4Address }
    ?.hostAddress

/** An account the core was told is a PBX WebRTC line offers what one does,
 * and its call is keyed by a handshake on the pair ICE chose. */
private fun aWebRtcLineReachesTheLibrary(): String {
    val host = hostAddress() ?: error("no interface but loopback: ICE has no host candidate to check with")
    // one codec, as the Kotlin layer's own test of the line: the offer with
    // every codec of the default list sits at RFC 3261 §18.1.1's 1300 bytes,
    // and the host address's length alone decides whether it still fits a
    // datagram
    val alice = Phone("alice", host = host, codecs = "PCMU")
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = host, codecs = "PCMU").use { bob ->
        try {
            val line = alice.core.addAccount(
                SipralAccountOptions(aor = alice.aor, registrarAddress = bob.bindAddress, webrtc = true),
            )
            bob.addAccount(
                aor = "sip:bob@sipral.invalid",
                registrarAddress = alice.address,
                security = SipralAccountSecurity(webrtc = true),
            )
            val (_, incoming) = runBlocking {
                bob.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
                    alice.core.placeCall(line, "sip:bob@${bob.bindAddress}", destination = null, codecs = null)
                }
            }
            val offer = String(assertNotNull(incoming.message, "the INVITE rode along"), Charsets.UTF_8)
            for (wanted in listOf("UDP/TLS/RTP/SAVPF", "a=fingerprint:", "a=group:BUNDLE 0", "a=rtcp-mux-only", "a=ice-ufrag:")) {
                assertTrue(offer.contains(wanted), "$wanted is not in the offer:\n$offer")
            }
            bob.answerCall(incoming).use { answered ->
                assertTrue(
                    waitUntil(15_000) { answered.media?.encryption()?.firstOrNull()?.encrypted == true },
                    "the handshake never keyed the call",
                )
                val stream = answered.media!!.encryption().first()
                assertEquals(SipralKeyExchange.DTLS, stream.keyExchange)
                assertTrue(stream.authenticated, "the certificate did not match the fingerprint")
            }
        } finally {
            alice.core.close()
        }
    }
    return "a WebRTC line offered and keyed by a handshake"
}

/** A mailbox's server on a UDP socket on loopback: what reaches it, and the
 * answers and NOTIFYs it sends back. */
private class Mailbox : AutoCloseable {
    private val socket = DatagramSocket(0, InetAddress.getLoopbackAddress()).apply { soTimeout = 50 }
    val address = "127.0.0.1:${socket.localPort}"

    /** The next message that starts with [start] within [withinMs], and
     * where it came from; anything else is let go. */
    fun next(start: String, withinMs: Long = 10_000): Pair<String, SocketAddress>? {
        val deadline = System.currentTimeMillis() + withinMs
        val buffer = ByteArray(65536)
        while (System.currentTimeMillis() < deadline) {
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                socket.receive(packet)
            } catch (_: SocketTimeoutException) {
                continue
            }
            val text = String(packet.data, 0, packet.length, Charsets.UTF_8)
            if (text.startsWith(start)) {
                return text to packet.socketAddress
            }
        }
        return null
    }

    /** A response to [request], its dialog's fields copied and `To` tagged. */
    fun answer(request: Pair<String, SocketAddress>, status: String, more: String = "") {
        val lines = mutableListOf("SIP/2.0 $status")
        for (name in listOf("Via", "From", "To", "Call-ID", "CSeq")) {
            val value = header(name, request.first) ?: continue
            lines += "$name: " + if (name == "To" && ";tag=" !in value) "$value;tag=mailbox" else value
        }
        send(lines.joinToString("\r\n") + "\r\n" + more + "Content-Length: 0\r\n\r\n", request.second)
    }

    /** A `message-summary` NOTIFY to [aor] at [phone]: in the dialog
     * [subscribe] opened, or outside any, the way a PBX that notifies unasked
     * sends it. */
    fun notify(aor: String, phone: String, subscribe: String?) {
        val body = waiting(aor)
        val dialog = if (subscribe != null) {
            "From: ${header("To", subscribe)};tag=mailbox\r\nTo: ${header("From", subscribe)}\r\n" +
                "Call-ID: ${header("Call-ID", subscribe)}\r\n"
        } else {
            "From: <$aor>;tag=mailbox\r\nTo: <$aor>\r\nCall-ID: unasked-${System.nanoTime()}\r\n"
        }
        val user = aor.removePrefix("sip:").substringBefore('@')
        val text = "NOTIFY sip:$user@$phone SIP/2.0\r\n" +
            "Via: SIP/2.0/UDP $address;branch=z9hG4bK-${System.nanoTime()}\r\n" +
            "Max-Forwards: 70\r\n" + dialog +
            "CSeq: 1 NOTIFY\r\n" +
            "Contact: <sip:mailbox@$address>\r\n" +
            "Event: message-summary\r\n" +
            "Subscription-State: active;expires=600\r\n" +
            "Content-Type: application/simple-message-summary\r\n" +
            "Content-Length: ${body.toByteArray().size}\r\n\r\n" + body
        val (host, port) = phone.substringBeforeLast(':') to phone.substringAfterLast(':').toInt()
        send(text, InetSocketAddress(host, port))
    }

    private fun send(text: String, to: SocketAddress) {
        val bytes = text.toByteArray(Charsets.UTF_8)
        socket.send(DatagramPacket(bytes, bytes.size, to))
    }

    override fun close() = socket.close()

    companion object {
        /** Two new messages, one of them urgent, and five old, for [account]. */
        fun waiting(account: String) =
            "Messages-Waiting: yes\r\nMessage-Account: $account\r\nVoice-Message: 2/5 (1/0)\r\n"

        fun header(name: String, message: String): String? = message.substringBefore("\r\n\r\n").split("\r\n")
            .firstOrNull { it.lowercase().startsWith(name.lowercase() + ":") }
            ?.substringAfter(':')?.trim()
    }
}

/** A mailbox subscribed to through the core: the SUBSCRIBE asks for
 * `message-summary`, the NOTIFY is emitted as `messagesWaiting` naming the
 * account and the subscription with every count, and ending it unsubscribes. */
private fun aSubscribedMailboxReachesJavaScript(): String {
    Mailbox().use { server ->
        val alice = Phone("alice")
        try {
            val line = alice.core.addAccount(SipralAccountOptions(aor = alice.aor, registrarAddress = server.address))
            refusal("invalidHandle") { alice.core.subscribeMailbox("424242", alice.aor) }
            val mailbox = alice.core.subscribeMailbox(line, alice.aor, expiresSeconds = 600)
            val subscribe = assertNotNull(server.next("SUBSCRIBE "), "no SUBSCRIBE")
            assertTrue(subscribe.first.startsWith("SUBSCRIBE ${alice.aor} "), subscribe.first)
            assertEquals("message-summary", Mailbox.header("Event", subscribe.first))
            assertEquals("600", Mailbox.header("Expires", subscribe.first))
            server.answer(subscribe, "200 OK", "Expires: 600\r\n")
            server.notify(alice.aor, alice.address, subscribe.first)
            val told = alice.await("the mailbox's state") { it["kind"] == "messagesWaiting" }
            assertEquals(line, told["account"])
            assertEquals(mailbox, told["subscription"])
            assertEquals(true, told["waiting"])
            assertEquals(2.0, told["newMessages"])
            assertEquals(5.0, told["oldMessages"])
            assertEquals(1.0, told["urgentNewMessages"])
            assertEquals(0.0, told["urgentOldMessages"])
            assertEquals(alice.aor, told["messageAccount"])

            alice.core.endSubscription(mailbox)
            val unsubscribe = assertNotNull(server.next("SUBSCRIBE "), "no unsubscribe")
            assertEquals("0", Mailbox.header("Expires", unsubscribe.first))
            refusal("invalidHandle") { alice.core.endSubscription("424242") }
        } finally {
            alice.core.close()
        }
    }
    return "a mailbox subscribed to reported 2 new and 5 old with its account and subscription, and was ended"
}

/** A PBX that notifies unasked (VitalPBX): an account added with
 * `unsolicitedMwi` answers 200 and reports the mailbox with no
 * subscription; one added without answers 481 and reports nothing. */
private fun anUnaskedMailboxReachesOnlyAnAccountThatAllowsIt(): String {
    for (allowed in listOf(true, false)) {
        Mailbox().use { server ->
            val alice = Phone("alice")
            try {
                val line = alice.core.addAccount(
                    SipralAccountOptions(aor = alice.aor, registrarAddress = server.address, unsolicitedMwi = allowed),
                )
                server.notify(alice.aor, alice.address, null)
                val answer = assertNotNull(server.next("SIP/2.0 "), "the NOTIFY was not answered").first
                if (allowed) {
                    assertTrue(answer.startsWith("SIP/2.0 200"), answer)
                    val told = alice.await("the unasked mailbox") { it["kind"] == "messagesWaiting" }
                    assertEquals(line, told["account"])
                    assertEquals("", told["subscription"])
                    assertEquals(true, told["waiting"])
                    assertEquals(2.0, told["newMessages"])
                    assertEquals(5.0, told["oldMessages"])
                    assertEquals(alice.aor, told["messageAccount"])
                } else {
                    assertTrue(answer.startsWith("SIP/2.0 481"), answer)
                    // refused, a second is long enough for an event that should not come
                    val raised = waitUntil(1_000) { synchronized(alice.events) { alice.events.any { it["kind"] == "messagesWaiting" } } }
                    assertFalse(raised, "an account that did not allow it reported an unasked mailbox")
                }
            } finally {
                alice.core.close()
            }
        }
    }
    return "an unasked mailbox reached only an account that allows it, refused 481 otherwise"
}

/** Account realms and held audio reach the library through the core,
 * unknown values are refused first, and a declined challenge is flattened
 * with refusal, server and realms. */
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
    val token = SipralReactCore.flatten(
        SipralEvent(
            size = 0,
            stack = 0,
            kind = SipralEventKind.TOKEN_REQUIRED.value.toLong(),
            account = 7,
            call = 0,
            message = null,
            payloadTokenAuthzServer = "https://as.example.com",
            payloadTokenScope = "sip register",
            payloadTokenRealm = "example.com",
            payloadTokenNumbers = longArrayOf(
                SipralTokenError.INVALID_TOKEN.value.toLong(),
                SipralToggle.ON.value.toLong(),
            ),
        ),
    )
    assertEquals("tokenRequired", token["kind"])
    assertEquals("invalidToken", token["tokenError"])
    assertEquals(true, token["tokenProxy"])
    assertEquals("https://as.example.com", token["tokenAuthzServer"])
    assertEquals("sip register", token["tokenScope"])
    assertEquals("example.com", token["tokenRealm"])
    val tested = SipralReactCore.flatten(
        SipralEvent(
            size = 0,
            stack = 0,
            kind = SipralEventKind.NETWORK_TEST.value.toLong(),
            account = 7,
            call = 0,
            message = null,
            payloadNetworkTestMapped = "203.0.113.7:41002",
            payloadNetworkTestNumbers = longArrayOf(
                4,
                SipralNetworkVerdict.ACCEPTABLE.value.toLong(),
                SipralNetworkProbe.SUCCEEDED.value.toLong(),
                SipralNatKind.PORT_CHANGED.value.toLong(),
                SipralNetworkProbe.NOT_TESTED.value.toLong(),
                0,
                SipralServerReach.ANSWERED.value.toLong(),
                200,
                37,
                SipralNetworkProbe.NOT_TESTED.value.toLong(),
                SipralNetworkVerdict.UNKNOWN.value.toLong(),
                0.0.toRawBits(),
                0.0.toRawBits(),
                0,
                0,
                0,
                0,
                0.0.toRawBits(),
            ),
        ),
    )
    assertEquals("networkTest", tested["kind"])
    assertEquals(4, tested["test"])
    assertEquals("acceptable", tested["verdict"])
    assertEquals("succeeded", tested["stun"])
    assertEquals("portChanged", tested["nat"])
    assertEquals("answered", tested["server"])
    assertEquals(200, tested["serverStatus"])
    assertEquals("203.0.113.7:41002", tested["mapped"])
    return "the realms and the held audio reached the library, and a declined challenge, a token asked for and a network test were flattened"
}

/** An action after the worker shut down is rejected as closed rather than
 * thrown at its caller; the close itself runs after what was queued. */
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

/** maxDialogs reaches the library: with a ceiling of one, a second call
 * placed while the first rings is refused as limitReached. */
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

/** The Kotlin layer's load-time check keeps the 1.x rule, and its refusal
 * reaches JavaScript as `unsupportedVersion` naming the caller's version:
 * any minor up to the library's is served, a later minor, another major or
 * any 0.x is refused. */
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

/** The rules as the hook applies them: a field matched in either form and
 * any case, a folded one taken out whole, a response matched by its CSeq,
 * the body untouched, nothing that does not fit changed. */
private fun theMessageRulesChangeWhatFitsThemAndNothingElse(): String {
    val rules = SipralMessageRule.parse(
        "rule outgoing REGISTER\nset Max-Forwards:42\nset X-New:1\nremove subject\nadd X-Lab-Hook:a: b\n" +
            "rule incoming *\nremove X-Trace",
    )
    val register = ("REGISTER sip:example.com SIP/2.0\r\nv: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\r\n" +
        "Max-Forwards: 70\r\nmax-forwards: 69\r\ns: one,\r\n two\r\nCSeq: 1 REGISTER\r\n" +
        "Content-Length: 4\r\n\r\nbody").toByteArray()
    assertEquals(
        "REGISTER sip:example.com SIP/2.0\r\nv: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\r\n" +
            "Max-Forwards: 42\r\nCSeq: 1 REGISTER\r\nContent-Length: 4\r\nX-New: 1\r\nX-Lab-Hook: a: b\r\n\r\nbody",
        String(assertNotNull(SipralMessageRule.apply(rules, true, register))),
    )
    assertEquals(null, SipralMessageRule.apply(rules, false, register), "an incoming REGISTER has no X-Trace")
    val invite = "INVITE sip:bob@example.com SIP/2.0\r\nCSeq: 2 INVITE\r\n\r\n".toByteArray()
    assertEquals(null, SipralMessageRule.apply(rules, true, invite), "a rule for REGISTER changed an INVITE")
    val answer = "SIP/2.0 200 OK\r\nCSeq: 1 REGISTER\r\nX-Trace: 9\r\nX-Trace: 10\r\n\r\n".toByteArray()
    assertEquals(
        "SIP/2.0 200 OK\r\nCSeq: 1 REGISTER\r\n\r\n",
        SipralMessageRule.apply(rules, false, answer)?.let { String(it) },
    )
    assertEquals(null, SipralMessageRule.apply(rules, true, "REGISTER x SIP/2.0\r\n".toByteArray()))
    assertEquals(emptyList(), SipralMessageRule.parse(""))
    for (bad in listOf("set X-A:1", "rule up *", "rule * *\nremove l", "rule * *\nadd X A:1", "rule * *\ndrop")) {
        refusal("invalidArgument") { SipralMessageRule.parse(bad) }
    }
    return "the message rules changed what fitted them and nothing else"
}

/** Rules set from JavaScript change the REGISTER on the wire, and each
 * message, as changed, is emitted while watched. */
private fun theMessageRulesReachTheWireAndTheMessagesAreHandedOver(): String {
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
        val events = Collections.synchronizedList(ArrayList<Map<String, Any>>())
        val core = SipralReactCore(emit = { events += it }, audio = { SipralAudioMode.Application })
        try {
            refusal("closed") { core.watchMessages(true) }
            core.open(SipralOpenOptions(bindHost = "127.0.0.1"))
            core.setMessageRules("rule outgoing REGISTER\nset Max-Forwards:42\nadd X-Lab-Hook:1")
            core.watchMessages(true)
            val address = "127.0.0.1:${registrar.localPort}"
            val line = core.addAccount(
                SipralAccountOptions(
                    aor = "sip:alice@sipral.invalid", registrar = "sip:sipral.invalid", registrarAddress = address,
                    streamProtocol = "tcp",
                ),
            )
            core.register(line)
            val message = register.get(10, TimeUnit.SECONDS)
            assertTrue("\r\nMax-Forwards: 42\r\n" in message, message)
            assertTrue("\r\nX-Lab-Hook: 1\r\n" in message, message)
            assertTrue(waitUntil { synchronized(events) { events.any { it["kind"] == "messageSeen" } } }, "no message was handed over")
            val seen = synchronized(events) { events.first { it["kind"] == "messageSeen" } }
            assertEquals(true, seen["outgoing"])
            assertEquals(address, seen["remote"])
            assertTrue("\r\nX-Lab-Hook: 1\r\n" in (seen["message"] as String), "$seen")
            core.setMessageRules("")
            core.watchMessages(false)
        } finally {
            core.close()
        }
    }
    return "the message rules reached the wire and the messages were handed over"
}

fun main() {
    val said = try {
        theMessageRulesChangeWhatFitsThemAndNothingElse() + "; " + theMessageRulesReachTheWireAndTheMessagesAreHandedOver() +
            "; " + everything() + "; " + reachability() + "; " + aCallThatEndedBeforeItWasKeptIsClosed() + "; " +
            aSettleAfterShutdownIsRejectedNotThrown() + "; " + anAccountOnAConnectionOfItsOwnAndTheSettingsReadBack() +
            "; " + aCallsOwnAudioIsSetAndReadBack() + "; " + theRealmsAndTheHeldAudioReachTheLibrary() + "; " +
            aCallPlacedPastMaxDialogsIsRefused() + "; " + theAbiCheckKeepsTheOneXRule() + "; " +
            theRateOfACallsFramesIsChosen() + "; " + theEchoCancellationIsSwitchedAndReadBack() + "; " +
            aCallsOwnCodecsReachTheLibrary() + "; " + aWebRtcLineReachesTheLibrary() + "; " +
            aSubscribedMailboxReachesJavaScript() + "; " + anUnaskedMailboxReachesOnlyAnAccountThatAllowsIt()
    } catch (failure: Throwable) {
        failure.printStackTrace()
        exitProcess(1)
    }
    println("react native core: $said")
    exitProcess(0)
}
