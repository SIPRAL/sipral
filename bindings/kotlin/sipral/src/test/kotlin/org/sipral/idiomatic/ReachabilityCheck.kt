// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// Where a client is reached and where its server is, through
// org.sipral.idiomatic: the address advertised when the application names
// none, a server named by a URI and located by RFC 3263, the account's
// keep-alive, a certificate trusted by its fingerprint, and the diagnostic
// trace -- the Kotlin counterpart of
// bindings/python/tests/test_reachability.py. The registrar is this check's
// own, a UDP socket on loopback that answers every REGISTER 200 and keeps
// every datagram. Run by IdiomaticCheck.kt's main, under -Xcheck:jni.

package org.sipral.idiomatic

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.util.Collections
import kotlinx.coroutines.delay
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.sipral.SipralDnsAnswer
import org.sipral.SipralDnsRecordType
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralLocateFailure
import org.sipral.SipralLogLevel
import org.sipral.SipralRegistrationFailure
import org.sipral.SipralRegistrationState
import org.sipral.SipralSrtp
import org.sipral.SipralStatus

private fun header(name: String, message: String): String? =
    message.split("\r\n")
        .firstOrNull { it.lowercase().startsWith(name.lowercase() + ":") }
        ?.substringAfter(':')?.trim()

/** A registrar on a loopback UDP port: every REGISTER answered 200, every
 * datagram kept as text. */
private class DatagramRegistrar : AutoCloseable {
    private val udp = DatagramSocket(0, InetAddress.getByName("127.0.0.1")).apply { soTimeout = 50 }
    @Volatile private var stopped = false
    val port = udp.localPort
    val address = "127.0.0.1:$port"
    val received: MutableList<String> = Collections.synchronizedList(ArrayList())
    val registers: List<String>
        get() = synchronized(received) { received.filter { it.startsWith("REGISTER ") } }

    init {
        Thread(::serve, "registrar-udp").apply { isDaemon = true; start() }
    }

    private fun serve() {
        val buffer = ByteArray(65536)
        while (!stopped) {
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                udp.receive(packet)
            } catch (_: SocketTimeoutException) {
                continue
            } catch (_: Exception) {
                return
            }
            val message = String(packet.data, 0, packet.length, Charsets.UTF_8)
            received += message
            if (!message.startsWith("REGISTER ")) continue
            val lines = mutableListOf("SIP/2.0 200 OK")
            for (name in listOf("Via", "From", "To", "Call-ID", "CSeq")) {
                val value = header(name, message) ?: ""
                lines += if (name == "To") "To: $value;tag=registrar" else "$name: $value"
            }
            lines += "Contact: ${header("Contact", message)};expires=3600"
            lines += "Content-Length: 0"
            val out = (lines.joinToString("\r\n") + "\r\n\r\n").toByteArray(Charsets.UTF_8)
            udp.send(DatagramPacket(out, out.size, packet.socketAddress))
        }
    }

    override fun close() {
        stopped = true
        udp.close()
    }
}

private fun application(resolver: SipralResolver? = null, srtp: SipralSrtp? = null) =
    SipralClient.open(audio = SipralAudioMode.Application, resolver = resolver, srtp = srtp)

private suspend fun registered(account: SipralAccount) {
    repeat(200) {
        if (account.registrationState == SipralRegistrationState.REGISTERED) return
        delay(25)
    }
    throw AssertionError("the account never registered")
}

private suspend fun until(seconds: Int = 5, what: () -> Boolean): Boolean {
    repeat(seconds * 50) {
        if (what()) return true
        delay(20)
    }
    return what()
}

private suspend fun theAddressAClientAdvertisesIsTheRouteTowardItsServer(): String {
    assertEquals("127.0.0.1:5060", advertisedAddress("0.0.0.0:5060", "127.0.0.1:5070"))
    val refused = runCatching { advertisedAddress("127.0.0.1:5060", "192.0.2.1:5060") }.exceptionOrNull()
    assertEquals(SipralStatus.UNREACHABLE_ADDRESS, (refused as? SipralException)?.status)
    assertEquals("127.0.0.1", routeHost("pbx.example.com:5060"), "a name has no route")

    DatagramRegistrar().use { registrar ->
        application().use { client ->
            val account = client.addAccount("sip:alice@example.com", registrar.address, registrar = "sip:example.com")
            account.register()
            registered(account)
            val contact = header("Contact", registrar.registers.first()) ?: ""
            assertTrue(contact.contains("@127.0.0.1:${client.bindAddress.substringAfterLast(':')}"), contact)
        }
    }

    val remote = "192.0.2.1:5060"
    val route = routeHost(remote)
    if (route != "127.0.0.1") {
        application().use { client ->
            val account = client.addAccount("sip:alice@example.com", remote, registrar = "sip:example.com")
            assertTrue(account.contact.contains("@$route:"), account.contact)
            assertEquals(route, client.bindAddress.substringBeforeLast(':'), "and the stack's Via with it")
        }
    }

    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
        val account = client.addAccount("sip:alice@example.com", remote, registrar = "sip:example.com")
        val stopped = runCatching { account.register() }.exceptionOrNull()
        assertEquals(SipralStatus.UNREACHABLE_ADDRESS, (stopped as? SipralException)?.status)
        assertEquals(5, SipralRegistrationFailure.UNREACHABLE_CONTACT.value)
    }

    application().use { alice ->
        application().use { bob ->
            val toBob = alice.addAccount("sip:alice@example.com", bob.bindAddress)
            bob.addAccount("sip:bob@example.com", alice.bindAddress)
            val (call, incoming) = bob.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 10_000) {
                alice.placeCall(toBob, "sip:bob@example.com")
            }
            assertTrue(call.mediaAddress.startsWith("127.0.0.1:"), call.mediaAddress)
            val answered = bob.answerCall(incoming)
            assertTrue(answered.mediaAddress.startsWith("127.0.0.1:"), answered.mediaAddress)
            call.close()
            answered.close()
        }
    }
    return "a client that names no address advertises the route toward its server, and loopback to loopback"
}

private suspend fun aServerNamedByAUriIsLocated(): String {
    DatagramRegistrar().use { registrar ->
        application().use { client ->
            val (account, located) = client.events.awaitNext(SipralEventKind.LOCATED, timeoutMs = 10_000) {
                client.addAccount(
                    "sip:alice@example.com", registrar = "sip:example.com", serverUri = "sip:localhost:${registrar.port}",
                ).also { it.register() }
            }
            val targets = locateOf(located)?.targets?.split(',') ?: emptyList()
            assertTrue("127.0.0.1:${registrar.port}" in targets, "$targets")
            registered(account)
            assertEquals(1, registrar.registers.size)
        }
    }

    DatagramRegistrar().use { registrar ->
        val asked = Collections.synchronizedList(ArrayList<String>())
        val resolver: SipralResolver = { name, record ->
            asked += "$record $name"
            when {
                record == SipralDnsRecordType.SRV && name == "_sip._udp.pbx.sipral.test" ->
                    SipralLookup(SipralDnsAnswer.RECORDS, listOf("300 10 60 ${registrar.port} host.sipral.test"))
                record == SipralDnsRecordType.A && name == "host.sipral.test" ->
                    SipralLookup(SipralDnsAnswer.RECORDS, listOf("300 127.0.0.1"))
                else -> SipralLookup.NOTHING
            }
        }
        application(resolver).use { client ->
            val (account, located) = client.events.awaitNext(SipralEventKind.LOCATED, timeoutMs = 10_000) {
                client.addAccount(
                    "sip:alice@pbx.sipral.test", registrar = "sip:pbx.sipral.test", serverUri = "sip:pbx.sipral.test",
                ).also { it.register() }
            }
            assertEquals("127.0.0.1:${registrar.port}", locateOf(located)?.targets?.split(',')?.first())
            registered(account)
            assertEquals("127.0.0.1:${registrar.port}", account.registrarAddress)
            assertTrue("SRV _sip._udp.pbx.sipral.test" in asked, "$asked")
        }
    }

    application({ _, _ -> SipralLookup.NOTHING }).use { client ->
        val (_, failed) = client.events.awaitNext(SipralEventKind.LOCATE_FAILED, timeoutMs = 10_000) {
            client.addAccount(
                "sip:alice@example.com", registrar = "sip:example.com", serverUri = "sip:nowhere.sipral.test",
            ).register()
        }
        val locate = assertNotNull(locateOf(failed))
        assertEquals(SipralLocateFailure.NOT_FOUND.value.toLong(), locate.failure)
        assertTrue(locate.retryInMs > 0)
    }

    val found = SipralDns.platform("localhost", SipralDnsRecordType.A)
    assertEquals(SipralDnsAnswer.RECORDS, found.answer)
    assertTrue("60 127.0.0.1" in found.records, "${found.records}")
    assertEquals("60 10 60 5060 sip1.example.com", SipralDns.zoneText(SipralDnsRecordType.SRV, "10 60 5060 sip1.example.com."))
    assertEquals(
        "60 10 50 S SIP+D2U _sip._udp.example.com",
        SipralDns.zoneText(SipralDnsRecordType.NAPTR, "10 50 \"S\" \"SIP+D2U\" \"\" _sip._udp.example.com."),
    )
    assertNull(SipralDns.zoneText(SipralDnsRecordType.SRV, "10 60"))

    application().use { client ->
        assertTrue(runCatching { client.addAccount("sip:alice@example.com") }.isFailure)
        assertTrue(runCatching { client.addAccount("sip:a@example.com", "127.0.0.1:5060", serverUri = "sip:a.test") }.isFailure)
    }
    return "a server named by a URI is located by an address, an SRV answer and a failure that says why"
}

private suspend fun anAccountKeepsItsFlowOpen(): String {
    DatagramRegistrar().use { registrar ->
        application().use { client ->
            val account = client.addAccount(
                "sip:alice@example.com", registrar.address, registrar = "sip:example.com", keepaliveMs = 1000,
            )
            account.register()
            registered(account)
            assertTrue(until(3) { "\r\n\r\n" in registrar.received }, "${registrar.received}")
        }
    }
    application().use { client ->
        val refused = runCatching { client.addAccount("sip:alice@example.com", "127.0.0.1:5060", keepaliveMs = 999) }
        assertEquals(SipralStatus.INVALID_ARGUMENT, (refused.exceptionOrNull() as? SipralException)?.status)
    }
    return "an account's keep-alive reaches its registrar"
}

private fun theAccountsPinDecidesOnACertificate(): String {
    val certificate = "the DER bytes of a leaf".toByteArray()
    val pin = "SHA256=" + MessageDigest.getInstance("SHA-256").digest(certificate).joinToString(":") { "%02X".format(it) }
    application().use { client ->
        val pinned = client.addAccount("sip:alice@example.com", "127.0.0.1:5060", tlsPin = pin)
        val verdict = assertNotNull(pinned.checkCertificate(certificate))
        assertEquals(0L, verdict.expired)
        val refused = runCatching { pinned.checkCertificate("another certificate".toByteArray()) }.exceptionOrNull()
        assertEquals(SipralStatus.CERTIFICATE_REFUSED, (refused as? SipralException)?.status)
        val unpinned = client.addAccount("sip:bob@example.com", "127.0.0.1:5060")
        assertNull(unpinned.checkCertificate(certificate))
        assertTrue(runCatching { client.addAccount("sip:carol@example.com", "127.0.0.1:5060", tlsPin = "00") }.isFailure)
    }
    return "an account's pin decides on a certificate"
}

private suspend fun theClientsNewOptionsReachTheLibrary(): String {
    val suite = runCatching { SipralClient.open(audio = SipralAudioMode.Application, srtpSuites = listOf("NOT_A_SUITE")).close() }
    assertEquals(SipralStatus.INVALID_ARGUMENT, (suite.exceptionOrNull() as? SipralException)?.status)
    val salt = runCatching { SipralClient.open(audio = SipralAudioMode.Application, pseudonymSalt = "short".toByteArray()).close() }
    assertEquals(SipralStatus.INVALID_ARGUMENT, (salt.exceptionOrNull() as? SipralException)?.status)
    SipralClient.open(
        audio = SipralAudioMode.Application, srtp = SipralSrtp.BEST_EFFORT,
        srtpSuites = listOf("AES_CM_128_HMAC_SHA1_80"), pseudonymSalt = ByteArray(16) { it.toByte() },
    ).close()

    DatagramRegistrar().use { registrar ->
        application().use { client ->
            val written = Collections.synchronizedList(ArrayList<String>())
            client.setLog(SipralLogLevel.TRACE) { _, _, message, _ -> written += message }
            val account = client.addAccount("sip:alice@example.com", registrar.address, registrar = "sip:example.com")
            account.register()
            registered(account)
            val whole = { synchronized(written) { written.any { "sip:alice@example.com" in it } } }
            assertFalse(whole(), "pseudonymised")
            client.setDiagnosticTrace(true)
            account.register()
            assertTrue(until(5, whole), "a whole REGISTER, the AOR as it went on the wire")
        }
    }

    application(srtp = SipralSrtp.BEST_EFFORT).use { alice ->
        application().use { bob ->
            val toBob = alice.addAccount("sip:alice@example.com", bob.bindAddress)
            bob.addAccount("sip:bob@example.com", alice.bindAddress)
            val (call, incoming) = bob.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 10_000) {
                alice.placeCall(toBob, "sip:bob@example.com")
            }
            val offer = incoming.message?.toString(Charsets.UTF_8) ?: ""
            assertTrue("RTP/AVP" in offer && "RTP/SAVP" !in offer && "a=crypto:" in offer, offer)
            call.close()
        }
    }
    return "the client's suites, salt and trace reach the library, and best effort keys plain RTP"
}

internal suspend fun reachabilityChecks(): String = listOf(
    theAddressAClientAdvertisesIsTheRouteTowardItsServer(),
    aServerNamedByAUriIsLocated(),
    anAccountKeepsItsFlowOpen(),
    theAccountsPinDecidesOnACertificate(),
    theClientsNewOptionsReachTheLibrary(),
).joinToString(", ")
