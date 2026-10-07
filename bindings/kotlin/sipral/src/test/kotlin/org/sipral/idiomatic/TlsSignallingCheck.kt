// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// SIP over TCP and TLS through SipralClient.open(signalling = ...), the
// counterpart of bindings/python/tests/test_signalling.py. The registrar
// runs on loopback with certificates made by keytool, one already expired.
// Run by IdiomaticCheck.kt's main, under -Xcheck:jni.

package org.sipral.idiomatic

import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.file.Files
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.Collections
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import kotlinx.coroutines.delay
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.sipral.Sipral
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralRegistrationState
import org.sipral.SipralStatus
import org.sipral.SipralTlsFailure
import org.sipral.SipralTransport
import org.sipral.SipralTransportError

private const val SERVER_NAME = "registrar.sipral.test"

private fun header(name: String, message: String): String? =
    message.split("\r\n").firstOrNull { it.lowercase().startsWith("${name.lowercase()}:") }
        ?.substringAfter(':')?.trim()

/** A key store holding one self-signed certificate for [SERVER_NAME], made
 * with keytool; [start] dates it, as keytool reads `-startdate`. */
private class Credential(directory: File, name: String, start: String?, days: Int) {
    val store: KeyStore
    val certificate: X509Certificate

    init {
        val file = File(directory, "$name.p12")
        val keytool = File(System.getProperty("java.home"), "bin/keytool").path
        val command = mutableListOf(
            keytool, "-genkeypair", "-alias", "registrar", "-keyalg", "EC", "-groupname", "secp256r1",
            "-dname", "CN=$SERVER_NAME", "-ext", "SAN=dns:$SERVER_NAME", "-ext", "EKU=serverAuth",
            "-validity", days.toString(), "-storetype", "PKCS12", "-keystore", file.path,
            "-storepass", "changeit", "-keypass", "changeit",
        )
        if (start != null) {
            command += listOf("-startdate", start)
        }
        val made = ProcessBuilder(command).redirectErrorStream(true).start()
        val said = made.inputStream.readBytes().toString(Charsets.UTF_8)
        check(made.waitFor(60, TimeUnit.SECONDS) && made.exitValue() == 0) { "keytool: $said" }
        store = KeyStore.getInstance("PKCS12").apply { file.inputStream().use { load(it, "changeit".toCharArray()) } }
        certificate = store.getCertificate("registrar") as X509Certificate
    }

    fun serverContext(): SSLContext {
        val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        keys.init(store, "changeit".toCharArray())
        return SSLContext.getInstance("TLS").apply { init(keys.keyManagers, null, null) }
    }
}

/** A registrar on a TCP port of loopback, over TLS when given a
 * credential, answering every REGISTER 200; or, [plainToTls], one that
 * answers a TLS client in plain text. */
private class Registrar(credential: Credential? = null, private val plainToTls: Boolean = false) : AutoCloseable {
    private val listener: ServerSocket = if (credential != null) {
        credential.serverContext().serverSocketFactory.createServerSocket(0, 50, InetAddress.getLoopbackAddress())
    } else {
        ServerSocket(0, 50, InetAddress.getLoopbackAddress())
    }
    private val connections = AtomicInteger(0)
    private val open: MutableList<Socket> = Collections.synchronizedList(ArrayList())
    val requests: MutableList<Pair<Int, String>> = Collections.synchronizedList(ArrayList())

    fun all(): List<Pair<Int, String>> = synchronized(requests) { requests.toList() }

    val address: String
        get() = "127.0.0.1:${listener.localPort}"

    init {
        Thread({ accept() }, "check-registrar").apply {
            isDaemon = true
            start()
        }
    }

    fun registers(): List<Pair<Int, String>> = synchronized(requests) { requests.filter { it.second.startsWith("REGISTER ") } }

    /** Close every connection from this end, the way a registrar that
     * restarted does. */
    fun drop() {
        val all = synchronized(open) { open.toList().also { open.clear() } }
        all.forEach { runCatching { it.close() } }
    }

    private fun accept() {
        while (!listener.isClosed) {
            val socket = try {
                listener.accept()
            } catch (_: Exception) {
                return
            }
            val number = connections.incrementAndGet()
            Thread({ serve(socket, number) }, "check-registrar-$number").apply {
                isDaemon = true
                start()
            }
        }
    }

    private fun serve(socket: Socket, number: Int) {
        try {
            val input: InputStream = socket.getInputStream()
            val output: OutputStream = socket.getOutputStream()
            if (plainToTls) {
                input.read(ByteArray(4096))
                output.write("SIP/2.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n".toByteArray())
                socket.close()
                return
            }
            open.add(socket)
            var held = ""
            val buffer = ByteArray(65536)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) {
                    break
                }
                held += String(buffer, 0, read, Charsets.UTF_8)
                while (true) {
                    val end = held.indexOf("\r\n\r\n")
                    if (end < 0) {
                        break
                    }
                    val length = header("Content-Length", held.substring(0, end))?.toInt() ?: 0
                    if (held.length < end + 4 + length) {
                        break
                    }
                    val message = held.substring(0, end + 4 + length)
                    held = held.substring(end + 4 + length)
                    requests.add(number to message)
                    if (message.startsWith("REGISTER ")) {
                        output.write(ok(message).toByteArray())
                        output.flush()
                    }
                }
            }
        } catch (_: Exception) {
            // the connection ended, or the handshake was refused
        }
        runCatching { socket.close() }
    }

    private fun ok(request: String): String {
        val lines = mutableListOf("SIP/2.0 200 OK")
        for (name in listOf("Via", "From", "To", "Call-ID", "CSeq")) {
            val value = header(name, request)
            lines += if (name == "To") "To: $value;tag=registrar" else "$name: $value"
        }
        lines += "Contact: ${header("Contact", request)};expires=3600"
        lines += "Content-Length: 0"
        return lines.joinToString("\r\n") + "\r\n\r\n"
    }

    override fun close() {
        runCatching { listener.close() }
        drop()
    }
}

private fun over(
    server: String,
    signalling: SipralTransport = SipralTransport.TLS,
    name: String? = SERVER_NAME,
    trust: SipralTlsTrust = SipralTlsTrust.Platform,
): SipralClient = SipralClient.open(
    audio = SipralAudioMode.Application,
    signalling = signalling,
    signallingServer = server,
    tlsServerName = name,
    tlsTrust = trust,
)

/** The next `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`: the first failure is
 * raised by the poll after `open`, and each failed reconnect raises
 * another within a second. */
private suspend fun refusal(client: SipralClient): org.sipral.SipralTransportFailedEvent {
    val (_, event) = client.events.awaitNext(SipralEventKind.TRANSPORT_FAILED, timeoutMs = 10_000) { }
    assertFalse(client.connected)
    return assertNotNull(transportFailedOf(event))
}

private suspend fun registered(client: SipralClient, account: SipralAccount) {
    repeat(100) {
        if (account.registrationState == SipralRegistrationState.REGISTERED) {
            return
        }
        delay(50)
    }
    throw AssertionError("the account never registered")
}

private suspend fun aRegistrarWhoseAuthorityIsPinnedRegistersOverTls(good: Credential): String {
    Registrar(good).use { registrar ->
        over(registrar.address, trust = SipralTlsTrust.OnlyAuthority(good.certificate)).use { client ->
            assertTrue(client.connected)
            val account = client.addAccount(
                aor = "sip:alice@$SERVER_NAME", registrarAddress = registrar.address, registrar = "sip:$SERVER_NAME",
            )
            account.register()
            registered(client, account)
            val (connection, register) = registrar.registers().single()
            assertEquals(1, connection)
            assertTrue(header("Via", register)!!.startsWith("SIP/2.0/TLS "), register)
            assertTrue(header("Contact", register)!!.contains(";transport=tls"))
            assertTrue(header("Contact", register)!!.contains(client.bindAddress))
        }
    }
    return "a pinned authority registers over TLS"
}

private suspend fun thePinnedCertificateIsTrustedWhateverItsNameAndSigner(good: Credential): String {
    val fingerprint = "SHA256=" + java.security.MessageDigest.getInstance("SHA-256").digest(good.certificate.encoded)
        .joinToString(":") { "%02X".format(it) }
    Registrar(good).use { registrar ->
        over(
            registrar.address, name = "a-name-the-certificate-does-not-carry.test",
            trust = SipralTlsTrust.Pinned(fingerprint),
        ).use { client ->
            assertTrue(client.connected)
            val account = client.addAccount(
                aor = "sip:alice@$SERVER_NAME", registrarAddress = registrar.address, registrar = "sip:$SERVER_NAME",
            )
            account.register()
            registered(client, account)
        }
    }
    val other = java.security.MessageDigest.getInstance("SHA-256").digest("another certificate".toByteArray())
        .joinToString("") { "%02x".format(it) }
    Registrar(good).use { registrar ->
        over(registrar.address, trust = SipralTlsTrust.Pinned(other)).use { client ->
            val failed = refusal(client)
            assertEquals(SipralTlsFailure.UNTRUSTED.value.toLong(), failed.tls)
            assertTrue(failed.detail?.contains("pinned") == true, failed.detail ?: "")
        }
    }
    return "a pinned certificate is trusted whatever its name and signer, and any other refused"
}

/** Every line of bindings/fixtures/pin-forms.txt, the forms every layer's
 * parser must accept, located from the JVM's working directory. */
private fun everyFormAnAdministratorCopiesIsRead(): String {
    var at: File? = File(System.getProperty("user.dir")).absoluteFile
    while (at != null && !File(at, "bindings/fixtures/pin-forms.txt").isFile) {
        at = at.parentFile
    }
    val list = File(assertNotNull(at, "bindings/fixtures/pin-forms.txt is not above the JVM's directory"), "bindings/fixtures/pin-forms.txt")
    var digest = ByteArray(0)
    var checked = 0
    for (line in list.readLines(Charsets.UTF_8)) {
        if (line.isEmpty() || line.startsWith("#")) {
            continue
        }
        val verdict = line.substringBefore('\t')
        val text = line.substringAfter('\t', "")
        when (verdict) {
            "digest" -> digest = ByteArray(text.length / 2) { text.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
            "accept" -> {
                assertTrue(SipralTlsTrust.pinDigest(text).contentEquals(digest), text)
                checked++
            }
            else -> {
                assertFailsWith<IllegalArgumentException>(text) { SipralTlsTrust.pinDigest(text) }
                checked++
            }
        }
    }
    assertEquals(32, digest.size)
    assertTrue(checked > 20, "only $checked forms were read")
    return "every form of a fingerprint in pin-forms.txt is read or refused"
}

private suspend fun aPrivateAuthorityIsTrustedBesideThePlatforms(good: Credential): String {
    Registrar(good).use { registrar ->
        over(registrar.address, trust = SipralTlsTrust.PrivateAuthority(good.certificate)).use { client ->
            val account = client.addAccount(
                aor = "sip:alice@$SERVER_NAME", registrarAddress = registrar.address, registrar = "sip:$SERVER_NAME",
            )
            account.register()
            registered(client, account)
        }
    }
    return "a private authority beside the platform's"
}

private suspend fun eachRefusalSaysWhy(good: Credential, expired: Credential): String {
    Registrar(good).use { registrar ->
        over(registrar.address).use { client ->
            val failed = refusal(client)
            assertEquals(SipralTlsFailure.UNTRUSTED.value.toLong(), failed.tls)
            assertEquals(SipralTransport.TLS.value.toLong(), failed.protocol)
            assertFalse(failed.detail.isNullOrEmpty(), "the platform's own words come with it")
            val account = client.addAccount(
                aor = "sip:alice@$SERVER_NAME", registrarAddress = registrar.address, registrar = "sip:$SERVER_NAME",
            )
            account.register()
            assertTrue(account.wantsRegistration)
            assertTrue(registrar.registers().isEmpty())
        }
        over(registrar.address, name = "other.sipral.test", trust = SipralTlsTrust.OnlyAuthority(good.certificate)).use {
            assertEquals(SipralTlsFailure.NAME_MISMATCH.value.toLong(), refusal(it).tls)
        }
    }
    Registrar(expired).use { registrar ->
        over(registrar.address, trust = SipralTlsTrust.OnlyAuthority(expired.certificate)).use {
            assertEquals(SipralTlsFailure.EXPIRED.value.toLong(), refusal(it).tls)
        }
    }
    Registrar(plainToTls = true).use { registrar ->
        over(registrar.address).use {
            assertEquals(SipralTlsFailure.HANDSHAKE_REFUSED.value.toLong(), refusal(it).tls)
        }
    }
    val nobody = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
    val address = "127.0.0.1:${nobody.localPort}"
    nobody.close()
    over(address).use {
        val failed = refusal(it)
        assertEquals(SipralTransportError.CONNECTION_REFUSED.value.toLong(), failed.error)
        assertEquals(SipralTlsFailure.NONE.value.toLong(), failed.tls)
    }
    return "untrusted, name mismatch, expired, handshake refused and refused each say so"
}

private suspend fun aConnectionLostIsMadeAgainAndTheAccountRegistersOnIt(): String {
    Registrar().use { registrar ->
        over(registrar.address, signalling = SipralTransport.TCP, name = null).use { client ->
            val account = client.addAccount(
                aor = "sip:alice@sipral.invalid", registrarAddress = registrar.address, registrar = "sip:sipral.invalid",
            )
            account.register()
            registered(client, account)
            val first = client.bindAddress
            val (_, lost) = client.events.awaitNext(SipralEventKind.TRANSPORT_FAILED, timeoutMs = 10_000) {
                registrar.drop()
            }
            val failed = assertNotNull(transportFailedOf(lost))
            assertEquals(SipralTransportError.CLOSED.value.toLong(), failed.error)
            assertEquals(SipralTransport.TCP.value.toLong(), failed.protocol)
            repeat(200) {
                if (registrar.registers().any { it.first == 2 }) {
                    return@repeat
                }
                delay(50)
            }
            val again = registrar.registers().firstOrNull { it.first == 2 }?.second
            assertNotNull(again, "no REGISTER on a second connection")
            assertNotEquals(first, client.bindAddress)
            assertTrue(header("Contact", again)!!.contains(client.bindAddress))
            assertTrue(header("Contact", again)!!.contains(";transport=tcp"))
        }
    }
    return "a lost connection is made again and the account registers on it"
}

/** The stack retires the main connection itself when a flow stops
 * answering keep-alives (RFC 5626 §4.4.1), with the socket still open
 * here. */
private suspend fun aConnectionTheStackLetGoOfIsMadeAgain(): String {
    Registrar().use { registrar ->
        over(registrar.address, signalling = SipralTransport.TCP, name = null).use { client ->
            val account = client.addAccount(
                aor = "sip:alice@sipral.invalid", registrarAddress = registrar.address, registrar = "sip:sipral.invalid",
            )
            account.register()
            registered(client, account)
            val first = client.bindAddress
            val (_, lost) = client.events.awaitNext(SipralEventKind.TRANSPORT_FAILED, timeoutMs = 10_000) {
                retryBusy {
                    Sipral.stackTransportFailed(
                        client.handle, Sipral.TRANSPORT_MAIN, SipralTransportError.TIMED_OUT.value.toLong(), client.nowMs(),
                    )
                }
            }
            assertEquals(Sipral.TRANSPORT_MAIN, assertNotNull(transportFailedOf(lost)).transport)
            repeat(200) {
                if (registrar.registers().any { it.first == 2 }) {
                    return@repeat
                }
                delay(50)
            }
            val again = registrar.registers().firstOrNull { it.first == 2 }?.second
            assertNotNull(again, "no REGISTER on a second connection after the stack let the first go")
            assertNotEquals(first, client.bindAddress)
            assertTrue(header("Contact", again)!!.contains(client.bindAddress))
        }
    }
    return "a connection the stack let go of is made again and the account registers on it"
}

/** Twenty INVITEs from one address at once: how many got 480, each
 * counted once however often its refusal is retransmitted. */
private fun rush(limit: SipralInviteLimit?): Int {
    SipralClient.open(audio = SipralAudioMode.Application, inviteLimit = limit).use { client ->
        client.addAccount(aor = "sip:bob@sipral.invalid", registrarAddress = "127.0.0.1:9")
        DatagramSocket(0, InetAddress.getLoopbackAddress()).use { caller ->
            caller.soTimeout = 200
            val here = "127.0.0.1:${caller.localPort}"
            val to = parseHostPort(client.bindAddress)
            for (n in 0 until 20) {
                val invite = "INVITE sip:bob@${client.bindAddress} SIP/2.0\r\n" +
                    "Via: SIP/2.0/UDP $here;branch=z9hG4bK-rush-$n\r\n" +
                    "Max-Forwards: 70\r\n" +
                    "From: <sip:trunk@$here>;tag=rush$n\r\n" +
                    "To: <sip:bob@${client.bindAddress}>\r\n" +
                    "Call-ID: rush-$n@trunk\r\n" +
                    "CSeq: 1 INVITE\r\n" +
                    "Contact: <sip:trunk@$here>\r\n" +
                    "Content-Length: 0\r\n\r\n"
                val bytes = invite.toByteArray()
                caller.send(DatagramPacket(bytes, bytes.size, InetSocketAddress(to.address, to.port)))
            }
            val refused = HashSet<String>()
            val until = System.nanoTime() + 2_000_000_000L
            val buffer = ByteArray(65536)
            while (System.nanoTime() < until) {
                val packet = DatagramPacket(buffer, buffer.size)
                try {
                    caller.receive(packet)
                } catch (_: SocketTimeoutException) {
                    continue
                }
                val text = String(packet.data, 0, packet.length, Charsets.UTF_8)
                if (text.startsWith("SIP/2.0 480 ")) {
                    refused += header("Call-ID", text) ?: ""
                }
            }
            return refused.size
        }
    }
}

private fun theVoiceAgentPresetTakesARushTheDefaultAnswers480(): String {
    assertEquals(10, rush(null), "ten at once, then one every two seconds")
    assertEquals(0, rush(SipralInviteLimit.VOICE_AGENT))
    assertEquals(SipralInviteLimit(10, 2000), SipralInviteLimit.DEFAULT)
    return "the voice-agent preset takes a rush the default answers 480"
}

/** An account on its own TLS connection beside one on the client's UDP
 * socket, each registering and calling through its own loopback registrar,
 * with `streamFallback` off (which leaves an account's own connection
 * alone). */
private suspend fun anAccountOverTlsAndOneOverUdpEachReachTheirOwnServer(good: Credential): String {
    val pin = "sha256 Fingerprint=" + java.security.MessageDigest.getInstance("SHA-256").digest(good.certificate.encoded)
        .joinToString(":") { "%02X".format(it) }
    DatagramRegistrar().use { udp ->
        Registrar(good).use { tls ->
            SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", streamFallback = false).use { client ->
                val wanted = Collections.synchronizedList(ArrayList<org.sipral.SipralTransportWantedEvent>())
                val overUdp = client.addAccount(
                    aor = "sip:alice@udp.sipral.test", registrarAddress = udp.address, registrar = "sip:udp.sipral.test",
                )
                val overTls = client.addAccount(
                    aor = "sip:bob@$SERVER_NAME", registrarAddress = tls.address, registrar = "sip:$SERVER_NAME",
                    tlsPin = pin, streamProtocol = SipralTransport.TLS,
                )
                assertEquals(SipralTransport.TLS, overTls.streamProtocol)
                assertEquals(null, overUdp.streamProtocol)
                assertTrue(overTls.contact.endsWith(";transport=tls"), overTls.contact)
                client.events.awaitNext(SipralEventKind.TRANSPORT_WANTED, timeoutMs = 10_000) {
                    overUdp.register()
                    overTls.register()
                }.let { (_, event) -> wanted += assertNotNull(transportWantedOf(event)) }
                registered(client, overUdp)
                registered(client, overTls)
                assertEquals(SipralTransport.TLS.value.toLong(), wanted.single().protocol)
                assertEquals(tls.address, wanted.single().destination)
                assertEquals(0L, wanted.single().requestBytes)
                val (connection, register) = tls.registers().single()
                assertTrue(header("Via", register)!!.startsWith("SIP/2.0/TLS "), register)
                assertTrue(register.contains("sip:bob@"))
                assertTrue(udp.registers.isNotEmpty() && udp.registers.all { it.contains("sip:alice@") })

                client.placeCall(overUdp, "sip:carol@udp.sipral.test").use {
                    client.placeCall(overTls, "sip:dave@$SERVER_NAME").use {
                        assertTrue(
                            eventually { synchronized(udp.received) { udp.received.any { it.startsWith("INVITE sip:carol@") } } },
                            "the UDP account's call never reached its server",
                        )
                        assertTrue(
                            eventually { tls.all().any { it.second.startsWith("INVITE sip:dave@") } },
                            "the TLS account's call never reached its server",
                        )
                        val invite = tls.all().first { it.second.startsWith("INVITE ") }
                        assertEquals(connection, invite.first, "the call went over the account's own connection")
                        assertTrue(header("Via", invite.second)!!.startsWith("SIP/2.0/TLS "))
                        assertFalse(synchronized(udp.received) { udp.received.any { it.contains("dave@") } })
                        assertFalse(tls.all().any { it.second.contains("carol@") })
                    }
                }
            }
        }
    }
    return "an account over TLS and one over UDP each reached their own server"
}

/** An account on its own TCP connection re-registers over a new one when
 * the server drops it; anything but TCP or TLS is refused. */
private suspend fun anAccountOverTcpIsOpenedAgainWhenItsServerDropsIt(): String {
    Registrar().use { registrar ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
            val account = client.addAccount(
                aor = "sip:alice@$SERVER_NAME", registrarAddress = registrar.address, registrar = "sip:$SERVER_NAME",
                streamProtocol = SipralTransport.TCP,
            )
            account.register()
            registered(client, account)
            val (_, register) = registrar.registers().single()
            assertTrue(header("Via", register)!!.startsWith("SIP/2.0/TCP "), register)
            assertTrue(header("Contact", register)!!.contains(";transport=tcp"))
            registrar.drop()
            assertTrue(
                eventually { registrar.registers().any { it.first == 2 } },
                "the account did not register again over a new connection",
            )
            assertFailsWith<IllegalArgumentException> {
                client.addAccount(
                    aor = "sip:carol@example.com", registrarAddress = "127.0.0.1:5060", streamProtocol = SipralTransport.UDP,
                )
            }
        }
    }
    return "an account over TCP opened again when its server dropped it"
}

/** ABI 1.2: an account on a WebSocket of its own opens a TCP connection
 * and the stack's handshake on it asks for the resource and `Host` the
 * account named; either one with another protocol is refused. */
private suspend fun anAccountOverAWebSocketAsksForItsResourceAndHost(): String {
    Registrar().use { server ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
            val account = client.addAccount(
                aor = "sip:alice@$SERVER_NAME", registrarAddress = server.address, registrar = "sip:$SERVER_NAME",
                streamProtocol = SipralTransport.WS, websocketHost = "pbx.sipral.test",
                websocketResource = "/sip?tenant=7",
            )
            assertEquals(SipralTransport.WS, account.streamProtocol)
            assertTrue(account.contact.endsWith(";transport=ws"), account.contact)
            account.register()
            assertTrue(
                eventually { server.all().any { it.second.startsWith("GET ") } },
                "no WebSocket handshake reached the server",
            )
            val handshake = server.all().first { it.second.startsWith("GET ") }.second
            assertTrue(handshake.startsWith("GET /sip?tenant=7 HTTP/1.1\r\n"), handshake)
            assertEquals("pbx.sipral.test", header("Host", handshake))
            assertEquals("sip", header("Sec-WebSocket-Protocol", handshake))
            val refused = assertFailsWith<SipralException> {
                client.addAccount(
                    aor = "sip:bob@example.com", registrarAddress = server.address,
                    streamProtocol = SipralTransport.TCP, websocketResource = "/ws",
                )
            }
            assertEquals(SipralStatus.INVALID_ARGUMENT, refused.status)
        }
    }
    return "an account over a WebSocket asked for its resource and Host"
}

/** The settings read back, every default filled in, and what was given. */
private fun theSettingsAreReadBack(): String {
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { plain ->
        val defaults = plain.settings()
        assertEquals(SipralTransport.UDP, defaults.transport)
        assertTrue(defaults.retransmits)
        assertTrue(defaults.systemEchoCancellation)
        assertFalse(defaults.pseudonymSalted)
        assertFalse(defaults.diagnosticTrace)
        assertTrue(defaults.srtpSuites.isNotEmpty(), "this build's own suites")
        assertTrue(defaults.codecCount > 0)
        assertEquals(null, defaults.rtpPorts)
    }
    SipralClient.open(
        audio = SipralAudioMode.Application, bindHost = "127.0.0.1", rtpPortMin = 40000, rtpPortMax = 40100,
        srtpSuites = listOf("AES_CM_128_HMAC_SHA1_32", "AES_CM_128_HMAC_SHA1_80"),
        pseudonymSalt = ByteArray(16) { 7 }, diagnosticTrace = true, systemEchoCancellation = false,
    ).use { given ->
        val settings = given.settings()
        assertEquals(listOf(org.sipral.SipralSrtpSuite.AES_CM32, org.sipral.SipralSrtpSuite.AES_CM80), settings.srtpSuites)
        assertTrue(settings.pseudonymSalted)
        assertTrue(settings.diagnosticTrace)
        assertFalse(settings.systemEchoCancellation)
        assertEquals(40000L..40100L, settings.rtpPorts)
        given.setDiagnosticTrace(false)
        assertFalse(given.settings().diagnosticTrace)
    }
    return "the settings read back with the defaults filled in"
}

private suspend fun eventually(seconds: Int = 8, what: () -> Boolean): Boolean {
    repeat(seconds * 50) {
        if (what()) return true
        delay(20)
    }
    return what()
}

internal suspend fun tlsSignallingChecks(): String {
    val directory = Files.createTempDirectory("sipral-tls").toFile()
    try {
        val good = Credential(directory, "good", null, 1)
        val expired = Credential(directory, "expired", "2020/01/01 00:00:00", 1)
        return listOf(
            aRegistrarWhoseAuthorityIsPinnedRegistersOverTls(good),
            aPrivateAuthorityIsTrustedBesideThePlatforms(good),
            thePinnedCertificateIsTrustedWhateverItsNameAndSigner(good),
            everyFormAnAdministratorCopiesIsRead(),
            eachRefusalSaysWhy(good, expired),
            aConnectionLostIsMadeAgainAndTheAccountRegistersOnIt(),
            aConnectionTheStackLetGoOfIsMadeAgain(),
            theVoiceAgentPresetTakesARushTheDefaultAnswers480(),
            anAccountOverTlsAndOneOverUdpEachReachTheirOwnServer(good),
            anAccountOverTcpIsOpenedAgainWhenItsServerDropsIt(),
            anAccountOverAWebSocketAsksForItsResourceAndHost(),
            theSettingsAreReadBack(),
        ).joinToString(", ")
    } finally {
        directory.deleteRecursively()
    }
}
