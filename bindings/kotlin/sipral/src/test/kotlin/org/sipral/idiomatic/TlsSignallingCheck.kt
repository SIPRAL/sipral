// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// SIP over TCP and TLS through org.sipral.idiomatic's SipralClient.open
// (signalling = ...): the counterpart of
// bindings/python/tests/test_signalling.py. The registrar is this check's
// own, on loopback, and its certificates are made with the JDK's keytool,
// one of them expired before the run began. Run by IdiomaticCheck.kt's
// main, under -Xcheck:jni.

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
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.sipral.Sipral
import org.sipral.SipralEventKind
import org.sipral.SipralRegistrationState
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

/** The next `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`: the first attempt's
 * failure is raised by the poll that follows `open`, and every attempt to
 * connect again that fails raises another, a second later at most. */
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

private fun everyFormAnAdministratorCopiesIsRead(): String {
    val digest = java.security.MessageDigest.getInstance("SHA-256").digest("a certificate".toByteArray())
    val plain = digest.joinToString("") { "%02x".format(it) }
    val colons = digest.joinToString(":") { "%02X".format(it) }
    for (text in listOf(plain, plain.uppercase(), colons, "sha-256 $colons", "SHA256=$colons", "  $plain  ")) {
        assertTrue(SipralTlsTrust.pinDigest(text).contentEquals(digest), text)
    }
    for (text in listOf(plain.dropLast(2), "sha-1 $colons", colons.take(2) + colons.drop(3), plain + "00")) {
        assertTrue(runCatching { SipralTlsTrust.pinDigest(text) }.isFailure, text)
    }
    return "every form of a fingerprint is read"
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

/** The stack retires the main connection on its own when a flow that
 * answered keep-alives stops answering them (RFC 5626 §4.4.1), with the
 * socket still open here; said here the way it says it. */
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

/** Twenty INVITEs from one address at once: how many were answered 480,
 * each counted once however often its refusal is sent again. */
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
        ).joinToString(", ")
    } finally {
        directory.deleteRecursively()
    }
}
