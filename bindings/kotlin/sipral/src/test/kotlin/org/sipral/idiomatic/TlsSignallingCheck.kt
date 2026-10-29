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
import org.sipral.SipralDomainRules
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

/** A key store whose `registrar` entry the registrar serves with: the
 * secondary constructor makes one self-signed certificate for
 * [SERVER_NAME] with keytool; [start] dates it, as keytool reads
 * `-startdate`, and [names] is its `subjectAltName` as keytool writes one. */
private class Credential(val store: KeyStore) {
    val certificate: X509Certificate = store.getCertificate("registrar") as X509Certificate

    constructor(
        directory: File,
        name: String,
        start: String?,
        days: Int,
        names: String = "dns:$SERVER_NAME",
    ) : this(selfSigned(directory, name, start, days, names))

    /** The context a registrar serves with; with [clients], one that trusts
     * that authority alone for the certificate a client presents. */
    fun serverContext(clients: X509Certificate? = null): SSLContext {
        val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        keys.init(store, "changeit".toCharArray())
        val trust = clients?.let { authority ->
            val anchors = KeyStore.getInstance("PKCS12").apply {
                load(null, null)
                setCertificateEntry("clients", authority)
            }
            javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm())
                .apply { init(anchors) }.trustManagers
        }
        return SSLContext.getInstance("TLS").apply { init(keys.keyManagers, trust, null) }
    }
}

private fun selfSigned(directory: File, name: String, start: String?, days: Int, names: String): KeyStore {
    val file = File(directory, "$name.p12")
    val keytool = File(System.getProperty("java.home"), "bin/keytool").path
    val command = mutableListOf(
        keytool, "-genkeypair", "-alias", "registrar", "-keyalg", "EC", "-groupname", "secp256r1",
        "-dname", "CN=$SERVER_NAME", "-ext", "SAN=$names", "-ext", "EKU=serverAuth",
        "-validity", days.toString(), "-storetype", "PKCS12", "-keystore", file.path,
        "-storepass", "changeit", "-keypass", "changeit",
    )
    if (start != null) {
        command += listOf("-startdate", start)
    }
    val made = ProcessBuilder(command).redirectErrorStream(true).start()
    val said = made.inputStream.readBytes().toString(Charsets.UTF_8)
    check(made.waitFor(60, TimeUnit.SECONDS) && made.exitValue() == 0) { "keytool: $said" }
    return KeyStore.getInstance("PKCS12").apply { file.inputStream().use { load(it, "changeit".toCharArray()) } }
}

/**
 * A registrar's credential under an intermediate that may name `corp.test`
 * and the names under it alone, made with keytool in [directory]: a root,
 * the intermediate it signs, and the registrar's key the intermediate
 * certifies with [names] as its `subjectAltName`, held with that chain so
 * the handshake sends the intermediate. The root is for the client to trust.
 */
private fun constrained(directory: File, name: String, names: String): Pair<Credential, X509Certificate> {
    val password = "changeit"
    fun store(file: String, alias: String, dname: String, vararg ext: String) = keytool(
        directory, "-genkeypair", "-alias", alias, "-keyalg", "EC", "-groupname", "secp256r1",
        "-dname", dname, *ext, "-validity", "1", "-storetype", "PKCS12", "-keystore", file,
        "-storepass", password, "-keypass", password,
    )
    fun signed(file: String, alias: String, by: String, out: String, vararg ext: String) {
        keytool(directory, "-certreq", "-alias", alias, "-keystore", file, "-storepass", password, "-file", "$out.csr")
        keytool(
            directory, "-gencert", "-rfc", "-alias", "authority", "-keystore", by, "-storepass", password,
            "-infile", "$out.csr", "-outfile", "$out.pem", *ext, "-validity", "1",
        )
    }
    fun imported(file: String, alias: String, pem: String) = keytool(
        directory, "-importcert", "-noprompt", "-alias", alias, "-file", pem, "-keystore", file, "-storepass", password,
    )
    val root = "$name-root.p12"
    store(root, "authority", "CN=Sipral $name root", "-ext", "bc:c=ca:true", "-ext", "ku:c=keyCertSign,cRLSign")
    keytool(directory, "-exportcert", "-rfc", "-alias", "authority", "-keystore", root, "-storepass", password, "-file", "$name-root.pem")
    val middle = "$name-middle.p12"
    store(middle, "authority", "CN=Sipral $name intermediate")
    // nameConstraints (RFC 5280 §4.2.1.10): permittedSubtrees, one dNSName, corp.test
    signed(
        middle, "authority", root, "$name-middle",
        "-ext", "bc:c=ca:true", "-ext", "ku:c=keyCertSign,cRLSign", "-ext", "2.5.29.30:c=300fa00d300b8209636f72702e74657374",
    )
    imported(middle, "root", "$name-root.pem")
    imported(middle, "authority", "$name-middle.pem")
    val server = "$name-server.p12"
    store(server, "registrar", "CN=pbx.corp.test")
    signed(server, "registrar", middle, "$name-server", "-ext", "SAN=$names", "-ext", "EKU=serverAuth")
    imported(server, "root", "$name-root.pem")
    imported(server, "middle", "$name-middle.pem")
    imported(server, "registrar", "$name-server.pem")
    fun opened(file: String) =
        KeyStore.getInstance("PKCS12").apply { File(directory, file).inputStream().use { load(it, password.toCharArray()) } }
    return Credential(opened(server)) to opened(root).getCertificate("authority") as X509Certificate
}

/** A registrar on a TCP port of loopback, over TLS when given a
 * credential, answering every REGISTER 200; or, [plainToTls], one that
 * answers a TLS client in plain text. With [clients] it requires a client
 * certificate that authority signed, over [protocol] alone, and keeps the
 * subject of each one it accepted in [presented], and by the connection's
 * number in [presentedOn]. */
private class Registrar(
    credential: Credential? = null,
    private val plainToTls: Boolean = false,
    clients: X509Certificate? = null,
    protocol: String? = null,
) : AutoCloseable {
    private val listener: ServerSocket = if (credential != null) {
        credential.serverContext(clients).serverSocketFactory.createServerSocket(0, 50, InetAddress.getLoopbackAddress())
            .also { made ->
                made as SSLServerSocket
                if (clients != null) {
                    made.needClientAuth = true
                }
                if (protocol != null) {
                    made.enabledProtocols = arrayOf(protocol)
                }
            }
    } else {
        ServerSocket(0, 50, InetAddress.getLoopbackAddress())
    }
    private val connections = AtomicInteger(0)
    private val open: MutableList<Socket> = Collections.synchronizedList(ArrayList())
    val requests: MutableList<Pair<Int, String>> = Collections.synchronizedList(ArrayList())
    val presented: MutableList<String> = Collections.synchronizedList(ArrayList())
    val presentedOn: MutableMap<Int, String> = Collections.synchronizedMap(HashMap())

    /** How many connections reached it, refused handshakes included. */
    val accepted: Int
        get() = connections.get()

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
            if (socket is javax.net.ssl.SSLSocket && socket.needClientAuth) {
                // this end's handshake ends with the client's Finished, after
                // its certificate was checked; a refusal throws here
                socket.startHandshake()
                val subject = (socket.session.peerCertificates[0] as X509Certificate).subjectX500Principal.name
                presentedOn[number] = subject
                presented += subject
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
    certificate: SipralClientCertificate? = null,
    rules: SipralDomainRules = SipralDomainRules.PLATFORM,
): SipralClient = SipralClient.open(
    audio = SipralAudioMode.Application,
    signalling = signalling,
    signallingServer = server,
    tlsServerName = name,
    tlsTrust = trust,
    tlsDomainRules = rules,
    clientCertificate = certificate,
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

/** RFC 5922 §7.1's own form, a `sip:` URI the HTTPS rules never read, is
 * trusted; a wildcard is, unless RFC 5922 alone is asked for. */
private suspend fun aSipUriNamesTheDomainAndRfc5922AloneRefusesAWildcard(directory: File): String {
    val byUri = Credential(directory, "uri", null, 1, names = "uri:sip:$SERVER_NAME")
    Registrar(byUri).use { registrar ->
        for (rules in SipralDomainRules.entries) {
            over(registrar.address, trust = SipralTlsTrust.OnlyAuthority(byUri.certificate), rules = rules).use {
                assertTrue(it.connected, "$rules refused a sip: URI naming the domain")
            }
        }
    }
    val wildcard = Credential(directory, "wildcard", null, 1, names = "dns:*.sipral.test")
    Registrar(wildcard).use { registrar ->
        over(registrar.address, trust = SipralTlsTrust.OnlyAuthority(wildcard.certificate)).use {
            assertTrue(it.connected, "the HTTPS rules' wildcard was refused")
        }
        over(
            registrar.address, trust = SipralTlsTrust.OnlyAuthority(wildcard.certificate),
            rules = SipralDomainRules.RFC5922,
        ).use {
            val failed = refusal(it)
            assertEquals(SipralTlsFailure.NAME_MISMATCH.value.toLong(), failed.tls)
            assertTrue(failed.detail?.contains("wildcard") == true, failed.detail ?: "")
        }
    }
    return "a sip: URI naming the domain is trusted, and a wildcard is refused under RFC 5922 alone"
}

/** A `sip:` URI is held to the name constraints of the intermediate the
 * server sends, which PKIX checks a `dNSName` against and skips for a URI:
 * one constrained to `corp.test` vouches for `sip:pbx.corp.test` and never
 * for `sip:`[SERVER_NAME]. */
private suspend fun aSipUriTheIntermediateMayNotNameIsRefused(directory: File): String {
    val (outside, outsideRoot) = constrained(directory, "outside", "uri:sip:$SERVER_NAME")
    Registrar(outside).use { registrar ->
        for (rules in SipralDomainRules.entries) {
            over(registrar.address, trust = SipralTlsTrust.OnlyAuthority(outsideRoot), rules = rules).use {
                val failed = refusal(it)
                assertEquals(SipralTlsFailure.NAME_MISMATCH.value.toLong(), failed.tls, "$rules: ${failed.detail}")
            }
        }
    }
    val (inside, insideRoot) = constrained(directory, "inside", "uri:sip:pbx.corp.test")
    Registrar(inside).use { registrar ->
        for (rules in SipralDomainRules.entries) {
            over(registrar.address, name = "pbx.corp.test", trust = SipralTlsTrust.OnlyAuthority(insideRoot), rules = rules).use {
                assertTrue(it.connected, "$rules refused a sip: URI inside the intermediate's constraint")
            }
        }
    }
    return "a sip: URI the intermediate may not name is refused, and one it may is trusted"
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

/** An account on its own TLS connection, its server named by a URI and
 * located by SRV at an address: the certificate is checked against the
 * URI's domain, as RFC 5922 §7.3 has it, not against the address, and a
 * `tlsServerName` the application gives still wins. */
private suspend fun aServerLocatedBySrvIsCheckedAgainstItsSipDomain(good: Credential): String {
    Registrar(good).use { tls ->
        val port = tls.address.substringAfterLast(':')
        val asked = Collections.synchronizedList(ArrayList<String>())
        val resolver: SipralResolver = { name, record ->
            asked += "$record $name"
            when {
                record == org.sipral.SipralDnsRecordType.SRV && name.endsWith(".$SERVER_NAME") ->
                    SipralLookup(org.sipral.SipralDnsAnswer.RECORDS, listOf("300 10 60 $port host.sipral.test"))
                record == org.sipral.SipralDnsRecordType.A && name == "host.sipral.test" ->
                    SipralLookup(org.sipral.SipralDnsAnswer.RECORDS, listOf("300 127.0.0.1"))
                else -> SipralLookup.NOTHING
            }
        }
        fun client(name: String?) = SipralClient.open(
            audio = SipralAudioMode.Application, bindHost = "127.0.0.1", resolver = resolver,
            tlsTrust = SipralTlsTrust.OnlyAuthority(good.certificate), tlsServerName = name,
        )
        fun SipralClient.account() = addAccount(
            aor = "sip:alice@$SERVER_NAME", registrar = "sip:$SERVER_NAME", serverUri = "sip:$SERVER_NAME",
            streamProtocol = SipralTransport.TLS,
        )
        client(null).use { client ->
            val account = client.account()
            account.register()
            registered(client, account)
            assertEquals(tls.address, account.registrarAddress, "located at the SRV record's address")
            assertTrue(asked.any { it.startsWith("SRV ") }, "$asked")
            val (_, register) = tls.registers().first()
            assertTrue(header("Via", register)!!.startsWith("SIP/2.0/TLS "), register)
        }
        client("other.sipral.test").use { client ->
            val (_, event) = client.events.awaitNext(SipralEventKind.TRANSPORT_FAILED, timeoutMs = 10_000) {
                client.account().register()
            }
            assertEquals(SipralTlsFailure.NAME_MISMATCH.value.toLong(), assertNotNull(transportFailedOf(event)).tls)
        }
    }
    return "a server located by SRV is checked against its SIP domain, and a given name still wins"
}

/** Two accounts whose SIP domains SRV places at one address, on their own
 * TLS connections, against a server whose certificate names the first
 * domain alone: each gets a connection checked against its own domain, so
 * the first registers, the second is refused for the name rather than
 * riding the first one's connection, and the first goes on working. */
private suspend fun accountsOfTwoDomainsAtOneAddressAreEachHeldToTheirOwnDomain(good: Credential): String {
    val tenant = "tenant.sipral.test"
    Registrar(good).use { tls ->
        val port = tls.address.substringAfterLast(':')
        val resolver: SipralResolver = { name, record ->
            when {
                record == org.sipral.SipralDnsRecordType.SRV && (name.endsWith(".$SERVER_NAME") || name.endsWith(".$tenant")) ->
                    SipralLookup(org.sipral.SipralDnsAnswer.RECORDS, listOf("300 10 60 $port host.sipral.test"))
                record == org.sipral.SipralDnsRecordType.A && name == "host.sipral.test" ->
                    SipralLookup(org.sipral.SipralDnsAnswer.RECORDS, listOf("300 127.0.0.1"))
                else -> SipralLookup.NOTHING
            }
        }
        SipralClient.open(
            audio = SipralAudioMode.Application, bindHost = "127.0.0.1", resolver = resolver,
            tlsTrust = SipralTlsTrust.OnlyAuthority(good.certificate),
        ).use { client ->
            fun SipralClient.account(user: String, domain: String) = addAccount(
                aor = "sip:$user@$domain", registrar = "sip:$domain", serverUri = "sip:$domain",
                streamProtocol = SipralTransport.TLS,
            )
            val first = client.account("alice", SERVER_NAME)
            first.register()
            registered(client, first)
            val (connection, _) = tls.registers().single()

            val second = client.account("bob", tenant)
            val (_, event) = client.events.awaitNext(SipralEventKind.TRANSPORT_FAILED, timeoutMs = 10_000) {
                second.register()
            }
            val refused = assertNotNull(transportFailedOf(event))
            assertEquals(SipralTlsFailure.NAME_MISMATCH.value.toLong(), refused.tls, refused.detail ?: "")
            assertEquals(tls.address, second.registrarAddress, "located at the same address")
            assertNotEquals(SipralRegistrationState.REGISTERED, second.registrationState)
            assertTrue(tls.registers().none { it.second.contains("sip:bob@") }, "the second tenant never reached the server")
            assertEquals(2, tls.accepted, "a connection for each domain")

            client.placeCall(first, "sip:carol@$SERVER_NAME").use {
                assertTrue(
                    eventually { tls.all().any { it.second.startsWith("INVITE sip:carol@") } },
                    "the first tenant's call never reached its server",
                )
                val invite = tls.all().first { it.second.startsWith("INVITE ") }
                assertEquals(connection, invite.first, "the call went over the first tenant's connection")
            }
        }
    }
    return "accounts of two domains at one address are each held to their own domain"
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

/** keytool, run in [directory], or the check fails with what it said. */
private fun keytool(directory: File, vararg arguments: String) {
    val command = listOf(File(System.getProperty("java.home"), "bin/keytool").path) + arguments
    val made = ProcessBuilder(command).directory(directory).redirectErrorStream(true).start()
    val said = made.inputStream.readBytes().toString(Charsets.UTF_8)
    check(made.waitFor(60, TimeUnit.SECONDS) && made.exitValue() == 0) { "keytool ${arguments.first()}: $said" }
}

/**
 * Client certificates for the checks, made with keytool in [directory]:
 * an authority the registrar trusts for its clients and a P-256 key it
 * certified for `clientAuth`; another authority and a key it certified; and
 * a certificate that expired in 2020. Each key is in a PKCS#12 store with
 * its chain, the way an application holds one on a desktop JVM.
 */
private class ClientIdentities(private val directory: File) {
    val authority: X509Certificate = authority("clients")
    val signed: KeyStore = certified("alice", "clients")
    val another: KeyStore = certified("bob", "clients")
    val stranger: KeyStore = run {
        authority("strangers")
        certified("mallory", "strangers")
    }
    val expired: KeyStore = run {
        keytool(
            directory, "-genkeypair", "-alias", "client", "-keyalg", "EC", "-groupname", "secp256r1",
            "-dname", "CN=expired client", "-ext", "EKU=clientAuth", "-startdate", "2020/01/01 00:00:00",
            "-validity", "1", "-storetype", "PKCS12", "-keystore", "expired.p12", "-storepass", PASSWORD,
        )
        opened("expired.p12")
    }

    private fun authority(name: String): X509Certificate {
        keytool(
            directory, "-genkeypair", "-alias", "authority", "-keyalg", "EC", "-groupname", "secp256r1",
            "-dname", "CN=Sipral $name authority", "-ext", "bc:c", "-validity", "1",
            "-storetype", "PKCS12", "-keystore", "$name.p12", "-storepass", PASSWORD,
        )
        keytool(directory, "-exportcert", "-rfc", "-alias", "authority", "-keystore", "$name.p12", "-storepass", PASSWORD, "-file", "$name.pem")
        return opened("$name.p12").getCertificate("authority") as X509Certificate
    }

    private fun certified(who: String, by: String): KeyStore {
        val store = "$who.p12"
        keytool(
            directory, "-genkeypair", "-alias", "client", "-keyalg", "EC", "-groupname", "secp256r1",
            "-dname", "CN=$who client", "-validity", "1", "-storetype", "PKCS12", "-keystore", store, "-storepass", PASSWORD,
        )
        keytool(directory, "-certreq", "-alias", "client", "-keystore", store, "-storepass", PASSWORD, "-file", "$who.csr")
        keytool(
            directory, "-gencert", "-rfc", "-alias", "authority", "-keystore", "$by.p12", "-storepass", PASSWORD,
            "-infile", "$who.csr", "-outfile", "$who.pem", "-ext", "EKU=clientAuth", "-validity", "1",
        )
        keytool(directory, "-importcert", "-noprompt", "-alias", "authority", "-file", "$by.pem", "-keystore", store, "-storepass", PASSWORD)
        keytool(directory, "-importcert", "-alias", "client", "-file", "$who.pem", "-keystore", store, "-storepass", PASSWORD)
        return opened(store)
    }

    private fun opened(name: String): KeyStore =
        KeyStore.getInstance("PKCS12").apply { File(directory, name).inputStream().use { load(it, PASSWORD.toCharArray()) } }

    fun of(store: KeyStore, alias: String = "client"): SipralClientCertificate =
        SipralClientCertificate.keyStore(store, alias, PASSWORD.toCharArray())

    companion object {
        const val PASSWORD = "changeit"
    }
}

/** A registrar that requires a client certificate over [protocol]: the one
 * the right authority signed registers, and the server saw it. */
private suspend fun aCertificateTheServerTrustsRegisters(good: Credential, ids: ClientIdentities, protocol: String) {
    Registrar(good, clients = ids.authority, protocol = protocol).use { registrar ->
        over(registrar.address, trust = SipralTlsTrust.OnlyAuthority(good.certificate), certificate = ids.of(ids.signed)).use { client ->
            val account = client.addAccount(
                aor = "sip:alice@$SERVER_NAME", registrarAddress = registrar.address, registrar = "sip:$SERVER_NAME",
            )
            account.register()
            registered(client, account)
            assertEquals(listOf("CN=alice client"), registrar.presented.toList())
            assertTrue(header("Via", registrar.registers().single().second)!!.startsWith("SIP/2.0/TLS "))
        }
    }
}

/** What a client the registrar refuses is told, over [protocol]. */
private suspend fun refusedFor(
    good: Credential,
    ids: ClientIdentities,
    protocol: String,
    certificate: SipralClientCertificate?,
): Pair<org.sipral.SipralTransportFailedEvent, Int> {
    Registrar(good, clients = ids.authority, protocol = protocol).use { registrar ->
        over(registrar.address, trust = SipralTlsTrust.OnlyAuthority(good.certificate), certificate = certificate).use { client ->
            val failed = refusal(client)
            assertTrue(registrar.presented.isEmpty(), "the registrar accepted ${registrar.presented}")
            return failed to registrar.accepted
        }
    }
}

private suspend fun eachClientCertificateRefusalSaysWhy(good: Credential, ids: ClientIdentities): String {
    for (protocol in listOf("TLSv1.3", "TLSv1.2")) {
        aCertificateTheServerTrustsRegisters(good, ids, protocol)
        val (none, _) = refusedFor(good, ids, protocol, null)
        assertEquals(SipralTlsFailure.CLIENT_CERTIFICATE_REQUIRED.value.toLong(), none.tls, "$protocol: ${none.detail}")
        assertEquals(SipralTransportError.CONNECTION_RESET.value.toLong(), none.error)
        val (stranger, _) = refusedFor(good, ids, protocol, ids.of(ids.stranger))
        assertEquals(SipralTlsFailure.CLIENT_CERTIFICATE_REFUSED.value.toLong(), stranger.tls, "$protocol: ${stranger.detail}")
        assertFalse(stranger.detail.isNullOrEmpty(), "the platform's own words come with it")
    }
    val (expired, reachedExpired) = refusedFor(good, ids, "TLSv1.3", ids.of(ids.expired))
    assertEquals(SipralTlsFailure.CLIENT_CERTIFICATE_EXPIRED.value.toLong(), expired.tls, expired.detail ?: "")
    assertEquals(SipralTransportError.OTHER.value.toLong(), expired.error)
    assertEquals(0, reachedExpired, "an expired certificate is not taken to the server")
    val (missing, reachedMissing) = refusedFor(good, ids, "TLSv1.3", ids.of(ids.signed, alias = "nobody"))
    assertEquals(SipralTlsFailure.CLIENT_KEY_UNAVAILABLE.value.toLong(), missing.tls, missing.detail ?: "")
    assertTrue(missing.detail?.contains("nobody") == true, missing.detail ?: "")
    assertEquals(0, reachedMissing, "a key that cannot be used costs no connection")
    val (wrongPassword, _) = refusedFor(
        good, ids, "TLSv1.3", SipralClientCertificate.keyStore(ids.signed, "client", "not it".toCharArray()),
    )
    assertEquals(SipralTlsFailure.CLIENT_KEY_UNAVAILABLE.value.toLong(), wrongPassword.tls, wrongPassword.detail ?: "")
    return "a client certificate the server trusts registers over TLS 1.3 and 1.2; none, a stranger's, " +
        "an expired one and an unusable key each say so"
}

/** An account on a TLS connection of its own presents its own certificate,
 * and one that presents none hears the server wanted one, on its own
 * transport. */
private suspend fun anAccountOnItsOwnConnectionPresentsItsCertificate(good: Credential, ids: ClientIdentities): String {
    val pin = java.security.MessageDigest.getInstance("SHA-256").digest(good.certificate.encoded).joinToString("") { "%02x".format(it) }
    Registrar(good, clients = ids.authority, protocol = "TLSv1.3").use { registrar ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
            val account = client.addAccount(
                aor = "sip:alice@$SERVER_NAME", registrarAddress = registrar.address, registrar = "sip:$SERVER_NAME",
                tlsPin = pin, streamProtocol = SipralTransport.TLS, clientCertificate = ids.of(ids.signed),
            )
            account.register()
            registered(client, account)
            assertEquals(listOf("CN=alice client"), registrar.presented.toList())
        }
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
            val account = client.addAccount(
                aor = "sip:bob@$SERVER_NAME", registrarAddress = registrar.address, registrar = "sip:$SERVER_NAME",
                tlsPin = pin, streamProtocol = SipralTransport.TLS,
            )
            val (_, event) = client.events.awaitNext(SipralEventKind.TRANSPORT_FAILED, timeoutMs = 10_000) { account.register() }
            val failed = assertNotNull(transportFailedOf(event))
            assertNotEquals(Sipral.TRANSPORT_MAIN, failed.transport)
            assertEquals(SipralTlsFailure.CLIENT_CERTIFICATE_REQUIRED.value.toLong(), failed.tls, failed.detail ?: "")
        }
    }
    return "an account on its own TLS connection presents its own certificate, and one with none hears it was wanted"
}

/** Two accounts at one registrar, one name and one pin, each with a client
 * certificate of its own: a connection presents one, and the server takes
 * all it carries as from the user it names, so each account registers over
 * a connection that presented its own. */
private suspend fun accountsWithCertificatesOfTheirOwnAtOneServerEachPresentTheirOwn(
    good: Credential,
    ids: ClientIdentities,
): String {
    val pin = java.security.MessageDigest.getInstance("SHA-256").digest(good.certificate.encoded).joinToString("") { "%02x".format(it) }
    Registrar(good, clients = ids.authority, protocol = "TLSv1.3").use { registrar ->
        SipralClient.open(
            audio = SipralAudioMode.Application, bindHost = "127.0.0.1", clientCertificate = ids.of(ids.stranger),
        ).use { client ->
            val users = listOf("alice" to ids.signed, "bob" to ids.another)
            val accounts = users.map { (user, store) ->
                client.addAccount(
                    aor = "sip:$user@$SERVER_NAME", registrarAddress = registrar.address, registrar = "sip:$SERVER_NAME",
                    tlsPin = pin, streamProtocol = SipralTransport.TLS, clientCertificate = ids.of(store),
                ).also { it.register() }
            }
            accounts.forEach { registered(client, it) }
            for ((user, _) in users) {
                val theirs = registrar.registers()
                    .filter { header("From", it.second)?.contains("sip:$user@") == true }
                    .map { registrar.presentedOn[it.first] }
                assertTrue(theirs.isNotEmpty(), "$user never registered")
                assertEquals(setOf("CN=$user client"), theirs.toSet(), "$user's REGISTER came on a connection that presented $theirs")
            }
            assertEquals(2, registrar.accepted, "a connection for each certificate")
        }
    }
    return "accounts with client certificates of their own at one server each present their own"
}

/** The alerts as each platform words them, and a key that could not sign,
 * read without a server: Conscrypt on Android is not on this JVM. */
private fun thePlatformsWordsForAnAlertAreRead(): String {
    fun alert(text: String) = receivedAlert(listOf(javax.net.ssl.SSLException(text)))
    assertEquals(42, alert("Received fatal alert: bad_certificate"))
    assertEquals(116, alert("Received fatal alert: certificate_required"))
    assertEquals(
        42,
        alert("Read error: ssl=0x7a: Failure in SSL library, usually a protocol error\nerror:10000412:SSL routines:OPENSSL_internal:SSLV3_ALERT_BAD_CERTIFICATE (external/boringssl/src/ssl/tls_record.cc:592 alert number 42)"),
    )
    assertEquals(116, alert("error:1000045c:SSL routines:OPENSSL_internal:TLSV1_ALERT_CERTIFICATE_REQUIRED"))
    assertEquals(48, alert("SSL handshake aborted: TLSV1_ALERT_UNKNOWN_CA"))
    assertEquals(45, alert("Received fatal alert: certificate_expired"))
    assertEquals(null, alert("PKIX path building failed: unable to find valid certification path to requested target"))

    val gave = ClientAuthentication().apply {
        asked.set(true)
        presented.set(true)
    }
    val locked = javax.net.ssl.SSLHandshakeException("Cannot produce CertificateVerify signature").apply {
        initCause(java.security.InvalidKeyException("User not authenticated"))
    }
    assertEquals(SipralTlsFailure.CLIENT_KEY_UNAVAILABLE, classify(locked, handshaking = true, auth = gave).tls)
    assertEquals(
        SipralTlsFailure.CLIENT_CERTIFICATE_EXPIRED,
        classify(javax.net.ssl.SSLException("Received fatal alert: certificate_expired"), false, gave).tls,
    )
    val wanted = ClientAuthentication().apply { asked.set(true) }
    assertEquals(
        SipralTlsFailure.CLIENT_CERTIFICATE_REQUIRED,
        classify(javax.net.ssl.SSLHandshakeException("Received fatal alert: handshake_failure"), true, wanted).tls,
    )
    assertEquals(
        SipralTlsFailure.HANDSHAKE_REFUSED,
        classify(javax.net.ssl.SSLHandshakeException("Received fatal alert: handshake_failure"), true, ClientAuthentication()).tls,
        "a handshake failure with no certificate asked for is not about one",
    )
    val dropped = classify(java.net.SocketException("Broken pipe"), true, wanted)
    assertEquals(SipralTlsFailure.CLIENT_CERTIFICATE_REQUIRED, dropped.tls)
    assertTrue(dropped.detail.contains("no alert"), dropped.detail)
    assertEquals(SipralTlsFailure.CLIENT_CERTIFICATE_REFUSED, classify(java.net.SocketException("Connection reset"), true, gave).tls)
    assertEquals(SipralTlsFailure.NONE, classify(java.net.SocketException("Connection reset"), true, ClientAuthentication()).tls)
    return "the platforms' words for an alert and a key that could not sign are read"
}

internal suspend fun tlsSignallingChecks(): String {
    val directory = Files.createTempDirectory("sipral-tls").toFile()
    try {
        val good = Credential(directory, "good", null, 1)
        val expired = Credential(directory, "expired", "2020/01/01 00:00:00", 1)
        val clients = ClientIdentities(directory)
        return listOf(
            eachClientCertificateRefusalSaysWhy(good, clients),
            anAccountOnItsOwnConnectionPresentsItsCertificate(good, clients),
            accountsWithCertificatesOfTheirOwnAtOneServerEachPresentTheirOwn(good, clients),
            thePlatformsWordsForAnAlertAreRead(),
            aRegistrarWhoseAuthorityIsPinnedRegistersOverTls(good),
            aPrivateAuthorityIsTrustedBesideThePlatforms(good),
            thePinnedCertificateIsTrustedWhateverItsNameAndSigner(good),
            everyFormAnAdministratorCopiesIsRead(),
            eachRefusalSaysWhy(good, expired),
            aSipUriNamesTheDomainAndRfc5922AloneRefusesAWildcard(directory),
            aSipUriTheIntermediateMayNotNameIsRefused(directory),
            aConnectionLostIsMadeAgainAndTheAccountRegistersOnIt(),
            aConnectionTheStackLetGoOfIsMadeAgain(),
            theVoiceAgentPresetTakesARushTheDefaultAnswers480(),
            anAccountOverTlsAndOneOverUdpEachReachTheirOwnServer(good),
            aServerLocatedBySrvIsCheckedAgainstItsSipDomain(good),
            accountsOfTwoDomainsAtOneAddressAreEachHeldToTheirOwnDomain(good),
            anAccountOverTcpIsOpenedAgainWhenItsServerDropsIt(),
            anAccountOverAWebSocketAsksForItsResourceAndHost(),
            theSettingsAreReadBack(),
        ).joinToString(", ")
    } finally {
        directory.deleteRecursively()
    }
}
