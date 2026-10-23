// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// SIP over TCP or TLS for SipralClient: TLS trust, the client's single
// signalling connection, and how a refused connection is classified. TLS is
// javax.net.ssl's, on the JVM and Android (docs/22-tls.md); nothing here
// turns its check off.

package org.sipral.idiomatic

import java.io.InputStream
import java.io.OutputStream
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.security.KeyStore
import java.security.cert.CertPathBuilderException
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager
import org.sipral.Sipral
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralStatus
import org.sipral.SipralTlsFailure
import org.sipral.SipralTransport
import org.sipral.SipralTransportError
import org.sipral.SipralTransportFailedEvent
import org.sipral.SipralTransportFailure
import org.sipral.SipralTransportWantedEvent

/**
 * Which authorities a TLS connection to the SIP server trusts
 * (`docs/22-tls.md`): [Platform] (the JVM's or Android's store),
 * [PrivateAuthority] (a private CA beside the platform's) or
 * [OnlyAuthority] (that CA alone). The name is always checked by the HTTPS
 * rules `SSLSocket` applies. [Pinned] instead trusts one certificate by
 * SHA-256 fingerprint, for a self-signed PBX.
 */
sealed class SipralTlsTrust {
    /** The platform's own trust anchors. */
    object Platform : SipralTlsTrust()

    /** The platform's anchors, and [authority] beside them. */
    class PrivateAuthority(val authority: X509Certificate) : SipralTlsTrust()

    /** [authority] alone: certificates from any other CA, the platform's
     * included, are refused. */
    class OnlyAuthority(val authority: X509Certificate) : SipralTlsTrust()

    /**
     * The one certificate whose SHA-256 fingerprint is [fingerprint]: 64 hex
     * digits in either case, colons and spaces ignored, optionally after
     * `sha-256 `, `SHA256=` or `SHA256 Fingerprint=` (as OpenSSL or RFC 8122
     * print it). Anything else throws [IllegalArgumentException]
     * (`bindings/fixtures/pin-forms.txt` lists the accepted forms). The
     * fingerprint is the whole verdict: no authority, name or date is checked,
     * and any other certificate is refused as untrusted. Compared in constant
     * time over the DER of the server's first certificate.
     */
    class Pinned(fingerprint: String) : SipralTlsTrust() {
        /** The 32 bytes the fingerprint names. */
        val digest: ByteArray = pinDigest(fingerprint)
    }

    companion object {
        /** The 32 bytes a fingerprint names, in any form [Pinned] takes. */
        fun pinDigest(fingerprint: String): ByteArray {
            var text = fingerprint.trim()
            val prefix = PIN_PREFIXES.firstOrNull { text.lowercase().startsWith(it) }
            if (prefix != null) {
                text = text.substring(prefix.length)
            }
            val digits = text.filter { it != ':' && it != ' ' }
            require(digits.length == 64 && digits.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
                "a certificate pin is a SHA-256 fingerprint: 64 hexadecimal digits, " +
                    "optionally after sha-256, SHA256= or SHA256 Fingerprint="
            }
            return ByteArray(32) { digits.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        }

        /** The prefixes a fingerprint may come after, lower case. */
        private val PIN_PREFIXES = listOf("sha256 fingerprint=", "sha-256 ", "sha256=")
    }

    /** The trust managers a handshake is checked with, the platform's first
     * where it applies. */
    internal fun trustManagers(): List<X509ExtendedTrustManager> {
        fun of(store: KeyStore?): X509ExtendedTrustManager {
            val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            factory.init(store)
            return factory.trustManagers.filterIsInstance<X509ExtendedTrustManager>().first()
        }
        fun holding(authority: X509Certificate): KeyStore =
            KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null, null)
                setCertificateEntry("sipral-authority", authority)
            }
        return when (this) {
            Platform -> listOf(of(null))
            is PrivateAuthority -> listOf(of(null), of(holding(authority)))
            is OnlyAuthority -> listOf(of(holding(authority)))
            is Pinned -> emptyList()
        }
    }
}

/**
 * How fast one address may ring a client: [burst] INVITEs at once, then
 * one every [everyMs] (`sipral_stack_invite_limit`); past it a call is
 * answered 480. [DEFAULT] is ten then one per two seconds; [VOICE_AGENT],
 * for a headless service on a trunk, is 128 then twenty a second
 * (`docs/08-ffi.md`).
 */
data class SipralInviteLimit(val burst: Long, val everyMs: Long) {
    companion object {
        /** Ten at once, then one every two seconds. */
        val DEFAULT = SipralInviteLimit(Sipral.INVITE_LIMIT_BURST, Sipral.INVITE_LIMIT_EVERY_MS)

        /** A hundred and twenty-eight at once, then one every fifty
         * milliseconds. */
        val VOICE_AGENT = SipralInviteLimit(Sipral.INVITE_LIMIT_VOICE_AGENT_BURST, Sipral.INVITE_LIMIT_VOICE_AGENT_EVERY_MS)
    }
}

/**
 * The `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` payload (transport, protocol,
 * error and, when TLS refused, `tls` as a [SipralTlsFailure] with the TLS
 * library's `detail`), or null for another kind.
 */
fun transportFailedOf(event: SipralEvent): SipralTransportFailedEvent? =
    if (event.kind == SipralEventKind.TRANSPORT_FAILED.value.toLong()) event.payload.transportFailed else null

/**
 * The `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` payload (a request too large
 * for a datagram, RFC 3261 §18.1.1: destination, size, limit), or null for
 * another kind. A client opened with `streamFallback` opens the stream
 * itself.
 */
fun transportWantedOf(event: SipralEvent): SipralTransportWantedEvent? =
    if (event.kind == SipralEventKind.TRANSPORT_WANTED.value.toLong()) event.payload.transportWanted else null

/** A connection that could not be made, and what the stack is to call it. */
internal class SignallingRefused(
    val error: SipralTransportError,
    val tls: SipralTlsFailure,
    val detail: String,
) : Exception(detail)

/**
 * Classify a failed connection the way the stack names it. A refused
 * certificate is expired, name mismatch or untrusted; any other handshake
 * failure is a refused handshake. No answer is refused, no route
 * unreachable, silence timed out.
 */
internal fun classify(failure: Throwable, handshaking: Boolean, auth: ClientAuthentication? = null): SignallingRefused {
    val causes = generateSequence(failure) { it.cause }.toList()
    val detail = sentence(causes.lastOrNull { !it.message.isNullOrBlank() }?.message ?: failure.toString())
    fun tls(reason: SipralTlsFailure) = SignallingRefused(SipralTransportError.CONNECTION_RESET, reason, detail)
    clientCertificateVerdict(causes, auth)?.let { return tls(it) }
    if (handshaking && auth?.asked?.get() == true && receivedAlert(causes) == null &&
        causes.any { it is SocketException || it is java.io.EOFException }) {
        // the server asked for a certificate and dropped the connection on
        // the flight that answered it; its alert, if it sent one, went with
        // the reset
        val reason = if (auth.presented.get()) {
            SipralTlsFailure.CLIENT_CERTIFICATE_REFUSED
        } else {
            SipralTlsFailure.CLIENT_CERTIFICATE_REQUIRED
        }
        return SignallingRefused(
            SipralTransportError.CONNECTION_RESET, reason,
            sentence("the server asked for a client certificate and closed the connection, no alert reaching this end: $detail"),
        )
    }
    return when {
        causes.any { it is CertificateExpiredException || it is CertificateNotYetValidException } ->
            tls(SipralTlsFailure.EXPIRED)
        causes.any { it is CertPathBuilderException || it is CertPathValidatorException } ->
            tls(SipralTlsFailure.UNTRUSTED)
        causes.any { it is NameMismatch } -> tls(SipralTlsFailure.NAME_MISMATCH)
        causes.any { it is CertificateException } -> tls(SipralTlsFailure.UNTRUSTED)
        causes.any { it is SSLException } || (handshaking && failure is java.io.EOFException) ->
            tls(SipralTlsFailure.HANDSHAKE_REFUSED)
        failure is ConnectException -> SignallingRefused(SipralTransportError.CONNECTION_REFUSED, SipralTlsFailure.NONE, detail)
        failure is SocketTimeoutException -> SignallingRefused(SipralTransportError.TIMED_OUT, SipralTlsFailure.NONE, detail)
        failure is NoRouteToHostException -> SignallingRefused(SipralTransportError.UNREACHABLE, SipralTlsFailure.NONE, detail)
        failure is SocketException -> SignallingRefused(SipralTransportError.CONNECTION_RESET, SipralTlsFailure.NONE, detail)
        else -> SignallingRefused(SipralTransportError.OTHER, SipralTlsFailure.NONE, detail)
    }
}

/**
 * The TLS alert the server sent, as RFC 8446 §6 numbers it, read from the
 * platform's sentence: JSSE writes `Received fatal alert: bad_certificate`,
 * Conscrypt on Android (BoringSSL) `SSLV3_ALERT_BAD_CERTIFICATE` or
 * `TLSV1_ALERT_CERTIFICATE_REQUIRED`. Null when no received alert is named.
 */
internal fun receivedAlert(causes: List<Throwable>): Int? {
    for (cause in causes) {
        val text = cause.message?.lowercase() ?: continue
        val name = RECEIVED_ALERT.find(text)?.groupValues?.get(1) ?: continue
        ALERTS[name]?.let { return it }
    }
    return null
}

private val RECEIVED_ALERT = Regex("(?:received fatal alert:\\s*|alert_)([a-z_]+)")

private val ALERTS = mapOf(
    "handshake_failure" to 40,
    "bad_certificate" to 42,
    "unsupported_certificate" to 43,
    "certificate_revoked" to 44,
    "certificate_expired" to 45,
    "certificate_unknown" to 46,
    "unknown_ca" to 48,
    "access_denied" to 49,
    "certificate_required" to 116,
)

/** Alerts a server sends about the certificate it was given, or not given. */
private val ABOUT_THE_CLIENT = setOf(42, 43, 44, 46, 48, 49, 116)

/**
 * What a failure says about this end's certificate, or null when it says
 * nothing about it: the key could not sign (locked, the user not
 * authenticated, invalidated by the platform), or the server's alert
 * refused the certificate given, wanted one when none was, or found it
 * expired. [auth] is what the handshake did; without it nothing was asked.
 */
private fun clientCertificateVerdict(causes: List<Throwable>, auth: ClientAuthentication?): SipralTlsFailure? {
    val presented = auth?.presented?.get() == true
    val asked = auth?.asked?.get() == true
    if (presented && causes.any { it is java.security.InvalidKeyException || it is java.security.SignatureException ||
            it is java.security.KeyStoreException || it is java.security.UnrecoverableKeyException ||
            it is java.security.ProviderException }) {
        return SipralTlsFailure.CLIENT_KEY_UNAVAILABLE
    }
    val alert = receivedAlert(causes) ?: return null
    return when {
        presented && alert == 45 -> SipralTlsFailure.CLIENT_CERTIFICATE_EXPIRED
        presented && alert in ABOUT_THE_CLIENT -> SipralTlsFailure.CLIENT_CERTIFICATE_REFUSED
        !presented && (alert in ABOUT_THE_CLIENT || (alert == 40 && asked)) -> SipralTlsFailure.CLIENT_CERTIFICATE_REQUIRED
        else -> null
    }
}

/** One line of at most `SIPRAL_TRANSPORT_DETAIL_BYTES` bytes of UTF-8. */
internal fun sentence(text: String): String {
    var line = text.map { if (it.isISOControl()) ' ' else it }.joinToString("").trim()
    while (line.toByteArray(Charsets.UTF_8).size > Sipral.TRANSPORT_DETAIL_BYTES) {
        line = line.dropLast(1)
    }
    return line
}

/** The certificate presented is not the pinned one: untrusted. */
private class PinMismatch : CertificateException("the server's certificate is not the pinned one")

/**
 * The pin as the whole verdict: SHA-256 of the server's first certificate
 * against [digest], in constant time; no chain, name or date.
 */
private class PinChecking(private val digest: ByteArray) : X509ExtendedTrustManager() {
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket?) {
        val leaf = chain.firstOrNull()?.encoded ?: ByteArray(0)
        if (!java.security.MessageDigest.isEqual(java.security.MessageDigest.getInstance("SHA-256").digest(leaf), digest)) {
            throw PinMismatch()
        }
    }

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine?) =
        checkServerTrusted(chain, authType, null as Socket?)

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) =
        checkServerTrusted(chain, authType, null as Socket?)

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket?) =
        throw CertificateException("a SIP client does not accept connections")

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine?) =
        throw CertificateException("a SIP client does not accept connections")

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
        throw CertificateException("a SIP client does not accept connections")

    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}

/** A trusted certificate naming another server, which `SSLSocket` reports
 * with the same exception type as an untrusted one. */
private class NameMismatch(cause: CertificateException) : CertificateException(cause.message, cause)

/**
 * The trust managers in turn: the first that accepts the chain decides,
 * and each one's error is kept for the reason. The name is checked here
 * after the chain is trusted, so a wrong name reads as a mismatch rather
 * than untrusted; and dates are checked on every certificate, including an
 * authority pinned as sole anchor, which PKIX alone does not.
 */
private class Checking(
    private val trust: List<X509ExtendedTrustManager>,
    private val serverName: String,
) : X509ExtendedTrustManager() {
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket?) {
        val refused = ArrayList<CertificateException>()
        for (manager in trust) {
            try {
                manager.checkServerTrusted(chain, authType, null as Socket?)
                refused.clear()
                break
            } catch (no: CertificateException) {
                refused.add(no)
            }
        }
        refused.firstOrNull()?.let { throw it }
        for (certificate in chain) {
            certificate.checkValidity()
        }
        try {
            checkName(chain[0], serverName)
        } catch (wrong: CertificateException) {
            throw NameMismatch(wrong)
        }
    }

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine?) =
        checkServerTrusted(chain, authType, null as Socket?)

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) =
        checkServerTrusted(chain, authType, null as Socket?)

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket?) =
        throw CertificateException("a SIP client does not accept connections")

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine?) =
        throw CertificateException("a SIP client does not accept connections")

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
        throw CertificateException("a SIP client does not accept connections")

    override fun getAcceptedIssuers(): Array<X509Certificate> = trust.flatMap { it.acceptedIssuers.toList() }.toTypedArray()
}

/**
 * The HTTPS name rules (RFC 6125, as `SSLSocket` applies them): a
 * `dNSName` equal to [name] ignoring case, wildcard only in the leftmost
 * label; an IP address against an `iPAddress` entry.
 */
private fun checkName(certificate: X509Certificate, name: String) {
    val entries = certificate.subjectAlternativeNames ?: emptyList()
    val literal = name.all { it.isDigit() || it == '.' } || name.contains(':')
    val matched = entries.any { entry ->
        val type = entry[0] as Int
        val value = entry[1] as? String ?: return@any false
        when {
            literal && type == 7 -> InetAddress.getByName(value) == InetAddress.getByName(name)
            !literal && type == 2 -> dnsMatches(value.lowercase(), name.lowercase().trimEnd('.'))
            else -> false
        }
    }
    if (!matched) {
        throw CertificateException("no subjectAltName of the certificate names $name")
    }
}

private fun dnsMatches(pattern: String, name: String): Boolean {
    if (!pattern.startsWith("*.")) {
        return pattern == name
    }
    val rest = pattern.substring(1)
    val dot = name.indexOf('.')
    return dot > 0 && name.substring(dot) == rest && rest.count { it == '.' } >= 2
}

/**
 * The one TCP/TLS connection a [SipralClient] signals on. Reconnected with
 * back-off whenever lost; each loss is reported to the stack
 * (`sipral_stack_transport_failed_with`), which raises
 * `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`.
 */
internal class SignallingLink(
    val protocol: SipralTransport,
    private val server: InetSocketAddress,
    private val serverName: String,
    trust: SipralTlsTrust,
    private val clientCertificate: SipralClientCertificate? = null,
) {
    private val checking: X509ExtendedTrustManager? = when {
        protocol != SipralTransport.TLS -> null
        trust is SipralTlsTrust.Pinned -> PinChecking(trust.digest)
        else -> Checking(trust.trustManagers(), serverName)
    }

    /** What the last attempt's handshake did about a client certificate. */
    private val auth = ClientAuthentication()

    /** A context for one attempt: the trust, and the client certificate read
     * again from where the platform keeps it, or the refusal to try. */
    private fun context(): SSLContext? {
        val trust = checking ?: return null
        auth.reset()
        val (key, chain) = clientCertificate?.load() ?: (null to null)
        return SSLContext.getInstance("TLS").apply { init(arrayOf(Presenting(key, chain, auth)), arrayOf(trust), null) }
    }

    /** [classify], told what the handshake did about a client certificate. */
    fun classifyHere(failure: Throwable, handshaking: Boolean): SignallingRefused =
        classify(failure, handshaking, if (checking != null) auth else null)

    private class Open(val socket: Socket, val local: String, val remote: String) {
        val input: InputStream = socket.getInputStream()
        val output: OutputStream = socket.getOutputStream()
    }

    /** The client this connection serves. Set late: the first connection is
     * made before the stack, whose address it supplies. */
    lateinit var owner: SipralClient

    private val client: SipralClient
        get() = owner

    private val current = AtomicReference<Open?>(null)
    private val reconnecting = AtomicBoolean(false)

    /** The local address to connect from; null for the route toward the
     * server. */
    @Volatile
    var bindHost: String? = null

    /** Whether the connection stands. */
    val connected: Boolean
        get() = current.get() != null

    /** What goes after the address in a `Contact` this layer writes. */
    val contactParameters: String
        get() = if (protocol == SipralTransport.TLS) ";transport=tls" else ";transport=tcp"

    /** One connection from [host], with `local` and `remote`, or the refusal. */
    fun connect(host: String?): Pair<Socket, Pair<String, String>> {
        val context = context()
        val raw = Socket()
        var handshaking = false
        try {
            if (host != null) {
                raw.bind(InetSocketAddress(InetAddress.getByName(host), 0))
            }
            raw.connect(server, PATIENCE_MS)
            raw.tcpNoDelay = true
            val socket = if (context != null) {
                handshaking = true
                (context.socketFactory.createSocket(raw, serverName, server.port, true) as SSLSocket).apply {
                    soTimeout = PATIENCE_MS
                    sslParameters = sslParameters.apply {
                        serverNames = listOf(SNIHostName(serverName))
                    }
                    val started = System.nanoTime()
                    startHandshake()
                    awaitVerdict(this, (System.nanoTime() - started) / 1_000_000)
                    soTimeout = 0
                }
            } else {
                raw
            }
            val local = formatAddress(raw.localAddress.hostAddress, raw.localPort)
            val remote = formatAddress(raw.inetAddress.hostAddress, raw.port)
            return socket to (local to remote)
        } catch (refused: Exception) {
            try {
                raw.close()
            } catch (_: Exception) {
                // closed either way
            }
            throw classifyHere(refused, handshaking)
        }
    }

    /** What the server sent while [awaitVerdict] listened, for the stack once
     * the connection is bound; taken once. */
    @Volatile
    private var early: ByteArray? = null

    /** The bytes the server sent before the connection was handed over. */
    fun takeEarly(): ByteArray? = early.also { early = null }

    /**
     * A TLS 1.3 server judges the client certificate after this end's
     * handshake is over (RFC 8446 §4.4.2), so a refusal comes as an alert
     * one round trip later; a request written meanwhile meets a connection
     * the server has already reset, and the alert is lost with it. When the
     * server asked for a certificate, listen first, for twice as long as
     * the handshake took (a quarter to three seconds): an alert is thrown
     * here and classified, bytes are kept for the stack, and silence is the
     * server accepting.
     */
    private fun awaitVerdict(socket: SSLSocket, handshakeMs: Long) {
        early = null
        if (!auth.asked.get() || socket.session.protocol != "TLSv1.3") {
            return
        }
        socket.soTimeout = (handshakeMs * 2).coerceIn(VERDICT_LEAST_MS, VERDICT_MOST_MS).toInt()
        val buffer = ByteArray(1 shl 16)
        val read = try {
            socket.inputStream.read(buffer)
        } catch (_: SocketTimeoutException) {
            return
        }
        if (read < 0) {
            throw java.io.EOFException("the server closed the connection when its handshake ended")
        }
        early = buffer.copyOfRange(0, read)
    }

    /** Tell the stack a connection is open, naming both ends, and read it on
     * its own thread. */
    fun install(socket: Socket, local: String, remote: String) {
        try {
            retryBusy { Sipral.stackTransportBind(client.handle, 0, protocol.value.toLong(), local, remote, client.nowMs()) }
        } catch (refused: SipralException) {
            socket.close()
            throw refused
        }
        val open = Open(socket, local, remote)
        client.linkBound(local)
        current.set(open)
        takeEarly()?.let { bytes ->
            try {
                retryBusy(deadlineMs = 5_000) { Sipral.stackReceiveStream(client.handle, 0, bytes, client.nowMs()) }
            } catch (_: SipralException) {
                // framing lost: the stack retired the transport and reported it
                lose(open, null, tell = false)
                return
            }
        }
        Thread({ read(open) }, "sipral-signalling").apply {
            isDaemon = true
            start()
        }
    }

    /** `sipral_stack_transport_failed_with`, never throwing on the way out. */
    fun report(refused: SignallingRefused) {
        try {
            retryBusy {
                Sipral.stackTransportFailedWith(
                    client.handle,
                    SipralTransportFailure(
                        transport = 0,
                        error = refused.error.value.toLong(),
                        tls = if (protocol == SipralTransport.TLS) refused.tls.value.toLong() else 0L,
                        detail = refused.detail.takeIf { it.isNotEmpty() },
                    ),
                    client.nowMs(),
                )
            }
        } catch (_: SipralException) {
            // the stack is going away
        }
    }

    /** Write one message whole; a failed write loses it. */
    fun write(payload: ByteArray, len: Int) {
        val open = current.get() ?: return
        try {
            synchronized(open) {
                open.output.write(payload, 0, len)
                open.output.flush()
            }
        } catch (broken: Exception) {
            lose(open, classifyHere(broken, handshaking = false), tell = true)
        }
    }

    private fun read(open: Open) {
        val buffer = ByteArray(1 shl 16)
        while (!client.isClosed) {
            val read = try {
                open.input.read(buffer)
            } catch (broken: Exception) {
                // a TLS 1.3 server's verdict on the client certificate comes
                // after this end's handshake finished, as the first read's alert
                lose(open, classifyHere(broken, handshaking = false), tell = true)
                return
            }
            if (read < 0) {
                lose(open, null, tell = true)
                return
            }
            if (read == 0) {
                continue
            }
            val bytes = buffer.copyOfRange(0, read)
            val kept = try {
                retryBusy(deadlineMs = 5_000) { Sipral.stackReceiveStream(client.handle, 0, bytes, client.nowMs()) }
                true
            } catch (refused: SipralException) {
                refused.status == SipralStatus.BUSY || refused.status == SipralStatus.CLOCK_BEHIND
            }
            if (!kept) {
                // framing lost: the stack retired the transport and reported it
                lose(open, null, tell = false)
                return
            }
        }
    }

    /** Close [open] if it is still current, report how it ended
     * (`sipral_stack_stream_closed` for an orderly close, else
     * `sipral_stack_transport_failed_with`; nothing unless [tell]), and
     * reconnect. */
    private fun lose(open: Open, refused: SignallingRefused?, tell: Boolean) {
        if (!current.compareAndSet(open, null)) {
            return
        }
        try {
            synchronized(open) { open.socket.close() }
        } catch (_: Exception) {
            // closed either way
        }
        if (client.isClosed) {
            return
        }
        if (tell && refused == null) {
            try {
                retryBusy { Sipral.stackStreamClosed(client.handle, 0, client.nowMs()) }
            } catch (_: SipralException) {
                // the stack is going away
            }
        } else if (tell && refused != null) {
            report(refused)
        }
        reconnectLater()
    }

    /** Close the connection the stack let go of, if still current, and
     * reconnect; the stack already knows. */
    fun letGo() {
        current.get()?.let { lose(it, null, tell = false) }
    }

    /** Start the thread that connects again, unless one runs. */
    fun reconnectLater() {
        if (client.isClosed || !reconnecting.compareAndSet(false, true)) {
            return
        }
        Thread(::reconnect, "sipral-reconnect").apply {
            isDaemon = true
            start()
        }
    }

    private fun reconnect() {
        var delay = FIRST_MS
        try {
            while (!client.isClosed) {
                Thread.sleep(delay)
                delay = minOf(delay * 2, MOST_MS)
                if (client.isClosed) {
                    return
                }
                val (socket, ends) = try {
                    connect(bindHost)
                } catch (refused: SignallingRefused) {
                    report(refused)
                    continue
                }
                try {
                    install(socket, ends.first, ends.second)
                } catch (_: SipralException) {
                    continue
                }
                client.afterReconnect()
                return
            }
        } catch (_: InterruptedException) {
            // the client is closing
        } finally {
            reconnecting.set(false)
        }
    }

    /** Reconnect from [host] after a network change; if that fails the stack
     * hears why and retries continue. Returns the local address, or null. */
    fun move(host: String): String? {
        bindHost = host
        current.getAndSet(null)?.let { old ->
            try {
                synchronized(old) { old.socket.close() }
            } catch (_: Exception) {
                // closed either way
            }
        }
        return try {
            val (socket, ends) = connect(host)
            install(socket, ends.first, ends.second)
            ends.first
        } catch (refused: SignallingRefused) {
            report(refused)
            reconnectLater()
            null
        }
    }

    /** Close the connection, for [SipralClient.close]. */
    fun close() {
        current.getAndSet(null)?.let { open ->
            try {
                synchronized(open) { open.socket.close() }
            } catch (_: Exception) {
                // closed either way
            }
        }
    }

    companion object {
        /** How long one attempt may take, the TLS handshake included. */
        const val PATIENCE_MS = 5_000
        /** The bounds of the wait for a TLS 1.3 server's verdict on the
         * client certificate. */
        const val VERDICT_LEAST_MS = 250L
        const val VERDICT_MOST_MS = 3_000L
        /** The wait before the first reconnect, doubled per failure up to
         * [MOST_MS]. */
        const val FIRST_MS = 1_000L
        const val MOST_MS = 30_000L
    }
}
