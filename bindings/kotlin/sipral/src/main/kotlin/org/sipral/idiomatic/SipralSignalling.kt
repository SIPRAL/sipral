// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// SIP over TCP or TLS for SipralClient: which authorities a TLS connection
// trusts, the one connection a client signals on, and what a refused
// connection is called. The TLS is javax.net.ssl's own, on the JVM and on
// Android alike (docs/22-tls.md); nothing here turns its check off.

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
 * Which authorities a TLS connection to the SIP server trusts -- the three
 * answers `docs/22-tls.md` gives for every platform: [Platform] (the
 * JVM's or Android's own store, what a public server's certificate is
 * checked against), [PrivateAuthority] (a private CA beside the
 * platform's) and [OnlyAuthority] (that authority and no other: pinning
 * it). The name is checked against the server name the client was given,
 * by the HTTPS rules `SSLSocket` applies; none of them turns a check off.
 */
sealed class SipralTlsTrust {
    /** The platform's own trust anchors. */
    object Platform : SipralTlsTrust()

    /** The platform's anchors, and [authority] beside them. */
    class PrivateAuthority(val authority: X509Certificate) : SipralTlsTrust()

    /** [authority] and nothing else: a certificate any other authority
     * signed is refused, the platform's included. */
    class OnlyAuthority(val authority: X509Certificate) : SipralTlsTrust()

    /** The trust managers a handshake is checked with, the platform's
     * first where it counts at all. */
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
        }
    }
}

/**
 * How fast one address may ring a client: [burst] INVITEs at once, then one
 * more every [everyMs] (`sipral_stack_invite_limit`). [DEFAULT] is what
 * every client starts with -- ten, then one every two seconds, past which a
 * call is answered 480 -- and [VOICE_AGENT] the preset for a headless
 * service taking a trunk's calls, a hundred and twenty-eight at once and
 * then twenty a second (`docs/08-ffi.md`, "How fast one address may ring
 * this stack").
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
 * The `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` payload -- which transport, what
 * it spoke, what went wrong and, when TLS refused the connection, why
 * (`tls`, a [SipralTlsFailure] number) with the TLS library's own `detail`
 * -- or null for an event of any other kind.
 */
fun transportFailedOf(event: SipralEvent): SipralTransportFailedEvent? =
    if (event.kind == SipralEventKind.TRANSPORT_FAILED.value.toLong()) event.payload.transportFailed else null

/**
 * The `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` payload -- a request too large for
 * a datagram (RFC 3261 §18.1.1), where it was going, its size and the limit
 * -- or null for an event of any other kind. A client opened with
 * `streamFallback` opens the stream itself.
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
 * What a failed connection was, as the stack names it. A certificate the
 * trust managers refused is expired, a name mismatch or untrusted by what
 * refused it; any other TLS failure during the handshake is a handshake
 * refused. A server nothing answered for is refused, a network with no way
 * through unreachable, silence timed out.
 */
internal fun classify(failure: Throwable, handshaking: Boolean): SignallingRefused {
    val causes = generateSequence(failure) { it.cause }.toList()
    val detail = sentence(causes.lastOrNull { !it.message.isNullOrBlank() }?.message ?: failure.toString())
    fun tls(reason: SipralTlsFailure) = SignallingRefused(SipralTransportError.CONNECTION_RESET, reason, detail)
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

/** One line of at most `SIPRAL_TRANSPORT_DETAIL_BYTES` bytes of UTF-8. */
internal fun sentence(text: String): String {
    var line = text.map { if (it.isISOControl()) ' ' else it }.joinToString("").trim()
    while (line.toByteArray(Charsets.UTF_8).size > Sipral.TRANSPORT_DETAIL_BYTES) {
        line = line.dropLast(1)
    }
    return line
}

/** A certificate trusted and naming another server, told apart from one
 * nobody trusts, which `SSLSocket` reports with the same exception type. */
private class NameMismatch(cause: CertificateException) : CertificateException(cause.message, cause)

/**
 * The trust managers, one after another: the first that accepts the chain
 * decides, and the error each would give is kept apart for the reason.
 * The name is checked here, once the chain is trusted, by the HTTPS rules,
 * so a trusted certificate naming another server reads as a name mismatch
 * rather than as untrusted; and every certificate's dates are checked, an
 * authority pinned as the only anchor included, which PKIX alone does not
 * look at.
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
 * The HTTPS name rules (RFC 6125 as `SSLSocket` applies them): a `dNSName`
 * in `subjectAltName` equal to [name], case aside, a wildcard allowed in its
 * leftmost label only; an IP address against an `iPAddress` entry.
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
 * The one connection a [SipralClient] signals on over TCP or TLS: made
 * again, backing off, whenever it is lost, and every loss told to the stack
 * with its reason (`sipral_stack_transport_failure`), which says so as
 * `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`.
 */
internal class SignallingLink(
    val protocol: SipralTransport,
    private val server: InetSocketAddress,
    private val serverName: String,
    trust: SipralTlsTrust,
) {
    private val context: SSLContext? = if (protocol == SipralTransport.TLS) {
        SSLContext.getInstance("TLS").apply { init(null, arrayOf(Checking(trust.trustManagers(), serverName)), null) }
    } else {
        null
    }

    private class Open(val socket: Socket, val local: String, val remote: String) {
        val input: InputStream = socket.getInputStream()
        val output: OutputStream = socket.getOutputStream()
    }

    /** The client this connection signals for, set once it exists: the
     * first connection is made before the stack is, so that its address is
     * the one the stack is created with. */
    lateinit var owner: SipralClient

    private val client: SipralClient
        get() = owner

    private val current = AtomicReference<Open?>(null)
    private val reconnecting = AtomicBoolean(false)

    @Volatile
    var bindHost: String = "127.0.0.1"

    /** Whether the connection stands. */
    val connected: Boolean
        get() = current.get() != null

    /** What goes after the address in a `Contact` this layer writes. */
    val contactParameters: String
        get() = if (protocol == SipralTransport.TLS) ";transport=tls" else ";transport=tcp"

    /** One connection from [host]; `local` and `remote` beside it, or the
     * refusal. */
    fun connect(host: String): Pair<Socket, Pair<String, String>> {
        val raw = Socket()
        var handshaking = false
        try {
            raw.bind(InetSocketAddress(InetAddress.getByName(host), 0))
            raw.connect(server, PATIENCE_MS)
            raw.tcpNoDelay = true
            val socket = if (context != null) {
                handshaking = true
                (context.socketFactory.createSocket(raw, serverName, server.port, true) as SSLSocket).apply {
                    soTimeout = PATIENCE_MS
                    sslParameters = sslParameters.apply {
                        serverNames = listOf(SNIHostName(serverName))
                    }
                    startHandshake()
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
            throw classify(refused, handshaking)
        }
    }

    /** Tell the stack a connection is open, naming both ends, and read it
     * on a thread of its own. */
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
        Thread({ read(open) }, "sipral-signalling").apply {
            isDaemon = true
            start()
        }
    }

    /** `sipral_stack_transport_failure`, never throwing on the way out. */
    fun report(refused: SignallingRefused) {
        try {
            retryBusy {
                Sipral.stackTransportFailure(
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

    /** Write one message on the connection, whole; a write that fails loses
     * it. */
    fun write(payload: ByteArray, len: Int) {
        val open = current.get() ?: return
        try {
            synchronized(open) {
                open.output.write(payload, 0, len)
                open.output.flush()
            }
        } catch (broken: Exception) {
            lose(open, classify(broken, handshaking = false), tell = true)
        }
    }

    private fun read(open: Open) {
        val buffer = ByteArray(1 shl 16)
        while (!client.isClosed) {
            val read = try {
                open.input.read(buffer)
            } catch (broken: Exception) {
                lose(open, classify(broken, handshaking = false), tell = true)
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
                refused.status == SipralStatus.BUSY
            }
            if (!kept) {
                // the framing is lost: the stack retired the transport and
                // said so itself
                lose(open, null, tell = false)
                return
            }
        }
    }

    /** Close [open] if it is still the connection, tell the stack how it
     * ended -- `sipral_stack_stream_closed` for an orderly close ([refused]
     * null), `sipral_stack_transport_failure` otherwise, nothing when not
     * [tell] -- and connect again. */
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

    /** The connection made again from [host], for a network change; when
     * the new one cannot be made, the stack hears why and this keeps
     * trying. The local address it was made from, or null. */
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
        /** The wait before the first attempt to connect again, doubled after
         * every one that fails, up to [MOST_MS]. */
        const val FIRST_MS = 1_000L
        const val MOST_MS = 30_000L
    }
}
