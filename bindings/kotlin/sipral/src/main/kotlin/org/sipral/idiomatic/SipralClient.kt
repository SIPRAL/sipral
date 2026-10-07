// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The idiomatic Kotlin layer over org.sipral.Sipral (SipralAbi.kt, generated
// by tools/abi-gen): classes over the handles, events as a Flow, and suspend
// functions where the ABI completes through an event. Threading follows the
// first section of docs/08-ffi.md.

package org.sipral.idiomatic

import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.logging.LogRecord
import java.util.logging.Logger
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import org.sipral.Sipral
import org.sipral.SipralAudioTransmit
import org.sipral.SipralAudioTransmitListener
import org.sipral.SipralCallConfig
import org.sipral.SipralCallEvent
import org.sipral.SipralCounters
import org.sipral.SipralDnsRecordType
import org.sipral.SipralDtmfDetection
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralEventListener
import org.sipral.SipralException
import org.sipral.SipralHeader
import org.sipral.SipralHeldAudio
import org.sipral.SipralIce
import org.sipral.SipralLink
import org.sipral.SipralLogLevel
import org.sipral.SipralLogListener
import org.sipral.SipralNat
import org.sipral.SipralNetworkTestConfig
import org.sipral.SipralRecovery
import org.sipral.SipralSrtp
import org.sipral.SipralStackConfig
import org.sipral.SipralStirConfig
import org.sipral.SipralStatus
import org.sipral.SipralToggle
import org.sipral.SipralTransport
import org.sipral.SipralTransportFailure
import org.sipral.SipralTransportError
import org.sipral.SipralTransportWantedEvent

private const val TRANSMIT_BYTES = 1 shl 16
private const val ADDRESS_BYTES = 64
private const val PACKET_BYTES = 1500

/** The first transport id this layer binds its own connections under (a
 * recording server, `TRANSPORT_WANTED`), counting up: clear of the main
 * transport and of the small ids an application would pick. */
private const val FIRST_LINK = 64L

/** The protocols an account on a connection of its own may speak. */
private val STREAMS = setOf(SipralTransport.TCP, SipralTransport.TLS, SipralTransport.WS, SipralTransport.WSS)

internal fun formatAddress(host: String, port: Int): String = "$host:$port"

internal fun parseHostPort(text: String): InetSocketAddress {
    val at = text.lastIndexOf(':')
    return InetSocketAddress(text.substring(0, at), text.substring(at + 1).toInt())
}

/** Whether a `SipralTransport` number marks bytes for a TURN server's
 * connection rather than a datagram. */
internal fun overStream(protocol: Long): Boolean =
    protocol == SipralTransport.TCP.value.toLong() || protocol == SipralTransport.TLS.value.toLong()

/** One media socket's TCP or TLS connection to the TURN server. Written by
 * the poll thread and the media thread, each write whole under the stream's
 * lock; read by a thread of its own. */
private class TurnStream(val socket: Socket) {
    val input: InputStream = socket.getInputStream()
    val output: OutputStream = socket.getOutputStream()
}

/**
 * One `sipral_stack_create` handle, its signalling socket and its poll
 * thread.
 *
 * Built with [SipralClient.open] and torn down with [close], which calls
 * `sipral_stack_destroy` exactly once. There is no public constructor: the
 * socket must be bound before `sipral_stack_create`, since its address goes
 * in every `Via`.
 */
class SipralClient private constructor(
    socket: DatagramSocket?,
    private val link: SignallingLink?,
    bindAddress: String,
    stunServer: String?,
    private val turnServer: String?,
    private val turn: SipralTurnServer?,
    /** Who runs this client's audio, as it was opened. */
    val audioMode: SipralAudioMode,
    network: SipralNetwork,
    /** The RTP port range media sockets are bound in, as `min to max`, or
     * null when the operating system picks. */
    val rtpPorts: Pair<Int, Int>?,
) : AutoCloseable {
    internal var handle: Long = 0L
        private set

    /** The STUN server this client asks where its sockets appear from, as
     * `host:port`, or null for a client that asks nobody: the one it was
     * opened with, then the first of what [setStunServers] last named. */
    @Volatile
    var stunServer: String? = stunServer
        private set

    /** The signalling socket: read and written by the poll thread, and put
     * in another's place by [networkChanged]. Null for a client signalling
     * over TCP or TLS, whose connection has a reader of its own. */
    @Volatile
    private var socket: DatagramSocket? = socket

    /** The port the application chose for the signalling socket, zero when
     * it let the system choose: what [networkChanged] binds again. */
    private var chosenPort = 0

    /**
     * Whether the last [networkChanged] that bound the UDP signalling socket
     * again kept its port. False when the port was taken at the new address
     * and the system chose another, which [bindAddress] names; a peer or
     * firewall rule that knows only the old port has to be told. True before
     * any change.
     */
    @Volatile
    var keptSignallingPort: Boolean = true
        private set

    /** The signalling socket's address, `host:port`, as bound now. Over TCP or
     * TLS, the local address of the current connection, which changes on every
     * reconnect. With no `bindHost` the socket listens everywhere and this is
     * the advertised address: the route toward the first account's server. */
    @Volatile
    var bindAddress: String = bindAddress
        private set

    /** What SIP travels over: UDP, or one TCP or TLS connection to the
     * server. */
    val signalling: SipralTransport
        get() = link?.protocol ?: SipralTransport.UDP

    /** Whether SIP can go out now: always over UDP, and over TCP or TLS
     * while the connection to the server stands. */
    val connected: Boolean
        get() = link?.connected ?: true

    internal val isClosed: Boolean
        get() = closed.get()

    /** The library's audio engine in [SipralAudioMode.Device]; null in
     * [SipralAudioMode.Application], where the application runs the audio. */
    var audio: SipralAudioDevices? = null
        private set

    /** Serialises a network change with the calls it moves, so every account
     * points at the new address before a call is offered there. Also guards
     * [network] and [accounts]. */
    private val movingLock = Any()
    private var network: SipralNetwork = network
    private val accounts = LinkedHashMap<Long, SipralAccount>()

    private val origin = System.nanoTime()

    private val eventsFlow = MutableSharedFlow<SipralEvent>(
        replay = 0,
        extraBufferCapacity = 4096,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )

    /**
     * Every event this stack's listener heard, in order.
     *
     * Each collector may lag at most 4096 events behind the poll thread; past
     * that its oldest unread events are dropped silently (`DROP_OLDEST`), so
     * the poll thread never blocks. A collector that must see every event
     * keeps its per-event work short or hands events to a queue.
     */
    val events: SharedFlow<SipralEvent> = eventsFlow

    private val calls = ConcurrentHashMap<Long, SipralCall>()
    private val closed = AtomicBoolean(false)

    private lateinit var thread: Thread

    companion object {
        /**
         * Open a UDP socket, bind it, and build a [SipralClient] over it.
         *
         * Port `0` picks an ephemeral port, read back from [bindAddress]. Every
         * option left null is this build's default.
         *
         * [ice] is every call's ICE policy (RFC 8445) unless [placeCall] says
         * otherwise; `SipralIce.OFF` by default. `SipralIce.LITE` is for a server
         * reachable at the address it advertises (`docs/06-nat.md`).
         * [stunServer], `host:port` (an address, not a name), turns on
         * `SIPRAL_NAT_STUN`: accounts' `Contact` moves to the public address
         * (`SIPRAL_EVENT_KIND_NAT_MAPPING`, [natOf]) and every media socket is
         * asked the same before its call is described. [turn] adds a relayed
         * candidate per media socket ([relayOf]); it needs [stunServer] and is
         * used only under ICE. [g729AnnexB] allows G.729 silence compression, on
         * by default.
         *
         * [referrals] hands a REFER outside any dialog (click-to-dial) to the
         * application as `SIPRAL_EVENT_KIND_REFERRAL` ([referralOf]), to take with
         * [acceptReferral] or refuse with [rejectReferral]. Off by default, when
         * each is refused 403: a peer that can make a phone dial is a toll-fraud
         * vector.
         *
         * [registrarKeepalive] sends a double CRLF every [registrarKeepaliveMs]
         * (`0` for 25 s, 1 000 to 120 000) to the registrar of every account STUN
         * showed to be behind a NAT, so the registrar's INVITE still gets in. On
         * by default; an interval with it off is refused. Nothing is sent while
         * suspended.
         *
         * [audio] says who runs the audio: [SipralAudioMode.platformDefault] or
         * [SipralAudioMode.Application]. Under `SipralAudioActivation.MANUAL` the
         * devices open only between [SipralAudioDevices.activate] and
         * [SipralAudioDevices.deactivate]. [audioProbeMs] bounds a blocking
         * platform device call before `DEVICE_TIMED_OUT` (`0` for 3 s);
         * [audioDeviceRateHz] is the device rate (`0` for 48 000).
         *
         * [maxDialogs] caps concurrent calls (`0` for 128): an incoming one past
         * it is answered 503, an outgoing one throws `LIMIT_REACHED`.
         * [maxServerTransactions] caps requests worked on at once (`0` for 256).
         * [diagnosticDecisions] and [diagnosticRecords] bound the diagnostic
         * record per call (`0` for 64) and in calls (`0` for 32).
         *
         * [network] is what the first [networkChanged] compares with.
         *
         * [srtp] is every call's SRTP policy unless [placeCall] overrides it;
         * DTLS-SRTP's suite is reported by `SIPRAL_EVENT_KIND_MEDIA_SECURED`
         * ([srtpSuiteOf]). `SipralSrtp.BEST_EFFORT` offers SDES on plain
         * `RTP/AVP`, for a PBX that answers an `RTP/SAVP` offer with 488.
         * [srtpSuites] are the suites offered and accepted, most preferred first,
         * by their RFC 4568 and RFC 7714 names.
         *
         * [stunFallbacks] are tried in order when [stunServer] does not answer in
         * 5.5 s or answers without an address. A failed server is passed over for
         * 30 s, doubling per failure up to ten minutes;
         * `SIPRAL_EVENT_KIND_STUN_SERVER` ([stunServerOf]) reports moves.
         *
         * [rtpPortMin] and [rtpPortMax] bound media ports for a firewall: each
         * media socket binds an even port from the range
         * (`sipral_stack_rtp_port_reserve`), the odd one above kept for RTCP (RFC
         * 3550 §11). Both `0` leave ports to the OS. A full range throws
         * `SipralStatus.EXHAUSTED`.
         *
         * [dtmfDetection] is when a call listens for digits in the far end's
         * audio; [SipralCall.setDtmfDetection] changes it per call.
         *
         * [signalling] is `SipralTransport.UDP` (default) on a socket at
         * [bindHost], or `TCP`/`TLS` on one connection to [signallingServer]
         * (`host:port`), shared by every account and call. Over TLS the
         * certificate is checked against [tlsServerName] (default: the host of
         * [signallingServer]) with [tlsTrust] (`docs/22-tls.md`); the check
         * cannot be turned off.
         *
         * The first connection is made before this returns. When it fails or
         * breaks, `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` ([transportFailedOf]) says
         * why, and the client reconnects after 1 s, doubling up to 30 s. On
         * reconnect every account is re-pointed and re-registered if it was
         * registering. [SipralAccount.register] while down waits for that; a call
         * placed meanwhile throws `SipralStatus.TRANSPORT_DOWN`.
         *
         * [inviteLimit] is how fast one address may ring this client:
         * [SipralInviteLimit.DEFAULT] (ten INVITEs, then one every 2 s, past which
         * a call gets 480) or [SipralInviteLimit.VOICE_AGENT] for a trunk.
         *
         * [streamFallback] covers a UDP request too large for a datagram, nearly
         * always an `Authorization` past RFC 3261 §18.1.1's 1300 bytes. On (the
         * default), `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` ([transportWantedOf]) is
         * answered by opening TCP to the same address and port and binding it
         * (`sipral_stack_transport_bind`); the held request goes on it. If that
         * fails, or with false, the stack is told
         * (`sipral_stack_transport_failed_with`) and the waiting call ends as
         * unreachable, `causeSip` 513 with the size and limit in `causeText`.
         * [streamServer] (`host:port`) redirects that connection, for a PBX
         * taking TCP on another port than UDP.
         *
         * [bindHost] left null listens on every interface and advertises the
         * route toward the first account's server (`sipral_advertised_address`).
         * Each account is reached at the route toward its own server, and a
         * media socket with no `mediaHost` at the route toward the far end. A
         * loopback address is never advertised to a remote peer
         * (`UNREACHABLE_ADDRESS`).
         *
         * [pathMtu] is the path MTU toward the server when known (`0` for
         * unknown, else at least 576); RFC 3261 §18.1.1 moves a request to a
         * stream within 200 bytes of it. [datagramWithoutStreamBytes] deliberately
         * deviates from that section for UDP-only servers: when no stream can be
         * had, requests up to this size still go over UDP (`0` never, at most
         * 65 507), recorded as `transport.kept.datagram`.
         *
         * [pseudonymSalt] (at least 16 bytes, kept by the installation) keys the
         * pseudonyms in the log and [state], so two runs' traces compare. Treat it
         * as a secret. [diagnosticTrace] logs whole SIP messages at trace level,
         * credentials and keys removed; see [setDiagnosticTrace].
         *
         * [systemEchoCancellation] false opens device-mode audio without the
         * platform's echo canceller (on Android, the voice-recognition preset),
         * for a headset or an application that cancels echo itself.
         *
         * [heldAudio] is what a held party is sent: [SipralHeldAudio.DEFAULT] and
         * [SipralHeldAudio.SILENCE] send silence in either mode, since application
         * frames may be a microphone's; [SipralHeldAudio.APPLICATION] sends the
         * application's frames (hold music, an announcement).
         *
         * [resolver] answers `SIPRAL_EVENT_KIND_LOOKUP_WANTED` for accounts added
         * with a `serverUri`, one thread per lookup; [SipralDns.platform] when
         * null.
         */
        fun open(
            bindHost: String? = null,
            bindPort: Int = 0,
            userAgent: String? = null,
            codecs: String? = null,
            ice: SipralIce? = null,
            stunServer: String? = null,
            turn: SipralTurnServer? = null,
            g729AnnexB: Boolean? = null,
            referrals: Boolean? = null,
            registrarKeepalive: Boolean? = null,
            registrarKeepaliveMs: Long = 0,
            audio: SipralAudioMode = SipralAudioMode.platformDefault,
            audioProbeMs: Long = 0,
            audioDeviceRateHz: Long = 0,
            maxDialogs: Long = 0,
            maxServerTransactions: Long = 0,
            diagnosticDecisions: Long = 0,
            diagnosticRecords: Long = 0,
            network: SipralNetwork? = null,
            srtp: SipralSrtp? = null,
            stunFallbacks: List<String> = emptyList(),
            rtpPortMin: Int = 0,
            rtpPortMax: Int = 0,
            dtmfDetection: SipralDtmfDetection = SipralDtmfDetection.AUTO,
            signalling: SipralTransport = SipralTransport.UDP,
            signallingServer: String? = null,
            tlsServerName: String? = null,
            tlsTrust: SipralTlsTrust = SipralTlsTrust.Platform,
            inviteLimit: SipralInviteLimit? = null,
            streamFallback: Boolean = true,
            streamServer: String? = null,
            srtpSuites: List<String> = emptyList(),
            pathMtu: Long = 0,
            datagramWithoutStreamBytes: Long = 0,
            pseudonymSalt: ByteArray? = null,
            diagnosticTrace: Boolean? = null,
            resolver: SipralResolver? = null,
            systemEchoCancellation: Boolean? = null,
            heldAudio: SipralHeldAudio = SipralHeldAudio.DEFAULT,
        ): SipralClient {
            require(signalling == SipralTransport.UDP || signalling == SipralTransport.TCP || signalling == SipralTransport.TLS) {
                "signalling is UDP, TCP or TLS"
            }
            val streamed = signalling != SipralTransport.UDP
            require(!streamed || signallingServer != null) { "SIP over TCP or TLS needs signallingServer, host:port" }
            var first: Pair<java.net.Socket, Pair<String, String>>? = null
            var refused: SignallingRefused? = null
            val socket = when {
                streamed -> null
                bindHost == null -> DatagramSocket(bindPort)
                else -> DatagramSocket(bindPort, InetAddress.getByName(bindHost))
            }
            val bindAddress = if (socket != null) {
                socket.soTimeout = 20
                formatAddress(bindHost?.let { socket.localAddress.hostAddress } ?: routeHost(streamServer), socket.localPort)
            } else {
                "${bindHost ?: routeHost(signallingServer)}:$bindPort"
            }
            val link = if (streamed) {
                val server = signallingServer!!
                SignallingLink(
                    signalling, parseHostPort(server),
                    tlsServerName ?: server.substring(0, server.lastIndexOf(':')), tlsTrust,
                ).also { made ->
                    made.bindHost = bindHost
                    try {
                        first = made.connect(bindHost)
                    } catch (no: SignallingRefused) {
                        refused = no
                    }
                }
            } else {
                null
            }
            val client = SipralClient(
                socket, link, first?.second?.first ?: bindAddress, stunServer, turn?.address, turn, audio,
                network ?: SipralNetwork(SipralLink.WIRED, address = bindHost ?: bindAddress.substringBeforeLast(':')),
                if (rtpPortMin == 0 && rtpPortMax == 0) null else rtpPortMin to rtpPortMax,
            )
            link?.owner = client
            client.chosenPort = bindPort
            client.streamFallback = streamFallback
            client.streamServer = streamServer
            client.streamTlsTrust = tlsTrust
            client.givenTlsServerName = tlsServerName
            client.routes = bindHost == null
            client.routeChosen = bindHost != null || streamed || streamServer != null
            client.resolver = resolver ?: SipralDns.platform
            try {
                client.start(
                    userAgent, codecs, ice, turn, g729AnnexB, referrals,
                    registrarKeepalive, registrarKeepaliveMs, audioProbeMs, audioDeviceRateHz, srtp,
                    maxDialogs, maxServerTransactions, diagnosticDecisions, diagnosticRecords,
                    stunFallbacks, dtmfDetection, signalling, inviteLimit,
                    Tail(
                        srtpSuites, pathMtu, datagramWithoutStreamBytes, pseudonymSalt, diagnosticTrace,
                        systemEchoCancellation, heldAudio,
                    ),
                )
            } catch (refusal: Exception) {
                socket?.close()
                first?.first?.close()
                throw refusal
            }
            if (link != null) {
                val made = first
                if (made != null) {
                    link.install(made.first, made.second.first, made.second.second)
                } else {
                    link.report(refused ?: SignallingRefused(org.sipral.SipralTransportError.OTHER, org.sipral.SipralTlsFailure.NONE, "no connection"))
                    link.reconnectLater()
                }
            }
            return client
        }

        internal fun toggle(value: Boolean?): Long = when (value) {
            null -> SipralToggle.DEFAULT.value.toLong()
            true -> SipralToggle.ON.value.toLong()
            false -> SipralToggle.OFF.value.toLong()
        }
    }

    private fun start(
        userAgent: String?,
        codecs: String?,
        ice: SipralIce?,
        turn: SipralTurnServer?,
        g729AnnexB: Boolean?,
        referrals: Boolean?,
        registrarKeepalive: Boolean?,
        registrarKeepaliveMs: Long,
        audioProbeMs: Long,
        audioDeviceRateHz: Long,
        srtp: SipralSrtp?,
        maxDialogs: Long,
        maxServerTransactions: Long,
        diagnosticDecisions: Long,
        diagnosticRecords: Long,
        stunFallbacks: List<String>,
        dtmfDetection: SipralDtmfDetection,
        signalling: SipralTransport,
        inviteLimit: SipralInviteLimit?,
        tail: Tail,
    ) {
        val random = SecureRandom()
        val entropy = ByteArray(32).also { random.nextBytes(it) }
        val mediaSeed = ByteArray(32).also { random.nextBytes(it) }
        val listener = SipralEventListener { event -> onEvent(event) }
        val (audioRaw, activationRaw) = audioMode.raw
        val device = audioMode is SipralAudioMode.Device
        val config = SipralStackConfig(
            eventListener = listener,
            transport = signalling.value.toLong(),
            bindAddress = bindAddress,
            userAgent = userAgent,
            entropy = entropy,
            codecs = codecs,
            // the wall clock the RTCP sender reports carry (RFC 3550 §6.4.1)
            mediaClockUnixSeconds = System.currentTimeMillis() / 1000,
            mediaSeed = mediaSeed,
            ice = (ice?.value ?: 0).toLong(),
            nat = if (stunServer != null) SipralNat.STUN.value.toLong() else 0,
            stunServer = stunServer,
            g729AnnexB = toggle(g729AnnexB),
            turnServer = turn?.address,
            turnUsername = turn?.username,
            turnPassword = turn?.password,
            referrals = toggle(referrals),
            registrarKeepalive = toggle(registrarKeepalive),
            registrarKeepaliveMs = registrarKeepaliveMs,
            turnTransport = if (turn != null) turn.transport.value.toLong() else 0,
            audio = audioRaw,
            audioActivation = activationRaw,
            audioTransmitListener = if (device) SipralAudioTransmitListener { transmitAudio(it) } else null,
            audioProbeMs = audioProbeMs,
            audioDeviceRateHz = audioDeviceRateHz,
            srtp = (srtp?.value ?: 0).toLong(),
            maxDialogs = maxDialogs,
            maxServerTransactions = maxServerTransactions,
            diagnosticDecisions = diagnosticDecisions,
            diagnosticRecords = diagnosticRecords,
            stunFallbacks = stunFallbacks.takeIf { it.isNotEmpty() }?.joinToString(","),
            rtpPortMin = (rtpPorts?.first ?: 0).toLong(),
            rtpPortMax = (rtpPorts?.second ?: 0).toLong(),
            dtmfDetection = dtmfDetection.value.toLong(),
            srtpSuites = tail.srtpSuites.takeIf { it.isNotEmpty() }?.joinToString(","),
            pathMtu = tail.pathMtu,
            datagramWithoutStreamBytes = tail.datagramWithoutStreamBytes,
            pseudonymSalt = tail.pseudonymSalt?.takeIf { it.isNotEmpty() },
            diagnosticTrace = toggle(tail.diagnosticTrace),
            systemEchoCancellation = toggle(tail.systemEchoCancellation),
            heldAudio = tail.heldAudio.value.toLong(),
        )
        handle = Sipral.stackCreate(config)
        if (inviteLimit != null) {
            Sipral.stackInviteLimit(handle, inviteLimit.everyMs, inviteLimit.burst)
        }
        if (device) {
            audio = SipralAudioDevices(this)
        }
        thread = Thread(::run, "sipral-client-$bindAddress").apply {
            isDaemon = true
            start()
        }
    }

    /** The rest of the stack's configuration, as [open] took it. */
    private class Tail(
        val srtpSuites: List<String>,
        val pathMtu: Long,
        val datagramWithoutStreamBytes: Long,
        val pseudonymSalt: ByteArray?,
        val diagnosticTrace: Boolean?,
        val systemEchoCancellation: Boolean?,
        val heldAudio: SipralHeldAudio,
    )

    /** Milliseconds since this stack was created: what every `now_ms` below
     * expects. */
    fun nowMs(): Long = (System.nanoTime() - origin) / 1_000_000

    /** Whether this client picks the address peers reach it at (opened with no
     * `bindHost`), and whether it has picked it yet since open or the last
     * network move. Under [movingLock]. */
    private var routes = false
    private var routeChosen = true

    /** Answers `SIPRAL_EVENT_KIND_LOOKUP_WANTED`. */
    private var resolver: SipralResolver = SipralDns.platform

    /** What `LOOKUP_WANTED` asked, and what `LOCATED` found, during the
     * poll that raised them, acted on right after it. */
    private val lookupsAsked = java.util.concurrent.ConcurrentLinkedQueue<Triple<Long, String, SipralDnsRecordType>>()
    private val located = java.util.concurrent.ConcurrentLinkedQueue<Pair<Long, String>>()

    /** Whether an account added now, with no `Contact` of its own, is
     * reached at the route toward its server. */
    private val picksAddress: Boolean
        get() = synchronized(movingLock) { routes } && link == null

    /** The `host:port` an account whose server is [peer] is reached at, on a
     * client that picks its own address. The first server named also becomes
     * the address in the stack's `Via`. */
    private fun advertiseToward(peer: String): String {
        val address = formatAddress(routeHost(peer), bindAddress.substringAfterLast(':').toInt())
        val first = synchronized(movingLock) { (!routeChosen).also { routeChosen = true } }
        if (first && address != bindAddress) {
            advertiseMain(address)
        }
        return address
    }

    /** The UDP transport the stack writes in its `Via` named [address] from
     * now on, on a client that picks its own address. */
    private fun advertiseMain(address: String) {
        val status = retryBusy {
            SipralSignalNative.stackTransportRebind(handle, address.toByteArray(Charsets.UTF_8), nowMs()).also {
                throwIfPassing(it)
            }
        }
        if (status != SipralStatus.OK.value) {
            throw SipralException(SipralStatus.of(status), Sipral.lastErrorMessage())
        }
        bindAddress = address
    }

    /** What a client bound on every interface advertises after a move: the
     * route toward its first account's server, or else [address] on the same
     * port. Under [movingLock]. */
    private fun advertiseAgain(address: String?): String {
        routeChosen = false
        val server = accounts.values.map { it.registrarAddress }.firstOrNull(::isAddress)
        if (server != null) {
            return advertiseToward(server)
        }
        val local = formatAddress(address ?: routeHost(streamServer), bindAddress.substringAfterLast(':').toInt())
        if (local != bindAddress) {
            advertiseMain(local)
        }
        return local
    }

    /** Where a call's media socket binds: [mediaHost] if given, else the route
     * toward [destination], the account's server, or this client's address. */
    private fun mediaHostFor(mediaHost: String?, account: SipralAccount?, destination: String?): String {
        if (mediaHost != null) {
            return mediaHost
        }
        for (peer in listOf(destination, account?.registrarAddress)) {
            if (peer != null && isAddress(peer)) {
                return routeHost(peer)
            }
        }
        return bindAddress.substringBeforeLast(':')
    }

    private fun accountFor(handle: Long): SipralAccount? = synchronized(movingLock) { accounts[handle] }

    /** Poll thread side: remember what the events asked, to act after the
     * poll. */
    private fun noteLocate(event: SipralEvent) {
        val locate = locateOf(event) ?: return
        val name = locate.name
        if (event.kind == SipralEventKind.LOOKUP_WANTED.value.toLong() && name != null) {
            val record = SipralDnsRecordType.of(locate.record.toInt()) ?: return
            lookupsAsked.add(Triple(event.account, name, record))
        } else if (event.kind == SipralEventKind.LOCATED.value.toLong()) {
            locate.targets?.split(',')?.firstOrNull()?.takeIf { it.isNotEmpty() }?.let { located.add(event.account to it) }
        }
    }

    /** Answer the lookups `LOOKUP_WANTED` asked during the last poll, each on
     * its own thread since a resolver may take seconds. An account `LOCATED`
     * at a new address is pointed at it and, on a client that picks its own
     * address, reached at the route toward it. */
    private fun actOnLookups() {
        while (true) {
            val (account, name, record) = lookupsAsked.poll() ?: break
            val resolver = resolver
            Thread({ lookedUp(account, name, record, resolve(resolver, name, record)) }, "sipral-lookup").apply {
                isDaemon = true
                start()
            }
        }
        while (true) {
            val (handle, target) = located.poll() ?: break
            val account = accountFor(handle) ?: continue
            account.located(target)
            if (!picksAddress || !account.derivesContact) {
                continue
            }
            try {
                account.reach(advertiseToward(target), target)
            } catch (_: SipralException) {
                // the account was removed meanwhile
            }
        }
    }

    private fun resolve(resolver: SipralResolver, name: String, record: SipralDnsRecordType): SipralLookup =
        try {
            resolver(name, record)
        } catch (_: Exception) {
            // a failure is an answer too: the procedure waits for every one
            SipralLookup.FAILED
        }

    /** `sipral_account_looked_up`, for one answer; an account removed while
     * the resolver ran is let go of quietly. */
    private fun lookedUp(account: Long, name: String, record: SipralDnsRecordType, answer: SipralLookup) {
        if (closed.get()) {
            return
        }
        try {
            retryBusy {
                Sipral.accountLookedUp(
                    handle, account, name, record.value.toLong(), answer.answer.value.toLong(),
                    answer.records.joinToString(","), nowMs(),
                )
            }
        } catch (_: SipralException) {
            // the account, or the client, went away while the resolver ran
        }
    }

    /** Turn the diagnostic trace on or off (`sipral_stack_diagnostic_trace`):
     * whole SIP messages with peers, rather than pseudonymised, at `TRACE`
     * level. Credentials and keys are removed either way. */
    fun setDiagnosticTrace(on: Boolean) {
        retryBusy { Sipral.stackDiagnosticTrace(handle, toggle(on)) }
    }

    /** What the stack runs with, every default filled in
     * (`sipral_stack_settings`), with the SRTP suites its calls offer in
     * order (`sipral_stack_srtp_suite_order`). */
    fun settings(): SipralSettings {
        val raw = retryBusy { Sipral.stackSettings(handle) }
        val suites = IntArray(raw.srtpSuiteCount.toInt())
        retryBusy { Sipral.stackSrtpSuiteOrder(handle, suites) }
        return SipralSettings.of(raw, suites)
    }

    /** The diagnostic record of every kept call, as JSON
     * (`sipral_stack_diagnostics_json`): each decision the stack made and
     * why. */
    fun diagnosticsJson(): String {
        var capacity = 4096
        while (true) {
            val buffer = ByteArray(capacity)
            try {
                val needed = retryBusy { Sipral.stackDiagnosticsJson(handle, buffer) }.toInt()
                return String(buffer, 0, maxOf(0, needed - 1), Charsets.UTF_8)
            } catch (small: SipralException) {
                if (small.status != SipralStatus.BUFFER_TOO_SMALL) throw small
                capacity *= 4
            }
        }
    }

    // Media ports, the log and the state snapshot

    /**
     * A UDP socket for a call's media at [host]: at [port] if given, else, on
     * a client with an RTP range, at a reserved even port
     * (`sipral_stack_rtp_port_reserve`), skipping ports another process holds.
     * `SipralStatus.EXHAUSTED` once every pair is taken.
     */
    fun openMediaSocket(host: String, port: Int = 0): DatagramSocket {
        val range = rtpPorts
        if (port != 0 || range == null) {
            return DatagramSocket(port, InetAddress.getByName(host))
        }
        var failure: Exception? = null
        repeat(maxOf(1, (range.second - range.first + 1) / 2)) {
            val reserved = retryBusy { Sipral.stackRtpPortReserve(handle) }.toInt()
            try {
                return DatagramSocket(reserved, InetAddress.getByName(host))
            } catch (taken: java.net.SocketException) {
                giveBackPort(reserved)
                failure = taken
            }
        }
        throw failure ?: SipralException(SipralStatus.EXHAUSTED, "no RTP port could be bound")
    }

    /** `sipral_stack_rtp_port_release` for a port no call took. Best effort: a
     * call's own port comes back when the call ends. */
    internal fun giveBackPort(port: Int) {
        if (rtpPorts == null) {
            return
        }
        try {
            retryBusy { Sipral.stackRtpPortRelease(handle, port.toLong()) }
        } catch (_: SipralException) {
            // not reserved, so there is nothing to give back
        }
    }

    /**
     * Send this client's log to [handler] at [level] and louder, or turn it
     * off with `SipralLogLevel.OFF` or null (`sipral_stack_log`).
     * The handler runs on whichever thread just left the stack (usually the
     * poll thread), with the stack unlocked, so it may call back in. Lines are
     * already redacted. Arguments: level, target, line, and how many lines a
     * flood suppressed before it.
     */
    fun setLog(level: SipralLogLevel, handler: ((SipralLogLevel, String, String, Long) -> Unit)?) {
        val on = level != SipralLogLevel.OFF && handler != null
        val listener = if (on) {
            SipralLogListener { record ->
                handler(
                    SipralLogLevel.of(record.level.toInt()) ?: SipralLogLevel.DEBUG,
                    record.target ?: "",
                    record.message ?: "",
                    record.suppressed,
                )
            }
        } else {
            null
        }
        retryBusy { Sipral.stackLog(handle, (if (on) level else SipralLogLevel.OFF).value.toLong(), listener) }
    }

    /**
     * Everything the stack holds, as the redacted text
     * `sipral_stack_state_text` writes for a crash report. Safe from any
     * thread, and never waits.
     */
    fun state(): String {
        val buffer = ByteArray(Sipral.STATE_TEXT_MAX.toInt())
        val length = Sipral.stackStateText(handle, buffer).toInt()
        return String(buffer, 0, maxOf(0, length - 1), Charsets.UTF_8)
    }

    /**
     * Send this client's log to `java.util.logging` (logcat on Android).
     * Each line goes to the child logger of its target (`sipral.call`,
     * `sipral.sip`, ...; `docs/17-observability.md`). Levels map `ERROR` to
     * `SEVERE`, `WARN` to `WARNING`, `INFO` to `INFO`, `DEBUG` to `FINE`,
     * `TRACE` to `FINEST`. [level] null follows the logger's current effective
     * level, so dropped lines are never formatted. For SLF4J or Timber, pass
     * [setLog] a lambda instead. Replaces whatever [setLog] installed.
     */
    fun logTo(logger: Logger = Logger.getLogger("sipral"), level: SipralLogLevel? = null) {
        val children = ConcurrentHashMap<String, Logger>()
        setLog(level ?: logLevelFor(effectiveLevel(logger))) { line, target, message, suppressed ->
            val child = children.getOrPut(target) { Logger.getLogger("${logger.name}.$target") }
            val julLevel = julLevelOf(line)
            if (child.isLoggable(julLevel)) {
                val text = if (suppressed == 0L) message else "$message ($suppressed lines turned away before this one)"
                child.log(LogRecord(julLevel, text).apply { loggerName = child.name })
            }
        }
    }

    /**
     * Health counters since open (`sipral_stack_counters`). One struct copy,
     * cheap to sample on a timer; every field only grows except `activeCalls`.
     */
    fun counters(): SipralCounters = retryBusy { Sipral.stackCounters(handle) }

    /**
     * Replace the STUN servers, in order of preference, each `host:port`
     * (`sipral_stack_stun_servers`). Every mapped socket asks the new list at
     * once; `SIPRAL_EVENT_KIND_STUN_SERVER` and `SIPRAL_EVENT_KIND_NAT_MAPPING`
     * follow. On a client opened without STUN, mapping starts now. An empty
     * list stops STUN: accounts register their own address again. A client
     * with a TURN server needs STUN, so an empty list there throws
     * `SipralStatus.INVALID_ARGUMENT`, as does a malformed entry.
     */
    fun setStunServers(servers: List<String>) {
        retryBusy { Sipral.stackStunServers(handle, servers.joinToString(","), nowMs()) }
        stunServer = servers.firstOrNull()
    }

    /**
     * `sipral_stack_network_test`: test the network without placing a call;
     * returns the test's number, and the result arrives as
     * `SIPRAL_EVENT_KIND_NETWORK_TEST` ([networkTestOf]). [account]'s server
     * gets an `OPTIONS`; with a STUN server, the signalling socket's last
     * answer stands for the STUN part. [echoCall] is a call to an echo
     * service, measured for [echoMs] (default 8000) once media starts, then
     * hung up. A part silent past [timeoutMs] (default 30000) fails.
     */
    fun networkTest(
        account: SipralAccount? = null,
        echoCall: SipralCall? = null,
        echoMs: Long = 0,
        timeoutMs: Long = 0,
    ): Long = retryBusy {
        Sipral.stackNetworkTest(
            handle,
            SipralNetworkTestConfig(
                account = account?.handle ?: 0,
                echoCall = echoCall?.handle ?: 0,
                echoMs = echoMs,
                timeoutMs = timeoutMs,
            ),
            nowMs(),
        )
    }

    /**
     * `sipral_stack_stir`: verify the callers of incoming calls against
     * [anchors] (PEM or DER, the STI-PA roots under SHAKEN) from now on (RFC
     * 8224), replacing earlier anchors. [unixSeconds] is the clock a PASSporT
     * is judged by. A client that only signs calls this too, with no anchors,
     * before adding accounts. The certificate is requested by
     * `SIPRAL_EVENT_KIND_CALLER_VERIFICATION` ([verificationOf]) and supplied
     * with [stirCertificate]. [acceptServiceProviderCodes] lets a certificate
     * naming a service provider code vouch for any caller, as SHAKEN's do.
     */
    fun stir(
        anchors: ByteArray?,
        freshnessSeconds: Long = 0,
        certificateWaitMs: Long = 0,
        unixSeconds: Long = System.currentTimeMillis() / 1000,
        acceptServiceProviderCodes: Boolean = false,
    ) {
        val config = SipralStirConfig(
            anchors = anchors?.takeIf { it.isNotEmpty() },
            freshnessSeconds = freshnessSeconds,
            certificateWaitMs = certificateWaitMs,
            unixSeconds = unixSeconds,
            acceptServiceProviderCodes = if (acceptServiceProviderCodes) SipralToggle.ON.value.toLong() else 0,
        )
        retryBusy { Sipral.stackStir(handle, config, nowMs()) }
    }

    /**
     * `sipral_call_stir_certificate`: the chain fetched for a verification
     * (PEM or DER, signer first), or null if it could not be had. [call] is
     * the handle from the event; the call is not yet announced. The verdict
     * follows as `SIPRAL_EVENT_KIND_CALLER_VERIFICATION` at
     * `SIPRAL_VERIFICATION_STAGE_VERIFIED`.
     */
    fun stirCertificate(call: Long, chain: ByteArray?) {
        retryBusy { Sipral.callStirCertificate(handle, call, chain ?: ByteArray(0), nowMs()) }
    }

    // Accounts and calls

    /**
     * `sipral_account_add`. See [SipralAccount].
     *
     * [sessionTimer] is the session timer the account's calls ask for (RFC
     * 4028), thirty minutes by default. [privacy] places calls anonymously
     * (RFC 3323): `setOf(SipralPrivacy.ID)` withholds the number, `From`
     * becomes `"Anonymous" <sip:anonymous@anonymous.invalid>`, and the real
     * identity goes in `P-Asserted-Identity` only toward a trusted peer.
     * [trustedPeers] are the IP addresses of RFC 3325's trust domain (usually
     * the registrar or trunk): a call from one has its asserted identity read
     * ([callerIdentity]), from elsewhere it is dropped, and once any are named
     * no identity header goes to other peers. [security] is the account's
     * SRTP and STIR/SHAKEN policy ([SipralAccountSecurity]).
     *
     * [serverUri] names the server by a URI located per RFC 3263
     * (`sip:pbx.example.com`), instead of [registrarAddress]: give exactly
     * one. `SIPRAL_EVENT_KIND_LOCATED` ([locateOf]) says where it was found,
     * `LOCATE_FAILED` why not. REGISTER waits for the first answer; a call
     * placed before it with no `destination` throws `WRONG_STATE`.
     * [serverNaptr] asks for NAPTR before SRV (RFC 3263 §4.1). [keepaliveMs]
     * keeps the flow open whatever STUN found (1 000 to 120 000, `0` never).
     * [tlsPin] is the SHA-256 fingerprint of the one TLS certificate trusted,
     * for an application running the account's TLS itself;
     * [SipralAccount.checkCertificate] gives the verdict.
     *
     * [streamProtocol] (TCP, TLS, WS or WSS) puts
     * the account on its own connection to its server, alongside UDP accounts
     * in the same stack. The stack asks for it with
     * `SIPRAL_EVENT_KIND_TRANSPORT_WANTED`, this client opens and binds it
     * regardless of `streamFallback`, and the account's REGISTER and calls use
     * it. TLS is held to [tlsPin] if set, else to the client's `tlsTrust`. A
     * closed connection is reopened; until it is open a call throws
     * `TRANSPORT_DOWN`. Only on a client signalling over UDP. WS/WSS run a
     * WebSocket (RFC 7118) asking for [websocketResource] (`/ws`) with
     * [websocketHost] as `Host` (the server's address).
     */
    fun addAccount(
        aor: String,
        registrarAddress: String? = null,
        registrar: String? = null,
        contact: String? = null,
        displayName: String? = null,
        authUser: String? = null,
        authPassword: String? = null,
        expiresSeconds: Long = 0,
        push: SipralPush? = null,
        sessionTimer: SipralSessionTimerChoice = SipralSessionTimerChoice.Default,
        privacy: Set<SipralPrivacy> = emptySet(),
        trustedPeers: List<String> = emptyList(),
        security: SipralAccountSecurity = SipralAccountSecurity(),
        serverUri: String? = null,
        serverNaptr: Boolean = false,
        keepaliveMs: Long = 0,
        tlsPin: String? = null,
        streamProtocol: SipralTransport? = null,
        realms: List<String> = emptyList(),
        websocketHost: String? = null,
        websocketResource: String? = null,
    ): SipralAccount {
        require((registrarAddress == null) != (serverUri == null)) {
            "an account names its server by registrarAddress or by serverUri, one of the two"
        }
        require(streamProtocol == null || (streamProtocol in STREAMS && link == null)) {
            "streamProtocol is TCP, TLS, WS or WSS, on a client that signals over UDP"
        }
        val advertised = if (contact == null && registrarAddress != null && picksAddress) {
            advertiseToward(registrarAddress)
        } else {
            null
        }
        val account = SipralAccount.add(
            this,
            aor,
            registrarAddress = registrarAddress,
            location = SipralAccount.Location(
                serverUri, serverNaptr, keepaliveMs, tlsPin, advertised, streamProtocol, realms,
                websocketHost, websocketResource,
            ),
            registrar = registrar,
            contact = contact,
            displayName = displayName,
            authUser = authUser,
            authPassword = authPassword,
            expiresSeconds = expiresSeconds,
            push = push,
            sessionTimer = sessionTimer,
            privacy = privacy,
            trustedPeers = trustedPeers,
            security = security,
        )
        synchronized(movingLock) { accounts[account.handle] = account }
        return account
    }

    internal fun forgetAccount(account: Long) {
        synchronized(movingLock) { accounts.remove(account) }
    }

    /** Where an account without its own `Contact` is reached: the AOR's user
     * at [at], with [stream]'s transport or the client's. */
    internal fun defaultContact(aor: String, at: String = bindAddress, stream: SipralTransport? = null): String {
        val scheme = aor.substringBefore(':', "sip")
        val rest = aor.substringAfter(':', aor)
        val user = rest.substringBefore('@', "")
        val parameters = when (stream) {
            SipralTransport.TLS -> ";transport=tls"
            SipralTransport.TCP -> ";transport=tcp"
            SipralTransport.WS -> ";transport=ws"
            SipralTransport.WSS -> ";transport=wss"
            else -> link?.contactParameters ?: ""
        }
        return if (user.isEmpty()) "$scheme:$at$parameters" else "$scheme:$user@$at$parameters"
    }

    /** The connection to the server was made from [local]: the address the
     * stack now signals from. */
    internal fun linkBound(local: String) {
        bindAddress = local
    }

    /** Accounts without their own `Contact` move to the new connection's
     * address, and those registering register again now rather than at their
     * next back-off. */
    internal fun afterReconnect() {
        val all = synchronized(movingLock) { accounts.values.toList() }
        for (account in all) {
            try {
                account.rebind(bindAddress, null)
                if (account.wantsRegistration) {
                    account.register()
                }
            } catch (_: SipralException) {
                // the next loss or refresh tries again
            }
        }
    }

    /**
     * `sipral_call_place`, with this stack running the call's audio: a media
     * socket is opened before the INVITE and offered as `media_address`.
     *
     * With a [stunServer] this blocks until the server answers (or 5.5 s
     * pass), and with TURN until the relay is allocated or refused, so call it
     * off the main thread. [ice] overrides the client's ICE policy. [headers]
     * go on the INVITE as written (`Alert-Info`, `Answer-Mode`).
     *
     * [codecs] orders this call's codecs (`sipral_codec_info_t` names,
     * comma-separated); `L16/16000` or `L16/8000` is the only way to offer
     * linear audio. [text] offers real-time text (RFC 4103) on a second socket
     * at [mediaHost], carried by [SipralMedia.sendText] and [SipralCall.text];
     * it is not offered with SRTP or ICE, which would leave it in the clear.
     * [feedback] offers RTP/AVPF with Generic NACK and reduced-size RTCP (RFC
     * 4585, RFC 5506), which an RTP/AVP-only peer refuses. [focus] marks this
     * end as a conference focus (`isfocus`, RFC 4579). [followRedirects]
     * follows a 3xx's targets (RFC 3261 §8.1.3.4); otherwise a 3xx ends the
     * call and its `Contact` is the application's to act on.
     */
    fun placeCall(
        account: SipralAccount,
        target: String,
        mediaHost: String? = null,
        mediaPort: Int = 0,
        destination: String? = null,
        srtp: Long = 0,
        ice: SipralIce? = null,
        headers: List<SipralHeader> = emptyList(),
        codecs: String? = null,
        text: Boolean = false,
        feedback: Boolean = false,
        focus: Boolean = false,
        followRedirects: Boolean = false,
    ): SipralCall {
        val mediaHost = mediaHostFor(mediaHost, account, destination)
        val mediaSocket = openMediaSocket(mediaHost, mediaPort)
        val mediaAddress = formatAddress(mediaSocket.localAddress.hostAddress, mediaSocket.localPort)
        val textSocket = try {
            if (text) DatagramSocket(InetSocketAddress(mediaHost, 0)) else null
        } catch (refused: Exception) {
            giveBackMediaSocket(mediaSocket, mediaAddress)
            throw refused
        }
        val config = SipralCallConfig(
            target = target,
            mediaAddress = mediaAddress,
            destination = destination,
            srtp = srtp,
            ice = (ice?.value ?: 0).toLong(),
            headers = headers.ifEmpty { null },
            codecs = codecs,
            textAddress = textSocket?.let { formatAddress(it.localAddress.hostAddress, it.localPort) },
            feedback = if (feedback) SipralToggle.ON.value.toLong() else 0L,
            focus = if (focus) 1L else 0L,
            followRedirects = if (followRedirects) 1L else 0L,
        )
        val callHandle = try {
            mapMediaSocket(mediaSocket, mediaAddress)
            retryBusy { Sipral.callPlace(handle, account.handle, config, nowMs()) }
        } catch (refused: Exception) {
            giveBackMediaSocket(mediaSocket, mediaAddress)
            textSocket?.close()
            throw refused
        }
        val call = SipralCall(this, callHandle, mediaSocket, mediaAddress, textSocket = textSocket)
        track(call, callHandle, mediaAddress)
        return call
    }

    /**
     * Open a media socket for an incoming call and answer it there.
     * `event` is the `SIPRAL_EVENT_KIND_INCOMING_CALL` read off [events].
     *
     * [text] takes the offer's real-time text on a second socket. [codecs]
     * orders the answer's codecs (`L16/16000` for linear audio). [focus] marks
     * a conference focus (`isfocus`, RFC 4579). An offer asking for RTCP
     * feedback is answered on RTP/AVPF regardless (RFC 4585 §4.1 leaves no
     * other way); [feedback] adds Generic NACK and reduced-size RTCP.
     */
    fun answerCall(
        event: SipralEvent,
        mediaHost: String? = null,
        mediaPort: Int = 0,
        text: Boolean = false,
        codecs: String? = null,
        focus: Boolean = false,
        feedback: Boolean = false,
    ): SipralCall = answerCall(
        event.call, mediaHostFor(mediaHost, accountFor(event.account), null), mediaPort, event.payload.call,
        Answered(text, codecs, focus, feedback),
    )

    /**
     * [answerCall] by call handle, for a caller that has only the handle (from
     * [SipralAnnounced.Arrived]). [SipralCall.identity] then lacks what only
     * the event carried: whether the peer was trusted and what it asserted.
     */
    fun answerCall(callHandle: Long, mediaHost: String? = null, mediaPort: Int = 0): SipralCall =
        answerCall(callHandle, mediaHostFor(mediaHost, null, null), mediaPort, null, Answered())

    /** What `sipral_call_answer_with` takes beyond the media socket; nothing
     * asked for by default. */
    private data class Answered(
        val text: Boolean = false,
        val codecs: String? = null,
        val focus: Boolean = false,
        val feedback: Boolean = false,
    ) {
        val plain: Boolean
            get() = !text && codecs == null && !focus && !feedback
    }

    private fun answerCall(
        callHandle: Long,
        mediaHost: String,
        mediaPort: Int,
        incoming: SipralCallEvent?,
        how: Answered,
    ): SipralCall {
        val mediaSocket = openMediaSocket(mediaHost, mediaPort)
        val mediaAddress = formatAddress(mediaSocket.localAddress.hostAddress, mediaSocket.localPort)
        val textSocket = try {
            if (how.text) DatagramSocket(InetSocketAddress(mediaHost, 0)) else null
        } catch (refused: Exception) {
            giveBackMediaSocket(mediaSocket, mediaAddress)
            throw refused
        }
        val call = SipralCall(this, callHandle, mediaSocket, mediaAddress, incoming, textSocket)
        track(call, callHandle, mediaAddress)
        try {
            mapMediaSocket(mediaSocket, mediaAddress)
            if (how.plain) {
                call.answer(mediaAddress)
            } else {
                call.answerWith(mediaAddress, how.codecs, how.focus, how.feedback)
            }
        } catch (refused: Exception) {
            calls.remove(callHandle)
            giveBackMediaSocket(mediaSocket, mediaAddress)
            textSocket?.close()
            throw refused
        }
        return call
    }

    /** `sipral_call_reject`, for a call nothing has answered. */
    fun rejectCall(event: SipralEvent, code: Long = 486) {
        rejectCall(event.call, code)
    }

    /** [rejectCall] by call handle. */
    fun rejectCall(callHandle: Long, code: Long = 486) {
        retryBusy { Sipral.callReject(handle, callHandle, code, nowMs()) }
    }

    /**
     * Answer an incoming call with a 3xx instead (`sipral_call_redirect`, RFC
     * 3261 §21.3): 302 is call forwarding, [targets] in order of preference.
     * [reason] (`no-answer`, `user-busy`, `unconditional`, `deflection`,
     * `do-not-disturb` or any token) adds a `Diversion` (RFC 5806) naming the
     * called address.
     */
    fun redirectCall(event: SipralEvent, targets: List<String>, status: Int = 302, reason: String? = null) {
        redirect(event.call, targets, status, reason)
    }

    internal fun redirect(callHandle: Long, targets: List<String>, status: Int, reason: String?) {
        retryBusy {
            Sipral.callRedirect(handle, callHandle, status.toLong(), targets.joinToString(","), reason ?: "", nowMs())
        }
    }

    /** Who is calling, beyond the `From`, for the incoming call [event] names;
     * read it before deciding whether to answer. */
    fun callerIdentity(event: SipralEvent): SipralCallerIdentity =
        IdentityReader.identity(this, event.call, event.payload.call)

    /** How the incoming call [event] names asked to be answered and rung. */
    fun answering(event: SipralEvent): SipralAnswering =
        IdentityReader.answering(this, event.call, event.payload.call)

    /**
     * Take a REFER outside any dialog and place the call it asks for
     * (`sipral_call_accept_transfer`). `event` is a `SIPRAL_EVENT_KIND_REFERRAL`
     * whose [referralOf] has a zero `statusCode`.
     *
     * The stack answers 202, reports progress to the referrer, and places the
     * call from the event's account to the REFER's target. A media socket is
     * opened as for [placeCall], and the returned [SipralCall] is that call.
     * The referrer can make this line dial anything, so this is never done
     * automatically. With a [stunServer] it blocks like [placeCall]; call it
     * off the main thread.
     */
    fun acceptReferral(
        event: SipralEvent,
        mediaHost: String? = null,
        mediaPort: Int = 0,
        srtp: Long = 0,
        ice: SipralIce? = null,
    ): SipralCall {
        val mediaHost = mediaHostFor(mediaHost, accountFor(event.account), null)
        val mediaSocket = openMediaSocket(mediaHost, mediaPort)
        val mediaAddress = formatAddress(mediaSocket.localAddress.hostAddress, mediaSocket.localPort)
        val config = SipralCallConfig(
            mediaAddress = mediaAddress,
            srtp = srtp,
            ice = (ice?.value ?: 0).toLong(),
        )
        val placed = try {
            mapMediaSocket(mediaSocket, mediaAddress)
            retryBusy { Sipral.callAcceptTransfer(handle, event.call, config, nowMs()) }
        } catch (refused: Exception) {
            giveBackMediaSocket(mediaSocket, mediaAddress)
            throw refused
        }
        val call = SipralCall(this, placed, mediaSocket, mediaAddress)
        track(call, placed, mediaAddress)
        return call
    }

    /** Refuse a REFER outside any dialog with [code], 300 to 699:
     * `sipral_call_reject_transfer` on the referral's handle. */
    fun rejectReferral(event: SipralEvent, code: Long = 603) {
        retryBusy { Sipral.callRejectTransfer(handle, event.call, code, nowMs()) }
    }

    /** `sipral_announcement_forget`: the user dismissed a screen a push raised
     * before its INVITE came. `SIPRAL_STATUS_WRONG_STATE` when it was already
     * fulfilled or expired, since that event and this call can cross. */
    fun forgetAnnouncement(announcement: Long) {
        retryBusy { Sipral.announcementForget(handle, announcement) }
    }

    internal fun callFor(callHandle: Long): SipralCall? = calls[callHandle]

    /** A call whose media this client runs. With TURN over TCP or TLS, the
     * socket is kept past the call until its connection closes, since the last
     * farewell goes on it. */
    private fun track(call: SipralCall, callHandle: Long, mediaAddress: String) {
        calls[callHandle] = call
        if (turn != null && overStream(turn.transport.value.toLong())) {
            turnSockets[callHandle] = mediaAddress
        }
    }

    internal fun forgetCall(callHandle: Long) {
        calls.remove(callHandle)
    }

    // Connections to recording servers

    /** The TCP connections to recording servers, by the transport id each
     * was bound under. */
    private val recordingLinks = ConcurrentHashMap<Long, Socket>()

    /** The next transport id for a connection this layer opens. One counter for
     * every kind of connection keeps two from ever sharing an id. */
    internal val nextLink = java.util.concurrent.atomic.AtomicLong(FIRST_LINK)

    /** The recording sessions running, by handle: the call each records and
     * the connection it went over. */
    private val recordings = ConcurrentHashMap<Long, Pair<SipralCall, Long?>>()

    /**
     * Connect over TCP to a recording server at [destination] (`host:port`)
     * and bind it as its own transport, for [SipralCall.recordTo]: the INVITE
     * is too large for UDP (RFC 3261 §18.1.1). `TRANSPORT_DOWN` when refused.
     */
    internal fun openRecordingLink(destination: String): Long {
        val socket = Socket()
        try {
            socket.bind(InetSocketAddress(InetAddress.getByName(currentHost), 0))
            socket.connect(parseHostPort(destination), SignallingLink.PATIENCE_MS)
            socket.tcpNoDelay = true
        } catch (refused: Exception) {
            socket.close()
            throw SipralException(SipralStatus.TRANSPORT_DOWN, "the recording server $destination: ${refused.message}")
        }
        val id = nextLink.getAndIncrement()
        val local = formatAddress(socket.localAddress.hostAddress, socket.localPort)
        val remote = formatAddress(socket.inetAddress.hostAddress, socket.port)
        try {
            retryBusy { Sipral.stackTransportBind(handle, id, SipralTransport.TCP.value.toLong(), local, remote, nowMs()) }
        } catch (refused: SipralException) {
            socket.close()
            throw refused
        }
        recordingLinks[id] = socket
        Thread({ readRecordingLink(id, socket) }, "sipral-recording-$id").apply {
            isDaemon = true
            start()
        }
        return id
    }

    /** Close a connection to a recording server and unbind it. */
    internal fun closeRecordingLink(id: Long) {
        val socket = recordingLinks.remove(id) ?: return
        try {
            socket.close()
        } catch (_: Exception) {
            // closed either way
        }
        try {
            retryBusy { Sipral.stackStreamClosed(handle, id, nowMs()) }
        } catch (_: SipralException) {
            // the stack is going away
        }
    }

    private fun writeRecordingLink(id: Long, payload: ByteArray, len: Int) {
        val socket = recordingLinks[id] ?: return
        try {
            synchronized(socket) {
                socket.getOutputStream().write(payload, 0, len)
                socket.getOutputStream().flush()
            }
        } catch (_: Exception) {
            closeRecordingLink(id)
        }
    }

    private fun readRecordingLink(id: Long, socket: Socket) {
        val buffer = ByteArray(1 shl 16)
        val input = try {
            socket.getInputStream()
        } catch (_: Exception) {
            closeRecordingLink(id)
            return
        }
        while (!closed.get()) {
            val read = try {
                input.read(buffer)
            } catch (_: Exception) {
                -1
            }
            if (read < 0) {
                closeRecordingLink(id)
                return
            }
            if (read == 0) {
                continue
            }
            val bytes = buffer.copyOfRange(0, read)
            try {
                retryBusy(deadlineMs = 5_000) { Sipral.stackReceiveStream(handle, id, bytes, nowMs()) }
            } catch (_: SipralException) {
                closeRecordingLink(id)
                return
            }
        }
    }

    /** A recording session is running for [call], over [link] when it has
     * a connection of its own. */
    internal fun recordingStarted(recording: Long, call: SipralCall, link: Long?) {
        recordings[recording] = call to link
    }

    /** A recording session ended: its call stops copying, and the connection
     * closes a second later, once the answer to the BYE has left on it. */
    private fun recordingEnded(recording: Long) {
        val (call, link) = recordings.remove(recording) ?: return
        call.recordingEnded()
        if (link != null) {
            Thread({
                try {
                    Thread.sleep(1_000)
                } catch (_: InterruptedException) {
                }
                closeRecordingLink(link)
            }, "sipral-recording-close").apply {
                isDaemon = true
                start()
            }
        }
    }

    // RFC 3261 §18.1.1: a request too large for a datagram

    /** Whether a request too large for a datagram gets a connection
     * ([open]'s `streamFallback`). */
    private var streamFallback = true

    /** Where such a connection goes, when not to the address asked for
     * ([open]'s `streamServer`). */
    private var streamServer: String? = null

    /** TCP connections opened for oversized requests, by transport id, with
     * their destination; destinations being connected; and what
     * `TRANSPORT_WANTED` asked during the last poll, acted on after it. */
    private val streamLinks = ConcurrentHashMap<Long, Pair<String, Socket>>()
    private val streamsOpening: MutableSet<String> = ConcurrentHashMap.newKeySet()
    private val streamsAsked = java.util.concurrent.ConcurrentLinkedQueue<SipralTransportWantedEvent>()

    /** Trust and server name for an account's own TLS connection when the
     * account pins nothing: [open]'s `tlsTrust` and `tlsServerName`. */
    private var streamTlsTrust: SipralTlsTrust = SipralTlsTrust.Platform
    private var givenTlsServerName: String? = null

    /** Transport ids `TRANSPORT_FAILED` named during the same poll. */
    private val streamsLetGo = java.util.concurrent.ConcurrentLinkedQueue<Long>()

    /** Whether that poll retired the main TCP/TLS transport. The stack retires
     * a connection that stopped answering keep-alives (RFC 5626 §4.4.1) while
     * its socket is still open here. Poll thread only. */
    private var mainLetGo = false

    /** Remember a transport the stack let go of, to close after the poll: a
     * retired connection left open would stand in for the new one the stack
     * asks for. */
    internal fun noteStreamLetGo(id: Long) {
        streamsLetGo.add(id)
    }

    /** Answer `TRANSPORT_WANTED` from the last poll: connect to each
     * destination not already connected or connecting, on its own thread, or,
     * with `streamFallback` off, say none is coming. Retired connections are
     * closed first. */
    private fun actOnStreamsWanted() {
        while (true) {
            val letGo = streamsLetGo.poll() ?: break
            loseStreamLink(letGo, tell = false)
        }
        val seen = HashSet<String>()
        while (true) {
            val wanted = streamsAsked.poll() ?: return
            val destination = wanted.destination ?: continue
            if (!seen.add(destination) || streamLinks.values.any { it.first == destination }) {
                continue
            }
            // an account on its own connection asks with nothing outgrown, and is
            // opened whatever streamFallback says
            val opens = streamFallback || (wanted.requestBytes == 0L && wanted.limitBytes == 0L)
            // a WebSocket is a TCP or TLS connection bound as WS or WSS, whose
            // handshake and frames are the stack's
            val bound = SipralTransport.entries.firstOrNull { it.value.toLong() == wanted.protocol }
                ?.takeIf { it in STREAMS } ?: SipralTransport.TCP
            val over = if (bound == SipralTransport.TLS || bound == SipralTransport.WSS) {
                SipralTransport.TLS
            } else {
                SipralTransport.TCP
            }
            if (!opens) {
                sayNoStream(
                    nextLink.getAndIncrement(),
                    SipralTransportError.CONNECTION_REFUSED,
                    "to $destination not tried: streamFallback is off",
                )
                continue
            }
            if (!streamsOpening.add(destination)) {
                continue
            }
            val id = nextLink.getAndIncrement()
            Thread({ openStreamLink(id, destination, over, bound) }, "sipral-stream-$id").apply {
                isDaemon = true
                start()
            }
        }
    }

    /** What a TLS connection to [destination] trusts: the pin of an account on
     * its own connection there, else the client's `tlsTrust`. */
    private fun streamTrust(destination: String): SipralTlsTrust {
        val pinned = synchronized(movingLock) {
            accounts.values.firstOrNull {
                (it.streamProtocol == SipralTransport.TLS || it.streamProtocol == SipralTransport.WSS) &&
                    it.registrarAddress == destination && it.tlsPin != null
            }
        }
        return pinned?.tlsPin?.let { SipralTlsTrust.Pinned(it) } ?: streamTlsTrust
    }

    /** Connect over TCP or TLS to [destination] (or `streamServer` for TCP),
     * bind it under [id] as [bound] (WS/WSS for a WebSocket) and read it
     * until it closes. A failed connection is reported under the same id,
     * which ends whatever waited for it. */
    private fun openStreamLink(
        id: Long,
        destination: String,
        over: SipralTransport = SipralTransport.TCP,
        bound: SipralTransport = over,
    ) {
        val tls = over == SipralTransport.TLS
        val server = if (tls) destination else streamServer ?: destination
        val socket: Socket
        try {
            socket = if (tls) {
                SignallingLink(
                    SipralTransport.TLS, parseHostPort(destination),
                    givenTlsServerName ?: destination.substringBeforeLast(':'), streamTrust(destination),
                ).connect(currentHost).first
            } else {
                Socket().also { plain ->
                    try {
                        plain.bind(InetSocketAddress(InetAddress.getByName(currentHost), 0))
                        plain.connect(parseHostPort(server), SignallingLink.PATIENCE_MS)
                        plain.tcpNoDelay = true
                    } catch (refused: Exception) {
                        plain.close()
                        throw refused
                    }
                }
            }
        } catch (refused: Exception) {
            streamsOpening.remove(destination)
            val said = refused as? SignallingRefused ?: classify(refused, handshaking = false)
            val target = if (server == destination) destination else "$server (for $destination)"
            val why = if (said.detail.isEmpty()) "" else ": ${said.detail}"
            sayNoStream(id, said.error, "to $target ${verdict(said.error)}$why", over, if (tls) said.tls else null)
            return
        }
        streamLinks[id] = destination to socket
        streamsOpening.remove(destination)
        if (closed.get()) {
            loseStreamLink(id, tell = false)
            return
        }
        val local = formatAddress(socket.localAddress.hostAddress, socket.localPort)
        try {
            retryBusy {
                Sipral.stackTransportBind(handle, id, bound.value.toLong(), local, destination, nowMs())
            }
        } catch (refused: SipralException) {
            loseStreamLink(id, tell = false)
            sayNoStream(
                id,
                SipralTransportError.OTHER,
                "to $destination connected, and the stack would not bind it: ${refused.message}",
            )
            return
        }
        readStreamLink(id, socket)
    }

    /** `sipral_stack_transport_failed_with` for a connection not made; never
     * throws. [what] completes a sentence starting with "TCP" or "TLS" and
     * ends up in the event's detail. */
    private fun sayNoStream(
        id: Long,
        error: SipralTransportError,
        what: String,
        over: SipralTransport = SipralTransport.TCP,
        tls: org.sipral.SipralTlsFailure? = null,
    ) {
        try {
            retryBusy {
                Sipral.stackTransportFailedWith(
                    handle,
                    SipralTransportFailure(
                        transport = id,
                        error = error.value.toLong(),
                        tls = (tls?.value ?: 0).toLong(),
                        detail = sentence("${if (over == SipralTransport.TLS) "TLS" else "TCP"} $what"),
                    ),
                    nowMs(),
                )
            }
        } catch (_: SipralException) {
            // nothing waits any more, or the stack is going away
        }
    }

    /** What became of a connection, in the words a log line reads. */
    private fun verdict(error: SipralTransportError): String = when (error) {
        SipralTransportError.CONNECTION_REFUSED -> "refused"
        SipralTransportError.TIMED_OUT -> "timed out"
        SipralTransportError.UNREACHABLE -> "unreachable"
        SipralTransportError.CONNECTION_RESET -> "reset"
        SipralTransportError.CLOSED -> "closed"
        else -> "failed"
    }

    private fun writeStreamLink(id: Long, payload: ByteArray, len: Int) {
        val socket = streamLinks[id]?.second ?: return
        try {
            synchronized(socket) {
                socket.getOutputStream().write(payload, 0, len)
                socket.getOutputStream().flush()
            }
        } catch (_: Exception) {
            loseStreamLink(id, tell = true)
        }
    }

    /** Feed the connection's bytes, in order, to `sipral_stack_receive_stream`;
     * the far end closing it is `sipral_stack_stream_closed`. */
    private fun readStreamLink(id: Long, socket: Socket) {
        val buffer = ByteArray(TRANSMIT_BYTES)
        val input = try {
            socket.getInputStream()
        } catch (_: Exception) {
            loseStreamLink(id, tell = true)
            return
        }
        while (!closed.get()) {
            val read = try {
                input.read(buffer)
            } catch (_: Exception) {
                -1
            }
            if (read < 0) {
                loseStreamLink(id, tell = true)
                return
            }
            if (read == 0) {
                continue
            }
            val bytes = buffer.copyOfRange(0, read)
            try {
                retryBusy(deadlineMs = 5_000) { Sipral.stackReceiveStream(handle, id, bytes, nowMs()) }
            } catch (_: SipralException) {
                // the framing is lost: the stack retired the transport itself
                loseStreamLink(id, tell = false)
                return
            }
        }
    }

    /** Close the connection bound under [id] and, when [tell], say so with
     * `sipral_stack_stream_closed`. */
    private fun loseStreamLink(id: Long, tell: Boolean) {
        val (_, socket) = streamLinks.remove(id) ?: return
        try {
            socket.close()
        } catch (_: Exception) {
            // closed either way
        }
        if (!tell || closed.get()) {
            return
        }
        try {
            retryBusy { Sipral.stackStreamClosed(handle, id, nowMs()) }
        } catch (_: SipralException) {
            // the stack is going away
        }
    }

    // Media sockets behind a NAT

    // Media sockets `sipral_stack_nat_map` named whose call has no media handle
    // yet, by `host:port`. The poll thread reads them for
    // `sipral_stack_receive_stun` and sends from them what
    // `sipral_stack_poll_stun` names. Every read, send and close happens under
    // `natLock`, so the poll thread never touches a socket just given back; no
    // ABI call is made under it.
    private val natLock = Any()
    private val stunSockets = HashMap<String, DatagramSocket>()
    private val natWaiters = ConcurrentHashMap<String, NatWaiter>()

    /** One media socket's wait for `SIPRAL_EVENT_KIND_NAT_MAPPING` and,
     * with a TURN server, `SIPRAL_EVENT_KIND_NAT_RELAY`. */
    private class NatWaiter(needsRelay: Boolean) {
        val mapped = AtomicBoolean(false)
        val relayed = AtomicBoolean(!needsRelay)
        val done = CountDownLatch(1)

        /** Where the STUN server saw the socket from. */
        @Volatile
        var publicAddress: String? = null

        fun settle() {
            if (mapped.get() && relayed.get()) done.countDown()
        }
    }

    /**
     * `sipral_stack_nat_map` for a media socket about to carry a call, then
     * wait until the stack can describe the call; placing or answering before
     * that is `SIPRAL_STATUS_WRONG_STATE`. STUN answers within 5.5 s whatever
     * the server does; an unanswered TURN Allocate is abandoned after 39.5 s.
     * Does nothing without a STUN server.
     */
    private fun mapMediaSocket(mediaSocket: DatagramSocket, local: String): String? {
        if (stunServer == null) {
            return null
        }
        val waiter = NatWaiter(needsRelay = turnServer != null)
        mediaSocket.soTimeout = 1
        synchronized(natLock) { stunSockets[local] = mediaSocket }
        natWaiters[local] = waiter
        try {
            retryBusy { Sipral.stackNatMap(handle, local, nowMs()) }
            waiter.done.await(if (turnServer == null) 7L else 42L, TimeUnit.SECONDS)
        } finally {
            natWaiters.remove(local)
        }
        return waiter.publicAddress
    }

    /** The poll thread's half of [mapMediaSocket]'s wait. */
    private fun noteNat(event: SipralEvent) {
        val nat = natOf(event)
        val relay = relayOf(event)
        when {
            nat != null && nat.signalling == 0L -> natWaiters[nat.local ?: return]?.let {
                it.publicAddress = nat.mapped
                it.mapped.set(true)
                it.settle()
            }
            relay != null -> natWaiters[relay.local ?: return]?.let {
                it.relayed.set(true)
                it.settle()
            }
        }
    }

    /** The call on `local` has its media handle: its datagrams now go to
     * `sipral_media_receive` on [SipralMedia]'s thread. Called on the poll
     * thread, in the poll that raised `SIPRAL_EVENT_KIND_MEDIA_STARTED`. */
    internal fun mediaSocketTaken(local: String) {
        synchronized(natLock) { stunSockets.remove(local) }
    }

    /**
     * A media socket that will carry no call, or whose call ended before
     * media: `sipral_stack_nat_unmap` stops the mapping refresh and releases
     * the relay (the Refresh is sent from the socket itself), then the socket
     * is closed.
     */
    internal fun giveBackMediaSocket(mediaSocket: DatagramSocket, local: String) {
        val named = synchronized(natLock) { stunSockets.containsKey(local) }
        if (named) {
            try {
                retryBusy { Sipral.stackNatUnmap(handle, local, nowMs()) }
            } catch (_: Exception) {
                // a stack already destroyed keeps nothing to give back
            }
            drainStun()
        }
        synchronized(natLock) {
            stunSockets.remove(local)
            mediaSocket.close()
        }
        giveBackPort(parseHostPort(local).port)
    }

    /**
     * `sipral_stack_poll_stun`: send each request from the socket the stack
     * names, since the source address the server sees is the point. Buffers
     * are local because the poll thread and a thread giving a socket back can
     * both be here.
     */
    private fun drainStun() {
        if (stunServer == null) {
            return
        }
        val data = ByteArray(PACKET_BYTES)
        val destination = ByteArray(ADDRESS_BYTES)
        val source = ByteArray(ADDRESS_BYTES)
        val lens = LongArray(4)
        var busyFor = 0
        while (true) {
            val status = SipralSignalNative.stackPollStun(handle, data, destination, source, lens)
            if (status == SipralStatus.BUSY.value && busyFor < 500) {
                busyFor += 1
                Thread.sleep(1)
                continue
            }
            val len = lens[0].toInt()
            if (status != SipralStatus.OK.value || len == 0) {
                return
            }
            val from = String(source, 0, lens[2].toInt(), Charsets.UTF_8)
            if (overStream(lens[3])) {
                // to the TURN server on its connection, never as a datagram, which a
                // network that blocks UDP drops
                writeTurn(from, data.copyOfRange(0, len))
                continue
            }
            val to = parseHostPort(String(destination, 0, lens[1].toInt(), Charsets.UTF_8))
            synchronized(natLock) {
                try {
                    stunSockets[from]?.send(DatagramPacket(data.copyOfRange(0, len), len, to))
                } catch (_: Exception) {
                    // best effort: the stack retransmits what goes unanswered
                }
            }
        }
    }

    /** Read the media sockets not yet handed to a call, under `natLock`, and
     * pass the data to `sipral_stack_receive_stun` outside it. */
    private fun receiveStun() {
        val arrived = ArrayList<Triple<ByteArray, String, String>>()
        synchronized(natLock) {
            val buffer = ByteArray(2048)
            for ((local, mediaSocket) in stunSockets) {
                while (true) {
                    val packet = DatagramPacket(buffer, buffer.size)
                    try {
                        mediaSocket.receive(packet)
                    } catch (_: Exception) {
                        break
                    }
                    val from = formatAddress(packet.address.hostAddress, packet.port)
                    arrived += Triple(packet.data.copyOfRange(0, packet.length), from, local)
                }
            }
        }
        for ((data, from, local) in arrived) {
            try {
                retryBusy { Sipral.stackReceiveStun(handle, data, from, local, nowMs()) }
            } catch (_: SipralException) {
                // a stranger's datagram, or early media before the session opens:
                // refused, at the cost of that one datagram
            }
        }
    }

    // A TURN server reached over TCP or TLS

    // Each media socket's connection to the TURN server, by `host:port`; what
    // `SIPRAL_EVENT_KIND_TURN_STREAM` asked during the last poll (nothing may
    // call into the stack from its own callback); and each call's socket, for
    // its last farewell.
    private val turnStreams = ConcurrentHashMap<String, TurnStream>()
    private val turnAsked = java.util.concurrent.ConcurrentLinkedQueue<org.sipral.SipralTurnStreamEvent>()
    private val turnSockets = ConcurrentHashMap<Long, String>()

    /** Write [payload] whole on [local]'s TURN connection. Thread-safe; a
     * connection that fails here is closed and the stack told, which loses
     * the relay on it. */
    internal fun writeTurn(local: String, payload: ByteArray) {
        val stream = turnStreams[local] ?: return
        try {
            synchronized(stream) {
                stream.output.write(payload)
                stream.output.flush()
            }
        } catch (_: Exception) {
            loseTurnStream(local, tell = true)
        }
    }

    /** Open or close what `TURN_STREAM` asked in the last poll, after this
     * round's queues were written. */
    private fun actOnTurnStreams() {
        while (true) {
            val said = turnAsked.poll() ?: return
            val local = said.local ?: continue
            when (said.state) {
                org.sipral.SipralTurnStream.OPEN.value.toLong() ->
                    Thread({ openTurnStream(local, said.server ?: return@Thread, said.protocol) }, "sipral-turn").apply {
                        isDaemon = true
                        start()
                    }
                org.sipral.SipralTurnStream.CLOSE.value.toLong() -> {
                    turnSockets.entries.removeIf { it.value == local }
                    loseTurnStream(local, tell = false)
                }
            }
        }
    }

    /** Connect to the TURN server for [local], over TLS checked against
     * [SipralTurnServer.serverName] when [protocol] says so, report the
     * outcome, and read it until it closes. */
    private fun openTurnStream(local: String, server: String, protocol: Long) {
        val turn = turn ?: return
        val stream = try {
            val raw = Socket()
            raw.connect(parseHostPort(server), 5_000)
            raw.tcpNoDelay = true
            val socket = if (protocol == SipralTransport.TLS.value.toLong()) {
                val name = turn.serverName ?: server.substring(0, server.lastIndexOf(':'))
                val factory = turn.sslSocketFactory ?: SSLSocketFactory.getDefault() as SSLSocketFactory
                (factory.createSocket(raw, name, raw.port, true) as SSLSocket).apply {
                    sslParameters = sslParameters.apply {
                        endpointIdentificationAlgorithm = "HTTPS"
                        serverNames = listOf(SNIHostName(name))
                    }
                    startHandshake()
                }
            } else {
                raw
            }
            TurnStream(socket)
        } catch (_: Exception) {
            sayTurn(local) { Sipral.stackTurnClosed(handle, local, nowMs()) }
            return
        }
        if (closed.get()) {
            stream.socket.close()
            return
        }
        turnStreams[local] = stream
        sayTurn(local) { Sipral.stackTurnConnected(handle, local, nowMs()) }
        val buffer = ByteArray(TRANSMIT_BYTES)
        while (true) {
            val read = try {
                stream.input.read(buffer)
            } catch (_: Exception) {
                -1
            }
            if (read < 0) {
                loseTurnStream(local, tell = true)
                return
            }
            if (read > 0 && !turnReceived(local, buffer.copyOfRange(0, read))) {
                loseTurnStream(local, tell = false)
                return
            }
        }
    }

    private fun sayTurn(local: String, entry: () -> Unit) {
        try {
            retryBusy(action = entry)
        } catch (_: Exception) {
            // the stack is going away, and with it everything on [local]
        }
    }

    /** Feed a connection's bytes to `sipral_stack_turn_receive`. Every byte,
     * in order: a stream that loses one never resyncs, so a busy stack is
     * waited for rather than skipped. False when the stack found it broken. */
    private fun turnReceived(local: String, bytes: ByteArray): Boolean {
        while (!closed.get()) {
            try {
                Sipral.stackTurnReceive(handle, local, bytes, nowMs())
                return true
            } catch (refused: SipralException) {
                when (refused.status) {
                    SipralStatus.BUSY, SipralStatus.CLOCK_BEHIND -> Thread.sleep(1)
                    SipralStatus.STREAM_BROKEN -> return false
                    else -> return true
                }
            }
        }
        return true
    }

    /** Close [local]'s connection and, when [tell], report it with
     * `sipral_stack_turn_closed` (not for one the stack closed or found
     * broken). */
    private fun loseTurnStream(local: String, tell: Boolean) {
        val stream = turnStreams.remove(local) ?: return
        try {
            synchronized(stream) { stream.socket.close() }
        } catch (_: Exception) {
            // closed either way
        }
        if (tell) {
            sayTurn(local) { Sipral.stackTurnClosed(handle, local, nowMs()) }
        }
    }

    // The network changing under the client

    /**
     * The platform said the network changed: `sipral_stack_network_changed`,
     * then whatever its answer asks of this client's sockets.
     *
     * On `SipralRecovery.REBUILD` (address or interface changed) the UDP
     * signalling socket is bound again at [next]'s address on the same port
     * ([keptSignallingPort] says if that failed), handed to the stack, and
     * every account is re-pointed (`sipral_account_rebind`) so the following
     * REGISTER names the new address. A client opened with no `bindHost`
     * keeps its socket and re-picks its advertised address as at open. Every
     * active call then raises `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED`, since
     * the far end still sends to the old address; [SipralCall.moveMedia]
     * offers the new one. Lesser changes only re-register. Safe to call on
     * every platform notification; `NOTHING` is the usual answer.
     */
    fun networkChanged(next: SipralNetwork): SipralRecovery = synchronized(movingLock) {
        val previous = network
        val moves = next.link != SipralLink.DOWN &&
            (next.address != previous.address || next.interfaceName != previous.interfaceName)
        var rebound: String? = null
        val link = link
        val picks = picksAddress
        if (moves && link != null) {
            rebound = link.move(next.address ?: bindAddress.substringBeforeLast(':'))
        } else if (moves && picks) {
            // a socket bound everywhere already receives at the new address; only
            // what is advertised moves. An address this machine lacks is refused,
            // as for a client bound at one.
            next.address?.let { DatagramSocket(0, InetAddress.getByName(it)).close() }
            keptSignallingPort = true
            rebound = advertiseAgain(next.address)
        } else if (moves) {
            val host = next.address ?: bindAddress.substringBeforeLast(':')
            val fresh = signallingSocket(InetAddress.getByName(host))
            fresh.soTimeout = 20
            val local = formatAddress(fresh.localAddress.hostAddress, fresh.localPort)
            val status = retryBusy {
                SipralSignalNative.stackTransportRebind(handle, local.toByteArray(Charsets.UTF_8), nowMs()).also {
                    throwIfPassing(it)
                }
            }
            if (status != SipralStatus.OK.value) {
                fresh.close()
                throw SipralException(SipralStatus.of(status), Sipral.lastErrorMessage())
            }
            val old = socket
            socket = fresh
            bindAddress = local
            old?.close()
            rebound = local
        }
        val raw = retryBusy {
            Sipral.stackNetworkChanged(
                handle,
                previous.link.value.toLong(), previous.address ?: "", previous.interfaceName ?: "",
                if (previous.resolves) 1L else 0L,
                next.link.value.toLong(), next.address ?: "", next.interfaceName ?: "",
                if (next.resolves) 1L else 0L,
                nowMs(),
            )
        }
        network = next.copy(address = next.address ?: previous.address)
        if (rebound != null) {
            for (account in accounts.values) {
                // each account is reached at the route toward its own server
                val server = account.registrarAddress
                val local = if (picks && account.derivesContact && isAddress(server)) advertiseToward(server) else rebound
                account.rebind(local, previous.address)
            }
        }
        SipralRecovery.of(raw.toInt()) ?: SipralRecovery.UNKNOWN
    }

    /**
     * The UDP signalling socket bound again at [host], on the port chosen at
     * open (or the current one when that was zero); a system-chosen port only
     * when another socket holds it, which [keptSignallingPort] reports. The
     * old socket may itself hold the port, so it is closed (ending the poll
     * thread's receive) before the port is tried again.
     */
    private fun signallingSocket(host: InetAddress): DatagramSocket {
        val inUse = socket?.localPort ?: 0
        val wanted = if (chosenPort != 0) chosenPort else inUse
        fun on(port: Int): DatagramSocket? =
            try {
                DatagramSocket(port, host)
            } catch (_: java.net.SocketException) {
                null
            }
        var made = if (wanted == 0) null else on(wanted)
        // the old socket is closed only for an address this machine has; a move
        // to one it lacks throws below with the socket still open
        if (made == null && wanted != 0 && inUse == wanted && on(0)?.also { it.close() } != null) {
            socket?.close()
            socket = null
            made = on(wanted)
        }
        keptSignallingPort = made != null || wanted == 0
        return made ?: DatagramSocket(0, host)
    }

    /** The address the client's sockets are bound on now. */
    internal val currentHost: String
        get() = synchronized(movingLock) { network.address } ?: bindAddress.substringBeforeLast(':')

    /** Runs [body] with no network change half done; held by
     * [SipralCall.moveMedia] while it binds and offers. */
    internal fun <T> moving(body: () -> T): T = synchronized(movingLock) { body() }

    /** `mapMediaSocket` for the socket [SipralCall.moveMedia] binds: where the
     * STUN server sees it from, or null on a client without one. */
    internal fun mapMovedSocket(mediaSocket: DatagramSocket, local: String): String? =
        mapMediaSocket(mediaSocket, local)

    /** `sipral_stack_nat_unmap` for a call's old socket, so the stack stops
     * refreshing it. */
    internal fun forgetMapping(local: String) {
        if (stunServer == null) {
            return
        }
        try {
            retryBusy { Sipral.stackNatUnmap(handle, local, nowMs()) }
        } catch (_: SipralException) {
            // a mapping the stack already let go of
        }
    }

    // The library's own audio engine

    /** An encoded microphone packet, sent from its call's media socket or on
     * its TURN connection. Runs on the engine's thread, which must not call
     * the engine back. */
    private fun transmitAudio(transmit: SipralAudioTransmit) {
        val call = calls[transmit.call] ?: return
        val payload = transmit.payload ?: return
        if (overStream(transmit.protocol)) {
            writeTurn(call.mediaAddress, payload)
            return
        }
        val destination = transmit.destination ?: return
        call.sendOnMediaSocket(payload, parseHostPort(destination))
    }

    // The poll thread

    private fun onEvent(event: SipralEvent) {
        // Side effects first, delivery second: a coroutine woken by `events` must
        // find `callFor(event.call)` already current.
        turnStreamOf(event)?.let { turnAsked.add(it) }
        if (link == null) {
            transportWantedOf(event)?.let { streamsAsked.add(it) }
            transportFailedOf(event)?.let { noteStreamLetGo(it.transport) }
        } else if (transportFailedOf(event)?.transport == Sipral.TRANSPORT_MAIN) {
            mainLetGo = true
        }
        noteNat(event)
        noteLocate(event)
        calls[event.call]?.deliver(event)
        if (event.kind == SipralEventKind.CALL_ENDED.value.toLong()) {
            recordingEnded(event.call)
        }
        eventsFlow.tryEmit(event)
    }

    private fun drainTransmit() {
        val data = ByteArray(TRANSMIT_BYTES)
        val destination = ByteArray(ADDRESS_BYTES)
        val lens = LongArray(4)
        while (true) {
            val status = SipralSignalNative.stackPollTransmit(handle, data, destination, lens)
            val len = lens[0].toInt()
            if (status != SipralStatus.OK.value || len == 0) {
                return
            }
            if (streamLinks.containsKey(lens[3])) {
                // a connection opened for a request too large for a datagram
                writeStreamLink(lens[3], data, len)
                continue
            }
            if (lens[3] != 0L) {
                // a recording session's own connection
                writeRecordingLink(lens[3], data, len)
                continue
            }
            val link = link
            if (link != null) {
                // one connection carries everything: it reaches the outbound proxy
                link.write(data, len)
                continue
            }
            val destinationLen = lens[1].toInt()
            val to = parseHostPort(String(destination, 0, destinationLen, Charsets.UTF_8))
            try {
                socket?.send(DatagramPacket(data, len, to))
            } catch (_: Exception) {
                // best effort: the poll loop never throws
            }
        }
    }

    /**
     * Send what a just-ended call still owes (its RTCP BYE and, with TURN, the
     * Refresh releasing its relay) from its own media socket to the address
     * the stack names. Under ICE that is the selected path or the TURN server,
     * not necessarily the last address media came from.
     */
    private fun drainFarewells() {
        val data = ByteArray(PACKET_BYTES)
        val destination = ByteArray(ADDRESS_BYTES)
        val lens = LongArray(3)
        val outCall = LongArray(1)
        while (true) {
            val status = SipralMediaNative.stackPollFarewell(handle, data, destination, lens, outCall)
            val len = lens[0].toInt()
            if (status != SipralStatus.OK.value || len == 0) {
                return
            }
            if (overStream(lens[2])) {
                // on the relay's connection, which belongs to the client and outlives
                // the call
                turnSockets[outCall[0]]?.let { writeTurn(it, data.copyOfRange(0, len)) }
                continue
            }
            val call = calls[outCall[0]] ?: continue
            val named = lens[1].toInt()
            val to = if (named > 0) {
                parseHostPort(String(destination, 0, named, Charsets.UTF_8))
            } else {
                call.media?.remoteAddress ?: continue
            }
            call.sendOnMediaSocket(data.copyOfRange(0, len), to)
        }
    }

    private fun run() {
        val buffer = ByteArray(TRANSMIT_BYTES)
        while (!closed.get()) {
            try {
                // this pass's socket: [networkChanged] closes the one it replaces, which
                // ends a receive waiting on it
                val listening = socket
                if (listening == null) {
                    // over TCP or TLS the connection has its own reader; this only keeps the
                    // poll cadence
                    Thread.sleep(20)
                    throw SocketTimeoutException()
                }
                val arrivedAt = bindAddress
                val packet = DatagramPacket(buffer, buffer.size)
                listening.receive(packet)
                val from = formatAddress(packet.address.hostAddress, packet.port)
                retryBusy {
                    Sipral.stackReceiveDatagram(
                        handle,
                        /* SIPRAL_TRANSPORT_MAIN */ 0,
                        packet.data.copyOfRange(0, packet.length),
                        from,
                        arrivedAt,
                        nowMs(),
                    )
                }
            } catch (_: SocketTimeoutException) {
                // expected: the receive timeout is what gives the loop its cadence
            } catch (_: Exception) {
                if (closed.get()) {
                    return
                }
            }
            if (closed.get()) {
                return
            }
            receiveStun()
            try {
                Sipral.stackPoll(handle, nowMs())
            } catch (_: Exception) {
                continue
            }
            drainTransmit()
            drainStun()
            drainFarewells()
            actOnTurnStreams()
            actOnStreamsWanted()
            actOnLookups()
            if (mainLetGo) {
                mainLetGo = false
                link?.letGo()
            }
        }
    }

    /**
     * Hang up every open call, let the goodbyes drain, then
     * `sipral_media_release`, `sipral_stack_destroy` and close the socket.
     *
     * Idempotent. Calls are hung up before their own [SipralCall.close]
     * releases the media handle, because the poll thread drains the BYE and
     * RTCP goodbye only while the call is tracked and its socket open.
     */
    override fun close() {
        if (!closed.compareAndSet(false, true)) {
            return
        }
        val open = calls.values.toList()
        for (call in open) {
            if (!call.ended) {
                try {
                    call.hangup()
                } catch (_: Exception) {
                    // best effort on the way out
                }
            }
        }
        if (open.isNotEmpty()) {
            Thread.sleep(200)
        }
        for (call in open) {
            call.close()
        }
        // A socket mapped for a call never placed still holds a relay the server
        // keeps for up to ten minutes; `sipral_stack_destroy` sends nothing.
        val unspent = synchronized(natLock) { stunSockets.toList() }
        for ((local, mediaSocket) in unspent) {
            giveBackMediaSocket(mediaSocket, local)
        }
        if (Thread.currentThread() !== thread) {
            thread.join(5000)
        }
        // and every TURN connection still open
        for (local in turnStreams.keys.toList()) {
            loseTurnStream(local, tell = false)
        }
        link?.close()
        for (id in recordingLinks.keys.toList()) {
            recordingLinks.remove(id)?.close()
        }
        for (id in streamLinks.keys.toList()) {
            loseStreamLink(id, tell = false)
        }
        Sipral.stackDestroy(handle)
        socket?.close()
    }
}
