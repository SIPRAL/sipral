// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// The idiomatic Kotlin layer over org.sipral.Sipral (SipralAbi.kt, printed
// by tools/abi-gen and never edited here): classes over the handles, events
// as a kotlinx.coroutines Flow, and suspend functions where the ABI
// completes through an event rather than through its own return value --
// the shape docs/08-ffi.md asks a binding author to build once they have
// met the threading rules in its own first section, and the one
// bindings/python (cffi, asyncio) and bindings/kotlin (JNI, coroutines)
// both build over the same six calls: create, poll, the two receive
// entry points, poll_transmit and destroy.

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
import org.sipral.SipralIce
import org.sipral.SipralLink
import org.sipral.SipralLogLevel
import org.sipral.SipralLogListener
import org.sipral.SipralNat
import org.sipral.SipralRecovery
import org.sipral.SipralSrtp
import org.sipral.SipralStackConfig
import org.sipral.SipralStirConfig
import org.sipral.SipralStatus
import org.sipral.SipralToggle
import org.sipral.SipralTransport
import org.sipral.SipralTransportFailure
import org.sipral.SipralTransportError

private const val TRANSMIT_BYTES = 1 shl 16
private const val ADDRESS_BYTES = 64
private const val PACKET_BYTES = 1500

/** The first transport id a connection this layer opens is bound under --
 * to a recording server, or for `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` -- one
 * more for each after it, whichever it is for: clear of the main transport
 * and of the small numbers an application driving [org.sipral.Sipral]
 * itself would pick. */
private const val FIRST_LINK = 64L

internal fun formatAddress(host: String, port: Int): String = "$host:$port"

internal fun parseHostPort(text: String): InetSocketAddress {
    val at = text.lastIndexOf(':')
    return InetSocketAddress(text.substring(0, at), text.substring(at + 1).toInt())
}

/** Whether a `SipralTransport` number marks bytes for a TURN server's
 * connection rather than a datagram. */
internal fun overStream(protocol: Long): Boolean =
    protocol == SipralTransport.TCP.value.toLong() || protocol == SipralTransport.TLS.value.toLong()

/** One media socket's TCP or TLS connection to the TURN server: written by
 * the poll thread and by the call's media thread, each write whole under
 * the stream's own lock; read by a thread of its own. */
private class TurnStream(val socket: Socket) {
    val input: InputStream = socket.getInputStream()
    val output: OutputStream = socket.getOutputStream()
}

/**
 * One `sipral_stack_create` handle, its signalling socket and its poll
 * thread: the class an application reaches for first.
 *
 * Built with [SipralClient.open], torn down with [close] (also reached
 * through `use { }`), which calls `sipral_stack_destroy` exactly once. Not
 * built with a public constructor: the socket has to be open, bound and
 * its address known before `sipral_stack_create` is ever called, since
 * that address is what every `Via` this stack writes carries.
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

    /** The signalling socket's address, `host:port`: where it was bound, and
     * after [networkChanged] where it is bound now. Over TCP or TLS, the
     * address the connection to the server was made from, which moves with
     * every connection made again. A client opened with no `bindHost`
     * listens on every interface, and this is the address it advertises:
     * the route toward its first account's server. */
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

    /**
     * The library's audio engine -- the devices, their gain, mute and level,
     * the ring and when they are open -- in [SipralAudioMode.Device], and
     * null in [SipralAudioMode.Application], where the application runs the
     * audio itself.
     */
    var audio: SipralAudioDevices? = null
        private set

    /** Serialises a network change with the calls it moves, so that every
     * account points at the new address before any call is offered there;
     * also guards [network] and [accounts]. */
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
     * Every event this stack's listener heard, in the order it heard them.
     *
     * Bounded, not unbounded: at most 4096 unread events are kept per
     * collector's own lag behind the poll thread. `DROP_OLDEST` means a
     * collector that falls more than 4096 events behind -- doing real work
     * per event, or simply not reading for a while -- has its oldest unread
     * events silently discarded to make room, with no exception and no
     * signal that anything was dropped; it never blocks the poll thread and
     * never grows without bound. A collector that intends to see every
     * event has to keep its own per-event work short, or hand events off to
     * something else (a channel, a queue) rather than do the work inline in
     * `collect`.
     */
    val events: SharedFlow<SipralEvent> = eventsFlow

    private val calls = ConcurrentHashMap<Long, SipralCall>()
    private val closed = AtomicBoolean(false)

    private lateinit var thread: Thread

    companion object {
        /**
         * Open a UDP socket, bind it, and build a [SipralClient] over it.
         *
         * `bindHost`/`bindPort` name where this stack's own socket binds;
         * `0` for the port picks an ephemeral one, read back from
         * [SipralClient.bindAddress] once this returns -- the same
         * two-step `bindings/python/sipral/stack.py` follows, because the
         * ABI has to be told the address before it exists.
         *
         * Every option left null is this build's own default, which is what
         * a client opened before the option existed does. [ice] is what
         * every call does about ICE (RFC 8445) unless [placeCall] says
         * otherwise; `SipralIce.OFF` by default. [stunServer], as
         * `host:port` -- an address, not a name -- turns on
         * `SIPRAL_NAT_STUN`: the signalling socket asks it where it appears
         * from, every account's `Contact` moves to that public address
         * (`SIPRAL_EVENT_KIND_NAT_MAPPING`, read with [natOf]), and every
         * media socket [placeCall] or [answerCall] opens is asked the same
         * before its call is described, so the SDP a far end reads names an
         * address it can actually send to. [turn] adds a relay on a TURN
         * server for each of those media sockets, offered as the call's
         * relayed ICE candidate ([relayOf]); it needs [stunServer] too, and
         * a call only uses the relay under ICE. [SipralTurnServer.transport]
         * reaches it over TCP or TLS instead of UDP, the client opening each
         * connection itself. [g729AnnexB] allows G.729's
         * silence compression, on by default. `SipralIce.LITE` is for a
         * server reachable at the address it advertises, answering full ICE
         * peers, and nothing else (`docs/06-nat.md`, "ICE-lite").
         *
         * [referrals] set to true hands a REFER outside any dialog --
         * click-to-dial from a switchboard -- to the application as
         * `SIPRAL_EVENT_KIND_REFERRAL` (read with [referralOf]), to take with
         * [acceptReferral] or refuse with [rejectReferral]. Off by default,
         * when every one is refused 403: a peer that can make a phone dial
         * is a toll-fraud vector, so each one is the application's decision.
         *
         * [registrarKeepalive] keeps the registrar's flow open behind a
         * NAT: every account [stunServer] showed to be behind one sends its
         * registrar a double CRLF every [registrarKeepaliveMs] (`0` for 25
         * seconds, 1 000 to 120 000), so that a NAT filtering by address and
         * port still lets the registrar's INVITE in minutes after the
         * REGISTER. On by default; false turns it off, and an interval with
         * it off is refused. Nothing is sent while the stack is suspended.
         *
         * [audio] says who runs the calls' audio:
         * [SipralAudioMode.platformDefault], the library's own engine
         * wherever this build has one for the platform, unless the
         * application pumps the frames itself with
         * [SipralAudioMode.Application]. Under `SipralAudioActivation.MANUAL`
         * the devices open only between [SipralAudioDevices.activate] and
         * [SipralAudioDevices.deactivate], rather than with the first call's
         * media and the last call's end. [audioProbeMs] bounds how long a
         * platform call about the devices may block before it is reported as
         * `DEVICE_TIMED_OUT` (`0` for three seconds), and [audioDeviceRateHz]
         * is the rate the devices are asked to run at (`0` for 48 000).
         *
         * [maxDialogs] is the most calls the client holds at once, either
         * way (`0` for 128): one that arrives past it is answered 503, and
         * one placed past it throws with `LIMIT_REACHED`.
         * [maxServerTransactions] is the most requests from other ends it
         * works on at once (`0` for 256). [diagnosticDecisions] and
         * [diagnosticRecords] bound the diagnostic record: decisions kept
         * per call (`0` for 64) and calls kept (`0` for 32).
         *
         * [network] is the network the client starts on, what the first
         * [networkChanged] compares with: a wired link at [bindHost], on no
         * interface in particular, unless the application knows better.
         *
         * [srtp] is what every call does about SRTP unless [placeCall]'s own
         * `srtp` says otherwise: offered, required, or keyed by DTLS-SRTP,
         * whose suite `SIPRAL_EVENT_KIND_MEDIA_SECURED` names ([srtpSuiteOf]).
         *
         * [stunFallbacks] are the STUN servers to turn to, in order, when
         * [stunServer] does not answer in five and a half seconds or answers
         * without an address, each `host:port`: every socket asking the one
         * that failed moves to the next at once, the one that failed is
         * passed over for thirty seconds and twice as long each time it
         * fails again, up to ten minutes, and `SIPRAL_EVENT_KIND_STUN_SERVER`
         * (read with [stunServerOf]) says when the server in use moves or
         * every one has failed.
         *
         * [rtpPortMin] and [rtpPortMax] are the range a firewall in front of
         * this machine was opened for: every media socket this client opens
         * without an explicit port then binds an even port from it, reserved
         * with `sipral_stack_rtp_port_reserve`, with the odd one above kept
         * for RTCP (RFC 3550 §11), and a call is refused a port outside it.
         * Both `0` -- the default -- leave the ports to the operating system.
         * Every pair taken throws `SipralStatus.EXHAUSTED` rather than binding
         * outside the range.
         *
         * [dtmfDetection] is when a call listens for keypad digits in the far
         * end's audio: `AUTO` on the calls that negotiated no telephone
         * event, `ALWAYS` or `OFF`; [SipralCall.setDtmfDetection] changes it
         * for one call.
         *
         * [signalling] is what SIP travels over: `SipralTransport.UDP` (the
         * default) on a socket bound at [bindHost], or `TCP` or `TLS` on one
         * connection to [signallingServer] (`host:port` -- the registrar or
         * the outbound proxy, 5061 for TLS by convention), which every
         * account and every call on this client then shares, and on which
         * the server's own requests arrive. Over TLS the server's
         * certificate is checked against [tlsServerName] (the host part of
         * [signallingServer] when null) with [tlsTrust]: the platform's
         * authorities, a private authority beside them, or only one
         * authority (`docs/22-tls.md`). Nothing here turns the check off.
         *
         * The first connection is made here, before this returns. When it
         * fails, or later breaks, the stack is told why and raises
         * `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`, read with [transportFailedOf]:
         * untrusted, a name that does not match, expired, a handshake
         * refused or a server that refused the connection, with
         * `SSLSocket`'s own words; and this client connects again, one
         * second after the loss and twice as long after each attempt that
         * fails, up to thirty seconds. Once connected again every account is
         * pointed at the new connection and registered again if it was
         * registering. [SipralAccount.register] asked while it is down is
         * kept for then; a call placed meanwhile throws with
         * `SipralStatus.TRANSPORT_DOWN`.
         *
         * [inviteLimit] is how fast one address may ring this client:
         * [SipralInviteLimit.DEFAULT] (what every client starts with, ten
         * INVITEs at once then one every two seconds, past which a call is
         * answered 480) or [SipralInviteLimit.VOICE_AGENT] for a service
         * taking a trunk's calls.
         *
         * [streamFallback] is what a client signalling over UDP does when a
         * request is too large for a datagram -- nearly always the answer to
         * a challenge, whose `Authorization` takes a call offering two SRTP
         * suites past RFC 3261 §18.1.1's 1300 bytes. On (the default),
         * `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` (read with
         * [transportWantedOf]) is answered by opening a TCP connection to the
         * address it names -- the registrar or proxy the request was going
         * to, on the same port -- and binding it
         * (`sipral_stack_transport_bind`): the request the stack was holding
         * goes on it, and the call or registration carries on over it. When
         * that connection is refused or times out, or with false, the stack
         * is told at once (`sipral_stack_transport_failed_with`, whose detail
         * names where the connection was going and whether it was refused,
         * timed out or not tried), and what was
         * waiting ends rather than hanging: a call as unreachable, its
         * `causeSip` 513 and its `causeText` naming the size and the limit.
         * The event reaches [events] either way. [streamServer]
         * (`host:port`) is where that connection goes instead, for a server
         * that takes TCP on another port than UDP -- a PBX on 5060 for one
         * and 5160 for the other: the connection stands for the address the
         * event named, and everything the stack sends there goes on it.
         *
         * [bindHost] is the address the signalling socket is bound at and
         * advertises. Left null, the socket listens on every interface and
         * the client advertises the address of the operating system's route
         * toward the server of its first account (`sipral_advertised_address`):
         * the address a PBX on the network reaches this device at, and
         * `127.0.0.1` for one on this machine. Each account is reached at the
         * route toward its own server, and a call's media socket, when
         * `mediaHost` is null, at the route toward the far end or the
         * account's server. A loopback address is never advertised to a peer
         * elsewhere: the library refuses that with `UNREACHABLE_ADDRESS`.
         *
         * [srtp] may be `SipralSrtp.BEST_EFFORT`: SDES offered on plain
         * `RTP/AVP`, the call encrypted when the answer takes a key and plain
         * when it takes none, for a PBX that answers an `RTP/SAVP` offer with
         * 488. [srtpSuites] are the SRTP suites every call offers and accepts
         * unless its account names its own, most preferred first, by their
         * RFC 4568 and RFC 7714 names.
         *
         * [pathMtu] is the MTU of the path toward the server when the
         * deployment knows it (`0` for unknown, else 576 or more): RFC 3261
         * §18.1.1 moves a request to a stream within 200 bytes of it.
         * [datagramWithoutStreamBytes] is a deliberate deviation from that
         * section, for a server that takes SIP over UDP alone: once no stream
         * to it can be had, a request up to this many bytes goes over UDP
         * anyway (`0` for never, at most 65 507), and [diagnosticsJson] says
         * so as `transport.kept.datagram`.
         *
         * [pseudonymSalt] (16 bytes or more, kept by the installation) keys
         * the pseudonyms the log and [state] write, so that two runs' traces
         * compare line by line; it is a secret, like a key.
         * [diagnosticTrace] writes whole SIP messages at the trace level,
         * peers included and credentials and keys taken out, for a diagnosis;
         * [setDiagnosticTrace] turns it on and off later.
         *
         * [resolver] answers `SIPRAL_EVENT_KIND_LOOKUP_WANTED` for the
         * accounts added with a `serverUri`, on a thread of its own per
         * lookup; [SipralDns.platform] when null.
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
            client.streamFallback = streamFallback
            client.streamServer = streamServer
            client.routes = bindHost == null
            client.routeChosen = bindHost != null || streamed || streamServer != null
            client.resolver = resolver ?: SipralDns.platform
            try {
                client.start(
                    userAgent, codecs, ice, turn, g729AnnexB, referrals,
                    registrarKeepalive, registrarKeepaliveMs, audioProbeMs, audioDeviceRateHz, srtp,
                    maxDialogs, maxServerTransactions, diagnosticDecisions, diagnosticRecords,
                    stunFallbacks, dtmfDetection, signalling, inviteLimit,
                    Tail(srtpSuites, pathMtu, datagramWithoutStreamBytes, pseudonymSalt, diagnosticTrace),
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

    /** The ABI 0.34 members of the stack's configuration, as [open] took
     * them. */
    private class Tail(
        val srtpSuites: List<String>,
        val pathMtu: Long,
        val datagramWithoutStreamBytes: Long,
        val pseudonymSalt: ByteArray?,
        val diagnosticTrace: Boolean?,
    )

    /** Elapsed milliseconds since this stack was created -- what every
     * `now_ms` parameter below expects. */
    fun nowMs(): Long = (System.nanoTime() - origin) / 1_000_000

    /** Whether this client picks the address peers reach it at -- it was
     * opened with no `bindHost` -- and whether it has picked it yet: the
     * route toward the first server an account names. Under [movingLock]. */
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
     * client that picks its own address: the route toward the server, on
     * this client's port. The first server named also becomes the address
     * the stack's `Via` carries. */
    private fun advertiseToward(peer: String): String {
        val address = formatAddress(routeHost(peer), bindAddress.substringAfterLast(':').toInt())
        val first = synchronized(movingLock) { (!routeChosen).also { routeChosen = true } }
        if (first && address != bindAddress) {
            val status = retryBusy {
                SipralSignalNative.stackTransportRebind(handle, address.toByteArray(Charsets.UTF_8), nowMs()).also {
                    if (it == SipralStatus.BUSY.value) throw SipralException(SipralStatus.BUSY, "")
                }
            }
            if (status != SipralStatus.OK.value) {
                throw SipralException(SipralStatus.of(status), Sipral.lastErrorMessage())
            }
            bindAddress = address
        }
        return address
    }

    /** Where a call's media socket is bound: [mediaHost] when one was given,
     * else the route toward where the media will come from -- [destination],
     * the account's server, or the address this client is reached at. */
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

    /** The poll thread's half: what the events asked, kept for right after
     * the poll. */
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

    /** Answer what `LOOKUP_WANTED` asked in the poll that just ran, each
     * lookup on a thread of its own -- a resolver may take seconds, and the
     * poll thread may not wait for it -- and act on what `LOCATED` found: an
     * account located at an address it has not been told of is pointed at
     * it and, on a client that picks its own address, reached at the route
     * toward it. */
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
                // the account was removed meanwhile: the next location says
                // it again, or nothing needs it
            }
        }
    }

    private fun resolve(resolver: SipralResolver, name: String, record: SipralDnsRecordType): SipralLookup =
        try {
            resolver(name, record)
        } catch (_: Exception) {
            // the resolver's failure is an answer: the procedure waits for
            // every one
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

    /** Turn the diagnostic trace on or off while the client runs
     * (`sipral_stack_diagnostic_trace`): whether the trace level writes every
     * SIP message whole, with its peer, from now on -- credentials and keys
     * taken out either way -- or pseudonymised, as by default. Nothing is
     * written unless the log is at `TRACE`. */
    fun setDiagnosticTrace(on: Boolean) {
        retryBusy { Sipral.stackDiagnosticTrace(handle, toggle(on)) }
    }

    /** The diagnostic record of every call the client keeps, as JSON
     * (`sipral_stack_diagnostics_json`): each decision the stack made and
     * why -- `transport.kept.datagram` among them for a request that went
     * over UDP past RFC 3261 §18.1.1's line because
     * `datagramWithoutStreamBytes` let it. */
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

    // -- media ports, the log and the state snapshot ---------------------------

    /**
     * A UDP socket for a call's media at [host]: at [port] when one is named,
     * otherwise -- on a client with an RTP range -- at an even port reserved
     * from it (`sipral_stack_rtp_port_reserve`), where one another process
     * already holds is given back and the next tried, and elsewhere wherever
     * the operating system puts it. `SipralStatus.EXHAUSTED` once every pair
     * is taken.
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

    /** `sipral_stack_rtp_port_release` for a port no call took, on a client
     * with a range. Best effort: a port a call did take comes back by itself
     * when the call ends. */
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
     * off with `SipralLogLevel.OFF` or a null handler (`sipral_stack_log`).
     * The handler runs on whichever thread has just finished a call into the
     * stack -- the poll thread, usually -- with the stack let go, so it may
     * call back into it. Every line is already redacted: no user part,
     * number, IP address or credential reaches it. Its arguments are the
     * level, which part of the stack wrote the line, the line, and how many
     * lines a flood had turned away before it.
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
     * Everything this client's stack is holding, as the redacted text
     * `sipral_stack_state_text` writes for a crash report: accounts, calls,
     * transports, media sessions, the last refused calls, the queues, the
     * RTP range and the counters. Safe from any thread, and never waits.
     */
    fun state(): String {
        val buffer = ByteArray(Sipral.STATE_TEXT_MAX.toInt())
        val length = Sipral.stackStateText(handle, buffer).toInt()
        return String(buffer, 0, maxOf(0, length - 1), Charsets.UTF_8)
    }

    /**
     * Send this client's log to `java.util.logging`, which every JVM and
     * Android carries with no library to add (on Android it reaches logcat).
     * Each line goes to the child logger of its target -- `sipral.call`,
     * `sipral.sip`, `sipral.api` and so on under the default `sipral`
     * logger (`docs/17-observability.md` lists the targets) -- so an
     * application filters by the part of the stack that wrote it. The
     * levels map as `ERROR` to `SEVERE`, `WARN` to `WARNING`, `INFO` to
     * `INFO`, `DEBUG` to `FINE` and `TRACE` to `FINEST`; a line that follows
     * a flood says how many lines were turned away before it. [level] left
     * null follows the logger's effective level as it is now, so lines the
     * logger would drop are never formatted. An application on SLF4J or
     * Timber hands [setLog] a lambda that calls it instead. Replaces
     * whatever [setLog] installed.
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
     * This client's health counters since it was opened
     * (`sipral_stack_counters`): registrations, how calls ended, what was
     * screened, and -- new in ABI 0.30 -- requests and responses sent again,
     * transactions timed out and requests refused at a limit. One struct
     * copy, cheap enough to sample on a timer; every field only grows except
     * `activeCalls`.
     */
    fun counters(): SipralCounters = retryBusy { Sipral.stackCounters(handle) }

    /**
     * Ask these STUN servers from now on, in order of preference, each
     * `host:port` -- what [open]'s `stunServer` and `stunFallbacks` would
     * have named -- without opening the client again
     * (`sipral_stack_stun_servers`). Every socket the stack keeps mapped is
     * asked again of the new list at once: `SIPRAL_EVENT_KIND_STUN_SERVER`
     * ([stunServerOf]) says the server in use moved and
     * `SIPRAL_EVENT_KIND_NAT_MAPPING` what the new one answers. On a client
     * opened without a STUN server the signalling socket starts being kept
     * mapped, and every media socket opened from then on is asked where it
     * appears from before its call is described. An empty list asks nobody
     * any more: accounts a STUN answer moved register their own address
     * again, and calls are described by their sockets' own addresses. A
     * client with a TURN server keeps asking STUN, so an empty list there
     * throws `SipralStatus.INVALID_ARGUMENT`, as does an entry that is not
     * an address and a port.
     */
    fun setStunServers(servers: List<String>) {
        retryBusy { Sipral.stackStunServers(handle, servers.joinToString(","), nowMs()) }
        stunServer = servers.firstOrNull()
    }

    /**
     * `sipral_stack_stir`: verify the callers of the calls this client's
     * accounts receive against [anchors] (PEM or DER certificates, the
     * STI-PA's roots in a SHAKEN deployment) from now on (RFC 8224),
     * replacing what an earlier call set. [unixSeconds] is the wall clock
     * now, which a PASSporT is signed and judged by, and defaults to this
     * machine's; a client whose accounts only sign calls this too, with no
     * anchors, before adding them. The certificate a call names is asked for
     * by `SIPRAL_EVENT_KIND_CALLER_VERIFICATION` ([verificationOf]) and
     * handed over with [stirCertificate]. [acceptServiceProviderCodes] lets
     * a certificate that names a service provider code rather than numbers
     * vouch for any caller, as a SHAKEN deployment's do; off, a certificate
     * covers only the numbers it names.
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
     * `sipral_call_stir_certificate`: the chain the URL a verification asked
     * for yielded -- PEM or DER, the signing certificate first -- or null for
     * one that could not be had. [call] is the handle the event named: the
     * call has not been announced yet. Its verdict follows as
     * `SIPRAL_EVENT_KIND_CALLER_VERIFICATION` at
     * `SIPRAL_VERIFICATION_STAGE_VERIFIED`.
     */
    fun stirCertificate(call: Long, chain: ByteArray?) {
        retryBusy { Sipral.callStirCertificate(handle, call, chain ?: ByteArray(0), nowMs()) }
    }

    // -- accounts and calls ------------------------------------------------

    /**
     * `sipral_account_add`. See [SipralAccount].
     *
     * [sessionTimer] is how the account's calls ask for a session timer (RFC
     * 4028): thirty minutes by default. [privacy] places every call
     * anonymously (RFC 3323): `setOf(SipralPrivacy.ID)` is "withhold my
     * number" -- `From` becomes `"Anonymous"
     * <sip:anonymous@anonymous.invalid>`, `Privacy` carries the values, and
     * the account's own identity goes in `P-Asserted-Identity` only toward a
     * trusted peer. [trustedPeers] are the IP addresses of the peers this
     * account trusts -- usually the registrar or the trunk -- RFC 3325's
     * trust domain: a call from one of them has its asserted identity read
     * ([callerIdentity]), from anywhere else it is left out, and once any
     * are named no identity field leaves toward any other peer. [security]
     * is the account's own SRTP policy and suites, and its STIR/SHAKEN
     * verification and signing ([SipralAccountSecurity]).
     *
     * [serverUri] names the server by a URI whose host RFC 3263 locates --
     * `sip:pbx.example.com`, `sips:example.com:5061` -- in place of
     * [registrarAddress]: exactly one of the two is given. The lookups are
     * the client's `resolver`'s; `SIPRAL_EVENT_KIND_LOCATED` ([locateOf])
     * says where the server was found and `LOCATE_FAILED` why not. A
     * REGISTER waits for the first answer, and a call placed before it with
     * no `destination` throws with `WRONG_STATE`. [serverNaptr] asks the
     * domain for NAPTR records before SRV (RFC 3263 §4.1). [keepaliveMs]
     * keeps the account's flow to its server open at that interval whatever
     * STUN found -- a double CRLF on UDP, a ping on a stream -- 1 000 to
     * 120 000, `0` for never. [tlsPin] is the SHA-256 fingerprint of the one
     * TLS certificate the account trusts, for an application that runs the
     * account's TLS itself: [SipralAccount.checkCertificate] is its verdict.
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
    ): SipralAccount {
        require((registrarAddress == null) != (serverUri == null)) {
            "an account names its server by registrarAddress or by serverUri, one of the two"
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
            location = SipralAccount.Location(serverUri, serverNaptr, keepaliveMs, tlsPin, advertised),
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

    internal fun defaultContact(aor: String, at: String = bindAddress): String {
        val scheme = aor.substringBefore(':', "sip")
        val rest = aor.substringAfter(':', aor)
        val user = rest.substringBefore('@', "")
        val parameters = link?.contactParameters ?: ""
        return if (user.isEmpty()) "$scheme:$at$parameters" else "$scheme:$user@$at$parameters"
    }

    /** The connection to the server was made from [local]: the address the
     * stack now signals from. */
    internal fun linkBound(local: String) {
        bindAddress = local
    }

    /** Every account added without a `Contact` of its own moves to the new
     * connection's address, and every one that was registering registers
     * again now rather than at its next back-off. */
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
     * `sipral_call_place`, with this stack running the call's own audio: a
     * media socket is opened here, before the INVITE goes out, and its
     * `host:port` is what `media_address` in `sipral_call_config_t` offers.
     *
     * With a [stunServer], the socket is first asked where it appears from,
     * and this returns once the server has answered -- or has not, five and
     * a half seconds on; with a TURN server, once the relay is allocated or
     * refused as well. So call it off the main thread. [ice] overrides the
     * client's own ICE policy for this call. [headers] go on the INVITE as
     * written -- an `Alert-Info` asking for a distinctive ring, an
     * `Answer-Mode` asking an intercom to pick up.
     *
     * [codecs] offers this call's audio in that order instead of the
     * client's (`sipral_codec_info_t` names, comma-separated): `L16/16000` or
     * `L16/8000` is how linear audio is offered at all. [text] binds a second
     * socket at [mediaHost] and offers real-time text on it (RFC 4103):
     * [SipralMedia.sendText] and [SipralCall.text] carry it once the far end
     * agrees; it is not offered on a call keyed by SRTP or gathering ICE,
     * which the text stream would leave in the clear. [feedback] offers
     * RTP/AVPF with Generic NACKs and reduced-size RTCP (RFC 4585, RFC 5506),
     * which a far end knowing only RTP/AVP refuses; [focus] says this end is
     * a conference's focus (`isfocus`, RFC 4579).
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
     * [text] binds a second socket at [mediaHost] and takes the real-time
     * text the offer carries on it. [codecs] answers in that order of this
     * build's codecs instead of the client's -- `L16/16000` for linear
     * audio -- and [focus] says this end is the focus of a conference
     * (`isfocus`, RFC 4579). An offer that asked for RTCP feedback is
     * answered on RTP/AVPF whatever this says (RFC 4585 §4.1 leaves an
     * answerer no other way to take the stream); [feedback] adds what this
     * end does with it, Generic NACKs and reduced-size RTCP.
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
     * [answerCall] by call handle, for a caller that has the handle and not
     * the event -- [SipralAnnounced.Arrived] hands back only the handle, and
     * the `SIPRAL_EVENT_KIND_INCOMING_CALL` behind it may already have been
     * read by somebody else. [SipralCall.identity] then has the lists but
     * not the facts the event carried: whether the peer was trusted, and
     * what it asserted.
     */
    fun answerCall(callHandle: Long, mediaHost: String? = null, mediaPort: Int = 0): SipralCall =
        answerCall(callHandle, mediaHostFor(mediaHost, null, null), mediaPort, null, Answered())

    /** How [answerCall] answers: what `sipral_call_answer_with` takes beyond
     * the media socket, none of it asked for by default. */
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

    /** `sipral_call_reject`, for a call nothing has answered: no media
     * socket was ever needed. */
    fun rejectCall(event: SipralEvent, code: Long = 486) {
        rejectCall(event.call, code)
    }

    /** [rejectCall] by call handle. */
    fun rejectCall(callHandle: Long, code: Long = 486) {
        retryBusy { Sipral.callReject(handle, callHandle, code, nowMs()) }
    }

    /**
     * Answer the `SIPRAL_EVENT_KIND_INCOMING_CALL` [event] names with a 3xx
     * instead of taking it (`sipral_call_redirect`, RFC 3261 §21.3): 302 is
     * call forwarding, [targets] are where to try in order of preference,
     * and [reason] -- `no-answer`, `user-busy`, `unconditional`,
     * `deflection`, `do-not-disturb` or any other token -- adds a
     * `Diversion` (RFC 5806) naming the address that was called.
     */
    fun redirectCall(event: SipralEvent, targets: List<String>, status: Int = 302, reason: String? = null) {
        redirect(event.call, targets, status, reason)
    }

    internal fun redirect(callHandle: Long, targets: List<String>, status: Int, reason: String?) {
        retryBusy {
            Sipral.callRedirect(handle, callHandle, status.toLong(), targets.joinToString(","), reason ?: "", nowMs())
        }
    }

    /** Who is calling, beyond the `From`, for the incoming call [event]
     * names -- read before deciding whether to answer. */
    fun callerIdentity(event: SipralEvent): SipralCallerIdentity =
        IdentityReader.identity(this, event.call, event.payload.call)

    /** How the incoming call [event] names asked to be answered and rung. */
    fun answering(event: SipralEvent): SipralAnswering =
        IdentityReader.answering(this, event.call, event.payload.call)

    /**
     * Take a REFER outside any dialog and place the call it asks for:
     * `sipral_call_accept_transfer` on the referral's handle. `event` is the
     * `SIPRAL_EVENT_KIND_REFERRAL` read off [events], whose [referralOf]
     * has a zero `statusCode`.
     *
     * The stack answers 202, reports on the call to whoever asked, and
     * places it from the account the event names, to the REFER's own target
     * -- never the caller's. A media socket is opened for it here, the way
     * [placeCall] opens one, and the [SipralCall] returned is that placed
     * call. Whoever sent the REFER can make this line dial anything, so this
     * is never done on the application's behalf. With a [stunServer] it
     * waits for the mapping as [placeCall] does, so call it off the main
     * thread.
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

    /** `sipral_announcement_forget`: the user dismissed a screen a push
     * raised before its INVITE came. `SIPRAL_STATUS_WRONG_STATE` when it
     * was already fulfilled or had already expired -- the event saying so
     * and this call can cross. */
    fun forgetAnnouncement(announcement: Long) {
        retryBusy { Sipral.announcementForget(handle, announcement) }
    }

    internal fun callFor(callHandle: Long): SipralCall? = calls[callHandle]

    /** A call this client runs the media of, and -- with a TURN server
     * reached over TCP or TLS -- the socket whose connection its last
     * farewell goes on, kept past the call itself until that connection
     * closes. */
    private fun track(call: SipralCall, callHandle: Long, mediaAddress: String) {
        calls[callHandle] = call
        if (turn != null && overStream(turn.transport.value.toLong())) {
            turnSockets[callHandle] = mediaAddress
        }
    }

    internal fun forgetCall(callHandle: Long) {
        calls.remove(callHandle)
    }

    // -- connections to recording servers -------------------------------------

    /** The TCP connections to recording servers, by the transport id each
     * was bound under. */
    private val recordingLinks = ConcurrentHashMap<Long, Socket>()

    /** The next transport id a connection this layer opens is bound under:
     * the number is the caller's to choose, and one count for every kind of
     * connection keeps two of them from ever sharing one, however many
     * recordings a long-running client makes. */
    internal val nextLink = java.util.concurrent.atomic.AtomicLong(FIRST_LINK)

    /** The recording sessions running, by handle: the call each records and
     * the connection it went over. */
    private val recordings = ConcurrentHashMap<Long, Pair<SipralCall, Long?>>()

    /**
     * Connect over TCP to a recording server at [destination] (`host:port`)
     * and bind the connection as a transport of its own, for
     * [SipralCall.recordTo]: its INVITE is larger than RFC 3261 §18.1.1 lets
     * over UDP. `TRANSPORT_DOWN` when the server refused the connection.
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

    /** A recording session ended: its call stops copying, and its
     * connection closes a second later, once what this end still owes the
     * server -- the answer to its BYE -- has left on it. */
    private fun recordingEnded(recording: Long) {
        val (call, link) = recordings.remove(recording) ?: return
        call.recordingEnded()
        if (link != null) {
            Thread({
                try {
                    Thread.sleep(1_000)
                } catch (_: InterruptedException) {
                    // closing now, then
                }
                closeRecordingLink(link)
            }, "sipral-recording-close").apply {
                isDaemon = true
                start()
            }
        }
    }

    // -- RFC 3261 §18.1.1: a request too large for a datagram -----------------

    /** Whether a request too large for a datagram gets a connection
     * ([open]'s `streamFallback`). */
    private var streamFallback = true

    /** Where such a connection goes, when not to the address asked for
     * ([open]'s `streamServer`). */
    private var streamServer: String? = null

    /** The TCP connections opened for requests too large for a datagram, by
     * the transport id each was bound under ([nextLink]), with where each
     * goes; the destinations one is being opened to; and where
     * `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` asked for one during the poll that
     * raised it, acted on right after that poll. */
    private val streamLinks = ConcurrentHashMap<Long, Pair<String, Socket>>()
    private val streamsOpening: MutableSet<String> = ConcurrentHashMap.newKeySet()
    private val streamsAsked = java.util.concurrent.ConcurrentLinkedQueue<String>()

    /** The transport ids `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` named during
     * that same poll, acted on at the same moment. */
    private val streamsLetGo = java.util.concurrent.ConcurrentLinkedQueue<Long>()

    /** Whether that same poll named the main transport of a client that
     * signals over TCP or TLS: the stack retires a connection that stopped
     * answering keep-alives (RFC 5626 §4.4.1) with its socket still open
     * here, and sends nothing on it again until a new one is bound. Read and
     * written on the poll thread only. */
    private var mainLetGo = false

    /** Remember a transport the stack let go of, for after the poll that
     * said so: a connection opened here that stopped answering keep-alives
     * (RFC 5626 §4.4.1) is retired by the stack while its socket is still
     * open here, and a connection kept open that the stack will never write
     * to again would stand in for the new one it asks for. */
    internal fun noteStreamLetGo(id: Long) {
        streamsLetGo.add(id)
    }

    /** Answer what `SIPRAL_EVENT_KIND_TRANSPORT_WANTED` asked for in the poll
     * that just ran: a connection to each destination not already connected
     * or being connected to, opened on a thread of its own, or -- with
     * `streamFallback` off -- the word that none is coming. First the
     * connections the stack let go of in that poll. */
    private fun actOnStreamsWanted() {
        while (true) {
            val letGo = streamsLetGo.poll() ?: break
            loseStreamLink(letGo, tell = false)
        }
        val seen = HashSet<String>()
        while (true) {
            val destination = streamsAsked.poll() ?: return
            if (!seen.add(destination) || streamLinks.values.any { it.first == destination }) {
                continue
            }
            if (!streamFallback) {
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
            Thread({ openStreamLink(id, destination) }, "sipral-stream-$id").apply {
                isDaemon = true
                start()
            }
        }
    }

    /** Connect over TCP to [destination] -- or to `streamServer` when one
     * was given -- and bind the connection under [id] as the stream to
     * [destination], then read it until it closes; a connection that cannot
     * be made is told to the stack under that same id, which ends what was
     * waiting for it. */
    private fun openStreamLink(id: Long, destination: String) {
        val socket = Socket()
        try {
            socket.bind(InetSocketAddress(InetAddress.getByName(currentHost), 0))
            socket.connect(parseHostPort(streamServer ?: destination), SignallingLink.PATIENCE_MS)
            socket.tcpNoDelay = true
        } catch (refused: Exception) {
            socket.close()
            streamsOpening.remove(destination)
            val said = classify(refused, handshaking = false)
            val server = streamServer ?: destination
            val target = if (server == destination) destination else "$server (for $destination)"
            val why = if (said.detail.isEmpty()) "" else ": ${said.detail}"
            sayNoStream(id, said.error, "to $target ${verdict(said.error)}$why")
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
                Sipral.stackTransportBind(handle, id, SipralTransport.TCP.value.toLong(), local, destination, nowMs())
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

    /** `sipral_stack_transport_failed_with` for a connection that was not made;
     * never throwing on the way out. [what] finishes a sentence that begins
     * "TCP" -- where the connection was going and what became of it --
     * carried to the event's detail. */
    private fun sayNoStream(id: Long, error: SipralTransportError, what: String) {
        try {
            retryBusy {
                Sipral.stackTransportFailedWith(
                    handle,
                    SipralTransportFailure(
                        transport = id,
                        error = error.value.toLong(),
                        tls = 0L,
                        detail = sentence("TCP $what"),
                    ),
                    nowMs(),
                )
            }
        } catch (_: SipralException) {
            // nothing was waiting any more, or the stack is going away
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

    /** What the connection carried, to `sipral_stack_receive_stream`, every
     * byte in order; the far end closing it is `sipral_stack_stream_closed`. */
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

    // -- media sockets behind a NAT ------------------------------------------

    // Media sockets `sipral_stack_nat_map` named whose call has no media
    // handle yet, by `host:port`: the poll thread reads them and hands what
    // arrives to `sipral_stack_receive_stun`, and sends what
    // `sipral_stack_poll_stun` names each of them as the source of. Every
    // read, send and close of one happens under `natLock`, so the poll
    // thread never touches a socket that was just given back; no ABI call
    // is made under it.
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
     * `sipral_stack_nat_map` for a media socket about to carry a call, and
     * the wait until the stack can describe the call by what the servers
     * said: placing or answering before that is `SIPRAL_STATUS_WRONG_STATE`.
     * The STUN answer comes within five and a half seconds whatever the
     * server does; a TURN Allocate nobody answers is given up on after
     * thirty-nine and a half. Nothing at all without a STUN server.
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

    /** The call on `local` has its media handle: its socket's datagrams go
     * to `sipral_media_receive` from now on, read by [SipralMedia]'s own
     * thread. Called on the poll thread, in the poll that raised
     * `SIPRAL_EVENT_KIND_MEDIA_STARTED`. */
    internal fun mediaSocketTaken(local: String) {
        synchronized(natLock) { stunSockets.remove(local) }
    }

    /**
     * A media socket that will carry no call after all, or whose call ended
     * before it had media: `sipral_stack_nat_unmap`, so the stack stops
     * refreshing its mapping and gives its relay back, the Refresh that
     * does that sent from the socket itself, and then the socket closed.
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
     * `sipral_stack_poll_stun`: every request a media socket owes, sent from
     * the socket the stack names -- the address the server sees it come from
     * is the whole point -- to wherever the stack says. Its buffers are its
     * own, since the poll thread and a thread giving a socket back can both
     * be here.
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
                // for the TURN server, on the socket's connection to it:
                // never a datagram, which a network that blocks UDP drops
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

    /** Everything waiting on the media sockets not yet handed to a call's
     * media, read under `natLock` and handed to `sipral_stack_receive_stun`
     * outside it. */
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
                // a datagram from a stranger, or early media before the
                // session opens: refused, and it costs that one datagram
            }
        }
    }

    // -- a TURN server reached over TCP or TLS --------------------------------

    // Every media socket's open connection to the TURN server, by the
    // socket's `host:port`; what `SIPRAL_EVENT_KIND_TURN_STREAM` asked for
    // during the poll that raised it -- nothing may call back into the stack
    // from its own callback -- acted on right after that poll; and every
    // call's socket, by the call, for its last farewell.
    private val turnStreams = ConcurrentHashMap<String, TurnStream>()
    private val turnAsked = java.util.concurrent.ConcurrentLinkedQueue<org.sipral.SipralTurnStreamEvent>()
    private val turnSockets = ConcurrentHashMap<Long, String>()

    /** Write [payload] on media socket [local]'s connection to the TURN
     * server, whole: what `sipral_stack_poll_stun`,
     * `sipral_stack_poll_farewell` and a call's media hand out marked TCP or
     * TLS. Thread-safe; a connection that fails here is closed and the stack
     * told, which loses the relay on it. */
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

    /** Open or close what `SIPRAL_EVENT_KIND_TURN_STREAM` asked for in the
     * poll that just ran, after this round's queues were written. */
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

    /** Connect to the TURN server for media socket [local] -- over TLS, with
     * the certificate checked against [SipralTurnServer.serverName], when
     * [protocol] says so -- say how that went, and read it until it closes. */
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

    /** What a connection carried, to `sipral_stack_turn_receive`: every
     * byte, in order, since a stream that loses one never finds its place
     * again, so a busy stack is waited for rather than skipped. False for a
     * connection the stack found broken. */
    private fun turnReceived(local: String, bytes: ByteArray): Boolean {
        while (!closed.get()) {
            try {
                Sipral.stackTurnReceive(handle, local, bytes, nowMs())
                return true
            } catch (refused: SipralException) {
                when (refused.status) {
                    SipralStatus.BUSY -> Thread.sleep(1)
                    SipralStatus.STREAM_BROKEN -> return false
                    else -> return true
                }
            }
        }
        return true
    }

    /** Close media socket [local]'s connection, and when [tell], say so with
     * `sipral_stack_turn_closed` -- not for one the stack itself asked to
     * close or found broken. */
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

    // -- the network changing under the client ------------------------------

    /**
     * The platform said the network changed: `sipral_stack_network_changed`,
     * and what its answer asks of the client's own sockets.
     *
     * When the address or the interface changed -- `SipralRecovery.REBUILD`
     * -- the signalling socket is bound again at [next]'s address and handed
     * to the stack as its transport, and every account is pointed at it
     * (`sipral_account_rebind`), so the REGISTER that follows names where
     * this end is now. Every call up at the time then raises
     * `SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED`: the far end is still sending
     * its audio to the old address, and [SipralCall.moveMedia] offers it the
     * new one. Anything less -- a roam that keeps the address -- only
     * re-registers or re-proves. Safe to call as often as the platform
     * notifies; `NOTHING` is most of the answers.
     */
    fun networkChanged(next: SipralNetwork): SipralRecovery = synchronized(movingLock) {
        val previous = network
        val moves = next.link != SipralLink.DOWN &&
            (next.address != previous.address || next.interfaceName != previous.interfaceName)
        var rebound: String? = null
        val link = link
        if (moves && link != null) {
            rebound = link.move(next.address ?: bindAddress.substringBeforeLast(':'))
        } else if (moves) {
            val host = next.address ?: bindAddress.substringBeforeLast(':')
            val fresh = DatagramSocket(0, InetAddress.getByName(host))
            // the application names the address from here on
            routes = false
            fresh.soTimeout = 20
            val local = formatAddress(fresh.localAddress.hostAddress, fresh.localPort)
            val status = retryBusy {
                SipralSignalNative.stackTransportRebind(handle, local.toByteArray(Charsets.UTF_8), nowMs()).also {
                    if (it == SipralStatus.BUSY.value) throw SipralException(SipralStatus.BUSY, "")
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
                account.rebind(rebound, previous.address)
            }
        }
        SipralRecovery.of(raw.toInt()) ?: SipralRecovery.UNKNOWN
    }

    /** The address the client's sockets are bound on now. */
    internal val currentHost: String
        get() = synchronized(movingLock) { network.address } ?: bindAddress.substringBeforeLast(':')

    /** Runs [body] with no network change half done: what
     * [SipralCall.moveMedia] holds while it binds and offers. */
    internal fun <T> moving(body: () -> T): T = synchronized(movingLock) { body() }

    /** `mapMediaSocket` for the socket [SipralCall.moveMedia] binds: where the
     * STUN server sees it from, or null on a client without one. */
    internal fun mapMovedSocket(mediaSocket: DatagramSocket, local: String): String? =
        mapMediaSocket(mediaSocket, local)

    /** The call's old socket is gone: `sipral_stack_nat_unmap`, so the stack
     * stops refreshing a mapping nothing uses. */
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

    // -- the library's own audio engine ---------------------------------------

    /** A packet the engine encoded from the microphone: sent from its call's
     * media socket, or on its connection to a TURN server. On the engine's
     * thread, which must not call the audio engine back. */
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

    // -- the poll thread -----------------------------------------------------

    private fun onEvent(event: SipralEvent) {
        // Side effects first, delivery second: a coroutine woken by
        // `events` reading `callFor(event.call)`'s own state must find it
        // already current, the same ordering `sipral.call.Call.deliver`
        // (the Python binding) keeps for the same reason.
        turnStreamOf(event)?.let { turnAsked.add(it) }
        if (link == null) {
            transportWantedOf(event)?.destination?.let { streamsAsked.add(it) }
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
                // one connection carries everything, whatever it names: the
                // server it reaches is the outbound proxy
                link.write(data, len)
                continue
            }
            val destinationLen = lens[1].toInt()
            val to = parseHostPort(String(destination, 0, destinationLen, Charsets.UTF_8))
            try {
                socket?.send(DatagramPacket(data, len, to))
            } catch (_: Exception) {
                // best effort: the poll thread never raises out of its own loop
            }
        }
    }

    /**
     * What a call that just ended still owes -- its RTCP BYE, and with a
     * TURN server the Refresh that gives its relay back -- sent through
     * that call's own media socket to the address the stack names. Under
     * ICE that is the path ICE chose or the TURN server, not necessarily the
     * last address media came from, which is only the fallback for a packet
     * that names none.
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
                // given back on the relay's connection, which is the
                // client's and not the call's, and outlives it
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
                // the socket of this pass: [networkChanged] closes the one
                // it replaces, which ends a receive waiting on it
                val listening = socket
                if (listening == null) {
                    // over TCP or TLS the connection has a reader of its
                    // own; this loop only keeps the poll's cadence
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
                // ordinary: this is what lets the loop poll on a cadence
                // rather than blocking on the socket forever
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
     * Hang up every call still open, let their goodbyes drain, then
     * `sipral_media_release`, `sipral_stack_destroy` and close the socket.
     *
     * Idempotent. Hanging up happens before any call's own [SipralCall.close]
     * -- which releases its media handle -- for the reason
     * `bindings/python/sipral/stack.py`'s own `close()` gives: the poll
     * thread is what actually drains the BYE and the RTCP goodbye it
     * queues, and it can only do that while the call is still tracked and
     * its media socket still open.
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
        // A socket mapped for a call that was never placed still holds a
        // relay the server would keep for up to ten minutes after the stack
        // is gone, since `sipral_stack_destroy` sends nothing.
        val unspent = synchronized(natLock) { stunSockets.toList() }
        for ((local, mediaSocket) in unspent) {
            giveBackMediaSocket(mediaSocket, local)
        }
        if (Thread.currentThread() !== thread) {
            thread.join(5000)
        }
        // and every connection to the TURN server still open: what it
        // carried was given back through it above, or lapses with it
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
