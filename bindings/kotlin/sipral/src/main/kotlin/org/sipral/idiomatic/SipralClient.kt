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
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import org.sipral.Sipral
import org.sipral.SipralAudioTransmit
import org.sipral.SipralAudioTransmitListener
import org.sipral.SipralCallConfig
import org.sipral.SipralCallEvent
import org.sipral.SipralEvent
import org.sipral.SipralEventListener
import org.sipral.SipralException
import org.sipral.SipralHeader
import org.sipral.SipralIce
import org.sipral.SipralLink
import org.sipral.SipralNat
import org.sipral.SipralRecovery
import org.sipral.SipralSrtp
import org.sipral.SipralStackConfig
import org.sipral.SipralStatus
import org.sipral.SipralToggle
import org.sipral.SipralTransport

private const val TRANSMIT_BYTES = 1 shl 16
private const val ADDRESS_BYTES = 64
private const val PACKET_BYTES = 1500

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
    socket: DatagramSocket,
    bindAddress: String,
    /** The STUN server this client asks where its sockets appear from, as
     * `host:port`, or null for a client that asks nobody. */
    val stunServer: String?,
    private val turnServer: String?,
    private val turn: SipralTurnServer?,
    /** Who runs this client's audio, as it was opened. */
    val audioMode: SipralAudioMode,
    network: SipralNetwork,
) : AutoCloseable {
    internal var handle: Long = 0L
        private set

    /** The signalling socket: read and written by the poll thread, and put
     * in another's place by [networkChanged]. */
    @Volatile
    private var socket: DatagramSocket = socket

    /** The signalling socket's address, `host:port`: where it was bound, and
     * after [networkChanged] where it is bound now. */
    @Volatile
    var bindAddress: String = bindAddress
        private set

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
         */
        fun open(
            bindHost: String = "127.0.0.1",
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
        ): SipralClient {
            val socket = DatagramSocket(bindPort, InetAddress.getByName(bindHost))
            socket.soTimeout = 20
            val bindAddress = formatAddress(socket.localAddress.hostAddress, socket.localPort)
            val client = SipralClient(
                socket, bindAddress, stunServer, turn?.address, turn, audio,
                network ?: SipralNetwork(SipralLink.WIRED, address = bindHost),
            )
            try {
                client.start(
                    userAgent, codecs, ice, turn, g729AnnexB, referrals,
                    registrarKeepalive, registrarKeepaliveMs, audioProbeMs, audioDeviceRateHz, srtp,
                    maxDialogs, maxServerTransactions, diagnosticDecisions, diagnosticRecords,
                    stunFallbacks,
                )
            } catch (refused: Exception) {
                socket.close()
                throw refused
            }
            return client
        }

        private fun toggle(value: Boolean?): Long = when (value) {
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
    ) {
        val random = SecureRandom()
        val entropy = ByteArray(32).also { random.nextBytes(it) }
        val mediaSeed = ByteArray(32).also { random.nextBytes(it) }
        val listener = SipralEventListener { event -> onEvent(event) }
        val (audioRaw, activationRaw) = audioMode.raw
        val device = audioMode is SipralAudioMode.Device
        val config = SipralStackConfig(
            eventListener = listener,
            transport = SipralTransport.UDP.value.toLong(),
            bindAddress = bindAddress,
            userAgent = userAgent,
            entropy = entropy,
            codecs = codecs,
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
        )
        handle = Sipral.stackCreate(config)
        if (device) {
            audio = SipralAudioDevices(this)
        }
        thread = Thread(::run, "sipral-client-$bindAddress").apply {
            isDaemon = true
            start()
        }
    }

    /** Elapsed milliseconds since this stack was created -- what every
     * `now_ms` parameter below expects. */
    fun nowMs(): Long = (System.nanoTime() - origin) / 1_000_000

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
     * are named no identity field leaves toward any other peer.
     */
    fun addAccount(
        aor: String,
        registrarAddress: String,
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
    ): SipralAccount {
        val account = SipralAccount.add(
            this,
            aor,
            registrarAddress = registrarAddress,
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
        return if (user.isEmpty()) "$scheme:$at" else "$scheme:$user@$at"
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
     */
    fun placeCall(
        account: SipralAccount,
        target: String,
        mediaHost: String = "127.0.0.1",
        mediaPort: Int = 0,
        destination: String? = null,
        srtp: Long = 0,
        ice: SipralIce? = null,
        headers: List<SipralHeader> = emptyList(),
    ): SipralCall {
        val mediaSocket = DatagramSocket(mediaPort, InetAddress.getByName(mediaHost))
        val mediaAddress = formatAddress(mediaSocket.localAddress.hostAddress, mediaSocket.localPort)
        val config = SipralCallConfig(
            target = target,
            mediaAddress = mediaAddress,
            destination = destination,
            srtp = srtp,
            ice = (ice?.value ?: 0).toLong(),
            headers = headers.ifEmpty { null },
        )
        val callHandle = try {
            mapMediaSocket(mediaSocket, mediaAddress)
            retryBusy { Sipral.callPlace(handle, account.handle, config, nowMs()) }
        } catch (refused: Exception) {
            giveBackMediaSocket(mediaSocket, mediaAddress)
            throw refused
        }
        val call = SipralCall(this, callHandle, mediaSocket, mediaAddress)
        track(call, callHandle, mediaAddress)
        return call
    }

    /**
     * Open a media socket for an incoming call and answer it there.
     * `event` is the `SIPRAL_EVENT_KIND_INCOMING_CALL` read off [events].
     */
    fun answerCall(event: SipralEvent, mediaHost: String = "127.0.0.1", mediaPort: Int = 0): SipralCall =
        answerCall(event.call, mediaHost, mediaPort, event.payload.call)

    /**
     * [answerCall] by call handle, for a caller that has the handle and not
     * the event -- [SipralAnnounced.Arrived] hands back only the handle, and
     * the `SIPRAL_EVENT_KIND_INCOMING_CALL` behind it may already have been
     * read by somebody else. [SipralCall.identity] then has the lists but
     * not the facts the event carried: whether the peer was trusted, and
     * what it asserted.
     */
    fun answerCall(callHandle: Long, mediaHost: String = "127.0.0.1", mediaPort: Int = 0): SipralCall =
        answerCall(callHandle, mediaHost, mediaPort, null)

    private fun answerCall(callHandle: Long, mediaHost: String, mediaPort: Int, incoming: SipralCallEvent?): SipralCall {
        val mediaSocket = DatagramSocket(mediaPort, InetAddress.getByName(mediaHost))
        val mediaAddress = formatAddress(mediaSocket.localAddress.hostAddress, mediaSocket.localPort)
        val call = SipralCall(this, callHandle, mediaSocket, mediaAddress, incoming)
        track(call, callHandle, mediaAddress)
        try {
            mapMediaSocket(mediaSocket, mediaAddress)
            call.answer(mediaAddress)
        } catch (refused: Exception) {
            calls.remove(callHandle)
            giveBackMediaSocket(mediaSocket, mediaAddress)
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
        mediaHost: String = "127.0.0.1",
        mediaPort: Int = 0,
        srtp: Long = 0,
        ice: SipralIce? = null,
    ): SipralCall {
        val mediaSocket = DatagramSocket(mediaPort, InetAddress.getByName(mediaHost))
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
        if (moves) {
            val host = next.address ?: bindAddress.substringBeforeLast(':')
            val fresh = DatagramSocket(0, InetAddress.getByName(host))
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
            old.close()
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
        noteNat(event)
        calls[event.call]?.deliver(event)
        eventsFlow.tryEmit(event)
    }

    private fun drainTransmit() {
        val data = ByteArray(TRANSMIT_BYTES)
        val destination = ByteArray(ADDRESS_BYTES)
        val lens = LongArray(3)
        while (true) {
            val status = SipralSignalNative.stackPollTransmit(handle, data, destination, lens)
            val len = lens[0].toInt()
            if (status != SipralStatus.OK.value || len == 0) {
                return
            }
            val destinationLen = lens[1].toInt()
            val to = parseHostPort(String(destination, 0, destinationLen, Charsets.UTF_8))
            try {
                socket.send(DatagramPacket(data, len, to))
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
        Sipral.stackDestroy(handle)
        socket.close()
    }
}
