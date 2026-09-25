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

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import org.sipral.Sipral
import org.sipral.SipralCallConfig
import org.sipral.SipralEvent
import org.sipral.SipralEventListener
import org.sipral.SipralException
import org.sipral.SipralIce
import org.sipral.SipralNat
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
    private val socket: DatagramSocket,
    val bindAddress: String,
    /** The STUN server this client asks where its sockets appear from, as
     * `host:port`, or null for a client that asks nobody. */
    val stunServer: String?,
    private val turnServer: String?,
) : AutoCloseable {
    internal var handle: Long = 0L
        private set

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
         * a call only uses the relay under ICE. [g729AnnexB] allows G.729's
         * silence compression, on by default.
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
        ): SipralClient {
            val socket = DatagramSocket(bindPort, InetAddress.getByName(bindHost))
            socket.soTimeout = 20
            val bindAddress = formatAddress(socket.localAddress.hostAddress, socket.localPort)
            val client = SipralClient(socket, bindAddress, stunServer, turn?.address)
            try {
                client.start(userAgent, codecs, ice, turn, g729AnnexB)
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

    private fun start(userAgent: String?, codecs: String?, ice: SipralIce?, turn: SipralTurnServer?, g729AnnexB: Boolean?) {
        val random = SecureRandom()
        val entropy = ByteArray(32).also { random.nextBytes(it) }
        val mediaSeed = ByteArray(32).also { random.nextBytes(it) }
        val listener = SipralEventListener { event -> onEvent(event) }
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
        )
        handle = Sipral.stackCreate(config)
        thread = Thread(::run, "sipral-client-$bindAddress").apply {
            isDaemon = true
            start()
        }
    }

    /** Elapsed milliseconds since this stack was created -- what every
     * `now_ms` parameter below expects. */
    fun nowMs(): Long = (System.nanoTime() - origin) / 1_000_000

    // -- accounts and calls ------------------------------------------------

    /** `sipral_account_add`. See [SipralAccount]. */
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
    ): SipralAccount = SipralAccount.add(
        this,
        aor,
        registrarAddress = registrarAddress,
        registrar = registrar,
        contact = contact ?: defaultContact(aor),
        displayName = displayName,
        authUser = authUser,
        authPassword = authPassword,
        expiresSeconds = expiresSeconds,
        push = push,
    )

    private fun defaultContact(aor: String): String {
        val scheme = aor.substringBefore(':', "sip")
        val rest = aor.substringAfter(':', aor)
        val user = rest.substringBefore('@', "")
        return if (user.isEmpty()) "$scheme:$bindAddress" else "$scheme:$user@$bindAddress"
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
     * client's own ICE policy for this call.
     */
    fun placeCall(
        account: SipralAccount,
        target: String,
        mediaHost: String = "127.0.0.1",
        mediaPort: Int = 0,
        destination: String? = null,
        srtp: Long = 0,
        ice: SipralIce? = null,
    ): SipralCall {
        val mediaSocket = DatagramSocket(mediaPort, InetAddress.getByName(mediaHost))
        val mediaAddress = formatAddress(mediaSocket.localAddress.hostAddress, mediaSocket.localPort)
        val config = SipralCallConfig(
            target = target,
            mediaAddress = mediaAddress,
            destination = destination,
            srtp = srtp,
            ice = (ice?.value ?: 0).toLong(),
        )
        val callHandle = try {
            mapMediaSocket(mediaSocket, mediaAddress)
            retryBusy { Sipral.callPlace(handle, account.handle, config, nowMs()) }
        } catch (refused: Exception) {
            giveBackMediaSocket(mediaSocket, mediaAddress)
            throw refused
        }
        val call = SipralCall(this, callHandle, mediaSocket, mediaAddress)
        calls[callHandle] = call
        return call
    }

    /**
     * Open a media socket for an incoming call and answer it there.
     * `event` is the `SIPRAL_EVENT_KIND_INCOMING_CALL` read off [events].
     */
    fun answerCall(event: SipralEvent, mediaHost: String = "127.0.0.1", mediaPort: Int = 0): SipralCall =
        answerCall(event.call, mediaHost, mediaPort)

    /**
     * [answerCall] by call handle, for a caller that has the handle and not
     * the event -- [SipralAnnounced.Arrived] hands back only the handle, and
     * the `SIPRAL_EVENT_KIND_INCOMING_CALL` behind it may already have been
     * read by somebody else.
     */
    fun answerCall(callHandle: Long, mediaHost: String = "127.0.0.1", mediaPort: Int = 0): SipralCall {
        val mediaSocket = DatagramSocket(mediaPort, InetAddress.getByName(mediaHost))
        val mediaAddress = formatAddress(mediaSocket.localAddress.hostAddress, mediaSocket.localPort)
        val call = SipralCall(this, callHandle, mediaSocket, mediaAddress)
        calls[callHandle] = call
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

    /** `sipral_announcement_forget`: the user dismissed a screen a push
     * raised before its INVITE came. `SIPRAL_STATUS_WRONG_STATE` when it
     * was already fulfilled or had already expired -- the event saying so
     * and this call can cross. */
    fun forgetAnnouncement(announcement: Long) {
        retryBusy { Sipral.announcementForget(handle, announcement) }
    }

    internal fun callFor(callHandle: Long): SipralCall? = calls[callHandle]

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
    private fun mapMediaSocket(mediaSocket: DatagramSocket, local: String) {
        if (stunServer == null) {
            return
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
    }

    /** The poll thread's half of [mapMediaSocket]'s wait. */
    private fun noteNat(event: SipralEvent) {
        val nat = natOf(event)
        val relay = relayOf(event)
        when {
            nat != null && nat.signalling == 0L -> natWaiters[nat.local ?: return]?.let {
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
        val lens = LongArray(3)
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
            val to = parseHostPort(String(destination, 0, lens[1].toInt(), Charsets.UTF_8))
            val from = String(source, 0, lens[2].toInt(), Charsets.UTF_8)
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

    // -- the poll thread -----------------------------------------------------

    private fun onEvent(event: SipralEvent) {
        // Side effects first, delivery second: a coroutine woken by
        // `events` reading `callFor(event.call)`'s own state must find it
        // already current, the same ordering `sipral.call.Call.deliver`
        // (the Python binding) keeps for the same reason.
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
        val lens = LongArray(2)
        val outCall = LongArray(1)
        while (true) {
            val status = SipralMediaNative.stackPollFarewell(handle, data, destination, lens, outCall)
            val len = lens[0].toInt()
            if (status != SipralStatus.OK.value || len == 0) {
                return
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
                val packet = DatagramPacket(buffer, buffer.size)
                socket.receive(packet)
                val from = formatAddress(packet.address.hostAddress, packet.port)
                retryBusy {
                    Sipral.stackReceiveDatagram(
                        handle,
                        /* SIPRAL_TRANSPORT_MAIN */ 0,
                        packet.data.copyOfRange(0, packet.length),
                        from,
                        bindAddress,
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
        Sipral.stackDestroy(handle)
        socket.close()
    }
}
