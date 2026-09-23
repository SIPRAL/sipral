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
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import org.sipral.Sipral
import org.sipral.SipralCallConfig
import org.sipral.SipralEvent
import org.sipral.SipralEventListener
import org.sipral.SipralStackConfig
import org.sipral.SipralStatus
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
) : AutoCloseable {
    internal var handle: Long = 0L
        private set

    private val origin = System.nanoTime()

    private val eventsFlow = MutableSharedFlow<SipralEvent>(
        replay = 0,
        extraBufferCapacity = 4096,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )

    /** Every event this stack's listener heard, in the order it heard them. */
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
         */
        fun open(
            bindHost: String = "127.0.0.1",
            bindPort: Int = 0,
            userAgent: String? = null,
            codecs: String? = null,
        ): SipralClient {
            val socket = DatagramSocket(bindPort, InetAddress.getByName(bindHost))
            socket.soTimeout = 20
            val bindAddress = formatAddress(socket.localAddress.hostAddress, socket.localPort)
            val client = SipralClient(socket, bindAddress)
            client.start(userAgent, codecs)
            return client
        }
    }

    private fun start(userAgent: String?, codecs: String?) {
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
     */
    fun placeCall(
        account: SipralAccount,
        target: String,
        mediaHost: String = "127.0.0.1",
        mediaPort: Int = 0,
        destination: String? = null,
        srtp: Long = 0,
    ): SipralCall {
        val mediaSocket = DatagramSocket(mediaPort, InetAddress.getByName(mediaHost))
        val mediaAddress = formatAddress(mediaSocket.localAddress.hostAddress, mediaSocket.localPort)
        val config = SipralCallConfig(
            target = target,
            mediaAddress = mediaAddress,
            destination = destination,
            srtp = srtp,
        )
        val callHandle = retryBusy { Sipral.callPlace(handle, account.handle, config, nowMs()) }
        val call = SipralCall(this, callHandle, mediaSocket, mediaAddress)
        calls[callHandle] = call
        return call
    }

    /**
     * Open a media socket for an incoming call and answer it there.
     * `event` is the `SIPRAL_EVENT_KIND_INCOMING_CALL` read off [events].
     */
    fun answerCall(event: SipralEvent, mediaHost: String = "127.0.0.1", mediaPort: Int = 0): SipralCall {
        val mediaSocket = DatagramSocket(mediaPort, InetAddress.getByName(mediaHost))
        val mediaAddress = formatAddress(mediaSocket.localAddress.hostAddress, mediaSocket.localPort)
        val call = SipralCall(this, event.call, mediaSocket, mediaAddress)
        calls[event.call] = call
        call.answer(mediaAddress)
        return call
    }

    /** `sipral_call_reject`, for a call nothing has answered: no media
     * socket was ever needed. */
    fun rejectCall(event: SipralEvent, code: Long = 486) {
        retryBusy { Sipral.callReject(handle, event.call, code, nowMs()) }
    }

    internal fun callFor(callHandle: Long): SipralCall? = calls[callHandle]

    internal fun forgetCall(callHandle: Long) {
        calls.remove(callHandle)
    }

    // -- the poll thread -----------------------------------------------------

    private fun onEvent(event: SipralEvent) {
        // Side effects first, delivery second: a coroutine woken by
        // `events` reading `callFor(event.call)`'s own state must find it
        // already current, the same ordering `sipral.call.Call.deliver`
        // (the Python binding) keeps for the same reason.
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
            val media = call.media ?: continue
            val remote = media.remoteAddress ?: continue
            media.sendTo(data.copyOfRange(0, len), remote)
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
            try {
                Sipral.stackPoll(handle, nowMs())
            } catch (_: Exception) {
                continue
            }
            drainTransmit()
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
        if (Thread.currentThread() !== thread) {
            thread.join(5000)
        }
        Sipral.stackDestroy(handle)
        socket.close()
    }
}
