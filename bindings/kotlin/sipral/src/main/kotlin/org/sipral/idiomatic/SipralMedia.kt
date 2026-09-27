// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

package org.sipral.idiomatic

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import org.sipral.Sipral
import org.sipral.SipralException
import org.sipral.SipralCandidateKind
import org.sipral.SipralMediaInfo
import org.sipral.SipralPathKind
import org.sipral.SipralPathOutcome
import org.sipral.SipralStatus
import org.sipral.SipralStreamStats

private const val PACKET_BYTES = 1500
private const val ADDRESS_BYTES = 64

/**
 * One path a call's ICE agent tried, and what became of it: a
 * `sipral_path_candidate_t` with its two addresses read out.
 */
data class PathCandidate(
    /** A candidate pair, or a relay. */
    val kind: SipralPathKind,
    /** What became of it. */
    val outcome: SipralPathOutcome,
    /** The STUN error code of a refusal, or the TURN server's; zero otherwise. */
    val code: Int,
    /** What [local] is. */
    val localKind: SipralCandidateKind,
    /** What [remote] is; `UNKNOWN` for a relay's server. */
    val remoteKind: SipralCandidateKind,
    /** The pair's priority (RFC 8445 §6.1.2.3); zero for a relay. */
    val priority: Long,
    /** For a pair, the candidate its checks left from; for a relay, the relayed address. */
    val local: String,
    /** For a pair, the far end's candidate; for a relay, the TURN server. */
    val remote: String,
)

private fun parseAddress(text: String): InetSocketAddress {
    val at = text.lastIndexOf(':')
    return InetSocketAddress(text.substring(0, at), text.substring(at + 1).toInt())
}

/**
 * One call's audio: `sipral_call_media` minted, and the four calls that
 * carry the packets (`docs/08-ffi.md`, "A call's media has a handle of its
 * own"), paced at the frame rate the negotiation settled on, on a UDP
 * socket this class owns and never shares with signalling.
 *
 * Not built directly. [SipralCall] mints one the moment
 * `SIPRAL_EVENT_KIND_MEDIA_STARTED` says the session exists, and hands it
 * over as [SipralCall.media]. `close()`, or `use { }`, releases the media
 * handle and the socket together; a media handle outlives its call
 * (`docs/08-ffi.md`), so releasing it explicitly rather than waiting for
 * `SipralClient.close()` to sweep it is what lets a long call's media be
 * let go the moment `SIPRAL_EVENT_KIND_CALL_ENDED` says the session is
 * over.
 */
class SipralMedia internal constructor(
    internal val client: SipralClient,
    private val callHandle: Long,
    private val socket: DatagramSocket,
) : AutoCloseable {
    /**
     * `sipral_call_media`'s own handle. Retried on `SIPRAL_STATUS_BUSY` the
     * same way every other signalling call in this layer is: minting
     * normally runs from inside the poll thread's own event callback, where
     * the ABI never answers Busy (docs/08-ffi.md, re-entry), but a second
     * thread's own signalling call -- [SipralCall.close] hanging up, most
     * often -- can still land on the stack's lock at the same moment, which
     * is exactly the ordinary contention [retryBusy] exists for.
     */
    val handle: Long = retryBusy { Sipral.callMedia(client.handle, callHandle) }

    private val negotiated: SipralMediaInfo = Sipral.mediaInfo(handle)

    /** `sipral_media_info_t::sample_rate`. */
    val sampleRate: Int = negotiated.sampleRate.toInt()

    /** `sipral_media_info_t::frame_samples`: exactly what one frame holds. */
    val frameSamples: Int = negotiated.frameSamples.toInt()
    private val frameMillis: Long = maxOf(negotiated.frameMs, 1L)
    private val silence = ShortArray(frameSamples)

    /**
     * Where the last datagram this call's media received came from. Null
     * until at least one has arrived. Read by [SipralClient] to send the
     * RTCP goodbye `sipral_stack_poll_farewell` hands back once signalling
     * has already ended this call.
     */
    @Volatile
    var remoteAddress: InetSocketAddress? = null
        private set

    private val outgoing = ArrayBlockingQueue<ShortArray>(64)
    private var pending = ShortArray(0)

    private val frameChannel = Channel<ShortArray>(Channel.UNLIMITED)

    /** Decoded 16-bit mono PCM, one frame per element, in arrival order. */
    val frames: Flow<ShortArray> = frameChannel.receiveAsFlow()

    private val closed = AtomicBoolean(false)
    private var active = true

    private val thread = Thread(::run, "sipral-media-${callHandle.toString(16)}").apply {
        isDaemon = true
    }

    init {
        socket.soTimeout = 5
        thread.start()
    }

    /** `sipral_media_info`, read fresh. */
    fun info(): SipralMediaInfo = Sipral.mediaInfo(handle)

    /** `sipral_media_statistics`. */
    fun statistics(): SipralStreamStats = Sipral.mediaStatistics(handle, client.nowMs())

    /**
     * Every path this call's ICE agent tried -- the candidate pairs its
     * checklist held, then the relays it held -- and what became of each
     * (`sipral_media_path_candidate_count`/`_at`; D5's transport and NAT
     * half, `docs/05-media.md`). Empty for a call not using ICE.
     */
    fun pathCandidates(): List<PathCandidate> {
        val count = Sipral.mediaPathCandidateCount(handle)
        return (0 until count).map { index ->
            val local = ByteArray(ADDRESS_BYTES)
            val remote = ByteArray(ADDRESS_BYTES)
            val numbers = LongArray(8)
            val status = SipralMediaNative.mediaPathCandidateAt(handle, index, local, remote, numbers)
            if (status != SipralStatus.OK.value) {
                throw SipralException(SipralStatus.of(status), Sipral.lastErrorMessage())
            }
            PathCandidate(
                kind = SipralPathKind.of(numbers[1].toInt()) ?: SipralPathKind.UNKNOWN,
                outcome = SipralPathOutcome.of(numbers[2].toInt()) ?: SipralPathOutcome.UNKNOWN,
                code = numbers[3].toInt(),
                localKind = SipralCandidateKind.of(numbers[4].toInt()) ?: SipralCandidateKind.UNKNOWN,
                remoteKind = SipralCandidateKind.of(numbers[5].toInt()) ?: SipralCandidateKind.UNKNOWN,
                priority = numbers[0],
                local = String(local, 0, numbers[6].toInt(), Charsets.UTF_8),
                remote = String(remote, 0, numbers[7].toInt(), Charsets.UTF_8),
            )
        }
    }

    /**
     * Queue 16-bit mono PCM to go out, one frame at a time. A chunk that is
     * not exactly [frameSamples] long is accepted and cut to size on the
     * frame-rate thread, the same way `sipral.media.Media.send_audio`
     * (the Python binding) cuts it.
     */
    fun sendAudio(pcm: ShortArray) {
        outgoing.put(pcm)
    }

    /** Write a datagram straight to this call's own RTP socket: how
     * [SipralClient] sends the RTCP goodbye a call that just ended still
     * owes the far end. */
    internal fun sendTo(payload: ByteArray, address: InetSocketAddress) {
        try {
            socket.send(DatagramPacket(payload, payload.size, address))
        } catch (_: Exception) {
            // best effort: a farewell nobody is listening for any more
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) {
            return
        }
        if (Thread.currentThread() !== thread) {
            thread.join(5000)
        }
        Sipral.mediaRelease(handle)
        socket.close()
    }

    // -- the frame-rate thread --------------------------------------------

    private fun nextChunk(): ShortArray {
        while (pending.size < frameSamples) {
            val more = outgoing.poll() ?: return silence
            pending += more
        }
        val chunk = pending.copyOfRange(0, frameSamples)
        pending = pending.copyOfRange(frameSamples, pending.size)
        return chunk
    }

    private fun drainReceive() {
        val buffer = ByteArray(2048)
        while (true) {
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                socket.receive(packet)
            } catch (_: SocketTimeoutException) {
                return
            } catch (_: Exception) {
                return
            }
            val from = InetSocketAddress(packet.address, packet.port)
            remoteAddress = from
            Sipral.mediaReceive(
                handle,
                packet.data.copyOfRange(0, packet.length),
                "${packet.address.hostAddress}:${packet.port}",
                client.nowMs(),
            )
        }
    }

    /** One drain loop shared by RTCP and the DTLS-SRTP handshake record
     * path: both fill a `sipral_media_packet_t` the same way and are sent
     * the same way, and differ only in which ABI call produces the packet. */
    private fun drainQueued(poll: (ByteArray, ByteArray, LongArray) -> Int) {
        val data = ByteArray(PACKET_BYTES)
        val destination = ByteArray(ADDRESS_BYTES)
        val lens = LongArray(2)
        while (true) {
            val status = poll(data, destination, lens)
            val len = lens[0].toInt()
            if (status != 0 || len == 0) {
                return
            }
            val destinationLen = lens[1].toInt()
            val destinationText = String(destination, 0, destinationLen, Charsets.UTF_8)
            sendTo(data.copyOfRange(0, len), parseAddress(destinationText))
        }
    }

    private fun drainRtcp() = drainQueued { data, destination, lens ->
        SipralMediaNative.mediaPollRtcp(handle, client.nowMs(), data, destination, lens)
    }

    private fun drainTransmit() = drainQueued { data, destination, lens ->
        SipralMediaNative.mediaPollTransmit(handle, client.nowMs(), data, destination, lens)
    }

    private fun run() {
        while (!closed.get()) {
            val started = System.nanoTime()

            if (active) {
                try {
                    drainReceive()
                    val playback = ShortArray(frameSamples)
                    val (written, _) = Sipral.mediaPlayback(handle, playback)
                    if (written > 0) {
                        frameChannel.trySend(playback.copyOfRange(0, written.toInt()))
                    }

                    val chunk = nextChunk()
                    captureOnce(chunk)
                    drainRtcp()
                    drainTransmit()
                } catch (stale: SipralException) {
                    // "A media handle outlives its call, and says so. Once
                    // the call has ended, or its stack has been destroyed,
                    // every media entry point answers
                    // SIPRAL_STATUS_WRONG_STATE" (docs/08-ffi.md) -- the
                    // frame thread stops pumping the moment that starts
                    // happening rather than raising on every remaining
                    // frame until close() catches up with it. Anything else
                    // this ABI could answer here is a real, unexpected
                    // failure and is left to reach this thread's own
                    // uncaught-exception handler.
                    if (stale.status == SipralStatus.WRONG_STATE ||
                        stale.status == SipralStatus.STALE_HANDLE
                    ) {
                        active = false
                    } else {
                        throw stale
                    }
                }
            }

            val elapsedMs = (System.nanoTime() - started) / 1_000_000
            val remaining = frameMillis - elapsedMs
            if (remaining > 0) {
                try {
                    Thread.sleep(remaining)
                } catch (_: InterruptedException) {
                    return
                }
            }
        }
    }

    private fun captureOnce(samples: ShortArray) {
        val data = ByteArray(PACKET_BYTES)
        val destination = ByteArray(ADDRESS_BYTES)
        val lens = LongArray(2)
        val status = SipralMediaNative.mediaCapture(handle, client.nowMs(), samples, data, destination, lens)
        val len = lens[0].toInt()
        if (status != 0 || len == 0) {
            return
        }
        val destinationLen = lens[1].toInt()
        val destinationText = String(destination, 0, destinationLen, Charsets.UTF_8)
        sendTo(data.copyOfRange(0, len), parseAddress(destinationText))
    }
}
