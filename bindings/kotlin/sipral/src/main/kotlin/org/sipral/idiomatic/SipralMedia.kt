// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
import org.sipral.SipralKeyExchange
import org.sipral.SipralMediaKind
import org.sipral.SipralSrtpSuite
import org.sipral.SipralCandidateKind
import org.sipral.SipralMediaInfo
import org.sipral.SipralPathKind
import org.sipral.SipralPathOutcome
import org.sipral.SipralRecordingFormat
import org.sipral.SipralRecordingLayout
import org.sipral.SipralRecordingOptions
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

internal fun parseAddress(text: String): InetSocketAddress {
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
 *
 * On a client in [SipralAudioMode.Device] the library's engine takes the far
 * end's audio and gives the microphone's, so this thread carries only the
 * packets: [frames] hands out nothing and [sendAudio] is not read
 * ([pumpsFrames] says which). Statistics, the ICE paths and the socket are
 * the same in both modes.
 */
class SipralMedia internal constructor(
    internal val client: SipralClient,
    private val callHandle: Long,
    socket: DatagramSocket,
    /** Whether this media carries the call's frames through [frames] and
     * [sendAudio] -- [SipralAudioMode.Application] -- or the library's
     * engine does. */
    val pumpsFrames: Boolean = true,
    /** The call's real-time text socket, when it has one: read and written
     * on this thread beside the audio, and closed with it. */
    private val textSocket: DatagramSocket? = null,
) : AutoCloseable {
    /** The two sockets the copies for a recording server leave from, while
     * a recording session runs, guarded by [ioLock]. */
    private var recordingSockets: Pair<DatagramSocket, DatagramSocket>? = null

    /** The call's socket, guarded by [ioLock] -- as is every send and
     * receive on it -- since [SipralCall.moveMedia] puts another in its
     * place and the engine's thread sends on it in device mode. */
    private var socket: DatagramSocket = socket
    private val ioLock = Any()
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

    /** Held for one frame's playback and capture, and while [setAppRate]
     * moves the frame's length under them. */
    private val frameLock = Any()

    /** `sipral_media_info_t::sample_rate`: the codec's, or the one
     * [setAppRate] chose. */
    @Volatile
    var sampleRate: Int = negotiated.sampleRate.toInt()
        private set

    /** `sipral_media_info_t::frame_samples`: exactly what one frame holds,
     * at [sampleRate]. */
    @Volatile
    var frameSamples: Int = negotiated.frameSamples.toInt()
        private set
    private val frameMillis: Long = maxOf(negotiated.frameMs, 1L)
    private var silence = ShortArray(frameSamples)

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

    /** Whether a [SipralLocalConference] carries this call's frames, which
     * this media's own thread then leaves alone, as it does in device mode. */
    @Volatile
    internal var carriedByConference: Boolean = false

    /** Decoded 16-bit mono PCM, one frame per element, in arrival order. */
    val frames: Flow<ShortArray> = frameChannel.receiveAsFlow()

    private val closed = AtomicBoolean(false)
    private var active = true

    private val thread = Thread(::run, "sipral-media-${callHandle.toString(16)}").apply {
        isDaemon = true
    }

    init {
        socket.soTimeout = 5
        textSocket?.soTimeout = 1
        thread.start()
    }

    /**
     * What the call agreed about RTCP feedback (RFC 4585, RFC 5506), read
     * fresh from `sipral_media_info_t`: whether the stream runs RTP/AVPF,
     * with Generic NACKs, and with reduced-size RTCP. A call asks for it
     * with `SipralClient.placeCall(feedback = true)`; an offer that asks is
     * answered on the profile, and with the NACKs and reduced size when
     * answered with `feedback = true`. [statistics] counts what it did.
     */
    fun rtcpFeedback(): SipralRtcpFeedback {
        val now = Sipral.mediaInfo(handle)
        return SipralRtcpFeedback(now.feedback != 0L, now.genericNack != 0L, now.reducedSize != 0L)
    }

    /** Whether the call agreed a real-time text stream (RFC 4103), which
     * [sendText] writes to. */
    val hasText: Boolean
        get() = Sipral.mediaInfo(handle).hasText != 0L

    /**
     * `sipral_media_send_text`: queue what the user typed for the far end
     * (RFC 4103, T.140), UTF-8. It leaves in the next 300 ms interval, each
     * block sent twice more as redundancy where both ends agreed `red`; a
     * new line goes as one, and BACKSPACE (U+0008) erases the far end's last
     * character. `NOT_NEGOTIATED` on a call that agreed no text stream,
     * `EXHAUSTED` when more is waiting unsent than a stream holds.
     */
    fun sendText(text: String) {
        retryBusy { Sipral.mediaSendText(handle, text) }
    }

    /** The recorded call's copies leave from these two sockets from now on
     * ([SipralCall.recordTo]). */
    internal fun copyRecording(thisEnd: DatagramSocket, farEnd: DatagramSocket) {
        thisEnd.soTimeout = 1
        farEnd.soTimeout = 1
        val old = synchronized(ioLock) {
            recordingSockets.also { recordingSockets = thisEnd to farEnd }
        }
        old?.first?.close()
        old?.second?.close()
    }

    /** No more copies: the recording session ended. Its sockets close. */
    internal fun stopCopyingRecording() {
        val old = synchronized(ioLock) { recordingSockets.also { recordingSockets = null } }
        old?.first?.close()
        old?.second?.close()
    }

    /** `sipral_media_info`, read fresh. */
    fun info(): SipralMediaInfo = Sipral.mediaInfo(handle)

    /**
     * `sipral_media_statistics`. Once the call has ended the stream is gone
     * and the library answers `SIPRAL_STATUS_WRONG_STATE`; from the moment
     * the end-of-call record has arrived this answers with that record
     * ([SipralCall.finalStatistics]) instead.
     */
    fun statistics(): SipralStreamStats =
        try {
            Sipral.mediaStatistics(handle, client.nowMs())
        } catch (refused: SipralException) {
            val final = finalStatistics
            if (refused.status != SipralStatus.WRONG_STATE || final == null) {
                throw refused
            }
            final
        }

    @Volatile
    private var finalStatistics: SipralStreamStats? = null

    /** The end-of-call record arrived: what [statistics] answers from now
     * on, when the library no longer can. */
    internal fun endedWith(record: SipralStreamStats) {
        finalStatistics = record
    }

    /**
     * `sipral_media_record_start_with`: record both directions to [path] --
     * WAV, or Ogg Opus where the build has Opus; one channel, or this end on
     * the left and the far end on the right; at [sampleRate] (zero for the
     * call's); Ogg Opus at [bitrate] (zero for libopus's choice); made to
     * survive a crash every [checkpointMs] (zero for five seconds). The file
     * is finished by [stopRecording], by the call ending, or by the client
     * closing.
     */
    fun record(
        path: String,
        format: SipralRecordingFormat = SipralRecordingFormat.WAV,
        layout: SipralRecordingLayout = SipralRecordingLayout.MIXED,
        sampleRate: Long = 0,
        bitrate: Long = 0,
        checkpointMs: Long = 0,
    ) {
        val options = SipralRecordingOptions(
            format = format.value.toLong(),
            layout = layout.value.toLong(),
            sampleRate = sampleRate,
            bitrate = bitrate,
            checkpointMs = checkpointMs,
        )
        retryBusy { Sipral.mediaRecordStartWith(handle, path, options) }
    }

    /** `sipral_media_record_stop`: stop, and finish the file. */
    fun stopRecording() {
        retryBusy { Sipral.mediaRecordStop(handle) }
    }

    /** `sipral_media_record_state`: whether a recording is running, and how
     * many milliseconds of audio it has taken. */
    val recording: Pair<Boolean, Long>
        get() {
            val (running, taken) = retryBusy { Sipral.mediaRecordState(handle) }
            return (running != 0L) to taken
        }

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
     * The call's encryption report, now (`sipral_media_encryption_count` and
     * `sipral_media_encryption_at`): per stream, whether it is encrypted, how
     * its keys were exchanged, the suite, and whether the exchange
     * authenticated the far end -- SDES never does, a DTLS-SRTP handshake
     * whose certificate matched the signalled fingerprint does.
     */
    fun encryption(): List<SipralStreamProtection> =
        (0 until Sipral.mediaEncryptionCount(handle)).map { index ->
            val stream = Sipral.mediaEncryptionAt(handle, index)
            SipralStreamProtection(
                media = SipralMediaKind.of(stream.media.toInt()) ?: SipralMediaKind.UNKNOWN,
                encrypted = stream.encrypted != 0L,
                keyExchange = SipralKeyExchange.of(stream.keyExchange.toInt()) ?: SipralKeyExchange.NONE,
                suite = SipralSrtpSuite.of(stream.suite.toInt()),
                authenticated = stream.authenticated != 0L,
                awaitingKeys = stream.awaitingKeys != 0L,
            )
        }

    /**
     * Queue 16-bit mono PCM to go out, one frame at a time. A chunk that is
     * not exactly [frameSamples] long is accepted and cut to size on the
     * frame-rate thread, the same way `sipral.media.Media.send_audio`
     * (the Python binding) cuts it.
     */
    fun sendAudio(pcm: ShortArray) {
        if (!pumpsFrames) {
            // the microphone is the engine's: nothing would ever read this
            return
        }
        outgoing.put(pcm)
    }

    /**
     * `sipral_media_set_app_rate`: the rate [frames] hands out and
     * [sendAudio] takes, whatever rate the codec runs at -- 8000, 16000,
     * 24000 or 48000, or 0 for the codec's own, which is where every call
     * starts. The library converts both ways with its own resampler, and the
     * frame keeps the call's duration, so [sampleRate] and [frameSamples]
     * say the new rate and its length from here on. Audio queued with
     * [sendAudio] and not yet sent was at the old rate, and is dropped. Any
     * other rate throws [SipralException] with `INVALID_ARGUMENT`, and
     * device mode with `WRONG_STATE`.
     */
    fun setAppRate(hz: Int) {
        synchronized(frameLock) {
            retryBusy { Sipral.mediaSetAppRate(handle, hz.toLong()) }
            val now = Sipral.mediaInfo(handle)
            sampleRate = now.sampleRate.toInt()
            frameSamples = now.frameSamples.toInt()
            silence = ShortArray(frameSamples)
            pending = ShortArray(0)
            outgoing.clear()
        }
    }

    /** Write a datagram straight to this call's own RTP socket: how
     * [SipralClient] sends the RTCP goodbye a call that just ended still
     * owes the far end, and the packets the engine encodes in device mode. */
    internal fun sendTo(payload: ByteArray, address: InetSocketAddress) {
        synchronized(ioLock) {
            try {
                socket.send(DatagramPacket(payload, payload.size, address))
            } catch (_: Exception) {
                // best effort: a farewell nobody is listening for any more
            }
        }
    }

    /** This call's media socket, as `host:port`: where it is offered now,
     * and the name of its connection to a TURN server. */
    val localAddress: String
        get() = synchronized(ioLock) { formatAddress(socket.localAddress.hostAddress, socket.localPort) }

    /** Put [fresh] in the place of the call's socket and close the old one:
     * [SipralCall.moveMedia], once the call has been offered at the new one. */
    internal fun replaceSocket(fresh: DatagramSocket) {
        fresh.soTimeout = 5
        synchronized(ioLock) {
            val old = socket
            socket = fresh
            old.close()
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
        val copies = synchronized(ioLock) {
            socket.close()
            recordingSockets.also { recordingSockets = null }
        }
        textSocket?.close()
        copies?.first?.close()
        copies?.second?.close()
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
        // the socket of this pass: one [replaceSocket] closes under a
        // receive ends it, and the next pass reads the new one
        val current = synchronized(ioLock) { socket }
        while (true) {
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                current.receive(packet)
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
        val lens = LongArray(3)
        while (true) {
            val status = poll(data, destination, lens)
            val len = lens[0].toInt()
            if (status != 0 || len == 0) {
                return
            }
            send(data.copyOfRange(0, len), destination, lens)
        }
    }

    /** One packet out where it says: a datagram from this call's socket,
     * or -- marked TCP or TLS -- bytes on the socket's connection to the TURN
     * server, which the client holds. `lens` is [len, destination_len,
     * protocol]. */
    private fun send(payload: ByteArray, destination: ByteArray, lens: LongArray) {
        if (overStream(lens[2])) {
            client.writeTurn(localAddress, payload)
            return
        }
        val destinationText = String(destination, 0, lens[1].toInt(), Charsets.UTF_8)
        sendTo(payload, parseAddress(destinationText))
    }

    /** What arrived on the text socket, to `sipral_media_receive_text`, and
     * what is due on it, out of it. */
    private fun pumpText() {
        val text = textSocket ?: return
        val buffer = ByteArray(2048)
        while (true) {
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                text.receive(packet)
            } catch (_: Exception) {
                break
            }
            Sipral.mediaReceiveText(
                handle,
                packet.data.copyOfRange(0, packet.length),
                "${packet.address.hostAddress}:${packet.port}",
                client.nowMs(),
            )
        }
        val data = ByteArray(PACKET_BYTES)
        val destination = ByteArray(ADDRESS_BYTES)
        val lens = LongArray(3)
        while (true) {
            val status = SipralMediaNative.mediaPollText(handle, client.nowMs(), data, destination, lens)
            val len = lens[0].toInt()
            if (status != 0 || len == 0) {
                return
            }
            val to = parseAddress(String(destination, 0, lens[1].toInt(), Charsets.UTF_8))
            try {
                text.send(DatagramPacket(data, len, to))
            } catch (_: Exception) {
                // best effort, as every datagram of a call's
            }
        }
    }

    /** Every copy waiting for the recording server, out of the socket its
     * party's stream is offered from. What the server sends back on them
     * (its RTCP) is read and let go. */
    private fun pumpRecording() {
        val sockets = synchronized(ioLock) { recordingSockets } ?: return
        val buffer = ByteArray(2048)
        for (socket in listOf(sockets.first, sockets.second)) {
            while (true) {
                try {
                    socket.receive(DatagramPacket(buffer, buffer.size))
                } catch (_: Exception) {
                    break
                }
            }
        }
        val data = ByteArray(PACKET_BYTES)
        val destination = ByteArray(ADDRESS_BYTES)
        val lens = LongArray(3)
        val farEnd = LongArray(1)
        while (true) {
            val status = SipralMediaNative.mediaPollRecording(handle, data, destination, lens, farEnd)
            val len = lens[0].toInt()
            if (status != 0 || len == 0) {
                return
            }
            val to = parseAddress(String(destination, 0, lens[1].toInt(), Charsets.UTF_8))
            synchronized(ioLock) {
                val open = recordingSockets ?: return
                try {
                    (if (farEnd[0] != 0L) open.second else open.first).send(DatagramPacket(data, len, to))
                } catch (_: Exception) {
                    // best effort, as every datagram of a call's
                }
            }
        }
    }

    private fun drainRtcp() = drainQueued { data, destination, lens ->
        SipralMediaNative.mediaPollRtcp(handle, client.nowMs(), data, destination, lens)
    }

    private fun drainTransmit() = drainQueued { data, destination, lens ->
        SipralMediaNative.mediaPollTransmit(handle, client.nowMs(), data, destination, lens)
    }

    private fun run() {
        var due = System.nanoTime()
        while (!closed.get()) {
            if (active) {
                try {
                    drainReceive()
                    if (pumpsFrames && !carriedByConference) {
                        synchronized(frameLock) {
                            val playback = ShortArray(frameSamples)
                            val (written, _) = Sipral.mediaPlayback(handle, playback)
                            if (written > 0) {
                                frameChannel.trySend(playback.copyOfRange(0, written.toInt()))
                            }
                            captureOnce(nextChunk())
                        }
                    } else {
                        // the engine plays and captures; asking after the
                        // media is what notices it gone
                        Sipral.mediaInfo(handle)
                    }
                    drainRtcp()
                    drainTransmit()
                    pumpText()
                    pumpRecording()
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

            // on a schedule, not a sleep after each frame: a sleep ends late,
            // and a frame clock that loses what it overslept sends and plays
            // fewer frames a second than the far end's clock expects, which
            // its buffer then fills with silence
            due += frameMillis * 1_000_000L
            val remainingNs = due - System.nanoTime()
            if (remainingNs > 0) {
                try {
                    Thread.sleep(remainingNs / 1_000_000L, (remainingNs % 1_000_000L).toInt())
                } catch (_: InterruptedException) {
                    return
                }
            } else {
                due = System.nanoTime()
            }
        }
    }

    private fun captureOnce(samples: ShortArray) {
        val data = ByteArray(PACKET_BYTES)
        val destination = ByteArray(ADDRESS_BYTES)
        val lens = LongArray(3)
        val status = SipralMediaNative.mediaCapture(handle, client.nowMs(), samples, data, destination, lens)
        val len = lens[0].toInt()
        if (status != 0 || len == 0) {
            return
        }
        send(data.copyOfRange(0, len), destination, lens)
    }
}
