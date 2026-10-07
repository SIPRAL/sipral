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

/** One path a call's ICE agent tried, and its outcome: a
 * `sipral_path_candidate_t` with both addresses read out. */
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
 * One call's audio: the `sipral_call_media` handle and the calls that carry
 * its packets (`docs/08-ffi.md`), paced at the negotiated frame rate, on a
 * UDP socket this class owns.
 *
 * Not built directly: [SipralCall] mints one on
 * `SIPRAL_EVENT_KIND_MEDIA_STARTED` and exposes it as [SipralCall.media].
 * `close()` releases the handle and the socket together. A media handle
 * outlives its call, so release it on `CALL_ENDED` rather than waiting for
 * `SipralClient.close()`.
 *
 * In [SipralAudioMode.Device] the library's engine plays and captures, so
 * this carries only packets: [frames] yields nothing and [sendAudio] is
 * ignored ([pumpsFrames] says which). Statistics, ICE paths and the socket
 * work in both modes.
 */
class SipralMedia internal constructor(
    internal val client: SipralClient,
    private val callHandle: Long,
    socket: DatagramSocket,
    /** Whether frames go through [frames] and [sendAudio]
     * ([SipralAudioMode.Application]) rather than the library's engine. */
    val pumpsFrames: Boolean = true,
    /** The real-time text socket, if any: serviced on this thread beside the
     * audio, and closed with it. */
    private val textSocket: DatagramSocket? = null,
) : AutoCloseable {
    /** The two sockets recording copies leave from while a recording session
     * runs. Guarded by [ioLock]. */
    private var recordingSockets: Pair<DatagramSocket, DatagramSocket>? = null

    /** The call's socket. Guarded by [ioLock], with every send and receive,
     * since [SipralCall.moveMedia] replaces it and the engine's thread sends
     * on it in device mode. */
    private var socket: DatagramSocket = socket
    private val ioLock = Any()
    /**
     * `sipral_call_media`'s handle. Retried on `SIPRAL_STATUS_BUSY`: minting
     * runs inside the poll thread's callback, where the ABI never answers
     * Busy (docs/08-ffi.md, re-entry), but another thread ([SipralCall.close]
     * hanging up) can still hold the stack's lock.
     */
    val handle: Long = retryBusy { Sipral.callMedia(client.handle, callHandle) }

    private val negotiated: SipralMediaInfo = Sipral.mediaInfo(handle)

    /** Held for one frame's playback and capture, and while [setAppRate]
     * changes the frame length. */
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
     * Where the last media datagram came from; null until one arrives. Used
     * by [SipralClient] for the RTCP goodbye after signalling has ended.
     */
    @Volatile
    var remoteAddress: InetSocketAddress? = null
        private set

    private val outgoing = ArrayBlockingQueue<ShortArray>(64)
    private var pending = ShortArray(0)

    private val frameChannel = Channel<ShortArray>(Channel.UNLIMITED)

    /** Whether a [SipralLocalConference] carries this call's frames; this
     * thread then leaves them alone, as in device mode. */
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
     * fresh from `sipral_media_info_t`: RTP/AVPF, Generic NACK, reduced-size
     * RTCP. Asked for with `placeCall(feedback = true)`; an offer that asks is
     * always answered on the profile, with NACK and reduced size only when
     * answered with `feedback = true`.
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
     * `sipral_media_send_text`: queue UTF-8 text for the far end (RFC 4103,
     * T.140). It leaves within 300 ms, repeated twice as redundancy when both
     * agreed `red`. BACKSPACE (U+0008) erases the far end's last character.
     * `NOT_NEGOTIATED` without a text stream, `EXHAUSTED` when too much is
     * queued.
     */
    fun sendText(text: String) {
        retryBusy { Sipral.mediaSendText(handle, text) }
    }

    /** Send the recording copies from these two sockets
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
     * `sipral_media_statistics`. After the call ends the library answers
     * `WRONG_STATE`; once the end-of-call record has arrived this returns it
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

    /** The end-of-call record, returned by [statistics] from now on. */
    internal fun endedWith(record: SipralStreamStats) {
        finalStatistics = record
    }

    /**
     * `sipral_media_record_start_with`: record both directions to [path], as
     * WAV, or Ogg Opus where the build has Opus; mono, or stereo with this end
     * left and the far end right; at [sampleRate] (zero: the call's); Opus at
     * [bitrate] (zero: libopus's choice); crash-safe every [checkpointMs]
     * (zero: 5 s). The file is finished by [stopRecording], the call ending,
     * or the client closing.
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
     * Every path this call's ICE agent tried (checklist pairs, then relays)
     * and its outcome (`sipral_media_path_candidate_count`/`_at`,
     * `docs/05-media.md`). Empty without ICE.
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
     * The call's encryption report (`sipral_media_encryption_count`/`_at`):
     * per stream, whether encrypted, the key exchange, the suite, and whether
     * the far end was authenticated. SDES never is; DTLS-SRTP is when the
     * certificate matched the signalled fingerprint.
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
     * Queue 16-bit mono PCM to send, one frame at a time. Chunks of any
     * length are cut to [frameSamples] on the frame thread.
     */
    fun sendAudio(pcm: ShortArray) {
        if (!pumpsFrames) {
            // the engine owns the microphone; nothing would read this
            return
        }
        outgoing.put(pcm)
    }

    /**
     * `sipral_media_set_app_rate`: the rate [frames] yields and [sendAudio]
     * takes, whatever the codec runs at: 8000, 16000, 24000 or 48000, or 0 for
     * the codec's own (the initial state). The library resamples both ways
     * and the frame keeps its duration, so [sampleRate] and [frameSamples]
     * change. Unsent audio queued at the old rate is dropped. Other rates
     * throw `INVALID_ARGUMENT`; device mode throws `WRONG_STATE`.
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

    /** Send a datagram from this call's RTP socket: the RTCP goodbye after
     * the call ended, and device-mode packets. */
    internal fun sendTo(payload: ByteArray, address: InetSocketAddress) {
        synchronized(ioLock) {
            try {
                socket.send(DatagramPacket(payload, payload.size, address))
            } catch (_: Exception) {
                // best effort: a farewell nobody is listening for any more
            }
        }
    }

    /** This call's media socket as `host:port`: where it is offered, and the
     * name of its TURN connection. */
    val localAddress: String
        get() = synchronized(ioLock) { formatAddress(socket.localAddress.hostAddress, socket.localPort) }

    /** Swap in [fresh] and close the old socket, once [SipralCall.moveMedia]
     * has offered the new one. */
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

    // The frame-rate thread

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
        // this pass's socket: closing it in [replaceSocket] ends the receive,
        // and the next pass reads the new one
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

    /** One drain loop for RTCP and DTLS records: same packet struct, same
     * send, only the ABI call differs. */
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

    /** Send one packet: a datagram from this call's socket or, marked TCP or
     * TLS, bytes on the client's TURN connection. `lens` is [len,
     * destination_len, protocol]. */
    private fun send(payload: ByteArray, destination: ByteArray, lens: LongArray) {
        if (overStream(lens[2])) {
            client.writeTurn(localAddress, payload)
            return
        }
        val destinationText = String(destination, 0, lens[1].toInt(), Charsets.UTF_8)
        sendTo(payload, parseAddress(destinationText))
    }

    /** Feed the text socket to `sipral_media_receive_text` and send what is
     * due on it. */
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
                // best effort, like every media datagram
            }
        }
    }

    /** Send the queued recording copies from each party's socket; whatever
     * the server sends back (its RTCP) is read and dropped. */
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
                    // best effort, like every media datagram
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
                        // the engine plays and captures; querying the media is how a dead handle
                        // is noticed
                        Sipral.mediaInfo(handle)
                    }
                    drainRtcp()
                    drainTransmit()
                    pumpText()
                    pumpRecording()
                } catch (stale: SipralException) {
                    // After the call or stack ends, every media entry point answers
                    // WRONG_STATE (docs/08-ffi.md): stop pumping instead of throwing every
                    // frame until close() runs. Anything else is a real failure and reaches
                    // the thread's uncaught-exception handler.
                    if (stale.status == SipralStatus.WRONG_STATE ||
                        stale.status == SipralStatus.STALE_HANDLE
                    ) {
                        active = false
                    } else {
                        throw stale
                    }
                }
            }

            // on a schedule, not a sleep per frame: sleeps end late, and a clock that
            // loses the oversleep sends fewer frames than the far end expects, which
            // it fills with silence
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
