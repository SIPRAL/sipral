// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

package org.sipral.sample

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaRecorder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.sipral.idiomatic.SipralMedia

/**
 * One call's audio between the device and [SipralMedia]: the microphone read
 * a frame at a time into `sendAudio`, and every decoded frame written to
 * the speaker. Both are voice-communication streams, so the platform
 * applies its own echo cancellation and routes them wherever the telecom
 * framework has routed the call -- nothing here picks a device.
 */
class AudioPump(context: Context, private val media: SipralMedia, scope: CoroutineScope) : AutoCloseable {
    private val frame = media.frameSamples
    private val track: AudioTrack
    private val record: AudioRecord?
    private val playback: Job
    private val capture: Thread?

    @Volatile
    private var running = true

    init {
        val rate = media.sampleRate
        val outMin = AudioTrack.getMinBufferSize(rate, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT)
        track = AudioTrack.Builder()
            .setAudioAttributes(
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                    .build(),
            )
            .setAudioFormat(
                AudioFormat.Builder()
                    .setSampleRate(rate)
                    .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                    .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                    .build(),
            )
            .setBufferSizeInBytes(maxOf(outMin, frame * 2 * 4))
            .setTransferMode(AudioTrack.MODE_STREAM)
            .build()
        track.play()
        playback = scope.launch(Dispatchers.IO) {
            media.frames.collect { pcm -> track.write(pcm, 0, pcm.size) }
        }

        val granted = context.checkSelfPermission(Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED
        record = if (granted) openRecord(rate) else null
        capture = record?.let { recorder ->
            recorder.startRecording()
            Thread({
                val buffer = ShortArray(frame)
                while (running) {
                    val read = recorder.read(buffer, 0, frame)
                    if (read > 0) {
                        media.sendAudio(buffer.copyOf(read))
                    }
                }
            }, "sample-capture").apply {
                isDaemon = true
                start()
            }
        }
    }

    /** Whether the microphone is being read: false until RECORD_AUDIO is
     * granted, and the far end then hears silence. */
    val capturing: Boolean get() = record != null

    @SuppressLint("MissingPermission") // checked by the caller, just above
    private fun openRecord(rate: Int): AudioRecord {
        val inMin = AudioRecord.getMinBufferSize(rate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
        return AudioRecord(
            MediaRecorder.AudioSource.VOICE_COMMUNICATION,
            rate,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
            maxOf(inMin, frame * 2 * 4),
        )
    }

    override fun close() {
        running = false
        capture?.join(500)
        record?.stop()
        record?.release()
        playback.cancel()
        track.stop()
        track.release()
    }
}
