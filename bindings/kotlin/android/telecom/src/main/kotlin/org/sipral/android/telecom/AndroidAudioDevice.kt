// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.android.telecom

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaRecorder
import org.sipral.telecom.AudioDevice
import org.sipral.telecom.AudioStreams

/**
 * [AudioDevice] over `AudioRecord` and `AudioTrack` as voice-communication
 * streams: the platform applies its echo cancellation and routes them with
 * the call, so nothing here picks a device. The ConnectionService guide
 * asks for a voice-call stream, which `USAGE_VOICE_COMMUNICATION` is.
 *
 * Each [open] builds both from scratch, as recovering from
 * `ERROR_DEAD_OBJECT` requires: a stream whose audio server died never
 * works again. The microphone opens only once `RECORD_AUDIO` is granted;
 * until then the far end hears silence.
 */
class AndroidAudioDevice(private val context: Context) : AudioDevice {
    override fun open(sampleRate: Int, frameSamples: Int): AudioStreams {
        val track = openTrack(sampleRate, frameSamples)
        val granted = context.checkSelfPermission(Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED
        val record = if (granted) {
            try {
                openRecord(sampleRate, frameSamples)
            } catch (refused: RuntimeException) {
                track.release()
                throw refused
            }
        } else {
            null
        }
        return Streams(track, record)
    }

    private fun openTrack(rate: Int, frame: Int): AudioTrack {
        val outMin = AudioTrack.getMinBufferSize(rate, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT)
        val track = AudioTrack.Builder()
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
        // a builder that cannot reach the audio server returns an uninitialised
        // track instead of throwing
        if (track.state != AudioTrack.STATE_INITIALIZED) {
            track.release()
            throw IllegalStateException("AudioTrack did not initialise")
        }
        track.play()
        return track
    }

    @SuppressLint("MissingPermission") // checked by the caller, just above
    private fun openRecord(rate: Int, frame: Int): AudioRecord {
        val inMin = AudioRecord.getMinBufferSize(rate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
        val record = AudioRecord(
            MediaRecorder.AudioSource.VOICE_COMMUNICATION,
            rate,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
            maxOf(inMin, frame * 2 * 4),
        )
        if (record.state != AudioRecord.STATE_INITIALIZED) {
            record.release()
            throw IllegalStateException("AudioRecord did not initialise")
        }
        record.startRecording()
        return record
    }

    private class Streams(private val track: AudioTrack, private val record: AudioRecord?) : AudioStreams {
        override val capturing: Boolean get() = record != null

        // both return a count or a negative ERROR_* code (ERROR_DEAD_OBJECT when
        // the audio server is gone), which CallAudio treats as failure
        override fun read(buffer: ShortArray): Int = record?.read(buffer, 0, buffer.size) ?: 0

        override fun write(frame: ShortArray): Int = track.write(frame, 0, frame.size)

        // Stopping unblocks another thread's read or write: AudioRecord.stop and
        // AudioTrack.pause interrupt a blocked transfer, and the flush drops
        // anything queued. Both are safe beside a transfer; release is not, which
        // is why CallAudio closes only once neither side is inside.
        override fun interrupt() {
            try {
                record?.stop()
            } catch (_: IllegalStateException) {
                // never started, or its server already gone
            }
            try {
                track.pause()
                track.flush()
            } catch (_: IllegalStateException) {
                // as above
            }
        }

        override fun close() {
            record?.release()
            track.release()
        }
    }
}
