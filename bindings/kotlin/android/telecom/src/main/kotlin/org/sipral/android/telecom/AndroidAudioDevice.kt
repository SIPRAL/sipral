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
 * [AudioDevice] over `AudioRecord` and `AudioTrack`, both voice-communication
 * streams: the platform applies its own echo cancellation to them and
 * routes them wherever the telecom framework routed the call, so nothing
 * here picks a device. The `ConnectionService` guide asks a self-managed
 * call's media to be a voice-call stream
 * (developer.android.com/develop/connectivity/telecom/selfManaged, "Manage
 * call audio endpoints"), which `USAGE_VOICE_COMMUNICATION` is.
 *
 * Each [open] builds both from nothing, which is what recovering from
 * `ERROR_DEAD_OBJECT` takes: a stream whose audio server died is never
 * usable again, and only a new one reaches the server that replaced it.
 * The microphone is opened only once `RECORD_AUDIO` is granted; before
 * that the far end hears silence.
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
        // A builder that could not reach the audio server hands back an
        // uninitialised track rather than throwing.
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

        // Both answer a count or one of the negative ERROR_* codes -- among
        // them ERROR_DEAD_OBJECT, the audio server gone -- which CallAudio
        // takes as the streams failing.
        override fun read(buffer: ShortArray): Int = record?.read(buffer, 0, buffer.size) ?: 0

        override fun write(frame: ShortArray): Int = track.write(frame, 0, frame.size)

        // Stopping is what unblocks a read or write another thread is inside:
        // AudioRecord.stop and AudioTrack.pause interrupt a blocked transfer,
        // and the track is flushed so that nothing queued plays later. Both
        // are safe beside a transfer in progress, and release is not, which
        // is why CallAudio calls close only once neither is inside.
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
