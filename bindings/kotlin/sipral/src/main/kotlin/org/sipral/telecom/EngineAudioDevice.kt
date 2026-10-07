// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The library's audio engine as a CallAudio device: on Android API 28+ the
// engine runs every call over AAudio, and a call's CallAudio only has to
// say when the devices are the call's, which is the engine's activation.

package org.sipral.telecom

import java.util.concurrent.atomic.AtomicBoolean

/**
 * [AudioDevice] over the library's engine
 * (`org.sipral.idiomatic.SipralAudioMode.Device`), for a client whose calls
 * the engine carries.
 *
 * The engine pumps every call, so nothing is read or written here: [open]
 * activates the engine's devices and returns streams without frames. One
 * engine serves every call, so all [CallAudio]s built over one instance
 * share it: devices come on with the first open and go off with the last
 * release (a call held for a cellular one releases; the call answered
 * beside it keeps them). A refusal from [activate] is a failed open, which
 * [CallAudio] retries and reports.
 *
 * The engine keeps its devices open through unplugs, route moves and
 * audio server restarts, reporting them as `AUDIO_DEVICES_CHANGED`, so
 * these streams never fail.
 */
class EngineAudioDevice(
    private val activate: () -> Unit,
    private val deactivate: () -> Unit,
) : AudioDevice {
    private val lock = Any()
    private var holders = 0

    /** How many streams hold the devices now. */
    val held: Int get() = synchronized(lock) { holders }

    override fun open(sampleRate: Int, frameSamples: Int): AudioStreams {
        synchronized(lock) {
            if (holders == 0) {
                activate()
            }
            holders++
        }
        return Held()
    }

    private fun release() {
        synchronized(lock) {
            holders--
            if (holders == 0) {
                deactivate()
            }
        }
    }

    private inner class Held : AudioStreams {
        private val released = AtomicBoolean(false)

        // the engine reads the microphone into the call itself
        override val capturing: Boolean = false

        override fun read(buffer: ShortArray): Int = 0

        // the engine plays the call itself; in device mode media hands out no
        // frames to write
        override fun write(frame: ShortArray): Int = frame.size

        override fun interrupt() {
            if (released.compareAndSet(false, true)) {
                release()
            }
        }

        override fun close() {
            interrupt()
        }
    }
}
