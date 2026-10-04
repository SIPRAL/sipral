// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The library's own audio engine as a CallAudio device: on Android from API
// level 28 the engine runs every call over AAudio, and what a call's
// CallAudio still has to do is say when the device is the call's -- which
// is the engine's activation.

package org.sipral.telecom

import java.util.concurrent.atomic.AtomicBoolean

/**
 * [AudioDevice] over the library's own engine
 * (`org.sipral.idiomatic.SipralAudioMode.Device`), for a client whose calls
 * the engine carries.
 *
 * The engine already pumps every call, so there is nothing here to read or
 * write: [open] turns the engine's devices on ([activate]) and the streams
 * it returns carry no frames. What is left is who holds the devices. One
 * engine serves every call, so the streams of every [CallAudio] built over
 * the same instance share it: the devices come on when the first is
 * opened and go off only when the last is let go -- a call held for a
 * cellular one lets go, the call answered beside it keeps them. A refusal
 * from [activate] is an open that failed, which [CallAudio] retries and
 * reports as it does any other.
 *
 * The engine keeps the devices open itself through what happens under
 * them -- a headset unplugged, a route moved, the audio server restarted --
 * and says so on the client's `AUDIO_DEVICES_CHANGED` events, so these
 * streams never fail.
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

        // The engine reads the microphone into the call itself.
        override val capturing: Boolean = false

        override fun read(buffer: ShortArray): Int = 0

        // The engine plays the call itself, and on a client in device mode
        // the media hands out no frames to write.
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
