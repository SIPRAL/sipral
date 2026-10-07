// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Hand-written, beside audio_routes.c: the call that gives the audio engine
// an Android Context, to list devices and route calls. Typed Any because
// this library also runs on a plain JVM; the shim checks it.

package org.sipral.idiomatic

/** The shim's side of [SipralAndroidAudio]. */
internal object SipralAudioRoutesNative {
    init {
        System.loadLibrary("sipral_jni")
    }

    /** 0 once held; -1 for no `android.content.Context`; -2 when it gave no
     * `AudioManager`. */
    external fun attach(context: Any): Int
}

/**
 * The phone's devices and call routes, for the library's audio engine on
 * Android.
 *
 * [SipralAudioMode.Device] runs calls through AAudio from API 28 (older
 * phones default to [SipralAudioMode.Application], with the telecom
 * helper's `AudioRecord`/`AudioTrack`). AAudio knows nothing of devices:
 * listing them and moving a call between them is `AudioManager`'s, which
 * needs a `Context`, given by [attach]. Before it,
 * [SipralAudioDevices.devices] is empty and calls stay on the platform's
 * route; after it, the list is the phone's, [SipralAudioDevices.select] on
 * the speaker role moves the call, and `AUDIO_DEVICES_CHANGED` reports
 * headsets and route moves as elsewhere.
 *
 * The telecom helper (`SipralCallAudios`) calls it itself. Call it once,
 * with any context (the application context is kept), before or after the
 * client opens.
 */
object SipralAndroidAudio {
    /**
     * Hand the engine [context]'s `AudioManager`.
     *
     * @throws IllegalArgumentException when [context] is not an
     * `android.content.Context` (always, off Android).
     * @throws IllegalStateException when the context gave no `AudioManager`.
     */
    fun attach(context: Any) {
        when (SipralAudioRoutesNative.attach(context)) {
            0 -> Unit
            -1 -> throw IllegalArgumentException("${context.javaClass.name} is not an android.content.Context")
            else -> throw IllegalStateException("the context gave no AudioManager")
        }
    }
}
