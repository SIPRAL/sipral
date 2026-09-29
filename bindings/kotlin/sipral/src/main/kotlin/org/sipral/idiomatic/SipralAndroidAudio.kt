// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// Hand-written, beside bindings/kotlin/sipral/src/main/jni/audio_routes.c:
// the one call that hands the library's audio engine an Android Context, so
// that it can list the phone's devices and route its calls. Typed Any
// because this library compiles and runs on a plain JVM too; the shim
// checks that it is a Context.

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
 * On Android, [SipralAudioMode.Device] runs every call through AAudio from
 * API level 28 (on an older phone [SipralAudioMode.platformDefault] is
 * [SipralAudioMode.Application], and the telecom helper's `AudioRecord` and
 * `AudioTrack` carry the call). AAudio opens streams and knows nothing of
 * the phone's devices: listing them -- the earpiece, the loudspeaker, a
 * wired or Bluetooth headset -- and moving a call between them is
 * `AudioManager`'s, which needs a `Context`. [attach] gives it one. Until
 * it is called [SipralAudioDevices.devices] is empty and every call stays
 * on the route the platform chose; after it, the list is the phone's,
 * [SipralAudioDevices.select] on the speaker role moves the call, and
 * `AUDIO_DEVICES_CHANGED` reports a headset arriving or leaving and the
 * route moving, as on every other platform.
 *
 * The telecom helper (`SipralCallAudios`) calls it itself. Call it once,
 * with any context -- the application's is kept, not the one given -- before
 * or after the client opens.
 */
object SipralAndroidAudio {
    /**
     * Hand the engine [context]'s `AudioManager`.
     *
     * @throws IllegalArgumentException when [context] is no
     * `android.content.Context`, which is every object on a JVM that is not
     * Android.
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
