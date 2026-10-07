// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.android.telecom

import android.content.Context
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import org.sipral.SipralAudioDirection
import org.sipral.idiomatic.SipralAudioDevices
import org.sipral.idiomatic.SipralMedia
import org.sipral.telecom.AudioDevice
import org.sipral.telecom.AudioPause
import org.sipral.telecom.AudioState
import org.sipral.telecom.AudioTransition
import org.sipral.telecom.CallAudio
import org.sipral.telecom.EngineAudioDevice
import org.sipral.telecom.TelecomBridge

/**
 * One self-managed call's microphone and speaker, kept through whatever
 * the platform does to them during the call, with every change reported.
 *
 * What a self-managed `ConnectionService` must handle about audio:
 *
 * - **Hold from the framework.** A cellular or other app's call answered
 *   over this one arrives as `Connection.onHold`, which must call
 *   `setOnHold()`, and returns through `onUnhold`, which must call
 *   `setActive()` (ConnectionService docs, "Holding and Unholding Calls").
 *   [TelecomBridge.hold] does both and holds the far end; this follows the
 *   bridge's phase, releasing the device while held.
 * - **Call focus.** From Android 9 the framework moves it between calling
 *   apps, and one that loses it should release call resources
 *   ([SipralConnectionService.onConnectionServiceFocusLost]). The device is
 *   released while focus is elsewhere, without holding the far end.
 * - **Routes and mute.** The framework routes a voice-communication stream
 *   wherever the call went and reports mute via `onMuteStateChanged`.
 *   Routes are reported; mute sends silence.
 * - **Audio focus.** Not requested: the framework holds it while a
 *   self-managed connection is live (`CAPABILITY_SELF_MANAGED`), leaving
 *   only call focus to the app.
 * - **Audio server death.** `read`/`write` answer `ERROR_DEAD_OBJECT`;
 *   both streams are rebuilt until they open, with silence meanwhile.
 *
 * When the engine carries the calls (device mode, Android 9+) nothing here
 * opens streams: the device is the engine's shared activation, released
 * when no call holds it; mute is the engine's; and audio server death is
 * the engine's to recover, reported as `AUDIO_DEVICES_CHANGED`.
 *
 * Built once the call has media, for the bridge's call [id], and closed
 * on its own when the call ends.
 */
class SipralCallAudio(
    context: Context,
    bridge: TelecomBridge,
    val id: String,
    media: SipralMedia,
    private val scope: CoroutineScope,
    /** The client's engine when it carries the call (device mode), or null
     * for `AudioRecord` and `AudioTrack` opened here. */
    private val engine: SipralAudioDevices? = null,
    /** What the call's audio is opened on: the engine's activation, shared
     * by every call, or this call's own `AudioRecord` and `AudioTrack`. */
    device: AudioDevice = if (engine != null) {
        EngineAudioDevice(engine::activate, engine::deactivate)
    } else {
        AndroidAudioDevice(context.applicationContext)
    },
) : AutoCloseable {
    private val audio = CallAudio(id, device, media, scope)
    private val jobs = CopyOnWriteArrayList<Job>()

    /** Every change to this call's audio, in order; see [CallAudio.transitions]. */
    val transitions: SharedFlow<AudioTransition> = audio.transitions

    val state: StateFlow<AudioState> = audio.state

    /** Why the device is let go, when it is. */
    val pauses: StateFlow<Set<AudioPause>> = audio.pauses

    init {
        SipralTelecom.register(audio)
        jobs += scope.launch(start = CoroutineStart.UNDISPATCHED) {
            val connection = SipralTelecom.connections.map { it[id] }.filterNotNull().first()
            launch { connection.route.filterNotNull().collect { audio.routeChanged(it) } }
            launch {
                connection.muted.collect { muted ->
                    audio.setMuted(muted)
                    // the engine reads the microphone itself, so the framework's mute is the
                    // engine's
                    engine?.setMuted(SipralAudioDirection.INPUT, muted)
                }
            }
        }
        jobs += scope.launch(start = CoroutineStart.UNDISPATCHED) {
            audio.state.first { it == AudioState.STOPPED }
            close()
        }
        jobs += audio.follow(bridge, id)
    }

    /** Stop for good, before the call ends if the application wants to. */
    override fun close() {
        SipralTelecom.unregister(audio)
        audio.close()
        for (job in jobs) {
            job.cancel()
        }
    }
}
