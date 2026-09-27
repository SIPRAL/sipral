// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

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
import org.sipral.idiomatic.SipralMedia
import org.sipral.telecom.AudioPause
import org.sipral.telecom.AudioState
import org.sipral.telecom.AudioTransition
import org.sipral.telecom.CallAudio
import org.sipral.telecom.TelecomBridge

/**
 * One self-managed call's microphone and speaker, kept through whatever the
 * platform does to them while the call lasts, with every change reported.
 *
 * What a self-managed `ConnectionService` is left to do about audio, and
 * what this does about each:
 *
 * - **Hold from the framework.** A cellular call or another application's
 *   call answered over this one reaches it as `Connection.onHold`, which
 *   "must call `Connection.setOnHold()`", and the call comes back through
 *   `onUnhold`, which "must call `Connection.setActive()`"
 *   (developer.android.com/reference/android/telecom/ConnectionService,
 *   "Holding and Unholding Calls"). [TelecomBridge.hold] does both at once
 *   and holds the far end with a re-INVITE; this follows the bridge's
 *   phase, letting the device go while the call is held -- the other call
 *   has the microphone -- and taking it back when it is active again.
 * - **The call focus.** From Android 9 the framework moves it between
 *   calling applications, and one that loses it "should release the call
 *   resources" ([SipralConnectionService.onConnectionServiceFocusLost]).
 *   The device is let go for as long as the focus is elsewhere, without
 *   holding the far end, since the framework did not hold the call.
 * - **Routes and mute.** The framework routes a voice-communication
 *   stream wherever the call went -- earpiece, speaker, a wired or
 *   Bluetooth headset, a car -- and applies the mute its own controls ask
 *   for through `onMuteStateChanged`. Routes are reported; mute sends the
 *   far end silence in place of the microphone.
 * - **Audio focus.** Not requested here. The framework holds it for the
 *   call while the connection is live -- a self-managed account is one
 *   that "want[s] to leverage the call and audio routing capabilities of
 *   the Telecom framework" (`PhoneAccount.CAPABILITY_SELF_MANAGED`) -- and
 *   what it leaves to the application is the call focus above.
 * - **The audio server dying.** `AudioRecord.read` and `AudioTrack.write`
 *   answer `ERROR_DEAD_OBJECT`; both streams are built again, until they
 *   open, and the far end hears silence meanwhile.
 *
 * Built once the call has media, for the call [id] the bridge knows it by,
 * and closed on its own when the call ends.
 */
class SipralCallAudio(
    context: Context,
    bridge: TelecomBridge,
    val id: String,
    media: SipralMedia,
    private val scope: CoroutineScope,
) : AutoCloseable {
    private val audio = CallAudio(id, AndroidAudioDevice(context.applicationContext), media, scope)
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
            launch { connection.muted.collect { audio.setMuted(it) } }
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
