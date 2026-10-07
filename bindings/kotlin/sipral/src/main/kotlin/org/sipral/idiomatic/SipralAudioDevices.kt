// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.idiomatic

import org.sipral.Sipral
import org.sipral.SipralAudio
import org.sipral.SipralAudioActivation
import org.sipral.SipralAudioChange
import org.sipral.SipralAudioDevice
import org.sipral.SipralAudioDirection
import org.sipral.SipralAudioEvent
import org.sipral.SipralAudioOrigin
import org.sipral.SipralAudioRole
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralNative
import org.sipral.SipralStatus
import org.sipral.SipralToggle

/**
 * Who runs a client's audio: `sipral_stack_config_t::audio`.
 *
 * [Device] has the library open the platform's devices (voice-processing
 * unit on macOS, communications streams on Windows, AAudio
 * voice-communication on Android) and pump every call from media start to
 * end; the application only picks devices through [SipralClient.audio]
 * (on Android, after [SipralAndroidAudio.attach]). [Application] hands
 * frames to the application through [SipralMedia.frames] and
 * [SipralMedia.sendAudio]: for a voice agent, a recorder, a test, or an
 * Android phone below API 28, whose calls the telecom helper carries over
 * `AudioRecord` and `AudioTrack`.
 */
sealed class SipralAudioMode {
    /** The library opens the devices, and [activation] says when. */
    data class Device(val activation: SipralAudioActivation = SipralAudioActivation.AUTOMATIC) : SipralAudioMode()

    /** The application pumps every call's frames itself. */
    data object Application : SipralAudioMode()

    companion object {
        /**
         * The default: [Device] with automatic activation where the library has an
         * engine (macOS, Windows, Android API 28+), else [Application] (Linux,
         * older Android). On Android this depends on the phone, not the build.
         */
        val platformDefault: SipralAudioMode
            get() = if (Sipral.capabilities().features and Sipral.FEATURE_AUDIO_DEVICE != 0L) {
                Device()
            } else {
                Application
            }
    }
}

/** One audio device, as `sipral_audio_device_at` lists it. */
data class SipralAudioDeviceInfo(
    /** The engine's id for it: stable across refreshes and unplugging, never
     * reused, never zero. What [SipralAudioDevices.select] takes and what an
     * application saves as a user's choice. */
    val id: Long,
    /** What the platform calls it. */
    val name: String,
    /** How many channels it captures; zero for a device that is no
     * microphone. */
    val inputChannels: Int,
    /** How many channels it plays; zero for a device that is no speaker. */
    val outputChannels: Int,
    val isDefaultInput: Boolean,
    val isDefaultOutput: Boolean,
    /** Whether the last refresh still found it. A removed device keeps its
     * row and id, so a saved selection still names it. */
    val isPresent: Boolean,
) {
    /** Whether it can serve [role]: a microphone needs input channels, a
     * speaker or a ringer output ones. */
    fun canServe(role: SipralAudioRole): Boolean =
        if (role == SipralAudioRole.MICROPHONE) inputChannels > 0 else outputChannels > 0
}

/** What a role was asked to run on, and what it runs on now: the two differ
 * while a chosen device is unplugged. Null is the system's route. */
data class SipralAudioSelection(val selected: Long?, val running: Long?)

/** What the engine is doing (`sipral_audio_info_t`). */
data class SipralAudioStatus(
    val isActive: Boolean,
    /** Whether the platform's processing sits behind the microphone (the
     * voice-processing unit on macOS, which cancels echo; a communications
     * stream on Windows). */
    val systemEchoCancellation: Boolean,
    /** The loudspeaker-to-microphone delay the devices report. */
    val renderDelayMs: Long,
    val microphoneRateHz: Int,
    val speakerRateHz: Int,
    /** The device each role runs on, null while it is closed; a null ringer
     * on an active engine rings through the loudspeaker. */
    val microphone: Long?,
    val speaker: Long?,
    val ringer: Long?,
)

/**
 * The `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED` payload, or null for
 * another kind. Origin `SYSTEM` is the operating system; `ENGINE` is the
 * library acting on a request or a lost device, on which an application
 * should not re-apply its own choice.
 */
fun audioOf(event: SipralEvent): SipralAudioEvent? =
    if (event.kind == SipralEventKind.AUDIO_DEVICES_CHANGED.value.toLong()) event.payload.audio else null

/** [audioOf]'s change, typed. */
val SipralAudioEvent.changeKind: SipralAudioChange? get() = SipralAudioChange.of(change.toInt())

/** [audioOf]'s origin, typed. */
val SipralAudioEvent.originKind: SipralAudioOrigin? get() = SipralAudioOrigin.of(origin.toInt())

/** [audioOf]'s role, typed; null for a change about no role. */
val SipralAudioEvent.roleKind: SipralAudioRole? get() = SipralAudioRole.of(role.toInt())

/**
 * The library's audio engine for a client in [SipralAudioMode.Device]:
 * devices per role, gain, mute, level, the ring, and when devices are
 * open. Reached as [SipralClient.audio].
 *
 * Every member is thread-safe and never takes the stack's lock, so a UI
 * level meter never waits on signalling. A platform that stops answering
 * throws `SipralStatus.DEVICE_TIMED_OUT` after the probe interval rather
 * than hanging.
 */
class SipralAudioDevices internal constructor(private val client: SipralClient) {
    private val stack: Long get() = client.handle

    /**
     * Re-enumerate and return the list. Known devices keep their id, removed
     * ones stay with `isPresent` false, new ones get the next id. The engine
     * refreshes on its own when the platform reports a change (and raises
     * `AUDIO_DEVICES_CHANGED`), so call this when a settings screen opens, not
     * on a timer.
     */
    fun refresh(): List<SipralAudioDeviceInfo> {
        Sipral.audioRefresh(stack)
        return devices()
    }

    /** The list as it stands, present and absent devices alike. */
    fun devices(): List<SipralAudioDeviceInfo> =
        (0 until Sipral.audioDeviceCount(stack)).map { deviceAt(it) }

    /** One row. `sipral_audio_device_at` returns the needed length even when
     * the name does not fit, which the generated wrapper (throwing on any
     * non-success) would hide, so this grows the buffer itself. */
    private fun deviceAt(index: Long): SipralAudioDeviceInfo {
        var buffer = ByteArray(256)
        val slots = LongArray(SipralAudioDevice.SLOTS)
        val needed = LongArray(1)
        var status = SipralNative.sipral_audio_device_at(stack, index, slots, buffer, needed)
        if (status == SipralStatus.BUFFER_TOO_SMALL.value) {
            buffer = ByteArray(needed[0].toInt())
            status = SipralNative.sipral_audio_device_at(stack, index, slots, buffer, needed)
        }
        if (status != SipralStatus.OK.value) {
            throw SipralException(SipralStatus.of(status), Sipral.lastErrorMessage())
        }
        val device = SipralAudioDevice.of(slots)
        return SipralAudioDeviceInfo(
            id = device.id,
            // the length counts the trailing NUL, which is not the name
            name = String(buffer, 0, minOf(needed[0].toInt() - 1, buffer.size).coerceAtLeast(0), Charsets.UTF_8),
            inputChannels = device.inputChannels.toInt(),
            outputChannels = device.outputChannels.toInt(),
            isDefaultInput = device.defaultInput != 0L,
            isDefaultOutput = device.defaultOutput != 0L,
            isPresent = device.present != 0L,
        )
    }

    /**
     * Put [role] on [device], or back on the system route with null.
     *
     * Microphone, speaker and ringer are chosen separately. Refused before
     * anything opens: `NO_SUCH_DEVICE` for an unknown id, `DEVICE_UNUSABLE`
     * for a device lacking channels for the role or unplugged,
     * `NOT_SUPPORTED` where the platform cannot route the role on its own (on
     * iOS, the microphone and ringer). While active the role moves at once,
     * keeping its gain and mute.
     */
    fun select(role: SipralAudioRole, device: Long?) {
        Sipral.audioSelect(stack, role.value.toLong(), device ?: 0L)
    }

    /** [select] by the device itself. */
    fun select(role: SipralAudioRole, device: SipralAudioDeviceInfo?) = select(role, device?.id)

    /** What [role] was asked to run on and what it runs on now. */
    fun selection(role: SipralAudioRole): SipralAudioSelection {
        val (selected, running) = Sipral.audioSelection(stack, role.value.toLong())
        return SipralAudioSelection(selected.takeIf { it != 0L }, running.takeIf { it != 0L })
    }

    /**
     * A direction's gain as a factor: 1 unchanged, 0.5 half, 2 double. Kept by
     * the engine across device changes, so a headset re-plugged mid-call is as
     * loud as before.
     */
    fun setGain(direction: SipralAudioDirection, gain: Double) {
        Sipral.audioSetGain(stack, direction.value.toLong(), Math.round(maxOf(gain, 0.0) * UNITY))
    }

    /** The gain [setGain] set, as a factor. */
    fun gain(direction: SipralAudioDirection): Double = Sipral.audioGain(stack, direction.value.toLong()) / UNITY

    /** Mute or unmute a direction: the input sends silence, the output plays
     * none. Kept across a change of device, like the gain. */
    fun setMuted(direction: SipralAudioDirection, muted: Boolean) {
        Sipral.audioSetMuted(stack, direction.value.toLong(), if (muted) 1L else 0L)
    }

    fun isMuted(direction: SipralAudioDirection): Boolean = Sipral.audioMuted(stack, direction.value.toLong()) != 0L

    /**
     * Turn the platform's echo cancellation on or off on a running client
     * (the `systemEchoCancellation` chosen at [SipralClient.open]). Open
     * devices are reopened at once on the same devices with gain and mute
     * kept; a call keeps its media across the short gap. [status] says what
     * the platform did, `SipralClient.settings()` what was asked.
     */
    fun setSystemEchoCancellation(on: Boolean) {
        Sipral.audioSetSystemEchoCancellation(stack, (if (on) SipralToggle.ON else SipralToggle.OFF).value.toLong())
    }

    /** The meter: a direction's recent peak, 0 to 1, after gain and mute.
     * Cheap enough for a UI timer; zero while inactive. */
    fun level(direction: SipralAudioDirection): Double =
        Sipral.audioLevel(stack, direction.value.toLong()) / Short.MAX_VALUE.toDouble()

    /**
     * One call's gain in one direction, on top of the direction's
     * ([setGain]): input is what that call alone receives from the microphone,
     * output how loud that call plays. Kept across hold and local conferences,
     * dropped when the call ends; `WRONG_STATE` outside the call's media.
     */
    fun setGain(call: SipralCall, direction: SipralAudioDirection, gain: Double) {
        Sipral.audioCallSetGain(stack, call.handle, direction.value.toLong(), Math.round(maxOf(gain, 0.0) * UNITY))
    }

    /** The gain [setGain] set for one call, as a factor. */
    fun gain(call: SipralCall, direction: SipralAudioDirection): Double =
        Sipral.audioCallGain(stack, call.handle, direction.value.toLong()) / UNITY

    /** Mute one call in one direction while the others go on. Kept and
     * refused like the call's gain. */
    fun setMuted(call: SipralCall, direction: SipralAudioDirection, muted: Boolean) {
        Sipral.audioCallSetMuted(stack, call.handle, direction.value.toLong(), if (muted) 1L else 0L)
    }

    fun isMuted(call: SipralCall, direction: SipralAudioDirection): Boolean =
        Sipral.audioCallMuted(stack, call.handle, direction.value.toLong()) != 0L

    /** One call's meter in one direction, 0 to 1, after its own gain and
     * mute. */
    fun level(call: SipralCall, direction: SipralAudioDirection): Double =
        Sipral.audioCallLevel(stack, call.handle, direction.value.toLong()) / Short.MAX_VALUE.toDouble()

    /** Open the devices under `SipralAudioActivation.MANUAL`, on the telecom
     * framework's audio focus or CallKit's `didActivate`. Calls whose media
     * already started are carried from now on. */
    fun activate() = Sipral.audioActivate(stack)

    /** Close the devices; calls stay attached and are heard again at the
     * next [activate]. */
    fun deactivate() = Sipral.audioDeactivate(stack)

    /** Play [tone] (16-bit mono PCM at [sampleRateHz]) on the ringer device
     * until [stopRinging], repeating when [looped]. Under automatic activation
     * the ring opens the devices itself. */
    fun ring(tone: ShortArray, sampleRateHz: Int, looped: Boolean = true) {
        Sipral.audioRing(stack, tone, sampleRateHz.toLong(), if (looped) 1L else 0L)
    }

    fun stopRinging() = Sipral.audioStopRinging(stack)

    /** What the engine is doing now. */
    fun status(): SipralAudioStatus {
        val info = Sipral.audioInfo(stack)
        return SipralAudioStatus(
            isActive = info.active != 0L,
            systemEchoCancellation = info.systemEchoCancellation != 0L,
            renderDelayMs = info.renderDelayMs,
            microphoneRateHz = info.microphoneRateHz.toInt(),
            speakerRateHz = info.speakerRateHz.toInt(),
            microphone = info.microphone.takeIf { it != 0L },
            speaker = info.speaker.takeIf { it != 0L },
            ringer = info.ringer.takeIf { it != 0L },
        )
    }

    private companion object {
        /** The gain `sipral_audio_set_gain` calls unity. */
        const val UNITY = 256.0
    }
}

internal val SipralAudioMode.raw: Pair<Long, Long>
    get() = when (this) {
        is SipralAudioMode.Device -> SipralAudio.DEVICE.value.toLong() to activation.value.toLong()
        SipralAudioMode.Application -> SipralAudio.APPLICATION.value.toLong() to 0L
    }
