// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

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

/**
 * Who runs a client's audio: `sipral_stack_config_t::audio`.
 *
 * [Device] has the library open the platform's own devices -- the
 * voice-processing unit on macOS, communications streams on Windows -- and
 * pump every call from the moment its media starts to the moment it ends,
 * with nothing for the application to do but choose devices through
 * [SipralClient.audio]. [Application] is the client as it was before:
 * [SipralMedia.frames] carries the far end's audio and
 * [SipralMedia.sendAudio] takes the microphone's, for an application that
 * runs its own audio -- a voice agent, a recorder, a test, and Android,
 * whose devices belong to the telecom helper's `CallAudio`.
 */
sealed class SipralAudioMode {
    /** The library opens the devices, and [activation] says when. */
    data class Device(val activation: SipralAudioActivation = SipralAudioActivation.AUTOMATIC) : SipralAudioMode()

    /** The application pumps every call's frames itself. */
    data object Application : SipralAudioMode()

    companion object {
        /**
         * What a client is opened with unless it says otherwise: [Device]
         * with automatic activation wherever this build of the library has
         * an engine for the platform -- macOS, Windows -- and [Application]
         * where it has none: Linux, and Android, whose telecom helper runs
         * the devices itself.
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
    /** The engine's name for it: stable across refreshes and unplugging,
     * never reused, never zero -- what [SipralAudioDevices.select] takes,
     * and what an application saves as a person's choice. */
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
    /** Whether the last refresh still found it. A device that went keeps
     * its row and its id, so a selection saved against it still names it. */
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
    /** Whether the platform's own processing sits behind the microphone:
     * the voice-processing unit on macOS, which cancels the echo; a
     * communications stream on Windows, which runs the endpoint's own. */
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
 * The `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED` payload -- what changed and
 * who changed it: `SipralAudioOrigin.SYSTEM` for the operating system,
 * `SipralAudioOrigin.ENGINE` for the library doing what it was asked or
 * what a lost device made it do, which an application never re-applies its
 * own choice on -- or null for an event of any other kind.
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
 * The library's own audio engine for one client opened in
 * [SipralAudioMode.Device]: the devices listed, chosen per role, their
 * gain, mute and level, the ring, and when they are open.
 * [SipralClient.audio].
 *
 * Every member calls the C ABI directly and may be called from any thread;
 * none takes the stack's own lock, so a level meter read on a UI timer
 * never waits for signalling. A platform that stops answering is a
 * [SipralException] with `SipralStatus.DEVICE_TIMED_OUT` after the probe
 * interval, never a hang.
 */
class SipralAudioDevices internal constructor(private val client: SipralClient) {
    private val stack: Long get() = client.handle

    /**
     * Ask the platform again, and return the list. A device seen before
     * keeps its id; one that has gone stays, `isPresent` false; a new one
     * gets the next id. The engine refreshes by itself when the platform
     * announces a change, and says so with
     * `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED`, so this is for a settings
     * screen opening rather than for polling.
     */
    fun refresh(): List<SipralAudioDeviceInfo> {
        Sipral.audioRefresh(stack)
        return devices()
    }

    /** The list as it stands, present and absent devices alike. */
    fun devices(): List<SipralAudioDeviceInfo> =
        (0 until Sipral.audioDeviceCount(stack)).map { deviceAt(it) }

    /** One row, its name read into a buffer that grows to what the library
     * says it needs: `sipral_audio_device_at` hands the length back even
     * when the name does not fit, which the generated wrapper, throwing on
     * anything but success, would not. */
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
            name = String(buffer, 0, minOf(needed[0].toInt(), buffer.size), Charsets.UTF_8),
            inputChannels = device.inputChannels.toInt(),
            outputChannels = device.outputChannels.toInt(),
            isDefaultInput = device.defaultInput != 0L,
            isDefaultOutput = device.defaultOutput != 0L,
            isPresent = device.present != 0L,
        )
    }

    /**
     * Put [role] on [device], or back on the system's route with null.
     *
     * The microphone, the speaker and the ringer are chosen separately.
     * Refused before anything is opened: `NO_SUCH_DEVICE` for an id the list
     * never held, `DEVICE_UNUSABLE` for a device with no channels for the
     * role or one that is not plugged in, and `NOT_SUPPORTED` where the
     * platform cannot put the role on a device of its own -- on macOS the
     * call's microphone and loudspeaker are one unit, so the microphone
     * follows the system's input and the ring goes through the loudspeaker.
     * While the engine is active the role moves at once, with its
     * direction's gain and mute carried over.
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
     * The gain of a direction as a factor: 1 leaves the audio as it is, 0.5
     * halves it, 2 doubles it. The input direction is the microphone's gain.
     * Kept by the engine and applied to whatever device the direction runs
     * on, so a headset unplugged mid-call comes back as loud as it was.
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

    /** The meter: the recent peak of a direction, 0 for silence to 1 for
     * full scale, after the gain and the mute. Cheap enough for a UI timer;
     * zero while the engine is not active. */
    fun level(direction: SipralAudioDirection): Double =
        Sipral.audioLevel(stack, direction.value.toLong()) / Short.MAX_VALUE.toDouble()

    /** Open the devices, under `SipralAudioActivation.MANUAL`: what the
     * telecom framework's audio focus, or CallKit's `didActivate`, is for.
     * Calls whose media started before this are carried from here on. */
    fun activate() = Sipral.audioActivate(stack)

    /** Close the devices; calls stay attached and are heard again at the
     * next [activate]. */
    fun deactivate() = Sipral.audioDeactivate(stack)

    /** Play [tone] -- 16-bit mono PCM at [sampleRateHz] -- on the ringer's
     * device until [stopRinging], over and over when [looped]. Under
     * automatic activation the ring opens the devices itself. */
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
