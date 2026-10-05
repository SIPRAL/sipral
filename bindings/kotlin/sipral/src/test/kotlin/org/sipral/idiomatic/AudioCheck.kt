// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// SipralAudioMode.Device on this machine's real devices, through
// org.sipral.idiomatic: the library's engine listed, chosen, turned up and
// down, opened and closed, and carrying a call against a client in
// application mode on 127.0.0.1. Run by IdiomaticCheck.kt's main, under
// -Xcheck:jni.
//
// The list, the choices and the settings are asked of the platform without
// opening anything, and run wherever the library has an engine. What opens
// the devices -- activation, the ring, a call -- runs the voice-processing
// unit, which on macOS needs the microphone granted to the process: without
// the grant the unit fails inside the framework, and the JVM with it. Those
// run only with SIPRAL_AUDIO_DEVICES=1, from a Terminal the system has asked
// about the microphone once (bindings/kotlin/README.md, "Build and test").
// One client in device mode at a time: two voice-processing units in one
// process do not survive on macOS.

package org.sipral.idiomatic

import kotlinx.coroutines.delay
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.sipral.Sipral
import org.sipral.SipralAudioActivation
import org.sipral.SipralAudioChange
import org.sipral.SipralAudioDirection
import org.sipral.SipralAudioOrigin
import org.sipral.SipralAudioRole
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralStatus
import org.sipral.SipralToggle

private val hasEngine: Boolean get() = Sipral.capabilities().features and Sipral.FEATURE_AUDIO_DEVICE != 0L

private val opensDevices: Boolean get() = System.getenv("SIPRAL_AUDIO_DEVICES") == "1"

private fun deviceClient(activation: SipralAudioActivation = SipralAudioActivation.MANUAL) =
    SipralClient.open(audio = SipralAudioMode.Device(activation), bindHost = "127.0.0.1")

/** The virtual loopback device a check that opens the devices plays and
 * records on when the machine has one: it plays nowhere and hands back what it
 * was given, so that a run never sounds through the machine's loudspeaker.
 * Without it the check runs on the system's route, as it always did. */
internal const val QUIET_DEVICE = "BlackHole 2ch"

private val everyRole = listOf(SipralAudioRole.SPEAKER, SipralAudioRole.MICROPHONE, SipralAudioRole.RINGER)

/** The device [role] goes on in a check that opens the devices: the quiet one
 * when the machine has it and it serves the role, and null otherwise. */
internal fun quietDevice(devices: List<SipralAudioDeviceInfo>, role: SipralAudioRole): SipralAudioDeviceInfo? =
    devices.firstOrNull { it.isPresent && it.name == QUIET_DEVICE && it.canServe(role) }

/** A client whose devices a check is going to open, every role on the quiet
 * device when the machine has one. */
private fun openingClient(activation: SipralAudioActivation): SipralClient {
    val client = deviceClient(activation)
    val audio = assertNotNull(client.audio)
    val devices = audio.refresh()
    for (role in everyRole) {
        quietDevice(devices, role)?.let { audio.select(role, it) }
    }
    return client
}

private fun theQuietDeviceIsChosenWhereTheMachineHasIt(): String {
    fun device(id: Long, name: String, inputs: Int, outputs: Int, present: Boolean = true) =
        SipralAudioDeviceInfo(id, name, inputs, outputs, false, id == 1L, present)
    val laptop = listOf(device(1, "MacBook Air Speakers", 0, 2), device(2, "MacBook Air Microphone", 1, 0))
    for (role in everyRole) {
        assertNull(quietDevice(laptop, role))
        assertEquals(3L, quietDevice(laptop + device(3, QUIET_DEVICE, 2, 2), role)?.id)
    }
    assertNull(quietDevice(laptop + device(3, QUIET_DEVICE, 2, 2, present = false), SipralAudioRole.SPEAKER))
    assertNull(quietDevice(laptop + device(4, "BlackHole 16ch", 16, 16), SipralAudioRole.SPEAKER))
    return "the quiet device chosen where the machine has it, and nothing new where it has not"
}

private suspend fun until(withinMs: Long, done: () -> Boolean): Boolean {
    val deadline = System.currentTimeMillis() + withinMs
    while (!done()) {
        if (System.currentTimeMillis() > deadline) return false
        delay(10)
    }
    return true
}

private fun thePlatformDefault(): String {
    val expected = if (hasEngine) SipralAudioMode.Device() else SipralAudioMode.Application
    assertEquals(expected, SipralAudioMode.platformDefault)
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { pumped ->
        assertNull(pumped.audio, "a client whose application pumps the frames has an engine")
    }
    return "the platform default is ${SipralAudioMode.platformDefault}"
}

private fun theListKeepsItsIdsAndEachRoleIsRefusedByStatus(): String {
    deviceClient().use { client ->
        val audio = assertNotNull(client.audio)
        val first = audio.refresh()
        val second = audio.refresh()
        assertFalse(first.isEmpty(), "no device listed")
        assertEquals(first.map { it.id }, second.map { it.id })
        assertTrue(first.all { it.id != 0L && it.name.isNotEmpty() })
        assertEquals(second, audio.devices())
        assertFalse(audio.status().isActive, "listing opened the devices")

        val speaker = assertNotNull(first.firstOrNull { it.isPresent && it.canServe(SipralAudioRole.SPEAKER) })
        val unknown = assertFailsWith<SipralException> { audio.select(SipralAudioRole.SPEAKER, 0xFFFF_FFFFL) }
        assertEquals(SipralStatus.NO_SUCH_DEVICE, unknown.status)
        first.firstOrNull { it.isPresent && it.outputChannels == 0 }?.let { microphoneOnly ->
            val unusable = assertFailsWith<SipralException> { audio.select(SipralAudioRole.SPEAKER, microphoneOnly) }
            assertEquals(SipralStatus.DEVICE_UNUSABLE, unusable.status)
        }
        audio.select(SipralAudioRole.SPEAKER, speaker)
        assertEquals(speaker.id, audio.selection(SipralAudioRole.SPEAKER).selected)
        audio.select(SipralAudioRole.SPEAKER, null as SipralAudioDeviceInfo?)
        assertNull(audio.selection(SipralAudioRole.SPEAKER).selected)
        if (System.getProperty("os.name").lowercase().contains("mac")) {
            // the microphone is named apart from the loudspeaker, on the one
            // voice-processing unit's other element
            val microphone = assertNotNull(first.firstOrNull { it.isPresent && it.canServe(SipralAudioRole.MICROPHONE) })
            audio.select(SipralAudioRole.MICROPHONE, microphone)
            assertEquals(microphone.id, audio.selection(SipralAudioRole.MICROPHONE).selected)
            audio.select(SipralAudioRole.MICROPHONE, null as SipralAudioDeviceInfo?)
            assertNull(audio.selection(SipralAudioRole.MICROPHONE).selected)
        }
        return "${first.size} devices listed under ids a refresh kept, every role refused by status"
    }
}

private fun gainAndMuteSurviveAChangeOfDevice(): String {
    deviceClient().use { client ->
        val audio = assertNotNull(client.audio)
        assertEquals(1.0, audio.gain(SipralAudioDirection.INPUT))
        audio.setGain(SipralAudioDirection.INPUT, 0.5)
        audio.setGain(SipralAudioDirection.OUTPUT, 2.0)
        audio.setMuted(SipralAudioDirection.OUTPUT, true)
        val speaker = assertNotNull(audio.refresh().firstOrNull { it.isPresent && it.canServe(SipralAudioRole.SPEAKER) })
        audio.select(SipralAudioRole.SPEAKER, speaker)
        assertEquals(0.5, audio.gain(SipralAudioDirection.INPUT))
        assertEquals(2.0, audio.gain(SipralAudioDirection.OUTPUT))
        assertTrue(audio.isMuted(SipralAudioDirection.OUTPUT))
        assertFalse(audio.isMuted(SipralAudioDirection.INPUT))
        assertEquals(0.0, audio.level(SipralAudioDirection.OUTPUT), "a closed device has a level")
    }
    return "gain and mute kept across a change of device"
}

private suspend fun activationRingAndTheEnginesOwnChoice(): String {
    openingClient(SipralAudioActivation.MANUAL).use { client ->
        val audio = assertNotNull(client.audio)
        audio.setMuted(SipralAudioDirection.OUTPUT, true)
        assertFalse(audio.status().isActive)
        audio.activate()
        val open = audio.status()
        assertTrue(open.isActive)
        assertNotEquals(0, open.speakerRateHz)
        val devices = audio.refresh()
        val speaker = assertNotNull(
            quietDevice(devices, SipralAudioRole.SPEAKER)
                ?: devices.firstOrNull { it.isPresent && it.canServe(SipralAudioRole.SPEAKER) },
        )
        val (_, selected) = client.events.awaitNext(
            timeoutMs = 10_000,
            matches = { audioOf(it)?.changeKind == SipralAudioChange.SELECTED },
        ) { audio.select(SipralAudioRole.SPEAKER, speaker) }
        val change = assertNotNull(audioOf(selected))
        assertEquals(SipralAudioOrigin.ENGINE, change.originKind)
        assertEquals(SipralAudioRole.SPEAKER, change.roleKind)
        assertEquals(speaker.id, change.device)
        assertEquals(Sipral.HANDLE_NONE, selected.call)
        audio.deactivate()
        assertFalse(audio.status().isActive)
    }
    openingClient(SipralAudioActivation.AUTOMATIC).use { client ->
        val audio = assertNotNull(client.audio)
        audio.setMuted(SipralAudioDirection.OUTPUT, true)
        audio.ring(ShortArray(800), 8_000)
        assertTrue(until(3_000) { audio.status().isActive }, "the ring opened nothing")
        audio.stopRinging()
        assertTrue(until(3_000) { !audio.status().isActive }, "the devices stayed open with nothing to play")
    }
    return "manual activation, the ring under automatic activation and the engine's own choice held"
}

private suspend fun aCallInDeviceModeIsPumpedByTheEngine(): String {
    openingClient(SipralAudioActivation.AUTOMATIC).use { bob ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { alice ->
            val audio = assertNotNull(bob.audio)
            audio.setGain(SipralAudioDirection.OUTPUT, 0.05)
            val aliceAccount = alice.addAccount(aor = "sip:alice@sipral.invalid", registrarAddress = bob.bindAddress)
            bob.addAccount(aor = "sip:bob@sipral.invalid", registrarAddress = alice.bindAddress)
            val (placed, incoming) = bob.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 10_000) {
                alice.placeCall(aliceAccount, "sip:bob@${bob.bindAddress}")
            }
            placed.use {
                bob.answerCall(incoming).use { taken ->
                    placed.waitConfirmed(10_000)
                    assertTrue(until(5_000) { placed.media != null && taken.media != null })
                    val aliceMedia = assertNotNull(placed.media)
                    assertFalse(assertNotNull(taken.media).pumpsFrames)
                    val tone = ShortArray(aliceMedia.frameSamples * 100) { if (it % 16 < 8) 6_000 else -6_000 }
                    aliceMedia.sendAudio(tone)
                    assertTrue(until(5_000) { audio.status().isActive }, "the call's media opened no device")
                    assertTrue(
                        until(3_000) { audio.level(SipralAudioDirection.OUTPUT) > 0.0 },
                        "the far end's audio never reached the loudspeaker",
                    )
                    assertTrue(
                        until(3_000) { aliceMedia.statistics().packetsReceived > 20 },
                        "the engine's packets never reached the far end",
                    )
                }
            }
        }
    }
    return "a call in device mode was pumped by the engine both ways"
}

/** A call's own gain and mute: held by the engine from the moment its media
 * starts -- the devices left closed under manual activation -- to the
 * moment it ends, beside the client's own, and refused outside that and in
 * application mode. */
private suspend fun aCallsOwnGainAndMuteLastFromItsMediaToItsEnd(): String {
    deviceClient().use { alice ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { bob ->
            val audio = assertNotNull(alice.audio)
            val account = alice.addAccount(aor = "sip:alice@sipral.invalid", registrarAddress = bob.bindAddress)
            bob.addAccount(aor = "sip:bob@sipral.invalid", registrarAddress = alice.bindAddress)
            val (placed, incoming) = bob.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 10_000) {
                alice.placeCall(account, "sip:bob@${bob.bindAddress}")
            }
            placed.use {
                val early = assertFailsWith<SipralException> { audio.setGain(placed, SipralAudioDirection.OUTPUT, 0.5) }
                assertEquals(SipralStatus.WRONG_STATE, early.status, "before its media starts")
                bob.answerCall(incoming).use { answered ->
                    placed.waitConfirmed(10_000)
                    assertTrue(
                        until(5_000) { runCatching { audio.setGain(placed, SipralAudioDirection.OUTPUT, 0.5) }.isSuccess },
                        "the engine never took the call's media",
                    )
                    audio.setMuted(placed, SipralAudioDirection.INPUT, true)
                    assertEquals(0.5, audio.gain(placed, SipralAudioDirection.OUTPUT))
                    assertEquals(1.0, audio.gain(placed, SipralAudioDirection.INPUT))
                    assertTrue(audio.isMuted(placed, SipralAudioDirection.INPUT))
                    assertFalse(audio.isMuted(placed, SipralAudioDirection.OUTPUT))
                    assertFalse(audio.isMuted(SipralAudioDirection.INPUT), "the client's own mute is another")
                    assertEquals(0.0, audio.level(placed, SipralAudioDirection.OUTPUT), "the devices are closed")
                    val application = assertFailsWith<SipralException> {
                        Sipral.audioCallSetMuted(bob.handle, answered.handle, SipralAudioDirection.INPUT.value.toLong(), 1)
                    }
                    assertEquals(SipralStatus.WRONG_STATE, application.status, "in application mode")
                    placed.hangup()
                    assertTrue(
                        until(5_000) {
                            (runCatching { audio.gain(placed, SipralAudioDirection.OUTPUT) }.exceptionOrNull() as? SipralException)
                                ?.status == SipralStatus.WRONG_STATE
                        },
                        "a call that ended still has controls",
                    )
                }
            }
        }
    }
    return "a call's own gain and mute last from its media to its end"
}

/** ABI 1.1: the platform's echo cancellation switched on a running client is
 * refused in application mode, where the library opens no device. */
private fun theEchoCancellationSwitchIsRefusedInApplicationMode(): String {
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { pumped ->
        val refused = assertFailsWith<SipralException> {
            Sipral.audioSetSystemEchoCancellation(pumped.handle, SipralToggle.OFF.value.toLong())
        }
        assertEquals(SipralStatus.WRONG_STATE, refused.status)
        assertTrue(pumped.settings().systemEchoCancellation)
    }
    return "the echo cancellation switch refused in application mode"
}

/** The switch in device mode: with the devices closed it opens nothing and
 * the settings read it back. */
private fun theEchoCancellationSwitchIsReadBack(): String {
    deviceClient().use { client ->
        val audio = assertNotNull(client.audio)
        audio.setSystemEchoCancellation(false)
        assertFalse(client.settings().systemEchoCancellation)
        assertFalse(audio.status().isActive, "the switch opened the devices")
        audio.setSystemEchoCancellation(true)
        assertTrue(client.settings().systemEchoCancellation)
    }
    return "the echo cancellation switch read back with the devices closed"
}

/** The switch on open devices reopens them where they were, with the gain
 * and the mute, and the status says what the platform did. */
private fun theEchoCancellationSwitchReopensTheOpenDevices(): String {
    openingClient(SipralAudioActivation.MANUAL).use { client ->
        val audio = assertNotNull(client.audio)
        audio.setMuted(SipralAudioDirection.OUTPUT, true)
        audio.setGain(SipralAudioDirection.INPUT, 0.5)
        audio.activate()
        val before = audio.status()
        audio.setSystemEchoCancellation(false)
        val off = audio.status()
        assertTrue(off.isActive)
        assertFalse(off.systemEchoCancellation, "the platform's processing is still behind the microphone")
        assertEquals(before.speaker, off.speaker)
        assertEquals(before.microphone, off.microphone)
        assertTrue(audio.isMuted(SipralAudioDirection.OUTPUT))
        assertEquals(0.5, audio.gain(SipralAudioDirection.INPUT))
        audio.setSystemEchoCancellation(true)
        assertTrue(client.settings().systemEchoCancellation)
        audio.deactivate()
    }
    return "the echo cancellation switched on open devices, kept where they were"
}

/** The Android context goes to the shim, which checks it is one: on a JVM
 * that is not Android there is no `android.content.Context` at all, and an
 * object is refused rather than kept. */
private fun anAndroidContextIsCheckedByTheShim(): String {
    val refused = assertFailsWith<IllegalArgumentException> { SipralAndroidAudio.attach(Any()) }
    assertEquals("java.lang.Object is not an android.content.Context", refused.message)
    return "an object that is no Android context refused by the shim"
}

/** Everything above, for IdiomaticCheck.kt's main: the settings wherever
 * there is an engine, what opens the devices only when asked. */
internal suspend fun audioChecks(): String {
    val said = mutableListOf(
        thePlatformDefault(),
        anAndroidContextIsCheckedByTheShim(),
        theQuietDeviceIsChosenWhereTheMachineHasIt(),
        theEchoCancellationSwitchIsRefusedInApplicationMode(),
    )
    if (!hasEngine) {
        return (said + "no audio engine in this build for this platform").joinToString(", ")
    }
    said += theListKeepsItsIdsAndEachRoleIsRefusedByStatus()
    said += gainAndMuteSurviveAChangeOfDevice()
    said += aCallsOwnGainAndMuteLastFromItsMediaToItsEnd()
    said += theEchoCancellationSwitchIsReadBack()
    if (opensDevices) {
        said += activationRingAndTheEnginesOwnChoice()
        said += theEchoCancellationSwitchReopensTheOpenDevices()
        said += aCallInDeviceModeIsPumpedByTheEngine()
    } else {
        said += "the devices left closed (SIPRAL_AUDIO_DEVICES=1 opens them)"
    }
    return said.joinToString(", ")
}
