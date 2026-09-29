// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
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

private val hasEngine: Boolean get() = Sipral.capabilities().features and Sipral.FEATURE_AUDIO_DEVICE != 0L

private val opensDevices: Boolean get() = System.getenv("SIPRAL_AUDIO_DEVICES") == "1"

private fun deviceClient(activation: SipralAudioActivation = SipralAudioActivation.MANUAL) =
    SipralClient.open(audio = SipralAudioMode.Device(activation), bindHost = "127.0.0.1")

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
            val microphone = assertNotNull(first.firstOrNull { it.isPresent && it.canServe(SipralAudioRole.MICROPHONE) })
            val refused = assertFailsWith<SipralException> { audio.select(SipralAudioRole.MICROPHONE, microphone) }
            assertEquals(SipralStatus.NOT_SUPPORTED, refused.status, "one voice-processing unit, one microphone")
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
    deviceClient(SipralAudioActivation.MANUAL).use { client ->
        val audio = assertNotNull(client.audio)
        audio.setMuted(SipralAudioDirection.OUTPUT, true)
        assertFalse(audio.status().isActive)
        audio.activate()
        val open = audio.status()
        assertTrue(open.isActive)
        assertNotEquals(0, open.speakerRateHz)
        val speaker = assertNotNull(audio.refresh().firstOrNull { it.isPresent && it.canServe(SipralAudioRole.SPEAKER) })
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
    deviceClient(SipralAudioActivation.AUTOMATIC).use { client ->
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
    deviceClient(SipralAudioActivation.AUTOMATIC).use { bob ->
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

/** Everything above, for IdiomaticCheck.kt's main: the settings wherever
 * there is an engine, what opens the devices only when asked. */
internal suspend fun audioChecks(): String {
    val said = mutableListOf(thePlatformDefault())
    if (!hasEngine) {
        return (said + "no audio engine in this build for this platform").joinToString(", ")
    }
    said += theListKeepsItsIdsAndEachRoleIsRefusedByStatus()
    said += gainAndMuteSurviveAChangeOfDevice()
    if (opensDevices) {
        said += activationRingAndTheEnginesOwnChoice()
        said += aCallInDeviceModeIsPumpedByTheEngine()
    } else {
        said += "the devices left closed (SIPRAL_AUDIO_DEVICES=1 opens them)"
    }
    return said.joinToString(", ")
}
