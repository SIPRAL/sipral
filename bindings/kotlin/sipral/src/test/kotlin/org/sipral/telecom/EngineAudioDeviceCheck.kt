// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// EngineAudioDevice under two calls' CallAudio, against a counting stand-in
// for the engine's activation: the devices on with the first call, kept
// while either is running, off only when both let go, and an activation the
// engine refuses retried and reported like any device that would not open.
// Run from TelecomCheck.kt's main.

package org.sipral.telecom

import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.emptyFlow

private class Engine {
    val activations = AtomicInteger()
    val deactivations = AtomicInteger()
    val refuse = AtomicInteger()

    @Volatile var active = false

    fun activate() {
        if (refuse.getAndUpdate { if (it > 0) it - 1 else 0 } > 0) {
            throw IllegalStateException("DEVICE_UNUSABLE")
        }
        check(!active) { "activated twice" }
        active = true
        activations.incrementAndGet()
    }

    fun deactivate() {
        check(active) { "deactivated while off" }
        active = false
        deactivations.incrementAndGet()
    }
}

private fun waitFor(what: String, condition: () -> Boolean) {
    val deadline = System.currentTimeMillis() + 5000
    while (!condition()) {
        check(System.currentTimeMillis() < deadline) { "timed out waiting for $what" }
        Thread.sleep(2)
    }
}

internal fun engineAudioSequences(): String {
    var ran = 0

    // Two calls over one engine: one activation for both, a hold on either
    // keeps the devices for the other, and they go off with the last.
    run {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val engine = Engine()
        val device = EngineAudioDevice(engine::activate, engine::deactivate)
        val sent = AtomicInteger()
        val first = CallAudio("a", device, 8000, 160, emptyFlow(), { sent.incrementAndGet() }, scope)
        val second = CallAudio("b", device, 8000, 160, emptyFlow(), { sent.incrementAndGet() }, scope)
        first.start()
        waitFor("the first call's audio") { first.state.value == AudioState.RUNNING }
        second.start()
        waitFor("the second call's audio") { second.state.value == AudioState.RUNNING }
        assertEquals(1, engine.activations.get(), "one engine, turned on once")
        assertEquals(2, device.held)

        first.pause(AudioPause.HELD)
        assertEquals(0, engine.deactivations.get(), "the other call still has the devices")
        assertTrue(engine.active)
        second.pause(AudioPause.CALL_FOCUS_LOST)
        assertEquals(1, engine.deactivations.get(), "off once nobody holds them")
        assertTrue(!engine.active)

        second.resume(AudioPause.CALL_FOCUS_LOST)
        waitFor("the devices back") { second.state.value == AudioState.RUNNING }
        assertEquals(2, engine.activations.get())
        first.resume(AudioPause.HELD)
        waitFor("the first call back") { first.state.value == AudioState.RUNNING }
        assertEquals(2, engine.activations.get(), "already on for the second call")

        first.close()
        second.close()
        assertEquals(2, engine.deactivations.get())
        assertEquals(0, device.held)
        assertEquals(0, sent.get(), "the engine sends the microphone, not CallAudio")
        scope.cancel()
        ran++
    }

    // The engine refusing to open is a device that would not open: reported
    // once, retried, and reported restored.
    run {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val engine = Engine()
        engine.refuse.set(2)
        val device = EngineAudioDevice(engine::activate, engine::deactivate)
        val audio = CallAudio("a", device, 8000, 160, emptyFlow(), {}, scope, listOf(0L, 5L, 10L))
        audio.start()
        waitFor("the engine to open at the third try") { audio.state.value == AudioState.RUNNING }
        val seen = audio.transitions.replayCache
        assertEquals(AudioDirection.OPEN, (seen.first() as AudioTransition.DeviceFailed).direction)
        assertEquals("DEVICE_UNUSABLE", (seen.first() as AudioTransition.DeviceFailed).detail)
        assertEquals(AudioTransition.DeviceRestored(2), seen.last())
        assertEquals(1, engine.activations.get())
        audio.close()
        assertEquals(1, engine.deactivations.get())
        scope.cancel()
        ran++
    }

    return "$ran engine audio sequences"
}
