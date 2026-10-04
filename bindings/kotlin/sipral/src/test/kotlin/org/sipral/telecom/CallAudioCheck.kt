// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// CallAudio against a fake device whose streams can be made to fail the way
// Android's do when the audio server dies (a negative code from read or
// write) or refuse to open at all: the device let go and taken back for a
// hold and for the platform's call focus, following a TelecomBridge call,
// reopened after every kind of failure, and every step reported. Run from
// TelecomCheck.kt's main.

package org.sipral.telecom

import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.receiveAsFlow
import org.sipral.SipralEventKind

/** Android's `AudioRecord.ERROR_DEAD_OBJECT`: the audio server went away. */
private const val DEAD_OBJECT = -6

private const val FRAME = 160

private class FakeDevice : AudioDevice {
    val opened = AtomicInteger()
    val closed = AtomicInteger()

    /** How many opens to refuse before the next one succeeds. */
    val refuseOpens = AtomicInteger()

    @Volatile var capturing = true

    /** Every stream opened reads as dead at once, as a device that dies the
     * moment it starts. */
    @Volatile var dieAtOnce = false

    @Volatile var live: FakeStreams? = null
    val written = LinkedBlockingQueue<ShortArray>()

    override fun open(sampleRate: Int, frameSamples: Int): AudioStreams {
        if (refuseOpens.getAndUpdate { if (it > 0) it - 1 else 0 } > 0) {
            throw IllegalStateException("the audio server is not back yet")
        }
        opened.incrementAndGet()
        return FakeStreams(this, capturing, opened.get()).also { live = it }
    }
}

private class FakeStreams(val device: FakeDevice, override val capturing: Boolean, val serial: Int) : AudioStreams {
    @Volatile var open = true

    @Volatile var failRead = 0

    @Volatile var failWrite = 0

    /** A read that does not come back until the streams are stopped: an
     * audio server that has stopped answering. */
    @Volatile var stall = false

    @Volatile var interrupted = false

    override fun read(buffer: ShortArray): Int {
        check(open) { "read from closed streams" }
        Thread.sleep(2)
        while (stall && !interrupted) {
            Thread.sleep(1)
        }
        if (interrupted) {
            return 0
        }
        val code = if (device.dieAtOnce) DEAD_OBJECT else failRead
        if (code != 0) {
            return code
        }
        buffer.fill(serial.toShort())
        return buffer.size
    }

    override fun write(frame: ShortArray): Int {
        check(open) { "write to closed streams" }
        if (interrupted) {
            return 0
        }
        val code = failWrite
        if (code != 0) {
            return code
        }
        device.written.add(frame)
        return frame.size
    }

    override fun interrupt() {
        interrupted = true
    }

    override fun close() {
        check(open) { "closed twice" }
        check(interrupted) { "closed without being stopped first" }
        open = false
        device.closed.incrementAndGet()
    }
}

private class AudioRig(retryDelays: List<Long> = listOf(0L, 5L, 10L)) {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val device = FakeDevice()
    val decoded = Channel<ShortArray>(Channel.UNLIMITED)
    val sent = LinkedBlockingQueue<ShortArray>()
    val audio = CallAudio("c1", device, 8000, FRAME, decoded.receiveAsFlow(), { sent.add(it) }, scope, retryDelays)

    fun waitFor(what: String, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 5000
        while (!condition()) {
            check(System.currentTimeMillis() < deadline) { "timed out waiting for $what; saw ${audio.transitions.replayCache}" }
            Thread.sleep(2)
        }
    }

    /** A frame the microphone produced after this call, from streams
     * number [serial]. */
    fun sentFrom(serial: Int) {
        sent.clear()
        val deadline = System.currentTimeMillis() + 5000
        while (true) {
            val frame = sent.poll(deadline - System.currentTimeMillis(), TimeUnit.MILLISECONDS)
                ?: error("no frame from streams $serial; saw ${audio.transitions.replayCache}")
            if (frame[0] == serial.toShort()) {
                return
            }
        }
    }

    /** A decoded frame reaches the speaker. */
    fun plays(value: Short) {
        device.written.clear()
        decoded.trySend(ShortArray(FRAME) { value })
        val frame = device.written.poll(5, TimeUnit.SECONDS) ?: error("frame $value never reached the speaker")
        assertEquals(value, frame[0])
    }

    fun transitions(): List<AudioTransition> = audio.transitions.replayCache

    fun close() {
        audio.close()
        scope.cancel()
    }
}

internal fun callAudioSequences(): String {
    var ran = 0

    // Started, held and taken back: the device closed for the length of the
    // hold, nothing played or sent from it meanwhile, frames decoded during
    // the hold dropped rather than played late, and each step reported.
    AudioRig().run {
        audio.start()
        waitFor("the device to open") { audio.state.value == AudioState.RUNNING }
        sentFrom(1)
        plays(11)
        audio.pause(AudioPause.HELD)
        assertEquals(AudioState.PAUSED, audio.state.value)
        assertTrue(device.live!!.interrupted, "the device was not stopped before the hold returned")
        waitFor("the device to be released") { device.closed.get() == 1 }
        assertFalse(device.live!!.open)
        decoded.trySend(ShortArray(FRAME) { 99 })
        Thread.sleep(50)
        assertTrue(device.written.none { it[0] == 99.toShort() }, "a frame reached a closed speaker")
        audio.resume(AudioPause.HELD)
        waitFor("the device to open again") { device.opened.get() == 2 && audio.state.value == AudioState.RUNNING }
        sentFrom(2)
        plays(12)
        assertTrue(device.written.none { it[0] == 99.toShort() }, "a frame decoded during the hold was played after it")
        assertEquals(
            listOf(AudioTransition.Started, AudioTransition.Paused(setOf(AudioPause.HELD)), AudioTransition.Resumed),
            transitions(),
        )
        close()
        assertEquals(AudioState.STOPPED, audio.state.value)
        assertEquals(AudioTransition.Stopped, transitions().last())
        waitFor("the device to be released") { device.closed.get() == 2 }
        ran++
    }

    // Two reasons at once -- held, then the call focus lost as well: the
    // device stays let go until both are lifted.
    AudioRig().run {
        audio.start()
        waitFor("the device to open") { audio.state.value == AudioState.RUNNING }
        audio.pause(AudioPause.HELD)
        audio.pause(AudioPause.CALL_FOCUS_LOST)
        audio.resume(AudioPause.HELD)
        Thread.sleep(50)
        assertEquals(1, device.opened.get(), "opened while the call focus was still someone else's")
        assertEquals(setOf(AudioPause.CALL_FOCUS_LOST), audio.pauses.value)
        audio.resume(AudioPause.CALL_FOCUS_LOST)
        waitFor("the device to open again") { device.opened.get() == 2 }
        assertEquals(
            listOf(
                AudioTransition.Started,
                AudioTransition.Paused(setOf(AudioPause.HELD)),
                AudioTransition.Paused(setOf(AudioPause.HELD, AudioPause.CALL_FOCUS_LOST)),
                AudioTransition.Paused(setOf(AudioPause.CALL_FOCUS_LOST)),
                AudioTransition.Resumed,
            ),
            transitions(),
        )
        close()
        ran++
    }

    // The audio server dies under the microphone: the dead streams closed,
    // the device opened again -- the second open refused, as it is while
    // the server restarts -- and the microphone read again, reported as one
    // failure and one recovery.
    AudioRig().run {
        audio.start()
        waitFor("the device to open") { audio.state.value == AudioState.RUNNING }
        device.refuseOpens.set(1)
        device.live!!.failRead = DEAD_OBJECT
        waitFor("the device to be opened again") { device.opened.get() == 2 && audio.state.value == AudioState.RUNNING }
        sentFrom(2)
        plays(21)
        val seen = transitions()
        assertEquals(AudioTransition.DeviceFailed(AudioDirection.CAPTURE, DEAD_OBJECT, null), seen[1])
        assertEquals(AudioTransition.DeviceRestored(2), seen[2], "the refused open was not counted: $seen")
        assertEquals(3, seen.size, "a failure reported more than once: $seen")
        waitFor("the dead streams to be released") { device.closed.get() == 1 }
        close()
        ran++
    }

    // The same under the speaker, on a device with no microphone granted:
    // the failure is noticed on the next frame written.
    AudioRig().run {
        device.capturing = false
        audio.start()
        waitFor("the device to open") { audio.state.value == AudioState.RUNNING }
        plays(31)
        device.live!!.failWrite = DEAD_OBJECT
        decoded.trySend(ShortArray(FRAME) { 32 })
        waitFor("the device to be opened again") { device.opened.get() == 2 && audio.state.value == AudioState.RUNNING }
        plays(33)
        assertEquals(AudioTransition.DeviceFailed(AudioDirection.PLAYBACK, DEAD_OBJECT, null), transitions()[1])
        assertTrue(sent.isEmpty(), "a device with no microphone sent something")
        close()
        ran++
    }

    // A device that will not open at first: retried until it does, once
    // reported.
    AudioRig().run {
        device.refuseOpens.set(3)
        audio.start()
        waitFor("the device to open") { audio.state.value == AudioState.RUNNING }
        val seen = transitions()
        assertEquals(AudioDirection.OPEN, (seen[0] as AudioTransition.DeviceFailed).direction)
        assertEquals("the audio server is not back yet", (seen[0] as AudioTransition.DeviceFailed).detail)
        assertEquals(AudioTransition.DeviceRestored(3), seen[1])
        close()
        ran++
    }

    // An audio server that stops answering, with the microphone's read stuck
    // inside it: a hold still lets the device go at once -- stopped, which
    // is what brings the read back -- and does not wait for the device,
    // since on Android the hold arrives on the main thread.
    AudioRig().run {
        audio.start()
        waitFor("the device to open") { audio.state.value == AudioState.RUNNING }
        val stuck = device.live!!
        stuck.stall = true
        Thread.sleep(20)
        val started = System.nanoTime()
        audio.pause(AudioPause.HELD)
        val took = (System.nanoTime() - started) / 1_000_000
        assertTrue(took < 100, "the hold waited $took ms on a stuck device")
        assertTrue(stuck.interrupted)
        waitFor("the stuck streams to be released") { device.closed.get() == 1 }
        close()
        ran++
    }

    // A device that dies as soon as it opens: each quick death waits a step
    // longer before the next open, rather than the device being rebuilt in
    // a tight loop.
    AudioRig(listOf(0L, 50L, 100L)).run {
        device.dieAtOnce = true
        audio.start()
        Thread.sleep(400)
        val opened = device.opened.get()
        assertTrue(opened > 1, "a device that died was not opened again")
        assertTrue(opened <= 12, "$opened opens in 400 ms: the device is being rebuilt in a loop")
        device.dieAtOnce = false
        waitFor("a device that stays up") { audio.state.value == AudioState.RUNNING }
        close()
        ran++
    }

    // Muted by the platform: the microphone still read, silence sent in its
    // place. A route change reported once, not again for the same route.
    AudioRig().run {
        audio.start()
        waitFor("the device to open") { audio.state.value == AudioState.RUNNING }
        audio.setMuted(true)
        sentFrom(0)
        audio.setMuted(false)
        sentFrom(1)
        val speaker = AudioRoute("2", "Speaker", AudioRoute.Kind.SPEAKER)
        audio.routeChanged(speaker)
        audio.routeChanged(speaker)
        audio.routeChanged(AudioRoute("1", "Earpiece", AudioRoute.Kind.EARPIECE))
        assertEquals(
            listOf(
                AudioTransition.Started,
                AudioTransition.MuteChanged(true),
                AudioTransition.MuteChanged(false),
                AudioTransition.RouteChanged(speaker),
                AudioTransition.RouteChanged(AudioRoute("1", "Earpiece", AudioRoute.Kind.EARPIECE)),
            ),
            transitions(),
        )
        close()
        ran++
    }

    // Following a TelecomBridge call: nothing opened while ringing is not
    // the rule (the call's media may carry early audio), but held means let
    // go, active means taken back, and the call ending closes it for good.
    AudioRig().run {
        val log = Log()
        val platform = FakePlatform(log)
        val sip = FakeSip(log)
        val bridge = TelecomBridge(platform, sip) { "c1" }.also { platform.bridge = it }
        bridge.onEvent(event(SipralEventKind.INCOMING_CALL, call = 920, account = ACCOUNT, message = invite("<sip:alice@example.invalid>")))
        platform.create("c1")
        bridge.answer("c1")
        bridge.onEvent(event(SipralEventKind.CALL_CONFIRMED, call = 920))
        val following = audio.follow(bridge, "c1")
        waitFor("the device to open") { audio.state.value == AudioState.RUNNING }
        bridge.hold("c1")
        waitFor("the hold to let the device go") { audio.state.value == AudioState.PAUSED }
        waitFor("the device to be released") { device.closed.get() == 1 }
        bridge.unhold("c1")
        waitFor("the device to be taken back") { device.opened.get() == 2 && audio.state.value == AudioState.RUNNING }
        bridge.onEvent(event(SipralEventKind.CALL_ENDED, call = 920))
        waitFor("the end of the call to stop the audio") { audio.state.value == AudioState.STOPPED }
        waitFor("the device to be released") { device.closed.get() == 2 }
        following.cancel()
        close()
        ran++
    }

    return "$ran call-audio sequences against a fake device (held and taken back, two reasons at once, " +
        "the audio server dying under the microphone and the speaker, a device that will not open, " +
        "a hold that does not wait on a stuck device, a device that dies as soon as it opens, " +
        "muted and rerouted, following a call through the bridge)"
}
