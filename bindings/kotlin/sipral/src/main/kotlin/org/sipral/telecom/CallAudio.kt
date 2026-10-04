// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// One call's audio device, kept alive through what a phone does to it in
// the middle of a call: the platform holding the call for a cellular one,
// the platform taking the call's audio resources for another calling
// application, the route moving to a headset or a car, and the audio
// server dying under an open stream. The device itself is behind
// AudioDevice, so that all of this runs on a plain JVM against a fake; the
// Android adapter in bindings/kotlin/android/telecom implements it over
// AudioRecord and AudioTrack.

package org.sipral.telecom

import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.sipral.idiomatic.SipralMedia

/** One place audio can go, as the platform offers it. */
data class AudioRoute(val id: String, val name: String, val kind: Kind) {
    enum class Kind { EARPIECE, SPEAKER, WIRED_HEADSET, BLUETOOTH, STREAMING, OTHER }
}

/**
 * A call's microphone and speaker, opened together. [open] opens both or
 * throws; what it returns is used by two threads at once, one reading and
 * one writing, stopped by a third while they may be inside, and closed once
 * neither is.
 */
fun interface AudioDevice {
    fun open(sampleRate: Int, frameSamples: Int): AudioStreams
}

/** The two open streams [AudioDevice.open] returned. */
interface AudioStreams : AutoCloseable {
    /** Whether there is a microphone to [read]: false when the user has not
     * granted it, and the far end then hears silence. */
    val capturing: Boolean

    /** Block for up to [buffer]'s length of samples. The count read, or a
     * negative platform error code (on Android, `AudioRecord.ERROR_DEAD_OBJECT`
     * and its siblings), after which the streams are not used again. */
    fun read(buffer: ShortArray): Int

    /** Write one frame. The count written, or a negative platform error
     * code, as [read]. */
    fun write(frame: ShortArray): Int

    /** Stop both at once, from any thread, while another may be blocked in
     * [read] or [write]: that call returns, and the microphone and speaker
     * are free for whoever the platform is giving them to. [close] follows,
     * once neither call is inside. */
    fun interrupt()
}

/** Why a call's device has been let go while the call goes on. */
enum class AudioPause {
    /** The call is on hold -- asked for by the platform (a cellular call
     * answered over it), by a Bluetooth or car control, or by the
     * application's own screen. */
    HELD,

    /** The platform took the call's audio resources for another calling
     * application without holding the call (on Android, the
     * `ConnectionService` lost the call focus). */
    CALL_FOCUS_LOST,
}

/** Which half of the device reported a failure. */
enum class AudioDirection { OPEN, CAPTURE, PLAYBACK }

/** Where a call's audio stands. */
enum class AudioState {
    /** Not started yet. */
    IDLE,
    RUNNING,

    /** Let go on purpose, for the reasons in [CallAudio.pauses]. */
    PAUSED,

    /** The device failed, and is being opened again. */
    RECOVERING,

    /** The call is over, and so is its audio. */
    STOPPED,
}

/** One thing that happened to a call's audio, in the order it happened. */
sealed class AudioTransition {
    /** The device was opened for the first time and is carrying the call. */
    data object Started : AudioTransition()

    /** The device was let go; [reasons] is every reason it is still let go
     * for, and the transition is reported each time that set grows or
     * shrinks without emptying. */
    data class Paused(val reasons: Set<AudioPause>) : AudioTransition()

    /** The last reason was lifted and the device is open again. */
    data object Resumed : AudioTransition()

    /** The platform moved the call's audio. Reported, never acted on: the
     * platform routes a voice-communication stream wherever the call went. */
    data class RouteChanged(val route: AudioRoute) : AudioTransition()

    /** The platform muted or unmuted the call -- a headset's button, a car's
     * control. While muted the far end is sent silence. */
    data class MuteChanged(val muted: Boolean) : AudioTransition()

    /** The device failed: [code] is the platform's own error code (zero when
     * opening threw, and [detail] says why). Reported once per failure; the
     * device is opened again until it opens. */
    data class DeviceFailed(val direction: AudioDirection, val code: Int, val detail: String?) : AudioTransition()

    /** The device opened again after [DeviceFailed], at the [attempts]th try. */
    data class DeviceRestored(val attempts: Int) : AudioTransition()

    /** The call is over and the device closed for good. */
    data object Stopped : AudioTransition()
}

/**
 * One call's audio between an [AudioDevice] and the call's media: the
 * microphone read a frame at a time into [send], and every decoded frame
 * from [frames] written to the speaker.
 *
 * What keeps it alive is that the device is never assumed to stay open.
 * [pause] lets it go -- stopped before it returns, so that whoever the
 * platform gave the microphone to has it at once, and released on a thread
 * of its own once no read or write is inside it, so that the caller (the
 * framework's main thread, on Android) never waits on a device -- and
 * lifting the last reason opens a new one. A negative code from either
 * stream, or an exception opening it, lets it go the same way and opens a
 * new one after [retryDelays], the last delay repeating for as long as the
 * call lasts. The far end is sent silence meanwhile: the
 * media keeps its own frame clock and sends silence when nothing is queued,
 * so a gap in the device is a gap in the sound and not in the stream.
 * Frames that arrive while the device is let go are dropped, so that the
 * speaker picks up at the live edge of the call rather than behind it.
 *
 * Every change is a [transitions] item and a [state] value. [transitions]
 * replays the last 64, so a reader that starts late still sees how the call
 * got where it is.
 */
class CallAudio(
    /** The id [TelecomBridge] knows the call by, or any label. */
    val callId: String,
    private val device: AudioDevice,
    private val sampleRate: Int,
    private val frameSamples: Int,
    private val frames: Flow<ShortArray>,
    private val send: (ShortArray) -> Unit,
    private val scope: CoroutineScope,
    private val retryDelays: List<Long> = DEFAULT_RETRY_DELAYS,
) : AutoCloseable {
    /** Over one call's [SipralMedia]. */
    constructor(callId: String, device: AudioDevice, media: SipralMedia, scope: CoroutineScope) :
        this(callId, device, media.sampleRate, media.frameSamples, media.frames, media::sendAudio, scope)

    init {
        require(retryDelays.isNotEmpty()) { "at least one retry delay is needed" }
    }

    private val lock = ReentrantLock()
    private val changed = lock.newCondition()
    private val captureUse = Any()
    private val playbackUse = Any()

    @Volatile
    private var current: AudioStreams? = null
    private val pauseSet = LinkedHashSet<AudioPause>()
    private var started = false
    private var stopped = false
    private var everOpened = false
    private var failing = false
    private var attempts = 0
    private var retryAt = 0L
    private var openedAt = 0L
    private var shortLivedInARow = 0
    private var lastRoute: AudioRoute? = null

    @Volatile
    private var muted = false

    private var driver: Thread? = null
    private var playback: Job? = null

    private val transitionFlow = MutableSharedFlow<AudioTransition>(
        replay = 64,
        extraBufferCapacity = 64,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    private val stateFlow = MutableStateFlow(AudioState.IDLE)
    private val pausesFlow = MutableStateFlow<Set<AudioPause>>(emptySet())

    /** Every transition, in order; the last 64 replayed to a new reader. */
    val transitions: SharedFlow<AudioTransition> = transitionFlow

    val state: StateFlow<AudioState> = stateFlow

    /** Every reason the device is let go for; empty while it runs. */
    val pauses: StateFlow<Set<AudioPause>> = pausesFlow

    /** Open the device (unless something already paused it) and start
     * moving frames. Once only; a second call does nothing. */
    fun start() {
        lock.withLock {
            if (started || stopped) {
                return
            }
            started = true
            if (pauseSet.isNotEmpty()) {
                stateFlow.value = AudioState.PAUSED
            }
        }
        // Undispatched, so that the subscription exists before this returns
        // and a frame decoded right after it is played, not lost.
        playback = scope.launch(Dispatchers.IO, start = CoroutineStart.UNDISPATCHED) {
            frames.collect { play(it) }
        }
        driver = Thread(::drive, "sipral-call-audio").apply {
            isDaemon = true
            start()
        }
    }

    /** Let the device go for [reason]; it stays let go until every reason
     * given is [resume]d. Returns once the device is closed. */
    fun pause(reason: AudioPause) {
        lock.withLock {
            if (stopped || !pauseSet.add(reason)) {
                return
            }
            pausesFlow.value = pauseSet.toSet()
            report(AudioTransition.Paused(pauseSet.toSet()))
            closeCurrent()
            if (started) {
                stateFlow.value = AudioState.PAUSED
            }
            changed.signalAll()
        }
    }

    /** Lift [reason]. The device opens again once no reason is left. */
    fun resume(reason: AudioPause) {
        lock.withLock {
            if (stopped || !pauseSet.remove(reason)) {
                return
            }
            pausesFlow.value = pauseSet.toSet()
            if (pauseSet.isNotEmpty()) {
                report(AudioTransition.Paused(pauseSet.toSet()))
            } else {
                retryAt = 0
            }
            changed.signalAll()
        }
    }

    /** The platform moved the call's audio to [route]. Reported once per
     * change. */
    fun routeChanged(route: AudioRoute) {
        lock.withLock {
            if (stopped || route == lastRoute) {
                return
            }
            lastRoute = route
            report(AudioTransition.RouteChanged(route))
        }
    }

    /** The platform muted or unmuted the call. The microphone is still read
     * while muted, and silence sent in its place. */
    fun setMuted(muted: Boolean) {
        lock.withLock {
            if (stopped || this.muted == muted) {
                return
            }
            this.muted = muted
            report(AudioTransition.MuteChanged(muted))
        }
    }

    /**
     * Follow call [id] on [bridge]: let the device go while it is held, take
     * it back when it is active again, and stop for good when it ends.
     * Started undispatched, and the call's state as it is now applied before
     * this returns; [start] is called once the call is not held, so a call
     * placed on hold before its audio started never opens the microphone.
     */
    fun follow(bridge: TelecomBridge, id: String): Job {
        apply(bridge.calls.value.firstOrNull { it.id == id })
        return scope.launch(start = CoroutineStart.UNDISPATCHED) {
            bridge.calls.collect { calls -> apply(calls.firstOrNull { it.id == id }) }
        }
    }

    private fun apply(call: TelecomCall?) {
        when {
            call == null || call.phase == TelecomPhase.ENDED -> close()
            call.phase == TelecomPhase.HELD -> pause(AudioPause.HELD)
            else -> {
                resume(AudioPause.HELD)
                start()
            }
        }
    }

    /** Stop for good: the device closed, no frame moved any more. */
    override fun close() {
        val thread: Thread?
        lock.withLock {
            if (stopped) {
                return
            }
            stopped = true
            closeCurrent()
            stateFlow.value = AudioState.STOPPED
            report(AudioTransition.Stopped)
            changed.signalAll()
            thread = driver
        }
        playback?.cancel()
        if (thread != null && thread !== Thread.currentThread()) {
            thread.join(2000)
        }
    }

    // -- the device ------------------------------------------------------------

    private fun report(transition: AudioTransition) {
        transitionFlow.tryEmit(transition)
    }

    /** Let the streams in use go: stopped here, so that a read or write
     * blocked in them returns and the device is someone else's at once, and
     * closed on a thread of their own once neither direction is inside.
     * Called with [lock] held, which is why nothing here waits. */
    private fun closeCurrent() {
        val streams = current ?: return
        current = null
        release(streams)
    }

    private fun release(streams: AudioStreams) {
        try {
            streams.interrupt()
        } catch (_: Exception) {
            // Stopping a device that failed can fail too; closing it below
            // is what matters.
        }
        Thread({
            synchronized(captureUse) {
                synchronized(playbackUse) {
                    try {
                        streams.close()
                    } catch (_: Exception) {
                        // As above: it is let go either way.
                    }
                }
            }
        }, "sipral-call-audio-release").apply {
            isDaemon = true
            start()
        }
    }

    /** The streams in [streams] failed. Closed and scheduled to be opened
     * again, unless something else already let them go. */
    private fun failed(streams: AudioStreams, direction: AudioDirection, code: Int) {
        lock.withLock {
            if (current !== streams) {
                return
            }
            closeCurrent()
            noteFailure(direction, code, null)
            changed.signalAll()
        }
    }

    /** Called with [lock] held. A device that fails again within
     * [SHORT_LIVED_MILLIS] of opening did not really come back: each such
     * failure in a row waits one step longer before the next open, so a
     * device that dies as soon as it starts is retried at the slowest delay
     * rather than in a tight loop. */
    private fun noteFailure(direction: AudioDirection, code: Int, detail: String?) {
        val now = System.currentTimeMillis()
        if (!failing) {
            failing = true
            attempts = 0
            shortLivedInARow = if (openedAt != 0L && now - openedAt < SHORT_LIVED_MILLIS) shortLivedInARow + 1 else 0
            stateFlow.value = AudioState.RECOVERING
            report(AudioTransition.DeviceFailed(direction, code, detail))
        }
        val delay = retryDelays[minOf(attempts + shortLivedInARow, retryDelays.size - 1)]
        retryAt = now + delay
    }

    /** Open the device, outside [lock]: opening can take as long as the
     * platform's audio server takes to answer, and nothing that pauses or
     * stops the call's audio waits for that. What it opened is kept only if
     * the device is still wanted once it has. */
    private fun open() {
        val opened = try {
            Result.success(device.open(sampleRate, frameSamples))
        } catch (refused: Exception) {
            Result.failure(refused)
        }
        lock.withLock {
            attempts++
            val streams = opened.getOrElse { refused ->
                noteFailure(AudioDirection.OPEN, 0, refused.message ?: refused.javaClass.simpleName)
                return
            }
            if (stopped || pauseSet.isNotEmpty()) {
                release(streams)
                return
            }
            current = streams
            stateFlow.value = AudioState.RUNNING
            when {
                failing -> report(AudioTransition.DeviceRestored(attempts))
                !everOpened -> report(AudioTransition.Started)
                else -> report(AudioTransition.Resumed)
            }
            failing = false
            everOpened = true
            openedAt = System.currentTimeMillis()
        }
    }

    /** What the driving thread does next. */
    private sealed class Next {
        data class Read(val streams: AudioStreams) : Next()
        data object Open : Next()
        data object Stop : Next()
    }

    private fun next(): Next {
        lock.withLock {
            while (true) {
                if (stopped) {
                    return Next.Stop
                }
                val open = current
                when {
                    pauseSet.isNotEmpty() -> changed.await()
                    open != null && open.capturing -> return Next.Read(open)
                    // Open, with no microphone to read: nothing to do until
                    // something changes.
                    open != null -> changed.await()
                    else -> {
                        val wait = retryAt - System.currentTimeMillis()
                        if (wait > 0) {
                            changed.await(wait, TimeUnit.MILLISECONDS)
                        } else {
                            return Next.Open
                        }
                    }
                }
            }
        }
    }

    private fun drive() {
        val buffer = ShortArray(frameSamples)
        val silence = ShortArray(frameSamples)
        val frameMillis = maxOf(1L, frameSamples * 1000L / maxOf(sampleRate, 1))
        while (true) {
            val streams = when (val next = next()) {
                Next.Stop -> return
                Next.Open -> {
                    open()
                    continue
                }
                is Next.Read -> next.streams
            }
            val read = synchronized(captureUse) {
                if (current !== streams) null else streams.read(buffer)
            } ?: continue
            when {
                read > 0 -> send(if (muted) silence.copyOf(read) else buffer.copyOf(read))
                read < 0 -> failed(streams, AudioDirection.CAPTURE, read)
                // A read that blocks is what paces this thread; one that
                // answers nothing at once would otherwise spin it.
                else -> Thread.sleep(frameMillis)
            }
        }
    }

    private fun play(frame: ShortArray) {
        val streams = current ?: return
        val wrote = synchronized(playbackUse) {
            if (current !== streams) null else streams.write(frame)
        } ?: return
        if (wrote < 0) {
            failed(streams, AudioDirection.PLAYBACK, wrote)
        }
    }

    companion object {
        /** Opened again at once, then after 100 ms, 250 ms, 500 ms, one
         * second, and every two seconds after that. */
        val DEFAULT_RETRY_DELAYS: List<Long> = listOf(0L, 100L, 250L, 500L, 1000L, 2000L)

        private const val SHORT_LIVED_MILLIS = 2000L
    }
}
