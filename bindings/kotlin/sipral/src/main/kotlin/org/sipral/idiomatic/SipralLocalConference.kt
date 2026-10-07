// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.idiomatic

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import org.sipral.Sipral
import org.sipral.SipralAudioDirection
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralLocalConferenceConfig
import org.sipral.SipralLocalConferenceEvent
import org.sipral.SipralLocalConferenceInfo
import org.sipral.SipralRecordingFormat
import org.sipral.SipralRecordingOptions
import org.sipral.SipralToggle

/** One member of a [SipralLocalConference] from
 * `sipral_local_conference_member_at`: its handle (a call's, or
 * [SipralLocalConference.handle] for this end), whether it is talking, its
 * two mutes and two gains in engine steps (256 is unity). */
data class SipralLocalMember(
    val member: Long,
    val talking: Boolean,
    val mutedInput: Boolean,
    val mutedOutput: Boolean,
    val gainInput: Long,
    val gainOutput: Long,
)

/**
 * A local conference: any number of this client's calls, each on its own
 * codec and rate, mixed so every member hears everyone but itself,
 * including this end unless made without (`docs/08-ffi.md`).
 *
 * An added call stops carrying its own frames (its [SipralMedia] still
 * reads the socket and sends RTCP); the conference carries them. In
 * [SipralAudioMode.Device] the engine does, packets leaving from each
 * member's socket; in [SipralAudioMode.Application] this class's thread
 * ticks every 20 ms, with [sendAudio] as this end's microphone and
 * [frames] what it hears. Changes arrive as
 * `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED` ([localConferenceOf]).
 *
 * `maxMembers` counts this end; `sampleRate` (8000, 16000, 32000 or 48000)
 * is this end's frame rate in application mode. A rate the conference
 * cannot mix throws `SIPRAL_STATUS_CONFERENCE_REFUSED`.
 */
class SipralLocalConference(
    private val client: SipralClient,
    maxMembers: Long = 16,
    local: Boolean = true,
    sampleRate: Long = 16_000,
) : AutoCloseable {
    /** The conference's handle, which is also this end's name as a member. */
    val handle: Long = retryBusy {
        Sipral.localConferenceCreate(
            client.handle,
            SipralLocalConferenceConfig(
                maxMembers = maxMembers,
                local = if (local) 0L else SipralToggle.OFF.value.toLong(),
                sampleRate = sampleRate,
            ),
        )
    }

    private val standing = info()

    /** Whether this end takes part. */
    val local: Boolean = standing.local != 0L

    /** The rate of this end's frames, in hertz. */
    val sampleRate: Int = standing.sampleRate.toInt()

    /** Samples in one of this end's frames: twenty milliseconds. */
    val frameSamples: Int = standing.frameSamples.toInt()

    private val members = ConcurrentHashMap<Long, SipralCall>()
    private val outgoing = ConcurrentLinkedQueue<ShortArray>()
    private var pending = ShortArray(0)
    private val closed = AtomicBoolean(false)
    private val frameChannel = Channel<ShortArray>(Channel.UNLIMITED)

    /** What this end hears, one frame of 16-bit mono PCM each, in
     * application mode. */
    val frames: Flow<ShortArray> = frameChannel.receiveAsFlow()

    private val thread: Thread? =
        if (client.audioMode is SipralAudioMode.Device) {
            null
        } else {
            Thread(::run, "sipral-conference").apply {
                isDaemon = true
                start()
            }
        }

    /** `sipral_local_conference_add`: [call] takes part from the next tick,
     * at its own codec's rate. A full conference, a call already in one, or a
     * codec it cannot mix throws with `SIPRAL_STATUS_CONFERENCE_REFUSED`. */
    fun add(call: SipralCall) {
        // the call's own thread stops before the conference starts, so no frame
        // is taken twice; a refused call keeps what it had
        val was = call.media?.carriedByConference ?: false
        call.media?.carriedByConference = true
        try {
            retryBusy { Sipral.localConferenceAdd(handle, call.handle) }
        } catch (refused: SipralException) {
            call.media?.carriedByConference = was
            throw refused
        }
        members[call.handle] = call
    }

    /** `sipral_local_conference_remove`: [call] carries its own frames again
     * from the next tick. */
    fun remove(call: SipralCall) {
        retryBusy { Sipral.localConferenceRemove(handle, call.handle) }
        members.remove(call.handle)
        call.media?.carriedByConference = false
    }

    /** Mute or unmute one way of a member -- null for this end: `INPUT` is
     * what it says, `OUTPUT` what it hears. */
    fun setMuted(member: SipralCall?, direction: SipralAudioDirection, muted: Boolean = true) {
        val named = member?.handle ?: handle
        retryBusy {
            Sipral.localConferenceSetMuted(handle, named, direction.value.toLong(), if (muted) 1L else 0L)
        }
    }

    /** The level of one way of a member, in the audio engine's steps: 256 is
     * unity, 1024 four times. */
    fun setGain(member: SipralCall?, direction: SipralAudioDirection, gain: Long) {
        val named = member?.handle ?: handle
        retryBusy { Sipral.localConferenceSetGain(handle, named, direction.value.toLong(), gain) }
    }

    /** `sipral_local_conference_info`. */
    fun info(): SipralLocalConferenceInfo = retryBusy { Sipral.localConferenceInfo(handle) }

    /** Every member, this end first. */
    fun memberList(): List<SipralLocalMember> =
        (0L until info().members).map { index ->
            val member = retryBusy { Sipral.localConferenceMemberAt(handle, index) }
            SipralLocalMember(
                member.member,
                member.talking != 0L,
                member.mutedInput != 0L,
                member.mutedOutput != 0L,
                member.gainInput,
                member.gainOutput,
            )
        }

    /** Who was talking in the last tick, loudest first, by handle. */
    fun talkers(): List<Long> {
        val found = mutableListOf<Long>()
        for (index in 0L until info().talkers) {
            val talker = try {
                Sipral.localConferenceTalkerAt(handle, index)
            } catch (_: SipralException) {
                break
            }
            found.add(talker)
        }
        return found
    }

    /** `sipral_local_conference_record_start`: the whole mix, one channel, to
     * [path], at the conference's rate unless [sampleRate] names another. */
    fun record(path: String, format: SipralRecordingFormat = SipralRecordingFormat.WAV, sampleRate: Long = 0) {
        retryBusy {
            Sipral.localConferenceRecordStart(
                handle,
                path,
                SipralRecordingOptions(format = format.value.toLong(), sampleRate = sampleRate),
            )
        }
    }

    /** `sipral_local_conference_record_stop`: stop, and finish the file. */
    fun stopRecording() {
        retryBusy { Sipral.localConferenceRecordStop(handle) }
    }

    /** What this end says, 16-bit mono PCM at [sampleRate], in any length:
     * the conference's thread takes a frame of it every tick. */
    fun sendAudio(pcm: ShortArray) {
        outgoing.add(pcm.copyOf())
    }

    private fun nextChunk(): ShortArray {
        while (pending.size < frameSamples) {
            val more = outgoing.poll() ?: break
            pending += more
        }
        val chunk = ShortArray(frameSamples)
        val taken = minOf(frameSamples, pending.size)
        pending.copyInto(chunk, 0, 0, taken)
        pending = pending.copyOfRange(taken, pending.size)
        return chunk
    }

    private fun run() {
        val speaker = ShortArray(frameSamples)
        var next = System.nanoTime()
        while (!closed.get()) {
            val written = try {
                Sipral.localConferenceTick(handle, client.nowMs(), nextChunk(), speaker)
            } catch (_: SipralException) {
                return
            }
            if (local) {
                frameChannel.trySend(speaker.copyOfRange(0, written.toInt()))
            }
            sendWaiting()
            next += 20_000_000L
            val remaining = (next - System.nanoTime()) / 1_000_000
            if (remaining > 0) {
                try {
                    Thread.sleep(remaining)
                } catch (_: InterruptedException) {
                    return
                }
            } else {
                next = System.nanoTime()
            }
        }
    }

    /** Every packet the tick left, out from its member's own socket. */
    private fun sendWaiting() {
        val data = ByteArray(1500)
        val destination = ByteArray(128)
        val lens = LongArray(3)
        val call = LongArray(1)
        while (true) {
            val status = SipralMediaNative.localConferencePollTransmit(handle, data, destination, lens, call)
            val len = lens[0].toInt()
            if (status != 0 || len == 0) {
                return
            }
            val media = members[call[0]]?.media ?: continue
            val text = String(destination, 0, lens[1].toInt(), Charsets.UTF_8)
            media.sendTo(data.copyOfRange(0, len), parseAddress(text))
        }
    }

    /** `sipral_local_conference_destroy`: every call still in it carries its
     * own frames again, a recording running is finished, and the handle is
     * spent. */
    override fun close() {
        if (!closed.compareAndSet(false, true)) {
            return
        }
        thread?.join(5_000)
        for (call in members.values) {
            call.media?.carriedByConference = false
        }
        members.clear()
        frameChannel.close()
        retryBusy { Sipral.localConferenceDestroy(handle) }
    }
}

/**
 * A `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED` payload (which
 * conference, what changed, why a member left, who, and the current
 * state), or null for any other kind.
 */
fun localConferenceOf(event: SipralEvent): SipralLocalConferenceEvent? =
    if (event.kind == SipralEventKind.LOCAL_CONFERENCE_CHANGED.value.toLong()) event.payload.localConference else null
