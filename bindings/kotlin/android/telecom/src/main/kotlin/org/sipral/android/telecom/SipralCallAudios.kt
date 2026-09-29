// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

package org.sipral.android.telecom

import android.content.Context
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.telecom.AudioState
import org.sipral.telecom.AudioTransition
import org.sipral.telecom.IdiomaticSipCalls
import org.sipral.telecom.TelecomBridge
import org.sipral.telecom.TelecomCall

/**
 * Every self-managed call's audio, run by the library: the Android half of
 * the device mode the C library runs on macOS, iOS and Windows, where the
 * devices belong to this helper rather than to the engine.
 *
 * Each call the [bridge] shows gets a [SipralCallAudio] -- `AudioRecord`
 * and `AudioTrack` in `VOICE_COMMUNICATION`, kept through the framework's
 * hold, the call focus, routes, mute and the audio server dying -- as soon
 * as its media has started, and loses it when the call is gone. What the
 * application sees is what a person does: every call's [states], and every
 * change as it happens on [transitions]. It writes no audio code of its
 * own.
 *
 * [events] is the client's own event flow, read for the moment a call's
 * media starts, since the list of calls does not change then.
 */
class SipralCallAudios(
    context: Context,
    private val bridge: TelecomBridge,
    private val sip: IdiomaticSipCalls,
    events: Flow<SipralEvent>,
    private val scope: CoroutineScope,
) : AutoCloseable {
    private val context: Context = context.applicationContext
    private val running = ConcurrentHashMap<String, SipralCallAudio>()
    private val watchers = ConcurrentHashMap<String, List<Job>>()
    private val statesFlow = MutableStateFlow<Map<String, AudioState>>(emptyMap())
    private val transitionsFlow = MutableSharedFlow<Pair<String, AudioTransition>>(
        extraBufferCapacity = 256,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    private val jobs: List<Job>

    /** Where each call's audio stands, by the id the bridge knows it by. */
    val states: StateFlow<Map<String, AudioState>> = statesFlow

    /** Every change to any call's audio, with the call's id, in order. */
    val transitions: SharedFlow<Pair<String, AudioTransition>> = transitionsFlow

    init {
        jobs = listOf(
            scope.launch { bridge.calls.collect { reconcile(it) } },
            scope.launch {
                events.collect { event ->
                    if (event.kind == SipralEventKind.MEDIA_STARTED.value.toLong()) {
                        reconcile(bridge.calls.value)
                    }
                }
            },
        )
    }

    /** The audio of the call the bridge knows as [id], once it has media. */
    fun audio(id: String): SipralCallAudio? = running[id]

    @Synchronized
    private fun reconcile(now: List<TelecomCall>) {
        for (call in now) {
            if (running.containsKey(call.id) || call.call == 0L) {
                continue
            }
            val media = sip.call(call.call)?.media ?: continue
            val started = SipralCallAudio(context, bridge, call.id, media, scope)
            running[call.id] = started
            watchers[call.id] = listOf(
                scope.launch { started.transitions.collect { transitionsFlow.emit(call.id to it) } },
                scope.launch { started.state.collect { statesFlow.value = statesFlow.value + (call.id to it) } },
            )
        }
        for (gone in running.keys - now.map { it.id }.toSet()) {
            running.remove(gone)?.close()
            watchers.remove(gone)?.forEach { it.cancel() }
            statesFlow.value = statesFlow.value - gone
        }
    }

    /** Let every call's device go and stop following the bridge. */
    @Synchronized
    override fun close() {
        jobs.forEach { it.cancel() }
        running.values.forEach { it.close() }
        running.clear()
        watchers.values.forEach { list -> list.forEach { it.cancel() } }
        watchers.clear()
        statesFlow.value = emptyMap()
    }
}
