// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The second telecom adapter: TelecomBridge's ports over Jetpack
// Core-Telecom (androidx.core:core-telecom), whose CallsManager drives the
// platform's transactional call API from Android 14 and a ConnectionService
// of its own below that (developer.android.com/develop/connectivity/telecom/voip-app/telecom).
// The bridge is the same one the self-managed ConnectionService adapter
// drives: the SIP side cannot tell the two apart.

package org.sipral.android.telecom

import android.content.Context
import android.telecom.DisconnectCause
import androidx.core.telecom.CallAttributesCompat
import androidx.core.telecom.CallControlResult
import androidx.core.telecom.CallControlScope
import androidx.core.telecom.CallEndpointCompat
import androidx.core.telecom.CallsManager
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.sipral.telecom.AudioRoute
import org.sipral.telecom.TelecomBridge
import org.sipral.telecom.TelecomConnection
import org.sipral.telecom.TelecomDirection
import org.sipral.telecom.TelecomDisconnect
import org.sipral.telecom.TelecomPlatform

/**
 * [TelecomPlatform] over Core-Telecom's `CallsManager`: each call the
 * bridge reports or places is added with `addCall`, and once the framework
 * has added it, the call's `CallControlScope` becomes its
 * [TelecomConnection] ([SipralCoreCall]). A call the framework will not add
 * (`CallException`, or no answer within its five seconds) is refused with
 * [TelecomBridge.connectionFailed], as the `ConnectionService` adapter
 * refuses one the framework would not create.
 *
 * ```kotlin
 * val platform = CoreTelecomPlatform(context, scope)
 * val bridge = TelecomBridge(platform, IdiomaticSipCalls(client, listOf(account)))
 * platform.install(bridge) { id, call -> showIncomingCallStyleNotification(id) }
 * bridge.collect(scope, client.events)
 * ```
 *
 * Calls are added in [scope], where the framework's callbacks then run; a
 * scope off the main thread keeps a call placed with STUN, which waits for
 * its mapping, from holding the main thread. The application keeps
 * [SipralCallForeground] following the bridge as with the other adapter:
 * Core-Telecom asks for a `phoneCall` foreground service and a
 * `Notification.CallStyle` within five seconds of a call being added, and
 * the incoming one is [CoreIncomingCallUi]'s to post. [report] hears what
 * the framework refused.
 */
class CoreTelecomPlatform internal constructor(
    private val scope: CoroutineScope,
    private val adder: CallAdder,
    private val report: (String) -> Unit,
) : TelecomPlatform {
    /** Registers this application with the framework (`registerAppWithTelecom`,
     * the baseline capability: audio calls that can be held). */
    constructor(context: Context, scope: CoroutineScope, report: (String) -> Unit = {}) :
        this(scope, CallsManagerAdder(context), report)

    @Volatile
    private var bridge: TelecomBridge? = null

    @Volatile
    private var incomingUi: CoreIncomingCallUi? = null

    /** Install the bridge the added calls report to, and the incoming-call
     * UI, before the first call. [SipralCallService]'s Hang up reaches the
     * same bridge. */
    fun install(bridge: TelecomBridge, incomingUi: CoreIncomingCallUi) {
        this.bridge = bridge
        this.incomingUi = incomingUi
        SipralTelecom.adopt(bridge)
    }

    override fun reportIncomingCall(id: String, caller: String, displayName: String?) {
        add(id, TelecomDirection.INCOMING, caller, displayName ?: caller.ifEmpty { ANONYMOUS })
    }

    override fun placeOutgoingCall(id: String, target: String) {
        add(id, TelecomDirection.OUTGOING, target, target)
    }

    private fun add(id: String, direction: TelecomDirection, address: String, displayName: String) {
        val bridge = checkNotNull(bridge) { "CoreTelecomPlatform.install was not called" }
        val call = SipralCoreCall(id, direction, bridge, report)
        scope.launch {
            var added = false
            try {
                adder.add(
                    incoming = direction == TelecomDirection.INCOMING,
                    address = address,
                    displayName = displayName,
                    onAnswer = { call.answeredByTelecom() },
                    onDisconnect = { call.disconnectedByTelecom() },
                    onSetActive = { call.activatedByTelecom() },
                    onSetInactive = { call.deactivatedByTelecom() },
                ) {
                    added = true
                    call.attach(this)
                    report("core-telecom: ${direction.name.lowercase()} call added, Telecom's id ${call.telecomId}")
                    bridge.connectionCreated(id, call.port)
                    if (call.ringing) {
                        showIncoming(id, call)
                    }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (refused: Exception) {
                report("core-telecom: ${direction.name.lowercase()} call ${if (added) "ended" else "not added"}: $refused")
            } finally {
                if (added) call.sessionEnded() else bridge.connectionFailed(id)
            }
        }
    }

    private fun showIncoming(id: String, call: SipralCoreCall) {
        try {
            incomingUi?.show(id, call)
        } catch (failed: RuntimeException) {
            // thrown here it would tear the call's session down; the call rings on
            // without its screen, and the log says why
            report("core-telecom: the incoming-call UI failed: $failed")
        }
    }

    private companion object {
        /** What a call that named nobody is shown as, RFC 3261 §8.1.1.3. */
        const val ANONYMOUS = "Anonymous"
    }
}

/** Raises the application's incoming-call screen for a call Core-Telecom
 * has added: a `Notification.CallStyle.forIncomingCall` notification
 * (within five seconds of the call being added), usually with a full-screen
 * intent. Answer and decline go to the bridge. */
fun interface CoreIncomingCallUi {
    fun show(id: String, call: SipralCoreCall)
}

/** `CallsManager.addCall`, as [CoreTelecomPlatform] uses it: the seam the
 * JVM tests stand a recorder in, since `CallsManager` needs a device. */
internal interface CallAdder {
    /** Returns once the call's session has ended, or throws if the
     * framework would not add it. [block] runs once it is added. */
    suspend fun add(
        incoming: Boolean,
        address: String,
        displayName: String,
        onAnswer: suspend () -> Unit,
        onDisconnect: suspend () -> Unit,
        onSetActive: suspend () -> Unit,
        onSetInactive: suspend () -> Unit,
        block: CallControlScope.() -> Unit,
    )
}

private class CallsManagerAdder(context: Context) : CallAdder {
    private val manager = CallsManager(context.applicationContext).apply {
        registerAppWithTelecom(CallsManager.CAPABILITY_BASELINE)
    }

    override suspend fun add(
        incoming: Boolean,
        address: String,
        displayName: String,
        onAnswer: suspend () -> Unit,
        onDisconnect: suspend () -> Unit,
        onSetActive: suspend () -> Unit,
        onSetInactive: suspend () -> Unit,
        block: CallControlScope.() -> Unit,
    ) {
        val attributes = CallAttributesCompat(
            displayName = displayName,
            address = addressOf(address),
            direction = if (incoming) CallAttributesCompat.DIRECTION_INCOMING else CallAttributesCompat.DIRECTION_OUTGOING,
            callType = CallAttributesCompat.CALL_TYPE_AUDIO_CALL,
            callCapabilities = CallAttributesCompat.SUPPORTS_SET_INACTIVE,
        )
        manager.addCall(
            attributes,
            onAnswer = { _ -> onAnswer() },
            onDisconnect = { _ -> onDisconnect() },
            onSetActive = { onSetActive() },
            onSetInactive = { onSetInactive() },
            block = block,
        )
    }
}

/**
 * One call Core-Telecom has added: what [TelecomBridge] tells it goes to
 * the call's `CallControlScope`, one request at a time and in order; what
 * the framework asks (answer, disconnect, set active, set inactive, from a
 * headset, a watch, a car or another call) goes to the bridge by call id.
 *
 * The framework's state moves in transactions that may be refused. A call
 * never let go active (an answer or a first `setActive` refused) is ended;
 * a refused resume puts the SIP call back on hold, a refused hold resumes
 * it, so that both sides keep agreeing. Routes and mute are the scope's
 * flows, reported here as [SipralCallRoutes]; the far end's hold has no
 * equivalent in this API and is not shown to the framework.
 */
class SipralCoreCall internal constructor(
    override val id: String,
    val direction: TelecomDirection,
    private val bridge: TelecomBridge,
    private val report: (String) -> Unit,
) : SipralCallRoutes {
    /** What the framework has been told, or has said, the call is. */
    private enum class Shown { RINGING, DIALING, ACTIVE, INACTIVE, ENDED }

    private val lock = Any()
    private var shown = if (direction == TelecomDirection.INCOMING) Shown.RINGING else Shown.DIALING

    /** The framework has had the call active at least once. */
    private var everActive = false

    private val steps = Channel<suspend CallControlScope.() -> Unit>(Channel.UNLIMITED)
    private val endpoints = ConcurrentHashMap<String, CallEndpointCompat>()
    private val routesFlow = MutableStateFlow<List<AudioRoute>>(emptyList())
    private val routeFlow = MutableStateFlow<AudioRoute?>(null)
    private val mutedFlow = MutableStateFlow(false)

    override val routes: StateFlow<List<AudioRoute>> = routesFlow
    override val route: StateFlow<AudioRoute?> = routeFlow
    override val muted: StateFlow<Boolean> = mutedFlow

    /** The framework's own id for the call (`CallControlScope.getCallId`),
     * as `dumpsys telecom` shows it; null until the call is added. */
    @Volatile
    var telecomId: String? = null
        private set

    internal val ringing: Boolean get() = synchronized(lock) { shown == Shown.RINGING }

    /** What [TelecomBridge] tells this call. Ringing and dialling are how
     * the call was added; the far end's hold has no counterpart, nor has a
     * caller learned after the call was added: `CallControlScope` keeps the
     * address `addCall` was given. */
    internal val port: TelecomConnection = object : TelecomConnection {
        override fun setRinging() = Unit
        override fun setDialing() = Unit
        override fun setActive() = request(Shown.ACTIVE)
        override fun setOnHold() = request(Shown.INACTIVE)
        override fun setRemoteHold(held: Boolean) = Unit

        override fun setDisconnected(cause: TelecomDisconnect) = setDisconnected(cause, cause.name.lowercase())

        override fun setDisconnected(cause: TelecomDisconnect, reason: String) {
            synchronized(lock) {
                if (shown == Shown.ENDED) {
                    return
                }
                shown = Shown.ENDED
            }
            steps.trySend {
                val result = disconnect(DisconnectCause(disconnectCodeOf(cause), null, null, reason))
                if (result is CallControlResult.Error) {
                    report("core-telecom: disconnect of $id refused, error ${result.errorCode}")
                }
            }
        }
    }

    /** The call was added: its requests run in [control], and its routes and
     * mute are followed there. */
    internal fun attach(control: CallControlScope) {
        telecomId = control.getCallId().toString()
        control.launch {
            for (step in steps) {
                control.step()
            }
        }
        control.launch {
            control.availableEndpoints.collect { offered ->
                endpoints.clear()
                routesFlow.value = offered.map { endpoint -> routeOf(endpoint).also { endpoints[it.id] = endpoint } }
            }
        }
        control.launch { control.currentCallEndpoint.collect { routeFlow.value = routeOf(it) } }
        control.launch { control.isMuted.collect { mutedFlow.value = it } }
        SipralTelecom.routesCreated(id, this)
    }

    override fun requestRoute(route: AudioRoute) {
        val endpoint = endpoints[route.id] ?: return
        steps.trySend {
            val result = requestEndpointChange(endpoint)
            if (result is CallControlResult.Error) {
                report("core-telecom: route ${route.name} refused for $id, error ${result.errorCode}")
            }
        }
    }

    // What the bridge asks

    private fun request(target: Shown) {
        val previous = synchronized(lock) {
            if (shown == target || shown == Shown.ENDED) {
                return
            }
            shown.also { shown = target }
        }
        steps.trySend {
            val answering = target == Shown.ACTIVE && direction == TelecomDirection.INCOMING &&
                synchronized(lock) { !everActive }
            val result = when {
                answering -> answer(CallAttributesCompat.CALL_TYPE_AUDIO_CALL)
                target == Shown.ACTIVE -> setActive()
                else -> setInactive()
            }
            when (result) {
                is CallControlResult.Success -> if (target == Shown.ACTIVE) {
                    synchronized(lock) { everActive = true }
                }
                is CallControlResult.Error -> refused(target, previous, result.errorCode)
            }
        }
    }

    private fun refused(target: Shown, previous: Shown, error: Int) {
        val first = synchronized(lock) {
            if (shown != target) {
                // moved on since it was asked; the later request stands
                return
            }
            shown = previous
            target == Shown.ACTIVE && !everActive
        }
        report("core-telecom: ${if (target == Shown.ACTIVE) "active" else "inactive"} refused for $id, error $error")
        when {
            first -> bridge.disconnect(id)
            target == Shown.ACTIVE -> bridge.hold(id)
            else -> bridge.unhold(id)
        }
    }

    // What the framework asks, each within its five seconds

    internal fun answeredByTelecom() {
        synchronized(lock) {
            if (shown == Shown.ENDED) {
                return
            }
            shown = Shown.ACTIVE
            everActive = true
        }
        bridge.answer(id)
    }

    internal fun disconnectedByTelecom() {
        synchronized(lock) {
            if (shown == Shown.ENDED) {
                return
            }
            shown = Shown.ENDED
        }
        bridge.disconnect(id)
    }

    internal fun activatedByTelecom() {
        synchronized(lock) {
            if (shown == Shown.ENDED) {
                return
            }
            shown = Shown.ACTIVE
            everActive = true
        }
        bridge.unhold(id)
    }

    /** "Your app must stop using the microphone and playing incoming media
     * when returning" (`CallsManager.addCall`): the call's device is let go
     * here, not when the bridge's phase reaches its audio. */
    internal fun deactivatedByTelecom() {
        synchronized(lock) {
            if (shown == Shown.ENDED) {
                return
            }
            shown = Shown.INACTIVE
        }
        bridge.hold(id)
        SipralTelecom.callHeld(id)
    }

    /** The session is over, however it ended; a bridge not yet told hears
     * it as a hang-up. */
    internal fun sessionEnded() {
        val untold = synchronized(lock) {
            (shown != Shown.ENDED).also { shown = Shown.ENDED }
        }
        steps.close()
        SipralTelecom.routesDestroyed(id)
        if (untold) {
            bridge.disconnect(id)
        }
    }
}

/** The four causes a transactional disconnect takes (LOCAL, REMOTE,
 * REJECTED, MISSED, `CallControlScope.disconnect`); the rest are carried as
 * the nearest of them, with the bridge's own name as the reason. */
internal fun disconnectCodeOf(cause: TelecomDisconnect): Int = when (cause) {
    TelecomDisconnect.LOCAL, TelecomDisconnect.CANCELED, TelecomDisconnect.ERROR -> DisconnectCause.LOCAL
    TelecomDisconnect.REMOTE, TelecomDisconnect.BUSY -> DisconnectCause.REMOTE
    TelecomDisconnect.REJECTED -> DisconnectCause.REJECTED
    TelecomDisconnect.MISSED -> DisconnectCause.MISSED
}

/** An endpoint as a route: keyed by the framework's identifier, or by its
 * type and name where the identifier carries none. */
internal fun routeOf(endpoint: CallEndpointCompat): AudioRoute {
    val kind = when (endpoint.type) {
        CallEndpointCompat.TYPE_EARPIECE -> AudioRoute.Kind.EARPIECE
        CallEndpointCompat.TYPE_SPEAKER -> AudioRoute.Kind.SPEAKER
        CallEndpointCompat.TYPE_WIRED_HEADSET -> AudioRoute.Kind.WIRED_HEADSET
        CallEndpointCompat.TYPE_BLUETOOTH -> AudioRoute.Kind.BLUETOOTH
        CallEndpointCompat.TYPE_STREAMING -> AudioRoute.Kind.STREAMING
        else -> AudioRoute.Kind.OTHER
    }
    val name = endpoint.name.toString()
    return AudioRoute(endpoint.identifier.uuid?.toString() ?: "${endpoint.type}:$name", name, kind)
}
