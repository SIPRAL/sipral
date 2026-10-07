// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.android.telecom

import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.OutcomeReceiver
import android.telecom.CallAudioState
import android.telecom.CallEndpoint
import android.telecom.CallEndpointException
import android.telecom.Connection
import android.telecom.DisconnectCause
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.sipral.telecom.AudioRoute
import org.sipral.telecom.TelecomBridge
import org.sipral.telecom.TelecomConnection
import org.sipral.telecom.TelecomDisconnect

/**
 * One self-managed call, as the telecom framework sees it.
 *
 * The framework's requests (answer, reject, disconnect, hold, unhold,
 * DTMF) go to the [TelecomBridge] by call id; what the bridge says reaches
 * the framework through [port], on the main thread. Routing is the
 * platform's: this class only reports the offered routes ([routes],
 * [route]) and mute ([muted]) and passes a choice back ([requestRoute]).
 * It never touches `AudioManager`, which the framework's guide warns
 * against under Telecom (developer.android.com/develop/connectivity/telecom/selfManaged).
 * [SipralCallAudio] follows all three with the call's device.
 */
class SipralConnection internal constructor(
    val id: String,
    private val bridge: TelecomBridge,
) : Connection() {
    private val main = Handler(Looper.getMainLooper())

    private val routesFlow = MutableStateFlow<List<AudioRoute>>(emptyList())
    private val routeFlow = MutableStateFlow<AudioRoute?>(null)
    private val endpoints = HashMap<String, CallEndpoint>()

    /** The routes the platform currently offers for this call. */
    val routes: StateFlow<List<AudioRoute>> = routesFlow

    /** The route the platform is currently using. */
    val route: StateFlow<AudioRoute?> = routeFlow

    private val mutedFlow = MutableStateFlow(false)

    /** Whether the platform muted this call, e.g. from a Bluetooth headset or
     * car control, which reach the call only through the framework. */
    val muted: StateFlow<Boolean> = mutedFlow

    init {
        connectionProperties = PROPERTY_SELF_MANAGED
        connectionCapabilities = CAPABILITY_HOLD or CAPABILITY_SUPPORT_HOLD or CAPABILITY_MUTE
        audioModeIsVoip = true
    }

    // named for the object below, whose methods share these names
    private val self: SipralConnection get() = this

    /** What [TelecomBridge] tells this call, posted to the main thread the
     * framework's callbacks arrive on. */
    internal val port: TelecomConnection = object : TelecomConnection {
        override fun setRinging() = onMain { self.setRinging() }
        override fun setDialing() = onMain { self.setDialing() }
        override fun setActive() = onMain { self.setActive() }
        override fun setOnHold() = onMain { self.setOnHold() }

        override fun setRemoteHold(held: Boolean) = onMain {
            // an event, not a state: the framework has no "far end holding" state, and
            // before Android 9 not even the event
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                sendConnectionEvent(if (held) EVENT_CALL_REMOTELY_HELD else EVENT_CALL_REMOTELY_UNHELD, null)
            }
        }

        override fun setDisconnected(cause: TelecomDisconnect) = onMain {
            self.setDisconnected(DisconnectCause(codeOf(cause)))
            // destroyed on the main thread's next turn, never inside this one: the
            // bridge can say "disconnected" from inside onCreateIncomingConnection,
            // before the service is listening for the destruction
            main.post {
                destroy()
                SipralTelecom.destroyed(id)
            }
        }
    }

    private fun onMain(action: () -> Unit) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            action()
        } else {
            main.post(action)
        }
    }

    // The framework's side

    override fun onAnswer() = bridge.answer(id)

    override fun onAnswer(videoState: Int) = bridge.answer(id)

    override fun onReject() = bridge.reject(id)

    // The framework also rejects through these two (Android 10's
    // Call.reject(int), and Call.reject(boolean, String)); Connection's own
    // versions do nothing, which would leave the call ringing. Both decline.
    override fun onReject(rejectReason: Int) = bridge.reject(id)

    override fun onReject(replyMessage: String?) = bridge.reject(id)

    override fun onDisconnect() = bridge.disconnect(id)

    override fun onAbort() = bridge.disconnect(id)

    override fun onHold() = bridge.hold(id)

    override fun onUnhold() = bridge.unhold(id)

    override fun onPlayDtmfTone(c: Char) = bridge.playDtmf(id, c)

    override fun onShowIncomingCallUi() {
        SipralTelecom.incomingUi?.show(id, this)
    }

    // Audio routes, as the platform offers them

    /** Ask the platform for [route]. The platform may refuse; [route] says
     * what it settled on. */
    fun requestRoute(route: AudioRoute) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val endpoint = endpoints[route.id] ?: return
            requestCallEndpointChange(
                endpoint,
                { it.run() },
                object : OutcomeReceiver<Void, CallEndpointException> {
                    override fun onResult(result: Void?) = Unit
                    override fun onError(error: CallEndpointException) = Unit
                },
            )
        } else {
            @Suppress("DEPRECATION")
            setAudioRoute(route.id.toInt())
        }
    }

    override fun onAvailableCallEndpointsChanged(available: List<CallEndpoint>) {
        endpoints.clear()
        routesFlow.value = available.map { endpoint ->
            val route = routeOf(endpoint)
            endpoints[route.id] = endpoint
            route
        }
    }

    override fun onCallEndpointChanged(endpoint: CallEndpoint) {
        routeFlow.value = routeOf(endpoint)
    }

    override fun onMuteStateChanged(isMuted: Boolean) {
        mutedFlow.value = isMuted
    }

    @Deprecated("Android 14 reports routes through onAvailableCallEndpointsChanged and onCallEndpointChanged")
    override fun onCallAudioStateChanged(state: CallAudioState) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            return
        }
        mutedFlow.value = state.isMuted
        val offered = LEGACY_ROUTES.filter { (mask, _) -> state.supportedRouteMask and mask != 0 }
            .map { (mask, kind) -> AudioRoute(mask.toString(), kind.name.lowercase().replace('_', ' '), kind) }
        routesFlow.value = offered
        routeFlow.value = offered.firstOrNull { it.id == state.route.toString() }
    }

    private fun routeOf(endpoint: CallEndpoint): AudioRoute {
        val kind = when (endpoint.endpointType) {
            CallEndpoint.TYPE_EARPIECE -> AudioRoute.Kind.EARPIECE
            CallEndpoint.TYPE_SPEAKER -> AudioRoute.Kind.SPEAKER
            CallEndpoint.TYPE_WIRED_HEADSET -> AudioRoute.Kind.WIRED_HEADSET
            CallEndpoint.TYPE_BLUETOOTH -> AudioRoute.Kind.BLUETOOTH
            CallEndpoint.TYPE_STREAMING -> AudioRoute.Kind.STREAMING
            else -> AudioRoute.Kind.OTHER
        }
        return AudioRoute(endpoint.identifier.toString(), endpoint.endpointName.toString(), kind)
    }

    private companion object {
        val LEGACY_ROUTES = listOf(
            CallAudioState.ROUTE_EARPIECE to AudioRoute.Kind.EARPIECE,
            CallAudioState.ROUTE_SPEAKER to AudioRoute.Kind.SPEAKER,
            CallAudioState.ROUTE_WIRED_HEADSET to AudioRoute.Kind.WIRED_HEADSET,
            CallAudioState.ROUTE_BLUETOOTH to AudioRoute.Kind.BLUETOOTH,
        )

        fun codeOf(cause: TelecomDisconnect): Int = when (cause) {
            TelecomDisconnect.LOCAL -> DisconnectCause.LOCAL
            TelecomDisconnect.REMOTE -> DisconnectCause.REMOTE
            TelecomDisconnect.REJECTED -> DisconnectCause.REJECTED
            TelecomDisconnect.MISSED -> DisconnectCause.MISSED
            TelecomDisconnect.BUSY -> DisconnectCause.BUSY
            TelecomDisconnect.CANCELED -> DisconnectCause.CANCELED
            TelecomDisconnect.ERROR -> DisconnectCause.ERROR
        }
    }
}
