// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.sample

import android.app.Application
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import java.net.Inet4Address
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.sipral.SipralAudioActivation
import org.sipral.SipralEventKind
import org.sipral.SipralIce
import org.sipral.android.telecom.AndroidTelecomPlatform
import org.sipral.android.telecom.SipralCallAudios
import org.sipral.android.telecom.SipralTelecom
import org.sipral.idiomatic.SipralAccount
import org.sipral.idiomatic.SipralAudioDeviceInfo
import org.sipral.idiomatic.SipralAudioMode
import org.sipral.idiomatic.SipralClient
import org.sipral.idiomatic.SipralTurnServer
import org.sipral.idiomatic.audioOf
import org.sipral.idiomatic.changeKind
import org.sipral.idiomatic.natOf
import org.sipral.telecom.AudioRoute
import org.sipral.telecom.AudioState
import org.sipral.telecom.AudioTransition
import org.sipral.telecom.IdiomaticSipCalls
import org.sipral.telecom.TelecomBridge
import org.sipral.telecom.TelecomCall
import org.sipral.telecom.TelecomPhase

/**
 * The sample's whole state: one stack, one account, and whatever calls the
 * telecom framework is showing. Every call action goes through the
 * [TelecomBridge], the same one the framework's own callbacks reach, so a
 * headset button and a button on this screen do the same thing.
 *
 * A `ViewModel`, so that the stack outlives the activity being recreated
 * (a rotation) and is closed only when the activity is gone for good.
 */
class SampleModel(application: Application) : AndroidViewModel(application) {
    private val context: Context get() = getApplication()
    private val scope: CoroutineScope get() = viewModelScope

    var aor by mutableStateOf("")
    var registrarAddress by mutableStateOf("")
    var registrar by mutableStateOf("")
    var authUser by mutableStateOf("")
    var authPassword by mutableStateOf("")
    var stunServer by mutableStateOf("")
    var turnServer by mutableStateOf("")
    var turnUser by mutableStateOf("")
    var turnPassword by mutableStateOf("")
    var target by mutableStateOf("")
    var pushCaller by mutableStateOf("")

    var status by mutableStateOf("not registered")
        private set
    var calls by mutableStateOf<List<TelecomCall>>(emptyList())
        private set
    val log = mutableStateListOf<String>()

    private var client: SipralClient? = null
    private var account: SipralAccount? = null
    private var bridge: TelecomBridge? = null
    private var audio: SipralCallAudios? = null

    /** Each call's audio state, by call id, for its card. */
    var audioStates by mutableStateOf<Map<String, AudioState>>(emptyMap())
        private set

    private fun describe(device: SipralAudioDeviceInfo): String = buildString {
        append(device.name)
        if (device.isDefaultOutput) {
            append(" (output)")
        }
        if (device.isDefaultInput) {
            append(" (input)")
        }
    }

    private fun append(line: String) {
        log.add(0, line)
        if (log.size > 100) {
            log.removeAt(log.size - 1)
        }
    }

    /** Open the stack on this device's own address, register the account,
     * and wire the bridge between the two and the telecom framework. */
    fun register() {
        if (client != null) {
            return
        }
        if (aor.isBlank() || registrarAddress.isBlank()) {
            status = "an address of record and a registrar address (host:port) are both needed"
            return
        }
        scope.launch {
            try {
                val host = withContext(Dispatchers.IO) { localAddress() }
                // Sockets are opened and the first REGISTER goes out here, so
                // off the main thread, which Android does not let touch the
                // network.
                // A STUN server makes the Contact the registrar stores, and
                // the SDP of every call, name the address this device appears
                // from beyond its NAT. A TURN server adds a relay, which only
                // an ICE call can use, so ICE is offered when one is given.
                val stun = stunServer.trim().ifEmpty { null }
                val turn = turnServer.trim().ifEmpty { null }?.let {
                    SipralTurnServer(it, turnUser.trim(), turnPassword)
                }
                val (opened, added) = withContext(Dispatchers.IO) {
                    // The library's engine carries the calls over AAudio
                    // where the phone allows (API level 28 and later), and
                    // opens the devices only when the framework's call is
                    // active: manual activation, driven by SipralCallAudios.
                    // An older phone pumps the frames through AudioRecord
                    // and AudioTrack instead.
                    val audio = if (SipralAudioMode.platformDefault is SipralAudioMode.Device) {
                        SipralAudioMode.Device(SipralAudioActivation.MANUAL)
                    } else {
                        SipralAudioMode.Application
                    }
                    val opened = SipralClient.open(
                        bindHost = host,
                        stunServer = stun,
                        turn = turn,
                        ice = if (turn != null) SipralIce.OFFERED else null,
                        audio = audio,
                    )
                    opened to opened.addAccount(
                        aor = aor,
                        registrarAddress = registrarAddress,
                        registrar = registrar.ifEmpty { null },
                        authUser = authUser.ifEmpty { null },
                        authPassword = authPassword.ifEmpty { null },
                    )
                }
                client = opened
                account = added
                val calls = IdiomaticSipCalls(opened, listOf(added), mediaHost = host)
                val handle = SipralTelecom.registerAccount(context, "Sipral sample")
                val wired = TelecomBridge(AndroidTelecomPlatform(context, handle), calls)
                bridge = wired
                SipralTelecom.install(wired) { id, _ -> notifyIncoming(id) }
                wired.collect(scope, opened.events)
                // Every call's microphone and speaker are the library's: it
                // opens them when a call's media starts, keeps them through
                // whatever the platform does, and lets them go when the call
                // ends. The sample only shows what happens to them.
                val audios = SipralCallAudios(context, wired, calls, opened.events, scope)
                audio = audios
                val engine = opened.audio
                if (engine == null) {
                    append("audio: AudioRecord and AudioTrack")
                } else {
                    append("audio: AAudio, devices ${engine.refresh().joinToString { describe(it) }}")
                    scope.launch {
                        opened.events.collect { event ->
                            val change = audioOf(event) ?: return@collect
                            append(
                                "audio devices: ${change.changeKind?.name?.lowercase()}, " +
                                    engine.devices().filter { it.isPresent }.joinToString { describe(it) },
                            )
                        }
                    }
                }
                scope.launch { audios.transitions.collect { (_, change) -> append("audio ${describe(change)}") } }
                scope.launch { audios.states.collect { audioStates = it } }
                scope.launch { wired.calls.collect { reconcile(it) } }
                scope.launch {
                    opened.events.collect { event ->
                        val nat = natOf(event)
                        if (nat != null) {
                            append("nat mapping ${nat.local} -> ${nat.mapped ?: "no answer"}")
                        } else {
                            SipralEventKind.of(event.kind.toInt())?.let { append(it.name.lowercase()) }
                        }
                    }
                }
                append("listening on ${opened.bindAddress}")
                if (registrar.isEmpty()) {
                    status = "no registrar: calls go straight to $registrarAddress"
                } else {
                    status = "registering"
                    withContext(Dispatchers.IO) { added.registerAndWait() }
                    status = "registered"
                }
            } catch (failed: Exception) {
                status = "failed: ${failed.message}"
            }
        }
    }

    // Placing and answering wait for the STUN server to map the call's
    // media socket when one is configured, so both run off the main thread.
    fun call() {
        val account = account ?: return
        val dialled = target.trim()
        if (dialled.isNotEmpty()) {
            scope.launch {
                try {
                    withContext(Dispatchers.IO) { bridge?.placeCall(account.handle, dialled) }
                } catch (failed: Exception) {
                    append("call failed: ${failed.message}")
                }
            }
        }
    }

    /**
     * What a push handler does on a real device -- `FirebaseMessagingService
     * .onMessageReceived`, reading the caller out of the push -- without a
     * push service: the call is reported to the framework, then announced,
     * and the INVITE that follows is matched to the screen already up.
     */
    fun simulatePush() {
        val account = account ?: return
        if (pushCaller.isNotBlank()) {
            bridge?.pushArrived(account.handle, pushCaller.trim())
        }
    }

    fun answer(id: String) {
        scope.launch {
            try {
                withContext(Dispatchers.IO) { bridge?.answer(id) }
            } catch (failed: Exception) {
                append("answer failed: ${failed.message}")
            }
        }
    }

    fun decline(id: String) {
        bridge?.reject(id)
    }

    fun hangup(id: String) {
        bridge?.disconnect(id)
    }

    fun toggleHold(call: TelecomCall) {
        if (call.phase == TelecomPhase.HELD) {
            bridge?.unhold(call.id)
        } else {
            bridge?.hold(call.id)
        }
    }

    fun dtmf(id: String, digit: Char) {
        bridge?.playDtmf(id, digit)
    }

    fun selectRoute(id: String, route: AudioRoute) {
        SipralTelecom.connections.value[id]?.requestRoute(route)
    }

    /** Show the calls the framework has; take the incoming-call
     * notification down once nothing rings. */
    private fun reconcile(now: List<TelecomCall>) {
        calls = now
        if (now.none { it.phase == TelecomPhase.RINGING }) {
            context.getSystemService(NotificationManager::class.java).cancel(INCOMING_NOTIFICATION)
        }
    }

    /**
     * The incoming-call screen a self-managed call owes the user
     * (`Connection.onShowIncomingCallUi`): a notification whose full-screen
     * intent opens this activity over the lock screen, where the call is
     * answered or declined.
     */
    private fun notifyIncoming(id: String) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, "Incoming calls", NotificationManager.IMPORTANCE_HIGH),
        )
        val open = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val caller = calls.firstOrNull { it.id == id }?.let { it.displayName ?: it.caller } ?: "Incoming call"
        val notification = Notification.Builder(context, CHANNEL)
            .setSmallIcon(android.R.drawable.sym_call_incoming)
            .setContentTitle(caller)
            .setContentText("Sipral sample")
            .setCategory(Notification.CATEGORY_CALL)
            .setFullScreenIntent(open, true)
            .setOngoing(true)
            .build()
        manager.notify(INCOMING_NOTIFICATION, notification)
    }

    private fun localAddress(): String {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val links = connectivity.getLinkProperties(connectivity.activeNetwork)
        return links?.linkAddresses
            ?.map { it.address }
            ?.firstOrNull { it is Inet4Address && !it.isLoopbackAddress }
            ?.hostAddress
            ?: "127.0.0.1"
    }

    private fun describe(transition: AudioTransition): String = when (transition) {
        AudioTransition.Started -> "started"
        is AudioTransition.Paused -> "paused: ${transition.reasons.joinToString { it.name.lowercase() }}"
        AudioTransition.Resumed -> "resumed"
        is AudioTransition.RouteChanged -> "route ${transition.route.name}"
        is AudioTransition.MuteChanged -> if (transition.muted) "muted" else "unmuted"
        is AudioTransition.DeviceFailed ->
            "device failed (${transition.direction.name.lowercase()} ${transition.code}" +
                (transition.detail?.let { ", $it" } ?: "") + ")"
        is AudioTransition.DeviceRestored -> "device restored after ${transition.attempts} tries"
        AudioTransition.Stopped -> "stopped"
    }

    override fun onCleared() {
        audio?.close()
        audio = null
        // Before the client goes: once it has, nothing would ever end the
        // calls the framework is still showing.
        bridge?.endAll()
        bridge = null
        client?.close()
        client = null
    }

    private companion object {
        const val CHANNEL = "calls"
        const val INCOMING_NOTIFICATION = 1
    }
}
