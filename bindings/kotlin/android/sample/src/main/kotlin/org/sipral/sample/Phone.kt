// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.sample

import android.app.Application
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Person
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.os.SystemClock
import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.sipral.SipralAudioActivation
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralIce
import org.sipral.SipralLogLevel
import org.sipral.SipralRegistrationState
import org.sipral.SipralTransport
import org.sipral.android.telecom.AndroidTelecomPlatform
import org.sipral.android.telecom.SipralCallAudios
import org.sipral.android.telecom.SipralCallForeground
import org.sipral.android.telecom.SipralKeystoreStore
import org.sipral.android.telecom.SipralNetworkMonitor
import org.sipral.android.telecom.SipralTelecom
import org.sipral.idiomatic.SipralAccount
import org.sipral.idiomatic.SipralAudioDeviceInfo
import org.sipral.idiomatic.SipralAudioMode
import org.sipral.idiomatic.SipralClient
import org.sipral.idiomatic.SipralLifecycle
import org.sipral.idiomatic.SipralNetwork
import org.sipral.idiomatic.SipralTurnServer
import org.sipral.idiomatic.audioOf
import org.sipral.idiomatic.awaitNext
import org.sipral.idiomatic.changeKind
import org.sipral.idiomatic.natOf
import org.sipral.telecom.AudioRoute
import org.sipral.telecom.AudioState
import org.sipral.telecom.AudioTransition
import org.sipral.telecom.IdiomaticSipCalls
import org.sipral.telecom.TelecomBridge
import org.sipral.telecom.TelecomCall
import org.sipral.telecom.TelecomPhase
import org.sipral.telecom.wakeForPush

/**
 * The sample's phone: one stack, one account, and the calls the telecom
 * framework shows, for as long as the process lives. Every call action goes
 * through the [TelecomBridge], as the framework's callbacks do, so a headset
 * button and an on-screen button behave the same.
 *
 * It belongs to the process rather than to a screen ([SampleApplication]
 * holds it), because a push wakes the process with no screen at all
 * ([PushReceiver]) and a call goes on with the screen closed.
 */
class Phone(private val app: Application) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val main = Handler(Looper.getMainLooper())
    val store = AccountStore(app)

    var settings by mutableStateOf(AccountImport.take(app)?.also(store::save) ?: store.load())
    var status by mutableStateOf("not registered")
        private set
    var target by mutableStateOf("")
    var pushCaller by mutableStateOf("")
    var calls by mutableStateOf<List<TelecomCall>>(emptyList())
        private set

    /** The newest hundred of the sample's own lines, for the screen. */
    val screenLog = mutableStateListOf<String>()

    /** The sample's own lines, and the stack's log, for the bundle. */
    val events = EventLog(5_000)
    val stackLog = EventLog(20_000)

    /** Each call's audio state and packet counts, by call id, for its card. */
    var audioStates by mutableStateOf<Map<String, AudioState>>(emptyMap())
        private set
    var mediaCounts by mutableStateOf<Map<String, String>>(emptyMap())
        private set

    /** Whole SIP messages in the stack's log (`TRACE`), pseudonymised. */
    var sipMessages by mutableStateOf(false)
        private set

    /** The diagnostic trace: messages with their real addresses and
     * numbers. Credentials are removed either way. */
    var diagnosticTrace by mutableStateOf(false)
        private set

    /** The decision records as the stack last had them, kept past the
     * stack's own life so that a bundle made after Unregister has them. */
    var lastDiagnostics: String? = null
        private set

    val running: Boolean get() = client != null

    private var client: SipralClient? = null
    private var account: SipralAccount? = null
    private var bridge: TelecomBridge? = null
    private var sipCalls: IdiomaticSipCalls? = null
    private var audio: SipralCallAudios? = null
    private var monitor: SipralNetworkMonitor? = null
    private var starting: Job? = null
    private var watching: Job? = null

    private var foreground: Job? = null

    /** The registration kept across processes, sealed by the Keystore; the
     * application's screens drive it ([SampleApplication]). */
    val lifecycle = SipralLifecycle(SipralKeystoreStore(app)).apply {
        failed = { note("registration record: $it") }
    }

    /** When this process started, on the wall clock. */
    val processStartedAt: Long =
        System.currentTimeMillis() - (SystemClock.uptimeMillis() - Process.getStartUptimeMillis())

    fun note(line: String) {
        val stamped = events.add(line)
        Log.i(TAG, line)
        main.post {
            screenLog.add(0, stamped)
            if (screenLog.size > 100) {
                screenLog.removeAt(screenLog.size - 1)
            }
        }
    }

    fun edit(change: (AccountSettings) -> AccountSettings) {
        settings = change(settings)
    }

    /**
     * Open the stack on this device's own address, add the account, and
     * register it: by carrying on the registration the last process wrote
     * down when there is one (C3), and from the beginning otherwise. [push]
     * names a caller a push announced: the call is shown ringing as soon as
     * the account exists, before the network has answered anything (C1).
     */
    fun start(trigger: String, push: String? = null): Job {
        starting?.takeIf { it.isActive }?.let { running ->
            if (push != null) {
                scope.launch {
                    running.join()
                    announce(push)
                }
            }
            return running
        }
        val opened = client
        if (opened != null) {
            return scope.launch { push?.let { announce(it) } }
        }
        val job = scope.launch { open(trigger, push) }
        starting = job
        return job
    }

    private suspend fun open(trigger: String, push: String?) {
        val s = settings
        if (s.aor.isBlank() || s.registrarAddress.isBlank()) {
            status = "an address of record and a registrar address (host:port) are both needed"
            return
        }
        store.save(s)
        val began = SystemClock.elapsedRealtime()
        try {
            val network = SipralNetworkMonitor.current(app)
            val host = network.address ?: throw IllegalStateException("no network with an IPv4 address")
            val transport = when (s.transport) {
                "tcp" -> SipralTransport.TCP
                "tls" -> SipralTransport.TLS
                else -> SipralTransport.UDP
            }
            val streamed = transport != SipralTransport.UDP
            // A STUN server makes the registered Contact and every call's SDP
            // name the address seen beyond the NAT. A TURN relay is usable only
            // under ICE, so ICE is offered when one is given.
            val stun = s.stunServer.trim().ifEmpty { null }
            val turn = s.turnServer.trim().ifEmpty { null }?.let { SipralTurnServer(it, s.turnUser.trim(), s.turnPassword) }
            val (opened, added) = withContext(Dispatchers.IO) {
                // The engine carries calls over AAudio where the phone allows (API
                // 28+), opening devices only while the framework's call is active
                // (manual activation, driven by SipralCallAudios). Older phones
                // pump frames through AudioRecord and AudioTrack.
                val mode = if (SipralAudioMode.platformDefault is SipralAudioMode.Device) {
                    SipralAudioMode.Device(SipralAudioActivation.MANUAL)
                } else {
                    SipralAudioMode.Application
                }
                val opened = SipralClient.open(
                    bindHost = host,
                    stunServer = stun,
                    turn = turn,
                    ice = if (turn != null) SipralIce.OFFERED else null,
                    audio = mode,
                    network = network,
                    signalling = transport,
                    signallingServer = if (streamed) s.registrarAddress.trim() else null,
                )
                if (push == null) {
                    // a push declares its own, in wakeForPush
                    opened.coldStart()
                }
                logTo(opened)
                opened to opened.addAccount(
                    aor = s.aor.trim(),
                    registrarAddress = s.registrarAddress.trim(),
                    registrar = s.registrar.trim().ifEmpty { null },
                    authUser = s.authUser.trim().ifEmpty { null },
                    authPassword = s.authPassword.ifEmpty { null },
                    // A phone is behind a NAT on every mobile network, and a NAT
                    // forgets a quiet flow: a double CRLF to the registrar every 25 s
                    // keeps the way in open while the process runs (docs/06-nat.md,
                    // "Refresh"). Nothing is sent while it is frozen or dozing.
                    keepaliveMs = KEEPALIVE_MS,
                )
            }
            client = opened
            account = added
            wire(opened, added, network)
            note(
                "opened on ${opened.bindAddress} (${s.transport}), $trigger, " +
                    "${SystemClock.elapsedRealtime() - began} ms, " +
                    "${System.currentTimeMillis() - processStartedAt} ms after the process started",
            )
            if (s.registrar.isBlank()) {
                status = "no registrar: calls go straight to ${s.registrarAddress}"
                push?.let { announce(it) }
                return
            }
            lifecycle.attach(opened, scope)
            val key = added.aor
            status = "registering"
            // Subscribed before anything is sent: on a push the announce's own
            // REGISTER can be answered before a later subscriber would listen.
            val (thawed, reached) = withContext(Dispatchers.IO) {
                opened.events.awaitNext(timeoutMs = 20_000, matches = { isFinal(it, added) }) {
                    if (push != null) {
                        // C1 then C3: the call rings first, then the binding the
                        // last process wrote down is carried on by the announce's
                        // refresh (or a registration from the beginning)
                        val wake = wakeForPush(opened, added, bridge!!, lifecycle, key, push)
                        note("announced $push: ringing before the INVITE")
                        wake.restored
                    } else {
                        // the record says where the binding stood; only an answer
                        // says it still stands, so it is confirmed now
                        val restored = lifecycle.restore(added, key)
                        if (restored) added.refreshBinding() else added.register()
                        restored
                    }
                }
            }
            if (thawed) {
                note("registration carried on from the last process's record")
            }
            val state = stateOf(reached)
            if (state != SipralRegistrationState.REGISTERED) {
                status = "not registered: ${state.name.lowercase()}" +
                    (reached.message?.let { ", " + String(it).lineSequence().first().trim() } ?: "")
                return
            }
            store.keepRegistered = true
            status = "registered"
            note(
                "ready: ${added.timeToReadyMs ?: -1} ms after the cold start, " +
                    "${System.currentTimeMillis() - processStartedAt} ms after the process started" +
                    if (thawed) ", carried on" else ", registered from the beginning",
            )
        } catch (failed: Exception) {
            status = "failed: ${failed.message}"
            note("start failed: $failed")
        }
    }

    private fun isFinal(event: SipralEvent, account: SipralAccount): Boolean =
        event.kind == SipralEventKind.REGISTRATION_CHANGED.value.toLong() && event.account == account.handle &&
            when (stateOf(event)) {
                SipralRegistrationState.REGISTERED, SipralRegistrationState.FAILED,
                SipralRegistrationState.UNREGISTERED,
                -> true
                else -> false
            }

    private fun stateOf(event: SipralEvent): SipralRegistrationState =
        SipralRegistrationState.of(event.payload.registration.state.toInt()) ?: SipralRegistrationState.UNKNOWN

    /** The stack's log into [stackLog]: `DEBUG` (every decision, by name),
     * or `TRACE` with every SIP message when [sipMessages] is on; `INFO` and
     * louder go to logcat as well, under the tag `Sipral`. */
    private fun logTo(opened: SipralClient) {
        opened.setLog(if (sipMessages) SipralLogLevel.TRACE else SipralLogLevel.DEBUG) { level, where, line, suppressed ->
            val text = if (suppressed == 0L) line else "$line ($suppressed lines turned away before this one)"
            stackLog.add("${level.name} $where $text")
            val priority = when (level) {
                SipralLogLevel.ERROR -> Log.ERROR
                SipralLogLevel.WARN -> Log.WARN
                SipralLogLevel.INFO -> Log.INFO
                else -> return@setLog
            }
            Log.println(priority, "Sipral", "$where $text")
        }
        if (diagnosticTrace) {
            opened.setDiagnosticTrace(true)
        }
    }

    fun logSipMessages(on: Boolean) {
        sipMessages = on
        client?.let(::logTo)
        note(if (on) "SIP messages logged" else "SIP messages no longer logged")
    }

    fun traceDiagnostics(on: Boolean) {
        diagnosticTrace = on
        client?.setDiagnosticTrace(on)
        note(if (on) "diagnostic trace on: real addresses and numbers" else "diagnostic trace off")
    }

    private fun wire(opened: SipralClient, added: SipralAccount, network: SipralNetwork) {
        val sip = IdiomaticSipCalls(opened, listOf(added))
        sipCalls = sip
        val handle = SipralTelecom.registerAccount(app, "Sipral sample")
        val wired = TelecomBridge(AndroidTelecomPlatform(app, handle), sip)
        bridge = wired
        SipralTelecom.install(wired) { id, _ -> notifyIncoming(id) }
        wired.collect(scope, opened.events)
        monitor = SipralNetworkMonitor(app, opened, sip, scope, network) { note(it) }
        foreground = SipralCallForeground.follow(app, wired, scope, ::ongoing) { note(it) }
        // The library opens each call's microphone and speaker when media starts,
        // keeps them through whatever the platform does, and releases them at the
        // end; the sample only displays what happens.
        val audios = SipralCallAudios(app, wired, sip, opened.events, scope)
        audio = audios
        val engine = opened.audio
        if (engine == null) {
            note("audio: AudioRecord and AudioTrack")
        } else {
            note("audio: AAudio, devices ${engine.refresh().joinToString { describe(it) }}")
            scope.launch {
                opened.events.collect { event ->
                    val change = audioOf(event) ?: return@collect
                    note(
                        "audio devices: ${change.changeKind?.name?.lowercase()}, " +
                            engine.devices().filter { it.isPresent }.joinToString { describe(it) },
                    )
                }
            }
        }
        scope.launch { audios.transitions.collect { (_, change) -> note("audio ${describe(change)}") } }
        scope.launch { audios.states.collect { audioStates = it } }
        scope.launch { wired.calls.collect { reconcile(it) } }
        scope.launch {
            opened.events.collect { event ->
                val nat = natOf(event)
                if (nat != null) {
                    note("nat mapping ${nat.local} -> ${nat.mapped ?: "no answer"}")
                    return@collect
                }
                val kind = SipralEventKind.of(event.kind.toInt()) ?: return@collect
                when (kind) {
                    SipralEventKind.REGISTRATION_CHANGED -> registrationChanged(event)
                    SipralEventKind.CALL_ENDED -> keepDiagnostics()
                    else -> note(kind.name.lowercase())
                }
            }
        }
    }

    /** Each change logged; [lifecycle] writes every accepted registration
     * down by itself. */
    private fun registrationChanged(event: SipralEvent) {
        // the status line of the answer that moved it, not the whole message
        val answer = event.message?.let { String(it).lineSequence().firstOrNull()?.trim() }
        note("registration ${stateOf(event).name.lowercase()}" + (answer?.let { ": $it" } ?: ""))
    }

    private fun keepDiagnostics() {
        note("call_ended")
        val opened = client ?: return
        scope.launch(Dispatchers.IO) {
            try {
                lastDiagnostics = opened.diagnosticsJson()
            } catch (_: SipralException) {
                // the stack is closing; the previous copy stands
            }
        }
    }

    /** Unregister, wait for the registrar's answer, and close the stack. The
     * account stays on the screen; its registration record goes. */
    fun stop() {
        scope.launch {
            starting?.join()
            store.keepRegistered = false
            val opened = client ?: return@launch
            account?.let { lifecycle.forget(it.aor) }
            val added = account
            if (added != null && settings.registrar.isNotBlank()) {
                status = "unregistering"
                withContext(Dispatchers.IO) {
                    try {
                        withTimeoutOrNull(5_000) {
                            opened.events.awaitNext(timeoutMs = 5_000, matches = { isFinal(it, added) }) { added.unregister() }
                        }
                    } catch (failed: Exception) {
                        note("unregister: $failed")
                    }
                }
            }
            close()
            status = "not registered"
        }
    }

    private fun close() {
        val opened = client ?: return
        try {
            lastDiagnostics = opened.diagnosticsJson()
        } catch (_: SipralException) {
            // nothing new to keep
        }
        lifecycle.attach(null, null)
        foreground?.cancel()
        foreground = null
        monitor?.close()
        monitor = null
        audio?.close()
        audio = null
        // before the client goes: afterwards nothing would end the calls the
        // framework still shows
        bridge?.endAll()
        bridge = null
        opened.close()
        client = null
        account = null
        sipCalls = null
        note("stack closed")
    }

    // with STUN, placing and answering wait for the media socket's mapping,
    // so both run off the main thread
    fun call() {
        val added = account ?: return
        val dialled = target.trim()
        if (dialled.isNotEmpty()) {
            scope.launch {
                try {
                    withContext(Dispatchers.IO) { bridge?.placeCall(added.handle, dialled) }
                } catch (failed: Exception) {
                    note("call failed: ${failed.message}")
                }
            }
        }
    }

    /**
     * What a push handler (`FirebaseMessagingService.onMessageReceived`) does
     * on a device: report the call to the framework, announce it, and match
     * the following INVITE to the screen already up. The stack is opened
     * first when the process was not running it. [done] runs once the
     * registration is settled, or after nine seconds, whichever is first:
     * the time a receiver may keep its broadcast.
     */
    fun pushArrived(caller: String, done: () -> Unit = {}) {
        note("push: $caller is calling")
        val job = start("woken by a push", caller)
        scope.launch {
            withTimeoutOrNull(9_000) { job.join() }
            done()
        }
    }

    private fun announce(caller: String) {
        val added = account ?: return
        bridge?.pushArrived(added.handle, caller)
        note("announced $caller: ringing before the INVITE")
    }

    fun answer(id: String) {
        scope.launch {
            try {
                withContext(Dispatchers.IO) { bridge?.answer(id) }
            } catch (failed: Exception) {
                note("answer failed: ${failed.message}")
            }
        }
    }

    fun decline(id: String) {
        bridge?.reject(id)
    }

    fun hangup(id: String) {
        bridge?.disconnect(id)
    }

    /** Every call the framework still shows, ended: the call notification's
     * Hang up. */
    fun hangupAll() {
        for (call in calls) {
            if (call.phase != TelecomPhase.ENDED) {
                bridge?.disconnect(call.id)
            }
        }
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
     * notification down once nothing rings; hold the foreground service for
     * as long as a call is connecting or connected. */
    private fun reconcile(now: List<TelecomCall>) {
        calls = now
        if (now.none { it.phase == TelecomPhase.RINGING }) {
            app.getSystemService(NotificationManager::class.java).cancel(INCOMING_NOTIFICATION)
        }
        if (now.any { it.call != 0L } && watching?.isActive != true) {
            watching = scope.launch(Dispatchers.IO) { watchMedia() }
        }
    }

    /**
     * Every call's packet counts, read four times a second while there are
     * calls: shown on its card each second, and a line in the log whenever
     * inbound audio stops and when it comes back, with the length of the gap.
     */
    private suspend fun watchMedia() {
        val watches = HashMap<String, MediaWatch>()
        var shown = 0L
        while (currentCoroutineContext().isActive) {
            val live = calls.filter { it.call != 0L && it.phase != TelecomPhase.ENDED }
            if (live.isEmpty()) {
                main.post { mediaCounts = emptyMap() }
                return
            }
            val now = SystemClock.elapsedRealtime()
            val counts = HashMap<String, String>()
            for (call in live) {
                val stats = try {
                    sipCalls?.call(call.call)?.media?.statistics()
                } catch (_: SipralException) {
                    null
                } ?: continue
                counts[call.id] = "sent ${stats.packetsSent}, received ${stats.packetsReceived}, lost ${stats.packetsLost}"
                when (val change = watches.getOrPut(call.id) { MediaWatch() }.sample(now, stats.packetsReceived)) {
                    is MediaWatch.Change.Stopped -> note("inbound audio stopped (${call.id}), ${counts[call.id]}")
                    is MediaWatch.Change.Back -> note("inbound audio back after ${change.gapMs} ms (${call.id})")
                    null -> Unit
                }
            }
            if (now - shown >= 1_000) {
                shown = now
                main.post { mediaCounts = counts }
            }
            delay(250)
        }
    }

    /**
     * The incoming-call UI a self-managed call owes the user
     * (`Connection.onShowIncomingCallUi`): a notification whose full-screen
     * intent opens the call screen over the lock screen. Where the user has
     * not allowed full-screen intents (Android 14 and later, see
     * [ReadinessFacts.fullScreenIntent]) the system shows the same
     * notification as a heads-up one instead.
     */
    private fun notifyIncoming(id: String) {
        val manager = app.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, "Incoming calls", NotificationManager.IMPORTANCE_HIGH),
        )
        val open = PendingIntent.getActivity(
            app,
            0,
            Intent(app, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val caller = calls.firstOrNull { it.id == id }?.let { it.displayName ?: it.caller } ?: "Incoming call"
        val notification = Notification.Builder(app, CHANNEL)
            .setSmallIcon(android.R.drawable.sym_call_incoming)
            .setContentTitle(caller)
            .setContentText("Sipral sample")
            .setCategory(Notification.CATEGORY_CALL)
            .setContentIntent(open)
            .setFullScreenIntent(open, true)
            .setOngoing(true)
            .build()
        manager.notify(INCOMING_NOTIFICATION, notification)
        note("incoming call shown: $caller")
    }

    /** What the call's foreground service shows: the call style Android 12
     * and later give a call, with its Hang up. */
    private fun ongoing(context: Context, call: TelecomCall, hangUp: PendingIntent): Notification {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(ONGOING_CHANNEL, "Ongoing calls", NotificationManager.IMPORTANCE_LOW))
        val who = call.displayName ?: call.caller
        val open = PendingIntent.getActivity(
            context, 0, Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = Notification.Builder(context, ONGOING_CHANNEL)
            .setSmallIcon(android.R.drawable.sym_action_call)
            .setContentTitle(who)
            .setContentText("Sipral sample call")
            .setCategory(Notification.CATEGORY_CALL)
            .setContentIntent(open)
            .setOngoing(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            builder.setStyle(Notification.CallStyle.forOngoingCall(Person.Builder().setName(who).build(), hangUp))
        } else {
            builder.addAction(Notification.Action.Builder(null, "Hang up", hangUp).build())
        }
        return builder.build()
    }

    private fun describe(device: SipralAudioDeviceInfo): String = buildString {
        append(device.name)
        if (device.isDefaultOutput) {
            append(" (output)")
        }
        if (device.isDefaultInput) {
            append(" (input)")
        }
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

    /** What the stack holds now, as the redacted text a crash report
     * carries, or null with no stack open. */
    fun state(): String? = client?.state()

    /** The decision records of every call the stack still holds, or the
     * last copy kept. */
    fun diagnostics(): String? = try {
        client?.diagnosticsJson()?.also { lastDiagnostics = it } ?: lastDiagnostics
    } catch (_: SipralException) {
        lastDiagnostics
    }

    private companion object {
        const val TAG = "SipralSample"
        const val CHANNEL = "calls"
        const val INCOMING_NOTIFICATION = 1
        const val ONGOING_CHANNEL = "ongoing"
        const val KEEPALIVE_MS = 25_000L
    }
}
