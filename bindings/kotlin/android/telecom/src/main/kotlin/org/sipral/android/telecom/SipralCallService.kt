// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.android.telecom

import android.Manifest
import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.sipral.telecom.TelecomBridge
import org.sipral.telecom.TelecomCall
import org.sipral.telecom.TelecomPhase

/** The notification a call's foreground service shows, under
 * [SipralCallForeground.NOTIFICATION_ID]. [hangUp] ends every call the
 * bridge has (declining one that rings). For a call whose phase is
 * `RINGING` it is the incoming-call notification
 * (`Notification.CallStyle.forIncomingCall` from Android 12, with the
 * application's Answer and Decline and usually a full-screen intent); for
 * any other, `Notification.CallStyle.forOngoingCall`. An `ENDED` call is
 * shown for an instant when every call ended while the service was being
 * started, which it has to finish before it leaves. The channel is the
 * application's to create. */
fun interface OngoingCallUi {
    fun notification(context: Context, call: TelecomCall, hangUp: PendingIntent): Notification
}

/**
 * The foreground service a call holds from the moment it rings (a push's
 * announcement included), is placed or is answered until the last call
 * ends, so that the process, its network and its microphone stay while the
 * screen is off or another application is in front. Android freezes a
 * cached process within seconds, and a ringing call's timers (the
 * announcement's twenty seconds, the caller's CANCEL, the user's decline)
 * run only in a process that is not frozen.
 *
 * Its types are `phoneCall`, which Android grants an application holding
 * `MANAGE_OWN_CALLS` (this library's manifest asks for it), and
 * `microphone`, which needs `RECORD_AUDIO` granted and, from Android 14,
 * the application visible when it starts (or the start coming from a
 * notification the user touched). While a call only rings the service is
 * `phoneCall` alone: started from a push, the process is in the background,
 * where Android 14 refuses a `microphone` service outright and earlier
 * releases give it no microphone. See [SipralCallForeground] for when it is
 * started, and `docs/15-mobile.md` for the order against a push.
 *
 * Started and stopped by [SipralCallForeground.follow]; the application
 * never starts it itself.
 */
class SipralCallService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_HANG_UP) {
            val bridge = SipralTelecom.bridge
            for (call in bridge?.calls?.value.orEmpty()) {
                if (call.phase != TelecomPhase.ENDED) {
                    bridge?.disconnect(call.id)
                }
            }
            return START_NOT_STICKY
        }
        val ui = SipralCallForeground.ui
        val shown = SipralCallForeground.entering()
        if (shown == null || ui == null) {
            // never started by follow, so there is no call to show
            stopSelf()
            return START_NOT_STICKY
        }
        val call = shown.call
        val hangUp = PendingIntent.getService(
            this, 0, Intent(this, SipralCallService::class.java).setAction(ACTION_HANG_UP), PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = ui.notification(this, call, hangUp)
        val withMicrophone = shown.microphone &&
            checkSelfPermission(Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED
        try {
            enterForeground(notification, withMicrophone)
            SipralCallForeground.report(
                "call service in the foreground (${call.phase.name.lowercase()}): " +
                    typesOf(withMicrophone, shown.microphone),
            )
        } catch (refused: SecurityException) {
            // From Android 14 a microphone service started while the application
            // is not visible is refused outright; the call goes on as phoneCall,
            // and the microphone is the application's only while it is visible.
            try {
                enterForeground(notification, false)
                SipralCallForeground.report("call service in the foreground as phoneCall only, microphone refused: ${refused.message}")
            } catch (again: RuntimeException) {
                SipralCallForeground.report("call service refused: $again")
                stopSelf()
            }
        } catch (refused: RuntimeException) {
            SipralCallForeground.report("call service refused: $refused")
            stopSelf()
        }
        if (!shown.stays) {
            // Every call ended while this start was on its way. A service started
            // with startForegroundService has to enter the foreground even then,
            // or Android ends the process; having done so, it leaves.
            stopSelf()
        }
        return START_NOT_STICKY
    }

    private fun enterForeground(notification: Notification, withMicrophone: Boolean) {
        val id = SipralCallForeground.NOTIFICATION_ID
        when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.R -> startForeground(
                id,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_PHONE_CALL or
                    if (withMicrophone) ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE else 0,
            )
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q ->
                startForeground(id, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_PHONE_CALL)
            else -> startForeground(id, notification)
        }
    }

    private fun typesOf(withMicrophone: Boolean, wanted: Boolean): String = when {
        Build.VERSION.SDK_INT < Build.VERSION_CODES.Q -> "untyped, before Android 10"
        Build.VERSION.SDK_INT < Build.VERSION_CODES.R -> "phoneCall"
        withMicrophone -> "phoneCall and microphone"
        !wanted -> "phoneCall only, the microphone comes with an answer"
        else -> "phoneCall only, the microphone is not allowed"
    }

    internal companion object {
        const val ACTION_HANG_UP = "org.sipral.android.telecom.HANG_UP"
    }
}

/**
 * When [SipralCallService] runs: from the moment a call rings (a push's
 * announcement, before its INVITE, included), is placed (the framework's
 * `REQUESTED`) or is answered, while it is dialling, active or held, until
 * no such call is left. It is started again when the shown call moves on,
 * so that its notification and its types follow:
 *
 * - while calls only ring, the first of them is shown and the service is
 *   `phoneCall` alone, the type Android lets a push handler start from the
 *   background (a high-priority FCM message is the exemption) and the only
 *   one a ringing call needs;
 * - once a call is placed or answered, that call is shown, a call ringing
 *   beside it is not, and the service adds `microphone` when `RECORD_AUDIO`
 *   is granted (re-checked each time: a permission granted mid-call takes
 *   effect). Answered from the notification or the call screen, the start
 *   comes from the user and Android allows the microphone.
 *
 * Follow the bridge before the push handler announces the call
 * (`wakeForPush`, [TelecomBridge.pushArrived]), so that the service is
 * started while the push's exemption lasts.
 */
object SipralCallForeground {
    /** The id of [SipralCallService]'s notification. An application that
     * posts its incoming-call notification under this id has one
     * notification for a ringing call whether or not Android let the service
     * start: the service's own replaces it, and is replaced in turn. */
    const val NOTIFICATION_ID: Int = 0x5195

    @Volatile
    internal var ui: OngoingCallUi? = null

    @Volatile
    internal var report: (String) -> Unit = {}

    private val CONNECTED = setOf(TelecomPhase.REQUESTED, TelecomPhase.DIALING, TelecomPhase.ACTIVE, TelecomPhase.HELD)

    /** What the service enters the foreground for: [call]'s notification,
     * with the `microphone` type when [microphone], and whether it [stays]
     * once it has (not when every call ended while it was being started). */
    internal class Shown(val call: TelecomCall, val microphone: Boolean, val stays: Boolean)

    /** What the bridge's [calls] hold the service for: the first call placed
     * or answered, with the microphone; else the first that rings, without;
     * else nothing. */
    internal fun heldFor(calls: List<TelecomCall>): Shown? {
        val connected = calls.firstOrNull { it.phase in CONNECTED }
        if (connected != null) {
            return Shown(connected, microphone = true, stays = true)
        }
        val ringing = calls.firstOrNull { it.phase == TelecomPhase.RINGING } ?: return null
        return Shown(ringing, microphone = false, stays = true)
    }

    /** What [move] asks of the service. */
    internal enum class Step { START, STOP, NOTHING }

    private val lock = Any()

    /** Under [lock]: what the service is to show, the call its latest start
     * was for, the starts asked whose `onStartCommand` has not yet run, and
     * the [follow] whose moves count. */
    private var current: Shown? = null
    private var last: TelecomCall? = null
    private var pending = 0
    private var following: Any? = null

    /** The follower [by] saw the calls move to [held]: start the service for
     * it, or stop it. Android ends a process whose service, asked with
     * `startForegroundService`, is stopped before it entered the foreground,
     * so with a start on its way the service is left to stop itself
     * ([entering]). A follower replaced by a newer one moves nothing. */
    internal fun move(by: Any, held: Shown?): Step = synchronized(lock) {
        when {
            by !== following -> Step.NOTHING
            held != null -> {
                current = held
                last = held.call
                pending++
                Step.START
            }
            else -> {
                current = null
                if (pending == 0) Step.STOP else Step.NOTHING
            }
        }
    }

    /** The start [move] asked for was refused: no `onStartCommand` follows. */
    internal fun startRefused(): Unit = synchronized(lock) {
        if (pending > 0) pending--
    }

    /** `onStartCommand`'s side of a start: what to show, or, every call
     * having ended meanwhile, the last call shown, as `ENDED`, to enter the
     * foreground with and leave. Null when [follow] never started it. */
    internal fun entering(): Shown? = synchronized(lock) {
        if (pending > 0) pending--
        current ?: last?.let { Shown(it.copy(phase = TelecomPhase.ENDED), microphone = false, stays = false) }
    }

    /** Follow [bridge]'s calls in [scope] for as long as it runs; [report]
     * hears what the service did, and what the system refused it. The
     * service is stopped when the job ends, whatever calls are left: a newer
     * [follow] takes over from this one. */
    fun follow(
        context: Context,
        bridge: TelecomBridge,
        scope: CoroutineScope,
        ui: OngoingCallUi,
        report: (String) -> Unit = {},
    ): Job {
        val app = context.applicationContext
        val token = Any()
        synchronized(lock) { following = token }
        this.ui = ui
        this.report = report
        return scope.launch {
            // the first calls seen are acted on whatever they are: a service an
            // earlier follower left running is stopped if nothing holds it now
            var acted = false
            var showing: Pair<String, TelecomPhase>? = null
            try {
                bridge.calls.collect { calls ->
                    val held = heldFor(calls)
                    val now = held?.let { it.call.id to it.call.phase }
                    if (acted && now == showing) return@collect
                    acted = true
                    showing = now
                    act(app, move(token, held), report)
                }
            } finally {
                if (showing != null) {
                    act(app, move(token, null), report)
                }
            }
        }
    }

    private fun act(app: Context, step: Step, report: (String) -> Unit) {
        when (step) {
            Step.START -> try {
                app.startForegroundService(Intent(app, SipralCallService::class.java))
            } catch (refused: RuntimeException) {
                // ForegroundServiceStartNotAllowedException, Android 12 and later:
                // started from the background with no exemption (a push Android
                // downgraded from high priority is none)
                startRefused()
                report("call service not started: $refused")
            }
            Step.STOP -> app.stopService(Intent(app, SipralCallService::class.java))
            Step.NOTHING -> Unit
        }
    }
}
