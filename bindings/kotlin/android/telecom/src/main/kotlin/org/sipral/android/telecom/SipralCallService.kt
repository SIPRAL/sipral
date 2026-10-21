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

/** The notification a call's foreground service shows. [hangUp] ends every
 * call the bridge has; on Android 12 and later
 * `Notification.CallStyle.forOngoingCall` is the style the system expects of
 * a call. The channel is the application's to create. */
fun interface OngoingCallUi {
    fun notification(context: Context, call: TelecomCall, hangUp: PendingIntent): Notification
}

/**
 * The foreground service a call holds from the moment it is placed or
 * answered until the last call ends, so that the process, its network and
 * its microphone stay while the screen is off or another application is in
 * front. Its types are `phoneCall`, which Android grants an application
 * holding `MANAGE_OWN_CALLS` (this library's manifest asks for it), and
 * `microphone`, which needs `RECORD_AUDIO` granted and, from Android 14,
 * the application visible when it starts (or the start coming from a
 * notification the user touched): see [SipralCallForeground] for when it
 * is started, and `docs/15-mobile.md` for the order against a push.
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
        val call = SipralCallForeground.shown
        val ui = SipralCallForeground.ui
        if (call == null || ui == null) {
            // nothing to show for: started for a call that has ended since
            stopSelf()
            return START_NOT_STICKY
        }
        val hangUp = PendingIntent.getService(
            this, 0, Intent(this, SipralCallService::class.java).setAction(ACTION_HANG_UP), PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = ui.notification(this, call, hangUp)
        val withMicrophone = checkSelfPermission(Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED
        try {
            enterForeground(notification, withMicrophone)
            SipralCallForeground.report(
                "call service in the foreground (${call.phase.name.lowercase()}): " +
                    typesOf(withMicrophone),
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
        return START_NOT_STICKY
    }

    private fun enterForeground(notification: Notification, withMicrophone: Boolean) {
        when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.R -> startForeground(
                ONGOING,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_PHONE_CALL or
                    if (withMicrophone) ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE else 0,
            )
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q ->
                startForeground(ONGOING, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_PHONE_CALL)
            else -> startForeground(ONGOING, notification)
        }
    }

    private fun typesOf(withMicrophone: Boolean): String = when {
        Build.VERSION.SDK_INT < Build.VERSION_CODES.Q -> "untyped, before Android 10"
        Build.VERSION.SDK_INT < Build.VERSION_CODES.R -> "phoneCall"
        withMicrophone -> "phoneCall and microphone"
        else -> "phoneCall only, the microphone is not allowed"
    }

    internal companion object {
        const val ONGOING = 0x5195
        const val ACTION_HANG_UP = "org.sipral.android.telecom.HANG_UP"
    }
}

/**
 * When [SipralCallService] runs: from the moment a call is placed (the
 * framework's `REQUESTED`) or answered, while it is dialling, active or
 * held, until no such call is left. Not while a call only rings: the
 * incoming-call notification needs no service, and a push handler that
 * starts one from the background could not give it the microphone anyway.
 * It is started again when the shown call moves on, so that its
 * notification and its types follow (`microphone` is re-checked: a
 * permission granted mid-call takes effect).
 */
object SipralCallForeground {
    @Volatile
    internal var shown: TelecomCall? = null

    @Volatile
    internal var ui: OngoingCallUi? = null

    @Volatile
    internal var report: (String) -> Unit = {}

    private val LIVE = setOf(TelecomPhase.REQUESTED, TelecomPhase.DIALING, TelecomPhase.ACTIVE, TelecomPhase.HELD)

    /** Follow [bridge]'s calls in [scope] for as long as it runs; [report]
     * hears what the service did, and what the system refused it. */
    fun follow(
        context: Context,
        bridge: TelecomBridge,
        scope: CoroutineScope,
        ui: OngoingCallUi,
        report: (String) -> Unit = {},
    ): Job {
        val app = context.applicationContext
        this.ui = ui
        this.report = report
        return scope.launch {
            var showing: Pair<String, TelecomPhase>? = null
            bridge.calls.collect { calls ->
                val live = calls.firstOrNull { it.phase in LIVE }
                val now = live?.let { it.id to it.phase }
                if (now == showing) return@collect
                showing = now
                shown = live
                if (live == null) {
                    app.stopService(Intent(app, SipralCallService::class.java))
                    return@collect
                }
                try {
                    app.startForegroundService(Intent(app, SipralCallService::class.java))
                } catch (refused: RuntimeException) {
                    // ForegroundServiceStartNotAllowedException, Android 12 and later:
                    // started from the background with no exemption
                    report("call service not started: $refused")
                }
            }
        }
    }
}
