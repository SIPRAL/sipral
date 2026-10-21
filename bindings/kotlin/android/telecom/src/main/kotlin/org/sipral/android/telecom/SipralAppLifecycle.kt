// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.android.telecom

import android.app.Activity
import android.app.Application
import android.os.Bundle
import org.sipral.SipralSuspending
import org.sipral.idiomatic.SipralLifecycle

/**
 * A [SipralLifecycle] driven by the application's own screens: when the
 * last of its activities stops, the application is in the background, and
 * its registrations are written down and the stack told it is suspending;
 * when one starts again, the stack is told it resumed. On Android 14 and
 * later a background application with no foreground service is soon frozen
 * by the system, and may be killed outright, so the background is the
 * moment a process has to assume is its last.
 *
 * A call holds [SipralCallService] in the foreground, and the process is
 * not frozen then; the stack is still told, since nothing it is told here
 * touches a call.
 *
 * Suspended, the stack sends nothing and keeps nothing scheduled, the
 * registration refresh included: right for an application a push wakes,
 * which is the one design that rings on a sleeping phone
 * (`docs/15-mobile.md`). An application with no push service that wants to
 * go on refreshing for as long as Android lets its process run passes
 * [suspendInBackground] false: its registrations are still written down,
 * and the stack is not told.
 *
 * Install it once, in `Application.onCreate`; [suspended] hears what was
 * standing each time.
 */
class SipralAppLifecycle(
    application: Application,
    val lifecycle: SipralLifecycle,
    private val suspendInBackground: Boolean = true,
    private val suspended: (SipralSuspending) -> Unit = {},
) : AutoCloseable {
    private val app = application
    private var started = 0
    private var inBackground = false

    private val callbacks = object : Application.ActivityLifecycleCallbacks {
        override fun onActivityStarted(activity: Activity) {
            started++
            if (inBackground) {
                inBackground = false
                if (suspendInBackground) lifecycle.enteredForeground()
            }
        }

        override fun onActivityStopped(activity: Activity) {
            // a configuration change stops and starts the same screen: that is
            // not the application leaving the foreground
            if (--started == 0 && !activity.isChangingConfigurations) {
                inBackground = true
                if (suspendInBackground) {
                    lifecycle.enteredBackground()?.let(suspended)
                } else {
                    lifecycle.writeDown()
                }
            }
        }

        override fun onActivityCreated(activity: Activity, saved: Bundle?) = Unit
        override fun onActivityResumed(activity: Activity) = Unit
        override fun onActivityPaused(activity: Activity) = Unit
        override fun onActivitySaveInstanceState(activity: Activity, state: Bundle) = Unit
        override fun onActivityDestroyed(activity: Activity) = Unit
    }

    init {
        app.registerActivityLifecycleCallbacks(callbacks)
    }

    override fun close() {
        app.unregisterActivityLifecycleCallbacks(callbacks)
    }
}
