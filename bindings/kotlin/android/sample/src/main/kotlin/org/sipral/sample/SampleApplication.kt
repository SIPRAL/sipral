// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.sample

import android.app.Application
import org.sipral.android.telecom.SipralAppLifecycle

/** Holds the [Phone] for the life of the process, which a push or a call
 * may keep running with no screen, and ties its stack to the application's
 * screens: the registration written down and the stack told it is
 * suspending when the last screen stops, told it resumed when one starts. */
class SampleApplication : Application() {
    lateinit var phone: Phone
        private set

    override fun onCreate() {
        super.onCreate()
        phone = Phone(this)
        SipralAppLifecycle(this, phone.lifecycle) { report ->
            phone.note(
                "suspending: ${report.unverified} registrations no longer counted as live, " +
                    "${report.calls} calls left as they are",
            )
        }
    }
}
