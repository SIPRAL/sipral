// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.sample

import android.app.Application
import android.content.pm.PackageManager
import org.sipral.android.telecom.SipralAppLifecycle

/** Holds the [Phone] for the life of the process, which a push or a call
 * may keep running with no screen, and ties its stack to the application's
 * screens: the registration written down and the stack told it is
 * suspending when the last screen stops, told it resumed when one starts.
 * The push service, when the build has one, is started here too, so that a
 * process a push started asks it for the token as early as one a screen
 * started. */
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
        pushTokens()?.let { service ->
            phone.pushServiceStarted(service.name)
            service.start(this, phone::pushTokenChanged)
        }
    }

    /** The push service the manifest names, if the build compiled one in
     * (`sample/build.gradle.kts`, src/fcm). */
    private fun pushTokens(): PushTokens? {
        val info = packageManager.getApplicationInfo(packageName, PackageManager.GET_META_DATA)
        val name = info.metaData?.getString(PushTokens.META_DATA) ?: return null
        return Class.forName(name).getDeclaredConstructor().newInstance() as PushTokens
    }
}

/** A push service's token source: [start] asks for the current token and
 * hands it, with the project it belongs to, to `changed`. */
interface PushTokens {
    val name: String

    fun start(app: Application, changed: (token: String, project: String) -> Unit)

    companion object {
        /** The manifest meta-data naming the implementation. */
        const val META_DATA = "org.sipral.sample.push"
    }
}
