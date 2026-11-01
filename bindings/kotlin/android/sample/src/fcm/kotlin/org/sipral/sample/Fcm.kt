// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.sample

import android.app.Application
import com.google.firebase.FirebaseApp
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** The FCM registration token and the project it belongs to: RFC 8599
 * §11's `pn-prid` and `pn-param`. */
class FcmTokens : PushTokens {
    override val name = "Firebase Cloud Messaging"

    override fun start(app: Application, changed: (token: String, project: String) -> Unit) {
        val project = FirebaseApp.getInstance().options.projectId ?: return
        FirebaseMessaging.getInstance().token.addOnCompleteListener { task ->
            val phone = (app as SampleApplication).phone
            if (task.isSuccessful) {
                changed(task.result, project)
            } else {
                phone.note("FCM token not issued: ${task.exception}")
            }
        }
    }
}

/**
 * The push gateway's high-priority data messages (`docs/15-mobile.md`, "The
 * lab's push gateway"), handed to the [Phone] as [PushReceiver] hands a
 * simulated one. `onMessageReceived` runs on a thread of its own and the
 * process may be ended once it returns, so it waits until the registration
 * has settled, nine seconds at most.
 */
class FcmService : FirebaseMessagingService() {
    private val phone: Phone get() = (application as SampleApplication).phone

    override fun onNewToken(token: String) {
        val project = FirebaseApp.getInstance().options.projectId ?: return
        phone.pushTokenChanged(token, project)
    }

    override fun onMessageReceived(message: RemoteMessage) {
        val settled = CountDownLatch(1)
        phone.note("FCM message, priority ${message.priority} (sent as ${message.originalPriority})")
        phone.pushReceived(message.data) { settled.countDown() }
        settled.await(9, TimeUnit.SECONDS)
    }
}
