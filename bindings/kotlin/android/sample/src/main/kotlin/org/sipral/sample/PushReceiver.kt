// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.sample

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * A push, without a push service: what `FirebaseMessagingService
 * .onMessageReceived` would be handed for a call, delivered from a computer
 * over adb so that a process the system killed can be woken the way a push
 * wakes it (`docs/15-mobile.md`):
 *
 * ```sh
 * adb shell am broadcast -a org.sipral.sample.SIMULATE_PUSH \
 *     -n org.sipral.sample/.PushReceiver --es caller sip:170@pbx.example.com
 * ```
 *
 * The manifest protects it with `android.permission.DUMP`, which adb's shell
 * holds and no installed application can, so nothing on the phone can
 * raise a fake call through it.
 */
class PushReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val caller = intent.getStringExtra("caller")?.trim().orEmpty()
        val phone = (context.applicationContext as SampleApplication).phone
        if (caller.isEmpty()) {
            phone.note("push with no caller, ignored")
            return
        }
        val pending = goAsync()
        phone.pushArrived(caller) { pending.finish() }
    }
}
