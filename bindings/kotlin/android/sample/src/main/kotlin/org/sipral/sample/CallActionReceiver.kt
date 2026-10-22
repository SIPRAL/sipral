// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.sample

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** The incoming-call notification's Decline, which needs no screen. Not
 * exported: only this application's own notification reaches it. Answer
 * goes to [MainActivity] instead, so that the application is visible when
 * the call takes the microphone. */
class CallActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val id = intent.getStringExtra(Phone.EXTRA_CALL) ?: return
        if (intent.action == Phone.ACTION_DECLINE) {
            (context.applicationContext as SampleApplication).phone.decline(id)
        }
    }
}
