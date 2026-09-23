// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

package org.sipral.android.telecom

import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.telecom.PhoneAccountHandle
import android.telecom.TelecomManager
import org.sipral.telecom.TelecomPlatform

/**
 * [TelecomPlatform] over `TelecomManager`, for the self-managed account
 * [SipralTelecom.registerAccount] registered. The framework answers each of
 * these by creating a connection in [SipralConnectionService], or by saying
 * it could not.
 */
class AndroidTelecomPlatform(
    context: Context,
    private val account: PhoneAccountHandle,
) : TelecomPlatform {
    private val telecom: TelecomManager = context.getSystemService(TelecomManager::class.java)

    override fun reportIncomingCall(id: String, caller: String, displayName: String?) {
        val extras = Bundle().apply {
            putString(SipralTelecom.EXTRA_CALL_ID, id)
            putParcelable(TelecomManager.EXTRA_INCOMING_CALL_ADDRESS, addressOf(caller))
        }
        telecom.addNewIncomingCall(account, extras)
    }

    override fun placeOutgoingCall(id: String, target: String) {
        val extras = Bundle().apply {
            putParcelable(TelecomManager.EXTRA_PHONE_ACCOUNT_HANDLE, account)
            putBundle(
                TelecomManager.EXTRA_OUTGOING_CALL_EXTRAS,
                Bundle().apply { putString(SipralTelecom.EXTRA_CALL_ID, id) },
            )
        }
        telecom.placeCall(addressOf(target), extras)
    }
}

/** A caller's URI as the framework takes it. A call that named nobody --
 * an INVITE with no usable `From` -- is shown the way RFC 3261 §8.1.1.3
 * spells an anonymous one. */
internal fun addressOf(uri: String): Uri =
    Uri.parse(uri.ifEmpty { "sip:anonymous@anonymous.invalid" })
