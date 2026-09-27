// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

package org.sipral.android.telecom

import android.telecom.Connection
import android.telecom.ConnectionRequest
import android.telecom.ConnectionService
import android.telecom.DisconnectCause
import android.telecom.PhoneAccountHandle
import android.telecom.TelecomManager
import org.sipral.telecom.TelecomBridge

/**
 * The `ConnectionService` this library's manifest declares, for the account
 * [SipralTelecom.registerAccount] registers. The framework creates it and
 * calls it on the main thread; it builds a [SipralConnection] for each call
 * the bridge asked for and hands it to the bridge, or tells the bridge the
 * framework would not have it.
 */
class SipralConnectionService : ConnectionService() {
    override fun onCreateIncomingConnection(account: PhoneAccountHandle?, request: ConnectionRequest): Connection =
        create(request)

    override fun onCreateOutgoingConnection(account: PhoneAccountHandle?, request: ConnectionRequest): Connection =
        create(request)

    override fun onCreateIncomingConnectionFailed(account: PhoneAccountHandle?, request: ConnectionRequest) {
        failed(request)
    }

    override fun onCreateOutgoingConnectionFailed(account: PhoneAccountHandle?, request: ConnectionRequest) {
        failed(request)
    }

    // The call focus, from Android 9: the framework moves it between calling
    // applications as the user moves between their calls, and on losing it
    // "The ConnectionService should release the call resources and invokes
    // connectionServiceFocusReleased() to inform telecom that it has
    // released the call resources"
    // (developer.android.com/reference/android/telecom/ConnectionService#onConnectionServiceFocusLost()).
    // Every call's device is let go before the framework is told so.
    override fun onConnectionServiceFocusLost() {
        SipralTelecom.callFocusChanged(false)
        connectionServiceFocusReleased()
    }

    // "The ConnectionService can acquire the call resources at this time."
    override fun onConnectionServiceFocusGained() {
        SipralTelecom.callFocusChanged(true)
    }

    private fun create(request: ConnectionRequest): Connection {
        val bridge: TelecomBridge = SipralTelecom.bridge
            ?: return Connection.createFailedConnection(DisconnectCause(DisconnectCause.ERROR, "no bridge installed"))
        val id = idOf(request)
            ?: return Connection.createFailedConnection(DisconnectCause(DisconnectCause.ERROR, "a call this application did not ask for"))
        val connection = SipralConnection(id, bridge)
        connection.setAddress(request.address, TelecomManager.PRESENTATION_ALLOWED)
        bridge.calls.value.firstOrNull { it.id == id }?.displayName?.let {
            connection.setCallerDisplayName(it, TelecomManager.PRESENTATION_ALLOWED)
        }
        SipralTelecom.created(id, connection)
        bridge.connectionCreated(id, connection.port)
        return connection
    }

    private fun failed(request: ConnectionRequest) {
        val id = idOf(request) ?: return
        SipralTelecom.bridge?.connectionFailed(id)
    }

    /** The id [AndroidTelecomPlatform] put in the extras: at the top level
     * for an incoming call, inside `EXTRA_OUTGOING_CALL_EXTRAS` for an
     * outgoing one, and looked for in both. */
    private fun idOf(request: ConnectionRequest): String? {
        val extras = request.extras ?: return null
        return extras.getString(SipralTelecom.EXTRA_CALL_ID)
            ?: extras.getBundle(TelecomManager.EXTRA_OUTGOING_CALL_EXTRAS)?.getString(SipralTelecom.EXTRA_CALL_ID)
            ?: extras.getBundle(TelecomManager.EXTRA_INCOMING_CALL_EXTRAS)?.getString(SipralTelecom.EXTRA_CALL_ID)
    }
}
