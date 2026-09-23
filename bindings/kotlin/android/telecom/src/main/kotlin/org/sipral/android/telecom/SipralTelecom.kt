// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

package org.sipral.android.telecom

import android.content.ComponentName
import android.content.Context
import android.telecom.PhoneAccount
import android.telecom.PhoneAccountHandle
import android.telecom.TelecomManager
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.sipral.telecom.TelecomBridge

/**
 * The process-wide wiring between an application and the telecom framework.
 *
 * The framework creates [SipralConnectionService] itself, with no way to
 * hand it anything, so what the service needs -- the [TelecomBridge] and
 * whoever raises the incoming-call screen -- is installed here by the
 * application once, before the first call:
 *
 * ```kotlin
 * val handle = SipralTelecom.registerAccount(context, "Acme Phone")
 * val bridge = TelecomBridge(AndroidTelecomPlatform(context, handle), IdiomaticSipCalls(client, listOf(account), localIp))
 * SipralTelecom.install(bridge) { id, connection -> showIncomingCallNotification(id, connection) }
 * bridge.collect(scope, client.events)
 * ```
 */
object SipralTelecom {
    /** The key a call's id travels under in the framework's extras. */
    const val EXTRA_CALL_ID: String = "org.sipral.telecom.CALL_ID"

    private const val ACCOUNT_ID = "sipral"

    @Volatile
    internal var bridge: TelecomBridge? = null
        private set

    @Volatile
    internal var incomingUi: IncomingCallUi? = null
        private set

    private val connectionsFlow = MutableStateFlow<Map<String, SipralConnection>>(emptyMap())
    private val live = ConcurrentHashMap<String, SipralConnection>()

    /** Every connection the framework has created and not yet destroyed,
     * by call id: what an application reads audio routes from. */
    val connections: StateFlow<Map<String, SipralConnection>> = connectionsFlow

    /** Install the bridge the service hands every connection to, and what
     * the service calls when the framework says the application may show
     * its incoming-call screen (`Connection.onShowIncomingCallUi`). */
    fun install(bridge: TelecomBridge, incomingUi: IncomingCallUi) {
        this.bridge = bridge
        this.incomingUi = incomingUi
    }

    /** This application's own `PhoneAccountHandle`, naming the service
     * this library's manifest declares. */
    fun accountHandle(context: Context): PhoneAccountHandle =
        PhoneAccountHandle(ComponentName(context, SipralConnectionService::class.java), ACCOUNT_ID)

    /**
     * Register the self-managed `PhoneAccount` calls are placed and received
     * on. A self-managed account needs no user consent to enable, and
     * registering it again replaces it.
     */
    // The platform marks CAPABILITY_SELF_MANAGED deprecated from API 37
    // (platforms/android-37.0/data/api-versions.xml); its newer route for a
    // calling application is the transactional one
    // (CAPABILITY_SUPPORTS_TRANSACTIONAL_OPERATIONS, API 34). The capability
    // is still what a self-managed ConnectionService needs on every release
    // this library supports, 8.0 to 17, and an adapter over the
    // transactional API would sit over the same TelecomBridge.
    @Suppress("DEPRECATION")
    fun registerAccount(context: Context, label: CharSequence): PhoneAccountHandle {
        val handle = accountHandle(context)
        val account = PhoneAccount.builder(handle, label)
            .setCapabilities(PhoneAccount.CAPABILITY_SELF_MANAGED)
            .addSupportedUriScheme(PhoneAccount.SCHEME_SIP)
            .build()
        context.getSystemService(TelecomManager::class.java).registerPhoneAccount(account)
        return handle
    }

    internal fun created(id: String, connection: SipralConnection) {
        live[id] = connection
        connectionsFlow.value = live.toMap()
    }

    internal fun destroyed(id: String) {
        live.remove(id)
        connectionsFlow.value = live.toMap()
    }
}

/** Raises the application's own incoming-call screen -- for a self-managed
 * call, typically a notification with a full-screen intent. */
fun interface IncomingCallUi {
    fun show(id: String, connection: SipralConnection)
}
