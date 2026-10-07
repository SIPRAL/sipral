// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.android.telecom

import android.content.ComponentName
import android.content.Context
import android.telecom.PhoneAccount
import android.telecom.PhoneAccountHandle
import android.telecom.TelecomManager
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.sipral.telecom.AudioPause
import org.sipral.telecom.CallAudio
import org.sipral.telecom.TelecomBridge

/**
 * Process-wide wiring between an application and the telecom framework.
 *
 * The framework creates [SipralConnectionService] itself and cannot pass
 * it anything, so the application installs the [TelecomBridge] and its
 * incoming-call UI here once, before the first call:
 *
 * ```kotlin
 * val handle = SipralTelecom.registerAccount(context, "Acme Phone")
 * val bridge = TelecomBridge(AndroidTelecomPlatform(context, handle), IdiomaticSipCalls(client, listOf(account), localIp))
 * SipralTelecom.install(bridge) { id, connection -> showIncomingCallNotification(id, connection) }
 * bridge.collect(scope, client.events)
 * ```
 *
 * Before closing the client, call `bridge.endAll()` so no connection
 * outlives its call.
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

    /** Install the bridge the service hands each connection to, and the
     * callback for when the framework lets the app show its incoming-call UI
     * (`Connection.onShowIncomingCallUi`). */
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
    // CAPABILITY_SELF_MANAGED is deprecated from API 37 in favour of the
    // transactional API (API 34), but it is still what a self-managed
    // ConnectionService needs on every release this library supports (8.0 to
    // 17); a transactional adapter would sit over the same TelecomBridge.
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

    private val callFocusFlow = MutableStateFlow(true)
    private val audios = ConcurrentHashMap.newKeySet<CallAudio>()

    /** Whether this app's `ConnectionService` has call focus: true until the
     * framework says otherwise, and always before Android 9, which has no
     * call focus. */
    val callFocus: StateFlow<Boolean> = callFocusFlow

    /** The framework moved call focus. Every call's audio is released or
     * retaken before this returns. */
    internal fun callFocusChanged(has: Boolean) {
        callFocusFlow.value = has
        for (audio in audios) {
            applyFocus(audio, has)
        }
    }

    internal fun register(audio: CallAudio) {
        audios.add(audio)
        applyFocus(audio, callFocusFlow.value)
    }

    internal fun unregister(audio: CallAudio) {
        audios.remove(audio)
    }

    private fun applyFocus(audio: CallAudio, has: Boolean) {
        if (has) {
            audio.resume(AudioPause.CALL_FOCUS_LOST)
        } else {
            audio.pause(AudioPause.CALL_FOCUS_LOST)
        }
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
