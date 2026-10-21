// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.sample

import android.content.Context
import org.sipral.android.telecom.SipralKeystoreBox

/** What the account screen holds, as typed. */
data class AccountSettings(
    val aor: String = "",
    val registrarAddress: String = "",
    val registrar: String = "",
    val transport: String = "udp",
    val authUser: String = "",
    val authPassword: String = "",
    val stunServer: String = "",
    val turnServer: String = "",
    val turnUser: String = "",
    val turnPassword: String = "",
) {
    /** The two passwords, for whatever must never carry them. */
    val secrets: List<String> get() = listOf(authPassword, turnPassword).filter { it.isNotEmpty() }
}

/**
 * The account, kept between runs of the process. The passwords are sealed
 * by a [SipralKeystoreBox], under an AES-256-GCM key the Android Keystore
 * holds and never lets out: the preferences file has only their
 * ciphertext. Everything else is plain: an address of record and a server
 * name are not secrets. The registration itself is kept by
 * `SipralLifecycle` in a `SipralKeystoreStore`, sealed the same way. Backups
 * are turned off in the manifest, so none of it leaves the device that way.
 */
class AccountStore(context: Context) {
    private val prefs = context.getSharedPreferences("account", Context.MODE_PRIVATE)
    private val box = SipralKeystoreBox("sipral-sample-account")

    fun load(): AccountSettings = AccountSettings(
        aor = prefs.getString("aor", "") ?: "",
        registrarAddress = prefs.getString("registrar_address", "") ?: "",
        registrar = prefs.getString("registrar", "") ?: "",
        transport = prefs.getString("transport", "udp") ?: "udp",
        authUser = prefs.getString("auth_user", "") ?: "",
        authPassword = box.openText(prefs.getString("auth_password", null)),
        stunServer = prefs.getString("stun", "") ?: "",
        turnServer = prefs.getString("turn", "") ?: "",
        turnUser = prefs.getString("turn_user", "") ?: "",
        turnPassword = box.openText(prefs.getString("turn_password", null)),
    )

    fun save(settings: AccountSettings) {
        prefs.edit()
            .putString("aor", settings.aor)
            .putString("registrar_address", settings.registrarAddress)
            .putString("registrar", settings.registrar)
            .putString("transport", settings.transport)
            .putString("auth_user", settings.authUser)
            .putString("auth_password", box.sealText(settings.authPassword))
            .putString("stun", settings.stunServer)
            .putString("turn", settings.turnServer)
            .putString("turn_user", settings.turnUser)
            .putString("turn_password", box.sealText(settings.turnPassword))
            .apply()
    }

    /** Whether the account was registered when the process last ran, so a
     * new process registers it again by itself. */
    var keepRegistered: Boolean
        get() = prefs.getBoolean("keep_registered", false)
        set(value) {
            prefs.edit().putBoolean("keep_registered", value).apply()
        }
}
