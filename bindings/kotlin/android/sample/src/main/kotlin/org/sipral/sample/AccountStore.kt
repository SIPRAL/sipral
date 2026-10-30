// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.sample

import android.content.Context
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException
import org.sipral.android.telecom.SipralKeystoreBox
import org.sipral.android.telecom.SipralTelecomAdapter

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
    /** Which telecom adapter carries the calls: `auto` (the library's choice
     * for this release), `connection-service` or `core-telecom`; read when
     * the stack opens. */
    val telecom: String = "auto",
) {
    /** The two passwords, for whatever must never carry them. */
    val secrets: List<String> get() = listOf(authPassword, turnPassword).filter { it.isNotEmpty() }
}

/** The adapter [AccountSettings.telecom] names on API level [sdk]; `auto`,
 * or anything else, is the library's choice for that release. */
fun telecomAdapterOf(setting: String, sdk: Int): SipralTelecomAdapter = when (setting) {
    "connection-service" -> SipralTelecomAdapter.CONNECTION_SERVICE
    "core-telecom" -> SipralTelecomAdapter.CORE_TELECOM
    else -> SipralTelecomAdapter.preferred(sdk)
}

/**
 * What the dial pad typed, as a URI, read as the iPhone sample reads it: a
 * `sip:`, `sips:` or `tel:` URI as typed, `user@host` as `sip:user@host`,
 * and a bare number or name (`100`, `*43`) as a user at the domain of the
 * address of record [aor].
 */
fun dialTarget(typed: String, aor: String): String {
    val trimmed = typed.trim()
    if (SCHEMES.any { trimmed.startsWith(it, ignoreCase = true) }) {
        return trimmed
    }
    if ('@' in trimmed) {
        return "sip:$trimmed"
    }
    return "sip:$trimmed@${domainOf(aor)}"
}

/** The host part of an address of record, with its port if it has one. */
internal fun domainOf(aor: String): String {
    var uri = aor.trim().removePrefix("<").substringBefore('>')
    SCHEMES.firstOrNull { uri.startsWith(it, ignoreCase = true) }?.let { uri = uri.substring(it.length) }
    return uri.substringAfter('@').substringBefore(';').substringBefore('?')
}

private val SCHEMES = listOf("sip:", "sips:", "tel:")

/** The registrar field split into host and port: `host:port`, a host
 * being a name or an IPv4 address, or `[IPv6]:port`. Null when it is
 * neither. */
fun hostPortOf(text: String): Pair<String, Int>? {
    val trimmed = text.trim()
    val (host, port) = if (trimmed.startsWith("[")) {
        val close = trimmed.indexOf(']')
        if (close < 0 || !trimmed.startsWith("]:", close)) {
            return null
        }
        trimmed.substring(1, close) to trimmed.substring(close + 2)
    } else {
        val colon = trimmed.indexOf(':')
        if (colon < 0 || colon != trimmed.lastIndexOf(':')) {
            return null
        }
        trimmed.substring(0, colon) to trimmed.substring(colon + 1)
    }
    val number = port.toIntOrNull()?.takeIf { it in 1..65_535 } ?: return null
    return if (host.isEmpty()) null else host to number
}

/**
 * The registrar field as the address the library's `registrarAddress`
 * takes: a host name looked up by [lookup] (A and AAAA, the platform's
 * resolver), an IPv4 address preferred since the sample binds on one, and
 * an address given as it is. Blocks on the lookup, so it runs off the main
 * thread. Throws `IllegalArgumentException` for a field that is not
 * `host:port` and `UnknownHostException` for a name that does not resolve.
 */
fun registrarAddressOf(text: String, lookup: (String) -> Array<InetAddress> = InetAddress::getAllByName): String {
    val (host, port) = hostPortOf(text)
        ?: throw IllegalArgumentException("the registrar \"${text.trim()}\" is not host:port")
    val found = lookup(host)
    val chosen = found.firstOrNull { it is Inet4Address } ?: found.firstOrNull() ?: throw UnknownHostException(host)
    return if (chosen is Inet6Address) "[${chosen.hostAddress}]:$port" else "${chosen.hostAddress}:$port"
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
        telecom = prefs.getString("telecom", "auto") ?: "auto",
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
            .putString("telecom", settings.telecom)
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
