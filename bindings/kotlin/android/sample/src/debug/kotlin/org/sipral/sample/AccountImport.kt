// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.sample

import android.content.Context
import java.io.File
import java.util.Properties

/**
 * Debug builds only: an account handed over by a file rather than typed,
 * so that a test run never types a password through adb (where a keystroke
 * that misses the field lands in whatever has the focus). The file is
 * written into the application's own files with `run-as`, which only a
 * debuggable build allows:
 *
 * ```sh
 * adb shell run-as org.sipral.sample sh -c 'cat > files/account-import.properties' < account.properties
 * ```
 *
 * with the keys `aor`, `registrar_address`, `registrar`, `transport`,
 * `auth_user`, `auth_password`, `stun` and `telecom` (`auto`,
 * `connection-service` or `core-telecom`). It is read once, when the
 * process starts, and deleted; the account then lives in [AccountStore],
 * its password sealed by the Keystore. The release build's
 * `AccountImport` reads nothing.
 */
object AccountImport {
    fun take(context: Context): AccountSettings? {
        val file = File(context.filesDir, "account-import.properties")
        if (!file.exists()) {
            return null
        }
        val read = Properties()
        try {
            file.inputStream().use { read.load(it) }
        } finally {
            file.delete()
        }
        return AccountSettings(
            aor = read.getProperty("aor", ""),
            registrarAddress = read.getProperty("registrar_address", ""),
            registrar = read.getProperty("registrar", ""),
            transport = read.getProperty("transport", "udp"),
            authUser = read.getProperty("auth_user", ""),
            authPassword = read.getProperty("auth_password", ""),
            stunServer = read.getProperty("stun", ""),
            telecom = read.getProperty("telecom", "auto"),
        )
    }
}
