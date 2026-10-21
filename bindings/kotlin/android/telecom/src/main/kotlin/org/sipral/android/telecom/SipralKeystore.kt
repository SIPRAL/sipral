// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.android.telecom

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.sipral.idiomatic.SipralSnapshotStore

/**
 * Bytes sealed with AES-256-GCM under a key the Android Keystore generates
 * and never lets out of it ([alias]): what is stored is the twelve-byte IV
 * and the ciphertext with its tag, so a copy of the application's files (a
 * backup, a device read at rest) carries nothing readable. Not
 * `EncryptedSharedPreferences`, which AndroidX has deprecated; this is the
 * Keystore directly, which is what it was a wrapper over.
 */
class SipralKeystoreBox(private val alias: String) {
    private fun key(): SecretKey {
        val keys = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keys.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    /** The IV, then the ciphertext and its tag. */
    fun seal(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        return cipher.iv + cipher.doFinal(plain)
    }

    /** The bytes back, or null when they cannot be read: damaged, or sealed
     * under a key this device's Keystore no longer has (a restore onto
     * another device, the key cleared). */
    fun open(sealed: ByteArray): ByteArray? {
        if (sealed.size <= IV_BYTES) {
            return null
        }
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed, 0, IV_BYTES))
            cipher.doFinal(sealed, IV_BYTES, sealed.size - IV_BYTES)
        } catch (_: GeneralSecurityException) {
            null
        }
    }

    /** [seal] for text, as base64 to keep in preferences; empty stays empty. */
    fun sealText(plain: String): String =
        if (plain.isEmpty()) "" else Base64.encodeToString(seal(plain.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)

    /** [open] for [sealText]'s form; empty when there is nothing readable. */
    fun openText(stored: String?): String {
        if (stored.isNullOrEmpty()) {
            return ""
        }
        val bytes = try {
            Base64.decode(stored, Base64.NO_WRAP)
        } catch (_: IllegalArgumentException) {
            return ""
        }
        return open(bytes)?.toString(Charsets.UTF_8) ?: ""
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
    }
}

/**
 * [SipralSnapshotStore] in the application's private preferences file
 * [name], every record sealed by a [SipralKeystoreBox]: where
 * `org.sipral.idiomatic.SipralLifecycle` keeps registrations between
 * processes on Android. A record that cannot be opened reads as absent, so
 * the account registers from the beginning.
 */
class SipralKeystoreStore(context: Context, name: String = "sipral.registrations") : SipralSnapshotStore {
    private val prefs = context.getSharedPreferences(name, Context.MODE_PRIVATE)
    private val box = SipralKeystoreBox("sipral.registrations")

    override fun write(key: String, record: ByteArray) {
        // commit, not apply: this runs on the way into the background, and a
        // process frozen right after must find the record on disk
        prefs.edit().putString(key, Base64.encodeToString(box.seal(record), Base64.NO_WRAP)).commit()
    }

    override fun read(key: String): ByteArray? {
        val stored = prefs.getString(key, null) ?: return null
        val sealed = try {
            Base64.decode(stored, Base64.NO_WRAP)
        } catch (_: IllegalArgumentException) {
            return null
        }
        return box.open(sealed)
    }

    override fun remove(key: String) {
        prefs.edit().remove(key).commit()
    }
}
