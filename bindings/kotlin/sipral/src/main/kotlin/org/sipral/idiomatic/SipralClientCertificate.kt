// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The certificate this end presents when a TLS server asks for one, with its
// private key left where the platform keeps it: an Android Keystore alias, or
// an entry of any java.security.KeyStore. The key is only ever handed to
// javax.net.ssl as the provider's own object, which signs the handshake; its
// bytes are never read.

package org.sipral.idiomatic

import java.net.Socket
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedKeyManager
import org.sipral.SipralTlsFailure
import org.sipral.SipralTransportError

/**
 * A client certificate for SIP over TLS, TURN over TLS and a secure
 * WebSocket (`docs/22-tls.md`, "A client certificate"). Each connection
 * reads the entry again, so a certificate renewed under the same alias is
 * presented from the next connection on.
 *
 * - [androidKeystore]: an alias in the Android Keystore
 *   (`KeyStore.getInstance("AndroidKeyStore")`), where the key may live in
 *   the TEE or StrongBox and may require the user to have unlocked the
 *   device. The `PrivateKey` is the keystore's handle; every signature is
 *   made inside the keystore.
 * - [keyStore]: an entry of a [KeyStore] the application loaded, such as a
 *   PKCS#12 file on a desktop JVM, or a store of a hardware provider.
 *
 * Before each connection the entry is checked: no such alias, no private
 * key under it or a key that cannot be recovered is
 * `SipralTlsFailure.CLIENT_KEY_UNAVAILABLE`; a leaf certificate outside
 * its dates is `CLIENT_CERTIFICATE_EXPIRED`; either is told to the stack
 * without connecting.
 */
class SipralClientCertificate private constructor(
    private val opened: () -> KeyStore,
    /** The alias the key and its chain are under. */
    val alias: String,
    private val password: CharArray?,
    /** What tells this certificate apart for the stack, the same for as
     * long as this object lives (`sipral_account_config_t::tls_client_tag`):
     * accounts whose tags match share a TLS connection, and the others never
     * do, since a connection presents one certificate. */
    internal val tag: String,
) {
    companion object {
        /** Numbers the entries whose certificate could not be read when they
         * were named, each a tag of its own. */
        private val unread = java.util.concurrent.atomic.AtomicLong()

        private fun digest(bytes: ByteArray): String =
            java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

        /** The Android Keystore's entry [alias]: a key made there with
         * `KeyPairGenerator.getInstance("EC", "AndroidKeyStore")`, its chain
         * set with `setKeyEntry` once the authority signed it. Told apart by
         * its alias, the one Keystore having one entry under each. */
        fun androidKeystore(alias: String): SipralClientCertificate =
            SipralClientCertificate(
                { KeyStore.getInstance("AndroidKeyStore").apply { load(null) } }, alias, null,
                "android-keystore " + digest(alias.toByteArray(Charsets.UTF_8)),
            )

        /** The entry [alias] of [store], already loaded, its key protected
         * by [password] (null for a store that keeps keys unprotected or
         * protects them itself). Told apart by its leaf certificate as the
         * store holds it now. */
        fun keyStore(store: KeyStore, alias: String, password: CharArray? = null): SipralClientCertificate {
            val leaf = runCatching { store.getCertificate(alias)?.encoded }.getOrNull()
            val tag = leaf?.let { "leaf " + digest(it) } ?: "entry ${unread.incrementAndGet()}"
            return SipralClientCertificate({ store }, alias, password, tag)
        }
    }

    /** The key and its chain, leaf first, or why they cannot be presented. */
    internal fun load(nowMs: Long = System.currentTimeMillis()): Pair<PrivateKey, Array<X509Certificate>> {
        val (key, chain) = try {
            val store = opened()
            val key = store.getKey(alias, password)
                ?: throw unavailable("no key under the alias $alias")
            val chain = store.getCertificateChain(alias)?.map { it as X509Certificate }?.toTypedArray()
            if (key !is PrivateKey) {
                throw unavailable("the entry $alias holds no private key")
            }
            if (chain.isNullOrEmpty()) {
                throw unavailable("the entry $alias holds no certificate")
            }
            key to chain
        } catch (refused: SignallingRefused) {
            throw refused
        } catch (failed: Exception) {
            throw unavailable("the key under $alias could not be opened: ${failed.message ?: failed.javaClass.simpleName}")
        }
        try {
            chain[0].checkValidity(java.util.Date(nowMs))
        } catch (dated: CertificateExpiredException) {
            throw SignallingRefused(
                SipralTransportError.OTHER, SipralTlsFailure.CLIENT_CERTIFICATE_EXPIRED,
                sentence("the client certificate $alias expired on ${chain[0].notAfter}"),
            )
        } catch (dated: CertificateNotYetValidException) {
            throw SignallingRefused(
                SipralTransportError.OTHER, SipralTlsFailure.CLIENT_CERTIFICATE_EXPIRED,
                sentence("the client certificate $alias is not valid before ${chain[0].notBefore}"),
            )
        }
        return key to chain
    }

    private fun unavailable(why: String) =
        SignallingRefused(SipralTransportError.OTHER, SipralTlsFailure.CLIENT_KEY_UNAVAILABLE, sentence(why))

    override fun toString(): String = "SipralClientCertificate(alias=$alias)"
}

/**
 * What one connection's handshake did about a client certificate: whether
 * the server asked for one, and whether this end gave it. Read when the
 * connection fails, to tell a server that wanted a certificate from one
 * that refused the certificate it was given.
 */
internal class ClientAuthentication {
    val asked = AtomicBoolean(false)
    val presented = AtomicBoolean(false)

    fun reset() {
        asked.set(false)
        presented.set(false)
    }
}

/**
 * The key manager every TLS connection of this layer is made with: it
 * offers [chain] and [key] when given them, and nothing otherwise, and in
 * both cases records in [seen] that the server asked.
 */
internal class Presenting(
    private val key: PrivateKey?,
    private val chain: Array<X509Certificate>?,
    private val seen: ClientAuthentication,
) : X509ExtendedKeyManager() {
    private fun choose(keyTypes: Array<out String>?): String? {
        seen.asked.set(true)
        val algorithm = key?.algorithm ?: return null
        val fits = keyTypes == null || keyTypes.any { it.equals(algorithm, ignoreCase = true) || it.startsWith("${algorithm}_") }
        if (!fits) {
            return null
        }
        seen.presented.set(true)
        return ALIAS
    }

    override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?): String? =
        choose(keyType)

    override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?): String? =
        choose(keyType)

    override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? =
        if (key != null) arrayOf(ALIAS) else null

    override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null

    override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?): String? = null

    override fun getCertificateChain(alias: String?): Array<X509Certificate>? = if (alias == ALIAS) chain else null

    override fun getPrivateKey(alias: String?): PrivateKey? = if (alias == ALIAS) key else null

    private companion object {
        const val ALIAS = "sipral-client"
    }
}
