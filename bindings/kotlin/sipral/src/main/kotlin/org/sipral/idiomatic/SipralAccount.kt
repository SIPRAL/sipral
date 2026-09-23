// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

package org.sipral.idiomatic

import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import org.sipral.Sipral
import org.sipral.SipralAccountConfig
import org.sipral.SipralEventKind
import org.sipral.SipralRegistrationState

/**
 * `sipral_account_add`, and the entry points that take its handle.
 *
 * Built through [SipralClient.addAccount], never directly: a handle names
 * something only on the stack that minted it (`docs/08-ffi.md`), so
 * keeping the two together is what makes every method here safe to call
 * with nothing further to pass.
 */
class SipralAccount internal constructor(val client: SipralClient, val handle: Long, val aor: String) {
    internal companion object {
        fun add(
            client: SipralClient,
            aor: String,
            registrarAddress: String,
            registrar: String?,
            contact: String,
            displayName: String?,
            authUser: String?,
            authPassword: String?,
            expiresSeconds: Long,
        ): SipralAccount {
            val config = SipralAccountConfig(
                aor = aor,
                registrar = registrar,
                contact = contact,
                registrarAddress = registrarAddress,
                displayName = displayName,
                authUser = authUser,
                authPassword = authPassword,
                expiresSeconds = expiresSeconds,
            )
            val accountHandle = retryBusy { Sipral.accountAdd(client.handle, config) }
            return SipralAccount(client, accountHandle, aor)
        }
    }

    /** `sipral_account_registration_state`, read fresh. */
    val registrationState: SipralRegistrationState
        get() = SipralRegistrationState.of(
            retryBusy { Sipral.accountRegistrationState(client.handle, handle) }.toInt(),
        ) ?: SipralRegistrationState.UNKNOWN

    /** `sipral_account_register`. A no-op account refuses this. */
    fun register() {
        retryBusy { Sipral.accountRegister(client.handle, handle, client.nowMs()) }
    }

    /** `sipral_account_unregister`. */
    fun unregister() {
        retryBusy { Sipral.accountUnregister(client.handle, handle, client.nowMs()) }
    }

    /**
     * [register], suspended until the registration reaches a terminal
     * state -- `REGISTERED` or one of the failures -- rather than left for
     * the caller to poll [registrationState] itself. This is the ABI
     * completing through an event: `sipral_account_register` only enqueues
     * the REGISTER, and `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED` is where
     * the answer actually arrives.
     */
    suspend fun registerAndWait(timeoutMs: Long = 10_000) {
        register()
        val last = withTimeout(timeoutMs) {
            client.events
                .filter { it.kind == SipralEventKind.REGISTRATION_CHANGED.value.toLong() && it.account == handle }
                .first { isTerminal(registrationState) }
        }
        val reached = registrationState
        if (reached != SipralRegistrationState.REGISTERED) {
            val detail = last.message?.let { String(it, Charsets.UTF_8) }
            throw IllegalStateException(
                "account $aor did not register: $reached" + (detail?.let { "\n$it" } ?: ""),
            )
        }
    }

    private fun isTerminal(state: SipralRegistrationState): Boolean = when (state) {
        SipralRegistrationState.REGISTERED,
        SipralRegistrationState.FAILED,
        SipralRegistrationState.UNREGISTERED,
        -> true
        else -> false
    }

    /** `sipral_account_remove`. Every call this account placed ends. */
    fun remove() {
        retryBusy { Sipral.accountRemove(client.handle, handle) }
    }
}
