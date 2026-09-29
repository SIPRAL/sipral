// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

package org.sipral.idiomatic

import org.sipral.Sipral
import org.sipral.SipralAccountConfig
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralRegistrationState
import org.sipral.SipralStatus

/**
 * `sipral_account_add`, and the entry points that take its handle.
 *
 * Built through [SipralClient.addAccount], never directly: a handle names
 * something only on the stack that minted it (`docs/08-ffi.md`), so
 * keeping the two together is what makes every method here safe to call
 * with nothing further to pass.
 */
class SipralAccount internal constructor(
    val client: SipralClient,
    val handle: Long,
    val aor: String,
    /** Where the account's requests go, `host:port`. */
    val registrarAddress: String,
    contact: String,
    /** The `Contact` the application wrote, or null when the account's is
     * the one this layer derives from the signalling socket. */
    private val givenContact: String?,
) {
    /** Where this account says it can be reached, as its `Contact` carries
     * it now: after [SipralClient.networkChanged], the new address. */
    @Volatile
    var contact: String = contact
        private set

    internal companion object {
        fun add(
            client: SipralClient,
            aor: String,
            registrarAddress: String,
            registrar: String?,
            contact: String?,
            displayName: String?,
            authUser: String?,
            authPassword: String?,
            expiresSeconds: Long,
            push: SipralPush?,
            sessionTimer: SipralSessionTimerChoice,
            privacy: Set<SipralPrivacy>,
            trustedPeers: List<String>,
            security: SipralAccountSecurity,
        ): SipralAccount {
            val written = contact ?: client.defaultContact(aor)
            val (timer, seconds) = sessionTimer.raw
            val config = SipralAccountConfig(
                aor = aor,
                registrar = registrar,
                contact = written,
                registrarAddress = registrarAddress,
                displayName = displayName,
                authUser = authUser,
                authPassword = authPassword,
                expiresSeconds = expiresSeconds,
                pushProvider = push?.provider,
                pushPrid = push?.prid,
                pushParam = push?.param,
                pushWakesItself = if (push?.wakesItself == true) 1L else 0L,
                sessionTimer = timer,
                sessionIntervalSeconds = seconds,
                privacy = SipralPrivacy.bits(privacy),
                trustedPeers = trustedPeers.takeIf { it.isNotEmpty() }?.joinToString(","),
                srtp = (security.srtp?.value ?: 0).toLong(),
                srtpSuites = security.srtpSuites.takeIf { it.isNotEmpty() }?.joinToString(","),
                stirVerification = (security.stirVerification?.value ?: 0).toLong(),
                stirKey = security.stirKey?.takeIf { it.isNotEmpty() },
                stirCertificateUrl = security.stirCertificateUrl,
                stirOrig = security.stirOrig,
                stirOrigid = security.stirOrigid,
                stirAttestation = (security.stirAttestation?.value ?: 0).toLong(),
            )
            val accountHandle = retryBusy { Sipral.accountAdd(client.handle, config) }
            return SipralAccount(client, accountHandle, aor, registrarAddress, written, contact)
        }
    }

    /**
     * `sipral_account_rebind` onto the signalling socket [local] the client
     * bound after a network change: a derived `Contact` names the new
     * socket; one the application wrote has the old address, wherever it
     * names it, replaced by the new host, and is otherwise left as written.
     */
    internal fun rebind(local: String, previous: String?) {
        val next = if (givenContact == null) {
            client.defaultContact(aor, local)
        } else if (previous != null && previous.isNotEmpty() && contact.contains(previous)) {
            contact.replace(previous, local.substringBeforeLast(':'))
        } else {
            contact
        }
        retryBusy {
            Sipral.accountRebind(
                client.handle, handle, /* SIPRAL_TRANSPORT_MAIN */ 0, registrarAddress, next, client.nowMs(),
            )
        }
        contact = next
    }

    /** `sipral_account_registration_state`, read fresh. */
    val registrationState: SipralRegistrationState
        get() = SipralRegistrationState.of(
            retryBusy { Sipral.accountRegistrationState(client.handle, handle) }.toInt(),
        ) ?: SipralRegistrationState.UNKNOWN

    /** Whether it was asked to register and not to unregister since: the
     * accounts a client signalling over TCP or TLS registers again once its
     * connection is made again. */
    @Volatile
    var wantsRegistration: Boolean = false
        private set

    /**
     * `sipral_account_register`. A no-op account refuses this. On a client
     * signalling over TCP or TLS whose connection is down
     * (`SipralStatus.TRANSPORT_DOWN`, already raised as
     * `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`) it is kept, and the REGISTER goes
     * the moment the connection is made again.
     */
    fun register() {
        wantsRegistration = true
        try {
            retryBusy { Sipral.accountRegister(client.handle, handle, client.nowMs()) }
        } catch (refused: SipralException) {
            if (refused.status != SipralStatus.TRANSPORT_DOWN) {
                throw refused
            }
        }
    }

    /** `sipral_account_unregister`. */
    fun unregister() {
        wantsRegistration = false
        retryBusy { Sipral.accountUnregister(client.handle, handle, client.nowMs()) }
    }

    /**
     * [register], suspended until the registration reaches a terminal
     * state -- `REGISTERED` or one of the failures -- rather than left for
     * the caller to poll [registrationState] itself. This is the ABI
     * completing through an event: `sipral_account_register` only enqueues
     * the REGISTER, and `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED` is where
     * the answer actually arrives, with the state already on it --
     * `event.payload.registration.state` -- so nothing here queries the
     * stack a second time for what the event that woke it already said.
     *
     * Subscribed before [register] runs, through [awaitNext], not after:
     * a terminal `REGISTRATION_CHANGED` for this account can arrive
     * within microseconds of the REGISTER going out, and `register()`
     * first, subscribe second would be free to miss it and then hang
     * until, or wrongly match, whatever this account's *next*
     * registration change happens to be -- a periodic refresh, a retry --
     * see [awaitNext]'s own note.
     */
    suspend fun registerAndWait(timeoutMs: Long = 10_000) {
        val (_, last) = client.events.awaitNext(
            timeoutMs = timeoutMs,
            matches = { it.kind == SipralEventKind.REGISTRATION_CHANGED.value.toLong() && it.account == handle && isTerminal(stateOf(it)) },
        ) { register() }
        val reached = stateOf(last)
        if (reached != SipralRegistrationState.REGISTERED) {
            val detail = last.message?.let { String(it, Charsets.UTF_8) }
            throw IllegalStateException(
                "account $aor did not register: $reached" + (detail?.let { "\n$it" } ?: ""),
            )
        }
    }

    private fun stateOf(event: SipralEvent): SipralRegistrationState =
        SipralRegistrationState.of(event.payload.registration.state.toInt()) ?: SipralRegistrationState.UNKNOWN

    private fun isTerminal(state: SipralRegistrationState): Boolean = when (state) {
        SipralRegistrationState.REGISTERED,
        SipralRegistrationState.FAILED,
        SipralRegistrationState.UNREGISTERED,
        -> true
        else -> false
    }

    /**
     * `sipral_account_announce`: a push said [caller] is calling on this
     * account (`docs/15-mobile.md`, "C2"). The binding is refreshed at once
     * as part of the same call, so nothing else needs asking for.
     *
     * [SipralAnnounced.Waiting] when the INVITE is still to come, and
     * [SipralAnnounced.Arrived] when it beat the push -- the call screen
     * just raised then belongs to that call handle.
     */
    fun announce(caller: String): SipralAnnounced {
        val (announcement, call) = retryBusy {
            Sipral.accountAnnounce(client.handle, handle, caller, client.nowMs())
        }
        return if (call != 0L) SipralAnnounced.Arrived(call) else SipralAnnounced.Waiting(announcement)
    }

    /** `sipral_account_refresh_binding`: the keep-alive wake-up RFC 8599
     * §5.5 describes, with no call announced. */
    fun refreshBinding() {
        retryBusy { Sipral.accountRefreshBinding(client.handle, handle, client.nowMs()) }
    }

    /** `sipral_account_remove`. Every call this account placed ends. */
    fun remove() {
        retryBusy { Sipral.accountRemove(client.handle, handle) }
        client.forgetAccount(handle)
    }
}

/**
 * The RFC 8599 parameters an account's REGISTER carries so that a proxy can
 * wake this device (`docs/15-mobile.md`, "RFC 8599 push parameters"):
 * `pn-provider` (`fcm` on Android), `pn-prid` (the device token) and
 * `pn-param` (for FCM, the project the token belongs to). [wakesItself]
 * is `+sip.pnsreg`, and is the application's fact to state.
 */
class SipralPush(
    val provider: String,
    val prid: String,
    val param: String? = null,
    val wakesItself: Boolean = false,
)

/** What [SipralAccount.announce] answered: exactly one of the two. */
sealed class SipralAnnounced {
    /** The INVITE has not arrived. `SIPRAL_EVENT_KIND_CALL_ANNOUNCED` will
     * come immediately before the `SIPRAL_EVENT_KIND_INCOMING_CALL` that
     * matches, or `SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING` when none does.
     * [SipralClient.forgetAnnouncement] takes this handle. */
    data class Waiting(val announcement: Long) : SipralAnnounced()

    /** The INVITE beat the push, and this is its call handle. */
    data class Arrived(val call: Long) : SipralAnnounced()
}
