// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.idiomatic

import org.sipral.Sipral
import org.sipral.SipralAccountConfig
import org.sipral.SipralChallengeRefusal
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralPinnedCertificate
import org.sipral.SipralPresence
import org.sipral.SipralRegistrationState
import org.sipral.SipralStatus
import org.sipral.SipralSubscribeConfig
import org.sipral.SipralTokenError
import org.sipral.SipralToggle
import org.sipral.SipralTransport

/**
 * `sipral_account_add`, and the entry points that take its handle.
 *
 * Built only through [SipralClient.addAccount]: a handle is valid only on
 * the stack that minted it (`docs/08-ffi.md`), so the account keeps its
 * client.
 */
class SipralAccount internal constructor(
    val client: SipralClient,
    val handle: Long,
    val aor: String,
    registrarAddress: String,
    contact: String,
    /** The `Contact` the application wrote, or null when this layer derives
     * it from the signalling socket. */
    private val givenContact: String?,
    /** The server named by a URI RFC 3263 locates, or null. */
    val serverUri: String? = null,
    /** TCP, TLS, WS or WSS for an account on its own connection, or null for
     * the client's transport. */
    val streamProtocol: SipralTransport? = null,
    /** The certificate pin a TLS connection of its own is held to. */
    internal val tlsPin: String? = null,
) {
    /** Where requests go, `host:port`: the address it was added with, or for a
     * [serverUri] account the last located address (empty until then). */
    @Volatile
    var registrarAddress: String = registrarAddress
        private set

    /** Whether its `Contact` is the one this layer derives. */
    internal val derivesContact: Boolean
        get() = givenContact == null

    /** The account's server was located at [target]. */
    internal fun located(target: String) {
        registrarAddress = target
    }

    /** `sipral_account_rebind` toward [remote], reached at [advertised]
     * (`host:port`), unless its `Contact` names that already. */
    internal fun reach(advertised: String, remote: String) {
        val next = client.defaultContact(aor, advertised, streamProtocol)
        if (next == contact) {
            return
        }
        retryBusy {
            Sipral.accountRebind(client.handle, handle, /* SIPRAL_TRANSPORT_MAIN */ 0, remote, next, client.nowMs())
        }
        contact = next
    }

    /**
     * `sipral_account_check_certificate`: this account's `tlsPin` verdict on
     * [certificate] (the leaf's DER), from inside the application's own
     * certificate check. Returns the certificate's dates when it is the pinned
     * one (accept it whoever signed it, even expired); null when nothing is
     * pinned and the platform decides; throws `CERTIFICATE_REFUSED` when
     * another is pinned.
     */
    fun checkCertificate(certificate: ByteArray, unixSeconds: Long = System.currentTimeMillis() / 1000): SipralPinnedCertificate? {
        val found = retryBusy { Sipral.accountCheckCertificate(client.handle, handle, certificate, unixSeconds) }
        return if (found.pinned == 0L) null else found
    }

    /** How an account names and keeps its server, beside the registrar's
     * address, and the address this layer chose for its `Contact`. */
    internal class Location(
        val serverUri: String?,
        val serverNaptr: Boolean,
        val keepaliveMs: Long,
        val tlsPin: String?,
        val advertised: String?,
        val streamProtocol: SipralTransport? = null,
        val realms: List<String> = emptyList(),
        val websocketHost: String? = null,
        val websocketResource: String? = null,
    )
    /** The account's current `Contact` address; after
     * [SipralClient.networkChanged], the new one. */
    @Volatile
    var contact: String = contact
        private set

    internal companion object {
        fun add(
            client: SipralClient,
            aor: String,
            registrarAddress: String?,
            location: Location,
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
            val written = contact ?: if (location.advertised != null) {
                client.defaultContact(aor, location.advertised, location.streamProtocol)
            } else {
                client.defaultContact(aor, stream = location.streamProtocol)
            }
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
                recordingInClear = if (security.recordingInClear) SipralToggle.ON.value.toLong() else 0,
                keepaliveMs = location.keepaliveMs,
                serverUri = location.serverUri,
                tlsPinSha256 = location.tlsPin,
                serverNaptr = if (location.serverNaptr) SipralToggle.ON.value.toLong() else 0,
                streamProtocol = (location.streamProtocol?.value ?: 0).toLong(),
                realms = location.realms.takeIf { it.isNotEmpty() }?.joinToString("\n"),
                websocketHost = location.websocketHost,
                websocketResource = location.websocketResource,
            )
            val accountHandle = retryBusy { Sipral.accountAdd(client.handle, config) }
            return SipralAccount(
                client, accountHandle, aor, registrarAddress ?: "", written, contact, location.serverUri,
                location.streamProtocol, location.tlsPin,
            )
        }
    }

    /**
     * `sipral_account_rebind` onto the new signalling socket [local] after a
     * network change. A derived `Contact` names the new socket; an
     * application-written one has the old address replaced by the new host and
     * is otherwise kept.
     */
    internal fun rebind(local: String, previous: String?) {
        val next = if (givenContact == null) {
            client.defaultContact(aor, local, streamProtocol)
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

    /** Asked to register and not since to unregister: a TCP/TLS client
     * re-registers these after reconnecting. */
    @Volatile
    var wantsRegistration: Boolean = false
        private set

    /**
     * `sipral_account_set_access_token`: the OAuth 2.0 access token the server
     * asked for (RFC 8898), replacing any previous one; null removes it. The
     * answer to `SIPRAL_EVENT_KIND_TOKEN_REQUIRED` ([tokenRequiredOf]) and the
     * way to renew: the next `Bearer` challenge is answered with it. A
     * registration that failed for lack of one restarts with [register].
     * `SipralStatus.INVALID_ARGUMENT`, changing nothing, for a token that is
     * not an RFC 6750 `b64token`.
     */
    fun setAccessToken(token: String?) {
        retryBusy { Sipral.accountSetAccessToken(client.handle, handle, token ?: "") }
    }

    /**
     * `sipral_account_register`. A no-op account refuses this. On a TCP/TLS
     * client whose connection is down (`TRANSPORT_DOWN`, already raised as
     * `TRANSPORT_FAILED`) the request is kept and sent on reconnect.
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

    /**
     * `sipral_account_unregister`: a REGISTER with Expires: 0.
     *
     * The state reads unregistered as soon as this returns; the registrar's
     * answer is the following registration-changed event. Wait for it before
     * closing the stack, which otherwise cannot answer a challenge to the
     * un-REGISTER.
     */
    fun unregister() {
        wantsRegistration = false
        retryBusy { Sipral.accountUnregister(client.handle, handle, client.nowMs()) }
    }

    /**
     * [register], suspended until the registration is `REGISTERED` or failed.
     * `sipral_account_register` only queues the REGISTER; the outcome arrives
     * in `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED`, state included.
     *
     * Subscribes through [awaitNext] before [register] runs: the answer can
     * arrive microseconds after the REGISTER leaves, and subscribing after
     * would miss it and then hang or match a later refresh.
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
     * account (`docs/15-mobile.md`, "C2"). The binding is refreshed by the
     * same call.
     *
     * [SipralAnnounced.Waiting] when the INVITE is still to come;
     * [SipralAnnounced.Arrived] when it beat the push, and the call screen
     * just raised belongs to that handle.
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

    // Subscriptions and presence

    /**
     * `sipral_account_subscribe` (RFC 6665): watch [target] for the event
     * [package] (`presence` RFC 3856, `conference` RFC 4575, `dialog` for a
     * busy lamp field, `message-summary`). [accept] overrides the package's
     * default body type, [expiresSeconds] is the requested duration (zero for
     * an hour), and [destination] (`host:port`) is where the SUBSCRIBE goes
     * when not to the registrar.
     */
    fun subscribe(
        target: String,
        `package`: String,
        accept: String? = null,
        expiresSeconds: Long = 0,
        destination: String? = null,
    ): SipralSubscription {
        val config = SipralSubscribeConfig(
            target = target,
            `package` = `package`,
            accept = accept,
            expiresSeconds = expiresSeconds,
            destination = destination,
        )
        val made = retryBusy { Sipral.accountSubscribe(client.handle, handle, config, client.nowMs()) }
        return SipralSubscription(client, made, `package`)
    }

    /**
     * Watch [target]'s presence (RFC 3856) with PIDF. Each notification is a
     * `SIPRAL_EVENT_KIND_PRESENCE_CHANGED` whose [presenceOf] `kind` is
     * `WATCHED`.
     */
    fun watchPresence(target: String, expiresSeconds: Long = 0, destination: String? = null): SipralSubscription =
        subscribe(target, "presence", "application/pidf+xml", expiresSeconds, destination)

    /**
     * `sipral_account_publish_presence` (RFC 3903): publish to the registrar
     * as presence compositor. Later calls modify the same publication, which
     * the stack refreshes until [unpublishPresence]. The outcome arrives as
     * `SIPRAL_EVENT_KIND_PRESENCE_CHANGED` with `kind` `PUBLICATION`.
     */
    fun publishPresence(presence: SipralPublishedPresence) {
        val document = SipralPresence(
            basic = presence.basic.value.toLong(),
            activity = presence.activity.value.toLong(),
            note = presence.note,
        )
        retryBusy { Sipral.accountPublishPresence(client.handle, handle, document, client.nowMs()) }
    }

    /** `sipral_account_unpublish_presence`: take the published presence
     * away; `REMOVED` says when it is gone. `WRONG_STATE` when nothing is
     * published. */
    fun unpublishPresence() {
        retryBusy { Sipral.accountUnpublishPresence(client.handle, handle, client.nowMs()) }
    }
}

/**
 * The RFC 8599 parameters a REGISTER carries so a proxy can wake this
 * device (`docs/15-mobile.md`): `pn-provider` (`fcm` on Android),
 * `pn-prid` (the device token) and `pn-param` (for FCM, the token's
 * project). [wakesItself] is `+sip.pnsreg`, the application's to state.
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

/**
 * A challenge the account's password was not given to
 * (`SIPRAL_EVENT_KIND_CHALLENGE_DECLINED`): why ([refusal], null when this
 * build has no name for it), where the request went ([server]), and every
 * realm challenged.
 */
class SipralDeclinedChallenge(
    val refusal: SipralChallengeRefusal?,
    val server: String?,
    val realms: List<String>,
)

/** The `CHALLENGE_DECLINED` payload with its realms as a list, or null for
 * another kind. */
fun declinedChallengeOf(event: SipralEvent): SipralDeclinedChallenge? {
    if (event.kind != SipralEventKind.CHALLENGE_DECLINED.value.toLong()) {
        return null
    }
    val told = event.payload.challenge
    return SipralDeclinedChallenge(
        SipralChallengeRefusal.of(told.refusal.toInt()),
        told.server,
        told.realms?.split('\n')?.filter { it.isNotEmpty() } ?: emptyList(),
    )
}

/**
 * The server asking for an OAuth 2.0 access token
 * (`SIPRAL_EVENT_KIND_TOKEN_REQUIRED`, RFC 8898): what was wrong with the
 * last ([error], `INVALID_TOKEN` when expired or revoked; [errorCode] as
 * written), whether a proxy asked, where the request went ([server]), the
 * [realm], the required [scope] and the [authzServer]. Check [authzServer]
 * against the servers the application trusts before contacting it, then
 * pass the token to [SipralAccount.setAccessToken].
 */
class SipralTokenRequired(
    val error: SipralTokenError?,
    val errorCode: String?,
    val proxy: Boolean,
    val server: String?,
    val realm: String,
    val scope: String?,
    val authzServer: String?,
)

/** The `TOKEN_REQUIRED` payload, or null for another kind. */
fun tokenRequiredOf(event: SipralEvent): SipralTokenRequired? {
    if (event.kind != SipralEventKind.TOKEN_REQUIRED.value.toLong()) {
        return null
    }
    val told = event.payload.token
    return SipralTokenRequired(
        SipralTokenError.of(told.error.toInt()),
        told.errorCode?.takeIf { it.isNotEmpty() },
        told.proxy == SipralToggle.ON.value.toLong(),
        told.server,
        told.realm ?: "",
        told.scope?.takeIf { it.isNotEmpty() },
        told.authzServer?.takeIf { it.isNotEmpty() },
    )
}
