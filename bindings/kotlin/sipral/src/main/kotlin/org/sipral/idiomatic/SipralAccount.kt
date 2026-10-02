// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

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
import org.sipral.SipralToggle
import org.sipral.SipralTransport

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
    registrarAddress: String,
    contact: String,
    /** The `Contact` the application wrote, or null when the account's is
     * the one this layer derives from the signalling socket. */
    private val givenContact: String?,
    /** The server named by a URI RFC 3263 locates, or null. */
    val serverUri: String? = null,
    /** The protocol of the connection of its own the account's requests go
     * over, [SipralTransport.TCP] or [SipralTransport.TLS], or null for the
     * client's own transport ([SipralClient.addAccount]'s `streamProtocol`). */
    val streamProtocol: SipralTransport? = null,
    /** The certificate pin it was added with, which a TLS connection of its
     * own is held to. */
    internal val tlsPin: String? = null,
) {
    /** Where the account's requests go, `host:port`: the address it was
     * added with, or -- for one added with a [serverUri] -- the address it
     * was last located at, empty until then. */
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
     * `sipral_account_check_certificate`: the verdict of this account's
     * `tlsPin` on [certificate], the DER bytes of the leaf a TLS server
     * presented, from inside the application's own certificate check. The
     * certificate's dates when it is the pinned one -- accept the handshake
     * whoever signed it, an expired one included; null when the account pins
     * nothing and the platform's own checks decide; a [SipralException] with
     * `CERTIFICATE_REFUSED` when it pins another.
     */
    fun checkCertificate(certificate: ByteArray, unixSeconds: Long = System.currentTimeMillis() / 1000): SipralPinnedCertificate? {
        val found = retryBusy { Sipral.accountCheckCertificate(client.handle, handle, certificate, unixSeconds) }
        return if (found.pinned == 0L) null else found
    }

    /** How an account names and keeps its server, beside the registrar's
     * address: the ABI 0.34 members of `sipral_account_config_t`, and the
     * address this layer chose for its `Contact`. */
    internal class Location(
        val serverUri: String?,
        val serverNaptr: Boolean,
        val keepaliveMs: Long,
        val tlsPin: String?,
        val advertised: String?,
        val streamProtocol: SipralTransport? = null,
        val realms: List<String> = emptyList(),
    )
    /** Where this account says it can be reached, as its `Contact` carries
     * it now: after [SipralClient.networkChanged], the new address. */
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
            )
            val accountHandle = retryBusy { Sipral.accountAdd(client.handle, config) }
            return SipralAccount(
                client, accountHandle, aor, registrarAddress ?: "", written, contact, location.serverUri,
                location.streamProtocol, location.tlsPin,
            )
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

    // -- subscriptions and presence ------------------------------------------

    /**
     * `sipral_account_subscribe` (RFC 6665): watch [target], a SIP URI, for
     * the event [package] -- `presence` (RFC 3856), `conference` (RFC 4575),
     * `dialog` for a busy lamp field, `message-summary` -- from this account.
     * [accept] is the `Accept` value when the package's default body type is
     * not the one wanted, [expiresSeconds] how long to ask for (zero for an
     * hour), and [destination] (`host:port`) where to send the SUBSCRIBE when
     * not where the account registers.
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
     * Watch [target]'s presence (RFC 3856): a `presence` subscription asking
     * for PIDF, whose every notification arrives as
     * `SIPRAL_EVENT_KIND_PRESENCE_CHANGED` with [presenceOf]'s `kind`
     * `WATCHED`: open or closed, the activity, the presentity and its note.
     */
    fun watchPresence(target: String, expiresSeconds: Long = 0, destination: String? = null): SipralSubscription =
        subscribe(target, "presence", "application/pidf+xml", expiresSeconds, destination)

    /**
     * `sipral_account_publish_presence` (RFC 3903): publish this account's
     * presence to its registrar as the presence compositor; the first call
     * publishes and every later one modifies the same publication, which the
     * stack keeps refreshed until [unpublishPresence]. What the compositor
     * did with it arrives as `SIPRAL_EVENT_KIND_PRESENCE_CHANGED` with
     * [presenceOf]'s `kind` `PUBLICATION`, naming this account.
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

/**
 * A challenge an account's password was not given to
 * (`SIPRAL_EVENT_KIND_CHALLENGE_DECLINED`): why ([refusal], null for a
 * reason this build has no name for), where the challenged request went
 * ([server], `host:port`), and every realm it was challenged for.
 */
class SipralDeclinedChallenge(
    val refusal: SipralChallengeRefusal?,
    val server: String?,
    val realms: List<String>,
)

/**
 * The `SIPRAL_EVENT_KIND_CHALLENGE_DECLINED` payload, its realms one per
 * line in C read as a list, or null for an event of any other kind.
 */
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
