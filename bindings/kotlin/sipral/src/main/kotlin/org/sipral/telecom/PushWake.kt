// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.telecom

import org.sipral.SipralRegistrationState
import org.sipral.idiomatic.SipralAccount
import org.sipral.idiomatic.SipralClient
import org.sipral.idiomatic.SipralLifecycle

/** What [wakeForPush] did: the call it raised, and whether the account
 * carried on the last process's registration or registers from the
 * beginning. */
data class PushWake(val id: String, val restored: Boolean)

/**
 * A push for a call, handled in a process the push itself started, in the
 * order `docs/15-mobile.md` gives it:
 *
 * 1. [SipralClient.coldStart], so that [SipralAccount.timeToReadyMs]
 *    measures this wake;
 * 2. the account's registration read back from the last process
 *    ([SipralLifecycle.restore], with how long it sat): `RESTORED`, the
 *    same `Call-ID` and the next sequence number, nothing sent yet;
 * 3. the call shown ringing ([TelecomBridge.pushArrived]) before anything
 *    has crossed the network, as the platform requires, which announces the
 *    caller (or, with a null [caller], a call on the account alone) and, on
 *    a restored account, sends the REGISTER that confirms the binding, the
 *    refresh RFC 8599 §5.5 has a woken device send;
 * 4. on an account with nothing to carry on, a registration from the
 *    beginning, unless the announce's own refresh already began one.
 *
 * [client] has just been opened and [account] just added under [key], the
 * key the lifecycle keeps it by; the bridge already collects the client's
 * events. The INVITE the push announced is matched to the ringing call when
 * it arrives (C2).
 */
fun wakeForPush(
    client: SipralClient,
    account: SipralAccount,
    bridge: TelecomBridge,
    lifecycle: SipralLifecycle,
    key: String,
    caller: String?,
    displayName: String? = null,
    callId: String? = null,
): PushWake {
    client.coldStart()
    val restored = lifecycle.restore(account, key)
    val id = bridge.pushArrived(account.handle, caller, displayName, callId)
    if (!restored && account.registrationState !in UNDER_WAY) {
        account.register()
    }
    return PushWake(id, restored)
}

private val UNDER_WAY = setOf(
    SipralRegistrationState.REGISTERING,
    SipralRegistrationState.REFRESHING,
    SipralRegistrationState.REGISTERED,
)
