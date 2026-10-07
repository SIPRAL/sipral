// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The three seams TelecomBridge talks through: the telecom framework, one
// call it shows, and the SIP side. Each is small enough to fake on a plain
// JVM, where docs/15-mobile.md's "C2" sequence is tested. The Android
// adapters in bindings/kotlin/android/telecom implement the first two;
// IdiomaticSipCalls the third.

package org.sipral.telecom

import org.sipral.idiomatic.SipralAnnounced

/**
 * What [TelecomBridge] asks of the telecom framework.
 *
 * On Android: `TelecomManager.addNewIncomingCall` and `placeCall` for a
 * self-managed `PhoneAccount`. Both answer later, by creating a connection
 * for [id] (passed to [TelecomBridge.connectionCreated]) or refusing
 * ([TelecomBridge.connectionFailed]).
 */
interface TelecomPlatform {
    /** A call is ringing, or a push says one is about to. Must be called
     * before the push handler that triggered it returns. */
    fun reportIncomingCall(id: String, caller: String, displayName: String?)

    /** The application wants to place a call; the framework decides
     * whether it may. */
    fun placeOutgoingCall(id: String, target: String)
}

/**
 * What [TelecomBridge] tells one call the framework is showing. On Android,
 * a self-managed `android.telecom.Connection`.
 */
interface TelecomConnection {
    fun setRinging()
    fun setDialing()
    fun setActive()
    fun setOnHold()

    /** The far end put this call on hold, or took it off. Android has a
     * connection event for each (`EVENT_CALL_REMOTELY_HELD`,
     * `EVENT_CALL_REMOTELY_UNHELD`) and no state. */
    fun setRemoteHold(held: Boolean)

    /** The call is over as far as the framework is concerned; the
     * connection is destroyed after this and told nothing more. */
    fun setDisconnected(cause: TelecomDisconnect)
}

/** Why a call left the framework. One for each `DisconnectCause` code a
 * self-managed connection has a use for. */
enum class TelecomDisconnect {
    /** This end hung up. */
    LOCAL,

    /** The far end hung up. */
    REMOTE,

    /** This end declined a call that was ringing. */
    REJECTED,

    /** A call that rang and was not answered: the caller gave up, or a
     * push announced a call whose INVITE never came. */
    MISSED,

    /** The far end was busy (486, 600). */
    BUSY,

    /** Withdrawn before it was ever a call: a duplicate screen for a call
     * that already had one. */
    CANCELED,

    /** Anything else: a failure response, or a step that threw. */
    ERROR,
}

/**
 * The SIP half, by handle. [IdiomaticSipCalls] implements it over
 * [org.sipral.idiomatic.SipralClient]; a test implements it with a
 * recorder.
 */
interface SipCalls {
    /** `sipral_account_announce`. */
    fun announce(account: Long, caller: String): SipralAnnounced

    /** `sipral_announcement_forget`. Throws `SipralException` with
     * `WRONG_STATE` when the announcement was already fulfilled or had
     * expired. */
    fun forgetAnnouncement(announcement: Long)

    fun answer(call: Long)
    fun reject(call: Long, code: Long)

    /** `sipral_call_place`; the new call's handle. */
    fun place(account: Long, target: String): Long
    fun hangup(call: Long)
    fun hold(call: Long)
    fun resume(call: Long)
    fun sendDtmf(call: Long, digits: String)

    /** `sipral_call_hold_state`: (this end holding, the far end holding). */
    fun holdState(call: Long): Pair<Boolean, Boolean>

    /** The call has ended: let go of whatever was kept for it. */
    fun release(call: Long)
}
