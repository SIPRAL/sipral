// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.telecom

import java.util.concurrent.ConcurrentHashMap
import org.sipral.idiomatic.SipralAccount
import org.sipral.idiomatic.SipralAnnounced
import org.sipral.idiomatic.SipralCall
import org.sipral.idiomatic.SipralAudioDevices
import org.sipral.idiomatic.SipralClient

/**
 * [SipCalls] over [org.sipral.idiomatic]: the accounts [TelecomBridge] may
 * name, by handle, on one [SipralClient].
 *
 * A call answered or placed through here is a [SipralCall] with its own
 * media socket bound on [mediaHost] -- on a device, the address of the
 * network the signalling socket is on -- and [call] hands it to whatever
 * moves its audio to and from the device.
 */
class IdiomaticSipCalls(
    private val client: SipralClient,
    accounts: Collection<SipralAccount>,
    private val mediaHost: String,
) : SipCalls {
    private val accounts = ConcurrentHashMap<Long, SipralAccount>().apply {
        for (account in accounts) {
            put(account.handle, account)
        }
    }
    private val calls = ConcurrentHashMap<Long, SipralCall>()

    /** Make another account nameable after construction. */
    fun addAccount(account: SipralAccount) {
        accounts[account.handle] = account
    }

    /** The [SipralCall] behind a handle, once it has been answered or
     * placed here and until it ends. */
    fun call(handle: Long): SipralCall? = calls[handle]

    /** The client's own audio engine, when it runs the calls' audio itself
     * ([org.sipral.idiomatic.SipralAudioMode.Device]); null when the
     * application does. */
    val audio: SipralAudioDevices? get() = client.audio

    private fun account(handle: Long): SipralAccount =
        accounts[handle] ?: throw IllegalArgumentException("account ${handle.toString(16)} is not one this bridge was given")

    override fun announce(account: Long, caller: String): SipralAnnounced = account(account).announce(caller)

    override fun forgetAnnouncement(announcement: Long) {
        client.forgetAnnouncement(announcement)
    }

    override fun answer(call: Long) {
        calls[call] = client.answerCall(call, mediaHost = mediaHost)
    }

    override fun reject(call: Long, code: Long) {
        client.rejectCall(call, code)
    }

    override fun place(account: Long, target: String): Long {
        val call = client.placeCall(account(account), target, mediaHost = mediaHost)
        calls[call.handle] = call
        return call.handle
    }

    override fun hangup(call: Long) {
        val known = calls[call]
        if (known != null) {
            known.hangup()
        } else {
            client.rejectCall(call, 486)
        }
    }

    override fun hold(call: Long) {
        calls[call]?.hold()
    }

    override fun resume(call: Long) {
        calls[call]?.resume()
    }

    override fun sendDtmf(call: Long, digits: String) {
        calls[call]?.sendDtmf(digits)
    }

    override fun holdState(call: Long): Pair<Boolean, Boolean> = calls[call]?.holdState ?: (false to false)

    override fun release(call: Long) {
        calls.remove(call)?.close()
    }
}
