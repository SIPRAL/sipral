// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

package org.sipral.idiomatic

import org.sipral.SipralException
import org.sipral.SipralStatus

/**
 * Call an ABI entry point through [org.sipral.Sipral], waiting out an
 * ordinary `SIPRAL_STATUS_BUSY`.
 *
 * "Signalling on one stack is one thread at a time, and a second thread is
 * told so rather than made to wait" (`docs/08-ffi.md`) is a promise about
 * the C ABI: the library itself never blocks a caller for it.
 * [SipralClient] keeps one thread polling continuously, so every entry
 * point an application calls from its own thread is liable to collide with
 * it for the length of one poll -- ordinary contention, not a real failure
 * -- and retrying here is what lets [SipralCall.hangup], [SipralAccount.register]
 * and the rest read as calls that simply work, the same shape
 * `bindings/python/sipral/errors.py`'s own `call()` gives the same problem.
 * A contention that has not cleared in [deadlineMs] is not ordinary any
 * more and is let through as whatever it still is.
 *
 * `SIPRAL_STATUS_CLOCK_BEHIND` gets the same retry, as the .NET layer gives
 * it: every [action] here reads `nowMs()` afresh on the calling thread right
 * before the entry point runs, so a reading the stack's last one beat was
 * overtaken by the poll thread between the two, not stale, and the next
 * reading can only be later.
 */
/** A raw status [retryBusy] waits out, thrown so that it does; any other is
 * returned for the caller to read. */
internal fun throwIfPassing(status: Int) {
    if (status == SipralStatus.BUSY.value || status == SipralStatus.CLOCK_BEHIND.value) {
        throw SipralException(SipralStatus.of(status), "")
    }
}

internal fun <T> retryBusy(deadlineMs: Long = 500, action: () -> T): T {
    val deadline = System.nanoTime() / 1_000_000 + deadlineMs
    while (true) {
        try {
            return action()
        } catch (busy: SipralException) {
            val passing = busy.status == SipralStatus.BUSY || busy.status == SipralStatus.CLOCK_BEHIND
            if (!passing || System.nanoTime() / 1_000_000 >= deadline) {
                throw busy
            }
            Thread.sleep(1)
        }
    }
}
