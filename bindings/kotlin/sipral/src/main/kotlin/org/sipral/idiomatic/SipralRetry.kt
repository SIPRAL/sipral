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
 */
internal fun <T> retryBusy(deadlineMs: Long = 500, action: () -> T): T {
    val deadline = System.nanoTime() / 1_000_000 + deadlineMs
    while (true) {
        try {
            return action()
        } catch (busy: SipralException) {
            if (busy.status != SipralStatus.BUSY || System.nanoTime() / 1_000_000 >= deadline) {
                throw busy
            }
            Thread.sleep(1)
        }
    }
}
