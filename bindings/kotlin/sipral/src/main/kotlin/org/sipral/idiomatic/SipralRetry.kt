// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.idiomatic

import org.sipral.SipralException
import org.sipral.SipralStatus

/** A raw status [retryBusy] waits out, thrown so that it does; any other is
 * returned for the caller to read. */
internal fun throwIfPassing(status: Int) {
    if (status == SipralStatus.BUSY.value || status == SipralStatus.CLOCK_BEHIND.value) {
        throw SipralException(SipralStatus.of(status), "")
    }
}

/**
 * Call an ABI entry point, waiting out an ordinary `SIPRAL_STATUS_BUSY`.
 *
 * The C ABI tells a second thread on one stack that it is busy rather than
 * blocking it (`docs/08-ffi.md`). [SipralClient]'s poll thread runs
 * continuously, so any call from an application thread can collide with
 * one poll; retrying makes [SipralCall.hangup], [SipralAccount.register]
 * and the rest just work, as `bindings/python/sipral/errors.py`'s `call()`
 * does. Contention that has not cleared within [deadlineMs] is thrown.
 *
 * `SIPRAL_STATUS_CLOCK_BEHIND` is retried too, as in the .NET layer: each
 * [action] reads `nowMs()` just before the call, so the poll thread merely
 * overtook it, and the next reading is later.
 */
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
