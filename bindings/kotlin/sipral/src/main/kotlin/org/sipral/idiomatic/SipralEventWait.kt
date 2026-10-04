// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.idiomatic

import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import org.sipral.SipralEvent
import org.sipral.SipralEventKind

/**
 * Run [action], then suspend until the next event this flow carries that
 * [matches] is true for, and hand back both.
 *
 * The subscription is made before [action] runs, never after:
 * [SipralClient.events] and [SipralCall.events] are both a [SharedFlow]
 * with `replay = 0`, and that replays nothing to a subscriber that starts
 * late, no matter how large `extraBufferCapacity` is -- that capacity only
 * lets emitting keep up with an existing *slow* collector, it never queues
 * a value for a collector that has not subscribed yet, and a fresh
 * subscriber's own starting point in the flow is always "now", not
 * whatever the buffer happens to hold. So `events.first { it.kind == X }`
 * run *after* the action that causes kind `X`, the order it is natural to
 * reach for, can subscribe too late to ever see that event: it is gone the
 * instant it is emitted to nobody, and `first` goes on to match the *next*
 * event of kind `X` instead -- caused by anything else that happens to
 * emit one, another call on the same client among them. That is the real,
 * reproducible bug (`IdiomaticCheck.kt`'s own test demonstrates it, using
 * this function to fix it). What it is not is a [SharedFlow] handing a
 * stale, already-emitted value to a subscriber that starts later -- it
 * never does that, with or without a slow collector already attached, also
 * demonstrated there -- so routing calls apart to dodge a shared buffer, or
 * shrinking `extraBufferCapacity`, was never the fix; only this ordering
 * is.
 *
 * [action] runs synchronously, on the calling coroutine, once the
 * subscription this makes is live -- [CoroutineStart.UNDISPATCHED] is what
 * makes that true without a real dispatch landing in between -- so an
 * event [action] itself causes synchronously, or a poll thread races in
 * immediately afterward, is never missed. Existing collectors of this flow
 * are untouched: this only ever adds one more.
 */
suspend fun <T> SharedFlow<SipralEvent>.awaitNext(
    timeoutMs: Long = 30_000,
    matches: (SipralEvent) -> Boolean,
    action: () -> T,
): Pair<T, SipralEvent> = withTimeout(timeoutMs) {
    coroutineScope {
        val next = async(start = CoroutineStart.UNDISPATCHED) { first(matches) }
        action() to next.await()
    }
}

/** [awaitNext], matching by [kinds] alone -- the common case, and the one
 * `events.first { it.kind == X }` reaches for by hand. */
suspend fun <T> SharedFlow<SipralEvent>.awaitNext(
    vararg kinds: SipralEventKind,
    timeoutMs: Long = 30_000,
    action: () -> T,
): Pair<T, SipralEvent> {
    val wanted = kinds.map { it.value.toLong() }.toSet()
    return awaitNext(timeoutMs, { it.kind in wanted }, action)
}
