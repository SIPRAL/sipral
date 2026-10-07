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
 * Run [action], then suspend until the next event for which [matches] is
 * true, and return both.
 *
 * The subscription is made before [action] runs. [SipralClient.events]
 * and [SipralCall.events] are `SharedFlow`s with `replay = 0`: a new
 * subscriber starts at "now", whatever `extraBufferCapacity` is. So
 * `events.first { it.kind == X }` written after the action that causes `X`
 * can miss that event entirely and match a later, unrelated one
 * (`IdiomaticCheck.kt` demonstrates this). The fix is this ordering, not a
 * smaller buffer.
 *
 * [action] runs synchronously on the calling coroutine once the
 * subscription is live ([CoroutineStart.UNDISPATCHED]), so neither an event
 * it causes nor one the poll thread delivers right after is missed.
 * Existing collectors are unaffected.
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

/** [awaitNext], matching by [kinds] alone: the common case. */
suspend fun <T> SharedFlow<SipralEvent>.awaitNext(
    vararg kinds: SipralEventKind,
    timeoutMs: Long = 30_000,
    action: () -> T,
): Pair<T, SipralEvent> {
    val wanted = kinds.map { it.value.toLong() }.toSet()
    return awaitNext(timeoutMs, { it.kind in wanted }, action)
}
