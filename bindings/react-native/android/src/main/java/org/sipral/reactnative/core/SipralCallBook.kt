// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// The calls a SipralReactCore holds for JavaScript, by the handle it knows
// them as, and the one race between keeping a call and its end.

package org.sipral.reactnative.core

/**
 * The calls placed or answered through the module, kept until their
 * `CALL_ENDED`.
 *
 * Keeping and ending come from two threads: the module's worker keeps a
 * call once `placeCall` or `answerCall` has returned it, and the client's
 * event collector ends it. A call can end before it is kept -- a far end that
 * refuses at once, a transfer that completes immediately -- and the end then
 * finds nothing to close; kept afterwards, the call would be held, its
 * sockets open, for as long as the core lives. So an end that finds nothing
 * is remembered, and a call kept after its end is closed instead of kept.
 * Only the last [REMEMBERED] such ends are remembered: an end for a call this
 * core never keeps -- one turned away while it rang -- would otherwise be
 * remembered for ever.
 */
internal class SipralCallBook<C : AutoCloseable> {
    private val lock = Any()
    private val calls = HashMap<String, C>()
    private val endedFirst = LinkedHashSet<String>()

    /** Keep [call] as [id], unless [ended] says it is over or its end has
     * already gone by, in which case it is closed and not kept. True when
     * it was kept. */
    fun keep(id: String, call: C, ended: Boolean): Boolean {
        val kept = synchronized(lock) {
            val over = endedFirst.remove(id) || ended
            if (!over) {
                calls[id] = call
            }
            !over
        }
        if (!kept) {
            call.close()
        }
        return kept
    }

    /** The call [id] ended: closed and forgotten, or remembered as over when
     * it has not been kept yet. */
    fun ended(id: String) {
        val gone = synchronized(lock) {
            calls.remove(id) ?: run {
                endedFirst.add(id)
                if (endedFirst.size > REMEMBERED) {
                    endedFirst.remove(endedFirst.first())
                }
                null
            }
        }
        gone?.close()
    }

    operator fun get(id: String): C? = synchronized(lock) { calls[id] }

    /** How many calls are kept. */
    val size: Int
        get() = synchronized(lock) { calls.size }

    /** Every call closed and forgotten, and every remembered end with them. */
    fun closeAll() {
        val all = synchronized(lock) {
            endedFirst.clear()
            calls.values.toList().also { calls.clear() }
        }
        all.forEach { it.close() }
    }

    companion object {
        const val REMEMBERED = 256
    }
}
