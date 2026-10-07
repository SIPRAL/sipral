// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The calls a SipralReactCore holds for JavaScript, by the handle it knows
// them as, and the one race between keeping a call and its end.

package org.sipral.reactnative.core

/**
 * Calls placed or answered through the module, kept until `CALL_ENDED`.
 *
 * Keeping and ending happen on two threads: the worker keeps a call once
 * `placeCall` or `answerCall` returns it, and the event collector ends it.
 * A call can end before it is kept (an immediate refusal or transfer); kept
 * afterwards it would hold its sockets for the core's lifetime. So an end
 * that finds nothing is remembered, and a call kept after its end is
 * closed instead. Only the last [REMEMBERED] such ends are kept, since a
 * call the core never keeps (refused while ringing) would otherwise be
 * remembered forever.
 */
internal class SipralCallBook<C : AutoCloseable> {
    private val lock = Any()
    private val calls = HashMap<String, C>()
    private val endedFirst = LinkedHashSet<String>()

    /** Keep [call] as [id], unless [ended] or its end already went by, in
     * which case it is closed. True when kept. */
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
