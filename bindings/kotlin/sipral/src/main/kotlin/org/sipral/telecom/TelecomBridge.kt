// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// The logic of the Android ConnectionService helper, with no Android in it:
// the telecom framework behind TelecomPlatform/TelecomConnection, the SIP
// side behind SipCalls, and in between the sequence docs/15-mobile.md's
// "C2" asks for --
//
//   push -> report to the framework -> announce (which refreshes the
//   binding) -> match the INVITE -> answer
//
// -- plus the other direction, the framework's answer/reject/hold/DTMF/
// disconnect carried onto the call. Audio routing is not here at all: a
// self-managed connection leaves it to the platform, and the adapter only
// surfaces what the platform offers.

package org.sipral.telecom

import java.util.UUID
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralStatus
import org.sipral.idiomatic.SipralAnnounced

/** Which way a call goes. */
enum class TelecomDirection { INCOMING, OUTGOING }

/** Where a call stands, from the framework's side. */
enum class TelecomPhase {
    /** Incoming and ringing -- including a call a push announced whose
     * INVITE has not arrived yet, which is ringing all the same. */
    RINGING,

    /** Outgoing, and waiting for the framework to allow it. */
    REQUESTED,

    /** Outgoing, and sent. */
    DIALING,
    ACTIVE,
    HELD,
    ENDED,
}

/** One call as [TelecomBridge.calls] shows it. [call] is the SIP handle,
 * zero while a push-announced call's INVITE has not arrived. */
data class TelecomCall(
    val id: String,
    val direction: TelecomDirection,
    val account: Long,
    val caller: String,
    val displayName: String?,
    val phase: TelecomPhase,
    val call: Long,
    val remoteHold: Boolean,
    val announced: Boolean,
)

/**
 * The ConnectionService helper's logic: every call the telecom framework
 * knows about, keyed by an id this class mints and the framework carries in
 * its extras, tied to the SIP call handle once there is one.
 *
 * Feed it the client's events with [collect] (or [onEvent] one at a time),
 * the framework's callbacks with [connectionCreated], [connectionFailed],
 * [answer], [reject], [disconnect], [hold], [unhold] and [playDtmf], and a
 * push with [pushArrived].
 *
 * Every entry point is safe from any thread, and each holds one monitor
 * for its whole length, calls out included. That is deliberate: the
 * events are read on another thread than the framework's callbacks, and
 * an INVITE handled between `announce` returning and its answer being
 * written down would be reported as a second call. Nothing waits behind
 * the monitor for long -- every ABI call answers at once or is retried for
 * at most half a second -- and nothing it calls out to calls back into
 * this class on another thread while waiting.
 */
class TelecomBridge(
    private val platform: TelecomPlatform,
    private val sip: SipCalls,
    private val newId: () -> String = { UUID.randomUUID().toString() },
) {
    private class Entry(
        val id: String,
        val direction: TelecomDirection,
        val account: Long,
        val caller: String,
        var displayName: String?,
        var phase: TelecomPhase,
    ) {
        var call: Long = 0
        var connection: TelecomConnection? = null

        /** The framework has been told this call is over, and is told
         * nothing more about it. */
        var closedForTelecom = false

        /** The announcement still waiting for its INVITE, or zero. */
        var announcement: Long = 0
        var announcedAt: Long = 0
        var announced = false
        var answered = false

        /** The user declined before the INVITE came, and the announcement
         * could no longer be forgotten: the INVITE is refused with this on
         * arrival. */
        var refuseWith: Long = 0
        var endedLocally = false
        var confirmed = false
        var remoteHold = false
    }

    private val lock = Any()
    private val entries = LinkedHashMap<String, Entry>()
    private val byCall = HashMap<Long, Entry>()
    private val announcedCalls = HashSet<Long>()
    private var sequence = 0L

    private val callsFlow = MutableStateFlow<List<TelecomCall>>(emptyList())

    /** Every call the framework is showing, in the order they started. */
    val calls: StateFlow<List<TelecomCall>> = callsFlow

    /** The SIP call handle behind [id], or zero. */
    fun callHandleOf(id: String): Long = synchronized(lock) { entries[id]?.call ?: 0L }

    /**
     * Subscribe to [events] and hand each to [onEvent]. Started undispatched,
     * so the subscription exists before this returns and no event emitted
     * after it can be missed.
     */
    fun collect(scope: CoroutineScope, events: Flow<SipralEvent>): Job =
        scope.launch(start = CoroutineStart.UNDISPATCHED) {
            events.collect { onEvent(it) }
        }

    // -- a push --------------------------------------------------------------

    /**
     * A push said [caller] is calling on [account]. Returns the id the
     * framework will know the call by.
     *
     * The framework is told first, before anything that could take time:
     * the platform's rule is that the application presents a ringing call
     * before the network session exists. Then the call is announced, which
     * refreshes the binding at once. A call from the same caller already
     * ringing on this account -- its INVITE beat the push -- is not
     * reported a second time: its id is the answer.
     */
    fun pushArrived(account: Long, caller: String, displayName: String? = null): String = settle {
        val existing = entries.values.firstOrNull {
            it.direction == TelecomDirection.INCOMING && it.account == account && it.call != 0L &&
                !it.announced && !it.closedForTelecom && it.phase == TelecomPhase.RINGING &&
                sameCaller(caller, it.caller)
        }
        if (existing != null) {
            existing.announced = true
            // Announced all the same, so the library's record of the pairing
            // is complete; it answers Arrived with this same call.
            quietly { sip.announce(account, caller) }
            return@settle existing.id
        }

        val entry = Entry(newId(), TelecomDirection.INCOMING, account, caller, displayName, TelecomPhase.RINGING)
        entry.announced = true
        entries[entry.id] = entry
        try {
            platform.reportIncomingCall(entry.id, caller, displayName)
        } catch (refused: RuntimeException) {
            // No screen, so nothing to announce for: the push handler hears
            // why, and the INVITE, if it comes, is an ordinary call.
            forget(entry)
            throw refused
        }

        val answer = try {
            sip.announce(account, caller)
        } catch (_: Exception) {
            end(entry, TelecomDisconnect.ERROR)
            return@settle entry.id
        }
        when (answer) {
            is SipralAnnounced.Waiting -> {
                entry.announcement = answer.announcement
                entry.announcedAt = ++sequence
            }
            is SipralAnnounced.Arrived -> {
                val other = byCall[answer.call]
                if (other != null) {
                    // Reported already, as an INVITE nobody had announced, by
                    // a path the look above did not match: that screen is the
                    // call, and this one a duplicate of it.
                    other.announced = true
                    end(entry, TelecomDisconnect.CANCELED)
                    return@settle other.id
                }
                bind(entry, answer.call)
            }
        }
        entry.id
    }

    // -- an outgoing call ----------------------------------------------------

    /** Ask the framework for a call to [target] on [account]; the INVITE
     * goes out once it has created the connection. */
    fun placeCall(account: Long, target: String): String = settle {
        val entry = Entry(newId(), TelecomDirection.OUTGOING, account, target, null, TelecomPhase.REQUESTED)
        entries[entry.id] = entry
        try {
            platform.placeOutgoingCall(entry.id, target)
        } catch (refused: RuntimeException) {
            forget(entry)
            throw refused
        }
        entry.id
    }

    // -- the framework's side ------------------------------------------------

    /**
     * The framework created the connection for [id]. It is brought up to
     * where the call already is; for an outgoing call, this is when the
     * INVITE is sent.
     */
    fun connectionCreated(id: String, connection: TelecomConnection): Unit = settle {
        val entry = entries[id]
        if (entry == null || entry.closedForTelecom) {
            // Nothing is behind this id any more: a call that ended while
            // the framework was still creating its connection.
            connection.setDisconnected(if (entry == null) TelecomDisconnect.ERROR else TelecomDisconnect.CANCELED)
            return@settle
        }
        entry.connection = connection
        if (entry.direction == TelecomDirection.OUTGOING && entry.phase == TelecomPhase.REQUESTED) {
            val handle = try {
                sip.place(entry.account, entry.caller)
            } catch (_: Exception) {
                end(entry, TelecomDisconnect.ERROR)
                return@settle
            }
            entry.phase = TelecomPhase.DIALING
            bind(entry, handle)
        }
        render(entry)
    }

    /** The framework refused to create the connection for [id]. */
    fun connectionFailed(id: String): Unit = settle {
        val entry = entries[id] ?: return@settle
        entry.closedForTelecom = true
        entry.phase = TelecomPhase.ENDED
        entry.endedLocally = true
        when {
            entry.call != 0L && entry.direction == TelecomDirection.INCOMING -> quietly { sip.reject(entry.call, 486) }
            entry.call != 0L -> quietly { sip.hangup(entry.call) }
            entry.announcement != 0L -> withdraw(entry, 486)
            else -> forget(entry)
        }
    }

    /** The user answered. Before the INVITE has come, the answer is kept
     * and given the moment it does. */
    fun answer(id: String): Unit = settle {
        val entry = entries[id] ?: return@settle
        if (entry.closedForTelecom || entry.direction != TelecomDirection.INCOMING || entry.answered) {
            return@settle
        }
        entry.answered = true
        if (entry.call != 0L) {
            answerNow(entry)
        }
    }

    /** The user declined a ringing call: 603, RFC 3261 §21.6.2. */
    fun reject(id: String): Unit = settle {
        val entry = entries[id] ?: return@settle
        decline(entry)
    }

    /** The user hung up -- from the application's own screen, a headset
     * button, a watch. A call still ringing is declined instead. */
    fun disconnect(id: String): Unit = settle {
        val entry = entries[id] ?: return@settle
        if (entry.direction == TelecomDirection.INCOMING && !entry.answered) {
            decline(entry)
            return@settle
        }
        entry.endedLocally = true
        tellClosed(entry, TelecomDisconnect.LOCAL)
        when {
            entry.call != 0L -> quietly { sip.hangup(entry.call) }
            entry.announcement != 0L -> withdraw(entry, 486)
            else -> forget(entry)
        }
    }

    /** The framework asked for hold. The connection says held once the
     * re-INVITE has been answered, from [onEvent]. */
    fun hold(id: String): Unit = settle {
        val call = callOf(id) ?: return@settle
        quietly { sip.hold(call) }
    }

    fun unhold(id: String): Unit = settle {
        val call = callOf(id) ?: return@settle
        quietly { sip.resume(call) }
    }

    fun playDtmf(id: String, digit: Char): Unit = settle {
        val call = callOf(id) ?: return@settle
        quietly { sip.sendDtmf(call, digit.toString()) }
    }

    // -- the SIP side --------------------------------------------------------

    /** One event off the client's stream. Events for calls this bridge does
     * not know are ignored. */
    fun onEvent(event: SipralEvent): Unit = settle {
        when (event.kind) {
            SipralEventKind.CALL_ANNOUNCED.value.toLong() -> {
                announcedCalls.add(event.call)
            }
            SipralEventKind.INCOMING_CALL.value.toLong() -> incoming(event)
            SipralEventKind.ANNOUNCED_CALL_MISSING.value.toLong() -> missing()
            SipralEventKind.CALL_CONFIRMED.value.toLong() -> confirmed(event.call)
            SipralEventKind.SESSION_CHANGED.value.toLong(),
            SipralEventKind.SESSION_CHANGE_FAILED.value.toLong(),
            -> sessionChanged(event.call)
            SipralEventKind.CALL_ENDED.value.toLong() -> {
                byCall[event.call]?.let { end(it, causeOf(it, statusOf(event.message))) }
            }
            else -> Unit
        }
    }

    private fun incoming(event: SipralEvent) {
        val who = callerOf(event.message)
        val caller = who.uri ?: ""
        val wasAnnounced = announcedCalls.remove(event.call)
        val known = byCall[event.call]
        if (known != null) {
            // Bound already, by an announce that answered Arrived.
            if (known.displayName == null) {
                known.displayName = who.displayName
            }
            return
        }
        if (wasAnnounced) {
            val waiting = entries.values
                .filter { it.announcement != 0L && it.account == event.account }
                .sortedBy { it.announcedAt }
            val entry = waiting.firstOrNull { sameCaller(it.caller, caller) } ?: waiting.firstOrNull()
            if (entry != null) {
                entry.announcement = 0L
                if (entry.displayName == null) {
                    entry.displayName = who.displayName
                }
                bind(entry, event.call)
                return
            }
        }
        val entry = Entry(newId(), TelecomDirection.INCOMING, event.account, caller, who.displayName, TelecomPhase.RINGING)
        entries[entry.id] = entry
        entry.call = event.call
        byCall[event.call] = entry
        try {
            platform.reportIncomingCall(entry.id, caller, who.displayName)
        } catch (_: RuntimeException) {
            // The framework would not take the call (on Android, a
            // SecurityException for an account it does not know). Nobody can
            // see it ring, so it is turned away rather than left ringing --
            // and this runs on the event stream, which a throw would end.
            entry.closedForTelecom = true
            entry.endedLocally = true
            entry.phase = TelecomPhase.ENDED
            quietly { sip.reject(event.call, 486) }
        }
    }

    /** Announcements expire in the order they were made -- the window is
     * one for the whole stack -- so the oldest still waiting is the one
     * that has run out. */
    private fun missing() {
        val entry = entries.values.filter { it.announcement != 0L }.minByOrNull { it.announcedAt } ?: return
        entry.announcement = 0L
        end(entry, TelecomDisconnect.MISSED)
    }

    private fun confirmed(call: Long) {
        val entry = byCall[call] ?: return
        entry.confirmed = true
        entry.phase = TelecomPhase.ACTIVE
        render(entry)
    }

    private fun sessionChanged(call: Long) {
        val entry = byCall[call] ?: return
        if (!entry.confirmed || entry.closedForTelecom) {
            return
        }
        val (here, there) = try {
            sip.holdState(call)
        } catch (_: SipralException) {
            return
        }
        entry.phase = if (here) TelecomPhase.HELD else TelecomPhase.ACTIVE
        render(entry)
        if (entry.remoteHold != there) {
            entry.remoteHold = there
            entry.connection?.setRemoteHold(there)
        }
    }

    // -- the pieces ------------------------------------------------------------

    private fun decline(entry: Entry) {
        entry.endedLocally = true
        tellClosed(entry, TelecomDisconnect.REJECTED)
        when {
            entry.call != 0L -> quietly { sip.reject(entry.call, 603) }
            entry.announcement != 0L -> withdraw(entry, 603)
            else -> forget(entry)
        }
    }

    private fun bind(entry: Entry, call: Long) {
        entry.call = call
        byCall[call] = entry
        when {
            entry.refuseWith != 0L -> quietly { sip.reject(call, entry.refuseWith) }
            entry.answered -> answerNow(entry)
        }
    }

    private fun answerNow(entry: Entry) {
        try {
            sip.answer(entry.call)
        } catch (_: Exception) {
            entry.endedLocally = true
            quietly { sip.hangup(entry.call) }
            end(entry, TelecomDisconnect.ERROR)
        }
    }

    /** Forget an announcement nothing has matched. When the library says
     * it was already fulfilled or had expired, the INVITE or the "missing"
     * is already on its way: the entry stays, so that the INVITE is
     * refused with [code] on arrival and a "missing" removes it quietly. */
    private fun withdraw(entry: Entry, code: Long) {
        try {
            sip.forgetAnnouncement(entry.announcement)
            entry.announcement = 0L
            forget(entry)
        } catch (crossed: SipralException) {
            if (crossed.status == SipralStatus.WRONG_STATE) {
                entry.refuseWith = code
            } else {
                entry.announcement = 0L
                forget(entry)
            }
        }
    }

    private fun callOf(id: String): Long? = entries[id]?.takeIf { it.call != 0L && !it.closedForTelecom }?.call

    private fun render(entry: Entry) {
        val connection = entry.connection ?: return
        when (entry.phase) {
            TelecomPhase.RINGING -> connection.setRinging()
            TelecomPhase.DIALING -> connection.setDialing()
            TelecomPhase.ACTIVE -> connection.setActive()
            TelecomPhase.HELD -> connection.setOnHold()
            TelecomPhase.REQUESTED, TelecomPhase.ENDED -> Unit
        }
    }

    /** Tell the framework once, and let go of the connection. */
    private fun tellClosed(entry: Entry, cause: TelecomDisconnect) {
        if (entry.closedForTelecom) {
            return
        }
        entry.closedForTelecom = true
        entry.phase = TelecomPhase.ENDED
        val connection = entry.connection
        entry.connection = null
        connection?.setDisconnected(cause)
    }

    /** The call is over on both sides. */
    private fun end(entry: Entry, cause: TelecomDisconnect) {
        tellClosed(entry, cause)
        if (entry.call != 0L) {
            quietly { sip.release(entry.call) }
        }
        forget(entry)
    }

    private fun forget(entry: Entry) {
        entry.phase = TelecomPhase.ENDED
        entries.remove(entry.id)
        if (entry.call != 0L && byCall[entry.call] === entry) {
            byCall.remove(entry.call)
        }
    }

    private fun causeOf(entry: Entry, status: Int): TelecomDisconnect = when {
        entry.endedLocally -> if (entry.confirmed) TelecomDisconnect.LOCAL else TelecomDisconnect.REJECTED
        status == 486 || status == 600 -> TelecomDisconnect.BUSY
        status == 603 -> TelecomDisconnect.REJECTED
        entry.direction == TelecomDirection.INCOMING && !entry.confirmed -> TelecomDisconnect.MISSED
        !entry.confirmed && status >= 400 -> TelecomDisconnect.ERROR
        else -> TelecomDisconnect.REMOTE
    }

    /**
     * Run [action] under the monitor, then publish what it left -- under the
     * same monitor, and whether it returned or threw, so that two entry
     * points finishing together cannot publish their snapshots out of order
     * and leave the older one standing. Setting a `StateFlow` never waits on
     * its collectors, so the monitor is not held for them.
     */
    private inline fun <T> settle(action: () -> T): T = synchronized(lock) {
        try {
            action()
        } finally {
            publish()
        }
    }

    /** Called only from [settle], with the monitor held. */
    private fun publish() {
        callsFlow.value = entries.values.map {
            TelecomCall(
                id = it.id,
                direction = it.direction,
                account = it.account,
                caller = it.caller,
                displayName = it.displayName,
                phase = it.phase,
                call = it.call,
                remoteHold = it.remoteHold,
                announced = it.announced,
            )
        }
    }

    private inline fun quietly(action: () -> Unit) {
        try {
            action()
        } catch (_: SipralException) {
            // The call moved on under this request -- it ended, or never got
            // this far -- and the event that says so is what settles it.
        }
    }
}

/** The status code of a response, zero for a request or no message. The
 * message a `SIPRAL_EVENT_KIND_CALL_ENDED` carries is the final response
 * that ended the call, when one did. */
internal fun statusOf(message: ByteArray?): Int {
    if (message == null || message.size < 12) {
        return 0
    }
    val start = String(message, 0, 12, Charsets.US_ASCII)
    if (!start.startsWith("SIP/2.0 ")) {
        return 0
    }
    return start.substring(8, 11).toIntOrNull() ?: 0
}
