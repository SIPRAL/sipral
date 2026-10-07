// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The Android ConnectionService helper's logic, with no Android in it: the
// telecom framework behind TelecomPlatform/TelecomConnection, SIP behind
// SipCalls, and between them the sequence docs/15-mobile.md ("C2") asks for:
//
//   push -> report to the framework -> announce -> match the INVITE -> answer
//
// plus the framework's answer/reject/hold/DTMF/disconnect carried onto the
// call. Audio routing is left to the platform; the call's audio device
// follows the phase published here, through CallAudio.follow.

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
    /** Incoming and ringing, including a pushed call whose INVITE has not
     * arrived yet. */
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
 * knows, keyed by an id minted here and carried in the framework's
 * extras, tied to the SIP call handle once there is one.
 *
 * Feed it events with [collect] (or [onEvent]), the framework's callbacks
 * with [connectionCreated], [connectionFailed], [answer], [reject],
 * [disconnect], [hold], [unhold] and [playDtmf], and pushes with
 * [pushArrived]. Call [endAll] before closing the client.
 *
 * Every entry point is thread-safe and holds one monitor for its whole
 * length, calls out included. Deliberate: events and framework callbacks
 * come on different threads, and an INVITE handled between `announce`
 * returning and its result being recorded would show as a second call.
 * Nothing waits long under the monitor (ABI calls retry at most half a
 * second), and nothing called out calls back in from another thread.
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

        /** Why, once [closedForTelecom]. */
        var closedWith: TelecomDisconnect? = null

        /** The framework was asked for a connection and has neither
         * created one nor refused to yet. */
        var awaitingConnection = false

        /** The announcement still waiting for its INVITE, or zero. */
        var announcement: Long = 0
        var announcedAt: Long = 0
        var announced = false
        var answered = false

        /** The user declined before the INVITE came and the announcement could
         * no longer be forgotten: refuse the INVITE with this on arrival. */
        var refuseWith: Long = 0
        var endedLocally = false
        var confirmed = false
        var remoteHold = false

        /** Hold or unhold asked through [hold]/[unhold] and not yet agreed by
         * the dialog; null once it is. */
        var holdWanted: Boolean? = null
    }

    private val lock = Any()
    private val entries = LinkedHashMap<String, Entry>()
    private val byCall = HashMap<Long, Entry>()
    private val announcedCalls = HashSet<Long>()

    /** Calls that ended while the framework was still creating their
     * connection, and why. The framework answers each request exactly once,
     * so the late connection is told this and the entry removed. */
    private val endedBeforeConnection = HashMap<String, TelecomDisconnect>()
    private var sequence = 0L

    private val callsFlow = MutableStateFlow<List<TelecomCall>>(emptyList())

    /** Every call the framework is showing, in the order they started. */
    val calls: StateFlow<List<TelecomCall>> = callsFlow

    /** The SIP call handle behind [id], or zero. */
    fun callHandleOf(id: String): Long = synchronized(lock) { entries[id]?.call ?: 0L }

    /** Subscribe to [events] and hand each to [onEvent]. Started undispatched,
     * so no event emitted after this returns is missed. */
    fun collect(scope: CoroutineScope, events: Flow<SipralEvent>): Job =
        scope.launch(start = CoroutineStart.UNDISPATCHED) {
            events.collect { onEvent(it) }
        }

    // A push

    /**
     * A push said [caller] is calling on [account]. Returns the id the
     * framework knows the call by.
     *
     * The framework is told first: the platform requires a ringing call to be
     * presented before the network session exists. Then the call is announced,
     * which refreshes the binding. A call from the same caller already ringing
     * on this account (its INVITE beat the push) is not reported again; its id
     * is returned.
     */
    fun pushArrived(account: Long, caller: String, displayName: String? = null): String = settle {
        val existing = entries.values.firstOrNull {
            it.direction == TelecomDirection.INCOMING && it.account == account && it.call != 0L &&
                !it.announced && !it.closedForTelecom && it.phase == TelecomPhase.RINGING &&
                sameCaller(caller, it.caller)
        }
        if (existing != null) {
            existing.announced = true
            // announced anyway, so the library's pairing record is complete; it
            // answers Arrived with this same call
            quietly { sip.announce(account, caller) }
            return@settle existing.id
        }

        val entry = Entry(newId(), TelecomDirection.INCOMING, account, caller, displayName, TelecomPhase.RINGING)
        entry.announced = true
        entries[entry.id] = entry
        entry.awaitingConnection = true
        try {
            platform.reportIncomingCall(entry.id, caller, displayName)
        } catch (refused: RuntimeException) {
            // no screen, so nothing to announce: the push handler hears why, and an
            // INVITE that comes is an ordinary call
            entry.awaitingConnection = false
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
                    // already reported, as an unannounced INVITE matched by another path:
                    // that screen is the call, and this one a duplicate
                    other.announced = true
                    end(entry, TelecomDisconnect.CANCELED)
                    return@settle other.id
                }
                bind(entry, answer.call)
            }
        }
        entry.id
    }

    // An outgoing call

    /** Ask the framework for a call to [target] on [account]; the INVITE
     * goes out once it has created the connection. */
    fun placeCall(account: Long, target: String): String = settle {
        val entry = Entry(newId(), TelecomDirection.OUTGOING, account, target, null, TelecomPhase.REQUESTED)
        entries[entry.id] = entry
        entry.awaitingConnection = true
        try {
            platform.placeOutgoingCall(entry.id, target)
        } catch (refused: RuntimeException) {
            entry.awaitingConnection = false
            forget(entry)
            throw refused
        }
        entry.id
    }

    /**
     * End every call, before the client is closed: afterwards no event will
     * end them, and a connection nobody ends stays in the framework and the
     * system's call screens for the life of the process.
     *
     * Each connection is disconnected as ended locally. On the SIP side a
     * ringing call is refused busy, any other hung up, and each is released at
     * once; a waiting announcement is forgotten. A connection the framework
     * creates afterwards for one of these calls is disconnected immediately.
     */
    fun endAll(): Unit = settle {
        for (entry in entries.values.toList()) {
            entry.endedLocally = true
            tellClosed(entry, TelecomDisconnect.LOCAL)
            val call = entry.call
            when {
                call != 0L -> {
                    try {
                        if (entry.direction == TelecomDirection.INCOMING && !entry.answered) {
                            sip.reject(call, 486)
                        } else {
                            sip.hangup(call)
                        }
                    } catch (_: Exception) {
                        // ended already, or never got this far: only releasing it is left
                    }
                    try {
                        sip.release(call)
                    } catch (_: Exception) {
                        // nothing more to do for this call; the others still have to end
                    }
                }
                entry.announcement != 0L -> {
                    try {
                        sip.forgetAnnouncement(entry.announcement)
                    } catch (_: Exception) {
                        // already matched or expired; the INVITE goes with the client
                    }
                }
            }
            forget(entry)
        }
        announcedCalls.clear()
    }

    // The framework's side

    /** The framework created the connection for [id]. It is brought up to the
     * call's current state; for an outgoing call, the INVITE goes now. */
    fun connectionCreated(id: String, connection: TelecomConnection): Unit = settle {
        val entry = entries[id]
        val endedAlready = endedBeforeConnection.remove(id)
        if (entry == null || entry.closedForTelecom) {
            // the call ended while the connection was being created: tell it why.
            // An id never asked for is an error.
            connection.setDisconnected(entry?.closedWith ?: endedAlready ?: TelecomDisconnect.ERROR)
            entry?.awaitingConnection = false
            return@settle
        }
        entry.awaitingConnection = false
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
        endedBeforeConnection.remove(id)
        val entry = entries[id] ?: return@settle
        entry.awaitingConnection = false
        if (entry.closedForTelecom) {
            // ended already, and its ending is under way
            return@settle
        }
        entry.closedForTelecom = true
        entry.closedWith = TelecomDisconnect.ERROR
        entry.phase = TelecomPhase.ENDED
        entry.endedLocally = true
        when {
            entry.call != 0L && entry.direction == TelecomDirection.INCOMING -> quietly { sip.reject(entry.call, 486) }
            entry.call != 0L -> quietly { sip.hangup(entry.call) }
            entry.announcement != 0L -> withdraw(entry, 486)
            else -> forget(entry)
        }
    }

    /** The user answered. Before the INVITE has come, the answer is kept and
     * given when it arrives. */
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

    /** The user hung up (app screen, headset, watch). A ringing call is
     * declined instead. */
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

    /**
     * The framework asked for hold: a cellular or other app's call was
     * answered, or hold was pressed somewhere.
     *
     * A live call reports held at once, before the far end answers the
     * re-INVITE: `Connection.onHold` requires `setOnHold`, and a connection not
     * `STATE_HOLDING` within two seconds is disconnected. It stays held until
     * [unhold] whatever the far end says, since the framework has given the
     * audio to someone else.
     */
    fun hold(id: String): Unit = settle {
        val entry = liveEntry(id) ?: return@settle
        if (entry.confirmed) {
            entry.holdWanted = true
            entry.phase = TelecomPhase.HELD
            render(entry)
        }
        quietly { sip.hold(entry.call) }
    }

    /** The framework asked to unhold. Active at once, as `ConnectionService`'s
     * guide requires for `onUnhold()`, with the resuming re-INVITE after. */
    fun unhold(id: String): Unit = settle {
        val entry = liveEntry(id) ?: return@settle
        if (entry.confirmed) {
            entry.holdWanted = false
            entry.phase = TelecomPhase.ACTIVE
            render(entry)
        }
        quietly { sip.resume(entry.call) }
    }

    fun playDtmf(id: String, digit: Char): Unit = settle {
        val call = callOf(id) ?: return@settle
        quietly { sip.sendDtmf(call, digit.toString()) }
    }

    // The SIP side

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
            // bound already, by an announce that answered Arrived
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
        entry.awaitingConnection = true
        try {
            platform.reportIncomingCall(entry.id, caller, who.displayName)
        } catch (_: RuntimeException) {
            // the framework refused the call (on Android, a SecurityException for an
            // unknown account); nobody can see it ring, so refuse it rather than
            // throw, which would end the event stream
            entry.awaitingConnection = false
            entry.closedForTelecom = true
            entry.closedWith = TelecomDisconnect.ERROR
            entry.endedLocally = true
            entry.phase = TelecomPhase.ENDED
            quietly { sip.reject(event.call, 486) }
        }
    }

    /** Announcements expire in creation order (one window for the whole
     * stack), so the oldest still waiting is the one that ran out. */
    private fun missing() {
        val entry = entries.values.filter { it.announcement != 0L }.minByOrNull { it.announcedAt } ?: return
        entry.announcement = 0L
        end(entry, TelecomDisconnect.MISSED)
    }

    private fun confirmed(call: Long) {
        val entry = byCall[call] ?: return
        entry.confirmed = true
        if (entry.closedForTelecom) {
            // hung up here while the confirmation was in flight; the framework knows
            return
        }
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
        // the framework's request stands until the dialog agrees; after that, a
        // hold made on the call directly is followed too
        if (entry.holdWanted == here) {
            entry.holdWanted = null
        }
        entry.phase = if (entry.holdWanted ?: here) TelecomPhase.HELD else TelecomPhase.ACTIVE
        render(entry)
        if (entry.remoteHold != there) {
            entry.remoteHold = there
            entry.connection?.setRemoteHold(there)
        }
    }

    // The pieces

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

    /** Forget an unmatched announcement. If the library says it was already
     * fulfilled or expired, the INVITE or "missing" is in flight: keep the
     * entry so the INVITE is refused with [code] and a "missing" removes it. */
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

    private fun liveEntry(id: String): Entry? = entries[id]?.takeIf { it.call != 0L && !it.closedForTelecom }

    private fun callOf(id: String): Long? = liveEntry(id)?.call

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
        entry.closedWith = cause
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
        if (entry.awaitingConnection) {
            endedBeforeConnection[entry.id] = entry.closedWith ?: TelecomDisconnect.CANCELED
        }
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
     * Run [action] under the monitor, then publish the result under the same
     * monitor whether it returned or threw, so two entry points cannot publish
     * snapshots out of order. Setting a `StateFlow` never waits on collectors.
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
            // the call moved on under this request (ended, or never got this far);
            // the event that says so settles it
        }
    }
}

/** The status code of a response; zero for a request or no message. A
 * `CALL_ENDED` message is the final response that ended the call, if
 * any. */
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
