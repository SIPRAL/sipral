// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.idiomatic

import org.sipral.Sipral
import org.sipral.SipralActivity
import org.sipral.SipralBasic
import org.sipral.SipralConferenceEvent
import org.sipral.SipralConferenceText
import org.sipral.SipralEndpointStatus
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralPresenceEvent
import org.sipral.SipralStatus
import org.sipral.SipralSubscriptionState
import org.sipral.SipralTextEvent

/**
 * A `SIPRAL_EVENT_KIND_CONFERENCE_CHANGED`'s `payload.conference`: the
 * subscription, merged or ended, version and user count. Null for any
 * other kind. [SipralSubscription.conference] reads the picture.
 */
fun conferenceOf(event: SipralEvent): SipralConferenceEvent? =
    if (event.kind == SipralEventKind.CONFERENCE_CHANGED.value.toLong()) event.payload.conference else null

/**
 * A `SIPRAL_EVENT_KIND_TEXT_RECEIVED`'s `payload.text`: the far end's
 * real-time text (RFC 4103), with U+FFFD where a block was lost beyond
 * recovery, and how many were. Null for any other kind.
 */
fun textOf(event: SipralEvent): SipralTextEvent? =
    if (event.kind == SipralEventKind.TEXT_RECEIVED.value.toLong()) event.payload.text else null

/**
 * A `SIPRAL_EVENT_KIND_PRESENCE_CHANGED`'s `payload.presence`: for `kind`
 * `WATCHED` a watched presentity (`basic`, `activity`, `entity`, `note`);
 * for `PUBLICATION` this account's own publication (`publicationState`,
 * `failure`, `statusCode`, `expiresMs`, `refreshInMs`). Null otherwise.
 */
fun presenceOf(event: SipralEvent): SipralPresenceEvent? =
    if (event.kind == SipralEventKind.PRESENCE_CHANGED.value.toLong()) event.payload.presence else null

/**
 * This account's presence for [SipralAccount.publishPresence] (RFC 3903,
 * PIDF): reachable or not, the activity (`NONE` publishes no person;
 * `OTHER` has no name and is refused), and a one-line note.
 */
data class SipralPublishedPresence(
    val basic: SipralBasic,
    val activity: SipralActivity = SipralActivity.NONE,
    val note: String? = null,
)

/** One user of a conference, as the focus described it (RFC 4575 §5.6). */
data class SipralConferenceMember(
    /** The address of record it takes part as. */
    val entity: String,
    val displayText: String,
    /** The `entity` of its first endpoint: the device it is on. */
    val endpoint: String,
    /** How many endpoints -- devices -- it is in the conference from. */
    val endpoints: Long,
    /** Where the first of them is. */
    val status: SipralEndpointStatus,
    /** How many media streams the first of them has. */
    val media: Long,
)

/**
 * A conference as a `conference` subscription holds it: every document the
 * focus sent, merged (RFC 4575 §4.6). A piece the focus never sent is an
 * empty string, a flag it never sent null.
 */
data class SipralConferencePicture(
    /** The version of the last document merged. */
    val version: Long,
    /** The conference's URI. */
    val entity: String,
    val subject: String,
    val displayText: String,
    /** How many users the focus says it counts, which may be more than
     * [members] lists. */
    val userCount: Long?,
    val active: Boolean?,
    val locked: Boolean?,
    /** Every user, in the order the focus first named them. */
    val members: List<SipralConferenceMember>,
)

/**
 * One subscription (RFC 6665): [SipralAccount.subscribe],
 * [SipralAccount.watchPresence] or [SipralCall.subscribeConference].
 *
 * The client refreshes it, and resubscribes after `deactivated`, until
 * [end]. Its events arrive on [SipralClient.events] naming this [handle]:
 * `SUBSCRIPTION_CHANGED` and `NOTIFIED` for every package,
 * `PRESENCE_CHANGED` ([presenceOf]) and `CONFERENCE_CHANGED`
 * ([conferenceOf]) for theirs.
 */
class SipralSubscription internal constructor(
    val client: SipralClient,
    val handle: Long,
    /** The event package, as the SUBSCRIBE named it. */
    val `package`: String,
) {
    /** `sipral_subscription_state`, read fresh. */
    val state: SipralSubscriptionState
        get() = SipralSubscriptionState.of(retryBusy { Sipral.subscriptionState(client.handle, handle) }.toInt())
            ?: SipralSubscriptionState.UNKNOWN

    /** `sipral_subscription_end`: unsubscribe (`Expires: 0`) and let the
     * handle go once the notifier's last word is in. */
    fun end() {
        retryBusy { Sipral.subscriptionEnd(client.handle, handle, client.nowMs()) }
    }

    /** The conference this subscription holds, read whole: null for one to
     * another package, and for one no document has reached yet. */
    fun conference(): SipralConferencePicture? {
        val whole = try {
            retryBusy { Sipral.subscriptionConference(client.handle, handle) }
        } catch (none: SipralException) {
            if (none.status == SipralStatus.NOT_SUPPORTED) {
                return null
            }
            throw none
        }
        val members = (0 until whole.users.toInt()).map { index ->
            val user = retryBusy { Sipral.subscriptionConferenceUserAt(client.handle, handle, index.toLong()) }
            SipralConferenceMember(
                entity = text(SipralConferenceText.USER_ENTITY, index),
                displayText = text(SipralConferenceText.USER_DISPLAY_TEXT, index),
                endpoint = text(SipralConferenceText.USER_ENDPOINT, index),
                endpoints = user.endpoints,
                status = SipralEndpointStatus.of(user.status.toInt()) ?: SipralEndpointStatus.UNKNOWN,
                media = user.media,
            )
        }
        return SipralConferencePicture(
            version = whole.version,
            entity = text(SipralConferenceText.ENTITY, 0),
            subject = text(SipralConferenceText.SUBJECT, 0),
            displayText = text(SipralConferenceText.DISPLAY_TEXT, 0),
            userCount = if (whole.hasUserCount != 0L) whole.userCount else null,
            active = flag(whole.active),
            locked = flag(whole.locked),
            members = members,
        )
    }

    private fun text(which: SipralConferenceText, index: Int): String = protocolText { buffer ->
        retryBusy {
            Sipral.subscriptionConferenceText(client.handle, handle, index.toLong(), which.value.toLong(), buffer)
        }
    }
}

/** `conference-state`'s tri-state: one said yes, two said no. */
private fun flag(raw: Long): Boolean? = when (raw) {
    1L -> true
    2L -> false
    else -> null
}

/** Text the ABI copies into a caller's buffer: read with a buffer large
 * enough for nearly all, and a larger second one for the rest. */
internal fun protocolText(fill: (ByteArray) -> Long): String {
    for (capacity in intArrayOf(1024, 65536)) {
        val buffer = ByteArray(capacity)
        val needed = try {
            fill(buffer)
        } catch (small: SipralException) {
            if (small.status == SipralStatus.BUFFER_TOO_SMALL && capacity < 65536) {
                continue
            }
            throw small
        }
        return String(buffer, 0, maxOf(needed.toInt() - 1, 0), Charsets.UTF_8)
    }
    return ""
}

/**
 * What a call's audio stream agreed about RTCP feedback
 * ([SipralMedia.rtcpFeedback]): RTP/AVPF (RFC 4585), Generic NACKs, and
 * reduced-size RTCP (RFC 5506).
 */
data class SipralRtcpFeedback(
    val feedback: Boolean,
    val genericNack: Boolean,
    val reducedSize: Boolean,
)

/**
 * A recording session to a recording server (SIPREC, RFC 7866), from
 * [SipralCall.recordTo].
 *
 * A call of its own on the client: [handle] is what its `CALL_CONFIRMED`
 * and `CALL_ENDED` name. The stack keeps it in step with the recorded call
 * (metadata follows hold and transfer; it ends with the call). The copies
 * leave from [thisEnd] (what this end sent, stream label `1`) and [farEnd]
 * (what it heard, label `2`).
 */
class SipralRecordingSession internal constructor(
    val handle: Long,
    /** The socket this end's audio is copied from, `host:port`. */
    val thisEnd: String,
    /** The socket the far end's audio is copied from. */
    val farEnd: String,
    private val call: SipralCall,
) {
    /** `sipral_call_stop_recording_to`: the copies stop at once and the
     * recording session is hung up. `WRONG_STATE` once nothing records the
     * call any more. */
    fun stop() {
        call.stopRecordingToServer()
    }
}
