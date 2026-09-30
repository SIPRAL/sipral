// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

package org.sipral.idiomatic

import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralReferralEvent
import org.sipral.SipralTransferEvent

/**
 * The `SIPRAL_EVENT_KIND_REFERRAL` payload -- a REFER outside any dialog,
 * to take with [SipralClient.acceptReferral] or refuse with
 * [SipralClient.rejectReferral] -- or null for an event of any other kind.
 * `statusCode` is zero while it waits; set, it is the word that it lapsed
 * unanswered, with what the stack answered it with and nothing else.
 * `referredBy` is what the sender wrote, never proof of who it is.
 */
fun referralOf(event: SipralEvent): SipralReferralEvent? =
    if (event.kind == SipralEventKind.REFERRAL.value.toLong()) event.payload.referral else null

/**
 * The payload of `SIPRAL_EVENT_KIND_TRANSFER_REQUESTED` -- the far end of a
 * call asking this end to call somebody else, taken with
 * [SipralClient.acceptReferral] or refused with [SipralClient.rejectReferral]
 * as a referral is -- and of `SIPRAL_EVENT_KIND_TRANSFER_PROGRESS` and
 * `SIPRAL_EVENT_KIND_TRANSFER_DONE`, which report on one [SipralCall.transfer]
 * asked for; null for an event of any other kind.
 */
fun transferOf(event: SipralEvent): SipralTransferEvent? = when (event.kind) {
    SipralEventKind.TRANSFER_REQUESTED.value.toLong(),
    SipralEventKind.TRANSFER_PROGRESS.value.toLong(),
    SipralEventKind.TRANSFER_DONE.value.toLong(),
    -> event.payload.transfer
    else -> null
}
