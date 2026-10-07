// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.idiomatic

import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralReferralEvent
import org.sipral.SipralTransferEvent

/**
 * The `SIPRAL_EVENT_KIND_REFERRAL` payload (a REFER outside any dialog, for
 * [SipralClient.acceptReferral] or [SipralClient.rejectReferral]), or null
 * for any other kind. `statusCode` is zero while it waits; nonzero means it
 * lapsed unanswered and is what the stack answered. `referredBy` is what
 * the sender wrote, not proof of identity.
 */
fun referralOf(event: SipralEvent): SipralReferralEvent? =
    if (event.kind == SipralEventKind.REFERRAL.value.toLong()) event.payload.referral else null

/**
 * The payload of `SIPRAL_EVENT_KIND_TRANSFER_REQUESTED` (the far end asking
 * this end to call someone else, taken or refused like a referral), and of
 * `TRANSFER_PROGRESS` and `TRANSFER_DONE`, which report on a
 * [SipralCall.transfer]. Null for any other kind.
 */
fun transferOf(event: SipralEvent): SipralTransferEvent? = when (event.kind) {
    SipralEventKind.TRANSFER_REQUESTED.value.toLong(),
    SipralEventKind.TRANSFER_PROGRESS.value.toLong(),
    SipralEventKind.TRANSFER_DONE.value.toLong(),
    -> event.payload.transfer
    else -> null
}
