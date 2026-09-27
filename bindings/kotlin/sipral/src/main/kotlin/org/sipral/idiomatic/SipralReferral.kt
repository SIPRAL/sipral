// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

package org.sipral.idiomatic

import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralReferralEvent

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
