// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.idiomatic

import org.sipral.Sipral
import org.sipral.SipralEvent
import org.sipral.SipralException

/**
 * Every line of header field [name] in the event's `message`, in order
 * (`sipral_message_header`); compact and long forms match, ignoring case.
 * Empty when the event carries no message or the message no such field. On
 * `REGISTRATION_CHANGED` to `REGISTERED` the message is the registrar's whole
 * 2xx, so a field the registrar or a push proxy added to it is read here.
 */
fun SipralEvent.headers(name: String): List<String> {
    val whole = message ?: return emptyList()
    return try {
        (0 until Sipral.messageHeaderCount(whole, name)).map { index ->
            val (offset, length) = Sipral.messageHeader(whole, name, index)
            String(whole, offset.toInt(), length.toInt(), Charsets.UTF_8)
        }
    } catch (_: SipralException) {
        emptyList()
    }
}

/** The first line of header field [name] in the event's `message`, or null. */
fun SipralEvent.header(name: String): String? = headers(name).firstOrNull()
