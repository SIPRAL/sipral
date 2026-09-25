// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

package org.sipral.idiomatic

import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralNatEvent
import org.sipral.SipralNatRelayEvent

/**
 * A TURN server (RFC 8656) and the long-term credential it knows this end
 * by: `sipral_stack_config_t::turn_server`, `turn_username` and
 * `turn_password`, for [SipralClient.open].
 *
 * `address` is `host:port`, an address and not a name. Not a data class:
 * [toString] leaves the password out, since a TURN credential that reaches
 * a log is a relay somebody else can use, and a generated `toString`,
 * `equals` or `component3` would hand it to whatever prints or destructures
 * one.
 */
class SipralTurnServer(
    val address: String,
    val username: String,
    internal val password: String,
) {
    override fun toString(): String = "SipralTurnServer(address=$address, username=$username, password=<redacted>)"
}

/**
 * The `SIPRAL_EVENT_KIND_NAT_MAPPING` payload -- which socket a STUN server
 * answered for (`signalling` nonzero for this client's own, zero for a
 * call's media socket) and the public address it saw it from -- or null
 * for an event of any other kind, whose `payload.nat` carries nothing.
 */
fun natOf(event: SipralEvent): SipralNatEvent? =
    if (event.kind == SipralEventKind.NAT_MAPPING.value.toLong()) event.payload.nat else null

/**
 * The `SIPRAL_EVENT_KIND_NAT_RELAY` payload -- whether the TURN server
 * allocated a relay for a media socket, and where -- or null for an event
 * of any other kind. Nothing of the credential is in it.
 */
fun relayOf(event: SipralEvent): SipralNatRelayEvent? =
    if (event.kind == SipralEventKind.NAT_RELAY.value.toLong()) event.payload.relay else null
