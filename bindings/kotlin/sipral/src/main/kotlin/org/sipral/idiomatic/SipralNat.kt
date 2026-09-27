// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

package org.sipral.idiomatic

import javax.net.ssl.SSLSocketFactory
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralNatEvent
import org.sipral.SipralNatRelayEvent
import org.sipral.SipralTransport
import org.sipral.SipralTurnStreamEvent

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
 *
 * [transport] is how every media socket reaches it (RFC 8656 §3.1):
 * `SipralTransport.UDP` by default, `TCP` for a network that lets no UDP
 * out, `TLS` for one that lets one port out -- 5349 is TURN's -- or for an
 * application that wants the server checked. Over either the client opens
 * a connection per media socket itself and carries everything for the
 * relay on it; over TLS that is an `SSLSocket` from [sslSocketFactory] --
 * the platform default when null, one built over a `TrustManagerFactory`
 * of the application's own for a private CA or a self-signed server --
 * with the server's name, [serverName] or the host part of [address],
 * checked against its certificate. Nothing here turns checking off.
 */
class SipralTurnServer(
    val address: String,
    val username: String,
    internal val password: String,
    val transport: SipralTransport = SipralTransport.UDP,
    val serverName: String? = null,
    val sslSocketFactory: SSLSocketFactory? = null,
) {
    override fun toString(): String =
        "SipralTurnServer(address=$address, username=$username, password=<redacted>, transport=$transport)"
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

/**
 * The `SIPRAL_EVENT_KIND_TURN_STREAM` payload -- open a media socket's
 * connection to a TURN server reached over TCP or TLS, or close it, which
 * [SipralClient] does itself -- or null for an event of any other kind.
 */
fun turnStreamOf(event: SipralEvent): SipralTurnStreamEvent? =
    if (event.kind == SipralEventKind.TURN_STREAM.value.toLong()) event.payload.turnStream else null
