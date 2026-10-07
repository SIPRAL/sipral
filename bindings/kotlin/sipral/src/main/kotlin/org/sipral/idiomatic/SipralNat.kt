// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.idiomatic

import javax.net.ssl.SSLSocketFactory
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralLink
import org.sipral.SipralNatEvent
import org.sipral.SipralNatRelayEvent
import org.sipral.SipralStunServerEvent
import org.sipral.SipralTransport
import org.sipral.SipralTurnStreamEvent

/**
 * A TURN server (RFC 8656) and this end's long-term credential:
 * `sipral_stack_config_t::turn_server`, `turn_username`, `turn_password`,
 * for [SipralClient.open].
 *
 * `address` is `host:port`, an address, not a name. Not a data class:
 * [toString] omits the password, since a leaked TURN credential is a relay
 * anyone can use, and a generated `toString` or `component3` would expose
 * it.
 *
 * [transport] is how media sockets reach it (RFC 8656 §3.1): `UDP` by
 * default, `TCP` where UDP is blocked, `TLS` where one port (5349) is open
 * or the server must be authenticated. Over TCP/TLS the client opens one
 * connection per media socket. TLS uses [sslSocketFactory] (platform
 * default when null; supply one for a private CA) and checks [serverName]
 * (default: the host of [address]). Checking cannot be turned off.
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
 * The `SIPRAL_EVENT_KIND_NAT_MAPPING` payload (which socket STUN answered
 * for, `signalling` nonzero for the client's own, and the public address),
 * or null for any other kind.
 */
fun natOf(event: SipralEvent): SipralNatEvent? =
    if (event.kind == SipralEventKind.NAT_MAPPING.value.toLong()) event.payload.nat else null

/**
 * The `SIPRAL_EVENT_KIND_NAT_RELAY` payload (whether and where a relay was
 * allocated), or null for any other kind. It holds nothing of the
 * credential.
 */
fun relayOf(event: SipralEvent): SipralNatRelayEvent? =
    if (event.kind == SipralEventKind.NAT_RELAY.value.toLong()) event.payload.relay else null

/**
 * The `SIPRAL_EVENT_KIND_TURN_STREAM` payload (open or close a media
 * socket's TCP/TLS connection to TURN, which [SipralClient] does itself),
 * or null for any other kind.
 */
fun turnStreamOf(event: SipralEvent): SipralTurnStreamEvent? =
    if (event.kind == SipralEventKind.TURN_STREAM.value.toLong()) event.payload.turnStream else null

/**
 * The `SIPRAL_EVENT_KIND_STUN_SERVER` payload (the STUN server in use
 * moved along [SipralClient.open]'s list, or all failed), or null for any
 * other kind.
 */
fun stunServerOf(event: SipralEvent): SipralStunServerEvent? =
    if (event.kind == SipralEventKind.STUN_SERVER.value.toLong()) event.payload.stunServer else null

/**
 * The device's network, as much as the stack needs
 * (`sipral_stack_network_changed`) for [SipralClient.networkChanged]: link
 * kind, local IPv4 literal without port, the platform's interface name
 * (opaque), and whether names resolve.
 */
data class SipralNetwork(
    val link: SipralLink,
    val address: String? = null,
    val interfaceName: String? = null,
    val resolves: Boolean = true,
)
