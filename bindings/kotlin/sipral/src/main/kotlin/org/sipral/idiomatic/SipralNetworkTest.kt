// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.idiomatic

import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralNatKind
import org.sipral.SipralNetworkProbe
import org.sipral.SipralNetworkVerdict
import org.sipral.SipralServerReach

/**
 * What a network test found (`SIPRAL_EVENT_KIND_NETWORK_TEST`): every part of
 * one test [SipralClient.networkTest] started, and the [verdict], the worst
 * of the parts tested. [roundTripMs] is null when RTCP brought none back;
 * [local] is the socket the STUN answer was about and [mapped] where the
 * server saw it.
 */
class SipralNetworkTest(
    val test: Long,
    val verdict: SipralNetworkVerdict?,
    val stun: SipralNetworkProbe?,
    val nat: SipralNatKind?,
    val turn: SipralNetworkProbe?,
    val server: SipralServerReach?,
    val serverStatus: Long,
    val serverRoundTripMs: Long,
    val echo: SipralNetworkProbe?,
    val echoVerdict: SipralNetworkVerdict?,
    val lossPercent: Double,
    val jitterMs: Double,
    val roundTripMs: Long?,
    val rFactor: Long,
    val mos: Double,
    val local: String?,
    val mapped: String?,
)

/** The `SIPRAL_EVENT_KIND_NETWORK_TEST` payload, or null for an event of any
 * other kind. */
fun networkTestOf(event: SipralEvent): SipralNetworkTest? {
    if (event.kind != SipralEventKind.NETWORK_TEST.value.toLong()) {
        return null
    }
    val told = event.payload.networkTest
    return SipralNetworkTest(
        told.test,
        SipralNetworkVerdict.of(told.verdict.toInt()),
        SipralNetworkProbe.of(told.stun.toInt()),
        SipralNatKind.of(told.nat.toInt()),
        SipralNetworkProbe.of(told.turn.toInt()),
        SipralServerReach.of(told.server.toInt()),
        told.serverStatus,
        told.serverRoundTripMs,
        SipralNetworkProbe.of(told.echo.toInt()),
        SipralNetworkVerdict.of(told.echoVerdict.toInt()),
        told.lossPercent,
        told.jitterMs,
        told.roundTripMs.takeIf { told.hasRoundTrip != 0L },
        told.rFactor,
        told.mos,
        told.local?.takeIf { it.isNotEmpty() },
        told.mapped?.takeIf { it.isNotEmpty() },
    )
}
