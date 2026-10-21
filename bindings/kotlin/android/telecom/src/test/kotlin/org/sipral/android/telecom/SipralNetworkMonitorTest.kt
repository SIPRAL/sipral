// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// What SipralNetworkMonitor tells the stack a network is, from what Android
// says of it: the kind, the address and the interface. The address is the
// one the stack's IPv4 sockets can bind; a network that has none is down to
// the stack, whatever Android calls it.

package org.sipral.android.telecom

import android.net.NetworkCapabilities
import java.net.InetAddress
import org.sipral.SipralLink
import org.sipral.idiomatic.SipralNetwork
import org.testng.Assert.assertEquals
import org.testng.annotations.Test

class SipralNetworkMonitorTest {
    private fun at(vararg text: String): List<InetAddress> = text.map { InetAddress.getByName(it) }

    @Test
    fun wifiIsNamedByItsIpv4Address() {
        assertEquals(
            SipralNetworkMonitor.networkOf(
                setOf(NetworkCapabilities.TRANSPORT_WIFI),
                at("fe80::1", "2001:db8::16", "10.0.2.16"),
                "wlan0",
            ),
            SipralNetwork(SipralLink.WIFI, "10.0.2.16", "wlan0"),
        )
    }

    @Test
    fun mobileDataIsCellular() {
        assertEquals(
            SipralNetworkMonitor.networkOf(setOf(NetworkCapabilities.TRANSPORT_CELLULAR), at("10.0.2.15"), "eth0"),
            SipralNetwork(SipralLink.CELLULAR, "10.0.2.15", "eth0"),
        )
    }

    @Test
    fun aVpnIsATunnelWhateverItRunsOver() {
        assertEquals(
            SipralNetworkMonitor.networkOf(
                setOf(NetworkCapabilities.TRANSPORT_VPN, NetworkCapabilities.TRANSPORT_WIFI),
                at("10.8.0.2"),
                "tun0",
            ).link,
            SipralLink.TUNNEL,
        )
    }

    @Test
    fun ethernetIsWired() {
        assertEquals(
            SipralNetworkMonitor.networkOf(setOf(NetworkCapabilities.TRANSPORT_ETHERNET), at("192.0.2.5"), "eth1").link,
            SipralLink.WIRED,
        )
    }

    @Test
    fun aNetworkWithOnlyIpv6OrLinkLocalIsDownToTheStack() {
        assertEquals(
            SipralNetworkMonitor.networkOf(
                setOf(NetworkCapabilities.TRANSPORT_CELLULAR),
                at("2001:db8::7", "169.254.3.4", "127.0.0.1"),
                "rmnet0",
            ),
            SipralNetwork(SipralLink.DOWN, interfaceName = "rmnet0"),
        )
    }
}
