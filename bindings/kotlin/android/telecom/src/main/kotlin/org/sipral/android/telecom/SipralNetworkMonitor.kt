// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.android.telecom

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.content.Context
import java.net.Inet4Address
import java.net.InetAddress
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralLink
import org.sipral.SipralStatus
import org.sipral.idiomatic.SipralClient
import org.sipral.idiomatic.SipralNetwork
import org.sipral.telecom.IdiomaticSipCalls

/**
 * The phone's default network, followed: every change Android reports for
 * it becomes [SipralClient.networkChanged], and every call the stack then
 * asks to move (`SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED`) is offered at the
 * new network with [org.sipral.idiomatic.SipralCall.moveMedia], or
 * [org.sipral.idiomatic.SipralCall.restartIce] for a call under ICE.
 *
 * Wi-Fi giving way to mobile data, the reverse, and a network coming back
 * after airplane mode change the address the phone is reached at; without
 * this, the registration and every call go on naming the address that is
 * gone, and nothing arrives. Changes are handled one at a time, in the
 * order Android reported them, off the thread it reported them on.
 * [report] hears one line for each thing done, for the application's log.
 *
 * [initial] is the network the client was opened on (`network =` at
 * [SipralClient.open], built with [current]): Android reports the default
 * network as soon as this starts listening, and that first report is then
 * recognised as no change.
 */
class SipralNetworkMonitor(
    context: Context,
    private val client: SipralClient,
    private val calls: IdiomaticSipCalls,
    scope: CoroutineScope,
    initial: SipralNetwork? = null,
    private val report: (String) -> Unit = {},
) : AutoCloseable {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val changes = Channel<SipralNetwork>(Channel.UNLIMITED)
    private var last: SipralNetwork? = initial

    // What Android last said of the default network, and which network that
    // was: when the default moves, the new network's capabilities can arrive
    // before its link properties, and the two must never be mixed across
    // networks (Wi-Fi's kind with the mobile network's address).
    private var current: Network? = null
    private var capabilities: NetworkCapabilities? = null
    private var properties: LinkProperties? = null

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, now: NetworkCapabilities) {
            follow(network)
            capabilities = now
            offer()
        }

        override fun onLinkPropertiesChanged(network: Network, now: LinkProperties) {
            follow(network)
            properties = now
            offer()
        }

        override fun onLost(network: Network) {
            if (network != current) {
                return
            }
            current = null
            capabilities = null
            properties = null
            changes.trySend(SipralNetwork(SipralLink.DOWN))
        }
    }

    private fun follow(network: Network) {
        if (network != current) {
            current = network
            capabilities = null
            properties = null
        }
    }

    private val worker: Job = scope.launch(Dispatchers.IO) {
        for (next in changes) {
            apply(next)
        }
    }

    private val mover: Job = scope.launch(Dispatchers.IO) {
        client.events.collect { event ->
            if (event.kind == SipralEventKind.CALL_ADDRESS_WANTED.value.toLong()) {
                move(event.call)
            }
        }
    }

    init {
        connectivity.registerDefaultNetworkCallback(callback)
    }

    private fun offer() {
        val transports = capabilities?.let { held -> TRANSPORTS.filter { held.hasTransport(it) }.toSet() } ?: return
        val linked = properties ?: return
        changes.trySend(networkOf(transports, linked.linkAddresses.map { it.address }, linked.interfaceName))
    }

    private fun apply(next: SipralNetwork) {
        if (next == last) {
            return
        }
        last = next
        try {
            val recovery = client.networkChanged(next)
            report("network ${describe(next)}: ${recovery.name.lowercase()}")
        } catch (refused: SipralException) {
            report("network ${describe(next)} refused: ${refused.message}")
        } catch (refused: java.io.IOException) {
            report("network ${describe(next)}: no socket there (${refused.message})")
        }
    }

    private fun move(handle: Long) {
        val call = calls.call(handle) ?: return
        try {
            call.moveMedia()
            report("call ${handle.toString(16)}: media offered on the new network")
        } catch (refused: SipralException) {
            if (refused.status != SipralStatus.WRONG_STATE || call.media == null) {
                report("call ${handle.toString(16)}: media not moved, ${refused.message}")
                return
            }
            // under ICE the address is not moved, every path is checked again
            try {
                call.restartIce()
                report("call ${handle.toString(16)}: ICE restarted on the new network")
            } catch (again: SipralException) {
                report("call ${handle.toString(16)}: media not moved, ${again.message}")
            }
        } catch (refused: java.io.IOException) {
            report("call ${handle.toString(16)}: no media socket on the new network (${refused.message})")
        }
    }

    override fun close() {
        try {
            connectivity.unregisterNetworkCallback(callback)
        } catch (_: IllegalArgumentException) {
            // never registered, or already let go
        }
        changes.close()
        worker.cancel()
        mover.cancel()
    }

    companion object {
        private val TRANSPORTS = listOf(
            NetworkCapabilities.TRANSPORT_WIFI,
            NetworkCapabilities.TRANSPORT_CELLULAR,
            NetworkCapabilities.TRANSPORT_ETHERNET,
            NetworkCapabilities.TRANSPORT_VPN,
        )

        /**
         * What a network Android describes is to the stack: its kind from
         * the transports it runs over (a VPN over anything is a tunnel), the
         * first IPv4 address it holds, since the stack's sockets are IPv4,
         * and the interface it is on.
         */
        fun networkOf(transports: Set<Int>, addresses: List<InetAddress>, interfaceName: String?): SipralNetwork {
            val link = when {
                NetworkCapabilities.TRANSPORT_VPN in transports -> SipralLink.TUNNEL
                NetworkCapabilities.TRANSPORT_WIFI in transports -> SipralLink.WIFI
                NetworkCapabilities.TRANSPORT_CELLULAR in transports -> SipralLink.CELLULAR
                NetworkCapabilities.TRANSPORT_ETHERNET in transports -> SipralLink.WIRED
                transports.isEmpty() -> SipralLink.DOWN
                else -> SipralLink.WIRED
            }
            val address = addresses.firstOrNull {
                it is Inet4Address && !it.isLoopbackAddress && !it.isLinkLocalAddress
            }?.hostAddress
            return if (address == null) {
                SipralNetwork(SipralLink.DOWN, interfaceName = interfaceName)
            } else {
                SipralNetwork(link, address, interfaceName)
            }
        }

        /** The default network as it is now, [networkOf] what Android says
         * of it: what to open the client on. */
        fun current(context: Context): SipralNetwork {
            val connectivity = context.getSystemService(ConnectivityManager::class.java)
            val network = connectivity.activeNetwork ?: return SipralNetwork(SipralLink.DOWN)
            val held = connectivity.getNetworkCapabilities(network) ?: return SipralNetwork(SipralLink.DOWN)
            val linked = connectivity.getLinkProperties(network) ?: return SipralNetwork(SipralLink.DOWN)
            return networkOf(
                TRANSPORTS.filter { held.hasTransport(it) }.toSet(),
                linked.linkAddresses.map { it.address },
                linked.interfaceName,
            )
        }

        private fun describe(network: SipralNetwork): String =
            listOfNotNull(network.link.name.lowercase(), network.interfaceName, network.address).joinToString(" ")
    }
}
