// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// A headless voice agent over org.sipral.idiomatic: registers, answers,
// echoes what it hears, hangs up on "#", and reports what it heard. The
// Kotlin equivalent of bindings/python/examples/agent.py, run in the lab by
// scripts/lab.sh's kotlin_agent the way python_agent runs the Python one,
// against the same [agent-call] extension.
//
//   SIPRAL_AOR=sip:labuser-agent-kotlin@asterisk \
//   SIPRAL_REGISTRAR=sip:asterisk \
//   SIPRAL_REGISTRAR_ADDRESS=203.0.113.10:5060 \
//   SIPRAL_AUTH_USER=labuser-agent-kotlin SIPRAL_AUTH_PASSWORD=labpass \
//   java -cp ... org.sipral.examples.AgentKt

package org.sipral.examples

import java.net.DatagramSocket
import java.net.InetSocketAddress
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeout
import org.sipral.SipralEventKind
import org.sipral.idiomatic.SipralCall
import org.sipral.idiomatic.SipralClient
import org.sipral.idiomatic.digitOf

/** Which of this host's addresses a datagram to `address` leaves from.
 * `bindings/python/examples/agent.py`'s own `route_to`: connecting a UDP
 * socket sends nothing, it only asks the system which route it would take,
 * which is what has to go in `Contact` and in every answer's SDP. */
private fun routeTo(address: String): String {
    val at = address.lastIndexOf(':')
    val host = address.substring(0, at)
    val port = address.substring(at + 1).toInt()
    DatagramSocket().use { probe ->
        probe.connect(InetSocketAddress(host, port))
        return probe.localAddress.hostAddress
    }
}

private suspend fun handleCall(call: SipralCall) = coroutineScope {
    println("answered ${call.handle.toString(16)}")
    withTimeout(10_000) {
        while (call.media == null) {
            delay(20)
        }
    }
    val media = call.media!!

    val talking = launch {
        media.frames.collect { frame -> media.sendAudio(frame) }
    }
    // Read while the call is still up: once the BYE is answered the stack
    // ends the call's media on its own poll thread, and a
    // sipral_media_statistics call after that answers that the media has
    // ended rather than with numbers -- bindings/python/examples/agent.py's
    // own comment on the same race, and its own fix, which this mirrors:
    // read the numbers right before hangup() rather than after it.
    var stats: org.sipral.SipralStreamStats? = null
    val hangingUp = launch {
        call.digits.collect { event ->
            val digit = digitOf(event) ?: return@collect
            println("dtmf $digit")
            if (digit == '#') {
                // Read while the call is still up. Once the BYE is answered
                // the stack ends the call's media on its own poll thread,
                // and a statistics() call after that answers that the media
                // has ended rather than with numbers -- Agent.kt's own
                // Python equivalent has the same race and the same fix.
                stats = try {
                    media.statistics()
                } catch (_: Exception) {
                    null
                }
                call.hangup()
                return@collect
            }
        }
    }
    val ending = launch { call.waitEnded(60_000) }

    select<Unit> {
        hangingUp.onJoin { }
        ending.onJoin { }
    }
    talking.cancel()
    hangingUp.cancel()
    ending.cancel()

    // The far end can also hang up first, with no third digit ever sent;
    // that path has not read the numbers yet, and this is its last chance
    // to -- the media handle is not released until close() below.
    if (stats == null) {
        stats = try {
            media.statistics()
        } catch (_: Exception) {
            null
        }
    }
    call.close()
    println(
        "ended ${call.handle.toString(16)} " +
            "packets_sent=${stats?.packetsSent ?: -1} packets_received=${stats?.packetsReceived ?: -1}",
    )
}

fun main() = runBlocking {
    val registrarAddress = System.getenv("SIPRAL_REGISTRAR_ADDRESS")
        ?: error("SIPRAL_REGISTRAR_ADDRESS is required")
    val host = routeTo(registrarAddress)
    val client = SipralClient.open(bindHost = host)
    val account = client.addAccount(
        aor = System.getenv("SIPRAL_AOR") ?: "sip:agent@example.invalid",
        registrarAddress = registrarAddress,
        registrar = System.getenv("SIPRAL_REGISTRAR"),
        authUser = System.getenv("SIPRAL_AUTH_USER"),
        authPassword = System.getenv("SIPRAL_AUTH_PASSWORD"),
    )
    if (System.getenv("SIPRAL_REGISTRAR") != null) {
        account.registerAndWait()
    }
    println("listening on ${client.bindAddress}")

    coroutineScope {
        while (true) {
            val event = client.events.first { it.kind == SipralEventKind.INCOMING_CALL.value.toLong() }
            val call = client.answerCall(event, mediaHost = host)
            launch {
                try {
                    handleCall(call)
                } catch (failure: Throwable) {
                    println("call failed: $failure")
                }
            }
        }
    }
}
