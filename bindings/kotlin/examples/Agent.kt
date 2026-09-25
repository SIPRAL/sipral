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
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeout
import org.sipral.SipralEventKind
import org.sipral.SipralStreamStats
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

    // Kept fresh at a steady interval rather than read once when the call
    // is seen to be over: once the BYE is answered the stack tears this
    // call's media down on its own poll thread, so by the time either
    // collector below notices the call has ended, `statistics()` can
    // already answer WRONG_STATE (bindings/c/include/sipral.h, `sipral_media_statistics`:
    // "the end-of-call record arrives instead as
    // SIPRAL_EVENT_KIND_MEDIA_STATISTICS ... because by then the stream is
    // gone"). A read that lands mid-teardown is skipped, not fatal --
    // `stats` just keeps the last good reading, at most one interval stale.
    // Cheap enough for this rate: the same doc calls it fit "at the frame
    // rate of a user interface".
    var stats: SipralStreamStats? = null
    val polling = launch {
        while (isActive) {
            stats = try {
                media.statistics()
            } catch (_: Exception) {
                stats
            }
            delay(200)
        }
    }

    val hangingUp = launch {
        call.digits.collect { event ->
            val digit = digitOf(event) ?: return@collect
            println("dtmf $digit")
            if (digit == '#') {
                // One last read while the call is still certainly up, for
                // the freshest number this path can give.
                stats = try {
                    media.statistics()
                } catch (_: Exception) {
                    stats
                }
                call.hangup()
                return@collect
            }
        }
    }
    // No cap: scripts/lab.sh always ends this call itself, either through
    // the digit handler above or by the far end hanging up on its own, and
    // a fixed wait here would end a call that outlives it -- cutting short
    // a phone's own hang-up is this agent's bug to avoid, not the far
    // end's. bindings/python/examples/agent.py's own wait_for_remote_hangup
    // is the same shape, with the same absence of a cap.
    //
    // waitEnded, not a hand-rolled `if (!call.ended) events.first { ... }`:
    // that check-then-subscribe shape has a real gap between reading
    // `ended` and the flow subscribing, where a CALL_ENDED delivered on
    // the poll thread is missed outright (replay = 0), and with no cap
    // left the miss hangs forever. waitEnded subscribes UNDISPATCHED
    // before it reads `ended`, closing that gap.
    val ending = launch {
        call.waitEnded(Long.MAX_VALUE)
    }

    select<Unit> {
        hangingUp.onJoin { }
        ending.onJoin { }
    }
    talking.cancel()
    polling.cancel()
    hangingUp.cancel()
    ending.cancel()

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

    // One persistent collector, not a loop calling `events.first { }`
    // again for every call: a fresh subscription each time round that loop
    // would leave a real gap between one match completing and the next
    // subscribe -- an INCOMING_CALL landing in it would be missed outright
    // (a SharedFlow with replay = 0 never queues a value for a subscriber
    // that has not subscribed yet, bindings/kotlin/README.md's own note) --
    // and this agent is meant to keep listening for the next call, forever,
    // not to miss one to a race with its own bookkeeping.
    coroutineScope {
        client.events
            .filter { it.kind == SipralEventKind.INCOMING_CALL.value.toLong() }
            .collect { event ->
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
