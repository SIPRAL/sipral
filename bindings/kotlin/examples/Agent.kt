// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
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
//
// SIPRAL_SIGNALLING is udp (the default), tcp or tls: over either of the
// last two the agent keeps one connection to SIPRAL_REGISTRAR_ADDRESS and
// signals on it, and over TLS checks the server's certificate against
// SIPRAL_TLS_SERVER_NAME (the address's host when unset) with SIPRAL_TLS_CA
// as the only authority it trusts (the platform's when unset). A connection
// that fails is printed as "transport failed error=<...> tls=<...>" with
// SSLSocket's own words, and tried again. SIPRAL_INVITE_LIMIT=voice-agent
// takes a trunk's rush of calls the default rate floor would answer 480.
// SIPRAL_TEXT=echo takes the real-time text a call offers, prints each
// piece as "text <...>" and types it back.

package org.sipral.examples

import java.io.File
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralIce
import org.sipral.SipralStreamStats
import org.sipral.SipralTlsFailure
import org.sipral.SipralTransport
import org.sipral.SipralTransportError
import org.sipral.idiomatic.SipralAudioMode
import org.sipral.idiomatic.SipralCall
import org.sipral.idiomatic.SipralClient
import org.sipral.idiomatic.SipralInviteLimit
import org.sipral.idiomatic.SipralTlsTrust
import org.sipral.idiomatic.SipralTurnServer
import org.sipral.idiomatic.digitOf
import org.sipral.idiomatic.transportFailedOf

/** With SIPRAL_TEXT=echo, what the caller types in real-time text (RFC
 * 4103) is printed and typed back to it. */
private val echoesText = System.getenv("SIPRAL_TEXT") == "echo"

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
    val texting = launch {
        call.text.collect { typed ->
            val text = typed.text.orEmpty()
            println("text \"$text\"")
            try {
                media.sendText(text)
            } catch (_: Exception) {
                // a stream gone with its call
            }
        }
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
    texting.cancel()
    polling.cancel()
    hangingUp.cancel()
    ending.cancel()

    call.close()
    println(
        "ended ${call.handle.toString(16)} " +
            "packets_sent=${stats?.packetsSent ?: -1} packets_received=${stats?.packetsReceived ?: -1}",
    )
}

/**
 * Talk for the life of one call this end placed, the same shape [handleCall]
 * is but for a peer with nothing of its own that would ever hang up first
 * (the lab's own two-NAT pair, `scripts/lab.sh`'s `ice_turn_flow`, where the
 * far end is the harness's own `iceanswer` role): [patienceMs] is how long
 * this end waits for media at all, so a call under `SipralIce.REQUIRED` with
 * every path blocked is given up on rather than waited on forever, and
 * [dwellMs] is how long it talks before hanging up on its own once media has
 * started. `false` when it ended before media ever started, which
 * [runDirectCall] needs to tell apart from an ordinary hangup.
 */
private suspend fun runCallDirect(call: SipralCall, patienceMs: Long, dwellMs: Long): Boolean = coroutineScope {
    println("answered ${call.handle.toString(16)}")
    try {
        withTimeout(patienceMs) {
            while (call.media == null && !call.ended) {
                delay(20)
            }
        }
    } catch (timedOut: TimeoutCancellationException) {
        println("ended ${call.handle.toString(16)}: no media within ${patienceMs}ms -- no path was ever chosen")
        try {
            call.hangup()
        } catch (_: SipralException) {
        }
        call.close()
        return@coroutineScope false
    }
    val media = call.media
    if (media == null) {
        println("ended ${call.handle.toString(16)}: no media -- the call never connected")
        call.close()
        return@coroutineScope false
    }

    val talking = launch {
        media.frames.collect { frame -> media.sendAudio(frame) }
    }
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
    val ending = launch { call.waitEnded(Long.MAX_VALUE) }
    val dwelling = launch { delay(dwellMs) }
    select<Unit> {
        ending.onJoin { }
        dwelling.onJoin { }
    }
    dwelling.cancel()
    if (!call.ended) {
        // one last read while the call is still certainly up, for the
        // freshest number this path can give
        stats = try {
            media.statistics()
        } catch (_: Exception) {
            stats
        }
        try {
            call.hangup()
        } catch (_: SipralException) {
        }
        // the relayed call's farewell -- the TURN Refresh that gives its
        // allocation back, not only the RTCP BYE -- is queued once the far
        // end's 200 to this end's own BYE is read on the poll thread, so
        // this waits for `ended` rather than closing right behind hangup()
        withTimeoutOrNull(5_000) { call.waitEnded() }
    }
    ending.cancel()
    talking.cancel()
    polling.cancel()
    // the same short wait bindings/python/examples/agent.py's own
    // hang_up_after_dwell gives, so a relayed call's farewell has had its
    // own turn on the poll thread before the stack tears the socket down
    delay(200)

    call.close()
    println(
        "ended ${call.handle.toString(16)}: packets_sent=${stats?.packetsSent ?: -1} " +
            "packets_received=${stats?.packetsReceived ?: -1}",
    )
    true
}

/**
 * Dial a peer straight at its address, no registrar between them --
 * `scripts/lab.sh`'s own `ice_turn_flow`, where the far end is the
 * harness's own `iceanswer` role rather than a server. SIPRAL_PEER_HOST/
 * SIPRAL_PEER_PORT name it, and the account this end adds is one
 * [SipralClient.addAccount]'s own registrarAddress is just the routing
 * destination for: `registrar` is left null, so nothing is ever registered.
 *
 * SIPRAL_STUN_SERVER turns on STUN the same way [SipralClient.open] already
 * offers any application; SIPRAL_TURN_SERVER/SIPRAL_TURN_USER/
 * SIPRAL_TURN_PASSWORD ride on it. SIPRAL_TURN_TRANSPORT is `udp`, `tcp` or
 * `tls` (RFC 8656 §3.1); over TLS the server's certificate is checked
 * against SIPRAL_TURN_NAME and trusted if it chains to the PEM file
 * SIPRAL_TURN_CA names, the platform's roots otherwise -- the lab's own
 * coturn presents a certificate made for the run, and this is how the run
 * tells the agent to trust it. SIPRAL_ICE=required asks
 * [SipralIce.REQUIRED] of the call this places, which is what makes a call
 * that cannot find a path fail outright rather than fall back to the
 * address this end bound to -- the one thing that would let a run through a
 * blocked NAT pair pass by accident.
 */
private suspend fun runDirectCall(): Boolean {
    val peerHost = System.getenv("SIPRAL_PEER_HOST") ?: error("SIPRAL_PEER_HOST is required")
    val peerPort = System.getenv("SIPRAL_PEER_PORT") ?: "5060"
    val peerUser = System.getenv("SIPRAL_PEER_USER") ?: "callee"
    val peer = "$peerHost:$peerPort"
    val host = routeTo(peer)

    val stunServer = System.getenv("SIPRAL_STUN_SERVER")
    val turnServer = System.getenv("SIPRAL_TURN_SERVER")
    val over = System.getenv("SIPRAL_TURN_TRANSPORT") ?: "udp"
    val transport = when (over) {
        "udp" -> SipralTransport.UDP
        "tcp" -> SipralTransport.TCP
        "tls" -> SipralTransport.TLS
        else -> error("SIPRAL_TURN_TRANSPORT is udp, tcp or tls, not $over")
    }
    val turn = if (turnServer != null) {
        SipralTurnServer(
            address = turnServer,
            username = System.getenv("SIPRAL_TURN_USER") ?: "",
            password = System.getenv("SIPRAL_TURN_PASSWORD") ?: "",
            transport = transport,
            serverName = System.getenv("SIPRAL_TURN_NAME"),
            sslSocketFactory = System.getenv("SIPRAL_TURN_CA")?.let(::trusting),
        )
    } else {
        null
    }
    val ice = if (System.getenv("SIPRAL_ICE") == "required") SipralIce.REQUIRED else null

    val client = SipralClient.open(audio = SipralAudioMode.Application, bindHost = host, stunServer = stunServer, turn = turn, ice = ice)
    val account = client.addAccount(aor = "sip:caller@${client.bindAddress}", registrarAddress = peer)
    println("dialling sip:$peerUser@$peer from ${client.bindAddress}")
    val call = try {
        client.placeCall(account, "sip:$peerUser@$peer", mediaHost = host, destination = peer)
    } catch (refused: SipralException) {
        println("call failed: $refused")
        client.close()
        return false
    }
    val patienceMs = System.getenv("SIPRAL_PATIENCE_MS")?.toLong() ?: 20_000L
    val dwellMs = System.getenv("SIPRAL_DWELL_MS")?.toLong() ?: 2_000L
    val ok = runCallDirect(call, patienceMs, dwellMs)
    client.close()
    if (ok && turn != null && transport != SipralTransport.UDP) {
        println("relay over ${over.uppercase()} to $turnServer: the call ran through it")
    }
    return ok
}

/** The authority in the PEM file at `path`. */
private fun authority(path: String): X509Certificate =
    File(path).inputStream().use { input ->
        CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
    }

/** A socket factory that trusts the certificates in the PEM file at `path`
 * and nothing else: how the lab's coturn, whose certificate is made for the
 * run, is trusted over TLS. */
private fun trusting(path: String): SSLSocketFactory {
    val anchors = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
    File(path).inputStream().use { input ->
        CertificateFactory.getInstance("X.509").generateCertificates(input).forEachIndexed { index, certificate ->
            anchors.setCertificateEntry("turn-$index", certificate)
        }
    }
    val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(anchors) }
    return SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) }.socketFactory
}

fun main() = runBlocking {
    // The lab's own NAT-pair flow (`ice_turn_flow`) runs this mode instead
    // of the registrar-and-listen one below: SIPRAL_PEER_HOST is what tells
    // the two apart, since a real registrar address never doubles as one --
    // the same tell bindings/python/examples/agent.py's own `main` reads.
    if (System.getenv("SIPRAL_PEER_HOST") != null) {
        if (!runDirectCall()) {
            kotlin.system.exitProcess(1)
        }
        return@runBlocking
    }
    val registrarAddress = System.getenv("SIPRAL_REGISTRAR_ADDRESS")
        ?: error("SIPRAL_REGISTRAR_ADDRESS is required")
    val host = routeTo(registrarAddress)
    val signalling = when (val over = System.getenv("SIPRAL_SIGNALLING") ?: "udp") {
        "udp" -> SipralTransport.UDP
        "tcp" -> SipralTransport.TCP
        "tls" -> SipralTransport.TLS
        else -> error("SIPRAL_SIGNALLING is udp, tcp or tls, not $over")
    }
    val streamed = signalling != SipralTransport.UDP
    val client = SipralClient.open(
        audio = SipralAudioMode.Application,
        bindHost = host,
        signalling = signalling,
        signallingServer = if (streamed) registrarAddress else null,
        tlsServerName = System.getenv("SIPRAL_TLS_SERVER_NAME"),
        tlsTrust = System.getenv("SIPRAL_TLS_CA")?.let { SipralTlsTrust.OnlyAuthority(authority(it)) }
            ?: SipralTlsTrust.Platform,
        inviteLimit = if (System.getenv("SIPRAL_INVITE_LIMIT") == "voice-agent") SipralInviteLimit.VOICE_AGENT else null,
    )
    val account = client.addAccount(
        aor = System.getenv("SIPRAL_AOR") ?: "sip:agent@example.invalid",
        registrarAddress = registrarAddress,
        registrar = System.getenv("SIPRAL_REGISTRAR"),
        authUser = System.getenv("SIPRAL_AUTH_USER"),
        authPassword = System.getenv("SIPRAL_AUTH_PASSWORD"),
    )
    if (streamed) {
        // over a connection the first attempt may already have failed, and
        // every one after it says so: printed as it happens, and the
        // registration left to go whenever the connection is made
        launch {
            client.events.collect { event ->
                transportFailedOf(event)?.let { failed ->
                    val error = SipralTransportError.of(failed.error.toInt())?.name?.lowercase()
                    val tls = SipralTlsFailure.of(failed.tls.toInt())?.name?.lowercase()
                    println("transport failed error=$error tls=$tls: ${failed.detail ?: ""}")
                }
            }
        }
        if (System.getenv("SIPRAL_REGISTRAR") != null) {
            account.register()
        }
    } else if (System.getenv("SIPRAL_REGISTRAR") != null) {
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
                val call = client.answerCall(event, mediaHost = host, text = echoesText)
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
