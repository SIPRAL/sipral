// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// A headless voice agent over org.sipral.idiomatic: registers, answers,
// echoes what it hears, hangs up on "#", and reports what it heard. The
// Kotlin twin of bindings/python/examples/agent.py, run by scripts/lab.sh's
// kotlin_agent against the [agent-call] extension.
//
//   SIPRAL_AOR=sip:labuser-agent-kotlin@asterisk \
//   SIPRAL_REGISTRAR=sip:asterisk \
//   SIPRAL_REGISTRAR_ADDRESS=203.0.113.10:5060 \
//   SIPRAL_AUTH_USER=labuser-agent-kotlin SIPRAL_AUTH_PASSWORD=labpass \
//   java -cp ... org.sipral.examples.AgentKt
//
// SIPRAL_SIGNALLING is udp (default), tcp or tls; over TLS the certificate
// is checked against SIPRAL_TLS_SERVER_NAME (default: the address's host)
// with SIPRAL_TLS_CA as the only authority (default: the platform's). A
// failed connection prints "transport failed error=<...> tls=<...>" and is
// retried. SIPRAL_INVITE_LIMIT=voice-agent lifts the default INVITE rate
// limit for a trunk. SIPRAL_TEXT=echo prints real-time text as
// "text <...>" and types it back.

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

/** Which local address a datagram to `address` leaves from: connecting a
 * UDP socket sends nothing, it only asks for the route. That address goes
 * in `Contact` and the SDP. */
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

    // Refreshed on an interval rather than read at the end: once the BYE is
    // answered the stack tears media down on its poll thread, and
    // `statistics()` may already answer WRONG_STATE (the end-of-call record
    // comes as MEDIA_STATISTICS instead). A read during teardown is skipped,
    // keeping the last good value.
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
                // a last read while the call is surely still up
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
    // No cap: lab.sh always ends this call (the "#" handler or the far end),
    // and a fixed wait would cut short a call that outlives it.
    //
    // waitEnded rather than `if (!call.ended) events.first { }`: that shape
    // misses a CALL_ENDED delivered between the check and the subscription,
    // and with no cap would hang forever.
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
 * Talk for one call this end placed, to a peer that never hangs up first
 * (lab.sh's `ice_turn_flow`, the harness's `iceanswer`). [patienceMs] bounds
 * the wait for media, so a `SipralIce.REQUIRED` call with every path
 * blocked gives up; [dwellMs] is how long it talks once media started.
 * `false` when it ended before media started.
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
        // a last read while the call is surely still up
        stats = try {
            media.statistics()
        } catch (_: Exception) {
            stats
        }
        try {
            call.hangup()
        } catch (_: SipralException) {
        }
        // the relayed call's farewell (TURN Refresh as well as RTCP BYE) is
        // queued once the 200 to our BYE is read, so wait for `ended` rather than
        // closing right after hangup()
        withTimeoutOrNull(5_000) { call.waitEnded() }
    }
    ending.cancel()
    talking.cancel()
    polling.cancel()
    // let the farewell take its turn on the poll thread before the socket goes
    delay(200)

    call.close()
    println(
        "ended ${call.handle.toString(16)}: packets_sent=${stats?.packetsSent ?: -1} " +
            "packets_received=${stats?.packetsReceived ?: -1}",
    )
    true
}

/**
 * Dial a peer directly, no registrar (lab.sh's `ice_turn_flow`).
 * SIPRAL_PEER_HOST/SIPRAL_PEER_PORT name it; the account's registrarAddress
 * is only a routing destination, and nothing is registered.
 *
 * SIPRAL_STUN_SERVER turns on STUN; SIPRAL_TURN_SERVER/USER/PASSWORD add
 * TURN. SIPRAL_TURN_TRANSPORT is `udp`, `tcp` or `tls` (RFC 8656 §3.1);
 * over TLS the certificate is checked against SIPRAL_TURN_NAME and trusted
 * if it chains to SIPRAL_TURN_CA (the lab's per-run coturn certificate),
 * else the platform roots. SIPRAL_ICE=required makes a call with no path
 * fail rather than fall back to the bound address, which would let a run
 * through a blocked NAT pair pass by accident.
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

/** A socket factory trusting only the certificates in the PEM file at
 * `path`: the lab's per-run coturn certificate. */
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
    // SIPRAL_PEER_HOST selects the NAT-pair mode (`ice_turn_flow`) instead of
    // registering and listening.
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
        // the first connection attempt may already have failed: print each
        // failure, and let registration go whenever it connects
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

    // One persistent collector, not `events.first { }` per call: resubscribing
    // leaves a gap where an INCOMING_CALL is missed (replay = 0).
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
