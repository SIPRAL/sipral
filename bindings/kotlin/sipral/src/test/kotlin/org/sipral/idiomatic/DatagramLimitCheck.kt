// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// RFC 3261 §18.1.1 through org.sipral.idiomatic: a call whose answer to a
// challenge is too large for a datagram -- the Kotlin counterpart of
// bindings/python/tests/test_datagram_limit.py. The PBX is this check's own,
// on loopback: a UDP socket that answers every INVITE without credentials
// with a 401 whose nonce takes the answer past 1300 bytes, and -- when asked
// for -- a TCP listener on the same port that answers the INVITE carrying
// credentials with a 486. With the listener there the client opens the
// connection itself and the call carries on over it; with none, or with
// `streamFallback = false`, the call ends at once with a 513 naming the
// limit, never hanging. Run by IdiomaticCheck.kt's main, under -Xcheck:jni.

package org.sipral.idiomatic

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.Collections
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.sipral.SipralCallEndReason
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralSrtp
import org.sipral.SipralStatus
import org.sipral.SipralTransportError

/** RFC 3261 §7.3.3's compact names for the fields this PBX reads: a request
 * over the line is written compact before it is weighed against it, and a
 * server reads either form. */
private val compactNames = mapOf("via" to "v", "from" to "f", "to" to "t", "call-id" to "i", "content-length" to "l")

private fun header(name: String, message: String): String? {
    val names = setOf(name.lowercase(), compactNames[name.lowercase()] ?: name.lowercase())
    return message.split("\r\n")
        .firstOrNull { it.contains(':') && it.substringBefore(':').trim().lowercase() in names }
        ?.substringAfter(':')?.trim()
}

private fun response(request: String, status: String, extra: String = ""): ByteArray {
    val lines = mutableListOf("SIP/2.0 $status")
    for (name in listOf("Via", "From", "To", "Call-ID", "CSeq")) {
        var value = header(name, request) ?: ""
        if (name == "To" && !value.contains(";tag=")) {
            value += ";tag=pbx"
        }
        lines += "$name: $value"
    }
    return (lines.joinToString("\r\n") + "\r\n" + extra + "Content-Length: 0\r\n\r\n").toByteArray(Charsets.UTF_8)
}

/** A PBX that challenges INVITEs over UDP, with a TCP listener when [tcp]:
 * on the same port, or -- [apart] -- on one of its own, as a PBX that takes
 * UDP on 5060 and TCP on 5160 has it. */
private class ChallengingPbx(tcp: Boolean, apart: Boolean = false) : AutoCloseable {
    private val udp = DatagramSocket(0, InetAddress.getByName("127.0.0.1")).apply { soTimeout = 50 }
    private val listener: ServerSocket? = if (tcp) {
        ServerSocket(if (apart) 0 else udp.localPort, 8, InetAddress.getByName("127.0.0.1")).apply { soTimeout = 50 }
    } else {
        null
    }
    @Volatile private var stopped = false
    val address = "127.0.0.1:${udp.localPort}"
    val tcpAddress: String? = listener?.let { "127.0.0.1:${it.localPort}" }
    val overTcp: MutableList<String> = Collections.synchronizedList(ArrayList())
    /** Every INVITE carrying credentials that arrived over UDP, and its size. */
    val answeredOverUdp: MutableList<Pair<String, Int>> = Collections.synchronizedList(ArrayList())
    @Volatile var connections = 0
    /** How many of those connections the client closed. */
    @Volatile var closedByTheClient = 0

    init {
        Thread(::serveUdp, "pbx-udp").apply { isDaemon = true; start() }
        if (listener != null) {
            Thread(::accept, "pbx-tcp").apply { isDaemon = true; start() }
        }
    }

    private fun serveUdp() {
        val nonce = "n".repeat(700)
        val buffer = ByteArray(65536)
        while (!stopped) {
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                udp.receive(packet)
            } catch (_: SocketTimeoutException) {
                continue
            } catch (_: Exception) {
                return
            }
            val message = String(packet.data, 0, packet.length, Charsets.UTF_8)
            if (message.startsWith("INVITE ") && header("Authorization", message) == null) {
                val challenge = "WWW-Authenticate: Digest realm=\"asterisk\", nonce=\"$nonce\", qop=\"auth\"\r\n"
                val out = response(message, "401 Unauthorized", challenge)
                udp.send(DatagramPacket(out, out.size, packet.socketAddress))
            } else if (message.startsWith("INVITE ")) {
                answeredOverUdp += message to packet.length
                val out = response(message, "486 Busy Here")
                udp.send(DatagramPacket(out, out.size, packet.socketAddress))
            }
        }
    }

    private fun accept() {
        while (!stopped) {
            val socket = try {
                listener!!.accept()
            } catch (_: SocketTimeoutException) {
                continue
            } catch (_: Exception) {
                return
            }
            connections += 1
            Thread({ serve(socket) }, "pbx-tcp-conn").apply { isDaemon = true; start() }
        }
    }

    private fun serve(socket: Socket) {
        socket.use {
            val input = it.getInputStream()
            val buffer = ByteArray(65536)
            var held = ""
            while (!stopped) {
                val read = try {
                    input.read(buffer)
                } catch (_: Exception) {
                    -1
                }
                if (read < 0) {
                    closedByTheClient += 1
                    return
                }
                held += String(buffer, 0, read, Charsets.UTF_8)
                while (true) {
                    val end = held.indexOf("\r\n\r\n")
                    if (end < 0) break
                    val head = held.substring(0, end) + "\r\n"
                    val length = header("Content-Length", head)?.toInt() ?: 0
                    if (held.length < end + 4 + length) break
                    held = held.substring(end + 4 + length)
                    overTcp += head
                    if (head.startsWith("INVITE ")) {
                        it.getOutputStream().write(response(head, "486 Busy Here"))
                    }
                }
            }
        }
    }

    override fun close() {
        stopped = true
        listener?.close()
        udp.close()
    }
}

/** Every event [client] raised from [place] until the call ended. */
private suspend fun untilTheEnd(client: SipralClient, place: () -> Unit): List<SipralEvent> =
    withTimeout(8_000) {
        coroutineScope {
            val seen = Collections.synchronizedList(ArrayList<SipralEvent>())
            val ended = async(start = CoroutineStart.UNDISPATCHED) {
                client.events.first {
                    seen += it
                    it.kind == SipralEventKind.CALL_ENDED.value.toLong()
                }
            }
            place()
            ended.await()
            seen.toList()
        }
    }

private fun place(client: SipralClient, pbx: ChallengingPbx) {
    val account = client.addAccount(
        aor = "sip:alice@example.com",
        registrarAddress = pbx.address,
        authUser = "alice",
        authPassword = "open sesame",
        security = SipralAccountSecurity(
            srtp = SipralSrtp.OFFERED,
            srtpSuites = listOf("AEAD_AES_256_GCM", "AES_CM_128_HMAC_SHA1_80"),
        ),
    )
    client.placeCall(account, "sip:bob@example.com")
}

private suspend fun aPbxListeningOnTcpGetsTheAnswerOverAConnectionTheClientOpened(): String {
    ChallengingPbx(tcp = true).use { pbx ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
            val seen = untilTheEnd(client) { place(client, pbx) }
            val wanted = seen.mapNotNull { transportWantedOf(it) }
            assertEquals(1, wanted.size)
            assertEquals(pbx.address, wanted[0].destination)
            assertTrue(wanted[0].requestBytes > 1300, "${wanted[0].requestBytes}")
            assertEquals(1300L, wanted[0].limitBytes)
            val ended = seen.last().payload.call
            assertEquals(486L, ended.statusCode, "the PBX's own answer, over the connection")
            assertEquals(SipralCallEndReason.REFUSED.value.toLong(), ended.endReason)
            assertEquals(1, pbx.connections)
            val invites = pbx.overTcp.filter { it.startsWith("INVITE ") }
            assertEquals(1, invites.size)
            assertNotNull(header("Authorization", invites[0]))
            assertTrue(header("Via", invites[0])?.startsWith("SIP/2.0/TCP ") == true)
            // the dialog carries on over the connection: the 486 is
            // acknowledged on it (RFC 3261 §17.1.1.3)
            repeat(100) {
                if (pbx.overTcp.none { it.startsWith("ACK ") }) delay(20)
            }
            assertTrue(pbx.overTcp.any { it.startsWith("ACK ") }, "${pbx.overTcp}")
        }
    }
    return "a challenged call over the datagram limit goes on a connection the client opened"
}

private suspend fun aPbxOnUdpAloneEndsTheCallAtOnceWithTheLimitNamed(): String {
    ChallengingPbx(tcp = false).use { pbx ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
            val started = System.currentTimeMillis()
            val seen = untilTheEnd(client) { place(client, pbx) }
            assertTrue(System.currentTimeMillis() - started < 5_000, "ended by the refusal, not by the wait")
            val lost = seen.mapNotNull { transportFailedOf(it) }
            assertEquals(SipralTransportError.CONNECTION_REFUSED.value.toLong(), lost.firstOrNull()?.error)
            // where the connection was going and what became of it, for a log
            val detail = lost.firstOrNull()?.detail ?: ""
            assertTrue(detail.startsWith("TCP to ${pbx.address} refused"), detail)
            val ended = seen.last().payload.call
            assertEquals(SipralCallEndReason.UNREACHABLE.value.toLong(), ended.endReason)
            assertEquals(513L, ended.statusCode)
            assertEquals(513L, ended.causeSip)
            val text = ended.causeText?.toString(Charsets.UTF_8) ?: ""
            assertTrue(text.contains("1300-byte") && text.contains("18.1.1"), text)
        }
    }
    return "one with no stream to go on ends at once with the limit named"
}

/** A deliberate deviation from §18.1.1: no stream is coming, and the
 * client was told the server takes a large request over UDP. */
private suspend fun aPbxOnUdpAloneTakesTheRequestOverUdpUpToTheClientsLimit(): String {
    ChallengingPbx(tcp = false).use { pbx ->
        SipralClient.open(
            audio = SipralAudioMode.Application, bindHost = "127.0.0.1", pathMtu = 1500, datagramWithoutStreamBytes = 4000,
        ).use { client ->
            val seen = untilTheEnd(client) { place(client, pbx) }
            assertEquals(486L, seen.last().payload.call.statusCode, "the PBX's own answer, over UDP")
            val (invite, bytes) = pbx.answeredOverUdp.single()
            assertNotNull(header("Authorization", invite))
            assertTrue(bytes > 1300, "$bytes")
            val diagnostics = client.diagnosticsJson()
            assertTrue(diagnostics.contains("transport.kept.datagram"))
            // written compact first, and still over the line
            assertTrue(diagnostics.contains("transport.compacted.size"))
        }
    }
    for ((options, what) in listOf(
        { SipralClient.open(audio = SipralAudioMode.Application, datagramWithoutStreamBytes = 65508) } to "past one datagram",
        { SipralClient.open(audio = SipralAudioMode.Application, pathMtu = 575) } to "under the IPv4 floor",
    )) {
        val refused = runCatching { options().close() }.exceptionOrNull()
        assertEquals(SipralStatus.INVALID_ARGUMENT, (refused as? SipralException)?.status, what)
    }
    return "one whose PBX takes UDP alone goes over UDP up to the client's limit"
}

private suspend fun aPbxTakingTcpOnAnotherPortIsReachedAtTheStreamServer(): String {
    ChallengingPbx(tcp = true, apart = true).use { pbx ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", streamServer = pbx.tcpAddress)
            .use { client ->
                val seen = untilTheEnd(client) { place(client, pbx) }
                assertEquals(486L, seen.last().payload.call.statusCode, "answered over the connection")
                assertEquals(1, pbx.connections)
                val invites = pbx.overTcp.filter { it.startsWith("INVITE ") }
                assertEquals(1, invites.size)
                assertNotNull(header("Authorization", invites[0]))
            }
    }
    return "one whose PBX takes TCP on another port reaches it at the stream server"
}

private suspend fun aClientToldToOpenNoStreamEndsTheCallWithoutTrying(): String {
    ChallengingPbx(tcp = true).use { pbx ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", streamFallback = false)
            .use { client ->
                val seen = untilTheEnd(client) { place(client, pbx) }
                assertEquals(513L, seen.last().payload.call.statusCode)
                assertEquals(0, pbx.connections, "nothing was opened")
                assertEquals(
                    "TCP to ${pbx.address} not tried: streamFallback is off",
                    seen.firstNotNullOfOrNull { transportFailedOf(it) }?.detail,
                )
            }
    }
    return "and so does one told to open none"
}

// RFC 5626 §4.4.1: the stack retires a stream that stopped answering
// keep-alives and says so with TRANSPORT_FAILED; the socket is this layer's,
// and one kept open would stand in for the new connection the stack asks for
// next time
private suspend fun aConnectionTheStackLetGoOfIsClosedHereToo(): String {
    ChallengingPbx(tcp = true).use { pbx ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
            untilTheEnd(client) { place(client, pbx) }
            assertEquals(1, pbx.connections)
            assertEquals(0, pbx.closedByTheClient, "the connection outlives the call")
            // the one connection opened is the last id handed out
            client.noteStreamLetGo(client.nextLink.get() - 1)
            repeat(150) {
                if (pbx.closedByTheClient == 0) delay(20)
            }
            assertEquals(1, pbx.closedByTheClient, "the connection was let go of")
        }
    }
    return "and a connection the stack let go of is closed here too"
}

internal suspend fun datagramLimitChecks(): String = listOf(
    aPbxListeningOnTcpGetsTheAnswerOverAConnectionTheClientOpened(),
    aPbxOnUdpAloneEndsTheCallAtOnceWithTheLimitNamed(),
    aPbxOnUdpAloneTakesTheRequestOverUdpUpToTheClientsLimit(),
    aPbxTakingTcpOnAnotherPortIsReachedAtTheStreamServer(),
    aClientToldToOpenNoStreamEndsTheCallWithoutTrying(),
    aConnectionTheStackLetGoOfIsClosedHereToo(),
).joinToString(", ")
