// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// SipralClient.open(ice, stunServer, turn) checked on the wire: an
// in-process STUN/TURN server reports every socket elsewhere, and the
// checks read what reaches a far end (Contact, SDP, relayed candidate,
// realm handling), plus two ICE-requiring clients carrying audio both
// ways. Run by IdiomaticCheck.kt's main, under -Xcheck:jni.

package org.sipral.idiomatic

import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.file.Files
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.util.Collections
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.onSubscription
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.sipral.SipralCandidateKind
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralIce
import org.sipral.SipralPathKind
import org.sipral.SipralPathOutcome
import org.sipral.SipralNatMapping
import org.sipral.SipralNatRelay
import org.sipral.SipralNatRelayEvent
import org.sipral.SipralStatus
import org.sipral.SipralStunServerState
import org.sipral.SipralTransport

/**
 * A STUN and TURN server on `host` that reports every socket at
 * `publicHost` with its port moved by ten thousand, so an address carrying
 * the socket's own port cannot pass. Binding gets an XOR-MAPPED-ADDRESS
 * (RFC 8489 §14.2); an unsigned Allocate gets a 401 with REALM and NONCE,
 * and a signed one is checked against the long-term key, MD5 of
 * `username:realm:password` (RFC 8489 §9.2.2), and answered with a signed
 * relay on 198.51.100.9. Silent until [open] is set.
 */
private class FakeStunServer(
    host: String,
    private val publicHost: String = "203.0.113.7",
    private val credential: Pair<String, String>? = null,
) : AutoCloseable {
    class Request(val method: Int, val from: String, val bytes: ByteArray, val attributes: Map<Int, ByteArray>)

    val socket = DatagramSocket(0, InetAddress.getByName(host)).apply { soTimeout = 20 }
    val address = formatAddress(host, socket.localPort)
    val requests: MutableList<Request> = Collections.synchronizedList(ArrayList())

    @Volatile var open = false

    @Volatile var signedAllocateVerified: Boolean? = null

    @Volatile private var running = true
    private val thread = Thread(::serve, "fake-stun").apply {
        isDaemon = true
        start()
    }

    override fun close() {
        running = false
        thread.join(2000)
        socket.close()
    }

    private fun serve() {
        val buffer = ByteArray(2048)
        while (running) {
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                socket.receive(packet)
            } catch (_: SocketTimeoutException) {
                continue
            } catch (_: Exception) {
                return
            }
            val from = formatAddress(packet.address.hostAddress, packet.port)
            val request = parse(packet.data.copyOfRange(0, packet.length), from) ?: continue
            requests += request
            if (!open) continue
            val answer = answer(request) ?: continue
            socket.send(DatagramPacket(answer, answer.size, packet.socketAddress))
        }
    }

    private fun answer(request: Request): ByteArray? {
        val transaction = request.bytes.copyOfRange(8, 20)
        return when (request.method) {
            0x0001 -> message(0x0101, transaction, listOf(0x0020 to xorAddress(mapped(request.from, publicHost))))
            0x0003 -> {
                val (username, password) = credential ?: return null
                val given = request.attributes[0x0006]
                    ?: return message(
                        0x0113, transaction,
                        listOf(
                            0x0009 to byteArrayOf(0, 0, 4, 1) + "Unauthorized".toByteArray(),
                            0x0014 to REALM.toByteArray(),
                            0x0015 to NONCE.toByteArray(),
                        ),
                    )
                val key = MessageDigest.getInstance("MD5").digest("$username:$REALM:$password".toByteArray())
                val verified = String(given) == username && integrityHolds(request.bytes, key)
                signedAllocateVerified = verified
                if (!verified) {
                    return message(0x0113, transaction, listOf(0x0009 to byteArrayOf(0, 0, 4, 1)))
                }
                val port = parseHostPort(request.from).port
                signed(
                    0x0103, transaction,
                    listOf(
                        0x0016 to xorAddress("$RELAY_HOST:${moved(port, 20000)}"),
                        0x0020 to xorAddress(mapped(request.from, publicHost)),
                        0x000D to byteArrayOf(0, 0, 0x02, 0x58),
                    ),
                    key,
                )
            }
            else -> null
        }
    }

    companion object {
        const val REALM = "sipral.test"
        const val NONCE = "0123456789abcdef"
        const val RELAY_HOST = "198.51.100.9"
        private val COOKIE = byteArrayOf(0x21, 0x12, 0xA4.toByte(), 0x42)

        fun moved(port: Int, by: Int): Int = if (port > 40000) port - by else port + by

        fun mapped(local: String, publicHost: String = "203.0.113.7"): String =
            "$publicHost:${moved(parseHostPort(local).port, 10000)}"

        private fun u16(bytes: ByteArray, at: Int): Int =
            ((bytes[at].toInt() and 0xFF) shl 8) or (bytes[at + 1].toInt() and 0xFF)

        fun parse(data: ByteArray, from: String): Request? {
            if (data.size < 20 || !data.copyOfRange(4, 8).contentEquals(COOKIE)) return null
            val type = u16(data, 0)
            if (type and 0x0110 != 0) return null
            val method = (type and 0x000F) or ((type and 0x00E0) shr 1) or ((type and 0x3E00) shr 2)
            val attributes = HashMap<Int, ByteArray>()
            var offset = 20
            while (offset + 4 <= data.size) {
                val length = u16(data, offset + 2)
                if (offset + 4 + length > data.size) break
                attributes[u16(data, offset)] = data.copyOfRange(offset + 4, offset + 4 + length)
                offset += 4 + (length + 3) / 4 * 4
            }
            return Request(method, from, data, attributes)
        }

        fun message(type: Int, transaction: ByteArray, attributes: List<Pair<Int, ByteArray>>): ByteArray {
            var body = ByteArray(0)
            for ((attribute, value) in attributes) {
                val padding = ByteArray((4 - value.size % 4) % 4)
                body += byteArrayOf(
                    (attribute shr 8).toByte(), attribute.toByte(), (value.size shr 8).toByte(), value.size.toByte(),
                ) + value + padding
            }
            return byteArrayOf((type shr 8).toByte(), type.toByte(), (body.size shr 8).toByte(), body.size.toByte()) +
                COOKIE + transaction + body
        }

        fun xorAddress(address: String): ByteArray {
            val parsed = parseHostPort(address)
            val octets = parsed.address.address
            val port = parsed.port xor 0x2112
            return byteArrayOf(0, 0x01, (port shr 8).toByte(), port.toByte()) +
                ByteArray(4) { (octets[it].toInt() xor COOKIE[it].toInt()).toByte() }
        }

        private fun hmac(data: ByteArray, key: ByteArray): ByteArray =
            Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(key, "HmacSHA1")) }.doFinal(data)

        /** RFC 8489 §14.5: the HMAC covers the message up to the attribute,
         * with the header's length counting up to the attribute's end. */
        fun integrityHolds(message: ByteArray, key: ByteArray): Boolean {
            var offset = 20
            while (offset + 4 <= message.size) {
                val length = u16(message, offset + 2)
                if (u16(message, offset) == 0x0008 && length == 20 && offset + 24 <= message.size) {
                    val covered = message.copyOfRange(0, offset)
                    val counted = offset + 24 - 20
                    covered[2] = (counted shr 8).toByte()
                    covered[3] = counted.toByte()
                    return hmac(covered, key).contentEquals(message.copyOfRange(offset + 4, offset + 24))
                }
                offset += 4 + (length + 3) / 4 * 4
            }
            return false
        }

        fun signed(type: Int, transaction: ByteArray, attributes: List<Pair<Int, ByteArray>>, key: ByteArray): ByteArray {
            val unsigned = message(type, transaction, attributes)
            val counted = unsigned.size - 20 + 24
            unsigned[2] = (counted shr 8).toByte()
            unsigned[3] = counted.toByte()
            return unsigned + byteArrayOf(0x00, 0x08, 0x00, 0x14) + hmac(unsigned, key)
        }
    }
}

/** A non-loopback IPv4 address of this machine, since RFC 8445 §5.1.1.1
 * keeps loopback out of candidates. Nothing leaves the machine. */
private fun hostAddress(): String? = NetworkInterface.getNetworkInterfaces().asSequence()
    .filter { it.isUp && !it.isLoopback && !it.isPointToPoint && !it.isVirtual }
    .flatMap { it.inetAddresses.asSequence() }
    .firstOrNull { it is Inet4Address }
    ?.hostAddress

/** The first datagram `peer` reads that starts with `prefix`, as text. */
private fun read(peer: DatagramSocket, prefix: String, withinMs: Long = 10_000): String? {
    val deadline = System.currentTimeMillis() + withinMs
    val buffer = ByteArray(65536)
    peer.soTimeout = 50
    while (System.currentTimeMillis() < deadline) {
        val packet = DatagramPacket(buffer, buffer.size)
        try {
            peer.receive(packet)
        } catch (_: SocketTimeoutException) {
            continue
        }
        val text = String(packet.data, 0, packet.length, Charsets.UTF_8)
        if (text.startsWith(prefix)) return text
    }
    return null
}

private suspend fun firstEvent(client: SipralClient, withinMs: Long = 10_000, match: (SipralEvent) -> Boolean): SipralEvent? =
    withTimeoutOrNull(withinMs) { client.events.first(match) }

/** Every event `client` raises from now on, collected on its own thread,
 * for a check that blocks in `placeCall`. */
private fun recordEvents(client: SipralClient, forMs: Long): MutableList<SipralEvent> {
    val seen = Collections.synchronizedList(ArrayList<SipralEvent>())
    val subscribed = java.util.concurrent.CountDownLatch(1)
    Thread {
        runBlocking {
            withTimeoutOrNull(forMs) {
                client.events.onSubscription { subscribed.countDown() }.collect { seen += it }
            }
        }
    }.apply {
        isDaemon = true
        start()
    }
    subscribed.await()
    return seen
}

private fun stunMappingReachesContactAndSdp(host: String): String {
    FakeStunServer(host).use { stun ->
        DatagramSocket(0, InetAddress.getByName(host)).use { peer ->
            val peerAddress = formatAddress(host, peer.localPort)
            SipralClient.open(audio = SipralAudioMode.Application, bindHost = host, stunServer = stun.address).use { client ->
                val seen = recordEvents(client, 20_000)
                val account = client.addAccount(aor = "sip:alice@example.invalid", registrarAddress = peerAddress)
                stun.open = true
                val deadline = System.currentTimeMillis() + 10_000
                fun mappingFor(signalling: Boolean) =
                    seen.toList().mapNotNull { natOf(it) }.firstOrNull { (it.signalling != 0L) == signalling }
                while (mappingFor(true) == null && System.currentTimeMillis() < deadline) Thread.sleep(20)
                val sip = assertNotNull(mappingFor(true), "the STUN server's answer never became an event")
                assertEquals(SipralNatMapping.LEARNED.value.toLong(), sip.mapping)
                assertEquals(client.bindAddress, sip.local)
                assertEquals(FakeStunServer.mapped(client.bindAddress), sip.mapped)
                assertEquals(1L, sip.accounts)

                client.placeCall(account, target = "sip:bob@$peerAddress", mediaHost = host).use {
                    // placeCall returns once the poll thread saw the mapping, before the
                    // event reaches this collector
                    val mediaDeadline = System.currentTimeMillis() + 5_000
                    while (mappingFor(false) == null && System.currentTimeMillis() < mediaDeadline) Thread.sleep(20)
                    val media = assertNotNull(mappingFor(false), "the media socket was never mapped")
                    assertEquals(FakeStunServer.mapped(media.local!!), media.mapped)
                    val invite = assertNotNull(read(peer, "INVITE "), "no INVITE reached the far end")
                    val publicMedia = parseHostPort(FakeStunServer.mapped(media.local))
                    assertTrue(
                        invite.contains("@${FakeStunServer.mapped(client.bindAddress)}"),
                        "the INVITE's Contact does not name the public address:\n$invite",
                    )
                    assertFalse(invite.contains("@${client.bindAddress}>"), "the Contact still names the private socket")
                    assertTrue(invite.contains("c=IN IP4 ${publicMedia.hostString}"), "the SDP does not name the public address")
                    assertTrue(invite.contains("m=audio ${publicMedia.port} "), "the SDP does not name the public port")
                }
                return "a STUN mapping reached the Contact and the SDP"
            }
        }
    }
}

/** `stunFallbacks`: the first server never answers, and after 5.5 s the
 * next is asked, with `SIPRAL_EVENT_KIND_STUN_SERVER` reporting it. */
private fun aSilentFirstServerHandsOver(host: String): String {
    DatagramSocket(0, InetAddress.getByName(host)).use { silent ->
        val silentAddress = formatAddress(host, silent.localPort)
        FakeStunServer(host).use { stun ->
            stun.open = true
            SipralClient.open(
                audio = SipralAudioMode.Application,
                bindHost = host,
                stunServer = silentAddress,
                stunFallbacks = listOf(stun.address),
            ).use { client ->
                val seen = recordEvents(client, 15_000)
                val deadline = System.currentTimeMillis() + 12_000
                fun changed() = seen.toList().mapNotNull { stunServerOf(it) }.firstOrNull()
                fun mapped() = seen.toList().mapNotNull { natOf(it) }.firstOrNull { it.signalling != 0L }
                while ((changed() == null || mapped() == null) && System.currentTimeMillis() < deadline) {
                    Thread.sleep(20)
                }
                val moved = assertNotNull(changed(), "no STUN server event after the first server stayed silent")
                assertEquals(SipralStunServerState.CHANGED.value.toLong(), moved.state)
                assertEquals(silentAddress, moved.previous)
                assertEquals(stun.address, moved.server)
                val sip = assertNotNull(mapped(), "the next server's answer never became a mapping")
                assertEquals(FakeStunServer.mapped(client.bindAddress), sip.mapped)
                return "a silent first STUN server handed the socket to the next"
            }
        }
    }
}

/** [SipralClient.setStunServers] on a client opened without STUN: the
 * signalling socket is mapped at once, a later call is offered at the
 * mapped address, and a malformed entry is refused. */
private fun aListNamedLaterMapsTheSignallingAndTheCalls(host: String): String {
    FakeStunServer(host).use { stun ->
        stun.open = true
        DatagramSocket(0, InetAddress.getByName(host)).use { peer ->
            val peerAddress = formatAddress(host, peer.localPort)
            SipralClient.open(audio = SipralAudioMode.Application, bindHost = host).use { client ->
                val seen = recordEvents(client, 15_000)
                client.setStunServers(listOf(stun.address))
                assertEquals(stun.address, client.stunServer)
                val deadline = System.currentTimeMillis() + 10_000
                fun mapped() = seen.toList().mapNotNull { natOf(it) }.firstOrNull { it.signalling != 0L }
                while (mapped() == null && System.currentTimeMillis() < deadline) Thread.sleep(20)
                val sip = assertNotNull(mapped(), "the server named later never mapped the signalling socket")
                assertEquals(FakeStunServer.mapped(client.bindAddress), sip.mapped)

                val account = client.addAccount(aor = "sip:alice@example.invalid", registrarAddress = peerAddress)
                client.placeCall(account, target = "sip:bob@$peerAddress", mediaHost = host).use {
                    val invite = assertNotNull(read(peer, "INVITE "), "no INVITE reached the far end")
                    assertTrue(invite.contains("c=IN IP4 203.0.113.7"), "the SDP does not name the public address:\n$invite")
                }

                client.setStunServers(emptyList())
                assertNull(client.stunServer)
                val refused = assertFailsWith<SipralException> { client.setStunServers(listOf("not an address")) }
                assertEquals(SipralStatus.INVALID_ARGUMENT, refused.status)
                return "a STUN server named on an open client mapped its signalling and its calls"
            }
        }
    }
}

private fun turnRelayIsAllocatedAndOffered(host: String): String {
    val password = "turn-secret-${System.nanoTime() % 1_000_000}"
    val turn = SipralTurnServer("", "alice-turn", password)
    assertFalse(turn.toString().contains(password), "SipralTurnServer.toString shows the password")
    FakeStunServer(host, credential = "alice-turn" to password).use { stun ->
        DatagramSocket(0, InetAddress.getByName(host)).use { peer ->
            val peerAddress = formatAddress(host, peer.localPort)
            stun.open = true
            SipralClient.open(
                audio = SipralAudioMode.Application,
                bindHost = host,
                ice = SipralIce.OFFERED,
                stunServer = stun.address,
                turn = SipralTurnServer(stun.address, "alice-turn", password),
            ).use { client ->
                val seen = recordEvents(client, 60_000)
                val account = client.addAccount(aor = "sip:alice@example.invalid", registrarAddress = peerAddress)
                client.placeCall(account, target = "sip:bob@$peerAddress", mediaHost = host).use {
                    // the relay event reaches `seen` on the recorder's thread, which may run
                    // after placeCall returns
                    fun relayed() = seen.toList().mapNotNull { relayOf(it) }.firstOrNull()
                    val deadline = System.currentTimeMillis() + 10_000
                    while (relayed() == null && System.currentTimeMillis() < deadline) Thread.sleep(20)
                    val relay = assertNotNull(relayed(), "no relay event")
                    assertEquals(SipralNatRelay.ALLOCATED.value.toLong(), relay.outcome, "relay failed: ${relay.code} ${relay.reason}")
                    val relayed = parseHostPort(relay.relayed!!)
                    assertEquals(FakeStunServer.RELAY_HOST, relayed.hostString)

                    val allocates = stun.requests.toList().filter { it.method == 0x0003 }
                    assertNull(allocates.first().attributes[0x0006], "the first Allocate carries no credential")
                    val signed = assertNotNull(allocates.firstOrNull { it.attributes[0x0006] != null }, "no signed Allocate")
                    assertEquals("alice-turn", signed.attributes[0x0006]?.let { String(it) })
                    assertEquals(FakeStunServer.REALM, signed.attributes[0x0014]?.let { String(it) })
                    assertEquals(FakeStunServer.NONCE, signed.attributes[0x0015]?.let { String(it) })
                    assertEquals(true, stun.signedAllocateVerified, "the Allocate's MESSAGE-INTEGRITY is not the long-term key's")
                    for (request in stun.requests.toList()) {
                        assertFalse(String(request.bytes, Charsets.ISO_8859_1).contains(password), "the password crossed the wire")
                    }
                    val invite = assertNotNull(read(peer, "INVITE "), "no INVITE reached the far end")
                    assertTrue(
                        invite.contains("${FakeStunServer.RELAY_HOST} ${relayed.port} typ relay"),
                        "the offer does not carry the relay as a candidate:\n$invite",
                    )
                }
                return "a TURN relay allocated with the credential's realm and nonce and offered as a candidate"
            }
        }
    }
}

private suspend fun iceBehindStunCarriesAudio(host: String): String {
    FakeStunServer(host, publicHost = host).use { stun ->
        stun.open = true
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = host, ice = SipralIce.REQUIRED, stunServer = stun.address).use { alice ->
            SipralClient.open(audio = SipralAudioMode.Application, bindHost = host, ice = SipralIce.REQUIRED, stunServer = stun.address).use { bob ->
                val aliceAccount = alice.addAccount(aor = "sip:alice@example.invalid", registrarAddress = bob.bindAddress)
                bob.addAccount(aor = "sip:bob@example.invalid", registrarAddress = alice.bindAddress)
                val (aliceCall, incoming) = bob.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
                    alice.placeCall(aliceAccount, target = "sip:bob@${bob.bindAddress}", mediaHost = host)
                }
                aliceCall.use {
                    bob.answerCall(incoming, mediaHost = host).use { bobCall ->
                        val chosen = firstEvent(alice) { it.kind == SipralEventKind.MEDIA_PATH_CHOSEN.value.toLong() }
                        assertNotNull(chosen, "ICE never chose a path")
                        val deadline = System.currentTimeMillis() + 5_000
                        while ((aliceCall.media == null || bobCall.media == null) && System.currentTimeMillis() < deadline) {
                            delay(20)
                        }
                        val aliceMedia = assertNotNull(aliceCall.media, "alice's media never started")
                        val bobMedia = assertNotNull(bobCall.media, "bob's media never started")
                        val until = System.currentTimeMillis() + 5_000
                        while (System.currentTimeMillis() < until &&
                            (aliceMedia.statistics().packetsReceived < 10 || bobMedia.statistics().packetsReceived < 10)
                        ) {
                            delay(50)
                        }
                        val heardByAlice = aliceMedia.statistics().packetsReceived
                        val heardByBob = bobMedia.statistics().packetsReceived
                        assertTrue(heardByAlice >= 10 && heardByBob >= 10, "RTP both ways: $heardByAlice and $heardByBob")
                        assertTrue(
                            stun.requests.toList().any {
                                it.method == 0x0001 && it.from != alice.bindAddress && it.from != bob.bindAddress
                            },
                            "no media socket asked the STUN server",
                        )
                        return "two clients requiring ICE behind STUN carried $heardByAlice and $heardByBob RTP packets"
                    }
                }
            }
        }
    }
}

/**
 * `SipralIce.LITE` answering a full agent that requires ICE (RFC 8445
 * §2.5): the lite end offers its host candidate and answers checks, the
 * full end nominates, both report the pair, and audio crosses both ways.
 */
private suspend fun liteAnsweringAFullAgentCarriesAudio(host: String): String {
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = host, ice = SipralIce.REQUIRED).use { alice ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = host, ice = SipralIce.LITE).use { bob ->
            val aliceAccount = alice.addAccount(aor = "sip:alice@example.invalid", registrarAddress = bob.bindAddress)
            bob.addAccount(aor = "sip:bob@example.invalid", registrarAddress = alice.bindAddress)
            val (aliceCall, incoming) = bob.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
                alice.placeCall(aliceAccount, target = "sip:bob@${bob.bindAddress}", mediaHost = host)
            }
            val offer = String(assertNotNull(incoming.message, "the INVITE rode along"), Charsets.UTF_8)
            assertFalse(offer.contains("a=ice-lite"), "the caller is the full agent:\n$offer")
            aliceCall.use {
                val (bobCall, chosenAtBob) = bob.events.awaitNext(SipralEventKind.MEDIA_PATH_CHOSEN, timeoutMs = 15_000) {
                    bob.answerCall(incoming, mediaHost = host)
                }
                bobCall.use {
                    assertEquals(bobCall.handle, chosenAtBob.call, "the lite end took the pair on its own call")
                    val deadline = System.currentTimeMillis() + 5_000
                    while ((aliceCall.media == null || bobCall.media == null) && System.currentTimeMillis() < deadline) {
                        delay(20)
                    }
                    val aliceMedia = assertNotNull(aliceCall.media, "alice's media never started")
                    val bobMedia = assertNotNull(bobCall.media, "bob's media never started")
                    val until = System.currentTimeMillis() + 5_000
                    while (System.currentTimeMillis() < until &&
                        (aliceMedia.statistics().packetsReceived < 10 || bobMedia.statistics().packetsReceived < 10)
                    ) {
                        delay(50)
                    }
                    val heardByAlice = aliceMedia.statistics().packetsReceived
                    val heardByBob = bobMedia.statistics().packetsReceived
                    assertTrue(heardByAlice >= 10 && heardByBob >= 10, "RTP both ways: $heardByAlice and $heardByBob")
                    return "a lite client answering a full one carried $heardByAlice and $heardByBob RTP packets"
                }
            }
        }
    }
}

/**
 * A call that allocated a TURN relay gives it back when it ends:
 * `drainFarewells` must send `stackPollFarewell`'s packet to the
 * destination it names (the TURN server, for the zero-lifetime Refresh),
 * falling back to the last media source only when none is named. A peer
 * without ICE still had a relay allocated, so a plain call that connects
 * and closes is enough: sending to the far end instead would never reach
 * this fake server.
 */
private suspend fun turnAllocationIsGivenBackWhenTheCallEnds(host: String): String {
    val password = "turn-secret-${System.nanoTime() % 1_000_000}"
    FakeStunServer(host, credential = "alice-turn" to password).use { stun ->
        stun.open = true
        // PCMU only: three ICE candidates plus every default codec exceed RFC
        // 3261 §18.1.1's 1300 bytes, and this loopback pair has no stream to fall
        // back to.
        SipralClient.open(
            audio = SipralAudioMode.Application,
            bindHost = host,
            ice = SipralIce.OFFERED,
            codecs = "PCMU",
            stunServer = stun.address,
            turn = SipralTurnServer(stun.address, "alice-turn", password),
        ).use { alice ->
            SipralClient.open(audio = SipralAudioMode.Application, bindHost = host, codecs = "PCMU").use { bob ->
                val seen = recordEvents(alice, 30_000)
                val aliceAccount = alice.addAccount(aor = "sip:alice@example.invalid", registrarAddress = bob.bindAddress)
                bob.addAccount(aor = "sip:bob@example.invalid", registrarAddress = alice.bindAddress)
                val (aliceCall, incoming) = bob.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
                    alice.placeCall(aliceAccount, target = "sip:bob@${bob.bindAddress}", mediaHost = host)
                }
                val relayDeadline = System.currentTimeMillis() + 10_000
                fun relayEvent() = seen.toList().mapNotNull { relayOf(it) }.firstOrNull()
                while (relayEvent() == null && System.currentTimeMillis() < relayDeadline) Thread.sleep(20)
                val relay = assertNotNull(relayEvent(), "no relay event")
                assertEquals(SipralNatRelay.ALLOCATED.value.toLong(), relay.outcome, "relay failed: ${relay.code} ${relay.reason}")

                val bobCall = bob.answerCall(incoming, mediaHost = host)

                // wait for the session to open and the relay to become the call's; bob
                // does no ICE, so MEDIA_PATH_CHOSEN never fires here
                val mediaDeadline = System.currentTimeMillis() + 8_000
                while (aliceCall.media == null && System.currentTimeMillis() < mediaDeadline) delay(20)
                assertNotNull(aliceCall.media, "alice's media never started")

                // SipralClient.close, not SipralCall.close: forgetting the call here would
                // race the poll thread's drain of its farewell. close() hangs up, lets the
                // poll thread drain while the call is tracked, then forgets it.
                alice.close()
                bobCall.close()

                val deadline = System.currentTimeMillis() + 5_000
                while (stun.requests.toList().none { it.method == 0x0004 } && System.currentTimeMillis() < deadline) {
                    Thread.sleep(20)
                }
                val refresh = assertNotNull(
                    stun.requests.toList().firstOrNull { it.method == 0x0004 },
                    "the TURN server never saw the Refresh that gives the relay back -- " +
                        "the farewell went somewhere other than ${stun.address}",
                )
                val lifetime = assertNotNull(refresh.attributes[0x000D], "the Refresh carries no LIFETIME")
                assertTrue(lifetime.contentEquals(byteArrayOf(0, 0, 0, 0)), "the Refresh does not ask for a lifetime of zero")
                return "the TURN allocation was given back to the server, not the far end, when the call ended"
            }
        }
    }
}

/**
 * ICE paths and a local restart through the idiomatic layer: the agent
 * reports the chosen pair and every other's outcome, and `restartIce()`
 * rechecks under new credentials until a second path is chosen.
 */
private suspend fun iceCallSaysWhichPathsItTriedAndRestarts(host: String): String {
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = host, ice = SipralIce.REQUIRED).use { alice ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = host, ice = SipralIce.REQUIRED).use { bob ->
            val aliceAccount = alice.addAccount(aor = "sip:alice@example.invalid", registrarAddress = bob.bindAddress)
            bob.addAccount(aor = "sip:bob@example.invalid", registrarAddress = alice.bindAddress)
            val (aliceCall, incoming) = bob.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
                alice.placeCall(aliceAccount, target = "sip:bob@${bob.bindAddress}", mediaHost = host)
            }
            aliceCall.use {
                bob.answerCall(incoming, mediaHost = host).use {
                    val chosen = firstEvent(alice) { it.kind == SipralEventKind.MEDIA_PATH_CHOSEN.value.toLong() }
                    assertNotNull(chosen, "ICE never chose a path")
                    val deadline = System.currentTimeMillis() + 5_000
                    while (aliceCall.media == null && System.currentTimeMillis() < deadline) {
                        delay(20)
                    }
                    val aliceMedia = assertNotNull(aliceCall.media, "alice's media never started")
                    val paths = aliceMedia.pathCandidates()
                    val selected = paths.filter {
                        it.kind == SipralPathKind.PAIR && it.outcome == SipralPathOutcome.SELECTED
                    }
                    assertTrue(selected.size == 1, "one pair carries the call: $paths")
                    assertTrue(
                        selected.single().localKind == SipralCandidateKind.HOST &&
                            selected.single().priority > 0 && selected.single().remote.isNotEmpty(),
                        "the selected pair is not described: $paths",
                    )

                    // the restart's selection is a second PATH_CHOSEN, subscribed before
                    // asking for it
                    val (_, again) = alice.events.awaitNext(SipralEventKind.MEDIA_PATH_CHOSEN, timeoutMs = 15_000) {
                        aliceCall.restartIce()
                    }
                    assertNotNull(again, "the restart never chose a path again")
                    return "an ICE call named ${paths.size} paths, one selected, and a restart chose again"
                }
            }
        }
    }
}

/** An account STUN showed behind a NAT keeps the registrar flow open: a
 * lone double CRLF every `registrarKeepaliveMs`, and none with the
 * keep-alive off (`docs/06-nat.md`). */
private fun registrarFlowIsKeptOpenBehindTheNat(host: String): String {
    for (keepalive in listOf(true, false)) {
        FakeStunServer(host).use { stun ->
            DatagramSocket(0, InetAddress.getByName(host)).use { registrar ->
                val registrarAddress = formatAddress(host, registrar.localPort)
                SipralClient.open(
                    audio = SipralAudioMode.Application,
                    bindHost = host,
                    stunServer = stun.address,
                    registrarKeepalive = keepalive,
                    registrarKeepaliveMs = if (keepalive) 1_000 else 0,
                ).use { client ->
                    val seen = recordEvents(client, 15_000)
                    val account = client.addAccount(
                        aor = "sip:alice@example.invalid",
                        registrarAddress = registrarAddress,
                        registrar = "sip:example.invalid",
                    )
                    stun.open = true
                    val deadline = System.currentTimeMillis() + 10_000
                    while (seen.toList().none { natOf(it)?.signalling == 1L } &&
                        System.currentTimeMillis() < deadline
                    ) {
                        Thread.sleep(20)
                    }
                    assertTrue(seen.toList().any { natOf(it)?.signalling == 1L }, "the STUN server's answer never became an event")
                    account.register()
                    val ping = read(registrar, "\r\n\r\n", withinMs = if (keepalive) 5_000 else 3_000)
                    if (keepalive) {
                        assertEquals("\r\n\r\n", ping, "no keep-alive reached the registrar")
                    } else {
                        assertEquals(null, ping, "a keep-alive went out with it turned off")
                    }
                }
            }
        }
    }
    return "an account behind the NAT kept its registrar's flow open, and did not with it off"
}

/**
 * A TURN server on loopback TCP only (TLS when given a TLS server socket).
 * Framing per RFC 8656 §12.5 and RFC 8489 §6.2.2; every request is recorded
 * with its connection number from one. Unsigned Allocate gets 401, signed
 * one a relay, any other signed request success.
 */
private class FakeTurnOverStream(
    private val credential: Pair<String, String>,
    private val listener: ServerSocket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1")),
) : AutoCloseable {
    class Request(val connection: Int, val method: Int, val attributes: Map<Int, ByteArray>)

    val address = "127.0.0.1:${listener.localPort}"
    val requests: MutableList<Request> = Collections.synchronizedList(ArrayList())
    val closed: MutableList<Int> = Collections.synchronizedList(ArrayList())
    @Volatile private var connections = 0
    private val accepting = Thread(::accept, "fake-turn-stream").apply {
        isDaemon = true
        start()
    }

    val allocations: List<Int>
        get() = requests.toList().filter { it.method == 0x0003 && it.attributes.containsKey(0x0006) }.map { it.connection }

    val refreshes: List<Pair<Int, ByteArray?>>
        get() = requests.toList().filter { it.method == 0x0004 && it.attributes.containsKey(0x0006) }
            .map { it.connection to it.attributes[0x000D] }

    override fun close() {
        listener.close()
        accepting.join(2000)
    }

    private fun accept() {
        while (!listener.isClosed) {
            val connection = try {
                listener.accept()
            } catch (_: Exception) {
                return
            }
            connections += 1
            val number = connections
            Thread({ serve(connection, number) }, "fake-turn-connection").apply {
                isDaemon = true
                start()
            }
        }
    }

    private fun serve(connection: Socket, number: Int) {
        val input = connection.getInputStream()
        val output = connection.getOutputStream()
        var held = ByteArray(0)
        val buffer = ByteArray(4096)
        while (true) {
            val read = try {
                input.read(buffer)
            } catch (_: Exception) {
                -1
            }
            if (read < 0) {
                closed += number
                connection.close()
                return
            }
            held += buffer.copyOfRange(0, read)
            while (true) {
                val (frame, rest) = frame(held) ?: break
                held = rest
                answer(frame, number)?.let {
                    output.write(it)
                    output.flush()
                }
            }
        }
    }

    private fun frame(held: ByteArray): Pair<ByteArray, ByteArray>? {
        if (held.size < 4) return null
        val length = (held[2].toInt() and 0xff shl 8) or (held[3].toInt() and 0xff)
        if ((held[0].toInt() and 0xff) < 4) {
            if (held.size < 20 + length) return null
            return held.copyOfRange(0, 20 + length) to held.copyOfRange(20 + length, held.size)
        }
        val padded = (4 + length + 3) / 4 * 4
        if (held.size < padded) return null
        return held.copyOfRange(0, 4 + length) to held.copyOfRange(padded, held.size)
    }

    private fun answer(frame: ByteArray, number: Int): ByteArray? {
        if ((frame[0].toInt() and 0xff) >= 4) return null
        val request = FakeStunServer.parse(frame, "") ?: return null
        requests += Request(number, request.method, request.attributes)
        val transaction = frame.copyOfRange(8, 20)
        val type = (frame[0].toInt() and 0xff shl 8) or (frame[1].toInt() and 0xff)
        if (!request.attributes.containsKey(0x0006)) {
            return FakeStunServer.message(
                type or 0x0110,
                transaction,
                listOf(
                    0x0009 to (byteArrayOf(0, 0, 4, 1) + "Unauthorized".toByteArray()),
                    0x0014 to FakeStunServer.REALM.toByteArray(),
                    0x0015 to FakeStunServer.NONCE.toByteArray(),
                ),
            )
        }
        val key = MessageDigest.getInstance("MD5")
            .digest("${credential.first}:${FakeStunServer.REALM}:${credential.second}".toByteArray())
        if (!FakeStunServer.integrityHolds(frame, key)) return null
        return when (request.method) {
            0x0003 -> FakeStunServer.signed(
                0x0103,
                transaction,
                listOf(
                    0x0016 to FakeStunServer.xorAddress("198.51.100.39:${50000 + number}"),
                    0x0020 to FakeStunServer.xorAddress("203.0.113.39:${41000 + number}"),
                    0x000D to byteArrayOf(0, 0, 0x02, 0x58),
                ),
                key,
            )
            0x0004 -> FakeStunServer.signed(
                type or 0x0100,
                transaction,
                listOf(0x000D to (request.attributes[0x000D] ?: byteArrayOf(0, 0, 0x02, 0x58))),
                key,
            )
            else -> FakeStunServer.signed(type or 0x0100, transaction, emptyList(), key)
        }
    }
}

private const val TURN_SERVER_NAME = "turn.sipral.test"

/** A key and certificate for [TURN_SERVER_NAME] made with `openssl`: the
 * server's key manager, and a client socket factory trusting only it. */
private fun selfSigned(): Pair<SSLContext, SSLSocketFactory> {
    val openssl = listOf("/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", "/usr/bin/openssl")
        .firstOrNull { File(it).canExecute() } ?: error("no openssl command to make the server's certificate with")
    val directory = Files.createTempDirectory("sipral-turn").toFile()
    try {
        val key = File(directory, "turn.key").path
        val pem = File(directory, "turn.pem").path
        val p12 = File(directory, "turn.p12").path
        fun run(vararg arguments: String) {
            val process = ProcessBuilder(listOf(openssl) + arguments).redirectErrorStream(true).start()
            process.inputStream.readAllBytes()
            check(process.waitFor() == 0) { "openssl ${arguments.first()} failed" }
        }
        run(
            "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
            "-subj", "/CN=$TURN_SERVER_NAME", "-addext", "subjectAltName=DNS:$TURN_SERVER_NAME",
            "-addext", "extendedKeyUsage=serverAuth", "-keyout", key, "-out", pem,
        )
        run("pkcs12", "-export", "-inkey", key, "-in", pem, "-passout", "pass:sipral", "-out", p12)
        val identity = KeyStore.getInstance("PKCS12").apply { File(p12).inputStream().use { load(it, "sipral".toCharArray()) } }
        val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
            init(identity, "sipral".toCharArray())
        }
        val server = SSLContext.getInstance("TLS").apply { init(keys.keyManagers, null, null) }
        val certificate = File(pem).inputStream().use { CertificateFactory.getInstance("X.509").generateCertificate(it) }
        val anchors = KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setCertificateEntry("turn", certificate)
        }
        val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(anchors) }
        val client = SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) }
        return server to client.socketFactory
    } finally {
        directory.deleteRecursively()
    }
}

/**
 * Alice behind `server`, reached as `turn` says, calls Bob, who answers;
 * returns her relay event. The call is closed with the clients still
 * running, so its farewell goes out after it.
 */
private suspend fun callThrough(
    host: String,
    stun: FakeStunServer,
    turn: SipralTurnServer,
    afterRelay: suspend (SipralNatRelayEvent) -> Unit,
) {
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = host, ice = SipralIce.OFFERED, codecs = "PCMU", stunServer = stun.address, turn = turn)
        .use { alice ->
            SipralClient.open(audio = SipralAudioMode.Application, bindHost = host, codecs = "PCMU").use { bob ->
                val seen = recordEvents(alice, 30_000)
                val aliceAccount = alice.addAccount(aor = "sip:alice@example.invalid", registrarAddress = bob.bindAddress)
                bob.addAccount(aor = "sip:bob@example.invalid", registrarAddress = alice.bindAddress)
                val (aliceCall, incoming) = bob.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
                    alice.placeCall(aliceAccount, target = "sip:bob@${bob.bindAddress}", mediaHost = host)
                }
                val relayDeadline = System.currentTimeMillis() + 10_000
                fun relayEvent() = seen.toList().mapNotNull { relayOf(it) }.firstOrNull()
                while (relayEvent() == null && System.currentTimeMillis() < relayDeadline) Thread.sleep(20)
                val relay = assertNotNull(relayEvent(), "no relay event")
                val bobCall = bob.answerCall(incoming, mediaHost = host)
                val mediaDeadline = System.currentTimeMillis() + 8_000
                while (aliceCall.media == null && System.currentTimeMillis() < mediaDeadline) delay(20)
                assertNotNull(aliceCall.media, "alice's media never started, relay or not")
                aliceCall.close()
                bobCall.close()
                afterRelay(relay)
            }
        }
}

private fun until(withinMs: Long = 5_000, done: () -> Boolean) {
    val deadline = System.currentTimeMillis() + withinMs
    while (!done() && System.currentTimeMillis() < deadline) Thread.sleep(20)
}

private suspend fun turnOverTcpIsMadeAndGivenBackOnItsConnection(host: String): String {
    val password = "turn-secret-${System.nanoTime() % 1_000_000}"
    FakeStunServer(host).use { stun ->
        stun.open = true
        FakeTurnOverStream("alice-turn" to password).use { server ->
            val turn = SipralTurnServer(server.address, "alice-turn", password, transport = SipralTransport.TCP)
            callThrough(host, stun, turn) { relay ->
                assertEquals(SipralNatRelay.ALLOCATED.value.toLong(), relay.outcome, "relay failed: ${relay.code} ${relay.reason}")
                assertTrue(relay.mapped.isNullOrEmpty(), "the connection's own mapping says nothing about the socket")
                assertEquals(listOf(1), server.allocations, "one Allocate, on the one connection")
                assertTrue(stun.requests.toList().none { it.method == 0x0003 }, "an Allocate went as a datagram")
                until { server.refreshes.any { it.second?.contentEquals(byteArrayOf(0, 0, 0, 0)) == true } }
                assertEquals(
                    listOf(1),
                    server.refreshes.filter { it.second?.contentEquals(byteArrayOf(0, 0, 0, 0)) == true }.map { it.first },
                    "given back on the connection it was made on, after the call was gone",
                )
                until { 1 in server.closed }
                assertTrue(1 in server.closed, "the connection was closed once nothing was left for it")
            }
        }
    }
    return "a relay over TCP was made and given back on its connection"
}

private suspend fun turnOverTlsTrustsWhatItIsTold(host: String): String {
    val password = "turn-secret-${System.nanoTime() % 1_000_000}"
    val (serverContext, trusting) = selfSigned()
    for (trusted in listOf(true, false)) {
        FakeStunServer(host).use { stun ->
            stun.open = true
            val listener = serverContext.serverSocketFactory.createServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
            FakeTurnOverStream("alice-turn" to password, listener).use { server ->
                val turn = SipralTurnServer(
                    server.address,
                    "alice-turn",
                    password,
                    transport = SipralTransport.TLS,
                    serverName = TURN_SERVER_NAME,
                    sslSocketFactory = if (trusted) trusting else null,
                )
                callThrough(host, stun, turn) { relay ->
                    if (trusted) {
                        assertEquals(SipralNatRelay.ALLOCATED.value.toLong(), relay.outcome, "relay failed: ${relay.code} ${relay.reason}")
                        assertEquals(listOf(1), server.allocations)
                    } else {
                        assertEquals(SipralNatRelay.FAILED.value.toLong(), relay.outcome, "a certificate nobody vouches for")
                        assertTrue(relay.reason?.contains("connection") == true, "${relay.reason}")
                        assertTrue(server.allocations.isEmpty(), "nothing reached the server past the handshake")
                    }
                }
            }
        }
    }
    return "a relay over TLS was made with the roots it was told to trust, and refused without them"
}

/** Everything above, for IdiomaticCheck.kt's main. */
internal suspend fun natChecks(): String {
    val host = hostAddress() ?: error("no interface but loopback: ICE has no host candidate to check with")
    return listOf(
        stunMappingReachesContactAndSdp(host),
        aSilentFirstServerHandsOver(host),
        aListNamedLaterMapsTheSignallingAndTheCalls(host),
        registrarFlowIsKeptOpenBehindTheNat(host),
        turnRelayIsAllocatedAndOffered(host),
        iceBehindStunCarriesAudio(host),
        iceCallSaysWhichPathsItTriedAndRestarts(host),
        liteAnsweringAFullAgentCarriesAudio(host),
        turnAllocationIsGivenBackWhenTheCallEnds(host),
        turnOverTcpIsMadeAndGivenBackOnItsConnection(host),
        turnOverTlsTrustsWhatItIsTold(host),
    ).joinToString(", ")
}
