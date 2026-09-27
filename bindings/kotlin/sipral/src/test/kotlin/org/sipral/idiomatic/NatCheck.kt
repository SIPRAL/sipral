// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// What SipralClient.open(ice, stunServer, turn) carries, proven on the wire
// rather than by reading a field back: a STUN and TURN server in the test
// itself tells every socket it appears somewhere else, and the checks look at
// what reaches a far end -- the INVITE's Contact and SDP, the relay offered
// as a candidate, the credential's realm handling -- and at two clients that
// require ICE carrying audio both ways through sockets the stack reads until
// their media exists. Run by IdiomaticCheck.kt's main, under -Xcheck:jni.

package org.sipral.idiomatic

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.util.Collections
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.onSubscription
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralIce
import org.sipral.SipralNatMapping
import org.sipral.SipralNatRelay

/**
 * A STUN and TURN server on `host` that tells every socket it appears at
 * `publicHost` on its own port moved by ten thousand: a NAT that moves the
 * port too, so an address naming the socket's own port cannot pass for
 * right. Binding requests get an XOR-MAPPED-ADDRESS (RFC 8489 §14.2); an
 * Allocate without a credential gets the 401 with a REALM and a NONCE, and a
 * signed one is checked against the long-term key -- MD5 of
 * `username:realm:password` (RFC 8489 §9.2.2) -- and answered with a relay on
 * 198.51.100.9, signed the same way. Nothing is answered until [open] is set.
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

/** An IPv4 address of this machine's own that ICE may use: RFC 8445
 * §5.1.1.1 keeps loopback out of the candidates. Nothing leaves the
 * machine: every socket these checks open is this process's own. */
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

/** Every event `client` raises from now on, collected on a thread of its
 * own, for a check that blocks its own thread in `placeCall`. */
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
            SipralClient.open(bindHost = host, stunServer = stun.address).use { client ->
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
                    val media = assertNotNull(mappingFor(false), "the media socket was never mapped")
                    assertEquals(FakeStunServer.mapped(media.local!!), media.mapped)
                    val invite = assertNotNull(read(peer, "INVITE "), "no INVITE reached the far end")
                    val publicMedia = parseHostPort(FakeStunServer.mapped(media.local!!))
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

private fun turnRelayIsAllocatedAndOffered(host: String): String {
    val password = "turn-secret-${System.nanoTime() % 1_000_000}"
    val turn = SipralTurnServer("", "alice-turn", password)
    assertFalse(turn.toString().contains(password), "SipralTurnServer.toString shows the password")
    FakeStunServer(host, credential = "alice-turn" to password).use { stun ->
        DatagramSocket(0, InetAddress.getByName(host)).use { peer ->
            val peerAddress = formatAddress(host, peer.localPort)
            stun.open = true
            SipralClient.open(
                bindHost = host,
                ice = SipralIce.OFFERED,
                stunServer = stun.address,
                turn = SipralTurnServer(stun.address, "alice-turn", password),
            ).use { client ->
                val seen = recordEvents(client, 60_000)
                val account = client.addAccount(aor = "sip:alice@example.invalid", registrarAddress = peerAddress)
                client.placeCall(account, target = "sip:bob@$peerAddress", mediaHost = host).use {
                    val relay = assertNotNull(seen.toList().mapNotNull { relayOf(it) }.firstOrNull(), "no relay event")
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
        SipralClient.open(bindHost = host, ice = SipralIce.REQUIRED, stunServer = stun.address).use { alice ->
            SipralClient.open(bindHost = host, ice = SipralIce.REQUIRED, stunServer = stun.address).use { bob ->
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
 * §2.5): the lite end offers its one host candidate and answers the checks,
 * the full end nominates, both ends report the pair, and audio crosses it
 * both ways.
 */
private suspend fun liteAnsweringAFullAgentCarriesAudio(host: String): String {
    SipralClient.open(bindHost = host, ice = SipralIce.REQUIRED).use { alice ->
        SipralClient.open(bindHost = host, ice = SipralIce.LITE).use { bob ->
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
 * Task 8.5.5, `intern/rapoarte/2026-09-25-nat-layers.json`
 * (`natmobile.review.findings[1]`): `SipralClient.drainFarewells` must send
 * what `stackPollFarewell` hands out to the destination it names -- the
 * TURN server, for the Refresh with a lifetime of zero that gives a relay
 * back (`crates/sipral/src/relay.rs`, "gives it back when the call ends")
 * -- and only fall back to the last address media was heard from when it
 * names none. A call whose peer never carries any ICE still had a relay
 * allocated for it and still gives it back the same way (`relay.rs`: "A
 * call whose peer does no ICE never uses it, and gives it back the same
 * way"), so this needs nothing more than a call that reaches both ends and
 * is then closed -- were the destination ignored in favour of the far
 * end's own address, as it once was, this fake TURN server would never see
 * the Refresh at all.
 */
private suspend fun turnAllocationIsGivenBackWhenTheCallEnds(host: String): String {
    val password = "turn-secret-${System.nanoTime() % 1_000_000}"
    FakeStunServer(host, credential = "alice-turn" to password).use { stun ->
        stun.open = true
        // codecs = "PCMU" keeps the offer short: three ICE candidates
        // (host, server-reflexive, relayed) on top of every codec this
        // build has by default clears RFC 3261 Section 18.1.1's
        // 1300-byte line, and this loopback pair has no stream transport
        // open to fall back to.
        SipralClient.open(
            bindHost = host,
            ice = SipralIce.OFFERED,
            codecs = "PCMU",
            stunServer = stun.address,
            turn = SipralTurnServer(stun.address, "alice-turn", password),
        ).use { alice ->
            SipralClient.open(bindHost = host, codecs = "PCMU").use { bob ->
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

                // The session has to actually open -- and the relay
                // actually become the call's -- before there is anything
                // for a farewell to give back; bob carries no ICE at all,
                // so MEDIA_PATH_CHOSEN (an ICE nomination) never fires
                // here the way it does when both ends require it.
                val mediaDeadline = System.currentTimeMillis() + 8_000
                while (aliceCall.media == null && System.currentTimeMillis() < mediaDeadline) delay(20)
                assertNotNull(aliceCall.media, "alice's media never started")

                // SipralClient.close, not SipralCall.close: hanging up and
                // forgetting the call right here would race the poll
                // thread's own drain of the farewell it leaves behind
                // (SipralClient.close's own doc comment). It hangs up,
                // gives the poll thread a round to drain both queues
                // while the call is still tracked, and only then forgets
                // it.
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

/** Everything above, for IdiomaticCheck.kt's main. */
internal suspend fun natChecks(): String {
    val host = hostAddress() ?: error("no interface but loopback: ICE has no host candidate to check with")
    return listOf(
        stunMappingReachesContactAndSdp(host),
        turnRelayIsAllocatedAndOffered(host),
        iceBehindStunCarriesAudio(host),
        liteAnsweringAFullAgentCarriesAudio(host),
        turnAllocationIsGivenBackWhenTheCallEnds(host),
    ).joinToString(", ")
}
