// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The message hook through org.sipral.idiomatic, the counterpart of
// bindings/python/tests/test_message_hook.py: a header added to the INVITE
// reaches a loopback PBX that answers 486, an incoming answer the hook
// drops is never read, and a hook that throws keeps the message. Run by
// IdiomaticCheck.kt's main, under -Xcheck:jni.

package org.sipral.idiomatic

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.util.Collections
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.sipral.SipralEventKind

private fun field(name: String, message: String): String? =
    message.split("\r\n")
        .firstOrNull { it.contains(':') && it.substringBefore(':').trim().equals(name, ignoreCase = true) }
        ?.substringAfter(':')?.trim()

/** A loopback PBX answering every INVITE 486 with an `X-Carrier-Route`
 * header, writing down everything it received. */
private class BusyPbx : AutoCloseable {
    private val udp = DatagramSocket(0, InetAddress.getByName("127.0.0.1")).apply { soTimeout = 50 }
    @Volatile private var stopped = false
    private val heard: MutableList<String> = Collections.synchronizedList(ArrayList())
    val address = "127.0.0.1:${udp.localPort}"
    val received: List<String> get() = synchronized(heard) { heard.toList() }
    val invites: List<String> get() = received.filter { it.startsWith("INVITE ") }

    init {
        Thread(::serve, "busy-pbx").apply { isDaemon = true; start() }
    }

    private fun serve() {
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
            heard += message
            if (!message.startsWith("INVITE ")) {
                continue
            }
            val lines = mutableListOf("SIP/2.0 486 Busy Here")
            for (name in listOf("Via", "From", "To", "Call-ID", "CSeq")) {
                var value = field(name, message) ?: ""
                if (name == "To" && !value.contains(";tag=")) {
                    value += ";tag=pbx"
                }
                lines += "$name: $value"
            }
            lines += "X-Carrier-Route: trunk-7"
            val out = (lines.joinToString("\r\n") + "\r\nContent-Length: 0\r\n\r\n").toByteArray(Charsets.UTF_8)
            udp.send(DatagramPacket(out, out.size, packet.socketAddress))
        }
    }

    override fun close() {
        stopped = true
        udp.close()
    }
}

/** [message] with [line] added at the end of its header fields. */
private fun adding(line: String, message: ByteArray): ByteArray {
    val text = String(message, Charsets.UTF_8)
    val end = text.indexOf("\r\n\r\n")
    return (text.substring(0, end) + "\r\n" + line + text.substring(end)).toByteArray(Charsets.UTF_8)
}

/** The status the call ended with, after [place]. */
private suspend fun endedStatus(client: SipralClient, place: () -> Unit): Long =
    withTimeout(8_000) {
        coroutineScope {
            val ended = async(start = CoroutineStart.UNDISPATCHED) {
                client.events.first { it.kind == SipralEventKind.CALL_ENDED.value.toLong() }
            }
            place()
            ended.await().payload.call.statusCode
        }
    }

private fun place(client: SipralClient, pbx: BusyPbx) {
    val account = client.addAccount(aor = "sip:alice@example.com", registrarAddress = pbx.address)
    client.placeCall(account, "sip:bob@example.com")
}

private suspend fun aHeaderAddedToTheInviteReachesThePbx(): String {
    BusyPbx().use { pbx ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
            val seen = CopyOnWriteArrayList<Triple<Boolean, String, String>>()
            client.setMessageHook { outgoing, message, remote ->
                seen += Triple(outgoing, String(message, Charsets.UTF_8), remote)
                if (outgoing && String(message, Charsets.UTF_8).startsWith("INVITE ")) {
                    SipralHookVerdict.Replace(adding("X-Tenant: blue", message))
                } else {
                    SipralHookVerdict.Keep
                }
            }
            assertEquals(486L, endedStatus(client) { place(client, pbx) })
            assertEquals(1, pbx.invites.size, "${pbx.received}")
            assertEquals("blue", field("X-Tenant", pbx.invites[0]))
            assertTrue(seen.any { !it.first && it.second.contains("X-Carrier-Route: trunk-7") }, "$seen")
            assertTrue(seen.all { it.third == pbx.address }, "$seen")
        }
    }
    return "a header the hook added to the INVITE reached the PBX"
}

private suspend fun anIncomingMessageTheHookDropsIsNotRead(): String {
    BusyPbx().use { pbx ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
            client.setMessageHook { outgoing, _, _ -> if (outgoing) SipralHookVerdict.Keep else SipralHookVerdict.Drop }
            val status = withTimeout(8_000) {
                coroutineScope {
                    val ended = async(start = CoroutineStart.UNDISPATCHED) {
                        client.events.first { it.kind == SipralEventKind.CALL_ENDED.value.toLong() }
                    }
                    place(client, pbx)
                    // every 486 is dropped unread, so the INVITE goes out again
                    repeat(100) {
                        if (pbx.invites.size < 2) delay(20)
                    }
                    assertTrue(pbx.invites.size >= 2, "${pbx.received}")
                    assertFalse(pbx.received.any { it.startsWith("ACK ") }, "a dropped 486 was acknowledged")
                    client.setMessageHook(null)
                    ended.await().payload.call.statusCode
                }
            }
            assertEquals(486L, status)
        }
    }
    return "an answer the hook dropped was not read, and removing the hook let the next one in"
}

private suspend fun aHookThatThrowsKeepsTheMessage(): String {
    BusyPbx().use { pbx ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
            client.setMessageHook { _, _, _ -> throw IllegalStateException("a mistake in the application's hook") }
            assertEquals(486L, endedStatus(client) { place(client, pbx) })
        }
    }
    return "a hook that threw kept the message"
}

internal suspend fun messageHookChecks(): String = listOf(
    aHeaderAddedToTheInviteReachesThePbx(),
    anIncomingMessageTheHookDropsIsNotRead(),
    aHookThatThrowsKeepsTheMessage(),
).joinToString("; ")
