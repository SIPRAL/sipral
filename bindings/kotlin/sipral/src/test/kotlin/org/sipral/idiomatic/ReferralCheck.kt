// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// A REFER outside any dialog through org.sipral.idiomatic -- the Kotlin
// counterpart of bindings/python/tests/test_referral.py. The referrer is a
// plain DatagramSocket writing RFC 3515 §4.1's own REFER by hand: a
// switchboard asking Bob's line to ring Carol, a second client that answers.
// Refused 403 by a client that was not told to take referrals; with it
// told, the application asked, a 202, NOTIFYs carrying message/sipfrag, and
// the call placed. Run by IdiomaticCheck.kt's main, under -Xcheck:jni.

package org.sipral.idiomatic

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import kotlinx.coroutines.delay
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.sipral.SipralEventKind

private fun refer(stack: String, referrer: String, target: String): ByteArray = (
    "REFER sip:bob@$stack SIP/2.0\r\n" +
        "Via: SIP/2.0/UDP $referrer;branch=z9hG4bK-click-to-dial\r\n" +
        "Max-Forwards: 70\r\n" +
        "From: <sip:switchboard@sipral.invalid>;tag=switchboard\r\n" +
        "To: <sip:bob@sipral.invalid>\r\n" +
        "Call-ID: click-to-dial@sipral.invalid\r\n" +
        "CSeq: 1 REFER\r\n" +
        "Contact: <sip:switchboard@$referrer>\r\n" +
        "Refer-To: <$target>\r\n" +
        "Referred-By: <sip:switchboard@sipral.invalid>\r\n" +
        "Content-Length: 0\r\n\r\n"
    ).toByteArray(Charsets.UTF_8)

private fun header(name: String, message: String): String? = message.split("\r\n")
    .firstOrNull { it.lowercase().startsWith("${name.lowercase()}:") }
    ?.substring(name.length + 1)
    ?.trim()

/** The switchboard's 200 to a NOTIFY the stack sent it. */
private fun okTo(request: String): ByteArray {
    val copied = listOf("Via", "From", "To", "Call-ID", "CSeq").mapNotNull { name ->
        header(name, request)?.let { "$name: $it" }
    }
    return (listOf("SIP/2.0 200 OK") + copied + listOf("Content-Length: 0", "", ""))
        .joinToString("\r\n")
        .toByteArray(Charsets.UTF_8)
}

private fun send(socket: DatagramSocket, bytes: ByteArray, to: String) {
    val address = parseHostPort(to)
    socket.send(DatagramPacket(bytes, bytes.size, address))
}

/** What reaches the referrer, each NOTIFY answered 200, until [done] holds
 * or [withinMs] pass. */
private suspend fun read(socket: DatagramSocket, withinMs: Long, done: (List<String>) -> Boolean): List<String> {
    val seen = ArrayList<String>()
    val buffer = ByteArray(65536)
    socket.soTimeout = 20
    val deadline = System.currentTimeMillis() + withinMs
    while (System.currentTimeMillis() < deadline && !done(seen)) {
        val packet = DatagramPacket(buffer, buffer.size)
        try {
            socket.receive(packet)
        } catch (_: SocketTimeoutException) {
            delay(10)
            continue
        }
        val text = String(packet.data, 0, packet.length, Charsets.UTF_8)
        seen += text
        if (text.startsWith("NOTIFY ")) {
            val ok = okTo(text)
            socket.send(DatagramPacket(ok, ok.size, packet.socketAddress))
        }
    }
    return seen
}

private suspend fun refusedUnlessTaken(): String {
    DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { referrer ->
        val referrerAddress = formatAddress("127.0.0.1", referrer.localPort)
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { bob ->
            bob.addAccount(aor = "sip:bob@sipral.invalid", registrarAddress = referrerAddress)
            send(referrer, refer(bob.bindAddress, referrerAddress, "sip:carol@sipral.invalid"), bob.bindAddress)
            val seen = read(referrer, 5_000) { seen -> seen.any { it.startsWith("SIP/2.0 ") } }
            assertTrue(seen.any { it.startsWith("SIP/2.0 403 ") }, "$seen")
            return "a REFER outside any dialog is refused 403 by a client that did not take them"
        }
    }
}

private suspend fun takenAndReported(): String {
    DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { referrer ->
        val referrerAddress = formatAddress("127.0.0.1", referrer.localPort)
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { carol ->
            SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", referrals = true).use { bob ->
                carol.addAccount(aor = "sip:carol@sipral.invalid", registrarAddress = bob.bindAddress)
                bob.addAccount(aor = "sip:bob@sipral.invalid", registrarAddress = carol.bindAddress)
                val target = "sip:carol@${carol.bindAddress}"
                val (_, asked) = bob.events.awaitNext(SipralEventKind.REFERRAL, timeoutMs = 10_000) {
                    send(referrer, refer(bob.bindAddress, referrerAddress, target), bob.bindAddress)
                }
                val referral = assertNotNull(referralOf(asked))
                assertEquals(0L, referral.statusCode)
                assertEquals(target, referral.target)
                assertEquals("<sip:switchboard@sipral.invalid>", referral.referredBy)
                assertEquals(0L, referral.attended)
                assertNotEquals(0L, asked.account, "the line it arrived for")

                val (placed, incoming) = carol.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 10_000) {
                    bob.acceptReferral(asked)
                }
                placed.use {
                    carol.answerCall(incoming).use {
                        val seen = read(referrer, 8_000) { seen ->
                            seen.any { it.startsWith("NOTIFY ") && it.contains("SIP/2.0 200 OK") }
                        }
                        assertTrue(seen.any { it.startsWith("SIP/2.0 202 ") }, "$seen")
                        val notifies = seen.filter { it.startsWith("NOTIFY ") }
                        assertFalse(notifies.isEmpty(), "$seen")
                        assertTrue(notifies.first().contains("SIP/2.0 100 Trying"))
                        assertTrue(header("Subscription-State", notifies.first())!!.startsWith("active"))
                        assertTrue(notifies.last().contains("SIP/2.0 200 OK"))
                        assertEquals("terminated;reason=noresource", header("Subscription-State", notifies.last()))
                        assertEquals("message/sipfrag;version=2.0", header("Content-Type", notifies.last()))
                        val deadline = System.currentTimeMillis() + 5_000
                        while (placed.media == null && System.currentTimeMillis() < deadline) delay(20)
                        assertNotNull(placed.media, "the placed call never got its audio")
                        return "a referral taken placed its call and reported 100 then 200 to the referrer"
                    }
                }
            }
        }
    }
}

/** Everything above, for IdiomaticCheck.kt's main. */
internal suspend fun referralChecks(): String = listOf(
    refusedUnlessTaken(),
    takenAndReported(),
).joinToString(", ")
