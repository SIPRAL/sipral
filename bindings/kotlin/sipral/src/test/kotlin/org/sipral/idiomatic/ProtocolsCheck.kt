// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Real-time text, RTCP feedback, linear audio and a conference's focus
// between two clients on 127.0.0.1; a conference's picture and presence
// against a notifier and a compositor played on a socket of this check's
// own; and a call recorded to a recording server played on a TCP port. Run
// by IdiomaticCheck.kt's main under -Xcheck:jni.

package org.sipral.idiomatic

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.runningFold
import kotlinx.coroutines.withTimeout
import org.sipral.SipralActivity
import org.sipral.SipralBasic
import org.sipral.SipralCodec
import org.sipral.SipralConferenceUpdate
import org.sipral.SipralEndpointStatus
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralPresenceKind
import org.sipral.SipralPublicationState
import org.sipral.SipralSrtp
import org.sipral.SipralStatus
import org.sipral.SipralSubscriptionState

/** Two clients, a call from the first placed by [place] and answered by the
 * second with [answer], and [body] run over it; everything closed after. */
private suspend fun <T> betweenTwo(
    place: (SipralClient, SipralAccount) -> SipralCall = { client, account ->
        client.placeCall(account, target = "sip:bob@example.invalid")
    },
    answer: (SipralClient, SipralEvent) -> SipralCall = { client, event -> client.answerCall(event) },
    body: suspend (SipralCall, SipralCall) -> T,
): T {
    val clientA = SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", codecs = "PCMU")
    val clientB = SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", codecs = "PCMU")
    try {
        val accountA = clientA.addAccount(aor = "sip:alice@example.invalid", registrarAddress = clientB.bindAddress)
        clientB.addAccount(aor = "sip:bob@example.invalid", registrarAddress = clientA.bindAddress)
        val (callA, incoming) = clientB.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
            place(clientA, accountA)
        }
        val callB = answer(clientB, incoming)
        withTimeout(15_000) {
            while (callA.media == null || callB.media == null) {
                delay(20)
            }
        }
        try {
            return body(callA, callB)
        } finally {
            callA.close()
            callB.close()
        }
    } finally {
        clientA.close()
        clientB.close()
    }
}

/** Everything [call]'s far end types, run together, until it reads [wanted]. */
private suspend fun typedUntil(call: SipralCall, wanted: String, start: () -> Unit): String = coroutineScope {
    val read = async(start = CoroutineStart.UNDISPATCHED) {
        call.text.runningFold("") { seen, typed -> seen + typed.text.orEmpty() }.first { it == wanted }
    }
    start()
    withTimeout(5_000) { read.await() }
}

private suspend fun realTimeTextIsTypedAndReadBothWays(): String = betweenTwo(
    place = { client, account -> client.placeCall(account, target = "sip:bob@example.invalid", text = true) },
    answer = { client, event -> client.answerCall(event, text = true) },
) { callA, callB ->
    assertNotNull(callA.textAddress)
    val mediaA = assertNotNull(callA.media)
    val mediaB = assertNotNull(callB.media)
    assertTrue(mediaA.hasText)
    assertTrue(mediaB.hasText)
    assertEquals("hello", typedUntil(callB, "hello") { mediaA.sendText("hello") })
    assertEquals("hi", typedUntil(callA, "hi") { mediaB.sendText("hi") })
    "real-time text typed both ways"
}

private suspend fun aFarEndThatTookNoTextLeavesNoneToSend(): String = betweenTwo(
    place = { client, account -> client.placeCall(account, target = "sip:bob@example.invalid", text = true) },
) { callA, _ ->
    val media = assertNotNull(callA.media)
    assertFalse(media.hasText)
    val refused = assertFailsWith<SipralException> { media.sendText("nobody reads this") }
    assertEquals(SipralStatus.NOT_NEGOTIATED, refused.status)
    "text a far end did not take refused NOT_NEGOTIATED"
}

private suspend fun rtcpFeedbackIsAgreedOnlyWhenACallAsks(): String {
    betweenTwo(
        place = { client, account -> client.placeCall(account, target = "sip:bob@example.invalid", feedback = true) },
        answer = { client, event -> client.answerCall(event, feedback = true) },
    ) { callA, callB ->
        val all = SipralRtcpFeedback(feedback = true, genericNack = true, reducedSize = true)
        assertEquals(all, assertNotNull(callA.media).rtcpFeedback())
        assertEquals(all, assertNotNull(callB.media).rtcpFeedback())
        assertEquals(1L, assertNotNull(callA.media).statistics().feedback)
    }
    betweenTwo(
        place = { client, account -> client.placeCall(account, target = "sip:bob@example.invalid", feedback = true) },
    ) { callA, _ ->
        assertEquals(SipralRtcpFeedback(true, false, false), assertNotNull(callA.media).rtcpFeedback())
    }
    betweenTwo { callA, _ ->
        assertEquals(SipralRtcpFeedback(false, false, false), assertNotNull(callA.media).rtcpFeedback())
    }
    return "RTP/AVPF with NACKs and reduced size agreed when asked, and only then"
}

private suspend fun linearAudioIsOfferedWhenACallNamesIt(): String = betweenTwo(
    place = { client, account -> client.placeCall(account, target = "sip:bob@example.invalid", codecs = "L16/16000,PCMU") },
    answer = { client, event -> client.answerCall(event, codecs = "L16/16000,PCMU") },
) { callA, callB ->
    val media = assertNotNull(callA.media)
    assertEquals(SipralCodec.L16_WIDEBAND.value.toLong(), media.info().codec)
    assertEquals(16_000, media.sampleRate)
    assertEquals(SipralCodec.L16_WIDEBAND.value.toLong(), assertNotNull(callB.media).info().codec)
    "L16 at 16 kHz agreed when both ends name it"
}

private suspend fun aFocusSaysSoAndTheCallerNamesItsConference(): String = betweenTwo(
    answer = { client, event -> client.answerCall(event, focus = true) },
) { callA, callB ->
    val uri = assertNotNull(callA.conferenceUri(), "the focus was not heard")
    assertTrue(uri.contains("127.0.0.1"), uri)
    assertNull(callB.conferenceUri(), "Alice never said she is a focus")
    val refused = assertFailsWith<SipralException> { callB.subscribeConference() }
    assertEquals(SipralStatus.NOT_A_FOCUS, refused.status)
    val watched = callA.subscribeConference()
    assertEquals("conference", watched.`package`)
    assertNotEquals(0L, watched.handle)
    "a focus named by its isfocus, and its conference subscribed to"
}

/** A SIP peer played by hand on a UDP socket of this check's own. */
private class FakePeer : AutoCloseable {
    val socket = DatagramSocket(InetSocketAddress(InetAddress.getLoopbackAddress(), 0)).apply { soTimeout = 20 }
    val address: String = "127.0.0.1:${socket.localPort}"

    /** The next request of [method] within five seconds, and where from. */
    suspend fun request(method: String): Pair<String, InetSocketAddress> = withTimeout(5_000) {
        val buffer = ByteArray(65536)
        var found: Pair<String, InetSocketAddress>? = null
        while (found == null) {
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                socket.receive(packet)
            } catch (_: SocketTimeoutException) {
                delay(10)
                continue
            }
            val text = String(packet.data, 0, packet.length, Charsets.UTF_8)
            if (text.startsWith("$method ")) {
                found = text to InetSocketAddress(packet.address, packet.port)
            }
        }
        found
    }

    fun send(text: String, to: InetSocketAddress) {
        val bytes = text.toByteArray(Charsets.UTF_8)
        socket.send(DatagramPacket(bytes, bytes.size, to))
    }

    override fun close() = socket.close()
}

private fun header(name: String, message: String): String? =
    message.substringBefore("\r\n\r\n").split("\r\n")
        .firstOrNull { it.lowercase().startsWith(name.lowercase() + ":") }
        ?.substringAfter(':')?.trim()

/** A response to [request], its dialog fields copied and `To` tagged. */
private fun answerTo(request: String, status: String, more: String = "", type: String? = null, body: String = ""): String {
    val lines = mutableListOf("SIP/2.0 $status")
    for (name in listOf("Via", "From", "To", "Call-ID", "CSeq")) {
        var value = header(name, request) ?: continue
        if (name == "To" && !value.contains(";tag=")) {
            value += ";tag=peer"
        }
        lines += "$name: $value"
    }
    return lines.joinToString("\r\n") + "\r\n" + more + (type?.let { "Content-Type: $it\r\n" } ?: "") +
        "Content-Length: ${body.toByteArray().size}\r\n\r\n" + body
}

/** A NOTIFY in the dialog [subscribe] opened, carrying [body]. */
private fun notifyIn(subscribe: String, to: String, from: String, `package`: String, type: String, body: String): String =
    "NOTIFY sip:alice@$to SIP/2.0\r\n" +
        "Via: SIP/2.0/UDP $from;branch=z9hG4bK-notify-${UUID.randomUUID().toString().take(8)}\r\n" +
        "Max-Forwards: 70\r\n" +
        "From: ${header("To", subscribe)};tag=peer\r\n" +
        "To: ${header("From", subscribe)}\r\n" +
        "Call-ID: ${header("Call-ID", subscribe)}\r\n" +
        "CSeq: 1 NOTIFY\r\n" +
        "Contact: <sip:peer@$from>\r\n" +
        "Event: $`package`\r\n" +
        "Subscription-State: active;expires=3600\r\n" +
        "Content-Type: $type\r\n" +
        "Content-Length: ${body.toByteArray().size}\r\n\r\n" + body

private val ROOM = """
    <?xml version="1.0"?>
    <conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="sip:room@example.invalid" state="full" version="1">
      <conference-description><subject>Weekly</subject><display-text>Team room</display-text></conference-description>
      <conference-state><user-count>3</user-count><active>true</active><locked>false</locked></conference-state>
      <users>
        <user entity="sip:bob@example.invalid" state="full"><display-text>Bob</display-text>
          <endpoint entity="sip:bob@192.0.2.5"><status>connected</status><media id="1"><type>audio</type></media></endpoint>
        </user>
        <user entity="sip:carol@example.invalid" state="full">
          <endpoint entity="sip:carol@192.0.2.6"><status>alerting</status></endpoint>
        </user>
      </users>
    </conference-info>
""".trimIndent()

private val BUDDY = """
    <?xml version="1.0" encoding="UTF-8"?>
    <presence xmlns="urn:ietf:params:xml:ns:pidf" xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model" xmlns:rpid="urn:ietf:params:xml:ns:pidf:rpid" entity="sip:bob@example.invalid">
      <tuple id="t1"><status><basic>open</basic></status><note>Back at four</note></tuple>
      <dm:person id="p1"><rpid:activities><rpid:meeting/></rpid:activities></dm:person>
    </presence>
""".trimIndent()

private suspend fun aConferenceIsReadBackWholeFromItsNotifications(): String = FakePeer().use { notifier ->
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
        val account = client.addAccount(aor = "sip:alice@example.invalid", registrarAddress = notifier.address)
        val watched = account.subscribe("sip:room@example.invalid", "conference")
        val (subscribe, from) = notifier.request("SUBSCRIBE")
        assertEquals("conference", header("Event", subscribe))
        notifier.send(answerTo(subscribe, "200 OK", "Expires: 3600\r\n"), from)
        assertNull(watched.conference(), "no document has arrived yet")
        val (_, changed) = client.events.awaitNext(SipralEventKind.CONFERENCE_CHANGED, timeoutMs = 5_000) {
            notifier.send(
                notifyIn(subscribe, client.bindAddress, notifier.address, "conference", "application/conference-info+xml", ROOM),
                parseHostPort(client.bindAddress),
            )
        }
        val told = assertNotNull(conferenceOf(changed))
        assertEquals(watched.handle, told.subscription)
        assertEquals(SipralConferenceUpdate.APPLIED.value.toLong(), told.update)
        assertEquals(1L, told.version)
        assertEquals(2L, told.users)
        val room = assertNotNull(watched.conference())
        assertEquals("sip:room@example.invalid", room.entity)
        assertEquals("Weekly", room.subject)
        assertEquals("Team room", room.displayText)
        assertEquals(3L, room.userCount)
        assertEquals(true, room.active)
        assertEquals(false, room.locked)
        assertEquals(
            listOf(
                SipralConferenceMember("sip:bob@example.invalid", "Bob", "sip:bob@192.0.2.5", 1, SipralEndpointStatus.CONNECTED, 1),
                SipralConferenceMember("sip:carol@example.invalid", "", "sip:carol@192.0.2.6", 1, SipralEndpointStatus.ALERTING, 0),
            ),
            room.members,
        )
        assertEquals(SipralSubscriptionState.ACTIVE, watched.state)
        "a conference read back whole: ${room.members.size} members, ${room.userCount} counted"
    }
}

private suspend fun presenceIsPublishedAndWhatTheCompositorGrantedIsTold(): String = FakePeer().use { compositor ->
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
        val account = client.addAccount(aor = "sip:alice@example.invalid", registrarAddress = compositor.address)
        assertEquals(SipralStatus.WRONG_STATE, assertFailsWith<SipralException> { account.unpublishPresence() }.status)
        assertEquals(
            SipralStatus.INVALID_ARGUMENT,
            assertFailsWith<SipralException> {
                account.publishPresence(SipralPublishedPresence(SipralBasic.OPEN, SipralActivity.OTHER))
            }.status,
        )
        account.publishPresence(SipralPublishedPresence(SipralBasic.OPEN, SipralActivity.ON_THE_PHONE, "In a call"))
        val (publish, from) = compositor.request("PUBLISH")
        assertEquals("presence", header("Event", publish))
        assertTrue(publish.contains("<basic>open</basic>") && publish.contains("on-the-phone"), publish)
        assertTrue(publish.contains("In a call"), publish)
        val published = PUBLISHED
        val (_, granted) = client.events.awaitNext(
            timeoutMs = 5_000,
            matches = { presenceOf(it)?.publicationState == published },
        ) { compositor.send(answerTo(publish, "200 OK", "SIP-ETag: tag-one\r\nExpires: 1800\r\n"), from) }
        val told = assertNotNull(presenceOf(granted))
        assertEquals(SipralPresenceKind.PUBLICATION.value.toLong(), told.kind)
        assertEquals(1_800_000L, told.expiresMs)
        assertEquals(account.handle, granted.account)

        account.unpublishPresence()
        val (removal, again) = compositor.request("PUBLISH")
        assertEquals("0", header("Expires", removal))
        assertEquals("tag-one", header("SIP-If-Match", removal))
        val removed = SipralPublicationState.REMOVED.value.toLong()
        client.events.awaitNext(timeoutMs = 5_000, matches = { presenceOf(it)?.publicationState == removed }) {
            compositor.send(answerTo(removal, "200 OK", "SIP-ETag: tag-one\r\nExpires: 0\r\n"), again)
        }
        "presence published for ${told.expiresMs / 1000} s and taken away"
    }
}

private val PUBLISHED = SipralPublicationState.PUBLISHED.value.toLong()

private suspend fun aWatchedPresentityIsToldWithItsActivityAndNote(): String = FakePeer().use { notifier ->
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { client ->
        val account = client.addAccount(aor = "sip:alice@example.invalid", registrarAddress = notifier.address)
        val watched = account.watchPresence("sip:bob@example.invalid")
        assertEquals("presence", watched.`package`)
        val (subscribe, from) = notifier.request("SUBSCRIBE")
        assertEquals("application/pidf+xml", header("Accept", subscribe))
        notifier.send(answerTo(subscribe, "200 OK", "Expires: 3600\r\n"), from)
        val (_, found) = client.events.awaitNext(
            timeoutMs = 5_000,
            matches = { presenceOf(it)?.kind == SipralPresenceKind.WATCHED.value.toLong() },
        ) {
            notifier.send(
                notifyIn(subscribe, client.bindAddress, notifier.address, "presence", "application/pidf+xml", BUDDY),
                parseHostPort(client.bindAddress),
            )
        }
        val told = assertNotNull(presenceOf(found))
        assertEquals(watched.handle, told.subscription)
        assertEquals(SipralBasic.OPEN.value.toLong(), told.basic)
        assertEquals(SipralActivity.MEETING.value.toLong(), told.activity)
        assertEquals("sip:bob@example.invalid", told.entity)
        assertEquals("Back at four", told.note)
        watched.end()
        val (unsubscribe, _) = notifier.request("SUBSCRIBE")
        assertEquals("0", header("Expires", unsubscribe))
        "a watched presentity told open, in a meeting, with its note"
    }
}

/**
 * A recording server (SIPREC, RFC 7866) on a TCP port of the loopback: it
 * answers the recording session's INVITE with one receive-only stream per
 * party, on the two ports it is given, and every BYE with 200.
 */
private class FakeRecordingServer(private val streams: Pair<Int, Int>) : AutoCloseable {
    private val listener = ServerSocket(0, 4, InetAddress.getLoopbackAddress())
    val address: String = "127.0.0.1:${listener.localPort}"

    /** Written by the server's thread: read it through `toList()`, which copies it under its lock. */
    val requests: MutableList<String> = java.util.Collections.synchronizedList(mutableListOf())
    private val open: MutableList<Socket> = java.util.Collections.synchronizedList(mutableListOf())

    init {
        Thread({ accept() }, "fake-recorder").apply {
            isDaemon = true
            start()
        }
    }

    private fun accept() {
        while (true) {
            val socket = try {
                listener.accept()
            } catch (_: Exception) {
                return
            }
            open += socket
            Thread({ serve(socket) }, "fake-recorder-connection").apply {
                isDaemon = true
                start()
            }
        }
    }

    private fun serve(socket: Socket) {
        val input = socket.getInputStream()
        val buffer = ByteArray(65536)
        var held = ""
        while (true) {
            val read = try {
                input.read(buffer)
            } catch (_: Exception) {
                return
            }
            if (read < 0) {
                return
            }
            held += String(buffer, 0, read, Charsets.UTF_8)
            while (true) {
                val end = held.indexOf("\r\n\r\n")
                if (end < 0) {
                    break
                }
                val head = held.substring(0, end)
                val length = header("Content-Length", "$head\r\n\r\n")?.toInt() ?: 0
                val body = held.substring(end + 4)
                if (body.toByteArray().size < length) {
                    break
                }
                val message = head + "\r\n\r\n" + body.take(length)
                held = body.drop(length)
                requests += message
                answer(message)?.let { reply ->
                    synchronized(socket) { socket.getOutputStream().write(reply.toByteArray()) }
                }
            }
        }
    }

    private fun answer(message: String): String? = when {
        message.startsWith("INVITE ") -> answerTo(
            message, "200 OK", "Contact: <sip:srs@$address;transport=tcp>\r\n", "application/sdp",
            "v=0\r\no=srs 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
                "m=audio ${streams.first} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=label:1\r\na=recvonly\r\n" +
                "m=audio ${streams.second} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=label:2\r\na=recvonly\r\n",
        )
        message.startsWith("BYE ") -> answerTo(message, "200 OK")
        else -> null
    }

    override fun close() {
        listener.close()
        open.toList().forEach { it.close() }
    }
}

/** How many RTP packets reached [socket] since the last time. */
private fun counted(socket: DatagramSocket): Int {
    var count = 0
    val buffer = ByteArray(2048)
    while (true) {
        val packet = DatagramPacket(buffer, buffer.size)
        try {
            socket.receive(packet)
        } catch (_: Exception) {
            return count
        }
        if (packet.length > 12 && (buffer[0].toInt() and 0xff) shr 6 == 2) {
            count += 1
        }
    }
}

private suspend fun aCallIsRecordedToARecordingServerOverItsOwnConnection(): String {
    val first = DatagramSocket(InetSocketAddress(InetAddress.getLoopbackAddress(), 0)).apply { soTimeout = 1 }
    val second = DatagramSocket(InetSocketAddress(InetAddress.getLoopbackAddress(), 0)).apply { soTimeout = 1 }
    return FakeRecordingServer(first.localPort to second.localPort).use { server ->
        try {
            betweenTwo(
                place = { client, account ->
                    client.placeCall(account, target = "sip:bob@example.invalid").also { placed ->
                        val early = assertFailsWith<SipralException> {
                            placed.recordTo("sip:srs@127.0.0.1", destination = server.address)
                        }
                        assertEquals(SipralStatus.WRONG_STATE, early.status, "no media yet")
                    }
                },
            ) { callA, callB ->
                val (session, confirmed) = callA.client.events.awaitNext(
                    timeoutMs = 5_000,
                    matches = { it.kind == SipralEventKind.CALL_CONFIRMED.value.toLong() && it.call != callA.handle },
                ) { callA.recordTo("sip:srs@127.0.0.1", destination = server.address) }
                assertEquals(session.handle, confirmed.call)
                assertTrue(callA.recordingSession === session)
                val invite = assertNotNull(server.requests.toList().firstOrNull { it.startsWith("INVITE ") })
                assertTrue(invite.startsWith("INVITE sip:srs@127.0.0.1"), invite)
                assertEquals("siprec", header("Require", invite))
                assertTrue(header("Content-Type", invite)?.startsWith("multipart/mixed") == true, invite)
                assertTrue(invite.contains("application/rs-metadata+xml"), invite)
                assertTrue(invite.contains("a=label:1") && invite.contains("a=label:2"), invite)
                assertTrue(invite.contains("m=audio ${session.thisEnd.substringAfterLast(':')} "), invite)
                assertTrue(invite.contains("m=audio ${session.farEnd.substringAfterLast(':')} "), invite)

                val mediaA = assertNotNull(callA.media)
                val mediaB = assertNotNull(callB.media)
                var (thisEnd, farEnd) = 0 to 0
                withTimeout(5_000) {
                    while (thisEnd < 10 || farEnd < 10) {
                        mediaA.sendAudio(ShortArray(mediaA.frameSamples) { 500 })
                        mediaB.sendAudio(ShortArray(mediaB.frameSamples) { 500 })
                        thisEnd += counted(first)
                        farEnd += counted(second)
                        delay(20)
                    }
                }

                callA.client.events.awaitNext(
                    timeoutMs = 5_000,
                    matches = { it.kind == SipralEventKind.CALL_ENDED.value.toLong() && it.call == session.handle },
                ) { session.stop() }
                assertNull(callA.recordingSession)
                withTimeout(5_000) {
                    while (server.requests.toList().none { it.startsWith("BYE ") }) {
                        delay(20)
                    }
                }
                delay(200)
                counted(first)
                delay(300)
                assertEquals(0, counted(first), "copies went on after the recording stopped")
                val again = assertFailsWith<SipralException> { callA.stopRecordingToServer() }
                assertEquals(SipralStatus.WRONG_STATE, again.status)
                "a call recorded to a recording server: $thisEnd and $farEnd copies, hung up on stop"
            }
        } finally {
            first.close()
            second.close()
        }
    }
}

/**
 * The recording session's offer for a call keyed with SDES (RFC 4568),
 * placed from an account that does or does not let its encrypted calls be
 * recorded in the clear; its connection bound under [link] when one is
 * given, as a client that has opened that many connections already binds
 * it.
 */
private suspend fun recordingOfferOfAnEncryptedCall(recordingInClear: Boolean, link: Long? = null): String {
    val first = DatagramSocket(InetSocketAddress(InetAddress.getLoopbackAddress(), 0)).apply { soTimeout = 1 }
    val second = DatagramSocket(InetSocketAddress(InetAddress.getLoopbackAddress(), 0)).apply { soTimeout = 1 }
    try {
        FakeRecordingServer(first.localPort to second.localPort).use { server ->
            SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", codecs = "PCMU").use { alice ->
                SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", codecs = "PCMU").use { bob ->
                    val account = alice.addAccount(
                        aor = "sip:alice@example.invalid",
                        registrarAddress = bob.bindAddress,
                        security = SipralAccountSecurity(srtp = SipralSrtp.REQUIRED, recordingInClear = recordingInClear),
                    )
                    bob.addAccount(
                        aor = "sip:bob@example.invalid",
                        registrarAddress = alice.bindAddress,
                        security = SipralAccountSecurity(srtp = SipralSrtp.REQUIRED),
                    )
                    val (placed, incoming) = bob.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
                        alice.placeCall(account, target = "sip:bob@example.invalid")
                    }
                    placed.use {
                        bob.answerCall(incoming).use { answered ->
                            withTimeout(15_000) {
                                while (placed.media == null || answered.media == null) {
                                    delay(20)
                                }
                            }
                            assertTrue(assertNotNull(placed.media).encryption().single().encrypted, "the call itself is keyed")
                            link?.let { alice.nextLink.set(it) }
                            placed.recordTo("sip:srs@127.0.0.1", destination = server.address)
                            withTimeout(5_000) {
                                while (server.requests.toList().none { it.startsWith("INVITE ") }) {
                                    delay(20)
                                }
                            }
                            return server.requests.toList().first { it.startsWith("INVITE ") }
                        }
                    }
                }
            }
        }
    } finally {
        first.close()
        second.close()
    }
}

private suspend fun anEncryptedCallIsOfferedToItsRecorderAsSrtp(): String {
    val offer = recordingOfferOfAnEncryptedCall(recordingInClear = false)
    assertEquals(2, offer.split("RTP/SAVP").size - 1, offer)
    assertTrue(offer.contains("a=crypto:"), offer)
    return "an encrypted call offered to its recorder as SRTP"
}

private suspend fun anAccountThatAllowsItRecordsAnEncryptedCallInTheClear(): String {
    val offer = recordingOfferOfAnEncryptedCall(recordingInClear = true)
    assertEquals(2, offer.split("RTP/AVP").size - 1, offer)
    assertFalse(offer.contains("RTP/SAVP"), offer)
    assertFalse(offer.contains("a=crypto:"), offer)
    return "an account that allows it records an encrypted call in the clear"
}

/** A client that has made a thousand recordings still reaches the server of
 * the next: its connection's transport id is past where the ids of the
 * connections opened for requests too large for a datagram once began, and
 * what the stack sends on it goes to the recording server all the same. */
private suspend fun aRecordingPastAThousandConnectionsStillReachesItsServer(): String {
    val offer = recordingOfferOfAnEncryptedCall(recordingInClear = false, link = 1_100)
    assertTrue(offer.startsWith("INVITE sip:srs@127.0.0.1"), offer)
    return "a recording bound past a thousand connections reaches its server"
}

suspend fun protocolsChecks(): String = listOf(
    realTimeTextIsTypedAndReadBothWays(),
    aFarEndThatTookNoTextLeavesNoneToSend(),
    rtcpFeedbackIsAgreedOnlyWhenACallAsks(),
    linearAudioIsOfferedWhenACallNamesIt(),
    aFocusSaysSoAndTheCallerNamesItsConference(),
    aConferenceIsReadBackWholeFromItsNotifications(),
    presenceIsPublishedAndWhatTheCompositorGrantedIsTold(),
    aWatchedPresentityIsToldWithItsActivityAndNote(),
    aCallIsRecordedToARecordingServerOverItsOwnConnection(),
    anEncryptedCallIsOfferedToItsRecorderAsSrtp(),
    anAccountThatAllowsItRecordsAnEncryptedCallInTheClear(),
    aRecordingPastAThousandConnectionsStillReachesItsServer(),
).joinToString("; ")
