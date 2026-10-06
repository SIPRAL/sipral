// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// A local conference through this layer -- the Kotlin counterpart of
// bindings/python/tests/test_local_conference.py: made on its own and asked
// about, recorded, refused at a rate it cannot mix, and, with three clients
// on 127.0.0.1, two calls bridged so that what one far end says the other
// hears. Run by IdiomaticCheck.kt's main under -Xcheck:jni.

package org.sipral.idiomatic

import java.io.File
import kotlin.math.abs
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.sipral.SipralAudioDirection
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralLocalConferenceChange
import org.sipral.SipralStatus

private fun square(samples: Int): ShortArray = ShortArray(samples) { n -> if ((n / 8) % 2 == 0) 8000 else -8000 }

// Above this, a frame of square() that came through PCMU whole: it decodes at
// 7900. A frame concealed in place of one that never came fades from the last
// one heard and stays under it, so it is not counted as heard.
private const val WHOLE_FRAME = 7_500

private fun loudness(frame: ShortArray): Int =
    if (frame.isEmpty()) 0 else frame.sumOf { abs(it.toInt()) } / frame.size

private fun open(): SipralClient =
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", codecs = "PCMU")

private suspend fun thisEndIsItsFirstMemberAndIsAnnounced(): String {
    val client = open()
    try {
        val (conference, event) = client.events.awaitNext(SipralEventKind.LOCAL_CONFERENCE_CHANGED, timeoutMs = 10_000) {
            SipralLocalConference(client, maxMembers = 3, sampleRate = 8_000)
        }
        conference.use {
            val info = conference.info()
            assertEquals(listOf(1L, 3L, 1L), listOf(info.members, info.capacity, info.local))
            assertEquals(8_000 to 160, conference.sampleRate to conference.frameSamples)
            var members = conference.memberList()
            assertEquals(conference.handle, members[0].member)
            assertEquals(256L, members[0].gainInput)

            conference.setMuted(null, SipralAudioDirection.INPUT)
            conference.setGain(null, SipralAudioDirection.OUTPUT, 128)
            members = conference.memberList()
            assertTrue(members[0].mutedInput)
            assertEquals(128L, members[0].gainOutput)

            val announced = assertNotNull(localConferenceOf(event))
            assertEquals(conference.handle, announced.conference)
            assertEquals(SipralLocalConferenceChange.JOINED.value.toLong(), announced.change)
            assertEquals(conference.handle, announced.member)
            assertEquals(1L, announced.members)
        }
    } finally {
        client.close()
    }
    return "this end its first member, muted and levelled, and announced"
}

private suspend fun theMixIsRecordedToAFile(): String {
    val client = open()
    val file = File.createTempFile("sipral-conference-", ".wav")
    try {
        SipralLocalConference(client, maxMembers = 2, sampleRate = 16_000).use { conference ->
            conference.record(file.path)
            repeat(10) { conference.sendAudio(square(320)) }
            delay(300)
            assertEquals(1L, conference.info().recording)
            conference.stopRecording()
            val refused = assertFailsWith<SipralException> { conference.stopRecording() }
            assertEquals(SipralStatus.WRONG_STATE, refused.status)
        }
        val written = file.readBytes()
        assertEquals("RIFF", String(written, 0, 4, Charsets.US_ASCII))
        assertTrue(written.size > 44)
        val refused = assertFailsWith<SipralException> { SipralLocalConference(client, sampleRate = 44_100) }
        assertEquals(SipralStatus.CONFERENCE_REFUSED, refused.status)
    } finally {
        file.delete()
        client.close()
    }
    return "the mix recorded to a WAV file, and 44.1 kHz refused"
}

/** Alice calls [far] directly, through an account of her own that names it
 * as the next hop, and it answers. */
private suspend fun call(alice: SipralClient, far: SipralClient, user: String): Pair<SipralCall, SipralCall> {
    val account = alice.addAccount(aor = "sip:alice-to-$user@example.invalid", registrarAddress = far.bindAddress)
    far.addAccount(aor = "sip:$user@example.invalid", registrarAddress = alice.bindAddress)
    val (near, incoming) = far.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
        alice.placeCall(account, target = "sip:$user@${far.bindAddress}")
    }
    val answered = far.answerCall(incoming)
    withTimeout(15_000) {
        while (near.media == null || answered.media == null) {
            delay(20)
        }
    }
    return near to answered
}

private suspend fun whatOneFarEndSaysTheOtherHears(): String {
    val alice = open()
    val bob = open()
    val carol = open()
    try {
        val (toBob, bobCall) = call(alice, bob, "bob")
        val (toCarol, carolCall) = call(alice, carol, "carol")
        try {
            SipralLocalConference(alice, maxMembers = 2, local = false).use { conference ->
                conference.add(toBob)
                conference.add(toCarol)
                val refused = assertFailsWith<SipralException> { conference.add(toBob) }
                assertEquals(SipralStatus.CONFERENCE_REFUSED, refused.status)
                assertEquals(2L, conference.info().members)

                val bobMedia = assertNotNull(bobCall.media)
                repeat(100) { bobMedia.sendAudio(square(bobMedia.frameSamples)) }
                val carolFrames = assertNotNull(carolCall.media).frames
                val heard = withTimeout(10_000) { carolFrames.first { loudness(it) > 2_000 } }
                assertTrue(loudness(heard) > 2_000, "Carol never heard Bob")
                // and in full, ninety-five of Bob's hundred frames at least:
                // a call whose own thread still carried frames beside the
                // conference would have every other frame taken from under
                // it, and a frame clock slower than the conference's
                // overflows the buffers and drops them. Counted whenever they
                // arrive rather than as an unbroken run: on a machine with
                // more work than cores, the threads of all three clients are
                // held up together for a hundred milliseconds and more,
                // Carol's buffer runs dry, and the frames play late but all
                // play.
                var whole = if (loudness(heard) > WHOLE_FRAME) 1 else 0
                withTimeoutOrNull(10_000) {
                    carolFrames.first { frame ->
                        if (loudness(frame) > WHOLE_FRAME) whole++
                        whole >= 95
                    }
                }
                assertTrue(whole >= 95, "Carol heard $whole of Bob's 100 frames")

                conference.remove(toCarol)
                assertEquals(1L, conference.info().members)
            }
        } finally {
            listOf(toBob, toCarol, bobCall, carolCall).forEach { it.close() }
        }
    } finally {
        alice.close()
        bob.close()
        carol.close()
    }
    return "two calls bridged, what one far end says the other hears"
}

suspend fun localConferenceChecks(): String = listOf(
    thisEndIsItsFirstMemberAndIsAnnounced(),
    theMixIsRecordedToAFile(),
    whatOneFarEndSaysTheOtherHears(),
).joinToString("; ")
