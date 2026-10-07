// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// In-band signals and recording through org.sipral.idiomatic: a digit
// written into the audio and detected by a call told to always listen,
// answering-party detection, the recording beep, and the WAV a recording
// writes. Two clients on 127.0.0.1, run by IdiomaticCheck.kt's main under
// -Xcheck:jni.

package org.sipral.idiomatic

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.roundToInt
import kotlin.math.sin
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import org.sipral.SipralAmdVerdict
import org.sipral.SipralDigitSource
import org.sipral.SipralDtmf
import org.sipral.SipralDtmfDetection
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralProgressKind
import org.sipral.SipralRecordingLayout

/** Two clients, a call from the first to the second answered, and [body]
 * run over it; everything closed afterwards. [beforeAnswer] runs on the
 * placed call before the far end has answered. */
private suspend fun <T> overACall(
    beforeAnswer: (SipralCall) -> Unit = {},
    body: suspend (SipralCall, SipralCall) -> T,
): T {
    val clientA = SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", codecs = "PCMU")
    val clientB = SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", codecs = "PCMU")
    try {
        val accountA = clientA.addAccount(aor = "sip:alice@example.invalid", registrarAddress = clientB.bindAddress)
        clientB.addAccount(aor = "sip:bob@example.invalid", registrarAddress = clientA.bindAddress)
        val (callA, incoming) = clientB.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
            clientA.placeCall(accountA, target = "sip:bob@example.invalid").also(beforeAnswer)
        }
        val callB = clientB.answerCall(incoming)
        callA.waitConfirmed()
        callB.waitConfirmed()
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

private suspend fun aDigitWrittenInTheAudioIsHeardThere(): String = overACall { callA, callB ->
    // both ends negotiated named events, so the far end listens in the audio
    // only because told to, and the key is there only because written there
    callB.setDtmfDetection(SipralDtmfDetection.ALWAYS)
    delay(200)
    val (_, heard) = callB.events.awaitNext(SipralEventKind.IN_BAND_DIGIT, timeoutMs = 10_000) {
        callA.sendDtmf("7", via = SipralDtmf.IN_BAND.value.toLong())
    }
    assertEquals('7', digitOf(heard))
    assertEquals(SipralDigitSource.IN_BAND.value.toLong(), heard.payload.media.source)
    assertTrue(abs(heard.payload.media.heldMs - 100) < 25, "held ${heard.payload.media.heldMs} ms")
    "a digit written in the audio heard there as ${digitOf(heard)}"
}

private suspend fun aStereoRecordingKeepsThisEndOnTheLeft(): String = overACall { callA, _ ->
    val media = assertNotNull(callA.media)
    val file = File.createTempFile("sipral-inband-", ".wav")
    try {
        media.record(file.path, layout = SipralRecordingLayout.STEREO, sampleRate = 16_000)
        repeat(25) { media.sendAudio(ShortArray(media.frameSamples) { 3_000 }) }
        delay(800)
        val (running, taken) = media.recording
        assertTrue(running)
        assertTrue(taken > 0)
        media.stopRecording()
        assertFalse(media.recording.first)
        val wav = ByteBuffer.wrap(file.readBytes()).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(2, wav.getShort(58).toInt())
        assertEquals(16_000, wav.getInt(60))
        assertEquals(wav.capacity() - 80, wav.getInt(76))
        val left = (0 until (wav.capacity() - 80) / 4).map { wav.getShort(80 + it * 4).toInt() }
        assertTrue(left.any { abs(it - 3_000) < 100 }, "this end is not on the left")
        "a stereo WAV at 16 kHz with this end on the left"
    } finally {
        file.delete()
    }
}

private suspend fun aGreetingThatRunsOnIsAMachine(): String = overACall(
    // a short greeting limit, so the decision comes in a second
    beforeAnswer = { it.detectProgress(SipralProgressOptions(maxGreetingMs = 600, beep = false)) },
) { callA, callB ->
    val mediaB = assertNotNull(callB.media)
    val rate = mediaB.info().sampleRate.toInt()
    val greeting = ShortArray(rate * 2) { n ->
        val voiced = (n / (rate / 5)) % 2 == 0
        val t = n.toDouble() / rate
        if (voiced) {
            (6_000 * sin(2 * PI * 180 * t) * (1 + 0.5 * sin(2 * PI * 700 * t))).roundToInt().toShort()
        } else {
            0
        }
    }
    val (_, heard) = callA.events.awaitNext(SipralEventKind.PROGRESS_DETECTED, timeoutMs = 15_000) {
        mediaB.sendAudio(greeting)
    }
    val progress = assertNotNull(progressOf(heard))
    assertEquals(SipralProgressKind.ANSWERED_BY.value.toLong(), progress.what)
    assertEquals(SipralAmdVerdict.MACHINE.value.toLong(), progress.verdict)
    assertTrue(progress.atMs > 0)
    "a greeting that ran on reported as a machine after ${progress.atMs} ms"
}

private suspend fun theConsentToneReachesTheFarEnd(): String = overACall { callA, callB ->
    callA.setConsentTone(intervalMs = 1_000)
    val file = File.createTempFile("sipral-consent-", ".wav")
    try {
        assertNotNull(callA.media).record(file.path)
        val loud = withTimeout(3_000) {
            assertNotNull(callB.media).frames.first { frame -> frame.maxOf { abs(it.toInt()) } > 1_000 }
        }
        assertTrue(loud.isNotEmpty())
        assertNotNull(callA.media).stopRecording()
        callA.clearConsentTone()
        assertFailsWith<SipralException> { callA.setConsentTone(frequencyHz = 5_000) }
        "the consent beep heard at the far end while recording"
    } finally {
        file.delete()
    }
}

suspend fun inBandChecks(): String = listOf(
    aDigitWrittenInTheAudioIsHeardThere(),
    aStereoRecordingKeepsThisEndOnTheLeft(),
    aGreetingThatRunsOnIsAMachine(),
    theConsentToneReachesTheFarEnd(),
).joinToString("; ")
