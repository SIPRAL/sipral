// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The rate a call's frames cross at, chosen by the application through
// org.sipral.idiomatic: both ends at 24 kHz hand out and take 480-sample
// frames whatever the codec, a rate outside the four is refused and changes
// nothing, and 0 is the codec's own again. Two clients on 127.0.0.1, run by
// IdiomaticCheck.kt's main under -Xcheck:jni.

package org.sipral.idiomatic

import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralStatus

internal suspend fun appRateChecks(): String {
    val clientA = SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1")
    val clientB = SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1")
    try {
        val accountA = clientA.addAccount(aor = "sip:alice@example.invalid", registrarAddress = clientB.bindAddress)
        clientB.addAccount(aor = "sip:bob@example.invalid", registrarAddress = clientA.bindAddress)
        val (callA, incoming) = clientB.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 15_000) {
            clientA.placeCall(accountA, target = "sip:bob@example.invalid")
        }
        val callB = clientB.answerCall(incoming)
        try {
            callA.waitConfirmed()
            callB.waitConfirmed()
            withTimeout(15_000) {
                while (callA.media == null || callB.media == null) {
                    delay(20)
                }
            }
            val mediaA = assertNotNull(callA.media)
            val mediaB = assertNotNull(callB.media)
            val codecRate = mediaB.sampleRate
            for (media in listOf(mediaA, mediaB)) {
                media.setAppRate(24_000)
                assertEquals(24_000, media.sampleRate)
                assertEquals(480, media.frameSamples)
                assertEquals(24_000L, media.info().sampleRate)
            }
            val refused = assertFailsWith<SipralException> { mediaB.setAppRate(44_100) }
            assertEquals(SipralStatus.INVALID_ARGUMENT, refused.status)
            assertEquals(480, mediaB.frameSamples)

            mediaA.sendAudio(ShortArray(480 * 5) { 4_096 })
            val heard = withTimeout(15_000) { mediaB.frames.first { it.size == 480 } }
            assertEquals(480, heard.size)

            mediaB.setAppRate(0)
            assertEquals(codecRate, mediaB.sampleRate)
        } finally {
            callA.close()
            callB.close()
        }
    } finally {
        clientA.close()
        clientB.close()
    }
    return "frames cross at the rate the application chose"
}
