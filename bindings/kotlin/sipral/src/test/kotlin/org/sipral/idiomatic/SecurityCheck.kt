// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// STIR/SHAKEN, the SRTP policy per account and the encryption report through
// org.sipral.idiomatic -- the Kotlin counterpart of
// bindings/python/tests/test_security.py. Two clients on loopback with no
// registrar between them, one signing the call it places and the other
// verifying it. The full verification of a valid signature is proved against
// a test certificate authority in the Rust and C ABI tests and in the lab
// (scripts/lab.sh security); what this proves is the plumbing every half of
// it runs through. Run by IdiomaticCheck.kt's main, under -Xcheck:jni.

package org.sipral.idiomatic

import kotlinx.coroutines.delay
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralKeyExchange
import org.sipral.SipralMediaKind
import org.sipral.SipralSrtp
import org.sipral.SipralSrtpSuite
import org.sipral.SipralStatus
import org.sipral.SipralStirVerification
import org.sipral.SipralVerificationFailure
import org.sipral.SipralVerificationOutcome
import org.sipral.SipralVerificationStage

// short, and the clients offer one codec: a signed INVITE is some five
// hundred octets longer than an unsigned one, and past RFC 3261 §18.1.1's
// 1300 it needs a stream transport this check does not open
private const val URL = "https://c.test/p"

// a P-256 private key as the bare scalar: any 32 octets below the group
// order are one, and these are nobody's
private val KEY = ByteArray(32) { 0x2B }

private suspend fun signedAndRefused(): String {
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", codecs = "PCMU").use { caller ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", codecs = "PCMU").use { callee ->
            val signing = SipralAccountSecurity(stirKey = KEY, stirCertificateUrl = URL)
            val early = assertFailsWith<SipralException> {
                caller.addAccount(
                    aor = "sip:+12155551212@a.test", registrarAddress = callee.bindAddress, security = signing,
                )
            }
            assertEquals(SipralStatus.WRONG_STATE, early.status, "an account that signs needs the time first")

            // a client that only signs is given the time, and no anchors
            caller.stir(null)
            callee.stir(null)
            val account = caller.addAccount(
                aor = "sip:+12155551212@a.test", registrarAddress = callee.bindAddress, security = signing,
            )
            callee.addAccount(
                aor = "sip:12125551213@b.test",
                registrarAddress = caller.bindAddress,
                security = SipralAccountSecurity(stirVerification = SipralStirVerification.STRICT),
            )
            val (call, wanted) = callee.events.awaitNext(SipralEventKind.CALLER_VERIFICATION, timeoutMs = 10_000) {
                caller.placeCall(account, "sip:12125551213@${callee.bindAddress}")
            }
            call.use {
                val asked = assertNotNull(verificationOf(wanted))
                assertEquals(SipralVerificationStage.CERTIFICATE_WANTED, asked.stage)
                assertEquals(URL, asked.certificateUrl)

                // a certificate that could not be had: RFC 8224's 436, sent
                val (judged, ended) = coroutineScope {
                    val ending = async(start = CoroutineStart.UNDISPATCHED) {
                        withTimeout(10_000) {
                            caller.events.first { it.kind == SipralEventKind.CALL_ENDED.value.toLong() }
                        }
                    }
                    val (_, verified) = callee.events.awaitNext(SipralEventKind.CALLER_VERIFICATION, timeoutMs = 10_000) {
                        callee.stirCertificate(wanted.call, null)
                    }
                    verified to ending.await()
                }
                val verdict = assertNotNull(verificationOf(judged))
                assertEquals(SipralVerificationStage.VERIFIED, verdict.stage)
                assertEquals(SipralVerificationOutcome.INVALID, verdict.outcome)
                assertEquals(SipralVerificationFailure.CERTIFICATE_UNAVAILABLE, verdict.failure)
                assertEquals(436, verdict.responseCode)
                assertTrue(verdict.refused)
                assertEquals(436L, ended.payload.call.statusCode, "the caller heard the 436")
            }
            return "a signed call asked for its certificate, and a strict account refused it 436"
        }
    }
}

private suspend fun sdesReported(): String {
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { caller ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1").use { callee ->
            val refused = assertFailsWith<SipralException> {
                caller.addAccount(
                    aor = "sip:alice@sipral.invalid",
                    registrarAddress = callee.bindAddress,
                    security = SipralAccountSecurity(srtpSuites = listOf("AES_CM_128_HMAC_SHA1_80", "NOT_A_SUITE")),
                )
            }
            assertEquals(SipralStatus.INVALID_ARGUMENT, refused.status)

            val account = caller.addAccount(
                aor = "sip:alice@sipral.invalid",
                registrarAddress = callee.bindAddress,
                security = SipralAccountSecurity(
                    srtp = SipralSrtp.REQUIRED, srtpSuites = listOf("AES_CM_128_HMAC_SHA1_80"),
                ),
            )
            callee.addAccount(
                aor = "sip:bob@sipral.invalid",
                registrarAddress = caller.bindAddress,
                security = SipralAccountSecurity(srtp = SipralSrtp.REQUIRED),
            )
            val (call, incoming) = callee.events.awaitNext(SipralEventKind.INCOMING_CALL, timeoutMs = 10_000) {
                caller.placeCall(account, "sip:bob@${callee.bindAddress}")
            }
            call.use {
                callee.answerCall(incoming).use {
                    val deadline = System.currentTimeMillis() + 5_000
                    while (call.media == null && System.currentTimeMillis() < deadline) delay(20)
                    val media = assertNotNull(call.media, "the placed call never got its audio")
                    val report = media.encryption()
                    assertEquals(1, report.size)
                    assertEquals(SipralMediaKind.AUDIO, report[0].media)
                    assertEquals(SipralKeyExchange.SDES, report[0].keyExchange)
                    assertTrue(report[0].encrypted)
                    assertEquals(SipralSrtpSuite.AES_CM80, report[0].suite)
                    assertFalse(report[0].authenticated, "SDES authenticates nothing")
                }
            }
            return "an SDES call required by its account reported how it is protected"
        }
    }
}

/** Everything above, for IdiomaticCheck.kt's main. */
internal suspend fun securityChecks(): String = listOf(
    signedAndRefused(),
    sdesReported(),
).joinToString(", ")
