// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// STIR/SHAKEN, the SRTP policy per account and the encryption report through
// org.sipral.idiomatic -- the Kotlin counterpart of
// bindings/python/tests/test_security.py. Two clients on loopback with no
// registrar between them, one signing the call it places and the other
// verifying it. A valid signature is verified against the chain the C ABI's
// tests keep in bindings/fixtures/stir-provider-709J, whose signing
// certificate names a service provider code and no number; beside that, what
// this proves is the plumbing every half of it runs through. Run by
// IdiomaticCheck.kt's main, under -Xcheck:jni.

package org.sipral.idiomatic

import java.io.File
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

/**
 * One of the credentials `sipral_stir::testing` issues for the service
 * provider code 709J, checked against it by the C ABI's own tests: a root, a
 * chain whose signing certificate names that code and no number, and its key.
 * Found from the directory the JVM runs in, anywhere inside the checkout.
 */
private fun provider(name: String): ByteArray {
    var at: File? = File(System.getProperty("user.dir")).absoluteFile
    while (at != null) {
        val wanted = File(at, "bindings/fixtures/stir-provider-709J/$name")
        if (wanted.isFile) {
            return wanted.readBytes()
        }
        at = at.parentFile
    }
    error("bindings/fixtures/stir-provider-709J/$name is not above ${System.getProperty("user.dir")}")
}

// a moment inside every certificate of the provider chain
private const val WITHIN = 1_790_000_000L

/** The verdict a client reaches on a call signed under the provider chain,
 * taking service provider codes or not. */
private suspend fun providerVerdict(acceptServiceProviderCodes: Boolean): SipralVerification {
    SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", codecs = "PCMU").use { caller ->
        SipralClient.open(audio = SipralAudioMode.Application, bindHost = "127.0.0.1", codecs = "PCMU").use { callee ->
            caller.stir(null, unixSeconds = WITHIN)
            callee.stir(
                provider("anchor.pem"), unixSeconds = WITHIN, acceptServiceProviderCodes = acceptServiceProviderCodes,
            )
            val scalar = String(provider("signing-scalar.hex")).trim().chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val account = caller.addAccount(
                aor = "sip:+12155551212@a.test",
                registrarAddress = callee.bindAddress,
                security = SipralAccountSecurity(stirKey = scalar, stirCertificateUrl = URL),
            )
            callee.addAccount(aor = "sip:12125551213@b.test", registrarAddress = caller.bindAddress)
            val (call, wanted) = callee.events.awaitNext(SipralEventKind.CALLER_VERIFICATION, timeoutMs = 10_000) {
                caller.placeCall(account, "sip:12125551213@${callee.bindAddress}")
            }
            call.use {
                assertEquals(SipralVerificationStage.CERTIFICATE_WANTED, assertNotNull(verificationOf(wanted)).stage)
                val (_, judged) = callee.events.awaitNext(SipralEventKind.CALLER_VERIFICATION, timeoutMs = 10_000) {
                    callee.stirCertificate(wanted.call, provider("chain.pem"))
                }
                val verdict = assertNotNull(verificationOf(judged))
                assertEquals(SipralVerificationStage.VERIFIED, verdict.stage)
                return verdict
            }
        }
    }
}

private suspend fun aCodeCoversNoNumberByDefault(): String {
    val verdict = providerVerdict(acceptServiceProviderCodes = false)
    assertEquals(SipralVerificationOutcome.INVALID, verdict.outcome)
    assertEquals(SipralVerificationFailure.NUMBER_NOT_COVERED, verdict.failure)
    return "a certificate naming only a service provider code covered no number by default"
}

private suspend fun aClientThatAcceptsCodesVerifiesTheCaller(): String {
    assertEquals(SipralVerificationOutcome.VALID, providerVerdict(acceptServiceProviderCodes = true).outcome)
    return "a client that accepts service provider codes verified the caller"
}

/** Everything above, for IdiomaticCheck.kt's main. */
internal suspend fun securityChecks(): String = listOf(
    signedAndRefused(),
    sdesReported(),
    aCodeCoversNoNumberByDefault(),
    aClientThatAcceptsCodesVerifiesTheCaller(),
).joinToString(", ")
