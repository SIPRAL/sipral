// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.idiomatic

import org.sipral.SipralAttestation
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralKeyExchange
import org.sipral.SipralMediaKind
import org.sipral.SipralSrtp
import org.sipral.SipralSrtpSuite
import org.sipral.SipralStirVerification
import org.sipral.SipralVerificationFailure
import org.sipral.SipralVerificationOutcome
import org.sipral.SipralVerificationStage
import org.sipral.SipralVerstat

/**
 * What one account holds its calls to, and signs them with, beyond what the
 * client does: the `srtp` and `stir_*` members of `sipral_account_config_t`,
 * given to [SipralClient.addAccount].
 *
 * [srtp] is the account's own SRTP policy over the client's (null keeps the
 * client's); a call it places may ask for more and never less. [srtpSuites]
 * are the suites it runs, most preferred first, by their RFC 4568 and RFC
 * 7714 names; RFC 7714's GCM ones only if named. [stirVerification] is what
 * the account does with the `Identity` of the calls it receives, once
 * [SipralClient.stir] gave the stack trust anchors. [stirKey] (a P-256 key:
 * the bare 32 bytes, or SEC1 or PKCS #8 in DER or PEM) with
 * [stirCertificateUrl] signs every call the account places (RFC 8224), as
 * [stirOrig] or the number in the AOR, claiming [stirAttestation] (null is A)
 * and [stirOrigid] (one drawn for the account when null). A PASSporT carries
 * the time, which [SipralClient.stir] gives the stack: call it first, with
 * no anchors on a client that only signs. [recordingInClear] lets the
 * account's encrypted calls be recorded to a recording server as plain RTP;
 * otherwise their copies go as SRTP or not at all (RFC 7866 §12.2).
 */
class SipralAccountSecurity(
    val srtp: SipralSrtp? = null,
    val srtpSuites: List<String> = emptyList(),
    val stirVerification: SipralStirVerification? = null,
    val stirKey: ByteArray? = null,
    val stirCertificateUrl: String? = null,
    val stirOrig: String? = null,
    val stirOrigid: String? = null,
    val stirAttestation: SipralAttestation? = null,
    val recordingInClear: Boolean = false,
)

/** How one stream of a call is protected: a `sipral_stream_encryption_t`
 * read out ([SipralMedia.encryption]). [awaitingKeys] is a stream that will
 * be encrypted once its DTLS-SRTP handshake ends. */
data class SipralStreamProtection(
    val media: SipralMediaKind,
    val encrypted: Boolean,
    val keyExchange: SipralKeyExchange,
    val suite: SipralSrtpSuite?,
    val authenticated: Boolean,
    val awaitingKeys: Boolean,
)

/**
 * What a `SIPRAL_EVENT_KIND_CALLER_VERIFICATION` carries. At
 * [SipralVerificationStage.CERTIFICATE_WANTED] the application fetches
 * [certificateUrl] and hands the chain to [SipralClient.stirCertificate]; at
 * [SipralVerificationStage.VERIFIED] the rest is the verdict, announced just
 * before the call it is about, which [refused] says a strict account turned
 * away with [responseCode].
 */
data class SipralVerification(
    val stage: SipralVerificationStage,
    val outcome: SipralVerificationOutcome,
    val failure: SipralVerificationFailure,
    val attestation: SipralAttestation,
    val verstat: SipralVerstat,
    val responseCode: Int,
    val refused: Boolean,
    val certificateUrl: String?,
    val orig: String?,
    val origid: String?,
    val detail: String?,
)

/** The verification a `SIPRAL_EVENT_KIND_CALLER_VERIFICATION` carries, or
 * null for any other kind. */
fun verificationOf(event: SipralEvent): SipralVerification? {
    if (event.kind != SipralEventKind.CALLER_VERIFICATION.value.toLong()) {
        return null
    }
    val v = event.payload.verification
    return SipralVerification(
        stage = SipralVerificationStage.of(v.stage.toInt()) ?: SipralVerificationStage.UNKNOWN,
        outcome = SipralVerificationOutcome.of(v.outcome.toInt()) ?: SipralVerificationOutcome.NONE,
        failure = SipralVerificationFailure.of(v.failure.toInt()) ?: SipralVerificationFailure.NONE,
        attestation = SipralAttestation.of(v.attestation.toInt()) ?: SipralAttestation.NONE,
        verstat = SipralVerstat.of(v.verstat.toInt()) ?: SipralVerstat.NONE,
        responseCode = v.responseCode.toInt(),
        refused = v.refused != 0L,
        certificateUrl = v.certificateUrl?.takeIf { it.isNotEmpty() },
        orig = v.orig?.takeIf { it.isNotEmpty() },
        origid = v.origid?.takeIf { it.isNotEmpty() },
        detail = v.detail?.takeIf { it.isNotEmpty() },
    )
}
