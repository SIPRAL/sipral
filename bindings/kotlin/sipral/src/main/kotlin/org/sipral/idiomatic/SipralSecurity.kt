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
 * One account's call security beyond the client's: the `srtp` and `stir_*`
 * members of `sipral_account_config_t`, for [SipralClient.addAccount].
 *
 * [srtp] overrides the client's policy (null keeps it); a call may ask for
 * more, never less. [srtpSuites] are its suites, most preferred first, by
 * RFC 4568 and RFC 7714 names; GCM only if named. [stirVerification] is
 * what it does with incoming `Identity` once [SipralClient.stir] set trust
 * anchors. [stirKey] (P-256: raw 32 bytes, or SEC1/PKCS #8 in DER or PEM)
 * with [stirCertificateUrl] signs every outgoing call (RFC 8224) as
 * [stirOrig] or the AOR's number, claiming [stirAttestation] (null is A)
 * and [stirOrigid] (drawn when null). A PASSporT carries the time, which
 * [SipralClient.stir] supplies: call it first, without anchors on a
 * sign-only client. [recordingInClear] lets encrypted calls be recorded as
 * plain RTP; otherwise copies go as SRTP or not at all (RFC 7866 §12.2).
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

/** How one stream is protected: a `sipral_stream_encryption_t`
 * ([SipralMedia.encryption]). [awaitingKeys] marks a stream encrypted once
 * its DTLS-SRTP handshake ends. */
data class SipralStreamProtection(
    val media: SipralMediaKind,
    val encrypted: Boolean,
    val keyExchange: SipralKeyExchange,
    val suite: SipralSrtpSuite?,
    val authenticated: Boolean,
    val awaitingKeys: Boolean,
)

/**
 * A `SIPRAL_EVENT_KIND_CALLER_VERIFICATION` payload. At
 * [SipralVerificationStage.CERTIFICATE_WANTED] fetch [certificateUrl] and
 * pass the chain to [SipralClient.stirCertificate]; at
 * [SipralVerificationStage.VERIFIED] the rest is the verdict, raised just
 * before its call, with [refused] and [responseCode] when a strict account
 * turned the call away.
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
