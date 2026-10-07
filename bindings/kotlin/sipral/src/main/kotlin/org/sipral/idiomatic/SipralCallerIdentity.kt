// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

package org.sipral.idiomatic

import org.sipral.Sipral
import org.sipral.SipralAnswerMode
import org.sipral.SipralCallEvent
import org.sipral.SipralEvent
import org.sipral.SipralEventKind
import org.sipral.SipralException
import org.sipral.SipralIdentityText
import org.sipral.SipralNative
import org.sipral.SipralRingSource
import org.sipral.SipralSessionTimer
import org.sipral.SipralSrtpSuite
import org.sipral.SipralStatus
import org.sipral.SipralVerstat
import org.sipral.SipralAttestation
import org.sipral.SipralVerificationFailure
import org.sipral.SipralVerificationOutcome

/**
 * The `Privacy` values of RFC 3323 §4.2: what a caller asked to withhold,
 * and what an account asks for on its calls ([SipralClient.addAccount]).
 * [ID] is "withhold my number".
 */
enum class SipralPrivacy(val bit: Long) {
    /** Obscure the fields that could identify the caller. */
    HEADER(Sipral.PRIVACY_HEADER),

    /** Hide the session description from the far end. */
    SESSION(Sipral.PRIVACY_SESSION),

    /** User-level privacy. */
    USER(Sipral.PRIVACY_USER),

    /** Keep the asserted identity inside the trust domain (RFC 3325 §9.3). */
    ID(Sipral.PRIVACY_ID),

    /** Fail the call rather than go without the privacy asked for. */
    CRITICAL(Sipral.PRIVACY_CRITICAL),

    /** No privacy, stated. Read only: an account asks for none with an
     * empty set. */
    NONE(Sipral.PRIVACY_NONE),
    ;

    companion object {
        fun of(bits: Long): Set<SipralPrivacy> = entries.filter { bits and it.bit != 0L }.toSet()

        internal fun bits(of: Set<SipralPrivacy>): Long = of.fold(0L) { bits, one -> bits or one.bit }
    }
}

/** How an account's calls ask for a session timer (RFC 4028). */
sealed class SipralSessionTimerChoice {
    /** The stack's default: thirty minutes. */
    data object Default : SipralSessionTimerChoice()

    /** Ask for none; a far end that insists on one is still honoured. */
    data object Off : SipralSessionTimerChoice()

    /** Ask for this interval, at least 90 seconds (RFC 4028 §5). */
    data class Interval(val seconds: Long) : SipralSessionTimerChoice()

    internal val raw: Pair<Long, Long>
        get() = when (this) {
            Default -> SipralSessionTimer.DEFAULT.value.toLong() to 0L
            Off -> SipralSessionTimer.OFF.value.toLong() to 0L
            is Interval -> SipralSessionTimer.INTERVAL.value.toLong() to seconds
        }
}

/**
 * Why this end ends a call, as a `Reason` (RFC 3326) on the BYE or CANCEL
 * [SipralCall.hangup] sends: a SIP status, a Q.850 cause, or both, with
 * text on the first.
 */
data class SipralHangupReason(val sipCause: Int? = null, val q850Cause: Int? = null, val text: String? = null) {
    companion object {
        /** `SIP;cause=200;text="Call completed elsewhere"`: another of the user's
         * phones answered, so this one shows no missed call. */
        val COMPLETED_ELSEWHERE = SipralHangupReason(sipCause = 200, text = "Call completed elsewhere")

        /** `Q.850;cause=16`: a normal end. */
        val NORMAL_CLEARING = SipralHangupReason(q850Cause = 16)

        /** `Q.850;cause=17`: the person is busy. */
        val USER_BUSY = SipralHangupReason(q850Cause = 17)

        /** `Q.850;cause=21`: the person declined. */
        val CALL_REJECTED = SipralHangupReason(q850Cause = 21)
    }
}

/** Why the far end ended a call, as the `Reason` (RFC 3326) on its BYE, its
 * CANCEL or its refusal said. */
data class SipralEndCause(val sip: Int?, val q850: Int?, val text: String?) {
    /** A forking proxy saying another phone answered: not a missed call. */
    val completedElsewhere: Boolean get() = sip == 200
}

/** One party a network asserted (`P-Asserted-Identity`, `Remote-Party-ID`). */
data class SipralParty(val uri: String, val displayName: String?)

/** One `Diversion` value (RFC 5806): who the call was diverted from, and
 * why -- `no-answer`, `user-busy`, `unconditional` and the rest. */
data class SipralDiversion(val uri: String, val displayName: String?, val reason: String?)

/** One `History-Info` entry (RFC 7044): a target the request was sent to,
 * and its `index`. */
data class SipralHistoryEntry(val uri: String, val index: String?)

/** One `Alert-Info` value: the ring asked for, and its `info=` name. */
data class SipralAlertInfo(val uri: String, val name: String?)

/**
 * Who is calling beyond the `From`: the network's assertion (behind the
 * account's trust gate), the caller's privacy request, and diversions.
 * Read with [SipralClient.callerIdentity] from the INCOMING_CALL before
 * answering, or with [SipralCall.identity] later.
 */
data class SipralCallerIdentity(
    /** Whether the INVITE came from a peer the account trusts; when it did
     * not, [asserted], [assertedParties] and [verstat] say nothing (RFC 3325
     * §8). */
    val trusted: Boolean,
    /** Who the network says is calling: the first `P-Asserted-Identity`, else
     * a calling `Remote-Party-ID`. */
    val asserted: SipralParty?,
    val assertedParties: List<SipralParty>,
    val remoteParties: List<SipralParty>,
    /** What the network concluded about the caller's number. */
    val verstat: SipralVerstat,
    /** What the caller's `Privacy` asked for. */
    val privacy: Set<SipralPrivacy>,
    /** Every `Diversion`, most recent first. */
    val diversions: List<SipralDiversion>,
    /** Every `History-Info` entry. */
    val history: List<SipralHistoryEntry>,
    /** This end's STIR/SHAKEN verdict on the call's `Identity` (RFC 8224)
     * when the account verifies: outcome, claimed attestation, and why an
     * invalid one failed. */
    val verification: SipralVerificationOutcome = SipralVerificationOutcome.NONE,
    val attestation: SipralAttestation = SipralAttestation.NONE,
    val verificationFailure: SipralVerificationFailure = SipralVerificationFailure.NONE,
)

/** How a call asked to be answered (RFC 5373) and rung (`Alert-Info`).
 * Whether to auto-answer is the application's policy. */
data class SipralAnswering(
    val mode: SipralAnswerMode,
    /** The caller would rather be refused, with a 403, than answered any
     * other way. */
    val modeRequired: Boolean,
    val privMode: SipralAnswerMode,
    val privModeRequired: Boolean,
    /** After how long to answer without the person, or null when the call
     * did not ask. */
    val answerAfterMs: Long?,
    val ringSource: SipralRingSource,
    val alertInfo: List<SipralAlertInfo>,
)

private fun text(bytes: ByteArray?): String? = bytes?.takeIf { it.isNotEmpty() }?.toString(Charsets.UTF_8)

/** The `Reason` a `SIPRAL_EVENT_KIND_CALL_ENDED` carries, or null for any
 * other kind, or one ended with none. */
fun endCauseOf(event: SipralEvent): SipralEndCause? {
    if (event.kind != SipralEventKind.CALL_ENDED.value.toLong()) {
        return null
    }
    val call = event.payload.call
    val said = text(call.causeText)
    if (call.causeSip == 0L && call.causeQ850 == 0L && said == null) {
        return null
    }
    return SipralEndCause(
        sip = call.causeSip.toInt().takeIf { it != 0 },
        q850 = call.causeQ850.toInt().takeIf { it != 0 },
        text = said,
    )
}

/** The SRTP suite keying a call, from `SIPRAL_EVENT_KIND_MEDIA_SECURED`
 * (RFC 4568 AES-CM, RFC 6188 AES-256, RFC 7714 AES-GCM). Null for any
 * other kind. */
fun srtpSuiteOf(event: SipralEvent): SipralSrtpSuite? =
    if (event.kind == SipralEventKind.MEDIA_SECURED.value.toLong()) {
        SipralSrtpSuite.of(event.payload.media.suite.toInt())
    } else {
        null
    }

internal object IdentityReader {
    /** Every entry's [which] piece, null for one the entry does not have. */
    fun texts(client: SipralClient, call: Long, which: SipralIdentityText): List<String?> {
        val count = retryBusy { Sipral.callIdentityCount(client.handle, call, which.value.toLong()) }
        return (0 until count).map { index ->
            var buffer = ByteArray(256)
            val needed = LongArray(1)
            val read = { into: ByteArray ->
                retryBusy {
                    SipralNative.sipral_call_identity_text(
                        client.handle, call, index, which.value.toLong(), into, needed,
                    ).also(::throwIfPassing)
                }
            }
            var status = read(buffer)
            if (status == SipralStatus.BUFFER_TOO_SMALL.value) {
                buffer = ByteArray(needed[0].toInt())
                status = read(buffer)
            }
            if (status != SipralStatus.OK.value) {
                throw SipralException(SipralStatus.of(status), Sipral.lastErrorMessage())
            }
            val length = (needed[0] - 1).toInt()
            if (length > 0) String(buffer, 0, length, Charsets.UTF_8) else null
        }
    }

    private fun parties(client: SipralClient, call: Long, uris: SipralIdentityText, names: SipralIdentityText) =
        texts(client, call, uris).let { found ->
            val named = texts(client, call, names)
            found.mapIndexedNotNull { index, uri -> uri?.let { SipralParty(it, named.getOrNull(index)) } }
        }

    fun identity(client: SipralClient, call: Long, data: SipralCallEvent?): SipralCallerIdentity {
        val diversionNames = texts(client, call, SipralIdentityText.DIVERSION_DISPLAY)
        val diversionReasons = texts(client, call, SipralIdentityText.DIVERSION_REASON)
        val historyIndexes = texts(client, call, SipralIdentityText.HISTORY_INDEX)
        return SipralCallerIdentity(
            trusted = (data?.identityTrusted ?: 0L) != 0L,
            asserted = text(data?.assertedUri)?.let { SipralParty(it, text(data?.assertedDisplay)) },
            assertedParties = parties(client, call, SipralIdentityText.ASSERTED, SipralIdentityText.ASSERTED_DISPLAY),
            remoteParties = parties(
                client, call, SipralIdentityText.REMOTE_PARTY, SipralIdentityText.REMOTE_PARTY_DISPLAY,
            ),
            verstat = SipralVerstat.of((data?.verstat ?: 0L).toInt()) ?: SipralVerstat.NONE,
            privacy = SipralPrivacy.of(data?.privacy ?: 0L),
            diversions = texts(client, call, SipralIdentityText.DIVERSION).mapIndexedNotNull { index, uri ->
                uri?.let { SipralDiversion(it, diversionNames.getOrNull(index), diversionReasons.getOrNull(index)) }
            },
            history = texts(client, call, SipralIdentityText.HISTORY).mapIndexedNotNull { index, uri ->
                uri?.let { SipralHistoryEntry(it, historyIndexes.getOrNull(index)) }
            },
            verification = SipralVerificationOutcome.of((data?.verification ?: 0L).toInt())
                ?: SipralVerificationOutcome.NONE,
            attestation = SipralAttestation.of((data?.attestation ?: 0L).toInt()) ?: SipralAttestation.NONE,
            verificationFailure = SipralVerificationFailure.of((data?.verificationFailure ?: 0L).toInt())
                ?: SipralVerificationFailure.NONE,
        )
    }

    fun answering(client: SipralClient, call: Long, data: SipralCallEvent?): SipralAnswering {
        val names = texts(client, call, SipralIdentityText.ALERT_NAME)
        return SipralAnswering(
            mode = SipralAnswerMode.of((data?.answerMode ?: 0L).toInt()) ?: SipralAnswerMode.NONE,
            modeRequired = (data?.answerModeRequired ?: 0L) != 0L,
            privMode = SipralAnswerMode.of((data?.privAnswerMode ?: 0L).toInt()) ?: SipralAnswerMode.NONE,
            privModeRequired = (data?.privAnswerModeRequired ?: 0L) != 0L,
            answerAfterMs = data?.takeIf { it.hasAnswerAfter != 0L }?.answerAfterMs,
            ringSource = SipralRingSource.of((data?.ringSource ?: 0L).toInt()) ?: SipralRingSource.UNKNOWN,
            alertInfo = texts(client, call, SipralIdentityText.ALERT_INFO).mapIndexedNotNull { index, uri ->
                uri?.let { SipralAlertInfo(it, names.getOrNull(index)) }
            },
        )
    }
}
