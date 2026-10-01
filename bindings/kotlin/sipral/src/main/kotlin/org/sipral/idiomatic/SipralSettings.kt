// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

package org.sipral.idiomatic

import org.sipral.SipralSrtpSuite
import org.sipral.SipralStackSettings
import org.sipral.SipralToggle
import org.sipral.SipralTransport

/**
 * What a client's stack runs with, every default filled in
 * (`sipral_stack_settings`, [SipralClient.settings]): what a settings screen
 * or a support report shows, rather than what was passed. [rtpPorts] is null
 * for no range, [mediaStallMs] and [registrarKeepaliveMs] zero with that
 * watchdog or keep-alive off. The last four are ABI 0.35: [srtpSuites] the
 * suites the stack's calls offer and accept unless their account names its
 * own, in order; whether a pseudonym salt was given (the salt itself is never
 * read back); whether the diagnostic trace is whole now; and whether the
 * platform's echo cancellation is asked for -- [SipralAudioDevices.info]
 * says what the platform did.
 */
data class SipralSettings(
    val transport: SipralTransport?,
    val retransmits: Boolean,
    val timerT1Ms: Long,
    val timerT2Ms: Long,
    val timerT4Ms: Long,
    val codecCount: Int,
    val frameMs: Long,
    val offerDtmf: Boolean,
    val offerRtcpMux: Boolean,
    val silenceSuppression: Boolean,
    val mediaStallMs: Long,
    val g729AnnexB: Boolean,
    val referrals: Boolean,
    val registrarKeepaliveMs: Long,
    val maxDialogs: Long,
    val maxServerTransactions: Long,
    val diagnosticDecisions: Long,
    val diagnosticRecords: Long,
    val rtpPorts: LongRange?,
    val pathMtu: Long,
    val datagramWithoutStreamBytes: Long,
    val srtpSuites: List<SipralSrtpSuite>,
    val pseudonymSalted: Boolean,
    val diagnosticTrace: Boolean,
    val systemEchoCancellation: Boolean,
) {
    internal companion object {
        fun of(raw: SipralStackSettings, suites: IntArray): SipralSettings {
            fun on(toggle: Long) = toggle == SipralToggle.ON.value.toLong()
            return SipralSettings(
                transport = SipralTransport.entries.firstOrNull { it.value.toLong() == raw.transport },
                retransmits = raw.retransmits != 0L,
                timerT1Ms = raw.timerT1Ms,
                timerT2Ms = raw.timerT2Ms,
                timerT4Ms = raw.timerT4Ms,
                codecCount = raw.codecCount.toInt(),
                frameMs = raw.frameMs,
                offerDtmf = on(raw.offerDtmf),
                offerRtcpMux = on(raw.offerRtcpMux),
                silenceSuppression = on(raw.silenceSuppression),
                mediaStallMs = raw.mediaStallMs,
                g729AnnexB = on(raw.g729AnnexB),
                referrals = on(raw.referrals),
                registrarKeepaliveMs = raw.registrarKeepaliveMs,
                maxDialogs = raw.maxDialogs,
                maxServerTransactions = raw.maxServerTransactions,
                diagnosticDecisions = raw.diagnosticDecisions,
                diagnosticRecords = raw.diagnosticRecords,
                rtpPorts = if (raw.rtpPortMin == 0L && raw.rtpPortMax == 0L) null else raw.rtpPortMin..raw.rtpPortMax,
                pathMtu = raw.pathMtu,
                datagramWithoutStreamBytes = raw.datagramWithoutStreamBytes,
                srtpSuites = suites.toList().mapNotNull { suite -> SipralSrtpSuite.entries.firstOrNull { it.value == suite } },
                pseudonymSalted = on(raw.pseudonymSalted),
                diagnosticTrace = on(raw.diagnosticTrace),
                systemEchoCancellation = on(raw.systemEchoCancellation),
            )
        }
    }
}
