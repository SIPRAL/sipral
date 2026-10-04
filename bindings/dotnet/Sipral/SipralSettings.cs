// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System.Collections.Generic;
using System.Linq;

namespace Sipral;

/// <summary>What a stack runs with, every default filled in
/// (<c>sipral_stack_settings</c>, <see cref="SipralStack.Settings"/>): what a
/// settings screen or a support report shows, rather than what was passed.
/// <see cref="RtpPorts"/> is <see langword="null"/> for no range,
/// <see cref="MediaStallMs"/> and <see cref="RegistrarKeepaliveMs"/> zero
/// with that watchdog or keep-alive off. The last four are ABI 0.35:
/// <see cref="SrtpSuites"/> the suites the stack's calls offer and accept
/// unless their account names its own, in order; whether a pseudonym salt
/// was given (the salt itself is never read back); whether the diagnostic
/// trace is whole now; and whether the platform's echo cancellation is
/// asked for — <see cref="SipralAudioSnapshot.SystemEchoCancellation"/> says
/// what the platform did.</summary>
public sealed record SipralSettings(
    SipralTransport Transport,
    bool Retransmits,
    ulong TimerT1Ms,
    ulong TimerT2Ms,
    ulong TimerT4Ms,
    int CodecCount,
    uint FrameMs,
    bool OfferDtmf,
    bool OfferRtcpMux,
    bool SilenceSuppression,
    ulong MediaStallMs,
    bool G729AnnexB,
    bool Referrals,
    ulong RegistrarKeepaliveMs,
    uint MaxDialogs,
    uint MaxServerTransactions,
    uint DiagnosticDecisions,
    uint DiagnosticRecords,
    (uint Min, uint Max)? RtpPorts,
    uint PathMtu,
    uint DatagramWithoutStreamBytes,
    IReadOnlyList<SipralSrtpSuite> SrtpSuites,
    bool PseudonymSalted,
    bool DiagnosticTrace,
    bool SystemEchoCancellation)
{
    internal static SipralSettings Of(SipralStackSettings raw, uint[] suites)
    {
        static bool On(uint toggle) => toggle == (uint)SipralToggle.On;
        return new SipralSettings(
            (SipralTransport)raw.Transport,
            raw.Retransmits != 0,
            raw.TimerT1Ms,
            raw.TimerT2Ms,
            raw.TimerT4Ms,
            (int)raw.CodecCount,
            raw.FrameMs,
            On(raw.OfferDtmf),
            On(raw.OfferRtcpMux),
            On(raw.SilenceSuppression),
            raw.MediaStallMs,
            On(raw.G729AnnexB),
            On(raw.Referrals),
            raw.RegistrarKeepaliveMs,
            raw.MaxDialogs,
            raw.MaxServerTransactions,
            raw.DiagnosticDecisions,
            raw.DiagnosticRecords,
            raw.RtpPortMin == 0 && raw.RtpPortMax == 0 ? null : (raw.RtpPortMin, raw.RtpPortMax),
            raw.PathMtu,
            raw.DatagramWithoutStreamBytes,
            suites.Select(suite => (SipralSrtpSuite)suite).ToList(),
            On(raw.PseudonymSalted),
            On(raw.DiagnosticTrace),
            On(raw.SystemEchoCancellation));
    }
}
