// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System.Collections.Generic;
using System.Linq;

namespace Sipral;

/// <summary>A stack's effective settings, defaults filled in
/// (<c>sipral_stack_settings</c>), for a settings screen or support report.
/// <see cref="RtpPorts"/> is <see langword="null"/> for no range; zero
/// <see cref="MediaStallMs"/> or <see cref="RegistrarKeepaliveMs"/> means
/// off. The pseudonym salt itself is never read back.</summary>
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
