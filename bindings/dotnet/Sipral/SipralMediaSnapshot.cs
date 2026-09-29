// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

namespace Sipral;

/// <summary>A copy of <c>sipral_media_info_t</c>. <see cref="HasText"/> says
/// the call agreed a real-time text stream (RFC 4103); <see cref="Feedback"/>
/// that its audio runs RTP/AVPF (RFC 4585), <see cref="GenericNack"/> that
/// both ends agreed Generic NACKs and <see cref="ReducedSize"/> reduced-size
/// RTCP (RFC 5506).</summary>
public sealed record SipralMediaSnapshot(
    SipralCodec Codec,
    uint PayloadType,
    uint ClockRate,
    uint SampleRate,
    uint FrameMs,
    int FrameSamples,
    SipralDirection Direction,
    bool Sending,
    bool Receiving,
    bool HasDtmf,
    uint DtmfPayloadType,
    SipralRtcp Rtcp,
    bool Secured,
    bool Recording,
    ulong RecordedMs,
    bool Stalled,
    bool HasText = false,
    bool Feedback = false,
    bool GenericNack = false,
    bool ReducedSize = false);
