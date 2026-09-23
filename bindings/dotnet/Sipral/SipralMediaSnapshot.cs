// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

namespace Sipral;

/// <summary>A copy of <c>sipral_media_info_t</c>.</summary>
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
    bool Stalled);
