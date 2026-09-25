// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

namespace Sipral;

/// <summary>What every call-shaped event carries — the fields of
/// <c>sipral_call_event_t</c>, copied out while the callback that carried
/// them was still live. Present when <see cref="SipralEvent.Kind"/> is one
/// of the call kinds; <see langword="null"/> otherwise.</summary>
public sealed record SipralCallEventInfo(
    SipralCallState State,
    SipralCallEndReason EndReason,
    uint StatusCode,
    ulong Other,
    bool HeldHere,
    bool HeldThere,
    byte[]? LocalSdp,
    byte[]? RemoteSdp,
    ulong RetryInMs,
    string? FromUri,
    string? FromDisplay,
    string? ToUri,
    string? CallId,
    uint Digit);

/// <summary>What every media-shaped event carries — the fields of
/// <c>sipral_media_event_t</c>. Present when <see cref="SipralEvent.Kind"/>
/// is one of the media kinds; <see langword="null"/> otherwise.</summary>
public sealed record SipralMediaEventInfo(
    SipralCodec Codec,
    SipralDirection Direction,
    ulong SilentForMs,
    ulong RecordedMs,
    SipralMediaFault Fault,
    string? Reason,
    SipralStreamStatistics? Statistics,
    char? Digit,
    uint EventCode,
    ulong HeldMs,
    SipralSrtpSuite Suite,
    SipralDigitSource Source);

/// <summary>What a <see cref="SipralEventKind.RegistrationChanged"/> event
/// carries.</summary>
public sealed record SipralRegistrationEventInfo(
    SipralRegistrationState State,
    SipralRegistrationFailure Failure,
    uint StatusCode,
    ulong ExpiresMs,
    ulong RefreshInMs,
    ulong RetryInMs);

/// <summary>What a transfer-shaped event carries.</summary>
public sealed record SipralTransferEventInfo(
    uint StatusCode,
    bool Attended,
    string? Target);

/// <summary>What <see cref="SipralEventKind.ResolveNeeded"/> carries.</summary>
public sealed record SipralResolveEventInfo(
    ulong Dialog,
    string? Host,
    uint Port,
    SipralTransport Protocol);

/// <summary>What a <see cref="SipralEventKind.NatMapping"/> event carries
/// — the fields of <c>sipral_nat_event_t</c>.</summary>
public sealed record SipralNatEventInfo(
    SipralNatMapping Mapping,
    bool Signalling,
    uint Transport,
    uint Accounts,
    string? Local,
    string? Mapped,
    string? Previous);

/// <summary>What a <see cref="SipralEventKind.NatRelay"/> event carries —
/// the fields of <c>sipral_nat_relay_event_t</c>.</summary>
public sealed record SipralNatRelayEventInfo(
    SipralNatRelay Outcome,
    uint Code,
    string? Local,
    string? Relayed,
    string? Mapped,
    string? Reason);

/// <summary>A snapshot of <c>sipral_stream_stats_t</c>, copied field by
/// field — never the library's own pointer, which is valid only for the
/// callback that carried it.</summary>
public sealed record SipralStreamStatistics(
    SipralCodec Codec,
    ulong? RoundTripUs,
    ulong PacketsSent,
    ulong OctetsSent,
    ulong PacketsReceived,
    ulong PacketsLost,
    ulong PacketsLate,
    ulong PacketsOverflowed,
    ulong PacketsDuplicated,
    ulong PacketsReordered,
    ulong DelayUs,
    ulong TargetDelayUs,
    ulong JitterUs,
    double LossRate,
    double Score,
    bool Suffering,
    ulong SilentForMs);
