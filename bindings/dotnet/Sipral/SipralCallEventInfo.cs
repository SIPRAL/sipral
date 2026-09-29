// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

namespace Sipral;

/// <summary>What every call-shaped event carries — the fields of
/// <c>sipral_call_event_t</c>, copied out while the callback that carried
/// them was still live. Present when <see cref="SipralEvent.Kind"/> is one
/// of the call kinds; <see langword="null"/> otherwise.
/// <see cref="Identity"/> and <see cref="Answering"/> are what the INVITE
/// of an incoming call said, repeated on every event of it;
/// <see cref="Cause"/> is why the far end ended the call, on
/// <see cref="SipralEventKind.CallEnded"/>.</summary>
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
    uint Digit,
    SipralCallerIdentity Identity,
    SipralAnswering Answering,
    SipralEndCause? Cause);

/// <summary>What an incoming INVITE said about who is calling, beyond its
/// <c>From</c>. <see cref="AssertedUri"/>, <see cref="AssertedDisplay"/> and
/// <see cref="Verstat"/> come only from a peer the account names in its
/// trusted peers (RFC 3325 §8): <see cref="Trusted"/> says whether this call
/// came from one. <see cref="Privacy"/> is the <c>Sipral.Privacy*</c> bits
/// the caller's <c>Privacy</c> asked for. <see cref="DivertedFrom"/> and
/// <see cref="DiversionReason"/> are the top-most <c>Diversion</c> (RFC
/// 5806); the full lists, and every <c>History-Info</c> entry (RFC 7044),
/// are read with <see cref="Call.Identity"/> or
/// <see cref="SipralStack.CallIdentity"/>.</summary>
public sealed record SipralCallerIdentity(
    bool Trusted,
    string? AssertedUri,
    string? AssertedDisplay,
    SipralVerstat Verstat,
    uint Privacy,
    string? DivertedFrom,
    string? DiversionReason,
    uint DiversionCount,
    uint HistoryCount);

/// <summary>How an incoming call asked to be answered (RFC 5373) and rung
/// (<c>Alert-Info</c>, RFC 7462). <see cref="AnswerAfterMs"/> is set when the
/// call asked to be answered without the user; whether to do so is the
/// application's policy, never the stack's (RFC 5373 §4.2).</summary>
public sealed record SipralAnswering(
    SipralAnswerMode AnswerMode,
    bool AnswerModeRequired,
    SipralAnswerMode PrivAnswerMode,
    bool PrivAnswerModeRequired,
    ulong? AnswerAfterMs,
    SipralRingSource RingSource,
    string? AlertInfo);

/// <summary>The <c>Reason</c> (RFC 3326) a call ended with: of the BYE, the
/// CANCEL or the refusal. <see cref="Sip"/> 200 on a CANCEL is a forking
/// proxy saying another phone answered — not a missed call.</summary>
public sealed record SipralEndCause(uint Sip, uint Q850, string? Text);

/// <summary>What <see cref="SipralEventKind.AudioDevicesChanged"/> carries,
/// in device mode: what changed and who changed it. An application notes a
/// <see cref="SipralAudioOrigin.System"/> change — a headset plugged in, the
/// default moved — and never answers an <see cref="SipralAudioOrigin.Engine"/>
/// one by selecting again: that is the engine doing what was asked, or
/// falling back after a loss, and re-applying a choice on it loops.
/// <see cref="Device"/> is an id <see cref="SipralAudioEngine.Devices"/>
/// lists, or <see langword="null"/>.</summary>
public sealed record SipralAudioEventInfo(
    SipralAudioChange Change,
    SipralAudioOrigin Origin,
    SipralAudioRole? Role,
    SipralAudioDirection? Direction,
    uint? Device);

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

/// <summary>What a <see cref="SipralEventKind.Referral"/> event carries
/// — the fields of <c>sipral_referral_event_t</c>: a REFER outside any
/// dialog, with <see cref="StatusCode"/> zero, or the word that one lapsed,
/// with the status the stack answered it with and nothing else.
/// <see cref="ReferredBy"/> is what the sender wrote, never proof of who it
/// is.</summary>
public sealed record SipralReferralEventInfo(
    uint StatusCode,
    bool Attended,
    string? Target,
    string? ReferredBy);

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

/// <summary>One path a call's ICE agent tried — a candidate pair it
/// checked, or a relay it held — and what became of it: a
/// <c>sipral_path_candidate_t</c> with its two addresses read out
/// (<see cref="CallMedia.PathCandidates"/>).</summary>
public sealed record SipralPath(
    SipralPathKind Kind,
    SipralPathOutcome Outcome,
    uint Code,
    SipralCandidateKind LocalKind,
    SipralCandidateKind RemoteKind,
    ulong Priority,
    string Local,
    string Remote);
/// <summary>What a <see cref="SipralEventKind.TurnStream"/> event carries —
/// the fields of <c>sipral_turn_stream_event_t</c>: open a media socket's
/// connection to a TURN server reached over TCP or TLS, or close it, which
/// <see cref="SipralStack"/> does itself.</summary>
public sealed record SipralTurnStreamEventInfo(
    SipralTurnStream State,
    SipralTransport Protocol,
    string? Local,
    string? Server);

/// <summary>What a <see cref="SipralEventKind.StunServer"/> event carries —
/// the fields of <c>sipral_stun_server_event_t</c>: the STUN server in use
/// is <see cref="Server"/> now and was <see cref="Previous"/>, or every
/// server in the list has failed and <see cref="Server"/> was the last
/// one.</summary>
public sealed record SipralStunServerEventInfo(
    SipralStunServerState State,
    string? Server,
    string? Previous);

/// <summary>A snapshot of <c>sipral_stream_stats_t</c>, copied field by
/// field — never the library's own pointer, which is valid only for the
/// callback that carried it. <see cref="FramesUnderrun"/> is
/// <c>frames_underrun</c>: frames the earpiece played as nothing because
/// the jitter buffer had run dry while the far end was still sending, which
/// <see cref="LossRate"/>, <see cref="Score"/> and <see cref="Suffering"/>
/// take in and no RTCP-XR figure does.</summary>
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
    ulong SilentForMs,
    ulong FramesUnderrun);
