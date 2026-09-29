// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

using System.Collections.Generic;

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
/// came from one. <see cref="Verification"/>, <see cref="Attestation"/> and
/// <see cref="VerificationFailure"/> are this end's own STIR/SHAKEN verdict on
/// the call's <c>Identity</c> (RFC 8224), when the account verifies. <see cref="Privacy"/> is the <c>Sipral.Privacy*</c> bits
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
    uint HistoryCount,
    SipralVerificationOutcome Verification = SipralVerificationOutcome.None,
    SipralAttestation Attestation = SipralAttestation.None,
    SipralVerificationFailure VerificationFailure = SipralVerificationFailure.None);

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
    SipralDigitSource Source,
    SipralKeyExchange KeyExchange = SipralKeyExchange.None,
    bool Encrypted = false,
    bool Authenticated = false);

/// <summary>How one stream of a call is protected: a
/// <c>sipral_stream_encryption_t</c> read out
/// (<see cref="CallMedia.Encryption"/>). <see cref="AwaitingKeys"/> is a
/// stream that will be encrypted once its DTLS-SRTP handshake ends.</summary>
public sealed record SipralStreamProtection(
    SipralMediaKind Media,
    bool Encrypted,
    SipralKeyExchange KeyExchange,
    SipralSrtpSuite Suite,
    bool Authenticated,
    bool AwaitingKeys);

/// <summary>What a <see cref="SipralEventKind.CallerVerification"/> event
/// carries — the fields of <c>sipral_verification_event_t</c>. At
/// <see cref="SipralVerificationStage.CertificateWanted"/> the application
/// fetches <see cref="CertificateUrl"/> and hands the chain to
/// <see cref="SipralStack.StirCertificate"/>; at
/// <see cref="SipralVerificationStage.Verified"/> the rest is the verdict,
/// announced just before the call it is about, which
/// <see cref="Refused"/> says a strict account turned away with
/// <see cref="ResponseCode"/>.</summary>
public sealed record SipralVerificationEventInfo(
    SipralVerificationStage Stage,
    SipralVerificationOutcome Outcome,
    SipralVerificationFailure Failure,
    SipralAttestation Attestation,
    SipralVerstat Verstat,
    uint ResponseCode,
    bool Refused,
    string? CertificateUrl,
    string? Orig,
    string? Origid,
    string? Detail);

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

/// <summary>What a <see cref="SipralEventKind.ProgressDetected"/> event
/// carries — the fields of <c>sipral_progress_event_t</c>.
/// <see cref="What"/> says which of the others mean anything: a tone of the
/// network (<see cref="Tone"/>, <see cref="AtMs"/> from the first frame
/// listened to), the special information tone (<see cref="SitHz"/> and
/// <see cref="SitMs"/> measured), who answered (<see cref="Verdict"/>,
/// <see cref="Reason"/>, <see cref="AtMs"/> after answer, and what it was
/// decided from), or the machine's beep (<see cref="FrequencyHz"/>,
/// <see cref="AtMs"/> when it ended after answer, <see cref="LengthMs"/>).
/// </summary>
public sealed record SipralProgressEventInfo(
    SipralProgressKind What,
    SipralProgressTone Tone,
    SipralAmdVerdict Verdict,
    SipralAmdReason Reason,
    ulong AtMs,
    ulong InitialSilenceMs,
    ulong GreetingMs,
    uint Words,
    uint FrequencyHz,
    ulong LengthMs,
    IReadOnlyList<uint> SitHz,
    IReadOnlyList<uint> SitMs);

/// <summary>How <see cref="Call.DetectProgress"/> listens: the network's
/// tones, whether to decide who answered and whether to listen for the
/// machine's beep, and every limit of <c>sipral_progress_config_t</c>, each
/// zero for the library's default.</summary>
public sealed record SipralProgressOptions
{
    /// <summary>Whose tones to listen for.</summary>
    public SipralToneRegion Region { get; init; } = SipralToneRegion.Europe;
    /// <summary>Whether to decide who answered.</summary>
    public bool AnsweringMachine { get; init; } = true;
    /// <summary>Whether to listen for the beep after a verdict of a machine.</summary>
    public bool Beep { get; init; } = true;
    /// <summary>How long after the verdict to listen for the beep.</summary>
    public uint BeepWindowMs { get; init; }
    /// <summary>The longest silence after answer before the verdict is not sure.</summary>
    public uint MaxInitialSilenceMs { get; init; }
    /// <summary>The longest greeting a person gives.</summary>
    public uint MaxGreetingMs { get; init; }
    /// <summary>The silence after a greeting that says a person is waiting.</summary>
    public uint SilenceAfterGreetingMs { get; init; }
    /// <summary>The most words a person's greeting has.</summary>
    public uint MaxWords { get; init; }
    /// <summary>The shortest run of speech that is a word.</summary>
    public uint MinWordMs { get; init; }
    /// <summary>The shortest silence that separates two words.</summary>
    public uint MinWordGapMs { get; init; }
    /// <summary>The longest the decision may take, from answer.</summary>
    public uint MaxDecisionMs { get; init; }
    /// <summary>How far above the noise floor a frame must be to be speech, in dB.</summary>
    public uint MinSpeechAboveFloorDb { get; init; }
    /// <summary>The shortest beep.</summary>
    public uint BeepMinMs { get; init; }
    /// <summary>The longest beep.</summary>
    public uint BeepMaxMs { get; init; }
    /// <summary>Whole cycles of a repeating cadence heard before a tone is reported, one to four.</summary>
    public uint ToneCycles { get; init; }
}

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
