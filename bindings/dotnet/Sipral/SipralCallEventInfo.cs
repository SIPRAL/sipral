// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

using System.Collections.Generic;

namespace Sipral;

/// <summary>The fields of <c>sipral_call_event_t</c>, present on call
/// events. <see cref="Identity"/> and <see cref="Answering"/> repeat what
/// the incoming INVITE said; <see cref="Cause"/> is set on
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

/// <summary>Who is calling, beyond <c>From</c>. The asserted fields and
/// <see cref="Verstat"/> come only from trusted peers (RFC 3325 §8, see
/// <see cref="Trusted"/>). <see cref="Verification"/>,
/// <see cref="Attestation"/> and <see cref="VerificationFailure"/> are this
/// end's STIR/SHAKEN verdict (RFC 8224). <see cref="Privacy"/> is the
/// <c>Sipral.Privacy*</c> bits the caller asked for.
/// <see cref="DivertedFrom"/> and <see cref="DiversionReason"/> are the top
/// <c>Diversion</c> (RFC 5806); full lists, and <c>History-Info</c> (RFC
/// 7044), via <see cref="Call.Identity"/>.</summary>
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

/// <summary>What <see cref="SipralEventKind.AudioDevicesChanged"/> carries.
/// Never answer an <see cref="SipralAudioOrigin.Engine"/> change by
/// selecting again: it is the engine's own doing, and re-applying loops.
/// <see cref="Device"/> is an id from <see cref="SipralAudioEngine.Devices"/>,
/// or <see langword="null"/>.</summary>
public sealed record SipralAudioEventInfo(
    SipralAudioChange Change,
    SipralAudioOrigin Origin,
    SipralAudioRole? Role,
    SipralAudioDirection? Direction,
    uint? Device);

/// <summary>The fields of <c>sipral_media_event_t</c>, present on media
/// events.</summary>
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

/// <summary>How one stream is protected (<see cref="CallMedia.Encryption"/>).
/// <see cref="AwaitingKeys"/>: encrypted once DTLS-SRTP completes.</summary>
public sealed record SipralStreamProtection(
    SipralMediaKind Media,
    bool Encrypted,
    SipralKeyExchange KeyExchange,
    SipralSrtpSuite Suite,
    bool Authenticated,
    bool AwaitingKeys);

/// <summary>What <see cref="SipralEventKind.CallerVerification"/> carries.
/// At <see cref="SipralVerificationStage.CertificateWanted"/>, fetch
/// <see cref="CertificateUrl"/> and pass it to
/// <see cref="SipralStack.StirCertificate"/>. At
/// <see cref="SipralVerificationStage.Verified"/>, the verdict, just before
/// the call; <see cref="Refused"/> when a strict account turned it away with
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

/// <summary>What <see cref="SipralEventKind.Referral"/> carries: a new
/// out-of-dialog REFER (<see cref="StatusCode"/> zero), or a lapsed one with
/// the status it was answered with. <see cref="ReferredBy"/> is what the
/// sender wrote, not proof.</summary>
public sealed record SipralReferralEventInfo(
    uint StatusCode,
    bool Attended,
    string? Target,
    string? ReferredBy);

/// <summary>What <see cref="SipralEventKind.SubscriptionChanged"/> and
/// <see cref="SipralEventKind.Notified"/> carry — the fields of
/// <c>sipral_subscription_event_t</c>.</summary>
public sealed record SipralSubscriptionEventInfo(
    ulong Subscription,
    SipralSubscriptionState State,
    SipralSubscriptionEnd Reason,
    uint StatusCode,
    bool HasDialogInfo,
    ulong ExpiresMs,
    ulong RefreshInMs,
    ulong RetryInMs,
    ulong ForkedFrom);

/// <summary>What <see cref="SipralEventKind.Recovery"/> carries.
/// <see cref="Unverified"/> counts registrations it could not prove.</summary>
public sealed record SipralRecoveryEventInfo(
    SipralRecoveryOutcome State,
    SipralRecoveryRung Rung,
    SipralRecoveryFailure Reason,
    uint Unverified);

/// <summary>What <see cref="SipralEventKind.CallAnnounced"/> and
/// <see cref="SipralEventKind.AnnouncedCallMissing"/> carry — the fields of
/// <c>sipral_announce_event_t</c>.</summary>
public sealed record SipralAnnounceEventInfo(
    ulong Announcement,
    ulong WaitedMs);

/// <summary>What <see cref="SipralEventKind.MessageReceived"/>,
/// <see cref="SipralEventKind.MessageSent"/> and
/// <see cref="SipralEventKind.MessagesWaiting"/> carry — the fields of
/// <c>sipral_message_event_t</c>.</summary>
public sealed record SipralMessageEventInfo(
    ulong Message,
    ulong Subscription,
    uint StatusCode,
    string? ContentType,
    byte[]? Body,
    bool Waiting,
    uint NewMessages,
    uint OldMessages,
    uint UrgentNewMessages,
    uint UrgentOldMessages,
    string? MessageAccount);

/// <summary>What <see cref="SipralEventKind.LookupWanted"/>,
/// <see cref="SipralEventKind.Located"/> and
/// <see cref="SipralEventKind.LocateFailed"/> carry. <see cref="Targets"/>
/// is comma-separated <c>host:port</c>, the one in use first.</summary>
public sealed record SipralLocateEventInfo(
    SipralDnsRecordType Record,
    SipralLocateFailure Failure,
    string? Name,
    string? Targets,
    ulong RetryInMs);

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

/// <summary>One path ICE tried (a checked pair or a held relay) and its
/// outcome (<see cref="CallMedia.PathCandidates"/>).</summary>
public sealed record SipralPath(
    SipralPathKind Kind,
    SipralPathOutcome Outcome,
    uint Code,
    SipralCandidateKind LocalKind,
    SipralCandidateKind RemoteKind,
    ulong Priority,
    string Local,
    string Remote);
/// <summary>What <see cref="SipralEventKind.TurnStream"/> carries: open or
/// close a TURN TCP/TLS connection, which <see cref="SipralStack"/> does
/// itself.</summary>
public sealed record SipralTurnStreamEventInfo(
    SipralTurnStream State,
    SipralTransport Protocol,
    string? Local,
    string? Server);

/// <summary>What <see cref="SipralEventKind.StunServer"/> carries: the
/// server in use moved from <see cref="Previous"/> to <see cref="Server"/>,
/// or all failed and <see cref="Server"/> was the last.</summary>
public sealed record SipralStunServerEventInfo(
    SipralStunServerState State,
    string? Server,
    string? Previous);

/// <summary>What <see cref="SipralEventKind.ProgressDetected"/> carries.
/// <see cref="What"/> says which fields apply: a network tone
/// (<see cref="Tone"/>), a SIT (<see cref="SitHz"/>, <see cref="SitMs"/>),
/// an answering verdict (<see cref="Verdict"/>, <see cref="Reason"/>), or a
/// beep (<see cref="FrequencyHz"/>, <see cref="LengthMs"/>).
/// <see cref="AtMs"/> counts from the first frame for tones, from answer
/// otherwise.
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

/// <summary>Options for <see cref="Call.DetectProgress"/>. Every limit is
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

/// <summary>A copy of <c>sipral_stream_stats_t</c>.
/// <see cref="FramesUnderrun"/> counts frames played as silence because the
/// jitter buffer ran dry while the far end was sending; it feeds
/// <see cref="LossRate"/>, <see cref="Score"/> and <see cref="Suffering"/>,
/// unlike any RTCP-XR figure. <see cref="Feedback"/> is
/// <see langword="null"/> without RTP/AVPF.</summary>
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
    ulong FramesUnderrun,
    SipralFeedbackStatistics? Feedback = null);

/// <summary>RTCP feedback counters for one stream (RFC 4585, RFC 5506).
/// <see cref="FeedbackSuppressed"/> counts feedback held back for lack of
/// RTCP bandwidth.</summary>
public sealed record SipralFeedbackStatistics(
    uint TrrIntervalMs,
    ulong NacksSent,
    ulong PacketsNacked,
    ulong NacksReceived,
    ulong PacketsAskedFor,
    ulong EarlyPackets,
    ulong ReducedSizePackets,
    ulong FeedbackSuppressed);

/// <summary>What a <see cref="SipralEventKind.ConferenceChanged"/> event
/// carries. After <see cref="SipralConferenceUpdate.Ended"/> the
/// subscription is given up. <see cref="SipralSubscription.Conference"/>
/// reads the state.</summary>
public sealed record SipralConferenceEventInfo(
    ulong Subscription,
    SipralConferenceUpdate Update,
    uint Version,
    uint Users);

/// <summary>What a <see cref="SipralEventKind.LocalConferenceChanged"/>
/// event carries. <see cref="Member"/> and <see cref="Loudest"/> are call
/// handles, or the conference's own handle for this end.</summary>
public sealed record SipralLocalConferenceEventInfo(
    ulong Conference,
    SipralLocalConferenceChange Change,
    SipralDeparture Departure,
    ulong Member,
    uint Members,
    uint Talkers,
    ulong Loudest);

/// <summary>Text typed by the far end (RFC 4103): erasure as BACKSPACE
/// (U+0008), new line as U+2028, lost blocks as U+FFFD, counted in
/// <see cref="Missing"/>.</summary>
public sealed record SipralTextEventInfo(string Text, uint Missing);

/// <summary>What a <see cref="SipralEventKind.PresenceChanged"/> event
/// carries. <see cref="SipralPresenceKind.Watched"/>: the PIDF document's
/// basic status, first activity, entity and note.
/// <see cref="SipralPresenceKind.Publication"/>: the state of the account's
/// own published presence.</summary>
public sealed record SipralPresenceEventInfo(
    SipralPresenceKind Kind,
    ulong Subscription,
    SipralBasic Basic,
    SipralActivity Activity,
    string? Entity,
    string? Note,
    SipralPublicationState PublicationState,
    SipralPublishFailure Failure,
    uint StatusCode,
    ulong ExpiresMs,
    ulong RefreshInMs);

/// <summary>What <see cref="SipralEventKind.ChallengeDeclined"/> carries: a
/// challenge the password was withheld from, why, the server
/// (<c>host:port</c>) and its realms.</summary>
public sealed record SipralChallengeEventInfo(
    SipralChallengeRefusal Refusal,
    string? Server,
    IReadOnlyList<string> Realms);

/// <summary>What <see cref="SipralEventKind.NetworkTest"/> carries: each
/// part's result and the verdict, the worst of them. <c>RoundTripMs</c> is
/// <see langword="null"/> without RTCP; <c>Mapped</c> is where STUN saw
/// <c>Local</c>.</summary>
public sealed record SipralNetworkTestEventInfo(
    uint Test,
    SipralNetworkVerdict Verdict,
    SipralNetworkProbe Stun,
    SipralNatKind Nat,
    SipralNetworkProbe Turn,
    SipralServerReach Server,
    uint ServerStatus,
    uint ServerRoundTripMs,
    SipralNetworkProbe Echo,
    SipralNetworkVerdict EchoVerdict,
    float LossPercent,
    float JitterMs,
    uint? RoundTripMs,
    uint RFactor,
    float Mos,
    string? Local,
    string? Mapped);

/// <summary>What <see cref="SipralEventKind.TokenRequired"/> carries: a
/// request for an OAuth 2.0 access token (RFC 8898). Check
/// <c>AuthzServer</c> against the servers the application trusts before
/// contacting it, fetch a token for <c>Scope</c>, and pass it to
/// <see cref="Account.SetAccessToken"/>. <c>Error</c> is
/// <see cref="SipralTokenError.InvalidToken"/> for an expired or revoked
/// token; <c>Proxy</c> means a 407; <c>Server</c> is <c>host:port</c>.</summary>
public sealed record SipralTokenEventInfo(
    SipralTokenError Error,
    string? ErrorCode,
    bool Proxy,
    string? Server,
    string Realm,
    string? Scope,
    string? AuthzServer);
