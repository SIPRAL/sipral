// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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

/// <summary>What <see cref="SipralEventKind.SubscriptionChanged"/> and
/// <see cref="SipralEventKind.Notified"/> carry — the fields of
/// <c>sipral_subscription_event_t</c>: which subscription, where it is now
/// and why it ended, the SIP status behind it, whether the NOTIFY's body was
/// a dialog-info document, its lifetime and when the stack refreshes or
/// retries it, and the subscription a fork of it came from.</summary>
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

/// <summary>What <see cref="SipralEventKind.Recovery"/> carries — the fields
/// of <c>sipral_recovery_event_t</c>: how the recovery settled, the rung it
/// reached, why it gave up, and how many registrations it could not
/// prove.</summary>
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
/// <c>sipral_message_event_t</c>: a MESSAGE's handle, body and type, the
/// status its sender was answered with, and a message summary's
/// counts.</summary>
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
/// <see cref="SipralEventKind.LocateFailed"/> carry: the DNS query an
/// account's server is located with, every address it was located at
/// (<c>host:port</c> separated by commas, the one in use first), or why it
/// was not and when it is asked again.</summary>
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
/// take in and no RTCP-XR figure does. <see cref="Feedback"/> is what RTP/AVPF
/// did on the stream, <see langword="null"/> while it does not run it.</summary>
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

/// <summary>What RTCP feedback (RFC 4585) did on one stream: the
/// <c>trr-int</c> both ends agreed (zero for none), the Generic NACKs this
/// end sent and the packets they asked for again, the ones the far end sent
/// and the packets they asked this end for, the early RTCP packets this end
/// sent, its reduced-size ones (RFC 5506), and the feedback it held back
/// because the stream's RTCP bandwidth had none to spare.</summary>
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
/// carries: which subscription, whether a document was merged into its
/// picture (<see cref="SipralConferenceUpdate.Applied"/>) or the focus
/// deleted the conference (<see cref="SipralConferenceUpdate.Ended"/>, after
/// which the subscription is being given up), the version the picture is at
/// and how many users it holds. <see cref="SipralSubscription.Conference"/>
/// reads the picture itself.</summary>
public sealed record SipralConferenceEventInfo(
    ulong Subscription,
    SipralConferenceUpdate Update,
    uint Version,
    uint Users);

/// <summary>What a <see cref="SipralEventKind.LocalConferenceChanged"/>
/// event carries: which <see cref="SipralLocalConference"/>, what changed —
/// a member joined or left and why, who is talking, a recording that stopped
/// by itself — and how it stands now. <see cref="Member"/> and
/// <see cref="Loudest"/> are call handles, or the conference's own handle
/// for this end.</summary>
public sealed record SipralLocalConferenceEventInfo(
    ulong Conference,
    SipralLocalConferenceChange Change,
    SipralDeparture Departure,
    ulong Member,
    uint Members,
    uint Talkers,
    ulong Loudest);

/// <summary>What a <see cref="SipralEventKind.TextReceived"/> event carries:
/// what the far end typed on the call's real-time text stream (RFC 4103), in
/// order — an erasure of its last character as BACKSPACE (U+0008), a new line
/// as LINE SEPARATOR (U+2028), a REPLACEMENT CHARACTER (U+FFFD) where a block
/// of text was lost for good — and how many blocks were lost so.</summary>
public sealed record SipralTextEventInfo(string Text, uint Missing);

/// <summary>What a <see cref="SipralEventKind.PresenceChanged"/> event
/// carries. For <see cref="SipralPresenceKind.Watched"/>: the
/// <see cref="Subscription"/> that was told, and what the PIDF document said —
/// open or closed, the first RPID activity, the presentity and the first
/// note. For <see cref="SipralPresenceKind.Publication"/>, about the event's
/// <see cref="SipralEventArgs.Account"/>: what became of its published
/// presence, why it failed, the SIP status the compositor answered with, the
/// lifetime granted and when the stack refreshes it.</summary>
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
/// challenge an account's password was not given to, why, where the
/// challenged request went (<c>host:port</c>), and every realm it was
/// challenged for.</summary>
public sealed record SipralChallengeEventInfo(
    SipralChallengeRefusal Refusal,
    string? Server,
    IReadOnlyList<string> Realms);

/// <summary>What <see cref="SipralEventKind.TokenRequired"/> carries: an
/// account's server asking for an OAuth 2.0 access token (RFC 8898). Check
/// <c>AuthzServer</c> against the authorization servers the application
/// trusts before going near it, fetch a token for <c>Scope</c>, and hand it
/// to <see cref="Account.SetAccessToken"/>. <c>Error</c> is
/// <see cref="SipralTokenError.InvalidToken"/> for a token expired or
/// revoked; <c>Proxy</c> is whether a proxy asked (407); <c>Server</c> is
/// where the challenged request went (<c>host:port</c>).</summary>
/// <summary>What <see cref="SipralEventKind.NetworkTest"/> carries: every
/// part of one test <see cref="SipralStack.NetworkTest"/> started, and the
/// verdict, the worst of the parts tested. <c>RoundTripMs</c> is
/// <see langword="null"/> when RTCP brought none back; <c>Local</c> is the
/// socket the STUN answer was about and <c>Mapped</c> where the server saw
/// it.</summary>
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

public sealed record SipralTokenEventInfo(
    SipralTokenError Error,
    string? ErrorCode,
    bool Proxy,
    string? Server,
    string Realm,
    string? Scope,
    string? AuthzServer);
