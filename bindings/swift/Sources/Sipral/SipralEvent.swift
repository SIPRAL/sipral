// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import CSipral

/// One event, copied out of `sipral_event_t` while it was still live.
///
/// `sipral_event_t`'s pointers are valid only during the C callback, so
/// everything is copied here, on the poll thread, into a `Sendable` value.
public struct SipralEvent: Sendable {
    /// The raw `sipral_event_kind_t`, kept so a kind newer than this package
    /// can still be reported (`kindName` comes from the library too).
    public let kindRaw: UInt32
    public let kind: SipralEventKind?
    public let kindName: String
    public let stack: SipralHandle
    public let account: SipralHandle
    public let call: SipralHandle
    public let message: [UInt8]?
    public let callData: CallEventData?
    public let mediaData: MediaEventData?
    public let registrationData: RegistrationEventData?
    public let announceData: AnnounceEventData?
    /// `payload.nat`, for `SipralEventKind.natMapping` only.
    public let natData: NatEventData?
    /// `payload.relay`, for `SipralEventKind.natRelay` only.
    public let relayData: RelayEventData?
    /// `payload.referral`, for `SipralEventKind.referral` only.
    public let referralData: ReferralEventData?
    /// `payload.transfer`, for `SipralEventKind.transferRequested`,
    /// `.transferProgress` and `.transferDone` only.
    public internal(set) var transferData: TransferEventData? = nil
    /// `payload.turn_stream`, for `SipralEventKind.turnStream` only.
    public let turnStreamData: TurnStreamEventData?
    /// `payload.audio`, for `SipralEventKind.audioDevicesChanged` only.
    public let audioData: AudioEventData?
    /// `payload.stun_server`, for `SipralEventKind.stunServer` only.
    public let stunServerData: StunServerEventData?
    /// `payload.verification`, for `SipralEventKind.callerVerification` only.
    public let verificationData: VerificationEventData?
    /// `payload.progress`, for `SipralEventKind.progressDetected` only.
    public internal(set) var progressData: ProgressEventData? = nil
    /// `payload.transport_failed`, for `SipralEventKind.transportFailed` only.
    public var transportFailedData: TransportFailedEventData? = nil
    /// `payload.transport_wanted`, for `SipralEventKind.transportWanted`
    /// only.
    public internal(set) var transportWantedData: TransportWantedEventData? = nil
    /// `payload.conference`, for `SipralEventKind.conferenceChanged` only.
    public internal(set) var conferenceData: ConferenceEventData? = nil
    /// `payload.text`, for `SipralEventKind.textReceived` only.
    public internal(set) var textData: TextEventData? = nil
    /// `payload.presence`, for `SipralEventKind.presenceChanged` only.
    public internal(set) var presenceData: PresenceEventData? = nil
    /// `payload.local_conference`, for `SipralEventKind.localConferenceChanged`
    /// only.
    public internal(set) var localConferenceData: LocalConferenceEventData? = nil
    /// `payload.subscription`, for `SipralEventKind.subscriptionChanged` and
    /// `.notified` only.
    public internal(set) var subscriptionData: SubscriptionEventData? = nil
    /// `payload.recovery`, for `SipralEventKind.recovery` only.
    public internal(set) var recoveryData: RecoveryEventData? = nil
    /// `payload.resolve`, for `SipralEventKind.resolveNeeded` only.
    public internal(set) var resolveData: ResolveEventData? = nil
    /// `payload.locate`, for `SipralEventKind.lookupWanted`, `.located` and
    /// `.locateFailed` only.
    public internal(set) var locateData: LocateEventData? = nil
    /// `payload.message`, for `SipralEventKind.messageReceived`,
    /// `.messageSent` and `.messagesWaiting` only.
    public internal(set) var messageData: MessageEventData? = nil
    /// `payload.challenge`, for `SipralEventKind.challengeDeclined` only.
    public internal(set) var challengeData: ChallengeEventData? = nil
    /// `payload.token`, for `SipralEventKind.tokenRequired` only.
    public internal(set) var tokenData: TokenEventData? = nil
    /// `payload.network_test`, for `SipralEventKind.networkTest` only.
    public internal(set) var networkTestData: NetworkTestEventData? = nil
}

/// What `SipralEventKind.networkTest` carries: each part's result and the
/// verdict, the worst of the parts tested.
public struct NetworkTestEventData: Sendable {
    /// The number the test was given.
    public let test: UInt32
    /// Good, acceptable or poor; unknown when nothing was tested.
    public let verdict: SipralNetworkVerdict?
    /// Whether a STUN server answered.
    public let stun: SipralNetworkProbe?
    /// What its answer says about the NAT.
    public let nat: SipralNatKind?
    /// Whether the TURN server allocated a relay.
    public let turn: SipralNetworkProbe?
    /// What the account's server did with the `OPTIONS`.
    public let server: SipralServerReach?
    /// The status it answered with, or zero.
    public let serverStatus: UInt32
    /// From the `OPTIONS` to its answer, in milliseconds.
    public let serverRoundTripMs: UInt32
    /// Whether audio came back on the echo call.
    public let echo: SipralNetworkProbe?
    /// The echo's own verdict.
    public let echoVerdict: SipralNetworkVerdict?
    /// Lost or late, as a percentage.
    public let lossPercent: Float
    /// Interarrival jitter, in milliseconds.
    public let jitterMs: Float
    /// The round trip RTCP measured, when it did.
    public let roundTripMs: UInt32?
    /// G.107's R, for concealed G.711.
    public let rFactor: UInt32
    /// The conversational MOS estimated from it.
    public let mos: Float
    /// The socket the STUN answer was about.
    public let local: String?
    /// Where the STUN server saw it.
    public let mapped: String?
}

/// What `SipralEventKind.tokenRequired` carries: a server asking for an
/// OAuth 2.0 access token (RFC 8898). Check `authzServer` against the
/// servers the application trusts before contacting it, then pass the token
/// to `Account.setAccessToken(_:)`.
public struct TokenEventData: Sendable {
    /// What the server said was wrong; `.invalidToken` for one expired or
    /// revoked.
    public let error: SipralTokenError?
    /// The `error` code as the server wrote it.
    public let errorCode: String?
    /// Whether a proxy asked (407) rather than the registrar (401).
    public let proxy: Bool
    /// Where the challenged request went, `host:port`.
    public let server: String?
    /// The protection domain, empty when the challenge named none.
    public let realm: String
    /// The scope the token has to carry.
    public let scope: String?
    /// The authorization server, an `https` URI.
    public let authzServer: String?
}

/// What `SipralEventKind.challengeDeclined` carries: a challenge the
/// password was withheld from, why, who asked and for which realms.
public struct ChallengeEventData: Sendable {
    public let refusal: SipralChallengeRefusal?
    /// Where the challenged request went, `host:port`.
    public let server: String?
    /// The realms it was challenged for.
    public let realms: [String]
}

/// What `SipralEventKind.subscriptionChanged` and `.notified` carry
/// (`sipral_subscription_event_t`).
public struct SubscriptionEventData: Sendable {
    public let subscription: SipralHandle
    public let state: SipralSubscriptionState?
    public let reason: SipralSubscriptionEnd?
    public let statusCode: UInt32
    public let hasDialogInfo: Bool
    public let expiresMs: UInt64
    public let refreshInMs: UInt64
    public let retryInMs: UInt64
    public let forkedFrom: SipralHandle
}

/// What `SipralEventKind.recovery` carries (`sipral_recovery_event_t`).
public struct RecoveryEventData: Sendable {
    public let state: SipralRecoveryOutcome?
    public let rung: SipralRecoveryRung?
    public let reason: SipralRecoveryFailure?
    public let unverified: UInt32
}

/// What `SipralEventKind.resolveNeeded` carries (`sipral_resolve_event_t`):
/// the dialog whose next hop needs a name resolved, and where.
public struct ResolveEventData: Sendable {
    public let dialog: SipralHandle
    public let host: String?
    public let port: UInt32
    /// A `SipralTransport` raw value.
    public let protocolRaw: UInt32
}

/// What `SipralEventKind.lookupWanted`, `.located` and `.locateFailed` carry
/// (`sipral_locate_event_t`).
public struct LocateEventData: Sendable {
    /// A `SipralDnsRecordType` raw value: what to ask `name` for.
    public let recordRaw: UInt32
    /// A `SipralLocateFailure` raw value.
    public let failureRaw: UInt32
    public let name: String?
    /// `host:port` separated by commas, the one in use first.
    public let targets: String?
    public let retryInMs: UInt64
}

/// What `SipralEventKind.messageReceived`, `.messageSent` and
/// `.messagesWaiting` carry (`sipral_message_event_t`).
public struct MessageEventData: Sendable {
    public let message: SipralHandle
    public let subscription: SipralHandle
    public let statusCode: UInt32
    public let contentType: String?
    public let body: [UInt8]?
    public let waiting: Bool
    public let newMessages: UInt32
    public let oldMessages: UInt32
    public let urgentNewMessages: UInt32
    public let urgentOldMessages: UInt32
    public let messageAccount: String?
}

/// What `SipralEventKind.localConferenceChanged` carries. `member` and
/// `loudest` are call handles, or the conference's own handle for this end.
public struct LocalConferenceEventData: Sendable, Equatable {
    public let conference: SipralHandle
    public let change: SipralLocalConferenceChange?
    public let departure: SipralDeparture?
    public let member: SipralHandle
    public let members: UInt32
    public let talkers: UInt32
    public let loudest: SipralHandle
}

/// What `SipralEventKind.callerVerification` carries. At
/// `.certificateWanted`, fetch `certificateUrl` and pass the chain to
/// `SipralStack.stirCertificate(call:chain:)`. At `.verified` it is the
/// verdict, raised just before the call; `refused` means a strict account
/// turned the call away with `responseCode`.
public struct VerificationEventData: Sendable {
    public let stage: SipralVerificationStage?
    public let outcome: SipralVerificationOutcome?
    public let failure: SipralVerificationFailure?
    public let attestation: SipralAttestation?
    public let verstat: SipralVerstat?
    public let responseCode: UInt32
    public let refused: Bool
    public let certificateUrl: String?
    public let orig: String?
    public let origid: String?
    public let detail: String?
}

/// What progress detection heard (`sipral_progress_event_t`); `what` says
/// which members are meaningful.
public struct ProgressEventData: Sendable {
    public let what: SipralProgressKind?
    public let tone: SipralProgressTone?
    public let verdict: SipralAmdVerdict?
    public let reason: SipralAmdReason?
    /// A tone's first burst from the first frame listened to; the decision
    /// after answer; the beep's end after answer.
    public let atMs: UInt64
    public let initialSilenceMs: UInt64
    public let greetingMs: UInt64
    public let words: UInt32
    /// The beep's frequency, as measured.
    public let frequencyHz: UInt32
    /// How long the beep sounded.
    public let lengthMs: UInt64
    /// The special information tone's three frequencies and lengths, as
    /// measured.
    public let sitHz: [UInt32]
    public let sitMs: [UInt32]
}

/// The STUN server in use moved to another in the list, or every one of
/// them failed (`sipral_stun_server_event_t`).
public struct StunServerEventData: Sendable {
    public let stateRaw: UInt32
    public let state: SipralStunServerState?
    /// The server in use now, or the last one that failed.
    public let server: String
    /// The server that was in use, for `.changed`; `nil` otherwise.
    public let previous: String?
}

/// Open or close a TURN-over-TCP/TLS connection. `SipralStack` acts on it
/// itself.
public struct TurnStreamEventData: Sendable {
    public let stateRaw: UInt32
    public let state: SipralTurnStream?
    /// What to open: `SipralTransport.tcp` or `.tls`, as a raw value.
    public let protocolRaw: UInt32
    /// The media socket, as `sipral_stack_nat_map` named it.
    public let local: String
    /// The TURN server, `host:port`.
    public let server: String
}

/// An out-of-dialog REFER: `SipralStack.acceptReferral` or `rejectReferral`.
/// `statusCode` is zero while it waits; nonzero means it lapsed and the
/// stack answered with that code. `referredBy` is unverified.
public struct ReferralEventData: Sendable {
    public let statusCode: UInt32
    public let attended: Bool
    public let target: String?
    public let referredBy: String?
}

/// A transfer inside a call. At `.transferRequested` the far end asks this
/// end to call `target` (accept or reject like a referral). At
/// `.transferProgress` and `.transferDone` it reports on our
/// `Call.transfer(to:)`, `statusCode` being the new call's status.
public struct TransferEventData: Sendable, Equatable {
    public let statusCode: UInt32
    public let attended: Bool
    public let target: String?
}

/// What a STUN server said about one of this stack's sockets
/// (`sipral_nat_event_t`).
public struct NatEventData: Sendable {
    public let mappingRaw: UInt32
    public let mapping: SipralNatMapping?
    /// True for the signalling socket, false for a call's media socket.
    public let signalling: Bool
    /// The transport, for the signalling socket; zero otherwise.
    public let transport: UInt32
    /// How many accounts' `Contact` moved to `mapped` because of this.
    public let accounts: UInt32
    /// The socket, as this layer bound it.
    public let local: String
    /// Where the server saw it from -- the public address -- or `nil` for
    /// `SipralNatMapping.unanswered`.
    public let mapped: String?
    /// The mapping before, for `SipralNatMapping.moved`.
    public let previous: String?
}

/// What a TURN server said about a media socket's relay
/// (`sipral_nat_relay_event_t`). Nothing of the credential is in it.
public struct RelayEventData: Sendable {
    public let outcomeRaw: UInt32
    public let outcome: SipralNatRelay?
    /// The STUN error code the server refused with, or zero.
    public let code: UInt32
    public let local: String
    /// The relayed address, for `SipralNatRelay.allocated`.
    public let relayed: String?
    public let mapped: String?
    /// Why there is none, for `SipralNatRelay.failed`.
    public let reason: String?
}

public struct CallEventData: Sendable {
    public let stateRaw: UInt32
    public let state: SipralCallState?
    public let endReasonRaw: UInt32
    public let endReason: SipralCallEndReason?
    public let statusCode: UInt32
    public let other: SipralHandle
    public let heldHere: Bool
    public let heldThere: Bool
    public let localSdp: [UInt8]?
    public let remoteSdp: [UInt8]?
    public let retryInMs: UInt64
    public let fromUri: String?
    public let fromDisplay: String?
    public let toUri: String?
    public let callId: String?
    public let digit: UInt32
    /// Why the far end ended the call, on `SipralEventKind.callEnded`: the
    /// `Reason` (RFC 3326) of its BYE, its CANCEL or its refusal, or `nil`
    /// when it gave none.
    public let endCause: EndCause?
    /// Whether an incoming call arrived from a peer its account trusts; when
    /// it did not, `assertedUri`, `assertedDisplay` and `verstat` say nothing.
    public let identityTrusted: Bool
    /// Who the network says is calling -- the first `P-Asserted-Identity`,
    /// or a calling `Remote-Party-ID` -- from a trusted peer only.
    public let assertedUri: String?
    public let assertedDisplay: String?
    /// What the network concluded about the caller's number.
    public let verstat: SipralVerstat?
    /// What the caller's `Privacy` asked for.
    public let privacy: Privacy
    /// The top `Diversion` and its reason; the counts say how many entries
    /// `SipralStack.callerIdentity(of:)` will read.
    public let divertedFrom: String?
    public let diversionReason: String?
    public let diversionCount: UInt32
    public let historyCount: UInt32
    /// `Answer-Mode` and `Priv-Answer-Mode` (RFC 5373), and whether each said
    /// `;require`.
    public let answerMode: SipralAnswerMode?
    public let answerModeRequired: Bool
    public let privAnswerMode: SipralAnswerMode?
    public let privAnswerModeRequired: Bool
    /// After how long the call asked to be answered without the person, or
    /// `nil` when it did not ask.
    public let answerAfterMs: UInt64?
    /// Whether the ring says the caller is internal or external.
    public let ringSource: SipralRingSource?
    /// The first `Alert-Info` URI.
    public let alertInfo: String?
    /// This end's STIR/SHAKEN verdict on the `Identity` (RFC 8224), when the
    /// account verifies.
    public let verification: SipralVerificationOutcome?
    public let attestation: SipralAttestation?
    public let verificationFailure: SipralVerificationFailure?
}

public struct MediaEventData: Sendable {
    public let codec: UInt32
    public let direction: UInt32
    public let silentForMs: UInt64
    public let recordedMs: UInt64
    public let fault: UInt32
    public let reason: String?
    /// `sipral_media_event_t::digit`, as the character it names, or `nil`
    /// for every kind but `SipralEventKind.digitReceived`.
    public let digit: Character?
    public let eventCode: UInt32
    public let heldMs: UInt64
    public let suite: UInt32
    public let sourceRaw: UInt32
    public let source: SipralDigitSource?
    /// Key exchange, encryption and far-end authentication, on media
    /// started, changed and secured.
    public let keyExchange: SipralKeyExchange?
    public let encrypted: Bool
    public let authenticated: Bool
    /// The end-of-call record, on `mediaStatistics` only. The stream is gone
    /// by then, so this (or `Call.finalStatistics`) is the only source.
    public var statistics: sipral_stream_stats_t? = nil

    /// The SRTP suite (RFC 4568, 6188, 7714), on `mediaSecured`; `nil` for
    /// one newer than this package.
    public var srtpSuite: SipralSrtpSuite? { SipralSrtpSuite(rawValue: suite) }
}

public struct RegistrationEventData: Sendable {
    public let stateRaw: UInt32
    public let state: SipralRegistrationState?
    public let failure: UInt32
    public let statusCode: UInt32
    public let expiresMs: UInt64
    public let refreshInMs: UInt64
    public let retryInMs: UInt64
}

public struct AnnounceEventData: Sendable {
    public let announcement: SipralHandle
    public let waitedMs: UInt64
}

enum SipralEventDecoder {
    // Kinds whose payload lives in `payload.call`.
    private static let callKinds: Set<UInt32> = [
        SipralEventKind.incomingCall.rawValue,
        SipralEventKind.callProgress.rawValue,
        SipralEventKind.callForked.rawValue,
        SipralEventKind.callConfirmed.rawValue,
        SipralEventKind.sessionChanged.rawValue,
        SipralEventKind.sessionOffered.rawValue,
        SipralEventKind.sessionChangeFailed.rawValue,
        SipralEventKind.callReplaced.rawValue,
        SipralEventKind.callEnded.rawValue,
        SipralEventKind.dtmfSent.rawValue,
        SipralEventKind.callAddressWanted.rawValue,
    ]

    // Kinds whose payload lives in `payload.media` (`sipral_media_event_t`).
    private static let mediaKinds: Set<UInt32> = [
        SipralEventKind.mediaStatistics.rawValue,
        SipralEventKind.mediaStalled.rawValue,
        SipralEventKind.mediaStarted.rawValue,
        SipralEventKind.mediaChanged.rawValue,
        SipralEventKind.mediaResumed.rawValue,
        SipralEventKind.mediaFailed.rawValue,
        SipralEventKind.recordingStopped.rawValue,
        SipralEventKind.digitReceived.rawValue,
        SipralEventKind.mediaSecured.rawValue,
        SipralEventKind.mediaPathChosen.rawValue,
        SipralEventKind.inBandDigit.rawValue,
        SipralEventKind.qualityReportSent.rawValue,
        SipralEventKind.mediaUnjoined.rawValue,
    ]

    private static func progressData(_ progress: sipral_progress_event_t) -> ProgressEventData {
        ProgressEventData(
            what: SipralProgressKind(rawValue: progress.what),
            tone: SipralProgressTone(rawValue: progress.tone),
            verdict: SipralAmdVerdict(rawValue: progress.verdict),
            reason: SipralAmdReason(rawValue: progress.reason),
            atMs: progress.at_ms,
            initialSilenceMs: progress.initial_silence_ms,
            greetingMs: progress.greeting_ms,
            words: progress.words,
            frequencyHz: progress.frequency_hz,
            lengthMs: progress.length_ms,
            sitHz: [progress.sit_hz_1, progress.sit_hz_2, progress.sit_hz_3],
            sitMs: [progress.sit_ms_1, progress.sit_ms_2, progress.sit_ms_3]
        )
    }

    private static func bytes(_ pointer: UnsafePointer<UInt8>?, _ length: Int) -> [UInt8]? {
        guard let pointer, length > 0 else { return nil }
        return Array(UnsafeBufferPointer(start: pointer, count: length))
    }

    private static func text(_ pointer: UnsafePointer<UInt8>?, _ length: Int) -> String? {
        guard let raw = bytes(pointer, length) else { return nil }
        return String(decoding: raw, as: UTF8.self)
    }

    private static func textC(_ pointer: UnsafePointer<CChar>?, _ length: Int) -> String? {
        guard let pointer, length > 0 else { return nil }
        return pointer.withMemoryRebound(to: UInt8.self, capacity: length) { text($0, length) }
    }

    private static func callData(_ call: sipral_call_event_t) -> CallEventData {
        CallEventData(
            stateRaw: call.state,
            state: SipralCallState(rawValue: call.state),
            endReasonRaw: call.end_reason,
            endReason: SipralCallEndReason(rawValue: call.end_reason),
            statusCode: call.status_code,
            other: call.other,
            heldHere: call.held_here != 0,
            heldThere: call.held_there != 0,
            localSdp: bytes(call.local_sdp, call.local_sdp_len),
            remoteSdp: bytes(call.remote_sdp, call.remote_sdp_len),
            retryInMs: call.retry_in_ms,
            fromUri: text(call.from_uri, call.from_uri_len),
            fromDisplay: text(call.from_display, call.from_display_len),
            toUri: text(call.to_uri, call.to_uri_len),
            callId: text(call.call_id, call.call_id_len),
            digit: call.digit,
            endCause: endCause(call),
            identityTrusted: call.identity_trusted != 0,
            assertedUri: text(call.asserted_uri, call.asserted_uri_len),
            assertedDisplay: text(call.asserted_display, call.asserted_display_len),
            verstat: SipralVerstat(rawValue: call.verstat),
            privacy: Privacy(rawValue: call.privacy),
            divertedFrom: text(call.diverted_from, call.diverted_from_len),
            diversionReason: text(call.diversion_reason, call.diversion_reason_len),
            diversionCount: call.diversion_count,
            historyCount: call.history_count,
            answerMode: SipralAnswerMode(rawValue: call.answer_mode),
            answerModeRequired: call.answer_mode_required != 0,
            privAnswerMode: SipralAnswerMode(rawValue: call.priv_answer_mode),
            privAnswerModeRequired: call.priv_answer_mode_required != 0,
            answerAfterMs: call.has_answer_after != 0 ? call.answer_after_ms : nil,
            ringSource: SipralRingSource(rawValue: call.ring_source),
            alertInfo: text(call.alert_info, call.alert_info_len),
            verification: SipralVerificationOutcome(rawValue: call.verification),
            attestation: SipralAttestation(rawValue: call.attestation),
            verificationFailure: SipralVerificationFailure(rawValue: call.verification_failure)
        )
    }

    private static func endCause(_ call: sipral_call_event_t) -> EndCause? {
        let text = text(call.cause_text, call.cause_text_len)
        guard call.cause_sip != 0 || call.cause_q850 != 0 || text != nil else { return nil }
        return EndCause(
            sip: call.cause_sip == 0 ? nil : call.cause_sip,
            q850: call.cause_q850 == 0 ? nil : call.cause_q850,
            text: text
        )
    }

    private static func audioData(_ audio: sipral_audio_event_t) -> AudioEventData {
        AudioEventData(
            changeRaw: audio.change,
            change: SipralAudioChange(rawValue: audio.change),
            originRaw: audio.origin,
            origin: SipralAudioOrigin(rawValue: audio.origin),
            role: SipralAudioRole(rawValue: audio.role),
            direction: SipralAudioDirection(rawValue: audio.direction),
            device: audio.device == 0 ? nil : audio.device
        )
    }

    private static func mediaData(_ media: sipral_media_event_t) -> MediaEventData {
        let digitChar: Character?
        if media.digit != 0, let scalar = Unicode.Scalar(media.digit) {
            digitChar = Character(scalar)
        } else {
            digitChar = nil
        }
        return MediaEventData(
            codec: media.codec,
            direction: media.direction,
            silentForMs: media.silent_for_ms,
            recordedMs: media.recorded_ms,
            fault: media.fault,
            reason: textC(media.reason, media.reason_len),
            digit: digitChar,
            eventCode: media.event_code,
            heldMs: media.held_ms,
            suite: media.suite,
            sourceRaw: media.source,
            source: SipralDigitSource(rawValue: media.source),
            keyExchange: SipralKeyExchange(rawValue: media.key_exchange),
            encrypted: media.encrypted != 0,
            authenticated: media.authenticated != 0,
            statistics: statistics(media.statistics)
        )
    }

    /// Reads only the `size` bytes the library wrote: an older library
    /// writes a shorter record, and the rest stays zero.
    static func statistics(_ pointer: UnsafePointer<sipral_stream_stats_t>?) -> sipral_stream_stats_t? {
        guard let pointer else { return nil }
        var copy = sipral_stream_stats_t.sized()
        let said = UnsafeRawPointer(pointer).loadUnaligned(as: Int.self)
        let written = min(max(said, 0), MemoryLayout<sipral_stream_stats_t>.size)
        withUnsafeMutableBytes(of: &copy) { into in
            guard let base = into.baseAddress else { return }
            base.copyMemory(from: UnsafeRawPointer(pointer), byteCount: written)
        }
        return copy
    }

    private static func registrationData(_ registration: sipral_registration_event_t) -> RegistrationEventData {
        RegistrationEventData(
            stateRaw: registration.state,
            state: SipralRegistrationState(rawValue: registration.state),
            failure: registration.failure,
            statusCode: registration.status_code,
            expiresMs: registration.expires_ms,
            refreshInMs: registration.refresh_in_ms,
            retryInMs: registration.retry_in_ms
        )
    }

    private static func announceData(_ announce: sipral_announce_event_t) -> AnnounceEventData {
        AnnounceEventData(announcement: announce.announcement, waitedMs: announce.waited_ms)
    }

    private static func natData(_ nat: sipral_nat_event_t) -> NatEventData {
        NatEventData(
            mappingRaw: nat.mapping,
            mapping: SipralNatMapping(rawValue: nat.mapping),
            signalling: nat.signalling != 0,
            transport: nat.transport,
            accounts: nat.accounts,
            local: textC(nat.local, nat.local_len) ?? "",
            mapped: textC(nat.mapped, nat.mapped_len),
            previous: textC(nat.previous, nat.previous_len)
        )
    }

    private static func relayData(_ relay: sipral_nat_relay_event_t) -> RelayEventData {
        RelayEventData(
            outcomeRaw: relay.outcome,
            outcome: SipralNatRelay(rawValue: relay.outcome),
            code: relay.code,
            local: textC(relay.local, relay.local_len) ?? "",
            relayed: textC(relay.relayed, relay.relayed_len),
            mapped: textC(relay.mapped, relay.mapped_len),
            reason: textC(relay.reason, relay.reason_len)
        )
    }

    private static func turnStreamData(_ stream: sipral_turn_stream_event_t) -> TurnStreamEventData {
        TurnStreamEventData(
            stateRaw: stream.state,
            state: SipralTurnStream(rawValue: stream.state),
            protocolRaw: stream.protocol,
            local: textC(stream.local, stream.local_len) ?? "",
            server: textC(stream.server, stream.server_len) ?? ""
        )
    }

    private static func stunServerData(_ server: sipral_stun_server_event_t) -> StunServerEventData {
        StunServerEventData(
            stateRaw: server.state,
            state: SipralStunServerState(rawValue: server.state),
            server: textC(server.server, server.server_len) ?? "",
            previous: textC(server.previous, server.previous_len)
        )
    }

    private static func verificationData(_ verification: sipral_verification_event_t) -> VerificationEventData {
        VerificationEventData(
            stage: SipralVerificationStage(rawValue: verification.stage),
            outcome: SipralVerificationOutcome(rawValue: verification.outcome),
            failure: SipralVerificationFailure(rawValue: verification.failure),
            attestation: SipralAttestation(rawValue: verification.attestation),
            verstat: SipralVerstat(rawValue: verification.verstat),
            responseCode: verification.response_code,
            refused: verification.refused != 0,
            certificateUrl: textC(verification.certificate_url, verification.certificate_url_len),
            orig: textC(verification.orig, verification.orig_len),
            origid: textC(verification.origid, verification.origid_len),
            detail: textC(verification.detail, verification.detail_len)
        )
    }

    private static func referralData(_ referral: sipral_referral_event_t) -> ReferralEventData {
        ReferralEventData(
            statusCode: referral.status_code,
            attended: referral.attended != 0,
            target: textC(referral.target, referral.target_len),
            referredBy: textC(referral.referred_by, referral.referred_by_len)
        )
    }

    /// Copies one `sipral_event_t` out into a standalone `SipralEvent`.
    ///
    /// Only from inside the C callback, while `raw` is valid.
    static func decode(_ raw: sipral_event_t) -> SipralEvent {
        let kindRaw = raw.kind
        let kindName = String(cString: sipral_event_kind_name(kindRaw))
        var callData: CallEventData?
        var mediaData: MediaEventData?
        var registrationData: RegistrationEventData?
        var announceData: AnnounceEventData?
        var natData: NatEventData?
        var relayData: RelayEventData?
        var referralData: ReferralEventData?
        var turnStreamData: TurnStreamEventData?
        var audioData: AudioEventData?
        var stunServerData: StunServerEventData?
        var verificationData: VerificationEventData?

        if kindRaw == SipralEventKind.callerVerification.rawValue {
            verificationData = self.verificationData(raw.payload.verification)
        } else if kindRaw == SipralEventKind.stunServer.rawValue {
            stunServerData = self.stunServerData(raw.payload.stun_server)
        } else if kindRaw == SipralEventKind.audioDevicesChanged.rawValue {
            audioData = self.audioData(raw.payload.audio)
        } else if kindRaw == SipralEventKind.turnStream.rawValue {
            turnStreamData = self.turnStreamData(raw.payload.turn_stream)
        } else if kindRaw == SipralEventKind.natMapping.rawValue {
            natData = self.natData(raw.payload.nat)
        } else if kindRaw == SipralEventKind.natRelay.rawValue {
            relayData = self.relayData(raw.payload.relay)
        } else if kindRaw == SipralEventKind.referral.rawValue {
            referralData = self.referralData(raw.payload.referral)
        } else if kindRaw == SipralEventKind.registrationChanged.rawValue {
            registrationData = self.registrationData(raw.payload.registration)
        } else if callKinds.contains(kindRaw) {
            callData = self.callData(raw.payload.call)
        } else if mediaKinds.contains(kindRaw) {
            mediaData = self.mediaData(raw.payload.media)
        } else if kindRaw == SipralEventKind.callAnnounced.rawValue
            || kindRaw == SipralEventKind.announcedCallMissing.rawValue {
            announceData = self.announceData(raw.payload.announce)
        }

        var event = SipralEvent(
            kindRaw: kindRaw,
            kind: SipralEventKind(rawValue: kindRaw),
            kindName: kindName,
            stack: raw.stack,
            account: raw.account,
            call: raw.call,
            message: bytes(raw.message, raw.message_len),
            callData: callData,
            mediaData: mediaData,
            registrationData: registrationData,
            announceData: announceData,
            natData: natData,
            relayData: relayData,
            referralData: referralData,
            turnStreamData: turnStreamData,
            audioData: audioData,
            stunServerData: stunServerData,
            verificationData: verificationData
        )
        if kindRaw == SipralEventKind.progressDetected.rawValue {
            event.progressData = progressData(raw.payload.progress)
        }
        if kindRaw == SipralEventKind.transferRequested.rawValue
            || kindRaw == SipralEventKind.transferProgress.rawValue
            || kindRaw == SipralEventKind.transferDone.rawValue {
            let transfer = raw.payload.transfer
            event.transferData = TransferEventData(
                statusCode: transfer.status_code,
                attended: transfer.attended != 0,
                target: textC(transfer.target, transfer.target_len)
            )
        }
        if kindRaw == SipralEventKind.transportWanted.rawValue {
            let wanted = raw.payload.transport_wanted
            event.transportWantedData = TransportWantedEventData(
                protocolRaw: wanted.protocol,
                destination: textC(wanted.destination, wanted.destination_len) ?? "",
                requestBytes: wanted.request_bytes,
                limitBytes: wanted.limit_bytes
            )
        }
        if kindRaw == SipralEventKind.transportFailed.rawValue {
            let lost = raw.payload.transport_failed
            event.transportFailedData = TransportFailedEventData(
                transport: lost.transport,
                protocolRaw: lost.protocol,
                error: SipralTransportError(rawValue: lost.error),
                tls: SipralTlsFailure(rawValue: lost.tls),
                detail: textC(lost.detail, lost.detail_len)
            )
        }
        if kindRaw == SipralEventKind.localConferenceChanged.rawValue {
            let changed = raw.payload.local_conference
            event.localConferenceData = LocalConferenceEventData(
                conference: changed.conference,
                change: SipralLocalConferenceChange(rawValue: changed.change),
                departure: SipralDeparture(rawValue: changed.departure),
                member: changed.member,
                members: changed.members,
                talkers: changed.talkers,
                loudest: changed.loudest
            )
        }
        if kindRaw == SipralEventKind.conferenceChanged.rawValue {
            let changed = raw.payload.conference
            event.conferenceData = ConferenceEventData(
                subscription: changed.subscription,
                update: SipralConferenceUpdate(rawValue: changed.update),
                version: changed.version,
                users: changed.users
            )
        }
        if kindRaw == SipralEventKind.textReceived.rawValue {
            let typed = raw.payload.text
            event.textData = TextEventData(text: textC(typed.text, typed.text_len) ?? "", missing: typed.missing)
        }
        if kindRaw == SipralEventKind.presenceChanged.rawValue {
            event.presenceData = presenceData(raw.payload.presence)
        }
        if kindRaw == SipralEventKind.subscriptionChanged.rawValue || kindRaw == SipralEventKind.notified.rawValue {
            let told = raw.payload.subscription
            event.subscriptionData = SubscriptionEventData(
                subscription: told.subscription,
                state: SipralSubscriptionState(rawValue: told.state),
                reason: SipralSubscriptionEnd(rawValue: told.reason),
                statusCode: told.status_code,
                hasDialogInfo: told.has_dialog_info != 0,
                expiresMs: told.expires_ms,
                refreshInMs: told.refresh_in_ms,
                retryInMs: told.retry_in_ms,
                forkedFrom: told.forked_from
            )
        }
        if kindRaw == SipralEventKind.recovery.rawValue {
            let told = raw.payload.recovery
            event.recoveryData = RecoveryEventData(
                state: SipralRecoveryOutcome(rawValue: told.state),
                rung: SipralRecoveryRung(rawValue: told.rung),
                reason: SipralRecoveryFailure(rawValue: told.reason),
                unverified: told.unverified
            )
        }
        if kindRaw == SipralEventKind.resolveNeeded.rawValue {
            let told = raw.payload.resolve
            event.resolveData = ResolveEventData(
                dialog: told.dialog,
                host: textC(told.host, told.host_len),
                port: told.port,
                protocolRaw: told.protocol
            )
        }
        if kindRaw == SipralEventKind.lookupWanted.rawValue
            || kindRaw == SipralEventKind.located.rawValue
            || kindRaw == SipralEventKind.locateFailed.rawValue {
            let told = raw.payload.locate
            event.locateData = LocateEventData(
                recordRaw: told.record,
                failureRaw: told.failure,
                name: textC(told.name, told.name_len),
                targets: textC(told.targets, told.targets_len),
                retryInMs: told.retry_in_ms
            )
        }
        if kindRaw == SipralEventKind.challengeDeclined.rawValue {
            let told = raw.payload.challenge
            let realms = textC(told.realms, told.realms_len) ?? ""
            event.challengeData = ChallengeEventData(
                refusal: SipralChallengeRefusal(rawValue: told.refusal),
                server: textC(told.server, told.server_len),
                realms: realms.split(separator: "\n").map(String.init)
            )
        }
        if kindRaw == SipralEventKind.networkTest.rawValue {
            let told = raw.payload.network_test
            event.networkTestData = NetworkTestEventData(
                test: told.test,
                verdict: SipralNetworkVerdict(rawValue: told.verdict),
                stun: SipralNetworkProbe(rawValue: told.stun),
                nat: SipralNatKind(rawValue: told.nat),
                turn: SipralNetworkProbe(rawValue: told.turn),
                server: SipralServerReach(rawValue: told.server),
                serverStatus: told.server_status,
                serverRoundTripMs: told.server_round_trip_ms,
                echo: SipralNetworkProbe(rawValue: told.echo),
                echoVerdict: SipralNetworkVerdict(rawValue: told.echo_verdict),
                lossPercent: told.loss_percent,
                jitterMs: told.jitter_ms,
                roundTripMs: told.has_round_trip != 0 ? told.round_trip_ms : nil,
                rFactor: told.r_factor,
                mos: told.mos,
                local: textC(told.local, told.local_len),
                mapped: textC(told.mapped, told.mapped_len)
            )
        }
        if kindRaw == SipralEventKind.tokenRequired.rawValue {
            let told = raw.payload.token
            let nonEmpty = { (text: String?) -> String? in
                guard let text, !text.isEmpty else { return nil }
                return text
            }
            event.tokenData = TokenEventData(
                error: SipralTokenError(rawValue: told.error),
                errorCode: nonEmpty(textC(told.error_code, told.error_code_len)),
                proxy: told.proxy == SipralToggle.on.rawValue,
                server: textC(told.server, told.server_len),
                realm: textC(told.realm, told.realm_len) ?? "",
                scope: nonEmpty(textC(told.scope, told.scope_len)),
                authzServer: nonEmpty(textC(told.authz_server, told.authz_server_len))
            )
        }
        if kindRaw == SipralEventKind.messageReceived.rawValue
            || kindRaw == SipralEventKind.messageSent.rawValue
            || kindRaw == SipralEventKind.messagesWaiting.rawValue {
            let told = raw.payload.message
            event.messageData = MessageEventData(
                message: told.message,
                subscription: told.subscription,
                statusCode: told.status_code,
                contentType: textC(told.content_type, told.content_type_len),
                body: bytes(told.body, told.body_len),
                waiting: told.waiting != 0,
                newMessages: told.new_messages,
                oldMessages: told.old_messages,
                urgentNewMessages: told.urgent_new_messages,
                urgentOldMessages: told.urgent_old_messages,
                messageAccount: textC(told.message_account, told.message_account_len)
            )
        }
        return event
    }

    private static func presenceData(_ told: sipral_presence_event_t) -> PresenceEventData {
        PresenceEventData(
            kind: SipralPresenceKind(rawValue: told.kind),
            subscription: told.subscription,
            basic: SipralBasic(rawValue: told.basic),
            activity: SipralActivity(rawValue: told.activity),
            entity: textC(told.entity, told.entity_len),
            note: textC(told.note, told.note_len),
            publicationState: SipralPublicationState(rawValue: told.publication_state),
            failure: SipralPublishFailure(rawValue: told.failure),
            statusCode: told.status_code,
            expiresMs: told.expires_ms,
            refreshInMs: told.refresh_in_ms
        )
    }
}
