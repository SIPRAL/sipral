// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import CSipral

/// The `Privacy` values of RFC 3323 §4.2: what a caller asked to keep to
/// itself, on an incoming call's `CallEventData.privacy`, and what an
/// account asks for on every call it places (`SipralStack.addAccount`).
/// `.id` is "withhold my number".
public struct Privacy: OptionSet, Sendable, Hashable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }

    /// Obscure the fields that could identify the caller.
    public static let header = Privacy(rawValue: Sipral.privacyHeader)
    /// Hide the session description from the far end.
    public static let session = Privacy(rawValue: Sipral.privacySession)
    /// User-level privacy.
    public static let user = Privacy(rawValue: Sipral.privacyUser)
    /// Keep the asserted identity inside the trust domain (RFC 3325 §9.3).
    public static let id = Privacy(rawValue: Sipral.privacyId)
    /// Fail the call rather than go without the privacy asked for.
    public static let critical = Privacy(rawValue: Sipral.privacyCritical)
    /// No privacy, stated. Read only: an account asks for none with `[]`.
    public static let none = Privacy(rawValue: Sipral.privacyNone)
}

/// How an account's calls ask for a session timer (RFC 4028).
public enum SessionTimer: Sendable, Equatable {
    /// The stack's default: thirty minutes.
    case `default`
    /// Ask for none; a far end that insists on one is still honoured.
    case off
    /// Ask for this interval, at least 90 seconds (RFC 4028 §5).
    case interval(seconds: UInt64)

    var raw: (mode: UInt32, seconds: UInt64) {
        switch self {
        case .default: return (SipralSessionTimer.default.rawValue, 0)
        case .off: return (SipralSessionTimer.off.rawValue, 0)
        case .interval(let seconds): return (SipralSessionTimer.interval.rawValue, seconds)
        }
    }
}

/// Why this end is ending a call, written as a `Reason` (RFC 3326) on the BYE
/// or the CANCEL `Call.hangup(reason:)` sends: a SIP status, a Q.850 cause,
/// or both, and a line of text on the first one written.
public struct HangupReason: Sendable, Equatable {
    public let sipCause: UInt32?
    public let q850Cause: UInt32?
    public let text: String?

    public init(sipCause: UInt32? = nil, q850Cause: UInt32? = nil, text: String? = nil) {
        self.sipCause = sipCause
        self.q850Cause = q850Cause
        self.text = text
    }

    /// `SIP;cause=200;text="Call completed elsewhere"`: another of this
    /// person's phones took the call, so the one cancelled shows no missed
    /// call.
    public static let completedElsewhere = HangupReason(sipCause: 200, text: "Call completed elsewhere")
    /// `Q.850;cause=16`: a normal end.
    public static let normalClearing = HangupReason(q850Cause: 16)
    /// `Q.850;cause=17`: the person is busy.
    public static let userBusy = HangupReason(q850Cause: 17)
    /// `Q.850;cause=21`: the person declined.
    public static let callRejected = HangupReason(q850Cause: 21)
}

/// Why the far end ended a call, as the `Reason` (RFC 3326) on its BYE, its
/// CANCEL or its refusal said: `CallEventData.endCause`.
public struct EndCause: Sendable, Equatable {
    /// The SIP status named, or `nil`.
    public let sip: UInt32?
    /// The Q.850 cause named -- 16 a normal clearing, 17 a busy line -- or
    /// `nil`.
    public let q850: UInt32?
    /// The first value's text.
    public let text: String?

    /// A forking proxy saying another phone answered: not a missed call.
    public var completedElsewhere: Bool { sip == 200 }
}

/// One party a network asserted (`P-Asserted-Identity`, `Remote-Party-ID`).
public struct Party: Sendable, Equatable {
    public let uri: String
    public let displayName: String?
}

/// One `Diversion` value (RFC 5806): who the call was diverted from, and why
/// -- `no-answer`, `user-busy`, `unconditional` and the rest.
public struct Diversion: Sendable, Equatable {
    public let uri: String
    public let displayName: String?
    public let reason: String?
}

/// One `History-Info` entry (RFC 7044): a target the request was sent to, and
/// its `index`.
public struct HistoryEntry: Sendable, Equatable {
    public let uri: String
    public let index: String?
}

/// One `Alert-Info` value: the ring asked for, and its `info=` name.
public struct AlertInfo: Sendable, Equatable {
    public let uri: String
    public let name: String?
}

/// Who is calling beyond the `From`: what the network asserted, behind the
/// account's trust gate, what the caller asked to keep private, and where
/// the call was diverted from. Read with `SipralStack.callerIdentity(of:)`
/// from the `.incomingCall` event, before deciding whether to answer, or with
/// `Call.identity()` later.
public struct CallerIdentity: Sendable, Equatable {
    /// Whether the INVITE came from a peer the account trusts
    /// (`trustedPeers`). When it did not, `asserted`, `assertedParties` and
    /// `verstat` say nothing, whatever it carried (RFC 3325 §8).
    public let trusted: Bool
    /// Who the network says is calling: the first `P-Asserted-Identity`, or
    /// a calling `Remote-Party-ID` when there is none.
    public let asserted: Party?
    /// Every `P-Asserted-Identity`.
    public let assertedParties: [Party]
    /// Every `Remote-Party-ID`.
    public let remoteParties: [Party]
    /// What the network concluded about the caller's number.
    public let verstat: SipralVerstat
    /// What the caller's `Privacy` asked for.
    public let privacy: Privacy
    /// Every `Diversion`, most recent first.
    public let diversions: [Diversion]
    /// Every `History-Info` entry.
    public let history: [HistoryEntry]
}

/// How a call asked to be answered (RFC 5373) and rung (`Alert-Info`). Whether
/// to answer without the person is the application's policy; this is what
/// the caller asked for.
public struct Answering: Sendable, Equatable {
    public let mode: SipralAnswerMode
    /// The caller would rather be refused, with a 403, than answered any
    /// other way.
    public let modeRequired: Bool
    public let privMode: SipralAnswerMode
    public let privModeRequired: Bool
    /// After how long to answer without the person -- `Answer-Mode: Auto`,
    /// `answer-after`, `info=alert-autoanswer` -- or `nil` when the call did
    /// not ask.
    public let answerAfterMs: UInt64?
    /// Whether the ring says the caller is inside the switch or outside it.
    public let ringSource: SipralRingSource
    /// Every `Alert-Info`, in order.
    public let alertInfo: [AlertInfo]
}

enum IdentityReader {
    /// Every entry's `which` piece, `nil` for one the entry does not have.
    static func texts(stack: SipralStack, call: SipralHandle, _ which: SipralIdentityText) throws -> [String?] {
        let count = try retryingBusy {
            try Sipral.callIdentityCount(stack: stack.handle, call: call, which: which.rawValue)
        }
        return try (0..<count).map { index in
            var buffer = [CChar](repeating: 0, count: 256)
            var needed = 0
            var status = buffer.withUnsafeMutableBufferPointer {
                sipral_call_identity_text(stack.handle, call, index, which.rawValue, $0.baseAddress, $0.count, &needed)
            }
            if status == SipralStatus.bufferTooSmall.rawValue {
                buffer = [CChar](repeating: 0, count: needed)
                status = buffer.withUnsafeMutableBufferPointer {
                    sipral_call_identity_text(stack.handle, call, index, which.rawValue, $0.baseAddress, $0.count, &needed)
                }
            }
            try Sipral.check(status)
            let length = max(needed - 1, 0)
            guard length > 0 else { return nil }
            return String(decoding: buffer.prefix(length).map { UInt8(bitPattern: $0) }, as: UTF8.self)
        }
    }

    static func identity(stack: SipralStack, call: SipralHandle, data: CallEventData?) throws -> CallerIdentity {
        let parties = { (uris: SipralIdentityText, names: SipralIdentityText) throws -> [Party] in
            let read = try texts(stack: stack, call: call, uris)
            let named = try texts(stack: stack, call: call, names)
            return read.enumerated().compactMap { index, uri in
                uri.map { Party(uri: $0, displayName: index < named.count ? named[index] : nil) }
            }
        }
        let diversionUris = try texts(stack: stack, call: call, .diversion)
        let diversionNames = try texts(stack: stack, call: call, .diversionDisplay)
        let diversionReasons = try texts(stack: stack, call: call, .diversionReason)
        let historyUris = try texts(stack: stack, call: call, .history)
        let historyIndexes = try texts(stack: stack, call: call, .historyIndex)
        let asserted = data?.assertedUri.map { Party(uri: $0, displayName: data?.assertedDisplay) }
        return CallerIdentity(
            trusted: data?.identityTrusted ?? false,
            asserted: asserted,
            assertedParties: try parties(.asserted, .assertedDisplay),
            remoteParties: try parties(.remoteParty, .remotePartyDisplay),
            verstat: data?.verstat ?? SipralVerstat.none,
            privacy: data?.privacy ?? [],
            diversions: diversionUris.enumerated().compactMap { index, uri in
                uri.map {
                    Diversion(
                        uri: $0,
                        displayName: index < diversionNames.count ? diversionNames[index] : nil,
                        reason: index < diversionReasons.count ? diversionReasons[index] : nil
                    )
                }
            },
            history: historyUris.enumerated().compactMap { index, uri in
                uri.map { HistoryEntry(uri: $0, index: index < historyIndexes.count ? historyIndexes[index] : nil) }
            }
        )
    }

    static func answering(stack: SipralStack, call: SipralHandle, data: CallEventData?) throws -> Answering {
        let uris = try texts(stack: stack, call: call, .alertInfo)
        let names = try texts(stack: stack, call: call, .alertName)
        return Answering(
            mode: data?.answerMode ?? SipralAnswerMode.none,
            modeRequired: data?.answerModeRequired ?? false,
            privMode: data?.privAnswerMode ?? SipralAnswerMode.none,
            privModeRequired: data?.privAnswerModeRequired ?? false,
            answerAfterMs: data?.answerAfterMs,
            ringSource: data?.ringSource ?? .unknown,
            alertInfo: uris.enumerated().compactMap { index, uri in
                uri.map { AlertInfo(uri: $0, name: index < names.count ? names[index] : nil) }
            }
        )
    }
}
