// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Foundation

/// The part of a VoIP push `PushKitBridge` needs, so it runs without PushKit
/// (absent on macOS and Linux).
public struct VoipPush: Sendable {
    /// The caller's URI, matched against the INVITE's `From` by account,
    /// user and host, unescaped (`docs/15-mobile.md`). Empty when the push
    /// named nobody: the call is then expected on the account alone
    /// (`sipral_account_announce_any`).
    public let callerId: String
    /// The held INVITE's `Call-ID`, when the proxy that pushed put it in
    /// the push (`call-id`); matched before the caller is.
    public let callId: String?
    /// The name the call screen shows for the caller
    /// (`CXCallUpdate.localizedCallerName`), when the push carried one.
    public let displayName: String?

    public init(callerId: String = "", callId: String? = nil, displayName: String? = nil) {
        self.callerId = callerId
        self.callId = callId
        self.displayName = displayName
    }

    /// Whether the push named the caller.
    public var namesCaller: Bool { !callerId.isEmpty }
}

/// What one push's payload says, as `PushKitAdapter` reads it: who is
/// calling, the held INVITE's `Call-ID`, and the caller's name. Any of them
/// may be missing; a push with no caller is expected on its account alone.
public struct VoipPushFields: Sendable, Equatable {
    public var callerId: String?
    public var callId: String?
    public var displayName: String?

    public init(callerId: String? = nil, callId: String? = nil, displayName: String? = nil) {
        self.callerId = callerId
        self.callId = callId
        self.displayName = displayName
    }

    /// The fields a push gateway writes in the clear part of the payload
    /// (`docs/15-mobile.md`, "The lab's push gateway"): `caller`, `call-id`
    /// and `name`, each a string. What `PushKitAdapter` reads when the
    /// application gives it no decoder.
    public init(clear payload: [AnyHashable: Any]) {
        func text(_ key: String) -> String? {
            guard let value = payload[key] as? String, !value.isEmpty else { return nil }
            return value
        }
        self.init(callerId: text("caller"), callId: text("call-id"), displayName: text("name"))
    }

    /// The push to announce, when there is a caller to announce it by.
    public var push: VoipPush? {
        guard let callerId, !callerId.isEmpty else { return nil }
        return VoipPush(callerId: callerId, callId: callId, displayName: displayName)
    }
}

/// Turns a received payload (`PKPushPayload.dictionaryPayload`) into the
/// fields `PushKitAdapter` reads: for a push whose payload is sealed, the
/// application opens it here. Runs on the registry's queue, before the push
/// is reported, so it is quick. One that throws makes the push unusable; a
/// call push whose seal would not open returns empty fields instead, and
/// the call is expected on the account alone.
public typealias VoipPushDecoder = @Sendable (_ payload: [AnyHashable: Any]) throws -> VoipPushFields

/// What became of one push handed to `PushKitBridge.receive(_:mustReport:account:)`.
public enum PushOutcome: Sendable {
    /// Shown, announced and waiting for its INVITE.
    case shown(PendingCall)
    /// Shown and ended at once, since its payload could not be read, it met
    /// no account or had its announcement refused; or never shown, the
    /// system refusing the screen (Do Not Disturb, a blocked caller).
    case unusable
    /// Not shown, since the system said this push need not be
    /// (`PKVoIPPushMetadata.mustReport` false); the binding was refreshed,
    /// and the INVITE, if one comes, is an ordinary incoming call. Carries
    /// what the push named, or `nil` when it named no caller.
    case notShown(VoipPush?)
}

/// Runs `docs/15-mobile.md`'s "C2" sequence for one incoming push:
///
/// > push -> report to CallKit before the handler returns -> announce ->
/// > refresh the binding -> match the INVITE -> answer
///
/// `handle(push:account:)` does the first two steps before returning: iOS
/// stops delivering VoIP pushes to an app that misses that deadline. The
/// stack does the matching; `PendingCall.resolve(with:)` then hands the
/// `Call` to `CallKitBridge`.
///
/// A screen nothing can fill any more is taken down rather than left
/// ringing: when the announcement is refused, and when the stack reports
/// the announced call missing (`announcedCallMissing`, twenty seconds with
/// no INVITE).
public final class PushKitBridge: @unchecked Sendable {
    private let callKit: CallKitBridge
    private let stateQueue = DispatchQueue(label: "org.sipral.pushkit.state")
    /// Shown and not yet matched, oldest first.
    private var pending: [PendingCall] = []
    /// The announcement each call was matched to by the stack
    /// (`callAnnounced`), until that call's `incomingCall`.
    private var announcedCalls: [SipralHandle: SipralHandle] = [:]
    /// The calls `matchIncomingCall` found no push for, which the
    /// application shows itself, by when each arrived: a push the stack
    /// later pairs with one of them is for a call already on screen. Kept
    /// for the announce window only, the stack pairing no older call.
    private var handedToApplication: [SipralHandle: DispatchTime] = [:]

    /// How long the stack pairs a push with an INVITE that came before it
    /// (`docs/15-mobile.md`: fixed at twenty seconds through `sipral.h`).
    private static let announceWindow = 20.0

    public init(callKit: CallKitBridge) {
        self.callKit = callKit
    }

    /// One push, matched to the account it woke.
    ///
    /// Reports to CallKit, then announces, then refreshes the binding
    /// without waiting (a MUST for a woken UA, RFC 8599 §4.1.3). Keep the
    /// returned `PendingCall` and `resolve(with:)` it when the matching
    /// `IncomingCall` arrives (or at once, if the INVITE came first).
    ///
    /// An announcement the stack refuses ends the call just shown, as
    /// failed, before the error is rethrown. A push for a call that is
    /// already on screen, because its INVITE came first and was shown, or
    /// was handed back by `matchIncomingCall` for the application to show,
    /// ends the second screen at once.
    ///
    /// The screen shows the push's `displayName` for the caller; a push
    /// that carried none has the INVITE's name shown once it is matched
    /// (`CallEventData.callerName`). A push that named nobody is shown as
    /// `Unknown`, and once matched its screen is given the INVITE's `From`
    /// URI and name.
    ///
    /// An application with a `PKPushRegistryDelegate` of its own calls this
    /// (or `receive(_:mustReport:account:)`) from its push handler, before
    /// that handler's completion, in place of `PushKitAdapter`.
    @discardableResult
    public func handle(push: VoipPush, account: Account) async throws -> PendingCall {
        let uuid = try await callKit.reportIncomingCall(
            callerId: push.namesCaller ? push.callerId : Self.unknownCaller, displayName: push.displayName
        )

        // Announced and recorded under the queue `matchIncomingCall` takes,
        // in one step: an INVITE the stack matches to this announcement
        // must find it pending, and one already handed back to the
        // application must be known when the answer names it.
        let recorded: (pendingCall: PendingCall, shownAlready: Bool)
        do {
            recorded = try stateQueue.sync { () throws -> (pendingCall: PendingCall, shownAlready: Bool) in
                let announced = try account.announce(caller: push.namesCaller ? push.callerId : nil, callId: push.callId)
                let pendingCall = PendingCall(
                    uuid: uuid, callerId: push.callerId, displayName: push.displayName,
                    announcement: announced.announcement, callKit: callKit
                )
                if let arrivedHandle = announced.call {
                    // The INVITE beat the push.
                    pendingCall.resolveLater(callHandle: arrivedHandle)
                    let handedBack = handedToApplication.removeValue(forKey: arrivedHandle) != nil
                    if handedBack || callKit.uuid(forCallHandle: arrivedHandle) != nil {
                        return (pendingCall, true)
                    }
                }
                pending.append(pendingCall)
                return (pendingCall, false)
            }
        } catch {
            callKit.takeDown(uuid: uuid, reason: .failed)
            throw error
        }
        try? account.refreshBinding()

        if recorded.shownAlready {
            callKit.takeDown(uuid: uuid, reason: .failed)
        }
        return recorded.pendingCall
    }

    /// What a screen shows for a caller nothing named.
    private static let unknownCaller = "Unknown"

    /// A push nothing could be read from, or one that arrives with no
    /// account to announce it on: PushKit still requires a call reported
    /// for it, so one is, and ended at once as failed.
    public func reportUnusable(callerId: String?) async {
        guard let uuid = try? await callKit.reportIncomingCall(callerId: callerId ?? Self.unknownCaller) else { return }
        callKit.takeDown(uuid: uuid, reason: .failed)
    }

    /// One push, as `PushKitAdapter` hands every one over: `fields` as the
    /// application's decoder read them (`nil` when it could not), whether
    /// the system requires a call shown for it, and the account it woke.
    ///
    /// With `mustReport` (always, before iOS 26.4), a push whose fields
    /// were read and that meets an account runs `handle(push:account:)`,
    /// on its caller, or on the account alone when it named none (RFC 8599
    /// asks a push for no payload, §13); any other is shown and ended at
    /// once (`reportUnusable(callerId:)`), so iOS keeps delivering. Without
    /// it nothing is shown or announced: the binding is refreshed (§4.1.3),
    /// and the INVITE, if one comes, arrives as an ordinary incoming call
    /// for the application to show, as one does while the application runs.
    public func receive(_ fields: VoipPushFields?, mustReport: Bool = true, account: Account?) async -> PushOutcome {
        guard mustReport else {
            try? account?.refreshBinding()
            return .notShown(fields?.push)
        }
        guard let fields, let account else {
            await reportUnusable(callerId: fields?.callerId)
            return .unusable
        }
        let push = fields.push ?? VoipPush(callId: fields.callId, displayName: fields.displayName)
        guard let pending = try? await handle(push: push, account: account) else { return .unusable }
        return .shown(pending)
    }

    /// Hand every event from `SipralStack.events()` here; three matter.
    ///
    /// `callAnnounced` records which announcement the stack matched a call
    /// to. `incomingCall` takes the push shown for it and returns it, to be
    /// `resolve(with:)`d with the `Call` from `SipralStack.takeIncomingCall`;
    /// `nil` means no push announced this call, so the application shows
    /// it itself. Only the stack's pairing counts: a call is found by the
    /// announcement it was matched to, or by the call a push's announce
    /// found already ringing, and never by a caller that merely looks
    /// alike. A screen the
    /// push gave no name is given the INVITE's (`CallEventData.callerName`),
    /// and one whose push named nobody the INVITE's `From` URI as well.
    /// `announcedCallMissing` ends the screen that was waiting for it, as
    /// unanswered.
    @discardableResult
    public func matchIncomingCall(_ event: SipralEvent, on stack: SipralStack) -> PendingCall? {
        switch event.kind {
        case .callAnnounced?:
            if let announcement = event.announceData?.announcement {
                stateQueue.sync { announcedCalls[event.call] = announcement }
            }
            return nil
        case .incomingCall?:
            let found = stateQueue.sync { () -> PendingCall? in
                let announcement = announcedCalls.removeValue(forKey: event.call)
                // The stack's pairing alone decides: a call it matched to no
                // waiting announcement is not a push's, however alike the
                // callers look (extension 100 on two PBXs).
                let index = pending.firstIndex { $0.matchedCallHandle == event.call }
                    ?? announcement.flatMap { named in pending.firstIndex { $0.announcement == named } }
                guard let index else {
                    let now = DispatchTime.now()
                    handedToApplication = handedToApplication.filter { now < $0.value + Self.announceWindow }
                    handedToApplication[event.call] = now
                    return nil
                }
                return pending.remove(at: index)
            }
            found?.resolveLater(callHandle: event.call)
            if let found {
                let name = found.displayName ?? event.callData?.callerName
                if found.callerId.isEmpty, let from = event.callData?.fromUri {
                    callKit.identifyCaller(uuid: found.uuid, callerId: from, displayName: name)
                } else if found.displayName == nil, let name {
                    callKit.nameCaller(uuid: found.uuid, displayName: name)
                }
            }
            return found
        case .announcedCallMissing?:
            guard let announcement = event.announceData?.announcement else { return nil }
            let missed = stateQueue.sync { () -> PendingCall? in
                pending.firstIndex { $0.announcement == announcement }.map { pending.remove(at: $0) }
            }
            if let missed {
                callKit.takeDown(uuid: missed.uuid, reason: .unanswered)
            }
            return nil
        default:
            return nil
        }
    }
}

/// A pushed call not yet matched to its INVITE. `resolve(with:)` takes the
/// `Call` (from `SipralStack.takeIncomingCall`, leaving the answer to
/// CallKit) and binds it into `CallKitBridge` under the existing `UUID`.
public final class PendingCall: @unchecked Sendable {
    public let uuid: UUID
    /// The caller the push named; empty when it named nobody.
    public let callerId: String
    /// The caller's name the push carried, or `nil`.
    public let displayName: String?
    /// The stack's announcement, or `nil` when the INVITE came first.
    public let announcement: SipralHandle?
    private let callKit: CallKitBridge
    private let stateQueue = DispatchQueue(label: "org.sipral.pushkit.pending")
    private var resolvedHandle: SipralHandle?

    init(uuid: UUID, callerId: String, displayName: String?, announcement: SipralHandle?, callKit: CallKitBridge) {
        self.uuid = uuid
        self.callerId = callerId
        self.displayName = displayName
        self.announcement = announcement
        self.callKit = callKit
    }

    /// The matched call handle, bound later by `resolve(with:)`.
    func resolveLater(callHandle: SipralHandle) {
        stateQueue.sync { resolvedHandle = callHandle }
    }

    public var matchedCallHandle: SipralHandle? {
        stateQueue.sync { resolvedHandle }
    }

    public func resolve(with call: Call) {
        callKit.bind(uuid: uuid, to: call)
    }
}
