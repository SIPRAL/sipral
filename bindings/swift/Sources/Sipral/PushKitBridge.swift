// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Foundation

/// The part of a VoIP push `PushKitBridge` needs, so it runs without PushKit
/// (absent on macOS and Linux).
public struct VoipPush: Sendable {
    /// The caller's URI, matched against the INVITE's `From` by account,
    /// user and host, unescaped (`docs/15-mobile.md`).
    public let callerId: String

    public init(callerId: String) {
        self.callerId = callerId
    }
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
    /// already on screen, because its INVITE came first and was shown, ends
    /// the second screen at once.
    @discardableResult
    public func handle(push: VoipPush, account: Account) async throws -> PendingCall {
        let uuid = try await callKit.reportIncomingCall(callerId: push.callerId)

        let announced: (announcement: SipralHandle?, call: SipralHandle?)
        do {
            announced = try account.announce(caller: push.callerId)
        } catch {
            callKit.endShown(uuid: uuid, reason: .failed)
            throw error
        }
        try? account.refreshBinding()

        let pendingCall = PendingCall(
            uuid: uuid, callerId: push.callerId, announcement: announced.announcement, callKit: callKit
        )
        if let arrivedHandle = announced.call {
            // The INVITE beat the push.
            pendingCall.resolveLater(callHandle: arrivedHandle)
            if callKit.uuid(forCallHandle: arrivedHandle) != nil {
                callKit.endShown(uuid: uuid, reason: .failed)
                return pendingCall
            }
        }
        stateQueue.sync { pending.append(pendingCall) }
        return pendingCall
    }

    /// A push that names no caller, or arrives with no account to announce
    /// it on: PushKit still requires a call reported for it, so one is,
    /// and ended at once as failed.
    public func reportUnusable(callerId: String?) async {
        guard let uuid = try? await callKit.reportIncomingCall(callerId: callerId ?? "Unknown") else { return }
        callKit.endShown(uuid: uuid, reason: .failed)
    }

    /// Hand every event from `SipralStack.events()` here; three matter.
    ///
    /// `callAnnounced` records which announcement the stack matched a call
    /// to. `incomingCall` takes the push shown for it and returns it, to be
    /// `resolve(with:)`d with the `Call` from `SipralStack.takeIncomingCall`;
    /// `nil` means no push announced this call, so the application shows
    /// it itself. A call the stack matched is found by its announcement,
    /// any other by the caller's user part, oldest push first.
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
            let caller = event.callData?.fromUri.map(Self.userPart(of:))
            let found = stateQueue.sync { () -> PendingCall? in
                let announcement = announcedCalls.removeValue(forKey: event.call)
                let index = pending.firstIndex { $0.matchedCallHandle == event.call }
                    ?? announcement.flatMap { named in pending.firstIndex { $0.announcement == named } }
                    ?? caller.flatMap { user in pending.firstIndex { Self.userPart(of: $0.callerId) == user } }
                return index.map { pending.remove(at: $0) }
            }
            found?.resolveLater(callHandle: event.call)
            return found
        case .announcedCallMissing?:
            guard let announcement = event.announceData?.announcement else { return nil }
            let missed = stateQueue.sync { () -> PendingCall? in
                pending.firstIndex { $0.announcement == announcement }.map { pending.remove(at: $0) }
            }
            if let missed {
                callKit.endShown(uuid: missed.uuid, reason: .unanswered)
            }
            return nil
        default:
            return nil
        }
    }

    private static func userPart(of uri: String) -> String {
        guard let colon = uri.firstIndex(of: ":") else { return uri }
        let rest = uri[uri.index(after: colon)...]
        guard let at = rest.firstIndex(of: "@") else { return String(rest) }
        return String(rest[rest.startIndex..<at])
    }
}

/// A pushed call not yet matched to its INVITE. `resolve(with:)` takes the
/// `Call` (from `SipralStack.takeIncomingCall`, leaving the answer to
/// CallKit) and binds it into `CallKitBridge` under the existing `UUID`.
public final class PendingCall: @unchecked Sendable {
    public let uuid: UUID
    public let callerId: String
    /// The stack's announcement, or `nil` when the INVITE came first.
    public let announcement: SipralHandle?
    private let callKit: CallKitBridge
    private let stateQueue = DispatchQueue(label: "org.sipral.pushkit.pending")
    private var resolvedHandle: SipralHandle?

    init(uuid: UUID, callerId: String, announcement: SipralHandle?, callKit: CallKitBridge) {
        self.uuid = uuid
        self.callerId = callerId
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
