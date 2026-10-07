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
public final class PushKitBridge: @unchecked Sendable {
    private let callKit: CallKitBridge
    private let stateQueue = DispatchQueue(label: "org.sipral.pushkit.state")
    private var pending: [String: PendingCall] = [:]

    public init(callKit: CallKitBridge) {
        self.callKit = callKit
    }

    /// One push, matched to the account it woke.
    ///
    /// Reports to CallKit, then announces, then refreshes the binding
    /// without waiting (a MUST for a woken UA, RFC 8599 §4.1.3). Keep the
    /// returned `PendingCall` and `resolve(with:)` it when the matching
    /// `IncomingCall` arrives (or at once, if the INVITE came first).
    @discardableResult
    public func handle(push: VoipPush, account: Account) async throws -> PendingCall {
        let uuid = try await callKit.reportIncomingCall(callerId: push.callerId)

        let announced = try account.announce(caller: push.callerId)
        try? account.refreshBinding()

        let pendingCall = PendingCall(uuid: uuid, callerId: push.callerId, callKit: callKit)
        stateQueue.sync { pending[Self.userPart(of: push.callerId)] = pendingCall }

        if let arrivedHandle = announced.call {
            // The INVITE beat the push.
            pendingCall.resolveLater(callHandle: arrivedHandle)
        }
        return pendingCall
    }

    /// Matches an `IncomingCall`/`CallAnnounced` pair to a pending push and
    /// resolves it. Call from any reader of `SipralStack.events()`.
    public func matchIncomingCall(_ event: SipralEvent, on stack: SipralStack) {
        guard event.kind == .incomingCall, let fromUri = event.callData?.fromUri else { return }
        let callerId = Self.userPart(of: fromUri)
        guard let pendingCall = stateQueue.sync(execute: { pending.removeValue(forKey: callerId) }) else { return }
        pendingCall.resolveLater(callHandle: event.call)
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
    private let callKit: CallKitBridge
    private let stateQueue = DispatchQueue(label: "org.sipral.pushkit.pending")
    private var resolvedHandle: SipralHandle?

    init(uuid: UUID, callerId: String, callKit: CallKitBridge) {
        self.uuid = uuid
        self.callerId = callerId
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
