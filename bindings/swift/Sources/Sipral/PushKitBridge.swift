// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import Foundation

/// What `PushKitBridge` reads out of a VoIP push, in place of a real
/// `PKPushPayload` -- just enough to run `docs/15-mobile.md`'s "C2" sequence
/// without `PushKit`, which does not exist on macOS or Linux at all.
public struct VoipPush: Sendable {
    /// The caller's URI, as `Account.announce` (`sipral_account_announce`)
    /// requires and as the `From` URI the far end will place this call with
    /// -- matched the way `docs/15-mobile.md`, "The matching rule"
    /// describes: same account, same user and host, unescaped.
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
/// The first two steps happen here, in `handle(push:account:)`, in that
/// order and before it returns -- a VoIP push gives the process one run
/// loop to raise the call screen, and missing that deadline gets the
/// application's future wake-ups stopped. The last two are `sipral-ua`'s
/// own job once `Account.announce` has told it about the push
/// (`UaEvent::CallAnnounced`/`IncomingCall`, paired); this bridge's own
/// remaining job is handing the `Call` off to `CallKitBridge` once that
/// resolves, through `PendingCall.resolve(with:)`.
public final class PushKitBridge: @unchecked Sendable {
    private let callKit: CallKitBridge
    private let stateQueue = DispatchQueue(label: "org.sipral.pushkit.state")
    private var pending: [String: PendingCall] = [:]

    public init(callKit: CallKitBridge) {
        self.callKit = callKit
    }

    /// One push, matched to the account it woke.
    ///
    /// Reports to CallKit first, then calls `Account.announce`, then
    /// `Account.refreshBinding` -- RFC 8599 §4.1.3 makes the refresh a MUST
    /// for a woken UA, and it is not waited for (`docs/15-mobile.md`, "The
    /// binding is refreshed at once"). Returns a `PendingCall` the caller
    /// keeps: `resolve(with:)` on it once `sipral-ua` reports the matching
    /// `IncomingCall` (or `Announced::Arrived` came back from `announce`
    /// itself, when the INVITE beat the push) hands the `Call` to
    /// `CallKitBridge` and marks the CallKit-reported call connecting.
    @discardableResult
    public func handle(push: VoipPush, account: Account) async throws -> PendingCall {
        let uuid = try await callKit.reportIncomingCall(callerId: push.callerId)

        let announced = try account.announce(caller: push.callerId)
        try? account.refreshBinding()

        let pendingCall = PendingCall(uuid: uuid, callerId: push.callerId, callKit: callKit)
        stateQueue.sync { pending[Self.userPart(of: push.callerId)] = pendingCall }

        if let arrivedHandle = announced.call {
            // `Announced::Arrived`: the INVITE beat the push. There is
            // nothing further to wait for.
            pendingCall.resolveLater(callHandle: arrivedHandle)
        }
        return pendingCall
    }

    /// Matches an `IncomingCall`/`CallAnnounced` pair off `stack.events()` to
    /// a still-pending push and resolves it. Call this from whatever reads
    /// `SipralStack.events()` for the application's account -- a loop of its
    /// own is as good as the application's main one, since every reader of
    /// that stream sees every event.
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

/// The call a `VoipPush` announced, before `sipral-ua` has matched an
/// INVITE to it. `resolve(with:)` hands the real `Call` over once the
/// application has built one (through `SipralStack.takeIncomingCall`, after
/// reading the matching `IncomingCall` off `stack.events()`, so that the
/// answer is left to CallKit's `CXAnswerCallAction`), and binds it
/// into `CallKitBridge` under the same `UUID` the system already knows.
/// The application can go on reading that `Call`'s own `events()` once it
/// is bound: the bridge takes a stream of its own.
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

    /// Records which call handle this push turned out to be, for
    /// `resolve(with:)` to bind once the application has a `Call` object
    /// for it.
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
