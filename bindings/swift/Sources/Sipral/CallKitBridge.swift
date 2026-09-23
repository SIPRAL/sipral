// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import Foundation

/// The slice of `CXProvider` `CallKitBridge` needs, small enough to fake in
/// a test that carries no device and no `CallKit` framework at all.
///
/// `docs/15-mobile.md`'s whole point is that **the application must present
/// a ringing call before the network session exists** -- so the sequence
/// this protocol's methods are called in is the part worth testing, and
/// testing it does not need a real `CXProvider` to report to, only
/// something that records what it was told.
public protocol CallKitProviding: AnyObject, Sendable {
    /// `CXProvider.reportNewIncomingCall`. Must be reported before the
    /// system push handler that triggered it returns.
    func reportIncomingCall(uuid: UUID, callerId: String, completion: @Sendable @escaping (Error?) -> Void)
    func reportCallConnecting(uuid: UUID)
    func reportCallConnected(uuid: UUID)
    func reportCallEnded(uuid: UUID, reason: CallKitBridge.EndReason)
}

/// Bridges `SipralStack`/`Call` events onto whatever conforms to
/// `CallKitProviding` -- the real `CXProvider` on iOS, behind
/// `#if canImport(CallKit)` in `CallKitAdapter.swift`, or a recorder in a
/// test.
///
/// `docs/15-mobile.md`, "C2": a call is announced out of band -- the push
/// arrives, this end reports it to the system call screen, *then* asks
/// `sipral-ua` to match the INVITE that follows. `CallKitBridge` owns the
/// second half, once a `Call` handle exists or the announcement is still
/// waiting; `PushKitBridge` owns getting from a push to that point.
public final class CallKitBridge: @unchecked Sendable {
    public enum EndReason: Sendable {
        case localHangup, remoteHangup, failed, unanswered
    }

    private let provider: any CallKitProviding
    private let stateQueue = DispatchQueue(label: "org.sipral.callkit.state")
    private var callsByUuid: [UUID: Call] = [:]
    private var uuidsByCallHandle: [SipralHandle: UUID] = [:]
    private var watchTasks: [UUID: Task<Void, Never>] = [:]

    public init(provider: any CallKitProviding) {
        self.provider = provider
    }

    /// Reports an incoming call to the system before the INVITE that will
    /// confirm it has necessarily arrived. Returns the `UUID` CallKit now
    /// knows this call by, matched to a `Call` later by `bind(uuid:to:)`
    /// once `sipral-ua` has resolved the announcement
    /// (`docs/15-mobile.md`, "The matching rule").
    @discardableResult
    public func reportIncomingCall(callerId: String) async throws -> UUID {
        let uuid = UUID()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            provider.reportIncomingCall(uuid: uuid, callerId: callerId) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
        return uuid
    }

    /// Ties a `UUID` CallKit is already showing to the `Call` handle
    /// `sipral-ua` resolved it to, and starts mirroring that call's own
    /// events onto `provider` -- ringing, connected, ended -- for as long
    /// as the call lasts.
    public func bind(uuid: UUID, to call: Call) {
        stateQueue.sync {
            callsByUuid[uuid] = call
            uuidsByCallHandle[call.handle] = uuid
        }
        let task = Task { [weak self, provider] in
            for await event in call.events {
                guard let self else { return }
                switch event.kind {
                case .callConfirmed?, .mediaStarted?:
                    provider.reportCallConnected(uuid: uuid)
                case .callProgress?:
                    provider.reportCallConnecting(uuid: uuid)
                case .callEnded?:
                    let reason = Self.endReason(for: event.callData?.endReason)
                    provider.reportCallEnded(uuid: uuid, reason: reason)
                    self.unbind(uuid: uuid)
                    return
                default:
                    break
                }
            }
        }
        stateQueue.sync { watchTasks[uuid] = task }
    }

    public func call(for uuid: UUID) -> Call? {
        stateQueue.sync { callsByUuid[uuid] }
    }

    public func uuid(forCallHandle handle: SipralHandle) -> UUID? {
        stateQueue.sync { uuidsByCallHandle[handle] }
    }

    private func unbind(uuid: UUID) {
        stateQueue.sync {
            if let call = callsByUuid.removeValue(forKey: uuid) {
                uuidsByCallHandle.removeValue(forKey: call.handle)
            }
            watchTasks.removeValue(forKey: uuid)?.cancel()
        }
    }

    private static func endReason(for reason: SipralCallEndReason?) -> EndReason {
        switch reason {
        case .some(.localHangup): return .localHangup
        case .some(.remoteHangup), .some(.refused): return .remoteHangup
        case .some(.cancelled), .some(.unreachable), .some(.forkLost), .some(.abandoned), .some(.expired):
            return .failed
        default:
            return .unanswered
        }
    }

    // MARK: - actions CallKit asks for (CXProviderDelegate forwards here)

    public func handleAnswer(uuid: UUID) throws {
        guard let call = call(for: uuid) else { throw CallKitBridgeError.unknownCall(uuid) }
        try call.answer()
    }

    public func handleEnd(uuid: UUID) throws {
        guard let call = call(for: uuid) else { throw CallKitBridgeError.unknownCall(uuid) }
        try call.hangup()
    }

    public func handleHold(uuid: UUID, onHold: Bool) throws {
        guard let call = call(for: uuid) else { throw CallKitBridgeError.unknownCall(uuid) }
        if onHold {
            try call.hold()
        } else {
            try call.resume()
        }
    }

    public func handleDtmf(uuid: UUID, digits: String) throws {
        guard let call = call(for: uuid) else { throw CallKitBridgeError.unknownCall(uuid) }
        try call.sendDtmf(digits)
    }
}

public enum CallKitBridgeError: Error, Sendable {
    case unknownCall(UUID)
}
