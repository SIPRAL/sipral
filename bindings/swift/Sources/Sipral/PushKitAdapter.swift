// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

// Same reasoning as `CallKitAdapter.swift`: `PushKit` is importable on plain
// macOS, but every type in it is unavailable there.
#if canImport(PushKit) && os(iOS)
import PushKit
import Foundation

/// The `PKPushRegistry` side, iOS only; the logic is in `PushKitBridge`,
/// which is testable without a device.
///
/// Every VoIP push is reported to CallKit, as iOS requires of an
/// application that wants to keep receiving them: one whose payload names
/// the caller under `caller` runs the "C2" sequence on the account
/// `account` returns, and any other, or one that arrives with no account,
/// is reported and ended at once.
public final class PushKitAdapter: NSObject, PKPushRegistryDelegate, @unchecked Sendable {
    private let registry: PKPushRegistry
    private let bridge: PushKitBridge
    private let account: @Sendable () -> Account?

    /// The VoIP token, as bytes, each time PushKit issues one, and `nil`
    /// when it is invalidated: what `SipralPush.apnsVoip` puts in
    /// `pn-prid`. Called on the registry's queue; set it before that
    /// queue next runs.
    public var tokenChanged: (@Sendable ([UInt8]?) -> Void)?

    /// Every push, once it has been reported: the call shown and waiting
    /// for its INVITE, or `nil` when it could not be used.
    public var received: (@Sendable (PendingCall?) -> Void)?

    /// The account is looked up on every push, so one added after launch,
    /// or none at all, is what the push meets.
    public init(bridge: PushKitBridge, queue: DispatchQueue = .main, account: @escaping @Sendable () -> Account?) {
        self.bridge = bridge
        self.account = account
        self.registry = PKPushRegistry(queue: queue)
        super.init()
        registry.delegate = self
        registry.desiredPushTypes = [.voIP]
    }

    public convenience init(bridge: PushKitBridge, account: Account, queue: DispatchQueue = .main) {
        self.init(bridge: bridge, queue: queue) { account }
    }

    /// The current VoIP token, if PushKit has issued one.
    public var token: [UInt8]? {
        registry.pushToken(for: .voIP).map { Array($0) }
    }

    public func pushRegistry(
        _ registry: PKPushRegistry, didUpdate pushCredentials: PKPushCredentials, for type: PKPushType
    ) {
        guard type == .voIP else { return }
        tokenChanged?(Array(pushCredentials.token))
    }

    public func pushRegistry(_ registry: PKPushRegistry, didInvalidatePushTokenFor type: PKPushType) {
        guard type == .voIP else { return }
        tokenChanged?(nil)
    }

    public func pushRegistry(
        _ registry: PKPushRegistry,
        didReceiveIncomingPushWith payload: PKPushPayload,
        for type: PKPushType,
        completion: @escaping () -> Void
    ) {
        guard type == .voIP else {
            completion()
            return
        }
        let callerId = payload.dictionaryPayload["caller"] as? String
        let callId = payload.dictionaryPayload["call-id"] as? String
        let account = self.account()
        let bridge = self.bridge
        let received = self.received
        // The deadline is met by the CallKit report, the first thing either
        // path does, not by this completion handler.
        Task {
            if let callerId, let account {
                let pending = try? await bridge.handle(push: VoipPush(callerId: callerId, callId: callId), account: account)
                received?(pending)
            } else {
                await bridge.reportUnusable(callerId: callerId)
                received?(nil)
            }
            completion()
        }
    }
}
#endif
