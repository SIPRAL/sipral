// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

// Same reasoning as `CallKitAdapter.swift`: `PushKit` is importable on plain
// macOS, but every type in it is unavailable there.
#if canImport(PushKit) && os(iOS)
import PushKit
import Foundation

/// The `PKPushRegistry` side, iOS only; the logic is in `PushKitBridge`,
/// which is testable without a device.
public final class PushKitAdapter: NSObject, PKPushRegistryDelegate, @unchecked Sendable {
    private let registry: PKPushRegistry
    private let bridge: PushKitBridge
    private let account: Account

    public init(bridge: PushKitBridge, account: Account, queue: DispatchQueue = .main) {
        self.bridge = bridge
        self.account = account
        self.registry = PKPushRegistry(queue: queue)
        super.init()
        registry.delegate = self
        registry.desiredPushTypes = [.voIP]
    }

    public func pushRegistry(
        _ registry: PKPushRegistry, didUpdate pushCredentials: PKPushCredentials, for type: PKPushType
    ) {
        // The application sends `pushCredentials.token` to its own server
        // (RFC 8599 proxy side); this package has none.
    }

    public func pushRegistry(_ registry: PKPushRegistry, didInvalidatePushTokenFor type: PKPushType) {}

    public func pushRegistry(
        _ registry: PKPushRegistry,
        didReceiveIncomingPushWith payload: PKPushPayload,
        for type: PKPushType,
        completion: @escaping () -> Void
    ) {
        guard type == .voIP, let callerId = payload.dictionaryPayload["caller"] as? String else {
            completion()
            return
        }
        // The deadline is met by `handle`'s first step, the CallKit report,
        // not by this completion handler.
        Task {
            _ = try? await bridge.handle(push: VoipPush(callerId: callerId), account: account)
            completion()
        }
    }
}
#endif
