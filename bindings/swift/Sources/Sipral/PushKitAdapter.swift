// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

// Same reasoning as `CallKitAdapter.swift`: `PushKit` is importable on plain
// macOS, but every type in it is unavailable there.
#if canImport(PushKit) && os(iOS)
import PushKit
import Foundation

/// The real `PKPushRegistry`-backed half of `docs/15-mobile.md`'s "C2"
/// sequence. Only where `PushKit` actually works -- iOS, never plain macOS
/// or Linux -- which is why the sequence itself lives in `PushKitBridge`,
/// tested through `VoipPush` and a recording `CallKitProviding` with no
/// device involved.
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
        // The application's own job from here: hand `pushCredentials.token`
        // to its server, so a proxy implementing RFC 8599's proxy half can
        // reach this device (`docs/15-mobile.md`, "Who sends the push").
        // The credentials never belong on the device either way, and this
        // package has no server to hand them to.
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
        // `PushKitBridge.handle` reports to CallKit as its very first
        // `await`, before `Account.announce` or anything else -- the
        // deadline `docs/15-mobile.md` opens with is about that report,
        // not about this completion handler.
        Task {
            _ = try? await bridge.handle(push: VoipPush(callerId: callerId), account: account)
            completion()
        }
    }
}
#endif
