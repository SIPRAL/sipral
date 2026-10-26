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
/// Each VoIP push's payload goes through `decoder` first, by default the
/// clear `caller`, `call-id` and `name` (`VoipPushFields(clear:)`); an
/// application whose push carries a sealed box opens it there. Every push
/// the system says must be reported is reported to CallKit, as iOS requires
/// of an application that wants to keep receiving them: one whose fields name
/// a caller runs the "C2" sequence on the account `account` returns, and
/// any other, or one that arrives with no account, is reported and ended at
/// once (`PushKitBridge.receive(_:mustReport:account:)`).
///
/// From iOS 26.4 PushKit also hands over a push with `PKVoIPPushMetadata`
/// (`pushRegistry(_:didReceiveIncomingVoIPPushWith:metadata:withCompletionHandler:)`),
/// which this adapter implements beside the older method. A push whose
/// `mustReport` is false (the application in the foreground or already in
/// a call, or the push delivered late) is not shown: the binding is
/// refreshed and `notShown` is told.
public final class PushKitAdapter: NSObject, PKPushRegistryDelegate, @unchecked Sendable {
    private let registry: PKPushRegistry
    private let bridge: PushKitBridge
    private let account: @Sendable () -> Account?
    private let decoder: VoipPushDecoder

    /// The VoIP token, as bytes, each time PushKit issues one, and `nil`
    /// when it is invalidated: what `SipralPush.apnsVoip` puts in
    /// `pn-prid`. Called on the registry's queue; set it before that
    /// queue next runs.
    public var tokenChanged: (@Sendable ([UInt8]?) -> Void)?

    /// Every push, once it has been reported: the call shown and waiting
    /// for its INVITE, or `nil` when it could not be used.
    public var received: (@Sendable (PendingCall?) -> Void)?

    /// Every push the system said need not be reported, which was not shown:
    /// what it named, or `nil` when it named no caller. Its INVITE, if one
    /// comes, is an ordinary incoming call.
    public var notShown: (@Sendable (VoipPush?) -> Void)?

    /// The account is looked up on every push, so one added after launch,
    /// or none at all, is what the push meets. `decoder` reads each payload
    /// on `queue`, before the push is reported.
    public init(
        bridge: PushKitBridge, queue: DispatchQueue = .main,
        decoder: @escaping VoipPushDecoder = { VoipPushFields(clear: $0) },
        account: @escaping @Sendable () -> Account?
    ) {
        self.bridge = bridge
        self.account = account
        self.decoder = decoder
        self.registry = PKPushRegistry(queue: queue)
        super.init()
        registry.delegate = self
        registry.desiredPushTypes = [.voIP]
    }

    public convenience init(
        bridge: PushKitBridge, account: Account, queue: DispatchQueue = .main,
        decoder: @escaping VoipPushDecoder = { VoipPushFields(clear: $0) }
    ) {
        self.init(bridge: bridge, queue: queue, decoder: decoder) { account }
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
        take(payload, mustReport: true, completion: completion)
    }

    /// iOS 26.4's delivery, with whether a call must be reported for it.
    @available(iOS 26.4, macCatalyst 26.4, *)
    public func pushRegistry(
        _ registry: PKPushRegistry,
        didReceiveIncomingVoIPPushWith payload: PKPushPayload,
        metadata: PKVoIPPushMetadata,
        withCompletionHandler completion: @escaping () -> Void
    ) {
        take(payload, mustReport: metadata.mustReport, completion: completion)
    }

    private func take(_ payload: PKPushPayload, mustReport: Bool, completion: @escaping () -> Void) {
        let fields = try? decoder(payload.dictionaryPayload)
        let account = self.account()
        let bridge = self.bridge
        let received = self.received
        let notShown = self.notShown
        // The deadline is met by the CallKit report, the first thing a push
        // that must be reported meets, not by this completion handler.
        Task {
            switch await bridge.receive(fields, mustReport: mustReport, account: account) {
            case .shown(let pending): received?(pending)
            case .unusable: received?(nil)
            case .notShown(let push): notShown?(push)
            }
            completion()
        }
    }
}
#endif
