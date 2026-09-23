// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

// `CallKit` is importable on plain macOS too (the module exists in the SDK),
// but every type in it is `API_UNAVAILABLE(macos)`; `canImport` alone would
// let this file compile-fail on a Mac. `os(iOS)` is what actually has
// `CXProvider`, and is also true under Mac Catalyst.
#if canImport(CallKit) && os(iOS)
import CallKit
import Foundation

/// The real `CXProvider`-backed `CallKitProviding`.
///
/// Only where `CallKit` actually works -- iOS and Mac Catalyst, never plain
/// macOS or Linux, which is why `CallKitBridge` itself is written against
/// the `CallKitProviding` protocol and not against this type
/// (`docs/08-ffi.md`/`docs/15-mobile.md`, "Swift" -- "so the core module
/// also builds on Linux").
///
/// Not unit-tested here: it has nothing left to test that `CallKitBridge`'s
/// own tests, against a recording `CallKitProviding`, do not already cover
/// -- what would be tested is `CXProvider` itself, which needs a device or
/// the simulator's telephony stack.
public final class CallKitAdapter: NSObject, CallKitProviding, @unchecked Sendable {
    private let provider: CXProvider
    public weak var bridge: CallKitBridge?

    public init(configuration: CXProviderConfiguration) {
        provider = CXProvider(configuration: configuration)
        super.init()
        provider.setDelegate(self, queue: nil)
    }

    public func reportIncomingCall(uuid: UUID, callerId: String, completion: @Sendable @escaping (Error?) -> Void) {
        let update = CXCallUpdate()
        update.remoteHandle = CXHandle(type: .generic, value: callerId)
        update.hasVideo = false
        provider.reportNewIncomingCall(with: uuid, update: update, completion: completion)
    }

    public func reportCallConnecting(uuid: UUID) {
        // CXProvider has no separate "connecting" report for an incoming
        // call beyond having already reported it; the transition to
        // answered is what CXAnswerCallAction.fulfill() in
        // provider(_:perform: CXAnswerCallAction) tells the system.
    }

    public func reportCallConnected(uuid: UUID) {
        // Likewise implied by fulfilling CXAnswerCallAction for an incoming
        // call; reportOutgoingCall(with:connectedAt:) is for a call this
        // end originated through CXStartCallAction, which this bridge does
        // not place -- SipralStack.placeCall goes straight to sipral-ua.
    }

    public func reportCallEnded(uuid: UUID, reason: CallKitBridge.EndReason) {
        let cxReason: CXCallEndedReason
        switch reason {
        case .localHangup, .remoteHangup: cxReason = .remoteEnded
        case .failed: cxReason = .failed
        case .unanswered: cxReason = .unanswered
        }
        provider.reportCall(with: uuid, endedAt: nil, reason: cxReason)
    }
}

extension CallKitAdapter: CXProviderDelegate {
    public func providerDidReset(_ provider: CXProvider) {}

    public func provider(_ provider: CXProvider, perform action: CXAnswerCallAction) {
        do {
            try bridge?.handleAnswer(uuid: action.callUUID)
            action.fulfill()
        } catch {
            action.fail()
        }
    }

    public func provider(_ provider: CXProvider, perform action: CXEndCallAction) {
        do {
            try bridge?.handleEnd(uuid: action.callUUID)
            action.fulfill()
        } catch {
            action.fail()
        }
    }

    public func provider(_ provider: CXProvider, perform action: CXSetHeldCallAction) {
        do {
            try bridge?.handleHold(uuid: action.callUUID, onHold: action.isOnHold)
            action.fulfill()
        } catch {
            action.fail()
        }
    }

    public func provider(_ provider: CXProvider, perform action: CXPlayDTMFCallAction) {
        do {
            try bridge?.handleDtmf(uuid: action.callUUID, digits: action.digits)
            action.fulfill()
        } catch {
            action.fail()
        }
    }
}
#endif
