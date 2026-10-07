// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

// `canImport(CallKit)` is true on macOS, where every type is unavailable;
// `os(iOS)` covers iOS and Mac Catalyst.
#if canImport(CallKit) && os(iOS)
@preconcurrency import AVFoundation
import CallKit
import Foundation

/// The real `CXProvider`-backed `CallKitProviding`.
///
/// iOS and Mac Catalyst only. Not unit-tested: the logic lives in
/// `CallKitBridge`, tested against a recorder; this is a thin wrapper.
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
        // No separate report for an incoming call: fulfilling
        // CXAnswerCallAction tells the system.
    }

    public func reportCallConnected(uuid: UUID) {
        // Likewise; reportOutgoingCall is for CXStartCallAction calls,
        // which this bridge does not place.
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
    public func providerDidReset(_ provider: CXProvider) {
        bridge?.providerDidReset()
    }

    /// Configure category and mode only; with CallKit the system activates
    /// the session (`provider(_:didActivate:)`).
    public static func configureAudioSession(_ session: AVAudioSession = .sharedInstance()) throws {
        try session.setCategory(.playAndRecord, mode: .voiceChat, options: [.allowBluetoothHFP])
    }

    public func provider(_ provider: CXProvider, perform action: CXAnswerCallAction) {
        do {
            try Self.configureAudioSession()
            try bridge?.handleAnswer(uuid: action.callUUID)
            action.fulfill()
        } catch {
            action.fail()
        }
    }

    public func provider(_ provider: CXProvider, didActivate audioSession: AVAudioSession) {
        bridge?.audioSessionActivated()
    }

    public func provider(_ provider: CXProvider, didDeactivate audioSession: AVAudioSession) {
        bridge?.audioSessionDeactivated()
    }

    public func provider(_ provider: CXProvider, perform action: CXSetMutedCallAction) {
        do {
            try bridge?.handleMute(uuid: action.callUUID, muted: action.isMuted)
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
