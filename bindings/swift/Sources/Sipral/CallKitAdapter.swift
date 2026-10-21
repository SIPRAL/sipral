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
    private let controller = CXCallController()
    public weak var bridge: CallKitBridge?

    private let stateQueue = DispatchQueue(label: "org.sipral.callkit.adapter")
    /// Calls placed through `startOutgoingCall`, and those of them already
    /// reported connected; guarded by `stateQueue`.
    private var outgoing: Set<UUID> = []
    private var connected: Set<UUID> = []

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

    /// An outgoing call's progress is the system's to show
    /// (`reportOutgoingCall(with:startedConnectingAt:)`); an incoming
    /// call's needs no report, since fulfilling `CXAnswerCallAction` says it.
    public func reportCallConnecting(uuid: UUID) {
        guard isOutgoing(uuid) else { return }
        provider.reportOutgoingCall(with: uuid, startedConnectingAt: nil)
    }

    /// Reported once per outgoing call, on its first confirmation or media.
    public func reportCallConnected(uuid: UUID) {
        let first = stateQueue.sync { outgoing.contains(uuid) && connected.insert(uuid).inserted }
        guard first else { return }
        provider.reportOutgoingCall(with: uuid, connectedAt: nil)
    }

    public func reportCallEnded(uuid: UUID, reason: CallKitBridge.EndReason) {
        stateQueue.sync {
            outgoing.remove(uuid)
            connected.remove(uuid)
        }
        let cxReason: CXCallEndedReason
        switch reason {
        case .localHangup, .remoteHangup: cxReason = .remoteEnded
        case .failed: cxReason = .failed
        case .unanswered: cxReason = .unanswered
        }
        provider.reportCall(with: uuid, endedAt: nil, reason: cxReason)
    }

    private func isOutgoing(_ uuid: UUID) -> Bool {
        stateQueue.sync { outgoing.contains(uuid) }
    }

    /// Asks the system for an outgoing call to `callee`
    /// (`CXStartCallAction`), then runs `dial` (normally
    /// `SipralStack.placeCall`) and binds the call it returns to `bridge`.
    /// Nothing is dialled if the system refuses; a `dial` that throws is
    /// reported failed before the error is rethrown. The call then shows in
    /// the system's call screen and recents, and a cellular call holds it
    /// as it would an incoming one.
    public func startOutgoingCall(callee: String, dial: () throws -> Call) async throws -> (uuid: UUID, call: Call) {
        guard let bridge else { throw CallKitBridgeError.notAttached }
        let uuid = UUID()
        stateQueue.sync { _ = outgoing.insert(uuid) }
        let start = CXStartCallAction(call: uuid, handle: CXHandle(type: .generic, value: callee))
        do {
            try await controller.request(CXTransaction(action: start))
        } catch {
            stateQueue.sync { _ = outgoing.remove(uuid) }
            throw error
        }
        let call: Call
        do {
            call = try dial()
        } catch {
            reportCallEnded(uuid: uuid, reason: .failed)
            throw error
        }
        reportCallConnecting(uuid: uuid)
        bridge.bind(uuid: uuid, to: call)
        return (uuid, call)
    }

    /// Asks the system to perform `action` on a call it shows: a mute, a
    /// hold, digits or the end, from the application's own buttons. The
    /// system's screen and the application's then agree, and the action
    /// comes back through this delegate to `bridge` like one the system
    /// started.
    public func request(_ action: CXCallAction) async throws {
        try await controller.request(CXTransaction(action: action))
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

    /// The call `startOutgoingCall` asked for: the session's category set,
    /// the dialling left to it.
    public func provider(_ provider: CXProvider, perform action: CXStartCallAction) {
        do {
            try Self.configureAudioSession()
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
