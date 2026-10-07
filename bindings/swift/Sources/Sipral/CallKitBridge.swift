// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Foundation

/// The part of `CXProvider` `CallKitBridge` uses, small enough to fake in a
/// test without CallKit. The order of calls matters: a ringing call must be
/// shown before the network session exists (`docs/15-mobile.md`).
public protocol CallKitProviding: AnyObject, Sendable {
    /// `CXProvider.reportNewIncomingCall`. Must be reported before the
    /// system push handler that triggered it returns.
    func reportIncomingCall(uuid: UUID, callerId: String, completion: @Sendable @escaping (Error?) -> Void)
    func reportCallConnecting(uuid: UUID)
    func reportCallConnected(uuid: UUID)
    func reportCallEnded(uuid: UUID, reason: CallKitBridge.EndReason)
}

/// Mirrors `Call` events onto a `CallKitProviding` (the real `CXProvider` in
/// `CallKitAdapter.swift`, or a test recorder).
///
/// A push is reported to the call screen first, then matched to the INVITE
/// that follows (`docs/15-mobile.md`). `PushKitBridge` handles the push;
/// this handles the call from there.
public final class CallKitBridge: @unchecked Sendable {
    public enum EndReason: Sendable {
        case localHangup, remoteHangup, failed, unanswered
    }

    private let provider: any CallKitProviding
    private let stateQueue = DispatchQueue(label: "org.sipral.callkit.state")
    private var callsByUuid: [UUID: Call] = [:]
    private var uuidsByCallHandle: [SipralHandle: UUID] = [:]
    private var watchTasks: [UUID: Task<Void, Never>] = [:]
    private var audiosByUuid: [UUID: CallAudio] = [:]
    private var sessionActive = false
    private var engine: (any CallAudioSessionEngine)?

    public init(provider: any CallKitProviding) {
        self.provider = provider
    }

    /// Reports an incoming call, possibly before its INVITE. The returned
    /// `UUID` is later tied to a `Call` with `bind(uuid:to:)`.
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

    /// Ties a shown `UUID` to its `Call` and mirrors the call's events onto
    /// `provider` while it lasts.
    ///
    /// The bridge takes its own `Call.events()` stream, so the application
    /// loses nothing to it. Earlier events are not replayed, except that an
    /// already-ended call still yields `callEnded`, so it does not stay
    /// ringing on screen.
    public func bind(uuid: UUID, to call: Call) {
        stateQueue.sync {
            callsByUuid[uuid] = call
            uuidsByCallHandle[call.handle] = uuid
        }
        let events = call.events()
        let task = Task { [weak self, provider] in
            for await event in events {
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
            // Finished without `.callEnded`: `Call.close()` finishes streams
            // before the hangup's CALL_ENDED is delivered. CallKit must
            // still be told and the uuid forgotten.
            guard let self else { return }
            provider.reportCallEnded(uuid: uuid, reason: .localHangup)
            self.unbind(uuid: uuid)
        }
        // An ended call's task may already have unbound it; don't keep it.
        stateQueue.sync {
            if callsByUuid[uuid] != nil {
                watchTasks[uuid] = task
            }
        }
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
            audiosByUuid.removeValue(forKey: uuid)
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

    /// Releases or retakes the device at once (the session is moving), and
    /// tells the far end with a re-INVITE.
    public func handleHold(uuid: UUID, onHold: Bool) throws {
        guard let call = call(for: uuid) else { throw CallKitBridgeError.unknownCall(uuid) }
        let audio = audio(for: uuid)
        if onHold {
            audio?.pause(.held)
            try call.hold()
        } else {
            audio?.resume(.held)
            try call.resume()
        }
    }

    /// `CXSetMutedCallAction`: the far end gets silence while muted.
    public func handleMute(uuid: UUID, muted: Bool) throws {
        guard call(for: uuid) != nil else { throw CallKitBridgeError.unknownCall(uuid) }
        audio(for: uuid)?.setMuted(muted)
        try stateQueue.sync { engine }?.setMuted(muted, for: .input)
    }

    // MARK: - the call's audio

    /// Route CallKit's hold, mute and session to `audio`. The device stays
    /// released until `audioSessionActivated()` (Apple's rule) and whenever
    /// the session is deactivated.
    ///
    /// Applied under the same lock as activation, so a concurrent activation
    /// is not lost.
    public func attach(_ audio: CallAudio, to uuid: UUID) {
        stateQueue.sync {
            audiosByUuid[uuid] = audio
            if sessionActive {
                audio.resume(.sessionInactive)
            } else {
                audio.pause(.sessionInactive)
            }
        }
    }

    public func audio(for uuid: UUID) -> CallAudio? {
        stateQueue.sync { audiosByUuid[uuid] }
    }

    /// Let the library engine (`AudioMode.device(activation: .manual)`)
    /// follow CallKit: `didActivate` opens the devices, `didDeactivate` and
    /// a reset close them (calls stay attached), mute mutes the microphone.
    /// No `CallAudio` is attached then. If already active, devices open now.
    public func drive(_ engine: any CallAudioSessionEngine) throws {
        let active = stateQueue.sync { () -> Bool in
            self.engine = engine
            return sessionActive
        }
        if active {
            try engine.activate()
        }
    }

    /// `provider(_:didActivate:)`: attached devices (or the engine) open.
    public func audioSessionActivated() {
        let engine = stateQueue.sync { () -> (any CallAudioSessionEngine)? in
            sessionActive = true
            for audio in audiosByUuid.values {
                audio.resume(.sessionInactive)
            }
            return self.engine
        }
        try? engine?.activate()
    }

    /// `provider(_:didDeactivate:)`: attached devices (or the engine) close.
    public func audioSessionDeactivated() {
        let engine = stateQueue.sync { () -> (any CallAudioSessionEngine)? in
            sessionActive = false
            for audio in audiosByUuid.values {
                audio.pause(.sessionInactive)
            }
            return self.engine
        }
        try? engine?.deactivate()
    }

    /// `providerDidReset(_:)`: CallKit forgot every call, so each is hung up
    /// here too rather than left running unseen.
    public func providerDidReset() {
        let (calls, audios, engine) = stateQueue.sync { () -> ([Call], [CallAudio], (any CallAudioSessionEngine)?) in
            sessionActive = false
            return (Array(callsByUuid.values), Array(audiosByUuid.values), self.engine)
        }
        for audio in audios {
            audio.pause(.sessionInactive)
        }
        try? engine?.deactivate()
        for call in calls {
            try? call.hangup()
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
