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
    private var audiosByUuid: [UUID: CallAudio] = [:]
    private var sessionActive = false

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
    ///
    /// The bridge reads a `Call.events()` stream of its own, taken here,
    /// before this returns: the application keeps reading the same call's
    /// events alongside it, and misses none to the bridge. Events raised
    /// before `bind` are not replayed, with one exception that matters here
    /// -- a call that has already ended, whose stream still hands over its
    /// `callEnded`, so a call the far end gave up on before it was bound is
    /// still reported ended rather than left ringing on the call screen.
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
            // The stream finished without ever handing over `.callEnded`:
            // `Call.close()` forgets the call and finishes its broadcasts
            // synchronously, ahead of the stack's own asynchronous delivery
            // of the CALL_ENDED that a hangup it just issued will raise
            // (`SipralStack.forgetCall` runs before that event can ever
            // reach `Call.deliver`) -- reachable whenever an application
            // hangs up and closes a bound call without reading its own
            // events() first. CallKit still has to be told, and this uuid
            // still has to be forgotten, or the call screen and this
            // bridge's own bookkeeping would both outlive the call.
            guard let self else { return }
            provider.reportCallEnded(uuid: uuid, reason: .localHangup)
            self.unbind(uuid: uuid)
        }
        // A call that had already ended can be unbound by its own task
        // before this line runs; keeping the task then would keep it for
        // good.
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

    /// Hold or resume, as CallKit asks: the call's device let go (or taken
    /// back) at once, since the system is handing the session to another
    /// call, and the far end told with a re-INVITE.
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

    /// `CXSetMutedCallAction`: the far end is sent silence while muted.
    public func handleMute(uuid: UUID, muted: Bool) throws {
        guard call(for: uuid) != nil else { throw CallKitBridgeError.unknownCall(uuid) }
        audio(for: uuid)?.setMuted(muted)
    }

    // MARK: - the call's audio

    /// Hand `audio` the call CallKit knows as `uuid`: CallKit's hold, mute
    /// and audio session reach it from now on. Until the system has
    /// activated the session (`audioSessionActivated()`) the device stays let
    /// go -- Apple's rule is that call audio starts in `didActivate`, not
    /// before -- and it is let go again whenever the system deactivates it.
    ///
    /// The session's state is applied under the same lock `audioSessionActivated`
    /// and `audioSessionDeactivated` take, so an activation arriving while this
    /// runs is never lost between reading it and applying it.
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

    /// `CXProviderDelegate.provider(_:didActivate:)`: the session is the
    /// calls' now, and every attached call's device is taken back.
    public func audioSessionActivated() {
        stateQueue.sync {
            sessionActive = true
            for audio in audiosByUuid.values {
                audio.resume(.sessionInactive)
            }
        }
    }

    /// `CXProviderDelegate.provider(_:didDeactivate:)`: the system took the
    /// session back -- another call, the calls ending -- and every attached
    /// call's device is let go.
    public func audioSessionDeactivated() {
        stateQueue.sync {
            sessionActive = false
            for audio in audiosByUuid.values {
                audio.pause(.sessionInactive)
            }
        }
    }

    /// `CXProviderDelegate.providerDidReset(_:)`: the system's call service
    /// restarted and every call it was showing is gone from it, so each is
    /// ended here too -- hung up, its device let go -- rather than left
    /// running with no call screen and no audio session.
    public func providerDidReset() {
        let (calls, audios) = stateQueue.sync { () -> ([Call], [CallAudio]) in
            sessionActive = false
            return (Array(callsByUuid.values), Array(audiosByUuid.values))
        }
        for audio in audios {
            audio.pause(.sessionInactive)
        }
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
