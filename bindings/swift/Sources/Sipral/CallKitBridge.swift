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
    /// The same, with the name the screen shows for the caller
    /// (`CXCallUpdate.localizedCallerName`), or `nil` for none. A provider
    /// that has no use for the name gets the call reported without it.
    func reportIncomingCall(
        uuid: UUID, callerId: String, displayName: String?, completion: @Sendable @escaping (Error?) -> Void
    )
    /// The caller's name, for a call already shown without one: the name
    /// its INVITE gave (`CXProvider.reportCall(with:updated:)`). Nothing,
    /// for a provider that shows no names.
    func reportCallerName(uuid: UUID, displayName: String)
    /// The caller itself, for a call shown before anything named it (a push
    /// with no caller): the INVITE's `From` URI, and its name when one is
    /// known. A provider with no use for the URI is given the name alone.
    func reportCaller(uuid: UUID, callerId: String, displayName: String?)
    func reportCallConnecting(uuid: UUID)
    func reportCallConnected(uuid: UUID)
    func reportCallEnded(uuid: UUID, reason: CallKitBridge.EndReason)
}

public extension CallKitProviding {
    func reportIncomingCall(
        uuid: UUID, callerId: String, displayName: String?, completion: @Sendable @escaping (Error?) -> Void
    ) {
        reportIncomingCall(uuid: uuid, callerId: callerId, completion: completion)
    }

    func reportCallerName(uuid: UUID, displayName: String) {}

    func reportCaller(uuid: UUID, callerId: String, displayName: String?) {
        if let displayName {
            reportCallerName(uuid: uuid, displayName: displayName)
        }
    }
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

    /// What the user asked of a call shown before it had a `Call` (a push
    /// rings seconds before its INVITE): applied by `bind(uuid:to:)`.
    private struct Waiting {
        /// Answer was tapped; told how the answer went once it has.
        var answer: (@Sendable (Error?) -> Void)?
        /// End or Decline was tapped, or the answer timed out: the INVITE,
        /// if it comes, is declined.
        var ended = false
    }

    /// Shown and not yet bound; guarded by `stateQueue`.
    private var waiting: [UUID: Waiting] = [:]

    public init(provider: any CallKitProviding) {
        self.provider = provider
    }

    /// Reports an incoming call, possibly before its INVITE. The returned
    /// `UUID` is later tied to a `Call` with `bind(uuid:to:)`; until then an
    /// Answer or End the user taps is kept for it.
    ///
    /// `displayName` is what the screen shows for the caller, beside
    /// `callerId`: from the push, or from the INVITE
    /// (`CallEventData.callerName`) for a call that came without one.
    ///
    /// An `async` call cannot be made from a `PKPushRegistryDelegate`: iOS
    /// checks that a call was reported the moment the delegate method
    /// returns, before any task it started has run, and ends the
    /// application if none was. That caller uses
    /// `reportIncomingCall(callerId:displayName:reported:)`.
    @discardableResult
    public func reportIncomingCall(callerId: String, displayName: String? = nil) async throws -> UUID {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UUID, Error>) in
            reportIncomingCall(callerId: callerId, displayName: displayName) { continuation.resume(with: $0) }
        }
    }

    /// `reportIncomingCall(callerId:displayName:)`, reported to the
    /// provider before this returns, as a PushKit delegate must: the
    /// returned `UUID` is the call's, and `reported` is told, when CallKit
    /// has answered, whether the screen was shown. A screen refused (Do Not
    /// Disturb, a blocked caller) is forgotten before `reported` hears of it.
    @discardableResult
    public func reportIncomingCall(
        callerId: String, displayName: String? = nil, reported: @escaping @Sendable (Result<UUID, Error>) -> Void
    ) -> UUID {
        let uuid = UUID()
        // Kept before the report: the screen can be answered the moment it shows.
        stateQueue.sync { waiting[uuid] = Waiting() }
        provider.reportIncomingCall(uuid: uuid, callerId: callerId, displayName: displayName) { [weak self] error in
            if let error {
                if let self {
                    self.stateQueue.sync { _ = self.waiting.removeValue(forKey: uuid) }
                }
                reported(.failure(error))
            } else {
                reported(.success(uuid))
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
    ///
    /// What the user did before the call existed is done now: an Answer
    /// answers it and is then fulfilled (or failed), an End declines it with
    /// 603 and binds nothing, since its screen is gone and the system was
    /// told. Take the application's own `Call.events()` before binding, to
    /// see what that answer brings.
    public func bind(uuid: UUID, to call: Call) {
        let asked = stateQueue.sync { () -> Waiting? in
            let asked = waiting.removeValue(forKey: uuid)
            if asked?.ended != true {
                callsByUuid[uuid] = call
                uuidsByCallHandle[call.handle] = uuid
            }
            return asked
        }
        if asked?.ended == true {
            // its screen is gone already, and the system was told so
            try? call.reject(code: 603)
            return
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
        if let answered = asked?.answer {
            do {
                try call.answer()
                answered(nil)
            } catch {
                answered(error)
            }
        }
    }

    public func call(for uuid: UUID) -> Call? {
        stateQueue.sync { callsByUuid[uuid] }
    }

    public func uuid(forCallHandle handle: SipralHandle) -> UUID? {
        stateQueue.sync { uuidsByCallHandle[handle] }
    }

    /// Takes a shown call off the screen as `reason`, `.unanswered` unless
    /// told otherwise: for a push the application could not use, or a call
    /// it decided not to ring. The system is told once, with `reason`.
    ///
    /// What waited on the screen settles as `handleEnd(uuid:)` settles it,
    /// with no `CXEndCallAction` needed: a call bound to it is hung up,
    /// an Answer kept for it fails with `.callNeverArrived`, and an INVITE
    /// still to come is declined with 603 when it is bound. Throws
    /// `.unknownCall` for a `uuid` neither shown nor bound.
    public func endShown(uuid: UUID, reason: EndReason = .unanswered) throws {
        if let call = call(for: uuid) {
            // unbound first, so the hangup's end is not reported a second time
            unbind(uuid: uuid)
            try? call.hangup()
            provider.reportCallEnded(uuid: uuid, reason: reason)
            return
        }
        let kept = stateQueue.sync { () -> (known: Bool, answer: (@Sendable (Error?) -> Void)?) in
            guard waiting[uuid] != nil else { return (false, nil) }
            waiting[uuid]?.ended = true
            defer { waiting[uuid]?.answer = nil }
            return (true, waiting[uuid]?.answer)
        }
        guard kept.known else { throw CallKitBridgeError.unknownCall(uuid) }
        kept.answer?(CallKitBridgeError.callNeverArrived(uuid))
        provider.reportCallEnded(uuid: uuid, reason: reason)
    }

    /// Ends a call shown on screen, bound or not, and forgets it: one a push
    /// raised that no INVITE will fill. An Answer kept for it fails.
    func takeDown(uuid: UUID, reason: EndReason) {
        let answer = stateQueue.sync { waiting.removeValue(forKey: uuid)?.answer }
        answer?(CallKitBridgeError.callNeverArrived(uuid))
        provider.reportCallEnded(uuid: uuid, reason: reason)
        unbind(uuid: uuid)
    }

    /// Shows `displayName` for a call already on screen without one.
    func nameCaller(uuid: UUID, displayName: String) {
        provider.reportCallerName(uuid: uuid, displayName: displayName)
    }

    /// Shows who is calling on a screen raised before anything named them.
    func identifyCaller(uuid: UUID, callerId: String, displayName: String?) {
        provider.reportCaller(uuid: uuid, callerId: callerId, displayName: displayName)
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

    /// `CXAnswerCallAction`, for a call that may not have arrived yet.
    ///
    /// A bound call is answered now. A shown one still waiting for its
    /// INVITE keeps the answer: `bind(uuid:to:)` answers it the moment the
    /// INVITE is matched, and `completion` is told then, so the action is
    /// fulfilled only once the call is really answered. It fails with
    /// `.callNeverArrived` when the announcement is refused or goes missing
    /// (`PushKitBridge`), and with `.unknownCall` for a uuid never shown.
    /// The audio session stays CallKit's to activate.
    public func handleAnswer(uuid: UUID, completion: @escaping @Sendable (Error?) -> Void) {
        enum Step { case now(Call), later, unknown }
        let step = stateQueue.sync { () -> Step in
            if let call = callsByUuid[uuid] { return .now(call) }
            guard waiting[uuid] != nil else { return .unknown }
            waiting[uuid]?.answer = completion
            return .later
        }
        switch step {
        case .now(let call):
            do {
                try call.answer()
                completion(nil)
            } catch {
                completion(error)
            }
        case .later:
            break
        case .unknown:
            completion(CallKitBridgeError.unknownCall(uuid))
        }
    }

    /// `CXEndCallAction`. A call shown and not yet arrived is remembered as
    /// declined: its INVITE, if it comes, is answered 603.
    public func handleEnd(uuid: UUID) throws {
        if let call = call(for: uuid) {
            try call.hangup()
            return
        }
        let kept = stateQueue.sync { () -> (known: Bool, answer: (@Sendable (Error?) -> Void)?) in
            guard waiting[uuid] != nil else { return (false, nil) }
            waiting[uuid]?.ended = true
            defer { waiting[uuid]?.answer = nil }
            return (true, waiting[uuid]?.answer)
        }
        guard kept.known else { throw CallKitBridgeError.unknownCall(uuid) }
        kept.answer?(CallKitBridgeError.callNeverArrived(uuid))
    }

    /// CallKit gave up on an Answer still waiting for its INVITE
    /// (`provider(_:timedOutPerforming:)`): the call is ended on screen and
    /// its INVITE, if it comes, declined.
    public func answerTimedOut(uuid: UUID) {
        let waited = stateQueue.sync { () -> Bool in
            guard waiting[uuid] != nil else { return false }
            waiting[uuid]?.answer = nil
            waiting[uuid]?.ended = true
            return true
        }
        if waited {
            provider.reportCallEnded(uuid: uuid, reason: .failed)
        }
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
        let (calls, audios, engine, answers) = stateQueue.sync {
            () -> ([Call], [CallAudio], (any CallAudioSessionEngine)?, [(UUID, @Sendable (Error?) -> Void)]) in
            sessionActive = false
            // Calls still to arrive are declined when they do.
            var answers: [(UUID, @Sendable (Error?) -> Void)] = []
            for uuid in Array(waiting.keys) {
                if let answer = waiting[uuid]?.answer { answers.append((uuid, answer)) }
                waiting[uuid] = Waiting(answer: nil, ended: true)
            }
            return (Array(callsByUuid.values), Array(audiosByUuid.values), self.engine, answers)
        }
        for (uuid, answer) in answers {
            answer(CallKitBridgeError.callNeverArrived(uuid))
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
    /// `CallKitAdapter.startOutgoingCall` with no `bridge` set.
    case notAttached
    /// A call shown for a push whose INVITE never came: the announcement
    /// was refused or went missing, or the user ended it first.
    case callNeverArrived(UUID)
}
