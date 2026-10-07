// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Foundation

/// The part of LiveCommunicationKit's `ConversationManager` that
/// `LiveCommunicationBridge` uses, small enough to fake in a test without
/// the framework. The real one is `LiveCommunicationAdapter`.
public protocol LiveCommunicationProviding: AnyObject, Sendable {
    /// `reportNewIncomingConversation(uuid:update:)`. Must be reported
    /// before the system push handler that triggered it returns.
    func reportIncomingConversation(uuid: UUID, callerId: String) async throws
    /// Performs a `StartConversationAction`: the system shows the call and
    /// may refuse it (another call it cannot hold, a restriction).
    func requestOutgoingConversation(uuid: UUID, callee: String) async throws
    func reportConversationConnecting(uuid: UUID)
    func reportConversationConnected(uuid: UUID)
    func reportConversationEnded(uuid: UUID, reason: CallKitBridge.EndReason)
}

/// Mirrors `Call` events onto a `LiveCommunicationProviding`, and routes the
/// system's join, end, mute, pause and tone actions to the bound `Call`.
///
/// The application chooses this or `CallKitBridge`, never both for one
/// call. The call handling, audio-session and reset rules are
/// `CallKitBridge`'s own, which this bridge runs underneath, so both system
/// call services behave the same way; this one adds outgoing calls.
public final class LiveCommunicationBridge: @unchecked Sendable {
    private let provider: any LiveCommunicationProviding
    private let calls: CallKitBridge

    public init(provider: any LiveCommunicationProviding) {
        self.provider = provider
        calls = CallKitBridge(provider: ConversationReporter(provider: provider))
    }

    /// Reports an incoming call, possibly before its INVITE. The returned
    /// `UUID` is later tied to a `Call` with `bind(uuid:to:)`.
    @discardableResult
    public func reportIncomingCall(callerId: String) async throws -> UUID {
        let uuid = UUID()
        try await provider.reportIncomingConversation(uuid: uuid, callerId: callerId)
        return uuid
    }

    /// Asks the system for an outgoing call to `callee`, then runs `dial`
    /// (normally `SipralStack.placeCall`) and binds the call it returns.
    /// Nothing is dialled if the system refuses; a `dial` that throws is
    /// reported to the system as a failed call before the error is rethrown.
    public func startOutgoingCall(callee: String, dial: () throws -> Call) async throws -> (uuid: UUID, call: Call) {
        let uuid = UUID()
        try await provider.requestOutgoingConversation(uuid: uuid, callee: callee)
        let call: Call
        do {
            call = try dial()
        } catch {
            provider.reportConversationEnded(uuid: uuid, reason: .failed)
            throw error
        }
        provider.reportConversationConnecting(uuid: uuid)
        calls.bind(uuid: uuid, to: call)
        return (uuid, call)
    }

    /// Ties a shown `UUID` to its `Call` and mirrors the call's events onto
    /// the provider while it lasts (`CallKitBridge.bind(uuid:to:)`).
    public func bind(uuid: UUID, to call: Call) {
        calls.bind(uuid: uuid, to: call)
    }

    public func call(for uuid: UUID) -> Call? {
        calls.call(for: uuid)
    }

    public func uuid(forCallHandle handle: SipralHandle) -> UUID? {
        calls.uuid(forCallHandle: handle)
    }

    // MARK: - actions the system asks for (ConversationManagerDelegate forwards here)

    /// `JoinConversationAction`: answers the ringing call.
    public func handleJoin(uuid: UUID) throws {
        try calls.handleAnswer(uuid: uuid)
    }

    /// `EndConversationAction`.
    public func handleEnd(uuid: UUID) throws {
        try calls.handleEnd(uuid: uuid)
    }

    /// `PauseConversationAction`: the device let go at once, the far end
    /// held with a re-INVITE; the reverse on resume.
    public func handlePause(uuid: UUID, paused: Bool) throws {
        try calls.handleHold(uuid: uuid, onHold: paused)
    }

    /// `MuteConversationAction`: the far end gets silence while muted.
    public func handleMute(uuid: UUID, muted: Bool) throws {
        try calls.handleMute(uuid: uuid, muted: muted)
    }

    /// `PlayToneAction`.
    public func handleTone(uuid: UUID, digits: String) throws {
        try calls.handleDtmf(uuid: uuid, digits: digits)
    }

    // MARK: - the call's audio

    /// `CallKitBridge.attach(_:to:)`: the device stays released until the
    /// system activates the audio session.
    public func attach(_ audio: CallAudio, to uuid: UUID) {
        calls.attach(audio, to: uuid)
    }

    public func audio(for uuid: UUID) -> CallAudio? {
        calls.audio(for: uuid)
    }

    /// `CallKitBridge.drive(_:)`: the library engine in
    /// `AudioMode.device(activation: .manual)` opens and closes with the
    /// system's audio session.
    public func drive(_ engine: any CallAudioSessionEngine) throws {
        try calls.drive(engine)
    }

    /// `conversationManager(_:didActivate:)`.
    public func audioSessionActivated() {
        calls.audioSessionActivated()
    }

    /// `conversationManager(_:didDeactivate:)`.
    public func audioSessionDeactivated() {
        calls.audioSessionDeactivated()
    }

    /// `conversationManagerDidReset(_:)`: every call hung up, rather than
    /// left running where the system no longer shows it.
    public func managerDidReset() {
        calls.providerDidReset()
    }
}

/// Lets `CallKitBridge` report through a `LiveCommunicationProviding`.
private final class ConversationReporter: CallKitProviding, @unchecked Sendable {
    private let provider: any LiveCommunicationProviding

    init(provider: any LiveCommunicationProviding) {
        self.provider = provider
    }

    func reportIncomingCall(uuid: UUID, callerId: String, completion: @Sendable @escaping (Error?) -> Void) {
        let provider = provider
        Task {
            do {
                try await provider.reportIncomingConversation(uuid: uuid, callerId: callerId)
                completion(nil)
            } catch {
                completion(error)
            }
        }
    }

    func reportCallConnecting(uuid: UUID) {
        provider.reportConversationConnecting(uuid: uuid)
    }

    func reportCallConnected(uuid: UUID) {
        provider.reportConversationConnected(uuid: uuid)
    }

    func reportCallEnded(uuid: UUID, reason: CallKitBridge.EndReason) {
        provider.reportConversationEnded(uuid: uuid, reason: reason)
    }
}
