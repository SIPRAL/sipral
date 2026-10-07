// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

// LiveCommunicationKit ships in the macOS SDK with every type unavailable;
// `os(iOS)` covers iOS and Mac Catalyst, where it works from 17.4.
#if canImport(LiveCommunicationKit) && os(iOS)
@preconcurrency import AVFoundation
import Foundation
import LiveCommunicationKit

/// The real `ConversationManager`-backed `LiveCommunicationProviding`, an
/// alternative to `CallKitAdapter` for iOS 17.4 and later.
///
/// Not unit-tested: the logic lives in `LiveCommunicationBridge`, tested
/// against a recorder; this is a thin wrapper.
@available(iOS 17.4, macCatalyst 17.4, *)
public final class LiveCommunicationAdapter: ConversationManagerDelegate, LiveCommunicationProviding, @unchecked Sendable {
    private let manager: ConversationManager
    public weak var bridge: LiveCommunicationBridge?

    public init(configuration: ConversationManager.Configuration) {
        manager = ConversationManager(configuration: configuration)
        manager.delegate = self
    }

    /// A configuration for audio-only SIP calls: one call per group, two
    /// groups (a call and the one held for it), generic and number handles.
    public static func audioConfiguration(ringtoneName: String? = nil, iconTemplateImageData: Data? = nil) -> ConversationManager.Configuration {
        ConversationManager.Configuration(
            ringtoneName: ringtoneName,
            iconTemplateImageData: iconTemplateImageData,
            maximumConversationGroups: 2,
            maximumConversationsPerConversationGroup: 1,
            includesConversationInRecents: true,
            supportsVideo: false,
            supportedHandleTypes: [.generic, .phoneNumber]
        )
    }

    /// Configure category and mode only; the system activates the session
    /// (`conversationManager(_:didActivate:)`).
    public static func configureAudioSession(_ session: AVAudioSession = .sharedInstance()) throws {
        try session.setCategory(.playAndRecord, mode: .voiceChat, options: [.allowBluetoothHFP])
    }

    private static func update(for handle: String) -> Conversation.Update {
        let remote = Handle(type: .generic, value: handle)
        return Conversation.Update(
            members: [remote],
            activeRemoteMembers: [remote],
            capabilities: [.pausing, .playingTones]
        )
    }

    // MARK: - LiveCommunicationProviding

    public func reportIncomingConversation(uuid: UUID, callerId: String) async throws {
        try await manager.reportNewIncomingConversation(uuid: uuid, update: Self.update(for: callerId))
    }

    public func requestOutgoingConversation(uuid: UUID, callee: String) async throws {
        let action = StartConversationAction(
            conversationUUID: uuid, handles: [Handle(type: .generic, value: callee)], isVideo: false
        )
        try await manager.perform([action])
    }

    public func reportConversationConnecting(uuid: UUID) {
        report(.conversationStartedConnecting(Date()), for: uuid)
    }

    public func reportConversationConnected(uuid: UUID) {
        report(.conversationConnected(Date()), for: uuid)
    }

    public func reportConversationEnded(uuid: UUID, reason: CallKitBridge.EndReason) {
        let ended: Conversation.EndedReason
        switch reason {
        case .localHangup, .remoteHangup: ended = .remoteEnded
        case .failed: ended = .failed
        case .unanswered: ended = .unanswered
        }
        report(.conversationEnded(Date(), ended), for: uuid)
    }

    /// The system knows a call only by its `Conversation`; one it has
    /// already forgotten (ended from its own screen) has nothing to report.
    private func report(_ event: Conversation.Event, for uuid: UUID) {
        guard let conversation = manager.conversations.first(where: { $0.uuid == uuid }) else { return }
        manager.reportConversationEvent(event, for: conversation)
    }

    // MARK: - ConversationManagerDelegate

    public func conversationManager(_ manager: ConversationManager, conversationChanged conversation: Conversation) {}

    public func conversationManagerDidBegin(_ manager: ConversationManager) {}

    public func conversationManagerDidReset(_ manager: ConversationManager) {
        bridge?.managerDidReset()
    }

    public func conversationManager(_ manager: ConversationManager, perform action: ConversationAction) {
        let uuid = action.conversationUUID
        do {
            switch action {
            case let start as StartConversationAction:
                try Self.configureAudioSession()
                start.fulfill(dateStarted: Date())
            case let join as JoinConversationAction:
                try Self.configureAudioSession()
                try requireBridge().handleJoin(uuid: uuid)
                join.fulfill(dateConnected: Date())
            case let end as EndConversationAction:
                try requireBridge().handleEnd(uuid: uuid)
                end.fulfill(dateEnded: Date())
            case let mute as MuteConversationAction:
                try requireBridge().handleMute(uuid: uuid, muted: mute.isMuted)
                mute.fulfill()
            case let pause as PauseConversationAction:
                try requireBridge().handlePause(uuid: uuid, paused: pause.isPaused)
                pause.fulfill()
            case let tone as PlayToneAction:
                try requireBridge().handleTone(uuid: uuid, digits: tone.digits)
                tone.fulfill()
            default:
                // Merging and unmerging are not offered (`capabilities`).
                action.fail()
            }
        } catch {
            action.fail()
        }
    }

    public func conversationManager(_ manager: ConversationManager, timedOutPerforming action: ConversationAction) {}

    public func conversationManager(_ manager: ConversationManager, didActivate audioSession: AVAudioSession) {
        bridge?.audioSessionActivated()
    }

    public func conversationManager(_ manager: ConversationManager, didDeactivate audioSession: AVAudioSession) {
        bridge?.audioSessionDeactivated()
    }

    private func requireBridge() throws -> LiveCommunicationBridge {
        guard let bridge else { throw LiveCommunicationAdapterError.noBridge }
        return bridge
    }
}

public enum LiveCommunicationAdapterError: Error, Sendable {
    /// An action arrived before `bridge` was set.
    case noBridge
}
#endif
