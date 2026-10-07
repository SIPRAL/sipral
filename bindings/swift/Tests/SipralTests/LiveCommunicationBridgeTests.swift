// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import XCTest
@testable import Sipral

/// Records what it was told, standing in for LiveCommunicationKit's
/// `ConversationManager`, which does not exist on macOS or Linux.
final actor RecordingConversations: LiveCommunicationProviding {
    enum Entry: Equatable {
        case incoming(UUID, String)
        case outgoing(UUID, String)
        case connecting(UUID)
        case connected(UUID)
        case ended(UUID, CallKitBridge.EndReason)
    }

    struct Refused: Error {}

    private(set) var entries: [Entry] = []
    private var refuseNext = false

    func setRefuseNext(_ refuse: Bool) { refuseNext = refuse }

    func reportIncomingConversation(uuid: UUID, callerId: String) async throws {
        try consumeRefusal()
        entries.append(.incoming(uuid, callerId))
    }

    func requestOutgoingConversation(uuid: UUID, callee: String) async throws {
        try consumeRefusal()
        entries.append(.outgoing(uuid, callee))
    }

    nonisolated func reportConversationConnecting(uuid: UUID) {
        Task { await self.append(.connecting(uuid)) }
    }

    nonisolated func reportConversationConnected(uuid: UUID) {
        Task { await self.append(.connected(uuid)) }
    }

    nonisolated func reportConversationEnded(uuid: UUID, reason: CallKitBridge.EndReason) {
        Task { await self.append(.ended(uuid, reason)) }
    }

    private func append(_ entry: Entry) { entries.append(entry) }

    private func consumeRefusal() throws {
        if refuseNext {
            refuseNext = false
            throw Refused()
        }
    }
}

final class LiveCommunicationBridgeTests: XCTestCase {
    func testIncomingCallIsReportedBeforeReturning() async throws {
        let provider = RecordingConversations()
        let bridge = LiveCommunicationBridge(provider: provider)

        let uuid = try await bridge.reportIncomingCall(callerId: "alice")

        let entries = await provider.entries
        XCTAssertEqual(entries, [.incoming(uuid, "alice")])
    }

    func testRefusedIncomingReportThrows() async {
        let provider = RecordingConversations()
        await provider.setRefuseNext(true)
        let bridge = LiveCommunicationBridge(provider: provider)

        do {
            _ = try await bridge.reportIncomingCall(callerId: "alice")
            XCTFail("expected the refusal")
        } catch {
            XCTAssertTrue(error is RecordingConversations.Refused)
        }
    }

    func testNothingIsDialledWhenTheSystemRefusesTheOutgoingCall() async {
        let provider = RecordingConversations()
        await provider.setRefuseNext(true)
        let bridge = LiveCommunicationBridge(provider: provider)
        var dialled = false

        do {
            _ = try await bridge.startOutgoingCall(callee: "sip:bob@sipral.invalid") {
                dialled = true
                throw RecordingConversations.Refused()
            }
            XCTFail("expected the refusal")
        } catch {
            XCTAssertTrue(error is RecordingConversations.Refused)
        }
        XCTAssertFalse(dialled)
        let entries = await provider.entries
        XCTAssertEqual(entries, [])
    }

    func testAFailedDialIsReportedEndedAsFailed() async throws {
        struct DialFailed: Error {}
        let provider = RecordingConversations()
        let bridge = LiveCommunicationBridge(provider: provider)

        do {
            _ = try await bridge.startOutgoingCall(callee: "bob") { throw DialFailed() }
            XCTFail("expected the dial's error")
        } catch {
            XCTAssertTrue(error is DialFailed)
        }
        let reported = await eventuallyEntries(provider) { $0.count == 2 }
        guard case let .outgoing(uuid, "bob")? = reported.first else {
            return XCTFail("the call was not requested first: \(reported)")
        }
        XCTAssertEqual(reported.last, .ended(uuid, .failed))
    }

    func testUnknownUuidActionsThrowRatherThanCrash() {
        let bridge = LiveCommunicationBridge(provider: RecordingConversations())
        let uuid = UUID()

        XCTAssertThrowsError(try bridge.handleJoin(uuid: uuid))
        XCTAssertThrowsError(try bridge.handleEnd(uuid: uuid))
        XCTAssertThrowsError(try bridge.handlePause(uuid: uuid, paused: true))
        XCTAssertThrowsError(try bridge.handleMute(uuid: uuid, muted: true))
        XCTAssertThrowsError(try bridge.handleTone(uuid: uuid, digits: "1"))
    }

    /// An outgoing call: requested, connecting, connected when answered,
    /// and ended by the system's End, all under the one UUID; the incoming
    /// side is joined from the system's Join.
    func testOutgoingAndIncomingCallsFollowTheSystemsActions() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }
        let aliceAccount = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress)
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress)
        let bobEvents = Recorder(bob.events())

        let aliceSystem = RecordingConversations()
        let aliceBridge = LiveCommunicationBridge(provider: aliceSystem)
        let target = "sip:bob@\(bob.bindAddress)"
        let (outUuid, aliceCall) = try await aliceBridge.startOutgoingCall(callee: target) {
            try alice.placeCall(account: aliceAccount, target: target)
        }
        defer { aliceCall.close() }
        XCTAssertTrue(aliceBridge.call(for: outUuid) === aliceCall)

        let arrived = await bobEvents.first(within: 5) { $0.kind == .incomingCall }
        let bobCall = try bob.takeIncomingCall(try XCTUnwrap(arrived, "no incoming call arrived"))
        defer { bobCall.close() }
        let bobSystem = RecordingConversations()
        let bobBridge = LiveCommunicationBridge(provider: bobSystem)
        let inUuid = try await bobBridge.reportIncomingCall(callerId: "alice")
        bobBridge.bind(uuid: inUuid, to: bobCall)
        try bobBridge.handleJoin(uuid: inUuid)

        let connected = await eventuallyEntries(aliceSystem) { $0.contains(.connected(outUuid)) }
        XCTAssertEqual(connected.first, .outgoing(outUuid, target))
        XCTAssertEqual(connected.dropFirst().first, .connecting(outUuid))

        try aliceBridge.handleTone(uuid: outUuid, digits: "1")
        try aliceBridge.handleMute(uuid: outUuid, muted: true)
        try aliceBridge.handleEnd(uuid: outUuid)
        let ended = await eventuallyEntries(aliceSystem) { $0.contains(.ended(outUuid, .localHangup)) }
        XCTAssertTrue(ended.contains(.ended(outUuid, .localHangup)))
        let farEnded = await eventuallyEntries(bobSystem) { $0.contains(.ended(inUuid, .remoteHangup)) }
        XCTAssertTrue(farEnded.contains(.ended(inUuid, .remoteHangup)))
        XCTAssertNil(aliceBridge.call(for: outUuid), "an ended call stayed bound")
    }

    /// A reset of the system's call service hangs up every bound call.
    func testManagerResetHangsUpBoundCalls() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }
        let aliceAccount = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress)
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress)
        let bobEvents = Recorder(bob.events())
        let system = RecordingConversations()
        let bridge = LiveCommunicationBridge(provider: system)
        let target = "sip:bob@\(bob.bindAddress)"
        let (uuid, aliceCall) = try await bridge.startOutgoingCall(callee: target) {
            try alice.placeCall(account: aliceAccount, target: target)
        }
        defer { aliceCall.close() }
        _ = await bobEvents.first(within: 5) { $0.kind == .incomingCall }

        bridge.managerDidReset()

        let ended = await eventuallyEntries(system) { entries in
            entries.contains { if case .ended(uuid, _) = $0 { return true } else { return false } }
        }
        XCTAssertTrue(ended.contains { if case .ended(uuid, _) = $0 { return true } else { return false } })
    }

    private func eventuallyEntries(
        _ provider: RecordingConversations, within seconds: Double = 5,
        _ done: @escaping ([RecordingConversations.Entry]) -> Bool
    ) async -> [RecordingConversations.Entry] {
        let deadline = Date().addingTimeInterval(seconds)
        while true {
            let entries = await provider.entries
            if done(entries) || Date() > deadline { return entries }
            try? await Task.sleep(nanoseconds: 20_000_000)
        }
    }
}
