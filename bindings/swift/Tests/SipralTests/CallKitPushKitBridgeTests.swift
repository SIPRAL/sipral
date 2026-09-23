// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import XCTest
@testable import Sipral

/// A `CallKitProviding` that records what it was told instead of driving a
/// real `CXProvider` -- `CallKit` does not exist on this platform at all
/// (macOS, and the Linux the core module also builds on), so this is the
/// only way `docs/15-mobile.md`'s sequence can be exercised without a
/// device: "push -> report to CallKit before the handler returns ->
/// announce -> refresh the binding -> match the INVITE -> answer".
final actor RecordingProvider: CallKitProviding {
    private(set) var reported: [(uuid: UUID, callerId: String)] = []
    private(set) var connecting: [UUID] = []
    private(set) var connected: [UUID] = []
    private(set) var ended: [(uuid: UUID, reason: CallKitBridge.EndReason)] = []
    var failNextReport = false

    nonisolated func reportIncomingCall(uuid: UUID, callerId: String, completion: @Sendable @escaping (Error?) -> Void) {
        Task {
            let shouldFail = await self.consumeFailNextReport()
            await self.record(uuid: uuid, callerId: callerId)
            completion(shouldFail ? CallKitBridgeError.unknownCall(uuid) : nil)
        }
    }

    nonisolated func reportCallConnecting(uuid: UUID) {
        Task { await self.recordConnecting(uuid) }
    }

    nonisolated func reportCallConnected(uuid: UUID) {
        Task { await self.recordConnected(uuid) }
    }

    nonisolated func reportCallEnded(uuid: UUID, reason: CallKitBridge.EndReason) {
        Task { await self.recordEnded(uuid, reason) }
    }

    private func consumeFailNextReport() -> Bool {
        defer { failNextReport = false }
        return failNextReport
    }

    private func record(uuid: UUID, callerId: String) { reported.append((uuid, callerId)) }
    private func recordConnecting(_ uuid: UUID) { connecting.append(uuid) }
    private func recordConnected(_ uuid: UUID) { connected.append(uuid) }
    private func recordEnded(_ uuid: UUID, _ reason: CallKitBridge.EndReason) { ended.append((uuid, reason)) }
}

final class CallKitBridgeTests: XCTestCase {
    func testReportIncomingCallRecordsBeforeReturning() async throws {
        let provider = RecordingProvider()
        let bridge = CallKitBridge(provider: provider)

        let uuid = try await bridge.reportIncomingCall(callerId: "alice")

        let reported = await provider.reported
        XCTAssertEqual(reported.count, 1)
        XCTAssertEqual(reported.first?.uuid, uuid)
        XCTAssertEqual(reported.first?.callerId, "alice")
    }

    func testReportIncomingCallPropagatesFailure() async throws {
        let provider = RecordingProvider()
        await provider.setFailNextReport(true)
        let bridge = CallKitBridge(provider: provider)

        do {
            _ = try await bridge.reportIncomingCall(callerId: "alice")
            XCTFail("expected an error")
        } catch {
            // Expected.
        }
    }

    func testUnknownUuidActionsThrowRatherThanCrash() {
        let provider = RecordingProvider()
        let bridge = CallKitBridge(provider: provider)
        let uuid = UUID()

        XCTAssertThrowsError(try bridge.handleAnswer(uuid: uuid))
        XCTAssertThrowsError(try bridge.handleEnd(uuid: uuid))
        XCTAssertThrowsError(try bridge.handleHold(uuid: uuid, onHold: true))
        XCTAssertThrowsError(try bridge.handleDtmf(uuid: uuid, digits: "1"))
    }
}

private extension RecordingProvider {
    func setFailNextReport(_ value: Bool) { failNextReport = value }
}

/// `PushKitBridge`'s own sequence, with no `PushKit` and no `CallKit`
/// involved: `Account.announce` and `Account.refreshBinding` are exercised
/// against a real loopback `SipralStack`/`Account` (the ABI calls
/// themselves need a real stack to mean anything), while the CallKit half
/// is the same `RecordingProvider` above.
final class PushKitBridgeTests: XCTestCase {
    func testHandlePushReportsToCallKitThenAnnouncesThenRefreshesBinding() async throws {
        let stack = try SipralStack()
        defer { stack.close() }
        // No registrar: `Account.announce` and `refreshBinding` both refuse
        // outright on a no-op account with `SIPRAL_STATUS_INVALID_ARGUMENT`
        // (`docs/08-ffi.md`, "An account with no registrar never
        // registers") -- which is exactly the shape this test wants to
        // observe without a real registrar to answer: the sequence still
        // runs in the right order, and PushKitBridge does not crash or stop
        // early when the refresh that follows announce is refused.
        let account = try stack.addAccount(aor: "sip:agent@sipral.invalid", registrarAddress: "127.0.0.1:5060")

        let provider = RecordingProvider()
        let callKit = CallKitBridge(provider: provider)
        let pushKit = PushKitBridge(callKit: callKit)

        let callerUri = "sip:alice@sipral.invalid"
        let pending = try await pushKit.handle(push: VoipPush(callerId: callerUri), account: account)

        let reported = await provider.reported
        XCTAssertEqual(reported.count, 1)
        XCTAssertEqual(reported.first?.callerId, callerUri)
        XCTAssertEqual(pending.callerId, callerUri)
        XCTAssertEqual(pending.uuid, reported.first?.uuid)
    }

    func testMatchIncomingCallResolvesPendingByCallerId() async throws {
        let stack = try SipralStack()
        defer { stack.close() }
        let account = try stack.addAccount(aor: "sip:agent@sipral.invalid", registrarAddress: "127.0.0.1:5060")

        let provider = RecordingProvider()
        let callKit = CallKitBridge(provider: provider)
        let pushKit = PushKitBridge(callKit: callKit)

        let pending = try await pushKit.handle(
            push: VoipPush(callerId: "sip:alice@sipral.invalid"), account: account
        )
        XCTAssertNil(pending.matchedCallHandle)

        // A synthetic `IncomingCall` naming "alice" in `From`, the shape
        // `docs/15-mobile.md`'s matching rule reads: same user, unescaped.
        let event = SipralEvent(
            kindRaw: SipralEventKind.incomingCall.rawValue,
            kind: .incomingCall,
            kindName: "incoming call",
            stack: stack.handle,
            account: account.handle,
            call: 424242,
            message: nil,
            callData: CallEventData(
                stateRaw: SipralCallState.incoming.rawValue, state: .incoming,
                endReasonRaw: 0, endReason: nil, statusCode: 0, other: Sipral.handleNone,
                heldHere: false, heldThere: false, localSdp: nil, remoteSdp: nil, retryInMs: 0,
                fromUri: "sip:alice@sipral.invalid", fromDisplay: nil, toUri: nil, callId: nil, digit: 0
            ),
            mediaData: nil, registrationData: nil, announceData: nil
        )

        pushKit.matchIncomingCall(event, on: stack)
        XCTAssertEqual(pending.matchedCallHandle, 424242)
    }
}
