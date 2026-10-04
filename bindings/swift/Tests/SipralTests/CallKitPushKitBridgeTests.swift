// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
        XCTAssertThrowsError(try bridge.handleMute(uuid: uuid, muted: true))
    }

    /// CallKit's hold, mute and audio session reach the call's audio: the
    /// device shut until the system activates the session, let go the moment
    /// CallKit holds the call (before the far end has answered the
    /// re-INVITE), taken back on resume, muted, let go when the system
    /// deactivates the session, and the call hung up when CallKit's own
    /// service resets under it.
    func testCallKitsHoldMuteAndSessionReachTheAttachedCallsAudio() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }
        let (aliceCall, bobCall) = try await ringingCall(from: alice, to: bob)
        defer { aliceCall.close(); bobCall.close() }

        let bridge = CallKitBridge(provider: RecordingProvider())
        let uuid = UUID()
        bridge.bind(uuid: uuid, to: bobCall)
        let aliceEvents = Recorder(aliceCall.events())
        try bridge.handleAnswer(uuid: uuid)
        _ = await aliceEvents.first(within: 5) { $0.kind == .callConfirmed }

        let device = FakeCallAudioDevice()
        let audio = CallAudio(
            sampleRate: 8000, frameSamples: 160, frames: AsyncStream { _ in }, send: { _ in }, device: device,
            retryDelays: [0]
        )
        defer { audio.close() }
        bridge.attach(audio, to: uuid)
        audio.start()
        try await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(device.opened, 0, "the device opened before CallKit activated the session")

        bridge.audioSessionActivated()
        let running = await eventually(within: 5) { audio.state == .running }
        XCTAssertTrue(running)

        try bridge.handleHold(uuid: uuid, onHold: true)
        XCTAssertEqual(audio.pauses, [.held], "the device was not let go before the hold returned")
        let farEndHeld = await aliceEvents.first(within: 5) { $0.kind == .sessionChanged }
        XCTAssertNotNil(farEndHeld, "the far end never heard the hold")
        try bridge.handleHold(uuid: uuid, onHold: false)
        let resumed = await eventually(within: 5) { device.opened == 2 && audio.state == .running }
        XCTAssertTrue(resumed)

        try bridge.handleMute(uuid: uuid, muted: true)
        XCTAssertEqual(audio.history.last, .muteChanged(true))

        bridge.audioSessionDeactivated()
        XCTAssertEqual(audio.pauses, [.sessionInactive])

        bridge.providerDidReset()
        let hungUp = await aliceEvents.first(within: 5) { $0.kind == .callEnded }
        XCTAssertNotNil(hungUp, "a call CallKit forgot was left up")
    }

    /// With the library running the devices, CallKit's audio session opens
    /// and closes the engine as a whole: nothing before `didActivate`, the
    /// devices at once when the session is already active, closed at
    /// `didDeactivate` and at a provider reset, and CallKit's mute on the
    /// engine's microphone.
    func testCallKitsSessionAndMuteDriveTheLibrarysEngine() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }
        let (aliceCall, bobCall) = try await ringingCall(from: alice, to: bob)
        defer { aliceCall.close(); bobCall.close() }
        let bridge = CallKitBridge(provider: RecordingProvider())
        let uuid = UUID()
        bridge.bind(uuid: uuid, to: bobCall)

        let engine = RecordingEngine()
        try bridge.drive(engine)
        XCTAssertEqual(engine.said, [], "the devices opened before CallKit activated the session")
        bridge.audioSessionActivated()
        XCTAssertEqual(engine.said, ["activate"])
        try bridge.handleMute(uuid: uuid, muted: true)
        XCTAssertEqual(engine.said.last, "mute input true")
        bridge.audioSessionDeactivated()
        XCTAssertEqual(engine.said.last, "deactivate")

        bridge.audioSessionActivated()
        let late = RecordingEngine()
        try bridge.drive(late)
        XCTAssertEqual(late.said, ["activate"], "an engine handed over mid-session stayed shut")
        bridge.providerDidReset()
        XCTAssertEqual(late.said, ["activate", "deactivate"])
    }

    /// Alice calls Bob over loopback; Bob's call is left ringing, as a call
    /// shown to a person is, with a reader on Bob's stack taken first.
    private func ringingCall(from alice: SipralStack, to bob: SipralStack) async throws -> (Call, Call) {
        let aliceAccount = try alice.addAccount(
            aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress
        )
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress)
        let bobEvents = Recorder(bob.events())
        let aliceCall = try alice.placeCall(account: aliceAccount, target: "sip:bob@\(bob.bindAddress)")
        let arrived = await bobEvents.first(within: 5) { $0.kind == .incomingCall }
        let bobCall = try bob.takeIncomingCall(try XCTUnwrap(arrived, "no incoming call arrived"))
        return (aliceCall, bobCall)
    }

    /// The bridge and the application both read the same bound call, and
    /// neither takes events from the other: the bridge reports the call
    /// connected and ended, and the application's own reader sees the
    /// confirmation and the end too.
    func testBridgeAndApplicationBothSeeEveryEventOfABoundCall() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }
        let (aliceCall, bobCall) = try await ringingCall(from: alice, to: bob)
        defer { aliceCall.close(); bobCall.close() }

        let provider = RecordingProvider()
        let bridge = CallKitBridge(provider: provider)
        let uuid = UUID()
        let application = Recorder(bobCall.events())
        bridge.bind(uuid: uuid, to: bobCall)

        try bridge.handleAnswer(uuid: uuid)
        let connected = await eventually(within: 5) { await provider.connected.contains(uuid) }
        XCTAssertTrue(connected, "the bridge never reported the call connected")
        let confirmed = await application.first(within: 5) { $0.kind == .callConfirmed }
        XCTAssertNotNil(confirmed, "the application's reader lost the confirmation to the bridge's")

        try aliceCall.hangup()
        let reported = await eventually(within: 5) { await provider.ended.contains { $0.uuid == uuid } }
        XCTAssertTrue(reported, "the bridge never reported the call ended")
        let endReason = await provider.ended.first { $0.uuid == uuid }?.reason
        XCTAssertEqual(endReason, .remoteHangup)
        let finished = await application.finished(within: 5)
        XCTAssertTrue(finished)
        XCTAssertEqual(application.elements.last?.kind, .callEnded)
        XCTAssertNil(bridge.call(for: uuid), "an ended call must be unbound")
    }

    /// A call the caller gave up on before it was bound is still reported
    /// ended once it is: its stream hands the bridge the end it missed,
    /// rather than leaving the call screen ringing.
    func testBindingACallThatAlreadyEndedReportsItEnded() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }
        let (aliceCall, bobCall) = try await ringingCall(from: alice, to: bob)
        defer { aliceCall.close(); bobCall.close() }

        try aliceCall.hangup()
        let ended = await eventually(within: 5) { bobCall.ended }
        XCTAssertTrue(ended, "the callee never heard the caller give up")

        let provider = RecordingProvider()
        let bridge = CallKitBridge(provider: provider)
        let uuid = UUID()
        bridge.bind(uuid: uuid, to: bobCall)
        let reported = await eventually(within: 5) { await provider.ended.contains { $0.uuid == uuid } }
        XCTAssertTrue(reported, "a call bound after it ended was never reported ended")
        let unbound = await eventually(within: 5) { bridge.call(for: uuid) == nil }
        XCTAssertTrue(unbound, "a call bound after it ended must be unbound again")
    }

    /// `Call.close()` forgets the call and force-finishes its broadcasts
    /// synchronously; a hangup it just issued still owes the stack an
    /// asynchronous CALL_ENDED, which can now never reach this call's
    /// `deliver` (the call is already forgotten by the time it would).
    /// Bob's own application code never reads `bobCall.events()` here, the
    /// same shape as `testHandlesReleaseWithNoUseAfterFreeWhilePendingEventsExist`
    /// -- only the bridge is watching -- so the bridge is the only thing
    /// that can be left holding a call CallKit still thinks is live.
    func testBridgeStillReportsEndedWhenTheApplicationHangsUpAndClosesWithoutReadingEvents() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }
        let (aliceCall, bobCall) = try await ringingCall(from: alice, to: bob)
        defer { aliceCall.close() }

        let provider = RecordingProvider()
        let bridge = CallKitBridge(provider: provider)
        let uuid = UUID()
        bridge.bind(uuid: uuid, to: bobCall)
        try bridge.handleAnswer(uuid: uuid)
        _ = await eventually(within: 5) { await provider.connected.contains(uuid) }

        // Bob hangs up and closes right away -- no draining of events()
        // first, the same shape as
        // testHandlesReleaseWithNoUseAfterFreeWhilePendingEventsExist.
        try bobCall.hangup()
        bobCall.close()

        let reported = await eventually(within: 5) { await provider.ended.contains { $0.uuid == uuid } }
        XCTAssertTrue(reported, "the bridge never reported the call ended")
        let endReason = await provider.ended.first { $0.uuid == uuid }?.reason
        XCTAssertEqual(endReason, .localHangup)
        let unbound = await eventually(within: 5) { bridge.call(for: uuid) == nil }
        XCTAssertTrue(unbound, "a call closed out from under the bridge must still be unbound")
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
        let stack = try SipralStack(audio: .application)
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
        let stack = try SipralStack(audio: .application)
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
                fromUri: "sip:alice@sipral.invalid", fromDisplay: nil, toUri: nil, callId: nil, digit: 0,
                endCause: nil, identityTrusted: false, assertedUri: nil, assertedDisplay: nil, verstat: nil,
                privacy: [], divertedFrom: nil, diversionReason: nil, diversionCount: 0, historyCount: 0,
                answerMode: nil, answerModeRequired: false, privAnswerMode: nil, privAnswerModeRequired: false,
                answerAfterMs: nil, ringSource: nil, alertInfo: nil,
                verification: nil, attestation: nil, verificationFailure: nil
            ),
            mediaData: nil, registrationData: nil, announceData: nil, natData: nil, relayData: nil,
            referralData: nil, turnStreamData: nil, audioData: nil, stunServerData: nil,
            verificationData: nil
        )

        pushKit.matchIncomingCall(event, on: stack)
        XCTAssertEqual(pending.matchedCallHandle, 424242)
    }
}

/// A `CallAudioSessionEngine` that records what it was told, in order.
final class RecordingEngine: CallAudioSessionEngine, @unchecked Sendable {
    private let lock = NSLock()
    private var told: [String] = []

    var said: [String] {
        lock.lock()
        defer { lock.unlock() }
        return told
    }

    private func note(_ what: String) {
        lock.lock()
        defer { lock.unlock() }
        told.append(what)
    }

    func activate() throws { note("activate") }
    func deactivate() throws { note("deactivate") }
    func setMuted(_ muted: Bool, for direction: SipralAudioDirection) throws {
        note("mute \(direction == .input ? "input" : "output") \(muted)")
    }
}
