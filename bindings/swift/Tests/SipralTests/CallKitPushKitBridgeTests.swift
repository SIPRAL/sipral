// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import XCTest
@testable import Sipral

/// Records what it was told, standing in for `CXProvider`, which does not
/// exist on macOS or Linux.
final actor RecordingProvider: CallKitProviding {
    private(set) var reported: [(uuid: UUID, callerId: String, displayName: String?)] = []
    /// The names given to calls already shown.
    private(set) var named: [(uuid: UUID, displayName: String)] = []
    /// The callers given to calls shown before anything named them.
    private(set) var identified: [(uuid: UUID, callerId: String, displayName: String?)] = []
    private(set) var connecting: [UUID] = []
    private(set) var connected: [UUID] = []
    private(set) var ended: [(uuid: UUID, reason: CallKitBridge.EndReason)] = []
    var failNextReport = false

    nonisolated func reportIncomingCall(uuid: UUID, callerId: String, completion: @Sendable @escaping (Error?) -> Void) {
        reportIncomingCall(uuid: uuid, callerId: callerId, displayName: nil, completion: completion)
    }

    nonisolated func reportIncomingCall(
        uuid: UUID, callerId: String, displayName: String?, completion: @Sendable @escaping (Error?) -> Void
    ) {
        Task {
            let shouldFail = await self.consumeFailNextReport()
            await self.record(uuid: uuid, callerId: callerId, displayName: displayName)
            completion(shouldFail ? CallKitBridgeError.unknownCall(uuid) : nil)
        }
    }

    nonisolated func reportCallerName(uuid: UUID, displayName: String) {
        Task { await self.recordName(uuid, displayName) }
    }

    nonisolated func reportCaller(uuid: UUID, callerId: String, displayName: String?) {
        Task { await self.recordCaller(uuid, callerId, displayName) }
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

    private func record(uuid: UUID, callerId: String, displayName: String?) {
        reported.append((uuid, callerId, displayName))
    }
    private func recordName(_ uuid: UUID, _ displayName: String) { named.append((uuid, displayName)) }
    private func recordCaller(_ uuid: UUID, _ callerId: String, _ displayName: String?) {
        identified.append((uuid, callerId, displayName))
    }
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

    /// CallKit's hold, mute, session activation and reset all reach the
    /// call's audio; hold releases the device before the re-INVITE is
    /// answered.
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

    /// A cellular call taken with Hold & Accept, as an iPhone XS ran it:
    /// CallKit holds ours and deactivates the session, the system posts an
    /// interruption's start and never its end, then CallKit resumes ours and
    /// activates the session again. That activation is the end of the
    /// interruption; the audio was left paused for it, the call running
    /// with nothing heard either way.
    func testAnInterruptionWhoseEndNeverComesIsOverWhenCallKitActivatesTheSession() async throws {
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
        bridge.audioSessionActivated()
        let running = await eventually(within: 5) { audio.state == .running }
        XCTAssertTrue(running)

        try bridge.handleHold(uuid: uuid, onHold: true)
        bridge.audioSessionDeactivated()
        audio.interruptionBegan()
        try bridge.handleHold(uuid: uuid, onHold: false)
        bridge.audioSessionActivated()

        let back = await eventually(within: 5) { audio.pauses.isEmpty && audio.state == .running }
        XCTAssertTrue(back, "the call's audio stayed paused for \(audio.pauses)")
    }

    /// In device mode the session drives the whole engine: opened at
    /// `didActivate` (or at once if already active), closed at deactivation
    /// and reset, muted with CallKit.
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

    /// The bridge and the application both see every event of a bound call.
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

    /// A call that ended before binding is still reported ended.
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

    /// `Call.close()` finishes the streams before the hangup's CALL_ENDED
    /// can arrive; with only the bridge watching, it must still report the
    /// end and forget the call.
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

        // Close right away, without draining events().
        try bobCall.hangup()
        bobCall.close()

        let reported = await eventually(within: 5) { await provider.ended.contains { $0.uuid == uuid } }
        XCTAssertTrue(reported, "the bridge never reported the call ended")
        let endReason = await provider.ended.first { $0.uuid == uuid }?.reason
        XCTAssertEqual(endReason, .localHangup)
        let unbound = await eventually(within: 5) { bridge.call(for: uuid) == nil }
        XCTAssertTrue(unbound, "a call closed out from under the bridge must still be unbound")
    }

    /// Whether the caller's `heard` events hold a 180 Ringing.
    private static func isRinging(_ event: SipralEvent) -> Bool {
        event.kind == .callProgress && event.callData?.statusCode == 180
    }

    /// A call bound while CallKit has yet to show its screen rings (180)
    /// the moment the screen is up, and not before.
    func testACallBoundBeforeItsScreenRingsOnceTheScreenIsUp() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }
        let (aliceCall, bobCall) = try await ringingCall(from: alice, to: bob)
        defer { aliceCall.close(); bobCall.close() }
        let heard = Recorder(aliceCall.events())

        let provider = DeferringProvider()
        let bridge = CallKitBridge(provider: provider)
        let uuid = bridge.reportIncomingCall(callerId: "sip:alice@sipral.invalid") { _ in }
        bridge.bind(uuid: uuid, to: bobCall)
        let early = await heard.first(within: 1, where: Self.isRinging)
        XCTAssertNil(early, "the call rang before CallKit showed it")

        provider.answer()
        let rang = await heard.first(within: 10, where: Self.isRinging)
        XCTAssertNotNil(rang, "the caller never heard the shown call ring: \(heard.elements.map(\.kindName))")
        XCTAssertEqual(heard.elements.filter(Self.isRinging).count, 1)
    }

    /// A pushed call: the screen is up before its INVITE, and the call
    /// rings as soon as it is bound to that screen.
    func testACallBoundToAScreenAlreadyUpRingsAtOnce() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }
        let (aliceCall, bobCall) = try await ringingCall(from: alice, to: bob)
        defer { aliceCall.close(); bobCall.close() }
        let heard = Recorder(aliceCall.events())

        let provider = DeferringProvider()
        let bridge = CallKitBridge(provider: provider)
        let uuid = bridge.reportIncomingCall(callerId: "sip:alice@sipral.invalid") { _ in }
        provider.answer()
        bridge.bind(uuid: uuid, to: bobCall)

        let rang = await heard.first(within: 10, where: Self.isRinging)
        XCTAssertNotNil(rang, "the caller never heard the shown call ring: \(heard.elements.map(\.kindName))")
    }

    /// Answer tapped on a pushed screen before its INVITE came: the call
    /// is answered when bound, and the caller gets the 200 OK with no 180
    /// before it.
    func testACallAnsweredBeforeItsInviteCameIsAnsweredWithoutRinging() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }
        let (aliceCall, bobCall) = try await ringingCall(from: alice, to: bob)
        defer { aliceCall.close(); bobCall.close() }
        let heard = Recorder(aliceCall.events())

        let provider = DeferringProvider()
        let bridge = CallKitBridge(provider: provider)
        let uuid = bridge.reportIncomingCall(callerId: "sip:alice@sipral.invalid") { _ in }
        provider.answer()
        let answered = Box<String>()
        bridge.handleAnswer(uuid: uuid) { failure in answered.value = failure.map { "\($0)" } ?? "answered" }
        XCTAssertNil(answered.value, "an Answer with no call to answer was settled")
        bridge.bind(uuid: uuid, to: bobCall)

        XCTAssertEqual(answered.value, "answered", "the kept Answer was not carried out at bind")
        let confirmed = await heard.first(within: 10) { $0.kind == .callConfirmed }
        XCTAssertNotNil(confirmed, "the caller never saw the answer: \(heard.elements.map(\.kindName))")
        XCTAssertFalse(heard.elements.contains(where: Self.isRinging), "a call answered at bind rang first")
    }
}

private extension RecordingProvider {
    func setFailNextReport(_ value: Bool) { failNextReport = value }
}

/// `PushKitBridge` against a real loopback stack, with `RecordingProvider`
/// for CallKit.
final class PushKitBridgeTests: XCTestCase {
    func testHandlePushReportsToCallKitThenAnnouncesThenRefreshesBinding() async throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        // No registrar, so announce and refresh are refused; the sequence
        // must still run in order and not stop early.
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

    /// A synthetic `IncomingCall` for `call`, from `fromUri`.
    private func incomingCall(_ call: SipralHandle, from fromUri: String, on stack: SipralStack, account: Account) -> SipralEvent {
        SipralEvent(
            kindRaw: SipralEventKind.incomingCall.rawValue,
            kind: .incomingCall,
            kindName: "incoming call",
            stack: stack.handle,
            account: account.handle,
            call: call,
            message: nil,
            callData: CallEventData(
                stateRaw: SipralCallState.incoming.rawValue, state: .incoming,
                endReasonRaw: 0, endReason: nil, statusCode: 0, other: Sipral.handleNone,
                heldHere: false, heldThere: false, localSdp: nil, remoteSdp: nil, retryInMs: 0,
                fromUri: fromUri, fromDisplay: nil, toUri: nil, callId: nil, digit: 0,
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
    }

    /// The stack decides which INVITE a push announced: one it matched to no
    /// announcement takes no screen, however alike the callers' user parts
    /// (extension 100 on two PBXs), and the one it matched takes the push's.
    func testOnlyTheInviteTheStackMatchedTakesThePushsScreen() async throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let account = try stack.addAccount(aor: "sip:agent@sipral.invalid", registrarAddress: "127.0.0.1:5060")

        let provider = RecordingProvider()
        let callKit = CallKitBridge(provider: provider)
        let pushKit = PushKitBridge(callKit: callKit)

        let pending = try await pushKit.handle(
            push: VoipPush(callerId: "sip:100@pbx-a.invalid"), account: account
        )
        XCTAssertNil(pending.matchedCallHandle)
        let announcement = try XCTUnwrap(pending.announcement)

        let other = incomingCall(424242, from: "sip:100@pbx-b.invalid", on: stack, account: account)
        XCTAssertNil(pushKit.matchIncomingCall(other, on: stack), "a call the stack did not match took the push's screen")
        XCTAssertNil(pending.matchedCallHandle)

        let announced = SipralEvent(
            kindRaw: SipralEventKind.callAnnounced.rawValue, kind: .callAnnounced, kindName: "call announced",
            stack: stack.handle, account: account.handle, call: 424243, message: nil, callData: nil,
            mediaData: nil, registrationData: nil,
            announceData: AnnounceEventData(announcement: announcement, waitedMs: 0), natData: nil,
            relayData: nil, referralData: nil, turnStreamData: nil, audioData: nil, stunServerData: nil,
            verificationData: nil
        )
        XCTAssertNil(pushKit.matchIncomingCall(announced, on: stack))
        let matched = incomingCall(424243, from: "sip:100@pbx-a.invalid", on: stack, account: account)
        XCTAssertEqual(pushKit.matchIncomingCall(matched, on: stack)?.uuid, pending.uuid)
        XCTAssertEqual(pending.matchedCallHandle, 424243)
    }

    /// The stack's events run on their own thread and may pair the INVITE
    /// with the announcement before `announce` has even returned. That
    /// INVITE must still find the push pending, not be handed to the
    /// application while the push's screen rings on with nothing to fill it.
    func testAnInviteMatchedWhileThePushIsAnnouncedTakesItsScreen() async throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let account = try stack.addAccount(aor: "sip:agent@sipral.invalid", registrarAddress: "127.0.0.1:5060")
        let provider = RecordingProvider()
        let pushKit = PushKitBridge(callKit: CallKitBridge(provider: provider))

        let call: SipralHandle = 424244
        let announcement: SipralHandle = 717171
        let announced = SipralEvent(
            kindRaw: SipralEventKind.callAnnounced.rawValue, kind: .callAnnounced, kindName: "call announced",
            stack: stack.handle, account: account.handle, call: call, message: nil, callData: nil,
            mediaData: nil, registrationData: nil,
            announceData: AnnounceEventData(announcement: announcement, waitedMs: 0), natData: nil,
            relayData: nil, referralData: nil, turnStreamData: nil, audioData: nil, stunServerData: nil,
            verificationData: nil
        )
        let invite = incomingCall(call, from: "sip:alice@sipral.invalid", on: stack, account: account)
        let announcer = RacingAnnouncer(announcement: announcement) {
            pushKit.matchIncomingCall(announced, on: stack)
            return pushKit.matchIncomingCall(invite, on: stack)
        }

        let pending = try await pushKit.handle(push: VoipPush(callerId: "sip:alice@sipral.invalid"), announcer: announcer)
        let taken = await eventually(within: 10) { announcer.matched != nil }
        XCTAssertTrue(taken, "the INVITE was never matched")
        XCTAssertEqual(announcer.matched??.uuid, pending.uuid, "the INVITE went to the application, not the push's screen")
        XCTAssertEqual(pending.matchedCallHandle, call)
        let ended = await provider.ended
        XCTAssertTrue(ended.isEmpty, "the push's screen was ended")
    }

    // MARK: - a push's payload, and the system's word on it

    func testTheClearPayloadIsReadAndAnythingElseIsNothing() {
        let fields = VoipPushFields(clear: [
            "caller": "sip:alice@sipral.invalid", "call-id": "a84b4c76e66710", "name": "Alice Liddell", "kind": "call",
        ])
        XCTAssertEqual(
            fields,
            VoipPushFields(callerId: "sip:alice@sipral.invalid", callId: "a84b4c76e66710", displayName: "Alice Liddell")
        )
        XCTAssertEqual(fields.push?.displayName, "Alice Liddell")
        let sealed = VoipPushFields(clear: ["box": "q9cXg2A=", "caller": "", "name": 7])
        XCTAssertEqual(sealed, VoipPushFields())
        XCTAssertNil(sealed.push, "no caller to announce it by")
    }

    func testAPushWithANameShowsItAndOneTheSystemNeedNotSeeIsNotShown() async throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let account = try stack.addAccount(aor: "sip:agent@sipral.invalid", registrarAddress: "127.0.0.1:5060")
        let provider = RecordingProvider()
        let pushKit = PushKitBridge(callKit: CallKitBridge(provider: provider))
        let fields = VoipPushFields(callerId: "sip:alice@sipral.invalid", displayName: "Alice Liddell")

        let quiet = await pushKit.receive(fields, mustReport: false, account: account)
        guard case .notShown(let named) = quiet else { return XCTFail("\(quiet)") }
        XCTAssertEqual(named?.callerId, "sip:alice@sipral.invalid")
        let nothing = await provider.reported
        XCTAssertTrue(nothing.isEmpty, "a push the system did not ask to see was shown")

        let shown = await pushKit.receive(fields, account: account)
        guard case .shown(let pending) = shown else { return XCTFail("\(shown)") }
        XCTAssertEqual(pending.displayName, "Alice Liddell")
        let reported = await provider.reported
        XCTAssertEqual(reported.map(\.displayName), ["Alice Liddell"])
        XCTAssertEqual(reported.first?.uuid, pending.uuid)
    }

    /// A decoder that could not open the payload leaves nothing to announce:
    /// the screen iOS requires is still shown, and ended at once.
    func testAPushNothingCouldBeReadFromIsShownAndEnded() async throws {
        let provider = RecordingProvider()
        let pushKit = PushKitBridge(callKit: CallKitBridge(provider: provider))
        let outcome = await pushKit.receive(nil, account: nil)
        guard case .unusable = outcome else { return XCTFail("\(outcome)") }
        let reported = await provider.reported
        XCTAssertEqual(reported.map(\.callerId), ["Unknown"])
        let ended = await eventually(within: 5) { await provider.ended.count == 1 }
        XCTAssertTrue(ended)
        let reason = await provider.ended.first?.reason
        XCTAssertEqual(reason, .failed)
    }

    /// A push read, but naming nobody (RFC 8599 asks for no payload, and a
    /// seal may not open): shown, and expected on the account alone.
    func testAPushThatNamesNobodyIsShownAndExpectedOnItsAccount() async throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let account = try stack.addAccount(aor: "sip:agent@sipral.invalid", registrarAddress: "127.0.0.1:5060")
        let provider = RecordingProvider()
        let pushKit = PushKitBridge(callKit: CallKitBridge(provider: provider))

        let outcome = await pushKit.receive(VoipPushFields(callId: "a84b4c76e66710"), account: account)
        guard case .shown(let pending) = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(pending.callerId, "", "a caller nothing named was made up")
        XCTAssertNotNil(pending.announcement, "nothing waits for the INVITE")
        let reported = await provider.reported
        XCTAssertEqual(reported.map(\.callerId), ["Unknown"])
        let ended = await provider.ended
        XCTAssertTrue(ended.isEmpty, "a call the account still expects was ended")
    }
}

/// Announces for `PushKitBridge` the way the stack's event thread can race
/// it: `announce` runs `deliver`, the events that pair an INVITE with the
/// announcement, on another thread, and gives them a second to finish
/// before it returns. A bridge that recorded the push only after announcing
/// would have the INVITE matched within that second, to nothing; one that
/// holds its state across both steps keeps the events waiting until the
/// push is recorded.
final class RacingAnnouncer: PushAnnouncing, @unchecked Sendable {
    private let announcement: SipralHandle
    private let deliver: @Sendable () -> PendingCall?
    private let lock = NSLock()
    private var delivered: PendingCall??

    init(announcement: SipralHandle, deliver: @escaping @Sendable () -> PendingCall?) {
        self.announcement = announcement
        self.deliver = deliver
    }

    /// What `deliver` returned for the INVITE: `nil` until it has run, and
    /// `.some(nil)` when the INVITE was handed to the application.
    var matched: PendingCall?? {
        lock.lock()
        defer { lock.unlock() }
        return delivered
    }

    func announce(caller: String?, callId: String?) throws -> (announcement: SipralHandle?, call: SipralHandle?) {
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            let found = self.deliver()
            self.lock.lock()
            self.delivered = .some(found)
            self.lock.unlock()
            done.signal()
        }
        _ = done.wait(timeout: .now() + 1)
        return (announcement, nil)
    }

    func refreshBinding() throws {}
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

/// Stands in for `CXProvider` as iOS holds it to a push: a report counts
/// the moment it is made, and CallKit answers it later, when `answer()` is
/// called. A push handler that has not reported by the time it returns is
/// what iOS ends the application for.
final class DeferringProvider: CallKitProviding, @unchecked Sendable {
    private let lock = NSLock()
    private var reports: [(uuid: UUID, callerId: String)] = []
    private var answers: [@Sendable (Error?) -> Void] = []
    private var endings: [(uuid: UUID, reason: CallKitBridge.EndReason)] = []

    var reported: [(uuid: UUID, callerId: String)] {
        lock.lock()
        defer { lock.unlock() }
        return reports
    }

    var ended: [(uuid: UUID, reason: CallKitBridge.EndReason)] {
        lock.lock()
        defer { lock.unlock() }
        return endings
    }

    /// CallKit's answers to every report made so far: the screens shown.
    func answer() {
        lock.lock()
        let waiting = answers
        answers.removeAll()
        lock.unlock()
        for answer in waiting {
            answer(nil)
        }
    }

    func reportIncomingCall(uuid: UUID, callerId: String, completion: @Sendable @escaping (Error?) -> Void) {
        lock.lock()
        defer { lock.unlock() }
        reports.append((uuid, callerId))
        answers.append(completion)
    }

    func reportCallConnecting(uuid: UUID) {}
    func reportCallConnected(uuid: UUID) {}

    func reportCallEnded(uuid: UUID, reason: CallKitBridge.EndReason) {
        lock.lock()
        defer { lock.unlock() }
        endings.append((uuid, reason))
    }
}

/// What a `PKPushRegistryDelegate` gets from the bridge: the call reported
/// before its method returns, on every path a push that must be reported
/// can take.
final class PushReportedInTheDelegateTests: XCTestCase {
    func testAPushThatNamesACallerIsReportedBeforeReceiveReturns() throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let account = try stack.addAccount(aor: "sip:agent@sipral.invalid", registrarAddress: "127.0.0.1:5060")
        let provider = DeferringProvider()
        let pushKit = PushKitBridge(callKit: CallKitBridge(provider: provider))
        let outcome = Box<PushOutcome>()

        pushKit.receive(VoipPushFields(callerId: "sip:alice@sipral.invalid"), account: account) { outcome.value = $0 }

        XCTAssertEqual(provider.reported.map(\.callerId), ["sip:alice@sipral.invalid"],
                       "the push handler returned with no call reported")
        XCTAssertNil(outcome.value, "told before CallKit answered")
        provider.answer()
        guard case .shown(let pending)? = outcome.value else { return XCTFail("\(String(describing: outcome.value))") }
        XCTAssertEqual(pending.uuid, provider.reported.first?.uuid)
        XCTAssertNotNil(pending.announcement, "nothing waits for the INVITE")
    }

    func testAPushThatNamesNobodyIsReportedBeforeHandleReturns() throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let account = try stack.addAccount(aor: "sip:agent@sipral.invalid", registrarAddress: "127.0.0.1:5060")
        let provider = DeferringProvider()
        let pushKit = PushKitBridge(callKit: CallKitBridge(provider: provider))

        let result = Box<Result<PendingCall, Error>>()

        let uuid = pushKit.handle(push: VoipPush(), account: account) { result.value = $0 }

        XCTAssertEqual(provider.reported.map(\.uuid), [uuid], "the push handler returned with no call reported")
        XCTAssertEqual(provider.reported.map(\.callerId), ["Unknown"])
        provider.answer()
        let pending = try XCTUnwrap(result.value).get()
        XCTAssertEqual(pending.uuid, uuid)
        XCTAssertEqual(pending.callerId, "", "a caller nothing named was made up")
        XCTAssertNotNil(pending.announcement, "nothing waits for the INVITE")
    }

    func testAnUnreadablePushIsReportedBeforeReceiveReturnsAndEndedOnceShown() {
        let provider = DeferringProvider()
        let pushKit = PushKitBridge(callKit: CallKitBridge(provider: provider))
        let outcome = Box<PushOutcome>()

        pushKit.receive(nil, account: nil) { outcome.value = $0 }

        XCTAssertEqual(provider.reported.map(\.callerId), ["Unknown"], "the push handler returned with no call reported")
        XCTAssertTrue(provider.ended.isEmpty, "ended before CallKit had shown it")
        provider.answer()
        guard case .unusable? = outcome.value else { return XCTFail("\(String(describing: outcome.value))") }
        XCTAssertEqual(provider.ended.map(\.reason), [.failed])
    }

    func testAPushThatNeedNotBeReportedIsNotShown() throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let account = try stack.addAccount(aor: "sip:agent@sipral.invalid", registrarAddress: "127.0.0.1:5060")
        let provider = DeferringProvider()
        let pushKit = PushKitBridge(callKit: CallKitBridge(provider: provider))
        let outcome = Box<PushOutcome>()

        pushKit.receive(VoipPushFields(callerId: "sip:alice@sipral.invalid"), mustReport: false, account: account) {
            outcome.value = $0
        }

        XCTAssertTrue(provider.reported.isEmpty)
        guard case .notShown(let named)? = outcome.value else { return XCTFail("\(String(describing: outcome.value))") }
        XCTAssertEqual(named?.callerId, "sip:alice@sipral.invalid")
    }
}

/// One value set from another thread, read under a lock.
final class Box<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var held: Value?

    var value: Value? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return held
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            held = newValue
        }
    }
}
