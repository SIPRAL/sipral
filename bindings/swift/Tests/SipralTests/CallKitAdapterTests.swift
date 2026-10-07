// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

// iOS only; elsewhere `CallKitPushKitBridgeTests.swift` covers the bridge.
#if canImport(CallKit) && os(iOS)
@preconcurrency import AVFoundation
import CallKit
import XCTest
@testable import Sipral

/// What CallKit would learn about an action: fulfilled or failed.
enum ActionOutcome: Equatable {
    case pending, fulfilled, failed
}

final class RecordingAnswer: CXAnswerCallAction, @unchecked Sendable {
    var outcome = ActionOutcome.pending
    override func fulfill() { outcome = .fulfilled }
    override func fail() { outcome = .failed }
}

final class RecordingHold: CXSetHeldCallAction, @unchecked Sendable {
    var outcome = ActionOutcome.pending
    override func fulfill() { outcome = .fulfilled }
    override func fail() { outcome = .failed }
}

final class RecordingDtmf: CXPlayDTMFCallAction, @unchecked Sendable {
    var outcome = ActionOutcome.pending
    override func fulfill() { outcome = .fulfilled }
    override func fail() { outcome = .failed }
}

final class RecordingMute: CXSetMutedCallAction, @unchecked Sendable {
    var outcome = ActionOutcome.pending
    override func fulfill() { outcome = .fulfilled }
    override func fail() { outcome = .failed }
}

final class RecordingEnd: CXEndCallAction, @unchecked Sendable {
    var outcome = ActionOutcome.pending
    override func fulfill() { outcome = .fulfilled }
    override func fail() { outcome = .failed }
}

/// Real CallKit actions handed to `CallKitAdapter` on a live call, checked
/// for their effect and for fulfil or fail.
///
/// They are passed to the delegate directly: the iOS Simulator refuses
/// third-party `CXProvider`s, so `CXCallController` cannot be used there.
final class CallKitAdapterTests: XCTestCase {
    func testActionsFromCallKitDriveARingingCall() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }
        let bobEvents = Recorder(bob.events())

        let aliceAccount = try alice.addAccount(
            aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress
        )
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress)
        let aliceCall = try alice.placeCall(account: aliceAccount, target: "sip:bob@\(bob.bindAddress)")
        defer { aliceCall.close() }
        let aliceEvents = Recorder(aliceCall.events())
        let aliceDigits = Recorder(aliceCall.dtmf())

        let arrived = await bobEvents.first(within: 5) { $0.kind == .incomingCall }
        let incoming = try XCTUnwrap(arrived, "no incoming call arrived")
        let bobCall = try bob.takeIncomingCall(incoming)
        defer { bobCall.close() }
        // The application's own reader of the call the bridge is about to
        // watch: both see every event.
        let bobCallEvents = Recorder(bobCall.events())

        let configuration = CXProviderConfiguration()
        configuration.supportsVideo = false
        configuration.supportedHandleTypes = [.generic]
        let adapter = CallKitAdapter(configuration: configuration)
        let bridge = CallKitBridge(provider: adapter)
        adapter.bridge = bridge
        let provider = CXProvider(configuration: configuration)

        let uuid = UUID()
        bridge.bind(uuid: uuid, to: bobCall)
        XCTAssertNil(bobCall.media, "a taken call must still be ringing until CallKit answers it")

        let answer = RecordingAnswer(call: uuid)
        adapter.provider(provider, perform: answer)
        XCTAssertEqual(answer.outcome, .fulfilled)
        let confirmed = await aliceEvents.first(within: 5) { $0.kind == .callConfirmed }
        XCTAssertNotNil(confirmed, "CallKit's answer never reached the caller as a 200 OK")

        let answerAgain = RecordingAnswer(call: uuid)
        adapter.provider(provider, perform: answerAgain)
        XCTAssertEqual(answerAgain.outcome, .failed, "a second answer to a call already up has to fail, not pass")

        let bobConfirmed = await bobCallEvents.first(within: 5) { $0.kind == .callConfirmed }
        XCTAssertNotNil(bobConfirmed, "the application's reader lost the confirmation to the bridge's")

        // audio starts only after CallKit activates the session
        let session = AVAudioSession.sharedInstance()
        XCTAssertEqual(session.category, .playAndRecord, "answering did not configure the call's session")
        XCTAssertEqual(session.mode, .voiceChat)
        let device = FakeCallAudioDevice()
        let audio = CallAudio(
            sampleRate: 8000, frameSamples: 160, frames: AsyncStream { _ in }, send: { _ in }, device: device,
            retryDelays: [0]
        )
        defer { audio.close() }
        bridge.attach(audio, to: uuid)
        audio.start()
        XCTAssertEqual(audio.pauses, [.sessionInactive])
        adapter.provider(provider, didActivate: session)
        let running = await eventually(within: 5) { audio.state == .running }
        XCTAssertTrue(running, "didActivate did not start the call's audio: \(audio.history)")

        let mute = RecordingMute(call: uuid, muted: true)
        adapter.provider(provider, perform: mute)
        XCTAssertEqual(mute.outcome, .fulfilled)
        XCTAssertEqual(audio.history.last, .muteChanged(true))

        let hold = RecordingHold(call: uuid, onHold: true)
        adapter.provider(provider, perform: hold)
        XCTAssertEqual(hold.outcome, .fulfilled)
        XCTAssertEqual(audio.pauses, [.held], "CallKit's hold did not let the device go")
        adapter.provider(provider, didDeactivate: session)
        XCTAssertEqual(audio.pauses, [.held, .sessionInactive])
        let held = await aliceEvents.first(within: 5) { $0.callData?.heldThere == true }
        XCTAssertNotNil(held, "CallKit's hold never reached the caller")
        let heldHere = await bobCallEvents.first(within: 5) { $0.callData?.heldHere == true }
        XCTAssertNotNil(heldHere, "the application's reader lost the hold to the bridge's")

        let beforeResume = aliceEvents.elements.count
        let resume = RecordingHold(call: uuid, onHold: false)
        adapter.provider(provider, perform: resume)
        XCTAssertEqual(resume.outcome, .fulfilled)
        let resumed = await aliceEvents.first(within: 5, after: beforeResume) {
            $0.kind == .sessionChanged && $0.callData?.heldThere == false
        }
        XCTAssertNotNil(resumed, "CallKit's resume never reached the caller")
        adapter.provider(provider, didActivate: session)
        let back = await eventually(within: 5) { device.opened == 2 && audio.state == .running }
        XCTAssertTrue(back, "the call's audio did not come back after the hold: \(audio.history)")

        let dtmf = RecordingDtmf(call: uuid, digits: "7", type: .singleTone)
        adapter.provider(provider, perform: dtmf)
        XCTAssertEqual(dtmf.outcome, .fulfilled)
        let digit = await aliceDigits.first(within: 5) { _ in true }
        XCTAssertEqual(digit, "7")

        let end = RecordingEnd(call: uuid)
        adapter.provider(provider, perform: end)
        XCTAssertEqual(end.outcome, .fulfilled)
        let ended = await aliceEvents.first(within: 5) { $0.kind == .callEnded }
        XCTAssertEqual(ended?.callData?.endReason, .remoteHangup, "CallKit's end never reached the caller as a BYE")
    }

    func testActionsForACallTheBridgeDoesNotKnowFail() {
        let configuration = CXProviderConfiguration()
        let adapter = CallKitAdapter(configuration: configuration)
        let bridge = CallKitBridge(provider: adapter)
        adapter.bridge = bridge
        let provider = CXProvider(configuration: configuration)
        let stranger = UUID()

        let answer = RecordingAnswer(call: stranger)
        adapter.provider(provider, perform: answer)
        let end = RecordingEnd(call: stranger)
        adapter.provider(provider, perform: end)
        let mute = RecordingMute(call: stranger, muted: true)
        adapter.provider(provider, perform: mute)

        XCTAssertEqual(answer.outcome, .failed)
        XCTAssertEqual(end.outcome, .failed)
        XCTAssertEqual(mute.outcome, .failed)
    }
}
#endif
