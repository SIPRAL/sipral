// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import Foundation
import XCTest
@testable import Sipral

/// `AudioMode.device` on this machine's real devices: the library's engine
/// listed, chosen, turned up and down, opened and closed, and carrying a call
/// against a stack in `.application` mode on 127.0.0.1.
///
/// The list, the choices and the settings are asked of the platform without
/// opening anything, and run everywhere the library has an engine. What opens
/// the devices -- activation, the ring, a call -- runs the voice-processing
/// unit, which on macOS needs the microphone granted to the process running
/// the tests: without the grant the unit fails inside the framework, and the
/// test process with it. Those run only with `SIPRAL_AUDIO_DEVICES=1`, from a
/// Terminal the system has asked about the microphone once
/// (`bindings/swift/README.md`, "Testing"). Only one stack in device mode is
/// alive at a time in any test: two voice-processing units in one process do
/// not survive on macOS.
final class AudioDeviceModeTests: XCTestCase {
    private func deviceStack(_ activation: SipralAudioActivation = .manual) throws -> SipralStack {
        let features = try Sipral.capabilities().features
        guard features & Sipral.featureAudioDevice != 0 else {
            throw XCTSkip("this build has no audio engine for this platform")
        }
        return try SipralStack(audio: .device(activation: activation))
    }

    /// A stack whose devices this test is going to open.
    private func openingStack(_ activation: SipralAudioActivation) throws -> SipralStack {
        guard ProcessInfo.processInfo.environment["SIPRAL_AUDIO_DEVICES"] == "1" else {
            throw XCTSkip("opens the real devices: SIPRAL_AUDIO_DEVICES=1, with the microphone granted")
        }
        return try deviceStack(activation)
    }

    func testThePlatformDefaultIsDeviceModeWhereTheLibraryHasAnEngine() throws {
        let features = try Sipral.capabilities().features
        if features & Sipral.featureAudioDevice != 0 {
            XCTAssertEqual(AudioMode.platformDefault, .device(activation: .automatic))
        } else {
            XCTAssertEqual(AudioMode.platformDefault, .application)
        }
        let pumped = try SipralStack(audio: .application)
        defer { pumped.close() }
        XCTAssertNil(pumped.audio, "a stack whose application pumps the frames has an engine")
        XCTAssertEqual(pumped.audioMode, .application)
    }

    func testTheDevicesAreListedUnderIdsThatSurviveARefresh() throws {
        let stack = try deviceStack()
        defer { stack.close() }
        let audio = try XCTUnwrap(stack.audio)
        let first = try audio.refresh()
        let second = try audio.refresh()
        XCTAssertFalse(first.isEmpty, "no device listed")
        XCTAssertEqual(first.map(\.id), second.map(\.id))
        XCTAssertTrue(first.allSatisfy { $0.id != 0 && !$0.name.isEmpty })
        XCTAssertEqual(try audio.devices(), second)
        XCTAssertTrue(first.contains { $0.outputChannels > 0 }, "no device can play")
        XCTAssertFalse(try audio.status().isActive, "listing opened the devices")
    }

    func testEachRoleIsChosenAndRefusedByStatus() throws {
        let stack = try deviceStack()
        defer { stack.close() }
        let audio = try XCTUnwrap(stack.audio)
        let devices = try audio.refresh()
        let speaker = try XCTUnwrap(devices.first { $0.isPresent && $0.canServe(.speaker) })

        XCTAssertThrowsError(try audio.select(UInt32.max, for: .speaker)) {
            XCTAssertEqual(($0 as? SipralError)?.status, .noSuchDevice)
        }
        if let microphoneOnly = devices.first(where: { $0.isPresent && $0.outputChannels == 0 }) {
            XCTAssertThrowsError(try audio.select(microphoneOnly, for: .speaker)) {
                XCTAssertEqual(($0 as? SipralError)?.status, .deviceUnusable)
            }
        }
        try audio.select(speaker, for: .speaker)
        XCTAssertEqual(try audio.selection(for: .speaker).selected, speaker.id)
        try audio.select(nil as AudioDevice?, for: .speaker)
        XCTAssertNil(try audio.selection(for: .speaker).selected)

        #if os(macOS) || os(iOS)
        let microphone = try XCTUnwrap(devices.first { $0.isPresent && $0.canServe(.microphone) })
        XCTAssertThrowsError(try audio.select(microphone, for: .microphone)) {
            XCTAssertEqual(($0 as? SipralError)?.status, .notSupported, "one voice-processing unit, one microphone")
        }
        #endif
    }

    func testGainAndMuteBelongToTheDirectionAndSurviveAChangeOfDevice() throws {
        let stack = try deviceStack()
        defer { stack.close() }
        let audio = try XCTUnwrap(stack.audio)
        XCTAssertEqual(try audio.gain(for: .input), 1)
        try audio.setGain(0.5, for: .input)
        try audio.setGain(2, for: .output)
        try audio.setMuted(true, for: .output)

        let speaker = try XCTUnwrap(try audio.refresh().first { $0.isPresent && $0.canServe(.speaker) })
        try audio.select(speaker, for: .speaker)
        XCTAssertEqual(try audio.gain(for: .input), 0.5)
        XCTAssertEqual(try audio.gain(for: .output), 2)
        XCTAssertTrue(try audio.isMuted(.output))
        XCTAssertFalse(try audio.isMuted(.input))
        XCTAssertEqual(try audio.level(for: .output), 0, "a closed device has a level")
    }

    func testManualActivationOpensAndClosesTheDevicesOnlyWhenAsked() throws {
        let stack = try openingStack(.manual)
        defer { stack.close() }
        let audio = try XCTUnwrap(stack.audio)
        try audio.setMuted(true, for: .output)
        XCTAssertFalse(try audio.status().isActive)

        try audio.activate()
        let open = try audio.status()
        XCTAssertTrue(open.isActive)
        XCTAssertNotEqual(open.speakerRateHz, 0)
        #if os(macOS) || os(iOS)
        XCTAssertTrue(open.systemEchoCancellation, "the voice-processing unit cancels the echo")
        #endif

        try audio.deactivate()
        XCTAssertFalse(try audio.status().isActive)
    }

    func testARingOpensTheDevicesUnderAutomaticActivationAndItsEndClosesThem() async throws {
        let stack = try openingStack(.automatic)
        defer { stack.close() }
        let audio = try XCTUnwrap(stack.audio)
        try audio.setMuted(true, for: .output)
        try audio.ring([Int16](repeating: 0, count: 800), sampleRate: 8000)
        let opened = await eventually(within: 3) { (try? audio.status().isActive) == true }
        XCTAssertTrue(opened, "the ring opened nothing")
        try audio.stopRinging()
        let closed = await eventually(within: 3) { (try? audio.status().isActive) == false }
        XCTAssertTrue(closed, "the devices stayed open with nothing left to play")
    }

    func testAChoiceTheEngineAppliedIsReportedAsTheEngines() async throws {
        let stack = try openingStack(.manual)
        defer { stack.close() }
        let audio = try XCTUnwrap(stack.audio)
        try audio.setMuted(true, for: .output)
        let events = Recorder(stack.events())
        try audio.activate()
        let speaker = try XCTUnwrap(try audio.refresh().first { $0.isPresent && $0.canServe(.speaker) })
        try audio.select(speaker, for: .speaker)

        let selected = await events.first(within: 5) {
            $0.kind == .audioDevicesChanged && $0.audioData?.change == .selected
        }
        XCTAssertEqual(selected?.audioData?.origin, .engine)
        XCTAssertEqual(selected?.audioData?.role, .speaker)
        XCTAssertEqual(selected?.audioData?.device, speaker.id)
        XCTAssertEqual(selected?.call, Sipral.handleNone)
        try audio.deactivate()
    }

    /// The call's frames are the engine's: the far end's audio reaches the
    /// loudspeaker's meter, and what the microphone gives reaches the far end
    /// as packets through the transmit callback and the call's own socket.
    func testACallInDeviceModeIsPumpedByTheEngine() async throws {
        let bob = try openingStack(.automatic)
        let alice = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }
        let audio = try XCTUnwrap(bob.audio)
        try audio.setGain(0.05, for: .output)

        let aliceAccount = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress)
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress)
        let bobEvents = Recorder(bob.events())
        let placed = try alice.placeCall(account: aliceAccount, target: "sip:bob@\(bob.bindAddress)")
        let aliceEvents = Recorder(placed.events())
        let arrived = await bobEvents.first(within: 5) { $0.kind == .incomingCall }
        let taken = try bob.takeIncomingCall(try XCTUnwrap(arrived))
        defer { placed.close(); taken.close() }
        try taken.answer()
        _ = await aliceEvents.first(within: 5) { $0.kind == .mediaStarted }
        let minted = await eventually(within: 5) { placed.media != nil && taken.media != nil }
        XCTAssertTrue(minted)
        let aliceMedia = try XCTUnwrap(placed.media)
        XCTAssertFalse(try XCTUnwrap(taken.media).pumpsFrames)
        XCTAssertTrue(aliceMedia.pumpsFrames)

        let tone = (0..<(aliceMedia.frameSamples * 100)).map { Int16(($0 % 16) < 8 ? 6000 : -6000) }
        aliceMedia.sendAudio(tone)
        let active = await eventually(within: 5) { (try? audio.status().isActive) == true }
        XCTAssertTrue(active, "the call's media opened no device")
        let loud = await eventually(within: 3) { ((try? audio.level(for: .output)) ?? 0) > 0 }
        XCTAssertTrue(loud, "the far end's audio never reached the loudspeaker")
        let heard = await eventually(within: 3) { ((try? aliceMedia.statistics().packets_received) ?? 0) > 20 }
        XCTAssertTrue(heard, "the engine's packets never reached the far end")
    }
}
