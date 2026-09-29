// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import Foundation
import XCTest
@testable import Sipral

/// What a call carries inside its audio, and how it is recorded, through
/// this package -- the Swift counterpart of
/// `bindings/python/tests/test_inband.py`: two stacks on 127.0.0.1 that
/// offer no telephone event, so a digit can only cross as its two tones; a
/// caller told to listen for who answered; the beep that says a call is
/// recorded; and the files a recording writes.
final class InBandTests: XCTestCase {
    private func stacks() throws -> (SipralStack, SipralStack) {
        (
            try SipralStack(audio: .application, codecs: "PCMU", offerDtmf: false),
            try SipralStack(audio: .application, codecs: "PCMU", offerDtmf: false)
        )
    }

    private func placeAndAnswer(
        _ alice: SipralStack, _ bob: SipralStack, beforeAnswer: (Call) throws -> Void = { _ in }
    ) async throws -> (Call, Call) {
        let aliceAccount = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress)
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress)
        let bobEvents = Recorder(bob.events())
        let aliceCall = try alice.placeCall(account: aliceAccount, target: "sip:bob@\(bob.bindAddress)")
        try beforeAnswer(aliceCall)
        let arrived = await bobEvents.first(within: 10) { $0.kind == .incomingCall }
        let bobCall = try bob.takeIncomingCall(try XCTUnwrap(arrived, "no incoming call arrived"))
        try bobCall.answer()
        let bothUp = await eventually(within: 10) { aliceCall.media != nil && bobCall.media != nil }
        XCTAssertTrue(bothUp, "media never started")
        return (aliceCall, bobCall)
    }

    func testADigitCrossesInTheAudioWhereNoTelephoneEventWasOffered() async throws {
        let (alice, bob) = try stacks()
        defer { alice.close(); bob.close() }
        let (aliceCall, bobCall) = try await placeAndAnswer(alice, bob)
        defer { aliceCall.close(); bobCall.close() }

        let events = Recorder(bobCall.events())
        let digits = Recorder(bobCall.dtmf())
        try await Task.sleep(nanoseconds: 200_000_000)
        try aliceCall.sendDtmf("7")
        let digit = await digits.first(within: 10) { _ in true }
        XCTAssertEqual(digit, "7")
        let found = await events.first(within: 5) { $0.kind == .inBandDigit }
        let media = try XCTUnwrap(try XCTUnwrap(found, "no in-band digit event").mediaData)
        XCTAssertEqual(media.source, .inBand)
        XCTAssertEqual(media.eventCode, 7)
        XCTAssertLessThan(abs(Int(media.heldMs) - 100), 25)
    }

    func testACallToldNotToListenHearsNoDigit() async throws {
        let (alice, bob) = try stacks()
        defer { alice.close(); bob.close() }
        let (aliceCall, bobCall) = try await placeAndAnswer(alice, bob)
        defer { aliceCall.close(); bobCall.close() }

        try bobCall.setDtmfDetection(.off)
        let digits = Recorder(bobCall.dtmf())
        try await Task.sleep(nanoseconds: 200_000_000)
        try aliceCall.sendDtmf("3")
        let digit = await digits.first(within: 1.5) { _ in true }
        XCTAssertNil(digit)
    }

    func testAStereoRecordingKeepsThisEndOnTheLeft() async throws {
        let (alice, bob) = try stacks()
        defer { alice.close(); bob.close() }
        let (aliceCall, bobCall) = try await placeAndAnswer(alice, bob)
        defer { aliceCall.close(); bobCall.close() }

        let media = try XCTUnwrap(aliceCall.media)
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("sipral-inband-\(UUID().uuidString).wav").path
        defer { try? FileManager.default.removeItem(atPath: path) }
        try media.record(to: path, layout: .stereo, sampleRate: 16_000)
        media.sendAudio([Int16](repeating: 3_000, count: media.frameSamples * 25))
        try await Task.sleep(nanoseconds: 800_000_000)
        let running = try media.recording
        XCTAssertTrue(running.running)
        XCTAssertGreaterThan(running.recordedMs, 0)
        try media.stopRecording()
        XCTAssertFalse(try media.recording.running)

        let wav = [UInt8](try Data(contentsOf: URL(fileURLWithPath: path)))
        func u16(_ at: Int) -> Int { Int(wav[at]) | Int(wav[at + 1]) << 8 }
        func u32(_ at: Int) -> Int { u16(at) | u16(at + 2) << 16 }
        XCTAssertEqual(Array(wav[0..<4]), Array("RIFF".utf8))
        XCTAssertEqual(u16(58), 2)
        XCTAssertEqual(u32(60), 16_000)
        XCTAssertEqual(u32(76), wav.count - 80)
        let left = stride(from: 80, to: wav.count - 3, by: 4).map { Int(Int16(bitPattern: UInt16(u16($0)))) }
        XCTAssertTrue(left.contains { abs($0 - 3_000) < 100 }, "this end is not on the left")
    }

    func testAnOggOpusRecordingIsAnOpusStream() async throws {
        let features = try Sipral.capabilities().features
        try XCTSkipIf(features & Sipral.featureOpus == 0, "this build has no Opus")
        let (alice, bob) = try stacks()
        defer { alice.close(); bob.close() }
        let (aliceCall, bobCall) = try await placeAndAnswer(alice, bob)
        defer { aliceCall.close(); bobCall.close() }

        let media = try XCTUnwrap(aliceCall.media)
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("sipral-inband-\(UUID().uuidString).opus").path
        defer { try? FileManager.default.removeItem(atPath: path) }
        try media.record(to: path, format: .oggOpus)
        try await Task.sleep(nanoseconds: 500_000_000)
        try media.stopRecording()
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        XCTAssertEqual(Array(data.prefix(4)), Array("OggS".utf8))
        XCTAssertNotNil(data.prefix(64).range(of: Data("OpusHead".utf8)))
        XCTAssertNotNil(data.range(of: Data("OpusTags".utf8)))
    }

    func testAGreetingThatRunsOnIsReportedAsAMachine() async throws {
        let (alice, bob) = try stacks()
        defer { alice.close(); bob.close() }
        var aliceEvents: Recorder<SipralEvent>?
        // a short greeting limit, so the decision comes in a second
        let (aliceCall, bobCall) = try await placeAndAnswer(alice, bob) { call in
            aliceEvents = Recorder(call.events())
            var options = ProgressOptions()
            options.maxGreetingMs = 600
            options.beep = false
            try call.detectProgress(options)
        }
        defer { aliceCall.close(); bobCall.close() }

        let bobMedia = try XCTUnwrap(bobCall.media)
        let rate = Int(try bobMedia.info().sample_rate)
        let greeting = (0..<(rate * 2)).map { n -> Int16 in
            let voiced = (n / (rate / 5)) % 2 == 0
            let t = Double(n) / Double(rate)
            let value = 6_000 * sin(2 * .pi * 180 * t) * (1 + 0.5 * sin(2 * .pi * 700 * t))
            return voiced ? Int16(value.rounded()) : 0
        }
        bobMedia.sendAudio(greeting)
        let found = await aliceEvents?.first(within: 15) { $0.kind == .progressDetected }
        let progress = try XCTUnwrap(try XCTUnwrap(found, "no progress event").progressData)
        XCTAssertEqual(progress.what, .answeredBy)
        XCTAssertEqual(progress.verdict, .machine)
        XCTAssertGreaterThan(progress.atMs, 0)
    }

    func testTheConsentToneReachesTheFarEndWhileRecording() async throws {
        let (alice, bob) = try stacks()
        defer { alice.close(); bob.close() }
        let (aliceCall, bobCall) = try await placeAndAnswer(alice, bob)
        defer { aliceCall.close(); bobCall.close() }

        let frames = Recorder(try XCTUnwrap(bobCall.media).frames())
        try aliceCall.setConsentTone(intervalMs: 1_000)
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("sipral-consent-\(UUID().uuidString).wav").path
        defer { try? FileManager.default.removeItem(atPath: path) }
        let media = try XCTUnwrap(aliceCall.media)
        try media.record(to: path)
        let loud = await frames.first(within: 3) { frame in frame.contains { abs(Int($0)) > 1_000 } }
        XCTAssertNotNil(loud, "no beep reached the far end")
        try media.stopRecording()
        try aliceCall.clearConsentTone()
        XCTAssertThrowsError(try aliceCall.setConsentTone(frequencyHz: 5_000))
    }
}
