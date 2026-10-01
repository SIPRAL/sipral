// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import Foundation
import XCTest
@testable import Sipral

/// A local conference through this layer -- the Swift counterpart of
/// `bindings/python/tests/test_local_conference.py`: made on its own and
/// asked about, recorded, refused at a rate it cannot mix, and, with three
/// stacks on 127.0.0.1, two calls bridged so that what one far end says the
/// other hears.
final class LocalConferenceTests: XCTestCase {
    private func square(_ samples: Int) -> [Int16] {
        (0..<samples).map { ($0 / 8) % 2 == 0 ? 8000 : -8000 }
    }

    private func loudness(_ frame: [Int16]) -> Int {
        frame.isEmpty ? 0 : frame.reduce(0) { $0 + abs(Int($1)) } / frame.count
    }

    func testThisEndIsItsFirstMemberAndIsAnnounced() async throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let events = stack.events()
        let conference = try LocalConference(stack: stack, maxMembers: 3, sampleRate: 8000)
        defer { conference.close() }
        let info = try conference.info()
        XCTAssertEqual(info.members, 1)
        XCTAssertEqual(info.capacity, 3)
        XCTAssertEqual(info.local, 1)
        XCTAssertEqual(conference.sampleRate, 8000)
        XCTAssertEqual(conference.frameSamples, 160)
        var members = try conference.memberList()
        XCTAssertEqual(members.first?.member, conference.handle)
        XCTAssertEqual(members.first?.gainInput, 256)

        try conference.setMuted(nil, .input)
        try conference.setGain(nil, .output, 128)
        members = try conference.memberList()
        XCTAssertEqual(members.first?.mutedInput, true)
        XCTAssertEqual(members.first?.gainOutput, 128)

        let announced = await firstOne(of: events) { $0.kind == .localConferenceChanged }?.localConferenceData
        XCTAssertEqual(announced?.conference, conference.handle)
        XCTAssertEqual(announced?.change, .joined)
        XCTAssertEqual(announced?.member, conference.handle)
        XCTAssertEqual(announced?.members, 1)
    }

    func testTheMixIsRecordedToAFile() async throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("sipral-conference-\(UUID().uuidString).wav").path
        defer { try? FileManager.default.removeItem(atPath: path) }
        let conference = try LocalConference(stack: stack, maxMembers: 2, sampleRate: 16000)
        try conference.record(to: path)
        for _ in 0..<10 {
            conference.sendAudio(square(320))
        }
        try await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertEqual(try conference.info().recording, 1)
        try conference.stopRecording()
        XCTAssertThrowsError(try conference.stopRecording()) { error in
            XCTAssertEqual((error as? SipralError)?.status, .wrongState)
        }
        conference.close()
        let written = try Data(contentsOf: URL(fileURLWithPath: path))
        XCTAssertEqual(Array(written.prefix(4)), Array("RIFF".utf8))
        XCTAssertGreaterThan(written.count, 44)
    }

    func testARateItCannotMixIsRefused() throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        XCTAssertThrowsError(try LocalConference(stack: stack, sampleRate: 44100)) { error in
            XCTAssertEqual((error as? SipralError)?.status, .conferenceRefused)
        }
    }

    /// Alice calls `far` directly, through an account of her own that names
    /// it as the next hop, and it answers.
    private func call(_ alice: SipralStack, _ far: SipralStack, _ user: String) async throws -> (Call, Call) {
        let account = try alice.addAccount(
            aor: "sip:alice-to-\(user)@sipral.invalid", registrarAddress: far.bindAddress
        )
        _ = try far.addAccount(aor: "sip:\(user)@sipral.invalid", registrarAddress: alice.bindAddress)
        let farEvents = far.events()
        let near = try alice.placeCall(account: account, target: "sip:\(user)@\(far.bindAddress)")
        let nearEvents = near.events()
        let arrived = await firstOne(of: farEvents) { $0.kind == .incomingCall }
        let incoming = try far.takeIncomingCall(try XCTUnwrap(arrived, "no incoming call arrived"))
        let events = incoming.events()
        try incoming.answer()
        if near.media == nil {
            _ = await firstOne(of: nearEvents) { _ in near.media != nil }
        }
        if incoming.media == nil {
            _ = await firstOne(of: events) { _ in incoming.media != nil }
        }
        return (near, incoming)
    }

    /// Alice calls Bob and Carol and bridges the two calls, taking no part
    /// herself: what Bob says, Carol hears.
    func testWhatOneFarEndSaysTheOtherHears() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        let carol = try SipralStack(audio: .application)
        defer { alice.close(); bob.close(); carol.close() }
        let (toBob, bobCall) = try await call(alice, bob, "bob")
        let (toCarol, carolCall) = try await call(alice, carol, "carol")
        defer { toBob.close(); toCarol.close(); bobCall.close(); carolCall.close() }

        let conference = try LocalConference(stack: alice, maxMembers: 2, local: false)
        defer { conference.close() }
        try conference.add(toBob)
        try conference.add(toCarol)
        XCTAssertThrowsError(try conference.add(toBob)) { error in
            XCTAssertEqual((error as? SipralError)?.status, .conferenceRefused)
        }
        XCTAssertEqual(try conference.info().members, 2)

        let bobMedia = try XCTUnwrap(bobCall.media)
        let carolFrames = try XCTUnwrap(carolCall.media).frames()
        for _ in 0..<100 {
            bobMedia.sendAudio(square(bobMedia.frameSamples))
        }
        let heard = Recorder(carolFrames)
        var loudest = 0
        var steady = 0
        var counted = 0
        _ = await eventually(within: 10) {
            loudest = 0
            steady = 0
            counted = 0
            for frame in heard.elements {
                if loudest > 2000 {
                    // and steadily, for sixty of Bob's hundred frames: a
                    // call whose own thread still carried frames beside the
                    // conference would have every other frame taken from
                    // under it, and a frame clock slower than the
                    // conference's leaves gaps the buffers fill with silence
                    steady += loudness(frame) > 2000 ? 1 : 0
                    counted += 1
                    if counted == 60 { return true }
                }
                loudest = max(loudest, loudness(frame))
            }
            return false
        }
        XCTAssertGreaterThan(loudest, 2000, "Carol never heard Bob")
        XCTAssertGreaterThanOrEqual(steady, 57, "Carol heard Bob in \(steady) of 60 frames")

        try conference.remove(toCarol)
        XCTAssertEqual(try conference.info().members, 1)
    }
}
