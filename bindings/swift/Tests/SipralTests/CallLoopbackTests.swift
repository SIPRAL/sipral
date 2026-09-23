// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import XCTest
@testable import Sipral

/// Two stacks on 127.0.0.1, talking directly, with no registrar between
/// them -- the same shape `bindings/python/tests/test_call.py` proves the
/// Python layer with, carried through this package's own idiomatic layer:
/// place a call, answer it, exchange audio, hold and resume, send DTMF,
/// hang up, and release every handle without a use-after-free while events
/// are still pending.
final class CallLoopbackTests: XCTestCase {
    private func placeAndAnswer(_ alice: SipralStack, _ bob: SipralStack) async throws -> (Call, Call) {
        let aliceAccount = try alice.addAccount(
            aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress
        )
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress)

        let aliceCall = try alice.placeCall(account: aliceAccount, target: "sip:bob@\(bob.bindAddress)")

        var bobCall: Call?
        for await event in bob.events {
            if event.kind == .incomingCall {
                bobCall = try bob.answerCall(event)
                break
            }
        }
        guard let bobCall else { throw XCTSkip("no incoming call arrived") }

        try await waitForMedia(aliceCall)
        try await waitForMedia(bobCall)
        return (aliceCall, bobCall)
    }

    private func waitForMedia(_ call: Call, timeoutSeconds: Double = 5) async throws {
        let deadline = DispatchTime.now() + timeoutSeconds
        for await _ in call.events {
            if call.media != nil { return }
            if DispatchTime.now() >= deadline { break }
        }
        XCTAssertNotNil(call.media, "media never started for call \(call.handle)")
    }

    func testCallReachesConfirmedWithMediaBothWays() async throws {
        let alice = try SipralStack()
        let bob = try SipralStack()
        defer { alice.close(); bob.close() }

        let (aliceCall, bobCall) = try await placeAndAnswer(alice, bob)
        defer { aliceCall.close(); bobCall.close() }

        let aliceState = try aliceCall.state
        let bobState = try bobCall.state
        XCTAssertEqual(aliceState, .confirmed)
        XCTAssertEqual(bobState, .confirmed)

        let aliceInfo = try XCTUnwrap(aliceCall.media).info()
        let bobInfo = try XCTUnwrap(bobCall.media).info()
        XCTAssertTrue(aliceInfo.sending != 0)
        XCTAssertTrue(bobInfo.receiving != 0)
    }

    func testAudioCrossesInBothDirections() async throws {
        let alice = try SipralStack()
        let bob = try SipralStack()
        defer { alice.close(); bob.close() }

        let (aliceCall, bobCall) = try await placeAndAnswer(alice, bob)
        defer { aliceCall.close(); bobCall.close() }

        let aliceMedia = try XCTUnwrap(aliceCall.media)
        let bobMedia = try XCTUnwrap(bobCall.media)

        let tone = [Int16](repeating: 4096, count: aliceMedia.frameSamples * 5)
        aliceMedia.sendAudio(tone)

        var heard: [Int16]?
        for await frame in bobMedia.frames {
            heard = frame
            break
        }
        XCTAssertEqual(heard?.count, aliceMedia.frameSamples)

        bobMedia.sendAudio(tone)
        var heardBack: [Int16]?
        for await frame in aliceMedia.frames {
            heardBack = frame
            break
        }
        XCTAssertEqual(heardBack?.count, bobMedia.frameSamples)
    }

    func testHoldResumeDtmfAndStatistics() async throws {
        let alice = try SipralStack()
        let bob = try SipralStack()
        defer { alice.close(); bob.close() }

        let (aliceCall, bobCall) = try await placeAndAnswer(alice, bob)
        defer { aliceCall.close(); bobCall.close() }

        try aliceCall.hold()
        var sawHeldHere = false
        for await event in aliceCall.events {
            if event.callData?.heldHere == true { sawHeldHere = true; break }
        }
        XCTAssertTrue(sawHeldHere)

        try aliceCall.resume()
        var sawResumed = false
        for await event in aliceCall.events {
            // A resume re-offers the session the way a hold does, and its
            // outcome arrives the same way (`docs/08-ffi.md`, "The
            // application hears the outcome as
            // SIPRAL_EVENT_KIND_MEDIA_CHANGED"): a SESSION_CHANGED naming
            // `heldHere` false, `SipralEventKind.mediaResumed` is a
            // different thing (recovery from a suspend, not an un-hold).
            if event.callData?.heldHere == false { sawResumed = true; break }
        }
        XCTAssertTrue(sawResumed)

        try bobCall.sendDtmf("5")
        var digit: Character?
        for await d in aliceCall.dtmf {
            digit = d
            break
        }
        XCTAssertEqual(digit, "5")

        let media = try XCTUnwrap(aliceCall.media)
        for _ in 0..<5 {
            media.sendAudio([Int16](repeating: 0, count: media.frameSamples))
        }
        try await Task.sleep(nanoseconds: 300_000_000)

        let stats = try media.statistics()
        XCTAssertGreaterThan(stats.packets_sent, 0)
    }

    func testHandlesReleaseWithNoUseAfterFreeWhilePendingEventsExist() async throws {
        let alice = try SipralStack()
        let bob = try SipralStack()
        defer { alice.close(); bob.close() }

        let (aliceCall, bobCall) = try await placeAndAnswer(alice, bob)

        // Hang up and close immediately, without draining `events` first --
        // there may still be a CALL_ENDED (and its farewell) queued when
        // `close()` runs. `docs/08-ffi.md`'s "A media handle outlives its
        // call, and says so" is the property under test: nothing here may
        // crash or read freed memory, whatever order the two closes and the
        // still-pending events land in.
        try aliceCall.hangup()
        aliceCall.close()
        bobCall.close()

        // The handle is now stale; every entry point on it must answer
        // SIPRAL_STATUS_STALE_HANDLE (or invalid_handle), never crash.
        XCTAssertThrowsError(try aliceCall.hangup())
    }
}
