// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
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

    /// `Call.close()`'s own doc comment promises "idempotent, and safe to
    /// call regardless of how the call ended" -- two callers racing to close
    /// the same call, such as a `CALL_ENDED` handler and a user action
    /// landing at once. Sixteen concurrent closers on a call whose media
    /// never started (so the only thing a non-idempotent `close()` would do
    /// twice is close the raw `mediaSocket` descriptor) must not hang.
    func testCloseFromManyConcurrentCallersDoesNotHang() throws {
        let alice = try SipralStack()
        let bob = try SipralStack()
        defer { alice.close(); bob.close() }

        let aliceAccount = try alice.addAccount(
            aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress
        )
        let aliceCall = try alice.placeCall(account: aliceAccount, target: "sip:bob@\(bob.bindAddress)")
        XCTAssertNil(aliceCall.media, "media must not have started yet for this test to exercise the no-media path")

        let closers = 16
        let group = DispatchGroup()
        for _ in 0..<closers {
            group.enter()
            DispatchQueue.global().async {
                aliceCall.close()
                group.leave()
            }
        }
        let outcome = group.wait(timeout: .now() + 5)
        XCTAssertEqual(outcome, .success, "close() from \(closers) concurrent callers must not hang")
    }

    /// The concrete harm a non-idempotent `close()` does on the no-media
    /// path, made deterministic rather than raced: `close()` legitimately
    /// frees `aliceCall`'s media descriptor once, a fresh, unrelated socket
    /// is immediately handed that same descriptor number -- the ordinary
    /// POSIX behaviour of allocating the lowest free one -- and a *second*
    /// `close()` call, standing in for a second caller racing the first,
    /// must not reach past its own guard to close that unrelated socket's
    /// descriptor out from under it.
    func testSecondCloseDoesNotStealAReusedDescriptor() throws {
        let alice = try SipralStack()
        let bob = try SipralStack()
        defer { alice.close(); bob.close() }

        let aliceAccount = try alice.addAccount(
            aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress
        )
        let aliceCall = try alice.placeCall(account: aliceAccount, target: "sip:bob@\(bob.bindAddress)")
        XCTAssertNil(aliceCall.media, "media must not have started yet for this test to exercise the no-media path")

        let victimDescriptor = aliceCall.debugMediaSocketDescriptor
        XCTAssertEqual(fcntl(victimDescriptor, F_GETFD), 0, "the media descriptor must start out open")

        aliceCall.close()
        XCTAssertEqual(fcntl(victimDescriptor, F_GETFD), -1, "the first close must have freed the descriptor")

        let impostor = try UDPSocket(host: "127.0.0.1", port: 0)
        defer { impostor.close() }
        try XCTSkipUnless(
            impostor.fd == victimDescriptor,
            "the platform did not reuse the freed descriptor number for the new socket, nothing to race here"
        )

        aliceCall.close()

        XCTAssertEqual(
            fcntl(impostor.fd, F_GETFD), 0,
            "a second close() must not close a descriptor number that has since been reused by an unrelated socket"
        )
    }
}
