// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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

        // Every stream is taken before the action whose outcome it waits
        // for: a reader sees nothing raised before it was taken.
        let bobEvents = bob.events()
        let aliceCall = try alice.placeCall(account: aliceAccount, target: "sip:bob@\(bob.bindAddress)")
        let aliceEvents = aliceCall.events()

        let arrived = await firstOrGiveUp(bobEvents, within: 5) { $0.kind == .incomingCall }
        let call = try bob.takeIncomingCall(try XCTUnwrap(arrived, "no incoming call arrived"))
        let events = call.events()
        try call.answer()
        let answered = (call: call, events: events)

        try await waitForMedia(aliceCall, aliceEvents)
        try await waitForMedia(answered.call, answered.events)
        return (aliceCall, answered.call)
    }

    private func waitForMedia(
        _ call: Call, _ events: AsyncStream<SipralEvent>, timeoutSeconds: Double = 5
    ) async throws {
        if call.media != nil { return }
        _ = await firstOrGiveUp(events, within: timeoutSeconds) { _ in call.media != nil }
        XCTAssertNotNil(call.media, "media never started for call \(call.handle)")
    }

    func testCallReachesConfirmedWithMediaBothWays() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
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
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }

        let (aliceCall, bobCall) = try await placeAndAnswer(alice, bob)
        defer { aliceCall.close(); bobCall.close() }

        let aliceMedia = try XCTUnwrap(aliceCall.media)
        let bobMedia = try XCTUnwrap(bobCall.media)

        let tone = [Int16](repeating: 4096, count: aliceMedia.frameSamples * 5)
        let bobFrames = bobMedia.frames()
        aliceMedia.sendAudio(tone)

        let heard = await firstOne(of: bobFrames)
        XCTAssertEqual(heard?.count, aliceMedia.frameSamples)

        let aliceFrames = aliceMedia.frames()
        bobMedia.sendAudio(tone)
        let heardBack = await firstOne(of: aliceFrames)
        XCTAssertEqual(heardBack?.count, bobMedia.frameSamples)
    }

    /// The loudest sample of what `bob` hears of `alice` sending a tone on a
    /// call `alice` holds, on stacks whose `heldAudio` is `heldAudio`.
    private func loudestHeardOnHold(_ heldAudio: SipralHeldAudio) async throws -> Int {
        let alice = try SipralStack(audio: .application, heldAudio: heldAudio)
        let bob = try SipralStack(audio: .application, heldAudio: heldAudio)
        defer { alice.close(); bob.close() }
        let (aliceCall, bobCall) = try await placeAndAnswer(alice, bob)
        defer { aliceCall.close(); bobCall.close() }

        let holdEvents = aliceCall.events()
        try aliceCall.hold()
        let held = await firstOne(of: holdEvents) { $0.callData?.heldHere == true }
        XCTAssertNotNil(held, "the hold never came into force")

        let aliceMedia = try XCTUnwrap(aliceCall.media)
        let bobMedia = try XCTUnwrap(bobCall.media)
        let heard = Recorder(bobMedia.frames(bufferingNewest: 256))
        aliceMedia.sendAudio([Int16](repeating: 8_000, count: aliceMedia.frameSamples * 40))
        try await Task.sleep(nanoseconds: 1_200_000_000)
        return heard.elements.map { frame in frame.map { abs(Int($0)) }.max() ?? 0 }.max() ?? 0
    }

    /// A party this end holds hears silence by default, in application mode
    /// too, where the frames sent may be a microphone's; it hears what the
    /// application sends — hold music, an announcement, a voice agent — on
    /// a stack told `heldAudio: .application`.
    func testAHeldPartyHearsSilenceUnlessTheStackSaysTheApplication() async throws {
        let byDefault = try await loudestHeardOnHold(.default)
        XCTAssertLessThan(byDefault, 100, "the held party heard the application on a stack told nothing")
        let application = try await loudestHeardOnHold(.application)
        XCTAssertGreaterThan(application, 1_000, "the held party did not hear what the application sent")
    }

    /// The realms a password answers reach the stack one per line: a realm
    /// with a comma of its own is one realm, and one with a control byte is
    /// refused there.
    func testTheRealmsAPasswordAnswersReachTheStackOnePerLine() throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        _ = try stack.addAccount(
            aor: "sip:alice@sipral.invalid", registrarAddress: "127.0.0.1:5060",
            authUser: "alice", authPassword: "open sesame", realms: ["registrar.example", "sbc, inc."]
        )
        XCTAssertThrowsError(
            try stack.addAccount(
                aor: "sip:bob@sipral.invalid", registrarAddress: "127.0.0.1:5060",
                realms: ["registrar.example", "sbc\texample"]
            )
        ) { error in
            XCTAssertEqual((error as? SipralError)?.status, .invalidArgument)
        }
    }

    func testHoldResumeDtmfAndStatistics() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }

        let (aliceCall, bobCall) = try await placeAndAnswer(alice, bob)
        defer { aliceCall.close(); bobCall.close() }

        let holdEvents = aliceCall.events()
        try aliceCall.hold()
        let sawHeldHere = await firstOne(of: holdEvents) { $0.callData?.heldHere == true }
        XCTAssertNotNil(sawHeldHere)

        let resumeEvents = aliceCall.events()
        try aliceCall.resume()
        let sawResumed = await firstOne(of: resumeEvents) { event in
            // A resume re-offers the session the way a hold does, and its
            // outcome arrives the same way (`docs/08-ffi.md`, "The
            // application hears the outcome as
            // SIPRAL_EVENT_KIND_MEDIA_CHANGED"): a SESSION_CHANGED naming
            // `heldHere` false, `SipralEventKind.mediaResumed` is a
            // different thing (recovery from a suspend, not an un-hold).
            event.callData?.heldHere == false
        }
        XCTAssertNotNil(sawResumed)

        let digits = aliceCall.dtmf()
        try bobCall.sendDtmf("5")
        let digit = await firstOne(of: digits)
        XCTAssertEqual(digit, "5")

        let media = try XCTUnwrap(aliceCall.media)
        for _ in 0..<5 {
            media.sendAudio([Int16](repeating: 0, count: media.frameSamples))
        }
        try await Task.sleep(nanoseconds: 300_000_000)

        let stats = try media.statistics()
        XCTAssertGreaterThan(stats.packets_sent, 0)

        // frames_underrun is the library's own count: read either side of
        // statistics(), it brackets what statistics() returned
        let before = try Sipral.mediaStatistics(media: media.handle, nowMs: 0).frames_underrun
        let read = try media.statistics().frames_underrun
        let after = try Sipral.mediaStatistics(media: media.handle, nowMs: 0).frames_underrun
        XCTAssertLessThanOrEqual(before, read)
        XCTAssertLessThanOrEqual(read, after)
        // each member appended after the ones before it, the newest at the
        // tail, where a caller built before it never reads
        XCTAssertLessThan(
            try XCTUnwrap(Self.offset(of: \.frames_underrun, in: stats)),
            try XCTUnwrap(Self.offset(of: \.feedback, in: stats))
        )
        XCTAssertEqual(
            Self.offset(of: \.feedback_suppressed, in: stats),
            MemoryLayout.size(ofValue: stats) - MemoryLayout<UInt64>.size,
            "appended at the tail, where a caller built before it never reads"
        )
    }

    private static func offset<T>(of member: PartialKeyPath<T>, in _: T) -> Int? {
        MemoryLayout<T>.offset(of: member)
    }

    /// Two readers of one call, both taken before anything happens on it,
    /// each see every event the call raises, in the same order, and each
    /// digit -- what a `CallKitBridge` bound to a call and the
    /// application's own loop over that call both rely on. A single
    /// `AsyncStream` read from two places splits its events between them.
    func testTwoConcurrentReadersBothSeeEveryEventOfARealCall() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }

        let aliceAccount = try alice.addAccount(
            aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress
        )
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress)
        let aliceStackFirst = Recorder(alice.events())
        let aliceStackSecond = Recorder(alice.events())
        let bobEvents = Recorder(bob.events())

        let aliceCall = try alice.placeCall(account: aliceAccount, target: "sip:bob@\(bob.bindAddress)")
        defer { aliceCall.close() }
        let first = Recorder(aliceCall.events())
        let second = Recorder(aliceCall.events())
        let firstDigits = Recorder(aliceCall.dtmf())
        let secondDigits = Recorder(aliceCall.dtmf())

        let arrived = await bobEvents.first(within: 5) { $0.kind == .incomingCall }
        let bobCall = try bob.takeIncomingCall(try XCTUnwrap(arrived, "no incoming call arrived"))
        defer { bobCall.close() }
        let bobCallEvents = Recorder(bobCall.events())
        try bobCall.answer()

        let aliceMedia = await first.first(within: 5) { $0.kind == .mediaStarted }
        XCTAssertNotNil(aliceMedia, "media never started on the caller's side")
        let bobMedia = await bobCallEvents.first(within: 5) { $0.kind == .mediaStarted }
        XCTAssertNotNil(bobMedia, "media never started on the callee's side")

        try aliceCall.hold()
        let held = await first.first(within: 5) { $0.callData?.heldHere == true }
        XCTAssertNotNil(held, "the hold never came back as a session change")
        let beforeResume = first.elements.count
        try aliceCall.resume()
        let resumed = await first.first(within: 5, after: beforeResume) {
            $0.kind == .sessionChanged && $0.callData?.heldHere == false
        }
        XCTAssertNotNil(resumed, "the resume never came back as a session change")

        try bobCall.sendDtmf("5")
        let digit = await firstDigits.first(within: 5) { _ in true }
        XCTAssertEqual(digit, "5")

        try bobCall.hangup()
        let firstFinished = await first.finished(within: 5)
        let secondFinished = await second.finished(within: 5)
        let firstDigitsFinished = await firstDigits.finished(within: 5)
        let secondDigitsFinished = await secondDigits.finished(within: 5)
        XCTAssertTrue(firstFinished && secondFinished, "a call's event streams must finish when it ends")
        XCTAssertTrue(firstDigitsFinished && secondDigitsFinished, "a call's digit streams must finish when it ends")

        let firstKinds = first.elements.map(\.kindRaw)
        XCTAssertEqual(firstKinds, second.elements.map(\.kindRaw), "both readers must see the same events, in order")
        for kind in [SipralEventKind.mediaStarted, .sessionChanged, .digitReceived, .callEnded] {
            XCTAssertTrue(firstKinds.contains(kind.rawValue), "\(kind) missing from what the readers saw")
        }
        XCTAssertEqual(firstKinds.last, SipralEventKind.callEnded.rawValue)
        XCTAssertEqual(firstDigits.elements, ["5"])
        XCTAssertEqual(secondDigits.elements, ["5"])
        XCTAssertEqual(aliceCall.debugEventReaders, 0, "a finished call must hold no reader")

        // The stack's own stream, read twice: the same events for this call,
        // up to its end, on both.
        func throughEnd(_ recorder: Recorder<SipralEvent>) async -> [UInt32] {
            _ = await recorder.first(within: 5) { $0.kind == .callEnded && $0.call == aliceCall.handle }
            let mine = recorder.elements.filter { $0.call == aliceCall.handle }.map(\.kindRaw)
            guard let end = mine.firstIndex(of: SipralEventKind.callEnded.rawValue) else { return mine }
            return Array(mine[...end])
        }
        let stackFirst = await throughEnd(aliceStackFirst)
        let stackSecond = await throughEnd(aliceStackSecond)
        XCTAssertEqual(stackFirst, stackSecond)
        XCTAssertEqual(stackFirst.last, SipralEventKind.callEnded.rawValue)
    }

    /// One reader leaves after its first event, and another is taken and
    /// never read at all: the reader beside them still gets every event on
    /// time, the one that left is forgotten, and the one never read still
    /// holds everything when it is finally drained.
    func testAReaderThatStopsEarlyDoesNotHoldUpTheOthers() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }

        let (aliceCall, bobCall) = try await placeAndAnswer(alice, bob)
        defer { aliceCall.close(); bobCall.close() }
        let settled = await eventually(within: 5) { aliceCall.debugEventReaders == 0 }
        XCTAssertTrue(settled, "the readers placeAndAnswer took must be gone once it returned")

        let quitter = Task { [events = aliceCall.events()] () -> SipralEvent? in
            await firstOrGiveUp(events, within: 5)
        }
        let neverRead = aliceCall.events()
        let steady = Recorder(aliceCall.events())
        XCTAssertEqual(aliceCall.debugEventReaders, 3)

        try aliceCall.hold()
        let quitterSaw = await quitter.value
        XCTAssertNotNil(quitterSaw)
        let held = await steady.first(within: 5) { $0.callData?.heldHere == true }
        XCTAssertNotNil(held, "the reader that stayed never saw the hold")
        let forgotten = await eventually(within: 5) { aliceCall.debugEventReaders == 2 }
        XCTAssertTrue(forgotten, "a reader whose loop has ended must be forgotten")

        let beforeResume = steady.elements.count
        try aliceCall.resume()
        let resumed = await steady.first(within: 5, after: beforeResume) {
            $0.kind == .sessionChanged && $0.callData?.heldHere == false
        }
        XCTAssertNotNil(resumed, "the reader that stayed never saw the resume")

        try bobCall.hangup()
        let finished = await steady.finished(within: 5)
        XCTAssertTrue(finished)
        let unread = await drain(neverRead)
        XCTAssertEqual(unread.map(\.kindRaw), steady.elements.map(\.kindRaw))
        XCTAssertEqual(unread.last?.kind, .callEnded)
    }

    /// Frames go to every reader too, and a slow one keeps only its newest.
    func testEveryFrameReaderHearsTheFarEnd() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }

        let (aliceCall, bobCall) = try await placeAndAnswer(alice, bob)
        defer { aliceCall.close(); bobCall.close() }
        let aliceMedia = try XCTUnwrap(aliceCall.media)
        let bobMedia = try XCTUnwrap(bobCall.media)

        let first = Recorder(bobMedia.frames())
        let second = Recorder(bobMedia.frames())
        let slow = bobMedia.frames(bufferingNewest: 2)
        // A square wave, not a constant: a codec is free to take a
        // constant level out as the DC offset it is.
        let tone = (0..<(aliceMedia.frameSamples * 25)).map { index -> Int16 in
            (index / 8) % 2 == 0 ? 8192 : -8192
        }
        aliceMedia.sendAudio(tone)

        func loud(_ frame: [Int16]) -> Bool { frame.contains { abs(Int32($0)) > 2048 } }
        let firstLoud = await first.count(atLeast: 10, within: 5, where: loud)
        let secondLoud = await second.count(atLeast: 10, within: 5, where: loud)
        XCTAssertGreaterThanOrEqual(firstLoud, 10, "the first reader did not hear the tone")
        XCTAssertGreaterThanOrEqual(secondLoud, 10, "the second reader did not hear the tone")
        XCTAssertEqual(bobMedia.debugFrameReaders, 3)

        bobCall.close()
        let unread = await drain(slow)
        XCTAssertLessThanOrEqual(unread.count, 2, "a reader bounded to two frames must keep at most two")
        let firstFinished = await first.finished(within: 5)
        XCTAssertTrue(firstFinished, "frame streams must finish when the media is closed")
        XCTAssertEqual(bobMedia.debugFrameReaders, 0)
    }

    /// Every stream a call hands out finishes when the call ends, with no
    /// `close()` needed; one taken after the end is handed that end and
    /// finished at once, and a digit stream taken then is empty.
    func testEveryStreamFinishesWhenTheCallEnds() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }

        let (aliceCall, bobCall) = try await placeAndAnswer(alice, bob)
        defer { aliceCall.close(); bobCall.close() }

        let events = Recorder(aliceCall.events())
        let digits = Recorder(aliceCall.dtmf())
        let frames = Recorder(try XCTUnwrap(aliceCall.media).frames())
        try bobCall.hangup()

        let eventsFinished = await events.finished(within: 5)
        let digitsFinished = await digits.finished(within: 5)
        let framesFinished = await frames.finished(within: 5)
        XCTAssertTrue(eventsFinished, "the event stream did not finish when the call ended")
        XCTAssertTrue(digitsFinished, "the digit stream did not finish when the call ended")
        XCTAssertTrue(framesFinished, "the frame stream did not finish when the call's media ended")
        XCTAssertEqual(events.elements.last?.kind, .callEnded)
        XCTAssertEqual(events.elements.last?.callData?.endReason, .remoteHangup)
        XCTAssertTrue(aliceCall.ended)

        let late = await drain(aliceCall.events())
        XCTAssertEqual(late.map(\.kind), [.callEnded])
        XCTAssertEqual(late.first?.callData?.endReason, .remoteHangup)
        let lateDigits = await drain(aliceCall.dtmf())
        XCTAssertEqual(lateDigits, [])
        XCTAssertEqual(aliceCall.debugEventReaders, 0)
    }

    /// The end-of-call record travels in `.mediaStatistics` itself, is kept
    /// on the call, and is what `Media.statistics()` answers once the stream
    /// is gone, where the library alone says `.wrongState`.
    func testTheEndOfCallRecordIsDecodedKeptAndStillReadable() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }

        let (aliceCall, bobCall) = try await placeAndAnswer(alice, bob)
        defer { aliceCall.close(); bobCall.close() }
        let media = try XCTUnwrap(aliceCall.media)
        for _ in 0..<5 {
            media.sendAudio([Int16](repeating: 0, count: media.frameSamples))
        }
        let sent = await eventually(within: 5) { ((try? media.statistics().packets_sent) ?? 0) >= 5 }
        XCTAssertTrue(sent, "the frames given were never sent")

        let stackEvents = Recorder(alice.events())
        try bobCall.hangup()
        let recorded = await stackEvents.first(within: 5) {
            $0.kind == .mediaStatistics && $0.call == aliceCall.handle
        }
        let record = try XCTUnwrap(recorded?.mediaData?.statistics, "the end-of-call record was not decoded")
        XCTAssertGreaterThanOrEqual(record.packets_sent, 5)
        XCTAssertEqual(record.size, MemoryLayout.size(ofValue: record))

        let kept = try XCTUnwrap(aliceCall.finalStatistics, "the call did not keep its record")
        XCTAssertEqual(kept.packets_sent, record.packets_sent)
        XCTAssertThrowsError(try Sipral.mediaStatistics(media: media.handle, nowMs: alice.nowMs())) { error in
            XCTAssertEqual((error as? SipralError)?.status, .wrongState, "the library itself has nothing left")
        }
        XCTAssertEqual(try media.statistics().packets_sent, record.packets_sent)
    }

    /// A stack's stream finishes when the stack closes, and one taken after
    /// that is finished from the start.
    func testStackStreamsFinishWhenTheStackCloses() async throws {
        let stack = try SipralStack(audio: .application)
        let first = Recorder(stack.events())
        let second = Recorder(stack.events())

        stack.close()
        let firstFinished = await first.finished(within: 5)
        let secondFinished = await second.finished(within: 5)
        XCTAssertTrue(firstFinished && secondFinished)
        let late = await drain(stack.events())
        XCTAssertEqual(late.count, 0)
    }

    func testHandlesReleaseWithNoUseAfterFreeWhilePendingEventsExist() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }

        let (aliceCall, bobCall) = try await placeAndAnswer(alice, bob)

        // Hang up and close immediately, without draining `events()` first --
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

    /// The caller cancels (CANCEL) before the callee ever takes the call:
    /// `takeIncomingCall` must not hand back a `Call` that can never end.
    /// Reproduces `intern/rapoarte/2026-09-25-review-day.json`'s "swift"
    /// finding on `SipralStack.takeIncomingCall`.
    func testTakeIncomingCallOnAHandleThatEndedBeforeItWasTakenThrowsAndCleansUp() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }

        let aliceAccount = try alice.addAccount(
            aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress
        )
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress)

        let bobEvents = Recorder(bob.events())
        let aliceCall = try alice.placeCall(account: aliceAccount, target: "sip:bob@\(bob.bindAddress)")

        let incoming = await bobEvents.first(within: 5) { $0.kind == .incomingCall }
        let event = try XCTUnwrap(incoming, "no incoming call arrived")

        // Alice gives up before bob ever calls takeIncomingCall: bob's
        // stack raises callEnded for this handle with no Call registered
        // to receive it, exactly the gap the finding describes.
        try aliceCall.hangup()
        aliceCall.close()
        let ended = await bobEvents.first(within: 5) { $0.kind == .callEnded && $0.call == event.call }
        XCTAssertNotNil(ended, "bob's stack must have observed the call end before takeIncomingCall runs")

        XCTAssertThrowsError(try bob.takeIncomingCall(event)) { error in
            guard let sipralError = error as? SipralError else {
                XCTFail("expected a SipralError, got \(error)")
                return
            }
            XCTAssertEqual(sipralError.status, .staleHandle)
        }
        XCTAssertNil(bob.callFor(event.call), "a Call minted on a dead handle must not stay registered")
    }

    /// `Call.close()`'s own doc comment promises "idempotent, and safe to
    /// call regardless of how the call ended" -- two callers racing to close
    /// the same call, such as a `CALL_ENDED` handler and a user action
    /// landing at once. Sixteen concurrent closers on a call whose media
    /// never started (so the only thing a non-idempotent `close()` would do
    /// twice is close the raw `mediaSocket` descriptor) must not hang.
    func testCloseFromManyConcurrentCallersDoesNotHang() throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
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
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
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
