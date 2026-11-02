// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import XCTest
@testable import Sipral

/// A blind transfer through this layer: Alice calls Bob, asks him with
/// `Call.transfer(to:)` to call Carol instead, Bob's application reads the
/// request's `transferData` and takes it with `acceptReferral`, Carol's
/// phone rings, and Alice hears how it went. The Swift counterpart of
/// `bindings/kotlin`'s `TransferCheck.kt`.
final class TransferTests: XCTestCase {
    func testABlindTransferRingsTheTargetAndReportsBack() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        let carol = try SipralStack(audio: .application)
        defer { alice.close(); bob.close(); carol.close() }
        let aliceLine = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress)
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: carol.bindAddress)
        _ = try carol.addAccount(aor: "sip:carol@sipral.invalid", registrarAddress: bob.bindAddress)
        let bobEvents = Recorder(bob.events())
        let carolEvents = Recorder(carol.events())

        let toBob = try alice.placeCall(account: aliceLine, target: "sip:bob@\(bob.bindAddress)")
        defer { toBob.close() }
        let aliceEvents = Recorder(toBob.events())
        let rang = await bobEvents.first(within: 10) { $0.kind == .incomingCall }
        let fromAlice = try bob.answerCall(try XCTUnwrap(rang, "Alice's call never reached Bob"))
        defer { fromAlice.close() }
        let confirmed = await aliceEvents.first(within: 10) { $0.kind == .callConfirmed }
        XCTAssertNotNil(confirmed, "Alice's call was never confirmed")

        let target = "sip:carol@\(carol.bindAddress)"
        try toBob.transfer(to: target)
        let asked = await bobEvents.first(within: 10) { $0.kind == .transferRequested }
        let request = try XCTUnwrap(asked, "Bob was never asked")
        let wanted = try XCTUnwrap(request.transferData, "the request carried no transfer payload")
        XCTAssertEqual(wanted.target, target)
        XCTAssertFalse(wanted.attended, "a blind transfer names no dialog to replace")

        let placed = try bob.acceptReferral(request)
        defer { placed.close() }
        let ringing = await carolEvents.first(within: 10) { $0.kind == .incomingCall }
        let answered = try carol.answerCall(try XCTUnwrap(ringing, "the transfer never rang Carol"))
        defer { answered.close() }

        let done = await aliceEvents.first(within: 15) { $0.kind == .transferDone }
        let outcome = try XCTUnwrap(try XCTUnwrap(done, "Alice never heard how it went").transferData)
        XCTAssertTrue((200...299).contains(outcome.statusCode), "the transfer ended \(outcome.statusCode)")
    }

    /// An attended transfer: Alice consults Carol from the line her call
    /// with Bob is on, then hands Bob over with `Call.transfer(to:)`. Bob
    /// is asked to call Carol with `Replaces`; Carol takes such an INVITE
    /// only from her call's own far end (RFC 3891 §3, the stack's default),
    /// so on loopback she answers 403, Alice hears it, and her call with Bob
    /// stays up. The Swift counterpart of the .NET binding's test.
    func testAnAttendedTransferConsultsFromTheSameLineAndNamesTheConsultation() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        let carol = try SipralStack(audio: .application)
        defer { alice.close(); bob.close(); carol.close() }
        let aliceLine = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress)
        // Bob's transfer INVITE goes to Carol, not back to Alice
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: carol.bindAddress)
        _ = try carol.addAccount(aor: "sip:carol@sipral.invalid", registrarAddress: alice.bindAddress)
        let bobEvents = Recorder(bob.events())
        let carolEvents = Recorder(carol.events())

        let toBob = try alice.placeCall(account: aliceLine, target: "sip:bob@\(bob.bindAddress)")
        defer { toBob.close() }
        let aliceEvents = Recorder(toBob.events())
        let rang = await bobEvents.first(within: 10) { $0.kind == .incomingCall }
        let fromAlice = try bob.answerCall(try XCTUnwrap(rang, "Alice's call never reached Bob"))
        defer { fromAlice.close() }
        let up = await aliceEvents.first(within: 10) { $0.kind == .callConfirmed }
        XCTAssertNotNil(up, "Alice's call was never confirmed")

        try toBob.hold()
        let toCarol = try toBob.consult(target: "sip:carol@\(carol.bindAddress)", destination: carol.bindAddress)
        defer { toCarol.close() }
        XCTAssertNotEqual(toCarol.handle, toBob.handle)
        let consultEvents = Recorder(toCarol.events())
        let consulted = await carolEvents.first(within: 10) { $0.kind == .incomingCall }
        let carolsCall = try XCTUnwrap(consulted, "the consultation never reached Carol")
        XCTAssertEqual(carolsCall.callData?.fromUri, "sip:alice@sipral.invalid", "the consultation left from another line")
        let fromConsultation = try carol.answerCall(carolsCall)
        defer { fromConsultation.close() }
        let consultationUp = await consultEvents.first(within: 10) { $0.kind == .callConfirmed }
        XCTAssertNotNil(consultationUp, "the consultation was never confirmed")
        XCTAssertEqual(try toCarol.state, .consulting, "the stack knows it consults")
        XCTAssertThrowsError(
            try toBob.consult(target: "sip:carol@\(carol.bindAddress)", destination: carol.bindAddress),
            "one consultation at a time"
        )

        try toBob.transfer(to: toCarol)
        let asked = await bobEvents.first(within: 10) { $0.kind == .transferRequested }
        let request = try XCTUnwrap(asked, "Bob was never asked")
        let wanted = try XCTUnwrap(request.transferData, "the request carried no transfer payload")
        XCTAssertTrue(wanted.attended, "an attended transfer names the dialog to replace")
        XCTAssertEqual(wanted.target, "sip:carol@\(carol.bindAddress)")

        let placed = try bob.acceptReferral(request)
        defer { placed.close() }
        let done = await aliceEvents.first(within: 15) { $0.kind == .transferDone }
        let outcome = try XCTUnwrap(try XCTUnwrap(done, "Alice never heard how it went").transferData)
        XCTAssertEqual(outcome.statusCode, 403)
        XCTAssertEqual(try carol.counters().screenedRefusedByReplaces, 1)
        XCTAssertEqual(try toBob.state, .confirmed, "a failed transfer lost the call")
    }
}
