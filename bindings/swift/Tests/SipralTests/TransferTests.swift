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
}
