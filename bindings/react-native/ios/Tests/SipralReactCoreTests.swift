// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import Foundation
import Sipral
import XCTest
@testable import SipralReactBridge

/// Everything one phone's module emitted, and a way to wait for one of it.
private final class Phone: @unchecked Sendable {
    private let lock = NSLock()
    private var seen: [[String: Any]] = []
    private(set) var core: SipralReactCore!
    let aor: String
    var address = ""

    init(_ name: String) throws {
        aor = "sip:\(name)@sipral.invalid"
        core = SipralReactCore(emit: { [weak self] event in self?.record(event) }, audio: { _ in .application })
        address = try core.open(SipralOpenOptions(bindHost: "127.0.0.1"))
    }

    private func record(_ event: [String: Any]) {
        lock.lock()
        defer { lock.unlock() }
        seen.append(event)
    }

    var events: [[String: Any]] {
        lock.lock()
        defer { lock.unlock() }
        return seen
    }

    var count: Int { events.count }

    func await(
        _ what: String, after: Int = 0, within seconds: Double = 15,
        file: StaticString = #filePath, line: UInt = #line,
        _ matches: ([String: Any]) -> Bool
    ) async throws -> [String: Any] {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if let found = events.dropFirst(after).first(where: matches) { return found }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("\(aor) never saw \(what); saw \(events.map { $0["kind"] as? String ?? "?" })", file: file, line: line)
        throw SipralRefusal("timedOut", what)
    }
}

private func refusal(_ code: String, file: StaticString = #filePath, line: UInt = #line, _ body: () throws -> Void) {
    XCTAssertThrowsError(try body(), file: file, line: line) { error in
        XCTAssertEqual((error as? SipralRefusal)?.code, code, "\(error)", file: file, line: line)
    }
}

/// The iOS half of the React Native package without React Native: three
/// cores on loopback, driven by the handles and options JavaScript would
/// hand them, every event read back as the dictionary the bridge would
/// emit. The Swift counterpart of the Android half's SipralReactCoreCheck.kt.
final class SipralReactCoreTests: XCTestCase {
    func testACallThroughEveryStepJavaScriptCanAskFor() async throws {
        let alice = try Phone("alice")
        let bob = try Phone("bob")
        let carol = try Phone("carol")
        defer { alice.core.close(); bob.core.close(); carol.core.close() }

        refusal("wrongState") { _ = try alice.core.open(SipralOpenOptions(bindHost: "127.0.0.1")) }
        let aliceLine = try alice.core.addAccount(SipralAccountOptions(aor: alice.aor, registrarAddress: bob.address))
        _ = try bob.core.addAccount(SipralAccountOptions(aor: bob.aor, registrarAddress: carol.address))
        _ = try carol.core.addAccount(SipralAccountOptions(aor: carol.aor, registrarAddress: bob.address))
        refusal("invalidHandle") { try alice.core.register("424242") }

        // Placed, rung, answered once.
        let toBob = try alice.core.placeCall(aliceLine, "sip:bob@\(bob.address)", destination: nil, codecs: nil)
        let rang = try await bob.await("the incoming call") { $0["kind"] as? String == "incomingCall" }
        let fromAlice = try XCTUnwrap(rang["call"] as? String)
        XCTAssertEqual(rang["callState"] as? String, "incoming")
        XCTAssertTrue((rang["fromUri"] as? String ?? "").contains("alice@"))
        refusal("invalidHandle") { try bob.core.hold(fromAlice) }
        try bob.core.answer(fromAlice)
        refusal("wrongState") { try bob.core.answer(fromAlice) }
        let confirmed = try await alice.await("the call confirmed") {
            $0["kind"] as? String == "callConfirmed" && $0["call"] as? String == toBob
        }
        XCTAssertEqual(confirmed["callState"] as? String, "confirmed")

        // Held, resumed.
        var mark = alice.count
        try alice.core.hold(toBob)
        _ = try await alice.await("the hold", after: mark) {
            $0["kind"] as? String == "sessionChanged" && $0["heldHere"] as? Bool == true
        }
        mark = alice.count
        try alice.core.resume(toBob)
        _ = try await alice.await("the resume", after: mark) {
            $0["kind"] as? String == "sessionChanged" && $0["heldHere"] as? Bool == false
        }

        // Digits, read back one by one on Bob's side.
        mark = bob.count
        try alice.core.sendDtmf(toBob, "5#")
        _ = try await bob.await("the 5", after: mark) {
            $0["kind"] as? String == "digitReceived" && $0["digit"] as? String == "5"
        }
        _ = try await bob.await("the #", after: mark) {
            $0["kind"] as? String == "digitReceived" && $0["digit"] as? String == "#"
        }
        refusal("invalidArgument") { try alice.core.sendDtmf(toBob, "5x") }

        // A blind transfer, taken by Bob, answered by Carol, reported to Alice.
        let target = "sip:carol@\(carol.address)"
        try alice.core.transfer(toBob, to: target)
        let asked = try await bob.await("the transfer request") { $0["kind"] as? String == "transferRequested" }
        XCTAssertEqual(asked["call"] as? String, fromAlice)
        XCTAssertEqual(asked["target"] as? String, target)
        XCTAssertEqual(asked["attended"] as? Bool, false)
        let toCarol = try bob.core.acceptTransfer(fromAlice)
        refusal("wrongState") { _ = try bob.core.acceptTransfer(fromAlice) }
        let ringing = try await carol.await("the transferred call") { $0["kind"] as? String == "incomingCall" }
        try carol.core.answer(try XCTUnwrap(ringing["call"] as? String))
        let done = try await alice.await("the transfer's outcome") {
            $0["kind"] as? String == "transferDone" && $0["call"] as? String == toBob
        }
        let status = try XCTUnwrap(done["statusCode"] as? Int)
        XCTAssertTrue((200...299).contains(status), "the transfer ended \(status)")

        // The transferred leg ends when the transfer has worked; its handle goes with it.
        let ended = try await alice.await("the transferred call's end") {
            $0["kind"] as? String == "callEnded" && $0["call"] as? String == toBob
        }
        XCTAssertEqual(ended["endReason"] as? String, "localHangup")
        refusal("invalidHandle") { try alice.core.hold(toBob) }
        try bob.core.hangup(toCarol)
        _ = try await carol.await("the end of the call Bob placed") { $0["kind"] as? String == "callEnded" }

        // A second call, turned away with a final response.
        mark = bob.count
        let second = try alice.core.placeCall(aliceLine, "sip:bob@\(bob.address)", destination: nil, codecs: nil)
        let again = try await bob.await("the second call", after: mark) { $0["kind"] as? String == "incomingCall" }
        try bob.core.reject(try XCTUnwrap(again["call"] as? String), code: 486)
        let refused = try await alice.await("the refusal") {
            $0["kind"] as? String == "callEnded" && $0["call"] as? String == second
        }
        XCTAssertEqual(refused["endReason"] as? String, "refused")
        XCTAssertEqual(refused["statusCode"] as? Int, 486)

        // Every dictionary is the spec's shape: a camel-case kind, handles as strings.
        for event in alice.events {
            let kind = try XCTUnwrap(event["kind"] as? String)
            XCTAssertTrue(kind.first?.isLowercase == true && !kind.contains("_"), kind)
            XCTAssertNotNil(event["call"] as? String)
            XCTAssertNotNil(event["account"] as? String)
            XCTAssertNotNil(event["kindName"] as? String)
        }

        alice.core.close()
        refusal("closed") { _ = try alice.core.addAccount(SipralAccountOptions(aor: alice.aor, registrarAddress: bob.address)) }
    }

    func testTheBridgeSettlesThroughTheBlocksAPromiseIs() async throws {
        let core = SipralReactCore(emit: { _ in }, audio: { _ in .application })
        let bridge = SipralReactBridge(core: core)
        defer { core.close() }

        let opened = expectation(description: "open resolved")
        var address: String?
        bridge.open(["bindHost": "127.0.0.1"], resolve: { value in
            address = value as? String
            opened.fulfill()
        }, reject: { code, message, _ in XCTFail("open refused: \(code) \(message)") })
        await fulfillment(of: [opened], timeout: 10)
        XCTAssertTrue(address?.hasPrefix("127.0.0.1:") == true, "\(String(describing: address))")

        let refused = expectation(description: "hold rejected")
        var code: String?
        bridge.hold("7", resolve: { _ in XCTFail("hold on no call resolved") }, reject: { refusal, _, _ in
            code = refusal
            refused.fulfill()
        })
        await fulfillment(of: [refused], timeout: 10)
        XCTAssertEqual(code, "invalidHandle")

        let options = SipralOpenOptions(["bindHost": "192.0.2.10", "bindPort": NSNumber(value: 5070), "manualAudio": NSNumber(value: true), "signalling": "tls"])
        XCTAssertEqual(options.bindHost, "192.0.2.10")
        XCTAssertEqual(options.bindPort, 5070)
        XCTAssertTrue(options.manualAudio)
        XCTAssertEqual(options.signalling, "tls")
        XCTAssertEqual(SipralAccountOptions(["aor": "sip:a@b", "registrarAddress": "c:1", "expiresSeconds": NSNumber(value: 300)]).expiresSeconds, 300)
    }

    /// A status reaches JavaScript by its name, and one this build has no
    /// name for as the platform's, as the Android half says it.
    func testALibraryRefusalIsNamedByItsStatus() {
        XCTAssertEqual(SipralReactCore.refusal(of: SipralError(status: .busy, message: "")).code, "busy")
        XCTAssertEqual(SipralReactCore.refusal(of: SipralError(code: 999, message: "")).code, "platform")
    }
}
