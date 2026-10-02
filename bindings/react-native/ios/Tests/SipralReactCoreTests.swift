// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import Foundation
import CSipral
@testable import Sipral
import XCTest
@testable import SipralReactBridge

/// Everything one phone's module emitted, and a way to wait for one of it.
private final class Phone: @unchecked Sendable {
    private let lock = NSLock()
    private var seen: [[String: Any]] = []
    private(set) var core: SipralReactCore!
    let aor: String
    var address = ""

    init(_ name: String, audio: AudioMode = .application) throws {
        aor = "sip:\(name)@sipral.invalid"
        core = SipralReactCore(emit: { [weak self] event in self?.record(event) }, audio: { _ in audio })
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

/// Whether `condition` came true within `seconds`.
private func waitFor(_ seconds: Double, _ condition: () -> Bool) async -> Bool {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
        if condition() { return true }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    return condition()
}

/// A registrar that takes one TCP connection on loopback and keeps the
/// first request on it.
private final class OneRegister: @unchecked Sendable {
    private let listener: Int32
    private let lock = NSLock()
    private var request: String?
    let address: String

    init() throws {
        let made = socket(AF_INET, SOCK_STREAM, 0)
        listener = made
        var bound = sockaddr_in()
        bound.sin_family = sa_family_t(AF_INET)
        bound.sin_addr.s_addr = inet_addr("127.0.0.1")
        bound.sin_port = 0
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let ready = withUnsafeMutablePointer(to: &bound) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { at in
                bind(made, at, length) == 0 && listen(made, 4) == 0 && getsockname(made, at, &length) == 0
            }
        }
        guard ready else { throw SipralRefusal("platform", "the registrar could not listen") }
        address = "127.0.0.1:\(UInt16(bigEndian: bound.sin_port))"
        Thread { [self] in serve() }.start()
    }

    deinit { close(listener) }

    private func serve() {
        let connection = accept(listener, nil, nil)
        guard connection >= 0 else { return }
        defer { close(connection) }
        var held = [UInt8]()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while !String(decoding: held, as: UTF8.self).contains("\r\n\r\n") {
            let read = recv(connection, &buffer, buffer.count, 0)
            guard read > 0 else { break }
            held += buffer[0..<read]
        }
        lock.withLock { request = String(decoding: held, as: UTF8.self) }
    }

    func first(within seconds: Double) -> String? {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if let seen = lock.withLock({ request }) { return seen }
            usleep(10_000)
        }
        return nil
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

    /// What ABI 0.34 brought to the module: a core opened with no address
    /// advertises the route toward its server -- loopback here -- an account
    /// named by a URI is located and the event flattened with where, the
    /// options reach the library, and the diagnostic trace is turned on.
    func testAnAccountNamedByAUriIsLocatedAndTheOptionsReachTheLibrary() async throws {
        let seen = NSLock()
        nonisolated(unsafe) var events: [[String: Any]] = []
        let core = SipralReactCore(emit: { event in seen.withLock { events.append(event) } }, audio: { _ in .application })
        defer { core.close() }
        refusal("invalidArgument") { _ = try core.open(SipralOpenOptions(["srtp": "sometimes"])) }
        refusal("invalidArgument") { _ = try core.open(SipralOpenOptions(["pseudonymSalt": "0g"])) }
        refusal("invalidArgument") { _ = try core.open(SipralOpenOptions(["pseudonymSalt": "0011"])) }
        let address = try core.open(SipralOpenOptions([
            "srtp": "bestEffort", "srtpSuites": "AES_CM_128_HMAC_SHA1_80", "pathMtu": NSNumber(value: 1500),
            "datagramWithoutStreamBytes": NSNumber(value: 4000), "pseudonymSalt": "00112233445566778899aabbccddeeff",
            "diagnosticTrace": NSNumber(value: false),
        ]))
        XCTAssertTrue(address.hasPrefix("127.0.0.1:"), address)
        try core.setDiagnosticTrace(true)
        refusal("invalidArgument") { _ = try core.addAccount(SipralAccountOptions(aor: "sip:alice@sipral.invalid")) }
        let line = try core.addAccount(SipralAccountOptions([
            "aor": "sip:alice@sipral.invalid", "registrar": "sip:sipral.invalid", "serverUri": "sip:localhost:5999",
            "keepaliveMs": NSNumber(value: 15000),
        ]))
        try core.register(line)
        var located: [String: Any]?
        let deadline = Date().addingTimeInterval(10)
        while located == nil, Date() < deadline {
            located = seen.withLock { events.first { $0["kind"] as? String == "located" } }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        let targets = try XCTUnwrap(located?["targets"] as? String)
        XCTAssertTrue(targets.split(separator: ",").contains("127.0.0.1:5999"), targets)
        XCTAssertEqual(located?["account"] as? String, line)
    }

    /// ABI 0.35: an account on a TCP connection of its own, beside the UDP
    /// socket, registers over a connection the core opened; a protocol that
    /// is neither is refused; and the settings come back as the spec's
    /// NativeSettings, the echo switch among them.
    func testAnAccountOnAConnectionOfItsOwnAndTheSettingsReadBack() async throws {
        let registrar = try OneRegister()
        let core = SipralReactCore(emit: { _ in }, audio: { _ in .application })
        defer { core.close() }
        _ = try core.open(SipralOpenOptions([
            "bindHost": "127.0.0.1", "systemEchoCancellation": NSNumber(value: false),
            "srtpSuites": "AES_CM_128_HMAC_SHA1_32,AES_CM_128_HMAC_SHA1_80",
        ]))
        refusal("invalidArgument") {
            _ = try core.addAccount(SipralAccountOptions([
                "aor": "sip:alice@sipral.invalid", "registrarAddress": registrar.address, "streamProtocol": "sctp",
            ]))
        }
        let line = try core.addAccount(SipralAccountOptions([
            "aor": "sip:alice@sipral.invalid", "registrar": "sip:sipral.invalid",
            "registrarAddress": registrar.address, "streamProtocol": "tcp",
        ]))
        try core.register(line)
        let register = try XCTUnwrap(registrar.first(within: 10), "no REGISTER over a connection")
        XCTAssertTrue(register.hasPrefix("REGISTER "), register)
        XCTAssertTrue(register.contains("Via: SIP/2.0/TCP "), register)
        XCTAssertTrue(register.contains(";transport=tcp"), register)

        let settings = try core.settings()
        XCTAssertEqual(settings["transport"] as? String, "udp")
        XCTAssertEqual(settings["srtpSuites"] as? String, "2,1")
        XCTAssertEqual(settings["systemEchoCancellation"] as? Bool, false)
        XCTAssertEqual(settings["pseudonymSalted"] as? Bool, false)
        XCTAssertGreaterThan(settings["codecCount"] as? Int ?? 0, 0)
    }

    /// ABI 0.36: the realms an account names and what a held party is sent
    /// reach the library through the core, a value of neither the core
    /// knows is refused before it, and a declined challenge is flattened
    /// with its refusal, server and realms.
    func testTheRealmsAndTheHeldAudioReachTheLibrary() throws {
        let refused = SipralReactCore(emit: { _ in }, audio: { _ in .application })
        refusal("invalidArgument") {
            _ = try refused.open(SipralOpenOptions(["bindHost": "127.0.0.1", "heldAudio": "music"]))
        }
        let core = SipralReactCore(emit: { _ in }, audio: { _ in .application })
        defer { core.close() }
        _ = try core.open(SipralOpenOptions(["bindHost": "127.0.0.1", "heldAudio": "application"]))
        _ = try core.addAccount(SipralAccountOptions([
            "aor": "sip:alice@sipral.invalid", "registrarAddress": "127.0.0.1:5060",
            "authUser": "alice", "authPassword": "open sesame", "realms": "registrar.example\nsbc, inc.",
        ]))
        refusal("invalidArgument") {
            _ = try core.addAccount(SipralAccountOptions([
                "aor": "sip:bob@sipral.invalid", "registrarAddress": "127.0.0.1:5060",
                "realms": "registrar.example\nsbc\texample",
            ]))
        }

        let server = "203.0.113.9:5060"
        let realms = "sbc.example\ncallee, inc."
        let flat = server.withCString { serverText in
            realms.withCString { realmsText in
                var raw = sipral_event_t()
                raw.size = MemoryLayout<sipral_event_t>.size
                raw.kind = SipralEventKind.challengeDeclined.rawValue
                raw.account = 7
                raw.payload.challenge.refusal = SipralChallengeRefusal.notTheAccountsRealm.rawValue
                raw.payload.challenge.server = serverText
                raw.payload.challenge.server_len = server.utf8.count
                raw.payload.challenge.realms = realmsText
                raw.payload.challenge.realms_len = realms.utf8.count
                return SipralReactCore.flatten(SipralEventDecoder.decode(raw))
            }
        }
        XCTAssertEqual(flat["kind"] as? String, "challengeDeclined")
        XCTAssertEqual(flat["account"] as? String, "7")
        XCTAssertEqual(flat["challengeRefusal"] as? String, "notTheAccountsRealm")
        XCTAssertEqual(flat["challengeServer"] as? String, server)
        XCTAssertEqual(flat["challengeRealms"] as? String, realms)
    }

    /// A call's own gain and mute through the core, on a stack in device mode
    /// whose devices stay closed under manual activation; a direction that is
    /// neither is refused, and so is a core in application mode.
    func testACallsOwnAudioIsSetAndReadBack() async throws {
        guard try Sipral.capabilities().features & Sipral.featureAudioDevice != 0 else {
            throw XCTSkip("this build has no audio engine for this platform")
        }
        let alice = try Phone("alice", audio: .device(activation: .manual))
        let bob = try Phone("bob")
        defer { alice.core.close(); bob.core.close() }
        let line = try alice.core.addAccount(SipralAccountOptions(aor: alice.aor, registrarAddress: bob.address))
        _ = try bob.core.addAccount(SipralAccountOptions(aor: bob.aor, registrarAddress: alice.address))
        let call = try alice.core.placeCall(line, "sip:bob@\(bob.address)", destination: nil, codecs: nil)
        let rang = try await bob.await("the incoming call") { $0["kind"] as? String == "incomingCall" }
        let taken = try XCTUnwrap(rang["call"] as? String)
        try bob.core.answer(taken)
        _ = try await alice.await("the media") { $0["kind"] as? String == "mediaStarted" && $0["call"] as? String == call }
        let carried = await waitFor(5) { (try? alice.core.setCallGain(call, "output", 0.5)) != nil }
        XCTAssertTrue(carried, "the engine never took the call's media")
        try alice.core.setCallMuted(call, "input", true)
        let output = try alice.core.callAudio(call, "output")
        XCTAssertEqual(output["gain"] as? Double, 0.5)
        XCTAssertEqual(output["muted"] as? Bool, false)
        XCTAssertEqual(output["level"] as? Double, 0)
        XCTAssertEqual(try alice.core.callAudio(call, "input")["muted"] as? Bool, true)
        refusal("invalidArgument") { try alice.core.setCallMuted(call, "sideways", true) }
        refusal("notSupported") { try bob.core.setCallGain(taken, "output", 1) }
    }

    /// maxDialogs reaches the library through the core: at a ceiling of one
    /// call, a second placed while the first still rings is refused as
    /// limitReached.
    func testACallPlacedPastMaxDialogsIsRefused() async throws {
        let capped = SipralReactCore(emit: { _ in }, audio: { _ in .application })
        let bob = try Phone("bob")
        defer { capped.close(); bob.core.close() }
        let address = try capped.open(SipralOpenOptions(["bindHost": "127.0.0.1", "maxDialogs": NSNumber(value: 1)]))
        let line = try capped.addAccount(SipralAccountOptions(aor: "sip:capped@sipral.invalid", registrarAddress: bob.address))
        _ = try bob.core.addAccount(SipralAccountOptions(aor: bob.aor, registrarAddress: address))
        _ = try capped.placeCall(line, "sip:bob@\(bob.address)", destination: nil, codecs: nil)
        _ = try await bob.await("the first call") { $0["kind"] as? String == "incomingCall" }
        refusal("limitReached") {
            _ = try capped.placeCall(line, "sip:bob@\(bob.address)", destination: nil, codecs: nil)
        }
    }

    /// A status reaches JavaScript by its name, and one this build has no
    /// name for as the platform's, as the Android half says it.
    func testALibraryRefusalIsNamedByItsStatus() {
        XCTAssertEqual(SipralReactCore.refusal(of: SipralError(status: .busy, message: "")).code, "busy")
        XCTAssertEqual(SipralReactCore.refusal(of: SipralError(code: 999, message: "")).code, "platform")
    }
}
