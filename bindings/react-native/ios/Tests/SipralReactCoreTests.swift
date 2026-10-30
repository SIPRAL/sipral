// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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

    init(_ name: String, audio: AudioMode = .application, host: String = "127.0.0.1", codecs: String? = nil) throws {
        aor = "sip:\(name)@sipral.invalid"
        core = SipralReactCore(emit: { [weak self] event in self?.record(event) }, audio: { _ in audio })
        var options = SipralOpenOptions(bindHost: host)
        options.codecs = codecs
        address = try core.open(options)
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

/// A non-loopback IPv4 address of this machine, since RFC 8445 §5.1.1.1
/// keeps loopback out of ICE's candidates. Nothing leaves the machine.
private func hostAddress() throws -> String {
    var list: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&list) == 0, let start = list else { throw XCTSkip("no interfaces") }
    defer { freeifaddrs(list) }
    for entry in sequence(first: start, next: { $0.pointee.ifa_next }) {
        let flags = Int32(entry.pointee.ifa_flags)
        guard let address = entry.pointee.ifa_addr, address.pointee.sa_family == sa_family_t(AF_INET),
              flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0, flags & IFF_POINTOPOINT == 0 else { continue }
        var text = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { inet in
            var sin = inet.pointee.sin_addr
            _ = inet_ntop(AF_INET, &sin, &text, socklen_t(INET_ADDRSTRLEN))
        }
        return String(cString: text)
    }
    throw XCTSkip("no interface but loopback: ICE has no host candidate to test with")
}

/// The first of `events` that `matches`, or a refusal once `seconds` pass.
private func first(
    _ events: AsyncStream<SipralEvent>, within seconds: Double = 15,
    _ matches: @escaping @Sendable (SipralEvent) -> Bool
) async throws -> SipralEvent {
    let found = await withTaskGroup(of: SipralEvent?.self) { group in
        group.addTask {
            for await event in events where matches(event) { return event }
            return nil
        }
        group.addTask {
            try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            return nil
        }
        let winner = await group.next() ?? nil
        group.cancelAll()
        return winner
    }
    guard let found else { throw SipralRefusal("timedOut", "no matching event within \(seconds) s") }
    return found
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

/// A mailbox's server on a UDP socket on loopback: what reaches it, and the
/// answers and NOTIFYs it sends back.
private final class Mailbox: @unchecked Sendable {
    /// Two new messages, one of them urgent, and five old, for `account`.
    static func waiting(for account: String) -> String {
        "Messages-Waiting: yes\r\nMessage-Account: \(account)\r\nVoice-Message: 2/5 (1/0)\r\n"
    }

    private let socket: UDPSocket
    var address: String { socket.localAddress }

    init() throws {
        socket = try UDPSocket(host: "127.0.0.1", port: 0)
    }

    func close() {
        socket.close()
    }

    /// The next message that starts with `start` within `seconds`, and where
    /// it came from; anything else is let go.
    func next(_ start: String, within seconds: Double = 10) async -> (message: String, from: String)? {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            while let (data, from) = socket.receive() {
                let text = String(decoding: data, as: UTF8.self)
                if text.hasPrefix(start) { return (text, from) }
            }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        return nil
    }

    static func header(_ name: String, in message: String) -> String? {
        let head = message.components(separatedBy: "\r\n\r\n").first ?? message
        return head.components(separatedBy: "\r\n")
            .first { $0.lowercased().hasPrefix(name.lowercased() + ":") }
            .map { String($0.drop(while: { $0 != ":" }).dropFirst()).trimmingCharacters(in: .whitespaces) }
    }

    /// A response to `request`, its dialog's fields copied and `To` tagged.
    func answer(_ request: (message: String, from: String), _ status: String, more: String = "") {
        var lines = ["SIP/2.0 \(status)"]
        for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
            guard var value = Self.header(name, in: request.message) else { continue }
            if name == "To" && !value.contains(";tag=") {
                value += ";tag=mailbox"
            }
            lines.append("\(name): \(value)")
        }
        let text = lines.joined(separator: "\r\n") + "\r\n" + more + "Content-Length: 0\r\n\r\n"
        _ = socket.send(Array(text.utf8), to: request.from)
    }

    /// A `message-summary` NOTIFY to `aor` at `phone`: in the dialog
    /// `subscribe` opened, or outside any, the way a PBX that notifies
    /// unasked sends it.
    func notify(_ aor: String, at phone: String, in subscribe: String?) {
        let body = Self.waiting(for: aor)
        let dialog: String
        if let subscribe {
            dialog = "From: \(Self.header("To", in: subscribe) ?? "");tag=mailbox\r\n"
                + "To: \(Self.header("From", in: subscribe) ?? "")\r\n"
                + "Call-ID: \(Self.header("Call-ID", in: subscribe) ?? "")\r\n"
        } else {
            dialog = "From: <\(aor)>;tag=mailbox\r\nTo: <\(aor)>\r\nCall-ID: unasked-\(UUID().uuidString)\r\n"
        }
        let user = aor.dropFirst("sip:".count).prefix { $0 != "@" }
        let text = "NOTIFY sip:\(user)@\(phone) SIP/2.0\r\n"
            + "Via: SIP/2.0/UDP \(address);branch=z9hG4bK-\(UUID().uuidString.prefix(8))\r\n"
            + "Max-Forwards: 70\r\n"
            + dialog
            + "CSeq: 1 NOTIFY\r\n"
            + "Contact: <sip:mailbox@\(address)>\r\n"
            + "Event: message-summary\r\n"
            + "Subscription-State: active;expires=600\r\n"
            + "Content-Type: application/simple-message-summary\r\n"
            + "Content-Length: \(body.utf8.count)\r\n\r\n"
            + body
        _ = socket.send(Array(text.utf8), to: phone)
    }
}

private func refusal(_ code: String, file: StaticString = #filePath, line: UInt = #line, _ body: () throws -> Void) {
    XCTAssertThrowsError(try body(), file: file, line: line) { error in
        XCTAssertEqual((error as? SipralRefusal)?.code, code, "\(error)", file: file, line: line)
    }
}

/// Three cores on loopback, driven as JavaScript would, events read back as
/// the bridge's dictionaries.
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

        // A second call, rung, then turned away with a final response.
        mark = bob.count
        let second = try alice.core.placeCall(aliceLine, "sip:bob@\(bob.address)", destination: nil, codecs: nil)
        let again = try await bob.await("the second call", after: mark) { $0["kind"] as? String == "incomingCall" }
        try bob.core.ring(try XCTUnwrap(again["call"] as? String))
        _ = try await alice.await("the 180") {
            $0["kind"] as? String == "callProgress" && $0["call"] as? String == second && $0["statusCode"] as? Int == 180
        }
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

    /// No address advertises the route to the server; a URI-named account is
    /// located; options and the diagnostic trace reach the library.
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

    /// The rules as the hook applies them: a field matched in either form
    /// and any case, a folded one taken out whole, a response matched by
    /// its CSeq, the body untouched, nothing that does not fit changed.
    func testTheMessageRulesChangeWhatFitsThemAndNothingElse() throws {
        let rules = try SipralMessageRule.parse(
            "rule outgoing REGISTER\nset Max-Forwards:42\nset X-New:1\nremove subject\nadd X-Lab-Hook:a: b\n"
                + "rule incoming *\nremove X-Trace"
        )
        let register = Array((
            "REGISTER sip:example.com SIP/2.0\r\nv: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\r\n"
                + "Max-Forwards: 70\r\nmax-forwards: 69\r\ns: one,\r\n two\r\nCSeq: 1 REGISTER\r\n"
                + "Content-Length: 4\r\n\r\nbody"
        ).utf8)
        let changed = try XCTUnwrap(SipralMessageRule.apply(rules, outgoing: true, to: register))
        XCTAssertEqual(String(decoding: changed, as: UTF8.self),
            "REGISTER sip:example.com SIP/2.0\r\nv: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\r\n"
                + "Max-Forwards: 42\r\nCSeq: 1 REGISTER\r\nContent-Length: 4\r\nX-New: 1\r\nX-Lab-Hook: a: b\r\n\r\nbody")
        XCTAssertNil(SipralMessageRule.apply(rules, outgoing: false, to: register), "an incoming REGISTER has no X-Trace")
        let invite = Array("INVITE sip:bob@example.com SIP/2.0\r\nCSeq: 2 INVITE\r\n\r\n".utf8)
        XCTAssertNil(SipralMessageRule.apply(rules, outgoing: true, to: invite), "a rule for REGISTER changed an INVITE")
        let answer = Array("SIP/2.0 200 OK\r\nCSeq: 1 REGISTER\r\nX-Trace: 9\r\nX-Trace: 10\r\n\r\n".utf8)
        XCTAssertEqual(SipralMessageRule.apply(rules, outgoing: false, to: answer).map { String(decoding: $0, as: UTF8.self) },
            "SIP/2.0 200 OK\r\nCSeq: 1 REGISTER\r\n\r\n")
        XCTAssertNil(SipralMessageRule.apply(rules, outgoing: true, to: Array("REGISTER x SIP/2.0\r\n".utf8)),
            "a message with no end to its header was changed")
        XCTAssertEqual(try SipralMessageRule.parse(""), [])
        refusal("invalidArgument") { _ = try SipralMessageRule.parse("set X-A:1") }
        refusal("invalidArgument") { _ = try SipralMessageRule.parse("rule up *") }
        refusal("invalidArgument") { _ = try SipralMessageRule.parse("rule * *\nremove l") }
        refusal("invalidArgument") { _ = try SipralMessageRule.parse("rule * *\nadd X A:1") }
        refusal("invalidArgument") { _ = try SipralMessageRule.parse("rule * *\ndrop") }
    }

    /// Rules set from JavaScript change the REGISTER on the wire, and each
    /// message, as changed, is emitted while watched.
    func testTheMessageRulesReachTheWireAndTheMessagesAreHandedOver() async throws {
        let registrar = try OneRegister()
        let lock = NSLock()
        nonisolated(unsafe) var events: [[String: Any]] = []
        let core = SipralReactCore(emit: { event in lock.withLock { events.append(event) } }, audio: { _ in .application })
        defer { core.close() }
        refusal("closed") { try core.watchMessages(true) }
        _ = try core.open(SipralOpenOptions(["bindHost": "127.0.0.1"]))
        try core.setMessageRules("rule outgoing REGISTER\nset Max-Forwards:42\nadd X-Lab-Hook:1")
        try core.watchMessages(true)
        let line = try core.addAccount(SipralAccountOptions([
            "aor": "sip:alice@sipral.invalid", "registrar": "sip:sipral.invalid",
            "registrarAddress": registrar.address, "streamProtocol": "tcp",
        ]))
        try core.register(line)
        let register = try XCTUnwrap(registrar.first(within: 10), "no REGISTER over a connection")
        XCTAssertTrue(register.contains("\r\nMax-Forwards: 42\r\n"), register)
        XCTAssertTrue(register.contains("\r\nX-Lab-Hook: 1\r\n"), register)
        var handed: [String: Any]?
        let deadline = Date().addingTimeInterval(5)
        while handed == nil, Date() < deadline {
            handed = lock.withLock { events.first { $0["kind"] as? String == "messageSeen" } }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        let seen = try XCTUnwrap(handed, "no message was handed over")
        XCTAssertEqual(seen["outgoing"] as? Bool, true)
        XCTAssertEqual(seen["remote"] as? String, registrar.address)
        XCTAssertTrue((seen["message"] as? String ?? "").contains("\r\nX-Lab-Hook: 1\r\n"), "\(seen)")
        try core.setMessageRules("")
        try core.watchMessages(false)
    }

    /// An account on its own TCP connection registers, with its instance and
    /// its own fields on the REGISTER; an unknown protocol is refused;
    /// settings come back as NativeSettings.
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
            "instanceId": "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
            "headers": "X-Push-Key:k-17\nX-Note:a: b",
        ]))
        try core.register(line)
        let register = try XCTUnwrap(registrar.first(within: 10), "no REGISTER over a connection")
        XCTAssertTrue(register.hasPrefix("REGISTER "), register)
        XCTAssertTrue(register.contains("Via: SIP/2.0/TCP "), register)
        XCTAssertTrue(register.contains(";transport=tcp"), register)
        XCTAssertTrue(register.contains("+sip.instance=\"<urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>\""), register)
        XCTAssertTrue(register.contains("\r\nX-Push-Key: k-17\r\n"), register)
        XCTAssertTrue(register.contains("\r\nX-Note: a: b\r\n"), register)

        let settings = try core.settings()
        XCTAssertEqual(settings["transport"] as? String, "udp")
        XCTAssertEqual(settings["srtpSuites"] as? String, "2,1")
        XCTAssertEqual(settings["systemEchoCancellation"] as? Bool, false)
        XCTAssertEqual(settings["pseudonymSalted"] as? Bool, false)
        XCTAssertGreaterThan(settings["codecCount"] as? Int ?? 0, 0)
    }

    /// Realms and held audio reach the library, unknown values are refused,
    /// and a declined challenge is flattened.
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

        let authz = "https://as.example.com"
        let scope = "sip register"
        let token = authz.withCString { authzText in
            scope.withCString { scopeText in
                var raw = sipral_event_t()
                raw.size = MemoryLayout<sipral_event_t>.size
                raw.kind = SipralEventKind.tokenRequired.rawValue
                raw.account = 7
                raw.payload.token.error = SipralTokenError.invalidToken.rawValue
                raw.payload.token.proxy = SipralToggle.on.rawValue
                raw.payload.token.authz_server = authzText
                raw.payload.token.authz_server_len = authz.utf8.count
                raw.payload.token.scope = scopeText
                raw.payload.token.scope_len = scope.utf8.count
                return SipralReactCore.flatten(SipralEventDecoder.decode(raw))
            }
        }
        XCTAssertEqual(token["kind"] as? String, "tokenRequired")
        XCTAssertEqual(token["tokenError"] as? String, "invalidToken")
        XCTAssertEqual(token["tokenProxy"] as? Bool, true)
        XCTAssertEqual(token["tokenAuthzServer"] as? String, authz)
        XCTAssertEqual(token["tokenScope"] as? String, scope)
        XCTAssertEqual(token["tokenRealm"] as? String, "")

        var tested = sipral_event_t()
        tested.size = MemoryLayout<sipral_event_t>.size
        tested.kind = SipralEventKind.networkTest.rawValue
        tested.payload.network_test.test = 4
        tested.payload.network_test.verdict = SipralNetworkVerdict.acceptable.rawValue
        tested.payload.network_test.stun = SipralNetworkProbe.succeeded.rawValue
        tested.payload.network_test.nat = SipralNatKind.portChanged.rawValue
        tested.payload.network_test.server = SipralServerReach.answered.rawValue
        tested.payload.network_test.server_status = 200
        let found = SipralReactCore.flatten(SipralEventDecoder.decode(tested))
        XCTAssertEqual(found["kind"] as? String, "networkTest")
        XCTAssertEqual(found["test"] as? Int, 4)
        XCTAssertEqual(found["verdict"] as? String, "acceptable")
        XCTAssertEqual(found["stun"] as? String, "succeeded")
        XCTAssertEqual(found["nat"] as? String, "portChanged")
        XCTAssertEqual(found["server"] as? String, "answered")
        XCTAssertEqual(found["serverStatus"] as? Int, 200)
    }

    /// Per-call gain and mute in device mode with devices closed; bad
    /// directions and application mode are refused.
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

    /// Echo cancellation toggled and read back; refused in application mode.
    func testTheEchoCancellationIsSwitchedAndReadBack() throws {
        let bob = try Phone("bob")
        refusal("notSupported") { try bob.core.setSystemEchoCancellation(false) }
        bob.core.close()
        guard try Sipral.capabilities().features & Sipral.featureAudioDevice != 0 else {
            throw XCTSkip("this build has no audio engine for this platform")
        }
        let alice = try Phone("alice", audio: .device(activation: .manual))
        defer { alice.core.close() }
        try alice.core.setSystemEchoCancellation(false)
        XCTAssertEqual(try alice.core.settings()["systemEchoCancellation"] as? Bool, false)
        try alice.core.setSystemEchoCancellation(true)
        XCTAssertEqual(try alice.core.settings()["systemEchoCancellation"] as? Bool, true)
    }

    /// App rate: 24 kHz gives 480-sample frames, others refused, 0 resets.
    func testTheRateOfACallsFramesIsChosen() async throws {
        let alice = try Phone("alice")
        let bob = try Phone("bob")
        defer { alice.core.close(); bob.core.close() }
        let line = try alice.core.addAccount(SipralAccountOptions(aor: alice.aor, registrarAddress: bob.address))
        _ = try bob.core.addAccount(SipralAccountOptions(aor: bob.aor, registrarAddress: alice.address))
        let call = try alice.core.placeCall(line, "sip:bob@\(bob.address)", destination: nil, codecs: nil)
        let rang = try await bob.await("the incoming call") { $0["kind"] as? String == "incomingCall" }
        try bob.core.answer(try XCTUnwrap(rang["call"] as? String))
        _ = try await alice.await("the media") { $0["kind"] as? String == "mediaStarted" && $0["call"] as? String == call }
        let carried = await waitFor(5) { (try? alice.core.setAppRate(call, hz: 24_000)) != nil }
        XCTAssertTrue(carried, "the call's media never came up")
        let chosen = try alice.core.setAppRate(call, hz: 24_000)
        XCTAssertEqual(chosen["sampleRate"] as? Int, 24_000)
        XCTAssertEqual(chosen["frameSamples"] as? Int, 480)
        refusal("invalidArgument") { _ = try alice.core.setAppRate(call, hz: 44_100) }
        let codec = try alice.core.setAppRate(call, hz: 0)
        XCTAssertEqual((codec["sampleRate"] as? Int).map { $0 / 50 }, codec["frameSamples"] as? Int)
    }

    /// With maxDialogs 1, a second call is refused as limitReached.
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

    /// Per-call codecs: placed or answered with PCMA,PCMU it settles on PCMA;
    /// an answer keeps the offer's order.
    func testACallsOwnCodecsReachTheLibraryPlacedAndAnswered() async throws {
        let pcma = SipralCodec.pcma.rawValue
        do {
            let alice = try Phone("alice")
            let bob = try SipralStack(audio: .application, bindHost: "127.0.0.1")
            defer { alice.core.close(); bob.close() }
            let line = try alice.core.addAccount(SipralAccountOptions(aor: alice.aor, registrarAddress: bob.bindAddress))
            _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: alice.address)
            let arrivals = bob.events()
            _ = try alice.core.placeCall(line, "sip:bob@\(bob.bindAddress)", destination: nil, codecs: "PCMA,PCMU")
            let incoming = try await first(arrivals) { $0.kind == .incomingCall }
            let answered = try bob.answerCall(incoming)
            defer { answered.close() }
            let up = await waitFor(15) { answered.media != nil }
            XCTAssertTrue(up, "the call's media never came up")
            XCTAssertEqual(try XCTUnwrap(answered.media).info().codec, pcma)
        }
        do {
            let alice = try SipralStack(audio: .application, bindHost: "127.0.0.1")
            let bob = try Phone("bob")
            defer { alice.close(); bob.core.close() }
            let line = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: bob.address)
            _ = try bob.core.addAccount(SipralAccountOptions(aor: bob.aor, registrarAddress: alice.bindAddress))
            let placed = try alice.placeCall(account: line, target: "sip:bob@\(bob.address)", codecs: "G722,PCMA,PCMU")
            defer { placed.close() }
            let rang = try await bob.await("the incoming call") { $0["kind"] as? String == "incomingCall" }
            try bob.core.answer(try XCTUnwrap(rang["call"] as? String), codecs: "PCMA,PCMU")
            let up = await waitFor(15) { placed.media != nil }
            XCTAssertTrue(up, "the call's media never came up")
            XCTAssertEqual(try XCTUnwrap(placed.media).info().codec, pcma)
        }
    }

    /// An account the bridge was told is a PBX WebRTC line offers what one
    /// does, and its call is keyed by a handshake on the pair ICE chose.
    func testAWebRtcLineReachesTheLibrary() async throws {
        let host = try hostAddress()
        // one codec, as the Swift layer's own test of the line: the offer
        // with every codec of the default list does not fit a datagram
        let alice = try Phone("alice", host: host, codecs: "PCMU")
        let bob = try SipralStack(audio: .application, bindHost: host, codecs: "PCMU")
        defer { alice.core.close(); bob.close() }
        let line = try alice.core.addAccount(SipralAccountOptions([
            "aor": alice.aor, "registrarAddress": bob.bindAddress, "webrtc": NSNumber(value: true),
        ]))
        _ = try bob.addAccount(
            aor: "sip:bob@sipral.invalid", registrarAddress: alice.address, security: AccountSecurity(webrtc: true)
        )
        let arrivals = bob.events()
        _ = try alice.core.placeCall(line, "sip:bob@\(bob.bindAddress)", destination: nil, codecs: nil)
        let incoming = try await first(arrivals) { $0.kind == .incomingCall }
        let offer = String(
            decoding: try XCTUnwrap(incoming.callData?.remoteSdp ?? incoming.message, "the call carried no offer"),
            as: UTF8.self
        )
        for wanted in ["UDP/TLS/RTP/SAVPF", "a=fingerprint:", "a=group:BUNDLE 0", "a=rtcp-mux-only", "a=ice-ufrag:"] {
            XCTAssertTrue(offer.contains(wanted), "\(wanted) is not in the offer:\n\(offer)")
        }
        let answered = try bob.answerCall(incoming)
        defer { answered.close() }
        let keyed = await waitFor(15) { (try? answered.media?.encryption().first?.encrypted) == true }
        XCTAssertTrue(keyed, "the handshake never keyed the call")
        let report = try XCTUnwrap(answered.media).encryption()
        XCTAssertEqual(report.first?.keyExchange, .dtls)
        XCTAssertEqual(report.first?.authenticated, true, "the certificate did not match the fingerprint")
    }

    /// A mailbox subscribed to through the bridge: the SUBSCRIBE asks for
    /// `message-summary`, the NOTIFY reaches JavaScript as `messagesWaiting`
    /// naming the account and the subscription with every count, and ending
    /// it unsubscribes.
    func testASubscribedMailboxReachesJavaScript() async throws {
        let server = try Mailbox()
        defer { server.close() }
        let alice = try Phone("alice")
        defer { alice.core.close() }
        let line = try alice.core.addAccount(SipralAccountOptions(["aor": alice.aor, "registrarAddress": server.address]))
        refusal("invalidHandle") { _ = try alice.core.subscribeMailbox("424242", target: alice.aor) }
        let mailbox = try alice.core.subscribeMailbox(line, target: alice.aor, expiresSeconds: 600)
        let subscribed = await server.next("SUBSCRIBE ")
        let subscribe = try XCTUnwrap(subscribed, "no SUBSCRIBE")
        XCTAssertTrue(subscribe.message.hasPrefix("SUBSCRIBE \(alice.aor) "), subscribe.message)
        XCTAssertEqual(Mailbox.header("Event", in: subscribe.message), "message-summary")
        XCTAssertEqual(Mailbox.header("Expires", in: subscribe.message), "600")
        server.answer(subscribe, "200 OK", more: "Expires: 600\r\n")
        server.notify(alice.aor, at: alice.address, in: subscribe.message)
        let told = try await alice.await("the mailbox's state") { $0["kind"] as? String == "messagesWaiting" }
        XCTAssertEqual(told["account"] as? String, line)
        XCTAssertEqual(told["subscription"] as? String, mailbox)
        XCTAssertEqual(told["waiting"] as? Bool, true)
        XCTAssertEqual(told["newMessages"] as? Double, 2)
        XCTAssertEqual(told["oldMessages"] as? Double, 5)
        XCTAssertEqual(told["urgentNewMessages"] as? Double, 1)
        XCTAssertEqual(told["urgentOldMessages"] as? Double, 0)
        XCTAssertEqual(told["messageAccount"] as? String, alice.aor)

        try alice.core.endSubscription(mailbox)
        let unsubscribing = await server.next("SUBSCRIBE ")
        let unsubscribe = try XCTUnwrap(unsubscribing, "no unsubscribe")
        XCTAssertEqual(Mailbox.header("Expires", in: unsubscribe.message), "0")
        refusal("invalidHandle") { try alice.core.endSubscription("424242") }
    }

    /// A PBX that notifies unasked (VitalPBX): an account JavaScript added
    /// with `unsolicitedMwi` answers 200 and reports the mailbox with no
    /// subscription; one added without answers 481 and reports nothing.
    func testAnUnaskedMailboxReachesOnlyAnAccountThatAllowsIt() async throws {
        for allowed in [true, false] {
            let server = try Mailbox()
            defer { server.close() }
            let alice = try Phone("alice")
            defer { alice.core.close() }
            var options: [String: Any] = ["aor": alice.aor, "registrarAddress": server.address]
            if allowed {
                options["unsolicitedMwi"] = NSNumber(value: true)
            }
            let line = try alice.core.addAccount(SipralAccountOptions(options))
            server.notify(alice.aor, at: alice.address, in: nil)
            let answered = await server.next("SIP/2.0 ")
            let answer = try XCTUnwrap(answered, "the NOTIFY was not answered")
            if allowed {
                XCTAssertTrue(answer.message.hasPrefix("SIP/2.0 200"), answer.message)
                let told = try await alice.await("the unasked mailbox") { $0["kind"] as? String == "messagesWaiting" }
                XCTAssertEqual(told["account"] as? String, line)
                XCTAssertEqual(told["subscription"] as? String, "")
                XCTAssertEqual(told["waiting"] as? Bool, true)
                XCTAssertEqual(told["newMessages"] as? Double, 2)
                XCTAssertEqual(told["oldMessages"] as? Double, 5)
                XCTAssertEqual(told["messageAccount"] as? String, alice.aor)
            } else {
                XCTAssertTrue(answer.message.hasPrefix("SIP/2.0 481"), answer.message)
                // refused, a second is long enough for an event that should not come
                let raised = await waitFor(1) { alice.events.contains { $0["kind"] as? String == "messagesWaiting" } }
                XCTAssertFalse(raised, "an account that did not allow it reported an unasked mailbox")
            }
        }
    }

    /// A status reaches JavaScript by its name, and one this build has no
    /// name for as the platform's, as the Android half says it.
    func testALibraryRefusalIsNamedByItsStatus() {
        XCTAssertEqual(SipralReactCore.refusal(of: SipralError(status: .busy, message: "")).code, "busy")
        XCTAssertEqual(SipralReactCore.refusal(of: SipralError(code: 999, message: "")).code, "platform")
    }

    /// The load-time version check: any minor up to the library's within
    /// 1.x passes; a later minor, another major or 0.x reaches JavaScript as
    /// `unsupportedVersion`.
    func testTheAbiCheckKeepsTheOneXRule() throws {
        let library = try Sipral.abiVersion()
        XCTAssertEqual(library.major, Sipral.abiVersionMajor)
        XCTAssertGreaterThanOrEqual(library.minor, Sipral.abiVersionMinor)
        for minor in 0...library.minor {
            XCTAssertNoThrow(try Sipral.abiCheck(major: library.major, minor: minor), "\(library.major).\(minor)")
        }
        for (major, minor) in [(library.major, library.minor + 1), (library.major + 1, 0), (0, 36)] {
            XCTAssertThrowsError(try Sipral.abiCheck(major: major, minor: minor), "\(major).\(minor) was served") {
                let refused = SipralReactCore.refusal(of: $0)
                XCTAssertEqual(refused.code, "unsupportedVersion")
                XCTAssertTrue(refused.message.contains("\(major).\(minor)"), refused.message)
            }
        }
    }
}
