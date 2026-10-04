// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
#if canImport(CryptoKit)
import CryptoKit
import Foundation
import XCTest
@testable import Sipral

/// A registrar on a loopback UDP port: every REGISTER is answered 200, and
/// every datagram is kept as text, keep-alives included.
final class DatagramRegistrar: @unchecked Sendable {
    private let socket: UDPSocket
    private let lock = NSLock()
    private var _received: [String] = []
    private var stopped = false
    let address: String
    var port: UInt16 { UDPSocket.parse(address).port }

    init() throws {
        socket = try UDPSocket(host: "127.0.0.1", port: 0)
        address = socket.localAddress
        Thread { [weak self] in self?.serve() }.start()
    }

    var received: [String] { lock.withLock { _received } }
    var registers: [String] { received.filter { $0.hasPrefix("REGISTER ") } }

    func stop() {
        lock.withLock { stopped = true }
    }

    private func serve() {
        while !lock.withLock({ stopped }) {
            guard let (data, from) = socket.receive() else {
                usleep(2_000)
                continue
            }
            let message = String(decoding: data, as: UTF8.self)
            lock.withLock { _received.append(message) }
            guard message.hasPrefix("REGISTER ") else { continue }
            var lines = ["SIP/2.0 200 OK"]
            for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
                let value = FakeRegistrarHeader.header(name, message) ?? ""
                lines.append(name == "To" ? "To: \(value);tag=registrar" : "\(name): \(value)")
            }
            lines.append("Contact: \(FakeRegistrarHeader.header("Contact", message) ?? "");expires=3600")
            lines.append("Content-Length: 0")
            socket.send(Array((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8), to: from)
        }
        socket.close()
    }
}

/// Lines written from another thread, kept for a test to read.
final class Written: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []

    func add(_ line: String) { lock.withLock { lines.append(line) } }
    func contains(_ text: String) -> Bool { lock.withLock { lines.contains { $0.contains(text) } } }
    var all: [String] { lock.withLock { lines } }
}

/// A header's value, the way the other fakes read one.
enum FakeRegistrarHeader {
    static func header(_ name: String, _ message: String) -> String? {
        message.components(separatedBy: "\r\n")
            .first { $0.lowercased().hasPrefix(name.lowercased() + ":") }
            .map { String($0.drop(while: { $0 != ":" }).dropFirst()).trimmingCharacters(in: .whitespaces) }
    }
}

/// Where a stack is reached and where its server is, through `SipralStack`:
/// the address advertised when the application names none, a server named
/// by a URI and located by RFC 3263, the account's keep-alive, a certificate
/// trusted by its fingerprint, and the diagnostic trace -- the Swift
/// counterpart of `bindings/python/tests/test_reachability.py`.
final class ReachabilityTests: XCTestCase {
    private func next(
        _ kind: SipralEventKind, on events: AsyncStream<SipralEvent>, seconds: Double = 5
    ) async throws -> SipralEvent {
        try await withThrowingTaskGroup(of: SipralEvent?.self) { group in
            group.addTask {
                for await event in events where event.kind == kind { return event }
                return nil
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                return nil
            }
            let first = try await group.next() ?? nil
            group.cancelAll()
            return try XCTUnwrap(first, "no \(kind) in \(seconds) seconds")
        }
    }

    private func registered(_ account: Account) async throws {
        for _ in 0..<100 {
            if try account.registrationState == .registered { return }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTFail("the account never registered")
    }

    private func until(_ seconds: Double = 5, _ what: () -> Bool) async throws -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while !what(), Date() < deadline {
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        return what()
    }

    // MARK: - the address a stack advertises

    func testTheAddressOfAWildcardSocketIsTheRouteTowardThePeer() throws {
        XCTAssertEqual(try SipralStack.advertisedAddress(bound: "0.0.0.0:5060", peer: "127.0.0.1:5070"), "127.0.0.1:5060")
        XCTAssertThrowsError(try SipralStack.advertisedAddress(bound: "127.0.0.1:5060", peer: "192.0.2.1:5060")) {
            XCTAssertEqual(($0 as? SipralError)?.status, .unreachableAddress)
        }
        XCTAssertEqual(SipralStack.routeHost(toward: "pbx.example.com:5060"), "127.0.0.1", "a name has no route")
    }

    func testAnAccountOnLoopbackRegistersFromLoopback() async throws {
        let registrar = try DatagramRegistrar()
        defer { registrar.stop() }
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let account = try stack.addAccount(
            aor: "sip:alice@example.com", registrarAddress: registrar.address, registrar: "sip:example.com"
        )
        try account.register()
        try await registered(account)
        let contact = FakeRegistrarHeader.header("Contact", registrar.registers.first ?? "") ?? ""
        XCTAssertTrue(contact.contains("@127.0.0.1:\(UDPSocket.parse(stack.bindAddress).port)"), contact)
    }

    func testAnAccountOnTheNetworkIsReachedAtTheRouteTowardItsServer() throws {
        let remote = "192.0.2.1:5060"
        let route = SipralStack.routeHost(toward: remote)
        try XCTSkipIf(route == "127.0.0.1", "this machine has no route off itself")
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let account = try stack.addAccount(aor: "sip:alice@example.com", registrarAddress: remote, registrar: "sip:example.com")
        XCTAssertTrue(account.contact.contains("@\(route):"), account.contact)
        XCTAssertEqual(UDPSocket.parse(stack.bindAddress).host, route, "and the stack's Via with it")
    }

    func testALoopbackContactTowardARegistrarElsewhereIsRefusedWithNothingSent() throws {
        let stack = try SipralStack(audio: .application, bindHost: "127.0.0.1")
        defer { stack.close() }
        let account = try stack.addAccount(
            aor: "sip:alice@example.com", registrarAddress: "192.0.2.1:5060", registrar: "sip:example.com"
        )
        XCTAssertThrowsError(try account.register()) {
            XCTAssertEqual(($0 as? SipralError)?.status, .unreachableAddress)
        }
        XCTAssertEqual(SipralRegistrationFailure.unreachableContact.rawValue, 5)
    }

    func testACallBetweenTwoStacksThatNamedNothingCarriesMediaOnLoopback() async throws {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }
        let toBob = try alice.addAccount(aor: "sip:alice@example.com", registrarAddress: bob.bindAddress)
        _ = try bob.addAccount(aor: "sip:bob@example.com", registrarAddress: alice.bindAddress)
        let bobEvents = bob.events()
        let call = try alice.placeCall(account: toBob, target: "sip:bob@example.com")
        defer { call.close() }
        XCTAssertTrue(call.mediaAddress.hasPrefix("127.0.0.1:"), call.mediaAddress)
        let incoming = try await next(.incomingCall, on: bobEvents)
        let answered = try bob.answerCall(incoming)
        defer { answered.close() }
        XCTAssertTrue(answered.mediaAddress.hasPrefix("127.0.0.1:"), answered.mediaAddress)
    }

    // MARK: - a server named by a URI

    func testAHostWithAPortIsAskedForItsAddressesAndRegisteredWith() async throws {
        let registrar = try DatagramRegistrar()
        defer { registrar.stop() }
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let events = stack.events()
        let account = try stack.addAccount(
            aor: "sip:alice@example.com", serverUri: "sip:localhost:\(registrar.port)", registrar: "sip:example.com"
        )
        try account.register()
        let located = try await next(.located, on: events)
        let targets = located.locateData?.targets?.split(separator: ",").map(String.init) ?? []
        XCTAssertTrue(targets.contains("127.0.0.1:\(registrar.port)"), targets.description)
        try await registered(account)
        XCTAssertEqual(registrar.registers.count, 1)
    }

    func testAnSrvAnswerNamesTheHostAndPortTheRequestsGoTo() async throws {
        let registrar = try DatagramRegistrar()
        defer { registrar.stop() }
        let port = registrar.port
        let asked = Written()
        let stack = try SipralStack(audio: .application, resolver: { name, record in
            asked.add("\(record) \(name)")
            if record == .srv, name == "_sip._udp.pbx.sipral.test" {
                return DnsLookupAnswer(answer: .records, records: ["300 10 60 \(port) host.sipral.test"])
            }
            if record == .a, name == "host.sipral.test" {
                return DnsLookupAnswer(answer: .records, records: ["300 127.0.0.1"])
            }
            return .nothing
        })
        defer { stack.close() }
        let events = stack.events()
        let account = try stack.addAccount(
            aor: "sip:alice@pbx.sipral.test", serverUri: "sip:pbx.sipral.test", registrar: "sip:pbx.sipral.test"
        )
        try account.register()
        let located = try await next(.located, on: events)
        XCTAssertEqual(located.locateData?.targets?.split(separator: ",").first.map(String.init), "127.0.0.1:\(port)")
        try await registered(account)
        XCTAssertEqual(account.registrarAddress, "127.0.0.1:\(port)")
        XCTAssertTrue(asked.all.contains("srv _sip._udp.pbx.sipral.test"), asked.all.description)
    }

    func testANameWithNoAddressIsALocateFailureThatSaysWhy() async throws {
        let stack = try SipralStack(audio: .application, resolver: { _, _ in .nothing })
        defer { stack.close() }
        let events = stack.events()
        let account = try stack.addAccount(
            aor: "sip:alice@example.com", serverUri: "sip:nowhere.sipral.test", registrar: "sip:example.com"
        )
        try account.register()
        let failed = try await next(.locateFailed, on: events)
        XCTAssertEqual(failed.locateData?.failureRaw, SipralLocateFailure.notFound.rawValue)
        XCTAssertGreaterThan(failed.locateData?.retryInMs ?? 0, 0)
    }

    func testThePlatformLookupFindsLocalhostAndReadsSrvAndNaptrData() {
        let found = SipralDns.platform("localhost", .a)
        XCTAssertEqual(found.answer, .records)
        XCTAssertTrue(found.records.contains("60 127.0.0.1"), found.records.description)
        // priority 10, weight 60, port 5060, sip1.example.com.
        let srv: [UInt8] = [0, 10, 0, 60, 0x13, 0xC4, 4] + Array("sip1".utf8) + [7] + Array("example".utf8) + [3] + Array("com".utf8) + [0]
        XCTAssertEqual(SipralDns.zoneText(of: .srv, data: srv, ttl: 300), "300 10 60 5060 sip1.example.com")
        // order 10, preference 50, "S", "SIP+D2U", no regexp, _sip._udp.example.com.
        let naptr: [UInt8] = [0, 10, 0, 50, 1] + Array("S".utf8) + [7] + Array("SIP+D2U".utf8) + [0]
            + [4] + Array("_sip".utf8) + [4] + Array("_udp".utf8) + [7] + Array("example".utf8) + [3] + Array("com".utf8) + [0]
        XCTAssertEqual(SipralDns.zoneText(of: .naptr, data: naptr, ttl: 300), "300 10 50 S SIP+D2U _sip._udp.example.com")
        XCTAssertNil(SipralDns.zoneText(of: .srv, data: [0, 10], ttl: 300))
    }

    func testExactlyOneOfTheTwoNamesTheServer() throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        XCTAssertThrowsError(try stack.addAccount(aor: "sip:alice@example.com"))
        XCTAssertThrowsError(
            try stack.addAccount(aor: "sip:alice@example.com", registrarAddress: "127.0.0.1:5060", serverUri: "sip:a.test")
        )
    }

    // MARK: - the account's keep-alive

    func testADoubleCrlfGoesToTheRegistrarAtTheInterval() async throws {
        let registrar = try DatagramRegistrar()
        defer { registrar.stop() }
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let account = try stack.addAccount(
            aor: "sip:alice@example.com", registrarAddress: registrar.address, keepaliveMs: 1000, registrar: "sip:example.com"
        )
        try account.register()
        try await registered(account)
        let kept = try await until(3) { registrar.received.contains("\r\n\r\n") }
        XCTAssertTrue(kept, registrar.received.description)
    }

    func testAnIntervalUnderASecondIsRefused() throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        XCTAssertThrowsError(
            try stack.addAccount(aor: "sip:alice@example.com", registrarAddress: "127.0.0.1:5060", keepaliveMs: 999)
        ) {
            XCTAssertEqual(($0 as? SipralError)?.status, .invalidArgument)
        }
    }

    // MARK: - a certificate trusted by its fingerprint

    func testTheAccountsPinDecidesOnTheCertificateAServerPresented() throws {
        let certificate = Array("the DER bytes of a leaf".utf8)
        let pin = SHA256.hash(data: Data(certificate)).map { String(format: "%02X", $0) }.joined(separator: ":")
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let pinned = try stack.addAccount(aor: "sip:alice@example.com", registrarAddress: "127.0.0.1:5060", tlsPin: pin)
        let verdict = try pinned.checkCertificate(certificate)
        XCTAssertNotNil(verdict)
        XCTAssertEqual(verdict?.expired, false)
        XCTAssertThrowsError(try pinned.checkCertificate(Array("another certificate".utf8))) {
            XCTAssertEqual(($0 as? SipralError)?.status, .certificateRefused)
        }
        let unpinned = try stack.addAccount(aor: "sip:bob@example.com", registrarAddress: "127.0.0.1:5060")
        XCTAssertNil(try unpinned.checkCertificate(certificate))
        XCTAssertThrowsError(
            try stack.addAccount(aor: "sip:carol@example.com", registrarAddress: "127.0.0.1:5060", tlsPin: "00")
        )
    }

    // MARK: - the stack's new options

    func testASuiteTheLibraryDoesNotRunAndAShortSaltAreRefused() throws {
        XCTAssertThrowsError(try SipralStack(audio: .application, srtpSuites: ["NOT_A_SUITE"])) {
            XCTAssertEqual(($0 as? SipralError)?.status, .invalidArgument)
        }
        XCTAssertThrowsError(try SipralStack(audio: .application, pseudonymSalt: Array("short".utf8))) {
            XCTAssertEqual(($0 as? SipralError)?.status, .invalidArgument)
        }
        let stack = try SipralStack(
            audio: .application, srtp: .bestEffort, srtpSuites: ["AES_CM_128_HMAC_SHA1_80"],
            pseudonymSalt: Array(0..<16)
        )
        stack.close()
    }

    func testTheTraceWritesWholeMessagesOnlyWhileTheDiagnosticTraceIsOn() async throws {
        let registrar = try DatagramRegistrar()
        defer { registrar.stop() }
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let written = Written()
        try stack.setLog(level: .trace) { _, _, message, _ in written.add(message) }
        let account = try stack.addAccount(
            aor: "sip:alice@example.com", registrarAddress: registrar.address, registrar: "sip:example.com"
        )
        try account.register()
        try await registered(account)
        let whole = { written.contains("sip:alice@example.com") }
        XCTAssertFalse(whole(), "pseudonymised")
        try stack.setDiagnosticTrace(true)
        try account.register()
        let seen = try await until(5, whole)
        XCTAssertTrue(seen, "a whole REGISTER, the AOR as it went on the wire")
    }

    func testBestEffortOffersKeysOnPlainRtp() async throws {
        let alice = try SipralStack(audio: .application, srtp: .bestEffort)
        let bob = try SipralStack(audio: .application)
        defer { alice.close(); bob.close() }
        let toBob = try alice.addAccount(aor: "sip:alice@example.com", registrarAddress: bob.bindAddress)
        _ = try bob.addAccount(aor: "sip:bob@example.com", registrarAddress: alice.bindAddress)
        let bobEvents = bob.events()
        let call = try alice.placeCall(account: toBob, target: "sip:bob@example.com")
        defer { call.close() }
        let incoming = try await next(.incomingCall, on: bobEvents)
        let offer = String(decoding: incoming.message ?? [], as: UTF8.self)
        XCTAssertTrue(offer.contains("RTP/AVP"), offer)
        XCTAssertFalse(offer.contains("RTP/SAVP"), offer)
        XCTAssertTrue(offer.contains("a=crypto:"), offer)
    }
}
#endif
