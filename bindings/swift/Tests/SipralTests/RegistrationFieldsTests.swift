// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(CryptoKit)
import Foundation
import XCTest
@testable import Sipral

/// A registrar on a loopback UDP port that challenges every REGISTER
/// without credentials with a 401, grants an authenticated one for two
/// seconds, so it is refreshed within one, and keeps every REGISTER it
/// received.
final class ChallengingRegistrar: @unchecked Sendable {
    private let socket: UDPSocket
    private let lock = NSLock()
    private var _registers: [String] = []
    private var stopped = false
    let address: String

    init() throws {
        socket = try UDPSocket(host: "127.0.0.1", port: 0)
        address = socket.localAddress
        Thread { [weak self] in self?.serve() }.start()
    }

    var registers: [String] { lock.withLock { _registers } }

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
            guard message.hasPrefix("REGISTER ") else { continue }
            lock.withLock { _registers.append(message) }
            var lines: [String]
            if FakeRegistrarHeader.header("Authorization", message) == nil {
                lines = ["SIP/2.0 401 Unauthorized"]
                lines += Self.echoed(message)
                lines.append("WWW-Authenticate: Digest realm=\"sipral.test\", nonce=\"5f3a9c\", algorithm=MD5")
            } else {
                lines = ["SIP/2.0 200 OK"]
                lines += Self.echoed(message)
                if FakeRegistrarHeader.header("Expires", message) != "0" {
                    lines.append("Contact: \(FakeRegistrarHeader.header("Contact", message) ?? "");expires=2")
                }
            }
            lines.append("Content-Length: 0")
            socket.send(Array((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8), to: from)
        }
        socket.close()
    }

    private static func echoed(_ request: String) -> [String] {
        ["Via", "From", "To", "Call-ID", "CSeq"].map { name in
            let value = FakeRegistrarHeader.header(name, request) ?? ""
            return name == "To" ? "To: \(value);tag=registrar" : "\(name): \(value)"
        }
    }
}

/// `SipralStack.addAccount(instanceId:headers:)`: RFC 5626's instance on the
/// `Contact`, and the application's fields, on every REGISTER the account
/// sends, whichever step of the registration sends it.
final class RegistrationFieldsTests: XCTestCase {
    private static let instance = "urn:uuid:3c1b7d2e-58f4-4b39-9a61-0d2c7e4f8a15"
    private static let fields = [
        SipralHeader(name: "X-Device-Class", value: "phone"),
        SipralHeader(name: "X-Tenant", value: "north-7"),
    ]

    private func until(_ seconds: Double, _ what: () -> Bool) async -> Bool {
        await eventually(within: seconds) { what() }
    }

    private func carriesBoth(_ register: String, _ step: String, file: StaticString = #filePath, line: UInt = #line) {
        let contact = FakeRegistrarHeader.header("Contact", register) ?? ""
        XCTAssertTrue(
            contact.contains(";+sip.instance=\"<\(Self.instance)>\""), "\(step): \(contact)", file: file, line: line
        )
        XCTAssertEqual(FakeRegistrarHeader.header("X-Device-Class", register), "phone", step, file: file, line: line)
        XCTAssertEqual(FakeRegistrarHeader.header("X-Tenant", register), "north-7", step, file: file, line: line)
    }

    func testTheInstanceAndTheFieldsGoOnEveryRegister() async throws {
        let registrar = try ChallengingRegistrar()
        defer { registrar.stop() }
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let account = try stack.addAccount(
            aor: "sip:alice@sipral.test", registrarAddress: registrar.address, registrar: "sip:sipral.test",
            authUser: "alice", authPassword: "open sesame", instanceId: Self.instance, headers: Self.fields
        )
        try account.register()

        // the first, its answer to the 401, and a refresh of the binding
        let refreshed = await until(8) {
            registrar.registers.filter { FakeRegistrarHeader.header("Authorization", $0) != nil }.count >= 2
        }
        XCTAssertTrue(refreshed, "the binding was never refreshed: \(registrar.registers.count) REGISTERs")
        let registers = registrar.registers
        let first = try XCTUnwrap(registers.first)
        XCTAssertNil(FakeRegistrarHeader.header("Authorization", first))
        carriesBoth(first, "the first REGISTER")
        let authenticated = registers.filter { FakeRegistrarHeader.header("Authorization", $0) != nil }
        let answer = try XCTUnwrap(authenticated.first)
        XCTAssertEqual(FakeRegistrarHeader.header("CSeq", answer)?.hasSuffix(" REGISTER"), true)
        carriesBoth(answer, "the REGISTER answering the 401")
        let refresh = authenticated[1]
        XCTAssertNotEqual(FakeRegistrarHeader.header("Expires", refresh), "0")
        carriesBoth(refresh, "the refresh")
        // the instance asks for a GRUU (RFC 5627 §4.1)
        XCTAssertEqual(FakeRegistrarHeader.header("Supported", first), "gruu")

        let before = registrar.registers.count
        try account.unregister()
        let removed = await until(5) {
            registrar.registers.dropFirst(before).contains { FakeRegistrarHeader.header("Expires", $0) == "0" }
        }
        XCTAssertTrue(removed, "no REGISTER removed the binding")
        let leaving = try XCTUnwrap(
            registrar.registers.dropFirst(before).first { FakeRegistrarHeader.header("Expires", $0) == "0" }
        )
        carriesBoth(leaving, "the de-registration")
    }

    func testFieldsTheStackWritesAndFieldsNoRegisterCarriesAreRefused() throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        XCTAssertThrowsError(
            try stack.addAccount(
                aor: "sip:alice@sipral.test", registrarAddress: "127.0.0.1:5060", registrar: "sip:sipral.test",
                headers: [SipralHeader(name: "Expires", value: "60")]
            )
        ) { error in
            XCTAssertEqual((error as? SipralError)?.status, .invalidArgument)
        }
        XCTAssertThrowsError(
            try stack.addAccount(
                aor: "sip:trunk@sipral.test", registrarAddress: "127.0.0.1:5060", headers: Self.fields
            )
        ) { error in
            XCTAssertEqual((error as? SipralError)?.status, .invalidArgument)
        }
        let line = try stack.addAccount(
            aor: "sip:bob@sipral.test", registrarAddress: "127.0.0.1:5060", registrar: "sip:sipral.test",
            instanceId: "<\(Self.instance)>", headers: [SipralHeader(name: "Supported", value: "path")]
        )
        XCTAssertEqual(line.aor, "sip:bob@sipral.test")
    }
}
#endif
