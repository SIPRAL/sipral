// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

#if canImport(Network) && canImport(CryptoKit)
import CryptoKit
import Foundation
import XCTest
@testable import Sipral

/// ABI 0.35 through `SipralStack`: an account on a connection of its own
/// beside one on the stack's UDP socket, each registered with its own
/// loopback registrar and each placing a call through it; and the settings
/// read back.
final class AccountStreamTests: XCTestCase {
    private func registered(_ account: Account) async throws {
        let done = await eventually(within: 8) { (try? account.registrationState) == .registered }
        XCTAssertTrue(done, "\(account.aor) never registered")
    }

    private func arrived(_ seconds: Double, _ condition: () -> Bool) async -> Bool {
        await eventually(within: seconds) { condition() }
    }

    func testAnAccountOverTlsAndOneOverUdpEachReachTheirOwnServer() async throws {
        let udpRegistrar = try DatagramRegistrar()
        defer { udpRegistrar.stop() }
        let (identity, der) = try SignallingTests.certificate("account")
        let tlsRegistrar = try FakeRegistrar(identity: identity)
        defer { tlsRegistrar.stop() }
        let pin = "sha256 Fingerprint=" + SHA256.hash(data: Data(der)).map { String(format: "%02X", $0) }
            .joined(separator: ":")

        // streamFallback off: the account's own connection is opened all the
        // same, since nothing outgrew a datagram
        let stack = try SipralStack(audio: .application, bindHost: "127.0.0.1", streamFallback: false)
        defer { stack.close() }
        let events = Recorder(stack.events())
        let overUdp = try stack.addAccount(
            aor: "sip:alice@udp.sipral.test", registrarAddress: udpRegistrar.address, registrar: "sip:udp.sipral.test"
        )
        let overTls = try stack.addAccount(
            aor: "sip:bob@\(SignallingTests.serverName)", registrarAddress: tlsRegistrar.address,
            tlsPin: pin, streamProtocol: .tls, registrar: "sip:\(SignallingTests.serverName)"
        )
        XCTAssertEqual(overTls.streamProtocol, .tls)
        XCTAssertNil(overUdp.streamProtocol)
        XCTAssertTrue(overTls.contact.hasSuffix(";transport=tls"), overTls.contact)
        try overUdp.register()
        try overTls.register()
        try await registered(overUdp)
        try await registered(overTls)

        let wanted = events.elements.compactMap(\.transportWantedData)
        XCTAssertEqual(wanted.first?.destination, tlsRegistrar.address)
        XCTAssertEqual(wanted.first?.protocolRaw, SipralTransport.tls.rawValue)
        XCTAssertEqual(wanted.first?.requestBytes, 0)
        let register = try XCTUnwrap(tlsRegistrar.registers.first)
        XCTAssertTrue(FakeRegistrar.header("Via", register.message)?.hasPrefix("SIP/2.0/TLS ") == true)
        XCTAssertTrue(register.message.contains("sip:bob@"))
        XCTAssertTrue(udpRegistrar.registers.allSatisfy { $0.contains("sip:alice@") })
        XCTAssertFalse(udpRegistrar.registers.isEmpty)

        let first = try stack.placeCall(account: overUdp, target: "sip:carol@udp.sipral.test")
        let second = try stack.placeCall(account: overTls, target: "sip:dave@\(SignallingTests.serverName)")
        defer {
            first.close()
            second.close()
        }
        let udpInvite = await arrived(5) { udpRegistrar.received.contains { $0.hasPrefix("INVITE sip:carol@") } }
        XCTAssertTrue(udpInvite, "the UDP account's call never reached its server")
        let tlsInvite = await arrived(5) {
            tlsRegistrar.requests.contains { $0.message.hasPrefix("INVITE sip:dave@") }
        }
        XCTAssertTrue(tlsInvite, "the TLS account's call never reached its server")
        let invite = try XCTUnwrap(tlsRegistrar.requests.first { $0.message.hasPrefix("INVITE ") })
        XCTAssertEqual(invite.connection, register.connection, "the call went over the account's own connection")
        XCTAssertTrue(FakeRegistrar.header("Via", invite.message)?.hasPrefix("SIP/2.0/TLS ") == true)
        XCTAssertFalse(udpRegistrar.received.contains { $0.contains("dave@") })
        XCTAssertFalse(tlsRegistrar.requests.contains { $0.message.contains("carol@") })
    }

    func testAnAccountOverTcpIsOpenedAgainWhenItsServerDropsTheConnection() async throws {
        let registrar = try FakeRegistrar()
        defer { registrar.stop() }
        let stack = try SipralStack(audio: .application, bindHost: "127.0.0.1")
        defer { stack.close() }
        let account = try stack.addAccount(
            aor: "sip:alice@\(SignallingTests.serverName)", registrarAddress: registrar.address, streamProtocol: .tcp,
            registrar: "sip:\(SignallingTests.serverName)"
        )
        XCTAssertTrue(account.contact.hasSuffix(";transport=tcp"), account.contact)
        try account.register()
        try await registered(account)
        XCTAssertTrue(FakeRegistrar.header("Via", try XCTUnwrap(registrar.registers.first).message)?
            .hasPrefix("SIP/2.0/TCP ") == true)

        registrar.drop()
        let again = await arrived(8) { registrar.registers.contains { $0.connection == 2 } }
        XCTAssertTrue(again, "the account did not register again over a new connection")
    }

    func testOnlyAStreamOnAStackThatSignalsOverUdpIsTaken() throws {
        let stack = try SipralStack(audio: .application, bindHost: "127.0.0.1")
        defer { stack.close() }
        XCTAssertThrowsError(
            try stack.addAccount(aor: "sip:alice@example.com", registrarAddress: "127.0.0.1:5060", streamProtocol: .udp)
        ) { error in
            XCTAssertEqual((error as? SipralError)?.status, .invalidArgument)
        }
    }

    func testTheSettingsAreReadBackWithTheDefaultsFilledIn() throws {
        let plain = try SipralStack(audio: .application, bindHost: "127.0.0.1")
        defer { plain.close() }
        let defaults = try plain.settings()
        XCTAssertEqual(defaults.transport, .udp)
        XCTAssertTrue(defaults.retransmits)
        XCTAssertTrue(defaults.systemEchoCancellation)
        XCTAssertFalse(defaults.pseudonymSalted)
        XCTAssertFalse(defaults.diagnosticTrace)
        XCTAssertFalse(defaults.srtpSuites.isEmpty, "this build's own suites")
        XCTAssertGreaterThan(defaults.codecCount, 0)

        let given = try SipralStack(
            audio: .application, bindHost: "127.0.0.1", rtpPortMin: 40000, rtpPortMax: 40100,
            srtpSuites: ["AES_CM_128_HMAC_SHA1_32", "AES_CM_128_HMAC_SHA1_80"],
            pseudonymSalt: Array(repeating: 7, count: 16), diagnosticTrace: true, systemEchoCancellation: false
        )
        defer { given.close() }
        let settings = try given.settings()
        XCTAssertEqual(settings.srtpSuites, [.aesCm32, .aesCm80])
        XCTAssertTrue(settings.pseudonymSalted)
        XCTAssertTrue(settings.diagnosticTrace)
        XCTAssertFalse(settings.systemEchoCancellation)
        XCTAssertEqual(settings.rtpPorts, 40000...40100)
        try given.setDiagnosticTrace(false)
        XCTAssertFalse(try given.settings().diagnosticTrace)
    }
}
#endif
