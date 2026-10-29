// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

// macOS only, as `SignallingTests`, whose registrars and certificate it uses.
#if os(macOS) && canImport(Network) && canImport(CryptoKit)
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

    func testAnAccountOverAWebSocketAsksForItsResourceAndHost() async throws {
        let server = try FakeRegistrar()
        defer { server.stop() }
        let stack = try SipralStack(audio: .application, bindHost: "127.0.0.1")
        defer { stack.close() }
        let account = try stack.addAccount(
            aor: "sip:alice@\(SignallingTests.serverName)", registrarAddress: server.address, streamProtocol: .ws,
            websocketHost: "pbx.sipral.test", websocketResource: "/sip?tenant=7",
            registrar: "sip:\(SignallingTests.serverName)"
        )
        XCTAssertEqual(account.streamProtocol, .ws)
        XCTAssertTrue(account.contact.hasSuffix(";transport=ws"), account.contact)
        try account.register()
        let asked = await arrived(5) { server.requests.contains { $0.message.hasPrefix("GET ") } }
        XCTAssertTrue(asked, "no WebSocket handshake reached the server")
        let handshake = try XCTUnwrap(server.requests.first { $0.message.hasPrefix("GET ") }).message
        XCTAssertTrue(handshake.hasPrefix("GET /sip?tenant=7 HTTP/1.1\r\n"), handshake)
        XCTAssertEqual(FakeRegistrar.header("Host", handshake), "pbx.sipral.test")
        XCTAssertEqual(FakeRegistrar.header("Sec-WebSocket-Protocol", handshake), "sip")

        XCTAssertThrowsError(
            try stack.addAccount(
                aor: "sip:bob@example.com", registrarAddress: server.address, streamProtocol: .tcp,
                websocketResource: "/ws"
            )
        ) { error in
            XCTAssertEqual((error as? SipralError)?.status, .invalidArgument)
        }
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

    // MARK: - an account located by SRV, on TLS

    /// A stack whose resolver sends `sips:registrar.sipral.test` through SRV
    /// to `pbx-7.sipral.test`, at `host`, the registrar's port.
    private func locating(
        to registrar: FakeRegistrar, trust: TLSTrust = .platform, domains: [String] = [SignallingTests.serverName]
    ) throws -> SipralStack {
        let port = registrar.port
        let host = registrar.host
        return try SipralStack(audio: .application, tlsTrust: trust, resolver: { name, record in
            if record == .srv, domains.contains(where: { name == "_sips._tcp.\($0)" }) {
                return DnsLookupAnswer(answer: .records, records: ["300 10 60 \(port) pbx-7.sipral.test"])
            }
            if record == .a, name == "pbx-7.sipral.test" {
                return DnsLookupAnswer(answer: .records, records: ["300 \(host)"])
            }
            return .nothing
        })
    }

    /// RFC 5922 §7.3: the certificate is checked against the SIP domain
    /// configured, not against the address SRV and the lookup led to.
    func testAnAccountLocatedBySrvIsHeldToItsSipDomainNotTheAddress() async throws {
        let (identity, der) = try SignallingTests.certificate("domain")
        let registrar = try FakeRegistrar(identity: identity)
        defer { registrar.stop() }
        let stack = try locating(to: registrar, trust: .onlyAuthority(der))
        defer { stack.close() }
        let events = Recorder(stack.events())
        let account = try stack.addAccount(
            aor: "sip:bob@\(SignallingTests.serverName)", serverUri: "sips:\(SignallingTests.serverName)",
            streamProtocol: .tls, registrar: "sips:\(SignallingTests.serverName)"
        )
        try account.register()
        try await registered(account)
        XCTAssertEqual(account.registrarAddress, registrar.address)
        let failed = events.elements.compactMap(\.transportFailedData)
        XCTAssertTrue(failed.isEmpty, failed.map { $0.detail ?? "" }.description)
        let wanted = events.elements.compactMap(\.transportWantedData)
        XCTAssertEqual(wanted.map(\.serverName), [SignallingTests.serverName], "the stack names the SIP domain")
    }

    /// Two accounts whose SIP domains SRV places at one address, against a
    /// server whose certificate names the first domain alone: each gets a
    /// connection checked against its own domain, so the first registers,
    /// the second is refused for the name rather than riding the first
    /// one's connection, and the first goes on working.
    func testAccountsOfTwoDomainsAtOneAddressAreEachHeldToTheirOwnDomain() async throws {
        let tenant = "tenant.sipral.test"
        let (identity, der) = try SignallingTests.certificate("tenants")
        let registrar = try FakeRegistrar(identity: identity)
        defer { registrar.stop() }
        let stack = try locating(
            to: registrar, trust: .onlyAuthority(der), domains: [SignallingTests.serverName, tenant]
        )
        defer { stack.close() }
        let events = Recorder(stack.events())
        let first = try stack.addAccount(
            aor: "sip:alice@\(SignallingTests.serverName)", serverUri: "sips:\(SignallingTests.serverName)",
            streamProtocol: .tls, registrar: "sips:\(SignallingTests.serverName)"
        )
        try first.register()
        try await registered(first)
        let connection = try XCTUnwrap(registrar.registers.first?.connection)

        let second = try stack.addAccount(
            aor: "sip:bob@\(tenant)", serverUri: "sips:\(tenant)", streamProtocol: .tls, registrar: "sips:\(tenant)"
        )
        try second.register()
        let refused = await arrived(10) { events.elements.contains { $0.transportFailedData != nil } }
        XCTAssertTrue(refused, "the second tenant's connection was never refused")
        let failed = events.elements.compactMap(\.transportFailedData)
        XCTAssertEqual(failed.map(\.tls), [.nameMismatch], failed.map { $0.detail ?? "" }.description)
        XCTAssertEqual(second.registrarAddress, registrar.address, "located at the same address")
        XCTAssertNotEqual(try second.registrationState, .registered)
        XCTAssertFalse(registrar.registers.contains { $0.message.contains("sip:bob@") })
        let names = Set(events.elements.compactMap(\.transportWantedData).map(\.serverName))
        XCTAssertEqual(names, [SignallingTests.serverName, tenant])

        let call = try stack.placeCall(account: first, target: "sip:carol@\(SignallingTests.serverName)")
        defer { call.close() }
        let invited = await arrived(5) { registrar.requests.contains { $0.message.hasPrefix("INVITE sip:carol@") } }
        XCTAssertTrue(invited, "the first tenant's call never reached its server")
        let invite = try XCTUnwrap(registrar.requests.first { $0.message.hasPrefix("INVITE ") })
        XCTAssertEqual(invite.connection, connection, "the call went over the first tenant's connection")
    }

    /// The first `Contact` is written before the server is known, so it moves
    /// once the server is located, while the connection asked for is being
    /// opened: the REGISTER still goes the moment the connection is up, and
    /// the connection is asked for once.
    func testAnAccountWhoseContactMovesOnceLocatedRegistersAsSoonAsItsConnectionIsUp() async throws {
        guard let here = Self.reachableLocalAddress() else {
            throw XCTSkip("this machine has no address but loopback that its own sockets reach")
        }
        let (identity, der) = try SignallingTests.certificate("moving")
        let registrar = try FakeRegistrar(identity: identity, host: here)
        defer { registrar.stop() }
        let stack = try locating(to: registrar)
        defer { stack.close() }
        let events = Recorder(stack.events())
        let pin = "SHA256=" + SHA256.hash(data: Data(der)).map { String(format: "%02X", $0) }.joined(separator: ":")
        let account = try stack.addAccount(
            aor: "sip:bob@\(SignallingTests.serverName)", serverUri: "sips:\(SignallingTests.serverName)",
            tlsPin: pin, streamProtocol: .tls, registrar: "sips:\(SignallingTests.serverName)"
        )
        XCTAssertFalse(account.contact.contains(here), account.contact)
        let started = Date()
        try account.register()
        let done = await eventually(within: 7) { (try? account.registrationState) == .registered }
        XCTAssertTrue(done, "registered only after \(Date().timeIntervalSince(started)) s")
        XCTAssertTrue(account.contact.contains(here), account.contact)
        let register = try XCTUnwrap(registrar.registers.first?.message)
        XCTAssertTrue(FakeRegistrar.header("Contact", register)?.contains(here) == true, register)
        let wanted = events.elements.compactMap(\.transportWantedData)
        XCTAssertEqual(wanted.map(\.destination), [registrar.address])
    }

    /// An IPv4 address of this machine other than loopback that a socket of
    /// its own reaches: not a point-to-point tunnel's, which a VPN may hold.
    static func reachableLocalAddress() -> String? {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return nil }
        defer { freeifaddrs(list) }
        var candidates: [String] = []
        for entry in sequence(first: first, next: { $0.pointee.ifa_next }).map(\.pointee) {
            let flags = Int32(entry.ifa_flags)
            guard let address = entry.ifa_addr, address.pointee.sa_family == sa_family_t(AF_INET),
                  flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0, flags & IFF_POINTOPOINT == 0 else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(
                address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST
            ) == 0 else { continue }
            candidates.append(String(cString: host))
        }
        for candidate in candidates {
            guard let listening = try? UDPSocket(host: candidate, port: 0),
                  let sending = try? UDPSocket(host: "0.0.0.0", port: 0) else { continue }
            defer {
                listening.close()
                sending.close()
            }
            _ = sending.send(Array("here".utf8), to: listening.localAddress)
            for _ in 0..<50 {
                if listening.receive() != nil { return candidate }
                usleep(2_000)
            }
        }
        return nil
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
