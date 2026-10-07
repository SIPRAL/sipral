// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(Network) && canImport(CryptoKit)
import CryptoKit
import Dispatch
import Foundation
import Network
import Security
import XCTest
@testable import Sipral

/// A TURN server on a TCP port of this machine's loopback, over TLS when it
/// is given an identity, and on nothing else: no datagram reaches it.
///
/// Framing per RFC 8656 §12.5 and RFC 8489 §6.2.2. Requests are recorded
/// with their connection number. An unsigned Allocate gets 401, signed
/// requests succeed, signed with `FakeStunServer`'s key.
final class FakeTurnOverStream: @unchecked Sendable {
    struct Request {
        let connection: Int
        let method: UInt16
        let attributes: [UInt16: [UInt8]]
    }

    private let listener: NWListener
    private let queue = DispatchQueue(label: "org.sipral.test.turn")
    private let credential: (username: String, password: String)
    private let lock = NSLock()
    private var _requests: [Request] = []
    private var _closed: [Int] = []
    private var connections = 0
    let port: UInt16

    init(credential: (username: String, password: String), identity: SecIdentity? = nil) throws {
        self.credential = credential
        let tcp = NWProtocolTCP.Options()
        let parameters: NWParameters
        if let identity {
            let tls = NWProtocolTLS.Options()
            sec_protocol_options_set_local_identity(tls.securityProtocolOptions, sec_identity_create(identity)!)
            parameters = NWParameters(tls: tls, tcp: tcp)
        } else {
            parameters = NWParameters(tls: nil, tcp: tcp)
        }
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { state in
            if case .ready = state { ready.signal() }
        }
        var accepted: (NWConnection) -> Void = { _ in }
        listener.newConnectionHandler = { accepted($0) }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 5) == .success, let bound = listener.port?.rawValue else {
            throw XCTSkip("the fake TURN server could not listen")
        }
        port = bound
        accepted = { [weak self] connection in self?.serve(connection) }
    }

    var address: String { "127.0.0.1:\(port)" }
    var requests: [Request] { lock.withLock { _requests } }
    var closed: [Int] { lock.withLock { _closed } }

    func stop() {
        listener.cancel()
    }

    /// The connection of every signed Allocate.
    var allocations: [Int] {
        requests.filter { $0.method == 0x0003 && $0.attributes[0x0006] != nil }.map(\.connection)
    }

    /// Every signed Refresh, with its connection and the lifetime it asked.
    var refreshes: [(connection: Int, lifetime: [UInt8]?)] {
        requests.filter { $0.method == 0x0004 && $0.attributes[0x0006] != nil }.map { ($0.connection, $0.attributes[0x000D]) }
    }

    private func serve(_ connection: NWConnection) {
        let number = lock.withLock { () -> Int in
            connections += 1
            return connections
        }
        connection.start(queue: queue)
        read(connection, number, held: [])
    }

    private func read(_ connection: NWConnection, _ number: Int, held: [UInt8]) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, complete, error in
            guard let self else { return }
            var held = held + (data.map { [UInt8]($0) } ?? [])
            while let (frame, rest) = Self.frame(held) {
                held = rest
                if let answer = self.answer(frame, number) {
                    connection.send(content: Data(answer), completion: .idempotent)
                }
            }
            if complete || error != nil {
                self.lock.withLock { self._closed.append(number) }
                connection.cancel()
                return
            }
            self.read(connection, number, held: held)
        }
    }

    private static func frame(_ held: [UInt8]) -> ([UInt8], [UInt8])? {
        guard held.count >= 4 else { return nil }
        let length = Int(held[2]) << 8 | Int(held[3])
        if held[0] < 4 {
            guard held.count >= 20 + length else { return nil }
            return (Array(held[..<(20 + length)]), Array(held[(20 + length)...]))
        }
        let padded = (4 + length + 3) / 4 * 4
        guard held.count >= padded else { return nil }
        return (Array(held[..<(4 + length)]), Array(held[padded...]))
    }

    private func answer(_ frame: [UInt8], _ number: Int) -> [UInt8]? {
        guard frame[0] < 4, let request = FakeStunServer.parse(frame, from: "") else { return nil }
        lock.withLock { _requests.append(Request(connection: number, method: request.method, attributes: request.attributes)) }
        let transaction = Array(frame[8..<20])
        let type = UInt16(frame[0]) << 8 | UInt16(frame[1])
        guard request.attributes[0x0006] != nil else {
            return FakeStunServer.message(type | 0x0110, transaction, [
                (0x0009, [0, 0, 4, 1] + Array("Unauthorized".utf8)),
                (0x0014, Array(FakeStunServer.realm.utf8)),
                (0x0015, Array(FakeStunServer.nonce.utf8)),
            ])
        }
        guard let key = FakeStunServer.longTermKey(credential.username, credential.password),
              FakeStunServer.integrityHolds(frame, key: key) else { return nil }
        switch request.method {
        case 0x0003:
            return FakeStunServer.signed(0x0103, transaction, [
                (0x0016, FakeStunServer.xorAddress("198.51.100.29:\(50000 + number)")),
                (0x0020, FakeStunServer.xorAddress("203.0.113.29:\(41000 + number)")),
                (0x000D, [0, 0, 0x02, 0x58]),
            ], key: key)
        case 0x0004:
            return FakeStunServer.signed(type | 0x0100, transaction, [
                (0x000D, request.attributes[0x000D] ?? [0, 0, 0x02, 0x58]),
            ], key: key)
        default:
            return FakeStunServer.signed(type | 0x0100, transaction, [], key: key)
        }
    }
}

/// TURN over TCP or TLS (RFC 8656 §3.1); the STUN mapping still uses UDP,
/// since it is about the socket itself.
final class TurnStreamTests: XCTestCase {
    private static let serverName = "turn.sipral.test"
    private let password = "turn-secret-\(UInt32.random(in: 100_000...999_999))"

    private func first(
        _ events: AsyncStream<SipralEvent>, within seconds: Double = 10,
        where match: @escaping @Sendable (SipralEvent) -> Bool
    ) async -> SipralEvent? {
        await withTaskGroup(of: SipralEvent?.self) { group in
            group.addTask {
                for await event in events where match(event) { return event }
                return nil
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                return nil
            }
            let found = await group.next() ?? nil
            group.cancelAll()
            return found
        }
    }

    /// A non-loopback local address (RFC 8445 §5.1.1.1).
    private func hostAddress() throws -> String {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { throw XCTSkip("no interfaces") }
        defer { freeifaddrs(list) }
        for entry in sequence(first: first, next: { $0.pointee.ifa_next }) {
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

    private func until(_ seconds: Double = 5, _ done: () -> Bool) {
        let deadline = DispatchTime.now() + seconds
        while !done() && DispatchTime.now() < deadline { usleep(20_000) }
    }

    /// Alice calls Bob from behind `turn`, Bob answers: what Alice's
    /// relay event said, with both stacks and the call running.
    private func call(
        through turn: TurnServer, stun: FakeStunServer
    ) async throws -> (RelayEventData, SipralStack, SipralStack, Call, Call) {
        let host = try hostAddress()
        let alice = try SipralStack(audio: .application, bindHost: host, ice: .offered, stunServer: stun.address, turn: turn)
        let bob = try SipralStack(audio: .application, bindHost: host)
        let events = alice.events()
        let bobEvents = bob.events()
        let account = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress)
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress)
        stun.open = true
        let aliceCall = try alice.placeCall(
            account: account, target: "sip:bob@\(bob.bindAddress)", mediaHost: host
        )
        let relayEvent = await first(events) { $0.relayData != nil }
        let relay = try XCTUnwrap(relayEvent?.relayData, "no relay event")
        let incoming = await first(bobEvents) { $0.kind == .incomingCall }
        let bobCall = try bob.takeIncomingCall(try XCTUnwrap(incoming, "bob never saw the call"), mediaHost: host)
        try bobCall.answer()
        return (relay, alice, bob, aliceCall, bobCall)
    }

    func testARelayOverTcpIsMadeAndGivenBackOnItsConnection() async throws {
        let stun = try FakeStunServer()
        defer { stun.stop() }
        let server = try FakeTurnOverStream(credential: ("alice-turn", password))
        defer { server.stop() }
        let turn = TurnServer(address: server.address, username: "alice-turn", password: password, transport: .tcp)
        let (relay, alice, bob, aliceCall, bobCall) = try await call(through: turn, stun: stun)
        defer { alice.close(); bob.close() }
        XCTAssertEqual(relay.outcome, .allocated, "relay failed: \(relay.code) \(relay.reason ?? "")")
        XCTAssertNil(relay.mapped, "the connection's own mapping says nothing about the socket")
        XCTAssertEqual(server.allocations, [1], "one Allocate, on the one connection")
        XCTAssertFalse(stun.requests.contains { $0.method == 0x0003 }, "an Allocate went as a datagram")

        // the relay is released on the connection, which then closes
        aliceCall.close()
        bobCall.close()
        until { server.refreshes.contains { $0.lifetime == [0, 0, 0, 0] } }
        XCTAssertEqual(
            server.refreshes.filter { $0.lifetime == [0, 0, 0, 0] }.map(\.connection), [1],
            "given back on the connection it was made on"
        )
        until { server.closed.contains(1) }
        XCTAssertTrue(server.closed.contains(1), "the connection was closed once nothing was left for it")
    }

    func testARelayOverTlsIsMadeWithTheRootsItWasToldToTrust() async throws {
        let (identity, certificate) = try Self.selfSigned()
        let stun = try FakeStunServer()
        defer { stun.stop() }
        let server = try FakeTurnOverStream(credential: ("alice-turn", password), identity: identity)
        defer { server.stop() }
        let turn = TurnServer(
            address: server.address, username: "alice-turn", password: password, transport: .tls,
            serverName: Self.serverName, trustedCertificates: [certificate]
        )
        let (relay, alice, bob, _, _) = try await call(through: turn, stun: stun)
        defer { alice.close(); bob.close() }
        XCTAssertEqual(relay.outcome, .allocated, "relay failed: \(relay.code) \(relay.reason ?? "")")
        XCTAssertEqual(server.allocations, [1])
    }

    func testACertificateNobodyVouchesForIsNoRelayAndTheCallGoesOn() async throws {
        let (identity, _) = try Self.selfSigned()
        let stun = try FakeStunServer()
        defer { stun.stop() }
        let server = try FakeTurnOverStream(credential: ("alice-turn", password), identity: identity)
        defer { server.stop() }
        let turn = TurnServer(
            address: server.address, username: "alice-turn", password: password, transport: .tls,
            serverName: Self.serverName
        )
        let (relay, alice, bob, aliceCall, _) = try await call(through: turn, stun: stun)
        defer { alice.close(); bob.close() }
        XCTAssertEqual(relay.outcome, .failed)
        XCTAssertTrue(relay.reason?.contains("connection") == true, relay.reason ?? "")
        XCTAssertTrue(server.allocations.isEmpty, "nothing reached the server past the handshake")
        XCTAssertFalse(aliceCall.ended, "the call went ahead without a relay")
    }

    /// A key and a certificate for `serverName`, made with the `openssl`
    /// command and imported into memory alone -- never into a keychain.
    private static func selfSigned() throws -> (SecIdentity, [UInt8]) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("sipral-turn-\(UInt32.random(in: 0...UInt32.max))")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let key = directory.appendingPathComponent("turn.key").path
        let pem = directory.appendingPathComponent("turn.pem").path
        let der = directory.appendingPathComponent("turn.der").path
        let p12 = directory.appendingPathComponent("turn.p12").path
        try openssl([
            "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
            "-subj", "/CN=\(serverName)", "-addext", "subjectAltName=DNS:\(serverName)",
            "-addext", "extendedKeyUsage=serverAuth",
            "-keyout", key, "-out", pem,
        ])
        try openssl(["x509", "-in", pem, "-outform", "der", "-out", der])
        try openssl([
            "pkcs12", "-export", "-inkey", key, "-in", pem, "-passout", "pass:sipral", "-out", p12,
            "-certpbe", "PBE-SHA1-3DES", "-keypbe", "PBE-SHA1-3DES", "-macalg", "sha1",
        ])
        guard #available(macOS 15.0, iOS 18.0, *) else {
            throw XCTSkip("importing an identity into memory alone needs macOS 15")
        }
        var items: CFArray?
        let options: [String: Any] = [
            kSecImportExportPassphrase as String: "sipral",
            kSecImportToMemoryOnly as String: true,
        ]
        let imported = SecPKCS12Import(try Data(contentsOf: URL(fileURLWithPath: p12)) as CFData, options as CFDictionary, &items)
        guard imported == errSecSuccess,
              let first = (items as? [[String: Any]])?.first,
              let identity = first[kSecImportItemIdentity as String] else {
            throw XCTSkip("the test certificate could not be imported: \(imported)")
        }
        return (identity as! SecIdentity, [UInt8](try Data(contentsOf: URL(fileURLWithPath: der))))
    }

    private static func openssl(_ arguments: [String]) throws {
        let candidates = ["/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", "/usr/bin/openssl"]
        guard let path = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            throw XCTSkip("no openssl command to make the server's certificate with")
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw XCTSkip("openssl \(arguments.first ?? "") failed")
        }
    }
}
#endif
