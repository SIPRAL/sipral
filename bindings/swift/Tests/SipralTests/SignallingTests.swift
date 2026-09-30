// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

#if canImport(Network)
import Dispatch
import Foundation
import Network
import Security
import XCTest
@testable import Sipral

/// A registrar on a TCP port of this machine's loopback, over TLS when it is
/// given an identity, answering every REGISTER 200 -- or, `plainToTls`, one
/// that answers a TLS client in plain text. Every request is recorded with
/// the connection it came on, counting from one.
final class FakeRegistrar: @unchecked Sendable {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "org.sipral.test.registrar")
    private let lock = NSLock()
    private let plainToTls: Bool
    private var _requests: [(connection: Int, message: String)] = []
    private var open: [NWConnection] = []
    private var connections = 0
    let port: UInt16

    init(identity: SecIdentity? = nil, plainToTls: Bool = false) throws {
        self.plainToTls = plainToTls
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
            throw XCTSkip("the fake registrar could not listen")
        }
        port = bound
        accepted = { [weak self] connection in self?.serve(connection) }
    }

    var address: String { "127.0.0.1:\(port)" }

    var registers: [(connection: Int, message: String)] {
        lock.withLock { _requests.filter { $0.message.hasPrefix("REGISTER ") } }
    }

    /// Close every connection from this end, the way a registrar that
    /// restarted does.
    func drop() {
        let all = lock.withLock { () -> [NWConnection] in
            defer { open = [] }
            return open
        }
        all.forEach { $0.cancel() }
    }

    func stop() {
        drop()
        listener.cancel()
    }

    private func serve(_ connection: NWConnection) {
        let number = lock.withLock { () -> Int in
            connections += 1
            open.append(connection)
            return connections
        }
        connection.start(queue: queue)
        read(connection, number, held: "")
    }

    private func read(_ connection: NWConnection, _ number: Int, held: String) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, complete, error in
            guard let self else { return }
            if self.plainToTls {
                connection.send(
                    content: Data("SIP/2.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n".utf8),
                    completion: .contentProcessed { _ in connection.cancel() }
                )
                return
            }
            var held = held + (data.map { String(decoding: $0, as: UTF8.self) } ?? "")
            while let end = held.range(of: "\r\n\r\n") {
                let head = String(held[..<end.lowerBound])
                let length = Int(Self.header("Content-Length", head) ?? "0") ?? 0
                let body = held[end.upperBound...]
                guard body.utf8.count >= length else { break }
                let message = head + "\r\n\r\n" + String(body.prefix(length))
                held = String(body.dropFirst(length))
                self.lock.withLock { self._requests.append((number, message)) }
                if message.hasPrefix("REGISTER ") {
                    connection.send(content: Data(Self.ok(message).utf8), completion: .idempotent)
                }
            }
            if complete || error != nil {
                connection.cancel()
                return
            }
            self.read(connection, number, held: held)
        }
    }

    static func header(_ name: String, _ message: String) -> String? {
        message.components(separatedBy: "\r\n")
            .first { $0.lowercased().hasPrefix(name.lowercased() + ":") }
            .map { String($0.drop(while: { $0 != ":" }).dropFirst()).trimmingCharacters(in: .whitespaces) }
    }

    private static func ok(_ request: String) -> String {
        var lines = ["SIP/2.0 200 OK"]
        for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
            let value = header(name, request) ?? ""
            lines.append(name == "To" ? "To: \(value);tag=registrar" : "\(name): \(value)")
        }
        lines.append("Contact: \(header("Contact", request) ?? "");expires=3600")
        lines.append("Content-Length: 0")
        return lines.joined(separator: "\r\n") + "\r\n\r\n"
    }
}

/// SIP over TCP and TLS through `SipralStack`'s `signalling` -- the Swift
/// counterpart of `bindings/python/tests/test_signalling.py`: a stack
/// registers over the one connection it opened; a certificate refused for
/// each reason `SipralTlsFailure` names arrives as
/// `SipralEventKind.transportFailed` carrying that reason; a registrar that
/// closes the connection is connected to again and the account registers
/// again on the new one; and the INVITE rate floor's voice-agent preset lets
/// through a burst the default answers 480.
final class SignallingTests: XCTestCase {
    private static let serverName = "registrar.sipral.test"

    private func stack(
        _ server: String, _ signalling: SipralTransport = .tls, name: String? = serverName,
        trust: TLSTrust = .platform
    ) throws -> SipralStack {
        try SipralStack(
            audio: .application, signalling: signalling, signallingServer: server, tlsServerName: name,
            tlsTrust: trust
        )
    }

    private func refusal(_ stack: SipralStack) async throws -> TransportFailedEventData {
        for await event in stack.events() where event.kind == .transportFailed {
            XCTAssertFalse(stack.connected)
            let failed = try XCTUnwrap(event.transportFailedData)
            XCTAssertEqual(failed.protocolRaw, SipralTransport.tls.rawValue)
            return failed
        }
        throw XCTSkip("the stack closed before it said why")
    }

    private func registered(_ account: Account) async throws {
        for _ in 0..<100 {
            if try account.registrationState == .registered { return }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTFail("the account never registered")
    }

    func testARegistrarWhoseAuthorityIsPinnedRegistersTheAccountOverTls() async throws {
        let (identity, der) = try Self.certificate("good")
        let registrar = try FakeRegistrar(identity: identity)
        defer { registrar.stop() }
        let stack = try stack(registrar.address, trust: .onlyAuthority(der))
        defer { stack.close() }
        XCTAssertTrue(stack.connected)
        let account = try stack.addAccount(
            aor: "sip:alice@\(Self.serverName)", registrarAddress: registrar.address,
            registrar: "sip:\(Self.serverName)"
        )
        try account.register()
        try await registered(account)
        XCTAssertEqual(registrar.registers.count, 1)
        let register = try XCTUnwrap(registrar.registers.first)
        XCTAssertEqual(register.connection, 1)
        XCTAssertTrue(FakeRegistrar.header("Via", register.message)?.hasPrefix("SIP/2.0/TLS ") == true)
        XCTAssertTrue(FakeRegistrar.header("Contact", register.message)?.contains(";transport=tls") == true)
        XCTAssertTrue(FakeRegistrar.header("Contact", register.message)?.contains(stack.bindAddress) == true)
    }

    func testACertificateNoTrustedAuthoritySignedIsUntrusted() async throws {
        let (identity, _) = try Self.certificate("good")
        let registrar = try FakeRegistrar(identity: identity)
        defer { registrar.stop() }
        let stack = try stack(registrar.address)
        defer { stack.close() }
        let failed = try await refusal(stack)
        XCTAssertEqual(failed.tls, .untrusted)
        XCTAssertFalse(failed.detail?.isEmpty ?? true)
        let account = try stack.addAccount(
            aor: "sip:alice@\(Self.serverName)", registrarAddress: registrar.address,
            registrar: "sip:\(Self.serverName)"
        )
        try account.register()
        XCTAssertTrue(account.wantsRegistration)
        XCTAssertTrue(registrar.registers.isEmpty)
    }

    func testACertificateForAnotherNameIsANameMismatch() async throws {
        let (identity, der) = try Self.certificate("good")
        let registrar = try FakeRegistrar(identity: identity)
        defer { registrar.stop() }
        let stack = try stack(registrar.address, name: "other.sipral.test", trust: .onlyAuthority(der))
        defer { stack.close() }
        let failed = try await refusal(stack)
        XCTAssertEqual(failed.tls, .nameMismatch, failed.detail ?? "")
    }

    func testAnExpiredCertificateIsExpired() async throws {
        let (identity, der) = try Self.certificate(
            "expired", ["-not_before", "20200101000000Z", "-not_after", "20200102000000Z"]
        )
        let registrar = try FakeRegistrar(identity: identity)
        defer { registrar.stop() }
        let stack = try stack(registrar.address, trust: .onlyAuthority(der))
        defer { stack.close() }
        let failed = try await refusal(stack)
        XCTAssertEqual(failed.tls, .expired, failed.detail ?? "")
    }

    func testAServerThatDoesNotSpeakTlsRefusesTheHandshake() async throws {
        let registrar = try FakeRegistrar(plainToTls: true)
        defer { registrar.stop() }
        let stack = try stack(registrar.address)
        defer { stack.close() }
        let failed = try await refusal(stack)
        XCTAssertEqual(failed.tls, .handshakeRefused, failed.detail ?? "")
    }

    func testNobodyListeningIsARefusedConnectionAndNoTlsReason() async throws {
        let nobody = try FakeRegistrar()
        let address = nobody.address
        nobody.stop()
        try await Task.sleep(nanoseconds: 100_000_000)
        let stack = try stack(address)
        defer { stack.close() }
        let failed = try await refusal(stack)
        XCTAssertEqual(failed.error, .connectionRefused, failed.detail ?? "")
        XCTAssertEqual(failed.tls, SipralTlsFailure.none)
    }

    /// A connection that is ready before its path names the local end --
    /// what a loaded machine does -- still hands its local address on once
    /// the path names it: the stack is created on that address and a
    /// recording server's connection is bound by it, and an empty one is
    /// refused as "not given" by whichever of the two it reaches.
    func testALocalAddressThatArrivesAfterTheConnectionIsReadyIsStillTaken() {
        var reads = 0
        let named = SignallingConnection.localAddress(within: 2000) {
            reads += 1
            return reads < 4 ? nil : .hostPort(host: "127.0.0.1", port: 50600)
        }
        XCTAssertEqual(named, "127.0.0.1:50600")
        XCTAssertEqual(reads, 4)
    }

    /// And one whose path never names it is refused, not handed on empty.
    func testALocalAddressThatNeverArrivesIsNoAddress() {
        XCTAssertNil(SignallingConnection.localAddress(within: 20) { nil })
    }

    func testTheAccountRegistersAgainOnTheNewConnection() async throws {
        let registrar = try FakeRegistrar()
        defer { registrar.stop() }
        let stack = try stack(registrar.address, .tcp, name: nil)
        defer { stack.close() }
        let events = stack.events()
        let account = try stack.addAccount(
            aor: "sip:alice@sipral.invalid", registrarAddress: registrar.address, registrar: "sip:sipral.invalid"
        )
        try account.register()
        try await registered(account)
        let first = stack.bindAddress
        registrar.drop()
        for await event in events where event.kind == .transportFailed {
            XCTAssertEqual(event.transportFailedData?.error, .closed)
            XCTAssertEqual(event.transportFailedData?.protocolRaw, SipralTransport.tcp.rawValue)
            break
        }
        for _ in 0..<200 where !registrar.registers.contains(where: { $0.connection == 2 }) {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        let again = try XCTUnwrap(registrar.registers.first { $0.connection == 2 }?.message)
        XCTAssertNotEqual(stack.bindAddress, first)
        XCTAssertTrue(FakeRegistrar.header("Contact", again)?.contains(stack.bindAddress) == true)
        XCTAssertTrue(FakeRegistrar.header("Contact", again)?.contains(";transport=tcp") == true)
    }

    /// The stack retires the main connection on its own when a flow that
    /// answered keep-alives stops answering them (RFC 5626 §4.4.1), with the
    /// socket still open here; said here the way it says it.
    func testAConnectionTheStackLetGoOfIsMadeAgain() async throws {
        let registrar = try FakeRegistrar()
        defer { registrar.stop() }
        let stack = try stack(registrar.address, .tcp, name: nil)
        defer { stack.close() }
        let events = stack.events()
        let account = try stack.addAccount(
            aor: "sip:alice@sipral.invalid", registrarAddress: registrar.address, registrar: "sip:sipral.invalid"
        )
        try account.register()
        try await registered(account)
        let first = stack.bindAddress
        try retryingBusy {
            try Sipral.stackTransportFailed(
                stack: stack.handle, transport: Sipral.transportMain,
                error: SipralTransportError.timedOut.rawValue, nowMs: stack.nowMs()
            )
        }
        for await event in events where event.kind == .transportFailed {
            XCTAssertEqual(event.transportFailedData?.transport, Sipral.transportMain)
            break
        }
        for _ in 0..<200 where !registrar.registers.contains(where: { $0.connection == 2 }) {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        let again = try XCTUnwrap(
            registrar.registers.first { $0.connection == 2 }?.message, "no REGISTER on a second connection"
        )
        XCTAssertNotEqual(stack.bindAddress, first)
        XCTAssertTrue(FakeRegistrar.header("Contact", again)?.contains(stack.bindAddress) == true)
    }

    /// Twenty INVITEs from one address at once: how many were answered
    /// 480, each counted once however often its refusal is sent again.
    private func rush(_ limit: InviteLimit?) async throws -> Int {
        let stack = try SipralStack(audio: .application, inviteLimit: limit)
        defer { stack.close() }
        _ = try stack.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: "127.0.0.1:9")
        let caller = try UDPSocket(host: "127.0.0.1", port: 0)
        defer { caller.close() }
        let here = caller.localAddress
        let target = stack.bindAddress
        for n in 0..<20 {
            let invite = "INVITE sip:bob@\(target) SIP/2.0\r\n"
                + "Via: SIP/2.0/UDP \(here);branch=z9hG4bK-rush-\(n)\r\n"
                + "Max-Forwards: 70\r\n"
                + "From: <sip:trunk@\(here)>;tag=rush\(n)\r\n"
                + "To: <sip:bob@\(target)>\r\n"
                + "Call-ID: rush-\(n)@trunk\r\n"
                + "CSeq: 1 INVITE\r\n"
                + "Contact: <sip:trunk@\(here)>\r\n"
                + "Content-Length: 0\r\n\r\n"
            // paced: a burst of datagrams from a non-blocking socket is
            // one the kernel may refuse part of, and every INVITE has to
            // arrive for the count to mean anything
            while !caller.send(Array(invite.utf8), to: target) {
                usleep(1000)
            }
            usleep(1000)
        }
        var refused = Set<String>()
        let until = Date().addingTimeInterval(2)
        while Date() < until {
            guard let (data, _) = caller.receive() else {
                try await Task.sleep(nanoseconds: 10_000_000)
                continue
            }
            let text = String(decoding: data, as: UTF8.self)
            if text.hasPrefix("SIP/2.0 480 ") {
                refused.insert(FakeRegistrar.header("Call-ID", text) ?? "")
            }
        }
        return refused.count
    }

    func testTheDefaultAnswersARush480AndTheVoiceAgentPresetTakesIt() async throws {
        let standard = try await rush(nil)
        XCTAssertEqual(standard, 10, "ten at once, then one every two seconds")
        let agent = try await rush(.voiceAgent)
        XCTAssertEqual(agent, 0)
        XCTAssertEqual(InviteLimit.standard, InviteLimit(burst: 10, everyMs: 2000))
    }

    /// A key and a certificate for `serverName`, made with the `openssl`
    /// command and imported into memory alone -- never into a keychain.
    private static func certificate(_ name: String, _ dates: [String] = ["-days", "1"]) throws -> (SecIdentity, [UInt8]) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("sipral-\(name)-\(UInt32.random(in: 0...UInt32.max))")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let key = directory.appendingPathComponent("\(name).key").path
        let pem = directory.appendingPathComponent("\(name).pem").path
        let der = directory.appendingPathComponent("\(name).der").path
        let p12 = directory.appendingPathComponent("\(name).p12").path
        try openssl([
            "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-subj", "/CN=\(serverName)", "-addext", "subjectAltName=DNS:\(serverName)",
            "-addext", "extendedKeyUsage=serverAuth",
            "-keyout", key, "-out", pem,
        ] + dates)
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
            throw XCTSkip("no openssl command to make the registrar's certificate with")
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
