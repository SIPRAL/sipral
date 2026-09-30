// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

#if canImport(Network)
import Dispatch
import Foundation
import Network
import XCTest
@testable import Sipral

/// A PBX on loopback that answers every INVITE without credentials with a 401
/// whose nonce takes the answer past RFC 3261 §18.1.1's 1300 bytes, and --
/// with `tcp` -- a TCP listener on the same port that answers the INVITE
/// carrying credentials with a 486. Every request a connection carried is
/// recorded.
final class ChallengingPbx: @unchecked Sendable {
    private let udp: UDPSocket
    private var listener: NWListener?
    private let queue = DispatchQueue(label: "org.sipral.test.pbx")
    private let lock = NSLock()
    private var _overTcp: [String] = []
    private var _connections = 0
    private var _closedByTheStack = 0
    private var stopped = false
    let address: String

    /// `apart`: TCP on a port of its own, as a PBX that takes UDP on 5060 and
    /// TCP on 5160 has it.
    init(tcp: Bool, apart: Bool = false) throws {
        udp = try UDPSocket(host: "127.0.0.1", port: 0)
        address = udp.localAddress
        let port = UDPSocket.parse(address).port
        if tcp {
            let parameters = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
            parameters.requiredLocalEndpoint = .hostPort(
                host: "127.0.0.1", port: apart ? .any : NWEndpoint.Port(rawValue: port)!
            )
            let listener = try NWListener(using: parameters)
            let ready = DispatchSemaphore(value: 0)
            listener.stateUpdateHandler = { state in
                if case .ready = state { ready.signal() }
            }
            listener.newConnectionHandler = { [weak self] connection in self?.serve(connection) }
            listener.start(queue: queue)
            guard ready.wait(timeout: .now() + 5) == .success else {
                throw XCTSkip("the PBX could not listen on TCP beside its UDP port")
            }
            self.listener = listener
        }
        Thread { [weak self] in self?.serveUdp() }.start()
    }

    /// Where TCP is taken, `nil` without it.
    var tcpAddress: String? { listener?.port.map { "127.0.0.1:\($0.rawValue)" } }
    var overTcp: [String] { lock.withLock { _overTcp } }
    var connections: Int { lock.withLock { _connections } }
    /// How many of those connections the stack closed.
    var closedByTheStack: Int { lock.withLock { _closedByTheStack } }

    func stop() {
        lock.withLock { stopped = true }
        listener?.cancel()
    }

    private func serveUdp() {
        let nonce = String(repeating: "n", count: 700)
        while !lock.withLock({ stopped }) {
            guard let (data, from) = udp.receive() else {
                usleep(2_000)
                continue
            }
            let message = String(decoding: data, as: UTF8.self)
            if message.hasPrefix("INVITE "), FakeRegistrar.header("Authorization", message) == nil {
                let challenge = "WWW-Authenticate: Digest realm=\"asterisk\", nonce=\"\(nonce)\", qop=\"auth\"\r\n"
                udp.send(Array(Self.response(message, "401 Unauthorized", challenge).utf8), to: from)
            }
        }
        udp.close()
    }

    private func serve(_ connection: NWConnection) {
        lock.withLock { _connections += 1 }
        connection.start(queue: queue)
        read(connection, held: "")
    }

    private func read(_ connection: NWConnection, held: String) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, complete, error in
            guard let self else { return }
            var held = held + (data.map { String(decoding: $0, as: UTF8.self) } ?? "")
            while let end = held.range(of: "\r\n\r\n") {
                let head = String(held[..<end.lowerBound]) + "\r\n"
                let length = Int(FakeRegistrar.header("Content-Length", head) ?? "0") ?? 0
                let body = held[end.upperBound...]
                guard body.utf8.count >= length else { break }
                held = String(body.dropFirst(length))
                self.lock.withLock { self._overTcp.append(head) }
                if head.hasPrefix("INVITE ") {
                    connection.send(content: Data(Self.response(head, "486 Busy Here").utf8), completion: .idempotent)
                }
            }
            if complete || error != nil {
                if complete {
                    self.lock.withLock { self._closedByTheStack += 1 }
                }
                connection.cancel()
                return
            }
            self.read(connection, held: held)
        }
    }

    static func response(_ request: String, _ status: String, _ extra: String = "") -> String {
        var lines = ["SIP/2.0 \(status)"]
        for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
            var value = FakeRegistrar.header(name, request) ?? ""
            if name == "To", !value.contains(";tag=") {
                value += ";tag=pbx"
            }
            lines.append("\(name): \(value)")
        }
        return lines.joined(separator: "\r\n") + "\r\n" + extra + "Content-Length: 0\r\n\r\n"
    }
}

/// RFC 3261 §18.1.1 through `SipralStack`: a call whose answer to a challenge
/// is too large for a datagram -- the Swift counterpart of
/// `bindings/python/tests/test_datagram_limit.py`. With a TCP listener at the
/// PBX the stack opens the connection itself and the call carries on over
/// it; with none, or with `streamFallback: false`, the call ends at once with
/// a 513 naming the limit, never hanging.
final class DatagramLimitTests: XCTestCase {
    private func place(_ stack: SipralStack, _ pbx: ChallengingPbx) throws {
        let account = try stack.addAccount(
            aor: "sip:alice@example.com", registrarAddress: pbx.address,
            authUser: "alice", authPassword: "open sesame",
            security: AccountSecurity(srtp: .offered, srtpSuites: ["AEAD_AES_256_GCM", "AES_CM_128_HMAC_SHA1_80"])
        )
        _ = try stack.placeCall(account: account, target: "sip:bob@example.com")
    }

    /// Every event up to and including the call's end, or a failure after
    /// `seconds`.
    private func untilTheEnd(_ stack: SipralStack, seconds: Double = 8) async throws -> [SipralEvent] {
        let events = stack.events()
        return try await withThrowingTaskGroup(of: [SipralEvent]?.self) { group in
            group.addTask {
                var seen: [SipralEvent] = []
                for await event in events {
                    seen.append(event)
                    if event.kind == .callEnded { return seen }
                }
                return nil
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                return nil
            }
            let first = try await group.next() ?? nil
            group.cancelAll()
            return try XCTUnwrap(first, "the call never ended")
        }
    }

    func testAPbxListeningOnTcpGetsTheAnswerOverAConnectionTheStackOpened() async throws {
        let pbx = try ChallengingPbx(tcp: true)
        defer { pbx.stop() }
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let ending = Task { try await untilTheEnd(stack) }
        try place(stack, pbx)
        let seen = try await ending.value

        let wanted = seen.compactMap(\.transportWantedData)
        XCTAssertEqual(wanted.count, 1)
        XCTAssertEqual(wanted.first?.destination, pbx.address)
        XCTAssertGreaterThan(wanted.first?.requestBytes ?? 0, 1300)
        XCTAssertEqual(wanted.first?.limitBytes, 1300)

        let ended = try XCTUnwrap(seen.last?.callData)
        XCTAssertEqual(ended.statusCode, 486, "the PBX's own answer, over the connection")
        XCTAssertEqual(ended.endReason, .refused)
        XCTAssertEqual(pbx.connections, 1)
        let invites = pbx.overTcp.filter { $0.hasPrefix("INVITE ") }
        XCTAssertEqual(invites.count, 1)
        XCTAssertNotNil(FakeRegistrar.header("Authorization", invites[0]))
        XCTAssertTrue(FakeRegistrar.header("Via", invites[0])?.hasPrefix("SIP/2.0/TCP ") == true)
        // the dialog carries on over the connection: the 486 is acknowledged
        // on it (RFC 3261 §17.1.1.3)
        for _ in 0..<100 where !pbx.overTcp.contains(where: { $0.hasPrefix("ACK ") }) {
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        XCTAssertTrue(pbx.overTcp.contains { $0.hasPrefix("ACK ") })
    }

    func testAPbxOnUdpAloneEndsTheCallAtOnceWithTheLimitNamed() async throws {
        let pbx = try ChallengingPbx(tcp: false)
        defer { pbx.stop() }
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let started = Date()
        let ending = Task { try await untilTheEnd(stack) }
        try place(stack, pbx)
        let seen = try await ending.value
        XCTAssertLessThan(Date().timeIntervalSince(started), 5, "ended by the refusal, not by the wait")

        let lost = seen.compactMap(\.transportFailedData)
        XCTAssertEqual(lost.first?.error, .connectionRefused)
        let ended = try XCTUnwrap(seen.last?.callData)
        XCTAssertEqual(ended.endReason, .unreachable)
        XCTAssertEqual(ended.statusCode, 513)
        XCTAssertEqual(ended.endCause?.sip, 513)
        XCTAssertTrue(ended.endCause?.text?.contains("1300-byte") == true, ended.endCause?.text ?? "")
        XCTAssertTrue(ended.endCause?.text?.contains("18.1.1") == true)
    }

    func testAPbxTakingTcpOnAnotherPortIsReachedAtTheStreamServer() async throws {
        let pbx = try ChallengingPbx(tcp: true, apart: true)
        defer { pbx.stop() }
        let stack = try SipralStack(audio: .application, streamServer: pbx.tcpAddress)
        defer { stack.close() }
        let ending = Task { try await untilTheEnd(stack) }
        try place(stack, pbx)
        let seen = try await ending.value
        XCTAssertEqual(seen.last?.callData?.statusCode, 486, "answered over the connection")
        XCTAssertEqual(pbx.connections, 1)
        let invites = pbx.overTcp.filter { $0.hasPrefix("INVITE ") }
        XCTAssertEqual(invites.count, 1)
        XCTAssertNotNil(FakeRegistrar.header("Authorization", invites.first ?? ""))
    }

    func testAStackToldToOpenNoStreamEndsTheCallWithoutTrying() async throws {
        let pbx = try ChallengingPbx(tcp: true)
        defer { pbx.stop() }
        let stack = try SipralStack(audio: .application, streamFallback: false)
        defer { stack.close() }
        let ending = Task { try await untilTheEnd(stack) }
        try place(stack, pbx)
        let seen = try await ending.value
        XCTAssertEqual(seen.last?.callData?.statusCode, 513)
        XCTAssertEqual(pbx.connections, 0, "nothing was opened")
    }

    /// RFC 5626 §4.4.1: the stack retires a stream that stopped answering
    /// keep-alives and says so with `transportFailed`; the socket is this
    /// layer's, and one kept open would stand in for the new connection the
    /// stack asks for next time.
    func testAConnectionTheStackLetGoOfIsClosedHereToo() async throws {
        let pbx = try ChallengingPbx(tcp: true)
        defer { pbx.stop() }
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let ending = Task { try await untilTheEnd(stack) }
        try place(stack, pbx)
        _ = try await ending.value
        XCTAssertEqual(pbx.connections, 1)
        XCTAssertEqual(pbx.closedByTheStack, 0, "the connection outlives the call")

        stack.noteStreamLetGo(SipralStack.firstStreamLink)
        for _ in 0..<150 where pbx.closedByTheStack == 0 {
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        XCTAssertEqual(pbx.closedByTheStack, 1, "the connection was let go of")
    }
}
#endif
