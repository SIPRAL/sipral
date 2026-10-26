// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Dispatch
import Foundation
import XCTest
@testable import Sipral

/// A loopback PBX that answers every INVITE 486 with an `X-Carrier-Route`
/// header and writes down what it received.
private final class BusyPbx: @unchecked Sendable {
    private let udp: UDPSocket
    private let lock = NSLock()
    private var _received: [String] = []
    private var stopped = false
    let address: String

    init() throws {
        udp = try UDPSocket(host: "127.0.0.1", port: 0)
        address = udp.localAddress
        Thread { [weak self] in self?.serve() }.start()
    }

    var received: [String] { lock.withLock { _received } }
    var invites: [String] { received.filter { $0.hasPrefix("INVITE ") } }

    func stop() {
        lock.withLock { stopped = true }
    }

    private func serve() {
        while !lock.withLock({ stopped }) {
            guard let (data, from) = udp.receive() else {
                usleep(2_000)
                continue
            }
            let message = String(decoding: data, as: UTF8.self)
            lock.withLock { _received.append(message) }
            guard message.hasPrefix("INVITE ") else { continue }
            var lines = ["SIP/2.0 486 Busy Here"]
            for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
                var value = FakeRegistrar.header(name, message) ?? ""
                if name == "To", !value.contains(";tag=") {
                    value += ";tag=pbx"
                }
                lines.append("\(name): \(value)")
            }
            lines.append("X-Carrier-Route: trunk-7")
            let answer = lines.joined(separator: "\r\n") + "\r\nContent-Length: 0\r\n\r\n"
            udp.send(Array(answer.utf8), to: from)
        }
        udp.close()
    }
}

/// What a hook saw, gathered from the thread the stack calls it on.
private final class Seen: @unchecked Sendable {
    private let lock = NSLock()
    private var _all: [(outgoing: Bool, message: String, remote: String)] = []
    var all: [(outgoing: Bool, message: String, remote: String)] { lock.withLock { _all } }

    func add(_ outgoing: Bool, _ message: [UInt8], _ remote: String) {
        lock.withLock { _all.append((outgoing, String(decoding: message, as: UTF8.self), remote)) }
    }
}

private struct HookMistake: Error {}

/// `message` with `line` added at the end of its header fields.
private func adding(_ line: String, to message: [UInt8]) -> [UInt8] {
    let text = String(decoding: message, as: UTF8.self)
    guard let end = text.range(of: "\r\n\r\n") else { return message }
    return Array((String(text[..<end.lowerBound]) + "\r\n" + line + String(text[end.lowerBound...])).utf8)
}

/// The message hook through the Swift layer, the counterpart of
/// bindings/python/tests/test_message_hook.py.
final class MessageHookTests: XCTestCase {
    /// The status the next call to end ended with, or a failure after
    /// `seconds`.
    private func endedStatus(_ events: AsyncStream<SipralEvent>, seconds: Double = 8) async throws -> UInt32 {
        try await withThrowingTaskGroup(of: UInt32?.self) { group in
            group.addTask {
                for await event in events where event.kind == .callEnded {
                    return event.callData?.statusCode
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

    func testAHeaderAddedToAnOutgoingInviteReachesThePbx() async throws {
        let pbx = try BusyPbx()
        defer { pbx.stop() }
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let seen = Seen()
        try stack.setMessageHook { outgoing, message, remote in
            seen.add(outgoing, message, remote)
            if outgoing, message.starts(with: Array("INVITE ".utf8)) {
                return .replace(adding("X-Tenant: blue", to: message))
            }
            return .keep
        }
        let events = stack.events()
        let account = try stack.addAccount(aor: "sip:alice@example.com", registrarAddress: pbx.address)
        _ = try stack.placeCall(account: account, target: "sip:bob@example.com")
        let status = try await endedStatus(events)
        XCTAssertEqual(status, 486)

        XCTAssertEqual(pbx.invites.count, 1, "\(pbx.received)")
        XCTAssertEqual(FakeRegistrar.header("X-Tenant", pbx.invites[0]), "blue")
        XCTAssertTrue(seen.all.contains { !$0.outgoing && $0.message.contains("X-Carrier-Route: trunk-7") })
        XCTAssertTrue(seen.all.allSatisfy { $0.remote == pbx.address })
    }

    func testAnIncomingMessageTheHookDropsIsNotRead() async throws {
        let pbx = try BusyPbx()
        defer { pbx.stop() }
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        try stack.setMessageHook { outgoing, _, _ in outgoing ? .keep : .drop }
        let events = stack.events()
        let account = try stack.addAccount(aor: "sip:alice@example.com", registrarAddress: pbx.address)
        _ = try stack.placeCall(account: account, target: "sip:bob@example.com")
        // every 486 is dropped unread, so the INVITE goes out again and the call stays up
        for _ in 0..<100 where pbx.invites.count < 2 {
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        XCTAssertGreaterThanOrEqual(pbx.invites.count, 2, "\(pbx.received)")
        XCTAssertFalse(pbx.received.contains { $0.hasPrefix("ACK ") }, "a 486 was read and acknowledged")

        try stack.setMessageHook(nil)
        let status = try await endedStatus(events)
        XCTAssertEqual(status, 486)
    }

    func testAHookThatThrowsKeepsTheMessage() async throws {
        let pbx = try BusyPbx()
        defer { pbx.stop() }
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        try stack.setMessageHook { _, _, _ in throw HookMistake() }
        let events = stack.events()
        let account = try stack.addAccount(aor: "sip:alice@example.com", registrarAddress: pbx.address)
        _ = try stack.placeCall(account: account, target: "sip:bob@example.com")
        let status = try await endedStatus(events)
        XCTAssertEqual(status, 486)
    }
}
