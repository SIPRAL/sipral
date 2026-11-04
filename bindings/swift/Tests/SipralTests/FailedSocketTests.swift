// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(Darwin)
import Darwin
import XCTest
@testable import Sipral

/// A signalling socket that polls readable and fails every read, as iOS
/// leaves one it took back while the application was suspended: made here
/// by putting a pipe with a byte in it on the socket's descriptor, which
/// `recvfrom` refuses with ENOTSOCK for as long as it is read.
final class FailedSocketTests: XCTestCase {
    func testASocketWhoseReadsFailSaysSoAndOneWithNothingWaitingDoesNot() throws {
        let idle = try UDPSocket(host: "127.0.0.1", port: 0)
        defer { idle.close() }
        XCTAssertNil(idle.receive())
        XCTAssertFalse(idle.failed, "nothing waiting is no failure")

        let broken = try UDPSocket(host: "127.0.0.1", port: 0)
        defer { broken.close() }
        try Self.makeUnreadable(broken.fd)
        XCTAssertNil(broken.receive())
        XCTAssertTrue(broken.failed)
    }

    func testAStackReplacesItsFailedSignallingSocketOnTheSamePort() throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let at = UDPSocket.parse(stack.bindAddress)
        let fd = try XCTUnwrap(Self.datagramDescriptor(on: at.port), "the stack's signalling socket")
        try Self.makeUnreadable(fd)

        let peer = try UDPSocket(host: "127.0.0.1", port: 0)
        defer { peer.close() }
        let deadline = Date().addingTimeInterval(5)
        var answer: String?
        var sequence = 0
        while answer == nil, Date() < deadline {
            sequence += 1
            peer.send(Array(Self.options(from: peer.localAddress, to: stack.bindAddress, sequence: sequence).utf8),
                      toHost: at.host, port: at.port)
            let until = Date().addingTimeInterval(0.5)
            while answer == nil, Date() < until {
                if let (data, _) = peer.receive() {
                    answer = String(decoding: data, as: UTF8.self)
                } else {
                    usleep(10_000)
                }
            }
        }
        let reply = try XCTUnwrap(answer, "nothing answered on the stack's port after its socket failed")
        XCTAssertTrue(reply.hasPrefix("SIP/2.0 200"), reply)
        XCTAssertEqual(UDPSocket.parse(stack.bindAddress).port, at.port, "the port moved")
    }

    /// A pipe holding a byte, on `fd`: readable to `poll` for good, and no
    /// socket to `recvfrom`.
    private static func makeUnreadable(_ fd: Int32) throws {
        var ends: [Int32] = [0, 0]
        guard pipe(&ends) == 0 else { throw XCTSkip("no pipe") }
        _ = write(ends[1], "x", 1)
        XCTAssertEqual(dup2(ends[0], fd), fd)
        close(ends[0])
        close(ends[1])
    }

    /// This process's UDP descriptor bound to `port`.
    private static func datagramDescriptor(on port: UInt16) -> Int32? {
        for fd in Int32(0)..<Int32(4096) {
            var kind: Int32 = 0
            var kindLength = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(fd, SOL_SOCKET, SO_TYPE, &kind, &kindLength) == 0, kind == SOCK_DGRAM else { continue }
            var address = sockaddr_in()
            var length = socklen_t(MemoryLayout<sockaddr_in>.size)
            let named = withUnsafeMutablePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
            }
            if named == 0, address.sin_family == sa_family_t(AF_INET), UInt16(bigEndian: address.sin_port) == port {
                return fd
            }
        }
        return nil
    }

    private static func options(from: String, to: String, sequence: Int) -> String {
        [
            "OPTIONS sip:\(to) SIP/2.0",
            "Via: SIP/2.0/UDP \(from);branch=z9hG4bKfailed\(sequence)",
            "Max-Forwards: 70",
            "From: <sip:peer@\(from)>;tag=peer",
            "To: <sip:\(to)>",
            "Call-ID: failed-socket-\(sequence)",
            "CSeq: \(sequence) OPTIONS",
            "Content-Length: 0",
            "",
            "",
        ].joined(separator: "\r\n")
    }
}
#endif
