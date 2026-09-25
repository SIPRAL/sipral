// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import XCTest
@testable import Sipral

/// A server reached at one address whose answer names another in its
/// `Contact` -- the lab's Asterisk, published on a mapped port and naming
/// the port it listens on inside its container, or any registrar behind a
/// NAT. The dialog's requests have to stay on the path the INVITE took:
/// the ACK did all along, and the BYE has to follow it rather than go to an
/// address nothing answers on.
final class DialogFlowTests: XCTestCase {
    func testEveryRequestOfTheDialogTakesThePathTheInviteTook() async throws {
        let server = try UDPSocket(host: "127.0.0.1", port: 0)
        let named = try UDPSocket(host: "127.0.0.1", port: 0)
        let audio = try UDPSocket(host: "127.0.0.1", port: 0)
        defer {
            server.close()
            named.close()
            audio.close()
        }

        let stack = try SipralStack()
        defer { stack.close() }
        let account = try stack.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: server.localAddress)
        let call = try stack.placeCall(account: account, target: "sip:bob@\(server.localAddress)")
        defer { call.close() }
        let events = Recorder(call.events())

        let arrived = await requests(on: server, within: 5, until: "INVITE")
        let invite = try XCTUnwrap(arrived.first { $0.hasPrefix("INVITE ") }, "no INVITE reached the server")
        let (_, audioPort) = UDPSocket.parse(audio.localAddress)
        let sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
            + "m=audio \(audioPort) RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
        let copied = ["Via", "From", "Call-ID", "CSeq"].compactMap { header($0, in: invite) }
        let answer = (["SIP/2.0 200 OK"] + copied + [
            (header("To", in: invite) ?? "To: <sip:bob@sipral.invalid>") + ";tag=far",
            "Contact: <sip:bob@\(named.localAddress)>",
            "Content-Type: application/sdp",
            "Content-Length: \(sdp.utf8.count)",
            "",
            sdp,
        ]).joined(separator: "\r\n")
        server.send(Array(answer.utf8), to: stack.bindAddress)

        let confirmed = await events.first(within: 5) { $0.kind == .callConfirmed }
        XCTAssertNotNil(confirmed, "the 200 OK did not confirm the call")
        try call.hangup()

        let atServer = await requests(on: server, within: 5, until: "BYE")
        let atNamed = await requests(on: named, within: 0.5, until: "BYE")
        XCTAssertTrue(atServer.contains { $0.hasPrefix("ACK ") }, "the ACK did not reach the server")
        XCTAssertTrue(atServer.contains { $0.hasPrefix("BYE ") }, "the BYE did not reach the server")
        XCTAssertFalse(
            atNamed.contains { $0.hasPrefix("BYE ") },
            "the BYE went to the address the Contact names instead of the path the INVITE took"
        )
    }

    /// Every request `socket` receives until one starts with `method`, or
    /// until `seconds` pass.
    private func requests(on socket: UDPSocket, within seconds: Double, until method: String) async -> [String] {
        var seen: [String] = []
        let deadline = DispatchTime.now() + seconds
        while DispatchTime.now() < deadline {
            while let (data, _) = socket.receive() {
                let text = String(decoding: data, as: UTF8.self)
                seen.append(text)
                if text.hasPrefix("\(method) ") { return seen }
            }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        return seen
    }

    private func header(_ name: String, in message: String) -> String? {
        message.components(separatedBy: "\r\n").first { $0.hasPrefix("\(name):") }
    }
}
