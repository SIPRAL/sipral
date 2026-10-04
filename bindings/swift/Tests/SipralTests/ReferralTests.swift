// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import XCTest
@testable import Sipral

/// A REFER outside any dialog, through this layer -- the Swift counterpart
/// of `bindings/python/tests/test_referral.py`. The referrer is a plain UDP
/// socket writing RFC 3515 §4.1's own REFER by hand: a switchboard asking
/// Bob's line to ring Carol, a second stack that answers.
final class ReferralTests: XCTestCase {
    func testAStackThatWasNotToldToTakeThemRefusesThem403() async throws {
        let referrer = try UDPSocket(host: "127.0.0.1", port: 0)
        defer { referrer.close() }
        let bob = try SipralStack(audio: .application)
        defer { bob.close() }
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: referrer.localAddress)

        referrer.send(refer(to: bob.bindAddress, from: referrer.localAddress, target: "sip:carol@sipral.invalid"),
                      to: bob.bindAddress)
        let seen = await read(referrer, within: 5) { seen in seen.contains { $0.hasPrefix("SIP/2.0 ") } }
        XCTAssertTrue(seen.contains { $0.hasPrefix("SIP/2.0 403 ") }, "\(seen)")
    }

    func testAReferralTakenPlacesTheCallAndReportsItToTheReferrer() async throws {
        let referrer = try UDPSocket(host: "127.0.0.1", port: 0)
        defer { referrer.close() }
        let carol = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application, referrals: true)
        defer { bob.close(); carol.close() }
        _ = try carol.addAccount(aor: "sip:carol@sipral.invalid", registrarAddress: bob.bindAddress)
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: carol.bindAddress)
        let bobEvents = Recorder(bob.events())
        let carolEvents = Recorder(carol.events())

        let target = "sip:carol@\(carol.bindAddress)"
        referrer.send(refer(to: bob.bindAddress, from: referrer.localAddress, target: target), to: bob.bindAddress)

        let asked = await bobEvents.first(within: 5) { $0.kind == .referral }
        let referral = try XCTUnwrap(asked, "the application was never asked")
        let data = try XCTUnwrap(referral.referralData)
        XCTAssertEqual(data.statusCode, 0)
        XCTAssertEqual(data.target, target)
        XCTAssertEqual(data.referredBy, "<sip:switchboard@sipral.invalid>")
        XCTAssertFalse(data.attended)
        XCTAssertNotEqual(referral.account, Sipral.handleNone, "the line it arrived for")

        let placed = try bob.acceptReferral(referral)
        defer { placed.close() }
        let rang = await carolEvents.first(within: 5) { $0.kind == .incomingCall }
        let incoming = try XCTUnwrap(rang, "the placed call never reached Carol")
        let answered = try carol.answerCall(incoming)
        defer { answered.close() }

        let seen = await read(referrer, within: 8) { seen in
            seen.contains { $0.hasPrefix("NOTIFY ") && $0.contains("SIP/2.0 200 OK") }
        }
        XCTAssertTrue(seen.contains { $0.hasPrefix("SIP/2.0 202 ") }, "\(seen)")
        let notifies = seen.filter { $0.hasPrefix("NOTIFY ") }
        let first = try XCTUnwrap(notifies.first, "\(seen)")
        XCTAssertTrue(first.contains("SIP/2.0 100 Trying"))
        XCTAssertTrue(header("Subscription-State", in: first)?.hasPrefix("active") ?? false)
        let last = try XCTUnwrap(notifies.last)
        XCTAssertTrue(last.contains("SIP/2.0 200 OK"))
        XCTAssertEqual(header("Subscription-State", in: last), "terminated;reason=noresource")
        XCTAssertEqual(header("Content-Type", in: last), "message/sipfrag;version=2.0")

        let deadline = DispatchTime.now() + 5
        while placed.media == nil && DispatchTime.now() < deadline {
            usleep(20_000)
        }
        XCTAssertNotNil(placed.media, "the placed call never got its audio")
    }

    private func refer(to stack: String, from referrer: String, target: String) -> [UInt8] {
        Array((
            "REFER sip:bob@\(stack) SIP/2.0\r\n"
                + "Via: SIP/2.0/UDP \(referrer);branch=z9hG4bK-click-to-dial\r\n"
                + "Max-Forwards: 70\r\n"
                + "From: <sip:switchboard@sipral.invalid>;tag=switchboard\r\n"
                + "To: <sip:bob@sipral.invalid>\r\n"
                + "Call-ID: click-to-dial@sipral.invalid\r\n"
                + "CSeq: 1 REFER\r\n"
                + "Contact: <sip:switchboard@\(referrer)>\r\n"
                + "Refer-To: <\(target)>\r\n"
                + "Referred-By: <sip:switchboard@sipral.invalid>\r\n"
                + "Content-Length: 0\r\n\r\n"
        ).utf8)
    }

    /// Everything `socket` receives, each NOTIFY answered 200 as the
    /// switchboard would, until `done` holds or `seconds` pass.
    private func read(_ socket: UDPSocket, within seconds: Double, until done: ([String]) -> Bool) async -> [String] {
        var seen: [String] = []
        let deadline = DispatchTime.now() + seconds
        while DispatchTime.now() < deadline && !done(seen) {
            while let (data, source) = socket.receive() {
                let text = String(decoding: data, as: UTF8.self)
                seen.append(text)
                if text.hasPrefix("NOTIFY ") {
                    socket.send(ok(to: text), to: source)
                }
            }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        return seen
    }

    private func ok(to request: String) -> [UInt8] {
        let copied = ["Via", "From", "To", "Call-ID", "CSeq"].compactMap { name in
            header(name, in: request).map { "\(name): \($0)" }
        }
        return Array(((["SIP/2.0 200 OK"] + copied + ["Content-Length: 0", "", ""]).joined(separator: "\r\n")).utf8)
    }

    private func header(_ name: String, in message: String) -> String? {
        message.components(separatedBy: "\r\n")
            .first { $0.lowercased().hasPrefix("\(name.lowercased()):") }
            .map { String($0.dropFirst(name.count + 1)).trimmingCharacters(in: .whitespaces) }
    }
}
