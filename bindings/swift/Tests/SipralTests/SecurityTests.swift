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

/// STIR/SHAKEN, per-account SRTP policy and the encryption report between
/// two loopback stacks. Valid signatures use the chain in
/// `bindings/fixtures/stir-provider-709J`, which names a service provider
/// code rather than numbers.
final class SecurityTests: XCTestCase {
    /// Kept short with one codec: a signed INVITE must stay under RFC 3261
    /// §18.1.1's 1300 bytes, as no stream is opened here.
    private let url = "https://c.test/p"
    /// A P-256 private key as the bare scalar: any 32 octets below the group
    /// order are one, and these are nobody's.
    private let key = [UInt8](repeating: 0x2B, count: 32)

    func testASignedCallAsksForItsCertificateAndAStrictAccountRefusesIt() async throws {
        let caller = try SipralStack(audio: .application, codecs: "PCMU")
        let callee = try SipralStack(audio: .application, codecs: "PCMU")
        defer { caller.close(); callee.close() }
        let signing = AccountSecurity(stirKey: key, stirCertificateUrl: url)
        XCTAssertThrowsError(
            try caller.addAccount(aor: "sip:+12155551212@a.test", registrarAddress: callee.bindAddress, security: signing)
        ) { error in
            XCTAssertEqual((error as? SipralError)?.status, .wrongState, "an account that signs needs the time first")
        }

        // a stack that only signs is given the time, and no anchors
        try caller.stir(anchors: nil)
        try callee.stir(anchors: nil)
        let account = try caller.addAccount(
            aor: "sip:+12155551212@a.test", registrarAddress: callee.bindAddress, security: signing
        )
        _ = try callee.addAccount(
            aor: "sip:12125551213@b.test", registrarAddress: caller.bindAddress,
            security: AccountSecurity(stirVerification: .strict)
        )
        let calleeEvents = Recorder(callee.events())
        let call = try caller.placeCall(account: account, target: "sip:12125551213@\(callee.bindAddress)")
        defer { call.close() }

        let wanted = await calleeEvents.first(within: 5) { $0.kind == .callerVerification }
        let asking = try XCTUnwrap(wanted, "the certificate was never asked for")
        let asked = try XCTUnwrap(asking.verificationData)
        XCTAssertEqual(asked.stage, .certificateWanted)
        XCTAssertEqual(asked.certificateUrl, url)

        // a certificate that could not be had: RFC 8224's 436, sent
        try callee.stirCertificate(call: asking.call, chain: nil)
        let judged = await calleeEvents.first(within: 5) {
            $0.kind == .callerVerification && $0.verificationData?.stage == .verified
        }
        let verdict = try XCTUnwrap(try XCTUnwrap(judged, "no verdict").verificationData)
        XCTAssertEqual(verdict.outcome, .invalid)
        XCTAssertEqual(verdict.failure, .certificateUnavailable)
        XCTAssertEqual(verdict.responseCode, 436)
        XCTAssertTrue(verdict.refused)

        let deadline = DispatchTime.now() + 5
        while !call.ended && DispatchTime.now() < deadline {
            usleep(20_000)
        }
        XCTAssertTrue(call.ended, "the caller never heard the 436")
    }

    /// The 709J test credential: root, chain and key.
    private func provider(_ name: String, here: String = #filePath) throws -> [UInt8] {
        let url = URL(fileURLWithPath: here)
            .deletingLastPathComponent()
            .appendingPathComponent("../../../fixtures/stir-provider-709J/\(name)")
        return [UInt8](try Data(contentsOf: url))
    }

    /// The verdict a stack reaches on a call signed under the provider
    /// chain, taking service provider codes or not.
    private func verdict(acceptServiceProviderCodes: Bool) async throws -> VerificationEventData {
        // a moment inside every certificate of the chain
        let within: UInt64 = 1_790_000_000
        let caller = try SipralStack(audio: .application, codecs: "PCMU")
        let callee = try SipralStack(audio: .application, codecs: "PCMU")
        defer { caller.close(); callee.close() }
        try caller.stir(anchors: nil, unixSeconds: within)
        try callee.stir(
            anchors: try provider("anchor.pem"), unixSeconds: within,
            acceptServiceProviderCodes: acceptServiceProviderCodes
        )
        let hex = String(decoding: try provider("signing-scalar.hex"), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        var scalar: [UInt8] = []
        var at = hex.startIndex
        while at < hex.endIndex {
            let next = hex.index(at, offsetBy: 2)
            scalar.append(try XCTUnwrap(UInt8(hex[at..<next], radix: 16)))
            at = next
        }
        let account = try caller.addAccount(
            aor: "sip:+12155551212@a.test", registrarAddress: callee.bindAddress,
            security: AccountSecurity(stirKey: scalar, stirCertificateUrl: url)
        )
        _ = try callee.addAccount(aor: "sip:12125551213@b.test", registrarAddress: caller.bindAddress)
        let calleeEvents = Recorder(callee.events())
        let call = try caller.placeCall(account: account, target: "sip:12125551213@\(callee.bindAddress)")
        defer { call.close() }
        let wanted = await calleeEvents.first(within: 5) { $0.kind == .callerVerification }
        let asking = try XCTUnwrap(wanted, "the certificate was never asked for")
        XCTAssertEqual(try XCTUnwrap(asking.verificationData).stage, .certificateWanted)
        try callee.stirCertificate(call: asking.call, chain: try provider("chain.pem"))
        let judged = await calleeEvents.first(within: 5) {
            $0.kind == .callerVerification && $0.verificationData?.stage == .verified
        }
        return try XCTUnwrap(try XCTUnwrap(judged, "no verdict").verificationData)
    }

    func testACertificateNamingOnlyACodeCoversNoNumberByDefault() async throws {
        let judged = try await verdict(acceptServiceProviderCodes: false)
        XCTAssertEqual(judged.outcome, .invalid)
        XCTAssertEqual(judged.failure, .numberNotCovered)
    }

    func testAStackThatAcceptsCodesVerifiesTheCaller() async throws {
        let judged = try await verdict(acceptServiceProviderCodes: true)
        XCTAssertEqual(judged.outcome, .valid)
    }

    func testAnSdesCallReportsHowItIsProtected() async throws {
        let caller = try SipralStack(audio: .application)
        let callee = try SipralStack(audio: .application)
        defer { caller.close(); callee.close() }
        XCTAssertThrowsError(
            try caller.addAccount(
                aor: "sip:alice@sipral.invalid", registrarAddress: callee.bindAddress,
                security: AccountSecurity(srtpSuites: ["AES_CM_128_HMAC_SHA1_80", "NOT_A_SUITE"])
            )
        ) { error in
            XCTAssertEqual((error as? SipralError)?.status, .invalidArgument)
        }
        let account = try caller.addAccount(
            aor: "sip:alice@sipral.invalid", registrarAddress: callee.bindAddress,
            security: AccountSecurity(srtp: .required, srtpSuites: ["AES_CM_128_HMAC_SHA1_80"])
        )
        _ = try callee.addAccount(
            aor: "sip:bob@sipral.invalid", registrarAddress: caller.bindAddress,
            security: AccountSecurity(srtp: .required)
        )
        let calleeEvents = Recorder(callee.events())
        let call = try caller.placeCall(account: account, target: "sip:bob@\(callee.bindAddress)")
        defer { call.close() }
        let rang = await calleeEvents.first(within: 5) { $0.kind == .incomingCall }
        let answered = try callee.answerCall(try XCTUnwrap(rang, "the call never rang"))
        defer { answered.close() }

        let deadline = DispatchTime.now() + 5
        while call.media == nil && DispatchTime.now() < deadline {
            usleep(20_000)
        }
        let media = try XCTUnwrap(call.media, "the placed call never got its audio")
        let report = try media.encryption()
        XCTAssertEqual(report.count, 1)
        XCTAssertEqual(report.first?.media, .audio)
        XCTAssertEqual(report.first?.keyExchange, .sdes)
        XCTAssertEqual(report.first?.encrypted, true)
        XCTAssertEqual(report.first?.suite, .aesCm80)
        XCTAssertEqual(report.first?.authenticated, false, "SDES authenticates nothing")
    }
}
