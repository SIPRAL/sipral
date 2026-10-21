// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

#if canImport(CryptoKit)
import Foundation
import XCTest
@testable import Sipral

/// RFC 8599's parameters on an account's REGISTER, the registrar's answer
/// to them, and the push bridge taking down a screen nothing will fill.
final class PushTests: XCTestCase {
    private static let token: [UInt8] = [0x00, 0xfc, 0x13, 0xad, 0xff, 0x78, 0x51, 0x2e]
    private static let push = SipralPush.apnsVoip(token: token, teamId: "TEAM123456", bundleId: "org.sipral.phone")

    private func registered(_ account: Account) async throws {
        for _ in 0..<100 {
            if try account.registrationState == .registered { return }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTFail("the account never registered")
    }

    private func until(_ seconds: Double = 5, _ what: () -> Bool) async throws -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while !what(), Date() < deadline {
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        return what()
    }

    func testAnApnsTokenIsWrittenInHexAndTheTopicEndsInVoip() {
        XCTAssertEqual(Self.push.provider, "apns")
        XCTAssertEqual(Self.push.prid, "00fc13adff78512e")
        XCTAssertEqual(Self.push.param, "TEAM123456.org.sipral.phone.voip")
        XCTAssertFalse(Self.push.wakesItself)
    }

    /// Inside the `Contact` URI's angle brackets on a REGISTER, and the
    /// identifier left out of the one that removes the binding (§4.1.2).
    func testThePushParametersGoOnTheRegisterAndThePridLeavesWithTheBinding() async throws {
        let registrar = try DatagramRegistrar()
        defer { registrar.stop() }
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let account = try stack.addAccount(
            aor: "sip:alice@example.com", registrarAddress: registrar.address, registrar: "sip:example.com",
            push: Self.push
        )
        try account.register()
        try await registered(account)
        let contact = try XCTUnwrap(FakeRegistrarHeader.header("Contact", registrar.registers.first ?? ""))
        let uri = try XCTUnwrap(contact.split(separator: ">").first)
        XCTAssertTrue(uri.contains(";pn-provider=apns"), contact)
        XCTAssertTrue(uri.contains(";pn-prid=00fc13adff78512e"), contact)
        XCTAssertTrue(uri.contains(";pn-param=TEAM123456.org.sipral.phone.voip"), contact)

        try account.unregister()
        let removed = try await until { registrar.registers.count >= 2 }
        XCTAssertTrue(removed, "no REGISTER removed the binding")
        let last = FakeRegistrarHeader.header("Contact", registrar.registers.last ?? "") ?? ""
        XCTAssertFalse(last.contains("pn-prid"), last)
        XCTAssertTrue(last.contains("pn-provider=apns"), last)
    }

    func testTheRegistrarsPromiseAndLeadAreRead() async throws {
        let registrar = try DatagramRegistrar(featureCaps: "*;+sip.pns=\"apns\";+sip.pnsreg=\"121\"")
        defer { registrar.stop() }
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let account = try stack.addAccount(
            aor: "sip:alice@example.com", registrarAddress: registrar.address, registrar: "sip:example.com",
            push: Self.push
        )
        try account.register()
        try await registered(account)
        let echo = try account.pushEcho()
        XCTAssertTrue(echo.accepted)
        XCTAssertEqual(echo.refreshLeadMs, 121_000)
    }

    /// No `Feature-Caps` is nobody promising anything, and an account that
    /// asked for no push has nothing to read.
    func testSilenceIsNoPromiseAndNoPushIsNotSupported() async throws {
        let registrar = try DatagramRegistrar()
        defer { registrar.stop() }
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let pushed = try stack.addAccount(
            aor: "sip:alice@example.com", registrarAddress: registrar.address, registrar: "sip:example.com",
            push: Self.push
        )
        let plain = try stack.addAccount(
            aor: "sip:bob@example.com", registrarAddress: registrar.address, registrar: "sip:example.com"
        )
        try pushed.register()
        try plain.register()
        try await registered(pushed)
        try await registered(plain)
        let echo = try pushed.pushEcho()
        XCTAssertFalse(echo.accepted)
        XCTAssertNil(echo.refreshLeadMs)
        XCTAssertThrowsError(try plain.pushEcho()) {
            XCTAssertEqual(($0 as? SipralError)?.status, .notSupported)
        }
    }

    // MARK: - screens nothing will fill

    private func announcementEvent(
        _ kind: SipralEventKind, stack: SipralStack, account: Account, call: SipralHandle, announcement: SipralHandle
    ) -> SipralEvent {
        SipralEvent(
            kindRaw: kind.rawValue, kind: kind, kindName: "\(kind)", stack: stack.handle, account: account.handle,
            call: call, message: nil, callData: nil, mediaData: nil, registrationData: nil,
            announceData: AnnounceEventData(announcement: announcement, waitedMs: 20_000), natData: nil,
            relayData: nil, referralData: nil, turnStreamData: nil, audioData: nil, stunServerData: nil,
            verificationData: nil
        )
    }

    func testAnAnnouncedCallThatNeverArrivesEndsItsScreenUnanswered() async throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let account = try stack.addAccount(aor: "sip:agent@sipral.invalid", registrarAddress: "127.0.0.1:5060")
        let provider = RecordingProvider()
        let pushKit = PushKitBridge(callKit: CallKitBridge(provider: provider))
        let pending = try await pushKit.handle(push: VoipPush(callerId: "sip:alice@sipral.invalid"), account: account)
        let announcement = try XCTUnwrap(pending.announcement)

        let missing = announcementEvent(
            .announcedCallMissing, stack: stack, account: account, call: Sipral.handleNone, announcement: announcement
        )
        XCTAssertNil(pushKit.matchIncomingCall(missing, on: stack))
        let ended = await eventually(within: 5) { await provider.ended.contains { $0.uuid == pending.uuid } }
        XCTAssertTrue(ended, "the screen was left ringing")
        let reason = await provider.ended.first { $0.uuid == pending.uuid }?.reason
        XCTAssertEqual(reason, .unanswered)
    }

    /// Two pushes from the same caller: the INVITE the stack matched to the
    /// second takes the second screen, not the older one.
    func testTheStacksMatchDecidesWhichScreenAnInviteTakes() async throws {
        let stack = try SipralStack(audio: .application)
        defer { stack.close() }
        let account = try stack.addAccount(aor: "sip:agent@sipral.invalid", registrarAddress: "127.0.0.1:5060")
        let pushKit = PushKitBridge(callKit: CallKitBridge(provider: RecordingProvider()))
        let first = try await pushKit.handle(push: VoipPush(callerId: "sip:alice@sipral.invalid"), account: account)
        let second = try await pushKit.handle(push: VoipPush(callerId: "sip:alice@sipral.invalid"), account: account)
        let announcement = try XCTUnwrap(second.announcement)

        let call: SipralHandle = 777
        let announced = announcementEvent(
            .callAnnounced, stack: stack, account: account, call: call, announcement: announcement
        )
        XCTAssertNil(pushKit.matchIncomingCall(announced, on: stack))
        let incoming = SipralEvent(
            kindRaw: SipralEventKind.incomingCall.rawValue, kind: .incomingCall, kindName: "incoming call",
            stack: stack.handle, account: account.handle, call: call, message: nil, callData: nil, mediaData: nil,
            registrationData: nil, announceData: nil, natData: nil, relayData: nil, referralData: nil,
            turnStreamData: nil, audioData: nil, stunServerData: nil, verificationData: nil
        )
        let taken = pushKit.matchIncomingCall(incoming, on: stack)
        XCTAssertEqual(taken?.uuid, second.uuid)
        XCTAssertEqual(taken?.matchedCallHandle, call)
        XCTAssertNil(first.matchedCallHandle)
    }

    func testAPushNoAccountCanTakeIsShownAndEndedAtOnce() async throws {
        let provider = RecordingProvider()
        let pushKit = PushKitBridge(callKit: CallKitBridge(provider: provider))
        await pushKit.reportUnusable(callerId: nil)
        let reported = await provider.reported
        XCTAssertEqual(reported.map(\.callerId), ["Unknown"])
        let ended = await eventually(within: 5) { await provider.ended.count == 1 }
        XCTAssertTrue(ended, "a push nothing could use was left ringing")
        let reason = await provider.ended.first?.reason
        XCTAssertEqual(reason, .failed)
    }
}
#endif
