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

    // MARK: - the user acts before the INVITE arrives

    /// What `CXAnswerCallAction` was told, from whichever thread.
    final class Outcome: @unchecked Sendable {
        private let lock = NSLock()
        private var results: [String] = []

        func record(_ error: Error?) {
            lock.withLock { results.append(error.map { "\($0)" } ?? "answered") }
        }

        var all: [String] { lock.withLock { results } }
    }

    /// Bob's phone, woken by a push naming Alice, and Alice's stack, ready
    /// to call it.
    private struct Woken {
        let alice: SipralStack
        let aliceAccount: Account
        let bob: SipralStack
        let provider: RecordingProvider
        let callKit: CallKitBridge
        let pushKit: PushKitBridge
        let pending: PendingCall
        let bobEvents: Recorder<SipralEvent>
    }

    private func woken(
        callerId: String = "sip:alice@sipral.invalid", callId: String? = nil, callerName: String? = nil
    ) async throws -> Woken {
        let alice = try SipralStack(audio: .application)
        let bob = try SipralStack(audio: .application)
        let aliceAccount = try alice.addAccount(
            aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress, displayName: callerName
        )
        let bobAccount = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress)
        let provider = RecordingProvider()
        let callKit = CallKitBridge(provider: provider)
        let pushKit = PushKitBridge(callKit: callKit)
        let bobEvents = Recorder(bob.events())
        let pending = try await pushKit.handle(push: VoipPush(callerId: callerId, callId: callId), account: bobAccount)
        return Woken(
            alice: alice, aliceAccount: aliceAccount, bob: bob, provider: provider, callKit: callKit,
            pushKit: pushKit, pending: pending, bobEvents: bobEvents
        )
    }

    /// Alice calls; Bob's side matches the INVITE to the push, as the
    /// application does, and binds the call to the screen shown for it.
    private func inviteArrives(_ phone: Woken) async throws -> (aliceCall: Call, bobCall: Call, aliceEvents: Recorder<SipralEvent>) {
        let aliceCall = try phone.alice.placeCall(account: phone.aliceAccount, target: "sip:bob@\(phone.bob.bindAddress)")
        let aliceEvents = Recorder(aliceCall.events())
        let announced = await phone.bobEvents.first(within: 5) { $0.kind == .callAnnounced }
        XCTAssertNotNil(announced, "the stack did not match the INVITE to the push")
        if let announced { phone.pushKit.matchIncomingCall(announced, on: phone.bob) }
        let arrived = await phone.bobEvents.first(within: 5) { $0.kind == .incomingCall }
        let incoming = try XCTUnwrap(arrived, "no INVITE reached the phone")
        let pending = try XCTUnwrap(phone.pushKit.matchIncomingCall(incoming, on: phone.bob))
        XCTAssertEqual(pending.uuid, phone.pending.uuid)
        let bobCall = try phone.bob.takeIncomingCall(incoming)
        pending.resolve(with: bobCall)
        return (aliceCall, bobCall, aliceEvents)
    }

    /// Answer tapped on the push's screen before the INVITE: kept, then the
    /// call answered the moment the INVITE is matched, and only then is the
    /// action told it succeeded.
    func testAnAnswerBeforeTheInviteAnswersTheCallWhenItArrives() async throws {
        let phone = try await woken()
        defer { phone.alice.close(); phone.bob.close() }
        let outcome = Outcome()
        phone.callKit.handleAnswer(uuid: phone.pending.uuid) { outcome.record($0) }
        try await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertEqual(outcome.all, [], "the answer was settled before there was a call to answer")

        let (aliceCall, bobCall, aliceEvents) = try await inviteArrives(phone)
        defer { aliceCall.close(); bobCall.close() }
        let confirmed = await aliceEvents.first(within: 5) { $0.kind == .callConfirmed }
        XCTAssertNotNil(confirmed, "the caller never saw the answer")
        XCTAssertEqual(outcome.all, ["answered"])
    }

    /// Answer tapped, and the INVITE never comes: the action fails and the
    /// screen is ended as unanswered.
    func testAnAnswerWhoseAnnouncementGoesMissingFails() async throws {
        let phone = try await woken()
        defer { phone.alice.close(); phone.bob.close() }
        let outcome = Outcome()
        phone.callKit.handleAnswer(uuid: phone.pending.uuid) { outcome.record($0) }
        let missing = SipralEvent(
            kindRaw: SipralEventKind.announcedCallMissing.rawValue, kind: .announcedCallMissing,
            kindName: "announced call missing", stack: phone.bob.handle, account: Sipral.handleNone,
            call: Sipral.handleNone, message: nil, callData: nil, mediaData: nil, registrationData: nil,
            announceData: AnnounceEventData(announcement: try XCTUnwrap(phone.pending.announcement), waitedMs: 20_000),
            natData: nil, relayData: nil, referralData: nil, turnStreamData: nil, audioData: nil,
            stunServerData: nil, verificationData: nil
        )
        phone.pushKit.matchIncomingCall(missing, on: phone.bob)
        XCTAssertEqual(outcome.all.count, 1)
        XCTAssertNotEqual(outcome.all.first, "answered")
        let ended = await eventually(within: 5) { await phone.provider.ended.contains { $0.uuid == phone.pending.uuid } }
        XCTAssertTrue(ended, "the screen was left up")
        let reason = await phone.provider.ended.first { $0.uuid == phone.pending.uuid }?.reason
        XCTAssertEqual(reason, .unanswered)
    }

    /// A push that carries a `Call-ID` no INVITE has: the caller still
    /// matches the INVITE to it, through `sipral_account_announce_call`.
    func testAPushsCallIdThatNoInviteCarriesFallsBackToTheCaller() async throws {
        let phone = try await woken(callId: "no-such-call@sipral.invalid")
        defer { phone.alice.close(); phone.bob.close() }
        let outcome = Outcome()
        phone.callKit.handleAnswer(uuid: phone.pending.uuid) { outcome.record($0) }

        let (aliceCall, bobCall, aliceEvents) = try await inviteArrives(phone)
        defer { aliceCall.close(); bobCall.close() }
        let confirmed = await aliceEvents.first(within: 5) { $0.kind == .callConfirmed }
        XCTAssertNotNil(confirmed, "the caller never saw the answer")
        XCTAssertEqual(outcome.all, ["answered"])
    }

    /// Declined on the push's screen before the INVITE: the INVITE, when it
    /// comes, is answered 603 and the caller's call ends.
    func testAnEndBeforeTheInviteDeclinesIt() async throws {
        let phone = try await woken()
        defer { phone.alice.close(); phone.bob.close() }
        try phone.callKit.handleEnd(uuid: phone.pending.uuid)

        let (aliceCall, bobCall, aliceEvents) = try await inviteArrives(phone)
        defer { aliceCall.close(); bobCall.close() }
        let endedEvent = await aliceEvents.first(within: 5) { $0.kind == .callEnded }
        let ended = try XCTUnwrap(endedEvent, "the caller's call stayed up")
        XCTAssertEqual(ended.callData?.statusCode, 603)
        let confirmed = aliceEvents.elements.contains { $0.kind == .callConfirmed }
        XCTAssertFalse(confirmed, "a declined call was answered")
    }

    // MARK: - the caller's name

    /// A push that carried no name: the screen is given the one the
    /// INVITE's `From` carries, once the INVITE is matched to it.
    func testAScreenThePushGaveNoNameIsGivenTheInvitesName() async throws {
        let phone = try await woken(callerName: "Alice Liddell")
        defer { phone.alice.close(); phone.bob.close() }
        let shown = await phone.provider.reported
        XCTAssertEqual(shown.map(\.displayName), [nil])

        let (aliceCall, bobCall, _) = try await inviteArrives(phone)
        defer { aliceCall.close(); bobCall.close() }
        let named = await eventually(within: 5) { await !phone.provider.named.isEmpty }
        XCTAssertTrue(named, "the INVITE's name never reached the screen")
        let given = await phone.provider.named
        XCTAssertEqual(given.map(\.uuid), [phone.pending.uuid])
        XCTAssertEqual(given.map(\.displayName), ["Alice Liddell"])
    }

    /// A push that named nobody: the stack matches Alice's INVITE on the
    /// account alone, the screen raised as `Unknown` is answered by it, and
    /// is then given Alice's URI and name.
    func testAPushThatNamesNobodyIsAnsweredByTheCallOnItsAccount() async throws {
        let phone = try await woken(callerId: "", callerName: "Alice Liddell")
        defer { phone.alice.close(); phone.bob.close() }
        let shown = await phone.provider.reported
        XCTAssertEqual(shown.map(\.callerId), ["Unknown"])
        XCTAssertNotNil(phone.pending.announcement)
        let outcome = Outcome()
        phone.callKit.handleAnswer(uuid: phone.pending.uuid) { outcome.record($0) }

        let (aliceCall, bobCall, aliceEvents) = try await inviteArrives(phone)
        defer { aliceCall.close(); bobCall.close() }
        let confirmed = await aliceEvents.first(within: 5) { $0.kind == .callConfirmed }
        XCTAssertNotNil(confirmed, "the caller never saw the answer")
        XCTAssertEqual(outcome.all, ["answered"])
        let identified = await eventually(within: 5) { await !phone.provider.identified.isEmpty }
        XCTAssertTrue(identified, "the screen was left showing nobody")
        let given = await phone.provider.identified
        XCTAssertEqual(given.map(\.uuid), [phone.pending.uuid])
        XCTAssertEqual(given.first?.callerId.hasPrefix("sip:alice@"), true, "\(given)")
        XCTAssertEqual(given.first?.displayName, "Alice Liddell")
    }

    // MARK: - the application ends a screen

    /// For a push the application will not ring: the screen ends as
    /// unanswered, a kept Answer fails, and the INVITE, when it comes, is
    /// declined.
    func testTheApplicationEndsAScreenAsUnansweredAndItsInviteIsDeclined() async throws {
        let phone = try await woken()
        defer { phone.alice.close(); phone.bob.close() }
        XCTAssertThrowsError(try phone.callKit.endShown(uuid: UUID())) { error in
            guard case CallKitBridgeError.unknownCall = error else { return XCTFail("\(error)") }
        }
        let outcome = Outcome()
        phone.callKit.handleAnswer(uuid: phone.pending.uuid) { outcome.record($0) }
        try phone.callKit.endShown(uuid: phone.pending.uuid)
        XCTAssertEqual(outcome.all.count, 1)
        XCTAssertNotEqual(outcome.all.first, "answered")
        let ended = await eventually(within: 5) { await phone.provider.ended.contains { $0.uuid == phone.pending.uuid } }
        XCTAssertTrue(ended, "the screen was left up")
        let reasons = await phone.provider.ended.filter { $0.uuid == phone.pending.uuid }.map(\.reason)
        XCTAssertEqual(reasons, [.unanswered])

        let (aliceCall, bobCall, aliceEvents) = try await inviteArrives(phone)
        defer { aliceCall.close(); bobCall.close() }
        let endedEvent = await aliceEvents.first(within: 5) { $0.kind == .callEnded }
        XCTAssertEqual(try XCTUnwrap(endedEvent, "the caller's call stayed up").callData?.statusCode, 603)
        let reportedAgain = await phone.provider.ended.filter { $0.uuid == phone.pending.uuid }.count
        XCTAssertEqual(reportedAgain, 1, "the end was reported twice")
    }
}
#endif
