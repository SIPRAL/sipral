// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import Dispatch
import Foundation
import XCTest
@testable import Sipral

/// Real-time text, RTCP feedback, linear audio and a conference's focus
/// between two stacks on 127.0.0.1, and a conference's picture and presence
/// against a notifier and a compositor played on a socket of the test's own.
final class ProtocolsTests: XCTestCase {
    private func stacks() throws -> (SipralStack, SipralStack) {
        (
            try SipralStack(audio: .application, codecs: "PCMU"),
            try SipralStack(audio: .application, codecs: "PCMU")
        )
    }

    /// Alice calls Bob as `place` says, Bob takes the call with `text` and
    /// answers as `answer` says, and both ends' media start.
    private func call(
        _ alice: SipralStack, _ bob: SipralStack, text: Bool = false,
        place: (SipralStack, Account, String) throws -> Call,
        answer: (Call) throws -> Void = { try $0.answer() }
    ) async throws -> (Call, Call) {
        let aliceAccount = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: bob.bindAddress)
        _ = try bob.addAccount(aor: "sip:bob@sipral.invalid", registrarAddress: alice.bindAddress)
        let bobEvents = Recorder(bob.events())
        let aliceCall = try place(alice, aliceAccount, "sip:bob@\(bob.bindAddress)")
        let arrived = await bobEvents.first(within: 10) { $0.kind == .incomingCall }
        let bobCall = try bob.takeIncomingCall(try XCTUnwrap(arrived, "no incoming call arrived"), text: text)
        try answer(bobCall)
        let bothUp = await eventually(within: 10) { aliceCall.media != nil && bobCall.media != nil }
        XCTAssertTrue(bothUp, "media never started")
        return (aliceCall, bobCall)
    }

    /// Everything `reader` has been handed, run together.
    private func typed(_ reader: Recorder<TextEventData>) -> String {
        reader.elements.map(\.text).joined()
    }

    func testRealTimeTextIsTypedAndReadBothWays() async throws {
        let (alice, bob) = try stacks()
        defer { alice.close(); bob.close() }
        let (aliceCall, bobCall) = try await call(alice, bob, text: true) { stack, account, target in
            try stack.placeCall(account: account, target: target, text: true)
        }
        defer { aliceCall.close(); bobCall.close() }
        XCTAssertNotNil(aliceCall.textAddress)
        let aliceMedia = try XCTUnwrap(aliceCall.media)
        let bobMedia = try XCTUnwrap(bobCall.media)
        XCTAssertTrue(try aliceMedia.hasText)
        XCTAssertTrue(try bobMedia.hasText)

        let atBob = Recorder(bobCall.text())
        let atAlice = Recorder(aliceCall.text())
        try aliceMedia.sendText("hello")
        let bobRead = await eventually(within: 5) { self.typed(atBob) == "hello" }
        XCTAssertTrue(bobRead, "Bob read \(typed(atBob))")
        XCTAssertEqual(atBob.elements.map(\.missing).reduce(0, +), 0)
        try bobMedia.sendText("hi")
        let aliceRead = await eventually(within: 5) { self.typed(atAlice) == "hi" }
        XCTAssertTrue(aliceRead, "Alice read \(typed(atAlice))")
    }

    func testAFarEndThatTookNoTextLeavesNoneToSend() async throws {
        let (alice, bob) = try stacks()
        defer { alice.close(); bob.close() }
        let (aliceCall, bobCall) = try await call(alice, bob) { stack, account, target in
            try stack.placeCall(account: account, target: target, text: true)
        }
        defer { aliceCall.close(); bobCall.close() }
        let media = try XCTUnwrap(aliceCall.media)
        XCTAssertFalse(try media.hasText)
        XCTAssertThrowsError(try media.sendText("nobody reads this")) { error in
            XCTAssertEqual((error as? SipralError)?.status, .notNegotiated)
        }
    }

    func testRtcpFeedbackIsAgreedOnlyWhenACallAsks() async throws {
        let (alice, bob) = try stacks()
        defer { alice.close(); bob.close() }
        let (asked, answered) = try await call(
            alice, bob,
            place: { stack, account, target in try stack.placeCall(account: account, target: target, feedback: true) },
            answer: { try $0.answer(feedback: true) }
        )
        defer { asked.close(); answered.close() }
        let agreed = RtcpFeedback(feedback: true, genericNack: true, reducedSize: true)
        XCTAssertEqual(try XCTUnwrap(asked.media).rtcpFeedback(), agreed)
        XCTAssertEqual(try XCTUnwrap(answered.media).rtcpFeedback(), agreed)
        XCTAssertEqual(try XCTUnwrap(asked.media).statistics().feedback, 1)

        // an answer that does nothing with it still takes the profile
        let (onlyAlice, onlyBob) = try stacks()
        defer { onlyAlice.close(); onlyBob.close() }
        let (profile, profileAnswered) = try await call(onlyAlice, onlyBob) { stack, account, target in
            try stack.placeCall(account: account, target: target, feedback: true)
        }
        defer { profile.close(); profileAnswered.close() }
        XCTAssertEqual(
            try XCTUnwrap(profile.media).rtcpFeedback(),
            RtcpFeedback(feedback: true, genericNack: false, reducedSize: false)
        )

        let (plainAlice, plainBob) = try stacks()
        defer { plainAlice.close(); plainBob.close() }
        let (plain, plainAnswered) = try await call(plainAlice, plainBob) { stack, account, target in
            try stack.placeCall(account: account, target: target)
        }
        defer { plain.close(); plainAnswered.close() }
        XCTAssertEqual(
            try XCTUnwrap(plain.media).rtcpFeedback(),
            RtcpFeedback(feedback: false, genericNack: false, reducedSize: false)
        )
    }

    func testLinearAudioIsOfferedWhenACallNamesIt() async throws {
        let (alice, bob) = try stacks()
        defer { alice.close(); bob.close() }
        let (aliceCall, bobCall) = try await call(
            alice, bob,
            place: { stack, account, target in
                try stack.placeCall(account: account, target: target, codecs: "L16/16000,PCMU")
            },
            answer: { try $0.answer(codecs: "L16/16000,PCMU") }
        )
        defer { aliceCall.close(); bobCall.close() }
        let media = try XCTUnwrap(aliceCall.media)
        XCTAssertEqual(try media.info().codec, SipralCodec.l16Wideband.rawValue)
        XCTAssertEqual(media.sampleRate, 16_000)
        XCTAssertEqual(try XCTUnwrap(bobCall.media).info().codec, SipralCodec.l16Wideband.rawValue)
    }

    func testAFocusSaysSoAndTheCallerNamesItsConference() async throws {
        let (alice, bob) = try stacks()
        defer { alice.close(); bob.close() }
        let (aliceCall, bobCall) = try await call(
            alice, bob,
            place: { stack, account, target in try stack.placeCall(account: account, target: target) },
            answer: { try $0.answer(focus: true) }
        )
        defer { aliceCall.close(); bobCall.close() }
        let uri = try XCTUnwrap(try aliceCall.conferenceUri(), "the focus was not heard")
        XCTAssertTrue(uri.contains(UDPSocket.parse(bob.bindAddress).host), uri)
        XCTAssertNil(try bobCall.conferenceUri(), "Alice never said she is a focus")
        XCTAssertThrowsError(try bobCall.subscribeConference()) { error in
            XCTAssertEqual((error as? SipralError)?.status, .notAFocus)
        }
        let watched = try aliceCall.subscribeConference()
        XCTAssertEqual(watched.package, "conference")
        XCTAssertNotEqual(watched.handle, Sipral.handleNone)
    }

    func testAConferenceIsReadBackWholeFromItsNotifications() async throws {
        let notifier = try UDPSocket(host: "127.0.0.1", port: 0)
        defer { notifier.close() }
        let alice = try SipralStack(audio: .application)
        defer { alice.close() }
        let account = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: notifier.localAddress)
        let events = Recorder(alice.events())
        let watched = try account.subscribe(to: "sip:room@sipral.invalid", package: "conference")
        let subscribed = await FakePeer.request(on: notifier, "SUBSCRIBE", within: 5)
        let subscribe = try XCTUnwrap(subscribed)
        XCTAssertEqual(FakePeer.header("Event", in: subscribe.message), "conference")
        notifier.send(FakePeer.answer(subscribe.message, "200 OK", more: "Expires: 3600\r\n"), to: subscribe.from)
        XCTAssertNil(try watched.conference(), "no document has arrived yet")
        notifier.send(
            FakePeer.notify(subscribe.message, to: alice.bindAddress, from: notifier.localAddress,
                            package: "conference", type: "application/conference-info+xml", body: Self.room),
            to: alice.bindAddress
        )
        let changed = await events.first(within: 5) { $0.kind == .conferenceChanged }
        let data = try XCTUnwrap(try XCTUnwrap(changed, "no conferenceChanged").conferenceData)
        XCTAssertEqual(data.subscription, watched.handle)
        XCTAssertEqual(data.update, .applied)
        XCTAssertEqual(data.version, 1)
        XCTAssertEqual(data.users, 2)

        let room = try XCTUnwrap(try watched.conference())
        XCTAssertEqual(room.entity, "sip:room@sipral.invalid")
        XCTAssertEqual(room.subject, "Weekly")
        XCTAssertEqual(room.displayText, "Team room")
        XCTAssertEqual(room.userCount, 3)
        XCTAssertEqual(room.active, true)
        XCTAssertEqual(room.locked, false)
        XCTAssertEqual(room.users, [
            ConferenceUser(
                entity: "sip:bob@sipral.invalid", displayText: "Bob", endpoint: "sip:bob@192.0.2.5",
                endpoints: 1, status: .connected, media: 1
            ),
            ConferenceUser(
                entity: "sip:carol@sipral.invalid", displayText: "", endpoint: "sip:carol@192.0.2.6",
                endpoints: 1, status: .alerting, media: 0
            ),
        ])
        XCTAssertEqual(try watched.state, .active)
    }

    func testPresenceIsPublishedAndWhatTheCompositorGrantedIsTold() async throws {
        let compositor = try UDPSocket(host: "127.0.0.1", port: 0)
        defer { compositor.close() }
        let alice = try SipralStack(audio: .application)
        defer { alice.close() }
        let account = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: compositor.localAddress)
        let events = Recorder(alice.events())
        XCTAssertThrowsError(try account.unpublishPresence()) { error in
            XCTAssertEqual((error as? SipralError)?.status, .wrongState)
        }
        XCTAssertThrowsError(try account.publishPresence(Presence(basic: .open, activity: .other))) { error in
            XCTAssertEqual((error as? SipralError)?.status, .invalidArgument)
        }

        try account.publishPresence(Presence(basic: .open, activity: .onThePhone, note: "In a call"))
        let published = await FakePeer.request(on: compositor, "PUBLISH", within: 5)
        let publish = try XCTUnwrap(published)
        XCTAssertEqual(FakePeer.header("Event", in: publish.message), "presence")
        XCTAssertTrue(publish.message.contains("<basic>open</basic>"), publish.message)
        XCTAssertTrue(publish.message.contains("on-the-phone"), publish.message)
        XCTAssertTrue(publish.message.contains("In a call"), publish.message)
        compositor.send(
            FakePeer.answer(publish.message, "200 OK", more: "SIP-ETag: tag-one\r\nExpires: 1800\r\n"), to: publish.from
        )
        let granted = await events.first(within: 5) { $0.presenceData?.publicationState == .published }
        let told = try XCTUnwrap(try XCTUnwrap(granted, "the grant was not told").presenceData)
        XCTAssertEqual(told.kind, .publication)
        XCTAssertEqual(told.expiresMs, 1_800_000)
        XCTAssertEqual(try XCTUnwrap(granted).account, account.handle)

        try account.unpublishPresence()
        let removing = await FakePeer.request(on: compositor, "PUBLISH", within: 5)
        let removal = try XCTUnwrap(removing)
        XCTAssertEqual(FakePeer.header("Expires", in: removal.message), "0")
        XCTAssertEqual(FakePeer.header("SIP-If-Match", in: removal.message), "tag-one")
        compositor.send(
            FakePeer.answer(removal.message, "200 OK", more: "SIP-ETag: tag-one\r\nExpires: 0\r\n"), to: removal.from
        )
        let removed = await events.first(within: 5) { $0.presenceData?.publicationState == .removed }
        XCTAssertNotNil(removed, "the removal was not told")
    }

    func testAWatchedPresentityIsToldWithItsActivityAndNote() async throws {
        let notifier = try UDPSocket(host: "127.0.0.1", port: 0)
        defer { notifier.close() }
        let alice = try SipralStack(audio: .application)
        defer { alice.close() }
        let account = try alice.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: notifier.localAddress)
        let events = Recorder(alice.events())
        let watched = try account.watchPresence(of: "sip:bob@sipral.invalid")
        XCTAssertEqual(watched.package, "presence")
        let subscribed = await FakePeer.request(on: notifier, "SUBSCRIBE", within: 5)
        let subscribe = try XCTUnwrap(subscribed)
        XCTAssertEqual(FakePeer.header("Accept", in: subscribe.message), "application/pidf+xml")
        notifier.send(FakePeer.answer(subscribe.message, "200 OK", more: "Expires: 3600\r\n"), to: subscribe.from)
        notifier.send(
            FakePeer.notify(subscribe.message, to: alice.bindAddress, from: notifier.localAddress,
                            package: "presence", type: "application/pidf+xml", body: Self.buddy),
            to: alice.bindAddress
        )
        let found = await events.first(within: 5) { $0.presenceData?.kind == .watched }
        let told = try XCTUnwrap(try XCTUnwrap(found, "no presence was told").presenceData)
        XCTAssertEqual(told.subscription, watched.handle)
        XCTAssertEqual(told.basic, .open)
        XCTAssertEqual(told.activity, .meeting)
        XCTAssertEqual(told.entity, "sip:bob@sipral.invalid")
        XCTAssertEqual(told.note, "Back at four")
        try watched.end()
        let unsubscribing = await FakePeer.request(on: notifier, "SUBSCRIBE", within: 5)
        let unsubscribe = try XCTUnwrap(unsubscribing)
        XCTAssertEqual(FakePeer.header("Expires", in: unsubscribe.message), "0")
    }

    static let room = """
    <?xml version="1.0"?>
    <conference-info xmlns="urn:ietf:params:xml:ns:conference-info" entity="sip:room@sipral.invalid" state="full" version="1">
      <conference-description><subject>Weekly</subject><display-text>Team room</display-text></conference-description>
      <conference-state><user-count>3</user-count><active>true</active><locked>false</locked></conference-state>
      <users>
        <user entity="sip:bob@sipral.invalid" state="full"><display-text>Bob</display-text>
          <endpoint entity="sip:bob@192.0.2.5"><status>connected</status><media id="1"><type>audio</type></media></endpoint>
        </user>
        <user entity="sip:carol@sipral.invalid" state="full">
          <endpoint entity="sip:carol@192.0.2.6"><status>alerting</status></endpoint>
        </user>
      </users>
    </conference-info>
    """

    static let buddy = """
    <?xml version="1.0" encoding="UTF-8"?>
    <presence xmlns="urn:ietf:params:xml:ns:pidf" xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model" \
    xmlns:rpid="urn:ietf:params:xml:ns:pidf:rpid" entity="sip:bob@sipral.invalid">
      <tuple id="t1"><status><basic>open</basic></status><note>Back at four</note></tuple>
      <dm:person id="p1"><rpid:activities><rpid:meeting/></rpid:activities></dm:person>
    </presence>
    """
}

/// A SIP peer played by hand on a socket of a test's own: the notifier, the
/// compositor, the recording server.
enum FakePeer {
    /// The next request of `method` that arrives on `socket` within
    /// `seconds`, and where it came from; anything else is let go.
    static func request(on socket: UDPSocket, _ method: String, within seconds: Double) async -> (message: String, from: String)? {
        let deadline = DispatchTime.now() + seconds
        while DispatchTime.now() < deadline {
            while let (data, from) = socket.receive() {
                let text = String(decoding: data, as: UTF8.self)
                if text.hasPrefix("\(method) ") {
                    return (text, from)
                }
            }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        return nil
    }

    static func header(_ name: String, in message: String) -> String? {
        let head = message.components(separatedBy: "\r\n\r\n").first ?? message
        return head.components(separatedBy: "\r\n")
            .first { $0.lowercased().hasPrefix(name.lowercased() + ":") }
            .map { String($0.drop(while: { $0 != ":" }).dropFirst()).trimmingCharacters(in: .whitespaces) }
    }

    /// A response to `request`, its dialog fields copied and `To` tagged,
    /// with the fields `more` adds and `body` as `type`.
    static func answer(_ request: String, _ status: String, more: String = "", type: String? = nil, body: String = "") -> [UInt8] {
        var lines = ["SIP/2.0 \(status)"]
        for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
            guard var value = header(name, in: request) else { continue }
            if name == "To" && !value.contains(";tag=") {
                value += ";tag=peer"
            }
            lines.append("\(name): \(value)")
        }
        var text = lines.joined(separator: "\r\n") + "\r\n" + more
        if let type {
            text += "Content-Type: \(type)\r\n"
        }
        text += "Content-Length: \(body.utf8.count)\r\n\r\n" + body
        return Array(text.utf8)
    }

    /// A NOTIFY in the dialog `subscribe` opened, carrying `body`.
    static func notify(
        _ subscribe: String, to: String, from: String, package: String, type: String, body: String
    ) -> [UInt8] {
        let text = "NOTIFY sip:alice@\(to) SIP/2.0\r\n"
            + "Via: SIP/2.0/UDP \(from);branch=z9hG4bK-notify-\(UUID().uuidString.prefix(8))\r\n"
            + "Max-Forwards: 70\r\n"
            + "From: \(header("To", in: subscribe) ?? "");tag=peer\r\n"
            + "To: \(header("From", in: subscribe) ?? "")\r\n"
            + "Call-ID: \(header("Call-ID", in: subscribe) ?? "")\r\n"
            + "CSeq: 1 NOTIFY\r\n"
            + "Contact: <sip:peer@\(from)>\r\n"
            + "Event: \(package)\r\n"
            + "Subscription-State: active;expires=3600\r\n"
            + "Content-Type: \(type)\r\n"
            + "Content-Length: \(body.utf8.count)\r\n\r\n"
            + body
        return Array(text.utf8)
    }
}
