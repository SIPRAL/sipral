// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import CSipral
import XCTest
@testable import Sipral

/// Every event the C ABI raises reaches Swift with its payload read: an event
/// whose arm this layer never reads would reach the application as a kind
/// and nothing else.
final class EventDecodingTests: XCTestCase {
    private func raw(_ kind: SipralEventKind) -> sipral_event_t {
        var event = sipral_event_t()
        event.size = MemoryLayout<sipral_event_t>.size
        event.kind = kind.rawValue
        return event
    }

    /// Whether any of the typed views (`callData`, `subscriptionData`, ...)
    /// was filled in.
    private func typed(_ event: SipralEvent) -> Bool {
        Mirror(reflecting: event).children.contains { child in
            guard let label = child.label, label.hasSuffix("Data") else { return false }
            let optional = Mirror(reflecting: child.value)
            return optional.displayStyle == .optional && !optional.children.isEmpty
        }
    }

    func testEveryKindWithAPayloadIsDecoded() {
        var unread: [String] = []
        for value in UInt32(1)...UInt32(255) {
            guard let kind = SipralEventKind(rawValue: value), kind != .started else { continue }
            if !typed(SipralEventDecoder.decode(raw(kind))) {
                unread.append("\(kind)")
            }
        }
        XCTAssertEqual(unread, [], "kinds whose payload this layer never reads")
    }

    func testASubscriptionNoticeCarriesItsState() throws {
        var event = raw(.notified)
        event.payload.subscription.subscription = 7
        event.payload.subscription.state = SipralSubscriptionState.active.rawValue
        event.payload.subscription.status_code = 202
        event.payload.subscription.expires_ms = 600_000
        event.payload.subscription.has_dialog_info = 1
        let told = try XCTUnwrap(SipralEventDecoder.decode(event).subscriptionData)
        XCTAssertEqual(told.subscription, 7)
        XCTAssertEqual(told.state, .active)
        XCTAssertEqual(told.statusCode, 202)
        XCTAssertEqual(told.expiresMs, 600_000)
        XCTAssertTrue(told.hasDialogInfo)
    }

    func testAMessageCarriesItsBodyAndASummaryItsCounts() throws {
        let body: [UInt8] = Array("hello".utf8)
        let type = "text/plain"
        let told = try body.withUnsafeBufferPointer { bodyBytes in
            try type.withCString { typeText in
                var event = raw(.messageReceived)
                event.payload.message.message = 3
                event.payload.message.body = bodyBytes.baseAddress
                event.payload.message.body_len = bodyBytes.count
                event.payload.message.content_type = typeText
                event.payload.message.content_type_len = type.utf8.count
                return try XCTUnwrap(SipralEventDecoder.decode(event).messageData)
            }
        }
        XCTAssertEqual(told.message, 3)
        XCTAssertEqual(told.body, body)
        XCTAssertEqual(told.contentType, type)

        var waiting = raw(.messagesWaiting)
        waiting.payload.message.waiting = 1
        waiting.payload.message.new_messages = 2
        waiting.payload.message.urgent_old_messages = 1
        let summary = try XCTUnwrap(SipralEventDecoder.decode(waiting).messageData)
        XCTAssertTrue(summary.waiting)
        XCTAssertEqual(summary.newMessages, 2)
        XCTAssertEqual(summary.urgentOldMessages, 1)
    }

    func testARecoveryAndANameToResolveCarryTheirPayloads() throws {
        var event = raw(.recovery)
        event.payload.recovery.state = SipralRecoveryOutcome.gaveUp.rawValue
        event.payload.recovery.unverified = 2
        let recovery = try XCTUnwrap(SipralEventDecoder.decode(event).recoveryData)
        XCTAssertEqual(recovery.state, .gaveUp)
        XCTAssertEqual(recovery.unverified, 2)

        let host = "pbx.sipral.invalid"
        let resolve = try host.withCString { text in
            var needed = raw(.resolveNeeded)
            needed.payload.resolve.dialog = 9
            needed.payload.resolve.host = text
            needed.payload.resolve.host_len = host.utf8.count
            needed.payload.resolve.port = 5061
            return try XCTUnwrap(SipralEventDecoder.decode(needed).resolveData)
        }
        XCTAssertEqual(resolve.dialog, 9)
        XCTAssertEqual(resolve.host, host)
        XCTAssertEqual(resolve.port, 5061)
    }

    /// A challenge an account's password was not given to says why, who
    /// asked, and every realm it was asked for, one per line in C.
    func testADeclinedChallengeCarriesWhoAskedAndForWhat() throws {
        let server = "203.0.113.9:5060"
        let realms = "sbc.example\ncallee, inc."
        let told = try server.withCString { serverText in
            try realms.withCString { realmsText in
                var event = raw(.challengeDeclined)
                event.payload.challenge.refusal = SipralChallengeRefusal.notTheAccountsRealm.rawValue
                event.payload.challenge.server = serverText
                event.payload.challenge.server_len = server.utf8.count
                event.payload.challenge.realms = realmsText
                event.payload.challenge.realms_len = realms.utf8.count
                return try XCTUnwrap(SipralEventDecoder.decode(event).challengeData)
            }
        }
        XCTAssertEqual(told.refusal, .notTheAccountsRealm)
        XCTAssertEqual(told.server, server)
        XCTAssertEqual(told.realms, ["sbc.example", "callee, inc."])
    }
}
