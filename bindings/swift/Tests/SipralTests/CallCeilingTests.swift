// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import Foundation
import XCTest
@testable import Sipral

/// `maxDialogs` reaches the stack: at a ceiling of one call, the second call
/// placed is refused with `.limitReached`.
final class CallCeilingTests: XCTestCase {
    func testACallPlacedPastMaxDialogsIsRefused() throws {
        let server = try UDPSocket(host: "127.0.0.1", port: 0)
        defer { server.close() }

        let stack = try SipralStack(audio: .application, maxDialogs: 1)
        defer { stack.close() }
        let account = try stack.addAccount(aor: "sip:alice@sipral.invalid", registrarAddress: server.localAddress)
        let first = try stack.placeCall(account: account, target: "sip:bob@\(server.localAddress)")
        defer { first.close() }

        XCTAssertThrowsError(
            try stack.placeCall(account: account, target: "sip:bob@\(server.localAddress)")
        ) { error in
            XCTAssertEqual((error as? SipralError)?.status, .limitReached, "\(error)")
        }
    }
}
