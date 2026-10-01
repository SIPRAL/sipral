// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

import XCTest

@testable import Sipral

/// A status this binding has no name for is one a newer library returned,
/// which the frozen ABI allows: it is thrown with its number and no name,
/// never as some other status it could be taken for.
final class StatusTests: XCTestCase {
    func testAStatusThisBindingKnowsIsThrownByName() {
        let behind = SipralStatus.clockBehind.rawValue
        XCTAssertThrowsError(try Sipral.check(behind)) {
            let error = $0 as? SipralError
            XCTAssertEqual(error?.status, .clockBehind)
            XCTAssertEqual(error?.code, behind)
        }
    }

    func testAStatusFromANewerLibraryKeepsItsNumberAndHasNoName() {
        XCTAssertThrowsError(try Sipral.check(999)) {
            let error = $0 as? SipralError
            XCTAssertEqual(error?.code, 999)
            XCTAssertNil(error?.status, "an unknown status was given a name")
            XCTAssertTrue(error?.description.hasPrefix("status 999") ?? false)
        }
    }

    /// A clock reading the poll thread overtook is read again, as a
    /// collision with it is; anything else goes straight through.
    func testAClockBehindIsRetriedLikeABusy() throws {
        for status in [SipralStatus.busy, .clockBehind] {
            var attempts = 0
            let answer = try retryingBusy { () -> Int in
                attempts += 1
                if attempts < 3 { throw SipralError(status: status, message: "") }
                return attempts
            }
            XCTAssertEqual(answer, 3, "\(status) was not retried")
        }
        var attempts = 0
        XCTAssertThrowsError(try retryingBusy { () -> Int in
            attempts += 1
            throw SipralError(status: .wrongState, message: "")
        })
        XCTAssertEqual(attempts, 1)
    }

    func testAnErrorMadeFromANameCarriesItsNumber() {
        let error = SipralError(status: .busy, message: "")
        XCTAssertEqual(error.code, SipralStatus.busy.rawValue)
        XCTAssertEqual(error.status, .busy)
    }
}
