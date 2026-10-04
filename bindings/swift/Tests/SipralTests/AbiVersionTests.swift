// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import XCTest

@testable import Sipral

/// The check this binding makes at load, asked of the library it loaded
/// about other versions than its own: within one major a binding built
/// against an earlier or equal minor is served, and one built against a
/// later minor, another major or any 0.x is refused.
final class AbiVersionTests: XCTestCase {
    private func refused(major: UInt32, minor: UInt32, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try Sipral.abiCheck(major: major, minor: minor), file: file, line: line) {
            let error = $0 as? SipralError
            XCTAssertEqual(error?.status, .unsupportedVersion, file: file, line: line)
            XCTAssertTrue(
                error?.description.contains("\(major).\(minor)") ?? false,
                "the refusal does not name \(major).\(minor): \(String(describing: error))",
                file: file, line: line)
        }
    }

    func testTheLibraryIsAtThisBindingsMajorAndNoEarlierMinor() throws {
        let version = try Sipral.abiVersion()
        XCTAssertEqual(version.major, Sipral.abiVersionMajor)
        XCTAssertGreaterThanOrEqual(version.minor, Sipral.abiVersionMinor)
    }

    func testTheMinorThisBindingWasPrintedAgainstIsServed() throws {
        XCTAssertNil(Sipral.abiMismatch)
        try Sipral.abiCheck(major: Sipral.abiVersionMajor, minor: Sipral.abiVersionMinor)
    }

    /// A library newer than its binding: every earlier minor of this major
    /// is a binding the library in hand is newer than.
    func testABindingBuiltAgainstAnEarlierMinorIsServed() throws {
        let version = try Sipral.abiVersion()
        for minor in 0...version.minor {
            XCTAssertNoThrow(try Sipral.abiCheck(major: version.major, minor: minor), "\(version.major).\(minor)")
        }
    }

    /// A library older than its binding.
    func testABindingBuiltAgainstALaterMinorIsRefused() throws {
        let version = try Sipral.abiVersion()
        refused(major: version.major, minor: version.minor + 1)
    }

    func testAnotherMajorIsRefused() throws {
        refused(major: Sipral.abiVersionMajor + 1, minor: 0)
        refused(major: 0, minor: 36)
    }
}
