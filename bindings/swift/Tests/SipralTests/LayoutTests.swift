// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import XCTest

@testable import Sipral

/// The lengths tools/abi-gen worked out for every record, on the layout this
/// runs on, held to the struct Swift imported from the header and to the
/// library's own answer. bindings/c/abi-layout.c holds a C compiler to the
/// same table on the layouts this machine cannot run.
final class LayoutTests: XCTestCase {
    func testEveryRecordIsAsLongAsTheLayoutSays() throws {
        XCTAssertGreaterThan(Sipral.recordLayouts.count, 50)
        for row in Sipral.recordLayouts {
            #if arch(x86_64) || arch(arm64)
                let expected = row.p64
            #elseif arch(i386)
                let expected = row.p32a4
            #else
                let expected = row.p32a8
            #endif
            XCTAssertEqual(row.imported, expected, row.name)
            XCTAssertEqual(try Sipral.abiStructSize(name: row.name), expected, row.name)
        }
    }
}
