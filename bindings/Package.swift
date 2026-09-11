// swift-tools-version: 5.9
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// The package sits at the root of bindings/ so that the Swift target and the
// C target share one header. SwiftPM will not look outside a package's own
// directory, and a second copy of a generated header is a second thing to keep
// in step.

import PackageDescription

let package = Package(
    name: "Sipral",
    products: [
        .library(name: "Sipral", targets: ["Sipral"])
    ],
    targets: [
        // smoke.c is excluded because it is a program with a main, run by
        // scripts/check.sh against the built library; SwiftPM sweeps every
        // source under the target's path and this one is not part of it.
        .target(name: "CSipral", path: "c", exclude: ["smoke.c"], publicHeadersPath: "include"),
        .target(name: "Sipral", dependencies: ["CSipral"], path: "swift/Sources/Sipral")
    ]
)
