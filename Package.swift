// swift-tools-version: 5.9
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The Swift package an application adds, by this repository's URL and a
// release's version: the `Sipral` module from bindings/swift/Sources/Sipral,
// over CSipral.xcframework, which each release carries as an asset rather
// than as a file in the tree. SwiftPM reads a package only from the root of
// its repository, which is why this manifest is here and not under
// bindings/; bindings/Package.swift stays the package the gate and the lab
// build from source.
//
// The two constants below are written by scripts/package/xcframework.sh
// --release, from the zip it built and the checksum SwiftPM computed over
// it, in the commit the release's tag is put on (docs/11-testing.md,
// "Releasing"). Until a release has written them, CSipral is the
// XCFramework `scripts/package/xcframework.sh --out target/xcframework`
// leaves in this checkout.

import PackageDescription

let csipralURL = "https://github.com/SIPRAL/sipral/releases/download/v1.1.0/CSipral.xcframework.zip"
let csipralChecksum = "b94b79ac2c740cc8ebb2716a022f3aea9ab408d8780af9b137befaf070ba382f"

let csipral: Target = csipralChecksum.isEmpty
    ? .binaryTarget(name: "CSipral", path: "target/xcframework/CSipral.xcframework")
    : .binaryTarget(name: "CSipral", url: csipralURL, checksum: csipralChecksum)

let package = Package(
    name: "Sipral",
    platforms: [.macOS(.v12), .iOS(.v15)],
    products: [
        .library(name: "Sipral", targets: ["Sipral"])
    ],
    targets: [
        csipral,
        .target(name: "Sipral", dependencies: ["CSipral"], path: "bindings/swift/Sources/Sipral"),
    ]
)
