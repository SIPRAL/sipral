// swift-tools-version: 5.9
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// The Swift half of the iOS module, built on its own: what scripts/check.sh
// compiles against bindings/swift and tests on macOS, the Objective-C++
// module beside it being the part only an application's React Native build
// compiles. An application never reads this manifest; the podspec at the
// package's root takes Bridge/ and the module together.

import Foundation
import PackageDescription

// The tests link the library `cargo build -p sipral-ffi --release` writes,
// the way bindings/Package.swift's own tests do.
let releaseDir = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .appendingPathComponent("../../../target/release")
    .standardizedFileURL
    .path

let package = Package(
    name: "SipralReactBridge",
    platforms: [.macOS(.v14), .iOS(.v16)],
    dependencies: [
        .package(path: "../.."),
    ],
    targets: [
        .target(
            name: "SipralReactBridge",
            dependencies: [.product(name: "Sipral", package: "bindings")],
            path: "Bridge"
        ),
        .testTarget(
            name: "SipralReactBridgeTests",
            dependencies: ["SipralReactBridge"],
            path: "Tests",
            linkerSettings: [
                .unsafeFlags([
                    "-L", releaseDir, "-lsipral_ffi",
                    "-Xlinker", "-rpath", "-Xlinker", releaseDir,
                ])
            ]
        ),
    ]
)
