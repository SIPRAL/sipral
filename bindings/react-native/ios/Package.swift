// swift-tools-version: 5.9
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The Swift half of the iOS module, for scripts/check.sh to build and test
// on macOS. Applications use the podspec instead.

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
