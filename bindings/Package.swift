// swift-tools-version: 5.9
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// The package sits at the root of bindings/ so that the Swift target and the
// C target share one header. SwiftPM will not look outside a package's own
// directory, and a second copy of a generated header is a second thing to keep
// in step.

import Foundation
import PackageDescription

// `SipralTests` and `SipralLabAgent` link against the actual library
// `cargo build -p sipral-ffi --release` produces, the way `scripts/check.sh`
// links `bindings/c/smoke.c` and `interop/harness-c/main.c` against it: an
// absolute path computed from this manifest's own location, so it resolves
// the same way whether this package is opened from the main checkout or a
// worktree under `.claude/worktrees/`.
let repoRoot = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .path
let releaseDir = repoRoot + "/target/release"
let linkAgainstSipralFfi: [LinkerSetting] = [
    .unsafeFlags([
        "-L", releaseDir, "-lsipral_ffi",
        "-Xlinker", "-rpath", "-Xlinker", releaseDir,
    ])
]

let package = Package(
    name: "Sipral",
    platforms: [.macOS(.v14), .iOS(.v16)],
    products: [
        .library(name: "Sipral", targets: ["Sipral"]),
        .executable(name: "SipralLabAgent", targets: ["SipralLabAgent"]),
    ],
    targets: [
        // smoke.c is excluded because it is a program with a main, run by
        // scripts/check.sh against the built library; SwiftPM sweeps every
        // source under the target's path and this one is not part of it.
        .target(name: "CSipral", path: "c", exclude: ["smoke.c"], publicHeadersPath: "include"),
        .target(name: "Sipral", dependencies: ["CSipral"], path: "swift/Sources/Sipral"),
        .testTarget(
            name: "SipralTests", dependencies: ["Sipral"], path: "swift/Tests/SipralTests",
            linkerSettings: linkAgainstSipralFfi
        ),
        .executableTarget(
            name: "SipralLabAgent", dependencies: ["Sipral"], path: "swift/Sources/SipralLabAgent",
            linkerSettings: linkAgainstSipralFfi
        ),
    ]
)

// The SwiftUI sample is a macOS app, and SwiftUI exists nowhere else a
// manifest is read: declared on Linux it would stop `swift test`, which
// builds every target, before a single test ran.
#if os(macOS)
package.targets.append(
    .executableTarget(
        name: "SipralSampleMac", dependencies: ["Sipral"], path: "swift/Sources/SipralSampleMac",
        linkerSettings: linkAgainstSipralFfi
    )
)
// Built with the rest and run only by hand: it opens the machine's real
// microphone and loudspeaker, which the gate has neither of.
package.targets.append(
    .executableTarget(
        name: "SipralDeviceCheck", dependencies: ["Sipral"], path: "swift/Sources/SipralDeviceCheck",
        linkerSettings: linkAgainstSipralFfi
    )
)
#endif
