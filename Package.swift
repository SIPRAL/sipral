// swift-tools-version: 6.1
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
// Two variants, chosen by package trait: `Standard`, the default, over
// CSipral.xcframework.zip, which carries no libopus; and `Opus`, over
// CSipral-opus.xcframework.zip, for an application that names it
// (`traits: ["Opus"]`) and so turns the default off. Both archives export
// the module CSipral, so exactly one of the two may be linked: asking for
// both fails the build.
//
// The constants below are written by scripts/package/xcframework.sh
// --release, the first pair without --with-opus and the second with it, from
// the zip it built and the checksum SwiftPM computed over it, in the commit
// the release's tag is put on (docs/11-testing.md, "Releasing"). Until a
// release has written the first pair, CSipral is the XCFramework
// `scripts/package/xcframework.sh --out target/xcframework` leaves in this
// checkout; until one has written the second, there is no trait `Opus`,
// because SwiftPM refuses a package that declares an archive it cannot find,
// even one no build asks for.

import PackageDescription

let csipralURL = "https://github.com/SIPRAL/sipral/releases/download/v1.3.2/CSipral.xcframework.zip"
let csipralChecksum = "cf783a4447581c0489c311949e8c561d8424e93e3d6617a51cf217f3f5897851"
let csipralOpusURL = "https://github.com/SIPRAL/sipral/releases/download/v1.3.2/CSipral-opus.xcframework.zip"
let csipralOpusChecksum = "ca6ea7768ad107ea37df06be7c4da91f3e20c2cb582fb7675d2e352889e1dc08"

let csipral: Target = csipralChecksum.isEmpty
    ? .binaryTarget(name: "CSipral", path: "target/xcframework/CSipral.xcframework")
    : .binaryTarget(name: "CSipral", url: csipralURL, checksum: csipralChecksum)
let withOpus = !csipralOpusChecksum.isEmpty

let package = Package(
    name: "Sipral",
    platforms: [.macOS(.v12), .iOS(.v15)],
    products: [
        .library(name: "Sipral", targets: ["Sipral"])
    ],
    traits: withOpus
        ? [.trait(name: "Standard"), .trait(name: "Opus"), .default(enabledTraits: ["Standard"])]
        : [.trait(name: "Standard"), .default(enabledTraits: ["Standard"])],
    targets: [csipral]
        + (withOpus ? [.binaryTarget(name: "CSipralOpus", url: csipralOpusURL, checksum: csipralOpusChecksum)] : [])
        + [
            .target(
                name: "Sipral",
                dependencies: [.target(name: "CSipral", condition: .when(traits: ["Standard"]))]
                    + (withOpus ? [.target(name: "CSipralOpus", condition: .when(traits: ["Opus"]))] : []),
                path: "bindings/swift/Sources/Sipral"),
        ],
    // the language mode bindings/Package.swift builds and tests the module in;
    // tools 6.1, needed for traits, would otherwise make it Swift 6
    swiftLanguageModes: [.v5]
)
