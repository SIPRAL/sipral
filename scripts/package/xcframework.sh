#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# The Apple artefact: one XCFramework carrying macOS (arm64+x86_64, universal),
# iOS device (arm64) and iOS Simulator (arm64+x86_64, universal), built from
# the C ABI, plus a distribution Package.swift over it -- a binaryTarget in
# place of bindings/Package.swift's source target, for a consumer who links
# the built library rather than compiling this workspace.
#
#   scripts/package/xcframework.sh --out DIR             the real artefact,
#                                                         its zip and the
#                                                         zip's checksum
#   scripts/package/xcframework.sh --out DIR --dry-run   the same, the zip
#                                                         left in DIR/_stage
#                                                         and the root
#                                                         Package.swift
#                                                         written only to a
#                                                         copy there
#   scripts/package/xcframework.sh --out DIR --release   the real artefact,
#                                                         and the root
#                                                         Package.swift
#                                                         pointed at the zip
#   ... --with-opus                                       the variant that
#                                                         carries libopus
#
# The Swift package an application adds is the root Package.swift: the
# Sipral module from bindings/swift/Sources/Sipral over a binaryTarget whose
# URL is the zip's place among the release's assets,
# REPOSITORY/releases/download/vVERSION/CSipral.xcframework.zip, and whose
# checksum is what `swift package compute-checksum` says of that zip.
# --release writes both into it; every run checks that it still reads and
# still names the platforms apple.sh builds for. The package carries the
# default variant, so --release refuses --with-opus: the zip with libopus is
# an asset an application points its own binaryTarget at.
#
# Without --with-opus the library is built without sipral-ffi's `opus`
# feature and every other default kept (features.sh says why and how);
# with it, the zip is CSipral-opus.xcframework.zip and the distribution
# Package.swift says what it carries. The XCFramework inside keeps the name
# CSipral either way, because a binaryTarget's artefact is found by the
# target's own name. Which variant came out is checked, not assumed: the
# macOS archive is read for libopus's own symbols, which have to be absent
# from the one and present in the other.
#
# Every slice is built by this machine's own Rust toolchain, `lipo`d where a
# platform needs two architectures, and handed to `xcodebuild
# -create-xcframework`, which is the one tool that writes a shape SwiftPM and
# Xcode both read. Nothing here signs or notarizes: that is the owner's, on
# the owner's certificate, and out of scope by the same rule that keeps it out
# of every other script in this directory.
set -uo pipefail

# found [GREP OPTIONS] PATTERN: whether standard input has a line PATTERN
# matches, read to its end. `grep -q` stops at the first match, and under
# pipefail whatever is still writing into the pipe then dies of SIGPIPE and
# fails the pipeline: a match read as none, and more often the busier the
# machine. A gate run in parallel lost classes.jar's first entries that way.
found() { grep "$@" >/dev/null; }

cd "$(dirname "$0")/../.."
ROOT="$PWD"

OUT=""
DRY_RUN=0
PUBLISH=0
WITH_OPUS=0
RELEASE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --publish) PUBLISH=1; shift ;;
        --with-opus) WITH_OPUS=1; shift ;;
        --release) RELEASE=1; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
if [ -z "$OUT" ]; then
    printf 'usage: xcframework.sh --out DIR [--dry-run | --release] [--publish] [--with-opus]\n' >&2
    exit 2
fi
if [ "$RELEASE" -eq 1 ] && [ "$DRY_RUN" -eq 1 ]; then
    printf 'xcframework.sh: --release writes the zip it builds into Package.swift, and --dry-run builds none to publish\n' >&2
    exit 2
fi
if [ "$RELEASE" -eq 1 ] && [ "$WITH_OPUS" -eq 1 ]; then
    printf 'xcframework.sh: the root Package.swift carries the default variant; --release does not take --with-opus\n' >&2
    exit 2
fi
. "$ROOT/scripts/package/features.sh"
package_features "$WITH_OPUS" || { printf 'no default feature list in crates/sipral-ffi/Cargo.toml\n' >&2; exit 1; }
. "$ROOT/scripts/package/neutral-paths.sh"
. "$ROOT/scripts/package/apple.sh"
APPLE_TARGET="$(apple_target_dir "${CARGO_TARGET_DIR:-$ROOT/target}")"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
note() { printf '  note  %s\n' "$1"; }
step() { printf '\n%s\n' "$1"; }

if [ "$(uname -s)" != "Darwin" ]; then
    fail "xcframework.sh runs only on macOS: xcodebuild built this, and no other host has it"
    exit 1
fi
command -v xcodebuild >/dev/null 2>&1 || { fail "xcodebuild not found (Xcode, not just the Command Line Tools)"; exit 1; }
command -v lipo >/dev/null 2>&1 || { fail "lipo not found"; exit 1; }

step "one version"
"$ROOT/scripts/version.sh" --check || { printf '\nxcframework.sh: failed\n'; exit 1; }
VERSION="$("$ROOT/scripts/version.sh")"
REPOSITORY=$(sed -n 's/^repository = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -1)
RELEASE_URL="$REPOSITORY/releases/download/v$VERSION/CSipral.xcframework.zip"

CRATE="sipral-ffi"
LIBNAME="libsipral_ffi.a"
HEADER="$ROOT/bindings/c/include/sipral.h"
STAGE="$OUT/_stage"
rm -rf "$STAGE"
mkdir -p "$STAGE"

# macOS, then iOS device, then iOS Simulator -- each an entry of
# "slice directory name:target triple[,target triple]" so a slice that needs
# two architectures lipo's them, and one that needs one does not.
SLICES=(
    "macos:aarch64-apple-darwin,x86_64-apple-darwin"
    "ios:aarch64-apple-ios"
    "ios-simulator:aarch64-apple-ios-sim,x86_64-apple-ios"
)

step "rust targets"
IFS=$'\n' read -r -d '' -a all_triples < <(
    for s in "${SLICES[@]}"; do printf '%s\n' "${s#*:}" | tr ',' '\n'; done
    printf '\0'
)
installed="$(rustup target list --installed 2>/dev/null || true)"
for t in "${all_triples[@]}"; do
    if printf '%s\n' "$installed" | found -x "$t"; then
        pass "$t installed"
    else
        fail "$t not installed: rustup target add $t"
    fi
done

if [ "$FAIL" -ne 0 ]; then
    printf '\nstopping before any build: the targets above are not installed.\n'
    exit 1
fi

step "building $CRATE, release, per target, for macOS $APPLE_MACOS_MIN and iOS $APPLE_IOS_MIN and later, $VARIANT_LABEL (features $FFI_FEATURES)"
# libopus's C sources compile, for arm64 Apple targets, with calls to
# ___chkstk_darwin -- part of the arm64 Darwin ABI for a frame over a page,
# not a bug in the C -- which lives in Apple's own compiler-rt and links
# automatically for an Xcode-built app, but not for a bare `cargo build`
# against an iOS target: nothing in that link line names the runtime that
# provides it. The device slice and both simulator architectures each need
# their own archive. It goes in as a `--config` target table beside
# neutral-paths.sh's, which cargo joins, where RUSTFLAGS would drop that one.
CLANG_RT_DIR="$(xcrun --sdk iphoneos clang --print-resource-dir 2>/dev/null)/lib/darwin"
clang_rt_for() {
    case "$1" in
        aarch64-apple-ios) printf '%s' "$CLANG_RT_DIR/libclang_rt.ios.a" ;;
        aarch64-apple-ios-sim|x86_64-apple-ios) printf '%s' "$CLANG_RT_DIR/libclang_rt.iossim.a" ;;
    esac
}
for t in "${all_triples[@]}"; do
    neutral_cargo_args "$t"
    clang_rt="$(clang_rt_for "$t")"
    [ -n "$clang_rt" ] && [ -f "$clang_rt" ] \
        && NEUTRAL_CARGO_ARGS+=(--config "target.$t.rustflags=['-Clink-arg=$clang_rt']")
    if cargo build --release -p "$CRATE" "${FFI_FEATURE_ARGS[@]}" --target "$t" "${NEUTRAL_CARGO_ARGS[@]}" \
        --target-dir "$APPLE_TARGET" >"$STAGE/build-$t.log" 2>&1; then
        pass "cargo build --release -p $CRATE ${FFI_FEATURE_ARGS[*]} --target $t"
    else
        fail "cargo build --release -p $CRATE ${FFI_FEATURE_ARGS[*]} --target $t:"
        tail -30 "$STAGE/build-$t.log" | sed 's/^/        /'
    fi
done
[ "$FAIL" -ne 0 ] && exit 1

# One module map beside the printed header, only in this staged copy: a
# binaryTarget's Headers directory has to say how to import it, where a
# source .target has SwiftPM synthesise that for it. bindings/c/include
# itself stays exactly what tools/abi-gen printed.
HDRDIR="$STAGE/headers"
mkdir -p "$HDRDIR"
cp "$HEADER" "$HDRDIR/"
cat >"$HDRDIR/module.modulemap" <<'EOF'
module CSipral {
    header "sipral.h"
    export *
}
EOF

step "lipo, per slice"
LIB_ARGS=()
for s in "${SLICES[@]}"; do
    name="${s%%:*}"
    triples="${s#*:}"
    IFS=',' read -r -a triple_arr <<<"$triples"
    dest="$STAGE/$name"
    mkdir -p "$dest"
    inputs=()
    for t in "${triple_arr[@]}"; do
        inputs+=("$APPLE_TARGET/$t/release/$LIBNAME")
    done
    # every object in the archive, Rust's and libopus's alike, built for the
    # oldest release the Package.swift below declares, or an older one
    case "$name" in
        macos) min="$APPLE_MACOS_MIN" ;;
        *) min="$APPLE_IOS_MIN" ;;
    esac
    for input in "${inputs[@]}"; do
        if newest=$(apple_min_at_most "$input" "$min"); then
            pass "$name: $(basename "$(dirname "$(dirname "$input")")"), every object for $min or older (newest: $newest)"
        else
            fail "$name: an object in $input was built for ${newest:-(no minimum named)}, newer than $min"
        fi
    done
    if [ "${#inputs[@]}" -eq 1 ]; then
        cp "${inputs[0]}" "$dest/$LIBNAME"
    else
        lipo -create -output "$dest/$LIBNAME" "${inputs[@]}" || { fail "lipo -create, $name"; continue; }
    fi
    lipo -info "$dest/$LIBNAME" >"$dest/lipo-info.txt" 2>&1
    pass "$name: $(cat "$dest/lipo-info.txt")"
    neutral_paths_held "$name/$LIBNAME" "$dest/$LIBNAME"
    LIB_ARGS+=(-library "$dest/$LIBNAME" -headers "$HDRDIR")
done
[ "$FAIL" -ne 0 ] && exit 1

step "xcodebuild -create-xcframework"
XCFRAMEWORK="$OUT/CSipral.xcframework"
rm -rf "$XCFRAMEWORK"
if xcodebuild -create-xcframework "${LIB_ARGS[@]}" -output "$XCFRAMEWORK" >"$STAGE/xcframework.log" 2>&1; then
    pass "CSipral.xcframework written"
else
    fail "xcodebuild -create-xcframework:"
    tail -30 "$STAGE/xcframework.log" | sed 's/^/        /'
    exit 1
fi

step "structure"
info_plist="$XCFRAMEWORK/Info.plist"
if [ -f "$info_plist" ]; then
    pass "Info.plist present"
else
    fail "Info.plist missing from $XCFRAMEWORK"
fi
slice_count=$(find "$XCFRAMEWORK" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
if [ "$slice_count" -eq "${#SLICES[@]}" ]; then
    pass "$slice_count platform slices, as built"
else
    fail "$slice_count platform slices in the xcframework, ${#SLICES[@]} were built"
fi

# libopus's own C symbols, read out of the macOS archive the XCFramework now
# holds, the same way scripts/check.sh reads the C ABI's debug build:
# nm-classic without `-g`, because libopus is built with hidden visibility,
# and `_opus_` at the start of the name, because the Rust `opus` crate's
# mangled names say nothing about whether the C library is in the file. A
# static archive keeps its symbols under the release profile's `strip`,
# which only a linked library loses them to. The archive's own `_sipral_`
# entry points are counted too, so that an nm that read nothing is not taken
# for an archive with no libopus in it.
MACOS_ARCHIVE=$(find "$XCFRAMEWORK" -path '*macos*' -name "$LIBNAME" | head -1)
if [ -z "$MACOS_ARCHIVE" ]; then
    fail "no macOS $LIBNAME inside $XCFRAMEWORK to read for libopus"
else
    symbols=$(xcrun nm-classic -U -arch arm64 "$MACOS_ARCHIVE" 2>/dev/null | awk '{print $NF}')
    entry_points=$(printf '%s\n' "$symbols" | grep -c '^_sipral_' || true)
    opus_symbols=$(printf '%s\n' "$symbols" | grep -c '^_opus_' || true)
    if [ "$entry_points" -eq 0 ]; then
        fail "nm read no _sipral_ entry point out of the macOS archive, so nothing was checked for libopus"
    elif [ "$WITH_OPUS" -eq 0 ] && [ "$opus_symbols" -eq 0 ]; then
        pass "no opus symbol in the macOS archive (nm, $entry_points _sipral_ entry points read)"
    elif [ "$WITH_OPUS" -eq 0 ]; then
        fail "the macOS archive links $opus_symbols opus symbols, in the build meant to be without libopus"
    elif [ "$opus_symbols" -gt 0 ]; then
        pass "$opus_symbols opus symbols in the macOS archive, as --with-opus asked (nm)"
    else
        fail "--with-opus, and not a single opus symbol in the macOS archive"
    fi
fi

step "the distribution Package.swift"
SPM="$OUT/spm"
rm -rf "$SPM"
mkdir -p "$SPM/Sources/Sipral" "$SPM/Tests/SipralTests"
cp "$ROOT"/bindings/swift/Sources/Sipral/*.swift "$SPM/Sources/Sipral/"
cp "$ROOT"/bindings/swift/Tests/SipralTests/*.swift "$SPM/Tests/SipralTests/"
copied=$(find "$SPM/Sources/Sipral" -name '*.swift' | wc -l | tr -d ' ')
expected=$(find "$ROOT/bindings/swift/Sources/Sipral" -name '*.swift' | wc -l | tr -d ' ')
if [ "$copied" -eq "$expected" ] && [ "$copied" -gt 0 ]; then
    pass "$copied Swift sources of the Sipral module copied, the whole module"
else
    fail "$copied Swift sources copied into spm/Sources/Sipral, $expected in bindings/swift/Sources/Sipral"
fi
# Unquoted, for the lines that name the variant and the platforms (apple.sh's
# two minimums, which every archive above was checked against); nothing else
# in it expands.
cat >"$SPM/Package.swift" <<EOF
// swift-tools-version: 5.9
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Printed by scripts/package/xcframework.sh, over the CSipral.xcframework
// beside it, for a consumer who links the built library instead of compiling
// bindings/Package.swift's source target. Sources/Sipral is
// bindings/swift/Sources/Sipral copied in unchanged -- the printed
// SipralAbi.swift and the layer written over it, CallKitBridge and
// PushKitBridge among it -- since none of it depends on anything but
// CSipral's module and the platform's own, whether that module comes from
// source or from here. Tests/SipralTests is that package's suite, run
// against this artefact instead of a library cargo left in target/:
// swift test here for the macOS slice, and xcodebuild test -scheme Sipral
// -destination 'platform=iOS Simulator,id=<device>' for the simulator one
// (docs/15-mobile.md, "The Swift package on iOS").
//
// Variant: $VARIANT_LABEL.
// sipral-ffi features: $FFI_FEATURES.
//
// The binaryTarget's path is local: this package is for running the suite
// against the artefact. What an application adds is the repository's root
// Package.swift, whose binaryTarget names the release's zip by URL and
// checksum (scripts/package/xcframework.sh --release).

import PackageDescription

let package = Package(
    name: "Sipral",
    platforms: [.macOS(.v${APPLE_MACOS_MIN%%.*}), .iOS(.v${APPLE_IOS_MIN%%.*})],
    products: [
        .library(name: "Sipral", targets: ["Sipral"])
    ],
    targets: [
        .binaryTarget(name: "CSipral", path: "../CSipral.xcframework"),
        .target(name: "Sipral", dependencies: ["CSipral"], path: "Sources/Sipral"),
        .testTarget(name: "SipralTests", dependencies: ["Sipral"], path: "Tests/SipralTests")
    ]
)
EOF
pass "spm/Package.swift written, over ../CSipral.xcframework"

if xcrun --toolchain default swift package dump-package --package-path "$SPM" >/dev/null 2>"$STAGE/dump-package.log"; then
    pass "swift package dump-package, spm/Package.swift"
else
    fail "swift package dump-package, spm/Package.swift:"
    tail -20 "$STAGE/dump-package.log" | sed 's/^/        /'
fi

# The zip and its checksum, for a remote binaryTarget. A dry run makes them
# too, in the stage directory, so that the release path below runs on a copy
# of the manifest; only a real run leaves the zip where a host would take it.
step "zip and checksum, for a remote binaryTarget"
ZIP="$OUT/CSipral$VARIANT_SUFFIX.xcframework.zip"
[ "$DRY_RUN" -eq 1 ] && ZIP="$STAGE/CSipral$VARIANT_SUFFIX.xcframework.zip"
CHECKSUM=""
rm -f "$ZIP"
( cd "$OUT" && ditto -c -k --sequesterRsrc --keepParent CSipral.xcframework "$ZIP" ) \
    && pass "$(basename "$ZIP") written" || fail "ditto -c -k, CSipral.xcframework"
if [ -f "$ZIP" ]; then
    CHECKSUM=$(xcrun --toolchain default swift package compute-checksum "$ZIP" 2>"$STAGE/checksum.log")
    if [ -n "$CHECKSUM" ]; then
        pass "checksum: $CHECKSUM"
        printf '%s\n' "$CHECKSUM" >"$ZIP.checksum"
    else
        fail "swift package compute-checksum, $ZIP:"
        tail -10 "$STAGE/checksum.log" | sed 's/^/        /'
    fi
fi

# The root Package.swift: the two constants a release writes, each on its
# own line, and the platforms apple.sh built every archive for.
MANIFEST="$ROOT/Package.swift"
manifest_value() {
    sed -n "s/^let $1 = \"\(.*\)\"\$/\1/p" "$2"
}
stamp_manifest() {
    awk -v url="$2" -v sum="$3" '
        /^let csipralURL = "/ { print "let csipralURL = \"" url "\""; next }
        /^let csipralChecksum = "/ { print "let csipralChecksum = \"" sum "\""; next }
        { print }
    ' "$1" >"$1.new" && mv "$1.new" "$1"
}
dump_manifest() {
    xcrun --toolchain default swift package dump-package --package-path "$(dirname "$1")" \
        >"$STAGE/dump-root.json" 2>"$STAGE/dump-root.log"
}
step "the release manifest, Package.swift"
platforms=".macOS(.v${APPLE_MACOS_MIN%%.*}), .iOS(.v${APPLE_IOS_MIN%%.*})"
url_lines=$(grep -c '^let csipralURL = "' "$MANIFEST" || true)
sum_lines=$(grep -c '^let csipralChecksum = "' "$MANIFEST" || true)
if [ "$url_lines" -ne 1 ] || [ "$sum_lines" -ne 1 ]; then
    fail "Package.swift: $url_lines csipralURL and $sum_lines csipralChecksum lines, one of each expected"
else
    pass "Package.swift: one csipralURL and one csipralChecksum line for --release to write"
fi
grep -qF "platforms: [$platforms]" "$MANIFEST" \
    && pass "Package.swift: platforms [$platforms], as apple.sh builds" \
    || fail "Package.swift does not say platforms: [$platforms], which every archive above was built for"
if dump_manifest "$MANIFEST" && grep -q '"bindings/swift/Sources/Sipral"' "$STAGE/dump-root.json"; then
    pass "swift package dump-package, Package.swift: the Sipral module from bindings/swift/Sources/Sipral"
else
    fail "swift package dump-package, Package.swift:"; tail -20 "$STAGE/dump-root.log" | sed 's/^/        /'
fi
have_url=$(manifest_value csipralURL "$MANIFEST")
have_sum=$(manifest_value csipralChecksum "$MANIFEST")
if [ -z "$have_sum" ]; then
    pass "Package.swift names no release yet: CSipral is target/xcframework/CSipral.xcframework"
elif ! printf '%s\n' "$have_sum" | grep -Eq '^[0-9a-f]{64}$'; then
    fail "Package.swift: csipralChecksum '$have_sum' is not a SHA-256 in hex"
elif [ "$have_url" = "$RELEASE_URL" ]; then
    pass "Package.swift names this version's zip, $have_url"
else
    note "Package.swift names $have_url, the last release's zip; --release writes $VERSION's"
fi

if [ -n "$CHECKSUM" ] && [ "$WITH_OPUS" -eq 0 ]; then
    if [ "$RELEASE" -eq 1 ]; then
        target_manifest="$MANIFEST"
    else
        mkdir -p "$STAGE/release-manifest"
        target_manifest="$STAGE/release-manifest/Package.swift"
        cp "$MANIFEST" "$target_manifest"
    fi
    stamp_manifest "$target_manifest" "$RELEASE_URL" "$CHECKSUM"
    if [ "$(manifest_value csipralURL "$target_manifest")" = "$RELEASE_URL" ] \
        && [ "$(manifest_value csipralChecksum "$target_manifest")" = "$CHECKSUM" ] \
        && dump_manifest "$target_manifest" && grep -q "\"$CHECKSUM\"" "$STAGE/dump-root.json"; then
        if [ "$RELEASE" -eq 1 ]; then
            pass "Package.swift written: CSipral from $RELEASE_URL, checksum $CHECKSUM"
        else
            pass "a copy of Package.swift written as --release would, and read back ($target_manifest)"
        fi
    else
        fail "Package.swift as --release writes it does not read back:"; tail -20 "$STAGE/dump-root.log" | sed 's/^/        /'
    fi
fi

# The SBOM sits beside the .xcframework, from sipral-ffi's own dependency
# graph across every Apple platform this one artefact carries
# (docs/10-roadmap.md). Hashed against the zip a host would actually
# publish when there is one; --dry-run builds no zip (above), so the SBOM
# there carries no hash rather than one of something that is not the
# artefact. --notices only for the variant whose feature list is
# THIRD-PARTY-LICENSES.txt's own (no flags at all, opus included).
step "SBOM"
XCF_VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -1)
SBOM_ARGS=(--crate sipral-ffi --features "$FFI_FEATURES" --target all \
    --artifact-name "CSipral$VARIANT_SUFFIX" --artifact-version "$XCF_VERSION" \
    --out "$XCFRAMEWORK.cdx.json")
[ -f "$ZIP" ] && SBOM_ARGS+=(--artifact "$ZIP")
[ "$WITH_OPUS" -eq 1 ] && SBOM_ARGS+=(--notices "$ROOT/THIRD-PARTY-LICENSES.txt")
if sbom_out=$(cargo run --quiet -p sipral-sbom-gen -- "${SBOM_ARGS[@]}" 2>&1); then
    pass "$(basename "$XCFRAMEWORK.cdx.json")"
else
    fail "sbom-gen:"; printf '%s\n' "$sbom_out" | sed 's/^/        /'
fi

if [ "$PUBLISH" -eq 1 ]; then
    step "publish"
    printf '  not run: the owner publishes. Commit the root Package.swift that --release\n'
    printf '  wrote, put the tag v%s on that commit, and upload\n' "$VERSION"
    printf '  %s to the release v%s as an asset, so that it is at\n' "$ZIP" "$VERSION"
    printf '  %s (docs/11-testing.md, "Releasing").\n' "$RELEASE_URL"
fi

printf '\n'
[ "$FAIL" -eq 0 ] && { printf 'xcframework.sh: done, %s, %s\n' "$OUT" "$VARIANT_LABEL"; exit 0; }
printf 'xcframework.sh: failed\n'; exit 1
