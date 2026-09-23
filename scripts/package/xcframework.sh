#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# The Apple artefact: one XCFramework carrying macOS (arm64+x86_64, universal),
# iOS device (arm64) and iOS Simulator (arm64+x86_64, universal), built from
# the C ABI, plus a distribution Package.swift over it -- a binaryTarget in
# place of bindings/Package.swift's source target, for a consumer who links
# the built library rather than compiling this workspace.
#
#   scripts/package/xcframework.sh --out DIR             the real artefact
#   scripts/package/xcframework.sh --out DIR --dry-run   same, minus the zip
#                                                         and checksum a host
#                                                         would publish
#
# Every slice is built by this machine's own Rust toolchain, `lipo`d where a
# platform needs two architectures, and handed to `xcodebuild
# -create-xcframework`, which is the one tool that writes a shape SwiftPM and
# Xcode both read. Nothing here signs or notarizes: that is the owner's, on
# the owner's certificate, and out of scope by the same rule that keeps it out
# of every other script in this directory.
set -uo pipefail

cd "$(dirname "$0")/../.."
ROOT="$PWD"

OUT=""
DRY_RUN=0
PUBLISH=0
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --publish) PUBLISH=1; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
if [ -z "$OUT" ]; then
    printf 'usage: xcframework.sh --out DIR [--dry-run] [--publish]\n' >&2
    exit 2
fi
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
step() { printf '\n%s\n' "$1"; }

if [ "$(uname -s)" != "Darwin" ]; then
    fail "xcframework.sh runs only on macOS: xcodebuild built this, and no other host has it"
    exit 1
fi
command -v xcodebuild >/dev/null 2>&1 || { fail "xcodebuild not found (Xcode, not just the Command Line Tools)"; exit 1; }
command -v lipo >/dev/null 2>&1 || { fail "lipo not found"; exit 1; }

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
    if printf '%s\n' "$installed" | grep -qx "$t"; then
        pass "$t installed"
    else
        fail "$t not installed: rustup target add $t"
    fi
done

if [ "$FAIL" -ne 0 ]; then
    printf '\nstopping before any build: the targets above are not installed.\n'
    exit 1
fi

step "building $CRATE, release, per target"
# libopus's C sources compile, for arm64 Apple targets, with calls to
# ___chkstk_darwin -- part of the arm64 Darwin ABI for a frame over a page,
# not a bug in the C -- which lives in Apple's own compiler-rt and links
# automatically for an Xcode-built app, but not for a bare `cargo build`
# against an iOS target: nothing in that link line names the runtime that
# provides it. The device slice and both simulator architectures each need
# their own archive.
CLANG_RT_DIR="$(xcrun --sdk iphoneos clang --print-resource-dir 2>/dev/null)/lib/darwin"
rustflags_for() {
    case "$1" in
        aarch64-apple-ios) [ -f "$CLANG_RT_DIR/libclang_rt.ios.a" ] && printf -- '-Clink-arg=%s' "$CLANG_RT_DIR/libclang_rt.ios.a" ;;
        aarch64-apple-ios-sim|x86_64-apple-ios) [ -f "$CLANG_RT_DIR/libclang_rt.iossim.a" ] && printf -- '-Clink-arg=%s' "$CLANG_RT_DIR/libclang_rt.iossim.a" ;;
    esac
}
for t in "${all_triples[@]}"; do
    extra_rustflags="$(rustflags_for "$t")"
    if env RUSTFLAGS="${RUSTFLAGS:-} $extra_rustflags" \
        cargo build --release -p "$CRATE" --target "$t" >"$STAGE/build-$t.log" 2>&1; then
        pass "cargo build --release -p $CRATE --target $t"
    else
        fail "cargo build --release -p $CRATE --target $t:"
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
        inputs+=("$ROOT/target/$t/release/$LIBNAME")
    done
    if [ "${#inputs[@]}" -eq 1 ]; then
        cp "${inputs[0]}" "$dest/$LIBNAME"
    else
        lipo -create -output "$dest/$LIBNAME" "${inputs[@]}" || { fail "lipo -create, $name"; continue; }
    fi
    lipo -info "$dest/$LIBNAME" >"$dest/lipo-info.txt" 2>&1
    pass "$name: $(cat "$dest/lipo-info.txt")"
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
step "the distribution Package.swift"
SPM="$OUT/spm"
rm -rf "$SPM"
mkdir -p "$SPM/Sources/Sipral"
cp "$ROOT/bindings/swift/Sources/Sipral/SipralAbi.swift" "$SPM/Sources/Sipral/"
cat >"$SPM/Package.swift" <<'EOF'
// swift-tools-version: 5.9
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// Printed by scripts/package/xcframework.sh, over the CSipral.xcframework
// beside it, for a consumer who links the built library instead of compiling
// bindings/Package.swift's source target. SipralAbi.swift is copied in
// unchanged from bindings/swift/Sources/Sipral: it depends on nothing but
// CSipral's module, whether that module comes from source or from here.
//
// The binaryTarget's path is local, which is what a package still under
// development at 0.0.1, with nowhere public to host a zip yet, can commit to.
// Publishing this package means replacing that path with a remote zip URL
// and the checksum this script prints beside it -- the owner's step, once
// there is a host to put the zip on.

import PackageDescription

let package = Package(
    name: "Sipral",
    platforms: [.macOS(.v12), .iOS(.v15)],
    products: [
        .library(name: "Sipral", targets: ["Sipral"])
    ],
    targets: [
        .binaryTarget(name: "CSipral", path: "../CSipral.xcframework"),
        .target(name: "Sipral", dependencies: ["CSipral"], path: "Sources/Sipral")
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

if [ "$DRY_RUN" -eq 0 ]; then
    step "zip and checksum, for a remote binaryTarget"
    ZIP="$OUT/CSipral.xcframework.zip"
    rm -f "$ZIP"
    ( cd "$OUT" && ditto -c -k --sequesterRsrc --keepParent CSipral.xcframework "$ZIP" ) \
        && pass "CSipral.xcframework.zip written" || fail "ditto -c -k, CSipral.xcframework"
    if [ -f "$ZIP" ]; then
        CHECKSUM=$(xcrun --toolchain default swift package compute-checksum "$ZIP" 2>"$STAGE/checksum.log")
        if [ -n "$CHECKSUM" ]; then
            pass "checksum: $CHECKSUM"
            printf '%s\n' "$CHECKSUM" >"$OUT/CSipral.xcframework.zip.checksum"
        else
            fail "swift package compute-checksum, $ZIP:"
            tail -10 "$STAGE/checksum.log" | sed 's/^/        /'
        fi
    fi
fi

if [ "$PUBLISH" -eq 1 ]; then
    step "publish"
    printf '  not run: nothing under bindings/ ships to a registry before the ABI\n'
    printf '  freezes (docs/08-ffi.md), and this repo has no public host for the zip\n'
    printf '  yet. What the owner runs once both exist: tag this commit, upload\n'
    printf '  %s to that release, and point spm/Package.swift'"'"'s\n' "$(basename "$OUT")/CSipral.xcframework.zip"
    printf '  binaryTarget at the release URL with the checksum printed above.\n'
fi

printf '\n'
[ "$FAIL" -eq 0 ] && { printf 'xcframework.sh: done, %s\n' "$OUT"; exit 0; }
printf 'xcframework.sh: failed\n'; exit 1
