#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# The .NET MAUI artefact: Sipral.Maui.<version>.nupkg, the binding in
# bindings/dotnet/Sipral compiled for net10.0-ios and net10.0-android with
# bindings/dotnet/Sipral.Maui around it, and the natives both need inside:
#
#   lib/net10.0-ios*/Sipral.dll           the binding, its P/Invokes bound to
#                                         __Internal, since iOS links the
#                                         library into the application
#   runtimes/ios/native/                  CSipral.xcframework (device arm64,
#                                         simulator arm64+x86_64)
#   buildTransitive/Sipral.Maui.targets   links it into every iOS
#                                         application that references the
#                                         package, as a NativeReference
#   lib/net10.0-android*/Sipral.dll       the binding
#   runtimes/android-arm64/native/        libsipral_ffi.so, for arm64-v8a,
#   runtimes/android-arm/native/          armeabi-v7a and x86_64, which the
#   runtimes/android-x64/native/          Android SDK puts under lib/<abi>/
#
#   scripts/package/maui.sh [--out DIR] [--with-opus] [--natives-only]
#
# DIR defaults to target/maui. The natives land in DIR/natives, where
# Sipral.Maui.csproj and the sample look for them by default; the package in
# DIR. --natives-only stops before `dotnet pack`, for a machine without the
# MAUI workloads. Runs only on macOS: the iOS half needs Xcode, and the
# Android half uses this Mac's own NDK (ANDROID_NDK_HOME, or the newest
# under ANDROID_HOME/ndk) with no container in between.
#
# Without --with-opus the natives are built without sipral-ffi's `opus`
# feature and every other default kept (features.sh says why and how).
# Nothing here publishes: the package is pushed by hand, if ever.
set -uo pipefail

found() { grep "$@" >/dev/null; }

cd "$(dirname "$0")/../.."
ROOT="$PWD"

OUT="$ROOT/target/maui"
WITH_OPUS=0
NATIVES_ONLY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --with-opus) WITH_OPUS=1; shift ;;
        --natives-only) NATIVES_ONLY=1; shift ;;
        *) printf 'unknown argument: %s\nusage: maui.sh [--out DIR] [--with-opus] [--natives-only]\n' "$1" >&2; exit 2 ;;
    esac
done
. "$ROOT/scripts/package/features.sh"
package_features "$WITH_OPUS" || { printf 'no default feature list in crates/sipral-ffi/Cargo.toml\n' >&2; exit 1; }
. "$ROOT/scripts/package/neutral-paths.sh"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
NATIVES="$OUT/natives"

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
note() { printf '  note  %s\n' "$1"; }
step() { printf '\n%s\n' "$1"; }
stop() { printf '\nmaui.sh: failed\n'; exit 1; }

[ "$(uname -s)" = "Darwin" ] || { fail "maui.sh runs only on macOS: the iOS natives need Xcode"; stop; }

step "one version"
"$ROOT/scripts/version.sh" --check || stop
VERSION="$("$ROOT/scripts/version.sh")"

# --- iOS -------------------------------------------------------------------
# xcframework.sh builds the Apple slices the Swift package ships; the
# macOS slice it also carries is ignored by the iOS SDK.
step "iOS: CSipral.xcframework, through scripts/package/xcframework.sh"
apple_args=(--out "$OUT/apple" --dry-run)
[ "$WITH_OPUS" -eq 1 ] && apple_args+=(--with-opus)
if "$ROOT/scripts/package/xcframework.sh" "${apple_args[@]}" >"$OUT/apple.log" 2>&1; then
    pass "xcframework.sh ${apple_args[*]}"
else
    fail "xcframework.sh ${apple_args[*]}:"
    tail -30 "$OUT/apple.log" | sed 's/^/        /'
    stop
fi
rm -rf "$NATIVES"
mkdir -p "$NATIVES/android"
cp -R "$OUT/apple/CSipral.xcframework" "$NATIVES/"
for slice in ios-arm64 ios-arm64_x86_64-simulator; do
    if [ -f "$NATIVES/CSipral.xcframework/$slice/libsipral_ffi.a" ]; then
        pass "$slice: $(lipo -archs "$NATIVES/CSipral.xcframework/$slice/libsipral_ffi.a")"
    else
        fail "CSipral.xcframework has no $slice slice"
    fi
done

# --- Android ---------------------------------------------------------------
step "Android: libsipral_ffi.so per ABI, with this Mac's NDK, $VARIANT_LABEL"
MIN_SDK="21" # Sipral.Maui.csproj's SupportedOSPlatformVersion for Android
NDK="${ANDROID_NDK_HOME:-}"
if [ -z "$NDK" ] && [ -d "${ANDROID_HOME:-$HOME/Library/Android/sdk}/ndk" ]; then
    NDK=$(ls -d "${ANDROID_HOME:-$HOME/Library/Android/sdk}"/ndk/* 2>/dev/null | sort -V | tail -1)
fi
LLVM="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin"
[ -n "$NDK" ] && [ -x "$LLVM/llvm-ar" ] || { fail "no Android NDK: set ANDROID_NDK_HOME, or install one under ANDROID_HOME/ndk"; stop; }
pass "NDK at $NDK"

# "<Android ABI>:<Rust target>:<NDK clang prefix>:<ELF e_machine>"
ANDROID_ABIS=(
    "arm64-v8a:aarch64-linux-android:aarch64-linux-android:183"
    "armeabi-v7a:armv7-linux-androideabi:armv7a-linux-androideabi:40"
    "x86_64:x86_64-linux-android:x86_64-linux-android:62"
)
installed="$(rustup target list --installed 2>/dev/null || true)"
for entry in "${ANDROID_ABIS[@]}"; do
    IFS=: read -r abi triple clang machine <<<"$entry"
    printf '%s\n' "$installed" | found -x "$triple" || { fail "$triple not installed: rustup target add $triple"; continue; }
    upper=$(printf '%s' "$triple" | tr 'a-z-' 'A-Z_')
    lower=$(printf '%s' "$triple" | tr '-' '_')
    neutral_cargo_args "$triple"
    if env "CARGO_TARGET_${upper}_LINKER=$LLVM/${clang}${MIN_SDK}-clang" \
        "CC_${lower}=$LLVM/${clang}${MIN_SDK}-clang" "AR_${lower}=$LLVM/llvm-ar" \
        cargo build --release -p sipral-ffi "${FFI_FEATURE_ARGS[@]}" --target "$triple" "${NEUTRAL_CARGO_ARGS[@]}" \
        >"$OUT/build-$triple.log" 2>&1; then
        pass "cargo build --release -p sipral-ffi --target $triple"
    else
        fail "cargo build --release -p sipral-ffi --target $triple:"
        tail -30 "$OUT/build-$triple.log" | sed 's/^/        /'
        continue
    fi
    built="${CARGO_TARGET_DIR:-$ROOT/target}/$triple/release/libsipral_ffi.so"
    mkdir -p "$NATIVES/android/$abi"
    "$LLVM/llvm-strip" --strip-unneeded -o "$NATIVES/android/$abi/libsipral_ffi.so" "$built"
    # bytes 18-19 of an ELF header, little-endian: the machine it runs on
    got=$(od -An -tu2 -j18 -N2 "$NATIVES/android/$abi/libsipral_ffi.so" | tr -d ' ')
    if [ "$got" = "$machine" ]; then
        pass "$abi: ELF machine $got, $(wc -c <"$NATIVES/android/$abi/libsipral_ffi.so" | tr -d ' ') bytes"
    else
        fail "$abi: ELF machine $got, expected $machine"
    fi
    neutral_paths_held "android/$abi/libsipral_ffi.so" "$NATIVES/android/$abi/libsipral_ffi.so"
done
printf '%s\n' "$FFI_FEATURES" >"$NATIVES/$FEATURES_MARKER"
[ "$FAIL" -ne 0 ] && stop

if [ "$NATIVES_ONLY" -eq 1 ]; then
    printf '\nmaui.sh: natives in %s\n' "$NATIVES"
    exit 0
fi

# --- the package -----------------------------------------------------------
step "dotnet pack, Sipral.Maui $VERSION"
command -v dotnet >/dev/null 2>&1 || { fail "no .NET SDK"; stop; }
dotnet workload list 2>/dev/null | found -E '^(maui-ios|maui) ' \
    && dotnet workload list 2>/dev/null | found -E '^(maui-android|maui) ' \
    || { fail "the MAUI workloads are missing: dotnet workload install maui-ios maui-android"; stop; }
PACKAGE="$OUT/Sipral.Maui.$VERSION.nupkg"
rm -f "$PACKAGE"
if dotnet pack "$ROOT/bindings/dotnet/Sipral.Maui/Sipral.Maui.csproj" -c Release --nologo \
    -p:SipralNatives="$NATIVES" -o "$OUT" >"$OUT/pack.log" 2>&1 && [ -f "$PACKAGE" ]; then
    pass "Sipral.Maui.$VERSION.nupkg"
else
    fail "dotnet pack:"
    tail -30 "$OUT/pack.log" | sed 's/^/        /'
    stop
fi

step "what the package carries"
listing=$(unzip -Z1 "$PACKAGE")
expect() {
    printf '%s\n' "$listing" | found -E "$1" && pass "$2" || fail "missing: $2"
}
expect '^lib/net10\.0-ios[0-9.]*/Sipral\.dll$' "lib/net10.0-ios/Sipral.dll"
expect '^runtimes/ios/native/CSipral\.xcframework/ios-arm64/libsipral_ffi\.a$' "runtimes/ios/native/CSipral.xcframework, device slice"
expect '^runtimes/ios/native/CSipral\.xcframework/ios-arm64_x86_64-simulator/libsipral_ffi\.a$' "runtimes/ios/native/CSipral.xcframework, simulator slice"
expect '^runtimes/ios/native/CSipral\.xcframework/Info\.plist$' "runtimes/ios/native/CSipral.xcframework/Info.plist"
expect '^buildTransitive/Sipral\.Maui\.targets$' "buildTransitive/Sipral.Maui.targets"
expect '^lib/net10\.0-android[0-9.]*/Sipral\.dll$' "lib/net10.0-android/Sipral.dll"
expect '^runtimes/android-arm64/native/libsipral_ffi\.so$' "runtimes/android-arm64/native/libsipral_ffi.so"
expect '^runtimes/android-arm/native/libsipral_ffi\.so$' "runtimes/android-arm/native/libsipral_ffi.so"
expect '^runtimes/android-x64/native/libsipral_ffi\.so$' "runtimes/android-x64/native/libsipral_ffi.so"
expect '^README\.md$' "README.md"

[ "$FAIL" -ne 0 ] && stop
printf '\nmaui.sh: %s\n' "$PACKAGE"
