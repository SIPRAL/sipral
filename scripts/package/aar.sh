#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# The Android artefact: sipral.aar, carrying libsipral_ffi.so for
# arm64-v8a, armeabi-v7a and x86_64 under jni/, and SipralAbi.kt's and
# sipral_jni.c's compiled classes over it.
#
#   scripts/package/aar.sh collect-natives --out DIR
#       needs Docker: builds the three ABIs with cargo-ndk inside a
#       container that installs the Android NDK itself (neither ships on
#       this workspace's machines), and writes
#       DIR/jni/<abi>/libsipral_ffi.so
#
#   scripts/package/aar.sh assemble --out DIR --natives DIR [--dry-run] [--publish]
#       compiles bindings/kotlin's two printed files with kotlinc, the same
#       compiler check.sh already requires for them, and zips the result
#       into sipral.aar over Android's own archive format (documented at
#       developer.android.com/studio/projects/android-library#aar-contents
#       -- a manifest, classes.jar, jni/<abi>/*.so, nothing Gradle-specific
#       in the format itself). No Gradle project is generated: fetching
#       Gradle and the Android Gradle Plugin from Google's Maven for one
#       packaging script is a standing, multi-gigabyte dependency this
#       repo would then carry, for a build Gradle would not do any
#       differently to the archive spec itself. A consumer adds this file
#       to a Gradle project the same way either route would have produced
#       it: `implementation(files("sipral.aar"))`, or as a local Maven
#       artifact.
#
# collect-natives is the only half that needs another machine; assemble
# runs anywhere kotlinc does, including with no natives at all under
# --dry-run.
set -uo pipefail

cd "$(dirname "$0")/../.."
ROOT="$PWD"

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
note() { printf '  note  %s\n' "$1"; }
step() { printf '\n%s\n' "$1"; }

ABIS=(arm64-v8a armeabi-v7a x86_64)

CMD="${1:-}"
[ $# -ge 1 ] && shift
case "$CMD" in
    collect-natives|assemble) ;;
    *) printf 'usage: aar.sh collect-natives --out DIR\n' >&2
       printf '       aar.sh assemble --out DIR --natives DIR [--dry-run] [--publish]\n' >&2
       exit 2 ;;
esac

OUT=""
NATIVES=""
DRY_RUN=0
PUBLISH=0
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --natives) NATIVES="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --publish) PUBLISH=1; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -z "$OUT" ] && { printf '%s needs --out DIR\n' "$CMD" >&2; exit 2; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

NDK_VERSION="r30" # developer.android.com/ndk/downloads, checked 2026-09-23

if [ "$CMD" = "collect-natives" ]; then
    step "collect-natives, via Docker"
    command -v docker >/dev/null 2>&1 || { fail "docker not found"; printf '\naar.sh: failed\n'; exit 1; }
    RUSTC_VERSION=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml")
    if docker run --rm -v "$ROOT:/work:ro" -v "$OUT:/out" -w /work \
        -e CARGO_TARGET_DIR=/tmp/target \
        rust:1.95-trixie \
        bash -c "set -eu
            rustup toolchain install $RUSTC_VERSION --profile minimal >/tmp/rustup.log 2>&1
            rustup default $RUSTC_VERSION >>/tmp/rustup.log 2>&1
            rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android >>/tmp/rustup.log 2>&1
            apt-get update -qq && apt-get install -qq -y --no-install-recommends unzip cmake >/dev/null
            cd /opt
            curl -fsSL -o ndk.zip https://dl.google.com/android/repository/android-ndk-$NDK_VERSION-linux.zip
            unzip -q ndk.zip && rm ndk.zip
            export ANDROID_NDK_HOME=/opt/android-ndk-$NDK_VERSION
            cargo install --quiet cargo-ndk --locked
            cd /work
            cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o /out/jni build --release -p sipral-ffi" \
        >"$OUT/collect-natives.log" 2>&1; then
        pass "container run"
    else
        fail "container run:"
        tail -40 "$OUT/collect-natives.log" | sed 's/^/        /'
    fi
    step "structure"
    for abi in "${ABIS[@]}"; do
        f="$OUT/jni/$abi/libsipral_ffi.so"
        if [ -f "$f" ]; then
            size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null)
            pass "jni/$abi/libsipral_ffi.so ($size bytes)"
        else
            fail "jni/$abi/libsipral_ffi.so was not produced"
        fi
    done
    printf '\n'
    [ "$FAIL" -eq 0 ] && { printf 'aar.sh collect-natives: done, %s\n' "$OUT"; exit 0; }
    printf 'aar.sh collect-natives: failed\n'; exit 1
fi

# assemble
[ -z "$NATIVES" ] && { printf 'assemble needs --natives DIR\n' >&2; exit 2; }

STAGE="$OUT/_stage"
rm -rf "$STAGE"
mkdir -p "$STAGE/aar"

step "classes, from bindings/kotlin"
if command -v kotlinc >/dev/null 2>&1; then
    kt_sources=()
    while IFS= read -r -d '' f; do kt_sources+=("$f"); done \
        < <(find "$ROOT/bindings/kotlin/sipral/src/main/kotlin" -name '*.kt' -print0)
    if [ "${#kt_sources[@]}" -eq 0 ]; then
        fail "no Kotlin source found under bindings/kotlin/sipral/src/main/kotlin"
    else
        mkdir -p "$STAGE/classes"
        if kotlinc "${kt_sources[@]}" -d "$STAGE/classes" >"$STAGE/kotlinc.log" 2>&1; then
            ( cd "$STAGE/classes" && jar cf "$STAGE/aar/classes.jar" . )
            pass "kotlinc, then jar cf classes.jar"
        else
            fail "kotlinc, bindings/kotlin/sipral/src/main/kotlin:"
            tail -30 "$STAGE/kotlinc.log" | sed 's/^/        /'
        fi
    fi
else
    fail "kotlinc not found (brew install kotlin)"
fi
[ "$FAIL" -ne 0 ] && { printf '\naar.sh: failed\n'; exit 1; }

step "the manifest"
# The minimum Android's own archive format asks for; no activity, no
# permission, nothing this library has an opinion about -- a consumer's
# own manifest carries those. developer.android.com/studio/projects/
# android-library#aar-contents lists this as the whole requirement.
cat >"$STAGE/aar/AndroidManifest.xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.sipral">
    <!-- 21: what collect-natives' `cargo ndk` built the three .so's against
         (its own default -- neither subcommand here names a platform, so
         changing this without changing that would claim a floor the native
         library was not actually built for). -->
    <uses-sdk android:minSdkVersion="21" />
</manifest>
EOF
pass "AndroidManifest.xml"

step "natives, from $NATIVES"
populated=0
for abi in "${ABIS[@]}"; do
    src="$NATIVES/jni/$abi/libsipral_ffi.so"
    dest="$STAGE/aar/jni/$abi"
    mkdir -p "$dest"
    if [ -f "$src" ]; then
        cp "$src" "$dest/libsipral_ffi.so"
        pass "$abi"
        populated=$((populated + 1))
    elif [ "$DRY_RUN" -eq 1 ]; then
        note "$abi: no native staged, layout only (jni/$abi/ created empty)"
    else
        fail "$abi: no native at $src (run collect-natives first)"
    fi
done
[ "$FAIL" -ne 0 ] && { printf '\naar.sh: failed\n'; exit 1; }
[ "$populated" -eq 0 ] && [ "$DRY_RUN" -eq 0 ] && { fail "no ABI had a native staged"; printf '\naar.sh: failed\n'; exit 1; }

step "the archive"
AAR="$OUT/sipral.aar"
rm -f "$AAR"
( cd "$STAGE/aar" && zip -qr "$AAR" . ) && pass "sipral.aar" || fail "zip -qr sipral.aar"

if [ -f "$AAR" ]; then
    listing=$(unzip -l "$AAR" 2>/dev/null)
    for entry in AndroidManifest.xml classes.jar; do
        printf '%s\n' "$listing" | grep -q "$entry" && pass "carries $entry" || fail "missing $entry"
    done
    for abi in "${ABIS[@]}"; do
        [ -f "$NATIVES/jni/$abi/libsipral_ffi.so" ] || continue
        printf '%s\n' "$listing" | grep -q "jni/$abi/libsipral_ffi.so" \
            && pass "carries jni/$abi/libsipral_ffi.so" \
            || fail "missing jni/$abi/libsipral_ffi.so"
    done
fi

if [ "$PUBLISH" -eq 1 ]; then
    step "publish"
    printf '  not run: nothing ships to Maven before the ABI freezes (docs/08-ffi.md).\n'
    printf '  What the owner runs once it has a Maven host: publish %s\n' "$AAR"
    printf '  through that host'"'"'s usual upload (a Maven repository publish, or\n'
    printf '  `gradle publish` once a Gradle project wraps it).\n'
fi

printf '\n'
[ "$FAIL" -eq 0 ] && { printf 'aar.sh assemble: done, %s\n' "$AAR"; exit 0; }
printf 'aar.sh assemble: failed\n'; exit 1
