#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# The Android artefact: sipral.aar, carrying libsipral_ffi.so (the C ABI) and
# libsipral_jni.so (the two shims in bindings/kotlin/sipral/src/main/jni,
# the generated sipral_jni.c and the hand-written idiomatic_media.c, linked
# against it -- the one a JVM actually loads, per bindings/kotlin/README.md)
# for arm64-v8a, armeabi-v7a and x86_64 under jni/, and the compiled classes
# of everything under bindings/kotlin/sipral/src/main/kotlin over it:
# SipralAbi.kt, org.sipral.idiomatic and org.sipral.telecom.
#
#   scripts/package/aar.sh collect-natives --out DIR
#       needs the Android NDK (ANDROID_NDK_HOME) and cargo-ndk, which the
#       image bindings/kotlin/android/Dockerfile carries and
#       scripts/package/android.sh runs this inside: builds the three ABIs
#       with cargo-ndk, links both shims against each with the same NDK's
#       own clang, and writes DIR/jni/<abi>/libsipral_ffi.so and
#       DIR/jni/<abi>/libsipral_jni.so
#
#   scripts/package/aar.sh assemble --out DIR --natives DIR [--dry-run] [--publish]
#       compiles bindings/kotlin's Kotlin with kotlinc, the same compiler
#       check.sh already requires for it, against the same
#       kotlinx-coroutines jar, checks that each native is an ELF shared
#       object for the machine its directory names, and zips the result
#       into sipral.aar over Android's own archive format (documented at
#       developer.android.com/studio/projects/android-library#aar-contents
#       -- a manifest, classes.jar, jni/<abi>/*.so, nothing Gradle-specific
#       in the format itself). No Gradle project is generated: fetching
#       Gradle and the Android Gradle Plugin from Google's Maven for one
#       packaging script is a standing, multi-gigabyte dependency this
#       repo would then carry, for a build Gradle would not do any
#       differently to the archive spec itself. A consumer adds this file
#       to a Gradle project the same way either route would have produced
#       it: `implementation(files("sipral.aar"))` in an application, or as
#       a local Maven artifact, which is how bindings/kotlin/android's own
#       Gradle build takes it (scripts/package/android.sh writes the POM).
#       Either way the application also depends on kotlinx-coroutines,
#       which an AAR does not carry inside itself.
#
# collect-natives is the only half that needs another machine's toolchain;
# assemble runs anywhere kotlinc does, including with no natives at all
# under --dry-run.
set -uo pipefail

cd "$(dirname "$0")/../.."
ROOT="$PWD"

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
note() { printf '  note  %s\n' "$1"; }
step() { printf '\n%s\n' "$1"; }

ABIS=(arm64-v8a armeabi-v7a x86_64)
# The two natives every ABI directory carries: the C ABI itself, and the JNI
# shim linked against it.
NATIVE_LIBS=(libsipral_ffi.so libsipral_jni.so)
# "<abi>:<NDK clang triple, minus the API suffix MIN_SDK appends>" -- what
# collect-natives links that ABI's shim with, below.
NDK_CLANG_TRIPLE=(arm64-v8a:aarch64-linux-android armeabi-v7a:armv7a-linux-androideabi x86_64:x86_64-linux-android)
# "<abi>:<ELF e_machine>:<ELF class>" -- what a native in that ABI's
# directory has to be, read out of its own ELF header by elf_matches below:
# EM_AARCH64 (183), EM_ARM (40) and EM_X86_64 (62), and 64 or 32 bits.
ELF_EXPECTED=(arm64-v8a:183:64 armeabi-v7a:40:32 x86_64:62:64)

# Whether $1 is an ELF shared object for the machine and word size $2:$3.
# Read from the header's own bytes -- EI_CLASS at 4, e_type at 16, e_machine
# at 18, both little-endian on every ABI here -- so no binutils is needed.
elf_matches() {
    local file="$1" machine="$2" bits="$3"
    local magic class etype emachine
    magic=$(od -An -tx1 -N4 "$file" 2>/dev/null | tr -d ' \n')
    [ "$magic" = "7f454c46" ] || return 1
    class=$(od -An -tu1 -j4 -N1 "$file" | tr -d ' \n')
    etype=$(od -An -tu1 -j16 -N1 "$file" | tr -d ' \n')
    emachine=$(od -An -tu1 -j18 -N2 "$file" | awk '{print $1 + 256 * $2}')
    local want_class=1
    [ "$bits" = "64" ] && want_class=2
    # e_type 3 is ET_DYN, a shared object.
    [ "$class" = "$want_class" ] && [ "$etype" = "3" ] && [ "$emachine" = "$machine" ]
}

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

MIN_SDK="21" # matches AndroidManifest.xml's minSdkVersion, below, and the
             # platform cargo-ndk is told to build against: the floor the
             # NDK's 64-bit ABIs (arm64-v8a, x86_64) require regardless.

if [ "$CMD" = "collect-natives" ]; then
    step "collect-natives, with the NDK at ${ANDROID_NDK_HOME:-(unset)}"
    # The NDK is not fetched here: it comes with the Android SDK licence,
    # which is accepted once, by whoever builds the image
    # (bindings/kotlin/android/Dockerfile), and not on every run of a
    # packaging script.
    LLVM_BIN="${ANDROID_NDK_HOME:-}/toolchains/llvm/prebuilt/linux-x86_64/bin"
    if [ -z "${ANDROID_NDK_HOME:-}" ] || [ ! -d "$LLVM_BIN" ]; then
        fail "no Linux NDK at ANDROID_NDK_HOME; run this through scripts/package/android.sh, whose image carries one"
        printf '\naar.sh: failed\n'; exit 1
    fi
    command -v cargo-ndk >/dev/null 2>&1 || { fail "cargo-ndk not found (cargo install cargo-ndk --locked)"; printf '\naar.sh: failed\n'; exit 1; }

    if cargo ndk --platform "$MIN_SDK" -t arm64-v8a -t armeabi-v7a -t x86_64 -o "$OUT/jni" \
        build --release -p sipral-ffi >"$OUT/collect-natives.log" 2>&1; then
        pass "cargo ndk build --release -p sipral-ffi"
    else
        fail "cargo ndk build:"
        tail -40 "$OUT/collect-natives.log" | sed 's/^/        /'
    fi
    for pair in "${NDK_CLANG_TRIPLE[@]}"; do
        abi="${pair%%:*}"
        clang="$LLVM_BIN/${pair#*:}$MIN_SDK-clang"
        [ -f "$OUT/jni/$abi/libsipral_ffi.so" ] || continue
        if "$clang" -std=c11 -shared -fPIC -O2 -Wall -Wextra -Werror \
            -I"$ROOT/bindings/c/include" \
            -o "$OUT/jni/$abi/libsipral_jni.so" \
            "$ROOT/bindings/kotlin/sipral/src/main/jni/sipral_jni.c" \
            "$ROOT/bindings/kotlin/sipral/src/main/jni/idiomatic_media.c" \
            -L"$OUT/jni/$abi" -lsipral_ffi -Wl,-soname,libsipral_jni.so \
            >>"$OUT/collect-natives.log" 2>&1; then
            pass "$abi: libsipral_jni.so linked against libsipral_ffi.so"
        else
            fail "$abi: linking the JNI shims:"
            tail -20 "$OUT/collect-natives.log" | sed 's/^/        /'
        fi
    done
    step "structure"
    for abi in "${ABIS[@]}"; do
        expected=""
        for e in "${ELF_EXPECTED[@]}"; do [ "${e%%:*}" = "$abi" ] && expected="${e#*:}"; done
        for lib in "${NATIVE_LIBS[@]}"; do
            f="$OUT/jni/$abi/$lib"
            if [ ! -f "$f" ]; then
                fail "jni/$abi/$lib was not produced"
            elif elf_matches "$f" "${expected%%:*}" "${expected#*:}"; then
                size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null)
                pass "jni/$abi/$lib ($size bytes, ELF machine ${expected%%:*}, ${expected#*:}-bit)"
            else
                fail "jni/$abi/$lib is not an ELF shared object for machine ${expected%%:*}, ${expected#*:}-bit"
            fi
        done
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
# org.sipral.idiomatic is compiled against kotlinx-coroutines-core-jvm, from
# the same cache scripts/check.sh reads it from (THIRD-PARTY-NOTICES.md says
# where it comes from and its checksum). It is compiled against, not packed
# in: an application depending on this AAR brings the library itself, the
# way it brings any other Maven dependency.
COROUTINES_JAR="${SIPRAL_COROUTINES_JAR:-$HOME/.cache/sipral/maven/org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/1.11.0/kotlinx-coroutines-core-jvm-1.11.0.jar}"
if ! command -v kotlinc >/dev/null 2>&1; then
    fail "kotlinc not found (brew install kotlin)"
elif [ ! -s "$COROUTINES_JAR" ]; then
    fail "kotlinx-coroutines-core-jvm is not at $COROUTINES_JAR (THIRD-PARTY-NOTICES.md says how to fetch it; SIPRAL_COROUTINES_JAR names another path)"
else
    kt_sources=()
    while IFS= read -r -d '' f; do kt_sources+=("$f"); done \
        < <(find "$ROOT/bindings/kotlin/sipral/src/main/kotlin" -name '*.kt' -print0)
    if [ "${#kt_sources[@]}" -eq 0 ]; then
        fail "no Kotlin source found under bindings/kotlin/sipral/src/main/kotlin"
    else
        mkdir -p "$STAGE/classes"
        # The language and API version the classes are compiled for, which
        # is also the Kotlin metadata version they carry. A consumer's
        # compiler reads metadata at most one version ahead of its own, so
        # classes compiled for kotlinc's own 2.4 would not compile against
        # the Kotlin 2.2 the Android Gradle Plugin 9 builds with unless told
        # otherwise. 2.2 is the oldest kotlinc 2.4 does not call deprecated,
        # and Kotlin 2.1 and later read it.
        KOTLIN_TARGET="2.2"
        if kotlinc -language-version "$KOTLIN_TARGET" -api-version "$KOTLIN_TARGET" -cp "$COROUTINES_JAR" \
            "${kt_sources[@]}" -d "$STAGE/classes" >"$STAGE/kotlinc.log" 2>&1; then
            ( cd "$STAGE/classes" && jar cf "$STAGE/aar/classes.jar" . )
            pass "kotlinc for Kotlin $KOTLIN_TARGET, then jar cf classes.jar"
            metadata=$(javap -v -cp "$STAGE/classes" org.sipral.Sipral 2>/dev/null \
                | sed -n 's/^ *mv=\[\([0-9]*\),\([0-9]*\),.*/\1.\2/p' | head -1)
            [ "$metadata" = "$KOTLIN_TARGET" ] \
                && pass "org.sipral.Sipral carries Kotlin metadata $metadata" \
                || fail "org.sipral.Sipral carries Kotlin metadata '${metadata}', not $KOTLIN_TARGET"
        else
            fail "kotlinc, bindings/kotlin/sipral/src/main/kotlin:"
            tail -30 "$STAGE/kotlinc.log" | sed 's/^/        /'
        fi
    fi
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
    <!-- 21: the platform collect-natives builds the natives against
         (MIN_SDK in aar.sh). Changing one without the other would claim a
         floor the native libraries were not built for. -->
    <uses-sdk android:minSdkVersion="21" />
</manifest>
EOF
pass "AndroidManifest.xml"

# The consumer keep rules an AAR carries as proguard.txt, which R8 applies to
# any application that shrinks: the three listener keepers are reached only
# from native code, by name, through FindClass and GetStaticMethodID in
# sipral_jni.c's JNI_OnLoad, and every external fun's name is what the
# shims' exported symbols are spelled from. Nothing in Kotlin calls
# `deliver`, so without these a release build removes or renames it and the
# first event finds nothing to land in.
cat >"$STAGE/aar/proguard.txt" <<'EOF'
-keep class org.sipral.SipralEventListeners { *** deliver(...); }
-keep class org.sipral.SipralScreenListeners { *** deliver(...); }
-keep class org.sipral.SipralProcessorListeners { *** deliver(...); }
-keepclasseswithmembernames class org.sipral.** { native <methods>; }
EOF
pass "proguard.txt"

step "natives, from $NATIVES"
populated=0
for abi in "${ABIS[@]}"; do
    dest="$STAGE/aar/jni/$abi"
    mkdir -p "$dest"
    have=0
    for lib in "${NATIVE_LIBS[@]}"; do
        [ -f "$NATIVES/jni/$abi/$lib" ] && have=$((have + 1))
    done
    if [ "$have" -eq "${#NATIVE_LIBS[@]}" ]; then
        expected=""
        for e in "${ELF_EXPECTED[@]}"; do [ "${e%%:*}" = "$abi" ] && expected="${e#*:}"; done
        wrong=""
        for lib in "${NATIVE_LIBS[@]}"; do
            elf_matches "$NATIVES/jni/$abi/$lib" "${expected%%:*}" "${expected#*:}" || wrong="$wrong $lib"
            cp "$NATIVES/jni/$abi/$lib" "$dest/$lib"
        done
        if [ -z "$wrong" ]; then
            pass "$abi (ELF machine ${expected%%:*}, ${expected#*:}-bit, both libraries)"
            populated=$((populated + 1))
        else
            fail "$abi:$wrong not an ELF shared object for machine ${expected%%:*}, ${expected#*:}-bit"
        fi
    elif [ "$have" -eq 0 ] && [ "$DRY_RUN" -eq 1 ]; then
        note "$abi: no native staged, layout only (jni/$abi/ created empty)"
    elif [ "$have" -eq 0 ]; then
        fail "$abi: no native at $NATIVES/jni/$abi/ (run collect-natives first)"
    else
        # A shim without the ABI it calls into, or the reverse, is a native
        # nothing can load -- worse than shipping neither, so this fails
        # even under --dry-run rather than passing as partial layout.
        fail "$abi: only some of ${NATIVE_LIBS[*]} staged at $NATIVES/jni/$abi/ (run collect-natives again)"
    fi
done
[ "$FAIL" -ne 0 ] && { printf '\naar.sh: failed\n'; exit 1; }
[ "$populated" -eq 0 ] && [ "$DRY_RUN" -eq 0 ] && { fail "no ABI had its natives staged"; printf '\naar.sh: failed\n'; exit 1; }

step "the archive"
AAR="$OUT/sipral.aar"
rm -f "$AAR"
( cd "$STAGE/aar" && zip -qr "$AAR" . ) && pass "sipral.aar" || fail "zip -qr sipral.aar"

if [ -f "$AAR" ]; then
    listing=$(unzip -l "$AAR" 2>/dev/null)
    for entry in AndroidManifest.xml classes.jar proguard.txt; do
        printf '%s\n' "$listing" | grep -q "$entry" && pass "carries $entry" || fail "missing $entry"
    done
    # One class from each layer: the printed binding, the idiomatic layer
    # and the telecom helper's logic. A classes.jar that compiled but lost
    # a package would otherwise pass as "present".
    classes=$(unzip -l "$STAGE/aar/classes.jar" 2>/dev/null)
    for class in org/sipral/SipralNative.class org/sipral/idiomatic/SipralClient.class \
        org/sipral/telecom/TelecomBridge.class; do
        printf '%s\n' "$classes" | grep -q " $class\$" \
            && pass "classes.jar carries $class" || fail "classes.jar is missing $class"
    done
    for abi in "${ABIS[@]}"; do
        for lib in "${NATIVE_LIBS[@]}"; do
            [ -f "$NATIVES/jni/$abi/$lib" ] || continue
            printf '%s\n' "$listing" | grep -q "jni/$abi/$lib" \
                && pass "carries jni/$abi/$lib" \
                || fail "missing jni/$abi/$lib"
        done
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
