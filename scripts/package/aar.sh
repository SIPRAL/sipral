#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# The Android artefact: sipral.aar, carrying libsipral_ffi.so (the C ABI) and
# libsipral_jni.so (the three shims in bindings/kotlin/sipral/src/main/jni,
# the generated sipral_jni.c and the hand-written idiomatic_media.c and
# audio_routes.c, linked against it -- the one a JVM actually loads, per
# bindings/kotlin/README.md)
# for arm64-v8a, armeabi-v7a and x86_64 under jni/, and the compiled classes
# of everything under bindings/kotlin/sipral/src/main/kotlin over it:
# SipralAbi.kt, org.sipral.idiomatic and org.sipral.telecom.
#
#   scripts/package/aar.sh collect-natives --out DIR
#       needs the Android NDK (ANDROID_NDK_HOME) and cargo-ndk, which the
#       image bindings/kotlin/android/Dockerfile carries and
#       scripts/package/android.sh runs this inside: builds the three ABIs
#       with cargo-ndk, links the shims against each with the same NDK's
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
#
# Beside the archive, assemble writes what a Maven repository publishes with
# it: sipral(-opus)-<version>.pom, carrying the name, description, URL, both
# licences, the developer, the SCM and the one dependency an AAR cannot
# carry inside itself, and sipral(-opus)-<version>-sources.jar. The group id
# is bindings/jvm/pom.xml's `sipral.groupId`, the same one the JVM jar
# publishes under, or SIPRAL_GROUP_ID when that names another. classes.jar
# carries the licence texts under META-INF/sipral/.
#
# Both take --with-opus, for the variant that carries libopus. Without it,
# collect-natives builds without sipral-ffi's `opus` feature and every other
# default kept (features.sh says why and how), and writes the list it built
# with to DIR/sipral-ffi.features; assemble refuses natives whose list is
# missing or is not the one its own --with-opus (or its absence) asks for,
# and writes the variant with libopus as sipral-opus.aar rather than
# sipral.aar.
set -uo pipefail

# found [GREP OPTIONS] PATTERN: whether standard input has a line PATTERN
# matches, read to its end. `grep -q` stops at the first match, and under
# pipefail whatever is still writing into the pipe then dies of SIGPIPE and
# fails the pipeline: a match read as none, and more often the busier the
# machine. A gate run in parallel lost classes.jar's first entries that way.
found() { grep "$@" >/dev/null; }

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
    *) printf 'usage: aar.sh collect-natives --out DIR [--with-opus]\n' >&2
       printf '       aar.sh assemble --out DIR --natives DIR [--dry-run] [--publish] [--with-opus]\n' >&2
       exit 2 ;;
esac

OUT=""
NATIVES=""
DRY_RUN=0
PUBLISH=0
WITH_OPUS=0
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --natives) NATIVES="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --publish) PUBLISH=1; shift ;;
        --with-opus) WITH_OPUS=1; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -z "$OUT" ] && { printf '%s needs --out DIR\n' "$CMD" >&2; exit 2; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
. "$ROOT/scripts/package/features.sh"
package_features "$WITH_OPUS" || { printf 'no default feature list in crates/sipral-ffi/Cargo.toml\n' >&2; exit 1; }

MIN_SDK="21" # matches AndroidManifest.xml's minSdkVersion, below, and the
             # platform cargo-ndk is told to build against: the floor the
             # NDK's 64-bit ABIs (arm64-v8a, x86_64) require regardless.

if [ "$CMD" = "collect-natives" ]; then
    step "collect-natives, with the NDK at ${ANDROID_NDK_HOME:-(unset)}, $VARIANT_LABEL (features $FFI_FEATURES)"
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

    rm -f "$OUT/$FEATURES_MARKER"
    if cargo ndk --platform "$MIN_SDK" -t arm64-v8a -t armeabi-v7a -t x86_64 -o "$OUT/jni" \
        build --release -p sipral-ffi "${FFI_FEATURE_ARGS[@]}" >"$OUT/collect-natives.log" 2>&1; then
        printf '%s\n' "$FFI_FEATURES" >"$OUT/$FEATURES_MARKER"
        pass "cargo ndk build --release -p sipral-ffi ${FFI_FEATURE_ARGS[*]}"
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
            "$ROOT/bindings/kotlin/sipral/src/main/jni/audio_routes.c" \
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

step "one version"
"$ROOT/scripts/version.sh" --check || { printf '\naar.sh: failed\n'; exit 1; }
AAR_VERSION="$("$ROOT/scripts/version.sh")"

STAGE="$OUT/_stage"
rm -rf "$STAGE"
mkdir -p "$STAGE/aar"

# What every artefact carrying the natives carries beside them, as
# bindings/jvm/pom.xml puts them in the JVM jar. Under a directory of their
# own rather than at META-INF/ itself: the Android Gradle Plugin leaves
# META-INF/LICENSE out of an APK by default, and two libraries' files at one
# path stop the application's build.
LICENCE_FILES=(LICENSE LICENSE-COMMERCIAL.md THIRD-PARTY-LICENSES.txt THIRD-PARTY-NOTICES.md)
LICENCE_DIR="META-INF/sipral"

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
            mkdir -p "$STAGE/classes/$LICENCE_DIR"
            for f in "${LICENCE_FILES[@]}"; do cp "$ROOT/$f" "$STAGE/classes/$LICENCE_DIR/$f"; done
            ( cd "$STAGE/classes" && jar cf "$STAGE/aar/classes.jar" . )
            pass "kotlinc for Kotlin $KOTLIN_TARGET, then jar cf classes.jar, the licence texts under $LICENCE_DIR/"
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

step "natives, from $NATIVES, $VARIANT_LABEL"
# Only when a native is staged at all, so that --dry-run over an empty
# directory still proves the layout; and then even under --dry-run, because
# natives of the other variant under this archive's name are the one mistake
# the name exists to prevent.
staged=$(find "$NATIVES/jni" -name '*.so' 2>/dev/null | head -1)
built_with=$(cat "$NATIVES/$FEATURES_MARKER" 2>/dev/null)
if [ -n "$staged" ] && [ "$built_with" != "$FFI_FEATURES" ]; then
    fail "the natives in $NATIVES were built with features '${built_with:-(no $FEATURES_MARKER beside them)}', not '$FFI_FEATURES'"
    printf '\naar.sh: failed\n'; exit 1
fi
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
AAR="$OUT/sipral$VARIANT_SUFFIX.aar"
rm -f "$AAR"
( cd "$STAGE/aar" && zip -qr "$AAR" . ) && pass "$(basename "$AAR")" || fail "zip -qr $(basename "$AAR")"

if [ -f "$AAR" ]; then
    listing=$(unzip -l "$AAR" 2>/dev/null)
    for entry in AndroidManifest.xml classes.jar proguard.txt; do
        printf '%s\n' "$listing" | found "$entry" && pass "carries $entry" || fail "missing $entry"
    done
    # One class from each layer: the printed binding, the idiomatic layer
    # and the telecom helper's logic. A classes.jar that compiled but lost
    # a package would otherwise pass as "present".
    classes=$(unzip -l "$STAGE/aar/classes.jar" 2>/dev/null)
    for class in org/sipral/SipralNative.class org/sipral/idiomatic/SipralClient.class \
        org/sipral/telecom/TelecomBridge.class; do
        printf '%s\n' "$classes" | found " $class\$" \
            && pass "classes.jar carries $class" || fail "classes.jar is missing $class"
    done
    for f in "${LICENCE_FILES[@]}"; do
        printf '%s\n' "$classes" | found " $LICENCE_DIR/$f\$" \
            && pass "classes.jar carries $LICENCE_DIR/$f" || fail "classes.jar is missing $LICENCE_DIR/$f"
    done
    for abi in "${ABIS[@]}"; do
        for lib in "${NATIVE_LIBS[@]}"; do
            [ -f "$NATIVES/jni/$abi/$lib" ] || continue
            printf '%s\n' "$listing" | found "jni/$abi/$lib" \
                && pass "carries jni/$abi/$lib" \
                || fail "missing jni/$abi/$lib"
        done
    done
fi

if [ -f "$AAR" ]; then
    step "for a Maven repository"
    ARTIFACT_ID="sipral$VARIANT_SUFFIX"
    GROUP_ID="${SIPRAL_GROUP_ID:-$(sed -n 's|.*<sipral.groupId>\(.*\)</sipral.groupId>.*|\1|p' "$ROOT/bindings/jvm/pom.xml")}"
    POM="$OUT/$ARTIFACT_ID-$AAR_VERSION.pom"
    COROUTINES_VERSION=$(sed -n 's|.*<coroutines.version>\(.*\)</coroutines.version>.*|\1|p' "$ROOT/bindings/jvm/pom.xml")
    cat >"$POM" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>$GROUP_ID</groupId>
  <artifactId>$ARTIFACT_ID</artifactId>
  <version>$AAR_VERSION</version>
  <packaging>aar</packaging>
  <name>Sipral for Android</name>
  <description>Sipral - Session Initiation Protocol Rust Audio Layer. The Kotlin binding for Android, with the native libraries for arm64-v8a, armeabi-v7a and x86_64 inside the archive; $VARIANT_LABEL.</description>
  <url>https://sipral.org</url>
  <licenses>
    <license>
      <name>AGPL-3.0-only</name>
      <url>https://www.gnu.org/licenses/agpl-3.0.txt</url>
      <distribution>repo</distribution>
    </license>
    <license>
      <name>LicenseRef-Sipral-Commercial</name>
      <url>https://github.com/SIPRAL/sipral/blob/main/LICENSE-COMMERCIAL.md</url>
      <distribution>repo</distribution>
    </license>
  </licenses>
  <developers>
    <developer>
      <name>Sytek</name>
      <organization>Sytek</organization>
      <organizationUrl>https://sytek.ro</organizationUrl>
    </developer>
  </developers>
  <scm>
    <url>https://github.com/SIPRAL/sipral</url>
    <connection>scm:git:https://github.com/SIPRAL/sipral.git</connection>
  </scm>
  <dependencies>
    <dependency>
      <groupId>org.jetbrains.kotlinx</groupId>
      <artifactId>kotlinx-coroutines-core</artifactId>
      <version>$COROUTINES_VERSION</version>
      <scope>runtime</scope>
    </dependency>
  </dependencies>
</project>
EOF
    if [ -z "$GROUP_ID" ] || [ -z "$COROUTINES_VERSION" ]; then
        fail "bindings/jvm/pom.xml names no sipral.groupId or coroutines.version to write the POM from"
    elif ! command -v xmllint >/dev/null 2>&1; then
        # android.sh's image has no libxml2; the template above is the one
        # every --dry-run of this script on the Mac lints
        note "$(basename "$POM"): $GROUP_ID:$ARTIFACT_ID:$AAR_VERSION, not linted (no xmllint on this host)"
    elif xmllint --noout "$POM" 2>"$STAGE/pom-lint.log"; then
        pass "$(basename "$POM"): $GROUP_ID:$ARTIFACT_ID:$AAR_VERSION"
    else
        fail "$(basename "$POM") is not well-formed:"; sed 's/^/        /' "$STAGE/pom-lint.log"
    fi
    SOURCES="$OUT/$ARTIFACT_ID-$AAR_VERSION-sources.jar"
    rm -f "$SOURCES"
    if ( cd "$ROOT/bindings/kotlin/sipral/src/main/kotlin" && jar cf "$SOURCES" . ); then
        pass "$(basename "$SOURCES")"
    else
        fail "jar cf $(basename "$SOURCES")"
    fi
fi

# The SBOM sits beside sipral(.opus).aar, from sipral-ffi's own dependency
# graph across every ABI this one archive carries (docs/10-roadmap.md).
# --notices only for the variant whose feature list is
# THIRD-PARTY-LICENSES.txt's own (no flags at all, opus included).
if [ -f "$AAR" ]; then
    step "SBOM"
    SBOM_ARGS=(--crate sipral-ffi --features "$FFI_FEATURES" --target all \
        --artifact-name "sipral$VARIANT_SUFFIX" --artifact-version "$AAR_VERSION" \
        --artifact "$AAR" --out "$AAR.cdx.json")
    [ "$WITH_OPUS" -eq 1 ] && SBOM_ARGS+=(--notices "$ROOT/THIRD-PARTY-LICENSES.txt")
    if sbom_out=$(cargo run --quiet -p sipral-sbom-gen -- "${SBOM_ARGS[@]}" 2>&1); then
        pass "$(basename "$AAR").cdx.json"
    else
        fail "sbom-gen:"; printf '%s\n' "$sbom_out" | sed 's/^/        /'
    fi
fi

if [ "$PUBLISH" -eq 1 ] && [ -f "$AAR" ]; then
    step "publish"
    printf '  not run: the owner publishes. To a Maven repository, signed, as\n'
    printf '  %s:%s:%s:\n' "$GROUP_ID" "$ARTIFACT_ID" "$AAR_VERSION"
    printf '    %s (as %s-%s.aar)\n' "$AAR" "$ARTIFACT_ID" "$AAR_VERSION"
    printf '    %s\n' "$POM" "$SOURCES"
    printf '  docs/11-testing.md, "Releasing", says what Maven Central asks beyond these.\n'
fi

printf '\n'
[ "$FAIL" -eq 0 ] && { printf 'aar.sh assemble: done, %s, %s\n' "$AAR" "$VARIANT_LABEL"; exit 0; }
printf 'aar.sh assemble: failed\n'; exit 1
