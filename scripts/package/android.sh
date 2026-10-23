#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# Everything Android, built for real inside the image
# bindings/kotlin/android/Dockerfile describes:
#
#   sipral.aar            scripts/package/aar.sh collect-natives + assemble:
#                         libsipral_ffi.so and libsipral_jni.so for
#                         arm64-v8a, armeabi-v7a and x86_64, and the
#                         binding's classes
#   sipral-telecom.aar    the telecom helper (ConnectionService and Core-Telecom
#                         adapters), by Gradle
#   sipral-sample.apk     the Compose sample, by Gradle (debug-signed)
#
# and then each of the three opened and checked: both natives in every ABI
# directory, each an ELF shared object for the machine that directory names,
# needing nothing a device does not have; the classes each is supposed to
# carry; the service and permission the helper's manifest declares. Before
# that, the helper's and the sample's unit tests run, and every artefact
# Gradle resolved for the helper, the sample and those tests is held to
# deny.toml's licences.
#
# With --release, the sample is also built for a store, unsigned:
#
#   sipral-sample-release-unsigned.apk   to install directly once signed
#   sipral-sample-release-unsigned.aab   to upload to Google Play once signed
#
# each checked like the debug APK, and for what a store asks besides: not
# debuggable, the target API level, and every 64-bit native aligned for 16 KB
# pages (each ELF LOAD segment, and the APK's uncompressed libraries). Neither is
# signed here: scripts/package/android-sign.sh signs them on the machine
# that holds the key, so the key never enters the build image or the
# machine it runs on. --version-code N sets the version code a store upload
# needs to be higher than the last one; without it the code is derived from
# the workspace version (sample/build.gradle.kts).
#
#   scripts/package/android.sh --out DIR --accept-android-sdk-licenses [--with-opus] [--release [--version-code N]]
#   scripts/package/android.sh --out DIR --dry-run [--with-opus]
#
# --dry-run installs nothing and needs no Docker, so it asks for no licence:
# it runs aar.sh assemble --dry-run on this host (the classes, the manifest,
# the archive's layout with no native in it, the POM and the sources jar) and
# checks that the Gradle build the image would run is pinned. The natives,
# the telecom helper, the sample and their checks are the image's, and the
# run says so.
#
# Without --with-opus the natives are built without sipral-ffi's `opus`
# feature and every other default kept (scripts/package/features.sh says why
# and how); with it, aar.sh builds the variant that carries libopus, and the
# two artefacts that carry natives are sipral-opus.aar and
# sipral-sample-opus.apk (and sipral-sample-opus-release-unsigned.apk and
# .aab, version name 1.2.3-opus). The local Maven repository the helper and the
# sample build against keeps the coordinate org.sipral:sipral either way,
# with the variant named in its POM's description.
#
# It needs Docker, and nothing else on the host. The flag is not a formality:
# the image installs Android SDK packages, which are under the Android SDK
# licence (developer.android.com/studio/terms), and passing it is the person
# running this accepting that licence -- this script never accepts it on
# anybody's behalf. Caches live in two Docker volumes
# (sipral-android-cargo, sipral-android-gradle), so a second run builds
# only what changed; `docker volume rm` them to start clean.
#
# No emulator run: nothing here needs /dev/kvm. What the telecom framework
# itself does with a self-managed call is observable only with the APK
# running, and docs/15-mobile.md says how it was run on an emulator and
# what was seen; audio routing and push delivery need a phone.
set -uo pipefail

cd "$(dirname "$0")/../.."
ROOT="$PWD"

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
step() { printf '\n%s\n' "$1"; }

usage() {
    printf 'usage: android.sh --out DIR --accept-android-sdk-licenses [--with-opus] [--release [--version-code N]]\n' >&2
    printf '       android.sh --out DIR --dry-run [--with-opus]\n' >&2
    exit 2
}

MODE="host"
if [ "${1:-}" = "inside" ]; then
    MODE="inside"
    shift
fi

OUT=""
ACCEPTED=0
IMAGE="sipral-android-build"
WITH_OPUS=0
DRY_RUN=0
RELEASE=0
VERSION_CODE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --accept-android-sdk-licenses) ACCEPTED=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --image) IMAGE="$2"; shift 2 ;;
        --with-opus) WITH_OPUS=1; shift ;;
        --release) RELEASE=1; shift ;;
        --version-code) VERSION_CODE="$2"; shift 2 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; usage ;;
    esac
done
[ -z "$OUT" ] && usage
if [ -n "$VERSION_CODE" ]; then
    [ "$RELEASE" -eq 1 ] || { printf -- '--version-code is for a --release build\n' >&2; usage; }
    case "$VERSION_CODE" in
        '' | *[!0-9]*) printf -- '--version-code takes a positive number\n' >&2; usage ;;
    esac
fi
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
. "$ROOT/scripts/package/features.sh"
package_features "$WITH_OPUS" || { printf 'no default feature list in crates/sipral-ffi/Cargo.toml\n' >&2; exit 1; }
# What aar.sh is told, and the names of the two artefacts that carry natives.
# Expanded as ${VARIANT_ARGS[@]+...}: bash 3.2 under `set -u` calls an empty
# array unbound.
VARIANT_ARGS=()
[ "$WITH_OPUS" -eq 1 ] && VARIANT_ARGS=(--with-opus)
AAR_NAME="sipral$VARIANT_SUFFIX.aar"
APK_NAME="sipral-sample$VARIANT_SUFFIX.apk"
RELEASE_APK="sipral-sample$VARIANT_SUFFIX-release-unsigned.apk"
RELEASE_AAB="sipral-sample$VARIANT_SUFFIX-release-unsigned.aab"
# What the image's own run is told on top of the variant, and what Gradle is.
INSIDE_ARGS=(${VARIANT_ARGS[@]+"${VARIANT_ARGS[@]}"})
[ "$RELEASE" -eq 1 ] && INSIDE_ARGS+=(--release)
[ -n "$VERSION_CODE" ] && INSIDE_ARGS+=(--version-code "$VERSION_CODE")
GRADLE_PROPS=()
[ "$WITH_OPUS" -eq 1 ] && GRADLE_PROPS+=(-Psipral.variant=opus)
[ -n "$VERSION_CODE" ] && GRADLE_PROPS+=(-Psipral.versionCode="$VERSION_CODE")

VERSION=$(awk -F'"' '/^\[workspace.package\]/{p=1} p && /^version = /{print $2; exit}' "$ROOT/Cargo.toml")
ABIS=(arm64-v8a armeabi-v7a x86_64)
# "<abi>:<ELF e_machine>:<ELF class>", as in aar.sh.
ELF_EXPECTED=(arm64-v8a:183:64 armeabi-v7a:40:32 x86_64:62:64)
# What a native here may need from the device: Bionic's own libraries, and
# the other native beside it. Anything else -- libc++_shared.so, most
# likely -- would have to ship in the archive too, and does not.
SYSTEM_LIBS="libc.so libm.so libdl.so liblog.so"

if [ "$MODE" = "host" ] && [ "$DRY_RUN" -eq 1 ]; then
    step "$AAR_NAME on this host, aar.sh assemble --dry-run"
    mkdir -p "$OUT/no-natives"
    if scripts/package/aar.sh assemble --out "$OUT/aar" --natives "$OUT/no-natives" --dry-run \
        ${VARIANT_ARGS[@]+"${VARIANT_ARGS[@]}"} >"$OUT/assemble.out" 2>&1; then
        pass "aar.sh assemble --dry-run: $(tail -1 "$OUT/assemble.out" | sed 's/^aar.sh assemble: //')"
    else
        fail "aar.sh assemble --dry-run:"
        sed 's/^/        /' "$OUT/assemble.out"
    fi
    step "the Gradle build the image runs, bindings/kotlin/android"
    wrapper="$ROOT/bindings/kotlin/android/gradle/wrapper/gradle-wrapper.properties"
    if grep -q '^distributionUrl=.*/gradle-.*-bin\.zip$' "$wrapper" 2>/dev/null \
        && grep -q '^distributionSha256Sum=[0-9a-f]\{64\}$' "$wrapper"; then
        pass "Gradle pinned by version and checksum ($(sed -n 's|^distributionUrl=.*/gradle-\(.*\)-bin\.zip$|\1|p' "$wrapper"))"
    else
        fail "$wrapper does not pin Gradle by version and SHA-256"
    fi
    for f in Dockerfile settings.gradle.kts build.gradle.kts telecom/build.gradle.kts sample/build.gradle.kts; do
        [ -f "$ROOT/bindings/kotlin/android/$f" ] && pass "bindings/kotlin/android/$f" || fail "bindings/kotlin/android/$f is missing"
    done
    printf '  note  not run here, the build image'"'"'s (Docker, and the Android SDK licence):\n'
    printf '        the natives for arm64-v8a, armeabi-v7a and x86_64, sipral-telecom.aar,\n'
    printf '        %s, their checks and the licence audit of what Gradle resolved\n' "$APK_NAME"
    printf '        (android.sh --out DIR --accept-android-sdk-licenses)\n'
    printf '\n'
    [ "$FAIL" -eq 0 ] && { printf 'android.sh: done (dry-run), %s\n' "$OUT"; exit 0; }
    printf 'android.sh: failed\n'; exit 1
fi

if [ "$MODE" = "host" ]; then
    if [ "$ACCEPTED" -ne 1 ]; then
        printf 'The build image installs Android SDK packages, which are under the Android SDK\n' >&2
        printf 'licence: developer.android.com/studio/terms. Read it, and pass\n' >&2
        printf '--accept-android-sdk-licenses to accept it and build.\n' >&2
        exit 2
    fi
    command -v docker >/dev/null 2>&1 || { fail "docker not found"; exit 1; }

    step "the build image ($IMAGE)"
    if docker build -t "$IMAGE" --build-arg ANDROID_SDK_LICENSE_ACCEPTED=yes \
        "$ROOT/bindings/kotlin/android" >"$OUT/image.log" 2>&1; then
        pass "docker build bindings/kotlin/android"
    else
        fail "docker build:"
        tail -30 "$OUT/image.log" | sed 's/^/        /'
        printf '\nandroid.sh: failed\n'; exit 1
    fi

    step "the build, inside it"
    docker run --rm \
        -v "$ROOT:/src:ro" \
        -v "$OUT:/out" \
        -v sipral-android-cargo:/cache/cargo \
        -v sipral-android-gradle:/cache/gradle \
        -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-}" \
        "$IMAGE" \
        bash /src/scripts/package/android.sh inside --out /out ${INSIDE_ARGS[@]+"${INSIDE_ARGS[@]}"}
    exit $?
fi

# -- inside the image ------------------------------------------------------

[ -n "${ANDROID_HOME:-}" ] && [ -n "${ANDROID_NDK_HOME:-}" ] || {
    fail "android.sh inside runs in the build image, which sets ANDROID_HOME and ANDROID_NDK_HOME"
    exit 1
}
[ -z "${CARGO_BUILD_JOBS:-}" ] && unset CARGO_BUILD_JOBS

# The checkout is mounted read-only, and Gradle writes beside its project:
# the build runs on a copy, and nothing it does reaches the host's tree.
SRC=/tmp/sipral
step "a working copy of the checkout"
rm -rf "$SRC"
mkdir -p "$SRC"
(cd /src && tar --exclude=./target --exclude=./.git --exclude='./bindings/kotlin/android/.gradle' \
    --exclude='./bindings/kotlin/android/build' --exclude='./bindings/kotlin/android/*/build' -cf - .) \
    | (cd "$SRC" && tar -xf -) && pass "$SRC" || { fail "copying /src"; exit 1; }
cd "$SRC"
# The target directory and cargo's registry both live on the cache volume,
# so a second run downloads and builds only what changed.
export CARGO_TARGET_DIR=/cache/cargo/target
mkdir -p /cache/cargo/registry
ln -sfn /cache/cargo/registry "$CARGO_HOME/registry"
export GRADLE_USER_HOME=/cache/gradle

step "$AAR_NAME, $VARIANT_LABEL"
rm -rf "$OUT/natives" "$OUT/aar"
if scripts/package/aar.sh collect-natives --out "$OUT/natives" ${VARIANT_ARGS[@]+"${VARIANT_ARGS[@]}"} \
    >"$OUT/collect-natives.out" 2>&1; then
    pass "aar.sh collect-natives"
else
    fail "aar.sh collect-natives:"
    sed 's/^/        /' "$OUT/collect-natives.out"
    printf '\nandroid.sh: failed\n'; exit 1
fi
if scripts/package/aar.sh assemble --out "$OUT/aar" --natives "$OUT/natives" ${VARIANT_ARGS[@]+"${VARIANT_ARGS[@]}"} \
    >"$OUT/assemble.out" 2>&1; then
    pass "aar.sh assemble"
else
    fail "aar.sh assemble:"
    sed 's/^/        /' "$OUT/assemble.out"
    printf '\nandroid.sh: failed\n'; exit 1
fi
cp "$OUT/aar/$AAR_NAME" "$OUT/$AAR_NAME"

# A Maven layout for Gradle to resolve org.sipral:sipral from, with the POM
# naming what an AAR cannot carry inside itself.
REPO="$OUT/maven/org/sipral/sipral/$VERSION"
rm -rf "$OUT/maven"
mkdir -p "$REPO"
cp "$OUT/$AAR_NAME" "$REPO/sipral-$VERSION.aar"
cat >"$REPO/sipral-$VERSION.pom" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.sipral</groupId>
  <artifactId>sipral</artifactId>
  <version>$VERSION</version>
  <packaging>aar</packaging>
  <description>$AAR_NAME, $VARIANT_LABEL</description>
  <dependencies>
    <dependency>
      <groupId>org.jetbrains.kotlinx</groupId>
      <artifactId>kotlinx-coroutines-core</artifactId>
      <version>1.11.0</version>
      <scope>runtime</scope>
    </dependency>
  </dependencies>
</project>
EOF
pass "local Maven repository, org.sipral:sipral:$VERSION"

step "Gradle"
cd "$SRC/bindings/kotlin/android"
wrapper=gradle/wrapper/gradle-wrapper.properties
gradle_version=$(sed -n 's|^distributionUrl=.*/gradle-\(.*\)-bin\.zip$|\1|p' "$wrapper")
gradle_sha=$(sed -n 's/^distributionSha256Sum=//p' "$wrapper")
if [ ! -x gradlew ]; then
    # The wrapper is generated rather than committed (its jar is a binary),
    # from the Gradle distribution the image carries, pinned to the version
    # and checksum the committed properties name. It is generated in an
    # empty project, so that making it does not configure this one, and the
    # properties it writes are compared with the committed ones: a wrapper
    # that drifted from the committed pin is not the build this repository
    # describes.
    gen=/tmp/wrapper-gen
    rm -rf "$gen" && mkdir -p "$gen" && touch "$gen/settings.gradle.kts"
    if (cd "$gen" && gradle --no-daemon -q wrapper --gradle-version "$gradle_version" \
        --gradle-distribution-sha256-sum "$gradle_sha") >"$OUT/wrapper.log" 2>&1 \
        && cmp -s "$gen/$wrapper" "$wrapper"; then
        cp "$gen/gradlew" "$gen/gradlew.bat" .
        cp "$gen/gradle/wrapper/gradle-wrapper.jar" gradle/wrapper/
        pass "gradle wrapper, $gradle_version"
    else
        fail "gradle wrapper did not reproduce the committed $wrapper:"
        [ -f "$gen/$wrapper" ] && diff "$wrapper" "$gen/$wrapper" | sed 's/^/        /'
        tail -20 "$OUT/wrapper.log" | sed 's/^/        /'
        printf '\nandroid.sh: failed\n'; exit 1
    fi
fi
TASKS=(:telecom:assembleRelease :sample:assembleDebug)
[ "$RELEASE" -eq 1 ] && TASKS+=(:sample:assembleRelease :sample:bundleRelease)
if ./gradlew --no-daemon --console=plain -Psipral.repo="$OUT/maven" ${GRADLE_PROPS[@]+"${GRADLE_PROPS[@]}"} \
    "${TASKS[@]}" >"$OUT/gradle.log" 2>&1; then
    pass "${TASKS[*]}${GRADLE_PROPS[*]+ ${GRADLE_PROPS[*]}}"
else
    fail "Gradle:"
    grep -E '^e: |error:|FAILURE|What went wrong' -A3 "$OUT/gradle.log" | head -60 | sed 's/^/        /'
    tail -20 "$OUT/gradle.log" | sed 's/^/        /'
    printf '\nandroid.sh: failed\n'; exit 1
fi
cp telecom/build/outputs/aar/telecom-release.aar "$OUT/sipral-telecom.aar"

# org.sipral:sipral-telecom, for a Maven repository: its POM names the three
# dependencies telecom/build.gradle.kts declares, with the metadata Maven
# Central asks for, beside a sources jar; the local repository gets both
# archives, so an application resolves the helper the way it resolves
# org.sipral:sipral. It names org.sipral:sipral, the coordinate it was built
# against in both variants; an application on sipral-opus excludes that one.
TELECOM_POM="$OUT/sipral-telecom-$VERSION.pom"
TELECOM_SOURCES="$OUT/sipral-telecom-$VERSION-sources.jar"
gradle_dep() { sed -n "s|^ *api(\"$1:\(.*\)\")\$|\1|p; s|^ *implementation(\"$1:\(.*\)\")\$|\1|p" telecom/build.gradle.kts; }
TELECOM_COROUTINES=$(gradle_dep org.jetbrains.kotlinx:kotlinx-coroutines-android)
TELECOM_CORE=$(gradle_dep androidx.core:core-telecom)
[ -n "$TELECOM_COROUTINES" ] && [ -n "$TELECOM_CORE" ] \
    || fail "telecom/build.gradle.kts: no kotlinx-coroutines-android or core-telecom version to write the POM from"
cat >"$TELECOM_POM" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.sipral</groupId>
  <artifactId>sipral-telecom</artifactId>
  <version>$VERSION</version>
  <packaging>aar</packaging>
  <name>Sipral telecom helper for Android</name>
  <description>Sipral - Session Initiation Protocol Rust Audio Layer. The calls of org.sipral:sipral in Android's telecom framework: a self-managed ConnectionService, a Core-Telecom adapter, the call's foreground service and the app lifecycle.</description>
  <url>https://sipral.org</url>
  <licenses>
    <license>
      <name>AGPL-3.0-only</name>
      <url>https://www.gnu.org/licenses/agpl-3.0.txt</url>
      <distribution>repo</distribution>
    </license>
    <license>
      <name>LicenseRef-Sipral-Commercial</name>
      <url>https://sipral.org/terms/</url>
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
      <groupId>org.sipral</groupId>
      <artifactId>sipral</artifactId>
      <version>$VERSION</version>
      <type>aar</type>
      <scope>compile</scope>
    </dependency>
    <dependency>
      <groupId>org.jetbrains.kotlinx</groupId>
      <artifactId>kotlinx-coroutines-android</artifactId>
      <version>$TELECOM_COROUTINES</version>
      <scope>compile</scope>
    </dependency>
    <dependency>
      <groupId>androidx.core</groupId>
      <artifactId>core-telecom</artifactId>
      <version>$TELECOM_CORE</version>
      <scope>runtime</scope>
    </dependency>
  </dependencies>
</project>
EOF
rm -f "$TELECOM_SOURCES"
if (cd telecom/src/main/kotlin && jar cf "$TELECOM_SOURCES" .); then
    TELECOM_REPO="$OUT/maven/org/sipral/sipral-telecom/$VERSION"
    mkdir -p "$TELECOM_REPO"
    cp "$OUT/sipral-telecom.aar" "$TELECOM_REPO/sipral-telecom-$VERSION.aar"
    cp "$TELECOM_POM" "$TELECOM_REPO/"
    pass "org.sipral:sipral-telecom:$VERSION: $(basename "$TELECOM_POM"), $(basename "$TELECOM_SOURCES"), and in the local Maven repository"
else
    fail "jar cf $(basename "$TELECOM_SOURCES")"
fi
cp sample/build/outputs/apk/debug/sample-debug.apk "$OUT/$APK_NAME"
if [ "$RELEASE" -eq 1 ]; then
    cp sample/build/outputs/apk/release/sample-release-unsigned.apk "$OUT/$RELEASE_APK"
    cp sample/build/outputs/bundle/release/sample-release.aab "$OUT/$RELEASE_AAB"
fi

# The connection's callbacks and the network monitor (telecom/src/test), the
# sample's diagnostics bundle and readiness screen (sample/src/test), on the
# JVM. What ran is read out of the results, because a test task that found
# nothing to run succeeds too.
step "the helper's and the sample's unit tests"
for project in telecom sample; do
    if ./gradlew --no-daemon --console=plain -Psipral.repo="$OUT/maven" ${GRADLE_PROPS[@]+"${GRADLE_PROPS[@]}"} \
        ":$project:testDebugUnitTest" >"$OUT/unit-tests-$project.log" 2>&1; then
        results=$project/build/test-results/testDebugUnitTest
        counted=$(cat "$results"/*.xml 2>/dev/null | grep -o '<testsuite [^>]*>' \
            | sed -E 's/.* tests="([0-9]+)".* failures="([0-9]+)".* errors="([0-9]+)".*/\1 \2 \3/' \
            | awk '{t += $1; f += $2 + $3} END {print t + 0, f + 0}')
        if [ "${counted% *}" -gt 0 ] && [ "${counted#* }" -eq 0 ]; then
            pass ":$project:testDebugUnitTest, ${counted% *} tests"
        else
            fail ":$project:testDebugUnitTest ran ${counted% *} tests with ${counted#* } failing"
        fi
    else
        fail ":$project:testDebugUnitTest:"
        grep -E 'FAILED|Exception|Error|What went wrong' -A3 "$OUT/unit-tests-$project.log" | head -60 | sed 's/^/        /'
    fi
done

# Every artefact Gradle actually resolved -- not what the build files
# declare -- for what the helper ships, what the sample ships and what the
# helper's unit tests run on, each read for the licence its own POM declares
# (or its parent's, when it declares none) out of Gradle's cache, and held to
# the licences this repository takes. THIRD-PARTY-NOTICES.md names them;
# this is where that is checked rather than assumed.
step "the licences of every artefact Gradle resolved"
pom_of() {
    local group="$1" artifact="$2" version="$3"
    ls "$GRADLE_USER_HOME/caches/modules-2/files-2.1/$group/$artifact/$version"/*/"$artifact-$version.pom" 2>/dev/null | head -1
}
licence_of() {
    local pom="$1" depth=0 names
    while [ -n "$pom" ] && [ "$depth" -lt 5 ]; do
        names=$(tr -d '\n' <"$pom" | grep -o '<licenses>.*</licenses>' | grep -o '<name>[^<]*</name>' \
            | sed 's/<[^>]*>//g' | paste -sd'|' -)
        if [ -n "$names" ]; then
            printf '%s' "$names"
            return
        fi
        local parent
        parent=$(tr -d '\n' <"$pom" | grep -o '<parent>.*</parent>' | head -1)
        [ -z "$parent" ] && break
        pom=$(pom_of "$(printf '%s' "$parent" | sed 's|.*<groupId>\([^<]*\)</groupId>.*|\1|')" \
            "$(printf '%s' "$parent" | sed 's|.*<artifactId>\([^<]*\)</artifactId>.*|\1|')" \
            "$(printf '%s' "$parent" | sed 's|.*<version>\([^<]*\)</version>.*|\1|')")
        depth=$((depth + 1))
    done
    printf 'none declared'
}
# The names POMs give the licences deny.toml allows (MIT, BSD, Apache-2.0,
# ISC, Zlib, MIT-0, Unicode-3.0, CC0). A POM naming several is taken as
# offering a choice, and passes when one of them is here; licences.txt keeps
# every name it gave.
ALLOWED='(The )?Apache (Software )?Licen[cs]e,? (Version )?2\.0|Apache-2\.0|(The )?MIT( No Attribution)? Licen[cs]e|MIT(-0)?|(The )?(New )?BSD( [23]-Clause)? Licen[cs]e|BSD-[23]-Clause|ISC( Licen[cs]e)?|zlib( Licen[cs]e)?|Zlib|Unicode-3\.0|CC0(-1\.0)?|Public Domain, per Creative Commons CC0'
# "group:artifact:version" for each artefact a dependency report resolved.
# A line reads "g:a:v", "g:a:v -> v2" (another version won) or "g:a -> v" (a
# platform chose the version); a constraint "(c)" and a declaration that was
# not resolved "(n)" are not artefacts, and a project is this build's own.
resolved_in() {
    awk '/--- / {
        line = $0; sub(/.*--- /, "", line)
        if (line ~ /\((c|n)\)$/ || line ~ /^project /) next
        n = split(line, word, " "); split(word[1], part, ":")
        version = (word[2] == "->") ? word[3] : part[3]
        print part[1] ":" part[2] ":" version
    }' "$1" | grep -v '^org\.sipral:' | sort -u
}
: >"$OUT/licences.txt"
for pair in ":telecom releaseRuntimeClasspath helper-runtime" ":sample debugRuntimeClasspath sample-runtime" \
    ":sample releaseRuntimeClasspath sample-release-runtime" \
    ":telecom debugUnitTestRuntimeClasspath helper-unit-tests" ":sample debugUnitTestRuntimeClasspath sample-unit-tests"; do
    read -r project configuration label <<<"$pair"
    report="$OUT/dependencies-$label.txt"
    if ! ./gradlew --no-daemon -q -Psipral.repo="$OUT/maven" "$project:dependencies" \
        --configuration "$configuration" >"$report" 2>&1; then
        fail "$project:dependencies --configuration $configuration:"
        tail -20 "$report" | sed 's/^/        /'
        continue
    fi
    count=0
    refused=""
    for coordinate in $(resolved_in "$report"); do
        IFS=: read -r group artifact version <<<"$coordinate"
        pom=$(pom_of "$group" "$artifact" "$version")
        licence=$([ -n "$pom" ] && licence_of "$pom" || printf 'no POM in the cache')
        printf '%s\t%s\t%s\n' "$label" "$coordinate" "$licence" >>"$OUT/licences.txt"
        # Not grep -q, which under pipefail can fail the pipeline over a
        # match (see the note at the telecom classes below).
        if ! printf '%s\n' "$licence" | tr '|' '\n' | grep -xE "$ALLOWED" >/dev/null; then
            refused="$refused$coordinate ($licence)"$'\n'
        fi
        count=$((count + 1))
    done
    if [ "$count" -eq 0 ]; then
        fail "$label: nothing was read out of $project:dependencies, so no licence was checked"
    elif [ -z "$refused" ]; then
        pass "$label: $count artefacts resolved ($project $configuration), every one under a licence deny.toml allows"
    else
        fail "$label: artefacts under a licence deny.toml does not allow:"
        printf '%s' "$refused" | sed 's/^/        /'
    fi
done

# -- what came out ---------------------------------------------------------

LLVM="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
BUILD_TOOLS=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)

elf_line() {
    # "<machine> <class>" out of the ELF header itself.
    local file="$1"
    local class emachine
    class=$(od -An -tu1 -j4 -N1 "$file" | tr -d ' \n')
    emachine=$(od -An -tu1 -j18 -N2 "$file" | awk '{print $1 + 256 * $2}')
    printf '%s %s' "$emachine" "$([ "$class" = 2 ] && echo 64 || echo 32)"
}

# Check the natives unpacked from an archive under <dir>/<prefix>/<abi>/.
check_natives() {
    local label="$1" dir="$2" prefix="$3"
    for pair in "${ELF_EXPECTED[@]}"; do
        local abi="${pair%%:*}" want="${pair#*:}"
        want="${want%%:*} ${want#*:}"
        for lib in libsipral_ffi.so libsipral_jni.so; do
            local f="$dir/$prefix/$abi/$lib"
            if [ ! -s "$f" ]; then
                fail "$label: $prefix/$abi/$lib is missing"
                continue
            fi
            local got
            got=$(elf_line "$f")
            if [ "$got" != "$want" ]; then
                fail "$label: $prefix/$abi/$lib is ELF machine/class '$got', not '$want'"
                continue
            fi
            local needed stray
            needed=$("$LLVM/llvm-readelf" -d "$f" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | tr '\n' ' ')
            stray=""
            for n in $needed; do
                case " $SYSTEM_LIBS libsipral_ffi.so " in
                    *" $n "*) ;;
                    *) stray="$stray $n" ;;
                esac
            done
            if [ -n "$stray" ]; then
                fail "$label: $prefix/$abi/$lib needs$stray, which nothing ships"
                continue
            fi
            pass "$label: $prefix/$abi/$lib, ELF machine ${want% *}, ${want#* }-bit, needs ${needed% }"
        done
        # The shim is what the JVM loads: it has to be linked against the
        # C ABI and export the entry points the Kotlin side declares.
        local jni="$dir/$prefix/$abi/libsipral_jni.so"
        if [ -s "$jni" ]; then
            local exported onload
            exported=$("$LLVM/llvm-nm" -D --defined-only "$jni" | grep -c ' T Java_org_sipral_' || true)
            onload=$("$LLVM/llvm-nm" -D --defined-only "$jni" | grep -c ' T JNI_OnLoad$' || true)
            if [ "$exported" -gt 0 ] && [ "$onload" -eq 1 ]; then
                pass "$label: $prefix/$abi/libsipral_jni.so exports JNI_OnLoad and $exported Java_org_sipral_ entry points"
            else
                fail "$label: $prefix/$abi/libsipral_jni.so exports $exported Java_org_sipral_ entry points and JNI_OnLoad $onload times"
            fi
        fi
    done
}

step "$AAR_NAME"
X=/tmp/unpacked
rm -rf "$X" && mkdir -p "$X/sipral" "$X/telecom" "$X/apk"
unzip -q "$OUT/$AAR_NAME" -d "$X/sipral"
for entry in AndroidManifest.xml classes.jar proguard.txt; do
    [ -s "$X/sipral/$entry" ] && pass "$AAR_NAME carries $entry" || fail "$AAR_NAME is missing $entry"
done
check_natives "$AAR_NAME" "$X/sipral" jni
declared=$(unzip -Z1 "$X/sipral/classes.jar" | grep -c '\.class$')
pass "$AAR_NAME: classes.jar holds $declared classes"
# Every `external fun` the Kotlin side declares, against what the shim
# exports, so that a native method nothing implements is found here rather
# than as an UnsatisfiedLinkError on a phone.
expected_symbols=$(grep -rhoE 'external fun [A-Za-z_][A-Za-z0-9_]*' "$SRC/bindings/kotlin/sipral/src/main/kotlin" \
    | awk '{print $3}' | sort -u)
# Java_org_sipral[_idiomatic]_<Class>_<method>, with every '_' in the method
# name written '_1' (the JNI specification's escape): the class segment is
# dropped and the escape undone, leaving the name as Kotlin spells it.
exported_symbols=$("$LLVM/llvm-nm" -D --defined-only "$X/sipral/jni/arm64-v8a/libsipral_jni.so" \
    | awk '/ T Java_org_sipral_/{print $3}' \
    | sed -e 's/^Java_org_sipral_\(idiomatic_\)\{0,1\}[A-Za-z0-9]*_//' -e 's/_1/_/g' | sort -u)
unresolved=$(comm -23 <(printf '%s\n' "$expected_symbols") <(printf '%s\n' "$exported_symbols") || true)
if [ -z "$expected_symbols" ]; then
    fail "no external fun found in bindings/kotlin/sipral/src/main/kotlin, so nothing was compared"
elif [ -z "$unresolved" ]; then
    pass "$AAR_NAME: every one of $(printf '%s\n' "$expected_symbols" | wc -l) external funs has its JNI symbol"
else
    fail "$AAR_NAME: external funs with no JNI symbol in libsipral_jni.so:"
    printf '        %s\n' $unresolved
fi

step "sipral-telecom.aar"
unzip -q "$OUT/sipral-telecom.aar" -d "$X/telecom"
for class in org/sipral/android/telecom/SipralConnectionService.class \
    org/sipral/android/telecom/SipralConnection.class \
    org/sipral/android/telecom/AndroidTelecomPlatform.class \
    org/sipral/android/telecom/CoreTelecomPlatform.class \
    org/sipral/android/telecom/SipralCoreCall.class \
    org/sipral/android/telecom/SipralCallRoutes.class \
    org/sipral/android/telecom/SipralCallAudio.class \
    org/sipral/android/telecom/SipralCallAudios.class \
    org/sipral/android/telecom/SipralNetworkMonitor.class \
    org/sipral/android/telecom/SipralCallService.class \
    org/sipral/android/telecom/SipralCallForeground.class \
    org/sipral/android/telecom/SipralAppLifecycle.class \
    org/sipral/android/telecom/SipralKeystoreStore.class \
    org/sipral/android/telecom/AndroidAudioDevice.class; do
    # grep reads to the end rather than -q: under pipefail, grep -q leaving
    # at the first match kills the writer with SIGPIPE and fails the
    # pipeline over a match it found.
    unzip -Z1 "$X/telecom/classes.jar" | grep -x "$class" >/dev/null \
        && pass "sipral-telecom.aar: $class" || fail "sipral-telecom.aar is missing $class"
done
manifest="$X/telecom/AndroidManifest.xml"
grep -q 'android.permission.BIND_TELECOM_CONNECTION_SERVICE' "$manifest" \
    && grep -q 'android.telecom.ConnectionService' "$manifest" \
    && pass "sipral-telecom.aar: the service, bindable only by the telecom framework" \
    || fail "sipral-telecom.aar: the manifest does not declare the ConnectionService as it should"
grep -q 'android.permission.MANAGE_OWN_CALLS' "$manifest" \
    && pass "sipral-telecom.aar: MANAGE_OWN_CALLS" || fail "sipral-telecom.aar: MANAGE_OWN_CALLS is not requested"
# Kotlin metadata 2.2, as sipral.aar's: newer would not compile in an
# application on AGP 9's built-in Kotlin 2.2 (telecom/build.gradle.kts)
unzip -q -o "$X/telecom/classes.jar" org/sipral/android/telecom/SipralTelecom.class -d "$X/telecom-classes"
telecom_mv=$(javap -v -cp "$X/telecom-classes" org.sipral.android.telecom.SipralTelecom 2>/dev/null \
    | sed -n 's/^ *mv=\[\([0-9]*\),\([0-9]*\),.*/\1.\2/p' | head -1)
[ "$telecom_mv" = "2.2" ] && pass "sipral-telecom.aar: Kotlin metadata 2.2" \
    || fail "sipral-telecom.aar: Kotlin metadata '$telecom_mv', not 2.2"
# the call's foreground service, with both types a store review asks about
grep -q 'android:name="org.sipral.android.telecom.SipralCallService"' "$manifest" \
    && grep -q 'android:foregroundServiceType="phoneCall|microphone"' "$manifest" \
    && grep -q 'android.permission.FOREGROUND_SERVICE_PHONE_CALL' "$manifest" \
    && grep -q 'android.permission.FOREGROUND_SERVICE_MICROPHONE' "$manifest" \
    && pass "sipral-telecom.aar: SipralCallService, phoneCall and microphone, with their permissions" \
    || fail "sipral-telecom.aar: the call's foreground service is not declared as it should be"

# The sample as an APK: its natives, its classes, what it asks of the phone.
check_apk() {
    local name="$1" dir="$2"
    unzip -q "$OUT/$name" -d "$dir"
    check_natives "$name" "$dir" lib
    local dexes classes badging
    dexes=$(ls "$dir"/classes*.dex 2>/dev/null | wc -l)
    [ "$dexes" -gt 0 ] && pass "$name: $dexes dex file(s)" || fail "$name carries no dex"
    classes=$("$ANDROID_HOME/cmdline-tools/latest/bin/apkanalyzer" dex packages --defined-only "$OUT/$name" 2>/dev/null \
        | awk '$1 == "C" {print $NF}')
    for class in org.sipral.telecom.TelecomBridge org.sipral.telecom.CallAudio org.sipral.idiomatic.SipralClient \
        org.sipral.SipralEventListeners org.sipral.android.telecom.SipralConnectionService \
        org.sipral.android.telecom.SipralCallAudio org.sipral.android.telecom.SipralCallAudios \
        org.sipral.android.telecom.SipralNetworkMonitor org.sipral.sample.MainActivity \
        org.sipral.android.telecom.SipralCallService org.sipral.idiomatic.SipralLifecycle \
        org.sipral.sample.PushReceiver org.sipral.android.telecom.CoreTelecomPlatform \
        androidx.core.telecom.CallsManager org.sipral.sample.CallActionReceiver; do
        printf '%s\n' "$classes" | grep -x "$class" >/dev/null \
            && pass "$name: $class" || fail "$name is missing $class"
    done
    badging=$("$BUILD_TOOLS/aapt2" dump badging "$OUT/$name" 2>/dev/null)
    for permission in android.permission.MANAGE_OWN_CALLS android.permission.RECORD_AUDIO \
        android.permission.FOREGROUND_SERVICE_PHONE_CALL android.permission.FOREGROUND_SERVICE_MICROPHONE \
        android.permission.POST_NOTIFICATIONS android.permission.USE_FULL_SCREEN_INTENT; do
        printf '%s\n' "$badging" | grep "uses-permission: name='$permission'" >/dev/null \
            && pass "$name: $permission" || fail "$name does not request $permission"
    done
    printf '%s\n' "$badging" | grep -x "native-code: 'arm64-v8a' 'armeabi-v7a' 'x86_64'" >/dev/null \
        && pass "$name: native code for arm64-v8a, armeabi-v7a and x86_64" \
        || fail "$name: $(printf '%s\n' "$badging" | grep native-code)"
    printf '%s\n' "$badging" | grep -x "targetSdkVersion:'37'" >/dev/null \
        && pass "$name: targets API level 37" || fail "$name: $(printf '%s\n' "$badging" | grep targetSdkVersion)"
    BADGING="$badging"
}

step "$APK_NAME"
check_apk "$APK_NAME" "$X/apk"

# What a store asks of the release build beyond what the debug one has: not
# debuggable, the version this build means, and natives a phone with 16 KB
# memory pages can map -- every ELF LOAD segment aligned to 16 KB, and every
# uncompressed library in the APK on a 16 KB boundary (zipalign -P 16).
check_page_alignment() {
    local label="$1" dir="$2"
    local file align misaligned=""
    # 16 KB pages are a 64-bit matter: Google Play asks it of arm64-v8a and
    # x86_64, and a 32-bit process maps 4 KB pages everywhere
    for file in $(find "$dir/arm64-v8a" "$dir/x86_64" -name '*.so' | sort); do
        # the last column of a program header is its alignment, in hex
        for align in $("$LLVM/llvm-readelf" -lW "$file" | awk '$1 == "LOAD" {print $NF}'); do
            if [ $((align)) -lt 16384 ]; then
                misaligned="$misaligned ${file#"$dir"/}"
                break
            fi
        done
    done
    [ -z "$misaligned" ] && pass "$label: every 64-bit native's LOAD segments aligned to 16 KB or more" \
        || fail "$label: natives with a LOAD segment aligned under 16 KB:$misaligned"
}
if [ "$RELEASE" -eq 1 ]; then
    step "$RELEASE_APK"
    check_apk "$RELEASE_APK" "$X/release-apk"
    printf '%s\n' "$BADGING" | grep -x 'application-debuggable' >/dev/null \
        && fail "$RELEASE_APK is debuggable" || pass "$RELEASE_APK: not debuggable"
    printf '%s\n' "$BADGING" | sed -n "s/^package: .*versionCode='\([0-9]*\)' versionName='\([^']*\)'.*/\1 \2/p" \
        | { read -r code name; pass "$RELEASE_APK: version $name, code $code"; }
    check_page_alignment "$RELEASE_APK" "$X/release-apk/lib"
    if "$BUILD_TOOLS/zipalign" -c -P 16 4 "$OUT/$RELEASE_APK" >/dev/null 2>&1; then
        pass "$RELEASE_APK: zipalign -c -P 16, uncompressed libraries on 16 KB boundaries"
    else
        fail "$RELEASE_APK: zipalign -c -P 16 refuses it"
    fi

    step "$RELEASE_AAB"
    mkdir -p "$X/aab"
    unzip -q "$OUT/$RELEASE_AAB" -d "$X/aab"
    for entry in BundleConfig.pb base/manifest/AndroidManifest.xml base/dex/classes.dex; do
        [ -s "$X/aab/$entry" ] && pass "$RELEASE_AAB carries $entry" || fail "$RELEASE_AAB is missing $entry"
    done
    check_natives "$RELEASE_AAB" "$X/aab/base" lib
    check_page_alignment "$RELEASE_AAB" "$X/aab/base/lib"
    if [ -n "$(ls "$X/aab/META-INF"/*.RSA "$X/aab/META-INF"/*.EC 2>/dev/null)" ]; then
        fail "$RELEASE_AAB is signed already, and is meant to be signed only by android-sign.sh"
    else
        pass "$RELEASE_AAB: unsigned, for android-sign.sh"
    fi
fi

printf '\n'
if [ "$FAIL" -eq 0 ]; then
    printf 'android.sh: done, %s\n' "$VARIANT_LABEL"
    printf '  %s\n' "$OUT/$AAR_NAME" "$OUT/sipral-telecom.aar" "$OUT/$APK_NAME"
    [ "$RELEASE" -eq 1 ] && printf '  %s\n' "$OUT/$RELEASE_APK" "$OUT/$RELEASE_AAB"
    exit 0
fi
printf 'android.sh: failed\n'; exit 1
