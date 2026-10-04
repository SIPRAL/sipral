#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# The JVM server artefact: sipral-jvm-<version>.jar, built by bindings/jvm's
# Maven project from bindings/kotlin's classes, with libsipral_ffi.so and
# libsipral_jni.so (the three shims in bindings/kotlin/sipral/src/main/jni
# linked against it, finding it beside themselves through $ORIGIN) for
# linux-x64 and linux-arm64 inside the jar, under org/sipral/jvm/native/.
#
#   scripts/package/jvm.sh --out DIR [--with-opus] [--no-qemu]
#       needs Docker, Maven, xmllint and a JDK carrying include/jni.h. linux-x64 is
#       built inside quay.io/pypa/manylinux_2_28_x86_64, so that it links
#       nothing newer than glibc 2.28, with Rust installed there (and cached
#       under DIR/cache) at rust-toolchain.toml's own channel; linux-arm64 is
#       cross-compiled in scripts/package/aarch64-cross.sh's image, against
#       the same glibc floor, and nothing arm64 executes to build it. Then
#       `mvn verify`: the loader's tests, and a Kotlin and a Java test that
#       each place a call between two stacks on loopback against the packaged
#       jar, under -Xcheck:jni. Unless --no-qemu, the same two tests run
#       again on an arm64 JVM (eclipse-temurin's, its filesystem exported
#       without ever running the image) under qemu-aarch64 in an
#       unprivileged container, so the arm64 pair is proved to load and to
#       carry a call, not only to be there.
#
#   scripts/package/jvm.sh --out DIR --dry-run [--with-opus]
#       for a Linux host without Docker: nothing cross-compiled. The gate
#       does not call it, since a Mac has no pair to build; it compiles and
#       runs bindings/jvm's sources itself (scripts/check.sh). The host's
#       own pair (linux-x64 or linux-arm64) is built with the host's
#       cargo and cc and is the only one staged; the same Maven build and
#       tests run over it, and the jar's layout is checked as far as that
#       pair goes. Maven resolves its plugins and the jar's dependencies from
#       the local repository, and from Maven Central the first time.
#       On a host that is not Linux -- a Mac -- there is no pair to build or
#       load, and --dry-run proves what that host can: sipral-ffi
#       type-checked for both Linux targets, and the JNI shims compiled (not
#       linked) for both against glibc's own headers with `zig cc`. Linking,
#       the glibc floor, `mvn verify` and the run under qemu are a Linux
#       host's, and the run says so.
#
# Every run, --dry-run or not, first holds bindings/jvm/pom.xml to what
# Maven Central shows and requires: a name, a description, a URL, both
# licences, a developer, the SCM, and no address anywhere in it.
#
# --with-opus builds the variant carrying libopus, as sipral-jvm-opus;
# features.sh says why the default leaves it out. The group id is
# bindings/jvm/pom.xml's, org.sipral, unless SIPRAL_GROUP_ID names another;
# nothing is installed into a Maven repository and nothing is published.
# DIR receives the jar, its sources jar, its POM (the flattened one, with the
# group id and version written out), the SBOM, and the build's own working
# files under DIR/maven, DIR/natives and DIR/cache.
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
finish() {
    printf '\n'
    if [ "$FAIL" -eq 0 ]; then
        printf 'jvm.sh: done%s, %s\n' "$([ "$DRY_RUN" -eq 1 ] && printf ' (dry-run)')" "$OUT"
        exit 0
    fi
    printf 'jvm.sh: failed\n'
    exit 1
}

OUT=""
DRY_RUN=0
WITH_OPUS=0
QEMU=1
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --with-opus) WITH_OPUS=1; shift ;;
        --no-qemu) QEMU=0; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -z "$OUT" ] && { printf 'usage: jvm.sh --out DIR [--dry-run] [--with-opus] [--no-qemu]\n' >&2; exit 2; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

. "$ROOT/scripts/package/features.sh"
package_features "$WITH_OPUS" || { printf 'no default feature list in crates/sipral-ffi/Cargo.toml\n' >&2; exit 1; }

VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -1)
ARTIFACT="sipral-jvm$VARIANT_SUFFIX"
RESOURCE_ROOT="org/sipral/jvm/native"
NATIVES="$OUT/natives"
MAVEN_BUILD="$OUT/maven"
# "<platform>:<ELF e_machine>:<Rust triple>": what each directory of the jar
# holds, what its two libraries' headers have to say, and what builds them.
PLATFORMS=(linux-x64:62:x86_64-unknown-linux-gnu linux-arm64:183:aarch64-unknown-linux-gnu)
LIBS=(libsipral_ffi.so libsipral_jni.so)
JNI_SOURCES=(sipral_jni.c idiomatic_media.c audio_routes.c)
# The oldest glibc either pair may ask for, manylinux_2_28's.
GLIBC_MINOR_MAX=28
JUNIT_PLATFORM_VERSION="6.1.3"

# Whether $1 is a 64-bit little-endian ELF shared object for machine $2, read
# from its own header: EI_CLASS at 4, EI_DATA at 5, e_type at 16, e_machine
# at 18.
elf_is() {
    local file="$1" machine="$2" magic class data etype emachine
    magic=$(od -An -tx1 -N4 "$file" 2>/dev/null | tr -d ' \n')
    [ "$magic" = "7f454c46" ] || return 1
    class=$(od -An -tu1 -j4 -N1 "$file" | tr -d ' \n')
    data=$(od -An -tu1 -j5 -N1 "$file" | tr -d ' \n')
    etype=$(od -An -tu1 -j16 -N1 "$file" | tr -d ' \n')
    emachine=$(od -An -tu1 -j18 -N2 "$file" | awk '{print $1 + 256 * $2}')
    [ "$class" = "2" ] && [ "$data" = "1" ] && [ "$etype" = "3" ] && [ "$emachine" = "$machine" ]
}

# The highest GLIBC_2.x minor in objdump -T's listing on standard input.
glibc_minor() {
    local highest
    highest=$(grep -oE 'GLIBC_2\.[0-9]+' | sort -t. -k2 -n -u | tail -1)
    [ -n "$highest" ] || return 1
    printf '%s\n' "${highest#GLIBC_2.}"
}

step "one version"
"$ROOT/scripts/version.sh" --check || { FAIL=1; finish; }

step "the POM, bindings/jvm/pom.xml"
POM_SOURCE="$ROOT/bindings/jvm/pom.xml"
if ! command -v xmllint >/dev/null 2>&1; then
    fail "xmllint not found (libxml2)"
elif xmllint --noout "$POM_SOURCE" 2>"$OUT/pom-lint.log"; then
    pass "well-formed (xmllint)"
    # The project's own elements, read with the namespace set aside.
    pom_count() { xmllint --xpath "count($1)" "$POM_SOURCE" 2>/dev/null; }
    for element in name description url; do
        [ "$(pom_count "/*[local-name()='project']/*[local-name()='$element'][normalize-space()]")" = "1" ] \
            && pass "<$element>" || fail "no <$element> in the POM"
    done
    licences=$(pom_count "/*[local-name()='project']/*[local-name()='licenses']/*[local-name()='license']")
    [ "$licences" = "2" ] && pass "both licences" || fail "$licences licence(s) in the POM, and Sipral has two arms"
    [ "$(pom_count "//*[local-name()='developers']/*[local-name()='developer']/*[local-name()='name']")" -ge 1 ] \
        && pass "<developers>" || fail "no developer named in the POM"
    [ "$(pom_count "//*[local-name()='scm']/*[local-name()='url' or local-name()='connection']")" = "2" ] \
        && pass "<scm>, its URL and connection" || fail "the POM's <scm> needs a URL and a connection"
    if grep -qE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$POM_SOURCE"; then
        fail "an address in the POM"
    else
        pass "no address in the POM"
    fi
    group_id=$(xmllint --xpath "string(//*[local-name()='properties']/*[local-name()='sipral.groupId'])" "$POM_SOURCE" 2>/dev/null)
    note "group id: ${SIPRAL_GROUP_ID:-$group_id}$([ -n "${SIPRAL_GROUP_ID:-}" ] && printf ', from SIPRAL_GROUP_ID in place of the POM'"'"'s %s' "$group_id")"
else
    fail "bindings/jvm/pom.xml is not well-formed:"; sed 's/^/        /' "$OUT/pom-lint.log"
fi
[ "$FAIL" -ne 0 ] && finish

JDK="${JAVA_HOME:-}"
if [ -z "$JDK" ] || [ ! -f "$JDK/include/jni.h" ]; then
    javac_path=$(command -v javac 2>/dev/null)
    [ -n "$javac_path" ] && JDK="$(cd "$(dirname "$(readlink -f "$javac_path")")/.." && pwd)"
fi

if [ "$DRY_RUN" -eq 1 ] && [ "$(uname -s)" != "Linux" ]; then
    step "$(uname -s) has no pair to build: what this host can prove, $VARIANT_LABEL"
    [ -n "$JDK" ] && [ -f "$JDK/include/jni.h" ] || { fail "no JDK carrying include/jni.h (set JAVA_HOME)"; finish; }
    command -v zig >/dev/null 2>&1 || { fail "zig not found (brew install zig): nothing else here reads C the way glibc does"; finish; }
    # The opus variant vendors a C build that needs a Linux C toolchain, so
    # the type check runs with the default package's features either way.
    package_features 0
    # This host's own jni_md.h, beside jni.h: what it decides (how
    # JNIEXPORT is spelt, which C type a jlong is) is not what can go wrong
    # here; what the shims ask of glibc is.
    md_dir=$(dirname "$(find "$JDK/include" -mindepth 2 -name jni_md.h | head -1)")
    for entry in "${PLATFORMS[@]}"; do
        platform="${entry%%:*}"
        triple="${entry##*:}"
        if ! rustup target list --installed 2>/dev/null | found -x "$triple"; then
            fail "$platform: $triple is not installed: rustup target add $triple"
        elif cargo check -p sipral-ffi "${FFI_FEATURE_ARGS[@]}" --target "$triple" >"$OUT/check-$platform.log" 2>&1; then
            pass "$platform: cargo check -p sipral-ffi ${FFI_FEATURE_ARGS[*]} --target $triple"
        else
            fail "$platform: cargo check --target $triple:"; tail -30 "$OUT/check-$platform.log" | sed 's/^/        /'
        fi
        compiled=1
        for source in "${JNI_SOURCES[@]}"; do
            if ! zig cc -target "${triple%%-*}-linux-gnu.2.$GLIBC_MINOR_MAX" -std=c11 -fPIC -O2 -Wall -Wextra -Werror \
                -I"$JDK/include" -I"$md_dir" -I"$ROOT/bindings/c/include" -c -o "$OUT/jni.o" \
                "$ROOT/bindings/kotlin/sipral/src/main/jni/$source" >"$OUT/zig-$platform.log" 2>&1; then
                fail "$platform: $source does not compile against glibc 2.$GLIBC_MINOR_MAX:"
                sed 's/^/        /' "$OUT/zig-$platform.log"
                compiled=0
            fi
        done
        [ "$compiled" -eq 1 ] && pass "$platform: ${JNI_SOURCES[*]} compile against glibc 2.$GLIBC_MINOR_MAX (zig cc, not linked)"
    done
    rm -f "$OUT/jni.o"
    note "not run here, a Linux host's with Docker, Maven and a JDK: both pairs linked against"
    note "glibc 2.$GLIBC_MINOR_MAX, mvn verify over the jar, and the arm64 run under qemu (jvm.sh --out DIR)"
    finish
fi

step "tools"
TOOLS=(mvn cargo)
if [ "$DRY_RUN" -eq 1 ]; then TOOLS+=(cc); else TOOLS+=(docker); fi
for tool in "${TOOLS[@]}"; do
    command -v "$tool" >/dev/null 2>&1 && pass "$tool" || fail "$tool not found"
done
if [ -n "$JDK" ] && [ -f "$JDK/include/jni.h" ] && [ -f "$JDK/include/linux/jni_md.h" ]; then
    pass "a JDK with Linux JNI headers, $JDK"
else
    fail "no JDK carrying include/jni.h and include/linux/jni_md.h (set JAVA_HOME)"
fi
[ "$FAIL" -ne 0 ] && finish

rm -rf "$NATIVES"
mkdir -p "$NATIVES"
EXPECTED=()

if [ "$DRY_RUN" -eq 1 ]; then
    step "the host's own pair, $VARIANT_LABEL (features $FFI_FEATURES)"
    case "$(uname -s)/$(uname -m)" in
        Linux/x86_64) HOST_PLATFORM="linux-x64" ;;
        Linux/aarch64) HOST_PLATFORM="linux-arm64" ;;
        *) HOST_PLATFORM="" ;;
    esac
    if [ -z "$HOST_PLATFORM" ]; then
        fail "$(uname -s) on $(uname -m): the jar carries natives for Linux on x86_64 and aarch64 only, so there is nothing to build or load here"
        finish
    fi
    stage="$NATIVES/$RESOURCE_ROOT/$HOST_PLATFORM"
    mkdir -p "$stage"
    target_dir="$OUT/cargo-host"
    if CARGO_TARGET_DIR="$target_dir" cargo build --release --locked -p sipral-ffi "${FFI_FEATURE_ARGS[@]}" \
        >"$OUT/cargo-host.log" 2>&1; then
        cp "$target_dir/release/libsipral_ffi.so" "$stage/"
        pass "cargo build --release -p sipral-ffi ${FFI_FEATURE_ARGS[*]}"
    else
        fail "cargo build:"
        tail -30 "$OUT/cargo-host.log" | sed 's/^/        /'
        finish
    fi
    sources=()
    for source in "${JNI_SOURCES[@]}"; do sources+=("$ROOT/bindings/kotlin/sipral/src/main/jni/$source"); done
    if cc -std=c11 -shared -fPIC -O2 -Wall -Wextra -Werror \
        -I"$JDK/include" -I"$JDK/include/linux" -I"$ROOT/bindings/c/include" \
        -o "$stage/libsipral_jni.so" "${sources[@]}" \
        -L"$stage" -lsipral_ffi -Wl,-soname,libsipral_jni.so '-Wl,-rpath,$ORIGIN' \
        >"$OUT/cc-host.log" 2>&1; then
        pass "cc: libsipral_jni.so linked against it, finding it through \$ORIGIN"
    else
        fail "cc, the JNI shims:"
        sed 's/^/        /' "$OUT/cc-host.log"
        finish
    fi
    EXPECTED=("$HOST_PLATFORM")
    for entry in "${PLATFORMS[@]}"; do
        [ "${entry%%:*}" = "$HOST_PLATFORM" ] || note "${entry%%:*}: not built (--dry-run builds only the host's own pair)"
    done
else
    CACHE="$OUT/cache"
    mkdir -p "$CACHE/x64-home"
    RUSTC_VERSION=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml")

    step "linux-x64, in quay.io/pypa/manylinux_2_28_x86_64, $VARIANT_LABEL"
    stage="$NATIVES/$RESOURCE_ROOT/linux-x64"
    mkdir -p "$stage" "$OUT/cargo-x64"
    # Rust is installed once into DIR/cache (rustup, pinned to
    # rust-toolchain.toml) rather than on every run; the container runs as
    # the caller, so what it leaves in DIR is the caller's to remove.
    inside='set -e
if [ ! -x "$CARGO_HOME/bin/cargo" ]; then
    curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --no-modify-path --default-toolchain "$RUSTC_VERSION" >/tmp/rustup.log 2>&1
fi
export PATH="$CARGO_HOME/bin:$PATH"
cd /work
cargo build --release --locked -p sipral-ffi --no-default-features --features "$FFI_FEATURES"
cp /tmp/target/release/libsipral_ffi.so /natives/
gcc -std=c11 -shared -fPIC -O2 -Wall -Wextra -Werror -I/jdk -I/jdk/linux -I/work/bindings/c/include \
    -o /natives/libsipral_jni.so \
    /work/bindings/kotlin/sipral/src/main/jni/sipral_jni.c \
    /work/bindings/kotlin/sipral/src/main/jni/idiomatic_media.c \
    /work/bindings/kotlin/sipral/src/main/jni/audio_routes.c \
    -L/natives -lsipral_ffi -Wl,-soname,libsipral_jni.so "-Wl,-rpath,\$ORIGIN"'
    if docker run --rm --user "$(id -u):$(id -g)" \
        -v "$ROOT:/work:ro" -v "$JDK/include:/jdk:ro" -v "$stage:/natives" \
        -v "$OUT/cargo-x64:/tmp/target" -v "$CACHE/x64-home:/home/build" \
        -e HOME=/home/build -e RUSTUP_HOME=/home/build/rustup -e CARGO_HOME=/home/build/cargo \
        -e CARGO_TARGET_DIR=/tmp/target -e RUSTC_VERSION="$RUSTC_VERSION" -e FFI_FEATURES="$FFI_FEATURES" \
        quay.io/pypa/manylinux_2_28_x86_64 bash -c "$inside" >"$OUT/linux-x64.log" 2>&1; then
        pass "cargo build --release -p sipral-ffi, then gcc: libsipral_jni.so against it"
    else
        fail "linux-x64 in manylinux_2_28_x86_64:"
        tail -30 "$OUT/linux-x64.log" | sed 's/^/        /'
    fi
    if [ -s "$stage/libsipral_ffi.so" ]; then
        for lib in "${LIBS[@]}"; do
            if minor=$(docker run --rm -v "$stage:/n:ro" quay.io/pypa/manylinux_2_28_x86_64 \
                objdump -T "/n/$lib" 2>/dev/null | glibc_minor); then
                [ "$minor" -le "$GLIBC_MINOR_MAX" ] \
                    && pass "linux-x64/$lib asks for nothing newer than GLIBC_2.$minor" \
                    || fail "linux-x64/$lib asks for GLIBC_2.$minor, newer than 2.$GLIBC_MINOR_MAX"
            else
                fail "linux-x64/$lib: no GLIBC_2.x symbol version read"
            fi
        done
    fi

    step "linux-arm64, cross-compiled in the aarch64 cross image, $VARIANT_LABEL"
    stage="$NATIVES/$RESOURCE_ROOT/linux-arm64"
    mkdir -p "$stage"
    # shellcheck source=aarch64-cross.sh
    . "$ROOT/scripts/package/aarch64-cross.sh"
    if aarch64_cross_ensure_image >"$OUT/aarch64-image.log" 2>&1; then
        pass "$AARCH64_CROSS_IMAGE"
        arm_target="$OUT/cargo-arm64"
        if aarch64_cross_build "$arm_target" >"$OUT/linux-arm64.log" 2>&1; then
            cp "$arm_target/aarch64-unknown-linux-gnu/release/libsipral_ffi.so" "$stage/"
            pass "cargo build --release -p sipral-ffi --target aarch64-unknown-linux-gnu"
        else
            fail "the aarch64 cross build:"
            tail -30 "$OUT/linux-arm64.log" | sed 's/^/        /'
        fi
        if [ -s "$stage/libsipral_ffi.so" ] && docker run --rm \
            -v "$ROOT:/work:ro" -v "$JDK/include:/jdk:ro" -v "$stage:/natives" \
            "$AARCH64_CROSS_IMAGE" \
            aarch64-linux-gnu-gcc --sysroot=/sysroot -B/sysroot/usr/lib64 \
            -std=c11 -shared -fPIC -O2 -Wall -Wextra -Werror \
            -I/jdk -I/jdk/linux -I/work/bindings/c/include \
            -o /natives/libsipral_jni.so \
            /work/bindings/kotlin/sipral/src/main/jni/sipral_jni.c \
            /work/bindings/kotlin/sipral/src/main/jni/idiomatic_media.c \
            /work/bindings/kotlin/sipral/src/main/jni/audio_routes.c \
            -L/natives -lsipral_ffi -Wl,-soname,libsipral_jni.so '-Wl,-rpath,$ORIGIN' \
            >>"$OUT/linux-arm64.log" 2>&1; then
            pass "aarch64-linux-gnu-gcc: libsipral_jni.so against it"
        else
            fail "linking the arm64 JNI shims:"
            tail -20 "$OUT/linux-arm64.log" | sed 's/^/        /'
        fi
        for lib in "${LIBS[@]}"; do
            [ -s "$stage/$lib" ] || continue
            if highest=$(aarch64_glibc_check "$stage/$lib" "$GLIBC_MINOR_MAX" 2>&1); then
                pass "linux-arm64/$lib asks for nothing newer than $highest"
            else
                fail "linux-arm64/$lib: $highest"
            fi
        done
    else
        fail "could not build the aarch64 cross image (scripts/package/docker/aarch64-cross.Dockerfile):"
        tail -20 "$OUT/aarch64-image.log" | sed 's/^/        /'
    fi
    EXPECTED=(linux-x64 linux-arm64)
fi

step "the natives staged"
for platform in "${EXPECTED[@]}"; do
    machine=""
    for entry in "${PLATFORMS[@]}"; do
        [ "${entry%%:*}" = "$platform" ] && { machine="${entry#*:}"; machine="${machine%%:*}"; }
    done
    for lib in "${LIBS[@]}"; do
        file="$NATIVES/$RESOURCE_ROOT/$platform/$lib"
        if [ ! -s "$file" ]; then
            fail "$platform/$lib was not produced"
        elif elf_is "$file" "$machine"; then
            pass "$platform/$lib ($(wc -c <"$file" | tr -d ' ') bytes, ELF machine $machine)"
        else
            fail "$platform/$lib is not a 64-bit ELF shared object for machine $machine"
        fi
    done
done
printf '%s\n' "$FFI_FEATURES" >"$NATIVES/$FEATURES_MARKER"
[ "$FAIL" -ne 0 ] && finish

step "mvn verify, bindings/jvm"
MVN_ARGS=(-B -f "$ROOT/bindings/jvm/pom.xml"
    -Drevision="$VERSION"
    -Dsipral.build="$MAVEN_BUILD"
    -Dsipral.natives="$NATIVES"
    -Dsipral.expected.platforms="$(IFS=,; printf '%s' "${EXPECTED[*]}")")
[ -n "${SIPRAL_GROUP_ID:-}" ] && MVN_ARGS+=(-Dsipral.groupId="$SIPRAL_GROUP_ID")
rm -rf "$MAVEN_BUILD"
if mvn "${MVN_ARGS[@]}" clean verify >"$OUT/maven.log" 2>&1; then
    pass "compiled, packaged and tested"
else
    fail "mvn verify:"
    grep -E '\[ERROR\]|Tests run:|FAIL' "$OUT/maven.log" | head -40 | sed 's/^/        /'
    finish
fi
for report in "$MAVEN_BUILD"/surefire-reports/TEST-*.xml "$MAVEN_BUILD"/failsafe-reports/TEST-*.xml; do
    [ -f "$report" ] || continue
    line=$(grep -o '<testsuite [^>]*' "$report" | head -1)
    name=$(printf '%s' "$line" | sed -n 's/.* name="\([^"]*\)".*/\1/p')
    tests=$(printf '%s' "$line" | sed -n 's/.* tests="\([0-9]*\)".*/\1/p')
    pass "${name##*.}: $tests test(s)"
done
checked=$(cat "$MAVEN_BUILD"/failsafe-reports/*-output.txt 2>/dev/null \
    | grep -E 'WARNING in native method|WARNING: JNI|FATAL ERROR in native method' || true)
if [ -n "$checked" ]; then
    fail "-Xcheck:jni found something wrong in the shim:"
    printf '%s\n' "$checked" | head -20 | sed 's/^/        /'
else
    pass "-Xcheck:jni: nothing reported during the loopback calls"
fi

step "the jar"
JAR="$MAVEN_BUILD/sipral-jvm-$VERSION.jar"
if [ ! -s "$JAR" ]; then
    fail "no $(basename "$JAR") was built"
    finish
fi
listing=$(unzip -l "$JAR" 2>/dev/null)
for class in org/sipral/SipralNative.class org/sipral/idiomatic/SipralClient.class \
    org/sipral/jvm/SipralNatives.class org/sipral/jvm/SipralJava.class \
    META-INF/LICENSE META-INF/THIRD-PARTY-LICENSES.txt; do
    printf '%s\n' "$listing" | found " $class\$" && pass "carries $class" || fail "missing $class"
done
for platform in "${EXPECTED[@]}"; do
    for lib in "${LIBS[@]}"; do
        printf '%s\n' "$listing" | found " $RESOURCE_ROOT/$platform/$lib\$" \
            && pass "carries $RESOURCE_ROOT/$platform/$lib" \
            || fail "missing $RESOURCE_ROOT/$platform/$lib"
    done
done
POM="$MAVEN_BUILD/.flattened-pom.xml"
if [ -s "$POM" ] && ! grep -q '\${' "$POM"; then
    pass "the POM, flattened: $(sed -n 's/^  <groupId>\(.*\)<\/groupId>$/\1/p' "$POM" | head -1):sipral-jvm:$VERSION"
else
    fail "the flattened POM is missing or still carries a property"
fi
[ "$FAIL" -ne 0 ] && finish
cp "$JAR" "$OUT/$ARTIFACT-$VERSION.jar"
cp "$MAVEN_BUILD/sipral-jvm-$VERSION-sources.jar" "$OUT/$ARTIFACT-$VERSION-sources.jar"
# The variant with libopus is an artefact of its own name: the project's
# own artifactId, the first one in the POM, becomes it.
sed "0,/<artifactId>sipral-jvm<\/artifactId>/s//<artifactId>$ARTIFACT<\/artifactId>/" "$POM" \
    >"$OUT/$ARTIFACT-$VERSION.pom"
pass "$ARTIFACT-$VERSION.jar, -sources.jar and .pom in $OUT"

if [ "$DRY_RUN" -eq 0 ] && [ "$QEMU" -eq 1 ]; then
    step "the loopback tests on an arm64 JVM, under qemu-aarch64 (unprivileged, no binfmt)"
    QEMU_DIR="$OUT/qemu"
    ROOTFS="$CACHE/arm64-jre-rootfs"
    mkdir -p "$QEMU_DIR"
    if [ -f "$ROOTFS/.complete" ]; then
        pass "the arm64 JRE's filesystem, reused from $ROOTFS"
    else
        rm -rf "$ROOTFS"
        mkdir -p "$ROOTFS"
        name="sipral-arm64-jre-$$"
        # docker create, never run: nothing arm64 executes to get the files.
        if docker create --platform linux/arm64 --name "$name" eclipse-temurin:21-jre true >/dev/null 2>"$QEMU_DIR/rootfs.log" \
            && docker export "$name" | tar -xf - -C "$ROOTFS" 2>>"$QEMU_DIR/rootfs.log"; then
            touch "$ROOTFS/.complete"
            pass "the arm64 JRE's filesystem, exported from eclipse-temurin:21-jre"
        else
            fail "could not export eclipse-temurin:21-jre for linux/arm64:"
            sed 's/^/        /' "$QEMU_DIR/rootfs.log"
        fi
        docker rm "$name" >/dev/null 2>&1
    fi
    rm -rf "$QEMU_DIR/lib"
    if [ "$FAIL" -eq 0 ] && mvn "${MVN_ARGS[@]}" -q dependency:copy-dependencies -DincludeScope=runtime \
        -DoutputDirectory="$QEMU_DIR/lib" >"$QEMU_DIR/dependencies.log" 2>&1 \
        && mvn "${MVN_ARGS[@]}" -q dependency:copy \
        -Dartifact="org.junit.platform:junit-platform-console-standalone:$JUNIT_PLATFORM_VERSION" \
        -DoutputDirectory="$QEMU_DIR/lib" >>"$QEMU_DIR/dependencies.log" 2>&1; then
        pass "the jar's runtime dependencies and the JUnit console launcher"
    elif [ "$FAIL" -eq 0 ]; then
        fail "copying the test's dependencies:"
        tail -20 "$QEMU_DIR/dependencies.log" | sed 's/^/        /'
    fi
    if [ "$FAIL" -eq 0 ]; then
        classpath="/jar/$(basename "$JAR"):/tests"
        for dependency in "$QEMU_DIR"/lib/*.jar; do
            case "$(basename "$dependency")" in
                junit-platform-console-standalone-*) ;;
                *) classpath="$classpath:/deps/$(basename "$dependency")" ;;
            esac
        done
        java_bin=$(find "$ROOTFS/opt/java" -path '*/bin/java' -type f 2>/dev/null | head -1)
        java_bin="/rootfs/${java_bin#"$ROOTFS"/}"
        if out=$(docker run --rm \
            -v "$ROOTFS:/rootfs:ro" -v "$MAVEN_BUILD:/jar:ro" -v "$MAVEN_BUILD/test-classes:/tests:ro" \
            -v "$QEMU_DIR/lib:/deps:ro" \
            debian:trixie-slim sh -c "
                apt-get update -qq >/dev/null && apt-get install -qq -y --no-install-recommends qemu-user >/dev/null 2>&1
                qemu-aarch64 -L /rootfs $java_bin -Xcheck:jni -jar /deps/junit-platform-console-standalone-$JUNIT_PLATFORM_VERSION.jar \
                    execute --disable-banner --details=summary --fail-if-no-tests \
                    --class-path '$classpath' \
                    --select-class org.sipral.jvm.LoopbackCallKotlinIT \
                    --select-class org.sipral.jvm.LoopbackCallJavaIT \
                    --select-class org.sipral.jvm.SipralNativesTest
            " 2>&1); then
            succeeded=$(printf '%s\n' "$out" | sed -n 's/.*\[ *\([0-9]*\) tests successful *\].*/\1/p' | tail -1)
            pass "on linux-arm64: ${succeeded:-all} tests successful, the Kotlin and the Java loopback call among them"
        else
            fail "the tests on an arm64 JVM under qemu-aarch64:"
            printf '%s\n' "$out" | tail -40 | sed 's/^/        /'
        fi
        checked=$(printf '%s\n' "$out" | grep -E 'WARNING in native method|FATAL ERROR in native method' || true)
        [ -z "$checked" ] || { fail "-Xcheck:jni on arm64:"; printf '%s\n' "$checked" | head -10 | sed 's/^/        /'; }
    fi
fi

# The SBOM sits beside the jar, from sipral-ffi's own dependency graph
# across every platform the jar carries, as scripts/package/aar.sh does.
# --notices only for the variant whose feature list is
# THIRD-PARTY-LICENSES.txt's own.
if [ "$FAIL" -eq 0 ]; then
    step "SBOM"
    FINAL="$OUT/$ARTIFACT-$VERSION.jar"
    SBOM_ARGS=(--crate sipral-ffi --features "$FFI_FEATURES" --target all
        --artifact-name "$ARTIFACT" --artifact-version "$VERSION"
        --artifact "$FINAL" --out "$FINAL.cdx.json")
    [ "$WITH_OPUS" -eq 1 ] && SBOM_ARGS+=(--notices "$ROOT/THIRD-PARTY-LICENSES.txt")
    if sbom_out=$(cargo run --quiet --locked -p sipral-sbom-gen -- "${SBOM_ARGS[@]}" 2>&1); then
        pass "$(basename "$FINAL").cdx.json"
    else
        fail "sbom-gen:"
        printf '%s\n' "$sbom_out" | sed 's/^/        /'
    fi
fi

finish
