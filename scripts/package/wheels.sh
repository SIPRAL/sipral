#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# The Python artefact: a platform wheel that carries the C ABI's native
# library beside bindings/python/sipral, closing the one thing
# docs/08-ffi.md's Python section lists as not here yet.
#
#   scripts/package/wheels.sh --out DIR [--dry-run] [--publish]
#       this host's own platform: builds sipral-ffi with cargo, for real --
#       macOS (arm64 or x86_64), Linux x86_64 outside manylinux, or Windows
#       under Git Bash with the MSVC Rust toolchain (win_amd64, win_arm64)
#   scripts/package/wheels.sh --out DIR --manylinux [--dry-run] [--publish]
#       linux-x64, manylinux_2_28: needs Docker, re-execs this script inside
#       quay.io/pypa/manylinux_2_28_x86_64
#   scripts/package/wheels.sh --out DIR --linux-arm64 [--dry-run] [--publish]
#       linux-arm64, manylinux_2_28: needs Docker, no arm64 hardware --
#       cross-compiles in scripts/package/aarch64-cross.sh's container, and
#       proves the result runs with scripts/package/qemu-verify.sh (qemu-user,
#       unprivileged, no binfmt)
#   ... --with-opus
#       any of the above, as the variant that carries libopus
#
# --manylinux and --linux-arm64 under --dry-run on a host without Docker
# prove what that host can: sipral-ffi type-checked for the wheel's target
# with the package's features. Building it, its glibc floor and the run
# under qemu are a Docker host's, and the run says so.
#
# Every wheel carries the licence texts from the repository root in its
# .dist-info/licenses (PEP 639), named by License-File in its METADATA.
#
# Without --with-opus the native is built without sipral-ffi's `opus`
# feature and every other default kept (features.sh says why and how). With
# it, the wheel is the distribution `sipral-opus` instead of `sipral`
# (sipral_opus-<version>-...whl, `Name: sipral-opus` in its METADATA), the
# same `sipral` package inside, so that the two cannot be told apart only by
# their contents.
#
# bindings/python/sipral is loaded as it is committed: sipral/_sipral_cffi.py
# already looks for the native library beside the package
# (docs/08-ffi.md, "_candidates") before it looks anywhere else writable, so
# a wheel that places the library there needs no change to that file, or to
# bindings/python/pyproject.toml, to be found at import time.
#
# maturin was the tool the plan named, and is not the tool this uses: its
# cffi bindings mode compiles a cffi *API-mode* extension from a build
# script maturin owns, which is a second load path beside the ABI-mode
# dlopen bindings/python/sipral/_sipral_cffi.py already is and ships. What
# this uses instead is the `wheel` package's own unpack/pack/tags -- the
# same primitives cibuildwheel and delocate repair a wheel with -- to take
# the ordinary py3-none-any wheel bindings/python/pyproject.toml's
# hatchling backend already builds, add the one native file, and retag it
# for the platform that native was built for. Nothing about how the
# bindings load changes; what ships now is what was missing.
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
step() { printf '\n%s\n' "$1"; }

OUT=""
DRY_RUN=0
PUBLISH=0
MANYLINUX=0
LINUX_ARM64=0
INSIDE_LINUX_ARM64=0
WITH_OPUS=0
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --publish) PUBLISH=1; shift ;;
        --manylinux) MANYLINUX=1; shift ;;
        --inside-manylinux) MANYLINUX=2; shift ;; # internal: this run is already inside the container
        --linux-arm64) LINUX_ARM64=1; shift ;;
        --inside-linux-arm64) INSIDE_LINUX_ARM64=1; shift ;; # internal: already inside the cross image
        --with-opus) WITH_OPUS=1; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -z "$OUT" ] && { printf 'usage: wheels.sh --out DIR [--dry-run] [--publish] [--manylinux] [--linux-arm64] [--with-opus]\n' >&2; exit 2; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
. "$ROOT/scripts/package/features.sh"
package_features "$WITH_OPUS" || { printf 'no default feature list in crates/sipral-ffi/Cargo.toml\n' >&2; exit 1; }

step "one version"
scripts/version.sh --check || { printf '\nwheels.sh: failed\n'; exit 1; }

# `dry_run_without_docker TRIPLE LABEL WHAT`: --manylinux or --linux-arm64
# under --dry-run with no Docker here. The variant with libopus vendors a C
# build that needs the container's cross compiler, so the type check runs
# with the default package's features either way.
dry_run_without_docker() {
    step "$2, --dry-run on a host without Docker"
    package_features 0
    if ! rustup target list --installed 2>/dev/null | found -x "$1"; then
        fail "$1 is not installed: rustup target add $1"
    elif cargo check -p sipral-ffi "${FFI_FEATURE_ARGS[@]}" --target "$1" >"$OUT/check-$1.log" 2>&1; then
        pass "cargo check -p sipral-ffi ${FFI_FEATURE_ARGS[*]} --target $1"
    else
        fail "cargo check -p sipral-ffi --target $1:"; tail -30 "$OUT/check-$1.log" | sed 's/^/        /'
    fi
    printf '  note  not run here, a Docker host'"'"'s: %s\n' "$3"
    printf '\n'
    [ "$FAIL" -eq 0 ] && { printf 'wheels.sh: done (dry-run, no Docker), %s\n' "$2"; exit 0; }
    printf 'wheels.sh: failed\n'; exit 1
}

if [ "$MANYLINUX" -eq 1 ]; then
    command -v docker >/dev/null 2>&1 || [ "$DRY_RUN" -eq 0 ] \
        || dry_run_without_docker x86_64-unknown-linux-gnu manylinux_2_28_x86_64 \
            "the build in quay.io/pypa/manylinux_2_28_x86_64 and the wheel made there"
    step "manylinux_2_28_x86_64, via Docker"
    command -v docker >/dev/null 2>&1 || { fail "docker not found"; printf '\nwheels.sh: failed\n'; exit 1; }
    args=(--out /out --inside-manylinux)
    [ "$DRY_RUN" -eq 1 ] && args+=(--dry-run)
    [ "$PUBLISH" -eq 1 ] && args+=(--publish)
    [ "$WITH_OPUS" -eq 1 ] && args+=(--with-opus)
    # The image carries no Rust: rustup, pinned to rust-toolchain.toml's own
    # channel, is installed once inside this disposable container rather
    # than assumed or left to whatever "stable" would resolve to.
    RUSTC_VERSION=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml")
    if docker run --rm -v "$ROOT:/work:ro" -v "$OUT:/out" -w /work \
        -e CARGO_TARGET_DIR=/tmp/target \
        quay.io/pypa/manylinux_2_28_x86_64 \
        sh -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain $RUSTC_VERSION >/tmp/rustup.log 2>&1 && . \"\$HOME/.cargo/env\" && cd /work && bash scripts/package/wheels.sh ${args[*]}"; then
        pass "container run"
    else
        fail "container run"
    fi
    printf '\n'
    [ "$FAIL" -eq 0 ] && { printf 'wheels.sh: done, %s\n' "$OUT"; exit 0; }
    printf 'wheels.sh: failed\n'; exit 1
fi

if [ "$LINUX_ARM64" -eq 1 ]; then
    command -v docker >/dev/null 2>&1 || [ "$DRY_RUN" -eq 0 ] \
        || dry_run_without_docker aarch64-unknown-linux-gnu manylinux_2_28_aarch64 \
            "the cross build in the aarch64 cross image, its glibc 2.28 check, and the wheel imported and tested under qemu (qemu-verify.sh)"
    step "manylinux_2_28_aarch64, cross-compiled (no arm64 hardware), via Docker"
    command -v docker >/dev/null 2>&1 || { fail "docker not found (linux-arm64 cross-compiles in a container)"; printf '\nwheels.sh: failed\n'; exit 1; }
    . "$ROOT/scripts/package/aarch64-cross.sh"
    aarch64_cross_ensure_image || { fail "could not build the aarch64 cross image (scripts/package/docker/aarch64-cross.Dockerfile)"; printf '\nwheels.sh: failed\n'; exit 1; }
    pass "$AARCH64_CROSS_IMAGE"
    args=(--out /out --inside-linux-arm64)
    [ "$DRY_RUN" -eq 1 ] && args+=(--dry-run)
    [ "$WITH_OPUS" -eq 1 ] && args+=(--with-opus)
    CARGO_TARGET="$OUT/cargo-target"
    mkdir -p "$CARGO_TARGET"
    # The inner run's own host is this same image, whose Python (unlike
    # whatever invoked docker) is guaranteed to have a working venv module
    # -- the same reason --manylinux re-execs into its own container rather
    # than trusting the outer host's Python either. CARGO_TARGET_DIR is
    # bind-mounted (not left at the container's default) so the native this
    # produces is still on the host afterwards, for qemu-verify.sh below.
    if docker run --rm -v "$ROOT:/work:ro" -v "$OUT:/out" -v "$CARGO_TARGET:/tmp/target" -w /work \
        -e CARGO_TARGET_DIR=/tmp/target \
        "$AARCH64_CROSS_IMAGE" \
        bash scripts/package/wheels.sh "${args[@]}"; then
        pass "container run"
    else
        fail "container run"
    fi
    NATIVE_PATH="$CARGO_TARGET/aarch64-unknown-linux-gnu/release/libsipral_ffi.so"
    FINAL=$(find "$OUT" -maxdepth 1 -name 'sipral*-manylinux_2_28_aarch64.whl' | head -1)
    if [ "$FAIL" -eq 0 ] && [ -n "$FINAL" ] && [ -s "$NATIVE_PATH" ]; then
        step "importing it for real (qemu-aarch64, unprivileged)"
        qv_args=(--native "$NATIVE_PATH" --wheel "$FINAL" --out "$OUT/qemu-verify")
        [ "$DRY_RUN" -eq 1 ] && qv_args+=(--dry-run)
        if bash "$ROOT/scripts/package/qemu-verify.sh" "${qv_args[@]}" >"$OUT/qemu-verify.log" 2>&1; then
            pass "qemu-verify.sh ${qv_args[*]}"
        else
            fail "qemu-verify.sh ${qv_args[*]}:"
            tail -60 "$OUT/qemu-verify.log" | sed 's/^/        /'
        fi
    fi
    if [ "$PUBLISH" -eq 1 ]; then
        step "publish"
        printf '  not run: the owner publishes, every wheel of the release together:\n'
        printf '    twine upload %s\n' "${FINAL:-$OUT/*.whl}"
    fi
    printf '\n'
    [ "$FAIL" -eq 0 ] && { printf 'wheels.sh: done, %s, linux-arm64\n' "${FINAL:-$OUT}"; exit 0; }
    printf 'wheels.sh: failed\n'; exit 1
fi

CROSS_AARCH64=0
step "host"
UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"
if [ "$INSIDE_LINUX_ARM64" -eq 1 ]; then
    TAG="manylinux_2_28_aarch64"
    RUST_TRIPLE="aarch64-unknown-linux-gnu"
    NATIVE="libsipral_ffi.so"
    PY=python3
    CROSS_AARCH64=1
    pass "inside the aarch64 cross image: tag $TAG"
elif [ "$MANYLINUX" -eq 2 ]; then
    TAG="manylinux_2_28_x86_64"
    RUST_TRIPLE="x86_64-unknown-linux-gnu"
    NATIVE="libsipral_ffi.so"
    PY=python3
    pass "inside manylinux_2_28_x86_64: tag $TAG"
elif [ "$UNAME_S" = "Darwin" ]; then
    # The wheel's platform tag is a promise pip checks before it installs,
    # so it is the oldest macOS the native is built for (apple.sh), read back
    # from the library once it exists -- never this host's own version, which
    # would refuse every older macOS the library runs on.
    case "$UNAME_M" in
        arm64) RUST_TRIPLE="aarch64-apple-darwin"; MACOS_ARCH="arm64" ;;
        x86_64) RUST_TRIPLE="x86_64-apple-darwin"; MACOS_ARCH="x86_64" ;;
        *) fail "unrecognised macOS arch: $UNAME_M"; printf '\nwheels.sh: failed\n'; exit 1 ;;
    esac
    . "$ROOT/scripts/package/apple.sh"
    TAG=""
    NATIVE="libsipral_ffi.dylib"
    PY=python3
    pass "macOS $(sw_vers -productVersion) $UNAME_M: native built for macOS $APPLE_MACOS_MIN and later"
elif [ "$UNAME_S" = "Linux" ]; then
    case "$UNAME_M" in
        x86_64) RUST_TRIPLE="x86_64-unknown-linux-gnu" ;;
        *) fail "unrecognised Linux arch: $UNAME_M (only x86_64, and only via --manylinux, is wired up)"; printf '\nwheels.sh: failed\n'; exit 1 ;;
    esac
    TAG="linux_x86_64"
    NATIVE="libsipral_ffi.so"
    PY=python3
    pass "Linux $UNAME_M, outside manylinux: tag $TAG (portable only to a like-built host; use --manylinux for a distributable tag)"
elif case "$UNAME_S" in MINGW*|MSYS*|CYGWIN*) true ;; *) false ;; esac; then
    # Git Bash on Windows, with Rust's MSVC toolchain: the wheel's tag is
    # the architecture's alone, since a DLL names no minimum Windows release
    # the way a Mach-O names a macOS one.
    case "$UNAME_M" in
        x86_64) RUST_TRIPLE="x86_64-pc-windows-msvc"; TAG="win_amd64" ;;
        aarch64|arm64) RUST_TRIPLE="aarch64-pc-windows-msvc"; TAG="win_arm64" ;;
        *) fail "unrecognised Windows arch: $UNAME_M"; printf '\nwheels.sh: failed\n'; exit 1 ;;
    esac
    NATIVE="sipral_ffi.dll"
    PY=python
    command -v python3 >/dev/null 2>&1 && PY=python3
    pass "Windows $UNAME_M ($UNAME_S): tag $TAG"
else
    fail "unsupported host: $UNAME_S"; printf '\nwheels.sh: failed\n'; exit 1
fi

STAGE="$OUT/_stage"
rm -rf "$STAGE"
mkdir -p "$STAGE"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
[ "$UNAME_S" = "Darwin" ] && [ "$MANYLINUX" -eq 0 ] && TARGET_DIR="$(apple_target_dir "$TARGET_DIR")"

step "building sipral-ffi, release, $VARIANT_LABEL (features $FFI_FEATURES)"
if cargo build --release -p sipral-ffi "${FFI_FEATURE_ARGS[@]}" --target "$RUST_TRIPLE" \
    --target-dir "$TARGET_DIR" >"$STAGE/build.log" 2>&1; then
    pass "cargo build --release -p sipral-ffi ${FFI_FEATURE_ARGS[*]} --target $RUST_TRIPLE"
else
    fail "cargo build --release -p sipral-ffi ${FFI_FEATURE_ARGS[*]} --target $RUST_TRIPLE:"
    tail -30 "$STAGE/build.log" | sed 's/^/        /'
    printf '\nwheels.sh: failed\n'; exit 1
fi
NATIVE_PATH="$TARGET_DIR/$RUST_TRIPLE/release/$NATIVE"
[ -f "$NATIVE_PATH" ] || { fail "$NATIVE_PATH was not produced"; printf '\nwheels.sh: failed\n'; exit 1; }

# On macOS the tag is read back from the library itself, so the wheel
# promises what was built. The static archive the same build wrote beside it
# still has every object's own minimum, libopus's included, which the linked
# library no longer shows: none may be newer than the tag.
if [ "$UNAME_S" = "Darwin" ] && [ "$MANYLINUX" -eq 0 ]; then
    built_min=$(apple_min_versions "$NATIVE_PATH" | tail -1)
    if [ "$built_min" != "$APPLE_MACOS_MIN" ]; then
        fail "$NATIVE was built for macOS ${built_min:-(none named)}, not $APPLE_MACOS_MIN"
        printf '\nwheels.sh: failed\n'; exit 1
    fi
    ARCHIVE_PATH="$TARGET_DIR/$RUST_TRIPLE/release/libsipral_ffi.a"
    if ! newest=$(apple_min_at_most "$ARCHIVE_PATH" "$APPLE_MACOS_MIN"); then
        fail "an object in $ARCHIVE_PATH was built for macOS ${newest:-(none named)}, newer than $APPLE_MACOS_MIN"
        printf '\nwheels.sh: failed\n'; exit 1
    fi
    # pip's tags: from macOS 11 on only the major version counts, and the
    # minor is always 0
    TAG="macosx_${built_min%%.*}_0_${MACOS_ARCH}"
    pass "$NATIVE and every object in its build were built for macOS $APPLE_MACOS_MIN or older: tag $TAG"
fi

step "a build-only virtualenv for hatchling and wheel"
"$PY" -m venv "$STAGE/venv" >"$STAGE/venv.log" 2>&1 && pass "$PY -m venv" || {
    fail "$PY -m venv:"; tail -20 "$STAGE/venv.log" | sed 's/^/        /'; printf '\nwheels.sh: failed\n'; exit 1
}
VENV_PY="$STAGE/venv/bin/python"
# a venv on Windows keeps its interpreter under Scripts/
[ -x "$VENV_PY" ] || VENV_PY="$STAGE/venv/Scripts/python.exe"
if "$VENV_PY" -m pip install --quiet hatchling 'wheel>=0.36' >"$STAGE/pip.log" 2>&1; then
    pass "pip install hatchling wheel, into the build venv"
else
    fail "pip install hatchling wheel:"; tail -30 "$STAGE/pip.log" | sed 's/^/        /'
    printf '\nwheels.sh: failed\n'; exit 1
fi

step "the pure wheel, from bindings/python's own hatchling backend"
mkdir -p "$STAGE/purewheel"
if "$VENV_PY" -m pip wheel "$ROOT/bindings/python" --no-deps --no-build-isolation \
    -w "$STAGE/purewheel" >"$STAGE/wheel-build.log" 2>&1; then
    pass "pip wheel bindings/python"
else
    fail "pip wheel bindings/python:"; tail -30 "$STAGE/wheel-build.log" | sed 's/^/        /'
    printf '\nwheels.sh: failed\n'; exit 1
fi
PUREWHEEL=$(find "$STAGE/purewheel" -maxdepth 1 -name '*.whl' | head -1)
[ -z "$PUREWHEEL" ] && { fail "no wheel came out of pip wheel"; printf '\nwheels.sh: failed\n'; exit 1; }
pass "$(basename "$PUREWHEEL")"

step "the native library, bundled in"
UNPACKED="$STAGE/unpacked"
rm -rf "$UNPACKED"
"$VENV_PY" -m wheel unpack "$PUREWHEEL" --dest "$UNPACKED" >"$STAGE/unpack.log" 2>&1 \
    && pass "wheel unpack" || { fail "wheel unpack:"; tail -20 "$STAGE/unpack.log" | sed 's/^/        /'; printf '\nwheels.sh: failed\n'; exit 1; }
DISTDIR=$(find "$UNPACKED" -mindepth 1 -maxdepth 1 -type d | head -1)
[ -d "$DISTDIR/sipral" ] || { fail "$DISTDIR has no sipral/ to place the native beside"; printf '\nwheels.sh: failed\n'; exit 1; }
cp "$NATIVE_PATH" "$DISTDIR/sipral/$NATIVE"
pass "$NATIVE placed in $(basename "$DISTDIR")/sipral/"

# hatchling built this wheel pure -- Root-Is-Purelib: true, meaning pip
# installs it into purelib. It is not pure any more: a platform's native
# library now sits beside sipral, and `wheel tags` below only ever changes
# the filename's tag, never this line. On every venv this is tested against,
# purelib and platlib are one directory, so the wrong flag does not show up
# there; on a host where they differ (a multiarch Linux distutils install is
# the common one), it would still install to the wrong tree.
WHEEL_METADATA=$(find "$DISTDIR" -maxdepth 1 -name '*.dist-info' -print -quit)/WHEEL
if [ -f "$WHEEL_METADATA" ] && grep -q '^Root-Is-Purelib: true$' "$WHEEL_METADATA"; then
    sed 's/^Root-Is-Purelib: true$/Root-Is-Purelib: false/' "$WHEEL_METADATA" >"$WHEEL_METADATA.new" \
        && mv "$WHEEL_METADATA.new" "$WHEEL_METADATA" \
        && pass "Root-Is-Purelib: false, now that a native is bundled in" \
        || fail "could not flip Root-Is-Purelib in $WHEEL_METADATA"
else
    fail "$WHEEL_METADATA has no 'Root-Is-Purelib: true' line to flip"
fi
[ "$FAIL" -ne 0 ] && { printf '\nwheels.sh: failed\n'; exit 1; }

# The licence texts, which PEP 639 keeps inside the project directory and
# so cannot be named from bindings/python/pyproject.toml: the AGPL, the
# commercial arm, and the third-party licences and notices of what the
# native links. Each is named by a License-File line beside
# License-Expression in METADATA, and `wheel pack` below writes RECORD over
# them.
LICENCE_FILES=(LICENSE LICENSE-COMMERCIAL.md THIRD-PARTY-LICENSES.txt THIRD-PARTY-NOTICES.md)
DIST_INFO=$(dirname "$WHEEL_METADATA")
mkdir -p "$DIST_INFO/licenses"
for f in "${LICENCE_FILES[@]}"; do cp "$ROOT/$f" "$DIST_INFO/licenses/$f"; done
if grep -q '^License-Expression: ' "$DIST_INFO/METADATA" \
    && awk -v files="${LICENCE_FILES[*]}" '
        { print }
        /^License-Expression: / && !done {
            n = split(files, f, " ")
            for (i = 1; i <= n; i++) print "License-File: " f[i]
            done = 1
        }' "$DIST_INFO/METADATA" >"$DIST_INFO/METADATA.new" \
    && mv "$DIST_INFO/METADATA.new" "$DIST_INFO/METADATA"; then
    pass "${LICENCE_FILES[*]} in .dist-info/licenses, named in METADATA"
else
    fail "no License-Expression in METADATA to name the licence files beside"
fi
[ "$FAIL" -ne 0 ] && { printf '\nwheels.sh: failed\n'; exit 1; }

# The variant with libopus is its own distribution, sipral-opus: `wheel pack`
# names the file after the .dist-info directory, and pip reads the name out
# of METADATA, so both change and nothing else does. The package inside is
# still `sipral`, imported the same way.
DIST_NAME="sipral"
DIST_VERSION=$(basename "$DIST_INFO" .dist-info)
DIST_VERSION="${DIST_VERSION#sipral-}"
if [ "$WITH_OPUS" -eq 1 ]; then
    DIST_NAME="sipral-opus"
    if grep -q '^Name: sipral$' "$DIST_INFO/METADATA" \
        && sed 's/^Name: sipral$/Name: sipral-opus/' "$DIST_INFO/METADATA" >"$DIST_INFO/METADATA.new" \
        && mv "$DIST_INFO/METADATA.new" "$DIST_INFO/METADATA" \
        && mv "$DIST_INFO" "$DISTDIR/sipral_opus-$DIST_VERSION.dist-info"; then
        pass "renamed sipral-opus $DIST_VERSION, for the variant that carries libopus"
    else
        fail "could not rename $(basename "$DIST_INFO") to the sipral-opus distribution"
    fi
fi
[ "$FAIL" -ne 0 ] && { printf '\nwheels.sh: failed\n'; exit 1; }

REPACKED="$STAGE/repacked"
mkdir -p "$REPACKED"
"$VENV_PY" -m wheel pack "$DISTDIR" --dest-dir "$REPACKED" >"$STAGE/pack.log" 2>&1 \
    && pass "wheel pack" || { fail "wheel pack:"; tail -20 "$STAGE/pack.log" | sed 's/^/        /'; printf '\nwheels.sh: failed\n'; exit 1; }
PACKED=$(find "$REPACKED" -maxdepth 1 -name '*.whl' | head -1)

step "retagging for $TAG"
retag_log="$STAGE/tags.log"
if "$VENV_PY" -m wheel tags --python-tag py3 --abi-tag none --platform-tag "$TAG" "$PACKED" >"$retag_log" 2>&1; then
    TAGGED=$(grep -o '[^ ]*\.whl$' "$retag_log" | tail -1)
    if [ -n "$TAGGED" ] && [ -f "$TAGGED" ]; then
        cp "$TAGGED" "$OUT/"
        pass "$(basename "$TAGGED")"
    elif [ -n "$TAGGED" ] && [ -f "$(dirname "$PACKED")/$(basename "$TAGGED")" ]; then
        cp "$(dirname "$PACKED")/$(basename "$TAGGED")" "$OUT/"
        pass "$(basename "$TAGGED")"
    else
        fail "wheel tags ran but did not name the file it wrote:"
        cat "$retag_log" | sed 's/^/        /'
    fi
else
    fail "wheel tags:"; tail -20 "$retag_log" | sed 's/^/        /'
fi
[ "$FAIL" -ne 0 ] && { printf '\nwheels.sh: failed\n'; exit 1; }

# By distribution and tag, so that a wheel of the other variant left in the
# same directory is never the one checked or named.
FINAL=$(find "$OUT" -maxdepth 1 -name "${DIST_NAME//-/_}-*-$TAG.whl" | head -1)
step "structure"
if [ -n "$FINAL" ]; then
    listing=$("$VENV_PY" -m zipfile -l "$FINAL" 2>/dev/null)
    named=$("$VENV_PY" -c 'import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
m = [n for n in z.namelist() if n.endswith(".dist-info/METADATA")]
print(next((l[6:] for l in z.read(m[0]).decode().splitlines() if l.startswith("Name: ")), "") if m else "")' "$FINAL" 2>/dev/null)
    if [ "$named" = "$DIST_NAME" ]; then
        pass "$(basename "$FINAL") is the distribution $DIST_NAME, $VARIANT_LABEL"
    else
        fail "$(basename "$FINAL") names itself '$named' in METADATA, not $DIST_NAME"
    fi
    if printf '%s\n' "$listing" | found "sipral/$NATIVE"; then
        pass "$(basename "$FINAL") carries sipral/$NATIVE"
    else
        fail "$(basename "$FINAL") is missing sipral/$NATIVE"
    fi
    if printf '%s\n' "$listing" | found 'sipral/stack.py'; then
        pass "$(basename "$FINAL") carries the idiomatic layer (stack.py)"
    else
        fail "$(basename "$FINAL") is missing sipral/stack.py"
    fi
    for f in "${LICENCE_FILES[@]}"; do
        printf '%s\n' "$listing" | found "\.dist-info/licenses/$f" \
            && pass "$(basename "$FINAL") carries .dist-info/licenses/$f" \
            || fail "$(basename "$FINAL") is missing .dist-info/licenses/$f"
    done
else
    fail "no tagged wheel in $OUT"
fi

# The SBOM sits beside the wheel it describes, from sipral-ffi's own
# dependency graph at the features and single target this wheel was actually
# built with (docs/10-roadmap.md). THIRD-PARTY-LICENSES.txt lists the graph
# across every target, not one: a single target's graph is a subset of it
# (x86_64 Linux has no libc crate, which aarch64 and macOS pull in), so the
# variant whose feature list is that file's own (no flags at all, opus
# included) is checked against it with a second, all-target graph, written
# to a scratch file and thrown away.
if [ -n "$FINAL" ]; then
    step "SBOM"
    SBOM="$FINAL.cdx.json"
    if sbom_out=$(cargo run --quiet -p sipral-sbom-gen -- \
        --crate sipral-ffi --features "$FFI_FEATURES" --target "$RUST_TRIPLE" \
        --artifact-name "$DIST_NAME" --artifact-version "$DIST_VERSION" \
        --artifact "$FINAL" --out "$SBOM" 2>&1); then
        pass "$(basename "$SBOM")"
    else
        fail "sbom-gen:"; printf '%s\n' "$sbom_out" | sed 's/^/        /'
    fi
    if [ "$WITH_OPUS" -eq 1 ]; then
        ALL_SBOM=$(mktemp)
        if sbom_out=$(cargo run --quiet -p sipral-sbom-gen -- \
            --crate sipral-ffi --features "$FFI_FEATURES" --target all \
            --artifact-name "$DIST_NAME" --artifact-version "$DIST_VERSION" \
            --out "$ALL_SBOM" --notices "$ROOT/THIRD-PARTY-LICENSES.txt" 2>&1); then
            pass "THIRD-PARTY-LICENSES.txt lists exactly the all-target graph"
        else
            fail "sbom-gen --notices:"; printf '%s\n' "$sbom_out" | sed 's/^/        /'
        fi
        rm -f "$ALL_SBOM"
    fi
fi
[ "$FAIL" -ne 0 ] && { printf '\nwheels.sh: failed\n'; exit 1; }

if [ "$CROSS_AARCH64" -eq 1 ]; then
    # This container's own Python is x86_64 and cannot import an aarch64
    # .so: the outer `--linux-arm64` run (scripts/package/wheels.sh itself,
    # one recursion up) does that with qemu-verify.sh once this inner run
    # returns the wheel and the native it bundled.
    :
elif [ "$DRY_RUN" -eq 0 ] && [ -n "$FINAL" ]; then
    step "importing it for real"
    INSTALL_VENV="$STAGE/install-venv"
    "$PY" -m venv "$INSTALL_VENV" >/dev/null 2>&1
    INSTALL_BIN="$INSTALL_VENV/bin"
    [ -d "$INSTALL_BIN" ] || INSTALL_BIN="$INSTALL_VENV/Scripts"
    if "$INSTALL_BIN/python" -m pip install --quiet "$FINAL" >"$STAGE/install.log" 2>&1 \
        && "$INSTALL_BIN/python" -c 'import sipral; print(sipral.__name__)' >"$STAGE/import.log" 2>&1; then
        pass "installed into a clean venv and imported: $(cat "$STAGE/import.log")"
    else
        fail "install-and-import, into a clean venv:"
        cat "$STAGE/install.log" "$STAGE/import.log" 2>/dev/null | sed 's/^/        /'
    fi
fi

if [ "$PUBLISH" -eq 1 ]; then
    step "publish"
    printf '  not run: the owner publishes, every wheel of the release together:\n'
    printf '    twine upload %s\n' "${FINAL:-$OUT/*.whl}"
fi

printf '\n'
[ "$FAIL" -eq 0 ] && { printf 'wheels.sh: done, %s, %s\n' "${FINAL:-$OUT}" "$VARIANT_LABEL"; exit 0; }
printf 'wheels.sh: failed\n'; exit 1
