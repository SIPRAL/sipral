#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# The Python artefact: a platform wheel that carries the C ABI's native
# library beside bindings/python/sipral, closing the one thing
# docs/08-ffi.md's Python section lists as not here yet.
#
#   scripts/package/wheels.sh --out DIR [--dry-run] [--publish]
#       this host's own platform: builds sipral-ffi with cargo, for real
#   scripts/package/wheels.sh --out DIR --manylinux [--dry-run] [--publish]
#       linux-x64, manylinux_2_28: needs Docker, re-execs this script inside
#       quay.io/pypa/manylinux_2_28_x86_64
#   ... --with-opus
#       either of the above, as the variant that carries libopus
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
WITH_OPUS=0
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --publish) PUBLISH=1; shift ;;
        --manylinux) MANYLINUX=1; shift ;;
        --inside-manylinux) MANYLINUX=2; shift ;; # internal: this run is already inside the container
        --with-opus) WITH_OPUS=1; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -z "$OUT" ] && { printf 'usage: wheels.sh --out DIR [--dry-run] [--publish] [--manylinux] [--with-opus]\n' >&2; exit 2; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
. "$ROOT/scripts/package/features.sh"
package_features "$WITH_OPUS" || { printf 'no default feature list in crates/sipral-ffi/Cargo.toml\n' >&2; exit 1; }

if [ "$MANYLINUX" -eq 1 ]; then
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

step "host"
UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"
if [ "$MANYLINUX" -eq 2 ]; then
    TAG="manylinux_2_28_x86_64"
    RUST_TRIPLE="x86_64-unknown-linux-gnu"
    NATIVE="libsipral_ffi.so"
    PY=python3
    pass "inside manylinux_2_28_x86_64: tag $TAG"
elif [ "$UNAME_S" = "Darwin" ]; then
    case "$UNAME_M" in
        arm64) RUST_TRIPLE="aarch64-apple-darwin"; MACOS_ARCH="arm64" ;;
        x86_64) RUST_TRIPLE="x86_64-apple-darwin"; MACOS_ARCH="x86_64" ;;
        *) fail "unrecognised macOS arch: $UNAME_M"; printf '\nwheels.sh: failed\n'; exit 1 ;;
    esac
    macos_major=$(sw_vers -productVersion | cut -d. -f1)
    TAG="macosx_${macos_major}_0_${MACOS_ARCH}"
    NATIVE="libsipral_ffi.dylib"
    PY=python3
    pass "macOS $(sw_vers -productVersion) $UNAME_M: tag $TAG"
elif [ "$UNAME_S" = "Linux" ]; then
    case "$UNAME_M" in
        x86_64) RUST_TRIPLE="x86_64-unknown-linux-gnu" ;;
        *) fail "unrecognised Linux arch: $UNAME_M (only x86_64, and only via --manylinux, is wired up)"; printf '\nwheels.sh: failed\n'; exit 1 ;;
    esac
    TAG="linux_x86_64"
    NATIVE="libsipral_ffi.so"
    PY=python3
    pass "Linux $UNAME_M, outside manylinux: tag $TAG (portable only to a like-built host; use --manylinux for a distributable tag)"
else
    fail "unsupported host: $UNAME_S"; printf '\nwheels.sh: failed\n'; exit 1
fi

STAGE="$OUT/_stage"
rm -rf "$STAGE"
mkdir -p "$STAGE"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

step "building sipral-ffi, release, $VARIANT_LABEL (features $FFI_FEATURES)"
if cargo build --release -p sipral-ffi "${FFI_FEATURE_ARGS[@]}" --target "$RUST_TRIPLE" >"$STAGE/build.log" 2>&1; then
    pass "cargo build --release -p sipral-ffi ${FFI_FEATURE_ARGS[*]} --target $RUST_TRIPLE"
else
    fail "cargo build --release -p sipral-ffi ${FFI_FEATURE_ARGS[*]} --target $RUST_TRIPLE:"
    tail -30 "$STAGE/build.log" | sed 's/^/        /'
    printf '\nwheels.sh: failed\n'; exit 1
fi
NATIVE_PATH="$TARGET_DIR/$RUST_TRIPLE/release/$NATIVE"
[ -f "$NATIVE_PATH" ] || { fail "$NATIVE_PATH was not produced"; printf '\nwheels.sh: failed\n'; exit 1; }

step "a build-only virtualenv for hatchling and wheel"
"$PY" -m venv "$STAGE/venv" >"$STAGE/venv.log" 2>&1 && pass "$PY -m venv" || {
    fail "$PY -m venv:"; tail -20 "$STAGE/venv.log" | sed 's/^/        /'; printf '\nwheels.sh: failed\n'; exit 1
}
VENV_PY="$STAGE/venv/bin/python"
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

# The variant with libopus is its own distribution, sipral-opus: `wheel pack`
# names the file after the .dist-info directory, and pip reads the name out
# of METADATA, so both change and nothing else does. The package inside is
# still `sipral`, imported the same way.
DIST_INFO=$(dirname "$WHEEL_METADATA")
DIST_NAME="sipral"
if [ "$WITH_OPUS" -eq 1 ]; then
    DIST_NAME="sipral-opus"
    dist_version=$(basename "$DIST_INFO" .dist-info)
    dist_version="${dist_version#sipral-}"
    if grep -q '^Name: sipral$' "$DIST_INFO/METADATA" \
        && sed 's/^Name: sipral$/Name: sipral-opus/' "$DIST_INFO/METADATA" >"$DIST_INFO/METADATA.new" \
        && mv "$DIST_INFO/METADATA.new" "$DIST_INFO/METADATA" \
        && mv "$DIST_INFO" "$DISTDIR/sipral_opus-$dist_version.dist-info"; then
        pass "renamed sipral-opus $dist_version, for the variant that carries libopus"
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
    if printf '%s\n' "$listing" | grep -q "sipral/$NATIVE"; then
        pass "$(basename "$FINAL") carries sipral/$NATIVE"
    else
        fail "$(basename "$FINAL") is missing sipral/$NATIVE"
    fi
    if printf '%s\n' "$listing" | grep -q 'sipral/stack.py'; then
        pass "$(basename "$FINAL") carries the idiomatic layer (stack.py)"
    else
        fail "$(basename "$FINAL") is missing sipral/stack.py"
    fi
else
    fail "no tagged wheel in $OUT"
fi

if [ "$DRY_RUN" -eq 0 ] && [ -n "$FINAL" ]; then
    step "importing it for real"
    INSTALL_VENV="$STAGE/install-venv"
    "$PY" -m venv "$INSTALL_VENV" >/dev/null 2>&1
    if "$INSTALL_VENV/bin/pip" install --quiet "$FINAL" >"$STAGE/install.log" 2>&1 \
        && "$INSTALL_VENV/bin/python" -c 'import sipral; print(sipral.__name__)' >"$STAGE/import.log" 2>&1; then
        pass "installed into a clean venv and imported: $(cat "$STAGE/import.log")"
    else
        fail "install-and-import, into a clean venv:"
        cat "$STAGE/install.log" "$STAGE/import.log" 2>/dev/null | sed 's/^/        /'
    fi
fi

if [ "$PUBLISH" -eq 1 ]; then
    step "publish"
    printf '  not run: nothing ships to PyPI before the ABI freezes (docs/08-ffi.md).\n'
    printf '  What the owner runs once it has: twine upload %s\n' "${FINAL:-$OUT/*.whl}"
fi

printf '\n'
[ "$FAIL" -eq 0 ] && { printf 'wheels.sh: done, %s, %s\n' "${FINAL:-$OUT}" "$VARIANT_LABEL"; exit 0; }
printf 'wheels.sh: failed\n'; exit 1
