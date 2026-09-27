#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# Proves a cross-compiled linux-arm64 artefact actually runs, without ever
# giving it privileges and without registering binfmt on the host: an
# unprivileged container installs qemu-user (the `qemu-user` Debian
# package, `qemu-aarch64`) and runs the aarch64 binaries through it
# explicitly, named on qemu's own command line rather than transparently
# via the kernel's binfmt_misc.
#
#   scripts/package/qemu-verify.sh --native SO_PATH --out DIR [--dry-run]
#       [--wheel WHEEL_PATH]
#
# --dry-run compiles bindings/c/smoke.c for aarch64 (scripts/package/
# aarch64-cross.sh's image) and stops there: it proves the cross toolchain
# still links against the header, without the network-heavy half (pulling
# quay.io/pypa/manylinux_2_28_aarch64, ~2.5 GB, and extracting its
# filesystem as the qemu run's -L rootfs) that a routine check.sh run
# should not pay on every machine. Without --dry-run, that rootfs is
# pulled (and cached at --out/rootfs, reused after the first run) and both
# proofs run for real: the C smoke test, and, with --wheel, installing
# that wheel and running bindings/python/tests against the same native --
# both under qemu, both in a container with no extra capability and no
# --privileged.
set -uo pipefail

cd "$(dirname "$0")/../.."
ROOT="$PWD"

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
step() { printf '\n%s\n' "$1"; }

NATIVE=""
OUT=""
WHEEL=""
DRY_RUN=0
while [ $# -gt 0 ]; do
    case "$1" in
        --native) NATIVE="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --wheel) WHEEL="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -z "$NATIVE" ] && { printf 'usage: qemu-verify.sh --native SO_PATH --out DIR [--wheel WHEEL_PATH] [--dry-run]\n' >&2; exit 2; }
[ -s "$NATIVE" ] || { printf 'no such native library: %s\n' "$NATIVE" >&2; exit 2; }
[ -z "$OUT" ] && { printf 'qemu-verify.sh needs --out DIR\n' >&2; exit 2; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
NATIVE="$(cd "$(dirname "$NATIVE")" && pwd)/$(basename "$NATIVE")"

command -v docker >/dev/null 2>&1 || { fail "docker not found"; printf '\nqemu-verify.sh: failed\n'; exit 1; }

# shellcheck source=aarch64-cross.sh
. "$ROOT/scripts/package/aarch64-cross.sh"
step "the cross image"
if aarch64_cross_ensure_image; then
    pass "$AARCH64_CROSS_IMAGE"
else
    fail "could not build the aarch64 cross image"
    printf '\nqemu-verify.sh: failed\n'; exit 1
fi

step "glibc symbol versions"
if highest=$(aarch64_glibc_check "$NATIVE" 28); then
    pass "$(basename "$NATIVE") links nothing newer than $highest (manylinux_2_28 is GLIBC_2.28)"
else
    fail "$(basename "$NATIVE") is not manylinux_2_28-compatible"
fi

step "the C smoke test, compiled for aarch64"
mkdir -p "$OUT/native"
cp "$NATIVE" "$OUT/native/libsipral_ffi.so"
if docker run --rm -v "$ROOT:/work:ro" -v "$OUT/native:/t" "$AARCH64_CROSS_IMAGE" \
    aarch64-linux-gnu-gcc -std=c11 -Wall -Wextra -Werror -O2 --sysroot=/sysroot -B/sysroot/usr/lib64 \
    -o /t/smoke-aarch64 /work/bindings/c/smoke.c -I /work/bindings/c/include \
    -L /t -lsipral_ffi -Wl,-rpath,/native -Wl,--dynamic-linker=/lib64/ld-linux-aarch64.so.1 \
    >"$OUT/smoke-cc.log" 2>&1; then
    pass "aarch64-linux-gnu-gcc -std=c11 -Wall -Wextra -Werror"
else
    fail "bindings/c/smoke.c does not cross-compile for aarch64:"
    sed 's/^/        /' "$OUT/smoke-cc.log"
fi
[ "$FAIL" -ne 0 ] && { printf '\nqemu-verify.sh: failed\n'; exit 1; }

if [ "$DRY_RUN" -eq 1 ]; then
    printf '\n  not run under qemu (--dry-run): the smoke binary cross-compiles, which is\n'
    printf '  as far as a routine check.sh run should pull quay.io/pypa/manylinux_2_28_aarch64\n'
    printf '  (~2.5 GB) to go. A real packaging run drops --dry-run.\n'
    printf '\nqemu-verify.sh: done (dry-run), %s\n' "$OUT"
    exit 0
fi

step "an aarch64 rootfs for qemu's -L (quay.io/pypa/manylinux_2_28_aarch64, cached)"
ROOTFS="$OUT/rootfs"
if [ -f "$ROOTFS/.complete" ]; then
    pass "reused, $ROOTFS"
else
    rm -rf "$ROOTFS"
    mkdir -p "$ROOTFS"
    name="sipral-arm64-rootfs-extract-$$"
    # docker create, never `run`: nothing in this arm64 image executes to
    # produce the rootfs, so no emulation is needed for this step either.
    if docker create --platform linux/arm64 --name "$name" quay.io/pypa/manylinux_2_28_aarch64 true >/dev/null 2>"$OUT/rootfs.log" \
        && docker export "$name" | tar -xf - -C "$ROOTFS" 2>>"$OUT/rootfs.log"; then
        docker rm "$name" >/dev/null 2>&1
        touch "$ROOTFS/.complete"
        pass "extracted, $ROOTFS"
    else
        docker rm "$name" >/dev/null 2>&1
        fail "could not extract the manylinux_2_28_aarch64 rootfs:"
        sed 's/^/        /' "$OUT/rootfs.log"
        printf '\nqemu-verify.sh: failed\n'; exit 1
    fi
fi

# debian:trixie-slim, not the cross image: qemu-user is an x86_64 program
# that only needs to run, never to cross-compile anything, and this keeps
# the container that gets it unprivileged and disposable rather than
# reusing the (already unprivileged) build image for a different job.
QEMU_RUN() {
    docker run --rm \
        -v "$ROOTFS:/rootfs:ro" \
        -v "$OUT/native:/native:ro" \
        -v "$ROOT:/work:ro" \
        "${EXTRA_MOUNTS[@]}" \
        debian:trixie-slim sh -c "
            apt-get update -qq >/dev/null && apt-get install -qq -y --no-install-recommends qemu-user >/dev/null 2>&1
            $1
        "
}

step "the C smoke test, under qemu-aarch64 (unprivileged, no binfmt)"
EXTRA_MOUNTS=()
if out=$(QEMU_RUN 'qemu-aarch64 -L /rootfs /native/smoke-aarch64' 2>&1); then
    pass "bindings/c/smoke.c, aarch64, under qemu-aarch64"
else
    fail "bindings/c/smoke.c under qemu-aarch64:"
    printf '%s\n' "$out" | sed 's/^/        /'
fi

if [ -n "$WHEEL" ]; then
    [ -s "$WHEEL" ] || { fail "no such wheel: $WHEEL"; printf '\nqemu-verify.sh: failed\n'; exit 1; }
    step "cffi, prefetched for cp312-manylinux_2_28_aarch64 (cached)"
    DEPS="$OUT/deps"
    if [ -f "$DEPS/.complete" ]; then
        pass "reused, $DEPS"
    else
        rm -rf "$DEPS"; mkdir -p "$DEPS"
        if docker run --rm -v "$DEPS:/out" python:3.13-slim sh -c \
            "pip download --quiet --only-binary=:all: --python-version 312 --implementation cp --abi cp312 --platform manylinux_2_28_aarch64 -d /out cffi pycparser" \
            >"$DEPS.log" 2>&1; then
            touch "$DEPS/.complete"
            pass "cffi, pycparser"
        else
            fail "pip download cffi pycparser:"
            sed 's/^/        /' "$DEPS.log"
            printf '\nqemu-verify.sh: failed\n'; exit 1
        fi
    fi

    step "the wheel, installed and imported, under qemu-aarch64"
    mkdir -p "$OUT/wheel"
    cp "$WHEEL" "$OUT/wheel/"
    EXTRA_MOUNTS=(-v "$OUT/wheel:/wheels:ro" -v "$DEPS:/deps:ro")
    # The exact patch version under manylinux_2_28_aarch64's own
    # /opt/_internal moves as that image (pulled as :latest, no pin) is
    # rebuilt upstream, so this globs for whichever cpython-3.12.x is
    # there rather than hardcoding one -- a rootfs with none, or more than
    # one, fails here with a clear reason rather than qemu's own "No such
    # file or directory" three steps later.
    cpython_dir=$(find "$ROOTFS/opt/_internal" -maxdepth 1 -type d -name 'cpython-3.12.*' 2>/dev/null | sort | tail -1)
    if [ -z "$cpython_dir" ] || [ ! -x "$cpython_dir/bin/python3.12" ]; then
        fail "no cpython-3.12.x/bin/python3.12 under $ROOTFS/opt/_internal (manylinux_2_28_aarch64's own layout changed?)"
        printf '\nqemu-verify.sh: failed\n'; exit 1
    fi
    PY="/rootfs/${cpython_dir#"$ROOTFS"/}/bin/python3.12"
    wheel_name=$(basename "$WHEEL")
    if out=$(QEMU_RUN "qemu-aarch64 -L /rootfs $PY -m pip install --quiet --no-index --find-links /wheels --find-links /deps --target=/tmp/inst /wheels/$wheel_name && qemu-aarch64 -L /rootfs -E PYTHONPATH=/tmp/inst $PY -c \"import sipral; print(sipral.__name__)\"" 2>&1); then
        pass "installed into a clean target dir and imported: $(printf '%s' "$out" | tail -1)"
    else
        fail "install-and-import, under qemu-aarch64:"
        printf '%s\n' "$out" | sed 's/^/        /'
    fi

    step "bindings/python/tests, under qemu-aarch64, against the source tree (test_abi.py compares the header)"
    if out=$(QEMU_RUN "qemu-aarch64 -L /rootfs $PY -m pip install --quiet --no-index --find-links /deps --target=/tmp/inst cffi pycparser && qemu-aarch64 -L /rootfs -E PYTHONPATH=/tmp/inst -E SIPRAL_LIBRARY=/native/libsipral_ffi.so $PY -m unittest discover -s /work/bindings/python/tests -t /work/bindings/python" 2>&1); then
        pass "python3 -m unittest discover, bindings/python/tests, aarch64 under qemu-aarch64"
    else
        fail "bindings/python/tests under qemu-aarch64:"
        printf '%s\n' "$out" | sed 's/^/        /'
    fi
fi

printf '\n'
[ "$FAIL" -eq 0 ] && { printf 'qemu-verify.sh: done, %s\n' "$OUT"; exit 0; }
printf 'qemu-verify.sh: failed\n'; exit 1
