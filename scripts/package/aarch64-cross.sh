# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# Cross-compiling sipral-ffi for aarch64-unknown-linux-gnu, from a host with
# no arm64 hardware, so wheels.sh --linux-arm64 and nuget.sh's linux-arm64
# RID have a native to package. Sourced, not run.
#
# Everything runs in an unprivileged Docker container: no --privileged, no
# binfmt registration on the host, nothing arm64 ever executed to build with
# -- scripts/package/docker/aarch64-cross.Dockerfile explains why that is
# possible (Debian's own x86_64 cross toolchain, linked against a sysroot
# taken out of quay.io/pypa/manylinux_2_28_aarch64 with `COPY --from`, which
# never starts that image). What runs the *result* is
# scripts/package/qemu-verify.sh, in a container of its own.
#
# aarch64_cross_ensure_image
#     builds (or reuses, if already built and the Dockerfile has not
#     changed) the sipral-aarch64-cross:<tag> image. The tag is a hash of the
#     Dockerfile's own content, so a Dockerfile edit rebuilds and an
#     unchanged one does not, without needing a registry.
#
# aarch64_cross_build TARGET_DIR
#     runs `cargo build --release -p sipral-ffi $FFI_FEATURE_ARGS --target
#     aarch64-unknown-linux-gnu` inside that image, with $ROOT mounted
#     read-only at /work and TARGET_DIR mounted at /tmp/target (so the
#     result lands at TARGET_DIR/aarch64-unknown-linux-gnu/release/, the
#     same layout a host-native `--target` build leaves).
#
# aarch64_glibc_check SO_PATH
#     reads SO_PATH's own dynamic symbol versions (aarch64-linux-gnu-objdump,
#     from the same image, since a host's own objdump may not read aarch64
#     ELF) and fails if any GLIBC_x.y exceeds 2.28 -- the version
#     scripts/package/docker/aarch64-cross.Dockerfile's sysroot links
#     against, and manylinux_2_28's own promise.
AARCH64_CROSS_DOCKERFILE="$ROOT/scripts/package/docker/aarch64-cross.Dockerfile"

aarch64_cross_ensure_image() {
    command -v docker >/dev/null 2>&1 || return 1
    [ -f "$AARCH64_CROSS_DOCKERFILE" ] || return 1
    local tag
    tag="sipral-aarch64-cross:$(shasum -a 256 "$AARCH64_CROSS_DOCKERFILE" 2>/dev/null | cut -c1-16)"
    AARCH64_CROSS_IMAGE="$tag"
    if docker image inspect "$tag" >/dev/null 2>&1; then
        return 0
    fi
    docker build -t "$tag" -f "$AARCH64_CROSS_DOCKERFILE" "$(dirname "$AARCH64_CROSS_DOCKERFILE")"
}

aarch64_cross_build() {
    local target_dir="$1"
    mkdir -p "$target_dir"
    docker run --rm \
        -v "$ROOT:/work:ro" -v "$target_dir:/tmp/target" -w /work \
        -e CARGO_TARGET_DIR=/tmp/target \
        "$AARCH64_CROSS_IMAGE" \
        cargo build --release -p sipral-ffi "${FFI_FEATURE_ARGS[@]}" --target aarch64-unknown-linux-gnu
}

aarch64_glibc_check() {
    local so_path="$1" max_minor="${2:-28}" highest minor
    highest=$(docker run --rm -v "$(dirname "$so_path"):/n:ro" "$AARCH64_CROSS_IMAGE" \
        aarch64-linux-gnu-objdump -T "/n/$(basename "$so_path")" 2>/dev/null \
        | grep -oE 'GLIBC_2\.[0-9]+' | sort -t. -k2 -n -u | tail -1)
    [ -z "$highest" ] && { printf 'no GLIBC_2.x symbol version found in %s\n' "$so_path" >&2; return 1; }
    minor="${highest#GLIBC_2.}"
    if [ "$minor" -gt "$max_minor" ]; then
        printf '%s links %s, newer than manylinux_2_28 (GLIBC_2.%s)\n' "$so_path" "$highest" "$max_minor" >&2
        return 1
    fi
    printf '%s\n' "$highest"
}
