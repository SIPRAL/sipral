# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# An x86_64 image that cross-compiles sipral-ffi for aarch64-unknown-linux-gnu,
# for a host with no arm64 hardware. Built and run by scripts/package/wheels.sh
# and scripts/package/nuget.sh; not pulled or run directly.
#
# No arm64 code ever executes to build this image or to build with it: the
# Debian cross toolchain (crossbuild-essential-arm64) is an x86_64 program
# that emits aarch64 object code, and the manylinux sysroot below is taken
# out of an arm64 image with `COPY --from=<image>`, which copies files out of
# that image's layers without starting it (the same thing `docker create`
# without `docker start` does) -- no QEMU, no binfmt, no --privileged.
#
# The sysroot is what makes the result manylinux_2_28-compatible: Debian
# trixie's own aarch64 glibc is newer than manylinux_2_28's (glibc 2.28), so
# linking against Debian's would produce a .so that refuses to load on an
# older glibc. Linking with --sysroot pointed at manylinux's glibc instead
# means every libc symbol the linker resolves is one manylinux_2_28 has,
# which scripts/package/aarch64-cross.sh's aarch64_glibc_check then confirms
# by reading the binary's own symbol versions.
FROM rust:1.99-trixie

# cmake: the `opus` feature vendors libopus and builds it with the `cmake`
# Rust crate, which shells out to a real cmake. python3-venv: scripts/
# package/wheels.sh --linux-arm64 re-execs itself in here (the way
# --manylinux already does in quay.io/pypa/manylinux_2_28_x86_64) to build
# the wheel with a host whose own Python is guaranteed to have a working
# venv module, rather than assuming that of whatever invoked docker.
RUN apt-get update -qq \
    && apt-get install -qq -y --no-install-recommends \
        crossbuild-essential-arm64 cmake python3 python3-venv python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add aarch64-unknown-linux-gnu

# quay.io/pypa/manylinux_2_28_aarch64's own glibc, includes and static
# objects (crt1.o etc.) -- nothing else from that image is needed to link
# against it, so nothing else is copied.
COPY --from=quay.io/pypa/manylinux_2_28_aarch64 /usr/include /sysroot/usr/include
COPY --from=quay.io/pypa/manylinux_2_28_aarch64 /usr/lib64 /sysroot/usr/lib64
# manylinux_2_28_aarch64 itself resolves both at runtime (RHEL8's aarch64
# build keeps everything under /usr/lib64, unlike upstream glibc's own
# default of /lib for this arch): /lib64 for its own binaries' PT_INTERP,
# and libc.so's linker script names /lib/ld-linux-aarch64.so.1 in its
# `AS_NEEDED`, which --sysroot below resolves against this tree at link
# time. Neither exists as a real directory in the extracted sysroot, so both
# are pointed at the one place that does.
RUN ln -s usr/lib64 /sysroot/lib64 && ln -s usr/lib64 /sysroot/lib

ENV AARCH64_MANYLINUX_SYSROOT=/sysroot
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
# aarch64's default PT_INTERP ("/lib/ld-linux-aarch64.so.1") does not exist in
# manylinux_2_28_aarch64: that image, built RHEL-style, keeps everything --
# including the loader -- under /usr/lib64, reached at runtime through
# /lib64 (its own /lib points at /usr/lib instead, empty on this arch). The
# --dynamic-linker override below is the path this produces a binary that
# expects, and it is real on any manylinux_2_28-labelled host.
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=--sysroot=/sysroot -C link-arg=-B/sysroot/usr/lib64 -C link-arg=-Wl,--dynamic-linker=/lib64/ld-linux-aarch64.so.1"
# audiopus-sys (the `opus` feature) compiles vendored C with the `cc` crate,
# which reads these instead of Cargo's own linker setting.
ENV CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
ENV AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar
ENV CFLAGS_aarch64_unknown_linux_gnu="--sysroot=/sysroot"
