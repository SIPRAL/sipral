# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# A Linux desktop's audio stack with no desktop and no sound card:
# PipeWire, its session manager, and a session bus for the two of them, next
# to the toolchain that builds sipral-io-pipewire against them. There is no
# ALSA device inside a container, so the only sinks and sources this graph
# ever has are the virtual cables interop/pipewire/run.sh makes, which is
# what lets it play into a cable's sink and read the same samples back out of
# its source.
#
# The pinned toolchain image the rest of the workspace builds with, plus
# Debian's own packages. libpipewire is MIT; nothing here pulls in libpulse
# or alsa-lib for this crate to link, and it links neither.

FROM rust:1.95-trixie

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpipewire-0.3-dev libspa-0.2-dev \
        pipewire pipewire-bin wireplumber dbus \
    && rm -rf /var/lib/apt/lists/*

# rust-toolchain.toml asks for both; the image ships neither, and without
# them the first cargo call downloads them into a container that is thrown
# away afterwards.
RUN rustup component add clippy rustfmt

WORKDIR /work
