# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# The lab's phone-to-phone peer, built from source rather than pulled as an
# image: nobody publishes a baresip container pinned the way the other three
# servers in this lab are, and a moving one is not a lab. libre and baresip
# are BSD (docs/02-clean-room.md): this file reads their own build
# instructions to build them, and copies nothing of their code into this
# repository -- what is ours here is the module list, the config and the
# account, all below.
#
# Both releases are v4.11.0, checked against github.com/baresip/re and
# github.com/baresip/baresip on 2026-09-22 -- the latest stable tag of each,
# published together, libre's own carrying two security fixes (an HTTP Basic
# auth check that accepted an empty credential, and a spoofed UDP packet that
# could forge an RTCP control message). Pinned by tag and by the sha256 of
# the tag's own source tarball, so a retagged release fails the build instead
# of changing what the lab runs.
#
# Multi-stage: the toolchain that builds libre and baresip never reaches the
# image compose starts. That image carries the two binaries this module set
# needs, nothing to build with, and no shell script of its own -- module_app
# account.so reads interop/baresip/config/accounts directly.

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git ca-certificates curl pkg-config \
        libssl-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# libre 4.11.0: the SIP, RTP/RTCP and DTLS stack baresip itself sits on,
# librem's audio and codec helpers folded into the same repository since
# baresip 4.x. -DCMAKE_INSTALL_LIBDIR=lib rather than the distribution's own
# multiarch default: baresip's own build looks for it at a fixed path
# (below), and a triplet directory picked by GNUInstallDirs' own guess is one
# more thing that could differ from what this file assumes.
RUN curl -fsSL -o re.tar.gz \
        https://github.com/baresip/re/archive/refs/tags/v4.11.0.tar.gz \
    && echo "2a8cbf13719618d879464617512a80fe2c13fe63cd5461cf01a195fbe46b3ca4  re.tar.gz" \
        | sha256sum -c - \
    && mkdir re && tar xzf re.tar.gz -C re --strip-components=1 \
    && cmake -S re -B re/build -G "Unix Makefiles" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DLIBRE_BUILD_STATIC=OFF \
    && cmake --build re/build -j"$(nproc)" \
    && cmake --install re/build

# baresip 4.11.0 itself, with only the modules this lab peer needs: the
# account and menu application modules (an account line registers it, and
# auto-answer -- see modules/menu/menu.c -- lives in menu, not the core), the
# G.711 codec every server in this lab already speaks, the audio-filter pair
# every non-trivial source or player needs, a sine-wave source and a file
# player for a headless container with no audio device, and the two media
# encryption modules for the SRTP and DTLS-SRTP peer accounts
# (interop/baresip/config/accounts). No video, no ICE/STUN/TURN -- this lab
# has no NAT to cross -- and no GUI or audio-hardware modules that would
# pull in libraries this image never uses.
RUN curl -fsSL -o baresip.tar.gz \
        https://github.com/baresip/baresip/archive/refs/tags/v4.11.0.tar.gz \
    && echo "e170ad5857994dfed0c84c4c04eb904fa410f3ec2d5a6c789b50b3fda47ba98c  baresip.tar.gz" \
        | sha256sum -c - \
    && mkdir baresip && tar xzf baresip.tar.gz -C baresip --strip-components=1 \
    && cmake -S baresip -B baresip/build -G "Unix Makefiles" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DCMAKE_PREFIX_PATH=/usr/local \
        -DMODULES="account;menu;g711;auconv;auresamp;ausine;aufile;srtp;dtls_srtp" \
    && cmake --build baresip/build -j"$(nproc)" \
    && cmake --install baresip/build

# Same base image and digest as the build stage, so the OpenSSL and zlib
# shared libraries baresip linked against are copied from a filesystem
# byte-for-byte identical to this one rather than pulled again under a
# runtime package name Debian has changed before (bookworm's own
# libssl3 -> libssl3t64 -> libssl3 round trip is the reason this file does
# not trust a name and reaches for the bytes that were actually linked).
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

COPY --from=build /usr/local/bin/baresip /usr/local/bin/baresip
COPY --from=build /usr/local/lib/ /usr/local/lib/
COPY --from=build /usr/lib/*/libssl.so* /usr/lib/*/libcrypto.so* /usr/lib/*/libz.so* /usr/local/lib/
ENV LD_LIBRARY_PATH=/usr/local/lib
RUN ldconfig
# where compose.yaml's own two read-only mounts land -- created ahead of them
# rather than left to a bind mount's own parent-directory behaviour
RUN mkdir -p /etc/sipral-baresip

# interop/baresip/config's own two files, read-only in compose.yaml, are
# mounted at this path rather than baked in: the same image serves every
# account this lab ever adds here without a rebuild.
ENTRYPOINT ["baresip", "-4", "-f", "/etc/sipral-baresip"]
