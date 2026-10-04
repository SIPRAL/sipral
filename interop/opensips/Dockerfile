# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# The official image, plus the one package it leaves out. OpenSIPS 4.0 ships
# digest authentication (auth.so: pv_www_authorize(), www_challenge()) in
# opensips-auth-modules rather than in opensips itself, and the image carries
# only the latter, so opensips.cfg's first loadmodule "auth.so" fails and the
# proxy never starts. The package is pinned to the version of the opensips
# package already in the image, since a module built for another release is
# refused at load time.

FROM opensips/opensips:4.0@sha256:8cde1548466b3a9f7637c91ff299a8d959c6c6953a8cd68deb391753324f702b

RUN apt-get update \
    && apt-get install -y --no-install-recommends opensips-auth-modules=4.0.2-1 \
    && rm -rf /var/lib/apt/lists/*
