# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# FusionPBX's own half of the lab's FusionPBX: its PostgreSQL database and
# its PHP application, the one that writes the schema, the domain, the
# extensions and the dialplan the switch then reads. Nobody publishes an
# image of FusionPBX (MPL 1.1); its own installer
# (github.com/fusionpbx/fusionpbx-install.sh) takes over a whole Debian
# machine under systemd and compiles FreeSWITCH from source, so neither is
# used. Instead the switch is the lab's pinned FreeSWITCH image running
# FusionPBX's configuration tree and Lua scripts (compose.yaml's
# `fusionpbx`), and this container prepares both into a volume the two
# share -- setup.sh says what it does, step by step, and each step is one
# FusionPBX's installer documents.
FROM debian:trixie-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates git postgresql php-cli php-pgsql php-xml php-mbstring php-curl \
    && rm -rf /var/lib/apt/lists/*

# pinned by release tag, as every other image here is pinned
ARG FUSIONPBX_VERSION=5.6.5
RUN git clone --quiet --depth 1 -b "$FUSIONPBX_VERSION" \
        https://github.com/fusionpbx/fusionpbx.git /var/www/fusionpbx

COPY setup.sh /usr/local/bin/sipral-fusionpbx-setup
COPY lab_dialplan.xml /usr/local/share/sipral/lab_dialplan.xml

CMD ["sh", "/usr/local/bin/sipral-fusionpbx-setup"]
