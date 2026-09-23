# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# A NAT for the lab, and the machine behind it.
#
# The lab's containers all sit on one bridge and see each other's real
# addresses, so a STUN server there tells every client the address it already
# has, and a flow that checked "the Contact is what STUN said" would pass with
# STUN switched off. This image is what puts a translation in the way: run as
# `natbox` (interop/compose.yaml) it has one leg on the lab network and one on
# `inside`, forwards between them and masquerades whatever leaves by the lab
# leg (interop/nat/route.sh); run a second time by scripts/lab.sh's own `nat`
# step, it is the host behind that NAT, with nothing on `inside` but a default
# route through the box. Same image both times because both need exactly
# `ip`, and the harness needs nothing else a slim Debian lacks.
#
# The same digest interop/baresip/Dockerfile builds from, so the two images
# the lab builds itself start from one pinned base.

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*

COPY route.sh /usr/local/bin/sipral-nat-route
