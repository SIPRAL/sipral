#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# The lab's NAT: forward from `inside` to the lab network and masquerade on
# the way out, the way a home router does.
#
# MASQUERADE keeps a source port wherever it is free, and one inside
# address:port keeps the same outside one whoever it talks to. That is the
# endpoint-independent mapping RFC 4787 REQ-1 asks of a NAT and the one STUN
# can describe: the address coturn reports for a socket is the address
# Asterisk sees the same socket at. Its filtering is conntrack's, which lets
# in only what answers a flow the inside host opened -- address- and
# port-dependent, the strictest a consumer router ships with.
#
# The lab leg is found rather than named: it is whichever interface the route
# to Asterisk leaves by, since Docker numbers a container's interfaces in the
# order its networks were attached and that order is not something compose
# promises.
set -eu

asterisk=$(getent hosts asterisk | cut -d' ' -f1)
lab=$(ip -o route get "$asterisk" | sed -n 's/.* dev \([^ ]*\).*/\1/p')
[ -n "$lab" ] || { echo "no route to the lab network"; exit 1; }

iptables -t nat -A POSTROUTING -o "$lab" -j MASQUERADE
echo "nat: masquerading out of $lab"
exec sleep infinity
