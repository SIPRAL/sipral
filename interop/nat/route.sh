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
# Keeping the port is also what a NAT that proves nothing about ports does: a
# Contact or an `m=` line that took the host from the STUN answer and the port
# from the socket would still reach the harness. So the two sockets the C
# harness binds for the `nat` flow (interop/harness-c's NAT_SIP_PORT and
# NAT_RTP_PORT; the numbers here have to match) leave from other ports: SNAT
# to one fixed port gives every flow from that socket the same outside port,
# which is still endpoint-independent, and now different from the inside one.
#
# The lab leg is found rather than named: it is whichever interface the route
# to Asterisk leaves by, since Docker numbers a container's interfaces in the
# order its networks were attached and that order is not something compose
# promises.
set -eu

asterisk=$(getent hosts asterisk | cut -d' ' -f1)
lab=$(ip -o route get "$asterisk" | sed -n 's/.* dev \([^ ]*\).*/\1/p')
[ -n "$lab" ] || { echo "no route to the lab network"; exit 1; }
outside=$(ip -o -4 addr show dev "$lab" | sed -n 's/.* inet \([0-9.]*\)\/.*/\1/p')
[ -n "$outside" ] || { echo "no address on $lab"; exit 1; }

iptables -t nat -A POSTROUTING -o "$lab" -p udp --sport 5062 -j SNAT --to-source "$outside:15062"
iptables -t nat -A POSTROUTING -o "$lab" -p udp --sport 40062 -j SNAT --to-source "$outside:45062"
iptables -t nat -A POSTROUTING -o "$lab" -j MASQUERADE
# A datagram nobody inside asked for -- a peer's connectivity check that gets
# here before this side's own has gone out, which is how ICE's checks from
# both ends at once always begin -- is dropped before conntrack confirms it.
# Delivered to this box's own stack instead, it stays in the table as a flow
# of its own for as long as the peer keeps retransmitting, and the inside
# host's next datagram to that same peer is then translated to another port:
# the mapping would depend on which end sent first, which RFC 4787 REQ-1
# forbids, and no pair through two such NATs would ever be found. Answers to
# what went out are translated before they get here, and the one port a step
# forwards (`scripts/lab.sh ice`) is forwarded, so neither meets this rule.
iptables -A INPUT -i "$lab" -p udp -m conntrack --ctstate NEW -j DROP
echo "nat: masquerading out of $lab, 5062 as $outside:15062 and 40062 as $outside:45062"
exec sleep infinity
