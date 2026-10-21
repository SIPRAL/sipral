#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# A carrier gateway's calls, SIP-I both ways (scripts/lab.sh's `isup` step):
# interop/isup/gateway.py plays the gateway on this container's loopback,
# writing the ISUP of each call from ITU-T Q.763 itself, and `harness-c isup`
# is the line it serves, registered at it and trusting it. Each judges what
# it can see -- the harness what the stack told it about the caller, the
# progress and the cause; the gateway what came back on the wire, the 415 to
# a required ANSI body among it -- and the step passes when both do.
set -eu

export DEBIAN_FRONTEND=noninteractive
apt-get -qq update >/dev/null 2>&1
apt-get -qq install -y python3 >/dev/null 2>&1

python3 -I /isup/gateway.py 127.0.0.1 5070 >/tmp/gateway.log 2>&1 &
gateway=$!
tries=0
until grep -q "listening on" /tmp/gateway.log 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -lt 50 ] || { cat /tmp/gateway.log; echo "the gateway never came up"; exit 1; }
    sleep 0.1
done

status=0
/harness-c isup 127.0.0.1 5070 || status=$?
wait "$gateway" || status=$?
cat /tmp/gateway.log
exit "$status"
