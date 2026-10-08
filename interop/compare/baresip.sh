#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# Runs baresip as Fedora packages it (baresip, baresip-opus, baresip-g722),
# configured for interop/compare/compare.sh and for nothing else:
#
#   - the `echo` module answers every incoming call and sends back what it
#     receives, through `aubridge`: the same echo pjsua's --auto-loop and the
#     Sipral agent do
#   - its console on UDP 127.0.0.1:5555, so compare.sh can type at it
#   - call_max_calls 200 and call_hold_other_calls off, so a second incoming
#     call does not put the first one on hold
#   - rtp_stats on, so a call's receive statistics are printed when it ends,
#     and `rtcpsummary` for the round trip
#   - `netroam` loaded, as the packaged configuration loads it
#
# Codecs in the packaged order: Opus, G.722, G.711. The registrar is given by
# address (`outbound`), as it is to the Sipral agent: by name, baresip spends
# about ten seconds on SRV and NAPTR lookups through Docker's resolver first.
# Environment: CMP_USER, CMP_PASS, CMP_REGISTRAR (an address), CMP_ICE and
# CMP_G711 (either non-empty to turn it on). The process becomes baresip, the
# container's PID 1.
set -eu
mkdir -p /tmp/bs
codecs=""
[ -n "${CMP_G711:-}" ] && codecs=";audio_codecs=PCMU/8000/1,PCMA/8000/1"
nat=""
[ -n "${CMP_ICE:-}" ] && nat=";medianat=ice"
cat >/tmp/bs/config <<EOF
sip_listen		0.0.0.0:5060
call_max_calls		200
call_hold_other_calls	no
audio_player		aubridge,nil
audio_source		aubridge,nil
rtp_stats		yes
module_path		/usr/lib64/baresip/modules
module			opus.so
module			g722.so
module			g711.so
module			auconv.so
module			auresamp.so
module			aubridge.so
module			stun.so
module			turn.so
module			ice.so
module			cons.so
module_app		account.so
module_app		menu.so
module_app		echo.so
module_app		netroam.so
module_app		rtcpsummary.so
cons_listen		127.0.0.1:5555
EOF
printf '<sip:%s@asterisk>;auth_pass=%s;outbound="sip:%s"%s%s\n' \
    "$CMP_USER" "$CMP_PASS" "$CMP_REGISTRAR" "$codecs" "$nat" >/tmp/bs/accounts
exec baresip -f /tmp/bs -c
