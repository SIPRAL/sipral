#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# Runs linphonec, the console client of Debian's linphone-cli package,
# answering every call by itself (-a), with its console on a named pipe so
# interop/compare/compare.sh can type at it the way pjsua.sh lets it type at
# pjsua. The account is written into a linphonerc, with `max_calls=200`;
# everything else is typed at its console once it has registered (`soundcard
# use files`, `play`, `codec disable`, `firewall ice`), as a user of
# linphonec would. Environment: CMP_USER, CMP_PASS, CMP_REGISTRAR (an
# address), CMP_LOGLEVEL (linphonec's -d, 0 unless given). The process
# becomes linphonec, the container's PID 1.
set -eu
mkdir -p /root/.local/share/linphone
cat >/tmp/linphonerc <<EOF
[sip]
sip_port=5060
sip_tcp_port=0
sip_tls_port=0
default_proxy=0
max_calls=200

[proxy_0]
reg_proxy=<sip:$CMP_REGISTRAR;transport=udp>
reg_identity=sip:$CMP_USER@asterisk
reg_expires=3600
reg_sendregister=1

[auth_info_0]
username=$CMP_USER
passwd=$CMP_PASS
EOF
mkfifo /tmp/in
sleep 2147483647 >/tmp/in &
exec linphonec -a -c /tmp/linphonerc -d "${CMP_LOGLEVEL:-0}" </tmp/in
