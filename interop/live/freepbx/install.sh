#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# Puts the lab's own accounts and numbers on a FreePBX (pjsip_sipral_lab.conf,
# extensions_sipral_lab.conf), run on the box itself:
#
#   install.sh SECRET
#
# SECRET is the accounts' password, from the env file scripts/lab.sh reads
# (FREEPBX_LAB_SECRET), never from the repository. Safe to run again: each
# include and the mailbox are added once. Changes nothing FreePBX generates:
# the two files are included from pjsip_custom_post.conf and
# extensions_custom.conf, the files FreePBX keeps for exactly this, and the
# mailbox is a line in voicemail.conf's [default], where FreePBX's own
# voicemail module keeps the mailboxes it makes.
set -eu
SECRET="$1"
HERE=$(cd "$(dirname "$0")" && pwd)
ETC=/etc/asterisk

# FreePBX's own UDP transport, whatever port it is on
TRANSPORT=$(asterisk -rx 'pjsip show transports' | awk '$1 == "Transport:" && $3 == "udp" {print $2; exit}')
[ -n "$TRANSPORT" ] || { echo "no UDP transport on this FreePBX" >&2; exit 1; }

sed -e "s/@SECRET@/$SECRET/" -e "s/@TRANSPORT@/$TRANSPORT/" \
    "$HERE/pjsip_sipral_lab.conf" >"$ETC/pjsip_sipral_lab.conf"
cp "$HERE/extensions_sipral_lab.conf" "$ETC/extensions_sipral_lab.conf"
chown asterisk:asterisk "$ETC/pjsip_sipral_lab.conf" "$ETC/extensions_sipral_lab.conf"
chmod 640 "$ETC/pjsip_sipral_lab.conf"
grep -q '^#include pjsip_sipral_lab.conf' "$ETC/pjsip_custom_post.conf" \
    || printf '#include pjsip_sipral_lab.conf\n' >>"$ETC/pjsip_custom_post.conf"
grep -q '^#include extensions_sipral_lab.conf' "$ETC/extensions_custom.conf" \
    || printf '\n#include extensions_sipral_lab.conf\n' >>"$ETC/extensions_custom.conf"

# the mailbox 9007 leaves a message in, and its unavailable greeting: a
# second of silence, so 9007's VoiceMail() starts recording at once
grep -q '^9007 =>' "$ETC/voicemail.conf" \
    || sed -i '/^\[default\]/a 9007 => 9007,Sipral lab,,,attach=no|saycid=no|envelope=no|delete=no' "$ETC/voicemail.conf"
mkdir -p /var/spool/asterisk/voicemail/default/9007
cp /var/lib/asterisk/sounds/en/silence/1.ulaw /var/spool/asterisk/voicemail/default/9007/unavail.ulaw
chown -R asterisk:asterisk /var/spool/asterisk/voicemail/default/9007

asterisk -rx 'module reload res_pjsip.so' >/dev/null
asterisk -rx 'module reload app_voicemail.so' >/dev/null
asterisk -rx 'dialplan reload' >/dev/null
asterisk -rx 'pjsip show endpoints' | grep -c 'Endpoint:  labuser'
