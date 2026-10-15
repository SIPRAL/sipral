#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# Puts the lab's own accounts and numbers on a ViciBox (sip_sipral_lab.conf,
# extensions_sipral_lab.conf), run on the box itself:
#
#   install.sh SECRET
#
# SECRET is the accounts' password, from the env file scripts/lab.sh reads
# (VICI_LAB_SECRET), never from the repository. Safe to run again: each
# include, setting and module is added once. Changes nothing the dialer
# writes: sip-vicidial.conf and extensions-vicidial.conf are VICIdial's own
# and are left alone; the settings here are chan_sip's [general] for
# MESSAGE outside a call, and a mailbox in VICIdial's own table.
set -eu
SECRET="$1"
HERE=$(cd "$(dirname "$0")" && pwd)
ETC=/etc/asterisk

sed "s/@SECRET@/$SECRET/" "$HERE/sip_sipral_lab.conf" >"$ETC/sip_sipral_lab.conf"
chmod 640 "$ETC/sip_sipral_lab.conf"
cp "$HERE/extensions_sipral_lab.conf" "$ETC/extensions_sipral_lab.conf"
grep -q '^#include sip_sipral_lab.conf' "$ETC/sip.conf" \
    || printf '\n#include sip_sipral_lab.conf\n' >>"$ETC/sip.conf"
grep -q '^#include extensions_sipral_lab.conf' "$ETC/extensions.conf" \
    || printf '\n#include extensions_sipral_lab.conf\n' >>"$ETC/extensions.conf"

# MESSAGE outside a call (RFC 3428) goes to the lab's context, where 9006
# answers it; chan_sip takes neither unless [general] says so
if ! grep -q '^accept_outofcall_message=yes' "$ETC/sip.conf"; then
    sed -i '/^\[general\]/a accept_outofcall_message=yes\noutofcall_message_context=sipral-lab' "$ETC/sip.conf"
fi

# the mailbox 9007 leaves a message in, made the way an administrator makes
# one in VICIdial (its vicidial_voicemail table): VICIdial writes
# voicemail.conf from that table and puts back anything edited there by
# hand. rebuild_conf_files asks its keepalive to write the file again now.
mysql asterisk -e "insert ignore into vicidial_voicemail (voicemail_id, pass, fullname, active) values ('9007', '9007', 'Sipral lab', 'Y'); update servers set rebuild_conf_files = 'Y'"

# the mailbox's unavailable greeting: a second of silence, so 9007's
# VoiceMail() starts recording at once
mkdir -p /var/spool/asterisk/voicemail/default/9007
cp /var/lib/asterisk/sounds/silence/1.gsm /var/spool/asterisk/voicemail/default/9007/unavail.gsm

# the DTLS-SRTP account's certificate, made once
if [ ! -f "$ETC/keys/sipral-lab.pem" ]; then
    mkdir -p "$ETC/keys"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=sipral-lab" \
        -keyout "$ETC/keys/sipral-lab.key" -out "$ETC/keys/sipral-lab.crt" 2>/dev/null
    cat "$ETC/keys/sipral-lab.crt" "$ETC/keys/sipral-lab.key" >"$ETC/keys/sipral-lab.pem"
    chown -R asterisk:asterisk "$ETC/keys" 2>/dev/null || true
fi

asterisk -rx 'module reload chan_sip.so' >/dev/null
asterisk -rx 'module reload app_voicemail.so' >/dev/null
asterisk -rx 'dialplan reload' >/dev/null
asterisk -rx 'sip show peers' | grep -c '^labuser' 
