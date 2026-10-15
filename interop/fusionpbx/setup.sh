#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# Prepares FusionPBX for the lab's switch and then keeps its database up.
# The steps are the ones FusionPBX's own installer documents for Debian
# (its finish step): a database and its user, /etc/fusionpbx/config.conf,
# the schema, a domain, the application defaults -- which also copy the
# Lua scripts into the switch's script directory -- and then what is the
# lab's own: an extension and the lab's numbers in the domain's dialplan.
#
# Everything the switch reads lives under /shared, a volume compose.yaml
# mounts in both containers: the configuration tree (FusionPBX's
# app/switch/resources/conf), the scripts and config.conf. It is emptied
# first, so a run never starts from what an earlier one left, and
# /shared/ready is written last: the switch waits for it.
set -eu

DOMAIN="${SIPRAL_FUSIONPBX_DOMAIN:-fusionpbx}"
PASS="${SIPRAL_FUSIONPBX_PASS:-labpass}"
DB_PASS="${SIPRAL_FUSIONPBX_DB_PASS:-labdbpass}"
APP=/var/www/fusionpbx

rm -rf /shared/ready /shared/conf /shared/scripts /shared/fusionpbx /shared/cache
mkdir -p /shared/conf /shared/scripts /shared/fusionpbx /shared/cache
ln -sfn /shared/conf /etc/freeswitch
mkdir -p /usr/share/freeswitch
ln -sfn /shared/scripts /usr/share/freeswitch/scripts
ln -sfn /shared/fusionpbx /etc/fusionpbx
ln -sfn /shared/cache /var/cache/fusionpbx
cp -R "$APP/app/switch/resources/conf/." /etc/freeswitch/

# the cluster Debian's package created, reachable from the switch's
# container over the lab network
CLUSTER_CONF=$(ls -d /etc/postgresql/*/main | head -1)
VERSION=$(basename "$(dirname "$CLUSTER_CONF")")
printf "listen_addresses = '*'\n" >>"$CLUSTER_CONF/postgresql.conf"
printf 'host all all 0.0.0.0/0 scram-sha-256\n' >>"$CLUSTER_CONF/pg_hba.conf"
pg_ctlcluster "$VERSION" main start
su postgres -c "psql -q -c \"CREATE USER fusionpbx WITH PASSWORD '$DB_PASS'\""
su postgres -c "psql -q -c 'CREATE DATABASE fusionpbx OWNER fusionpbx'"

cat >/etc/fusionpbx/config.conf <<EOF
database.0.type = pgsql
database.0.host = $(hostname -i | cut -d' ' -f1)
database.0.port = 5432
database.0.sslmode = disable
database.0.name = fusionpbx
database.0.username = fusionpbx
database.0.password = $DB_PASS

database.1.type = sqlite
database.1.path = /var/lib/freeswitch/db
database.1.name = core.db

document.root = $APP
project.path =
temp.dir = /tmp
php.dir = /usr/bin
php.bin = php

cache.method = file
cache.location = /var/cache/fusionpbx
cache.settings = true

switch.conf.dir = /etc/freeswitch
switch.sounds.dir = /usr/share/freeswitch/sounds
switch.database.dir = /var/lib/freeswitch/db
switch.recordings.dir = /var/lib/freeswitch/recordings
switch.storage.dir = /var/lib/freeswitch/storage
switch.voicemail.dir = /var/lib/freeswitch/storage/voicemail
switch.scripts.dir = /usr/share/freeswitch/scripts

xml_handler.fs_path = false
xml_handler.reg_as_number_alias = false
xml_handler.number_as_presence_id = true

error.reporting = user
EOF

export PGPASSWORD="$DB_PASS"
sql() { psql -q -t -A -h 127.0.0.1 -U fusionpbx fusionpbx "$@"; }
uuid() { cat /proc/sys/kernel/random/uuid; }

cd "$APP"
php core/upgrade/upgrade.php --schema
DOMAIN_UUID=$(uuid)
sql -c "insert into v_domains (domain_uuid, domain_name, domain_enabled) values ('$DOMAIN_UUID', '$DOMAIN', true)"
php core/upgrade/upgrade.php --defaults

# G.729 among the codecs every profile accepts, after the ones FusionPBX
# lists, so 9008 can be offered G.729 alone: the profile negotiates as the
# INVITE arrives, before any dialplan could name a codec for the call. Both
# the variable's row and the vars.xml the defaults wrote from it.
sql -c "update v_vars set var_value = var_value || ',G729' where var_name = 'global_codec_prefs' and var_value not like '%G729%'"
sed -i 's/\(global_codec_prefs=[^"]*\)"/\1,G729"/' /etc/freeswitch/vars.xml
grep -q 'global_codec_prefs=[^"]*G729' /etc/freeswitch/vars.xml

# 9006 answers a MESSAGE with one of its own, as Asterisk's does: mod_sms
# routes a MESSAGE from an extension through the chatplan's public context,
# which FusionPBX ships with nothing but a commented-out demo
sed -i 's|<context name="public">|<context name="public">\n<extension name="sipral_lab_message"><condition field="to_user" expression="^9006$"><action application="reply" data="echo: ${_body}"/></condition></extension>|' /etc/freeswitch/chatplan/default.xml
grep -q sipral_lab_message /etc/freeswitch/chatplan/default.xml

# the harness's account, an extension like any a phone registers as
sql -c "insert into v_extensions (extension_uuid, domain_uuid, extension, password, user_context, effective_caller_id_name, effective_caller_id_number, call_timeout, enabled)
        values ('$(uuid)', '$DOMAIN_UUID', 'labuser', '$PASS', '$DOMAIN', 'labuser', 'labuser', 30, true)"

# the lab's numbers, its header comment dropped, ahead of every dialplan
# FusionPBX installed in the domain's context (their orders start at 10)
DIALPLAN=$(awk 'done { print } /-->/ { done = 1 }' /usr/local/share/sipral/lab_dialplan.xml \
    | sed "s/CONTEXT/$DOMAIN/g; s/'/''/g")
sql -c "insert into v_dialplans (dialplan_uuid, domain_uuid, app_uuid, hostname, dialplan_context, dialplan_name, dialplan_number, dialplan_continue, dialplan_order, dialplan_enabled, dialplan_description, dialplan_xml)
        values ('$(uuid)', '$DOMAIN_UUID', '$(uuid)', null, '$DOMAIN', 'sipral_lab', '9000', false, 1, true, 'the lab''s numbers', '$DIALPLAN')"

# Message waiting as FusionPBX offers it: mwi_subscribe.lua answers a
# message-summary SUBSCRIBE from the voicemail tables. FusionPBX ships it
# commented out in lua.conf.xml, and as shipped it stops at its first event:
# resources/functions/config.lua replaces the global `debug` library with a
# table of FusionPBX's own flags, and the event loop's xpcall then gets nil
# for debug.traceback. The table keeps traceback here; nothing else in the
# script is touched. Its mailboxes are numeric only, so the flow subscribes as
# extension 1001 with a voicemail box of that number.
sed -i 's|^\(\s*\)debug = {}$|\1debug = { traceback = debug.traceback }|' /usr/share/freeswitch/scripts/resources/functions/config.lua
grep -q 'debug = { traceback = debug.traceback }' /usr/share/freeswitch/scripts/resources/functions/config.lua
sed -i 's|<!--<param name="startup-script" value="app/voicemail/resources/scripts/mwi_subscribe.lua"/>-->|<param name="startup-script" value="app/voicemail/resources/scripts/mwi_subscribe.lua"/>|' /etc/freeswitch/autoload_configs/lua.conf.xml
grep -q '^ *<param name="startup-script" value="app/voicemail/resources/scripts/mwi_subscribe.lua"/>' /etc/freeswitch/autoload_configs/lua.conf.xml
sql -c "insert into v_extensions (extension_uuid, domain_uuid, extension, password, user_context, effective_caller_id_name, effective_caller_id_number, call_timeout, enabled)
        values ('$(uuid)', '$DOMAIN_UUID', '1001', '$PASS', '$DOMAIN', '1001', '1001', 30, true)"
sql -c "insert into v_voicemails (voicemail_uuid, domain_uuid, voicemail_id, voicemail_password, voicemail_enabled)
        values ('$(uuid)', '$DOMAIN_UUID', '1001', '1001', true)"

rm -rf /var/cache/fusionpbx/*
touch /shared/ready
printf 'FusionPBX ready: domain %s\n' "$DOMAIN"

trap 'pg_ctlcluster "$VERSION" main stop; exit 0' TERM INT
while :; do sleep 3600 & wait $!; done
