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

# the harness's account, an extension like any a phone registers as
sql -c "insert into v_extensions (extension_uuid, domain_uuid, extension, password, user_context, effective_caller_id_name, effective_caller_id_number, call_timeout, enabled)
        values ('$(uuid)', '$DOMAIN_UUID', 'labuser', '$PASS', '$DOMAIN', 'labuser', 'labuser', 30, true)"

# the lab's numbers, its header comment dropped, ahead of every dialplan
# FusionPBX installed in the domain's context (their orders start at 10)
DIALPLAN=$(awk 'done { print } /-->/ { done = 1 }' /usr/local/share/sipral/lab_dialplan.xml \
    | sed "s/CONTEXT/$DOMAIN/g; s/'/''/g")
sql -c "insert into v_dialplans (dialplan_uuid, domain_uuid, app_uuid, hostname, dialplan_context, dialplan_name, dialplan_number, dialplan_continue, dialplan_order, dialplan_enabled, dialplan_description, dialplan_xml)
        values ('$(uuid)', '$DOMAIN_UUID', '$(uuid)', null, '$DOMAIN', 'sipral_lab', '9000', false, 1, true, 'the lab''s numbers', '$DIALPLAN')"

rm -rf /var/cache/fusionpbx/*
touch /shared/ready
printf 'FusionPBX ready: domain %s\n' "$DOMAIN"

trap 'pg_ctlcluster "$VERSION" main stop; exit 0' TERM INT
while :; do sleep 3600 & wait $!; done
