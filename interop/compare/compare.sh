# shellcheck shell=bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# `scripts/lab.sh compare`: the same scenarios run for Sipral's headless
# agent (crates/sipral/examples/headless-agent.rs) and for pjsua, PJSIP's own
# command-line client, against the lab's Asterisk. Sourced by scripts/lab.sh,
# whose `step`, `pass`, `fail`, `LAB_NETWORK` and `ROOT` it uses; it defines
# functions only, and `compare_run` runs them.
#
# pjsua is the distribution's binary and nothing else: Debian and Ubuntu ship
# no pjsua package, Alpine does (`apk add pjsua`), so it runs in an Alpine
# image built here from that one package. No PJSIP source is fetched, built or
# read. docs/23-compared-with-pjsip.md is the write-up of one run of this.
#
# Both clients run the same way: in a container that shares the network
# namespace of a capture container ("the pod"), which is on the lab network,
# holds tcpdump, tc and python3, and is what moves when the network changes.
# Every time is read off the pod's capture (interop/compare/wire.py), never
# off what a client says about itself; memory and CPU are read from the
# client's own /proc/1, the same file for both. Captures and each client's
# log are kept in interop/pcap/compare/, which git ignores.
#
# What each client is asked, in order, under the one account
# `labuser-compare` (interop/asterisk/pjsip.conf):
#
#   plain    register; place one call to Asterisk's echo (9008) and have
#            Asterisk hang it up; sit idle; then take SIPRAL_COMPARE_CALLS
#            calls at once (1, 4, 10 and 100 unless told otherwise) that Asterisk
#            originates to 9020's tone, reading memory and CPU with each
#   ice      register with ICE on, and place the same call: the INVITE's
#            size and its candidates
#   netem    one call Asterisk originates, over each of
#            SIPRAL_COMPARE_PROFILES (interop/impairment/*.sh; lossy, mobile
#            and satellite unless told otherwise) applied both ways on the
#            pod's link, for SIPRAL_COMPARE_HOLD_S seconds; what Asterisk
#            measured of the client's audio, and what the client measured of
#            Asterisk's
#   move     one call up, then the pod taken off the lab network and put back
#            at another address: how long until the client spoke SIP from
#            there, sent audio from there, and heard audio there again. pjsua
#            does nothing about a new address by itself -- its console's `I`
#            command is what an application calls when the platform reports
#            one -- so it is moved twice, once left alone and once told
#
# pjsua is run with the null audio device, auto-answer 200 and --auto-loop
# (what it receives is what it sends back), Sipral's agent echoes; both are
# given the most calls they can hold. pjsua's --max-calls stops at the limit
# its build was compiled with, and Alpine's is 4 (`pjsua --max-calls=5` says
# "maximum call setting exceeds compile time limit (PJSUA_MAX_CALLS=4)"), so
# its rows past 4 calls say how many came up. The agent is told to let 200
# INVITEs arrive at once from Asterisk (--invite-burst): the stack's own
# default lets ten through and then one every two seconds, a guard against a
# scanner that a PBX's only extension does not need.

CMP_PREFIX="${COMPOSE_PROJECT_NAME:-sipral-interop}-compare"
CMP_POD="$CMP_PREFIX-pod"
CMP_CLIENT="$CMP_PREFIX-client"
CMP_POD_IMAGE="$CMP_PREFIX-pod:local"
CMP_PJSUA_IMAGE="$CMP_PREFIX-pjsua:local"
CMP_ALPINE="${SIPRAL_COMPARE_ALPINE:-alpine:3.24}"
CMP_OUT="$ROOT/interop/pcap/compare"
CMP_USER=labuser-compare
CMP_PASS=labpass
CMP_CLIENTS="${SIPRAL_COMPARE_CLIENTS:-sipral pjsua}"
CMP_CALLS="${SIPRAL_COMPARE_CALLS:-1 4 10 100}"
CMP_PROFILES="${SIPRAL_COMPARE_PROFILES:-lossy mobile satellite}"
CMP_HOLD_S="${SIPRAL_COMPARE_HOLD_S:-30}"
CMP_WINDOW_S="${SIPRAL_COMPARE_WINDOW_S:-20}"
CMP_PJSUA_MAX_CALLS="${SIPRAL_COMPARE_PJSUA_MAX_CALLS:-4}"
CMP_AGENT=""
CMP_ASTERISK_IP=""

cmp_note() { printf '  note  %s\n' "$1"; }
# one result line: client, scenario, then name=value pairs -- the lines the
# write-up's tables are made from
cmp_result() { printf '  cmp   %-6s %-22s %s\n' "$1" "$2" "$3"; }

cmp_ast() {
    ( cd "$ROOT/interop" && docker compose exec -T asterisk asterisk -rx "$1" ) 2>/dev/null
}

cmp_calls_up() {
    cmp_ast "core show channels concise" | grep -c '!Up!'
}

cmp_channels() {
    cmp_ast "core show channels count" | sed -n 's/^\([0-9][0-9]*\) active channel.*/\1/p'
}

# Asterisk originates $1 calls to the registered client, in one shell inside
# its own container rather than one `docker compose exec` each, so a hundred
# of them leave within a second or two the way a hundred callers would.
cmp_originate() {
    local count="$1"
    ( cd "$ROOT/interop" && docker compose exec -T asterisk sh -c "
        i=0
        while [ \$i -lt $count ]; do
            asterisk -rx 'channel originate PJSIP/$CMP_USER extension 9020@lab' >/dev/null 2>&1
            i=\$((i + 1))
        done" ) >/dev/null 2>&1
}

cmp_hangup_all() {
    local tries=0
    cmp_ast "channel request hangup all" >/dev/null
    while [ "$(cmp_channels)" != 0 ] && [ "$tries" -lt 30 ]; do
        tries=$((tries + 1))
        sleep 1
    done
}

# Until the count of calls Asterisk sees up reaches $1, or stops moving for
# five seconds; prints the count it settled at.
cmp_wait_up() {
    local want="$1" seen=0 last=-1 still=0 tries=0
    while [ "$tries" -lt 90 ]; do
        seen=$(cmp_calls_up)
        [ "$seen" -ge "$want" ] && break
        if [ "$seen" = "$last" ]; then
            still=$((still + 1))
            [ "$still" -ge 5 ] && [ "$seen" -gt 0 ] && break
            [ "$still" -ge 20 ] && break
        else
            still=0
        fi
        last="$seen"
        tries=$((tries + 1))
        sleep 1
    done
    printf '%s\n' "$seen"
}

cmp_pod_ip() {
    docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CMP_POD"
}

cmp_images() {
    printf 'FROM debian:trixie-slim\nRUN apt-get update && apt-get install -y --no-install-recommends tcpdump iproute2 python3-minimal && rm -rf /var/lib/apt/lists/*\n' \
        | docker build -q -t "$CMP_POD_IMAGE" - >/dev/null 2>&1 \
        || { fail "the capture image (debian:trixie-slim with tcpdump, tc and python3)"; return 1; }
    printf 'FROM %s\nRUN apk add --no-cache pjsua\n' "$CMP_ALPINE" \
        | docker build -q -t "$CMP_PJSUA_IMAGE" - >/dev/null 2>&1 \
        || { fail "the pjsua image ($CMP_ALPINE, apk add pjsua)"; return 1; }
    pass "images: the capture pod, and pjsua from $CMP_ALPINE's own package"
}

cmp_pod_up() {
    docker rm -f "$CMP_CLIENT" "$CMP_POD" >/dev/null 2>&1
    docker run -d --name "$CMP_POD" --network "$LAB_NETWORK" \
        --cap-add NET_ADMIN --cap-add NET_RAW \
        -v "$CMP_OUT:/out" -v "$ROOT/interop/compare:/compare:ro" \
        "$CMP_POD_IMAGE" sleep 2147483647 >/dev/null
}

cmp_pod_down() {
    docker rm -f "$CMP_CLIENT" "$CMP_POD" >/dev/null 2>&1
}

cmp_capture_start() {
    docker exec -d "$CMP_POD" sh -c "echo \$\$ >/tmp/tcpdump.pid; exec tcpdump -i any -s 0 -U -w /out/$1.pcap udp >/dev/null 2>&1"
    sleep 1
}

cmp_capture_stop() {
    docker exec "$CMP_POD" sh -c 'kill -INT "$(cat /tmp/tcpdump.pid)"' >/dev/null 2>&1
    sleep 1
}

cmp_wire() {
    docker exec "$CMP_POD" python3 /compare/wire.py "$@"
}

# $1 the client, $2 "ice" for ICE on, $3 a call to place once registered
# (the agent's --call; pjsua is typed at instead, by cmp_dial), $4 "g711" to
# offer G.711 alone rather than every codec the client has
cmp_client_up() {
    local kind="$1" ice="${2:-}" call="${3:-}" g711="${4:-}" ip tries=0
    docker rm -f "$CMP_CLIENT" >/dev/null 2>&1
    if [ "$kind" = pjsua ]; then
        docker run -d --name "$CMP_CLIENT" --network "container:$CMP_POD" \
            -v "$ROOT/interop/compare:/compare:ro" "$CMP_PJSUA_IMAGE" \
            sh /compare/pjsua.sh --null-audio --auto-answer=200 --auto-loop \
            "--max-calls=$CMP_PJSUA_MAX_CALLS" --no-tcp --no-color \
            --log-level=3 --app-log-level=3 \
            --registrar=sip:asterisk "--id=sip:$CMP_USER@asterisk" "--realm=*" \
            "--username=$CMP_USER" "--password=$CMP_PASS" \
            ${ice:+--use-ice} ${g711:+"--dis-codec=*" --add-codec=PCMA --add-codec=PCMU} \
            >/dev/null || return 1
    else
        docker run -d --name "$CMP_CLIENT" --network "container:$CMP_POD" \
            -v "$(dirname "$CMP_AGENT"):/sipral:ro" debian:trixie-slim \
            "/sipral/$(basename "$CMP_AGENT")" \
            --register "$CMP_USER@asterisk" --registrar "$CMP_ASTERISK_IP:5060" \
            --pass "$CMP_PASS" --invite-burst 200 \
            ${ice:+--ice} ${g711:+--codecs PCMU,PCMA} \
            ${call:+--call "$call"} >/dev/null || return 1
    fi
    ip=$(cmp_pod_ip)
    # read from the registrar's own store rather than `pjsip show contacts`,
    # whose column cuts an address the length of the move's short
    until cmp_ast "database show registrar/contact" | grep -q "\"uri\":\"sip:$CMP_USER@$ip:"; do
        tries=$((tries + 1))
        if [ "$(docker inspect -f '{{.State.Running}}' "$CMP_CLIENT" 2>/dev/null)" != true ] \
            || [ "$tries" -ge 60 ]; then
            printf '  %s never registered from %s\n' "$kind" "$ip"
            docker logs "$CMP_CLIENT" 2>&1 | tail -20
            return 1
        fi
        sleep 1
    done
}

# Keeps the client's log beside the captures, then stops it.
cmp_client_down() {
    docker logs "$CMP_CLIENT" >"$CMP_OUT/$1.log" 2>&1
    docker rm -f "$CMP_CLIENT" >/dev/null 2>&1
}

cmp_type() {
    docker exec "$CMP_CLIENT" sh -c "printf '$1' >/tmp/in"
}

cmp_dial() {
    [ "$1" = pjsua ] && cmp_type 'm\nsip:9008@asterisk\n'
    return 0
}

# Resident memory and the private part of it, in kB, from the client's own
# /proc/1: RSS counts every shared library page the process has touched,
# which a dynamically linked binary has more of, so the private figure is
# printed beside it.
cmp_memory() {
    local rss private
    rss=$(docker exec "$CMP_CLIENT" cat /proc/1/status 2>/dev/null | awk '/^VmRSS:/{print $2}')
    private=$(docker exec "$CMP_CLIENT" cat /proc/1/smaps_rollup 2>/dev/null \
        | awk '/^Private_(Clean|Dirty):/{sum += $2} END {print sum + 0}')
    printf 'rss_kb=%s private_kb=%s' "${rss:--}" "${private:--}"
}

cmp_ticks() {
    docker exec "$CMP_CLIENT" cat /proc/1/stat 2>/dev/null | sed 's/.*) //' | awk '{print $12 + $13}'
}

# The client's CPU over CMP_WINDOW_S seconds, as a percentage of one core:
# user and system time of every thread, from /proc/1/stat, at the kernel's
# own USER_HZ.
cmp_cpu() {
    local hz before after
    hz=$(docker exec "$CMP_POD" getconf CLK_TCK 2>/dev/null || printf 100)
    before=$(cmp_ticks)
    sleep "$CMP_WINDOW_S"
    after=$(cmp_ticks)
    awk -v b="$before" -v a="$after" -v hz="$hz" -v s="$CMP_WINDOW_S" \
        'BEGIN { printf "%.2f", (a - b) / hz / s * 100 }'
}

cmp_phase_plain() {
    local kind="$1" up idle_cpu cpu per name short=0
    name="$kind-plain"
    cmp_capture_start "$name"
    cmp_client_up "$kind" "" "sip:9008@asterisk" || { cmp_capture_stop; return 1; }
    cmp_dial "$kind"
    up=$(cmp_wait_up 1)
    [ "$up" -ge 1 ] || printf '  %s placed no call to the echo\n' "$kind"
    sleep 3
    cmp_hangup_all
    sleep 5
    idle_cpu=$(cmp_cpu)
    cmp_result "$kind" "idle" "$(cmp_memory) cpu_pct=$idle_cpu"
    for n in $CMP_CALLS; do
        cmp_originate "$n"
        up=$(cmp_wait_up "$n")
        sleep 5
        cpu=$(cmp_cpu)
        per=$(awk -v c="$cpu" -v i="$idle_cpu" -v n="$up" \
            'BEGIN { if (n > 0) printf "%.3f", (c - i) / n; else printf "-" }')
        cmp_result "$kind" "calls=$n" "up=$up $(cmp_memory) cpu_pct=$cpu cpu_pct_per_call=$per"
        cmp_hangup_all
        sleep 3
        # pjsua stopping at the calls its build allows is what is being
        # measured; this stack stopping short of what Asterisk offered is a
        # failure of the step
        if [ "$kind" = sipral ] && [ "$up" -lt "$n" ]; then
            printf '  only %s of %s calls came up\n' "$up" "$n"
            short=1
        fi
    done
    cmp_client_down "$name"
    cmp_capture_stop
    cmp_result "$kind" "register" "$(cmp_wire register "/out/$name.pcap" "$(cmp_pod_ip)")"
    cmp_result "$kind" "call-out" "$(cmp_wire invite-out "/out/$name.pcap" "$(cmp_pod_ip)")"
    cmp_result "$kind" "call-in" "$(cmp_wire invite-in "/out/$name.pcap" "$(cmp_pod_ip)")"
    [ "$short" -eq 0 ]
}

# The call to the echo with ICE on, twice: with every codec the client
# offers by default, and with G.711 alone, so the size of the candidates is
# read apart from the size of the codec list. $2 "g711" for the second.
cmp_phase_ice() {
    local kind="$1" g711="${2:-}" name up wanted
    name="$kind-ice${g711:+-g711}"
    cmp_capture_start "$name"
    cmp_client_up "$kind" ice "sip:9008@asterisk" "$g711" || { cmp_capture_stop; return 1; }
    cmp_dial "$kind"
    up=$(cmp_wait_up 1)
    sleep 2
    cmp_hangup_all
    cmp_client_down "$name"
    cmp_capture_stop
    wanted=$(grep -m1 '^transport wanted' "$CMP_OUT/$name.log" | sed 's/^transport wanted: //; s/ /_/g')
    cmp_result "$kind" "call-out-ice${g711:+-g711}" \
        "up=$up $(cmp_wire invite-out "/out/$name.pcap" "$(cmp_pod_ip)")${wanted:+ transport_wanted=$wanted}"
    # G.711 alone and ICE fit a datagram whoever sends them; this stack not
    # completing that call is a failure of the step
    [ "$kind" != sipral ] || [ -z "$g711" ] || [ "$up" -ge 1 ]
}

cmp_netem_on() {
    local profile="$1" applied
    # the profile sets all three; WHY is its description, not read here
    # shellcheck disable=SC2034
    WHY=""; NETEM=""; REQUIRE=""
    # shellcheck disable=SC1090
    . "$ROOT/interop/impairment/$profile.sh"
    applied=$(docker exec "$CMP_POD" sh -c "
        link=\$(ip route | awk '/^default/{print \$5}')
        tc qdisc add dev \"\$link\" root netem $NETEM
        ip link add ifb0 type ifb
        ip link set ifb0 up
        tc qdisc add dev \"\$link\" handle ffff: ingress
        tc filter add dev \"\$link\" parent ffff: protocol ip u32 \
            match u32 0 0 action mirred egress redirect dev ifb0
        tc qdisc add dev ifb0 root netem $NETEM
        echo out: \$(tc qdisc show dev \"\$link\" | head -1)
        echo in: \$(tc qdisc show dev ifb0)" 2>&1)
    printf '%s\n' "$applied" | sed 's/^/          /'
    [ -z "$REQUIRE" ] && return 0
    [ "$(printf '%s\n' "$applied" | grep -c "$REQUIRE")" -ge 2 ]
}

cmp_netem_off() {
    docker exec "$CMP_POD" sh -c "
        link=\$(ip route | awk '/^default/{print \$5}')
        tc qdisc del dev \"\$link\" root
        tc qdisc del dev \"\$link\" ingress
        ip link del ifb0" >/dev/null 2>&1
}

cmp_phase_netem() {
    local kind="$1" name="$1-netem" profile stats
    cmp_client_up "$kind" || return 1
    for profile in $CMP_PROFILES; do
        if ! cmp_netem_on "$profile"; then
            printf '  the %s profile was not applied on this kernel\n' "$profile"
            cmp_netem_off
            return 1
        fi
        cmp_originate 1
        cmp_wait_up 1 >/dev/null
        sleep "$CMP_HOLD_S"
        stats="$CMP_OUT/$name-$profile.channelstats"
        cmp_ast "pjsip show channelstats" >"$stats"
        [ "$kind" = pjsua ] && { cmp_type 'dq\n'; sleep 1; }
        cmp_hangup_all
        sleep 2
        docker logs "$CMP_CLIENT" >"$CMP_OUT/$name-$profile.log" 2>&1
        cmp_netem_off
        cmp_result "$kind" "$profile/asterisk" "$(cmp_wire channelstats "/out/$(basename "$stats")" "$CMP_USER")"
        if [ "$kind" = pjsua ]; then
            cmp_result "$kind" "$profile/client" "$(cmp_wire pjsua-dq "/out/$name-$profile.log")"
        else
            cmp_result "$kind" "$profile/client" "$(cmp_wire sipral-ended "/out/$name-$profile.log")"
        fi
    done
    cmp_client_down "$name"
}

# An address near the top of the lab network's own subnet, which Docker hands
# out last, $1 below its broadcast address.
cmp_address() {
    local subnet base bits a b c d n
    subnet=$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$LAB_NETWORK" \
        | tr ' ' '\n' | grep -m1 '^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*/')
    [ -n "$subnet" ] || return 1
    base=${subnet%/*}
    bits=${subnet#*/}
    IFS=. read -r a b c d <<<"$base"
    n=$(( (a << 24) + (b << 16) + (c << 8) + d + (1 << (32 - bits)) - $1 ))
    printf '%d.%d.%d.%d\n' $(( (n >> 24) & 255 )) $(( (n >> 16) & 255 )) \
        $(( (n >> 8) & 255 )) $(( n & 255 ))
}

# $2 "told" types pjsua's `I` the moment the new address exists; $3 how far
# below the top of the subnet the new address is
cmp_move() {
    local kind="$1" told="$2" below="$3" name to moved_at up wire
    name="$kind-move${told:+-told}"
    cmp_client_up "$kind" || return 1
    to=$(cmp_address "$below") || { printf '  cannot read the lab network'"'"'s subnet\n'; return 1; }
    cmp_capture_start "$name"
    cmp_originate 1
    cmp_wait_up 1 >/dev/null
    sleep 5
    docker network disconnect "$LAB_NETWORK" "$CMP_POD" >/dev/null 2>&1
    docker network connect --ip "$to" "$LAB_NETWORK" "$CMP_POD" >/dev/null 2>&1 \
        || { printf '  could not put the pod back at %s\n' "$to"; cmp_capture_stop; return 1; }
    moved_at=$(date +%s.%N)
    [ -n "$told" ] && cmp_type 'I\n'
    sleep 20
    up=$(cmp_calls_up)
    cmp_capture_stop
    cmp_hangup_all
    cmp_client_down "$name"
    wire=$(cmp_wire move "/out/$name.pcap" "$to" "$CMP_ASTERISK_IP" "$moved_at")
    cmp_result "$kind" "move${told:+ (told)}" "call_up_after_20s=$up $wire"
    # pjsua left alone is measured, not judged; this stack has to have
    # carried its call to the new address, audio heard there again
    [ "$kind" != sipral ] && return 0
    [ "$up" -ge 1 ] && ! printf '%s\n' "$wire" | grep -q 'audio_back_ms=-'
}

cmp_versions() {
    local pj
    pj=$(docker run --rm "$CMP_PJSUA_IMAGE" sh -c \
        'apk info -v 2>/dev/null | grep "^pjsua-"; pjsua --version 2>&1 | sed -n "s/.*PJ_VERSION *: *//p" | head -1')
    cmp_note "pjsua: package $(printf '%s' "$pj" | head -1), PJ_VERSION $(printf '%s' "$pj" | sed -n 2p), on $CMP_ALPINE"
    cmp_note "sipral: $(git -C "$ROOT" describe --always --dirty 2>/dev/null || printf unknown), $(basename "$CMP_AGENT")"
    cmp_note "asterisk: $(cmp_ast 'core show version' | head -1 | cut -d' ' -f1-2)"
    cmp_note "host: $(uname -sr), $(nproc 2>/dev/null || printf '?') cores"
}

compare_run() {
    local kind status=0
    CMP_AGENT="$1"
    mkdir -p "$CMP_OUT"
    CMP_ASTERISK_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
        "$(cd "$ROOT/interop" && docker compose ps -q asterisk)")
    [ -n "$CMP_ASTERISK_IP" ] || { fail "the lab's Asterisk has no address"; return 1; }
    cmp_images || return 1
    cmp_versions
    for kind in $CMP_CLIENTS; do
        step "compared with PJSIP -- $kind"
        cmp_pod_up || { fail "the capture pod for $kind"; status=1; continue; }
        cmp_phase_plain "$kind" && pass "$kind: registered, called, carried calls" \
            || { fail "$kind: the plain scenarios"; status=1; }
        cmp_phase_ice "$kind" && cmp_phase_ice "$kind" g711 \
            && pass "$kind: placed a call with ICE, every codec and G.711 alone" \
            || { fail "$kind: the ICE call"; status=1; }
        cmp_phase_netem "$kind" && pass "$kind: a call over each profile" \
            || { fail "$kind: the calls over a bad link"; status=1; }
        if [ "$kind" = pjsua ]; then
            cmp_move "$kind" "" 10 && cmp_move "$kind" told 11 \
                && pass "$kind: moved, left alone and told" \
                || { fail "$kind: the move"; status=1; }
        else
            cmp_move "$kind" "" 10 && pass "$kind: moved" \
                || { fail "$kind: the move"; status=1; }
        fi
        cmp_pod_down
    done
    docker rmi "$CMP_POD_IMAGE" "$CMP_PJSUA_IMAGE" >/dev/null 2>&1
    return "$status"
}
