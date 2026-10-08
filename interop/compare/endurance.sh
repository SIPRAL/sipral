# shellcheck shell=bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# `scripts/soak.sh compare [HOURS]`: the clients interop/compare/compare.sh
# compares, each registered and taking one call after another from the same
# Asterisk for the same wall-clock time, all of them at once, sampled every
# minute. Sourced by scripts/soak.sh after compare.sh, whose images, capture
# pods and client launchers it uses unchanged; it defines functions only,
# and `endurance_run` runs them.
#
# Each client has an account of its own, labuser-endure-<client> (soak.sh
# writes them, registration held to one or two minutes as for soak.sh
# endurance, so each client registers again every minute or two), and a pod
# of its own: its own network namespace, its own capture of its SIP, its own
# PID 1 to read. They share the machine and the Asterisk, which carries one
# call per client at a time; nothing one of them does is read as another's.
#
# A call is [compare-endurance] in interop/asterisk/extensions.conf: three
# minutes of cadenced tone, a DTMF "#", then Asterisk hangs up -- the same
# call scripts/soak.sh endurance places, ended by Asterisk because the other
# clients do not hang up on a digit. Each client echoes what it hears (the
# agent, pjsua --auto-loop, baresip's echo module) or, linphonec, plays a
# file back, so audio flows both ways for the whole call. The next call is
# placed once the last one is gone.
#
# Every SOAK_INTERVAL_S (60 unless told otherwise) one row per client goes
# to <client>.csv:
#
#   utc, elapsed_s     the sample's time, seconds since the run started
#   rss_kb             VmRSS of the client's process
#   private_kb         Private_Clean + Private_Dirty of its smaps_rollup
#   anon_kb            Anonymous of its smaps_rollup: what it allocated
#   cpu_s              user plus system time since it started, in seconds
#   fds, threads       its open descriptors and its threads
#   offered            calls Asterisk was asked to place to it
#   answered, done     calls it answered, and calls it held to the end
#
# The process is read from the host's /proc, by the PID Docker reports for
# the container, so the reading costs the client nothing.

END_KINDS="${SIPRAL_COMPARE_CLIENTS:-sipral pjsua baresip linphone}"
END_POLL_S=3

end_user() { printf 'labuser-endure-%s' "$1"; }

# Calls for client $1 until $2 (Unix time): one at a time, the next placed
# once Asterisk holds no channel of that account any more. Each one placed
# is a line in $OUT/$1.offered.
end_driver() {
    local kind="$1" until="$2" user waited channels
    user=$(end_user "$kind")
    # $$ is the run itself: a driver whose run is gone stops placing calls
    while [ "$(date +%s)" -lt "$until" ] && kill -0 $$ 2>/dev/null; do
        cmp_ast "channel originate PJSIP/$user extension s@compare-endurance" >/dev/null
        printf '%s\n' "$(date +%s)" >>"$END_OUT/$kind.offered"
        sleep "$END_POLL_S"
        waited=0
        # a call that is still there past its three minutes, a ring and
        # the end, by a margin, is ended here so that the next one can come
        # a reading that failed is read again rather than taken for "no
        # channel" (the 8 October run placed one call over a live one, by a
        # reading that did not show the live call)
        while :; do
            if ! channels=$(cmp_ast "core show channels concise"); then
                sleep 1
                continue
            fi
            printf '%s\n' "$channels" | grep -q "^PJSIP/$user-" || break
            waited=$((waited + END_POLL_S))
            if [ "$waited" -ge 240 ]; then
                cmp_ast "core show channels concise" | grep "^PJSIP/$user-" | cut -d'!' -f1 \
                    | while read -r channel; do
                        cmp_ast "channel request hangup $channel" >/dev/null
                    done
                printf '%s\n' "$(date +%s)" >>"$END_OUT/$kind.stuck"
            fi
            sleep "$END_POLL_S"
        done
        sleep 1
    done
}

# One row for client $1, whose process is host PID $2.
end_sample() {
    local kind="$1" pid="$2" now status rollup stat rss threads private anon cpu fds hz
    local offered globals up held
    now=$(date +%s)
    status=$(cat "/proc/$pid/status" 2>/dev/null) || return 1
    rollup=$(cat "/proc/$pid/smaps_rollup" 2>/dev/null)
    stat=$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null)
    hz=$(getconf CLK_TCK)
    rss=$(printf '%s\n' "$status" | awk '/^VmRSS:/{print $2}')
    threads=$(printf '%s\n' "$status" | awk '/^Threads:/{print $2}')
    private=$(printf '%s\n' "$rollup" | awk '/^Private_(Clean|Dirty):/{sum += $2} END {print sum + 0}')
    anon=$(printf '%s\n' "$rollup" | awk '/^Anonymous:/{print $2}')
    cpu=$(printf '%s\n' "$stat" | awk -v hz="$hz" '{printf "%.2f", ($12 + $13) / hz}')
    fds=$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
    offered=$(wc -l <"$END_OUT/$kind.offered" 2>/dev/null || printf 0)
    globals="$3"
    up=$(printf '%s\n' "$globals" | sed -n "s/^ *ENDURE_UP_$kind=\([0-9]*\).*/\1/p")
    held=$(printf '%s\n' "$globals" | sed -n "s/^ *ENDURE_DONE_$kind=\([0-9]*\).*/\1/p")
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$(date -u +%FT%TZ)" "$((now - END_START))" \
        "$rss" "$private" "${anon:-0}" "$cpu" "$fds" "$threads" "$((offered + 0))" \
        "${up:-0}" "${held:-0}" >>"$END_OUT/$kind.csv"
}

# $1 hours, $2 the agent binary, $3 the directory everything goes to.
endurance_run() {
    local hours="$1" kind until next globals ip pids="" status=0
    CMP_AGENT="$2"
    END_OUT="$3"
    CMP_OUT="$END_OUT"
    mkdir -p "$CMP_OUT"
    CMP_ASTERISK_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
        "$(cd "$ROOT/interop" && docker compose ps -q asterisk)")
    [ -n "$CMP_ASTERISK_IP" ] || { fail "Asterisk has no address"; return 1; }
    cmp_images || return 1
    cmp_versions
    # every client up and registered, each in a pod of its own, before the
    # clock starts, so that none of them is measured starting while another
    # is already taking calls
    for kind in $END_KINDS; do
        CMP_POD="$CMP_PREFIX-$kind-pod"
        CMP_CLIENT="$CMP_PREFIX-$kind"
        CMP_USER=$(end_user "$kind")
        cmp_pod_up || { fail "the pod for $kind"; return 1; }
        docker exec -d "$CMP_POD" sh -c \
            "echo \$\$ >/tmp/tcpdump.pid; exec tcpdump -i any -s 0 -U -w /out/$kind-sip.pcap udp port 5060 >/dev/null 2>&1"
        cmp_client_up "$kind" || { fail "$kind did not register"; return 1; }
        pass "$kind: registered as $CMP_USER"
        printf 'utc,elapsed_s,rss_kb,private_kb,anon_kb,cpu_s,fds,threads,offered,answered,done\n' \
            >"$END_OUT/$kind.csv"
        : >"$END_OUT/$kind.offered"
    done
    END_START=$(date +%s)
    # hours may be a fraction, for a short trial of the whole run
    until=$((END_START + $(awk -v h="$hours" 'BEGIN { printf "%d", h * 3600 }')))
    printf '  note  %s hours from %s, a row a client every %s s in %s\n' \
        "$hours" "$(date -u +%FT%TZ)" "$INTERVAL" "$END_OUT"
    for kind in $END_KINDS; do
        end_driver "$kind" "$until" &
        pids="$pids $!"
        END_DRIVERS="$pids"
    done
    next=$END_START
    while [ "$(date +%s)" -lt "$until" ]; do
        if [ "$(date +%s)" -ge "$next" ]; then
            globals=$(cmp_ast "dialplan show globals")
            for kind in $END_KINDS; do
                end_sample "$kind" "$(docker inspect -f '{{.State.Pid}}' "$CMP_PREFIX-$kind" 2>/dev/null)" \
                    "$globals" || printf '  %s is gone\n' "$kind"
            done
            next=$((next + INTERVAL))
        fi
        sleep 1
    done
    for pid in $pids; do
        wait "$pid" 2>/dev/null
    done
    # the last calls run out by themselves, and the last row follows them
    sleep 5
    globals=$(cmp_ast "dialplan show globals")
    for kind in $END_KINDS; do
        end_sample "$kind" "$(docker inspect -f '{{.State.Pid}}' "$CMP_PREFIX-$kind" 2>/dev/null)" \
            "$globals" || { printf '  %s is gone\n' "$kind"; status=1; }
    done
    for kind in $END_KINDS; do
        CMP_POD="$CMP_PREFIX-$kind-pod"
        CMP_CLIENT="$CMP_PREFIX-$kind"
        ip=$(cmp_pod_ip)
        docker exec "$CMP_POD" sh -c 'kill -INT "$(cat /tmp/tcpdump.pid)"' >/dev/null 2>&1
        sleep 1
        docker logs "$CMP_CLIENT" >"$END_OUT/$kind.log" 2>&1
        cmp_result "$kind" "endurance" "$(python3 "$ROOT/interop/compare/endurance.py" "$END_OUT/$kind.csv") $(cmp_wire registrations "/out/$kind-sip.pcap" "$ip") stuck=$(cat "$END_OUT/$kind.stuck" 2>/dev/null | wc -l | tr -d ' ')"
        cmp_pod_down
    done
    docker rmi "$CMP_POD_IMAGE" "$CMP_PJSUA_IMAGE" "$CMP_BARESIP_IMAGE" "$CMP_LINPHONE_IMAGE" >/dev/null 2>&1
    return "$status"
}
