#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# Long runs against the lab's Asterisk, with the voice agent pair the lab's
# headless step already uses: the application
# (crates/sipral/examples/headless-socket-agent.rs) holds the SIP and RTP,
# the echo agent (crates/sipral-headless/examples/agent.rs) sits on its
# socket.
#
#   scripts/soak.sh endurance [HOURS]   calls one after another for HOURS
#                                       (default 24), sampled to a CSV
#   scripts/soak.sh latency [CALLS]     CALLS short calls (default 200),
#                                       timed at both ends of the socket
#   scripts/soak.sh compare [HOURS]     the endurance comparison: Sipral's
#                                       headless agent, pjsua, baresip and
#                                       linphonec taking calls side by side
#                                       for HOURS (default 3), sampled to a
#                                       CSV each (interop/compare/
#                                       endurance.sh says how)
#
# The first two need the two binaries built for Linux, named the way
# scripts/lab.sh names them:
#
#   SIPRAL_HEADLESS_APP     the headless-socket-agent example
#   SIPRAL_HEADLESS_CLIENT  the sipral-headless agent example
#
# and `compare` the headless-agent example, as `scripts/lab.sh compare`
# takes it:
#
#   SIPRAL_HEADLESS_AGENT   the headless-agent example
#
# Each writes everything under SOAK_DIR (default target/soak/<word>-<UTC
# time>).
#
# None takes the lab lock: each runs under a Compose project of its own
# (sipral-soak-<word>, or SOAK_PROJECT), Asterisk alone, on a network of its
# own, so a long run never holds the lock every lab run waits on and never
# touches another run's containers. It removes only what it started, by
# name.
#
# endurance: each call is the dialplan's [soak-call], three minutes of tone,
# then the "#" the agent hangs up on, so the BYE is the stack's own; the next
# call starts once the last one ended. The account's registration is held
# to between one and two minutes (the overlay below), so the stack
# registers again every minute or two for the whole run. Every
# SOAK_INTERVAL_S (default 60) one row goes to samples.csv:
#
#   utc          the sample's time
#   elapsed_s    seconds since the application started
#   rss_kb       the application's resident memory (/proc/PID/status VmRSS)
#   cpu_pct      its processor time since the last row, percent of one core
#   fds          its open descriptors (/proc/PID/fd)
#   threads      its threads
#   calls        calls it ended (`ended` lines in its log)
#   registered   registrations it reported (`registered` lines)
#   errors       lines in its log that report a failure, plus the calls
#                Asterisk had to end itself because the agent never did,
#                plus the calls that had not ended five minutes on
#
# The run holds, in the sense docs/19-numbers.md publishes, when rss_kb and
# fds are flat after the first hour, calls grows by one every three minutes
# and errors stays at 0.
#
# latency: each call is the dialplan's [agent-call], a tone and the "#". With
# --timings on both binaries, the application prints when the INVITE reached
# it and when the first RTP packet carrying the agent's audio left, and the
# agent when the call's first frame reached it and when it wrote its first
# frame back; both read the same host's wall clock. latency.csv has one row a
# call, and the summary the median and the 95th percentile of
#
#   invite_to_first_frame_us   INVITE in, to the first audio frame at the agent
#   reply_to_first_rtp_us      the agent's first frame written, to the first
#                              RTP packet carrying it on the wire
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

WORD="${1:-}"
case "$WORD" in
endurance) HOURS="${2:-24}" ;;
latency) CALLS="${2:-200}" ;;
compare) HOURS="${2:-3}" ;;
*)
    printf 'usage: scripts/soak.sh endurance [HOURS] | latency [CALLS] | compare [HOURS]\n'
    exit 2
    ;;
esac

APP="${SIPRAL_HEADLESS_APP:-}"
CLIENT="${SIPRAL_HEADLESS_CLIENT:-}"
AGENT="${SIPRAL_HEADLESS_AGENT:-}"
if [ "$WORD" = compare ]; then
    [ -x "$AGENT" ] || { printf 'set SIPRAL_HEADLESS_AGENT to the Linux headless-agent binary\n'; exit 2; }
    AGENT=$(cd "$(dirname "$AGENT")" && pwd)/$(basename "$AGENT")
else
    [ -x "$APP" ] && [ -x "$CLIENT" ] || {
        printf 'set SIPRAL_HEADLESS_APP and SIPRAL_HEADLESS_CLIENT to the two Linux binaries\n'
        exit 2
    }
fi
command -v docker >/dev/null 2>&1 || { printf 'docker is not on the path\n'; exit 2; }

OUT="${SOAK_DIR:-$ROOT/target/soak/$WORD-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT" || exit 2
OUT=$(cd "$OUT" && pwd)
INTERVAL="${SOAK_INTERVAL_S:-60}"

export COMPOSE_PROJECT_NAME="${SOAK_PROJECT:-sipral-soak-$WORD}"
NETWORK="${COMPOSE_PROJECT_NAME}_lab"
APP_NAME="$COMPOSE_PROJECT_NAME-app"
CLIENT_NAME="$COMPOSE_PROJECT_NAME-agent"
USER_NAME=labuser-agent-headless

# The registration overlay: pjsip.conf's own #include of pjsip_local.conf is
# its last line, so a (+) section there adds to the account as declared;
# filtered to the aor, since the auth and the endpoint share its name.
cat >"$OUT/pjsip_local.conf" <<'CONF'
; generated by scripts/soak.sh
[labuser-agent-headless](+type=aor)
minimum_expiration=60
default_expiration=120
maximum_expiration=120
CONF
# `compare`: an account per client compared, declared whole here (the file
# is included last, so new sections are as good as pjsip.conf's own), the
# registration held the same way
if [ "$WORD" = compare ]; then
    for kind in sipral pjsua baresip linphone; do
        cat >>"$OUT/pjsip_local.conf" <<CONF
[labuser-endure-$kind]
type=auth
auth_type=userpass
username=labuser-endure-$kind
password=labpass

[labuser-endure-$kind]
type=aor
max_contacts=1
remove_existing=yes
minimum_expiration=60
default_expiration=120
maximum_expiration=120

[labuser-endure-$kind]
type=endpoint
transport=transport-udp
context=lab
auth=labuser-endure-$kind
aors=labuser-endure-$kind
disallow=all
allow=ulaw
allow=alaw

CONF
    done
fi
cat >"$OUT/compose.override.yaml" <<YAML
services:
  asterisk:
    volumes:
      - $OUT/pjsip_local.conf:/etc/asterisk/pjsip_local.conf:ro
YAML

compose() {
    ( cd "$ROOT/interop" && docker compose -f compose.yaml -f "$OUT/compose.override.yaml" "$@" )
}
asterisk_cli() { compose exec -T asterisk asterisk -rx "$1" 2>/dev/null; }

LOGS_PIDS=""
teardown() {
    docker rm -f "$APP_NAME" "$CLIENT_NAME" >/dev/null 2>&1
    for pid in $LOGS_PIDS; do
        wait "$pid" 2>/dev/null
    done
    compose down >/dev/null 2>&1
}
trap teardown EXIT
trap 'exit 130' INT TERM

compose up -d asterisk >/dev/null 2>&1 || { printf 'Asterisk did not come up\n'; exit 1; }
tries=0
until asterisk_cli 'pjsip show transports' | grep '0\.0\.0\.0:5060' >/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -ge 60 ] && { printf 'Asterisk never opened its SIP socket\n'; exit 1; }
    sleep 1
done

# compare: the clients compared, from interop/compare/, with the step, pass
# and fail lines scripts/lab.sh prints, on this run's own network
if [ "$WORD" = compare ]; then
    step() { printf '%s\n' "$1"; }
    pass() { printf '  ok    %s\n' "$1"; }
    fail() { printf '  FAIL  %s\n' "$1"; }
    LAB_NETWORK="$NETWORK"
    # shellcheck source=interop/compare/compare.sh
    . "$ROOT/interop/compare/compare.sh"
    # shellcheck source=interop/compare/endurance.sh
    . "$ROOT/interop/compare/endurance.sh"
    END_DRIVERS=""
    compare_teardown() {
        for pid in $END_DRIVERS; do
            kill "$pid" 2>/dev/null
        done
        for kind in $END_KINDS; do
            docker rm -f "$CMP_PREFIX-$kind" "$CMP_PREFIX-$kind-pod" >/dev/null 2>&1
        done
        compose down >/dev/null 2>&1
    }
    trap compare_teardown EXIT
    step "the endurance comparison, $HOURS hours"
    endurance_run "$HOURS" "$AGENT" "$OUT"
    exit $?
fi

TIMINGS=""
[ "$WORD" = latency ] && TIMINGS="--timings"

docker rm -f "$APP_NAME" "$CLIENT_NAME" >/dev/null 2>&1
docker run -d --name "$APP_NAME" --network "$NETWORK" \
    -v "$(cd "$(dirname "$APP")" && pwd):/sipral:ro" \
    debian:trixie-slim sh -c '
        own=$(hostname -i)
        address=$(getent hosts asterisk | cut -d" " -f1)
        exec /sipral/'"$(basename "$APP")"' \
            --host "$own" --port 5060 --socket 0.0.0.0:7001 \
            --register '"$USER_NAME"'@asterisk \
            --registrar "$address:5060" --pass labpass '"$TIMINGS" >/dev/null \
    || { printf 'the application did not start\n'; exit 1; }
docker logs -f "$APP_NAME" >"$OUT/app.log" 2>&1 &
LOGS_PIDS="$!"

tries=0
until grep '^waiting for the agent' "$OUT/app.log" >/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -ge 30 ] && { printf 'the application never came up\n'; exit 1; }
    sleep 1
done
docker run -d --name "$CLIENT_NAME" --network "$NETWORK" \
    -v "$(cd "$(dirname "$CLIENT")" && pwd):/sipral:ro" \
    debian:trixie-slim "/sipral/$(basename "$CLIENT")" --addr "$APP_NAME:7001" $TIMINGS >/dev/null \
    || { printf 'the agent did not start\n'; exit 1; }
docker logs -f "$CLIENT_NAME" >"$OUT/agent.log" 2>&1 &
LOGS_PIDS="$LOGS_PIDS $!"

tries=0
until asterisk_cli 'pjsip show contacts' | grep "$USER_NAME" >/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -ge 60 ] && { printf 'the application never registered\n'; exit 1; }
    sleep 1
done
printf 'up: application %s, agent %s, logs in %s\n' "$APP_NAME" "$CLIENT_NAME" "$OUT"

count() { grep -c -E "$1" "$2" 2>/dev/null || true; }

# Waits for the application's `ended` line count to reach $1, up to $2 s.
wait_ended() {
    local want="$1" limit="$2" waited=0
    while [ "$(count '^ended ' "$OUT/app.log")" -lt "$want" ]; do
        waited=$((waited + 1))
        [ "$waited" -ge "$limit" ] && return 1
        sleep 1
    done
}

originate() {
    asterisk_cli "channel originate PJSIP/$USER_NAME extension s@$1" >/dev/null
}

if [ "$WORD" = latency ]; then
    missed=0
    i=0
    while [ "$i" -lt "$CALLS" ]; do
        i=$((i + 1))
        originate agent-call
        wait_ended "$i" 30 || { missed=$((missed + 1)); i=$(count '^ended ' "$OUT/app.log"); }
        sleep 1
    done
    python3 - "$OUT" "$missed" <<'PY'
import statistics, sys
out, missed = sys.argv[1], int(sys.argv[2])
at = {}
for name in ("app.log", "agent.log"):
    for line in open(f"{out}/{name}", encoding="utf-8", errors="replace"):
        parts = line.split()
        if len(parts) == 4 and parts[0] == "timing":
            at.setdefault(parts[2], {})[parts[1]] = int(parts[3])
rows = []
for call, t in at.items():
    if all(k in t for k in ("invite", "first-frame", "reply", "first-rtp")):
        rows.append((call, t["first-frame"] - t["invite"], t["first-rtp"] - t["reply"]))
with open(f"{out}/latency.csv", "w", encoding="utf-8") as csv:
    csv.write("call,invite_to_first_frame_us,reply_to_first_rtp_us\n")
    for row in rows:
        csv.write(",".join(map(str, row)) + "\n")
def p95(values):
    ordered = sorted(values)
    return ordered[max(0, -(-95 * len(ordered) // 100) - 1)]
print(f"calls timed: {len(rows)} of {len(at)} seen, {missed} never ended in time")
if rows:
    for index, name in ((1, "invite_to_first_frame_us"), (2, "reply_to_first_rtp_us")):
        values = [row[index] for row in rows]
        print(f"{name}: median {statistics.median(values):.0f} p95 {p95(values)} "
              f"min {min(values)} max {max(values)}")
PY
    exit $?
fi

# endurance
PID=$(docker inspect -f '{{.State.Pid}}' "$APP_NAME")
TICKS=$(getconf CLK_TCK)
START=$(date +%s)
END=$((START + HOURS * 3600))
CSV="$OUT/samples.csv"
printf 'utc,elapsed_s,rss_kb,cpu_pct,fds,threads,calls,registered,errors\n' >"$CSV"
printf 'application pid %s on this host; samples every %s s to %s\n' "$PID" "$INTERVAL" "$CSV"

cpu_ticks() { awk '{print $14 + $15}' "/proc/$PID/stat" 2>/dev/null; }

sample() {
    local now ticks rss fds threads calls registered errors backstop cpu
    now=$(date +%s)
    ticks=$(cpu_ticks)
    [ -n "$ticks" ] || return 1
    rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$PID/status")
    threads=$(awk '/^Threads:/ {print $2}' "/proc/$PID/status")
    fds=$(ls "/proc/$PID/fd" 2>/dev/null | wc -l)
    calls=$(count '^ended ' "$OUT/app.log")
    registered=$(count '^registered$' "$OUT/app.log")
    errors=$(count 'failed|refused|stopped reading|socket closed|cannot' "$OUT/app.log")
    backstop=$(asterisk_cli 'dialplan show globals' | awk -F= '/SOAK_BACKSTOP/ {print $2}' | tr -dc 0-9)
    errors=$((errors + ${backstop:-0} + MISSED))
    cpu=$(awk -v d="$((ticks - LAST_TICKS))" -v s="$((now - LAST_AT))" -v hz="$TICKS" \
        'BEGIN { if (s > 0) printf "%.2f", 100 * d / hz / s; else print "0.00" }')
    LAST_TICKS=$ticks
    LAST_AT=$now
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$(date -u +%FT%TZ)" "$((now - START))" \
        "$rss" "$cpu" "$fds" "$threads" "$calls" "$registered" "$errors" >>"$CSV"
}

LAST_TICKS=$(cpu_ticks)
LAST_AT=$START
NEXT_SAMPLE=$START
placed=0
give_up=$START
MISSED=0
while [ "$(date +%s)" -lt "$END" ]; do
    now=$(date +%s)
    if [ "$now" -ge "$NEXT_SAMPLE" ]; then
        sample || { printf 'the application is gone (pid %s)\n' "$PID"; exit 1; }
        NEXT_SAMPLE=$((NEXT_SAMPLE + INTERVAL))
    fi
    ended=$(count '^ended ' "$OUT/app.log")
    # a call still not ended five minutes on (three of tone, the backstop
    # ten seconds after) never came up or never ended: an error, and the
    # next one is placed anyway
    if [ "$ended" -ge "$placed" ] || [ "$now" -ge "$give_up" ]; then
        [ "$ended" -lt "$placed" ] && MISSED=$((MISSED + 1))
        originate soak-call
        placed=$((ended + 1))
        give_up=$((now + 300))
    fi
    sleep 1
done
sample
printf 'done: %s hours, %s\n' "$HOURS" "$CSV"
