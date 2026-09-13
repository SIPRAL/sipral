#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# The interop lab: three real servers on default settings, and the flows run
# against them. Every other test in this workspace runs the stack against a
# peer we wrote; this is the one that does not.
#
#   scripts/lab.sh              register, call, hold, resume, both transfers,
#                               through the proxy and straight at Asterisk,
#                               then the same call over a link made bad
#   scripts/lab.sh kamailio     one server only
#   scripts/lab.sh asterisk
#   scripts/lab.sh netem        only the runs over a bad link, every profile
#   PROFILE=blackout scripts/lab.sh netem      one of them
#
# The profiles are interop/impairment/*.sh, and its README says what each one
# is for and how to write another.
#
# Needs Docker. That is the whole requirement, and it is why this is a script
# and not a hosted workflow: it runs wherever there is a Linux kernel with
# containers on it, including a machine of ours, and it takes the keys and the
# capture with it.
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
step() { printf '\n%s\n' "$1"; }

WANT="${1:-all}"

command -v docker >/dev/null 2>&1 || {
    printf 'docker is not on the path, and the lab is three containers.\n'
    printf 'On a machine without it, run this on one that has it: the lab is\n'
    printf 'self-contained and needs nothing from this checkout but the binary\n'
    printf 'it builds in the first step.\n'
    exit 2
}

# The machine that runs the lab need not be the machine that built the harness,
# and on at least one of ours it cannot be: the host is old enough that libopus
# will not compile on it, while the containers it runs are current. Build it
# wherever there is a toolchain and point SIPRAL_HARNESS at the result; it has
# to be a Linux binary, since that is what the container will run it as.
step "the harness"
if [ -n "${SIPRAL_HARNESS:-}" ]; then
    [ -x "$SIPRAL_HARNESS" ] || { fail "SIPRAL_HARNESS is not an executable file"; exit 1; }
    HARNESS="$SIPRAL_HARNESS"
    pass "taken as given: $HARNESS"
else
    cargo build --release -p sipral-interop >/dev/null 2>&1 \
        && pass "built" || { fail "cargo build -p sipral-interop"; exit 1; }
    HARNESS="$ROOT/target/release/sipral-interop"
fi

step "the lab"
mkdir -p interop/pcap
( cd interop && docker compose up -d ) >/dev/null 2>&1 \
    && pass "three containers up" || { fail "docker compose up"; exit 1; }

teardown() {
    step "what the servers said"
    ( cd interop && docker compose logs --no-color | tail -80 )
    ( cd interop && docker compose down ) >/dev/null 2>&1
}
trap teardown EXIT

# An active probe rather than a fixed sleep: FreeSWITCH is much the slowest of
# the three to open its socket, and how slow depends on the machine. Read from
# the log rather than from inside the container -- the Kamailio image is built
# without a shell, so there is nothing in there to run a check with, and a
# probe that needs the image's contents is a probe that breaks when the image
# is rebuilt.
wait_for() {
    local service="$1" phrase="$2" required="${3:-required}" tries=0
    while [ "$tries" -lt 45 ]; do
        if ( cd interop && docker compose logs --no-color "$service" 2>/dev/null ) \
            | grep -qF "$phrase"; then
            pass "$service: $phrase"
            return 0
        fi
        tries=$((tries + 1))
        sleep 2
    done
    if [ "$required" = optional ]; then
        printf '  note  %s never said "%s"; carrying on\n' "$service" "$phrase"
        return 1
    fi
    fail "$service never said it was up"
    ( cd interop && docker compose logs --no-color "$service" | tail -40 )
    return 1
}

step "waiting for the servers to listen"
wait_for kamailio "Listening on" || exit 1
wait_for freeswitch "MSG Thread 0 Started" || exit 1
# calls are relayed to the lab's own profile, which comes up after the core
# does. Not fatal on its own: the harness is the verdict, and a readiness probe
# that guesses at log wording should not be the thing that fails the run
wait_for freeswitch "Started Profile lab" optional || true
wait_for asterisk "Asterisk Ready" || exit 1

# The capture runs inside the harness's own container, on its own interface.
# Two other places were tried: the proxy's network namespace, which cannot see
# a flow that talks straight to Asterisk, and the lab's bridge on the host,
# which produced a twenty-four byte file on the runs worth looking at. The
# harness is one end of every exchange, so its own view is enough.
#
# A glibc image, because the binary is built against glibc here and the proxy's
# own image is musl -- the two are not interchangeable, and the error when they
# are swapped is "no such file or directory" for a file that is plainly there.
flows() {
    local server="$1" capture="$2"
    docker run --rm --network sipral-interop_lab \
        --cap-add NET_RAW --cap-add NET_ADMIN \
        -e SIPRAL_REQUIRE_AUDIO=1 \
        -v "$HARNESS:/harness:ro" \
        -v "$ROOT/interop/pcap:/pcap" \
        debian:trixie-slim sh -c "
            export DEBIAN_FRONTEND=noninteractive
            apt-get -qq update >/dev/null 2>&1
            apt-get -qq install -y tcpdump >/dev/null 2>&1
            tcpdump -i any -s 0 -U -w /pcap/$capture.pcap 2>/dev/null &
            sleep 2
            /harness $server 5060 9000
            status=\$?
            sleep 1
            kill %1 2>/dev/null
            exit \$status"
}

# The same call again, over a link deliberately made bad. netem shapes egress,
# so it is our packets that are delayed, lost in bursts and reordered; the echo
# means the return path suffers too, since a packet that never arrived is never
# echoed.
#
# The shapes live in interop/impairment/ rather than here, because a threshold
# is only meaningful against a profile somebody else can run.
#
# `tc` accepts what the kernel it is talking to does not necessarily apply, and
# says nothing when it does not: on a 3.10 kernel the delay is dropped in
# silence while the loss goes through. A run whose impairment never happened
# reads exactly like a clean one, which is worse than no run at all -- so the
# qdisc is read back against what the profile said it needed.
bad_network() {
    local profile="$1"
    # shellcheck disable=SC1090
    WHY=""; NETEM=""; REQUIRE=""; DWELL_MS=""; DURING=""
    . "$ROOT/interop/impairment/$profile.sh"
    printf '  %-10s %s\n' "$profile" "$WHY"
    docker run --rm --network sipral-interop_lab \
        --cap-add NET_ADMIN \
        -e SIPRAL_REQUIRE_AUDIO=1 -e SIPRAL_FLOWS=register,call \
        -e "SIPRAL_DWELL_MS=${DWELL_MS:-2000}" \
        -e "SIPRAL_PATIENCE_MS=$(( ${DWELL_MS:-2000} + 20000 ))" \
        -e "NETEM=$NETEM" -e "REQUIRE=$REQUIRE" -e "DURING=$DURING" \
        -v "$HARNESS:/harness:ro" \
        debian:trixie-slim sh -c '
            export DEBIAN_FRONTEND=noninteractive
            apt-get -qq update >/dev/null 2>&1
            apt-get -qq install -y iproute2 >/dev/null 2>&1
            link=$(ip route | awk "/^default/{print \$5}")
            # shellcheck disable=SC2086
            tc qdisc add dev "$link" root netem $NETEM
            applied=$(tc qdisc show dev "$link")
            echo "  $applied"
            if [ -n "$REQUIRE" ]; then
                case "$applied" in
                  *"$REQUIRE"*) ;;
                  *) echo "IMPAIRMENT-NOT-APPLIED"; exit 3 ;;
                esac
            fi
            if [ -n "$DURING" ]; then
                ( eval "$DURING" ) > /tmp/during 2>&1 &
            fi
            /harness kamailio 5060 9000
            status=$?
            wait
            if grep -q IMPAIRMENT-NOT-APPLIED /tmp/during 2>/dev/null; then
                cat /tmp/during
                exit 3
            fi
            exit $status'
}

if [ "$WANT" = all ] || [ "$WANT" = kamailio ]; then
    step "register, call, hold, resume, transfer -- through the proxy"
    flows kamailio proxy && pass "kamailio to freeswitch" || fail "kamailio to freeswitch"
fi

# No proxy in front of this one, and a different stack behind it. The point of
# the second server is that a rule we read one way and Kamailio reads the same
# way may still be read differently by res_pjsip.
if [ "$WANT" = all ] || [ "$WANT" = asterisk ]; then
    step "register, call, hold, resume, transfer -- straight at Asterisk"
    flows asterisk asterisk && pass "asterisk" || fail "asterisk"
fi

if [ "$WANT" = all ] || [ "$WANT" = netem ]; then
    step "the same call, over a bad network"
    for profile in ${PROFILE:-lossy mobile satellite blackout}; do
        [ -f "$ROOT/interop/impairment/$profile.sh" ] || {
            fail "no such profile: $profile"; continue
        }
        bad_network "$profile"
        case $? in
            0) pass "$profile: audio survived it" ;;
            # not a pass and not a failure: what the profile needed did not
            # happen, and the profile's own lines above say which part. On a
            # 3.10 kernel it is usually tc dropping a setting in silence; for
            # the outage it can also be the cut missing the call
            3) printf '  note  %s: the impairment did not happen the way the\n' "$profile"
               printf '        profile needs, so the run proves nothing. What it\n'
               printf '        found is printed above.\n' ;;
            *) fail "$profile" ;;
        esac
    done
fi

step "the capture"
ls -l interop/pcap || true

printf '\n'
[ "$FAIL" -eq 0 ] && { printf 'the lab agrees\n'; exit 0; }
printf 'the lab does not agree\n'; exit 1
