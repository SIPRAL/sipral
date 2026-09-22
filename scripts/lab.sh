#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# The interop lab: three real servers on default settings, and the flows run
# against them, plus a fourth proxy brought up only for its own step. Every
# other test in this workspace runs the stack against a peer we wrote; this
# is the one that does not.
#
#   scripts/lab.sh              register, call, hold, resume, both transfers,
#                               through each proxy and straight at Asterisk,
#                               then phone to phone through the proxy, then
#                               the same call over a link made bad
#   scripts/lab.sh kamailio     one server only
#   scripts/lab.sh opensips     the second proxy only
#   scripts/lab.sh asterisk
#   scripts/lab.sh baresip      only the phone-to-phone flows, against baresip
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

# The same flows again, through the C ABI rather than through the Rust API.
# The Rust driver proves the stack; this one proves the header, which is a
# different thing and the one an integrator actually meets. A defect that
# lives in the boundary -- a struct whose length the two sides disagree
# about, a handle that goes stale, an entry point that wants a clock nobody
# passes it -- cannot fail the Rust driver by construction.
#
# It is skipped rather than fatal when the library is not there: the C driver
# links the shared library, and a machine that built the Rust harness for a
# different target has one and not the other. A skip says so.
step "the harness, in C"
if [ -n "${SIPRAL_HARNESS_C:-}" ]; then
    [ -x "$SIPRAL_HARNESS_C" ] || { fail "SIPRAL_HARNESS_C is not an executable file"; exit 1; }
    HARNESS_C="$SIPRAL_HARNESS_C"
    pass "taken as given: $HARNESS_C"
else
    HARNESS_C=""
    for suffix in so dylib; do
        [ -f "$ROOT/target/release/libsipral_ffi.$suffix" ] || continue
        if cc -std=c99 -Wall -Wextra -Werror \
            -I "$ROOT/bindings/c/include" \
            -o "$ROOT/target/release/harness-c" "$ROOT/interop/harness-c/main.c" \
            -L "$ROOT/target/release" -lsipral_ffi \
            -Wl,-rpath,"$ROOT/target/release" >/dev/null 2>&1; then
            HARNESS_C="$ROOT/target/release/harness-c"
            pass "built"
        else
            fail "cc interop/harness-c/main.c"
        fi
        break
    done
    [ -n "$HARNESS_C" ] || printf '  note  no libsipral_ffi to link against; the C flows are skipped\n'
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
    # $4, when given, is a Compose profile name to pass on every call here:
    # opensips carries one so that `up` does not start it by accident, and
    # `logs` on an existing container needs no such flag but takes it without
    # complaint, so the same probe serves both cases
    local service="$1" phrase="$2" required="${3:-required}" profile="${4:-}" tries=0
    local -a compose_profile=()
    [ -n "$profile" ] && compose_profile=(--profile "$profile")
    while [ "$tries" -lt 45 ]; do
        if ( cd interop && docker compose "${compose_profile[@]}" logs --no-color "$service" 2>/dev/null ) \
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
    ( cd interop && docker compose "${compose_profile[@]}" logs --no-color "$service" | tail -40 )
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

# The same, driven through the C ABI. A function of its own rather than an
# argument to the one above, because the two differ in more than the binary:
# the C driver links the shared library, so the container needs that mounted
# beside it, and its capture is written under its own name so that neither run
# overwrites the other's.
flows_c() {
    local server="$1" capture="$2" beside
    [ -n "$HARNESS_C" ] || return 0
    # the library comes from wherever the binary did, not from this
    # checkout's own target directory: the machine that runs the lab need not
    # be the machine that built either, and on the one of ours that cannot
    # build them the two live under /opt rather than here
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    docker run --rm --network sipral-interop_lab \
        --cap-add NET_RAW --cap-add NET_ADMIN \
        -e SIPRAL_REQUIRE_AUDIO=1 \
        -e LD_LIBRARY_PATH=/lib-sipral \
        -v "$HARNESS_C:/harness-c:ro" \
        -v "$beside:/lib-sipral:ro" \
        -v "$ROOT/interop/pcap:/pcap" \
        debian:trixie-slim sh -c "
            export DEBIAN_FRONTEND=noninteractive
            apt-get -qq update >/dev/null 2>&1
            apt-get -qq install -y tcpdump >/dev/null 2>&1
            tcpdump -i any -s 0 -U -w /pcap/$capture.pcap 2>/dev/null &
            sleep 2
            /harness-c $server 5060 9000
            status=\$?
            sleep 1
            kill %1 2>/dev/null
            exit \$status"
}

# The Python binding's example agent, run exactly as its own docstring says to
# run it, registered at Asterisk and called by it. What the loopback test in
# bindings/python/tests cannot show is that what the agent advertises -- its
# Contact, its answer's SDP -- is somewhere a real server can reach, and that
# the tone the server plays comes back through `respond`. It needs the shared
# library the C driver links, so it runs when that one does.
#
# The agent never exits on its own, it serves calls until stopped, so it runs
# detached and the lab reads its output: registered, answered, heard audio,
# and hung up on the "#" rather than being hung up on.
AGENT_NAME=sipral-lab-agent
python_agent() {
    local beside log tries
    [ -n "$HARNESS_C" ] || return 0
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    docker rm -f "$AGENT_NAME" >/dev/null 2>&1
    docker run -d --name "$AGENT_NAME" --network sipral-interop_lab \
        -e SIPRAL_LIBRARY=/lib-sipral \
        -e PYTHONPATH=/python \
        -e SIPRAL_AOR=sip:labuser-agent@asterisk \
        -e SIPRAL_REGISTRAR=sip:asterisk \
        -e SIPRAL_AUTH_USER=labuser-agent -e SIPRAL_AUTH_PASSWORD=labpass \
        -v "$beside:/lib-sipral:ro" \
        -v "$ROOT/bindings/python:/python:ro" \
        debian:trixie-slim sh -c '
            export DEBIAN_FRONTEND=noninteractive
            apt-get -qq update >/dev/null 2>&1
            apt-get -qq install -y python3 python3-cffi >/dev/null 2>&1
            address=$(getent hosts asterisk | cut -d" " -f1)
            SIPRAL_REGISTRAR_ADDRESS="$address:5060" \
                exec python3 -u /python/examples/agent.py' >/dev/null \
        || { printf '  could not start the agent container\n'; return 1; }

    tries=0
    until ( cd interop && docker compose exec -T asterisk \
            asterisk -rx "pjsip show contacts" 2>/dev/null ) | grep -q labuser-agent; do
        tries=$((tries + 1))
        # an agent that died on start is not going to register however long
        # it is given, and what it said as it died is the useful part
        if [ "$(docker inspect -f '{{.State.Running}}' "$AGENT_NAME" 2>/dev/null)" != true ] \
            || [ "$tries" -ge 60 ]; then
            printf '  the agent never registered\n'
            docker logs "$AGENT_NAME" 2>&1 | tail -20
            docker rm -f "$AGENT_NAME" >/dev/null 2>&1
            return 1
        fi
        sleep 2
    done

    ( cd interop && docker compose exec -T asterisk asterisk -rx \
        "channel originate PJSIP/labuser-agent extension s@agent-call" ) >/dev/null 2>&1

    tries=0
    until docker logs "$AGENT_NAME" 2>&1 | grep -q '^ended '; do
        tries=$((tries + 1))
        [ "$tries" -ge 30 ] && break
        sleep 1
    done
    log=$(docker logs "$AGENT_NAME" 2>&1)
    docker rm -f "$AGENT_NAME" >/dev/null 2>&1
    printf '%s\n' "$log" | sed 's/^/    /'

    printf '%s\n' "$log" | grep -q '^answered ' \
        || { printf '  it never answered\n'; return 1; }
    printf '%s\n' "$log" | grep -q '^dtmf #' \
        || { printf '  it never heard the "#" it hangs up on\n'; return 1; }
    printf '%s\n' "$log" \
        | grep '^ended ' | grep -Eq "'packets_received': [1-9]" \
        || { printf '  it heard no audio\n'; return 1; }
    printf '%s\n' "$log" \
        | grep '^ended ' | grep -Eq "'packets_sent': [1-9]" \
        || { printf '  it sent no audio back\n'; return 1; }
}

# The phone-to-phone peer. The same shape as flows() above -- server,
# capture name, a tcpdump started first -- but the server is always
# "kamailio" (baresip is dialed through the proxy, never straight), the
# extension dialed is baresip's own AOR rather than 9000, and SIPRAL_PEER
# and SIPRAL_FLOWS keep the register/blind/attended flows and Asterisk's own
# hardcoded extensions out of a run that has neither: interop/harness's own
# main.rs only adds the SRTP and DTLS-SRTP flows below to a run that asks
# for SIPRAL_PEER=baresip, precisely so this step cannot silently start
# dialling baresip's accounts from scripts/lab.sh kamailio or asterisk.
flows_baresip() {
    local capture="$1"
    docker run --rm --network sipral-interop_lab \
        --cap-add NET_RAW --cap-add NET_ADMIN \
        -e SIPRAL_REQUIRE_AUDIO=1 -e SIPRAL_PEER=baresip \
        -e SIPRAL_FLOWS=call,hold,peersrtp,peerdtls \
        -v "$HARNESS:/harness:ro" \
        -v "$ROOT/interop/pcap:/pcap" \
        debian:trixie-slim sh -c "
            export DEBIAN_FRONTEND=noninteractive
            apt-get -qq update >/dev/null 2>&1
            apt-get -qq install -y tcpdump >/dev/null 2>&1
            tcpdump -i any -s 0 -U -w /pcap/$capture.pcap 2>/dev/null &
            sleep 2
            /harness kamailio 5060 baresip
            status=\$?
            sleep 1
            kill %1 2>/dev/null
            exit \$status"
}

# The same, through the C ABI. See flows_c() above for why this is a
# function of its own rather than an argument to flows_baresip().
flows_baresip_c() {
    local capture="$1" beside
    [ -n "$HARNESS_C" ] || return 0
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    docker run --rm --network sipral-interop_lab \
        --cap-add NET_RAW --cap-add NET_ADMIN \
        -e SIPRAL_REQUIRE_AUDIO=1 -e SIPRAL_PEER=baresip \
        -e SIPRAL_FLOWS=call,hold,peersrtp,peerdtls \
        -e LD_LIBRARY_PATH=/lib-sipral \
        -v "$HARNESS_C:/harness-c:ro" \
        -v "$beside:/lib-sipral:ro" \
        -v "$ROOT/interop/pcap:/pcap" \
        debian:trixie-slim sh -c "
            export DEBIAN_FRONTEND=noninteractive
            apt-get -qq update >/dev/null 2>&1
            apt-get -qq install -y tcpdump >/dev/null 2>&1
            tcpdump -i any -s 0 -U -w /pcap/$capture.pcap 2>/dev/null &
            sleep 2
            /harness-c kamailio 5060 baresip
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
    if [ -n "$HARNESS_C" ]; then
        step "the same, through the C ABI -- through the proxy"
        flows_c kamailio proxy-c && pass "kamailio to freeswitch, in C" \
            || fail "kamailio to freeswitch, in C"
    fi
fi

# OpenSIPS carries the `opensips` Compose profile, so it never came up with
# the three servers above; it is started here, for this step alone, and
# removed the moment the step's flows are done -- the host next to this lab
# is small, and a second proxy sitting idle through the Asterisk and netem
# steps below would raise the footprint for no run that needs it.
if [ "$WANT" = all ] || [ "$WANT" = opensips ]; then
    step "register, call, hold, resume, transfer -- through OpenSIPS"
    ( cd interop && docker compose --profile opensips up -d opensips ) >/dev/null 2>&1 \
        && pass "opensips container up" || { fail "docker compose up opensips"; exit 1; }
    wait_for opensips "Listening on" required opensips || exit 1
    flows opensips opensips && pass "opensips to freeswitch" || fail "opensips to freeswitch"
    if [ -n "$HARNESS_C" ]; then
        step "the same, through the C ABI -- through OpenSIPS"
        flows_c opensips opensips-c && pass "opensips to freeswitch, in C" \
            || fail "opensips to freeswitch, in C"
    fi
    ( cd interop && docker compose --profile opensips rm -sf opensips ) >/dev/null 2>&1
fi

# No proxy in front of this one, and a different stack behind it. The point of
# the second server is that a rule we read one way and Kamailio reads the same
# way may still be read differently by res_pjsip.
if [ "$WANT" = all ] || [ "$WANT" = asterisk ]; then
    step "register, call, hold, resume, transfer -- straight at Asterisk"
    flows asterisk asterisk && pass "asterisk" || fail "asterisk"
    if [ -n "$HARNESS_C" ]; then
        step "the same, through the C ABI -- straight at Asterisk"
        flows_c asterisk asterisk-c && pass "asterisk, in C" || fail "asterisk, in C"
        step "the Python example agent, called by Asterisk"
        python_agent && pass "agent.py answered, echoed and hung up" \
            || fail "agent.py"
    fi
fi

# The one step in this file where the far end is a client stack rather than
# a server: baresip, started and registered for this step alone
# (interop/compose.yaml's own "baresip" profile) and removed straight after
# -- this host already carries a live PBX beside the lab, and the image is
# the most expensive one here to build, so it must not add to the lab's
# steady footprint the way the three servers that run for the whole script
# do.
if [ "$WANT" = all ] || [ "$WANT" = baresip ]; then
    step "phone to phone -- baresip through the proxy"
    if ( cd interop && docker compose --profile baresip up -d baresip ) >/dev/null 2>&1; then
        pass "baresip: built and started"
        # the plain account is required -- without it neither flow below has
        # anyone to call -- and the SRTP and DTLS-SRTP ones are read the same
        # optional way freeswitch's own profile is above: a peer slower to
        # bring up its media-encryption modules should not stop the plain
        # call and hold flows from running, and the flows below name their
        # own missing account if it never registered.
        # bracketed exactly as interop/kamailio/kamailio.cfg's own xlog line
        # is: "baresip" is a prefix of "baresip-srtp" and "baresip-dtls" too,
        # and wait_for's own grep is an unanchored substring match, so the
        # plain account's phrase would otherwise be satisfied by either of
        # the other two registering first.
        if wait_for kamailio "lab: baresip registered [baresip]"; then
            wait_for kamailio "lab: baresip registered [baresip-srtp]" optional || true
            wait_for kamailio "lab: baresip registered [baresip-dtls]" optional || true
            flows_baresip proxy-baresip && pass "sipral to baresip" \
                || fail "sipral to baresip"
            if [ -n "$HARNESS_C" ]; then
                step "the same, through the C ABI -- baresip through the proxy"
                flows_baresip_c proxy-baresip-c && pass "sipral to baresip, in C" \
                    || fail "sipral to baresip, in C"
            fi
        fi
    else
        fail "docker compose up baresip"
    fi
    ( cd interop && docker compose stop baresip && docker compose rm -f baresip ) \
        >/dev/null 2>&1
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
