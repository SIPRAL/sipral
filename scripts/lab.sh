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
#   scripts/lab.sh nat          only the call from behind a NAT, with STUN
#                               against coturn, through the C ABI
#   scripts/lab.sh netem        only the runs over a bad link, every profile
#   PROFILE=blackout scripts/lab.sh netem      one of them
#   scripts/lab.sh pipewire     sipral-io-pipewire against a real PipeWire,
#                               then a call to Asterisk whose microphone and
#                               earpiece are PipeWire nodes -- built and run
#                               in interop/pipewire's own image, and not part
#                               of a run that names nothing, because it
#                               compiles the facade inside a container
#   scripts/lab.sh wasapi up    bring the lab up reachable from the LAN, for
#                               a call carried on a Windows machine's real
#                               WASAPI devices (interop/harness/src/wasapi.rs,
#                               interop/wasapi/run.ps1); nothing here runs
#                               that call itself -- there is no WASAPI in a
#                               Linux container -- only what the Windows
#                               machine needs to reach in
#   scripts/lab.sh wasapi down  tear that down again
#   scripts/lab.sh --matrix     the above, then regenerate docs/11-testing.md's
#                               own generated section from this run
#                               (scripts/interop-matrix.py); any of the words
#                               above may follow it, the same as without it
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

# Regenerates docs/11-testing.md's own generated section from this run's
# output, once the run is over -- not interleaved with it, so the generator
# only ever reads a complete log. Re-invoking this script without the flag
# and piping its output through tee, rather than teeing it in place with
# exec, is what gets that for free: the shell does not return from the
# pipeline below until both ends of it are done, so the log is whole by the
# time interop-matrix.py opens it, and the run is still shown on screen as it
# happens, tee's other job.
if [ "${1:-}" = "--matrix" ]; then
    shift
    command -v python3 >/dev/null 2>&1 || {
        printf 'python3 is not on the path, and scripts/interop-matrix.py needs it.\n'
        exit 2
    }
    LOG="$(mktemp)"
    "$0" "$@" 2>&1 | tee "$LOG"
    STATUS="${PIPESTATUS[0]}"
    if python3 "$ROOT/scripts/interop-matrix.py" "$LOG" --date "$(date -u +%F)"; then
        printf 'docs/11-testing.md regenerated from this run.\n'
    else
        printf 'note: docs/11-testing.md was not regenerated; see the error above.\n'
    fi
    rm -f "$LOG"
    exit "$STATUS"
fi

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

# interop/wasapi/run.ps1's other half: nothing below this runs on Windows, so
# this word only manages the lab's own side of that flow -- the override that
# publishes Asterisk's SIP and RTP ports so a machine outside the lab's own
# Docker network can reach in (interop/wasapi/compose.override.yaml says why
# that is an override rather than a change to compose.yaml itself), and the
# lock every step that brings the lab's servers up or down takes, so this
# never races another run doing the same on the same host.
if [ "$WANT" = wasapi ]; then
    SUB="${2:-}"
    LOCK="/var/lock/sipral-lab.lock"
    [ -e "$LOCK" ] || LOCK="$ROOT/.sipral-lab.lock"
    case "$SUB" in
    up)
        LAN_ADDR="${SIPRAL_LAN_ADDR:-}"
        if [ -z "$LAN_ADDR" ]; then
            LAN_ADDR="$(ip -4 -o addr show scope global 2>/dev/null \
                | awk '{print $4}' | cut -d/ -f1 | head -1)"
        fi
        [ -n "$LAN_ADDR" ] || {
            printf 'no LAN address found; set SIPRAL_LAN_ADDR to this machine'"'"'s own.\n'
            exit 2
        }
        # local_net is what tells PJSIP a peer is reached over the docker
        # bridge -- and, backwards, what tells it a peer is NOT, which is
        # the half this flow actually needs: get that wrong wide (a blanket
        # 192.168.0.0/16, say) and it also matches this machine's own real
        # LAN, PJSIP decides the Windows machine is "local" the same as the
        # bridge, and every SDP answer keeps advertising Asterisk's
        # container-internal address instead of $LAN_ADDR -- a call that
        # answers, on a media path that goes nowhere, silently. So this
        # asks Docker what the bridge's subnet actually is rather than
        # guessing a range that might overlap the real LAN: first with
        # nothing to reach past yet, so the container gets one made, then
        # again once it exists.
        printf '; generated by scripts/lab.sh wasapi up -- not committed, see .gitignore\n[transport-udp](+)\nexternal_media_address=%s\nexternal_signaling_address=%s\n' \
            "$LAN_ADDR" "$LAN_ADDR" >interop/wasapi/pjsip_local.generated.conf
        flock "$LOCK" sh -c \
            'cd interop && docker compose -f compose.yaml -f wasapi/compose.override.yaml up -d' \
            >/dev/null 2>&1 \
            || { fail "docker compose up (wasapi override)"; exit 1; }
        BRIDGE_SUBNET="$(docker network inspect sipral-interop_lab \
            --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null)"
        [ -n "$BRIDGE_SUBNET" ] || { fail "could not read sipral-interop_lab's own subnet"; exit 1; }
        printf 'local_net=%s\n' "$BRIDGE_SUBNET" >>interop/wasapi/pjsip_local.generated.conf
        flock "$LOCK" sh -c \
            'cd interop && docker compose -f compose.yaml -f wasapi/compose.override.yaml restart asterisk' \
            >/dev/null 2>&1 \
            && pass "the lab, reachable at $LAN_ADDR:5062 (bridge $BRIDGE_SUBNET)" \
            || { fail "docker compose restart asterisk (wasapi override)"; exit 1; }
        printf '  note  point interop/wasapi/run.ps1 (or SIPRAL_SERVER_HOST) at %s:5062\n' "$LAN_ADDR"
        ;;
    down)
        flock "$LOCK" sh -c \
            'cd interop && docker compose -f compose.yaml -f wasapi/compose.override.yaml down' \
            && pass "the lab, down" \
            || fail "docker compose down (wasapi override)"
        rm -f interop/wasapi/pjsip_local.generated.conf
        ;;
    *)
        printf 'usage: scripts/lab.sh wasapi up|down\n'
        exit 2
        ;;
    esac
    [ "$FAIL" -eq 0 ] && exit 0
    exit 1
fi

# The machine that runs the lab need not be the machine that built the harness,
# and on at least one of ours it cannot be: the host is old enough that libopus
# will not compile on it, while the containers it runs are current. Build it
# wherever there is a toolchain and point SIPRAL_HARNESS at the result; it has
# to be a Linux binary, since that is what the container will run it as.
#
# The PipeWire step builds its own, inside the image that has libpipewire to
# link it against, so neither build below is its to wait for.
step "the harness"
if [ "$WANT" = pipewire ]; then
    HARNESS=""
    printf '  note  built inside interop/pipewire'"'"'s image by its own step\n'
elif [ -n "${SIPRAL_HARNESS:-}" ]; then
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
if [ "$WANT" = pipewire ]; then
    HARNESS_C=""
    printf '  note  not used by the PipeWire step\n'
elif [ -n "${SIPRAL_HARNESS_C:-}" ]; then
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

# 8.5.4's own flow: the application that carries the call and speaks
# `sipral-headless`'s wire protocol on a socket, and the reference agent that
# answers over it — two binaries, `headless_socket_agent` below runs both.
# Skipped rather than fatal, on the same reasoning as the C harness above: a
# machine that cannot build one still runs the rest of the lab.
step "the socket-framed agent"
if [ -n "${SIPRAL_HEADLESS_APP:-}" ] && [ -n "${SIPRAL_HEADLESS_CLIENT:-}" ]; then
    HEADLESS_APP="$SIPRAL_HEADLESS_APP"
    HEADLESS_CLIENT="$SIPRAL_HEADLESS_CLIENT"
    pass "taken as given: $HEADLESS_APP, $HEADLESS_CLIENT"
else
    if cargo build --release -p sipral --features headless \
        --example headless-socket-agent >/dev/null 2>&1 \
        && cargo build --release -p sipral-headless --example agent >/dev/null 2>&1; then
        HEADLESS_APP="$ROOT/target/release/examples/headless-socket-agent"
        HEADLESS_CLIENT="$ROOT/target/release/examples/agent"
        pass "built"
    else
        HEADLESS_APP=""
        HEADLESS_CLIENT=""
        printf '  note  could not build the socket-framed agent; that step is skipped\n'
    fi
fi

# The Swift binding's own lab agent: `bindings/swift`'s `SipralLabAgent`
# executable target, over the same C ABI `HARNESS_C` above and the Python
# agent both prove, carried through `SipralStack`/`Account`/`Call`/`Media`
# instead. Needs `libsipral_ffi.so`, already built by the C harness step
# above -- built here, once, in a `swift:6.1` container (Swift on Linux is
# never assumed to be on the host's own `PATH`), the same reasoning as the
# socket-framed agent's own build: skipped rather than fatal when either is
# missing, so a machine that cannot build one still runs the rest of the lab.
step "the Swift binding's lab agent"
if [ -n "${SIPRAL_SWIFT_AGENT:-}" ]; then
    SWIFT_AGENT="$SIPRAL_SWIFT_AGENT"
    pass "taken as given: $SWIFT_AGENT"
elif [ -z "$HARNESS_C" ]; then
    SWIFT_AGENT=""
    printf '  note  no libsipral_ffi to link against; that step is skipped\n'
elif ! command -v docker >/dev/null 2>&1; then
    SWIFT_AGENT=""
else
    if docker run --rm -v "$ROOT":/work -w /work/bindings swift:6.1 \
        swift build -c release --product SipralLabAgent >/dev/null 2>&1; then
        SWIFT_AGENT="$ROOT/bindings/.build/release/SipralLabAgent"
        pass "built"
    else
        SWIFT_AGENT=""
        printf '  note  could not build the Swift lab agent; that step is skipped\n'
    fi
fi

step "the lab"
mkdir -p interop/pcap
( cd interop && docker compose up -d ) >/dev/null 2>&1 \
    && pass "three containers up" || { fail "docker compose up"; exit 1; }

teardown() {
    step "what the servers said"
    ( cd interop && docker compose logs --no-color | tail -80 )
    # a `down` with no profile named leaves profiled services running and the
    # networks only they use in place, so the `nat` step's two containers and
    # its `inside` network go here too, in case it never got to remove them
    ( cd interop && docker compose --profile nat down ) >/dev/null 2>&1
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
    # complaint, so the same probe serves both cases. The array is expanded
    # as ${a[@]+"${a[@]}"} because the lab host's bash is 4.2, where an empty
    # array expanded under `set -u` is an unbound variable and every probe in
    # this file would fail on it
    local service="$1" phrase="$2" required="${3:-required}" profile="${4:-}" tries=0
    local -a compose_profile=()
    [ -n "$profile" ] && compose_profile=(--profile "$profile")
    while [ "$tries" -lt 45 ]; do
        if ( cd interop && docker compose ${compose_profile[@]+"${compose_profile[@]}"} \
                logs --no-color "$service" 2>/dev/null ) \
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
    ( cd interop && docker compose ${compose_profile[@]+"${compose_profile[@]}"} \
        logs --no-color "$service" | tail -40 )
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

# org.sipral.idiomatic's own headless agent, bindings/kotlin/examples/Agent.kt,
# on a JVM (`eclipse-temurin`, the JDK variant -- its own `jni.h` is what the
# container compiles the shim against). Kotlin has no build tool in this tree
# (`bindings/kotlin/README.md`), so the classes are compiled once with
# `kotlinc` wherever this is run from and handed to this step as a jar,
# exactly the way `SIPRAL_HARNESS_C` above is a binary built elsewhere rather
# than something this script builds for itself;
# KOTLIN_AGENT_JAR/KOTLIN_STDLIB_JAR/KOTLIN_COROUTINES_JAR name the three jars
# its classpath needs. Skipped, not fatal, when any of the three -- or the
# shared library the C harness also needs -- is not there.
KOTLIN_AGENT_NAME=sipral-lab-agent-kotlin
kotlin_agent() {
    local log tries beside
    [ -n "${KOTLIN_AGENT_JAR:-}" ] && [ -n "${KOTLIN_STDLIB_JAR:-}" ] \
        && [ -n "${KOTLIN_COROUTINES_JAR:-}" ] || return 0
    [ -n "$HARNESS_C" ] || return 0
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    docker rm -f "$KOTLIN_AGENT_NAME" >/dev/null 2>&1
    docker run -d --name "$KOTLIN_AGENT_NAME" --network sipral-interop_lab \
        -e SIPRAL_AOR=sip:labuser-agent-kotlin@asterisk \
        -e SIPRAL_REGISTRAR=sip:asterisk \
        -e SIPRAL_AUTH_USER=labuser-agent-kotlin -e SIPRAL_AUTH_PASSWORD=labpass \
        -v "$beside:/lib-sipral:ro" \
        -v "$ROOT/bindings/c/include:/sipral-include:ro" \
        -v "$ROOT/bindings/kotlin/sipral/src/main/jni:/sipral-jni:ro" \
        -v "$KOTLIN_AGENT_JAR:/kotlin/sipral-kotlin.jar:ro" \
        -v "$KOTLIN_STDLIB_JAR:/kotlin/kotlin-stdlib.jar:ro" \
        -v "$KOTLIN_COROUTINES_JAR:/kotlin/kotlinx-coroutines.jar:ro" \
        eclipse-temurin:21-jdk sh -c '
            set -e
            export DEBIAN_FRONTEND=noninteractive
            apt-get -qq update >/dev/null 2>&1
            apt-get -qq install -y gcc >/dev/null 2>&1
            cc -std=c11 -Wall -shared -fPIC \
                -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" -I/sipral-include \
                -o /tmp/libsipral_jni.so \
                /sipral-jni/sipral_jni.c /sipral-jni/idiomatic_media.c \
                -L/lib-sipral -lsipral_ffi -Wl,-rpath,/lib-sipral
            address=$(getent hosts asterisk | cut -d" " -f1)
            SIPRAL_REGISTRAR_ADDRESS="$address:5060" \
                exec java -Djava.library.path=/tmp \
                -cp "/kotlin/sipral-kotlin.jar:/kotlin/kotlin-stdlib.jar:/kotlin/kotlinx-coroutines.jar" \
                org.sipral.examples.AgentKt' >/dev/null \
        || { printf '  could not start the Kotlin agent container\n'; return 1; }

    tries=0
    until ( cd interop && docker compose exec -T asterisk \
            asterisk -rx "pjsip show contacts" 2>/dev/null ) | grep -q labuser-agent-kotlin; do
        tries=$((tries + 1))
        if [ "$(docker inspect -f '{{.State.Running}}' "$KOTLIN_AGENT_NAME" 2>/dev/null)" != true ] \
            || [ "$tries" -ge 90 ]; then
            printf '  the agent never registered\n'
            docker logs "$KOTLIN_AGENT_NAME" 2>&1 | tail -30
            docker rm -f "$KOTLIN_AGENT_NAME" >/dev/null 2>&1
            return 1
        fi
        sleep 2
    done

    ( cd interop && docker compose exec -T asterisk asterisk -rx \
        "channel originate PJSIP/labuser-agent-kotlin extension s@agent-call" ) >/dev/null 2>&1

    tries=0
    until docker logs "$KOTLIN_AGENT_NAME" 2>&1 | grep -q '^ended '; do
        tries=$((tries + 1))
        [ "$tries" -ge 30 ] && break
        sleep 1
    done
    log=$(docker logs "$KOTLIN_AGENT_NAME" 2>&1)
    docker rm -f "$KOTLIN_AGENT_NAME" >/dev/null 2>&1
    printf '%s\n' "$log" | sed 's/^/    /'

    printf '%s\n' "$log" | grep -q '^answered ' \
        || { printf '  it never answered\n'; return 1; }
    # No digit value, only that three arrived: the generated Kotlin/JNI shim
    # forwards no event payload (bindings/kotlin/README.md), so an RFC 4733
    # digit -- what Asterisk's SendDTMF sends here by default -- carries no
    # character this binding can read yet. Agent.kt's own header says so.
    printf '%s\n' "$log" | grep -q '^dtmf-event 3' \
        || { printf '  it never heard all three DTMF events\n'; return 1; }
    printf '%s\n' "$log" \
        | grep '^ended ' | grep -Eq "packets_received=[1-9]" \
        || { printf '  it heard no audio\n'; return 1; }
    printf '%s\n' "$log" \
        | grep '^ended ' | grep -Eq "packets_sent=[1-9]" \
        || { printf '  it sent no audio back\n'; return 1; }
}

# The Swift binding's own example agent, `SWIFT_AGENT` above, registered at
# Asterisk as `labuser-agent-swift` (`interop/asterisk/pjsip.conf`) and
# called by it -- the same shape `python_agent` above is, and the same
# reason: what the loopback tests in `bindings/swift/Tests` cannot show is
# that what the agent advertises is somewhere a real server can reach, and
# that the tone the server plays comes back through its own echo. Run in a
# `swift:6.1` container for the runtime `SWIFT_AGENT` was linked against,
# with `libsipral_ffi.so` mounted at the same absolute path
# (`$ROOT`/`/work`) the build step above used, since the binary's own
# `-rpath` is that path.
SWIFT_AGENT_NAME=sipral-lab-agent-swift
swift_agent() {
    local log tries
    [ -n "$SWIFT_AGENT" ] || return 0
    docker rm -f "$SWIFT_AGENT_NAME" >/dev/null 2>&1
    docker run -d --name "$SWIFT_AGENT_NAME" --network sipral-interop_lab \
        -v "$ROOT":/work:ro \
        -e SIPRAL_AOR=sip:labuser-agent-swift@asterisk \
        -e SIPRAL_REGISTRAR=sip:asterisk \
        -e SIPRAL_AUTH_USER=labuser-agent-swift -e SIPRAL_AUTH_PASSWORD=labpass \
        swift:6.1 sh -c '
            address=$(getent hosts asterisk | cut -d" " -f1)
            SIPRAL_REGISTRAR_ADDRESS="$address:5060" \
                exec /work/bindings/.build/release/SipralLabAgent' >/dev/null \
        || { printf '  could not start the agent container\n'; return 1; }

    tries=0
    until ( cd interop && docker compose exec -T asterisk \
            asterisk -rx "pjsip show contacts" 2>/dev/null ) | grep -q labuser-agent-swift; do
        tries=$((tries + 1))
        if [ "$(docker inspect -f '{{.State.Running}}' "$SWIFT_AGENT_NAME" 2>/dev/null)" != true ] \
            || [ "$tries" -ge 60 ]; then
            printf '  the agent never registered\n'
            docker logs "$SWIFT_AGENT_NAME" 2>&1 | tail -20
            docker rm -f "$SWIFT_AGENT_NAME" >/dev/null 2>&1
            return 1
        fi
        sleep 2
    done

    ( cd interop && docker compose exec -T asterisk asterisk -rx \
        "channel originate PJSIP/labuser-agent-swift extension s@agent-call" ) >/dev/null 2>&1

    tries=0
    until docker logs "$SWIFT_AGENT_NAME" 2>&1 | grep -q '^ended '; do
        tries=$((tries + 1))
        [ "$tries" -ge 30 ] && break
        sleep 1
    done
    log=$(docker logs "$SWIFT_AGENT_NAME" 2>&1)
    docker rm -f "$SWIFT_AGENT_NAME" >/dev/null 2>&1
    printf '%s\n' "$log" | sed 's/^/    /'

    printf '%s\n' "$log" | grep -q '^answered ' \
        || { printf '  it never answered\n'; return 1; }
    printf '%s\n' "$log" | grep -q '^dtmf #' \
        || { printf '  it never heard the "#" it hangs up on\n'; return 1; }
    printf '%s\n' "$log" | grep -Eq '^ended .*packets_received=[1-9]' \
        || { printf '  it heard no audio\n'; return 1; }
    printf '%s\n' "$log" | grep -Eq '^ended .*packets_sent=[1-9]' \
        || { printf '  it sent no audio back\n'; return 1; }
}

# 8.5.4's own flow: `crates/sipral/examples/headless-socket-agent.rs` carries
# the call over SIP and RTP exactly as `labuser-agent` above does, and speaks
# `sipral-headless`'s wire protocol on a TCP port instead of holding the audio
# itself; `crates/sipral-headless/examples/agent.rs` is the reference agent
# on the other end of it, depending on nothing but that crate.
#
# Two containers rather than one: the application listens for the agent
# before it can be dialled, so it starts first and the log line it prints
# once a connection lands is the gate the agent's own container waits behind.
# Both are removed at the end either way, the same as `python_agent` above.
HEADLESS_APP_NAME=sipral-lab-headless-app
HEADLESS_CLIENT_NAME=sipral-lab-headless-agent
headless_socket_agent() {
    local app_log tries
    [ -n "$HEADLESS_APP" ] && [ -n "$HEADLESS_CLIENT" ] || return 0
    local app_beside client_beside
    app_beside=$(cd "$(dirname "$HEADLESS_APP")" && pwd)
    client_beside=$(cd "$(dirname "$HEADLESS_CLIENT")" && pwd)
    docker rm -f "$HEADLESS_APP_NAME" "$HEADLESS_CLIENT_NAME" >/dev/null 2>&1

    # Mounted beside the image's own directories, never over /bin: on Debian
    # 13 /bin is /usr/bin, and covering it takes the container's shell away.
    docker run -d --name "$HEADLESS_APP_NAME" --network sipral-interop_lab \
        -v "$app_beside:/sipral:ro" \
        debian:trixie-slim sh -c '
            own=$(hostname -i)
            address=$(getent hosts asterisk | cut -d" " -f1)
            exec /sipral/headless-socket-agent \
                --host "$own" --port 5060 --socket 0.0.0.0:7001 \
                --register labuser-agent-headless@asterisk \
                --registrar "$address:5060" --pass labpass' >/dev/null \
        || { printf '  could not start the application container\n'; return 1; }

    tries=0
    until docker logs "$HEADLESS_APP_NAME" 2>&1 | grep -q '^waiting for the agent'; do
        tries=$((tries + 1))
        if [ "$(docker inspect -f '{{.State.Running}}' "$HEADLESS_APP_NAME" 2>/dev/null)" != true ] \
            || [ "$tries" -ge 30 ]; then
            printf '  the application never came up\n'
            docker logs "$HEADLESS_APP_NAME" 2>&1 | tail -20
            docker rm -f "$HEADLESS_APP_NAME" >/dev/null 2>&1
            return 1
        fi
        sleep 1
    done

    docker run -d --name "$HEADLESS_CLIENT_NAME" --network sipral-interop_lab \
        -v "$client_beside:/sipral:ro" \
        debian:trixie-slim /sipral/agent --addr "$HEADLESS_APP_NAME:7001" >/dev/null \
        || {
            printf '  could not start the agent container\n'
            docker rm -f "$HEADLESS_APP_NAME" >/dev/null 2>&1
            return 1
        }

    tries=0
    until ( cd interop && docker compose exec -T asterisk \
            asterisk -rx "pjsip show contacts" 2>/dev/null ) | grep -q labuser-agent-headless; do
        tries=$((tries + 1))
        if [ "$(docker inspect -f '{{.State.Running}}' "$HEADLESS_APP_NAME" 2>/dev/null)" != true ] \
            || [ "$tries" -ge 60 ]; then
            printf '  the application never registered\n'
            docker logs "$HEADLESS_APP_NAME" 2>&1 | tail -20
            docker rm -f "$HEADLESS_APP_NAME" "$HEADLESS_CLIENT_NAME" >/dev/null 2>&1
            return 1
        fi
        sleep 2
    done

    ( cd interop && docker compose exec -T asterisk asterisk -rx \
        "channel originate PJSIP/labuser-agent-headless extension s@agent-call" ) >/dev/null 2>&1

    tries=0
    until docker logs "$HEADLESS_APP_NAME" 2>&1 | grep -q '^ended '; do
        tries=$((tries + 1))
        [ "$tries" -ge 30 ] && break
        sleep 1
    done
    app_log=$(docker logs "$HEADLESS_APP_NAME" 2>&1)
    printf '%s\n' "$(docker logs "$HEADLESS_CLIENT_NAME" 2>&1)" | sed 's/^/    agent  /'
    printf '%s\n' "$app_log" | sed 's/^/    app    /'
    docker rm -f "$HEADLESS_APP_NAME" "$HEADLESS_CLIENT_NAME" >/dev/null 2>&1

    printf '%s\n' "$app_log" | grep -q '^answered ' \
        || { printf '  it never answered\n'; return 1; }
    printf '%s\n' "$app_log" | grep -q '^dtmf #' \
        || { printf '  it never heard the "#" the dialplan sends\n'; return 1; }
    printf '%s\n' "$app_log" | grep -Eq '^ended .*packets_received=[1-9]' \
        || { printf '  it heard no audio\n'; return 1; }
    printf '%s\n' "$app_log" | grep -Eq '^ended .*packets_sent=[1-9]' \
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

# 8.5.5's own step: the C harness behind a NAT, registering and calling
# Asterisk with the stack asking coturn where its sockets appear from
# (SIPRAL_NAT_STUN). interop/nat is the NAT -- a container with a leg on the
# lab network and one on `inside`, masquerading between them -- and the
# harness runs on `inside` alone, with its default route through it, so the
# address coturn reports for each socket is the NAT's and not the one the
# socket is bound to. The harness checks that difference first and fails a
# run where there is none, since a Contact that matched what STUN said would
# then prove nothing. See interop/harness-c's own flow_nat for the rest.
#
# Both containers carry the `nat` profile, so the lab every other step sees
# never has them; they come up here and are removed straight after, the way
# opensips and baresip are. The harness container is the NAT's own image,
# because it needs `ip` to set its route and nothing else a slim Debian
# lacks, and it cannot install anything: `inside` has no way out but the NAT.
# The lab's names do not resolve there either, so Asterisk is handed to it by
# address.
#
# The networks are named from the Compose project rather than written out, so
# that the step also runs under a COMPOSE_PROJECT_NAME of its own -- a second
# copy of the lab beside one somebody else already has up.
nat_flow() {
    local beside natbox gateway coturn stun asterisk status
    local project="${COMPOSE_PROJECT_NAME:-sipral-interop}"
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    ( cd interop && docker compose --profile nat up -d --build coturn natbox ) >/dev/null 2>&1 \
        || { printf '  could not start coturn and the NAT\n'; return 1; }
    wait_for natbox "nat: masquerading out of" required nat || return 1
    # coturn 4.18 logs the addresses it will listen on and then nothing about
    # having opened them; the harness's own retransmissions cover the gap
    wait_for coturn "Listener address to use" optional nat || true

    natbox=$(cd interop && docker compose --profile nat ps -q natbox)
    coturn=$(cd interop && docker compose --profile nat ps -q coturn)
    asterisk=$(cd interop && docker compose ps -q asterisk)
    gateway=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"${project}_inside\"}}{{.IPAddress}}{{end}}" \
        "$natbox")
    stun=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"${project}_lab\"}}{{.IPAddress}}{{end}}" \
        "$coturn")
    asterisk=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"${project}_lab\"}}{{.IPAddress}}{{end}}" \
        "$asterisk")
    if [ -z "$gateway" ] || [ -z "$stun" ] || [ -z "$asterisk" ]; then
        printf '  could not read the addresses: NAT %s, coturn %s, Asterisk %s\n' \
            "${gateway:-?}" "${stun:-?}" "${asterisk:-?}"
        return 1
    fi
    printf '  behind %s, STUN at %s:3478, Asterisk at %s\n' "$gateway" "$stun" "$asterisk"

    docker run --rm --network "${project}_inside" \
        --cap-add NET_ADMIN \
        --add-host "asterisk:$asterisk" \
        -e SIPRAL_REQUIRE_AUDIO=1 -e SIPRAL_FLOWS=nat \
        -e "SIPRAL_STUN_SERVER=$stun:3478" \
        -e LD_LIBRARY_PATH=/lib-sipral \
        -v "$HARNESS_C:/harness-c:ro" \
        -v "$beside:/lib-sipral:ro" \
        sipral-lab-nat sh -c "
            ip route replace default via $gateway || exit 1
            exec /harness-c asterisk 5060 9000"
    status=$?
    ( cd interop && docker compose --profile nat rm -sf coturn natbox ) >/dev/null 2>&1
    return "$status"
}

# The same call again, over a link deliberately made bad in both directions.
#
# netem only ever shapes egress. That used to be enough on the strength of a
# comment here that no longer holds: extension 9000 does not echo. It plays a
# fixed tone -- interop/asterisk/extensions.conf's own Playtones, FreeSWITCH's
# tone_stream in interop/freeswitch/lab.xml -- regardless of what this end
# sends or whether it arrives at all (see interop/harness/src/quality.rs for
# why an echo was tried and abandoned). So impairing only what this container
# sends out never touches the audio it receives, which is the one side the
# audio quality gate below exists to judge, and every "audio survived it"
# this step ever printed proved only that signalling survives a bad egress --
# never that a single frame of the returned tone had been delayed, dropped or
# concealed. `ifb` plus a `mirred` redirect is the standard way around
# netem's own egress-only limit: it hands this container's own ingress to a
# virtual device netem can shape as if it were egress, so `$NETEM` is applied
# once each way and the link is bad symmetrically, the way a real one is.
#
# The shapes live in interop/impairment/ rather than here, because a threshold
# is only meaningful against a profile somebody else can run.
#
# `tc` accepts what the kernel it is talking to does not necessarily apply, and
# says nothing when it does not: on a 3.10 kernel the delay is dropped in
# silence while the loss goes through. A run whose impairment never happened
# reads exactly like a clean one, which is worse than no run at all -- so both
# qdiscs are read back against what the profile said it needed.
#
# SIPRAL_AUDIO_GATE=1 turns on the harness's own audio quality gate
# (interop/harness/src/quality.rs): segmental SNR and splice continuity
# against the lab's own 350+440 Hz tone, on every frame the primary call
# played back. It runs only here -- the ordinary, unimpaired steps above
# never set it -- because it is the netem profiles' own claim that is worth
# a measured number rather than a pass/fail on packet counts alone.
bad_network() {
    local profile="$1"
    # shellcheck disable=SC1090
    WHY=""; NETEM=""; REQUIRE=""; DWELL_MS=""; DURING=""
    . "$ROOT/interop/impairment/$profile.sh"
    printf '  %-10s %s\n' "$profile" "$WHY"
    docker run --rm --network sipral-interop_lab \
        --cap-add NET_ADMIN \
        -e SIPRAL_REQUIRE_AUDIO=1 -e SIPRAL_FLOWS=register,call \
        -e SIPRAL_AUDIO_GATE=1 \
        -e "SIPRAL_DWELL_MS=${DWELL_MS:-2000}" \
        -e "SIPRAL_PATIENCE_MS=$(( ${DWELL_MS:-2000} + 20000 ))" \
        -e "NETEM=$NETEM" -e "REQUIRE=$REQUIRE" -e "DURING=$DURING" \
        -v "$HARNESS:/harness:ro" \
        debian:trixie-slim sh -c '
            export DEBIAN_FRONTEND=noninteractive
            apt-get -qq update >/dev/null 2>&1
            apt-get -qq install -y iproute2 >/dev/null 2>&1
            link=$(ip route | awk "/^default/{print \$5}")
            ifb=ifb0
            # shellcheck disable=SC2086
            tc qdisc add dev "$link" root netem $NETEM
            ip link add "$ifb" type ifb
            ip link set "$ifb" up
            tc qdisc add dev "$link" handle ffff: ingress
            tc filter add dev "$link" parent ffff: protocol ip u32 \
                match u32 0 0 action mirred egress redirect dev "$ifb"
            # shellcheck disable=SC2086
            tc qdisc add dev "$ifb" root netem $NETEM
            applied_out=$(tc qdisc show dev "$link")
            applied_in=$(tc qdisc show dev "$ifb")
            echo "  out: $applied_out"
            echo "  in:  $applied_in"
            impaired=1
            if [ -n "$REQUIRE" ]; then
                case "$applied_out" in *"$REQUIRE"*) ;; *) impaired=0 ;; esac
                case "$applied_in" in *"$REQUIRE"*) ;; *) impaired=0 ;; esac
            fi
            if [ "$impaired" -eq 0 ]; then
                echo "IMPAIRMENT-NOT-APPLIED"; exit 3
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
    step "the socket-framed agent, called by Asterisk"
    headless_socket_agent && pass "headless-socket-agent answered, echoed and carried DTMF" \
        || fail "headless-socket-agent"
    step "the Swift binding's example agent, called by Asterisk"
    swift_agent && pass "SipralLabAgent answered, echoed and carried DTMF" \
        || fail "SipralLabAgent"
    step "the Kotlin idiomatic-layer agent, called by Asterisk"
    if [ -n "${KOTLIN_AGENT_JAR:-}" ]; then
        kotlin_agent && pass "Agent.kt answered, echoed and carried DTMF" \
            || fail "Agent.kt"
    else
        printf '  note  KOTLIN_AGENT_JAR not set; see bindings/kotlin/README.md\n'
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
        #
        # Read off baresip's own log, which prints each account's REGISTER
        # answer in this form. A line of Kamailio's own was tried first and
        # never appeared: the proxy logs nothing below a warning, and the lab
        # is better off not raising that for every server's step to suit this
        # one. The account names are followed by "@", so the plain one's
        # phrase is not satisfied by baresip-srtp or baresip-dtls registering.
        if wait_for baresip "baresip@kamailio: (prio 0) {0/UDP/v4} 200 OK" required baresip; then
            wait_for baresip "baresip-srtp@kamailio: (prio 0) {0/UDP/v4} 200 OK" \
                optional baresip || true
            wait_for baresip "baresip-dtls@kamailio: (prio 0) {0/UDP/v4} 200 OK" \
                optional baresip || true
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

if [ "$WANT" = all ] || [ "$WANT" = nat ]; then
    step "behind a NAT -- STUN against coturn, then register and call Asterisk, in C"
    if [ -n "$HARNESS_C" ]; then
        nat_flow && pass "registered and heard from behind the NAT, at the address STUN reported" \
            || fail "behind a NAT"
    elif [ "$WANT" = nat ]; then
        # the flow is the C harness's, since the setting it proves is the C
        # ABI's: asked for by name, a machine with no C harness fails it
        fail "behind a NAT: there is no C harness to run it with"
    else
        printf '  note  no C harness, so the flow behind a NAT is skipped with the other C flows\n'
    fi
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

# The one step where the audio is a device's rather than the harness's own:
# sipral-io-pipewire's tests against a real graph, then the facade carrying a
# call to Asterisk's echo extension with PipeWire nodes for a microphone and
# an earpiece (interop/harness/src/pipewire.rs says what is played where and
# why the tone coming back proves the whole path). interop/pipewire/run.sh
# is the recipe, and interop/pipewire/Dockerfile the machine it runs on: a
# daemon, a session manager and two virtual cables, since a container has no
# sound card. The checkout is mounted read-only and compiled inside, into a
# volume of its own so a second run starts from the first one's build.
if [ "$WANT" = pipewire ]; then
    step "a call on a Linux desktop's devices -- PipeWire, straight at Asterisk"
    docker build -q -t sipral-pipewire interop/pipewire >/dev/null 2>&1 \
        && pass "the PipeWire image" || { fail "docker build interop/pipewire"; exit 1; }
    docker run --rm --network sipral-interop_lab \
        -v "$ROOT:/src:ro" -v sipral-pipewire-target:/target \
        -e CARGO_TARGET_DIR=/target -w /src \
        sipral-pipewire bash interop/pipewire/run.sh call \
        && pass "sipral-io-pipewire, and a call carried on it" \
        || fail "interop/pipewire/run.sh call"
fi

step "the capture"
ls -l interop/pcap || true

printf '\n'
[ "$FAIL" -eq 0 ] && { printf 'the lab agrees\n'; exit 0; }
printf 'the lab does not agree\n'; exit 1
