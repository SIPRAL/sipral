#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
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
#   scripts/lab.sh kamailio     one server only; through the proxy, the run
#                               also forks a call to two phones registered
#                               as one user, the second answering first
#   scripts/lab.sh opensips     the second proxy only
#   scripts/lab.sh asterisk
#   scripts/lab.sh baresip      only the phone-to-phone flows, against baresip
#   scripts/lab.sh nat          only the calls from and to behind a NAT, with
#                               STUN against coturn, through the C ABI
#   scripts/lab.sh nat-idle     only the call placed 330 seconds after the
#                               REGISTER, behind the NAT, with the registrar
#                               keep-alive on (part of a run that names
#                               nothing) and then off, which the NAT's filter
#                               has to drop for the lab to prove anything --
#                               about twelve minutes
#   scripts/lab.sh referral     only a REFER from outside any call, sent at a
#                               stack driven through the C ABI: refused while
#                               it does not take them, taken when it does,
#                               the call placed to Asterisk's echo (part of
#                               the Asterisk run too)
#   scripts/lab.sh move         only the call whose address moves under it:
#                               the harness's container taken off the lab
#                               network and connected again elsewhere
#                               mid-call, the echo heard after (part of the
#                               Asterisk run too)
#   scripts/lab.sh icelite      only the call that requires ICE placed at a
#                               C ABI stack answering as ICE-lite (part of
#                               the ice run too)
#   scripts/lab.sh ice          only the ICE steps: a call that requires ICE,
#                               from the harness and from Asterisk, answered
#                               by the headless agent as an ICE-lite endpoint,
#                               and the harness's through the C ABI;
#                               then two stacks behind two NATs completing
#                               full ICE on what coturn told them, then the
#                               same two with the path between them blocked,
#                               through a relay on coturn as a TURN server
#   scripts/lab.sh turn         only that last, relayed, step: the call placed
#                               from the Rust harness, then forked by
#                               Kamailio to two phones behind the second NAT,
#                               every end relayed, both branches carrying
#                               media until one answers; then through the C
#                               ABI and through each idiomatic binding --
#                               Python, Kotlin, .NET, Swift -- and again from
#                               behind a NAT that drops every datagram to
#                               coturn, the relay reached over TCP from the
#                               C ABI, over TLS from Python, over TCP and TLS
#                               from Kotlin and .NET, and over TCP from Swift
#   scripts/lab.sh tls          only SIP over a connection through the four
#                               idiomatic layers: the Python, Kotlin and
#                               .NET agents over TLS to Asterisk, each first
#                               refusing a certificate no trusted authority
#                               signed, one for another name and one that
#                               expired, and saying which; then registered
#                               and called; the Swift agent over TCP, since
#                               the lab runs it on Linux, where Swift has no
#                               TLS (interop/tls/pjsip_local.conf); then the
#                               Python layer pinned to the certificate 5061
#                               presents, by its SHA-256 fingerprint alone,
#                               calling the echo, and pinned to another
#                               one's, refused as untrusted; then two lines
#                               in one Python stack, one account over UDP
#                               at Kamailio and one over a pinned TLS
#                               connection of its own at Asterisk, both
#                               registered at once and a call up on each
#                               (interop/lines/caller.py)
#   scripts/lab.sh robust      only the field failures that need a network
#                               to show (docs/11-testing.md's table): a
#                               link that drops IP fragments, with INVITEs
#                               carrying ICE at 1300, 1301 and 1600 bytes;
#                               a TCP connection accepted and never answered,
#                               and one whose path goes dark after the
#                               handshake, each call ended at Timer B; then
#                               the NAT pair's call with its first STUN
#                               server dead, both ends moving to coturn.
#                               About three minutes
#   scripts/lab.sh datagram     only a call whose INVITE, once it answers
#                               Asterisk's challenge, is past RFC 3261
#                               §18.1.1's 1300 bytes, placed from the Python
#                               layer with four SDES suites offered
#                               (interop/datagram/caller.py): at a port where
#                               Asterisk listens on TCP too, the answer goes
#                               over a connection the layer opens by itself
#                               and the call is held, resumed and hung up; at
#                               one with UDP alone, the INVITE goes again with
#                               one suite and fits; and made too large even
#                               for that, the call ends at once with a 513
#                               that names the limit -- unless the stack was
#                               told a request up to 1600 bytes may go over
#                               UDP anyway, when it goes as one datagram and
#                               the call connects (part of a run that names
#                               nothing too)
#   scripts/lab.sh besteffort   only SRTP best effort through the Python
#                               layer: SDES offered on RTP/AVP to Asterisk's
#                               tone from an account with SRTP off, which
#                               comes up plain, and from one with SDES on,
#                               which comes up keyed (part of `security` and
#                               of a run that names nothing too)
#   scripts/lab.sh locate       only RFC 3263 through the Python layer: a
#                               registrar named by its host name, found by
#                               the A record the lab's DNS answers, then a
#                               server named by a domain, found by the SRV
#                               record a resolver of the application's own
#                               gives (part of a run that names nothing too)
#   scripts/lab.sh security     only the SRTP policy per account, through the
#                               C ABI -- SDES required, DTLS-SRTP required
#                               and off, set on the account and read back
#                               from the encryption report -- straight at
#                               Asterisk and through the proxy to
#                               FreeSWITCH; then STIR/SHAKEN between two C
#                               ABI stacks, one signing and one verifying,
#                               with a certificate authority made for the run
#                               (interop/stir/run.sh): a signed call verified
#                               and carried, an unsigned one refused 428, one
#                               signed by an authority nobody trusts refused
#                               437; then `besteffort` above (part of a run
#                               that names nothing too)
#   scripts/lab.sh nway         only the local conference: three of the
#                               harness's own stacks registered at Kamailio,
#                               each on a codec of its own, called by a
#                               fourth that mixes the three; each hears the
#                               other two and not itself, and the two left
#                               go on hearing each other once one hangs up
#                               (part of a run that names nothing too)
#   scripts/lab.sh netem        only the runs over a bad link, every profile
#   PROFILE=blackout scripts/lab.sh netem      one of them
#   scripts/lab.sh pipewire     sipral-io-pipewire against a real PipeWire,
#                               then a call to Asterisk whose microphone and
#                               earpiece are PipeWire nodes -- built and run
#                               in interop/pipewire's own image, and not part
#                               of a run that names nothing, because it
#                               compiles the facade inside a container
#   scripts/lab.sh drift        an hour on six calls to Asterisk's echo, with
#                               each earpiece's clock set off by a known skew
#                               and taking one frame or two at a callback,
#                               reporting what the jitter buffer did every
#                               five minutes -- not part of a run that names
#                               nothing, because it takes an hour.
#                               SIPRAL_DRIFT_MS, SIPRAL_DRIFT_REPORT_MS and
#                               SIPRAL_DRIFT_PPM change its length, its
#                               interval and its skew (milliseconds,
#                               milliseconds, parts per million); a few
#                               minutes wants a larger skew, since 250 ppm
#                               is two frames of drift in three minutes:
#                               SIPRAL_DRIFT_MS=180000
#                               SIPRAL_DRIFT_REPORT_MS=30000
#                               SIPRAL_DRIFT_PPM=2000 scripts/lab.sh drift
#                               Past 5000 ppm, a skew no device runs at, a
#                               call is judged on staying bounded and on the
#                               stack reporting every frame it ran dry, not
#                               on never running dry
#   scripts/lab.sh drift-netem  the same six calls, over a link made bad
#                               the way `netem` makes one -- PROFILE names
#                               which of interop/impairment/*.sh, "lossy"
#                               unless told otherwise -- with the audio
#                               quality gate engaged on all six, so a
#                               report line also carries its segmental SNR
#                               and its splice clicks. The same
#                               SIPRAL_DRIFT_* variables as `drift` above
#                               shorten it; docs/19-numbers.md's own run used
#                               three minutes, not an hour, since a bad link
#                               moves the buffer's target within seconds, not
#                               within an hour the way a clean one's drift
#                               does
#   scripts/lab.sh latency      the delay from this end's own microphone to
#                               its own earpiece, on a call to Asterisk's
#                               echo: a marker frame's round trip, halved,
#                               every SIPRAL_LATENCY_MARK_MS for
#                               SIPRAL_LATENCY_MS (two seconds and two
#                               minutes unless told otherwise) --
#                               interop/harness/src/latency.rs's own module
#                               doc says what the three stages it reports are
#   scripts/lab.sh inband       what a call carries in its audio, straight at
#                               Asterisk with no telephone event: digits
#                               dialled in the audio and heard back in it,
#                               ringback then a recorded greeting and its
#                               beep (a machine), and a call recorded to
#                               stereo WAV and Ogg Opus, read back by the
#                               harness and then by soxi and opusinfo --
#                               interop/harness/src/inband.rs's module doc
#   scripts/lab.sh volume       a hundred calls (SIPRAL_VOLUME_CALLS) at once
#                               rather than one -- SIPRAL_VOLUME_STAGGER_MS
#                               apart, held on the tone for
#                               SIPRAL_VOLUME_HOLD_MS once every one that is
#                               coming up has, then hung up together. Run
#                               twice, straight at Asterisk and through
#                               Kamailio to FreeSWITCH (there is no route
#                               from Kamailio to Asterisk in this lab) --
#                               SIPRAL_VOLUME_SERVER="asterisk" or
#                               "kamailio" runs one alone. Wrapped in
#                               /usr/bin/time -v for this end's own CPU and
#                               peak memory; the real server's own peak
#                               channel count is read over its console the
#                               way the other steps already read it, and
#                               printed beside it
#   scripts/lab.sh compare      the same scenarios for Sipral's headless
#                               agent and for pjsua, PJSIP's own client from
#                               Alpine's package, against Asterisk:
#                               registering, a call each way, memory and CPU
#                               idle and at 1, 4, 10 and 100 calls, a call over
#                               each netem profile rated from both ends, a
#                               move to another address mid-call, and the
#                               INVITE with ICE -- interop/compare/compare.sh
#                               says how, docs/23-compared-with-pjsip.md
#                               reports a run. Not part of a run that names
#                               nothing: about thirteen minutes, and a
#                               comparison rather than a check.
#                               SIPRAL_HEADLESS_AGENT names the agent binary
#                               built elsewhere (a Linux build of
#                               `cargo build --release -p sipral --example
#                               headless-agent`); SIPRAL_COMPARE_CLIENTS,
#                               _CALLS, _PROFILES, _HOLD_S and _WINDOW_S
#                               narrow it
#   scripts/lab.sh bridge       only the bridge to a voice agent
#                               (crates/sipral/examples/agent-bridge.rs),
#                               registered at Asterisk as labuser-bridge: one
#                               call with the Python layer's agent.py as the
#                               voice agent -- audio both ways, the dialplan's
#                               "12#" forwarded, and the agent's hangup ending
#                               Asterisk's call with an outcome (part of the
#                               Asterisk run too); then SIPRAL_BRIDGE_CALLS
#                               (thirty) calls at once to the headless agent's
#                               echo, every one bridged both ways and ended,
#                               with the bridge's own CPU time printed.
#                               SIPRAL_AGENT_BRIDGE and SIPRAL_HEADLESS_AGENT
#                               name the two binaries when built elsewhere
#   scripts/lab.sh wasapi up    bring the lab up reachable from the LAN, for
#                               a call carried on a Windows machine's real
#                               WASAPI devices (interop/harness/src/wasapi.rs,
#                               interop/wasapi/run.ps1); nothing here runs
#                               that call itself -- there is no WASAPI in a
#                               Linux container -- only what the Windows
#                               machine needs to reach in
#   scripts/lab.sh wasapi down  tear that down again
#                               Every word above takes /var/lock/sipral-lab.lock
#                               (or ./.sipral-lab.lock where that path does not
#                               exist) itself, for its whole run, so two runs
#                               against the same Docker Compose project never
#                               race each other -- five agents at once tore
#                               down each other's containers on 27 Sept. An
#                               outer `flock` wrapped around this script is not
#                               needed any more for any word, including
#                               `wasapi up|down`, and should not be used: the
#                               lock is not re-entrant, so a caller already
#                               holding it (an outer flock, or a lab.sh call
#                               nested inside another one) would deadlock
#                               against its own hold. A run that already holds
#                               it -- this script re-invoking itself, or a
#                               caller that wants several words to share one
#                               lab state, `wasapi up` then some calls then
#                               `wasapi down` -- sets SIPRAL_LAB_LOCK_HELD=1
#                               first, and every invocation started with that
#                               already set skips taking the lock again instead
#                               of deadlocking. A run that finds the lock held
#                               prints a message and then waits for it.
#                               COMPOSE_PROJECT_NAME (default sipral-interop)
#                               names the Compose project and the lab's own
#                               Docker network throughout, so a run under a
#                               project name of its own is fully isolated from
#                               any other run sharing the same lock file.
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

# found [GREP OPTIONS] PATTERN: whether standard input has a line PATTERN
# matches, read to its end. `grep -q` stops at the first match, and under
# pipefail whatever is still writing into the pipe then dies of SIGPIPE and
# fails the pipeline: a match read as none, and more often the busier the
# machine. A gate run in parallel lost classes.jar's first entries that way.
found() { grep "$@" >/dev/null; }

cd "$(dirname "$0")/.."
ROOT="$PWD"

# This script's own re-entrant lock, held for the whole run, every word
# (including `wasapi up|down` and `--matrix`, which just re-invokes this
# script under the flag stripped). /var/lock does not exist on every machine
# that runs this (macOS has none), so this falls back to a lock file inside
# the checkout when the system one is not there. Held on fd 9 for the life of
# this process, so every function and subshell below inherits it; a nested
# invocation of this same script (a caller stacking several words on one lab
# state, or this block re-execing itself) is a new process with a new fd, so
# it would just block on the same file forever -- that is what
# SIPRAL_LAB_LOCK_HELD=1 is for: set once the lock is taken, inherited by any
# child this process starts, and checked here so a nested run skips locking
# instead of deadlocking against its own parent.
if [ -z "${SIPRAL_LAB_LOCK_HELD:-}" ]; then
    LOCK="/var/lock/sipral-lab.lock"
    [ -e "$LOCK" ] || LOCK="$ROOT/.sipral-lab.lock"
    exec 9>"$LOCK" || { printf 'could not open %s for locking\n' "$LOCK"; exit 2; }
    if ! flock -n 9; then
        printf 'waiting for the lab lock (%s) -- another run holds it...\n' "$LOCK"
        flock 9 || { printf 'could not take the lab lock at %s\n' "$LOCK"; exit 2; }
    fi
    export SIPRAL_LAB_LOCK_HELD=1
fi

# The Compose project name, and the lab's own Docker network that follows it
# everywhere a flow reaches into the lab from outside Compose (docker run
# --network, docker inspect on a container Compose did not start). A run
# under a COMPOSE_PROJECT_NAME of its own is then fully isolated on the
# network too, not only under the lock.
LAB_NETWORK="${COMPOSE_PROJECT_NAME:-sipral-interop}_lab"

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

# Every agent and harness a step runs in a container of its own goes through
# lab_run, with a wall-clock of its own: one that hangs would otherwise hold
# the lab lock above until something outside it gave up, and every run
# queued behind it with it. The limit is derived from what the run does --
# the calls it places, each LAB_CALL_S at most, plus what starting it takes
# -- so a run that takes longer is stuck, not slow. Past it, only the
# container this run started is removed, by the name it was given, and the
# step fails by the label it passed, with LAB_RUN_TIMED_OUT as its status so
# that a step expecting a call to fail does not read a hang as that failure.
#
# One call, whoever places it: the ICE flows' patience for a path
# (interop/harness/src/ice_lite.rs's PATIENCE, interop/harness-c's
# ICE_PATIENCE_MS, 30 s), the 8 s a mapping is waited for before it
# (ice_nat.rs's MAPPING_PATIENCE), the 3 s dwell and the farewell after it.
# The harness's ordinary flows wait 20 s for each answer
# (SIPRAL_PATIENCE_MS) and dwell 2 s, and the idiomatic agents are told the
# same (LAB_PATIENCE_MS, LAB_DWELL_MS), all of which fit inside it.
LAB_CALL_S=45
LAB_PATIENCE_MS=20000
LAB_DWELL_MS=2000
# What starting a run takes before its first call: a binary run as it is;
# a container that installs a package first; the Kotlin agent, whose JNI
# shim is compiled and a JVM started; the .NET one, whose `dotnet run`
# builds the binding and the sample.
LAB_START_S=15
LAB_START_APT_S=90
LAB_START_KOTLIN_S=60
LAB_START_DOTNET_S=240
# and the PipeWire step, which compiles the facade inside its container
# before its call
LAB_START_BUILD_S=1800
# The most calls one run of the harness's ordinary flows places: nineteen
# flows against Asterisk, the transfers, the local conference and the call
# muted on its own placing more than one call each.
LAB_SUITE_CALLS=24
LAB_RUN_TIMED_OUT=124
LAB_RUN_SEQ=0
lab_run() {
    local label="$1" limit="$2" name status waited logs
    shift 2
    LAB_RUN_SEQ=$((LAB_RUN_SEQ + 1))
    name="${COMPOSE_PROJECT_NAME:-sipral-interop}-run-$$-$LAB_RUN_SEQ"
    docker run -d --name "$name" "$@" >/dev/null \
        || { printf '  FAIL  %s: its container did not start\n' "$label"; return 1; }
    docker logs -f "$name" 2>&1 &
    logs=$!
    status=$(timeout "$limit" docker wait "$name" 2>/dev/null)
    waited=$?
    if [ "$waited" -eq 124 ]; then
        printf '  FAIL  %s: still running after %s s, its container stopped\n' "$label" "$limit"
        docker rm -f "$name" >/dev/null 2>&1
        wait "$logs" 2>/dev/null
        return "$LAB_RUN_TIMED_OUT"
    fi
    wait "$logs" 2>/dev/null
    docker rm -f "$name" >/dev/null 2>&1
    [ "$waited" -eq 0 ] || return 1
    return "${status:-1}"
}

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
    # The lock block above already holds the lock for this whole run, so the
    # compose calls below run under it directly, no per-call flock of their
    # own needed.
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
        # bind moves the transport onto the port the override publishes, one
        # to one: interop/wasapi/compose.override.yaml says why a request
        # Asterisk starts itself has to leave from the port a phone sent to
        printf '; generated by scripts/lab.sh wasapi up -- not committed, see .gitignore\n[transport-udp](+)\nbind=0.0.0.0:5062\nexternal_media_address=%s\nexternal_signaling_address=%s\n' \
            "$LAN_ADDR" "$LAN_ADDR" >interop/wasapi/pjsip_local.generated.conf
        ( cd interop && docker compose -f compose.yaml -f wasapi/compose.override.yaml up -d ) \
            >/dev/null 2>&1 \
            || { fail "docker compose up (wasapi override)"; exit 1; }
        # named from the Compose project, as the `nat` step's networks are,
        # so that a copy of the lab under a COMPOSE_PROJECT_NAME of its own
        # reads its own bridge
        BRIDGE="$LAB_NETWORK"
        BRIDGE_SUBNET="$(docker network inspect "$BRIDGE" \
            --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null)"
        [ -n "$BRIDGE_SUBNET" ] || { fail "could not read $BRIDGE's own subnet"; exit 1; }
        printf 'local_net=%s\n' "$BRIDGE_SUBNET" >>interop/wasapi/pjsip_local.generated.conf
        ( cd interop && docker compose -f compose.yaml -f wasapi/compose.override.yaml restart asterisk ) \
            >/dev/null 2>&1 \
            || { fail "docker compose restart asterisk (wasapi override)"; exit 1; }
        # the socket itself, asked rather than assumed from the file: the
        # port published one to one is only half of it, and a transport
        # still on 5060 behind it is the phone that never rings
        tries=0
        until ( cd interop && docker compose exec -T asterisk \
                asterisk -rx 'pjsip show transports' 2>/dev/null ) | found '0\.0\.0\.0:5062'; do
            tries=$((tries + 1))
            [ "$tries" -ge 30 ] && { fail "Asterisk's own SIP socket is not on 5062"; exit 1; }
            sleep 1
        done
        pass "the lab, reachable at $LAN_ADDR:5062 (bridge $BRIDGE_SUBNET)"
        printf '  note  point interop/wasapi/run.ps1 (or SIPRAL_SERVER_HOST) at %s:5062\n' "$LAN_ADDR"
        ;;
    down)
        ( cd interop && docker compose -f compose.yaml -f wasapi/compose.override.yaml down ) \
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
elif [ "$WANT" = compare ]; then
    HARNESS=""
    printf '  note  not used by the comparison, which runs the headless agent\n'
elif [ "$WANT" = bridge ]; then
    HARNESS=""
    printf '  note  not used by the bridge step, which runs its own example\n'
elif [ -n "${SIPRAL_HARNESS:-}" ]; then
    [ -x "$SIPRAL_HARNESS" ] || { fail "SIPRAL_HARNESS is not an executable file"; exit 1; }
    HARNESS="$SIPRAL_HARNESS"
    pass "taken as given: $HARNESS"
else
    # Opus only for the step that records to Ogg Opus: every other step's
    # binary builds without libopus (interop/harness/Cargo.toml says why)
    HARNESS_FEATURES=""
    [ "$WANT" = inband ] && HARNESS_FEATURES=opus
    cargo build --release -p sipral-interop ${HARNESS_FEATURES:+--features "$HARNESS_FEATURES"} >/dev/null 2>&1 \
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
if [ "$WANT" = pipewire ] || [ "$WANT" = compare ]; then
    HARNESS_C=""
    printf '  note  not used by the %s step\n' "$WANT"
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
if [ "$WANT" = compare ] || [ "$WANT" = security ] || [ "$WANT" = bridge ]; then
    HEADLESS_APP=""
    HEADLESS_CLIENT=""
    printf '  note  not used by the %s step\n' "$WANT"
elif [ -n "${SIPRAL_HEADLESS_APP:-}" ] && [ -n "${SIPRAL_HEADLESS_CLIENT:-}" ]; then
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
elif [ "$WANT" = security ] || [ "$WANT" = bridge ]; then
    SWIFT_AGENT=""
    printf '  note  not used by the %s step\n' "$WANT"
elif ! command -v docker >/dev/null 2>&1; then
    SWIFT_AGENT=""
else
    # Package.swift links against `<repo>/target/release`, which is where a
    # checkout's own `cargo build` leaves the library; the lab's is wherever
    # the C harness was built, so that directory is mounted there instead.
    SWIFT_LIB_DIR=$(cd "$(dirname "$HARNESS_C")" && pwd)
    if docker run --rm -v "$ROOT":/work -v "$SWIFT_LIB_DIR":/work/target/release:ro \
        -w /work/bindings swift:6.1 \
        swift build -c release --product SipralLabAgent >/dev/null 2>&1; then
        SWIFT_AGENT="$ROOT/bindings/.build/release/SipralLabAgent"
        pass "built"
    else
        SWIFT_AGENT=""
        printf '  note  could not build the Swift lab agent; that step is skipped\n'
    fi
fi

# The comparison's own client: the headless agent (crates/sipral/examples/
# headless-agent.rs), a binary with no library beside it to find, since the
# stack is linked into it. Fatal rather than skipped when it cannot be had:
# `compare` is asked for by name, and a comparison with one side missing
# would read as a result.
if [ "$WANT" = compare ]; then
    step "the headless agent"
    if [ -n "${SIPRAL_HEADLESS_AGENT:-}" ]; then
        [ -x "$SIPRAL_HEADLESS_AGENT" ] \
            || { fail "SIPRAL_HEADLESS_AGENT is not an executable file"; exit 1; }
        HEADLESS_AGENT="$SIPRAL_HEADLESS_AGENT"
        pass "taken as given: $HEADLESS_AGENT"
    elif cargo build --release -p sipral --example headless-agent >/dev/null 2>&1; then
        HEADLESS_AGENT="$ROOT/target/release/examples/headless-agent"
        pass "built"
    else
        fail "cargo build -p sipral --example headless-agent; set SIPRAL_HEADLESS_AGENT"
        exit 1
    fi
fi

# The bridge to a voice agent, and -- for the step of its own -- the headless
# agent's echo as the voice agent of many calls at once. Skipped rather than
# fatal in a run that names nothing, on the socket-framed agent's reasoning.
AGENT_BRIDGE=""
if [ "$WANT" = all ] || [ "$WANT" = asterisk ] || [ "$WANT" = bridge ]; then
    step "the agent bridge"
    if [ -n "${SIPRAL_AGENT_BRIDGE:-}" ]; then
        AGENT_BRIDGE="$SIPRAL_AGENT_BRIDGE"
        pass "taken as given: $AGENT_BRIDGE"
    elif cargo build --release -p sipral --example agent-bridge >/dev/null 2>&1; then
        AGENT_BRIDGE="$ROOT/target/release/examples/agent-bridge"
        pass "built"
    else
        printf '  note  could not build the agent bridge; its steps are skipped\n'
    fi
fi
if [ "$WANT" = bridge ]; then
    step "the headless agent, as the voice agent of many calls"
    if [ -n "${SIPRAL_HEADLESS_AGENT:-}" ]; then
        HEADLESS_AGENT="$SIPRAL_HEADLESS_AGENT"
        pass "taken as given: $HEADLESS_AGENT"
    elif cargo build --release -p sipral --example headless-agent >/dev/null 2>&1; then
        HEADLESS_AGENT="$ROOT/target/release/examples/headless-agent"
        pass "built"
    else
        HEADLESS_AGENT=""
        printf '  note  could not build the headless agent\n'
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
    # grep reads the whole log rather than stopping at the first match (-q):
    # under pipefail, a grep that leaves early kills the writer with SIGPIPE,
    # which fails the pipeline for every log longer than one pipe buffer --
    # coturn's, with the relay step's --verbose, among them
    while [ "$tries" -lt 45 ]; do
        if ( cd interop && docker compose ${compose_profile[@]+"${compose_profile[@]}"} \
                logs --no-color "$service" 2>/dev/null ) \
            | grep -F "$phrase" >/dev/null; then
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
# does. It really does say so -- sofia.c logs "Started Profile lab
# [sofia_reg_lab]" at NOTICE -- but never where wait_for above can read it:
# the image runs `freeswitch -nc`, so only WARNING and above ever reach the
# stdout `docker compose logs` captures, and that line never does regardless
# of the phrase hunted for it. Asked over the event socket instead, the way
# the image's own healthcheck.sh asks it (interop/freeswitch's own
# lab_event_socket.conf.xml is why that connects at all here): freeswitch,
# unlike kamailio's image, has a shell and fs_cli in it. "Invalid Profile!"
# is what an unready or misnamed profile answers with; not fatal on its own
# either way, since the harness's own flows are the real verdict, not a
# probe of what a server said about itself.
freeswitch_lab_profile_up() {
    ( cd interop && docker compose exec -T freeswitch \
        fs_cli -x 'sofia status profile lab' 2>/dev/null ) | found 'sofia_reg_lab'
}
tries=0
profile_seen=0
while [ "$tries" -lt 45 ]; do
    if freeswitch_lab_profile_up; then
        profile_seen=1
        break
    fi
    tries=$((tries + 1))
    sleep 2
done
if [ "$profile_seen" -eq 1 ]; then
    pass "freeswitch: lab profile running"
else
    printf '  note  freeswitch never confirmed the lab profile running; carrying on\n'
fi
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
    lab_run "the harness's flows against $server" $((LAB_START_APT_S + LAB_SUITE_CALLS * LAB_CALL_S)) \
        --network "$LAB_NETWORK" \
        --cap-add NET_RAW --cap-add NET_ADMIN \
        -e SIPRAL_REQUIRE_AUDIO=1 \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
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
    local server="$1" capture="$2" named="${3:-}" beside
    [ -n "$HARNESS_C" ] || return 0
    # the library comes from wherever the binary did, not from this
    # checkout's own target directory: the machine that runs the lab need not
    # be the machine that built either, and on the one of ours that cannot
    # build them the two live under /opt rather than here
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    lab_run "the C harness's flows against $server" $((LAB_START_APT_S + LAB_SUITE_CALLS * LAB_CALL_S)) \
        --network "$LAB_NETWORK" \
        --cap-add NET_RAW --cap-add NET_ADMIN \
        -e SIPRAL_REQUIRE_AUDIO=1 \
        -e LD_LIBRARY_PATH=/lib-sipral \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        ${named:+-e SIPRAL_FLOWS="$named"} \
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

# STIR/SHAKEN between two stacks of the C ABI in one container: the
# certificates made there by interop/stir/run.sh, which then runs
# `harness-c stir` against them -- three calls, each its own two stacks.
stir_flow() {
    local beside
    [ -n "$HARNESS_C" ] || return 0
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    lab_run "STIR/SHAKEN between two C ABI stacks" $((LAB_START_APT_S + 3 * LAB_CALL_S)) \
        --network "$LAB_NETWORK" \
        -e LD_LIBRARY_PATH=/lib-sipral \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS_C:/harness-c:ro" \
        -v "$beside:/lib-sipral:ro" \
        -v "$ROOT/interop/stir:/stir:ro" \
        debian:trixie-slim sh /stir/run.sh
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
    docker run -d --name "$AGENT_NAME" --network "$LAB_NETWORK" \
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
            asterisk -rx "pjsip show contacts" 2>/dev/null ) | found labuser-agent; do
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
    until docker logs "$AGENT_NAME" 2>&1 | found '^ended '; do
        tries=$((tries + 1))
        [ "$tries" -ge 30 ] && break
        sleep 1
    done
    log=$(docker logs "$AGENT_NAME" 2>&1)
    docker rm -f "$AGENT_NAME" >/dev/null 2>&1
    printf '%s\n' "$log" | sed 's/^/    /'

    printf '%s\n' "$log" | found '^answered ' \
        || { printf '  it never answered\n'; return 1; }
    printf '%s\n' "$log" | found '^dtmf #' \
        || { printf '  it never heard the "#" it hangs up on\n'; return 1; }
    printf '%s\n' "$log" \
        | grep '^ended ' | found -E "'packets_received': [1-9]" \
        || { printf '  it heard no audio\n'; return 1; }
    printf '%s\n' "$log" \
        | grep '^ended ' | found -E "'packets_sent': [1-9]" \
        || { printf '  it sent no audio back\n'; return 1; }
}

# The bridge to a voice agent (crates/sipral/examples/agent-bridge.rs),
# registered at Asterisk as labuser-bridge (interop/asterisk/pjsip.conf) and
# calling a voice agent of the step's choosing: an extension forwarding to an
# agent's SIP address, as on a real PBX.
BRIDGE_NAME=sipral-lab-bridge
BRIDGE_AGENT_NAME=sipral-lab-bridge-agent

# bridge_start AGENT_URI [FLAG...]: the bridge, calling AGENT_URI, once
# Asterisk has its registration.
bridge_start() {
    local agent_uri="$1" beside tries at
    shift
    beside=$(cd "$(dirname "$AGENT_BRIDGE")" && pwd)
    docker rm -f "$BRIDGE_NAME" >/dev/null 2>&1
    docker run -d --name "$BRIDGE_NAME" --network "$LAB_NETWORK" \
        -v "$beside:/sipral:ro" \
        debian:trixie-slim sh -c '
            address=$(getent hosts asterisk | cut -d" " -f1)
            exec /sipral/'"$(basename "$AGENT_BRIDGE")"' --pbx "$address:5060" \
                --register labuser-bridge@asterisk --pass labpass --agent "$0" "$@"' \
        "$agent_uri" "$@" >/dev/null \
        || { printf '  could not start the bridge container\n'; return 1; }
    # this bridge's own binding, not one an earlier bridge left behind
    at=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
        "$BRIDGE_NAME")
    tries=0
    until ( cd interop && docker compose exec -T asterisk \
            asterisk -rx "pjsip show contacts" 2>/dev/null ) | found "labuser-bridge@$at:"; do
        tries=$((tries + 1))
        if [ "$(docker inspect -f '{{.State.Running}}' "$BRIDGE_NAME" 2>/dev/null)" != true ] \
            || [ "$tries" -ge 60 ]; then
            printf '  the bridge never registered\n'
            docker logs "$BRIDGE_NAME" 2>&1 | tail -20
            return 1
        fi
        sleep 2
    done
}

bridge_stop() {
    docker rm -f "$BRIDGE_NAME" "$BRIDGE_AGENT_NAME" >/dev/null 2>&1
}

# One call through the bridge, with the Python layer's agent.py as the voice
# agent, listening and never registering. [agent-call] plays a tone and
# dials "12#"; the agent echoes, hears the "#" through the bridge and hangs
# up, and the bridge ends Asterisk's call saying how it ended.
agent_bridge_flow() {
    local beside log agent_log agent_at tries
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    bridge_stop
    docker run -d --name "$BRIDGE_AGENT_NAME" --network "$LAB_NETWORK" \
        -e SIPRAL_LIBRARY=/lib-sipral \
        -e PYTHONPATH=/python \
        -e SIPRAL_AOR=sip:agent@lab.invalid \
        -v "$beside:/lib-sipral:ro" \
        -v "$ROOT/bindings/python:/python:ro" \
        debian:trixie-slim sh -c '
            export DEBIAN_FRONTEND=noninteractive
            apt-get -qq update >/dev/null 2>&1
            apt-get -qq install -y python3 python3-cffi >/dev/null 2>&1
            address=$(getent hosts asterisk | cut -d" " -f1)
            SIPRAL_REGISTRAR_ADDRESS="$address:5060" \
                exec python3 -u /python/examples/agent.py' >/dev/null \
        || { printf '  could not start the voice agent container\n'; return 1; }
    tries=0
    until docker logs "$BRIDGE_AGENT_NAME" 2>&1 | found '^listening on '; do
        tries=$((tries + 1))
        if [ "$(docker inspect -f '{{.State.Running}}' "$BRIDGE_AGENT_NAME" 2>/dev/null)" != true ] \
            || [ "$tries" -ge 60 ]; then
            printf '  the voice agent never started\n'
            docker logs "$BRIDGE_AGENT_NAME" 2>&1 | tail -20
            bridge_stop
            return 1
        fi
        sleep 2
    done
    agent_at=$(docker logs "$BRIDGE_AGENT_NAME" 2>&1 | sed -n 's/^listening on //p' | head -1)
    bridge_start "sip:agent@$agent_at" || { bridge_stop; return 1; }

    ( cd interop && docker compose exec -T asterisk asterisk -rx \
        "channel originate PJSIP/labuser-bridge extension s@agent-call" ) >/dev/null 2>&1

    tries=0
    until docker logs "$BRIDGE_NAME" 2>&1 | found "^ended .*the caller's call is over"; do
        tries=$((tries + 1))
        [ "$tries" -ge 40 ] && break
        sleep 1
    done
    sleep 1
    log=$(docker logs "$BRIDGE_NAME" 2>&1)
    agent_log=$(docker logs "$BRIDGE_AGENT_NAME" 2>&1)
    bridge_stop
    printf '%s\n' "$agent_log" | sed 's/^/    agent   /'
    printf '%s\n' "$log" | sed 's/^/    bridge  /'

    printf '%s\n' "$log" | found '^bridged ' \
        || { printf '  the two calls were never bridged\n'; return 1; }
    printf '%s\n' "$log" | found '^dtmf # from' \
        || { printf '  the bridge never forwarded the "#"\n'; return 1; }
    printf '%s\n' "$agent_log" | found '^dtmf #' \
        || { printf '  the agent never heard the "#"\n'; return 1; }
    printf '%s\n' "$log" | found 'X-Sipral-Outcome: resolved' \
        || { printf '  the PBX was not told the call was resolved\n'; return 1; }
    [ "$(printf '%s\n' "$log" | grep '^stats ' | grep -c -E 'sent=[1-9][0-9]* received=[1-9]')" -ge 2 ] \
        || { printf '  a leg carried no audio one way\n'; return 1; }
    printf '%s\n' "$agent_log" \
        | grep '^ended ' | found -E "'packets_received': [1-9]" \
        || { printf '  the agent heard no audio\n'; return 1; }
}

# SIPRAL_BRIDGE_CALLS (thirty) calls placed by Asterisk at once, through one
# bridge, to the headless agent's echo: every one bridged, carrying audio
# both ways and ended when [agent-call] hangs up. The bridge's own CPU time
# over the run is read from its /proc entry and printed, with Asterisk's own
# channel count halfway through.
agent_bridge_volume() {
    local calls="${SIPRAL_BRIDGE_CALLS:-30}" beside agent_ip log agent_log tries before after
    local started finished bridged over legs silent channels
    beside=$(cd "$(dirname "$HEADLESS_AGENT")" && pwd)
    bridge_stop
    docker run -d --name "$BRIDGE_AGENT_NAME" --network "$LAB_NETWORK" \
        -v "$beside:/sipral:ro" \
        debian:trixie-slim sh -c 'exec /sipral/'"$(basename "$HEADLESS_AGENT")"' \
            --host "$(hostname -i)" --port 5060 --invite-burst 200' >/dev/null \
        || { printf '  could not start the echo agent container\n'; return 1; }
    sleep 2
    agent_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
        "$BRIDGE_AGENT_NAME")
    bridge_start "sip:agent@$agent_ip:5060" --invite-burst 200 || { bridge_stop; return 1; }

    before=$(docker exec "$BRIDGE_NAME" cat /proc/1/stat | awk '{print $14 + $15}')
    started=$(date +%s)
    ( cd interop && docker compose exec -T asterisk sh -c '
        i=0
        while [ "$i" -lt '"$calls"' ]; do
            asterisk -rx "channel originate PJSIP/labuser-bridge extension s@agent-call" \
                >/dev/null 2>&1 &
            i=$((i + 1))
        done
        wait' ) >/dev/null 2>&1
    sleep 6
    channels=$(cd interop && docker compose exec -T asterisk asterisk -rx \
        "core show channels count" 2>/dev/null | sed -n 's/^\([0-9][0-9]*\) active channel.*/\1/p')
    tries=0
    over=0
    while [ "$over" -lt "$calls" ] && [ "$tries" -lt 90 ]; do
        sleep 1
        tries=$((tries + 1))
        over=$(docker logs "$BRIDGE_NAME" 2>&1 | grep -c "the caller's call is over")
    done
    sleep 2
    after=$(docker exec "$BRIDGE_NAME" cat /proc/1/stat | awk '{print $14 + $15}')
    finished=$(date +%s)
    log=$(docker logs "$BRIDGE_NAME" 2>&1)
    agent_log=$(docker logs "$BRIDGE_AGENT_NAME" 2>&1)
    bridge_stop
    printf '%s\n' "$log" | grep -v -E '^(codec|dtmf|stats) ' | head -12 | sed 's/^/    bridge  /'
    printf '%s\n' "$agent_log" | head -4 | sed 's/^/    agent   /'
    bridged=$(printf '%s\n' "$log" | grep -c '^bridged ')
    legs=$(printf '%s\n' "$log" | grep -c '^stats ')
    silent=$(printf '%s\n' "$log" | grep '^stats ' | grep -c -E 'sent=0 |received=0 ')
    printf '  note  %s calls placed: %s bridged, %s ended, %s legs reported, %s without audio one way\n' \
        "$calls" "$bridged" "$over" "$legs" "$silent"
    printf '  note  Asterisk had %s channels up six seconds in\n' "${channels:-an unknown number of}"
    printf '  note  the bridge used %s ticks of CPU (1/100 s each) over %s s of wall clock\n' \
        "$((after - before))" "$((finished - started))"
    [ "$bridged" -ge "$calls" ] && [ "$over" -ge "$calls" ] \
        && [ "$legs" -ge $((2 * calls)) ] && [ "$silent" -eq 0 ]
}

# org.sipral.idiomatic's own headless agent, bindings/kotlin/examples/Agent.kt,
# on a JVM (`interop/kotlin`: `eclipse-temurin`'s JDK, whose own `jni.h` the
# container compiles the shim against, plus the compiler, built once and
# reused). Kotlin has no build tool in this tree
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
    docker build -q -t sipral-lab-kotlin interop/kotlin >/dev/null 2>&1 \
        || { printf '  could not build interop/kotlin\n'; return 1; }
    docker rm -f "$KOTLIN_AGENT_NAME" >/dev/null 2>&1
    docker run -d --name "$KOTLIN_AGENT_NAME" --network "$LAB_NETWORK" \
        -e SIPRAL_AOR=sip:labuser-agent-kotlin@asterisk \
        -e SIPRAL_REGISTRAR=sip:asterisk \
        -e SIPRAL_AUTH_USER=labuser-agent-kotlin -e SIPRAL_AUTH_PASSWORD=labpass \
        -v "$beside:/lib-sipral:ro" \
        -v "$ROOT/bindings/c/include:/sipral-include:ro" \
        -v "$ROOT/bindings/kotlin/sipral/src/main/jni:/sipral-jni:ro" \
        -v "$KOTLIN_AGENT_JAR:/kotlin/sipral-kotlin.jar:ro" \
        -v "$KOTLIN_STDLIB_JAR:/kotlin/kotlin-stdlib.jar:ro" \
        -v "$KOTLIN_COROUTINES_JAR:/kotlin/kotlinx-coroutines.jar:ro" \
        sipral-lab-kotlin sh -c '
            set -e
            cc -std=c11 -Wall -shared -fPIC \
                -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" -I/sipral-include \
                -o /tmp/libsipral_jni.so \
                /sipral-jni/sipral_jni.c /sipral-jni/idiomatic_media.c /sipral-jni/audio_routes.c \
                -L/lib-sipral -lsipral_ffi -Wl,-rpath,/lib-sipral
            address=$(getent hosts asterisk | cut -d" " -f1)
            SIPRAL_REGISTRAR_ADDRESS="$address:5060" \
                exec java -Djava.library.path=/tmp \
                -cp "/kotlin/sipral-kotlin.jar:/kotlin/kotlin-stdlib.jar:/kotlin/kotlinx-coroutines.jar" \
                org.sipral.examples.AgentKt' >/dev/null \
        || { printf '  could not start the Kotlin agent container\n'; return 1; }

    tries=0
    until ( cd interop && docker compose exec -T asterisk \
            asterisk -rx "pjsip show contacts" 2>/dev/null ) | found labuser-agent-kotlin; do
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
    until docker logs "$KOTLIN_AGENT_NAME" 2>&1 | found '^ended '; do
        tries=$((tries + 1))
        [ "$tries" -ge 30 ] && break
        sleep 1
    done
    log=$(docker logs "$KOTLIN_AGENT_NAME" 2>&1)
    docker rm -f "$KOTLIN_AGENT_NAME" >/dev/null 2>&1
    printf '%s\n' "$log" | sed 's/^/    /'

    printf '%s\n' "$log" | found '^answered ' \
        || { printf '  it never answered\n'; return 1; }
    printf '%s\n' "$log" | found '^dtmf 1' \
        || { printf '  it never heard the digit "1"\n'; return 1; }
    printf '%s\n' "$log" | found '^dtmf 2' \
        || { printf '  it never heard the digit "2"\n'; return 1; }
    printf '%s\n' "$log" | found '^dtmf #' \
        || { printf '  it never heard the "#" it hangs up on\n'; return 1; }
    printf '%s\n' "$log" \
        | grep '^ended ' | found -E "packets_received=[1-9]" \
        || { printf '  it heard no audio\n'; return 1; }
    printf '%s\n' "$log" \
        | grep '^ended ' | found -E "packets_sent=[1-9]" \
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
    docker run -d --name "$SWIFT_AGENT_NAME" --network "$LAB_NETWORK" \
        -v "$ROOT":/work:ro -v "${SWIFT_LIB_DIR:-$ROOT/target/release}":/work/target/release:ro \
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
            asterisk -rx "pjsip show contacts" 2>/dev/null ) | found labuser-agent-swift; do
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
    until docker logs "$SWIFT_AGENT_NAME" 2>&1 | found '^ended '; do
        tries=$((tries + 1))
        [ "$tries" -ge 30 ] && break
        sleep 1
    done
    log=$(docker logs "$SWIFT_AGENT_NAME" 2>&1)
    docker rm -f "$SWIFT_AGENT_NAME" >/dev/null 2>&1
    printf '%s\n' "$log" | sed 's/^/    /'

    printf '%s\n' "$log" | found '^answered ' \
        || { printf '  it never answered\n'; return 1; }
    printf '%s\n' "$log" | found '^dtmf #' \
        || { printf '  it never heard the "#" it hangs up on\n'; return 1; }
    printf '%s\n' "$log" | found -E '^ended .*packets_received=[1-9]' \
        || { printf '  it heard no audio\n'; return 1; }
    printf '%s\n' "$log" | found -E '^ended .*packets_sent=[1-9]' \
        || { printf '  it sent no audio back\n'; return 1; }
}

# 8.6.3's .NET binding: bindings/dotnet/samples/Sipral.Sample.Agent, the same
# echo-and-hang-up-on-"#" shape as `python_agent` above, over
# bindings/dotnet/Sipral instead of bindings/python, and against the same
# shared library, found beside the C harness the way `python_agent` finds it.
# The image already carries the SDK, so nothing is installed at container
# start; the source is copied into the container's own writable filesystem
# before `dotnet build`, since the shared library it is mounted beside is
# read-only and a build needs somewhere to write bin/ and obj/. Requires no
# network once the image itself is pulled -- neither project names a NuGet
# package.
CSHARP_AGENT_NAME=sipral-lab-agent-csharp
csharp_agent() {
    local beside log tries
    [ -n "$HARNESS_C" ] || return 0
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    [ -s "$beside/libsipral_ffi.so" ] || { printf '  no libsipral_ffi.so beside the C harness\n'; return 1; }
    docker rm -f "$CSHARP_AGENT_NAME" >/dev/null 2>&1
    docker run -d --name "$CSHARP_AGENT_NAME" --network "$LAB_NETWORK" \
        -e SIPRAL_LIBRARY=/lib-sipral/libsipral_ffi.so \
        -e SIPRAL_AOR=sip:labuser-agent-csharp@asterisk \
        -e SIPRAL_REGISTRAR=sip:asterisk \
        -e SIPRAL_AUTH_USER=labuser-agent-csharp -e SIPRAL_AUTH_PASSWORD=labpass \
        -v "$beside:/lib-sipral:ro" \
        -v "$ROOT/bindings/dotnet:/src-dotnet:ro" \
        mcr.microsoft.com/dotnet/sdk:8.0 sh -c '
            cp -r /src-dotnet /dotnet
            address=$(getent hosts asterisk | cut -d" " -f1)
            cd /dotnet/samples/Sipral.Sample.Agent
            SIPRAL_REGISTRAR_ADDRESS="$address:5060" \
                exec dotnet run -c Release --no-launch-profile' >/dev/null \
        || { printf '  could not start the agent container\n'; return 1; }

    tries=0
    until ( cd interop && docker compose exec -T asterisk \
            asterisk -rx "pjsip show contacts" 2>/dev/null ) | found labuser-agent-csharp; do
        tries=$((tries + 1))
        # a container that died, or a `dotnet build` that already came back
        # and printed nothing further, is not going to register however
        # long it is given -- the build's own errors are the useful part
        if [ "$(docker inspect -f '{{.State.Running}}' "$CSHARP_AGENT_NAME" 2>/dev/null)" != true ] \
            || [ "$tries" -ge 90 ]; then
            printf '  the agent never registered\n'
            docker logs "$CSHARP_AGENT_NAME" 2>&1 | tail -40
            docker rm -f "$CSHARP_AGENT_NAME" >/dev/null 2>&1
            return 1
        fi
        sleep 2
    done

    ( cd interop && docker compose exec -T asterisk asterisk -rx \
        "channel originate PJSIP/labuser-agent-csharp extension s@agent-call" ) >/dev/null 2>&1

    tries=0
    until docker logs "$CSHARP_AGENT_NAME" 2>&1 | found '^ended '; do
        tries=$((tries + 1))
        [ "$tries" -ge 30 ] && break
        sleep 1
    done
    log=$(docker logs "$CSHARP_AGENT_NAME" 2>&1)
    docker rm -f "$CSHARP_AGENT_NAME" >/dev/null 2>&1
    printf '%s\n' "$log" | tail -20 | sed 's/^/    /'

    printf '%s\n' "$log" | found '^answered ' \
        || { printf '  it never answered\n'; return 1; }
    printf '%s\n' "$log" | found '^dtmf #' \
        || { printf '  it never heard the "#" it hangs up on\n'; return 1; }
    printf '%s\n' "$log" \
        | grep '^ended ' | found -E 'packets_received=[1-9]' \
        || { printf '  it heard no audio\n'; return 1; }
    printf '%s\n' "$log" \
        | grep '^ended ' | found -E 'packets_sent=[1-9]' \
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
    docker run -d --name "$HEADLESS_APP_NAME" --network "$LAB_NETWORK" \
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
    until docker logs "$HEADLESS_APP_NAME" 2>&1 | found '^waiting for the agent'; do
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

    docker run -d --name "$HEADLESS_CLIENT_NAME" --network "$LAB_NETWORK" \
        -v "$client_beside:/sipral:ro" \
        debian:trixie-slim /sipral/agent --addr "$HEADLESS_APP_NAME:7001" >/dev/null \
        || {
            printf '  could not start the agent container\n'
            docker rm -f "$HEADLESS_APP_NAME" >/dev/null 2>&1
            return 1
        }

    tries=0
    until ( cd interop && docker compose exec -T asterisk \
            asterisk -rx "pjsip show contacts" 2>/dev/null ) | found labuser-agent-headless; do
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
    until docker logs "$HEADLESS_APP_NAME" 2>&1 | found '^ended '; do
        tries=$((tries + 1))
        [ "$tries" -ge 30 ] && break
        sleep 1
    done
    app_log=$(docker logs "$HEADLESS_APP_NAME" 2>&1)
    printf '%s\n' "$(docker logs "$HEADLESS_CLIENT_NAME" 2>&1)" | sed 's/^/    agent  /'
    printf '%s\n' "$app_log" | sed 's/^/    app    /'
    docker rm -f "$HEADLESS_APP_NAME" "$HEADLESS_CLIENT_NAME" >/dev/null 2>&1

    printf '%s\n' "$app_log" | found '^answered ' \
        || { printf '  it never answered\n'; return 1; }
    printf '%s\n' "$app_log" | found '^dtmf #' \
        || { printf '  it never heard the "#" the dialplan sends\n'; return 1; }
    printf '%s\n' "$app_log" | found -E '^ended .*packets_received=[1-9]' \
        || { printf '  it heard no audio\n'; return 1; }
    printf '%s\n' "$app_log" | found -E '^ended .*packets_sent=[1-9]' \
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
    lab_run "the harness's calls to baresip" $((LAB_START_APT_S + 4 * LAB_CALL_S)) \
        --network "$LAB_NETWORK" \
        --cap-add NET_RAW --cap-add NET_ADMIN \
        -e SIPRAL_REQUIRE_AUDIO=1 -e SIPRAL_PEER=baresip \
        -e SIPRAL_FLOWS=call,hold,peersrtp,peerdtls \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
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
    lab_run "the C harness's calls to baresip" $((LAB_START_APT_S + 4 * LAB_CALL_S)) \
        --network "$LAB_NETWORK" \
        --cap-add NET_RAW --cap-add NET_ADMIN \
        -e SIPRAL_REQUIRE_AUDIO=1 -e SIPRAL_PEER=baresip \
        -e SIPRAL_FLOWS=call,hold,peersrtp,peerdtls \
        -e LD_LIBRARY_PATH=/lib-sipral \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
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

# docs/11-testing.md's "call, ended by the far end": one netstring-wrapped
# JSON command, {"command":"hangup"}, to baresip-hangup's own ctrl_tcp port
# (interop/baresip/config-hangup/config's own module_app ctrl_tcp.so, on
# baresip's own default 4444) -- baresip answering it by hanging the one
# call it has up through the same code path its own menu module's "b" key
# would. Nothing in baresip's own account or call configuration can do this
# to a call already answered: src/call.c's own call_local_timeout is
# cancelled the instant one is (interop/baresip/config-hangup/config's own
# reasoning), so this is what stands in for a person on that phone deciding
# to hang up.
baresip_ctrl_hangup() {
    local json='{"command":"hangup","params":"","token":"lab"}'
    local len=${#json}
    docker run --rm --network "$LAB_NETWORK" \
        debian:trixie-slim sh -c "
            export DEBIAN_FRONTEND=noninteractive
            apt-get -qq update >/dev/null 2>&1
            apt-get -qq install -y netcat-openbsd >/dev/null 2>&1
            printf '%s:%s,' '$len' '$json' | nc -w2 baresip-hangup 4444" \
        >/dev/null 2>&1
}

# The Rust harness's own half of the same flow (`Flow::PeerHangup`, key
# "peerhangup"): places the call and then only waits -- no `listen_until`
# ever schedules its own hangup, unlike every other flow this file runs
# against baresip -- so `baresip_ctrl_hangup`, backgrounded two seconds in
# (comfortably inside SIPRAL_PATIENCE_MS's default twenty), has to be what
# ends it. The trigger runs concurrently with the harness, which blocks for
# the whole call; its own status is waited on after so a slow image pull or
# `apt-get install` inside it can never outlive this function's caller.
#
# flows_baresip_hangup_c() below is the same flow through the C ABI.
flows_baresip_hangup() {
    local status trigger_pid
    ( sleep 2; baresip_ctrl_hangup ) &
    trigger_pid=$!
    lab_run "the harness's call baresip hangs up" $((LAB_START_S + LAB_CALL_S)) \
        --network "$LAB_NETWORK" \
        -e SIPRAL_REQUIRE_AUDIO=1 -e SIPRAL_PEER=baresip-hangup \
        -e SIPRAL_FLOWS=peerhangup \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS:/harness:ro" \
        debian:trixie-slim sh -c "/harness kamailio 5060 baresip-hangup"
    status=$?
    wait "$trigger_pid" 2>/dev/null
    return "$status"
}

# The same, through the C ABI. See flows_c() above for why this is a function
# of its own rather than an argument to flows_baresip_hangup(); see
# interop/harness-c/main.c's own FLOW_PEER_HANGUP for the flow itself.
flows_baresip_hangup_c() {
    local status trigger_pid beside
    [ -n "$HARNESS_C" ] || return 0
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    ( sleep 2; baresip_ctrl_hangup ) &
    trigger_pid=$!
    lab_run "the C harness's call baresip hangs up" $((LAB_START_S + LAB_CALL_S)) \
        --network "$LAB_NETWORK" \
        -e SIPRAL_REQUIRE_AUDIO=1 -e SIPRAL_PEER=baresip-hangup \
        -e SIPRAL_FLOWS=peerhangup \
        -e LD_LIBRARY_PATH=/lib-sipral \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS_C:/harness-c:ro" \
        -v "$beside:/lib-sipral:ro" \
        debian:trixie-slim sh -c "/harness-c kamailio 5060 baresip-hangup"
    status=$?
    wait "$trigger_pid" 2>/dev/null
    return "$status"
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
    local beside status
    local project="${COMPOSE_PROJECT_NAME:-sipral-interop}"
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    nat_up || return 1
    printf '  behind %s, STUN at %s:3478, Asterisk at %s\n' "$NAT_GATEWAY" "$NAT_STUN" "$NAT_ASTERISK"

    lab_run "the C harness behind the NAT" $((LAB_START_S + 2 * LAB_CALL_S)) \
        --network "${project}_inside" \
        --cap-add NET_ADMIN \
        --add-host "asterisk:$NAT_ASTERISK" \
        -e SIPRAL_REQUIRE_AUDIO=1 -e SIPRAL_FLOWS=nat \
        -e "SIPRAL_STUN_SERVER=$NAT_STUN:3478" \
        -e LD_LIBRARY_PATH=/lib-sipral \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS_C:/harness-c:ro" \
        -v "$beside:/lib-sipral:ro" \
        sipral-lab-nat sh -c "
            ip route replace default via $NAT_GATEWAY || exit 1
            exec /harness-c asterisk 5060 9000"
    status=$?
    nat_down
    return "$status"
}

# coturn and the NAT, up, with the three addresses a step behind it needs
# read into NAT_GATEWAY (the NAT's own leg on `inside`, the default route
# there), NAT_STUN and NAT_ASTERISK (both on the lab network).
nat_up() {
    local project="${COMPOSE_PROJECT_NAME:-sipral-interop}"
    local natbox coturn asterisk
    ( cd interop && docker compose --profile nat up -d --build coturn natbox ) >/dev/null 2>&1 \
        || { printf '  could not start coturn and the NAT\n'; return 1; }
    wait_for natbox "nat: masquerading out of" required nat || return 1
    # coturn 4.18 logs the addresses it will listen on and then nothing about
    # having opened them; the harness's own retransmissions cover the gap
    wait_for coturn "Listener address to use" optional nat || true

    natbox=$(cd interop && docker compose --profile nat ps -q natbox)
    coturn=$(cd interop && docker compose --profile nat ps -q coturn)
    asterisk=$(cd interop && docker compose ps -q asterisk)
    NAT_GATEWAY=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"${project}_inside\"}}{{.IPAddress}}{{end}}" \
        "$natbox")
    NAT_STUN=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"${project}_lab\"}}{{.IPAddress}}{{end}}" \
        "$coturn")
    NAT_ASTERISK=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"${project}_lab\"}}{{.IPAddress}}{{end}}" \
        "$asterisk")
    if [ -z "$NAT_GATEWAY" ] || [ -z "$NAT_STUN" ] || [ -z "$NAT_ASTERISK" ]; then
        printf '  could not read the addresses: NAT %s, coturn %s, Asterisk %s\n' \
            "${NAT_GATEWAY:-?}" "${NAT_STUN:-?}" "${NAT_ASTERISK:-?}"
        nat_down
        return 1
    fi
}

nat_down() {
    ( cd interop && docker compose --profile nat rm -sf coturn natbox ) >/dev/null 2>&1
}

# The same account behind the same NAT, called rather than calling: the C
# harness's own `natin` flow registers `labuser` at the address coturn
# reported and says so on a `waiting for a call to <URI>` line, and Asterisk
# then calls that URI into extension 9010, which echoes for eight seconds and
# hangs up. The binding is named rather than `PJSIP/labuser` alone because
# the account keeps ten, and one an earlier run never gave back would take
# the call.
#
# What it guards is the half of a phone's life the network starts: the
# INVITE reaching the address STUN reported, the 2xx answering it with that
# address in its `Contact` too, Asterisk's ACK and BYE both reaching it, and
# the echo coming back to the `c=`. interop/harness-c's flow_nat_incoming
# checks each and says which one failed. The harness runs detached, since
# this script reads its output while it waits for the call; a harness that
# never says it is waiting, or dies first, fails the step with its log.
NAT_CALLED_NAME=sipral-lab-nat-called
nat_called_flow() {
    local beside uri status tries=0
    local project="${COMPOSE_PROJECT_NAME:-sipral-interop}"
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    nat_up || return 1
    printf '  behind %s, STUN at %s:3478, Asterisk at %s\n' "$NAT_GATEWAY" "$NAT_STUN" "$NAT_ASTERISK"
    docker rm -f "$NAT_CALLED_NAME" >/dev/null 2>&1
    docker run -d --name "$NAT_CALLED_NAME" --network "${project}_inside" \
        --cap-add NET_ADMIN \
        --add-host "asterisk:$NAT_ASTERISK" \
        -e SIPRAL_REQUIRE_AUDIO=1 -e SIPRAL_FLOWS=natin \
        -e "SIPRAL_STUN_SERVER=$NAT_STUN:3478" \
        -e LD_LIBRARY_PATH=/lib-sipral \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS_C:/harness-c:ro" \
        -v "$beside:/lib-sipral:ro" \
        sipral-lab-nat sh -c "
            ip route replace default via $NAT_GATEWAY || exit 1
            exec /harness-c asterisk 5060 9000" >/dev/null \
        || { printf '  could not start the harness\n'; nat_down; return 1; }
    uri=""
    until [ -n "$uri" ]; do
        uri=$(docker logs "$NAT_CALLED_NAME" 2>&1 \
            | sed -n 's/^  nat   waiting for a call to \(sip:[^ ]*\)$/\1/p' | head -1)
        [ -n "$uri" ] && break
        tries=$((tries + 1))
        if [ "$(docker inspect -f '{{.State.Running}}' "$NAT_CALLED_NAME" 2>/dev/null)" != true ] \
            || [ "$tries" -ge 45 ]; then
            printf '  the harness never said it was waiting for the call\n'
            docker logs "$NAT_CALLED_NAME" 2>&1
            docker rm -f "$NAT_CALLED_NAME" >/dev/null 2>&1
            nat_down
            return 1
        fi
        sleep 1
    done
    ( cd interop && docker compose exec -T asterisk asterisk -rx \
        "channel originate PJSIP/labuser/$uri extension 9010@lab" ) >/dev/null 2>&1
    status=$(timeout 90 docker wait "$NAT_CALLED_NAME" 2>/dev/null || echo 1)
    docker logs "$NAT_CALLED_NAME" 2>&1
    docker rm -f "$NAT_CALLED_NAME" >/dev/null 2>&1
    nat_down
    [ "$status" = 0 ]
}

# The same called flow, with the call placed 330 seconds after the REGISTER
# rather than at once: long past the NAT's UDP timeout (interop/nat is Linux
# masquerading, whose conntrack forgets a UDP flow minutes after its last
# packet, and which lets in only what matches a flow it remembers -- address
# and port dependent filtering, RFC 4787 §5, like most NATs). The STUN refresh every 25 s goes to coturn and says nothing for
# the flow to Asterisk; only the stack's own registrar keep-alive, a double
# CRLF to Asterisk every 20 to 25 s, keeps the INVITE's way in open.
#
# `$1` is `on` or `off`: off sets SIPRAL_REGISTRAR_KEEPALIVE=off in the
# harness, and then the call must NOT arrive -- that run is the proof the NAT
# in front of it forgets, without which the `on` run proves nothing. The
# harness waits for the call for 420 s, the originate goes at 330 s, and the
# step returns 0 when the outcome is the one `$1` expects.
NAT_IDLE_NAME=sipral-lab-nat-idle
NAT_IDLE_WAIT=330
nat_idle_called_flow() {
    local keepalive="$1" beside uri status tries=0 waited
    local project="${COMPOSE_PROJECT_NAME:-sipral-interop}"
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    nat_up || return 1
    printf '  behind %s, STUN at %s:3478, Asterisk at %s, keep-alive %s\n' \
        "$NAT_GATEWAY" "$NAT_STUN" "$NAT_ASTERISK" "$keepalive"
    docker rm -f "$NAT_IDLE_NAME" >/dev/null 2>&1
    docker run -d --name "$NAT_IDLE_NAME" --network "${project}_inside" \
        --cap-add NET_ADMIN \
        --add-host "asterisk:$NAT_ASTERISK" \
        -e SIPRAL_REQUIRE_AUDIO=1 -e SIPRAL_FLOWS=natin \
        -e SIPRAL_CALLED_PATIENCE_MS=420000 \
        -e "SIPRAL_REGISTRAR_KEEPALIVE=$keepalive" \
        -e "SIPRAL_STUN_SERVER=$NAT_STUN:3478" \
        -e LD_LIBRARY_PATH=/lib-sipral \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS_C:/harness-c:ro" \
        -v "$beside:/lib-sipral:ro" \
        sipral-lab-nat sh -c "
            ip route replace default via $NAT_GATEWAY || exit 1
            exec /harness-c asterisk 5060 9000" >/dev/null \
        || { printf '  could not start the harness\n'; nat_down; return 1; }
    uri=""
    until [ -n "$uri" ]; do
        uri=$(docker logs "$NAT_IDLE_NAME" 2>&1 \
            | sed -n 's/^  nat   waiting for a call to \(sip:[^ ]*\)$/\1/p' | head -1)
        [ -n "$uri" ] && break
        tries=$((tries + 1))
        if [ "$(docker inspect -f '{{.State.Running}}' "$NAT_IDLE_NAME" 2>/dev/null)" != true ] \
            || [ "$tries" -ge 45 ]; then
            printf '  the harness never said it was waiting for the call\n'
            docker logs "$NAT_IDLE_NAME" 2>&1
            docker rm -f "$NAT_IDLE_NAME" >/dev/null 2>&1
            nat_down
            return 1
        fi
        sleep 1
    done
    printf '  registered; calling %s in %s s\n' "$uri" "$NAT_IDLE_WAIT"
    waited=0
    while [ "$waited" -lt "$NAT_IDLE_WAIT" ]; do
        if [ "$(docker inspect -f '{{.State.Running}}' "$NAT_IDLE_NAME" 2>/dev/null)" != true ]; then
            printf '  the harness stopped while it waited\n'
            break
        fi
        sleep 10
        waited=$((waited + 10))
    done
    ( cd interop && docker compose exec -T asterisk asterisk -rx \
        "channel originate PJSIP/labuser/$uri extension 9010@lab" ) >/dev/null 2>&1
    status=$(timeout 150 docker wait "$NAT_IDLE_NAME" 2>/dev/null || echo 1)
    docker logs "$NAT_IDLE_NAME" 2>&1
    docker rm -f "$NAT_IDLE_NAME" >/dev/null 2>&1
    nat_down
    if [ "$keepalive" = off ]; then
        [ "$status" != 0 ]
    else
        [ "$status" = 0 ]
    fi
}

# 8.5.5's ICE-lite steps: the headless application answering as an ICE-lite
# endpoint (`headless-socket-agent --ice-lite`, sipral::IcePolicy::Lite),
# with the reference agent behind its socket echoing what it hears. The lab
# network stands in for the public Internet here: every container on it
# reaches every other at the address it is bound to, which is the one
# property RFC 8445 Appendix A asks of a lite host.
#
# Two containers again, started the way headless_socket_agent starts them.
# SIPRAL_LITE_REGISTER, when set, is the account the application registers
# at Asterisk; without it the application is dialled directly.
ICE_APP_NAME=sipral-lab-icelite-app
ICE_CLIENT_NAME=sipral-lab-icelite-agent
start_lite_agent() {
    local account="$1" app_beside client_beside tries
    app_beside=$(cd "$(dirname "$HEADLESS_APP")" && pwd)
    client_beside=$(cd "$(dirname "$HEADLESS_CLIENT")" && pwd)
    docker rm -f "$ICE_APP_NAME" "$ICE_CLIENT_NAME" >/dev/null 2>&1
    docker run -d --name "$ICE_APP_NAME" --network "$LAB_NETWORK" \
        -e "SIPRAL_LITE_REGISTER=$account" \
        -v "$app_beside:/sipral:ro" \
        debian:trixie-slim sh -c '
            own=$(hostname -i)
            if [ -n "$SIPRAL_LITE_REGISTER" ]; then
                address=$(getent hosts asterisk | cut -d" " -f1)
                exec /sipral/headless-socket-agent --ice-lite \
                    --host "$own" --port 5060 --socket 0.0.0.0:7001 \
                    --register "$SIPRAL_LITE_REGISTER@asterisk" \
                    --registrar "$address:5060" --pass labpass
            fi
            exec /sipral/headless-socket-agent --ice-lite \
                --host "$own" --port 5060 --socket 0.0.0.0:7001' >/dev/null \
        || { printf '  could not start the application container\n'; return 1; }
    tries=0
    until docker logs "$ICE_APP_NAME" 2>&1 | found '^waiting for the agent'; do
        tries=$((tries + 1))
        if [ "$(docker inspect -f '{{.State.Running}}' "$ICE_APP_NAME" 2>/dev/null)" != true ] \
            || [ "$tries" -ge 30 ]; then
            printf '  the application never came up\n'
            docker logs "$ICE_APP_NAME" 2>&1 | tail -20
            docker rm -f "$ICE_APP_NAME" >/dev/null 2>&1
            return 1
        fi
        sleep 1
    done
    docker run -d --name "$ICE_CLIENT_NAME" --network "$LAB_NETWORK" \
        -v "$client_beside:/sipral:ro" \
        debian:trixie-slim /sipral/agent --addr "$ICE_APP_NAME:7001" >/dev/null \
        || { printf '  could not start the agent container\n'; stop_lite_agent; return 1; }
    tries=0
    until docker logs "$ICE_APP_NAME" 2>&1 | found '^agent connected'; do
        tries=$((tries + 1))
        if [ "$tries" -ge 30 ]; then
            printf '  the agent never connected\n'
            stop_lite_agent
            return 1
        fi
        sleep 1
    done
}

# What both containers said, and both gone. Prints the application's log a
# second time on its own, bare, for the caller to judge.
stop_lite_agent() {
    docker logs "$ICE_CLIENT_NAME" 2>&1 | sed 's/^/    agent  /'
    docker logs "$ICE_APP_NAME" 2>&1 | sed 's/^/    app    /'
    docker rm -f "$ICE_APP_NAME" "$ICE_CLIENT_NAME" >/dev/null 2>&1
}

# Wait for the application to report its call over, then keep its log.
lite_agent_log() {
    local tries=0
    until docker logs "$ICE_APP_NAME" 2>&1 | found '^ended '; do
        tries=$((tries + 1))
        [ "$tries" -ge "$1" ] && break
        sleep 1
    done
    docker logs "$ICE_APP_NAME" 2>&1
}

# The first half: the Rust harness, as the full agent a WebRTC gateway would
# be, calls the application directly under IcePolicy::Required
# (interop/harness/src/ice_lite.rs). A lite end that did nothing -- no
# `a=ice-lite`, no candidate, no answer to a check -- fails it on the
# harness's side with IceRequired or with no path, never with audio; the
# application's own "path chosen" line is the other side of the same pair.
ice_lite_flow() {
    local address status app_log
    start_lite_agent "" || return 1
    address=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"$LAB_NETWORK\"}}{{.IPAddress}}{{end}}" \
        "$ICE_APP_NAME")
    lab_run "the harness's call to the ICE-lite application" $((LAB_START_S + LAB_CALL_S)) \
        --network "$LAB_NETWORK" \
        -e SIPRAL_FLOWS=icelite \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS:/harness:ro" \
        debian:trixie-slim /harness "$address" 5060 agent
    status=$?
    app_log=$(lite_agent_log 10)
    stop_lite_agent
    [ "$status" -eq 0 ] || return 1
    printf '%s\n' "$app_log" | found '^path chosen ' \
        || { printf '  the lite end never took a nominated pair\n'; return 1; }
    printf '%s\n' "$app_log" | found -E '^ended .*packets_sent=[1-9]' \
        || { printf '  the lite end sent no audio on the pair\n'; return 1; }
}

# The second half: Asterisk's own ICE (res_pjsip's ice_support) as the full
# agent, calling the application registered on an endpoint that has it on.
# That endpoint lives in interop/ice/pjsip_local.conf, mounted by
# interop/ice/compose.override.yaml over the empty default only for this
# step, so no other flow ever meets an Asterisk that offers ICE; Asterisk is
# put back as it was afterwards, whatever happened.
#
# The application's own log cannot tell whether Asterisk's checks succeeded:
# Asterisk nominates as it checks, so the lite end reports a pair on the
# first check it receives, and an Asterisk whose checks all failed still
# sends its audio to the lite end's candidate, which is also its `c=`. So
# Asterisk's RTP debug is read as well: it marks each packet it sends
# through a completed ICE session "(via ICE)", and a lite end whose answers
# never reached it gets none.
ice_lite_asterisk() {
    local app_log rtp_log since via_ice status=0 tries
    ( cd interop && docker compose -f compose.yaml -f ice/compose.override.yaml up -d asterisk ) \
        >/dev/null 2>&1 || { printf '  could not restart Asterisk with the ICE endpoint\n'; return 1; }
    wait_for asterisk "Asterisk Ready" || status=1
    if [ "$status" -eq 0 ] && start_lite_agent labuser-agent-ice; then
        tries=0
        until ( cd interop && docker compose exec -T asterisk \
                asterisk -rx "pjsip show contacts" 2>/dev/null ) | found labuser-agent-ice; do
            tries=$((tries + 1))
            if [ "$tries" -ge 30 ]; then
                printf '  the application never registered\n'
                status=1
                break
            fi
            sleep 2
        done
        if [ "$status" -eq 0 ]; then
            ( cd interop && docker compose exec -T asterisk asterisk -rx "rtp set debug on" ) \
                >/dev/null 2>&1
            since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
            ( cd interop && docker compose exec -T asterisk asterisk -rx \
                "channel originate PJSIP/labuser-agent-ice extension s@agent-call" ) >/dev/null 2>&1
            app_log=$(lite_agent_log 30)
            rtp_log=$( cd interop && docker compose logs --no-color --since "$since" asterisk \
                2>/dev/null )
        fi
        stop_lite_agent
    else
        status=1
    fi
    ( cd interop && docker compose up -d asterisk ) >/dev/null 2>&1
    wait_for asterisk "Asterisk Ready" >/dev/null || true
    [ "$status" -eq 0 ] || return 1
    printf '%s\n' "$app_log" | found '^path chosen ' \
        || { printf '  Asterisk never nominated a pair on the lite end\n'; return 1; }
    printf '%s\n' "$app_log" | found '^dtmf #' \
        || { printf '  it never heard the "#" the dialplan sends\n'; return 1; }
    printf '%s\n' "$app_log" | found -E '^ended .*packets_received=[1-9]' \
        || { printf '  it heard no audio\n'; return 1; }
    printf '%s\n' "$app_log" | found -E '^ended .*packets_sent=[1-9]' \
        || { printf '  it sent no audio back\n'; return 1; }
    # a fifth of a second of Asterisk's audio, which a packet or two sent
    # before its checks finished cannot reach
    via_ice=$(printf '%s\n' "$rtp_log" | grep -c 'Sent RTP packet to .*(via ICE)')
    [ "$via_ice" -ge 10 ] \
        || { printf '  Asterisk sent %s packet(s) through ICE: its checks never succeeded\n' \
            "$via_ice"; return 1; }
}

# 8.4.13's steps through the C ABI where the stack under test is the one
# called or asked rather than the one calling: `harness-c listen`
# (interop/harness-c's own run_listen) in a container on the lab network, at
# port 5060 of its own address there, with SIPRAL_REFERRALS and SIPRAL_ICE
# shaping its stack, and the Rust harness reaching it. Its account is the
# lab's own at Asterisk, never registered: a referral it takes calls through
# Asterisk as every call the account places does.
C_LISTENER_NAME=sipral-lab-c-listener
start_c_listener() {
    local referrals="$1" ice="$2" beside tries
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    docker rm -f "$C_LISTENER_NAME" >/dev/null 2>&1
    docker run -d --name "$C_LISTENER_NAME" --network "$LAB_NETWORK" \
        -e LD_LIBRARY_PATH=/lib-sipral \
        -e "SIPRAL_REFERRALS=$referrals" -e "SIPRAL_ICE=$ice" \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS_C:/harness-c:ro" \
        -v "$beside:/lib-sipral:ro" \
        debian:trixie-slim /harness-c listen asterisk 5060 >/dev/null \
        || { printf '  could not start the C listener\n'; return 1; }
    tries=0
    until docker logs "$C_LISTENER_NAME" 2>&1 | found '^waiting for a call or a referral'; do
        tries=$((tries + 1))
        if [ "$(docker inspect -f '{{.State.Running}}' "$C_LISTENER_NAME" 2>/dev/null)" != true ] \
            || [ "$tries" -ge 30 ]; then
            printf '  the C listener never came up\n'
            docker logs "$C_LISTENER_NAME" 2>&1 | tail -20
            docker rm -f "$C_LISTENER_NAME" >/dev/null 2>&1
            return 1
        fi
        sleep 1
    done
}

# Where the listener is on the lab network, for the harness to reach.
c_listener_address() {
    docker inspect -f \
        "{{with index .NetworkSettings.Networks \"$LAB_NETWORK\"}}{{.IPAddress}}{{end}}" \
        "$C_LISTENER_NAME"
}

# Wait up to $1 seconds for the listener to finish with its call, then print
# what it said.
c_listener_log() {
    local tries=0
    until docker logs "$C_LISTENER_NAME" 2>&1 | found -E '^(ended |nothing arrived|referral lapsed)'; do
        tries=$((tries + 1))
        [ "$tries" -ge "$1" ] && break
        sleep 1
    done
    docker logs "$C_LISTENER_NAME" 2>&1
}

# What the listener said, indented, and the container gone.
stop_c_listener() {
    docker logs "$C_LISTENER_NAME" 2>&1 | sed 's/^/    c      /'
    docker rm -f "$C_LISTENER_NAME" >/dev/null 2>&1
}

# The Rust harness, as the switchboard that sends a REFER from outside any
# call (interop/harness/src/referral.rs), at the listener: `flow` is
# `referraloff` or `referral`, and the extension it asks for is Asterisk's
# echo, 9008.
refer_the_listener() {
    local flow="$1" address
    address=$(c_listener_address)
    lab_run "the harness's REFER to the C listener" $((LAB_START_S + LAB_CALL_S)) \
        --network "$LAB_NETWORK" \
        -e "SIPRAL_FLOWS=$flow" \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS:/harness:ro" \
        debian:trixie-slim /harness "$address" 5060 "sip:9008@asterisk"
}

# A stack that was never told to take referrals: the REFER is refused 403
# and the program driving the stack never hears of it.
referral_refused_flow() {
    local status log
    start_c_listener off off || return 1
    refer_the_listener referraloff
    status=$?
    log=$(docker logs "$C_LISTENER_NAME" 2>&1)
    stop_c_listener
    [ "$status" -eq 0 ] || return 1
    if printf '%s\n' "$log" | found '^referral asked'; then
        printf '  the program heard a referral its stack was never told to take\n'
        return 1
    fi
}

# A stack told to take them: the program hears the referral, takes it, and
# the call it places reaches Asterisk's echo -- the switchboard is told 202,
# then 100 and 200 in `message/sipfrag`, and the program hears its own tone
# come back.
referral_taken_flow() {
    local status log audible
    start_c_listener on off || return 1
    refer_the_listener referral
    status=$?
    log=$(c_listener_log 15)
    stop_c_listener
    [ "$status" -eq 0 ] || return 1
    printf '%s\n' "$log" | found '^referral taken: ok$' \
        || { printf '  the program never took the referral\n'; return 1; }
    audible=$(printf '%s\n' "$log" | sed -n 's/^ended .*audible=\([0-9]*\).*/\1/p')
    [ "${audible:-0}" -ge 25 ] \
        || { printf '  the call the referral placed heard %s audible frame(s) of the echo\n' \
            "${audible:-no}"; return 1; }
}

# ICE-lite through the C ABI: the listener's stack under SIPRAL_ICE_LITE,
# called by the Rust harness as the full agent a WebRTC gateway would be,
# requiring ICE -- interop/harness/src/ice_lite.rs's own flow, pointed at the
# C listener instead of `headless-socket-agent --ice-lite`. The listener
# echoes what it hears, which is the tone the harness judges the path by.
ice_lite_c_flow() {
    local address status log
    start_c_listener off lite || return 1
    address=$(c_listener_address)
    lab_run "the harness's call to the ICE-lite C listener" $((LAB_START_S + LAB_CALL_S)) \
        --network "$LAB_NETWORK" \
        -e SIPRAL_FLOWS=icelite \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS:/harness:ro" \
        debian:trixie-slim /harness "$address" 5060 agent
    status=$?
    log=$(c_listener_log 10)
    stop_c_listener
    [ "$status" -eq 0 ] || return 1
    printf '%s\n' "$log" | found '^path chosen' \
        || { printf '  the lite end never took a nominated pair\n'; return 1; }
    printf '%s\n' "$log" | found -E '^ended packets_sent=[1-9]' \
        || { printf '  the lite end sent no audio on the pair\n'; return 1; }
}

# 8.6.16's step: two stacks, each behind a NAT of its own, completing full
# ICE on the server-reflexive candidates coturn gave them
# (interop/harness/src/ice_nat.rs). The Rust harness twice, as caller on
# `inside` behind natbox and as callee on `inside2` behind natbox2, both
# requiring ICE. The callee's NAT forwards its SIP port -- signalling is not
# what this proves -- and nothing else: its media is reachable only through
# the hole its own checks punch. Both halves print how long ICE took, and the
# caller fails a path that does not end at the callee's NAT.
ICE_CALLEE_NAME=sipral-lab-ice-callee
ice_nat_flow() {
    nat_pair_up -f compose.yaml || return 1
    printf '  caller behind %s, callee behind %s (%s outside), STUN at %s:3478\n' \
        "$NAT_PAIR_GATEWAY" "$NAT_PAIR_GATEWAY2" "$NAT_PAIR_OUTSIDE2" "$NAT_PAIR_COTURN"
    nat_pair_call
    local status=$?
    nat_pair_down -f compose.yaml
    return "$status"
}

# coturn and the two NATs, up, with their addresses read into NAT_PAIR_*:
# the compose files to layer are the arguments, which is how the relay step
# below puts interop/turn's override over the lab's own coturn.
nat_pair_up() {
    local project="${COMPOSE_PROJECT_NAME:-sipral-interop}"
    ( cd interop && docker compose "$@" --profile nat up -d --build coturn natbox natbox2 ) >/dev/null 2>&1 \
        || { printf '  could not start coturn and the two NATs\n'; return 1; }
    wait_for natbox "nat: masquerading out of" required nat || return 1
    wait_for natbox2 "nat: masquerading out of" required nat || return 1
    wait_for coturn "Listener address to use" optional nat || true

    NAT_PAIR_BOX=$(cd interop && docker compose --profile nat ps -q natbox)
    NAT_PAIR_BOX2=$(cd interop && docker compose --profile nat ps -q natbox2)
    local coturn
    coturn=$(cd interop && docker compose --profile nat ps -q coturn)
    NAT_PAIR_GATEWAY=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"${project}_inside\"}}{{.IPAddress}}{{end}}" \
        "$NAT_PAIR_BOX")
    NAT_PAIR_GATEWAY2=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"${project}_inside2\"}}{{.IPAddress}}{{end}}" \
        "$NAT_PAIR_BOX2")
    NAT_PAIR_OUTSIDE=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"${project}_lab\"}}{{.IPAddress}}{{end}}" \
        "$NAT_PAIR_BOX")
    NAT_PAIR_OUTSIDE2=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"${project}_lab\"}}{{.IPAddress}}{{end}}" \
        "$NAT_PAIR_BOX2")
    NAT_PAIR_COTURN=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"${project}_lab\"}}{{.IPAddress}}{{end}}" \
        "$coturn")
    if [ -z "$NAT_PAIR_GATEWAY" ] || [ -z "$NAT_PAIR_GATEWAY2" ] || [ -z "$NAT_PAIR_OUTSIDE" ] \
        || [ -z "$NAT_PAIR_OUTSIDE2" ] || [ -z "$NAT_PAIR_COTURN" ]; then
        printf '  could not read the addresses: NATs %s and %s (%s and %s outside), coturn %s\n' \
            "${NAT_PAIR_GATEWAY:-?}" "${NAT_PAIR_GATEWAY2:-?}" "${NAT_PAIR_OUTSIDE:-?}" \
            "${NAT_PAIR_OUTSIDE2:-?}" "${NAT_PAIR_COTURN:-?}"
        nat_pair_down "$@"
        return 1
    fi
}

nat_pair_down() {
    ( cd interop && docker compose "$@" --profile nat rm -sf coturn natbox natbox2 ) >/dev/null 2>&1
}

# One call across the pair nat_pair_up started: the Rust harness as callee
# on `inside2` behind natbox2 and as caller on `inside` behind natbox, both
# requiring ICE, with the arguments as extra `docker run` options for both
# (the relay step's TURN server and credential; expanded as ${1+"$@"}, since
# bash 3.2 calls a bare "$@" with no arguments unbound under `set -u`). The
# callee's NAT forwards its SIP port -- signalling is not what this proves --
# and nothing else. Both halves' output is printed; the status is 0 only
# when both passed, and LAB_RUN_TIMED_OUT when the caller ran past the
# wall-clock lab_run gave it -- one call and its start -- and was stopped. NAT_PAIR_CALLER=c, set for the call, places it from the
# C harness instead (interop/harness-c's own FLOW_ICE_NAT, the same flow key
# and the same variables), with the Rust harness still answering; with
# NAT_PAIR_CALLER_TURN=1 as well, that caller alone is given the relay
# step's TURN server and credential. NAT_PAIR_CALLER=python, kotlin, dotnet
# or swift places it instead from that binding's own idiomatic layer --
# bindings/python/examples/agent.py's run_direct_call,
# bindings/kotlin/examples/Agent.kt's runDirectCall,
# bindings/dotnet/samples/Sipral.Sample.Agent/Program.cs's
# RunDirectCallAsync, bindings/swift/Sources/SipralLabAgent/main.swift's
# runDirectCall -- SIPRAL_PEER_HOST/_PORT naming the callee directly, no
# registrar, the same shape `docs/08-ffi.md`'s "An account with no
# registrar never registers" gives a trunk -- proving each idiomatic layer
# takes TURN and ICE the way an application actually would, not only the
# harnesses written for this lab.
nat_pair_call() {
    local project="${COMPOSE_PROJECT_NAME:-sipral-interop}"
    local callee callee_status status=0 tries=0 beside
    local -a caller_only=()
    local turn_port=3478
    # TURN over TLS is 5349, the port the "turns" scheme implies (RFC 8656
    # §4.1); TCP shares 3478 with UDP
    [ "${NAT_PAIR_TURN_TRANSPORT:-udp}" = tls ] && turn_port=5349
    if [ -n "${NAT_PAIR_CALLER_TURN:-}" ]; then
        caller_only=(-e "SIPRAL_TURN_SERVER=$NAT_PAIR_COTURN:$turn_port"
            -e "SIPRAL_TURN_USER=$SIPRAL_TURN_USER"
            -e "SIPRAL_TURN_PASSWORD=$SIPRAL_TURN_PASSWORD"
            -e "SIPRAL_TURN_TRANSPORT=${NAT_PAIR_TURN_TRANSPORT:-udp}"
            -e "SIPRAL_TURN_NAME=$TURN_TLS_NAME"
            -e SIPRAL_TURN_CA=/turn-certs/turn.pem
            -v "$SIPRAL_TURN_CERTS:/turn-certs:ro")
    fi
    docker rm -f "$ICE_CALLEE_NAME" >/dev/null 2>&1
    docker run -d --name "$ICE_CALLEE_NAME" --network "${project}_inside2" \
        --cap-add NET_ADMIN \
        -e SIPRAL_FLOWS=iceanswer \
        -e "SIPRAL_STUN_SERVER=$NAT_PAIR_COTURN:3478" \
        -e "SIPRAL_CONTACT=$NAT_PAIR_OUTSIDE2:5060" \
        ${1+"$@"} \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS:/harness:ro" \
        sipral-lab-nat sh -c "
            ip route replace default via $NAT_PAIR_GATEWAY2 || exit 1
            exec /harness $NAT_PAIR_COTURN 3478 callee" >/dev/null \
        || status=1
    callee=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"${project}_inside2\"}}{{.IPAddress}}{{end}}" \
        "$ICE_CALLEE_NAME" 2>/dev/null)
    # the forward: SIP arriving at the second NAT from the lab network goes
    # to the callee, and only SIP. Replaced rather than added, so a second
    # call across the same pair forwards to its own callee and not to the
    # first one's address as well
    if [ "$status" -eq 0 ] && [ -n "$callee" ]; then
        docker exec "$NAT_PAIR_BOX2" sh -c "
            lab=\$(ip -o route get $NAT_PAIR_COTURN | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p')
            iptables -t nat -F PREROUTING
            iptables -t nat -I PREROUTING -i \"\$lab\" -p udp --dport 5060 \
                -j DNAT --to-destination $callee:5060" \
            || { printf '  could not forward SIP to the callee\n'; status=1; }
    else
        printf '  could not start the callee\n'
        status=1
    fi
    until [ "$status" -ne 0 ] \
        || docker logs "$ICE_CALLEE_NAME" 2>&1 | found '^waiting for the call'; do
        tries=$((tries + 1))
        if [ "$(docker inspect -f '{{.State.Running}}' "$ICE_CALLEE_NAME" 2>/dev/null)" != true ] \
            || [ "$tries" -ge 30 ]; then
            printf '  the callee never came up\n'
            status=1
            break
        fi
        sleep 1
    done

    if [ "$status" -eq 0 ] && [ "${NAT_PAIR_CALLER:-rust}" = c ]; then
        beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
        lab_run "the C harness's call across the NAT pair" $((LAB_START_S + LAB_CALL_S)) \
            --network "${project}_inside" \
            --cap-add NET_ADMIN \
            -e SIPRAL_FLOWS=icenat \
            -e "SIPRAL_STUN_SERVER=$NAT_PAIR_COTURN:3478" \
            ${1+"$@"} \
            ${caller_only[@]+"${caller_only[@]}"} \
            -e LD_LIBRARY_PATH=/lib-sipral \
            ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
            -v "$HARNESS_C:/harness-c:ro" \
            -v "$beside:/lib-sipral:ro" \
            sipral-lab-nat sh -c "
                ip route replace default via $NAT_PAIR_GATEWAY || exit 1
                exec /harness-c $NAT_PAIR_OUTSIDE2 5060 callee"
        status=$?
    elif [ "$status" -eq 0 ] && [ "${NAT_PAIR_CALLER:-rust}" = python ]; then
        if [ -z "$HARNESS_C" ]; then
            # the library the Python bindings load rides beside the C
            # harness (the build step both need is the same one), the same
            # gate python_agent() already takes
            printf '  note  no C harness built, so there is no libsipral for the Python agent -- skipped\n'
            status=1
        else
            beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
            # `inside` is a Docker `internal` network (interop/compose.yaml)
            # with no route out to anywhere -- an `apt-get` from behind it
            # can never reach a mirror, so Python and cffi are built into
            # the image ahead of time instead (interop/nat/Dockerfile.python's
            # own reasoning). Built once per run and cached by Docker after
            # that, the same way natbox/natbox2's own image is.
            docker build -q -f "$ROOT/interop/nat/Dockerfile.python" \
                -t sipral-lab-nat-python "$ROOT/interop/nat" >/dev/null \
                || { printf '  could not build the Python agent'"'"'s own NAT image\n'; status=1; }
        fi
        if [ "$status" -eq 0 ]; then
            lab_run "the Python agent's call across the NAT pair" $((LAB_START_S + LAB_CALL_S)) \
                --network "${project}_inside" \
                --cap-add NET_ADMIN \
                -e "SIPRAL_STUN_SERVER=$NAT_PAIR_COTURN:3478" \
                -e "SIPRAL_PEER_HOST=$NAT_PAIR_OUTSIDE2" -e SIPRAL_PEER_PORT=5060 \
                -e SIPRAL_ICE=required \
                -e "SIPRAL_PATIENCE_MS=$LAB_PATIENCE_MS" -e "SIPRAL_DWELL_MS=$LAB_DWELL_MS" \
                -e SIPRAL_LIBRARY=/lib-sipral -e PYTHONPATH=/python \
                ${1+"$@"} \
                ${caller_only[@]+"${caller_only[@]}"} \
                -v "$beside:/lib-sipral:ro" \
                -v "$ROOT/bindings/python:/python:ro" \
                sipral-lab-nat-python sh -c "
                    ip route replace default via $NAT_PAIR_GATEWAY || exit 1
                    exec python3 -u /python/examples/agent.py"
            status=$?
        fi
    elif [ "$status" -eq 0 ] && [ "${NAT_PAIR_CALLER:-rust}" = kotlin ]; then
        # bindings/kotlin/examples/Agent.kt's own runDirectCall, the same
        # shape as the Python branch above: interop/nat/Dockerfile.kotlin,
        # built FROM interop/kotlin's own image, which already carries the
        # JDK and a C compiler the JNI shim needs -- `ip` is the one thing
        # it does not, and `inside` has no route out to anywhere at all, so
        # that is built in ahead of time too (interop/nat/Dockerfile.python's
        # own reasoning). Built once per run and cached by Docker after that.
        if [ -z "${KOTLIN_AGENT_JAR:-}" ] || [ -z "${KOTLIN_STDLIB_JAR:-}" ] \
            || [ -z "${KOTLIN_COROUTINES_JAR:-}" ]; then
            printf '  note  no Kotlin agent jar built; see bindings/kotlin/README.md -- skipped\n'
            status=1
        elif [ -z "$HARNESS_C" ]; then
            printf '  note  no C harness built, so there is no libsipral for the Kotlin agent -- skipped\n'
            status=1
        else
            beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
            docker build -q -t sipral-lab-kotlin "$ROOT/interop/kotlin" >/dev/null \
                && docker build -q -f "$ROOT/interop/nat/Dockerfile.kotlin" \
                    -t sipral-lab-nat-kotlin "$ROOT/interop/nat" >/dev/null \
                || { printf '  could not build the Kotlin agent'"'"'s own NAT image\n'; status=1; }
        fi
        if [ "$status" -eq 0 ]; then
            lab_run "the Kotlin agent's call across the NAT pair" $((LAB_START_KOTLIN_S + LAB_CALL_S)) \
                --network "${project}_inside" \
                --cap-add NET_ADMIN \
                -e "SIPRAL_STUN_SERVER=$NAT_PAIR_COTURN:3478" \
                -e "SIPRAL_PEER_HOST=$NAT_PAIR_OUTSIDE2" -e SIPRAL_PEER_PORT=5060 \
                -e SIPRAL_ICE=required \
                -e "SIPRAL_PATIENCE_MS=$LAB_PATIENCE_MS" -e "SIPRAL_DWELL_MS=$LAB_DWELL_MS" \
                ${1+"$@"} \
                ${caller_only[@]+"${caller_only[@]}"} \
                -v "$beside:/lib-sipral:ro" \
                -v "$ROOT/bindings/c/include:/sipral-include:ro" \
                -v "$ROOT/bindings/kotlin/sipral/src/main/jni:/sipral-jni:ro" \
                -v "$KOTLIN_AGENT_JAR:/kotlin/sipral-kotlin.jar:ro" \
                -v "$KOTLIN_STDLIB_JAR:/kotlin/kotlin-stdlib.jar:ro" \
                -v "$KOTLIN_COROUTINES_JAR:/kotlin/kotlinx-coroutines.jar:ro" \
                sipral-lab-nat-kotlin sh -c "
                    set -e
                    ip route replace default via $NAT_PAIR_GATEWAY || exit 1
                    cc -std=c11 -Wall -shared -fPIC \
                        -I\"\$JAVA_HOME/include\" -I\"\$JAVA_HOME/include/linux\" -I/sipral-include \
                        -o /tmp/libsipral_jni.so \
                        /sipral-jni/sipral_jni.c /sipral-jni/idiomatic_media.c \
                        -L/lib-sipral -lsipral_ffi -Wl,-rpath,/lib-sipral
                    exec java -Djava.library.path=/tmp \
                        -cp /kotlin/sipral-kotlin.jar:/kotlin/kotlin-stdlib.jar:/kotlin/kotlinx-coroutines.jar \
                        org.sipral.examples.AgentKt"
            status=$?
        fi
    elif [ "$status" -eq 0 ] && [ "${NAT_PAIR_CALLER:-rust}" = dotnet ]; then
        # Program.cs's own RunDirectCallAsync, the same shape as the Python
        # branch above: interop/nat/Dockerfile.dotnet, the SDK image with
        # `ip` added -- `inside` has no route out to anywhere at all, so
        # that is built in ahead of time too (interop/nat/Dockerfile.python's
        # own reasoning). Neither project under bindings/dotnet names a
        # NuGet package, so `dotnet run` itself still touches nothing
        # outside the container once it is there. Built once per run and
        # cached by Docker after that.
        if [ -z "$HARNESS_C" ]; then
            printf '  note  no C harness built, so there is no libsipral for the .NET agent -- skipped\n'
            status=1
        else
            beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
            [ -s "$beside/libsipral_ffi.so" ] \
                || { printf '  no libsipral_ffi.so beside the C harness\n'; status=1; }
            docker build -q -f "$ROOT/interop/nat/Dockerfile.dotnet" \
                -t sipral-lab-nat-dotnet "$ROOT/interop/nat" >/dev/null \
                || { printf '  could not build the .NET agent'"'"'s own NAT image\n'; status=1; }
        fi
        if [ "$status" -eq 0 ]; then
            lab_run "the .NET agent's call across the NAT pair" $((LAB_START_DOTNET_S + LAB_CALL_S)) \
                --network "${project}_inside" \
                --cap-add NET_ADMIN \
                -e "SIPRAL_STUN_SERVER=$NAT_PAIR_COTURN:3478" \
                -e "SIPRAL_PEER_HOST=$NAT_PAIR_OUTSIDE2" -e SIPRAL_PEER_PORT=5060 \
                -e SIPRAL_ICE=required \
                -e "SIPRAL_PATIENCE_MS=$LAB_PATIENCE_MS" -e "SIPRAL_DWELL_MS=$LAB_DWELL_MS" \
                -e SIPRAL_LIBRARY=/lib-sipral/libsipral_ffi.so \
                -e DOTNET_CLI_TELEMETRY_OPTOUT=1 -e DOTNET_NOLOGO=1 \
                ${1+"$@"} \
                ${caller_only[@]+"${caller_only[@]}"} \
                -v "$beside:/lib-sipral:ro" \
                -v "$ROOT/bindings/dotnet:/src-dotnet:ro" \
                sipral-lab-nat-dotnet sh -c '
                    cp -r /src-dotnet /dotnet
                    cd /dotnet/samples/Sipral.Sample.Agent
                    ip route replace default via '"$NAT_PAIR_GATEWAY"' || exit 1
                    exec dotnet run -c Release --no-launch-profile'
            status=$?
        fi
    elif [ "$status" -eq 0 ] && [ "${NAT_PAIR_CALLER:-rust}" = swift ]; then
        # SipralLabAgent's own runDirectCall, the same shape as the Python
        # branch above: the same $SWIFT_AGENT binary swift_agent() runs, and
        # the same mounts -- its own -rpath is the absolute path they land
        # on -- so nothing is built again here but
        # interop/nat/Dockerfile.swift, the same `swift:6.1` with `ip` added
        # -- `inside` has no route out to anywhere at all, so that is built
        # in ahead of time too (interop/nat/Dockerfile.python's own
        # reasoning). Built once per run and cached by Docker after that.
        if [ -z "$SWIFT_AGENT" ]; then
            printf '  note  no Swift lab agent built; that step is skipped\n'
            status=1
        elif ! docker build -q -f "$ROOT/interop/nat/Dockerfile.swift" \
                -t sipral-lab-nat-swift "$ROOT/interop/nat" >/dev/null; then
            printf '  could not build the Swift agent'"'"'s own NAT image\n'
            status=1
        else
            lab_run "the Swift agent's call across the NAT pair" $((LAB_START_S + LAB_CALL_S)) \
                --network "${project}_inside" \
                --cap-add NET_ADMIN \
                -e "SIPRAL_STUN_SERVER=$NAT_PAIR_COTURN:3478" \
                -e "SIPRAL_PEER_HOST=$NAT_PAIR_OUTSIDE2" -e SIPRAL_PEER_PORT=5060 \
                -e SIPRAL_ICE=required \
                -e "SIPRAL_PATIENCE_MS=$LAB_PATIENCE_MS" -e "SIPRAL_DWELL_MS=$LAB_DWELL_MS" \
                ${1+"$@"} \
                ${caller_only[@]+"${caller_only[@]}"} \
                -v "$ROOT":/work:ro -v "${SWIFT_LIB_DIR:-$ROOT/target/release}":/work/target/release:ro \
                sipral-lab-nat-swift sh -c "
                    ip route replace default via $NAT_PAIR_GATEWAY || exit 1
                    exec /work/bindings/.build/release/SipralLabAgent"
            status=$?
        fi
    elif [ "$status" -eq 0 ]; then
        lab_run "the Rust harness's call across the NAT pair" $((LAB_START_S + LAB_CALL_S)) \
            --network "${project}_inside" \
            --cap-add NET_ADMIN \
            -e SIPRAL_FLOWS=icenat \
            -e "SIPRAL_STUN_SERVER=$NAT_PAIR_COTURN:3478" \
            ${1+"$@"} \
            ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
            -v "$HARNESS:/harness:ro" \
            sipral-lab-nat sh -c "
                ip route replace default via $NAT_PAIR_GATEWAY || exit 1
                exec /harness $NAT_PAIR_OUTSIDE2 5060 callee"
        status=$?
    fi
    # the callee's own patience for the call is two of them (ice_nat.rs's
    # CALLEE_PATIENCE); past that it is stuck, and only it is removed
    callee_status=$(timeout $((LAB_CALL_S * 2)) docker wait "$ICE_CALLEE_NAME" 2>/dev/null || echo 1)
    docker logs "$ICE_CALLEE_NAME" 2>&1 | sed 's/^/    callee  /'
    docker rm -f "$ICE_CALLEE_NAME" >/dev/null 2>&1
    [ "$status" -ne "$LAB_RUN_TIMED_OUT" ] || return "$LAB_RUN_TIMED_OUT"
    [ "$status" -eq 0 ] || return 1
    [ "$callee_status" = 0 ] || { printf '  the callee did not pass\n'; return 1; }
}

# 8.5.5's relay step: the same two stacks behind the same two NATs, told
# this time to drop every datagram between them but SIP -- natbox and natbox2
# forward nothing addressed to the other's outside address, or from it,
# unless it is port 5060 -- so that neither host candidates (no route) nor
# server-reflexive ones (dropped) connect, and coturn turned into a TURN
# server with long-term credentials by interop/turn's override, which no
# other step sees. First the block is proved: the call from the step above,
# STUN and nothing else, has to find no path. Then each end allocates a
# relay (interop/harness/src/ice_nat.rs, `SIPRAL_TURN_*`), and the call has
# to complete with the tone crossing through coturn both ways, the caller
# failing a path that does not go through it. Last, coturn's own log has to
# show both allocations given back when the call ended rather than left to
# lapse.
#
# Then the same two calls again with the C harness as the caller (8.5.5's
# relay through the C ABI): the TURN server, user and password set through
# sipral_stack_config_t, the relay seen as SIPRAL_EVENT_KIND_NAT_RELAY, the
# path judged by where the library addresses the audio, and the Refresh of
# lifetime zero read off whichever queue hands it out -- with the Rust harness
# still answering, so the relay is proved from both drivers on every run of
# the word. Without TURN that call has to find no path too, and coturn's log
# has to count its two allocations as given back on top of the first two.
# Then the C caller alone is given TURN: the only path left runs through its
# own relay, and its one allocation has to be given back as well. Last, the
# same with the caller's NAT dropping every datagram to or from coturn, the
# relay reached over TCP.
#
# Then the same two calls again from each idiomatic binding in turn --
# Python, Kotlin, .NET, Swift -- each placing the call itself through its
# own `Stack`/`Client`/`SipralStack`, not through a harness written for this
# lab, so the same claim is proved from every layer an application would
# actually use; and then, the caller's NAT dropping every datagram to or
# from coturn, that binding's caller alone reaching its relay over the
# connection it opens itself: Python over TLS, Kotlin and .NET over TCP and
# over TLS, Swift over TCP only -- its TLS is Network.framework's, which only
# Apple's platforms have, and the lab's containers are Linux. Each is
# skipped, rather than failed, when its own build step above found nothing
# to run -- except under `scripts/lab.sh turn`, asked for by name, where a
# skip fails the run instead of passing silently.
#
# Last, the same pair carries a call Kamailio forks to two phones behind the
# second NAT (turn_forked, below), every end on a relay and both branches
# carrying media before one answers.
#
# coturn's log is the container's whole life, so every relay allocated so
# far is counted in TURN_ALLOCATED as the steps go, and each step's
# turn_given_back asks for that many, whichever steps before it ran.
ice_turn_flow() {
    local status=0 caller
    TURN_ALLOCATED=0
    SIPRAL_TURN_USER=sipral-lab
    SIPRAL_TURN_PASSWORD=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
    export SIPRAL_TURN_USER SIPRAL_TURN_PASSWORD
    turn_certificate || return 1
    nat_pair_up -f compose.yaml -f turn/compose.override.yaml || { rm -rf "$SIPRAL_TURN_CERTS"; return 1; }
    printf '  caller behind %s (%s outside), callee behind %s (%s outside), TURN at %s:3478\n' \
        "$NAT_PAIR_GATEWAY" "$NAT_PAIR_OUTSIDE" "$NAT_PAIR_GATEWAY2" "$NAT_PAIR_OUTSIDE2" \
        "$NAT_PAIR_COTURN"
    docker exec "$NAT_PAIR_BOX" sh -c "
        iptables -I FORWARD -d $NAT_PAIR_OUTSIDE2 -p udp ! --dport 5060 -j DROP
        iptables -I FORWARD -s $NAT_PAIR_OUTSIDE2 -p udp ! --sport 5060 -j DROP" \
        && docker exec "$NAT_PAIR_BOX2" sh -c "
        iptables -I FORWARD -s $NAT_PAIR_OUTSIDE -p udp ! --dport 5060 -j DROP
        iptables -I FORWARD -d $NAT_PAIR_OUTSIDE -p udp ! --sport 5060 -j DROP" \
        || { printf '  could not block the path between the two NATs\n'; status=1; }

    if [ "$status" -eq 0 ]; then
        printf '  without TURN: the call has to find no path\n'
        turn_blocked "" || status=1
    fi
    if [ "$status" -eq 0 ]; then
        printf '  with TURN: the call has to go through coturn\n'
        turn_both_ends "" || status=1
    fi
    if [ "$status" -eq 0 ] && [ -z "$HARNESS_C" ]; then
        if [ "$WANT" = turn ]; then
            # asked for by name, the relay step proves both drivers or fails
            printf '  there is no C harness to place the relayed call through the C ABI\n'
            status=1
        else
            printf '  note  no C harness, so the relayed call through the C ABI is skipped with the other C flows\n'
        fi
    elif [ "$status" -eq 0 ]; then
        printf '  without TURN, through the C ABI: the call has to find no path\n'
        turn_blocked c "through the C ABI" || status=1
        if [ "$status" -eq 0 ]; then
            printf '  with TURN, through the C ABI: the call has to go through coturn\n'
            turn_both_ends c || status=1
        fi
        # with both ends relayed, ICE settles on the callee's relay and the
        # caller's own goes back unused; with the caller's alone, the block
        # leaves no path but through it, so the tone crosses what the C ABI
        # wraps and unwraps for the TURN server itself
        if [ "$status" -eq 0 ]; then
            printf '  with TURN at the C caller alone: the call has to go through its own relay\n'
            NAT_PAIR_CALLER=c NAT_PAIR_CALLER_TURN=1 nat_pair_call || status=1
        fi
        if [ "$status" -eq 0 ]; then
            TURN_ALLOCATED=$((TURN_ALLOCATED + 1))
            turn_given_back "$TURN_ALLOCATED" || status=1
        fi
        # and from behind a NAT that also drops every datagram to or from
        # coturn: the mapping asked over UDP goes unanswered, which the
        # harness requires as the proof that the block holds, and the only
        # relay there can be is one reached over TCP -- the connection the
        # library asks for, carrying the Allocate, the permission, the
        # channel, the tone both ways and the Refresh that gives it back
        [ "$status" -ne 0 ] || turn_over_stream c tcp C || status=1
    fi
    for caller in python kotlin dotnet swift; do
        [ "$status" -eq 0 ] || break
        turn_binding "$caller" || status=1
    done
    if [ "$status" -eq 0 ]; then
        printf '  forked through the proxy to two phones behind the NAT, every end relayed: media on both branches until one answers\n'
        turn_forked || status=1
    fi
    nat_pair_down -f compose.yaml -f turn/compose.override.yaml
    rm -rf "$SIPRAL_TURN_CERTS"
    unset SIPRAL_TURN_USER SIPRAL_TURN_PASSWORD SIPRAL_TURN_CERTS
    return "$status"
}

# The call a proxy forks, across the blocked pair (interop/harness/src/fork_ice.rs):
# two phones, the desk and the mobile, in one container behind the second
# NAT, each on a SIP port of its own the NAT forwards and each with a relay
# on coturn, registered at Kamailio as the one user interop/kamailio forks;
# the caller behind the first NAT, with a relay of its own, calls that user
# through the proxy. Neither side's container resolves the lab's names, so
# the proxy is handed to both by address, and as `kamailio` for the name it
# writes into Record-Route. Both phones ring with media, so both branches
# run ICE through the relays and carry the tone both ways before the mobile
# answers; the desk is cancelled, the caller keeps the mobile's branch and
# hangs up, and the three relays -- the caller's one, held by both of its
# branches, and each phone's -- have to be given back.
turn_forked() {
    local project="${COMPOSE_PROJECT_NAME:-sipral-interop}"
    local phones="${project}-fork-phones" proxy address status=0 placed phones_status tries=0
    proxy=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"${project}_lab\"}}{{.IPAddress}}{{end}}" \
        "$(cd interop && docker compose ps -q kamailio)" 2>/dev/null)
    [ -n "$proxy" ] || { printf '  could not read the proxy'"'"'s address\n'; return 1; }
    docker rm -f "$phones" >/dev/null 2>&1
    docker run -d --name "$phones" --network "${project}_inside2" \
        --cap-add NET_ADMIN \
        --add-host "kamailio:$proxy" \
        -e SIPRAL_FLOWS=forkiceanswer \
        -e "SIPRAL_STUN_SERVER=$NAT_PAIR_COTURN:3478" \
        -e "SIPRAL_CONTACT=$NAT_PAIR_OUTSIDE2" \
        -e "SIPRAL_TURN_SERVER=$NAT_PAIR_COTURN:3478" \
        -e "SIPRAL_TURN_USER=$SIPRAL_TURN_USER" \
        -e "SIPRAL_TURN_PASSWORD=$SIPRAL_TURN_PASSWORD" \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS:/harness:ro" \
        sipral-lab-nat sh -c "
            ip route replace default via $NAT_PAIR_GATEWAY2 || exit 1
            exec /harness $proxy 5060 forked" >/dev/null \
        || { printf '  could not start the phones\n'; return 1; }
    address=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"${project}_inside2\"}}{{.IPAddress}}{{end}}" \
        "$phones" 2>/dev/null)
    # the proxy reaches each phone at the port it registered as its contact
    # on the NAT's outside address (interop/harness/src/fork_ice.rs's
    # PHONE_PORTS), and nothing else is forwarded
    docker exec "$NAT_PAIR_BOX2" sh -c "
        lab=\$(ip -o route get $NAT_PAIR_COTURN | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p')
        iptables -t nat -F PREROUTING
        iptables -t nat -I PREROUTING -i \"\$lab\" -p udp --dport 5060 \
            -j DNAT --to-destination $address:5060
        iptables -t nat -I PREROUTING -i \"\$lab\" -p udp --dport 5062 \
            -j DNAT --to-destination $address:5062" \
        || { printf '  could not forward SIP to the phones\n'; status=1; }
    until [ "$status" -ne 0 ] \
        || docker logs "$phones" 2>&1 | found '^waiting for the call'; do
        tries=$((tries + 1))
        if [ "$(docker inspect -f '{{.State.Running}}' "$phones" 2>/dev/null)" != true ] \
            || [ "$tries" -ge 30 ]; then
            printf '  the phones never registered\n'
            status=1
            break
        fi
        sleep 1
    done
    placed=1
    if [ "$status" -eq 0 ]; then
        lab_run "the forked call's caller" $((LAB_START_S + LAB_CALL_S)) \
            --network "${project}_inside" \
            --cap-add NET_ADMIN \
            --add-host "kamailio:$proxy" \
            -e SIPRAL_FLOWS=forkice \
            -e "SIPRAL_STUN_SERVER=$NAT_PAIR_COTURN:3478" \
            -e "SIPRAL_TURN_SERVER=$NAT_PAIR_COTURN:3478" \
            -e "SIPRAL_TURN_USER=$SIPRAL_TURN_USER" \
            -e "SIPRAL_TURN_PASSWORD=$SIPRAL_TURN_PASSWORD" \
            ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
            -v "$HARNESS:/harness:ro" \
            sipral-lab-nat sh -c "
                ip route replace default via $NAT_PAIR_GATEWAY || exit 1
                exec /harness $proxy 5060 forked"
        placed=$?
    fi
    # the phones wait for the call for two of them at most, and then give
    # their bindings back; past that they are stuck, and only they go
    phones_status=$(timeout $((LAB_CALL_S * 2)) docker wait "$phones" 2>/dev/null || echo 1)
    docker logs "$phones" 2>&1 | sed 's/^/    callee  /'
    docker rm -f "$phones" >/dev/null 2>&1
    [ "$placed" -eq 0 ] || return 1
    [ "$phones_status" = 0 ] || { printf '  the phones did not pass\n'; return 1; }
    TURN_ALLOCATED=$((TURN_ALLOCATED + 3))
    turn_given_back "$TURN_ALLOCATED"
}

# The call across the blocked pair with no TURN anywhere, from the caller
# NAT_PAIR_CALLER=$1 names (empty for the Rust harness), which has to find
# no path: a call that connects is a block that does not hold, and a caller
# stopped for running past its time proved nothing either way. $2 is how
# that caller is named in what is printed.
turn_blocked() {
    local placed
    NAT_PAIR_CALLER="${1:-rust}" nat_pair_call
    placed=$?
    if [ "$placed" -eq 0 ]; then
        printf '  the call%s connected with the path between the NATs blocked: the block does not hold\n' \
            "${2:+ $2}"
        return 1
    fi
    [ "$placed" -ne "$LAB_RUN_TIMED_OUT" ]
}

# The call across the blocked pair with both ends given TURN over UDP, from
# the caller NAT_PAIR_CALLER=$1 names (empty for the Rust harness), and both
# relays given back after it.
turn_both_ends() {
    NAT_PAIR_CALLER="${1:-rust}" nat_pair_call \
        -e "SIPRAL_TURN_SERVER=$NAT_PAIR_COTURN:3478" \
        -e "SIPRAL_TURN_USER=$SIPRAL_TURN_USER" \
        -e "SIPRAL_TURN_PASSWORD=$SIPRAL_TURN_PASSWORD" \
        || return 1
    TURN_ALLOCATED=$((TURN_ALLOCATED + 2))
    turn_given_back "$TURN_ALLOCATED"
}

# The caller NAT_PAIR_CALLER=$1 names given TURN alone, over $2 (tcp or
# tls), with every datagram to or from coturn dropped at its NAT for the
# length of the call, and its one relay given back after it. $3 is how that
# caller is named in what is printed.
turn_over_stream() {
    local caller="$1" over="$2" said="$3" placed=0 upper how
    upper=$(printf '%s' "$over" | tr '[:lower:]' '[:upper:]')
    how="the connection"
    [ "$over" = tls ] && how="TLS"
    printf '  with TURN over %s at the %s caller alone, UDP to coturn dropped at its NAT: the call has to go through its relay over %s\n' \
        "$upper" "$said" "$how"
    turn_udp_dropped -I || return 1
    NAT_PAIR_CALLER="$caller" NAT_PAIR_CALLER_TURN=1 NAT_PAIR_TURN_TRANSPORT="$over" nat_pair_call \
        || placed=1
    turn_udp_dropped -D
    [ "$placed" -eq 0 ] || return 1
    TURN_ALLOCATED=$((TURN_ALLOCATED + 1))
    turn_given_back "$TURN_ALLOCATED"
}

# One idiomatic binding's relayed calls, placed through its own layer by
# NAT_PAIR_CALLER=$1: the pair with no TURN and with TURN at both ends, then
# its caller alone over each stream transport its platform has here. A
# binding whose build step found nothing to run is noted and skipped, or,
# under `scripts/lab.sh turn`, fails the run.
turn_binding() {
    local caller="$1" said missing="" over
    local -a streams=()
    case "$caller" in
    python)
        said="Python bindings"
        streams=(tls)
        [ -n "$HARNESS_C" ] || missing="no C harness, so there is no libsipral for the relayed call through the Python bindings"
        ;;
    kotlin)
        said="Kotlin bindings"
        streams=(tcp tls)
        if [ -z "${KOTLIN_AGENT_JAR:-}" ] || [ -z "${KOTLIN_STDLIB_JAR:-}" ] \
            || [ -z "${KOTLIN_COROUTINES_JAR:-}" ] || [ -z "$HARNESS_C" ]; then
            missing="no Kotlin agent jar built, or no C harness for the libsipral it loads, so there is no relayed call through the Kotlin bindings"
        fi
        ;;
    dotnet)
        said=".NET bindings"
        streams=(tcp tls)
        [ -n "$HARNESS_C" ] || missing="no C harness, so there is no libsipral for the relayed call through the .NET bindings"
        ;;
    swift)
        said="Swift bindings"
        streams=(tcp)
        [ -n "$SWIFT_AGENT" ] || missing="no Swift lab agent built, so there is no relayed call through the Swift bindings"
        ;;
    esac
    if [ -n "$missing" ]; then
        if [ "$WANT" = turn ]; then
            printf '  %s\n' "$missing"
            return 1
        fi
        printf '  note  %s -- skipped\n' "$missing"
        return 0
    fi
    printf '  without TURN, through the %s: the call has to find no path\n' "$said"
    turn_blocked "$caller" "through the $said" || return 1
    printf '  with TURN, through the %s: the call has to go through coturn\n' "$said"
    turn_both_ends "$caller" || return 1
    if [ "$caller" = swift ]; then
        printf '  note  the Swift layer'"'"'s TLS is Network.framework'"'"'s, which only Apple'"'"'s platforms have; this Linux container reaches the relay over TCP alone, and TLS is proved by its own TurnStreamTests on macOS\n'
    fi
    for over in "${streams[@]}"; do
        turn_over_stream "$caller" "$over" "${said% bindings}" || return 1
    done
}

# The name the relay step's TLS certificate is made for, and the one the
# clients check it against: coturn is reached by address, and a certificate
# for an address the lab hands out afresh on every run is one nobody could
# have checked beforehand.
TURN_TLS_NAME=turn.lab.sipral.test

# A key and a self-signed certificate for coturn's TLS listener, made for
# this run alone and thrown away after it, in the directory SIPRAL_TURN_CERTS
# names (interop/turn/compose.override.yaml mounts it). serverAuth is in it
# because Apple's TLS refuses a server certificate without it. Readable by
# coturn's own unprivileged user: the key protects a lab that lasts minutes.
turn_certificate() {
    SIPRAL_TURN_CERTS=$(mktemp -d)
    export SIPRAL_TURN_CERTS
    if ! openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
        -subj "/CN=$TURN_TLS_NAME" -addext "subjectAltName=DNS:$TURN_TLS_NAME" \
        -addext extendedKeyUsage=serverAuth \
        -keyout "$SIPRAL_TURN_CERTS/turn.key" -out "$SIPRAL_TURN_CERTS/turn.pem" >/dev/null 2>&1; then
        printf '  could not make the certificate for coturn'"'"'s TLS listener (openssl)\n'
        rm -rf "$SIPRAL_TURN_CERTS"
        return 1
    fi
    chmod 755 "$SIPRAL_TURN_CERTS"
    chmod 644 "$SIPRAL_TURN_CERTS/turn.key" "$SIPRAL_TURN_CERTS/turn.pem"
}

# At the caller's NAT, every datagram to or from coturn dropped (-I) or let
# through again (-D): the network TURN over TCP and TLS exists for (RFC 8656
# §3.1), for as long as the step through it runs.
turn_udp_dropped() {
    docker exec "$NAT_PAIR_BOX" sh -c "
        iptables $1 FORWARD -d $NAT_PAIR_COTURN -p udp -j DROP &&
        iptables $1 FORWARD -s $NAT_PAIR_COTURN -p udp -j DROP" \
        || { printf '  could not change what the NAT drops to and from coturn\n'; return 1; }
}

# What coturn --verbose has written so far for an allocation made
# ("allocation new") and for one a Refresh with a lifetime of zero took down
# ("allocation refreshed ... lifetime=0"): at least $1 of the former, and as
# many of the latter, every relay given back rather than lapsing. The
# permissions and the channel ("lifetime updated") are printed beside them,
# which is where the relayed path shows. The log is the container's whole
# life, so a second call's count includes the first's. Over TLS coturn
# writes the cipher right after the lifetime ("lifetime=0, cipher=..."), so
# the zero ends at a space or a comma.
turn_given_back() {
    local wanted="$1" allocations deleted said
    said=$( (cd interop && docker compose --profile nat logs --no-color coturn) 2>/dev/null )
    printf '%s\n' "$said" | grep 'allocation new,\|allocation refreshed,\|lifetime updated' \
        | tail -40 | sed 's/^/    coturn  /'
    allocations=$(printf '%s\n' "$said" | grep -c 'allocation new,')
    deleted=$(printf '%s\n' "$said" | grep -c 'allocation refreshed,.*lifetime=0[ ,]')
    printf '  coturn: %s allocation(s), %s given back\n' "$allocations" "$deleted"
    [ "$allocations" -ge "$wanted" ] && [ "$deleted" -ge "$allocations" ]
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
    lab_run "the harness over $profile" $((LAB_START_APT_S + 2 * (LAB_CALL_S + ${DWELL_MS:-2000} / 1000))) \
        --network "$LAB_NETWORK" \
        --cap-add NET_ADMIN \
        -e SIPRAL_REQUIRE_AUDIO=1 -e SIPRAL_FLOWS=register,call \
        -e SIPRAL_AUDIO_GATE=1 \
        -e "SIPRAL_DWELL_MS=${DWELL_MS:-2000}" \
        -e "SIPRAL_PATIENCE_MS=$(( ${DWELL_MS:-2000} + 20000 ))" \
        -e "NETEM=$NETEM" -e "REQUIRE=$REQUIRE" -e "DURING=$DURING" \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
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

# An hour on six calls to Asterisk's echo (interop/harness/src/drift.rs):
# the drift a real pair of clocks makes, which the lab's two ends cannot make
# on their own since they read one host's clock, made instead by running each
# call's earpiece a known number of parts per million fast or slow, taking
# one frame at a callback on three of them and two at once on the other
# three. No capture: six calls for an hour are over two million packets,
# and what this step proves is in the report lines, not on the wire. The
# network is the Compose project's own, so a copy of the lab under a
# COMPOSE_PROJECT_NAME of its own runs this against its own Asterisk.
drift_flow() {
    lab_run "the drift flow's six calls" $((LAB_START_S + ${SIPRAL_DRIFT_MS:-3600000} / 1000 + LAB_CALL_S)) \
        --network "$LAB_NETWORK" \
        -e SIPRAL_FLOWS=drift \
        -e SIPRAL_DRIFT_MS="${SIPRAL_DRIFT_MS:-3600000}" \
        -e SIPRAL_DRIFT_REPORT_MS="${SIPRAL_DRIFT_REPORT_MS:-300000}" \
        -e SIPRAL_DRIFT_PPM="${SIPRAL_DRIFT_PPM:-250}" \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS:/harness:ro" \
        debian:trixie-slim /harness asterisk 5060 9000
}

if [ "$WANT" = drift ]; then
    step "an hour on one call -- six calls to Asterisk's echo, their earpieces skewed"
    drift_flow && pass "the jitter buffer kept all six calls level" \
        || fail "an hour of drift"
fi

# The same six calls as drift_flow, over a link `bad_network`'s own profile
# shapes -- ifb plus mirred, both directions, exactly the setup bad_network
# uses, kept here as its own function because drift_flow's own container never
# takes NET_ADMIN or installs iproute2 and giving it both unconditionally
# would cost every ordinary `drift` run an apt-get it never needs.
# SIPRAL_AUDIO_GATE=1 throughout, so interop/harness/src/drift.rs's own
# verdict carries each leg's segmental SNR and splice clicks beside what the
# buffer did.
drift_under_netem() {
    local profile="$1"
    # shellcheck disable=SC1090
    WHY=""; NETEM=""; REQUIRE=""
    . "$ROOT/interop/impairment/$profile.sh"
    printf '  %-10s %s\n' "$profile" "$WHY"
    lab_run "the drift flow's six calls over $profile" $((LAB_START_APT_S + ${SIPRAL_DRIFT_MS:-180000} / 1000 + LAB_CALL_S)) \
        --network "$LAB_NETWORK" \
        --cap-add NET_ADMIN \
        -e SIPRAL_FLOWS=drift \
        -e SIPRAL_AUDIO_GATE=1 \
        -e SIPRAL_DRIFT_MS="${SIPRAL_DRIFT_MS:-180000}" \
        -e SIPRAL_DRIFT_REPORT_MS="${SIPRAL_DRIFT_REPORT_MS:-30000}" \
        -e SIPRAL_DRIFT_PPM="${SIPRAL_DRIFT_PPM:-250}" \
        -e "NETEM=$NETEM" -e "REQUIRE=$REQUIRE" \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
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
            /harness asterisk 5060 9000'
}

if [ "$WANT" = drift-netem ]; then
    PROFILE="${PROFILE:-lossy}"
    step "the drift flow over a bad link -- $PROFILE"
    drift_under_netem "$PROFILE" \
        && pass "the jitter buffer and the audio quality gate both held" \
        || fail "drift under $PROFILE"
fi

# One call to Asterisk's echo, a marker frame's round trip standing in for a
# real microphone-to-earpiece measurement this lab has no second host to take
# with two real clocks. interop/harness/src/latency.rs's own module doc says
# why a round trip halved is what is reported instead.
latency_flow() {
    lab_run "the latency flow's call" $((LAB_START_S + ${SIPRAL_LATENCY_MS:-120000} / 1000 + LAB_CALL_S)) \
        --network "$LAB_NETWORK" \
        -e SIPRAL_FLOWS=latency \
        -e SIPRAL_LATENCY_MS="${SIPRAL_LATENCY_MS:-120000}" \
        -e SIPRAL_LATENCY_MARK_MS="${SIPRAL_LATENCY_MARK_MS:-2000}" \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS:/harness:ro" \
        debian:trixie-slim /harness asterisk 5060 9000
}

if [ "$WANT" = latency ]; then
    step "microphone to earpiece -- a marker's round trip to Asterisk's echo"
    latency_flow && pass "the markers came back" || fail "microphone to earpiece"
fi

# What a call carries in its audio, and a call recorded, on Asterisk's
# labuser-inband (no telephone event): interop/harness/src/inband.rs's module
# doc says what each of its three flows proves. The greeting the machine
# flow's far end plays is written by the harness itself and copied into
# Asterisk first; the recordings land in a directory of this run's own, which
# the harness reads back and then soxi and opusinfo, readers that are not
# this stack's own. Run as this user, so what the containers write here is
# this user's to remove.
inband_flow() {
    local greetings recordings status
    greetings=$(mktemp -d) && recordings=$(mktemp -d) || return 1
    docker run --rm --user "$(id -u):$(id -g)" -v "$HARNESS:/harness:ro" -v "$greetings:/out" \
        debian:trixie-slim /harness --write-greeting /out >/dev/null \
        && ( cd interop && docker compose cp "$greetings/sipral-greeting.sln" asterisk:/tmp/ \
            && docker compose cp "$greetings/sipral-beep.sln" asterisk:/tmp/ ) >/dev/null 2>&1 \
        || { printf '  the greeting did not reach Asterisk\n'; rm -rf "$greetings" "$recordings"; return 1; }
    lab_run "the in-band flows' calls" $((LAB_START_S + 3 * LAB_CALL_S)) \
        --network "$LAB_NETWORK" \
        --user "$(id -u):$(id -g)" \
        -e SIPRAL_FLOWS=inband,amd,recording \
        -e SIPRAL_USER=labuser-inband \
        -e SIPRAL_RECORDINGS=/recordings \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS:/harness:ro" \
        -v "$recordings:/recordings" \
        debian:trixie-slim /harness asterisk 5060 9000
    status=$?
    if [ "$status" -eq 0 ]; then
        lab_run "soxi and opusinfo on the recordings" $((LAB_START_APT_S + LAB_CALL_S)) \
            -v "$recordings:/recordings:ro" \
            debian:trixie-slim sh -c '
                export DEBIAN_FRONTEND=noninteractive
                apt-get -qq update >/dev/null 2>&1
                apt-get -qq install -y sox opus-tools >/dev/null 2>&1
                soxi /recordings/sipral-call.wav && opusinfo /recordings/sipral-call.opus'
        status=$?
    fi
    rm -rf "$greetings" "$recordings"
    return "$status"
}

if [ "$WANT" = inband ]; then
    step "digits, ringback, a machine and a recording -- in the audio, at Asterisk"
    inband_flow && pass "heard in the audio, and both recordings read by other readers" \
        || fail "what a call carries in its audio"
fi

# A hundred calls (or SIPRAL_VOLUME_CALLS) at once rather than one,
# `/usr/bin/time -v` around the whole container for this end's own CPU and
# peak memory, GNU time is not on debian:trixie-slim's own image so it is
# installed here the same way bad_network installs iproute2.
# interop/harness/src/volume.rs's own module doc says why SIPRAL_VOLUME_SERVER
# is "asterisk" (straight at the PBX, no proxy) or "kamailio" (the proxy,
# which this lab's own kamailio.cfg forwards to FreeSWITCH and nowhere else).
volume_flow() {
    local server="$1"
    lab_run "the volume flow's calls to $server" $((LAB_START_APT_S + ${SIPRAL_VOLUME_CALLS:-100} * ${SIPRAL_VOLUME_STAGGER_MS:-50} / 1000 + ${SIPRAL_VOLUME_HOLD_MS:-5000} / 1000 + 2 * LAB_CALL_S)) \
        --network "$LAB_NETWORK" \
        -e SIPRAL_FLOWS=volume \
        -e SIPRAL_VOLUME_CALLS="${SIPRAL_VOLUME_CALLS:-100}" \
        -e SIPRAL_VOLUME_STAGGER_MS="${SIPRAL_VOLUME_STAGGER_MS:-50}" \
        -e SIPRAL_VOLUME_HOLD_MS="${SIPRAL_VOLUME_HOLD_MS:-5000}" \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS:/harness:ro" \
        debian:trixie-slim sh -c '
            export DEBIAN_FRONTEND=noninteractive
            apt-get -qq update >/dev/null 2>&1
            apt-get -qq install -y time >/dev/null 2>&1
            /usr/bin/time -v /harness '"$server"' 5060 9000'
}

# Peak channel count on whichever real server is carrying the calls, sampled
# once a second while `volume_flow` runs, printed the way `scripts/lab.sh`'s
# other steps already read a server's own console rather than trust this
# end's own count of calls still up.
volume_peak() {
    local server="$1" peak=0 seen
    while :; do
        if [ "$server" = asterisk ]; then
            seen=$(cd interop && docker compose exec -T asterisk asterisk -rx \
                "core show channels count" 2>/dev/null \
                | sed -n 's/^\([0-9][0-9]*\) active channel.*/\1/p')
        else
            seen=$(cd interop && docker compose exec -T freeswitch fs_cli \
                -x 'show channels count' 2>/dev/null \
                | sed -n 's/^\([0-9][0-9]*\) total.*/\1/p')
        fi
        case "$seen" in
            ''|*[!0-9]*) ;;
            *) [ "$seen" -gt "$peak" ] && peak="$seen" ;;
        esac
        printf '%s\n' "$peak" >"$PEAK_FILE"
        sleep 1
    done
}

if [ "$WANT" = volume ]; then
    for server in ${SIPRAL_VOLUME_SERVER:-asterisk kamailio}; do
        behind="asterisk, no proxy"
        [ "$server" = kamailio ] && behind="kamailio, to FreeSWITCH"
        step "a volume of calls -- $behind"
        PEAK_FILE="$(mktemp)"
        volume_peak "$server" &
        SAMPLER=$!
        volume_flow "$server"
        STATUS=$?
        kill "$SAMPLER" >/dev/null 2>&1
        wait "$SAMPLER" 2>/dev/null
        printf '  note  peak channel count on the real server: %s\n' \
            "$(cat "$PEAK_FILE" 2>/dev/null || printf unknown)"
        rm -f "$PEAK_FILE"
        [ "$STATUS" -eq 0 ] && pass "the calls came up ($behind)" \
            || fail "a volume of calls ($behind)"
    done
fi

# The Rust run through the proxy carries one flow more than the others: a call
# Kamailio forks to two of the harness's own stacks registered as one user,
# the second answering first (interop/harness/src/fork.rs, and the user
# kamailio.cfg forks). The C run and the phone-to-phone and bad-network runs
# name their own flows and do not carry it. The step keeps its title, which
# scripts/interop-matrix.py reads the section by.
if [ "$WANT" = all ] || [ "$WANT" = kamailio ]; then
    step "register, call, hold, resume, transfer -- through the proxy"
    flows kamailio proxy && pass "kamailio to freeswitch" || fail "kamailio to freeswitch"
    if [ -n "$HARNESS_C" ]; then
        step "the same, through the C ABI -- through the proxy"
        flows_c kamailio proxy-c && pass "kamailio to freeswitch, in C" \
            || fail "kamailio to freeswitch, in C"
    fi
fi

# A local conference of three of the harness's own stacks, each registered at
# Kamailio as one of the users kamailio.cfg keeps for it and each on a codec
# of its own, called by a fourth that mixes the three itself
# (interop/harness/src/nway.rs): each has to hear the other two and not
# itself, and the two left have to go on hearing each other once one hangs
# up. The step keeps its title, which scripts/interop-matrix.py reads the
# section by.
nway_flow() {
    lab_run "the harness's local conference" $((LAB_START_S + 2 * LAB_CALL_S)) \
        --network "$LAB_NETWORK" \
        -e SIPRAL_FLOWS=nway \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS:/harness:ro" \
        debian:trixie-slim sh -c "/harness kamailio 5060 9000"
}

if [ "$WANT" = all ] || [ "$WANT" = kamailio ] || [ "$WANT" = nway ]; then
    step "an N-way local conference -- three calls through the proxy, each on its own codec"
    nway_flow && pass "three calls mixed, each heard the other two, and two kept talking" \
        || fail "an N-way local conference"
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
    if [ -n "$SWIFT_AGENT" ]; then
        swift_agent && pass "SipralLabAgent answered, echoed and carried DTMF" \
            || fail "SipralLabAgent"
    else
        printf '  note  no Swift lab agent was built; see its build step above\n'
    fi
    step "the Kotlin idiomatic-layer agent, called by Asterisk"
    if [ -n "${KOTLIN_AGENT_JAR:-}" ]; then
        kotlin_agent && pass "Agent.kt answered, echoed and carried DTMF" \
            || fail "Agent.kt"
    else
        printf '  note  KOTLIN_AGENT_JAR not set; see bindings/kotlin/README.md\n'
    fi
    step "the .NET sample agent, called by Asterisk"
    if [ -n "$HARNESS_C" ]; then
        csharp_agent && pass "Sipral.Sample.Agent answered, echoed and hung up" \
            || fail "Sipral.Sample.Agent"
    else
        printf '  note  no libsipral_ffi to load; that step is skipped\n'
    fi
fi

if [ "$WANT" = all ] || [ "$WANT" = asterisk ] || [ "$WANT" = bridge ]; then
    step "the bridge to a voice agent, called by Asterisk"
    if [ -n "$AGENT_BRIDGE" ] && [ -n "$HARNESS_C" ]; then
        agent_bridge_flow \
            && pass "agent-bridge bridged the call to agent.py, forwarded its digits and passed its hangup on" \
            || fail "agent-bridge"
    elif [ "$WANT" = bridge ]; then
        fail "agent-bridge: no bridge, or no libsipral_ffi for the Python agent"
    else
        printf '  note  no bridge, or no libsipral_ffi for its voice agent; that step is skipped\n'
    fi
fi
if [ "$WANT" = bridge ]; then
    step "${SIPRAL_BRIDGE_CALLS:-30} calls at once through the bridge, to the headless agent's echo"
    if [ -n "$AGENT_BRIDGE" ] && [ -n "$HEADLESS_AGENT" ]; then
        agent_bridge_volume && pass "every call bridged both ways and ended" \
            || fail "agent-bridge with ${SIPRAL_BRIDGE_CALLS:-30} calls at once"
    else
        fail "agent-bridge with many calls: no bridge or no headless agent"
    fi
fi

# A REFER from outside any call, sent by the Rust harness at a stack driven
# through the C ABI (`harness-c listen`): refused where the stack was never
# told to take them, taken where it was, the call it asks for placed through
# Asterisk to its echo. Part of the Asterisk run, and a word of its own.
if [ "$WANT" = all ] || [ "$WANT" = asterisk ] || [ "$WANT" = referral ]; then
    if [ -n "$HARNESS_C" ]; then
        step "a REFER from outside any call -- refused by a C ABI stack that does not take them"
        referral_refused_flow && pass "refused 403, and the program never heard of it" \
            || fail "a REFER from outside any call, refused"
        step "a REFER from outside any call -- taken by a C ABI stack, calling Asterisk's echo"
        referral_taken_flow && pass "taken; 202, then 100 and 200 to the switchboard, and the echo heard" \
            || fail "a REFER from outside any call, taken"
    elif [ "$WANT" = referral ]; then
        fail "a REFER from outside any call: there is no C harness to listen with"
    else
        printf '  note  no C harness, so the REFER from outside any call is skipped with the other C flows\n'
    fi
fi

# 8.10: the SRTP policy per account and the encryption report, through the C
# ABI, against both servers -- the account and not the call holds the policy,
# and the report read back names what the far end answered -- then
# STIR/SHAKEN between two stacks of the C ABI, one signing and one
# verifying, with a certificate authority made for the run.
if [ "$WANT" = all ] || [ "$WANT" = security ]; then
    if [ -n "$HARNESS_C" ]; then
        step "SRTP required, DTLS-SRTP required and off, on the account -- straight at Asterisk"
        flows_c asterisk security-asterisk-c acctsdes,acctdtls,acctoff \
            && pass "asterisk, the policy per account" \
            || fail "asterisk, the policy per account"
        step "SRTP required, DTLS-SRTP required and off, on the account -- through the proxy"
        flows_c kamailio security-proxy-c acctsdes,acctdtls,acctoff \
            && pass "kamailio to freeswitch, the policy per account" \
            || fail "kamailio to freeswitch, the policy per account"
        step "STIR/SHAKEN between two C ABI stacks -- one signs, one verifies"
        stir_flow && pass "signed and verified, unsigned refused 428, untrusted refused 437" \
            || fail "STIR/SHAKEN between two C ABI stacks"
    elif [ "$WANT" = security ]; then
        fail "the security step: there is no C harness to run it with"
    else
        printf '  note  no C harness, so the security step is skipped with the other C flows\n'
    fi
fi

# A call whose address moves under it (interop/harness/src/moved.rs): the
# Rust harness calls Asterisk's echo from the lab network, and once it says
# the echo is coming back, this takes its container off the network and
# connects it again at another address -- a laptop moving between networks,
# as the stack on it sees it. Asterisk's own endpoint keeps its defaults, so
# it sends the echo to the `c=` it was given and nowhere else: the audio
# comes back only if the stack offered the call again at the new address.
# The new address is near the top of the network's own subnet, which Docker
# hands out last. Part of the Asterisk run, and a word of its own.
MOVE_NAME="sipral-lab-move-${COMPOSE_PROJECT_NAME:-sipral-interop}"
move_address() {
    local subnet base bits a b c d n
    subnet=$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$LAB_NETWORK" \
        | tr ' ' '\n' | grep -m1 '^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*/')
    [ -n "$subnet" ] || return 1
    base=${subnet%/*}
    bits=${subnet#*/}
    IFS=. read -r a b c d <<<"$base"
    n=$(( (a << 24) + (b << 16) + (c << 8) + d + (1 << (32 - bits)) - 10 ))
    printf '%d.%d.%d.%d\n' $(( (n >> 24) & 255 )) $(( (n >> 16) & 255 )) \
        $(( (n >> 8) & 255 )) $(( n & 255 ))
}
move_flow() {
    local to status tries=0
    to=$(move_address) || { printf '  cannot read the lab network'"'"'s subnet\n'; return 1; }
    docker rm -f "$MOVE_NAME" >/dev/null 2>&1
    docker run -d --name "$MOVE_NAME" --network "$LAB_NETWORK" \
        -e SIPRAL_FLOWS=move \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS:/harness:ro" \
        debian:trixie-slim /harness asterisk 5060 9000 >/dev/null \
        || { printf '  could not start the harness\n'; return 1; }
    until docker logs "$MOVE_NAME" 2>&1 | found '^  move  the call is up at'; do
        tries=$((tries + 1))
        if [ "$(docker inspect -f '{{.State.Running}}' "$MOVE_NAME" 2>/dev/null)" != true ] \
            || [ "$tries" -ge 45 ]; then
            printf '  the harness never said the call was up\n'
            docker logs "$MOVE_NAME" 2>&1
            docker rm -f "$MOVE_NAME" >/dev/null 2>&1
            return 1
        fi
        sleep 1
    done
    printf '  moving the harness to %s\n' "$to"
    docker network disconnect "$LAB_NETWORK" "$MOVE_NAME" >/dev/null 2>&1 \
        && docker network connect --ip "$to" "$LAB_NETWORK" "$MOVE_NAME" >/dev/null 2>&1 \
        || printf '  could not move the harness to %s\n' "$to"
    status=$(timeout 90 docker wait "$MOVE_NAME" 2>/dev/null || echo 1)
    docker logs "$MOVE_NAME" 2>&1
    docker rm -f "$MOVE_NAME" >/dev/null 2>&1
    [ "$status" = 0 ]
}

if [ "$WANT" = all ] || [ "$WANT" = asterisk ] || [ "$WANT" = move ]; then
    step "a call whose address moves under it -- straight at Asterisk"
    move_flow && pass "offered again at the new address, and the echo heard after" \
        || fail "a call whose address moves under it"
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
    if ( cd interop && docker compose --profile baresip up -d baresip baresip-hangup ) \
            >/dev/null 2>&1; then
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
        # a container and an account of its own (interop/baresip/config-hangup),
        # so this one flow's own ctrl_tcp command can never reach whichever
        # of the three flows above happens to have a call up at the time
        if wait_for baresip-hangup "baresip-hangup@kamailio: (prio 0) {0/UDP/v4} 200 OK" \
                required baresip; then
            flows_baresip_hangup && pass "baresip hangs the call up on its own" \
                || fail "baresip hangs the call up on its own"
            if [ -n "$HARNESS_C" ]; then
                flows_baresip_hangup_c && pass "baresip hangs the call up on its own, in C" \
                    || fail "baresip hangs the call up on its own, in C"
            fi
        fi
    else
        fail "docker compose up baresip baresip-hangup"
    fi
    ( cd interop && docker compose stop baresip baresip-hangup \
        && docker compose rm -f baresip baresip-hangup ) >/dev/null 2>&1
fi

if [ "$WANT" = all ] || [ "$WANT" = nat ]; then
    step "behind a NAT -- STUN against coturn, then register and call Asterisk, in C"
    if [ -n "$HARNESS_C" ]; then
        nat_flow && pass "registered and heard from behind the NAT, at the address STUN reported" \
            || fail "behind a NAT"
        step "called behind a NAT -- STUN against coturn, then Asterisk calls in, in C"
        nat_called_flow \
            && pass "called behind the NAT: the 2xx named the address STUN reported, and the ACK, the BYE and the echo reached it" \
            || fail "called behind a NAT"
    elif [ "$WANT" = nat ]; then
        # the flow is the C harness's, since the setting it proves is the C
        # ABI's: asked for by name, a machine with no C harness fails it
        fail "behind a NAT: there is no C harness to run it with"
    else
        printf '  note  no C harness, so the flow behind a NAT is skipped with the other C flows\n'
    fi
fi

if [ "$WANT" = all ] || [ "$WANT" = nat-idle ]; then
    step "called ${NAT_IDLE_WAIT} s after registering, behind a filtering NAT, keep-alive on, in C"
    if [ -n "$HARNESS_C" ]; then
        nat_idle_called_flow on \
            && pass "called ${NAT_IDLE_WAIT} s after the REGISTER: the registrar keep-alive held the NAT's filter open" \
            || fail "called ${NAT_IDLE_WAIT} s after registering behind a NAT"
        # the control, only when asked for by name: six more minutes, to show
        # the NAT does forget -- a lab whose NAT never did would pass the step
        # above with the keep-alive doing nothing
        if [ "$WANT" = nat-idle ]; then
            step "the same with the keep-alive off: the NAT has to drop the call"
            nat_idle_called_flow off \
                && pass "with no keep-alive the NAT's filter dropped the call, so the step above proves the keep-alive" \
                || fail "the call got through with no keep-alive: this NAT proves nothing about one"
        fi
    elif [ "$WANT" = nat-idle ]; then
        fail "called behind a NAT after an idle: there is no C harness to run it with"
    else
        printf '  note  no C harness, so the idle call behind a NAT is skipped with the other C flows\n'
    fi
fi

if [ "$WANT" = all ] || [ "$WANT" = ice ]; then
    step "ICE-lite -- a call that requires ICE, placed at the headless agent answering as lite"
    if [ -n "$HEADLESS_APP" ] && [ -n "$HEADLESS_CLIENT" ]; then
        ice_lite_flow && pass "the full caller chose a path on the lite end, and the tone came back on it" \
            || fail "ICE-lite, from the harness"
        step "ICE-lite -- Asterisk's own ICE calling the headless agent"
        ice_lite_asterisk && pass "Asterisk's checks succeeded on the lite end, and audio crossed the pair both ways" \
            || fail "ICE-lite, from Asterisk"
    elif [ "$WANT" = ice ]; then
        fail "ICE-lite: the socket-framed agent was not built, so there is no lite end to call"
    else
        printf '  note  no socket-framed agent, so the ICE-lite steps are skipped with its own\n'
    fi
fi

if [ "$WANT" = all ] || [ "$WANT" = ice ] || [ "$WANT" = icelite ]; then
    step "ICE-lite -- the same call, placed at a C ABI stack answering as lite"
    if [ -n "$HARNESS_C" ]; then
        ice_lite_c_flow && pass "the full caller chose a path on SIPRAL_ICE_LITE, and the tone came back on it" \
            || fail "ICE-lite, through the C ABI"
    elif [ "$WANT" = icelite ]; then
        fail "ICE-lite through the C ABI: there is no C harness to answer with"
    else
        printf '  note  no C harness, so ICE-lite through the C ABI is skipped with the other C flows\n'
    fi
fi

if [ "$WANT" = all ] || [ "$WANT" = ice ]; then
    step "full ICE -- two stacks, each behind a NAT of its own, on what STUN gave them"
    ice_nat_flow && pass "the call found its path through both NATs, and the tone crossed it both ways" \
        || fail "full ICE through two NATs"
fi

if [ "$WANT" = all ] || [ "$WANT" = ice ] || [ "$WANT" = turn ]; then
    step "full ICE through a relay -- the path between the two NATs blocked, coturn as TURN"
    ice_turn_flow && pass "no path without TURN; with it, every call went through coturn and every relay was given back" \
        || fail "full ICE through a TURN relay"
fi

# The field failures that need a network to show, docs/11-testing.md's table
# "What a field failure is answered by". Two parts.
#
# robust_link_flow: interop/robust/listener.py on the lab network, a peer that
# takes UDP and TCP on 5060 and never answers anything, printing one line for
# whatever reached it; and the C harness's `robust` mode beside it, its own
# egress shaped so that every IP fragment it sends is dropped -- what a good
# many NATs and firewalls do to a datagram too large for one frame. Three tc
# filters on a prio qdisc whose third band is netem at 100% loss: a fragment
# with more to come, and, of what is left, anything with an offset, which is
# a last fragment; everything else goes out as usual. SIPRAL_ROBUST_DARKEN is
# a fourth filter the harness adds itself once its `dark` connection is up:
# every TCP segment to the peer, so the path goes dark after the handshake
# and the kernel is left retransmitting into nothing.
#
# The harness proves its half on its own lines (interop/harness-c's comment
# above ROBUST_MARKER); the listener's log proves the other: the 200-byte
# control arrived and the 1600-byte one did not, which is the link doing what
# the step says it does -- without it, the INVITEs below prove nothing -- the
# 1300-byte INVITE arrived as a datagram, and the two placed again on TCP
# after the 1301- and 1600-byte ones were refused as datagrams arrived whole.
robust_link_flow() {
    local project="${COMPOSE_PROJECT_NAME:-sipral-interop}"
    local name="$project-robust-listener"
    local beside listener status said
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    docker build -q -f "$ROOT/interop/nat/Dockerfile.python" \
        -t sipral-lab-nat-python "$ROOT/interop/nat" >/dev/null \
        && docker build -q -t sipral-lab-nat "$ROOT/interop/nat" >/dev/null \
        || { printf '  could not build the images the step runs in\n'; return 1; }
    docker rm -f "$name" >/dev/null 2>&1
    docker run -d --name "$name" --network "$LAB_NETWORK" \
        -v "$ROOT/interop/robust:/robust:ro" \
        sipral-lab-nat-python python3 -u /robust/listener.py 5060 >/dev/null \
        || { printf '  could not start the listener\n'; return 1; }
    listener=$(docker inspect -f \
        "{{with index .NetworkSettings.Networks \"$LAB_NETWORK\"}}{{.IPAddress}}{{end}}" "$name")
    if [ -z "$listener" ]; then
        printf '  could not read the listener'"'"'s address\n'
        docker rm -f "$name" >/dev/null 2>&1
        return 1
    fi
    printf '  the listener at %s:5060\n' "$listener"

    lab_run "the C harness's robust runs" $((LAB_START_S + 3 * LAB_CALL_S)) \
        --network "$LAB_NETWORK" \
        --cap-add NET_ADMIN \
        -e LD_LIBRARY_PATH=/lib-sipral \
        ${SIPRAL_HARNESS_SEED:+-e SIPRAL_HARNESS_SEED} \
        -v "$HARNESS_C:/harness-c:ro" \
        -v "$beside:/lib-sipral:ro" \
        sipral-lab-nat sh -c "
            dev=\$(ip -o route get $listener | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p')
            [ -n \"\$dev\" ] || exit 1
            tc qdisc add dev \"\$dev\" root handle 1: prio bands 3 \
                priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 || exit 1
            tc qdisc add dev \"\$dev\" parent 1:3 handle 30: netem loss 100% || exit 1
            tc filter add dev \"\$dev\" parent 1: protocol ip prio 2 \
                u32 match u16 0x2000 0x2000 at 6 flowid 1:3 || exit 1
            tc filter add dev \"\$dev\" parent 1: protocol ip prio 3 \
                u32 match u16 0x0000 0x1fff at 6 flowid 1:2 || exit 1
            tc filter add dev \"\$dev\" parent 1: protocol ip prio 4 \
                u32 match u32 0 0 flowid 1:3 || exit 1
            export SIPRAL_ROBUST_DARKEN=\"tc filter add dev \$dev parent 1: protocol ip prio 1 u32 match ip dst $listener/32 match ip protocol 6 0xff flowid 1:3\"
            exec /harness-c robust $listener 5060"
    status=$?
    said=$(docker logs "$name" 2>&1)
    docker rm -f "$name" >/dev/null 2>&1
    printf '%s\n' "$said" | sed 's/^/  listener  /'
    if ! printf '%s\n' "$said" | found '^udp 200 SIPRAL-CONTROL-SMALL'; then
        printf '  the 200-byte control never arrived: the link drops more than fragments\n'
        return 1
    fi
    if printf '%s\n' "$said" | found '^udp 1600 '; then
        printf '  the 1600-byte control arrived: the link does not drop fragments, and the run proves nothing\n'
        return 1
    fi
    printf '%s\n' "$said" | found '^udp 1300 INVITE ' \
        || { printf '  the 1300-byte INVITE never arrived as a datagram\n'; status=1; }
    # the INVITE placed again on the stream comes to within a byte or two of
    # the one refused, so what is counted is two over the line, whole
    if [ "$(printf '%s\n' "$said" \
        | awk '$1 == "tcp" && $2 > 1300 && $3 == "INVITE" && $NF == "complete"' | wc -l)" -lt 2 ]; then
        printf '  the INVITEs over the line never arrived whole over TCP\n'
        status=1
    fi
    if printf '%s\n' "$said" | awk '$1 == "udp" && $2 > 1300 { found = 1 } END { exit !found }'; then
        printf '  a datagram over 1300 bytes reached the listener\n'
        status=1
    fi
    return "$status"
}

# The NAT pair's STUN step with its first server dead: both ends -- the C
# harness calling, the Rust harness answering -- are told to ask the second
# NAT's own outside address first, where nothing listens on 3478, and coturn
# behind it (SIPRAL_STUN_FALLBACKS). With SIPRAL_STUN_EXPECT_FAILOVER=1 each
# fails its step unless the server in use moved before the mapping came back,
# so a first server that answered after all is a failure too. The rest is the
# ordinary call across the pair: ICE on what coturn said, and the tone both
# ways.
robust_stun_failover() {
    local status
    nat_pair_up -f compose.yaml || return 1
    printf '  caller behind %s, callee behind %s, STUN at %s:3478 (dead) and then %s:3478\n' \
        "$NAT_PAIR_GATEWAY" "$NAT_PAIR_GATEWAY2" "$NAT_PAIR_OUTSIDE2" "$NAT_PAIR_COTURN"
    NAT_PAIR_CALLER=c nat_pair_call \
        -e "SIPRAL_STUN_SERVER=$NAT_PAIR_OUTSIDE2:3478" \
        -e "SIPRAL_STUN_FALLBACKS=$NAT_PAIR_COTURN:3478" \
        -e SIPRAL_STUN_EXPECT_FAILOVER=1
    status=$?
    nat_pair_down -f compose.yaml
    return "$status"
}

# One call from the Python layer's datagram caller
# (interop/datagram/caller.py), the vehicle of the datagram step below and
# of the best-effort SRTP, pinned TLS and location steps. Its first use is
# RFC 3261 §18.1.1 on a challenged call: an account whose INVITE, once it
# carries Asterisk's `Authorization`, is past 1300 bytes. `$1` is the port
# the INVITE goes to, `$2` the SDES suites the account offers, `$3` a display
# name to make it larger, empty for none, `$4` how many seconds the call is
# up before the hold, empty for the dwell, and anything after it more
# `docker run` arguments -- the caller's other variables; what the caller
# printed is left in DATAGRAM_LOG, and what Asterisk took, and over what, in
# DATAGRAM_SEEN while pjsip's logger is on. Four suites are about 1100 bytes
# and 1450 answered; one suite and 250 bytes of display name about 1150 and
# 1500, with no suite to drop. CALLER_ACCOUNT names another of Asterisk's
# accounts to call from, labuser-big unless set; DATAGRAM_MARK is a file the
# step made for the call to note where Asterisk's log stood.
DATAGRAM_SUITES=AEAD_AES_256_GCM,AES_CM_128_HMAC_SHA1_80,AEAD_AES_128_GCM,AES_256_CM_HMAC_SHA1_80
datagram_call() {
    local port="$1" suites="$2" display="$3" hold_after="${4:-0}" beside
    local user="${CALLER_ACCOUNT:-labuser-big}"
    shift $(( $# < 4 ? $# : 4 ))
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    ( cd interop && docker compose logs --no-color asterisk 2>/dev/null ) | wc -l > "$DATAGRAM_MARK"
    DATAGRAM_LOG=$(lab_run "the datagram caller" $((LAB_START_APT_S + LAB_CALL_S + hold_after)) \
        --network "$LAB_NETWORK" \
        -e SIPRAL_LIBRARY=/lib-sipral -e PYTHONPATH=/python \
        -e SIPRAL_AOR="sip:$user@asterisk" \
        -e SIPRAL_AUTH_USER="$user" -e SIPRAL_AUTH_PASSWORD=labpass \
        -e SIPRAL_TARGET=sip:9002@asterisk \
        -e SIPRAL_SUITES="$suites" \
        -e SIPRAL_DISPLAY_NAME="$display" \
        -e SIPRAL_DWELL_MS="$LAB_DWELL_MS" -e SIPRAL_PATIENCE_MS="$LAB_PATIENCE_MS" \
        -e SIPRAL_HOLD_AFTER_MS=$((hold_after * 1000)) \
        ${@+"$@"} \
        -v "$beside:/lib-sipral:ro" \
        -v "$ROOT/bindings/python:/python:ro" \
        -v "$ROOT/interop/datagram:/datagram:ro" \
        debian:trixie-slim sh -c "
            export DEBIAN_FRONTEND=noninteractive
            apt-get -qq update >/dev/null 2>&1
            apt-get -qq install -y python3 python3-cffi >/dev/null 2>&1
            address=\$(getent hosts asterisk | cut -d' ' -f1)
            SIPRAL_SERVER=\"\$address:$port\" exec python3 -u /datagram/caller.py" 2>&1)
    printf '%s\n' "$DATAGRAM_LOG" | sed 's/^/    /'
    DATAGRAM_SEEN=$( ( cd interop && docker compose logs --no-color asterisk 2>/dev/null ) \
        | tail -n +"$(( $(cat "$DATAGRAM_MARK") + 1 ))" \
        | grep -o 'Received SIP request ([0-9]* bytes) from [A-Z]*:' || true)
    printf '%s\n' "$DATAGRAM_SEEN" | sed 's/^/    asterisk: /'
}

# Whether the caller's own lines say `$1`.
datagram_said() {
    printf '%s\n' "$DATAGRAM_LOG" | found -E "$1"
}

# SIP over TCP and TLS through the four idiomatic layers (docs/22-tls.md,
# "SIP over TLS in the four layers"): each layer's own lab agent, told to
# signal over one connection, registered at Asterisk and called by it the
# way the agents above are over UDP. Before its call, every TLS agent is
# pointed at three listeners it has to refuse, and says why: 5061 with the
# platform's authorities only (the lab authority is not among them, so
# untrusted), 5062 presenting a certificate for another name, 5063 one that
# expired in 2020. interop/tls/pjsip_local.conf is the listeners and the
# accounts; tls_certificates makes the certificates for the run. The Swift
# agent runs on Linux, where Swift has no TLS, so it signals over TCP and is
# given no refusals to report.
TLS_NAME=asterisk.lab.sipral.test
tls_certificate() {
    local file="$1" name="$2"
    shift 2
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$name" \
        -keyout "$SIPRAL_TLS_CERTS/$file.key" -out "$SIPRAL_TLS_CERTS/$file.csr" >/dev/null 2>&1 \
        && printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$name" \
            > "$SIPRAL_TLS_CERTS/$file.ext" \
        && openssl x509 -req -in "$SIPRAL_TLS_CERTS/$file.csr" \
            -CA "$SIPRAL_TLS_CERTS/ca.pem" -CAkey "$SIPRAL_TLS_CERTS/ca.key" -CAcreateserial \
            -extfile "$SIPRAL_TLS_CERTS/$file.ext" "$@" -out "$SIPRAL_TLS_CERTS/$file.pem" >/dev/null 2>&1
}
tls_certificates() {
    SIPRAL_TLS_CERTS=$(mktemp -d)
    export SIPRAL_TLS_CERTS
    if ! openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
            -subj "/CN=Sipral lab authority" \
            -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
            -keyout "$SIPRAL_TLS_CERTS/ca.key" -out "$SIPRAL_TLS_CERTS/ca.pem" >/dev/null 2>&1 \
        || ! tls_certificate asterisk "$TLS_NAME" -days 1 \
        || ! tls_certificate wrong wrong.lab.sipral.test -days 1 \
        || ! tls_certificate expired "$TLS_NAME" -not_before 20200101000000Z -not_after 20200102000000Z; then
        printf '  could not make the certificates for the TLS listeners (openssl)\n'
        rm -rf "$SIPRAL_TLS_CERTS"
        return 1
    fi
    chmod 755 "$SIPRAL_TLS_CERTS"
    chmod 644 "$SIPRAL_TLS_CERTS"/*
}

# One layer's agent in a container of its own: `$1` the layer, `$2` the
# account, `$3` tls or tcp, then the `docker run` arguments up to `--`, the
# image, a shell line that prepares the agent, and the command that runs it.
# Over TLS the agent is run three times with a ten-second limit first, once
# against each listener it must refuse, and what it said about each is kept
# as a "probe" line in its log; then once against 5061, trusting the lab
# authority alone, and left to answer the call. `TLS_AGENT_NAME` is the
# container.
tls_agent_start() {
    local layer="$1" user="$2" over="$3" port=5061 run_args=() image prepare agent
    shift 3
    while [ "$1" != "--" ]; do
        run_args+=("$1")
        shift
    done
    shift
    image="$1" prepare="$2" agent="$3"
    [ "$over" = tcp ] && port=5060
    TLS_AGENT_NAME="sipral-lab-tls-$layer-${COMPOSE_PROJECT_NAME:-sipral-interop}"
    docker rm -f "$TLS_AGENT_NAME" >/dev/null 2>&1
    docker run -d --name "$TLS_AGENT_NAME" --network "$LAB_NETWORK" \
        -v "$SIPRAL_TLS_CERTS:/lab-tls:ro" \
        -e SIPRAL_AOR="sip:$user@asterisk" \
        -e SIPRAL_REGISTRAR=sip:asterisk \
        -e SIPRAL_AUTH_USER="$user" -e SIPRAL_AUTH_PASSWORD=labpass \
        -e SIPRAL_SIGNALLING="$over" \
        -e SIPRAL_TLS_SERVER_NAME="$TLS_NAME" \
        ${run_args[@]+"${run_args[@]}"} \
        "$image" sh -c "
            $prepare
            address=\$(getent hosts asterisk | cut -d' ' -f1)
            probe() {
                env SIPRAL_REGISTRAR_ADDRESS=\"\$address:\$1\" \${2:+SIPRAL_TLS_CA=\$2} \
                    timeout 20 $agent 2>&1 | grep -m1 '^transport failed' | sed \"s/^/probe \$1: /\"
            }
            if [ '$over' = tls ]; then
                probe 5061 ''
                probe 5062 /lab-tls/ca.pem
                probe 5063 /lab-tls/ca.pem
            fi
            SIPRAL_REGISTRAR_ADDRESS=\"\$address:$port\" SIPRAL_TLS_CA=/lab-tls/ca.pem exec $agent" \
        >/dev/null || { printf '  could not start the %s agent container\n' "$layer"; return 1; }
}

# Registered, called, and what it said checked: over TLS, each refusal for
# its own reason first; then the call answered, the "#" heard, audio both
# ways, and Asterisk's contact for it naming the transport it came over --
# read from the registrar's own store, since `pjsip show contacts` cuts a
# URI that long short of its parameters.
tls_agent_call() {
    local layer="$1" user="$2" over="$3" limit="$4" log tries contact
    tries=0
    until contact=$( ( cd interop && docker compose exec -T asterisk \
            asterisk -rx "database show registrar/contact" 2>/dev/null ) | grep "/$user;@" ) \
            && [ -n "$contact" ]; do
        tries=$((tries + 1))
        if [ "$(docker inspect -f '{{.State.Running}}' "$TLS_AGENT_NAME" 2>/dev/null)" != true ] \
            || [ "$tries" -ge "$limit" ]; then
            printf '  the %s agent never registered\n' "$layer"
            docker logs "$TLS_AGENT_NAME" 2>&1 | tail -30
            docker rm -f "$TLS_AGENT_NAME" >/dev/null 2>&1
            return 1
        fi
        sleep 2
    done
    printf '%s\n' "$contact" | grep -o '"uri":"[^"]*"' | sed 's/^/    contact /'
    ( cd interop && docker compose exec -T asterisk asterisk -rx \
        "channel originate PJSIP/$user extension s@agent-call" ) >/dev/null 2>&1
    tries=0
    until docker logs "$TLS_AGENT_NAME" 2>&1 | found '^ended '; do
        tries=$((tries + 1))
        [ "$tries" -ge 30 ] && break
        sleep 1
    done
    log=$(docker logs "$TLS_AGENT_NAME" 2>&1)
    docker rm -f "$TLS_AGENT_NAME" >/dev/null 2>&1
    printf '%s\n' "$log" | grep -E '^(probe|listening|answered|dtmf|ended|transport failed|call failed)' \
        | sed 's/^/    /'
    printf '%s\n' "$contact" | found "transport=$over" \
        || { printf '  Asterisk holds its contact over another transport\n'; return 1; }
    if [ "$over" = tls ]; then
        printf '%s\n' "$log" | found '^probe 5061: transport failed .*tls=untrusted' \
            || { printf '  the platform'"'"'s authorities alone did not refuse the lab'"'"'s certificate as untrusted\n'; return 1; }
        printf '%s\n' "$log" | found '^probe 5062: transport failed .*tls=name_mismatch' \
            || { printf '  the certificate for another name was not refused as a name mismatch\n'; return 1; }
        printf '%s\n' "$log" | found '^probe 5063: transport failed .*tls=expired' \
            || { printf '  the expired certificate was not refused as expired\n'; return 1; }
    fi
    printf '%s\n' "$log" | found '^answered ' \
        || { printf '  it never answered\n'; return 1; }
    printf '%s\n' "$log" | found '^dtmf #' \
        || { printf '  it never heard the "#" it hangs up on\n'; return 1; }
    printf '%s\n' "$log" | grep '^ended ' | found -E "packets_received'?[:=] ?[1-9]" \
        || { printf '  it heard no audio\n'; return 1; }
    printf '%s\n' "$log" | grep '^ended ' | found -E "packets_sent'?[:=] ?[1-9]" \
        || { printf '  it sent no audio back\n'; return 1; }
}

tls_python_agent() {
    local beside
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    tls_agent_start python labuser-agent-tls tls \
        -e SIPRAL_LIBRARY=/lib-sipral -e PYTHONPATH=/python \
        -v "$beside:/lib-sipral:ro" -v "$ROOT/bindings/python:/python:ro" -- \
        debian:trixie-slim \
        'export DEBIAN_FRONTEND=noninteractive
         apt-get -qq update >/dev/null 2>&1
         apt-get -qq install -y python3 python3-cffi >/dev/null 2>&1' \
        'python3 -u /python/examples/agent.py' || return 1
    tls_agent_call python labuser-agent-tls tls 60
}

tls_kotlin_agent() {
    local beside
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    docker build -q -t sipral-lab-kotlin interop/kotlin >/dev/null 2>&1 \
        || { printf '  could not build interop/kotlin\n'; return 1; }
    tls_agent_start kotlin labuser-agent-kotlin-tls tls \
        -v "$beside:/lib-sipral:ro" \
        -v "$ROOT/bindings/c/include:/sipral-include:ro" \
        -v "$ROOT/bindings/kotlin/sipral/src/main/jni:/sipral-jni:ro" \
        -v "$KOTLIN_AGENT_JAR:/kotlin/sipral-kotlin.jar:ro" \
        -v "$KOTLIN_STDLIB_JAR:/kotlin/kotlin-stdlib.jar:ro" \
        -v "$KOTLIN_COROUTINES_JAR:/kotlin/kotlinx-coroutines.jar:ro" -- \
        sipral-lab-kotlin \
        'cc -std=c11 -Wall -shared -fPIC \
             -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" -I/sipral-include \
             -o /tmp/libsipral_jni.so /sipral-jni/sipral_jni.c /sipral-jni/idiomatic_media.c \
             -L/lib-sipral -lsipral_ffi -Wl,-rpath,/lib-sipral || exit 1' \
        'java -Djava.library.path=/tmp -cp /kotlin/sipral-kotlin.jar:/kotlin/kotlin-stdlib.jar:/kotlin/kotlinx-coroutines.jar org.sipral.examples.AgentKt' \
        || return 1
    tls_agent_call kotlin labuser-agent-kotlin-tls tls 90
}

tls_csharp_agent() {
    local beside
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    tls_agent_start csharp labuser-agent-csharp-tls tls \
        -e SIPRAL_LIBRARY=/lib-sipral/libsipral_ffi.so \
        -v "$beside:/lib-sipral:ro" -v "$ROOT/bindings/dotnet:/src-dotnet:ro" -- \
        mcr.microsoft.com/dotnet/sdk:8.0 \
        'cp -r /src-dotnet /dotnet
         dotnet build -c Release -o /agent /dotnet/samples/Sipral.Sample.Agent >/dev/null 2>&1 || exit 1' \
        'dotnet /agent/Sipral.Sample.Agent.dll' || return 1
    tls_agent_call csharp labuser-agent-csharp-tls tls 150
}

# The SHA-256 fingerprint of a certificate's DER, as a pin is written.
tls_fingerprint() {
    openssl x509 -in "$1" -outform DER | openssl dgst -sha256 | awk '{print $NF}'
}

# A TLS trust pinned to one certificate (docs/22-tls.md), through the Python
# layer's datagram caller over TLS to 5061: pinned to the certificate
# Asterisk presents there, the call to the echo goes up whatever signed it
# and whatever name it carries; pinned to the fingerprint of another, the
# connection is refused as untrusted and no call goes up.
tls_pin_flow() {
    local ok=0
    DATAGRAM_MARK=$(mktemp)
    CALLER_ACCOUNT=labuser-agent-tls datagram_call 5061 "" "" "" \
        -e SIPRAL_SRTP=off -e SIPRAL_SIGNALLING=tls \
        -e SIPRAL_TLS_PIN="$(tls_fingerprint "$SIPRAL_TLS_CERTS/asterisk.pem")"
    if datagram_said '^confirmed$' && datagram_said '^ended LOCAL_HANGUP ' \
        && ! datagram_said '^tls refused'; then
        pass "a certificate pinned by its SHA-256 fingerprint, over TLS: the Python layer trusting Asterisk's certificate by its fingerprint alone, no authority and no name, called the echo over TLS and hung up"
    else
        fail "a certificate pinned by its SHA-256 fingerprint, over TLS"
        ok=1
    fi
    CALLER_ACCOUNT=labuser-agent-tls datagram_call 5061 "" "" "" \
        -e SIPRAL_SRTP=off -e SIPRAL_SIGNALLING=tls \
        -e SIPRAL_TLS_PIN="$(tls_fingerprint "$SIPRAL_TLS_CERTS/wrong.pem")"
    if datagram_said '^tls refused UNTRUSTED$' && ! datagram_said '^confirmed$'; then
        pass "another certificate's fingerprint pinned, refused: the Python layer pinned to a certificate Asterisk does not present refused the connection as untrusted, and no call went up"
    else
        fail "another certificate's fingerprint pinned, refused"
        ok=1
    fi
    rm -f "$DATAGRAM_MARK"
    return "$ok"
}

# Two lines in one stack (interop/lines/caller.py): the Python layer with an
# account on its UDP socket registered at Kamailio and another on a TLS
# connection of its own registered at Asterisk's 5061, pinned to the
# certificate Asterisk presents there. Both have to be registered at once,
# then a call goes up on each together -- through the proxy to FreeSWITCH's
# tone, and to Asterisk's echo -- each with audio both ways; 5061 takes
# nothing but TLS, so the second line registering there is its connection.
tls_two_lines_flow() {
    local beside log
    beside=$(cd "$(dirname "$HARNESS_C")" && pwd)
    log=$(lab_run "two lines in one stack" $((LAB_START_APT_S + LAB_CALL_S)) \
        --network "$LAB_NETWORK" \
        -e SIPRAL_LIBRARY=/lib-sipral -e PYTHONPATH=/python \
        -e SIPRAL_UDP_AOR=sip:labuser@kamailio -e SIPRAL_UDP_USER=labuser \
        -e SIPRAL_UDP_PASSWORD=labpass -e SIPRAL_UDP_TARGET=sip:9000@kamailio \
        -e SIPRAL_TLS_AOR=sip:labuser-agent-tls@asterisk -e SIPRAL_TLS_USER=labuser-agent-tls \
        -e SIPRAL_TLS_PASSWORD=labpass -e SIPRAL_TLS_TARGET=sip:9008@asterisk \
        -e SIPRAL_TLS_PIN="$(tls_fingerprint "$SIPRAL_TLS_CERTS/asterisk.pem")" \
        -e SIPRAL_DWELL_MS=6000 -e SIPRAL_PATIENCE_MS="$LAB_PATIENCE_MS" \
        -v "$beside:/lib-sipral:ro" \
        -v "$ROOT/bindings/python:/python:ro" \
        -v "$ROOT/interop/lines:/lines:ro" \
        debian:trixie-slim sh -c "
            export DEBIAN_FRONTEND=noninteractive
            apt-get -qq update >/dev/null 2>&1
            apt-get -qq install -y python3 python3-cffi >/dev/null 2>&1
            udp=\$(getent hosts kamailio | cut -d' ' -f1)
            tls=\$(getent hosts asterisk | cut -d' ' -f1)
            SIPRAL_UDP_SERVER=\"\$udp:5060\" SIPRAL_TLS_SERVER=\"\$tls:5061\" \
                exec python3 -u /lines/caller.py" 2>&1)
    printf '%s\n' "$log" | sed 's/^/    /'
    said() { printf '%s\n' "$log" | found -E "$1"; }
    if said '^both registered$' && said '^both up$' \
        && said '^udp media sent [1-9][0-9]* received [1-9][0-9]* audible [1-9]' \
        && said '^tls media sent [1-9][0-9]* received [1-9][0-9]* audible [1-9]' \
        && said '^udp ended LOCAL_HANGUP ' && said '^tls ended LOCAL_HANGUP ' \
        && said '^udp registration UNREGISTERED$' && said '^tls registration UNREGISTERED$'; then
        pass "two accounts in one stack, UDP through Kamailio and TLS to Asterisk: both registered at once, a call up on each together with audio both ways, both bindings given back"
    else
        fail "two accounts in one stack, UDP through Kamailio and TLS to Asterisk"
        return 1
    fi
}

tls_swift_agent() {
    tls_agent_start swift labuser-agent-swift-tcp tcp \
        -v "$ROOT:/work:ro" -v "${SWIFT_LIB_DIR:-$ROOT/target/release}:/work/target/release:ro" -- \
        swift:6.1 ':' '/work/bindings/.build/release/SipralLabAgent' || return 1
    tls_agent_call swift labuser-agent-swift-tcp tcp 60
}

if [ "$WANT" = all ] || [ "$WANT" = tls ]; then
    step "SIP over TCP and TLS through the four idiomatic layers, called by Asterisk"
    if [ -z "$HARNESS_C" ]; then
        if [ "$WANT" = tls ]; then
            fail "SIP over TLS: there is no libsipral_ffi for the agents to load"
        else
            printf '  note  no libsipral_ffi, so the TLS agents are skipped with the other C flows\n'
        fi
    elif ! tls_certificates; then
        fail "SIP over TLS: the certificates"
    else
        ( cd interop && docker compose -f compose.yaml -f tls/compose.override.yaml up -d asterisk ) \
            >/dev/null 2>&1 || fail "could not restart Asterisk with the TLS listeners"
        if wait_for asterisk "Asterisk Ready"; then
            tls_python_agent \
                && pass "agent.py over TLS: refused untrusted, a name mismatch and expired, then registered, answered, echoed and hung up" \
                || fail "agent.py over TLS"
            if [ -n "${KOTLIN_AGENT_JAR:-}" ]; then
                tls_kotlin_agent \
                    && pass "Agent.kt over TLS: refused untrusted, a name mismatch and expired, then registered, answered and echoed" \
                    || fail "Agent.kt over TLS"
            else
                printf '  note  KOTLIN_AGENT_JAR not set; the Kotlin agent is skipped\n'
            fi
            tls_csharp_agent \
                && pass "Sipral.Sample.Agent over TLS: refused untrusted, a name mismatch and expired, then registered, answered and echoed" \
                || fail "Sipral.Sample.Agent over TLS"
            if [ -n "$SWIFT_AGENT" ]; then
                tls_swift_agent \
                    && pass "SipralLabAgent over TCP: registered, answered and echoed on its connection" \
                    || fail "SipralLabAgent over TCP"
            else
                printf '  note  no Swift lab agent was built; see its build step above\n'
            fi
            tls_pin_flow || true
            tls_two_lines_flow || true
        fi
        ( cd interop && docker compose up -d asterisk ) >/dev/null 2>&1
        wait_for asterisk "Asterisk Ready" >/dev/null || true
        rm -rf "$SIPRAL_TLS_CERTS"
        unset SIPRAL_TLS_CERTS
    fi
fi

datagram_flow() {
    local ok=0
    DATAGRAM_MARK=$(mktemp)
    ( cd interop && docker compose -f compose.yaml -f datagram/compose.override.yaml up -d asterisk ) \
        >/dev/null 2>&1 || { fail "Asterisk could not be restarted with TCP and a UDP-only port"; return 1; }
    wait_for asterisk "Asterisk Ready" >/dev/null \
        || { fail "Asterisk did not come back with TCP and a UDP-only port"; return 1; }
    ( cd interop && docker compose exec -T asterisk asterisk -rx 'pjsip set logger on' ) >/dev/null 2>&1

    # UDP and TCP both on 5060: the answer goes over a connection the layer
    # opened by itself, and the call carries on to the hold and the hangup.
    # The hold comes 45 seconds in: past the first keep-alive ping on the
    # connection, which Asterisk does not answer, and past the ten seconds
    # a flow that has answered one is given (RFC 5626 section 4.4.1)
    datagram_call 5060 "$DATAGRAM_SUITES" "" 45
    if datagram_said '^wanted 2 [0-9.]+:5060 1[3-9][0-9][0-9] 1300$' \
        && datagram_said '^confirmed$' && datagram_said '^held$' && datagram_said '^resumed$' \
        && datagram_said '^ended LOCAL_HANGUP ' \
        && printf '%s\n' "$DATAGRAM_SEEN" | found -E '\(1[3-9][0-9][0-9] bytes\) from TCP:'; then
        pass "a challenged INVITE past 1300 bytes, taken over TCP: Asterisk on UDP and TCP, the answer to its challenge went on a connection the Python layer opened, and the call was held 45 seconds in, resumed and hung up"
    else
        fail "a challenged INVITE past 1300 bytes, taken over TCP"
        ok=1
    fi

    # UDP alone on 5070: the connection is refused, and the offer with one
    # suite is what fits the datagram
    datagram_call 5070 "$DATAGRAM_SUITES" ""
    if datagram_said '^wanted 2 [0-9.]+:5070 ' && datagram_said '^transport failed [0-9]+ 1$' \
        && datagram_said '^confirmed$' && datagram_said '^held$' && datagram_said '^resumed$' \
        && datagram_said '^ended LOCAL_HANGUP ' \
        && ! printf '%s\n' "$DATAGRAM_SEEN" | found 'from TCP:'; then
        pass "a challenged INVITE past 1300 bytes, trimmed to one SDES suite over UDP: Asterisk on UDP alone refused the connection, the INVITE went again over UDP with one SDES suite, and the call was held, resumed and hung up"
    else
        fail "a challenged INVITE past 1300 bytes, trimmed to one SDES suite over UDP"
        ok=1
    fi

    # UDP alone, one suite and a long From: nothing to drop, and the call
    # ends at once, with the limit named -- the stack not told it may send
    # past the limit over UDP
    datagram_call 5070 AES_CM_128_HMAC_SHA1_80 "$(printf 'A%.0s' $(seq 1 250))"
    if datagram_said '^transport failed [0-9]+ 1$' \
        && datagram_said '^ended UNREACHABLE 513 513 request of [0-9]+ bytes is over the 1300-byte datagram limit'; then
        pass "a challenged INVITE past 1300 bytes, nothing to trim, ended with the limit named: one suite and a long From over UDP alone, UDP past the limit not allowed, the call ended at once, 513"
    else
        fail "a challenged INVITE past 1300 bytes, nothing to trim, ended with the limit named"
        ok=1
    fi

    # The same request, the deployment saying a request of up to 1600 bytes
    # may go over UDP when no stream is coming: the connection is refused,
    # the INVITE goes as one datagram past 1300 bytes, and the call connects
    datagram_call 5070 AES_CM_128_HMAC_SHA1_80 "$(printf 'A%.0s' $(seq 1 250))" "" \
        -e SIPRAL_UDP_ANYWAY_BYTES=1600
    if datagram_said '^confirmed$' && datagram_said '^held$' && datagram_said '^resumed$' \
        && datagram_said '^ended LOCAL_HANGUP ' \
        && printf '%s\n' "$DATAGRAM_SEEN" | found -E '\(1[3-9][0-9][0-9] bytes\) from UDP:' \
        && ! printf '%s\n' "$DATAGRAM_SEEN" | found 'from TCP:'; then
        pass "a challenged INVITE past 1300 bytes, sent over UDP anyway: one suite and a long From to UDP alone, UDP past the limit allowed up to 1600 bytes, the INVITE went as one datagram and the call was held, resumed and hung up"
    else
        fail "a challenged INVITE past 1300 bytes, sent over UDP anyway"
        ok=1
    fi

    ( cd interop && docker compose exec -T asterisk asterisk -rx 'pjsip set logger off' ) >/dev/null 2>&1
    ( cd interop && docker compose up -d asterisk ) >/dev/null 2>&1
    wait_for asterisk "Asterisk Ready" >/dev/null || true
    rm -f "$DATAGRAM_MARK"
    return "$ok"
}

if [ "$WANT" = all ] || [ "$WANT" = datagram ]; then
    step "a challenged INVITE past 1300 bytes -- over TCP where Asterisk listens, trimmed or ended where it does not"
    if [ -n "$HARNESS_C" ]; then
        datagram_flow || true
    elif [ "$WANT" = datagram ]; then
        fail "the datagram flows: there is no libsipral_ffi for the Python layer to load"
    else
        printf '  note  no libsipral_ffi, so the datagram flows are skipped with the other C flows\n'
    fi
fi

# SRTP best effort (SIPRAL_SRTP_BEST_EFFORT) through the Python layer's
# datagram caller: SDES offered on plain RTP/AVP, the "SRTP optional" of desk
# phones, straight at Asterisk's tone from an account with no SRTP
# (labuser) and from one that requires SDES (labuser-srtp). The first comes
# up plain rather than answered 488, the second keyed -- what the encryption
# report says once the call is up.
best_effort_flow() {
    local ok=0
    DATAGRAM_MARK=$(mktemp)
    CALLER_ACCOUNT=labuser datagram_call 5060 "" "" "" -e SIPRAL_SRTP=best_effort
    if datagram_said '^confirmed$' && datagram_said '^protection [A-Z_]+ plain ' \
        && datagram_said '^ended LOCAL_HANGUP '; then
        pass "best-effort SRTP to an endpoint with SRTP off: SDES offered on RTP/AVP, the call came up plain rather than refused, held, resumed and hung up"
    else
        fail "best-effort SRTP to an endpoint with SRTP off"
        ok=1
    fi
    CALLER_ACCOUNT=labuser-srtp datagram_call 5060 "" "" "" -e SIPRAL_SRTP=best_effort
    if datagram_said '^confirmed$' && datagram_said '^protection SDES encrypted ' \
        && datagram_said '^ended LOCAL_HANGUP '; then
        pass "best-effort SRTP to an endpoint with SDES on: SDES offered on RTP/AVP, the answer took a key and the call was encrypted, held, resumed and hung up"
    else
        fail "best-effort SRTP to an endpoint with SDES on"
        ok=1
    fi
    rm -f "$DATAGRAM_MARK"
    return "$ok"
}

if [ "$WANT" = all ] || [ "$WANT" = security ] || [ "$WANT" = besteffort ]; then
    step "SRTP best effort through the Python layer -- straight at Asterisk, SRTP off and SDES on"
    if [ -n "$HARNESS_C" ]; then
        best_effort_flow || true
    elif [ "$WANT" != all ]; then
        fail "the best-effort SRTP flows: there is no libsipral_ffi for the Python layer to load"
    else
        printf '  note  no libsipral_ffi, so the best-effort SRTP flows are skipped with the other C flows\n'
    fi
fi

# RFC 3263 through the Python layer's datagram caller, with Asterisk on its
# datagram listeners (UDP and TCP on 5060, UDP alone on 5070): a registrar
# named by its host name, found by the A record Docker's own DNS answers for
# it, registered at and called through; then a server named by a domain
# nothing resolves, found by the SRV record a resolver of the application's
# own gives for it -- port 5070 and the host `asterisk` -- and called
# through. The stack asks; the layer answers with the resolver it was given.
locate_flow() {
    local ok=0
    DATAGRAM_MARK=$(mktemp)
    ( cd interop && docker compose -f compose.yaml -f datagram/compose.override.yaml up -d asterisk ) \
        >/dev/null 2>&1 || { fail "Asterisk could not be restarted with its datagram listeners"; return 1; }
    wait_for asterisk "Asterisk Ready" >/dev/null \
        || { fail "Asterisk did not come back with its datagram listeners"; return 1; }
    ( cd interop && docker compose exec -T asterisk asterisk -rx 'pjsip set logger on' ) >/dev/null 2>&1

    CALLER_ACCOUNT=labuser datagram_call 5060 "" "" "" \
        -e SIPRAL_SRTP=off -e SIPRAL_SERVER_URI=sip:asterisk -e SIPRAL_REGISTER=1
    if datagram_said '^located [0-9.]+:5060(,|$)' && datagram_said '^registration REGISTERED$' \
        && datagram_said '^confirmed$' && datagram_said '^ended LOCAL_HANGUP ' \
        && datagram_said '^registration UNREGISTERED$'; then
        pass "a registrar named by its host name, located by its A record through the lab's DNS: registered at the address found, called the tone through it, hung up and unregistered"
    else
        fail "a registrar named by its host name, located by its A record through the lab's DNS"
        ok=1
    fi

    datagram_call 5070 AES_CM_128_HMAC_SHA1_80 "" "" \
        -e SIPRAL_SERVER_URI=sip:lab.sipral.test -e "SIPRAL_SRV=60 10 50 5070 asterisk"
    if datagram_said '^located [0-9.]+:5070(,|$)' && datagram_said '^confirmed$' \
        && datagram_said '^ended LOCAL_HANGUP ' \
        && printf '%s\n' "$DATAGRAM_SEEN" | found 'from UDP:'; then
        pass "a server named by a domain, located by an SRV record from the application's resolver: the domain has no address of its own, the record named port 5070 of the lab's Asterisk, and the call went there and was hung up"
    else
        fail "a server named by a domain, located by an SRV record from the application's resolver"
        ok=1
    fi

    ( cd interop && docker compose exec -T asterisk asterisk -rx 'pjsip set logger off' ) >/dev/null 2>&1
    ( cd interop && docker compose up -d asterisk ) >/dev/null 2>&1
    wait_for asterisk "Asterisk Ready" >/dev/null || true
    rm -f "$DATAGRAM_MARK"
    return "$ok"
}

if [ "$WANT" = all ] || [ "$WANT" = locate ]; then
    step "a server by name -- RFC 3263 from the Python layer, straight at Asterisk"
    if [ -n "$HARNESS_C" ]; then
        locate_flow || true
    elif [ "$WANT" = locate ]; then
        fail "the location flows: there is no libsipral_ffi for the Python layer to load"
    else
        printf '  note  no libsipral_ffi, so the location flows are skipped with the other C flows\n'
    fi
fi

if [ "$WANT" = all ] || [ "$WANT" = robust ]; then
    step "the field failures -- a link that drops fragments, and connections nobody answers on, in C"
    if [ -n "$HARNESS_C" ]; then
        robust_link_flow \
            && pass "fragments dropped; the 1300-byte INVITE went as a datagram, the 1301- and 1600-byte ones over TCP; both silent connections ended the call by Timer B" \
            || fail "the field failures over a bad link"
        step "the NAT pair with its first STUN server dead -- C calling, Rust answering"
        robust_stun_failover \
            && pass "both ends moved to coturn after the dead server, and the call crossed both NATs" \
            || fail "the NAT pair with its first STUN server dead"
    elif [ "$WANT" = robust ]; then
        fail "the field failures: there is no C harness to run them with"
    else
        printf '  note  no C harness, so the field failures are skipped with the other C flows\n'
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
    lab_run "the PipeWire step" $((LAB_START_BUILD_S + LAB_CALL_S)) --network "$LAB_NETWORK" \
        -v "$ROOT:/src:ro" -v sipral-pipewire-target:/target \
        -e CARGO_TARGET_DIR=/target -w /src \
        sipral-pipewire bash interop/pipewire/run.sh call \
        && pass "sipral-io-pipewire, and a call carried on it" \
        || fail "interop/pipewire/run.sh call"
fi

# Sipral's headless agent and pjsua, one after the other, through the same
# scenarios against the same Asterisk: interop/compare/compare.sh says what
# and how, and docs/23-compared-with-pjsip.md reports a run of it.
if [ "$WANT" = compare ]; then
    # shellcheck source=interop/compare/compare.sh
    . "$ROOT/interop/compare/compare.sh"
    compare_run "$HEADLESS_AGENT" || fail "the comparison with PJSIP"
fi

step "the capture"
ls -l interop/pcap || true

printf '\n'
[ "$FAIL" -eq 0 ] && { printf 'the lab agrees\n'; exit 0; }
printf 'the lab does not agree\n'; exit 1
