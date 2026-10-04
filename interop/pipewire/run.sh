#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# sipral-io-pipewire against a real PipeWire, inside the image
# interop/pipewire/Dockerfile builds, from a checkout mounted into it:
#
#   interop/pipewire/run.sh          the crate's tests, the ones that need a
#                                    running graph included
#   interop/pipewire/run.sh call     the same, then a call to the lab's
#                                    Asterisk whose microphone and earpiece
#                                    are PipeWire nodes (scripts/lab.sh
#                                    pipewire runs this on the lab network)
#
# There is no sound card in a container, so the graph is made of two
# virtual cables: a mono sink whose samples come straight out of a mono
# source. "The mouth" (sink sipral-mouth, source sipral-mic) is the room a
# microphone listens to; "the ear" (sink sipral-ear, source
# sipral-ear-monitor) is what an earpiece plays into, read back to check what
# arrived. The graph is driven by PipeWire's own dummy driver.
#
# The daemon, the session manager and the session bus they share are
# started here rather than by the image, because a container has no user
# session to start them.
set -euo pipefail

cd "$(dirname "$0")/../.."

export XDG_RUNTIME_DIR=/tmp/sipral-pw-runtime
mkdir -p "$XDG_RUNTIME_DIR"
chmod 0700 "$XDG_RUNTIME_DIR"
LOGS="$XDG_RUNTIME_DIR/logs"
mkdir -p "$LOGS"

# waits for a condition for up to ten seconds, and says what it was waiting
# for when it gives up
wait_for() {
    local what="$1" tries=0
    shift
    until "$@" >/dev/null 2>&1; do
        tries=$((tries + 1))
        if [ "$tries" -ge 100 ]; then
            printf 'never happened: %s\n' "$what"
            tail -20 "$LOGS"/*.log
            exit 1
        fi
        sleep 0.1
    done
}

dbus-daemon --session --fork --print-address=1 >"$LOGS/bus" \
    --address="unix:path=$XDG_RUNTIME_DIR/bus"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"

pipewire >"$LOGS/pipewire.log" 2>&1 &
wait_for "the PipeWire socket" test -S "$XDG_RUNTIME_DIR/pipewire-0"
wireplumber >"$LOGS/wireplumber.log" 2>&1 &
wait_for "the session manager" sh -c 'wpctl status | grep -q "PipeWire"'

# one mono cable: a sink, and a source that says what the sink was given
cable() {
    pw-loopback -m '[ MONO ]' \
        --capture-props="media.class=Audio/Sink node.name=$1 node.description=$1" \
        --playback-props="media.class=Audio/Source node.name=$2 node.description=$2" \
        >"$LOGS/cable-$1.log" 2>&1 &
}
cable sipral-mouth sipral-mic
cable sipral-ear sipral-ear-monitor
for node in sipral-mouth sipral-mic sipral-ear sipral-ear-monitor; do
    wait_for "the node $node" sh -c "pw-cli ls Node | grep -q 'node.name = \"$node\"'"
done
printf 'the graph:\n'
wpctl status | sed -n '/^Audio/,/^Video/p'

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}"
printf '\nthe crate, against it:\n'
cargo test --locked -p sipral-io-pipewire -- --include-ignored --nocapture --test-threads=1

if [ "${1:-}" = call ]; then
    printf '\na call to the lab, through it:\n'
    cargo build --locked --release -p sipral-interop --features pipewire
    SIPRAL_FLOWS=pipewire "${CARGO_TARGET_DIR:-target}/release/sipral-interop" asterisk 5060
fi
