#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# The numbers in docs/19-numbers.md, measured rather than remembered.
#
#   scripts/bench.sh            everything below, printed as the document's
#                               own table rows
#
# What it measures, and what each number is worth knowing:
#
# - the shared library's size, stripped, for this platform: what an
#   application ships, and the first question every integrator asks;
# - the cost of one frame of audio, in thread time, with two hundred calls
#   running on four threads (crates/sipral-ffi's own load test): what decides
#   how many calls a machine holds;
# - the peak memory of that run against the same run with one call: the
#   difference over a hundred and ninety-nine is what a call costs;
# - how long opening a stack takes, and how long bringing one call up takes;
# - a hundred calls' worth of signalling, then a thousand, between two stacks
#   (crates/sipral-ffi/tests/signalling_load.rs): every call challenged,
#   answered, held, resumed and hung up, with the thread time each end spent
#   per call set up and per transaction, the messages a second one stack gets
#   through, and the memory a live call holds at each end, counted by that
#   test's own allocator rather than read off the operating system.
#
# Everything here runs in this process, against the library, with no network
# underneath it: what is measured is the library's own cost. A lab run's own
# result line (scripts/lab.sh) is where end-to-end audio is measured instead.
#
# The load test is a test, not a benchmark harness: the same run that prints
# these numbers also fails if a session was ever found locked by another
# thread, which is the claim the numbers are only interesting alongside.
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
# where cargo actually puts things: a container build points CARGO_TARGET_DIR
# somewhere else, and a script that assumes ./target measures nothing there
TARGET="${CARGO_TARGET_DIR:-$ROOT/target}"
RSS_FILE="$(mktemp)"
trap 'rm -f "$RSS_FILE"' EXIT

# A minute of audio per call rather than the five seconds the gate runs, so
# the per-frame figure is taken over a long enough run to settle.
FRAMES="${SIPRAL_LOAD_FRAMES:-3000}"
CALLS="${SIPRAL_LOAD_CALLS:-200}"
# The signalling runs: the hundred the gate runs as well, and ten times that,
# which is past the default ceilings on dialogs and server transactions and
# so also says what raising them costs.
SIGNALLING="${SIPRAL_SIGNALLING_RUNS:-100 1000}"

printf 'sipral %s, %s, %s\n' \
    "$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)" \
    "$(date -u +%F)" \
    "$(uname -sm)"
printf 'rustc: %s\n\n' "$(rustc --version)"

# The library, stripped the way a release artefact is: cargo's own release
# profile keeps symbols the platform's linker is happy to drop.
step_library() {
    cargo build --release -p sipral-ffi >/dev/null 2>&1 || {
        printf 'library: cargo build -p sipral-ffi failed\n'
        return 1
    }
    local lib size stripped
    for name in libsipral_ffi.dylib libsipral_ffi.so sipral_ffi.dll; do
        [ -f "$TARGET/release/$name" ] && lib="$TARGET/release/$name"
    done
    [ -n "${lib:-}" ] || { printf 'library: nothing built to measure\n'; return 1; }
    size=$(wc -c < "$lib" | tr -d ' ')
    stripped="$(mktemp)"
    cp "$lib" "$stripped"
    # -S -x on Apple's strip, plain strip elsewhere. The release profile
    # carries no debug information to begin with, so the two numbers are
    # usually the same; printing both is what says so.
    strip -S -x "$stripped" 2>/dev/null || strip "$stripped" 2>/dev/null || true
    printf 'library %s: %s bytes, %s stripped\n' \
        "$(basename "$lib")" "$size" "$(wc -c < "$stripped" | tr -d ' ')"
    rm -f "$stripped"
}

# The load test prints its own line; this runs it twice, once with the calls
# asked for and once with a single call, and reads peak memory from the
# platform's own timer around each run. macOS reports bytes, GNU time
# kilobytes, which is why each is read where it is printed rather than
# converted blind.
step_load() {
    local calls="$1" out rss
    out="$(mktemp)"
    if /usr/bin/time -l env SIPRAL_LOAD_CALLS="$calls" SIPRAL_LOAD_FRAMES="$FRAMES" \
        cargo test --release -q -p sipral-ffi --lib load -- --nocapture >"$out" 2>&1; then
        :
    elif /usr/bin/time -v env SIPRAL_LOAD_CALLS="$calls" SIPRAL_LOAD_FRAMES="$FRAMES" \
        cargo test --release -q -p sipral-ffi --lib load -- --nocapture >"$out" 2>&1; then
        :
    else
        printf 'load(%s): the test did not pass; its output:\n' "$calls"
        sed 's/^/    /' "$out"
        rm -f "$out"
        return 1
    fi
    # the test's own line, which the runner prefixes with its progress dots
    grep -o 'load: .*' "$out" | sed 's/^/    /'
    # Apple's time prints "<bytes>  maximum resident set size", GNU's
    # "Maximum resident set size (kbytes): <n>": the same number with the
    # count on either side of the words, in either bytes or kilobytes
    if grep -qi 'Maximum resident set size (kbytes)' "$out"; then
        rss=$(sed -n 's/.*Maximum resident set size (kbytes): *\([0-9]*\).*/\1/p' "$out" | head -1)
        rss=$((rss * 1024))
    else
        rss=$(awk '/maximum resident set size/ {print $1; exit}' "$out")
    fi
    printf '    peak memory: %s bytes\n' "${rss:-unknown}"
    rm -f "$out"
    printf '%s' "${rss:-0}" > "$RSS_FILE"
}

printf 'library\n'
step_library

# built before anything is measured: a run that compiles the test first
# reports the compiler's own memory, which on a cold checkout is hundreds of
# megabytes and has nothing to do with a call
cargo test --release -q -p sipral-ffi --lib load --no-run >/dev/null 2>&1 \
    || printf 'note: the load test would not build; the numbers below say so\n'
cargo test --release -q -p sipral-ffi --test signalling_load --no-run >/dev/null 2>&1 \
    || printf 'note: the signalling test would not build; the numbers below say so\n'

printf '\nload, %s calls, %s frames each\n' "$CALLS" "$FRAMES"
step_load "$CALLS"
many=$(cat "$RSS_FILE" 2>/dev/null || printf '0')

printf '\nload, one call, %s frames\n' "$FRAMES"
step_load 1
one=$(cat "$RSS_FILE" 2>/dev/null || printf '0')

if [ "$many" -gt "$one" ] && [ "$CALLS" -gt 1 ]; then
    printf '\nmemory per call: %s bytes (%s calls against one)\n' \
        "$(( (many - one) / (CALLS - 1) ))" "$CALLS"
fi

# The signalling test prints its own line, and fails -- printing everything
# it said -- if a call ended the wrong way or a message went missing.
STATUS=0
for count in $SIGNALLING; do
    printf '\nsignalling, %s calls\n' "$count"
    out="$(mktemp)"
    if SIPRAL_SIGNALLING_CALLS="$count" cargo test --release -q -p sipral-ffi \
        --test signalling_load -- --nocapture >"$out" 2>&1; then
        grep -o 'signalling: .*' "$out" | sed 's/^/    /'
    else
        printf 'signalling(%s): the test did not pass; its output:\n' "$count"
        sed 's/^/    /' "$out"
        STATUS=1
    fi
    rm -f "$out"
done
exit "$STATUS"
