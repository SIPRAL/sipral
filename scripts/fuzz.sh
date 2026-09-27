#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# Every fuzz target, for as long as you give it.
#
#   scripts/fuzz.sh            five minutes a target
#   scripts/fuzz.sh 3600       an hour a target
#   scripts/fuzz.sh 60 parse   one target, one minute
#
# Not a part of scripts/check.sh: thirty targets at five minutes each would
# add two and a half hours to every commit and buy very little, since the
# corpus only grows when something new reaches it. The gate builds them
# instead, so they cannot rot uncompiled. Run this before a release, and
# overnight on a machine that has nothing better to do.
#
# `fuzz/` is a workspace of its own with its own nightly pin, because libFuzzer
# needs one and the rest of the tree does not.
#
# Two corpus directories per target, and the order matters. libFuzzer writes
# what it finds into the first one, so that is a scratch under `fuzz/target/`,
# which is ignored; `fuzz/corpus/<target>` comes second and is read only. The
# seeds are committed and a run must not push a thousand mutations in beside
# them -- an input worth keeping is copied in on purpose, with the commit that
# says why.
set -uo pipefail

cd "$(dirname "$0")/../fuzz"

SECONDS_EACH="${1:-300}"
ONLY="${2:-}"

command -v cargo-fuzz >/dev/null 2>&1 || {
    printf 'cargo-fuzz is not installed: cargo install cargo-fuzz\n'
    printf 'It also needs the nightly this directory pins, which\n'
    printf 'rustup toolchain install picks up from fuzz/rust-toolchain.toml.\n'
    exit 2
}

FAIL=0
for target in $(cargo fuzz list); do
    [ -n "$ONLY" ] && [ "$target" != "$ONLY" ] && continue
    printf '\n%s, %s seconds\n' "$target" "$SECONDS_EACH"
    FOUND="target/corpus/$target"
    mkdir -p "$FOUND"
    if cargo fuzz run "$target" "$FOUND" "corpus/$target" -- \
        -max_total_time="$SECONDS_EACH" -max_len=65535 -rss_limit_mb=2048; then
        printf '  ok    %s found nothing\n' "$target"
    else
        printf '  FAIL  %s: the input that did it is under fuzz/artifacts/%s\n' \
            "$target" "$target"
        FAIL=1
    fi
done

printf '\n'
[ "$FAIL" -eq 0 ] && { printf 'nothing found\n'; exit 0; }
printf 'something was found; the crashing input is kept\n'; exit 1
