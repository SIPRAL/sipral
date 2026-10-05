#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# The version every artefact ships under, from one source: `version` in
# Cargo.toml's [workspace.package]. Every other file that carries a copy --
# the crates' own dependencies on each other, sipral-aec-webrtc's own
# version (it is outside the workspace), the three lockfiles, the .NET
# project and the constant the layer reports, the Python project and its
# `__version__`, the Pipecat integration's project and its `__version__`,
# the Dart package, the React Native package and its lockfile, the JVM POM
# -- is written from it here and held to it here.
# What reads the version at build time instead (the podspec and the React
# Native Gradle build read package.json, every other crate inherits the
# workspace's, each script under scripts/package/ reads Cargo.toml) has no
# copy to keep. The C header's version macros are the ABI's, printed by
# tools/abi-gen, and are not a package version: nothing here touches them.
#
#   scripts/version.sh            prints the workspace version
#   scripts/version.sh --check    every carrier says the workspace version;
#                                 exits 1 naming each one that does not
#   scripts/version.sh X.Y.Z      writes X.Y.Z into every carrier, then
#                                 checks
#
# X.Y.Z is three numbers and nothing else: a pre-release suffix is spelled
# differently by each registry (1.0.0-rc.1 on crates.io, NuGet and npm,
# 1.0.0rc1 on PyPI), so one string cannot be all of them. The Python
# projects' Development Status classifier follows the major: Pre-Alpha
# below 1, Production/Stable from 1 on.
set -uo pipefail

cd "$(dirname "$0")/.."

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }

# `simple MODE FILE AFTER PREFIX SUFFIX [ANY]`: the first line, after the
# line AFTER (or from the top when it is empty), that is PREFIX, a version,
# SUFFIX. MODE read prints the version; MODE write prints FILE with $NEW in
# its place. ANY accepts any text between the two, for the classifier.
simple() {
    awk -v mode="$1" -v new="${NEW:-}" -v after="$3" -v p="$4" -v s="$5" -v any="${6:-0}" '
        BEGIN { armed = (after == "") }
        !done && armed && index($0, p) == 1 && length($0) > length(p) + length(s) \
            && substr($0, length($0) - length(s) + 1) == s {
            mid = substr($0, length(p) + 1, length($0) - length(p) - length(s))
            if (any || mid ~ /^[0-9A-Za-z.+-]+$/) {
                done = 1
                if (mode == "read") print mid
                else $0 = p new s
            }
        }
        !armed && $0 == after { armed = 1 }
        mode == "write" { print }
    ' "$2"
}

# `deps MODE FILE`: every dependency on a Sipral crate written inline with
# both a path and a version, `sipral-core = { path = "...", version = "..." }`.
# Cargo refuses a path dependency whose version requirement the crate at that
# path does not meet, so these move with the workspace.
deps() {
    awk -v mode="$1" -v new="${NEW:-}" '
        /^sipral[a-z0-9-]* = \{.*path = "[^"]*".*version = "[^"]*"/ {
            match($0, /version = "[^"]*"/)
            if (mode == "read") print substr($0, RSTART + 11, RLENGTH - 12)
            else $0 = substr($0, 1, RSTART - 1) "version = \"" new "\"" substr($0, RSTART + RLENGTH)
        }
        mode == "write" { print }
    ' "$2"
}

# `lock MODE FILE`: the entries of a Cargo.lock for this workspace's own
# crates (a `name` in $NAMES and no `source`, so built from a path).
lock() {
    awk -v mode="$1" -v new="${NEW:-}" -v names=" $NAMES " '
        function flush(   i, l, hit) {
            hit = (nm != "" && index(names, " " nm " ") && !src)
            for (i = 1; i <= n; i++) {
                l = buf[i]
                if (hit && l ~ /^version = "/) {
                    if (mode == "read") print substr(l, 12, length(l) - 12)
                    else l = "version = \"" new "\""
                }
                if (mode == "write") print l
            }
            n = 0; nm = ""; src = 0
        }
        /^\[\[package\]\]$/ { flush() }
        {
            buf[++n] = $0
            if ($0 ~ /^name = "/) nm = substr($0, 9, length($0) - 9)
            if ($0 ~ /^source = /) src = 1
        }
        END { flush() }
    ' "$2"
}

# The Development Status classifier the version calls for.
status_of() {
    case "$1" in
        0.*) printf '2 - Pre-Alpha' ;;
        *) printf '5 - Production/Stable' ;;
    esac
}

MANIFESTS="Cargo.toml $(ls crates/*/Cargo.toml tools/*/Cargo.toml) interop/harness/Cargo.toml fuzz/Cargo.toml"
LOCKS="Cargo.lock crates/sipral-aec-webrtc/Cargo.lock fuzz/Cargo.lock"
NAMES=""
for f in crates/*/Cargo.toml tools/*/Cargo.toml interop/harness/Cargo.toml; do
    NAMES="$NAMES $(sed -n 's/^name = "\(.*\)"$/\1/p' "$f" | head -1)"
done

# `carriers MODE`: every place a version is written. In read mode, one
# `FILE|KIND|VERSION` line per place, VERSION empty when a carrier that must
# be there is not.
SIMPLE_CARRIERS=(
    'Cargo.toml|[workspace.package]|version = "|"'
    'crates/sipral-aec-webrtc/Cargo.toml|[package]|version = "|"'
    'bindings/dotnet/Sipral/Sipral.csproj||    <Version>|</Version>'
    'bindings/dotnet/Sipral/SipralInfo.cs||    public const string Version = "|";'
    'bindings/python/pyproject.toml|[project]|version = "|"'
    'bindings/python/sipral/__init__.py||__version__ = "|"'
    'integrations/pipecat/pyproject.toml|[project]|version = "|"'
    'integrations/pipecat/sipral_pipecat/__init__.py||__version__ = "|"'
    'bindings/dart/pubspec.yaml||version: |'
    'bindings/react-native/package.json||  "version": "|",'
    'bindings/react-native/package-lock.json||  "version": "|",'
    'bindings/react-native/package-lock.json|    "": {|      "version": "|",'
    'bindings/jvm/pom.xml||        <revision>|</revision>'
)
CLASSIFIER=(
    'bindings/python/pyproject.toml||    "Development Status :: |",'
    'integrations/pipecat/pyproject.toml||    "Development Status :: |",'
)

carriers() {
    local mode="$1" entry file after prefix suffix any classifier found value tmp
    for entry in "${SIMPLE_CARRIERS[@]}" "${CLASSIFIER[@]}"; do
        IFS='|' read -r file after prefix suffix <<<"$entry"
        any=0
        for classifier in "${CLASSIFIER[@]}"; do
            [ "$entry" = "$classifier" ] && any=1
        done
        if [ "$mode" = "read" ]; then
            found=$(simple read "$file" "$after" "$prefix" "$suffix" "$any")
            printf '%s|%s|%s\n' "$file" "$([ "$any" -eq 1 ] && printf classifier || printf version)" "$found"
        else
            tmp=$(mktemp)
            if [ "$any" -eq 1 ]; then
                NEW="$(status_of "$NEW")" simple write "$file" "$after" "$prefix" "$suffix" 1 >"$tmp"
            else
                simple write "$file" "$after" "$prefix" "$suffix" >"$tmp"
            fi
            cmp -s "$tmp" "$file" || cat "$tmp" >"$file"
            rm -f "$tmp"
        fi
    done
    for file in $MANIFESTS; do
        if [ "$mode" = "read" ]; then
            deps read "$file" | while read -r value; do printf '%s|dependency|%s\n' "$file" "$value"; done
        else
            tmp=$(mktemp); deps write "$file" >"$tmp"; cmp -s "$tmp" "$file" || cat "$tmp" >"$file"; rm -f "$tmp"
        fi
    done
    for file in $LOCKS; do
        if [ "$mode" = "read" ]; then
            lock read "$file" | while read -r value; do printf '%s|lock entry|%s\n' "$file" "$value"; done
        else
            tmp=$(mktemp); lock write "$file" >"$tmp"; cmp -s "$tmp" "$file" || cat "$tmp" >"$file"; rm -f "$tmp"
        fi
    done
}

workspace_version() {
    simple read Cargo.toml '[workspace.package]' 'version = "' '"'
}

# Every carrier against VERSION; prints a FAIL per one that differs.
check_against() {
    local want="$1" status file kind value count=0
    status="$(status_of "$want")"
    while IFS='|' read -r file kind value; do
        count=$((count + 1))
        if [ -z "$value" ]; then
            fail "$file: no $kind found where this script looks for one"
        elif [ "$kind" = "classifier" ]; then
            [ "$value" = "$status" ] || fail "$file: Development Status :: $value, and $want calls for $status"
        elif [ "$value" != "$want" ]; then
            fail "$file: $kind $value, not $want"
        fi
    done < <(carriers read)
    [ "$FAIL" -eq 0 ] && pass "$count places carry the version, and every one says $want"
}

case "${1:-}" in
    "")
        workspace_version
        ;;
    --check)
        check_against "$(workspace_version)"
        exit "$FAIL"
        ;;
    -h|--help)
        # the comment at the top, after the SPDX and copyright lines
        awk 'NR < 5 { next } !/^#/ { exit } { sub(/^# ?/, ""); print }' "$0"
        ;;
    *)
        NEW="$1"
        if ! printf '%s\n' "$NEW" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
            printf 'version.sh: %s is not X.Y.Z (three numbers, no suffix)\n' "$NEW" >&2
            exit 2
        fi
        missing=$(carriers read | awk -F'|' '$3 == "" { print "  " $1 ": no " $2 " found" }')
        if [ -n "$missing" ]; then
            printf 'version.sh: not written, a carrier is not where this script looks for it:\n%s\n' "$missing" >&2
            exit 1
        fi
        OLD="$(workspace_version)"
        carriers write
        printf 'version.sh: %s -> %s\n' "$OLD" "$NEW"
        check_against "$NEW"
        exit "$FAIL"
        ;;
esac
