#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# The Dart and Flutter artefact: the `sipral` package on pub.dev, from
# bindings/dart.
#
#   scripts/package/pub.sh --out DIR [--dry-run] [--publish]
#
# DIR is outside any git work tree: dart pub applies the enclosing tree's
# ignore rules to the package it validates.
#
# bindings/dart/pubspec.yaml carries `publish_to: none`, so that a
# `dart pub publish` run by mistake in the checkout goes nowhere. What
# publishes is a staged copy, DIR/sipral: the package's committed files, the
# pubspec without that line, the licence texts from the repository root
# (pub.dev wants a LICENSE beside the pubspec) and a CHANGELOG.md for this
# version that points at the project's own. `dart pub publish --dry-run`
# then validates it the way pub.dev will, on any host with the Dart SDK.
# The package is Dart over dart:ffi and carries no native library; the
# application brings libsipral_ffi (bindings/dart/README.md). Nothing is
# uploaded: --publish prints the command the owner runs in DIR/sipral.
set -uo pipefail

cd "$(dirname "$0")/../.."

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
step() { printf '\n%s\n' "$1"; }
finish() {
    printf '\n'
    [ "$FAIL" -eq 0 ] && { printf 'pub.sh: done%s, %s\n' "$([ "$DRY_RUN" -eq 1 ] && printf ' (dry-run)')" "$STAGE"; exit 0; }
    printf 'pub.sh: failed\n'; exit 1
}

OUT=""
DRY_RUN=0
PUBLISH=0
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --publish) PUBLISH=1; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -z "$OUT" ] && { printf 'usage: pub.sh --out DIR [--dry-run] [--publish]\n' >&2; exit 2; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
STAGE="$OUT/sipral"
# dart pub validates a package inside a git work tree against that tree's
# ignore rules, so a stage under this repository's ignored target/ would be
# a package with every file hidden
if git -C "$OUT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    printf 'pub.sh: %s is inside a git work tree, whose ignore rules dart pub applies to the staged package; name a directory outside it\n' "$OUT" >&2
    exit 2
fi

step "one version"
scripts/version.sh --check || FAIL=1
VERSION="$(scripts/version.sh)"
command -v dart >/dev/null 2>&1 || { fail "dart not found (the Dart SDK, or Flutter's)"; finish; }

step "the staged package, $STAGE"
rm -rf "$STAGE"
mkdir -p "$STAGE"
git ls-files -z bindings/dart | while IFS= read -r -d '' f; do
    mkdir -p "$STAGE/$(dirname "${f#bindings/dart/}")"
    cp "$f" "$STAGE/${f#bindings/dart/}"
done
[ -f "$STAGE/pubspec.yaml" ] && pass "bindings/dart's committed files" || { fail "nothing staged from bindings/dart"; finish; }
if grep -qx 'publish_to: none' "$STAGE/pubspec.yaml"; then
    grep -vx 'publish_to: none' "$STAGE/pubspec.yaml" >"$STAGE/pubspec.yaml.new" && mv "$STAGE/pubspec.yaml.new" "$STAGE/pubspec.yaml"
    pass "publish_to: none taken out of the staged pubspec"
else
    fail "bindings/dart/pubspec.yaml has lost its publish_to: none guard"
fi
cp LICENSE "$STAGE/LICENSE"
cp LICENSE-COMMERCIAL.md THIRD-PARTY-NOTICES.md "$STAGE/"
pass "LICENSE, LICENSE-COMMERCIAL.md and THIRD-PARTY-NOTICES.md from the repository root"
printf '## %s\n\nWhat changed in this version, across every part of Sipral, is in the\nproject'"'"'s changelog: https://github.com/SIPRAL/sipral/blob/main/CHANGELOG.md\n' \
    "$VERSION" >"$STAGE/CHANGELOG.md"
pass "CHANGELOG.md for $VERSION"

step "dart pub publish --dry-run"
if (cd "$STAGE" && { dart pub get --offline >"$OUT/pub-get.log" 2>&1 || dart pub get >>"$OUT/pub-get.log" 2>&1; }); then
    pass "dart pub get"
else
    fail "dart pub get:"; tail -20 "$OUT/pub-get.log" | sed 's/^/        /'; finish
fi
if (cd "$STAGE" && dart pub publish --dry-run) >"$OUT/publish-dry-run.log" 2>&1; then
    pass "pub.dev's own validation: $(grep -E 'Package has' "$OUT/publish-dry-run.log" | tail -1)"
else
    fail "dart pub publish --dry-run:"; sed 's/^/        /' "$OUT/publish-dry-run.log"
fi
rm -rf "$STAGE/.dart_tool" "$STAGE/pubspec.lock"

if [ "$PUBLISH" -eq 1 ]; then
    step "publish"
    printf '  not run: the owner publishes, logged in to pub.dev:\n'
    printf '    cd %s && dart pub publish\n' "$STAGE"
fi

finish
