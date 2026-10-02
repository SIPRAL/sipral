#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# The React Native artefact: sipral-react-native-<version>.tgz for npm, from
# bindings/react-native.
#
#   scripts/package/npm.sh --out DIR [--dry-run] [--publish]
#
# Packs a staged copy, DIR/stage: the package's committed files and the
# licence texts from the repository root, which npm puts in every tarball
# when they sit beside package.json. `files` in package.json decides the
# rest; the tarball's listing is then held to it: the TypeScript API, both
# native halves and the podspec in, the tests and node_modules out. With
# --dry-run it is `npm pack --dry-run` and no tarball; without, the tarball
# lands in DIR. Either runs on any host with npm, and needs neither
# node_modules nor the network. The Android half resolves the Kotlin layer
# as a Maven artefact and the iOS half the Swift package, so neither is in
# the tarball; bindings/react-native/README.md says what an application
# adds. Nothing is uploaded: --publish prints the command the owner runs.
set -uo pipefail

cd "$(dirname "$0")/../.."
ROOT="$PWD"

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
step() { printf '\n%s\n' "$1"; }
finish() {
    printf '\n'
    [ "$FAIL" -eq 0 ] && { printf 'npm.sh: done%s, %s\n' "$([ "$DRY_RUN" -eq 1 ] && printf ' (dry-run)')" "${TARBALL:-$OUT}"; exit 0; }
    printf 'npm.sh: failed\n'; exit 1
}

OUT=""
DRY_RUN=0
PUBLISH=0
TARBALL=""
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --publish) PUBLISH=1; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -z "$OUT" ] && { printf 'usage: npm.sh --out DIR [--dry-run] [--publish]\n' >&2; exit 2; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
STAGE="$OUT/stage"

step "one version"
scripts/version.sh --check || FAIL=1
VERSION="$(scripts/version.sh)"
for tool in npm node; do
    command -v "$tool" >/dev/null 2>&1 || { fail "$tool not found"; finish; }
done

step "package.json, as npm will show it"
# name, version, description, licence, repository, homepage, keywords, and
# an author with no address in it
node -e '
const p = require(process.argv[1]);
const problems = [];
for (const k of ["name", "version", "description", "license", "homepage", "author"]) if (!p[k]) problems.push("no " + k);
if (!p.repository || !p.repository.url) problems.push("no repository url");
if (!Array.isArray(p.keywords) || p.keywords.length === 0) problems.push("no keywords");
if (JSON.stringify(p).match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/)) problems.push("an address");
if (p.dependencies && Object.keys(p.dependencies).length) problems.push("runtime dependencies");
process.stdout.write(problems.join(", "));
process.exit(problems.length ? 1 : 0);
' "$ROOT/bindings/react-native/package.json" >"$OUT/manifest.txt" 2>&1 \
    && pass "name, version, description, licence, repository, homepage, keywords, author" \
    || fail "bindings/react-native/package.json: $(cat "$OUT/manifest.txt")"

step "the staged package, $STAGE"
rm -rf "$STAGE"
mkdir -p "$STAGE"
git ls-files -z bindings/react-native | while IFS= read -r -d '' f; do
    mkdir -p "$STAGE/$(dirname "${f#bindings/react-native/}")"
    cp "$f" "$STAGE/${f#bindings/react-native/}"
done
[ -f "$STAGE/package.json" ] && pass "bindings/react-native's committed files" || { fail "nothing staged from bindings/react-native"; finish; }
cp LICENSE LICENSE-COMMERCIAL.md "$STAGE/"
pass "LICENSE and LICENSE-COMMERCIAL.md from the repository root"

if [ "$DRY_RUN" -eq 1 ]; then
    step "npm pack --dry-run"
    PACK_ARGS=(pack --dry-run --json --ignore-scripts)
else
    step "npm pack"
    PACK_ARGS=(pack --json --ignore-scripts --pack-destination "$OUT")
fi
if (cd "$STAGE" && npm "${PACK_ARGS[@]}") >"$OUT/pack.json" 2>"$OUT/pack.log"; then
    pass "npm ${PACK_ARGS[*]}"
else
    fail "npm ${PACK_ARGS[*]}:"; tail -20 "$OUT/pack.log" | sed 's/^/        /'; finish
fi
node -e '
const r = require(process.argv[1])[0];
console.log(r.filename);
for (const f of r.files) console.log(f.path);
' "$OUT/pack.json" >"$OUT/pack.list"
NAME=$(head -1 "$OUT/pack.list")
[ "$NAME" = "sipral-react-native-$VERSION.tgz" ] && pass "$NAME" || fail "npm names the tarball '$NAME', not sipral-react-native-$VERSION.tgz"
for f in package.json README.md LICENSE LICENSE-COMMERCIAL.md src/index.ts src/NativeSipral.ts \
    sipral-react-native.podspec android/build.gradle.kts; do
    grep -qx "$f" "$OUT/pack.list" && pass "carries $f" || fail "missing $f"
done
grep -q '^ios/.*\.mm$' "$OUT/pack.list" && pass "carries the iOS module (ios/*.mm)" || fail "no ios/*.mm in the tarball"
grep -q '^android/src/' "$OUT/pack.list" && pass "carries the Android sources" || fail "no android/src in the tarball"
leaked=$(grep -E '__tests__|^node_modules/|jvm-check|\.test\.ts$' "$OUT/pack.list" || true)
[ -z "$leaked" ] && pass "no tests and no node_modules in the tarball" || {
    fail "the tarball carries what it should not:"; printf '%s\n' "$leaked" | sed 's/^/        /'; }
count=$(($(wc -l <"$OUT/pack.list") - 1))
pass "$count files in all, listed in $OUT/pack.list"
[ "$DRY_RUN" -eq 0 ] && TARBALL="$OUT/$NAME"

if [ "$PUBLISH" -eq 1 ]; then
    step "publish"
    printf '  not run: the owner publishes, logged in to npm:\n'
    printf '    npm publish %s --access public\n' "${TARBALL:-$OUT/sipral-react-native-$VERSION.tgz}"
fi

finish
