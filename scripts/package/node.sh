#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# The Node.js artefact: sipral-<version>.tgz for npm, from bindings/node.
#
#   scripts/package/node.sh --out DIR [--dry-run] [--publish]
#
# Compiles the TypeScript layer with the package's own tsc, then packs a
# staged copy, DIR/stage: package.json, the README, the compiled dist/ and
# the licence texts from the repository root. `files` in package.json
# decides what goes in; the tarball's listing is then held to it: the
# printed binding and the layer in, the tests and node_modules out. The
# package carries no native library: it loads the one the application
# installs (bindings/node/README.md). With --dry-run it is `npm pack
# --dry-run` and no tarball; without, the tarball lands in DIR. Needs
# bindings/node/node_modules as package-lock.json names it (`npm ci --prefix
# bindings/node`), and no network after that. Nothing is uploaded:
# --publish prints the command the owner runs.
set -uo pipefail

cd "$(dirname "$0")/../.."
ROOT="$PWD"
NODE_DIR="$ROOT/bindings/node"

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
step() { printf '\n%s\n' "$1"; }
finish() {
    printf '\n'
    [ "$FAIL" -eq 0 ] && { printf 'node.sh: done%s, %s\n' "$([ "$DRY_RUN" -eq 1 ] && printf ' (dry-run)')" "${TARBALL:-$OUT}"; exit 0; }
    printf 'node.sh: failed\n'; exit 1
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
[ -z "$OUT" ] && { printf 'usage: node.sh --out DIR [--dry-run] [--publish]\n' >&2; exit 2; }
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
process.stdout.write(problems.join(", "));
process.exit(problems.length ? 1 : 0);
' "$NODE_DIR/package.json" >"$OUT/manifest.txt" 2>&1 \
    && pass "name, version, description, licence, repository, homepage, keywords, author" \
    || fail "bindings/node/package.json: $(cat "$OUT/manifest.txt")"

step "the TypeScript layer"
if [ ! -d "$NODE_DIR/node_modules/koffi" ] || ! npm --prefix "$NODE_DIR" ls >/dev/null 2>&1; then
    fail "bindings/node/node_modules is missing or not what package-lock.json names: npm ci --prefix bindings/node"
    finish
fi
if (cd "$NODE_DIR" && rm -rf dist && ./node_modules/.bin/tsc -p .) >"$OUT/tsc.log" 2>&1; then
    pass "tsc -p bindings/node"
else
    fail "tsc -p bindings/node:"; tail -20 "$OUT/tsc.log" | sed 's/^/        /'; finish
fi

step "the staged package, $STAGE"
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp "$NODE_DIR/package.json" "$NODE_DIR/README.md" "$STAGE/"
cp -R "$NODE_DIR/dist" "$STAGE/dist"
pass "package.json, README.md and dist/ from bindings/node"
cp LICENSE LICENSE-COMMERCIAL.md THIRD-PARTY-NOTICES.md "$STAGE/"
pass "LICENSE, LICENSE-COMMERCIAL.md and THIRD-PARTY-NOTICES.md from the repository root"

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
[ "$NAME" = "sipral-$VERSION.tgz" ] && pass "$NAME" || fail "npm names the tarball '$NAME', not sipral-$VERSION.tgz"
for f in package.json README.md LICENSE LICENSE-COMMERCIAL.md THIRD-PARTY-NOTICES.md \
    dist/index.js dist/index.d.ts dist/sipral_abi.js dist/sipral_abi.d.ts; do
    grep -qx "$f" "$OUT/pack.list" && pass "carries $f" || fail "missing $f"
done
leaked=$(grep -E '^dist/test/|^node_modules/|^src/' "$OUT/pack.list" || true)
[ -z "$leaked" ] && pass "no tests, sources or node_modules in the tarball" || {
    fail "the tarball carries what it should not:"; printf '%s\n' "$leaked" | sed 's/^/        /'; }
count=$(($(wc -l <"$OUT/pack.list") - 1))
pass "$count files in all, listed in $OUT/pack.list"
[ "$DRY_RUN" -eq 0 ] && TARBALL="$OUT/$NAME"

if [ "$PUBLISH" -eq 1 ]; then
    step "publish"
    printf '  not run: the owner publishes, logged in to npm:\n'
    printf '    npm publish %s --access public\n' "${TARBALL:-$OUT/sipral-$VERSION.tgz}"
fi

finish
