#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# The Rust artefact: the `sipral` crate on crates.io, the one crate in this
# workspace with `publish = true`.
#
#   scripts/package/crate.sh --out DIR [--dry-run] [--publish]
#   scripts/package/crate.sh --out DIR --crates-io [--dry-run] [--publish]
#
# No release publishes it. What Sipral releases are the C library and the
# language packages over it; the Rust crates are not part of the 1.0
# publication, their API makes no compatibility promise, and the `sipral`
# name on crates.io is a reservation at 0.0.1 that stays what it is
# (docs/11-testing.md, "Releasing"). So without --crates-io this script
# refuses, saying that, and builds nothing. --crates-io runs the checks
# below, for the day a release does publish the crates:
#
# crates.io takes a crate only when every dependency it names with a
# version is already on crates.io, dev-dependencies included. `sipral`
# names a dozen crates of this workspace, so `cargo publish -p sipral` works
# only once each of those can be published too, before it, in dependency
# order -- which is what a multi-package `cargo publish -p A -p B ...` does in
# one invocation. This script reads that set from `cargo metadata` rather
# than from a list kept here, and checks, for every crate in it:
#
#   - that it can be published (`publish` not `false`);
#   - the metadata crates.io shows: a description, a licence expression
#     crates.io reads (SPDX identifiers only: a `LicenseRef-` it refuses),
#     the repository, the homepage, a README, keywords (five at most) and
#     categories;
#   - that no author carries an address.
#
# Then, if all of that holds, `cargo publish --dry-run` over the whole set,
# which packages each crate and builds it from the packaged sources against
# the others; without --dry-run, `cargo package` over the set instead,
# leaving the .crate files under DIR. Either way it runs on any host with
# the workspace's toolchain. Nothing is uploaded: --publish prints the one
# command the owner runs.
#
# Until the set can be published, the run fails and says which crate stops
# it and why: a dry run that passed there would promise a `cargo publish`
# that crates.io then refuses.
set -uo pipefail

cd "$(dirname "$0")/../.."

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
note() { printf '  note  %s\n' "$1"; }
step() { printf '\n%s\n' "$1"; }
finish() {
    printf '\n'
    [ "$FAIL" -eq 0 ] && { printf 'crate.sh: done%s, %s\n' "$([ "$DRY_RUN" -eq 1 ] && printf ' (dry-run)')" "$OUT"; exit 0; }
    printf 'crate.sh: failed\n'; exit 1
}

OUT=""
DRY_RUN=0
PUBLISH=0
CRATES_IO=0
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --publish) PUBLISH=1; shift ;;
        --crates-io) CRATES_IO=1; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -z "$OUT" ] && { printf 'usage: crate.sh --out DIR [--crates-io] [--dry-run] [--publish]\n' >&2; exit 2; }
if [ "$CRATES_IO" -eq 0 ]; then
    printf 'crate.sh: refused. The Rust crates are not part of the Sipral %s publication:\n' "$(scripts/version.sh)" >&2
    printf '  the release is the C library and the language packages over it, and the\n' >&2
    printf '  crates'"'"' API makes no compatibility promise. The sipral name on crates.io is\n' >&2
    printf '  reserved with 0.0.1 and stays so (docs/11-testing.md, "Releasing").\n' >&2
    printf '  --crates-io checks the crates as a publication there would need them.\n' >&2
    exit 1
fi
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

step "one version"
scripts/version.sh --check || FAIL=1
VERSION="$(scripts/version.sh)"

step "the crates sipral needs on crates.io, in the order they would publish"
command -v python3 >/dev/null 2>&1 || { fail "python3 not found"; finish; }
if ! cargo metadata --format-version 1 --no-deps --offline >"$OUT/metadata.json" 2>"$OUT/metadata.log"; then
    fail "cargo metadata:"; sed 's/^/        /' "$OUT/metadata.log"; finish
fi
# One line per crate, dependencies first: NAME|PROBLEM;PROBLEM;... with no
# problem listed when it is ready. A dependency belongs to the set when it is
# a path into this workspace and carries a version: one with no version is
# stripped from the published manifest and needs nothing on crates.io.
python3 - "$OUT/metadata.json" >"$OUT/set.txt" <<'EOF'
import json, re, sys
meta = json.load(open(sys.argv[1]))
packages = {p["name"]: p for p in meta["packages"]}
order, seen = [], set()
def visit(name):
    if name in seen:
        return
    seen.add(name)
    for dep in packages[name]["dependencies"]:
        if dep.get("path") and dep["req"] != "*" and dep["name"] in packages:
            visit(dep["name"])
    order.append(name)
visit("sipral")
spdx = re.compile(r"^[A-Za-z0-9.+-]+( (AND|OR|WITH) [A-Za-z0-9.+-]+)*$")
for name in order:
    p = packages[name]
    problems = []
    if p["publish"] == []:
        problems.append("publish = false")
    if not p["description"]:
        problems.append("no description")
    licence = p["license"] or ""
    if not licence:
        problems.append("no licence")
    elif "LicenseRef-" in licence or not spdx.match(licence):
        problems.append("licence '%s' is not one crates.io reads" % licence)
    for field in ("repository", "homepage", "readme"):
        if not p[field]:
            problems.append("no " + field)
    if not p["keywords"]:
        problems.append("no keywords")
    elif len(p["keywords"]) > 5:
        problems.append("%d keywords, crates.io takes five" % len(p["keywords"]))
    if not p["categories"]:
        problems.append("no categories")
    if any("@" in a for a in p["authors"]):
        problems.append("an author carries an address")
    print(name + "|" + ";".join(problems))
EOF
SET=()
blocked=0
while IFS='|' read -r name problems; do
    SET+=("$name")
    if [ -z "$problems" ]; then
        pass "$name"
    else
        fail "$name: $(printf '%s' "$problems" | sed 's/;/, /g')"
        blocked=$((blocked + 1))
    fi
done <"$OUT/set.txt"
if [ "$blocked" -gt 0 ]; then
    note "$blocked of the ${#SET[@]} crates above stop \`cargo publish -p sipral\`: crates.io would"
    note "refuse sipral for naming a crate it does not have. Publishing them all is a"
    note "name and a compatibility promise per crate; docs/11-testing.md, \"Releasing\","
    note "lists this as the owner's decision."
fi

step "what the sipral .crate carries"
if cargo package --list -p sipral --allow-dirty >"$OUT/sipral.list" 2>"$OUT/list.log"; then
    for f in Cargo.toml README.md LICENSE src/lib.rs; do
        grep -qx "$f" "$OUT/sipral.list" && pass "$f" || fail "sipral's package has no $f"
    done
    note "$(wc -l <"$OUT/sipral.list" | tr -d ' ') files in all, listed in $OUT/sipral.list"
else
    fail "cargo package --list -p sipral:"; sed 's/^/        /' "$OUT/list.log"
fi

[ "$FAIL" -ne 0 ] && finish

PACKAGE_ARGS=()
for name in "${SET[@]}"; do PACKAGE_ARGS+=(-p "$name"); done
if [ "$DRY_RUN" -eq 1 ]; then
    step "cargo publish --dry-run, the set of ${#SET[@]}"
    if CARGO_TARGET_DIR="$OUT/target" cargo publish --dry-run --locked "${PACKAGE_ARGS[@]}" >"$OUT/publish.log" 2>&1; then
        pass "every crate packaged and built from its packaged sources"
    else
        fail "cargo publish --dry-run:"; tail -30 "$OUT/publish.log" | sed 's/^/        /'
    fi
else
    step "cargo package, the set of ${#SET[@]}"
    if CARGO_TARGET_DIR="$OUT/target" cargo package --locked "${PACKAGE_ARGS[@]}" >"$OUT/package.log" 2>&1; then
        cp "$OUT"/target/package/*-"$VERSION".crate "$OUT/"
        pass "$(ls "$OUT"/*.crate | wc -l | tr -d ' ') .crate files in $OUT"
    else
        fail "cargo package:"; tail -30 "$OUT/package.log" | sed 's/^/        /'
    fi
fi

if [ "$PUBLISH" -eq 1 ]; then
    step "publish"
    printf '  not run: the owner publishes. From the tagged commit, logged in with\n'
    printf '  cargo login:\n'
    printf '    cargo publish --locked %s\n' "${PACKAGE_ARGS[*]}"
fi

finish
