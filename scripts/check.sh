#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# Everything that must hold before a commit. Run it, do not read it.
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

HYGIENE_ONLY=0
[ "${1:-}" = "--hygiene-only" ] && HYGIENE_ONLY=1

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
step() { printf '\n%s\n' "$1"; }

SELF="scripts/check.sh"

tracked() {
    if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
        git -C "$ROOT" ls-files "$@"
    else
        local pats=()
        for p in "$@"; do pats+=(-name "$p" -o); done
        if [ ${#pats[@]} -eq 0 ]; then pats=(-name '*' -o); fi
        unset 'pats[${#pats[@]}-1]'
        find . -path ./target -prune -o -path ./intern -prune -o -path ./.git -prune \
            -o -type f \( "${pats[@]}" \) -print | sed 's|^\./||'
    fi
}

# the script names the things it looks for, so it never scans itself
others() { tracked "$@" | grep -v "^$SELF$"; }

step "licence headers"
missing=$(tracked '*.rs' '*.sh' | while read -r f; do
    head -3 "$f" | grep -q 'SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial' || echo "$f"
done)
if [ -z "$missing" ]; then pass "SPDX header present"; else
    fail "SPDX header missing:"; printf '        %s\n' $missing
fi

nocopy=$(tracked '*.rs' '*.sh' | while read -r f; do
    head -4 "$f" | grep -q 'Copyright (c) 2026 Tiberiu Balasea' || echo "$f"
done)
[ -z "$nocopy" ] && pass "copyright line present" || {
    fail "copyright line missing:"; printf '        %s\n' $nocopy
}

step "nothing internal in the tree"
leaked=$(tracked | grep -E '^(intern/|CLAUDE\.md$|\.claude/|\.vscode/)' || true)
[ -z "$leaked" ] && pass "internal paths untracked" || {
    fail "internal files tracked:"; printf '        %s\n' $leaked
}

captures=$(tracked | grep -E '\.pcapng?$' | grep -v '^fixtures/rfc4475/' || true)
[ -z "$captures" ] && pass "no captures outside fixtures/rfc4475" || {
    fail "captures tracked:"; printf '        %s\n' $captures
}

step "rfc 4475 corpus is byte exact"
if [ -f fixtures/rfc4475/manifest.toml ]; then
    bad=$(awk -F'"' '/^file = /{f=$2} /^sha256 = /{print f, $2}' fixtures/rfc4475/manifest.toml \
        | while read -r f sha; do
            [ "$(shasum -a 256 "fixtures/rfc4475/$f" 2>/dev/null | cut -d' ' -f1)" = "$sha" ] || echo "$f"
          done)
    n=$(grep -c '^\[\[message\]\]' fixtures/rfc4475/manifest.toml)
    [ -z "$bad" ] && pass "$n messages match the manifest" || {
        fail "corpus files altered or missing:"; printf '        %s\n' $bad
    }
else
    fail "fixtures/rfc4475/manifest.toml missing"
fi

step "no addresses to harvest"
mails=$(others '*.rs' '*.md' '*.toml' '*.sh' '*.yml' '*.yaml' \
    | xargs grep -InE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' 2>/dev/null \
    | grep -v 'users\.noreply\.github\.com' || true)
[ -z "$mails" ] && pass "no email address in the tree" || {
    fail "email address in published files:"; printf '        %s\n' "$mails"
}

if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    # not in any file, so grep and gitleaks never see it
    authors=$(git -C "$ROOT" log --format='%ae%n%ce' --all \
        | sort -u | grep -v 'users\.noreply\.github\.com' || true)
    [ -z "$authors" ] && pass "no email address in commit metadata" || {
        fail "email address in commit metadata:"; printf '        %s\n' $authors
    }
fi

step "language of the published tree"
dia=$(others '*.rs' '*.md' '*.toml' '*.sh' '*.yml' \
    | xargs grep -lI '[ăâîșțĂÂÎȘȚşţŞŢ]' 2>/dev/null || true)
[ -z "$dia" ] && pass "English only" || {
    fail "Romanian text in published files:"; printf '        %s\n' $dia
}

step "provenance"
forbidden='pjsip\|pjproject\|pjmedia\|sofia-sip\|osip2\|eXosip\|linphone\|bcg729\|spandsp\|libnice'
hits=$(others '*.rs' | xargs grep -ln "$forbidden" 2>/dev/null || true)
[ -z "$hits" ] && pass "no forbidden-source references in code" || {
    fail "review provenance in:"; printf '        %s\n' $hits
}

traces=$(others '*.rs' '*.md' '*.toml' '*.sh' '*.yml' \
    | xargs grep -lin 'co-authored-by: claude\|generated with \[claude\|copilot' 2>/dev/null || true)
[ -z "$traces" ] && pass "no assistant traces" || {
    fail "assistant traces in:"; printf '        %s\n' $traces
}

if [ "$HYGIENE_ONLY" -eq 1 ]; then
    printf '\n'
    [ "$FAIL" -eq 0 ] && { printf 'hygiene checks passed\n'; exit 0; }
    printf 'hygiene checks failed\n'; exit 1
fi

step "build"
cargo fmt --all --check >/dev/null 2>&1 && pass "cargo fmt" || fail "cargo fmt --all"
cargo clippy --workspace --all-targets -- -D warnings >/dev/null 2>&1 \
    && pass "cargo clippy" || fail "cargo clippy --workspace --all-targets"
cargo test --workspace >/dev/null 2>&1 && pass "cargo test" || fail "cargo test --workspace"
cargo build --workspace --release >/dev/null 2>&1 && pass "release build" || fail "cargo build --release"

step "dependency licences"
if command -v cargo-deny >/dev/null 2>&1; then
    cargo deny check >/dev/null 2>&1 \
        && pass "cargo deny" || fail "cargo deny check"
else
    fail "cargo-deny not installed: cargo install cargo-deny --locked"
fi

step "secrets"
if command -v gitleaks >/dev/null 2>&1; then
    gitleaks detect --no-banner --redact >/dev/null 2>&1 \
        && pass "gitleaks" || fail "gitleaks detect"
else
    printf '  skip  gitleaks not installed: brew install gitleaks\n'
fi

printf '\n'
[ "$FAIL" -eq 0 ] && { printf 'all checks passed\n'; exit 0; }
printf 'checks failed\n'; exit 1
