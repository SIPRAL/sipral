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

# --others too: a file that is new and not yet staged is exactly the one a
# pre-commit check must look at, and ls-files alone cannot see it
tracked() {
    if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
        git -C "$ROOT" ls-files --cached --others --exclude-standard "$@"
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
missing=$(tracked '*.rs' '*.sh' '*.h' '*.c' '*.swift' '*.cs' '*.kt' | while read -r f; do
    head -3 "$f" | grep -q 'SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial' || echo "$f"
done)
if [ -z "$missing" ]; then pass "SPDX header present"; else
    fail "SPDX header missing:"; printf '        %s\n' $missing
fi

nocopy=$(tracked '*.rs' '*.sh' '*.h' '*.c' '*.swift' '*.cs' '*.kt' | while read -r f; do
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

step "one version everywhere"
ws=$(awk -F'"' '/^\[workspace.package\]/{p=1} p && /^version = /{print $2; exit}' Cargo.toml)
cs=$(sed -n 's/.*<Version>\(.*\)<\/Version>.*/\1/p' bindings/dotnet/Sipral/Sipral.csproj 2>/dev/null)
ci=$(sed -n 's/.*Version = "\(.*\)".*/\1/p' bindings/dotnet/Sipral/SipralInfo.cs 2>/dev/null)
if [ "$ws" = "$cs" ] && [ "$ws" = "$ci" ]; then pass "workspace, csproj and SipralInfo.cs all say $ws"; else
    fail "version drift: workspace=$ws csproj=$cs SipralInfo.cs=$ci"
fi

step "no addresses to harvest"
mails=$(others '*.rs' '*.md' '*.toml' '*.sh' '*.yml' '*.yaml' \
    '*.h' '*.c' '*.swift' '*.cs' '*.kt' \
    | xargs grep -InE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' 2>/dev/null \
    | grep -v 'users\.noreply\.github\.com' \
    | grep -vE '@([A-Za-z0-9.-]+\.)?(example\.(com|net|org)|[A-Za-z0-9-]+\.(example|invalid|test|localhost))\b' || true)
# RFC 2606 reserved domains are SIP URIs in walkthroughs, not addresses anyone can harvest
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
dia=$(others '*.rs' '*.md' '*.toml' '*.sh' '*.yml' '*.h' '*.c' '*.swift' '*.cs' '*.kt' \
    | xargs grep -lI '[ăâîșțĂÂÎȘȚşţŞŢ]' 2>/dev/null || true)
[ -z "$dia" ] && pass "English only" || {
    fail "Romanian text in published files:"; printf '        %s\n' $dia
}

step "provenance"
forbidden='pjsip\|pjproject\|pjmedia\|sofia-sip\|osip2\|eXosip\|linphone\|bcg729\|spandsp\|libnice'
hits=$(others '*.rs' '*.h' '*.c' '*.swift' '*.cs' '*.kt' \
    | xargs grep -ln "$forbidden" 2>/dev/null || true)
[ -z "$hits" ] && pass "no forbidden-source references in code" || {
    fail "review provenance in:"; printf '        %s\n' $hits
}

traces=$(others '*.rs' '*.md' '*.toml' '*.sh' '*.yml' '*.h' '*.c' '*.swift' '*.cs' '*.kt' \
    | xargs grep -lin 'co-authored-by: claude\|generated with \[claude\|copilot' 2>/dev/null || true)
[ -z "$traces" ] && pass "no assistant traces" || {
    fail "assistant traces in:"; printf '        %s\n' $traces
}

# Artwork arrives with a signed C2PA manifest naming the tool that made it, in
# a PNG chunk or an SVG <metadata> element. Base64 inside a binary, so the text
# scan above never sees it -- and this repository is public.
#
# Only asset files are scanned. Prose that documents this check -- BRAND.md,
# the changelog -- names the very strings it looks for, the same way the
# script itself does; the list grows when a new kind of asset arrives.
stamped=$(others '*.png' '*.jpg' '*.jpeg' '*.gif' '*.webp' '*.ico' '*.svg' \
    '*.pdf' '*.woff' '*.woff2' '*.ttf' '*.otf' '*.mp4' '*.mov' | while read -r f; do
    LC_ALL=C grep -laq 'c2pa\|caBX\|Anthropic\|Content Credentials' "$f" 2>/dev/null && echo "$f"
done)
[ -z "$stamped" ] && pass "no provenance metadata in assets" || {
    fail "provenance metadata in:"; printf '        %s\n' $stamped
    printf '        strip it: PNG keeps IHDR/PLTE/tRNS/IDAT/IEND/sRGB only,\n'
    printf '        SVG drops <metadata> and its namespace. See assets/BRAND.md.\n'
}

# The guarantee deterministic replay stands on, and the reason it is a check
# rather than a paragraph: the protocol crates take the time they are given and
# never ask the machine for it, so a test drives a week of timers in a
# millisecond and a recorded session replays to the same bytes.
#
# Test code may read the clock -- a test that wants a starting point has to get
# one somewhere -- so everything from the first #[cfg(test)] down is cut, and
# the modules that are nothing but tests are skipped by name. `runtime.rs` is
# the one exception in library code and is meant to be: it is the reference
# loop over real sockets, which is where the clock belongs.
step "no clock read in the protocol crates"
clock=$(find crates/sipral-core/src crates/sipral-ua/src crates/sipral-rtp/src \
    crates/sipral-media/src crates/sipral-nat/src -name '*.rs' \
    ! -name 'tests.rs' ! -name '*_tests.rs' ! -name 'runtime.rs' 2>/dev/null \
    | sort | while read -r f; do
    awk '/^#\[cfg\(test\)\]/ { exit } { print FILENAME ":" FNR ": " $0 }' "$f"
done | grep 'Instant::now\|SystemTime::now' || true)
[ -z "$clock" ] && pass "time is given, never read" || {
    fail "the clock is read outside the reference loop:"
    printf '%s\n' "$clock" | sed 's/^/        /'
}

# A panic that unwinds into C takes the host process with it, and no C caller
# can defend itself against that. The `entry!` macro is the only way to declare
# an entry point and every shape of it catches, so the guarantee holds exactly
# as long as nobody declares one by hand. That is what this looks for: the
# macro lives in error.rs and no other file in the workspace may export a
# symbol.
step "nothing unwinds into C"
exported=$(tracked '*.rs' | xargs grep -ln 'no_mangle' 2>/dev/null \
    | grep -v '^crates/sipral-ffi/src/error\.rs$' || true)
[ -z "$exported" ] && pass "every C entry point goes through the guard" || {
    fail "an entry point declared outside the entry! macro:"
    printf '        %s\n' $exported
    printf '        use entry! in crates/sipral-ffi, or the panic reaches C.\n'
}

# B7. The header and the three bindings are printed from the declarations in
# sipral-ffi, so the one thing a person can forget is the line in abi.rs that
# names a declaration. These four scans are that line's other half: the first
# two say that nothing crossing the boundary was declared where the macros
# cannot see it, and the last two compare what the modules declare against what
# abi.rs lists. The comparison the generator itself makes -- committed output
# against printed output -- needs cargo and runs below, with the build.
step "one declaration of the ABI"
FFI=$(tracked '*.rs' | grep '^crates/sipral-ffi/src/' || true)

listed() {
    sed -n '/^pub const SURFACE/,/^};/p' crates/sipral-ffi/src/abi.rs | grep -o "$1" | sort -u
}

# Everything that crosses is declared through a macro from crate::abi, and a
# macro invocation puts its contents one level in. So a repr, a published
# constant or a published alias at the left margin is one written out by hand,
# where nothing recorded it -- and the reprs a test declares for its own use
# sit inside their module, indented, so this does not have to cut the tests off
# first and cannot be slipped past by declaring something below them.
byhand=$(grep -l '^#\[repr(' $FFI 2>/dev/null || true)
[ -z "$byhand" ] && pass "no type crosses without record! or codes!" || {
    fail "a repr written where the ABI cannot see it:"; printf '        %s\n' $byhand
    printf '        declare it with record! or codes! from crate::abi.\n'
}

byhand=$(grep -l '^pub const SIPRAL_\|^pub type Sipral' $FFI 2>/dev/null || true)
[ -z "$byhand" ] && pass "no constant or alias crosses without constants! or alias!" || {
    fail "a published constant or alias declared where the ABI cannot see it:"
    printf '        %s\n' $byhand
    printf '        declare it with constants! or alias! from crate::abi.\n'
}

# Names, both ways round: declared and unlisted, or listed and gone. The three
# entry points a test declares to prove the macro catches a panic are the one
# thing here that is not the ABI's, and they say so in their names.
missing=$(comm -3 \
    <(cat $FFI | sed -n 's/^ *\(quiet \)\{0,1\}fn \(sipral_[a-z0-9_]*\)(.*/\2/p' \
        | grep -v '^sipral_test_' | sort -u) \
    <(listed 'sipral_[a-z0-9_]*'))
[ -z "$missing" ] && pass "every entry point is in abi.rs" || {
    fail "the entry points and abi.rs disagree:"; printf '        %s\n' $missing
    printf '        the left column is declared and unlisted, the right listed and gone.\n'
    printf '        add or remove its line in crates/sipral-ffi/src/abi.rs.\n'
}

missing=$(comm -3 \
    <(cat $FFI | grep -oE '^ *pub (struct|union|enum|type) Sipral[A-Za-z0-9]*' \
        | grep -o 'Sipral[A-Za-z0-9]*' | sort -u) \
    <(listed 'Sipral[A-Za-z0-9]*'))
[ -z "$missing" ] && pass "every type that crosses is in abi.rs" || {
    fail "the types that cross and abi.rs disagree:"; printf '        %s\n' $missing
    printf '        the left column is declared and unlisted, the right listed and gone.\n'
    printf '        add or remove its line in crates/sipral-ffi/src/abi.rs.\n'
}

if [ "$HYGIENE_ONLY" -eq 1 ]; then
    printf '\n'
    [ "$FAIL" -eq 0 ] && { printf 'hygiene checks passed\n'; exit 0; }
    printf 'hygiene checks failed\n'; exit 1
fi

step "build"
cargo fmt --all --check >/dev/null 2>&1 && pass "cargo fmt" || fail "cargo fmt --all"
# --all-features, because the reference loop is behind one and nothing else
# would ever lint it
cargo clippy --workspace --all-targets --all-features -- -D warnings >/dev/null 2>&1 \
    && pass "cargo clippy" || fail "cargo clippy --workspace --all-targets --all-features"
cargo test --workspace --all-features >/dev/null 2>&1 \
    && pass "cargo test" || fail "cargo test --workspace --all-features"
cargo build --workspace --release >/dev/null 2>&1 && pass "release build" || fail "cargo build --release"

# the other half of B7: what is committed under bindings/ against what the
# declarations produce right now. The scans above say a declaration is listed;
# this says the listed declaration reached the header and all three bindings.
step "the header and the bindings"
if printed=$(cargo run -q -p sipral-abi-gen -- --check 2>&1); then
    pass "printed from the declarations"
else
    fail "bindings/ is not what the declarations produce:"
    printf '%s\n' "$printed" | sed 's/^/        /'
fi

step "dependency licences"
if command -v cargo-deny >/dev/null 2>&1; then
    cargo deny check >/dev/null 2>&1 \
        && pass "cargo deny" || fail "cargo deny check"
    # fuzz/ is its own workspace, so the run above never sees it
    (cd "$ROOT/fuzz" && cargo deny check licenses >/dev/null 2>&1) \
        && pass "cargo deny (fuzz)" || fail "cargo deny check in fuzz/"
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
