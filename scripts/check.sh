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
forbidden='pjsip\|pjproject\|pjmedia\|sofia-sip\|osip2\|exosip\|linphone\|bcg729\|spandsp\|libnice\|janus'
hits=$(others '*.rs' '*.h' '*.c' '*.swift' '*.cs' '*.kt' \
    | xargs grep -lin "$forbidden" 2>/dev/null || true)
[ -z "$hits" ] && pass "no forbidden-source references in code" || {
    fail "review provenance in:"; printf '        %s\n' $hits
}

# An ITU Recommendation reserves every part of itself, and its scope clause counts
# the reference source and the conformance vectors as parts. So they are used on a
# machine and never committed: what ships is our own result and our own script.
# A whitelist rather than a pattern, because the mistake this catches is somebody
# adding a directory of vectors while implementing a codec, and no pattern
# predicts what they would call it.
stray=$(git ls-files fixtures | cut -d/ -f2 | sort -u | grep -vxE 'rfc4475|replay' || true)
[ -z "$stray" ] && pass "no unvetted fixtures" || {
    fail "fixtures/ holds something nobody vetted for a licence:"
    printf '        fixtures/%s\n' $stray
    printf '        ITU material is never committed. Widen this list only alongside a README naming the licence.\n'
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
# rustdoc is a compiler nothing else here runs, and the mistakes only it sees
# are the ones a reader hits: a public doc linking something private, a link
# that resolves to nothing, an RFC quotation whose angle brackets read as
# HTML. A documentation comment is source, and source compiles clean.
# --all-features for the reason clippy above takes it: the reference loop is
# behind one, and rustdoc that never reads a module never reads its links.
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features >/dev/null 2>&1 \
    && pass "cargo doc" \
    || fail "RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps --all-features"
cargo build --workspace --release >/dev/null 2>&1 && pass "release build" || fail "cargo build --release"

# The header describes a library, and nothing until now said there was one:
# a crate that declares no crate-type produces an rlib and nothing a C linker
# can open. What this step reads is the two artefacts the release build above
# produced, and the names in them. The tests are -s rather than -f because a
# run whose build went red still finds yesterday's file here, and a file
# truncated to nothing would otherwise be reported as built.
step "the library, and what it exports"

DYLIB="target/release/libsipral_ffi.dylib"
ARCHIVE="target/release/libsipral_ffi.a"

# Apple's nm is an LLVM 14 tool and refuses to read an object carrying newer
# bitcode, which under `lto = "thin"` is every Rust object in the archive.
# nm-classic reads the Mach-O symbol table and never looks at the bitcode; the
# dylib is plain Mach-O and either would do.
exported() { xcrun nm-classic -gU "$1" 2>/dev/null | awk 'NF == 3 { print $3 }' | sort -u; }

# The two artefacts are removed and built here rather than read out of
# whatever the release build above happened to leave behind. Take `crate-type`
# out of the manifest and `cargo build --workspace --release` still exits 0,
# having produced no C library at all -- and a step that only reads the
# directory finds yesterday's and prints ok five times. That regression is the
# one this step exists for, so it must not be the one it cannot see.
rm -f "$DYLIB" "$ARCHIVE"

if ! cargo build -p sipral-ffi --release >/dev/null 2>&1; then
    fail "cargo build -p sipral-ffi --release"
elif ! xcrun -f nm-classic >/dev/null 2>&1; then
    # a step that cannot read the symbols has not checked them
    fail "nm-classic is not there: xcode-select --install"
elif [ -s "$DYLIB" ] && [ -s "$ARCHIVE" ]; then
    pass "the shared library and the static archive are both built"

    # Mach-O writes a leading underscore on every C name, so the entry point
    # sipral_abi_check is the symbol _sipral_abi_check.
    #
    # The declared list is read once and asserted to exist before it is
    # compared: `comm -23` against an empty left side prints nothing, which
    # reads as "every entry point is there" when what happened is that SURFACE
    # was never read at all.
    declared=$(listed 'sipral_[a-z0-9_]*')
    if [ -z "$declared" ]; then
        fail "SURFACE listed no entry point, so the library was compared against nothing"
    else
        for artefact in "$DYLIB" "$ARCHIVE"; do
            absent=$(comm -23 <(printf '%s\n' "$declared" | sed 's/^/_/') \
                <(exported "$artefact" | grep '^_sipral_'))
            [ -z "$absent" ] && pass "every entry point is in $(basename "$artefact")" || {
                fail "abi.rs declares entry points $(basename "$artefact") does not export:"
                printf '        %s\n' $absent
            }
        done
    fi

    # The two counts below are both answers about one list, so the list is
    # read once and asserted to exist: an nm that resolves and fails prints
    # nothing, and a question asked of no symbols answers ok.
    symbols=$(exported "$DYLIB")
    if [ -z "$symbols" ]; then
        fail "nm read no symbol out of $(basename "$DYLIB"), so nothing was counted"
    else
        # And not one more. An entry point that was renamed and whose old
        # symbol is still in the library links for an application built
        # against a header that no longer mentions it, and stops linking the
        # day it is noticed.
        count=$(printf '%s\n' "$symbols" | grep -c '^_sipral_')
        listed_count=$(printf '%s\n' "$declared" | grep -c . || true)
        [ "$count" = "$listed_count" ] && pass "$count exported, $listed_count in SURFACE" || {
            fail "the library exports $count _sipral_ symbols and SURFACE lists $listed_count"
        }

        # What else leaves. A Rust symbol keeps its mangling and is nobody's
        # to collide with; a bare C name in a library an application links
        # beside its own is ours to account for. The archive is not asked,
        # because an archive carries every dependency's objects -- libopus and
        # compiler-rt among them -- and those names are theirs, which
        # `docs/08-ffi.md` says out loud for the consumer who static-links.
        stray=$(printf '%s\n' "$symbols" | grep -v '^_sipral_' | grep -v '^__Z\|^__R' || true)
        [ -z "$stray" ] && pass "nothing else leaves the library unmangled" || {
            fail "the library exports a name that is not the ABI's:"
            printf '        %s\n' $stray
        }
    fi
else
    fail "$DYLIB and $ARCHIVE are not both there:"
    printf '        the crate needs [lib] crate-type in crates/sipral-ffi/Cargo.toml.\n'
fi

# A header, three generated bindings and a scan that says they agree still
# prove nothing about a compiler having read any of it. This is the one
# consumer in the tree that is written the way an integrator writes one:
# compiled with warnings fatal, linked against the shared library, and run.
step "linked from C"
if [ -s "$DYLIB" ]; then
    work=$(mktemp -d)
    if cc -std=c11 -Wall -Wextra -Werror -o "$work/smoke" bindings/c/smoke.c \
        -L"$ROOT/target/release" -lsipral_ffi -Wl,-rpath,"$ROOT/target/release" \
        >"$work/cc" 2>&1; then
        pass "cc -std=c11 -Wall -Wextra -Werror"
        if ran=$("$work/smoke" 2>&1); then
            pass "bindings/c/smoke.c"
        else
            fail "bindings/c/smoke.c did not come back zero:"
            printf '%s\n' "$ran" | sed 's/^/        /'
        fi
    else
        fail "bindings/c/smoke.c does not compile:"
        sed 's/^/        /' "$work/cc"
    fi
    rm -rf "$work"
else
    fail "$DYLIB: nothing to link against"
fi

# Everything behind cfg(target_os = "windows") in sipral-io-wasapi, and the
# three iOS bodies in sipral-io-coreaudio, are read by no compiler on this
# machine, and a crate whose platform half only compiles on the platform is a
# crate that stops compiling there quietly. Both targets are rustup
# components rather than machines, so this type-checks and lints without
# running anything -- which is what rots. Rustdoc goes with clippy for
# Windows, because the links into the Windows-only types are the ones that
# resolve on no other target.
step "the code this machine does not compile"
if rustup target list --installed 2>/dev/null | grep -qx x86_64-pc-windows-msvc; then
    cargo clippy -p sipral-io-wasapi --target x86_64-pc-windows-msvc --all-targets \
        -- -D warnings >/dev/null 2>&1 \
        && pass "cargo clippy -p sipral-io-wasapi for Windows" \
        || fail "cargo clippy -p sipral-io-wasapi --target x86_64-pc-windows-msvc --all-targets"
    RUSTDOCFLAGS="-D warnings" cargo doc -p sipral-io-wasapi --no-deps \
        --target x86_64-pc-windows-msvc >/dev/null 2>&1 \
        && pass "cargo doc -p sipral-io-wasapi for Windows" \
        || fail "RUSTDOCFLAGS=-D warnings cargo doc -p sipral-io-wasapi --no-deps --target x86_64-pc-windows-msvc"
else
    fail "x86_64-pc-windows-msvc is not installed: rustup target add x86_64-pc-windows-msvc"
fi
if rustup target list --installed 2>/dev/null | grep -qx aarch64-apple-ios; then
    cargo clippy -p sipral-io-coreaudio --target aarch64-apple-ios --all-targets \
        -- -D warnings >/dev/null 2>&1 \
        && pass "cargo clippy -p sipral-io-coreaudio for iOS" \
        || fail "cargo clippy -p sipral-io-coreaudio --target aarch64-apple-ios --all-targets"
else
    fail "aarch64-apple-ios is not installed: rustup target add aarch64-apple-ios"
fi

# The mirror of --all-features. Opus is behind a feature because libopus is
# licensed rather than written (`docs/05-media.md`), and the customer who
# needs it out is the one shipping hardware -- so the build without it has to
# be one somebody compiles, or the cfg rots and the promise is worth nothing.
step "the build without Opus"
cargo build -p sipral --no-default-features >/dev/null 2>&1 \
    && pass "cargo build -p sipral" || fail "cargo build -p sipral --no-default-features"
cargo build -p sipral-ffi --no-default-features >/dev/null 2>&1 \
    && pass "cargo build -p sipral-ffi" || fail "cargo build -p sipral-ffi --no-default-features"
cargo test -p sipral-media --no-default-features >/dev/null 2>&1 \
    && pass "cargo test -p sipral-media" || fail "cargo test -p sipral-media --no-default-features"
cargo test -p sipral --no-default-features >/dev/null 2>&1 \
    && pass "cargo test -p sipral" || fail "cargo test -p sipral --no-default-features"
cargo test -p sipral-ffi --no-default-features >/dev/null 2>&1 \
    && pass "cargo test -p sipral-ffi" || fail "cargo test -p sipral-ffi --no-default-features"

# A Cargo feature belongs to the crate that declares it and features are
# additive, so the ABI crate without its own `opus` over a facade that linked
# the codec is a configuration somebody can really build -- and the one in
# which an answer copied from the wrong crate's flag lies about a codec the
# build can negotiate. Every C-side answer about Opus is read from the
# catalogue so that this passes.
cargo test -p sipral-ffi --no-default-features --features sipral/opus >/dev/null 2>&1 \
    && pass "cargo test -p sipral-ffi over sipral/opus" \
    || fail "cargo test -p sipral-ffi --no-default-features --features sipral/opus"

# The cfg-ed code has lints of its own -- the `Result` that is always `Ok`
# where no codec refuses anything is one, and it needed an allow -- and
# nothing above ever lints this configuration.
cargo clippy -p sipral --no-default-features --all-targets -- -D warnings >/dev/null 2>&1 \
    && pass "cargo clippy -p sipral" \
    || fail "cargo clippy -p sipral --no-default-features --all-targets"
cargo clippy -p sipral-ffi --no-default-features --all-targets -- -D warnings >/dev/null 2>&1 \
    && pass "cargo clippy -p sipral-ffi" \
    || fail "cargo clippy -p sipral-ffi --no-default-features --all-targets"
cargo clippy -p sipral-media --no-default-features --all-targets -- -D warnings >/dev/null 2>&1 \
    && pass "cargo clippy -p sipral-media" \
    || fail "cargo clippy -p sipral-media --no-default-features --all-targets"
cargo clippy -p sipral-ffi --no-default-features --features sipral/opus --all-targets -- -D warnings >/dev/null 2>&1 \
    && pass "cargo clippy -p sipral-ffi over sipral/opus" \
    || fail "cargo clippy -p sipral-ffi --no-default-features --features sipral/opus"

# And the thing the feature exists for, which every check above passes
# without: with it off, libopus is not in the dependency graph at all. A
# build that compiles and tests and still links it is a build the customer
# who asked cannot ship. Both crates, because what that customer ships is
# the C library, which reaches libopus down an edge of its own: two graphs
# that are clean today and that one edit can make disagree.
#
# The tree is captured first and asserted about second, which is the whole
# point. Written the other way -- `! cargo tree ... | grep -qi opus` -- a
# cargo that failed for any reason, a renamed package or a manifest that
# will not parse, makes the pipeline non-zero under `pipefail` and the `!`
# turns that into success: the one assertion this step exists for prints ok
# having read nothing.
for crate in sipral sipral-ffi; do
    tree=$(cargo tree -p "$crate" --no-default-features 2>/dev/null)
    listed=$?
    if [ "$listed" -ne 0 ] || [ -z "$tree" ]; then
        fail "cargo tree -p $crate --no-default-features listed nothing, so nothing was checked"
    elif printf '%s\n' "$tree" | grep -qi opus; then
        fail "libopus is in the dependency graph of $crate, the build meant to be without it"
    else
        pass "nothing links libopus ($crate)"
    fi
done

# And the other half of the promise, which nothing above can see: the feature
# is on by default. Every command in this step passes --no-default-features
# and is therefore indifferent to what `default` contains, and the lints above
# force the feature on whatever the manifests say. Empty `default` and the
# whole gate stays green while every build that asked for nothing quietly
# loses the codec.
tree=$(cargo tree -p sipral 2>/dev/null)
listed=$?
if [ "$listed" -ne 0 ] || [ -z "$tree" ]; then
    fail "cargo tree -p sipral listed nothing, so the default was not checked"
elif printf '%s\n' "$tree" | grep -qi opus; then
    pass "the default still links libopus"
else
    fail "the default build does not link libopus: the feature is meant to be on"
fi

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
    # not a skip: a gate that goes green without the scanner has not looked
    fail "gitleaks not installed: brew install gitleaks"
fi

printf '\n'
[ "$FAIL" -eq 0 ] && { printf 'all checks passed\n'; exit 0; }
printf 'checks failed\n'; exit 1
