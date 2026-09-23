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
# only for a tool that is not on this machine, and only when it names what is
# missing and how to get it. Never for something that could be checked here
# and was not: a gate that goes green without looking has not looked.
skip() { printf '  skip  %s\n' "$1"; }
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

# Every pattern below appears in this file as a literal string, so the file is
# left out of the scans it runs. Anything put here that is not a pattern belongs
# in a file the scans can see.
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
py=$(sed -n 's/^version = "\(.*\)"$/\1/p' bindings/python/pyproject.toml 2>/dev/null)
if [ "$ws" = "$cs" ] && [ "$ws" = "$ci" ] && [ "$ws" = "$py" ]; then
    pass "workspace, csproj, SipralInfo.cs and pyproject.toml all say $ws"
else
    fail "version drift: workspace=$ws csproj=$cs SipralInfo.cs=$ci pyproject.toml=$py"
fi

step "no addresses to harvest"
mails=$(others '*.rs' '*.md' '*.toml' '*.sh' '*.yml' '*.yaml' \
    '*.h' '*.c' '*.swift' '*.cs' '*.kt' \
    | xargs grep -InE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' 2>/dev/null \
    | grep -v 'users\.noreply\.github\.com' \
    | grep -v 'thetestcall@sip2sip\.info' \
    | grep -vE '@([A-Za-z0-9.-]+\.)?(example\.(com|net|org)|[A-Za-z0-9-]+\.(example|invalid|test|localhost))\b' || true)
# RFC 2606 reserved domains are SIP URIs in walkthroughs, not addresses anyone can harvest.
# `thetestcall@sip2sip.info` is the same case for a real domain: sip2sip.info
# publishes that extension itself, for anyone to dial with no account, as its
# own public IVR — not a mailbox, and not anybody's to harvest.
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

# The other place bytes of no obvious origin could land. fuzz/corpus/ is
# committed -- a clone that gets seventeen targets and no corpus gets seventeen
# targets that start from the empty input -- and two things keep it from
# becoming somewhere unvetted material is dropped. Both are checked here.
#
# Its shape, first: every directory in it is a target fuzz/Cargo.toml
# declares, every target has one, fuzz/corpus/README.md says where the bytes
# came from, and the whole of it is bounded. tools/fuzz-seeds writes them out
# of this repository's own builders, puts each one through the reader its
# target puts it through, and sweeps whatever it did not write.
#
# Its content, second, because shape alone would pass a seed holding
# anything at all.
#
# WHAT IS READ. Every byte of every tracked file under fuzz/corpus/, for the
# same four things the rest of the tree is read for: an address somebody
# could harvest, a forbidden project's name, an assistant trace, and
# Romanian. Read as bytes, with `grep -a`, because a seed is a datagram as
# often as it is a message and the `-I` the scans above carry would skip
# exactly the files this exists for.
#
# The first three patterns are ASCII and several characters long, so a
# chance match inside ciphertext is not a thing that happens. Romanian is
# different and is matched differently: each letter is two bytes of UTF-8,
# and an encrypted payload holds those pairs by chance -- the three
# srtp_unprotect seeds really do, which is how this was found out. So what
# is looked for here is not the bare character class the Markdown scan uses
# but a Romanian letter with an ASCII letter on either side of it, which is
# what one looks like inside a word and what ciphertext does not produce.
#
# WHAT IS NOT READ. A lone Romanian letter with no ASCII letter on either
# side of it. One letter is enough, and both was too much: the commonest
# words in the language carry the diacritic at an edge -- `si`, `sa`,
# `doua`, `invata` -- so a rule wanting a letter on both sides reads past
# exactly the words a leak would be made of. The
# SPDX and copyright headers, which a seed cannot carry and is not asked
# for. fuzz/corpus/README.md, which is Markdown and went through the scans
# above with the rest of the tree. The asset provenance scan, which is for
# images. And anything a run leaves under fuzz/target/, which is not
# committed and never will be.
#
# The declared names are read out of the manifest rather than written here:
# a list of seventeen kept by hand beside a list of seventeen kept by cargo is
# two lists, and they drift.
# One ASCII letter on at least one side of a Romanian letter. Written as an
# alternation rather than a bracket because under LC_ALL=C a bracket over
# multi-byte characters matches single bytes, and the halves of those
# sequences do occur inside ciphertext.
dia='ă\|â\|î\|ș\|ț\|Ă\|Â\|Î\|Ș\|Ț\|ş\|ţ\|Ş\|Ţ'
romanian="[A-Za-z]\\($dia\\)\\|\\($dia\\)[A-Za-z]"

declared=$(awk '/^\[\[bin\]\]/ {found=1; next}
                found && /^name = / {gsub(/"/, "", $3); print $3; found=0}' fuzz/Cargo.toml)
seeded=$(tracked | grep '^fuzz/corpus/' | cut -d/ -f3 | grep -v '^README\.md$' | sort -u)
if [ -z "$declared" ]; then
    fail "fuzz/Cargo.toml declares no target, so the corpus was compared against nothing"
elif [ -z "$seeded" ]; then
    fail "nothing is tracked under fuzz/corpus/: a clone gets targets with nothing to start from"
else
    unseeded=$(comm -23 <(printf '%s\n' "$declared" | sort -u) <(printf '%s\n' "$seeded"))
    unknown=$(comm -13 <(printf '%s\n' "$declared" | sort -u) <(printf '%s\n' "$seeded"))
    if [ -z "$unseeded" ] && [ -z "$unknown" ]; then
        pass "every fuzz target has seeds, and every seed directory a target"
    else
        fail "fuzz/corpus/ and the targets fuzz/Cargo.toml declares disagree:"
        [ -n "$unseeded" ] && {
            printf '        a target with no seeds: %s\n' $unseeded
            printf '        write them with: cargo run -p sipral-fuzz-seeds\n'
        }
        [ -n "$unknown" ] && {
            printf '        not a fuzz target: %s\n' $unknown
            printf '        bytes under fuzz/corpus/ belong to a target, and fuzz/corpus/README.md says where they came from.\n'
        }
    fi
fi

# Every tracked byte under fuzz/corpus/ except the README, which the
# Markdown scans above already read.
seeds() { tracked | grep '^fuzz/corpus/' | grep -vx 'fuzz/corpus/README\.md'; }

corpus_files=$(seeds)
corpus_count=$(printf '%s\n' "$corpus_files" | grep -c . || true)
unreadable=$(printf '%s\n' "$corpus_files" | while read -r f; do
    [ -n "$f" ] && { [ -r "$f" ] && [ -s "$f" ]; } || echo "${f:-<nothing listed>}"
done)
# The scan is asked for the addresses first with the allow-list off. The
# seeds really do hold them -- they are built out of RFC 2606 names, and
# fuzz/corpus/README.md says so -- so a run that matches none of those
# matched nothing because it read nothing, which is the one way this step
# could go green having looked at no bytes at all.
control=$(printf '%s\n' "$corpus_files" | while read -r f; do
    [ -n "$f" ] && LC_ALL=C grep -aoE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$f" 2>/dev/null
done | grep -c . || true)
suspect=$(printf '%s\n' "$corpus_files" | while read -r f; do
    [ -n "$f" ] || continue
    LC_ALL=C grep -aoE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$f" 2>/dev/null \
        | grep -v 'users\.noreply\.github\.com' \
        | grep -vE '@([A-Za-z0-9.-]+\.)?(example\.(com|net|org)|[A-Za-z0-9-]+\.(example|invalid|test|localhost))\b' \
        | sort -u | sed "s|^|$f: an address: |"
    LC_ALL=C grep -aoi "$forbidden" "$f" 2>/dev/null \
        | sort -u | sed "s|^|$f: a forbidden project: |"
    LC_ALL=C grep -aoi 'co-authored-by: claude\|generated with \[claude\|copilot' "$f" 2>/dev/null \
        | sort -u | sed "s|^|$f: an assistant trace: |"
    LC_ALL=C grep -ao "$romanian" \
        "$f" 2>/dev/null | sort -u | sed "s|^|$f: a Romanian word: |"
done)
if [ "$corpus_count" -eq 0 ]; then
    fail "no seed under fuzz/corpus/ was listed, so not one of them was read"
elif [ -n "$unreadable" ]; then
    fail "a seed could not be read, so the scan below did not read it:"
    printf '        %s\n' $unreadable
elif [ "$control" -eq 0 ]; then
    fail "the address scan read no bytes: it matched nothing under fuzz/corpus/, not even the RFC 2606 names the seeds are built out of"
elif [ -z "$suspect" ]; then
    pass "$corpus_count seeds read for addresses, Romanian, provenance and assistant traces"

    # And they are the seeds this repository says they are. Everything above
    # reads the bytes for what they must not hold; none of it asks whether
    # they are the bytes `tools/fuzz-seeds` writes. Replace one with any text
    # at all and the shape check still passes, the content scan still passes,
    # and the corpus has quietly stopped being the corpus documented in
    # fuzz/corpus/README.md -- while the generator, which validates every seed
    # through its own target's parser, would never have produced it.
    fresh=$(mktemp -d)
    if ! cargo run -q -p sipral-fuzz-seeds -- "$fresh" >/dev/null 2>&1; then
        fail "cargo run -p sipral-fuzz-seeds could not write a corpus, so nothing was compared"
    elif [ -z "$(find "$fresh" -type f 2>/dev/null)" ]; then
        fail "the seed generator wrote no file, so the tracked corpus was compared against nothing"
    else
        drift=$( (cd "$ROOT/fuzz/corpus" && find . -type f ! -name 'README.md' | sed 's|^\./||' | sort) \
            | while read -r one; do
                cmp -s "$ROOT/fuzz/corpus/$one" "$fresh/$one" 2>/dev/null || echo "$one"
              done
            (cd "$fresh" && find . -type f | sed 's|^\./||' | sort) \
            | while read -r one; do
                [ -f "$ROOT/fuzz/corpus/$one" ] || echo "$one (the generator writes it; it is not tracked)"
              done )
        [ -z "$drift" ] && pass "every seed is what the generator produces" || {
            fail "fuzz/corpus/ is not what tools/fuzz-seeds writes:"
            printf '        %s\n' $drift
        }
    fi
    rm -rf "$fresh"
else
    fail "fuzz/corpus/ holds what the rest of the tree is not allowed to hold:"
    printf '%s\n' "$suspect" | sed 's/^/        /'
    printf '        seeds come out of tools/fuzz-seeds, which builds them from RFC 5737 and RFC 2606 names.\n'
fi

readme=$(tracked | grep -cx 'fuzz/corpus/README.md' || true)
[ "$readme" = "1" ] && pass "the corpus says where its bytes came from" || {
    fail "fuzz/corpus/README.md is not tracked: committed bytes need an origin"
}

# and a bound, so that the corpus a clone pays for stays something a person
# would read rather than a directory nobody opens
weight=$(tracked | grep '^fuzz/corpus/' | while read -r f; do wc -c <"$f"; done \
    | awk '{total += $1} END {print total + 0}')
if [ -z "$weight" ] || [ "$weight" -eq 0 ]; then
    fail "fuzz/corpus/ weighed nothing, so the bound was not checked"
elif [ "$weight" -le 204800 ]; then
    pass "the seed corpus is $weight bytes, inside the 204800 it is allowed"
else
    fail "the seed corpus is $weight bytes and the bound is 204800"
fi

# No code enters this tree from outside it before 1.0, so an attribution
# trailer or a tool fingerprint left in a file is a mistake rather than a
# credit. The patterns are literal on purpose: a looser one fails the gate on
# ordinary prose.
traces=$(others '*.rs' '*.md' '*.toml' '*.sh' '*.yml' '*.h' '*.c' '*.swift' '*.cs' '*.kt' \
    | xargs grep -lin 'co-authored-by: claude\|generated with \[claude\|copilot' 2>/dev/null || true)
[ -z "$traces" ] && pass "no assistant traces" || {
    fail "assistant traces in:"; printf '        %s\n' $traces
}

# Artwork can carry a signed provenance manifest naming the tool that produced
# it, in a PNG chunk or an SVG <metadata> element. Base64 inside a binary, so
# the text scan above never sees it, and an image ships byte for byte to
# everyone who clones. assets/BRAND.md puts it plainly: this project publishes
# what it wrote and nothing about how.
#
# Only asset files are scanned; the list of extensions grows when a new kind of
# asset arrives.
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
    crates/sipral-media/src crates/sipral-nat/src crates/sipral-dtls/src -name '*.rs' \
    ! -name 'tests.rs' ! -name '*_tests.rs' ! -name 'runtime.rs' 2>/dev/null \
    | sort | while read -r f; do
    awk '/^#\[cfg\(test\)\]/ { exit } { print FILENAME ":" FNR ": " $0 }' "$f"
done | grep 'Instant::now\|SystemTime::now' || true)
[ -z "$clock" ] && pass "time is given, never read" || {
    fail "the clock is read outside the reference loop:"
    printf '%s\n' "$clock" | sed 's/^/        /'
}

# glibc under -std=c99 or c11 defines __STRICT_ANSI__, and with no feature-test
# macro it then hides every declaration that is POSIX rather than ISO C --
# clock_gettime, getaddrinfo, struct timespec, struct addrinfo. macOS exposes
# them either way, so a file that compiles cleanly on this machine fails on
# Linux, which is how the lab's C driver first met the lab. The Apple compiler
# cannot see that; "C compiled against glibc" further down reads each file
# with glibc's own headers and does. This is the cheaper half, and the one
# that says what to do: whether a file asked. One that includes a
# header ISO C does not define, or calls one of the POSIX extensions an ISO
# header only declares on request, names its _POSIX_C_SOURCE (or one of the
# macros that imply it) before its first #include. jni.h is Java's and not
# POSIX, and a quoted include is this tree's own.
step "C that asks for POSIX before it uses it"
iso='assert|complex|ctype|errno|fenv|float|inttypes|iso646|limits|locale|math|setjmp|signal|stdalign|stdarg|stdatomic|stdbool|stddef|stdint|stdio|stdlib|stdnoreturn|string|tgmath|threads|time|uchar|wchar|wctype'
extensions='(clock_gettime|clock_getres|nanosleep|strdup|strndup|strtok_r|fileno|fdopen|getline|localtime_r|gmtime_r)[[:space:]]*\('
unasked=""
for file in $(tracked '*.c' '*.h'); do
    beyond=$(grep -E '^[[:space:]]*#[[:space:]]*include[[:space:]]*<' "$file" \
        | grep -vE "<($iso)\.h>|<jni\.h>" | head -1)
    called=$(grep -E "$extensions" "$file" | head -1)
    [ -z "$beyond$called" ] && continue
    asked=$(grep -nE '^#define _(POSIX_C_SOURCE|XOPEN_SOURCE|GNU_SOURCE|DEFAULT_SOURCE)\b' "$file" \
        | head -1 | cut -d: -f1)
    first=$(grep -nE '^[[:space:]]*#[[:space:]]*include' "$file" | head -1 | cut -d: -f1)
    if [ -z "$asked" ] || { [ -n "$first" ] && [ "$asked" -gt "$first" ]; }; then
        unasked="$unasked $file"
    fi
done
[ -z "$unasked" ] && pass "every C file that reaches past ISO C says so first" || {
    fail "C that needs POSIX and does not ask for it before its first #include:"
    printf '        %s\n' $unasked
    printf '        #define _POSIX_C_SOURCE 200809L above the includes, or glibc hides it.\n'
}

# RFC 4568 §9.2: "the SDP MUST be protected". A `{:?}` on a live stack is not
# protection, and the reason this is a gate rather than a review note is that
# the leak is never in the type that holds the key -- those redact themselves.
# It is in whatever derives `Debug` above them. So the rule is stated the way
# it can be checked: every type that carries key material or a device token
# writes its own `Debug`, and a derive on one of them is what this catches.
#
# The last two are the two ends of one secret. ICE signs every connectivity
# check with a short-term password (RFC 8445 §7.1.2.3), each end draws its own
# and sends it in the description, so the credential exists twice: `Credentials`
# is ours and `RemoteIce` is the peer's, read off the network. `Credentials`
# wrote its `Debug` by hand from the start and `RemoteIce` derived one, which
# is the usual shape of this -- one end is remembered and the other is not,
# and the half that leaks is the half that came in from outside.
#
# WHAT IS READ. The declaration of each, and the line before it, which is where
# a `#[derive]` on it would be. WHAT IS NOT READ. Anything that merely holds
# one of them -- that is the point of putting the redaction at the bottom, and
# a holder deriving `Debug` is correct.
step "nothing that holds a key derives Debug"
redacting="crates/sipral-core/src/sdp/session.rs:Attribute
crates/sipral-core/src/sdp/session.rs:KeyLine
crates/sipral-core/src/sdp/crypto.rs:KeySalt
crates/sipral-ua/src/account.rs:Push
crates/sipral-nat/src/ice/full/mod.rs:Credentials
crates/sipral-nat/src/ice/sdp.rs:RemoteIce
crates/sipral/src/ice.rs:Ice"
derived=""
for pair in $redacting; do
    file=${pair%%:*}
    name=${pair##*:}
    if [ ! -f "$file" ]; then
        derived="$derived
        $file is gone, and $name's redaction with it"
        continue
    fi
    # the declaration, and whether its own derive list carries Debug
    line=$(grep -nE "^pub(\(crate\))? struct $name\b" "$file" | head -1 | cut -d: -f1)
    if [ -z "$line" ]; then
        derived="$derived
        $file no longer declares $name"
        continue
    fi
    before=$((line - 1))
    if [ "$before" -ge 1 ] && sed -n "${before}p" "$file" | grep -q 'derive(.*Debug'; then
        derived="$derived
        $file:$line $name derives Debug"
    fi
    # the trailing brace is load-bearing: without it `Push` matches
    # `PushGone`, and the step passes on a type whose redaction has been
    # renamed out from under it
    if ! grep -q "impl fmt::Debug for $name {\|impl core::fmt::Debug for $name {" "$file"; then
        derived="$derived
        $file $name has no Debug of its own"
    fi
done
[ -z "$derived" ] && pass "every type that carries key material writes its own" || {
    fail "a type that carries key material prints it:"
    printf '%s\n' "$derived"
    printf '        docs/05-media.md says why: the redaction goes at the bottom,\n'
    printf '        because every holder above it is a place to forget.\n'
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

# docs/11-testing.md's generated "Interoperability matrix" section
# (scripts/interop-matrix.py) against the one fixture it can be checked
# without Docker or a live lab: interop/fixtures/lab-run.log, a real
# scripts/lab.sh run, and the date it ran on beside it. A live run regenerates
# the section with scripts/lab.sh --matrix; this only asks whether the section
# committed here is still what that fixture produces.
step "interop matrix matches its fixture"
if command -v python3 >/dev/null 2>&1; then
    matrix_out=$(mktemp)
    if python3 scripts/interop-matrix.py interop/fixtures/lab-run.log --check \
        >"$matrix_out" 2>&1; then
        pass "docs/11-testing.md's generated section matches interop/fixtures/lab-run.log"
    else
        fail "docs/11-testing.md's generated section is stale:"
        sed 's/^/        /' "$matrix_out"
        printf '        regenerate it: scripts/interop-matrix.py interop/fixtures/lab-run.log\n'
    fi
    rm -f "$matrix_out"
else
    fail "python3 not found, and scripts/interop-matrix.py needs it"
fi

# THIRD-PARTY-LICENSES.txt against the normal dependency graph of the crates
# Sipral ships a binary of. tools/license-gen regenerates it from
# `cargo tree` and each dependency's own registry checkout; this only asks
# whether the file committed here is still what that graph produces.
step "third-party licences match the dependency graph"
if lic_out=$(cargo run -p sipral-license-gen -- --check 2>&1); then
    pass "THIRD-PARTY-LICENSES.txt matches the shipped dependency graph"
else
    fail "THIRD-PARTY-LICENSES.txt is stale:"
    printf '        %s\n' "$lic_out"
    printf '        regenerate it: cargo run -p sipral-license-gen\n'
fi

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
    # and the lab's own C driver, compiled the same way and not run: what it
    # needs is three servers in containers, which is `scripts/lab.sh`'s job and
    # not this one's. Compiling it here is what keeps it honest between lab
    # runs -- an ABI change that makes it stop building is a change an
    # integrator would meet, and this is the step that meets it first.
    if cc -std=c99 -Wall -Wextra -Werror -o "$work/harness-c" \
        interop/harness-c/main.c -I bindings/c/include \
        -L"$ROOT/target/release" -lsipral_ffi -Wl,-rpath,"$ROOT/target/release" \
        >"$work/cc-harness" 2>&1; then
        pass "interop/harness-c/main.c"
    else
        fail "interop/harness-c/main.c does not compile:"
        sed 's/^/        /' "$work/cc-harness"
    fi
    rm -rf "$work"
else
    fail "$DYLIB: nothing to link against"
fi

# The same C again, for Linux, because the compiler above cannot see what
# glibc does. Under a strict -std, glibc declares nothing beyond ISO C unless
# the file asks for POSIX, and the Apple SDK declares all of it anyway -- so a
# file that compiles cleanly here stops compiling on the machine it runs on,
# which is how the lab's C driver first met the lab. `zig cc` carries glibc's
# own headers for every target it knows, so this is glibc's reading of each
# file rather than a guess at it: compiled, warnings fatal, and not linked,
# since the library it would link against is a Linux build this machine does
# not make. Linking and running it is the lab's. The POSIX check above names
# the one known way to fail this; this is what catches the next one.
#
# The JNI files are compiled against the JDK's headers from here, whose
# jni_md.h is Darwin's. What that header decides -- how JNIEXPORT is spelt,
# which C type a jlong is -- is not what can go wrong here; what the file
# asks of libc is.
step "C compiled against glibc"
if command -v zig >/dev/null 2>&1; then
    work=$(mktemp -d)
    jdk="${JAVA_HOME:-$(/usr/libexec/java_home 2>/dev/null || true)}"
    for arch in x86_64 aarch64; do
        compiled=1
        for pair in "c99:interop/harness-c/main.c" "c11:bindings/c/smoke.c" "c99:bindings/c/sipral.c"; do
            if ! zig cc -target "$arch-linux-gnu" -std="${pair%%:*}" -Wall -Wextra -Werror -pedantic \
                -I bindings/c/include -c -o "$work/out.o" "${pair#*:}" >"$work/cc" 2>&1; then
                fail "${pair#*:} does not compile against glibc for $arch:"
                sed 's/^/        /' "$work/cc"
                compiled=0
            fi
        done
        if [ -n "$jdk" ] && [ -f "$jdk/include/jni.h" ]; then
            for file in bindings/kotlin/sipral/src/main/jni/sipral_jni.c \
                bindings/kotlin/sipral/src/test/jni/native_thread.c; do
                if ! zig cc -target "$arch-linux-gnu" -std=c11 -Wall -Wextra -Werror \
                    -I"$jdk/include" -I"$jdk/include/darwin" -I bindings/c/include \
                    -c -o "$work/out.o" "$file" >"$work/cc" 2>&1; then
                    fail "$file does not compile against glibc for $arch:"
                    sed 's/^/        /' "$work/cc"
                    compiled=0
                fi
            done
        fi
        [ "$compiled" -eq 1 ] && pass "zig cc -target $arch-linux-gnu"
    done
    [ -n "$jdk" ] && [ -f "$jdk/include/jni.h" ] \
        || skip "the JNI files against glibc: no JDK carrying include/jni.h"
    rm -rf "$work"
else
    fail "zig is not installed, and nothing else here can read C the way glibc does (brew install zig)"
fi

# Everything behind cfg(target_os = "windows") in sipral-io-wasapi, everything
# behind cfg(target_os = "linux") in sipral-io-pipewire and the harness's own
# PipeWire flow, and the three iOS bodies in sipral-io-coreaudio, are read by
# no compiler on this machine, and a crate whose platform half only compiles
# on the platform is a crate that stops compiling there quietly. The targets
# are rustup components rather than machines, so this type-checks and lints
# without linking anything -- which is what rots. Rustdoc goes with clippy for
# Windows and Linux, because the links into the platform-only types are the
# ones that resolve on no other target. What this cannot do is run them:
# interop/pipewire/run.sh is where the Linux half meets a real PipeWire.
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
if [ "$(uname -s)" = Linux ]; then
    pass "sipral-io-pipewire compiles natively here, with the rest of the workspace"
elif rustup target list --installed 2>/dev/null | grep -qx x86_64-unknown-linux-gnu; then
    cargo clippy -p sipral-io-pipewire --target x86_64-unknown-linux-gnu --all-targets \
        -- -D warnings >/dev/null 2>&1 \
        && pass "cargo clippy -p sipral-io-pipewire for Linux" \
        || fail "cargo clippy -p sipral-io-pipewire --target x86_64-unknown-linux-gnu --all-targets"
    RUSTDOCFLAGS="-D warnings" cargo doc -p sipral-io-pipewire --no-deps \
        --target x86_64-unknown-linux-gnu >/dev/null 2>&1 \
        && pass "cargo doc -p sipral-io-pipewire for Linux" \
        || fail "RUSTDOCFLAGS=-D warnings cargo doc -p sipral-io-pipewire --no-deps --target x86_64-unknown-linux-gnu"
    cargo clippy -p sipral-interop --features pipewire --target x86_64-unknown-linux-gnu \
        --all-targets -- -D warnings >/dev/null 2>&1 \
        && pass "cargo clippy -p sipral-interop --features pipewire for Linux" \
        || fail "cargo clippy -p sipral-interop --features pipewire --target x86_64-unknown-linux-gnu --all-targets"
else
    fail "x86_64-unknown-linux-gnu is not installed: rustup target add x86_64-unknown-linux-gnu"
fi
if rustup target list --installed 2>/dev/null | grep -qx aarch64-apple-ios; then
    cargo clippy -p sipral-io-coreaudio --target aarch64-apple-ios --all-targets \
        -- -D warnings >/dev/null 2>&1 \
        && pass "cargo clippy -p sipral-io-coreaudio for iOS" \
        || fail "cargo clippy -p sipral-io-coreaudio --target aarch64-apple-ios --all-targets"
else
    fail "aarch64-apple-ios is not installed: rustup target add aarch64-apple-ios"
fi

# crates/sipral-aec-webrtc is outside the workspace (Cargo.toml at its root
# says why: webrtc-audio-processing-sys's bundled feature needs meson, ninja
# and a C++ toolchain nothing else here asks a machine for), so
# --workspace/--all-features above never touch it and this is its one real
# build, run against its own Cargo.lock. Missing tools fail rather than skip:
# `scripts/check.sh`'s own "gata" bar is zero of either, and a step that
# quietly skipped whenever meson is absent would let the crate rot exactly
# the way the module doc for `the_synthetic_surface_reaches_every_shape`
# warns an unmeasured "wide enough" does.
step "sipral-aec-webrtc, outside the workspace"
if command -v meson >/dev/null 2>&1 && command -v ninja >/dev/null 2>&1; then
    manifest=crates/sipral-aec-webrtc/Cargo.toml
    cargo fmt --manifest-path "$manifest" --check >/dev/null 2>&1 \
        && pass "cargo fmt --manifest-path $manifest --check" \
        || fail "cargo fmt --manifest-path $manifest --check"
    if cargo build --manifest-path "$manifest" >/dev/null 2>&1; then
        pass "cargo build --manifest-path $manifest"
    else
        fail "cargo build --manifest-path $manifest"
    fi
    cargo test --manifest-path "$manifest" >/dev/null 2>&1 \
        && pass "cargo test --manifest-path $manifest" \
        || fail "cargo test --manifest-path $manifest"
    cargo clippy --manifest-path "$manifest" --all-targets -- -D warnings >/dev/null 2>&1 \
        && pass "cargo clippy --manifest-path $manifest --all-targets" \
        || fail "cargo clippy --manifest-path $manifest --all-targets -- -D warnings"
    if command -v cargo-deny >/dev/null 2>&1; then
        cargo deny --manifest-path "$manifest" check >/dev/null 2>&1 \
            && pass "cargo deny --manifest-path $manifest check" \
            || fail "cargo deny --manifest-path $manifest check"
    else
        fail "cargo-deny is not installed: cargo install cargo-deny"
    fi
else
    fail "meson and/or ninja are not installed: crates/sipral-aec-webrtc cannot build \
webrtc-audio-processing-sys's bundled library without them (brew install meson ninja, or \
apt install meson ninja-build)"
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

# Two features now, and `--no-default-features` turns off both at once -- so
# the two interesting halves, "DTLS on and Opus off" and "Opus on and DTLS
# off", are configurations nothing above ever compiles. They are also the two
# a real customer builds: the desk phone that cannot ship libopus still wants
# encrypted calls, and the carrier deployment behind a TLS SIP transport wants
# the codec and has no use for an elliptic curve.
for combination in dtls opus; do
    cargo test -p sipral --no-default-features --features "$combination" >/dev/null 2>&1 \
        && pass "cargo test -p sipral with $combination alone" \
        || fail "cargo test -p sipral --no-default-features --features $combination"
    cargo clippy -p sipral --no-default-features --features "$combination" --all-targets \
        -- -D warnings >/dev/null 2>&1 \
        && pass "cargo clippy -p sipral with $combination alone" \
        || fail "cargo clippy -p sipral --no-default-features --features $combination"
done
cargo test -p sipral-ffi --no-default-features --features dtls >/dev/null 2>&1 \
    && pass "cargo test -p sipral-ffi with dtls alone" \
    || fail "cargo test -p sipral-ffi --no-default-features --features dtls"
cargo clippy -p sipral-ffi --no-default-features --features dtls --all-targets \
    -- -D warnings >/dev/null 2>&1 \
    && pass "cargo clippy -p sipral-ffi with dtls alone" \
    || fail "cargo clippy -p sipral-ffi --no-default-features --features dtls"

# And what the DTLS feature exists for, on the same principle as the libopus
# check below: with it off, none of the four RustCrypto crates the handshake
# stands on is in the graph at all. A build that compiles without the feature
# and still carries p256 is a build whose flash the feature saved nothing of.
for crate in sipral sipral-ffi; do
    if graph=$(cargo tree -p "$crate" --no-default-features -e normal 2>&1); then
        if printf '%s' "$graph" | grep -qiE '(^| )(p256|sipral-dtls|sipral-nat)( |$| v)'; then
            fail "a DTLS dependency is in the graph of $crate, the build meant to be without it"
        else
            pass "nothing links a DTLS primitive ($crate)"
        fi
    else
        fail "cargo tree -p $crate --no-default-features"
    fi
done

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

# The tree says libopus is not a dependency; it says nothing about what is in
# the file a customer actually links. Rebuilt and removed first for the same
# reason the release artefacts above are: `cargo test -p sipral-ffi
# --no-default-features --features sipral/opus` a few lines up already
# rebuilt this exact path with the codec back in over the facade's flag, and
# a check that read it without saying so would be checking that build.
FFI_DEBUG_DYLIB="target/debug/libsipral_ffi.dylib"
FFI_DEBUG_ARCHIVE="target/debug/libsipral_ffi.a"
rm -f "$FFI_DEBUG_DYLIB" "$FFI_DEBUG_ARCHIVE"
if ! cargo build -p sipral-ffi --no-default-features >/dev/null 2>&1; then
    fail "cargo build -p sipral-ffi --no-default-features, to inspect the artefact"
elif [ ! -s "$FFI_DEBUG_DYLIB" ]; then
    fail "$FFI_DEBUG_DYLIB is not there to inspect"
else
    # libopus is vendored and built statically (crates/sipral-media/Cargo.toml
    # says so, and opusic-sys is what does the building), so it never shows up
    # here today. Asserted anyway: the day something links a system libopus
    # dylib instead -- a pkg-config found on the machine that built it, say --
    # is a day this stops being true silently.
    dynamic=$(otool -L "$FFI_DEBUG_DYLIB" 2>/dev/null)
    read_ok=$?
    if [ "$read_ok" -ne 0 ] || [ -z "$dynamic" ]; then
        fail "otool -L read nothing out of $(basename "$FFI_DEBUG_DYLIB"), so nothing was checked"
    elif printf '%s\n' "$dynamic" | grep -qi opus; then
        fail "the no-default-features build links opus dynamically:"
        printf '%s\n' "$dynamic" | grep -i opus | sed 's/^/        /'
    else
        pass "no dynamic dependency on opus (otool -L, no-default-features)"
    fi

    # The static half, which is the one that matters, since the Rust `opus`
    # crate builds libopus into the archive rather than against it: libopus's
    # own C symbols, not sipral_media's `opus` module, whose Rust-mangled
    # names also match a plain `grep -i opus` and say nothing about whether
    # the library itself is in the file. nm-classic without `-g`, because
    # opusic-sys builds libopus with hidden visibility, and a symbol hidden
    # from the exported table is still a symbol linked into the binary.
    symbols=$(xcrun nm-classic -U "$FFI_DEBUG_DYLIB" 2>/dev/null | awk '{print $NF}')
    if [ -z "$symbols" ]; then
        fail "nm read no symbol out of $(basename "$FFI_DEBUG_DYLIB"), so nothing was checked"
    else
        linked=$(printf '%s\n' "$symbols" | grep '^_opus_' || true)
        if [ -n "$linked" ]; then
            fail "the no-default-features build links opus symbols (nm):"
            printf '%s\n' "$linked" | head -5 | sed 's/^/        /'
        else
            pass "no opus symbol in the artefact (nm, no-default-features)"
        fi
    fi
fi

# The mirror of the nm check above, over the same path built with the default
# features instead -- opus on. Not the release $DYLIB from earlier: its
# profile sets `strip = true`, which throws away every local symbol and
# leaves the 66 exported `_sipral_*` entry points and nothing else, in this
# build or that one, so it would report "no opus symbol" whether or not
# libopus is in the file and call that a pass. Removed and rebuilt at the
# same debug path for the same reason the no-default-features half above is.
rm -f "$FFI_DEBUG_DYLIB" "$FFI_DEBUG_ARCHIVE"
if ! cargo build -p sipral-ffi >/dev/null 2>&1; then
    fail "cargo build -p sipral-ffi, to inspect the default-features artefact"
elif [ ! -s "$FFI_DEBUG_DYLIB" ]; then
    fail "$FFI_DEBUG_DYLIB is not there for the default-features mirror check"
else
    symbols=$(xcrun nm-classic -U "$FFI_DEBUG_DYLIB" 2>/dev/null | awk '{print $NF}')
    if [ -z "$symbols" ]; then
        fail "nm read no symbol out of $(basename "$FFI_DEBUG_DYLIB"), so nothing was checked"
    else
        linked=$(printf '%s\n' "$symbols" | grep '^_opus_' || true)
        if [ -n "$linked" ]; then
            pass "opus symbols are in the default artefact (nm)"
        else
            fail "the default build does not link a single opus symbol: an empty default feature set would pass this silently"
        fi
    fi
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

# sipral_abi_check compares numbers, not declarations, so a header whose
# declarations moved and whose number did not is one no load-time check can
# tell from the one before it: a binding generated against the new header
# loads against a library built before the change and finds the symbol missing
# at the first call. The Versioning section of docs/08-ffi.md makes a change
# to any declaration a new minor at least, and leaves a patch for a fix that
# changes none -- so what is compared is the declarations alone, with the
# comments and the three version numbers taken out, and a corrected sentence
# or a patch bump passes. Held against the last commit, which is the header
# the tree last said was published, and not against anybody's memory.
HEADER=bindings/c/include/sipral.h
declarations() {
    printf '%s\n' "$1" | awk '
        {
            line = $0; out = ""
            while (length(line) > 0) {
                if (inside) {
                    at = index(line, "*/")
                    if (at == 0) { line = ""; break }
                    line = substr(line, at + 2); inside = 0
                } else {
                    at = index(line, "/*")
                    if (at == 0) { out = out line; line = "" }
                    else { out = out substr(line, 1, at - 1); line = substr(line, at + 2); inside = 1 }
                }
            }
            if (out !~ /^[[:space:]]*$/ && out !~ /^#define SIPRAL_ABI_VERSION_(MAJOR|MINOR|PATCH) /) print out
        }'
}
version_of() {
    local number
    for number in MAJOR MINOR; do
        printf '%s\n' "$1" | grep -E "^#define SIPRAL_ABI_VERSION_$number " \
            | grep -oE '[0-9]+' | tail -1
    done | tr '\n' ' '
}
if published=$(git show HEAD:"$HEADER" 2>/dev/null); then
    current=$(cat "$HEADER")
    if [ "$(declarations "$published")" = "$(declarations "$current")" ]; then
        pass "the header declares what the last commit's did"
    else
        read -r was_major was_minor <<<"$(version_of "$published")"
        read -r is_major is_minor <<<"$(version_of "$current")"
        if [ "$is_major" -gt "$was_major" ] \
            || { [ "$is_major" -eq "$was_major" ] && [ "$is_minor" -gt "$was_minor" ]; }; then
            pass "the declarations moved, and the ABI version with them ($was_major.$was_minor to $is_major.$is_minor)"
        else
            fail "$HEADER declares something new and the ABI version did not move past $was_major.$was_minor:"
            printf '        raise SIPRAL_ABI_VERSION_MINOR in crates/sipral-ffi/src/version.rs\n'
            printf '        and run cargo run -p sipral-abi-gen.\n'
        fi
    fi
else
    pass "no header in the last commit to hold this one against"
fi

# Sixteen fuzz targets in a workspace of its own, on a nightly pin of its
# own, and nothing else here reads them: `cargo test --workspace`, `cargo
# fmt --all` and the clippy run above all stop at the workspace boundary. A
# target that stops building, or drifts out of the format the rest of the
# tree keeps, is then found the next time somebody fuzzes -- which is before
# a release, which is the worst moment to find it. So the gate formats,
# lints and builds them. It does not run them: seventeen targets at five
# minutes each is an hour, and that is what scripts/fuzz.sh is for.
#
# The toolchain is named out of fuzz/rust-toolchain.toml and passed
# explicitly, so that all three use the pinned nightly and not whatever a
# stray rustup default happens to be.
step "the fuzz targets"
NIGHTLY=$(awk -F'"' '/^channel = /{print $2; exit}' fuzz/rust-toolchain.toml 2>/dev/null)
if [ -z "$NIGHTLY" ]; then
    fail "fuzz/rust-toolchain.toml names no toolchain, so nothing says what to build with"
elif ! rustup toolchain list 2>/dev/null | grep -q "^$NIGHTLY"; then
    skip "fuzz/: $NIGHTLY is not installed (rustup toolchain install $NIGHTLY)"
else
    # these two need the pinned nightly and nothing else, so they run even
    # on a machine with no cargo-fuzz
    (cd "$ROOT/fuzz" && cargo "+$NIGHTLY" fmt -- --check) >/dev/null 2>&1 \
        && pass "cargo fmt, in fuzz/" || fail "cargo +$NIGHTLY fmt -- --check, in fuzz/"
    (cd "$ROOT/fuzz" && cargo "+$NIGHTLY" clippy --all-targets -- -D warnings) >/dev/null 2>&1 \
        && pass "cargo clippy, in fuzz/" \
        || fail "cargo +$NIGHTLY clippy --all-targets -- -D warnings, in fuzz/"

    if ! command -v cargo-fuzz >/dev/null 2>&1; then
        skip "cargo fuzz build: cargo-fuzz is not installed (cargo install cargo-fuzz --locked)"
    elif ! (cd "$ROOT/fuzz" && cargo "+$NIGHTLY" fuzz build) >/dev/null 2>&1; then
        fail "cargo +$NIGHTLY fuzz build, in fuzz/"
    else
        # exiting zero is not the same as having produced anything, and the
        # names come from cargo-fuzz rather than from a list kept here. Each
        # one is then looked for on disk, non-empty.
        #
        # Where on disk is cargo's answer and not a guess: cargo-fuzz builds
        # with plain `cargo build`, which honours CARGO_TARGET_DIR, so a
        # machine that sets it puts the binaries somewhere fuzz/target/ is
        # not -- and a step that looks in fuzz/target/ then reports seventeen
        # targets missing, or worse finds yesterday's.
        targets=$(cd "$ROOT/fuzz" && cargo "+$NIGHTLY" fuzz list 2>/dev/null)
        built_into=$(cd "$ROOT/fuzz" && cargo "+$NIGHTLY" metadata --no-deps --format-version 1 \
            2>/dev/null | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
        if [ -z "$targets" ]; then
            fail "cargo fuzz list named no target, so no binary was looked for"
        elif [ -z "$built_into" ]; then
            fail "cargo metadata did not say where fuzz/ builds, so no binary was looked for"
        elif [ ! -d "$built_into" ]; then
            fail "cargo says fuzz/ builds into $built_into, and there is no such directory"
        else
            absent=$(printf '%s\n' $targets | while read -r one; do
                built=$(find "$built_into" -type f -name "$one" -perm -u+x 2>/dev/null | head -1)
                { [ -n "$built" ] && [ -s "$built" ]; } || echo "$one"
            done)
            count=$(printf '%s\n' $targets | grep -c .)
            [ -z "$absent" ] && pass "$count fuzz targets build under $NIGHTLY" || {
                fail "cargo fuzz build left no binary under $built_into for:"
                printf '        %s\n' $absent
            }
        fi
    fi
fi

# A generated file nobody compiles is a file that is wrong the day it changes.
# Until the generator grew a name pass, the C# binding had two entry points
# with duplicated P/Invoke parameter names and the JNI shim had five; a
# compiler would have said so on the day they were printed, and no compiler had
# ever been pointed at them. Build outputs land in bin/, obj/ and .build/,
# which .gitignore already covers.
step "the bindings compile"

if command -v dotnet >/dev/null 2>&1; then
    (cd "$ROOT/bindings/dotnet/Sipral" && dotnet build -c Release --nologo) >/dev/null 2>&1 \
        && pass "dotnet build" || fail "dotnet build -c Release, in bindings/dotnet/Sipral"
else
    skip "dotnet build: no .NET SDK (https://dot.net/v1/dotnet-install.sh --channel 8.0)"
fi

# org.sipral.idiomatic needs kotlinx-coroutines-core-jvm (Apache-2.0,
# THIRD-PARTY-NOTICES.md), fetched once into a cache outside the repo so the
# gate can reuse it offline afterward -- never downloaded here, and never
# accepted here without its checksum matching what Maven Central published.
COROUTINES_VERSION="1.11.0"
COROUTINES_SHA256="d1d75aa01dffbb4d1c520e67e4c4e7f5f6174718e7cb4632412503f2f0e604fa"
COROUTINES_JAR="$HOME/.cache/sipral/maven/org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/$COROUTINES_VERSION/kotlinx-coroutines-core-jvm-$COROUTINES_VERSION.jar"
coroutines_ok=0
if [ -s "$COROUTINES_JAR" ]; then
    found_sha256=$(shasum -a 256 "$COROUTINES_JAR" 2>/dev/null | cut -d' ' -f1)
    if [ "$found_sha256" = "$COROUTINES_SHA256" ]; then
        coroutines_ok=1
    fi
fi

kotlin_classes=""
kotlin_lib=""
if [ "$coroutines_ok" -ne 1 ]; then
    fail "kotlinx-coroutines-core-jvm $COROUTINES_VERSION is not cached with the right checksum at $COROUTINES_JAR (fetch it once from Maven Central and verify its sha256 matches $COROUTINES_SHA256)"
elif command -v kotlinc >/dev/null 2>&1; then
    # The sources are found rather than listed: a new file nobody added here
    # would otherwise go uncompiled, which is the failure this step exists
    # for. Collected NUL-separated into an array, because a checkout whose
    # path has a space in it -- and this one has -- splits an unquoted list
    # into halves that are not filenames, and the compiler then reports that
    # it found no source while looking at two.
    kotlin_sources=()
    while IFS= read -r -d '' one; do
        kotlin_sources+=("$one")
    done < <(find "$ROOT/bindings/kotlin" -name '*.kt' -print0 2>/dev/null)
    # BindingCheck.kt is compiled with the rest and asserts with kotlin.test,
    # which ships in the lib/ of the distribution kotlinc runs from, beside
    # the standard library the JVM run below needs as well. The directory is
    # read off the command rather than guessed, and asserted to hold both.
    #
    # Two layouts, because Homebrew's `kotlin` is not the distribution
    # unpacked: its bin/kotlinc is a one-line wrapper that execs the real
    # compiler under libexec/, so `readlink -f` lands beside the wrapper and
    # the jars are a directory further in. The distribution's own layout is
    # tried first, and the wrapper's after it.
    kotlin_home="$(cd "$(dirname "$(readlink -f "$(command -v kotlinc)")")/.." 2>/dev/null && pwd)"
    kotlin_lib="$kotlin_home/lib"
    if [ ! -s "$kotlin_lib/kotlin-stdlib.jar" ] && [ -s "$kotlin_home/libexec/lib/kotlin-stdlib.jar" ]; then
        kotlin_lib="$kotlin_home/libexec/lib"
    fi
    if [ "${#kotlin_sources[@]}" -eq 0 ]; then
        fail "no Kotlin source found under bindings/kotlin, so nothing was compiled"
    elif [ ! -s "$kotlin_lib/kotlin-test.jar" ] || [ ! -s "$kotlin_lib/kotlin-stdlib.jar" ]; then
        fail "kotlinc runs from a distribution with no kotlin-test.jar and kotlin-stdlib.jar in $kotlin_lib"
    else
        kotlin_classes=$(mktemp -d)
        if kotlinc -cp "$kotlin_lib/kotlin-test.jar:$COROUTINES_JAR" "${kotlin_sources[@]}" \
            -d "$kotlin_classes" >/dev/null 2>&1; then
            pass "kotlinc"
        else
            fail "kotlinc, over bindings/kotlin"
            rm -rf "$kotlin_classes"
            kotlin_classes=""
        fi
    fi
else
    skip "kotlinc: no Kotlin compiler (brew install kotlin)"
fi

# The JNI shim needs jni.h, and `java_home` answers with a JRE on a machine
# that has one installed beside no JDK -- the applet plugin is one. So the
# header is what is looked for, not the command.
jdk="${JAVA_HOME:-$(/usr/libexec/java_home 2>/dev/null || true)}"
if [ -n "$jdk" ] && [ -f "$jdk/include/jni.h" ]; then
    for shim in sipral_jni idiomatic_media; do
        cc -fsyntax-only -Wall -Wextra -Werror \
            -I"$jdk/include" -I"$jdk/include/darwin" -I"$ROOT/bindings/c/include" \
            "$ROOT/bindings/kotlin/sipral/src/main/jni/$shim.c" >/dev/null 2>&1 \
            && pass "cc -fsyntax-only, $shim.c" \
            || fail "cc -fsyntax-only, bindings/kotlin/sipral/src/main/jni/$shim.c"
    done

    # Compiling the shim says it is C, not that it works. So it is linked
    # against the shared library built above, beside a helper that polls from
    # a thread no JVM made, and BindingCheck.kt / IdiomaticCheck.kt run
    # against the two on a JVM under -Xcheck:jni. What each run printed is
    # looked for as well as how it exited, because a JVM that ran nothing
    # also exits zero.
    if [ -z "$kotlin_classes" ]; then
        skip "the JVM run: kotlinc compiled nothing to run, which the lines above say why"
    elif [ ! -s "$DYLIB" ]; then
        fail "the JVM run: $DYLIB is not there to link the shim against"
    elif [ ! -x "$jdk/bin/java" ]; then
        fail "the JVM run: $jdk carries include/jni.h and no bin/java"
    else
        work=$(mktemp -d)
        linked=1
        # idiomatic_media.c is hand-written, not generated, and links into
        # the same "sipral_jni" library the generated shim does: the two
        # structs it builds (sipral_media_packet_t, sipral_transmit_t) are
        # what SipralAbi.kt itself cannot construct (bindings/kotlin/README.md),
        # so org.sipral.idiomatic's own native calls have to resolve out of
        # the library the generated one already loads.
        for pair in "sipral_jni:bindings/kotlin/sipral/src/main/jni/sipral_jni.c bindings/kotlin/sipral/src/main/jni/idiomatic_media.c" \
            "sipral_jni_check:bindings/kotlin/sipral/src/test/jni/native_thread.c"; do
            name="${pair%%:*}"
            sources="${pair#*:}"
            abs_sources=()
            for src in $sources; do abs_sources+=("$ROOT/$src"); done
            if ! cc -std=c11 -Wall -Wextra -Werror -dynamiclib \
                -I"$jdk/include" -I"$jdk/include/darwin" -I"$ROOT/bindings/c/include" \
                -o "$work/lib${name}.dylib" "${abs_sources[@]}" \
                -L"$ROOT/target/release" -lsipral_ffi -Wl,-rpath,"$ROOT/target/release" \
                >"$work/cc" 2>&1; then
                fail "$sources does not build against the shared library:"
                sed 's/^/        /' "$work/cc"
                linked=0
            fi
        done
        if [ "$linked" -eq 1 ]; then
            ran=$("$jdk/bin/java" -Xcheck:jni -Djava.library.path="$work" \
                -cp "$kotlin_classes:$kotlin_lib/kotlin-stdlib.jar:$kotlin_lib/kotlin-test.jar:$COROUTINES_JAR" \
                org.sipral.BindingCheckKt 2>&1)
            exited=$?
            said=$(printf '%s\n' "$ran" | grep '^kotlin binding: ' || true)
            warned=$(printf '%s\n' "$ran" \
                | grep -E 'WARNING in native method|WARNING: JNI|FATAL ERROR in native method' || true)
            if [ "$exited" -ne 0 ]; then
                fail "BindingCheck.kt did not come back zero:"
                printf '%s\n' "$ran" | sed 's/^/        /'
            elif [ -z "$said" ]; then
                fail "BindingCheck.kt came back zero and said nothing, so nothing was checked"
            elif [ -n "$warned" ]; then
                fail "-Xcheck:jni found something wrong in the shim:"
                printf '%s\n' "$warned" | sed 's/^/        /'
            else
                pass "${said#kotlin binding: }"
            fi

            ran=$("$jdk/bin/java" -Xcheck:jni -Djava.library.path="$work" \
                -cp "$kotlin_classes:$kotlin_lib/kotlin-stdlib.jar:$kotlin_lib/kotlin-test.jar:$COROUTINES_JAR" \
                org.sipral.idiomatic.IdiomaticCheckKt 2>&1)
            exited=$?
            said=$(printf '%s\n' "$ran" | grep '^kotlin idiomatic: ' || true)
            warned=$(printf '%s\n' "$ran" \
                | grep -E 'WARNING in native method|WARNING: JNI|FATAL ERROR in native method' || true)
            if [ "$exited" -ne 0 ]; then
                fail "IdiomaticCheck.kt did not come back zero:"
                printf '%s\n' "$ran" | sed 's/^/        /'
            elif [ -z "$said" ]; then
                fail "IdiomaticCheck.kt came back zero and said nothing, so nothing was checked"
            elif [ -n "$warned" ]; then
                fail "-Xcheck:jni found something wrong in the idiomatic layer's native calls:"
                printf '%s\n' "$warned" | sed 's/^/        /'
            else
                pass "${said#kotlin idiomatic: }"
            fi
        fi
        rm -rf "$work"
    fi
else
    skip "the JNI shim: no JDK carrying include/jni.h (JAVA_HOME must name a JDK, not a JRE)"
fi
[ -n "$kotlin_classes" ] && rm -rf "$kotlin_classes"

# SwiftPM reads Package.swift by compiling it against the PackageDescription
# module, which a full Xcode ships and the Command Line Tools alone do not --
# so the manifest is tried first and its failure is told apart from the
# package's.
if (cd "$ROOT/bindings" && xcrun --toolchain default swift package dump-package) >/dev/null 2>&1; then
    (cd "$ROOT/bindings" && xcrun --toolchain default swift build) >/dev/null 2>&1 \
        && pass "swift build" || fail "swift build, in bindings/"

    # SipralTests and SipralLabAgent link against $DYLIB (Package.swift's own
    # `linkAgainstSipralFfi`, an absolute path computed from the manifest's
    # own location) rather than merely compiling against the header the way
    # `swift build` above does, so this is the step that actually drives two
    # real stacks through the Swift layer -- the loopback call
    # bindings/python/tests/test_call.py proves the Python layer with,
    # carried through Call/Media/Account, plus CallKitBridge/PushKitBridge's
    # own sequence against a recording CallKitProviding.
    if [ -s "$ROOT/$DYLIB" ]; then
        (cd "$ROOT/bindings" && xcrun --toolchain default swift test) >/dev/null 2>&1 \
            && pass "swift test" || fail "swift test, in bindings/"
    else
        fail "swift test: $DYLIB is not there to link against (the build step above must pass first)"
    fi
else
    skip "swift build: SwiftPM cannot read the manifest here (the Command Line Tools ship no PackageDescription module; a full Xcode does)"
    skip "swift test: same reason"
fi

# Unlike dotnet/kotlinc/swift above, python3 and cffi are not optional
# toolchains this step may find missing: bindings/python/sipral/_sipral_cffi.py
# is one of the five files "the header and the bindings" step above already
# regenerated and compared, so a machine that cannot import it has not
# actually checked that step's own output. No C compiler is needed -- cffi's
# ABI mode reads the cdef and dlopen's $DYLIB directly -- so the only two
# things this can be missing on a machine that built the rest of this gate
# are python3 itself and the cffi package.
step "the python bindings"
if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 is not installed"
elif ! python3 -c 'import cffi' >/dev/null 2>&1; then
    fail "python3 has no cffi (pip install cffi)"
elif [ ! -s "$DYLIB" ]; then
    fail "the python bindings: $DYLIB is not there to load (the build step above must pass first)"
else
    if SIPRAL_LIBRARY="$ROOT/$DYLIB" python3 -c \
        'import sys; sys.path.insert(0, "bindings/python"); import sipral' >/dev/null 2>&1; then
        pass "python3 -c 'import sipral'"
    else
        fail "python3 could not import sipral against $DYLIB"
    fi

    work=$(mktemp -d)
    if SIPRAL_LIBRARY="$ROOT/$DYLIB" python3 -m unittest discover \
        -s "$ROOT/bindings/python/tests" -t "$ROOT/bindings/python" >"$work/out" 2>&1; then
        pass "python3 -m unittest discover, bindings/python/tests"
    else
        fail "python3 -m unittest discover, bindings/python/tests:"
        sed 's/^/        /' "$work/out"
    fi
    rm -rf "$work"
fi

step "package --dry-run"
# The four scripts under scripts/package/ each need at least one machine this
# gate does not have: win-x64, win-arm64 and linux-x64 natives, and the
# Android .so's, come from another machine's toolchain, not from a Mac. What
# this step proves is everything short of that: the scripts run to
# completion, the parts buildable on a Mac are built for real (macOS and iOS
# via xcodebuild and cargo, the Python and .NET packages carrying real macOS
# natives, the Kotlin classes compiled by kotlinc), and every RID or ABI this
# machine cannot reach gets its layout checked and is reported as exactly
# that -- never silently skipped, and never a fabricated native standing in
# for one nothing here built.
PKG_WORK=$(mktemp -d)

pkg_run() {
    local label="$1"; shift
    if "$@" >"$PKG_WORK/log-$label" 2>&1; then
        pass "$label"
    else
        fail "$label:"
        tail -40 "$PKG_WORK/log-$label" | sed 's/^/        /'
    fi
}

pkg_run "xcframework.sh --dry-run" \
    scripts/package/xcframework.sh --out "$PKG_WORK/xcframework" --dry-run

pkg_run "wheels.sh --dry-run" \
    scripts/package/wheels.sh --out "$PKG_WORK/wheels" --dry-run

pkg_run "nuget.sh collect (osx-arm64, osx-x64)" \
    scripts/package/nuget.sh collect --out "$PKG_WORK/nuget-natives" --rid osx-arm64 --rid osx-x64
pkg_run "nuget.sh pack --dry-run" \
    scripts/package/nuget.sh pack --out "$PKG_WORK/nuget" --staging "$PKG_WORK/nuget-natives" --dry-run

pkg_run "aar.sh assemble --dry-run" \
    scripts/package/aar.sh assemble --out "$PKG_WORK/aar" --natives "$PKG_WORK/no-natives" --dry-run

rm -rf "$PKG_WORK"

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
