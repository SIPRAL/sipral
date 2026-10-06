#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# Everything that must hold before a commit. Run it, do not read it.
#
# The checks are grouped into areas, and an area is a list of the step
# functions below: the complete gate runs every area, an area gate runs some
# of them, and both call the same functions. `scripts/check.sh --help` lists
# the areas; docs/11-testing.md, "Where the checks run", says when to run
# which.
set -uo pipefail

# found [GREP OPTIONS] PATTERN: whether standard input has a line PATTERN
# matches, read to its end. `grep -q` stops at the first match, and under
# pipefail whatever is still writing into the pipe then dies of SIGPIPE and
# fails the pipeline: a match read as none, and more often the busier the
# machine. A gate run in parallel lost classes.jar's first entries that way.
found() { grep "$@" >/dev/null; }

cd "$(dirname "$0")/.."
ROOT="$PWD"

# Every `dotnet` below runs once and exits. Left to its defaults it starts a
# compiler server and MSBuild worker nodes that outlive it by minutes and
# inherit this script's file descriptors, so anything waiting on this run --
# a lock held around it, a pipe read to its end -- waits for them too. MSBuild
# reads the environment as properties, so these reach every invocation.
export UseSharedCompilation=false MSBUILDDISABLENODEREUSE=1 DOTNET_CLI_USE_MSBUILD_SERVER=0

# In the order the complete gate reports them.
AREAS="hygiene rust abi numbers swift dotnet kotlin jvm python pipecat agents dart rn site"
# The layers: every area that loads the C library built from sipral-ffi.
LAYERS="swift dotnet kotlin jvm python pipecat agents dart rn"

usage() {
    cat <<'EOF'
usage: scripts/check.sh                       the complete gate: every area
       scripts/check.sh --only AREA[,AREA...] [--crates CRATE[,CRATE...]]
       scripts/check.sh --hygiene-only        the same as --only hygiene
       scripts/check.sh --changed [BASE]      the areas a change touches
       any of these with --list               print the areas it would run, run nothing

areas:
  hygiene  the tree: headers, provenance, language, private names, the fuzz
           corpus, the ABI's declarations, the interop matrix, licences,
           secrets. No build of the workspace.
  rust     cargo fmt, clippy, test, rustdoc and the release build of the
           workspace; the code for Windows, Linux, iOS and Android; the
           feature combinations; sipral-aec-webrtc; the fuzz targets;
           cargo deny. --crates narrows fmt, clippy, test, rustdoc and the
           release build to the named packages and leaves out the rest.
  abi      the C library and its symbols, bindings/c/smoke.c linked and run,
           the C against glibc, abi-gen --check, the version rule, and the
           layout and offsets on every target.
  numbers  the figures the README, docs/19-numbers.md, docs/23 and the
           website publish -- the library's size, the INVITE's, a call's
           memory and an idle stack's, a frame of the in-band digit
           detector -- measured and held to docs/numbers.toml.
  swift    bindings/ (SwiftPM) built and tested, xcframework.sh --dry-run
           and the root Package.swift.
  dotnet   bindings/dotnet built and tested, nuget.sh collect and pack.
  kotlin   bindings/kotlin compiled, the JNI shims, the checks on a JVM
           (the React Native package's Android logic among them),
           aar.sh assemble --dry-run.
  jvm      bindings/jvm's loader and Java layer and their tests, jvm.sh.
  python   bindings/python imported and tested, wheels.sh --dry-run, the
           linux-arm64 cross path.
  pipecat  integrations/pipecat tested over bindings/python, in a virtual
           environment with pipecat-ai.
  agents   integrations/agents tested over bindings/python against local
           stand-ins for each service, in a virtual environment with
           websockets.
  dart     bindings/dart analysed, formatted and tested, pub.sh --dry-run.
  rn       bindings/react-native: jest, tsc, codegen, the Android library
           with Gradle, the iOS half, npm.sh --dry-run.
  site     the documentation site built and its links checked.

--changed reads `git diff` against BASE (default: the merge base with
origin/main) and the untracked files, picks the areas those paths reach and
prints why; hygiene always runs. Areas run in parallel, at most
SIPRAL_CHECK_JOBS at once (default: the number of CPUs), and each one's
output is kept in target/check/AREA.log.
EOF
}

MODE=full
LIST=0
SELECTED=""
CRATES=""
BASE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --hygiene-only) MODE=only; SELECTED="$SELECTED hygiene" ;;
        --only)
            [ $# -ge 2 ] || { usage >&2; exit 2; }
            MODE=only; SELECTED="$SELECTED $(printf '%s' "$2" | tr ',' ' ')"; shift ;;
        --only=*) MODE=only; SELECTED="$SELECTED $(printf '%s' "${1#--only=}" | tr ',' ' ')" ;;
        --crates)
            [ $# -ge 2 ] || { usage >&2; exit 2; }
            CRATES="$CRATES $(printf '%s' "$2" | tr ',' ' ')"; shift ;;
        --crates=*) CRATES="$CRATES $(printf '%s' "${1#--crates=}" | tr ',' ' ')" ;;
        --changed)
            MODE=changed
            if [ $# -ge 2 ] && [ "${2#-}" = "$2" ]; then BASE="$2"; shift; fi ;;
        --list) LIST=1 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'check.sh: unknown argument %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done
if [ "$MODE" = only ]; then
    for a in $SELECTED; do
        case " $AREAS " in
            *" $a "*) ;;
            *) printf 'check.sh: no area called %s (areas: %s)\n' "$a" "$AREAS" >&2; exit 2 ;;
        esac
    done
    [ -n "$(printf '%s' "$SELECTED" | tr -d ' ')" ] || { usage >&2; exit 2; }
fi
# --crates narrows the rust area and nothing else, so it is only taken where
# that is what was asked for: the complete gate and --changed run all of it.
if [ -n "$CRATES" ]; then
    case " $SELECTED " in
        *" rust "*) ;;
        *) printf 'check.sh: --crates narrows the rust area: use it with --only rust\n' >&2; exit 2 ;;
    esac
fi

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
# only for a tool that is not on this machine, and only when it names what is
# missing and how to get it. Never for something that could be checked here
# and was not: a gate that goes green without looking has not looked.
skip() { printf '  skip  %s\n' "$1"; }
# what a narrowed run left out, so that nobody reads it as the whole gate;
# counted as neither
note() { printf '  note  %s\n' "$1"; }
step() { printf '\n%s\n' "$1"; }

# One `cargo test` run, quiet when it passes and named when it does not. The
# whole output goes to a log under target/check-logs, one file per run, kept
# whatever the outcome: a test that fails only when the machine is loaded
# fails once in twenty gates, and a run whose output went to /dev/null has
# nothing left to say which test it was. On failure the names of the failing
# tests are printed under the FAIL line, with the log's path.
# Usage: cargo_test "<what the FAIL line says>" <cargo test arguments...>
TEST_LOGS="$ROOT/target/check-logs"
# test_log LABEL: where cargo_test keeps the output of the run it calls LABEL
test_log() { printf '%s/%s.log' "$TEST_LOGS" "$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-120)"; }
cargo_test() {
    local label="$1"
    shift
    mkdir -p "$TEST_LOGS"
    local log
    log="$(test_log "$label")"
    if cargo test "$@" >"$log" 2>&1; then
        pass "$label"
        return 0
    fi
    fail "$label"
    local failed
    failed=$(sed -n 's/^test \(.*\) \.\.\. FAILED$/\1/p' "$log" | sort -u)
    if [ -n "$failed" ]; then
        printf '%s\n' "$failed" | sed 's/^/        failed: /'
    else
        grep -E '^error(\[|:)' "$log" | head -5 | sed 's/^/        /'
    fi
    printf '        the whole output: %s\n' "${log#$ROOT/}"
    return 1
}

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

# The names abi.rs's SURFACE lists that match $1.
listed() {
    sed -n '/^pub const SURFACE/,/^};/p' crates/sipral-ffi/src/abi.rs | grep -o "$1" | sort -u
}

# The C library, as the release build of sipral-ffi leaves it: what the abi
# area checks and every layer loads.
DYLIB="target/release/libsipral_ffi.dylib"
ARCHIVE="target/release/libsipral_ffi.a"

# Apple's nm is an LLVM 14 tool and refuses to read an object carrying newer
# bitcode, which under `lto = "thin"` is every Rust object in the archive.
# nm-classic reads the Mach-O symbol table and never looks at the bitcode; the
# dylib is plain Mach-O and either would do.
exported() { xcrun nm-classic -gU "$1" 2>/dev/null | awk 'NF == 3 { print $3 }' | sort -u; }

# Everything a run keeps: each area's output in target/check/AREA.log, each
# area's scratch space under work/, and under prep/ what several areas share.
CHECK_DIR="$ROOT/target/check"
PREP="$CHECK_DIR/prep"

# prep NAME FUNCTION: what more than one area needs -- the C library, the
# Kotlin layer's classes, the JNI shims, sipral.aar -- made once per run,
# by whichever area asks first, while any other that asks waits for it.
# FUNCTION is given $PREP/NAME to build into; its output is kept in
# $PREP/NAME.log and its exit status, which prep returns, in
# $PREP/NAME.status.
prep() {
    local name="$1" fn="$2"
    if mkdir "$PREP/$name.lock" 2>/dev/null; then
        mkdir -p "$PREP/$name"
        "$fn" "$PREP/$name" >"$PREP/$name.log" 2>&1
        prep_record "$name" $?
    else
        while [ ! -f "$PREP/$name.status" ]; do sleep 1; done
    fi
    return "$(cat "$PREP/$name.status")"
}

# prep_record NAME STATUS: NAME was made by a step of its own, which reports
# it, and anything that asks for it from here on takes that result.
prep_record() {
    mkdir "$PREP/$1.lock" 2>/dev/null
    printf '%s\n' "$2" >"$PREP/$1.status.part" && mv "$PREP/$1.status.part" "$PREP/$1.status"
}

# What a failed prep printed, as this area's own failure: each line it
# printed at the margin is a FAIL, and what it indented goes under it.
prep_failed() {
    local line
    while IFS= read -r line; do
        case "$line" in
            " "*) printf '%s\n' "$line" ;;
            *) fail "$line" ;;
        esac
    done <"$PREP/$1.log"
}

# gate_lock NAME COMMAND...: COMMAND, with no other area inside NAME at the
# same time.
gate_lock() {
    local name="$1" status
    shift
    until mkdir "$PREP/$name.held" 2>/dev/null; do sleep 1; done
    "$@"
    status=$?
    rmdir "$PREP/$name.held"
    return "$status"
}

# The C library every layer loads, built as the abi area builds it. When the
# abi area runs it goes first and its build is the one taken; without it,
# the first layer to ask builds the library and the others wait.
build_library() { cargo build -p sipral-ffi --release; }
need_library() {
    prep library build_library && return 0
    fail "cargo build -p sipral-ffi --release, the library this area loads:"
    tail -20 "$PREP/library.log" | sed 's/^/        /'
    return 1
}

step_licence_headers() {
    step "licence headers"
    missing=$(tracked '*.rs' '*.sh' '*.h' '*.c' '*.swift' '*.cs' '*.kt' '*.kts' '*.ts' '*.js' '*.mm' '*.podspec' | while read -r f; do
        head -3 "$f" | found 'SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial' || echo "$f"
    done)
    if [ -z "$missing" ]; then pass "SPDX header present"; else
        fail "SPDX header missing:"; printf '        %s\n' $missing
    fi

    nocopy=$(tracked '*.rs' '*.sh' '*.h' '*.c' '*.swift' '*.cs' '*.kt' '*.kts' '*.ts' '*.js' '*.mm' '*.podspec' | while read -r f; do
        head -4 "$f" | found 'Copyright (c) 2026 Sytek' || echo "$f"
    done)
    [ -z "$nocopy" ] && pass "copyright line present" || {
        fail "copyright line missing:"; printf '        %s\n' $nocopy
    }
}

step_nothing_internal() {
    step "nothing internal in the tree"
    leaked=$(tracked | grep -E '^(intern/|CLAUDE\.md$|\.claude/|\.vscode/)' || true)
    [ -z "$leaked" ] && pass "internal paths untracked" || {
        fail "internal files tracked:"; printf '        %s\n' $leaked
    }

    # A published file that names a folder or file kept out of the tree points
    # its reader at something they can never open. Two mentions are meant: the
    # G.729 conformance test's path to the ITU vectors, which are deliberately
    # not committed, and docs/11-testing.md's sentence saying where the private
    # name list lives.
    pointers=$(others | grep -vx '\.gitignore' | tr '\n' '\0' \
        | xargs -0 grep -IHnE '\.claude/|CLAUDE\.md|AGENTS\.md|(^|[^A-Za-z0-9_])intern/' 2>/dev/null \
        | grep -vE '^crates/sipral-media/src/g729/[a-z_]+\.rs:[0-9]+:.*intern/itu/g729-vectors/' \
        | grep -vE '^docs/11-testing\.md:[0-9]+:.*\(in the ignored `intern/`' || true)
    [ -z "$pointers" ] && pass "no published file points into the untracked folders" || {
        fail "published files point into the untracked folders:"; printf '%s\n' "$pointers" | sed 's/^/        /'
    }

    captures=$(tracked | grep -E '\.pcapng?$' | grep -v '^fixtures/rfc4475/' || true)
    [ -z "$captures" ] && pass "no captures outside fixtures/rfc4475" || {
        fail "captures tracked:"; printf '        %s\n' $captures
    }
}

step_security_policy() {
    step "security policy"
    # A buyer's security review reads SECURITY.md first: how to report, what
    # happens next, which versions get fixes. Its reporting channel is never an
    # address -- "no addresses to harvest" below already scans it with the rest.
    if [ -n "$(tracked | grep -x 'SECURITY.md')" ]; then
        missing=""
        for h in '## Reporting a vulnerability' '## What happens after a report' '## Supported versions'; do
            grep -qxF "$h" SECURITY.md || missing="$missing|$h"
        done
        [ -z "$missing" ] && pass "SECURITY.md says how to report, what happens next, and what is supported" || {
            fail "SECURITY.md lacks a section:"; printf '%s' "$missing" | tr '|' '\n' | sed '/^$/d; s/^/        /'
        }
    else
        fail "SECURITY.md is not tracked"
    fi
}

step_rfc4475_corpus() {
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
}

# Every copy of the release version -- the crates' dependencies on each
# other and the lockfiles, the .NET project and SipralInfo.cs, the Python
# project and __version__, the Dart, React Native and JVM manifests --
# against the workspace's, which scripts/version.sh owns: the list of where
# a copy lives is kept there and nowhere else.
step_one_version() {
    step "one version everywhere (scripts/version.sh --check)"
    scripts/version.sh --check || FAIL=1
}

step_no_addresses() {
    step "no addresses to harvest"
    mails=$(others '*.rs' '*.md' '*.toml' '*.sh' '*.yml' '*.yaml' \
        '*.h' '*.c' '*.swift' '*.cs' '*.kt' '*.kts' '*.ts' '*.js' '*.mm' '*.json' '*.podspec' '*.xml' \
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
}

step_language() {
    step "language of the published tree"
    dia=$(others '*.rs' '*.md' '*.toml' '*.sh' '*.yml' '*.h' '*.c' '*.swift' '*.cs' '*.kt' \
        '*.kts' '*.ts' '*.js' '*.mm' '*.json' '*.podspec' '*.xml' \
        | xargs grep -lI '[ăâîșțĂÂÎȘȚşţŞŢ]' 2>/dev/null || true)
    [ -z "$dia" ] && pass "English only" || {
        fail "Romanian text in published files:"; printf '        %s\n' $dia
    }
}

step_provenance() {
    step "provenance"
    forbidden='pjsip\|pjproject\|pjmedia\|sofia-sip\|osip2\|exosip\|linphone\|bcg729\|spandsp\|libnice\|janus'
    hits=$(others '*.rs' '*.h' '*.c' '*.swift' '*.cs' '*.kt' '*.kts' '*.ts' '*.js' '*.mm' \
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
    stray=$(git ls-files fixtures | cut -d/ -f2 | sort -u | grep -vxE 'rfc4475|rfc5118|rfc4317|replay' || true)
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
        '*.kts' '*.ts' '*.js' '*.mm' '*.json' '*.podspec' '*.xml' \
        | xargs grep -lin 'co-authored-by: claude\|generated with \[claude\|copilot' 2>/dev/null || true)
    [ -z "$traces" ] && pass "no assistant traces" || {
        fail "assistant traces in:"; printf '        %s\n' $traces
    }

    # Some names must never reach this tree -- a customer's, a product sold on its
    # own -- and a list of them committed here would publish exactly what it
    # guards. So the list lives in intern/, which the first check keeps out of git,
    # one fixed string per line, matched without regard to case in every file the
    # tree would publish and in every commit message not yet pushed. A checkout
    # without the list cannot check, and says so.
    private_names="$ROOT/intern/ops/private-names.txt"
    if [ -s "$private_names" ]; then
        named=$(others | while read -r f; do
            [ -f "$ROOT/$f" ] && grep -IqiF -f "$private_names" "$ROOT/$f" && printf '%s\n' "$f"
        done)
        upstream=$(git -C "$ROOT" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)
        told=""
        if [ -n "$upstream" ]; then
            told=$(git -C "$ROOT" log --format='%h %s%n%b' "$upstream..HEAD" \
                | grep -iF -f "$private_names" || true)
        fi
        if [ -z "$named" ] && [ -z "$told" ]; then
            pass "no private name in the tree or in an unpushed commit message"
        else
            [ -n "$named" ] && { fail "a private name in:"; printf '        %s\n' $named; }
            [ -n "$told" ] && { fail "a private name in an unpushed commit message:"; printf '%s\n' "$told" | sed 's/^/        /'; }
        fi
    else
        skip "private names: intern/ops/private-names.txt is not on this machine"
    fi

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
step_no_clock_read() {
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
step_c_asks_for_posix() {
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
step_keys_do_not_derive_debug() {
    step "nothing that holds a key derives Debug"
    redacting="crates/sipral-core/src/sdp/session.rs:Attribute
crates/sipral-core/src/sdp/session.rs:KeyLine
crates/sipral-core/src/sdp/crypto.rs:KeySalt
crates/sipral-ua/src/account.rs:Push
crates/sipral-nat/src/ice/full/mod.rs:Credentials
crates/sipral-nat/src/ice/sdp.rs:RemoteIce
crates/sipral/src/ice.rs:Ice
crates/sipral-diag/src/redact.rs:Mode"
    derived=""
    for pair in $redacting; do
        file=${pair%%:*}
        name=${pair##*:}
        if [ ! -f "$file" ]; then
            derived="$derived
        $file is gone, and $name's redaction with it"
            continue
        fi
        # the declaration, and whether its own derive list carries Debug -- a
        # struct or an enum, since Mode::Hash's HMAC key lives in an enum variant
        line=$(grep -nE "^pub(\(crate\))? (struct|enum) $name\b" "$file" | head -1 | cut -d: -f1)
        if [ -z "$line" ]; then
            derived="$derived
        $file no longer declares $name"
            continue
        fi
        before=$((line - 1))
        if [ "$before" -ge 1 ] && sed -n "${before}p" "$file" | found 'derive(.*Debug'; then
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
}

# A panic that unwinds into C takes the host process with it, and no C caller
# can defend itself against that. The `entry!` macro is the only way to declare
# an entry point and every shape of it catches, so the guarantee holds exactly
# as long as nobody declares one by hand. That is what this looks for: the
# macro lives in error.rs and no other file in the workspace may export a
# symbol.
step_nothing_unwinds_into_c() {
    step "nothing unwinds into C"
    exported=$(tracked '*.rs' | xargs grep -ln 'no_mangle' 2>/dev/null \
        | grep -v '^crates/sipral-ffi/src/error\.rs$' || true)
    [ -z "$exported" ] && pass "every C entry point goes through the guard" || {
        fail "an entry point declared outside the entry! macro:"
        printf '        %s\n' $exported
        printf '        use entry! in crates/sipral-ffi, or the panic reaches C.\n'
    }
}

# A packaged library runs on whatever machine its target names, which for
# x86_64 is a machine from 2004: a `target-cpu` or `target-feature` in any
# build configuration would have the compiler emit instructions an older
# PC does not have, and the first one it meets is a SIGILL in a customer's
# log with nothing in ours. Nothing in this tree names one, and this is what
# keeps it so; runtime detection in a dependency is that dependency's own
# and is fine, since it checks before it runs.
step_cpu_baseline() {
    step "no CPU instructions beyond the baseline"
    tuned=$(others '*.toml' '*.sh' '*.ps1' 'build.rs' \
        | xargs grep -ln 'target-cpu\|target-feature' 2>/dev/null || true)
    [ -z "$tuned" ] && pass "no target-cpu or target-feature in any build configuration" || {
        fail "a build configuration names a CPU or a feature beyond the baseline:"
        printf '        %s\n' $tuned
        printf '        docs/05-media.md, "The built-in engine": a packaged library\n'
        printf '        must run on the oldest machine its target names.\n'
    }
}

# B7. The header and the three bindings are printed from the declarations in
# sipral-ffi, so the one thing a person can forget is the line in abi.rs that
# names a declaration. These four scans are that line's other half: the first
# two say that nothing crossing the boundary was declared where the macros
# cannot see it, and the last two compare what the modules declare against what
# abi.rs lists. The comparison the generator itself makes -- committed output
# against printed output -- needs cargo and runs below, with the build.
step_one_declaration_of_the_abi() {
    step "one declaration of the ABI"
    FFI=$(tracked '*.rs' | grep '^crates/sipral-ffi/src/' || true)

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
}

# docs/11-testing.md's generated "Interoperability matrix" section
# (scripts/interop-matrix.py) against the one fixture it can be checked
# without Docker or a live lab: interop/fixtures/lab-run.log, a real
# scripts/lab.sh run, and the date it ran on beside it. A live run regenerates
# the section with scripts/lab.sh --matrix; this only asks whether the section
# committed here is still what that fixture produces.
step_interop_matrix() {
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
}

# What `scripts/lab.sh compare` reads its numbers with (interop/compare/
# wire.py), against captures and logs its own tests write byte by byte: the
# comparison with PJSIP runs only on a machine with Docker, and a reading of
# the wire that drifted would otherwise show only as a wrong table.
step_wire_reader() {
    step "the comparison's wire reader"
    if command -v python3 >/dev/null 2>&1; then
        wire_out=$(mktemp)
        if PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s interop/compare \
            >"$wire_out" 2>&1; then
            pass "python3 -m unittest discover, interop/compare"
        else
            fail "python3 -m unittest discover, interop/compare:"
            sed 's/^/        /' "$wire_out"
        fi
        rm -f "$wire_out"
    else
        fail "python3 not found, and interop/compare/wire.py needs it"
    fi
}

# THIRD-PARTY-LICENSES.txt against the normal dependency graph of the crates
# Sipral ships a binary of. tools/license-gen regenerates it from
# `cargo tree` and each dependency's own registry checkout; this only asks
# whether the file committed here is still what that graph produces.
step_third_party_licences() {
    step "third-party licences match the dependency graph"
    if lic_out=$(cargo run -p sipral-license-gen -- --check 2>&1); then
        pass "THIRD-PARTY-LICENSES.txt matches the shipped dependency graph"
    else
        fail "THIRD-PARTY-LICENSES.txt is stale:"
        printf '        %s\n' "$lic_out"
        printf '        regenerate it: cargo run -p sipral-license-gen\n'
    fi
}

# The workspace, or with --crates the packages named: `--workspace` becomes
# one `-p` per package, and the fmt line says which it read.
step_build() {
    step "build"
    local scope=(--workspace) fmt_scope=(--all) said="" crate
    if [ -n "$CRATES" ]; then
        scope=()
        for crate in $CRATES; do scope+=(-p "$crate"); done
        fmt_scope=("${scope[@]}")
        said=" ${scope[*]}"
    fi
    cargo fmt "${fmt_scope[@]}" --check >/dev/null 2>&1 && pass "cargo fmt$said" || fail "cargo fmt ${fmt_scope[*]}"
    # --all-features, because the reference loop is behind one and nothing else
    # would ever lint it
    cargo clippy "${scope[@]}" --all-targets --all-features -- -D warnings >/dev/null 2>&1 \
        && pass "cargo clippy$said" || fail "cargo clippy ${scope[*]} --all-targets --all-features"
    cargo_test "cargo test ${scope[*]} --all-features" "${scope[@]}" --all-features
    # rustdoc is a compiler nothing else here runs, and the mistakes only it sees
    # are the ones a reader hits: a public doc linking something private, a link
    # that resolves to nothing, an RFC quotation whose angle brackets read as
    # HTML. A documentation comment is source, and source compiles clean.
    # --all-features for the reason clippy above takes it: the reference loop is
    # behind one, and rustdoc that never reads a module never reads its links.
    RUSTDOCFLAGS="-D warnings" cargo doc "${scope[@]}" --no-deps --all-features >/dev/null 2>&1 \
        && pass "cargo doc$said" \
        || fail "RUSTDOCFLAGS=-D warnings cargo doc ${scope[*]} --no-deps --all-features"
    # Not sipral-ffi as a package of its own: across the workspace the facade
    # is built with `headless` as well, and a library built that way would
    # replace target/release/libsipral_ffi.dylib -- the one the abi area
    # checks and the layers load, perhaps while they load it. It is still
    # compiled here, as tools/abi-gen's dependency, which leaves that file
    # alone; the library itself is the abi area's own build.
    # Named with --crates, it is built on its own, exactly as the abi area
    # builds it.
    local release=(--workspace --exclude sipral-ffi) alone=0
    if [ -n "$CRATES" ]; then
        release=()
        for crate in $CRATES; do
            if [ "$crate" = sipral-ffi ]; then alone=1; else release+=(-p "$crate"); fi
        done
    fi
    if [ "${#release[@]}" -gt 0 ]; then
        cargo build "${release[@]}" --release >/dev/null 2>&1 && pass "release build$said" \
            || fail "cargo build ${release[*]} --release"
    fi
    if [ "$alone" -eq 1 ]; then
        cargo build -p sipral-ffi --release >/dev/null 2>&1 && pass "release build -p sipral-ffi" \
            || fail "cargo build -p sipral-ffi --release"
    fi
}

# The header describes a library, and nothing until now said there was one:
# a crate that declares no crate-type produces an rlib and nothing a C linker
# can open. What this step reads is the two artefacts its own release build
# produces, and the names in them. The tests are -s rather than -f because a
# run whose build went red still finds yesterday's file here, and a file
# truncated to nothing would otherwise be reported as built.
step_the_library() {
    step "the library, and what it exports"

    # The two artefacts are removed and built here rather than read out of
    # whatever an earlier build happened to leave behind. Take `crate-type`
    # out of the manifest and `cargo build --workspace --release` still exits 0,
    # having produced no C library at all -- and a step that only reads the
    # directory finds yesterday's and prints ok five times. That regression is the
    # one this step exists for, so it must not be the one it cannot see.
    #
    # The build is also the one every layer loads, so it is recorded as the
    # library they wait for (need_library, below) rather than built again.
    rm -f "$DYLIB" "$ARCHIVE"
    cargo build -p sipral-ffi --release >"$PREP/library.log" 2>&1
    prep_record library $?

    if [ "$(cat "$PREP/library.status")" -ne 0 ]; then
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
}

# A header, three generated bindings and a scan that says they agree still
# prove nothing about a compiler having read any of it. This is the one
# consumer in the tree that is written the way an integrator writes one:
# compiled with warnings fatal, linked against the shared library, and run.
step_linked_from_c() {
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
}

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
step_c_against_glibc() {
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
                    bindings/kotlin/sipral/src/main/jni/audio_routes.c \
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
}

# Everything behind cfg(target_os = "windows") in sipral-io-wasapi, everything
# behind cfg(target_os = "linux") in sipral-io-pipewire and the harness's own
# PipeWire flow, the three iOS bodies in sipral-io-coreaudio, and the AAudio
# streams and backend behind cfg(target_os = "android") in sipral-io-aaudio
# and sipral-audio, are read by no compiler on this machine, and a crate whose platform half only compiles
# on the platform is a crate that stops compiling there quietly. The targets
# are rustup components rather than machines, so this type-checks and lints
# without linking anything -- which is what rots. Rustdoc goes with clippy for
# Windows and Linux, because the links into the platform-only types are the
# ones that resolve on no other target. What this cannot do is run them:
# interop/pipewire/run.sh is where the Linux half meets a real PipeWire.
step_other_targets() {
    step "the code this machine does not compile"
    if rustup target list --installed 2>/dev/null | found -x x86_64-pc-windows-msvc; then
        cargo clippy -p sipral-io-wasapi --target x86_64-pc-windows-msvc --all-targets \
            -- -D warnings >/dev/null 2>&1 \
            && pass "cargo clippy -p sipral-io-wasapi for Windows" \
            || fail "cargo clippy -p sipral-io-wasapi --target x86_64-pc-windows-msvc --all-targets"
        RUSTDOCFLAGS="-D warnings" cargo doc -p sipral-io-wasapi --no-deps \
            --target x86_64-pc-windows-msvc >/dev/null 2>&1 \
            && pass "cargo doc -p sipral-io-wasapi for Windows" \
            || fail "RUSTDOCFLAGS=-D warnings cargo doc -p sipral-io-wasapi --no-deps --target x86_64-pc-windows-msvc"
        # the harness's own WASAPI flow, the Windows twin of the PipeWire one
        # below: nothing else here ever compiles it
        cargo clippy -p sipral-interop --features wasapi --target x86_64-pc-windows-msvc \
            --all-targets -- -D warnings >/dev/null 2>&1 \
            && pass "cargo clippy -p sipral-interop --features wasapi for Windows" \
            || fail "cargo clippy -p sipral-interop --features wasapi --target x86_64-pc-windows-msvc --all-targets"
    else
        fail "x86_64-pc-windows-msvc is not installed: rustup target add x86_64-pc-windows-msvc"
    fi
    if [ "$(uname -s)" = Linux ]; then
        pass "sipral-io-pipewire compiles natively here, with the rest of the workspace"
    elif rustup target list --installed 2>/dev/null | found -x x86_64-unknown-linux-gnu; then
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
    if rustup target list --installed 2>/dev/null | found -x aarch64-apple-ios; then
        cargo clippy -p sipral-io-coreaudio --target aarch64-apple-ios --all-targets \
            -- -D warnings >/dev/null 2>&1 \
            && pass "cargo clippy -p sipral-io-coreaudio for iOS" \
            || fail "cargo clippy -p sipral-io-coreaudio --target aarch64-apple-ios --all-targets"
        # Rustdoc for every crate that builds for iOS: sipral-ffi's own graph,
        # which is what scripts/package/xcframework.sh compiles for the device,
        # read from cargo rather than listed here so a crate that joins it is
        # covered the day it does, and sipral-io-coreaudio, whose iOS half no
        # other target compiles.
        ios_docs=$(cargo tree -p sipral-ffi --target aarch64-apple-ios -e normal --prefix none 2>/dev/null \
            | awk '$1 ~ /^sipral/ && $3 ~ /^\(/ { print $1 }' | sort -u | tr '\n' ' ')
        ios_docs="${ios_docs}sipral-io-coreaudio"
        ios_args=""
        for crate in $ios_docs; do
            ios_args="$ios_args -p $crate"
        done
        RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --target aarch64-apple-ios $ios_args \
            >/dev/null 2>&1 \
            && pass "cargo doc for iOS: $ios_docs" \
            || fail "RUSTDOCFLAGS=-D warnings cargo doc --no-deps --target aarch64-apple-ios$ios_args"
    else
        fail "aarch64-apple-ios is not installed: rustup target add aarch64-apple-ios"
    fi
    # the Android half: sipral-ffi's graph as scripts/package/aar.sh builds it,
    # with the AAudio backend in it. Type-checked and linted only; the streams
    # themselves run on a phone or an emulator (docs/15-mobile.md).
    if rustup target list --installed 2>/dev/null | found -x aarch64-linux-android; then
        cargo clippy -p sipral-io-aaudio -p sipral-audio -p sipral-ffi --no-default-features \
            --target aarch64-linux-android -- -D warnings >/dev/null 2>&1 \
            && pass "cargo clippy -p sipral-io-aaudio -p sipral-audio -p sipral-ffi for Android" \
            || fail "cargo clippy -p sipral-io-aaudio -p sipral-audio -p sipral-ffi --no-default-features --target aarch64-linux-android"
        RUSTDOCFLAGS="-D warnings" cargo doc -p sipral-io-aaudio -p sipral-audio --no-deps \
            --target aarch64-linux-android >/dev/null 2>&1 \
            && pass "cargo doc -p sipral-io-aaudio -p sipral-audio for Android" \
            || fail "RUSTDOCFLAGS=-D warnings cargo doc -p sipral-io-aaudio -p sipral-audio --no-deps --target aarch64-linux-android"
    else
        fail "aarch64-linux-android is not installed: rustup target add aarch64-linux-android"
    fi
}

# crates/sipral-aec-webrtc is outside the workspace (Cargo.toml at its root
# says why: webrtc-audio-processing-sys's bundled feature needs meson, ninja
# and a C++ toolchain nothing else here asks a machine for), so
# --workspace/--all-features above never touch it and this is its one real
# build, run against its own Cargo.lock. Missing tools fail rather than skip:
# `scripts/check.sh`'s own "gata" bar is zero of either, and a step that
# quietly skipped whenever meson is absent would let the crate rot exactly
# the way the module doc for `the_synthetic_surface_reaches_every_shape`
# warns an unmeasured "wide enough" does.
step_aec_webrtc() {
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
        # Only reachable after the build above, which is what fetches abseil-cpp
        # into this crate's own target/ — the one component tools/license-gen
        # cannot read from a registry checkout alone, so this cannot run any
        # earlier than here (the workspace's own third-party-licences step,
        # above, runs long before this crate is built at all).
        if lic_out=$(cargo run -p sipral-license-gen -- --aec --check 2>&1); then
            pass "crates/sipral-aec-webrtc/THIRD-PARTY-LICENSES.txt matches its dependency graph"
        else
            fail "crates/sipral-aec-webrtc/THIRD-PARTY-LICENSES.txt is stale:"
            printf '        %s\n' "$lic_out"
            printf '        regenerate it: cargo run -p sipral-license-gen -- --aec\n'
        fi
        cargo_test "cargo test --manifest-path $manifest" --manifest-path "$manifest"
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
}

# The mirror of --all-features. Opus is behind a feature because libopus is
# licensed rather than written (`docs/05-media.md`), and the customer who
# needs it out is the one shipping hardware -- so the build without it has to
# be one somebody compiles, or the cfg rots and the promise is worth nothing.
step_without_opus() {
    step "the build without Opus"
    cargo build -p sipral --no-default-features >/dev/null 2>&1 \
        && pass "cargo build -p sipral" || fail "cargo build -p sipral --no-default-features"
    cargo build -p sipral-ffi --no-default-features >/dev/null 2>&1 \
        && pass "cargo build -p sipral-ffi" || fail "cargo build -p sipral-ffi --no-default-features"
    cargo_test "cargo test -p sipral-media --no-default-features" -p sipral-media --no-default-features
    cargo_test "cargo test -p sipral --no-default-features" -p sipral --no-default-features
    cargo_test "cargo test -p sipral-ffi --no-default-features" -p sipral-ffi --no-default-features
    # `dtls` is off to keep the handshake's RustCrypto crates out
    # (crates/sipral/Cargo.toml), and nothing else the facade links by default
    # may bring them back. AES-GCM is not among them: sipral-rtp carries it for
    # SRTP's AEAD suites (RFC 7714), which SDES keys as well as DTLS-SRTP does.
    facade_tree=$(cargo tree -p sipral --no-default-features -e normal --prefix none 2>/dev/null)
    if [ -z "$facade_tree" ]; then
        fail "cargo tree -p sipral --no-default-features printed nothing"
    elif printf '%s\n' "$facade_tree" | found -E '^(hmac|sha2|p256) '; then
        fail "cargo tree -p sipral --no-default-features names a crate only dtls should bring"
    else
        pass "no RustCrypto crate in the facade without dtls"
    fi

    # A Cargo feature belongs to the crate that declares it and features are
    # additive, so the ABI crate without its own `opus` over a facade that linked
    # the codec is a configuration somebody can really build -- and the one in
    # which an answer copied from the wrong crate's flag lies about a codec the
    # build can negotiate. Every C-side answer about Opus is read from the
    # catalogue so that this passes.
    cargo_test "cargo test -p sipral-ffi --no-default-features --features sipral/opus" \
        -p sipral-ffi --no-default-features --features sipral/opus

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
        cargo_test "cargo test -p sipral --no-default-features --features $combination" \
            -p sipral --no-default-features --features "$combination"
        cargo clippy -p sipral --no-default-features --features "$combination" --all-targets \
            -- -D warnings >/dev/null 2>&1 \
            && pass "cargo clippy -p sipral with $combination alone" \
            || fail "cargo clippy -p sipral --no-default-features --features $combination"
    done
    cargo_test "cargo test -p sipral-ffi --no-default-features --features dtls" \
        -p sipral-ffi --no-default-features --features dtls
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
            if printf '%s' "$graph" | found -iE '(^| )(p256|sipral-dtls|sipral-nat)( |$| v)'; then
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
        elif printf '%s\n' "$tree" | found -i opus; then
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
    elif printf '%s\n' "$tree" | found -i opus; then
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
        elif printf '%s\n' "$dynamic" | found -i opus; then
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
}

# the other half of B7: what is committed under bindings/ against what the
# declarations produce right now. The scans above say a declaration is listed;
# this says the listed declaration reached the header and all three bindings.
step_header_and_bindings() {
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
}

# The library is built for 32-bit Android as well as for 64-bit everything,
# and a struct of pointers is one length on each. tools/abi-gen works out
# every length and offset on the three layouts those targets fall in and
# prints them into bindings/c/abi-layout.c as assertions over the header;
# compiling that file for a target is the test, so a C compiler has the last
# word on each layout rather than the build this runs on. No sysroot is
# needed: -ffreestanding takes stddef.h and stdint.h from clang itself.
step_layout() {
    step "the layout on every target"
    if ! command -v clang >/dev/null 2>&1; then
        fail "clang not found, and bindings/c/abi-layout.c is only checked by compiling it"
    else
        for target in x86_64-linux-gnu aarch64-linux-gnu i386-linux-gnu armv7-linux-gnueabihf \
            x86_64-pc-windows-msvc i686-pc-windows-msvc; do
            if said=$(clang -target "$target" -ffreestanding -std=c11 -fsyntax-only -Werror \
                -I bindings/c/include bindings/c/abi-layout.c 2>&1); then
                pass "every length, offset and pin in bindings/c/abi-layout.c holds on $target"
            else
                fail "bindings/c/abi-layout.c does not hold on $target:"
                printf '%s\n' "$said" | grep 'error:' | head -5 | sed 's/^/        /'
            fi
        done
    fi

    # A pin is the least a caller may declare, and the one number about a struct
    # that must never move while the major stands: a caller built against the
    # oldest header of this major declares exactly that. Held against the last
    # commit, like the declarations above; the columns compared are the member
    # and the pin on each layout, not the lengths, which grow.
    pins() {
        printf '%s\n' "$1" | awk '!/^#/ && NF == 8 { print $1, $2, $3, $5, $7 }' | sort
    }
    if published_sizes=$(git show HEAD:bindings/c/abi-sizes.txt 2>/dev/null); then
        moved=$(comm -23 <(pins "$published_sizes") <(pins "$(cat bindings/c/abi-sizes.txt)"))
        read -r was_major _ <<<"$(version_of "$(git show HEAD:"$HEADER" 2>/dev/null)")"
        read -r is_major _ <<<"$(version_of "$(cat "$HEADER")")"
        if [ -z "$moved" ]; then
            pass "no pinned length moved against the last commit"
        elif [ -n "$was_major" ] && [ "$is_major" -gt "$was_major" ]; then
            pass "pinned lengths moved, and the ABI major with them ($was_major to $is_major)"
        else
            fail "a pinned length moved or went away within ABI major $is_major:"
            printf '%s\n' "$moved" | sed 's/^/        was: /'
        fi
    else
        pass "no bindings/c/abi-sizes.txt in the last commit to hold the pins to"
    fi

    # A member put into a hole between two members, or moved, changes no length
    # and no pin, and bindings/c/abi-layout.c is printed again with it, so
    # nothing above notices. It is the same fault as a member in tail padding:
    # a caller built against the header before it never wrote those bytes, and
    # the library reads them as a value it set. So every member's offset on
    # every layout is held to the last commit's, a member the last commit did
    # not have must start at or past the length the struct had there, and a
    # member it had must still be there. The union is left out: its members all
    # sit at zero, and an arm added to it is how a new event gets a payload.
    layout_facts() {
        printf '%s\n' "$1" | awk '
            /^_Static_assert\(sizeof\(/ {
                name = $0; sub(/^_Static_assert\(sizeof\(/, "", name); sub(/\).*/, "", name)
                nums = $0; sub(/.*SIPRAL_LAYOUT\(/, "", nums); sub(/\).*/, "", nums); gsub(/,/, "", nums)
                print name, "sizeof", nums
            }
            /^_Static_assert\(offsetof\(/ && !/ \+ sizeof/ {
                pair = $0; sub(/^_Static_assert\(offsetof\(/, "", pair); sub(/\).*/, "", pair)
                split(pair, p, ", ")
                nums = $0; sub(/.*SIPRAL_LAYOUT\(/, "", nums); sub(/\).*/, "", nums); gsub(/,/, "", nums)
                print p[1], p[2], nums
            }'
    }
    if published_layout=$(git show HEAD:bindings/c/abi-layout.c 2>/dev/null); then
        unions=$(grep -E '^union [a-z_0-9]+ \{' "$HEADER" | awk '{ print $2 "_t" }' | tr '\n' ' ')
        misplaced=$(awk -v unions="$unions" '
            BEGIN { split(unions, list, " "); for (i in list) union[list[i]] = 1 }
            FNR == NR { was[$1 " " $2] = $3 " " $4 " " $5; next }
            $1 in union { next }
            !(($1 " sizeof") in was) { next }
            {
                key = $1 " " $2
                now = $3 " " $4 " " $5
                seen[key] = 1
                if ($2 == "sizeof") next
                if (key in was) {
                    if (was[key] != now) print $1 "::" $2 " moved from " was[key] " to " now
                    next
                }
                split(was[$1 " sizeof"], size, " ")
                if ($3 < size[1] || $4 < size[2] || $5 < size[3])
                    print $1 "::" $2 " at " now " starts inside the length the last commit declared, " was[$1 " sizeof"]
            }
            END {
                for (key in was) {
                    split(key, part, " ")
                    if (part[2] != "sizeof" && !(key in seen) && !(part[1] in union) && ((part[1] " sizeof") in seen))
                        print part[1] "::" part[2] " went away"
                }
            }' <(layout_facts "$published_layout") <(layout_facts "$(cat bindings/c/abi-layout.c)"))
        read -r was_major _ <<<"$(version_of "$(git show HEAD:"$HEADER" 2>/dev/null)")"
        read -r is_major _ <<<"$(version_of "$(cat "$HEADER")")"
        if [ -z "$misplaced" ]; then
            pass "every member the last commit declared is where it was, and every new one is past the old length"
        elif [ -n "$was_major" ] && [ "$is_major" -gt "$was_major" ]; then
            pass "members moved, and the ABI major with them ($was_major to $is_major)"
        else
            fail "a member moved, went away, or was put inside a length callers already declare, within ABI major $is_major:"
            printf '%s\n' "$misplaced" | sed 's/^/        /'
        fi
    else
        pass "no bindings/c/abi-layout.c in the last commit to hold the offsets to"
    fi
}

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
step_fuzz_targets() {
    step "the fuzz targets"
    NIGHTLY=$(awk -F'"' '/^channel = /{print $2; exit}' fuzz/rust-toolchain.toml 2>/dev/null)
    if [ -z "$NIGHTLY" ]; then
        fail "fuzz/rust-toolchain.toml names no toolchain, so nothing says what to build with"
    elif ! rustup toolchain list 2>/dev/null | found "^$NIGHTLY"; then
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
}

# A generated file nobody compiles is a file that is wrong the day it changes.
# Until the generator grew a name pass, the C# binding had two entry points
# with duplicated P/Invoke parameter names and the JNI shim had five; a
# compiler would have said so on the day they were printed, and no compiler had
# ever been pointed at them. Build outputs land in bin/, obj/ and .build/,
# which .gitignore already covers.
step_dotnet_compiles() {
    step "the bindings compile: dotnet"
    if command -v dotnet >/dev/null 2>&1; then
        (cd "$ROOT/bindings/dotnet/Sipral" && dotnet build -c Release --nologo) >/dev/null 2>&1 \
            && pass "dotnet build" || fail "dotnet build -c Release, in bindings/dotnet/Sipral"
        # The lab's own headless agent (scripts/lab.sh's csharp_agent) -- net8.0,
        # not net8.0-windows, so it builds here same as the layer it sits on.
        # bindings/dotnet/samples/Sipral.Sample.Wpf is deliberately not built on
        # this machine: it targets net8.0-windows, which only Windows carries,
        # and the layer it is a thin skeleton over is exactly what the dotnet
        # build above and the "the dotnet bindings" step below already cover.
        (cd "$ROOT/bindings/dotnet/samples/Sipral.Sample.Agent" && dotnet build -c Release --nologo) >/dev/null 2>&1 \
            && pass "dotnet build, the sample agent" \
            || fail "dotnet build -c Release, in bindings/dotnet/samples/Sipral.Sample.Agent"
    else
        skip "dotnet build: no .NET SDK (https://dot.net/v1/dotnet-install.sh --channel 8.0)"
    fi
}

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

# bindings/jvm's tests are JUnit tests, run here without Maven by the JUnit
# console launcher (EPL-2.0, test-only, never shipped), cached the same way.
JUNIT_VERSION="6.1.3"
JUNIT_SHA256="e62b96ac475dbcde8599ea905d088f65d90778f86e259b856a49fa5c4ea256ec"
JUNIT_JAR="$HOME/.cache/sipral/maven/org/junit/platform/junit-platform-console-standalone/$JUNIT_VERSION/junit-platform-console-standalone-$JUNIT_VERSION.jar"
junit_ok=0
if [ -s "$JUNIT_JAR" ] \
    && [ "$(shasum -a 256 "$JUNIT_JAR" 2>/dev/null | cut -d' ' -f1)" = "$JUNIT_SHA256" ]; then
    junit_ok=1
fi

# The JNI shim needs jni.h, and `java_home` answers with a JRE on a machine
# that has one installed beside no JDK -- the applet plugin is one. So the
# header is what is looked for, not the command.
jdk="${JAVA_HOME:-$(/usr/libexec/java_home 2>/dev/null || true)}"

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
kotlin_lib_dir() {
    local home
    home="$(cd "$(dirname "$(readlink -f "$(command -v kotlinc)")")/.." 2>/dev/null && pwd)"
    if [ ! -s "$home/lib/kotlin-stdlib.jar" ] && [ -s "$home/libexec/lib/kotlin-stdlib.jar" ]; then
        printf '%s\n' "$home/libexec/lib"
    else
        printf '%s\n' "$home/lib"
    fi
}

# The Kotlin layer's classes, compiled into $1/classes: what the kotlin area
# runs on a JVM and what bindings/jvm compiles over. The first line it prints
# is what a failure is reported as; it returns 2 for a compiler that is not
# on this machine.
compile_kotlin() {
    local out="$1" one lib
    local kotlin_sources=()
    if [ "$coroutines_ok" -ne 1 ]; then
        printf 'kotlinx-coroutines-core-jvm %s is not cached with the right checksum at %s (fetch it once from Maven Central and verify its sha256 matches %s)\n' \
            "$COROUTINES_VERSION" "$COROUTINES_JAR" "$COROUTINES_SHA256"
        return 1
    fi
    if ! command -v kotlinc >/dev/null 2>&1; then
        printf 'kotlinc: no Kotlin compiler (brew install kotlin)\n'
        return 2
    fi
    # The sources are found rather than listed: a new file nobody added here
    # would otherwise go uncompiled, which is the failure this step exists
    # for. Collected NUL-separated into an array, because a checkout whose
    # path has a space in it -- and this one has -- splits an unquoted list
    # into halves that are not filenames, and the compiler then reports that
    # it found no source while looking at two.
    #
    # bindings/kotlin/android is the one part left out: it is Android code
    # (android.telecom, Compose) that compiles only against the Android SDK,
    # which this machine does not carry. It is built, with the Android SDK,
    # by scripts/package/android.sh; its logic is not in there but in
    # org.sipral.telecom, which is compiled and run here.
    #
    # The React Native package's Android logic goes in with it the same way:
    # org.sipral.reactnative.core has nothing of React Native in it, and its
    # check runs in the kotlin area beside the Kotlin layer's. The
    # TurboModule around it is built by Gradle in the rn area.
    while IFS= read -r -d '' one; do
        kotlin_sources+=("$one")
    done < <(find "$ROOT/bindings/kotlin" -path "$ROOT/bindings/kotlin/android" -prune \
            -o -name '*.kt' -print0 2>/dev/null
        find "$ROOT/bindings/react-native/android/src/main/java/org/sipral/reactnative/core" \
            "$ROOT/bindings/react-native/android/jvm-check" -name '*.kt' -print0 2>/dev/null)
    lib=$(kotlin_lib_dir)
    if [ "${#kotlin_sources[@]}" -eq 0 ]; then
        printf 'no Kotlin source found under bindings/kotlin, so nothing was compiled\n'
        return 1
    elif [ ! -s "$lib/kotlin-test.jar" ] || [ ! -s "$lib/kotlin-stdlib.jar" ]; then
        printf 'kotlinc runs from a distribution with no kotlin-test.jar and kotlin-stdlib.jar in %s\n' "$lib"
        return 1
    fi
    mkdir -p "$out/classes"
    if ! kotlinc -cp "$lib/kotlin-test.jar:$COROUTINES_JAR" "${kotlin_sources[@]}" \
        -d "$out/classes" >"$out/kotlinc.log" 2>&1; then
        printf 'kotlinc, over bindings/kotlin\n'
        return 1
    fi
}

# Sets kotlin_classes and kotlin_lib, or says why it could not: a compiler
# that is not here is a skip, anything else a failure.
kotlin_classes=""
kotlin_lib=""
need_kotlin_classes() {
    prep kotlin compile_kotlin
    case $? in
        0) kotlin_classes="$PREP/kotlin/classes"; kotlin_lib=$(kotlin_lib_dir); return 0 ;;
        2) skip "$(head -1 "$PREP/kotlin.log")" ;;
        *) prep_failed kotlin ;;
    esac
    return 1
}

# Compiling the shim says it is C, not that it works. So it is linked
# against the shared library, beside a helper that polls from a thread no
# JVM made, into $1, which is the java.library.path every JVM run below
# takes.
#
# idiomatic_media.c is hand-written, not generated, and links into
# the same "sipral_jni" library the generated shim does: the two
# structs it builds (sipral_media_packet_t, sipral_transmit_t) are
# what SipralAbi.kt itself cannot construct (bindings/kotlin/README.md),
# so org.sipral.idiomatic's own native calls have to resolve out of
# the library the generated one already loads.
link_jni() {
    local out="$1" pair name sources src linked=0
    local abs_sources=()
    for pair in "sipral_jni:bindings/kotlin/sipral/src/main/jni/sipral_jni.c bindings/kotlin/sipral/src/main/jni/idiomatic_media.c bindings/kotlin/sipral/src/main/jni/audio_routes.c" \
        "sipral_jni_check:bindings/kotlin/sipral/src/test/jni/native_thread.c"; do
        name="${pair%%:*}"
        sources="${pair#*:}"
        abs_sources=()
        for src in $sources; do abs_sources+=("$ROOT/$src"); done
        if ! cc -std=c11 -Wall -Wextra -Werror -dynamiclib \
            -I"$jdk/include" -I"$jdk/include/darwin" -I"$ROOT/bindings/c/include" \
            -o "$out/lib${name}.dylib" "${abs_sources[@]}" \
            -L"$ROOT/target/release" -lsipral_ffi -Wl,-rpath,"$ROOT/target/release" \
            >"$out/cc" 2>&1; then
            printf '%s does not build against the shared library:\n' "$sources"
            sed 's/^/        /' "$out/cc"
            linked=1
        fi
    done
    return "$linked"
}
need_jni() {
    prep jni link_jni && return 0
    prep_failed jni
    return 1
}

step_kotlin_compiles() {
    step "the bindings compile: kotlin"
    need_kotlin_classes && pass "kotlinc"
}

step_kotlin_on_a_jvm() {
    step "the kotlin layer on a JVM"
    if [ -n "$jdk" ] && [ -f "$jdk/include/jni.h" ]; then
        for shim in sipral_jni idiomatic_media audio_routes; do
            cc -fsyntax-only -Wall -Wextra -Werror \
                -I"$jdk/include" -I"$jdk/include/darwin" -I"$ROOT/bindings/c/include" \
                "$ROOT/bindings/kotlin/sipral/src/main/jni/$shim.c" >/dev/null 2>&1 \
                && pass "cc -fsyntax-only, $shim.c" \
                || fail "cc -fsyntax-only, bindings/kotlin/sipral/src/main/jni/$shim.c"
        done

        # BindingCheck.kt / IdiomaticCheck.kt run against the shim on a JVM
        # under -Xcheck:jni. What each run printed is looked for as well as
        # how it exited, because a JVM that ran nothing also exits zero.
        if [ -z "$kotlin_classes" ]; then
            skip "the JVM run: kotlinc compiled nothing to run, which the lines above say why"
        elif [ ! -s "$DYLIB" ]; then
            fail "the JVM run: $DYLIB is not there to link the shim against"
        elif [ ! -x "$jdk/bin/java" ]; then
            fail "the JVM run: $jdk carries include/jni.h and no bin/java"
        elif need_jni; then
            work="$PREP/jni"
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

            # org.sipral.telecom, the Android ConnectionService helper's
            # logic, against fakes of the telecom framework and then over
            # two real stacks on loopback.
            ran=$("$jdk/bin/java" -Xcheck:jni -Djava.library.path="$work" \
                -cp "$kotlin_classes:$kotlin_lib/kotlin-stdlib.jar:$kotlin_lib/kotlin-test.jar:$COROUTINES_JAR" \
                org.sipral.telecom.TelecomCheckKt 2>&1)
            exited=$?
            said=$(printf '%s\n' "$ran" | grep '^kotlin telecom: ' || true)
            warned=$(printf '%s\n' "$ran" \
                | grep -E 'WARNING in native method|WARNING: JNI|FATAL ERROR in native method' || true)
            if [ "$exited" -ne 0 ]; then
                fail "TelecomCheck.kt did not come back zero:"
                printf '%s\n' "$ran" | sed 's/^/        /'
            elif [ -z "$said" ]; then
                fail "TelecomCheck.kt came back zero and said nothing, so nothing was checked"
            elif [ -n "$warned" ]; then
                fail "-Xcheck:jni found something wrong under the telecom helper:"
                printf '%s\n' "$warned" | sed 's/^/        /'
            else
                pass "${said#kotlin telecom: }"
            fi

            # The React Native package's Android half without React Native:
            # SipralReactCore over three real stacks, driven the way the
            # TurboModule drives it.
            ran=$("$jdk/bin/java" -Xcheck:jni -Djava.library.path="$work" \
                -cp "$kotlin_classes:$kotlin_lib/kotlin-stdlib.jar:$kotlin_lib/kotlin-test.jar:$COROUTINES_JAR" \
                org.sipral.reactnative.core.SipralReactCoreCheckKt 2>&1)
            exited=$?
            said=$(printf '%s\n' "$ran" | grep '^react native core: ' || true)
            warned=$(printf '%s\n' "$ran" \
                | grep -E 'WARNING in native method|WARNING: JNI|FATAL ERROR in native method' || true)
            if [ "$exited" -ne 0 ]; then
                fail "SipralReactCoreCheck.kt did not come back zero:"
                printf '%s\n' "$ran" | sed 's/^/        /'
            elif [ -z "$said" ]; then
                fail "SipralReactCoreCheck.kt came back zero and said nothing, so nothing was checked"
            elif [ -n "$warned" ]; then
                fail "-Xcheck:jni found something wrong under the React Native package's Android half:"
                printf '%s\n' "$warned" | sed 's/^/        /'
            else
                pass "the React Native Android half: ${said#react native core: }"
            fi
        fi
    else
        skip "the JNI shim: no JDK carrying include/jni.h (JAVA_HOME must name a JDK, not a JRE)"
    fi
}

# bindings/jvm, the server jar's own code, without Maven: its loader and
# SipralJava compiled over the Kotlin layer's classes, and its tests run by
# the JUnit console launcher (cached, checksummed, like the coroutines jar).
# What a Mac can run of them runs: the loader's choice of platform and its
# ELF reading, and the Java caller's loopback call, account on a TCP
# connection of its own, realms and raised ceilings through SipralJava, the
# application's frame rate, the echo cancellation switch and the ABI check's
# 1.x rule, with the shim found on
# java.library.path as in the kotlin area. The two tests that need Linux --
# the running JVM loading its own pair out of the jar, and the Kotlin
# loopback call that asserts it runs from the packaged jar -- run in
# scripts/package/jvm.sh, on a Linux host.
step_jvm() {
    step "bindings/jvm"
    if [ -z "$jdk" ] || [ ! -f "$jdk/include/jni.h" ]; then
        skip "bindings/jvm: no JDK carrying include/jni.h (JAVA_HOME must name a JDK, not a JRE)"
        return
    fi
    need_kotlin_classes || return
    if [ ! -s "$DYLIB" ]; then
        fail "the JVM run: $DYLIB is not there to link the shim against"
        return
    elif [ ! -x "$jdk/bin/java" ]; then
        fail "the JVM run: $jdk carries include/jni.h and no bin/java"
        return
    fi
    need_jni || return
    work="$PREP/jni"
    if [ "$junit_ok" -ne 1 ]; then
        fail "junit-platform-console-standalone $JUNIT_VERSION is not cached with the right checksum at $JUNIT_JAR (fetch it once from Maven Central and verify its sha256 matches $JUNIT_SHA256)"
    else
        jvm_classes=$(mktemp -d)
        jvm_sources=()
        while IFS= read -r -d '' one; do
            jvm_sources+=("$one")
        done < <(find "$ROOT/bindings/jvm/src/main/kotlin" "$ROOT/bindings/jvm/src/test/kotlin" \
            -name '*.kt' -print0 2>/dev/null)
        java_sources=()
        while IFS= read -r -d '' one; do
            java_sources+=("$one")
        done < <(find "$ROOT/bindings/jvm/src/test/java" -name '*.java' -print0 2>/dev/null)
        if [ "${#jvm_sources[@]}" -eq 0 ] || [ "${#java_sources[@]}" -eq 0 ]; then
            fail "no Kotlin or no Java source found under bindings/jvm/src, so nothing was compiled"
        elif ! kotlinc -cp "$kotlin_classes:$COROUTINES_JAR:$JUNIT_JAR" "${jvm_sources[@]}" \
            -d "$jvm_classes" >"$AREA_WORK/jvm-kotlinc" 2>&1; then
            fail "kotlinc, over bindings/jvm:"
            sed 's/^/        /' "$AREA_WORK/jvm-kotlinc"
        elif ! "$jdk/bin/javac" -d "$jvm_classes" \
            -cp "$jvm_classes:$kotlin_classes:$kotlin_lib/kotlin-stdlib.jar:$COROUTINES_JAR:$JUNIT_JAR" \
            "${java_sources[@]}" >"$AREA_WORK/jvm-javac" 2>&1; then
            fail "javac, over bindings/jvm/src/test/java:"
            sed 's/^/        /' "$AREA_WORK/jvm-javac"
        else
            selected=(--select-class org.sipral.jvm.LoopbackCallJavaIT)
            for method in linuxOnX64SpellingsChooseLinuxX64 linuxOnArm64SpellingsChooseLinuxArm64 \
                anythingElseChoosesNothing eachPlatformReadsItsOwnDirectory \
                theElfMachineIsReadFromTheHeader eachStagedPairIsForItsOwnMachine; do
                selected+=(--select-method "org.sipral.jvm.SipralNativesTest#$method")
            done
            ran=$("$jdk/bin/java" -Xcheck:jni --enable-native-access=ALL-UNNAMED \
                -Djava.library.path="$work" -Dsipral.expected.platforms= \
                -jar "$JUNIT_JAR" execute --disable-banner --disable-ansi-colors \
                --details=summary --fail-if-no-tests \
                --class-path "$jvm_classes:$kotlin_classes:$kotlin_lib/kotlin-stdlib.jar:$COROUTINES_JAR" \
                "${selected[@]}" 2>&1)
            exited=$?
            succeeded=$(printf '%s\n' "$ran" | sed -n 's/.*\[ *\([0-9]*\) tests successful *\].*/\1/p' | tail -1)
            # eachStagedPairIsForItsOwnMachine has no natives to read
            # here -- they are staged by a Linux build -- and says so
            # as a skip rather than passing with nothing checked
            skipped=$(printf '%s\n' "$ran" | sed -n 's/.*\[ *\([0-9]*\) tests aborted *\].*/\1/p' | tail -1)
            warned=$(printf '%s\n' "$ran" \
                | grep -E 'WARNING in native method|WARNING: JNI|FATAL ERROR in native method' || true)
            if [ "$exited" -ne 0 ] || [ "${succeeded:-0}" -ne 12 ] || [ "${skipped:-0}" -ne 1 ]; then
                fail "bindings/jvm's tests, the loader's five and the Java caller's seven (${succeeded:-0} of 12 passed, ${skipped:-0} of 1 skipped by its assumption):"
                printf '%s\n' "$ran" | grep -vE '^[[:space:]]+at ' | tail -40 | sed 's/^/        /'
            elif [ -n "$warned" ]; then
                fail "-Xcheck:jni found something wrong under SipralJava:"
                printf '%s\n' "$warned" | sed 's/^/        /'
            else
                pass "bindings/jvm: the loader's platform and ELF checks, a Java loopback call, an account on a TCP connection of its own, its realms, the raised ceilings, the application's frame rate, the echo cancellation switch and the ABI check's 1.x rule through the Java layer (12 tests; the staged pairs' check skipped, as no natives are staged off Linux)"
            fi
        fi
        rm -rf "$jvm_classes"
    fi
}

# SwiftPM reads Package.swift by compiling it against the PackageDescription
# module, which a full Xcode ships and the Command Line Tools alone do not --
# so the manifest is tried first and its failure is told apart from the
# package's.
step_swift() {
    step "the swift package"
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
            fail "swift test: $DYLIB is not there to link against (the build of the library, above, says why)"
        fi
    else
        skip "swift build: SwiftPM cannot read the manifest here (the Command Line Tools ship no PackageDescription module; a full Xcode does)"
        skip "swift test: same reason"
    fi
}

# The idiomatic .NET layer (bindings/dotnet/Sipral, everything beside the
# generated SipralAbi.cs) against the real ABI: two stacks on loopback,
# proved the way bindings/python/tests already proves its own layer --
# register or dial directly, answer, hold/resume, DTMF, hang up, events
# observed, handles released -- plus the threading rules the ABI documents,
# not just the happy path: events land on the poll thread and not the
# caller's, SIPRAL_STATUS_BUSY surfaces rather than blocking, and disposing
# a stack with events still queued behind it does not touch a freed handle.
# `DOTNET_ROLL_FORWARD=LatestMajor` covers a machine, like this one, whose
# SDK is newer than the net8.0 runtime it shipped beside; a machine that
# actually has the net8.0 runtime installed sees no difference.
step_dotnet_tests() {
    step "the dotnet bindings"
    if ! command -v dotnet >/dev/null 2>&1; then
        skip "dotnet test: no .NET SDK (https://dot.net/v1/dotnet-install.sh --channel 8.0)"
    elif [ ! -s "$DYLIB" ]; then
        fail "the dotnet bindings: $DYLIB is not there to load (the build of the library, above, says why)"
    else
        work=$(mktemp -d)
        if DOTNET_ROLL_FORWARD=LatestMajor dotnet test "$ROOT/bindings/dotnet/Sipral.Tests" \
            -c Release --nologo -v minimal >"$work/out" 2>&1; then
            pass "dotnet test, bindings/dotnet/Sipral.Tests"
        else
            fail "dotnet test, bindings/dotnet/Sipral.Tests:"
            sed 's/^/        /' "$work/out"
        fi
        rm -rf "$work"
    fi
}

# Unlike dotnet/kotlinc/swift above, python3 and cffi are not optional
# toolchains this step may find missing: bindings/python/sipral/_sipral_cffi.py
# is one of the five files "the header and the bindings" step already
# regenerated and compared, so a machine that cannot import it has not
# actually checked that step's own output. No C compiler is needed -- cffi's
# ABI mode reads the cdef and dlopen's $DYLIB directly -- so the only two
# things this can be missing on a machine that built the rest of this gate
# are python3 itself and the cffi package.
step_python() {
    step "the python bindings"
    if ! command -v python3 >/dev/null 2>&1; then
        fail "python3 is not installed"
    elif ! python3 -c 'import cffi' >/dev/null 2>&1; then
        fail "python3 has no cffi (pip install cffi)"
    elif [ ! -s "$DYLIB" ]; then
        fail "the python bindings: $DYLIB is not there to load (the build of the library, above, says why)"
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
}

# integrations/pipecat over bindings/python and $DYLIB: a Pipecat pipeline
# on a call between two stacks on loopback. pipecat-ai and what it brings are
# the integration's and not the binding's, so they go into a virtual
# environment under target/check made from the python3 the python area runs,
# whose cffi it still sees, and never into that python3 itself. The version
# installed is the lowest the integration accepts; the first run fetches it
# from PyPI and later runs reuse it.
step_pipecat() {
    step "the pipecat integration"
    local venv="$CHECK_DIR/venv-pipecat" pipecat work
    pipecat=$(sed -n 's/.*"pipecat-ai>=\([0-9.]*\)".*/\1/p' "$ROOT/integrations/pipecat/pyproject.toml")
    if ! command -v python3 >/dev/null 2>&1; then
        fail "python3 is not installed"
    elif ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
        fail "python3 is $(python3 -c 'import platform; print(platform.python_version())'), and pipecat-ai needs 3.11 or later"
    elif ! python3 -c 'import cffi' >/dev/null 2>&1; then
        fail "python3 has no cffi (pip install cffi)"
    elif [ -z "$pipecat" ]; then
        fail "integrations/pipecat/pyproject.toml names no pipecat-ai>= version"
    elif [ ! -s "$DYLIB" ]; then
        fail "the pipecat integration: $DYLIB is not there to load (the build of the library, above, says why)"
    else
        work=$(mktemp -d)
        if [ ! -x "$venv/bin/python" ] && ! python3 -m venv --system-site-packages "$venv" >"$work/venv" 2>&1; then
            fail "python3 -m venv $venv:"
            sed 's/^/        /' "$work/venv"
        elif ! "$venv/bin/python" -m pip show pipecat-ai 2>/dev/null | found -x "Version: $pipecat" \
            && ! "$venv/bin/python" -m pip install -q "pipecat-ai==$pipecat" >"$work/pip" 2>&1; then
            fail "pip install pipecat-ai==$pipecat, into $venv:"
            tail -20 "$work/pip" | sed 's/^/        /'
        elif SIPRAL_LIBRARY="$ROOT/$DYLIB" PYTHONPATH="$ROOT/integrations/pipecat:$ROOT/bindings/python" \
            "$venv/bin/python" -m unittest discover -s "$ROOT/integrations/pipecat/tests" \
            -t "$ROOT/integrations/pipecat" >"$work/out" 2>&1; then
            pass "python3 -m unittest discover, integrations/pipecat/tests (pipecat-ai $pipecat)"
        else
            fail "python3 -m unittest discover, integrations/pipecat/tests (pipecat-ai $pipecat):"
            sed 's/^/        /' "$work/out"
        fi
        rm -rf "$work"
    fi
}

# integrations/agents over bindings/python and $DYLIB: calls between two
# stacks on loopback, each joined to a local WebSocket server that speaks one
# service's protocol as its public documentation describes it. No network
# beyond loopback and no key. websockets is the package's and not the
# binding's, so it goes into a virtual environment under target/check, at
# the lowest version the package accepts, as for the Pipecat integration.
step_agents() {
    step "the voice-agent connectors"
    local venv="$CHECK_DIR/venv-agents" websockets work
    websockets=$(sed -n 's/.*"websockets>=\([0-9.]*\)".*/\1/p' "$ROOT/integrations/agents/pyproject.toml")
    if ! command -v python3 >/dev/null 2>&1; then
        fail "python3 is not installed"
    elif ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
        fail "python3 is $(python3 -c 'import platform; print(platform.python_version())'), and sipral-agents needs 3.11 or later"
    elif ! python3 -c 'import cffi' >/dev/null 2>&1; then
        fail "python3 has no cffi (pip install cffi)"
    elif [ -z "$websockets" ]; then
        fail "integrations/agents/pyproject.toml names no websockets>= version"
    elif [ ! -s "$DYLIB" ]; then
        fail "the voice-agent connectors: $DYLIB is not there to load (the build of the library, above, says why)"
    else
        work=$(mktemp -d)
        if [ ! -x "$venv/bin/python" ] && ! python3 -m venv --system-site-packages "$venv" >"$work/venv" 2>&1; then
            fail "python3 -m venv $venv:"
            sed 's/^/        /' "$work/venv"
        elif ! "$venv/bin/python" -m pip show websockets 2>/dev/null | found -x "Version: $websockets" \
            && ! "$venv/bin/python" -m pip install -q "websockets==$websockets" >"$work/pip" 2>&1; then
            fail "pip install websockets==$websockets, into $venv:"
            tail -20 "$work/pip" | sed 's/^/        /'
        elif SIPRAL_LIBRARY="$ROOT/$DYLIB" PYTHONPATH="$ROOT/integrations/agents:$ROOT/bindings/python" \
            "$venv/bin/python" -m unittest discover -s "$ROOT/integrations/agents/tests" \
            -t "$ROOT/integrations/agents" >"$work/out" 2>&1; then
            pass "python3 -m unittest discover, integrations/agents/tests (websockets $websockets)"
        else
            fail "python3 -m unittest discover, integrations/agents/tests (websockets $websockets):"
            sed 's/^/        /' "$work/out"
        fi
        rm -rf "$work"
    fi
}

# Like the Python one, bindings/dart/lib/src/sipral_abi.dart is printed by
# "the header and the bindings", so a machine without dart has not
# checked that step's own output: a missing SDK fails. `dart analyze` is the
# compiler's front end over the printed file and the layer over it;
# test/abi_test.dart holds every record's dart:ffi layout to the length
# the library reports, and test/loopback_test.dart places a call between
# two stacks against $DYLIB. The package's dependencies come from the pub
# cache when they are there, and from pub.dev the first time.
step_dart() {
    step "the dart bindings"
    if ! command -v dart >/dev/null 2>&1; then
        fail "dart is not installed (brew install --cask flutter, which carries it)"
    elif [ ! -s "$DYLIB" ]; then
        fail "the dart bindings: $DYLIB is not there to load (the build of the library, above, says why)"
    else
        work=$(mktemp -d)
        if ! (cd "$ROOT/bindings/dart" && { dart pub get --offline || dart pub get; }) >"$work/pub" 2>&1; then
            fail "dart pub get, in bindings/dart:"
            sed 's/^/        /' "$work/pub"
        else
            (cd "$ROOT/bindings/dart" && dart analyze --fatal-infos) >"$work/analyze" 2>&1 \
                && pass "dart analyze, bindings/dart" \
                || { fail "dart analyze --fatal-infos, in bindings/dart:"; sed 's/^/        /' "$work/analyze"; }
            # the printed binding is abi-gen's layout, not dart format's
            handwritten=()
            while IFS= read -r one; do
                handwritten+=("$one")
            done < <(cd "$ROOT/bindings/dart" && find lib test -name '*.dart' ! -path lib/src/sipral_abi.dart | sort)
            (cd "$ROOT/bindings/dart" && dart format --output=none --set-exit-if-changed "${handwritten[@]}") \
                >"$work/format" 2>&1 \
                && pass "dart format, the hand-written layer" \
                || { fail "dart format, in bindings/dart:"; grep '^Changed' "$work/format" | sed 's/^/        /'; }
            if (cd "$ROOT/bindings/dart" && SIPRAL_LIBRARY="$ROOT/$DYLIB" dart test --reporter expanded) \
                >"$work/test" 2>&1; then
                passed=$(grep -oE '\+[0-9]+: All tests passed' "$work/test" | grep -oE '[0-9]+' | tail -1)
                # a run that exited zero without its own closing line has not
                # said what it ran, and is not taken for one that passed
                if [ -n "$passed" ] && [ "$passed" -gt 0 ]; then
                    pass "dart test, bindings/dart ($passed tests: record layouts, the ABI version, the loopback call)"
                else
                    fail "dart test, bindings/dart, exited zero without \"All tests passed\":"
                    tail -20 "$work/test" | sed 's/^/        /'
                fi
            else
                fail "dart test, bindings/dart:"
                tail -40 "$work/test" | sed 's/^/        /'
            fi
        fi
        rm -rf "$work"
    fi
}

# The documentation site (site/book.toml) built from docs/, with its links,
# hosts and addresses checked by scripts/site.sh, which fails on any of the
# three; nothing is published.
step_site() {
    step "the documentation site"
    if ! command -v mdbook >/dev/null 2>&1; then
        fail "mdbook is not installed: cargo install mdbook --locked"
    else
        work=$(mktemp -d)
        if scripts/site.sh >"$work/site" 2>&1; then
            pass "$(grep '^site: ' "$work/site" | sed 's/^site: //'), no broken link, foreign host or address"
        else
            fail "scripts/site.sh:"
            tail -40 "$work/site" | sed 's/^/        /'
        fi
        rm -rf "$work"
    fi
}

# package --dry-run. The scripts under scripts/package/ each need at least
# one machine this gate does not have: win-x64, win-arm64 and linux-x64
# natives, and the Android .so's, come from another machine's toolchain, not
# from a Mac. What these steps prove is everything short of that: the
# scripts run to completion, the parts buildable on a Mac are built for real
# (macOS and iOS via xcodebuild and cargo, the Python and .NET packages
# carrying real macOS natives, the Kotlin classes compiled by kotlinc), and
# every RID or ABI this machine cannot reach gets its layout checked and is
# reported as exactly that -- never silently skipped, and never a fabricated
# native standing in for one nothing here built. Each script runs in the
# area of the layer it packages, with its output under that area's own
# work directory.
pkg_run() {
    local label="$1"; shift
    if "$@" >"$PKG_WORK/log-$label" 2>&1; then
        pass "$label"
    else
        fail "$label:"
        tail -40 "$PKG_WORK/log-$label" | sed 's/^/        /'
    fi
}

# xcframework.sh, wheels.sh and nuget.sh build their Apple natives into one
# target directory (scripts/package/apple.sh), and each copies what it built
# out of it afterwards. Cargo's own lock covers the build and not the copy,
# so with the areas in parallel one script's variant with libopus could be
# what another copies. They take turns.
APPLE_PACKAGING=apple-packaging

step_xcframework() {
    step "package --dry-run: the XCFramework"
    gate_lock "$APPLE_PACKAGING" pkg_run "xcframework.sh --dry-run" \
        scripts/package/xcframework.sh --out "$PKG_WORK/xcframework" --dry-run

    # What the scripts build by default is the artefact without libopus
    # (docs/05-media.md): read out of the macOS archive the XCFramework above
    # carries, the same way as the C ABI's own no-default-features build
    # -- libopus's `_opus_` C symbols, with nm-classic and without `-g`. The
    # archive is static, so the release profile's `strip` has not emptied it the
    # way it empties a linked library, and its `_sipral_` entry points are
    # counted so that an nm that read nothing is not taken for a clean archive.
    PKG_ARCHIVE=$(find "$PKG_WORK/xcframework/CSipral.xcframework" -path '*macos*' -name 'libsipral_ffi.a' 2>/dev/null | head -1)
    if [ -z "$PKG_ARCHIVE" ]; then
        fail "no macOS libsipral_ffi.a in the packaged XCFramework, so nothing was read for libopus"
    else
        symbols=$(xcrun nm-classic -U -arch arm64 "$PKG_ARCHIVE" 2>/dev/null | awk '{print $NF}')
        entry_points=$(printf '%s\n' "$symbols" | grep -c '^_sipral_' || true)
        linked=$(printf '%s\n' "$symbols" | grep '^_opus_' || true)
        if [ "$entry_points" -eq 0 ]; then
            fail "nm read no _sipral_ entry point out of the packaged macOS archive, so nothing was checked"
        elif [ -n "$linked" ]; then
            fail "the packaged XCFramework links opus symbols, and the default package is meant to be without libopus:"
            printf '%s\n' "$linked" | head -5 | sed 's/^/        /'
        else
            pass "no opus symbol in the packaged XCFramework's macOS archive (nm, default package)"
        fi
    fi
}

step_wheels() {
    step "package --dry-run: the wheels"
    gate_lock "$APPLE_PACKAGING" pkg_run "wheels.sh --dry-run" \
        scripts/package/wheels.sh --out "$PKG_WORK/wheels" --dry-run

    # The --with-opus variant, once, is where the SBOM each packaging script now
    # writes beside its artefact (docs/10-roadmap.md) is checked for real: that
    # variant's own sbom-gen invocation carries --notices THIRD-PARTY-LICENSES.txt,
    # so a wheels.sh that runs to completion here already proves the SBOM's
    # crates.io components are exactly what that file lists -- wheels.sh chosen
    # because it is the cheapest of the four to build twice. The other three
    # scripts' own --notices wiring is the same shape (each script's own SBOM
    # step) and is not re-proven artefact by artefact.
    gate_lock "$APPLE_PACKAGING" pkg_run "wheels.sh --dry-run --with-opus" \
        scripts/package/wheels.sh --out "$PKG_WORK/wheels-opus" --dry-run --with-opus
}

# linux-arm64 cross-compiles in an unprivileged Docker container
# (scripts/package/aarch64-cross.sh), no arm64 hardware needed. A host with
# Docker runs both scripts' linux-arm64 path for real; a host without it --
# this Mac -- proves what it can without one, and never skips: sipral-ffi
# type-checked and linted for aarch64-unknown-linux-gnu with the features
# the default package builds (the variant with libopus needs a C cross
# compiler for its vendored build, which is the container's), and every file
# the cross path names present and parseable. The container build, its
# glibc check and the qemu run are the Docker host's step, and
# docs/11-testing.md names it.
step_linux_arm64() {
    step "package --dry-run: linux-arm64"
    if command -v docker >/dev/null 2>&1; then
        pkg_run "wheels.sh --linux-arm64 --dry-run" \
            scripts/package/wheels.sh --out "$PKG_WORK/wheels-arm64" --linux-arm64 --dry-run
        pkg_run "nuget.sh collect (linux-arm64)" \
            scripts/package/nuget.sh collect --out "$PKG_WORK/nuget-natives" --rid linux-arm64
    elif ! rustup target list --installed 2>/dev/null | found -x aarch64-unknown-linux-gnu; then
        fail "linux-arm64 without Docker: aarch64-unknown-linux-gnu is not installed: rustup target add aarch64-unknown-linux-gnu"
    else
        . "$ROOT/scripts/package/features.sh"
        if ! package_features 0; then
            fail "linux-arm64 without Docker: no default feature list in crates/sipral-ffi/Cargo.toml"
        else
            pkg_run "cargo clippy -p sipral-ffi for linux-arm64 ($FFI_FEATURES)" \
                cargo clippy -p sipral-ffi --target aarch64-unknown-linux-gnu "${FFI_FEATURE_ARGS[@]}" -- -D warnings
        fi
        cross_missing=""
        for f in scripts/package/aarch64-cross.sh scripts/package/qemu-verify.sh \
            scripts/package/docker/aarch64-cross.Dockerfile bindings/c/smoke.c \
            bindings/c/include/sipral.h bindings/python/tests; do
            [ -e "$f" ] || cross_missing="$cross_missing $f"
        done
        for f in scripts/package/aarch64-cross.sh scripts/package/qemu-verify.sh \
            scripts/package/wheels.sh scripts/package/nuget.sh; do
            bash -n "$f" 2>/dev/null || cross_missing="$cross_missing $f(syntax)"
        done
        [ -z "$cross_missing" ] && pass "linux-arm64's cross path: every file it names is there, and its scripts parse" || {
            fail "linux-arm64's cross path is broken:"; printf '        %s\n' $cross_missing
        }
    fi
}

# scripts/package/jvm.sh builds the server jar on a Linux host with Maven,
# which this gate never is; that it parses is what can be proved here.
step_jvm_package() {
    step "package --dry-run: the server jar"
    pkg_run "jvm.sh parses (bash -n)" bash -n scripts/package/jvm.sh
}

step_nuget() {
    step "package --dry-run: the NuGet package"
    gate_lock "$APPLE_PACKAGING" pkg_run "nuget.sh collect (osx-arm64, osx-x64)" \
        scripts/package/nuget.sh collect --out "$PKG_WORK/nuget-natives" --rid osx-arm64 --rid osx-x64
    pkg_run "nuget.sh pack --dry-run" \
        scripts/package/nuget.sh pack --out "$PKG_WORK/nuget" --staging "$PKG_WORK/nuget-natives" --dry-run
}

# The Dart package as pub.dev would take it: a staged copy without the
# publish_to guard, validated by `dart pub publish --dry-run`. Nothing is
# uploaded. Staged outside the checkout, since dart pub applies the ignore
# rules of the git work tree a package sits in, and target/ is ignored.
step_pub() {
    step "package --dry-run: the Dart package"
    local pub_out
    pub_out=$(mktemp -d)
    pkg_run "pub.sh --dry-run" scripts/package/pub.sh --out "$pub_out" --dry-run
    rm -rf "$pub_out"
}

# The React Native tarball as npm would pack it, its listing held to what
# the package has to carry and must not. Nothing is uploaded.
step_npm() {
    step "package --dry-run: the React Native package"
    pkg_run "npm.sh --dry-run" scripts/package/npm.sh --out "$PKG_WORK/npm" --dry-run
}

# sipral.aar, which the rn area's Gradle build takes as well: made once per
# run under $PREP/aar, by whichever of the two asks first.
assemble_aar() {
    scripts/package/aar.sh assemble --out "$1" --natives "$1/no-natives" --dry-run
}
step_aar() {
    step "package --dry-run: the AAR"
    if prep aar assemble_aar; then
        pass "aar.sh assemble --dry-run"
    else
        fail "aar.sh assemble --dry-run:"
        tail -40 "$PREP/aar.log" | sed 's/^/        /'
    fi
}

# bindings/react-native: the TypeScript layer and its spec, the Android
# library, and the iOS module. Its Android half's logic runs on the JVM in
# the kotlin area, beside the Kotlin layer's checks; what is left is
# everything around it. Nothing here downloads: node_modules comes from
# `npm ci`, run once, and Gradle runs --offline over the cache one online
# build filled, so what is missing fails and says how to get it.
step_react_native() {
    step "the react native package"
    RN="$ROOT/bindings/react-native"
    RN_MODULES="$RN/node_modules"
    rn_run() {
        local label="$1"; shift
        if "$@" >"$PKG_WORK/rn-log" 2>&1; then
            pass "$label"
        else
            fail "$label:"
            tail -40 "$PKG_WORK/rn-log" | sed 's/^/        /'
        fi
    }

    # No runtime dependency of its own: React Native and React are the
    # application's, as peers (THIRD-PARTY-NOTICES.md).
    if ! command -v node >/dev/null 2>&1; then
        fail "node is not installed (brew install node)"
    elif [ -n "$(node -e 'const p=require(process.argv[1]); process.stdout.write(Object.keys(p.dependencies||{}).join(" "))' "$RN/package.json")" ]; then
        fail "bindings/react-native/package.json has runtime dependencies; the package takes only peers"
    else
        pass "no runtime dependency in bindings/react-native/package.json"
    fi

    if [ ! -d "$RN_MODULES/react-native" ] || ! npm --prefix "$RN" ls >/dev/null 2>&1; then
        fail "bindings/react-native/node_modules is missing or not what package-lock.json names: npm ci --prefix bindings/react-native"
    else
        # What jest printed is read as well as how it exited: a run that found
        # no test exits zero too.
        if (cd "$RN" && npx --no-install jest --ci) >"$PKG_WORK/rn-jest" 2>&1; then
            ran=$(grep -Eo 'Tests: +[0-9]+ passed, [0-9]+ total' "$PKG_WORK/rn-jest" | head -1 | sed 's/^Tests: *//')
            [ -n "$ran" ] && pass "jest, bindings/react-native: $ran" \
                || fail "jest came back zero and reported no test"
        else
            fail "jest, bindings/react-native:"
            tail -40 "$PKG_WORK/rn-jest" | sed 's/^/        /'
        fi
        rn_run "tsc --noEmit, the spec and the TypeScript layer" "$RN_MODULES/.bin/tsc" -p "$RN" --noEmit

        # Codegen reads the spec the way an application's build will, into the
        # schema both halves are generated from; the module has to come out as
        # "Sipral" with its event emitter.
        if node "$RN_MODULES/@react-native/codegen/lib/cli/combine/combine-js-to-schema-cli.js" \
            "$PKG_WORK/rn-schema.json" "$RN/src/NativeSipral.ts" >"$PKG_WORK/rn-log" 2>&1 \
            && node -e '
                const s = require(process.argv[1]).modules.NativeSipral;
                if (!s || s.moduleName !== "Sipral") process.exit(1);
                if (!s.spec.eventEmitters.some((e) => e.name === "onEvent")) process.exit(2);
                process.stdout.write(String(s.spec.methods.length));' "$PKG_WORK/rn-schema.json" >"$PKG_WORK/rn-methods"; then
            pass "codegen reads src/NativeSipral.ts: module Sipral, $(cat "$PKG_WORK/rn-methods") methods and onEvent"
        else
            fail "codegen could not read src/NativeSipral.ts into a Sipral module with onEvent:"
            tail -20 "$PKG_WORK/rn-log" | sed 's/^/        /'
        fi

        # The Android library, TurboModule and codegen included, against the
        # classes-only sipral.aar aar.sh assemble --dry-run makes. The wrapper's
        # jar is a binary and never committed: it is made here from the Gradle
        # on the machine, and has to name the version and checksum the
        # committed properties pin.
        wrapper="$RN/android/gradle/wrapper/gradle-wrapper.properties"
        android_sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
        if [ ! -f "$RN/android/gradlew" ] || [ ! -f "$RN/android/gradle/wrapper/gradle-wrapper.jar" ]; then
            if command -v gradle >/dev/null 2>&1; then
                gen="$PKG_WORK/rn-wrapper"
                mkdir -p "$gen" && touch "$gen/settings.gradle.kts"
                version=$(sed -n 's|^distributionUrl=.*/gradle-\(.*\)-bin\.zip$|\1|p' "$wrapper")
                sha=$(sed -n 's/^distributionSha256Sum=//p' "$wrapper")
                if gradle -p "$gen" --no-daemon -q wrapper --gradle-version "$version" \
                    --gradle-distribution-sha256-sum "$sha" --no-validate-url >"$PKG_WORK/rn-log" 2>&1 \
                    && [ "$(grep -E '^distribution(Url|Sha256Sum)=' "$gen/gradle/wrapper/gradle-wrapper.properties")" \
                        = "$(grep -E '^distribution(Url|Sha256Sum)=' "$wrapper")" ]; then
                    cp "$gen/gradlew" "$RN/android/gradlew"
                    cp "$gen/gradle/wrapper/gradle-wrapper.jar" "$RN/android/gradle/wrapper/"
                fi
            fi
        fi
        if [ ! -f "$RN/android/gradlew" ]; then
            fail "no Gradle wrapper in bindings/react-native/android, and none could be made: brew install gradle"
        elif [ ! -d "$android_sdk/platforms" ] && [ ! -d "$android_sdk/platform-tools" ]; then
            fail "no Android SDK at $android_sdk (ANDROID_HOME names another)"
        elif ! prep aar assemble_aar || [ ! -f "$PREP/aar/sipral.aar" ]; then
            fail "the React Native Android library: aar.sh assemble --dry-run wrote no sipral.aar to build against:"
            tail -20 "$PREP/aar.log" | sed 's/^/        /'
        else
            version=$(sed -n 's/^  "version": "\(.*\)",$/\1/p' "$RN/package.json")
            repo="$PKG_WORK/rn-maven/org/sipral/sipral/$version"
            mkdir -p "$repo"
            cp "$PREP/aar/sipral.aar" "$repo/sipral-$version.aar"
            printf '<?xml version="1.0" encoding="UTF-8"?>\n<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>org.sipral</groupId><artifactId>sipral</artifactId><version>%s</version><packaging>aar</packaging><dependencies><dependency><groupId>org.jetbrains.kotlinx</groupId><artifactId>kotlinx-coroutines-core</artifactId><version>%s</version><scope>runtime</scope></dependency></dependencies></project>\n' \
                "$version" "$COROUTINES_VERSION" >"$repo/sipral-$version.pom"
            rm -rf "$RN/android/build"
            if ANDROID_HOME="$android_sdk" "$RN/android/gradlew" -p "$RN/android" --offline --no-daemon --console=plain \
                -Psipral.repo="$PKG_WORK/rn-maven" assembleRelease >"$PKG_WORK/rn-gradle" 2>&1; then
                classes=$(unzip -p "$RN/android/build/outputs/aar/sipral-react-native-release.aar" classes.jar 2>/dev/null \
                    >"$PKG_WORK/rn-classes.jar" && unzip -l "$PKG_WORK/rn-classes.jar" 2>/dev/null)
                missing=""
                for class in org/sipral/reactnative/NativeSipralSpec.class org/sipral/reactnative/SipralModule.class \
                    org/sipral/reactnative/SipralPackage.class org/sipral/reactnative/core/SipralReactCore.class; do
                    printf '%s\n' "$classes" | found " $class\$" || missing="$missing $class"
                done
                [ -z "$missing" ] && pass "gradle assembleRelease, bindings/react-native/android: the TurboModule over the codegen spec" || {
                    fail "the React Native Android library was built without:"; printf '        %s\n' $missing
                }
            else
                fail "gradle assembleRelease --offline, bindings/react-native/android (a cache never filled needs one online run of the same command):"
                grep -E '^e: |error:|What went wrong' -A3 "$PKG_WORK/rn-gradle" | head -30 | sed 's/^/        /'
            fi
        fi

        # The iOS half: its Swift over bindings/swift, built and tested on macOS
        # over real stacks; then the Objective-C++ module compiled for iOS
        # against React Native's own headers laid out as CocoaPods lays them out,
        # codegen's output for the spec, and the header the Swift half exports.
        if [ ! -s "$ROOT/$DYLIB" ]; then
            fail "the React Native iOS half: $DYLIB is not there to link its tests against"
        else
            rn_run "swift test, bindings/react-native/ios" \
                xcrun --toolchain default swift test --package-path "$RN/ios"
        fi
        swift_header=$(find "$RN/ios/.build" -path '*SipralReactBridge.build/include/SipralReactBridge-Swift.h' 2>/dev/null | head -1)
        rn_native="$RN_MODULES/react-native"
        inc="$PKG_WORK/rn-include"
        if [ -z "$swift_header" ]; then
            fail "the Swift half exported no Objective-C header, so SipralModule.mm was compiled against nothing"
        elif ! node "$rn_native/scripts/generate-specs-cli.js" --platform ios --schemaPath "$PKG_WORK/rn-schema.json" \
            --outputDir "$PKG_WORK/rn-ios" --libraryName SipralReactNativeSpec >"$PKG_WORK/rn-log" 2>&1; then
            fail "codegen wrote no iOS spec:"; tail -20 "$PKG_WORK/rn-log" | sed 's/^/        /'
        else
            mkdir -p "$inc/React" "$inc/RCTRequired" "$inc/RCTTypeSafety" "$inc/ReactCommon" \
                "$inc/RCTDeprecation" "$inc/SipralReactNativeSpec"
            headers_into() {
                local into="$1"; shift
                find "$@" -maxdepth "${DEPTH:-99}" -name '*.h' -print0 | while IFS= read -r -d '' h; do
                    ln -sf "$h" "$into/$(basename "$h")"
                done
            }
            headers_into "$inc/React" "$rn_native/React"
            headers_into "$inc/RCTRequired" "$rn_native/Libraries/Required"
            headers_into "$inc/RCTTypeSafety" "$rn_native/Libraries/TypeSafety"
            headers_into "$inc/RCTDeprecation" "$rn_native/ReactApple/Libraries/RCTFoundation/RCTDeprecation/Exported"
            DEPTH=1 headers_into "$inc/ReactCommon" "$rn_native/ReactCommon/react/nativemodule/core/platform/ios/ReactCommon" \
                "$rn_native/ReactCommon/react/nativemodule/core/ReactCommon" "$rn_native/ReactCommon/callinvoker/ReactCommon" \
                "$rn_native/ReactCommon/react/bridging"
            cp "$PKG_WORK/rn-ios/SipralReactNativeSpec/SipralReactNativeSpec.h" "$inc/SipralReactNativeSpec/"
            cp "$swift_header" "$inc/sipral_react_native-Swift.h"
            rn_run "clang++ -fsyntax-only for iOS, bindings/react-native/ios/SipralModule.mm" \
                xcrun clang++ -fsyntax-only -Werror -x objective-c++ -std=c++20 -fobjc-arc -fmodules -fcxx-modules \
                -isysroot "$(xcrun --sdk iphoneos --show-sdk-path)" -target arm64-apple-ios16.0 \
                -I "$inc" -I "$rn_native/Libraries/FBLazyVector" -I "$rn_native/ReactCommon" \
                -I "$rn_native/ReactCommon/jsi" -I "$rn_native/ReactCommon/callinvoker" \
                -I "$rn_native/ReactCommon/runtimeexecutor" -I "$rn_native/ReactCommon/reactperflogger" \
                -I "$rn_native/ReactCommon/logger" "$RN/ios/SipralModule.mm"
        fi
    fi
    rn_run "ruby -c, bindings/react-native/sipral-react-native.podspec" ruby -c "$RN/sipral-react-native.podspec"
}

step_dependency_licences() {
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
}

step_secrets() {
    step "secrets"
    if command -v gitleaks >/dev/null 2>&1; then
        gitleaks detect --no-banner --redact >/dev/null 2>&1 \
            && pass "gitleaks" || fail "gitleaks detect"
    else
        # not a skip: a gate that goes green without the scanner has not looked
        fail "gitleaks not installed: brew install gitleaks"
    fi
}

# Known vulnerabilities in every dependency the tree declares: the Cargo
# lockfiles, but also npm, NuGet, Maven and Python, which cargo deny never
# reads. The database moves while the code stands still, so this is a tree
# check that runs on every invocation, the release one included.
step_vulnerabilities() {
    step "known vulnerabilities"
    if command -v osv-scanner >/dev/null 2>&1; then
        local out
        if out="$(osv-scanner scan source -r --config "$ROOT/osv-scanner.toml" "$ROOT" 2>&1)"; then
            pass "osv-scanner"
        else
            printf '%s\n' "$out" | grep -E '^\| https://osv.dev|^Total' | sed 's/^/        /'
            fail "osv-scanner: a dependency has a known vulnerability (osv-scanner.toml sets one aside, with its reason)"
        fi
    else
        fail "osv-scanner not installed: brew install osv-scanner"
    fi
}

# The figures the README, docs/19-numbers.md, docs/23-compared-with-pjsip.md
# and the website publish, measured and held to docs/numbers.toml, which says
# for each one its published value, how far a measurement may pass it and
# where it is published. A change that makes one of them untrue fails here,
# naming the figure, what it now measures, its budget and every place it is
# published, rather than waiting for somebody to measure it again by hand.
#
# Every measurement here is one that does not move with the machine: the
# library as the release build leaves it, the INVITEs as the stack writes
# them for the lab's call (crates/sipral/src/numbers_tests.rs), a call's
# memory and an idle stack's counted by the signalling test's own allocator,
# and a frame of the in-band digit detector as a multiple of a fixed
# arithmetic loop timed beside it on the same thread, in a release build
# (crates/sipral-media/src/inband/tests.rs, published_cost_of_a_frame). Each
# test prints `numbers:` lines, and scripts/numbers.py judges them.
step_published_figures() {
    step "the published figures"
    local measured="$AREA_WORK/measured" verdicts="$AREA_WORK/verdicts"
    local label status verdict text failed=0
    : >"$measured"
    if need_library; then
        if [ -s "$DYLIB" ]; then
            printf 'numbers: library.bytes=%s\n' "$(wc -c <"$DYLIB" | tr -d ' ')" >>"$measured"
        else
            fail "$DYLIB is not there to be measured"
        fi
    fi
    cargo_test "the INVITE sizes, measured" -p sipral --lib numbers_tests -- --nocapture
    cargo_test "a call's memory, counted" -p sipral-ffi --test signalling_load -- --nocapture
    cargo_test "a frame of the digit detector, timed" --release -p sipral-media --lib -- \
        --ignored --exact inband::tests::published_cost_of_a_frame --nocapture
    for label in "the INVITE sizes, measured" "a call's memory, counted" \
        "a frame of the digit detector, timed"; do
        grep 'numbers: ' "$(test_log "$label")" >>"$measured"
    done
    if ! command -v python3 >/dev/null 2>&1; then
        fail "python3 not found, and scripts/numbers.py needs it"
        return
    fi
    python3 scripts/numbers.py docs/numbers.toml "$measured" >"$verdicts" 2>&1
    status=$?
    while IFS=$'\t' read -r verdict text; do
        case "$verdict" in
            ok) pass "$text" ;;
            fail) fail "$text"; failed=1 ;;
            detail) printf '        %s\n' "$text" ;;
            *) fail "scripts/numbers.py: $verdict${text:+ $text}"; failed=1 ;;
        esac
    done <"$verdicts"
    [ "$status" -eq 0 ] || [ "$failed" -eq 1 ] || fail "scripts/numbers.py exited $status and said why nowhere"
}

# The areas. Each is the list of steps the complete gate runs for it, in the
# order it runs them; an area gate runs the same list.
area_hygiene() {
    step_licence_headers
    step_nothing_internal
    step_security_policy
    step_rfc4475_corpus
    step_one_version
    step_no_addresses
    step_language
    step_provenance
    step_no_clock_read
    step_c_asks_for_posix
    step_keys_do_not_derive_debug
    step_nothing_unwinds_into_c
    step_cpu_baseline
    step_one_declaration_of_the_abi
    step_interop_matrix
    step_wire_reader
    step_third_party_licences
    step_secrets
    step_vulnerabilities
}
area_rust() {
    step_build
    if [ -n "$CRATES" ]; then
        note "--crates:$CRATES only; the other targets, sipral-aec-webrtc, the builds without Opus or DTLS, the fuzz targets and cargo deny were not run"
        return
    fi
    step_other_targets
    step_aec_webrtc
    step_without_opus
    step_fuzz_targets
    step_dependency_licences
}
area_abi() {
    step_the_library
    step_linked_from_c
    step_c_against_glibc
    step_header_and_bindings
    step_layout
}
area_numbers() { step_published_figures; }
area_swift() { need_library; step_swift; step_xcframework; }
area_dotnet() { need_library; step_dotnet_compiles; step_dotnet_tests; step_nuget; }
area_kotlin() { need_library; step_kotlin_compiles; step_kotlin_on_a_jvm; step_aar; }
area_jvm() { need_library; step_jvm; step_jvm_package; }
area_python() { need_library; step_python; step_wheels; step_linux_arm64; }
area_pipecat() { need_library; step_pipecat; }
area_agents() { need_library; step_agents; }
area_dart() { need_library; step_dart; step_pub; }
area_rn() { need_library; step_react_native; step_npm; }
area_site() { step_site; }

# --changed: which areas a path reaches. Each line of $ROUTES is
# "area<TAB>path<TAB>why"; a path may reach several areas, and when in doubt
# it reaches more rather than fewer.
#
# A crate below the facade that the C library links reaches rust, where its
# own tests and the facade's run, abi, because that area checks the library
# and runs it from C, and every layer: what such a crate puts on the wire or
# in a device reaches the layers' tests through the library without a line
# of crates/sipral changing (a request written compact by sipral-core once
# broke the datagram-limit test of four layers). Whether a crate is linked
# into the library is cargo's answer, not a list kept here.
route_to() {
    local areas="$1" why="$2" area
    for area in $areas; do
        printf '%s\t%s\t%s\n' "$area" "$ROUTED_PATH" "$why" >>"$ROUTES"
    done
}
route() {
    local crate
    ROUTED_PATH="$1"
    case "$1" in
        *.md|THIRD-PARTY-LICENSES.txt) route_to site "the documentation site carries it" ;;
    esac
    case "$1" in
        docs/numbers.toml|scripts/numbers.py)
            route_to numbers "the published figures' budgets, or what holds the figures to them" ;;
        Cargo.toml|Cargo.lock|rust-toolchain.toml|crates/sipral-ffi/*|crates/sipral/*)
            route_to numbers "what the published figures are measured on" ;;
        crates/*)
            crate=${1#crates/}
            crate=${crate%%/*}
            if [ -z "$FFI_GRAPH" ] || printf '%s\n' "$FFI_GRAPH" | found -x "$crate"; then
                route_to numbers "linked into the C library the published figures are measured on"
            fi ;;
    esac
    case "$1" in
        scripts/check.sh)
            route_to "$AREAS" "the gate itself" ;;
        Cargo.toml|Cargo.lock|rust-toolchain.toml)
            route_to "rust abi $LAYERS" "the workspace's manifest or toolchain, which every build reads" ;;
        deny.toml)
            route_to rust "cargo deny's policy" ;;
        crates/sipral-ffi/*|tools/abi-gen/*|bindings/c/include/*)
            route_to "rust abi $LAYERS" "the C ABI, which every layer loads" ;;
        crates/sipral/*)
            route_to "rust abi $LAYERS" "the facade, whose behaviour every layer's tests drive through the C library" ;;
        crates/sipral-aec-webrtc/*)
            route_to rust "outside the workspace, built on its own by the rust area" ;;
        crates/*)
            crate=${1#crates/}
            crate=${crate%%/*}
            if [ -z "$FFI_GRAPH" ] || printf '%s\n' "$FFI_GRAPH" | found -x "$crate"; then
                route_to "rust abi $LAYERS" "below the facade and linked into the C library every layer loads"
            else
                route_to rust "a crate the C library does not link"
            fi ;;
        bindings/fixtures/*)
            route_to "rust $LAYERS" "fixtures the crates' tests and the layers' tests read" ;;
        tools/*|fixtures/*|fuzz/*|interop/harness/*)
            route_to rust "built, linted or tested by the rust area" ;;
        bindings/c/sipral.c)
            route_to "abi swift" "C compiled by the abi area and by the Swift package" ;;
        bindings/c/*|interop/harness-c/*)
            route_to abi "C the abi area compiles" ;;
        bindings/Package.swift|bindings/swift/*)
            route_to "swift rn" "the Swift layer, which the React Native iOS half builds over" ;;
        Package.swift)
            route_to "swift rn" "the Swift package a release publishes, which the React Native pod resolves" ;;
        bindings/dotnet/*)
            route_to dotnet "the .NET layer" ;;
        bindings/kotlin/*)
            route_to "kotlin jvm rn" "the Kotlin layer, which bindings/jvm compiles over and sipral.aar carries" ;;
        bindings/jvm/*)
            route_to jvm "the server jar's own code" ;;
        bindings/python/*)
            route_to "python pipecat agents" "the Python layer, which the Pipecat and agent integrations run on" ;;
        integrations/pipecat/*)
            route_to pipecat "the Pipecat integration" ;;
        integrations/agents/*)
            route_to agents "the voice-agent connectors" ;;
        bindings/dart/*)
            route_to dart "the Dart layer" ;;
        bindings/react-native/android/src/main/java/org/sipral/reactnative/core/*|bindings/react-native/android/jvm-check/*)
            route_to "rn kotlin" "the React Native Android logic, which runs on a JVM in the kotlin area" ;;
        bindings/react-native/*)
            route_to rn "the React Native package" ;;
        scripts/package/features.sh)
            route_to "swift dotnet kotlin jvm python rn" "the feature list every packaging script reads" ;;
        scripts/package/apple.sh)
            route_to "swift dotnet python" "how the Apple natives are built for the XCFramework, NuGet and the wheels" ;;
        scripts/package/xcframework.sh)
            route_to swift "the XCFramework's packaging" ;;
        scripts/package/wheels.sh|scripts/package/qemu-verify.sh)
            route_to python "the wheels' packaging" ;;
        scripts/package/aarch64-cross.sh|scripts/package/docker/*)
            route_to "python dotnet" "the linux-arm64 cross path the wheels and NuGet take" ;;
        scripts/package/nuget.sh)
            route_to dotnet "the NuGet packaging" ;;
        scripts/package/aar.sh|scripts/package/android.sh)
            route_to "kotlin rn" "the Android packaging, whose sipral.aar the React Native build takes" ;;
        scripts/package/jvm.sh)
            route_to jvm "the server jar's packaging" ;;
        scripts/package/pub.sh)
            route_to dart "the Dart package's packaging" ;;
        scripts/package/npm.sh)
            route_to rn "the React Native package's packaging" ;;
        scripts/site.sh|site/*|docs/*)
            route_to site "the documentation site" ;;
        *.md|THIRD-PARTY-*|scripts/*|interop/*|assets/*|.github/*|LICENSE*|AUTHORS|SECURITY.md|.gitignore|.gitattributes|.gitleaksignore)
            route_to hygiene "read by the tree checks, built by nothing" ;;
        *)
            route_to "$AREAS" "not mapped to an area, so every area" ;;
    esac
}

# Sets SELECTED to the areas the change reaches, and says why.
choose_changed() {
    local base="$BASE" described paths path area first more n
    if [ -z "$base" ]; then
        if ! base=$(git -C "$ROOT" merge-base HEAD origin/main 2>/dev/null); then
            printf 'check.sh: no merge base with origin/main; name one: --changed BASE\n' >&2
            return 1
        fi
        described="the merge base with origin/main, $(git -C "$ROOT" rev-parse --short "$base")"
    else
        if ! git -C "$ROOT" rev-parse --verify -q "$base^{commit}" >/dev/null; then
            printf 'check.sh: %s is not a commit\n' "$base" >&2
            return 1
        fi
        described="$base"
    fi
    # what differs from the base in the working tree, committed or not, and
    # what is new and not yet added
    paths=$( { git -C "$ROOT" diff --name-only "$base" -- ; git -C "$ROOT" ls-files --others --exclude-standard; } | sort -u)
    FFI_GRAPH=$(cargo tree -p sipral-ffi -e normal --prefix none --target all 2>/dev/null \
        | awk '$1 ~ /^sipral/ { print $1 }' | sort -u)
    ROUTES=$(mktemp)
    ROUTED_PATH="(always)"
    route_to hygiene "the tree checks run on every change"
    n=0
    for path in $paths; do
        route "$path"
        n=$((n + 1))
    done
    printf 'changed against %s: %s path(s)\n' "$described" "$n"
    SELECTED=""
    for area in $AREAS; do
        first=$(awk -F'\t' -v a="$area" '$1 == a { print $2 ": " $3; exit }' "$ROUTES")
        [ -n "$first" ] || continue
        more=$(awk -F'\t' -v a="$area" '$1 == a { seen[$2] = 1 } END { print length(seen) - 1 }' "$ROUTES")
        if [ "$more" -gt 0 ]; then
            printf '  %-8s %s (and %s more)\n' "$area" "$first" "$more"
        else
            printf '  %-8s %s\n' "$area" "$first"
        fi
        SELECTED="$SELECTED $area"
    done
    rm -f "$ROUTES"
    [ -z "$FFI_GRAPH" ] && printf '  (cargo tree did not answer, so every crate counted as linked into the C library)\n'
    return 0
}

# One area, in the process it was started in, with its own scratch space.
run_area() {
    FAIL=0
    AREA_WORK="$CHECK_DIR/work/$1"
    PKG_WORK="$AREA_WORK"
    rm -rf "$AREA_WORK"
    mkdir -p "$AREA_WORK"
    "area_$1"
    rm -rf "$AREA_WORK"
    return "$FAIL"
}

# What an area may not start before. The layers load the library the abi
# area builds and checks, and numbers measures it, so they start once it is
# done; the others start at once.
waits_for() {
    case "$1" in
        numbers|swift|dotnet|kotlin|jvm|python|pipecat|agents|dart|rn) printf 'abi\n' ;;
    esac
}

# How many lines of one kind (ok, skip, FAIL) an area printed.
counted() {
    if [ -f "$CHECK_DIR/$2.log" ]; then grep -c "^  $1 " "$CHECK_DIR/$2.log" || true; else echo 0; fi
}

case "$MODE" in
    full) SELECTED="$AREAS" ;;
    changed) choose_changed || exit 2 ;;
esac
ordered=""
for a in $AREAS; do
    case " $SELECTED " in *" $a "*) ordered="$ordered $a" ;; esac
done
SELECTED="${ordered# }"
if [ "$LIST" -eq 1 ]; then
    printf '%s\n' "$SELECTED"
    exit 0
fi

JOBS="${SIPRAL_CHECK_JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}"
case "$JOBS" in ''|*[!0-9]*|0) JOBS=1 ;; esac
rm -rf "$PREP"
mkdir -p "$PREP"
for a in $SELECTED; do rm -f "$CHECK_DIR/$a.log" "$CHECK_DIR/$a.status" "$CHECK_DIR/$a.started" "$CHECK_DIR/$a.secs"; done
began=$(date +%s)

if [ "$(printf '%s\n' $SELECTED | grep -c .)" -eq 1 ]; then
    # one area: its output as it comes, and kept as well
    date +%s >"$CHECK_DIR/$SELECTED.started"
    ( run_area "$SELECTED" ) 2>&1 | tee "$CHECK_DIR/$SELECTED.log"
    printf '%s\n' "${PIPESTATUS[0]}" >"$CHECK_DIR/$SELECTED.status"
    printf '%s\n' "$(( $(date +%s) - began ))" >"$CHECK_DIR/$SELECTED.secs"
else
    printf 'areas: %s, at most %s at a time; each one'"'"'s output in target/check/AREA.log\n' "$SELECTED" "$JOBS"
    pending="$SELECTED"
    running=""
    trap 'for e in $running; do kill "${e#*:}" 2>/dev/null; done; exit 130' INT TERM
    while [ -n "$pending$running" ]; do
        still=""
        for e in $running; do
            a=${e%%:*}
            pid=${e#*:}
            if kill -0 "$pid" 2>/dev/null; then
                still="$still $e"
                continue
            fi
            wait "$pid"
            printf '%s\n' "$?" >"$CHECK_DIR/$a.status"
            secs=$(( $(date +%s) - $(cat "$CHECK_DIR/$a.started") ))
            printf '%s\n' "$secs" >"$CHECK_DIR/$a.secs"
            if [ "$(cat "$CHECK_DIR/$a.status")" -eq 0 ]; then said=passed; else said=FAILED; fi
            printf '  %-8s %s after %ss: %s ok, %s skip, %s FAIL\n' "$a" "$said" "$secs" \
                "$(counted ok "$a")" "$(counted skip "$a")" "$(counted FAIL "$a")"
        done
        running="${still# }"
        busy=""
        for e in $running; do busy="$busy ${e%%:*}"; done
        left=""
        for a in $pending; do
            blocked=0
            for d in $(waits_for "$a"); do
                case " $pending $busy " in *" $d "*) blocked=1 ;; esac
            done
            if [ "$blocked" -eq 0 ] && [ "$(printf '%s\n' $running | grep -c .)" -lt "$JOBS" ]; then
                date +%s >"$CHECK_DIR/$a.started"
                ( run_area "$a" ) >"$CHECK_DIR/$a.log" 2>&1 &
                running="$running $a:$!"
                busy="$busy $a"
                printf '  %-8s started\n' "$a"
            else
                left="$left $a"
            fi
        done
        pending="${left# }"
        [ -n "$pending$running" ] && sleep 1
    done
    trap - INT TERM

    # every area's output, in the order the complete gate lists them
    for a in $SELECTED; do
        printf '\n==== %s ====\n' "$a"
        cat "$CHECK_DIR/$a.log"
    done
fi

printf '\n'
ok=0; skipped=0; failed=0; failed_areas=""
for a in $SELECTED; do
    ok=$((ok + $(counted ok "$a")))
    skipped=$((skipped + $(counted skip "$a")))
    failed=$((failed + $(counted FAIL "$a")))
    [ "$(cat "$CHECK_DIR/$a.status" 2>/dev/null || echo 1)" -eq 0 ] || failed_areas="$failed_areas $a"
    printf '  %-8s %4s ok %3s skip %3s FAIL %6ss\n' "$a" "$(counted ok "$a")" "$(counted skip "$a")" \
        "$(counted FAIL "$a")" "$(cat "$CHECK_DIR/$a.secs" 2>/dev/null || echo '?')"
done
printf '%s ok, %s skip, %s FAIL in %ss\n' "$ok" "$skipped" "$failed" "$(( $(date +%s) - began ))"
[ -n "$failed_areas" ] && printf 'failed:%s\n' "$failed_areas"
# the complete gate's last line is what it always was; an area gate's names
# the areas, so that it is not taken for the complete one
if [ "$MODE" = full ]; then
    what="all checks"
    failed_said="checks failed"
else
    what="$(printf '%s' "$SELECTED" | sed 's/ /, /g') checks"
    failed_said="$what failed"
fi
[ -z "$failed_areas" ] && { printf '%s passed\n' "$what"; exit 0; }
printf '%s\n' "$failed_said"
exit 1
