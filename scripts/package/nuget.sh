#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# The .NET artefact: a Sipral.nupkg carrying the C ABI's native library under
# runtimes/<rid>/native/ for every RID this build reaches, over the printed
# bindings/dotnet/Sipral project unchanged.
#
# Building the five natives (win-x64, win-arm64, osx-arm64, osx-x64,
# linux-x64) needs five machines' worth of toolchain, which is why this is
# two subcommands rather than one:
#
#   scripts/package/nuget.sh collect --out DIR [--rid RID ...]
#       builds whatever RIDs *this* host can build for real -- osx-arm64 and
#       osx-x64 on macOS with cargo, linux-x64 on Linux with Docker's
#       rust:1.99-trixie (the toolchain this workspace is pinned to),
#       linux-arm64 in the aarch64 cross image wherever Docker is, win-x64
#       and win-arm64 on Windows under Git Bash with Rust's MSVC toolchain --
#       and writes DIR/<rid>/<native file>. The packing host then takes every
#       RID's directory, from whichever machine built it, as its --staging.
#
#   scripts/package/nuget.sh pack --out DIR --staging DIR [--rid RID ...] \
#       [--dry-run] [--publish]
#       assembles runtimes/<rid>/native/ from whatever DIR/<rid>/ holds, for
#       every requested RID (default: all five), and runs dotnet pack over a
#       staged copy of bindings/dotnet/Sipral -- the committed project is
#       never written to. A requested RID with nothing staged for it is a
#       FAIL outside --dry-run, and under --dry-run is reported as "layout
#       only" and does not fail the step: the empty runtimes/<rid>/native/
#       directory it still creates is what a machine without that RID's
#       toolchain can honestly prove -- the pack logic and the layout, not a
#       native nothing here built.
#
# Both take --with-opus, for the variant that carries libopus. Without it,
# collect builds without sipral-ffi's `opus` feature and every other default
# kept (features.sh says why and how), and writes the feature list it built
# with to DIR/<rid>/sipral-ffi.features beside each native; a native placed
# by hand carries that file too, holding the same list. pack refuses a staged
# native whose list is missing or is not the one its own --with-opus (or its
# absence) asks for, so the two halves cannot mix variants, and packs the
# variant with libopus under its own package ID, Sipral.Opus, rather than
# Sipral.
set -uo pipefail

# found [GREP OPTIONS] PATTERN: whether standard input has a line PATTERN
# matches, read to its end. `grep -q` stops at the first match, and under
# pipefail whatever is still writing into the pipe then dies of SIGPIPE and
# fails the pipeline: a match read as none, and more often the busier the
# machine. A gate run in parallel lost classes.jar's first entries that way.
found() { grep "$@" >/dev/null; }

cd "$(dirname "$0")/../.."
ROOT="$PWD"

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
note() { printf '  note  %s\n' "$1"; }
step() { printf '\n%s\n' "$1"; }

ALL_RIDS=(win-x64 win-arm64 osx-arm64 osx-x64 linux-x64 linux-arm64)
triple_of() {
    case "$1" in
        win-x64) printf 'x86_64-pc-windows-msvc' ;;
        win-arm64) printf 'aarch64-pc-windows-msvc' ;;
        osx-arm64) printf 'aarch64-apple-darwin' ;;
        osx-x64) printf 'x86_64-apple-darwin' ;;
        linux-x64) printf 'x86_64-unknown-linux-gnu' ;;
        linux-arm64) printf 'aarch64-unknown-linux-gnu' ;;
        *) printf ''; return 1 ;;
    esac
}
native_name_of() {
    case "$1" in
        win-*) printf 'sipral_ffi.dll' ;;
        osx-*) printf 'libsipral_ffi.dylib' ;;
        linux-*) printf 'libsipral_ffi.so' ;;
        *) printf ''; return 1 ;;
    esac
}
cargo_artifact_of() {
    case "$1" in
        win-*) printf 'sipral_ffi.dll' ;;
        osx-*) printf 'libsipral_ffi.dylib' ;;
        linux-*) printf 'libsipral_ffi.so' ;;
    esac
}

CMD="${1:-}"
[ $# -ge 1 ] && shift
case "$CMD" in
    collect|pack) ;;
    *) printf 'usage: nuget.sh collect --out DIR [--rid RID ...] [--with-opus]\n' >&2
       printf '       nuget.sh pack --out DIR --staging DIR [--rid RID ...] [--dry-run] [--publish] [--with-opus]\n' >&2
       exit 2 ;;
esac

OUT=""
STAGING=""
DRY_RUN=0
PUBLISH=0
WITH_OPUS=0
RIDS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --staging) STAGING="$2"; shift 2 ;;
        --rid) RIDS+=("$2"); shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --publish) PUBLISH=1; shift ;;
        --with-opus) WITH_OPUS=1; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -z "$OUT" ] && { printf '%s needs --out DIR\n' "$CMD" >&2; exit 2; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
[ "${#RIDS[@]}" -eq 0 ] && RIDS=("${ALL_RIDS[@]}")
. "$ROOT/scripts/package/features.sh"
package_features "$WITH_OPUS" || { printf 'no default feature list in crates/sipral-ffi/Cargo.toml\n' >&2; exit 1; }
. "$ROOT/scripts/package/neutral-paths.sh"
. "$ROOT/scripts/package/apple.sh"
APPLE_TARGET="$(apple_target_dir "${CARGO_TARGET_DIR:-$ROOT/target}")"
PACKAGE_ID="Sipral"
[ "$WITH_OPUS" -eq 1 ] && PACKAGE_ID="Sipral.Opus"

if [ "$CMD" = "collect" ]; then
    step "collecting on $(uname -sm), $VARIANT_LABEL (features $FFI_FEATURES)"
    HOST_OS="$(uname -s)"

    for rid in "${RIDS[@]}"; do
        triple="$(triple_of "$rid")"
        if [ -z "$triple" ]; then fail "unknown RID: $rid"; continue; fi
        case "$rid" in
            osx-arm64|osx-x64)
                if [ "$HOST_OS" != "Darwin" ]; then
                    note "$rid: skipped, this host is $HOST_OS"; continue
                fi
                if ! rustup target list --installed 2>/dev/null | found -x "$triple"; then
                    fail "$rid: $triple not installed (rustup target add $triple)"; continue
                fi
                rm -f "$OUT/$rid/$FEATURES_MARKER"
                # built for apple.sh's oldest macOS, in its own target
                # directory, and checked object by object in the static
                # archive the same build writes, libopus's included
                neutral_cargo_args "$triple"
                if cargo build --release -p sipral-ffi "${FFI_FEATURE_ARGS[@]}" --target "$triple" \
                    "${NEUTRAL_CARGO_ARGS[@]}" --target-dir "$APPLE_TARGET" >"$OUT/.build-$rid.log" 2>&1; then
                    if ! newest=$(apple_min_at_most "$APPLE_TARGET/$triple/release/libsipral_ffi.a" "$APPLE_MACOS_MIN"); then
                        fail "$rid: an object was built for macOS ${newest:-(no minimum named)}, newer than $APPLE_MACOS_MIN"
                        continue
                    fi
                    mkdir -p "$OUT/$rid"
                    cp "$APPLE_TARGET/$triple/release/$(cargo_artifact_of "$rid")" "$OUT/$rid/$(native_name_of "$rid")"
                    pass "$rid: cargo build --release -p sipral-ffi ${FFI_FEATURE_ARGS[*]} --target $triple"
                    neutral_paths_held "$rid/$(native_name_of "$rid")" "$OUT/$rid/$(native_name_of "$rid")" || continue
                    printf '%s\n' "$FFI_FEATURES" >"$OUT/$rid/$FEATURES_MARKER"
                else
                    fail "$rid: cargo build --release -p sipral-ffi ${FFI_FEATURE_ARGS[*]} --target $triple:"
                    tail -20 "$OUT/.build-$rid.log" | sed 's/^/        /'
                fi
                ;;
            linux-x64)
                if [ "$HOST_OS" != "Linux" ]; then
                    note "$rid: skipped, this host is $HOST_OS (run collect on the Linux box)"; continue
                fi
                if ! command -v docker >/dev/null 2>&1; then
                    fail "$rid: docker not found, and rust:1.99-trixie is how this build matches rust-toolchain.toml"
                    continue
                fi
                rm -f "$OUT/$rid/$FEATURES_MARKER"
                neutral_docker_env /usr/local/cargo /usr/local/rustup /work
                if docker run --rm -v "$ROOT:/work:ro" -v "$OUT:/out" -w /work \
                    -e CARGO_TARGET_DIR=/tmp/target "${NEUTRAL_DOCKER_ENV[@]}" \
                    rust:1.99-trixie \
                    sh -c "apt-get update -qq && apt-get install -qq -y --no-install-recommends cmake >/dev/null && cargo build --release -p sipral-ffi ${FFI_FEATURE_ARGS[*]} --target $triple --config \"\$NEUTRAL_PATHS_CONFIG\" && mkdir -p /out/$rid && cp /tmp/target/$triple/release/$(cargo_artifact_of "$rid") /out/$rid/$(native_name_of "$rid") && echo $FFI_FEATURES >/out/$rid/$FEATURES_MARKER" \
                    >"$OUT/.build-$rid.log" 2>&1; then
                    pass "$rid: docker run rust:1.99-trixie, cargo build --release -p sipral-ffi ${FFI_FEATURE_ARGS[*]} --target $triple"
                    neutral_paths_held "$rid/$(native_name_of "$rid")" "$OUT/$rid/$(native_name_of "$rid")"
                else
                    fail "$rid: docker build failed:"
                    tail -20 "$OUT/.build-$rid.log" | sed 's/^/        /'
                fi
                ;;
            linux-arm64)
                # No arm64 hardware needed, and not gated on $HOST_OS: this
                # cross-compiles in scripts/package/aarch64-cross.sh's own
                # unprivileged container regardless of what this host is,
                # the same as scripts/package/wheels.sh --linux-arm64.
                if ! command -v docker >/dev/null 2>&1; then
                    fail "$rid: docker not found (cross-compiles in a container, no arm64 hardware needed)"
                    continue
                fi
                . "$ROOT/scripts/package/aarch64-cross.sh"
                if ! aarch64_cross_ensure_image; then
                    fail "$rid: could not build the aarch64 cross image (scripts/package/docker/aarch64-cross.Dockerfile)"
                    continue
                fi
                rm -f "$OUT/$rid/$FEATURES_MARKER"
                cross_target="$OUT/.cargo-target-$rid"
                if aarch64_cross_build "$cross_target" >"$OUT/.build-$rid.log" 2>&1; then
                    native_so="$cross_target/aarch64-unknown-linux-gnu/release/$(cargo_artifact_of "$rid")"
                    if highest=$(aarch64_glibc_check "$native_so" 28); then
                        mkdir -p "$OUT/$rid"
                        cp "$native_so" "$OUT/$rid/$(native_name_of "$rid")"
                        pass "$rid: cross-compiled ($AARCH64_CROSS_IMAGE), manylinux_2_28-compatible ($highest)"
                        neutral_paths_held "$rid/$(native_name_of "$rid")" "$OUT/$rid/$(native_name_of "$rid")" \
                            && printf '%s\n' "$FFI_FEATURES" >"$OUT/$rid/$FEATURES_MARKER"
                    else
                        fail "$rid: $native_so is not manylinux_2_28-compatible: $highest"
                    fi
                else
                    fail "$rid: cross build failed:"
                    tail -20 "$OUT/.build-$rid.log" | sed 's/^/        /'
                fi
                ;;
            win-x64|win-arm64)
                case "$HOST_OS" in
                    MINGW*|MSYS*|CYGWIN*)
                        # Git Bash on Windows, with Rust's MSVC toolchain and
                        # the Visual Studio build tools for the target's
                        # architecture
                        if ! rustup target list --installed 2>/dev/null | found -x "$triple"; then
                            fail "$rid: $triple not installed (rustup target add $triple)"; continue
                        fi
                        rm -f "$OUT/$rid/$FEATURES_MARKER"
                        win_target="${CARGO_TARGET_DIR:-$ROOT/target}"
                        neutral_cargo_args "$triple"
                        if cargo build --release -p sipral-ffi "${FFI_FEATURE_ARGS[@]}" --target "$triple" \
                            "${NEUTRAL_CARGO_ARGS[@]}" --target-dir "$win_target" >"$OUT/.build-$rid.log" 2>&1; then
                            mkdir -p "$OUT/$rid"
                            cp "$win_target/$triple/release/$(cargo_artifact_of "$rid")" "$OUT/$rid/$(native_name_of "$rid")"
                            pass "$rid: cargo build --release -p sipral-ffi ${FFI_FEATURE_ARGS[*]} --target $triple"
                            neutral_paths_held "$rid/$(native_name_of "$rid")" "$OUT/$rid/$(native_name_of "$rid")" \
                                && printf '%s\n' "$FFI_FEATURES" >"$OUT/$rid/$FEATURES_MARKER"
                        else
                            fail "$rid: cargo build --release -p sipral-ffi ${FFI_FEATURE_ARGS[*]} --target $triple:"
                            tail -20 "$OUT/.build-$rid.log" | sed 's/^/        /'
                        fi
                        continue
                        ;;
                esac
                note "$rid: not built by this subcommand here; in Git Bash on a Windows host run"
                note "         scripts/package/nuget.sh collect --out DIR --rid $rid${VARIANT_SUFFIX:+ --with-opus}"
                note "         and copy DIR/$rid/ (the native and $FEATURES_MARKER) to $OUT/$rid/"
                ;;
        esac
    done
    printf '\n'
    [ "$FAIL" -eq 0 ] && { printf 'nuget.sh collect: done, %s\n' "$OUT"; exit 0; }
    printf 'nuget.sh collect: failed\n'; exit 1
fi

# pack
[ -z "$STAGING" ] && { printf 'pack needs --staging DIR\n' >&2; exit 2; }
[ -d "$STAGING" ] || { printf 'no such staging directory: %s\n' "$STAGING" >&2; exit 2; }
STAGING="$(cd "$STAGING" && pwd)"

command -v dotnet >/dev/null 2>&1 || { fail "dotnet not found"; printf '\nnuget.sh pack: failed\n'; exit 1; }

step "one version"
"$ROOT/scripts/version.sh" --check || { printf '\nnuget.sh pack: failed\n'; exit 1; }

STAGE="$OUT/_stage"
rm -rf "$STAGE"
mkdir -p "$STAGE/proj"
cp -R "$ROOT/bindings/dotnet/Sipral/." "$STAGE/proj/"

# The licence texts at the package's root, beside the README: the AGPL, the
# commercial arm, and the third-party licences and notices of what the
# natives link -- what the JVM jar carries under META-INF/.
LICENCE_FILES=(LICENSE LICENSE-COMMERCIAL.md THIRD-PARTY-LICENSES.txt THIRD-PARTY-NOTICES.md)
ITEMS=""
for f in "${LICENCE_FILES[@]}"; do
    cp "$ROOT/$f" "$STAGE/proj/$f"
    ITEMS="$ITEMS    <None Include=\"$f\" Pack=\"true\" PackagePath=\"/\" />\n"
done

step "runtimes, from $STAGING, for $PACKAGE_ID, $VARIANT_LABEL"
populated=0
for rid in "${RIDS[@]}"; do
    native="$(native_name_of "$rid")"
    src="$STAGING/$rid/$native"
    dest_dir="$STAGE/proj/runtimes/$rid/native"
    mkdir -p "$dest_dir"
    built_with=$(cat "$STAGING/$rid/$FEATURES_MARKER" 2>/dev/null)
    if [ -f "$src" ] && [ "$built_with" != "$FFI_FEATURES" ]; then
        # Even under --dry-run: a native of the other variant in this
        # package is the one mistake the package ID exists to prevent.
        fail "$rid: $native was built with features '${built_with:-(no $FEATURES_MARKER beside it)}', not '$FFI_FEATURES' ($VARIANT_LABEL)"
    elif [ -f "$src" ]; then
        cp "$src" "$dest_dir/$native"
        size=$(stat -f%z "$src" 2>/dev/null || stat -c%s "$src" 2>/dev/null)
        pass "$rid: $native ($size bytes)"
        # built elsewhere, so held again here to what any host leaves behind
        neutral_paths_held "$rid/$native" "$src"
        ITEMS="$ITEMS    <None Include=\"runtimes/$rid/native/$native\" Pack=\"true\" PackagePath=\"runtimes/$rid/native/\" />\n"
        populated=$((populated + 1))
    elif [ "$DRY_RUN" -eq 1 ]; then
        note "$rid: no native staged, layout only (runtimes/$rid/native/ created empty)"
    else
        fail "$rid: no native staged at $src (run collect on the machine that builds it first, or pass --rid to narrow the request)"
    fi
done
[ "$FAIL" -ne 0 ] && { printf '\nnuget.sh pack: failed\n'; exit 1; }
[ "$populated" -eq 0 ] && [ "$DRY_RUN" -eq 0 ] && { fail "no RID had a native staged"; printf '\nnuget.sh pack: failed\n'; exit 1; }

# Appended to the staged copy only -- bindings/dotnet/Sipral/Sipral.csproj
# stays exactly what was committed. One project, packed once per run, so a
# run that only reached two of five RIDs still produces one truthful
# package rather than five partial ones.
if [ -n "$ITEMS" ]; then
    CSPROJ="$STAGE/proj/Sipral.csproj"
    grep -q '</Project>' "$CSPROJ" || { fail "$CSPROJ has no </Project> to insert before"; printf '\nnuget.sh pack: failed\n'; exit 1; }
    awk -v items="$ITEMS" '
        /<\/Project>/ { printf "  <ItemGroup>\n%s  </ItemGroup>\n</Project>\n", items; next }
        { print }
    ' "$CSPROJ" >"$CSPROJ.new" && mv "$CSPROJ.new" "$CSPROJ"
fi

step "dotnet pack"
if dotnet pack "$STAGE/proj/Sipral.csproj" -c Release -p:PackageId="$PACKAGE_ID" -o "$OUT" >"$STAGE/pack.log" 2>&1; then
    pass "dotnet pack -c Release -p:PackageId=$PACKAGE_ID"
else
    fail "dotnet pack -c Release -p:PackageId=$PACKAGE_ID:"
    tail -30 "$STAGE/pack.log" | sed 's/^/        /'
fi

# A version, then .nupkg: `Sipral.*` alone would also match Sipral.Opus's.
NUPKG=$(find "$OUT" -maxdepth 1 -name "$PACKAGE_ID.[0-9]*.nupkg" | head -1)
if [ -n "$NUPKG" ]; then
    step "structure"
    listing=$(unzip -l "$NUPKG" 2>/dev/null)
    for rid in "${RIDS[@]}"; do
        native="$(native_name_of "$rid")"
        if [ -f "$STAGING/$rid/$native" ]; then
            if printf '%s\n' "$listing" | found "runtimes/$rid/native/$native"; then
                pass "$NUPKG carries runtimes/$rid/native/$native"
            else
                fail "$NUPKG is missing runtimes/$rid/native/$native, though it was staged"
            fi
        fi
    done
    for f in README.md "${LICENCE_FILES[@]}"; do
        printf '%s\n' "$listing" | found " $f\$" && pass "carries $f" || fail "$NUPKG is missing $f"
    done
    nuspec=$(unzip -p "$NUPKG" "$PACKAGE_ID.nuspec" 2>/dev/null)
    for element in '<license type="expression">' '<projectUrl>' '<repository type="git"' '<readme>' '<icon>' '<copyright>' '<tags>'; do
        printf '%s\n' "$nuspec" | found -F "$element" && pass "the nuspec carries $element" || fail "the nuspec has no $element"
    done
else
    fail "no $PACKAGE_ID.<version>.nupkg landed in $OUT"
fi

# The SBOM sits beside the .nupkg, from sipral-ffi's own dependency graph at
# the features this pack was staged with, across every RID a .nupkg carries
# in one file (docs/10-roadmap.md). --notices only for the variant whose
# feature list is THIRD-PARTY-LICENSES.txt's own (no flags at all, opus
# included).
if [ -n "$NUPKG" ]; then
    step "SBOM"
    NUPKG_VERSION=$(basename "$NUPKG" .nupkg)
    NUPKG_VERSION="${NUPKG_VERSION#"$PACKAGE_ID".}"
    SBOM="$NUPKG.cdx.json"
    # Expanded as ${NOTICES_ARGS[@]+...}: bash 3.2 under `set -u` calls an
    # empty array's [@] an unbound variable.
    NOTICES_ARGS=()
    [ "$WITH_OPUS" -eq 1 ] && NOTICES_ARGS=(--notices "$ROOT/THIRD-PARTY-LICENSES.txt")
    if sbom_out=$(cargo run --quiet -p sipral-sbom-gen -- \
        --crate sipral-ffi --features "$FFI_FEATURES" --target all \
        --artifact-name "$PACKAGE_ID" --artifact-version "$NUPKG_VERSION" \
        --artifact "$NUPKG" --out "$SBOM" ${NOTICES_ARGS[@]+"${NOTICES_ARGS[@]}"} 2>&1); then
        pass "$(basename "$SBOM")"
    else
        fail "sbom-gen:"; printf '%s\n' "$sbom_out" | sed 's/^/        /'
    fi
fi

if [ "$PUBLISH" -eq 1 ]; then
    step "publish"
    printf '  not run: the owner publishes, with every RID staged (not a --dry-run pack):\n'
    printf '    dotnet nuget push %s\n' "${NUPKG:-$OUT/$PACKAGE_ID.<version>.nupkg}"
    printf '      --source https://api.nuget.org/v3/index.json --api-key <key>\n'
fi

printf '\n'
[ "$FAIL" -eq 0 ] && { printf 'nuget.sh pack: done, %s, %s\n' "${NUPKG:-$OUT}" "$VARIANT_LABEL"; exit 0; }
printf 'nuget.sh pack: failed\n'; exit 1
