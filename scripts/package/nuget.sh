#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
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
#       rust:1.95-trixie (the toolchain this workspace is pinned to) -- and
#       writes DIR/<rid>/<native file>. A RID neither of those covers
#       (win-x64, win-arm64) is not this subcommand's job: build it directly
#       with cargo on a Windows host and place the .dll at
#       DIR/<rid>/sipral_ffi.dll by hand, the same shape this writes.
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

cd "$(dirname "$0")/../.."
ROOT="$PWD"

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
note() { printf '  note  %s\n' "$1"; }
step() { printf '\n%s\n' "$1"; }

ALL_RIDS=(win-x64 win-arm64 osx-arm64 osx-x64 linux-x64)
triple_of() {
    case "$1" in
        win-x64) printf 'x86_64-pc-windows-msvc' ;;
        win-arm64) printf 'aarch64-pc-windows-msvc' ;;
        osx-arm64) printf 'aarch64-apple-darwin' ;;
        osx-x64) printf 'x86_64-apple-darwin' ;;
        linux-x64) printf 'x86_64-unknown-linux-gnu' ;;
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
                if ! rustup target list --installed 2>/dev/null | grep -qx "$triple"; then
                    fail "$rid: $triple not installed (rustup target add $triple)"; continue
                fi
                rm -f "$OUT/$rid/$FEATURES_MARKER"
                # built for apple.sh's oldest macOS, in its own target
                # directory, and checked object by object in the static
                # archive the same build writes, libopus's included
                if cargo build --release -p sipral-ffi "${FFI_FEATURE_ARGS[@]}" --target "$triple" \
                    --target-dir "$APPLE_TARGET" >"$OUT/.build-$rid.log" 2>&1; then
                    if ! newest=$(apple_min_at_most "$APPLE_TARGET/$triple/release/libsipral_ffi.a" "$APPLE_MACOS_MIN"); then
                        fail "$rid: an object was built for macOS ${newest:-(no minimum named)}, newer than $APPLE_MACOS_MIN"
                        continue
                    fi
                    mkdir -p "$OUT/$rid"
                    cp "$APPLE_TARGET/$triple/release/$(cargo_artifact_of "$rid")" "$OUT/$rid/$(native_name_of "$rid")"
                    printf '%s\n' "$FFI_FEATURES" >"$OUT/$rid/$FEATURES_MARKER"
                    pass "$rid: cargo build --release -p sipral-ffi ${FFI_FEATURE_ARGS[*]} --target $triple"
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
                    fail "$rid: docker not found, and rust:1.95-trixie is how this build matches rust-toolchain.toml"
                    continue
                fi
                rm -f "$OUT/$rid/$FEATURES_MARKER"
                if docker run --rm -v "$ROOT:/work:ro" -v "$OUT:/out" -w /work \
                    -e CARGO_TARGET_DIR=/tmp/target \
                    rust:1.95-trixie \
                    sh -c "apt-get update -qq && apt-get install -qq -y --no-install-recommends cmake >/dev/null && cargo build --release -p sipral-ffi ${FFI_FEATURE_ARGS[*]} --target $triple && mkdir -p /out/$rid && cp /tmp/target/$triple/release/$(cargo_artifact_of "$rid") /out/$rid/$(native_name_of "$rid") && echo $FFI_FEATURES >/out/$rid/$FEATURES_MARKER" \
                    >"$OUT/.build-$rid.log" 2>&1; then
                    pass "$rid: docker run rust:1.95-trixie, cargo build --release -p sipral-ffi ${FFI_FEATURE_ARGS[*]} --target $triple"
                else
                    fail "$rid: docker build failed:"
                    tail -20 "$OUT/.build-$rid.log" | sed 's/^/        /'
                fi
                ;;
            win-x64|win-arm64)
                note "$rid: not built by this subcommand; on a Windows host run"
                note "         cargo build --release -p sipral-ffi ${FFI_FEATURE_ARGS[*]} --target $triple,"
                note "         place the result at $OUT/$rid/$(native_name_of "$rid")"
                note "         and the line $FFI_FEATURES at $OUT/$rid/$FEATURES_MARKER"
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

STAGE="$OUT/_stage"
rm -rf "$STAGE"
mkdir -p "$STAGE/proj"
cp -R "$ROOT/bindings/dotnet/Sipral/." "$STAGE/proj/"

step "runtimes, from $STAGING, for $PACKAGE_ID, $VARIANT_LABEL"
ITEMS=""
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
            if printf '%s\n' "$listing" | grep -q "runtimes/$rid/native/$native"; then
                pass "$NUPKG carries runtimes/$rid/native/$native"
            else
                fail "$NUPKG is missing runtimes/$rid/native/$native, though it was staged"
            fi
        fi
    done
else
    fail "no $PACKAGE_ID.<version>.nupkg landed in $OUT"
fi

if [ "$PUBLISH" -eq 1 ]; then
    step "publish"
    printf '  not run: nothing ships to NuGet before the ABI freezes (docs/08-ffi.md).\n'
    printf '  What the owner runs once it has: dotnet nuget push %s\n' "${NUPKG:-$OUT/$PACKAGE_ID.<version>.nupkg}"
    printf '  --source https://api.nuget.org/v3/index.json --api-key <key>\n'
fi

printf '\n'
[ "$FAIL" -eq 0 ] && { printf 'nuget.sh pack: done, %s, %s\n' "${NUPKG:-$OUT}" "$VARIANT_LABEL"; exit 0; }
printf 'nuget.sh pack: failed\n'; exit 1
