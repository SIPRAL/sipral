# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# Which of sipral-ffi's features a packaged artefact is built with. Sourced,
# not run, by every script in this directory that builds or packs the C ABI,
# so that they all answer the same way.
#
# A binary somebody downloads instead of compiling is the one place the
# crate's `opus` default would put libopus into a product quietly
# (docs/05-media.md), so an artefact leaves it out unless the script was
# given --with-opus. Every other default stays in, read out of
# crates/sipral-ffi/Cargo.toml rather than repeated here, so a default added
# there reaches the artefacts without an edit here.
#
# `package_features 0|1` (1: with Opus) sets
#   FFI_FEATURES       the comma-separated feature list, "dtls,ice,stun" today
#   FFI_FEATURE_ARGS   the cargo arguments that build exactly that list
#   VARIANT_SUFFIX     "" without Opus and "-opus" with it, for artefact names
#   VARIANT_LABEL      one line naming the variant, for logs and metadata
# and returns non-zero when the default list cannot be read.
#
# FEATURES_MARKER is the file a native's directory carries beside it,
# holding FFI_FEATURES, so that the half of a script that packs natives
# built elsewhere can refuse ones built for the other variant.
FEATURES_MARKER="sipral-ffi.features"

package_features() {
    local with_opus="$1" defaults rest f
    defaults=$(sed -n 's/^default = \[\(.*\)\]$/\1/p' "$ROOT/crates/sipral-ffi/Cargo.toml" | tr -d '" ')
    [ -n "$defaults" ] || return 1
    rest=""
    for f in $(printf '%s\n' "$defaults" | tr ',' ' '); do
        [ "$f" = "opus" ] && continue
        rest="${rest:+$rest,}$f"
    done
    if [ "$with_opus" -eq 1 ]; then
        FFI_FEATURES="${rest:+$rest,}opus"
        VARIANT_SUFFIX="-opus"
        VARIANT_LABEL="with Opus: this artefact contains libopus (THIRD-PARTY-NOTICES.md)"
    else
        FFI_FEATURES="$rest"
        VARIANT_SUFFIX=""
        VARIANT_LABEL="without Opus: no libopus in this artefact"
    fi
    FFI_FEATURE_ARGS=(--no-default-features --features "$FFI_FEATURES")
}
