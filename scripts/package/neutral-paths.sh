# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# Keeping the build machine's paths out of every packaged native. Sourced,
# not run, by every script in this directory that builds sipral-ffi, once
# ROOT is set.
#
# A release build writes source paths into the library: rustc's panic
# locations, for the workspace's own crates and for every dependency built
# out of cargo's registry, and __FILE__ in the C that libopus is built from.
# The macOS linker adds the path it wrote a dylib at, as its install name.
# Left alone, a package carries its builder's home directory and checkout.
# So every release build maps
#     cargo's home (the registry's sources)   to /cargo
#     rustup's home (the toolchain)           to /rustc
#     the checkout                            to /sipral
# rustc's with `--remap-path-prefix`, handed to cargo as a `--config` value
# for a `cfg(all())` target table: cargo adds those flags to any other
# target table's and to CARGO_TARGET_<TRIPLE>_RUSTFLAGS, which the aarch64
# cross image sets its linker flags in, where RUSTFLAGS would replace them
# all. RUSTFLAGS or CARGO_ENCODED_RUSTFLAGS would in turn drop the mapping,
# so sourcing this unsets both. The C compiler maps cargo's home through
# CFLAGS, which the cc crate adds to a per-target CFLAGS_<target> rather
# than replacing it: `-ffile-prefix-map` to /cargo, or for MSVC
# `/d1trimfile:`, which drops the prefix and leaves registry\src\...
#
# neutral_paths CARGO_HOME RUSTUP_HOME CHECKOUT [MSVC]
#     sets NEUTRAL_PATHS_CONFIG, the `--config` value, and NEUTRAL_CFLAGS,
#     for the three paths as the build sees them (MSVC 1: written for
#     cl.exe). Sourcing this calls it for this host's own and exports
#     CFLAGS.
#
# neutral_docker_env CARGO_HOME RUSTUP_HOME CHECKOUT
#     the same for a build in a Linux container, as the paths are inside
#     it, leaving this host's alone: sets NEUTRAL_DOCKER_ENV to the
#     `docker run` arguments that hand the container NEUTRAL_PATHS_CONFIG
#     and CFLAGS, for its cargo to be given `--config "$NEUTRAL_PATHS_CONFIG"`.
#
# neutral_cargo_args TRIPLE
#     sets NEUTRAL_CARGO_ARGS, what a `cargo build --target TRIPLE` on this
#     host is given: the `--config` above and, for an *-apple-darwin
#     TRIPLE, a second one making the dylib's install name
#     @rpath/libsipral_ffi.dylib rather than the path it was linked at.
#     Every binding opens the library by its own path, so nothing resolves
#     it by that name.
#
# neutral_paths_check FILE...
#     fails, naming each FILE and what it holds how many times, when a FILE
#     holds this host's home directory, the checkout, or cargo's or
#     rustup's home: what a build that missed the mapping leaves behind.
#
# neutral_paths_held LABEL FILE...
#     neutral_paths_check as a step of the calling script, reported through
#     its own pass and fail under LABEL; non-zero when it fails.

neutral_paths() {
    local cargo_home="$1" rustup_home="$2" checkout="$3" msvc="${4:-0}"
    NEUTRAL_PATHS_CONFIG="target.'cfg(all())'.rustflags=['--remap-path-prefix=$cargo_home=/cargo','--remap-path-prefix=$rustup_home=/rustc','--remap-path-prefix=$checkout=/sipral']"
    if [ "$msvc" -eq 1 ]; then
        NEUTRAL_CFLAGS="/d1trimfile:$cargo_home\\"
    else
        NEUTRAL_CFLAGS="-ffile-prefix-map=$cargo_home=/cargo"
    fi
}

neutral_docker_env() {
    local config cflags
    config=$(neutral_paths "$1" "$2" "$3" 0 && printf '%s' "$NEUTRAL_PATHS_CONFIG")
    cflags=$(neutral_paths "$1" "$2" "$3" 0 && printf '%s' "$NEUTRAL_CFLAGS")
    NEUTRAL_DOCKER_ENV=(-e "NEUTRAL_PATHS_CONFIG=$config" -e "CFLAGS=$cflags")
}

neutral_cargo_args() {
    NEUTRAL_CARGO_ARGS=(--config "$NEUTRAL_PATHS_CONFIG")
    case "$1" in
        *-apple-darwin)
            NEUTRAL_CARGO_ARGS+=(--config "target.$1.rustflags=['-Clink-arg=-Wl,-install_name,@rpath/libsipral_ffi.dylib']")
            ;;
    esac
}

neutral_paths_check() {
    local f needle n status=0
    for f in "$@"; do
        for needle in "${NEUTRAL_NEEDLES[@]}"; do
            n=$(LC_ALL=C grep -a -o -F -- "$needle" "$f" 2>/dev/null | wc -l | tr -d ' ')
            if [ "$n" -gt 0 ]; then
                printf '%s holds %s %s time(s)\n' "$f" "$needle" "$n"
                status=1
            fi
        done
    done
    return "$status"
}

neutral_paths_held() {
    local label="$1" found
    shift
    if found=$(neutral_paths_check "$@"); then
        pass "$label: no path of the build machine's in it"
    else
        fail "$label holds the build machine's paths:"
        printf '%s\n' "$found" | sed 's/^/        /'
        return 1
    fi
}

unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
NEUTRAL_CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
NEUTRAL_RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
# Each with the separator after it, so that a longer name sharing the
# prefix is not taken for it. After this host's own, the homes of the
# containers the scripts here build in, and the registry and toolchains
# under a default home on any host, either separator: a native built
# elsewhere and checked here is held to the same rule.
NEUTRAL_NEEDLES=("$HOME/" "$ROOT/" "$NEUTRAL_CARGO_HOME/" "$NEUTRAL_RUSTUP_HOME/"
    /usr/local/cargo/ /usr/local/rustup/ /home/build/cargo/ /home/build/rustup/
    .cargo/registry/ '.cargo\registry\' .rustup/toolchains/ '.rustup\toolchains\')
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        # rustc and cl.exe see Windows paths, C:\Users\..., and a binary
        # can hold either separator.
        for p in "$HOME" "$ROOT" "$NEUTRAL_CARGO_HOME" "$NEUTRAL_RUSTUP_HOME"; do
            NEUTRAL_NEEDLES+=("$(cygpath -w "$p")\\" "$(cygpath -m "$p")/")
        done
        neutral_paths "$(cygpath -w "$NEUTRAL_CARGO_HOME")" "$(cygpath -w "$NEUTRAL_RUSTUP_HOME")" "$(cygpath -w "$ROOT")" 1
        ;;
    *)
        neutral_paths "$NEUTRAL_CARGO_HOME" "$NEUTRAL_RUSTUP_HOME" "$ROOT" 0
        # The cc crate splits CFLAGS on whitespace unless told the flags
        # are quoted the way a shell would quote them.
        case "$NEUTRAL_CARGO_HOME" in
            *[[:space:]]*)
                NEUTRAL_CFLAGS="'-ffile-prefix-map=$NEUTRAL_CARGO_HOME=/cargo'"
                CC_SHELL_ESCAPED_FLAGS=1
                export CC_SHELL_ESCAPED_FLAGS
                ;;
        esac
        ;;
esac
CFLAGS="${CFLAGS:+$CFLAGS }$NEUTRAL_CFLAGS"
export CFLAGS
