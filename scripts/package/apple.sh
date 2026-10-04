# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# The oldest macOS and iOS a packaged native is built for. Sourced, not run,
# by every script in this directory that builds for an Apple platform, so
# that a wheel, a NuGet package and the XCFramework make one promise, and
# the Swift package's `platforms:` line is written from the same two numbers.
#
# Nothing here is inherited from the machine doing the build. Left unset,
# rustc builds for its own oldest release per target, but cmake -- which
# builds libopus for every --with-opus variant -- builds for the SDK's, which
# is this Mac's own macOS or iOS version, and cargo does not rebuild a C
# dependency when the deployment target changes. So both are exported here,
# and each script builds its Apple natives in a target directory named after
# them (`apple_target_dir`), where nothing built for another minimum can be
# picked up from cache.
APPLE_MACOS_MIN="12.0"
APPLE_IOS_MIN="15.0"
MACOSX_DEPLOYMENT_TARGET="$APPLE_MACOS_MIN"
IPHONEOS_DEPLOYMENT_TARGET="$APPLE_IOS_MIN"
export MACOSX_DEPLOYMENT_TARGET IPHONEOS_DEPLOYMENT_TARGET

# `apple_target_dir DIR`: the cargo target directory under DIR that Apple
# natives for these two minimums are built in.
apple_target_dir() {
    printf '%s/apple-macos%s-ios%s' "$1" "$APPLE_MACOS_MIN" "$APPLE_IOS_MIN"
}

# `apple_min_versions FILE`: every minimum OS version a Mach-O file names,
# one per line, oldest first -- one for a linked library, one per object for
# a static archive, so a C object built for another release shows up.
apple_min_versions() {
    otool -l "$1" 2>/dev/null | awk '
        /cmd LC_BUILD_VERSION/ { build = 1; legacy = 0; next }
        /cmd LC_VERSION_MIN_/ { legacy = 1; build = 0; next }
        /cmd / { build = 0; legacy = 0 }
        build && $1 == "minos" { print $2; build = 0 }
        legacy && $1 == "version" { print $2; legacy = 0 }' \
        | sort -u -t. -k1,1n -k2,2n
}

# `apple_min_at_most FILE VERSION`: prints the newest minimum FILE names, and
# succeeds only when there is one and it is not newer than VERSION.
apple_min_at_most() {
    local newest
    newest=$(apple_min_versions "$1" | tail -1)
    printf '%s' "$newest"
    [ -n "$newest" ] || return 1
    [ "$(printf '%s\n%s\n' "$newest" "$2" | sort -t. -k1,1n -k2,2n | tail -1)" = "$2" ]
}
