#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# What an application has to ship to make calls with a stack, read inside the
# image a distribution's packages were installed into: the files named here
# (the stack's own library, and for baresip the modules a call needs) and
# every shared library they load, by `ldd`, with every symbolic link
# followed to the file it names, each file counted once.
#
# Left out, for every stack alike: the C and C++ runtimes and the dynamic
# loader (glibc's or musl's libc and the libraries glibc ships beside it --
# libm, libmvec, libdl, libpthread, librt, libresolv -- ld-linux or ld-musl,
# libgcc_s, libstdc++) and the kernel's vDSO, which an application on Linux
# finds on any machine. Everything else a library pulls in is counted, as
# installed: an application that bundles the stack bundles that.
#
# SIZE_OWN, file-name patterns separated by spaces, names the project's own
# libraries among them, which are added up apart as well: the rest is what
# the distribution built the project against (OpenSSL, codecs, video).
#
# Prints one `lib SIZE PATH` line a file, then `files=N bytes=B
# own_files=N own_bytes=B`. A file named here that does not exist fails the
# run: a size of what is missing would read as a result.
set -eu
[ "$#" -gt 0 ] || { printf 'usage: size.sh LIBRARY...\n' >&2; exit 2; }

system() {
    case "${1##*/}" in
    libc.so* | libc.musl-* | libm.so* | libmvec.so* | libdl.so* | libpthread.so* \
        | librt.so* | libresolv.so* | ld-linux* | ld-musl* | libgcc_s.so* \
        | libstdc++.so* | linux-vdso* | linux-gate*) return 0 ;;
    esac
    return 1
}

own() {
    for pattern in ${SIZE_OWN:-}; do
        # shellcheck disable=SC2254
        case "${1##*/}" in $pattern) return 0 ;; esac
    done
    return 1
}

list=$(mktemp)
for root in "$@"; do
    [ -e "$root" ] || { printf 'size.sh: %s is not there\n' "$root" >&2; exit 1; }
    readlink -f "$root" >>"$list"
    # `name => /path (0x...)`, and the loader alone as `/path (0x...)`
    ldd "$root" 2>/dev/null | awk '
        $2 == "=>" && $3 ~ /^\// { print $3; next }
        $1 ~ /^\// { print $1 }' | while read -r found; do
        system "$found" && continue
        readlink -f "$found"
    done >>"$list"
done

total=0
count=0
own_total=0
own_count=0
for file in $(sort -u "$list"); do
    system "$file" && continue
    size=$(wc -c <"$file" | tr -d ' ')
    printf 'lib %s %s\n' "$size" "$file"
    total=$((total + size))
    count=$((count + 1))
    if own "$file"; then
        own_total=$((own_total + size))
        own_count=$((own_count + 1))
    fi
done
rm -f "$list"
printf 'files=%s bytes=%s own_files=%s own_bytes=%s\n' "$count" "$total" "$own_count" "$own_total"
