#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# The sample's store build, signed on the machine that holds the key:
# scripts/package/android.sh --release builds sipral-sample[-opus]-release-
# unsigned.apk and .aab in its build image, which never sees a key; this
# signs them here.
#
#   sipral-sample[-opus]-release.apk   zipalign -P 16 (uncompressed libraries
#                                      on 16 KB boundaries), then apksigner
#                                      (v2 and v3 signatures), and verified
#   sipral-sample[-opus]-release.aab   jarsigner, as Google Play expects an
#                                      upload to be signed, and verified
#
#   scripts/package/android-sign.sh --in DIR [--out DIR]
#   scripts/package/android-sign.sh --new-test-keystore DIR
#
# The key comes from the environment, and nothing here prints a password:
#
#   SIPRAL_ANDROID_KEYSTORE           the keystore file (PKCS12 or JKS)
#   SIPRAL_ANDROID_KEYSTORE_PASSWORD  its password
#   SIPRAL_ANDROID_KEY_ALIAS          the key in it
#   SIPRAL_ANDROID_KEY_PASSWORD       the key's password; the keystore's when unset
#
# A keystore inside this repository is refused: a key in a working tree is
# one `git add -A` from being public.
#
# --new-test-keystore DIR makes a test upload key where there is none:
# DIR/upload-test.p12 and DIR/keystore.env, which sets the four variables
# above, the directory 0700 and both files 0600; it refuses a DIR that
# already holds either. A key Google Play has seen on a first upload is the
# upload key of that application from then on (Play App Signing keeps the key
# the store itself signs with), so for a listing that is to last, the owner's
# own upload key is the one to give it, and this one is for internal testing
# of a throwaway listing, or for installing directly.
#
# Needs a JDK (keytool, jarsigner; JAVA_HOME's when it is set) and the
# Android SDK's build tools (zipalign, apksigner): ANDROID_HOME, or
# ~/Library/Android/sdk, or ~/Android/Sdk; the newest build-tools there is
# used.
set -uo pipefail

cd "$(dirname "$0")/../.."
ROOT="$PWD"
[ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/keytool" ] && export PATH="$JAVA_HOME/bin:$PATH"

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }
step() { printf '\n%s\n' "$1"; }

usage() {
    printf 'usage: android-sign.sh --in DIR [--out DIR]\n' >&2
    printf '       android-sign.sh --new-test-keystore DIR\n' >&2
    exit 2
}

IN=""
OUT=""
NEW=""
while [ $# -gt 0 ]; do
    case "$1" in
        --in) IN="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --new-test-keystore) NEW="$2"; shift 2 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; usage ;;
    esac
done

inside_repo() {
    local dir
    dir="$(cd "$(dirname "$1")" 2>/dev/null && pwd -P)" || return 1
    case "$dir/" in
        "$(cd "$ROOT" && pwd -P)/"*) return 0 ;;
    esac
    return 1
}

if [ -n "$NEW" ]; then
    [ -z "$IN" ] && [ -z "$OUT" ] || usage
    mkdir -p "$NEW" && chmod 700 "$NEW" || { printf 'cannot make %s\n' "$NEW" >&2; exit 1; }
    NEW="$(cd "$NEW" && pwd -P)"
    if inside_repo "$NEW/upload-test.p12"; then
        printf '%s is inside this repository; a key belongs outside it\n' "$NEW" >&2
        exit 1
    fi
    if [ -e "$NEW/upload-test.p12" ] || [ -e "$NEW/keystore.env" ]; then
        printf '%s already holds a keystore; nothing was changed\n' "$NEW" >&2
        exit 1
    fi
    command -v keytool >/dev/null 2>&1 || { printf 'keytool not found: a JDK is needed\n' >&2; exit 1; }
    umask 077
    # 32 random bytes as base64, without the characters a shell or a
    # properties file would read as something else
    password=$(head -c 32 /dev/urandom | base64 | tr -d '/+=\n')
    if ! SIPRAL_NEW_PASSWORD="$password" keytool -genkeypair -noprompt \
        -keystore "$NEW/upload-test.p12" -storetype PKCS12 \
        -storepass:env SIPRAL_NEW_PASSWORD -keypass:env SIPRAL_NEW_PASSWORD \
        -alias upload -keyalg RSA -keysize 4096 -validity 10000 \
        -dname "CN=Sipral sample test upload key" >"$NEW/keytool.log" 2>&1; then
        printf 'keytool failed:\n' >&2
        sed 's/^/    /' "$NEW/keytool.log" >&2
        exit 1
    fi
    rm -f "$NEW/keytool.log"
    {
        printf 'export SIPRAL_ANDROID_KEYSTORE=%s\n' "$NEW/upload-test.p12"
        printf 'export SIPRAL_ANDROID_KEYSTORE_PASSWORD=%s\n' "$password"
        printf 'export SIPRAL_ANDROID_KEY_ALIAS=upload\n'
        printf 'export SIPRAL_ANDROID_KEY_PASSWORD=%s\n' "$password"
    } >"$NEW/keystore.env"
    chmod 600 "$NEW/upload-test.p12" "$NEW/keystore.env"
    fingerprint=$(SIPRAL_NEW_PASSWORD="$password" keytool -list -keystore "$NEW/upload-test.p12" \
        -storepass:env SIPRAL_NEW_PASSWORD -alias upload 2>/dev/null | sed -n 's/.*(SHA-256): //p')
    printf 'android-sign.sh: a test upload key, SHA-256 %s\n' "$fingerprint"
    printf '  %s\n  %s (source it to sign)\n' "$NEW/upload-test.p12" "$NEW/keystore.env"
    exit 0
fi

[ -n "$IN" ] || usage
IN="$(cd "$IN" && pwd)" || exit 2
OUT="${OUT:-$IN}"
mkdir -p "$OUT" && OUT="$(cd "$OUT" && pwd)"

for name in SIPRAL_ANDROID_KEYSTORE SIPRAL_ANDROID_KEYSTORE_PASSWORD SIPRAL_ANDROID_KEY_ALIAS; do
    [ -n "${!name:-}" ] || { printf '%s is not set (see the head of this script)\n' "$name" >&2; exit 2; }
done
[ -f "$SIPRAL_ANDROID_KEYSTORE" ] || { printf 'no keystore at %s\n' "$SIPRAL_ANDROID_KEYSTORE" >&2; exit 2; }
if inside_repo "$SIPRAL_ANDROID_KEYSTORE"; then
    printf 'the keystore is inside this repository; move it out before signing with it\n' >&2
    exit 2
fi
export SIPRAL_ANDROID_KEY_PASSWORD="${SIPRAL_ANDROID_KEY_PASSWORD:-$SIPRAL_ANDROID_KEYSTORE_PASSWORD}"

sdk="${ANDROID_HOME:-}"
for candidate in "$sdk" "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
    if [ -n "$candidate" ] && [ -d "$candidate/build-tools" ]; then
        sdk="$candidate"
        break
    fi
done
BUILD_TOOLS=$(ls -d "$sdk"/build-tools/* 2>/dev/null | sort -V | tail -1)
[ -x "$BUILD_TOOLS/apksigner" ] && [ -x "$BUILD_TOOLS/zipalign" ] \
    || { printf 'no build-tools with apksigner and zipalign under %s\n' "${sdk:-ANDROID_HOME}" >&2; exit 2; }
command -v jarsigner >/dev/null 2>&1 || { printf 'jarsigner not found: a JDK is needed\n' >&2; exit 2; }

signed=()
found=0
for unsigned in "$IN"/sipral-sample*-release-unsigned.apk; do
    [ -f "$unsigned" ] || continue
    found=1
    name=$(basename "$unsigned" -release-unsigned.apk)-release.apk
    step "$name"
    aligned="$OUT/.$name.aligned"
    if "$BUILD_TOOLS/zipalign" -f -P 16 4 "$unsigned" "$aligned" >/dev/null 2>&1; then
        pass "zipalign -P 16 4"
    else
        fail "zipalign -P 16 4 $unsigned"
        continue
    fi
    if "$BUILD_TOOLS/apksigner" sign --ks "$SIPRAL_ANDROID_KEYSTORE" \
        --ks-pass env:SIPRAL_ANDROID_KEYSTORE_PASSWORD --key-pass env:SIPRAL_ANDROID_KEY_PASSWORD \
        --ks-key-alias "$SIPRAL_ANDROID_KEY_ALIAS" --out "$OUT/$name" "$aligned" >"$OUT/.$name.log" 2>&1; then
        pass "apksigner sign"
    else
        fail "apksigner sign:"
        sed 's/^/        /' "$OUT/.$name.log"
        rm -f "$aligned" "$OUT/.$name.log"
        continue
    fi
    rm -f "$aligned" "$OUT/.$name.log" "$OUT/$name.idsig"
    verified=$("$BUILD_TOOLS/apksigner" verify --verbose --print-certs "$OUT/$name" 2>&1)
    if printf '%s\n' "$verified" | grep -q '^Verified using v2 scheme (APK Signature Scheme v2): true'; then
        pass "apksigner verify: $(printf '%s\n' "$verified" | grep -E '^Verified using v[0-9.]+ scheme.*: true' | sed -E 's/^Verified using (v[0-9.]+) scheme.*/\1/' | paste -sd, -) signatures"
        pass "signer SHA-256 $(printf '%s\n' "$verified" | sed -n 's/^Signer #1 certificate SHA-256 digest: //p')"
    else
        fail "apksigner verify:"
        printf '%s\n' "$verified" | sed 's/^/        /'
    fi
    if "$BUILD_TOOLS/zipalign" -c -P 16 4 "$OUT/$name" >/dev/null 2>&1; then
        pass "zipalign -c -P 16 4 after signing"
    else
        fail "the signed APK is no longer 16 KB aligned"
    fi
    signed+=("$OUT/$name")
done

for unsigned in "$IN"/sipral-sample*-release-unsigned.aab; do
    [ -f "$unsigned" ] || continue
    found=1
    name=$(basename "$unsigned" -release-unsigned.aab)-release.aab
    step "$name"
    cp "$unsigned" "$OUT/$name"
    if jarsigner -keystore "$SIPRAL_ANDROID_KEYSTORE" -storepass:env SIPRAL_ANDROID_KEYSTORE_PASSWORD \
        -keypass:env SIPRAL_ANDROID_KEY_PASSWORD -sigalg SHA256withRSA -digestalg SHA-256 \
        "$OUT/$name" "$SIPRAL_ANDROID_KEY_ALIAS" >"$OUT/.$name.log" 2>&1; then
        pass "jarsigner, SHA256withRSA"
    else
        fail "jarsigner:"
        sed 's/^/        /' "$OUT/.$name.log"
        rm -f "$OUT/$name" "$OUT/.$name.log"
        continue
    fi
    rm -f "$OUT/.$name.log"
    # Not -strict: an upload key is self-signed and its signature carries no
    # timestamp, which -strict reports as errors and Google Play expects.
    if jarsigner -verify "$OUT/$name" >"$OUT/.$name.verify" 2>&1 \
        && grep -qx 'jar verified.' "$OUT/.$name.verify"; then
        pass "jarsigner -verify: jar verified (a self-signed upload key, no timestamp)"
    else
        fail "jarsigner -verify:"
        sed 's/^/        /' "$OUT/.$name.verify"
    fi
    rm -f "$OUT/.$name.verify"
    signed+=("$OUT/$name")
done

if [ "$found" -eq 0 ]; then
    printf 'nothing to sign in %s: run scripts/package/android.sh --release first\n' "$IN" >&2
    exit 1
fi
printf '\n'
if [ "$FAIL" -eq 0 ]; then
    printf 'android-sign.sh: done\n'
    printf '  %s\n' "${signed[@]}"
    exit 0
fi
printf 'android-sign.sh: failed\n'; exit 1
