#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Sytek
#
# DTLS-SRTP between this library and OpenSSL (scripts/lab.sh's
# `dtls-interop` step), in one container, over its loopback: the Rust
# harness's `--dtls` (interop/harness/src/dtls.rs) as client and as server,
# OpenSSL's `s_server` and `s_client` with `-dtls1_2 -use_srtp` on the other
# side, each with an ECDSA P-256 certificate made for the run.
#
# A handshake that completes is judged on what RFC 5764 §4.2 makes the
# point of it: the keying material both ends export under the label
# EXTRACTOR-dtls_srtp -- client key, server key, client salt, server salt --
# has to be the same octets on both sides, and the profile the same one.
# OpenSSL prints its own with -keymatexport; the harness prints its own.
#
# Then the refusals, each of which has to be the harness's, for the reason
# given, with no keys released:
#
#   - OpenSSL's certificate is not the one the signalling named (RFC 8122
#     §5.1, RFC 5763 §5): FingerprintMismatch, as client and as server;
#   - the only SRTP profile OpenSSL will use is one the harness does not
#     accept: NoSrtpProfile, as client (OpenSSL's ServerHello leaves
#     use_srtp out, RFC 5764 §4.1.1) and as server;
#   - OpenSSL speaks DTLS 1.0 only: as client, the harness refuses its
#     ClientHello with ProtocolVersion; as server, OpenSSL finds no suite
#     it can use in DTLS 1.0 among the harness's -- AES-GCM is TLS 1.2's --
#     and says so with a handshake_failure alert (40), which the harness
#     reports as the peer's.
#
# BoringSSL is not run: its `bssl` tool has no DTLS client or server.
#
# Arguments: the harness binary. It prints one line a case and exits 1 if
# any failed.
set -u

HARNESS="${1:-/harness}"

export DEBIAN_FRONTEND=noninteractive
if ! command -v openssl >/dev/null 2>&1; then
    apt-get -qq update >/dev/null 2>&1
    apt-get -qq install -y openssl >/dev/null 2>&1
fi
printf '  note  %s\n' "$(openssl version)"

work=$(mktemp -d)
cd "$work" || exit 1

made() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -sha256 \
        -days 2 -subj "/CN=$1" -keyout "$1.key" -out "$1.pem" >/dev/null 2>&1
}
made openssl-peer
made stranger
# the a=fingerprint value of a certificate, as RFC 8122 §5 writes it
fingerprint() {
    printf 'sha-256 %s' "$(openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2)"
}
PEER_FP=$(fingerprint openssl-peer.pem)
STRANGER_FP=$(fingerprint stranger.pem)

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }

PORT=40000
# One handshake: the harness in `sipral_role`, OpenSSL in the other, the
# server started first and given a second to bind. The harness's output
# lands in sipral.out and its exit status in SIPRAL_STATUS, OpenSSL's in
# openssl.out.
#
# Both OpenSSL tools take their stdin from a sleep, since each stops at the
# end of its input: long enough for the harness to finish, and s_server
# answers one connection. -verify 1 makes each ask for the harness's
# certificate and go on when no authority signed it, which is how
# DTLS-SRTP uses certificates: the fingerprint in the signalling is the
# trust, and OpenSSL has no signalling to check it against.
pair() {
    sipral_role="$1" protocol="$2" profiles="$3" length="$4" fp="$5" sipral_profiles="$6"
    PORT=$((PORT + 1))
    common="-$protocol -use_srtp $profiles -keymatexport EXTRACTOR-dtls_srtp \
        -keymatexportlen $length -cert openssl-peer.pem -key openssl-peer.key -verify 1"
    # DTLS 1.0 has no AEAD suite, and OpenSSL's default security level
    # keeps it from offering the CBC ones it does have: lowered for it, so
    # the refusal is the harness's and not OpenSSL's own
    [ "$protocol" = dtls1 ] && common="$common -cipher DEFAULT:@SECLEVEL=0"
    if [ "$sipral_role" = client ]; then
        # shellcheck disable=SC2086
        (sleep 6 | timeout 30 openssl s_server $common -accept "127.0.0.1:$PORT" -naccept 1) \
            >openssl.out 2>&1 &
        openssl_pid=$!
        sleep 1
        timeout 30 "$HARNESS" --dtls client "127.0.0.1:$PORT" "$fp" "$sipral_profiles" \
            >sipral.out 2>&1
        SIPRAL_STATUS=$?
    else
        timeout 30 "$HARNESS" --dtls server "127.0.0.1:$PORT" "$fp" "$sipral_profiles" \
            >sipral.out 2>&1 &
        sipral_pid=$!
        sleep 1
        # -mtu: OpenSSL asks the socket for the path MTU, and where it gets
        # no answer -- macOS -- it falls back to 256 octets and fragments
        # its second ClientHello. A server answering with a stateless
        # cookie exchange reads only an unfragmented one, by design (RFC
        # 6347 Section 4.2.1; crates/sipral-dtls/src/connection/mod.rs),
        # as OpenSSL's own DTLSv1_listen does
        # shellcheck disable=SC2086
        (sleep 5 | timeout 30 openssl s_client $common -mtu 1200 -connect "127.0.0.1:$PORT") \
            >openssl.out 2>&1 &
        openssl_pid=$!
        wait "$sipral_pid"
        SIPRAL_STATUS=$?
    fi
    wait "$openssl_pid" 2>/dev/null
}

show() {
    printf '        the harness said:\n'; sed 's/^/          /' sipral.out
    printf '        OpenSSL said:\n'; sed 's/^/          /' openssl.out | tail -25
}

# A handshake both ends complete, the keying material compared.
agree() {
    label="$1" sipral_role="$2" openssl_profiles="$3" length="$4" sipral_profiles="$5" want="$6"
    pair "$sipral_role" dtls1_2 "$openssl_profiles" "$length" "$PEER_FP" "$sipral_profiles"
    ours=$(sed -n 's/^keyed \([0-9A-F]*\) \([0-9A-F]*\)$/\1 \2/p' sipral.out)
    theirs=$(sed -n 's/^ *Keying material: *\([0-9A-Fa-f]*\).*$/\1/p' openssl.out \
        | tr 'a-f' 'A-F' | head -1)
    profile=${ours%% *}
    material=${ours#* }
    if [ "$SIPRAL_STATUS" -eq 0 ] && [ "$profile" = "$want" ] && [ -n "$theirs" ] \
        && [ "$material" = "$theirs" ] && [ "${#material}" -eq $((length * 2)) ]; then
        pass "$label: $profile, $length octets exported alike by both ends"
    else
        fail "$label"
        show
    fi
}

# A handshake the harness must refuse, for the reason given, with no keys
# on its side. On OpenSSL's, only s_server's output says anything: it prints
# the exporter's output once its handshake is complete, so a line of keying
# material there would be a handshake OpenSSL finished. s_client prints it
# as soon as its own Finished is out, before the server's arrives -- and a
# harness server that refused the client's certificate never sends one --
# so for s_client the harness's own refusal is the whole answer.
refuse() {
    label="$1" sipral_role="$2" protocol="$3" openssl_profiles="$4" fp="$5" sipral_profiles="$6" want="$7"
    pair "$sipral_role" "$protocol" "$openssl_profiles" 60 "$fp" "$sipral_profiles"
    unfinished=yes
    if [ "$sipral_role" = client ] && grep -q 'Keying material: *[0-9A-Fa-f]' openssl.out; then
        unfinished=no
    fi
    if [ "$SIPRAL_STATUS" -eq 3 ] && grep -q "^refused $want\$" sipral.out \
        && ! grep -q '^keyed' sipral.out && [ "$unfinished" = yes ]; then
        pass "$label: refused, $want, no keys"
    else
        fail "$label"
        show
    fi
}

# The profiles by number (RFC 5764 §4.1.2, RFC 7714 §14.2) for the harness,
# by name for OpenSSL. Key and salt: 16 and 14 octets for the HMAC-SHA1
# profiles, 16 and 12 for AEAD_AES_128_GCM, 32 and 12 for AEAD_AES_256_GCM;
# twice each, one set a direction.
agree "Sipral client, OpenSSL server, SRTP_AES128_CM_HMAC_SHA1_80" \
    client SRTP_AES128_CM_SHA1_80 60 0001 0001
agree "OpenSSL client, Sipral server, SRTP_AES128_CM_HMAC_SHA1_80" \
    server SRTP_AES128_CM_SHA1_80 60 0001 0001
agree "Sipral client, OpenSSL server, SRTP_AES128_CM_HMAC_SHA1_32" \
    client SRTP_AES128_CM_SHA1_32 60 0002 0002
agree "Sipral client, OpenSSL server, SRTP_AEAD_AES_128_GCM" \
    client SRTP_AEAD_AES_128_GCM 56 0007,0001 0007
agree "OpenSSL client, Sipral server, SRTP_AEAD_AES_256_GCM" \
    server SRTP_AEAD_AES_256_GCM 88 0008,0007,0001 0008
# the server chooses: OpenSSL offers two, the harness prefers the second
agree "OpenSSL client offering two, Sipral server choosing its own preference" \
    server SRTP_AES128_CM_SHA1_80:SRTP_AEAD_AES_128_GCM 56 0007,0001 0007

refuse "Sipral client, OpenSSL server with a certificate the signalling did not name" \
    client dtls1_2 SRTP_AES128_CM_SHA1_80 "$STRANGER_FP" 0001 FingerprintMismatch
refuse "OpenSSL client with a certificate the signalling did not name, Sipral server" \
    server dtls1_2 SRTP_AES128_CM_SHA1_80 "$STRANGER_FP" 0001 FingerprintMismatch
refuse "Sipral client offering SHA1_80, OpenSSL server taking only AEAD_AES_128_GCM" \
    client dtls1_2 SRTP_AEAD_AES_128_GCM "$PEER_FP" 0001 NoSrtpProfile
refuse "OpenSSL client offering only SHA1_32, Sipral server taking only SHA1_80" \
    server dtls1_2 SRTP_AES128_CM_SHA1_32 "$PEER_FP" 0001 NoSrtpProfile
refuse "OpenSSL client speaking DTLS 1.0 only, Sipral server" \
    server dtls1 SRTP_AES128_CM_SHA1_80 "$PEER_FP" 0001 ProtocolVersion
refuse "Sipral client, OpenSSL server speaking DTLS 1.0 only" \
    client dtls1 SRTP_AES128_CM_SHA1_80 "$PEER_FP" 0001 "PeerAlert(AlertDescription(40))"

exit "$FAIL"
