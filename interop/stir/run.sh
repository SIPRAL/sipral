#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# STIR/SHAKEN between two stacks of this library (scripts/lab.sh's
# `security` step): a certificate authority made for this run and gone with
# its container, a signing certificate it issues whose TNAuthList (RFC 8226
# §9) covers the caller's number, a second authority nobody trusts with a
# certificate of its own, both chains served over HTTPS the way an `x5u` is
# -- the only scheme the verifier fetches by default -- under a TLS
# certificate made for the run too, which curl, the harness's fetch, is told
# to trust (CURL_CA_BUNDLE), and `harness-c stir` placing its three calls
# against them.
#
# Every certificate is ECDSA over P-256 with SHA-256, the one algorithm STIR
# certificates are issued with (RFC 8226 §4, RFC 5758 §3.2). The TNAuthList
# is written as the DER the RFC's module gives it: a SEQUENCE of TNEntry,
# here one `one` entry, [2] EXPLICIT IA5String, the caller's number.
set -eu

export DEBIAN_FRONTEND=noninteractive
apt-get -qq update >/dev/null 2>&1
apt-get -qq install -y openssl curl python3 >/dev/null 2>&1

work=/stir-run
mkdir -p "$work"
cd "$work"

cat >ca.cnf <<'EOF'
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = Sipral Lab STI Root
[ ca ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[ signer ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
1.3.6.1.5.5.7.1.26 = ASN1:SEQUENCE:tn_auth_list
[ tn_auth_list ]
caller = EXPLICIT:2,IA5STRING:12155551212
EOF

authority() {
    name="$1"
    openssl ecparam -name prime256v1 -genkey -noout -out "$name-root.key"
    openssl req -new -x509 -sha256 -days 2 -key "$name-root.key" -config ca.cnf \
        -extensions ca -subj "/CN=Sipral Lab STI Root $name" -out "$name-root.pem"
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$name-signer.key"
    openssl req -new -sha256 -key "$name-signer.key" -subj "/CN=Sipral Lab STI Signer $name" \
        -out "$name-signer.csr"
    openssl x509 -req -sha256 -days 1 -in "$name-signer.csr" -CA "$name-root.pem" \
        -CAkey "$name-root.key" -CAcreateserial -extfile ca.cnf -extensions signer \
        -out "$name-signer.pem"
    cat "$name-signer.pem" "$name-root.pem" >"$name-chain.pem"
}
authority trusted
authority rogue

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 -days 1 \
    -keyout https.key -out https.pem -subj "/CN=127.0.0.1" \
    -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
export CURL_CA_BUNDLE="$work/https.pem"
python3 - "$work" >/dev/null 2>&1 <<'EOF' &
import functools
import http.server
import ssl
import sys

directory = sys.argv[1]
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
server = http.server.ThreadingHTTPServer(("127.0.0.1", 8443), handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(f"{directory}/https.pem", f"{directory}/https.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
EOF
server=$!
tries=0
until curl -sf -o /dev/null https://127.0.0.1:8443/trusted-chain.pem; do
    tries=$((tries + 1))
    [ "$tries" -lt 50 ] || { echo "the certificate server never came up"; exit 1; }
    sleep 0.1
done

status=0
SIPRAL_STIR_ANCHOR="$work/trusted-root.pem" \
SIPRAL_STIR_KEY="$work/trusted-signer.key" \
SIPRAL_STIR_URL=https://127.0.0.1:8443/trusted-chain.pem \
SIPRAL_STIR_ROGUE_KEY="$work/rogue-signer.key" \
SIPRAL_STIR_ROGUE_URL=https://127.0.0.1:8443/rogue-chain.pem \
    /harness-c stir || status=$?
kill "$server" 2>/dev/null || true
exit "$status"
