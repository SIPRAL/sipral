<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# 22 — TLS, per platform

What is checked when a Sipral application talks TLS, who checks it, against
which trust anchors, and how to trust a private authority or only one — for
Linux, Windows, macOS and iOS, and Android. Every sample below was built and
run; the outputs quoted are what the runs printed, against the lab's TLS
endpoint described under "The lab's TLS endpoint".

## Who checks what

Sipral links no TLS library and never will (`01-architecture.md`, "Who owns
the sockets, the resolver and TLS"; `20-security-model.md`, "It has no TLS
of its own"). So the certificate check is always done by the platform's TLS
library, and by whoever drives it:

| Connection | Opened by | Certificate checked by | Checked against | Where |
|---|---|---|---|---|
| SIP over TLS, C | the application, through the C ABI: `transport` `SIPRAL_TRANSPORT_TLS`, `sipral_stack_transport_bind`, bytes in with `sipral_stack_receive_stream`, out with `sipral_stack_poll_transmit` | the application's TLS library, and the application's own RFC 5922 check | the SIP domain the user configured | `crates/sipral-ffi/src/transport.rs`; the stack only frames the bytes (`crates/sipral-core/src/msg/framer.rs`) |
| SIP over TLS, Python | the binding, `Stack(signalling=Transport.TLS)` | Python's `ssl` (OpenSSL) | `tls_server_name`, or the host part of `signalling_server` | `bindings/python/sipral/signalling.py`, `bindings/python/sipral/stack.py` |
| SIP over TLS, .NET | the binding, `new SipralStack(signalling: SipralTransport.Tls)` | `SslStream` | `tlsServerName`, or the host part of `signallingServer` | `bindings/dotnet/Sipral/SipralSignalling.cs` |
| SIP over TLS, Kotlin | the binding, `SipralClient.open(signalling = SipralTransport.TLS)` | `SSLSocket`'s trust managers; the name by the HTTPS rules, in the binding | `tlsServerName`, or the host part of `signallingServer` | `bindings/kotlin/.../idiomatic/SipralSignalling.kt` |
| SIP over TLS, Swift | the binding, on Apple platforms only, `SipralStack(signalling: .tls)` | Network.framework and `SecTrust` with the SSL policy | `tlsServerName`, or the host part of `signallingServer` | `bindings/swift/Sources/Sipral/Signalling.swift` |
| TURN over TLS, Python | the binding, on `SIPRAL_EVENT_KIND_TURN_STREAM` | Python's `ssl` (OpenSSL) | `turn_server_name`, or the host part of `turn_server` | `bindings/python/sipral/stack.py`, `_open_turn_stream` |
| TURN over TLS, .NET | the binding | `SslStream` | `turnServerName`, or the host part of `turnServer` | `bindings/dotnet/Sipral/SipralStack.cs`, `OpenTurnStream` |
| TURN over TLS, Kotlin | the binding | `SSLSocket`, endpoint identification `HTTPS` | `SipralTurnServer.serverName`, or the host part of `address` | `bindings/kotlin/sipral/src/main/kotlin/org/sipral/idiomatic/SipralClient.kt`, `openTurnStream` |
| TURN over TLS, Swift | the binding, on Apple platforms only | Network.framework and `SecTrust` | `TurnServer.serverName`, or the host part of `address` | `bindings/swift/Sources/Sipral/TurnConnection.swift` |
| TURN over TLS, C | the application | the application's TLS library | the name the application chose | `crates/sipral-ffi/src/nat.rs`, `sipral_stack_turn_connected` |

Two things follow from the table that are easy to miss:

- **Each idiomatic layer signals over UDP, TCP or TLS.** Over the last two
  a stack keeps one connection to the server it was given, carries every
  account and call on it, reads the server's own requests off it, and
  connects again when it is lost (see "SIP over TLS in the four layers"
  below). The name those layers check is the one HTTPS checks, as the
  platform applies it; an application that wants RFC 5922's reading, below,
  drives the stream itself through the C ABI, the way the C sample does.
- **Nothing in any binding turns checking off.** None of them takes a
  "verify: false"; a certificate that fails is a relay that is not made.
  With roots handed over, those roots replace the platform's rather than
  joining them (`20-security-model.md`, "A TURN server reached over TLS is
  checked by the application's TLS").

## What the platform checks, and what RFC 5922 adds

Every platform library above checks the chain up to a trusted anchor, the
validity dates, and the host name by the rules HTTPS uses: a `dNSName` in
`subjectAltName` equal to the name, a wildcard allowed in its leftmost
label, an IP-address entry when the name is an address. Apple's TLS also
wants `serverAuth` among the certificate's extended key usages
(`scripts/lab.sh`, `turn_certificate`, which adds it for that reason).

For a TURN server that is the right check, and it is the one the bindings
apply. For a SIP server it is not quite: RFC 5922 changes how a SIP
domain's certificate is read.

- **Which identities count** (§7.1). A `sip:` URI in `subjectAltName` with
  no user part names a SIP domain. A `dNSName` counts only when there is no
  such URI. The subject's CN counts only when there is no `subjectAltName`
  at all.
- **How they compare** (§7.2). As whole DNS names, case-insensitively. No
  suffix matching, and **no wildcard**: `*.example.com` matches only the
  literal `*.example.com`.
- **Against what** (§7.3). The domain of the SIP URI the user configured —
  `example.com` in `sips:alice@example.com` — not the host an SRV lookup
  turned it into. A client that finds no match closes the connection at
  once.

So a platform check alone accepts `*.lab.sipral.test` for
`turn.lab.sipral.test` — Python's default context did exactly that when this
document was checked — and never looks at a `sip:` URI. An application that
wants RFC 5922 behaviour runs its own check after the handshake has
verified the chain. The C sample below does; the same check in C# and in
Kotlin is further down, and all three refused the wildcard certificate and
took the `sip:` URI one when they were run.

## A PBX's own certificate, pinned

A PBX on a LAN usually serves a certificate it signed itself, for
`localhost` or its factory hostname, and no authority an application ships
vouches for it. Rather than turn checking off, an account can pin that one
certificate by the SHA-256 fingerprint of its DER encoding
(`Account::tls_pin`, `sipral::CertificatePin`): the value `openssl x509
-noout -fingerprint -sha256` prints, taken with or without colons, or after
`sha-256 ` or `SHA256=`. The application's certificate verifier hands the leaf
certificate the server presented to `CertificatePin::check`, which compares
the digests in constant time; `crates/sipral/examples/tls.rs` does it as a
`rustls` verifier (`--pin`). Over the C ABI the pin is
`sipral_account_config_t::tls_pin_sha256` and the check
`sipral_account_check_certificate`, which answers
`SIPRAL_STATUS_CERTIFICATE_REFUSED` for another certificate.

With a pin, the fingerprint is the whole verdict:

- **Chain and trust anchors** are not consulted. The pin replaces them.
- **The host name is not checked.** The pin names every byte of one
  certificate, its public key included, which a matching name cannot add
  to, and the name in a PBX's own certificate is the part most often wrong.
  Connections without a pin keep RFC 5922's rules above.
- **An expired certificate that matches is accepted**, and
  `PinnedCertificate::expired` says so for the application to warn. Its
  dates were written by the holder of the pinned key, so they protect
  against nobody else, and a PBX whose year-long self-signed certificate
  lapsed would otherwise go silent mid-deployment. To stop trusting it, pin
  the new certificate.
- **The handshake signature is still verified**: a matching certificate
  proves nothing until the server has shown it holds the key.

## The lab's TLS endpoint

The lab has two kinds of TLS listener. Asterisk's, for SIP, are described
under "SIP over TLS in the four layers" below (`scripts/lab.sh tls`). The
other is coturn's, on 5349, in `scripts/lab.sh turn`
(`interop/turn/compose.override.yaml`). Its certificate is made for each run
by `turn_certificate` in `scripts/lab.sh`: self-signed, P-256, for
`turn.lab.sipral.test` as both CN and `subjectAltName`, with `serverAuth`.
Self-signed means the certificate is its own authority, so trusting "the
lab's CA" and pinning it are the same act: hand the file over as the only
root.

The step runs the TURN-over-TLS call through the Python, .NET and Kotlin
layers with that certificate as the only root (`SIPRAL_TURN_CA`) and the
name as `SIPRAL_TURN_NAME`. To get the same endpoint without the rest of the
lab — which is how the samples here were run, on the lab VM — make the
certificate the way the step does and start coturn with the step's own
flags:

```text
$ mkdir -p certs && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -nodes -days 1 -subj "/CN=turn.lab.sipral.test" \
    -addext "subjectAltName=DNS:turn.lab.sipral.test" -addext extendedKeyUsage=serverAuth \
    -keyout certs/turn.key -out certs/turn.pem
$ chmod 755 certs && chmod 644 certs/turn.key certs/turn.pem
$ TURN_PASSWORD=$(openssl rand -hex 12)
$ docker run -d --name turn-tls --network host -v "$PWD/certs:/certs:ro" \
    coturn/coturn:4.18.0-debian -n --listening-port=3478 --tls-listening-port=5349 \
    --cert=/certs/turn.pem --pkey=/certs/turn.key --lt-cred-mech \
    --realm=lab.sipral.test --user="sipral:$TURN_PASSWORD" \
    --min-port=49152 --max-port=49251 --log-file=stdout --simple-log
```

In the commands below `LAB` is that host's address, reachable from the
machine running the sample, and `turn.pem` is the certificate copied from
it. The runs quoted used this container on the lab VM, on ports of its own
beside the lab's, and a TURN user and password drawn for the run. The samples take the name to check as an argument, since the lab
certificate names `turn.lab.sipral.test` and the server is reached by
address; that is also why a sample given no name would fail — the host part
of an address is checked against the certificate as an IP address.

## Linux

**Trust anchors by default.** OpenSSL's default verify locations, which a
distribution points at its own bundle (`/etc/ssl/certs` on Debian and
Ubuntu, `/etc/pki/tls/certs` on Fedora), overridable per process with
`SSL_CERT_FILE` and `SSL_CERT_DIR`. Python's `ssl.create_default_context()`
reads the same.

**Adding a private CA** for every program on the machine: copy it, in PEM
with a `.crt` name, to `/usr/local/share/ca-certificates/` and run
`update-ca-certificates` (Debian, Ubuntu), or to
`/etc/pki/ca-trust/source/anchors/` and run `update-ca-trust` (Fedora,
RHEL). For one program only, load it beside the defaults:
`SSL_CTX_set_default_verify_paths` and then `SSL_CTX_load_verify_locations`
in C; `context = ssl.create_default_context()` and then
`context.load_verify_locations(cafile=...)` in Python.

**Pinning one authority:** load that file and nothing else —
`SSL_CTX_load_verify_locations` without the default paths, or
`ssl.create_default_context(cafile=...)`, which loads only the file when one
is given.

### SIP over TLS, in C with OpenSSL

A complete client: it connects, lets OpenSSL verify the chain, applies RFC
5922 to the certificate, and only then creates a stack speaking
`SIPRAL_TRANSPORT_TLS` over the connection and registers through it. The
same file builds on macOS against Homebrew's OpenSSL, with
`-I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib`
added, which is where the runs below were made; on Debian 13 it was
compiled with the flags below and not run.

```c
/* SIP over TLS through the C ABI, with OpenSSL doing the TLS and the
 * application doing RFC 5922's identity check.
 *
 *   sip_tls <address> <port> <sip-domain> [ca-file]
 *
 * With ca-file, that file's authorities are the only ones trusted;
 * without it, the platform's store as OpenSSL finds it. */
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "sipral.h"

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int entropy(uint8_t *out, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    ssize_t got = read(fd, out, len);
    close(fd);
    return got == (ssize_t)len;
}

/* RFC 5922 section 7.2: the whole name, case-insensitively, and nothing
 * that looks like a wildcard or a suffix. */
static int same_domain(const char *name, size_t name_len, const char *domain)
{
    return name_len == strlen(domain) && strncasecmp(name, domain, name_len) == 0;
}

/* RFC 5922 section 7.1: a "sip:" URI with no user part in subjectAltName
 * names a SIP domain; a dNSName counts only when there is no such URI; the
 * subject's CN only when there is no subjectAltName at all. */
static int rfc5922_identity(X509 *certificate, const char *domain, const char **why)
{
    GENERAL_NAMES *names = X509_get_ext_d2i(certificate, NID_subject_alt_name, NULL, NULL);
    if (names == NULL) {
        char cn[256];
        int len = X509_NAME_get_text_by_NID(X509_get_subject_name(certificate), NID_commonName,
                                            cn, sizeof cn);
        *why = "no subjectAltName, and the subject's CN is not the domain";
        return len > 0 && same_domain(cn, (size_t)len, domain);
    }
    int uri_found = 0;
    int uri_matched = 0;
    int dns_matched = 0;
    for (int i = 0; i < sk_GENERAL_NAME_num(names); i++) {
        const GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
        if (name->type == GEN_URI) {
            const char *uri = (const char *)ASN1_STRING_get0_data(name->d.uniformResourceIdentifier);
            size_t len = (size_t)ASN1_STRING_length(name->d.uniformResourceIdentifier);
            if (len > 4 && strncasecmp(uri, "sip:", 4) == 0 && memchr(uri, '@', len) == NULL) {
                uri_found = 1;
                uri_matched |= same_domain(uri + 4, len - 4, domain);
            }
        } else if (name->type == GEN_DNS) {
            const char *dns = (const char *)ASN1_STRING_get0_data(name->d.dNSName);
            size_t len = (size_t)ASN1_STRING_length(name->d.dNSName);
            dns_matched |= same_domain(dns, len, domain);
        }
    }
    GENERAL_NAMES_free(names);
    if (uri_found) {
        *why = "no sip: URI in subjectAltName names the domain";
        return uri_matched;
    }
    *why = "no dNSName in subjectAltName names the domain, and wildcards do not count";
    return dns_matched;
}

static int connect_to(const char *address, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in at = { 0 };
    at.sin_family = AF_INET;
    at.sin_port = htons((uint16_t)port);
    if (fd < 0 || inet_pton(AF_INET, address, &at.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&at, sizeof at) != 0) {
        return -1;
    }
    return fd;
}

/* The TLS connection, checked twice: the chain by OpenSSL against the
 * trusted authorities, then the name by RFC 5922. NULL, with the reason
 * printed, when either says no. */
static SSL *secure(SSL_CTX *context, int fd, const char *domain)
{
    SSL *tls = SSL_new(context);
    SSL_set_fd(tls, fd);
    SSL_set_tlsext_host_name(tls, domain);
    if (SSL_connect(tls) != 1) {
        long verdict = SSL_get_verify_result(tls);
        if (verdict != X509_V_OK) {
            fprintf(stderr, "TLS: certificate refused: %s\n",
                    X509_verify_cert_error_string(verdict));
        } else {
            fprintf(stderr, "TLS: handshake failed: %s\n",
                    ERR_reason_error_string(ERR_get_error()));
        }
        SSL_free(tls);
        return NULL;
    }
    X509 *certificate = SSL_get1_peer_certificate(tls);
    const char *why = "no certificate";
    int matched = certificate != NULL && rfc5922_identity(certificate, domain, &why);
    X509_free(certificate);
    if (!matched) {
        fprintf(stderr, "TLS: certificate is not for %s: %s\n", domain, why);
        SSL_free(tls);
        return NULL;
    }
    return tls;
}

struct line {
    int registration_state;
    int registration_failure;
    int status_code;
    int settled;
};

static void on_event(const sipral_event_t *event, void *user_data)
{
    struct line *line = user_data;
    if (event->kind != SIPRAL_EVENT_KIND_REGISTRATION_CHANGED) {
        return;
    }
    line->registration_state = (int)event->payload.registration.state;
    line->registration_failure = (int)event->payload.registration.failure;
    line->status_code = (int)event->payload.registration.status_code;
    printf("registration: state %d, failure %d, status %d\n", line->registration_state,
           line->registration_failure, line->status_code);
    if (line->registration_state == SIPRAL_REGISTRATION_STATE_REGISTERED ||
        line->registration_state == SIPRAL_REGISTRATION_STATE_FAILED ||
        line->status_code >= 400) {
        line->settled = 1;
    }
}

static void address_of(int fd, int local, char *out, size_t capacity)
{
    struct sockaddr_in at;
    socklen_t len = sizeof at;
    char host[INET_ADDRSTRLEN];
    if (local) {
        getsockname(fd, (struct sockaddr *)&at, &len);
    } else {
        getpeername(fd, (struct sockaddr *)&at, &len);
    }
    inet_ntop(AF_INET, &at.sin_addr, host, sizeof host);
    snprintf(out, capacity, "%s:%u", host, ntohs(at.sin_port));
}

static void say_last_error(const char *what)
{
    char why[256];
    size_t len = 0;
    sipral_last_error_message(why, sizeof why, &len);
    fprintf(stderr, "%s: %.*s\n", what, (int)len, why);
}

/* Write everything the stack has queued onto the TLS connection. */
static int flush(sipral_handle_t stack, SSL *tls)
{
    static uint8_t out[SIPRAL_MESSAGE_BYTES];
    char destination[128];
    char source[128];
    for (;;) {
        sipral_transmit_t transmit;
        memset(&transmit, 0, sizeof transmit);
        transmit.size = sizeof transmit;
        transmit.data = out;
        transmit.capacity = sizeof out;
        transmit.destination = destination;
        transmit.destination_capacity = sizeof destination;
        transmit.source = source;
        transmit.source_capacity = sizeof source;
        if (sipral_stack_poll_transmit(stack, &transmit) != SIPRAL_STATUS_OK) {
            return 0;
        }
        if (transmit.len == 0) {
            return 1;
        }
        int wrote;
        while ((wrote = SSL_write(tls, out, (int)transmit.len)) <= 0 &&
               SSL_get_error(tls, wrote) == SSL_ERROR_WANT_WRITE) {
            usleep(1000);
        }
        if (wrote <= 0) {
            sipral_stack_transport_failed(stack, SIPRAL_TRANSPORT_MAIN,
                                          SIPRAL_TRANSPORT_ERROR_CONNECTION_RESET, now_ms());
            return 0;
        }
    }
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <address> <port> <sip-domain> [ca-file]\n", argv[0]);
        return 64;
    }
    const char *domain = argv[3];
    setvbuf(stdout, NULL, _IOLBF, 0);
    SSL_CTX *context = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION);
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
    int trusted = argc > 4 ? SSL_CTX_load_verify_locations(context, argv[4], NULL)
                           : SSL_CTX_set_default_verify_paths(context);
    if (trusted != 1) {
        fprintf(stderr, "TLS: no trust anchors loaded\n");
        return 1;
    }

    int fd = connect_to(argv[1], atoi(argv[2]));
    if (fd < 0) {
        fprintf(stderr, "TCP: no connection to %s:%s\n", argv[1], argv[2]);
        return 1;
    }
    SSL *tls = secure(context, fd, domain);
    if (tls == NULL) {
        close(fd);
        return 2;
    }
    printf("TLS: %s, certificate accepted for %s\n", SSL_get_version(tls), domain);
    /* from here on a read never waits: a TLS 1.3 session ticket makes the
     * socket readable with no application data behind it */
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

    char local[64];
    char remote[64];
    address_of(fd, 1, local, sizeof local);
    address_of(fd, 0, remote, sizeof remote);

    struct line line = { 0, 0, 0, 0 };
    uint8_t seed[32];
    uint8_t media_seed[32];
    if (!entropy(seed, sizeof seed) || !entropy(media_seed, sizeof media_seed)) {
        return 1;
    }
    sipral_stack_config_t config;
    memset(&config, 0, sizeof config);
    config.size = sizeof config;
    config.event_callback = on_event;
    config.event_user_data = &line;
    config.transport = SIPRAL_TRANSPORT_TLS;
    config.bind_address = local;
    config.bind_address_len = strlen(local);
    config.entropy = seed;
    config.entropy_len = sizeof seed;
    config.media_seed = media_seed;
    config.media_seed_len = sizeof media_seed;
    sipral_handle_t stack = SIPRAL_HANDLE_NONE;
    if (sipral_stack_create(&config, &stack) != SIPRAL_STATUS_OK ||
        sipral_stack_transport_bind(stack, SIPRAL_TRANSPORT_MAIN, 0, local, strlen(local), remote,
                                    strlen(remote), now_ms(), NULL) != SIPRAL_STATUS_OK) {
        say_last_error("stack");
        return 1;
    }

    char aor[256];
    char registrar[256];
    char contact[256];
    snprintf(aor, sizeof aor, "sips:sipral-example@%s", domain);
    snprintf(registrar, sizeof registrar, "sips:%s", domain);
    snprintf(contact, sizeof contact, "sips:sipral-example@%s;transport=tls", local);
    sipral_account_config_t account;
    memset(&account, 0, sizeof account);
    account.size = sizeof account;
    account.aor = aor;
    account.aor_len = strlen(aor);
    account.registrar = registrar;
    account.registrar_len = strlen(registrar);
    account.contact = contact;
    account.contact_len = strlen(contact);
    account.registrar_address = remote;
    account.registrar_address_len = strlen(remote);
    sipral_handle_t handle = SIPRAL_HANDLE_NONE;
    if (sipral_account_add(stack, &account, &handle) != SIPRAL_STATUS_OK ||
        sipral_account_register(stack, handle, now_ms()) != SIPRAL_STATUS_OK) {
        say_last_error("account");
        return 1;
    }

    uint64_t deadline = now_ms() + 40000;
    while (!line.settled && now_ms() < deadline) {
        sipral_poll_result_t polled;
        memset(&polled, 0, sizeof polled);
        polled.size = sizeof polled;
        sipral_stack_poll(stack, now_ms(), &polled);
        if (!flush(stack, tls)) {
            sipral_stack_poll(stack, now_ms(), NULL);
            break;
        }
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(fd, &readable);
        uint64_t wait = polled.has_deadline && polled.next_poll_in_ms < 100
                            ? polled.next_poll_in_ms : 100;
        struct timeval tv = { 0, (int)(wait * 1000) };
        if (SSL_pending(tls) == 0 && select(fd + 1, &readable, NULL, NULL, &tv) <= 0) {
            continue;
        }
        uint8_t in[4096];
        int got = SSL_read(tls, in, sizeof in);
        if (got > 0) {
            if (sipral_stack_receive_stream(stack, SIPRAL_TRANSPORT_MAIN, in, (size_t)got,
                                            now_ms()) != SIPRAL_STATUS_OK) {
                say_last_error("stream");
                break;
            }
        } else if (SSL_get_error(tls, got) != SSL_ERROR_WANT_READ) {
            /* an orderly close_notify is a close; anything else, a reset */
            if (SSL_get_error(tls, got) == SSL_ERROR_ZERO_RETURN) {
                printf("TLS: the server closed the connection\n");
                sipral_stack_stream_closed(stack, SIPRAL_TRANSPORT_MAIN, now_ms());
            } else {
                printf("TLS: the connection broke\n");
                sipral_stack_transport_failed(stack, SIPRAL_TRANSPORT_MAIN,
                                              SIPRAL_TRANSPORT_ERROR_CONNECTION_RESET, now_ms());
            }
            sipral_stack_poll(stack, now_ms(), NULL);
            break;
        }
    }

    sipral_stack_destroy(stack);
    SSL_shutdown(tls);
    SSL_free(tls);
    close(fd);
    SSL_CTX_free(context);
    return line.registration_state == SIPRAL_REGISTRATION_STATE_REGISTERED ? 0 : 3;
}
```

```text
$ sudo apt install libssl-dev        # Debian, Ubuntu; openssl-devel on Fedora
$ cc -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror -Ibindings/c/include sip_tls.c \
    -Ltarget/debug -lsipral_ffi -Wl,-rpath,"$PWD/target/debug" -lssl -lcrypto -o sip_tls
```

What it printed, run against a local registrar that answers REGISTER over
TLS with each certificate it names, and against the lab's endpoint:

| Server's certificate | Run as | Printed |
|---|---|---|
| the lab's, trusted | `sip_tls 127.0.0.1 25061 turn.lab.sipral.test turn.pem` | `TLS: TLSv1.3, certificate accepted for turn.lab.sipral.test`, then `registration: state 2` and `state 3` (registered), exit 0 |
| the lab's, platform trust only | `sip_tls 127.0.0.1 25061 turn.lab.sipral.test` | `TLS: certificate refused: self-signed certificate`, exit 2; the server logged `tlsv1 alert unknown ca` |
| the lab's, another name | `sip_tls 127.0.0.1 25061 other.lab.sipral.test turn.pem` | `TLS: certificate is not for other.lab.sipral.test: no dNSName in subjectAltName names the domain, and wildcards do not count`, exit 2 |
| `DNS:*.lab.sipral.test` | `sip_tls 127.0.0.1 25061 turn.lab.sipral.test wild.pem` | the same refusal, for the wildcard |
| `URI:sip:lab.sipral.test, DNS:pbx.lab.sipral.test` | `... lab.sipral.test uri.pem` | accepted, registered |
| the same | `... pbx.lab.sipral.test uri.pem` | `certificate is not for pbx.lab.sipral.test: no sip: URI in subjectAltName names the domain` — the `dNSName` does not count once a `sip:` URI is there |
| the lab's, while trusting only another authority | `... turn.lab.sipral.test other-ca.pem` | `TLS: certificate refused: self-signed certificate`, exit 2 |
| the lab's coturn on 5349, trusted | `sip_tls $LAB 5349 turn.lab.sipral.test turn.pem` | accepted; coturn does not speak SIP, so the REGISTER goes unanswered and after 64·T1 the stack says `state 5, failure 3` (retrying, unreachable) |
| the lab's coturn, by its address | `sip_tls $LAB 5349 $LAB turn.pem` | `certificate is not for <address>` |
| a registrar that closes the connection after reading the REGISTER | trusted | `TLS: the connection broke`, then `registration: state 5, failure 3` |

When the check refuses, no stack is created: nothing reaches the wire in
the clear and nothing about the connection is told to Sipral. Once a stack
is running over a connection, the connection's end is told to it —
`sipral_stack_stream_closed` for a TLS close, `sipral_stack_transport_failed`
for anything else — and every transaction on it fails at the next poll,
which for a registration is `SIPRAL_REGISTRATION_STATE_RETRYING` with
`SIPRAL_REGISTRATION_FAILURE_UNREACHABLE`.

### TURN over TLS, in Python

```python
"""A relay over TLS on the lab's TURN server, through the Python layer.

turn_tls.py <server-address> <tls-port> <stun-port> <server-name> <user> <password> [ca-file]
"""

import asyncio
import socket
import ssl
import sys

from sipral import Stack
from sipral._sipral_cffi import lib
from sipral.enums import AudioMode, Nat, NatRelay, Transport


def route_to(host: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((host, 9))
        return probe.getsockname()[0]


async def main() -> None:
    server, tls_port, stun_port, name, user, password = sys.argv[1:7]
    ca_file = sys.argv[7] if len(sys.argv) > 7 else None
    here = route_to(server)
    loop = asyncio.get_running_loop()
    with Stack(bind_host=here, loop=loop, audio=AudioMode.APPLICATION) as peer, Stack(
        bind_host=here,
        loop=loop,
        audio=AudioMode.APPLICATION,
        nat=Nat.STUN,
        stun_server=f"{server}:{stun_port}",
        turn_server=f"{server}:{tls_port}",
        turn_username=user,
        turn_password=password,
        turn_transport=Transport.TLS,
        turn_server_name=name,
        # only this authority; None trusts the platform's store instead
        turn_tls_context=ssl.create_default_context(cafile=ca_file) if ca_file else None,
    ) as stack:
        account = stack.add_account(
            f"sip:caller@{here}",
            registrar_address=peer.bind_address,
            contact=f"sip:caller@{stack.bind_address}",
        )
        # the media socket is mapped and relayed before the INVITE leaves
        call = stack.place_call(account, f"sip:callee@{peer.bind_address}", media_host=here)
        while True:
            event = await stack.events.get()
            if event.kind == lib.SIPRAL_EVENT_KIND_NAT_RELAY:
                relay = event.fields
                if relay["outcome"] == NatRelay.ALLOCATED:
                    print("relay allocated at", relay["relayed"])
                else:
                    print("no relay:", relay["reason"], "code", relay["code"])
                break
        call.hangup()
        call.close()


asyncio.run(main())
```

```text
$ PYTHONPATH=bindings/python SIPRAL_LIBRARY=target/debug \
    python3 turn_tls.py $LAB 5349 3478 turn.lab.sipral.test sipral "$TURN_PASSWORD" turn.pem
relay allocated at <LAB>:42016
$ ... turn_tls.py $LAB 5349 3478 turn.lab.sipral.test sipral "$TURN_PASSWORD"
no relay: the connection to the server closed code 0
$ ... turn_tls.py $LAB 5349 3478 other.lab.sipral.test sipral "$TURN_PASSWORD" turn.pem
no relay: the connection to the server closed code 0
$ ... turn_tls.py $LAB 5349 3478 turn.lab.sipral.test sipral wrong turn.pem
no relay: the server refused the credentials code 401
```

## Windows

**Trust anchors by default.** `SslStream` on Windows is SChannel over the
Windows certificate store: the machine's and the user's Trusted Root
Certification Authorities.

**Adding a private CA:** into the machine store, from an elevated prompt,
`certutil -addstore Root lab-ca.cer`, or in PowerShell
`Import-Certificate -FilePath lab-ca.cer -CertStoreLocation Cert:\LocalMachine\Root`;
`Cert:\CurrentUser\Root` for one user. A Python application on Windows gets
the same store: `ssl.create_default_context()` loads the system's root
store there.

**Pinning one authority:** `turnTrustedCertificates` — the binding then
builds the chain with `X509ChainTrustMode.CustomRootTrust` over those roots
alone (`SipralStack.cs`, `OpenTurnStream`). For SIP over TLS, the same
`SslClientAuthenticationOptions.CertificateChainPolicy` on the application's
own `SslStream`, followed by the RFC 5922 check:

```csharp
using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

static class Rfc5922
{
    /// <summary>RFC 5922 §7.1-7.2: a "sip:" URI with no user part names the
    /// domain; a dNSName only when no such URI is present; the CN only when
    /// there is no subjectAltName; whole names, no wildcards.</summary>
    public static bool Names(X509Certificate2 certificate, string domain)
    {
        var san = certificate.Extensions["2.5.29.17"];
        if (san is null)
        {
            var cn = certificate.GetNameInfo(X509NameType.DnsName, forIssuer: false);
            return string.Equals(cn, domain, StringComparison.OrdinalIgnoreCase);
        }
        var uris = new List<string>();
        var dns = new List<string>();
        var names = new AsnReader(san.RawData, AsnEncodingRules.DER).ReadSequence();
        while (names.HasData)
        {
            var tag = names.PeekTag();
            if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 6)
            {
                var uri = names.ReadCharacterString(UniversalTagNumber.IA5String, tag);
                if (uri.StartsWith("sip:", StringComparison.OrdinalIgnoreCase) && !uri.Contains('@'))
                {
                    uris.Add(uri[4..]);
                }
            }
            else if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 2)
            {
                dns.Add(names.ReadCharacterString(UniversalTagNumber.IA5String, tag));
            }
            else
            {
                names.ReadEncodedValue();
            }
        }
        var candidates = uris.Count > 0 ? uris : dns;
        return candidates.Any(name => string.Equals(name, domain, StringComparison.OrdinalIgnoreCase));
    }
}
```

Run over the three certificates of the Linux table, it answered `True` for
`turn.lab.sipral.test` on the lab's certificate and `False` for another
name; `False` for `turn.lab.sipral.test` on the wildcard certificate and
`True` only for the literal `*.lab.sipral.test`; `True` for
`lab.sipral.test` and `False` for `pbx.lab.sipral.test` on the `sip:` URI
certificate.

### TURN over TLS, in C#

```csharp
// args: <server> <tls-port> <stun-port> <server-name> <user> <password> [ca-file]
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Sipral;

var (server, tlsPort, stunPort, name, user, password) = (args[0], args[1], args[2], args[3], args[4], args[5]);
string here;
using (var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
{
    probe.Connect(IPAddress.Parse(server), 9);
    here = ((IPEndPoint)probe.LocalEndPoint!).Address.ToString();
}

// the only authorities trusted for this server; null trusts the platform's store
X509Certificate2Collection? trusted = null;
if (args.Length > 6)
{
    trusted = new X509Certificate2Collection();
    trusted.ImportFromPemFile(args[6]);
}

using var peer = new SipralStack(bindHost: here, audio: SipralAudio.Application);
using var stack = new SipralStack(
    bindHost: here,
    audio: SipralAudio.Application,
    nat: SipralNat.Stun,
    stunServer: $"{server}:{stunPort}",
    turnServer: $"{server}:{tlsPort}",
    turnUsername: user,
    turnPassword: password,
    turnTransport: SipralTransport.Tls,
    turnServerName: name,
    turnTrustedCertificates: trusted);

var account = stack.AddAccount($"sip:caller@{here}", registrarAddress: peer.BindAddress);
using var call = stack.PlaceCall(account, $"sip:callee@{peer.BindAddress}", mediaHost: here);
using var patience = new CancellationTokenSource(TimeSpan.FromSeconds(20));
await foreach (var e in stack.Events.WithCancellation(patience.Token))
{
    if (e.Relay is { } relay)
    {
        Console.WriteLine(relay.Outcome == SipralNatRelay.Allocated
            ? $"relay allocated at {relay.Relayed}"
            : $"no relay: {relay.Reason} (code {relay.Code})");
        break;
    }
}
call.Hangup();
```

```text
$ dotnet run -- $LAB 5349 3478 turn.lab.sipral.test sipral "$TURN_PASSWORD" turn.pem
relay allocated at <LAB>:42014
$ dotnet run -- $LAB 5349 3478 turn.lab.sipral.test sipral "$TURN_PASSWORD"
no relay: the connection to the server closed (code 0)
$ dotnet run -- $LAB 5349 3478 other.lab.sipral.test sipral "$TURN_PASSWORD" turn.pem
no relay: the connection to the server closed (code 0)
```

These runs were on macOS (.NET 10, the project rolled forward from
`net8.0`), where `SslStream` sits on Apple's TLS rather than SChannel; the
code and its outcome are the same, and only the store the default trust
reads differs.

## macOS and iOS

**Trust anchors by default.** The system's roots, plus any root the user or
an administrator marked as trusted: in the keychain on macOS, through an
installed configuration profile on iOS.

**Adding a private CA:** on macOS,
`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain lab-ca.pem`.
On iOS, install it in a configuration profile, then turn on full trust for
it under Settings, General, About, Certificate Trust Settings. The
certificate must list `serverAuth` among its extended key usages, or
Apple's TLS refuses it before anything else is checked.

**Pinning one authority:** `TurnServer.trustedCertificates`, as DER — the
binding then evaluates the chain against those anchors only
(`SecTrustSetAnchorCertificatesOnly`), with an SSL policy for the name
(`TurnConnection.swift`). For SIP over TLS, the same verify block on the
application's own `NWProtocolTLS.Options`.

**RFC 5922 on Apple platforms** needs the `subjectAltName` entries, and the
Security framework has no public call that returns them on iOS. An
application that must apply §7.1 and §7.2 there parses the certificate's DER
(`SecCertificateCopyData`) itself; one that controls its SIP servers'
certificates gets the same protection more simply by pinning the private
authority that issues only them, so that no wildcard certificate from a
public authority is trusted in the first place.

On Linux the Swift binding has no TLS to bring and refuses a TURN server
over TLS (`TurnConnection.swift`); TCP works there.

### TURN over TLS, in Swift

```swift
// args: <local-address> <server> <tls-port> <stun-port> <server-name> <user> <password> [ca.der]
import Foundation
import Sipral

let arguments = CommandLine.arguments
let (here, server, tlsPort, stunPort, name, user, password) =
    (arguments[1], arguments[2], arguments[3], arguments[4], arguments[5], arguments[6], arguments[7])
// DER, one certificate per entry: these roots and nothing else, or the system's when empty
let anchors = arguments.count > 8 ? [[UInt8](try Data(contentsOf: URL(fileURLWithPath: arguments[8])))] : []

let turn = TurnServer(
    address: "\(server):\(tlsPort)", username: user, password: password,
    transport: .tls, serverName: name, trustedCertificates: anchors
)
let peer = try SipralStack(audio: .application, bindHost: here)
let stack = try SipralStack(audio: .application, bindHost: here, stunServer: "\(server):\(stunPort)", turn: turn)
let events = stack.events()  // asked for before the call, so the relay's event is in it
let account = try stack.addAccount(aor: "sip:caller@\(here)", registrarAddress: peer.bindAddress)
let call = try stack.placeCall(account: account, target: "sip:callee@\(peer.bindAddress)", mediaHost: here)
for await event in events {
    guard let relay = event.relayData else { continue }
    if relay.outcome == .allocated {
        print("relay allocated at \(relay.relayed ?? "")")
    } else {
        print("no relay: \(relay.reason ?? "") (code \(relay.code))")
    }
    break
}
try call.hangup()
stack.close()
peer.close()
```

```text
$ openssl x509 -in turn.pem -outform der -out turn.der
$ swift run TurnTls <this host's address> $LAB 5349 3478 turn.lab.sipral.test sipral "$TURN_PASSWORD" turn.der
relay allocated at <LAB>:42007
$ swift run TurnTls <this host's address> $LAB 5349 3478 turn.lab.sipral.test sipral "$TURN_PASSWORD"
no relay: the connection to the server closed (code 0)
$ swift run TurnTls <this host's address> $LAB 5349 3478 other.lab.sipral.test sipral "$TURN_PASSWORD" turn.der
no relay: the connection to the server closed (code 0)
```

## Android

**Trust anchors by default.** `SSLSocketFactory.getDefault()` — what the
Kotlin binding uses when `sslSocketFactory` is null — trusts the system's
CA store. Since Android 7 (API 24), a CA the user installed is not trusted
by an app that targets that level or later unless the app says so.

**Adding a private CA:** either ship it with the app and name it in the
network security configuration (`res/xml/network_security_config.xml`, a
`<trust-anchors>` with `<certificates src="@raw/lab_ca"/>`, referenced from
the manifest's `android:networkSecurityConfig`), or let user-installed
authorities in with `<certificates src="user"/>`. On a desktop JVM the store
is the runtime's `cacerts`, and `keytool -importcert -cacerts -alias lab -file lab-ca.pem`
adds one.

**Pinning one authority:** a factory over a `TrustManagerFactory` holding
that certificate alone, handed over as `sslSocketFactory`. The binding
keeps endpoint identification at `HTTPS` and sets the SNI name either way
(`SipralClient.kt`, `openTurnStream`). For SIP over TLS, the same factory on
the application's own `SSLSocket`, then the RFC 5922 check:

```kotlin
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

/** RFC 5922 §7.1-7.2: a "sip:" URI with no user part names the domain; a
 * dNSName only when no such URI is present; the CN only when there is no
 * subjectAltName; whole names, no wildcards. */
fun namesSipDomain(certificate: X509Certificate, domain: String): Boolean {
    val alternatives = certificate.subjectAlternativeNames
    if (alternatives == null) {
        val cn = certificate.subjectX500Principal.getName(X500Principal.RFC2253)
            .split(',').map { it.trim() }.firstOrNull { it.startsWith("CN=", ignoreCase = true) }?.substring(3)
        return cn.equals(domain, ignoreCase = true)
    }
    // entry[0] is the GeneralName tag: 2 dNSName, 6 uniformResourceIdentifier
    val uris = alternatives.filter { it[0] == 6 }.map { it[1] as String }
        .filter { it.startsWith("sip:", ignoreCase = true) && '@' !in it }.map { it.substring(4) }
    val dns = alternatives.filter { it[0] == 2 }.map { it[1] as String }
    return (uris.ifEmpty { dns }).any { it.equals(domain, ignoreCase = true) }
}
```

Over the three test certificates it gave the same answers as the C# check.

### TURN over TLS, in Kotlin

```kotlin
import java.io.File
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.sipral.SipralNatRelay
import org.sipral.SipralTransport
import org.sipral.idiomatic.SipralAudioMode
import org.sipral.idiomatic.SipralClient
import org.sipral.idiomatic.SipralTurnServer
import org.sipral.idiomatic.relayOf

/** Trust the authorities in one PEM file, and nothing else. */
fun trustingOnly(pem: File): SSLSocketFactory {
    val anchors = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
    pem.inputStream().use { input ->
        CertificateFactory.getInstance("X.509").generateCertificates(input).forEachIndexed { i, cert ->
            anchors.setCertificateEntry("anchor-$i", cert)
        }
    }
    val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(anchors) }
    return SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) }.socketFactory
}

// args: <server> <tls-port> <stun-port> <server-name> <user> <password> [ca-file]
fun main(args: Array<String>) = runBlocking {
    val (server, tlsPort, stunPort, name, user, password) = args
    val here = java.net.DatagramSocket().use { probe ->
        probe.connect(java.net.InetSocketAddress(server, 9))
        probe.localAddress.hostAddress
    }
    val turn = SipralTurnServer(
        address = "$server:$tlsPort",
        username = user,
        password = password,
        transport = SipralTransport.TLS,
        serverName = name,
        // null: the platform's default trust
        sslSocketFactory = args.getOrNull(6)?.let { trustingOnly(File(it)) },
    )
    val peer = SipralClient.open(audio = SipralAudioMode.Application, bindHost = here)
    val client = SipralClient.open(
        audio = SipralAudioMode.Application, bindHost = here, stunServer = "$server:$stunPort", turn = turn,
    )
    // subscribed before the call is placed: events is a hot flow, and
    // placeCall returns only once the relay has been asked for and answered
    val relay = async(start = CoroutineStart.UNDISPATCHED) { client.events.first { relayOf(it) != null }.let { relayOf(it)!! } }
    val account = client.addAccount(aor = "sip:caller@$here", registrarAddress = peer.bindAddress)
    val call = client.placeCall(account, "sip:callee@${peer.bindAddress}", mediaHost = here)
    val said = withTimeout(20_000) { relay.await() }
    if (said.outcome == SipralNatRelay.ALLOCATED.value.toLong()) {
        println("relay allocated at ${said.relayed}")
    } else {
        println("no relay: ${said.reason} (code ${said.code})")
    }
    call.hangup()
    client.close()
    peer.close()
}

private operator fun <T> Array<T>.component6(): T = this[5]
```

```text
$ java -Djava.library.path=<libsipral_jni> -cp <classes>:kotlin-stdlib.jar:kotlinx-coroutines-core-jvm.jar \
    TurnTlsKt $LAB 5349 3478 turn.lab.sipral.test sipral "$TURN_PASSWORD" turn.pem
relay allocated at <LAB>:42012
$ ... TurnTlsKt $LAB 5349 3478 turn.lab.sipral.test sipral "$TURN_PASSWORD"
no relay: the connection to the server closed (code 0)
$ ... TurnTlsKt $LAB 5349 3478 other.lab.sipral.test sipral "$TURN_PASSWORD" turn.pem
no relay: the connection to the server closed (code 0)
```

These ran on a desktop JVM, which uses the same `javax.net.ssl` classes
Android does; the Android build itself needs the Android SDK
(`scripts/package/android.sh`) and was not part of these runs.

## SIP over TLS in the four layers

A stack created with `signalling` set to TCP or TLS makes one connection to
`signalling_server` (`signallingServer`) — the registrar or the outbound
proxy — before its constructor returns, binds it as the main transport
with both ends named (`sipral_stack_transport_bind`), and from then on
writes every message the stack produces on it and hands everything read off
it to `sipral_stack_receive_stream`. Every account and every call on the
stack share it, whatever address they name: the server it reaches is the
outbound proxy. A `Contact` the layer writes carries `;transport=tls` or
`;transport=tcp`, so that the server's INVITE comes back on the same
connection. The trust is one of three, the same three this document gives
for every platform:

| | Python | .NET | Kotlin | Swift |
|---|---|---|---|---|
| The platform's authorities | `TlsTrust.platform()` (the default) | `SipralTlsTrust.Platform` (the default) | `SipralTlsTrust.Platform` (the default) | `.platform` (the default) |
| A private CA beside them | `TlsTrust.private_authority(cafile)` | `SipralTlsTrust.PrivateAuthority(cert)` | `SipralTlsTrust.PrivateAuthority(cert)` | `.privateAuthority(der)` |
| One authority and no other | `TlsTrust.only_authority(cafile)` | `SipralTlsTrust.OnlyAuthority(cert)` | `SipralTlsTrust.OnlyAuthority(cert)` | `.onlyAuthority(der)` |

None of them turns the check off, and Python's `TlsTrust.from_context`
refuses a context that does not verify the server. The name checked is
`tls_server_name` (`tlsServerName`), the host part of the server's address
when it is left out.

**When the connection fails.** The first attempt is made before the
constructor returns and every later one on a thread of the layer's own;
each one that fails is told to the stack with
`sipral_stack_transport_failed_with`, carrying the TLS library's reason and its
own sentence, and arrives as `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`. The
layer tries again one second after a loss, twice as long after each attempt
that fails, up to thirty seconds. Once connected again it points every
account without a `Contact` of its own at the new connection's address
(`sipral_account_rebind`) and registers again every account that was
registering, rather than leave it to the next back-off. A registration asked
for while the connection is down is kept for then; a call placed meanwhile
is refused with `SIPRAL_STATUS_TRANSPORT_DOWN`. A connection the server
closes is told with `sipral_stack_stream_closed` and is raised with
`SIPRAL_TRANSPORT_ERROR_CLOSED`. A connection the stack itself let go of —
one that answered keep-alive pings and then left one unanswered for ten
seconds (RFC 5626 §4.4.1), or one that carried bytes no message starts
with — arrives as `SIPRAL_EVENT_KIND_TRANSPORT_FAILED` on
`SIPRAL_TRANSPORT_MAIN` with the socket still open in the layer: the layer
closes it after that poll, says nothing more to the stack, and connects
again the same way.

How each platform's error becomes a `SipralTlsFailure`:

| | Python (`ssl`) | .NET (`SslStream`) | Kotlin (`SSLSocket`) | Swift (Network.framework) |
|---|---|---|---|---|
| `UNTRUSTED` | `SSLCertVerificationError` with any other verification code (self-signed, unknown issuer) | `RemoteCertificateChainErrors` with `UntrustedRoot`, `PartialChain` or a bad signature in the chain | the trust managers refuse the chain (PKIX path building or validation) | `SecTrustEvaluateWithError` fails with any other code |
| `NAME_MISMATCH` | verification code 62 or 64 (`X509_V_ERR_HOSTNAME_MISMATCH`, `..._IP_ADDRESS_MISMATCH`) | `RemoteCertificateNameMismatch` | the chain is trusted and no `subjectAltName` names the server | `errSecHostNameMismatch` |
| `EXPIRED` | verification code 10 or 9 (expired, not yet valid) | `NotTimeValid` or `NotTimeNested` in the chain status | `CertificateExpiredException`, `CertificateNotYetValidException` | `errSecCertificateExpired`, `errSecCertificateNotValidYet` |
| `HANDSHAKE_REFUSED` | any other `SSLError` during the handshake | any other `AuthenticationException` or `IOException` during it | any other `SSLException` during it | `NWError.tls` with no certificate verdict |
| `NONE`, refused | `ConnectionRefusedError` | `SocketError.ConnectionRefused` | `ConnectException` | `ECONNREFUSED`, or a reset before the connection was ready |

Swift has TLS only where Network.framework is: on Linux a stack asked for
`.tls` throws `.notSupported`, and `.tcp` works there on a plain socket.

**In the lab.** `scripts/lab.sh tls` gives Asterisk three TLS listeners for
the step alone (`interop/tls/`), each with a certificate a lab authority
made for the run signed: 5061 for `asterisk.lab.sipral.test`, 5062 for
`wrong.lab.sipral.test`, 5063 for the right name, expired in 2020. The
Python, Kotlin and .NET agents are each run against 5061 trusting the
platform's authorities alone, then against 5062 and 5063 trusting only the
lab's, and then against 5061 trusting only the lab's, where they register
and Asterisk calls them on that connection. What they printed, one run on
the lab VM:

```text
probe 5061: transport failed error=connection_reset tls=untrusted: CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate
probe 5062: transport failed error=connection_reset tls=name_mismatch: CERTIFICATE_VERIFY_FAILED: Hostname mismatch, certificate is not valid for 'asterisk.lab.sipral.test'.
probe 5063: transport failed error=connection_reset tls=expired: CERTIFICATE_VERIFY_FAILED: certificate has expired
```

(Python). Kotlin said `unable to find valid certification path to
requested target`, `no subjectAltName of the certificate names
asterisk.lab.sipral.test` and `NotAfter: Thu Jan 02 00:00:00 UTC 2020`;
.NET said `RemoteCertificateChainErrors; unable to get local issuer
certificate`, `RemoteCertificateNameMismatch` and
`RemoteCertificateChainErrors; certificate has expired`. Each then registered over TLS, Asterisk's
contact for it read `;transport=tls`, and the call Asterisk placed to it
was answered and carried the dialplan's `#` and audio both ways. The Swift
agent did the same over TCP.

## What the application sees when TLS fails

| What went wrong | SIP over TLS (the C sample) | SIP over TLS (every binding) | TURN over TLS (every binding) |
|---|---|---|---|
| No trusted authority behind the certificate | the TLS library's reason (OpenSSL: `self-signed certificate`, `unable to get local issuer certificate`); no stack is bound to the connection | `SIPRAL_EVENT_KIND_TRANSPORT_FAILED`, `tls` `SIPRAL_TLS_FAILURE_UNTRUSTED`, `detail` the library's sentence; tried again | `SIPRAL_EVENT_KIND_NAT_RELAY`, outcome failed, code 0, reason `the connection to the server closed`; the call goes on without a relay |
| The name does not match | the RFC 5922 check's reason | the same event, `SIPRAL_TLS_FAILURE_NAME_MISMATCH` | the same event, the same reason |
| The certificate has expired | the TLS library's reason | the same event, `SIPRAL_TLS_FAILURE_EXPIRED` | the same event, the same reason |
| The server does not speak TLS there | the TLS library's reason | the same event, `SIPRAL_TLS_FAILURE_HANDSHAKE_REFUSED` | the same event, the same reason |
| Nothing listens there | `connect` refused | the same event, `SIPRAL_TRANSPORT_ERROR_CONNECTION_REFUSED` and no TLS reason | outcome failed, code 0 |
| A wildcard certificate for a SIP domain | refused by the RFC 5922 check | accepted: the HTTPS rules | accepted: HTTPS rules apply to a TURN server |
| Trusting only another authority | as "no trusted authority" | as "no trusted authority" | as "no trusted authority" |
| The TURN credential is wrong | — | — | outcome failed, code 401, reason `the server refused the credentials` |
| The connection drops later | `sipral_stack_transport_failed` or `sipral_stack_stream_closed`; a registration goes to retrying, failure unreachable | the same, told by the binding and raised as the event with `SIPRAL_TRANSPORT_ERROR_CLOSED` or the reset; connected again and registered again | a relay still being made fails as above; a call that had one keeps the paths that need none (`sipral_stack_turn_closed`) |
| The server never answers | the transaction times out after 64·T1 (32 seconds); retrying, unreachable | the connection times out after five seconds: `SIPRAL_TRANSPORT_ERROR_TIMED_OUT`, tried again | outcome failed, code 0 |

The SIP reasons are the TLS library's, mapped as the table in "SIP over TLS
in the four layers" says and carried in
`sipral_transport_failed_event_t` (`crates/sipral-ffi/src/transport.rs`).
The TURN reasons are the stack's (`crates/sipral-nat/src/turn/client.rs`,
`TurnError`'s `Display`), carried in `sipral_nat_relay_event_t::reason`
(`crates/sipral-ffi/src/nat.rs`), and for TURN no binding passes the TLS
library's reason on yet: an untrusted certificate, a wrong name and a
refused port all arrive as "the connection to the server closed". An
application that has to tell a user which it was checks the TURN server
itself, with the same trust settings, before or after the stack does.
