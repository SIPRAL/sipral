/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
 * Copyright (c) 2026 Sytek
 *
 * SIP over TLS with a client certificate, through the C ABI, OpenSSL doing
 * the TLS and holding the key: scripts/lab.sh's `tls` step runs it against an
 * Asterisk transport that requires a client certificate, with one and
 * without. Every way the connection fails is told to the stack with
 * sipral_stack_transport_failed_with, and what the stack raised for it,
 * SIPRAL_EVENT_KIND_TRANSPORT_FAILED, is what this prints.
 *
 *   client-cert <address> <port> <sip-domain> <ca-file> <user> <password> [<cert-file> <key-file>]
 *
 * The server's certificate is trusted from ca-file alone and checked against
 * sip-domain by OpenSSL's host name rules. cert-file holds the client
 * certificate and any intermediates after it, key-file its private key; a
 * key in a token or a TPM is loaded the same way through an OpenSSL
 * provider, as an EVP_PKEY, and handed to SSL_CTX_use_PrivateKey.
 *
 * Prints `registered` and exits 0, or `transport failed error=<e> tls=<t>:
 * <detail>` and exits 2.
 */
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "sipral.h"

/* What the server said, and whether it asked for a certificate: written by
 * OpenSSL's callbacks on this one thread. */
static int alert_received = -1;
static int certificate_asked = 0;

struct line {
    int registered;
    int failed;
};

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

static void on_tls_info(const SSL *tls, int where, int value)
{
    (void)tls;
    /* close_notify (0) says the connection ended, not why */
    if ((where & SSL_CB_READ_ALERT) && (value & 0xff) != 0) {
        alert_received = value & 0xff;
    }
}

/* Called when the server's CertificateRequest arrives, whether or not a
 * certificate was loaded. */
static int on_certificate_request(SSL *tls, void *unused)
{
    (void)tls;
    (void)unused;
    certificate_asked = 1;
    return 1;
}

/* docs/22-tls.md, "A client certificate": what the server's alert says about
 * this end's certificate, SIPRAL_TLS_FAILURE_NONE when it says nothing. */
static sipral_tls_failure_t client_refusal(int presented)
{
    int alert = alert_received;
    int about_certificate = alert == 42 || alert == 43 || alert == 44 || alert == 46 || alert == 48 ||
                            alert == 49 || alert == 116;
    if (presented) {
        if (alert == 45) {
            return SIPRAL_TLS_FAILURE_CLIENT_CERTIFICATE_EXPIRED;
        }
        return about_certificate ? SIPRAL_TLS_FAILURE_CLIENT_CERTIFICATE_REFUSED : SIPRAL_TLS_FAILURE_NONE;
    }
    if (about_certificate || (alert == 40 && certificate_asked)) {
        return SIPRAL_TLS_FAILURE_CLIENT_CERTIFICATE_REQUIRED;
    }
    return SIPRAL_TLS_FAILURE_NONE;
}

/* A server that asked for a certificate, finished the handshake and then
 * closed before answering anything, with no alert: Asterisk does this at
 * TLS 1.2 for a certificate its authority did not sign. Read as the Kotlin
 * layer reads it, by whether one was presented. */
static sipral_tls_failure_t silent_refusal(int presented, int heard)
{
    if (!certificate_asked || heard || alert_received >= 0) {
        return SIPRAL_TLS_FAILURE_NONE;
    }
    return presented ? SIPRAL_TLS_FAILURE_CLIENT_CERTIFICATE_REFUSED
                     : SIPRAL_TLS_FAILURE_CLIENT_CERTIFICATE_REQUIRED;
}

/* What OpenSSL's check of the server's certificate said, when it refused. */
static sipral_tls_failure_t server_refusal(long verdict)
{
    switch (verdict) {
    case X509_V_OK:
        return SIPRAL_TLS_FAILURE_NONE;
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_CERT_NOT_YET_VALID:
        return SIPRAL_TLS_FAILURE_EXPIRED;
    case X509_V_ERR_HOSTNAME_MISMATCH:
    case X509_V_ERR_IP_ADDRESS_MISMATCH:
        return SIPRAL_TLS_FAILURE_NAME_MISMATCH;
    default:
        return SIPRAL_TLS_FAILURE_UNTRUSTED;
    }
}

static const char *tls_name(sipral_tls_failure_t tls)
{
    switch (tls) {
    case SIPRAL_TLS_FAILURE_UNTRUSTED: return "untrusted";
    case SIPRAL_TLS_FAILURE_NAME_MISMATCH: return "name_mismatch";
    case SIPRAL_TLS_FAILURE_EXPIRED: return "expired";
    case SIPRAL_TLS_FAILURE_HANDSHAKE_REFUSED: return "handshake_refused";
    case SIPRAL_TLS_FAILURE_CLIENT_CERTIFICATE_REQUIRED: return "client_certificate_required";
    case SIPRAL_TLS_FAILURE_CLIENT_CERTIFICATE_REFUSED: return "client_certificate_refused";
    case SIPRAL_TLS_FAILURE_CLIENT_KEY_UNAVAILABLE: return "client_key_unavailable";
    case SIPRAL_TLS_FAILURE_CLIENT_CERTIFICATE_EXPIRED: return "client_certificate_expired";
    default: return "none";
    }
}

static const char *error_name(sipral_transport_error_t error)
{
    switch (error) {
    case SIPRAL_TRANSPORT_ERROR_CONNECTION_REFUSED: return "connection_refused";
    case SIPRAL_TRANSPORT_ERROR_CONNECTION_RESET: return "connection_reset";
    case SIPRAL_TRANSPORT_ERROR_UNREACHABLE: return "unreachable";
    case SIPRAL_TRANSPORT_ERROR_TIMED_OUT: return "timed_out";
    case SIPRAL_TRANSPORT_ERROR_CLOSED: return "closed";
    default: return "other";
    }
}

static void on_event(const sipral_event_t *event, void *user_data)
{
    struct line *line = user_data;
    if (event->kind == SIPRAL_EVENT_KIND_TRANSPORT_FAILED) {
        const sipral_transport_failed_event_t *failed = &event->payload.transport_failed;
        printf("transport failed error=%s tls=%s: %.*s\n", error_name(failed->error), tls_name(failed->tls),
               (int)failed->detail_len, failed->detail ? failed->detail : "");
        line->failed = 1;
    } else if (event->kind == SIPRAL_EVENT_KIND_REGISTRATION_CHANGED &&
               event->payload.registration.state == SIPRAL_REGISTRATION_STATE_REGISTERED) {
        printf("registered\n");
        line->registered = 1;
    }
}

/* Tell the stack why the connection failed, and let it say so. */
static void report(sipral_handle_t stack, sipral_transport_error_t error, sipral_tls_failure_t tls,
                   const char *detail)
{
    sipral_transport_failure_t failure;
    memset(&failure, 0, sizeof failure);
    failure.size = sizeof failure;
    failure.transport = SIPRAL_TRANSPORT_MAIN;
    failure.error = error;
    failure.tls = tls;
    failure.detail = detail;
    failure.detail_len = strlen(detail);
    sipral_stack_transport_failed_with(stack, &failure, now_ms());
    sipral_stack_poll(stack, now_ms(), NULL);
}

/* The OpenSSL reason for the last failure, or `fallback`. */
static const char *reason(const char *fallback)
{
    unsigned long code = ERR_peek_last_error();
    const char *said = code ? ERR_reason_error_string(code) : NULL;
    return said ? said : fallback;
}

static int connect_to(const char *address, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in at;
    memset(&at, 0, sizeof at);
    at.sin_family = AF_INET;
    at.sin_port = htons((uint16_t)port);
    if (fd < 0 || inet_pton(AF_INET, address, &at.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&at, sizeof at) != 0) {
        return -1;
    }
    return fd;
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

/* Load the client certificate and its key; the reason it cannot be
 * presented, or SIPRAL_TLS_FAILURE_NONE. */
static sipral_tls_failure_t load_certificate(SSL_CTX *context, const char *cert_file, const char *key_file,
                                             const char **why)
{
    if (SSL_CTX_use_certificate_chain_file(context, cert_file) != 1) {
        *why = reason("the certificate could not be read");
        return SIPRAL_TLS_FAILURE_CLIENT_KEY_UNAVAILABLE;
    }
    if (SSL_CTX_use_PrivateKey_file(context, key_file, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(context) != 1) {
        *why = reason("the private key could not be used");
        return SIPRAL_TLS_FAILURE_CLIENT_KEY_UNAVAILABLE;
    }
    X509 *leaf = SSL_CTX_get0_certificate(context);
    if (X509_cmp_current_time(X509_get0_notBefore(leaf)) > 0 ||
        X509_cmp_current_time(X509_get0_notAfter(leaf)) < 0) {
        *why = "the client certificate is out of its dates";
        return SIPRAL_TLS_FAILURE_CLIENT_CERTIFICATE_EXPIRED;
    }
    return SIPRAL_TLS_FAILURE_NONE;
}

/* Write everything the stack has queued; 0 when the connection broke. */
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
        if (sipral_stack_poll_transmit(stack, &transmit) != SIPRAL_STATUS_OK || transmit.len == 0) {
            return 1;
        }
        int wrote;
        while ((wrote = SSL_write(tls, out, (int)transmit.len)) <= 0 &&
               SSL_get_error(tls, wrote) == SSL_ERROR_WANT_WRITE) {
            usleep(1000);
        }
        if (wrote <= 0) {
            return 0;
        }
    }
}

int main(int argc, char **argv)
{
    if (argc != 7 && argc != 9) {
        fprintf(stderr,
                "usage: %s <address> <port> <sip-domain> <ca-file> <user> <password> [<cert-file> <key-file>]\n",
                argv[0]);
        return 64;
    }
    const char *domain = argv[3];
    const char *user = argv[5];
    const char *password = argv[6];
    int presented = argc == 9;
    setvbuf(stdout, NULL, _IOLBF, 0);
    /* a write to a connection the server closed is an error, not a signal */
    signal(SIGPIPE, SIG_IGN);

    int fd = connect_to(argv[1], atoi(argv[2]));
    if (fd < 0) {
        printf("transport failed error=connection_refused tls=none: no connection to %s:%s\n", argv[1], argv[2]);
        return 2;
    }
    char local[64];
    char remote[64];
    address_of(fd, 1, local, sizeof local);
    address_of(fd, 0, remote, sizeof remote);

    struct line line = { 0, 0 };
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
        sipral_stack_transport_bind(stack, SIPRAL_TRANSPORT_MAIN, 0, local, strlen(local), remote, strlen(remote),
                                    now_ms(), NULL) != SIPRAL_STATUS_OK) {
        fprintf(stderr, "the stack could not be made\n");
        return 1;
    }

    SSL_CTX *context = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION);
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_info_callback(context, on_tls_info);
    SSL_CTX_set_cert_cb(context, on_certificate_request, NULL);
    if (SSL_CTX_load_verify_locations(context, argv[4], NULL) != 1) {
        fprintf(stderr, "no trust anchors in %s\n", argv[4]);
        return 1;
    }
    const char *why = "";
    sipral_tls_failure_t unusable = presented ? load_certificate(context, argv[7], argv[8], &why)
                                              : SIPRAL_TLS_FAILURE_NONE;
    if (unusable != SIPRAL_TLS_FAILURE_NONE) {
        /* the certificate is never offered: the server sees a connection
         * that closes before TLS starts */
        close(fd);
        report(stack, SIPRAL_TRANSPORT_ERROR_OTHER, unusable, why);
        sipral_stack_destroy(stack);
        return 2;
    }

    SSL *tls = SSL_new(context);
    SSL_set_fd(tls, fd);
    SSL_set_tlsext_host_name(tls, domain);
    SSL_set1_host(tls, domain);
    if (SSL_connect(tls) != 1) {
        long verdict = SSL_get_verify_result(tls);
        sipral_tls_failure_t said = server_refusal(verdict);
        if (said == SIPRAL_TLS_FAILURE_NONE) {
            said = client_refusal(presented);
        }
        if (said == SIPRAL_TLS_FAILURE_NONE) {
            said = SIPRAL_TLS_FAILURE_HANDSHAKE_REFUSED;
        }
        const char *detail = verdict != X509_V_OK ? X509_verify_cert_error_string(verdict) : reason("handshake failed");
        report(stack, SIPRAL_TRANSPORT_ERROR_CONNECTION_RESET, said, detail);
        sipral_stack_destroy(stack);
        return 2;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

    char aor[256];
    char registrar[256];
    char contact[256];
    snprintf(aor, sizeof aor, "sip:%s@%s", user, domain);
    snprintf(registrar, sizeof registrar, "sip:%s", domain);
    snprintf(contact, sizeof contact, "sip:%s@%s;transport=tls", user, local);
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
    account.auth_user = user;
    account.auth_user_len = strlen(user);
    account.auth_password = password;
    account.auth_password_len = strlen(password);
    sipral_handle_t handle = SIPRAL_HANDLE_NONE;
    if (sipral_account_add(stack, &account, &handle) != SIPRAL_STATUS_OK ||
        sipral_account_register(stack, handle, now_ms()) != SIPRAL_STATUS_OK) {
        fprintf(stderr, "the account could not be registered\n");
        return 1;
    }

    int heard = 0;
    uint64_t deadline = now_ms() + 20000;
    while (!line.registered && !line.failed && now_ms() < deadline) {
        sipral_poll_result_t polled;
        memset(&polled, 0, sizeof polled);
        polled.size = sizeof polled;
        sipral_stack_poll(stack, now_ms(), &polled);
        if (!flush(stack, tls)) {
            /* the server may have said why before it closed: an alert is
             * only seen when it is read */
            uint8_t rest[256];
            SSL_read(tls, rest, sizeof rest);
            sipral_tls_failure_t said = client_refusal(presented);
            if (said == SIPRAL_TLS_FAILURE_NONE) {
                said = silent_refusal(presented, heard);
            }
            report(stack, SIPRAL_TRANSPORT_ERROR_CONNECTION_RESET, said, reason("the connection broke"));
            break;
        }
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(fd, &readable);
        struct timeval tv = { 0, 100000 };
        if (SSL_pending(tls) == 0 && select(fd + 1, &readable, NULL, NULL, &tv) <= 0) {
            continue;
        }
        uint8_t in[4096];
        int got = SSL_read(tls, in, sizeof in);
        if (got > 0) {
            heard = 1;
            sipral_stack_receive_stream(stack, SIPRAL_TRANSPORT_MAIN, in, (size_t)got, now_ms());
        } else if (SSL_get_error(tls, got) != SSL_ERROR_WANT_READ) {
            /* a TLS 1.3 server refuses the certificate here, after this
             * end's handshake is over */
            sipral_tls_failure_t said = client_refusal(presented);
            if (said == SIPRAL_TLS_FAILURE_NONE) {
                said = silent_refusal(presented, heard);
                if (said != SIPRAL_TLS_FAILURE_NONE) {
                    report(stack, SIPRAL_TRANSPORT_ERROR_CONNECTION_RESET, said,
                           "the server closed the connection before answering, and no alert came");
                    break;
                }
            }
            if (SSL_get_error(tls, got) == SSL_ERROR_ZERO_RETURN && said == SIPRAL_TLS_FAILURE_NONE) {
                sipral_stack_stream_closed(stack, SIPRAL_TRANSPORT_MAIN, now_ms());
                sipral_stack_poll(stack, now_ms(), NULL);
                printf("transport failed error=closed tls=none: the server closed the connection\n");
            } else {
                report(stack, SIPRAL_TRANSPORT_ERROR_CONNECTION_RESET, said, reason("the connection broke"));
            }
            break;
        }
    }

    sipral_stack_destroy(stack);
    SSL_shutdown(tls);
    SSL_free(tls);
    close(fd);
    SSL_CTX_free(context);
    return line.registered ? 0 : 2;
}
