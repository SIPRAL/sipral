/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
 * Copyright (c) 2026 Sytek
 *
 * A C program with no networking code of its own: no socket, no TLS, no
 * resolver. The library's networking component (sipral_network_*) finds the
 * SIP domain by NAPTR and SRV, connects over TLS checked against the domain,
 * registers, places a call, carries its audio, holds it and resumes it.
 * scripts/lab.sh's `network` step runs it against Asterisk, with a name
 * server that knows the domain by its NAPTR and SRV records alone.
 *
 *   register-and-hold <sip-domain> <ca-file> <user> <password> <extension>
 *
 * The server's certificate is trusted from ca-file alone, checked against
 * sip-domain. Prints what happened, one line each, and exits 0 when it was
 * registered, heard the far end, held, resumed, heard it again and hung up;
 * 2 otherwise.
 */
#define _DEFAULT_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sipral.h"

#define FRAME_SAMPLES_MAX 960

struct line {
    int registered;
    int unregistered;
    int media_started;
    int sessions_changed;
    int ended;
    sipral_handle_t call;
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

/* The whole of a small file, NUL-terminated; NULL when it cannot be read. */
static char *slurp(const char *path, size_t *out_len)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return NULL;
    }
    char *text = malloc(65536);
    size_t len = text ? fread(text, 1, 65535, file) : 0;
    fclose(file);
    if (text == NULL || len == 0) {
        free(text);
        return NULL;
    }
    text[len] = '\0';
    *out_len = len;
    return text;
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

static void on_event(const sipral_event_t *event, void *user_data)
{
    struct line *line = user_data;
    switch (event->kind) {
    case SIPRAL_EVENT_KIND_LOOKUP_WANTED:
        printf("lookup %s %.*s\n",
               event->payload.locate.record == SIPRAL_DNS_RECORD_TYPE_NAPTR ? "NAPTR"
               : event->payload.locate.record == SIPRAL_DNS_RECORD_TYPE_SRV ? "SRV"
               : event->payload.locate.record == SIPRAL_DNS_RECORD_TYPE_A   ? "A"
                                                                           : "AAAA",
               (int)event->payload.locate.name_len, event->payload.locate.name);
        break;
    case SIPRAL_EVENT_KIND_LOCATED:
        printf("located %.*s\n", (int)event->payload.locate.targets_len, event->payload.locate.targets);
        break;
    case SIPRAL_EVENT_KIND_TRANSPORT_FAILED:
        printf("transport failed tls=%s: %.*s\n", tls_name(event->payload.transport_failed.tls),
               (int)event->payload.transport_failed.detail_len,
               event->payload.transport_failed.detail ? event->payload.transport_failed.detail : "");
        break;
    case SIPRAL_EVENT_KIND_REGISTRATION_CHANGED:
        if (event->payload.registration.state == SIPRAL_REGISTRATION_STATE_REGISTERED && !line->registered) {
            printf("registered\n");
            line->registered = 1;
        } else if (event->payload.registration.state == SIPRAL_REGISTRATION_STATE_UNREGISTERED &&
                   line->registered) {
            printf("unregistered\n");
            line->unregistered = 1;
        }
        break;
    case SIPRAL_EVENT_KIND_MEDIA_STARTED:
        if (event->call == line->call) {
            line->media_started = 1;
        }
        break;
    case SIPRAL_EVENT_KIND_SESSION_CHANGED:
        if (event->call == line->call) {
            line->sessions_changed++;
        }
        break;
    case SIPRAL_EVENT_KIND_CALL_ENDED:
        if (event->call == line->call) {
            printf("ended\n");
            line->ended = 1;
        }
        break;
    default:
        break;
    }
}

/* Turn the component's loop until `*flag` reaches `wanted`, or `limit_ms`. */
static int run_until(sipral_handle_t stack, const int *flag, int wanted, uint64_t limit_ms)
{
    uint64_t deadline = now_ms() + limit_ms;
    while (*flag < wanted && now_ms() < deadline) {
        if (sipral_network_run(stack, now_ms(), 20) != SIPRAL_STATUS_OK) {
            return 0;
        }
    }
    return *flag >= wanted;
}

/* Carry the call's audio for `ms`: a frame of silence out every 20 ms, a frame
 * of the far end's in; how many of those came from its packets. */
static int talk(sipral_handle_t stack, sipral_handle_t media, size_t frame_samples, uint64_t ms)
{
    static int16_t silence[FRAME_SAMPLES_MAX];
    static int16_t heard[FRAME_SAMPLES_MAX];
    int from_far_end = 0;
    uint64_t until = now_ms() + ms;
    uint64_t next_frame = now_ms();
    while (now_ms() < until) {
        sipral_network_run(stack, now_ms(), 5);
        if (now_ms() < next_frame) {
            continue;
        }
        next_frame += 20;
        sipral_network_media_capture(stack, media, now_ms(), silence, frame_samples);
        size_t written = 0;
        sipral_playback_t source = 0;
        if (sipral_media_playback(media, heard, frame_samples, &written, &source) == SIPRAL_STATUS_OK &&
            source == SIPRAL_PLAYBACK_PACKET) {
            from_far_end++;
        }
    }
    return from_far_end;
}

int main(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr, "usage: %s <sip-domain> <ca-file> <user> <password> <extension>\n", argv[0]);
        return 64;
    }
    const char *domain = argv[1];
    const char *user = argv[3];
    const char *password = argv[4];
    setvbuf(stdout, NULL, _IOLBF, 0);

    sipral_capabilities_t capabilities;
    memset(&capabilities, 0, sizeof capabilities);
    capabilities.size = sizeof capabilities;
    if (sipral_capabilities(&capabilities) != SIPRAL_STATUS_OK ||
        !(capabilities.features & SIPRAL_FEATURE_NETWORK)) {
        printf("this library has no networking component\n");
        return 2;
    }
    size_t authority_len = 0;
    char *authority = slurp(argv[2], &authority_len);
    if (authority == NULL) {
        fprintf(stderr, "no authority in %s\n", argv[2]);
        return 1;
    }

    sipral_network_config_t net;
    memset(&net, 0, sizeof net);
    net.size = sizeof net;
    net.trust = SIPRAL_NETWORK_TRUST_ONLY_AUTHORITY;
    net.authority_pem = authority;
    net.authority_pem_len = authority_len;

    /* the address this end is reached at: the interface toward the server
     * RFC 3263 finds, asked of the library rather than of a socket */
    char server_uri[256];
    snprintf(server_uri, sizeof server_uri, "sips:%s", domain);
    char located[512];
    if (sipral_network_locate(&net, server_uri, strlen(server_uri), SIPRAL_TRANSPORT_TLS, located,
                              sizeof located, NULL) != SIPRAL_STATUS_OK) {
        printf("not located\n");
        return 2;
    }
    printf("found %s\n", located);
    char local[SIPRAL_ADDRESS_BYTES];
    if (sipral_advertised_address("0.0.0.0:0", 9, located, strcspn(located, ","), local, sizeof local,
                                  NULL) != SIPRAL_STATUS_OK) {
        printf("no route toward %s\n", located);
        return 2;
    }
    char host[SIPRAL_ADDRESS_BYTES];
    snprintf(host, sizeof host, "%.*s", (int)strcspn(local, ":"), local);

    struct line line;
    memset(&line, 0, sizeof line);
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
    config.transport = SIPRAL_TRANSPORT_UDP;
    config.bind_address = local;
    config.bind_address_len = strlen(local);
    config.entropy = seed;
    config.entropy_len = sizeof seed;
    config.media_seed = media_seed;
    config.media_seed_len = sizeof media_seed;
    sipral_handle_t stack = SIPRAL_HANDLE_NONE;
    if (sipral_stack_create(&config, &stack) != SIPRAL_STATUS_OK ||
        sipral_network_start(stack, &net, now_ms()) != SIPRAL_STATUS_OK) {
        fprintf(stderr, "the stack could not be made\n");
        return 1;
    }

    char aor[256];
    char registrar[256];
    char contact[256];
    snprintf(aor, sizeof aor, "sip:%s@%s", user, domain);
    snprintf(registrar, sizeof registrar, "sip:%s", domain);
    snprintf(contact, sizeof contact, "sip:%s@%s;transport=tls", user, host);
    sipral_account_config_t account;
    memset(&account, 0, sizeof account);
    account.size = sizeof account;
    account.aor = aor;
    account.aor_len = strlen(aor);
    account.registrar = registrar;
    account.registrar_len = strlen(registrar);
    account.contact = contact;
    account.contact_len = strlen(contact);
    account.server_uri = server_uri;
    account.server_uri_len = strlen(server_uri);
    account.server_naptr = SIPRAL_TOGGLE_ON;
    account.stream_protocol = SIPRAL_TRANSPORT_TLS;
    account.srtp = SIPRAL_SRTP_NOT_OFFERED;
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
    int ok = run_until(stack, &line.registered, 1, 20000);

    char media_at[SIPRAL_ADDRESS_BYTES];
    char target[256];
    snprintf(target, sizeof target, "sip:%s@%s", argv[5], domain);
    if (ok) {
        sipral_call_config_t call;
        memset(&call, 0, sizeof call);
        call.size = sizeof call;
        call.target = target;
        call.target_len = strlen(target);
        ok = sipral_network_media_open(stack, media_at, sizeof media_at, NULL) == SIPRAL_STATUS_OK;
        call.media_address = media_at;
        call.media_address_len = strlen(media_at);
        ok = ok && sipral_call_place(stack, handle, &call, &line.call, now_ms()) == SIPRAL_STATUS_OK;
        ok = ok && run_until(stack, &line.media_started, 1, 20000);
    }

    sipral_handle_t media = SIPRAL_HANDLE_NONE;
    sipral_media_info_t info;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    if (ok) {
        ok = sipral_call_media(stack, line.call, &media) == SIPRAL_STATUS_OK &&
             sipral_media_info(media, &info) == SIPRAL_STATUS_OK && info.frame_samples <= FRAME_SAMPLES_MAX &&
             sipral_network_media_attach(stack, media_at, strlen(media_at), line.call, media) == SIPRAL_STATUS_OK;
    }
    if (ok) {
        int heard = talk(stack, media, info.frame_samples, 4000);
        printf("heard %d frames from the far end\n", heard);
        ok = heard >= 25;
    }
    if (ok) {
        int before = line.sessions_changed;
        ok = sipral_call_hold(stack, line.call, now_ms()) == SIPRAL_STATUS_OK &&
             run_until(stack, &line.sessions_changed, before + 1, 10000);
        if (ok) {
            printf("held\n");
            talk(stack, media, info.frame_samples, 2000);
        }
    }
    if (ok) {
        int before = line.sessions_changed;
        ok = sipral_call_resume(stack, line.call, now_ms()) == SIPRAL_STATUS_OK &&
             run_until(stack, &line.sessions_changed, before + 1, 10000);
        if (ok) {
            printf("resumed\n");
            int heard = talk(stack, media, info.frame_samples, 4000);
            printf("heard %d frames from the far end after resuming\n", heard);
            ok = heard >= 25;
        }
    }
    if (line.call != SIPRAL_HANDLE_NONE && !line.ended) {
        sipral_call_hangup(stack, line.call, now_ms());
        run_until(stack, &line.ended, 1, 10000);
    }
    if (line.registered) {
        sipral_account_unregister(stack, handle, now_ms());
        run_until(stack, &line.unregistered, 1, 10000);
    }
    sipral_network_stop(stack);
    sipral_stack_destroy(stack);
    free(authority);
    return ok && line.ended ? 0 : 2;
}
