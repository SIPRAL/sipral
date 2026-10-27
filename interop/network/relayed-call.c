/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
 * Copyright (c) 2026 Sytek
 *
 * A C program with no networking code of its own places a call that requires
 * ICE, its media socket mapped by STUN and relayed by TURN through the
 * library's networking component: the component names the socket, carries
 * the STUN and TURN traffic, and opens the TURN connection over TCP or TLS
 * when the stack asks. scripts/lab.sh's TURN step runs it behind the NAT pair,
 * where no path but a relay goes through.
 *
 *   relayed-call
 *
 * Read from the environment, as the bindings' lab agents read it:
 * SIPRAL_PEER_HOST and SIPRAL_PEER_PORT, the callee dialled directly with an
 * account that never registers; SIPRAL_STUN_SERVER; SIPRAL_TURN_SERVER,
 * SIPRAL_TURN_USER and SIPRAL_TURN_PASSWORD for a relay, reached over
 * SIPRAL_TURN_TRANSPORT (udp, tcp or tls), over TLS trusting SIPRAL_TURN_CA
 * alone and checked against SIPRAL_TURN_NAME; SIPRAL_PATIENCE_MS for a path,
 * SIPRAL_DWELL_MS on it. Prints what happened, one line each, and exits 0
 * when ICE chose a path and the far end's audio was heard on it; 2 otherwise.
 */
#define _DEFAULT_SOURCE
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sipral.h"

#define FRAME_SAMPLES_MAX 960

struct line {
    char media_at[SIPRAL_ADDRESS_BYTES];
    int mapped;
    int relay_said;
    int relayed;
    int media_started;
    int path_chosen;
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

static const char *setting(const char *name, const char *otherwise)
{
    const char *value = getenv(name);
    return value != NULL && value[0] != '\0' ? value : otherwise;
}

/* Whether `text`, `len` bytes long, is the media socket. */
static int names_socket(const struct line *line, const char *text, size_t len)
{
    return text != NULL && len == strlen(line->media_at) && memcmp(text, line->media_at, len) == 0;
}

static void on_event(const sipral_event_t *event, void *user_data)
{
    struct line *line = user_data;
    switch (event->kind) {
    case SIPRAL_EVENT_KIND_NAT_MAPPING:
        if (names_socket(line, event->payload.nat.local, event->payload.nat.local_len)) {
            printf("mapped %s to %.*s\n", line->media_at, (int)event->payload.nat.mapped_len,
                   event->payload.nat.mapped ? event->payload.nat.mapped : "");
            line->mapped = 1;
        }
        break;
    case SIPRAL_EVENT_KIND_NAT_RELAY:
        if (names_socket(line, event->payload.relay.local, event->payload.relay.local_len)) {
            if (event->payload.relay.outcome == SIPRAL_NAT_RELAY_ALLOCATED) {
                printf("relayed at %.*s\n", (int)event->payload.relay.relayed_len, event->payload.relay.relayed);
                line->relayed = 1;
            } else {
                printf("no relay: %.*s\n", (int)event->payload.relay.reason_len,
                       event->payload.relay.reason ? event->payload.relay.reason : "");
            }
            line->relay_said = 1;
        }
        break;
    case SIPRAL_EVENT_KIND_TURN_STREAM:
        printf("the TURN connection %s, %s\n",
               event->payload.turn_stream.state == SIPRAL_TURN_STREAM_OPEN ? "asked for" : "let go",
               event->payload.turn_stream.protocol == SIPRAL_TRANSPORT_TLS ? "TLS" : "TCP");
        break;
    case SIPRAL_EVENT_KIND_TRANSPORT_FAILED:
        printf("transport failed: %.*s\n", (int)event->payload.transport_failed.detail_len,
               event->payload.transport_failed.detail ? event->payload.transport_failed.detail : "");
        break;
    case SIPRAL_EVENT_KIND_MEDIA_STARTED:
        if (event->call == line->call) {
            line->media_started = 1;
        }
        break;
    case SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN:
        if (event->call == line->call && !line->path_chosen) {
            printf("path chosen\n");
            line->path_chosen = 1;
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

/* Turn the component's loop until `*flag` is set, or `limit_ms`. */
static int run_until(sipral_handle_t stack, const int *flag, uint64_t limit_ms)
{
    uint64_t deadline = now_ms() + limit_ms;
    while (!*flag && now_ms() < deadline) {
        if (sipral_network_run(stack, now_ms(), 20) != SIPRAL_STATUS_OK) {
            return 0;
        }
    }
    return *flag;
}

/* Carry the call's audio until a path has carried it for `dwell_ms`, or
 * `patience_ms` passed without one: a frame of a 1 kHz tone out every 20 ms,
 * a frame of the far end's in; how many came from its packets. */
static int talk(sipral_handle_t stack, struct line *line, sipral_handle_t media, const sipral_media_info_t *info,
                uint64_t patience_ms, uint64_t dwell_ms)
{
    static int16_t tone[FRAME_SAMPLES_MAX];
    static int16_t heard[FRAME_SAMPLES_MAX];
    double rate = info->sample_rate > 0 ? (double)info->sample_rate : 8000.0;
    uint64_t phase = 0;
    int from_far_end = 0;
    uint64_t give_up = now_ms() + patience_ms;
    uint64_t until = 0;
    uint64_t next_frame = now_ms();
    for (;;) {
        uint64_t now = now_ms();
        if (line->ended || (until == 0 && now >= give_up) || (until != 0 && now >= until)) {
            break;
        }
        if (line->path_chosen && until == 0) {
            until = now + dwell_ms;
        }
        sipral_network_run(stack, now, 5);
        if (now_ms() < next_frame) {
            continue;
        }
        next_frame += 20;
        for (size_t i = 0; i < info->frame_samples; i++, phase++) {
            tone[i] = (int16_t)(8000.0 * sin(2.0 * M_PI * 1000.0 * (double)phase / rate));
        }
        sipral_network_media_capture(stack, media, now_ms(), tone, info->frame_samples);
        size_t written = 0;
        sipral_playback_t source = 0;
        if (sipral_media_playback(media, heard, info->frame_samples, &written, &source) == SIPRAL_STATUS_OK &&
            source == SIPRAL_PLAYBACK_PACKET) {
            from_far_end++;
        }
    }
    return from_far_end;
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    const char *peer_host = setting("SIPRAL_PEER_HOST", NULL);
    const char *stun = setting("SIPRAL_STUN_SERVER", NULL);
    if (peer_host == NULL || stun == NULL) {
        fprintf(stderr, "SIPRAL_PEER_HOST and SIPRAL_STUN_SERVER are required\n");
        return 64;
    }
    char peer[SIPRAL_ADDRESS_BYTES];
    snprintf(peer, sizeof peer, "%s:%s", peer_host, setting("SIPRAL_PEER_PORT", "5060"));
    const char *turn = setting("SIPRAL_TURN_SERVER", NULL);
    const char *over = setting("SIPRAL_TURN_TRANSPORT", "udp");
    const char *turn_name = setting("SIPRAL_TURN_NAME", NULL);
    const char *turn_ca = setting("SIPRAL_TURN_CA", NULL);
    uint64_t patience_ms = strtoull(setting("SIPRAL_PATIENCE_MS", "20000"), NULL, 10);
    uint64_t dwell_ms = strtoull(setting("SIPRAL_DWELL_MS", "2000"), NULL, 10);

    sipral_capabilities_t capabilities;
    memset(&capabilities, 0, sizeof capabilities);
    capabilities.size = sizeof capabilities;
    if (sipral_capabilities(&capabilities) != SIPRAL_STATUS_OK ||
        !(capabilities.features & SIPRAL_FEATURE_NETWORK)) {
        printf("this library has no networking component\n");
        return 2;
    }

    /* the TURN server over TLS is trusted from its own authority alone, and
     * held to its own name; the SIP side here has no TLS at all */
    sipral_network_config_t net;
    memset(&net, 0, sizeof net);
    net.size = sizeof net;
    size_t authority_len = 0;
    char *authority = NULL;
    if (turn_ca != NULL) {
        authority = slurp(turn_ca, &authority_len);
        if (authority == NULL) {
            fprintf(stderr, "no authority in %s\n", turn_ca);
            return 1;
        }
        net.turn_trust = SIPRAL_NETWORK_TRUST_ONLY_AUTHORITY;
        net.turn_authority_pem = authority;
        net.turn_authority_pem_len = authority_len;
    }
    if (turn_name != NULL) {
        net.turn_server_name = turn_name;
        net.turn_server_name_len = strlen(turn_name);
    }

    /* the interface toward the callee, at a port of this container's own, so
     * that the Contact names the socket and STUN's answer replaces it */
    char toward[SIPRAL_ADDRESS_BYTES];
    if (sipral_advertised_address("0.0.0.0:0", 9, peer, strlen(peer), toward, sizeof toward, NULL) !=
        SIPRAL_STATUS_OK) {
        printf("no route toward %s\n", peer);
        return 2;
    }
    char local[SIPRAL_ADDRESS_BYTES];
    snprintf(local, sizeof local, "%.*s:5060", (int)strcspn(toward, ":"), toward);

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
    config.ice = SIPRAL_ICE_REQUIRED;
    config.nat = SIPRAL_NAT_STUN;
    config.stun_server = stun;
    config.stun_server_len = strlen(stun);
    if (turn != NULL) {
        const char *user = setting("SIPRAL_TURN_USER", "");
        const char *password = setting("SIPRAL_TURN_PASSWORD", "");
        config.turn_server = turn;
        config.turn_server_len = strlen(turn);
        config.turn_username = user;
        config.turn_username_len = strlen(user);
        config.turn_password = password;
        config.turn_password_len = strlen(password);
        config.turn_transport = strcmp(over, "tls") == 0   ? SIPRAL_TRANSPORT_TLS
                                : strcmp(over, "tcp") == 0 ? SIPRAL_TRANSPORT_TCP
                                                           : SIPRAL_TRANSPORT_UDP;
    }
    sipral_handle_t stack = SIPRAL_HANDLE_NONE;
    if (sipral_stack_create(&config, &stack) != SIPRAL_STATUS_OK ||
        sipral_network_start(stack, &net, now_ms()) != SIPRAL_STATUS_OK) {
        fprintf(stderr, "the stack could not be made\n");
        return 1;
    }

    char aor[256];
    char contact[256];
    snprintf(aor, sizeof aor, "sip:caller@%s", local);
    snprintf(contact, sizeof contact, "sip:caller@%s", local);
    sipral_account_config_t account;
    memset(&account, 0, sizeof account);
    account.size = sizeof account;
    account.aor = aor;
    account.aor_len = strlen(aor);
    account.contact = contact;
    account.contact_len = strlen(contact);
    account.registrar_address = peer;
    account.registrar_address_len = strlen(peer);
    sipral_handle_t handle = SIPRAL_HANDLE_NONE;
    if (sipral_account_add(stack, &account, &handle) != SIPRAL_STATUS_OK ||
        sipral_network_media_open(stack, line.media_at, sizeof line.media_at, NULL) != SIPRAL_STATUS_OK) {
        fprintf(stderr, "the account or the media socket could not be made\n");
        return 1;
    }

    /* the stack refuses a call on a socket it is still asking about */
    int ok = run_until(stack, &line.mapped, 10000);
    if (ok && turn != NULL) {
        ok = run_until(stack, &line.relay_said, 15000) && line.relayed;
    }
    char target[256];
    snprintf(target, sizeof target, "sip:callee@%s", peer);
    printf("dialling %s from %s, media at %s\n", target, local, line.media_at);
    if (ok) {
        sipral_call_config_t call;
        memset(&call, 0, sizeof call);
        call.size = sizeof call;
        call.target = target;
        call.target_len = strlen(target);
        call.destination = peer;
        call.destination_len = strlen(peer);
        call.media_address = line.media_at;
        call.media_address_len = strlen(line.media_at);
        ok = sipral_call_place(stack, handle, &call, &line.call, now_ms()) == SIPRAL_STATUS_OK &&
             run_until(stack, &line.media_started, patience_ms);
    }

    sipral_handle_t media = SIPRAL_HANDLE_NONE;
    sipral_media_info_t info;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    if (ok) {
        ok = sipral_call_media(stack, line.call, &media) == SIPRAL_STATUS_OK &&
             sipral_media_info(media, &info) == SIPRAL_STATUS_OK && info.frame_samples <= FRAME_SAMPLES_MAX &&
             sipral_network_media_attach(stack, line.media_at, strlen(line.media_at), line.call, media) ==
                 SIPRAL_STATUS_OK;
    }
    if (ok) {
        int heard = talk(stack, &line, media, &info, patience_ms, dwell_ms);
        printf("heard %d frames from the far end\n", heard);
        ok = line.path_chosen && heard >= 25;
        if (!line.path_chosen) {
            printf("no path was chosen\n");
        }
    }
    if (line.call != SIPRAL_HANDLE_NONE && !line.ended) {
        sipral_call_hangup(stack, line.call, now_ms());
        run_until(stack, &line.ended, 10000);
    } else if (line.call == SIPRAL_HANDLE_NONE) {
        sipral_network_media_close(stack, line.media_at, strlen(line.media_at));
    }
    /* the RTCP goodbye, the relay's Refresh of lifetime zero and the TURN
     * connection's close all go in the turns after the call */
    int never = 0;
    run_until(stack, &never, 2000);
    if (ok && turn != NULL) {
        printf("relay over %s to %s: the call ran through the networking component\n", over, turn);
    }
    sipral_network_stop(stack);
    sipral_stack_destroy(stack);
    free(authority);
    return ok && line.ended ? 0 : 2;
}
