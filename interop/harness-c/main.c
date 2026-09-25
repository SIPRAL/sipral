/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
 * Copyright (c) 2026 Tiberiu Balasea
 *
 * The lab, driven through the C ABI.
 *
 * `interop/harness` runs the same flows against the same servers in Rust and
 * proves the stack. This one proves the header: every byte it sends leaves
 * through `sipral.h`, every byte it receives goes back in through it, and
 * everything it knows about a call it learned from a `sipral_event_t`. A
 * defect that lives in the boundary rather than in the stack -- a struct whose
 * length the two sides disagree about, a handle that goes stale, an entry
 * point that wants a clock nobody passes it -- is invisible to the Rust
 * harness by construction, and is what this one is for.
 *
 * It is written the way an integrator writes one, which is the other half of
 * the point: C99, warnings fatal, nothing linked but libc and this library,
 * and a socket loop somebody could have written on a first afternoon. If this
 * file is awkward to write, the ABI is awkward to use, and that is a finding
 * rather than a matter of taste.
 *
 * Same command line, same output lines and same exit code as the Rust
 * harness, so `scripts/lab.sh` reads both with one parser:
 *
 *     harness-c <server> [port] [extension] [other]
 *
 * The lab passes no credentials in the environment -- it calls the harness
 * with three arguments and nothing else -- so the account names below are the
 * same built-in defaults `interop/harness/src/main.rs` carries, and for the
 * same reason: a real server is reached with real credentials, and those do
 * not belong in a repository that becomes public.
 */

/* Asked for before any header is included, and load-bearing on glibc: with
 * `-std=c99` and nothing else, glibc defines `__STRICT_ANSI__` and hides every
 * declaration that is POSIX rather than ISO C -- `clock_gettime`, `nanosleep`,
 * `getaddrinfo`, `struct timespec`, `struct addrinfo`. macOS's libc exposes
 * them regardless, so a file that compiles cleanly there fails on Linux with a
 * page of "storage size isn't known", which is what happened the first time
 * this one was built for the lab. 200809 is the edition all four are in.
 */
#define _POSIX_C_SOURCE 200809L
/* `getentropy` is not POSIX -- glibc gates it behind this (or `_GNU_SOURCE`)
 * rather than exposing it whenever `_POSIX_C_SOURCE` alone is defined, and
 * macOS's own `<sys/random.h>` wants nothing extra, so defining it costs
 * that platform nothing. */
#define _DEFAULT_SOURCE 1

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "sipral.h"

/* How long a flow may take before it is a failure. Generous, because a
 * registrar that challenges, a proxy that forks and a media server that takes
 * its time are all ordinary, and a harness that gives up early reports the
 * stack for the network's patience. */
#define FLOW_PATIENCE_MS 25000u

/* How long a call that is up carries audio before it is judged. */
#define DWELL_MS 2500u

/* The buffer one frame of playback goes into. The real number is
 * `sipral_media_info_t::frame_samples`, asked of the library per call; this is
 * only the ceiling. */
#define MAX_FRAME_SAMPLES 1024u

/* A datagram buffer: the ordinary 64 KiB, so that a message which outgrew its
 * path is reported by the stack rather than truncated here. */
#define DATAGRAM 65535u

/* What the tone is. Square rather than sine, and judged on mean absolute
 * sample value, both copied deliberately from `interop/harness/src/audio.rs`:
 * two harnesses that measured audio differently would disagree about a call
 * for a reason that had nothing to do with the call. */
#define TONE_HZ 440u
#define TONE_AMPLITUDE 8000
#define AUDIBLE 500

/* 1200 ms of tone then 600 ms of silence, repeating. A continuous tone never
 * lets a de-jitter buffer give back the delay it grew, because that only
 * happens in a pause. */
#define SPURT_MS 1200u
#define PAUSE_MS 600u

/* Audible frames `FLOW_G729` has to hear back from the echo: half a second
 * of twenty-millisecond frames, of the call's dwell, a third of which is the
 * tone's own pauses -- the Rust harness's own `G729_ECHOED`. */
#define G729_ECHOED 25u

/* `FLOW_ICE_NAT`: how long a path is waited for once the call is answered,
 * how long the tone then runs on it, and how many frames of the far end's
 * tone have to be heard -- interop/harness/src/ice_lite.rs's own `PATIENCE`,
 * `DWELL` and `AUDIBLE_FRAMES`, so the two drivers judge one call alike. */
#define ICE_PATIENCE_MS 30000u
#define ICE_DWELL_MS 3000u
#define ICE_AUDIBLE 10u

/* The digit this harness presses, and how long it holds it. */
#define TEST_DIGIT "5"
#define DIGIT_MS 200u

/* `FLOW_MESSAGE`'s own body. Not read back for a match -- the lab's own
 * dialplan is free to prefix it on the way back (`interop/asterisk`'s own
 * extension 9006 does) -- only that a MESSAGE came back at all. Copied from
 * `interop/harness/src/main.rs`'s own `MESSAGE_BODY`, so a capture shows the
 * same bytes from either driver. */
#define MESSAGE_BODY "sipral interop lab"

/* What the hold-with-a-codec-change flow moves the call onto: the other G.711
 * law, which every server in the lab takes and which the call cannot already
 * be on, since the catalogue offers PCMU first. */
#define CHANGED_CODECS "PCMA"

/* `FLOW_NAT`'s two sockets are bound at these ports rather than at ephemeral
 * ones, because interop/nat/route.sh translates exactly these two to other
 * ports on the way out. A NAT that kept every port would let a Contact or an
 * `m=` that took the host from the STUN answer and the port from the socket
 * pass for right; with the ports moved, only the port the server reported
 * reaches this end. The two files have to agree on the numbers. */
#define NAT_SIP_PORT 5062u
#define NAT_RTP_PORT 40062u

/* -- the clock ------------------------------------------------------------ */

/* Milliseconds since some point before this process started.
 *
 * Monotonic, because every entry point that takes `now_ms` refuses a clock
 * that went backwards, and a wall clock stepped by NTP in the middle of a lab
 * run is exactly that. */
static uint64_t now_ms(void)
{
    struct timespec at;
    if (clock_gettime(CLOCK_MONOTONIC, &at) != 0) {
        return 0;
    }
    return (uint64_t)at.tv_sec * 1000u + (uint64_t)(at.tv_nsec / 1000000L);
}

static void sleep_ms(unsigned millis)
{
    struct timespec how_long;
    how_long.tv_sec = (time_t)(millis / 1000u);
    how_long.tv_nsec = (long)(millis % 1000u) * 1000000L;
    (void)nanosleep(&how_long, NULL);
}

/* -- addresses ------------------------------------------------------------ */

/* The address a datagram to `remote` would leave this host from.
 *
 * A connected UDP socket that never sends anything: the kernel picks the
 * source for the route and `getsockname` reports it. What this answers is what
 * goes in `Contact` and in `c=` -- inside a container, the container's address
 * on the lab network rather than the wildcard a bind to 0.0.0.0 reports. */
static int route_to(const struct sockaddr_in *remote, char *out, size_t room)
{
    struct sockaddr_in mine;
    socklen_t length = sizeof mine;
    int probe = socket(AF_INET, SOCK_DGRAM, 0);
    if (probe < 0) {
        return -1;
    }
    if (connect(probe, (const struct sockaddr *)remote, sizeof *remote) != 0
        || getsockname(probe, (struct sockaddr *)&mine, &length) != 0) {
        (void)close(probe);
        return -1;
    }
    (void)close(probe);
    return inet_ntop(AF_INET, &mine.sin_addr, out, (socklen_t)room) == NULL ? -1 : 0;
}

/* `host:port`, as every address in this ABI is spelled. */
static int address_text(const struct sockaddr_in *address, char *out, size_t room)
{
    char host[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &address->sin_addr, host, sizeof host) == NULL) {
        return -1;
    }
    return snprintf(out, room, "%s:%u", host, (unsigned)ntohs(address->sin_port))
                   >= (int)room
               ? -1
               : 0;
}

/* The other way: the ABI hands an address back as text and a socket wants a
 * sockaddr. */
static int address_of(const char *text, struct sockaddr_in *out)
{
    char host[INET_ADDRSTRLEN + 8];
    const char *colon = strrchr(text, ':');
    size_t length;
    if (colon == NULL) {
        return -1;
    }
    length = (size_t)(colon - text);
    if (length >= sizeof host) {
        return -1;
    }
    memcpy(host, text, length);
    host[length] = '\0';
    memset(out, 0, sizeof *out);
    out->sin_family = AF_INET;
    out->sin_port = htons((uint16_t)atoi(colon + 1));
    return inet_pton(AF_INET, host, &out->sin_addr) == 1 ? 0 : -1;
}

/* The lab's servers are named, not numbered. */
static int resolve(const char *host, uint16_t port, struct sockaddr_in *out)
{
    struct addrinfo hints;
    struct addrinfo *found = NULL;
    char service[8];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    (void)snprintf(service, sizeof service, "%u", (unsigned)port);
    if (getaddrinfo(host, service, &hints, &found) != 0 || found == NULL) {
        return -1;
    }
    memcpy(out, found->ai_addr, sizeof *out);
    freeaddrinfo(found);
    return 0;
}

/* A non-blocking UDP socket on `port`, or on an ephemeral one for zero, and
 * where it landed. */
static int bind_udp_at(struct sockaddr_in *out, uint16_t port)
{
    struct sockaddr_in any;
    struct timeval instant;
    socklen_t length = sizeof *out;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    memset(&any, 0, sizeof any);
    any.sin_family = AF_INET;
    any.sin_addr.s_addr = htonl(INADDR_ANY);
    any.sin_port = htons(port);
    if (bind(fd, (const struct sockaddr *)&any, sizeof any) != 0
        || getsockname(fd, (struct sockaddr *)out, &length) != 0) {
        (void)close(fd);
        return -1;
    }
    /* a read that waits forever is a harness that hangs instead of failing */
    instant.tv_sec = 0;
    instant.tv_usec = 1000;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &instant, sizeof instant);
    return fd;
}

/* The same on an ephemeral port, which is what every flow but one wants. */
static int bind_udp(struct sockaddr_in *out)
{
    return bind_udp_at(out, 0u);
}

/* -- the tone, and hearing it back ---------------------------------------- */

/* What this end sends: a square wave, so nothing about the signal itself can
 * be blamed for what comes back. */
static void tone(int16_t *samples, size_t count, uint32_t rate, uint32_t *phase)
{
    uint32_t period = rate / TONE_HZ;
    size_t index;
    if (period < 2u) {
        period = 2u;
    }
    for (index = 0; index < count; index++) {
        samples[index] = (*phase % period) < (period / 2u) ? (int16_t)TONE_AMPLITUDE
                                                           : (int16_t)-TONE_AMPLITUDE;
        *phase += 1u;
    }
}

/* Mean absolute sample value. G.711 and G.722 silence sits within a handful of
 * units of zero; a tone at a quarter of full scale is thousands. */
static int loudness(const int16_t *samples, size_t count)
{
    long total = 0;
    size_t index;
    if (count == 0) {
        return 0;
    }
    for (index = 0; index < count; index++) {
        int value = samples[index];
        total += value < 0 ? -(long)value : (long)value;
    }
    return (int)(total / (long)count);
}

/* Whether the tone is sounding at this point in the call. */
static int in_spurt(uint64_t elapsed_ms)
{
    return (elapsed_ms % (SPURT_MS + PAUSE_MS)) < SPURT_MS;
}

/* -- what the callback saw ------------------------------------------------ */

/* Everything this harness learns about a flow in progress.
 *
 * Filled by the event callback and read by the script. A struct behind
 * `sipral_stack_config_t::event_user_data` rather than a global, because that
 * member is how the ABI hands an application its own state back and a harness
 * that used a global would not be exercising it.
 */
struct seen {
    unsigned marker;
    uint32_t registration;
    uint32_t registration_failure;
    int confirmed;
    int ended;
    int media_started;
    int media_secured;
    int media_failed;
    int transfer_done;
    int transfer_failed;
    int digit_named_back;
    int dtmf_sent;
    uint32_t dtmf_sent_status;
    int held_here;
    int held_once;
    /* every session change agreed, so a flow can tell one from the next */
    int session_changes;
    /* a change this end offered and the far end refused for good -- a 491
     * goes out again by itself and is not counted */
    int change_refused;
    uint32_t change_status;
    /* the codec the call came up on, and the one it is on now */
    uint32_t codec_started;
    uint32_t codec_now;
    /* `FLOW_MESSAGE`: this end's own send was answered, and with what
     * status; the lab's own echo dialplan sent a MESSAGE back */
    int message_sent;
    uint32_t message_sent_status;
    int message_received;
    /* `FLOW_MWI`: the message-summary subscription was granted, or it ended
     * (refused, or given up on) before the flow had what it came for */
    int subscribed;
    int subscription_ended;
    /* a message-summary NOTIFY arrived, and the mailbox's own `new` count on
     * the latest one -- `flow_mwi` reads this once for its baseline and
     * again, after the voicemail call, for the claim that it climbed */
    int mailbox_notified;
    uint32_t mailbox_new_count;
    /* `FLOW_NAT`: what the STUN server said about the signalling socket and
     * about the media one, as `SIPRAL_EVENT_KIND_NAT_MAPPING` carried it */
    int sip_mapped;
    uint32_t sip_mapping;
    uint32_t sip_accounts_moved;
    char sip_public[SIPRAL_ADDRESS_BYTES];
    int media_mapped;
    uint32_t media_mapping;
    char media_public[SIPRAL_ADDRESS_BYTES];
    /* `FLOW_ICE_NAT`: what the TURN server said about the media socket, as
     * `SIPRAL_EVENT_KIND_NAT_RELAY` carried it, and when */
    int relay_seen;
    uint32_t relay_outcome;
    uint32_t relay_code;
    uint64_t relay_at_ms;
    char relayed[SIPRAL_ADDRESS_BYTES];
    char relay_reason[128];
    /* `FLOW_ICE_NAT`: when the call was answered, and when ICE chose the
     * path its media takes -- the event carries no addresses, so which path
     * it was is read off the packets the library addresses afterwards */
    uint64_t confirmed_at_ms;
    int path_chosen;
    uint64_t path_chosen_at_ms;
    /* the registrar's own 200 to the REGISTER, which lists the bindings it
     * now holds -- the registrar's word for which Contact it took -- and the
     * description this end sent last, as the latest session change reported
     * it: the one place this ABI hands an application its own SDP back */
    char registered_with[2048];
    char local_sdp[2048];
    int events;
    char fault[192];
};

/* Copy `len` bytes the library lent for the length of a callback into `out`,
 * NUL-terminated, cut short where `room` ends. */
static void keep(char *out, size_t room, const void *bytes, size_t len)
{
    if (room == 0) {
        return;
    }
    if (bytes == NULL) {
        len = 0;
    }
    if (len >= room) {
        len = room - 1u;
    }
    if (len > 0) {
        memcpy(out, bytes, len);
    }
    out[len] = '\0';
}

#define MARKER 0x5A1AB5u

static void on_event(const sipral_event_t *event, void *user_data)
{
    struct seen *seen = (struct seen *)user_data;
    if (seen == NULL || seen->marker != MARKER || event == NULL) {
        return;
    }
    seen->events++;
    switch (event->kind) {
    case SIPRAL_EVENT_KIND_REGISTRATION_CHANGED:
        seen->registration = event->payload.registration.state;
        seen->registration_failure = event->payload.registration.failure;
        if (event->payload.registration.state == SIPRAL_REGISTRATION_STATE_REGISTERED) {
            keep(seen->registered_with, sizeof seen->registered_with, event->message,
                 event->message_len);
        }
        break;
    case SIPRAL_EVENT_KIND_CALL_CONFIRMED:
        seen->confirmed = 1;
        if (seen->confirmed_at_ms == 0) {
            seen->confirmed_at_ms = now_ms();
        }
        break;
    case SIPRAL_EVENT_KIND_NAT_RELAY:
        seen->relay_seen = 1;
        seen->relay_outcome = event->payload.relay.outcome;
        seen->relay_code = event->payload.relay.code;
        seen->relay_at_ms = now_ms();
        keep(seen->relayed, sizeof seen->relayed, event->payload.relay.relayed,
             event->payload.relay.relayed_len);
        keep(seen->relay_reason, sizeof seen->relay_reason, event->payload.relay.reason,
             event->payload.relay.reason_len);
        break;
    case SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN:
        /* the first nomination is the one timed; a later one of higher
         * priority replacing it changes where packets go, which is read
         * off the packets rather than off this */
        if (!seen->path_chosen) {
            seen->path_chosen = 1;
            seen->path_chosen_at_ms = now_ms();
        }
        break;
    case SIPRAL_EVENT_KIND_NAT_MAPPING:
        if (event->payload.nat.signalling != 0) {
            seen->sip_mapped = 1;
            seen->sip_mapping = event->payload.nat.mapping;
            seen->sip_accounts_moved = event->payload.nat.accounts;
            keep(seen->sip_public, sizeof seen->sip_public, event->payload.nat.mapped,
                 event->payload.nat.mapped_len);
        } else {
            seen->media_mapped = 1;
            seen->media_mapping = event->payload.nat.mapping;
            keep(seen->media_public, sizeof seen->media_public, event->payload.nat.mapped,
                 event->payload.nat.mapped_len);
        }
        break;
    case SIPRAL_EVENT_KIND_SESSION_CHANGED:
        /* hold and resume are this one event with the flag turned over, and
         * the flag is `held_here` -- "whether this end has asked the far end
         * to stop sending". `held_there` is the far end holding us, which is
         * a different thing and not what these flows ask for */
        seen->held_here = (int)event->payload.call.held_here;
        if (seen->held_here) {
            seen->held_once = 1;
        }
        seen->session_changes++;
        keep(seen->local_sdp, sizeof seen->local_sdp, event->payload.call.local_sdp,
             event->payload.call.local_sdp_len);
        break;
    case SIPRAL_EVENT_KIND_SESSION_CHANGE_FAILED:
        if (event->payload.call.retry_in_ms == 0) {
            seen->change_refused = 1;
            seen->change_status = event->payload.call.status_code;
        }
        break;
    case SIPRAL_EVENT_KIND_CALL_ENDED:
        seen->ended = 1;
        break;
    case SIPRAL_EVENT_KIND_MEDIA_STARTED:
        seen->media_started = 1;
        seen->codec_started = event->payload.media.codec;
        seen->codec_now = event->payload.media.codec;
        break;
    case SIPRAL_EVENT_KIND_MEDIA_CHANGED:
        seen->codec_now = event->payload.media.codec;
        break;
    case SIPRAL_EVENT_KIND_MEDIA_SECURED:
        seen->media_secured = 1;
        break;
    case SIPRAL_EVENT_KIND_MEDIA_FAILED:
        seen->media_failed = 1;
        if (event->payload.media.reason != NULL
            && event->payload.media.reason_len < sizeof seen->fault) {
            memcpy(seen->fault, event->payload.media.reason,
                   event->payload.media.reason_len);
            seen->fault[event->payload.media.reason_len] = '\0';
        }
        break;
    case SIPRAL_EVENT_KIND_DIGIT_RECEIVED:
        /* the digit this end pressed, and not merely a digit: a dialplan that
         * named back something else has not heard this one */
        if (event->payload.media.digit == (uint32_t)(unsigned char)TEST_DIGIT[0]) {
            seen->digit_named_back = 1;
        }
        break;
    case SIPRAL_EVENT_KIND_DTMF_SENT:
        seen->dtmf_sent = 1;
        seen->dtmf_sent_status = event->payload.call.status_code;
        break;
    case SIPRAL_EVENT_KIND_TRANSFER_DONE:
        /* both outcomes arrive here; the status code says which */
        if (event->payload.transfer.status_code >= 200u
            && event->payload.transfer.status_code < 300u) {
            seen->transfer_done = 1;
        } else {
            seen->transfer_failed = 1;
        }
        break;
    case SIPRAL_EVENT_KIND_MESSAGE_RECEIVED:
        seen->message_received = 1;
        break;
    case SIPRAL_EVENT_KIND_MESSAGE_SENT:
        seen->message_sent = 1;
        seen->message_sent_status = event->payload.message.status_code;
        break;
    case SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED:
        /* one kind carries both a subscription granted and one that is no
         * longer live -- `state` says which, not the kind. Requesting is
         * neither: nothing has answered the SUBSCRIBE yet */
        if (event->payload.subscription.state == SIPRAL_SUBSCRIPTION_STATE_ACTIVE
            || event->payload.subscription.state == SIPRAL_SUBSCRIPTION_STATE_PENDING) {
            seen->subscribed = 1;
        } else if (event->payload.subscription.state == SIPRAL_SUBSCRIPTION_STATE_RETRYING
                   || event->payload.subscription.state == SIPRAL_SUBSCRIPTION_STATE_ENDED) {
            seen->subscription_ended = 1;
        }
        break;
    case SIPRAL_EVENT_KIND_MESSAGES_WAITING:
        seen->mailbox_notified = 1;
        seen->mailbox_new_count = event->payload.message.new_messages;
        break;
    default:
        break;
    }
}

/* -- one end of the lab --------------------------------------------------- */

/* The stack, its two sockets, and what has crossed them.
 *
 * Two sockets and not one: signalling and media are separate ports on every
 * SIP endpoint there has ever been, and the ABI keeps them separate too --
 * `sipral_stack_receive_datagram` for one, `sipral_media_receive` for the
 * other, and neither knows about the other's.
 */
struct endpoint {
    sipral_handle_t stack;
    sipral_handle_t account;
    sipral_handle_t call;
    sipral_handle_t consulted;
    sipral_handle_t media;
    /* `flow_mwi`'s own subscription to `message-summary`. SIPRAL_HANDLE_NONE
     * on every other flow, and `finish`'s own signal that there is one to
     * give up. */
    sipral_handle_t subscription;

    int sip_fd;
    int rtp_fd;
    char sip_address[SIPRAL_ADDRESS_BYTES];
    char rtp_address[SIPRAL_ADDRESS_BYTES];
    /* this account's own AOR, as `open_endpoint` built it to add the
     * account -- kept so `flow_mwi` can subscribe to the same address of
     * record rather than build it again from parts it was never handed */
    char aor[128];
    struct sockaddr_in server;

    uint64_t next_frame_ms;
    uint64_t media_since_ms;
    /* how many session changes had been agreed when this end asked for the
     * one it is now waiting on */
    int changes_before;
    uint32_t phase;
    size_t frame_samples;
    uint32_t sample_rate;
    /* `flow_mwi`'s own mailbox `new` count, read from the first
     * notification -- before the voicemail call, whatever an earlier run
     * already left behind. The claim is that a later one reads higher than
     * this, not that it starts at zero. */
    uint32_t mailbox_baseline;
    /* `FLOW_NAT`: whether the RTP socket is being asked about, so that what
     * arrives on it before the call has media goes to the STUN client rather
     * than nowhere */
    int mapping_media;
    /* `FLOW_NAT`: while this is set, the STUN server's answers on the
     * signalling socket are held back, the newest kept, so that the account
     * registers its private address first -- the REGISTER a phone sends
     * before a slow STUN server has answered -- and the flow can prove that
     * the REGISTER after the answer takes that binding back */
    int withhold_stun;
    uint8_t withheld[1024];
    size_t withheld_len;
    char withheld_from[SIPRAL_ADDRESS_BYTES];
    /* where the last frame of this end's own audio was addressed: after ICE
     * has chosen, the one statement of which path it chose that reaches an
     * application, since every packet names its own destination */
    char media_to[SIPRAL_ADDRESS_BYTES];
    /* `FLOW_ICE_NAT`: the Refreshes with a lifetime of zero this end sent,
     * whichever queue handed them out, and where the last went */
    unsigned relays_given_back;
    char given_back_to[SIPRAL_ADDRESS_BYTES];

    /* the same four numbers the Rust harness prints, counted the same way:
     * from outside the session, watching what each call returns */
    unsigned sent;
    unsigned received;
    unsigned audible;
    unsigned refused;
    /* `FLOW_ICE_NAT`: what arrived on the media socket after the call was
     * placed and before its media handle existed -- all of it handed to
     * `sipral_stack_receive_stun`, as docs/08-ffi.md asks -- and how much of
     * that the library refused */
    unsigned early;
    unsigned early_refused;

    struct seen seen;
};

/* Why a flow stopped, when it stopped badly. One buffer, because a flow
 * reports the first thing that went wrong and nothing after it. */
static char trouble[256];

/* The STUN server the flow being opened asks, as `host:port`, or NULL for a
 * stack that asks nobody -- every flow but `FLOW_NAT`, which `main` sets this
 * for from SIPRAL_STUN_SERVER. */
static const char *stun_for_this_flow;

/* The TURN server the flow being opened allocates its media socket's relay
 * on, as `host:port`, with the credential it knows this end by, or NULL for
 * a stack with no TURN server -- every flow but `FLOW_ICE_NAT` run with
 * SIPRAL_TURN_SERVER set, which is scripts/lab.sh's own relay step. */
static const char *turn_for_this_flow;
static const char *turn_user_for_this_flow;
static const char *turn_password_for_this_flow;

/* The codec order the call a flow places is offered with, as
 * `sipral_call_config_t::codecs` takes it, or NULL for the stack's own --
 * every flow but `FLOW_G729`. */
static const char *codecs_for_this_flow;

/* Whether the flow being opened is `FLOW_ICE_NAT`: an account that never
 * registers, calling the other stack straight at its NAT's address, from
 * sockets on ephemeral ports whose STUN answers go straight in. `FLOW_NAT`
 * asks the same STUN server and is none of those things. */
static int calling_a_peer;

static void wrong(const char *what, sipral_status_t status)
{
    if (trouble[0] == '\0') {
        (void)snprintf(trouble, sizeof trouble, "%s: %s", what,
                       sipral_status_name(status));
    }
}

static void wrong_text(const char *what)
{
    if (trouble[0] == '\0') {
        (void)snprintf(trouble, sizeof trouble, "%s", what);
    }
}

/* Everything waiting to go out on the signalling socket. */
static void flush_signalling(struct endpoint *end)
{
    static uint8_t out[DATAGRAM];
    static char destination[SIPRAL_ADDRESS_BYTES];
    for (;;) {
        sipral_transmit_t message;
        struct sockaddr_in to;
        memset(&message, 0, sizeof message);
        message.size = sizeof message;
        message.data = out;
        message.capacity = sizeof out;
        message.destination = destination;
        message.destination_capacity = sizeof destination;
        if (sipral_stack_poll_transmit(end->stack, &message) != SIPRAL_STATUS_OK) {
            return;
        }
        /* nothing left to send, which is how the draining loop ends */
        if (message.len == 0) {
            return;
        }
        if (address_of(destination, &to) == 0) {
            (void)sendto(end->sip_fd, out, message.len, 0,
                         (const struct sockaddr *)&to, sizeof to);
        }
    }
}

/* Everything that has arrived on the signalling socket. */
static void read_signalling(struct endpoint *end, uint64_t now)
{
    static uint8_t in[DATAGRAM];
    for (;;) {
        struct sockaddr_in from;
        socklen_t length = sizeof from;
        char from_text[SIPRAL_ADDRESS_BYTES];
        ssize_t got = recvfrom(end->sip_fd, in, sizeof in, 0,
                               (struct sockaddr *)&from, &length);
        if (got <= 0) {
            return;
        }
        if (address_text(&from, from_text, sizeof from_text) != 0) {
            continue;
        }
        if (end->withhold_stun && stun_for_this_flow != NULL
            && strcmp(from_text, stun_for_this_flow) == 0) {
            if ((size_t)got <= sizeof end->withheld) {
                memcpy(end->withheld, in, (size_t)got);
                end->withheld_len = (size_t)got;
                keep(end->withheld_from, sizeof end->withheld_from, from_text,
                     strlen(from_text));
            }
            continue;
        }
        /* a refusal here is one packet's worth of trouble and no more: an
         * ordinary morning on a public SIP port is a stream of bytes that are
         * not messages, and the ABI's own documentation says to log it and
         * carry on */
        (void)sipral_stack_receive_datagram(
            end->stack, SIPRAL_TRANSPORT_MAIN, in, (size_t)got, from_text,
            strlen(from_text), end->sip_address, strlen(end->sip_address), now);
    }
}

/* One media packet the library handed back, put on the wire. */
static void send_media(struct endpoint *end, const uint8_t *data, size_t len,
                       const char *destination)
{
    struct sockaddr_in to;
    if (len == 0 || address_of(destination, &to) != 0) {
        return;
    }
    (void)sendto(end->rtp_fd, data, len, 0, (const struct sockaddr *)&to, sizeof to);
}

/* Whether `data` is a TURN Refresh request (RFC 8656 §7.2) whose LIFETIME is
 * zero: the one that deletes an allocation. Read off the wire format itself --
 * a 20-byte header with the magic cookie, then type-length-value attributes
 * padded to four bytes -- rather than taken on trust from where it was sent,
 * because an RTCP goodbye leaves through the same queue to the same server
 * when the call's media ran over the relay. */
static int releases_a_relay(const uint8_t *data, size_t len)
{
    size_t at = 20u;
    size_t body;
    if (len < 20u || data[0] != 0x00u || data[1] != 0x04u || data[4] != 0x21u
        || data[5] != 0x12u || data[6] != 0xA4u || data[7] != 0x42u) {
        return 0;
    }
    body = ((size_t)data[2] << 8) | (size_t)data[3];
    if (20u + body > len) {
        return 0;
    }
    while (at + 4u <= 20u + body) {
        unsigned kind = ((unsigned)data[at] << 8) | (unsigned)data[at + 1u];
        size_t size = ((size_t)data[at + 2u] << 8) | (size_t)data[at + 3u];
        if (at + 4u + size > 20u + body) {
            return 0;
        }
        if (kind == 0x000Du && size == 4u) {
            return data[at + 4u] == 0u && data[at + 5u] == 0u && data[at + 6u] == 0u
                   && data[at + 7u] == 0u;
        }
        at += 4u + ((size + 3u) & ~(size_t)3u);
    }
    return 0;
}

/* Count `data`, just sent to `destination`, if it gave a relay back: three
 * seconds after ICE settles on a pair that does not use this end's relay it
 * leaves through `sipral_media_poll_transmit`, and when the call ends through
 * `sipral_stack_poll_farewell`, so both are watched. */
static void note_given_back(struct endpoint *end, const uint8_t *data, size_t len,
                            const char *destination)
{
    if (releases_a_relay(data, len)) {
        end->relays_given_back++;
        keep(end->given_back_to, sizeof end->given_back_to, destination, strlen(destination));
    }
}

/* Everything the media side owes, and everything it is owed.
 *
 * The three-part shape every driver of this ABI needs and `docs/08-ffi.md`
 * spells out: hand in what arrived, take the frame that is due, and drain what
 * is waiting. A driver that skips the last is a call that is up with no audio
 * and no error.
 */
static void run_media(struct endpoint *end, uint64_t now)
{
    static uint8_t in[DATAGRAM];
    static uint8_t out[DATAGRAM];
    static char destination[SIPRAL_ADDRESS_BYTES];
    static int16_t samples[MAX_FRAME_SAMPLES];
    sipral_media_packet_t packet;

    if (end->media == SIPRAL_HANDLE_NONE) {
        return;
    }

    for (;;) {
        struct sockaddr_in from;
        socklen_t length = sizeof from;
        char from_text[SIPRAL_ADDRESS_BYTES];
        uint32_t arrival = 0;
        ssize_t got = recvfrom(end->rtp_fd, in, sizeof in, 0,
                               (struct sockaddr *)&from, &length);
        if (got <= 0) {
            break;
        }
        if (address_text(&from, from_text, sizeof from_text) != 0) {
            continue;
        }
        if (sipral_media_receive(end->media, in, (size_t)got, from_text,
                                 strlen(from_text), now, &arrival)
            != SIPRAL_STATUS_OK) {
            continue;
        }
        if (arrival == SIPRAL_ARRIVAL_QUEUED) {
            end->received++;
        } else if (arrival == SIPRAL_ARRIVAL_DROPPED) {
            end->refused++;
        }
    }

    /* whatever the handshake or the connectivity checks owe the far end,
     * ungated by the frame clock: a record that never leaves is a call that
     * never keys, and a check that never leaves is a call that never chooses
     * a path */
    for (;;) {
        memset(&packet, 0, sizeof packet);
        packet.size = sizeof packet;
        packet.data = out;
        packet.capacity = sizeof out;
        packet.destination = destination;
        packet.destination_capacity = sizeof destination;
        if (sipral_media_poll_transmit(end->media, now, &packet) != SIPRAL_STATUS_OK
            || packet.len == 0) {
            break;
        }
        send_media(end, out, packet.len, destination);
        note_given_back(end, out, packet.len, destination);
    }

    if (now < end->next_frame_ms) {
        return;
    }
    end->next_frame_ms = now + 20u;

    /* the earpiece, first: a frame taken is a frame the buffer may move on */
    {
        size_t written = 0;
        uint32_t source = 0;
        size_t room = end->frame_samples;
        if (room > MAX_FRAME_SAMPLES) {
            room = MAX_FRAME_SAMPLES;
        }
        if (sipral_media_playback(end->media, samples, room, &written, &source)
                == SIPRAL_STATUS_OK
            && source == SIPRAL_PLAYBACK_PACKET
            && loudness(samples, written) >= AUDIBLE) {
            end->audible++;
        }
    }

    /* and the microphone */
    {
        size_t room = end->frame_samples;
        if (room > MAX_FRAME_SAMPLES) {
            room = MAX_FRAME_SAMPLES;
        }
        if (in_spurt(now - end->media_since_ms)) {
            tone(samples, room, end->sample_rate, &end->phase);
        } else {
            memset(samples, 0, room * sizeof samples[0]);
        }
        memset(&packet, 0, sizeof packet);
        packet.size = sizeof packet;
        packet.data = out;
        packet.capacity = sizeof out;
        packet.destination = destination;
        packet.destination_capacity = sizeof destination;
        if (sipral_media_capture(end->media, now, samples, room, &packet)
                == SIPRAL_STATUS_OK
            && packet.len > 0) {
            send_media(end, out, packet.len, destination);
            end->sent++;
            keep(end->media_to, sizeof end->media_to, destination, strlen(destination));
        }
    }

    /* the control traffic RFC 3550 §6.3 schedules, after every frame, as the
     * header says to */
    memset(&packet, 0, sizeof packet);
    packet.size = sizeof packet;
    packet.data = out;
    packet.capacity = sizeof out;
    packet.destination = destination;
    packet.destination_capacity = sizeof destination;
    if (sipral_media_poll_rtcp(end->media, now, &packet) == SIPRAL_STATUS_OK) {
        send_media(end, out, packet.len, destination);
    }
}

/* The RTP socket's own STUN exchange, before the call it is for has media:
 * send what the stack asks from the socket it names, and hand back whatever
 * arrives on it -- the servers' answers, and once the call is placed, what
 * the far end sends before this end holds the call's media handle, its first
 * connectivity checks among them, which the library keeps for the call.
 * `FLOW_NAT` and `FLOW_ICE_NAT` only; on every other flow nothing is asked,
 * and nothing is read from the socket until the media handle exists. */
static void run_stun(struct endpoint *end, uint64_t now)
{
    static uint8_t in[DATAGRAM];
    static uint8_t out[DATAGRAM];
    static char destination[SIPRAL_ADDRESS_BYTES];
    static char source[SIPRAL_ADDRESS_BYTES];
    sipral_status_t taken;

    if (!end->mapping_media || end->media != SIPRAL_HANDLE_NONE) {
        return;
    }
    for (;;) {
        sipral_transmit_t request;
        memset(&request, 0, sizeof request);
        request.size = sizeof request;
        request.data = out;
        request.capacity = sizeof out;
        request.destination = destination;
        request.destination_capacity = sizeof destination;
        request.source = source;
        request.source_capacity = sizeof source;
        if (sipral_stack_poll_stun(end->stack, &request) != SIPRAL_STATUS_OK
            || request.len == 0) {
            break;
        }
        /* the library names the socket, and this harness has one RTP socket:
         * one that named another would be a request asking the wrong
         * question, and is not sent */
        if (strcmp(source, end->rtp_address) != 0) {
            wrong_text("a STUN request named a socket this end never asked about");
            continue;
        }
        send_media(end, out, request.len, destination);
    }
    for (;;) {
        struct sockaddr_in from;
        socklen_t length = sizeof from;
        char from_text[SIPRAL_ADDRESS_BYTES];
        ssize_t got = recvfrom(end->rtp_fd, in, sizeof in, 0,
                               (struct sockaddr *)&from, &length);
        if (got <= 0) {
            break;
        }
        if (address_text(&from, from_text, sizeof from_text) != 0) {
            continue;
        }
        /* anything that is neither a server's answer nor the call's is
         * refused, one datagram's worth */
        taken = sipral_stack_receive_stun(end->stack, in, (size_t)got, from_text,
                                          strlen(from_text), end->rtp_address,
                                          strlen(end->rtp_address), now);
        if (end->call != SIPRAL_HANDLE_NONE) {
            end->early++;
            if (taken != SIPRAL_STATUS_OK) {
                end->early_refused++;
            }
        }
    }
}

/* What a call that has ended still owes: its RTCP goodbye, and the Refresh
 * that gives its relay back, both sent from the call's own socket. Drained
 * after every poll rather than only the ones that ended a call, as the header
 * asks, since a call that turns out not to use its relay queues the Refresh
 * earlier -- then, while its media runs, through `sipral_media_poll_transmit`
 * instead, which `run_media` counts the same way. */
static void run_farewells(struct endpoint *end)
{
    static uint8_t out[DATAGRAM];
    static char destination[SIPRAL_ADDRESS_BYTES];
    for (;;) {
        sipral_handle_t call = SIPRAL_HANDLE_NONE;
        sipral_media_packet_t packet;
        memset(&packet, 0, sizeof packet);
        packet.size = sizeof packet;
        packet.data = out;
        packet.capacity = sizeof out;
        packet.destination = destination;
        packet.destination_capacity = sizeof destination;
        if (sipral_stack_poll_farewell(end->stack, &call, &packet) != SIPRAL_STATUS_OK
            || packet.len == 0) {
            return;
        }
        send_media(end, out, packet.len, destination);
        note_given_back(end, out, packet.len, destination);
    }
}

/* One turn of everything. */
static void pump(struct endpoint *end, uint64_t now)
{
    sipral_poll_result_t result;
    memset(&result, 0, sizeof result);
    result.size = sizeof result;
    (void)sipral_stack_poll(end->stack, now, &result);
    flush_signalling(end);
    read_signalling(end, now);
    run_stun(end, now);
    run_media(end, now);
    run_farewells(end);
    flush_signalling(end);
}

/* Turn the loop until `wanted` says the flow may move on, or until patience
 * runs out. Answers whether it was `wanted` that stopped it. */
static int wait_until(struct endpoint *end, int (*wanted)(const struct endpoint *),
                      unsigned patience_ms)
{
    uint64_t deadline = now_ms() + patience_ms;
    for (;;) {
        uint64_t now = now_ms();
        pump(end, now);
        if (wanted != NULL && wanted(end)) {
            return 1;
        }
        if (now >= deadline) {
            return 0;
        }
        sleep_ms(5);
    }
}

/* -- the conditions a flow waits on --------------------------------------- */

static int registered(const struct endpoint *end)
{
    return end->seen.registration == SIPRAL_REGISTRATION_STATE_REGISTERED
           || end->seen.registration == SIPRAL_REGISTRATION_STATE_FAILED;
}

static int unregistered(const struct endpoint *end)
{
    return end->seen.registration == SIPRAL_REGISTRATION_STATE_UNREGISTERED
           || end->seen.registration == SIPRAL_REGISTRATION_STATE_FAILED;
}

static int answered(const struct endpoint *end)
{
    return end->seen.confirmed || end->seen.ended;
}

static int hung_up(const struct endpoint *end)
{
    return end->seen.ended;
}

static int held(const struct endpoint *end)
{
    return end->seen.held_here || end->seen.ended;
}

static int resumed(const struct endpoint *end)
{
    /* the hold has to have been agreed before its undoing means anything:
     * `held_here` is false before the hold as well as after the resume */
    return (end->seen.held_once && !end->seen.held_here) || end->seen.ended;
}

/* `held`, given up on early if the handshake that keys this call has
 * already failed -- waiting out the rest of the flow's patience for a hold
 * that has nothing left to say would only hide the reason with a timeout. */
static int held_or_unkeyable(const struct endpoint *end)
{
    return held(end) || end->seen.media_failed;
}

/* `resumed`, the same way. */
static int resumed_or_unkeyable(const struct endpoint *end)
{
    return resumed(end) || end->seen.media_failed;
}

/* Real media has arrived -- as opposed to the handshake's own records, which
 * `sipral_media_receive` reports as `SIPRAL_ARRIVAL_HANDSHAKE` and this
 * driver never counts in `received` -- or the handshake has already failed,
 * so there is nothing left this wait could be for. */
static int keyed_media_arrived(const struct endpoint *end)
{
    return end->received > 0 || end->seen.media_failed;
}

static int handed_over(const struct endpoint *end)
{
    return end->seen.transfer_done || end->seen.transfer_failed || end->seen.ended;
}

static int named_back(const struct endpoint *end)
{
    return end->seen.digit_named_back || end->seen.ended;
}

static int info_answered_and_named_back(const struct endpoint *end)
{
    return (end->seen.dtmf_sent && end->seen.digit_named_back) || end->seen.ended;
}

/* The change this end asked for, agreed or refused. */
static int change_settled(const struct endpoint *end)
{
    return end->seen.session_changes > end->changes_before || end->seen.change_refused
           || end->seen.ended;
}

/* `FLOW_NAT`: the STUN server has said where the signalling socket is. */
static int sip_mapped(const struct endpoint *end)
{
    return end->seen.sip_mapped;
}

/* And where the RTP socket is. */
static int media_mapped(const struct endpoint *end)
{
    return end->seen.media_mapped;
}

/* `FLOW_MESSAGE`'s own send reached a final answer, whatever it was. */
static int message_accepted(const struct endpoint *end)
{
    return end->seen.message_sent;
}

/* The lab's own echo dialplan sent a MESSAGE back. */
static int message_echoed(const struct endpoint *end)
{
    return end->seen.message_received;
}

/* `FLOW_MWI`'s own subscription reached a state worth reading: granted, or
 * gone before it was. */
static int subscribed_or_ended(const struct endpoint *end)
{
    return end->seen.subscribed || end->seen.subscription_ended;
}

/* A message-summary NOTIFY arrived -- the first one is the baseline, read
 * before the voicemail call is placed. */
static int mailbox_notified(const struct endpoint *end)
{
    return end->seen.mailbox_notified || end->seen.subscription_ended;
}

/* The mailbox's `new` count, on the latest notification, reads higher than
 * `flow_mwi`'s own baseline. */
static int mailbox_counted(const struct endpoint *end)
{
    return end->seen.mailbox_new_count > end->mailbox_baseline || end->seen.subscription_ended;
}

/* -- opening and closing an end ------------------------------------------- */

/* This run's own entropy, drawn once by `main` before the flow loop and read
 * by every `seeds_for` after that -- a run-scoped global rather than a
 * parameter threaded through `open_endpoint`, for the same reason
 * `trouble` above is one. All zero until `run_entropy` or a parsed
 * `SIPRAL_HARNESS_SEED` fills it. */
static uint8_t g_run_seed[32];

/* Thirty-two octets from the operating system: `getentropy`, falling back to
 * `/dev/urandom` for a libc old enough, or minimal enough, not to have it.
 * Zero on success, -1 if neither worked, `out` left alone. */
static int run_entropy(uint8_t out[32])
{
    FILE *urandom;
    size_t got;
    if (getentropy(out, 32) == 0) {
        return 0;
    }
    urandom = fopen("/dev/urandom", "rb");
    if (urandom == NULL) {
        return -1;
    }
    got = fread(out, 1, 32, urandom);
    (void)fclose(urandom);
    return got == 32 ? 0 : -1;
}

/* One hex digit, either case; -1 for anything else, so a caller can tell a
 * malformed pair from a genuine zero rather than have `sscanf`'s own
 * variable-width match silently accept one. */
static int hex_nibble(char digit, unsigned *out)
{
    if (digit >= '0' && digit <= '9') {
        *out = (unsigned)(digit - '0');
        return 0;
    }
    if (digit >= 'a' && digit <= 'f') {
        *out = (unsigned)(digit - 'a' + 10);
        return 0;
    }
    if (digit >= 'A' && digit <= 'F') {
        *out = (unsigned)(digit - 'A' + 10);
        return 0;
    }
    return -1;
}

/* `SIPRAL_HARNESS_SEED`: 64 hex digits, or nothing parsed and -1. */
static int parse_hex_seed(const char *text, uint8_t out[32])
{
    size_t index;
    if (text == NULL || strlen(text) != 64u) {
        return -1;
    }
    for (index = 0; index < 32u; index++) {
        unsigned high, low;
        if (hex_nibble(text[index * 2u], &high) != 0
            || hex_nibble(text[index * 2u + 1u], &low) != 0) {
            return -1;
        }
        out[index] = (uint8_t)((high << 4u) | low);
    }
    return 0;
}

static void seed_hex(const uint8_t seed[32], char out[65])
{
    size_t index;
    for (index = 0; index < 32u; index++) {
        (void)snprintf(out + index * 2u, 3, "%02x", seed[index]);
    }
}

/* The entropy a flow's stack is given: a fixed pattern per flow, folded by
 * XOR with this run's own entropy (`g_run_seed`, drawn once by `main`).
 *
 * The pattern alone -- fixed, no platform entropy -- is what it was before
 * `main` started drawing `g_run_seed`: reproducible within a run, but the
 * same on every run, so two runs of the same flow sent the same `Call-ID`,
 * the same `From` tag and the same first branch. RFC 3261 §8.1.1.4 wants a
 * `Call-ID` globally unique and §19.3 wants tags random; a proxy that still
 * held the previous run's transaction or dialog answered the new one 482
 * Request Merged, which is what happened running two of this harness's own
 * `call` flow at once against the lab's Kamailio. XOR cannot undo the
 * per-flow variation `which` already gives two flows of one run: `a != b`
 * implies `a ^ r != b ^ r` for the same `r`, so the two still differ, and the
 * ABI's requirement that the signalling and media seeds differ from each
 * other (`docs/20-security-model.md` says why) survives folding the same
 * way.
 *
 * `which` still varies them **per flow**, and that is not decoration. A
 * stack's `Call-ID` for its registration is drawn from the signalling seed
 * once per boot cycle (RFC 3261 §10.2), so six flows from one seed are six
 * registrations that call themselves the same dialogue with a CSeq that
 * starts again from one -- and a registrar that has seen the first refuses
 * the rest as out of order. What that looks like from here is every other
 * flow failing to register for no reason it can see, which is exactly what
 * happened the first time this was run against Asterisk.
 */
static void seeds_for(unsigned which, uint8_t signalling[32], uint8_t media[32])
{
    unsigned index;
    for (index = 0; index < 32u; index++) {
        signalling[index] =
            (uint8_t)((0x11u + index * 7u + which * 29u) ^ g_run_seed[index]);
        media[index] = (uint8_t)((0xF1u - index * 5u + which * 37u) ^ g_run_seed[index]);
    }
}

static void close_endpoint(struct endpoint *end)
{
    if (end->stack != SIPRAL_HANDLE_NONE) {
        (void)sipral_stack_destroy(end->stack);
        end->stack = SIPRAL_HANDLE_NONE;
    }
    if (end->sip_fd >= 0) {
        (void)close(end->sip_fd);
        end->sip_fd = -1;
    }
    if (end->rtp_fd >= 0) {
        (void)close(end->rtp_fd);
        end->rtp_fd = -1;
    }
}

/* Bind the sockets, build the stack, and add the account -- everything a flow
 * needs before it has anything to say. */
static int open_endpoint(struct endpoint *end, unsigned which, const char *server,
                         const struct sockaddr_in *remote, const char *user,
                         const char *pass)
{
    sipral_stack_config_t config;
    sipral_account_config_t account;
    struct sockaddr_in sip_local;
    struct sockaddr_in rtp_local;
    uint8_t signalling_seed[32];
    uint8_t media_seed[32];
    char routable[INET_ADDRSTRLEN];
    char registrar[128];
    char contact[192];
    char registrar_address[SIPRAL_ADDRESS_BYTES];
    sipral_status_t status;

    memset(end, 0, sizeof *end);
    end->sip_fd = -1;
    end->rtp_fd = -1;
    end->seen.marker = MARKER;
    end->server = *remote;
    /* from before the first poll, which is when the signalling socket's
     * first request goes out */
    end->withhold_stun = stun_for_this_flow != NULL && !calling_a_peer;

    if (route_to(remote, routable, sizeof routable) != 0) {
        wrong_text("no route to the lab network");
        return -1;
    }
    /* behind the lab's NAT, at the two ports it moves (NAT_SIP_PORT) */
    end->sip_fd = bind_udp_at(&sip_local, end->withhold_stun ? NAT_SIP_PORT : 0u);
    end->rtp_fd = bind_udp_at(&rtp_local, end->withhold_stun ? NAT_RTP_PORT : 0u);
    if (end->sip_fd < 0 || end->rtp_fd < 0) {
        wrong_text("cannot bind a socket");
        close_endpoint(end);
        return -1;
    }
    /* the wildcard the sockets are bound on is not an address a peer can send
     * to, so what is advertised is the address the route picked */
    (void)snprintf(end->sip_address, sizeof end->sip_address, "%s:%u", routable,
                   (unsigned)ntohs(sip_local.sin_port));
    (void)snprintf(end->rtp_address, sizeof end->rtp_address, "%s:%u", routable,
                   (unsigned)ntohs(rtp_local.sin_port));

    memset(&config, 0, sizeof config);
    config.size = sizeof config;
    config.event_callback = on_event;
    config.event_user_data = &end->seen;
    config.transport = SIPRAL_TRANSPORT_UDP;
    config.bind_address = end->sip_address;
    config.bind_address_len = strlen(end->sip_address);
    seeds_for(which, signalling_seed, media_seed);
    config.entropy = signalling_seed;
    config.entropy_len = sizeof signalling_seed;
    config.media_seed = media_seed;
    config.media_seed_len = sizeof media_seed;
    /* the lab's own catalogue: the two G.711 laws, which is what every server
     * in it offers and what the Rust harness asks for too */
    config.codecs = "PCMU,PCMA";
    config.codecs_len = strlen("PCMU,PCMA");
    config.media_clock_unix_seconds = (uint64_t)time(NULL);
    if (stun_for_this_flow != NULL) {
        config.nat = SIPRAL_NAT_STUN;
        config.stun_server = stun_for_this_flow;
        config.stun_server_len = strlen(stun_for_this_flow);
    }
    /* the relay rides on the STUN path above: the same media socket named
     * with `sipral_stack_nat_map` is given a relay on this server too */
    if (turn_for_this_flow != NULL) {
        config.turn_server = turn_for_this_flow;
        config.turn_server_len = strlen(turn_for_this_flow);
        config.turn_username = turn_user_for_this_flow;
        config.turn_username_len = strlen(turn_user_for_this_flow);
        config.turn_password = turn_password_for_this_flow;
        config.turn_password_len = strlen(turn_password_for_this_flow);
    }

    status = sipral_stack_create(&config, &end->stack);
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_stack_create", status);
        close_endpoint(end);
        return -1;
    }

    /* a peer is called as the address this end is at, and knows it by
     * nothing else: interop/harness/src/ice_nat.rs's own `sip:caller@` */
    if (calling_a_peer) {
        (void)snprintf(end->aor, sizeof end->aor, "sip:%s@%s", user, end->sip_address);
    } else {
        (void)snprintf(end->aor, sizeof end->aor, "sip:%s@%s", user, server);
    }
    (void)snprintf(registrar, sizeof registrar, "sip:%s", server);
    (void)snprintf(contact, sizeof contact, "sip:%s@%s", user, end->sip_address);
    if (address_text(remote, registrar_address, sizeof registrar_address) != 0) {
        wrong_text("the registrar has no address");
        close_endpoint(end);
        return -1;
    }

    memset(&account, 0, sizeof account);
    account.size = sizeof account;
    account.aor = end->aor;
    account.aor_len = strlen(end->aor);
    /* no registrar for a peer: a `registrar_len` of zero is an account that
     * never registers, and whose requests go to `registrar_address` all the
     * same -- here the other stack's NAT, which forwards its SIP port */
    if (!calling_a_peer) {
        account.registrar = registrar;
        account.registrar_len = strlen(registrar);
        account.auth_user = user;
        account.auth_user_len = strlen(user);
        account.auth_password = pass;
        account.auth_password_len = strlen(pass);
        account.expires_seconds = 300u;
    }
    account.contact = contact;
    account.contact_len = strlen(contact);
    account.registrar_address = registrar_address;
    account.registrar_address_len = strlen(registrar_address);

    status = sipral_account_add(end->stack, &account, &end->account);
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_account_add", status);
        close_endpoint(end);
        return -1;
    }
    return 0;
}

/* The media handle of a call that has just been confirmed, and the two numbers
 * every frame after it needs. */
static int open_media(struct endpoint *end, sipral_handle_t call)
{
    sipral_media_info_t info;
    sipral_status_t status = sipral_call_media(end->stack, call, &end->media);
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_call_media", status);
        return -1;
    }
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    status = sipral_media_info(end->media, &info);
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_media_info", status);
        return -1;
    }
    /* asked, never assumed: G.722 samples at a rate its RTP clock does not
     * count in, and a harness that guessed would send half a frame */
    end->frame_samples = info.frame_samples;
    end->sample_rate = info.sample_rate;
    end->media_since_ms = now_ms();
    end->next_frame_ms = end->media_since_ms;
    return 0;
}

/* Place a call at an extension on this server, and give it the RTP socket the
 * endpoint bound. `srtp` is a `SIPRAL_SRTP_*`, or zero for the stack's own
 * policy. */
static int place(struct endpoint *end, const char *server, const char *extension,
                 uint32_t srtp, sipral_handle_t *out_call)
{
    sipral_call_config_t call;
    char target[192];
    sipral_status_t status;
    (void)snprintf(target, sizeof target, "sip:%s@%s", extension, server);
    memset(&call, 0, sizeof call);
    call.size = sizeof call;
    call.target = target;
    call.target_len = strlen(target);
    call.media_address = end->rtp_address;
    call.media_address_len = strlen(end->rtp_address);
    call.srtp = srtp;
    if (codecs_for_this_flow != NULL) {
        call.codecs = codecs_for_this_flow;
        call.codecs_len = strlen(codecs_for_this_flow);
    }
    status = sipral_call_place(end->stack, end->account, &call, out_call, now_ms());
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_call_place", status);
        return -1;
    }
    return 0;
}

/* -- the flows ------------------------------------------------------------ */

enum flow {
    FLOW_REGISTER,
    FLOW_CALL,
    FLOW_HOLD,
    FLOW_BLIND,
    FLOW_ATTENDED,
    FLOW_DTMF,
    FLOW_DTMF_INFO,
    FLOW_SRTP,
    FLOW_HOLD_CODEC_CHANGE,
    FLOW_MESSAGE,
    FLOW_MWI,
    /* 8.6.15: G.729 alone, to Asterisk's echo, as the one endpoint there that
     * allows it -- interop/harness/src/main.rs's own Flow::G729, and in the
     * same place in the run, after message waiting and before DTLS-SRTP. */
    FLOW_G729,
    FLOW_DTLS,
    /* The phone-to-phone peer: interop/harness/src/main.rs's own
     * Flow::PeerSrtp and Flow::PeerDtls, run only when SIPRAL_PEER names
     * baresip -- see runs_against() below. */
    FLOW_PEER_SRTP,
    FLOW_PEER_DTLS,
    /* 8.5.5: registered and calling from behind a NAT, with the stack asking
     * a STUN server where its two sockets appear from. Run only when
     * SIPRAL_STUN_SERVER names one -- scripts/lab.sh's own `nat` step, which
     * also puts this process behind interop/nat's NAT. */
    FLOW_NAT,
    /* 8.5.5: the calling half of two stacks behind two NATs finding each
     * other with full ICE -- interop/harness/src/ice_nat.rs's own `call`,
     * through this ABI, with the Rust harness answering behind the second
     * NAT. With SIPRAL_TURN_SERVER set its media socket also gets a relay,
     * which is scripts/lab.sh's own `turn` step. Run only when SIPRAL_FLOWS
     * names it. */
    FLOW_ICE_NAT,
    FLOW_COUNT
};

static const char *flow_name(enum flow which)
{
    switch (which) {
    case FLOW_REGISTER:
        return "register";
    case FLOW_CALL:
        return "call";
    case FLOW_HOLD:
        return "hold and resume";
    case FLOW_BLIND:
        return "blind transfer";
    case FLOW_ATTENDED:
        return "attended transfer";
    case FLOW_DTMF:
        return "DTMF, RFC 4733";
    case FLOW_DTMF_INFO:
        return "DTMF, SIP INFO";
    case FLOW_SRTP:
        return "SRTP";
    case FLOW_HOLD_CODEC_CHANGE:
        return "hold with a codec change";
    case FLOW_MESSAGE:
        return "MESSAGE, echoed";
    case FLOW_MWI:
        return "message waiting indication";
    case FLOW_G729:
        return "G.729, echoed";
    case FLOW_DTLS:
        return "DTLS-SRTP, held and resumed";
    case FLOW_PEER_SRTP:
        return "SRTP, phone to phone";
    case FLOW_PEER_DTLS:
        return "DTLS-SRTP, phone to phone";
    case FLOW_NAT:
        return "behind a NAT, through STUN";
    case FLOW_ICE_NAT:
        return "full ICE through two NATs, calling";
    case FLOW_COUNT:
    default:
        return "?";
    }
}

/* The name `SIPRAL_FLOWS` selects this flow by, which is the Rust harness's
 * own key for the same flow. */
static const char *flow_key(enum flow which)
{
    switch (which) {
    case FLOW_REGISTER:
        return "register";
    case FLOW_CALL:
        return "call";
    case FLOW_HOLD:
        return "hold";
    case FLOW_BLIND:
        return "blind";
    case FLOW_ATTENDED:
        return "attended";
    case FLOW_DTMF:
        return "dtmf";
    case FLOW_DTMF_INFO:
        return "dtmfinfo";
    case FLOW_SRTP:
        return "srtp";
    case FLOW_HOLD_CODEC_CHANGE:
        return "holdcodec";
    case FLOW_MESSAGE:
        return "message";
    case FLOW_MWI:
        return "mwi";
    case FLOW_G729:
        return "g729";
    case FLOW_DTLS:
        return "dtls";
    case FLOW_PEER_SRTP:
        return "peersrtp";
    case FLOW_PEER_DTLS:
        return "peerdtls";
    case FLOW_NAT:
        return "nat";
    case FLOW_ICE_NAT:
        return "icenat";
    case FLOW_COUNT:
    default:
        return "?";
    }
}

/* Whether `SIPRAL_FLOWS` names this flow: a comma-separated list of keys,
 * compared whole. A substring match would have `hold` select `holdcodec`
 * too, which is not what anybody who typed it meant. */
static int selected(const char *wanted, const char *key)
{
    size_t length = strlen(key);
    const char *at = wanted;
    while (*at != '\0') {
        const char *end;
        const char *stop;
        while (*at == ' ' || *at == ',') {
            at++;
        }
        end = strchr(at, ',');
        if (end == NULL) {
            end = at + strlen(at);
        }
        stop = end;
        while (stop > at && stop[-1] == ' ') {
            stop--;
        }
        if ((size_t)(stop - at) == length && strncmp(at, key, length) == 0) {
            return 1;
        }
        at = end;
    }
    return 0;
}

/* The account a flow places its call as.
 *
 * Four flows have one of their own on Asterisk, and for the reason the Rust
 * harness gives: the SDES endpoint is `labuser-srtp`, so that the plain one
 * every other flow uses stays plain, INFO's own `dtmf_mode` is
 * `labuser-infodtmf`'s, DTLS-SRTP is `labuser-dtls`'s, and message waiting
 * indication is `labuser-mwi`'s. Same defaults, same variables to override
 * them. Only on Asterisk: the proxy knows one user, and FreeSWITCH behind it
 * decides per extension rather than per account. */
static void account_for(enum flow which, const char *server, const char **user,
                        const char **pass)
{
    const char *named = NULL;
    const char *secret = NULL;
    const char *fallback = NULL;
    if (strcmp(server, "asterisk") != 0) {
        return;
    }
    if (which == FLOW_SRTP) {
        named = getenv("SIPRAL_USER_SRTP");
        secret = getenv("SIPRAL_PASS_SRTP");
        fallback = "labuser-srtp";
    } else if (which == FLOW_DTMF_INFO) {
        named = getenv("SIPRAL_USER_INFODTMF");
        secret = getenv("SIPRAL_PASS_INFODTMF");
        fallback = "labuser-infodtmf";
    } else if (which == FLOW_DTLS) {
        named = getenv("SIPRAL_USER_DTLS");
        secret = getenv("SIPRAL_PASS_DTLS");
        fallback = "labuser-dtls";
    } else if (which == FLOW_MWI) {
        /* the one account whose AOR carries `mailboxes=9007@default`
         * (interop/asterisk's own configuration); the plain one every other
         * flow uses stays plain */
        named = getenv("SIPRAL_USER_MWI");
        secret = getenv("SIPRAL_PASS_MWI");
        fallback = "labuser-mwi";
    } else if (which == FLOW_G729) {
        /* the one endpoint that allows G.729, and allows nothing else, so
         * every other flow's offer is answered as it always was */
        named = getenv("SIPRAL_USER_G729");
        secret = getenv("SIPRAL_PASS_G729");
        fallback = "labuser-g729";
    } else {
        return;
    }
    *user = named != NULL && named[0] != '\0' ? named : fallback;
    if (secret != NULL && secret[0] != '\0') {
        *pass = secret;
    }
}

/* Take a binding, and give it back. */
static int flow_register(struct endpoint *end)
{
    sipral_status_t status = sipral_account_register(end->stack, end->account, now_ms());
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_account_register", status);
        return -1;
    }
    if (!wait_until(end, registered, FLOW_PATIENCE_MS)) {
        wrong_text("the registrar never answered");
        return -1;
    }
    if (end->seen.registration != SIPRAL_REGISTRATION_STATE_REGISTERED) {
        wrong_text("the registrar refused the binding");
        return -1;
    }
    /* and given back, because a lab that leaves bindings behind is a lab whose
     * next run inherits them */
    end->seen.registration = SIPRAL_REGISTRATION_STATE_UNKNOWN;
    status = sipral_account_unregister(end->stack, end->account, now_ms());
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_account_unregister", status);
        return -1;
    }
    if (!wait_until(end, unregistered, FLOW_PATIENCE_MS)) {
        wrong_text("the binding was never given back");
        return -1;
    }
    return 0;
}

/* Register, place a call, and wait for it to be answered with media. */
static int up_and_talking(struct endpoint *end, const char *server,
                          const char *extension, uint32_t srtp)
{
    sipral_status_t status = sipral_account_register(end->stack, end->account, now_ms());
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_account_register", status);
        return -1;
    }
    if (!wait_until(end, registered, FLOW_PATIENCE_MS)
        || end->seen.registration != SIPRAL_REGISTRATION_STATE_REGISTERED) {
        wrong_text("not registered, so there is nobody to place a call as");
        return -1;
    }
    if (place(end, server, extension, srtp, &end->call) != 0) {
        return -1;
    }
    if (!wait_until(end, answered, FLOW_PATIENCE_MS)) {
        wrong_text("the call was never answered");
        return -1;
    }
    if (end->seen.ended) {
        wrong_text("the call ended before it was answered");
        return -1;
    }
    if (open_media(end, end->call) != 0) {
        return -1;
    }
    return 0;
}

/* Give up whatever is still open: `flow_mwi`'s own subscription, a call
 * (mostly already hung up, since only `flow_mwi` needs one gone before it can
 * finish), a media socket named for a call that was never placed, and the
 * binding. */
static void finish(struct endpoint *end)
{
    if (end->subscription != SIPRAL_HANDLE_NONE) {
        (void)sipral_subscription_end(end->stack, end->subscription, now_ms());
        (void)wait_until(end, NULL, 400u);
        end->subscription = SIPRAL_HANDLE_NONE;
    }
    if (end->call != SIPRAL_HANDLE_NONE && !end->seen.ended) {
        (void)sipral_call_hangup(end->stack, end->call, now_ms());
        (void)wait_until(end, hung_up, 5000u);
    }
    /* a flow that failed between `sipral_stack_nat_map` and placing its call
     * still holds the socket's relay, which `sipral_stack_destroy` would
     * leave on the TURN server for its whole lifetime: the header asks for
     * every socket still named to be unmapped first, and the Refresh that
     * gives the relay back leaves through `sipral_stack_poll_stun` */
    if (end->mapping_media && end->call == SIPRAL_HANDLE_NONE) {
        (void)sipral_stack_nat_unmap(end->stack, end->rtp_address, strlen(end->rtp_address),
                                     now_ms());
        (void)wait_until(end, NULL, 400u);
    }
    if (end->account != SIPRAL_HANDLE_NONE) {
        (void)sipral_account_unregister(end->stack, end->account, now_ms());
        (void)wait_until(end, NULL, 400u);
    }
}

/* Carry audio for a while, so there is something to judge. */
static void dwell(struct endpoint *end, unsigned millis)
{
    uint64_t deadline = now_ms() + millis;
    while (now_ms() < deadline) {
        pump(end, now_ms());
        sleep_ms(5);
    }
}

/* Whether a flow is run against this server at all.
 *
 * Seven of them only against Asterisk, and the Rust harness does the same for
 * the same reasons: `interop/asterisk/extensions.conf` is the only dialplan in
 * the lab with an extension that names a digit back, the one Asterisk names
 * never came back through the proxy from FreeSWITCH, and the SDES endpoint,
 * the INFO one, the echo extension MESSAGE is sent to, the mailbox message
 * waiting indication watches and the one endpoint that allows G.729 all
 * exist only in Asterisk's own configuration.
 * DTLS-SRTP runs on both, since `interop/freeswitch/lab.xml` answers 9005 as
 * well. `docs/11-testing.md` carries the reasons. A flow is not run where it
 * is known not to pass until somebody has found out why.
 *
 * `for_baresip` gates the two phone-to-phone flows, the same way SIPRAL_PEER gates them
 * in interop/harness/src/main.rs: `server` reads "kamailio" for this run and
 * for the ordinary kamailio-to-freeswitch one alike, so the server name alone
 * cannot tell them apart, and only a run that asked for the peer explicitly
 * may dial an account interop/asterisk knows nothing about.
 */
static int runs_against(enum flow which, const char *server, int for_baresip)
{
    switch (which) {
    case FLOW_DTMF:
    case FLOW_DTMF_INFO:
    case FLOW_SRTP:
    case FLOW_HOLD_CODEC_CHANGE:
    case FLOW_MESSAGE:
    case FLOW_MWI:
    case FLOW_G729:
        return strcmp(server, "asterisk") == 0;
    case FLOW_PEER_SRTP:
    case FLOW_PEER_DTLS:
        return for_baresip;
    case FLOW_ICE_NAT: {
        /* only when named, and with a STUN server to ask: the far end is a
         * second stack behind a second NAT, which only scripts/lab.sh's own
         * ICE steps start, and `server` is that NAT's address rather than a
         * server's name */
        const char *wanted = getenv("SIPRAL_FLOWS");
        const char *stun = getenv("SIPRAL_STUN_SERVER");
        return wanted != NULL && selected(wanted, "icenat") && stun != NULL
               && stun[0] != '\0';
    }
    case FLOW_NAT: {
        /* only a run that named a STUN server, which is only scripts/lab.sh's
         * own `nat` step: anywhere else there is no NAT in front of this end
         * and nothing for the flow to prove */
        const char *stun = getenv("SIPRAL_STUN_SERVER");
        return stun != NULL && stun[0] != '\0';
    }
    case FLOW_DTLS:
    case FLOW_REGISTER:
    case FLOW_CALL:
    case FLOW_HOLD:
    case FLOW_BLIND:
    case FLOW_ATTENDED:
    case FLOW_COUNT:
    default:
        return 1;
    }
}

/* Which extension a flow calls.
 *
 * The digits need one of their own: `interop/asterisk/extensions.conf`
 * answers 9003 with `Read()` and names the digit straight back with
 * `SendDTMF()`, which is what makes the round trip provable from this end,
 * and it goes back over INFO to an endpoint whose `dtmf_mode` is INFO. SRTP
 * has 9004, DTLS-SRTP 9005 — its own number so a capture shows which leg
 * keyed by handshake without reading the SDP — and `FLOW_MWI`'s own mailbox
 * extension is 9007, whose hangup handler is what leaves the message this
 * flow watches for; `FLOW_G729` calls the echo, 9008 (`Answer(); Echo();`),
 * so what it hears is its own tone back. FLOW_PEER_SRTP and FLOW_PEER_DTLS
 * are the same shape against the phone-to-phone peer: one AOR per media policy
 * (interop/baresip/config/accounts) rather than one per extension number,
 * since baresip is a single client and not a dialplan. Every other flow calls
 * the extension the command line named, and a bridge answers it -- FLOW_CALL
 * and FLOW_HOLD reused against that same peer take scripts/lab.sh's own
 * baresip AOR this way, exactly as interop/harness/src/main.rs's
 * `call_extension` does; `FLOW_MESSAGE` places no call at all, and
 * `flow_message` names its own extension (9006) directly.
 */
static const char *extension_for(enum flow which, const char *named)
{
    switch (which) {
    case FLOW_DTMF:
    case FLOW_DTMF_INFO:
        return "9003";
    case FLOW_SRTP:
        return "9004";
    case FLOW_DTLS:
        return "9005";
    case FLOW_MWI:
        return "9007";
    case FLOW_G729:
        return "9008";
    case FLOW_PEER_SRTP:
        return "baresip-srtp";
    case FLOW_PEER_DTLS:
        return "baresip-dtls";
    case FLOW_REGISTER:
    case FLOW_CALL:
    case FLOW_HOLD:
    case FLOW_BLIND:
    case FLOW_ATTENDED:
    case FLOW_HOLD_CODEC_CHANGE:
    case FLOW_MESSAGE:
    case FLOW_NAT:
    case FLOW_ICE_NAT:
    case FLOW_COUNT:
    default:
        return named;
    }
}

/* Whether the call's media runs under a key, asked of the library. */
static int secured(const struct endpoint *end)
{
    sipral_media_info_t info;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    return sipral_media_info(end->media, &info) == SIPRAL_STATUS_OK && info.secured != 0;
}

/* Whether the DTLS-SRTP handshake that keys this call has failed, filling
 * `trouble` with its reason if so.
 *
 * `SIPRAL_EVENT_KIND_MEDIA_FAILED` leaves the call itself up -- nothing else
 * says the handshake went wrong -- so this is checked after every wait
 * `FLOW_DTLS` takes, and the flow ends at once on the first one that finds it
 * true rather than reporting whatever timed out next as if it were the
 * fault. */
static int keying_failed(const struct endpoint *end)
{
    if (!end->seen.media_failed) {
        return 0;
    }
    if (trouble[0] == '\0') {
        (void)snprintf(trouble, sizeof trouble, "the DTLS-SRTP handshake failed: %s",
                       end->seen.fault);
    }
    return 1;
}

/* The SRTP policy a flow places its call with -- a `SIPRAL_SRTP_*`, or zero
 * for the stack's own default, which every flow but these two takes. */
static uint32_t srtp_for(enum flow which)
{
    switch (which) {
    case FLOW_SRTP:
    case FLOW_PEER_SRTP:
        return (uint32_t)SIPRAL_SRTP_REQUIRED;
    case FLOW_DTLS:
    case FLOW_PEER_DTLS:
        return (uint32_t)SIPRAL_SRTP_DTLS_REQUIRED;
    case FLOW_REGISTER:
    case FLOW_CALL:
    case FLOW_HOLD:
    case FLOW_BLIND:
    case FLOW_ATTENDED:
    case FLOW_DTMF:
    case FLOW_DTMF_INFO:
    case FLOW_HOLD_CODEC_CHANGE:
    case FLOW_MESSAGE:
    case FLOW_MWI:
    case FLOW_G729:
    case FLOW_NAT:
    case FLOW_ICE_NAT:
    case FLOW_COUNT:
    default:
        return 0u;
    }
}

/* Register, and send a MESSAGE out of any dialog to the lab's own echo
 * extension (RFC 3428 §3). Both halves are waited for -- this end's own send
 * answered with success, and the dialplan's own MESSAGE arriving back --
 * whichever the callback saw first, since it remembers what happened
 * regardless of when this end asks about it.
 *
 * Placed apart from `up_and_talking`, the way `flow_register` is: no call is
 * placed at all.
 */
static int flow_message(struct endpoint *end, const char *server)
{
    char target[192];
    sipral_status_t status;
    sipral_handle_t sent = SIPRAL_HANDLE_NONE;

    status = sipral_account_register(end->stack, end->account, now_ms());
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_account_register", status);
        return -1;
    }
    if (!wait_until(end, registered, FLOW_PATIENCE_MS)
        || end->seen.registration != SIPRAL_REGISTRATION_STATE_REGISTERED) {
        wrong_text("not registered, so there is nobody to send a MESSAGE as");
        return -1;
    }

    (void)snprintf(target, sizeof target, "sip:9006@%s", server);
    status = sipral_account_message(end->stack, end->account, target, strlen(target),
                                    "text/plain", strlen("text/plain"),
                                    (const uint8_t *)MESSAGE_BODY, strlen(MESSAGE_BODY),
                                    &sent, now_ms());
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_account_message", status);
        return -1;
    }
    if (!wait_until(end, message_accepted, FLOW_PATIENCE_MS)) {
        wrong_text("the MESSAGE was never answered");
        return -1;
    }
    if (end->seen.message_sent_status != 200u && end->seen.message_sent_status != 202u) {
        (void)snprintf(trouble, sizeof trouble, "the MESSAGE was answered %u",
                       (unsigned)end->seen.message_sent_status);
        return -1;
    }
    if (!wait_until(end, message_echoed, FLOW_PATIENCE_MS)) {
        wrong_text("no MESSAGE came back");
        return -1;
    }
    return 0;
}

/* Subscribe to this account's own mailbox (RFC 3842), place a call into the
 * lab's own voicemail extension, and watch the mailbox's `new` count climb
 * once Asterisk's own MWI support reports the message the call left.
 *
 * Placed apart from `up_and_talking`, and unlike every flow that uses it:
 * the subscription has to be granted and its first notification read -- the
 * baseline, before anything is left in the mailbox -- before there is
 * anything to place a call for, and the call has to be hung up from here
 * rather than left for `finish` to close, since the hangup is what makes the
 * dialplan announce the message and this flow still has a NOTIFY to wait for
 * after it.
 */
static int flow_mwi(struct endpoint *end, const char *server)
{
    sipral_subscribe_config_t watch;
    sipral_status_t status;

    status = sipral_account_register(end->stack, end->account, now_ms());
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_account_register", status);
        return -1;
    }
    if (!wait_until(end, registered, FLOW_PATIENCE_MS)
        || end->seen.registration != SIPRAL_REGISTRATION_STATE_REGISTERED) {
        wrong_text("not registered, so there is no mailbox to watch as");
        return -1;
    }

    memset(&watch, 0, sizeof watch);
    watch.size = sizeof watch;
    watch.target = end->aor;
    watch.target_len = strlen(end->aor);
    watch.package = "message-summary";
    watch.package_len = strlen("message-summary");
    status = sipral_account_subscribe(end->stack, end->account, &watch, &end->subscription,
                                      now_ms());
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_account_subscribe", status);
        return -1;
    }
    if (!wait_until(end, subscribed_or_ended, FLOW_PATIENCE_MS) || end->seen.subscription_ended) {
        wrong_text("the message-summary subscription was never granted");
        return -1;
    }

    /* the mailbox's own count, read before anything is left in it: the claim
     * below is that a later notification reads higher than this, not that it
     * starts at zero -- an earlier run may have left mail behind */
    if (!wait_until(end, mailbox_notified, FLOW_PATIENCE_MS) || end->seen.subscription_ended) {
        wrong_text("no message-summary notification ever arrived");
        return -1;
    }
    end->mailbox_baseline = end->seen.mailbox_new_count;

    if (place(end, server, extension_for(FLOW_MWI, NULL), 0u, &end->call) != 0) {
        return -1;
    }
    if (!wait_until(end, answered, FLOW_PATIENCE_MS)) {
        wrong_text("the voicemail call was never answered");
        return -1;
    }
    if (end->seen.ended) {
        wrong_text("the voicemail call ended before it was answered");
        return -1;
    }
    if (open_media(end, end->call) != 0) {
        return -1;
    }
    /* a plain call carrying audio, the same as `FLOW_CALL`'s own dwell --
     * long enough for the dialplan on the far end to have something to hang
     * up on */
    dwell(end, DWELL_MS);
    status = sipral_call_hangup(end->stack, end->call, now_ms());
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_call_hangup", status);
        return -1;
    }
    if (!wait_until(end, hung_up, FLOW_PATIENCE_MS)) {
        wrong_text("the voicemail call never ended");
        return -1;
    }

    if (!wait_until(end, mailbox_counted, FLOW_PATIENCE_MS) || end->seen.subscription_ended) {
        wrong_text("the mailbox's new-message count never went up after the voicemail was left");
        return -1;
    }
    return 0;
}

/* `address`, a `host:port`, split in two: the host into `host`, and a pointer
 * to the port returned, or NULL for text with no port in it. */
static const char *split_address(const char *address, char *host, size_t room)
{
    const char *colon = strrchr(address, ':');
    size_t length;
    if (colon == NULL) {
        return NULL;
    }
    length = (size_t)(colon - address);
    if (length >= room) {
        return NULL;
    }
    memcpy(host, address, length);
    host[length] = '\0';
    return colon + 1;
}

/* Whether two `host:port`s name different ports: the NAT moved this one. */
static int port_moved(const char *local, const char *public_address)
{
    char host[SIPRAL_ADDRESS_BYTES];
    const char *before = split_address(local, host, sizeof host);
    const char *after = split_address(public_address, host, sizeof host);
    return before != NULL && after != NULL && strcmp(before, after) != 0;
}

/* Register and call from behind a NAT, with the stack asking a STUN server
 * where each of its two sockets appears from, and check that the far end was
 * told what the server said -- not what this end is bound to.
 *
 * Three things make the check mean something, and each is checked rather
 * than assumed. The server's answer differs from the socket's own address,
 * in the host and in the port (NAT_SIP_PORT), so there is a translation in
 * the way and a Contact or a `c=`/`m=` that took either half from the socket
 * would name somewhere the lab cannot reach. The registrar's own 200
 * lists the public address among the bindings it holds. And the tone comes
 * back: Asterisk sends its audio where `c=` says and nowhere else
 * (`rtp_symmetric` is off in interop/asterisk), so audio arriving at all is
 * audio that found the address STUN put there. A hold then shows the
 * description itself, which only a session change hands back through this
 * ABI, and proves the re-offer kept the public address too.
 */
static int flow_nat(struct endpoint *end, const char *server, const char *extension)
{
    char host[SIPRAL_ADDRESS_BYTES];
    char binding[SIPRAL_ADDRESS_BYTES + 2];
    char c_line[SIPRAL_ADDRESS_BYTES + 16];
    char m_line[32];
    const char *port;
    sipral_status_t status;

    /* first the REGISTER a phone sends before a slow STUN server has
     * answered: the signalling socket's request went out on the first poll,
     * on the SIP socket itself, and its answers are held back until the
     * registrar holds the private address */
    status = sipral_account_register(end->stack, end->account, now_ms());
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_account_register", status);
        return -1;
    }
    if (!wait_until(end, registered, FLOW_PATIENCE_MS)
        || end->seen.registration != SIPRAL_REGISTRATION_STATE_REGISTERED) {
        wrong_text("not registered at the private address");
        return -1;
    }
    (void)snprintf(binding, sizeof binding, "@%s>", end->sip_address);
    if (strstr(end->seen.registered_with, binding) == NULL) {
        wrong_text("the registrar never held the private binding, and the run proves nothing "
                   "about taking it back");
        printf("%s\n", end->seen.registered_with);
        return -1;
    }

    /* now the answer, as if it had just arrived: the account moves, and the
     * REGISTER that says so has to take the private binding back */
    end->withhold_stun = 0;
    end->seen.registration = 0;
    end->seen.registered_with[0] = '\0';
    if (end->withheld_len > 0) {
        (void)sipral_stack_receive_datagram(
            end->stack, SIPRAL_TRANSPORT_MAIN, end->withheld, end->withheld_len,
            end->withheld_from, strlen(end->withheld_from), end->sip_address,
            strlen(end->sip_address), now_ms());
    }
    if (!wait_until(end, sip_mapped, FLOW_PATIENCE_MS)) {
        wrong_text("the STUN server never said where the signalling socket is");
        return -1;
    }
    if (end->seen.sip_mapping != SIPRAL_NAT_MAPPING_LEARNED) {
        wrong_text("the STUN server did not answer for the signalling socket");
        return -1;
    }
    if (strcmp(end->seen.sip_public, end->sip_address) == 0) {
        wrong_text("the STUN server saw the signalling socket at its own address: nothing "
                   "translates in front of this end, and the run proves nothing");
        return -1;
    }
    if (!port_moved(end->sip_address, end->seen.sip_public)) {
        wrong_text("the NAT kept the signalling socket's port: a Contact with the socket's own "
                   "port would pass for right, and the run proves nothing about the port");
        return -1;
    }
    printf("  nat   signalling %s appears as %s\n", end->sip_address, end->seen.sip_public);
    if (end->seen.sip_accounts_moved != 1u) {
        wrong_text("the mapping event does not count the one account it moved");
        return -1;
    }

    if (!wait_until(end, registered, FLOW_PATIENCE_MS)
        || end->seen.registration != SIPRAL_REGISTRATION_STATE_REGISTERED) {
        wrong_text("not registered again at the public address");
        return -1;
    }
    (void)snprintf(binding, sizeof binding, "@%s>", end->seen.sip_public);
    if (strstr(end->seen.registered_with, binding) == NULL) {
        wrong_text("the registrar's own 200 does not list the public address among its "
                   "bindings");
        printf("%s\n", end->seen.registered_with);
        return -1;
    }
    (void)snprintf(binding, sizeof binding, "@%s>", end->sip_address);
    if (strstr(end->seen.registered_with, binding) != NULL) {
        wrong_text("the registrar holds a binding to the private address as well");
        return -1;
    }

    /* the RTP socket next, before the call: it is this end's, and the stack
     * can only ask about a socket it has been told of */
    status = sipral_stack_nat_map(end->stack, end->rtp_address, strlen(end->rtp_address),
                                  now_ms());
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_stack_nat_map", status);
        return -1;
    }
    end->mapping_media = 1;
    if (!wait_until(end, media_mapped, FLOW_PATIENCE_MS)
        || end->seen.media_mapping != SIPRAL_NAT_MAPPING_LEARNED) {
        wrong_text("the STUN server never said where the RTP socket is");
        return -1;
    }
    if (strcmp(end->seen.media_public, end->rtp_address) == 0) {
        wrong_text("the STUN server saw the RTP socket at its own address");
        return -1;
    }
    if (!port_moved(end->rtp_address, end->seen.media_public)) {
        wrong_text("the NAT kept the RTP socket's port, and the run proves nothing about the "
                   "m= port");
        return -1;
    }
    printf("  nat   media %s appears as %s\n", end->rtp_address, end->seen.media_public);

    if (place(end, server, extension, 0u, &end->call) != 0) {
        return -1;
    }
    if (!wait_until(end, answered, FLOW_PATIENCE_MS)) {
        wrong_text("the call from behind the NAT was never answered");
        return -1;
    }
    if (end->seen.ended) {
        wrong_text("the call from behind the NAT ended before it was answered");
        return -1;
    }
    if (open_media(end, end->call) != 0) {
        return -1;
    }
    /* audio first: Asterisk sends it only where the INVITE's `c=` and `m=`
     * said, so a tone that comes back at all came back to the address STUN
     * put there -- the private one is on a network Asterisk has no route to */
    dwell(end, DWELL_MS);
    if (end->audible == 0) {
        wrong_text("nothing audible came back to the address the offer named");
        return -1;
    }

    /* then a hold, because a session change is where this ABI hands an
     * application its own description back, and a re-offer is the one that
     * must not forget the public address: the call's second description is
     * written from its first */
    status = sipral_call_hold(end->stack, end->call, now_ms());
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_call_hold", status);
        return -1;
    }
    if (!wait_until(end, held, FLOW_PATIENCE_MS) || end->seen.ended) {
        wrong_text("the hold was never agreed");
        return -1;
    }
    port = split_address(end->seen.media_public, host, sizeof host);
    if (port == NULL) {
        wrong_text("the media socket's public address is not a host and a port");
        return -1;
    }
    (void)snprintf(c_line, sizeof c_line, "c=IN IP4 %s\r\n", host);
    (void)snprintf(m_line, sizeof m_line, "m=audio %s ", port);
    if (strstr(end->seen.local_sdp, c_line) == NULL
        || strstr(end->seen.local_sdp, m_line) == NULL) {
        wrong_text("the re-offer does not name the address the STUN server reported");
        printf("%s\n", end->seen.local_sdp);
        return -1;
    }
    status = sipral_call_resume(end->stack, end->call, now_ms());
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_call_resume", status);
        return -1;
    }
    if (!wait_until(end, resumed, FLOW_PATIENCE_MS) || end->seen.ended) {
        wrong_text("the resume was never agreed");
        return -1;
    }
    dwell(end, 1000u);
    return 0;
}

/* Whether two `host:port`s name the same host, whatever their ports. */
static int same_host(const char *one, const char *other)
{
    char first[SIPRAL_ADDRESS_BYTES];
    char second[SIPRAL_ADDRESS_BYTES];
    return split_address(one, first, sizeof first) != NULL
           && split_address(other, second, sizeof second) != NULL
           && strcmp(first, second) == 0;
}

/* ICE chose a path, or the call has nothing left to choose one for. */
static int path_settled(const struct endpoint *end)
{
    return end->seen.path_chosen || end->seen.media_failed || end->seen.ended;
}

/* The media socket's mapping is in, and its relay's outcome too when a TURN
 * server was named: before both, a call on the socket is refused. */
static int media_ready(const struct endpoint *end)
{
    return end->seen.media_mapped && (turn_for_this_flow == NULL || end->seen.relay_seen);
}

/* The calling half of two stacks behind two NATs finding each other with full
 * ICE, through this ABI: interop/harness/src/ice_nat.rs's own `call`, with the
 * Rust harness's `answer` behind the second NAT.
 *
 * The media socket is named with `sipral_stack_nat_map` and the call waits for
 * what coturn said about it -- where it appears from, and with a TURN server
 * named, the relay allocated for it -- since the call's description is written
 * from both. Then a call under `SIPRAL_ICE_REQUIRED` to `extension` at
 * `server`, the callee's NAT, which forwards its SIP port and nothing else; a
 * path chosen, the other end's tone heard on it, and the path judged by where
 * the library addresses this end's audio afterwards: through the TURN server
 * when one was named, since the lab's relay step has blocked every other path,
 * and at the callee's NAT otherwise. This end hangs up, and with a relay the
 * Refresh of lifetime zero that gives it back has to have left for the TURN
 * server -- through `sipral_media_poll_transmit` when ICE settled on a pair
 * that does not use it, through `sipral_stack_poll_farewell` when the call's
 * end is what released it. coturn's own log is scripts/lab.sh's half of that
 * check.
 */
static int flow_ice_nat(struct endpoint *end, const char *server, const char *extension)
{
    sipral_call_config_t call;
    char target[192];
    char callee_nat[SIPRAL_ADDRESS_BYTES] = "?";
    uint64_t mapping_from;
    uint64_t offered;
    sipral_status_t status;

    mapping_from = now_ms();
    status = sipral_stack_nat_map(end->stack, end->rtp_address, strlen(end->rtp_address),
                                  mapping_from);
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_stack_nat_map", status);
        return -1;
    }
    end->mapping_media = 1;
    if (!wait_until(end, media_ready, FLOW_PATIENCE_MS)) {
        wrong_text(end->seen.media_mapped ? "the TURN server never said whether there is a relay"
                                          : "the STUN server never said where the media socket "
                                            "is");
        return -1;
    }
    if (end->seen.media_mapping != SIPRAL_NAT_MAPPING_LEARNED) {
        wrong_text("the STUN server did not answer for the media socket");
        return -1;
    }
    if (strcmp(end->seen.media_public, end->rtp_address) == 0) {
        wrong_text("the STUN server saw the media socket at its own address: there is no NAT in "
                   "the way, and the run proves nothing");
        return -1;
    }
    if (turn_for_this_flow != NULL) {
        if (end->seen.relay_outcome != SIPRAL_NAT_RELAY_ALLOCATED) {
            (void)snprintf(trouble, sizeof trouble, "%s gave no relay (%u): %s",
                           turn_for_this_flow, (unsigned)end->seen.relay_code,
                           end->seen.relay_reason);
            return -1;
        }
        printf("  ice   media %s appears as %s, relay %s allocated in %u ms\n",
               end->rtp_address, end->seen.media_public, end->seen.relayed,
               (unsigned)(end->seen.relay_at_ms - mapping_from));
    } else {
        printf("  ice   media %s appears as %s\n", end->rtp_address, end->seen.media_public);
    }

    (void)snprintf(target, sizeof target, "sip:%s@%s", extension, server);
    memset(&call, 0, sizeof call);
    call.size = sizeof call;
    call.target = target;
    call.target_len = strlen(target);
    call.media_address = end->rtp_address;
    call.media_address_len = strlen(end->rtp_address);
    call.ice = SIPRAL_ICE_REQUIRED;
    offered = now_ms();
    status = sipral_call_place(end->stack, end->account, &call, &end->call, offered);
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_call_place", status);
        return -1;
    }
    if (!wait_until(end, answered, FLOW_PATIENCE_MS)) {
        wrong_text("the call was never answered");
        return -1;
    }
    if (end->seen.ended) {
        wrong_text("the call ended before it was answered");
        return -1;
    }
    if (open_media(end, end->call) != 0) {
        return -1;
    }

    (void)wait_until(end, path_settled, ICE_PATIENCE_MS);
    if (end->seen.media_failed) {
        (void)snprintf(trouble, sizeof trouble, "the media failed: %s", end->seen.fault);
        return -1;
    }
    if (!end->seen.path_chosen) {
        (void)snprintf(trouble, sizeof trouble,
                       "no path was ever chosen (%u sent, %u back): the far end answered no "
                       "check",
                       end->sent, end->received);
        return -1;
    }
    dwell(end, ICE_DWELL_MS);
    if (end->seen.ended) {
        wrong_text("the call ended while the tone was running on its path");
        return -1;
    }
    if (end->audible < ICE_AUDIBLE) {
        (void)snprintf(trouble, sizeof trouble,
                       "a path was chosen, sending to %s, but only %u frame(s) of the tone "
                       "came back (%u sent, %u back, %u refused)",
                       end->media_to, end->audible, end->sent, end->received, end->refused);
        return -1;
    }
    /* with the direct path blocked, audio addressed anywhere but the TURN
     * server -- this end's own relay, or the far end's relayed address on the
     * same server -- is audio the block let through, and proves nothing
     * about the relay; without one, the only address on the callee's side
     * this end can reach is its NAT's */
    if (turn_for_this_flow != NULL && !same_host(end->media_to, turn_for_this_flow)) {
        (void)snprintf(trouble, sizeof trouble,
                       "the path sends to %s, which does not go through the TURN server at %s",
                       end->media_to, turn_for_this_flow);
        return -1;
    }
    if (turn_for_this_flow == NULL
        && (address_text(&end->server, callee_nat, sizeof callee_nat) != 0
            || !same_host(end->media_to, callee_nat))) {
        (void)snprintf(trouble, sizeof trouble,
                       "the path sends to %s, which is not the callee's NAT at %s",
                       end->media_to, callee_nat);
        return -1;
    }
    printf("  ice   path sends to %s, chosen %u ms after the offer and %u ms after the answer\n",
           end->media_to, (unsigned)(end->seen.path_chosen_at_ms - offered),
           (unsigned)(end->seen.path_chosen_at_ms > end->seen.confirmed_at_ms
                          ? end->seen.path_chosen_at_ms - end->seen.confirmed_at_ms
                          : 0u));
    printf("  ice   %u datagram(s) on the media socket before its media handle, %u of them "
           "refused\n",
           end->early, end->early_refused);

    status = sipral_call_hangup(end->stack, end->call, now_ms());
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_call_hangup", status);
        return -1;
    }
    if (!wait_until(end, hung_up, FLOW_PATIENCE_MS)) {
        wrong_text("the call never ended");
        return -1;
    }
    if (turn_for_this_flow != NULL) {
        /* the farewell queue is drained on every turn of the loop; a moment
         * more gives the Refresh its turn after the call's own end */
        dwell(end, 500u);
        if (end->relays_given_back == 0) {
            wrong_text("the call ended and its relay was never given back: no Refresh of "
                       "lifetime zero left this end");
            return -1;
        }
        if (!same_host(end->given_back_to, turn_for_this_flow)) {
            (void)snprintf(trouble, sizeof trouble,
                           "the relay's Refresh of lifetime zero went to %s, not to the TURN "
                           "server at %s",
                           end->given_back_to, turn_for_this_flow);
            return -1;
        }
        printf("  ice   relay given back: a Refresh of lifetime zero to %s\n",
               end->given_back_to);
    }
    return 0;
}

static int run_flow(enum flow which, struct endpoint *end, const char *server,
                    const char *extension, const char *other)
{
    if (which == FLOW_REGISTER) {
        return flow_register(end);
    }
    if (which == FLOW_NAT) {
        return flow_nat(end, server, extension);
    }
    if (which == FLOW_ICE_NAT) {
        return flow_ice_nat(end, server, extension);
    }
    if (which == FLOW_MESSAGE) {
        return flow_message(end, server);
    }
    if (which == FLOW_MWI) {
        return flow_mwi(end, server);
    }
    if (up_and_talking(end, server, extension_for(which, extension), srtp_for(which))
        != 0) {
        return -1;
    }

    switch (which) {
    case FLOW_CALL:
        dwell(end, DWELL_MS);
        break;

    case FLOW_SRTP:
    case FLOW_PEER_SRTP:
        /* the same tone as the plain call, and judged the same way: a stream
         * that agreed a key and never decrypted a frame is the failure this
         * flow exists to find, and it looks like silence. FLOW_PEER_SRTP is
         * this same case against the phone-to-phone peer instead of
         * Asterisk -- extension_for() and srtp_for() already point it at
         * that peer's own SRTP account, so nothing below needs to know
         * which one it is running against */
        dwell(end, DWELL_MS);
        if (!secured(end)) {
            wrong_text("the call connected but never ran under SDES");
            return -1;
        }
        break;

    case FLOW_HOLD: {
        sipral_status_t status;
        dwell(end, 500u);
        status = sipral_call_hold(end->stack, end->call, now_ms());
        if (status != SIPRAL_STATUS_OK) {
            wrong("sipral_call_hold", status);
            return -1;
        }
        if (!wait_until(end, held, FLOW_PATIENCE_MS) || end->seen.ended) {
            wrong_text("the hold was never agreed");
            return -1;
        }
        status = sipral_call_resume(end->stack, end->call, now_ms());
        if (status != SIPRAL_STATUS_OK) {
            wrong("sipral_call_resume", status);
            return -1;
        }
        if (!wait_until(end, resumed, FLOW_PATIENCE_MS) || end->seen.ended) {
            wrong_text("the resume was never agreed");
            return -1;
        }
        break;
    }

    case FLOW_BLIND: {
        char target[192];
        sipral_status_t status;
        /* not straight into the REFER: a call the far end has only just
         * answered is a call its own state machine is still settling, and a
         * transfer that arrives inside that window is refused for a reason
         * that has nothing to do with transfers */
        dwell(end, 1500u);
        (void)snprintf(target, sizeof target, "sip:%s@%s", other, server);
        status = sipral_call_transfer(end->stack, end->call, target,
                                      strlen(target), now_ms());
        if (status != SIPRAL_STATUS_OK) {
            wrong("sipral_call_transfer", status);
            return -1;
        }
        if (!wait_until(end, handed_over, FLOW_PATIENCE_MS)) {
            wrong_text("the transfer was never answered");
            return -1;
        }
        if (end->seen.transfer_failed) {
            wrong_text("the far end refused the transfer");
            return -1;
        }
        break;
    }

    case FLOW_ATTENDED: {
        sipral_status_t status;
        dwell(end, 500u);
        /* the second leg: placing it is itself the settling wait the blind
         * flow has to take deliberately */
        if (place(end, server, other, 0u, &end->consulted) != 0) {
            return -1;
        }
        end->seen.confirmed = 0;
        if (!wait_until(end, answered, FLOW_PATIENCE_MS) || end->seen.ended) {
            wrong_text("the consultation was never answered");
            return -1;
        }
        status = sipral_call_transfer_to(end->stack, end->call, end->consulted,
                                         now_ms());
        if (status != SIPRAL_STATUS_OK) {
            wrong("sipral_call_transfer_to", status);
            return -1;
        }
        if (!wait_until(end, handed_over, FLOW_PATIENCE_MS)) {
            wrong_text("the attended transfer was never answered");
            return -1;
        }
        if (end->seen.transfer_failed) {
            wrong_text("the far end refused the attended transfer");
            return -1;
        }
        break;
    }

    case FLOW_DTMF: {
        sipral_status_t status;
        dwell(end, 500u);
        status = sipral_call_send_dtmf(end->stack, end->call, TEST_DIGIT,
                                       strlen(TEST_DIGIT), SIPRAL_DTMF_RTP,
                                       DIGIT_MS, now_ms());
        if (status != SIPRAL_STATUS_OK) {
            wrong("sipral_call_send_dtmf", status);
            return -1;
        }
        /* the lab's dialplan names the digit back as audio, so the wait is for
         * the far end to say it heard, not for this end to finish sending */
        if (!wait_until(end, named_back, FLOW_PATIENCE_MS)) {
            wrong_text("the digit was never named back");
            return -1;
        }
        if (end->seen.ended) {
            wrong_text("the call ended before the digit was named back");
            return -1;
        }
        break;
    }

    case FLOW_DTMF_INFO: {
        sipral_status_t status;
        dwell(end, 500u);
        status = sipral_call_send_dtmf(end->stack, end->call, TEST_DIGIT,
                                       strlen(TEST_DIGIT), SIPRAL_DTMF_INFO_RELAY, 0u,
                                       now_ms());
        if (status != SIPRAL_STATUS_OK) {
            wrong("sipral_call_send_dtmf", status);
            return -1;
        }
        /* both halves: the far end answered the INFO, and the endpoint's own
         * echo named the digit back -- over INFO too, which exercises this
         * end's receiving half against a real peer as well as its sending one */
        if (!wait_until(end, info_answered_and_named_back, FLOW_PATIENCE_MS)) {
            wrong_text(end->seen.dtmf_sent ? "the digit sent by INFO was never named back"
                                           : "the INFO was never answered");
            return -1;
        }
        if (end->seen.ended) {
            wrong_text("the call ended before the digit was named back");
            return -1;
        }
        if (end->seen.dtmf_sent_status < 200u || end->seen.dtmf_sent_status >= 300u) {
            (void)snprintf(trouble, sizeof trouble, "the INFO was answered %u",
                           (unsigned)end->seen.dtmf_sent_status);
            return -1;
        }
        break;
    }

    case FLOW_HOLD_CODEC_CHANGE: {
        sipral_status_t status;
        dwell(end, 500u);
        status = sipral_call_hold(end->stack, end->call, now_ms());
        if (status != SIPRAL_STATUS_OK) {
            wrong("sipral_call_hold", status);
            return -1;
        }
        if (!wait_until(end, held, FLOW_PATIENCE_MS) || end->seen.ended) {
            wrong_text("the hold was never agreed");
            return -1;
        }
        /* a narrower list, offered while the call is held -- which the change
         * keeps: only the codecs move */
        end->changes_before = end->seen.session_changes;
        status = sipral_call_change_codecs(end->stack, end->call, CHANGED_CODECS,
                                           strlen(CHANGED_CODECS), now_ms());
        if (status != SIPRAL_STATUS_OK) {
            wrong("sipral_call_change_codecs", status);
            return -1;
        }
        if (!wait_until(end, change_settled, FLOW_PATIENCE_MS) || end->seen.ended) {
            wrong_text("the codec change was never answered");
            return -1;
        }
        if (end->seen.change_refused) {
            (void)snprintf(trouble, sizeof trouble,
                           "the far end refused the codec change (%u)",
                           (unsigned)end->seen.change_status);
            return -1;
        }
        /* the media's own report of the change comes out of the same drain as
         * the signalling's, a turn or two behind it */
        dwell(end, 200u);
        if (!end->seen.held_here) {
            wrong_text("the codec change took the call off hold");
            return -1;
        }
        if (end->seen.codec_now == end->seen.codec_started) {
            wrong_text("the codec change never moved the call off the one it held on");
            return -1;
        }
        status = sipral_call_resume(end->stack, end->call, now_ms());
        if (status != SIPRAL_STATUS_OK) {
            wrong("sipral_call_resume", status);
            return -1;
        }
        if (!wait_until(end, resumed, FLOW_PATIENCE_MS) || end->seen.ended) {
            wrong_text("the resume was never agreed");
            return -1;
        }
        /* and audio on the new codec, so the counters say something */
        dwell(end, 1000u);
        if (end->seen.codec_now == end->seen.codec_started) {
            wrong_text("the resume went back to the codec the call held on");
            return -1;
        }
        break;
    }

    case FLOW_G729:
        /* the claim is the codec and the echo together: a call that settled
         * on anything else proved nothing about G.729, and `audio_holds`
         * asks for more than a stray frame of the tone back. The lab's
         * Asterisk has no G.729 translator, so what `Echo()` hands back is
         * what this end's encoder wrote, for this end's decoder */
        dwell(end, DWELL_MS);
        if (end->seen.codec_started != (uint32_t)SIPRAL_CODEC_G729) {
            const char *codec = sipral_codec_name(end->seen.codec_started);
            (void)snprintf(trouble, sizeof trouble, "the call settled on %s, not G.729",
                           codec != NULL ? codec : "no codec at all");
            return -1;
        }
        break;

    case FLOW_DTLS:
    case FLOW_PEER_DTLS: {
        /* FLOW_PEER_DTLS is this same case against the phone-to-phone
         * peer's baresip-dtls account instead of Asterisk's
         * or FreeSWITCH's -- extension_for() and srtp_for() already sent it
         * there, and nothing below needs to know which one it is running
         * against: a third independent DTLS-SRTP implementation on the far
         * side of a call this stack placed rather than answered. */
        sipral_status_t status;
        const char *require_audio = getenv("SIPRAL_REQUIRE_AUDIO");
        unsigned audible_at_resume;

        /* the handshake runs silently under the first packets of this call,
         * and `received` only counts real RTP -- `sipral_media_receive`
         * reports the handshake's own records as `SIPRAL_ARRIVAL_HANDSHAKE`
         * and this driver does not count those -- so waiting for it is
         * waiting for the far end's tone to prove the keys are in place,
         * exactly as `Flow::Blind` waits to be worth handing over before it
         * sends its own REFER */
        (void)wait_until(end, keyed_media_arrived, DWELL_MS);
        if (keying_failed(end)) {
            return -1;
        }

        status = sipral_call_hold(end->stack, end->call, now_ms());
        if (status != SIPRAL_STATUS_OK) {
            wrong("sipral_call_hold", status);
            return -1;
        }
        if (!wait_until(end, held_or_unkeyable, FLOW_PATIENCE_MS) || end->seen.ended) {
            wrong_text("the hold was never agreed");
            return -1;
        }
        if (keying_failed(end)) {
            return -1;
        }

        status = sipral_call_resume(end->stack, end->call, now_ms());
        if (status != SIPRAL_STATUS_OK) {
            wrong("sipral_call_resume", status);
            return -1;
        }
        if (!wait_until(end, resumed_or_unkeyable, FLOW_PATIENCE_MS) || end->seen.ended) {
            wrong_text("the resume was never agreed");
            return -1;
        }
        if (keying_failed(end)) {
            return -1;
        }

        /* how many audible frames had already arrived, so what is judged
         * after this is only what the resume itself carried back -- the
         * hold and the resume are both re-offers that hand the DTLS roles
         * back with a=setup:actpass (RFC 8842 §5.5), and audio heard only
         * once they are both agreed is what says the far end answered with
         * the roles already in force */
        audible_at_resume = end->audible;
        dwell(end, DWELL_MS);
        if (keying_failed(end)) {
            return -1;
        }
        if (!end->seen.media_secured) {
            /* not the same question `MEDIA_STARTED` answers: a DTLS call is
             * still waiting for its keys there, and this end has nothing to
             * play until `SIPRAL_EVENT_KIND_MEDIA_SECURED` says the
             * handshake finished */
            wrong_text("the call connected but was never keyed by its DTLS-SRTP handshake");
            return -1;
        }
        if (require_audio != NULL && require_audio[0] != '\0' && require_audio[0] != '0'
            && end->audible <= audible_at_resume) {
            wrong_text("nothing audible came back after the resume");
            return -1;
        }
        break;
    }

    case FLOW_REGISTER:
    case FLOW_MESSAGE:
    case FLOW_MWI:
    case FLOW_NAT:
    case FLOW_ICE_NAT:
    case FLOW_COUNT:
    default:
        break;
    }
    return 0;
}

/* -- the run -------------------------------------------------------------- */

/* Whether the audio a flow carried is worth calling audio.
 *
 * The same question the Rust harness asks and, deliberately, the same answer:
 * a call that sent nothing is a failure whatever else happened, and a call
 * that sent and heard nothing back is a failure only where audio was
 * required. The lab sets SIPRAL_REQUIRE_AUDIO; a developer running this by
 * hand against a server with no media on the extension does not.
 */
static int audio_holds(const struct endpoint *end, enum flow which)
{
    const char *required = getenv("SIPRAL_REQUIRE_AUDIO");
    if (which != FLOW_CALL && which != FLOW_SRTP && which != FLOW_NAT && which != FLOW_G729) {
        return 1;
    }
    if (end->sent == 0) {
        wrong_text("no audio left this end");
        return 0;
    }
    if (required == NULL || required[0] == '\0' || required[0] == '0') {
        return 1;
    }
    if (end->audible == 0) {
        wrong_text("nothing audible came back");
        return 0;
    }
    if (which == FLOW_G729 && end->audible < G729_ECHOED) {
        (void)snprintf(trouble, sizeof trouble,
                       "the echo came back as %u audible frames of %u wanted: %u sent, "
                       "%u received, %u refused",
                       end->audible, G729_ECHOED, end->sent, end->received, end->refused);
        return 0;
    }
    return 1;
}

/* -- a local conference of two calls, joined through this stack ----------- */

/* interop/asterisk/extensions.conf's own cadenced tone, the same extension
 * FLOW_CALL dials. */
#define JOIN_TONE_EXTENSION "9000"

/* interop/asterisk/extensions.conf's echo extension, added for this flow:
 * Answer(); Echo(); -- silent on its own, and sends back only whatever it is
 * sent. interop/harness/src/join.rs's own module documentation says why that
 * is enough to prove one call's audio crossed to the other's wire without
 * this harness carrying a second G.711 decoder of its own. */
#define JOIN_ECHO_EXTENSION "9008"

/* How long both calls run joined, driving the mix -- long enough for several
 * turns of the tone extension's own cadence (SPURT_MS/PAUSE_MS, 1200 ms/600
 * ms) to have crossed to the echo extension and come back at least once. */
#define JOIN_DWELL_MS 6000u

/* How many frames audible during the tone extension's own predicted silence
 * have to be seen before the crossing counts as proven rather than a fluke --
 * a hundred milliseconds' worth, which a single stray concealment frame or a
 * moment of network jitter does not reach on its own. */
#define JOIN_CROSSED_THRESHOLD 5u

/* One call this flow placed, and its own RTP socket.
 *
 * `struct endpoint` above carries a single RTP socket because every other
 * flow needs only one call; a join needs two, each with its own local media
 * address, so this flow keeps its own pair rather than growing that struct
 * for everybody else.
 */
struct join_leg {
    sipral_handle_t call;
    sipral_handle_t media;
    int rtp_fd;
    char rtp_address[SIPRAL_ADDRESS_BYTES];
    uint64_t confirmed_at_ms;
};

/* What the callback saw, for the two calls this flow places. `struct seen`
 * above is keyed to one call and cannot tell the tone leg's events from the
 * echo leg's. */
struct join_seen {
    unsigned marker;
    sipral_handle_t tone_call;
    sipral_handle_t echo_call;
    int tone_media_started;
    int echo_media_started;
    uint32_t registration;
};

#define JOIN_MARKER 0x501A10u

static void join_on_event(const sipral_event_t *event, void *user_data)
{
    struct join_seen *seen = (struct join_seen *)user_data;
    if (seen == NULL || seen->marker != JOIN_MARKER || event == NULL) {
        return;
    }
    if (event->kind == SIPRAL_EVENT_KIND_REGISTRATION_CHANGED) {
        seen->registration = event->payload.registration.state;
        return;
    }
    if (event->kind != SIPRAL_EVENT_KIND_MEDIA_STARTED) {
        return;
    }
    if (event->call == seen->tone_call) {
        seen->tone_media_started = 1;
    } else if (event->call == seen->echo_call) {
        seen->echo_media_started = 1;
    }
}

/* `flush_signalling`/`read_signalling` above, taking the stack and the
 * socket as plain arguments rather than a `struct endpoint`: this flow's own
 * stack has no such struct, since it carries two calls rather than one. */
static void join_flush_signalling(sipral_handle_t stack, int sip_fd)
{
    static uint8_t out[DATAGRAM];
    static char destination[SIPRAL_ADDRESS_BYTES];
    for (;;) {
        sipral_transmit_t message;
        struct sockaddr_in to;
        memset(&message, 0, sizeof message);
        message.size = sizeof message;
        message.data = out;
        message.capacity = sizeof out;
        message.destination = destination;
        message.destination_capacity = sizeof destination;
        if (sipral_stack_poll_transmit(stack, &message) != SIPRAL_STATUS_OK) {
            return;
        }
        if (message.len == 0) {
            return;
        }
        if (address_of(destination, &to) == 0) {
            (void)sendto(sip_fd, out, message.len, 0, (const struct sockaddr *)&to,
                        sizeof to);
        }
    }
}

static void join_read_signalling(sipral_handle_t stack, int sip_fd,
                                 const char *sip_address, uint64_t now)
{
    static uint8_t in[DATAGRAM];
    for (;;) {
        struct sockaddr_in from;
        socklen_t length = sizeof from;
        char from_text[SIPRAL_ADDRESS_BYTES];
        ssize_t got = recvfrom(sip_fd, in, sizeof in, 0, (struct sockaddr *)&from, &length);
        if (got <= 0) {
            return;
        }
        if (address_text(&from, from_text, sizeof from_text) != 0) {
            continue;
        }
        (void)sipral_stack_receive_datagram(stack, SIPRAL_TRANSPORT_MAIN, in, (size_t)got,
                                            from_text, strlen(from_text), sip_address,
                                            strlen(sip_address), now);
    }
}

/* One turn of signalling alone -- polling the stack, flushing what it wrote,
 * and reading what arrived. Media is this flow's own, driven separately by
 * `join_mix_one` once both calls are joined, and by nothing before that. */
static void join_pump_signalling(sipral_handle_t stack, int sip_fd, const char *sip_address,
                                 uint64_t now)
{
    sipral_poll_result_t result;
    memset(&result, 0, sizeof result);
    result.size = sizeof result;
    (void)sipral_stack_poll(stack, now, &result);
    join_flush_signalling(stack, sip_fd);
    join_read_signalling(stack, sip_fd, sip_address, now);
}

/* `send_media` above, taking a raw socket rather than a `struct endpoint`. */
static void join_send(int fd, const uint8_t *data, size_t len, const char *destination)
{
    struct sockaddr_in to;
    if (len == 0 || address_of(destination, &to) != 0) {
        return;
    }
    (void)sendto(fd, data, len, 0, (const struct sockaddr *)&to, sizeof to);
}

/* Bind a fresh RTP socket, place a call at `extension`, and give it that
 * socket's own address -- interop/harness/src/join.rs's own `place`, in C. */
static int join_place(sipral_handle_t stack, sipral_handle_t account, const char *server,
                      const char *extension, const char *routable, struct join_leg *leg)
{
    struct sockaddr_in local;
    sipral_call_config_t call;
    char target[192];
    sipral_status_t status;

    memset(leg, 0, sizeof *leg);
    leg->call = SIPRAL_HANDLE_NONE;
    leg->media = SIPRAL_HANDLE_NONE;
    leg->rtp_fd = bind_udp(&local);
    if (leg->rtp_fd < 0) {
        wrong_text("cannot bind an RTP socket for the join flow");
        return -1;
    }
    (void)snprintf(leg->rtp_address, sizeof leg->rtp_address, "%s:%u", routable,
                  (unsigned)ntohs(local.sin_port));
    (void)snprintf(target, sizeof target, "sip:%s@%s", extension, server);
    memset(&call, 0, sizeof call);
    call.size = sizeof call;
    call.target = target;
    call.target_len = strlen(target);
    call.media_address = leg->rtp_address;
    call.media_address_len = strlen(leg->rtp_address);
    status = sipral_call_place(stack, account, &call, &leg->call, now_ms());
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_call_place", status);
        return -1;
    }
    return 0;
}

/* One frame of the joined pair: read whatever arrived on either socket, mix
 * through the facade, and send what each far end is owed. `*crossed` is set
 * when the mixed frame handed to this end's own loudspeaker was audible
 * while `cadence_ms` -- elapsed since the tone call confirmed -- says the
 * tone extension's own cadence should currently be silent, which
 * interop/harness/src/join.rs's own module documentation explains. Answers
 * whether a frame was mixed at all. */
static int join_mix_one(struct join_leg *tone, struct join_leg *echo, uint64_t cadence_ms,
                        uint64_t now, int *crossed)
{
    static uint8_t in[DATAGRAM];
    static uint8_t out_a[DATAGRAM];
    static uint8_t out_b[DATAGRAM];
    static char destination_a[SIPRAL_ADDRESS_BYTES];
    static char destination_b[SIPRAL_ADDRESS_BYTES];
    static int16_t mic[MAX_FRAME_SAMPLES];
    static int16_t local_out[MAX_FRAME_SAMPLES];
    sipral_media_info_t info;
    sipral_media_packet_t packet_a;
    sipral_media_packet_t packet_b;
    struct join_leg *legs[2];
    size_t frame;
    sipral_status_t status;
    int index;

    *crossed = 0;
    legs[0] = tone;
    legs[1] = echo;
    for (index = 0; index < 2; index++) {
        for (;;) {
            struct sockaddr_in from;
            socklen_t length = sizeof from;
            char from_text[SIPRAL_ADDRESS_BYTES];
            uint32_t arrival = 0;
            ssize_t got = recvfrom(legs[index]->rtp_fd, in, sizeof in, 0,
                                   (struct sockaddr *)&from, &length);
            if (got <= 0) {
                break;
            }
            if (address_text(&from, from_text, sizeof from_text) != 0) {
                continue;
            }
            (void)sipral_media_receive(legs[index]->media, in, (size_t)got, from_text,
                                       strlen(from_text), now, &arrival);
        }
    }

    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    if (sipral_media_info(tone->media, &info) != SIPRAL_STATUS_OK) {
        return -1;
    }
    frame = info.frame_samples;
    if (frame > MAX_FRAME_SAMPLES) {
        frame = MAX_FRAME_SAMPLES;
    }
    memset(mic, 0, frame * sizeof mic[0]);
    memset(local_out, 0, frame * sizeof local_out[0]);

    memset(&packet_a, 0, sizeof packet_a);
    packet_a.size = sizeof packet_a;
    packet_a.data = out_a;
    packet_a.capacity = sizeof out_a;
    packet_a.destination = destination_a;
    packet_a.destination_capacity = sizeof destination_a;
    memset(&packet_b, 0, sizeof packet_b);
    packet_b.size = sizeof packet_b;
    packet_b.data = out_b;
    packet_b.capacity = sizeof out_b;
    packet_b.destination = destination_b;
    packet_b.destination_capacity = sizeof destination_b;

    status = sipral_media_mix(tone->media, echo->media, now, mic, frame, local_out, frame,
                              &packet_a, &packet_b);
    if (status != SIPRAL_STATUS_OK) {
        return -1;
    }
    if (packet_a.len > 0) {
        join_send(tone->rtp_fd, out_a, packet_a.len, destination_a);
    }
    if (packet_b.len > 0) {
        join_send(echo->rtp_fd, out_b, packet_b.len, destination_b);
    }

    if (!in_spurt(cadence_ms) && loudness(local_out, frame) >= AUDIBLE) {
        *crossed = 1;
    }
    return 0;
}

/* Register one account, place both calls, join them, and drive the mix long
 * enough to see one call's tone come back by way of the other --
 * interop/harness/src/join.rs's own `run`, in C. Prints its own result line
 * and answers 0 on success, the same shape `run_flow` answers for every
 * other flow.
 */
static int run_join(const char *server, const struct sockaddr_in *remote, const char *user,
                    const char *pass)
{
    sipral_handle_t stack = SIPRAL_HANDLE_NONE;
    sipral_handle_t account = SIPRAL_HANDLE_NONE;
    struct join_leg tone;
    struct join_leg echo;
    struct join_seen seen;
    sipral_stack_config_t config;
    sipral_account_config_t account_config;
    uint8_t signalling_seed[32];
    uint8_t media_seed[32];
    int sip_fd = -1;
    char routable[INET_ADDRSTRLEN];
    char sip_address[SIPRAL_ADDRESS_BYTES];
    char aor[128];
    char registrar[128];
    char contact[192];
    char registrar_address[SIPRAL_ADDRESS_BYTES];
    struct sockaddr_in sip_local;
    sipral_status_t status;
    uint64_t deadline;
    uint64_t joined_at_ms = 0;
    unsigned mixed_frames = 0;
    unsigned crossed_frames = 0;
    int outcome = -1;

    /* reset here, the same as `main`'s own loop does before every other
     * flow: `wrong`/`wrong_text` keep the first message and say nothing
     * about a second one, and a flow that starts without resetting this
     * would report whatever the flow before it failed with instead of its
     * own reason, or nothing at all if the flow before it passed clean */
    trouble[0] = '\0';

    tone.call = SIPRAL_HANDLE_NONE;
    tone.media = SIPRAL_HANDLE_NONE;
    tone.rtp_fd = -1;
    tone.confirmed_at_ms = 0;
    echo.call = SIPRAL_HANDLE_NONE;
    echo.media = SIPRAL_HANDLE_NONE;
    echo.rtp_fd = -1;
    echo.confirmed_at_ms = 0;
    memset(&seen, 0, sizeof seen);
    seen.marker = JOIN_MARKER;
    seen.tone_call = SIPRAL_HANDLE_NONE;
    seen.echo_call = SIPRAL_HANDLE_NONE;

    /* distinct from `seeds_for`'s own range (0 .. FLOW_COUNT - 1), so this
     * flow's own stack never mints the same branch as another flow's */
    seeds_for(90u, signalling_seed, media_seed);

    if (route_to(remote, routable, sizeof routable) != 0) {
        wrong_text("no route to the lab network");
        goto done;
    }
    sip_fd = bind_udp(&sip_local);
    if (sip_fd < 0) {
        wrong_text("cannot bind a socket");
        goto done;
    }
    (void)snprintf(sip_address, sizeof sip_address, "%s:%u", routable,
                  (unsigned)ntohs(sip_local.sin_port));

    memset(&config, 0, sizeof config);
    config.size = sizeof config;
    config.event_callback = join_on_event;
    config.event_user_data = &seen;
    config.transport = SIPRAL_TRANSPORT_UDP;
    config.bind_address = sip_address;
    config.bind_address_len = strlen(sip_address);
    config.entropy = signalling_seed;
    config.entropy_len = sizeof signalling_seed;
    config.media_seed = media_seed;
    config.media_seed_len = sizeof media_seed;
    config.codecs = "PCMU,PCMA";
    config.codecs_len = strlen("PCMU,PCMA");
    config.media_clock_unix_seconds = (uint64_t)time(NULL);
    status = sipral_stack_create(&config, &stack);
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_stack_create", status);
        goto done;
    }

    (void)snprintf(aor, sizeof aor, "sip:%s@%s", user, server);
    (void)snprintf(registrar, sizeof registrar, "sip:%s", server);
    (void)snprintf(contact, sizeof contact, "sip:%s@%s", user, sip_address);
    if (address_text(remote, registrar_address, sizeof registrar_address) != 0) {
        wrong_text("the registrar has no address");
        goto done;
    }
    memset(&account_config, 0, sizeof account_config);
    account_config.size = sizeof account_config;
    account_config.aor = aor;
    account_config.aor_len = strlen(aor);
    account_config.registrar = registrar;
    account_config.registrar_len = strlen(registrar);
    account_config.contact = contact;
    account_config.contact_len = strlen(contact);
    account_config.registrar_address = registrar_address;
    account_config.registrar_address_len = strlen(registrar_address);
    account_config.auth_user = user;
    account_config.auth_user_len = strlen(user);
    account_config.auth_password = pass;
    account_config.auth_password_len = strlen(pass);
    account_config.expires_seconds = 300u;
    status = sipral_account_add(stack, &account_config, &account);
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_account_add", status);
        goto done;
    }

    status = sipral_account_register(stack, account, now_ms());
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_account_register", status);
        goto done;
    }
    deadline = now_ms() + FLOW_PATIENCE_MS;
    for (;;) {
        uint64_t now = now_ms();
        join_pump_signalling(stack, sip_fd, sip_address, now);
        if (seen.registration == SIPRAL_REGISTRATION_STATE_REGISTERED
            || seen.registration == SIPRAL_REGISTRATION_STATE_FAILED) {
            break;
        }
        if (now >= deadline) {
            wrong_text("registration never finished");
            goto done;
        }
        sleep_ms(5);
    }
    if (seen.registration != SIPRAL_REGISTRATION_STATE_REGISTERED) {
        wrong_text("not registered, so there is nobody to place either call as");
        goto done;
    }

    if (join_place(stack, account, server, JOIN_TONE_EXTENSION, routable, &tone) != 0) {
        goto done;
    }
    seen.tone_call = tone.call;
    if (join_place(stack, account, server, JOIN_ECHO_EXTENSION, routable, &echo) != 0) {
        goto done;
    }
    seen.echo_call = echo.call;

    deadline = now_ms() + FLOW_PATIENCE_MS;
    for (;;) {
        uint64_t now = now_ms();
        join_pump_signalling(stack, sip_fd, sip_address, now);
        if (seen.tone_media_started && seen.echo_media_started) {
            break;
        }
        if (now >= deadline) {
            wrong_text("one of the two calls never got media on it");
            goto done;
        }
        sleep_ms(5);
    }
    /* near enough: Asterisk's own Playtones() started counting when the tone
     * call was answered, a moment before MEDIA_STARTED reached this end */
    tone.confirmed_at_ms = now_ms();

    status = sipral_call_media(stack, tone.call, &tone.media);
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_call_media", status);
        goto done;
    }
    status = sipral_call_media(stack, echo.call, &echo.media);
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_call_media", status);
        goto done;
    }
    status = sipral_call_join(stack, tone.call, echo.call);
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_call_join", status);
        goto done;
    }
    joined_at_ms = now_ms();

    deadline = joined_at_ms + JOIN_DWELL_MS;
    while (now_ms() < deadline) {
        uint64_t now = now_ms();
        int crossed = 0;
        join_pump_signalling(stack, sip_fd, sip_address, now);
        if (join_mix_one(&tone, &echo, now - tone.confirmed_at_ms, now, &crossed) == 0) {
            mixed_frames++;
            if (crossed) {
                crossed_frames++;
            }
        }
        sleep_ms(20);
    }

    (void)sipral_call_leave(stack, tone.call);
    (void)sipral_call_hangup(stack, tone.call, now_ms());
    (void)sipral_call_hangup(stack, echo.call, now_ms());
    deadline = now_ms() + 5000u;
    while (now_ms() < deadline) {
        join_pump_signalling(stack, sip_fd, sip_address, now_ms());
        sleep_ms(5);
    }
    /* the binding goes back too, as every other flow's does: left in place it
     * names a port nobody listens on any more, and the next flow to register
     * the same account shares the account with it -- the lab's MESSAGE echo,
     * sent to every contact, then goes to this one */
    (void)sipral_account_unregister(stack, account, now_ms());
    deadline = now_ms() + 1000u;
    while (now_ms() < deadline) {
        join_pump_signalling(stack, sip_fd, sip_address, now_ms());
        sleep_ms(5);
    }

    if (mixed_frames == 0) {
        wrong_text("joined, but no frame was ever mixed");
        goto done;
    }
    if (crossed_frames < JOIN_CROSSED_THRESHOLD) {
        (void)snprintf(trouble, sizeof trouble,
                       "joined and mixed %u frame(s), but only %u were audible while the "
                       "tone extension's own cadence said it should be silent",
                       mixed_frames, crossed_frames);
        goto done;
    }
    outcome = 0;

done:
    if (outcome == 0) {
        printf("  pass  local conference   (%u frame(s) mixed, %u crossed)\n", mixed_frames,
               crossed_frames);
    } else {
        printf("  FAIL  local conference — %s\n",
               trouble[0] != '\0' ? trouble : "no reason was recorded");
    }
    if (stack != SIPRAL_HANDLE_NONE) {
        (void)sipral_stack_destroy(stack);
    }
    if (tone.rtp_fd >= 0) {
        (void)close(tone.rtp_fd);
    }
    if (echo.rtp_fd >= 0) {
        (void)close(echo.rtp_fd);
    }
    if (sip_fd >= 0) {
        (void)close(sip_fd);
    }
    return outcome;
}

int main(int argc, char **argv)
{
    const char *server = argc > 1 ? argv[1] : "kamailio";
    uint16_t port = (uint16_t)(argc > 2 ? atoi(argv[2]) : 5060);
    const char *extension = argc > 3 ? argv[3] : "9000";
    const char *other = argc > 4 ? argv[4] : "9001";
    /* the lab's own account unless something else is named, exactly as the
     * Rust harness does it and for the same reason */
    const char *user = getenv("SIPRAL_USER");
    const char *pass = getenv("SIPRAL_PASS");
    const char *wanted = getenv("SIPRAL_FLOWS");
    /* The phone-to-phone peer: interop/harness/src/main.rs's own
     * SIPRAL_PEER gate, read the same way here so FLOW_PEER_SRTP and
     * FLOW_PEER_DTLS cannot start dialling baresip's accounts from a run
     * that never asked for that peer. */
    const char *peer = getenv("SIPRAL_PEER");
    int for_baresip = peer != NULL && strcmp(peer, "baresip") == 0;
    struct sockaddr_in remote;
    char remote_text[SIPRAL_ADDRESS_BYTES];
    int failed = 0;
    int which;

    if (user == NULL || user[0] == '\0') {
        user = "labuser";
    }
    if (pass == NULL || pass[0] == '\0') {
        pass = "labpass";
    }
    if (port == 0) {
        port = 5060;
    }

    /* the header and the library agree about their own shapes before anything
     * is built on either: a mismatch here is the one failure that would make
     * every line below it meaningless */
    if (sipral_abi_check(SIPRAL_ABI_VERSION_MAJOR, SIPRAL_ABI_VERSION_MINOR)
        != SIPRAL_STATUS_OK) {
        printf("the library does not speak this header's ABI\n");
        return 1;
    }

    if (resolve(server, port, &remote) != 0
        || address_text(&remote, remote_text, sizeof remote_text) != 0) {
        printf("cannot resolve %s:%u\n", server, (unsigned)port);
        return 1;
    }
    printf("lab: %s:%u at %s, extension %s, as %s\n", server, (unsigned)port,
           remote_text, extension, user);

    /* `g_run_seed`, once, before the loop below ever calls `seeds_for`:
     * pinned by `SIPRAL_HARNESS_SEED` (64 hex digits) so a failing run can be
     * repeated exactly, or drawn fresh from the OS otherwise. Printed either
     * way, so a run that is not pinned can still be told apart from the one
     * before it. */
    {
        const char *pinned = getenv("SIPRAL_HARNESS_SEED");
        char hex[65];
        if (pinned != NULL) {
            if (parse_hex_seed(pinned, g_run_seed) != 0) {
                printf("SIPRAL_HARNESS_SEED is not 64 hex digits: %s\n", pinned);
                return 1;
            }
        } else if (run_entropy(g_run_seed) != 0) {
            printf("cannot draw a run seed from the OS\n");
            return 1;
        }
        seed_hex(g_run_seed, hex);
        printf("seed: %s\n", hex);
    }

    for (which = 0; which < (int)FLOW_COUNT; which++) {
        struct endpoint end;
        enum flow flow = (enum flow)which;
        const char *flow_user = user;
        const char *flow_pass = pass;
        int outcome;

        if (wanted != NULL && wanted[0] != '\0' && !selected(wanted, flow_key(flow))) {
            continue;
        }
        if (!runs_against(flow, server, for_baresip)) {
            continue;
        }
        account_for(flow, server, &flow_user, &flow_pass);
        stun_for_this_flow = flow == FLOW_NAT || flow == FLOW_ICE_NAT
                                 ? getenv("SIPRAL_STUN_SERVER")
                                 : NULL;
        calling_a_peer = flow == FLOW_ICE_NAT;
        codecs_for_this_flow = flow == FLOW_G729 ? "G729" : NULL;
        turn_for_this_flow = NULL;
        turn_user_for_this_flow = NULL;
        turn_password_for_this_flow = NULL;
        if (flow == FLOW_ICE_NAT) {
            /* interop/harness/src/ice_nat.rs's own three variables: the
             * callee behind the other NAT reads the same ones */
            const char *turn = getenv("SIPRAL_TURN_SERVER");
            if (turn != NULL && turn[0] != '\0') {
                turn_for_this_flow = turn;
                turn_user_for_this_flow = getenv("SIPRAL_TURN_USER");
                turn_password_for_this_flow = getenv("SIPRAL_TURN_PASSWORD");
                if (turn_user_for_this_flow == NULL || turn_password_for_this_flow == NULL) {
                    printf("  FAIL  %s — SIPRAL_TURN_SERVER needs SIPRAL_TURN_USER and "
                           "SIPRAL_TURN_PASSWORD\n",
                           flow_name(flow));
                    failed++;
                    continue;
                }
            }
            /* the caller, as the Rust harness names it: the callee answers
             * whoever calls */
            flow_user = "caller";
        }

        trouble[0] = '\0';
        if (open_endpoint(&end, (unsigned)which, server, &remote, flow_user, flow_pass)
            != 0) {
            printf("  FAIL  %s — %s\n", flow_name(flow), trouble);
            failed++;
            continue;
        }
        outcome = run_flow(flow, &end, server, extension, other);
        if (outcome == 0 && !audio_holds(&end, flow)) {
            outcome = -1;
        }
        finish(&end);

        if (outcome == 0) {
            if (flow == FLOW_REGISTER) {
                printf("  pass  %s\n", flow_name(flow));
            } else {
                printf("  pass  %s   (%u sent, %u back, %u audible, %u refused)\n",
                       flow_name(flow), end.sent, end.received, end.audible,
                       end.refused);
            }
        } else {
            printf("  FAIL  %s — %s\n", flow_name(flow),
                   trouble[0] != '\0' ? trouble : "no reason was recorded");
            failed++;
        }
        close_endpoint(&end);
    }

    /* this lab's own echo extension (interop/asterisk's 9008) exists only on
     * Asterisk, the same reason the SDES and codec-change flows above are
     * gated to it. Two calls placed on one account, which `enum flow` and
     * `run_flow` have no shape for -- see `run_join`'s own documentation --
     * so this is driven outside that dispatch entirely, the way
     * interop/harness/src/main.rs's own `join::run` is. */
    if (strcmp(server, "asterisk") == 0
        && (wanted == NULL || wanted[0] == '\0' || selected(wanted, "join"))) {
        if (run_join(server, &remote, user, pass) != 0) {
            failed++;
        }
    }

    if (failed == 0) {
        printf("every flow passed\n");
        return 0;
    }
    printf("%d flow(s) failed\n", failed);
    return 1;
}
