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

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* The digit this harness presses, and how long it holds it. */
#define TEST_DIGIT "5"
#define DIGIT_MS 200u

/* What the hold-with-a-codec-change flow moves the call onto: the other G.711
 * law, which every server in the lab takes and which the call cannot already
 * be on, since the catalogue offers PCMU first. */
#define CHANGED_CODECS "PCMA"

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

/* A non-blocking UDP socket on an ephemeral port, and where it landed. */
static int bind_udp(struct sockaddr_in *out)
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
    int events;
    char fault[192];
};

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
        break;
    case SIPRAL_EVENT_KIND_CALL_CONFIRMED:
        seen->confirmed = 1;
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

    int sip_fd;
    int rtp_fd;
    char sip_address[SIPRAL_ADDRESS_BYTES];
    char rtp_address[SIPRAL_ADDRESS_BYTES];
    struct sockaddr_in server;

    uint64_t next_frame_ms;
    uint64_t media_since_ms;
    /* how many session changes had been agreed when this end asked for the
     * one it is now waiting on */
    int changes_before;
    uint32_t phase;
    size_t frame_samples;
    uint32_t sample_rate;

    /* the same four numbers the Rust harness prints, counted the same way:
     * from outside the session, watching what each call returns */
    unsigned sent;
    unsigned received;
    unsigned audible;
    unsigned refused;

    struct seen seen;
};

/* Why a flow stopped, when it stopped badly. One buffer, because a flow
 * reports the first thing that went wrong and nothing after it. */
static char trouble[256];

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

/* One turn of everything. */
static void pump(struct endpoint *end, uint64_t now)
{
    sipral_poll_result_t result;
    memset(&result, 0, sizeof result);
    result.size = sizeof result;
    (void)sipral_stack_poll(end->stack, now, &result);
    flush_signalling(end);
    read_signalling(end, now);
    run_media(end, now);
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

/* -- opening and closing an end ------------------------------------------- */

/* The entropy a flow's stack is given.
 *
 * Fixed patterns rather than platform entropy, because this is a lab and a
 * harness whose failures did not reproduce would be worth less than no
 * harness. The two seeds differ from each other because the ABI refuses them
 * equal, and `docs/20-security-model.md` says why.
 *
 * `which` varies them **per flow**, and that is not decoration. A stack's
 * `Call-ID` for its registration is drawn from the signalling seed once per
 * boot cycle (RFC 3261 §10.2), so six flows from one seed are six
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
        signalling[index] = (uint8_t)(0x11u + index * 7u + which * 29u);
        media[index] = (uint8_t)(0xF1u - index * 5u + which * 37u);
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
    char aor[128];
    char registrar[128];
    char contact[192];
    char registrar_address[SIPRAL_ADDRESS_BYTES];
    sipral_status_t status;

    memset(end, 0, sizeof *end);
    end->sip_fd = -1;
    end->rtp_fd = -1;
    end->seen.marker = MARKER;
    end->server = *remote;

    if (route_to(remote, routable, sizeof routable) != 0) {
        wrong_text("no route to the lab network");
        return -1;
    }
    end->sip_fd = bind_udp(&sip_local);
    end->rtp_fd = bind_udp(&rtp_local);
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

    status = sipral_stack_create(&config, &end->stack);
    if (status != SIPRAL_STATUS_OK) {
        wrong("sipral_stack_create", status);
        close_endpoint(end);
        return -1;
    }

    (void)snprintf(aor, sizeof aor, "sip:%s@%s", user, server);
    (void)snprintf(registrar, sizeof registrar, "sip:%s", server);
    (void)snprintf(contact, sizeof contact, "sip:%s@%s", user, end->sip_address);
    if (address_text(remote, registrar_address, sizeof registrar_address) != 0) {
        wrong_text("the registrar has no address");
        close_endpoint(end);
        return -1;
    }

    memset(&account, 0, sizeof account);
    account.size = sizeof account;
    account.aor = aor;
    account.aor_len = strlen(aor);
    account.registrar = registrar;
    account.registrar_len = strlen(registrar);
    account.contact = contact;
    account.contact_len = strlen(contact);
    account.registrar_address = registrar_address;
    account.registrar_address_len = strlen(registrar_address);
    account.auth_user = user;
    account.auth_user_len = strlen(user);
    account.auth_password = pass;
    account.auth_password_len = strlen(pass);
    account.expires_seconds = 300u;

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
 * Two flows have one of their own on Asterisk, and for the reason the Rust
 * harness gives: the SDES endpoint is `labuser-srtp`, so that the plain one
 * every other flow uses stays plain, and INFO's own `dtmf_mode` is
 * `labuser-infodtmf`'s. Same defaults, same variables to override them. */
static void account_for(enum flow which, const char **user, const char **pass)
{
    const char *named = NULL;
    const char *secret = NULL;
    const char *fallback = NULL;
    if (which == FLOW_SRTP) {
        named = getenv("SIPRAL_USER_SRTP");
        secret = getenv("SIPRAL_PASS_SRTP");
        fallback = "labuser-srtp";
    } else if (which == FLOW_DTMF_INFO) {
        named = getenv("SIPRAL_USER_INFODTMF");
        secret = getenv("SIPRAL_PASS_INFODTMF");
        fallback = "labuser-infodtmf";
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

/* Hang up, and wait for the far end to agree that it is over. */
static void finish(struct endpoint *end)
{
    if (end->call != SIPRAL_HANDLE_NONE && !end->seen.ended) {
        (void)sipral_call_hangup(end->stack, end->call, now_ms());
        (void)wait_until(end, hung_up, 5000u);
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
 * The last four only against Asterisk, and the Rust harness does the same for
 * the same reasons: `interop/asterisk/extensions.conf` is the only dialplan in
 * the lab with an extension that names a digit back, the one Asterisk names
 * never came back through the proxy from FreeSWITCH, and the SDES endpoint
 * and the INFO one exist only in Asterisk's own configuration.
 * `docs/11-testing.md` carries the reasons. A flow is not run where it is
 * known not to pass until somebody has found out why.
 */
static int runs_against(enum flow which, const char *server)
{
    switch (which) {
    case FLOW_DTMF:
    case FLOW_DTMF_INFO:
    case FLOW_SRTP:
    case FLOW_HOLD_CODEC_CHANGE:
        return strcmp(server, "asterisk") == 0;
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
 * has 9004. Every other flow calls the extension the command line named, and
 * a bridge answers it.
 */
static const char *extension_for(enum flow which, const char *named)
{
    switch (which) {
    case FLOW_DTMF:
    case FLOW_DTMF_INFO:
        return "9003";
    case FLOW_SRTP:
        return "9004";
    case FLOW_REGISTER:
    case FLOW_CALL:
    case FLOW_HOLD:
    case FLOW_BLIND:
    case FLOW_ATTENDED:
    case FLOW_HOLD_CODEC_CHANGE:
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

static int run_flow(enum flow which, struct endpoint *end, const char *server,
                    const char *extension, const char *other)
{
    if (which == FLOW_REGISTER) {
        return flow_register(end);
    }
    if (up_and_talking(end, server, extension_for(which, extension),
                       which == FLOW_SRTP ? (uint32_t)SIPRAL_SRTP_REQUIRED : 0u)
        != 0) {
        return -1;
    }

    switch (which) {
    case FLOW_CALL:
        dwell(end, DWELL_MS);
        break;

    case FLOW_SRTP:
        /* the same tone as the plain call, and judged the same way: a stream
         * that agreed a key and never decrypted a frame is the failure this
         * flow exists to find, and it looks like silence */
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

    case FLOW_REGISTER:
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
    if (which != FLOW_CALL && which != FLOW_SRTP) {
        return 1;
    }
    if (end->sent == 0) {
        wrong_text("no audio left this end");
        return 0;
    }
    if (required != NULL && required[0] != '\0' && required[0] != '0'
        && end->audible == 0) {
        wrong_text("nothing audible came back");
        return 0;
    }
    return 1;
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

    for (which = 0; which < (int)FLOW_COUNT; which++) {
        struct endpoint end;
        enum flow flow = (enum flow)which;
        const char *flow_user = user;
        const char *flow_pass = pass;
        int outcome;

        if (wanted != NULL && wanted[0] != '\0' && !selected(wanted, flow_key(flow))) {
            continue;
        }
        if (!runs_against(flow, server)) {
            continue;
        }
        account_for(flow, &flow_user, &flow_pass);

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

    if (failed == 0) {
        printf("every flow passed\n");
        return 0;
    }
    printf("%d flow(s) failed\n", failed);
    return 1;
}
