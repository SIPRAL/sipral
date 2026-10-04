<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# 21 — Migrating from PJSIP

For a team that has a softphone or a voice service on PJSIP's `pjsua` C API
or its `pjsua2` C++ layer and wants to move it onto Sipral. Each concept the
two share is mapped to its Sipral equivalent, with a sample in C and one in
Python, the idiomatic layer every sample here was run with; the Swift, .NET
and Kotlin layers have the same shape (`docs/08-ffi.md`).

**Where the PJSIP side comes from.** Only PJSIP's own public documentation
as published on docs.pjsip.org, cited below by page title: the PJSUA2 guide
("Introduction to PJSUA2", "General Concepts", and under "Using PJSUA2":
"The Endpoint", "Accounts", "Calls", "Working with Audio Media", "Presence
and Instant Messaging"), the PJSUA-LIB API reference ("PJSUA API - High Level
Softphone API", "PJSUA-API Basic API", "PJSUA-API Media Manipulation") and
the TLS guide ("SSL/TLS"). No PJSIP source file or header was opened to write
this, as `02-clean-room.md` requires. PJSIP's names appear only where a
reader has to recognise the thing being replaced; nothing here reproduces
their text, and every statement about PJSIP is a paraphrase of those pages
that a reader should check against them.

## What is different before anything else

Four differences decide how a port is structured; the concept-by-concept
mapping further down follows from them.

1. **Sipral opens no socket, starts no thread and reads no clock.** PJSIP's
   library creates transports that own sockets, runs worker threads that
   poll them, and resolves names ("The Endpoint"; "General Concepts" on
   worker threads). Sipral's core is sans-I/O (`01-architecture.md`, "Who
   owns the sockets, the resolver and TLS"): the application reads a
   socket and hands the bytes in (`sipral_stack_receive_datagram`,
   `sipral_stack_receive_stream`), calls `sipral_stack_poll` with the time
   now, and writes what `sipral_stack_poll_transmit` hands back. The
   idiomatic layers own the signalling socket — UDP, or one TCP or TLS
   connection — and one poll thread for the
   application, so the Python sample below has no loop in it; the C sample
   shows the loop they hide.
2. **There is no audio device in the core, unless the application asks for
   device mode.** PJSIP's conference bridge has the sound device as its
   port zero, and a "null" device for a machine that has none ("Working with
   Audio Media"; `pjsua_set_null_snd_dev` in "PJSUA-API Media
   Manipulation"). Sipral's default in C is application mode: the
   application hands in microphone frames (`sipral_media_capture`) and
   takes loudspeaker frames out (`sipral_media_playback`). Device mode
   (`SIPRAL_AUDIO_DEVICE`) has the library open the platform's devices on
   macOS, iOS and Windows; even then the encoded packets come back to the
   application to send, because the media sockets are the application's
   too.
3. **One callback per stack, called only from inside `sipral_stack_poll`,
   on the thread that polled.** PJSIP delivers callbacks from its worker
   threads and asks every foreign thread to register itself before calling
   in ("General Concepts"). Sipral has no thread registry: any thread may
   call any entry point, one thread at a time per stack, and a second
   thread that arrives while the first is inside is told
   `SIPRAL_STATUS_BUSY` instead of blocking (`08-ffi.md`, "The shape").
   Nothing is locked while the callback runs, so the callback may call
   back in.
4. **Handles, status codes and a last-error string, not objects and
   exceptions.** A `pjsua2` application subclasses `Account`, `Call` and
   `Buddy` and overrides their callbacks, and errors are exceptions
   ("General Concepts"). Sipral hands out 64-bit handles
   (`08-ffi.md`, "Handles") that name nothing once their object is gone —
   a stale one is `SIPRAL_STATUS_STALE_HANDLE`, not a crash — and every
   entry point returns a `sipral_status_t` with the reason in
   `sipral_last_error_message`, per thread. The idiomatic layers turn both
   into their language's objects and exceptions.

## The map

| Concept | PJSIP (`pjsua` / `pjsua2`) | Sipral C ABI | Sipral Python |
|---|---|---|---|
| Library lifetime | create, init with UA, log and media config, add transports, start, destroy ("The Endpoint"; "PJSUA-API Basic API") | `sipral_stack_create` with a `sipral_stack_config_t`, `sipral_stack_destroy` | `Stack(...)`, `with` or `close()` |
| Transport | a transport per protocol and port, created by the library | the application's socket; `transport` and `bind_address` in the config, further ones with `sipral_stack_transport_bind` | one UDP socket per `Stack`, or one TCP or TLS connection (`signalling`) |
| Event pump | worker threads, or the application polling the library's event handler | `sipral_stack_poll`, `sipral_stack_poll_transmit`, `sipral_stack_receive_*` | the `Stack`'s own poll thread |
| Callbacks | a callback struct (`pjsua`), virtual methods (`pjsua2`) | `event_callback` in the config: one `sipral_event_t` with a kind and a payload | `stack.events`, `call.events` (asyncio queues) |
| Account | account config with id URI, registrar and credentials; registration state callback ("Accounts") | `sipral_account_add`, `sipral_account_register`, `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED` | `stack.add_account(...)`, `account.register()` |
| Outgoing call | make call from an account, call state callback ("Calls") | `sipral_call_place`, `SIPRAL_EVENT_KIND_CALL_PROGRESS` / `_CONFIRMED` / `_ENDED` | `stack.place_call(account, target)` |
| Incoming call | incoming call callback on the account, then answer ("Calls") | `SIPRAL_EVENT_KIND_INCOMING_CALL`, then `sipral_call_answer_media`, `sipral_call_reject` | `stack.answer_call(event)`, `stack.reject_call(event)` |
| Call media | media state callback, then connect the call's audio port to the sound device ("Calls") | `SIPRAL_EVENT_KIND_MEDIA_STARTED`, `sipral_call_media` for the call's media handle | `call.media` (`frames`, `send_audio`) |
| Sound device | port zero of the conference bridge; the null device for none | device mode, `sipral_audio_*` | `stack.audio` |
| Conference bridge | connect any port to any port, mixed ("Working with Audio Media") | `sipral_call_join` and `sipral_media_mix` for two calls and this end; `sipral_local_conference_create` and its siblings for any number, each call on its own codec | `LocalConference` |
| WAV player / recorder | file player and recorder ports | the application plays by handing PCM in; `sipral_media_record_start` records a call | `call.media.send_audio`; `call.media.record` |
| Buddy / presence | buddy objects, subscribe, buddy state callback, publish own status ("Presence and Instant Messaging") | `sipral_account_subscribe` with the `presence` package, `SIPRAL_EVENT_KIND_NOTIFIED`; `sipral_account_publish_presence` | `account.watch_presence`, `account.publish_presence` |
| Instant message | send and receive on an account or a buddy | `sipral_account_message`, `SIPRAL_EVENT_KIND_MESSAGE_SENT` / `_RECEIVED` | the raw layer |
| Logging | log config: level, console level, file, callback ("The Endpoint") | no log stream: events, `sipral_last_error_message`, `sipral_stack_diagnostics_json`, `sipral_call_record_json` | `SipralError` carries the last error |
| Threads | worker thread count, register external threads ("General Concepts") | none; any thread, one at a time per stack | one poll thread per `Stack`, and one per call's media |
| DNS | the library's resolver | the procedure is the stack's, the lookups the application's: `server_uri` is located by RFC 3263, each query asked by `SIPRAL_EVENT_KIND_LOOKUP_WANTED` and answered with `sipral_account_looked_up`, or `registrar_address` names an address; `SIPRAL_EVENT_KIND_RESOLVE_NEEDED` asks about a dialog's next hop | `server_uri`, answered by the platform's resolver unless `resolver=` replaces it |
| TLS | TLS settings on the transport: CA list, verify flags, backend choice ("SSL/TLS") | the application's TLS library; the stack is told `SIPRAL_TRANSPORT_TLS` | `signalling=Transport.TLS` with `tls_trust`, and TURN over TLS; `22-tls.md` |

## Endpoint, transport, account and call, whole

The smallest complete port: two stacks on loopback, one calling the other,
the call confirmed at both ends and hung up. Every PJSIP concept of the
first four rows of the map is in it — library lifetime, transport, event
pump, callbacks, account, outgoing and incoming call — and nothing else.

```c
/* Two stacks on loopback, one calling the other: endpoint, account and
 * call, with the application owning every socket and the clock. */
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "sipral.h"

struct end {
    const char *name;
    const char *address; /* host:port, what goes in Via and Contact */
    int sip;             /* the UDP socket this end's SIP uses */
    int media;           /* the UDP socket its call's audio would use */
    const char *media_address;
    sipral_handle_t stack;
    sipral_handle_t account;
    sipral_handle_t call;
    int confirmed;
    int ended;
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

static int udp_socket(const char *host, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in at = { 0 };
    at.sin_family = AF_INET;
    at.sin_port = htons(port);
    inet_pton(AF_INET, host, &at.sin_addr);
    if (fd < 0 || bind(fd, (struct sockaddr *)&at, sizeof at) != 0) {
        return -1;
    }
    fcntl(fd, F_SETFL, O_NONBLOCK);
    return fd;
}

/* Every event of one stack arrives here, on the thread that called
 * sipral_stack_poll: the place pjsua's callback struct used to be. */
static void on_event(const sipral_event_t *event, void *user_data)
{
    struct end *end = user_data;
    switch (event->kind) {
    case SIPRAL_EVENT_KIND_INCOMING_CALL:
        end->call = event->call;
        printf("%s: incoming call from %.*s\n", end->name,
               (int)event->payload.call.from_uri_len,
               (const char *)event->payload.call.from_uri);
        break;
    case SIPRAL_EVENT_KIND_CALL_CONFIRMED:
        end->confirmed = 1;
        printf("%s: call confirmed\n", end->name);
        break;
    case SIPRAL_EVENT_KIND_CALL_ENDED:
        end->ended = 1;
        printf("%s: call ended\n", end->name);
        break;
    default:
        break;
    }
}

static void say_last_error(const char *what)
{
    char why[256];
    size_t len = 0;
    sipral_last_error_message(why, sizeof why, &len);
    fprintf(stderr, "%s: %.*s\n", what, (int)len, why);
}

static int create_end(struct end *end)
{
    uint8_t seed[32];
    uint8_t media_seed[32];
    if (!entropy(seed, sizeof seed) || !entropy(media_seed, sizeof media_seed)) {
        return 0;
    }
    sipral_stack_config_t config;
    memset(&config, 0, sizeof config);
    config.size = sizeof config;
    config.event_callback = on_event;
    config.event_user_data = end;
    config.transport = SIPRAL_TRANSPORT_UDP;
    config.bind_address = end->address;
    config.bind_address_len = strlen(end->address);
    config.entropy = seed;
    config.entropy_len = sizeof seed;
    config.media_seed = media_seed;
    config.media_seed_len = sizeof media_seed;
    config.media_clock_unix_seconds = (uint64_t)time(NULL);
    config.audio = SIPRAL_AUDIO_APPLICATION;
    return sipral_stack_create(&config, &end->stack) == SIPRAL_STATUS_OK;
}

/* An account with no registrar never registers: every request it places
 * goes to registrar_address, here the other end directly. */
static int add_account(struct end *end, const char *aor, const char *contact, const char *peer)
{
    sipral_account_config_t account;
    memset(&account, 0, sizeof account);
    account.size = sizeof account;
    account.aor = aor;
    account.aor_len = strlen(aor);
    account.contact = contact;
    account.contact_len = strlen(contact);
    account.registrar_address = peer;
    account.registrar_address_len = strlen(peer);
    return sipral_account_add(end->stack, &account, &end->account) == SIPRAL_STATUS_OK;
}

static void split(const char *address, char *host, size_t capacity, uint16_t *port)
{
    const char *colon = strrchr(address, ':');
    size_t len = (size_t)(colon - address);
    if (len >= capacity) {
        len = capacity - 1;
    }
    memcpy(host, address, len);
    host[len] = '\0';
    *port = (uint16_t)atoi(colon + 1);
}

/* What pjsua's worker thread did: read the socket, hand the bytes in, let
 * the timers run, and write what the stack wants written. */
static void turn_once(struct end *end)
{
    uint8_t in[4096];
    struct sockaddr_in from;
    socklen_t from_len = sizeof from;
    ssize_t got;
    while ((got = recvfrom(end->sip, in, sizeof in, 0, (struct sockaddr *)&from, &from_len)) > 0) {
        char text[64];
        char host[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &from.sin_addr, host, sizeof host);
        snprintf(text, sizeof text, "%s:%u", host, ntohs(from.sin_port));
        sipral_stack_receive_datagram(end->stack, SIPRAL_TRANSPORT_MAIN, in, (size_t)got, text,
                                      strlen(text), NULL, 0, now_ms());
        from_len = sizeof from;
    }
    sipral_stack_poll(end->stack, now_ms(), NULL);

    uint8_t out[SIPRAL_MESSAGE_BYTES];
    char destination[128];
    char source[128];
    for (;;) {
        sipral_transmit_t transmit;
        memset(&transmit, 0, sizeof transmit);
        transmit.size = sizeof transmit;
        transmit.data = out;
        transmit.capacity = sizeof out;
        transmit.destination = destination;
        transmit.destination_capacity = sizeof destination - 1;
        transmit.source = source;
        transmit.source_capacity = sizeof source;
        if (sipral_stack_poll_transmit(end->stack, &transmit) != SIPRAL_STATUS_OK ||
            transmit.len == 0) {
            break;
        }
        destination[transmit.destination_len] = '\0';
        char host[64];
        uint16_t port;
        split(destination, host, sizeof host, &port);
        struct sockaddr_in to = { 0 };
        to.sin_family = AF_INET;
        to.sin_port = htons(port);
        inet_pton(AF_INET, host, &to.sin_addr);
        sendto(end->sip, out, transmit.len, 0, (struct sockaddr *)&to, sizeof to);
    }
}

int main(void)
{
    struct end alice = { "alice", "127.0.0.1:15060", -1, -1, "127.0.0.1:14000",
                         SIPRAL_HANDLE_NONE, SIPRAL_HANDLE_NONE, SIPRAL_HANDLE_NONE, 0, 0 };
    struct end bob = { "bob", "127.0.0.1:15062", -1, -1, "127.0.0.1:14002",
                       SIPRAL_HANDLE_NONE, SIPRAL_HANDLE_NONE, SIPRAL_HANDLE_NONE, 0, 0 };
    alice.sip = udp_socket("127.0.0.1", 15060);
    bob.sip = udp_socket("127.0.0.1", 15062);
    alice.media = udp_socket("127.0.0.1", 14000);
    bob.media = udp_socket("127.0.0.1", 14002);
    if (alice.sip < 0 || bob.sip < 0 || alice.media < 0 || bob.media < 0 ||
        !create_end(&alice) || !create_end(&bob) ||
        !add_account(&alice, "sip:alice@127.0.0.1", "sip:alice@127.0.0.1:15060", bob.address) ||
        !add_account(&bob, "sip:bob@127.0.0.1", "sip:bob@127.0.0.1:15062", alice.address)) {
        say_last_error("setup failed");
        return 1;
    }

    sipral_call_config_t call;
    memset(&call, 0, sizeof call);
    call.size = sizeof call;
    call.target = "sip:bob@127.0.0.1";
    call.target_len = strlen(call.target);
    call.media_address = alice.media_address;
    call.media_address_len = strlen(alice.media_address);
    if (sipral_call_place(alice.stack, alice.account, &call, &alice.call, now_ms()) !=
        SIPRAL_STATUS_OK) {
        say_last_error("sipral_call_place");
        return 1;
    }

    uint64_t deadline = now_ms() + 5000;
    int answered = 0;
    int hung_up = 0;
    while (now_ms() < deadline && !(alice.ended && bob.ended)) {
        turn_once(&alice);
        turn_once(&bob);
        if (bob.call != SIPRAL_HANDLE_NONE && !answered) {
            sipral_call_answer_media(bob.stack, bob.call, bob.media_address,
                                     strlen(bob.media_address), now_ms());
            answered = 1;
        }
        if (alice.confirmed && bob.confirmed && !hung_up) {
            sipral_call_hangup(alice.stack, alice.call, now_ms());
            hung_up = 1;
        }
        usleep(5000);
    }
    sipral_stack_destroy(alice.stack);
    sipral_stack_destroy(bob.stack);
    return alice.ended && bob.ended ? 0 : 1;
}
```

Built against the header and the library, it prints the call's five
events and exits 0:

```text
$ cargo build -p sipral-ffi
$ cc -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror -Ibindings/c/include two_ends.c \
    -Ltarget/debug -lsipral_ffi -Wl,-rpath,"$PWD/target/debug" -o two_ends
$ ./two_ends
bob: incoming call from sip:alice@127.0.0.1
alice: call confirmed
bob: call confirmed
alice: call ended
bob: call ended
```

What moved, from a PJSIP application's point of view:

- **Library lifetime.** PJSIP's create, init and start collapse into one
  `sipral_stack_create`; its configuration objects (UA, media, log) are one
  `sipral_stack_config_t`, versioned by its `size` member, zeroed and then
  filled. There is no separate start: the stack does nothing until it is
  polled.
- **Transport.** The two UDP sockets are the program's, and each stack is
  told the address its socket answers at (`bind_address`), which goes in
  every `Via`. A TCP or TLS transport is a connection the program opens and
  names with `sipral_stack_transport_bind` (`22-tls.md` has one, over
  OpenSSL).
- **Event pump.** `turn_once` is what PJSIP's worker thread did: read the
  socket, hand the bytes in, poll, and write what the stack queued. A real
  application waits on its sockets with the stack's own deadline,
  `sipral_poll_result_t::next_poll_in_ms`, instead of sleeping five
  milliseconds.
- **Account.** An account that names no `registrar` never registers, which
  is how two stacks call each other with nothing between them;
  `registrar_address` is where its requests go either way. A registering
  account names `registrar`, `auth_user` and `auth_password` and calls
  `sipral_account_register`; its progress is
  `SIPRAL_EVENT_KIND_REGISTRATION_CHANGED` with a `state` and a `failure`
  (`04-ua.md`).
- **Call.** `media_address` is where this end will receive audio, a socket
  the application already holds. With it set the stack writes the offer and
  the answer itself (`sipral_call_answer_media` at the far end); without
  it the application brings its own SDP (`sipral_call_answer`).

The same program through the Python layer, where the `Stack` owns the
socket and the poll thread:

```python
"""Two stacks on loopback, one calling the other, through the Python layer."""

import asyncio

from sipral import Stack
from sipral._sipral_cffi import lib
from sipral.enums import AudioMode


async def main() -> None:
    loop = asyncio.get_running_loop()
    with Stack(loop=loop, audio=AudioMode.APPLICATION) as alice, Stack(
        loop=loop, audio=AudioMode.APPLICATION
    ) as bob:
        # no registrar: each account sends straight to the other stack
        to_bob = alice.add_account(
            "sip:alice@127.0.0.1",
            registrar_address=bob.bind_address,
            contact=f"sip:alice@{alice.bind_address}",
        )
        bob.add_account(
            "sip:bob@127.0.0.1",
            registrar_address=alice.bind_address,
            contact=f"sip:bob@{bob.bind_address}",
        )

        call = alice.place_call(to_bob, "sip:bob@127.0.0.1")
        while True:
            event = await bob.events.get()
            if event.kind == lib.SIPRAL_EVENT_KIND_INCOMING_CALL:
                answered = bob.answer_call(event)
                break

        while True:
            event = await call.events.get()
            print("alice:", event.kind_name)
            if event.kind == lib.SIPRAL_EVENT_KIND_CALL_CONFIRMED:
                call.hangup()
            if event.kind == lib.SIPRAL_EVENT_KIND_CALL_ENDED:
                break
        answered.close()
        call.close()


asyncio.run(main())
```

```text
$ PYTHONPATH=bindings/python SIPRAL_LIBRARY=target/debug python3 two_ends.py
alice: call progress
alice: call confirmed
alice: media started
alice: call ended
```

## Media ports, the conference bridge and the sound device

PJSIP routes audio through a conference bridge: every source and sink is a
port, the sound device is one of them, and connecting ports is how a call
reaches the speaker or a WAV file ("Working with Audio Media"). Sipral has
no bridge and no ports. A call's media is a handle, minted with
`sipral_call_media` once `SIPRAL_EVENT_KIND_MEDIA_STARTED` says the session
is up, and it is driven one frame at a time:

- **The application's own audio** (application mode, PJSIP's null device):
  `sipral_media_capture` encodes the frame the application hands in and
  fills a packet to send; `sipral_media_playback` hands the next frame to
  play out of the jitter buffer. What PJSIP did with a file player port,
  an application does by handing the file's PCM to `capture`; recording a
  call is `sipral_media_record_start`.
- **The platform's devices** (device mode): the library opens microphone
  and loudspeaker and pumps every call through them. The packets still come
  back to the application to send from the call's own socket:

```c
#include <string.h>

#include "sipral.h"

/* Device mode: the library opens the platform's microphone and loudspeaker
 * and pumps every call through them. Each encoded packet still comes back
 * to the application, through this callback, to send from the call's own
 * media socket: the library never opens a socket. */
void configure_device_mode(sipral_stack_config_t *config, sipral_audio_transmit_callback_t send,
                           void *user_data)
{
    config->audio = SIPRAL_AUDIO_DEVICE;
    config->audio_activation = SIPRAL_AUDIO_ACTIVATION_AUTOMATIC;
    config->audio_transmit_callback = send;
    config->audio_transmit_user_data = user_data;
}

/* The loudspeaker on device `id` from sipral_audio_device_at, and the
 * microphone muted: what pjsua's sound device selection and conference
 * port levels did. */
sipral_status_t speaker_and_mute(sipral_handle_t stack, uint32_t id)
{
    sipral_status_t status = sipral_audio_select(stack, SIPRAL_AUDIO_ROLE_SPEAKER, id);
    if (status != SIPRAL_STATUS_OK) {
        return status;
    }
    return sipral_audio_set_muted(stack, SIPRAL_AUDIO_DIRECTION_INPUT, 1);
}
```

```python
import asyncio

from sipral import Stack, features
from sipral.enums import AudioDirection, AudioMode, AudioRole, Feature


async def main() -> None:
    loop = asyncio.get_running_loop()
    # device mode is the default where the build has an audio backend
    # (macOS, iOS, Windows); AudioMode.APPLICATION is pjsua's null sound device
    with Stack(loop=loop) as stack:
        if stack.audio_mode != AudioMode.DEVICE:
            print("no audio backend here:", Feature.AUDIO_DEVICE in features())
            return
        for device in stack.audio.devices():
            print(device.id, device.name, device.input_channels, device.output_channels)
        speaker = next(d for d in stack.audio.devices() if d.output_channels and d.present)
        try:
            stack.audio.select(AudioRole.SPEAKER, speaker)
        except Exception as refused:  # noqa: BLE001 -- printed, not hidden
            print("speaker not chosen:", refused)
        stack.audio.set_muted(AudioDirection.INPUT, True)
        stack.audio.volume = 0.8
        print("selection:", stack.audio.selection(AudioRole.SPEAKER))


asyncio.run(main())
```

On this machine the Python run listed the five devices macOS reported, chose
a speaker and muted the microphone; `stack.audio.selection(...)` answered
`(2, None)` — chosen, and not running, since device mode opens the devices
with the first call (`AudioActivation.AUTOMATIC`).

- **A local conference** is the one bridge-shaped thing: two calls joined,
  so that each far end hears the other and this end's microphone, which is
  what three `pjsua_conf_connect`-style connections made in PJSIP. It is
  joined once and then mixed frame by frame from the audio thread, in
  application mode:

```c
#include <stddef.h>
#include <stdint.h>

#include "sipral.h"

/* Two calls this stack already has media on, joined into a conference of
 * three: once, with sipral_call_join, then one frame at a time from the
 * audio thread. `mic` is this end's frame; `speaker` receives what this
 * end's loudspeaker is owed; each packet is what one far end is owed, to
 * send from that call's media socket. */
sipral_status_t conference_frame(sipral_handle_t media_a, sipral_handle_t media_b, uint64_t now_ms,
                                 const int16_t *mic, int16_t *speaker, size_t frame_samples,
                                 sipral_media_packet_t *to_a, sipral_media_packet_t *to_b)
{
    return sipral_media_mix(media_a, media_b, now_ms, mic, frame_samples, speaker, frame_samples,
                            to_a, to_b);
}

sipral_status_t start_conference(sipral_handle_t stack, sipral_handle_t call_a,
                                 sipral_handle_t call_b)
{
    return sipral_call_join(stack, call_a, call_b);
}
```

Both calls must have media running and agree on a sample rate and a frame
length, since nothing resamples (`08-ffi.md`, "Two calls can be joined into
a local conference of three"). For more than two calls, or calls on
different codecs and rates, `sipral_local_conference_create` mixes any
number, each on its own codec, and the idiomatic layers carry it as a
class of their own — Python's `LocalConference`, .NET's and Kotlin's
`SipralLocalConference`, Swift's `LocalConference` — which takes a member's
frames over from that call's own media thread while it is in the
conference (`08-ffi.md`, "Any number of calls can be mixed in a local
conference").

## Buddies, presence and messages

A PJSIP buddy is an object that holds a subscription and reports the
buddy's state ("Presence and Instant Messaging"). Sipral has the
subscription and not the object: `sipral_account_subscribe` with the
`presence` package keeps one SUBSCRIBE dialog alive, refreshing it and
starting a new one after a recoverable failure under the same handle, and
every NOTIFY arrives as `SIPRAL_EVENT_KIND_NOTIFIED` with the request in
`event->message`; a watched address's presence also arrives as
`SIPRAL_EVENT_KIND_PRESENCE_CHANGED`. The body is a PIDF document (RFC 3863),
and reading it is the application's; this tree reads the bodies of the
`dialog` package (a busy lamp field), of `message-summary` (message waiting,
`SIPRAL_EVENT_KIND_MESSAGES_WAITING`) and of `conference`
(`sipral_subscription_conference`). This end's own status is published with
`sipral_account_publish_presence` (RFC 3903), which the stack then refreshes
and modifies under the entity tag the compositor gave.

```c
#include <string.h>

#include "sipral.h"

/* One SUBSCRIBE dialog per watched address. What it learns arrives as
 * SIPRAL_EVENT_KIND_NOTIFIED, whose event->message is the NOTIFY itself;
 * for `presence` the body is a PIDF document (RFC 3863) to read. */
sipral_status_t watch_presence(sipral_handle_t stack, sipral_handle_t account, const char *uri,
                               uint64_t now_ms, sipral_handle_t *out_subscription)
{
    static const char package[] = "presence";
    sipral_subscribe_config_t config;
    memset(&config, 0, sizeof config);
    config.size = sizeof config;
    config.target = uri;
    config.target_len = strlen(uri);
    config.package = package;
    config.package_len = strlen(package);
    return sipral_account_subscribe(stack, account, &config, out_subscription, now_ms);
}
```

The Python layer does not wrap subscriptions yet, and the raw layer
underneath it (`sipral._sipral_cffi`) takes the same call:

```python
import asyncio

from sipral import Stack
from sipral._sipral_cffi import ffi, lib
from sipral.enums import AudioMode


def subscribe(stack, account, target: str, package: str = "presence") -> int:
    """`sipral_account_subscribe`, which the idiomatic layer does not wrap yet."""
    target_buf = ffi.new("char[]", target.encode())
    package_buf = ffi.new("char[]", package.encode())
    config = ffi.new("sipral_subscribe_config_t *")
    config.size = ffi.sizeof("sipral_subscribe_config_t")
    config.target, config.target_len = target_buf, len(target.encode())
    config.package, config.package_len = package_buf, len(package.encode())
    out = ffi.new("sipral_handle_t *")
    while True:
        status = lib.sipral_account_subscribe(stack.handle, account.handle, config, out, stack.now_ms())
        if status != lib.SIPRAL_STATUS_BUSY:  # the poll thread held the stack for a moment
            break
    if status != lib.SIPRAL_STATUS_OK:
        raise RuntimeError(ffi.string(lib.sipral_status_name(status)).decode())
    return int(out[0])


async def main() -> None:
    loop = asyncio.get_running_loop()
    with Stack(loop=loop, audio=AudioMode.APPLICATION) as alice, Stack(
        loop=loop, audio=AudioMode.APPLICATION
    ) as bob:
        account = alice.add_account(
            "sip:alice@127.0.0.1",
            registrar_address=bob.bind_address,
            contact=f"sip:alice@{alice.bind_address}",
        )
        watched = subscribe(alice, account, "sip:bob@127.0.0.1")
        print("subscribed, handle", hex(watched))
        try:
            while True:
                event = await asyncio.wait_for(alice.events.get(), timeout=5)
                if event.kind == lib.SIPRAL_EVENT_KIND_NOTIFIED:
                    # the NOTIFY itself; its body is the PIDF document (RFC 3863)
                    print(event.message.split(b"\r\n\r\n", 1)[1].decode())
                elif event.kind == lib.SIPRAL_EVENT_KIND_SUBSCRIPTION_CHANGED:
                    state = ffi.new("uint32_t *")
                    lib.sipral_subscription_state(alice.handle, watched, state)
                    print("subscription state", state[0])
        except asyncio.TimeoutError:
            pass

asyncio.run(main())
```

Against a second Sipral stack, which is not a presence server, the run
prints `subscription state 1` (requesting) and then finds the handle gone
when the refusal ends it; against a presence server the NOTIFY bodies print
instead.

An instant message is `sipral_account_message` (a MESSAGE outside any
dialog, RFC 3428), answered by `SIPRAL_EVENT_KIND_MESSAGE_SENT`; one that
arrives is `SIPRAL_EVENT_KIND_MESSAGE_RECEIVED`. Typing indications have no
entry point.

## Logging, errors and what to put in a bug report

PJSIP's log configuration sets a level, a console level, a file and a
callback ("The Endpoint"). Sipral writes no log. What it has instead:

- **Every failure answers.** A status code from the call that failed, and
  its reason in English in `sipral_last_error_message`, kept per thread
  until the next call on that thread.
- **Every change of state is an event**, with its reason in the payload:
  a registration's `failure` and `status_code`, a call's `end_reason` and
  `Reason` causes, a relay's `reason`.
- **The diagnostic record** (`14-diagnostics.md`): the endpoint's decisions
  and each call's, as JSON, bounded in memory, for a bug report.
- **A recording** (`18-replay.md`) of everything that crossed the boundary,
  which replays the session exactly.

```c
#include <stdio.h>
#include <stdlib.h>

#include "sipral.h"

/* Why the last call on this thread failed, in English. */
void print_last_error(const char *what, sipral_status_t status)
{
    char text[512];
    size_t len = 0;
    sipral_last_error_message(text, sizeof text, &len);
    fprintf(stderr, "%s: %s: %.*s\n", what, sipral_status_name(status), (int)len, text);
}

/* The stack's diagnostic record as JSON (docs/14-diagnostics.md): asked
 * once for its length, then read. The caller frees the result. */
char *diagnostics_json(sipral_handle_t stack)
{
    size_t needed = 0;
    sipral_stack_diagnostics_json(stack, NULL, 0, &needed);
    char *json = malloc(needed + 1);
    if (json == NULL ||
        sipral_stack_diagnostics_json(stack, json, needed, &needed) != SIPRAL_STATUS_OK) {
        free(json);
        return NULL;
    }
    json[needed] = '\0';
    return json;
}
```

## Threads and handles

PJSIP asks for worker threads to be configured and for every thread the
library did not create to register itself before calling in; it also warns
that a garbage-collected language must destroy its objects explicitly
("General Concepts"). In Sipral:

- No thread belongs to the library in application mode; device mode adds
  the audio engine's own, which calls the application only through
  `audio_transmit_callback`, one encoded packet at a time.
- Any thread may call any entry point. Signalling on one stack is one
  thread at a time; the loser of a race is told `SIPRAL_STATUS_BUSY` and
  retries. A call's media handle has a lock of its own, so the audio
  thread never waits on signalling.
- The event callback runs on the thread that called `sipral_stack_poll`,
  with nothing held: calling back into the stack from inside it is
  allowed, and so is destroying the stack.
- A handle names one object on one stack. Used after its object is gone it
  is `SIPRAL_STATUS_STALE_HANDLE`; used on another stack,
  `SIPRAL_STATUS_INVALID_HANDLE`. The idiomatic layers close their objects
  deterministically (`with` in Python, `using` in C#, `close()` in Swift and
  Kotlin), which is the moment the native object goes.

## TLS and DNS

PJSIP resolves names and runs TLS inside its transports, with a choice of
TLS backend and verification flags ("SSL/TLS"). Sipral's core does neither.
A registrar or a proxy is an address (`registrar_address`) or a URI
(`server_uri`): for a URI the stack runs RFC 3263 — NAPTR when asked for,
SRV, A or AAAA, the order kept for failover — and asks the application for
each lookup, which every idiomatic layer answers with the platform's
resolver. A dialog whose next hop turns out to be a name is
`SIPRAL_EVENT_KIND_RESOLVE_NEEDED`, answered with `sipral_stack_resolved`
or, legitimately, not at all. TLS is the application's, with the platform's
own library — the Swift, Kotlin, .NET and Python layers run it, and the Dart
layer on an account's own connection — and so is
the certificate check: `22-tls.md` is the recipe, per platform, with what
RFC 5922 asks beyond an ordinary HTTPS check and how to pin a PBX's own
certificate.

## What has no equivalent here

- **Video.** Phase 6, after 1.0 (`10-roadmap.md`).
- **A buddy list and a PIDF reader.** Watching and publishing presence are
  here; the list around them and the document inside a notification are
  the application's.
- **A file player port.** Audio in is PCM the application hands over.
- **Persisting configuration as JSON.** PJSUA2's configuration classes can
  write themselves out ("General Concepts"); a Sipral configuration is a
  struct the application fills from wherever it keeps its settings.
