/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
 * Copyright (c) 2026 Tiberiu Balasea
 *
 * What an integrator does on the first afternoon, compiled and run by
 * scripts/check.sh: ask the library whether it speaks this header's ABI and
 * whether it agrees about the length of every struct in it, build a stack
 * with a callback of its own, add an account, place one call, have another
 * refused, retire the transport and watch a third come back as not sent,
 * poll once, and dispose of the stack from inside the event callback --
 * which docs/08-ffi.md says is the one re-entrant call and which nothing
 * else proves from C.
 *
 * It links the shared library rather than the archive, because that is
 * what a packaged binding loads.
 */

#include <stdio.h>
#include <string.h>

#include "include/sipral.h"

/* Every struct that carries its own size. C's sizeof comes from the header
 * and the library answers with what it was compiled to, so a header and a
 * library from two builds disagree at load rather than in the first call.
 * Lengths only: two members of the same width exchanged is a struct of the
 * same length and passes. The list is compared against the library's own
 * count of them, so a fifteenth versioned struct fails here rather than
 * going unasked about. */
#define VERSIONED(X)                                                          \
    X(sipral_abi_version) X(sipral_capabilities) X(sipral_counters)           \
    X(sipral_stack_config) X(sipral_poll_result) X(sipral_stack_settings)     \
    X(sipral_account_config) X(sipral_call_config) X(sipral_codec_info)       \
    X(sipral_media_info) X(sipral_stream_stats) X(sipral_media_packet)        \
    X(sipral_transmit) X(sipral_event)

static int failures;

static void expect(const char *what, int held)
{
    if (!held) {
        printf("  smoke.c: %s\n", what);
        failures++;
    }
}

/* What an application keeps behind event_user_data. */
struct seen {
    unsigned marker;
    int events;
    /* what sipral_stack_destroy answered, or SIPRAL_STATUS_PANIC for a
     * callback that never ran: a status the entry point cannot return, so
     * the assertion below fails rather than passes on nothing */
    sipral_status_t destroyed;
};

/* The marker proves the pointer that comes back is the one handed over,
 * rather than null or somebody else's. */
#define MARKER 0xC0FFEEu

static void on_event(const sipral_event_t *event, void *user_data)
{
    struct seen *seen = (struct seen *)user_data;

    expect("the callback was handed a null user pointer", seen != NULL);
    if (seen == NULL) {
        return;
    }
    expect("event_user_data is not what was passed in", seen->marker == MARKER);
    seen->events++;
    /* The one call the contract allows from in here, and once. A second
     * destroy in the same poll answers SIPRAL_STATUS_STALE_HANDLE, which is
     * correct and is not what the contract is about; recording it would
     * overwrite what the first call answered. */
    if (seen->events == 1) {
        seen->destroyed = sipral_stack_destroy(event->stack);
    }
}

static void sizes_agree(void)
{
#define ASK(type)                                                             \
    {                                                                         \
        size_t reported = 0;                                                  \
        sipral_status_t status =                                              \
            sipral_abi_struct_size(#type "_t", strlen(#type "_t"), &reported);      \
        expect("the library has no " #type, status == SIPRAL_STATUS_OK);      \
        expect(#type " is a different length in the library",                 \
               reported == sizeof(type##_t));                                 \
    }
    VERSIONED(ASK)
#undef ASK

    /* And the list itself. Fourteen names typed here answer for fourteen
     * structs and say nothing about a fifteenth, so the library is asked how
     * many it has. A struct added to the ABI and not to VERSIONED fails
     * here. */
#define COUNT(type) +1
    {
        size_t carried = 0;
        sipral_status_t status = sipral_abi_versioned_count(&carried);
        expect("the library will not say how many structs carry a size",
               status == SIPRAL_STATUS_OK);
        expect("this ABI has a versioned struct smoke.c never asks about",
               carried == (size_t)(0 VERSIONED(COUNT)));
    }
#undef COUNT
}

int main(void)
{
    /* Read, not written down. Every branch parameter, tag and Call-ID is
     * derived from these thirty-two bytes, and RFC 3261 section 19.3 wants a
     * tag an attacker cannot guess, so a constant here would be a constant in
     * whatever an integrator copied this file into. That is the second job of
     * this file after guarding the gate: it is the shortest correct example of
     * the ABI anybody will read. */
    uint8_t entropy[32];
    uint8_t media_seed[32];
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom == NULL || fread(entropy, 1, sizeof entropy, urandom) != sizeof entropy ||
        fread(media_seed, 1, sizeof media_seed, urandom) != sizeof media_seed) {
        printf("  smoke.c: could not read %zu bytes of entropy\n",
               sizeof entropy + sizeof media_seed);
        if (urandom != NULL) {
            fclose(urandom);
        }
        return 1;
    }
    fclose(urandom);

    static const char bind[] = "192.0.2.10:5060";
    static const char aor[] = "sip:alice@example.com";
    static const char registrar[] = "sip:example.com";
    static const char contact[] = "sip:alice@192.0.2.10:5060";
    static const char registrar_address[] = "203.0.113.5:5060";
    static const char target[] = "sip:bob@example.com";
    static const char nonsense[] = "bob, the one in accounts";
    static const char media[] = "192.0.2.10:40000";

    struct seen seen = { MARKER, 0, SIPRAL_STATUS_PANIC };
    sipral_stack_config_t config = { 0 };
    sipral_account_config_t account_config = { 0 };
    sipral_call_config_t call_config = { 0 };
    sipral_call_config_t refused = { 0 };
    sipral_call_config_t stranded = { 0 };
    sipral_poll_result_t poll = { 0 };
    sipral_handle_t stack = SIPRAL_HANDLE_NONE;
    sipral_handle_t account = SIPRAL_HANDLE_NONE;
    sipral_handle_t call = SIPRAL_HANDLE_NONE;
    sipral_handle_t nowhere = SIPRAL_HANDLE_NONE;
    sipral_handle_t unsent = SIPRAL_HANDLE_NONE;
    char message[512] = { 0 };

    /* first, because nothing below means anything if the library was built
     * from another header */
    if (sipral_abi_check(SIPRAL_ABI_VERSION_MAJOR, SIPRAL_ABI_VERSION_MINOR)
        != SIPRAL_STATUS_OK) {
        printf("  smoke.c: this library does not speak the header's ABI\n");
        return 1;
    }
    sizes_agree();

    config.size = sizeof config;
    config.event_callback = on_event;
    config.event_user_data = &seen;
    config.transport = SIPRAL_TRANSPORT_UDP;
    config.bind_address = bind;
    config.bind_address_len = strlen(bind);
    config.entropy = entropy;
    config.entropy_len = sizeof entropy;
    /* A second, independent draw. Not a slice of the first and not a copy of
     * it: the library refuses the same bytes twice, because a replay recording
     * carries the signalling entropy in clear and must never carry the means
     * to derive a media key. */
    config.media_seed = media_seed;
    config.media_seed_len = sizeof media_seed;
    expect("the stack would not start",
           sipral_stack_create(&config, &stack) == SIPRAL_STATUS_OK);

    account_config.size = sizeof account_config;
    account_config.aor = aor;
    account_config.aor_len = strlen(aor);
    account_config.registrar = registrar;
    account_config.registrar_len = strlen(registrar);
    account_config.contact = contact;
    account_config.contact_len = strlen(contact);
    account_config.registrar_address = registrar_address;
    account_config.registrar_address_len = strlen(registrar_address);
    expect("the account was refused",
           sipral_account_add(stack, &account_config, &account)
               == SIPRAL_STATUS_OK);

    /* Nothing has bound a socket and nothing has been polled out of the
     * stack, so this INVITE is written and waits. That is the arrangement:
     * this library never touches the network, and `sipral_stack_poll_transmit`
     * is where the bytes come from. */
    call_config.size = sizeof call_config;
    call_config.target = target;
    call_config.target_len = strlen(target);
    call_config.media_address = media;
    call_config.media_address_len = strlen(media);
    expect("the call would not go out",
           sipral_call_place(stack, account, &call_config, &call, 0)
               == SIPRAL_STATUS_OK);
    expect("a call that went out has no handle", call != SIPRAL_HANDLE_NONE);

    /* And the other way: a call this stack cannot make has to come back as a
     * status with a sentence behind it, no handle, and a stack still usable.
     */
    refused.size = sizeof refused;
    refused.target = nonsense;
    refused.target_len = strlen(nonsense);
    refused.media_address = media;
    refused.media_address_len = strlen(media);
    expect("a call to something that is not a URI was accepted",
           sipral_call_place(stack, account, &refused, &nowhere, 0)
               == SIPRAL_STATUS_INVALID_ARGUMENT);
    expect("the call that failed handed back a handle anyway",
           nowhere == SIPRAL_HANDLE_NONE);
    expect("the refusal left no sentence behind",
           sipral_last_error_message(message, sizeof message, NULL)
                   == SIPRAL_STATUS_OK
               && message[0] != '\0');
    /* and the sentence is about what went wrong, not any sentence at all */
    expect("the sentence behind the refusal is about something else",
           strstr(message, "which is not a URI") != NULL);

    /* The third case, and the one a binding meets in the field: the socket
     * is gone. `sipral_stack_transport_failed` is how a caller says so, and
     * it retires the transport -- so a call that is otherwise perfect has
     * nowhere to be written, and has to come back saying so rather than
     * leave an INVITE nobody will ever send. */
    expect("retiring the transport was refused",
           sipral_stack_transport_failed(stack, SIPRAL_TRANSPORT_MAIN,
                                         SIPRAL_TRANSPORT_ERROR_CLOSED, 0)
               == SIPRAL_STATUS_OK);
    stranded.size = sizeof stranded;
    stranded.target = target;
    stranded.target_len = strlen(target);
    stranded.media_address = media;
    stranded.media_address_len = strlen(media);
    expect("a call was placed over a transport that is gone",
           sipral_call_place(stack, account, &stranded, &unsent, 0)
               == SIPRAL_STATUS_NOT_SENT);
    expect("the call that went nowhere handed back a handle anyway",
           unsent == SIPRAL_HANDLE_NONE);

    poll.size = sizeof poll;
    expect("the poll failed", sipral_stack_poll(stack, 0, &poll)
                                  == SIPRAL_STATUS_OK);
    expect("nothing reached the callback", seen.events > 0);
    expect("the poll and the callback disagree on how many events there were",
           poll.events_delivered == (size_t)seen.events);
    expect("destroying the stack from inside the callback was refused",
           seen.destroyed == SIPRAL_STATUS_OK);
    /* With a real out parameter, so the refusal is about the handle and
     * nothing else. Passing NULL here answers the same thing today, but only
     * because the handle is looked up before the pointer is read, and this
     * file is read as an example of how the entry points are called. */
    expect("the handle outlived the destroy",
           sipral_stack_poll(stack, 1, &poll) == SIPRAL_STATUS_STALE_HANDLE);

    if (failures != 0) {
        printf("  smoke.c: %d checks failed\n", failures);
        return 1;
    }
    return 0;
}
