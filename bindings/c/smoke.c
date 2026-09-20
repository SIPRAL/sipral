/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
 * Copyright (c) 2026 Tiberiu Balasea
 *
 * What an integrator does on the first afternoon, compiled and run by
 * scripts/check.sh: ask the library whether it speaks this header's ABI and
 * whether it agrees about the length of every struct in it, hand every struct
 * a caller declares to an entry point that takes it at the oldest length
 * abi-sizes.txt pins and one byte short of it, carry a header field of its own
 * across a call between two stacks and read it back out of the answer, build
 * a stack with a callback of its own, add an account, place one call, ask for
 * its media handle before it has any media, have another call refused, retire
 * the transport and watch a third come back as not sent, poll once, call back
 * into the stack from inside the event callback, and dispose of the stack from
 * in there too -- docs/08-ffi.md says the callback runs with nothing held, and
 * nothing else proves that from C.
 *
 * It links the shared library rather than the archive, because that is
 * what a packaged binding loads.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/sipral.h"

/* Every struct that carries its own size. C's sizeof comes from the header
 * and the library answers with what it was compiled to, so a header and a
 * library from two builds disagree at load rather than in the first call.
 * Lengths only: two members of the same width exchanged is a struct of the
 * same length and passes. The list is compared against the library's own
 * count of them, so a struct this list does not name fails here rather than
 * going unasked about. */
#define VERSIONED(X)                                                          \
    X(sipral_abi_version) X(sipral_capabilities) X(sipral_counters)           \
    X(sipral_stack_config) X(sipral_poll_result) X(sipral_stack_settings)     \
    X(sipral_account_config) X(sipral_call_config) X(sipral_codec_info)       \
    X(sipral_codec_candidate) X(sipral_media_info) X(sipral_stream_stats)     \
    X(sipral_media_packet) X(sipral_transmit) X(sipral_event)                 \
    X(sipral_suspending) X(sipral_screen_request)                             \
    X(sipral_subscribe_config) X(sipral_watched_dialog) X(sipral_push_echo)

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
    /* what a question put to the stack from inside the callback answered,
     * and what sipral_stack_destroy answered after it -- each
     * SIPRAL_STATUS_PANIC for a callback that never ran: a status the entry
     * points cannot return, so the assertions below fail rather than pass on
     * nothing */
    sipral_status_t reentered;
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
    /* Nothing is held while this runs, so a question put to the stack from in
     * here is an ordinary call -- and so is disposing of it, which is what a
     * binding whose object dies in its own event handler does. Once each: a
     * second destroy in the same poll answers SIPRAL_STATUS_STALE_HANDLE,
     * which is correct and is not what the contract is about; recording it
     * would overwrite what the first call answered. */
    if (seen->events == 1) {
        sipral_stack_settings_t settings = { 0 };
        settings.size = sizeof settings;
        seen->reentered = sipral_stack_settings(event->stack, &settings);
        seen->destroyed = sipral_stack_destroy(event->stack);
    }
}

/* The same, about one named struct. */
static void expect_about(const char *what, const char *about, int held)
{
    if (!held) {
        printf("  smoke.c: %s: %s\n", about, what);
        failures++;
    }
}

/* -- the oldest lengths -----------------------------------------------------
 *
 * A caller compiled against the first published header declared its structs
 * at the lengths that header had, and appending a member to a released struct
 * is the one change allowed -- so those lengths have to keep working after
 * the struct grows, and one byte short of each has to be a status this
 * library defines rather than whatever reading past a declared end would do.
 *
 * The length tried is the pinned one, never the one the library compiled the
 * struct to. The day a member is appended the two part company, and a test
 * that asks for the current length is testing the rule the pin replaced.
 * `sipral_abi_struct_size` answers with the current length and nothing across
 * the ABI answers with the pinned one, so the pins are read from
 * abi-sizes.txt beside this file, which tools/abi-gen prints from them and
 * the gate diffs. The file is held to the library before any number in it is
 * used: every current length in it is the one the library reports, and it
 * lists exactly as many structs as `sipral_abi_versioned_count` says there
 * are. Every pinned struct then has to find the entry point below that takes
 * one, and every entry point below has to find its struct pinned, so a struct
 * the ABI gains, or one that stops being pinned, fails here by name. */

/* A stack, an account and a call of this test's own, so that what it does to
 * them -- an account added and a call placed per length tried -- stays out of
 * the stack main() walks through. */
struct fixture {
    sipral_handle_t stack;
    sipral_handle_t account;
    sipral_handle_t call;
    sipral_handle_t subscription;
};

static uint8_t message_buffer[SIPRAL_MESSAGE_BYTES];
static uint8_t packet_buffer[SIPRAL_MEDIA_PACKET_BYTES];
static char destination_buffer[SIPRAL_ADDRESS_BYTES];
static char source_buffer[SIPRAL_ADDRESS_BYTES];

static const char fixture_bind[] = "192.0.2.30:5060";
static const char fixture_aor[] = "sip:carol@example.com";
static const char fixture_registrar[] = "sip:example.com";
static const char fixture_contact[] = "sip:carol@192.0.2.30:5060";
static const char fixture_registrar_address[] = "203.0.113.5:5060";
static const char fixture_target[] = "sip:dave@example.com";
static const char fixture_media[] = "192.0.2.30:40000";
static const char fixture_peer[] = "203.0.113.5:5060";
static const char fixture_watched[] = "sip:dave@example.com";
static const char fixture_push_provider[] = "apns";
static const char fixture_push_prid[] = "smoke-device-token";

/* One dialog on the watched extension, ringing, so that the table a busy
 * lamp field reads has a row in it. */
static const char fixture_dialog_info[] =
    "<?xml version=\"1.0\"?>\n"
    "<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\" version=\"1\" state=\"full\" "
    "entity=\"sip:dave@example.com\">\n"
    "  <dialog id=\"smoke\"><state>early</state></dialog>\n"
    "</dialog-info>";

/* A call that comes in with an offer and is answered with media of this
 * stack's own, because two of the structs describe a call's media and a call
 * that was only placed has none yet. */
static const char fixture_invite[] =
    "INVITE sip:carol@192.0.2.30:5060 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-smoke-oldest\r\n"
    "Max-Forwards: 70\r\n"
    "From: <sip:dave@example.com>;tag=smoke\r\n"
    "To: <sip:carol@example.com>\r\n"
    "Call-ID: smoke-oldest@203.0.113.5\r\n"
    "CSeq: 1 INVITE\r\n"
    "Contact: <sip:dave@203.0.113.5:5060>\r\n"
    "Content-Type: application/sdp\r\n";
static const char fixture_offer[] =
    "v=0\r\n"
    "o=dave 1 1 IN IP4 203.0.113.5\r\n"
    "s=-\r\n"
    "c=IN IP4 203.0.113.5\r\n"
    "t=0 0\r\n"
    "m=audio 41000 RTP/AVP 0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=sendrecv\r\n";

/* Stacks built only to be refused or thrown away never report anything that
 * is read. */
static void on_event_ignored(const sipral_event_t *event, void *user_data)
{
    (void)event;
    (void)user_data;
}

/* Below, beside the two structs a busy lamp field reads, because it is what
 * fills their table in. */
static int fixture_subscribe(struct fixture *fixture);
static int fixture_register(struct fixture *fixture);

/* The one thing the fixture's own stack reports that it keeps: the call that
 * came in. */
static void on_fixture_event(const sipral_event_t *event, void *user_data)
{
    struct fixture *fixture = (struct fixture *)user_data;
    if (event->kind == SIPRAL_EVENT_KIND_INCOMING_CALL) {
        fixture->call = event->call;
    }
}

/* Fresh bytes per stack: two stacks must never be handed the same ones. */
static int draw(uint8_t *into, size_t len)
{
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom == NULL) {
        return 0;
    }
    size_t taken = fread(into, 1, len, urandom);
    fclose(urandom);
    return taken == len;
}

static sipral_stack_config_t fixture_stack_config(size_t declared, const uint8_t *entropy,
                                                  const uint8_t *media_seed)
{
    sipral_stack_config_t config = { 0 };
    config.size = declared;
    config.event_callback = on_event_ignored;
    config.transport = SIPRAL_TRANSPORT_UDP;
    config.bind_address = fixture_bind;
    config.bind_address_len = strlen(fixture_bind);
    config.entropy = entropy;
    config.entropy_len = 32;
    config.media_seed = media_seed;
    config.media_seed_len = 32;
    return config;
}

static sipral_account_config_t fixture_account_config(size_t declared)
{
    sipral_account_config_t config = { 0 };
    config.size = declared;
    config.aor = fixture_aor;
    config.aor_len = strlen(fixture_aor);
    config.registrar = fixture_registrar;
    config.registrar_len = strlen(fixture_registrar);
    config.contact = fixture_contact;
    config.contact_len = strlen(fixture_contact);
    config.registrar_address = fixture_registrar_address;
    config.registrar_address_len = strlen(fixture_registrar_address);
    /* woken through a notification service, because one of the structs below
     * is what the registrar answered about that. Every one of these goes on
     * the REGISTER's Contact and on no other request, so the call this
     * fixture also places is unaffected. */
    config.push_provider = fixture_push_provider;
    config.push_provider_len = strlen(fixture_push_provider);
    config.push_prid = fixture_push_prid;
    config.push_prid_len = strlen(fixture_push_prid);
    return config;
}

static sipral_call_config_t fixture_call_config(size_t declared)
{
    sipral_call_config_t config = { 0 };
    config.size = declared;
    config.target = fixture_target;
    config.target_len = strlen(fixture_target);
    config.media_address = fixture_media;
    config.media_address_len = strlen(fixture_media);
    return config;
}

static int fixture_up(struct fixture *fixture)
{
    uint8_t entropy[32];
    uint8_t media_seed[32];
    fixture->stack = SIPRAL_HANDLE_NONE;
    fixture->account = SIPRAL_HANDLE_NONE;
    fixture->call = SIPRAL_HANDLE_NONE;
    if (!draw(entropy, sizeof entropy) || !draw(media_seed, sizeof media_seed)) {
        expect("could not read entropy for the stack the oldest lengths are tried on", 0);
        return 0;
    }
    sipral_stack_config_t stack = fixture_stack_config(sizeof stack, entropy, media_seed);
    stack.event_callback = on_fixture_event;
    stack.event_user_data = fixture;
    sipral_account_config_t account = fixture_account_config(sizeof account);
    expect("the stack the oldest lengths are tried on would not start",
           sipral_stack_create(&stack, &fixture->stack) == SIPRAL_STATUS_OK);
    expect("the account the oldest lengths are tried on was refused",
           sipral_account_add(fixture->stack, &account, &fixture->account) == SIPRAL_STATUS_OK);

    char invite[1024];
    int length = snprintf(invite, sizeof invite, "%sContent-Length: %zu\r\n\r\n%s",
                          fixture_invite, strlen(fixture_offer), fixture_offer);
    if (length <= 0 || (size_t)length >= sizeof invite) {
        expect("the INVITE the oldest lengths are tried on does not fit its buffer", 0);
        return 0;
    }
    sipral_poll_result_t poll = { 0 };
    poll.size = sizeof poll;
    expect("the INVITE the oldest lengths are tried on was not taken",
           sipral_stack_receive_datagram(fixture->stack, SIPRAL_TRANSPORT_MAIN,
                                         (const uint8_t *)invite, (size_t)length, fixture_peer,
                                         strlen(fixture_peer), fixture_bind, strlen(fixture_bind),
                                         0) == SIPRAL_STATUS_OK);
    expect("the stack the oldest lengths are tried on would not poll",
           sipral_stack_poll(fixture->stack, 0, &poll) == SIPRAL_STATUS_OK);
    expect("the call the oldest lengths are tried on never came in",
           fixture->call != SIPRAL_HANDLE_NONE);
    if (fixture->call == SIPRAL_HANDLE_NONE) {
        return 0;
    }
    sipral_status_t answered = sipral_call_answer_media(
        fixture->stack, fixture->call, fixture_media, strlen(fixture_media), 0);
    expect("the call the oldest lengths are tried on could not be answered with media",
           answered == SIPRAL_STATUS_OK);
    if (answered != SIPRAL_STATUS_OK) {
        return 0;
    }

    /* The stream opens when the 200 is acknowledged, and the ACK has to carry
     * the To tag this end chose, so it is copied out of the 200 the stack
     * wrote. */
    char to[256] = { 0 };
    for (int drained = 0; drained < 8 && to[0] == '\0'; drained++) {
        sipral_transmit_t transmit = { 0 };
        transmit.size = sizeof transmit;
        transmit.data = message_buffer;
        transmit.capacity = sizeof message_buffer - 1;
        transmit.destination = destination_buffer;
        transmit.destination_capacity = sizeof destination_buffer;
        transmit.source = source_buffer;
        transmit.source_capacity = sizeof source_buffer;
        if (sipral_stack_poll_transmit(fixture->stack, &transmit) != SIPRAL_STATUS_OK ||
            transmit.len == 0) {
            break;
        }
        message_buffer[transmit.len] = '\0';
        const char *text = (const char *)message_buffer;
        if (strncmp(text, "SIP/2.0 200", strlen("SIP/2.0 200")) != 0) {
            continue;
        }
        const char *field = strstr(text, "\r\nTo: ");
        const char *end = field == NULL ? NULL : strstr(field + 6, "\r\n");
        if (end == NULL || (size_t)(end - (field + 6)) >= sizeof to) {
            break;
        }
        memcpy(to, field + 6, (size_t)(end - (field + 6)));
    }
    expect("the 200 for the call the oldest lengths are tried on never went out with a To",
           to[0] != '\0');
    if (to[0] == '\0') {
        return 0;
    }
    char ack[512];
    length = snprintf(ack, sizeof ack,
                      "ACK %s SIP/2.0\r\n"
                      "Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-smoke-oldest-ack\r\n"
                      "Max-Forwards: 70\r\n"
                      "From: <sip:dave@example.com>;tag=smoke\r\n"
                      "To: %s\r\n"
                      "Call-ID: smoke-oldest@203.0.113.5\r\n"
                      "CSeq: 1 ACK\r\n"
                      "Content-Length: 0\r\n\r\n",
                      fixture_contact, to);
    if (length <= 0 || (size_t)length >= sizeof ack) {
        expect("the ACK the oldest lengths are tried on does not fit its buffer", 0);
        return 0;
    }
    expect("the ACK for the call the oldest lengths are tried on was not taken",
           sipral_stack_receive_datagram(fixture->stack, SIPRAL_TRANSPORT_MAIN,
                                         (const uint8_t *)ack, (size_t)length, fixture_peer,
                                         strlen(fixture_peer), fixture_bind, strlen(fixture_bind),
                                         0) == SIPRAL_STATUS_OK);
    expect("the stack the oldest lengths are tried on would not poll after the ACK",
           sipral_stack_poll(fixture->stack, 0, &poll) == SIPRAL_STATUS_OK);
    expect("the registrar never answered the fixture's account about push",
           fixture_register(fixture));
    expect("the subscription the oldest lengths are tried on was never told about a dialog",
           fixture_subscribe(fixture));
    return 1;
}

/* One entry point per struct, each handed that struct declared at the length
 * it is given. */

static sipral_status_t abi_version_at(struct fixture *fixture, size_t declared)
{
    (void)fixture;
    sipral_abi_version_t version = { 0 };
    version.size = declared;
    return sipral_abi_version(&version);
}

static sipral_status_t capabilities_at(struct fixture *fixture, size_t declared)
{
    (void)fixture;
    sipral_capabilities_t capabilities = { 0 };
    capabilities.size = declared;
    return sipral_capabilities(&capabilities);
}

static sipral_status_t counters_at(struct fixture *fixture, size_t declared)
{
    sipral_counters_t counters = { 0 };
    counters.size = declared;
    return sipral_stack_counters(fixture->stack, &counters);
}

/* What a stack hands back when it is told the machine is going to sleep:
 * how much of what it holds has stopped being evidence. Asked at an old
 * length here like every other versioned struct, which is the whole of what
 * this table is for. */
static sipral_status_t suspending_at(struct fixture *fixture, size_t declared)
{
    sipral_suspending_t suspending = { 0 };
    suspending.size = declared;
    return sipral_stack_suspending(fixture->stack, 0, &suspending);
}

static sipral_status_t stack_config_at(struct fixture *fixture, size_t declared)
{
    (void)fixture;
    uint8_t entropy[32];
    uint8_t media_seed[32];
    if (!draw(entropy, sizeof entropy) || !draw(media_seed, sizeof media_seed)) {
        expect("could not read entropy for a stack declared at an old length", 0);
        return SIPRAL_STATUS_PANIC;
    }
    sipral_stack_config_t config = fixture_stack_config(declared, entropy, media_seed);
    sipral_handle_t stack = SIPRAL_HANDLE_NONE;
    sipral_status_t status = sipral_stack_create(&config, &stack);
    expect("a refused stack construction handed back a handle anyway",
           status == SIPRAL_STATUS_OK || stack == SIPRAL_HANDLE_NONE);
    if (stack != SIPRAL_HANDLE_NONE) {
        sipral_stack_destroy(stack);
    }
    return status;
}

static sipral_status_t poll_result_at(struct fixture *fixture, size_t declared)
{
    sipral_poll_result_t result = { 0 };
    result.size = declared;
    return sipral_stack_poll(fixture->stack, 0, &result);
}

static sipral_status_t stack_settings_at(struct fixture *fixture, size_t declared)
{
    sipral_stack_settings_t settings = { 0 };
    settings.size = declared;
    return sipral_stack_settings(fixture->stack, &settings);
}

static sipral_status_t account_config_at(struct fixture *fixture, size_t declared)
{
    sipral_account_config_t config = fixture_account_config(declared);
    sipral_handle_t account = SIPRAL_HANDLE_NONE;
    sipral_status_t status = sipral_account_add(fixture->stack, &config, &account);
    expect("a refused account handed back a handle anyway",
           status == SIPRAL_STATUS_OK || account == SIPRAL_HANDLE_NONE);
    if (account != SIPRAL_HANDLE_NONE) {
        sipral_account_remove(fixture->stack, account);
    }
    return status;
}

static sipral_status_t call_config_at(struct fixture *fixture, size_t declared)
{
    sipral_call_config_t config = fixture_call_config(declared);
    sipral_handle_t call = SIPRAL_HANDLE_NONE;
    sipral_status_t status =
        sipral_call_place(fixture->stack, fixture->account, &config, &call, 0);
    expect("a refused call handed back a handle anyway",
           status == SIPRAL_STATUS_OK || call == SIPRAL_HANDLE_NONE);
    return status;
}

/* One header field of a message this stack wrote, copied out by name: the
 * answer to a SUBSCRIBE has to carry the branch, the tags and the Call-ID
 * that request chose, and there is no parser here to ask. */
static int header_of(const char *text, const char *name, char *out, size_t room)
{
    char wanted[64];
    if ((size_t)snprintf(wanted, sizeof wanted, "\r\n%s: ", name) >= sizeof wanted) {
        return 0;
    }
    const char *found = strstr(text, wanted);
    if (found == NULL) {
        return 0;
    }
    const char *value = found + strlen(wanted);
    const char *end = strstr(value, "\r\n");
    if (end == NULL || (size_t)(end - value) >= room) {
        return 0;
    }
    memcpy(out, value, (size_t)(end - value));
    out[end - value] = '\0';
    return 1;
}

/* The SUBSCRIBE this stack last wrote, if it wrote one. */
static int drain_for_subscribe(struct fixture *fixture, char *into, size_t room)
{
    for (int drained = 0; drained < 8; drained++) {
        sipral_transmit_t transmit = { 0 };
        transmit.size = sizeof transmit;
        transmit.data = message_buffer;
        transmit.capacity = sizeof message_buffer - 1;
        transmit.destination = destination_buffer;
        transmit.destination_capacity = sizeof destination_buffer;
        transmit.source = source_buffer;
        transmit.source_capacity = sizeof source_buffer;
        if (sipral_stack_poll_transmit(fixture->stack, &transmit) != SIPRAL_STATUS_OK ||
            transmit.len == 0) {
            return 0;
        }
        message_buffer[transmit.len] = '\0';
        if (strncmp((const char *)message_buffer, "SUBSCRIBE ", strlen("SUBSCRIBE ")) != 0) {
            continue;
        }
        if (transmit.len >= room) {
            return 0;
        }
        memcpy(into, message_buffer, transmit.len);
        into[transmit.len] = '\0';
        return 1;
    }
    return 0;
}

/* The registrar's answer about push, so that the struct it is read out of can
 * be handed over at its oldest published length. */
static int fixture_register(struct fixture *fixture)
{
    if (sipral_account_register(fixture->stack, fixture->account, 0) != SIPRAL_STATUS_OK) {
        return 0;
    }
    char reg[2048] = { 0 };
    for (int drained = 0; drained < 8 && reg[0] == '\0'; drained++) {
        sipral_transmit_t transmit = { 0 };
        transmit.size = sizeof transmit;
        transmit.data = message_buffer;
        transmit.capacity = sizeof message_buffer - 1;
        transmit.destination = destination_buffer;
        transmit.destination_capacity = sizeof destination_buffer;
        transmit.source = source_buffer;
        transmit.source_capacity = sizeof source_buffer;
        if (sipral_stack_poll_transmit(fixture->stack, &transmit) != SIPRAL_STATUS_OK ||
            transmit.len == 0) {
            break;
        }
        message_buffer[transmit.len] = '\0';
        if (strncmp((const char *)message_buffer, "REGISTER ", strlen("REGISTER ")) != 0 ||
            transmit.len >= sizeof reg) {
            continue;
        }
        memcpy(reg, message_buffer, transmit.len);
        reg[transmit.len] = '\0';
    }
    if (reg[0] == '\0') {
        return 0;
    }
    char via[256];
    char from[256];
    char to[256];
    char call_id[256];
    char cseq[64];
    char contact[512];
    if (!header_of(reg, "Via", via, sizeof via) || !header_of(reg, "From", from, sizeof from) ||
        !header_of(reg, "To", to, sizeof to) ||
        !header_of(reg, "Call-ID", call_id, sizeof call_id) ||
        !header_of(reg, "CSeq", cseq, sizeof cseq) ||
        !header_of(reg, "Contact", contact, sizeof contact)) {
        return 0;
    }
    char answer[2048];
    int length = snprintf(answer, sizeof answer,
                          "SIP/2.0 200 OK\r\n"
                          "Via: %s\r\n"
                          "From: %s\r\n"
                          "To: %s;tag=smoke-registrar\r\n"
                          "Call-ID: %s\r\n"
                          "CSeq: %s\r\n"
                          "Contact: %s\r\n"
                          "Feature-Caps: *;+sip.pns=\"apns\";+sip.pnsreg=\"121\"\r\n"
                          "Expires: 3600\r\n"
                          "Content-Length: 0\r\n\r\n",
                          via, from, to, call_id, cseq, contact);
    if (length <= 0 || (size_t)length >= sizeof answer) {
        return 0;
    }
    if (sipral_stack_receive_datagram(fixture->stack, SIPRAL_TRANSPORT_MAIN,
                                      (const uint8_t *)answer, (size_t)length, fixture_peer,
                                      strlen(fixture_peer), fixture_bind, strlen(fixture_bind),
                                      0) != SIPRAL_STATUS_OK) {
        return 0;
    }
    sipral_poll_result_t poll = { 0 };
    poll.size = sizeof poll;
    if (sipral_stack_poll(fixture->stack, 0, &poll) != SIPRAL_STATUS_OK) {
        return 0;
    }
    sipral_push_echo_t echo = { 0 };
    echo.size = sizeof echo;
    return sipral_account_push_echo(fixture->stack, fixture->account, &echo) ==
               SIPRAL_STATUS_OK &&
           echo.accepted != 0;
}

static sipral_status_t push_echo_at(struct fixture *fixture, size_t declared)
{
    sipral_push_echo_t echo = { 0 };
    echo.size = declared;
    return sipral_account_push_echo(fixture->stack, fixture->account, &echo);
}

static sipral_subscribe_config_t fixture_subscribe_config(size_t declared)
{
    sipral_subscribe_config_t config = { 0 };
    config.size = declared;
    config.target = fixture_watched;
    config.target_len = strlen(fixture_watched);
    config.package = "dialog";
    config.package_len = strlen("dialog");
    return config;
}

/* A subscription of the fixture's own, granted and told about one dialog, so
 * that the struct a busy lamp field reads can be handed over at its oldest
 * published length. */
static int fixture_subscribe(struct fixture *fixture)
{
    /* Emptied first, so that the SUBSCRIBE read back below is this one's and
     * not something the stack had already queued: waking up refreshes every
     * subscription it already holds, and answering one of those would leave
     * the one asked for here unanswered. */
    for (int drained = 0; drained < 16; drained++) {
        sipral_transmit_t transmit = { 0 };
        transmit.size = sizeof transmit;
        transmit.data = message_buffer;
        transmit.capacity = sizeof message_buffer - 1;
        transmit.destination = destination_buffer;
        transmit.destination_capacity = sizeof destination_buffer;
        transmit.source = source_buffer;
        transmit.source_capacity = sizeof source_buffer;
        if (sipral_stack_poll_transmit(fixture->stack, &transmit) != SIPRAL_STATUS_OK ||
            transmit.len == 0) {
            break;
        }
    }
    sipral_subscribe_config_t config = fixture_subscribe_config(sizeof config);
    if (sipral_account_subscribe(fixture->stack, fixture->account, &config,
                                 &fixture->subscription, 0) != SIPRAL_STATUS_OK) {
        return 0;
    }
    char subscribe[2048];
    if (!drain_for_subscribe(fixture, subscribe, sizeof subscribe)) {
        return 0;
    }
    char via[256];
    char from[256];
    char to[256];
    char call_id[256];
    char cseq[64];
    if (!header_of(subscribe, "Via", via, sizeof via) ||
        !header_of(subscribe, "From", from, sizeof from) ||
        !header_of(subscribe, "To", to, sizeof to) ||
        !header_of(subscribe, "Call-ID", call_id, sizeof call_id) ||
        !header_of(subscribe, "CSeq", cseq, sizeof cseq)) {
        return 0;
    }

    char answer[1024];
    int length = snprintf(answer, sizeof answer,
                          "SIP/2.0 200 OK\r\n"
                          "Via: %s\r\n"
                          "From: %s\r\n"
                          "To: %s;tag=smoke-notifier\r\n"
                          "Call-ID: %s\r\n"
                          "CSeq: %s\r\n"
                          "Expires: 600\r\n"
                          "Contact: <sip:pbx@203.0.113.5:5060>\r\n"
                          "Content-Length: 0\r\n\r\n",
                          via, from, to, call_id, cseq);
    if (length <= 0 || (size_t)length >= sizeof answer) {
        return 0;
    }
    if (sipral_stack_receive_datagram(fixture->stack, SIPRAL_TRANSPORT_MAIN,
                                      (const uint8_t *)answer, (size_t)length, fixture_peer,
                                      strlen(fixture_peer), fixture_bind, strlen(fixture_bind),
                                      0) != SIPRAL_STATUS_OK) {
        return 0;
    }

    char notify[2048];
    /* A branch of its own per subscription, because this runs more than once
     * -- what a notifier said stops being evidence the moment the machine
     * suspends, and one of the structs tried before this one suspends it --
     * and a NOTIFY reusing a branch would read as a retransmission of the
     * first. */
    static unsigned notified;
    notified++;
    length = snprintf(notify, sizeof notify,
                      "NOTIFY %s SIP/2.0\r\n"
                      "Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-smoke-notify-%u\r\n"
                      "Max-Forwards: 70\r\n"
                      "From: %s;tag=smoke-notifier\r\n"
                      "To: %s\r\n"
                      "Call-ID: %s\r\n"
                      "CSeq: 1 NOTIFY\r\n"
                      "Contact: <sip:pbx@203.0.113.5:5060>\r\n"
                      "Event: dialog\r\n"
                      "Subscription-State: active;expires=600\r\n"
                      "Content-Type: application/dialog-info+xml\r\n"
                      "Content-Length: %zu\r\n\r\n%s",
                      fixture_contact, notified, to, from, call_id,
                      strlen(fixture_dialog_info), fixture_dialog_info);
    if (length <= 0 || (size_t)length >= sizeof notify) {
        return 0;
    }
    if (sipral_stack_receive_datagram(fixture->stack, SIPRAL_TRANSPORT_MAIN,
                                      (const uint8_t *)notify, (size_t)length, fixture_peer,
                                      strlen(fixture_peer), fixture_bind, strlen(fixture_bind),
                                      0) != SIPRAL_STATUS_OK) {
        return 0;
    }
    sipral_poll_result_t poll = { 0 };
    poll.size = sizeof poll;
    if (sipral_stack_poll(fixture->stack, 0, &poll) != SIPRAL_STATUS_OK) {
        return 0;
    }
    size_t dialogs = 0;
    return sipral_subscription_dialog_count(fixture->stack, fixture->subscription, &dialogs) ==
               SIPRAL_STATUS_OK &&
           dialogs == 1;
}

static sipral_status_t subscribe_config_at(struct fixture *fixture, size_t declared)
{
    sipral_subscribe_config_t config = fixture_subscribe_config(declared);
    sipral_handle_t subscription = SIPRAL_HANDLE_NONE;
    return sipral_account_subscribe(fixture->stack, fixture->account, &config, &subscription, 0);
}

static sipral_status_t watched_dialog_at(struct fixture *fixture, size_t declared)
{
    /* Something tried before this one may have taken the table away:
     * sipral_stack_suspending is defined to, because what a notifier said
     * stops being evidence the moment the machine sleeps. So the subscription
     * is made again here rather than relied on, and the order the lengths are
     * tried in stops mattering. */
    size_t dialogs = 0;
    if (sipral_subscription_dialog_count(fixture->stack, fixture->subscription, &dialogs) !=
            SIPRAL_STATUS_OK ||
        dialogs == 0) {
        /* and a stack that was told the machine is going to sleep sends
         * nothing until it is told it woke up, which is what the one before
         * this left it believing */
        if (sipral_stack_resumed(fixture->stack, 0) != SIPRAL_STATUS_OK ||
            !fixture_subscribe(fixture)) {
            return SIPRAL_STATUS_WRONG_STATE;
        }
    }
    sipral_watched_dialog_t dialog = { 0 };
    dialog.size = declared;
    return sipral_subscription_dialog_at(fixture->stack, fixture->subscription, 0, &dialog);
}

static sipral_status_t codec_info_at(struct fixture *fixture, size_t declared)
{
    (void)fixture;
    sipral_codec_info_t info = { 0 };
    info.size = declared;
    return sipral_codec_at(0, &info);
}

/* The three media structs go through a handle on the fixture's call, minted
 * for the one question and let go after it. A mint that fails answers
 * WRONG_STATE, which is neither status either check expects, so both of that
 * struct's checks fail by name rather than passing on nothing. */
static sipral_handle_t media_handle_of(struct fixture *fixture)
{
    sipral_handle_t media = SIPRAL_HANDLE_NONE;
    if (sipral_call_media(fixture->stack, fixture->call, &media) != SIPRAL_STATUS_OK) {
        return SIPRAL_HANDLE_NONE;
    }
    return media;
}

static sipral_status_t media_info_at(struct fixture *fixture, size_t declared)
{
    sipral_media_info_t info = { 0 };
    info.size = declared;
    sipral_handle_t media = media_handle_of(fixture);
    if (media == SIPRAL_HANDLE_NONE) {
        return SIPRAL_STATUS_WRONG_STATE;
    }
    sipral_status_t status = sipral_media_info(media, &info);
    sipral_media_release(media);
    return status;
}

static sipral_status_t codec_candidate_at(struct fixture *fixture, size_t declared)
{
    sipral_codec_candidate_t candidate = { 0 };
    candidate.size = declared;
    sipral_handle_t media = media_handle_of(fixture);
    if (media == SIPRAL_HANDLE_NONE) {
        return SIPRAL_STATUS_WRONG_STATE;
    }
    sipral_status_t status = sipral_media_codec_candidate_at(media, 0, &candidate);
    sipral_media_release(media);
    return status;
}

static sipral_status_t stream_stats_at(struct fixture *fixture, size_t declared)
{
    sipral_stream_stats_t stats = { 0 };
    stats.size = declared;
    sipral_handle_t media = media_handle_of(fixture);
    if (media == SIPRAL_HANDLE_NONE) {
        return SIPRAL_STATUS_WRONG_STATE;
    }
    sipral_status_t status = sipral_media_statistics(media, 0, &stats);
    sipral_media_release(media);
    return status;
}

static sipral_status_t media_packet_at(struct fixture *fixture, size_t declared)
{
    sipral_media_packet_t packet = { 0 };
    packet.size = declared;
    packet.data = packet_buffer;
    packet.capacity = sizeof packet_buffer;
    packet.destination = destination_buffer;
    packet.destination_capacity = sizeof destination_buffer;
    sipral_handle_t media = media_handle_of(fixture);
    if (media == SIPRAL_HANDLE_NONE) {
        return SIPRAL_STATUS_WRONG_STATE;
    }
    sipral_status_t status = sipral_media_poll_rtcp(media, 0, &packet);
    sipral_media_release(media);
    return status;
}

static sipral_status_t transmit_at(struct fixture *fixture, size_t declared)
{
    sipral_transmit_t transmit = { 0 };
    transmit.size = declared;
    transmit.data = message_buffer;
    transmit.capacity = sizeof message_buffer;
    transmit.destination = destination_buffer;
    transmit.destination_capacity = sizeof destination_buffer;
    transmit.source = source_buffer;
    transmit.source_capacity = sizeof source_buffer;
    return sipral_stack_poll_transmit(fixture->stack, &transmit);
}

static const struct {
    const char *name;
    sipral_status_t (*at)(struct fixture *fixture, size_t declared);
} handovers[] = {
    { "sipral_abi_version_t", abi_version_at },
    { "sipral_capabilities_t", capabilities_at },
    { "sipral_counters_t", counters_at },
    { "sipral_stack_config_t", stack_config_at },
    { "sipral_poll_result_t", poll_result_at },
    { "sipral_stack_settings_t", stack_settings_at },
    { "sipral_account_config_t", account_config_at },
    { "sipral_call_config_t", call_config_at },
    { "sipral_codec_info_t", codec_info_at },
    { "sipral_codec_candidate_t", codec_candidate_at },
    { "sipral_media_info_t", media_info_at },
    { "sipral_stream_stats_t", stream_stats_at },
    { "sipral_media_packet_t", media_packet_at },
    { "sipral_transmit_t", transmit_at },
    { "sipral_suspending_t", suspending_at },
    { "sipral_subscribe_config_t", subscribe_config_at },
    { "sipral_watched_dialog_t", watched_dialog_at },
    { "sipral_push_echo_t", push_echo_at },
};

#define HANDOVERS (sizeof handovers / sizeof handovers[0])

/* abi-sizes.txt sits beside this file, and check.sh compiles and runs this
 * file from the repository root, which is where __FILE__ is relative to. */
static FILE *beside_this_file(const char *name)
{
    const char *slash = strrchr(__FILE__, '/');
    size_t directory = slash == NULL ? 0 : (size_t)(slash - __FILE__) + 1;
    char path[4096];
    if (directory + strlen(name) + 1 > sizeof path) {
        return NULL;
    }
    memcpy(path, __FILE__, directory);
    memcpy(path + directory, name, strlen(name) + 1);
    return fopen(path, "r");
}

static void oldest_lengths_still_work(void)
{
    FILE *sizes = beside_this_file("abi-sizes.txt");
    expect("abi-sizes.txt could not be read from beside smoke.c, and a length test that "
           "reads nothing proves nothing",
           sizes != NULL);
    if (sizes == NULL) {
        return;
    }
    struct fixture fixture;
    if (!fixture_up(&fixture)) {
        fclose(sizes);
        return;
    }

    size_t listed = 0;
    unsigned tried[HANDOVERS] = { 0 };
    char line[256];
    while (fgets(line, sizeof line, sizes) != NULL) {
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        char name[64];
        char pinned_text[32];
        size_t current = 0;
        if (sscanf(line, "%63s %31s %zu", name, pinned_text, &current) != 3) {
            expect("abi-sizes.txt has a line smoke.c cannot read", 0);
            continue;
        }
        listed++;

        size_t reported = 0;
        expect_about("abi-sizes.txt and the library disagree about how long it is now", name,
                     sipral_abi_struct_size(name, strlen(name), &reported) == SIPRAL_STATUS_OK &&
                         reported == current);
        if (strcmp(pinned_text, "-") == 0) {
            continue;
        }
        char *end = NULL;
        unsigned long long pinned = strtoull(pinned_text, &end, 10);
        if (end == pinned_text || *end != '\0' || pinned == 0 || pinned > current) {
            expect_about("abi-sizes.txt pins it at something that is not a length", name, 0);
            continue;
        }
        size_t which = 0;
        while (which < HANDOVERS && strcmp(handovers[which].name, name) != 0) {
            which++;
        }
        if (which == HANDOVERS) {
            expect_about("abi-sizes.txt pins it and smoke.c has no entry point to hand one to",
                         name, 0);
            continue;
        }
        tried[which]++;
        expect_about("declared at its oldest published length, it was refused", name,
                     handovers[which].at(&fixture, (size_t)pinned) == SIPRAL_STATUS_OK);
        expect_about("declared one byte short of its oldest published length, it was not "
                     "refused as a version",
                     name,
                     handovers[which].at(&fixture, (size_t)pinned - 1) ==
                         SIPRAL_STATUS_UNSUPPORTED_VERSION);
    }
    fclose(sizes);

    size_t carried = 0;
    expect("abi-sizes.txt does not list every struct the library says carries a size",
           sipral_abi_versioned_count(&carried) == SIPRAL_STATUS_OK && carried == listed);
    for (size_t which = 0; which < HANDOVERS; which++) {
        expect_about("smoke.c hands it over and abi-sizes.txt does not pin it exactly once",
                     handovers[which].name, tried[which] == 1);
    }
    sipral_stack_destroy(fixture.stack);
}

/* -- header fields in and out ------------------------------------------------
 *
 * What an integrator asks for right after placing a call: a field of its own
 * on the INVITE, and the same field read back out of what the far end
 * answered, without a SIP parser written in C to find it. Two stacks in one
 * process, a caller and a callee, with the bytes carried between them by hand.
 * The callee reads the field out of the INVITE its event carries and echoes it
 * on the 200 with sipral_call_set_headers; the caller reads it out of the 200
 * its own event carries. Both reads happen inside the callback, because the
 * message an event points at lives exactly that long. */

static const char crossing_caller_bind[] = "192.0.2.40:5060";
static const char crossing_callee_bind[] = "192.0.2.41:5060";
static const char crossing_target[] = "sip:frank@192.0.2.41:5060";
static const char crossing_name[] = "X-Conversation-Id";
static const char crossing_label[] = "smoke-crossing-7";

/* What one of the two stacks saw: the call that came in, and the field read
 * out of the message the event carried. */
struct crossing {
    sipral_handle_t call;
    int invited;
    int confirmed;
    char value[64];
};

/* The first line of a field, copied out of a message as a C string: 1 when
 * there was one and it fit. */
static int field_of(const uint8_t *message, size_t message_len, const char *name, char *into,
                    size_t room)
{
    size_t count = 0;
    size_t offset = 0;
    size_t len = 0;
    if (sipral_message_header_count(message, message_len, name, strlen(name), &count) !=
            SIPRAL_STATUS_OK ||
        count == 0 ||
        sipral_message_header(message, message_len, name, strlen(name), 0, &offset, &len) !=
            SIPRAL_STATUS_OK ||
        len >= room) {
        return 0;
    }
    memcpy(into, message + offset, len);
    into[len] = '\0';
    return 1;
}

static void on_crossing_event(const sipral_event_t *event, void *user_data)
{
    struct crossing *crossing = (struct crossing *)user_data;
    if (event->kind == SIPRAL_EVENT_KIND_INCOMING_CALL) {
        crossing->call = event->call;
        crossing->invited = field_of(event->message, event->message_len, crossing_name,
                                     crossing->value, sizeof crossing->value);
    } else if (event->kind == SIPRAL_EVENT_KIND_CALL_CONFIRMED) {
        crossing->confirmed = field_of(event->message, event->message_len, crossing_name,
                                       crossing->value, sizeof crossing->value);
    }
}

/* Everything `from` wants written, handed to `to` as datagrams arriving from
 * `from_address`: how many were carried, or -1 when a call refused. */
static int carry(sipral_handle_t from, const char *from_address, sipral_handle_t to,
                 const char *to_address)
{
    int carried = 0;
    for (;;) {
        sipral_transmit_t transmit = { 0 };
        transmit.size = sizeof transmit;
        transmit.data = message_buffer;
        transmit.capacity = sizeof message_buffer;
        transmit.destination = destination_buffer;
        transmit.destination_capacity = sizeof destination_buffer;
        transmit.source = source_buffer;
        transmit.source_capacity = sizeof source_buffer;
        if (sipral_stack_poll_transmit(from, &transmit) != SIPRAL_STATUS_OK) {
            return -1;
        }
        if (transmit.len == 0) {
            return carried;
        }
        if (sipral_stack_receive_datagram(to, SIPRAL_TRANSPORT_MAIN, message_buffer, transmit.len,
                                          from_address, strlen(from_address), to_address,
                                          strlen(to_address), 0) != SIPRAL_STATUS_OK) {
            return -1;
        }
        carried++;
    }
}

/* A stack for one end of the crossing, with an account whose requests go to
 * the other end. */
static sipral_handle_t crossing_end(struct crossing *seen, const char *bind, const char *aor,
                                    const char *contact, const char *other,
                                    sipral_handle_t *out_account)
{
    uint8_t entropy[32];
    uint8_t media_seed[32];
    sipral_handle_t stack = SIPRAL_HANDLE_NONE;
    *out_account = SIPRAL_HANDLE_NONE;
    if (!draw(entropy, sizeof entropy) || !draw(media_seed, sizeof media_seed)) {
        expect("could not read entropy for a stack the header fields cross between", 0);
        return SIPRAL_HANDLE_NONE;
    }
    sipral_stack_config_t config = fixture_stack_config(sizeof config, entropy, media_seed);
    config.bind_address = bind;
    config.bind_address_len = strlen(bind);
    config.event_callback = on_crossing_event;
    config.event_user_data = seen;
    expect("a stack the header fields cross between would not start",
           sipral_stack_create(&config, &stack) == SIPRAL_STATUS_OK);
    sipral_account_config_t account = fixture_account_config(sizeof account);
    account.aor = aor;
    account.aor_len = strlen(aor);
    account.contact = contact;
    account.contact_len = strlen(contact);
    account.registrar_address = other;
    account.registrar_address_len = strlen(other);
    expect("an account the header fields cross between was refused",
           sipral_account_add(stack, &account, out_account) == SIPRAL_STATUS_OK);
    return stack;
}

static void headers_cross_a_call(void)
{
    struct crossing caller_seen = { SIPRAL_HANDLE_NONE, 0, 0, { 0 } };
    struct crossing callee_seen = { SIPRAL_HANDLE_NONE, 0, 0, { 0 } };
    sipral_handle_t caller_account = SIPRAL_HANDLE_NONE;
    sipral_handle_t callee_account = SIPRAL_HANDLE_NONE;
    sipral_handle_t call = SIPRAL_HANDLE_NONE;
    sipral_poll_result_t poll = { 0 };
    poll.size = sizeof poll;

    sipral_handle_t caller =
        crossing_end(&caller_seen, crossing_caller_bind, "sip:erin@example.com",
                     "sip:erin@192.0.2.40:5060", crossing_callee_bind, &caller_account);
    sipral_handle_t callee =
        crossing_end(&callee_seen, crossing_callee_bind, "sip:frank@example.com",
                     "sip:frank@192.0.2.41:5060", crossing_caller_bind, &callee_account);

    const sipral_header_t label[1] = {
        { crossing_name, strlen(crossing_name), crossing_label, strlen(crossing_label) },
    };
    sipral_call_config_t call_config = { 0 };
    call_config.size = sizeof call_config;
    call_config.target = crossing_target;
    call_config.target_len = strlen(crossing_target);
    call_config.sdp = (const uint8_t *)fixture_offer;
    call_config.sdp_len = strlen(fixture_offer);
    call_config.headers = label;
    call_config.headers_len = 1;
    expect("a call carrying a header field of the application's own would not go out",
           sipral_call_place(caller, caller_account, &call_config, &call, 0) == SIPRAL_STATUS_OK);
    expect("the INVITE did not reach the callee",
           carry(caller, crossing_caller_bind, callee, crossing_callee_bind) == 1);
    expect("the callee would not poll", sipral_stack_poll(callee, 0, &poll) == SIPRAL_STATUS_OK);
    expect("the call never reached the callee", callee_seen.call != SIPRAL_HANDLE_NONE);
    expect("the field was not read out of the INVITE through sipral_message_header",
           callee_seen.invited && strcmp(callee_seen.value, crossing_label) == 0);
    if (callee_seen.call == SIPRAL_HANDLE_NONE) {
        sipral_stack_destroy(callee);
        sipral_stack_destroy(caller);
        return;
    }

    const sipral_header_t echo[1] = {
        { crossing_name, strlen(crossing_name), callee_seen.value, strlen(callee_seen.value) },
    };
    expect("the callee would not set the field it answers with",
           sipral_call_set_headers(callee, callee_seen.call, echo, 1) == SIPRAL_STATUS_OK);

    /* Two it must not take, and taking neither leaves the field above in
     * place: a field the stack writes itself, and a value that would end its
     * line and start another. */
    static const char owned_name[] = "Call-ID";
    static const char owned_value[] = "somebody-elses@example.net";
    static const char broken_value[] = "smoke\r\nContact: <sip:elsewhere@example.net>";
    const sipral_header_t owned[1] = {
        { owned_name, strlen(owned_name), owned_value, strlen(owned_value) },
    };
    const sipral_header_t broken[1] = {
        { crossing_name, strlen(crossing_name), broken_value, strlen(broken_value) },
    };
    expect("a Call-ID of the application's own was taken",
           sipral_call_set_headers(callee, callee_seen.call, owned, 1) ==
               SIPRAL_STATUS_INVALID_ARGUMENT);
    expect("a value with a line break in it was taken",
           sipral_call_set_headers(callee, callee_seen.call, broken, 1) ==
               SIPRAL_STATUS_INVALID_ARGUMENT);

    expect("the callee would not answer",
           sipral_call_answer(callee, callee_seen.call, (const uint8_t *)fixture_offer,
                              strlen(fixture_offer), 0) == SIPRAL_STATUS_OK);
    expect("the 200 did not reach the caller",
           carry(callee, crossing_callee_bind, caller, crossing_caller_bind) >= 1);
    expect("the caller would not poll", sipral_stack_poll(caller, 0, &poll) == SIPRAL_STATUS_OK);
    expect("the field did not come back on the 200, read through sipral_message_header",
           caller_seen.confirmed && strcmp(caller_seen.value, crossing_label) == 0);

    /* And reading a field that is on two lines, one of them a list, and a
     * Call-ID written in its compact form. */
    static const char listed[] = "SIP/2.0 200 OK\r\n"
                                 "Via: SIP/2.0/UDP 192.0.2.40:5060;branch=z9hG4bK-smoke-listed\r\n"
                                 "From: <sip:erin@example.com>;tag=e\r\n"
                                 "To: <sip:frank@example.com>;tag=f\r\n"
                                 "i: smoke-listed@192.0.2.40\r\n"
                                 "CSeq: 1 INVITE\r\n"
                                 "Diversion: <sip:desk@example.com>, <sip:front@example.com>\r\n"
                                 "Diversion: <sip:mobile@example.com>\r\n"
                                 "Content-Length: 0\r\n"
                                 "\r\n";
    static const char diversion[] = "Diversion";
    static const char call_id[] = "Call-ID";
    const uint8_t *bytes = (const uint8_t *)listed;
    size_t count = 0;
    size_t offset = 0;
    size_t len = 0;
    expect("two lines of one field did not count as two",
           sipral_message_header_count(bytes, strlen(listed), diversion, strlen(diversion),
                                       &count) == SIPRAL_STATUS_OK &&
               count == 2);
    expect("the second line of a field is not the one that arrived second",
           sipral_message_header(bytes, strlen(listed), diversion, strlen(diversion), 1, &offset,
                                 &len) == SIPRAL_STATUS_OK &&
               len == strlen("<sip:mobile@example.com>") &&
               memcmp(listed + offset, "<sip:mobile@example.com>", len) == 0);
    expect("an index past the count was not refused",
           sipral_message_header(bytes, strlen(listed), diversion, strlen(diversion), 2, &offset,
                                 &len) == SIPRAL_STATUS_INVALID_ARGUMENT);
    expect("three values across two lines did not count as three",
           sipral_message_header_element_count(bytes, strlen(listed), diversion,
                                               strlen(diversion), &count) == SIPRAL_STATUS_OK &&
               count == 3);
    expect("the second value of the list is not the one after the first comma",
           sipral_message_header_element(bytes, strlen(listed), diversion, strlen(diversion), 1,
                                         &offset, &len) == SIPRAL_STATUS_OK &&
               len == strlen("<sip:front@example.com>") &&
               memcmp(listed + offset, "<sip:front@example.com>", len) == 0);
    expect("a Call-ID written compact was not counted by its long name",
           sipral_message_header_count(bytes, strlen(listed), call_id, strlen(call_id), &count) ==
                   SIPRAL_STATUS_OK &&
               count == 1);
    expect("a Call-ID written compact was not found by its long name",
           sipral_message_header(bytes, strlen(listed), call_id, strlen(call_id), 0, &offset,
                                 &len) == SIPRAL_STATUS_OK &&
               len == strlen("smoke-listed@192.0.2.40") &&
               memcmp(listed + offset, "smoke-listed@192.0.2.40", len) == 0);

    sipral_stack_destroy(callee);
    sipral_stack_destroy(caller);
}

/* -- a next hop nothing here will look up ------------------------------------
 *
 * RFC 3263 4 through the ABI: the far end answered with a Contact naming a
 * host, so the dialog's requests should go somewhere only a resolver can
 * name. Nothing below this boundary owns one, so the question comes out as an
 * event and the answer goes back in as a list.
 */
static sipral_handle_t asked_dialog;
static char asked_host[256];
static uint32_t asked_port;
static uint32_t asked_protocol;

static void on_resolve_event(const sipral_event_t *event, void *user_data)
{
    (void)user_data;
    if (event->kind != SIPRAL_EVENT_KIND_RESOLVE_NEEDED) {
        return;
    }
    asked_dialog = event->payload.resolve.dialog;
    asked_port = event->payload.resolve.port;
    asked_protocol = event->payload.resolve.protocol;
    size_t len = event->payload.resolve.host_len;
    if (len >= sizeof asked_host) {
        len = sizeof asked_host - 1;
    }
    if (event->payload.resolve.host != NULL) {
        memcpy(asked_host, event->payload.resolve.host, len);
    }
    asked_host[len] = '\0';
}

/* Drain everything the stack wants written and report where the first message
 * beginning with `start` was going. */
static int going_to(sipral_handle_t stack, const char *start, char *into, size_t room)
{
    int found = 0;
    for (;;) {
        sipral_transmit_t transmit = { 0 };
        transmit.size = sizeof transmit;
        transmit.data = message_buffer;
        transmit.capacity = sizeof message_buffer - 1;
        transmit.destination = destination_buffer;
        transmit.destination_capacity = sizeof destination_buffer;
        transmit.source = source_buffer;
        transmit.source_capacity = sizeof source_buffer;
        if (sipral_stack_poll_transmit(stack, &transmit) != SIPRAL_STATUS_OK ||
            transmit.len == 0) {
            return found;
        }
        message_buffer[transmit.len] = '\0';
        if (found || strncmp((const char *)message_buffer, start, strlen(start)) != 0) {
            continue;
        }
        if (strlen(destination_buffer) >= room) {
            return 0;
        }
        memcpy(into, destination_buffer, strlen(destination_buffer) + 1);
        found = 1;
    }
}

static void a_next_hop_is_asked_about_and_answered(void)
{
    static const char elsewhere[] = "198.51.100.7:5080";
    static const char target[] = "sip:bob@example.com";
    uint8_t entropy[32];
    uint8_t media_seed[32];
    if (!draw(entropy, sizeof entropy) || !draw(media_seed, sizeof media_seed)) {
        expect("could not read entropy for the stack a next hop is asked about on", 0);
        return;
    }
    asked_dialog = SIPRAL_HANDLE_NONE;
    asked_host[0] = '\0';

    sipral_stack_config_t config = fixture_stack_config(sizeof config, entropy, media_seed);
    config.event_callback = on_resolve_event;
    sipral_handle_t stack = SIPRAL_HANDLE_NONE;
    expect("the stack a next hop is asked about on would not start",
           sipral_stack_create(&config, &stack) == SIPRAL_STATUS_OK);
    if (stack == SIPRAL_HANDLE_NONE) {
        return;
    }
    sipral_account_config_t account_config = fixture_account_config(sizeof account_config);
    sipral_handle_t account = SIPRAL_HANDLE_NONE;
    expect("the account a next hop is asked about on was refused",
           sipral_account_add(stack, &account_config, &account) == SIPRAL_STATUS_OK);

    sipral_call_config_t call_config = { 0 };
    call_config.size = sizeof call_config;
    call_config.target = target;
    call_config.target_len = strlen(target);
    call_config.sdp = (const uint8_t *)fixture_offer;
    call_config.sdp_len = strlen(fixture_offer);
    sipral_handle_t call = SIPRAL_HANDLE_NONE;
    expect("the call whose next hop is a name would not go out",
           sipral_call_place(stack, account, &call_config, &call, 0) == SIPRAL_STATUS_OK);

    char invite[2048] = { 0 };
    for (int drained = 0; drained < 8 && invite[0] == '\0'; drained++) {
        sipral_transmit_t transmit = { 0 };
        transmit.size = sizeof transmit;
        transmit.data = message_buffer;
        transmit.capacity = sizeof message_buffer - 1;
        transmit.destination = destination_buffer;
        transmit.destination_capacity = sizeof destination_buffer;
        transmit.source = source_buffer;
        transmit.source_capacity = sizeof source_buffer;
        if (sipral_stack_poll_transmit(stack, &transmit) != SIPRAL_STATUS_OK ||
            transmit.len == 0) {
            break;
        }
        message_buffer[transmit.len] = '\0';
        if (strncmp((const char *)message_buffer, "INVITE ", strlen("INVITE ")) != 0 ||
            transmit.len >= sizeof invite) {
            continue;
        }
        memcpy(invite, message_buffer, transmit.len + 1);
    }
    if (invite[0] == '\0') {
        expect("the INVITE never came out", 0);
        sipral_stack_destroy(stack);
        return;
    }

    char via[256];
    char from[256];
    char to[256];
    char call_id[256];
    char cseq[64];
    if (!header_of(invite, "Via", via, sizeof via) ||
        !header_of(invite, "From", from, sizeof from) ||
        !header_of(invite, "To", to, sizeof to) ||
        !header_of(invite, "Call-ID", call_id, sizeof call_id) ||
        !header_of(invite, "CSeq", cseq, sizeof cseq)) {
        expect("the INVITE the far end is answering cannot be read", 0);
        sipral_stack_destroy(stack);
        return;
    }
    /* the Contact names a host, which is the whole point: the dialog's next
     * hop is now something only a resolver turns into an address */
    char answer[2048];
    int length = snprintf(answer, sizeof answer,
                          "SIP/2.0 200 OK\r\n"
                          "Via: %s\r\n"
                          "From: %s\r\n"
                          "To: %s;tag=smoke-farend\r\n"
                          "Call-ID: %s\r\n"
                          "CSeq: %s\r\n"
                          "Contact: <sip:bob@bob.example.com>\r\n"
                          "Content-Length: 0\r\n\r\n",
                          via, from, to, call_id, cseq);
    if (length <= 0 || (size_t)length >= sizeof answer) {
        expect("the answer the far end sends does not fit its buffer", 0);
        sipral_stack_destroy(stack);
        return;
    }
    expect("the answer was not taken",
           sipral_stack_receive_datagram(stack, SIPRAL_TRANSPORT_MAIN, (const uint8_t *)answer,
                                         (size_t)length, fixture_peer, strlen(fixture_peer),
                                         fixture_bind, strlen(fixture_bind),
                                         0) == SIPRAL_STATUS_OK);
    sipral_poll_result_t poll = { 0 };
    poll.size = sizeof poll;
    expect("the stack would not poll", sipral_stack_poll(stack, 0, &poll) == SIPRAL_STATUS_OK);

    expect("nothing asked about the next hop", asked_dialog != SIPRAL_HANDLE_NONE);
    expect("the host asked about is not the one the Contact named",
           strcmp(asked_host, "bob.example.com") == 0);
    expect("a port was invented for a URI that gave none", asked_port == 0);
    expect("a transport was invented for a URI that named none", asked_protocol == 0);
    if (asked_dialog == SIPRAL_HANDLE_NONE) {
        sipral_stack_destroy(stack);
        return;
    }

    /* a name where an address belongs is refused, because resolving one is
     * exactly what this call is the answer to */
    expect("a name was accepted as an answer",
           sipral_stack_resolved(stack, asked_dialog, "bob.example.com:5060",
                                 strlen("bob.example.com:5060"),
                                 0) == SIPRAL_STATUS_INVALID_ARGUMENT);

    expect("the answer was refused",
           sipral_stack_resolved(stack, asked_dialog, elsewhere, strlen(elsewhere), 0) ==
               SIPRAL_STATUS_OK);
    expect("the call would not hang up",
           sipral_call_hangup(stack, call, 1) == SIPRAL_STATUS_OK);
    char went[SIPRAL_ADDRESS_BYTES] = { 0 };
    expect("the BYE never came out", going_to(stack, "BYE ", went, sizeof went));
    expect("the answer did not move where the dialog's requests go",
           strcmp(went, elsewhere) == 0);

    sipral_stack_destroy(stack);
}

/* -- a registration that survives the process --------------------------------
 *
 * C3 through the ABI: a binding written down on the way into suspend, read
 * back by a process that was not there when it was written, and coming up
 * restored rather than registered -- because nobody has confirmed it since.
 */
/* DTLS-SRTP, from the one side of the boundary that can prove it is really
 * there: a C program.
 *
 * What the ABI promises is that naming the policy writes a description keyed
 * by a handshake and that the handshake's first record is waiting to be sent.
 * Both are checked against the octets, because the failure they guard against
 * is exactly the one that looks like success -- a call that rings, answers,
 * and carries nothing in either direction for the two minutes it takes DTLS
 * to give up.
 *
 * In a build without the feature the policy is refused instead, and that is
 * checked too: a number that has left the header is spent, so it is in this
 * header either way and must answer for itself in both builds. */
static void a_call_keyed_by_a_handshake_says_so_in_its_offer(void)
{
    static const char target[] = "sip:bob@example.com";
    uint8_t entropy[32];
    uint8_t media_seed[32];
    if (!draw(entropy, sizeof entropy) || !draw(media_seed, sizeof media_seed)) {
        expect("could not read entropy for the DTLS-SRTP stack", 0);
        return;
    }

    sipral_capabilities_t capabilities = { 0 };
    capabilities.size = sizeof capabilities;
    expect("capabilities would not be read for the DTLS-SRTP check",
           sipral_capabilities(&capabilities) == SIPRAL_STATUS_OK);
    int has_dtls = (capabilities.features & SIPRAL_FEATURE_DTLS_SRTP) != 0;

    sipral_stack_config_t config = fixture_stack_config(sizeof config, entropy, media_seed);
    sipral_handle_t stack = SIPRAL_HANDLE_NONE;
    expect("the DTLS-SRTP stack would not start",
           sipral_stack_create(&config, &stack) == SIPRAL_STATUS_OK);
    if (stack == SIPRAL_HANDLE_NONE) {
        return;
    }
    sipral_account_config_t account_config = fixture_account_config(sizeof account_config);
    sipral_handle_t account = SIPRAL_HANDLE_NONE;
    expect("the DTLS-SRTP account was refused",
           sipral_account_add(stack, &account_config, &account) == SIPRAL_STATUS_OK);

    sipral_call_config_t call_config = { 0 };
    call_config.size = sizeof call_config;
    call_config.target = target;
    call_config.target_len = strlen(target);
    call_config.media_address = fixture_media;
    call_config.media_address_len = strlen(fixture_media);
    call_config.srtp = SIPRAL_SRTP_DTLS;
    sipral_handle_t call = SIPRAL_HANDLE_NONE;
    sipral_status_t placed = sipral_call_place(stack, account, &call_config, &call, 0);

    if (!has_dtls) {
        /* the whole of what a build without it owes an application: say so,
         * rather than place the unencrypted call the policy was chosen to
         * prevent */
        expect("a build with no handshake took a DTLS-SRTP policy anyway",
               placed == SIPRAL_STATUS_NOT_SUPPORTED);
        sipral_stack_destroy(stack);
        return;
    }
    expect("the DTLS-SRTP call would not go out", placed == SIPRAL_STATUS_OK);

    char invite[4096] = { 0 };
    for (int drained = 0; drained < 8 && invite[0] == '\0'; drained++) {
        sipral_transmit_t transmit = { 0 };
        transmit.size = sizeof transmit;
        transmit.data = message_buffer;
        transmit.capacity = sizeof message_buffer - 1;
        transmit.destination = destination_buffer;
        transmit.destination_capacity = sizeof destination_buffer;
        transmit.source = source_buffer;
        transmit.source_capacity = sizeof source_buffer;
        if (sipral_stack_poll_transmit(stack, &transmit) != SIPRAL_STATUS_OK ||
            transmit.len == 0) {
            break;
        }
        message_buffer[transmit.len] = '\0';
        if (strncmp((const char *)message_buffer, "INVITE ", strlen("INVITE ")) != 0 ||
            transmit.len >= sizeof invite) {
            continue;
        }
        memcpy(invite, message_buffer, transmit.len + 1);
    }
    expect("no INVITE came out of the DTLS-SRTP call", invite[0] != '\0');

    /* RFC 5764 section 4.1 names the transport; RFC 8122 the fingerprint;
     * RFC 5763 section 5 makes an offerer write actpass */
    expect("the offer did not name the DTLS transport",
           strstr(invite, "UDP/TLS/RTP/SAVP") != NULL);
    expect("the offer carries no fingerprint",
           strstr(invite, "a=fingerprint:sha-256 ") != NULL);
    expect("the offer did not leave the role to the answer",
           strstr(invite, "a=setup:actpass") != NULL);
    /* RFC 5764 section 4.2 would put a second handshake on a separate RTCP
     * port, and this stack runs one */
    expect("the offer did not ask to multiplex its control traffic",
           strstr(invite, "a=rtcp-mux") != NULL);
    /* and the key is not in the body, which is the whole point of it */
    expect("a description keyed by a handshake also put a key in the body",
           strstr(invite, "a=crypto:") == NULL);

    sipral_stack_destroy(stack);
}

/* The entry point without which none of the above ever leaves: a call that
 * has no media yet still has to answer, and answer "nothing due" rather than
 * fail, or an application cannot write one loop for every call it has. */
static void nothing_is_due_on_a_call_with_no_media(void)
{
    uint8_t entropy[32];
    uint8_t media_seed[32];
    if (!draw(entropy, sizeof entropy) || !draw(media_seed, sizeof media_seed)) {
        expect("could not read entropy for the poll_transmit check", 0);
        return;
    }
    sipral_stack_config_t config = fixture_stack_config(sizeof config, entropy, media_seed);
    sipral_handle_t stack = SIPRAL_HANDLE_NONE;
    expect("the stack poll_transmit is checked on would not start",
           sipral_stack_create(&config, &stack) == SIPRAL_STATUS_OK);
    if (stack == SIPRAL_HANDLE_NONE) {
        return;
    }
    sipral_media_packet_t packet = { 0 };
    packet.size = sizeof packet;
    packet.data = message_buffer;
    packet.capacity = sizeof message_buffer;
    packet.destination = destination_buffer;
    packet.destination_capacity = sizeof destination_buffer;
    /* a handle of no media at all: the answer is a refusal with a name, not a
     * crash and not silence */
    expect("polling a media handle that is not one answered something else",
           sipral_media_poll_transmit(SIPRAL_HANDLE_NONE, 0, &packet) ==
               SIPRAL_STATUS_INVALID_HANDLE);
    sipral_stack_destroy(stack);
}

static void a_registration_freezes_and_thaws(void)
{
    struct fixture fixture;
    if (!fixture_up(&fixture)) {
        return;
    }

    size_t needed = 0;
    expect("freezing into no room did not say how much is needed",
           sipral_account_freeze(fixture.stack, fixture.account, NULL, 0, &needed, 0) ==
               SIPRAL_STATUS_BUFFER_TOO_SMALL);
    expect("a standing binding froze to nothing", needed > 0);
    if (needed == 0 || needed > 4096) {
        sipral_stack_destroy(fixture.stack);
        return;
    }
    uint8_t snapshot[4096];
    size_t written = 0;
    expect("the registration would not be written down",
           sipral_account_freeze(fixture.stack, fixture.account, snapshot, sizeof snapshot,
                                 &written, 0) == SIPRAL_STATUS_OK);
    expect("the second answer disagreed with the first", written == needed);
    sipral_stack_destroy(fixture.stack);

    /* a process that was not there when it was written */
    uint8_t entropy[32];
    uint8_t media_seed[32];
    if (!draw(entropy, sizeof entropy) || !draw(media_seed, sizeof media_seed)) {
        expect("could not read entropy for the stack a snapshot is thawed on", 0);
        return;
    }
    sipral_stack_config_t config = fixture_stack_config(sizeof config, entropy, media_seed);
    sipral_handle_t woken = SIPRAL_HANDLE_NONE;
    expect("the stack a snapshot is thawed on would not start",
           sipral_stack_create(&config, &woken) == SIPRAL_STATUS_OK);
    if (woken == SIPRAL_HANDLE_NONE) {
        return;
    }
    sipral_account_config_t account_config = fixture_account_config(sizeof account_config);
    sipral_handle_t account = SIPRAL_HANDLE_NONE;
    expect("the account a snapshot is thawed into was refused",
           sipral_account_add(woken, &account_config, &account) == SIPRAL_STATUS_OK);

    expect("the snapshot was refused by the account it was written for",
           sipral_account_thaw(woken, account, snapshot, written, 60000, 0) ==
               SIPRAL_STATUS_OK);
    uint32_t state = 0;
    expect("the thawed account would not say what state it is in",
           sipral_account_registration_state(woken, account, &state) == SIPRAL_STATUS_OK);
    expect("a binding nobody has confirmed came back as evidence",
           state == SIPRAL_REGISTRATION_STATE_RESTORED);

    /* and the one mix-up that would otherwise send a REGISTER for somebody
     * else: bytes that are not a snapshot at all */
    expect("bytes that are not a snapshot were read as one",
           sipral_account_thaw(woken, account, (const uint8_t *)"not a snapshot",
                               strlen("not a snapshot"), 0, 0) ==
               SIPRAL_STATUS_INVALID_ARGUMENT);

    /* time to ready has no answer without a cold start to measure from, which
     * is why the two entry points ship together */
    uint32_t has_value = 1;
    uint64_t took = 1;
    expect("time to ready would not answer",
           sipral_account_time_to_ready(woken, account, &has_value, &took) ==
               SIPRAL_STATUS_OK);
    expect("a launch nobody declared was measured anyway", has_value == 0 && took == 0);
    expect("the cold start was refused", sipral_stack_cold_start(woken, 0) == SIPRAL_STATUS_OK);

    sipral_stack_destroy(woken);
}

/* -- one call's own codec order ----------------------------------------------
 *
 * D6: the order is a property of the call, not of the process. Two calls off
 * one stack, offering different formats, with no second stack anywhere.
 */
static int invite_out_of(sipral_handle_t stack, char *into, size_t capacity)
{
    for (int drained = 0; drained < 8; drained++) {
        sipral_transmit_t transmit = { 0 };
        transmit.size = sizeof transmit;
        transmit.data = message_buffer;
        transmit.capacity = sizeof message_buffer - 1;
        transmit.destination = destination_buffer;
        transmit.destination_capacity = sizeof destination_buffer;
        transmit.source = source_buffer;
        transmit.source_capacity = sizeof source_buffer;
        if (sipral_stack_poll_transmit(stack, &transmit) != SIPRAL_STATUS_OK ||
            transmit.len == 0) {
            return 0;
        }
        message_buffer[transmit.len] = '\0';
        if (strncmp((const char *)message_buffer, "INVITE ", strlen("INVITE ")) != 0) {
            continue;
        }
        if (transmit.len >= capacity) {
            return 0;
        }
        memcpy(into, message_buffer, transmit.len + 1);
        return 1;
    }
    return 0;
}

static void a_call_names_its_own_codecs(void)
{
    static const char stack_order[] = "PCMU";
    static const char call_order[] = "G722";
    static const char absent[] = "SILK";
    static const char target[] = "sip:bob@example.com";
    static const char media[] = "192.0.2.10:40000";
    uint8_t entropy[32];
    uint8_t media_seed[32];
    if (!draw(entropy, sizeof entropy) || !draw(media_seed, sizeof media_seed)) {
        expect("could not read entropy for the stack a call's own order is tried on", 0);
        return;
    }

    sipral_stack_config_t config =
        fixture_stack_config(sizeof config, entropy, media_seed);
    config.codecs = stack_order;
    config.codecs_len = strlen(stack_order);
    sipral_handle_t stack = SIPRAL_HANDLE_NONE;
    expect("the stack a call's own order is tried on would not start",
           sipral_stack_create(&config, &stack) == SIPRAL_STATUS_OK);
    if (stack == SIPRAL_HANDLE_NONE) {
        return;
    }
    sipral_account_config_t account_config = fixture_account_config(sizeof account_config);
    sipral_handle_t account = SIPRAL_HANDLE_NONE;
    expect("the account a call's own order is tried on was refused",
           sipral_account_add(stack, &account_config, &account) == SIPRAL_STATUS_OK);

    sipral_call_config_t call_config = { 0 };
    call_config.size = sizeof call_config;
    call_config.target = target;
    call_config.target_len = strlen(target);
    call_config.media_address = media;
    call_config.media_address_len = strlen(media);
    call_config.codecs = call_order;
    call_config.codecs_len = strlen(call_order);
    sipral_handle_t call = SIPRAL_HANDLE_NONE;
    expect("a call naming its own order would not go out",
           sipral_call_place(stack, account, &call_config, &call, 0) == SIPRAL_STATUS_OK);

    char invite[SIPRAL_MESSAGE_BYTES];
    expect("the INVITE a call's own order wrote never came out",
           invite_out_of(stack, invite, sizeof invite));
    expect("the call's own order did not reach its offer", strstr(invite, "G722") != NULL);
    expect("the stack's order is in the offer of a call that overrode it",
           strstr(invite, "PCMU") == NULL);

    /* and the stack's own order is where it was: a per-call order that
     * mutated the catalogue everything else shares would show up here */
    sipral_call_config_t plain = call_config;
    plain.codecs = NULL;
    plain.codecs_len = 0;
    sipral_handle_t second = SIPRAL_HANDLE_NONE;
    expect("a second call on the same stack would not go out",
           sipral_call_place(stack, account, &plain, &second, 0) == SIPRAL_STATUS_OK);
    expect("the INVITE of the second call never came out",
           invite_out_of(stack, invite, sizeof invite));
    expect("the earlier call's order outlived the call",
           strstr(invite, "PCMU") != NULL && strstr(invite, "G722") == NULL);

    /* a name this build has no encoder for is refused where the caller still
     * knows which string it passed, and nothing is placed */
    sipral_call_config_t unknown = call_config;
    unknown.codecs = absent;
    unknown.codecs_len = strlen(absent);
    sipral_handle_t nowhere = SIPRAL_HANDLE_NONE;
    expect("a codec this build has no encoder for was accepted on a call",
           sipral_call_place(stack, account, &unknown, &nowhere, 0) ==
               SIPRAL_STATUS_NOT_SUPPORTED);
    expect("the call that was refused handed back a handle anyway",
           nowhere == SIPRAL_HANDLE_NONE);

    sipral_stack_destroy(stack);
}

/* -- why each codec lost -----------------------------------------------------
 *
 * D5 through the ABI: a call that settled on one format, and the list saying
 * what became of every other format this end could have offered. The
 * integrator's question is "we configured Opus and the call is on G.711" and
 * this is where it is answered, without a packet capture.
 */
static void every_codec_says_what_became_of_it(void)
{
    struct fixture fixture;
    if (!fixture_up(&fixture)) {
        return;
    }
    sipral_handle_t media = media_handle_of(&fixture);
    expect("the fixture call has no media to explain", media != SIPRAL_HANDLE_NONE);
    if (media == SIPRAL_HANDLE_NONE) {
        sipral_stack_destroy(fixture.stack);
        return;
    }

    size_t candidates = 0;
    expect("the call would not say how many codecs were in the running",
           sipral_media_codec_candidate_count(media, &candidates) == SIPRAL_STATUS_OK);
    expect("a call that negotiated a codec had none in the running", candidates > 0);

    sipral_media_info_t info = { 0 };
    info.size = sizeof info;
    expect("the call would not say what it settled on",
           sipral_media_info(media, &info) == SIPRAL_STATUS_OK);

    unsigned chosen = 0;
    for (size_t which = 0; which < candidates; which++) {
        sipral_codec_candidate_t candidate = { 0 };
        candidate.size = sizeof candidate;
        expect("a candidate inside the count was refused",
               sipral_media_codec_candidate_at(media, which, &candidate) == SIPRAL_STATUS_OK);
        if (candidate.outcome == SIPRAL_CODEC_OUTCOME_CHOSEN) {
            chosen++;
            expect("the codec the call chose is not the codec it is using",
                   candidate.codec == info.codec);
            expect("something is said to have beaten the codec that won",
                   candidate.outranked_by == SIPRAL_CODEC_UNKNOWN);
        } else {
            expect("a codec that did not win is not said to have lost either way",
                   candidate.outcome == SIPRAL_CODEC_OUTCOME_NOT_NAMED ||
                       candidate.outcome == SIPRAL_CODEC_OUTCOME_OUTRANKED);
        }
        /* the far end named one format, so nothing here can have been
         * outranked -- and a candidate that was would have to name what beat
         * it */
        if (candidate.outcome == SIPRAL_CODEC_OUTCOME_OUTRANKED) {
            expect("a codec was outranked by nothing",
                   candidate.outranked_by != SIPRAL_CODEC_UNKNOWN);
        }
    }
    expect("the list does not name exactly one codec as the one that won", chosen == 1);

    sipral_codec_candidate_t past = { 0 };
    past.size = sizeof past;
    expect("a candidate index past the end was answered",
           sipral_media_codec_candidate_at(media, candidates, &past) ==
               SIPRAL_STATUS_INVALID_ARGUMENT);

    sipral_media_release(media);
    sipral_stack_destroy(fixture.stack);
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

    /* And the list itself. The names typed here answer for the structs they
     * name and say nothing about one more, so the library is asked how many
     * it has. A struct added to the ABI and not to VERSIONED fails here. */
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

    struct seen seen = { MARKER, 0, SIPRAL_STATUS_PANIC, SIPRAL_STATUS_PANIC };
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
    sipral_handle_t audio = SIPRAL_HANDLE_NONE;
    int16_t frame[160] = { 0 };
    char message[512] = { 0 };

    /* first, because nothing below means anything if the library was built
     * from another header */
    if (sipral_abi_check(SIPRAL_ABI_VERSION_MAJOR, SIPRAL_ABI_VERSION_MINOR)
        != SIPRAL_STATUS_OK) {
        printf("  smoke.c: this library does not speak the header's ABI\n");
        return 1;
    }
    sizes_agree();
    oldest_lengths_still_work();
    headers_cross_a_call();
    a_call_names_its_own_codecs();
    every_codec_says_what_became_of_it();
    a_call_keyed_by_a_handshake_says_so_in_its_offer();
    nothing_is_due_on_a_call_with_no_media();
    a_registration_freezes_and_thaws();
    a_next_hop_is_asked_about_and_answered();

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

    /* A call's audio is reached through a handle of its own, minted once the
     * negotiation has settled, and it never waits on the stack. Nothing has
     * answered this call, so there is no media yet, and the answer says so
     * rather than handing out a handle to nothing. */
    expect("a media handle was handed out for a call that has no media yet",
           sipral_call_media(stack, call, &audio) == SIPRAL_STATUS_WRONG_STATE);
    expect("the media handle that was refused was written anyway",
           audio == SIPRAL_HANDLE_NONE);
    expect("a media handle nobody minted played a frame",
           sipral_media_playback(audio, frame, sizeof frame / sizeof frame[0],
                                 NULL, NULL)
               == SIPRAL_STATUS_INVALID_HANDLE);
    expect("a media handle nobody minted was released",
           sipral_media_release(audio) == SIPRAL_STATUS_INVALID_HANDLE);

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
    expect("a question put to the stack from inside its callback was refused",
           seen.reentered == SIPRAL_STATUS_OK);
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
