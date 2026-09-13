/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
 * Copyright (c) 2026 Tiberiu Balasea
 *
 * Printed from the declarations in crates/sipral-ffi by tools/abi-gen.
 * Do not edit: `cargo run -p sipral-abi-gen` writes it again, and
 * `scripts/check.sh` fails when what is committed is not what came out.
 *
 * Every function here returns a sipral_status_t except where its own
 * comment says otherwise, sets the calling thread's last error on
 * failure, and catches any panic rather than letting one reach C. A
 * stack may be used from any thread but only one at a time, and may not
 * be re-entered from inside its own event callback; both are
 * SIPRAL_STATUS_BUSY rather than a deadlock. sipral_stack_destroy is the
 * one exception, and works from inside the callback.
 */

#ifndef SIPRAL_H
#define SIPRAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * What names one thing the library holds.
 */
typedef uint64_t sipral_handle_t;

/**
 * The handle that names nothing.
 */
#define SIPRAL_HANDLE_NONE ((sipral_handle_t)0)

/**
 * The bit a hardware customer is told to check for.
 */
#define SIPRAL_FEATURE_OPUS ((uint32_t)64)

/**
 * The longest message that crosses.
 */
#define SIPRAL_MESSAGE_BYTES ((size_t)65535)

/**
 * Nothing built against another major works against this one.
 */
#define SIPRAL_ABI_VERSION_MAJOR ((uint32_t)0)

/**
 * Raised by anything the header gains.
 */
#define SIPRAL_ABI_VERSION_MINOR ((uint32_t)8)

/* Every record, named before any of them is defined, so that a
 * declaration never has to come before the one it mentions. */
typedef struct sipral_counters sipral_counters_t;
typedef struct sipral_stack_config sipral_stack_config_t;
typedef struct sipral_media_packet sipral_media_packet_t;
typedef struct sipral_registration_event sipral_registration_event_t;
typedef struct sipral_media_event sipral_media_event_t;
typedef union sipral_event_payload sipral_event_payload_t;
typedef struct sipral_event sipral_event_t;

/**
 * What a call across the boundary answered.
 *
 * Numbers already spent on features this build does not have:
 * - 9: video
 */
typedef int32_t sipral_status_t;
enum {
    /**
     * It worked.
     */
    SIPRAL_STATUS_OK = 0,
    /**
     * Something handed in was not usable.
     */
    SIPRAL_STATUS_INVALID_ARGUMENT = 1,
    /**
     * A panic was caught before it reached C.
     */
    SIPRAL_STATUS_PANIC = 2,
    /**
     * A word three of the four languages will not take plain.
     */
    SIPRAL_STATUS_DEFAULT = 3,
};

/**
 * On or off, where C has no bool worth relying on.
 */
typedef uint32_t sipral_toggle_t;
enum {
    SIPRAL_TOGGLE_OFF = 0,
    SIPRAL_TOGGLE_ON = 1,
};

/**
 * What the library calls when something happens.
 */
typedef void (*sipral_event_callback_t)(const sipral_event_t *event, void *user_data);

/**
 * What a stack has done since it was made.
 */
struct sipral_counters {
    size_t size;
    /**
     * How many went out.
     */
    uint64_t requests_sent;
    /**
     * The fraction lost, which crosses JNI as its own bits.
     */
    float loss;
};

/**
 * What a stack is made with.
 *
 * Holds buffers of the caller's and the library only reads it, so it
 * crosses behind a `const` pointer as a struct going in.
 */
struct sipral_stack_config {
    size_t size;
    /**
     * Called for every event, from inside the poll.
     */
    sipral_event_callback_t event_callback;
    /**
     * Handed back to the callback untouched.
     */
    void *event_user_data;
    /**
     * Where to listen, as UTF-8.
     */
    const char *bind_address;
    size_t bind_address_len;
    sipral_toggle_t echo;
};

/**
 * One datagram, in room the caller brought.
 *
 * Holds writable buffers of the caller's, so it crosses behind a
 * mutable pointer as a struct going both ways.
 */
struct sipral_media_packet {
    size_t size;
    /**
     * Where to write the datagram.
     */
    uint8_t *data;
    size_t capacity;
    size_t len;
    /**
     * Where to write the address it goes to, as UTF-8.
     */
    char *destination;
    size_t destination_capacity;
    size_t destination_len;
};

/**
 * What a registration event says.
 */
struct sipral_registration_event {
    /**
     * Where it got to.
     */
    uint32_t state;
    uint32_t status_code;
};

/**
 * What a media event says.
 *
 * Lifetime
 *
 * Everything a pointer here names is the library's and lives until
 * the callback returns.
 */
struct sipral_media_event {
    uint32_t codec;
    /**
     * Why, as UTF-8, or null.
     */
    const char *reason;
    size_t reason_len;
    /**
     * What the stream has done, or null when there is none.
     */
    const sipral_counters_t *statistics;
};

/**
 * The one arm sipral_event_t::kind names, and no other.
 */
union sipral_event_payload {
    /**
     * Read when the kind is a registration one.
     */
    sipral_registration_event_t registration;
    /**
     * Read when the kind is a media one.
     */
    sipral_media_event_t media;
};

/**
 * One thing that happened, as the callback is handed it.
 */
struct sipral_event {
    size_t size;
    /**
     * Which stack it came from.
     */
    sipral_handle_t stack;
    /**
     * Which of them, from sipral_status_t.
     */
    uint32_t kind;
    /**
     * The message behind it, or null. It is the library's, and
     * it lives as long as SIPRAL_STATUS_OK is being reported
     * -- see sipral_stack_create for who owns what.
     */
    const uint8_t *message;
    size_t message_len;
    /**
     * The arm the kind names.
     */
    sipral_event_payload_t payload;
};

/**
 * Whether this library can serve a binding generated against `major`.`minor`.
 */
sipral_status_t sipral_abi_check(uint32_t major, uint32_t minor);

/**
 * The calling thread's last error.
 */
sipral_status_t sipral_last_error_message(char *buffer, size_t capacity, size_t *out_needed);

/**
 * The name of one sipral_status_t, for a log line.
 */
const char *sipral_status_name(int32_t code);

/**
 * Make one.
 */
sipral_status_t sipral_stack_create(const sipral_stack_config_t *config, sipral_handle_t *out_stack);

/**
 * Read sipral_counters_t off it.
 */
sipral_status_t sipral_stack_counters(sipral_handle_t stack, sipral_counters_t *out_counters);

/**
 * Hand it bytes to send.
 */
sipral_status_t sipral_stack_send(sipral_handle_t stack, const uint8_t *message, size_t message_len);

/**
 * Hand it text, which crosses as UTF-8 and not as a String.
 */
sipral_status_t sipral_stack_describe(sipral_handle_t stack, const char *note, size_t note_len);

/**
 * Fill a buffer the caller brings.
 */
sipral_status_t sipral_stack_name(sipral_handle_t stack, char *name, size_t capacity, size_t *out_len);

/**
 * Fill a buffer of numbers the caller brings.
 */
sipral_status_t sipral_stack_codec_order(sipral_handle_t stack, uint32_t *out_codecs, size_t capacity, size_t *out_count);

/**
 * Fill a buffer of samples the caller brings.
 */
sipral_status_t sipral_call_playback(sipral_handle_t stack, int16_t *samples, size_t capacity, size_t *out_written);

/**
 * Hand it samples, and get one datagram back in the struct.
 */
sipral_status_t sipral_call_capture(sipral_handle_t stack, const int16_t *samples, size_t sample_count, sipral_media_packet_t *packet);

/**
 * Hand it a datagram that arrived, in a buffer it may rewrite in
 * place, and hear what became of it.
 */
sipral_status_t sipral_call_media_receive(sipral_handle_t stack, uint8_t *data, size_t len, uint32_t *out_arrival);

/**
 * Take it apart.
 */
sipral_status_t sipral_stack_destroy(sipral_handle_t stack);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SIPRAL_H */
