/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
 * Copyright (c) 2026 Tiberiu Balasea
 *
 * Printed from the declarations in crates/sipral-ffi by tools/abi-gen.
 * Do not edit: `cargo run -p sipral-abi-gen` writes it again, and
 * `scripts/check.sh` fails when what is committed is not what came out.
 *
 * CONVENTIONS. Every declaration below follows these; a comment that
 * says otherwise is the exception, and says so.
 *
 * Status. Every function returns a sipral_status_t, except the three
 * that return a static name (sipral_status_name, sipral_codec_name,
 * sipral_event_kind_name: NUL-terminated, the library's, valid while it
 * is loaded). sipral_status_t is the one signed type: zero is success,
 * every failure is positive, none is negative, and a newer library may
 * return one an older header has no name for, which is a failure like
 * any other. A failure sets the calling thread's last error
 * (sipral_last_error_message); a success clears it. A panic never
 * crosses: it is SIPRAL_STATUS_PANIC.
 *
 * Enumerations. Each is a typedef of a fixed-width integer and the
 * names as constants, so no compiler picks a width. Values are only
 * ever added, never renumbered. In the enumerations that start at 1
 * zero names nothing: read it as absent.
 *
 * Structs that carry `size`. Zero the whole struct, padding included,
 * then set `size` to its sizeof, on a struct handed in and on one the
 * library fills alike. A library that knows fewer members reads what
 * it knows and refuses a nonzero byte past it with
 * SIPRAL_STATUS_NOT_SUPPORTED; one that fills fewer writes back the
 * `size` it filled and zeroes the rest. A struct only ever grows by appending members
 * at its end, and no struct here ends in padding on any target, so an
 * appended member never lands inside a length a caller declares. The
 * least a caller may declare is where the oldest version of each
 * struct ended (bindings/c/abi-sizes.txt). sipral_header_t is the one
 * struct without a size: it is the element of an array, and never
 * grows. The event payload union is zeroed whole before the one arm
 * its kind names is written.
 *
 * Text and bytes in. A pointer and a length in bytes, the pointer
 * read for that length during the call and never kept. Text is UTF-8
 * with no NUL expected or read, and at most 65536 bytes. For an
 * optional piece a length of zero is absent, whatever the pointer.
 *
 * Text out. `buffer`, `capacity`, `out_needed`: the text is written
 * with a trailing NUL, and `out_needed`, which may be null, receives
 * the bytes it needs with that NUL counted. Too small a buffer is
 * SIPRAL_STATUS_BUFFER_TOO_SMALL and nothing is written; a null
 * buffer with a capacity of zero asks for the length alone.
 * Bytes out (sipral_account_freeze, sipral_stack_codec_order,
 * sipral_media_playback) are counted without a NUL and say so. A
 * packet struct (sipral_media_packet_t, sipral_transmit_t) brings
 * buffers at least as large as the constant each member's comment
 * names, is refused whole with SIPRAL_STATUS_BUFFER_TOO_SMALL when one
 * is smaller, and comes back with a `len` of zero when nothing was
 * waiting.
 *
 * Handles. 64-bit, zero never valid. A handle that never came from
 * this library, or from another stack, is
 * SIPRAL_STATUS_INVALID_HANDLE; one whose object is gone is
 * SIPRAL_STATUS_STALE_HANDLE. The library hands out no memory for a
 * caller to free.
 *
 * Threads. A stack may be used from any thread, one at a time: a
 * second thread gets SIPRAL_STATUS_BUSY rather than a wait. A call's
 * media is reached through a handle of its own (sipral_call_media) and
 * never waits on the stack; it waits only for a frame another thread
 * is in the middle of on that same call. The sipral_audio_* calls wait
 * for the audio engine, which a platform probe holds for up to
 * sipral_stack_config_t::audio_probe_ms; nothing else waits on them.
 *
 * Callbacks. None may unwind into the library. Each gets back its
 * `user_data` untouched and reads nothing else the caller owns.
 *   event (sipral_stack_config_t::event_callback): on the thread in
 *     sipral_stack_poll, with nothing held; may call anything, this
 *     stack included. user_data lives as long as the stack.
 *   screen (sipral_stack_screen): on the thread feeding the stack
 *     bytes, with the stack's lock held; a call into this stack is
 *     SIPRAL_STATUS_BUSY. user_data lives until the policy is replaced
 *     or removed and no thread is inside the stack.
 *   processor (sipral_media_attach_processor): on the thread in
 *     sipral_media_capture or sipral_media_playback, with that call's
 *     media held; a call on any media handle, or into that call's
 *     stack, is SIPRAL_STATUS_BUSY. user_data lives until
 *     sipral_media_detach_processor returns or the handle is released.
 *   audio transmit (sipral_stack_config_t::audio_transmit_callback):
 *     on the audio engine's own thread, with nothing of the library's
 *     held; sipral_stack_destroy from it is SIPRAL_STATUS_BUSY.
 *     user_data lives as long as the stack.
 *   log (sipral_stack_log): on the thread that just finished a call
 *     into the stack, with nothing held, one line at a time; may call
 *     anything. user_data lives until the log is replaced or turned off
 *     and no thread is inside the stack.
 * Every pointer a callback is handed points into the library's memory
 * and is valid for that one call.
 */

#ifndef SIPRAL_H
#define SIPRAL_H

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
 * How long a refused request waits before it is tried again.
 */
#define SIPRAL_RETRY_EVERY_MS ((uint64_t)2000)

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
typedef struct sipral_header sipral_header_t;
typedef struct sipral_stack_config sipral_stack_config_t;
typedef struct sipral_media_packet sipral_media_packet_t;
typedef struct sipral_registration_event sipral_registration_event_t;
typedef struct sipral_media_event sipral_media_event_t;
typedef union sipral_event_payload sipral_event_payload_t;
typedef struct sipral_event sipral_event_t;
typedef struct sipral_screen_event sipral_screen_event_t;
typedef struct sipral_processor_event sipral_processor_event_t;

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
 * Asked before the library goes on, and answered with whether to
 * continue. A listener that throws instead of answering is read as
 * zero, which every callback here that answers is defined to take
 * as "no".
 */
typedef uint32_t (*sipral_screen_callback_t)(const sipral_screen_event_t *event, void *user_data);

/**
 * Run over one frame, and hand back what replaces it.
 */
typedef void (*sipral_process_callback_t)(const sipral_processor_event_t *event, void *user_data);

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
 * One header field: a name and a value.
 */
struct sipral_header {
    const char *name;
    size_t name_len;
    const char *value;
    size_t value_len;
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
    /**
     * Header fields to send, `headers_len` of them.
     */
    const sipral_header_t *headers;
    size_t headers_len;
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
 * What a policy callback is asked before the library goes on.
 */
struct sipral_screen_event {
    size_t size;
    /**
     * Who is calling, as UTF-8, or null.
     */
    const char *from;
    size_t from_len;
};

/**
 * What a processing callback is handed: a frame to read and one to fill.
 */
struct sipral_processor_event {
    size_t size;
    /**
     * The frame just captured, to read.
     */
    const int16_t *near;
    size_t near_len;
    /**
     * Where the processed frame is written.
     */
    int16_t *far;
    size_t far_len;
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
 * Hand it header fields, an array of them with its length beside it.
 */
sipral_status_t sipral_stack_label(sipral_handle_t stack, const sipral_header_t *headers, size_t headers_len);

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
 * Fill a buffer of opaque bytes the caller brings.
 */
sipral_status_t sipral_stack_freeze(sipral_handle_t stack, uint8_t *buffer, size_t capacity, size_t *out_len);

/**
 * Fill a buffer of samples the caller brings.
 */
sipral_status_t sipral_call_playback(sipral_handle_t stack, int16_t *samples, size_t capacity, size_t *out_written);

/**
 * Hand it samples, and get one datagram back in the struct.
 */
sipral_status_t sipral_call_capture(sipral_handle_t stack, const int16_t *samples, size_t sample_count, sipral_media_packet_t *packet);

/**
 * Hand it one buffer of samples and fill another, in the same call,
 * neither one named `capacity` — two buffers going in, one of them
 * writable, which is not the same shape as one being filled.
 */
sipral_status_t sipral_call_mix(sipral_handle_t stack, const int16_t *mic, size_t mic_count, int16_t *local, size_t local_count);

/**
 * Hand it a datagram that arrived, in a buffer it may rewrite in
 * place, and hear what became of it.
 */
sipral_status_t sipral_call_media_receive(sipral_handle_t stack, uint8_t *data, size_t len, uint32_t *out_arrival);

/**
 * Install a policy on it, replace the one installed, or remove it.
 *
 * The callback and the pointer after it are one listener, the same
 * pair a struct going in already means by them, and a null callback
 * removes whatever was installed.
 */
sipral_status_t sipral_stack_screen(sipral_handle_t stack, sipral_screen_callback_t callback, void *user_data);

/**
 * Install a processor on it, replace the one installed, or remove it.
 *
 * The callback and the pointer after it are one listener, the same
 * pair a struct going in already means by them, and a null callback
 * removes whatever was installed.
 */
sipral_status_t sipral_stack_process(sipral_handle_t stack, sipral_process_callback_t callback, void *user_data);

/**
 * Take it apart.
 */
sipral_status_t sipral_stack_destroy(sipral_handle_t stack);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SIPRAL_H */
