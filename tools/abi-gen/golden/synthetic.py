# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# Printed from the declarations in crates/sipral-ffi by tools/abi-gen. Do
# not edit: `cargo run -p sipral-abi-gen` writes it again, and
# `scripts/check.sh` fails when what is committed is not what came out.
#
# The raw cffi surface over the C ABI, built in cffi's ABI mode so that
# installing this package needs no C compiler: one `cdef` naming the same
# types, constants and entry points `bindings/c/include/sipral.h` does,
# and the `dlopen` that turns it into `lib`. Every name below is spelled
# exactly as the header spells it, so `docs/08-ffi.md` reads for this
# module too.
#
# Nothing here is idiomatic. `sipral.stack`, `sipral.account` and
# `sipral.call` are written against `lib` and `ffi` by hand, the way
# `SipralAbi.swift` is the base the Swift package is written against; an
# application reaches for those rather than this module.
"""The raw cffi surface: `ffi` and `lib`, generated from crates/sipral-ffi.

See sipral.stack, sipral.account and sipral.call for the layer applications
are meant to use.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from cffi import FFI

CDEF = r"""
/**
 * What names one thing the library holds.
 */
typedef uint64_t sipral_handle_t;

/**
 * The handle that names nothing.
 */
#define SIPRAL_HANDLE_NONE 0

/**
 * The bit a hardware customer is told to check for.
 */
#define SIPRAL_FEATURE_OPUS 64

/**
 * The longest message that crosses.
 */
#define SIPRAL_MESSAGE_BYTES 65535

/**
 * Nothing built against another major works against this one.
 */
#define SIPRAL_ABI_VERSION_MAJOR 0

/**
 * Raised by anything the header gains.
 */
#define SIPRAL_ABI_VERSION_MINOR 8

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

"""

ffi = FFI()
ffi.cdef(CDEF)


def _library_name() -> str:
    """What the crate's `cdylib` is called on this platform."""
    if sys.platform == "darwin":
        return "libsipral_ffi.dylib"
    if sys.platform == "win32":
        return "sipral_ffi.dll"
    return "libsipral_ffi.so"


def _candidates() -> list[Path]:
    """Where the library might be, in the order it is looked for.

    `SIPRAL_LIBRARY` first, whether it names the library file itself
    or the directory holding it; then beside this package, for a
    wheel that bundled the library next to the Python; then the
    repository's own `target/release` and `target/debug`, for
    working against a checkout with no install step at all.
    """
    name = _library_name()
    found: list[Path] = []
    override = os.environ.get("SIPRAL_LIBRARY")
    if override:
        given = Path(override)
        found.append(given if given.is_file() else given / name)
    package_dir = Path(__file__).resolve().parent
    found.append(package_dir / name)
    repository = package_dir.parents[2] if len(package_dir.parents) > 2 else None
    if repository is not None:
        found.append(repository / "target" / "release" / name)
        found.append(repository / "target" / "debug" / name)
    return found


def _load():
    tried = _candidates()
    for candidate in tried:
        if candidate.is_file():
            return ffi.dlopen(str(candidate))
    searched = "\n".join(f"  {candidate}" for candidate in tried)
    raise OSError(
        "sipral: could not find "
        + _library_name()
        + ". Tried:\n"
        + searched
        + "\n\nBuild it with `cargo build --release -p sipral-ffi`, "
        "or set SIPRAL_LIBRARY to its path or its directory."
    )


lib = _load()

# Checked once, at import, the way every other binding checks itself at
# load: sipral_abi_check is called with the major and minor this file was
# printed from, so a library that cannot serve them is refused here, in
# a sentence naming both, rather than in whichever call first reads a
# member that is not there.
_abi_status = lib.sipral_abi_check(lib.SIPRAL_ABI_VERSION_MAJOR, lib.SIPRAL_ABI_VERSION_MINOR)
if _abi_status != lib.SIPRAL_STATUS_OK:
    raise OSError(
        f"sipral: this build of the library does not implement ABI "
        f"{lib.SIPRAL_ABI_VERSION_MAJOR}.{lib.SIPRAL_ABI_VERSION_MINOR}, which this binding was "
        "generated against; regenerate the binding or rebuild the library"
    )

