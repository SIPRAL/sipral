// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Printed from the declarations in crates/sipral-ffi by tools/abi-gen. Do
// not edit: `cargo run -p sipral-abi-gen` writes it again, and
// `scripts/check.sh` fails when what is committed is not what came out.
//
// The raw koffi surface over the C ABI: every alias, enumeration width,
// struct, union and callback declared to koffi under the name
// `bindings/c/include/sipral.h` gives it, so `docs/08-ffi.md` reads for
// this module too, and every entry point a member of `Sipral`, loaded
// from the library `Sipral.open` found and checked. A pointer member of
// a record is an address here, read for the length beside it.
//
// Nothing here is idiomatic. The stack, the account, the call and the
// media in `bindings/node/src/` are written against this file by hand,
// and are what an application reaches for.

import { existsSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import koffi from 'koffi';

/** An address as koffi hands one back, or anything it takes for one. */
export type Pointer = bigint | number | Buffer | ArrayBufferView | null;

/** A 64-bit integer: a `number` while it is exact, a `bigint` past that. */
export type Wide = number | bigint;

/**
 * What names one thing the library holds.
 */
koffi.alias('sipral_handle_t', 'uint64_t');

/**
 * The handle that names nothing.
 */
export const SIPRAL_HANDLE_NONE = 0;

/**
 * The bit a hardware customer is told to check for.
 */
export const SIPRAL_FEATURE_OPUS = 64;

/**
 * The longest message that crosses.
 */
export const SIPRAL_MESSAGE_BYTES = 65535;

/**
 * How long a refused request waits before it is tried again.
 */
export const SIPRAL_RETRY_EVERY_MS = 2000;

/**
 * Nothing built against another major works against this one.
 */
export const SIPRAL_ABI_VERSION_MAJOR = 0;

/**
 * Raised by anything the header gains.
 */
export const SIPRAL_ABI_VERSION_MINOR = 8;

/**
 * What a call across the boundary answered.
 *
 * Numbers already spent on features this build does not have:
 * - 9: video
 */
export const SipralStatus = Object.freeze({
  /**
   * It worked.
   */
  Ok: 0,
  /**
   * Something handed in was not usable.
   */
  InvalidArgument: 1,
  /**
   * A panic was caught before it reached C.
   */
  Panic: 2,
  /**
   * A word three of the four languages will not take plain.
   */
  Default: 3,
} as const);
koffi.alias('sipral_status_t', 'int32_t');

/**
 * On or off, where C has no bool worth relying on.
 */
export const SipralToggle = Object.freeze({
  Off: 0,
  On: 1,
} as const);
koffi.alias('sipral_toggle_t', 'uint32_t');

/**
 * What a stack has done since it was made.
 */
export interface SipralCounters {
  size: number;
  /**
   * How many went out.
   */
  requests_sent: Wide;
  /**
   * The fraction lost, which crosses JNI as its own bits.
   */
  loss: number;
}
koffi.struct('sipral_counters_t', {
  size: 'size_t',
  requests_sent: 'uint64_t',
  loss: 'float',
});

/**
 * One header field: a name and a value.
 */
export interface SipralHeader {
  name: Pointer;
  name_len: number;
  value: Pointer;
  value_len: number;
}
koffi.struct('sipral_header_t', {
  name: 'void *',
  name_len: 'size_t',
  value: 'void *',
  value_len: 'size_t',
});

/**
 * What a stack is made with.
 *
 * Holds buffers of the caller's and the library only reads it, so it
 * crosses behind a `const` pointer as a struct going in.
 */
export interface SipralStackConfig {
  size: number;
  /**
   * Called for every event, from inside the poll.
   */
  event_callback: Pointer;
  /**
   * Handed back to the callback untouched.
   */
  event_user_data: Pointer;
  /**
   * Where to listen, as UTF-8.
   */
  bind_address: Pointer;
  bind_address_len: number;
  echo: number;
  /**
   * A sipral_toggle_t, read as a number and checked where it is used.
   */
  record: number;
  /**
   * Header fields to send, `headers_len` of them.
   */
  headers: Pointer;
  headers_len: number;
}
koffi.struct('sipral_stack_config_t', {
  size: 'size_t',
  event_callback: 'void *',
  event_user_data: 'void *',
  bind_address: 'void *',
  bind_address_len: 'size_t',
  echo: 'sipral_toggle_t',
  record: 'sipral_toggle_t',
  headers: 'void *',
  headers_len: 'size_t',
});

/**
 * One datagram, in room the caller brought.
 *
 * Holds writable buffers of the caller's, so it crosses behind a
 * mutable pointer as a struct going both ways.
 */
export interface SipralMediaPacket {
  size: number;
  /**
   * Where to write the datagram.
   */
  data: Pointer;
  capacity: number;
  len: number;
  /**
   * Where to write the address it goes to, as UTF-8.
   */
  destination: Pointer;
  destination_capacity: number;
  destination_len: number;
}
koffi.struct('sipral_media_packet_t', {
  size: 'size_t',
  data: 'void *',
  capacity: 'size_t',
  len: 'size_t',
  destination: 'void *',
  destination_capacity: 'size_t',
  destination_len: 'size_t',
});

/**
 * What a registration event says.
 */
export interface SipralRegistrationEvent {
  /**
   * Where it got to.
   */
  state: number;
  status_code: number;
}
koffi.struct('sipral_registration_event_t', {
  state: 'uint32_t',
  status_code: 'uint32_t',
});

/**
 * What a media event says.
 *
 * Lifetime
 *
 * Everything a pointer here names is the library's and lives until
 * the callback returns.
 */
export interface SipralMediaEvent {
  codec: number;
  /**
   * Why, as UTF-8, or null.
   */
  reason: Pointer;
  reason_len: number;
  /**
   * What the stream has done, or null when there is none.
   */
  statistics: Pointer;
}
koffi.struct('sipral_media_event_t', {
  codec: 'uint32_t',
  reason: 'void *',
  reason_len: 'size_t',
  statistics: 'void *',
});

/**
 * The one arm sipral_event_t::kind names, and no other.
 */
export interface SipralEventPayload {
  /**
   * Read when the kind is a registration one.
   */
  registration: SipralRegistrationEvent;
  /**
   * Read when the kind is a media one.
   */
  media: SipralMediaEvent;
}
koffi.union('sipral_event_payload_t', {
  registration: 'sipral_registration_event_t',
  media: 'sipral_media_event_t',
});

/**
 * One thing that happened, as the callback is handed it.
 */
export interface SipralEvent {
  size: number;
  /**
   * Which stack it came from.
   */
  stack: Wide;
  /**
   * Which of them, from sipral_status_t.
   */
  kind: number;
  /**
   * The message behind it, or null. It is the library's, and
   * it lives as long as SIPRAL_STATUS_OK is being reported
   * -- see sipral_stack_create for who owns what.
   */
  message: Pointer;
  message_len: number;
  /**
   * The arm the kind names.
   */
  payload: SipralEventPayload;
}
koffi.struct('sipral_event_t', {
  size: 'size_t',
  stack: 'sipral_handle_t',
  kind: 'uint32_t',
  message: 'void *',
  message_len: 'size_t',
  payload: 'sipral_event_payload_t',
});

/**
 * What a policy callback is asked before the library goes on.
 */
export interface SipralScreenEvent {
  size: number;
  /**
   * Who is calling, as UTF-8, or null.
   */
  from: Pointer;
  from_len: number;
}
koffi.struct('sipral_screen_event_t', {
  size: 'size_t',
  from: 'void *',
  from_len: 'size_t',
});

/**
 * What a processing callback is handed: a frame to read and one to fill.
 */
export interface SipralProcessorEvent {
  size: number;
  /**
   * The frame just captured, to read.
   */
  near: Pointer;
  near_len: number;
  /**
   * Where the processed frame is written.
   */
  far: Pointer;
  far_len: number;
}
koffi.struct('sipral_processor_event_t', {
  size: 'size_t',
  near: 'void *',
  near_len: 'size_t',
  far: 'void *',
  far_len: 'size_t',
});

/**
 * What the library calls when something happens.
 */
export const sipral_event_callback_t = koffi.proto('void sipral_event_callback_t(const sipral_event_t *event, void *user_data)');

/**
 * Asked before the library goes on, and answered with whether to
 * continue. A listener that throws instead of answering is read as
 * zero, which every callback here that answers is defined to take
 * as "no".
 */
export const sipral_screen_callback_t = koffi.proto('uint32_t sipral_screen_callback_t(const sipral_screen_event_t *event, void *user_data)');

/**
 * Run over one frame, and hand back what replaces it.
 */
export const sipral_process_callback_t = koffi.proto('void sipral_process_callback_t(const sipral_processor_event_t *event, void *user_data)');

/** Why the library could not be opened, or cannot serve this binding. */
export class SipralLoadError extends Error {
  constructor(message: string) {
    super(`sipral: ${message}`);
    this.name = 'SipralLoadError';
  }
}

/** What the library is called on this platform. */
export function libraryName(): string {
  if (process.platform === 'darwin') return 'libsipral_ffi.dylib';
  if (process.platform === 'win32') return 'sipral_ffi.dll';
  return 'libsipral_ffi.so';
}

/**
 * Where the library might be, in the order it is looked for:
 * `path` or `SIPRAL_LIBRARY`, whether either names the file or the
 * directory holding it; then beside this package, for one that
 * bundled the library; then the repository's own `target/release` and
 * `target/debug`, for working against a checkout.
 */
export function libraryCandidates(path?: string): string[] {
  const name = libraryName();
  const found: string[] = [];
  const named = path ?? process.env.SIPRAL_LIBRARY;
  if (named) {
    found.push(existsSync(named) && statSync(named).isDirectory() ? join(named, name) : named);
  }
  const here = dirname(fileURLToPath(import.meta.url));
  found.push(join(here, '..', name));
  const repository = join(here, '..', '..', '..');
  found.push(join(repository, 'target', 'release', name));
  found.push(join(repository, 'target', 'debug', name));
  return found;
}

/**
 * The library, opened and checked, with every entry point it has.
 *
 * {@link Sipral.open} is the only way to get one: it opens the
 * library and asks `sipral_abi_check` whether it can serve the ABI this
 * file was printed from, and throws {@link SipralLoadError} naming both
 * versions when it cannot, rather than letting whichever call first
 * reads a member that is not there fail instead.
 */
export class Sipral {
  /** Open the library and check it. */
  static open(path?: string): Sipral {
    const tried = libraryCandidates(path);
    const file = tried.find((candidate) => existsSync(candidate));
    if (file === undefined) {
      throw new SipralLoadError(
        `could not find ${libraryName()}. Tried:\n${tried.map((one) => `  ${one}`).join('\n')}\n\n` +
          'Build it with `cargo build --release -p sipral-ffi`, or set SIPRAL_LIBRARY to its path or its directory.',
      );
    }
    const sipral = new Sipral(koffi.load(file), file);
    const status = sipral.sipral_abi_check(SIPRAL_ABI_VERSION_MAJOR, SIPRAL_ABI_VERSION_MINOR);
    if (status !== SipralStatus.Ok) {
      throw new SipralLoadError(
        `this build of the library does not implement ABI ${SIPRAL_ABI_VERSION_MAJOR}.${SIPRAL_ABI_VERSION_MINOR}, ` +
          'which this binding was generated against; regenerate the binding or rebuild the library',
      );
    }
    return sipral;
  }

  /** The file the library was loaded from. */
  readonly path: string;


  /**
   * Whether this library can serve a binding generated against `major`.`minor`.
   */
  readonly sipral_abi_check: (major: number, minor: number) => number;

  /**
   * The calling thread's last error.
   */
  readonly sipral_last_error_message: (buffer: Pointer, capacity: number, out_needed: Pointer) => number;

  /**
   * The name of one sipral_status_t, for a log line.
   */
  readonly sipral_status_name: (code: number) => string;

  /**
   * Make one.
   */
  readonly sipral_stack_create: (config: Pointer, out_stack: Pointer) => number;

  /**
   * Read sipral_counters_t off it.
   */
  readonly sipral_stack_counters: (stack: Wide, out_counters: Pointer) => number;

  /**
   * Turn the echo on or off, and say what it was.
   */
  readonly sipral_stack_set_echo: (stack: Wide, echo: number, out_was: Pointer) => number;

  /**
   * Every setting it has, one sipral_toggle_t each.
   */
  readonly sipral_stack_toggles: (stack: Wide, out_toggles: Pointer, capacity: number, out_count: Pointer) => number;

  /**
   * Hand it bytes to send.
   */
  readonly sipral_stack_send: (stack: Wide, message: Pointer, message_len: number) => number;

  /**
   * Hand it header fields, an array of them with its length beside it.
   */
  readonly sipral_stack_label: (stack: Wide, headers: Pointer, headers_len: number) => number;

  /**
   * Hand it text, which crosses as UTF-8 and not as a String.
   */
  readonly sipral_stack_describe: (stack: Wide, note: Pointer, note_len: number) => number;

  /**
   * Fill a buffer the caller brings.
   */
  readonly sipral_stack_name: (stack: Wide, name: Pointer, capacity: number, out_len: Pointer) => number;

  /**
   * Fill a buffer of numbers the caller brings.
   */
  readonly sipral_stack_codec_order: (stack: Wide, out_codecs: Pointer, capacity: number, out_count: Pointer) => number;

  /**
   * Fill a buffer of opaque bytes the caller brings.
   */
  readonly sipral_stack_freeze: (stack: Wide, buffer: Pointer, capacity: number, out_len: Pointer) => number;

  /**
   * Fill a buffer of samples the caller brings.
   */
  readonly sipral_call_playback: (stack: Wide, samples: Pointer, capacity: number, out_written: Pointer) => number;

  /**
   * Hand it samples, and get one datagram back in the struct.
   */
  readonly sipral_call_capture: (stack: Wide, samples: Pointer, sample_count: number, packet: Pointer) => number;

  /**
   * Hand it one buffer of samples and fill another, in the same call,
   * neither one named `capacity` — two buffers going in, one of them
   * writable, which is not the same shape as one being filled.
   */
  readonly sipral_call_mix: (stack: Wide, mic: Pointer, mic_count: number, local: Pointer, local_count: number) => number;

  /**
   * Hand it a datagram that arrived, in a buffer it may rewrite in
   * place, and hear what became of it.
   */
  readonly sipral_call_media_receive: (stack: Wide, data: Pointer, len: number, out_arrival: Pointer) => number;

  /**
   * Install a policy on it, replace the one installed, or remove it.
   *
   * The callback and the pointer after it are one listener, the same
   * pair a struct going in already means by them, and a null callback
   * removes whatever was installed.
   */
  readonly sipral_stack_screen: (stack: Wide, callback: Pointer, user_data: Pointer) => number;

  /**
   * Install a processor on it, replace the one installed, or remove it.
   *
   * The callback and the pointer after it are one listener, the same
   * pair a struct going in already means by them, and a null callback
   * removes whatever was installed.
   */
  readonly sipral_stack_process: (stack: Wide, callback: Pointer, user_data: Pointer) => number;

  /**
   * Take it apart.
   */
  readonly sipral_stack_destroy: (stack: Wide) => number;

  private constructor(library: ReturnType<typeof koffi.load>, path: string) {
    this.path = path;
    this.sipral_abi_check = library.func('sipral_status_t sipral_abi_check(uint32_t major, uint32_t minor)');
    this.sipral_last_error_message = library.func('sipral_status_t sipral_last_error_message(char *buffer, size_t capacity, size_t *out_needed)');
    this.sipral_status_name = library.func('const char *sipral_status_name(int32_t code)');
    this.sipral_stack_create = library.func('sipral_status_t sipral_stack_create(const sipral_stack_config_t *config, sipral_handle_t *out_stack)');
    this.sipral_stack_counters = library.func('sipral_status_t sipral_stack_counters(sipral_handle_t stack, sipral_counters_t *out_counters)');
    this.sipral_stack_set_echo = library.func('sipral_status_t sipral_stack_set_echo(sipral_handle_t stack, sipral_toggle_t echo, sipral_toggle_t *out_was)');
    this.sipral_stack_toggles = library.func('sipral_status_t sipral_stack_toggles(sipral_handle_t stack, sipral_toggle_t *out_toggles, size_t capacity, size_t *out_count)');
    this.sipral_stack_send = library.func('sipral_status_t sipral_stack_send(sipral_handle_t stack, const uint8_t *message, size_t message_len)');
    this.sipral_stack_label = library.func('sipral_status_t sipral_stack_label(sipral_handle_t stack, const sipral_header_t *headers, size_t headers_len)');
    this.sipral_stack_describe = library.func('sipral_status_t sipral_stack_describe(sipral_handle_t stack, const char *note, size_t note_len)');
    this.sipral_stack_name = library.func('sipral_status_t sipral_stack_name(sipral_handle_t stack, char *name, size_t capacity, size_t *out_len)');
    this.sipral_stack_codec_order = library.func('sipral_status_t sipral_stack_codec_order(sipral_handle_t stack, uint32_t *out_codecs, size_t capacity, size_t *out_count)');
    this.sipral_stack_freeze = library.func('sipral_status_t sipral_stack_freeze(sipral_handle_t stack, uint8_t *buffer, size_t capacity, size_t *out_len)');
    this.sipral_call_playback = library.func('sipral_status_t sipral_call_playback(sipral_handle_t stack, int16_t *samples, size_t capacity, size_t *out_written)');
    this.sipral_call_capture = library.func('sipral_status_t sipral_call_capture(sipral_handle_t stack, const int16_t *samples, size_t sample_count, sipral_media_packet_t *packet)');
    this.sipral_call_mix = library.func('sipral_status_t sipral_call_mix(sipral_handle_t stack, const int16_t *mic, size_t mic_count, int16_t *local, size_t local_count)');
    this.sipral_call_media_receive = library.func('sipral_status_t sipral_call_media_receive(sipral_handle_t stack, uint8_t *data, size_t len, uint32_t *out_arrival)');
    this.sipral_stack_screen = library.func('sipral_status_t sipral_stack_screen(sipral_handle_t stack, sipral_screen_callback_t *callback, void *user_data)');
    this.sipral_stack_process = library.func('sipral_status_t sipral_stack_process(sipral_handle_t stack, sipral_process_callback_t *callback, void *user_data)');
    this.sipral_stack_destroy = library.func('sipral_status_t sipral_stack_destroy(sipral_handle_t stack)');
  }
}

/**
 * Every struct and union the header declares, with how long tools/abi-gen
 * worked it out to be on each of the three layouts the ABI ships for:
 * 64-bit pointers (p64), then 32-bit pointers with 64-bit integers aligned
 * to four (p32a4, i386) and to eight (p32a8, ARM and Windows x86). A size
 * test holds this binding's own layout of each record, and the library's
 * answer from sipral_abi_struct_size, to the number for the layout it runs
 * on; bindings/c/abi-layout.c holds a C compiler to all three.
 */
export const RECORD_LAYOUTS: Readonly<Record<string, readonly [number, number, number]>> = {
  sipral_counters_t: [24, 16, 24],
  sipral_header_t: [32, 16, 16],
  sipral_stack_config_t: [64, 36, 36],
  sipral_media_packet_t: [56, 28, 28],
  sipral_registration_event_t: [8, 8, 8],
  sipral_media_event_t: [32, 16, 16],
  sipral_event_payload_t: [32, 16, 16],
  sipral_event_t: [72, 40, 48],
  sipral_screen_event_t: [24, 12, 12],
  sipral_processor_event_t: [40, 20, 20],
};
