// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// What the stack, the account, the call and the media share: the library
// opened once, the status check, text in and out of the library's memory,
// and `host:port` read and written.

import { isIP } from 'node:net';

import koffi from 'koffi';

import { type Pointer, Sipral, SipralStatus, SipralToggle, type Wide } from './sipral_abi.js';

/** The largest datagram a socket here reads or a packet here is written into. */
export const PACKET_BYTES = 65536;

/** Room for one `host:port`, as the library writes it. */
export const ADDRESS_BYTES = 128;

let shared: Sipral | undefined;

/**
 * The library a stack uses when it is given none: opened, and its ABI
 * checked, the first time a stack needs it.
 */
export function library(): Sipral {
  shared ??= Sipral.open();
  return shared;
}

/** A call into the library that did not return `SIPRAL_STATUS_OK`. */
export class SipralError extends Error {
  /** The `SipralStatus` value it returned. */
  readonly status: number;

  /** The entry point, as the header names it. */
  readonly operation: string;

  /** What the library said about it, from `sipral_last_error_message`. */
  readonly detail: string;

  constructor(status: number, operation: string, detail: string) {
    super(`sipral: ${operation} returned ${status}${detail ? `: ${detail}` : ''}`);
    this.name = 'SipralError';
    this.status = status;
    this.operation = operation;
    this.detail = detail;
  }
}

/** What the library said about the last call that failed on this thread. */
function lastError(sipral: Sipral): string {
  const buffer = Buffer.alloc(1024);
  const length = new BigUint64Array(1);
  if (sipral.sipral_last_error_message(buffer, buffer.length, length) !== SipralStatus.Ok) {
    return '';
  }
  // the length counts the trailing NUL, which is not part of the message
  const used = Math.max(0, Math.min(Number(length[0]), buffer.length) - 1);
  return buffer.toString('utf8', 0, used).trim();
}

/** Throw {@link SipralError} unless `status` is `SIPRAL_STATUS_OK`. */
export function check(sipral: Sipral, operation: string, status: number): void {
  if (status !== SipralStatus.Ok) {
    throw new SipralError(status, operation, lastError(sipral));
  }
}

const pause = new Int32Array(new SharedArrayBuffer(4));

/** Whether `status` is one a moment's wait gets past: busy, or a clock reading behind. */
export function passing(status: number): boolean {
  return status === SipralStatus.ClockBehind || status === SipralStatus.Busy;
}

/**
 * The status `entryPoint` returns, called again while that is
 * `SipralStatus.ClockBehind` or `SipralStatus.Busy` -- for up to half a
 * second. Every entry point here reads the stack's clock afresh right
 * before the call, so a reading the stack's last one beat can only be
 * followed by a later one; a busy stack is one the audio engine's thread
 * holds for a moment.
 */
export function retryingClockBehind(entryPoint: () => number): number {
  const started = Date.now();
  let status = entryPoint();
  while (passing(status) && Date.now() - started < 500) {
    Atomics.wait(pause, 0, 0, 1);
    status = entryPoint();
  }
  return status;
}

/** {@link check} over what {@link retryingClockBehind} makes of `entryPoint`. */
export function checkNow(sipral: Sipral, operation: string, entryPoint: () => number): void {
  check(sipral, operation, retryingClockBehind(entryPoint));
}

/**
 * `value` as UTF-8 with a zero after it, and its length in bytes without
 * the zero; no buffer and zero for no text.
 */
export function text(value: string | null | undefined): [Buffer | null, number] {
  if (value === null || value === undefined) {
    return [null, 0];
  }
  const bytes = Buffer.from(`${value}\0`, 'utf8');
  return [bytes, bytes.length - 1];
}

/** Whether an address koffi handed back is the null pointer. */
export function isNull(address: Pointer): boolean {
  return address === null || address === 0 || address === 0n;
}

/** `length` bytes at `address`, copied out of the library's memory. */
export function readBytes(address: Pointer, length: Wide): Buffer | null {
  if (isNull(address)) {
    return null;
  }
  const count = Number(length);
  if (count === 0) {
    return Buffer.alloc(0);
  }
  return Buffer.from(koffi.view(address, count).slice(0));
}

/** `length` bytes at `address` as UTF-8, or null for the null pointer. */
export function readText(address: Pointer, length: Wide): string | null {
  return readBytes(address, length)?.toString('utf8') ?? null;
}

/** A handle as koffi hands it back, as the `bigint` this layer keeps it in. */
export function handle(value: Wide): bigint {
  return BigInt(value);
}

/**
 * A record of `type`, laid out in a buffer of its own, `size` filled in and
 * every member not named zero. Each buffer named in `values` must outlive
 * the call it is handed to, which the caller's own reference sees to.
 */
export function record(type: string, values: Record<string, unknown> = {}): Buffer {
  const size = koffi.sizeof(type);
  const memory = Buffer.alloc(size);
  koffi.encode(memory, type, { size, ...values });
  return memory;
}

/** The record of `type` a buffer holds. */
export function read<T>(memory: Buffer | Pointer, type: string, offset = 0): T {
  return koffi.decode(memory, offset, type) as T;
}

/** `host:port`, with an IPv6 host in brackets. */
export function formatAddress(host: string, port: number): string {
  return isIP(host) === 6 ? `[${host}]:${port}` : `${host}:${port}`;
}

/**
 * The host and the port of a `host:port` the library wrote, or null for one
 * whose host is not an address literal: a name is the application's to
 * resolve.
 */
export function parseAddress(value: string): { host: string; port: number } | null {
  const colon = value.lastIndexOf(':');
  if (colon <= 0) {
    return null;
  }
  let host = value.slice(0, colon);
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1);
  }
  const port = Number(value.slice(colon + 1));
  if (isIP(host) === 0 || !Number.isInteger(port) || port <= 0 || port > 65535) {
    return null;
  }
  return { host, port };
}

/** `camelCase` as the header's `snake_case`. */
export function snake(name: string): string {
  return name.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`);
}

/** The header's `snake_case` as `camelCase`. */
export function camel(name: string): string {
  return name.replace(/_([a-z0-9])/g, (_, letter: string) => letter.toUpperCase());
}

/**
 * The members of a record that are a `sipral_toggle_t`: a boolean given for
 * one is `SIPRAL_TOGGLE_ON` or `SIPRAL_TOGGLE_OFF`, where every other
 * boolean member is a plain 1 or 0.
 */
const TOGGLES: ReadonlySet<string> = new Set([
  'offer_dtmf',
  'offer_rtcp_mux',
  'silence_suppression',
  'media_stall_watchdog',
  'g729_annex_b',
  'referrals',
  'registrar_keepalive',
  'diagnostic_trace',
  'system_echo_cancellation',
  'server_naptr',
  'feedback',
  'accept_service_provider_codes',
  'listen',
  'answering_machine',
  'beep',
  'enabled',
  'local',
]);

/** The members that hold a handle, read back as a `bigint`. */
const HANDLES: ReadonlySet<string> = new Set([
  'stack',
  'account',
  'call',
  'other',
  'subscription',
  'forked_from',
  'conference',
  'member',
  'loudest',
  'announcement',
  'message',
  'dialog',
  'echo_call',
]);

/** The pointer members whose bytes are kept as bytes rather than read as text. */
const BYTES: ReadonlySet<string> = new Set(['body', 'local_sdp', 'remote_sdp', 'sdp', 'payload', 'data']);

/** The names of a record's members, as the header gives them. */
const membersOf = new Map<string, ReadonlySet<string>>();

function members(type: string): ReadonlySet<string> {
  let found = membersOf.get(type);
  if (found === undefined) {
    found = new Set(Object.keys(koffi.type(type).members ?? {}));
    membersOf.set(type, found);
  }
  return found;
}

/** What an option may be given as, before it is laid out in a record. */
export type Option = string | Buffer | Uint8Array | number | bigint | boolean | readonly string[] | null | undefined;

/**
 * A record of `type` built from `options`, whose names are its members' in
 * `camelCase`: text and bytes go in as a pointer and the `_len` beside it, a
 * list of text joined with `separator`, a boolean as a toggle or a 1, a
 * number as itself. A name the record has no member for is not this
 * record's, and is passed over: an options object carries what the binding
 * itself acts on beside what the library reads. `fixed` is laid out last,
 * under the header's own names. Every buffer made is kept on the record, so
 * it lives exactly as long as the record handed to the library.
 */
export function config(
  type: string,
  options: object,
  fixed: Record<string, unknown> = {},
  separator: Readonly<Record<string, string>> = {},
): Buffer {
  const names = members(type);
  const values: Record<string, unknown> = {};
  const kept: unknown[] = [];
  for (const [key, given] of Object.entries(options) as [string, Option][]) {
    const name = snake(key);
    if (given === undefined || given === null || !names.has(name) || name === 'size') {
      continue;
    }
    const length = `${name}_len`;
    if (typeof given === 'string' || Array.isArray(given)) {
      const joined = typeof given === 'string' ? given : (given as readonly string[]).join(separator[name] ?? ',');
      if (joined.length === 0) {
        continue;
      }
      const [bytes, count] = text(joined);
      kept.push(bytes);
      values[name] = bytes;
      values[length] = count;
    } else if (given instanceof Uint8Array) {
      if (given.length === 0) {
        continue;
      }
      const bytes = Buffer.from(given);
      kept.push(bytes);
      values[name] = bytes;
      values[length] = bytes.length;
    } else if (typeof given === 'boolean') {
      values[name] = TOGGLES.has(name) ? toggle(given) : given ? 1 : 0;
    } else {
      values[name] = given;
    }
  }
  for (const [name, value] of Object.entries(fixed)) {
    if (value !== undefined) {
      values[name] = value;
    }
  }
  const memory = record(type, values);
  Object.defineProperty(memory, 'kept', { value: kept });
  return memory;
}

/** A number koffi read, as a `number` while that is exact. */
function exact(value: unknown): unknown {
  if (typeof value === 'bigint' && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(value);
  }
  return value;
}

/**
 * A record the library filled in, as a plain object with `camelCase` names:
 * `size` and the reserved members left out, a handle as a `bigint`, and a
 * pointer with a `_len` beside it as its text (or bytes, for a body). A
 * pointer with no length beside it is an address, which the caller reads
 * itself or leaves alone.
 */
export function plain(memory: Buffer | Pointer, type: string, offset = 0): Record<string, unknown> {
  const raw = read<Record<string, unknown>>(memory, type, offset);
  const out: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(raw)) {
    if (name === 'size' || name.startsWith('reserved') || name.endsWith('_len') || name.endsWith('_capacity')) {
      continue;
    }
    const length = raw[`${name}_len`];
    if (length !== undefined) {
      const bytes = readBytes(value as Pointer, length as Wide);
      out[camel(name)] =
        bytes === null || bytes.length === 0 ? null : BYTES.has(name) ? bytes : bytes.toString('utf8');
      continue;
    }
    if (typeof value === 'object' && value !== null) {
      continue;
    }
    out[camel(name)] = HANDLES.has(name) ? BigInt(value as Wide) : exact(value);
  }
  return out;
}

/**
 * Text an entry point copies into a caller's buffer with its NUL, answering
 * `SipralStatus.BufferTooSmall` and the bytes it needs when the buffer is
 * short: tried again with exactly that many, and again while the stack is
 * busy, for half a second.
 */
export function copyText(
  sipral: Sipral,
  operation: string,
  copy: (buffer: Buffer, capacity: number, needed: BigUint64Array) => number,
  capacity = 256,
): string {
  const needed = new BigUint64Array(1);
  const started = Date.now();
  let room = capacity;
  for (;;) {
    const buffer = Buffer.alloc(room);
    const status = copy(buffer, room, needed);
    if (status === SipralStatus.BufferTooSmall && Number(needed[0]) > room) {
      room = Number(needed[0]);
      continue;
    }
    if (passing(status) && Date.now() - started < 500) {
      Atomics.wait(pause, 0, 0, 1);
      continue;
    }
    check(sipral, operation, status);
    const used = Math.max(0, Math.min(Number(needed[0]), room) - 1);
    return buffer.toString('utf8', 0, used);
  }
}

/** The value of `toggle`: unset is the library's default. */
export function toggle(value: boolean | undefined): number {
  if (value === undefined) {
    return SipralToggle.Default;
  }
  return value ? SipralToggle.On : SipralToggle.Off;
}

/**
 * The promise `promise`, rejected with a `TimeoutError` after `ms`
 * milliseconds. The timer never keeps the process up on its own.
 */
export function within<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      const error = new Error(`sipral: ${what} did not happen within ${ms} ms`);
      error.name = 'TimeoutError';
      reject(error);
    }, ms);
    timer.unref();
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error(String(error)));
      },
    );
  });
}
