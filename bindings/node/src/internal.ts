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

/**
 * The status `entryPoint` returns, called again while that is
 * `SipralStatus.ClockBehind` -- for up to half a second. Every entry point
 * here reads the stack's clock afresh right before the call, so a reading
 * the stack's last one beat can only be followed by a later one.
 */
export function retryingClockBehind(entryPoint: () => number): number {
  const started = Date.now();
  let status = entryPoint();
  while (status === SipralStatus.ClockBehind && Date.now() - started < 500) {
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
