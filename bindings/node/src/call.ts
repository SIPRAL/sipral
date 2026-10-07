// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// One call, its media socket, and its media once the session is up.

import type { Socket } from 'node:dgram';
import { EventEmitter, on } from 'node:events';

import type { MediaStatistics, StackEvent } from './events.js';
import { check, checkNow, parseAddress, text, within } from './internal.js';
import { Media } from './media.js';
import { SipralCallState, SipralDtmf, SipralEventKind } from './sipral_abi.js';
import type { Stack } from './stack.js';

/** What a call emits. */
export interface CallEvents {
  /** Every event about this call, in order. */
  event: [StackEvent];
  /** Each digit the far end sends, RFC 4733 or SIP INFO alike. */
  digit: [string];
  /** The call is confirmed. */
  confirmed: [];
  /** The call has ended. */
  ended: [StackEvent];
  /** The media started: {@link Call.media} is there from now on. */
  media: [Media];
}

/**
 * A call placed with {@link Stack.placeCall} or answered with
 * {@link Stack.answerCall}.
 */
export class Call extends EventEmitter<CallEvents> {
  /** The stack it belongs to. */
  readonly stack: Stack;
  /** The call's handle. */
  readonly handle: bigint;
  /** Whether the far end placed it. */
  readonly incoming: boolean;
  /** Where its media socket is bound, `host:port`: what its SDP offers. */
  readonly mediaAddress: string;

  private readonly socket: Socket;
  private mediaStream: Media | null = null;
  private isConfirmed = false;
  private hasEnded = false;
  private closed = false;
  private kept: MediaStatistics | null = null;

  /** @internal Built by the stack. */
  constructor(stack: Stack, callHandle: bigint, socket: Socket, mediaAddress: string, incoming: boolean) {
    super();
    this.stack = stack;
    this.handle = callHandle;
    this.socket = socket;
    this.mediaAddress = mediaAddress;
    this.incoming = incoming;
  }

  /** The call's media, from `MediaStarted` until the call is closed. */
  get media(): Media | null {
    return this.mediaStream;
  }

  /** Whether `CallEnded` has been delivered. */
  get ended(): boolean {
    return this.hasEnded;
  }

  /**
   * What the call's media cost in the end: the record `MediaStatistics`
   * carries, kept from the moment it arrives, right after `CallEnded`.
   */
  get finalStatistics(): MediaStatistics | null {
    return this.kept;
  }

  /** Where the call is, a `SipralCallState` value; `Terminated` once it has ended. */
  get state(): number {
    if (this.hasEnded) {
      return SipralCallState.Terminated;
    }
    const sipral = this.stack.sipral;
    const out = new Uint32Array(1);
    check(sipral, 'sipral_call_state', sipral.sipral_call_state(this.stack.handle, this.handle, out));
    return out[0] ?? SipralCallState.Unknown;
  }

  /** Every event about this call, as an async iterator, from now on. */
  events(options: { signal?: AbortSignal } = {}): AsyncIterableIterator<StackEvent> {
    const iterator = on(this, 'event', options) as AsyncIterableIterator<[StackEvent]>;
    return (async function* () {
      for await (const [event] of iterator) {
        yield event;
      }
    })();
  }

  /**
   * The next event about this call that `matches`, or a `TimeoutError`
   * after `timeoutMs`. Listening starts at once, so nothing raised after
   * this returns is missed.
   */
  next(matches: (event: StackEvent) => boolean, timeoutMs = 15000): Promise<StackEvent> {
    return within(
      new Promise<StackEvent>((resolve) => {
        const listener = (event: StackEvent): void => {
          if (matches(event)) {
            this.off('event', listener);
            resolve(event);
          }
        };
        this.on('event', listener);
      }),
      timeoutMs,
      'the event waited for on the call',
    );
  }

  /** Resolve once the call is confirmed; reject if it ends first. */
  confirmed(timeoutMs = 30000): Promise<void> {
    if (this.isConfirmed) {
      return Promise.resolve();
    }
    if (this.hasEnded) {
      return Promise.reject(new Error('sipral: the call ended before it was confirmed'));
    }
    return within(
      new Promise<void>((resolve, reject) => {
        const confirmed = (): void => {
          this.off('ended', ended);
          resolve();
        };
        const ended = (): void => {
          this.off('confirmed', confirmed);
          reject(new Error('sipral: the call ended before it was confirmed'));
        };
        this.once('confirmed', confirmed);
        this.once('ended', ended);
      }),
      timeoutMs,
      'the call being confirmed',
    );
  }

  /** Resolve once the call has ended. */
  whenEnded(timeoutMs = 30000): Promise<void> {
    if (this.hasEnded) {
      return Promise.resolve();
    }
    return within(
      new Promise<void>((resolve) => {
        this.once('ended', () => resolve());
      }),
      timeoutMs,
      'the call ending',
    );
  }

  /**
   * Send `digits` (`0`-`9`, `*`, `#`, `A`-`D`), `via` a `SipralDtmf`
   * value -- RFC 4733 events by default -- each lasting `durationMs`.
   */
  sendDtmf(digits: string, via: number = SipralDtmf.Rtp, durationMs = 100): void {
    this.stack.ensureOpen();
    const [data, length] = text(digits);
    checkNow(this.stack.sipral, 'sipral_call_send_dtmf', () =>
      this.stack.sipral.sipral_call_send_dtmf(
        this.stack.handle,
        this.handle,
        data,
        length,
        via,
        durationMs,
        this.stack.nowMs(),
      ),
    );
    this.stack.poll();
  }

  /** Hang up: a BYE once confirmed, a CANCEL while still ringing out. */
  hangup(): void {
    this.stack.ensureOpen();
    checkNow(this.stack.sipral, 'sipral_call_hangup', () =>
      this.stack.sipral.sipral_call_hangup(this.stack.handle, this.handle, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /** Put the far end on hold (`sipral_call_hold`). */
  hold(): void {
    this.stack.ensureOpen();
    checkNow(this.stack.sipral, 'sipral_call_hold', () =>
      this.stack.sipral.sipral_call_hold(this.stack.handle, this.handle, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /** Take the far end off hold (`sipral_call_resume`). */
  resume(): void {
    this.stack.ensureOpen();
    checkNow(this.stack.sipral, 'sipral_call_resume', () =>
      this.stack.sipral.sipral_call_resume(this.stack.handle, this.handle, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /**
   * REFER the far end to `target` (RFC 3515, `sipral_call_transfer`).
   * `TransferProgress` and then `TransferDone` follow on this call's events;
   * a REFER the far end refuses is a `TransferDone` carrying the refusal.
   */
  transfer(target: string): void {
    this.stack.ensureOpen();
    const [data, length] = text(target);
    checkNow(this.stack.sipral, 'sipral_call_transfer', () =>
      this.stack.sipral.sipral_call_transfer(
        this.stack.handle,
        this.handle,
        data,
        length,
        this.stack.nowMs(),
      ),
    );
    this.stack.poll();
  }

  /**
   * Release the media and close the media socket. The call is forgotten by
   * its stack; hang it up first if it is still up.
   */
  close(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.mediaStream?.close();
    this.mediaStream = null;
    this.socket.close();
    this.stack.forget(this);
  }

  /** @internal What the stack hands each event about this call to. */
  deliver(event: StackEvent): void {
    switch (event.kind) {
      case SipralEventKind.MediaStarted:
        if (this.mediaStream === null && !this.closed) {
          this.mediaStream = new Media(this, this.socket);
          this.emit('media', this.mediaStream);
        }
        break;
      case SipralEventKind.CallConfirmed:
        if (!this.isConfirmed) {
          this.isConfirmed = true;
          this.emit('confirmed');
        }
        break;
      case SipralEventKind.MediaStatistics:
        this.kept = event.statistics ?? this.kept;
        break;
      case SipralEventKind.DigitReceived:
        if (event.digit !== null) {
          this.emit('digit', event.digit);
        }
        break;
      case SipralEventKind.CallEnded:
        this.hasEnded = true;
        break;
      default:
        break;
    }
    this.emit('event', event);
    if (event.kind === SipralEventKind.CallEnded) {
      this.emit('ended', event);
    }
  }

  /** @internal One packet out of the call's socket, where it says to go. */
  sendPacket(payload: Buffer, destination: string): void {
    if (this.closed) {
      return;
    }
    const to = parseAddress(destination);
    if (to !== null) {
      this.socket.send(payload, to.port, to.host);
    }
  }
}
