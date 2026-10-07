// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// One call, its media socket, and its media once the session is up.

import type { Socket } from 'node:dgram';
import { EventEmitter, on } from 'node:events';

import koffi from 'koffi';

import type { MediaStatistics, StackEvent } from './events.js';
import { check, checkNow, config, copyText, formatAddress, parseAddress, text, within } from './internal.js';
import { Media } from './media.js';
import { SipralCallState, SipralDtmf, SipralEventKind, SipralStatus, SipralTransport } from './sipral_abi.js';
import type { CallOptions, Stack } from './stack.js';
import { Subscription } from './subscription.js';

/** What a call emits. */
export interface CallEvents {
  /** Every event about this call, in order. */
  event: [StackEvent];
  /** Each digit the far end sends: RFC 4733, SIP INFO or heard in the audio alike. */
  digit: [string];
  /** What the far end typed on the real-time text stream (RFC 4103), in order. */
  text: [string];
  /** The call is confirmed. */
  confirmed: [];
  /** The call has ended. */
  ended: [StackEvent];
  /** The media started: {@link Call.media} is there from now on. */
  media: [Media];
}

/** Header fields for a request or an answer: name and value pairs, or an object. */
export type HeaderFields = ReadonlyArray<readonly [string, string]> | Readonly<Record<string, string>>;

/**
 * Header fields laid out as the `sipral_header_t` array the library reads,
 * the buffers kept on it.
 */
export function headerArray(fields: HeaderFields): { array: Buffer | null; count: number } {
  const pairs: (readonly [string, string])[] = Array.isArray(fields)
    ? [...(fields as ReadonlyArray<readonly [string, string]>)]
    : Object.entries(fields as Record<string, string>);
  if (pairs.length === 0) {
    return { array: null, count: 0 };
  }
  const size = koffi.sizeof('sipral_header_t');
  const array = Buffer.alloc(size * pairs.length);
  const kept: Buffer[] = [];
  pairs.forEach(([name, value], index) => {
    const [nameBytes, nameLength] = text(name);
    const [valueBytes, valueLength] = text(value);
    kept.push(nameBytes as Buffer, valueBytes as Buffer);
    koffi.encode(array, index * size, 'sipral_header_t', {
      name: nameBytes,
      name_len: nameLength,
      value: valueBytes,
      value_len: valueLength,
    });
  });
  Object.defineProperty(array, 'kept', { value: kept });
  return { array, count: pairs.length };
}

/** How a call listens for the network's tones, who answered and the beep. */
export interface ProgressOptions {
  /** A `SipralToneRegion` value: whose tones to know. */
  region?: number;
  /** Decide whether a person or a machine answered (on by default). */
  answeringMachine?: boolean;
  /** Listen for the machine's beep (on by default). */
  beep?: boolean;
  beepWindowMs?: number;
  maxInitialSilenceMs?: number;
  maxGreetingMs?: number;
  silenceAfterGreetingMs?: number;
  maxWords?: number;
  minWordMs?: number;
  minWordGapMs?: number;
  maxDecisionMs?: number;
  minSpeechAboveFloorDb?: number;
  beepMinMs?: number;
  beepMaxMs?: number;
  toneCycles?: number;
}

/** The beep a recorded call carries; every value left out is the library's default. */
export interface ConsentToneOptions {
  /** 1400 Hz by default. */
  frequencyHz?: number;
  /** 18 dB below 0 dBm0 by default. */
  attenuationDb?: number;
  /** 200 ms by default. */
  lengthMs?: number;
  /** Every fifteen seconds by default. */
  intervalMs?: number;
  /** Whether this end hears it too (on by default). */
  local?: boolean;
}

/**
 * A call placed with {@link Stack.placeCall}, answered with
 * {@link Stack.answerCall} or rung with {@link Stack.ringCall}.
 */
export class Call extends EventEmitter<CallEvents> {
  /** The stack it belongs to. */
  readonly stack: Stack;
  /** The call's handle. */
  readonly handle: bigint;
  /** Whether the far end placed it. */
  readonly incoming: boolean;
  /** Where its real-time text socket is bound, `host:port`, when it has one. */
  readonly textAddress: string | null;
  /** The recording session {@link recordTo} placed, while it records. */
  recordingSession: bigint | null = null;

  private socket: Socket;
  private address: string;
  private readonly textSocket: Socket | null;
  private mediaStream: Media | null = null;
  private isConfirmed = false;
  private hasEnded = false;
  private closed = false;
  private kept: MediaStatistics | null = null;
  private suite: number | null = null;
  private joined: Call | null = null;

  /** @internal Built by the stack. */
  constructor(
    stack: Stack,
    callHandle: bigint,
    socket: Socket,
    mediaAddress: string,
    incoming: boolean,
    textSocket: Socket | null = null,
  ) {
    super();
    this.stack = stack;
    this.handle = callHandle;
    this.socket = socket;
    this.address = mediaAddress;
    this.incoming = incoming;
    this.textSocket = textSocket;
    const bound = textSocket?.address();
    this.textAddress = bound === undefined ? null : formatAddress(bound.address, bound.port);
  }

  /** Where its media socket is bound, `host:port`: what its SDP offers. */
  get mediaAddress(): string {
    return this.address;
  }

  /** The call's media socket: where its packets leave from. */
  get mediaSocket(): Socket {
    return this.socket;
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

  /**
   * The SRTP suite (a `SipralSrtpSuite` value) a DTLS-SRTP handshake settled
   * the media on, as the last `MediaSecured` said, or null; a call keyed by
   * SDES says it is encrypted in {@link Media.info}.
   */
  get srtpSuite(): number | null {
    return this.suite;
  }

  /** Where the call is, a `SipralCallState` value; `Terminated` once it has ended. */
  get state(): number {
    if (this.hasEnded) {
      return SipralCallState.Terminated;
    }
    const sipral = this.stack.sipral;
    const out = new Uint32Array(1);
    checkNow(sipral, 'sipral_call_state', () => sipral.sipral_call_state(this.stack.handle, this.handle, out));
    return out[0] ?? SipralCallState.Unknown;
  }

  /** Who holds whom: this end the far end (`here`), the far end this end (`there`). */
  holdState(): { here: boolean; there: boolean } {
    const sipral = this.stack.sipral;
    const here = new Uint32Array(1);
    const there = new Uint32Array(1);
    checkNow(sipral, 'sipral_call_hold_state', () => sipral.sipral_call_hold_state(this.stack.handle, this.handle, here, there));
    return { here: here[0] !== 0, there: there[0] !== 0 };
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

  /** Resolve with the call's media once it has started. */
  mediaStarted(timeoutMs = 15000): Promise<Media> {
    if (this.mediaStream !== null) {
      return Promise.resolve(this.mediaStream);
    }
    return within(
      new Promise<Media>((resolve) => {
        this.once('media', resolve);
      }),
      timeoutMs,
      "the call's media starting",
    );
  }

  /**
   * Answer a call this stack rang with {@link Stack.ringCall}, on the media
   * socket it opened then: `sipral_call_answer_media`, or
   * `sipral_call_answer_with` given `options`.
   */
  answer(options: Pick<CallOptions, 'feedback' | 'focus' | 'codecs'> = {}): void {
    this.stack.ensureOpen();
    if (options.feedback === undefined && options.focus === undefined && options.codecs === undefined && this.textSocket === null) {
      const [media, length] = text(this.address);
      checkNow(this.stack.sipral, 'sipral_call_answer_media', () =>
        this.stack.sipral.sipral_call_answer_media(this.stack.handle, this.handle, media, length, this.stack.nowMs()),
      );
    } else {
      const made = config('sipral_call_config_t', {
        mediaAddress: this.address,
        textAddress: this.textAddress,
        feedback: options.feedback === true ? true : undefined,
        focus: options.focus,
        codecs: options.codecs,
      });
      checkNow(this.stack.sipral, 'sipral_call_answer_with', () =>
        this.stack.sipral.sipral_call_answer_with(this.stack.handle, this.handle, made, this.stack.nowMs()),
      );
    }
    this.stack.poll();
  }

  /** `sipral_call_ring`: 180 Ringing, or with `sdp` a 183 carrying that description of the application's own. */
  ring(sdp?: string | Buffer): void {
    this.stack.ensureOpen();
    const body = sdp === undefined ? null : Buffer.from(sdp);
    checkNow(this.stack.sipral, 'sipral_call_ring', () =>
      this.stack.sipral.sipral_call_ring(this.stack.handle, this.handle, body, body?.length ?? 0, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /**
   * `sipral_call_ring_media`: a 183 whose answer this stack writes against
   * the call's media socket, so the caller hears what the application plays
   * before {@link answer}, which reuses that session.
   */
  ringMedia(options: Pick<CallOptions, 'srtp' | 'codecs'> = {}): void {
    this.stack.ensureOpen();
    const made = config('sipral_call_config_t', { mediaAddress: this.address, srtp: options.srtp, codecs: options.codecs });
    checkNow(this.stack.sipral, 'sipral_call_ring_media', () =>
      this.stack.sipral.sipral_call_ring_media(this.stack.handle, this.handle, made, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /**
   * `sipral_call_set_headers`: header fields on what this call sends at the
   * application's request from now on -- the 180, the 200, a refusal, the
   * BYE -- in place of any set before; empty takes them all off.
   */
  setHeaders(fields: HeaderFields): void {
    const { array, count } = headerArray(fields);
    check(this.stack.sipral, 'sipral_call_set_headers', this.stack.sipral.sipral_call_set_headers(this.stack.handle, this.handle, array, count));
  }

  /**
   * Send `digits` (`0`-`9`, `*`, `#`, `A`-`D`), `via` a `SipralDtmf`
   * value -- RFC 4733 events by default -- each lasting `durationMs`.
   */
  sendDtmf(digits: string, via: number = SipralDtmf.Rtp, durationMs = 100): void {
    this.stack.ensureOpen();
    const [data, length] = text(digits);
    checkNow(this.stack.sipral, 'sipral_call_send_dtmf', () =>
      this.stack.sipral.sipral_call_send_dtmf(this.stack.handle, this.handle, data, length, via, durationMs, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /**
   * `sipral_call_dtmf_detection`: when this call listens for digits in the
   * far end's audio, a `SipralDtmfDetection` value. A digit heard there is
   * an `InBandDigit` and a `digit` event like any other.
   */
  setDtmfDetection(mode: number): void {
    check(this.stack.sipral, 'sipral_call_dtmf_detection', this.stack.sipral.sipral_call_dtmf_detection(this.stack.handle, this.handle, mode));
  }

  /**
   * `sipral_call_detect_progress`: listen for the network's tones, decide
   * who answered and listen for the beep. Call it straight after placing
   * the call; each thing heard is a `ProgressDetected`.
   */
  detectProgress(options: ProgressOptions = {}): void {
    const made = config('sipral_progress_config_t', {
      ...options,
      listen: true,
      answeringMachine: options.answeringMachine ?? true,
      beep: options.beep ?? true,
    });
    check(this.stack.sipral, 'sipral_call_detect_progress', this.stack.sipral.sipral_call_detect_progress(this.stack.handle, this.handle, made));
  }

  /** Stop listening for progress. */
  stopProgress(): void {
    const made = config('sipral_progress_config_t', { listen: false });
    check(this.stack.sipral, 'sipral_call_detect_progress', this.stack.sipral.sipral_call_detect_progress(this.stack.handle, this.handle, made));
  }

  /** `sipral_call_consent_tone`: beep while this call is recorded. */
  setConsentTone(options: ConsentToneOptions = {}): void {
    const made = config('sipral_consent_tone_t', { ...options, enabled: true, local: options.local ?? true });
    check(this.stack.sipral, 'sipral_call_consent_tone', this.stack.sipral.sipral_call_consent_tone(this.stack.handle, this.handle, made));
  }

  /** No consent tone. */
  clearConsentTone(): void {
    const made = config('sipral_consent_tone_t', { enabled: false });
    check(this.stack.sipral, 'sipral_call_consent_tone', this.stack.sipral.sipral_call_consent_tone(this.stack.handle, this.handle, made));
  }

  /** Hang up: a BYE once confirmed, a CANCEL while still ringing out. */
  hangup(): void {
    this.stack.ensureOpen();
    checkNow(this.stack.sipral, 'sipral_call_hangup', () =>
      this.stack.sipral.sipral_call_hangup(this.stack.handle, this.handle, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /**
   * End the call saying why, as a `Reason` (RFC 3326) on the BYE or the
   * CANCEL: `sipCause` a SIP status, `q850Cause` a Q.850 cause (16 is normal
   * clearing), either or both, with `reason` beside them.
   */
  hangupFor(options: { sipCause?: number; q850Cause?: number; reason?: string }): void {
    this.stack.ensureOpen();
    const [said, length] = text(options.reason);
    checkNow(this.stack.sipral, 'sipral_call_hangup_for', () =>
      this.stack.sipral.sipral_call_hangup_for(
        this.stack.handle,
        this.handle,
        options.sipCause ?? 0,
        options.q850Cause ?? 0,
        said,
        length,
        this.stack.nowMs(),
      ),
    );
    this.stack.poll();
  }

  /** Refuse a call nothing answered with `code`: `sipral_call_reject`. */
  reject(code = 486): void {
    this.stack.ensureOpen();
    checkNow(this.stack.sipral, 'sipral_call_reject', () =>
      this.stack.sipral.sipral_call_reject(this.stack.handle, this.handle, code, this.stack.nowMs()),
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

  /** Offer the call again with only `codecs` -- `'PCMU'` -- in that order (`sipral_call_change_codecs`). */
  changeCodecs(codecs: string): void {
    this.stack.ensureOpen();
    const [bytes, length] = text(codecs);
    checkNow(this.stack.sipral, 'sipral_call_change_codecs', () =>
      this.stack.sipral.sipral_call_change_codecs(this.stack.handle, this.handle, bytes, length, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /**
   * Answer a re-offer the far end made (`SessionOffered`) with the
   * application's own description (`sipral_call_accept_session`).
   */
  acceptSession(sdp: string | Buffer): void {
    this.stack.ensureOpen();
    const body = Buffer.from(sdp);
    checkNow(this.stack.sipral, 'sipral_call_accept_session', () =>
      this.stack.sipral.sipral_call_accept_session(this.stack.handle, this.handle, body, body.length, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /** Refuse a re-offer with `code` (488 by default): `sipral_call_reject_session`. */
  rejectSession(code = 488): void {
    this.stack.ensureOpen();
    checkNow(this.stack.sipral, 'sipral_call_reject_session', () =>
      this.stack.sipral.sipral_call_reject_session(this.stack.handle, this.handle, code, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /**
   * `sipral_call_restart_ice`: offer the call again with new ICE credentials
   * (RFC 8445 §9) and check every pair again; the new path arrives as
   * another `MediaPathChosen`.
   */
  restartIce(): void {
    this.stack.ensureOpen();
    checkNow(this.stack.sipral, 'sipral_call_restart_ice', () =>
      this.stack.sipral.sipral_call_restart_ice(this.stack.handle, this.handle, this.stack.nowMs()),
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
      this.stack.sipral.sipral_call_transfer(this.stack.handle, this.handle, data, length, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /**
   * An attended transfer: REFER this call's far end to `other`'s, replacing
   * `other` (`sipral_call_transfer_to`).
   */
  transferTo(other: Call): void {
    this.stack.ensureOpen();
    checkNow(this.stack.sipral, 'sipral_call_transfer_to', () =>
      this.stack.sipral.sipral_call_transfer_to(this.stack.handle, this.handle, other.handle, this.stack.nowMs()),
    );
    this.stack.poll();
  }

  /**
   * Join this call and `other` into a three-way call carried here
   * (`sipral_call_join`): each far end hears the other and this end, mixed
   * every frame on this call's media clock (`sipral_media_mix`) --
   * {@link Media.sendAudio} on this call's media is what both hear, and its
   * `frame` what this end hears of both. Neither far end is told. Both calls
   * need their media running at the same rate and frame length; application
   * mode only, since in device mode the engine carries the frames.
   */
  join(other: Call): void {
    const mine = this.mediaStream;
    const theirs = other.media;
    if (mine === null || theirs === null) {
      throw new Error('sipral: both calls need their media running to be joined');
    }
    if (this.stack.deviceMode) {
      throw new Error("sipral: in device mode the engine carries the calls' frames; use a local conference");
    }
    check(this.stack.sipral, 'sipral_call_join', this.stack.sipral.sipral_call_join(this.stack.handle, this.handle, other.handle));
    this.joined = other;
    other.joined = this;
    mine.drive(theirs);
  }

  /** Take this call out of a three-way call (`sipral_call_leave`): both carry their own frames again. */
  leave(): void {
    check(this.stack.sipral, 'sipral_call_leave', this.stack.sipral.sipral_call_leave(this.stack.handle, this.handle));
    const partner = this.joined;
    this.joined = null;
    this.mediaStream?.stopDriving();
    if (partner !== null) {
      partner.joined = null;
      partner.media?.stopDriving();
    }
  }

  /**
   * Every entry of one identity list this call's INVITE carried -- `which`
   * a `SipralIdentityText` value: the asserted parties, every `Diversion`,
   * every `History-Info` entry, every `Alert-Info` URI.
   */
  identity(which: number): string[] {
    return this.stack.callIdentity(this.handle, which);
  }

  /**
   * Move this call's audio to a new network: what `CallAddressWanted` asks
   * for once {@link Stack.moveTo} changed the stack's address. A media
   * socket is bound at `mediaHost` and the call offered at it, with
   * `publicAddress` in its place when a NAT the application knows sits in
   * front of it; the old socket is closed.
   */
  async readdress(mediaHost: string, options: { mediaPort?: number; publicAddress?: string } = {}): Promise<void> {
    this.stack.ensureOpen();
    const socket = await this.stack.openMediaSocket(mediaHost, options.mediaPort ?? 0);
    const bound = socket.address();
    const address = formatAddress(bound.address, bound.port);
    const [local, localLength] = text(address);
    const [published, publishedLength] = text(options.publicAddress);
    try {
      checkNow(this.stack.sipral, 'sipral_call_media_readdress', () =>
        this.stack.sipral.sipral_call_media_readdress(
          this.stack.handle,
          this.handle,
          local,
          localLength,
          published,
          publishedLength,
          this.stack.nowMs(),
        ),
      );
    } catch (error) {
      this.stack.closeMediaSocket(socket);
      throw error;
    }
    const old = this.mediaStream === null ? this.socket : this.mediaStream.rebind(socket);
    this.socket = socket;
    this.address = address;
    this.stack.closeMediaSocket(old);
    this.stack.poll();
  }

  /**
   * `sipral_media_send_text`: queue text for the far end's real-time text
   * stream (RFC 4103). The call must have been placed or answered with
   * `text: true` and its media started.
   */
  sendText(typed: string): void {
    if (this.mediaStream === null) {
      throw new Error('sipral: the call has no media yet; wait for MediaStarted');
    }
    this.mediaStream.sendText(typed);
  }

  /** `sipral_call_set_focus`: say, or stop saying, that this end is a conference's focus (RFC 4579). */
  setFocus(focus: boolean): void {
    check(this.stack.sipral, 'sipral_call_set_focus', this.stack.sipral.sipral_call_set_focus(this.stack.handle, this.handle, focus ? 1 : 0));
  }

  /** The conference URI the far end named as a focus (`isfocus`), or null when it is not one. */
  conferenceUri(): string | null {
    try {
      return copyText(this.stack.sipral, 'sipral_call_conference_uri', (buffer, capacity, needed) =>
        this.stack.sipral.sipral_call_conference_uri(this.stack.handle, this.handle, buffer, capacity, needed),
      );
    } catch (error) {
      if (error instanceof Error && (error as { status?: number }).status === SipralStatus.NotAFocus) {
        return null;
      }
      throw error;
    }
  }

  /**
   * `sipral_call_subscribe_conference`: watch the conference of this call's
   * focus (RFC 4579 §3.4); `ConferenceChanged` says what it learns and
   * {@link Subscription.conference} reads the picture.
   */
  subscribeConference(): Subscription {
    this.stack.ensureOpen();
    const out = new BigUint64Array(1);
    checkNow(this.stack.sipral, 'sipral_call_subscribe_conference', () =>
      this.stack.sipral.sipral_call_subscribe_conference(this.stack.handle, this.handle, out, this.stack.nowMs()),
    );
    this.stack.poll();
    return new Subscription(this.stack, out[0] ?? 0n, 'conference');
  }

  /**
   * `sipral_call_record_to`: record this call to a recording server (RFC
   * 7866). Two sockets are opened beside the media socket -- this end's
   * copy leaves from one, the far end's from the other -- and a recording
   * session is placed to `server` (its URI), where the account sends or at
   * `destination`. Needs media started; returns the session's handle.
   */
  async recordTo(server: string, options: { destination?: string } = {}): Promise<bigint> {
    const media = this.mediaStream;
    if (media === null) {
      throw new Error('sipral: the call has no media yet; wait for MediaStarted');
    }
    const host = this.address.slice(0, this.address.lastIndexOf(':')).replace(/^\[|\]$/g, '');
    const thisEnd = await this.stack.openMediaSocket(host);
    const farEnd = await this.stack.openMediaSocket(host);
    const name = (socket: Socket): string => formatAddress(socket.address().address, socket.address().port);
    const made = config('sipral_record_config_t', {
      server,
      destination: options.destination,
      thisEnd: name(thisEnd),
      farEnd: name(farEnd),
    });
    const out = new BigUint64Array(1);
    try {
      checkNow(this.stack.sipral, 'sipral_call_record_to', () =>
        this.stack.sipral.sipral_call_record_to(this.stack.handle, this.handle, made, out, this.stack.nowMs()),
      );
    } catch (error) {
      this.stack.closeMediaSocket(thisEnd);
      this.stack.closeMediaSocket(farEnd);
      throw error;
    }
    media.attachRecording(thisEnd, farEnd);
    this.recordingSession = out[0] ?? 0n;
    this.stack.poll();
    return this.recordingSession;
  }

  /** `sipral_call_stop_recording_to`: the copies stop, the session is hung up, its sockets closed. */
  stopRecordingTo(): void {
    checkNow(this.stack.sipral, 'sipral_call_stop_recording_to', () =>
      this.stack.sipral.sipral_call_stop_recording_to(this.stack.handle, this.handle, this.stack.nowMs()),
    );
    this.mediaStream?.detachRecording();
    this.recordingSession = null;
    this.stack.poll();
  }

  /** This call's diagnostic record, as JSON: each decision the stack made about it and why. */
  recordJson(): string {
    return copyText(
      this.stack.sipral,
      'sipral_call_record_json',
      (buffer, capacity, needed) => this.stack.sipral.sipral_call_record_json(this.stack.handle, this.handle, buffer, capacity, needed),
      4096,
    );
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
    if (this.mediaStream !== null) {
      this.mediaStream.close();
      this.mediaStream = null;
    } else {
      this.stack.forgetMediaSocket(this.address);
    }
    this.stack.closeMediaSocket(this.socket);
    if (this.textSocket !== null) {
      this.stack.closeMediaSocket(this.textSocket);
    }
    this.stack.forget(this);
  }

  /** @internal What the stack hands each event about this call to. */
  deliver(event: StackEvent): void {
    switch (event.kind) {
      case SipralEventKind.MediaStarted:
        if (this.mediaStream === null && !this.closed) {
          // from here the socket is the media's to read: the stack stops
          // handing what arrives on it to STUN first
          this.stack.releaseStunSocket(this.address);
          this.mediaStream = new Media(this, this.socket, this.textSocket, this.stack.deviceMode);
          this.emit('media', this.mediaStream);
        }
        break;
      case SipralEventKind.MediaSecured:
        this.suite = (event.fields.suite as number | undefined) ?? null;
        break;
      case SipralEventKind.CallConfirmed:
        if (!this.isConfirmed) {
          this.isConfirmed = true;
          this.emit('confirmed');
        }
        break;
      case SipralEventKind.MediaStatistics:
        this.kept = event.statistics ?? this.kept;
        if (event.statistics !== null) {
          this.mediaStream?.endedWith(event.statistics);
        }
        break;
      case SipralEventKind.DigitReceived:
      case SipralEventKind.InBandDigit:
        if (event.digit !== null) {
          this.emit('digit', event.digit);
        }
        break;
      case SipralEventKind.TextReceived:
        if (typeof event.fields.text === 'string' && event.fields.text.length > 0) {
          this.emit('text', event.fields.text);
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

  /**
   * @internal One packet out of the call's socket, where it says to go --
   * or, marked TCP or TLS, onto the socket's connection to the TURN server.
   * A packet naming no destination goes where the far end's media last
   * came from.
   */
  sendPacket(payload: Buffer | Uint8Array, destination: string, protocol: number = SipralTransport.Udp): void {
    if (this.closed) {
      return;
    }
    if (protocol === SipralTransport.Tcp || protocol === SipralTransport.Tls) {
      this.stack.writeTurn(this.address, payload);
      return;
    }
    const to = parseAddress(destination || (this.mediaStream?.remoteAddress ?? ''));
    if (to !== null) {
      this.socket.send(payload, to.port, to.host);
    }
  }
}
