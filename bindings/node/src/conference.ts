// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// A local conference: any number of this stack's calls, mixed here.

import { EventEmitter, on } from 'node:events';

import type { Call } from './call.js';
import { check, config, plain, record } from './internal.js';
import { MediaPacket } from './media.js';
import { SipralStatus } from './sipral_abi.js';
import type { Stack } from './stack.js';

/** How often an application-mode conference mixes, in milliseconds. */
const TICK_MS = 20;

/** How a local conference is made. */
export interface LocalConferenceOptions {
  /** The most members it holds, this end counted (16 by default, at most 1024). */
  maxMembers?: number;
  /** Whether this end takes part: it speaks with {@link LocalConference.sendAudio} and hears `frame`. On by default. */
  local?: boolean;
  /** The rate of this end's frames, 8000, 16000, 32000 or 48000 hertz (16000 by default). */
  sampleRate?: number;
}

/** What `sipral_local_conference_info` says. */
export interface LocalConferenceInfo {
  readonly members: number;
  readonly capacity: number;
  readonly talkers: number;
  readonly local: boolean;
  readonly sampleRate: number;
  readonly frameSamples: number;
  readonly recording: boolean;
  readonly recordedMs: number;
  readonly packetsDropped: number;
}

/** One member: a call's handle, or the conference's own for this end. */
export interface LocalConferenceMember {
  readonly member: bigint;
  readonly talking: boolean;
  readonly mutedInput: boolean;
  readonly mutedOutput: boolean;
  readonly gainInput: number;
  readonly gainOutput: number;
}

/** How a recording of the mix is written. */
export interface ConferenceRecordingOptions {
  /** A `SipralRecordingFormat` value; WAV by default. */
  format?: number;
  /** The file's rate in hertz; the conference's by default. */
  sampleRate?: number;
}

/**
 * Any number of this stack's calls, mixed here (`docs/08-ffi.md`, "A local
 * conference"): every member hears everybody but itself, each call on its
 * own codec and rate, and this end is a member too unless it was made
 * without. A call added stops carrying its own frames and the conference
 * carries them: in device mode the library's engine does it, and in
 * application mode this class ticks every twenty milliseconds --
 * {@link sendAudio} is this end's microphone and `frame` what it hears.
 * `LocalConferenceChanged` arrives on the stack's events.
 */
export class LocalConference extends EventEmitter<{ frame: [Int16Array] }> {
  /** The stack it belongs to. */
  readonly stack: Stack;
  /** The conference's handle, which is also this end's name as a member. */
  readonly handle: bigint;
  /** Whether this end takes part. */
  readonly local: boolean;
  /** The rate of this end's frames. */
  readonly sampleRate: number;
  /** How many samples one of this end's frames is. */
  readonly frameSamples: number;

  private readonly members = new Map<bigint, Call>();
  private readonly mic: Int16Array;
  private readonly speaker: Int16Array;
  private readonly written = new BigUint64Array(1);
  private readonly packet = new MediaPacket();
  private readonly packetCall = new BigUint64Array(1);
  private queued: Int16Array[] = [];
  private queuedOffset = 0;
  private clock: NodeJS.Timeout | undefined;
  private due = 0;
  private closed = false;

  /** @internal Made by {@link Stack.createConference}. */
  constructor(stack: Stack, options: LocalConferenceOptions = {}) {
    super();
    this.stack = stack;
    const sipral = stack.sipral;
    const made = config('sipral_local_conference_config_t', {
      maxMembers: options.maxMembers ?? 16,
      sampleRate: options.sampleRate ?? 16000,
      local: options.local === false ? false : undefined,
    });
    const out = new BigUint64Array(1);
    check(sipral, 'sipral_local_conference_create', sipral.sipral_local_conference_create(stack.handle, made, out));
    this.handle = out[0] ?? 0n;
    const info = this.info();
    this.local = info.local;
    this.sampleRate = info.sampleRate;
    this.frameSamples = info.frameSamples;
    this.mic = new Int16Array(this.frameSamples);
    this.speaker = new Int16Array(this.frameSamples);
    if (!stack.deviceMode) {
      this.due = stack.nowMs();
      this.schedule();
    }
  }

  /**
   * `sipral_local_conference_add`: `call` takes part from the next tick. A
   * full conference, a call already in one, or a codec it cannot mix is
   * `SipralStatus.ConferenceRefused`.
   */
  add(call: Call): void {
    const media = call.media;
    const was = media?.pumped ?? false;
    if (media !== null) {
      media.pumped = true;
    }
    try {
      const sipral = this.stack.sipral;
      check(sipral, 'sipral_local_conference_add', sipral.sipral_local_conference_add(this.handle, call.handle));
    } catch (error) {
      if (media !== null) {
        media.pumped = was;
      }
      throw error;
    }
    this.members.set(call.handle, call);
  }

  /** `sipral_local_conference_remove`: `call` carries its own frames again. */
  remove(call: Call): void {
    const sipral = this.stack.sipral;
    check(sipral, 'sipral_local_conference_remove', sipral.sipral_local_conference_remove(this.handle, call.handle));
    this.members.delete(call.handle);
    if (call.media !== null) {
      call.media.pumped = this.stack.deviceMode;
    }
  }

  /**
   * Mute or unmute one way of a member -- null for this end: `Input` is what
   * it says, `Output` what it hears (`SipralAudioDirection`).
   */
  setMuted(member: Call | null, direction: number, muted = true): void {
    const sipral = this.stack.sipral;
    check(
      sipral,
      'sipral_local_conference_set_muted',
      sipral.sipral_local_conference_set_muted(this.handle, member?.handle ?? this.handle, direction, muted ? 1 : 0),
    );
  }

  /** The level of one way of a member, in the engine's steps: 256 is unity. */
  setGain(member: Call | null, direction: number, gain: number): void {
    const sipral = this.stack.sipral;
    check(
      sipral,
      'sipral_local_conference_set_gain',
      sipral.sipral_local_conference_set_gain(this.handle, member?.handle ?? this.handle, direction, gain),
    );
  }

  /** `sipral_local_conference_info`. */
  info(): LocalConferenceInfo {
    const out = record('sipral_local_conference_info_t');
    const sipral = this.stack.sipral;
    check(sipral, 'sipral_local_conference_info', sipral.sipral_local_conference_info(this.handle, out));
    const read = plain(out, 'sipral_local_conference_info_t');
    return {
      members: read.members as number,
      capacity: read.capacity as number,
      talkers: read.talkers as number,
      local: read.local !== 0,
      sampleRate: read.sampleRate as number,
      frameSamples: read.frameSamples as number,
      recording: read.recording !== 0,
      recordedMs: read.recordedMs as number,
      packetsDropped: read.packetsDropped as number,
    };
  }

  /** Every member, this end first. */
  memberList(): LocalConferenceMember[] {
    const sipral = this.stack.sipral;
    const found: LocalConferenceMember[] = [];
    for (let index = 0; index < this.info().members; index++) {
      const out = record('sipral_local_conference_member_t');
      check(sipral, 'sipral_local_conference_member_at', sipral.sipral_local_conference_member_at(this.handle, index, out));
      const read = plain(out, 'sipral_local_conference_member_t');
      found.push({
        member: read.member as bigint,
        talking: read.talking !== 0,
        mutedInput: read.mutedInput !== 0,
        mutedOutput: read.mutedOutput !== 0,
        gainInput: read.gainInput as number,
        gainOutput: read.gainOutput as number,
      });
    }
    return found;
  }

  /** Who was talking in the last tick, loudest first, by handle. */
  talkers(): bigint[] {
    const sipral = this.stack.sipral;
    const found: bigint[] = [];
    const out = new BigUint64Array(1);
    for (let index = 0; index < this.info().talkers; index++) {
      if (sipral.sipral_local_conference_talker_at(this.handle, index, out) !== SipralStatus.Ok) {
        break;
      }
      found.push(out[0] ?? 0n);
    }
    return found;
  }

  /** `sipral_local_conference_record_start`: the whole mix, one channel, to `path`. */
  record(path: string, options: ConferenceRecordingOptions = {}): void {
    const sipral = this.stack.sipral;
    const bytes = Buffer.from(path, 'utf8');
    const made = config('sipral_recording_options_t', options);
    check(
      sipral,
      'sipral_local_conference_record_start',
      sipral.sipral_local_conference_record_start(this.handle, bytes, bytes.length, made),
    );
  }

  /** `sipral_local_conference_record_stop`: stop, and finish the file. */
  stopRecording(): void {
    const sipral = this.stack.sipral;
    check(sipral, 'sipral_local_conference_record_stop', sipral.sipral_local_conference_record_stop(this.handle));
  }

  /** What this end says, 16-bit mono PCM at {@link sampleRate}, in any length. */
  sendAudio(pcm: Int16Array): void {
    if (pcm.length > 0) {
      this.queued.push(Int16Array.from(pcm));
    }
  }

  /** What this end hears, one frame at a time, as an async iterator. */
  frames(options: { signal?: AbortSignal } = {}): AsyncIterableIterator<Int16Array> {
    const iterator = on(this, 'frame', options) as AsyncIterableIterator<[Int16Array]>;
    return (async function* () {
      for await (const [frame] of iterator) {
        yield frame;
      }
    })();
  }

  /**
   * `sipral_local_conference_destroy`: every call still in it carries its
   * own frames again, a recording running is finished, and the handle is
   * spent.
   */
  close(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    clearTimeout(this.clock);
    for (const call of this.members.values()) {
      if (call.media !== null) {
        call.media.pumped = this.stack.deviceMode;
      }
    }
    this.members.clear();
    const sipral = this.stack.sipral;
    check(sipral, 'sipral_local_conference_destroy', sipral.sipral_local_conference_destroy(this.handle));
    this.removeAllListeners();
  }

  private schedule(): void {
    this.due += TICK_MS;
    let wait = this.due - this.stack.nowMs();
    if (wait < 0) {
      this.due = this.stack.nowMs();
      wait = 0;
    }
    this.clock = setTimeout(() => {
      if (this.closed) {
        return;
      }
      try {
        this.tick();
      } catch (error) {
        this.stack.report(error);
      }
      if (!this.closed) {
        this.schedule();
      }
    }, wait);
  }

  private tick(): void {
    const sipral = this.stack.sipral;
    this.mic.fill(0);
    let filled = 0;
    while (filled < this.frameSamples && this.queued.length > 0) {
      const head = this.queued[0] as Int16Array;
      const take = Math.min(this.frameSamples - filled, head.length - this.queuedOffset);
      this.mic.set(head.subarray(this.queuedOffset, this.queuedOffset + take), filled);
      filled += take;
      this.queuedOffset += take;
      if (this.queuedOffset >= head.length) {
        this.queued.shift();
        this.queuedOffset = 0;
      }
    }
    const status = sipral.sipral_local_conference_tick(
      this.handle,
      this.stack.nowMs(),
      this.mic,
      this.frameSamples,
      this.speaker,
      this.frameSamples,
      this.written,
    );
    if (status !== SipralStatus.Ok) {
      return;
    }
    const heard = Number(this.written[0] ?? 0n);
    if (this.local && heard > 0) {
      this.emit('frame', this.speaker.slice(0, heard));
    }
    for (;;) {
      this.packet.prepare();
      if (sipral.sipral_local_conference_poll_transmit(this.handle, this.packetCall, this.packet.packet) !== SipralStatus.Ok) {
        return;
      }
      const out = this.packet.written();
      if (out === null) {
        return;
      }
      const owner = this.packetCall[0] ?? 0n;
      (this.members.get(owner) ?? this.stack.callFor(owner))?.sendPacket(out.payload, out.destination, out.protocol);
    }
  }
}
