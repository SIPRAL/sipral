// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// A call's media: the `sipral_call_media` handle, the socket's datagrams
// into it, and a frame clock that plays, captures and sends.

import type { Socket } from 'node:dgram';
import { EventEmitter, on } from 'node:events';

import type { Call } from './call.js';
import { type MediaStatistics, statisticsOf } from './events.js';
import {
  ADDRESS_BYTES,
  PACKET_BYTES,
  check,
  formatAddress,
  handle,
  read,
  record,
  text,
} from './internal.js';
import {
  type SipralMediaInfo,
  type SipralMediaPacket,
  SipralStatus,
  type SipralStreamStats,
} from './sipral_abi.js';

/** One `sipral_media_packet_t` with room of its own, filled again and again. */
export class MediaPacket {
  private readonly data = Buffer.alloc(PACKET_BYTES);
  private readonly to = Buffer.alloc(ADDRESS_BYTES);
  /** The record handed to the library. */
  readonly packet = record('sipral_media_packet_t');

  /** Hand the room over again, empty. */
  prepare(): Buffer {
    this.packet.set(
      record('sipral_media_packet_t', {
        data: this.data,
        capacity: this.data.length,
        destination: this.to,
        destination_capacity: this.to.length,
      }),
    );
    return this.packet;
  }

  /** The datagram the library wrote and where it goes, or null for none. */
  written(): { payload: Buffer; destination: string } | null {
    const filled = read<SipralMediaPacket>(this.packet, 'sipral_media_packet_t');
    const length = Number(filled.len);
    if (length === 0) {
      return null;
    }
    return {
      payload: Buffer.from(this.data.subarray(0, length)),
      destination: this.to.toString('utf8', 0, Number(filled.destination_len)),
    };
  }
}

/**
 * A call's media, from `MediaStarted` on: {@link Call.media}.
 *
 * Every frame, on a schedule rather than a sleep after each: the far end's
 * audio is played out as a `frame` event, one frame of this end's is
 * captured from what {@link sendAudio} queued, or silence, and what RTCP and
 * DTMF owe goes out.
 */
export class Media extends EventEmitter<{ frame: [Int16Array] }> {
  /** The call it carries. */
  readonly call: Call;
  /** The media handle. */
  readonly handle: bigint;
  /** How long one frame is, in milliseconds. */
  readonly frameMs: number;

  private rate = 0;
  private samples = 0;
  private playback = new Int16Array(0);
  private capture = new Int16Array(0);
  private readonly socket: Socket;
  private readonly packet = new MediaPacket();
  private readonly written = new BigUint64Array(1);
  private readonly source = new Uint32Array(1);
  private readonly arrival = new Uint32Array(1);
  private queued: Int16Array[] = [];
  private queuedOffset = 0;
  private clock: NodeJS.Timeout | undefined;
  private due = 0;
  private running = true;
  private readonly onDatagram = (data: Buffer, from: { address: string; port: number }) =>
    this.receive(data, from);

  /** @internal Built by the call on `MediaStarted`. */
  constructor(call: Call, socket: Socket) {
    super();
    this.call = call;
    this.socket = socket;
    const sipral = call.stack.sipral;
    const out = new BigUint64Array(1);
    check(sipral, 'sipral_call_media', sipral.sipral_call_media(call.stack.handle, call.handle, out));
    this.handle = handle(out[0] ?? 0n);
    const info = this.info();
    this.frameMs = Math.max(info.frame_ms, 1);
    this.socket.on('message', this.onDatagram);
    this.due = call.stack.nowMs();
    this.schedule();
  }

  /** The rate of the PCM in `frame` and {@link sendAudio}, in hertz. */
  get sampleRate(): number {
    return this.rate;
  }

  /** How many samples one frame is, at {@link sampleRate}. */
  get frameSamples(): number {
    return this.samples;
  }

  /** Queue `pcm`, 16-bit mono at {@link sampleRate}, to go out a frame at a time. */
  sendAudio(pcm: Int16Array): void {
    if (pcm.length > 0) {
      this.queued.push(Int16Array.from(pcm));
    }
  }

  /** The far end's audio, one frame at a time, as an async iterator. */
  frames(options: { signal?: AbortSignal } = {}): AsyncIterableIterator<Int16Array> {
    const iterator = on(this, 'frame', options) as AsyncIterableIterator<[Int16Array]>;
    return (async function* () {
      for await (const [frame] of iterator) {
        yield frame;
      }
    })();
  }

  /**
   * `sipral_media_set_app_rate`: the rate `frame` hands out and
   * {@link sendAudio} takes -- 8000, 16000, 24000 or 48000, or 0 for the
   * codec's own. Audio queued and not yet sent was at the old rate, and is
   * dropped.
   */
  setAppRate(hz: number): void {
    const sipral = this.call.stack.sipral;
    check(sipral, 'sipral_media_set_app_rate', sipral.sipral_media_set_app_rate(this.handle, hz));
    this.info();
    this.queued = [];
    this.queuedOffset = 0;
  }

  /**
   * What the media has done so far. Once the call has ended the library
   * answers with the end-of-call record the call kept.
   */
  statistics(): MediaStatistics {
    const sipral = this.call.stack.sipral;
    const stats = record('sipral_stream_stats_t');
    const status = sipral.sipral_media_statistics(this.handle, this.call.stack.nowMs(), stats);
    const kept = this.call.finalStatistics;
    if (status === SipralStatus.WrongState && kept !== null) {
      return kept;
    }
    check(sipral, 'sipral_media_statistics', status);
    return statisticsOf(read<SipralStreamStats>(stats, 'sipral_stream_stats_t'));
  }

  /** @internal Stop the clock and let the library release the stream. */
  close(): void {
    if (!this.running) {
      return;
    }
    this.running = false;
    clearTimeout(this.clock);
    this.socket.off('message', this.onDatagram);
    this.call.stack.sipral.sipral_media_release(this.handle);
    this.removeAllListeners();
  }

  private info(): SipralMediaInfo {
    const sipral = this.call.stack.sipral;
    const memory = record('sipral_media_info_t');
    check(sipral, 'sipral_media_info', sipral.sipral_media_info(this.handle, memory));
    const info = read<SipralMediaInfo>(memory, 'sipral_media_info_t');
    this.rate = info.sample_rate;
    this.samples = Number(info.frame_samples);
    this.playback = new Int16Array(this.samples);
    this.capture = new Int16Array(this.samples);
    return info;
  }

  private receive(data: Buffer, from: { address: string; port: number }): void {
    if (!this.running) {
      return;
    }
    const [source, length] = text(formatAddress(from.address, from.port));
    this.call.stack.sipral.sipral_media_receive(
      this.handle,
      data,
      data.length,
      source,
      length,
      this.call.stack.nowMs(),
      this.arrival,
    );
  }

  private schedule(): void {
    this.due += this.frameMs;
    let wait = this.due - this.call.stack.nowMs();
    if (wait < 0) {
      // a clock that has fallen a whole frame behind starts again from now
      // rather than bursting to catch up
      this.due = this.call.stack.nowMs();
      wait = 0;
    }
    this.clock = setTimeout(() => this.tick(), wait);
  }

  private tick(): void {
    if (!this.running) {
      return;
    }
    try {
      this.frame();
    } catch (error) {
      this.call.stack.report(error);
    }
    if (this.running) {
      this.schedule();
    }
  }

  private frame(): void {
    const sipral = this.call.stack.sipral;
    const now = this.call.stack.nowMs();
    const played = sipral.sipral_media_playback(
      this.handle,
      this.playback,
      this.samples,
      this.written,
      this.source,
    );
    const count = Number(this.written[0] ?? 0n);
    if (played === SipralStatus.Ok && count > 0) {
      this.emit('frame', this.playback.slice(0, count));
    }
    this.fillCapture();
    this.packet.prepare();
    if (
      sipral.sipral_media_capture(this.handle, now, this.capture, this.samples, this.packet.packet) ===
      SipralStatus.Ok
    ) {
      this.send();
    }
    this.drain((packet) => sipral.sipral_media_poll_rtcp(this.handle, now, packet));
    this.drain((packet) => sipral.sipral_media_poll_transmit(this.handle, now, packet));
  }

  /** One frame of what {@link sendAudio} queued, silence after it. */
  private fillCapture(): void {
    this.capture.fill(0);
    let filled = 0;
    while (filled < this.samples && this.queued.length > 0) {
      const head = this.queued[0] as Int16Array;
      const take = Math.min(this.samples - filled, head.length - this.queuedOffset);
      this.capture.set(head.subarray(this.queuedOffset, this.queuedOffset + take), filled);
      filled += take;
      this.queuedOffset += take;
      if (this.queuedOffset >= head.length) {
        this.queued.shift();
        this.queuedOffset = 0;
      }
    }
  }

  private drain(poll: (packet: Buffer) => number): void {
    while (this.running) {
      this.packet.prepare();
      if (poll(this.packet.packet) !== SipralStatus.Ok || !this.send()) {
        return;
      }
    }
  }

  /** Send what the packet holds; whether it held anything. */
  private send(): boolean {
    const out = this.packet.written();
    if (out === null) {
      return false;
    }
    this.call.sendPacket(out.payload, out.destination);
    return true;
  }
}
