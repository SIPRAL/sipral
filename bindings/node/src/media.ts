// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// A call's media: the `sipral_call_media` handle, the socket's datagrams
// into it, and a frame clock that plays, captures and sends.

import type { Socket } from 'node:dgram';
import { EventEmitter, on } from 'node:events';

import koffi from 'koffi';

import type { Call } from './call.js';
import { type MediaStatistics, statisticsOf } from './events.js';
import {
  ADDRESS_BYTES,
  PACKET_BYTES,
  check,
  config,
  formatAddress,
  handle,
  plain,
  read,
  record,
  text,
} from './internal.js';
import {
  type Pointer,
  type SipralMediaPacket,
  type SipralProcessorFrame,
  SipralStatus,
  type SipralStreamStats,
  SipralTransport,
  sipral_processor_callback_t,
} from './sipral_abi.js';

/** One packet the library wrote: where it goes and how. */
export interface WrittenPacket {
  readonly payload: Buffer;
  readonly destination: string;
  /** A `SipralTransport` value: UDP a datagram, TCP and TLS bytes for the TURN connection. */
  readonly protocol: number;
}

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
  written(): WrittenPacket | null {
    const filled = read<SipralMediaPacket>(this.packet, 'sipral_media_packet_t');
    const length = Number(filled.len);
    if (length === 0) {
      return null;
    }
    return {
      payload: Buffer.from(this.data.subarray(0, length)),
      destination: this.to.toString('utf8', 0, Number(filled.destination_len)),
      protocol: filled.protocol,
    };
  }
}

/** What `sipral_media_info` says about a call's media now. */
export interface MediaInfo {
  readonly codec: number;
  readonly payloadType: number;
  readonly clockRate: number;
  readonly sampleRate: number;
  readonly frameMs: number;
  readonly frameSamples: number;
  readonly direction: number;
  readonly sending: boolean;
  readonly receiving: boolean;
  readonly hasDtmf: boolean;
  readonly dtmfPayloadType: number;
  readonly rtcp: number;
  readonly secured: boolean;
  readonly recording: boolean;
  readonly recordedMs: number;
  readonly stalled: boolean;
  readonly hasText: boolean;
  readonly feedback: boolean;
  readonly genericNack: boolean;
  readonly reducedSize: boolean;
}

/** How one stream is protected: an entry of the encryption report. */
export interface Protection {
  /** A `SipralMediaKind` value. */
  readonly media: number;
  /** A `SipralKeyExchange` value. */
  readonly keyExchange: number;
  readonly encrypted: boolean;
  /** Set for DTLS-SRTP whose handshake checked the far end's fingerprint; never for SDES. */
  readonly authenticated: boolean;
  /** A `SipralSrtpSuite` value, zero while none runs. */
  readonly suite: number;
  readonly awaitingKeys: boolean;
}

/** One path a call's ICE agent tried, and what became of it. */
export interface PathCandidate {
  readonly priority: number | bigint;
  readonly kind: number;
  readonly outcome: number;
  readonly code: number;
  readonly localKind: number;
  readonly remoteKind: number;
  readonly local: string | null;
  readonly remote: string | null;
}

/** One codec the negotiation weighed, and what became of it. */
export interface CodecCandidate {
  readonly codec: number;
  readonly outcome: number;
  readonly outrankedBy: number;
}

/** How a call is recorded to a file. */
export interface RecordingOptions {
  /** A `SipralRecordingFormat` value: WAV, or Ogg Opus where the build has Opus. */
  format?: number;
  /** A `SipralRecordingLayout` value: one channel, or this end left and the far end right. */
  layout?: number;
  /** The file's rate in hertz; the call's by default. */
  sampleRate?: number;
  /** Ogg Opus's bitrate. */
  bitrate?: number;
  /** How often the file is made to survive a crash, in milliseconds (five seconds by default). */
  checkpointMs?: number;
}

/** One frame a processor attached with {@link Media.attachProcessor} is handed. */
export interface ProcessorFrame {
  /** True to forget what it learnt (a device or codec change): the buffers are then empty. */
  readonly reset: boolean;
  /** The frame just captured, this end's voice. */
  readonly nearEnd: Int16Array;
  /** The far end's audio played over the same span. */
  readonly farEnd: Int16Array;
  /** Where the replacement for `nearEnd` is written, every sample of it. */
  readonly out: Int16Array;
}

/** `count` samples at `address`, as a view valid for the callback only. */
function samplesAt(address: Pointer, count: number | bigint): Int16Array {
  const length = Number(count);
  if (length === 0 || address === null) {
    return new Int16Array(0);
  }
  return new Int16Array(koffi.view(address, length * 2));
}

/**
 * A call's media, from `MediaStarted` on: {@link Call.media}.
 *
 * Every frame, on a schedule rather than a sleep after each: the far end's
 * audio is played out as a `frame` event, one frame of this end's is
 * captured from what {@link sendAudio} queued, or silence, and what RTCP,
 * DTMF, real-time text and a recording server's copies owe goes out. While
 * {@link pumped} -- in device mode, where the library's engine carries the
 * frames, or while the call is in a local conference -- this class carries
 * no frames and still reads the socket and sends the rest.
 */
export class Media extends EventEmitter<{ frame: [Int16Array] }> {
  /** The call it carries. */
  readonly call: Call;
  /** The media handle. */
  readonly handle: bigint;
  /** How long one frame is, in milliseconds. */
  readonly frameMs: number;
  /**
   * Whether somebody else carries this call's frames: the library's engine
   * in device mode, a local conference while the call is in one, or the
   * application calling {@link mix}. {@link sendAudio} is refused while it is.
   */
  pumped: boolean;
  /** Where the far end's media last came from, `host:port`. */
  remoteAddress: string | null = null;

  private rate = 0;
  private samples = 0;
  private playback = new Int16Array(0);
  private capture = new Int16Array(0);
  private socket: Socket;
  private readonly textSocket: Socket | null;
  private recordingSockets: [Socket, Socket] | null = null;
  private readonly packet = new MediaPacket();
  private readonly written = new BigUint64Array(1);
  private readonly source = new Uint32Array(1);
  private readonly arrival = new Uint32Array(1);
  private readonly taken = new Uint32Array(1);
  private readonly farEnd = new Uint32Array(1);
  private processor: bigint | null = null;
  private mixing: Media | null = null;
  private queued: Int16Array[] = [];
  private queuedOffset = 0;
  private clock: NodeJS.Timeout | undefined;
  private due = 0;
  private running = true;
  private ended: MediaStatistics | null = null;
  private readonly onDatagram = (data: Buffer, from: { address: string; port: number }): void =>
    this.receive(data, from);
  private readonly onText = (data: Buffer, from: { address: string; port: number }): void =>
    this.receiveText(data, from);

  /** @internal Built by the call on `MediaStarted`. */
  constructor(call: Call, socket: Socket, textSocket: Socket | null, pumped: boolean) {
    super();
    this.call = call;
    this.socket = socket;
    this.textSocket = textSocket;
    this.pumped = pumped;
    const sipral = call.stack.sipral;
    const out = new BigUint64Array(1);
    check(sipral, 'sipral_call_media', sipral.sipral_call_media(call.stack.handle, call.handle, out));
    this.handle = handle(out[0] ?? 0n);
    const info = this.refreshFrame();
    this.frameMs = Math.max(info.frameMs, 1);
    this.socket.on('message', this.onDatagram);
    this.textSocket?.on('message', this.onText);
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

  /** Where this media's socket is bound, `host:port`. */
  get localAddress(): string {
    const bound = this.socket.address();
    return formatAddress(bound.address, bound.port);
  }

  /**
   * Queue `pcm`, 16-bit mono at {@link sampleRate}, to go out a frame at a
   * time. Refused while {@link pumped}: in device mode the microphone is the
   * call's audio and nothing else is.
   */
  sendAudio(pcm: Int16Array): void {
    if (this.pumped && this.mixing === null) {
      throw new Error("sipral: this call's frames are carried elsewhere (device mode, or a local conference)");
    }
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
    this.refreshFrame();
    this.queued = [];
    this.queuedOffset = 0;
  }

  /** `sipral_media_info`. */
  info(): MediaInfo {
    const sipral = this.call.stack.sipral;
    const memory = record('sipral_media_info_t');
    check(sipral, 'sipral_media_info', sipral.sipral_media_info(this.handle, memory));
    const raw = plain(memory, 'sipral_media_info_t');
    const flag = (name: string): boolean => raw[name] !== 0;
    return {
      codec: raw.codec as number,
      payloadType: raw.payloadType as number,
      clockRate: raw.clockRate as number,
      sampleRate: raw.sampleRate as number,
      frameMs: raw.frameMs as number,
      frameSamples: raw.frameSamples as number,
      direction: raw.direction as number,
      sending: flag('sending'),
      receiving: flag('receiving'),
      hasDtmf: flag('hasDtmf'),
      dtmfPayloadType: raw.dtmfPayloadType as number,
      rtcp: raw.rtcp as number,
      secured: flag('secured'),
      recording: flag('recording'),
      recordedMs: raw.recordedMs as number,
      stalled: flag('stalled'),
      hasText: flag('hasText'),
      feedback: flag('feedback'),
      genericNack: flag('genericNack'),
      reducedSize: flag('reducedSize'),
    };
  }

  /**
   * What the media has done so far. Once the call has ended the library
   * answers with the end-of-call record the call kept.
   */
  statistics(): MediaStatistics {
    const sipral = this.call.stack.sipral;
    const stats = record('sipral_stream_stats_t');
    const status = sipral.sipral_media_statistics(this.handle, this.call.stack.nowMs(), stats);
    const kept = this.ended ?? this.call.finalStatistics;
    if (status === SipralStatus.WrongState && kept !== null) {
      return kept;
    }
    check(sipral, 'sipral_media_statistics', status);
    return statisticsOf(read<SipralStreamStats>(stats, 'sipral_stream_stats_t'));
  }

  /** How each stream of the call is protected now: the encryption report. */
  encryption(): Protection[] {
    const sipral = this.call.stack.sipral;
    const count = new BigUint64Array(1);
    check(sipral, 'sipral_media_encryption_count', sipral.sipral_media_encryption_count(this.handle, count));
    const report: Protection[] = [];
    for (let index = 0; index < Number(count[0]); index++) {
      const out = record('sipral_stream_encryption_t');
      check(sipral, 'sipral_media_encryption_at', sipral.sipral_media_encryption_at(this.handle, index, out));
      const raw = plain(out, 'sipral_stream_encryption_t');
      report.push({
        media: raw.media as number,
        keyExchange: raw.keyExchange as number,
        encrypted: raw.encrypted !== 0,
        authenticated: raw.authenticated !== 0,
        suite: raw.suite as number,
        awaitingKeys: raw.awaitingKeys !== 0,
      });
    }
    return report;
  }

  /** Every path the call's ICE agent tried and what became of it; empty without ICE. */
  pathCandidates(): PathCandidate[] {
    const sipral = this.call.stack.sipral;
    const count = new BigUint64Array(1);
    check(sipral, 'sipral_media_path_candidate_count', sipral.sipral_media_path_candidate_count(this.handle, count));
    const paths: PathCandidate[] = [];
    for (let index = 0; index < Number(count[0]); index++) {
      const local = Buffer.alloc(ADDRESS_BYTES);
      const remote = Buffer.alloc(ADDRESS_BYTES);
      const out = record('sipral_path_candidate_t', {
        local,
        local_capacity: local.length,
        remote,
        remote_capacity: remote.length,
      });
      check(sipral, 'sipral_media_path_candidate_at', sipral.sipral_media_path_candidate_at(this.handle, index, out));
      const raw = plain(out, 'sipral_path_candidate_t');
      paths.push({
        priority: raw.priority as number | bigint,
        kind: raw.kind as number,
        outcome: raw.outcome as number,
        code: raw.code as number,
        localKind: raw.localKind as number,
        remoteKind: raw.remoteKind as number,
        local: raw.local as string | null,
        remote: raw.remote as string | null,
      });
    }
    return paths;
  }

  /** Every codec the negotiation weighed, and why the one chosen won. */
  codecCandidates(): CodecCandidate[] {
    const sipral = this.call.stack.sipral;
    const count = new BigUint64Array(1);
    check(sipral, 'sipral_media_codec_candidate_count', sipral.sipral_media_codec_candidate_count(this.handle, count));
    const found: CodecCandidate[] = [];
    for (let index = 0; index < Number(count[0]); index++) {
      const out = record('sipral_codec_candidate_t');
      check(sipral, 'sipral_media_codec_candidate_at', sipral.sipral_media_codec_candidate_at(this.handle, index, out));
      const raw = plain(out, 'sipral_codec_candidate_t');
      found.push({ codec: raw.codec as number, outcome: raw.outcome as number, outrankedBy: raw.outrankedBy as number });
    }
    return found;
  }

  /**
   * Record both directions to `path` (`sipral_media_record_start`, or
   * `sipral_media_record_start_with` given `options`). The file is finished
   * by {@link stopRecording}, by the call ending, or by the stack closing.
   */
  record(path: string, options?: RecordingOptions): void {
    const sipral = this.call.stack.sipral;
    const bytes = Buffer.from(path, 'utf8');
    if (options === undefined) {
      check(sipral, 'sipral_media_record_start', sipral.sipral_media_record_start(this.handle, bytes, bytes.length));
      return;
    }
    const made = config('sipral_recording_options_t', options);
    check(
      sipral,
      'sipral_media_record_start_with',
      sipral.sipral_media_record_start_with(this.handle, bytes, bytes.length, made),
    );
  }

  /** `sipral_media_record_stop`: stop, and finish the file. */
  stopRecording(): void {
    const sipral = this.call.stack.sipral;
    check(sipral, 'sipral_media_record_stop', sipral.sipral_media_record_stop(this.handle));
  }

  /** Whether a recording runs, and how many milliseconds of audio it has taken. */
  recording(): { recording: boolean; recordedMs: number } {
    const sipral = this.call.stack.sipral;
    const running = new Uint32Array(1);
    const taken = new BigUint64Array(1);
    check(sipral, 'sipral_media_record_state', sipral.sipral_media_record_state(this.handle, running, taken));
    return { recording: running[0] !== 0, recordedMs: Number(taken[0]) };
  }

  /**
   * `sipral_media_send_text`: queue text for the far end's real-time text
   * stream (RFC 4103). `SipralStatus.NotNegotiated` on a call that agreed
   * none.
   */
  sendText(typed: string): void {
    const sipral = this.call.stack.sipral;
    const [bytes, length] = text(typed);
    check(sipral, 'sipral_media_send_text', sipral.sipral_media_send_text(this.handle, bytes, length));
  }

  /**
   * Whether digits queued for the far end are still being sent
   * (`sipral_media_dialling`), and how many wait.
   */
  dialling(): { dialling: boolean; waiting: number } {
    const sipral = this.call.stack.sipral;
    const dialling = new Uint32Array(1);
    const waiting = new BigUint64Array(1);
    check(sipral, 'sipral_media_dialling', sipral.sipral_media_dialling(this.handle, dialling, waiting));
    return { dialling: dialling[0] !== 0, waiting: Number(waiting[0]) };
  }

  /** `sipral_media_stop_dialling`: drop the digits not yet sent. */
  stopDialling(): void {
    const sipral = this.call.stack.sipral;
    check(sipral, 'sipral_media_stop_dialling', sipral.sipral_media_stop_dialling(this.handle));
  }

  /**
   * Run `process` on every frame this end captures, with the far end's
   * audio over the same span, to write its replacement: an echo canceller,
   * a noise suppressor, a voice changer (`sipral_media_attach_processor`).
   * It runs inside the frame, so it must not call back into this media.
   * Application mode only: in device mode the frame is the engine's thread,
   * and a processor there would wait on this one.
   */
  attachProcessor(process: (frame: ProcessorFrame) => void): void {
    if (this.call.stack.deviceMode) {
      throw new Error("sipral: a processor runs on the frame's own thread, which in device mode is the engine's");
    }
    this.detachProcessor();
    const callback = koffi.register((address: Pointer) => {
      const frame = read<SipralProcessorFrame>(address, 'sipral_processor_frame_t');
      try {
        process({
          reset: frame.reset !== 0,
          nearEnd: samplesAt(frame.near_end, frame.near_end_len),
          farEnd: samplesAt(frame.far_end, frame.far_end_len),
          out: samplesAt(frame.out, frame.out_len),
        });
      } catch (error) {
        queueMicrotask(() => this.call.stack.report(error));
      }
    }, koffi.pointer(sipral_processor_callback_t));
    const sipral = this.call.stack.sipral;
    try {
      check(sipral, 'sipral_media_attach_processor', sipral.sipral_media_attach_processor(this.handle, callback, null));
    } catch (error) {
      koffi.unregister(callback);
      throw error;
    }
    this.processor = callback;
  }

  /** Take the processor away; whether there was one. */
  detachProcessor(): boolean {
    const sipral = this.call.stack.sipral;
    const was = new Uint32Array(1);
    check(sipral, 'sipral_media_detach_processor', sipral.sipral_media_detach_processor(this.handle, was));
    if (this.processor !== null) {
      koffi.unregister(this.processor);
      this.processor = null;
    }
    return was[0] !== 0;
  }

  /** Have the processor forget what it learnt, at the next frame; whether there is one. */
  resetProcessor(): boolean {
    const sipral = this.call.stack.sipral;
    const was = new Uint32Array(1);
    check(sipral, 'sipral_media_reset_processor', sipral.sipral_media_reset_processor(this.handle, was));
    return was[0] !== 0;
  }

  /**
   * One frame of a three-way call carried here (`sipral_media_mix`): `mic`
   * goes to both this call and `other`, each far end hears the other too,
   * and what this end hears of both comes back. {@link Call.join} runs it
   * every frame by itself; called by hand, both calls must be
   * {@link pumped} meanwhile, so that neither carries its own frames.
   */
  mix(other: Media, mic: Int16Array): Int16Array {
    const sipral = this.call.stack.sipral;
    const heard = new Int16Array(this.samples);
    const theirs = new MediaPacket();
    this.packet.prepare();
    theirs.prepare();
    check(
      sipral,
      'sipral_media_mix',
      sipral.sipral_media_mix(
        this.handle,
        other.handle,
        this.call.stack.nowMs(),
        mic,
        mic.length,
        heard,
        heard.length,
        this.packet.packet,
        theirs.packet,
      ),
    );
    this.send();
    const out = theirs.written();
    if (out !== null) {
      other.call.sendPacket(out.payload, out.destination, out.protocol);
    }
    return heard;
  }

  /**
   * @internal Carry a three-way call with `other` on this media's frame
   * clock: what {@link sendAudio} queued goes to both far ends, and `frame`
   * is what this end hears of both. `other` carries no frames meanwhile.
   */
  drive(other: Media): void {
    this.mixing = other;
    other.pumped = true;
  }

  /** @internal Stop carrying the three-way call; both carry their own frames again. */
  stopDriving(): void {
    if (this.mixing !== null) {
      this.mixing.pumped = this.call.stack.deviceMode;
      this.mixing = null;
    }
  }

  /** @internal Copies for a recording server leave from these two sockets from now on. */
  attachRecording(thisEnd: Socket, farEnd: Socket): void {
    const ignore = (): void => undefined;
    thisEnd.on('message', ignore);
    farEnd.on('message', ignore);
    this.recordingSockets = [thisEnd, farEnd];
  }

  /** @internal The recording stopped: its two sockets close. */
  detachRecording(): void {
    const taken = this.recordingSockets;
    this.recordingSockets = null;
    if (taken !== null) {
      for (const socket of taken) {
        this.call.stack.closeMediaSocket(socket);
      }
    }
  }

  /** @internal The end-of-call record arrived: what {@link statistics} answers once the stream is gone. */
  endedWith(statistics: MediaStatistics): void {
    this.ended = statistics;
  }

  /** @internal Carry the media on `socket` from now on; the old one is the caller's to close. */
  rebind(socket: Socket): Socket {
    const old = this.socket;
    old.off('message', this.onDatagram);
    this.socket = socket;
    socket.on('message', this.onDatagram);
    return old;
  }

  /** @internal Stop the clock and let the library release the stream. */
  close(): void {
    if (!this.running) {
      return;
    }
    this.running = false;
    clearTimeout(this.clock);
    this.stopDriving();
    this.socket.off('message', this.onDatagram);
    this.textSocket?.off('message', this.onText);
    if (this.processor !== null) {
      this.call.stack.sipral.sipral_media_detach_processor(this.handle, new Uint32Array(1));
      koffi.unregister(this.processor);
      this.processor = null;
    }
    this.call.stack.sipral.sipral_media_release(this.handle);
    this.detachRecording();
    this.removeAllListeners();
  }

  /** The frame's shape, read again after the rate changed. */
  private refreshFrame(): MediaInfo {
    const info = this.info();
    this.rate = info.sampleRate;
    this.samples = info.frameSamples;
    this.playback = new Int16Array(this.samples);
    this.capture = new Int16Array(this.samples);
    return info;
  }

  private receive(data: Buffer, from: { address: string; port: number }): void {
    if (!this.running) {
      return;
    }
    this.remoteAddress = formatAddress(from.address, from.port);
    const [source, length] = text(this.remoteAddress);
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

  private receiveText(data: Buffer, from: { address: string; port: number }): void {
    if (!this.running) {
      return;
    }
    const [source, length] = text(formatAddress(from.address, from.port));
    this.call.stack.sipral.sipral_media_receive_text(
      this.handle,
      data,
      data.length,
      source,
      length,
      this.call.stack.nowMs(),
      this.taken,
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
    if (this.mixing !== null) {
      this.fillCapture();
      const heard = this.mix(this.mixing, this.capture);
      if (heard.length > 0) {
        this.emit('frame', heard);
      }
    } else if (!this.pumped) {
      const played = sipral.sipral_media_playback(this.handle, this.playback, this.samples, this.written, this.source);
      const count = Number(this.written[0] ?? 0n);
      if (played === SipralStatus.Ok && count > 0) {
        this.emit('frame', this.playback.slice(0, count));
      }
      this.fillCapture();
      this.packet.prepare();
      if (sipral.sipral_media_capture(this.handle, now, this.capture, this.samples, this.packet.packet) === SipralStatus.Ok) {
        this.send();
      }
    }
    this.drain((packet) => sipral.sipral_media_poll_rtcp(this.handle, now, packet));
    this.drain((packet) => sipral.sipral_media_poll_transmit(this.handle, now, packet));
    if (this.textSocket !== null) {
      this.drain((packet) => sipral.sipral_media_poll_text(this.handle, now, packet), this.textSocket);
    }
    this.carryRecording();
  }

  /** Every copy `sipral_media_poll_recording` has waiting, each from the socket it names. */
  private carryRecording(): void {
    const sockets = this.recordingSockets;
    if (sockets === null) {
      return;
    }
    const sipral = this.call.stack.sipral;
    for (;;) {
      this.packet.prepare();
      if (sipral.sipral_media_poll_recording(this.handle, this.packet.packet, this.farEnd) !== SipralStatus.Ok) {
        return;
      }
      if (!this.send(this.farEnd[0] !== 0 ? sockets[1] : sockets[0])) {
        return;
      }
    }
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

  private drain(poll: (packet: Buffer) => number, from?: Socket): void {
    while (this.running) {
      this.packet.prepare();
      if (poll(this.packet.packet) !== SipralStatus.Ok || !this.send(from)) {
        return;
      }
    }
  }

  /** Send what the packet holds, from `from` or the call's own socket; whether it held anything. */
  private send(from?: Socket): boolean {
    const out = this.packet.written();
    if (out === null) {
      return false;
    }
    if (from === undefined) {
      this.call.sendPacket(out.payload, out.destination, out.protocol);
      return true;
    }
    const to = out.destination.lastIndexOf(':');
    const port = Number(out.destination.slice(to + 1));
    const host = out.destination.slice(0, to).replace(/^\[|\]$/g, '');
    if (to > 0 && out.protocol !== SipralTransport.Tcp && out.protocol !== SipralTransport.Tls) {
      from.send(out.payload, port, host);
    }
    return true;
  }
}
