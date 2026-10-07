// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// One event, copied out of the `sipral_event_t` the callback was handed,
// which is the library's only for the length of the callback.

import koffi from 'koffi';

import { handle, isNull, read, readBytes, readText } from './internal.js';
import {
  type Pointer,
  type SipralCallEvent,
  type SipralEvent,
  SipralEventKind,
  type SipralMediaEvent,
  type SipralReferralEvent,
  type SipralRegistrationEvent,
  type SipralStreamStats,
  type SipralTransferEvent,
} from './sipral_abi.js';

/** The kinds whose payload is `sipral_call_event_t`. */
const CALL_ARM: ReadonlySet<number> = new Set([
  SipralEventKind.Started,
  SipralEventKind.IncomingCall,
  SipralEventKind.CallProgress,
  SipralEventKind.CallForked,
  SipralEventKind.CallConfirmed,
  SipralEventKind.SessionChanged,
  SipralEventKind.SessionOffered,
  SipralEventKind.SessionChangeFailed,
  SipralEventKind.CallReplaced,
  SipralEventKind.CallEnded,
  SipralEventKind.DtmfSent,
]);

/** The kinds whose payload is `sipral_transfer_event_t`. */
const TRANSFER_ARM: ReadonlySet<number> = new Set([
  SipralEventKind.TransferRequested,
  SipralEventKind.TransferProgress,
  SipralEventKind.TransferDone,
]);

/** The kinds whose payload is `sipral_media_event_t`. */
const MEDIA_ARM: ReadonlySet<number> = new Set([
  SipralEventKind.MediaStatistics,
  SipralEventKind.MediaStarted,
  SipralEventKind.MediaChanged,
  SipralEventKind.DigitReceived,
]);

/** Where the payload union starts inside `sipral_event_t`. */
const PAYLOAD = koffi.offsetof('sipral_event_t', 'payload');

/** What a call's media has done, from `sipral_stream_stats_t`. */
export interface MediaStatistics {
  /** RTP packets sent. */
  readonly packetsSent: number;
  /** RTP packets received. */
  readonly packetsReceived: number;
  /** RTP packets the far end sent that never arrived. */
  readonly packetsLost: number;
  /** Interarrival jitter, in microseconds. */
  readonly jitterUs: number;
  /** The round trip RTCP measured, in microseconds, or null before it has. */
  readonly roundTripUs: number | null;
  /** Frames played as nothing, because nothing had arrived in time. */
  readonly framesUnderrun: number;
  /** The fraction of packets lost. */
  readonly lossRate: number;
  /** How the call sounds, as the library scores it. */
  readonly score: number;
}

/** {@link MediaStatistics} out of the record the library filled in. */
export function statisticsOf(stats: SipralStreamStats): MediaStatistics {
  return {
    packetsSent: Number(stats.packets_sent),
    packetsReceived: Number(stats.packets_received),
    packetsLost: Number(stats.packets_lost),
    jitterUs: Number(stats.jitter_us),
    roundTripUs: stats.has_round_trip !== 0 ? Number(stats.round_trip_us) : null,
    framesUnderrun: Number(stats.frames_underrun),
    lossRate: stats.loss_rate,
    score: stats.score,
  };
}

/**
 * One event the stack raised, every field the kind carries copied out. A
 * field the kind does not carry is null; `kind` says which apply, and
 * `docs/08-ffi.md` lists what each kind's payload means.
 */
export class StackEvent {
  /** A `SipralEventKind` value. */
  readonly kind: number;
  /** The account it concerns, or `0n`. */
  readonly account: bigint;
  /** The call it concerns, or `0n`. */
  readonly call: bigint;
  /** The SIP message that caused it, whole, when there was one. */
  readonly message: Buffer | null;
  /** A `SipralCallState` value, for a call's event. */
  readonly callState: number | null;
  /** The SIP status code a call's or a transfer's event carries. */
  readonly statusCode: number | null;
  /** A `SipralCallEndReason` value, for `CallEnded`. */
  readonly endReason: number | null;
  /** Who is calling, for `IncomingCall`. */
  readonly fromUri: string | null;
  /** A `SipralRegistrationState` value, for `RegistrationChanged`. */
  readonly registrationState: number | null;
  /** A `SipralRegistrationFailure` value, for `RegistrationChanged`. */
  readonly registrationFailure: number | null;
  /** The digit, for `DigitReceived`. */
  readonly digit: string | null;
  /** Where a transfer or a referral sends the call. */
  readonly transferTarget: string | null;
  /** Whether a transfer replaces a call (attended), for a transfer's event. */
  readonly attended: boolean | null;
  /** The end-of-call record, for `MediaStatistics`. */
  readonly statistics: MediaStatistics | null;

  private constructor(fields: {
    kind: number;
    account: bigint;
    call: bigint;
    message: Buffer | null;
    callState?: number | null;
    statusCode?: number | null;
    endReason?: number | null;
    fromUri?: string | null;
    registrationState?: number | null;
    registrationFailure?: number | null;
    digit?: string | null;
    transferTarget?: string | null;
    attended?: boolean | null;
    statistics?: MediaStatistics | null;
  }) {
    this.kind = fields.kind;
    this.account = fields.account;
    this.call = fields.call;
    this.message = fields.message;
    this.callState = fields.callState ?? null;
    this.statusCode = fields.statusCode ?? null;
    this.endReason = fields.endReason ?? null;
    this.fromUri = fields.fromUri ?? null;
    this.registrationState = fields.registrationState ?? null;
    this.registrationFailure = fields.registrationFailure ?? null;
    this.digit = fields.digit ?? null;
    this.transferTarget = fields.transferTarget ?? null;
    this.attended = fields.attended ?? null;
    this.statistics = fields.statistics ?? null;
  }

  /** The name the library gives the kind, `SIPRAL_EVENT_KIND_...`'s tail. */
  get kindName(): string {
    for (const [name, value] of Object.entries(SipralEventKind)) {
      if (value === this.kind) {
        return name;
      }
    }
    return String(this.kind);
  }

  /** Copy out what the event at `address` carries. */
  static read(address: Pointer): StackEvent {
    const event = read<SipralEvent>(address, 'sipral_event_t');
    const kind = event.kind;
    const base = {
      kind,
      account: handle(event.account),
      call: handle(event.call),
      message: readBytes(event.message, event.message_len),
    };
    if (CALL_ARM.has(kind)) {
      const call = read<SipralCallEvent>(address, 'sipral_call_event_t', PAYLOAD);
      return new StackEvent({
        ...base,
        callState: call.state,
        statusCode: call.status_code,
        endReason: kind === SipralEventKind.CallEnded ? call.end_reason : null,
        fromUri: readText(call.from_uri, call.from_uri_len),
      });
    }
    if (kind === SipralEventKind.RegistrationChanged) {
      const registration = read<SipralRegistrationEvent>(
        address,
        'sipral_registration_event_t',
        PAYLOAD,
      );
      return new StackEvent({
        ...base,
        registrationState: registration.state,
        registrationFailure: registration.failure,
        statusCode: registration.status_code,
      });
    }
    if (TRANSFER_ARM.has(kind)) {
      const transfer = read<SipralTransferEvent>(address, 'sipral_transfer_event_t', PAYLOAD);
      return new StackEvent({
        ...base,
        statusCode: transfer.status_code,
        attended: transfer.attended !== 0,
        transferTarget: readText(transfer.target, transfer.target_len),
      });
    }
    if (kind === SipralEventKind.Referral) {
      const referral = read<SipralReferralEvent>(address, 'sipral_referral_event_t', PAYLOAD);
      return new StackEvent({
        ...base,
        statusCode: referral.status_code,
        attended: referral.attended !== 0,
        transferTarget: readText(referral.target, referral.target_len),
      });
    }
    if (MEDIA_ARM.has(kind)) {
      const media = read<SipralMediaEvent>(address, 'sipral_media_event_t', PAYLOAD);
      const digit =
        kind === SipralEventKind.DigitReceived && media.digit > 0
          ? String.fromCharCode(media.digit)
          : null;
      const statistics =
        kind === SipralEventKind.MediaStatistics && !isNull(media.statistics)
          ? statisticsOf(read<SipralStreamStats>(media.statistics, 'sipral_stream_stats_t'))
          : null;
      return new StackEvent({ ...base, digit, statistics });
    }
    return new StackEvent(base);
  }

  toString(): string {
    return `StackEvent(${this.kindName}, account ${this.account}, call ${this.call})`;
  }
}
