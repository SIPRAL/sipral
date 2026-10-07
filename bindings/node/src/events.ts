// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// One event, copied out of the `sipral_event_t` the callback was handed,
// which is the library's only for the length of the callback.

import koffi from 'koffi';

import { handle, isNull, plain, read, readBytes } from './internal.js';
import { type Pointer, type SipralEvent, SipralEventKind, type SipralStreamStats } from './sipral_abi.js';

/**
 * The payload arm each kind writes, as `EVENT_KIND_ARMS` in
 * `crates/sipral-ffi/src/event.rs` lists them. A kind missing here -- one a
 * newer library raises -- carries no fields, and still arrives.
 */
const ARMS: ReadonlyMap<number, string> = new Map([
  [SipralEventKind.Started, 'sipral_call_event_t'],
  [SipralEventKind.RegistrationChanged, 'sipral_registration_event_t'],
  [SipralEventKind.IncomingCall, 'sipral_call_event_t'],
  [SipralEventKind.CallProgress, 'sipral_call_event_t'],
  [SipralEventKind.CallForked, 'sipral_call_event_t'],
  [SipralEventKind.CallConfirmed, 'sipral_call_event_t'],
  [SipralEventKind.SessionChanged, 'sipral_call_event_t'],
  [SipralEventKind.SessionOffered, 'sipral_call_event_t'],
  [SipralEventKind.SessionChangeFailed, 'sipral_call_event_t'],
  [SipralEventKind.TransferRequested, 'sipral_transfer_event_t'],
  [SipralEventKind.TransferProgress, 'sipral_transfer_event_t'],
  [SipralEventKind.TransferDone, 'sipral_transfer_event_t'],
  [SipralEventKind.CallReplaced, 'sipral_call_event_t'],
  [SipralEventKind.CallEnded, 'sipral_call_event_t'],
  [SipralEventKind.SubscriptionChanged, 'sipral_subscription_event_t'],
  [SipralEventKind.MediaStatistics, 'sipral_media_event_t'],
  [SipralEventKind.TransportWanted, 'sipral_transport_wanted_event_t'],
  [SipralEventKind.MediaStalled, 'sipral_media_event_t'],
  [SipralEventKind.AnnouncedCallMissing, 'sipral_announce_event_t'],
  [SipralEventKind.MediaStarted, 'sipral_media_event_t'],
  [SipralEventKind.MediaChanged, 'sipral_media_event_t'],
  [SipralEventKind.MediaResumed, 'sipral_media_event_t'],
  [SipralEventKind.MediaFailed, 'sipral_media_event_t'],
  [SipralEventKind.RecordingStopped, 'sipral_media_event_t'],
  [SipralEventKind.DigitReceived, 'sipral_media_event_t'],
  [SipralEventKind.DtmfSent, 'sipral_call_event_t'],
  [SipralEventKind.Recovery, 'sipral_recovery_event_t'],
  [SipralEventKind.ResolveNeeded, 'sipral_resolve_event_t'],
  [SipralEventKind.Notified, 'sipral_subscription_event_t'],
  [SipralEventKind.CallAnnounced, 'sipral_announce_event_t'],
  [SipralEventKind.MediaSecured, 'sipral_media_event_t'],
  [SipralEventKind.MediaPathChosen, 'sipral_media_event_t'],
  [SipralEventKind.MessageReceived, 'sipral_message_event_t'],
  [SipralEventKind.MessageSent, 'sipral_message_event_t'],
  [SipralEventKind.MessagesWaiting, 'sipral_message_event_t'],
  [SipralEventKind.QualityReportSent, 'sipral_media_event_t'],
  [SipralEventKind.MediaUnjoined, 'sipral_media_event_t'],
  [SipralEventKind.NatMapping, 'sipral_nat_event_t'],
  [SipralEventKind.NatRelay, 'sipral_nat_relay_event_t'],
  [SipralEventKind.Referral, 'sipral_referral_event_t'],
  [SipralEventKind.TurnStream, 'sipral_turn_stream_event_t'],
  [SipralEventKind.AudioDevicesChanged, 'sipral_audio_event_t'],
  [SipralEventKind.CallAddressWanted, 'sipral_call_event_t'],
  [SipralEventKind.StunServer, 'sipral_stun_server_event_t'],
  [SipralEventKind.CallerVerification, 'sipral_verification_event_t'],
  [SipralEventKind.InBandDigit, 'sipral_media_event_t'],
  [SipralEventKind.ProgressDetected, 'sipral_progress_event_t'],
  [SipralEventKind.ConferenceChanged, 'sipral_conference_event_t'],
  [SipralEventKind.TextReceived, 'sipral_text_event_t'],
  [SipralEventKind.PresenceChanged, 'sipral_presence_event_t'],
  [SipralEventKind.TransportFailed, 'sipral_transport_failed_event_t'],
  [SipralEventKind.LocalConferenceChanged, 'sipral_local_conference_event_t'],
  [SipralEventKind.LookupWanted, 'sipral_locate_event_t'],
  [SipralEventKind.Located, 'sipral_locate_event_t'],
  [SipralEventKind.LocateFailed, 'sipral_locate_event_t'],
  [SipralEventKind.ChallengeDeclined, 'sipral_challenge_event_t'],
  [SipralEventKind.TokenRequired, 'sipral_token_event_t'],
  [SipralEventKind.NetworkTest, 'sipral_network_test_event_t'],
]);

/** Where the payload union starts inside `sipral_event_t`. */
const PAYLOAD = koffi.offsetof('sipral_event_t', 'payload');

/** What a call's media has done, from `sipral_stream_stats_t`. */
export interface MediaStatistics {
  /** The codec, a `SipralCodec` value. */
  readonly codec: number;
  /** RTP packets sent. */
  readonly packetsSent: number;
  /** Octets of RTP payload sent. */
  readonly octetsSent: number;
  /** RTP packets received. */
  readonly packetsReceived: number;
  /** RTP packets the far end sent that never arrived. */
  readonly packetsLost: number;
  /** Packets that arrived too late to play. */
  readonly packetsLate: number;
  /** Packets the jitter buffer had no room for. */
  readonly packetsOverflowed: number;
  /** Packets that arrived twice. */
  readonly packetsDuplicated: number;
  /** Packets that arrived out of order. */
  readonly packetsReordered: number;
  /** How long a packet waits in the jitter buffer, in microseconds. */
  readonly delayUs: number;
  /** What the jitter buffer aims for, in microseconds. */
  readonly targetDelayUs: number;
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
  /** Whether the call is suffering now. */
  readonly suffering: boolean;
  /** How long nothing has been heard, in milliseconds. */
  readonly silentForMs: number;
  /**
   * What RTP/AVPF (RFC 4585) did on the stream, while it runs it: the
   * `trr-int` agreed, the Generic NACKs and the reduced-size RTCP.
   */
  readonly feedback: Readonly<Record<string, number>> | null;
}

/** {@link MediaStatistics} out of the record the library filled in. */
export function statisticsOf(stats: SipralStreamStats): MediaStatistics {
  const raw = stats as unknown as Record<string, number | bigint>;
  const number = (name: string): number => Number(raw[name] ?? 0);
  const feedback =
    number('feedback') !== 0
      ? Object.freeze({
          trrIntervalMs: number('trr_interval_ms'),
          nacksSent: number('nacks_sent'),
          packetsNacked: number('packets_nacked'),
          nacksReceived: number('nacks_received'),
          packetsAskedFor: number('packets_asked_for'),
          earlyPackets: number('early_packets'),
          reducedSizePackets: number('reduced_size_packets'),
          feedbackSuppressed: number('feedback_suppressed'),
        })
      : null;
  return {
    codec: number('codec'),
    packetsSent: number('packets_sent'),
    octetsSent: number('octets_sent'),
    packetsReceived: number('packets_received'),
    packetsLost: number('packets_lost'),
    packetsLate: number('packets_late'),
    packetsOverflowed: number('packets_overflowed'),
    packetsDuplicated: number('packets_duplicated'),
    packetsReordered: number('packets_reordered'),
    delayUs: number('delay_us'),
    targetDelayUs: number('target_delay_us'),
    jitterUs: number('jitter_us'),
    roundTripUs: number('has_round_trip') !== 0 ? number('round_trip_us') : null,
    framesUnderrun: number('frames_underrun'),
    lossRate: number('loss_rate'),
    score: number('score'),
    suffering: number('suffering') !== 0,
    silentForMs: number('silent_for_ms'),
    feedback,
  };
}

/**
 * What an event's payload carries, under the header's member names in
 * `camelCase`: a number for a number or an enumeration, a `bigint` for a
 * handle, text for text, a `Buffer` for a body or an SDP, and null for text
 * the event did not carry. `docs/08-ffi.md` says what each member means.
 */
export type EventFields = Readonly<Record<string, unknown>>;

/**
 * One event the stack raised, every field the kind carries copied out:
 * {@link fields} has the whole payload, and the members below the ones an
 * application reaches for most. A member the kind does not carry is null.
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
  /** The payload, whole (see {@link EventFields}). */
  readonly fields: EventFields;
  /** A `SipralCallState` value, for a call's event. */
  readonly callState: number | null;
  /** The SIP status code a call's, a registration's or a transfer's event carries. */
  readonly statusCode: number | null;
  /** A `SipralCallEndReason` value, for `CallEnded`. */
  readonly endReason: number | null;
  /** Who is calling, for `IncomingCall`. */
  readonly fromUri: string | null;
  /** A `SipralRegistrationState` value, for `RegistrationChanged`. */
  readonly registrationState: number | null;
  /** A `SipralRegistrationFailure` value, for `RegistrationChanged`. */
  readonly registrationFailure: number | null;
  /** The digit, for `DigitReceived` and `InBandDigit`. */
  readonly digit: string | null;
  /** Where a transfer or a referral sends the call. */
  readonly transferTarget: string | null;
  /** Whether a transfer replaces a call (attended), for a transfer's event. */
  readonly attended: boolean | null;
  /** The end-of-call record, for `MediaStatistics`. */
  readonly statistics: MediaStatistics | null;

  private constructor(kind: number, account: bigint, call: bigint, message: Buffer | null, fields: EventFields) {
    this.kind = kind;
    this.account = account;
    this.call = call;
    this.message = message;
    this.fields = fields;
    const number = (name: string): number | null => (typeof fields[name] === 'number' ? (fields[name] as number) : null);
    const callArm = ARMS.get(kind) === 'sipral_call_event_t';
    this.callState = callArm ? number('state') : null;
    this.statusCode = number('statusCode');
    this.endReason = kind === SipralEventKind.CallEnded ? number('endReason') : null;
    this.fromUri = callArm ? ((fields.fromUri as string | null) ?? null) : null;
    this.registrationState = kind === SipralEventKind.RegistrationChanged ? number('state') : null;
    this.registrationFailure = kind === SipralEventKind.RegistrationChanged ? number('failure') : null;
    const digit = number('digit');
    this.digit =
      (kind === SipralEventKind.DigitReceived || kind === SipralEventKind.InBandDigit) && digit !== null && digit > 0
        ? String.fromCharCode(digit)
        : null;
    const transfer = ARMS.get(kind) === 'sipral_transfer_event_t' || kind === SipralEventKind.Referral;
    this.transferTarget = transfer ? ((fields.target as string | null) ?? null) : null;
    this.attended = transfer ? fields.attended !== 0 : null;
    this.statistics = (fields.statistics as MediaStatistics | null | undefined) ?? null;
  }

  /** The name the library gives the kind, `SIPRAL_EVENT_KIND_...`'s tail in `PascalCase`. */
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
    const arm = ARMS.get(kind);
    let fields: Record<string, unknown> = {};
    if (arm !== undefined) {
      fields = plain(address, arm, PAYLOAD);
      if (arm === 'sipral_media_event_t') {
        const media = read<{ statistics: Pointer }>(address, 'sipral_media_event_t', PAYLOAD);
        fields.statistics = isNull(media.statistics)
          ? null
          : statisticsOf(read<SipralStreamStats>(media.statistics, 'sipral_stream_stats_t'));
      }
    }
    return new StackEvent(
      kind,
      handle(event.account),
      handle(event.call),
      readBytes(event.message, event.message_len),
      Object.freeze(fields),
    );
  }

  toString(): string {
    return `StackEvent(${this.kindName}, account ${this.account}, call ${this.call})`;
  }
}
