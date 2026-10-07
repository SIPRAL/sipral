// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// What the library says about itself, and what it reads for anybody: the
// ABI version, what this build has, the codecs it knows, the names of its
// statuses and events, where a socket is reached, and the header fields of
// a SIP message.

import { ADDRESS_BYTES, check, copyText, library, plain, record, text } from './internal.js';
import type { Sipral } from './sipral_abi.js';

/** What `sipral_capabilities` says this build has. */
export interface Capabilities {
  /** How many codecs it knows. */
  readonly codecCount: number;
  /** `SIPRAL_TRANSPORT_BIT_*` bits: the transports it carries. */
  readonly transports: number;
  /** `SIPRAL_FEATURE_*` bits: what it has compiled in. */
  readonly features: number;
}

/** One codec the library knows (`sipral_codec_at`). */
export interface CodecInfo {
  /** A `SipralCodec` value. */
  readonly codec: number;
  /** Its name as SDP writes it. */
  readonly name: string;
  readonly clockRate: number;
  readonly sampleRate: number;
  /** Its static RTP payload type, or null for a dynamic one. */
  readonly staticPayloadType: number | null;
}

/** `sipral_capabilities`. */
export function capabilities(sipral: Sipral = library()): Capabilities {
  const out = record('sipral_capabilities_t');
  check(sipral, 'sipral_capabilities', sipral.sipral_capabilities(out));
  const read = plain(out, 'sipral_capabilities_t');
  return { codecCount: read.codecCount as number, transports: read.transports as number, features: read.features as number };
}

/**
 * What this build has compiled in, as `SIPRAL_FEATURE_*` bits:
 * `SIPRAL_FEATURE_AUDIO_DEVICE` is set where a stack can be opened in
 * device mode (macOS, iOS, Windows) and clear where it cannot.
 */
export function features(sipral: Sipral = library()): number {
  return capabilities(sipral).features;
}

/** The ABI version of the library loaded (`sipral_abi_version`). */
export function abiVersion(sipral: Sipral = library()): { major: number; minor: number; patch: number } {
  const out = record('sipral_abi_version_t');
  check(sipral, 'sipral_abi_version', sipral.sipral_abi_version(out));
  const read = plain(out, 'sipral_abi_version_t');
  return { major: read.major as number, minor: read.minor as number, patch: read.patch as number };
}

/** Whether the library serves a binding built against `major.minor` (`sipral_abi_check`): `SipralStatus.Ok` when it does. */
export function abiCheck(major: number, minor: number, sipral: Sipral = library()): number {
  return sipral.sipral_abi_check(major, minor);
}

/** The size the library gives a versioned record, by its header name (`sipral_abi_struct_size`). */
export function structSize(name: string, sipral: Sipral = library()): number {
  const [bytes, length] = text(name);
  const out = new BigUint64Array(1);
  check(sipral, 'sipral_abi_struct_size', sipral.sipral_abi_struct_size(bytes, length, out));
  return Number(out[0]);
}

/** How many versioned records the ABI has (`sipral_abi_versioned_count`). */
export function versionedCount(sipral: Sipral = library()): number {
  const out = new BigUint64Array(1);
  check(sipral, 'sipral_abi_versioned_count', sipral.sipral_abi_versioned_count(out));
  return Number(out[0]);
}

/** The name the library gives a status: `SIPRAL_STATUS_...`. */
export function statusName(status: number, sipral: Sipral = library()): string {
  return sipral.sipral_status_name(status);
}

/** The name the library gives an event kind, current even for a kind this package does not know. */
export function eventKindName(kind: number, sipral: Sipral = library()): string {
  return sipral.sipral_event_kind_name(kind);
}

/** The name SDP writes a codec under. */
export function codecName(codec: number, sipral: Sipral = library()): string {
  return sipral.sipral_codec_name(codec);
}

/** Every codec this build knows, in the library's order. */
export function codecs(sipral: Sipral = library()): CodecInfo[] {
  const count = new BigUint64Array(1);
  check(sipral, 'sipral_codec_count', sipral.sipral_codec_count(count));
  const found: CodecInfo[] = [];
  for (let index = 0; index < Number(count[0]); index++) {
    const out = record('sipral_codec_info_t');
    check(sipral, 'sipral_codec_at', sipral.sipral_codec_at(index, out));
    const read = plain(out, 'sipral_codec_info_t');
    found.push({
      codec: read.codec as number,
      name: sipral.sipral_codec_name(read.codec as number),
      clockRate: read.clockRate as number,
      sampleRate: read.sampleRate as number,
      staticPayloadType: read.hasStaticPayloadType !== 0 ? (read.staticPayloadType as number) : null,
    });
  }
  return found;
}

/**
 * `sipral_advertised_address`: the `host:port` to advertise for a socket
 * bound at `bound` whose traffic goes to `peer`. A wildcard bind gives the
 * route toward `peer`; a loopback bind toward a peer that is not is
 * `SipralStatus.UnreachableAddress`.
 */
export function advertisedAddress(bound: string, peer: string, sipral: Sipral = library()): string {
  const [near, nearLength] = text(bound);
  const [far, farLength] = text(peer);
  return copyText(
    sipral,
    'sipral_advertised_address',
    (buffer, capacity, needed) => sipral.sipral_advertised_address(near, nearLength, far, farLength, buffer, capacity, needed),
    ADDRESS_BYTES,
  );
}

/** The values a count-then-locate pair of entry points finds in `message`. */
function located(
  sipral: Sipral,
  message: Buffer,
  name: string,
  count: (name: Buffer | null, nameLength: number, out: BigUint64Array) => number,
  at: (name: Buffer | null, nameLength: number, index: number, offset: BigUint64Array, length: BigUint64Array) => number,
  operation: string,
): string[] {
  const [field, fieldLength] = text(name);
  const total = new BigUint64Array(1);
  check(sipral, `${operation}_count`, count(field, fieldLength, total));
  const found: string[] = [];
  const offset = new BigUint64Array(1);
  const length = new BigUint64Array(1);
  for (let index = 0; index < Number(total[0]); index++) {
    check(sipral, operation, at(field, fieldLength, index, offset, length));
    const start = Number(offset[0]);
    found.push(message.toString('utf8', start, start + Number(length[0])));
  }
  return found;
}

/**
 * Every line of header field `name` in a whole SIP message -- an event's
 * `message` -- trimmed, in arrival order; the name is case-insensitive and
 * a compact form equals its long form.
 */
export function messageHeaders(message: Buffer, name: string, sipral: Sipral = library()): string[] {
  return located(
    sipral,
    message,
    name,
    (field, fieldLength, out) => sipral.sipral_message_header_count(message, message.length, field, fieldLength, out),
    (field, fieldLength, index, offset, length) =>
      sipral.sipral_message_header(message, message.length, field, fieldLength, index, offset, length),
    'sipral_message_header',
  );
}

/**
 * Every value of a list field (`Contact`, `Diversion`...) across every line
 * it is on, split at the commas outside quotes and angle brackets.
 */
export function messageHeaderElements(message: Buffer, name: string, sipral: Sipral = library()): string[] {
  return located(
    sipral,
    message,
    name,
    (field, fieldLength, out) => sipral.sipral_message_header_element_count(message, message.length, field, fieldLength, out),
    (field, fieldLength, index, offset, length) =>
      sipral.sipral_message_header_element(message, message.length, field, fieldLength, index, offset, length),
    'sipral_message_header_element',
  );
}
