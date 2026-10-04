// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

/**
 * What a promise from this package rejects with. The library's own statuses
 * (`sipral_status_t`, in lower camel case) come through as they are; the
 * rest are this layer's.
 */
export type SipralErrorCode =
  | 'invalidArgument'
  | 'invalidHandle'
  | 'staleHandle'
  | 'unsupportedVersion'
  | 'bufferTooSmall'
  | 'busy'
  | 'exhausted'
  | 'panic'
  | 'wrongState'
  | 'notSent'
  | 'notSupported'
  | 'streamBroken'
  | 'noSuchDevice'
  | 'deviceUnusable'
  | 'deviceTimedOut'
  | 'limitReached'
  | 'securityPolicy'
  | 'recordingFailed'
  | 'notNegotiated'
  | 'notAFocus'
  | 'transportDown'
  | 'conferenceRefused'
  | 'clockBehind'
  | 'certificateRefused'
  | 'unreachableAddress'
  /** The client was closed, or never opened. */
  | 'closed'
  /** The platform refused: a socket that would not bind, an address that would not parse. */
  | 'platform';

const LIBRARY_CODES: ReadonlySet<string> = new Set<SipralErrorCode>([
  'invalidArgument',
  'invalidHandle',
  'staleHandle',
  'unsupportedVersion',
  'bufferTooSmall',
  'busy',
  'exhausted',
  'panic',
  'wrongState',
  'notSent',
  'notSupported',
  'streamBroken',
  'noSuchDevice',
  'deviceUnusable',
  'deviceTimedOut',
  'limitReached',
  'securityPolicy',
  'recordingFailed',
  'notNegotiated',
  'notAFocus',
  'transportDown',
  'conferenceRefused',
  'clockBehind',
  'certificateRefused',
  'unreachableAddress',
  'closed',
  'platform',
]);

export class SipralError extends Error {
  readonly code: SipralErrorCode;

  constructor(code: SipralErrorCode, message: string) {
    super(message);
    this.name = 'SipralError';
    this.code = code;
  }
}

/**
 * A native half's rejection as a `SipralError`. React Native hands the code
 * a native promise was rejected with over as the error's `code`; one this
 * package does not know is the platform's, never guessed into a status.
 */
export function fromNative(failure: unknown): SipralError {
  if (failure instanceof SipralError) {
    return failure;
  }
  const code = (failure as {code?: unknown} | null)?.code;
  const message =
    failure instanceof Error ? failure.message : String((failure as {message?: unknown} | null)?.message ?? failure);
  if (typeof code === 'string' && LIBRARY_CODES.has(code)) {
    return new SipralError(code as SipralErrorCode, message);
  }
  return new SipralError('platform', message);
}
