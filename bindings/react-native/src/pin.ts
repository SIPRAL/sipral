// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Certificate fingerprints are normalised here; the native half only sees
// bare digits.

import {SipralError} from './errors';

const PREFIXES = ['sha256 fingerprint=', 'sha-256 ', 'sha256='];

/**
 * The SHA-256 digest a certificate fingerprint names, as 64 lower-case hex
 * digits. Accepts `openssl x509 -fingerprint -sha256` and RFC 8122 output:
 * either case, colons and spaces ignored, optionally after `sha-256 `,
 * `SHA256=` or `SHA256 Fingerprint=`. Anything else throws a `SipralError`
 * with code `invalidArgument`; `bindings/fixtures/pin-forms.txt` lists the
 * accepted forms.
 */
export function pinDigest(fingerprint: string): string {
  let text = fingerprint.trim();
  const lowered = text.toLowerCase();
  const prefix = PREFIXES.find((one) => lowered.startsWith(one));
  if (prefix !== undefined) {
    text = text.slice(prefix.length);
  }
  const digits = text.replace(/[: ]/g, '');
  if (!/^[0-9a-fA-F]{64}$/.test(digits)) {
    throw new SipralError(
      'invalidArgument',
      'a certificate pin is a SHA-256 fingerprint: 64 hexadecimal digits, optionally after sha-256, SHA256= or SHA256 Fingerprint=',
    );
  }
  return digits.toLowerCase();
}
