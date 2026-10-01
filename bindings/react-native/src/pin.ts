// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// A certificate fingerprint as an administrator copies it, read here before
// it crosses to the native half, which then only ever sees bare digits.

import {SipralError} from './errors';

/** The prefixes a fingerprint may come after, lower case. */
const PREFIXES = ['sha256 fingerprint=', 'sha-256 ', 'sha256='];

/**
 * The SHA-256 digest a certificate fingerprint names, as 64 lower-case
 * hexadecimal digits. It is read as `openssl x509 -fingerprint -sha256`
 * (`sha256 Fingerprint=`, or `SHA256 Fingerprint=` before OpenSSL 3) or RFC
 * 8122 prints it: 64 hexadecimal digits, either case, colons and spaces
 * between them ignored, optionally after `sha-256 `, `SHA256=` or
 * `SHA256 Fingerprint=`, in any case. Anything else throws a `SipralError`
 * with the code `invalidArgument`; `bindings/fixtures/pin-forms.txt` lists
 * what every layer takes.
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
