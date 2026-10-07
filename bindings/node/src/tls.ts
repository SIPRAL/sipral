// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// SIP over TCP or TLS: which authorities a TLS connection trusts, one
// connection opened and checked, and what a refused connection is called.
//
// Sipral links no TLS library (`docs/22-tls.md`), so a connection is Node's
// own `tls`, checked by OpenSSL against the name the server is expected to
// have. Nothing here turns that check off: a certificate that fails is a
// connection that is not made, and the stack hears why
// (`sipral_stack_transport_failed_with`), which it passes on to the
// application as `TransportFailed`.

import { createHash, timingSafeEqual } from 'node:crypto';
import { type Socket, connect as connectTcp, isIP } from 'node:net';
import { type ConnectionOptions, type PeerCertificate, type TLSSocket, checkServerIdentity, connect as connectTls, rootCertificates } from 'node:tls';

import { SIPRAL_TRANSPORT_DETAIL_BYTES, SipralTlsFailure, SipralTransportError } from './sipral_abi.js';

/** The prefixes a fingerprint may come after, lower case. */
const PIN_PREFIXES = ['sha256 fingerprint=', 'sha-256 ', 'sha256='];

/**
 * The 32 bytes a SHA-256 fingerprint names: 64 hexadecimal digits, either
 * case, colons and spaces between them ignored, optionally after
 * `sha-256 `, `SHA256=` or `SHA256 Fingerprint=` in any case -- what
 * `openssl x509 -fingerprint -sha256` and RFC 8122 print
 * (`bindings/fixtures/pin-forms.txt` lists what every layer takes). A
 * `RangeError` for anything else.
 */
export function parsePin(fingerprint: string): Buffer {
  let rest = fingerprint.trim();
  for (const prefix of PIN_PREFIXES) {
    if (rest.toLowerCase().startsWith(prefix)) {
      rest = rest.slice(prefix.length);
      break;
    }
  }
  const digits = rest.replace(/[: ]/g, '');
  if (!/^[0-9a-fA-F]{64}$/.test(digits)) {
    throw new RangeError(
      'a certificate pin is a SHA-256 fingerprint: 64 hexadecimal digits, ' +
        'optionally after sha-256, SHA256= or SHA256 Fingerprint=',
    );
  }
  return Buffer.from(digits, 'hex');
}

/**
 * Which authorities a TLS connection to a server trusts.
 *
 * The three answers `docs/22-tls.md` describes for every platform:
 * {@link platform} (Node's own store, what a public server's certificate is
 * checked against), {@link privateAuthority} (a private CA beside it) and
 * {@link onlyAuthority} (that one authority and nothing else). {@link pinned}
 * trusts one certificate by its SHA-256 fingerprint, for a PBX that signed
 * its own, and {@link fromOptions} takes options the application built,
 * refusing any that check nothing. None of them turns the check off.
 */
export class TlsTrust {
  /** What it trusts, in words. */
  readonly description: string;
  /** The SHA-256 digest of the one certificate {@link pinned} trusts, or null. */
  readonly pin: Buffer | null;
  private readonly options: ConnectionOptions;

  private constructor(description: string, options: ConnectionOptions, pin: Buffer | null) {
    this.description = description;
    this.options = options;
    this.pin = pin;
  }

  /** The platform's own trust anchors: Node's bundled store. */
  static platform(): TlsTrust {
    return new TlsTrust("the platform's authorities", {}, null);
  }

  /** The platform's anchors, and the PEM authority `ca` beside them. */
  static privateAuthority(ca: string | Buffer): TlsTrust {
    return new TlsTrust("the platform's authorities and a private one", { ca: [...rootCertificates, ca] }, null);
  }

  /** The PEM authority `ca` and no other: the platform's are refused too. */
  static onlyAuthority(ca: string | Buffer): TlsTrust {
    return new TlsTrust('only one authority', { ca }, null);
  }

  /**
   * The one certificate whose SHA-256 fingerprint is `fingerprint`, in any
   * of the forms {@link parsePin} takes. The fingerprint is the whole
   * verdict: no authority, host name or date is consulted, and any other
   * certificate is refused as untrusted. Compared in constant time over
   * the DER bytes of the certificate the server presented first.
   */
  static pinned(fingerprint: string): TlsTrust {
    return new TlsTrust('the pinned certificate', { rejectUnauthorized: false }, parsePin(fingerprint));
  }

  /**
   * Options the application built for `tls.connect`. They must verify the
   * server: `rejectUnauthorized: false` is refused with a `TypeError`.
   */
  static fromOptions(options: ConnectionOptions): TlsTrust {
    if (options.rejectUnauthorized === false) {
      throw new TypeError("sipral: TLS options for SIP must verify the server's certificate and name");
    }
    return new TlsTrust("the application's own options", { ...options }, null);
  }

  /** @internal The options a connection is made with; at least TLS 1.2. */
  connectionOptions(): ConnectionOptions {
    return { minVersion: 'TLSv1.2', ...this.options };
  }
}

/** A certificate other than the pinned one, as a connection refused. */
class PinRefused extends Error {
  readonly code = 'CERTIFICATE_REFUSED';

  constructor() {
    super("the server's certificate is not the pinned one");
    this.name = 'PinRefused';
  }
}

/** What a failed connection was, as the stack names it. */
export interface Refusal {
  /** A `SipralTransportError` value. */
  readonly error: number;
  /** A `SipralTlsFailure` value. */
  readonly tls: number;
  /** The platform's own sentence, one line. */
  readonly detail: string;
}

/** The OpenSSL verification codes that are a certificate out of its dates. */
const EXPIRED = new Set(['CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID']);

/** The codes that are a certificate for another name. */
const NAME_MISMATCH = new Set(['ERR_TLS_CERT_ALTNAME_INVALID', 'HOSTNAME_MISMATCH', 'IP_ADDRESS_MISMATCH']);

/** The codes that are a chain reaching no trusted authority. */
const UNTRUSTED = new Set([
  'CERTIFICATE_REFUSED',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'CERT_UNTRUSTED',
  'CERT_REJECTED',
  'CERT_SIGNATURE_FAILURE',
  'INVALID_CA',
]);

/** One line of at most `SIPRAL_TRANSPORT_DETAIL_BYTES` bytes of UTF-8. */
export function oneLine(sentence: string): string {
  const flat = [...sentence].map((ch) => (ch.charCodeAt(0) < 0x20 || ch.charCodeAt(0) === 0x7f ? ' ' : ch)).join('');
  let bytes = Buffer.from(flat.trim(), 'utf8');
  if (bytes.length > SIPRAL_TRANSPORT_DETAIL_BYTES) {
    bytes = bytes.subarray(0, SIPRAL_TRANSPORT_DETAIL_BYTES);
  }
  // a character the cut went through is left out rather than mangled
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes).replace(/�+$/, '');
}

/**
 * What a failed connection was: a certificate OpenSSL refused is untrusted,
 * a name mismatch or expired by its code; any other TLS error is a
 * handshake refused. A server nothing answered for is refused, a network
 * with no way through unreachable, silence timed out.
 */
export function classify(failure: unknown): Refusal {
  const error = failure instanceof Error ? failure : new Error(String(failure));
  const code = (error as NodeJS.ErrnoException).code ?? '';
  const detail = oneLine(code && !error.message.includes(code) ? `${code}: ${error.message}` : error.message);
  if (EXPIRED.has(code)) {
    return { error: SipralTransportError.ConnectionReset, tls: SipralTlsFailure.Expired, detail };
  }
  if (NAME_MISMATCH.has(code)) {
    return { error: SipralTransportError.ConnectionReset, tls: SipralTlsFailure.NameMismatch, detail };
  }
  if (UNTRUSTED.has(code)) {
    return { error: SipralTransportError.ConnectionReset, tls: SipralTlsFailure.Untrusted, detail };
  }
  if (code.startsWith('ERR_SSL') || code.startsWith('ERR_TLS')) {
    return { error: SipralTransportError.ConnectionReset, tls: SipralTlsFailure.HandshakeRefused, detail };
  }
  switch (code) {
    case 'ETIMEDOUT':
      return { error: SipralTransportError.TimedOut, tls: SipralTlsFailure.None, detail };
    case 'ECONNREFUSED':
      return { error: SipralTransportError.ConnectionRefused, tls: SipralTlsFailure.None, detail };
    case 'ECONNRESET':
    case 'EPIPE':
    case 'ECONNABORTED':
      return { error: SipralTransportError.ConnectionReset, tls: SipralTlsFailure.None, detail };
    case 'ENETUNREACH':
    case 'EHOSTUNREACH':
    case 'ENETDOWN':
    case 'EHOSTDOWN':
      return { error: SipralTransportError.Unreachable, tls: SipralTlsFailure.None, detail };
    default:
      return { error: SipralTransportError.Other, tls: SipralTlsFailure.None, detail };
  }
}

/** Where a connection goes, and how. */
export interface ConnectOptions {
  /** The address it is made from; the route's own when left out. */
  bindHost?: string | undefined;
  /** Over TLS, checked with this; plain TCP without. */
  trust?: TlsTrust | null | undefined;
  /** The name the certificate must carry; the host's when left out. */
  serverName?: string | undefined;
  /** How long the connection and its handshake may take. */
  timeoutMs?: number;
}

/**
 * One connection to `host:port`, over TLS when `trust` is given; rejects
 * with what refused it, which {@link classify} names.
 */
export function openStream(host: string, port: number, options: ConnectOptions = {}): Promise<Socket> {
  const timeoutMs = options.timeoutMs ?? 5000;
  return new Promise<Socket>((resolve, reject) => {
    let settled = false;
    let socket: Socket;
    const fail = (error: unknown): void => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        reject(error);
      }
    };
    const timer = setTimeout(() => {
      const error = new Error(`no connection to ${host}:${port} within ${timeoutMs} ms`) as NodeJS.ErrnoException;
      error.code = 'ETIMEDOUT';
      fail(error);
    }, timeoutMs);
    const done = (): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      socket.off('error', fail);
      socket.setNoDelay(true);
      resolve(socket);
    };
    const local = options.bindHost === undefined ? {} : { localAddress: options.bindHost };
    const trust = options.trust;
    if (trust === null || trust === undefined) {
      socket = connectTcp({ host, port, ...local }, done);
      socket.once('error', fail);
      return;
    }
    const name = options.serverName ?? host;
    const tlsOptions: ConnectionOptions = {
      ...trust.connectionOptions(),
      host,
      port,
      ...local,
      ...(isIP(name) === 0 ? { servername: name } : {}),
    };
    if (trust.pin === null && options.serverName !== undefined && tlsOptions.checkServerIdentity === undefined) {
      tlsOptions.checkServerIdentity = (_host: string, certificate: PeerCertificate) =>
        checkServerIdentity(name, certificate);
    }
    const secure: TLSSocket = connectTls(tlsOptions, () => {
      if (trust.pin !== null) {
        const leaf = secure.getPeerCertificate(false);
        const digest = leaf?.raw ? createHash('sha256').update(leaf.raw).digest() : Buffer.alloc(32);
        if (!timingSafeEqual(digest, trust.pin)) {
          fail(new PinRefused());
          return;
        }
      }
      done();
    });
    socket = secure;
    secure.once('error', fail);
  });
}
