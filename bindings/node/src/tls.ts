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
import { Socket, connect as connectTcp, isIP } from 'node:net';
import {
  type ConnectionOptions,
  type DetailedPeerCertificate,
  type PeerCertificate,
  TLSSocket,
  checkServerIdentity,
  connect as connectTls,
  createSecureContext,
  rootCertificates,
} from 'node:tls';

import { lastError, text } from './internal.js';
import {
  SIPRAL_TRANSPORT_DETAIL_BYTES,
  type Sipral,
  SipralDomainRules,
  SipralStatus,
  SipralTlsFailure,
  SipralTransportError,
} from './sipral_abi.js';

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

/**
 * The certificate this end presents to a server that asks for one (mutual
 * TLS), as files read by the application: `cert` and `key` in PEM -- the
 * leaf first in `cert`, then any intermediates -- or both in one PKCS#12
 * `pfx`. `passphrase` opens an encrypted key or the PKCS#12. Node's TLS
 * signs with the key in this process; a key held by a hardware module or the
 * operating system needs the Swift, Kotlin or .NET layer.
 */
export interface ClientCertificate {
  /** The certificate chain in PEM, the leaf first. */
  readonly cert?: string | Buffer;
  /** The leaf's private key in PEM. */
  readonly key?: string | Buffer;
  /** The certificate chain and its key in one PKCS#12, instead of `cert` and `key`. */
  readonly pfx?: Buffer;
  /** The password of an encrypted `key` or of `pfx`. */
  readonly passphrase?: string;
}

/**
 * What tells `certificate` apart for the stack, the same each time
 * (`sipral_account_config_t::tls_client_tag`): the SHA-256 of its `cert`, or
 * of its `pfx`. Accounts whose tags match share a TLS connection; the others
 * never do, since a connection presents one certificate.
 */
export function clientTag(certificate: ClientCertificate): string {
  const { cert, pfx } = certificate;
  if (cert !== undefined) {
    return `chain ${createHash('sha256').update(cert).digest('hex')}`;
  }
  return `pkcs12 ${createHash('sha256').update(pfx ?? Buffer.alloc(0)).digest('hex')}`;
}

/** A client certificate that cannot be used, found before connecting. */
class ClientCertificateUnusable extends Error {
  readonly code: 'CLIENT_KEY_UNAVAILABLE' | 'CLIENT_CERTIFICATE_EXPIRED';

  constructor(code: 'CLIENT_KEY_UNAVAILABLE' | 'CLIENT_CERTIFICATE_EXPIRED', message: string) {
    super(message);
    this.name = 'ClientCertificateUnusable';
    this.code = code;
  }
}

/**
 * The TLS options that present `certificate`, once it is shown usable now:
 * its key loads and belongs to its leaf, and the leaf is within its dates.
 * Throws a {@link ClientCertificateUnusable} otherwise, which
 * {@link classify} names `ClientKeyUnavailable` or `ClientCertificateExpired`.
 */
export function presenting(certificate: ClientCertificate, now: Date = new Date()): ConnectionOptions {
  const { cert, key, pfx, passphrase } = certificate;
  if (pfx === undefined && (cert === undefined || key === undefined)) {
    throw new ClientCertificateUnusable('CLIENT_KEY_UNAVAILABLE', 'a client certificate needs cert and key, or pfx');
  }
  const options: ConnectionOptions = pfx === undefined ? { cert, key } : { pfx };
  if (passphrase !== undefined) {
    options.passphrase = passphrase;
  }
  let leaf: ReturnType<TLSSocket['getCertificate']>;
  try {
    // the key is checked against the leaf as the context takes them both
    const holder = new TLSSocket(new Socket(), { secureContext: createSecureContext(options) });
    leaf = holder.getCertificate();
    holder.destroy();
  } catch (error) {
    throw new ClientCertificateUnusable(
      'CLIENT_KEY_UNAVAILABLE',
      `the client certificate's key cannot be used: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (leaf === null || !('valid_to' in leaf)) {
    throw new ClientCertificateUnusable('CLIENT_KEY_UNAVAILABLE', 'the client certificate holds no certificate');
  }
  const from = Date.parse(leaf.valid_from);
  const to = Date.parse(leaf.valid_to);
  if (now.getTime() < from || now.getTime() > to) {
    throw new ClientCertificateUnusable(
      'CLIENT_CERTIFICATE_EXPIRED',
      `the client certificate is valid from ${leaf.valid_from} to ${leaf.valid_to}`,
    );
  }
  return options;
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

/**
 * The alerts a server sends about the client's certificate, as OpenSSL
 * codes them: certificate_required (116), bad_certificate (42),
 * unsupported_certificate (43), certificate_revoked (44),
 * certificate_unknown (46), unknown_ca (48) and access_denied (49).
 */
const CLIENT_CERTIFICATE_ALERTS = new Set([
  'ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED',
  'ERR_SSL_SSLV3_ALERT_BAD_CERTIFICATE',
  'ERR_SSL_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE',
  'ERR_SSL_SSLV3_ALERT_CERTIFICATE_REVOKED',
  'ERR_SSL_SSLV3_ALERT_CERTIFICATE_UNKNOWN',
  'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA',
  'ERR_SSL_TLSV1_ALERT_ACCESS_DENIED',
]);

/** certificate_expired (45), which a server sends about the client's certificate. */
const CLIENT_CERTIFICATE_EXPIRED_ALERT = 'ERR_SSL_SSLV3_ALERT_CERTIFICATE_EXPIRED';

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
 *
 * `presented` says whether this end offered a client certificate: a server
 * alert about the client's certificate is then that certificate refused, or
 * expired, and without one a certificate the server required. These alerts
 * come during the handshake under TLS 1.2 and on the first read after it
 * under TLS 1.3, so the same reading serves a connection that failed later.
 * A bare handshake_failure stays a handshake refused: Node does not say
 * whether the server had asked for a certificate.
 */
export function classify(failure: unknown, presented = false): Refusal {
  const error = failure instanceof Error ? failure : new Error(String(failure));
  const code = (error as NodeJS.ErrnoException).code ?? '';
  const detail = oneLine(code && !error.message.includes(code) ? `${code}: ${error.message}` : error.message);
  if (code === 'CLIENT_KEY_UNAVAILABLE') {
    return { error: SipralTransportError.Other, tls: SipralTlsFailure.ClientKeyUnavailable, detail };
  }
  if (code === 'CLIENT_CERTIFICATE_EXPIRED') {
    return { error: SipralTransportError.Other, tls: SipralTlsFailure.ClientCertificateExpired, detail };
  }
  if (CLIENT_CERTIFICATE_ALERTS.has(code)) {
    const tls = presented ? SipralTlsFailure.ClientCertificateRefused : SipralTlsFailure.ClientCertificateRequired;
    return { error: SipralTransportError.ConnectionReset, tls, detail };
  }
  if (code === CLIENT_CERTIFICATE_EXPIRED_ALERT && presented) {
    return { error: SipralTransportError.ConnectionReset, tls: SipralTlsFailure.ClientCertificateExpired, detail };
  }
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
  /** Over TLS, the certificate this end presents when the server asks; none when left out. */
  clientCertificate?: ClientCertificate | null | undefined;
  /** How long the connection and its handshake may take. */
  timeoutMs?: number;
  /**
   * Over TLS to a SIP server, the library that reads its certificate for the
   * name once the chain is trusted (`sipral_certificate_check_domain_in_chain`), by
   * {@link domainRules}. Left out, as for a TURN server, the HTTPS rules
   * Node applies are the whole check.
   */
  sipral?: Sipral | undefined;
  /** How that name is read, a `SipralDomainRules`: by default the HTTPS rules, with a `sip:` URI naming the domain accepted besides. */
  domainRules?: number | undefined;
}

/**
 * The domain a `sip:` or `sips:` URI names (`sips:example.com:5061` and
 * `sip:example.com;transport=tls` both give `example.com`), the name RFC
 * 5922 §7.3 checks a server's certificate against; null for an IP address,
 * which is then the destination itself, or for no such URI.
 */
export function sipDomainOf(uri: string | null): string | null {
  const colon = uri?.indexOf(':') ?? -1;
  if (uri === null || colon < 0 || !['sip', 'sips'].includes(uri.slice(0, colon).toLowerCase())) {
    return null;
  }
  const rest = uri.slice(colon + 1).split(/[;?]/)[0] ?? '';
  const hostPort = rest.slice(rest.lastIndexOf('@') + 1);
  if (hostPort.startsWith('[')) {
    return null;
  }
  const host = (hostPort.split(':')[0] ?? '').replace(/\.$/, '');
  return host === '' || isIP(host) !== 0 ? null : host;
}

/**
 * Whether a trusted `certificate` names `name`, the SIP domain: Node's own
 * check by the HTTPS rules, then RFC 5922's reading under `rules`, which
 * accepts a `sip:` URI naming the domain where every authority above it may
 * name it and, with
 * `SipralDomainRules.Rfc5922`, refuses a wildcard. The refusal Node raises,
 * or one that says why.
 */
function domainNamed(sipral: Sipral, name: string, certificate: PeerCertificate, rules: number): Error | undefined {
  const https = checkServerIdentity(name, certificate);
  if (https === undefined && rules === SipralDomainRules.Platform) {
    return undefined;
  }
  const [domain, length] = text(name);
  const raw = certificate.raw ?? Buffer.alloc(0);
  // every authority above the leaf in the chain Node verified, the anchor
  // included, whose name constraints a sip: URI is held to; Node hands the
  // chain over with the certificate, and an anchor is its own issuer
  const issuers: Buffer[] = [];
  let below = certificate as DetailedPeerCertificate;
  let above: DetailedPeerCertificate | undefined = below.issuerCertificate;
  while (above?.raw !== undefined && above.fingerprint256 !== below.fingerprint256) {
    issuers.push(above.raw);
    below = above;
    above = above.issuerCertificate;
  }
  const chain = Buffer.concat(issuers);
  const status = sipral.sipral_certificate_check_domain_in_chain(
    raw,
    raw.length,
    chain,
    chain.length,
    domain,
    length,
    rules,
    https === undefined ? 1 : 0,
    null,
  );
  if (status === SipralStatus.Ok) {
    return undefined;
  }
  const refused = new Error(lastError(sipral) || `the server's certificate does not name ${name}`) as NodeJS.ErrnoException;
  refused.code = 'ERR_TLS_CERT_ALTNAME_INVALID';
  return refused;
}

/**
 * One connection to `host:port`, over TLS when `trust` is given; rejects
 * with what refused it, which {@link classify} names. A client certificate
 * that cannot be used now rejects before anything is sent.
 */
export function openStream(host: string, port: number, options: ConnectOptions = {}): Promise<Socket> {
  const timeoutMs = options.timeoutMs ?? 5000;
  let presented: ConnectionOptions = {};
  const trusted = options.trust !== null && options.trust !== undefined;
  if (trusted && options.clientCertificate !== null && options.clientCertificate !== undefined) {
    try {
      presented = presenting(options.clientCertificate);
    } catch (error) {
      return Promise.reject(error);
    }
  }
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
      ...presented,
      host,
      port,
      ...local,
      ...(isIP(name) === 0 ? { servername: name } : {}),
    };
    if (trust.pin === null && tlsOptions.checkServerIdentity === undefined) {
      const sipral = options.sipral;
      const rules = options.domainRules ?? SipralDomainRules.Platform;
      tlsOptions.checkServerIdentity = (_host: string, certificate: PeerCertificate) =>
        sipral === undefined ? checkServerIdentity(name, certificate) : domainNamed(sipral, name, certificate, rules);
    }
    const began = Date.now();
    const secure: TLSSocket = connectTls(tlsOptions, () => {
      if (trust.pin !== null) {
        const leaf = secure.getPeerCertificate(false);
        const digest = leaf?.raw ? createHash('sha256').update(leaf.raw).digest() : Buffer.alloc(32);
        if (!timingSafeEqual(digest, trust.pin)) {
          fail(new PinRefused());
          return;
        }
      }
      if (secure.getProtocol() !== 'TLSv1.3') {
        done();
        return;
      }
      // Under TLS 1.3 the server's verdict on the client's certificate --
      // or on its having none -- comes a round trip after this end's
      // handshake. Something written meanwhile reaches a server that has
      // already refused, which then resets the connection with it unread,
      // and the reset loses the alert that said why. So nothing is handed
      // over to write on until twice the handshake's time has passed
      // quietly (at least 250 ms, at most 3 s): an alert in that time fails
      // the connection with its reason, and what arrived stays unread in
      // the socket for whoever reads it next. Node does not say whether the
      // server asked for a certificate, so every TLS 1.3 connection waits.
      const quietMs = Math.min(3000, Math.max(250, 2 * (Date.now() - began)));
      clearTimeout(timer);
      const closed = (): void => {
        const error = new Error('the server closed the connection just after the TLS handshake') as NodeJS.ErrnoException;
        error.code = 'ECONNRESET';
        fail(error);
      };
      secure.once('close', closed);
      setTimeout(() => {
        secure.off('close', closed);
        done();
      }, quietMs).unref();
    });
    socket = secure;
    secure.once('error', fail);
  });
}
