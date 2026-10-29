// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// What the tests share: waiting, SIP written by hand for a peer this test
// plays -- a registrar, a compositor, a notifier, a focus -- over UDP, TCP
// or TLS, certificates made with the `openssl` command, a STUN server, and
// two stacks calling each other on loopback.

import assert from 'node:assert/strict';
import { type ChildProcess, execFileSync, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { type Socket as DatagramSocket, createSocket } from 'node:dgram';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { type Server, type Socket, connect as connectTcp, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TLSSocket, type TlsOptions, createServer as createTlsServer } from 'node:tls';

import { type Call, SipralEventKind, type Stack, type StackEvent } from '../index.js';

/** Poll `probe` every 20 ms until it holds, or fail after `withinMs`. */
export async function until(probe: () => boolean, withinMs = 15000): Promise<void> {
  const deadline = Date.now() + withinMs;
  while (!probe()) {
    if (Date.now() > deadline) {
      assert.fail(`nothing within ${withinMs} ms`);
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

/** The next event of `kind` on `stack`. */
export function kind(stack: Stack, wanted: number, timeoutMs = 15000): Promise<StackEvent> {
  return stack.next((event) => event.kind === wanted, timeoutMs);
}

/** `samples` samples of a 1 kHz tone at `rate`, peak 8000. */
export function tone(rate: number, samples: number): Int16Array {
  const out = new Int16Array(samples);
  for (let at = 0; at < samples; at++) {
    out[at] = Math.round(8000 * Math.sin((2 * Math.PI * 1000 * at) / rate));
  }
  return out;
}

/** The value of header `name` in `message`, or null. */
export function header(name: string, message: string): string | null {
  for (const line of message.split('\r\n')) {
    if (line === '') {
      return null;
    }
    if (line.toLowerCase().startsWith(`${name.toLowerCase()}:`)) {
      return line.slice(line.indexOf(':') + 1).trim();
    }
  }
  return null;
}

/** The URI inside a name-addr. */
export function uri(nameAddr: string): string {
  const start = nameAddr.indexOf('<');
  const end = nameAddr.indexOf('>');
  return start >= 0 && end > start ? nameAddr.slice(start + 1, end) : nameAddr;
}

/** A response to `request`, its dialog's headers copied and `tag` on its `To`. */
export function answer(request: string, status: string, tag: string, more = '', body = ''): string {
  let out = `SIP/2.0 ${status}\r\n`;
  for (const name of ['Via', 'From', 'To', 'Call-ID', 'CSeq']) {
    const value = header(name, request);
    out += name === 'To' ? `To: ${value};tag=${tag}\r\n` : `${name}: ${value}\r\n`;
  }
  return `${out}${more}Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`;
}

/** A NOTIFY in the dialog `subscribe` opened. */
export function notify(subscribe: string, sender: string, eventPackage: string, contentType: string, body: string, cseq: number): string {
  return (
    `NOTIFY ${uri(header('Contact', subscribe) ?? '')} SIP/2.0\r\n` +
    `Via: SIP/2.0/UDP ${sender};branch=z9hG4bK-notify-${cseq}\r\n` +
    'Max-Forwards: 70\r\n' +
    `From: ${header('To', subscribe)};tag=notifier\r\n` +
    `To: ${header('From', subscribe)}\r\n` +
    `Call-ID: ${header('Call-ID', subscribe)}\r\n` +
    `CSeq: ${cseq} NOTIFY\r\n` +
    `Contact: <sip:notifier@${sender}>\r\n` +
    `Event: ${eventPackage}\r\n` +
    'Subscription-State: active;expires=3600\r\n' +
    `Content-Type: ${contentType}\r\n` +
    `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`
  );
}

/** A 200 to a REGISTER, its `Contact` echoed with an hour. */
export function registered(request: string): string {
  return answer(request, '200 OK', 'registrar', `Contact: ${header('Contact', request)};expires=3600\r\n`);
}

/**
 * A UDP socket on loopback that reads SIP as text and writes what a test
 * hands it: a notifier, a compositor, a registrar.
 */
export class Peer {
  readonly socket: DatagramSocket;
  address = '';
  private readonly waiting: { method: string; resolve: (message: string) => void }[] = [];
  private readonly held: string[] = [];

  private constructor() {
    this.socket = createSocket('udp4');
  }

  static async open(): Promise<Peer> {
    const peer = new Peer();
    await new Promise<void>((resolve) => peer.socket.bind(0, '127.0.0.1', resolve));
    peer.address = `127.0.0.1:${peer.socket.address().port}`;
    peer.socket.on('message', (data: Buffer, from) => peer.arrived(data.toString('utf8'), `${from.address}:${from.port}`));
    return peer;
  }

  /** What to answer a request with, as it arrives: null leaves it to the test. */
  responder: ((message: string, from: string) => string | null) | null = null;

  send(message: string, to: string): void {
    const colon = to.lastIndexOf(':');
    this.socket.send(Buffer.from(message), Number(to.slice(colon + 1)), to.slice(0, colon));
  }

  /** The next request with `method`, every other datagram passed over. */
  request(method: string, timeoutMs = 15000): Promise<string> {
    const index = this.held.findIndex((message) => message.startsWith(`${method} `));
    if (index >= 0) {
      return Promise.resolve(this.held.splice(index, 1)[0] as string);
    }
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`no ${method} within ${timeoutMs} ms`)), timeoutMs);
      this.waiting.push({
        method,
        resolve: (message) => {
          clearTimeout(timer);
          resolve(message);
        },
      });
    });
  }

  close(): void {
    this.socket.close();
  }

  private arrived(message: string, from: string): void {
    const reply = this.responder?.(message, from) ?? null;
    if (reply !== null) {
      this.send(reply, from);
    }
    const index = this.waiting.findIndex((waiter) => message.startsWith(`${waiter.method} `));
    if (index >= 0) {
      this.waiting.splice(index, 1)[0]?.resolve(message);
    } else if (!message.startsWith('SIP/2.0')) {
      this.held.push(message);
    }
  }
}

/** A registrar on UDP that answers every REGISTER 200 and counts them. */
export async function udpRegistrar(): Promise<Peer & { registers: string[] }> {
  const peer = (await Peer.open()) as Peer & { registers: string[] };
  peer.registers = [];
  peer.responder = (message) => {
    if (message.startsWith('REGISTER ')) {
      peer.registers.push(message);
      return registered(message);
    }
    return null;
  };
  return peer;
}

/** Whole SIP messages out of a stream's bytes, as they complete. */
export function framer(deliver: (message: string) => void): (data: Buffer) => void {
  let held = Buffer.alloc(0);
  return (data) => {
    held = Buffer.concat([held, data]);
    for (;;) {
      while (held.length >= 2 && held[0] === 0x0d && held[1] === 0x0a) {
        held = held.subarray(2);
      }
      const end = held.indexOf('\r\n\r\n');
      if (end < 0) {
        return;
      }
      const head = held.subarray(0, end + 2).toString('utf8');
      const length = Number(header('Content-Length', head) ?? 0);
      if (held.length < end + 4 + length) {
        return;
      }
      deliver(held.subarray(0, end + 4 + length).toString('utf8'));
      held = held.subarray(end + 4 + length);
    }
  };
}

/**
 * A SIP server on a TCP port -- over TLS given a certificate -- that answers
 * every REGISTER 200 and keeps every message, `[connection, message]`, the
 * connection counted from one.
 */
export class StreamServer {
  readonly messages: [number, string][] = [];
  readonly connections: Socket[] = [];
  /** The subject CN of the certificate each TLS client presented, in order; empty for none. */
  readonly peers: string[] = [];
  /** The same, by the number of the connection that presented it. */
  readonly peerOn = new Map<number, string>();
  address = '';
  /** How many connections it took, the dropped ones counted. */
  accepted = 0;
  /** How many TCP connections reached it, a TLS handshake that failed counted. */
  reached = 0;
  private server: Server | null = null;

  /** What to answer a request with, beside the REGISTER's 200: null for nothing. */
  responder: ((message: string, socket: Socket) => string | null) | null = null;

  /** Over TLS given a certificate, with any other server option beside it (`requestCert`, `ca`, versions). */
  static async open(certificate?: TlsOptions & { cert: Buffer; key: Buffer }): Promise<StreamServer> {
    const made = new StreamServer();
    const serve = (socket: Socket): void => made.serve(socket);
    made.server = certificate === undefined ? createServer(serve) : createTlsServer({ ...certificate }, serve);
    made.server.on('connection', () => {
      made.reached += 1;
    });
    made.server.on('tlsClientError', () => undefined);
    await new Promise<void>((resolve) => made.server?.listen(0, '127.0.0.1', resolve));
    const bound = made.server.address();
    made.address = `127.0.0.1:${typeof bound === 'object' && bound !== null ? bound.port : 0}`;
    return made;
  }

  /** Every REGISTER, in order. */
  registers(): [number, string][] {
    return this.messages.filter(([, message]) => message.startsWith('REGISTER '));
  }

  /** Close every connection from this end, as a server that restarted does. */
  drop(): void {
    for (const socket of this.connections.splice(0)) {
      socket.destroy();
    }
  }

  async close(): Promise<void> {
    this.drop();
    await new Promise<void>((resolve) => this.server?.close(() => resolve()));
  }

  private serve(socket: Socket): void {
    this.connections.push(socket);
    this.accepted += 1;
    const connection = this.accepted;
    if (socket instanceof TLSSocket) {
      const presented = socket.getPeerCertificate(false);
      const name = typeof presented?.subject?.CN === 'string' ? presented.subject.CN : '';
      this.peers.push(name);
      this.peerOn.set(connection, name);
    }
    socket.on('error', () => undefined);
    socket.on(
      'data',
      framer((message) => {
        this.messages.push([connection, message]);
        if (message.startsWith('REGISTER ')) {
          socket.write(registered(message));
          return;
        }
        const reply = this.responder?.(message, socket) ?? null;
        if (reply !== null) {
          socket.write(reply);
        }
      }),
    );
  }
}

/** The name every certificate made here is for. */
export const SERVER_NAME = 'pbx.sipral.test';

/** A self-signed certificate valid for a day whose `subjectAltName` is `names` (`URI:sip:...`, `DNS:*.example`), or null without `openssl`. */
export function certificateNaming(names: string): { cert: Buffer; key: Buffer } | null {
  const directory = mkdtempSync(join(tmpdir(), 'sipral-tls-'));
  try {
    return selfSigned(directory, 'named', ['-days', '1'], names);
  } catch {
    return null;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

/**
 * A root, an intermediate it signs that may name `corp.test` and the names
 * under it alone, and a server certificate the intermediate signs, `names`
 * its `subjectAltName`, made with the `openssl` command, or null without
 * one: `cert` holds the intermediate after the server's certificate, so the
 * handshake sends both, and `root` is the authority to trust.
 */
export function constrainedChain(names: string): { cert: Buffer; key: Buffer; root: Buffer } | null {
  const directory = mkdtempSync(join(tmpdir(), 'sipral-tls-'));
  const path = (file: string): string => join(directory, file);
  // the key identifiers are what a strict verifier asks for
  const identified = 'subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid:always\n';
  try {
    writeFileSync(
      path('extensions.cnf'),
      '[authority]\nbasicConstraints = critical, CA:TRUE\nkeyUsage = critical, keyCertSign, cRLSign\n' +
        identified +
        '[constrained]\nbasicConstraints = critical, CA:TRUE\nkeyUsage = critical, keyCertSign, cRLSign\n' +
        `nameConstraints = critical, permitted;DNS:corp.test\n${identified}` +
        '[server]\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\n' +
        `extendedKeyUsage = serverAuth\nsubjectAltName = ${names}\n${identified}`,
    );
    const signed = (file: string, subject: string, section: string, by: string): Buffer => {
      execFileSync(
        'openssl',
        ['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-subj', subject, '-keyout', path(`${file}.key`), '-out', path(`${file}.csr`)],
        { stdio: 'ignore' },
      );
      const signer = file === by ? ['-signkey', path(`${file}.key`)] : ['-CA', path(`${by}.pem`), '-CAkey', path(`${by}.key`)];
      execFileSync(
        'openssl',
        [
          'x509',
          '-req',
          '-in',
          path(`${file}.csr`),
          ...signer,
          '-set_serial',
          String(randomBytes(4).readUInt32BE() | 1),
          '-extfile',
          path('extensions.cnf'),
          '-extensions',
          section,
          '-days',
          '1',
          '-out',
          path(`${file}.pem`),
        ],
        { stdio: 'ignore' },
      );
      return readFileSync(path(`${file}.pem`));
    };
    const root = signed('root', '/CN=Sipral Test Root', 'authority', 'root');
    const middle = signed('middle', '/CN=Sipral Test Corp', 'constrained', 'root');
    const server = signed('server', '/CN=pbx.corp.test', 'server', 'middle');
    return { cert: Buffer.concat([server, middle]), key: readFileSync(path('server.key')), root };
  } catch {
    return null;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

/** Self-signed certificates for {@link SERVER_NAME}, made with the `openssl` command, or null without one. */
export function certificates(): { good: { cert: Buffer; key: Buffer }; expired: { cert: Buffer; key: Buffer } } | null {
  const directory = mkdtempSync(join(tmpdir(), 'sipral-tls-'));
  try {
    const make = (name: string, extra: string[]): { cert: Buffer; key: Buffer } => selfSigned(directory, name, extra);
    return {
      good: make('good', ['-days', '1']),
      expired: make('expired', ['-not_before', '20200101000000Z', '-not_after', '20200102000000Z']),
    };
  } catch {
    return null;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

/** One self-signed certificate for {@link SERVER_NAME} made in `directory`, `names` its `subjectAltName`. */
function selfSigned(directory: string, name: string, extra: string[], names = `DNS:${SERVER_NAME}`): { cert: Buffer; key: Buffer } {
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:prime256v1',
      '-nodes',
      '-subj',
      `/CN=${SERVER_NAME}`,
      '-addext',
      `subjectAltName=${names}`,
      '-addext',
      'extendedKeyUsage=serverAuth',
      '-keyout',
      join(directory, `${name}.key`),
      '-out',
      join(directory, `${name}.pem`),
      ...extra,
    ],
    { stdio: 'ignore' },
  );
  return { cert: readFileSync(join(directory, `${name}.pem`)), key: readFileSync(join(directory, `${name}.key`)) };
}

/** A client certificate and the authority that signed it, as PEM, with the key's password where it has one. */
export interface ClientCertificates {
  /** The authority a server requiring client certificates trusts. */
  authority: Buffer;
  /** A certificate it signed for `CLIENT_NAME`, with `clientAuth`, and its key. */
  good: { cert: Buffer; key: Buffer };
  /** One it signed for `OTHER_CLIENT_NAME`. */
  other: { cert: Buffer; key: Buffer };
  /** The same certificate and key in one PKCS#12, and its password. */
  pfx: { pfx: Buffer; passphrase: string };
  /** One another authority signed. */
  stranger: { cert: Buffer; key: Buffer };
  /** One the authority signed that expired in 2020. */
  expired: { cert: Buffer; key: Buffer };
  /** The good certificate with the stranger's key. */
  mismatched: { cert: Buffer; key: Buffer };
}

/** The subject CN of every client certificate made here but one. */
export const CLIENT_NAME = 'alice-phone.sipral.test';

/** The subject CN of {@link ClientCertificates.other}. */
export const OTHER_CLIENT_NAME = 'bob-phone.sipral.test';

/** Client certificates made with the `openssl` command, or null without one. */
export function clientCertificates(): ClientCertificates | null {
  const directory = mkdtempSync(join(tmpdir(), 'sipral-client-tls-'));
  const at = (name: string): string => join(directory, name);
  const run = (...args: string[]): void => {
    execFileSync('openssl', args, { stdio: 'ignore' });
  };
  try {
    const authority = (name: string, cn: string): void =>
      run(
        'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
        '-subj', `/CN=${cn}`,
        '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign',
        '-keyout', at(`${name}.key`), '-out', at(`${name}.pem`),
      );
    authority('ca', 'Sipral test client authority');
    authority('other', 'Another authority');
    writeFileSync(at('client.ext'), 'extendedKeyUsage=clientAuth\n');
    const signed = (name: string, by: string, dates: string[], cn = CLIENT_NAME): void => {
      run(
        'req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-subj', `/CN=${cn}`,
        '-keyout', at(`${name}.key`), '-out', at(`${name}.csr`),
      );
      run(
        'x509', '-req', '-in', at(`${name}.csr`), '-CA', at(`${by}.pem`), '-CAkey', at(`${by}.key`), '-CAcreateserial',
        '-extfile', at('client.ext'), ...dates, '-out', at(`${name}.pem`),
      );
    };
    signed('good', 'ca', ['-days', '1']);
    signed('bobs', 'ca', ['-days', '1'], OTHER_CLIENT_NAME);
    signed('stranger', 'other', ['-days', '1']);
    signed('expired', 'ca', ['-not_before', '20200101000000Z', '-not_after', '20200102000000Z']);
    const passphrase = randomBytes(12).toString('hex');
    run('pkcs12', '-export', '-in', at('good.pem'), '-inkey', at('good.key'), '-out', at('good.p12'), '-passout', `pass:${passphrase}`);
    const pair = (name: string): { cert: Buffer; key: Buffer } => ({ cert: readFileSync(at(`${name}.pem`)), key: readFileSync(at(`${name}.key`)) });
    return {
      authority: readFileSync(at('ca.pem')),
      good: pair('good'),
      other: pair('bobs'),
      pfx: { pfx: readFileSync(at('good.p12')), passphrase },
      stranger: pair('stranger'),
      expired: pair('expired'),
      mismatched: { cert: readFileSync(at('good.pem')), key: readFileSync(at('stranger.key')) },
    };
  } catch {
    return null;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

/**
 * OpenSSL's own TLS server, `openssl s_server`, requiring a client
 * certificate `authority` signed: unlike Node's, which resets the
 * connection, it refuses a certificate with the alert TLS defines for why.
 * It answers nothing; `close` ends it.
 */
export class OpenSslServer {
  address = '';
  private child: ChildProcess | null = null;
  private directory = '';

  static async open(served: { cert: Buffer; key: Buffer }, authority: Buffer, version: '-tls1_2' | '-tls1_3'): Promise<OpenSslServer> {
    const made = new OpenSslServer();
    made.directory = mkdtempSync(join(tmpdir(), 'sipral-s-server-'));
    const at = (name: string): string => join(made.directory, name);
    writeFileSync(at('server.pem'), served.cert);
    writeFileSync(at('server.key'), served.key);
    writeFileSync(at('ca.pem'), authority);
    const probe = createServer();
    await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
    const port = (probe.address() as { port: number }).port;
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    const child = spawn(
      'openssl',
      [
        's_server', '-accept', `127.0.0.1:${port}`, version, '-Verify', '1', '-verify_return_error',
        '-CAfile', at('ca.pem'), '-cert', at('server.pem'), '-key', at('server.key'),
      ],
      { stdio: ['pipe', 'pipe', 'ignore'] },
    );
    made.child = child;
    await new Promise<void>((resolve, reject) => {
      let said = '';
      child.stdout?.on('data', (data: Buffer) => {
        said += data.toString();
        if (said.includes('ACCEPT')) {
          resolve();
        }
      });
      child.once('exit', () => reject(new Error('openssl s_server ended before it listened')));
    });
    made.address = `127.0.0.1:${port}`;
    return made;
  }

  async close(): Promise<void> {
    const child = this.child;
    this.child = null;
    if (child !== null && child.exitCode === null) {
      await new Promise<void>((resolve) => {
        child.once('exit', () => resolve());
        child.kill();
      });
    }
    rmSync(this.directory, { recursive: true, force: true });
  }
}

/**
 * A TCP relay to `target` that holds what each end sends for `delayMs`
 * before passing it on, as a long path would, each later segment from the
 * client 20 ms longer than the one before, as a path whose queue is filling
 * holds it. Bytes that reach a server
 * which has closed its end are answered the way its kernel answers them,
 * with a reset, and the reset is passed on at once, dropping whatever the
 * server sent that has not arrived yet -- as a client's kernel drops what
 * it held unread when the reset comes. What a client wrote before the
 * server's delayed answer reached it then loses it that answer.
 */
export class SlowPath {
  address = '';
  private server: Server | null = null;
  private readonly sockets: Socket[] = [];

  static async open(target: string, delayMs: number): Promise<SlowPath> {
    const made = new SlowPath();
    const [host, port] = [target.slice(0, target.lastIndexOf(':')), Number(target.slice(target.lastIndexOf(':') + 1))];
    made.server = createServer((client) => {
      const upstream = connectTcp({ host, port });
      made.sockets.push(client, upstream);
      client.on('error', () => undefined);
      upstream.on('error', () => client.resetAndDestroy());
      let segments = 0;
      client.on('data', (data: Buffer) => {
        setTimeout(() => {
          if (upstream.readableEnded) {
            upstream.destroy();
            client.resetAndDestroy();
          } else if (!upstream.destroyed) {
            upstream.write(data);
          }
        }, delayMs + 20 * segments++);
      });
      client.on('close', () => upstream.destroy());
      upstream.on('data', (data: Buffer) => {
        setTimeout(() => {
          if (!client.destroyed) {
            client.write(data);
          }
        }, delayMs);
      });
      upstream.on('end', () => setTimeout(() => client.end(), delayMs));
    });
    await new Promise<void>((resolve) => made.server?.listen(0, '127.0.0.1', resolve));
    made.address = `127.0.0.1:${(made.server.address() as { port: number }).port}`;
    return made;
  }

  async close(): Promise<void> {
    for (const socket of this.sockets.splice(0)) {
      socket.destroy();
    }
    await new Promise<void>((resolve) => this.server?.close(() => resolve()));
  }
}

/** Place a call from Alice to Bob, let both ends confirm it and their media start. */
export async function up(
  alice: Stack,
  bob: Stack,
  placed: Parameters<Stack['placeCall']>[2] = {},
  answered: Parameters<Stack['answerCall']>[1] = {},
): Promise<[Call, Call]> {
  const line = alice.addAccount('sip:alice@sipral.invalid', { registrarAddress: bob.bindAddress });
  bob.addAccount('sip:bob@sipral.invalid', { registrarAddress: alice.bindAddress });
  const ringing = kind(bob, SipralEventKind.IncomingCall);
  const callA = await alice.placeCall(line, `sip:bob@${bob.bindAddress}`, placed);
  const callB = await bob.answerCall(await ringing, answered);
  await Promise.all([callA.confirmed(15000), callB.confirmed(15000)]);
  await Promise.all([callA.mediaStarted(), callB.mediaStarted()]);
  return [callA, callB];
}

/** STUN (RFC 8489): a Binding success answering every request, naming `mapped`. */
export class StunServer {
  readonly socket: DatagramSocket = createSocket('udp4');
  address = '';
  requests = 0;

  static async open(mappedHost: string, mappedPort: number): Promise<StunServer> {
    const made = new StunServer();
    await new Promise<void>((resolve) => made.socket.bind(0, '127.0.0.1', resolve));
    made.address = `127.0.0.1:${made.socket.address().port}`;
    made.socket.on('message', (data: Buffer, from) => {
      if (data.length < 20 || data.readUInt16BE(0) !== 0x0001) {
        return;
      }
      made.requests += 1;
      const cookie = 0x2112a442;
      const value = Buffer.alloc(8);
      value.writeUInt8(0, 0);
      value.writeUInt8(1, 1);
      value.writeUInt16BE(mappedPort ^ (cookie >>> 16), 2);
      const octets = mappedHost.split('.').map(Number);
      const address = (((octets[0] ?? 0) << 24) | ((octets[1] ?? 0) << 16) | ((octets[2] ?? 0) << 8) | (octets[3] ?? 0)) >>> 0;
      value.writeUInt32BE((address ^ cookie) >>> 0, 4);
      const attribute = Buffer.alloc(4);
      attribute.writeUInt16BE(0x0020, 0);
      attribute.writeUInt16BE(value.length, 2);
      const head = Buffer.alloc(20);
      head.writeUInt16BE(0x0101, 0);
      head.writeUInt16BE(attribute.length + value.length, 2);
      data.copy(head, 4, 4, 20);
      made.socket.send(Buffer.concat([head, attribute, value]), from.port, from.address);
    });
    return made;
  }

  close(): void {
    this.socket.close();
  }
}
