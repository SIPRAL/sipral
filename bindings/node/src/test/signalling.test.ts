// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// SIP over TCP and TLS, against this test's own registrar on loopback: a
// stack signalling over a connection registers on it, trusts a server by
// its authority or by its pin and says why it refused one, connects again
// when the connection is lost; an account on a connection of its own
// beside a UDP stack; and a request too large for a datagram, which goes on
// a connection the stack opens or ends the call at once.

import assert from 'node:assert/strict';
import { X509Certificate, createHash } from 'node:crypto';
import { type AddressInfo, createServer } from 'node:net';
import { after, describe, test } from 'node:test';

import {
  type Call,
  SipralCallEndReason,
  SipralEventKind,
  SipralRegistrationState,
  SipralTlsFailure,
  SipralTransport,
  SipralTransportError,
  Stack,
  type StackOptions,
  TlsTrust,
} from '../index.js';
import { Peer, SERVER_NAME, StreamServer, answer, certificates, header, kind, until } from './helpers.js';

const made = certificates();
const opened: Stack[] = [];
const servers: StreamServer[] = [];

async function stack(options: StackOptions): Promise<Stack> {
  const one = await Stack.open(options);
  opened.push(one);
  return one;
}

async function server(certificate?: { cert: Buffer; key: Buffer }): Promise<StreamServer> {
  const one = await StreamServer.open(certificate);
  servers.push(one);
  return one;
}

/** Register `aor` on `on` and wait for the registrar's 200. */
async function registers(on: Stack, aor: string): Promise<void> {
  const account = on.addAccount(aor, { registrarAddress: on.bindAddress, registrar: 'sip:sipral.test' });
  await account.registered();
}

after(async () => {
  for (const one of opened.splice(0)) {
    await one.close();
  }
  for (const one of servers.splice(0)) {
    await one.close();
  }
});

describe('a stack signalling over TCP', () => {
  test('registers on its one connection and says so in its Contact', async () => {
    const registrar = await server();
    const alice = await stack({ signalling: SipralTransport.Tcp, signallingServer: registrar.address });
    assert.ok(alice.connected);
    const account = alice.addAccount('sip:alice@sipral.test', { registrarAddress: registrar.address, registrar: 'sip:sipral.test' });
    await account.registered();
    const [[, register]] = registrar.registers() as [[number, string]];
    assert.match(header('Contact', register) ?? '', /transport=tcp/);
    assert.match(header('Via', register) ?? '', /^SIP\/2\.0\/TCP /);
  });

  test('connects again when the server drops it, and registers again on the new one', async () => {
    const registrar = await server();
    const alice = await stack({ signalling: SipralTransport.Tcp, signallingServer: registrar.address });
    const account = alice.addAccount('sip:alice@sipral.test', { registrarAddress: registrar.address, registrar: 'sip:sipral.test' });
    await account.registered();
    registrar.drop();
    await until(() => registrar.registers().some(([connection]) => connection === 2), 10000);
    assert.equal(account.registrationState, SipralRegistrationState.Registered);
  });

  test('nobody listening is a refused connection, with no TLS reason', async () => {
    const registrar = await server();
    const address = registrar.address;
    await registrar.close();
    servers.splice(servers.indexOf(registrar), 1);
    const failed = Stack.open({ signalling: SipralTransport.Tcp, signallingServer: address }).then((alice) => {
      opened.push(alice);
      return kind(alice, SipralEventKind.TransportFailed);
    });
    const event = await failed;
    assert.equal(event.fields.error, SipralTransportError.ConnectionRefused);
    assert.equal(event.fields.tls, SipralTlsFailure.None);
  });
});

describe('a stack signalling over TLS', { skip: made === null ? 'no openssl command to make a certificate with' : false }, () => {
  const certificate = made?.good as { cert: Buffer; key: Buffer };
  const expired = made?.expired as { cert: Buffer; key: Buffer };

  test('registers on a server whose one authority it trusts', async () => {
    const registrar = await server(certificate);
    const alice = await stack({
      signalling: SipralTransport.Tls,
      signallingServer: registrar.address,
      tlsServerName: SERVER_NAME,
      tlsTrust: TlsTrust.onlyAuthority(certificate.cert),
    });
    await registers(alice, 'sip:alice@sipral.test');
    const [[, register]] = registrar.registers() as [[number, string]];
    assert.match(header('Contact', register) ?? '', /transport=tls/);
  });

  test('trusts a private authority beside the platform', async () => {
    const registrar = await server(certificate);
    const alice = await stack({
      signalling: SipralTransport.Tls,
      signallingServer: registrar.address,
      tlsServerName: SERVER_NAME,
      tlsTrust: TlsTrust.privateAuthority(certificate.cert),
    });
    await registers(alice, 'sip:alice@sipral.test');
  });

  test('trusts the pinned certificate whatever its name and signer, and no other', async () => {
    const registrar = await server(certificate);
    const fingerprint = new X509Certificate(certificate.cert).fingerprint256;
    const alice = await stack({ signalling: SipralTransport.Tls, signallingServer: registrar.address, tlsTrust: TlsTrust.pinned(fingerprint) });
    await registers(alice, 'sip:alice@sipral.test');
    const other = createHash('sha256').update('another certificate').digest('hex');
    const refused = await Stack.open({
      signalling: SipralTransport.Tls,
      signallingServer: registrar.address,
      tlsTrust: TlsTrust.pinned(other),
    }).then((bob) => {
      opened.push(bob);
      return kind(bob, SipralEventKind.TransportFailed);
    });
    assert.equal(refused.fields.tls, SipralTlsFailure.Untrusted);
  });

  test('says why it refused a server: untrusted, another name, expired, no TLS at all', async () => {
    const cases: [StackOptions, { cert: Buffer; key: Buffer } | undefined, number][] = [
      [{ tlsServerName: SERVER_NAME }, certificate, SipralTlsFailure.Untrusted],
      [{ tlsServerName: 'other.sipral.test', tlsTrust: TlsTrust.onlyAuthority(certificate.cert) }, certificate, SipralTlsFailure.NameMismatch],
      [{ tlsServerName: SERVER_NAME, tlsTrust: TlsTrust.onlyAuthority(expired.cert) }, expired, SipralTlsFailure.Expired],
      [{ tlsServerName: SERVER_NAME }, undefined, SipralTlsFailure.HandshakeRefused],
    ];
    for (const [options, served, expected] of cases) {
      let address: string;
      if (served === undefined) {
        // a server that answers a TLS client in plain text
        const plain = createServer((socket) => {
          socket.on('error', () => undefined);
          socket.once('data', () => socket.end('SIP/2.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n'));
        });
        await new Promise<void>((resolve) => plain.listen(0, '127.0.0.1', resolve));
        after(() => plain.close());
        address = `127.0.0.1:${(plain.address() as AddressInfo).port}`;
      } else {
        address = (await server(served)).address;
      }
      const alice = await Stack.open({ signalling: SipralTransport.Tls, signallingServer: address, ...options });
      opened.push(alice);
      const event = await kind(alice, SipralEventKind.TransportFailed);
      assert.equal(event.fields.tls, expected, String(event.fields.detail));
      assert.ok(typeof event.fields.detail === 'string' && event.fields.detail.length > 0);
    }
  });

  test('options that check nothing are refused', () => {
    assert.throws(() => TlsTrust.fromOptions({ rejectUnauthorized: false }), TypeError);
  });

  test("an account's pin decides on the certificate a server presented", async () => {
    const alice = await stack({ bindHost: '127.0.0.1' });
    const der = new X509Certificate(certificate.cert).raw;
    const pinned = alice.addAccount('sip:alice@sipral.test', {
      registrarAddress: '127.0.0.1:5061',
      tlsPin: new X509Certificate(certificate.cert).fingerprint256,
    });
    const verdict = pinned.checkCertificate(der);
    assert.ok(verdict !== null && verdict.notAfter > verdict.notBefore && !verdict.expired);
    const unpinned = alice.addAccount('sip:bob@sipral.test', { registrarAddress: '127.0.0.1:5061' });
    assert.equal(unpinned.checkCertificate(der), null);
  });
});

describe('an account on a connection of its own, beside a stack on UDP', () => {
  test('registers over TCP while the stack stays on UDP', async () => {
    const registrar = await server();
    const alice = await stack({ bindHost: '127.0.0.1' });
    const account = alice.addAccount('sip:alice@sipral.test', {
      registrarAddress: registrar.address,
      registrar: 'sip:sipral.test',
      streamProtocol: SipralTransport.Tcp,
    });
    await account.registered();
    const [[, register]] = registrar.registers() as [[number, string]];
    assert.match(header('Contact', register) ?? '', /transport=tcp/);
    assert.throws(() =>
      alice.addAccount('sip:carol@sipral.test', { registrarAddress: registrar.address, streamProtocol: SipralTransport.Udp }),
    );
  });
});

describe('an answer to a challenge too large for a datagram', () => {
  /**
   * A PBX on UDP that challenges every INVITE without credentials with a
   * nonce long enough that the `Authorization` answering it takes the
   * INVITE past RFC 3261 §18.1.1's line.
   */
  async function challenging(): Promise<Peer> {
    const pbx = await Peer.open();
    pbx.responder = (message) =>
      message.startsWith('INVITE ') && header('Authorization', message) === null
        ? answer(message, '401 Unauthorized', 'pbx', `WWW-Authenticate: Digest realm="pbx", nonce="${'n'.repeat(700)}", qop="auth"\r\n`)
        : null;
    after(() => pbx.close());
    return pbx;
  }

  async function place(alice: Stack, pbx: Peer): Promise<Call> {
    const line = alice.addAccount('sip:alice@sipral.test', {
      registrarAddress: pbx.address,
      authUser: 'alice',
      authPassword: 'secret',
    });
    return alice.placeCall(line, `sip:bob@${pbx.address}`, { headers: { 'X-Padding': 'x'.repeat(300) } });
  }

  test('goes on a TCP connection the stack opened, to the stream server named', async () => {
    const pbx = await challenging();
    const tcp = await server();
    tcp.responder = (message) => (message.startsWith('INVITE ') ? answer(message, '486 Busy Here', 'pbx') : null);
    const alice = await stack({ bindHost: '127.0.0.1', streamServer: tcp.address });
    const wanted = kind(alice, SipralEventKind.TransportWanted);
    const call = await place(alice, pbx);
    const asked = await wanted;
    assert.ok((asked.fields.requestBytes as number) > (asked.fields.limitBytes as number));
    const ended = await call.next((event) => event.kind === SipralEventKind.CallEnded);
    assert.equal(ended.statusCode, 486);
    const invite = tcp.messages.find(([, message]) => message.startsWith('INVITE '))?.[1] ?? '';
    assert.ok(header('Authorization', invite) !== null);
    call.close();
  });

  test('ends the call at once, the limit named, when no stream is to be opened', async () => {
    const pbx = await challenging();
    const alice = await stack({ bindHost: '127.0.0.1', streamFallback: false });
    const call = await place(alice, pbx);
    const ended = await call.next((event) => event.kind === SipralEventKind.CallEnded);
    assert.equal(ended.endReason, SipralCallEndReason.Unreachable);
    assert.equal(ended.fields.causeSip, 513);
    call.close();
  });
});
