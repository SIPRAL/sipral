// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// A client certificate on SIP over TLS, against servers on loopback that
// require one: this test's registrar on Node's TLS, which takes a
// certificate its authority signed and registers the stack, and OpenSSL's
// own server, which refuses one with the alert TLS defines for why. Each
// refusal arrives as `TransportFailed` with its own reason; a certificate
// that is out of its dates or whose key cannot be used is refused before
// anything reaches the server.

import assert from 'node:assert/strict';
import { after, describe, test } from 'node:test';

import {
  type ClientCertificate,
  SipralEventKind,
  SipralTlsFailure,
  SipralTransport,
  SipralTransportError,
  Stack,
  type StackOptions,
  TlsTrust,
  classify,
} from '../index.js';
import { CLIENT_NAME, OTHER_CLIENT_NAME, OpenSslServer, SERVER_NAME, SlowPath, StreamServer, certificates, clientCertificates, header, kind, until } from './helpers.js';

const served = certificates();
const clients = clientCertificates();
const opened: Stack[] = [];
const servers: { close(): Promise<void> }[] = [];

after(async () => {
  for (const one of opened.splice(0)) {
    await one.close();
  }
  for (const one of servers.splice(0)) {
    await one.close();
  }
});

const skip = served === null || clients === null ? 'no openssl command to make the certificates with' : false;

describe('a client certificate on SIP over TLS', { skip }, () => {
  const certificate = served?.good as { cert: Buffer; key: Buffer };
  const made = clients as NonNullable<typeof clients>;

  /** This test's registrar at TLS 1.3, requiring a certificate the client authority signed. */
  async function requiring(): Promise<StreamServer> {
    const one = await StreamServer.open({
      ...certificate,
      requestCert: true,
      rejectUnauthorized: true,
      ca: made.authority,
      minVersion: 'TLSv1.3',
    });
    servers.push(one);
    return one;
  }

  /** A stack signalling over TLS to `address`, trusting the server's certificate alone. */
  async function signalling(address: string, clientCertificate?: ClientCertificate): Promise<Stack> {
    const options: StackOptions = {
      signalling: SipralTransport.Tls,
      signallingServer: address,
      tlsServerName: SERVER_NAME,
      tlsTrust: TlsTrust.onlyAuthority(certificate.cert),
    };
    const one = await Stack.open(clientCertificate === undefined ? options : { ...options, clientCertificate });
    opened.push(one);
    return one;
  }

  test('presents its certificate in PEM and registers', async () => {
    const registrar = await requiring();
    const alice = await signalling(registrar.address, made.good);
    const account = alice.addAccount('sip:alice@sipral.test', { registrarAddress: registrar.address, registrar: 'sip:sipral.test' });
    await account.registered();
    assert.deepEqual(registrar.peers.slice(0, 1), [CLIENT_NAME]);
    const [[, register]] = registrar.registers() as [[number, string]];
    assert.match(header('Contact', register) ?? '', /transport=tls/);
  });

  test('presents its certificate from a PKCS#12 and registers', async () => {
    const registrar = await requiring();
    const alice = await signalling(registrar.address, made.pfx);
    const account = alice.addAccount('sip:alice@sipral.test', { registrarAddress: registrar.address, registrar: 'sip:sipral.test' });
    await account.registered();
    assert.equal(registrar.peers[0], CLIENT_NAME);
  });

  test('with no certificate, the server requiring one is said to require it', async () => {
    const registrar = await requiring();
    const alice = await signalling(registrar.address);
    const event = await kind(alice, SipralEventKind.TransportFailed);
    assert.equal(event.fields.tls, SipralTlsFailure.ClientCertificateRequired, String(event.fields.detail));
    assert.equal(event.fields.error, SipralTransportError.ConnectionReset);
    assert.equal(registrar.registers().length, 0);
  });

  test('registering at once over a slow path still hears why TLS 1.3 refused it', async () => {
    // the server's answers take 150 ms to arrive, so a REGISTER written as
    // soon as this end's handshake ends would reach a server that has
    // refused already, and its reset would overtake the alert saying why
    for (const presents of [undefined, made.stranger]) {
      const refusing = presents === undefined ? await requiring() : await OpenSslServer.open(certificate, made.authority, '-tls1_3');
      if (presents !== undefined) {
        servers.push(refusing);
      }
      const path = await SlowPath.open(refusing.address, 150);
      servers.push(path);
      const opening = Stack.open({
        signalling: SipralTransport.Tls,
        signallingServer: path.address,
        tlsServerName: SERVER_NAME,
        tlsTrust: TlsTrust.onlyAuthority(certificate.cert),
        ...(presents === undefined ? {} : { clientCertificate: presents }),
      });
      const alice = await opening;
      opened.push(alice);
      const failed = kind(alice, SipralEventKind.TransportFailed);
      // an application that registers a moment after the stack opened
      await new Promise((resolve) => setTimeout(resolve, 20));
      alice.addAccount('sip:alice@sipral.test', { registrarAddress: path.address, registrar: 'sip:sipral.test' }).register();
      const event = await failed;
      const expected = presents === undefined ? SipralTlsFailure.ClientCertificateRequired : SipralTlsFailure.ClientCertificateRefused;
      assert.equal(event.fields.tls, expected, String(event.fields.detail));
    }
  });

  for (const version of ['-tls1_3', '-tls1_2'] as const) {
    test(`a certificate another authority signed is refused, by its alert (${version.slice(1)})`, async () => {
      const refusing = await OpenSslServer.open(certificate, made.authority, version);
      servers.push(refusing);
      const alice = await signalling(refusing.address, made.stranger);
      const event = await kind(alice, SipralEventKind.TransportFailed);
      assert.equal(event.fields.tls, SipralTlsFailure.ClientCertificateRefused, String(event.fields.detail));
      assert.match(String(event.fields.detail), /unknown ca/i);
    });
  }

  test('an expired certificate is refused before anything reaches the server', async () => {
    const registrar = await requiring();
    const alice = await signalling(registrar.address, made.expired);
    const event = await kind(alice, SipralEventKind.TransportFailed);
    assert.equal(event.fields.tls, SipralTlsFailure.ClientCertificateExpired, String(event.fields.detail));
    assert.equal(event.fields.error, SipralTransportError.Other);
    assert.equal(registrar.reached, 0);
  });

  test("a key that is not the certificate's, a wrong password or no key at all is a key unavailable", async () => {
    const registrar = await requiring();
    const unusable: ClientCertificate[] = [
      made.mismatched,
      { pfx: made.pfx.pfx, passphrase: 'not the password' },
      { cert: made.good.cert },
    ];
    for (const one of unusable) {
      const alice = await signalling(registrar.address, one);
      const event = await kind(alice, SipralEventKind.TransportFailed);
      assert.equal(event.fields.tls, SipralTlsFailure.ClientKeyUnavailable, String(event.fields.detail));
      assert.equal(event.fields.error, SipralTransportError.Other);
    }
    assert.equal(registrar.reached, 0);
  });

  test('an account on a TLS connection of its own presents its own certificate', async () => {
    const registrar = await requiring();
    const alice = await Stack.open({ bindHost: '127.0.0.1', tlsServerName: SERVER_NAME, tlsTrust: TlsTrust.onlyAuthority(certificate.cert) });
    opened.push(alice);
    const account = alice.addAccount('sip:alice@sipral.test', {
      registrarAddress: registrar.address,
      registrar: 'sip:sipral.test',
      streamProtocol: SipralTransport.Tls,
      clientCertificate: made.good,
    });
    await account.registered();
    assert.equal(registrar.peers[0], CLIENT_NAME);
  });

  test('accounts with certificates of their own at one server each present their own', async () => {
    // a connection presents one certificate, and the server takes all it
    // carries as from the user that one names
    const registrar = await requiring();
    const stack = await Stack.open({
      bindHost: '127.0.0.1',
      tlsServerName: SERVER_NAME,
      tlsTrust: TlsTrust.onlyAuthority(certificate.cert),
      clientCertificate: made.stranger,
    });
    opened.push(stack);
    const users = [
      ['alice', made.good, CLIENT_NAME],
      ['bob', made.other, OTHER_CLIENT_NAME],
    ] as const;
    const accounts = users.map(([user, mine]) =>
      stack.addAccount(`sip:${user}@sipral.test`, {
        registrarAddress: registrar.address,
        registrar: 'sip:sipral.test',
        streamProtocol: SipralTransport.Tls,
        clientCertificate: mine,
      }),
    );
    await Promise.all(accounts.map((account) => account.registered()));
    for (const [user, , name] of users) {
      const theirs = registrar
        .registers()
        .filter(([, message]) => (header('From', message) ?? '').includes(`sip:${user}@`))
        .map(([connection]) => registrar.peerOn.get(connection));
      assert.ok(theirs.length > 0, `${user} never registered`);
      assert.deepEqual(new Set(theirs), new Set([name]), `${user}'s REGISTER came on a connection that presented ${theirs.join(', ')}`);
    }
  });

  test('an account on a TLS connection of its own with no certificate is said to need one', async () => {
    const registrar = await requiring();
    const alice = await Stack.open({ bindHost: '127.0.0.1', tlsServerName: SERVER_NAME, tlsTrust: TlsTrust.onlyAuthority(certificate.cert) });
    opened.push(alice);
    const failed = kind(alice, SipralEventKind.TransportFailed);
    const account = alice.addAccount('sip:alice@sipral.test', {
      registrarAddress: registrar.address,
      registrar: 'sip:sipral.test',
      streamProtocol: SipralTransport.Tls,
    });
    account.register();
    const event = await failed;
    assert.equal(event.fields.tls, SipralTlsFailure.ClientCertificateRequired, String(event.fields.detail));
    await until(() => registrar.reached > 0);
  });
});

describe('the alerts a server sends about the client certificate', () => {
  const alert = (code: string): Error => Object.assign(new Error(code), { code });

  test('are refused when one was presented, required when none was', () => {
    for (const code of [
      'ERR_SSL_SSLV3_ALERT_BAD_CERTIFICATE',
      'ERR_SSL_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE',
      'ERR_SSL_SSLV3_ALERT_CERTIFICATE_REVOKED',
      'ERR_SSL_SSLV3_ALERT_CERTIFICATE_UNKNOWN',
      'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA',
      'ERR_SSL_TLSV1_ALERT_ACCESS_DENIED',
      'ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED',
    ]) {
      assert.equal(classify(alert(code), true).tls, SipralTlsFailure.ClientCertificateRefused, code);
      assert.equal(classify(alert(code), false).tls, SipralTlsFailure.ClientCertificateRequired, code);
    }
  });

  test('certificate_expired is the client certificate expired only when one was presented', () => {
    const code = 'ERR_SSL_SSLV3_ALERT_CERTIFICATE_EXPIRED';
    assert.equal(classify(alert(code), true).tls, SipralTlsFailure.ClientCertificateExpired);
    assert.equal(classify(alert(code), false).tls, SipralTlsFailure.HandshakeRefused);
  });

  test("handshake_failure stays a handshake refused, and the server's own certificate keeps its reasons", () => {
    assert.equal(classify(alert('ERR_SSL_TLS_ALERT_HANDSHAKE_FAILURE'), false).tls, SipralTlsFailure.HandshakeRefused);
    assert.equal(classify(alert('CERT_HAS_EXPIRED'), true).tls, SipralTlsFailure.Expired);
    assert.equal(classify(alert('UNABLE_TO_GET_ISSUER_CERT_LOCALLY'), true).tls, SipralTlsFailure.Untrusted);
  });
});
