// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Registration against a registrar simulated on a UDP socket: the first
// REGISTER is challenged 401 with a digest nonce (RFC 3261 §22.4), the
// second must carry an Authorization whose response is the RFC 2617 digest
// of the account's own password, and is then taken 200 with the binding;
// an unregister is a REGISTER with Expires 0.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { type Socket, createSocket } from 'node:dgram';
import { after, before, test } from 'node:test';

import { SipralEventKind, SipralRegistrationState, Stack } from '../index.js';

const REALM = 'registrar.example';
const NONCE = 'a1b2c3d4';

function header(message: string, name: string): string | null {
  for (const line of message.split('\r\n')) {
    if (line.toLowerCase().startsWith(`${name.toLowerCase()}:`)) {
      return line.slice(line.indexOf(':') + 1).trim();
    }
  }
  return null;
}

function parameter(value: string, name: string): string | null {
  const found = new RegExp(`${name}="?([^",]*)"?`).exec(value);
  return found?.[1] ?? null;
}

function md5(text: string): string {
  return createHash('md5').update(text).digest('hex');
}

/** A registrar that challenges, checks the digest, and keeps every request. */
class Registrar {
  readonly requests: string[] = [];
  readonly verified: boolean[] = [];
  private readonly socket: Socket = createSocket('udp4');

  async open(): Promise<void> {
    await new Promise<void>((resolve) => this.socket.bind(0, '127.0.0.1', () => resolve()));
    this.socket.on('message', (data, from) => this.answer(data.toString('utf8'), from.address, from.port));
  }

  get address(): string {
    return `127.0.0.1:${this.socket.address().port}`;
  }

  close(): void {
    this.socket.close();
  }

  private answer(message: string, host: string, port: number): void {
    if (!message.startsWith('REGISTER ')) {
      return;
    }
    this.requests.push(message);
    const authorization = header(message, 'Authorization');
    const lines: string[] = [];
    if (authorization === null) {
      lines.push('SIP/2.0 401 Unauthorized');
    } else {
      const uri = parameter(authorization, 'uri') ?? '';
      const nc = parameter(authorization, 'nc');
      const cnonce = parameter(authorization, 'cnonce');
      const qop = parameter(authorization, 'qop');
      const a1 = md5(`alice:${REALM}:open sesame`);
      const a2 = md5(`REGISTER:${uri}`);
      const expected =
        qop === null ? md5(`${a1}:${NONCE}:${a2}`) : md5(`${a1}:${NONCE}:${nc}:${cnonce}:${qop}:${a2}`);
      const good = parameter(authorization, 'response') === expected;
      this.verified.push(good);
      lines.push(good ? 'SIP/2.0 200 OK' : 'SIP/2.0 403 Forbidden');
    }
    for (const name of ['Via', 'From', 'To', 'Call-ID', 'CSeq']) {
      const value = header(message, name) ?? '';
      lines.push(name === 'To' ? `To: ${value};tag=registrar` : `${name}: ${value}`);
    }
    if (authorization === null) {
      lines.push(`WWW-Authenticate: Digest realm="${REALM}", nonce="${NONCE}", qop="auth", algorithm=MD5`);
    } else {
      const expires = header(message, 'Expires') ?? '3600';
      const contact = header(message, 'Contact') ?? '';
      if (expires !== '0') {
        lines.push(`Contact: ${contact.split(';expires=')[0]};expires=${expires}`);
      }
    }
    lines.push('Content-Length: 0', '', '');
    this.socket.send(Buffer.from(lines.join('\r\n')), port, host);
  }
}

let registrar: Registrar;
let stack: Stack;

before(async () => {
  registrar = new Registrar();
  await registrar.open();
  stack = await Stack.open({ bindHost: '127.0.0.1' });
});

after(async () => {
  await stack.close();
  registrar.close();
});

test('an account registers through a digest challenge, and unregisters', async () => {
  const account = stack.addAccount('sip:alice@registrar.example', {
    registrarAddress: registrar.address,
    registrar: 'sip:registrar.example',
    authUser: 'alice',
    authPassword: 'open sesame',
  });
  const states: number[] = [];
  account.on('registration', (state) => states.push(state));
  await account.registered(10000);

  assert.equal(account.registrationState, SipralRegistrationState.Registered);
  assert.ok(registrar.requests.length >= 2, `${registrar.requests.length} REGISTERs`);
  assert.equal(header(registrar.requests[0] ?? '', 'Authorization'), null);
  assert.deepEqual(registrar.verified, [true]);
  assert.ok(states.includes(SipralRegistrationState.Registered));

  const gone = stack.next(
    (event) =>
      event.kind === SipralEventKind.RegistrationChanged &&
      event.registrationState === SipralRegistrationState.Unregistered,
  );
  account.unregister();
  await gone;
  const last = registrar.requests[registrar.requests.length - 1] ?? '';
  assert.ok(header(last, 'Expires') === '0' || /expires=0/.test(header(last, 'Contact') ?? ''), last);
});
