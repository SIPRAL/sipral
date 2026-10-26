// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// An account's RFC 5626 instance id and its own header fields on every
// REGISTER it sends: a push proxy (RFC 8599) refuses one whose `Contact` has
// no `+sip.instance`. A loopback registrar challenges the first REGISTER,
// grants the answer for a few seconds so the refresh comes soon, and keeps
// every REGISTER once, the de-registration included, a retransmission
// answered as the request it repeats.

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, test } from 'node:test';

import { SipralError, SipralStatus, Stack } from '../index.js';
import { Peer, answer, header } from './helpers.js';

const URN = 'urn:uuid:f81d4fae-7ced-11d0-a765-00a0c91e6bf6';

let stacks: Stack[] = [];
let registrar: Peer;
let registers: string[] = [];

beforeEach(async () => {
  stacks = [];
  registers = [];
  const seen = new Set<string | null>();
  registrar = await Peer.open();
  registrar.responder = (message) => {
    if (!message.startsWith('REGISTER ')) {
      return null;
    }
    // a stack slowed down retransmits before the answer lands
    if (!seen.has(header('CSeq', message))) {
      seen.add(header('CSeq', message));
      registers.push(message);
    }
    if (header('Authorization', message) === null && registers.length === 1) {
      return answer(message, '401 Unauthorized', 'registrar', 'WWW-Authenticate: Digest realm="example.com", nonce="n1", qop="auth"\r\n');
    }
    const expires = header('Expires', message) === '0' ? '0' : '4';
    return answer(message, '200 OK', 'registrar', `Contact: ${header('Contact', message)};expires=${expires}\r\n`);
  };
});

afterEach(async () => {
  for (const stack of stacks) {
    await stack.close();
  }
  registrar.close();
});

async function until(count: number, ms: number): Promise<void> {
  const deadline = Date.now() + ms;
  while (registers.length < count && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

describe("an account's instance and fields", () => {
  test('ride on the first REGISTER, the answer to a challenge, the refresh and the de-registration', async () => {
    const stack = await Stack.open({ bindHost: '127.0.0.1' });
    stacks.push(stack);
    const account = stack.addAccount('sip:alice@example.com', {
      registrarAddress: registrar.address,
      registrar: 'sip:example.com',
      authUser: 'alice',
      authPassword: 'open sesame',
      instanceId: URN,
      headers: [['X-Push-Key', 'k-17']],
    });
    account.register();
    await until(3, 10_000);
    assert.ok(registers.length >= 3, registers.join('\n---\n'));
    account.unregister();
    await until(4, 5_000);
    assert.ok(registers.length >= 4, registers.join('\n---\n'));

    const [first, answered, refresh, goodbye] = registers as [string, string, string, string];
    assert.equal(header('Authorization', first), null);
    assert.notEqual(header('Authorization', answered), null);
    assert.equal(header('Expires', goodbye), '0');
    for (const request of [first, answered, refresh, goodbye]) {
      assert.equal(header('X-Push-Key', request), 'k-17');
      assert.ok((header('Contact', request) ?? '').includes(`+sip.instance="<${URN}>"`), request);
    }
  });

  test('a field the stack writes itself is refused', async () => {
    const stack = await Stack.open({ bindHost: '127.0.0.1' });
    stacks.push(stack);
    assert.throws(
      () =>
        stack.addAccount('sip:alice@example.com', {
          registrarAddress: '127.0.0.1:5060',
          registrar: 'sip:example.com',
          headers: [['Expires', '60']],
        }),
      (error: unknown) => error instanceof SipralError && error.status === SipralStatus.InvalidArgument,
    );
  });
});
