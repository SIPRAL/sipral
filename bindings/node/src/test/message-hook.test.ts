// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The message hook: a header added to an INVITE on its way out, a response
// stopped on its way in, and a hook that throws. A loopback PBX on UDP
// answers every INVITE 486 and keeps what it received.

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, test } from 'node:test';

import { type Call, MessageVerdict, SipralEventKind, Stack } from '../index.js';
import { Peer, answer, header } from './helpers.js';

let stacks: Stack[] = [];
let calls: Call[] = [];
let pbx: Peer;
let received: string[] = [];

beforeEach(async () => {
  stacks = [];
  calls = [];
  received = [];
  pbx = await Peer.open();
  pbx.responder = (message) => {
    received.push(message);
    return message.startsWith('INVITE ') ? answer(message, '486 Busy Here', 'pbx') : null;
  };
});

afterEach(async () => {
  for (const call of calls) {
    call.close();
  }
  for (const stack of stacks) {
    await stack.close();
  }
  pbx.close();
});

async function open(): Promise<Stack> {
  const made = await Stack.open({ bindHost: '127.0.0.1', codecs: 'PCMU' });
  stacks.push(made);
  return made;
}

async function place(stack: Stack): Promise<Call> {
  const account = stack.addAccount('sip:alice@example.com', { registrarAddress: pbx.address });
  const call = await stack.placeCall(account, 'sip:bob@example.com');
  calls.push(call);
  return call;
}

function withHeader(message: Buffer, line: string): Buffer {
  const text = message.toString('utf8');
  const end = text.indexOf('\r\n\r\n');
  return Buffer.from(`${text.slice(0, end)}\r\n${line}${text.slice(end)}`);
}

const invites = (): string[] => received.filter((message) => message.startsWith('INVITE '));

describe('the message hook', () => {
  test('adds a header to an outgoing INVITE that reaches the PBX', async () => {
    const stack = await open();
    const remotes: string[] = [];
    stack.setMessageHook((outgoing, message, remote) => {
      remotes.push(remote);
      return outgoing && message.toString('utf8').startsWith('INVITE ')
        ? MessageVerdict.replace(withHeader(message, 'X-Tenant: blue'))
        : MessageVerdict.keep;
    });
    const call = await place(stack);
    const ended = await call.next((event) => event.kind === SipralEventKind.CallEnded, 8000);
    assert.equal(ended.statusCode, 486);
    assert.equal(invites().length, 1);
    assert.equal(header('X-Tenant', invites()[0] as string), 'blue');
    assert.ok(remotes.length > 0 && remotes.every((remote) => remote === pbx.address), String(remotes));
  });

  test('drops an incoming response, which is not read', async () => {
    const stack = await open();
    let dropped = 0;
    stack.setMessageHook((outgoing, message) => {
      if (!outgoing && message.toString('utf8').startsWith('SIP/2.0 486')) {
        dropped += 1;
        return MessageVerdict.drop;
      }
      return MessageVerdict.keep;
    });
    const call = await place(stack);
    let over = false;
    const ended = call.next((event) => event.kind === SipralEventKind.CallEnded, 10000).then((event) => {
      over = true;
      return event;
    });
    await new Promise((resolve) => setTimeout(resolve, 1500));
    assert.equal(over, false);
    assert.ok(dropped > 0);

    stack.setMessageHook(null);
    assert.equal((await ended).statusCode, 486);
  });

  test('that throws keeps the message, and the error is reported', async () => {
    const stack = await open();
    const reported: Error[] = [];
    stack.on('error', (error) => reported.push(error));
    stack.setMessageHook(() => {
      throw new Error("a mistake in the application's hook");
    });
    const call = await place(stack);
    const ended = await call.next((event) => event.kind === SipralEventKind.CallEnded, 8000);
    assert.equal(ended.statusCode, 486);
    assert.equal(invites().length, 1);
    assert.ok(reported.length > 0);
  });
});
