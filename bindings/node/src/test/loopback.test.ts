// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Two stacks on 127.0.0.1, one calling the other directly with no
// registrar between them: placed, answered, confirmed, a tone carried both
// ways, digits over, hung up from one side and ended on both. Then a
// transfer: Alice refers Bob to Carol, Bob takes it, Carol answers and Alice
// hears the transfer succeed.

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';

import { type Call, type Media, SipralCallState, SipralEventKind, Stack } from '../index.js';

/** Poll `probe` every 20 ms until it holds, or fail after `withinMs`. */
async function until(probe: () => boolean, withinMs = 15000): Promise<void> {
  const deadline = Date.now() + withinMs;
  while (!probe()) {
    if (Date.now() > deadline) {
      assert.fail(`nothing within ${withinMs} ms`);
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

/** `samples` samples of a 1 kHz tone at `rate`, peak 8000. */
function tone(rate: number, samples: number): Int16Array {
  const out = new Int16Array(samples);
  for (let at = 0; at < samples; at++) {
    out[at] = Math.round(8000 * Math.sin((2 * Math.PI * 1000 * at) / rate));
  }
  return out;
}

/** The loudest sample in what `media` plays out over the next `ms`. */
async function loudest(media: Media, ms: number): Promise<number> {
  let peak = 0;
  const listener = (frame: Int16Array): void => {
    for (const sample of frame) {
      peak = Math.max(peak, Math.abs(sample));
    }
  };
  media.on('frame', listener);
  await new Promise((resolve) => setTimeout(resolve, ms));
  media.off('frame', listener);
  return peak;
}

/** Resolve with the first frame `media` plays out louder than `level`, within `ms`. */
function heard(media: Media, level: number, ms: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      media.off('frame', listener);
      reject(new Error(`nothing louder than ${level} within ${ms} ms`));
    }, ms);
    const listener = (frame: Int16Array): void => {
      const peak = frame.reduce((loudest, sample) => Math.max(loudest, Math.abs(sample)), 0);
      if (peak > level) {
        clearTimeout(timer);
        media.off('frame', listener);
        resolve(peak);
      }
    };
    media.on('frame', listener);
  });
}

/** Place a call from Alice to Bob and let both ends confirm it. */
async function up(alice: Stack, bob: Stack): Promise<[Call, Call]> {
  const line = alice.addAccount('sip:alice@sipral.invalid', { registrarAddress: bob.bindAddress });
  bob.addAccount('sip:bob@sipral.invalid', { registrarAddress: alice.bindAddress });
  // listening before the INVITE can arrive, so it cannot be missed
  const ringing = bob.next((event) => event.kind === SipralEventKind.IncomingCall);
  const callA = await alice.placeCall(line, `sip:bob@${bob.bindAddress}`);
  const incoming = await ringing;
  assert.equal(incoming.callState, SipralCallState.Incoming);
  const callB = await bob.answerCall(incoming);
  await Promise.all([callA.confirmed(15000), callB.confirmed(15000)]);
  return [callA, callB];
}

describe('two stacks on loopback', () => {
  let alice: Stack;
  let bob: Stack;

  before(async () => {
    alice = await Stack.open({ bindHost: '127.0.0.1', userAgent: 'sipral-node-test' });
    bob = await Stack.open({ bindHost: '127.0.0.1' });
  });

  after(async () => {
    await alice.close();
    await bob.close();
  });

  test('a call carries a tone both ways, digits over, and ends on both sides', async () => {
    const [callA, callB] = await up(alice, bob);
    assert.equal(callA.state, SipralCallState.Confirmed);
    assert.equal(callB.state, SipralCallState.Confirmed);
    assert.equal(callB.incoming, true);

    await until(() => callA.media !== null && callB.media !== null);
    const mediaA = callA.media as Media;
    const mediaB = callB.media as Media;
    await until(() => mediaA.statistics().packetsReceived > 0 && mediaB.statistics().packetsReceived > 0);

    // silence first, then a tone from each end heard at the other
    const quiet = await loudest(mediaB, 200);
    assert.ok(quiet < 200, `silence played out at ${quiet}`);
    const atB = heard(mediaB, 4000, 5000);
    const atA = heard(mediaA, 4000, 5000);
    mediaA.sendAudio(tone(mediaA.sampleRate, mediaA.frameSamples * 100));
    mediaB.sendAudio(tone(mediaB.sampleRate, mediaB.frameSamples * 100));
    assert.ok((await atB) > 4000, "Bob heard Alice's tone");
    assert.ok((await atA) > 4000, "Alice heard Bob's tone");

    const frame = await mediaB.frames().next();
    assert.equal(frame.value?.length, mediaB.frameSamples);

    const digits: string[] = [];
    callB.on('digit', (digit) => digits.push(digit));
    callA.sendDtmf('42#');
    await until(() => digits.length >= 3);
    assert.deepEqual(digits, ['4', '2', '#']);

    const recorded = alice.next(
      (event) => event.kind === SipralEventKind.MediaStatistics && event.call === callA.handle,
    );
    const bobEnded = callB.whenEnded(15000);
    callA.hangup();
    await callA.whenEnded(15000);
    await bobEnded;
    assert.equal(callA.state, SipralCallState.Terminated);
    const record = (await recorded).statistics;
    assert.ok(record !== null && record.packetsSent > 0);
    assert.equal(callA.finalStatistics?.packetsSent, record.packetsSent);

    callA.close();
    callB.close();
    assert.equal(callA.media, null);
  });
});

describe('a transfer', () => {
  const stacks: Stack[] = [];

  after(async () => {
    for (const stack of stacks) {
      await stack.close();
    }
  });

  test('a REFER refused is heard as TransferDone with the refusal', async () => {
    const alice = await Stack.open({ bindHost: '127.0.0.1' });
    const bob = await Stack.open({ bindHost: '127.0.0.1' });
    stacks.push(alice, bob);
    const [callA, callB] = await up(alice, bob);
    const asked = callB.next((event) => event.kind === SipralEventKind.TransferRequested);
    callA.transfer('sip:carol@sipral.invalid');
    bob.rejectTransfer(await asked, 603);
    const done = await callA.next((event) => event.kind === SipralEventKind.TransferDone);
    assert.equal(done.statusCode, 603);
    assert.equal(callA.state, SipralCallState.Confirmed);
  });

  test('a REFER taken places the call, and its answer reaches the transferor', async () => {
    const alice = await Stack.open({ bindHost: '127.0.0.1' });
    const bob = await Stack.open({ bindHost: '127.0.0.1' });
    const carol = await Stack.open({ bindHost: '127.0.0.1' });
    stacks.push(alice, bob, carol);
    carol.addAccount('sip:carol@sipral.invalid', { registrarAddress: bob.bindAddress });
    const [callA, callB] = await up(alice, bob);

    const asked = callB.next((event) => event.kind === SipralEventKind.TransferRequested);
    const ringing = carol.next((event) => event.kind === SipralEventKind.IncomingCall);
    const target = `sip:carol@${carol.bindAddress}`;
    callA.transfer(target);
    const request = await asked;
    assert.equal(request.transferTarget, target);
    // listening before the new call can be answered, so the report cannot be missed
    const done = callA.next((event) => event.kind === SipralEventKind.TransferDone);
    const placed = await bob.acceptTransfer(request, { destination: carol.bindAddress });
    const answered = await carol.answerCall(await ringing);
    await Promise.all([placed.confirmed(15000), answered.confirmed(15000)]);
    assert.equal((await done).statusCode, 200);
  });
});
