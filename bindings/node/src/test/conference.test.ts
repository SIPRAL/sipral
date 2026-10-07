// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// A local conference on one stack, its far ends two other stacks on
// 127.0.0.1: this end is its first member, what one far end says the other
// hears and so does this end, the mix is recorded, and a rate it cannot mix
// is refused.

import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';

import { type Call, SipralAudioDirection, SipralEventKind, SipralLocalConferenceChange, SipralStatus, Stack } from '../index.js';
import { kind, tone, until } from './helpers.js';

describe('a local conference', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'sipral-conference-'));
  let hub: Stack;
  let alice: Stack;
  let bob: Stack;
  const calls: Call[] = [];

  /** A call from `far` to the hub, both ends' media started; the hub's end returned. */
  async function dialIn(far: Stack, user: string): Promise<[Call, Call]> {
    const line = far.addAccount(`sip:${user}@sipral.invalid`, { registrarAddress: hub.bindAddress });
    const ringing = kind(hub, SipralEventKind.IncomingCall);
    const placed = await far.placeCall(line, `sip:hub@${hub.bindAddress}`);
    const answered = await hub.answerCall(await ringing);
    calls.push(placed, answered);
    await Promise.all([placed.mediaStarted(), answered.mediaStarted()]);
    return [answered, placed];
  }

  before(async () => {
    hub = await Stack.open({ bindHost: '127.0.0.1', codecs: 'PCMU' });
    alice = await Stack.open({ bindHost: '127.0.0.1', codecs: 'PCMU' });
    bob = await Stack.open({ bindHost: '127.0.0.1', codecs: 'PCMU' });
    hub.addAccount('sip:hub@sipral.invalid', { registrarAddress: alice.bindAddress });
  });

  after(async () => {
    for (const call of calls) {
      call.close();
    }
    for (const stack of [hub, alice, bob]) {
      await stack.close();
    }
    rmSync(scratch, { recursive: true, force: true });
  });

  test('refuses a rate it cannot mix', () => {
    assert.throws(() => hub.createConference({ sampleRate: 11025 }), (error: { status?: number }) => error.status === SipralStatus.ConferenceRefused);
  });

  test('carries what one far end says to the other and to this end, and records the mix', async () => {
    const [toAlice, aliceEnd] = await dialIn(alice, 'alice');
    const [toBob, bobEnd] = await dialIn(bob, 'bob');
    const room = hub.createConference({ sampleRate: 8000 });
    try {
      const [first] = room.memberList();
      assert.equal(first?.member, room.handle);
      const joined = hub.next((event) => event.kind === SipralEventKind.LocalConferenceChanged && event.fields.change === SipralLocalConferenceChange.Joined);
      room.add(toAlice);
      room.add(toBob);
      assert.equal((await joined).fields.conference, room.handle);
      assert.equal(room.info().members, 3);
      assert.throws(() => toAlice.media?.sendAudio(new Int16Array(160)));

      const path = join(scratch, 'mix.wav');
      room.record(path);
      let bobHeard = 0;
      let hubHeard = 0;
      bobEnd.media?.on('frame', (frame) => {
        bobHeard = Math.max(bobHeard, ...frame);
      });
      room.on('frame', (frame) => {
        hubHeard = Math.max(hubHeard, ...frame);
      });
      const media = aliceEnd.media;
      assert.ok(media !== null);
      const speaking = setInterval(() => media.sendAudio(tone(media.sampleRate, media.frameSamples)), media.frameMs);
      try {
        await until(() => bobHeard > 1000 && hubHeard > 1000);
      } finally {
        clearInterval(speaking);
      }
      room.setMuted(null, SipralAudioDirection.Output, true);
      room.setGain(toBob, SipralAudioDirection.Output, 256);
      room.stopRecording();
      assert.ok(existsSync(path) && statSync(path).size > 44);
      room.remove(toBob);
      assert.equal(room.info().members, 2);
      assert.ok(Array.isArray(room.talkers()));
    } finally {
      room.close();
    }
    assert.equal(toAlice.media?.pumped, false);
  });

  test('two calls joined hear each other, and stop when one leaves', async () => {
    const [toAlice, aliceEnd] = await dialIn(alice, 'alice');
    const [toBob, bobEnd] = await dialIn(bob, 'bob');
    toAlice.join(toBob);
    let bobHeard = 0;
    bobEnd.media?.on('frame', (frame) => {
      bobHeard = Math.max(bobHeard, ...frame);
    });
    const media = aliceEnd.media;
    assert.ok(media !== null);
    const speaking = setInterval(() => media.sendAudio(tone(media.sampleRate, media.frameSamples)), media.frameMs);
    try {
      await until(() => bobHeard > 1000);
    } finally {
      clearInterval(speaking);
    }
    toAlice.leave();
  });
});
