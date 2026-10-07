// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The process around the stack and the policies an application installs:
// an account frozen and thawed across a suspension, measured from a cold
// start, moved to another registrar and refreshed, a call announced by a
// push; the stack told it is suspending, resumed and losing its network; a
// screening policy refusing an INVITE; a processor on a call's frames; and
// the trust anchors of caller verification.

import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, test } from 'node:test';

import {
  type Call,
  SIPRAL_SCREEN_ACCEPT,
  SipralDtmf,
  SipralEventKind,
  SipralRecordingLayout,
  SipralStatus,
  Stack,
} from '../index.js';
import { kind, tone, udpRegistrar, up, until } from './helpers.js';

let stacks: Stack[] = [];
let calls: Call[] = [];
let closers: (() => void)[] = [];

async function open(): Promise<Stack> {
  const made = await Stack.open({ bindHost: '127.0.0.1', codecs: 'PCMU' });
  stacks.push(made);
  return made;
}

beforeEach(() => {
  stacks = [];
  calls = [];
  closers = [];
});

afterEach(async () => {
  for (const call of calls) {
    call.close();
  }
  for (const stack of stacks) {
    await stack.close();
  }
  for (const close of closers) {
    close();
  }
});

describe('an account across the life of the process', () => {
  test('is frozen and thawed, measured from a cold start, moved and refreshed', async () => {
    const first = await udpRegistrar();
    const second = await udpRegistrar();
    closers.push(() => first.close(), () => second.close());
    const stack = await open();
    stack.coldStart();
    const account = stack.addAccount('sip:alice@sipral.test', { registrarAddress: first.address, registrar: 'sip:sipral.test' });
    await account.registered();
    const ready = account.timeToReady();
    assert.ok(ready === null || ready >= 0);
    const snapshot = account.freeze();
    assert.ok(snapshot.length > 0);
    account.thaw(snapshot, 1000);

    account.retarget(second.address);
    assert.equal(account.registrarAddress, second.address);
    account.refreshBinding();
    await until(() => second.registers.length > 0);

    // an account that asked for no push has no echo of one
    assert.throws(() => account.pushEcho(), (error: { status?: number }) => error.status === SipralStatus.NotSupported);
    const { announcement } = account.announce('sip:bob@sipral.test');
    assert.ok(announcement > 0n);
    stack.forgetAnnouncement(announcement);
  });
});

describe('the stack and the process around it', () => {
  test('is told it is suspending, resumes, and hears the network go', async () => {
    const registrar = await udpRegistrar();
    closers.push(() => registrar.close());
    const stack = await open();
    const account = stack.addAccount('sip:alice@sipral.test', { registrarAddress: registrar.address, registrar: 'sip:sipral.test' });
    await account.registered();
    const report = stack.suspending();
    assert.equal(typeof report.unverified, 'number');
    stack.resumed();
    stack.nameResolutionLost();
    stack.interfaceLost();
  });

  test('screens an INVITE before it rings', async () => {
    const alice = await open();
    const bob = await open();
    const seen: string[] = [];
    bob.setScreen((request) => {
      seen.push(request.source);
      return request.message?.toString('utf8').includes('X-Robocall: yes') ? 403 : SIPRAL_SCREEN_ACCEPT;
    });
    const line = alice.addAccount('sip:alice@sipral.invalid', { registrarAddress: bob.bindAddress });
    bob.addAccount('sip:bob@sipral.invalid', { registrarAddress: alice.bindAddress });
    const call = await alice.placeCall(line, `sip:bob@${bob.bindAddress}`, { headers: { 'X-Robocall': 'yes' } });
    calls.push(call);
    const ended = await call.next((event) => event.kind === SipralEventKind.CallEnded);
    assert.equal(ended.statusCode, 403);
    assert.equal(seen.length, 1);
    bob.setScreen(null);
    const ringing = kind(bob, SipralEventKind.IncomingCall);
    calls.push(await alice.placeCall(line, `sip:bob@${bob.bindAddress}`, { headers: { 'X-Robocall': 'yes' } }));
    bob.rejectCall(await ringing);
  });

  test("takes trust anchors for its callers' signatures, or none for a stack that only signs", async () => {
    const stack = await open();
    stack.stir(null);
  });
});

describe("a call's frames", () => {
  test('go through a processor that writes their replacement', async () => {
    const [callA, callB] = await up(await open(), await open());
    calls.push(callA, callB);
    const media = callA.media;
    assert.ok(media !== null);
    let frames = 0;
    media.attachProcessor((frame) => {
      frames += 1;
      frame.out.set(frame.nearEnd);
    });
    media.sendAudio(tone(media.sampleRate, media.sampleRate));
    await until(() => frames > 5);
    assert.equal(media.resetProcessor(), true);
    assert.equal(media.detachProcessor(), true);
    assert.equal(media.detachProcessor(), false);
  });

  test('are recorded to a stereo file, and the digits queued are told', async () => {
    const scratch = mkdtempSync(join(tmpdir(), 'sipral-record-'));
    closers.push(() => rmSync(scratch, { recursive: true, force: true }));
    const [callA, callB] = await up(await open(), await open());
    calls.push(callA, callB);
    const media = callA.media;
    assert.ok(media !== null);
    const path = join(scratch, 'stereo.wav');
    media.record(path, { layout: SipralRecordingLayout.Stereo });
    callA.sendDtmf('123', SipralDtmf.Rtp, 200);
    assert.equal(media.dialling().dialling, true);
    media.stopDialling();
    await until(() => media.recording().recordedMs > 200);
    media.stopRecording();
    assert.ok(statSync(path).size > 44);
  });
});
