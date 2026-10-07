// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// What a call does beyond placing, answering and hanging up, between stacks
// on 127.0.0.1: a redirect followed or left to the application, ringing
// before the answer with header fields both ways, a hangup that says why,
// real-time text, a focus naming its conference, a recording to a file,
// digits heard in the audio, SRTP reported, a hold read back, and a call
// moved to a new address.

import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, afterEach, beforeEach, describe, test } from 'node:test';

import {
  type Call,
  SipralCallEndReason,
  SipralCallState,
  SipralDtmf,
  SipralDtmfDetection,
  SipralEventKind,
  SipralKeyExchange,
  SipralRecovery,
  SipralSrtp,
  Stack,
  messageHeaders,
} from '../index.js';
import { kind, tone, up, until } from './helpers.js';

const scratch = mkdtempSync(join(tmpdir(), 'sipral-node-'));
after(() => rmSync(scratch, { recursive: true, force: true }));

let stacks: Stack[] = [];
let calls: Call[] = [];

async function open(options: Parameters<typeof Stack.open>[0] = {}): Promise<Stack> {
  const made = await Stack.open({ bindHost: '127.0.0.1', codecs: 'PCMU', ...options });
  stacks.push(made);
  return made;
}

function kept<T extends Call[]>(...made: T): T {
  calls.push(...made);
  return made;
}

beforeEach(() => {
  stacks = [];
  calls = [];
});

afterEach(async () => {
  for (const call of calls) {
    call.close();
  }
  for (const stack of stacks) {
    await stack.close();
  }
});

describe('a redirect', () => {
  test('is answered 3xx with where to go and why, and followed when asked to', async () => {
    const alice = await open();
    const bob = await open();
    const line = alice.addAccount('sip:alice@sipral.invalid', { registrarAddress: bob.bindAddress });
    bob.addAccount('sip:bob@sipral.invalid', { registrarAddress: alice.bindAddress });
    const carol = `sip:carol@${bob.bindAddress}`;
    // the first INVITE for bob is sent on to carol; the one for carol is taken
    const answered: Promise<Call> = new Promise((resolve) => {
      bob.on('event', (event) => {
        if (event.kind !== SipralEventKind.IncomingCall) {
          return;
        }
        if ((event.message as Buffer).toString('utf8').startsWith('INVITE sip:bob@')) {
          bob.redirectCall(event, [carol], { statusCode: 302, reason: 'user-busy' });
        } else {
          resolve(bob.answerCall(event));
        }
      });
    });

    const refused = kept(await alice.placeCall(line, `sip:bob@${bob.bindAddress}`))[0];
    const ended = await refused.next((event) => event.kind === SipralEventKind.CallEnded);
    assert.equal(ended.statusCode, 302);
    assert.deepEqual(messageHeaders(ended.message as Buffer, 'Contact'), [`<${carol}>`]);
    assert.match(messageHeaders(ended.message as Buffer, 'Diversion')[0] ?? '', /reason=user-busy/);

    const followed = kept(await alice.placeCall(line, `sip:bob@${bob.bindAddress}`, { followRedirects: true }))[0];
    const taken = kept(await answered)[0];
    await Promise.all([followed.confirmed(), taken.confirmed()]);
  });
});

describe('an attended transfer', () => {
  test('refers the held party to a second call, which it would replace', async () => {
    const alice = await open();
    const bob = await open();
    const carol = await open();
    const [toBob] = kept(...(await up(alice, bob)));
    carol.addAccount('sip:carol@sipral.invalid', { registrarAddress: alice.bindAddress });
    toBob.hold();
    await until(() => toBob.holdState().here);
    const line = alice.addAccount('sip:alice@sipral.invalid', { registrarAddress: carol.bindAddress });
    const ringing = kind(carol, SipralEventKind.IncomingCall);
    const consultation = kept(await alice.placeCall(line, `sip:carol@${carol.bindAddress}`))[0];
    const answered = kept(await carol.answerCall(await ringing))[0];
    await Promise.all([consultation.confirmed(), answered.confirmed()]);
    const referred = kind(bob, SipralEventKind.TransferRequested);
    toBob.transferTo(consultation);
    const asked = await referred;
    assert.equal(asked.attended, true);
    assert.match(asked.transferTarget ?? '', /carol/);
    const refused = toBob.next((event) => event.kind === SipralEventKind.TransferDone);
    bob.rejectTransfer(asked, 603);
    assert.equal((await refused).statusCode, 603);
  });
});

describe('a call rung before it is answered', () => {
  test('rings, carries header fields both ways, and is answered on the socket opened then', async () => {
    const alice = await open();
    const bob = await open();
    const line = alice.addAccount('sip:alice@sipral.invalid', { registrarAddress: bob.bindAddress });
    bob.addAccount('sip:bob@sipral.invalid', { registrarAddress: alice.bindAddress });
    const ringing = kind(bob, SipralEventKind.IncomingCall);
    const placed = kept(
      await alice.placeCall(line, `sip:bob@${bob.bindAddress}`, { headers: [['X-Conversation-Id', 'c-42']] }),
    )[0];
    const incoming = await ringing;
    assert.deepEqual(messageHeaders(incoming.message as Buffer, 'X-Conversation-Id'), ['c-42']);
    const progress = placed.next((event) => event.kind === SipralEventKind.CallProgress && event.statusCode === 180);
    const rung = kept(await bob.ringCall(incoming))[0];
    rung.setHeaders({ 'X-Agent': 'node' });
    await progress;
    const answered = await bob.answerCall(incoming);
    assert.equal(answered, rung);
    const confirmed = await placed.next((event) => event.kind === SipralEventKind.CallConfirmed);
    assert.deepEqual(messageHeaders(confirmed.message as Buffer, 'X-Agent'), ['node']);
  });

  test('rings with media: the caller hears the session before the answer', async () => {
    const alice = await open();
    const bob = await open();
    const line = alice.addAccount('sip:alice@sipral.invalid', { registrarAddress: bob.bindAddress });
    bob.addAccount('sip:bob@sipral.invalid', { registrarAddress: alice.bindAddress });
    const ringing = kind(bob, SipralEventKind.IncomingCall);
    const placed = kept(await alice.placeCall(line, `sip:bob@${bob.bindAddress}`))[0];
    const rung = kept(await bob.ringCall(await ringing, { media: true }))[0];
    await placed.mediaStarted();
    assert.notEqual(placed.state, SipralCallState.Confirmed);
    rung.answer();
    await placed.confirmed();
  });
});

describe('a call that is up', () => {
  test('ends saying why, as a Reason on the BYE', async () => {
    const [callA, callB] = kept(...(await up(await open(), await open())));
    callA.hangupFor({ sipCause: 480, q850Cause: 16, reason: 'agent gone' });
    const ended = await callB.next((event) => event.kind === SipralEventKind.CallEnded);
    assert.equal(ended.endReason, SipralCallEndReason.RemoteHangup);
    assert.equal(ended.fields.causeQ850, 16);
    assert.equal(ended.fields.causeText, 'agent gone');
  });

  test('carries real-time text both ways', async () => {
    const [callA, callB] = kept(...(await up(await open(), await open(), { text: true }, { text: true })));
    assert.ok(callA.media?.info().hasText);
    const heard: string[] = [];
    callB.on('text', (typed) => heard.push(typed));
    callA.sendText('hello');
    await until(() => heard.join('') === 'hello');
    const back: string[] = [];
    callA.on('text', (typed) => back.push(typed));
    callB.sendText('hi');
    await until(() => back.join('') === 'hi');
  });

  test('a focus that answered names its conference, and nobody else does', async () => {
    const [callA, callB] = kept(...(await up(await open(), await open(), {}, { focus: true })));
    assert.match(callA.conferenceUri() ?? '', /^sip:/);
    assert.equal(callB.conferenceUri(), null);
    const watching = callA.subscribeConference();
    assert.equal(watching.package, 'conference');
  });

  test('is recorded to a file, both directions', async () => {
    const [callA, callB] = kept(...(await up(await open(), await open())));
    const path = join(scratch, 'call.wav');
    const media = callA.media;
    assert.ok(media !== null);
    media.record(path);
    callB.media?.sendAudio(tone(callB.media.sampleRate, callB.media.sampleRate));
    await until(() => media.recording().recordedMs > 300);
    media.stopRecording();
    assert.equal(media.recording().recording, false);
    assert.ok(existsSync(path) && statSync(path).size > 44);
  });

  test('hears digits played into the audio where no telephone event was agreed', async () => {
    const [callA, callB] = kept(...(await up(await open({ offerDtmf: false }), await open({ offerDtmf: false }))));
    callB.setDtmfDetection(SipralDtmfDetection.Always);
    const digits: string[] = [];
    callB.on('digit', (digit) => digits.push(digit));
    callA.sendDtmf('5', SipralDtmf.InBand, 160);
    await until(() => digits.includes('5'));
    callA.detectProgress({ answeringMachine: false });
    callA.stopProgress();
    callA.setConsentTone({ lengthMs: 100 });
    callA.clearConsentTone();
  });

  test('says how its media is protected, and what its codec negotiation weighed', async () => {
    const [callA] = kept(...(await up(await open({ srtp: SipralSrtp.Required }), await open({ srtp: SipralSrtp.Required }))));
    const [stream] = callA.media?.encryption() ?? [];
    assert.ok(stream !== undefined && stream.encrypted);
    assert.equal(stream.keyExchange, SipralKeyExchange.Sdes);
    assert.ok(callA.media?.info().secured);
    assert.ok((callA.media?.codecCandidates().length ?? 0) > 0);
    assert.deepEqual(callA.media?.pathCandidates(), []);
  });

  test('is held and resumed, read back each time, and offered another codec', async () => {
    const [callA, callB] = kept(...(await up(await open({ codecs: 'PCMU,PCMA' }), await open({ codecs: 'PCMU,PCMA' }))));
    callA.hold();
    await until(() => callA.holdState().here && callB.holdState().there);
    callA.resume();
    await until(() => !callA.holdState().here);
    const changed = callA.next((event) => event.kind === SipralEventKind.SessionChanged);
    callA.changeCodecs('PCMA');
    await changed;
  });

  test('is moved to a new address and heard both ways after', async () => {
    const alice = await open();
    const bob = await open();
    const [callA, callB] = kept(...(await up(alice, bob)));
    const recovery = await alice.moveTo('127.0.0.1');
    assert.ok(Object.values(SipralRecovery).includes(recovery as never));
    const before = callA.mediaAddress;
    const moved = callA.next((event) => event.kind === SipralEventKind.SessionChanged);
    await callA.readdress('127.0.0.1');
    assert.notEqual(callA.mediaAddress, before);
    await moved;
    const media = callA.media;
    assert.ok(media !== null && callB.media !== null);
    callB.media.sendAudio(tone(callB.media.sampleRate, callB.media.sampleRate));
    let peak = 0;
    media.on('frame', (frame) => {
      peak = Math.max(peak, ...frame);
    });
    await until(() => peak > 2000);
  });
});
