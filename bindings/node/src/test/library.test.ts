// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// What the library says about itself and about a stack: the ABI version,
// the build's capabilities and codecs, the names of statuses and events, a
// SIP message's header fields, a certificate pin in every form an
// administrator copies, and a stack's settings, counters, state, record and
// log.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { after, before, describe, test } from 'node:test';

import {
  type LogLine,
  SIPRAL_FEATURE_AUDIO_DEVICE,
  SipralCodec,
  SipralEventKind,
  SipralLogLevel,
  SipralStatus,
  Stack,
  abiCheck,
  abiVersion,
  advertisedAddress,
  capabilities,
  codecName,
  codecs,
  eventKindName,
  features,
  messageHeaderElements,
  messageHeaders,
  parsePin,
  statusName,
  structSize,
  versionedCount,
} from '../index.js';
import { SIPRAL_ABI_VERSION_MAJOR, SIPRAL_ABI_VERSION_MINOR } from '../sipral_abi.js';
import { kind, up, until } from './helpers.js';

describe('the library', () => {
  test('names its version, its build and its codecs', () => {
    const version = abiVersion();
    assert.equal(version.major, SIPRAL_ABI_VERSION_MAJOR);
    assert.ok(version.minor >= SIPRAL_ABI_VERSION_MINOR);
    assert.equal(abiCheck(SIPRAL_ABI_VERSION_MAJOR, SIPRAL_ABI_VERSION_MINOR), SipralStatus.Ok);
    assert.notEqual(abiCheck(SIPRAL_ABI_VERSION_MAJOR + 1, 0), SipralStatus.Ok);
    assert.ok(versionedCount() > 10);
    assert.ok(structSize('sipral_stack_config_t') > 0);
    const built = capabilities();
    assert.equal(built.features, features());
    const known = codecs();
    assert.equal(known.length, built.codecCount);
    const pcmu = known.find((codec) => codec.codec === SipralCodec.Pcmu);
    assert.equal(pcmu?.name, 'PCMU');
    assert.equal(pcmu?.staticPayloadType, 0);
    assert.equal(codecName(SipralCodec.Pcma), 'PCMA');
    assert.equal(statusName(SipralStatus.WrongState), 'wrong state');
    assert.equal(eventKindName(SipralEventKind.TokenRequired), 'token required');
    assert.equal(eventKindName(SipralEventKind.NetworkTest), 'network test');
    assert.equal(advertisedAddress('127.0.0.1:5060', '127.0.0.1:5070'), '127.0.0.1:5060');
    assert.equal(typeof (features() & SIPRAL_FEATURE_AUDIO_DEVICE), 'number');
  });

  test("reads a message's header fields, a line or a value at a time", () => {
    const message = Buffer.from(
      'INVITE sip:bob@example.com SIP/2.0\r\n' +
        'Diversion: <sip:a@example.com>;reason=user-busy, <sip:b@example.com>\r\n' +
        'i: call-one\r\n' +
        'Diversion: "Carol, the third" <sip:c@example.com>\r\n' +
        'Content-Length: 0\r\n\r\n',
    );
    assert.deepEqual(messageHeaders(message, 'Call-ID'), ['call-one']);
    assert.equal(messageHeaders(message, 'Diversion').length, 2);
    assert.deepEqual(messageHeaderElements(message, 'diversion'), [
      '<sip:a@example.com>;reason=user-busy',
      '<sip:b@example.com>',
      '"Carol, the third" <sip:c@example.com>',
    ]);
    assert.deepEqual(messageHeaders(message, 'Subject'), []);
  });

  test('takes every certificate pin form the fixtures list, and refuses the rest', () => {
    const lines = readFileSync(new URL('../../../fixtures/pin-forms.txt', import.meta.url), 'utf8').split('\n');
    const digest = lines.find((line) => line.startsWith('digest\t'))?.slice(7) ?? '';
    let seen = 0;
    for (const line of lines) {
      const [verdict, ...rest] = line.split('\t');
      const form = rest.join('\t');
      if (verdict === 'accept') {
        assert.equal(parsePin(form).toString('hex'), digest, form);
        seen += 1;
      } else if (verdict === 'refuse') {
        assert.throws(() => parsePin(form), RangeError, form);
        seen += 1;
      }
    }
    assert.ok(seen > 20);
  });
});

describe('a stack says what it runs with and what it did', () => {
  let alice: Stack;
  let bob: Stack;

  before(async () => {
    alice = await Stack.open({ bindHost: '127.0.0.1', codecs: 'PCMU,PCMA', maxDialogs: 7 });
    bob = await Stack.open({ bindHost: '127.0.0.1' });
  });

  after(async () => {
    await alice.close();
    await bob.close();
  });

  test('its settings, its codec order, its counters, its state and its log', async () => {
    const settings = alice.settings();
    assert.equal(settings.maxDialogs, 7);
    assert.ok(Array.isArray(settings.srtpSuites));
    assert.deepEqual(alice.codecOrder(), [SipralCodec.Pcmu, SipralCodec.Pcma]);
    const lines: LogLine[] = [];
    alice.setLog(SipralLogLevel.Debug, (line) => lines.push(line));
    const [callA, callB] = await up(alice, bob);
    assert.ok(callA.recordJson().length > 2);
    callA.hangup();
    await callB.whenEnded();
    const counters = alice.counters();
    assert.equal(counters.callsEndedLocalHangup, 1);
    assert.match(alice.state(), /call|account/i);
    const record = JSON.parse(alice.diagnosticsJson()) as unknown;
    assert.ok(record !== null && typeof record === 'object');
    await until(() => lines.length > 0);
    assert.ok(lines.every((line) => typeof line.target === 'string' && line.message.length > 0));
    alice.setLog(SipralLogLevel.Off);
    alice.setDiagnosticTrace(true);
    alice.setDiagnosticTrace(false);
    callA.close();
    callB.close();
  });

  test('a stack recording what it is fed hands the recording back', async () => {
    alice.startRecording('node binding test');
    const line = alice.addAccount('sip:carol@sipral.invalid', { registrarAddress: bob.bindAddress });
    bob.addAccount('sip:dave@sipral.invalid', { registrarAddress: alice.bindAddress });
    const ringing = kind(bob, SipralEventKind.IncomingCall);
    const call = await alice.placeCall(line, `sip:dave@${bob.bindAddress}`);
    bob.rejectCall(await ringing, 486);
    await call.whenEnded();
    const replay = alice.stopRecording();
    assert.ok(replay.length > 0);
    call.close();
  });
});
