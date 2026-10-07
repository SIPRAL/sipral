// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Device mode: the engine's packets cross from a worker thread of their
// own, so the engine never waits on the application's; and, where this build
// has an audio backend, a stack whose devices are opened only when asked
// lists them, keeps its gain and mute, and connects a call whose frames are
// the engine's. Nothing here opens a device.

import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { Worker } from 'node:worker_threads';

import koffi from 'koffi';

import {
  type Call,
  SIPRAL_FEATURE_AUDIO_DEVICE,
  SipralAudio,
  SipralAudioActivation,
  SipralAudioDirection,
  SipralAudioRole,
  SipralStatus,
  SipralTransport,
  Stack,
  features,
} from '../index.js';
import { record } from '../internal.js';
import { sipral_audio_transmit_callback_t } from '../sipral_abi.js';
import type { EnginePacket } from '../transmit-worker.js';
import { up } from './helpers.js';

const hasDevices = (features() & SIPRAL_FEATURE_AUDIO_DEVICE) !== 0;

describe("the engine's transmit callback", () => {
  test('hands a packet, copied, to the thread that opened the stack, called from any other', async () => {
    const worker = new Worker(new URL('../transmit-worker.js', import.meta.url));
    try {
      const { callback } = await new Promise<{ callback: bigint }>((resolve) => worker.once('message', resolve));
      const payload = Buffer.from('\x80\x00rtp-shaped', 'latin1');
      const destination = Buffer.from('127.0.0.1:40000');
      const transmit = record('sipral_audio_transmit_t', {
        call: 42n,
        protocol: SipralTransport.Udp,
        destination,
        destination_len: destination.length,
        payload,
        payload_len: payload.length,
      });
      const arrived = new Promise<EnginePacket>((resolve) => worker.once('message', resolve));
      // called here, on a thread that is not the worker's: koffi relays it
      // there and returns once the worker has copied the packet out
      koffi.call(callback, sipral_audio_transmit_callback_t, transmit, null);
      const packet = await arrived;
      assert.equal(packet.call, 42n);
      assert.equal(packet.protocol, SipralTransport.Udp);
      assert.equal(packet.destination, '127.0.0.1:40000');
      assert.deepEqual(Buffer.from(packet.payload), payload);
    } finally {
      worker.postMessage('close');
      await worker.terminate();
    }
  });
});

describe('a stack in device mode', { skip: hasDevices ? false : 'this build has no audio backend for this platform' }, () => {
  let alice: Stack;
  let bob: Stack;
  const calls: Call[] = [];

  before(async () => {
    alice = await Stack.open({
      bindHost: '127.0.0.1',
      codecs: 'PCMU',
      audio: SipralAudio.Device,
      audioActivation: SipralAudioActivation.Manual,
    });
    bob = await Stack.open({ bindHost: '127.0.0.1', codecs: 'PCMU' });
  });

  after(async () => {
    for (const call of calls) {
      call.close();
    }
    await alice.close();
    await bob.close();
  });

  test('lists its devices, keeps its gain and mute, and opens nothing until activated', () => {
    assert.ok(alice.deviceMode);
    const devices = alice.audio.devices();
    assert.ok(devices.every((device) => device.id > 0 && typeof device.name === 'string'));
    assert.deepEqual(
      alice.audio.refresh().map((device) => device.id),
      devices.map((device) => device.id),
    );
    alice.audio.volume = 0.5;
    assert.equal(alice.audio.volume, 0.5);
    alice.audio.setMuted(SipralAudioDirection.Input, true);
    assert.equal(alice.audio.muted(SipralAudioDirection.Input), true);
    alice.audio.setMuted(SipralAudioDirection.Input, false);
    assert.throws(() => alice.audio.select(SipralAudioRole.Speaker, 999999), (error: { status?: number }) => error.status === SipralStatus.NoSuchDevice);
    assert.throws(() => alice.audio.setGain(SipralAudioDirection.Output, -1), RangeError);
    assert.equal(alice.audio.info().active, false);
    assert.throws(() => bob.audio.info(), (error: { status?: number }) => error.status === SipralStatus.WrongState);
  });

  test("connects a call whose frames are the engine's", async () => {
    const [callA, callB] = await up(alice, bob);
    calls.push(callA, callB);
    assert.equal(callA.media?.pumped, true);
    assert.equal(callB.media?.pumped, false);
    assert.throws(() => callA.media?.sendAudio(new Int16Array(160)));
    assert.throws(() => callA.media?.attachProcessor(() => undefined));
    alice.audio.setGain(SipralAudioDirection.Output, 2, callA);
    assert.equal(alice.audio.gain(SipralAudioDirection.Output, callA), 2);
    assert.equal(alice.audio.info().active, false);
  });
});
