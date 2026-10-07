// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// Device mode's `audio_transmit_callback`, registered on a thread of its own.
//
// The audio engine calls it on the engine's thread once per packet, and koffi
// runs a JavaScript callback on the thread that registered it, holding the
// engine until it returns. Registered on the main thread, a packet would wait
// for whatever the application's thread is doing -- and the application's
// thread waiting on the engine (a stack destroyed, the devices closed) would
// wait for ever. Registered here, on a thread that never calls into the
// library, the callback only copies the packet out, posts it to the stack's
// thread, which sends it from the call's own socket, and returns at once.

import { parentPort } from 'node:worker_threads';

import koffi from 'koffi';

import { type Pointer, type SipralAudioTransmit, sipral_audio_transmit_callback_t } from './sipral_abi.js';

/** One packet the engine encoded, as it crosses to the stack's thread. */
export interface EnginePacket {
  /** The call whose socket it leaves from. */
  readonly call: bigint;
  /** A `SipralTransport` value: UDP is a datagram, TCP and TLS the TURN connection's bytes. */
  readonly protocol: number;
  /** Where it goes, `host:port`. */
  readonly destination: string;
  /** The octets. */
  readonly payload: Uint8Array;
}

/** `length` bytes at `address`, copied. */
function copied(address: Pointer, length: number | bigint): Uint8Array {
  const count = Number(length);
  if (count === 0 || address === null) {
    return new Uint8Array(0);
  }
  return new Uint8Array(koffi.view(address, count).slice(0));
}

const port = parentPort;
if (port !== null) {
  const callback = koffi.register((address: Pointer) => {
    const transmit = koffi.decode(address, 'sipral_audio_transmit_t') as SipralAudioTransmit;
    const payload = copied(transmit.payload, transmit.payload_len);
    const packet: EnginePacket = {
      call: BigInt(transmit.call),
      protocol: transmit.protocol,
      destination: Buffer.from(copied(transmit.destination, transmit.destination_len)).toString('utf8'),
      payload,
    };
    port.postMessage(packet, [payload.buffer as ArrayBuffer]);
  }, koffi.pointer(sipral_audio_transmit_callback_t));
  port.on('message', (message: unknown) => {
    if (message === 'close') {
      koffi.unregister(callback);
      port.close();
    }
  });
  port.postMessage({ callback });
}
