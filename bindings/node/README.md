<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# Sipral for Node.js

Sipral -- Session Initiation Protocol Rust Audio Layer -- for Node.js 20 or
later, in TypeScript: a SIP stack with accounts, registration, calls, DTMF,
transfer and each call's audio as 16-bit PCM frames in the application's
hands, which is what a voice agent or a bridge needs.

The package loads the Sipral C library through [koffi](https://koffi.dev/)
(MIT), whose prebuilt module means nothing is compiled at install. Its raw
layer, `src/sipral_abi.ts`, is printed from the ABI's declarations by
`tools/abi-gen` and never edited by hand; `Stack`, `Account`, `Call` and
`Media` are written over it.

## The library

The package looks for `libsipral_ffi` (`.dylib`, `.so` or `sipral_ffi.dll`)
in this order: `SIPRAL_LIBRARY` (the file or its directory), beside the
package, then a checkout's `target/release` and `target/debug`. Build it with:

```bash
cargo build --release -p sipral-ffi
```

## A call

```ts
import { Stack, SipralEventKind } from 'sipral';

const stack = await Stack.open();
const line = stack.addAccount('sip:1001@pbx.example', {
  registrarAddress: '192.0.2.10:5060',
  registrar: 'sip:pbx.example',
  authUser: '1001',
  authPassword: process.env.SIP_PASSWORD,
});
await line.registered();

const call = await stack.placeCall(line, 'sip:1002@pbx.example');
await call.confirmed();
call.on('media', (media) => {
  media.on('frame', (pcm) => {
    // the far end's audio, one frame at media.sampleRate
  });
  media.sendAudio(new Int16Array(media.frameSamples * 50)); // one second of silence at 20 ms frames
});
call.on('digit', (digit) => console.log('pressed', digit));
```

An incoming call is an event:

```ts
for await (const event of stack.events()) {
  if (event.kind === SipralEventKind.IncomingCall) {
    const call = await stack.answerCall(event);
  }
}
```

`stack.next(predicate)` and `call.next(predicate)` wait for one event, with a
timeout. `call.transfer(target)` sends a REFER; a `TransferRequested` event
is taken with `stack.acceptTransfer(event)` or refused with
`stack.rejectTransfer(event)`. `call.hold()`, `call.resume()` and
`call.hangup()` do what they say, and `stack.close()` hangs up what is still
up and releases everything.

## What it does not do yet

Signalling is UDP only: no account of its own over TCP or TLS, and a request
that outgrows a datagram waits for the stack's own timeout. Device mode,
conferences, subscriptions and presence are in the library and in the raw
layer (`sipral/abi`), not yet in the TypeScript classes.

## Tests

```bash
npm ci
npm test
```

They run against the library: two stacks on loopback carrying a tone each
way with digits, a transfer refused and one taken, and a registration through
a simulated registrar's digest challenge. `scripts/check.sh --only node` runs
them as part of the gate.

## Licence

AGPL-3.0-only, or the Sipral commercial licence.
