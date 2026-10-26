<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# Sipral for Node.js

Sipral -- Session Initiation Protocol Rust Audio Layer -- for Node.js 20 or
later, in TypeScript: a SIP stack with accounts, registration, calls, DTMF,
transfer, presence, messages and conferences, signalling over UDP, TCP or
TLS, and each call's audio either as 16-bit PCM frames in the application's
hands -- what a voice agent or a bridge needs -- or run by the library
through the machine's own microphone and loudspeaker.

The package loads the Sipral C library through [koffi](https://koffi.dev/)
(MIT), whose prebuilt module means nothing is compiled at install. Its raw
layer, `src/sipral_abi.ts` (`sipral/abi`), is printed from the ABI's
declarations by `tools/abi-gen` and never edited by hand; the classes below
are written over it.

## Install

```bash
npm install sipral
```

## The library

The package carries no native library of its own. It looks for `libsipral_ffi` (`.dylib`, `.so` or `sipral_ffi.dll`)
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
const media = await call.mediaStarted();
media.on('frame', (pcm) => {
  // the far end's audio, one frame at media.sampleRate
});
media.sendAudio(new Int16Array(media.frameSamples * 50)); // one second of silence at 20 ms frames
call.on('digit', (digit) => console.log('pressed', digit));
```

An incoming call is an event; `answerCall`, `ringCall` (a 180, or with
`media: true` a 183 with early media), `rejectCall` and `redirectCall` decide
what becomes of it:

```ts
for await (const event of stack.events()) {
  if (event.kind === SipralEventKind.IncomingCall) {
    const call = await stack.answerCall(event);
  }
}
```

`stack.next(predicate)` and `call.next(predicate)` wait for one event, with a
timeout. Every event carries its whole payload as `event.fields`, under the
header's member names in `camelCase` (`event.fields.authzServer`,
`event.fields.causeSip`); `docs/08-ffi.md` says what each means.

## Signalling over TCP or TLS

```ts
const stack = await Stack.open({
  signalling: SipralTransport.Tls,
  signallingServer: 'pbx.example.com:5061',
  tlsTrust: TlsTrust.privateAuthority(readFileSync('company-ca.pem')),
});
```

`TlsTrust.platform()` (the default), `privateAuthority(pem)`,
`onlyAuthority(pem)` and `pinned(fingerprint)` -- in any form `openssl x509
-fingerprint -sha256` prints -- are what a connection trusts; nothing turns
the check off. A connection refused or lost is a `TransportFailed` naming why
(`fields.tls`: untrusted, another name, expired, a handshake refused), and is
made again, one second later and twice as long after each failure, up to
thirty; the accounts register again on it. On a UDP stack an account may have
a TCP or TLS connection of its own (`streamProtocol`), and a request too
large for a datagram goes on a TCP connection the stack opens, to
`streamServer` when the server takes TCP on another port.

### A client certificate

A server that requires one (mutual TLS) is given the certificate in
`clientCertificate`, read from files by the application: `{ cert, key }` in
PEM, the leaf first in `cert` and then any intermediates, or `{ pfx }`, a
PKCS#12 holding both, with `passphrase` for an encrypted key or the PKCS#12.

```ts
const stack = await Stack.open({
  signalling: SipralTransport.Tls,
  signallingServer: 'pbx.example.com:5061',
  clientCertificate: { cert: readFileSync('phone.pem'), key: readFileSync('phone.key') },
});
```

It is presented on the signalling connection and on every TLS or WSS
connection of an account's own; an account's own `clientCertificate` takes
its place there, and `turnClientCertificate` is the TURN server's. Node's TLS
signs with the key in this process: a key that stays in a hardware module or
the operating system's keystore needs the Swift, Kotlin or .NET layer. Each
refusal is a `TransportFailed` with its own `fields.tls`:

| What happened | `fields.tls` | `fields.error` |
|---|---|---|
| no certificate given, and the server required one (`certificate_required`, or any alert about the client's certificate) | `ClientCertificateRequired` | `ConnectionReset` |
| the server refused the one presented (`bad_certificate`, `unknown_ca`, `certificate_unknown`, `unsupported_certificate`, `certificate_revoked`, `access_denied`) | `ClientCertificateRefused` | `ConnectionReset` |
| the server said it has expired (`certificate_expired`) | `ClientCertificateExpired` | `ConnectionReset` |
| the leaf is out of its dates, found before connecting | `ClientCertificateExpired` | `Other` |
| the key does not load, does not belong to the leaf, or its password is wrong, found before connecting | `ClientKeyUnavailable` | `Other` |

The last two are found before anything is sent, and the connection is tried
again on the usual back-off. A server under TLS 1.3 says what it made of the
certificate a round trip after this end's handshake has finished, and a
REGISTER written in that time would make a server that refused reset the
connection and lose the alert; so a TLS 1.3 connection is handed to the
stack only once twice the handshake's time has passed quietly (250 ms at
least, 3 s at most), and an alert in that time is named as above. Node does
not say whether the server asked for a certificate, so every TLS 1.3
connection waits so, with or without one. A bare `handshake_failure`
stays `HandshakeRefused`: Node does not say whether the server had asked for
a certificate, which a TLS 1.2 server refusing a missing one sends.

## Device mode

```ts
const stack = await Stack.open({ audio: SipralAudio.Device });
stack.audio.select(SipralAudioRole.Speaker, stack.audio.devices()[0]);
stack.audio.volume = 0.8;
```

The library opens the platform's microphone and loudspeaker (macOS, Windows;
`features() & SIPRAL_FEATURE_AUDIO_DEVICE` says where) and runs every call
through them; the application writes no audio code. Device mode is opt-in
here, application mode the default. The engine hands its packets over on a
worker thread of this package's own, so the engine never waits on the
application's thread.

## The rest

- **Accounts:** `subscribe`, `watchPresence`, `publishPresence`,
  `sendMessage`, `setAccessToken` (the answer to `TokenRequired`, RFC 8898),
  `checkCertificate`, `rebind`, `retarget`, `freeze` and `thaw`, `announce`.
  An account added with `serverUri` is located through RFC 3263 with the
  stack's `resolver` -- the platform's lookup and DNS SRV/NAPTR by default.
- **Calls:** `hold`, `resume`, `transfer`, `transferTo`, `join` (a three-way
  call mixed here), `hangupFor` (a `Reason`), `setHeaders`, `sendText` (RFC
  4103), `setFocus`, `conferenceUri`, `subscribeConference`, `recordTo` (RFC
  7866), `readdress`, `restartIce`, `detectProgress`, `setDtmfDetection`,
  `setConsentTone`, `identity`. `followRedirects` sends a call on to the
  target a 3xx names.
- **Media:** `record`, `encryption`, `pathCandidates`, `codecCandidates`,
  `statistics`, `setAppRate`, `attachProcessor`.
- **Stack:** `createConference` (a local conference), `networkTest`,
  `moveTo`, `setStunServers` (with `nat: SipralNat.Stun`, every media socket
  is mapped before its call is described; a TURN server over UDP, TCP or TLS
  rides on it), `setScreen`, `setLog`, `settings`, `counters`, `state`,
  `diagnosticsJson`, `stir`, `suspending` and `resumed`.
- **The library:** `abiVersion`, `capabilities`, `codecs`, `statusName`,
  `eventKindName`, `messageHeaders`, `advertisedAddress`.

`stack.close()` hangs up what is still up and releases everything.

## A message hook

`stack.setMessageHook((outgoing, message, remote) => ...)` sees every SIP
message just before it is sent and just after it arrives, whole as a
`Buffer`, with the far end as `host:port`, and answers `MessageVerdict.keep`,
`MessageVerdict.replace(bytes)` (`Content-Length` must match the body) or
`MessageVerdict.drop`: not sent, or not read. It runs synchronously on the
main thread, inside the call into the stack that moved the message, with the
stack locked: it must not call into this stack and should return quickly.
One that throws keeps the message as it is; `setMessageHook(null)` removes
it. `src/test/message-hook.test.ts` proves each against a loopback PBX.

## Tests

```bash
npm ci
npm test
```

They run against the library, on loopback: calls between stacks, with audio,
digits, text, redirects, transfers, recording and three-way mixing; TLS and
TCP against this test's own registrar, with certificates made by the
`openssl` command, and a client certificate presented to it, required by it
and refused by OpenSSL's own `s_server` at TLS 1.3 and 1.2, and again
through a slow relay where a REGISTER would otherwise overtake the verdict;
presence, dialogs, a conference's picture, MESSAGE, an
OAuth 2.0 token, the network test, lookups, STUN and TURN; a local
conference; and device mode where the build has an audio backend, opening no
device. `scripts/check.sh --only node` runs them as part of the gate.

## Licence

AGPL-3.0-only, or the Sipral commercial licence.
