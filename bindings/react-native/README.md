<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# sipral-react-native

The Sipral SIP stack for React Native: accounts and registration, calls
placed and answered, hold, blind transfer, DTMF, and every event as a typed
emitter, with the phone's microphone and speaker run by the library itself.

It is a TurboModule for React Native's New Architecture, written against
React Native 0.87.1 (the newest stable release on 30 September 2026). The
codegen spec is `src/NativeSipral.ts`. Its two native halves wrap the
idiomatic layers the other bindings already ship, never the C ABI: the
Kotlin layer (`bindings/kotlin`, `org.sipral.idiomatic`) on Android and the
Swift layer (`bindings/swift`) on iOS. So this package speaks whatever ABI
those two speak, and moves when they do.

Nothing is published yet. The package's version is the workspace's
(`Cargo.toml`), and the gate checks that they agree.

## In an application

```sh
npm install sipral-react-native
```

**Android.** The module depends on `org.sipral:sipral`, the archive
`scripts/package/aar.sh` builds. Until it is on a Maven host, add the local
repository `scripts/package/android.sh` writes to the application's
`settings.gradle`:

```kotlin
dependencyResolutionManagement {
    repositories {
        maven { url = uri("/path/to/target/android/maven") }
    }
}
```

The library runs a phone's audio from Android 9 (API level 28); opening the
client on anything older rejects with `notSupported`. The module's manifest
asks for `INTERNET`, `RECORD_AUDIO`, `MODIFY_AUDIO_SETTINGS` and
`BLUETOOTH_CONNECT`; the application still asks the user for the microphone
at run time before the first call.

**iOS.** The pod takes the Sipral Swift package that
`scripts/package/xcframework.sh` writes, from wherever
`SIPRAL_SWIFT_PACKAGE` says it is, a directory or a git URL:

```sh
SIPRAL_SWIFT_PACKAGE=/path/to/xcframework-out bundle exec pod install
```

The application's `Info.plist` carries `NSMicrophoneUsageDescription`, and
the `audio` and `voip` background modes when calls should survive the app
leaving the screen.

## Using it

```ts
import Sipral from 'sipral-react-native';

const client = await Sipral.open({bindHost: '192.0.2.10'});
const account = await client.addAccount({
  aor: 'sip:alice@example.com',
  registrarAddress: '203.0.113.5:5060',
  registrar: 'sip:example.com',
  authUser: 'alice',
  authPassword: secret,
});
await account.registerAndWait();

client.on('incomingCall', async ({call, from}) => {
  await call.answer();
});

const call = await client.placeCall(account, 'sip:bob@example.com');
call.on('confirmed', async () => {
  await call.sendDtmf('123#');
  await call.hold();
  await call.resume();
  await call.transfer('sip:carol@example.com');
});
call.on('ended', ({reason, statusCode}) => console.log(reason, statusCode));
```

`bindHost` is the phone's own address on the network the server is reached
over; the stack signals from it and every call's audio goes out from it. A
phone has several addresses and only the application knows which one the
account lives on, so it is required.

### The client

`Sipral.open(options)` resolves with a `SipralClient`. There is one per
application: the native module holds it, and a second `open` while one is
open rejects with `wrongState`. `close()` ends it, and everything of it with
it.

| Option | |
|---|---|
| `bindHost` | this phone's address, required |
| `bindPort` | zero or left out for any free port |
| `userAgent`, `codecs` | the `User-Agent`, and codec names in order of preference |
| `signalling` | `"udp"` (the default), `"tcp"` or `"tls"` |
| `signallingServer` | `host:port`, required for TCP and TLS |
| `stunServer` | `host:port` of a STUN server |
| `audioActivation` | `"automatic"` (the default) or `"manual"` |

With `"manual"`, the devices open only between `client.audio.activate()`
and `client.audio.deactivate()`, which is what CallKit's audio session
callbacks and Android's audio focus are for. `client.audio.setMuted(true)`
sends silence in place of the microphone, on every call.

### Accounts

`client.addAccount(options)` resolves with a `SipralAccount`: `register()`,
`unregister()`, `registerAndWait()`, `remove()`, and `registrationState`,
which follows the events. Without `registrar` the account never registers,
and `registrarAddress` is only where requests go.

### Calls

`client.placeCall(account, target, options)` resolves with a `SipralCall`;
one that arrives is handed over by `incomingCall`. A call has `state`,
`direction`, `remote`, `heldHere`, `heldThere`, `ended` and `endReason`, and
these:

| Method | When |
|---|---|
| `answer()`, `reject(code = 486)` | a call that arrived, once |
| `hangup()` | until it has ended, in any state |
| `hold()`, `resume()` | confirmed |
| `sendDtmf(digits)` | confirmed; `0`-`9`, `A`-`D`, `*` and `#` |
| `transfer(target)` | confirmed: a blind transfer; this end stays in the call until `transferDone` |
| `acceptTransfer()`, `rejectTransfer(code = 603)` | after `transferRequested`, the far end asking this end to call somebody else |

What a call cannot do in the state it is in is refused before anything
crosses to native code, with the `wrongState` the library would answer.

### Events

The client's emitter carries each of these, and each call's own emitter the
ones about it (`progress`, `confirmed`, `holdChanged`, `ended`,
`transferRequested`, `transferProgress`, `transferDone`, `digit`).
`on(name, listener)` returns a subscription whose `remove()` stops it; a
listener that throws does not stop the others.

| Event | Carries |
|---|---|
| `registrationChanged` | `account`, `state`, `statusCode`, `retryInMs` |
| `incomingCall` | `call`, `from`, `fromDisplay`, `to` |
| `callProgress`, `callConfirmed` | `call`, `state`, `statusCode` |
| `holdChanged` | `call`, `heldHere`, `heldThere` |
| `callEnded` | `call`, `reason`, `statusCode` |
| `transferRequested` | `call`, `target`, `attended` |
| `transferProgress`, `transferDone` | `call`, `statusCode` |
| `digitReceived` | `call`, `digit` |
| `event` | every event, as the native half handed it over |

State and reason names are the library's own enumerations in lower camel
case: `SIPRAL_CALL_STATE_EARLY_MEDIA` is `"earlyMedia"`.

### Errors

Every promise rejects with a `SipralError` whose `code` is the library's
status in lower camel case (`wrongState`, `invalidArgument`, `staleHandle`,
...), `closed` for a client that was closed, or `platform` for what the
platform refused, a socket that would not bind among them.

## Layout

| | |
|---|---|
| `src/NativeSipral.ts` | the codegen spec: what crosses, in the types codegen reads |
| `src/client.ts`, `src/types.ts`, `src/errors.ts`, `src/emitter.ts` | the typed API above it |
| `android/src/main/java/org/sipral/reactnative/core/` | the Android half's logic over the Kotlin layer, with nothing of React Native in it |
| `android/src/main/java/org/sipral/reactnative/*.kt` | the TurboModule and its package |
| `android/jvm-check/` | that logic's check, run on a JVM by `scripts/check.sh` |
| `ios/Bridge/` | the iOS half's logic over the Swift layer, and its Objective-C face |
| `ios/SipralModule.mm` | the TurboModule |
| `sipral-react-native.podspec` | the pod |

## What is tested, and where

`scripts/check.sh` runs all of it on a Mac:

- `npm test`: the TypeScript layer under jest, against a fake native module
  (`src/__tests__/support/fakeNative.ts`): the call state machine, the
  events on the client and on each call, and how refusals come back.
- `npm run typecheck`: the spec and the layer against React Native's own
  type definitions, and codegen reading the spec into its schema.
- The Android half's logic (`SipralReactCore`) compiled with the Kotlin
  layer and run on a JVM over three real stacks on loopback
  (`android/jvm-check`, outside every Gradle source set): a call placed, answered, held, resumed, sent
  digits, transferred to a third that answers, a second call refused.
- The Android library itself, TurboModule included, built by Gradle
  (`android/gradle/wrapper` pins the version) against the Android SDK and
  an `org.sipral:sipral` archive holding the Kotlin layer's classes.
- The iOS half's Swift (`ios/Package.swift`) built against the Swift layer
  and tested on macOS over the same three stacks.
- `ios/SipralModule.mm` compiled for iOS against React Native's headers,
  the codegen output for the spec, and the Swift half's generated header.

What a Mac cannot run is a phone: the module inside a running application,
on a device's audio, is the one step left to a device.
