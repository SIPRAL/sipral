<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# The Dart binding

A Dart package, `sipral`, over the C ABI through `dart:ffi`, for a Dart
program or a Flutter application.

- `lib/src/sipral_abi.dart` is printed by `tools/abi-gen` from the same
  declarations as the header and the other bindings, and is never edited:
  `cargo run -p sipral-abi-gen` writes it again, and `--check` fails when
  what is committed is not what came out. It is the raw surface: a `Struct`
  or `Union` class per record, the enumerations as `int` constants, the
  callbacks as function types, and every entry point in `Sipral`, looked up
  in the library `Sipral.open()` opened and checked. Names are Dart's, and a
  reserved word has a `$` after it (`SipralToggle.default$`).
  `package:sipral/sipral_abi.dart` exports it.
- `lib/src/{idiomatic,stack,account,call,media,events}.dart` are written by
  hand against it, and are what `package:sipral/sipral.dart` exports:
  `SipralStack`, `SipralAccount`, `SipralCall`, `SipralMedia` and the
  stack's events as a `Stream<SipralStackEvent>`.

```dart
final stack = await SipralStack.open(bindHost: '192.0.2.10');
final account = stack.addAccount(
  'sip:alice@example.com',
  registrarAddress: '203.0.113.5:5060',
  registrar: 'sip:example.com',
  authUser: 'alice',
  authPassword: secret,
);
await account.registered();
final call = await stack.placeCall(account, 'sip:bob@example.com',
    mediaHost: '192.0.2.10');
await call.confirmed();
call.digits.listen(print);
call.sendDtmf('123#');
call.hangup();
await call.whenEnded();
await stack.close();
```

Everything runs on the isolate that opened the stack: the sockets are
`RawDatagramSocket`s, the poll and each call's frame clock are timers, and
the event callback is a `NativeCallable.isolateLocal`, which the library calls
from inside `sipral_stack_poll` on that same thread. The application carries
each call's audio: `SipralMedia.frames` is the far end's PCM,
`SipralMedia.sendAudio` queues this end's, and silence goes out when nothing
is queued.

Signalling is UDP only. The other idiomatic layers answer
`SIPRAL_EVENT_KIND_TRANSPORT_WANTED` by opening a TCP connection for a
request that outgrew a datagram; this one does not, so such a request (most
often the answer to a challenge on a call offering two SRTP suites) waits
the stack's ten seconds for a stream and is then sent trimmed or ended with
a 513, as `docs/08-ffi.md` describes for an application that says nothing.

## The library

`Sipral.open()` takes a path to `libsipral_ffi` or the directory holding it;
without one it reads `SIPRAL_LIBRARY`, and without that it opens the library
by name where the platform looks for libraries (the application's own
`jniLibs` on Android), or finds it in the process on iOS, where the
xcframework links it in.

## Tests

```sh
cargo build --release -p sipral-ffi
cd bindings/dart
dart pub get
SIPRAL_LIBRARY=../../target/release dart test
```

`test/abi_test.dart` checks the ABI version and holds every struct and union
`dart:ffi` lays out to the length `sipral_abi_struct_size` reports for it.
`test/loopback_test.dart` places a call between two stacks on 127.0.0.1:
answered, confirmed, RTP both ways, audio heard as frames, three digits, a
hang-up ended on both ends; a refused call; and a failing call's error text.
