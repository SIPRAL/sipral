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
  stack's events as a `Stream<SipralStackEvent>`. `SipralStackEvent` copies
  out a call's state, a registration's and a digit; `SipralStack.onRawEvent`
  is handed every event whole, as the printed `SipralEvent`, inside the
  poll, so any payload arm (a subscription, a message, a recovery) is read
  there before the library takes the struct back.

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

## Where a stack is reached, and where its server is

`SipralStack.open()` with no `bindHost` listens on every interface and
advertises the address of the operating system's route toward the server of
its first account (`advertisedAddress`, `sipral_advertised_address`): the
address a PBX on the network reaches the machine at, and `127.0.0.1` for a
server on this machine. A call's media socket, without `mediaHost`, is bound
at the route toward the far end or the account's server. The library refuses
to advertise a loopback address to a peer elsewhere
(`SipralStatus.unreachableAddress`).

`addAccount(aor, serverUri: 'sip:pbx.example.com')` names the server by a URI
whose host RFC 3263 locates, in place of `registrarAddress`. The stack's
`resolver` answers each `lookupWanted`: `SipralDns.platform` by default.
`dart:io` asks the platform for addresses only, so SRV and NAPTR are
answered `nothing` there and the procedure goes on to the host's own
addresses; an application whose server publishes SRV records passes a
resolver that reads them. `located` (`event.locatedTargets`) says where the
server was found and `locateFailed` (`event.locateFailure`) why not.

`keepaliveMs` keeps an account's flow to its server open; this layer has no
TLS, and an account's `tlsPin` with `SipralAccount.checkCertificate` is the
verdict for an application that runs the account's TLS itself. `srtp`
(`SipralSrtp.bestEffort` offers SDES on plain RTP/AVP), `srtpSuites`,
`pathMtu`, `datagramWithoutStreamBytes` (UDP anyway up to that size: this
layer opens no stream, and `diagnosticsJson()` says `transport.kept.datagram`),
`pseudonymSalt` and `diagnosticTrace` (`setDiagnosticTrace`) reach the
library as `sipral_stack_config_t` takes them.

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
