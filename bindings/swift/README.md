<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# The Swift binding

Two layers, the way every binding here is two layers:

- `Sources/Sipral/SipralAbi.swift` — printed by `tools/abi-gen`'s Swift back
  end from `sipral_ffi::abi::SURFACE`, the same declarations the header and
  the .NET, Kotlin and Python bindings are printed from, over the `CSipral`
  C target (`c/include/sipral.h`, this package's own copy of the header).
  A status is a thrown `SipralError` carrying the last message; a pointer
  and a length are a `String` or an array held alive across the call; a
  struct the library fills in whole is what the call returns. Regenerated
  by `cargo run -p sipral-abi-gen`, never edited by hand.
- `Sources/Sipral/SipralStack.swift`, `Account.swift`, `Call.swift`,
  `Media.swift`, `SipralEvent.swift`, `UDPSocket.swift`, `CStrings.swift`,
  `CallKitBridge.swift`, `CallKitAdapter.swift`, `PushKitBridge.swift`,
  `PushKitAdapter.swift` — written by hand against the printed layer
  directly, the way `bindings/python/sipral/stack.py` is written against
  `ffi`/`lib`. `SipralStack`, `Account`, `Call` and `Media` are what an
  application reaches for.

## The idiomatic layer

`SipralStack` owns one `sipral_stack_create` handle, the UDP socket
signalling travels on, and a background thread that drains
`sipral_stack_poll` and the transport queues around it. Its C event callback
is decoded synchronously, on that poll thread, into a `Sendable`
`SipralEvent` before anything crosses — `sipral_event_t`'s pointers are only
valid for the length of the callback that carries them (`docs/08-ffi.md`,
"Signalling across the boundary") — and fed into an `AsyncStream<SipralEvent>`,
`stack.events`. `Call.events` is the same stream narrowed to one call's own
handle, and `Call.dtmf` narrows further still, to an `AsyncStream<Character>`
of just the digits from `SipralEventKind.digitReceived`.

`Account` (`stack.addAccount`) registers and carries `sipral_account_announce`/
`refreshBinding` for `docs/15-mobile.md`'s C2 push sequence. `Call`
(`stack.placeCall`, `stack.answerCall`) answers, rejects, holds, resumes,
sends DTMF and hangs up; `Call.media` mints a `Media` once
`SipralEventKind.mediaStarted` says the session is up. `Media` runs on a
thread of its own, paced at the call's own frame rate (`docs/08-ffi.md`, "A
call's media has a handle of its own"): `sendAudio([Int16])` queues 16-bit
mono PCM out, `media.frames` is an `AsyncStream<[Int16]>` of what came back,
and `media.statistics()` is `sipral_stream_stats_t`.

`CallKitBridge` and `PushKitBridge` run `docs/15-mobile.md`'s "C2" sequence —
push, report to CallKit, announce, refresh the binding, match the INVITE,
answer — behind `CallKitProviding`, a protocol small enough to fake in a
test with no device and no `CallKit` framework at all. `CallKitAdapter.swift`
and `PushKitAdapter.swift` are the real `CXProvider`/`PKPushRegistry` behind
it, compiled in only where those frameworks actually work
(`canImport(CallKit) && os(iOS)` — the module is importable on plain macOS
too, but every type in it is `API_UNAVAILABLE(macos)`, so `canImport` alone
is not enough to keep this package building there).

## Build and test

```sh
cargo build --release -p sipral-ffi   # once, from the repository root
cd bindings
xcrun --toolchain default swift build
xcrun --toolchain default swift test
```

`Package.swift` sits at the root of `bindings/` so the Swift target and the
C target (`CSipral`) share one header with `bindings/c`. `SipralTests` and
`SipralLabAgent` link against the library `cargo build -p sipral-ffi
--release` produces — `target/release/libsipral_ffi.{dylib,so}`, found from
an absolute path this manifest computes from its own location — rather than
merely compiling against the header the way `swift build` alone does, so
`swift test` is what actually drives two real stacks through this layer:
place a call, answer it, exchange audio, hold and resume, send DTMF, hang
up and release every handle without a use-after-free while events are still
pending (`Tests/SipralTests/CallLoopbackTests.swift`), plus
`CallKitBridge`/`PushKitBridge`'s own "C2" sequence against a recording
`CallKitProviding`, with no device involved
(`Tests/SipralTests/CallKitPushKitBridgeTests.swift`).

`scripts/check.sh` runs both steps from `bindings/` — `swift build` then,
only if the release library is there to link against, `swift test` — and
skips both with a stated reason where SwiftPM cannot read the manifest at
all (the Command Line Tools alone ship no `PackageDescription` module; a
full Xcode does).

## Use

```swift
import Sipral

let stack = try SipralStack(bindHost: "192.0.2.10")
let account = try stack.addAccount(
    aor: "sip:alice@example.invalid",
    registrarAddress: "203.0.113.10:5060",
    registrar: "sip:example.invalid",
    authUser: "alice",
    authPassword: secret
)
try account.register()

// Without `registrar` the account never registers: registering throws, and
// the registrar address is only the outbound proxy. The stack and media
// sockets default to 127.0.0.1, so name an address the registrar can reach.

let call = try stack.placeCall(account: account, target: "sip:bob@example.invalid", mediaHost: "192.0.2.10")
for await event in call.events {
    if event.kind == .mediaStarted { break }
}
call.media?.sendAudio(pcmSamples)          // 16-bit mono, one call at a time
for await frame in call.media!.frames {
    // the far end's own audio, one frame per item
}

try call.hold()
try call.resume()
try call.sendDtmf("123#")
try call.hangup()
call.close()
```

An incoming call has no `Call` until the application decides what to do
with it: read `SipralEventKind.incomingCall` off `stack.events` and call
`stack.answerCall(event)` or `stack.rejectCall(event)`.

## Samples

`Sources/SipralLabAgent` — a headless voice agent (answers, echoes, hangs up
on `"#"`), the Swift-layer equivalent of `bindings/python/examples/agent.py`.
It is both a runnable example of the layer above and the agent
`scripts/lab.sh` runs in the lab, headless, as `labuser-agent-swift`.

`Sources/SipralSampleMac` — a SwiftUI skeleton (not a product) macOS app:
registration, a call, hold/resume, DTMF, and `AudioBridge.swift` wiring the
device's own microphone and speaker through `AVAudioEngine` into
`Call.media`. `swift build` compiles it, since it is a target in the same
package, but nothing launches it headlessly; `scripts/check.sh` covers the
layer it sits on through `swift test` instead.

## What is not here

The iOS platform component: `CallKitAdapter` and `PushKitAdapter` are
compiled only where `CallKit`/`PushKit` actually work, and are not
unit-tested here — what would be tested is `CXProvider`/`PKPushRegistry`
themselves, which need a device or the simulator's telephony stack, not
anything this package adds in front of them; `CallKitBridge` and
`PushKitBridge`, the sequence that matters, are tested against a recording
`CallKitProviding` instead. `AVAudioSession` category and interruption
handling beyond what `SipralSampleMac`'s own `AudioBridge.swift` does; a DNS
resolver for `SipralEventKind.resolveNeeded` beyond treating the host as a
literal address (`SipralStack.resolve`), the same gap
`bindings/python/README.md` states for its own layer.
