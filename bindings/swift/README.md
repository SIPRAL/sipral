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
"Signalling across the boundary") — and handed to every stream a caller has
asked for. Streams are asked for, not stored: `stack.events()`,
`call.events()` (one call's own events), `call.dtmf()` (an
`AsyncStream<Character>` of just the digits from
`SipralEventKind.digitReceived`) and `media.frames()` each return a new
`AsyncStream`, and every one gets every item from then on, in order — so
`CallKitBridge`, a UI and a recorder can all read the same call. Nothing
raised before a stream is taken reaches it: take it first, then act. A
reader that falls behind drops its own oldest items (past
`Call.eventBuffer`, 4096 events or digits; past `Media.frameBuffer`, 50
frames, unless `frames(bufferingNewest:)` asks for another number), and a
call's streams finish right after its `callEnded`.

`Account` (`stack.addAccount`) registers and carries `sipral_account_announce`/
`refreshBinding` for `docs/15-mobile.md`'s C2 push sequence. `Call`
(`stack.placeCall`, `stack.answerCall`) answers, rejects, holds, resumes,
sends DTMF and hangs up; `Call.media` mints a `Media` once
`SipralEventKind.mediaStarted` says the session is up. `Media` runs on a
thread of its own, paced at the call's own frame rate (`docs/08-ffi.md`, "A
call's media has a handle of its own"): `sendAudio([Int16])` queues 16-bit
mono PCM out, `media.frames()` is an `AsyncStream<[Int16]>` of what came back,
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

`bindings/Package.swift` is the macOS and Linux package: it links
`target/release`. For iOS, `scripts/package/xcframework.sh --out DIR`
builds `DIR/CSipral.xcframework` (macOS, iOS device, iOS Simulator) and
prints `DIR/spm/Package.swift` over it, carrying this whole module and its
test suite on a `binaryTarget`. An application depends on `DIR/spm`; the
suite runs on a simulator from there:

```sh
UDID=$(xcrun simctl create sipral-test "iPhone 17" com.apple.CoreSimulator.SimRuntime.iOS-26-5)
cd DIR/spm && xcodebuild test -scheme Sipral -destination "platform=iOS Simulator,id=$UDID"
xcrun simctl delete "$UDID"
```

`Tests/SipralTests/HostPeerCallTests.swift` makes a call out of the process
— to a peer, or through a registrar — and is skipped, with the reason, unless
`SIPRAL_PEER` names one as `host:port`; `SIPRAL_REGISTRAR`, `SIPRAL_AOR`,
`SIPRAL_AUTH_USER`, `SIPRAL_AUTH_PASSWORD`, `SIPRAL_TARGET` and
`SIPRAL_WAIT_INCOMING_SECONDS` say the rest (the file's own comment says
how). `xcodebuild` hands the test process every `TEST_RUNNER_<NAME>` it is
given as `<NAME>`. `docs/15-mobile.md`, "The Swift package on iOS", has what
ran on the iOS 26.5 simulator, against a peer on the same Mac and through
the lab's Asterisk.

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
let events = call.events()                 // take it at once: nothing earlier is replayed
for await event in events {
    if event.kind == .mediaStarted { break }
}
let media = call.media!
let frames = media.frames()                // before sending, so the first reply is not missed
media.sendAudio(pcmSamples)                // 16-bit mono, one call at a time
for await frame in frames {
    // the far end's own audio, one frame per item
}

try call.hold()
try call.resume()
try call.sendDtmf("123#")
try call.hangup()
call.close()
```

An incoming call has no `Call` until the application decides what to do
with it: read `SipralEventKind.incomingCall` off `stack.events()` and call
`stack.answerCall(event)` or `stack.rejectCall(event)`. To see everything
the call does from its answer on, take it with
`stack.takeIncomingCall(event)`, which hands over the `Call` still ringing,
then its `events()`, then `answer()`. Under CallKit, bind the ringing `Call`
into `CallKitBridge` instead, and CallKit's `CXAnswerCallAction` is what
answers it.

### Behind a NAT

```swift
let stack = try SipralStack(
    bindHost: "10.0.2.16",
    ice: .offered,                          // every call; placeCall(ice:) overrides one
    stunServer: "198.51.100.1:3478",        // an address, not a name
    turn: TurnServer(address: "198.51.100.1:3478", username: "alice", password: secret)
)
```

Every option left `nil` is the build's own default, so a stack made without
them behaves as it always did: no STUN, no ICE, no relay. With `stunServer`
the signalling socket asks the server where it appears from, and every
account's `Contact` moves to that public address — `SipralEventKind.natMapping`
says so, with `event.natData` naming the socket, the mapping and how many
accounts moved. `placeCall` and `takeIncomingCall` then ask the same about
the call's media socket before the call is described, so the SDP names an
address the far end can send to; they return once the server has answered, or
five and a half seconds on without an answer (longer with a TURN server,
whose `SipralEventKind.natRelay` and `event.relayData` say whether a relay was
allocated). Until the call has media the stack's poll thread reads that
socket, sends what `sipral_stack_poll_stun` names it as the source of, and
hands everything arriving there — the servers' answers, the far end's first
ICE checks — to `sipral_stack_receive_stun`. The relay is offered only as an
ICE candidate, so it is used only with `ice`. `TurnServer`'s password stays
out of its `description` and of `dump()`. `g729AnnexB: false` turns off
G.729's silence compression. `ice: .lite` is the server's value, never the
phone's: an ICE-lite endpoint (RFC 8445 §2.5) for a host reachable at the
address it advertises, answering full ICE peers. `Tests/SipralTests/NatTests.swift`
proves each on the wire against a STUN and TURN server inside the test, and
carries a call between two stacks that require ICE and one between a lite
stack and a full one.

### A REFER from outside any call

`SipralStack(referrals: true)` hands a REFER that names no dialog —
click-to-dial from a switchboard, RFC 3515 §4.1 — to the application as
`SipralEventKind.referral`, `event.referralData` saying who to call, whether
it is attended and who the sender says is asking. `stack.acceptReferral(event)`
answers 202, reports on the call to whoever asked and places it from the line
it arrived for, returning that `Call`; `stack.rejectReferral(event, code: 603)`
refuses it. **Off by default, and then every one is refused 403**: a peer that
can make a phone dial is a toll-fraud vector, so each one is the
application's decision. `Tests/SipralTests/ReferralTests.swift` proves both
halves on the wire.

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

CallKit and PushKit delivered by the system: `CallKitAdapter` and
`PushKitAdapter` are compiled only where `CallKit`/`PushKit` actually work,
and `Tests/SipralTests/CallKitAdapterTests.swift` drives the adapter with
CallKit's own action classes on iOS — but the iOS 26.5 simulator refuses
every third-party `CXProvider`, so `reportNewIncomingCall` never completes
there, and it registers no VoIP push without an `aps-environment`
entitlement. The incoming-call screen and a real VoIP push need a device and
its provisioning. `CallKitBridge` and `PushKitBridge`, the sequence that
matters, are tested against a recording `CallKitProviding` on every
platform. `AVAudioSession` category and interruption handling beyond what
`SipralSampleMac`'s own `AudioBridge.swift` does. A DNS resolver for
`SipralEventKind.resolveNeeded`: the event is delivered and left unanswered,
so that a dialog stays on the path its INVITE took; an application with a
real lookup answers it through `Sipral.stackResolved` — the same gap
`bindings/python/README.md` states for its own layer.
