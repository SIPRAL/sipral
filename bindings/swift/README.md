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
  `Media.swift`, `SipralEvent.swift`, `AudioDevices.swift`,
  `CallerIdentity.swift`, `UDPSocket.swift`, `CStrings.swift`,
  `CallKitBridge.swift`, `CallKitAdapter.swift`, `PushKitBridge.swift`,
  `PushKitAdapter.swift` — written by hand against the printed layer
  directly, the way `bindings/python/sipral/stack.py` is written against
  `ffi`/`lib`. `SipralStack`, `Account`, `Call` and `Media` are what an
  application reaches for; `stack.audio` is the library's own audio engine.

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
(`stack.placeCall`, `stack.answerCall`) answers, rejects, redirects, holds,
resumes, sends DTMF, moves to a new network and hangs up, with a reason or
without; `Call.media` mints a `Media` once `SipralEventKind.mediaStarted`
says the session is up. `Media` runs on a thread of its own, paced at the
call's own frame rate (`docs/08-ffi.md`, "A call's media has a handle of its
own"), and carries the call's packets. Who carries its audio is the stack's
`AudioMode`: the library, opening the devices itself (`.device`, the default
wherever the library has an engine for the platform), or the application
(`.application`), for which `sendAudio([Int16])` queues 16-bit mono PCM out
and `media.frames()` is an `AsyncStream<[Int16]>` of what came back.
`media.statistics()` is `sipral_stream_stats_t` either way.

`CallKitBridge` and `PushKitBridge` run `docs/15-mobile.md`'s "C2" sequence —
push, report to CallKit, announce, refresh the binding, match the INVITE,
answer — behind `CallKitProviding`, a protocol small enough to fake in a
test with no device and no `CallKit` framework at all. `CallKitAdapter.swift`
and `PushKitAdapter.swift` are the real `CXProvider`/`PKPushRegistry` behind
it, compiled in only where those frameworks actually work
(`canImport(CallKit) && os(iOS)` — the module is importable on plain macOS
too, but every type in it is `API_UNAVAILABLE(macos)`, so `canImport` alone
is not enough to keep this package building there).

`CallAudio` is a call's device kept through interruptions, route changes,
media services resets and CallKit's hold, mute and audio session, over a
`CallAudioDevice`; `VoiceProcessingAudioDevice` (wherever `AVFoundation`
is) and `AudioSessionObserver` (iOS only, as `AVAudioSession` is) are the
real device and the real notifications behind it.

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

`Tests/SipralTests/AudioDeviceModeTests.swift` runs the library's engine on
this machine's real devices. Listing, choosing, gain and mute ask the
platform without opening anything and always run; what opens the devices —
activation, the ring, a call in device mode — runs the voice-processing
unit, which on macOS needs the microphone granted to the process running the
tests: without it the unit fails inside the framework and takes the test
process with it. Those run only when asked, from a Terminal the system has
asked about the microphone once:

```sh
SIPRAL_AUDIO_DEVICES=1 xcrun --toolchain default swift test --filter AudioDeviceModeTests
```

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
// the microphone and the loudspeaker are the library's from here on: the
// stack is in device mode, and the call is heard without a line of audio code

try call.hold()
try call.resume()
try call.sendDtmf("123#")
try call.hangup(reason: .normalClearing)   // or hangup(), with no Reason
call.close()
```

An application that runs its own audio -- a voice agent, a recorder -- makes
the stack in application mode, and pumps each call's frames:

```swift
let stack = try SipralStack(audio: .application, bindHost: "192.0.2.10")
// ... placed as above ...
let media = call.media!
let frames = media.frames()                // before sending, so the first reply is not missed
media.sendAudio(pcmSamples)                // 16-bit mono, one call at a time
for await frame in frames {
    // the far end's own audio, one frame per item
}
```

### The library runs the audio

`SipralStack(audio:)` takes an `AudioMode`. `.device(activation: .automatic)`
-- `AudioMode.platformDefault` wherever this build of the library has an
engine for the platform, macOS and iOS among them -- has the library open the
voice-processing unit with the first call's media or the first ring and close
it with the last: every call is resampled to the device's rate and mixed into
the loudspeaker, the microphone goes into every call, and the platform's own
echo cancellation sits behind it. Each packet the engine encodes is handed
back to this layer, which sends it from the call's own socket (or on its
connection to a TURN server); received packets go in as before. Where there
is no engine -- Linux -- `.platformDefault` is `.application`.

`stack.audio` is the engine: `refresh()` and `devices()` list the devices
with their channel counts under ids that survive a refresh and an unplug,
`select(_:for:)` puts the `.microphone`, the `.speaker` or the `.ringer` on
one (or back on the system's route with `nil`), refused by status before
anything opens (`.noSuchDevice`, `.deviceUnusable`, and `.notSupported`
where the platform cannot: on macOS and iOS the microphone and the
loudspeaker are one unit, so the microphone follows the system's input and
the ring plays on the loudspeaker), `selection(for:)` says what was asked and
what runs while a chosen device is unplugged, `setGain(_:for:)` (1 is unity,
the input direction is the microphone's gain) and `setMuted(_:for:)` belong
to the direction and survive a change of device, `level(for:)` is the meter,
0 to 1, `ring(_:sampleRate:looped:)` and `stopRinging()` play a tone on the
ringer, and `status()` says whether the devices are open, the render delay
and whether the system cancels the echo. `SipralEventKind.audioDevicesChanged`
carries `event.audioData`: what changed, and whether the `.system` or the
`.engine` changed it -- an application re-applies nothing on the second.

`.device(activation: .manual)` opens the devices only between
`audio.activate()` and `audio.deactivate()`, which is CallKit's rule:
`CallKitBridge.drive(stack.audio!)` opens them at `didActivate`, closes them
at `didDeactivate` and at a provider reset -- the calls stay attached and are
heard again at the next activation -- and mutes the microphone on
`CXSetMutedCallAction`.

### Who is calling, why a call ended, and where it goes

```swift
for await event in stack.events() where event.kind == .incomingCall {
    let identity = try stack.callerIdentity(of: event)   // before answering
    let name = identity.asserted?.displayName ?? event.callData?.fromDisplay
    if identity.privacy.contains(.id) { /* number withheld */ }
    let answering = try stack.answering(of: event)
    if let after = answering.answerAfterMs { /* the caller asked to be answered without the person */ }
    try stack.redirectCall(event, to: ["sip:desk@example.invalid"], reason: "no-answer")  // a 302
}
```

`CallerIdentity` is what the network asserted -- `P-Asserted-Identity`, a
calling `Remote-Party-ID`, `verstat` -- read only from a peer the account
trusts (`trustedPeers`, RFC 3325 §8; `trusted` says whether it was), the
caller's `Privacy`, every `Diversion` (RFC 5806) and `History-Info` entry
(RFC 7044). `Answering` is `Answer-Mode`/`Priv-Answer-Mode` (RFC 5373),
`answer-after` and every `Alert-Info` with the ring source it names.
`Call.identity()` and `Call.answering()` read the same for a call taken.
`Call.hangup(reason:)` writes a `Reason` (RFC 3326) on the BYE or the CANCEL
-- `.completedElsewhere` is the one a phone that lost a fork race is told --
and `callEnded`'s `callData.endCause` is the far end's. `Call.redirect(to:)`
answers a ringing call with a 3xx.

### The account's options

```swift
let account = try stack.addAccount(
    aor: "sip:alice@example.invalid",
    registrarAddress: "203.0.113.10:5060",
    sessionTimer: .interval(seconds: 600),  // or .off; thirty minutes by default
    privacy: [.id],                         // withhold my number
    trustedPeers: ["203.0.113.10"]          // whose asserted identity is believed
)
```

### A call on the move

`stack.networkChanged(to: SipralStack.Network(link: .wifi, address: "10.0.0.7", interface: "en0"))`
tells the stack the platform moved it. When the address or the interface
changed (`SipralRecovery.rebuild`) the signalling socket is bound again there,
every account is pointed at it, and every call up raises
`SipralEventKind.callAddressWanted`: `call.moveMedia()` binds a socket on the
new network and offers the call there with a re-INVITE that moves only `c=`
and the port (RFC 3264 §8.3.1). A call under ICE moves with `restartIce()`
instead.

An incoming call has no `Call` until the application decides what to do
with it: read `SipralEventKind.incomingCall` off `stack.events()` and call
`stack.answerCall(event)` or `stack.rejectCall(event)`. To see everything
the call does from its answer on, take it with
`stack.takeIncomingCall(event)`, which hands over the `Call` still ringing,
then its `events()`, then `answer()`. Under CallKit, bind the ringing `Call`
into `CallKitBridge` instead, and CallKit's `CXAnswerCallAction` is what
answers it.

### The call's audio

For an application in application mode, `CallAudio` keeps one call's
microphone and speaker through what iOS does to them mid-call -- C4 of
`docs/13-client-requirements.md` -- over a
`CallAudioDevice`; `VoiceProcessingAudioDevice` is one over `AVAudioEngine`
with the system's voice processing, a new engine on every open:

```swift
let audio = CallAudio(media: call.media!, device: VoiceProcessingAudioDevice(managesSession: false))
let observer = AudioSessionObserver(audio: audio)   // interruptions, routes, media services
bridge.attach(audio, to: uuid)                      // CallKit's hold, mute and audio session
audio.follow(call)                                  // closed when the call ends
audio.start()
for await transition in audio.transitions() {
    // .started, .paused(reasons), .resumed, .interruptionEnded(shouldResume:),
    // .routeChanged, .muteChanged, .mediaServicesLost, .mediaServicesReset,
    // .deviceFailed, .deviceRestored, .stopped
}
```

Under CallKit the device starts only once the system has activated the
session (`CallKitAdapter` forwards `didActivate` and `didDeactivate`, and sets
the session's category when it answers); without CallKit,
`VoiceProcessingAudioDevice(managesSession: true)` configures and activates
the session itself. A device that is let go -- held, interrupted, the
session deactivated -- is closed, and a new one opened when the last reason
lifts; one that fails, or whose media services were reset, is built again
until it opens. The far end hears silence meanwhile, never a stopped stream:
`Media` keeps its own frame clock. `docs/15-mobile.md` ("C4") has the whole
table and what the simulator showed.

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

Behind a NAT, every account `stunServer` showed to be behind one keeps its
registrar's flow open: a double CRLF, alone in a datagram, every 20 to 25
seconds, so that a NAT filtering by address and port keeps letting the
registrar's INVITE in long after the REGISTER (`docs/06-nat.md`).
`registrarKeepalive: false` turns it off and `registrarKeepaliveMs` sets the
interval, 1 000 to 120 000; nothing goes while the stack is suspended.
`NatTests.swift` proves both on the wire.

A stack holds 128 calls at once unless `maxDialogs` says otherwise: past
it an incoming call is answered 503 and `placeCall` throws
`.limitReached`. `maxServerTransactions` (256), `diagnosticDecisions` (64)
and `diagnosticRecords` (32) are the other ceilings, zero for the default
each (`docs/08-ffi.md`, "Limits, and what went out twice").

`TurnServer(..., transport: .tcp)` reaches the TURN server over TCP, for the
network that lets no UDP out, and `.tls` over TLS (RFC 8656 §3.1) — 5349 is
the port for it. The stack opens a Network.framework `NWConnection` per media
socket when `sipral_stack_nat_map` asks for one, carries everything for the
relay on it and closes it when told; the relay is then used exactly as over
UDP. Over TLS the server's certificate is checked against `serverName` — the
host part of `address` when it is `nil` — with the system's trust, or, when
`trustedCertificates` holds any DER certificates, with those roots and
nothing else, which is how a private CA or a self-signed server is trusted.
Apple's TLS refuses a server certificate without `serverAuth` among its
extended key usages. Linux has no Network.framework: there the lab agent's
build reaches a TURN server over TCP with a plain socket, and refuses TLS.
`Tests/SipralTests/TurnStreamTests.swift` proves both against a TURN server
on a TCP port inside the test, over TLS with a certificate trusted and not.

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
registration, a call, hold/resume, DTMF, an incoming call shown with who the
network says it is and rung on the library's ringer, a speaker picker,
volume, microphone gain, mute and meters, and a call moved when the Mac
changes network. It has no audio code of its own: the stack is in device
mode. It binds where the Mac reaches the registrar from, and every field can
come from the environment for a run from a Terminal (`AppModel.swift` names
them; `SIPRAL_SAMPLE_CALL=1` places the call as it opens):

```sh
SIPRAL_SAMPLE_REGISTRAR_ADDRESS=192.0.2.20:5060 SIPRAL_SAMPLE_AOR=sip:labuser@192.0.2.20 \
SIPRAL_SAMPLE_AUTH_USER=labuser SIPRAL_SAMPLE_AUTH_PASSWORD=... \
SIPRAL_SAMPLE_TARGET=sip:9002@192.0.2.20:5060 SIPRAL_SAMPLE_CALL=1 \
    xcrun --toolchain default swift run SipralSampleMac
```

The first call asks the system for the microphone on behalf of whatever
launched the sample, and a firewall that asks about new programs asks about
this one. `swift build` compiles it; `scripts/check.sh` covers the layer it
sits on through `swift test`.

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
platform. The system's own delivery of an audio interruption, a route
change or a media services reset: the simulator raises none of them, so
`AudioSessionObserverTests` posts each as the system does, and a carrier's
call, a Bluetooth headset or CarPlay taking the route need a device. A DNS resolver for
`SipralEventKind.resolveNeeded`: the event is delivered and left unanswered,
so that a dialog stays on the path its INVITE took; an application with a
real lookup answers it through `Sipral.stackResolved` — the same gap
`bindings/python/README.md` states for its own layer.
