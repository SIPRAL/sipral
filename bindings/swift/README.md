<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# The Swift binding

Two layers, the way every binding here is two layers:

- `Sources/Sipral/SipralAbi.swift` — printed by `tools/abi-gen`'s Swift back
  end from `sipral_ffi::abi::SURFACE`, the same declarations the header and
  the .NET, Kotlin, Python and Dart bindings are printed from, over the `CSipral`
  C target (`c/include/sipral.h`, this package's own copy of the header).
  A status is a thrown `SipralError` carrying the last message, the number
  (`code`) and its name (`status`, nil for one a newer library returned
  that this binding does not know); a pointer
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

On a Mac with the virtual loopback device `BlackHole 2ch`, those tests put
every role on it, so nothing sounds through the machine's loudspeaker;
without it they run on the system's route.

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
// the registrar address is only the outbound proxy. Left out, `bindHost` and
// `mediaHost` are the address of the route toward the registrar.

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
try call.transfer(to: "sip:carol@example.invalid")   // blind: .transferDone's transferData says how it went
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
(`SipralAudioDevice`, which was `AudioDevice` until the name was prefixed
so that it does not collide with another package's; the old name stays a
deprecated alias for one minor release, as `Subscription` does for
`SipralSubscription`, which Combine's protocol of that name collided with)
with their channel counts under ids that survive a refresh and an unplug,
`select(_:for:)` puts the `.microphone`, the `.speaker` or the `.ringer` on
one (or back on the system's route with `nil`), refused by status before
anything opens (`.noSuchDevice`, `.deviceUnusable`, and `.notSupported`
where the platform cannot: on iOS, whose route is the audio session's, the
microphone and the ringer; on macOS the microphone is chosen apart from the
speaker without moving the system's default input, and a ringer on another
device plays through an output of its own), `selection(for:)` says what was asked and
what runs while a chosen device is unplugged, `setGain(_:for:)` (1 is unity,
the input direction is the microphone's gain) and `setMuted(_:for:)` belong
to the direction and survive a change of device, `level(for:)` is the meter,
0 to 1, `ring(_:sampleRate:looped:)` and `stopRinging()` play a tone on the
ringer, and `status()` says whether the devices are open, the render delay
and whether the system cancels the echo. `SipralEventKind.audioDevicesChanged`
carries `event.audioData`: what changed, and whether the `.system` or the
`.engine` changed it -- an application re-applies nothing on the second.

Each call has a gain, a mute and a meter of its own on top of the
direction's: `setGain(_:for:of:)`, `setMuted(_:for:of:)`, `gain(for:of:)`,
`isMuted(_:of:)` and `level(for:of:)` take the `Call`. The input direction is
what the microphone sends that call alone and the output how loud it is in
the loudspeaker beside the others -- mute the call being spoken about in a
consultation, turn one conference member down. They hold from the moment the
call's media starts to its end, through a hold or a local conference and
back, and throw `.wrongState` outside that.

`systemEchoCancellation: false` opens the devices past the platform's echo
cancellation, gain control and noise suppression -- on macOS and iOS the
voice-processing unit with its processing bypassed -- for a headset, which
has no echo to cancel, or an application that cancels it on each call
itself; `status().systemEchoCancellation` says what the platform did.

**Ending a call never needs the main thread.** The engine opens the devices
on a thread of its own when a call's media starts — the call is carried, on
silence, until they answer — and lets them go on its own thread when the
last call's media ends, after the poll that ended it has returned; so
`call.hangup()` and `account.unregister()` called on the main thread, which
then waits there while the application shuts down, still have their BYE
and un-REGISTER sent within a poll, though the voice unit's teardown on
macOS has been seen to wait for the main thread. `audio.deactivate()` waits
for that teardown at most the probe wait. `account.registrationState` reads
`.unregistered` from the moment `unregister()` returns, before the registrar
has answered; the answer is the `.registrationChanged` event that follows,
and an application that waits for the binding to be gone waits for that
event rather than polling the state. `AudioDeviceModeTests` hangs up with
the main thread held, on the real devices (`SIPRAL_AUDIO_DEVICES=1`).

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

### STIR/SHAKEN, SRTP per account and the encryption report

`addAccount(..., security: AccountSecurity(stirKey: key,
stirCertificateUrl: url))` signs every call the account places (RFC 8224,
with RFC 8588's `attest` and `origid`); the key is the bare 32 bytes or SEC1
or PKCS #8 in DER or PEM, and the stack needs the time first:
`stack.stir(anchors: nil)` on one that only signs. A signed INVITE is some
five hundred octets longer, and past RFC 3261's 1300 over UDP it needs a
stream transport. `stack.stir(anchors:)` verifies the callers of every
account that reports (the default) or is `.strict`:
`SipralEventKind.callerVerification` with `verificationData.stage ==
.certificateWanted` asks for the chain at `certificateUrl`, which
`stack.stirCertificate(call: event.call, chain:)` hands over (`nil` for one
that could not be had); the verdict follows as the same kind, just before the
call, and `callData.verification` carries it on every call event.
A certificate covers the numbers its TNAuthList names (RFC 8226 §9); one that
names a service provider code instead, as a SHAKEN certificate does, covers
no caller until `stack.stir(anchors:acceptServiceProviderCodes: true)` says
the deployment trusts its certified providers that far.
`Tests/SipralTests/SecurityTests.swift` proves both verdicts with the chain in
`bindings/fixtures/stir-provider-709J`.
`AccountSecurity(srtp: .required, srtpSuites: ["AES_CM_128_HMAC_SHA1_80"])`
holds every call of one account to its own SRTP policy and suites; a call may
ask for more and never less. `call.media?.encryption()` is the encryption
report (`StreamProtection`: how the keys were exchanged, encrypted, the
suite, and whether the exchange authenticated the far end), and
`mediaData` carries the same on media started, changed and secured.

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

`stunFallbacks: ["198.51.100.2:3478"]` names the STUN servers to turn to, in
order, when `stunServer` stops answering; every socket moves on by itself,
and a `.stunServer` event (`stunServerData`: the state, the server, the one
before it) says when the server in use changed or every one failed
(`docs/06-nat.md`, "More than one server"). `stack.setStunServers([...])`
replaces the list on a running stack, and turns STUN on for one created
without it; an empty list turns it off again.

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

### Where a stack is reached, and where its server is

`SipralStack()` with no `bindHost` listens on every interface and advertises
the address of the operating system's route toward the server of its first
account (`SipralStack.advertisedAddress(bound:peer:)`,
`sipral_advertised_address`): the address a PBX on the network reaches the
device at, and `127.0.0.1` for a server on this machine. Each account is
reached at the route toward its own server, and a call's media socket,
without `mediaHost`, at the route toward the far end or the account's
server. The library refuses to advertise a loopback address to a peer
elsewhere: `.unreachableAddress`, and
`SipralRegistrationFailure.unreachableContact` for a REGISTER it sends on
its own.

`addAccount(aor:serverUri:)` names the server by a URI whose host RFC 3263
locates, in place of `registrarAddress`. The stack's `resolver` answers each
`.lookupWanted`: `SipralDns.platform` by default, which asks the system's DNS
service (`DNSServiceQueryRecord`, VPN and per-interface resolvers included)
for SRV and NAPTR and `getaddrinfo` for addresses; on Linux SRV and NAPTR
are answered `.nothing` and the procedure goes on to the host's own
addresses. `.located` says where the server was found (`account.registrarAddress`
follows it) and `.locateFailed` why not.

`keepaliveMs` keeps an account's flow to its server open whatever STUN found.
`TLSTrust.pinned("SHA256=AB:CD:...")` trusts the one certificate with that
fingerprint on a TLS signalling connection, whoever signed it and whatever
name it carries; an account's `tlsPin` and `Account.checkCertificate(_:)` are
the same verdict for an application that runs the account's TLS itself.

`srtp: .bestEffort` offers SDES on plain RTP/AVP, for a PBX that answers an
RTP/SAVP offer with 488; `srtpSuites` names the suites every call offers.
`pathMtu` tells RFC 3261 §18.1.1 the path's MTU, and
`datagramWithoutStreamBytes` sends a request over UDP anyway once no stream
to a UDP-only server can be had -- a deliberate deviation, written to
`diagnosticsJson()` as `transport.kept.datagram`. `pseudonymSalt` keys the
log's pseudonyms so that two runs compare, and `diagnosticTrace` (or
`setDiagnosticTrace(true)`) writes whole SIP messages at the trace level,
credentials and keys taken out.

### The log, the state and the counters

```swift
try stack.logTo(subsystem: "com.example.phone", level: .info)
print(try stack.counters().requestsRetransmitted)
let report = try stack.state()   // redacted, from any thread
```

`logTo(subsystem:level:)` sends the stack's log to the unified logging
system: one `os.Logger` per part of the stack that wrote a line, as its
category (`call`, `registration`, `sip`, `api`, ...), `.error` as
`OSLogType.error`, `.warn` as `.default`, `.info` as `.info`, and `.debug`
and `.trace` as `.debug` (`SipralLogLevel.osLogType`). Every line is
redacted before it leaves the library — no user part, number, IP address or
credential (`docs/17-observability.md`) — so it is logged as public, and
Console shows its text rather than `<private>`. The system keeps warnings
and errors; info and debug lines are seen live, with `log stream --level
debug`. `setLog(level:handler:)`
takes a closure instead, and is what Linux, which has no unified logging,
uses. `counters()` is a `SipralCounters`: registrations, how calls ended,
what screening refused and, since ABI 0.30, `requestsRetransmitted`,
`responsesRetransmitted`, `transactionsTimedOut` and
`requestsRefusedAtLimit`. `state()` is the redacted text snapshot of what the
stack holds. `SipralStack(rtpPortMin: ..., rtpPortMax: ...)` keeps every
media socket this package opens inside a firewall's range.
`Tests/SipralTests/LoggingTests.swift` proves each.

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

### What a call carries in its audio, and recording it

A digit the far end leaves in the audio arrives as
`SipralEventKind.inBandDigit` and on `call.dtmf()` like any other: by default
on a call that negotiated no telephone event, and on every call or none with
`SipralStack(dtmfDetection: .always)` / `.off` or
`call.setDtmfDetection(_:)`. `call.sendDtmf(digits)` writes the tones into the
audio where the far end took no telephone event, and `via: .inBand` does so
on any call. `call.detectProgress(ProgressOptions())`, straight after
`placeCall`, reports the network's tones, who answered and the machine's beep
as `SipralEventKind.progressDetected` with `event.progressData` set.
`call.setConsentTone(...)` beeps while the call is recorded.
`media.record(to:format:layout:sampleRate:bitrate:checkpointMs:)` writes WAV
or Ogg Opus, mixed or stereo with this end on the left, and `stopRecording()`
/ `recording` stop it and say how far it got. This end is silence in the file
while the microphone is muted (`audio.setMuted(true, for: .input)`, or the
call's own mute) and while the call is on hold, either way, each such frame
in its place on the call's timeline (`docs/05-media.md`, "Recording a
call").
`Tests/SipralTests/InBandTests.swift` proves each over two stacks on
loopback.

### SIP over TCP or TLS

```swift
let stack = try SipralStack(
    bindHost: "192.0.2.20",
    signalling: .tls,
    signallingServer: "198.51.100.10:5061",
    tlsServerName: "pbx.example.com",
    tlsTrust: .onlyAuthority(pbxAuthorityDER)
)
let account = try stack.addAccount(
    aor: "sip:alice@example.com", registrarAddress: "198.51.100.10:5061", registrar: "sip:example.com"
)
try account.register()
for await event in stack.events() {
    if let failed = event.transportFailedData {
        print(failed.tls.map { "\($0)" } ?? "", failed.detail ?? "")
    }
}
```

`signalling` is `.udp` (the default), `.tcp` or `.tls`. Over either of the
last two the stack keeps one connection to `signallingServer`, the registrar
or the outbound proxy, and every account and call rides on it; a `Contact`
this layer writes names the transport. TLS is Network.framework's, on Apple
platforms only: the certificate is evaluated by `SecTrust` with the SSL
policy for `tlsServerName` (the server's host when `nil`), under `tlsTrust`
— `.platform` (the default), `.privateAuthority(der)` beside it, or
`.onlyAuthority(der)` alone. On Linux `.tls` throws `.notSupported` and
`.tcp` works on a plain socket. The first connection is made in the
initializer. One that fails, or breaks later, arrives as
`SipralEventKind.transportFailed` with `transportFailedData`: `tls`
`.untrusted`, `.nameMismatch`, `.expired` or `.handshakeRefused`, the
`error`, and Security's own `detail`. The stack connects again, one second
later and up to thirty seconds apart, registering every account again once
it is back; `stack.connected` says whether it is up, and `account.register()`
asked meanwhile is kept for then. `docs/22-tls.md` has the whole mapping.

An account can have a connection of its own on a stack that signals over
UDP, so that one stack and one audio engine hold an account on UDP with one
PBX and another on TCP or TLS with a second:

```swift
let stack = try SipralStack()
let office = try stack.addAccount(aor: "sip:alice@office.example", registrarAddress: "192.0.2.10:5060")
let carrier = try stack.addAccount(
    aor: "sip:+15550100@carrier.example", registrarAddress: "198.51.100.20:5061",
    tlsPin: "sha256 Fingerprint=AB:CD:...", streamProtocol: .tls
)
```

The stack asks for the connection with `SipralEventKind.transportWanted`,
nothing outgrown, and this layer opens it to the account's server whatever
`streamFallback` says: a TLS one held to the account's `tlsPin` when it has
one, to `tlsTrust` under `tlsServerName` otherwise. The account's REGISTER
and every request of its calls go over it, its `Contact` names the protocol,
and a connection that closes is opened again and the account registered
again. Until it is open, a call the account places throws `.transportDown`.

`stack.settings()` reads back what the stack runs with, every default filled
in: the timers, the codecs' count, the SRTP suites its calls offer in order,
whether a pseudonym salt was given, whether the diagnostic trace is whole
now, and whether the platform's echo cancellation is asked for.

`inviteLimit` is how fast one address may ring the stack: every stack
starts at `InviteLimit.standard`, ten INVITEs at once and one every two
seconds, past which a call is answered 480. A voice agent behind a trunk
takes `.voiceAgent`, a hundred and twenty-eight at once and twenty a second.

### Real-time text, RTCP feedback and linear audio

```swift
let call = try stack.placeCall(account: account, target: "sip:bob@example.com", text: true, feedback: true)
// on the far end: stack.takeIncomingCall(event, text: true), then call.answer(feedback: true)
for await typed in call.text() {
    print(typed.text)
}
try call.media?.sendText("hello")
```

`text: true` binds a second socket beside the audio one and offers
real-time text on it (RFC 4103, T.140 with redundancy); a call taken with
`takeIncomingCall(event, text: true)` takes the text an offer carries. Once
both ends agree, `media.sendText(_:)` types (a new line and BACKSPACE
included), `call.text()` reads what the far end typed, each piece a
`TextEventData` with how many blocks were lost past recovery, and
`media.hasText` says whether it was agreed -- `.notNegotiated` from
`sendText` otherwise. It is not offered on a call keyed by SRTP or
gathering ICE, where it would travel in the clear.

`feedback: true` offers RTP/AVPF with Generic NACKs and reduced-size RTCP
(RFC 4585, RFC 5506); a far end that knows only RTP/AVP refuses the
profile, so it is off by default. An offer that asks is answered on the
profile whatever this end says, and `answer(feedback: true)` adds the NACKs
and reduced size. `media.rtcpFeedback()` says what was agreed, and
`statistics()` counts the NACKs, the early and reduced-size packets.

`codecs:` on `placeCall` and `answer` orders one call's codecs:
`"L16/16000"` or `"L16/8000"` offers linear audio, which no default offer
carries.

### Conferences and presence

```swift
_ = try account.watchPresence(of: "sip:bob@example.com")
try account.publishPresence(Presence(basic: .open, activity: .onThePhone, note: "In a call"))
let watched = try call.subscribeConference()   // a call whose far end is a focus
for await event in stack.events() {
    if let told = event.presenceData, told.kind == .watched {
        print(told.entity ?? "", told.basic.map { "\($0)" } ?? "", told.note ?? "")
    }
    if let changed = event.conferenceData, let room = try watched.conference() {
        print(changed.version, room.subject, room.users.map(\.entity))
    }
}
```

`account.subscribe(to:package:)` is any RFC 6665 subscription, kept and
refreshed by the stack until `SipralSubscription.end()`; `watchPresence(of:)`
is one to `presence`, told as `SipralEventKind.presenceChanged` with
`presenceData.kind == .watched`. `publishPresence(_:)` publishes the
account's own (RFC 3903): the first call publishes, every later one
modifies, the stack refreshes it, and `.presenceChanged` with `.publication`
says what the compositor granted or why it refused; `unpublishPresence()`
takes it away. A call whose far end is a conference's focus (`isfocus`,
RFC 4579) names it with `call.conferenceUri()`, and
`call.subscribeConference()` watches it: each notification is a
`.conferenceChanged`, and `SipralSubscription.conference()` reads the whole
picture -- subject, counts, and every user with its endpoint and status.
This end says it is a focus with `placeCall(focus: true)`,
`answer(focus: true)` or `call.setFocus(true)`.

### Recording to a recording server

```swift
let session = try call.record(toServer: "sip:srs@recorder.example.com", destination: "198.51.100.20:5060")
// ...
try session.stop()
```

`record(toServer:destination:host:)` records a call whose media has started
to a SIPREC recording server (RFC 7866): an INVITE with `Require: siprec`,
the metadata (RFC 7865) and a stream per party, over a TCP connection to
`destination` this stack opens for it, or, with none, where the account
sends -- a stack signalling over TCP or TLS, since the INVITE is too large
for UDP. Both parties' audio is copied from two sockets of its own; the
session follows the call's holds and transfers and ends with it, and
`stop()` hangs it up. The copies of an encrypted call are offered as SRTP
with SDES keys of their own (RFC 7866 §12.2), and a stream the server will
not take that way gets nothing; `AccountSecurity(recordingInClear: true)`
lets that account's encrypted calls be recorded as plain RTP instead.
`Tests/SipralTests/RecordingServerTests.swift` and
`ProtocolsTests.swift` prove each of these.

## A local conference

`LocalConference(stack:)` mixes any number of this stack's calls, each on
its own codec and rate, so that every member hears everybody but itself --
this end too, unless it is made with `local: false`. `add(_:)` and
`remove(_:)` take calls in and out (a full conference, a call already in
one, or a codec it cannot mix throw with `.conferenceRefused`); `setMuted`
and `setGain` act on one way of a member, `nil` naming this end;
`memberList()` and `talkers()` say who is in it and who is talking, loudest
first; `record(to:)` records the whole mix. In device mode the library's
engine carries it; in application mode its own thread does, with
`sendAudio` as this end's microphone and `frames()` what it hears.
`SipralEventKind.localConferenceChanged`, with `localConferenceData`, says
who joined or left and why and who is talking. `LocalConferenceTests.swift`
bridges two calls between three stacks on loopback.

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
