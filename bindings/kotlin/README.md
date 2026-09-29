<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# The Kotlin binding

Two printed files that have to agree with each other as well as with the ABI:

- `sipral/src/main/kotlin/org/sipral/SipralAbi.kt` — one `external fun` per
  entry point in `SipralNative`, the enumerations, the constants, the
  exception, a class for each struct a caller builds and for each record
  handed over in a list, the listener the event callback reaches, and the layer
  above them where a status becomes a throw.
- `sipral/src/main/jni/sipral_jni.c` — the C that implements them: the casts
  and the array handling, each struct built out of the fields its class crossed
  as, each list made into the C array it stands for, and the function the event
  callback lands in. It is printed from the same walk over the same
  declarations, which is the only reason it is safe for the two to be separate
  files.

Build the shim against `sipral.h` from `bindings/c/include` and link it to the
shared library, `libsipral_ffi.dylib` or `libsipral_ffi.so`, which is what a
JVM can load; the Kotlin side loads it as `sipral_jni` and checks the ABI
version as it does.

```sh
cc -std=c11 -dynamiclib -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/darwin" \
    -Ibindings/c/include -o libsipral_jni.dylib \
    bindings/kotlin/sipral/src/main/jni/sipral_jni.c \
    bindings/kotlin/sipral/src/main/jni/idiomatic_media.c \
    -Ltarget/release -lsipral_ffi
```

On Linux, `-shared -fPIC` in place of `-dynamiclib`, `include/linux` in place
of `include/darwin`, and `libsipral_jni.so` in place of `.dylib`. Run with
`-Djava.library.path` naming the directory the shim landed in.

```kotlin
val stack = Sipral.stackCreate(
    SipralStackConfig(
        eventListener = SipralEventListener { event -> println(event.kind) },
        transport = SipralTransport.UDP.value.toLong(),
        bindAddress = "192.0.2.10:5060",
        entropy = entropy,      // 32 bytes from SecureRandom
        mediaSeed = mediaSeed,  // 32 more, a second draw
    ),
)
Sipral.stackPoll(stack, nowMs)  // the listener is called from in here
```

`sipral/src/test` is what `scripts/check.sh` runs: `BindingCheck.kt`, and a
small C helper that polls from a thread no JVM made, so that the half of the
shim that attaches a thread is run too, and reads back what a stack sends, so
that header fields handed over in a list can be found in the message they went
out in. The gate links both against the shared library and runs them on a JVM
under `-Xcheck:jni`.

The binding itself has no Gradle project: `scripts/package/aar.sh` assembles
`sipral.aar` by hand, straight to Android's own archive format, with
`libsipral_jni.so` (both shims) linked against `libsipral_ffi.so` for
arm64-v8a, armeabi-v7a and x86_64 beside the compiled classes of everything
under `sipral/src/main/kotlin`, and a `proguard.txt` keeping what only native
code calls. The classes are compiled for Kotlin 2.2 (`-language-version` and
`-api-version`), so that an application built with Kotlin 2.1 or later -- the
Android Gradle Plugin 9's own is 2.2 -- can compile against them.
`docs/08-ffi.md` says what the binding still does not carry: three structs a
caller part-fills with buffers, which still cross as addresses. The event
payload union does cross now — every event carries every arm the union
declares, read back through `SipralEvent.payload`, one class per arm.

## The idiomatic layer

`org.sipral.idiomatic` (`sipral/src/main/kotlin/org/sipral/idiomatic/`) is
what an application actually reaches for: `SipralClient`, `SipralAccount`,
`SipralCall` and `SipralMedia`, `AutoCloseable` and built on top of `Sipral`
above rather than instead of it. Events are a `kotlinx.coroutines.Flow`, and
`SipralAccount.registerAndWait`/`SipralCall.waitConfirmed`/`waitEnded` are
suspend functions that complete when the matching event does rather than
when the ABI call that started them returns.

```kotlin
val client = SipralClient.open(bindHost = "192.0.2.10")
val account = client.addAccount(
    "sip:alice@example.com",
    registrarAddress = "203.0.113.5:5060",
    registrar = "sip:example.com",
    authUser = "alice",
    authPassword = secret,
)
account.registerAndWait()
val call = client.placeCall(account, "sip:bob@example.com", mediaHost = "192.0.2.10")
call.waitConfirmed()        // heard at once: the client is in device mode wherever the library has an engine
call.hold(); call.resume()
call.sendDtmf("123#")
call.hangup(SipralHangupReason.NORMAL_CLEARING)   // or hangup(), with no Reason
client.close()
```

Without `registrar` the account never registers: registering throws, and
the registrar address is only the outbound proxy. The stack and media
sockets default to 127.0.0.1, so name an address the registrar can reach.

### The library runs the audio

`SipralClient.open(audio = ...)` takes a `SipralAudioMode`.
`SipralAudioMode.Device(activation)` -- `SipralAudioMode.platformDefault`
wherever this build of the library has an engine for the platform, macOS and
Windows on a JVM -- has the library open the devices with the first call's
media or the first ring and close them with the last (`AUTOMATIC`), or only
between `audio.activate()` and `audio.deactivate()` (`MANUAL`): every call is
resampled to the device's rate and mixed into the loudspeaker, the microphone
goes into every call, and the platform's own echo processing sits behind it.
Each packet the engine encodes reaches this layer on the engine's thread, and
goes out of the call's own socket or on its connection to a TURN server.
`SipralAudioMode.Application` is the client as it was: `SipralMedia.sendAudio`
and `frames` carry the call's PCM, for a voice agent, a recorder, a test --
and Android, where the default is `Application` because the devices belong to
the telecom helper (below).

`client.audio` is the engine: `refresh()`/`devices()` list
`SipralAudioDeviceInfo` with channel counts under ids that survive a refresh
and an unplug; `select(role, device)` puts the `MICROPHONE`, the `SPEAKER` or
the `RINGER` on one, or back on the system's route with null, refused by
status before anything opens (`NO_SUCH_DEVICE`, `DEVICE_UNUSABLE`,
`NOT_SUPPORTED` where the platform cannot -- on macOS the microphone follows
the voice-processing unit's system input and the ring plays on the
loudspeaker); `selection(role)` says what was asked and what runs while a
chosen device is unplugged; `setGain(direction, factor)` (1.0 is unity, the
input direction is the microphone's gain) and `setMuted` belong to the
direction and survive a change of device; `level(direction)` is the meter, 0
to 1; `ring(tone, rate)`/`stopRinging()` play on the ringer; `status()` says
whether the devices are open, the render delay and whether the platform
cancels the echo. `audioOf(event)` reads `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED`:
`changeKind`, and `originKind` -- `SYSTEM` or `ENGINE`, and an application
re-applies nothing on the second.

### Who is calling, why a call ended, and where it goes

```kotlin
client.events.collect { event ->
    if (event.kind != SipralEventKind.INCOMING_CALL.value.toLong()) return@collect
    val identity = client.callerIdentity(event)   // before answering
    val name = identity.asserted?.displayName ?: event.payload.call.fromDisplay?.toString(Charsets.UTF_8)
    if (SipralPrivacy.ID in identity.privacy) { /* number withheld */ }
    client.answering(event).answerAfterMs?.let { /* the caller asked to be answered without the person */ }
    client.redirectCall(event, listOf("sip:desk@example.com"), reason = "no-answer")   // a 302
}
```

`SipralCallerIdentity` is what the network asserted -- `P-Asserted-Identity`,
a calling `Remote-Party-ID`, `verstat` -- read only from a peer the account
trusts (`trustedPeers`, RFC 3325 §8), the caller's `Privacy`, every
`Diversion` (RFC 5806) and `History-Info` entry (RFC 7044). `SipralAnswering`
is `Answer-Mode`/`Priv-Answer-Mode` (RFC 5373), `answer-after` and every
`Alert-Info` with the ring source it names. `SipralCall.identity()` and
`answering()` read the same for a call answered from its event.
`SipralCall.hangup(reason)` writes a `Reason` (RFC 3326) on the BYE or the
CANCEL -- `SipralHangupReason.COMPLETED_ELSEWHERE` is what a phone that lost a
fork race is told -- and `endCauseOf(event)` reads the far end's off
`CALL_ENDED`. `SipralCall.redirect(targets)` answers a ringing call with a
3xx. `srtpSuiteOf(event)` names the suite a DTLS-SRTP call was keyed with,
RFC 6188's AES-256 and RFC 7714's AES-GCM among them; `SipralClient.open(srtp
= ...)` sets every call's policy.

### The account's options

```kotlin
val account = client.addAccount(
    "sip:alice@example.com",
    registrarAddress = "203.0.113.5:5060",
    sessionTimer = SipralSessionTimerChoice.Interval(600),   // or Off; thirty minutes by default
    privacy = setOf(SipralPrivacy.ID),                        // withhold my number
    trustedPeers = listOf("203.0.113.5"),                     // whose asserted identity is believed
)
```

### A call on the move

`client.networkChanged(SipralNetwork(SipralLink.WIFI, "10.0.0.7", interfaceName = "wlan0"))`
tells the stack the platform moved it. When the address or the interface
changed (`SipralRecovery.REBUILD`) the signalling socket is bound again there,
every account is pointed at it, and every call up raises
`SIPRAL_EVENT_KIND_CALL_ADDRESS_WANTED`: `call.moveMedia()` binds a socket on
the new network and offers the call there with a re-INVITE that moves only
`c=` and the port (RFC 3264 §8.3.1). A call under ICE moves with
`restartIce()` instead.

`src/test/kotlin/org/sipral/idiomatic/SignallingCheck.kt` proves all of the
above between two clients on loopback, and `AudioCheck.kt` the engine on this
machine's devices: the list, the choices and the settings always, and what
opens the devices -- activation, the ring, a call in device mode -- only with
`SIPRAL_AUDIO_DEVICES=1`, since on macOS the voice-processing unit needs the
microphone granted to the JVM's process and takes the process down without
it.

Three structs the generated shim has no way to build from Kotlin —
`sipral_media_packet_t`, `sipral_transmit_t` and `sipral_path_candidate_t`,
"three structs a caller part-fills with buffers" the paragraph above still
names — are what `SipralMedia`/`SipralClient` need to drive real RTP, to
drain outgoing SIP messages and to say which ICE paths a call tried;
`sipral/src/main/jni/idiomatic_media.c` is a second, hand-written shim beside
the generated one, exposing the ABI calls that take them
(`sipral_media_capture`, `sipral_media_poll_rtcp`,
`sipral_media_poll_transmit`, `sipral_stack_poll_farewell`,
`sipral_stack_poll_transmit`, `sipral_stack_poll_stun`,
`sipral_media_path_candidate_at`) as plain byte arrays, linked into the same
`libsipral_jni` the generated shim already loads -- and
`sipral_stack_transport_bind` with no remote, which the generated
`stackTransportBind` cannot say: it hands an empty array over as a remote
address.

It depends on `kotlinx-coroutines-core-jvm` (Apache-2.0,
`THIRD-PARTY-NOTICES.md`), fetched once into a cache outside the repository
and reused offline afterward; `scripts/check.sh` names the exact path and
checksum it expects if that cache is not there.

A `SIPRAL_EVENT_KIND_DIGIT_RECEIVED` reads its digit off `event.payload.media`
now, an RFC 4733 (RTP) one the same as one of the two INFO forms — `digitOf`
reads `event.payload.media.digit` directly, and `SipralAccount.registerAndWait`
reads the state a terminal `REGISTRATION_CHANGED` reached off
`event.payload.registration.state`, rather than a second, synchronous call
back into the stack for something the event already said.

`SipralAccount.announce` and `refreshBinding`, `SipralClient.forgetAnnouncement`
and a `SipralPush` on `addAccount` are `docs/15-mobile.md`'s C2 and push
parameters from Kotlin.

`SipralClient.events` and `SipralCall.events` (and `SipralCall.digits`,
derived from it) are a `kotlinx.coroutines.flow.SharedFlow` with `replay =
0`: a fresh subscriber never sees a value emitted before it subscribed, no
matter how large `extraBufferCapacity` is -- that capacity only lets
emitting keep up with an existing *slow* collector, it never queues a value
for one that has not subscribed yet. `events.first { it.kind == X }` run
*after* the action that is expected to cause kind `X`, rather than before
it, can therefore subscribe too late to ever see that event, and then match
the *next* one of that kind instead -- from another call on the same
client, say, not the one the action caused. `SharedFlow<SipralEvent>.awaitNext`
(`org.sipral.idiomatic.SipralEventWait.kt`) is the fix: it subscribes
before running its `action`, the same order `SipralAccount.registerAndWait`
and `SipralCall.waitConfirmed`/`waitEnded` already keep.

That `extraBufferCapacity` is 4096 events, with `onBufferOverflow =
DROP_OLDEST`: it does not make a slow collector see everything, only lets
it lag up to 4096 events behind before its oldest unread ones start being
silently discarded to make room for new ones -- no exception, no signal,
delivery never blocks the poll thread and the buffer never grows past that.
A collector meant to see every event keeps its own per-event work short.

```kotlin
val (call, incoming) = client.events.awaitNext(SipralEventKind.INCOMING_CALL) {
    peer.placeCall(peerAccount, target = "sip:alice@example.com")
}
val answered = client.answerCall(incoming)
```

### Behind a NAT

```kotlin
val client = SipralClient.open(
    bindHost = "10.0.2.16",
    ice = SipralIce.OFFERED,                // every call; placeCall(ice = ...) overrides one
    stunServer = "198.51.100.1:3478",       // an address, not a name
    turn = SipralTurnServer("198.51.100.1:3478", "alice", secret),
)
```

Every option left null is the build's own default, so a client opened without
them behaves as it always did: no STUN, no ICE, no relay. With `stunServer`
the signalling socket asks the server where it appears from, and every
account's `Contact` moves to that public address: `natOf(event)` reads the
`SIPRAL_EVENT_KIND_NAT_MAPPING` payload, `relayOf(event)` the
`SIPRAL_EVENT_KIND_NAT_RELAY` one. `placeCall` and `answerCall` ask the same
about the call's media socket before the call is described and block until
the server has answered, or five and a half seconds on without an answer
(longer with a TURN server) — call them off the main thread. Until the call
has media, the poll thread reads that socket, sends what
`sipral_stack_poll_stun` names it as the source of (through
`idiomatic_media.c`'s `stackPollStun`), and hands everything arriving there to
`sipral_stack_receive_stun`. The relay is offered only as an ICE candidate,
so it is used only with `ice`. `SipralTurnServer.toString()` leaves the
password out. `g729AnnexB = false` turns off G.729's silence compression.
`ice = SipralIce.LITE` is the server's value, never the phone's: an ICE-lite
endpoint (RFC 8445 §2.5) for a host reachable at the address it advertises,
answering full ICE peers.
`src/test/kotlin/org/sipral/idiomatic/NatCheck.kt`, run by `scripts/check.sh`
with `IdiomaticCheck.kt`, proves each on the wire against a STUN and TURN
server inside the check, and carries a call between two clients that require
ICE and one between a lite client and a full one.

Behind a NAT, every account `stunServer` showed to be behind one keeps its
registrar's flow open: a double CRLF, alone in a datagram, every 20 to 25
seconds, so that a NAT filtering by address and port keeps letting the
registrar's INVITE in long after the REGISTER (`docs/06-nat.md`).
`registrarKeepalive = false` turns it off and `registrarKeepaliveMs` sets the
interval, 1 000 to 120 000; nothing goes while the stack is suspended.
`NatCheck.kt` proves both on the wire.

`SipralTurnServer(..., transport = SipralTransport.TCP)` reaches the TURN
server over TCP, for the network that lets no UDP out, and `TLS` over TLS
(RFC 8656 §3.1), 5349 being the port for it: the client opens a `Socket` per
media socket when `SIPRAL_EVENT_KIND_TURN_STREAM` asks (`turnStreamOf`), an
`SSLSocket` over it for TLS, carries everything for the relay on it and
closes it when told. The certificate is checked against `serverName` — the
host part of `address` when null — with HTTPS endpoint identification, by
`sslSocketFactory` or the platform's default; a factory over a
`TrustManagerFactory` of the application's own is how a private CA or a
self-signed server is trusted. `NatCheck.kt` proves it against a TURN server
on a TCP port inside the check, over TLS with a certificate trusted and not.

### A REFER from outside any call

`SipralClient.open(referrals = true)` hands a REFER that names no dialog —
click-to-dial from a switchboard, RFC 3515 §4.1 — to the application as
`SIPRAL_EVENT_KIND_REFERRAL`; `referralOf(event)` reads who to call, whether
it is attended and who the sender says is asking. `client.acceptReferral(event)`
answers 202, reports on the call to whoever asked and places it from the line
it arrived for, returning that `SipralCall`; `client.rejectReferral(event, 603)`
refuses it. **Off by default, and then every one is refused 403**: a peer that
can make a phone dial is a toll-fraud vector, so each one is the
application's decision. `ReferralCheck.kt`, run with `IdiomaticCheck.kt`,
proves both halves on the wire.

## The ConnectionService helper

Split in two, so that the part worth testing needs no Android:

- `org.sipral.telecom` (`sipral/src/main/kotlin/org/sipral/telecom/`, inside
  `sipral.aar`) is the logic. `TelecomBridge` runs C2's sequence -- a push
  is reported to the telecom framework first, then announced (which
  refreshes the binding), and the INVITE that follows is matched to the
  screen already up rather than reported again -- and maps the framework's
  answer, reject, hold, unhold, DTMF and disconnect onto the call, and the
  call's progress, hold (both ends'), and end back onto the framework, with a
  `DisconnectCause` for each way a call ends -- including a call that ended
  while the framework was still creating its connection, whose connection is
  disconnected with that cause the moment it exists. `endAll` ends every call
  at once, for an application about to close its client: once the client is
  closed nothing would end them, and a connection nobody ends stays up in
  the framework for as long as the process lives. The framework is behind
  `TelecomPlatform` and `TelecomConnection` and the SIP side behind
  `SipCalls`, the way the Swift layer puts CallKit behind
  `CallKitProviding`; `IdiomaticSipCalls` is `SipCalls` over
  `org.sipral.idiomatic`. `sipral/src/test/kotlin/org/sipral/telecom/TelecomCheck.kt`
  drives it through fakes of both sides, one sequence per race
  `docs/15-mobile.md` names, and then end to end over two real stacks on
  loopback with only the framework faked; `scripts/check.sh` runs it.
- `android/telecom` is the Android library over it: a self-managed
  `PhoneAccount` (`SipralTelecom.registerAccount`), the `ConnectionService`
  its manifest declares, a `Connection` per call, and `AndroidTelecomPlatform`
  over `TelecomManager`. Audio routing is left to the platform: a connection
  reports the routes the platform offers (`CallEndpoint` on Android 14 and
  later, `CallAudioState` before) and passes a choice back, and never touches
  `AudioManager`. API 37 marks `PhoneAccount.CAPABILITY_SELF_MANAGED`
  deprecated, and the platform's newer route for a calling application is
  the transactional telecom API (API 34); the capability is still what a
  self-managed `ConnectionService` needs on Android 8.0 to 17, and an adapter
  over the transactional API would sit over the same `TelecomBridge`.
  `android/telecom/src/test` runs the connection's callbacks on the JVM
  against the platform's stub jar, with TestNG: every one the framework may
  answer, turn away (`onReject` with no argument, with a reason, or with a
  message), hang up, abort, hold, resume or send a digit through reaches the
  bridge, a hold says held at once, the framework's mute is reported, and
  losing the call focus lets every call's device go before the service
  tells the framework it has. What the connection tells the framework
  cannot be seen there; it was on an emulator, through `dumpsys telecom`
  (`docs/15-mobile.md`).

A hold from the framework -- a cellular call answered over this one, a
headset's or a car's button -- says held at once and holds the far end
with a re-INVITE: `Connection.onHold` disconnects a connection that is not
held within two seconds, so held cannot wait for the far end's answer.

The call's audio, and C4 of `docs/13-client-requirements.md` -- the device
taken away and given back mid-call -- is `CallAudio` in
`org.sipral.telecom`, over an `AudioDevice`, and on Android
`SipralCallAudio`, one per call. `SipralCallAudios` is the library running
them all: each call the bridge shows gets its `SipralCallAudio` when its
media starts and loses it when it ends, so an application writes no audio
code of its own -- it reads what happens:

```kotlin
val audios = SipralCallAudios(context, bridge, sip, client.events, scope)
scope.launch { audios.transitions.collect { (callId, change) -> log(callId, change) } }
// Started, Paused(reasons), Resumed, RouteChanged, MuteChanged,
// DeviceFailed, DeviceRestored, Stopped
scope.launch { audios.states.collect { show(it) } }   // each call's AudioState, by id
```

It follows the call through the bridge (let go while held, taken back when
active, closed when it ends), the call focus the framework moves between
calling applications, the routes and mute the framework applies, and
`ERROR_DEAD_OBJECT` from `AudioRecord` or `AudioTrack`, after which both are
built again until they open. The far end is sent silence whenever there is
no device: `SipralMedia` keeps its own frame clock. `CallAudioCheck.kt` runs
all of it against a fake device on a plain JVM, and `docs/15-mobile.md`
("C4") says what the emulator showed.

`SIPRAL_EVENT_KIND_CALL_ANNOUNCED` names the announcement an INVITE answered
in `event.payload.announce.announcement`. `TelecomBridge` still matches by
its own rule (same account, same user and host in `From`, oldest first on a
tie), which agrees with the library's whenever the two readings of the URI
do. An `ANNOUNCED_CALL_MISSING` is the oldest announcement still waiting,
because every announcement waits the same window.

`android/sample` is a Compose skeleton, not a product: register, call, a
simulated push standing in for a push service, answer and decline, hold, a
DTMF keypad and the audio routes, with every call's microphone and speaker
run by `SipralCallAudios` and every audio transition in its log -- it has no
audio code of its own.

`scripts/package/android.sh --out DIR --accept-android-sdk-licenses` builds all
three -- `sipral.aar`, `sipral-telecom.aar` and the sample's APK -- inside the
image `android/Dockerfile` describes (the Android SDK, the NDK, cargo-ndk,
kotlinc and Gradle, every download pinned and checked), runs the helper's
unit tests, and opens each artefact to check it. The flag is the person running it accepting the Android SDK
licence, which the script never does on anybody's behalf. The Gradle
wrapper's properties are committed and its jar is not: the jar is a binary,
so the script generates the wrapper from the Gradle distribution in the
image and checks it reproduces the committed pin. `scripts/check.sh` does not
compile `android/`, since this machine has no Android SDK to compile it
against.

Proven off a phone: the logic, by `TelecomCheck.kt`; the connection's
callbacks reaching it, by the helper's unit tests; the three artefacts, built
and opened. Proven on an Android 16 emulator: the sample's APK installing,
loading both natives, and placing, holding, resuming and hanging up a call
with the telecom framework following each state, a simulated push ringing
through the framework and its incoming-call notification, and, registered
with the lab's Asterisk, a call placed through it and an incoming INVITE
from it rung, answered in the sample and hung up, a GSM call answered over a
live call holding it and the call resumed with media both ways, and the
audio server stopped mid-call and the device rebuilt --
`docs/15-mobile.md` says what was seen and how to run it again. Not provable
without a phone: switching between real audio routes (the emulator offers
only its speaker), a Bluetooth headset or a car, a carrier's call, and push
delivery.
