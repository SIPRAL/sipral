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
`docs/08-ffi.md` says what the binding still does not carry: two structs a
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
call.waitConfirmed()
call.hold(); call.resume()
call.sendDtmf("123#")
call.hangup()
client.close()
```

Without `registrar` the account never registers: registering throws, and
the registrar address is only the outbound proxy. The stack and media
sockets default to 127.0.0.1, so name an address the registrar can reach.

Two structs the generated shim has no way to build from Kotlin —
`sipral_media_packet_t` and `sipral_transmit_t`, "two structs a caller
part-fills with buffers" the paragraph above still names — are what
`SipralMedia`/`SipralClient` need to drive real RTP and to drain outgoing
SIP messages; `sipral/src/main/jni/idiomatic_media.c` is a second,
hand-written shim beside the generated one, exposing the five ABI calls
that take them (`sipral_media_capture`, `sipral_media_poll_rtcp`,
`sipral_media_poll_transmit`, `sipral_stack_poll_farewell`,
`sipral_stack_poll_transmit`) as plain byte arrays, linked into the same
`libsipral_jni` the generated shim already loads.

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
  bridge. What the connection tells the framework cannot be seen there; it
  was on an emulator, through `dumpsys telecom` (`docs/15-mobile.md`).

`SIPRAL_EVENT_KIND_CALL_ANNOUNCED` names the announcement an INVITE answered
in `event.payload.announce.announcement`. `TelecomBridge` still matches by
its own rule (same account, same user and host in `From`, oldest first on a
tie), which agrees with the library's whenever the two readings of the URI
do. An `ANNOUNCED_CALL_MISSING` is the oldest announcement still waiting,
because every announcement waits the same window.

`android/sample` is a Compose skeleton, not a product: register, call, a
simulated push standing in for a push service, answer and decline, hold, a
DTMF keypad and the audio routes, with the device's microphone and speaker
pumped through `SipralMedia` as voice-communication streams.

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
from it rung, answered in the sample and hung up --
`docs/15-mobile.md` says what was seen and how to run it again. Not provable
without a phone: real audio routes, and push delivery.
