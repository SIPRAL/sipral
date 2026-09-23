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
code calls. `docs/08-ffi.md` says what the binding still does not carry: two
structs a caller part-fills with buffers, which still cross as addresses. The
event payload union does cross now — every event carries every arm the union
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
val account = client.addAccount("sip:alice@example.com", registrarAddress = "203.0.113.5:5060")
account.registerAndWait()
val call = client.placeCall(account, "sip:bob@example.com")
call.waitConfirmed()
call.hold(); call.resume()
call.sendDtmf("123#")
call.hangup()
client.close()
```

Two structs the generated shim has no way to build from Kotlin —
`sipral_media_packet_t` and `sipral_transmit_t`, "two structs a caller
part-fills with buffers" the paragraph above still names — are what
`SipralMedia`/`SipralClient` need to drive real RTP and to drain outgoing
SIP messages; `sipral/src/main/jni/idiomatic_media.c` is a second,
hand-written shim beside the generated one, exposing just those four ABI
calls as plain byte arrays, linked into the same `libsipral_jni` the
generated shim already loads.

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

## The ConnectionService helper

Split in two, so that the part worth testing needs no Android:

- `org.sipral.telecom` (`sipral/src/main/kotlin/org/sipral/telecom/`, inside
  `sipral.aar`) is the logic. `TelecomBridge` runs C2's sequence -- a push
  is reported to the telecom framework first, then announced (which
  refreshes the binding), and the INVITE that follows is matched to the
  screen already up rather than reported again -- and maps the framework's
  answer, reject, hold, unhold, DTMF and disconnect onto the call, and the
  call's progress, hold (both ends'), and end back onto the framework, with a
  `DisconnectCause` for each way a call ends. The framework is behind
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

Which announcement an INVITE answered is in the event payload, which does not
cross this binding yet, so `TelecomBridge` chooses among its own by the same
rule the library applied -- same account, same user and host in `From`,
oldest first on a tie -- and they agree whenever the two readings of the URI
do. An `ANNOUNCED_CALL_MISSING` is the oldest announcement still waiting,
because every announcement waits the same window.

`android/sample` is a Compose skeleton, not a product: register, call, a
simulated push standing in for a push service, answer and decline, hold, a
DTMF keypad and the audio routes, with the device's microphone and speaker
pumped through `SipralMedia` as voice-communication streams.

`scripts/package/android.sh --out DIR --accept-android-sdk-licenses` builds all
three -- `sipral.aar`, `sipral-telecom.aar` and the sample's APK -- inside the
image `android/Dockerfile` describes (the Android SDK, the NDK, cargo-ndk,
kotlinc and Gradle, every download pinned and checked), and opens each to
check it. The flag is the person running it accepting the Android SDK
licence, which the script never does on anybody's behalf. The Gradle
wrapper's properties are committed and its jar is not: the jar is a binary,
so the script generates the wrapper from the Gradle distribution in the
image and checks it reproduces the committed pin. `scripts/check.sh` does not
compile `android/`, since this machine has no Android SDK to compile it
against.

Proven off a phone: the logic, by `TelecomCheck.kt`; the three artefacts,
built and opened. Not provable without one: what the telecom framework itself
does with a self-managed call, audio routing, and push delivery.
