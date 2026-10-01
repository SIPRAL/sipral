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
    bindings/kotlin/sipral/src/main/jni/audio_routes.c \
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
call.transfer("sip:carol@example.com")   // blind: TRANSFER_DONE, read with transferOf, says how it went
call.hangup(SipralHangupReason.NORMAL_CLEARING)   // or hangup(), with no Reason
client.close()
```

Without `registrar` the account never registers: registering throws, and
the registrar address is only the outbound proxy. Left out, `bindHost` and
`mediaHost` are the address of the route toward the registrar.

### The library runs the audio

`SipralClient.open(audio = ...)` takes a `SipralAudioMode`.
`SipralAudioMode.Device(activation)` -- `SipralAudioMode.platformDefault`
wherever the library has an engine for the platform, macOS and Windows on a
JVM and Android from API level 28 -- has the library open the devices with the first call's
media or the first ring and close them with the last (`AUTOMATIC`), or only
between `audio.activate()` and `audio.deactivate()` (`MANUAL`): every call is
resampled to the device's rate and mixed into the loudspeaker, the microphone
goes into every call, and the platform's own echo processing sits behind it.
Each packet the engine encodes reaches this layer on the engine's thread, and
goes out of the call's own socket or on its connection to a TURN server.
`SipralAudioMode.Application` is the client as it was: `SipralMedia.sendAudio`
and `frames` carry the call's PCM, for a voice agent, a recorder, a test --
and an Android phone below API level 28, where the default is `Application`
and the telecom helper (below) carries each call over `AudioRecord` and
`AudioTrack`.

On Android the engine's streams are AAudio's (voice communication, the
platform's echo canceller in the input preset, a ringtone stream for the
ringer), and its devices and routes are `AudioManager`'s:
`SipralAndroidAudio.attach(context)` hands it a context, after which
`devices()` lists the earpiece, the loudspeaker, a wired or Bluetooth headset
as the phone has them, `select(SPEAKER, device)` moves every call there (the
communication device from API level 31, the speakerphone and Bluetooth SCO
switches before it), and a headset arriving or the route moving arrives as
`AUDIO_DEVICES_CHANGED`. Without it the list is empty and calls follow the
platform's route. `SipralCallAudios` calls it itself.

`client.audio` is the engine: `refresh()`/`devices()` list
`SipralAudioDeviceInfo` with channel counts under ids that survive a refresh
and an unplug; `select(role, device)` puts the `MICROPHONE`, the `SPEAKER` or
the `RINGER` on one, or back on the system's route with null, refused by
status before anything opens (`NO_SUCH_DEVICE`, `DEVICE_UNUSABLE`,
`NOT_SUPPORTED` where the platform cannot -- on iOS, whose route is the audio
session's, the microphone and the ringer); `selection(role)` says what was asked and what runs while a
chosen device is unplugged; `setGain(direction, factor)` (1.0 is unity, the
input direction is the microphone's gain) and `setMuted` belong to the
direction and survive a change of device; `level(direction)` is the meter, 0
to 1; `ring(tone, rate)`/`stopRinging()` play on the ringer; `status()` says
whether the devices are open, the render delay and whether the platform
cancels the echo. `audioOf(event)` reads `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED`:
`changeKind`, and `originKind` -- `SYSTEM` or `ENGINE`, and an application
re-applies nothing on the second.

Each call has a gain, a mute and a meter of its own on top of the
direction's: `setGain(call, direction, factor)`, `gain(call, direction)`,
`setMuted(call, direction, muted)`, `isMuted(call, direction)` and
`level(call, direction)`. The input direction is what the microphone sends
that call alone and the output how loud it is in the loudspeaker beside the
others -- mute the call being spoken about in a consultation, turn one
conference member down. They hold from the moment the call's media starts
to its end, through a hold or a local conference and back, and throw with
`WRONG_STATE` outside that. `open(systemEchoCancellation = false)` opens the
devices past the platform's echo cancellation -- on Android the microphone
with the voice-recognition preset rather than the voice-communication one --
for a headset, which has no echo to cancel, or an application that cancels
it on each call itself; `status()` says what the platform did.

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

### STIR/SHAKEN, SRTP per account and the encryption report

`addAccount(..., security = SipralAccountSecurity(stirKey = key,
stirCertificateUrl = url))` signs every call the account places (RFC 8224,
with RFC 8588's `attest` and `origid`); the key is the bare 32 bytes or SEC1
or PKCS #8 in DER or PEM, and the client needs the time first:
`client.stir(null)` on one that only signs. A signed INVITE is some five
hundred octets longer, and past RFC 3261's 1300 over UDP it needs a stream
transport. `client.stir(anchors)` verifies the callers of every account that
reports (the default) or is `SipralStirVerification.STRICT`:
`SIPRAL_EVENT_KIND_CALLER_VERIFICATION`, read with `verificationOf(event)`,
asks at `CERTIFICATE_WANTED` for the chain at `certificateUrl`, which
`client.stirCertificate(event.call, chain)` hands over (null for one that
could not be had); the verdict follows as the same kind, just before the
call, and `SipralCallerIdentity.verification` carries it.
A certificate covers the numbers its TNAuthList names (RFC 8226 §9); one that
names a service provider code instead, as a SHAKEN certificate does, covers
no caller until `client.stir(anchors, acceptServiceProviderCodes = true)`
says the deployment trusts its certified providers that far.
`SecurityCheck.kt` proves both verdicts with the chain in
`bindings/fixtures/stir-provider-709J`.
`SipralAccountSecurity(srtp = SipralSrtp.REQUIRED, srtpSuites =
listOf("AES_CM_128_HMAC_SHA1_80"))` holds every call of one account to its
own SRTP policy and suites; a call may ask for more and never less.
`call.media?.encryption()` is the encryption report (`SipralStreamProtection`:
how the keys were exchanged, encrypted, the suite, and whether the exchange
authenticated the far end), and `payload.media` carries the same on media
started, changed and secured.

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
it. On a Mac with the virtual loopback device `BlackHole 2ch` those put every
role on it, so nothing sounds through the machine's loudspeaker.

Three structs the generated shim has no way to build from Kotlin —
`sipral_media_packet_t`, `sipral_transmit_t` and `sipral_path_candidate_t`,
"three structs a caller part-fills with buffers" the paragraph above still
names — are what `SipralMedia`/`SipralClient` need to drive real RTP, to
drain outgoing SIP messages and to say which ICE paths a call tried;
`sipral/src/main/jni/idiomatic_media.c` is a second, hand-written shim beside
the generated one, exposing the ABI calls that take them
(`sipral_media_capture`, `sipral_media_mix`, `sipral_media_poll_rtcp`,
`sipral_media_poll_transmit`, `sipral_media_poll_text`,
`sipral_media_poll_recording`, `sipral_stack_poll_farewell`,
`sipral_local_conference_poll_transmit`, `sipral_stack_poll_transmit`,
`sipral_stack_poll_stun`, `sipral_media_path_candidate_at`) as plain byte
arrays, linked into the same `libsipral_jni` the generated shim already
loads. An empty string is a length of zero, which the library reads as an
address left out, so the generated `stackTransportBind` with a remote of
`""` binds with no remote.

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

`stunFallbacks = listOf("198.51.100.2:3478")` names the STUN servers to turn
to, in order, when `stunServer` stops answering; every socket moves on by
itself, and a `STUN_SERVER` event (read with `stunServerOf`: the state, the
server, the one before it) says when the server in use changed or every one
failed (`docs/06-nat.md`, "More than one server").
`client.setStunServers(listOf(...))` replaces the list on an open client,
and turns STUN on for one opened without it; an empty list turns it off
again.

Behind a NAT, every account `stunServer` showed to be behind one keeps its
registrar's flow open: a double CRLF, alone in a datagram, every 20 to 25
seconds, so that a NAT filtering by address and port keeps letting the
registrar's INVITE in long after the REGISTER (`docs/06-nat.md`).
`registrarKeepalive = false` turns it off and `registrarKeepaliveMs` sets the
interval, 1 000 to 120 000; nothing goes while the stack is suspended.
`NatCheck.kt` proves both on the wire.

A client holds 128 calls at once unless `maxDialogs` says otherwise: past
it an incoming call is answered 503 and `placeCall` throws with
`LIMIT_REACHED`. `maxServerTransactions` (256), `diagnosticDecisions` (64)
and `diagnosticRecords` (32) are the other ceilings, zero for the default
each (`docs/08-ffi.md`, "Limits, and what went out twice").

### Where a client is reached, and where its server is

`SipralClient.open()` with no `bindHost` listens on every interface and
advertises the address of the operating system's route toward the server of
its first account (`advertisedAddress`, `sipral_advertised_address`): the
address a PBX on the network reaches the device at, and `127.0.0.1` for a
server on this machine. Each account is reached at the route toward its own
server, and a call's media socket, without `mediaHost`, at the route toward
the far end or the account's server. The library refuses to advertise a
loopback address to a peer elsewhere: `UNREACHABLE_ADDRESS`, and
`SipralRegistrationFailure.UNREACHABLE_CONTACT` for a REGISTER it sends on
its own.

`addAccount(aor, serverUri = "sip:pbx.example.com")` names the server by a
URI whose host RFC 3263 locates, in place of `registrarAddress`. The client's
`resolver` answers each `LOOKUP_WANTED` (read with `locateOf`):
`SipralDns.platform` by default, which asks `InetAddress` for addresses and,
on a JVM, JNDI's DNS provider for SRV and NAPTR. Android has no JNDI: there
SRV and NAPTR are answered `NOTHING` and the procedure goes on to the host's
own addresses, and an application whose server publishes SRV records passes
a resolver built on `android.net.DnsResolver` (API 29). Neither platform
lookup reports a time-to-live, so a minute is given. `LOCATED` says where
the server was found (`account.registrarAddress` follows it) and
`LOCATE_FAILED` why not.

`keepaliveMs` keeps an account's flow to its server open whatever STUN found.
`SipralTlsTrust.Pinned("SHA256=AB:CD:...")` trusts the one certificate with
that fingerprint on a TLS signalling connection, whoever signed it and
whatever name it carries; an account's `tlsPin` and
`SipralAccount.checkCertificate(der)` are the same verdict for an application
that runs the account's TLS itself.

`srtp = SipralSrtp.BEST_EFFORT` offers SDES on plain RTP/AVP, for a PBX that
answers an RTP/SAVP offer with 488; `srtpSuites` names the suites every call
offers. `pathMtu` tells RFC 3261 §18.1.1 the path's MTU, and
`datagramWithoutStreamBytes` sends a request over UDP anyway once no stream
to a UDP-only server can be had -- a deliberate deviation, written to
`diagnosticsJson()` as `transport.kept.datagram`. `pseudonymSalt` keys the
log's pseudonyms so that two runs compare, and `diagnosticTrace` (or
`setDiagnosticTrace(true)`) writes whole SIP messages at the trace level,
credentials and keys taken out.

### The log, the state and the counters

```kotlin
client.logTo()                                   // java.util.logging, "sipral"
Logger.getLogger("sipral.sip").level = Level.FINEST   // whole SIP messages
println(client.counters().requestsRetransmitted)
crashReport.attach(client.state())               // redacted, from any thread
```

`logTo(logger, level)` sends the client's log to `java.util.logging`, which
every JVM and Android carries (on Android it reaches logcat): each line to
the child logger of the part of the stack that wrote it (`sipral.call`,
`sipral.registration`, `sipral.sip`, `sipral.api`, ...), `ERROR` as
`SEVERE`, `WARN` as `WARNING`, `INFO` as `INFO`, `DEBUG` as `FINE` and
`TRACE` as `FINEST` (`julLevelOf`). Left null, `level` follows the logger's
effective level. An application on SLF4J or Timber hands `setLog` a lambda
that calls it instead. Every line is redacted before it leaves the library:
no user part, number, IP address or credential (`docs/17-observability.md`).
`counters()` returns the `SipralCounters` data class: registrations, how
calls ended, what screening refused and, since ABI 0.30,
`requestsRetransmitted`, `responsesRetransmitted`, `transactionsTimedOut` and
`requestsRefusedAtLimit`. `state()` is the redacted text snapshot of what the
stack holds. `open(rtpPortMin = ..., rtpPortMax = ...)` keeps every media
socket the client opens inside a firewall's range. `LoggingCheck.kt` proves
each.

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

### What a call carries in its audio, and recording it

A digit the far end leaves in the audio arrives as
`SIPRAL_EVENT_KIND_IN_BAND_DIGIT`, read with `digitOf` like any other: by
default on a call that negotiated no telephone event, and on every call or
none with `SipralClient.open(dtmfDetection = SipralDtmfDetection.ALWAYS)` /
`OFF` or `call.setDtmfDetection(...)`. `call.sendDtmf(digits)` writes the
tones into the audio where the far end took no telephone event, and
`via = SipralDtmf.IN_BAND.value.toLong()` does so on any call.
`call.detectProgress(SipralProgressOptions(...))`, straight after
`placeCall`, reports the network's tones, who answered and the machine's
beep as `SIPRAL_EVENT_KIND_PROGRESS_DETECTED`, read with `progressOf`.
`call.setConsentTone(...)` beeps while the call is recorded.
`media.record(path, format, layout, sampleRate, bitrate, checkpointMs)`
writes WAV or Ogg Opus, mixed or stereo with this end on the left, and
`stopRecording()` / `recording` stop it and say how far it got.
`InBandCheck.kt`, run with `IdiomaticCheck.kt`, proves each on loopback.

### SIP over TCP or TLS

```kotlin
val client = SipralClient.open(
    bindHost = "192.0.2.20",
    signalling = SipralTransport.TLS,
    signallingServer = "198.51.100.10:5061",
    tlsServerName = "pbx.example.com",
    tlsTrust = SipralTlsTrust.OnlyAuthority(pbxAuthority),
)
val account = client.addAccount(
    aor = "sip:alice@example.com", registrarAddress = "198.51.100.10:5061", registrar = "sip:example.com",
)
account.register()
client.events.collect { event ->
    transportFailedOf(event)?.let { println("${SipralTlsFailure.of(it.tls.toInt())}: ${it.detail}") }
}
```

`signalling` is `SipralTransport.UDP` (the default), `TCP` or `TLS`. Over
either of the last two the client keeps one connection to `signallingServer`,
the registrar or the outbound proxy, and every account and call rides on
it; a `Contact` this layer writes names the transport. Over TLS the chain is
checked by the platform's trust managers — `SipralTlsTrust.Platform` (the
default), `PrivateAuthority(cert)` beside them, or `OnlyAuthority(cert)`
alone, on the JVM and on Android alike — and the name, `tlsServerName` or
the server's host, by the HTTPS rules. The first connection is made in
`open`. One that fails, or breaks later, arrives as
`SIPRAL_EVENT_KIND_TRANSPORT_FAILED`, read with `transportFailedOf(event)`:
`tls` untrusted, name mismatch, expired or handshake refused, the `error`,
and `SSLSocket`'s own `detail`. The client connects again, one second later
and up to thirty seconds apart, registering every account again once it is
back; `client.connected` says whether it is up, and `account.register()`
asked meanwhile is kept for then. `docs/22-tls.md` has the whole mapping.

An account can have a connection of its own on a client that signals over
UDP, so that one client and one audio engine hold an account on UDP with
one PBX and another on TCP or TLS with a second:

```kotlin
val client = SipralClient.open()
val office = client.addAccount("sip:alice@office.example", "192.0.2.10:5060", registrar = "sip:office.example")
val carrier = client.addAccount(
    "sip:+15550100@carrier.example", "198.51.100.20:5061", registrar = "sip:carrier.example",
    tlsPin = "sha256 Fingerprint=AB:CD:...", streamProtocol = SipralTransport.TLS,
)
```

The stack asks for the connection with `SIPRAL_EVENT_KIND_TRANSPORT_WANTED`,
nothing outgrown, and the client opens it to the account's server whatever
`streamFallback` says: a TLS one held to the account's `tlsPin` when it has
one, to `tlsTrust` under `tlsServerName` otherwise. The account's REGISTER
and every request of its calls go over it, its `Contact` names the
protocol, and a connection that closes is opened again and the account
registered again. Until it is open a call the account places throws with
`TRANSPORT_DOWN`.

`client.settings()` reads back what the stack runs with, every default
filled in (`SipralSettings`): the timers, the codecs' count, the SRTP
suites its calls offer in order, whether a pseudonym salt was given,
whether the diagnostic trace is whole now, and whether the platform's echo
cancellation is asked for.

`inviteLimit` is how fast one address may ring the client: every client
starts at `SipralInviteLimit.DEFAULT`, ten INVITEs at once and one every
two seconds, past which a call is answered 480. A voice agent behind a
trunk takes `SipralInviteLimit.VOICE_AGENT`, a hundred and twenty-eight at
once and twenty a second.

### Real-time text, RTCP feedback and linear audio

```kotlin
val call = client.placeCall(account, target = "sip:bob@example.com", text = true, feedback = true)
// on the far end: client.answerCall(event, text = true, feedback = true)
scope.launch { call.text.collect { println(it.text) } }
call.media?.sendText("hello")
```

`text = true` binds a second socket beside the audio one and offers
real-time text on it (RFC 4103, T.140 with redundancy); `answerCall(event,
text = true)` takes the text an offer carries. Once both ends agree,
`media.sendText` types (a new line and BACKSPACE included), `call.text`
is what the far end typed, each a `SipralTextEvent` with how many blocks
were lost past recovery (`textOf` reads one off any event), and
`media.hasText` says whether it was agreed -- `NOT_NEGOTIATED` from
`sendText` otherwise. It is not offered on a call keyed by SRTP or
gathering ICE, where it would travel in the clear.

`feedback = true` offers RTP/AVPF with Generic NACKs and reduced-size RTCP
(RFC 4585, RFC 5506); a far end that knows only RTP/AVP refuses the
profile, so it is off by default. An offer that asks is answered on the
profile whatever this end says, and `answerCall(event, feedback = true)`
adds the NACKs and reduced size. `media.rtcpFeedback()` says what was
agreed, and `statistics()` counts the NACKs, the early and reduced-size
packets.

`codecs` on `placeCall` and `answerCall` orders one call's codecs:
`"L16/16000"` or `"L16/8000"` offers linear audio, which no default offer
carries.

### Conferences and presence

```kotlin
account.watchPresence("sip:bob@example.com")
account.publishPresence(SipralPublishedPresence(SipralBasic.OPEN, SipralActivity.ON_THE_PHONE, "In a call"))
val watched = call.subscribeConference()   // a call whose far end is a focus
client.events.collect { event ->
    presenceOf(event)?.let { println("${it.entity} ${SipralBasic.of(it.basic.toInt())} ${it.note}") }
    conferenceOf(event)?.let { watched.conference()?.let { room -> println(room.members.map { m -> m.entity }) } }
}
```

`account.subscribe(target, package)` is any RFC 6665 subscription, kept and
refreshed by the client until `SipralSubscription.end()`;
`watchPresence(target)` is one to `presence`, told as
`SIPRAL_EVENT_KIND_PRESENCE_CHANGED` and read with `presenceOf`, `kind`
`WATCHED`. `publishPresence` publishes the account's own (RFC 3903): the
first call publishes, every later one modifies, the client refreshes it,
and the same kind with `kind` `PUBLICATION` says what the compositor
granted or why it refused; `unpublishPresence()` takes it away. A call
whose far end is a conference's focus (`isfocus`, RFC 4579) names it with
`call.conferenceUri()`, and `call.subscribeConference()` watches it: each
notification is a `SIPRAL_EVENT_KIND_CONFERENCE_CHANGED` (`conferenceOf`),
and `SipralSubscription.conference()` reads the whole picture -- subject,
counts, and every member with its endpoint and status. This end says it is
a focus with `placeCall(focus = true)`, `answerCall(event, focus = true)`
or `call.setFocus(true)`.

### Recording to a recording server

```kotlin
val session = call.recordTo("sip:srs@recorder.example.com", destination = "198.51.100.20:5060")
// ...
session.stop()
```

`recordTo(server, destination, host)` records a call whose media has
started to a SIPREC recording server (RFC 7866): an INVITE with
`Require: siprec`, the metadata (RFC 7865) and a stream per party, over a
TCP connection to `destination` this client opens for it, or, with none,
where the account sends -- a client signalling over TCP or TLS, since the
INVITE is too large for UDP. Both parties' audio is copied from two sockets
of its own; the session follows the call's holds and transfers and ends
with it, and `stop()` hangs it up. The copies of an encrypted call are
offered as SRTP with SDES keys of their own (RFC 7866 §12.2), and a stream
the server will not take that way gets nothing;
`SipralAccountSecurity(recordingInClear = true)` lets that account's
encrypted calls be recorded as plain RTP instead. `ProtocolsCheck.kt`, run with
`IdiomaticCheck.kt`, proves each of these on loopback, against a
notifier, a compositor and a recording server played by the check itself.

## A local conference

`SipralLocalConference(client)` mixes any number of this client's calls,
each on its own codec and rate, so that every member hears everybody but
itself -- this end too, unless it is made with `local = false`. `add(call)`
and `remove(call)` take calls in and out (a full conference, a call already
in one, or a codec it cannot mix throw with
`SipralStatus.CONFERENCE_REFUSED`); `setMuted` and `setGain` act on one way
of a member, `null` naming this end; `memberList()` and `talkers()` say who
is in it and who is talking, loudest first; `record(path)` records the whole
mix. In device mode the library's engine carries it; in application mode its
own thread does, with `sendAudio` as this end's microphone and `frames` what
it hears. `SIPRAL_EVENT_KIND_LOCAL_CONFERENCE_CHANGED`, read with
`localConferenceOf(event)`, says who joined or left and why and who is
talking. `LocalConferenceCheck.kt` bridges two calls between three clients
on loopback.

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

On a client in device mode it opens no stream of its own: every call's
device is `EngineAudioDevice`, the engine's activation shared by all of
them -- on while any call holds it, off when the last lets go -- and the
framework's mute is the engine's; open such a client with
`SipralAudioMode.Device(SipralAudioActivation.MANUAL)`, as the sample does,
so that nothing opens before the framework's call is active. On an older
phone each call has its own `AudioRecord` and `AudioTrack`.

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
