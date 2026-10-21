<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# 15 — A stack for a device that sleeps

Everything in this document follows from one sentence, which is the platform's
rule and not ours:

> **The application must present a ringing call before the network session
> exists.**

A VoIP wake-up gives the process one run loop to raise the system call screen.
No delay, no exceptions; an application that misses the deadline stops
receiving wake-ups and is terminated. So the user is looking at a ringing call
before there is a transport, possibly before the registration has been
refreshed, and always before an INVITE has arrived. That is `C1` in
`docs/13-client-requirements.md`, and `C2` and `C3` are what an engine owes an
application that lives under it.

Up to its section on `C4`, nothing here is platform code. It is all
signalling, it is all in `sipral-ua`, and it runs on the same injected
`Instant`s as everything else — a wake-up chain that takes twenty seconds in
the field takes microseconds in a test.

## C2 — a call announced out of band

The application tells the user agent what the push told it:

```rust
match agent.announce(account, caller, now)? {
    Announced::Waiting(id) => /* the INVITE is still coming */,
    Announced::Arrived(call) => /* it beat the push; this is the call */,
}
```

and three things happen.

**The binding is refreshed at once.** RFC 8599 §4.1.3 makes it a MUST for a
woken UA, and §5.6.2 says why it is urgent: the proxy is holding the INVITE in
a bucket and will only forward it after this device's REGISTER has been
answered. The scheduled refresh is not waited for, and the back-off an earlier
outage earned is dropped — a push is proof that the path to the proxy works,
whatever happened an hour ago. A registration that has failed in a way trying
again cannot fix is left alone: repeating a refused password is how an account
gets locked out, and a wake-up does not change that.

There is a second half to the pre-warm, and it exists because of the sentence
at the top. When `announce` is called there is usually no transport yet — the
application is still opening a socket — so the REGISTER cannot be sent. It is
not lost and it is not an error: the refresh is owed, and it goes in the same
call in which the application hands over a transport. The stack cannot open a
socket itself, and being ready to write the instant one appears is the fastest
a sans-I/O core can be.

`UserAgent::refresh_binding` is the same thing without a call attached, for the
periodic wake-up a proxy sends to keep a suspended device's binding alive
(§5.5).

**The INVITE is matched to the announcement.** When it arrives, the application
is told which screen it belongs to before it is told there is a call at all:

```
UaEvent::CallAnnounced { call, announcement }   <- queued first
UaEvent::IncomingCall  { call, account, request }
```

The pair is always queued together and in that order, so an application walking
the queue never sees a call it has to guess about. `CallAnnounced` is a
separate event rather than a field on `IncomingCall` because a variant that
grows a field breaks every pattern that names its fields — here, and in the C
ABI and the bindings generated from it, where `B7` makes "adding a function
cannot leave a platform behind" a requirement rather than a preference.

**An announced call that never arrives is reported.** `AnnouncedCallMissing`,
with the announcement and how long it was waited for. It is not an error. A
wake-up chain has a notification service, a proxy, a bucket timer and a radio
in it, and this is the only place that says which end gave up: the push was
delivered, this device woke, it refreshed its binding, and no INVITE followed.
RFC 8599 §5.6.2 lists several ways for that to be the proxy's doing — the
caller hung up, the push request failed, the bucket timer ran out — and none of
them reaches this device as a SIP message. Tuning a wake-up chain without this
event means reading two sets of logs that nobody has.

### The matching rule

**Same account, and the same user and host in the `From` URI. Time is only a
tie-break.**

A push carries no SIP identifier and cannot be made to. RFC 8599 §13 says the
mechanism "does not require a proxy to insert any payload", and §5.6.2 has the
proxy hold the request rather than describe it. There is no `Call-ID` to match
on, and there never will be. What a push does carry is who is calling and which
account, so that is what is compared.

Nothing else about the URI is compared, and that is the deliberate part. RFC
3261 §19.1.4 equivalence insists that a parameter present in one URI be present
in the other, which a proxy breaks on the way through by adding `;user=phone`
or a transport; requiring it would fail to match almost every real call. That
sounds like the safe direction and is not, because the failure it produces is a
*second* call screen for the call the user is already looking at. The user part
is compared unescaped and case-sensitively, the host without regard to case,
exactly as §19.1.4 requires of those two fields. A URI of any other scheme —
`tel:` — falls back to whole-URI equivalence, because there is no user and host
to take apart.

**When two announcements are indistinguishable**, which means the same caller
on the same account, the oldest is taken first. Not because it is more likely
to be right: when nothing distinguishes them there is no wrong answer about who
is calling, and the pushes and the INVITEs are both in the order the proxy made
them. Time is *only* the tie-break — two announcements naming different callers
are told apart by who is calling, whichever was announced first. Matching
first-come would show the user the wrong name whenever two calls overlap, and a
wrong match is the one failure this design will not accept.

An announcement is used once and then gone, and it lives for twenty seconds by
default (`UserAgent::expect_within` changes it in Rust; through `sipral.h`
and the bindings it is fixed at twenty seconds). Twenty is made of two
numbers: the far
end's own INVITE transaction gives up after 64·T1, thirty-two seconds, so a
longer window would be waiting for a caller who has already hung up; and a cold
start that has to resolve a name, build a connection, answer a challenge and
retransmit a REGISTER on a radio that was idle fits inside twenty comfortably.

### The three races

They are part of the requirement rather than exceptions to it, and each has a
test.

**The caller hung up before the device woke.** The announcement is fulfilled by
nothing. At the end of the window it becomes `AnnouncedCallMissing`, and a
later INVITE from the same caller is a new call that inherits nothing — the
dead screen is not handed to it. The window is checked where the match is made
as well as where the sweep runs, because a datagram can arrive before the
timeout the stack asked for.

**Two calls in quick succession.** Two announcements outstanding, and each
INVITE takes the one that names its caller rather than the one that came first:
Carol's INVITE takes Carol's announcement even when Bob's is older.

**The INVITE arrived before the push.** `announce` answers
`Announced::Arrived(call)` with the call that is already ringing, and records
nothing. The screen the application has just raised belongs to that handle; no
second call is invented. When the `IncomingCall` event has not been read yet, a
`CallAnnounced` is slipped in front of it so the ordered stream is complete
too. A push naming somebody *other* than the caller who is already ringing does
not take that call: it becomes an ordinary announcement and expires
harmlessly.

`forget_announcement` drops one that the user dismissed before the INVITE came.

### Through `sipral.h`

`sipral_account_announce` is `announce`: it fills `out_call` when the INVITE
came first and `out_announcement` otherwise. `sipral_account_refresh_binding`
is `refresh_binding`, and `sipral_announcement_forget` is
`forget_announcement`. The events are `SIPRAL_EVENT_KIND_CALL_ANNOUNCED` (31),
then `SIPRAL_EVENT_KIND_INCOMING_CALL`; a miss is
`SIPRAL_EVENT_KIND_ANNOUNCED_CALL_MISSING` (20). The push parameters are
`push_provider`, `push_prid`, `push_param` and `push_wakes_itself` on
`sipral_account_config_t`, and `sipral_account_push_echo` reads the
registrar's answer. On iOS, `CallKitBridge` and `PushKitBridge` run this
sequence (or `LiveCommunicationBridge`, below, in CallKit's place); on Android, `org.sipral.telecom.TelecomBridge` does.

In the Swift package the push parameters are `SipralStack.addAccount(push:)`
with a `SipralPush` (`SipralPush.apnsVoip(token:teamId:bundleId:)` writes
the token in hex and the topic as `TEAMID.bundle.voip`, RFC 8599 §10), and
`Account.pushEcho()` reads the answer. `PushKitAdapter` reports a call to
CallKit for every VoIP push, which iOS requires of an application that wants
to keep receiving them: one that names no caller, or arrives before there is
an account, is shown and ended at once. A shown call that no INVITE fills is
ended too, as failed when the announcement was refused and as unanswered
when `ANNOUNCED_CALL_MISSING` arrives, rather than left ringing. The push's
payload carries the caller under `caller`; that, and what sends the push, is
the push gateway's side (below).

## C3 — a registration that freezes and thaws

### The snapshot

`freeze_registration` writes an account's registration down;
`thaw_registration` reads it back into an account that has been added and has
not registered. One layout, version 1, every number big-endian:

| bytes | what |
|---|---|
| 4 | `SPRG` |
| 2 | version |
| 4 | the sequence number the next REGISTER continues from |
| 4 | seconds the registrar granted |
| 4 | seconds the binding still had when this was written |
| 2 + n | the `Call-ID`, and its length |
| 2 + m | the address of record, and its length |

It is parsed and written by hand, with no dependency and no schema language,
because the compatibility rule is the whole reason there is a version and it
has to be enforceable in twenty lines somebody can read in one sitting.

**The version rule: a reader takes every layout it was built to understand and
refuses every other one.** A snapshot from a newer build is an error —
`SnapshotError::FromTheFuture` — and never a misreading. Fields that moved
would still parse, into the wrong meanings, and a sequence number read out of a
length field produces REGISTERs a registrar answers 400 to for as long as the
file exists. Adding a field means version 2, never a longer version 1. Trailing
bytes are refused for the same reason: a document that is longer than it says
it is, is not the document it says it is. A snapshot whose address of record is
not this account's is refused too, and the account is left exactly as it was.
So is one offered to an account that never registers
(`SnapshotError::NotRegistering`): there is no binding for it to continue, and
restoring one would book a refresh that can never be sent.

**How long the snapshot sat unused is the application's to say.** This crate
never reads a clock, and a monotonic `Instant` does not survive the process
that minted it — so `thaw_registration` takes an `asleep: Duration`. The
application has the wall clock and knows whether this is a wake from suspend or
a launch a week later.

### What a restored binding may and may not be trusted for

**May:** that the next REGISTER can continue the same `Call-ID` and sequence
number, so a registrar reads it as a refresh of the binding it is already
holding rather than as a second registration for the same device. That is the
whole saving, and it is on the wire, not in the state. And a schedule: the
refresh is booked for where it would have fallen, or for now when the binding
has already lapsed.

**May not:** anything about reachability. Not that the registrar still holds
the binding, not that the address in the `Contact` is still this device's, not
that the registrar's name still resolves. The account comes back as
`RegistrationState::Restored` and never `Registered`, and it reaches
`Registered` only when a registrar has answered. `B3` records the failure this
distinction exists to make un-representable: a machine that had lost name
resolution while asleep, with a cached registration that still read as valid,
so that no amount of "are we registered?" checking could have prevented what
followed. A state that means "there is a binding on paper and nothing has
confirmed it" is the smallest honest thing to put in its place.

`binding_expires_in` reports what is believed to be left, and is believed no
more strongly than that.

### Through `sipral.h`

`sipral_account_freeze(stack, account, buffer, capacity, out_len, now_ms)` and
`sipral_account_thaw(stack, account, snapshot, snapshot_len, asleep_ms, now_ms)`
are the same two calls from C. Freeze writes `out_len` whether or not there was
room, so a null buffer with a capacity of zero asks how much to bring and gets
`SIPRAL_STATUS_BUFFER_TOO_SMALL` with the answer — a question, not a failure —
and nothing is written to a buffer too short. An account with nothing worth
keeping is `SIPRAL_STATUS_WRONG_STATE` rather than zero bytes, which a caller
could not tell from the question. The clock is read and not moved: a snapshot
taken on the way into suspend writes nothing and sends nothing, so it cannot be
what makes a later `now_ms` unacceptable.

**The bytes are opaque across this boundary, and the table above is not part of
the C ABI.** It is published here because this document is the specification of
the format for whoever maintains it, not so that an application can parse one:
the version rule only stays enforceable while the library is the only reader.

The three ways thaw refuses map onto three statuses, which is what lets a
caller tell them apart without reading the sentence:
`SIPRAL_STATUS_UNSUPPORTED_VERSION` for bytes a newer build wrote — the same
answer a struct that is too short gets, and for the same reason —
`SIPRAL_STATUS_NOT_SUPPORTED` for an account that does not register at all, and
`SIPRAL_STATUS_INVALID_ARGUMENT` for bytes that are not a snapshot, are damaged,
or are another account's. The account is left exactly as it was in every one of
them.

### Time-to-ready from cold

`cold_start(now)` says when the process was launched or woken;
`time_to_ready(account)` answers with how long that account took to become
reachable. Measured from the same injected instants as everything else,
`None` until an account has registered, and `None` always for one that never
registers.

The application has to declare the cold start, and the reason is the same one
that makes this stack testable: the launch happened before any of this existed,
and reading a clock to find out when is the one thing the protocol crates may
not do. A refresh an hour later does not overwrite the number — an hourly
refresh is not a cold start.

From C the two are `sipral_stack_cold_start(stack, now_ms)` and
`sipral_account_time_to_ready(stack, account, out_has_value, out_ms)`. They
ship together because either alone is useless: without a declared cold start
there is nothing to measure from, so the reader could only ever answer
"nothing". `out_has_value` is how a caller tells "no answer yet" from an answer
of zero milliseconds, which is a real and different thing.

It is a product number rather than a curiosity. How long a queue rings each
agent before skipping to the next has to be longer than this, or a phone that
was asleep is skipped every time and its owner is told the queue was quiet.

### C3 in the Swift package

The calls are on the objects they act on: `SipralStack.suspending()`,
`resumed()`, `coldStart()`, `interfaceLost()` and `nameResolutionLost()`;
`Account.freeze()`, `thaw(_:asleepMs:)` and `timeToReadyMs()`, `nil`
until there is an answer. `SipralAppLifecycle` is the order an iPhone
application needs them in, over a `SipralSnapshotStore` —
`KeychainSnapshotStore`, readable after the first unlock so that a push to a
locked phone can read it, never carried by a backup to another phone:

```swift
let lifecycle = SipralAppLifecycle(store: KeychainSnapshotStore())
// at launch, a push's included, before didFinishLaunching returns
let stack = try SipralStack(...)
try lifecycle.launched(stack)                 // the cold start, zero of time-to-ready
let account = try stack.addAccount(..., push: push)
if !lifecycle.restore(account, key: "main") { // .restored, or nothing usable
    try account.register()
}
// scene to background / back
lifecycle.enteredBackground()                 // freeze into the Keychain, then suspending
lifecycle.enteredForeground()                 // resumed
```

On the way into the background each kept account is written down
**before** the stack is told it is suspending, as `SipralAppLifecycle` does
for .NET MAUI and for the same reason: once told, a binding no longer counts
as bound and there is nothing to write. With a call up nothing is done: iOS
keeps a process with a call running, and a suspended stack would stop
refreshing the registration under it. The record kept is eight bytes of
Unix milliseconds and the opaque snapshot; how long it slept is the wall
clock's difference, since a monotonic clock does not survive the process. A
snapshot the stack refuses — another account's, a newer build's — is removed
so it is not tried again, and `restore` answers `false`.

In a process a push started, the account comes back `.restored` and its
next REGISTER continues the same `Call-ID` and sequence: the push's own
refresh (`PushKitBridge.handle`, RFC 8599 §4.1.3) is that REGISTER, and the
registrar reads it as the binding it is already holding rather than a
second registration of the same phone. `LifecycleTests` runs the whole of
it on macOS against a registrar on loopback: written down on the way into
the background, the first stack closed without unregistering, a new stack
whose account comes up `.restored` 90 seconds of wall clock later, and the
refresh confirming it with the first process's `Call-ID`, with a
time-to-ready. `KeychainSnapshotStore` itself ran in the iPhone sample on
the simulator, across a process that was ended (below).

### RFC 8599 push parameters

`Account::push(Push::new(provider, prid).param(…))` puts `pn-provider`,
`pn-param` and `pn-prid` on the `Contact` **URI** of every REGISTER — inside
the angle brackets, before any URI headers, which is where §19.1.1 puts URI
parameters and where §4.1.1 asks for these. `+sip.instance` stays outside the
brackets, where a header parameter belongs. Values that are not `pvalue` are
percent-escaped, as §8.7 requires: a base64 identifier carries `=`, and an
RFC 8030 identifier is a whole URL.

Two rules about where they must *not* go, and both are enforced rather than
documented:

- **Never on anything but a REGISTER.** §4.1: a UA "MUST NOT insert the SIP URI
  parameters ... in non-REGISTER requests in order to prevent the PNS
  information associated with the UA from reaching the remote peer". A
  `pn-prid` that leaks into an INVITE or a 200 hands the far end a token that
  wakes this device whenever it likes. The `Contact` a dialog uses and the
  `Contact` a REGISTER uses are two different renderings for exactly this
  reason.
- **Not on a de-registration.** §4.1.2: a REGISTER that removes the binding
  "MUST NOT insert the 'pn-prid' SIP URI parameter", and its absence is how the
  network is told to stop sending notifications for it. The provider and the
  parameter still go, so the network knows which subscription is being ended.

`+sip.pnsreg` (§4.1.4) is sent when the application says the device can wake
itself to refresh — `Push::wakes_itself`. It is the application's fact and not
ours to guess: a process the operating system has suspended has no timer that
runs, and one that claims otherwise gets a registrar that stops sending the
wake-ups it is relying on.

**What the registrar says back** is `UserAgent::push_echo`, read from
`Feature-Caps` in the 2xx:

- `+sip.pns` naming the same service we asked for means another proxy will
  request notifications. Anything else — a different service, no indicator at
  all — means §4.1.1's "MUST NOT assume", and `accepted()` says `false`. The
  RFC leaves what to do then out of scope, and so does this stack: it reports
  it, because an application that lets itself be suspended believing it will be
  woken, when nobody said so, is an application that stops ringing.
- `+sip.pnsreg` with a value is the network demanding to see a refresh at least
  that many seconds before the binding lapses (§4.1.4, a MUST). Our own
  thirty-second margin becomes a floor and the larger of the two wins, so the
  refresh moves earlier to meet it. A lead longer than the binding is a network
  contradicting itself, and the halfway floor answers it.

One thing §4.1.4 allows is deliberately **not** done: a UA that advertised
`+sip.pnsreg` and got no indicator back "SHOULD only send a binding-refresh
REGISTER request when it receives a push notification". Stopping the refresh
timer would trade reachability for battery on the strength of a SHOULD, and
nothing in this crate can tell whether the wake-ups are actually arriving. The
timer keeps running; an application that knows better takes the account down.

### Who sends the push

Not this stack, and not the application on the device. RFC 8599 gives the push
request to a SIP proxy on the path to the device (§1, §5.6.2): it keeps the
`pn-*` parameters from the REGISTER, and when an INVITE or a MESSAGE arrives for
that binding it asks the notification service to wake the device, holds the
request in its "SIP Request Push Bucket" (§5.2), and forwards it once the
woken device's refresh REGISTER has been accepted. How it talks to APNs or FCM,
and the credentials it needs to, belong to the notification service and are
outside the RFC (§5.1).

So a deployment that wants a sleeping device to ring needs, on the server side,
one of two things:

- **a proxy or PBX that implements the proxy half of RFC 8599** and holds the
  push credentials for the application — for APNs, a key or certificate tied to
  the team and topic that `pn-param` names; for FCM, the project's server
  credentials; or
- **a push gateway in front of a PBX that does not**: a proxy that plays that
  role and passes everything else through.

This stack ships neither, and the credentials never belong on the device.
Whether the registrar a device talks to is one of the two is exactly what
`push_echo` reports: `+sip.pns` naming the service asked for is the network
saying it will send the pushes, and anything else means nobody has.

## Android, run on an emulator

The Compose sample (`bindings/kotlin/android/sample`) and the
`ConnectionService` helper under it have been run, not only built: the APK
`scripts/package/android.sh` produces (without Opus, debug-signed,
20,193,618 bytes, natives for arm64-v8a, armeabi-v7a and x86_64) on an
Android 16 (API 36, `google_apis`, arm64-v8a) emulator on an Apple-silicon
Mac, headless, against a Sipral agent on the same Mac. What was seen, from
both ends:

| | |
|---|---|
| Cold start to first frame (`am start -W`, `TotalTime`) | 1.40 to 1.66 s, and up to 2.05 s on the first launch after an install |
| Native load | `libsipral_jni.so` from `lib/arm64-v8a`, with `libsipral_ffi.so` as its `NEEDED`, loaded when the stack is first opened: within 40 ms of the tap on Register |
| Call setup | INVITE to 200 OK 26 to 111 ms on the wire, ACK 7 to 24 ms after it; the tap on Call to the framework's `SET_ACTIVE` 240 to 650 ms |
| Media | G.722 both ways; a 60-second call carried 2,756 packets from the phone and 2,121 back, the difference being the 12 seconds the phone held the call; the agent counted 2,121 sent and 2,762 received; one digit from the keypad crossed as 7 RFC 4733 packets |
| Telecom | `CONNECTING`, `DIALING`, `ACTIVE`, `ON_HOLD`, `ACTIVE`, then `DISCONNECTED` with cause `LOCAL` for the phone's own hang-up (BYE from the phone, 200 OK back) and `REMOTE` for the agent's, and `DESTROYED`; the only route the emulator offers is Speaker |
| Audio | a voice-communication capture from the built-in microphone and a voice-communication playback track, both at 16 kHz, in `dumpsys media.audio_flinger`; with `-no-audio` the microphone reads silence (-89 dB) |
| A simulated push | `RINGING` through the framework with no INVITE, and the incoming-call notification (category `call`, importance high, a full-screen intent); declined, `DISCONNECTED` with `REJECTED`; left alone, `MISSED` 20 seconds later, when the announcement's window ran out |

The sample shows no audio levels. The full-screen intent: from Android 14,
`USE_FULL_SCREEN_INTENT` is not simply granted by the manifest, and the
sideloaded sample was refused it (`adb shell appops get org.sipral.sample
USE_FULL_SCREEN_INTENT`), so the call showed as a heads-up notification
rather than a screen over the lock screen; the user can allow it in the
application's settings.

Running it again, from a checkout, with the APK built on a machine with
Docker (`scripts/package/android.sh --out out --accept-android-sdk-licenses`)
and copied to the Mac:

```sh
export ANDROID_HOME=~/Library/Android/sdk JAVA_HOME=/opt/homebrew/opt/openjdk
echo no | "$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager" create avd -n sipral \
    -k "system-images;android-36;google_apis;arm64-v8a"
"$ANDROID_HOME/emulator/emulator" -avd sipral -no-window -no-audio -no-snapshot \
    -no-boot-anim -gpu swiftshader_indirect -tcpdump emulator.pcap &
adb wait-for-device
adb install out/sipral-sample.apk
adb shell pm grant org.sipral.sample android.permission.RECORD_AUDIO
adb shell pm grant org.sipral.sample android.permission.POST_NOTIFICATIONS
adb shell am start -W -n org.sipral.sample/.MainActivity
```

The far end is `bindings/kotlin/examples/Agent.kt` on the Mac's JVM, built
as `bindings/kotlin/README.md` says, with no registrar, and bound to the
Mac's LAN address rather than to loopback: its answer advertises the address
it is bound to, and 127.0.0.1 inside the emulator is the emulator's own.
`SIPRAL_REGISTRAR_ADDRESS` only picks that address:

```sh
SIPRAL_AOR=sip:agent@192.0.2.20 SIPRAL_REGISTRAR_ADDRESS=192.0.2.20:5060 \
    java -Djava.library.path=<shim dir> -cp <classes>:<coroutines jar>:<kotlin-stdlib.jar> \
    org.sipral.examples.AgentKt
```

It prints `listening on 192.0.2.20:<port>`. In the sample, the address of
record is any SIP URI, the registrar address is that `192.0.2.20:<port>`,
the registrar URI stays empty, Register, then call
`sip:agent@192.0.2.20:<port>`. The emulator's NAT carries the call out, and
symmetric RTP on the agent carries the media back. The agent hangs up a call
a minute after answering it, so hang up from the sample before then to see
the phone's own BYE. `adb shell dumpsys telecom` shows the framework's side,
and `emulator.pcap` the wire — but only the wire of `eth0`. An AVD created
as above has `wlan0` (10.0.2.16) as well as `eth0` (10.0.2.15), the sample
binds `wlan0`'s address, and `-tcpdump` records only `eth0`: a run against
the lab below left the sample's own traffic out of the capture entirely, and
the far end's view is what showed it.

**Through the lab's Asterisk.** The same APK registered with the lab's
Asterisk on another machine, reached from the Mac over a VPN, and called
through it both ways. `scripts/lab.sh wasapi up` on the lab machine
publishes Asterisk on its LAN address, SIP on 5062 and RTP on 10000 to
10020. In the sample: address of record `sip:labuser-mobile@192.0.2.30`,
registrar address `192.0.2.30:5062`, registrar URI `sip:192.0.2.30:5062`,
auth user `labuser-mobile`, password `labpass`, Register; then call
`sip:9008@192.0.2.30:5062`, the lab's echo. For the other direction, on the
lab machine:

```sh
docker exec sipral-interop-asterisk-1 asterisk -rx \
    'channel originate PJSIP/labuser-mobile extension 9008@lab'
```

and the sample rings; Answer, and Hang up. `labuser-mobile`
(`interop/asterisk/pjsip.conf`) is the account for a phone behind a NAT: the
emulator is behind its own, and in this run the path to the lab added a
second, so Asterisk saw the phone at the VPN concentrator's public address
while the phone's `Contact` and `c=` named 10.0.2.16. What was seen:

| | |
|---|---|
| Register | REGISTER, 401, REGISTER with credentials, 200 OK: 106 ms at Asterisk from the first REGISTER to the 200, timed on the run with `labuser` below, and inside one second on `labuser-mobile`; the binding `labuser-mobile` keeps is the NAT's public address and port, not the `Contact` |
| Outgoing, to 9008 | INVITE, 401, INVITE, 200 OK, ACK, all in the same second at Asterisk; the tap on Call to the framework's `SET_ACTIVE` 700 ms |
| Outgoing media | G.711 µ-law both ways; Asterisk counted 2,114 packets in and 2,114 out 48 seconds into the call, one of the phone's lost on the way in and 38 of its own reported lost by the phone's RTCP; hung up from the sample, BYE and 200 OK, `DISCONNECTED` with cause `LOCAL` |
| Incoming, from `channel originate` | INVITE to the NAT's public address and port, `SET_RINGING` in the sample and the incoming-call notification; the tap on Answer to `SET_ACTIVE` 200 ms, 200 OK and ACK |
| Incoming media | Asterisk counted 1,449 packets each way over the 48 seconds from the originate, 17 of them ringing; hung up from the sample, BYE and 200 OK, `DISCONNECTED` with `LOCAL` |

The sample does not show its own packet counts, and with the capture
missing `wlan0` the phone's side of the media is Asterisk's count of what
arrived from it, and the echo it sent back.

The same phone on `labuser`, an account with Asterisk's defaults, shows why
the other one exists. The REGISTER succeeds and Asterisk keeps
`sip:labuser@10.0.2.16:<port>` as the binding; a call placed to it sends the
INVITE to 10.0.2.16 and nothing rings; a call from it connects, and
Asterisk sends its audio to the `c=` address 10.0.2.16, so the phone hears
nothing while Asterisk hears the phone. `rewrite_contact` and
`rtp_symmetric` on `labuser-mobile` are the settings a registrar facing
phones behind NATs is configured with (`docs/06-nat.md`, "The order that
matters"); STUN (`SIPRAL_NAT_STUN`) is the answer for one that is not. The
sample's account screen takes a STUN server (and a TURN server, with ICE
offered when one is given), passed to `SipralClient.open`.

With a STUN server the same account works both ways, which a run on 27
September 2026 showed on an `android-36` arm64 AVD started without
`-no-audio`: `labuser`, the lab machine's own address as registrar
(`192.0.2.30:5062`), and as STUN server a coturn answering Binding requests
only, on the lab machine's own network at port 3479. The Binding request and
every REGISTER after it reached the lab machine from one public address and
port, the VPN concentrator's, and `pjsip show contacts` read
`labuser/sip:labuser@<concentrator>:<port>`. `channel originate` to
`PJSIP/labuser` into 9008 rang the sample; answered, the 200 OK Asterisk
received named that address in its `Contact` as well as in `c=`, the ACK
went there, and Asterisk counted 2,555 packets each way 69 seconds in, none
lost, until the sample's own BYE. The call the other way, to 9008, counted
1,694 each way at 36 seconds, none lost. The same incoming call with the
emulator started with `-no-audio` counted 883 each way at 23 seconds: the
microphone reads silence then, and silence is sent like any other frame.

An earlier attempt had reported that call answered with the private address
in the 200 OK's `Contact` and no audio either way. That did not happen
again: not in any of the four incoming calls answered in this run, each
200 OK read at Asterisk, and not in the lab, where the C harness and, in a
run of its own, the Kotlin example agent, each behind `interop/nat` with a
STUN server, answered calls from Asterisk with the public `Contact`, were
acknowledged and heard the echo (`scripts/lab.sh nat` now runs the C half
of that on every run). What the attempts had in common was the lab itself:
`scripts/lab.sh wasapi up` published Asterisk's internal 5060 as 5062. A
request Asterisk starts itself leaves the lab machine from 5062 only while
the machine's own connection tracking still holds the flow the phone's
REGISTER opened, two minutes after its last packet; after that the INVITE
left from 5060, and the concentrator, which lets in only what comes from the
address and port the phone sent to, dropped it. Captured on the lab machine
with the old override: the INVITE from `192.0.2.30:5060`, retransmitted and
never answered, and the phone never rang. The override now moves Asterisk's
own socket to 5062 and publishes it one to one, and the same call rings
whenever it is placed.

Whenever, within limits: nothing but the phone's own traffic keeps the
concentrator's way in open. A call two and a half minutes after the REGISTER
rang and carried 794 packets each way; one five and a half minutes after it
left the lab machine from 5062, to the right address, and nothing answered.
The STUN refresh every 25 seconds keeps the mapping, but it goes to the STUN
server, and a NAT that filters by address and port opens nothing towards the
registrar for it (`docs/06-nat.md`, "Refresh"); the registration refreshes
once an hour. A phone that has to be reachable while idle is woken by a push
(`SipralPush`, RFC 8599), which makes it register again, or registers more
often than its NAT forgets.
`NatTests.swift` and `NatCheck.kt` show the `Contact` and `c=` on the wire
under a controlled test; this is the same address, written the same way,
under a live registrar.

## The Swift package on iOS

`scripts/package/xcframework.sh --out DIR` builds `DIR/CSipral.xcframework`
— macOS (arm64 and x86_64), iOS device (arm64) and iOS Simulator (arm64 and
x86_64) — and prints `DIR/spm/Package.swift` over it: the whole `Sipral`
module from `bindings/swift/Sources/Sipral`, CallKit and PushKit bridges
included, on a `binaryTarget` instead of the source target, with the
package's test suite beside it. Every slice is built for iOS 15.0 and macOS
12.0 and later, the two minimums `scripts/package/apple.sh` sets once and
the printed `platforms:` line repeats, and the script reads every object in
each archive — libopus's too, in the `--with-opus` variant, which cmake would
otherwise build for the Mac's own SDK — and fails on one built for a newer
release. What an application adds is the repository's root
`Package.swift`, the same module over the zip of that XCFramework a release
carries as an asset, by URL and checksum (`scripts/package/xcframework.sh
--release`, `docs/11-testing.md`, "Releasing"). `bindings/Package.swift` itself stays the
macOS and Linux package the gate and the lab build: its tests link the
library `cargo` leaves in `target/release`, which is a macOS or Linux
library and nothing an iOS target can link. So the suite runs on iOS
against the artefact an application would ship with:

```bash
scripts/package/xcframework.sh --out /tmp/sipral-xcf --dry-run
UDID=$(xcrun simctl create sipral-test "iPhone 17" com.apple.CoreSimulator.SimRuntime.iOS-26-5)
cd /tmp/sipral-xcf/spm
xcodebuild test -scheme Sipral -destination "platform=iOS Simulator,id=$UDID"
xcrun simctl delete "$UDID"
```

The same directory answers `swift test` for the macOS slice.

**A call from the simulator to a peer on the Mac.** The simulator shares
the Mac's network stack, so a peer listening on the Mac's loopback is
reachable from it with no registrar in between. `SipralLabAgent` is that
peer: built by `swift build` in `bindings/`, run with no registrar, it
answers, echoes every frame, hangs up on `#`, and prints what it saw.
`HostPeerCallTests` places the call when `SIPRAL_PEER` names the agent, and
is skipped, saying why, when it does not; `xcodebuild` passes a test process
every `TEST_RUNNER_<NAME>` variable as `<NAME>`:

```bash
cd bindings && swift build
SIPRAL_REGISTRAR_ADDRESS=127.0.0.1:5060 .build/debug/SipralLabAgent &   # prints "listening on 127.0.0.1:<port>"
cd /tmp/sipral-xcf/spm
TEST_RUNNER_SIPRAL_PEER=127.0.0.1:<port> xcodebuild test -scheme Sipral \
    -destination "platform=iOS Simulator,id=$UDID"
```

**Through the lab's Asterisk.** The same test registers first when
`SIPRAL_REGISTRAR` names a registrar URI, with `SIPRAL_AOR`,
`SIPRAL_AUTH_USER` and `SIPRAL_AUTH_PASSWORD`, and calls `SIPRAL_TARGET`
instead of the agent, hanging up itself once the echo is heard.
`testCallFromThePeerThroughTheRegistrar` is the other direction: with
`SIPRAL_WAIT_INCOMING_SECONDS` as well, it registers, waits that long for a
call, answers it, and hangs it up once its audio has come back. Both are
skipped, saying which variable is missing, without them. Against the lab
brought up with `scripts/lab.sh wasapi up` at 192.0.2.30, from a Mac whose
address on the way there is 192.0.2.41:

```bash
export TEST_RUNNER_SIPRAL_PEER=192.0.2.30:5062 TEST_RUNNER_SIPRAL_LOCAL_HOST=192.0.2.41 \
    TEST_RUNNER_SIPRAL_REGISTRAR=sip:192.0.2.30:5062 \
    TEST_RUNNER_SIPRAL_AOR=sip:labuser-mobile@192.0.2.30 \
    TEST_RUNNER_SIPRAL_AUTH_USER=labuser-mobile TEST_RUNNER_SIPRAL_AUTH_PASSWORD=labpass \
    TEST_RUNNER_SIPRAL_TARGET=sip:9008@192.0.2.30:5062 TEST_RUNNER_SIPRAL_WAIT_INCOMING_SECONDS=60
xcodebuild test -scheme Sipral -destination "platform=iOS Simulator,id=$UDID" \
    -only-testing:SipralTests/HostPeerCallTests/testCallToThePeerNamedBySipralPeer
xcodebuild test -scheme Sipral -destination "platform=iOS Simulator,id=$UDID" \
    -only-testing:SipralTests/HostPeerCallTests/testCallFromThePeerThroughTheRegistrar &
# once it prints "waiting", on the lab machine:
docker exec sipral-interop-asterisk-1 asterisk -rx \
    'channel originate PJSIP/labuser-mobile extension 9008@lab'
```

What that showed, with the simulator on the Mac's VPN address and Asterisk
seeing it at the VPN concentrator's public one:

| | Outgoing, to 9008 | Incoming, from `channel originate` |
|---|---|---|
| Register, REGISTER to the 200 after the challenge | 142 ms | 139 ms |
| Call set up | confirmed 98 ms after the INVITE, the 401 and the second INVITE included | confirmed 119 ms after the INVITE arrived |
| Media, simulator's count when it read its statistics | 39 sent, 33 received, 25 frames of its tone heard back | 38 sent, 31 received, 25 frames heard back |
| Media, Asterisk's count (`rtp set debug on`) | 34 in and 33 out on an earlier run of the same call | 35 in, 34 out |
| Ended | BYE from the simulator, 200 OK, no channel left | BYE from the simulator, 200 OK, no channel left |

The first runs of both ended with no BYE reaching Asterisk and its channel
left up: its 200 OK names `sip:<lab>:5060`, the port inside its container,
while it is reached on the mapped 5062, and the Swift package answered
`SIPRAL_EVENT_KIND_RESOLVE_NEEDED` with that `Contact` as a literal address,
which moved the dialog off the path its INVITE took. The ACK had already
gone the right way, the BYE went to 5060, and nothing answered there. The
package now leaves the event unanswered (`DialogFlowTests` is the case, with
a server whose `Contact` names a second socket), and so do the Python and
.NET packages, which did the same. The lab no longer names the port inside
its container either: `wasapi up` binds Asterisk to 5062 and publishes it
one to one, for the reason the Android section above gives. On the account with Asterisk's defaults,
`labuser`, the simulator's call works as well: the Mac's VPN address is
routable from the lab, so the `c=` Asterisk sends to reaches it, where the
emulator's does not.

**What ran, on the iOS 26.5 simulator (iPhone 17, arm64) under Xcode 26.6.**
With `SIPRAL_PEER` naming `SipralLabAgent` on the Mac, thirty-one tests
ran: thirty passed — the in-process loopback calls (two readers of one call
among them), the event broadcaster's own tests, `DialogFlowTests`, the
bridges against a recording provider, `CallKitAdapter` against CallKit's
own action classes, and the call to the agent — and the one that waits for
a call through a registrar was skipped, saying why. The call to the agent
was up 119 ms after the INVITE; the simulator end counted 38 RTP packets
sent and 34 received at the moment it read its statistics, heard 25 frames
of its own tone come back, and was hung up by the agent's BYE. The agent's
own log showed it answered, the ACK arrived (the call read `confirmed`),
`#` came in, and 44 packets sent and 45 received by the time it hung up. The x86_64 simulator slice and
the device slice link the same test bundle; neither was run.

**What the simulator cannot show.** Its `callservicesd` turns away every
third-party `CXProvider` — from an application bundle as much as from a
test bundle — logging that a call source "couldn't be created", and never
calls `reportNewIncomingCall`'s completion, so `CallKitBridge.reportIncomingCall`
waits for good there. `CallKitAdapterTests` therefore hands CallKit's action
classes to the adapter's `CXProviderDelegate` methods directly: Answer answers
a call left ringing by `SipralStack.takeIncomingCall` and the caller sees the
200 OK, a second Answer fails, Hold and resume reach the caller as
re-offers, a keypad digit arrives as DTMF, and End reaches it as a BYE. The
system's own delivery of those actions, and the incoming-call screen, need a
device. PushKit fares no better: a `PKPushRegistry` asking for VoIP pushes
is ignored ("no environment could be determined") without an
`aps-environment` entitlement, which only a provisioning profile gives, and
`xcrun simctl push` delivers to an application's notification centre, not to
PushKit. The push half of `C2` is tested through `PushKitBridge` and a
`VoipPush` value, as on macOS.

**What an application has to know.** A call shown to a person before it is
answered is taken with `takeIncomingCall`, not `answerCall`, so that
CallKit's Answer is its one answer. Binding a call to `CallKitBridge` takes
nothing away from the application: `Call.events()` hands every caller a
stream of its own, and every stream gets every event, in order, so the
bridge's reader and the application's own loops over the same call each see
all of them. A reader sees what is raised from the moment it takes its
stream, not before, so the application takes it before the action it wants
to see the outcome of — `takeIncomingCall`, then `events()`, then the
answer. The one thing handed to a late reader is the end: every stream
finishes right after the call's `CALL_ENDED`, and one taken after that gets
that event and finishes, which is how a call the caller gave up on before
it was bound is still reported ended to CallKit instead of left ringing.
`Call.dtmf()` and `Media.frames()` work the same way; a reader that falls
behind drops its own oldest items (past 4096 events or digits, and past 50
frames — one second at 20 ms — unless it asks for another number) and
never slows the others.

## C4 — the device taken away and given back

`C4` is the device taken away and given back mid-call: by an incoming
cellular call, by a Bluetooth headset connecting mid-sentence, by a car taking
over routing, by the operating system reclaiming the session. It is not a
protocol problem and has no business in `sipral-ua`; each platform delivers
the signal in a layer of its own, and that layer is where it is handled. What
the engine contributes is that none of it is fatal to the call: `Media` in
every binding keeps its own frame clock and sends silence when nothing is
queued, so a gap in the device is a gap in the sound, never in the RTP
stream, and the far end, its NAT and its RTP timeout see a call that is still
there. A hold the platform asks for is carried to the far end as a re-INVITE,
the same one the application's own hold sends.

### Android

`org.sipral.telecom.CallAudio` (in the JVM library, tested on a plain JVM by
`CallAudioCheck.kt`) keeps one call's microphone and speaker, over an
`AudioDevice`; `SipralCallAudio` (in the `ConnectionService` helper) builds
one for a call with `AndroidAudioDevice`, `AudioRecord` and `AudioTrack` as
voice-communication streams, and follows the call through the bridge and the
framework. What a self-managed `ConnectionService` is left to do, and what
each becomes:

| The platform's signal | What happens |
|---|---|
| `Connection.onHold` — a cellular call or another application's call answered over this one, a hold from a headset, a car or a watch | The connection says held at once (the framework disconnects one that has not within two seconds), the device is let go so that the other call has the microphone, and the far end is held with a re-INVITE. What the framework asked for stands until `onUnhold`, even if the far end refuses the re-INVITE |
| `Connection.onUnhold` | Active at once, a new device opened, the far end resumed |
| `ConnectionService.onConnectionServiceFocusLost` (API 28) | Every call's device is stopped before `connectionServiceFocusReleased()` tells the framework; the far end is not held, since the framework did not hold the call. `onConnectionServiceFocusGained` takes the devices back |
| `onAvailableCallEndpointsChanged`, `onCallEndpointChanged` (API 34), `onCallAudioStateChanged` before it | Reported as a route change. Nothing is reopened: the framework routes a voice-communication stream wherever the call went, and the helper never touches `AudioManager` (the framework's own guide warns against `setCommunicationDevice` and `startBluetoothSco` beside it) |
| `onMuteStateChanged` (API 34), `CallAudioState.isMuted` before it — a headset's or a car's mute | The microphone is still read, silence sent in its place |
| `ERROR_DEAD_OBJECT` from `AudioRecord.read` or `AudioTrack.write` — the audio server gone | Both streams stopped, released once neither thread is inside them, and built again at once, then after 100 ms, 250 ms, 500 ms, one second and every two seconds, for as long as the call lasts. A device that dies again within two seconds of opening is waited on a step longer each time |
| Audio focus | Not requested: the framework holds it for a live self-managed connection, which is one that "want[s] to leverage the call and audio routing capabilities of the Telecom framework" (`PhoneAccount.CAPABILITY_SELF_MANAGED`); what it leaves to the application is the call focus above |

Nothing that pauses or resumes waits on the device: stopping it is what
brings a blocked read back, it is released on a thread of its own, and it is
opened outside every lock. `onHold` and `onConnectionServiceFocusLost` arrive
on the main thread, and an audio server that has stopped answering holds a
read, or an open, for as long as it is gone.

Every change is an `AudioTransition` on `SipralCallAudio.transitions`
(`Started`, `Paused` with every reason still standing, `Resumed`,
`RouteChanged`, `MuteChanged`, `DeviceFailed` with the platform's code,
`DeviceRestored` with the number of tries, `Stopped`), and `state` says
where the audio stands. `SipralCallAudios` builds a `SipralCallAudio` for
every call the bridge shows once its media has started and closes it when
the call is gone, and carries every call's transitions and states: the
library's device mode on Android, where the C library opens no device. The
sample holds no audio code of its own; it logs each transition and shows
the state on the call's card.

**Run on the emulator, 27 September 2026.** The sample's APK
(`scripts/package/android.sh`, 20,374,994 bytes) on an `android-36`
`google_apis` arm64 AVD, registered as `labuser-mobile` with the lab's
Asterisk (`scripts/lab.sh wasapi up`) and calling its echo, 9008:

| | |
|---|---|
| The call | Active, the sample's log `audio started`, `audio route Speaker`; Asterisk's `pjsip show channelstats` 543 packets each way at 11 seconds, none lost |
| A cellular call arrives (`adb emu gsm call`) | Ringing beside ours, which stays active |
| It is answered (`KEYCODE_CALL`) | The framework holds ours: `ON_HOLD` in `dumpsys telecom`, the GSM call `ACTIVE`; the log `audio paused: held`, then `audio paused: held, call_focus_lost` as the framework moves the call focus, and `session_changed` for the re-INVITE; Asterisk's counts kept rising, the silence the media clock sends |
| The network ends it (`adb emu gsm cancel`) | Ours stays held: the framework does not resume a call on its own when the other one ends remotely, and the user resumes it from the call's screen, here the sample's Resume |
| Resumed | `ACTIVE` again, the log `audio paused: call_focus_lost` then `audio resumed` as the focus came back; Asterisk 8,156 packets each way, 8,425 six seconds later, none lost |
| The audio server killed mid-call (`kill` as root) | The platform's own `AudioTrack` and `AudioRecord` restored themselves within 0.3 s (`restoreTrack_l`, `restoreRecord_l` in logcat) and the helper saw nothing to do, as intended |
| The audio server stopped for 45 seconds (`stop audioserver`) | The platform gave up restoring after three tries, and `AudioRecord.read` answered `ERROR_DEAD_OBJECT`: the log `audio device failed (capture -6)`; the helper's open blocked, off the main thread, until `start audioserver`, then `audio device restored after 1 tries`; one track and one record for the process afterwards in `dumpsys media.audio_flinger`, the dead ones released. Asterisk counted 1,239 packets each way before, 3,280 after the 45 seconds — the silence the media clock sent while there was no device — and 3,876 twelve seconds after the restart, none lost |
| Hung up | `call_ended`, `audio stopped`, no channel left at Asterisk |

The emulator's audio policy declares one output, the speaker, so the
framework offered no other route to move to (`dumpsys media.audio_policy`),
and its telephony and Bluetooth stacks have no headset or car to connect:
switching the route between earpiece, speaker, a wired and a Bluetooth
headset, the framework's mute from a headset button, and a car taking the
call over need a phone, as does a real carrier's call.

### Device mode on Android

From Android 9 (API level 28) the library's own engine runs every call on
Android, as it does on the desktops, over AAudio (`sipral-io-aaudio`):
`SIPRAL_FEATURE_AUDIO_DEVICE` is set, `SipralAudioMode.platformDefault` is
`Device`, and the application writes no audio code. Below API level 28 the
feature bit is clear, the default is `Application`, and `SipralCallAudios`
carries each call over `AudioRecord` and `AudioTrack` as described above.
The bit is the phone's, read when asked: the same `libsipral_ffi.so` loads
on the API level 21 floor, because `libaaudio.so` is looked up with `dlsym`
rather than linked.

| What | How |
|---|---|
| The microphone | An AAudio input stream with `AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION`, the platform's own echo canceller, noise suppressor and gain control where the phone has them; on the device chosen for the microphone role, or following the call's route when none is |
| The loudspeaker | An AAudio output stream with `AAUDIO_USAGE_VOICE_COMMUNICATION`: the platform puts it on the call's route and it plays at the call volume. Both ask for `AAUDIO_PERFORMANCE_MODE_LOW_LATENCY`, shared, one channel of sixteen-bit samples, and take whatever rate and format AAudio answers with (two channels and floats are converted in the callback) |
| The ring | A stream of its own, `AAUDIO_USAGE_NOTIFICATION_RINGTONE`, which the platform plays where a ring goes, on the ringer's device when one is chosen |
| The device list | `AudioManager.getDevices`, merged so that a headset's two halves are one device: the earpiece, the loudspeaker, the built-in microphones, a wired headset or headphones, a Bluetooth headset (the call profile, not A2DP), USB, hearing aids and Bluetooth LE. Each is named by kind and address (`android:bluetooth-sco:AA:BB:…`), so a headset that reconnects keeps its engine id. The default output is the communication device; the default input is that device's microphone, or the built-in one |
| Routing | `select(SPEAKER, device)` sets the call route: `setCommunicationDevice` from API level 31, and before it `setSpeakerphoneOn` for the loudspeaker and `startBluetoothSco` with `setBluetoothScoOn` for a Bluetooth headset. Handing the role back to the system gives the route back (`clearCommunicationDevice`, both switches off) |
| Changes | The list and the route are read again every half second, and what moved is `SIPRAL_EVENT_KIND_AUDIO_DEVICES_CHANGED` with the same changes and origins as on the desktops. A route the engine set itself is not announced back as the system's for a second and a half, while the platform applies it. A stream AAudio disconnects — the device gone, the audio server restarted — is `LOST`, then `REOPENED` on the route |

AAudio lists no devices and routes nothing: both are `AudioManager`'s, a Java
API. The Kotlin binding's shim holds the application's context and a
`JavaVM` and gives the engine a table of C functions over them
(`bindings/kotlin/sipral/src/main/jni/audio_routes.c`, found by `dlsym` in
the library the JVM loaded, and not part of `sipral.h`), once the
application has called `SipralAndroidAudio.attach(context)`;
`SipralCallAudios` calls it itself. Without it — an application that drives
the C ABI from JNI of its own — the list is empty and every call follows the
platform's route, as on iOS.

Under the telecom framework the engine is opened with manual activation,
and `SipralCallAudios` drives it: every call's device is `EngineAudioDevice`,
one for all of them, which activates the engine when the first call's audio
starts and deactivates it when the last one is let go — a call held for a
cellular one lets go, the call answered beside it keeps the devices — and
the framework's mute is the engine's input mute. A self-managed call's
route is still the framework's; the engine reports it.

**Run on the emulator, 29 September 2026.** The sample's APK
(`scripts/package/android.sh`, 22,916,490 bytes) on an `android-36`
`google_apis` arm64 AVD, calling a Sipral headless agent (`headless-agent`,
cross-built for arm64-v8a) running inside the same emulator:

| | |
|---|---|
| `sipral-io-aaudio`'s own tests, cross-built and run in `adb shell` (`--include-ignored`) | 15 passed. The microphone, a call stream and a ring stream at 48, 16 and 8 kHz, each opened at the rate asked for; in one second the microphone gave 59, 48 and 43 frames, and each output took every frame it was given. Without the Kotlin shim the list is empty |
| The client opened | `audio: AAudio, devices Speaker (output), Microphone (bottom) (input)` — device mode, and the phone's list through the shim |
| The call placed | Both roles `REOPENED` as the engine activated; `dumpsys audio` showed the sample's AAudio player with `USAGE_VOICE_COMMUNICATION` on device 2 at 48 kHz, one channel, and its recording with source `VOICE_COMMUNICATION` at 48 kHz |
| Held from the sample | `held, audio paused`: the recording stopped and no player was left |
| Resumed | `audio resumed`, both roles `REOPENED`, a new recording session |
| The audio server killed mid-call (`kill`, as root) | `LOST`, then `REOPENED`; a new player and a new recording on the new audio server, and no `MEDIA_STALLED` |
| Hung up | `call_ended`, `audio stopped`, no player or recording left. The agent counted 2,871 packets sent and 2,743 received over the 57 seconds, none lost, G.722 |

The emulator's audio policy has one output, the loudspeaker, so no route
could be moved and no headset connected: the routing paths above (the
communication device from API level 31, the two switches before it, and
the notices) are tested on the build machine against a fake `AudioManager`
(`crates/sipral-io-aaudio/src/route.rs`), and need a phone to be seen
working. So do an Android 8 phone, where the telecom helper's own streams
take over, and a real Bluetooth headset.

### iOS

`CallAudio` (in the Swift package) keeps one call's device over a
`CallAudioDevice`; `VoiceProcessingAudioDevice` is one over `AVAudioEngine`
with the system's voice processing on its input node, and builds a new engine
on every open. Three things feed it:

| The platform's signal | Carried by | What happens |
|---|---|---|
| `AVAudioSession.interruptionNotification`, `.began` | `AudioSessionObserver` | The device let go (`CallAudioPause.interrupted`) |
| `.ended` with `.shouldResume` | `AudioSessionObserver` | A new device opened. Without `.shouldResume` the interruption stays one of the reasons the device is let go, as Apple asks, until the application calls `resume(.interrupted)`; either way `interruptionEnded(shouldResume:)` is reported |
| `routeChangeNotification` | `AudioSessionObserver` | Reported with the output the session is on now and why it moved (`newDeviceAvailable`, `oldDeviceUnavailable`, anything else). An engine that stops because of it (`AVAudioEngineConfigurationChange`) is started again in place, and only one that will not start is the device failing |
| `mediaServicesWereLostNotification`, then `mediaServicesWereResetNotification` | `AudioSessionObserver` | The device let go when the services go, and built again from nothing when they come back: every audio object made before a reset is dead |
| `CXProviderDelegate.provider(_:didActivate:)`, `didDeactivate` | `CallKitAdapter` to `CallKitBridge` | A call's device starts only once the system has activated the session (`CallAudioPause.sessionInactive` until then), and is let go when the system deactivates it |
| `CXSetHeldCallAction` — Hold & Accept for a cellular call, CarPlay, a headset | `CallKitBridge.handleHold` | The device let go at once, the far end held with a re-INVITE; the reverse on resume |
| `CXSetMutedCallAction` | `CallKitBridge.handleMute` | Silence sent in the microphone's place |
| `providerDidReset` | `CallKitBridge.providerDidReset` | Every call hung up and its device let go: the system's call service no longer knows them |

In device mode the library's engine runs the voice-processing unit, and
**nothing that ends a call waits for the main thread**: the stack's poll
thread never opens or tears down a device — the engine opens them on a
thread of its own and lets them go on its pump's, after the poll that ended
the call has returned — so the BYE and an un-REGISTER queued from the main
thread go out while that thread waits, as an application shutting down
does; the teardown itself, which has been seen to wait for the main thread,
finishes once it is free (`docs/08-ffi.md`, "The built-in audio engine").
`AudioDevices.deactivate()` waits for it at most the probe wait. What an
account reads while its un-REGISTER is unanswered is `.unregistered`
already; the registrar's answer is the `.registrationChanged` event.

`CallKitAdapter` also sets the session's category to `.playAndRecord` in
`.voiceChat` mode when CallKit answers, and leaves activating it to the
system; an application without CallKit builds its device with
`VoiceProcessingAudioDevice(managesSession: true)`, which does both itself.
A device that fails or will not open is opened again on the same schedule
as on Android. Every change is a `CallAudioTransition`, from
`CallAudio.transitions()`, with the last 64 kept in `history`.

**Run on the iOS 26.5 simulator.** The simulator cannot raise a real
interruption, route change or media services reset, so
`AudioSessionObserverTests` posts each notification as the system posts it —
same name, same object, same `userInfo` — and checks what reaches the call's
audio, against a device that records what was asked of it;
`CallKitAdapterTests` hands the adapter CallKit's own action classes and
`didActivate`/`didDeactivate` with the real session, and reads the category
answering set; `CallAudioTests` and `CallKitBridgeTests` run on macOS and
Linux as well. With `SIPRAL_AUDIO_DEVICE=1`, one test opens
`VoiceProcessingAudioDevice` on the simulator, which shares the Mac's
audio: frames from the microphone within the first second, and again from a
rebuilt engine after a posted media services reset. That test is also what
found that a voice-processing engine on the simulator reports a
configuration change as soon as it starts; rebuilding on it had the device
rebuilt in a loop, and it is now started again in place, with a device that
dies within two seconds of every open waited on longer each time.
`sipral-io-coreaudio`, for an application that uses it from Rust, reports
the same thing on iOS as `StreamEvent::DeviceLost` — the unit the system
stopped for an interruption, or one a reset left unable to answer — and
`Stream::recover` builds a new unit, which a test on the simulator checks
by stopping the unit behind the stream's back.

### LiveCommunicationKit

LiveCommunicationKit is Apple's newer system call service: iOS, iPadOS and
Mac Catalyst 17.4 and later (watchOS 10.4, visionOS 1.1), not plain macOS,
per Apple's documentation read on 7 October 2026. An application on iOS 17.4
or later may use it in CallKit's place; one that still supports iOS 15 or 16
keeps CallKit there. The two are alternatives, one per application, and
nothing in CallKit's path changed for it.

`LiveCommunicationBridge` runs the same rules as `CallKitBridge` (it holds
one underneath) behind `LiveCommunicationProviding`, and adds outgoing
calls: `startOutgoingCall(callee:dial:)` asks the system first with a
`StartConversationAction`, dials only once it has agreed, reports the call
connecting, and reports a dial that throws as failed. `LiveCommunicationAdapter`
is the real `ConversationManager`:

| The system's signal | Carried to | What happens |
|---|---|---|
| `reportNewIncomingConversation` | from `LiveCommunicationBridge.reportIncomingCall` | The ringing call shown, before the push handler returns |
| `StartConversationAction` | performed by `startOutgoingCall` | The call shown, then dialled; the audio session's category set |
| `JoinConversationAction` | `handleJoin` | The call answered, the session's category set |
| `EndConversationAction` | `handleEnd` | The call hung up |
| `MuteConversationAction` | `handleMute` | Silence sent in the microphone's place; the engine's input muted in device mode |
| `PauseConversationAction` | `handlePause` | The device let go at once, the far end held with a re-INVITE; the reverse on resume |
| `PlayToneAction` | `handleTone` | The digits sent as DTMF |
| `didActivate`, `didDeactivate` | `audioSessionActivated`, `audioSessionDeactivated` | The call's device, or the library's engine (`drive`), opened and let go with the system's session |
| `conversationManagerDidReset` | `managerDidReset` | Every call hung up |
| the call progressing, confirmed, ended | `reportConversationEvent` | `conversationStartedConnecting`, `conversationConnected`, `conversationEnded` with `failed`, `remoteEnded` or `unanswered` |

Merging is not offered (`capabilities` names pausing and tones), and a
merge or unmerge action fails. `LiveCommunicationBridgeTests` runs on macOS
and Linux against a recording provider: an incoming report and its refusal,
an outgoing call refused (nothing dialled), one whose dial throws, one
placed, joined, muted, toned and ended between two stacks, and a reset. The
adapter is built for the iOS device, the simulator and Mac Catalyst with
`xcodebuild build -scheme Sipral` from `bindings/`. A phone is needed for
the rest: the system's incoming screen and its join and end buttons, the
outgoing call in the system's call list and recents, `didActivate` for a
real call, the Dynamic Island, a cellular call put on pause, and whether
the system accepts the adapter's configuration as given.

What the simulator cannot give is the system's own delivery: a real cellular
call interrupting the session, CallKit calling `didActivate` for a call it
really placed, a Bluetooth headset or CarPlay taking the route. Those need a
phone.

The same goes for `C5`'s measurements: what runs while the application is
backgrounded with no call is a property of the whole process, and the polled
core is what makes it *possible* to answer, not the answer.

## The iPhone sample

`bindings/swift/samples/SipralPhone` is a SwiftUI iPhone application over the
Swift package, made to be installed on a phone and to send back what it saw.
It is an Xcode project and not a target of `bindings/Package.swift`, as the
Mac sample is: an iOS application is a signed bundle with an `Info.plist`,
entitlements and an icon, which SwiftPM does not build. It sits under
`samples/` as the .NET MAUI sample does.

**What it is.** An account screen (server, port, UDP, TCP or TLS, user,
password, an optional authentication user and domain, SRTP, STUN), a dial pad
with the registration's state, the in-call screen (mute, hold, a keypad for
DTMF, speaker, the system's route picker, `AVRoutePickerView`, and hang up),
an incoming screen where CallKit does not ring, and Diagnostics. The password
is kept in the Keychain, readable after the first unlock and on this phone
only; everything else in `UserDefaults`. One stack, one account, one call at
a time; every call's audio is a `CallAudio` over
`VoiceProcessingAudioDevice`, fed by `AudioSessionObserver` and, with
CallKit, by `CallKitBridge`.

- **CallKit and PushKit**, on a phone: `CallKitAdapter` shows every call,
  incoming and outgoing (`startOutgoingCall`), and the application's own
  mute, hold, digits and hang-up go through the system (`request(_:)`), so
  the lock screen, a headset and CarPlay act on the same call.
  `PushKitAdapter` is created in `didFinishLaunching`, so a launch a push
  caused gets the push; the account is opened before that returns.
  Every push is reported to CallKit ("Through `sipral.h`", above).
- **Push parameters.** With a VoIP token and a team in the build
  (`SipralTeamIdentifier`, from `DEVELOPMENT_TEAM`), the account's REGISTER
  carries `pn-provider=apns`, the token in hex as `pn-prid` and
  `TEAMID.org.sipral.phone.voip` as `pn-param`; a new token re-registers.
  Diagnostics says whether the registrar promised pushes (`pushEcho`). A
  push's payload names the caller under `caller`. What sends it is a proxy
  or push gateway holding the APNs key for the team ("Who sends the push",
  above): FreePBX does not, so against the live PBX the push path ends at the
  REGISTER and the registrar's answer, "promised nothing".
- **The network.** `NWPathMonitor`; each path that names another link,
  address or interface goes to `SipralStack.networkChanged(to:)`, and a call
  asked to move (`callAddressWanted`) is moved (`Call.moveMedia()`).
- **The lifecycle.** `SipralAppLifecycle` over `KeychainSnapshotStore`
  ("C3 in the Swift package", above): into the background with no call, the
  registration written down and the stack suspending; back, resumed; at a
  launch, the snapshot read back and the binding refreshed at once.
- **Evidence.** Every line the application writes and every line of the
  stack's log at trace level, with whole SIP messages (Diagnostics' "Whole
  SIP messages", on by default; credentials and keys are removed by the
  stack), go to `Library/Application Support/Logs/sipral-phone.log`, each
  physical line starting with its UTC time to the millisecond; at 4 MB it
  becomes `sipral-phone.1.log`, so two files at most. "Share log" writes
  one text file, `sipral-phone-YYYYMMDD-HHMMSSZ.txt`, and hands it to the
  share sheet: what the screen shows (account without password, network,
  push, lifecycle, battery, counters), both log files, the decision record
  (`sipral_stack_diagnostics_json`) and the state dump
  (`sipral_stack_state_text`); the password is taken out of all of it once
  more before it is written. A pcapng is not in it: the C ABI exports none
  (`docs/14-diagnostics.md`, "Handing a call's diagnostics over redacted").

The deployment target is iOS 15.0, the package's own minimum: nothing the
application uses is newer (CallKit, PushKit, `AVRoutePickerView`,
`NWPathMonitor` and SwiftUI's iOS 15 API), and LiveCommunicationKit, which
would need 17.4, is not used. The first phone is on iOS 18.7.

**Building it.** `scripts/package/ios-app.sh` builds the XCFramework from
this tree (`xcframework.sh --out target/ios-app/apple --dry-run`; the project
names `target/ios-app/apple/spm` as its package, so the application links
this tree's library, not a release's), draws the icon from
`assets/sipral-mark.svg` into the asset catalog (git ignores the PNG), and
builds for the simulator and for a phone:

```bash
scripts/package/ios-app.sh                                 # simulator, and a phone unsigned
scripts/package/ios-app.sh --reuse-xcframework --test UDID # and its tests on that simulator
DEVELOPMENT_TEAM=ABCDE12345 scripts/package/ios-app.sh --reuse-xcframework --archive
```

With `DEVELOPMENT_TEAM` the phone build is signed for development with
`-allowProvisioningUpdates`, and `--archive` archives it, signs it ad hoc
with its entitlements, and exports an IPA for App Store Connect, signed for
distribution; the upload is not run, and the script prints the commands
that would. `SIPRAL_PHONE_BUNDLE_ID` replaces `org.sipral.phone`. Built from
Xcode instead, the team goes in `bindings/swift/samples/SipralPhone/Local.xcconfig`
(`DEVELOPMENT_TEAM = ...`), which git ignores; choosing it in the Signing tab
would write it into the project.

**Store readiness.** `NSMicrophoneUsageDescription`; `UIBackgroundModes`
`voip` (PushKit's VoIP pushes) and `audio` (a call keeps its audio while
the screen is off or another application is in front); `aps-environment` in
the entitlements, which the export turns into `production`. The privacy
manifest declares no tracking, no collected data, and the required-reason
APIs the device binary actually references, read with `nm -u`:
`NSUserDefaults` (`CA92.1`) and `fstat` (file timestamps, `C617.1`);
`mach_absolute_time` and `systemUptime` are not referenced. The export
compliance question App Store Connect asks about encryption (TLS, SRTP) is
the owner's to answer; `ITSAppUsesNonExemptEncryption` is not set.

**A run without the screen.** The launch environment can hold the account
and a call, which is how the simulator ran it: `xcrun simctl launch` hands
`SIMCTL_CHILD_SIPRAL_PHONE_<NAME>` to the application as
`SIPRAL_PHONE_<NAME>`. `SERVER`, `PORT`, `TRANSPORT`, `USER`, `PASSWORD`,
`AUTH_USER`, `DOMAIN`, `SRTP`, `REGISTER=0` for a peer with no registrar;
`CALL` (dialled once registered), `CALL_AFTER`, `CALL_SECONDS`, `DTMF`;
`ANSWER=1`; `EVIDENCE=1` and `UNREGISTER=1` when the call ends. Nothing given
this way is saved.

**What ran, on the iOS 26.5 simulator (iPhone 17) under Xcode 27.1, 21
October 2026.** Built for the simulator and, unsigned, for a phone
(`generic/platform=iOS`, Release); the application's 10 tests passed on the
simulator (the account and dialling rules, the password only in the secret
store, the real Keychain, every line of the log timed, a whole SIP message's
included, the log's turnover, the evidence file's sections and the password
removed from it). CallKit and PushKit are off on
the simulator, which refuses both (above), so calls rang and were answered in
the application's own screens.

| | |
|---|---|
| A call to `SipralLabAgent` on the Mac (no registrar) | Confirmed 267 ms after it was placed; G.722 at 16 kHz both ways; 20 seconds, then hung up from the phone: 1,007 packets sent and 992 received, none lost; the agent counted 991 sent and 1,003 received, and read the digits `1`, `2`, `3` sent three seconds in. A second run, 10 seconds: INVITE to 200 OK 101 ms on the wire, ACK 12 ms later, 532 sent and 528 received, digits `4`, `5` read by the agent |
| A call from the agent | Answered in the application's screen, confirmed 246 ms after it was taken; hung up by the agent after 15 seconds: 754 sent, 747 received, none lost; the agent 746 and 750 |
| The live PBX (`docs/11-testing.md`, "A live PBX"), one of its extensions, UDP | REGISTER, 401, REGISTER, 200 OK; `*43`, the echo: INVITE, 401, ACK, INVITE, 100, 200 OK in 242 ms from the first INVITE, ACK 7 ms later; G.711 at 8 kHz; 20 seconds: 1,004 packets sent and 990 received, none lost; BYE, then the un-REGISTER answered 200 and the stack closed |
| The same over TCP | Registered 140 ms from the stack's start; the echo's 200 OK 81 ms after the first INVITE; 8 seconds: 411 sent, 404 received |
| The same over TLS | The server's certificate accepted by the system's trust; registered 138 ms from the stack's start; the echo's 200 OK 201 ms after the first INVITE; 8 seconds: 397 sent, 392 received |
| Into the background and back (`simctl launch` of Settings, then of the application, 12 seconds apart) | `background: registration written down, suspending: 1 bindings no longer believed, 0 calls`, the registration `unverified`; back, `foreground: resumed`, a REGISTER, `registered` 58 ms after the resume; a call to the echo afterwards: 316 sent, 308 received |
| The process ended in the background, started again (`simctl terminate`, then `launch`) | `registration restored from the keychain (restored), refreshing it`: the new process's REGISTER carried the first one's `Call-ID` with CSeq 3 (the first process had sent 1 and 2), and the account read `registered` 141 ms after the stack started, against 4,339 ms for the first process's cold registration |
| "Share log" | One file each run, 26 to 35 KB for a registration and a call: every line timed, the four sections present, the extension's password in none of them (`grep -c` 0) |

Two things seen on the live PBX, and neither the stack's: in two of the three
first registrations over UDP the PBX answered nothing for 4 to 6 seconds,
then all four 401s — one per retransmission of the first REGISTER — arrived
within two milliseconds of each other; and the PBX sends a request of its
own right after the registration, which the application answers 200. The
simulator reached the PBX from the Mac through a VPN, where
`docs/11-testing.md`'s runs were on the PBX host's own network; which of
the two held the first answers back was not found out.

**Not run on the simulator.** A network change: the simulator shares the
Mac's network, and changing the Mac's — shared, with a tunnel up — was not
done, so the forwarding to `networkChanged(to:)` has not run in this
application; the Wi-Fi to cellular step below is where it is first seen
and measured. CallKit's screens, PushKit
and a push, the audio session's interruptions and routes, Bluetooth, CarPlay
and the battery: a phone's (`What the simulator cannot show`, above). The
iOS 27.1 runtime installed on this Mac offers only one device type, which
this run did not use.

**On the Apple account.** With the owner's team and no phone registered to
it: the signed development build fails as it must ("Your team has no
devices from which to generate a provisioning profile"); the archive and
the export for App Store Connect succeeded, signed "Apple Distribution",
4.4 MB, its entitlements `aps-environment` `production` and
`beta-reports-active`, with the privacy manifest and the icon in the bundle.
The App ID `org.sipral.phone` and the distribution certificate are what
`-allowProvisioningUpdates` made in the account. The upload to App Store
Connect was not run.

## On a real iPhone

The run on the phone is short and every step ends with the same thing: on
Diagnostics, "Share log", and the file sent back (AirDrop, Mail, Messages).
Write down the time of each step; the log's times are UTC.

**Before.** On the Mac, with the phone plugged in and Xcode open once (it
registers the phone with the team), then:

```bash
echo 'DEVELOPMENT_TEAM = <team>' > bindings/swift/samples/SipralPhone/Local.xcconfig
DEVELOPMENT_TEAM=<team> scripts/package/ios-app.sh --reuse-xcframework
open bindings/swift/samples/SipralPhone/SipralPhone.xcodeproj   # Run on the phone
```

or the TestFlight build: `--archive`, then the upload, then the invitation
on the phone.

1. **Install and open.** Expected: the Phone tab, "Not registered". On
   Diagnostics, "Push" shows a token. Send: the log.
2. **Permissions.** Fill in the account, "Save and register". Expected: the
   system asks for the microphone once; allow. Send: the log ("microphone
   granted").
3. **Register over UDP, then TCP, then TLS** (change Transport, "Save and
   register" each time). Expected: "Registered since ..." each time;
   Diagnostics' "Push" says what the registrar promised. Send: the log after
   the three.
4. **Outgoing call** to the echo (`*43` on a FreePBX). Expected: the system's
   call screen, your voice back; hang up after 30 seconds. Send: the log.
5. **Incoming call** from another phone, the application in front.
   Expected: the system's incoming screen; answer, talk, hang up from the
   other end. Send: the log.
6. **Incoming call, screen locked**, then **unlocked but the application in
   the background**. Expected: the full-screen call on the lock screen, the
   banner otherwise; both answerable. Send: the log.
7. **A cellular call during ours.** Call the phone's number while on the
   echo; "Hold & Accept"; end the cellular call; resume ours from the call
   screen. Expected: ours held (far end hears silence or hold), then audio
   both ways again. Send: the log.
8. **Routes.** During a call: earpiece, speaker (the in-call button and the
   route picker), wired headphones plugged and unplugged, a Bluetooth
   headset, CarPlay if there is a car. Expected: audio follows each; the
   in-call screen's route line changes. Send: the log, with the order
   written down.
9. **Mute from the headset** (the call button or the car's mute). Expected:
   the far end hears silence, the in-call Mute shows on. Send: the log.
10. **Wi-Fi to cellular mid-call.** On the echo, walk out of the Wi-Fi (or
    turn Wi-Fi off in Control Center) and count until your voice comes back.
    Expected: "network changed to cellular ..." in the log, and the echo
    again. Send: the log and the seconds counted.
11. **Killed, then a push.** Swipe the application away; call it from
    another phone. Expected with a push gateway: the call screen within a
    few seconds, answerable. Without one (the live PBX): no ring, which the log
    after reopening shows as "registrar promised nothing". Send: the log.
12. **Thirty minutes idle, registered.** Note the battery percentage,
    lock the phone for 30 minutes, unlock, note it again, place one call.
    Expected: the call works; the log shows the background, the resume and
    the REGISTER that proved the binding. Send: the log and both
    percentages.

## .NET MAUI

`bindings/dotnet/Sipral.Maui` is the .NET binding compiled for
`net10.0-ios` and `net10.0-android`, packed by `scripts/package/maui.sh`
with the iOS XCFramework above and `libsipral_ffi.so` built for Android API
21 with the Mac's own NDK (`bindings/dotnet/README.md`, ".NET MAUI on iOS
and Android", says what the package carries and how each platform loads
it). On iOS every P/Invoke names `__Internal`, since the library is linked
into the application; on Android it is loaded from the APK by name.

`SipralAppLifecycle` applies `C3` and the suspend and resume calls to a
MAUI application: entering the background (iOS) or the activity stopping
(Android) writes down every kept account with `sipral_account_freeze` into
the platform's secure storage, **then** calls `sipral_stack_suspending` --
in that order, since a registration no longer counts as bound once the
stack is told it is suspending, and there would be nothing to freeze.
Coming back calls `sipral_stack_resumed`; a process the system ended thaws
the stored snapshot on its new account, with the time it sat unused as
`asleep_ms`. On iOS the audio session is the application's, as for the
Swift package: `SipralAudioSession` sets play-and-record in voice-chat mode
for an application without CallKit.

**Run on the iOS 26.5 simulator and an Android 16 emulator.**
`samples/Sipral.Sample.Maui` was built for both and started on each, its
first screen showing the feature bits read through the native library, so
the static link and `__Internal` on iOS and the `.so` lookup on Android are
proven at start. The suspend, freeze and thaw sequence is tested on the
desktop binding against a simulated registrar
(`bindings/dotnet/Sipral.Tests/LifecycleTests.cs`). Not yet run: an
application built from the packed `.nupkg` rather than the project, a
physical iPhone or Android phone, armeabi-v7a and x86_64, the background
and foreground events delivered by the system to `SipralAppLifecycle`, the
microphone prompt, and any registration or call through this layer.
