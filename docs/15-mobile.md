<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
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

Nothing here is platform code. It is all signalling, it is all in `sipral-ua`,
and it runs on the same injected `Instant`s as everything else — a wake-up
chain that takes twenty seconds in the field takes microseconds in a test.

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
sequence; on Android, `org.sipral.telecom.TelecomBridge` does.

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
matters"); STUN (`SIPRAL_NAT_STUN`) is the answer for one that is not, and
the sample does not offer it yet. The NAT's mapping is not kept open by
anything but the phone's own traffic, since UDP has no keepalive here and
the registration refreshes once an hour: a call to a phone left idle longer
than its NAT keeps a mapping is not something this run tested.

## The Swift package on iOS

`scripts/package/xcframework.sh --out DIR` builds `DIR/CSipral.xcframework`
— macOS (arm64 and x86_64), iOS device (arm64) and iOS Simulator (arm64 and
x86_64) — and prints `DIR/spm/Package.swift` over it: the whole `Sipral`
module from `bindings/swift/Sources/Sipral`, CallKit and PushKit bridges
included, on a `binaryTarget` instead of the source target, with the
package's test suite beside it. `bindings/Package.swift` itself stays the
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
.NET packages, which did the same. On the account with Asterisk's defaults,
`labuser`, the simulator's call works as well: the Mac's VPN address is
routable from the lab, so the `c=` Asterisk sends to reaches it, where the
emulator's does not.

**What ran, on the iOS 26.5 simulator (iPhone 17, arm64) under Xcode 26.6.**
With none of the variables set, sixteen tests ran: fourteen passed — the
in-process loopback calls, `DialogFlowTests`, the bridges against a
recording provider and `CallKitAdapter` against CallKit's own action
classes — and the two `HostPeerCallTests` were skipped, each saying why.
Earlier, the call to `SipralLabAgent` on the Mac was up 60 ms after the
INVITE; the simulator end counted 31 RTP packets sent and 29 received at the
moment it read its statistics, heard 25 frames of its own tone come back,
and was hung up by the agent's BYE. The agent's own log showed it answered,
the ACK arrived (the call read `confirmed`), `#` came in, and 40 packets
sent and 39 received by the time it hung up. The x86_64 simulator slice and
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
CallKit's Answer is its one answer. Once bound to `CallKitBridge`, a call's
`events` stream is the bridge's: an `AsyncStream` hands each event to one
reader, so a second loop over the same stream sees only some of them.

## What is still owed to phase 4, and is not signalling

**The platform audio session is not here, deliberately.** `C4` — the device
taken away and given back mid-call by an incoming cellular call, by a Bluetooth
headset connecting mid-sentence, by a car taking over routing, by the operating
system reclaiming the session — is not a protocol problem and has no business
in `sipral-ua`. On iOS and Android it is the application's today
(`AVAudioSession` on iOS, the telecom framework's audio routes on Android).
No `sipral-io-*` crate handles either yet. The
same goes for `C5`'s measurements: what runs while the application is
backgrounded with no call is a property of the whole process, and the polled
core is what makes it *possible* to answer, not the answer.

What this document covers is everything about a sleeping device that is
signalling, and that is the whole of `C2` and `C3`.
