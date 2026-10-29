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

**The `Call-ID`, when the push carries one. Otherwise, and always as the
fallback, the same account and the same user and host in the `From` URI; for
a push that named nobody, the account alone. Time is only a tie-break.**

RFC 8599 §13 says the mechanism "does not require a proxy to insert any
payload", and §5.6.2 has the proxy hold the request rather than describe it,
so a push need not carry any SIP identifier, and from many senders it does
not. What a push from most senders does carry is who is calling and which
account, so that is the rule that always applies when it is there.

A push may name nobody: one that follows §13 to the letter, or one sealed for
the application whose seal does not open on the device. iOS still makes the
application show it as a call, so `announce_any`
(`sipral_account_announce_any`, ABI 1.7) expects the call on the account
alone: the INVITE with the push's `Call-ID` when it carried one, else the
oldest INVITE on the account that no announcement naming its caller takes.
An announcement that names the caller always goes first, so the account rule
only takes what the caller rule leaves; two such calls ringing together on
one account may be matched the other way round, which nothing in such a push
can prevent. The screen raised for it shows `Unknown` until the INVITE is
matched, and then the INVITE's `From` URI and name (Swift's
`CallKitProviding.reportCaller`, Kotlin's `TelecomConnection.setCaller`; a
Core-Telecom call keeps the address it was added with).

A proxy that holds the INVITE while it pushes has the INVITE in hand, and
nothing stops it putting the `Call-ID` in the push; `interop/push-gateway`
does (below). `announce_call` (`sipral_account_announce_call` through
`sipral.h`, ABI 1.3) takes it: the INVITE with that `Call-ID` on the same
account is the announced call, whoever its `From` names, which tells two
calls from one caller apart where the caller rule can only take the oldest.
The `Call-ID` is compared as written, case and all (RFC 3261 §20.8). When no
INVITE carries it, the caller rule decides, over every announcement: an
intermediary that changed the `Call-ID` after the push was sent costs the
exact match, not a second call screen. `announce` is `announce_call` with no
`Call-ID`.

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
came first and `out_announcement` otherwise; `sipral_account_announce_call`
is `announce_call`, the same with the push's `Call-ID`, and
`sipral_account_announce_any` is `announce_any`, for a push that named
nobody. `sipral_account_refresh_binding`
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
`Account.pushEcho()` reads the answer; `addAccount(instanceId:)` puts RFC
5626's `+sip.instance` on every REGISTER's `Contact`, which a push proxy may
require of a binding, and `addAccount(headers:)` adds the application's own
fields to every REGISTER. `PushKitAdapter` reports a call to
CallKit for every VoIP push the system says must be, which iOS requires of an application that wants
to keep receiving them: one whose payload names no caller is expected on the
account alone ("The matching rule"), and one the decoder could not read, or
that arrives before there is an account, is shown and ended at once. A shown
call that no INVITE fills is
ended too, as failed when the announcement was refused and as unanswered
when `ANNOUNCED_CALL_MISSING` arrives, rather than left ringing; so is the
screen of a push whose INVITE came first and was handed to the application
by `matchIncomingCall`, whose own screen is that call's. Only the stack's
pairing gives an INVITE a push's screen: one matched to no announcement is
the application's to show, however alike its caller looks. The push's
payload carries the caller under `caller`, its name under `name` and the
held INVITE's `Call-ID` under `call-id`; that, and what sends the push, is
the push gateway's side (below). A push whose payload is sealed is opened by
the decoder the application gives `PushKitAdapter`, which returns the same
three fields. From iOS 26.4 PushKit says with each push whether a call must
be reported for it (`PKVoIPPushMetadata.mustReport`); the adapter takes that
delivery too, and a push that need not be reported is not shown: the binding
is refreshed, and its INVITE is shown as any other incoming call. The name
reaches the call screen as `CXCallUpdate.localizedCallerName`, from the push
or, when it carried none, from the INVITE once matched; and
`CallKitBridge.endShown(uuid:reason:)` takes down a screen the application
will not ring, as unanswered, its INVITE declined if it comes. An
application with its own `PKPushRegistryDelegate` calls
`PushKitBridge.handle(push:account:)`, or `receive(_:mustReport:account:)`,
from it instead (`bindings/swift/README.md`).

**The user answers before the INVITE.** On a phone this is the usual order:
the push raises the call screen at once, and the INVITE follows the refresh
REGISTER a second or more later. `CallKitBridge` keeps what the user does to
a screen that has no call yet. An Answer (`CXAnswerCallAction`, through
`handleAnswer(uuid:completion:)`) is held, not fulfilled: when the INVITE is
matched and the call bound to the screen (`PendingCall.resolve(with:)`), the
call is answered on the spot and only then is the action fulfilled, so the
system shows the call connecting until it is. If the announcement is refused
or goes missing the action fails, with `CallKitBridgeError.callNeverArrived`,
and the screen ends as unanswered; if CallKit gives up waiting on the action
(`timedOutPerforming`), the screen ends and the INVITE, if it still comes, is
declined. An End or Decline tapped before the INVITE is fulfilled at once and
remembered: the INVITE is answered 603 when it arrives. Activating the audio
session stays CallKit's (`didActivate`), as for any answered call. An
application binds its own reader to the call before resolving it, since the
answer can go out inside `resolve(with:)`. `PushTests` runs the three cases
between two stacks on loopback: answered when the INVITE comes, failed when
the announcement goes missing, declined with 603 after an End. They passed
on macOS and on the iOS 26.5 simulator, over the XCFramework, with
`CallKitAdapterTests` beside them; the real delay between a push and its
INVITE, and CallKit's own patience with a held Answer, are the phone's to
show (step 11 below).

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

The library ships neither, and the credentials never belong on the device.
Whether the registrar a device talks to is one of the two is exactly what
`push_echo` reports: `+sip.pns` naming the service asked for is the network
saying it will send the pushes, and anything else means nobody has.

### The lab's push gateway

The second of the two is in this repository as a test tool, so the whole
wake-up can be run before a phone is in the room: `interop/push-gateway`
(`sipral-push-gateway`, never published), written from RFC 8599, its proxy
logic in `src/proxy.rs` with no socket or clock of its own and its tests
beside it. In front of one PBX it does what §5.6 asks — `+sip.pns` added to
a REGISTER that asks for pushes and to its 2xx, `+sip.pnsreg="121"` for a
device that wakes itself, a PURR in `+sip.pnspurr` (§6.2.1), 423 for a
binding too short to wake, 555 when told no other proxy could push; an INVITE
or a MESSAGE for such a binding held in the bucket while the device is pushed,
forwarded once the device's refresh is answered 2xx, and answered 480 when
the bucket timer runs out or the push fails, a CANCEL meanwhile answered 487;
a request inside a dialog whose target names a PURR held the same way
(§6.2.3); and a push to refresh a binding 120 seconds before it lapses (§5.5).

It also does what a PBX that knows nothing of push needs from it: the
REGISTER's `Contact` is given the gateway's address, keeping every URI
parameter, so the PBX sends the account's calls to the gateway, `pn-*` and
all, whether it rewrites `Contact`s (FreePBX's default) or not, and with no
`Path` (RFC 3327) support asked of it; the 2xx is given the device's own
`Contact` back. Every other `Contact` a device sends carries its own address
in one parameter, so what the PBX sends inside a dialog reaches the device
behind any NAT, with no dialog state kept. Everything a device sends goes to
the PBX.

What a push carries is `kind` (`call`, `message`, `dialog`, `refresh`),
`caller` (the held request's `From` URI, which `PushKitAdapter` reads),
`name` when the `From` has one, and `call-id` (the held request's, for
`announce_call`). `PushKitAdapter` reads `call-id` and `name` beside `caller`, and the
Swift push bridge announces with it whenever the push has one
(`Account.announce(caller:callId:)`); on Android, `TelecomBridge.pushArrived`
and `wakeForPush` take it as `callId` (`SipralAccount.announce(caller,
callId)`). A push whose payload names no caller — the decoder found none, or
returned empty fields for a seal that would not open — is announced on the
account alone (`caller` nil, or null on Android), not ended at once; one the
decoder could not read at all (it threw) still is.

**On APNs only an INVITE is pushed.** A VoIP push is the only kind that
reaches a VoIP application, and since iOS 13 one that reports no call to
CallKit gets the application terminated and, repeated, its VoIP pushes
stopped. So on APNs a MESSAGE or a request inside a dialog goes straight to
the device's last address, and no refresh push is sent: an iOS binding has to
be refreshed by the application itself while it runs, or registered long. On
FCM, whose high-priority data message carries no such rule, all four kinds
are pushed.

It is the lab's, and its limits are a test tool's: UDP only on both sides,
no TLS (§13 asks for TLS, or signalling secured some other way, wherever
this runs for real), one PBX, every binding and every held request in memory
and gone on a restart, no forking, one connection per push to Apple and to
Google rather than one kept open. Its own `Contact` for a device is the same
whatever socket the device registers from, which is what lets a woken phone's
refresh replace the binding it had; the price is that a removal, which
carries no `pn-prid` (§4.1.2), also removes the binding of another device of
the same account and the same `pn-param` through the same gateway.

**What the lab proves**, `scripts/lab.sh push`, run on 21 October 2026 on
the second lab machine and ending "the lab agrees": the gateway in front of
the lab's Asterisk (`labuser-push`, set up as FreePBX sets up an extension),
the lab's own notification service beside it standing in for APNs and FCM,
and the C harness as the phone (`interop/harness-c`'s `run_push`). The
harness takes a token from the service, registers through the gateway and
reads `+sip.pns="apns"` back with `sipral_account_push_echo`, then sleeps as
an application the system suspends and then ends: the registration frozen
(79 bytes), the stack destroyed, both sockets closed. Asterisk calls the
account; the gateway holds the INVITE and pushes; the service delivers
`{"kind":"call","caller":"sip:anonymous@anonymous.invalid","name":"Anonymous","call-id":"…"}`
about 1.3 seconds after the harness fell asleep. Woken, the harness starts
from cold on new sockets, thaws the registration and announces the call; the
refresh goes, the gateway releases the INVITE to the new socket once
Asterisk has answered the refresh 200, and the harness reports
`SIPRAL_EVENT_KIND_CALL_ANNOUNCED` before `SIPRAL_EVENT_KIND_INCOMING_CALL`,
13 ms after its cold start, answers, hears the tone come back from
extension 9010 (266 of 391 frames audible) and is hung up by Asterisk. Run
twice: announced by the push's `Call-ID` with a caller the INVITE does not
name, so that only the `Call-ID` can have matched it, and announced by the
caller alone. Then a MESSAGE, on FCM's terms, held and delivered after the
refresh; a push the service accepts and loses, which leaves the harness
asleep and the INVITE answered 480 by the gateway at its bucket timer; and a
push the harness answers twelve seconds late, past the timer: 480 at the
gateway, and the announced call reported missing after twenty seconds.

What it does not prove is the last hop: Apple's and Google's own delivery to
a phone, and a phone's own suspend and wake. The senders for both are in the
gateway (`src/apns.rs`: HTTP/2 to `api.sandbox.push.apple.com` or
`api.push.apple.com`, an ES256 provider token from the `.p8` key, `apns-topic`
the bundle with `.voip`, `apns-push-type: voip`; `src/fcm.rs`: the service
account's RS256 assertion traded for an access token, then a high-priority
data message to the HTTP v1 API), with HTTP/2 and HPACK written from
RFC 9113 and RFC 7541. Their request building and token signing are tested
against the documented formats, and `probe`, run the same day without any
credentials, reached all three endpoints and was answered as it should be:
APNs `403 InvalidProviderToken` to a token signed by a key made up for the
probe, on the sandbox and on production; Google's token endpoint
`400 invalid_request` to an assertion nobody signed; FCM `401 UNAUTHENTICATED`
to an access token nobody issued. With a real key, nothing has been sent.

### Device day: the gateway with real keys

What the owner creates once, and keeps outside the repository:

- **APNs** (Apple Developer, Certificates, Identifiers & Profiles): an App ID
  for the application with the Push Notifications capability; under Keys, a
  key with "Apple Push Notifications service (APNs)" enabled — for a build
  installed from Xcode, one for the Sandbox environment — downloaded once as
  `AuthKey_<KEYID>.p8`; its 10-character Key ID; the Team ID (Membership
  details). The application's `pn-param` is `<TEAMID>.<bundle id>.voip` and
  its `pn-prid` the PushKit token in hexadecimal (RFC 8599 §10).
- **FCM** (Firebase console): the Android application added to a project
  (its `google-services.json` goes into the application); under Project
  settings, Service accounts, "Generate new private key", a JSON file. The
  application's `pn-param` is the project ID and its `pn-prid` the FCM
  registration token (§11).

On a machine both the phone and the PBX reach — with `ca-certificates`
installed, since the senders check Apple's and Google's chains against the
system's store — first the keys alone, before any phone:

```sh
sipral-push-gateway probe apns --apns-key /secure/AuthKey_ABC123DEFG.p8 \
    --apns-key-id ABC123DEFG --apns-team DEF123GHIJ --topic org.example.app.voip
sipral-push-gateway probe fcm --fcm-service-account /secure/service-account.json
```

What a working key should be answered with, by Apple's and Google's
documentation, since nothing here has seen it yet: from APNs a refusal of
the device token (`400 BadDeviceToken`) rather than of the provider token
(`403 InvalidProviderToken`, what a key it does not know gets); from Google
an access token, then a refusal of the registration token
(`400 INVALID_ARGUMENT`) rather than `401 UNAUTHENTICATED`.
`--apns-production` sends to production, for a TestFlight or App Store
build; the sandbox is the default. With the phone's own token as
`--device-token`, the probe pushes a call from `sip:probe@sipral.invalid`
that never comes: the push leg alone, which on the phone should raise the
call screen and then report the announced call missing twenty seconds later.
Then the gateway itself, in front of the PBX:

```sh
sipral-push-gateway run --pbx pbx.example.com:5060 --listen 0.0.0.0:5070 \
    --advertise <address the phone and the PBX reach>:5070 \
    --apns-key /secure/AuthKey_ABC123DEFG.p8 --apns-key-id ABC123DEFG \
    --apns-team DEF123GHIJ \
    --fcm-service-account /secure/service-account.json
```

The same values can come from `SIPRAL_APNS_KEY_FILE`, `SIPRAL_APNS_KEY_ID`,
`SIPRAL_APNS_TEAM` and `SIPRAL_FCM_SERVICE_ACCOUNT`; nothing of a key is
printed. The phone's account keeps the PBX as its registrar and its address
of record and names the gateway as the address its requests go to
(`registrar_address` in `sipral_account_config_t`), with the push parameters
above. The PBX needs no SIP setting changed, but a firewall in front of it
(FreePBX has one) has to let the gateway's address in. The gateway prints one
line per thing it does, the same lines the lab reads.

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

The sample shows no audio levels; since 21 October 2026 each call's card
shows its packet counts. The full-screen intent: from Android 14,
`USE_FULL_SCREEN_INTENT` is not simply granted by the manifest, and in this
run the sideloaded sample was refused it (`adb shell appops get
org.sipral.sample USE_FULL_SCREEN_INTENT`), so the call showed as a heads-up
notification rather than a screen over the lock screen; the user can allow
it in the application's settings. On 21 October the same system image
granted it to a fresh install (`granted=true`, app op `default`); "The store
build" below says how the refused case was produced and what it does.

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

### The store build

The sample is built for Google Play as well as for a debugger, and what a
store asks of it is in the code rather than in a list:

| | |
|---|---|
| Target API level | 37 (Android 17), the newest stable level in Google's SDK repository on 21 October 2026 (`platforms;android-37.2` is a minor release of it). Play has required 36 for new apps and updates since 31 August 2026 |
| A call in the background | `SipralCallService` in the telecom helper, a foreground service of types `phoneCall` and `microphone` (`FOREGROUND_SERVICE_PHONE_CALL`, `FOREGROUND_SERVICE_MICROPHONE`), from the moment a call rings (a push's announcement included, as `phoneCall` alone), is placed or answered until the last one ends; "Lifecycle on Android" below says when it starts and what Android 14 refuses it. Play asks each type to be declared in the Play Console with a video of the feature (support.google.com/googleplay/android-developer/answer/13392821) |
| Microphone | Asked at first launch (`RECORD_AUDIO`), shown again on the Readiness screen with the reason, and the system settings offered once Android stops asking |
| Notifications | `POST_NOTIFICATIONS` asked at first launch on Android 13 and later |
| A call over the lock screen | `USE_FULL_SCREEN_INTENT`, checked with `NotificationManager.canUseFullScreenIntent` on Android 14 and later; refused, the Readiness screen says what changes (the call is a heads-up notification and a locked screen stays dark) and opens `ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT`. Play grants it by default only to applications whose core function is calling or alarms, declared in the Play Console (support.google.com/googleplay/android-developer/answer/13392821) |
| Battery optimisation | Shown, never asked to be lifted: the sample does not hold `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`. Android's own table of acceptable exemptions lists a calling application that can use high-priority FCM messages as **not acceptable** (developer.android.com/training/monitoring-device-state/doze-standby, "Acceptable use cases for exemption"), and Play's Device and Network Abuse policy says "Don't bypass System power management unless eligible" (support.google.com/googleplay/android-developer/answer/9888379). The Readiness screen explains Doze and opens `ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS`, the list where the user decides |
| Background restriction, standby bucket | `ActivityManager.isBackgroundRestricted` and `UsageStatsManager.getAppStandbyBucket`, on the Readiness screen with what each means for a call |
| The password | Sealed with AES-256-GCM under a key the Android Keystore generates and never lets out (`SipralKeystoreBox`); the preferences file holds only ciphertext. Not `EncryptedSharedPreferences`, which AndroidX has deprecated |
| Backups | `allowBackup="false"` and data-extraction rules excluding everything from cloud backup and device transfer: the key that opens the password stays on the device, and so does everything else |

**Data safety, for the Play Console form.** What the sample collects and
where it goes, as built:

- **Stored on the device only:** the account (address of record, server,
  user name, the password sealed by the Keystore), the registration record
  (`SipralLifecycle`, sealed the same way), and the logs below in memory.
- **Sent to the user's own SIP server, and only there:** the account's
  REGISTER (user name, digest answer — never the password itself), calls
  (SIP signalling with the numbers dialled and the caller's, RTP audio from
  the microphone). To the STUN or TURN server the user names, if any: STUN
  Binding requests, and, through TURN, the call's audio.
- **Shared only when the user taps Share log:** the diagnostics bundle below,
  through the system share sheet, to whatever the user picks. It carries IP
  addresses and the address of record; never a password.
- **Nothing to the developer, no analytics, no advertising identifier, no
  crash reporter, no third-party SDK beyond AndroidX and Kotlin.**
- In the form's terms: personal info (user IDs, the SIP address), audio
  (voice, in calls), app activity (call logs, in the bundle only when
  shared); all of it "processed ephemerally" or "stored on device", none of
  it collected by the developer; encrypted in transit when the account uses
  TLS and SRTP, which is the server's choice, not the sample's.

**Diagnostics.** The Diagnostics screen keeps, in memory, the sample's own
event log (5,000 lines) and the stack's log (20,000 lines, `DEBUG`, or
`TRACE` with every SIP message when switched on; pseudonymised by the stack,
or with real addresses and numbers when the diagnostic trace is switched on
for comparing with a PBX's log). **Share log** writes one zip under the
cache and hands it to the share sheet through a `FileProvider` limited to
that directory: `README.txt` (application and variant, device, Android
release, process start, every readiness fact), `events.txt`,
`stack-log.txt`, `diagnostics.json` (the decision record of every call the
stack holds, `docs/14-diagnostics.md`, with real addresses), `state.txt`
(the stack's redacted state snapshot) and `logcat.txt` (this application's
own logcat, which is all Android shows an application). Every line carries
the phone's wall clock with its offset. There is no pcapng: the C ABI
offers no packet capture, so a capture comes from the network or the PBX.
Before a byte is written, `EvidenceBundle` removes every value of the
account's two passwords (four characters or longer) and the value of every
`Authorization` and `Proxy-Authorization` header, wherever it sits in a
line; the stack never logs credentials in the first place
(`docs/17-observability.md`), so this is the second line, for text from
anywhere else. `EvidenceTest` holds it to that on the JVM.

**Release build.** `scripts/package/android.sh --release` builds the
sample's store artefacts unsigned in the build image, and
`scripts/package/android-sign.sh` signs them on the machine that holds the
key, so the key never enters the image or the machine the image runs on:

```sh
scripts/package/android.sh --out out --accept-android-sdk-licenses --release [--with-opus] [--version-code N]
# on the machine with the key; the four variables come from the environment
export SIPRAL_ANDROID_KEYSTORE=... SIPRAL_ANDROID_KEYSTORE_PASSWORD=... SIPRAL_ANDROID_KEY_ALIAS=... SIPRAL_ANDROID_KEY_PASSWORD=...
scripts/package/android-sign.sh --in out
```

The variant is in every name: `sipral-sample-release.apk` and `.aab` carry
natives without Opus (version name `1.2.3`), `sipral-sample-opus-release.apk`
and `.aab` natives with it (`1.2.3-opus`); the version code is the
workspace version times ten plus one for Opus (`102030`, `102031`), and
`--version-code` overrides it for an upload that needs a higher one.
`android.sh` checks the release APK and the bundle as it checks the debug
APK, and for what a store asks besides: not debuggable, target API level
37, every 64-bit native's LOAD segments aligned to 16 KB and the APK's
uncompressed libraries on 16 KB boundaries (Play has asked 16 KB page
support of apps targeting Android 15 and later since November 2025), and
the bundle unsigned. `android-sign.sh` aligns the APK (`zipalign -P 16`),
signs it with v2 and v3 signatures and verifies it, and signs the bundle
with `jarsigner`, which is how Play expects an upload to be signed.
`--new-test-keystore DIR` makes a throwaway upload key with random
passwords (the directory 0700, the files 0600, refused inside the
repository). A key Play has seen on a first upload stays that listing's
upload key, so a listing meant to last is given the owner's key, not a
test one.

Run on 21 October 2026, from this tree on the lab machine's Docker:
`android.sh --release` passed every check (`:telecom:testDebugUnitTest` 12
tests, `:sample:testDebugUnitTest` 8; 96 artefacts on the sample's release
classpath, every one under a licence `deny.toml` allows): the release APK
23,634,594 bytes, the bundle 15,858,097, version 1.2.3 code 102030, not
debuggable, 16 KB aligned. Signed on the Mac with a test key: v2 and v3
signatures verified, the bundle `jar verified`. The signed release APK
installed on the `android-36` emulator, launched cold in 3.1 s (host load
600, see below), and asked for the microphone and then notifications.

### Lifecycle on Android

The Kotlin layer carries what `docs/16-lifecycle.md` and "C3" above
describe, as the .NET MAUI layer does:

| | |
|---|---|
| `SipralClient.suspending()`, `resumed()`, `interfaceLost()`, `nameResolutionLost()`, `coldStart()` | `sipral_stack_suspending`, `_resumed`, `_interface_lost`, `_name_resolution_lost`, `_cold_start` |
| `SipralAccount.freeze()`, `thaw(snapshot, asleepMs)`, `timeToReadyMs`, `pushEcho` | `sipral_account_freeze`, `_thaw`, `_time_to_ready`, `_push_echo` |
| `SipralLifecycle(store)` | every registration a registrar accepts for a kept account written down with the wall-clock time, so the record never trails the sequence number the registrar last saw; `enteredBackground()` writes each down once more and then calls `suspending()`; `enteredForeground()` calls `resumed()`; `restore(account, key)` thaws with how long the record sat |
| `wakeForPush(client, account, bridge, lifecycle, key, caller)` | the cold start after a push, in order: `coldStart()`; the record thawed (`RESTORED`, the same `Call-ID`, nothing sent); `TelecomBridge.pushArrived`, so the call rings before anything crosses the network, whose announce sends the REGISTER that confirms the binding; a registration from the beginning only when there was no record |
| `SipralKeystoreStore` (Android) | the records, each sealed by `SipralKeystoreBox` in the application's private preferences; one that cannot be opened reads as absent |
| `SipralAppLifecycle(application, lifecycle)` (Android) | `enteredBackground()` when the application's last activity stops (not for a configuration change), `enteredForeground()` when one starts again. `suspendInBackground = false` writes the records and tells the stack nothing, for an application with no push service that wants to refresh for as long as Android lets it run |

`FreezeCheck.kt` and `LifecycleCheck.kt` run all of it on a JVM over real
stacks and a loopback registrar (`scripts/check.sh --only kotlin`): a
registration written down on acceptance and on the way into the
background, `suspending` reporting one binding no longer counted as live, a
second client woken by a push ten minutes later (on the injected wall
clock) showing the call before anything else, carrying the binding on with
one REGISTER on the same `Call-ID`, and ready 22 ms after its cold start;
with no record, a new binding.

**The call's foreground service and a push, in order.** `SipralCallForeground.follow`
starts `SipralCallService` as soon as a call rings — a push's announcement
included, before its INVITE — or is placed (the framework's `REQUESTED`),
keeps it while a call rings, dials, is active or held, starts it again as
the shown call moves on (so its notification and its types follow, and a
microphone granted mid-call is added), and stops it with the last call. A
process a push started is otherwise cached, and Android's freezer stops it
about ten seconds after the push (`ActivityManager: freezing <pid>`): the
announcement's twenty seconds, the caller's CANCEL and the user's decline
would then never be acted on, and the call would ring until dismissed. The
order:

1. The application wires the bridge and calls `SipralCallForeground.follow`
   before anything announces a call, in the process the push started too:
   the service has to be started while the push's exemption lasts.
2. A push arrives (high-priority FCM); the process may be cold. The handler
   calls `wakeForPush`: `TelecomBridge.pushArrived` reports the call to the
   framework, which rings it, and announces it, whose REGISTER carries the
   registration on. The call is `RINGING`, and `SipralCallForeground` starts
   the service at once, of type `phoneCall` alone, with the application's
   `OngoingCallUi` notification for a ringing call (the incoming-call one).
   `phoneCall` is the type a ringing call needs and the one Android lets a
   background process start: a high-priority FCM message is an exemption
   from the background-start rule, and `phoneCall` (granted with
   `MANAGE_OWN_CALLS`) is not a while-in-use type. `microphone` is: from the
   background Android 14 refuses such a service outright (`SecurityException`)
   and earlier releases start it without the microphone
   (developer.android.com/develop/background-work/services/fgs/restrictions-bg-start,
   "Restrictions on starting foreground services that need while-in-use
   permissions"). A message Android downgraded to normal priority is no
   exemption: the start is refused with `ForegroundServiceStartNotAllowedException`,
   logged, and the call rings for as long as Android lets the process run;
   read `RemoteMessage.priority` before relying on it.
3. While it rings, the process stays: the INVITE is matched to the
   announced call, or the announcement's twenty seconds run out
   (`ANNOUNCED_CALL_MISSING`), or the caller cancels, or the user declines.
   Each of the last three ends the call, and with no other call the service
   stops.
4. The user answers on the full-screen activity or the notification: the
   application is visible, or the start comes from a notification the user
   touched, both exemptions for while-in-use permissions. The answer
   reaches `TelecomBridge.answer`, the call goes `ACTIVE`, and
   `SipralCallForeground` starts the service again, now with `phoneCall`
   and `microphone`, and the ongoing-call notification. The service is
   never let go between ringing and answered.
5. Answered from a headset, a car or a watch with the phone locked, the
   application is not visible: the service goes on as `phoneCall` alone if
   the system refuses `microphone`, and says so in the log; the far end
   then hears silence until the application is opened. That path needs a
   phone and a headset to see.
6. The last call ends: the service stops. A call that ends while the
   service is still being started is shown once, ended, before the service
   leaves: Android ends a process whose service, asked for with
   `startForegroundService`, stops before entering the foreground.

A second call that rings beside one already placed or answered leaves the
service on that one, `microphone` kept; its incoming-call notification is
the application's own. `SipralCallForeground.NOTIFICATION_ID` is the
service's notification id: the sample posts a call ringing alone under it,
so that it is one notification whether or not Android let the service
start. `SipralCallForegroundTest` (`:telecom:testDebugUnitTest`) runs the
order above on a JVM: a pushed call held as `phoneCall` from its
announcement until its INVITE never comes, answered with the microphone
added, cancelled, declined, a second call ringing beside an answered one, a
call ended while its service starts, a start Android refuses, and a
follower cancelled while a call rings.

### Two telecom adapters

The telecom helper puts calls in front of Android's telecom framework in
one of two ways, both over the same `TelecomBridge`, so the SIP side, the
push order above and everything an application builds on the bridge behave
the same whichever carries the calls:

| | `ConnectionService` | Core-Telecom |
|---|---|---|
| Classes | `AndroidTelecomPlatform`, `SipralConnectionService`, a `SipralConnection` per call, the account from `SipralTelecom.registerAccount` | `CoreTelecomPlatform` over Jetpack's `androidx.core:core-telecom` 1.0.1: `CallsManager.addCall`, a `SipralCoreCall` per call over its `CallControlScope` |
| What it drives | a self-managed `ConnectionService`, on every release from Android 8 | the platform's transactional call API from Android 14 (`TelecomManager.addCall`); below that, a `ConnectionService` of Jetpack's own |
| A ringing call's screen | `Connection.onShowIncomingCallUi`, then `IncomingCallUi` | as soon as the call is added, `CoreIncomingCallUi`, which posts a `Notification.CallStyle` within five seconds |
| The framework's hold | `onHold`, held at once (two seconds, or the connection is disconnected) | `onSetInactive`, the call's device let go before the callback returns (five seconds for each callback) |
| The application's answer, hold, resume | `setActive`, `setOnHold` | `answer` (an incoming call's first activation), `setActive`, `setInactive`: transactions the framework may refuse. A call never let go active is ended on both sides, a refused resume holds the SIP call again, a refused hold resumes it |
| The far end's hold | `EVENT_CALL_REMOTELY_HELD` and `_UNHELD` | not shown: the API has no counterpart |
| Call focus | `onConnectionServiceFocusLost` and `Gained` | none; the framework holds a call whose audio it takes |
| Routes and mute | `CallEndpoint` (Android 14+) or `CallAudioState`, `onMuteStateChanged` | `availableEndpoints`, `currentCallEndpoint`, `isMuted`; a choice goes through `requestEndpointChange` |
| How a call ends | the seven `TelecomDisconnect` causes | the four a transactional disconnect takes: busy is sent as `REMOTE`, cancelled and error as `LOCAL`, each with the bridge's own name as the reason `dumpsys telecom` shows |

Either way `SipralTelecom.callRoutes` holds each live call's routes and mute
(`SipralCallRoutes`, which `SipralCallAudio` follows), `SipralCallForeground`
holds the `phoneCall` foreground service with its call-style notification,
which Core-Telecom asks for as well, and `SipralCallService`'s Hang up
reaches the bridge. The helper's AAR depends on Core-Telecom whichever an
application uses, so its manifest also merges in Core-Telecom's own:
Jetpack's `ConnectionService` (used below Android 14), a receiver for the
microphone's mute, `MODIFY_AUDIO_SETTINGS`, and `BLUETOOTH_CONNECT`, a
runtime permission from Android 12 that, granted, lets Core-Telecom name
every connected headset rather than only the active one; the sample does
not ask for it.

**Which to choose.** `SipralTelecomAdapter.preferred(sdk)`, the sample's
"Automatic", is Core-Telecom from Android 14 (API 34) and the
`ConnectionService` below it. From 14 Core-Telecom drives the transactional
API, the one the platform documents for calling applications: API 37
deprecates `PhoneAccount.CAPABILITY_SELF_MANAGED`, the capability the
`ConnectionService` stands on, with "VoIP applications that want to
integrate with the Telecom framework should transition to the new Telecom
VoIP APIs which are wrapped by the CoreTelecom Jetpack Library". Below 14,
Core-Telecom would only put a `ConnectionService` of its own where the
helper's is, and give up call focus and the far end's hold, which the
helper's handles. An application that wants the other one constructs the
other platform; the sample's account screen offers Automatic,
ConnectionService and Core-Telecom, read at Register (and `telecom` in the
debug build's account file). Neither has run on a phone yet: the checklist
below runs both.

**What ran, 22 October 2026.** The sample's debug APK built by
`android.sh --release` from this tree on the lab machine's Docker (every
check passed: `:telecom:testDebugUnitTest` 24 tests, 12 of them
`CoreTelecomPlatformTest`'s, `:sample:testDebugUnitTest` 10; 98 artefacts
on the sample's runtime classpath, every one under a licence `deny.toml`
allows; the telecom AAR's Kotlin metadata 2.2; the release APK 23,795,970
bytes, the bundle 16,021,585, 16 KB aligned), on an `android-36`
`google_apis` arm64-v8a AVD and then an `android-37.0` one, both headless
and `-no-audio`, with Core-Telecom (Automatic on both). The `android-36`
run used the build before the account screen's telecom chips were made to
wrap, its only difference. The Mac's load average was 35 to 40 throughout,
which the times below carry. On `android-36`:

| | What was seen |
|---|---|
| The framework's side | the account `ComponentInfo{org.sipral.sample/org.sipral.sample}` with `Capabilities: SelfManaged TransactOps` and `isCoreTelecomAccount=true` in `dumpsys telecom`; every call created by `TelecomServiceImpl.addCall` (`TSI.aC`), `voip=true`, `self_mng`, capabilities `hld sup_hld`, and moved by transactions (`RequestNewActiveCallTransaction`, `HoldCallTransaction`, `EndCallTransaction`, each `SUCCESS`) |
| A call to `SipralLabAgent` on the Mac, no registrar | `SET_CONNECTING`, `GAINED_FGS_DELEGATION`, `SET_DIALING`, `SET_ACTIVE` 234 ms after the call was created, the setActive transaction completing in 15 ms; 162 ms from the foreground service's start to the 200 OK's confirmation. Hold and Resume from the sample: `SET_HOLD` and `SET_ACTIVE`, media stopping and coming back. A digit read by the agent. Hung up from the sample after 134 s: `SET_DISCONNECTED` `LOCAL`, `DESTROYED` 24 ms later; the agent counted 4,957 packets sent and 4,956 received. A second call, hung up by the agent: `REMOTE` |
| A cellular call over it | `adb emu gsm call`, answered with `KEYCODE_CALL`: the framework's `REQUEST_HOLD (swap to TC@1)`, the sample's audio paused 46 ms later, `SET_HOLD` 1 ms after that and the cellular call `SET_ANSWERED` 11 ms after: the device was let go before the other call had the audio. With the cellular call ended, Resume in the sample: `SET_ACTIVE` and audio back 114 ms later |
| Routes | the emulator offers only Speaker, as under the `ConnectionService`; asking for it went through `requestEndpointChange` and was not refused |
| A simulated push, no INVITE | `SET_RINGING` through the incoming-call transaction 15 ms after the push, the incoming-call notification 148 ms after it, with the template `Notification$CallStyle`, category `call`, two actions; left alone, `MISSED` 20.0 s after the push, when the announcement's window ran out; Decline in the notification, `REJECTED` |
| The lab's Asterisk, `labuser-mobile`, over the VPN | registered; `channel originate` rang the sample 15 ms after the INVITE (`SET_RINGING`); Answer in the notification opened the sample and answered (`SET_ACTIVE` by the answer transaction); Hold and Resume; 4,261 packets sent and 4,254 received when the sample hung up, `LOCAL`. Declined in the sample, `REJECTED`; left ringing until Asterisk gave up after 30 s, `MISSED`; hung up by Asterisk, `REMOTE` |
| A push, then its INVITE | the push naming the caller as Asterisk writes it (`sip:anonymous@anonymous.invalid`), `channel originate` 3.7 s later: one call in the framework (created once, by the push), `call_announced`, answered, hung up |
| The `ConnectionService` on the same build | ConnectionService chosen and Register again: the call created on `ComponentInfo{org.sipral.sample/org.sipral.android.telecom.SipralConnectionService}`, `SET_ACTIVE (active set explicitly for self-managed)`, hold, resume, `LOCAL`, the two accounts registered side by side |

On `android-37.0` (Android 17), the same, and the same account in
`dumpsys telecom` (`SelfManaged TransactOps`): the events said "telecom:
Core-Telecom CallsManager, API 37" at Register. A call to the agent,
`SET_ACTIVE` 943 ms after it was created; Hold, Resume, Speaker asked for;
a cellular call answered over it, the framework's `REQUEST_HOLD`, the
sample's audio paused 206 ms later, `SET_HOLD`, the cellular call answered
134 ms after the pause; resumed once it ended, hung up from the sample
(`LOCAL`, `DESTROYED` 23 ms later by the end-call transaction), the agent
counting 6,168 packets sent and 6,095 received. A simulated push rang 12 ms
after it, its call-style notification 98 ms after it, and went `MISSED`
20.0 s after it. From the lab's Asterisk: an INVITE rang 13 ms after it
arrived; left ringing, `MISSED` when Asterisk gave up; answered in the
notification and hung up by Asterisk, `REMOTE`; a push and its INVITE
3.7 s later, one call in the framework, `call_announced`, declined in the
notification, `REJECTED`, and Asterisk left with no channel.

The first call's first packet from the agent came 4.6 s after the call was
confirmed, and on the lab calls within 0.75 s; nothing in the framework's
log sits in that gap, and it was not looked into further. What the
emulator cannot show: a choice between real routes (earpiece, wired,
Bluetooth, car), and the framework's own answer, disconnect and set-active
requests, which come from a headset, a watch or a car; set-inactive was
seen, from the cellular call.

### What ran on the emulator, 21 October 2026

An `android-36` `google_apis` arm64-v8a AVD, headless, `-no-audio`, on the
Apple-silicon Mac, the sample's debug APK built from this tree. The far end
was voip-demo (FreePBX 16.0.47, Asterisk 18.9), reached from the Mac over
the SCIT VPN: the sample registered as extension 152 over UDP with no STUN
server, and a Sipral client on the Mac (the idiomatic Kotlin layer on the
JVM) registered as 170, to call or be called. Each extension was left
unregistered at the end. The account reached the debug build as a file
written into the application's own storage with `run-as` and read once at
start (`AccountImport`, debug builds only; the release build's reads
nothing), so no password was typed over `adb`, where a keystroke that
misses its field lands in whatever has the focus. The Mac was shared with other work: its load
average is given beside each group of numbers, and the emulator itself
reported system processes not responding above 500.

**Registration and media through two NATs, with no STUN.** The REGISTER,
its 401 and the REGISTER with credentials were answered 200 in about
0.35 s; voip-demo kept the binding the 200 OK names as `10.0.2.16`, and
still reached the phone: its OPTIONS (about once a minute, more often
after a change) and INVITEs
arrived at the phone's socket through the emulator's NAT and the VPN's,
which is FreePBX's NAT handling for an extension (`rewrite_contact`,
`force_rport`) answering to the address the REGISTER came from. Media
flowed both ways from the first second, PCMU, 284 packets received in the
first six seconds, though the phone's `c=` named 10.0.2.16: FreePBX's
`rtp_symmetric` sends to where the phone's RTP comes from. So against a
PBX set up the way FreePBX sets up an extension behind a NAT — which is
what a phone on mobile data meets — nothing on the phone is needed; against
a peer that does not latch, STUN (`SIPRAL_NAT_STUN`) or TURN with ICE is,
as "Through the lab's Asterisk" above shows. No STUN server sits on the VPN
path to voip-demo, so STUN was not tried against it.

**Network changes, mid-call** (152 calling 170, load 595 to 630). The
telecom helper's `SipralNetworkMonitor` follows Android's default network
and calls `networkChanged`; every call the stack then asks to move is
offered on the new address with a re-INVITE (`moveMedia`). Times are from
the `adb` command; "at the far end" is the gap the Mac client measured in
what it received.

| | What happened | Audio back |
|---|---|---|
| Wi-Fi off, mobile data on | Android lost Wi-Fi 1.5 s after the command; 0.2 s later the stack was on the mobile network (`eth0`, 10.0.2.15), re-INVITE 0.2 s after, REGISTER on the same `Call-ID` with the new `Contact` | at the phone after a 1.0 s gap; at the far end 2.0 s after the command (gap 1.2 s) |
| Wi-Fi on again | Android moved the default network 8 s after the command, once Wi-Fi was validated; the call moved with it | gaps of 2.7 s at the phone, 1.0 and 1.8 s at the far end (an interleaved report from Android was taken as a second move; the monitor now pairs each network's kind and address, see below) |
| Mobile data off while on Wi-Fi | nothing: not the default network | no gap |
| Wi-Fi off with mobile data off | no network 2.2 s after the command: `detach`, the registration `unverified`, inbound audio stopped | — |
| Mobile data on | the network 1.3 s after the command, the call moved and the account registered 0.3 s later | at the phone 1.6 s after the command, after 12.7 s without a network; at the far end gap 12.8 s |
| Airplane mode on | no network 3 s after | — |
| Airplane mode off | the mobile network 9.6 s after the command (the emulated radio attaching), audio 0.3 s after that; Wi-Fi joined 3.9 s later and the call moved again without a measurable gap | at the far end after 21.3 s without audio |

Idle, with no call, each move re-registered within 0.3 s of Android
reporting the network. The first Wi-Fi-on above was reported by Android as
Wi-Fi's capabilities with the mobile network's address, for a few
milliseconds, and the stack moved twice; `SipralNetworkMonitor` now keeps
the capabilities and the link properties of one network together and drops
anything left from the previous one. Run again with that in (load 115 to
145): Wi-Fi off moved the call to the mobile network 1.3 s after the
command with a 0.96 s gap at the phone and 1.0 s at the far end; Wi-Fi on
moved it back in one step, 5.6 s after the command, with no gap over
400 ms at either end.

**Process death and a push** (load 340 to 700 unless given). The sample
writes its registration down (`SipralLifecycle`, `SipralKeystoreStore`) on
every acceptance and when it goes to the background, and the simulated push
is `adb shell am broadcast -a org.sipral.sample.SIMULATE_PUSH -n
org.sipral.sample/.PushReceiver --es caller sip:170@<pbx>` (the receiver is
protected by `android.permission.DUMP`, which the shell holds and no
installed application can); `--es call-id <Call-ID>` beside it passes the
held INVITE's `Call-ID` as a push gateway's payload does, and the sample
announces with it (`TelecomBridge.pushArrived(..., callId)`).

| | Push to ringing | Ready |
|---|---|---|
| Killed in the background (`am kill`, after `suspending`) | the stack open 165 ms and the call ringing 1.1 s after the process started | 679 ms after the cold start, 1.82 s after the process started; the REGISTER continued `Call-ID` `4bcf…` at CSeq 16 after 14 |
| Crashed in the foreground (`am crash`) | ringing 1.66 s after the process started | 386 ms after the cold start, 1.93 s after the process started, from the record written on the last acceptance |
| `am force-stop` | delivered all the same, since the shell names the receiver; ringing 1.77 s after the process started | 204 ms after the cold start, 1.90 s after the process started. A real push is another matter: a force-stopped application is not started by broadcasts until the user opens it, and FCM delivers nothing to it either, which an emulator without Play services cannot show |
| Opened by the user after the process had gone | — | 2.58 s after the cold start, 4.39 s after the process started; again at load 52, 2.02 s and 4.40 s |

An `am crash` sent to a frozen process (below) takes effect when the
process is next woken: a push then woke it into the crash, and the push
was lost with it.

**Doze, App Standby and the freezer** (load 130 to 360). What the UDP
socket and the keep-alive do, as measured:

- **In the background with no call, the process is frozen.** Android's
  cached-apps freezer froze the sample ten seconds after it became a
  cached process (`isFrozen=true` in `dumpsys activity processes`), before
  any Doze. A frozen process runs no timer and reads no socket: no refresh,
  no keep-alive, no answer to the PBX's OPTIONS. voip-demo then answered
  calls to 152 with `503 Service Unavailable` within 0.2 s, its OPTIONS
  having gone unanswered.
- **A push wakes it.** The broadcast thawed the frozen process; the
  announce's REGISTER was answered 0.36 s after the push, and an INVITE
  sent five seconds later rang on the screen the push had raised, matched
  to it (C2). The push has to name the caller as the INVITE's `From` will:
  FreePBX writes its own address as the host (`sip:170@<pbx address>`), and
  a push naming the domain instead left the INVITE unmatched, a second
  ringing call, which Telecom refused (`MAX_RINGING_CALLS`) and the bridge
  answered 486.
- **Doze.** Forced (`dumpsys deviceidle force-idle`, unplugged, screen
  off), with the process in the background and not yet frozen, an INVITE
  never reached the application: Doze cuts an idle application's network.
  A temporary allowlist like the one a high-priority FCM message grants
  (`dumpsys deviceidle tempwhitelist`) let the push's REGISTER through in
  0.17 s; a call four seconds later still had 503 from voip-demo, which
  had marked the contact unreachable and had not yet sent the OPTIONS that
  would clear it. With the application on screen (the full-screen intent
  had woken the screen and opened it), calls rang in Doze within 0.8 s.
- **App standby buckets.** `am set-standby-bucket org.sipral.sample
  restricted` (45) did not stop a push's REGISTER (0.36 s); a call ten
  seconds later had 503, the same unreachable contact.
- **Idle in the foreground.** Three minutes with nothing sent but the
  answers to voip-demo's OPTIONS, a call rang at once. Once, after the
  application had been sent to the background, woken by a push and brought
  back, an INVITE was lost 22 seconds after the last OPTIONS had reached the
  phone and the next call had 503; a move to the mobile network, which
  registers from a new mapping, made calls ring again. That was not seen
  again and is not explained from the phone's side; the PBX's view was not
  available. The sample now gives its account a 25-second keep-alive
  (`keepaliveMs`, a double CRLF to the registrar, `docs/06-nat.md`
  "Refresh") for the NATs of mobile networks, which forget a quiet flow
  sooner than this path did; it runs while the process does and never while
  it is frozen or dozing. Its effect was not measured here.

What the documentation should promise, then: **an Android phone is
reachable while the application is on screen or holds a call; in the
background it is reachable only through a push.** A registration does not
stay alive by itself in the background on Android 14 and later — the
freezer stops it within seconds — and Doze stops it on every release since
6.0. With a push gateway in front of the PBX (RFC 8599, "Who sends the
push"), a woken phone is registered within half a second; a PBX that
qualifies its contacts, as FreePBX does, can still answer 503 for the
first seconds after, until its next OPTIONS reaches the phone, which is a
setting of the PBX (`qualify_frequency`) and the gateway's to wait out.

**Audio** (load 50 to 60).

- The microphone refused at the start of a call: the foreground service ran
  as `phoneCall` only, AAudio refused the input stream
  (`AAUDIO_ERROR_INTERNAL`), and RTP went on both ways, silence from the
  phone.
- Refused while the process runs (`pm revoke`): Android killed the process
  ("permissions revoked"), the call with it; the next launch asked again.
- Granted mid-call (`pm grant`): nothing reopened the input by itself; after
  Hold and Resume the engine reopened both roles and `audio_flinger` showed
  an active `VOICE_COMMUNICATION` record client for the sample, and the
  service's types grew to `phoneCall` and `microphone`.
- Audio focus: during the self-managed call the focus stack held no entry
  (the framework holds focus for the call, "C4" above). Another
  application taking focus could not be driven from `adb` on this image;
  it is on the phone checklist.
- The full-screen intent: allowed, a push with the screen off woke the
  screen (`mWakefulness=Awake`); with `appops set org.sipral.sample
  USE_FULL_SCREEN_INTENT deny`, the same push left it asleep and the call
  was a notification, and the Readiness screen said so.

- An incoming call answered at load 170: the engine's microphone open timed
  out (`DEVICE_TIMED_OUT`), recording stopped a second after it started,
  and the far end heard the media clock's silence. At load 68 the same call
  recorded throughout (an active `VOICE_COMMUNICATION` record client), and
  the first audio reached each end 2.3 to 2.4 s after the answer, while
  AAudio opened both streams. The audio probe's limit is what a starved
  emulator crosses; a phone is the measure.

**The diagnostics bundle.** Shared after the mid-call network run: 27,623
bytes, six files, the stack's log pseudonymising every address (the PBX
read as `146.182.29.189` there and as itself in `diagnostics.json`). Shared
again with SIP messages and the diagnostic trace both on, after a
registration and a call (38 whole SIP messages in `stack-log.txt`, real
addresses and numbers, six `Authorization` headers each reduced to
`Authorization: [removed]`). In every bundle, searched with `grep -F` for
each extension's password and for any `Authorization` header with a value,
nothing was found, in any file or in the zip itself.

**With Opus.** `android.sh --release --with-opus` passed the same checks
(the release APK 24,814,250 bytes, the bundle 16,584,235, version
`1.2.3-opus` code 102031, 16 KB aligned), was signed the same way,
installed on the emulator in place of the other, and called the Sipral
client on the Mac directly, with no registrar: Opus was negotiated, and 35
seconds carried 1,458 packets from the phone and 1,483 to it, none lost.
voip-demo offers its extensions no Opus, so the calls through it above were
PCMU.

### On a real Android phone

What only a phone can show, in the order that wastes least time, with what
to expect and what to send back. Every step ends with **Diagnostics →
Share log** sent to the developer, unless it says otherwise; the bundle
holds the timings, so a step needs no stopwatch unless it says so.

Before: the APK or bundle from "Release build" above (or the debug APK for
`adb`), voip-demo test extensions, a second phone or a softphone as the far
end, and `adb` on a computer for the steps that use it.

1. **Install.** From Play internal testing (the `.aab`), or
   `adb install sipral-sample-release.apk`. With the bundle locally:
   `bundletool build-apks --bundle sipral-sample-release.aab --output s.apks
   --ks <upload key> --connected-device && bundletool install-apks --apks s.apks`.
   *Expect:* installs; the launcher shows "Sipral sample". *Send:* phone
   model, Android version, where it was installed from.
2. **Permissions.** Open it. *Expect:* the microphone asked, then
   notifications (Android 13+). Allow both. Readiness tab: every line
   "Ready", except battery optimisation, which is information. Installed
   from Play, "Calls over the lock screen" should read Ready; sideloaded,
   it may not: tap Open the setting and allow it. *Send:* a screenshot of
   the Readiness tab.
3. **Register over UDP, then TCP, then TLS.** The account (extension,
   `host:port` of each transport, `sip:<host>` as the registrar URI),
   Register. *Expect:* "registered" within 2 s on each; the bundle's
   `events.txt` says "ready: N ms". Unregister between transports.
4. **Calls both ways, screen on.** Call the far end, talk for 30 s, hang
   up; have it call the phone, answer, 30 s, hang up from the far end.
   *Expect:* both directions heard; the call's card shows packets rising
   both ways; "call service in the foreground: phoneCall and microphone" in
   the events. *Send:* the bundle, and whether each side heard the other.
5. **Locked phone, incoming.** Lock the phone, wait one minute, call it.
   *Expect:* the screen lights and the call shows over the lock screen
   (full-screen intent); answer, 20 s, hang up. If it does not ring at all,
   that is the freezer and Doze, step 11: note it and go on. *Send:*
   whether it lit the screen, rang as a notification only, or not at all.
6. **A cellular call over ours.** In a call, have a cellular call arrive;
   answer it; end it; resume ours. *Expect:* ours held (the far end hears
   hold), ours resumed with audio both ways. Then reject a cellular call
   during ours. *Send:* the bundle.
7. **Routes.** In one call, switch earpiece, speaker, a wired headset
   (plug it in mid-call), a Bluetooth headset (connect it mid-call), and
   Android Auto if there is a car. *Expect:* the card's route chips follow,
   audio moves with each, and "audio route ..." lines in the events. Press
   the headset's button once: *expect* mute ("audio muted"), or hang-up,
   per the headset. *Send:* the bundle and which route had no audio.
8. **Another application's audio.** In a call, start music in another app.
   *Expect:* the music does not play over the call, or ducks; the call's
   audio stays. *Send:* what was heard.
9. **Wi-Fi to mobile data mid-call.** In a call on Wi-Fi, walk out of
   range or switch Wi-Fi off. *Expect:* "network cellular ...: rebuild",
   "media offered on the new network", "inbound audio back after N ms".
   Time it by ear too: *send* the seconds until the far end was heard
   again, and the bundle. Then back to Wi-Fi.
10. **Battery.** Fully charged, registered, screen off, 30 minutes idle.
    *Send:* Settings → Battery for the app (percentage and time), and
    `adb shell dumpsys batterystats org.sipral.sample > batterystats.txt`.
11. **Doze overnight.** Registered, unplugged, screen off overnight. In the
    morning, before touching it, call it from the far end. *Expect,* with
    no push service (this sample has none): no ring — the freezer and Doze
    stop a background application, as above. Then open the app and call
    again: *expect* a ring. To see the push path instead: `adb shell
    dumpsys deviceidle tempwhitelist -d 10000 org.sipral.sample` and the
    `SIMULATE_PUSH` broadcast above, then the call. *Send:* the bundle and
    what rang.
12. **Process death.** In the background, `adb shell am kill
    org.sipral.sample`, then the `SIMULATE_PUSH` broadcast naming the far
    end as the PBX writes it. *Expect:* ringing within two seconds, "ready:
    N ms after the cold start ... carried on". *Send:* the bundle.
13. **Android 8 (API 26 or 27), if a phone is available.** Steps 1 to 4
    and 7. *Expect:* "audio: AudioRecord and AudioTrack" (no AAudio device
    mode below Android 9), calls heard both ways; no notifications or
    full-screen permission to ask. *Send:* the bundle.
14. **Both telecom adapters** ("Two telecom adapters" above). Steps 4 to 7
    ran on Automatic, which on Android 14 and later is Core-Telecom: the
    events say "telecom: Core-Telecom CallsManager" at Register. During one
    of those calls, `adb shell dumpsys telecom > core-telecom.txt`. Then,
    with a Bluetooth headset and a watch or a car if there is one: answer an
    incoming call from the headset's button (or the watch), hang it up from
    the headset, and with a call active take a cellular call and end it.
    *Expect:* each reaches the call as on screen (answered, ended, held and
    resumed), the far end hears hold, and the headset's name among the
    route chips. Then Telecom: ConnectionService, Register again, and steps
    4 and 6 once more, with `dumpsys telecom > connection-service.txt`.
    *Expect:* the same behaviour; in the first file the call on
    `ComponentInfo{org.sipral.sample/org.sipral.sample}` with
    `TransactOps`, in the second on
    `.../org.sipral.android.telecom.SipralConnectionService`. On an
    Android 13 phone, Core-Telecom chosen by hand runs over Jetpack's own
    `ConnectionService`: steps 4 and 6 with it, if there is one. *Send:*
    the bundle after each adapter, both `dumpsys` files, and anything that
    behaved differently between the two.

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
  Every push the system says must be reported is reported to CallKit ("Through `sipral.h`", above).
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
    few seconds; tap Answer as soon as it shows. The screen says connecting
    until the INVITE arrives, then the call is up with audio both ways; note
    the seconds between the tap and the voice. Once more, tapping Decline at
    once: the other phone hears a decline (603). Without a gateway (the live
    PBX): no ring, which the log after reopening shows as "registrar promised
    nothing". Send: the log.
12. **Thirty minutes idle, registered.** Note the battery percentage,
    lock the phone for 30 minutes, unlock, note it again, place one call.
    Expected: the call works; the log shows the background, the resume and
    the REGISTER that proved the binding. Send: the log and both
    percentages.

## A client certificate whose key never leaves the phone

Some PBXs and SBCs admit a phone only when it presents a certificate their
own authority issued for it, on SIP over TLS (`docs/22-tls.md`, "A client
certificate"). On a phone the private key of that certificate is made by
the platform's key store and never read out of it: the Secure Enclave on
iOS, Android Keystore (the TEE, or StrongBox where the phone has one). The
binding hands the platform an identity and the platform signs the
handshake; nothing in Sipral sees the key.

**Enrolling once.** The key is made on the phone, the authority signs a
certificate for its public half, and the certificate is kept next to the
key:

- iOS: `ClientIdentity.secureEnclaveKey(tag:)` makes a P-256 key in the
  Secure Enclave, kept in the Keychain under the tag (which takes the
  application's keychain entitlement);
  `ClientIdentity.certificateRequest(commonName:privateKey:)` is the PKCS#10
  request for it, signed by the enclave. The certificate the authority
  returns goes into the Keychain with `SecItemAdd`, labelled, and
  `ClientIdentity.keychain(label:)` finds the identity they make together
  before each connection; or `ClientIdentity(certificate:privateKey:)` joins
  them in memory.
- Android: a key made by `KeyPairGenerator` in `"AndroidKeyStore"` under an
  alias, for signing, P-256 with SHA-256; the authority's chain is stored
  over it with `KeyStore.setKeyEntry(alias, key, null, chain)`.
  `SipralClientCertificate.androidKeystore(alias)` presents it, its
  `PrivateKey` the Keystore's handle.

**A phone woken while locked.** The registration a push brings back is made
before the user has touched the phone, so the key has to sign then:

- iOS: `secureEnclaveKey` makes the key usable after the first unlock
  (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`); keep the
  certificate's Keychain item at the same accessibility. A key whose access
  control asks for the user's presence cannot sign in the background.
- Android: a key that requires user authentication cannot sign until the
  user has authenticated within its validity window.

Either way the binding says so rather than failing silently:
`transportFailed` with `clientKeyUnavailable` (Swift) or
`CLIENT_KEY_UNAVAILABLE`, and the connection is tried again on the usual
back-off, so the account registers once the key can sign.

**Renewal.** A certificate out of its dates is never presented: the binding
reads them before connecting and reports `CLIENT_CERTIFICATE_EXPIRED`, with
nothing sent. The application renews it — the same key, a new request — and
the next attempt presents the new one. A server that refuses a valid
certificate, because it was revoked or another authority issued it, is
`CLIENT_CERTIFICATE_REFUSED`; one that wanted a certificate and got none is
`CLIENT_CERTIFICATE_REQUIRED`.

**What has run.** The Swift tests make the key in the Secure Enclave on an
Apple silicon Mac, sign the request with it, and register with it through a
Network.framework registrar that requires a client certificate, at TLS 1.3
and 1.2; a Secure Enclave key that needs the user's presence, on a context
not allowed to ask, is told as the key unavailable. The iOS simulator has no
Secure Enclave, so the same tests use a software key there. The Kotlin
layer's tests run on a JVM, through a `KeyStore` `keytool` makes at test
time: the
Android Keystore path is the same key manager with the Keystore's handle in
it, and has not yet been run on an emulator or a phone, nor has the iOS
path on a real iPhone. `scripts/lab.sh tls` runs the same outcomes against
Asterisk from the Python, Kotlin and .NET agents and through the C ABI
(`docs/22-tls.md`, "A client certificate").

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
(`bindings/dotnet/Sipral.Tests/LifecycleTests.cs`).

**Run from the package, on 21 October 2026.** The same sample, copied out
of the repository and built with `-p:SipralMauiVersion=1.2.3`, which swaps
its project reference for a `PackageReference` to `Sipral.Maui`, restored
from a folder feed holding the `.nupkg` `scripts/package/maui.sh` packed
(and a package folder of its own, so that no other copy of 1.2.3 was
read). The iOS build needs `-p:ValidateXcodeVersion=false` under Xcode 27.1:
the .NET for iOS 27.0.10722 workload asks for Xcode 27.0 exactly. The sample
takes its fields from `SIPRAL_SAMPLE_*` at launch and presses its own
buttons in the order `SIPRAL_SAMPLE_STEPS` gives, and writes every line it
shows to standard output, so one command runs it and its log is the
evidence (the comment at the top of `App.cs` says how):

```sh
# iOS simulator
SIMCTL_CHILD_SIPRAL_SAMPLE_AOR=sip:152@pbx.example.com \
SIMCTL_CHILD_SIPRAL_SAMPLE_SERVER=pbx.example.com:5060 \
SIMCTL_CHILD_SIPRAL_SAMPLE_PASSWORD=... SIMCTL_CHILD_SIPRAL_SAMPLE_TARGET='sip:*43@pbx.example.com' \
SIMCTL_CHILD_SIPRAL_SAMPLE_STEPS='register call' \
xcrun simctl launch --console-pty "$UDID" org.sipral.sample.maui | grep sipral-sample
# Android
adb shell am start -n org.sipral.sample.maui/crc643105ea7c209f525f.MainActivity \
    -e SIPRAL_SAMPLE_AOR sip:152@192.0.2.30 -e SIPRAL_SAMPLE_SERVER 192.0.2.30:5060 \
    -e SIPRAL_SAMPLE_PASSWORD ... -e SIPRAL_SAMPLE_TARGET "'sip:*43@192.0.2.30'" \
    -e SIPRAL_SAMPLE_STEPS "'register call unregister'"
adb logcat -s DOTNET | grep sipral-sample
```

What it showed, on the iOS 26.5 simulator (iPhone 17) and the Android 16
emulator (API 36, arm64-v8a, `-no-audio`), with the stack in device mode:

| | iOS simulator | Android emulator |
|---|---|---|
| The microphone prompt | shown at the first Register ("Sipral would like to access the Microphone", with the `Info.plist` text), screenshot taken; answered with `xcrun simctl privacy grant microphone`, which iOS applies by ending the process, so the run after it started granted | shown ("Allow Sipral to record audio?"), answered by tapping "While using the app" (`adb shell input tap` on the button `uiautomator dump` located); `SipralMicrophone.RequestAsync` returned granted and the step went on |
| A call to `SipralLabAgent` on the Mac, no registrar | G.722 both ways; 645 packets sent and 470 received by the sample when it hung up after 20 s, 0 lost; the agent counted 478 sent and 644 received | G.722; 994 sent and 994 received at the sample's hang-up after 20 s, 0 lost; the agent 997 sent, 992 received |
| A live FreePBX (Asterisk 18.9), extension 152 | registered (named by host name, located through RFC 3263); its echo test `*43` in G.711 µ-law, 764 packets sent and 755 received in 15 s, 0 lost | the same by address (the emulator had no DNS of its own here); registered, `*43` 747 sent and 737 received, 0 lost |
| Into the background (iOS: another application launched; Android: Home) | `registration written down as sample`, then `suspending, 1 binding(s) unverified`, in that order | the same |
| Back (the sample launched again) | `resumed`, the registration proved again: Registering, Registered | the same |
| Background again, the process ended (`simctl terminate`, `am force-stop`), started again | `registration restored from the last run: Restored`, no REGISTER handshake, then Unregister answered: Unregistered | the same |

Both extensions were left with no binding: the last step of each run was
the unregister. Three things in the binding failed on the way, and were
fixed before the runs above:

- `SipralStack.Suspending` and `Resumed` called the library once and threw
  `Busy` when the poll thread held the stack at that moment, which it does
  while a registration is up. Thrown from iOS's `DidEnterBackground`, that
  ended the process on its first move to the background. They now wait for
  the stack as every other entry point of the binding does.
- An account named by `serverUri` was added with the stack's placeholder
  address in its `Contact`, and once located its route was compared with
  an address the location itself had just moved, so the `Contact` was never
  rewritten: the first REGISTER, and every one after it, was refused as
  `UnreachableContact` toward a server off the machine. The account is now
  pointed at the route its server is reached by, and the REGISTER (or the
  unregister) the location released before that is sent again from there.
  The first `RegistrationChanged` still reads `Failed` with
  `UnreachableContact`, about 70 ms before `Registering`.
- The sample itself named no registrar URI and no authentication user, so
  its Register never registered with anything, and read its launch values
  before Android's activity existed.

Still not run: a physical iPhone or Android phone (audio routes, a real
microphone, the system ending a process on its own rather than on a
command, push), the prompt answered by a person's tap on iOS, and the
`armeabi-v7a` and `x86_64` libraries inside a running MAUI application (the
Android 16 arm64 image runs no 32-bit code, and no x86_64 image runs on an
Apple-silicon Mac). A .NET for Android Release build packs only arm64-v8a
and x86_64 unless the application lists `android-arm` among its
`RuntimeIdentifiers`; with
`-p:RuntimeIdentifiers="android-arm64;android-arm;android-x64"` the APK
carried `lib/armeabi-v7a/libsipral_ffi.so` from the package beside the
other two.

## Consuming the packages

What is published, read from the registries on 21 October 2026, and what
was built and launched from them that day, each in a project outside the
repository.

| Artefact | Where | Versions there |
|---|---|---|
| Swift package, default (no Opus) | this repository, root `Package.swift`, over `CSipral.xcframework.zip` among the release's assets | 1.2.0 on, by tag |
| `CSipral-opus.xcframework.zip` | an asset of the releases v1.2.1 and v1.2.3; from 1.3 the root `Package.swift`'s trait `Opus` names it | - |
| `org.sipral:sipral`, `org.sipral:sipral-opus` (AAR) | Maven Central | 1.1.0, 1.2.0 |
| `org.sipral:sipral-jvm`, `org.sipral:sipral-jvm-opus` | Maven Central | 1.1.0, 1.2.0 |
| `org.sipral:sipral-telecom` (the telecom helper) | not published yet; `scripts/package/android.sh` builds it with its POM and sources jar, for Maven Central from 1.3 | - |
| `Sipral.Maui` | NuGet | 1.2.0 |

Opus stays out of the default artefacts on purpose (`docs/05-media.md`,
THIRD-PARTY-NOTICES.md); an application that wants it names the variant.

**SwiftPM, default.** An application adds the repository:

```swift
.package(url: "https://github.com/SIPRAL/sipral", exact: "1.2.3"),
// target: .product(name: "Sipral", package: "sipral")
```

**SwiftPM, with Opus, from 1.3.** The root package has two traits:
`Standard`, the default, over `CSipral.xcframework.zip`, and `Opus`, over
`CSipral-opus.xcframework.zip`. Naming `Opus` turns the default off, so one
library is linked; it needs Swift 6.1 (Xcode 16.3) or later:

```swift
.package(url: "https://github.com/SIPRAL/sipral", exact: "1.3.0", traits: ["Opus"]),
// target: .product(name: "Sipral", package: "sipral")
```

`traits: [.defaults, "Opus"]` would ask for both libraries, and the build
fails with "Multiple commands produce" the same header, module map and
archive. A release declares the
trait only once its Opus zip is among the assets, because SwiftPM refuses a
package that names an archive it cannot fetch, even one no build uses.

**SwiftPM, with Opus, v1.2.1 to v1.2.3.** Those root packages cannot be
pointed at the other zip, so an application that wants Opus carries the
`Sipral` module's sources from the same tag (`bindings/swift/Sources/Sipral`)
in a package of its own, over the Opus zip, whose checksum is the SHA-256
GitHub shows for the asset:

```swift
targets: [
    .binaryTarget(
        name: "CSipral",
        url: "https://github.com/SIPRAL/sipral/releases/download/v1.2.3/CSipral-opus.xcframework.zip",
        checksum: "ced22863aadb4b73bd49183aec3cab2c659c2354dc734236fc7a9945f36376fb"),
    .target(name: "Sipral", dependencies: ["CSipral"], path: "Sources/Sipral"),
]
```

**Gradle.** From Maven Central, 1.2.0 being the newest there:

```kotlin
dependencies {
    implementation("org.sipral:sipral:1.2.0")        // or org.sipral:sipral-opus:1.2.0
}
```

For a version Central does not have, `scripts/package/android.sh --out DIR`
writes `DIR/maven`, a local Maven repository with `org.sipral:sipral` and
its POM (kotlinx-coroutines as its dependency), named in
`dependencyResolutionManagement` as `maven { url = uri("DIR/maven") }`. The
telecom helper is in the same repository, as `org.sipral:sipral-telecom`,
whose POM names `org.sipral:sipral`, `kotlinx-coroutines-android` and
`androidx.core:core-telecom`; an application on the Opus AAR leaves the
default one out:

```kotlin
implementation("org.sipral:sipral-telecom:1.3.0")
// with Opus instead:
implementation("org.sipral:sipral-opus:1.3.0")
implementation("org.sipral:sipral-telecom:1.3.0") { exclude(group = "org.sipral", module = "sipral") }
```

Its classes are compiled as Kotlin 2.2, like `sipral.aar`'s, so an
application on Android Gradle Plugin 9.4's built-in Kotlin (2.2) compiles
against both; `android.sh` reads the helper's Kotlin metadata to hold it to
that. Up to 1.2.3 the helper was compiled by Kotlin 2.4 and taken as a file
(`implementation(files("libs/sipral-telecom.aar"))`, with
`kotlinx-coroutines-android` beside it), and such an application had to add
`id("org.jetbrains.kotlin.android") version "2.4.21" apply false` to its
root `plugins`.

What ran from them:

| Consumer | Built from | Launched on | It printed |
|---|---|---|---|
| A UIKit application, `swift build` for `arm64-apple-ios15.0-simulator` and wrapped as an `.app` | the repository at 1.2.3 by URL (SwiftPM fetched the release's zip and checked its checksum) | the iOS 26.5 simulator | 6 codecs, features `0x1ffffbf`, a stack opened on 127.0.0.1 |
| the same | the XCFramework `scripts/package/xcframework.sh --dry-run` built from this tree, through the `spm/Package.swift` it prints | the same | the same |
| the same | the Opus package above | the same | 7 codecs, features `0x1ffffff` |
| An Android application, AGP 9.4.1 | `org.sipral:sipral:1.2.3` from the local repository `android.sh` wrote, its POM pulling in kotlinx-coroutines; then `sipral-telecom.aar` as a file | the Android 16 emulator, arm64-v8a | ABI 1.2.0, 6 codecs, features `0x1ffffbf`; with the helper, `SipralConnectionService` resolved and `MANAGE_OWN_CALLS` merged and granted |
| `samples/Sipral.Sample.Maui` | `Sipral.Maui.1.2.3.nupkg` from a folder feed | both | the calls and registrations above |

## 32-bit ARM, under emulation

The Android packages carry `armeabi-v7a`, which no available emulator runs:
the arm64 Android 16 image has no 32-bit userspace. The library's own test
suites were run instead for `armv7-unknown-linux-gnueabihf` (the same
32-bit ARMv7 with hardware floating point, on glibc rather than Bionic) on
the Linux lab machine, cross-compiled with Debian's `gcc-arm-linux-gnueabihf`
and run by `qemu-arm` from `qemu-user` 10.0, named as cargo's `runner` in a
`.cargo/config.toml` beside the checkout (`binfmt` was not registered):

```toml
[target.armv7-unknown-linux-gnueabihf]
linker = "arm-linux-gnueabihf-gcc"
runner = ["qemu-arm", "-L", "/usr/arm-linux-gnueabihf"]

[env]
CC_armv7_unknown_linux_gnueabihf = "arm-linux-gnueabihf-gcc"
AR_armv7_unknown_linux_gnueabihf = "arm-linux-gnueabihf-ar"
# armeabi-v7a, as the NDK builds it, has NEON; Debian's armhf leaves it off
CFLAGS_armv7_unknown_linux_gnueabihf = "-mfpu=neon"
```

then `cargo test --target armv7-unknown-linux-gnueabihf --no-fail-fast`
over `sipral-core`, `sipral-ua`, `sipral-rtp`, `sipral-media`, `sipral`,
`sipral-ffi`, `sipral-dtls`, `sipral-nat`, `sipral-audio`, `sipral-stir`,
`sipral-headless`, `sipral-io-common` and `sipral-diag`, with Opus. On 21
October 2026: `sipral-core` 1,030 and its RFC corpora 42, `sipral-ua` 937,
`sipral-rtp` 466, `sipral-media` 490 (33 ignored, as on 64-bit) and its
allocation test, `sipral` 574 and its bridges 12, `sipral-ffi` 751 of 752 (the
one below) and its memory endurance test, `sipral-dtls` 190, `sipral-nat` 348, `sipral-stir`
137, `sipral-audio` 58, `sipral-headless` 103, `sipral-io-common` 34,
`sipral-diag` 45 passed. What failed, and why:

- `sipral-ffi`'s tests did not compile: three read a C string through
  `i8`, which `c_char` is on x86_64 and on Apple's arm64, and is not on ARM
  Linux or Android, where it is `u8`. Test code only; the library itself
  built. They now read it whatever its sign.
- `robust::every_feature_this_build_lacks_is_refused_where_it_is_asked_for_never_ignored`
  failed on any Linux, x86_64 as much as ARM: it asked for device mode with
  the value 2, which names nothing, and was answered `InvalidArgument`; and
  device mode without its transmit callback was refused for the callback
  before the missing backend. It asks with `SIPRAL_AUDIO_DEVICE` now, and a
  build with no audio backend answers `NOT_SUPPORTED` first, as the header
  says.
- Two timing budgets, under emulation and a debug build:
  `a_slow_device_does_not_hold_the_poll_that_starts_the_call` (the call came
  up in 0.94 to 1.04 s against a budget of 0.8 s, with the device's open
  held for 1.5 s, so it did not wait for the device; alone, it passed three
  times out of three) and `signalling_load`'s hundred calls (3.6 s per call
  to set up, against the budget for native code). That load test measured a
  live call at 47,285 bytes here, signalling 13,346 and media 33,963.

Nothing showed a `usize` or `u64` truncation, an atomic the target lacks or
a misaligned read. What this does not cover: Bionic, Android's dynamic
linker, AAudio and JNI on a 32-bit phone, and timing on real hardware.
`x86_64` Android is covered no further than the gate's own x86_64 Linux
runs of the same tests, which say nothing of Bionic or an x86_64 Android
device; no x86_64 Android image runs on an Apple-silicon Mac.
