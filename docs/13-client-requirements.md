<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# 13 — What a production softphone asks of this stack

`docs/10-roadmap.md` says phase 3 is a desktop softphone running on Sipral with
the previous engine gone from the binary. This document is the other half of
that sentence: what such a client actually needs, written from operating one in
production rather than from imagining one.

Every item here is here because its absence cost something measurable. That is
the only admission criterion. Where a number appears it was measured on
equipment we control and is reproducible on ours.

Two things this document deliberately does not do. It does not describe, name
or characterise any other implementation — `docs/02-clean-room.md` makes the
provenance of this stack a business condition, and a requirement is a statement
about Sipral, not about anybody else's code. And it does not restate the
roadmap: the phases stay where they are, but their contents are ordered against
this list.

## How to read the priorities

| | Meaning |
|---|---|
| **P0** | A desktop client cannot run on Sipral without it. Blocks phase 3. |
| **P1** | A mobile client cannot ship without it. Blocks phase 4. |
| **P2** | Nothing in this field has it. It changes how the product is built and supported. |

P2 is not padding. The whole argument for owning an engine is that the
expensive problems are the ones no engine solves, and they are expensive
precisely because everybody re-solves them badly, one application at a time.

---

## A — Parity: what a desktop client needs on day one

### A1 · Subscriptions and busy-lamp-field · P0

The largest single piece of protocol still missing. A subscription dialog with
refresh, expiry and re-subscription after failure (RFC 6665), carrying
`application/dialog-info+xml` (RFC 4235) parsed into state an application can
render. Per-subscription state is an event, including termination *and its
reason*.

Two properties are requirements in their own right, not implementation detail:

- **A subscription whose initial request fails — dead transport, name
  resolution gone, an interface that changed underneath — reports an event.**
  It never leaves the stack in a state from which the process can be
  terminated. See B3; these are the same problem.
- **Bulk operations.** Subscribing to thirty extensions must not be thirty
  serialised round trips on start-up, because that is a visible stall on every
  launch.

The REFER subscription in `sipral-ua` is the same shape and predates this. It
is a special case of the general machine and should end up expressed as one,
not maintained beside it.

### A2 · Audio devices on desktop · P0

The core has no device in it and that is correct for a phone, where the
operating system owns routing. On a desktop it is inverted: choosing the
headset *is* a feature, with its own screen and its own long tail.

- Enumeration with an identity that **survives unplug and replug**. A name is
  not an identity; two identical headsets are a real configuration.
- Selection **per call**, not per process — see D6.
- An event when the device set changes, and when the device in use disappears
  mid-call, with a defined fallback rather than silence.
- Re-application of a saved selection after the operating system resets it.
  Docking stations and some headset firmware change the default device behind
  the application's back.

### A3 · Volume, mute, level metering · P0

Input and output gain, mute, and a peak level cheap enough to poll at the frame
rate of a user interface. Used on every call.

### A4 · Codec enumeration and priority · P0

List what this build actually contains, set the order, and report what a live
call negotiated. A fixed order is not sufficient: this is configured per site.
The reporting half is D5.

### A5 · Call recording · P0

The mixed conversation to a file, started and stopped mid-call, both directions
in one file, in a format that plays without conversion.

Recording is neither protocol nor device, and pretending it belongs to either
is how it ends up in both. It is a tap on the media path with a file writer
behind it, and it is specified as such.

### A6 · Stream statistics · P0

Loss, jitter, round-trip time and a quality score, sampled during the call and
available when it ends. Two consumers with different needs: a live indicator
that must be cheap, and an end-of-call record that must be complete. The
jitter buffer already computes most of this; the requirement is that it reaches
the application.

### A7 · Network change and recovery · P0

An explicit entry point for "the network changed" and a documented recovery
ladder behind it. Wi-Fi to cable, a VPN coming up, a VPN going down, sleep and
wake. The general form is D4.

### A8 · Refusing an unwanted INVITE before it is visible · P0

Scanners dial common extension numbers at every hour. A policy hook runs
**before any user-visible effect** — before ringing, before an event is emitted
— and may refuse with a chosen status code. Rate limiting and counters for what
was refused are D7.

### A9 · DTMF over INFO · P0

Both forms, selectable per send, because some peers accept only the second.

### A10 · Product identity and a signalling trace · P0

A settable `User-Agent`, and a trace of SIP messages that can be switched on and
**attached to a bug report by somebody who does not read SIP**. D1 is the better
version of this and supersedes most of it.

---

## B — Requirements that exist because of failures

Each of these describes a class of failure that has actually occurred in
production. They are stated as properties Sipral must have.

### B1 · Never emit a request that cannot arrive · P0

**The failure.** An authenticated request measured 1785 bytes on the wire and
fragmented on a 1500-byte path. The NAT in front could not translate a
non-initial fragment, so it was dropped and the far end never saw it. Six
retransmissions, a 32-second timeout, no error anywhere. The unauthenticated
attempt was 308 bytes smaller, fitted one datagram, and was answered — which is
why the symptom read as "authentication is broken" for two days. Optional
NAT-traversal attributes accounted for 405 of those bytes and bought nothing,
because the peer did not speak that protocol at all.

**The requirement.** The effective size limit of the path is a constraint the
stack holds, not a hope:

- A request that would exceed it is promoted to a stream transport or refused
  with a specific reason. It is never emitted silently. RFC 3261 §18.1.1
  already requires exactly this and names the threshold; the implementation
  follows the RFC rather than inventing one.
- The choice is an event carrying both sizes.
- **The on-wire byte size of every request is readable by the application
  without a packet capture.** A log line reading "request 1785 bytes, path
  limit 1500" turns two days into an afternoon.
- An optional mechanism that inflates a request is off unless it can be shown
  to help this peer, and enabling it reports what it costs in bytes.

### B2 · A silently ignored setting is worse than an unsupported one · P0

**The failure.** A setting with a working control, saved to disk, plumbed
through the application, accepted by the engine without complaint — and
ignored, because a neighbouring value disabled the subsystem it belonged to.
The control was dead for months and nobody could tell from either side.

**The requirement.** Every configuration entry point answers with exactly one
of three things, and says which:

- **applied**, and the effective value reads back;
- **rejected**, with a reason;
- **not supported in this build**, as a distinct machine-readable answer.

"Accepted and ignored" is not representable. Where a value is only meaningful
in combination with another, the invalid combination is an error where it is
set, not silence where it is used.

### B3 · A failure during suspend or resume is an event, not an abort · P0

**The failure.** The worst recurring crash of a production softphone fires
during wake-from-sleep or a network change, on a background timer, while
subscriptions are being refreshed over a transport that is no longer alive. In
one shape the machine had lost name resolution while asleep and a cached
registration still read as valid, so no amount of "are we registered?" checking
could have prevented it. The process terminated. On a desktop that is a crash
report; on a phone it is an application the operating system stops trusting.

**The requirement.** No failure of a network operation may terminate the
process. Not on a background timer, not on a dead transport, not during
suspend, not when name resolution has gone. Each is an event with a reason
code.

This is the strongest single argument for writing the stack in Rust, and it is
worth nothing unless it is stated and tested as a guarantee. The workspace
already denies `unsafe` outside the FFI and device crates, and denies panics,
unwrapping and unchecked indexing through the gate. That is the mechanism. The
guarantee is the mechanism plus the tests that prove it holds where it matters,
and an explicit statement of what it does **not** cover.

### B4 · The threading contract is a guarantee, not a convention · P0

**The failure.** A call into an engine from a thread it did not know about
produced a process-level fault that no handler could catch. The rule existed in
documentation; nothing enforced it, and the failure gave no clue which rule had
been broken.

**The requirement.** Sipral is polled rather than callback-driven, which
retires this class of failure outright. Make it explicit:

- document, and test, which functions may be called from any thread;
- a violation returns an error and never faults the process;
- no callback is ever delivered from a thread the caller did not provide.

### B5 · Media that has stopped is detected by the engine · P0

**The failure.** Calls where signalling stayed healthy and audio simply
stopped. Inbound RTP frozen, both parties silent, neither hanging up, because
to the signalling layer the call was still up.

**The requirement.** The engine watches its own media and reports a stall as an
event, with a configurable threshold and an optional recovery attempt. Every
application otherwise builds this watchdog, and each one discovers the need the
same way: from a complaint.

### B6 · Defaults chosen for the equipment actually deployed against · P1

**The failure.** NAT-traversal features that are correct in general were
harmful against the deployment they were enabled for, an Asterisk-family PBX
behind consumer NAT: they inflated requests past the fragmentation threshold
(B1) and published an address discovered through a third party that a
symmetric NAT had already invalidated. Turning them off made calls work.

**The requirement.** A documented default profile for the common case — an
Asterisk-family PBX behind consumer NAT, which learns the real address from the
media it receives — and that profile is the default. A mechanism useful only
against a peer that supports it is negotiated or detected, never assumed. The
byte cost of each optional mechanism is documented next to it.

### B7 · Adding a function cannot leave a platform behind · P0

**The failure.** A C seam declared in three places that must agree. Adding a
function and forgetting one of them produced a build that compiled and failed
at run time, on one platform, in the field.

**The requirement.** One source of truth for the ABI, with the Swift, Kotlin
and .NET bindings generated from it. Adding a function on the Rust side and
forgetting a binding is a **failure of `scripts/check.sh`**, on every platform,
not a surprise on one.

There is no CI and there will not be one: a runner that builds, signs or
publishes needs credentials on machines that are not ours, and for Apple
signing it cannot work at all, because a runner has no keychain. The gate is
`scripts/check.sh` and it runs where the keys already are. That is where this
check belongs.

The timing is fortunate. There is no generated header yet and the .NET binding
is a name reservation, so this is designed before three bindings exist rather
than retrofitted across them.

---

## C — What a client on a device that sleeps needs

Phase 4. This is where existing engines help least, because they were designed
for machines that stay awake.

### C1 · A stack that knows the device sleeps · P1

The platform rules are absolute. A VoIP wake-up must raise the system call
screen in the same run loop, with no delay and no exceptions; an application
that fails stops receiving wake-ups and is terminated. The consequence for an
engine is one sentence, and everything else in this section follows from it:
**the application must present a ringing call before the network session
exists.**

### C2 · Accepting a call announced out of band · P1

The novel requirement.

A push notification says who is calling and on which account *before* there is
a transport and possibly before registration. The application tells the engine:

> A call is expected on this account, from this caller, announced at this
> instant. Get ready.

and the engine:

- pre-warms the transport and refreshes the registration on the fastest path
  available;
- **matches the INVITE that subsequently arrives to that announcement**, so the
  application can attach the call screen it has already raised to the real call
  instead of treating it as a second one;
- reports, as its own event, that **an announced call never arrived** — not an
  error, a diagnosis, and one that will be needed constantly while a wake-up
  chain is being tuned.

Three races are part of the requirement, not exceptions to it: the call
cancelled before the application woke, two calls in quick succession, and the
INVITE arriving before the push.

### C3 · Registration that freezes and thaws · P1

- Registration state that can be persisted and restored, so that a cold start
  does not always pay for a full handshake.
- **Time-to-ready from cold, measured and exposed by the stack.** That number
  is a product requirement, not a curiosity: it decides how long a queue rings
  each agent before skipping a sleeping phone.
- Push parameters on registration per RFC 8599 (`pn-provider`, `pn-prid`,
  `pn-param`). Peers that act on them are not yet common; a release should not
  be needed on the day one does.

### C4 · Audio that survives the platform's own interruptions · P1

The device is taken away and given back during a live call — by the network's
own call, by a Bluetooth device connecting mid-sentence, by a car taking over
routing, by the operating system reclaiming the session. The engine survives
each of these unaided and reports every transition. Rare on a desktop, daily on
a phone.

### C5 · Cheap when idle · P1

A polled architecture suits a phone only if the polling can become cheap or
stop entirely while the application is backgrounded with no call. What runs,
how often, and what may be stopped without losing correctness are documented
and measurable.

---

## D — What nothing has

### D1 · A call's story as a structured object · P2, and the highest value here

**The problem.** "The call failed" is diagnosed today by obtaining a text log —
often megabytes — from somebody who does not read logs, correlating timestamps
by eye, and inferring what the stack decided. The expensive support incidents
are long for this reason, not because the bug is hard.

**The requirement.** Every call carries a diagnostic record: an ordered list of
the decisions the stack made, each entry carrying

- a **stable machine-readable reason code** — not a string, not a number that
  moves between versions;
- the wire event that caused it, where there was one;
- a monotonic timestamp;
- the sizes and addresses involved.

Readable at any point during the call, returned on failure, serialising to
JSON, attached to a bug report unchanged.

Most of this is recording decisions that are already made and already named.
The work is in making the naming stable and the memory bounded, not in finding
the decisions.

**If one thing in this document gets built, it is this one.**

### D2 · Deterministic replay · P2

**The problem.** The hardest failures happen on one PBX, on one carrier, behind
one NAT, and do not reproduce in a lab. They are fixed by reasoning about
captures, shipping a guess, and waiting.

**The requirement.** A recorded-session format holding the inbound wire
messages, their timing and the clock, and a replay mode that feeds them back
deterministically. Two consequences: a failure captured in the field becomes a
permanent test, and a fix is proven against the exact conditions that produced
the bug — which is the standard this project already holds itself to, since a
fix must be shown to bite by failing without it.

The sans-I/O core is what makes this nearly free, and it is the reason to build
it here rather than wish for it elsewhere. The format is a public, versioned
artefact that support engineers can send, and it **never contains audio** —
enforced by its structure, not by discipline.

### D3 · Health counters, sampled rather than grepped · P2

A flat set of counters and gauges readable at any moment and shippable as
telemetry: registrations attempted, succeeded and failed **by reason**; calls
by disposition; retransmissions; media gaps; jitter-buffer events; transport
promotions. "Is this deployment healthy?" should not be answered by searching
text.

### D4 · A lifecycle model for a machine that suspends · P0 desktop, P1 mobile

The general form of A7, B3 and C4, and its own design problem because this is
where the worst failures live. First-class, documented, tested states:

- **`suspending`** — entered from an operating-system notification, on a hard
  deadline: the process is suspended shortly after and nothing waits for us.
  Everything reachable from here is synchronous and bounded.
- **`resumed`** — arbitrary time has passed and every transport may be dead.
- **`network_changed(from, to)`** — with enough detail to choose between
  re-registering and rebuilding.
- **`interface_lost`** and **`name_resolution_lost`** — distinct states,
  because they need different recovery.

Each with a documented recovery ladder, and — the part that is usually missing
— **tests that suspend and resume the stack under adverse conditions**, not
only unit tests of the path where everything works.

### D5 · The engine explains its negotiations · P2

Per call: the codec chosen **and why each other candidate was not**; the
transport chosen and why; the NAT strategy chosen and on what evidence. This
also makes B6 self-documenting — a wrong default becomes visible instead of
being inferred from a capture.

### D6 · Per call, not per process · P2

Audio device, codec preference and transport are properties of a call. Every
piece of global mutable state in an engine becomes a race in an application
with two calls up, which is what an attended transfer is. Sipral has the
chance not to have this problem rather than to document it.

### D7 · Abuse resistance below the application · P1

A8's policy hook, plus rate limiting per source, plus counters for what was
refused. Every softphone reachable from the internet needs this and every one
builds it separately.

### D8 · Honest capability reporting · P0

One machine-readable answer to "what does this build support?" — codecs
compiled in, transports available, features present — so that an application
can disable what is genuinely absent instead of shipping a control that does
nothing. This is B2 seen from the outside.

### D9 · Time is injectable · P2

No direct clock reads in the core, so that timers are driven deterministically
by tests and a retransmission schedule is verified rather than waited for. The
sans-I/O design already implies it; the requirement is that it be a stated,
tested guarantee, because D2 depends on it.

### D10 · Impairment as a first-class test target · P2

The `tc netem` profiles the roadmap commits to live in the repository as
fixtures, and include the shapes actually seen in the field rather than the
ones easiest to simulate: a mobile leg losing two per cent in bursts, a
satellite-latency carrier, and a link that disappears for eight seconds and
comes back. The last is the shape of every report that says the call froze.

---

## What this changes in the roadmap

Phases stay as `docs/10-roadmap.md` defines them. What changes is what each
one contains and in what order.

**Two items move earlier than their phase would suggest**, because their cost
rises the longer they wait:

- **B7** — the ABI's single source of truth. It is cheapest before three
  bindings exist, and it is nearly free today.
- **D1** — the diagnostic record. Every decision site added before it exists is
  a site that has to be revisited afterwards.

**One item is larger than its position suggests.** A1 is a subscription state
machine and a document format, and it is P0 for phase 3 while being signalling
work in a phase about media. It is sized accordingly rather than assumed to
fit.

**Several are closer to done than they look**, and the ordering reflects that:
D9 and B4 are properties the architecture already has and that need stating and
testing; A6 exists in the jitter buffer and needs to travel upwards; D6 is how
the code is already shaped.
