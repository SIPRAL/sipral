<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Roadmap

Phases are defined by their exit criterion, not by a date. A phase ends when
the criterion is demonstrated, in the test suite or against real equipment.

What each phase contains is ordered against `docs/13-client-requirements.md`,
which is what a softphone in production asks of an engine. Items below are
tagged with the requirement they answer, so that a phase can be read as a list
of things somebody is waiting for rather than a list of things that sounded
interesting.

## Phase 0 — design

**In:** design documents per crate, the RFC index, the clean-room rules, the
licensing set, the workspace skeleton, the check script, the RFC 4475 corpus,
the public API
surface of `sipral-core` agreed on paper, and the capture fixtures from the lab
PBX.

**Exit:** every state machine in `03-core-signalling.md` can be explained from
the RFC alone, with no other implementation's source ever having been opened.

**Done.**

## Phase 1 — signalling

`sipral-core` and `sipral-ua`, plus the smallest media slice that lets a call
be heard: RTP send and receive in `sipral-rtp` with a fixed-depth buffer, and
G.711 in `sipral-media`. The adaptive buffer, loss concealment, Opus, SRTP and
everything else in those two crates stay in phase 2. UDP, TCP and TLS. Digest
with MD5 and SHA-256. REGISTER with refresh, INVITE and BYE, SDP offer/answer,
session timers, PRACK, REFER for blind and attended transfer.

**Status: written, and five of the six exit criteria met.** Every line of the
phase is in the tree — `sipral-core`, `sipral-ua`, `sipral-rtp` and
`sipral-media` — and five flows run against two servers whenever
`scripts/lab.sh` is run. What is left is one paid carrier account.

The criteria are demonstrations rather than code, and they earned their place
on the first day they ran: a call a PBX challenges was acknowledged and then
abandoned, because the lab's proxy never challenges one and so nothing in the
unit suite had ever asked.

**Exit, all of them:**

- **met** — registration and a bidirectional call through the lab Kamailio and
  FreeSWITCH, with hold and resume, judged against conditions written before
  the run;
- **met** — the same against Asterisk with `chan_pjsip` at defaults, in a
  container, with no proxy in front of it;
- the same against at least one real carrier, on a paid account;
- **met** — the RFC 4475 torture corpus passes: valid messages parsed, invalid
  messages rejected without a panic;
- **met** — the parser survives a continuous fuzzing run without a crash or a
  hang;
- **met** — blind and attended transfer complete against both FreeSWITCH and
  Asterisk.

## Phase 2 — media, and the things that get more expensive by waiting

`sipral-rtp`, `sipral-media`, `sipral-nat`, `sipral-io-coreaudio`. Adaptive
jitter buffer, loss concealment, Opus, SRTP, DTMF, echo cancellation attached,
STUN and TURN.

Three groups join it from `13-client-requirements.md`, for one reason each.

**The guarantees the architecture already almost provides.** Cheap now,
and every one of them is something a client is entitled to assume:

- **D9** — no clock read anywhere in the core, stated and tested. `D2` depends
  on it, so it goes first.
- **B4** — the threading contract documented and tested; a violation is an
  error and never a fault.
- **B3** — no network failure terminates the process, with the boundary of the
  guarantee written down rather than implied.
- **A6, D3** — the statistics the jitter buffer already computes reach the
  application, and the counters beside them.
- **D8, B2** — a build says what it supports, and no setting can be accepted
  and ignored.

**The things whose cost rises with every week they wait.**

- **B7** — one source of truth for the ABI, with the bindings generated from
  it and `scripts/check.sh` failing when one is missing. Cheapest before three
  bindings exist, which is now.
- **D1** — the call's diagnostic record. Every decision site written before it
  exists is a site to revisit afterwards.
- **D2** — deterministic replay, which the sans-I/O core makes nearly free and
  which turns every later field failure into a permanent test.

**The media and transport work the phase was already about**, plus what
production says is missing from it:

- **B1** — the path size limit as a constraint: promotion to a stream
  transport or a specific refusal, never a silent send, per RFC 3261 §18.1.1,
  with the on-wire size readable by the application.
- **B5** — a media stall detected by the engine and reported, with an optional
  recovery attempt.
- **B6** — a documented default profile for the deployment actually shipped
  against, made the default.
- **D10** — the impairment profiles as fixtures in the repository, including a
  link that disappears for eight seconds.

**And one piece of signalling that does not belong to media at all**, but is
P0 for phase 3 and is sized like a phase of its own:

- **A1** — the subscription machine (RFC 6665) and `dialog-info+xml`
  (RFC 4235), with bulk operations and with the REFER subscription expressed
  as the special case it is.

**Exit:**

- mean opinion score at parity with a reference stack, measured on the same
  `tc netem` impairment profiles, committed with the tests;
- DTMF recognised by the lab PBX and by a carrier IVR;
- SRTP interoperating in both SDES and DTLS-SRTP;
- a call held open for an hour with no drift-induced underrun;
- echo cancellation good enough for a speakerphone call in a normal room —
  which on Apple and Windows means the platform's own, reached through the
  device crate, and elsewhere means a component attached at the seam
  `docs/05-media.md` describes, with the render-to-capture delay reported by
  the device rather than guessed;
- a busy-lamp-field subscription to thirty extensions survives a network
  change and reports every state transition, including its own termination
  and the reason;
- a session recorded in the lab replays deterministically and is committed as
  a test;
- a request too large for the path is promoted or refused, never emitted, and
  the decision is visible without a capture.

## Phase 3 — desktop replacement

`sipral-ffi`, the Swift Package, `sipral-io-wasapi`, the NuGet package — and
the parity surface a desktop client needs on the day it switches engines.

- **A2, A3** — device enumeration with an identity that survives replug,
  selection per call, gain, mute and a peak level cheap enough for a meter.
- **A5** — call recording: the mixed conversation to one file, started and
  stopped mid-call.
- **A4, D5** — codec enumeration and priority, and the engine explaining what
  it negotiated and why the other candidates lost.
- **A7, D4** — the network-change entry point and the lifecycle model behind
  it, with tests that suspend and resume under adverse conditions.
- **A8, D7** — refusing an unwanted INVITE before any user-visible effect,
  with rate limiting and counters.
- **A9, A10** — DTMF over INFO, settable product identity, and the signalling
  trace that D1 mostly supersedes.
- **D6** — device, codec and transport as properties of a call rather than of
  the process.

**Exit:** the existing desktop softphone clients run on Sipral, and the previous
stack is gone from both binaries.

## Phase 4 — mobile

`sipral-io-aaudio` and the AAR. `CallKit` and `PushKit` on iOS,
`ConnectionService` and foreground services on Android.

- **C2** — a call announced out of band: the engine pre-warms, matches the
  INVITE that follows to the announcement, and reports an announced call that
  never arrived. The three races are part of the requirement.
- **C3** — registration that can be frozen and thawed, time-to-ready measured
  by the stack, and RFC 8599 push parameters.
- **C4** — the audio device taken away and given back during a live call,
  survived unaided, every transition reported.
- **C5** — an idle cost that is explicit, measurable, and reducible to nothing.
- **C1, D4** — and behind all of them, the lifecycle model, because a phone is
  where its absence is fatal rather than merely expensive.

**Exit:** applications accepted in both stores, incoming calls waking the app
reliably from the background, and Bluetooth hands-free transitions surviving a
call.

## Phase 5 — headless and SDK

`sipral-headless`, packaging, public documentation, published packages.

**Exit:** an external developer integrates Sipral from the published
documentation without asking a question that the documentation should have
answered.

## Where this gets abandoned

Phases 1 and 2. If signalling interoperability or audio quality cannot be
reached, the sunk cost is a few months and the answer is to stop.

After phase 3 the project has already paid for itself, because the licensing
exposure it removes is the reason it exists, independently of anything sold
later.

## Ordering constraints

- The repository stays private until the phase 1 exit criteria are met. Then
  visibility is flipped in place. The history is never copied into a new
  repository, because the history is the clean-room evidence.
- Before that flip: private captures confirmed out of the tree, `gitleaks` clean
  over the whole history, and the licence set, SPDX headers and `cargo deny`
  in place, which they are from commit zero.
- No crate is published to a registry before the ABI in `08-ffi.md` is frozen.
  A published crate name is a promise about compatibility. The one exception
  is the `sipral` name reservation, a placeholder that exports a version
  constant and promises nothing.
