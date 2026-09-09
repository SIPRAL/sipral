<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Roadmap

Phases are defined by their exit criterion, not by a date. A phase ends when
the criterion is demonstrated, in the test suite or against real equipment.

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

## Phase 2 — media

`sipral-rtp`, `sipral-media`, `sipral-nat`, and `sipral-io-coreaudio`. Adaptive
jitter buffer, loss concealment, Opus, SRTP, DTMF, echo cancellation attached,
STUN and TURN.

**Exit:**

- mean opinion score at parity with a reference stack, measured on the same
  `tc netem` impairment profiles, committed with the tests;
- DTMF recognised by the lab PBX and by a carrier IVR;
- SRTP interoperating in both SDES and DTLS-SRTP;
- a call held open for an hour with no drift-induced underrun;
- echo cancellation good enough for a speakerphone call in a normal room.

## Phase 3 — desktop replacement

`sipral-ffi`, the Swift Package, `sipral-io-wasapi`, the NuGet package.

**Exit:** the existing desktop softphone clients run on Sipral, and the previous
stack is gone from both binaries.

## Phase 4 — mobile

`sipral-io-aaudio` and the AAR. `CallKit` and `PushKit` on iOS,
`ConnectionService` and foreground services on Android.

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
