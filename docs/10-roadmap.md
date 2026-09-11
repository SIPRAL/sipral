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
and the public API surface of `sipral-core` agreed on paper.

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

**Status: written, and four of the eight exit criteria met.** Every line of the
phase is in the tree — `sipral-core`, `sipral-ua`, `sipral-rtp` and
`sipral-media` — and five flows run against three servers whenever
`scripts/lab.sh` is run. What is left is one paid carrier account, the 24-hour
fuzzing run, and the two criteria added after the tree was read end to end: the
lab drove the stack through a media join written for the lab, not through the
one an application links, so what it proved was the harness. A phase whose
proof runs on a path no customer uses has not exited.

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
- the parser survives 24 hours on each fuzz target with no crash and no
  timeout, which is the gate `11-testing.md` sets for this criterion;
- **met** — blind and attended transfer complete against both FreeSWITCH and
  Asterisk;
- the same flows, plus DTMF in both forms, run through `sipral::MediaEngine` —
  the join an application links — and then through `sipral.h` from a C driver,
  so that the path a customer ships is the path the lab proves;
- no request the stack can build leaves as an oversized datagram: the
  §18.1.1 promotion applies inside a dialog as it does outside one.

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
  guarantee written down rather than implied. *Built*, and the tests that carry
  it drive the stack through suspend and resume over a dead transport and with
  name resolution gone, rather than only the path where everything works.
- **A6, D3** — the statistics the jitter buffer already computes reach the
  application, and the counters beside them. *Built*, and the counters split
  failures by reason, which is the half that is a diagnosis rather than a
  number.
- **D8, B2** — a build says what it supports, and no setting can be accepted
  and ignored. *Built*, with the capability answer derived from the build
  rather than maintained by hand: a list that can drift from the binary is
  worse than none, because it is believed.

**The things whose cost rises with every week they wait.**

- **B7** — one source of truth for the ABI, with the bindings generated from
  it and `scripts/check.sh` failing when one is missing. It was cheapest before
  three bindings existed; there are still not three, but the C ABI has roughly
  doubled since this line was written, so the saving is being spent.
- **D1** — the call's diagnostic record. *Built.* The argument for doing it
  early held: every decision site written before it exists is a site to
  revisit, and the sites written since have carried their reason codes from the
  start.
- **D2** — deterministic replay, which the sans-I/O core makes nearly free and
  which turns every later field failure into a permanent test.

**The media and transport work the phase was already about**, plus what
production says is missing from it:

- **B1** — the path size limit as a constraint: promotion to a stream
  transport or a specific refusal, never a silent send, per RFC 3261 §18.1.1,
  with the on-wire size readable by the application. *Built* for the first
  send and the authenticated retry; the in-dialog path skipped it, and it is
  closed with phase 1's last criterion.
- **B5** — a media stall detected by the engine and reported, with an optional
  recovery attempt. *Built.*
- **B6** — a documented default profile for the deployment actually shipped
  against, made the default. *Built.*
- **D10** — the impairment profiles as fixtures in the repository, including a
  link that disappears for eight seconds. *Built.*

**And one piece of signalling that does not belong to media at all**, but is
P0 for phase 3 and is sized like a phase of its own:

- **A1** — the subscription machine (RFC 6665) and `dialog-info+xml`
  (RFC 4235), with bulk operations and with the REFER subscription expressed
  as the special case it is. *Built.*

**Added to this phase after the tree was read end to end**, because each is
signalling or media a carrier or a second kind of customer asks for by name,
and each is cheaper before the ABI carries it than after:

- **a re-negotiation that keeps what it should** — a codec change no longer
  restarts the stream on the identity the call opened with, and never reuses
  an SRTP index under a master key; re-keying reaches the RTP session; a
  re-offer that drops `a=crypto` under a *required* policy is refused, not
  answered;
- **RTCP-XR** (RFC 3611) VoIP metrics, sent and read, with the R factor and
  MOS from the E-model written from ITU-T G.107, and **quality reports**
  published per RFC 6035 where an account names a collector;
- **SIP MESSAGE** (RFC 3428) in both directions and **message waiting**
  (RFC 3842) parsed to a count, because a softphone has chat and voicemail
  whether or not the requirements document remembered them;
- **a local three-way conference**: two calls mixed in `sipral-media`'s mixer,
  which is written and reached by nothing;
- **STUN reached from a call** — the softphone profile behind a NAT learns its
  public address from `sipral-nat`, which is written, tested and linked by
  nothing; ICE-lite stays where `06-nat.md` puts it, on a public server;
- **early media on the answering side**, so a stack that answers can speak
  before 200 OK through its own engine rather than through a second one;
- **the 200 OK to REGISTER kept**, and with it Service-Route (RFC 3608) in the
  route set, GRUU (RFC 5627) learned and used, P-Associated-URI reported;
- **G.729**, base plus Annex A and Annex B, written from the text of the
  Recommendation the way G.722 was — never from the reference C code, never
  from the crates that repackage a GPL implementation under another name.
  Interoperable first, bit-exact against the ITU sequences second if a
  customer asks. The base patents are reported expired since 2017; that is
  confirmed in writing before the codec ships under the commercial licence,
  and G.729.1 and the later annexes stay out. Not in the default offer:
  narrower and worse than Opus or G.722, it is there for the carrier that
  insists.
- **DTLS-SRTP** (RFC 5764), decided on 10 September 2026: written in-tree.
  `rustls` carries no DTLS and no permissively licensed DTLS crate is mature,
  so the DTLS 1.2 state machine — both roles, retransmission, fragmentation,
  the `use_srtp` extension, key export per RFC 5705, fingerprint verification
  against `a=fingerprint` and nothing else — is written from RFC 6347, while
  the primitives it needs (P-256, AES-GCM, SHA-256, HMAC) come from the same
  permissively licensed crate family that already supplies AES, because a
  constant-time elliptic curve is the one place a home-grown implementation is
  a risk rather than a virtue. Reviewed adversarially before it ships under
  the commercial licence. It is the last item of the phase, and nothing else
  waits on it.

**Exit:**

- mean opinion score at parity with a reference stack, measured on the same
  `tc netem` impairment profiles, committed with the tests;
- DTMF recognised by the lab PBX and by a carrier IVR, in the RTP form and in
  both INFO forms, received as well as sent;
- SRTP interoperating over SDES and over DTLS-SRTP, against FreeSWITCH and
  Asterisk with each keying, re-keyed on re-negotiation, with no index ever
  repeated under one key;
- every call reports an R factor and a MOS the lab PBX accepts as RTCP-XR;
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

Most of the parity surface is built. What is written below as done is done in
the tree with tests, not planned; what is left is named as such, because a
roadmap whose finished items still read as future work is a roadmap nobody
trusts.

- **A2, A3** — device enumeration with an identity that survives replug, gain,
  mute and a peak level cheap enough for a meter. *Built.* Selection per call
  is the part that is not, and it is D6's rather than the device layer's.
- **A5** — call recording: the mixed conversation to one file, started and
  stopped mid-call. *Built.*
- **A4** — codec enumeration and priority, and what a live call settled on.
  *Built.* **D5**, the engine explaining why the other candidates lost, is not.
- **A7, D4** — the network-change entry point and the lifecycle model behind
  it, with tests that suspend and resume under adverse conditions. *Built*, and
  it brought `RegistrationState::Unverified` with it: a monotonic clock cannot
  tell a stack that it slept, so a binding granted before a suspend stops being
  evidence rather than staying valid.
- **A8** — refusing an unwanted INVITE before any user-visible effect. *Built.*
  **D7**'s rate limiting and refusal counters ride on it.
- **A9, A10** — DTMF and settable product identity. *Built*, and A9 in all
  three forms rather than the one the requirement asked for: RFC 4733 in the
  media, and INFO with either body, chosen per send because which one a peer
  accepts is a fact about the peer. The signalling trace A10 asked for is
  superseded by **D1**, which is built.
- **B7** — the ABI's single source of truth, with the Swift, Kotlin and .NET
  bindings generated from it and `scripts/check.sh` failing when one is
  missing. *Built* as declarations; **not yet as platforms**: on 10 September
  2026 the tree built no C-linkable library at all, three of the four printed
  bindings did not compile, and the gate could not tell, because it compared
  the generator's output with itself. The library and a C program that links
  it are now steps of the gate. The generator has tests of its own and reads
  its derived names back before it prints anything — two declarations that
  become one name, or a name a language will not take, stop it rather than
  reaching a consumer — which is what found the two entry points that made
  the C# file unbuildable and the five that made the JNI shim unbuildable:
  the same two, where `out_call` beside `call` derived one name twice, and
  three more where a parameter called `status` landed on the local the shim
  writes for the status it is about to return. Compiling the Swift, Kotlin and .NET
  bindings in the gate is still to be added, and the ABI does not freeze
  before it is.
- **D6** — device, codec and transport as properties of a call rather than of
  the process. *Built* in Rust; the transport half is not yet across the ABI.

**What is built in Rust and cannot be reached through `sipral.h`** — the list
phase 3 closes before the ABI freezes, because each of these is a shape and a
shape is permanent once published:

- the real-time media path shares the stack lock that `sipral_stack_poll`
  holds across the application's callback, so the audio thread is answered
  `SIPRAL_STATUS_BUSY` at the moments a user listens hardest; events are
  delivered after the lock is released and a call's media has a lock of its
  own;
- handles are minted per stack and carry no stack, so one call's handle names
  another call on a second stack; the handle carries its stack;
- one monotonic clock per stack is advanced by every entry point, including
  the ones the network thread calls; media entry points stop advancing it;
- A1 subscriptions, A7 and D4 lifecycle (suspend, resume, network change,
  rebind — the two registration states the header publishes cannot be
  produced by any C call today), A8 screening before any effect, C2 and C3
  announce and freeze, D1 the diagnostic record, D2 recording, D5 why each
  codec lost — each gets its entry points;
- SRTP cannot be offered or required from C while `sipral_capabilities`
  reports it; it becomes a member of the stack and call configuration;
- no event says who is calling; `From`, `To` and `Call-ID` join the call event,
  from the core's own parse, so no binding writes a SIP parser to show a
  caller;
- an application header cannot be put on any request or response; a header
  list joins the configurations and a call-scoped setter covers responses;
- a transfer accepted through the ABI places an INVITE with no offer; the
  entry point takes a call configuration like `sipral_call_place`;
- one transport per stack, and a registrar that cannot be re-pointed: a
  transport per account and per call, `sipral_account_retarget`, and the
  resolve request as an event with its answer;
- an account without a registrar, for trunks authenticated by address;
- the size-versioning constants pin the oldest published size rather than the
  current one, and every binding calls `sipral_abi_check` at load.

**The layers a developer actually adopts**, above the printed bindings:

- an idiomatic Swift module (stack, account and call as classes, events as an
  async stream, the `CallKit` and `PushKit` sequence from `15-mobile.md`), an
  idiomatic C# namespace (safe handles, events, tasks, PCM as spans) and an
  idiomatic Kotlin layer (coroutines, `ConnectionService`), each with a sample
  application skeleton that makes a call;
- the artefacts each platform consumes, built locally: an `.xcframework`, an
  AAR with the shared object for each Android ABI, a NuGet with native runtimes,
  wheels — with publishing left to a person, and each of them built without
  the `opus` feature or published as two variants labelled clearly enough that
  nobody ships the wrong one without noticing, because a binary somebody
  downloads instead of compiling is the one place the default would put
  libopus into a product quietly (`05-media.md`);
- `sipral-io-pipewire` for Linux desktops over `libpipewire` (MIT; ALSA and
  PulseAudio client libraries are LGPL and stay out), on a `sipral-io-common`
  crate holding what the two device crates currently duplicate;
- the platform echo canceller reached on Windows and Linux through the
  processor seam, with a reference module attachable as an optional crate.

**Exit:** a desktop softphone ships on Sipral with no other SIP stack linked
into its binary; the lab's flows have run through `sipral.h`; and the ABI is
frozen only after every item above exists in C.

## Phase 4 — mobile

`sipral-io-aaudio` and the AAR. `CallKit` and `PushKit` on iOS,
`ConnectionService` and foreground services on Android.

The signalling half of this phase is already built, because none of it needed a
phone: it is protocol and state, and it was cheaper to write beside D4 than
after it. What is left is platform work, and platform work needs the platform.

- **C2** — a call announced out of band: the engine pre-warms, matches the
  INVITE that follows to the announcement, and reports an announced call that
  never arrived. *Built*, three races included. A push carries no `Call-ID` and
  cannot be made to, so the match is on the account plus the caller's user and
  host; the reasoning is in `docs/15-mobile.md`.
- **C3** — registration that can be frozen and thawed, time-to-ready measured
  by the stack, and RFC 8599 push parameters. *Built.*
- **C5** — an idle cost that is explicit, measurable, and reducible to nothing.
  *Built*: one wake per hour per account, and nothing at all while suspended.
- **C1, D4** — the lifecycle model behind all of them. *Built*, and the reason
  the rest of this phase is now within reach.
- **C4** — the audio device taken away and given back during a live call,
  survived unaided, every transition reported. **Not built, and not buildable
  from here**: it is `AVAudioSession` and `AudioManager`, so it needs
  `sipral-io-*` crates for iOS and Android that do not exist yet, and a device
  to run them on.
- **ICE in the full role** (RFC 8445) with TURN, on top of the STUN, TURN and
  ICE-lite already written in `sipral-nat`: gathering, pairing, checks,
  nomination, role conflicts, restarts, consent freshness (RFC 7675). Off by
  default for a desktop softphone, where it only adds setup time; on for a
  phone on a carrier-grade NAT, and lite on a public server. Proven in the lab
  with a TURN server and two stacks behind two simulated NATs, and against
  Asterisk with ICE enabled.

**Exit:** applications accepted in both stores, incoming calls waking the app
reliably from the background, and Bluetooth hands-free transitions surviving a
call.

## Phase 5 — headless and SDK

`sipral-headless`, packaging, public documentation, published packages.

The headless crate — the reason the README says the stack is small enough to
embed in a voice agent — shares no type with the media pipeline it is drawn
beside and is linked by nothing. The phase therefore starts one layer lower
than planned:

- **headless joined to the engine**: socket frames become `MediaSession`
  capture and playback, the sample rate is negotiated against the media plan
  rather than chosen blind, voice activity from `sipral-media` becomes a
  control event so an agent can be interrupted, a received digit becomes the
  control message that already exists for it, and an in-process session exists
  for an agent that embeds rather than connects;
- **hundreds of calls in one process**, measured: one stack, many calls, a lock
  per media session, four threads driving them, the numbers committed — and if
  one stack is not enough, the shape with several stacks on one port is
  designed from the measurement rather than from a guess;
- **Python**, because that is what voice agents are written in: a package over
  the C ABI (a fifth generated back end, not a second binding of the Rust API),
  with an idiomatic asynchronous layer, PCM as bytes, and an eighty-line agent
  as the example;
- **a call in sixty seconds with no account**: `cargo run --example call`
  dials a public test IVR, plays the menu through the device crate or into a
  file, presses a digit and hears it read back; the other examples register,
  call, hold, transfer, and run over TLS with the transport the application
  brings;
- **numbers** rather than adjectives: library size per platform, memory and CPU
  per call for G.711 and Opus, end-to-end latency in the lab, in a dated
  document produced by a script;
- the interoperability matrix as a public page generated from lab results,
  with carriers and session border controllers added as access to each is
  obtained, and marked untested until then;
- a security model in two pages: the threat model, what is fuzzed and for how
  long, what is redacted where, what the stack does not cover.

**Exit:** an external developer integrates Sipral from the published
documentation without asking a question that the documentation should have
answered; `pip install sipral` answers a call from the lab.

## Phase 6 — video, after 1.0

Decided on 10 September 2026: not before 1.0, because a video path written
beside an unfinished audio path makes both shallow; on the roadmap after it,
because a softphone product line eventually asks. What it contains: capture
and rendering per platform, in the device crates; VP8, VP9 and AV1 through
`libvpx` and `libaom` (BSD), H.264 only once its patent position is settled
in writing; the payload formats (RFC 6184, 7741, 7798); RTCP feedback for
pictures and loss (RFC 4585, 5104); a frame buffer and bandwidth estimation;
and hold per stream rather than per call, which the audio-only design
deliberately does not need.

**Exit:** a video call in both directions against FreeSWITCH and against a
second Sipral, surviving the impairment profiles, with audio quality
unchanged from the audio-only build.

## What the phases are risked against

Phases 1 and 2 carry the technical risk: signalling interoperability and audio
quality are demonstrated against real equipment, or they are not. From phase 3
onward the work is platform integration, where the risk is schedule rather than
feasibility.

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
- The ABI is not frozen before every entry the desktop client needs exists in
  C (the phase 3 list), before a C driver has run the lab's flows through
  `sipral.h`, and before every printed binding compiles in the gate. Flipping
  the repository public does not wait for the freeze; publishing packages does.
- Video waits for 1.0 by decision, not by omission, and is phase 6 after it.
