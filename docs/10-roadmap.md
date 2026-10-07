<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# Roadmap

Phases are defined by their exit criterion, not by a date. A phase ends when
the criterion is demonstrated, in the test suite or against real equipment.

What each phase contains is ordered against `docs/13-client-requirements.md`,
which is what a softphone in production asks of an engine. Items below are
tagged with the requirement they answer, so that a phase can be read as a list
of things somebody is waiting for rather than a list of things that sounded
interesting.

## Where 1.0 falls

1.0 is a promise about the C ABI rather than the end of a phase: the surface
frozen at ABI minor 33 holds for every 1.x release of the library (`08-ffi.md`,
"The freeze"), later ABI minors only appending to it. The 1.0.0 release is at
ABI 1.0, which is 0.36's surface under the first frozen major (`08-ffi.md`,
"ABI 1.0"): a binding built against ABI 1.k loads against every later 1.x
library. The library's version and the ABI's are two numbers, each moved by
its own rule (`08-ffi.md`, "Versioning"). What 1.0 publishes is the C library
and the language packages over it; the Rust crates are not part of it, and
their API promises nothing (`11-testing.md`, "Releasing").

It does not wait for what only a third party can supply — a paid carrier
account (phase 1), real phones and the two stores (phase 4), a public
registry the packages are pulled from (phase 5) — nor for what each phase
below still names as left: the adversarial review of DTLS-SRTP (phase 2), a
device chosen per call (phase 3), and video (phase 6), which comes after 1.0
by decision.

**1.1.0 is released** (4 October 2026), still at ABI 1.0, since it changed no
part of the C surface: the headless agent's steady 20 ms clock and its wait
on the SIP socket, Opus rebuilding lost frames from in-band FEC, a lighter
in-band DTMF detector, the gate holding every published figure to its
budget, and the fixes `CHANGELOG.md` lists.

## Releases

What each release brings, the same list as <https://sipral.org/roadmap/>: the site renders this section from its own roadmap and its check fails on any difference, so the two cannot drift. The phases below are the engineering underneath it, ordered by exit criterion rather than date.

<!-- releases: begin -->
### 1.0 — Complete, at C ABI 1.0

October 2026, released.

- SIP signalling, media, SRTP and DTLS-SRTP, ICE, STUN and TURN, STIR/SHAKEN behind one C ABI *(done)*
- Swift, Kotlin and Java, .NET, Python, Dart and React Native bindings *(done)*
- Device mode with the platform echo cancellation, or application mode for voice agents *(done)*
- Ten thousand concurrent calls in one process *(done)*

### 1.1 — Sharper at scale, released ahead of schedule

October 2026, released.

- Call set-up in the voice agent with no idle wait between reads *(done)*
- In-band DTMF detection at a fraction of its cost per frame *(done)*
- A call forked to two lines of one stack rings on both *(done)*
- Outgoing audio sent on a steady 20 ms clock *(done)*
- Opus rebuilds a lost frame from the copy the next packet carries, sized by the loss the far end reports *(done)*

### 1.2 — Voice agents and the enterprise

November 2026, planned.

- A SIP bridge from a PBX line to any voice agent that answers SIP, the outcome handed back to the PBX *(done)*
- Call audio at the rate a speech service asks for, in every language *(done)*
- A Pipecat transport, reaching every speech service Pipecat supports *(done)*
- How to connect more than forty voice-agent services, one by one *(done)*
- Direct connectors to the realtime speech APIs of five voice-agent services *(done)*
- A ready-to-run bridge from a configuration file, each account to its own agent *(done)*
- OAuth2 sign-in to the PBX (RFC 8898) *(done)*
- A call as a participant in a LiveKit room, as an example *(done)*
- A phone voice agent that runs in five minutes, speech to speech, from one command *(done)*
- Time from the INVITE to the first audio the agent hears, and from its reply to the first packet, measured and published *(done)*
- Calls held for a day and for a week with no growth in memory or processor time, measured and published *(in progress)*

### 1.3 — More platforms

Q1 2027, planned.

- Node.js and TypeScript package *(done)*
- .NET MAUI package for iOS and Android *(done)*
- A network test before the call *(done)*
- Answering-machine detection on calls the agent places *(done)*
- SIP over WebSocket with the connection made by the stack (RFC 7118) *(done)*
- LiveCommunicationKit on iOS *(done)*

### 2.0 — Beyond audio

Mid 2027, planned.

- Video with VP8, VP9 and AV1, with RTCP feedback for pictures
- ZRTP end-to-end key agreement

### Ongoing — Proven, and kept proven

Every release.

- Every published figure measured again by the gate on each change *(in progress)*
- An adversarial review of the DTLS-SRTP code, with interop and failure tests against other implementations *(in progress)*
- More PBXs proven in the lab, and caller identity, diversion, redirection and failover between servers shown working *(in progress)*
- Interop with carriers and a commercial SBC
<!-- releases: end -->

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

**Status: written, and seven of the eight exit criteria met.** Every line of the
phase is in the tree — `sipral-core`, `sipral-ua`, `sipral-rtp` and
`sipral-media` — and the lab's flows run against Kamailio, FreeSWITCH,
Asterisk and OpenSIPS whenever `scripts/lab.sh` is run, twice: once through
`sipral::MediaEngine`, the join an application links, and once through
`sipral.h` from a C driver. That was the
criterion added after the tree was read end to end, because until then the lab
drove the stack through a media join written for the lab, and what it proved
was the harness. What is left is one paid carrier account, which needs a
contract rather than code and which 1.0 does not wait for.

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
- **met** — the parser survives 24 hours on each fuzz target with no crash and
  no timeout, which is the gate `11-testing.md` sets for this criterion: 24
  CPU-hours on each of the thirty targets there were on 27 September 2026,
  the last four of them between 25 and 27 September, about 61 billion
  executions, nothing found. The four added on 29 September (`stir_identity`,
  `multipart`, `rtt`, `rtcp_fb`) are built and seeded, and their own 24 hours
  are still to run;
- **met** — blind and attended transfer complete against both FreeSWITCH and
  Asterisk;
- **met** — the same flows, plus DTMF in both forms, run through
  `sipral::MediaEngine` — the join an application links — and then through
  `sipral.h` from a C driver, so that the path a customer ships is the path the
  lab proves;
- **met** — no request the stack can build leaves as an oversized datagram: the
  §18.1.1 promotion applies inside a dialog as it does outside one.

## Phase 2 — media, and the things that get more expensive by waiting

`sipral-rtp`, `sipral-media`, `sipral-nat`, `sipral-io-coreaudio`. Adaptive
jitter buffer, loss concealment, Opus, SRTP, DTMF, echo cancellation attached,
STUN and TURN.

Three groups join it from `13-client-requirements.md`, for one reason each.

**The guarantees the architecture already almost provides.** Cheap now,
and every one of them is something a client is entitled to assume:

- **D9** — no clock read anywhere in the core, stated and tested. `D2` depends
  on it, so it goes first. *Built.*
- **B4** — the threading contract documented and tested; a violation is an
  error and never a fault. *Built.*
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
  three bindings existed; there are now five (Swift, .NET, Kotlin, Python,
  Dart), all printed from the one source, with a React Native package over
  the Swift and Kotlin layers, and the C ABI has more than doubled since this
  line was written.
- **D1** — the call's diagnostic record. *Built.* The argument for doing it
  early held: every decision site written before it exists is a site to
  revisit, and the sites written since have carried their reason codes from the
  start.
- **D2** — deterministic replay, which the sans-I/O core makes nearly free and
  which turns every later field failure into a permanent test. *Built*
  (`docs/18-replay.md`).

**The media and transport work the phase was already about**, plus what
production says is missing from it:

- **B1** — the path size limit as a constraint: promotion to a stream
  transport or a specific refusal, never a silent send, per RFC 3261 §18.1.1,
  with the on-wire size readable by the application. *Built* for the first
  send, the authenticated retry and every request inside a dialog, the ACK to
  a 2xx included; phase 1's last criterion is the lab showing it.
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

- **a re-negotiation that keeps what it should** — a re-offer that drops
  `a=crypto` under a *required* policy is refused, not answered;
- **RTCP-XR** (RFC 3611) VoIP metrics, sent and read, with the R factor and
  MOS from the E-model written from ITU-T G.107, and **quality reports**
  published per RFC 6035 where an account names a collector;
- **SIP MESSAGE** (RFC 3428) in both directions and **message waiting**
  (RFC 3842) parsed to a count, because a softphone has chat and voicemail
  whether or not the requirements document remembered them;
- **a local three-way conference**: two calls mixed in `sipral-media`'s mixer.
  *Built*: `MediaEngine::join`/`leave`/`mix` pair two calls and drive the
  mix a frame at a time, `sipral_call_join`/`sipral_call_leave`/
  `sipral_media_mix` carry it across the C ABI, and the interop lab proves
  one call's audio crosses to the other's wire on Asterisk;
- **STUN reached from a call** — the softphone profile behind a NAT learns its
  public address from `sipral-nat`; ICE-lite stays where `06-nat.md` puts it,
  on a public server.
  *Built*: `sipral::Mappings` asks a STUN server about the
  signalling socket and each media socket, `UserAgent::readdress` moves the
  accounts' `Contact` onto the answer and `CallMedia::public_address` puts it in
  `c=` and `m=` — and in a server-reflexive ICE candidate when ICE is on.
  `SIPRAL_NAT_STUN` and `stun_server` carry it across the C ABI, and the lab
  proves it through a NAT against coturn and Asterisk. ICE-lite for the
  headless profile is wired too: `IcePolicy::Lite`, only in a build with
  `headless` or `ice-lite`, answers a full peer's checks and carries the audio
  on the pair it nominates, proven in process and in the lab against the
  harness and Asterisk (`docs/06-nat.md#ice-lite`); `SIPRAL_ICE_LITE` carries
  it across the C ABI, proven in every binding and in the lab through
  `harness-c listen`. TURN is wired too: `sipral::Relays`
  and `turn_server` allocate a relay for a media socket before its call, and
  the full agent carries it as the relayed candidate, proven in the lab
  between two NATs that let nothing else through (`docs/06-nat.md#turn`),
  over UDP and — for the network that lets no UDP out — over TCP and TLS,
  the connection opened by the application and by every binding;
- **early media on the answering side**, so a stack that answers can speak
  before 200 OK through its own engine rather than through a second one.
  *Built*: `MediaEngine::ring`/`ring_with`, and
  `sipral_call_ring_media` in C, open the session on the 183 itself and the
  200 OK that follows reuses it, per RFC 3262 §5 and RFC 6337 §3.1.1;
- **the 200 OK to REGISTER kept**, and with it Service-Route (RFC 3608) in the
  route set, GRUU (RFC 5627) learned and used, P-Associated-URI reported.
  *Built*: the route on what an account starts and never on its REGISTER, the
  GRUU as the `Contact` of what opens a dialog, and every value bounded and
  written down when it is refused, as `docs/04-ua.md` sets out;
- **G.729**, base plus Annex A and Annex B, written from the text of the
  Recommendation the way G.722 was — never from the reference C code, never
  from the crates that repackage a GPL implementation under another name.
  Interoperable first, bit-exact against the ITU sequences second if a
  customer asks. The base patents are reported expired since 2017; that is
  confirmed in writing before the codec ships under the commercial licence,
  and G.729.1 and the later annexes stay out. Not in the default offer:
  narrower and worse than Opus or G.722, it is there for the carrier that
  insists. *Built*: Annex A's encoder and decoder and Annex
  B over them, bit-exact against every ITU Annex A and Annex B conformance
  stream and input, in a call on payload type 18 when an order names it,
  and heard through the lab's Asterisk. Annex B is offered with
  `annexb=yes` unless the catalogue turns it off, an answer follows the
  offer, and the encoder sends SID frames and nothing in the pauses where
  both ends said yes (`docs/05-media.md`).
- **DTLS-SRTP** (RFC 5764), decided on 10 September 2026: written in-tree.
  `rustls` carries no DTLS and no permissively licensed DTLS crate is mature,
  so the DTLS 1.2 state machine — both roles, retransmission, fragmentation,
  the `use_srtp` extension, key export per RFC 5705, fingerprint verification
  against `a=fingerprint` and nothing else — is written from RFC 6347, while
  the primitives it needs (P-256, AES-GCM, SHA-256, HMAC) come from the same
  permissively licensed crate family that already supplies AES, because a
  constant-time elliptic curve is the one place a home-grown implementation is
  a risk rather than a virtue. **Built**, and joined to a call behind the
  `dtls` feature, which is on by default: `SrtpPolicy::DtlsOffered` and
  `DtlsRequired`, `MediaEvent::Secured`, and a stream that agreed to be
  encrypted and sends nothing until the handshake has keyed it. Still to do:
  the adversarial cryptography review, before it ships under the commercial
  licence. The lab runs it against FreeSWITCH and Asterisk
  (`docs/11-testing.md`).

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
  mute and a peak level cheap enough for a meter. *Built*, and reached through
  `sipral.h`: `sipral-audio` is the built-in engine over CoreAudio, WASAPI and
  AAudio, and a stack created in device mode (`sipral_stack_config_t::audio`)
  opens, pumps and mixes the platform's devices itself, with the microphone,
  the speaker and the ringer chosen per stack (`08-ffi.md`, "The built-in
  audio engine"). Each call has its own gain, mute and level in that engine
  as well (`sipral_audio_call_set_gain`, `_set_muted`, `_level`). Selection
  per call is the part that is not, and it is D6's
  rather than the device layer's; the codec and transport halves of D6 are
  across the ABI, the device half is not. Linux has no backend in the engine;
  `sipral-io-pipewire` is there for an application to wire itself.
- **A5** — call recording: the mixed conversation to one file, started and
  stopped mid-call. *Built.*
- **A4** — codec enumeration and priority, and what a live call settled on.
  *Built*, and with it **D5** in both halves: the engine says what became of
  every codec candidate that lost, through `sipral_media_codec_candidate_count`
  and `..._at`, and of every ICE candidate pair and relay a call tried —
  selected, outranked, nominated elsewhere, unanswered, refused with its
  code, answered from another address, refused by the relay with its reason,
  never checked, a relay released or lost — through
  `sipral_media_path_candidate_count` and `..._at`
  (`MediaSession::path_candidates` in Rust, a `pathCandidates` in each
  binding).
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
- **B7** — the ABI's single source of truth, with the Swift, Kotlin, .NET and
  Python bindings generated from it and `scripts/check.sh` failing when one is
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
  writes for the status it is about to return. The gate now compiles the
  Swift, Kotlin and .NET bindings too (`scripts/check.sh`, step "the bindings
  compile"); it skips a binding whose toolchain is missing from the machine,
  and a skip does not count as a pass. *Built as platforms* since: every
  printed binding, the Dart one included, and the React Native package are
  compiled and their tests run against the library on every gate run.
- **D6** — device, codec and transport as properties of a call rather than of
  the process. *Built* in Rust, and the codec and transport halves are across
  the ABI: `sipral_call_config_t` carries `codecs` and `transport` beside
  `media_address` and `srtp`. The device half is A2's per-call selection,
  which is not built.

**What is built in Rust and cannot be reached through `sipral.h`** — the list
phase 3 closed before the ABI froze at minor 33, because each of these is a
shape and a shape is permanent once published:

- one monotonic clock per stack is advanced by every signalling entry point,
  with no room for two threads reading it a moment apart, and it moves even
  when the call it gated then fails; a small tolerance, and a clock that
  moves only on success;
- A1 subscriptions, A7 and D4 lifecycle (suspend, resume, network change,
  rebind — the two registration states the header publishes cannot be
  produced by any C call today), A8 screening before any effect, C2 and C3
  announce and freeze, D1 the diagnostic record, D2 recording, D5 why each
  codec lost — each gets its entry points. *Built*: A7 and D4
  (`sipral_stack_suspending`, `_resumed`, `_network_changed`,
  `_interface_lost`, `_name_resolution_lost`, `sipral_account_rebind`, and
  `SIPRAL_EVENT_KIND_RECOVERY` reporting every rung), A8 and D7
  (`sipral_stack_screen`, `sipral_stack_invite_limit` and the four
  `screened_*` counters), D1 (`sipral_call_record_json`,
  `sipral_stack_diagnostics_json`), D2 (`sipral_stack_recording_start`,
  `_stop`) and A1 (`sipral_account_subscribe`, `sipral_subscription_end`,
  `sipral_subscription_lamp` and the three dialog readers, with event kinds 15
  and 30 behind them and `SIPRAL_FEATURE_SUBSCRIPTIONS` set), and C2 with the
  RFC 8599 half of C3 (`sipral_account_announce`,
  `sipral_account_refresh_binding`, `sipral_announcement_forget`,
  `sipral_account_push_echo`, the four push members on
  `sipral_account_config_t`, and event kinds 20 and 31), D5 in both halves
  (`sipral_media_codec_candidate_count`, `..._at` and
  `sipral_codec_candidate_t`; `sipral_media_path_candidate_count`, `..._at`
  and `sipral_path_candidate_t`) and the freeze and thaw half of C3
  (`sipral_account_freeze`, `sipral_account_thaw`, `sipral_stack_cold_start`
  and `sipral_account_time_to_ready`). **Every one of them is across**;
- SRTP cannot be offered or required from C while `sipral_capabilities`
  reports it; it becomes a member of the stack and call configuration.
  *Built*: `srtp` on `sipral_stack_config_t` as the stack's default and on
  `sipral_call_config_t` as a call's own, a `sipral_srtp_t` or zero for
  unspecified;
- no event says who is calling; `From`, `To` and `Call-ID` join the call event,
  from the core's own parse, so no binding writes a SIP parser to show a
  caller. *Built*: `sipral_call_event_t` carries the display name, the address
  of record and the `Call-ID` of the call it is about;
- application header fields on requests and responses, and a way to read any
  field back out. *Built*: `sipral_header_t` in `headers`/`headers_len` on the
  call and account configurations, `sipral_call_set_headers` for what a call
  sends at the application's request, and `sipral_message_header` with its
  three siblings over the core's parser;
- a transfer accepted through the ABI places an INVITE with no offer; the
  entry point takes a call configuration like `sipral_call_place`. *Built*:
  `sipral_call_accept_transfer` takes a `sipral_call_config_t`, reads
  `destination`, `keep_all_forks`, `headers`, `srtp` and `codecs` from it, and
  refuses `target`, which the REFER already named;
- one transport per stack, and a registrar that cannot be re-pointed: a
  transport per account and per call, `sipral_account_retarget`, and the
  resolve request as an event with its answer. *Built*: `transport` on the
  account and call configurations, `sipral_account_retarget`, and
  `SIPRAL_EVENT_KIND_RESOLVE_NEEDED` — number 29, which was held for it —
  answered by `sipral_stack_resolved` with a list of addresses in RFC 3263
  §4.3 order;
- an account without a registrar, for trunks authenticated by address.
  *Built*: `registrar_len` zero, with `registrar_address` as the outbound proxy
  and `SIPRAL_REGISTRATION_STATE_NOT_REGISTERING` as its state.

*Built*, all three: the .NET binding calls `sipral_abi_check` from a static
constructor, Kotlin from the singleton object's `init {}` block, and Swift,
which has neither, from `ensureAbi()`, which every call reads a static
property through before it reaches C.

**The layers a developer actually adopts**, above the printed bindings:

- an idiomatic Swift module (stack, account and call as classes, events as an
  async stream, the `CallKit` and `PushKit` sequence from `15-mobile.md`), an
  idiomatic C# namespace (safe handles, events, tasks, PCM as spans) and an
  idiomatic Kotlin layer (coroutines, `ConnectionService`), each with a sample
  application skeleton that makes a call. *Built*: Swift, C#, Kotlin and
  Python, each with a sample (`bindings/README.md`), then Dart for Flutter,
  a React Native package over the Swift and Kotlin layers, and a JVM jar
  with a Java face over the Kotlin one;
- the artefacts each platform consumes, built locally: an `.xcframework`, an
  AAR with the shared object for each Android ABI, a NuGet with native runtimes
  (`win-x64`, `win-arm64`, `osx-arm64`, `osx-x64`, `linux-x64`, `linux-arm64` --
  `linux-arm64` cross-compiled, no arm64 hardware needed), wheels including a
  `manylinux_2_28_aarch64` one built the same cross-compiled way — with
  publishing left to a person, and each of them built without
  the `opus` feature unless `--with-opus` asks for the second variant, whose
  name says it carries libopus so that nobody ships the wrong one without
  noticing, because a binary somebody downloads instead of compiling is the
  one place the default would put libopus into a product quietly
  (`05-media.md`). *Built* locally by `scripts/package/*.sh`; publishing is
  left to a person;
- a CycloneDX SBOM beside every one of those artefacts, from `sipral-ffi`'s
  own dependency graph at the features and target that artefact was actually
  built with, plus libopus itself as its own component in a `--with-opus`
  one — the C library `opusic-sys` vendors rather than declares, read the
  same way `sipral-license-gen --aec` already reads a vendored library's own
  licence file. *Built*: `tools/sbom-gen`, called from each packaging
  script; `scripts/check.sh` checks the `--with-opus` SBOM's crates.io
  components against `THIRD-PARTY-LICENSES.txt` exactly;
- `sipral-io-pipewire` for Linux desktops over `libpipewire` (MIT; ALSA and
  PulseAudio client libraries are LGPL and stay out), on a `sipral-io-common`
  crate holding what the two device crates currently duplicate. *Built*:
  enumeration and hotplug from the registry and the `"default"` metadata,
  capture and playback over `pw_stream`, the render delay from `pw_time`, a
  lost node reported rather than rerouted, and PipeWire's own echo canceller
  documented as the session module it is (`05-media.md`); tested against a
  real graph and through a lab call by `scripts/lab.sh pipewire`;
- the platform echo canceller reached on Windows and Linux through the
  processor seam, with a reference module attachable as an optional crate.
  *Built*: Windows' own capture processing on every stream `sipral-io-wasapi`
  declares a communications stream, PipeWire's echo-cancel module where the
  session loads it, and `sipral-aec-webrtc` attached at the seam anywhere
  else (`05-media.md`, "Where the canceller itself comes from").

**Exit:** a desktop softphone ships on Sipral with no other SIP stack linked
into its binary; the lab's flows have run through `sipral.h`; and the ABI is
frozen only after every item above exists in C. The last two hold: the C
driver runs every lab flow, and minor 33 froze the surface once the list
above was across (`08-ffi.md`, "The freeze"). The first is the one left.

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
  survived unaided, every transition reported. *Built*, in the layer where
  each platform delivers the signal: on Android the `ConnectionService`
  helper's `SipralCallAudio` over `CallAudio` (the framework's hold, the call
  focus, routes, mute, and the audio server dying under `AudioRecord` and
  `AudioTrack`), run on an emulator with a GSM call answered over a live
  call through the lab's Asterisk and the audio server stopped mid-call; on
  iOS the Swift package's `CallAudio`, `AudioSessionObserver` and
  `VoiceProcessingAudioDevice` with `CallKitBridge` (interruptions, routes,
  media services lost and reset, CallKit's hold, mute and audio session),
  run on the simulator with the system's notifications posted; and
  `sipral-io-coreaudio` reporting on iOS a unit the system stopped
  (`docs/15-mobile.md`, "C4"). What needs a phone is the system's own
  delivery: a carrier's call, a Bluetooth headset, a car, a route switched
  between real outputs.
- **Device mode on Android** — the built-in engine over `sipral-io-aaudio`:
  AAudio voice-communication streams from API level 28 (the input preset is
  the platform's echo canceller), a ringtone stream for the ringer, the
  phone's devices and call routes from `AudioManager` through the Kotlin
  shim, and the same device-change events as the desktops; below API level
  28 the telecom helper's `AudioRecord` and `AudioTrack` stay the path.
  *Built, and run on an emulator* (`docs/15-mobile.md`, "Device mode on
  Android"); a route switched between real outputs needs a phone.
- **`ConnectionService` and the AAR** — C2 carried onto Android's telecom
  framework as a self-managed connection, and the AAR with both natives for
  arm64-v8a, armeabi-v7a and x86_64. *Built, and run on an emulator*: the
  helper's logic on a JVM through fakes and over two real stacks, the AAR,
  the helper's library and a Compose sample built with the Android SDK and
  opened (`bindings/kotlin/README.md`), and the sample's APK on an Android 16
  arm64 emulator placing a call to a Sipral agent, holding, resuming, sending
  a digit and hanging up, with the telecom framework following every state,
  and a simulated push ringing through it (`docs/15-mobile.md`). An incoming
  INVITE, real audio devices and routes, and push delivery wait for a phone
  and a registrar in front of it; so does the foreground service for a
  call's lifetime.
- **ICE in the full role** (RFC 8445) with TURN, on top of the STUN, TURN and
  ICE-lite in `sipral-nat`: gathering, pairing, checks, nomination, role
  conflicts, restarts, consent freshness (RFC 7675). *The agent is written*,
  tested over a simulated network and reached from a call through
  `IcePolicy`; the lab proves two stacks behind two NATs finding each other on
  STUN's reflexive candidates and, with the path between them blocked,
  through a relay on a TURN server, with the start-up cost of both measured
  (`docs/06-nat.md`), and Asterisk's own ICE against the lite role; an ICE
  restart from either end, in either role, keeps the audio on the old pair
  until the new one is chosen; the relay reaches its server over UDP, TCP or
  TLS, the last two proven from behind a NAT that drops every datagram to the
  server. A restart this end starts is `sipral_call_restart_ice` in C and
  `restartIce()` or its equivalent in the Swift, Kotlin, .NET and Python
  layers. Off by default for a desktop
  softphone, where it only adds setup time; on for a phone on a carrier-grade
  NAT, and lite on a public server.

**Exit:** applications accepted in both stores, incoming calls waking the app
reliably from the background, and Bluetooth hands-free transitions surviving a
call.

## Phase 5 — headless and SDK

`sipral-headless`, packaging, public documentation, published packages.

The headless crate is joined to the engine: `sipral::HeadlessSession`, behind
the `headless` feature, turns socket frames into `MediaSession` capture and
playback at the negotiated rate, sends voice activity and received digits as
control events, and gives an agent that embeds rather than connects an
in-process session. *Built* (`docs/07-headless.md#real-media`).

- **hundreds of calls in one process**, measured: one stack, many calls, a lock
  per media session, four threads driving them, the numbers committed — and if
  one stack is not enough, the shape with several stacks on one port is
  designed from the measurement rather than from a guess;
- **Python**, because that is what voice agents are written in: a package over
  the C ABI (a fifth generated back end, not a second binding of the Rust API),
  with an idiomatic asynchronous layer, PCM as bytes, and a one-file agent
  as the example. *Built* (`bindings/python`), with wheels for the host,
  manylinux x86-64 and aarch64 (`scripts/package/wheels.sh`); `pip install`
  from a registry waits for 1.0;
- **a call in sixty seconds with no account**: `cargo run --example call`
  dials a public test IVR, plays the menu through the device crate or into a
  file, presses a digit and hears it read back; the other examples register,
  call, hold, transfer, and run over TLS with the transport the application
  brings. *Built*, and timed on 27 September 2026 by a reader given only the
  README, in a fresh Linux container: a connected call in about two minutes,
  most of it the first build — after a stop the README then did not prevent,
  CMake missing for libopus, which it now names;
- **numbers** rather than adjectives: library size per platform, memory and CPU
  per call for G.711 and Opus, end-to-end latency in the lab, in a dated
  document produced by a script. *Built*: `docs/19-numbers.md`,
  `scripts/bench.sh`;
- the interoperability matrix as a public page generated from lab results,
  with carriers and session border controllers added as access to each is
  obtained, and marked untested until then. *Built*: `scripts/interop-matrix.py`
  into `docs/11-testing.md`;
- a security model in two pages: the threat model, what is fuzzed and for how
  long, what is redacted where, what the stack does not cover. *Built*:
  `docs/20-security-model.md`.

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
- No package is published to a registry before the ABI in `08-ffi.md` is
  frozen. A published name is a promise about compatibility. The exceptions
  are name reservations: `Sipral` 0.0.1 on NuGet, a stub assembly that
  implements nothing, and `sipral` 0.0.1 on crates.io, the one crate with
  `publish = true`. The 1.0 release publishes the language packages, not the
  crate: the reservation stays what it is, and `scripts/package/crate.sh`
  says so rather than packaging it.
- The ABI is not frozen before every entry the desktop client needs exists in
  C (the phase 3 list), before a C driver has run the lab's flows through
  `sipral.h`, and before every printed binding compiles in the gate. Flipping
  the repository public does not wait for the freeze; publishing packages does.
  All three held at minor 33, whose surface is the one 1.0 promises; every
  minor since grew it only by appending, as the freeze allows, and packages
  are published from 1.0.
- Video waits for 1.0 by decision, not by omission, and is phase 6 after it.
