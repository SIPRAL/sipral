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

**Status: written, and seven of the eight exit criteria met.** Every line of the
phase is in the tree — `sipral-core`, `sipral-ua`, `sipral-rtp` and
`sipral-media` — and the lab's flows run against three servers whenever
`scripts/lab.sh` is run, twice: once through `sipral::MediaEngine`, the join an
application links, and once through `sipral.h` from a C driver. That was the
criterion added after the tree was read end to end, because until then the lab
drove the stack through a media join written for the lab, and what it proved
was the harness. What is left is one paid carrier account.

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
  CPU-hours on all thirty targets, the newest four between 25 and 27
  September 2026, about 61 billion executions, nothing found;
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
  three bindings existed; there are now four (Swift, .NET, Kotlin, Python), all
  printed from the one source, and the C ABI has roughly doubled since this
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
  between two NATs that let nothing else through (`docs/06-nat.md#turn`);
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
  mute and a peak level cheap enough for a meter, *built inside the three
  device crates*; not yet reachable through `sipral` or `sipral.h`, which is
  what docs/13 counts. Selection per call is the part that is not, and it is
  D6's rather than the device layer's; the codec and transport halves of D6
  are across the ABI, the device half is not.
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
  and a skip does not count as a pass.
- **D6** — device, codec and transport as properties of a call rather than of
  the process. *Built* in Rust, and the codec and transport halves are across
  the ABI: `sipral_call_config_t` carries `codecs` and `transport` beside
  `media_address` and `srtp`. The device half waits on A2 crossing at all.

**What is built in Rust and cannot be reached through `sipral.h`** — the list
phase 3 closes before the ABI freezes, because each of these is a shape and a
shape is permanent once published:

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
  Python, each with a sample (`bindings/README.md`);
- the artefacts each platform consumes, built locally: an `.xcframework`, an
  AAR with the shared object for each Android ABI, a NuGet with native runtimes,
  wheels — with publishing left to a person, and each of them built without
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
  until the new one is chosen. What is left is TURN over TCP and TLS, for
  the network that lets nothing out but 443, and a C ABI entry point for a
  restart this end starts, which only the Rust API has. Off by default for a desktop
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
  as the example. *Built* (`bindings/python`); `pip install` from a registry
  waits for the freeze;
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
- No crate is published to a registry before the ABI in `08-ffi.md` is frozen.
  A published crate name is a promise about compatibility. The exceptions are
  name reservations: `Sipral` 0.0.1 on NuGet, a stub assembly that implements
  nothing, and the `sipral` name on crates.io, reserved the same way by a
  pre-release version of the one crate with `publish = true`.
- The ABI is not frozen before every entry the desktop client needs exists in
  C (the phase 3 list), before a C driver has run the lab's flows through
  `sipral.h`, and before every printed binding compiles in the gate. Flipping
  the repository public does not wait for the freeze; publishing packages does.
- Video waits for 1.0 by decision, not by omission, and is phase 6 after it.
