<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/sipral-lockup-dark.png">
  <img src="assets/sipral-lockup.png" alt="Sipral" width="314">
</picture>

**S**ession **I**nitiation **P**rotocol **R**ust **A**udio **L**ayer.

**Sipral is a SIP client stack in Rust — signalling, media, encryption and NAT
traversal behind one C ABI — that replaces PJSIP without the GPL, and puts a
phone line inside a voice agent without a media server in between.**

[sipral.org](https://sipral.org) · [Voice agents](https://sipral.org/voice-agents/) · [Interoperability](https://sipral.org/#lab-title) · [Roadmap](https://sipral.org/roadmap/) · [Blog](https://sipral.org/blog/) · [Licensing](https://sipral.org/licensing/)

## What sets it apart

- **Memory-safe, and built for hostile input.** Rust throughout; `unsafe` is denied everywhere but the C boundary and the device crates; `unwrap`, `panic` and unchecked indexing fail the gate; 36 `cargo-fuzz` targets, thirty of them run 24 CPU-hours each (about 61 billion executions, nothing found); the RFC 4475 torture corpus asserted message by message.
- **A sans-I/O core.** It opens no socket, starts no thread, reads no clock and draws no random number: the RFC 3261 §17 timer diagrams are ordinary unit tests, and a recorded field session replays deterministically ([`docs/18-replay.md`](docs/18-replay.md)).
- **No GPL or LGPL code in it.** Written clean-room from the RFCs and ITU Recommendations, permissive dependencies only (`cargo deny` fails on anything else), offered under AGPL-3.0 or a commercial licence that ships in closed apps and app stores.
- **One C ABI, every language printed from one declaration.** The header and the Swift, Kotlin, .NET, Python, Dart and Node.js bindings come out of `tools/abi-gen`; struct layouts are checked on 64-bit and both 32-bit ABIs and compiled for six targets, and every member keeps its offset across minors.
- **Device mode or headless, per stack.** The library opens the microphone and speaker itself (CoreAudio, WASAPI, AAudio, with the platform's echo cancellation as a switch and each call's own mute, gain and level meter) — a softphone with no audio code — or hands the application its PCM a frame at a time, or carries it over a socket to a separate agent process.
- **Encrypted the ways real PBXs and carriers ask for.** SRTP with SDES (AES-CM 128/256, AES-GCM), DTLS-SRTP written in-tree, "SRTP best effort" for PBXs that answer `RTP/SAVP` with 488, TLS with the platform's trust, a private CA or one pinned certificate, and STIR/SHAKEN signing and verification (RFC 8224, 8588).
- **NAT handled, not hoped for.** STUN with failover, TURN over UDP, TCP and TLS, ICE in the full and lite roles with restarts and consent freshness, RFC 5626 keep-alives, and a call that follows its own address when the network moves.
- **Signalling that survives real deployments.** RFC 3263 location (NAPTR, SRV, A/AAAA, failover, re-lookup on TTL), accounts on UDP, TCP and TLS side by side in one stack, RFC 3261 §18.1.1 size rules (the compact form first, then promotion to TCP or a trimmed retry), PRACK, UPDATE, session timers, forking, GRUU, Service-Route, push-announced calls (RFC 8599), SIP over a WebSocket the stack opens (RFC 7118) and OAuth2 sign-in to the PBX (RFC 8898). The Swift, Kotlin, .NET, Python and Dart bindings open the TLS connections and run the NAPTR and SRV lookups with the platform's own APIs; only the optional Rust reference loop is limited to plain UDP and TCP and A records.
- **More than a call.** Opus, G.722, G.711, L16 and G.729 Annexes A and B (bit-exact against the ITU conformance streams); Opus's in-band FEC, its copies sized by the loss the far end reports and decoded where a frame is lost; an adaptive jitter buffer with concealment and drift correction; DTMF three ways; N-way local conferences with each call on its own codec; SIPREC; presence, MESSAGE, message waiting and busy lamp field; real-time text; RTCP-XR with MOS.
- **Diagnosable in the field.** A per-call record of every decision with its reason code as JSON, pcapng export with GDPR redaction, health counters, and a diagnostic trace with credentials and keys stripped.
- **Proven against what is deployed.** A container lab runs registration, calls, hold, transfers, DTMF, SRTP, DTLS-SRTP, NAT, ICE and TURN against Asterisk 22, FreeSWITCH 1.10, FusionPBX 5.6, Kamailio 6.1, OpenSIPS 4.0 and baresip — through the Rust API, again from a C program through `sipral.h`, and with the Python, Swift, Kotlin and .NET layers answering, over clean and impaired links — and a short set of them ran against a live FreePBX 16 on 29 September 2026, a live VitalPBX 4.5 on 8 October 2026 and a VICIdial dialer (ViciBox 12) on 11 October 2026, where an agent's phone was rung into its session, answered and joined to a caller ([`docs/11-testing.md`, "A live PBX"](docs/11-testing.md#a-live-pbx)).
- **Measured, not claimed.** Ten thousand concurrent calls with audio held in one process at about 72 KB each, once the ceiling is raised to fit them: a stack holds 128 calls at once unless `max_dialogs` (`maxDialogs` in the layers, `--max-calls` on the headless agent) says otherwise, and answers the next one 503 with `Retry-After: 2`; under 1 µs per audio frame with two hundred calls on four threads, the in-band digit detector included while the far end is quiet, and about 1.4 µs more while the library listens for digits in a far end that is talking; seven days of calls against Asterisk, 3,337 of them and 6,795 registrations with no error and resident memory flat at 6.07 MB; a 5 MB shared library with Opus, SRTP, DTLS, ICE, STIR and the device engine in it ([`docs/19-numbers.md`](docs/19-numbers.md), [`docs/23-compared-with-pjsip.md`](docs/23-compared-with-pjsip.md)).

## Install

```sh
pip install sipral                # or sipral-opus, with Opus
dotnet add package Sipral         # Sipral.Opus; Sipral.Maui for iOS and Android
npm install sipral                # Node.js; sipral-react-native for React Native
cargo add sipral
dart pub add sipral
```

Android and the JVM: `org.sipral:sipral` and `org.sipral:sipral-jvm` on Maven
Central (`-opus` for the variants with Opus). Swift: this repository as a
Swift package, from 1.2.0.

## A call, in Python

```python
import asyncio
from sipral import Stack
from sipral.enums import RegistrationState

async def main():
    with Stack(loop=asyncio.get_running_loop()) as stack:  # device mode: the library opens mic and speaker
        account = stack.add_account(
            "sip:alice@example.com", registrar="sip:example.com",
            server_uri="sip:example.com",  # RFC 3263: A/AAAA here, SRV with Stack(resolver=...)
            auth_user="alice", auth_password="secret")
        account.register()
        while account.registration_state != RegistrationState.REGISTERED:
            await stack.events.get()
        call = stack.place_call(account, "sip:bob@example.com")
        while not call.ended:
            print((await call.events.get()).kind_name)

asyncio.run(main())
```

No bind address, no media address: the stack listens on every interface and
advertises the route toward the server it found. With
`Stack(..., audio=AudioMode.APPLICATION)` — the default where there is no
audio backend — the same call hands over its audio instead:
`await call.media.frames.get()` is the far end's next frame as 16-bit PCM,
and `call.media.send_audio(pcm)` is what the far end hears, which is all a voice agent
needs. The Swift, Kotlin, .NET, Dart, Node.js and React Native layers have the same
shape ([`bindings/README.md`](bindings/README.md)).

A [Pipecat](https://github.com/pipecat-ai/pipecat) voice agent answers calls through `sipral-pipecat`, one pipeline per call ([`integrations/pipecat`](integrations/pipecat/README.md)); `sipral-agents` joins each call to OpenAI Realtime, Gemini Live, ElevenLabs Agents, Vapi or Deepgram Voice Agent over their WebSocket APIs, with no framework ([`integrations/agents`](integrations/agents/README.md)).

No server at hand? `cargo run --example call` dials a public test IVR, presses
a digit and plays back what it reads (CMake is needed once, for libopus).

## Platforms

| Platform | Languages | Device mode | Artefact (`scripts/package/`) |
|---|---|---|---|
| macOS | Rust, C, Swift, Kotlin/Java, .NET, Python, Dart, Node.js | CoreAudio voice processing | XCFramework, NuGet, wheel |
| iOS | Rust, C, Swift, .NET MAUI, React Native, Flutter | CoreAudio voice processing, CallKit and PushKit helpers | XCFramework, NuGet (MAUI) |
| Android | Rust, C, Kotlin, .NET MAUI, React Native, Flutter | AAudio (API 28+), `ConnectionService` helper | AAR for arm64-v8a, armeabi-v7a, x86_64; NuGet (MAUI) |
| Windows | Rust, C, .NET, Python, Dart, Node.js | WASAPI communications streams | NuGet, wheels (x64, arm64) |
| Linux | Rust, C, Kotlin/Java, .NET, Python, Dart, Node.js | application mode; `sipral-io-pipewire` for a desktop | NuGet, manylinux wheels, JVM jar (x64, arm64) |

Application mode — PCM in the application's hands — is available on every
platform and in every language but one: the React Native package runs device
mode over the Swift and Kotlin layers. The Dart layer runs application mode,
signalling over UDP with an account's own TCP or TLS connection beside it; the
Node.js layer runs device or application mode, signalling over UDP, TCP or TLS.

## Status

**1.2.3, at C ABI 1.2.** These are two numbers on purpose: 1.2.3 is the
release every package ships under, and 1.2 is the version of the C
interface, which `sipral_abi_check` compares when a binding loads
([`docs/08-ffi.md`, "Versioning"](docs/08-ffi.md#versioning)).

What 1.0 promises, for every 1.x release: the C ABI surface frozen at minor
0.33 and carried into ABI 1.0 unchanged — names, numbers, struct layouts and
ownership rules
([`docs/08-ffi.md`, "The freeze"](docs/08-ffi.md#the-freeze-abi-033), and
["ABI 1.0"](docs/08-ffi.md#abi-10)) — stands, and a later minor only
appends to it; the gate holds every pinned struct length and every member's
offset to the commit before it. Every binding asks the native library it
loads whether it speaks the ABI the binding was printed against, and that
check keeps older applications working: a binding built against ABI 1.k
loads against any library at 1.m with m ≥ k, and one built against a later
minor than the library's is refused at load with both versions named.
From 1.2.0 the `sipral` crate on crates.io is part of the release too, and
its Rust API carries the same promise for every later 1.x
([`docs/08-ffi.md`, "The Rust crates"](docs/08-ffi.md#the-rust-crates)). Security
fixes reach the current minor release and the one before it
([`SECURITY.md`](SECURITY.md)). The artefacts in the table above, the
Swift package over the XCFramework, the Dart package and the React Native
package are built by `scripts/package/`, and
[`docs/11-testing.md`, "Releasing"](docs/11-testing.md#releasing) is the
order they are published in.

## Not yet

- **Video** comes in 2.0.
- **WebRTC:** a PBX WebRTC line comes in 1.3, a browser at the other end and
  trickle ICE in 1.4.

## Roadmap

[`docs/10-roadmap.md`](docs/10-roadmap.md) has every release and its exit
criteria, the same list as [sipral.org/roadmap](https://sipral.org/roadmap/).

- **1.2, voice agents and more platforms:** the SIP bridge, the Pipecat transport, connectors to five speech services, a bridge run from a configuration file, OAuth2 sign-in to the PBX and the agent's own latency; Node.js and TypeScript, .NET MAUI, a network test before the call, answering-machine detection, SIP over WebSocket and LiveCommunicationKit; the Rust API promised between releases and published on crates.io; a week of calls held with no error. Released on 15 October 2026.
- **1.3, November 2026:** iOS and Android proven on real phones (call screen, audio routes, a push that wakes the phone, Wi-Fi to mobile data, battery) and through the stores' test tracks; a cold start after a push in Swift and Kotlin; Android's transactional Telecom API; calls on a PBX WebRTC line (BUNDLE, the browser profile).
- **1.4, December 2026:** trickle ICE, an audio call to and from a browser, and SIP-T and SIP-I on a carrier gateway; networking ready to use from Rust and C (sockets, TLS, NAPTR/SRV), a C++ API, and a hook that rewrites any SIP message in or out.
- **1.5, March 2027:** a client certificate on SIP over TLS, its key held by the platform (Secure Enclave, Android Keystore, the macOS Keychain, CNG), in the C ABI and the Swift, Kotlin and .NET bindings.
- **2.0, mid 2027:** video (VP8, VP9, AV1) and ZRTP.
- **Ongoing:** carrier interop on paid accounts and a commercial SBC, more PBXs in the lab.

## Documentation

| | |
|---|---|
| [`docs/01-architecture.md`](docs/01-architecture.md) | the crates, the sans-I/O boundary, who owns sockets, resolver and TLS |
| [`docs/08-ffi.md`](docs/08-ffi.md) | the C ABI, its rules, versioning and the freeze, and every binding |
| [`docs/21-migrating-from-pjsip.md`](docs/21-migrating-from-pjsip.md) | each pjsua concept and its equivalent here |
| [`docs/24-voice-agents.md`](docs/24-voice-agents.md) | reaching AI voice-agent services: by a SIP call, through Pipecat, or with the call's PCM |
| [`docs/11-testing.md`](docs/11-testing.md) | fuzzing, the audio quality gate, the interoperability matrix |
| [`docs/09-rfc-index.md`](docs/09-rfc-index.md) | every specification implemented, and by which crate |
| [`docs/README.md`](docs/README.md) | all design documents, also built as a site by `scripts/site.sh` |

## Build

```bash
cargo build --workspace && cargo test --workspace
./scripts/check.sh        # the full release gate
```

Rust 1.99 (pinned in `rust-toolchain.toml`; the crates build from 1.95) and CMake for libopus are enough
to build and test. `./scripts/check.sh` also builds and tests every binding,
so it needs their toolchains as well
([`docs/11-testing.md`, "Where the checks run"](docs/11-testing.md#where-the-checks-run));
a tool it cannot find is reported as a skip, and a run with a skip has not
checked that part. `./scripts/check.sh --hygiene-only` runs the tree checks
without a build, `--only AREA` one part of the gate, and `--changed` the parts
a change reaches (`./scripts/check.sh --help`).

## Licence

Dual: **AGPL-3.0-only**, or a **commercial licence** for closed-source products
and app store distribution — [`LICENSING.md`](LICENSING.md) says in one page
which one you need. How every component was written from its specification is
recorded in [`CLEANROOM_AUDIT.md`](CLEANROOM_AUDIT.md). The name is a
trademark, see [`TRADEMARK.md`](TRADEMARK.md).

## Contributing

Issues, interoperability reports and anonymised captures are welcome. Code
contributions are taken under a contributor licence agreement, once it is
published in [`CONTRIBUTING.md`](CONTRIBUTING.md), for the reason given there.
