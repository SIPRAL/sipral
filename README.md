<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/sipral-lockup-dark.png">
  <img src="assets/sipral-lockup.png" alt="Sipral" width="314">
</picture>

**S**ession **I**nitiation **P**rotocol **R**ust **A**udio **L**ayer.

**Sipral is a SIP client stack in Rust — signalling, media, encryption and NAT
traversal behind one C ABI — that replaces PJSIP without the GPL, and puts a
phone line inside a voice agent without a media server in between.**

## What sets it apart

- **Memory-safe, and built for hostile input.** Rust throughout; `unsafe` is denied everywhere but the C boundary and the device crates; `unwrap`, `panic` and unchecked indexing fail the gate; 34 `cargo-fuzz` targets, thirty of them run 24 CPU-hours each (about 61 billion executions, nothing found); the RFC 4475 torture corpus asserted message by message.
- **A sans-I/O core.** It opens no socket, starts no thread, reads no clock and draws no random number: the RFC 3261 §17 timer diagrams are ordinary unit tests, and a recorded field session replays deterministically ([`docs/18-replay.md`](docs/18-replay.md)).
- **No GPL or LGPL code in it.** Written clean-room from the RFCs and ITU Recommendations, permissive dependencies only (`cargo deny` fails on anything else), offered under AGPL-3.0 or a commercial licence that ships in closed apps and app stores.
- **One C ABI, every language printed from one declaration.** The header and the Swift, Kotlin, .NET, Python and Dart bindings come out of `tools/abi-gen`; struct layouts are checked on 64-bit and both 32-bit ABIs and compiled for six targets, and every member keeps its offset across minors.
- **Device mode or headless, per stack.** The library opens the microphone and speaker itself (CoreAudio, WASAPI, AAudio, with the platform's echo cancellation) — a softphone with no audio code — or hands the application its PCM a frame at a time, or carries it over a socket to a separate agent process.
- **Encrypted the ways real PBXs and carriers ask for.** SRTP with SDES (AES-CM 128/256, AES-GCM), DTLS-SRTP written in-tree, "SRTP best effort" for PBXs that answer `RTP/SAVP` with 488, TLS with the platform's trust, a private CA or one pinned certificate, and STIR/SHAKEN signing and verification (RFC 8224, 8588).
- **NAT handled, not hoped for.** STUN with failover, TURN over UDP, TCP and TLS, ICE in the full and lite roles with restarts and consent freshness, RFC 5626 keep-alives, and a call that follows its own address when the network moves.
- **Signalling that survives real deployments.** RFC 3263 location (NAPTR, SRV, A/AAAA, failover, re-lookup on TTL), RFC 3261 §18.1.1 size rules with promotion to TCP and a trimmed retry, PRACK, UPDATE, session timers, forking, GRUU, Service-Route, push-announced calls (RFC 8599).
- **More than a call.** Opus, G.722, G.711, L16 and G.729 Annexes A and B (bit-exact against the ITU conformance streams); an adaptive jitter buffer with concealment and drift correction; DTMF three ways; N-way local conferences with each call on its own codec; SIPREC; presence, MESSAGE, message waiting and busy lamp field; real-time text; RTCP-XR with MOS.
- **Diagnosable in the field.** A per-call record of every decision with its reason code as JSON, pcapng export with GDPR redaction, health counters, and a diagnostic trace with credentials and keys stripped.
- **Proven against what is deployed.** A container lab runs registration, calls, hold, transfers, DTMF, SRTP, DTLS-SRTP, NAT, ICE and TURN against Asterisk 22, FreeSWITCH 1.10, Kamailio 6.1, OpenSIPS 4.0 and baresip — through the Rust API and again from a C program through `sipral.h`, over clean and impaired links — and a short set of them has run against a live FreePBX 16.
- **Measured, not claimed.** Ten thousand concurrent calls with audio held in one process at about 72 KB each; under 3 µs per audio frame with two hundred calls on four threads; a 3 MB shared library ([`docs/19-numbers.md`](docs/19-numbers.md), [`docs/23-compared-with-pjsip.md`](docs/23-compared-with-pjsip.md)).

## A call, in Python

```python
import asyncio
from sipral import Stack
from sipral.enums import RegistrationState

async def main():
    with Stack(loop=asyncio.get_running_loop()) as stack:  # device mode: the library opens mic and speaker
        account = stack.add_account(
            "sip:alice@example.com", registrar="sip:example.com",
            server_uri="sip:example.com",  # located by RFC 3263: NAPTR, SRV, A/AAAA
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
needs. The Swift, Kotlin, .NET, Dart and React Native layers have the same
shape ([`bindings/README.md`](bindings/README.md)).

No server at hand? `cargo run --example call` dials a public test IVR, presses
a digit and plays back what it reads (CMake is needed once, for libopus).

## Platforms

| Platform | Languages | Device mode | Artefact (`scripts/package/`) |
|---|---|---|---|
| macOS | Rust, C, Swift, Kotlin/Java, .NET, Python, Dart | CoreAudio voice processing | XCFramework, NuGet, wheel |
| iOS | Rust, C, Swift, React Native, Flutter | CoreAudio voice processing, CallKit and PushKit helpers | XCFramework |
| Android | Rust, C, Kotlin, React Native, Flutter | AAudio (API 28+), `ConnectionService` helper | AAR for arm64-v8a, armeabi-v7a, x86_64 |
| Windows | Rust, C, .NET, Python, Dart | WASAPI communications streams | NuGet, wheel |
| Linux | Rust, C, Kotlin/Java, .NET, Python, Dart | application mode; `sipral-io-pipewire` for a desktop | NuGet, manylinux wheels, JVM jar (x64, arm64) |

Application mode — PCM in the application's hands — is available on every
platform and in every language. The Dart layer runs application mode over UDP;
the React Native package runs device mode over the Swift and Kotlin layers.

## Status

Version 0.x, pre-1.0. The C ABI is at **0.34**: minor 0.33 is the surface 1.0
freezes — names, numbers, layouts and ownership rules
([`docs/08-ffi.md`, "The freeze"](docs/08-ffi.md#the-freeze-abi-033)) — and
0.34 grew it only the way the freeze allows, by appending. Seven of the eight
phase-1 exit criteria are met; the eighth is a paid carrier account. Nothing is
published yet beyond name reservations (`Sipral` 0.0.1 on NuGet is an empty
stub).

## Roadmap

All of this is **planned, not done**; [`docs/10-roadmap.md`](docs/10-roadmap.md)
has the exit criteria.

- **1.0:** the 0.33 surface declared frozen, and the packages above published.
- **Carriers:** interoperability on two paid carrier accounts and a commercial SBC.
- **Security:** an adversarial cryptography review of DTLS-SRTP before it ships under the commercial licence.
- **Mobile on real phones:** store acceptance, a push waking the app from the background, Bluetooth hand-off during a call.
- **Video, after 1.0:** VP8, VP9 and AV1, RTCP feedback for pictures, per-stream hold.

## Documentation

| | |
|---|---|
| [`docs/01-architecture.md`](docs/01-architecture.md) | the crates, the sans-I/O boundary, who owns sockets, resolver and TLS |
| [`docs/08-ffi.md`](docs/08-ffi.md) | the C ABI, its rules, versioning and the freeze, and every binding |
| [`docs/21-migrating-from-pjsip.md`](docs/21-migrating-from-pjsip.md) | each pjsua concept and its equivalent here |
| [`docs/11-testing.md`](docs/11-testing.md) | fuzzing, the audio quality gate, the interoperability matrix |
| [`docs/09-rfc-index.md`](docs/09-rfc-index.md) | every specification implemented, and by which crate |
| [`docs/README.md`](docs/README.md) | all design documents, also built as a site by `scripts/site.sh` |

## Build

```bash
cargo build --workspace && cargo test --workspace
./scripts/check.sh        # the full release gate
```

Rust 1.95 (pinned in `rust-toolchain.toml`) and CMake for libopus are enough
to build and test. `./scripts/check.sh` also builds and tests every binding,
so it needs their toolchains as well
([`docs/11-testing.md`, "Where the checks run"](docs/11-testing.md#where-the-checks-run));
a tool it cannot find is reported as a skip, and a run with a skip has not
checked that part. `./scripts/check.sh --hygiene-only` runs the tree checks
without a build.

## Licence

Dual: **AGPL-3.0-only**, or a **commercial licence** for closed-source products
and app store distribution — [`LICENSING.md`](LICENSING.md) says in one page
which one you need. How every component was written from its specification is
recorded in [`CLEANROOM_AUDIT.md`](CLEANROOM_AUDIT.md). The name is a
trademark, see [`TRADEMARK.md`](TRADEMARK.md).

## Contributing

Issues, interoperability reports and anonymised captures are welcome. Code
contributions are not accepted before 1.0, for the reason in
[`CONTRIBUTING.md`](CONTRIBUTING.md).
