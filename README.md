<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/sipral-lockup-dark.png">
  <img src="assets/sipral-lockup.png" alt="Sipral" width="314">
</picture>

**S**ession **I**nitiation **P**rotocol **R**ust **A**udio **L**ayer.

A SIP user agent stack written in Rust: memory-safe, sans-I/O at the core, no
audio device inside it, one C ABI, and thin bindings for Swift, .NET and Kotlin.
Small enough to embed in an AI voice agent, complete enough to run a softphone.

> **Status: pre-alpha, phase 1.** Registration, calls, hold, and blind and
> attended transfer run against Kamailio, FreeSWITCH and Asterisk in the
> container lab (`scripts/lab.sh`); registration, a call and hold run against
> a live FreePBX over the Internet. The C ABI is not frozen, and the only thing
> on a registry is a name reservation: `Sipral` 0.0.1 on NuGet, which holds the
> name and carries a stub assembly that implements nothing. Nothing is on
> crates.io yet. The roadmap and the exit criteria for each phase
> are in [`docs/10-roadmap.md`](docs/10-roadmap.md).

## Why this exists

Every mature SIP client stack is either GPL with a private commercial arm, or
LGPL, which is its own problem the moment you statically link into an iOS app.
The permissive ones are C, and none of them is in Rust with real language
bindings. Meanwhile every AI voice agent that needs to answer a phone call is
made to run a whole media server or a whole PBX to get at the audio.

Sipral is the narrow answer to both: a stack you can link into a closed product
under a clear commercial licence, and a headless mode that will hand you raw PCM
on a socket with no audio device and no room abstraction anywhere near it. The
framing and control protocol for that mode is written and tested; joining it to
the media pipeline is phase 5, and until then no audio reaches it.

## Try it in sixty seconds

No account, no server to run, nothing to configure. With Rust installed
(from [rustup.rs](https://rustup.rs); the right toolchain is fetched on the
first build), from the repository root:

```bash
cargo run --example call
```

This dials `sip:thetestcall@sip2sip.info`, a public IVR that sip2sip.info
publishes for exactly this — reachable by anyone, no registration needed. It
waits for the greeting, presses `2` to ask for its digits read back, sends a
short string, and plays what comes back through the default output device.
On a machine with no audio device it writes what it heard to `call.wav` in the
current directory instead, and `--wav out.wav` does the same on any machine.
The first build compiles the dependencies and takes a minute or two. A call
that worked prints:

```text
calling sip:thetestcall@sip2sip.info ...
connected
media started on PCMU
sending 2
sending 1234#
```

and, when it wrote a file, `wrote N samples (call.wav)` at the end: about
twenty-five seconds of the IVR talking.

That one example is also the shortest way to read what embedding this stack
looks like: a [`sipral::UserAgent`](crates/sipral/examples/call.rs) and a
[`sipral::MediaEngine`] driven over sockets the application owns, RTP paced
against a real clock, and PCM handed to a device or a file. The other
examples in [`crates/sipral/examples/`](crates/sipral/examples/) build on the
same shape: `register-and-call.rs` adds an account, a registrar, hold and
transfer, with the destination on the command line; `tls.rs` is `call.rs`
again with the signalling carried over TLS instead of plain UDP, using
`rustls` as that one example's own dependency (`cargo run --example tls
--features example-tls`); `headless-agent.rs` is a fifty-line agent that
answers whatever calls it and repeats back whatever it hears, with no device
and no room abstraction anywhere near it — the shape a voice agent embeds.

## Design in one paragraph

The core opens no sockets, starts no threads, reads no clock and draws no random
numbers. It takes bytes, a time and a seed, and returns bytes and events. That
makes every state machine deterministically testable — a full RFC 3261 §17 timer
diagram is an ordinary unit test — and it lets the same core sit inside a Swift
async context, a .NET `Task` or a Kotlin coroutine without fighting anyone's
runtime.

There is no transport crate, and that is the point: **you** own the sockets. The
core says what to send and where, names what needs resolving, and asks for a
stream connection when a message outgrows a datagram (§18.1.1). A reference
event loop over `std::net` ships in `sipral-ua` behind the `reference-loop`
feature, off by default, for callers who would rather not write one. Platform
audio is the same shape: separate crates
you pick, or replace, or leave out entirely.

## Crates

| Crate | Contents |
|---|---|
| `sipral-core` | message parser and serializer, transactions, dialogs, SDP, authentication, the diagnostic record, session recording and replay. Sans-I/O, no allocation surprises, no clock of its own |
| `sipral-ua` | registration, calls, hold, transfer, subscriptions and busy lamp field, push-announced calls, suspend and resume, screening of unwanted INVITEs. Built on the core |
| `sipral-rtp` | RTP and RTCP, adaptive jitter buffer, packet loss concealment, DTMF, SRTP |
| `sipral-nat` | STUN client, TURN client, and ICE in both roles — the lite one, and the full one with gathering, checklists, nomination, role conflicts, restarts and consent freshness. The full agent is reached from a call through `IcePolicy`, and the STUN client through `sipral::Mappings` and `SIPRAL_NAT_STUN`, both off by default; the TURN client is not reached yet |
| `sipral-dtls` | DTLS 1.2 for DTLS-SRTP: the client and server handshake with retransmission, the stateless cookie exchange, alerts and the SRTP key export, over the record layer, handshake framing and messages, key derivation, and self-signed certificates checked by fingerprint. Reached from a call behind the `dtls` feature |
| `sipral-media` | audio pipeline: mixing, resampling, clock drift correction, comfort noise, echo cancellation as an external module. Codecs: G.711 A-law and µ-law and G.722 in-tree, written from the Recommendations; Opus linked (libopus), behind a compile-time feature that is on by default and that a build meant for hardware turns off; G.729 follows in phase 2, written the same way, for the carrier that insists |
| `sipral-io-common` | the parts of a device backend that are not about any device: the lock-free ring between the audio thread and an ordinary one, the gate that says when that thread is out of our memory, and volume, mute and the meter |
| `sipral-io-coreaudio` | macOS and iOS device I/O |
| `sipral-io-wasapi` | Windows device I/O |
| `sipral-io-pipewire` | Linux desktop device I/O, over `libpipewire`. AAudio for Android follows |
| `sipral-headless` | the PCM-over-a-socket framing and control protocol for AI agents, with no audio device. Not yet joined to the media pipeline |
| `sipral-ffi` | the C ABI, printed from one declaration into the header and the Swift, .NET and Kotlin bindings. Not frozen yet |
| `sipral` | the facade: signalling from `sipral-ua` joined to the media pipeline, with the codec catalogue, SRTP keying, DTMF, call recording and statistics per call. The one crate an application depends on, and what `sipral-ffi` exposes |

## Standards

Implemented from the RFCs, not from anyone's source tree. The full list, and
which crate owns each one, is in [`docs/09-rfc-index.md`](docs/09-rfc-index.md).
Core set: RFC 3261, 3262, 3263, 3264, 3311, 3515, 3581, 4028, 6026, 6665, 8760
for signalling; 3550, 3551, 4733, 6716 and 7587 for media; 3711 with 4568 for
SRTP and its SDES keying; 5763, 5764, 6347 and 8122 for DTLS-SRTP; 8445, 8489
and 8656 for NAT. DTLS-SRTP is behind the `dtls` feature, on by default, and
has not had its adversarial cryptography review yet.

## Not trusting the input

A public SIP port receives malformed packets as a matter of course, so nothing
here treats them as exceptional.

- **No panics on input.** `unwrap`, `expect`, `panic` and unchecked indexing are
  lints across the workspace, and `scripts/check.sh` runs with `-D warnings`.
- **`Limits`** bounds every message parse before it starts: 64 KiB per message,
  128 header fields, 4 KiB per header value, all three lower on request.
- **Fuzzing** since the twenty-sixth commit — eighteen `cargo-fuzz` targets,
  over the parser, the builder, the stream framer, SDP and its `a=crypto`
  lines, the recording format, the dialog-info and message-summary bodies,
  the headless control channel, RTCP, RTP named events, an incoming DTMF
  INFO, SRTP unprotect, STUN, TURN, the ICE agent, and the DTLS record layer
  and handshake messages. Each has run for 24 CPU-hours, about 37 billion
  executions in all, with no crash, hang or runaway memory. Run by
  `scripts/fuzz.sh`; built by `scripts/check.sh` on every run so none of them
  can rot uncompiled. The seeds are committed under `fuzz/corpus/`, written by
  `tools/fuzz-seeds` out of the library's own encoders, so a clone starts with
  something rather than with the empty input; a long run is worth pointing at
  `fixtures/rfc4475/` as well.
- **The RFC 4475 torture corpus** is in the tree bit-exact, 49 messages with a
  SHA-256 per file, and a test asserts on the outcome the RFC specifies for each
  one rather than on "it did not crash".

## Numbers

Measured on an Apple M-series machine with `scripts/bench.sh`, which anybody
can rerun: the shared library is **2.79 MB**; one frame of audio in and out —
`sipral_media_receive` and `sipral_media_playback`, G.711 through the jitter
buffer — costs **under 3 µs** of thread time with **two hundred calls running
on four threads**, and no call ever waited on another. What each number is, what
it is not, and what it would take to make it worse:
[`docs/19-numbers.md`](docs/19-numbers.md).

## Build

```bash
cargo build --workspace
cargo test --workspace
./scripts/check.sh
```

Rust 1.95 or newer, edition 2024. The toolchain is pinned in
`rust-toolchain.toml`.

## Where to start reading

An application depends on the `sipral` crate and nothing else. The design
documents are indexed in [`docs/README.md`](docs/README.md); the ones to read
first are [`docs/01-architecture.md`](docs/01-architecture.md) for the shape of
the stack, [`docs/12-core-api.md`](docs/12-core-api.md) for the sans-I/O core
and [`docs/08-ffi.md`](docs/08-ffi.md) for the C ABI and what each binding
covers.

## Licence

Dual: **AGPL-3.0-only**, or a **commercial licence** for closed source products
and app store distribution. [`LICENSING.md`](LICENSING.md) tells you in one page
which one you need. Full terms in [`LICENSE`](LICENSE) and
[`LICENSE-COMMERCIAL.md`](LICENSE-COMMERCIAL.md).

Dependencies are permissive only, and `cargo deny` fails the build on
anything else. Every protocol in here is written from its specification rather
than from anyone's implementation, which is what makes the second arm of that
licence possible; the record of how, component by component, is in
[`CLEANROOM_AUDIT.md`](CLEANROOM_AUDIT.md).

The name is a trademark and is not covered by either licence, see
[`TRADEMARK.md`](TRADEMARK.md), which also carries the additional terms under
section 7 of the AGPL-3.0 that come with every file.

## Contributing

Issues, interoperability reports and anonymised captures are welcome now. Code
contributions are not accepted before 1.0, for the reason explained in
[`CONTRIBUTING.md`](CONTRIBUTING.md).
