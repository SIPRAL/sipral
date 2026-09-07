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

> **Status: pre-alpha.** Design and skeleton. Nothing interoperates yet. The
> roadmap and the exit criteria for each phase are in
> [`docs/10-roadmap.md`](docs/10-roadmap.md).

## Why this exists

Every mature SIP client stack is either GPL with a private commercial arm, or
LGPL, which is its own problem the moment you statically link into an iOS app.
The permissive ones are C, and none of them is in Rust with real language
bindings. Meanwhile every AI voice agent that needs to answer a phone call is
made to run a whole media server or a whole PBX to get at the audio.

Sipral is the narrow answer to both: a stack you can link into a closed product
under a clear commercial licence, and a headless mode that hands you raw PCM on
a socket with no audio device and no room abstraction anywhere near it.

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
event loop over `std::net` will ship in `sipral-ua` for callers who would rather
not write one, off by default. Platform audio is the same shape: separate crates
you pick, or replace, or leave out entirely.

## Crates

| Crate | Contents |
|---|---|
| `sipral-core` | message parser and serializer, transactions, dialogs, SDP, authentication. Sans-I/O, no allocation surprises, no clock of its own |
| `sipral-ua` | registration, calls, hold, transfer, subscriptions. Built on the core |
| `sipral-rtp` | RTP and RTCP, adaptive jitter buffer, packet loss concealment, DTMF, SRTP |
| `sipral-nat` | STUN client, TURN client, ICE-lite |
| `sipral-media` | audio pipeline: mixing, resampling, clock drift correction, comfort noise, echo cancellation as an external module. Codecs: G.711 A-law and µ-law in-tree, Opus and G.722 linked, G.729 only if a carrier forces it |
| `sipral-io-coreaudio` | macOS and iOS device I/O. Siblings for WASAPI and AAudio follow |
| `sipral-headless` | PCM in and out over a local socket or WebSocket. No audio device, for AI agents |
| `sipral-ffi` | stable C ABI, and the Swift Package, NuGet and AAR built on it |
| `sipral` | the facade crate. Today a name reservation on crates.io that exports nothing; later the one crate an application depends on, re-exporting the stack |

## Standards

Implemented from the RFCs, not from anyone's source tree. The full list, and
which crate owns each one, is in [`docs/09-rfc-index.md`](docs/09-rfc-index.md).
Core set: RFC 3261, 3262, 3263, 3264, 3311, 3515, 3581, 4028, 6026, 6665, 8760
for signalling; 3550, 3551, 4733, 6716 and 7587 for media; 3711 with 4568 and
5764 for SRTP and its keying; 8445, 8489 and 8656 for NAT.

## Not trusting the input

A public SIP port receives malformed packets as a matter of course, so nothing
here treats them as exceptional.

- **No panics on input.** `unwrap`, `expect`, `panic` and unchecked indexing are
  lints across the workspace, and CI runs with `-D warnings`.
- **`Limits`** bounds every message parse before it starts: 64 KiB per message,
  128 header fields, 4 KiB per header value, all three lower on request.
- **Fuzzing** since the twenty-sixth commit — four `cargo-fuzz` targets over the
  parser, the builder, the stream framer and SDP, seeded with the RFC 4475
  corpus.
- **The RFC 4475 torture corpus** is in the tree bit-exact, 49 messages with a
  SHA-256 per file, and a test asserts on the outcome the RFC specifies for each
  one rather than on "it did not crash".

## Build

```bash
cargo build --workspace
cargo test --workspace
./scripts/check.sh
```

Rust 1.95 or newer, edition 2024. The toolchain is pinned in
`rust-toolchain.toml`.

## Licence

Dual: **AGPL-3.0-only**, or a **commercial licence** for closed source products
and app store distribution. [`LICENSING.md`](LICENSING.md) tells you in one page
which one you need. Full terms in [`LICENSE`](LICENSE) and
[`LICENSE-COMMERCIAL.md`](LICENSE-COMMERCIAL.md).

Dependencies are permissive only, and CI fails the build on anything else.

The name is a trademark and is not covered by either licence, see
[`TRADEMARK.md`](TRADEMARK.md).

## Contributing

Issues, interoperability reports and anonymised captures are welcome now. Code
contributions are not accepted before 1.0, for the reason explained in
[`CONTRIBUTING.md`](CONTRIBUTING.md).
