<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Architecture

## The one decision everything follows from

**The protocol core performs no I/O and owns no time.**

It exposes, in essence:

```rust
fn receive(&mut self, input: Input<'_>, now: Instant) -> Result<(), ReceiveError>;
fn handle_timeout(&mut self, now: Instant);
fn poll_transmit(&mut self) -> Option<Transmit>;
fn poll_event(&mut self) -> Option<Event>;
fn poll_timeout(&self) -> Option<Instant>;
```

`Input` is bytes that arrived on a transport the caller owns. `Transmit` is
bytes to send. `Event` is what the application should know. `poll_timeout`
says when the caller must call `handle_timeout` even if nothing arrives; a
timer firing is not an arrival, so it gets its own call. The full surface is
in [12-core-api.md](12-core-api.md).

Consequences, in the order they matter:

1. **Every state machine is testable without a network.** Transaction timers,
   retransmission, forking, race conditions between a `CANCEL` and a `200 OK`:
   all reproducible by feeding bytes and advancing a fake clock. This is the
   difference between finding an interoperability bug in a unit test and finding
   it on a customer's carrier.
2. **The core embeds in any runtime.** Swift structured concurrency, a .NET
   `Task`, a Kotlin coroutine, Tokio, a bare `epoll` loop. None of them has to
   agree with any other, because the core does not bring one.
3. **Blocking is impossible by construction.** There is no socket to block on.
4. **Platform code is isolated.** Audio devices and TLS live at the edges, and
   the headless build simply does not link them.

The cost is honest: the caller writes the event loop. `sipral-ua` ships a
reference loop for people who do not want to, and the bindings ship the
idiomatic one for their language.

## Layers

```
                    sipral-ffi          C ABI, Swift / .NET / Kotlin
                        │
        ┌───────────────┼───────────────┐
        │               │               │
   sipral-ua      sipral-headless   sipral-io-*     device or socket
        │               │               │
        ├───────────────┴───────────────┤
        │                               │
   sipral-core                     sipral-media     pipeline, codecs, AEC
   parser, transactions,                 │
   dialogs, SDP, auth              sipral-rtp       RTP/RTCP, jitter, SRTP
                                         │
                                    sipral-nat      STUN, TURN, ICE-lite
```

Dependencies point down only. `sipral-core` depends on nothing outside the
standard library. Nothing depends on `sipral-io-*` except the application.

One edge the picture allows and the design forbids: **`sipral-ua` does not
depend on `sipral-media`, `sipral-rtp` or `sipral-nat`, and none of those
depends on `sipral-ua`.** Signalling and media never call each other. What
passes between them is a description — `MediaPlan` out of the negotiation and
`MediaCapabilities` back into it, both in `sipral-core::sdp` and both written
out in [05-media.md](05-media.md) — and something carries it across.

**Today nothing does.** `sipral-rtp` and `sipral-media` name no Sipral crate at
all in their manifests, only `sipral-nat` names `sipral-core`, and `MediaPlan`
and `MediaCapabilities` are used nowhere outside `sipral-core::sdp` and its own
tests. The vocabulary is designed and unspoken: the two halves are not loosely
coupled, they are unconnected, and an application that wants both writes the
join itself.

The crate that is supposed to write it is [`sipral`](#the-facade), below, and
the consequence of it being empty is not abstract — it is that the C ABI links
signalling only, so a client on the other side of it still has to parse SDP,
run RTP and own its devices. `docs/13-client-requirements.md` is largely a list
of things that are blocked on this and on nothing else.

The reason is the build in the third column: an agent that puts PCM on a socket
links no media pipeline at all, and a `sipral-ua` that reached into one could
not be built without it.

### Who owns the sockets, the resolver and TLS

Nothing in this tree opens one. The core says where a message should go and
what has to be resolved (`Event::ResolveNeeded`, `Event::TransportWanted`); the
caller answers.

`sipral-ua` ships a reference loop for callers who do not want to write one. It
is deliberately the plainest thing that works — `std::net`, blocking sockets,
one thread each, UDP and TCP — and it is **off by default**, behind the
`reference-loop` feature, because two things it cannot do are things a real
deployment needs:

- **NAPTR and SRV.** `std::net` resolves a name to addresses and nothing else,
  so the reference loop answers `ResolveNeeded` with an A lookup and takes what
  it gets. A deployment that has to reach a carrier through SRV supplies its own
  resolver — the platform has one, and on mobile it is the only one allowed to
  answer while the radio is asleep.
- **TLS.** No TLS implementation is linked here, and none will be: a stack that
  picks one imposes it on every embedder. `TransportProtocol::Tls` describes a
  transport the caller has already secured, and the caller supplies the
  connection.

### sipral-core

Message representation, parser and serializer, the transaction layer, the dialog
layer, SDP, and digest authentication. It knows about bytes and about time as a
number. It does not know what a call is.

Detail in [03-core-signalling.md](03-core-signalling.md).

### sipral-ua

What a user agent does with those primitives: register and keep the registration
alive, place and answer calls, hold, transfer, subscribe. Still sans-I/O, still
deterministic. Detail in [04-ua.md](04-ua.md).

### sipral-rtp, sipral-nat, sipral-media

Media. `sipral-rtp` is where call quality is decided, because the adaptive
jitter buffer and the loss concealment live there. `sipral-media` owns the
pipeline and the seam for an external echo canceller. `sipral-nat` is the escape
hatch for the minority of paths that symmetric RTP does not solve.

Detail in [05-media.md](05-media.md) and [06-nat.md](06-nat.md).

### sipral-io-*, sipral-headless

Two ways to get audio in and out, and they are mutually exclusive by design. A
device build links `sipral-io-coreaudio` (or WASAPI, or AAudio). An agent build
links `sipral-headless` and touches no audio API at all.

That second build is not a stripped-down first build. It is why the audio device
layer was kept out of the core in the first place.

### sipral-ffi

One narrow C ABI. Handles are opaque, ownership is explicit, and events arrive
on a callback. The expressive API is written once per language, on top.

### sipral

<a id="the-facade"></a>The facade, and the only place the two halves of the
picture are allowed to meet. An application that just wants a softphone stack
depends on this one crate and gets `sipral-ua` plus a media pipeline
re-exported under one name.

At this commit it is a name reservation on crates.io that exports a version
constant and nothing else; it is the only crate with `publish = true`, and the
only one that ships before the ABI freezes, precisely because it promises
nothing yet.

That emptiness is the single largest gap in the tree, and it is load-bearing
rather than cosmetic. Because nothing joins signalling to media, the C ABI
carries signalling alone, and a device, a codec list, a recording, a level
meter and a stream statistic have nowhere to cross. The rule above — that
`sipral-ua` never reaches into a media crate — stays exactly as it is; this
crate is where the join was always meant to live, and writing it here is
keeping the rule rather than bending it.

## What is not in the tree

- **No SIP server, proxy, registrar or B2BUA.** Sipral is an endpoint. The
  server side is a different product with different constraints, and pretending
  otherwise is how stacks become unmaintainable.
- **No WebRTC.** SDP for SIP only. No data channels, no SFU, no simulcast.
- **No video.** The audio path is deep enough to be worth doing properly. Video
  would make it shallow.
- **No global state, no singletons, no ambient logger.** Multiple independent
  stacks in one process must not interfere.
- **No `unsafe`**, except inside `sipral-ffi` and the platform I/O crates, where
  it is unavoidable. The workspace denies it everywhere else, and those two
  crates re-enable it explicitly in their own manifests.

## Errors and panics

The library never panics on input. Malformed packets are the normal case on a
public SIP port, not an exception. `unwrap`, `expect`, `panic` and unchecked
indexing are lints at warn level across the workspace, and a suppression of any
of them carries a comment saying why it cannot fire.

Errors are typed per layer and do not leak the layer below.

## Allocation

The parse path borrows from the input buffer and does not copy header values
unless the caller keeps them. Buffers are reused across packets. This is not
premature optimisation: a stack embedded in a mobile app on battery, or handling
hundreds of concurrent agent sessions in one process, is judged on exactly this.
