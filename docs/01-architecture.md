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
reference loop for people who do not want to, off by default and described
below. The bindings ship more than the declarations: each has a handwritten
idiomatic layer over the printed C ABI (Swift classes and async events, a C#
layer over P/Invoke, Kotlin coroutines, Python) — `bindings/README.md` lists
which files are generated and which are written by hand, and
[08-ffi.md](08-ffi.md) covers each one.

## Layers

```
                    sipral-ffi          C ABI, Swift / .NET / Kotlin / Python
                        │
                     sipral             the facade, and the one crate an
                        │               application depends on
        ┌───────────────┼───────────────┐
        │               │               │
   sipral-ua      sipral-media     sipral-rtp        sipral-nat
   registration,  pipeline,        RTP/RTCP,         STUN, TURN,
   calls, hold    codecs, AEC      jitter, SRTP      ICE
        │                                                 │
        └────────────────────────┬────────────────────────┘
                                 │
                            sipral-core     parser, transactions,
                                            dialogs, SDP, auth

   sipral-dtls       DTLS 1.2 for DTLS-SRTP, keyed beside sipral-nat (`dtls`)
   sipral-headless   PCM on a socket, no audio device — sipral ⇠ ⎯ ⎯ (`headless`)
   sipral-io-*       CoreAudio, WASAPI, PipeWire, the device itself
        │
   sipral-io-common  the ring, the gate, volume — no device at all
```

Dependencies point down only, and most of these crates have none. `sipral-core`
depends on nothing outside the standard library; `sipral-media`, `sipral-rtp`,
`sipral-dtls` and `sipral-headless` name no Sipral crate at all, and the three `sipral-io-*`
name exactly one, `sipral-io-common`, which names none. The device crates
stand outside the picture because nothing in it depends on them: an
application links at most one of `sipral-io-coreaudio`, `sipral-io-wasapi` or
`sipral-io-pipewire`, and never more than one.

`sipral-headless` stands outside the picture the same way, and names no
Sipral crate itself — it stays the leaf the picture above draws it as, sans-I/O
and free of every other layer's state. The dashed edge is the one exception to
"nothing in the picture depends on them": `sipral`'s own optional `headless`
feature (off by default, unlike `dtls`, `ice` and `stun`, which are on) depends
on it,
to carry PCM between this protocol's queues and a live `MediaSession` — the
[facade's own section](#the-facade) below and
[07-headless.md](07-headless.md#real-media) say what that join does and does
not do. It is still one edge pointing down and not a cycle:
`sipral-headless` depends on nothing above it in return, so an application
that links only `sipral-headless` — the agent build described above — still
names no Sipral crate but this one, exactly as before.

One edge the picture allows and the design forbids: **`sipral-ua` does not
depend on `sipral-media`, `sipral-rtp` or `sipral-nat`, and none of those
depends on `sipral-ua`.** Signalling and media never call each other. What
passes between them is a description — `MediaPlan` out of the negotiation and
`MediaCapabilities` back into it, both in `sipral-core::sdp` and both written
out in [05-media.md](05-media.md) — and something carries it across.

The crate that carries it is [`sipral`](#the-facade), below, and until 9
September 2026 it did not: `MediaPlan` and `MediaCapabilities` were used
nowhere outside `sipral-core::sdp` and its own tests, so the two halves were
not loosely coupled but unconnected, and an application that wanted both wrote
the join itself. It is written now. The rule above is unchanged and is the
reason the join lives there and only there — `sipral-rtp` and `sipral-media`
still name no Sipral crate in their manifests, and `sipral-ua` still reaches
into neither.

The consequence one layer up is the same shape: `sipral-ffi` names `sipral`
first in its manifest, with `sipral-core` and `sipral-ua` beside it for the
places the facade has no opinion about — binding a transport, a timer, an
in-dialog INFO. So **the C ABI carries media as well as signalling**: a client
on the other side of it hands a datagram in and gets PCM back, rather than
bringing a second stack to parse its own SDP and run its own RTP. That half of
the boundary is `crates/sipral-ffi/src/media.rs`, and it is written out in
[08-ffi.md](08-ffi.md).

The reason for the rule is the build standing outside the picture: an agent
that puts PCM on a socket links no media pipeline at all, and a `sipral-ua`
that reached into one could not be built without it.

### Who owns the sockets, the resolver and TLS

Nothing in this tree opens one. The core says where a message should go and
what has to be resolved (`Event::ResolveNeeded`, `Event::TransportWanted`); the
caller answers.

An account can name its registrar or its outbound proxy by a URI rather than
an address (`Account::located`). RFC 3263 is then this tree's and the lookups
are the caller's: `sipral_core::endpoint::Locator` decides what to ask — NAPTR
when asked for, SRV for the account's transport, then A or AAAA for its
address family — and ranks what comes back, and the user agent hands each
query out as `UaEvent::LookupWanted` and takes the answer with
`UserAgent::looked_up`. Every address found is kept for §4.3's failover, and
the name is looked up again when they have all failed or the answer's
time-to-live runs out, so a PBX that changes address is followed without a
restart.

`sipral-ua` ships a reference loop for callers who do not want to write one. It
is deliberately the plainest thing that works — `std::net`, blocking sockets,
one thread each, UDP and TCP — and it is **off by default**, behind the
`reference-loop` feature, because two things it cannot do are things a real
deployment needs:

- **NAPTR and SRV.** `std::net` resolves a name to addresses and nothing else,
  so the reference loop answers `ResolveNeeded` with an A lookup and takes what
  it gets, and answers an account's NAPTR and SRV queries with nothing, which
  leaves the locator the host's own addresses. A deployment that has to reach a carrier through SRV supplies its own
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

### sipral-dtls

DTLS 1.2, for the SRTP keys of a DTLS-SRTP handshake (RFC 5764): the client
and server handshake, sans-I/O like the core, over the record layer, the
handshake framing and messages, the key derivation and the exporter, and the
self-signed certificate a peer checks against `a=fingerprint`. Like
`sipral-rtp` it names no Sipral crate.

The facade depends on it, and on `sipral-nat` beside it, behind the `dtls`
feature: the handshake runs on the call's own media socket, and telling its
records from the RTP there is the first-octet rule of RFC 7983, which lives in
`sipral-nat` because ICE needs it in the same place. The `ice` feature is the
second edge into that crate and reaches the full agent, and `stun` the third,
reaching the Binding client; all three are optional, and with all three off a
build that will only ever place SDES calls leaves four cryptographic crates
and the agent out of its binary.

Detail in [05-media.md](05-media.md).

### sipral-io-*, sipral-headless

Two ways to get audio in and out, and they are mutually exclusive by design. A
device build links `sipral-io-coreaudio`, `sipral-io-wasapi`,
`sipral-io-pipewire` or `sipral-io-aaudio`. An agent build links `sipral-headless` and touches no audio API at
all.

That second build is not a stripped-down first build. It is why the audio device
layer was kept out of the core in the first place.

Neither device backend depends on `sipral` either — the same rule that keeps
`sipral-media` and `sipral-rtp` from naming `sipral-ua` keeps a device backend
from naming the facade, and an application wires a device's ring buffer to a
live `MediaSession` itself, the way `crates/sipral/examples/` does. `sipral`'s
own optional `headless` feature is the one exception to that pattern, and it
is one only because the facade is the seam already, not because
`sipral-headless` moved: see the note on the diagram above and
[07-headless.md](07-headless.md#real-media).

Three things in a device backend are not about the device, and they are the
three that are hard to get right: the lock-free ring where the thread the
system will not wait for meets an ordinary one, the gate that says when that
thread is out of our memory before the memory is freed, and volume, mute and
the meter. They were written twice, once per backend, and the second copy's
own documentation said it was the first copy's. They are `sipral-io-common`
now — one file each, compiled and tested on every platform the workspace
builds on rather than once per backend — so that PipeWire and AAudio were not
the third and fourth copy.

What stayed behind in each backend is what is genuinely its own, and the
counters are the clearest case of the difference. All three keep the same four
numbers — samples captured, dropped, played and invented — and then CoreAudio
counts the times `AudioUnitRender` refused while WASAPI counts buffer gaps,
refused `GetBuffer` calls, and a buffer-ready event that did not arrive, and
PipeWire counts the cycles `pw_stream_dequeue_buffer` had no buffer for. Those
are not one measurement with three names, so they are not shared.

### sipral-ffi

One narrow C ABI. Handles are opaque, ownership is explicit, and events arrive
on a callback. The expressive API is written once per language, on top.

### sipral

<a id="the-facade"></a>The facade, and the only place the two halves of the
picture are allowed to meet. An application that just wants a softphone stack
depends on this one crate and gets `sipral-ua` plus a media pipeline
re-exported under one name.

It is still the only crate with `publish = true` and the only one that ships
before the ABI freezes. The crates.io name is not held yet: the upload has not
happened.
What it now also carries is the join:

- **`CodecCatalog` and `Codec`** — what this build actually contains, in the
  order it is offered, and what one live call settled on. A name the build has
  no encoder for is refused where the order is set, with the name in the
  error, rather than dropped where it would have been used.
- **`MediaSession`** — one call's audio. It takes a `MediaPlan`, opens the
  `sipral-rtp` session, drives the `sipral-media` codec and its concealment,
  records both directions to a WAVE file when asked, and reports a stream that
  has stopped. Sans-I/O throughout: `now` arrives from the caller, no socket
  and no device are opened, and the datagrams it produces are handed back to
  the application to send.
- **`MediaEngine`** — the join proper. It writes the offer, reads the answer,
  attaches a session to a call the user agent has answered, follows it through
  hold, resume and a re-negotiated codec, and lets it go when the call ends,
  with what it cost.

The rule above stays exactly as it is: `sipral-ua` names no media crate in its
manifest and no media crate names `sipral-ua`. This one names both, which is
what makes it the seam rather than a hole in the wall. `MediaEngine` therefore
takes a `&mut UserAgent` on the three operations that genuinely need both
halves — placing a call, answering one, and draining the events — rather than
wrapping the user agent, whose sixty-odd methods would each be a place to get
registration or transfer subtly wrong on the way through.

The same pattern joins a third thing, behind its own `headless` feature:
`sipral::HeadlessSession` pairs one call's `MediaSession` with one session of
`sipral-headless`'s own sans-I/O socket protocol — PCM resampled against
whatever the negotiation actually settled on, voice activity, DTMF and call
state carried across, described in full in
[07-headless.md](07-headless.md#real-media). `sipral-headless` still names no
Sipral crate of its own, the same way `sipral-ua` and the media crates still
do not name each other; only the facade's manifest grows an edge.

All of `sipral-nat` is joined now. The RFC 7983 demultiplexing rule, the full
agent, the lite one behind `IcePolicy::Lite`, the STUN Binding client and the
TURN client are — the STUN client through `sipral::Mappings`, which asks where
each socket appears from and hands the answer to `UserAgent::readdress` for the
`Contact` and to `CallMedia::public_address` for `c=`, `m=` and the reflexive
candidate, and the TURN client through `sipral::Relays`, which allocates a
relay from a media socket before its call and hands it to `CallMedia::relay`,
where the full agent takes it over as the relayed candidate. The mapping
crosses `sipral-ua` as a `SocketAddr`; `sipral-ua` still names no NAT crate.

## What is not in the tree

- **No SIP server, proxy, registrar or B2BUA.** Sipral is an endpoint. The
  server side is a different product with different constraints, and pretending
  otherwise is how stacks become unmaintainable.
- **No WebRTC.** SDP for SIP only. No data channels, no SFU, no simulcast.
- **No video.** The audio path is deep enough to be worth doing properly. Video
  would make it shallow.
- **No global state, no singletons, no ambient logger.** Multiple independent
  stacks in one process must not interfere. The one exception is at the C
  boundary, where a handle has to be checked against something before it can
  be trusted: `sipral-ffi` keeps a process-wide table of live stacks and the
  256 tags that make a handle name only the stack that minted it. Nothing below
  the ABI reads either.
- **No `unsafe`**, except inside `sipral-ffi` and the platform I/O crates, where
  it is unavoidable. The workspace denies it everywhere else, and those two
  crates re-enable it explicitly in their own manifests.

## Errors and panics

The library never panics on input. Malformed packets are the normal case on a
public SIP port, not an exception. `unwrap`, `expect` and `panic` are lints at
warn level and unchecked indexing is denied, across the workspace;
`scripts/check.sh` runs clippy with `-D warnings`, so none of them passes the
gate, and a suppression of any of them carries a comment saying why it cannot
fire.

Errors are typed per layer and do not leak the layer below.

## Allocation

The parse path borrows from the input buffer and does not copy header values
unless the caller keeps them. Buffers are reused across packets. This is not
premature optimisation: a stack embedded in a mobile app on battery, or handling
hundreds of concurrent agent sessions in one process, is judged on exactly this.
