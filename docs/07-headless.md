<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# sipral-headless: PCM on a socket

## What it is for

An AI voice agent needs three things from telephony: answer the call, hand me
the caller's audio as it arrives, and play mine back with low enough latency
that interrupting works. Everything else is overhead.

The available options today all impose more than that. A media server with a
room abstraction, or an entire PBX, or a hosted service. Each brings its own
infrastructure, its own ports, its own operational surface, and its own latency
budget, in exchange for features the agent does not use.

An agent build is a SIP endpoint whose audio device is a socket, and
`sipral-headless` is that socket's end of it: the framing, the control
vocabulary and the session state, and nothing besides. No `CoreAudio`, no
WASAPI, no device enumeration, no room, no Redis, no port range. One process,
one call or many, raw frames both ways.

## Interface

The transport is the application's: a local Unix domain socket, a TCP socket or
a WebSocket, opened and accepted by whatever hosts the agent. This crate owns
the framing and the control vocabulary on top of it, and they are the same on
all three, so an agent written against one transport moves to another without
touching the protocol. Nothing here opens a socket, for the reason
[01-architecture.md](01-architecture.md) gives for the rest of the tree.

**Audio frames**, in both directions:

```
+--------+--------+----------------+
| u8     | u16    | payload        |
| kind   | length | ...            |
+--------+--------+----------------+
```

Audio payload is signed 16-bit little-endian PCM, mono, at the session rate
declared when the session opens: 8000, 16000, 24000 or 48000 Hz. Frame duration
is fixed per session, default 20 ms, and the same in both directions.

Raw PCM rather than an encoded format is deliberate. The agent side is a speech
model, and every transcode between it and the network costs latency and quality
for no benefit. Sipral does the codec work once, at the RTP edge.

**Control messages** on the same socket, as JSON, distinguished by `kind`:
session open and its parameters, incoming call with the caller identity,
answer, reject, hangup, DTMF received, DTMF send, call state changes, transfer,
voice activity, and an error channel.

Control and audio share a socket so ordering between "the caller stopped
speaking" and the frames around it is preserved. A separate control channel
makes that ordering ambiguous, and barge-in is exactly where the ambiguity
hurts.

## Latency

The budget is what the design is for. From the last RTP packet of the caller's
speech to the first frame delivered on the socket: jitter buffer depth plus
decode plus one frame. From a frame written on the socket to it leaving as RTP:
encode plus one frame.

**Barge-in** is a control message that discards everything queued for playback
immediately, without waiting for what is buffered to drain. Target under 100 ms
from the request to silence on the wire. This is the number the whole component
exists to hit, and it is measured in the test suite rather than asserted here.

An agent does not have to wait for its own microphone to notice the caller
started talking before it can act: **voice activity** is a control message
this crate sends on its own, `speaking: true` the frame this call's own
voice-activity detector first reads the caller's decoded audio as speech and
`speaking: false` the frame its hangover runs out, one message per transition
rather than one per frame. An agent that wants to interrupt itself the moment
the caller starts talking watches for `speaking: true` and answers with its
own `BargeIn`; the two are separate messages because deciding to barge in is
a policy this crate does not have an opinion about, and reporting activity is
a fact it can state on its own.

## Concurrency

One process holds many independent sessions. No global state, no shared buffer
pool that couples them, and no thread per call. A stalled agent on one session
does not affect another; its frames are dropped, not queued forever, and the
drop always takes the **oldest** frame a queue is holding rather than refusing
the one that just arrived — a stale frame is worse to deliver than a recent
one to have skipped, in both directions. Each queue counts how many frames it
has had to evict this way, on its own session, so an application that wants to
know its agent is falling behind reads the number rather than parsing an error
off every frame it sends. A queue opened with zero capacity — legal, if
useless — drops every frame offered to it the same way, since there is no
older frame in it to make room by.

## Real media

This crate still opens nothing and still names no other Sipral crate — that
has not changed, and will not: it is what lets the same protocol front a
completely different stack later, and what keeps its own tests running in a
millisecond with no call anywhere near them. What changed is that there is
now somewhere the frames on this socket actually go.

The join is [`sipral`](01-architecture.md#the-facade)'s, the same way the join
between signalling and media already is. `sipral` is the one crate that
depends on both `sipral-ua` and a media pipeline, so it is the one crate that
can depend on this one too without pulling either into a build that does not
want it — `sipral-headless` remains a leaf with nothing under it, so this is
one more edge pointing down, not a cycle. It sits behind its own `headless`
Cargo feature, off by default like `dtls` and `ice`: a softphone build that
never answers a call from an agent framework links none of this.

`sipral::HeadlessSession` (`crates/sipral/src/headless.rs`) is what a call
looks like once this protocol's session is paired with one: it owns a
[`Session`](crate::Session) exactly as before, plus what pairing it with a
live [`MediaSession`](../crates/sipral/src/session.rs) needs and this crate
has no way to supply on its own —

- **Rate matching.** The socket's own rate is whatever `SessionOpen` agreed
  with the application — 8, 16, 24 or 48 kHz — and it does not have to be the
  codec's. `HeadlessSession` builds a resampling filter each way from
  `sipral_media::resample::Resampler`, against `MediaSession::sample_rate()`
  as the negotiation actually settled it, not a rate the agent guessed at or
  the application hard-coded. A re-negotiation that lands the call on a
  different codec — [`MediaEvent::Changed`](../crates/sipral/src/event.rs) —
  rebuilds both filters against the new rate; the socket session's own state
  and queues are untouched by it.
- **Voice activity.** `HeadlessSession` runs its own
  `sipral_media::vad::Vad` over the caller's decoded audio — the same signal
  [`MediaSession::playback`](../crates/sipral/src/session.rs) already
  produces for the earpiece, read again rather than reached into, because
  `sipral-media` and this crate still do not know about each other — and
  turns a transition into the [`VoiceActivity`](crate::VoiceActivity) message
  above.
- **DTMF.** A digit `sipral::MediaEvent::DigitReceived` reports becomes
  [`DtmfReceived`](crate::DtmfReceived) for the sixteen keys this protocol's
  own [`DtmfDigit`](crate::DtmfDigit) names; a `DtmfSend` off the socket
  becomes a call to `MediaSession::send_dtmf`.
- **Call state.** `sipral_ua::UaEvent::IncomingCall`, `CallConfirmed` and
  `CallEnded` become this protocol's own three-state
  [`CallState`](crate::CallState) — session-local `Held` still has no wire
  counterpart, for the reason [`SessionState`](crate::SessionState)'s own
  documentation gives.

What crosses the seam is PCM, in `i16`, and the handful of facts above —
never a `MediaSession`, an `RtpSession` or a socket of any kind, which is
what keeps this crate honest about naming no Sipral crate of its own. An
application driving both ends on a real socket paces the two exactly as
`crates/sipral/examples/common/media_socket.rs`'s own `MediaSocket::turn`
paces `MediaSession` against a UDP one: on the media tick, decode this call's
audio, hand it to `HeadlessSession::hear`, and write whatever whole frames
that produced onto the socket as this crate's own audio frames (kind 0); read
what the socket offers back with [`Decoder`](crate::Decoder), push it onto
[`Session::push_playback`](crate::Session::push_playback), and let
`HeadlessSession::speak` turn it into the next frame `MediaSession::capture`
sends as RTP.

`HeadlessSession` has no socket of its own either way — the paragraph above
is the wiring an application writes, not something this type does for it —
so an embedder with no socket at all, driving a call from Rust directly
against `MediaEngine`, uses exactly the same object: it calls `hear` and
`speak` itself, in place of what a socket loop would have decoded and framed,
and reads or writes DTMF and call state as plain Rust values instead of JSON.
That is the in-process path the socket path is built the same way as, not a
second implementation of it.

## What it does not do

No speech recognition, no synthesis, no turn detection, no agent logic. Those
belong to whoever is on the other end of the socket, and putting them here would
tie the component to a model vendor.

No transcoding to Opus or MP3 for the agent side. PCM in, PCM out.

No audio device, on any platform. That is not a missing feature.
