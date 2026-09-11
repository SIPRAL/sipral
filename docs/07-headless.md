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
and an error channel.

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

## Concurrency

One process holds many independent sessions. No global state, no shared buffer
pool that couples them, and no thread per call. A stalled agent on one session
does not affect another; its frames are dropped with an event, not queued
forever.

## What it does not do

No speech recognition, no synthesis, no turn detection, no agent logic. Those
belong to whoever is on the other end of the socket, and putting them here would
tie the component to a model vendor.

No transcoding to Opus or MP3 for the agent side. PCM in, PCM out.

No audio device, on any platform. That is not a missing feature.
