<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
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

`length` is an unsigned 16-bit count of payload bytes in big-endian (network)
order, not counting the 3-byte header. The PCM inside an audio frame is
little-endian regardless, so the two fields use two different byte orders.

Audio payload is signed 16-bit little-endian PCM, mono, at the session rate
declared when the session opens: 8000, 16000, 24000 or 48000 Hz. Frame duration
is fixed per session, default 20 ms, and the same in both directions. It is
at least 1 ms and at most the longest frame the 16-bit length carries at the
session's rate — 682 ms at 48 kHz, 4095 ms at 8 kHz. A `SessionOpen` outside
that is refused where it is decoded (`ControlError::FrameDuration`) and not
written by `encode_control` either, so the sender hears about it on the error
channel rather than a session failing later on frames that cannot exist. The
longest frame a session carries follows from its audio: `payload_bound` says
it, and a reader that meets the session's audio only in `SessionOpen` —
`examples/agent.rs` — raises its `FrameDecoder` to that bound when it does,
rather than refusing audio longer than a control message as final.

Raw PCM rather than an encoded format is deliberate. The agent side is a speech
model, and every transcode between it and the network costs latency and quality
for no benefit. Sipral does the codec work once, at the RTP edge.

**Control messages** on the same socket, as a JSON object in the payload, told
apart by the frame's kind byte: session open and its parameters, incoming call
with the caller identity, answer, reject, hangup, DTMF received, DTMF send,
call state changes, transfer, barge-in, voice activity, and an error channel.

| Kind | Name | Fields |
|---|---|---|
| 0 | Audio | PCM, not JSON |
| 1 | SessionOpen | `sample_rate`, `frame_duration_ms?` |
| 2 | IncomingCall | `call_id`, `caller`, `display_name?` |
| 3 | Answer | `call_id` |
| 4 | Reject | `call_id`, `reason?` |
| 5 | Hangup | `call_id`, `reason?` |
| 6 | DtmfReceived | `call_id`, `digit`, `duration_ms?` |
| 7 | DtmfSend | `call_id`, `digit`, `duration_ms?` |
| 8 | CallState | `call_id`, `state: ringing\|answered\|ended`, `reason?` when ended |
| 9 | Transfer | `call_id`, `target` |
| 10 | BargeIn | `call_id` |
| 11 | Error | `call_id?`, `code`, `message` — `code` one of `protocol_violation`, `frame_too_large`, `invalid_audio_frame`, `unknown_call`, `session_not_open`, `internal`, or a vendor string |
| 12 | VoiceActivity | `call_id`, `speaking` |

Control and audio share a socket so ordering between "the caller stopped
speaking" and the frames around it is preserved. A separate control channel
makes that ordering ambiguous, and barge-in is exactly where the ambiguity
hurts.

A control message's JSON is at most `MAX_CONTROL_PAYLOAD` (8192) bytes, and
that bound holds on the way out as well as on the way in: `encode_control`
refuses a longer one rather than write a frame the far end's decoder would
refuse as final. The caller's address and display name come off an INVITE
anybody can send, so the application cuts them to fit before they go.

Only a length past the bound ends a connection — there is no knowing where
the frame it announced ends. An audio frame of the wrong size or a control
message that does not decode was still a whole frame; the decoder reads on
past it (`DecodeError::is_final` says which is which), and the refusal
belongs on the error channel, not in a closed socket.

## Latency

The budget is what the design is for. From the last RTP packet of the caller's
speech to the first frame delivered on the socket: jitter buffer depth plus
decode plus one frame. From a frame written on the socket to it leaving as RTP:
encode plus one frame.

**Barge-in** is a control message that discards everything queued for playback
immediately, without waiting for what is buffered to drain. Target under 100 ms
from the request to silence on the wire. This is the number the whole component
exists to hit, and it is measured in the test suite rather than asserted here.
What is discarded includes audio already taken off the queue and resampled for
the codec's next frame: the session counts every barge-in
(`Session::barge_ins`), and the layer holding that audio drops it the next time
it looks, so no tail of the interrupted sentence plays ahead of the next one.

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
know its agent is falling behind reads the number, `Session::capture_dropped`
and `Session::playback_dropped`, rather than parsing an error off every frame
it sends. A queue opened with zero capacity — legal, if
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
Cargo feature, off by default, unlike `opus`, `dtls`, `ice` and `stun`, which
are on: a softphone build that never answers a call from an agent framework
links none of this.

`sipral::HeadlessSession` (`crates/sipral/src/headless.rs`) is what a call
looks like once this protocol's session is paired with one: it owns a
`sipral_headless::Session` exactly as before, plus what pairing it with a
live [`MediaSession`](../crates/sipral/src/session.rs) needs and this crate
has no way to supply on its own —

- **Rate matching.** The socket's own rate is whatever `SessionOpen` agreed
  with the application — 8, 16, 24 or 48 kHz — and it does not have to be the
  codec's. `HeadlessSession` builds a resampling filter each way from
  `sipral_media::resample::Resampler`, against `MediaSession::sample_rate()`
  as the negotiation actually settled it, not a rate the agent guessed at or
  the application hard-coded. A re-negotiation that lands the call on a
  codec at a different rate — [`MediaEvent::Changed`](../crates/sipral/src/event.rs)
  — rebuilds both filters against the new rate, and drops only what was
  already at the old codec rate; the caller's audio already at the socket's
  rate, and the socket session's own state and queues, are untouched by it.
  A `Changed` that keeps the rate — a hold, a resume, a moved address —
  changes nothing at all, so an application can hand every one of them over.
  An agent driven through the C ABI or one of its bindings, with no socket
  of this protocol in between, asks for the same per call with
  `sipral_media_set_app_rate` (`08-ffi.md`, "What ABI 1.1 added"), from the
  same resampler.
- **Voice activity.** `HeadlessSession` runs its own
  `sipral_media::vad::Vad` over the caller's decoded audio — the same signal
  [`MediaSession::playback`](../crates/sipral/src/session.rs) already
  produces for the earpiece, read again rather than reached into, because
  `sipral-media` and this crate still do not know about each other — once it
  is resampled to the socket's rate, which is fixed for the session: a codec
  change never restarts the detector, whose hangover would otherwise be lost
  and the next quiet frame of a word read as its end. A transition becomes
  the `sipral_headless::VoiceActivity` message above.
- **DTMF.** A digit `sipral::MediaEvent::DigitReceived` reports becomes
  `sipral_headless::DtmfReceived` for the sixteen keys this protocol's
  own `sipral_headless::DtmfDigit` names; a `DtmfSend` off the socket
  becomes a call to `MediaSession::send_dtmf`.
- **Call state.** `sipral_ua::UaEvent::IncomingCall`, `CallConfirmed` and
  `CallEnded` become this protocol's own three-state
  `sipral_headless::CallState` — session-local `Held` still has no wire
  counterpart, for the reason `sipral_headless::SessionState`'s own
  documentation gives.

**Try it.** SIP side:
`cargo run -p sipral --example headless-socket-agent --features headless -- --host 127.0.0.1 --port 5070 --socket 0.0.0.0:7001`
(`crates/sipral/examples/headless-socket-agent.rs`; add
`--register user@domain --registrar ip:port --pass secret` to register,
`--ice-lite [--public ip]` for ICE-lite). Agent side:
`cargo run -p sipral-headless --example agent -- --addr 127.0.0.1:7001`
(`crates/sipral-headless/examples/agent.rs`), which echoes audio. The socket
is TCP, one call at a time, at 16 kHz.

What crosses the seam is PCM, in `i16`, and the handful of facts above —
never a `MediaSession`, an `RtpSession` or a socket of any kind, which is
what keeps this crate honest about naming no Sipral crate of its own. An
application driving both ends on a real socket paces the two exactly as
`crates/sipral/examples/common/media_socket.rs`'s own `MediaSocket::turn`
paces `MediaSession` against a UDP one: on the media tick, decode this call's
audio, hand it to `HeadlessSession::hear`, and write whatever whole frames
that produced onto the socket as this crate's own audio frames (kind 0); read
what the socket offers back with `sipral_headless::Decoder`, push it onto
`sipral_headless::Session::push_playback`, and let
`HeadlessSession::speak` turn it into the next frame `MediaSession::capture`
sends as RTP. `speak` hands `capture` a frame on every tick, one of silence
while the agent has nothing queued: that call is where the RTP timestamp
moves on, where a digit the agent asked for with `DtmfSend` goes out, and
where the session's own silence suppression, if configured, decides whether
the frame is sent — skipping it would stop the clock, strand the digit, and
leave a listening agent's far end with no RTP at all.

The media tick keeps its own cadence rather than catching up: a loop that
finds itself more than a tick behind — the first tick of a call answered
long after the loop began is always one — starts again from now, since
running every missed tick back to back sends RTP several times faster than
real time. And nothing on the media side waits on the agent's socket. A
write that blocks there, behind an agent that stopped reading, stalls every
call's SIP and RTP with it; the application writes from somewhere that
cannot block the loop, and what the socket has no room for yet it holds in
the order it was produced — so a `VoiceActivity` still arrives among the
frames it describes — dropping the oldest held audio past a bound, the
capture queue's own policy one step further along, and never a control
message. `headless-socket-agent.rs` is that shape, and prints how much audio
it had to drop when a call ends.

A call the application cannot take is refused at once rather than left
ringing, and the agent hears why on the error channel, under the call's id.
No RTP port to carry it on is a shortage of the host's, not a fault in the
call: 503 with a `Retry-After`, so that a server in front of several agents
tries another (RFC 3263 §4.3) and a caller retrying this one waits for a port
to come free. An offer that cannot be answered is 488; anything else the
application could not do is 500.

`HeadlessSession` has no socket of its own either way — the paragraph above
is the wiring an application writes, not something this type does for it —
so an embedder with no socket at all, driving a call from Rust directly
against `MediaEngine`, uses exactly the same object: it calls `hear` and
`speak` itself, in place of what a socket loop would have decoded and framed,
and reads or writes DTMF and call state as plain Rust values instead of JSON.
That is the in-process path the socket path is built the same way as, not a
second implementation of it.

## On a public server: ICE-lite

An agent answering a WebRTC gateway, or any peer that will send media only on
a path it has checked, has to speak ICE. On a server with a public address it
does not need the whole of it: it is the ICE-lite endpoint RFC 8445 describes,
which advertises where it is, answers the checks the full peer sends, and
carries the audio on the pair that peer nominates. `sipral::IcePolicy::Lite`
is that, on a call's codec catalogue, and it exists only in a build with
`headless` (and `ice`) or the facade's own `ice-lite` — the softphone's build
cannot turn it on, because behind a NAT it is worse than no ICE at all. An
agent driven through the C ABI instead asks for it as `SIPRAL_ICE_LITE`, and
brings none of `sipral-headless` with it. `docs/06-nat.md#ice-lite` has what
it does on the wire, and why.

It is off unless the application asks. `headless-socket-agent --ice-lite`
asks, and answers every call with it; `--public ip` is for a server behind a
one-to-one NAT, where the address to advertise is not the one the socket is
bound to. What an application has to add to its loop is what it already does
for a DTLS-SRTP call: after handing a datagram to `MediaSession::receive`,
send whatever `MediaSession::poll_transmit` hands back, from the same socket
— that is where the answers to the peer's checks come from. The call has no
audio going out until the peer nominates a pair, and `MediaEvent::PathChosen`
says when it has; a peer that does no ICE gets its call on the signalled
address as before.

The lab proves it both ways (`scripts/lab.sh ice`): a call that requires ICE,
placed straight at the agent by the interop harness acting as the full peer,
with the reference agent's echo coming back on the chosen pair; and Asterisk's
own ICE calling the agent registered to it.

## Bridging a call to a voice agent that speaks SIP

Some voice agents are SIP endpoints themselves: a hosted realtime model or
an agent platform answers an INVITE at an address of its own and runs the
whole conversation. For those nothing on this page is needed, and no vendor
protocol either. The agent is a SIP address, and what sits between it and a
PBX is a phone line that forwards its calls there:

1. Register on the PBX as an extension, or take what a trunk sends.
2. On an incoming call, ring it (a plain 180, so the PBX plays its own
   ringback) and place a second call, to the agent's address.
3. When the agent answers, answer the caller, and join the two calls in a
   local conference made without this end (`LocalConferenceConfig::local`
   `None`, `sipral_local_conference_config_t::local` off): two members, each
   on its own codec and rate, one audio stream each.
4. Forward digits from the events. The conference mixes audio, and a
   telephone event is not audio: a `DigitReceived` from one leg (RTP or
   INFO, not one heard in the audio, which the mix already carries) is a
   `send_dtmf` on the other.
5. Either leg ending ends the other. The PBX's leg ends saying how the
   agent's part went — `human`, `callback`, `resolved`, `unresolved` or
   `expired` — in an `X-Sipral-Outcome` field on the BYE, or, for a PBX that
   reads no field off a BYE, as a REFER of the caller's call to an address
   set for that outcome.
6. A REFER from the agent is the agent asking for a person. One function
   decides what it means: by default a user part that names an outcome other
   than `human` ends the call with it, and any other target is the same user
   at the PBX's domain, reached by REFERring the caller's call to the PBX, so
   the PBX places the new call and owns all of it. Placing that call from the
   bridge and joining it in the agent's place is the other choice. The
   agent's REFER is not taken with `accept_transfer`, which would place the
   call from the agent's account, on the agent's transport: it stays open
   while the PBX works, is refused with the PBX's own failure, and ends with
   the agent's call when the transfer succeeds. A REFER the PBX refuses
   outright raises no event, only the NOTIFYs of one it took do, so ten
   seconds without a word from the PBX is read as a refusal.

The caller's number and display name, and the PBX INVITE's own `X-` fields,
go on the INVITE to the agent (`X-Sipral-Caller-Number`,
`X-Sipral-Caller-Name`, `X-Sipral-Called`), for an agent platform that hands
an INVITE's fields to the application. The agent's call can be given a
longest duration, after which it is hung up and the call ends as `expired`.

**Try it.** `crates/sipral/examples/agent-bridge.rs`, whose logic is
`examples/common/agent_bridge.rs` and is what `tests/agent_bridge.rs` runs
between three stacks on loopback:

```text
cargo run -p sipral --example agent-bridge [--features example-tls] -- \
    --pbx 192.0.2.10:5060 --register bridge@pbx.example --pass secret \
    --agent 'sip:agent@203.0.113.7:5060'
```

| Flag | What it does |
|---|---|
| `--pbx host:port` | the PBX; calls to a transfer's or an outcome's address go there |
| `--register user@domain`, `--pass` | register as that extension; without them, take what a trunk sends to `--port` |
| `--agent uri` | the agent's address; `sips:` or `;transport=tls` is called over TLS (built with `example-tls`) |
| `--agent-address host:port` | where the agent's server is, when its address's host is not |
| `--pin sha-256` | trust the agent's TLS certificate by its fingerprint instead of the platform's roots |
| `--transfer refer\|bridge` | how a transfer reaches the person: a REFER to the PBX (default), or a call bridged here |
| `--outcomes header\|refer`, `--outcome-uri name=uri` | how the PBX hears the outcome |
| `--max-agent-seconds n` | the agent's longest call |
| `--copy-headers list` | the INVITE fields passed on, `*` ending a prefix (default `X-*`) |
| `--invite-burst n` | calls the PBX may offer at once (the stack's guard lets ten) |
| `--host ip`, `--port n` | the address advertised to both, the route to the PBX by default |

`integrations/agents/sipral_agents/sip_bridge.py` (`python -m
sipral_agents.sip_bridge`, in the `sipral-agents` package) is the same
bridge over the C ABI, configured from the environment as `agent.py` is: `SIPRAL_AOR`,
`SIPRAL_REGISTRAR`, `SIPRAL_REGISTRAR_ADDRESS`, `SIPRAL_AUTH_USER` and
`SIPRAL_AUTH_PASSWORD` for the line; `SIPRAL_AGENT_URI` and
`SIPRAL_AGENT_ADDRESS` for the agent (TLS and TCP both), `SIPRAL_TLS_CA` to
trust; `SIPRAL_TRANSFER`, `SIPRAL_OUTCOMES`, `SIPRAL_OUTCOME_URIS`
(`callback=sip:800@pbx.example,...`), `SIPRAL_AGENT_MAX_SECONDS`,
`SIPRAL_COPY_HEADERS` and `SIPRAL_INVITE_LIMIT=voice-agent`. The Python
layer has no `ring`, `transfer` or `set_headers` on a call and no fields on
`place_call`, though the C ABI has all four: that example answers at once
and plays its own ringback, reaches `sipral_call_transfer` and
`sipral_call_set_headers` through the layer's own C bindings, and prints the
caller's context instead of sending it.

The lab runs the Rust bridge registered on its Asterisk, with the Python
layer's `agent.py` as the agent, and then with many calls at once to the
headless agent's echo (`scripts/lab.sh bridge`).

Agents of this kind publish addresses of these forms (from their own
documentation; not tested here):

- OpenAI Realtime: `sip:<project id>@sip.api.openai.com;transport=tls`,
  on port 5061, the call accepted by the application through a webhook.
- ElevenLabs Agents: `sip.rtc.elevenlabs.io`, over UDP or TCP on 5060 or TLS
  on 5061, G.711 or G.722.
- Vapi: `sip:<id>@sip.vapi.ai`, or `sip.eu.vapi.ai`.

## Pipecat

An agent written in Python needs no socket between it and the call: the
Python binding's application audio mode hands each call's decoded frames to
the process that answered it, and `sipral-pipecat`
([`integrations/pipecat`](../integrations/pipecat/)) carries them
into a [Pipecat](https://github.com/pipecat-ai/pipecat) pipeline.
`SipralTransport` is one call as a Pipecat transport -- the caller's frames
in at the call's own rate for Pipecat to resample, the pipeline's audio out a
codec frame at a time in real time so that an interruption silences it within
100 ms, DTMF both ways, the call's end ending the pipeline and the pipeline's
end hanging up -- and `serve` answers every call to an account with a
pipeline of its own, many calls to one process.

Without a framework, `sipral-agents`
([`integrations/agents`](../integrations/agents/)) joins each call to a
voice-agent service over its WebSocket API -- OpenAI Realtime, Gemini Live,
ElevenLabs Agents, Vapi or Deepgram Voice Agent -- with the frames at the service's rate, barge-in, reconnection and
either side's end ending the other (`24-voice-agents.md`).

## What it does not do

No speech recognition, no synthesis, no turn detection, no agent logic. Those
belong to whoever is on the other end of the socket, and putting them here would
tie the component to a model vendor.

No transcoding to Opus or MP3 for the agent side. PCM in, PCM out.

No audio device, on any platform. That is not a missing feature.
