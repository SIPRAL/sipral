<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# 18 — Deterministic replay

`docs/13-client-requirements.md` calls this D2. It lives in
`crates/sipral-core/src/replay/`, and it is the second half of the pair whose
first half is `docs/14-diagnostics.md`: the record says what the stack
decided, and a recording is the session it decided it about.

## The problem it replaces

The failures that cost the most happen on one PBX, on one carrier, behind one
NAT, and do not happen in a laboratory. They are diagnosed by reasoning about
a packet capture, shipping a guess, and waiting a week to hear whether the
guess was right. The loop is long because the evidence is inert: a capture can
be read, and it cannot be run.

A recording can be run. The session that failed comes back as a file, the fix
is proved against the conditions that produced the bug, and the file stays in
the tree afterwards as a test that it does not come back. That last part is
the standard the rest of this project already holds itself to — a fix has to
be shown to bite by failing without it — extended to the failures that until
now could not be reproduced at all.

## Why this is nearly free here

It is the sans-I/O design collecting a dividend, and it is the reason to build
this here rather than wish for it in the application.

Most of what enters the stack enters through `Endpoint::receive` and
`Endpoint::handle_timeout`, and the time they work from is the caller's rather
than the clock's — D9, which `scripts/check.sh` enforces as a build gate. So a
session **is** the sequence of those calls (and, where a resolver answered
one, `Endpoint::resolved`) and the offsets they were made at. A recording is
that sequence written down, and a replay is making the calls again. There is
nothing to simulate, no network to fake and no clock to freeze, because none
of the three was ever there.

The same shape is why a recording is not tied to a layer.
`sipral_core::replay::Driven` is those calls as a trait, `Endpoint` and
`UserAgent` both implement it, and a session taken from a phone is therefore
replayed into whichever layer the bug is thought to be in. The same replay is
how a recording becomes a capture of both directions:
`sipral_diag::export_replayed` places every message the replayed layer writes
beside what arrived, in one pcapng (`docs/14-diagnostics.md`).

## What a recording holds

**The seed.** Thirty-two bytes, and every branch, tag, `Call-ID` and `cnonce`
the stack writes is derived from it — **and nothing else is.** Without it a
replay writes different requests, and the recorded answers — which echo `Via`,
`From`, `To`, `Call-ID` and `CSeq` — no longer belong to anything the replay
sent. A recording that did not carry the seed would replay into a different
call and would not say so.

It is not the seed the stack was built with. Anyone holding that one could
work out every `Call-ID`, tag, branch and SSRC the stack will ever draw, and
address in-dialog requests or RTP to calls they never saw; a recording is a
file that gets handed to people. So `UserAgent::start_recording` moves the
endpoint onto a fresh seed (`Endpoint::reseed`), drawn from a stream derived
one way from the stack's own, and the recording carries that one;
`stop_recording` moves the endpoint onto another. A replay built with the
recording's seed draws exactly what the stack drew while it recorded, and
nothing drawn before or after it can be predicted from the file.

The media keys are not in that list, and the format has no field for them.
They come from a second seed the application supplies to `MediaEngine::new`,
which is never written here. The two are separate for exactly this reason: a
recording is meant to reproduce a session, not to decrypt one. A consequence
worth expecting — replaying a secured session produces a *different*
`a=crypto` from the one recorded, deliberately, because the key that made the
original is not in the file and cannot be derived from what is.

**The frames**, each with how far into the session it was, from the first
frame rather than from a wall clock:

- **an arrival** — a datagram, a stream read, a stream that closed, a
  transport that came up, a transport that failed. The five shapes of
  `Input`, which is the whole of what arrives.
- **a wake** — a deadline the application came back at. Recorded because the
  deadlines are part of the session: whether a retransmission went before the
  answer arrived is a fact about the run, not a detail of the loop.
- **a resolved answer** — `Endpoint::resolved`: the dialog it named, the
  transport the lookup named (`-` for none), and the addresses it was given.
  Unlike a cue this is data rather than a name, so a replay repeats it exactly
  instead of asking the caller to.
- **a cue** — the application acting on its own, under a name the application
  chose. Placing a call, answering one, registering an account: none of those
  arrive from anywhere, so no recording can feed them back. What it does
  instead is say when they happened and what they were called, and hand the
  name back at the same offset so that the replay does the same thing in the
  same order.

**A note**, one line of prose, because a recording arrives from somebody who
cannot be asked a follow-up question.

## What it cannot hold, and why that is structural

**It never contains audio.** Not by convention, and not because the writer
declines to put it there:

- Media never reaches this layer. RTP arrives at `sipral-rtp` on another
  socket and is never an `Input`. The format does not omit a media frame; it
  has none to define.
- The transcript is text. A payload is written as `|` lines, one line of the
  message to a line of the file, with four escapes and no others — `\\`,
  `\r`, `\n` and `\t`. There is no `\x`, no `\u`, no base64 and no
  length-prefixed blob anywhere in the grammar, so a byte outside text has no
  spelling.
- That rule is a type rather than a habit. `replay::Payload` is the only way
  to put bytes in a frame, its only constructor refuses anything that is not
  text, and both the recorder and the reader go through it. A frame of G.711
  cannot be written into a recording and cannot be read out of one.
- And there are only two doors. A `Recording` is obtained from
  `Recorder::finish` or from `Recording::parse`, never assembled from frames
  by a caller, so there is no third path that could reach the writer with
  something neither of them would have accepted.

**The boundary that comes with it, stated rather than hidden:** a message with
a binary body cannot be recorded either. A recorder handed one refuses, and
the refusal spoils the whole recording rather than dropping the body — a
recording holds every byte the stack was fed or it does not exist. In the
traffic this exists for that costs nothing, because SIP and SDP are text; a
build that has to record binary bodies needs a new version of the format (4
or later), and `Recorder::finish` says so instead of guessing.

It also holds no configuration. See the boundaries below.

## The version rule

The first line is `sipral-recording 3`.

A reader that meets a higher number **refuses the file and says so** —
`ReadError::Version { found, supported }` — rather than reading the lines it
recognises and ignoring the rest. A later version may have changed what one of
those lines means, and a recording is fed into a state machine: a replay that
quietly took a wrong turn would report a result that looks exactly like a
real one. Every other line is read the same way. A line the reader does not
understand stops the read; it is never skipped. A version 1 file is still read
without complaint, because it has no `resolved` lines. A version 2 file reads
the same way unless it has a `resolved` line. That line is refused as
`ReadError::Syntax`, not `ReadError::Version`, because version 3 added a token
to it. Re-record such a session, or insert `-` after the dialog id on each
`resolved` line and change the banner to 3.

The version rises when what an existing line means changes, or when a frame is
added that a version 1 reader would have to understand to replay the session
correctly. Version 2 is the second case: `resolved` lines
(`Endpoint::resolved`, above) carry an address a version 1 replay would send
nothing to, so a version 1 reader is made to refuse the file rather than
replay the session at the wrong destination.

Version 3 is the second case again: `Endpoint::resolved` learned the transport
an RFC 3263 lookup names, so a `resolved` line carries a protocol token (`-`
for none) between the dialog and the addresses, and a version 2 reader would
take that token for an address.

## The file

This is `fixtures/replay/registration-challenged.sipralrec`. A phone
registering, a registrar that challenges, the retry with credentials, the
binding granted for an hour, and the refresh fifty-one minutes later.

```
sipral-recording 3
seed 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
note a registrar that challenges, a binding granted for an hour, one refresh
+0.000000000 bound 1 UDP 192.0.2.1:5060 -
+0.000000000 cue register
+0.040000000 datagram 1 192.0.2.9:5060 192.0.2.1:5060
| SIP/2.0 401 Unauthorized\r\n
| Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK8ee39ff3ad4bdce497364379bef2d1fe;rport\r\n
| From: <sip:alice@example.com>;tag=f3f87c38c7910810adc9525948eab095\r\n
| To: <sip:alice@example.com>\r\n
| Call-ID: e49c8d74a73c5bdf49b1186b53e0e547\r\n
| CSeq: 1 REGISTER\r\n
| WWW-Authenticate: Digest realm="example.com", nonce="abc123", qop="auth"\r\n
| Content-Length: 0\r\n
| \r\n
+0.095000000 datagram 1 192.0.2.9:5060 192.0.2.1:5060
| SIP/2.0 200 OK\r\n
…
+5.040000000 wake
+5.095000000 wake
+3060.095000000 wake
```

An offset is `+seconds.nanoseconds`, always nine digits, which is what an
`Instant` holds and therefore what the session was driven at. Frames are in
order and a reader refuses one stamped before the frame above it. A `-` in a
`bound` line is a datagram socket, which has no single far end.

The whole thing is readable without a tool, which is deliberate: it travels by
mail and through ticket systems, and it is quoted in bug reports. A carriage
return that a mail gateway added at the end of a line is dropped on the way
in; a carriage return inside a message is spelled `\r` and is never the last
character of a line of the file.

## What replay reproduces, and what it does not

**Exactly**, and this is what the tests assert rather than assume — the two
runs are compared byte for byte, event for event, and record for record:

- every byte the stack writes, and in what order;
- every event the application is handed;
- the diagnostic record of `docs/14-diagnostics.md`, entry for entry,
  including the microsecond offsets — which is the stack's own answer to
  whether it made the same decisions;
- the timing, to the nanosecond, relative to whatever instant the replay is
  started at.

**Not, and each of these is a real limit:**

- **The far end.** A recording is a script, not a peer. The answers in it were
  written for the requests the recorded build sent, and they echo that build's
  branch, tags and `Call-ID`. Change what this end writes — a new header, a
  different tag — and the recorded answers may match nothing and be discarded.
  That is a loud failure rather than a quiet one, and it is the price of a
  recording that is a fixed piece of evidence.
- **The application.** What the application did on its own is named, not
  captured. A replay that ignores its cues drives a stack that never sends
  anything; there is a test that says exactly that.
- **The configuration.** `EndpointConfig` is the application's and is not in
  the file. A replay under different timers or a different parse mode is a
  different run, and nothing here can tell. A recording made under the
  defaults needs nothing said about it; one made under anything else says so
  in its `note`.
- **Anything that changes the stack from outside `receive`, `handle_timeout`
  and `resolved`.** Those three are the whole of what a sans-I/O core lets in,
  which is the reason this works at all — but a layer that grows a fourth way
  in has to record it too or the recordings of it are incomplete, the way
  `resolved` itself once was: two runs that called it differently produced the
  identical recording text right up until version 2 gave it a frame of its
  own.
- **The wall clock.** Offsets are from the first frame. A session that
  depended on the time of day would not be reproduced, and nothing in these
  crates depends on it, because nothing in them reads it.

## Replaying one

```rust
let recording = Recording::parse(&text)?;
let mut agent = UserAgent::new(config, recording.seed())?;
let mut replay = Replay::new(&recording, origin);
while replay.next_at().is_some() {
    match replay.step(&mut agent)? {
        Some(Played::Cue(label)) => { /* repeat the application's action named by label */ }
        Some(Played::Fed) => {}
        None => break,
    }
    while let Some(tx) = agent.poll_transmit() { /* compare or discard */ }
    while let Some(ev) = agent.poll_event() { /* assert */ }
}
```

## How a support engineer produces one

The simplest way is built in. `UserAgent::start_recording(Some("note"))`
starts one, and `UserAgent::stop_recording()` hands back the `Recording` (or
the `RecordError`), or `None` when nothing was being recorded. From C, `sipral_stack_recording_start` and
`sipral_stack_recording_stop` do the same and copy out the text. Both use a
seed drawn for the recording, as above. They record arrivals and wakes only, with no
cues and no `resolved` answers, so a replay of one has to repeat the
application's own actions itself.

The recorder can also be driven by hand, which is what a layer with cues or
`resolved` answers of its own needs. It is passive: it is told about the
calls the driver is already making, and it never reads a clock of its own.
Its seed must be the 32 bytes the endpoint is drawing from when it starts:
the ones passed to `Endpoint::new` or `UserAgent::new` for a recording from
the first frame, or, better, what `Endpoint::reseed` returns at that moment,
followed by another `reseed` when the recording ends, so the file carries no
seed that outlives it.

```rust
let mut recorder = Recorder::new(seed).about("Asterisk 20.5, one-way audio after hold");

recorder.arrived(&input, now);          // beside every UserAgent::receive
agent.receive(input, now)?;

recorder.woke(now);                     // beside every UserAgent::handle_timeout
agent.handle_timeout(now);

recorder.resolved(dialog, &addresses, protocol, now); // beside every Endpoint::resolved

recorder.cue("answer", now);            // beside anything the application does
agent.answer(call, sdp, now)?;

let text = recorder.finish()?.to_text(); // and this is the file
```

`finish` is the only call that can refuse, and a refusal means the recording
was never whole. A long-running driver reads `Recorder::spoiled()` and stops
early rather than finding out at the end.

The file carries no key of this end's and permits deriving none. What it does
carry, beyond the seed, is what was on the wire — which is what a capture
would have carried. It is not the diagnostic record of
`docs/14-diagnostics.md`, which is safe to send without being read: **a
recording holds messages, so it holds whatever the messages held.** A `To` and
a `From` name the parties, an SDP names the addresses, an `Authorization`
holds the digest response, and a recorded *inbound* SDP for a secured call
holds the far end's `inline:` key exactly as it arrived. Anyone asking a user
to send one should say so, and this is why the two artefacts are separate.

## The recording in the tree

`fixtures/replay/registration-challenged.sipralrec` is a capture rather than a
document: it is what `record()` in `crates/sipral-ua/src/replay_tests.rs`
writes when the session is run, and a test says so, printing the new text when
it drifts. Four tests use it. It replays into the registration the recording
says it is; it replays twice into two agents that share nothing and gives the
same run both times; it replays into a bare `Endpoint`, which has no policy
for a registration and therefore sends nothing; and it is the text a live run
produces.

A recording that comes in from the field joins it in the same directory, with
the bug it belongs to in its `note`, and it is a test from that day on.
