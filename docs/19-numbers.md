<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Numbers

What this library costs, measured with `scripts/bench.sh` rather than
estimated. Every figure below says which machine, which version and which day
it came from, because a number without those three is not reproducible and a
number nobody can reproduce is marketing.

Run it yourself:

```bash
./scripts/bench.sh
```

It builds the shared library, measures it, and runs `sipral-ffi`'s own load
test twice — two hundred calls on four threads, then one call — printing what
each run cost. The load test is a test before it is a measurement: the same
run fails if any thread was ever told another call's session was busy, which
is the claim these numbers are only worth reading beside. Then it runs the
signalling test twice, a hundred calls between two stacks and then a
thousand, which fails in the same way if any call ends wrongly or any message
goes missing.

## What is measured, and what it is not

**Measured here:** the library's own cost, in one process, with no network
underneath it. Audio is fed in through `sipral_media_receive` — the entry
point a transport calls — and taken out through `sipral_media_playback`, both
against calls brought up from a written SDP answer rather than a socket.

**Measured elsewhere:** anything that needs a peer. End-to-end audio quality,
delay and loss under impaired links are the lab's
(`scripts/lab.sh`, `docs/11-testing.md`); a call's own R factor and mean
opinion score come from RTCP-XR on a real call (`docs/05-media.md`).

**Not measured yet:** an hour-long call's drift, and the same load on a
mobile processor.

## 23 September 2026 — `0.0.1`

Apple M-series, macOS, `rustc 1.95.0`, release profile, a minute of audio per
call. Ranges rather than single figures where several runs disagreed: the
machine was doing other work at the time, which is the ordinary case and the
honest way to report it.

| What | Number | How |
|---|---|---|
| Shared library, `libsipral_ffi.dylib` | 2.79 MB | as built; the release profile carries no debug information, so stripping it changes nothing |
| Audio, per frame of 20 ms, 200 calls on 4 threads | 1.8–2.7 µs of thread time | `sipral_media_receive` and `sipral_media_playback` together, G.711 through the jitter buffer |
| The same, one call | 0.3–0.4 µs | the difference is contention and cache, not locking: no call ever waited on another |
| 200 calls, a minute of audio each | 600 000 frames in 0.3–0.4 s of wall time | four threads on one stack |
| Opening a stack | 56 µs–4 ms | the first stack in a process pays for its own lazy initialisation; a later one does not |
| Bringing one call up | 69–161 µs | placing the INVITE, reading the answer, opening the session |
| Memory per call | 1.4–1.7 KB | the difference in peak resident memory between the 200-call run and the one-call run, divided by 199 |

The same run inside a `rust:1.95-trixie` container on a Linux x86-64 machine,
eight cores given to it: **2.6 µs** per frame with two hundred calls, 1.0 µs
with one, 223 µs to open a stack and 259 µs to bring a call up. Its memory
figures are not recorded here — the first run of the script there measured
the compiler as well as the library, which is what the `--no-run` build the
script now does first exists to prevent, and it has not been rerun since.

Two hundred calls at 50 frames a second is 10 000 frames a second; at 2 µs
each that is about 20 milliseconds of one core per second of audio, two per
cent of a single core. The load test's own assertion is far looser — a frame
may cost up to 2 ms of thread time before it fails — because what it guards
is a regression, not this machine's figure.

## 24 September 2026 — `0.0.1`, signalling

`crates/sipral-ffi/tests/signalling_load.rs`, run by `scripts/bench.sh`. Two
stacks, each a user agent and a media engine — what one `sipral_stack_new`
holds — call each other in one process with no network between them, a
hundred calls at once and then a thousand. Every call goes the way a call on
a PBX goes: the INVITE is challenged with a 401, sent again with digest
credentials (MD5, `qop=auth`, checked by the test the way a server checks
them), answered with a 100, a reliable 180 and its PRACK, a 200 and its ACK,
then held by a re-INVITE, resumed by another and hung up with a BYE:
twenty-one messages and six transactions a call. Each phase runs for every
call before the next starts, so each stack holds all the calls at once.

The same run is a test. It fails if any call does not end the way it was
ended — hung up at the calling end, hung up on at the other — if the messages
that crossed differ by one from what that exchange makes, in either
direction and by kind, and if anything is sent once the clock has been run
forty seconds past the hangups, beyond the last timer any RFC 3261
transaction keeps. The gate runs it on every commit, at a hundred calls.

Thread time is what each stack spent inside the library, measured around
every call into it: placing, receiving, polling, answering, holding,
hanging up and running its timers — writing the offer and the answer and
opening each call's media session included, since that is part of setting a
call up in this stack. The far end's half of the digest exchange, which a
user agent never does, is outside it. "Per transaction" is the whole run's
thread time over the six transactions a call makes. Memory is counted by the
test's own allocator, not read from the operating system: what each half of
each stack gives back when it is dropped, holding all the calls against
holding none, over the number of calls — signalling (the user agent and its
endpoint: dialogs, transactions, the messages they keep) apart from media
(the media engine and one idle G.711 session per call). "Settled" is forty
seconds after the calls came up, once the transactions that brought them up
are gone; "fresh" is straight after.

Apple M2, macOS, `rustc 1.95.0`, release profile. The machine was shared with
other builds throughout — a load average between eleven and sixteen on eight
cores — so the ranges are wide, and the low end is the one taken when it was
least busy.

| What, a hundred calls | Calling end | Answering end | How |
|---|---|---|---|
| Setting one call up | 187–424 µs | 390–833 µs | thread time from the first INVITE to the ACK, per call |
| One transaction | 52–112 µs | 125–265 µs | the whole run's thread time over six transactions a call |
| Messages a second, one stack | 31 000–68 000 | 13 000–28 000 | messages written and read over the stack's own thread time |
| A live call, signalling, settled | 16.1 KB | 17.3–17.5 KB | the user agent's share |
| The same, fresh | 18.0 KB | 22.6 KB | while the transactions that set it up still run |
| A live call, media | 35.3 KB | 35.3 KB | the media engine's share: one idle G.711 session |

A thousand calls, same machine: 204–578 µs and 544–1 483 µs to set a call up,
60–165 µs and 168–450 µs a transaction, 17.2 KB and 15.1 KB of signalling a
settled call. Past 128 calls the defaults turn calls away — 128 dialogs and
256 server transactions, a softphone's ceiling and a flood's
(`EndpointConfig`) — so the thousand-call run raises both, as a media server
built on this stack would; the hundred-call run measures the stack as it
ships.

The same test inside a `rust:1.95-trixie` container on the Linux x86-64
machine, an Intel Xeon E5-2698 v4 at 2.2 GHz with eight cores given to it and
nothing else running: a hundred calls cost **346 µs** of thread time to set
one up at the calling end and **640 µs** at the answering end, 91 µs and
191 µs a transaction, 38 600 and 18 300 messages a second; a thousand calls
cost 392 µs and 974 µs, 125 µs and 301 µs, 28 000 and 11 600. Memory is the
same to within a few dozen bytes: 16.1 KB and 17.3 KB of signalling a settled
call, 35.2 KB of media.

Read together:

- **The answering end costs about twice the calling end.** It answers four
  INVITEs, a PRACK and a BYE where the calling end sends them, with a 100
  for each INVITE and a server transaction for each request; which part of
  that accounts for the difference is not broken down here. The digest
  response the calling end computes is not what makes a call expensive: the
  calling end is the cheaper of the two with it.
- **A hundred calls set up in a burst cost one core about 60 ms at the
  answering end.** A dialler that brings a hundred calls up a second spends
  under a tenth of a core on the signalling for them, by the Linux figure;
  a contact centre's switchboard answering them spends about the same.
- **The cost of a call grows with the number of calls around it.** From a
  hundred calls to a thousand the answering end's cost per call rises by half
  on the Linux machine. `MediaEngine::poll_event` looks at every live
  session, and takes its lock, each time it is asked for the next event, so
  every signalling event costs a little more for each call already up. A
  softphone never sees it; a server holding thousands of calls on one engine
  would, and it is the first thing to change before anybody plans around a
  thousand-call figure.
- **A call's memory is mostly its media session.** 35 KB of the roughly
  51 KB one end holds for a live call is the idle G.711 session, against
  16–17 KB for everything the signalling keeps. A hundred calls on one stack
  hold about 5 MB.
- **The 23 September figure for memory per call is not the one to use.**
  "1.4–1.7 KB" there is the difference in peak resident memory between two
  `cargo test` runs, and the timer around them reports the largest process
  in the tree, which is cargo: 42 MB for either run, and on this day's run
  the one-call run peaked higher than the two-hundred-call one. The media
  load test's own binary, timed directly on the same machine, peaks at
  4.7 MB with one call and 20.2 MB with two hundred — about 78 KB a call of
  resident memory, against the 51 KB the allocator above counts at one end.
  `scripts/bench.sh` still reads it through cargo, and its memory line should
  not be quoted until it does not.

What a real peer adds — a proxy's and a PBX's own processing, and the
network — is not in these figures; a hundred calls through the lab's
Kamailio to FreeSWITCH or to Asterisk has not been run.

## What would make these numbers worse

A codec that is not G.711: Opus costs an encode and a decode of its own, and
is not in the numbers above. Recording a call writes every frame to disk.
SRTP adds a pass over each packet. Each is worth measuring separately before
anybody plans around the figures here.
