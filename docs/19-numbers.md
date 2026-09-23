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
is the claim these numbers are only worth reading beside.

## What is measured, and what it is not

**Measured here:** the library's own cost, in one process, with no network
underneath it. Audio is fed in through `sipral_media_receive` — the entry
point a transport calls — and taken out through `sipral_media_playback`, both
against calls brought up from a written SDP answer rather than a socket.

**Measured elsewhere:** anything that needs a peer. End-to-end audio quality,
delay and loss under impaired links are the lab's
(`scripts/lab.sh`, `docs/11-testing.md`); a call's own R factor and mean
opinion score come from RTCP-XR on a real call (`docs/05-media.md`).

**Not measured yet:** an hour-long call's drift, a hundred calls' worth of
signalling rather than media, and the same load on a mobile processor.

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

## What would make these numbers worse

A codec that is not G.711: Opus costs an encode and a decode of its own, and
is not in the numbers above. Recording a call writes every frame to disk.
SRTP adds a pass over each packet. Each is worth measuring separately before
anybody plans around the figures here.
