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

**Measured in the lab, and recorded here:** an hour on a call, and what the
jitter buffer did about two clocks for all of it (`scripts/lab.sh drift`,
below).

**Not measured yet:** the same load on a mobile processor; a frame of Opus
rather than G.711; the delay from one end's microphone to the other's
earpiece in the lab; a hundred calls through a real proxy and PBX rather than
between two stacks in one process; the media load test's memory on Linux; and
drift on a path with loss and jitter, where the buffer's target is more than
the one frame a clean path gives it.

## 23 September 2026 — `0.0.1`

Apple M-series, macOS, `rustc 1.95.0`, release profile, a minute of audio per
call. Ranges rather than single figures where several runs disagreed: the
machine was doing other work at the time, which is the ordinary case and the
honest way to report it.

| What | Number | How |
|---|---|---|
| Shared library, `libsipral_ffi.dylib` | 2.79 MB | as built; the release profile carries no debug information, so stripping it changes nothing |
| Audio, per frame of 20 ms, 200 calls on 4 threads | 1.8–2.7 µs of wall time | `sipral_media_receive` and `sipral_media_playback` together, G.711 through the jitter buffer, timed by the wall clock on each of the four threads |
| The same, one call | 0.3–0.4 µs | the difference is contention and cache, not locking: no call ever waited on another |
| 200 calls, a minute of audio each | 600 000 frames in 0.3–0.4 s of wall time | four threads on one stack |
| Opening a stack | 56 µs–4 ms | the first stack in a process pays for its own lazy initialisation; a later one does not |
| Bringing one call up | 69–161 µs | placing the INVITE, reading the answer, opening the session |
| Memory per call | not measured | the 1.4–1.7 KB first given here was cargo's own peak memory, not the test's: see 24 September |

The same run inside a `rust:1.95-trixie` container on a Linux x86-64 machine,
eight cores given to it: **2.6 µs** per frame with two hundred calls, 1.0 µs
with one, 223 µs to open a stack and 259 µs to bring a call up. Its memory
figures are not recorded here — the first run of the script there measured
the compiler as well as the library, which is what the `--no-run` build the
script now does first exists to prevent, and it has not been rerun since.

Two hundred calls at 50 frames a second is 10 000 frames a second; at 2 µs
each that is about 20 milliseconds of one core per second of audio, two per
cent of a single core. The load test's own assertion is far looser — a frame
may cost up to 2 ms of wall time before it fails — because what it guards
is a regression, not this machine's figure.

## 24 September 2026 — `0.0.1`, signalling

`crates/sipral-ffi/tests/signalling_load.rs`, run by `scripts/bench.sh`. Two
stacks, each a user agent and a media engine — what one `sipral_stack_create`
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

Time is what each stack spent inside the library, read off the wall clock
around every call into it, on the one thread making them all: placing,
receiving, polling, answering, holding, hanging up and running its timers —
writing the offer and the answer and opening each call's media session
included, since that is part of setting a call up in this stack. It is not
the processor time the operating system charged the thread, so a machine
busy with other work reads slower; that is why the ranges below are wide. The
far end's half of the digest exchange, which a user agent never does, is
outside it. "Per transaction" is the whole run's time inside the library,
the forty seconds of timers after the hangups included, over the six
transactions a call makes. Memory is counted by the
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
least busy. A review later the same day, at a load average between four and
seven, read lower still: a call set up in 124–203 µs and 254–403 µs, a
transaction in 33–47 µs and 80–106 µs, 75 000–106 000 and 33 000–44 000
messages a second. Those are the same kind of time as the table's, taken on a
quieter machine, and they are the better guide to what the code costs; the
table keeps what was first measured.

| What, a hundred calls | Calling end | Answering end | How |
|---|---|---|---|
| Setting one call up | 187–424 µs | 390–833 µs | time inside the library from the first INVITE to the ACK, all the calls' together, over the number of calls |
| One transaction | 52–112 µs | 125–265 µs | the whole run's time inside the library over six transactions a call |
| Messages a second, one stack | 31 000–68 000 | 13 000–28 000 | messages written and read over the stack's own time inside the library |
| A live call, signalling, settled | 16.1 KB | 14.0–17.5 KB | the user agent's share |
| The same, fresh | 18.0 KB | 19.2–22.6 KB | while the transactions that set it up still run |
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
nothing else running: a hundred calls cost **346 µs** inside the library to set
one up at the calling end and **640 µs** at the answering end, 91 µs and
191 µs a transaction, 38 600 and 18 300 messages a second; a thousand calls
cost 392 µs and 974 µs, 125 µs and 301 µs, 28 000 and 11 600. Memory: 16.1 KB
and 17.3 KB of signalling a settled call, 35.2 KB of media.

The calling end's memory is the same to the byte from run to run; the
answering end's is not. Seven runs of a hundred calls on the Mac, on the same
code, gave 14.0, 14.0, 17.3, 17.3, 17.4, 17.5 and 17.5 KB a settled call and
19.2 to 22.6 KB a fresh one, so a single figure for that end is one draw
from a range, and the range is what the table gives.

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
  `scripts/bench.sh` now puts the timer around the test's own binary rather
  than around cargo, and on the same machine later the same day it printed
  4.5 MB with one call, 20.2 MB with two hundred, and 79 203 bytes a call.
  The same run put the shared library at 2.99 MB, up from 2.79 MB the day
  before, and a frame of audio at 0.8 µs with two hundred calls and 0.3 µs
  with one, at a load average of four to five.

What a real peer adds — a proxy's and a PBX's own processing, and the
network — is not in these figures; a hundred calls through the lab's
Kamailio to FreeSWITCH or to Asterisk has not been run.

## 24 September 2026 — `0.0.1`, an hour on a call

`scripts/lab.sh drift`, at `70aeba6`: three calls to Asterisk's echo
extension held for sixty minutes, a report every five
(`interop/harness/src/drift.rs`, `docs/11-testing.md`). The lab's two ends
read one host's clock, so a call there drifts by nothing, and a drift
measured against nothing proves nothing: each call's earpiece plays on a
clock of its own instead, 250 ppm slow, true, or 250 ppm fast, against the
clock its microphone and the network run on. The echo returns audio at the
pace it was sent, so each call's jitter buffer faces exactly the skew its
earpiece was given, and the true one is the control. The skew is then read
back out of what the buffer did — frames played that never arrived, less
frames that arrived and were never played, over the frames that arrived,
which is the ratio of the two clocks less one — and set beside the one given.

The Linux x86-64 lab machine, an Intel Xeon E5-2698 v4 at 2.2 GHz, Debian
13; the harness built with `rustc 1.95.0` in `rust:1.95-trixie`, release
profile, and run in a `debian:trixie-slim` container on the lab network
against Asterisk 22.10.1. G.711, 20 ms frames, the lab's cadenced tone
(1.2 s on, 0.6 s off). The flow passed, as it judged a call then; it now
also fails a call whose buffer runs dry in the middle of the tone. How many
of the fast earpiece's 44 did was not counted in this run; in the short runs
below, most of them did, so it would almost certainly have failed. The
skews in the table are the run's own counts read the way the flow now reads
them, over the frames that arrived; over the frames played, as the run
printed them, they were −245.2 and +250.6.

| After an hour | Earpiece 250 ppm slow | Control | Earpiece 250 ppm fast |
|---|---|---|---|
| Frames played | 179 456 | 179 500 | 179 545 |
| Skew measured | −245.1 ppm | 0.0 ppm | +250.7 ppm |
| Frames of drift absorbed | 44 (44.9 due) | 0 | 45 (44.9 due) |
| Dropped from a pause (shrunk) | 44 | 0 | 0 |
| Stretched into a pause | 0 | 0 | 0 |
| Played as silence, the buffer run dry | 0 | 0 | 44 |
| Concealed, discarded late, discarded for overflow | 0, 0, 0 | 0, 0, 0 | 0, 0, 0 |
| Buffer depth at every report, target 20 ms | 20 ms | 0–20 ms | 0 ms |
| Jitter at every report | 0–1 ms | 0–1 ms | 0–1 ms |
| Audible frames per report, 9 665–10 003 due | 9 670–10 020 | 9 670–10 020 | 9 671–10 020 |
| R factor, MOS-LQ, at every report | 93, 4.4 | 93, 4.4 | 93, 4.4 |
| Session changes, stalls | 0, 0 | 0, 0 | 0, 0 |

The skew each call measured, report by report, settles as the frames add
up — a frame of drift is five minutes at 250 ppm, so the first report is a
whole frame from exact: −206.9, −237.3, −247.3 and −235.3 ppm for the slow
earpiece at five, ten, fifteen and twenty minutes, and +206.9, +237.2,
+247.1 and +252.0 for the fast one, both within 8 ppm of the given skew for
the last half hour. The shrunk and run-dry counts climbed by three or four
every five minutes, as 250 ppm of fifteen thousand frames says they should.

Read together:

- **The buffer never grew.** None of the three was ever deeper than its
  20 ms target at any report, an hour in, and nothing was discarded for
  overflow. A buffer that was not correcting 250 ppm would hold 900 ms more
  by the end.
- **A slow earpiece is absorbed where nobody hears it.** Every frame of its
  drift was shrunk, which the buffer only does in a pause, and the audible
  count stayed with the cadence throughout.
- **A fast one is not.** Not one frame was stretched into a pause. With a
  clean path the target is one frame, and the stretch only happens when a
  packet has arrived since the last pull and the buffer holds less than its
  target — which, at a target of one, is a buffer holding nothing although
  something arrived. So the buffer runs dry instead, plays one frame of
  silence wherever that falls, in the tone as readily as in a pause, and
  starts again from the next packet: at 250 ppm, one 20 ms gap every eighty
  seconds or so. The mean opinion score does not see it — RTCP-XR counts
  loss and discard, and nothing was lost or discarded — and neither did the
  audible-frame check, which a single frame in five minutes does not move.
  The flow now counts silence that begins straight after the tone, or ends
  straight into it, as the tone cut off, and fails on any, so it stays red on the fast earpiece until
  the buffer changes. `docs/05-media.md` says so beside the buffer's design
  targets; making the stretch reachable at a one-frame target is the change
  it asks for. That change, and what the same flow measured after it, is
  the next section.
- **The control is the count's own check.** One frame shrunk early in the
  control's call, and its buffer one frame shallower for it, balance to
  nothing: every frame the other two moved is accounted for by the same
  count.

The review of this flow, on the same machine the same evening, ran it short
— three minutes at 2000 ppm, the review length `docs/11-testing.md` gives —
and broke it on purpose to see it fail:

- **As it stands**, it measured −2000.0, 0.0 and +2000.0 ppm, 17 frames
  each way, and failed: the fast earpiece's 17 frames were all the buffer
  running dry, and 11 of them cut the tone off. Before the check on the tone
  the same run passed; the ratio it printed then, over the frames played,
  was −2004.0 and +1996.0.
- **At an absurd skew**, ±50 000 ppm for two minutes, the flow as first
  committed passed, with the fast earpiece's buffer running dry 275 times —
  a gap every 0.4 s — and its audible count still above half. On the code as
  it stands the same run fails: 183 of the 275 cut the tone off. Its slow
  earpiece passed both times, 275 frames shrunk out of pauses and never
  deeper than 80 ms at a report.
- **At a skew no buffer can absorb**, ±500 000 ppm for two minutes, the slow
  earpiece's buffer sat at 1 960–1 980 ms at every report, 2 384 frames
  discarded for overflow, and the flow failed it at every report; the fast
  one failed on 1 896 cuts. Its R factor and MOS-LQ stayed at 93 and 4.4
  throughout, overflow and all: the ratings were computed from the loss
  rate alone, and the next section has them counting discards.
- **With the far end's audio dropped for five seconds** in the middle of a
  two-minute run at 2000 ppm, it failed on every call's skew. It also showed
  the measure counting that gap twice, once as the silence played and once
  as the sequence numbers the buffer skipped afterwards: the control
  balanced 500 frames for a gap of 250. The count now comes from what the
  earpiece played, and the same run on the code as it stands balanced 250,
  +47 619 ppm over the 5 250 frames that arrived, and failed every call on
  the tone as well: the gap began in a pause and ended in the tone, which
  counts.

## 25 September 2026 — `0.0.1`, a frame in hand, and discards rated

The two things the hour above left open, changed and measured again with
the review's short run of the same flow: `scripts/lab.sh drift` with
`SIPRAL_DRIFT_MS=180000 SIPRAL_DRIFT_REPORT_MS=30000 SIPRAL_DRIFT_PPM=2000`,
and the same at 500 000 ppm for two minutes. Same machine, toolchain,
Asterisk and tone as the hour; "before" is `209694c`, "after" is the commit
that adds this section. The hour was not run again.

**A pause keeps a frame in hand** (`docs/05-media.md`): a pause never
leaves fewer than two packets queued, so a fast earpiece's slip takes the
spare one and the next pause stretches it back, rather than the buffer
running dry.

| Three minutes at 2000 ppm | Slow, before | Slow, after | Control, before | Control, after | Fast, before | Fast, after |
|---|---|---|---|---|---|---|
| Skew measured | −2000.0 ppm | −2000.0 ppm | 0.0 ppm | 0.0 ppm | +2000.0 ppm | +2000.0 ppm |
| Dropped from a pause (shrunk) | 17 | 17 | 0 | 0 | 0 | 0 |
| Stretched into a pause | 0 | 0 | 0 | 0 | 0 | 17 |
| Played as silence, the buffer run dry | 0 | 0 | 0 | 0 | 17 | 0 |
| Of those, in the tone | 0 | 0 | 0 | 0 | 11 | 0 |
| Buffer depth at every report, target 20 ms | 20 ms | 40 ms | 20 ms | 20 ms | 20 ms | 20 ms |
| R factor, MOS-LQ | 93, 4.4 | 93, 4.4 | 93, 4.4 | 93, 4.4 | 93, 4.4 | 93, 4.4 |
| Verdict | | | | | failed, 11 cuts | passed |

Counted from ten seconds into the calls, as the flow counts; the control's
frame in hand was bought before that. The depth is read wherever the report
falls between an arrival and the pull that plays it, so it reads a frame
either way with the phase of the two clocks; the slow earpiece's extra
20 ms is the top of the dead band, where a slow clock sits until its next
frame of drift is dropped. A first version of the change put the dead band
on a single level, stretching below two and shrinking above two; on the
same run it passed too, with no frame run dry, but the two skewed calls
answered a pull landing either side of an arrival both ways, 56 frames
shrunk and 39 stretched on the slow one for 17 frames of drift, 43 and 61
on the fast one. The band is two packets wide above the frame in hand, as
it is above any target, and the counts above are exactly the drift.

**The ratings count what the buffer threw out.** R and MOS-LQ were rated
from the loss rate alone; RFC 3611 §4.7.1 gives loss and discard "equal
effect on the quality of the voice stream", and the E-model's packet loss
is now the two together.

| Two minutes at 500 000 ppm, slow earpiece | Before | After |
|---|---|---|
| Buffer depth at every report | 1 960–1 980 ms | 1 960–1 980 ms |
| Discarded for overflow | 2 384 | 2 384 |
| R factor, MOS-LQ, at every report | 93, 4.4 | 6–7, 1.0 |

The control rated 93 and 4.4 in both runs, and so did the fast earpiece,
which runs dry rather than discarding: a frame played as silence because
nothing had arrived is not a packet lost or discarded, and RTCP-XR has no
field for it. At 500 000 ppm the fast earpiece slips a frame every other
pull, far more than a frame in hand per talk spurt can take, and it still
fails on the tone: 2 750 frames run dry and 1 896 cuts before; 793
stretched, 1 957 run dry and 1 774 cuts after.

Both runs again at `4806c7d`, which has a spurt that starts in a pause
wait for its frame in hand rather than stretch for it, and brings RTCP-XR's
loss and discard rates to RFC 3611's definitions (`docs/05-media.md`): the
three minutes at 2000 ppm read exactly as the "after" columns above and
passed. At 500 000 ppm the slow earpiece rated R 8 at the first report and
7 after it, MOS-LQ 1.0 throughout, its frames given up in pauses now
counted among the packets expected; the fast one stretched 732, ran dry
2 018 times and was cut off 1 774 times, the control 93 and 4.4. The
`scripts/lab.sh netem` profiles passed at both commits with no splice
clicking.

## What would make these numbers worse

A codec that is not G.711: Opus costs an encode and a decode of its own, and
is not in the numbers above. Recording a call writes every frame to disk.
SRTP adds a pass over each packet. Each is worth measuring separately before
anybody plans around the figures here.
