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

`./scripts/bench.sh scale` is apart from that run: five and then ten thousand
calls with audio both ways, between two processes on one machine, each over
real UDP sockets. It wants a machine with the cores for it and is the
29 September section below.

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

**Not measured yet:** the same load on a mobile processor. A frame of Opus
against G.711, the microphone-to-earpiece delay, a hundred calls through a
real proxy and PBX, the media load test's memory on Linux, and drift on a
path with loss and jitter are answered further down, dated 27 September.

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
  thousand-call figure. (Changed on 29 September: a poll now reads only the
  sessions that raised an event; the section of that date below measures
  five and ten thousand calls.)
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
Kamailio to FreeSWITCH, and a hundred straight at Asterisk, are the
27 September section further down.

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
- **A fast one was not.** Not one frame was stretched into a pause. With a
  clean path the target is one frame, and the stretch then only happened
  when a packet had arrived since the last pull and the buffer held less
  than its target — which, at a target of one, is a buffer holding nothing
  although something arrived. So the buffer ran dry instead, played one
  frame of silence wherever that fell, in the tone as readily as in a
  pause, and started again from the next packet: at 250 ppm, one 20 ms gap
  every eighty seconds or so. The mean opinion score did not see it —
  RTCP-XR counts loss and discard, and nothing was lost or discarded — and
  neither did the audible-frame check, which a single frame in five
  minutes does not move. The flow now counts silence that begins straight
  after the tone, or ends straight into it, as the tone cut off, and fails
  on any. Making the stretch reachable at a one-frame target was the change
  that asked for; that change, and what the same flow measured after it,
  is the next section, and what the application now reads about such a
  gap is the one after it.
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
which ran dry rather than discarding: a frame played as silence because
nothing had arrived is not a packet lost or discarded, and RTCP-XR has no
field for it (the next section has where it is counted instead). At
500 000 ppm the fast earpiece slips a frame every other pull, far more
than a frame in hand per talk spurt could take, and it still failed on
the tone: 2 750 frames run dry and 1 896 cuts before; 793 stretched,
1 957 run dry and 1 774 cuts after.

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

## 27 September 2026 — `0.0.1`, what a spurt will slip kept in hand

Two ways a fast earpiece still ran dry after the frame in hand, changed
(`docs/05-media.md`) and measured again. An earpiece that takes two frames
a callback, a 40 ms device period on 20 ms packets, pulls twice at one
instant: the second pull could never stretch a pause, since the evidence
of audio still arriving it waited for was an arrival since the last pull,
so the queue the first pull left at its floor was drained by the second.
And one fast enough to slip more than a frame inside a talk spurt spent
the frame in hand and ran dry in the middle of it; the buffer now measures
the earpiece's pace against the far end's clock and the length of its
recent spurts, and keeps in hand what the next spurt will slip. "Before"
is `4133b7a` (the lab's harness built at `78a25e1`, which differs from it
only in packaging scripts and documentation), "after" the commit that
adds this section.

**The lab, `scripts/lab.sh drift`**, the review's short runs as in the
section above: same machine, toolchain, Asterisk and tone.

| Two minutes at 500 000 ppm, fast earpiece | Before | After |
|---|---|---|
| Stretched into a pause | 732 | 2 623 |
| Played as silence, the buffer run dry | 2 018 | 122 |
| Of those, in the tone | 1 774 | 0 |
| Buffer depth at the reports, target 20 ms | 0 ms | 40–340 ms |
| R factor, MOS-LQ | 93, 4.4 | 93, 4.4 |

The tone was not cut once. What still runs dry does so in the far end's
pauses, 22, 56, 90 and 122 at the four reports, where a skew that plays
three frames for every two sent has to stretch more than half the pulls
of each pause to have the next spurt's slip in hand when it starts. The
simulation below, whose verdicts of speech and silence are exact, runs
dry in no pause after its first minute; the lab's come from the facade's
detector on decoded audio. Those frames are inaudible, and
`Quality::underruns` counts them. The frames in hand are
what they cost: up to 340 ms at a report, which the flow's 250 ms ceiling
fails, as it fails the slow earpiece's two seconds of overflow at every
report, unchanged at 365 frames shrunk, 2 385 discarded and R 7. The
control read 0 ppm, nothing moved and R 93, as before. Three minutes at
2000 ppm read exactly as the 25 September "after" columns and passed:
−2000.0, 0.0 and +2000.0 ppm, 17 frames shrunk on the slow earpiece and 17
stretched on the fast one, none run dry, every buffer at 20 ms but the
slow one's 40.

**The crate's own simulation**, for what the lab's harness does not do:
its earpiece takes one frame per pull, and a two-frame device period is
not among its flows. `playout.rs`'s tests play the lab's cadenced tone
(1.2 s on, 0.6 s off, a packet every 20 ms on a clean path, each pull up to
3 ms either side of its tick) into a buffer configured as the facade
configures it, for two minutes of the earpiece's clock, and count what
`interop/harness` counts: frames played as silence because the buffer had
nothing, and the runs of that silence that cut the tone off. The far end
suppressing silence, in the last two rows, sends nothing in its pauses and
opens each spurt with a marker; there, every frame without a packet inside
a spurt counts.

| Two minutes of the tone | Before: dry, cuts | After: dry, cuts |
|---|---|---|
| One frame a pull, +2000 ppm | 0, 0 | 0, 0 |
| One frame a pull, +50 000 ppm | 131, 83 | 3, 3 |
| One frame a pull, +500 000 ppm | 1 357, 589 | 31, 14 |
| Two frames a pull, +2000 ppm | 10, 10 | 0, 0 |
| Two frames a pull, +5000 ppm | 21, 21 | 0, 0 |
| Two frames a pull, +50 000 ppm | 191, 191 | 6, 6 |
| Two frames a pull, +500 000 ppm | 1 369, 600 | 29, 14 |
| Silent pauses, +50 000 ppm | 129 | 4 |
| Silent pauses, +500 000 ppm | 1 269 | 56 |

What remains after is all in the first seconds of a call, while the pace
and the length of a spurt are being measured, and none of it after:
`an_earpiece_that_slips_frames_by_the_handful_in_a_spurt_has_them_in_hand`
runs each skew for eight minutes of the earpiece's clock and fails on a
single frame run dry after the first. The two-frame earpiece at 2000 ppm
stretched 13 frames for 12 of drift and the one in hand, and shrank none;
at −2000 ppm it shrank 11 and stretched the one in hand. With its dead
band a packet narrower, as before, four minutes at 2000 ppm shrank 161
frames where the drift called for none. A true or slow earpiece taking
one frame a pull is as it was; one taking two now buys its frame in hand,
one frame stretched, as the other always has.

**What the application reads of it.** RTCP-XR's figures stay literal to
RFC 3611 §4.7.1: a share of packets lost or discarded, and a frame played
as nothing because the packet for it had not arrived yet is neither, so a
fast earpiece whose tone was cut 1 774 times in two minutes rated R 93 and
MOS-LQ 4.4 at every report, above, and would again. The degradation is
counted where an application reads a call's quality instead:
`Quality::underruns` counts each such frame — it is, frame for frame, the
simulation's "dry" count above, which the test asserts — and
`Quality::loss_rate`, the share of the last ten seconds or so the listener
did not get from the far end, takes it as it takes a concealed frame, so
`StreamStatistics::score` and `is_suffering`, and the C ABI's `loss_rate`,
`score` and `suffering`, fall with it. Three frames of silence among five
played read as a loss rate of 0.6 with RTCP-XR's loss and discard rates
both at zero (`an_earpiece_that_outruns_the_far_end_counts_the_silence_it_played`).

**Silence for a packet lost on the way is not an under-run.** An
under-run is the buffer having nothing to play because the earpiece asked
before the far end's next packet arrived. A packet lost on the way with a
later one already held is concealed, and counted in `Quality::lost`; one
lost with nothing behind it yet leaves the buffer empty too, and the
earpiece plays a frame of silence for it. That frame is
`Quality::silenced`, beside `Quality::underruns`: the two together are
every frame of silence heard while the far end was sending, frame for
frame (`the_silence_heard_is_under_runs_and_losses_silenced`), and
`Quality::lost` still holds the lost packet as well. The C ABI's
`frames_underrun` is `Quality::underruns` alone, as before; the silenced
count is read from the Rust facade (`StreamStatistics::quality`). The
drift flow under `lossy` is where the two came apart: the earpiece played
12 frames as silence where the stack had counted 3 under-runs, the other
nine being lost packets, and `interop/harness/src/drift.rs` now sets the
silence it heard against both counts.

## 27 September 2026 — `0.0.1`, Opus against G.711, and the load test's memory on Linux

`scripts/bench.sh`'s new step, `crates/sipral/src/pipeline::tests::cost_of_a_frame_by_codec`
(`SIPRAL_CODEC_BENCH_FRAMES`, `SIPRAL_CODEC_BENCH_CALLS`, the same two the load test's own
`FRAMES`/`CALLS` already gave a name: a minute of audio, two hundred calls). It times
`Coder::encode` and `Coder::decode` directly — the codec layer alone, no session, no jitter
buffer, no socket — for one call, twenty-five frames of warm-up first the same reason every
codec's own round-trip test in that file gives one; and then at the load test's own shape:
two hundred calls' worth of `Coder`, fifty to a thread on four threads, driven for the same
number of frames each, wall-clock time over every call and every thread together. Every codec
this build carries, not Opus alone, because the other four came for the same price once the
harness existed.

Apple M2, macOS, `rustc 1.95.0`, release profile; the Intel Xeon E5-2698 v4 at 2.2 GHz Linux
lab machine, `rust:1.95-trixie`, ten cores given to the container this time rather than the
eight of 23 September. Both shared with other work throughout, the same reason the 24
September signalling figures are ranges rather than points — this table is not, because a
frame's own cost moves by tens of a microsecond where a call's setup moves by hundreds, and
the run below was not repeated to find its range.

| Codec, one call | Mac, encode | decode | total | Linux, encode | decode | total |
|---|---|---|---|---|---|---|
| PCMU (G.711 μ-law) | 0.86 µs | 0.04 µs | 0.91 µs | 0.95 µs | 0.15 µs | 1.10 µs |
| PCMA (G.711 A-law) | 0.41 µs | 0.05 µs | 0.46 µs | 0.70 µs | 0.16 µs | 0.87 µs |
| G.722 | 21.0 µs | 11.3 µs | 32.3 µs | 45.8 µs | 33.5 µs | 79.3 µs |
| G.729 | 195.1 µs | 43.6 µs | 238.6 µs | 181.6 µs | 36.0 µs | 217.6 µs |
| Opus | 200.3 µs | 29.2 µs | 229.5 µs | 191.9 µs | 63.7 µs | 255.6 µs |

| Codec, 200 calls on 4 threads | Mac, µs/frame | Linux, µs/frame |
|---|---|---|
| PCMU | 1.33 | 1.20 |
| PCMA | 0.89 | 0.90 |
| G.722 | 33.6 | 54.1 |
| G.729 | 171.8 | 224.5 |
| Opus | 195.0 | 157.3 |

Read together:

- **Opus costs about two hundred and fifty times G.711's per frame, one call at a time.**
  G.711 is a table lookup a sample at a time; Opus is a real-time encoder doing linear
  prediction, a psychoacoustic model and entropy coding on every twenty-millisecond frame,
  and the difference between "companding a sample" and "encoding a signal" is exactly the
  size this table gives it. G.729, the other codec here that predicts rather than compands,
  costs about the same as Opus — CELP's codebook search is not cheaper than what Opus does,
  it is a different way of being expensive.
- **Two hundred Opus calls cost about two of this Mac's eight cores, continuously.** Two
  hundred calls at fifty frames a second is ten thousand frames a second; at the load
  shape's own 195 µs a frame that is 1.95 seconds of processor time a second of audio — near
  enough two whole cores busy without stopping. The 23 September table's "two per cent of a
  single core" for G.711 at the same two hundred calls holds for Opus only if two per cent
  is read as two hundred: PCMU's own 1.33 µs a frame here is 13.3 ms of a core a second,
  matching that figure exactly.
- **The load shape did not cost more than one call, and for Opus and G.729 it cost less.**
  A lock two hundred calls contend for would show as the opposite — the 24 September
  signalling table's own "the cost of a call grows with the number of calls" is exactly
  that, from `MediaEngine::poll_event`'s lock. Nothing here takes one: every `Coder` is its
  own state, encoding and decoding nothing but its own call's samples, so what moved between
  one call and two hundred is cache and a machine shared with other work, not contention —
  the same qualification the 24 September table's own wide ranges carry, read onto a
  narrower number.
- **The Linux machine is not uniformly faster or slower.** G.711 reads about the same on
  both; G.722 and G.729 read slower on the Linux container than the Mac; Opus reads slower
  alone and faster at the load shape. A single run on a shared machine is not a verdict on
  either processor, only what this run measured.

The same Linux run gives the media load test's own memory, which the 24 September table left
open: `crates/sipral-ffi`'s own load test, timed directly rather than through `cargo test`,
the same method the 24 September addendum settled on for the Mac. Two hundred calls at a
minute of audio each peaked at 19 615 744 bytes; one call at 6 516 736 bytes; 65 824 bytes a
call over the difference between them. The Mac read the same day, same method: 20 578 304
bytes at two hundred calls, 4 554 752 bytes at one, 80 520 bytes a call — within a few
per cent of the 24 September addendum's own 79 203, the same figure read again rather than
a different one.

## 27 September 2026 — `0.0.1`, microphone to earpiece

`scripts/lab.sh latency` (`interop/harness/src/latency.rs`): there is no second host in this
lab to put a real microphone and a real earpiece on either end of, so what is measured is a
round trip on one call to Asterisk's echo (9008) — a marker frame, full scale rather than the
tone, in place of whatever this end would otherwise have sent, and the same call's own
playback watching for its echo — halved. The path is capture, encode, network, Asterisk's
`Echo()`, network, jitter buffer, decode and playback, twice each but Asterisk's own
turnaround; halving it assumes the two directions cost the same, which a lab on one host and
one link is the closest thing here to being able to say. A marker every two seconds for two
minutes, the buffer given five seconds to settle first. Three stages, only one of them read
directly off `sipral`: **framing**, the wait from the marker's own instant to the next
twenty-millisecond tick that actually carries it — this harness's own capture loop and its
poll granularity included, the same way a real device's callback scheduling would be;
**jitter buffer**, the playout buffer's own target delay the instant the echo came back
(`MediaSession::statistics`); and **network**, the round trip less the two of those —
Asterisk's own turnaround and this end's own next playback tick folded into it, since nothing
here can tell them apart from the wire. The Linux lab machine, as above.

| One way | Value |
|---|---|
| Markers sent, come back | 58, 58 (none lost) |
| Minimum | 28.2 ms |
| Median | 30.8 ms |
| 90th percentile | 31.0 ms |
| Maximum | 31.2 ms |
| Mean | 30.0 ms |
| — framing | 20.1 ms |
| — jitter buffer | 20.0 ms |
| — network | 0.0 ms |

Read together:

- **Framing and the jitter buffer are the delay.** Twenty milliseconds waiting for the next
  captured frame and twenty more held by the playout buffer at its default one-frame target
  account for all but nothing of the thirty measured; on a container network a few
  microseconds wide, that is the honest answer, not a rounding trick — `docs/05-media.md`'s
  own default target is one frame, and one frame is what a call on a clean path pays for it
  twice, once on each end of the round trip this measures.
- **The spread is a few tenths of a millisecond, not milliseconds.** Every mark measured
  within three milliseconds of the median; the buffer never had to stretch or shrink to keep
  up with a marker sent every two seconds on an otherwise idle call, so what moved was
  scheduling noise in this harness's own poll loop, not the network or Asterisk's own
  processing.
- **This is a floor, not a call's own worst case.** A real network and a real device add to
  both framing (real hardware buffers more than one host's own scheduling jitter) and the
  network term this run reads as zero; the netem-shaped drift run further down reads the
  jitter buffer's own target moving well past one frame once the link is not clean, which
  changes the second of these two numbers directly.

## 27 September 2026 — `0.0.1`, a hundred calls through a real proxy and PBX

`scripts/lab.sh volume` (`interop/harness/src/volume.rs`): a hundred calls at once rather than
one, fifty milliseconds apart, held five seconds once every one that came up has started its
media, hung up together. `interop/kamailio/kamailio.cfg` in this lab has no route to
Asterisk — it forwards everything to FreeSWITCH, and nowhere else — so "a real proxy and PBX"
is two runs here, not one: straight at Asterisk, no proxy in front of it, and through
Kamailio to FreeSWITCH behind it. This end's own process, `/usr/bin/time -v` around the whole
of it: signalling, media and the harness's own bookkeeping together, not `sipral`'s alone. The
real server's own peak channel count is read over its console (`asterisk -rx`, `fs_cli`)
rather than guessed from this end's count of calls still up. The Linux lab machine, as above.

| | Asterisk, no proxy | Kamailio, to FreeSWITCH |
|---|---|---|
| Calls up | 100 of 100 | 58 of 100 |
| Setup time (of the calls that came up) | min 9 ms, p50 12 ms, p90 14 ms, max 66 ms | min 7 ms, p50 10 ms, p90 12 ms, max 51 ms |
| This end's CPU | 0.85 s user + 1.52 s system, 23% of one core over 10.11 s | 0.56 s user + 1.03 s system, 15% of one core over 10.11 s |
| This end's peak memory | 10 192 KB | 8 296 KB |
| Real server's peak channels | 300 (three a call: the SIP leg and `Local/9002`'s own pair) | 169 |
| Failures | none | 42, all `Refused (500)`: FreeSWITCH's own admission control |

Read together:

- **Asterisk took a hundred calls in a burst without complaint.** Every call answered inside
  sixty-six milliseconds of being placed, the slowest ninety per cent of them inside
  fourteen; this end's own share of carrying them was under a quarter of one core.
- **FreeSWITCH did not.** `mod_loopback`'s own session-rate limiter — thirty sessions a
  second by default, and each of these calls opens two (`Local/9002`'s own pair) on top of
  its one SIP leg — started refusing calls with a 500 partway through the burst: the
  container's own log carried `Throttle Error!` and `Over Session Rate of 30!` for every one
  of the forty-two. This is not a defect in this stack: FreeSWITCH said no, in band, and the
  harness's own verdict reports exactly that refusal rather than a call that silently never
  came up. It is what "the lab's Asterisk itself could take" turns out to depend on which
  server is actually behind the proxy — Kamailio itself never refused anything; the limit
  belongs to what it is forwarding to, at fifty calls a second including both of a call's
  legs. `SIPRAL_VOLUME_STAGGER_MS=100` (ten calls a second, twenty sessions) is comfortably
  under it; this run used the default to find where the ceiling was rather than to avoid it.
- **A call that does come up costs about the same either way.** Ten to twelve milliseconds
  at the middle of the distribution, straight at Asterisk or through Kamailio to FreeSWITCH,
  is closer to the 24 September signalling table's own single-call figures than the extra
  hop through a proxy might suggest — a hundred calls in a ten-second burst is not the
  regime that table's own "cost grows with the number of calls already up" was measured in.

## 27 September 2026 — `0.0.1`, drift on a bad link

`scripts/lab.sh drift-netem` (the drift flow, `interop/harness/src/drift.rs`, under a netem
profile the way `scripts/lab.sh netem` shapes the ordinary calls, `SIPRAL_AUDIO_GATE=1`
throughout): the same three calls as an hour on a call, above, their earpieces at −2000, 0
and +2000 ppm, `SIPRAL_DRIFT_MS=180000 SIPRAL_DRIFT_REPORT_MS=30000 SIPRAL_DRIFT_PPM=2000` —
the review length `docs/11-testing.md` gives, since 250 ppm is too small to read against a
link already this noisy — over `lossy` (`interop/impairment/lossy.sh`): "delay 40ms 15ms loss
gemodel 4% 40% 60% 2%", both directions, the general-case profile `scripts/lab.sh netem`
already passes on an ordinary two-second call. This measures the buffer that is on `main` at
`156f7c0`, this batch's own base; the tooling that measured it is `caa4067`. `media2`, working
on the buffer's own drift handling at the same time, is not in it. The Linux lab machine, as
above.

| At three minutes | Slow (−2000 ppm) | Control (0 ppm) | Fast (+2000 ppm) |
|---|---|---|---|
| Buffer depth, target 60 ms | 20 ms | 60 ms | 40 ms |
| Jitter | 13 ms | 15 ms | 13 ms |
| Shrunk, stretched | 126, 117 | 112, 120 | 114, 142 |
| Ran dry, of those in the tone | 153, 41 | 133, 42 | 145, 40 |
| Concealed | 1 034 | 1 024 | 1 012 |
| Measured skew | +161 418.4 ppm | +158 669.6 ppm | +161 778.7 ppm |
| R factor, MOS-LQ | 20, 1.3 | 21, 1.3 | 21, 1.3 |
| Audio gate | segSNR −4.3 dB, 5 123 frames, 120/1 224 splices clicked, worst 374% | segSNR −4.2 dB, 5 175 frames, 124/1 163 clicked, worst 367% | segSNR −4.0 dB, 5 159 frames, 114/1 204 clicked, worst 366% |
| Verdict | failed | failed | failed |

Read together:

- **The buffer's target left one frame behind at the first report and never came back.**
  Twenty milliseconds, the clean-path target every earlier section in this document reads,
  grew to sixty within the first thirty seconds on every one of the three calls, the control
  included, and the depth itself moved between zero and eighty for the rest of the run —
  `lossy`'s own fifteen milliseconds of jitter is most of a frame by itself, and the buffer's
  own adaptive target (`docs/05-media.md`) did what it is meant to about it. This is the
  regime the microphone-to-earpiece section above could not read, on a clean path where the
  target never leaves one frame.
- **The skew this flow measures is not readable under real loss.** The control call, given
  no skew at all, measured +158 669.6 ppm — indistinguishable from the −2000 and +2000 ppm
  calls' own readings. `balance`'s own accounting (`interop/harness/src/drift.rs`) counts
  every concealed frame as drift absorbed, and `lossy`'s own four per cent loss concealed far
  more frames in three minutes than either clock's own 2000 ppm skew would; a method built to
  read a clean path's clock skew from what the buffer invented reads a bad path's own loss
  instead, and over this profile cannot tell the two apart. The buffer depth, the ratings and
  the gate are what this run is actually worth reading; `verdict`'s own skew check is not,
  here, and the failure it reports for that reason is not evidence of anything about drift.
- **The ratings fell from a clean path's 93 and 4.4 to about 20 and 1.3, on every leg
  alike — control included.** `lossy`'s own loss rate accounts for that on RFC 3611's E-model
  before a single frame of drift enters into it; a call in the middle of nothing but this
  profile, no skew at all, is already rated this badly.
- **The audio quality gate failed all three, and the control failed the same way the skewed
  legs did.** A tenth of the concealment splices clicked, at three to four times the
  threshold that counts as one, and the segmental SNR read negative — more noise than signal
  by the gate's own measure — on every leg, including the one running true. Since the
  control shares the failure with the skewed legs almost exactly (124 of 1163 splices against
  120 of 1224 and 114 of 1204, the same order of magnitude of frames concealed), what failed
  it is `lossy` itself sustained for three minutes, not the drift this flow adds: the same
  profile passes `scripts/lab.sh netem`'s own two-second call, and three minutes of it is a
  different, harder claim that this run is the first to have made. Whether the buffer's own
  handling of `lossy`'s bursts, sustained, or the gate's own segmental-SNR fit losing its
  footing over that many concealed frames in a row is the more accurate account of the
  negative reading is not settled by this run; what is settled is that a call held on this
  profile for three minutes clicks, on `main` as it stands, where the same profile briefly
  does not.

## 27 September 2026 — `0.0.1`, what a real clock drifts, and a budget for the rest

The sections above made a fast earpiece keep in hand what its pace slips
over a talk spurt, and at 500 000 ppm that came to 340 ms of delay, past
the lab flow's 250 ms ceiling, with the tone still run dry 122 times in two
minutes, every one in the far end's pauses. Three questions were left: what
skew a real device makes, what the product should do past it, and why the
lab ran dry in pauses where the crate's simulation did not.

**What a real clock drifts.** An Apple M2 MacBook Air, macOS 26.5.2, read
for fifteen minutes. Each output device's own sample clock against the
machine's (`mach_absolute_time`), through an output-only HAL unit rendering
silence, first and last render timestamps: the built-in loudspeaker ran
+3.13 ppm off it (CoreAudio's own rate scalar said 3.1), and the two virtual
devices, BlackHole and Microsoft Teams Audio, which are clocked off the
machine itself, +0.02 ppm, the measure's own floor. The machine's crystal
against the wall clock the time daemon holds to NTP, over the same fifteen
minutes: +8.8 ppm. The lab machine's, read off its time daemon's frequency
correction: +1.3 ppm. Two ends of a call on such hardware drift apart by
tens of ppm, and the widest a device's clock may be off and meet its bus's
specification is 2500 ppm, a USB full-speed one's ±0.25 %, and ±500 ppm at
high speed (USB 2.0 §7.1.11). No microphone or USB device was read: reading
one asks for a permission this machine's owner grants by hand, and none was
attached.

**What the product does about it.** What a pause keeps in hand for the
pace is bounded at 100 ms (`docs/05-media.md`), which carries 2500 ppm
through a twenty-second spurt. Past it the skew is a stream played at the
wrong rate, and the buffer runs dry and counts it rather than grow the delay.
The crate's simulations of the lab's tone, two minutes of the earpiece's
clock through the facade's own codec, concealment and detector of speech
(`earpiece_against` in `crates/sipral/src/tests.rs`), after the change:

| Two minutes of the tone | One frame a callback: dry, cuts, deepest | Two frames: dry, cuts, deepest |
|---|---|---|
| −10 000, −5000, +500, +2500, +5000, +10 000 ppm | 0, 0, 40–60 ms | 0, 0, 60–100 ms |
| +20 000 ppm | 1, 0, 60 ms | 1, 0, 100 ms |
| +50 000 ppm | 5, 3, 100 ms | 5, 4, 100 ms |
| +500 000 ppm, before | 123, 14, 220 ms held at the end | 97, 16, 300 ms held at the end |
| +500 000 ppm, after | 1 255, 1 055, 80 ms | 1 274, 1 090, 80 ms |

Every frame run dry there was one the stack counted as an under-run,
frame for frame, and at 500 000 ppm the call's loss rate ended at 0.25.

**The lab, `scripts/lab.sh drift`**, now six calls: slow, true and fast,
each once taking one frame a callback and once two at a time, as a 40 ms
device period on 20 ms packets does — the shape the simulation alone had
proved the paired-pull fix on. The Linux x86-64 lab machine, the harness
built with `rustc 1.95.0` in `rust:1.95-trixie`, Asterisk 22.10.1, a report
every thirty seconds, the same tone.

| | ±2000 ppm, 3 min | ±5000 ppm, 3 min | ±500 000 ppm, 2 min |
|---|---|---|---|
| Fast, one frame: stretched, run dry, in the tone | 17, 0, 0 | 43, 0, 0 | 1 036, 1 714, 1 528 |
| Fast, two frames: stretched, run dry, in the tone | 17, 0, 0 | 43, 0, 0 | 1 008, 1 742, 1 501 |
| Of the frames run dry, counted by the stack | — | — | 1 714, 1 742 |
| Fast earpieces' depth at the reports | 20 ms | 0–40 ms | 0–80 ms |
| Slow, one frame and two: shrunk | 17, 16 | 42, 42 | 358, 329, and 2 392, 2 421 thrown out for overflow at 1 960–1 980 ms |
| Skew measured, one frame and two | ±2000.0; −1882.4, +2117.6 | −4941.2, +5058.8; −4941.2, +4941.2 | ±500 000.0, both |
| Score, suffering, R and MOS-LQ | 92–96, no, 93 and 4.4 | 88–96, no, 93 and 4.4 | fast 0, suffering, 93 and 4.4; slow 0, 7 and 1.0 |
| Verdict | passed | passed | passed, judged as a skew no device runs at |

Neither two-frame earpiece ran dry at a skew a device runs at, and both
controls read 0.0 ppm with nothing moved. At 500 000 ppm the fast
earpieces held no more than 80 ms where they held 340, and ran dry on a
fifth of their frames, cutting the tone; the stack counted each of those
frames, scored the calls 0 and called them suffering at every report,
while RTCP-XR, which counts packets, still rated them 93 and 4.4. The
slow earpieces filled their rings, as they did before. The flow now judges
such a skew on that: bounded, and reported (`docs/11-testing.md`).

**Why the lab ran dry in pauses where the simulation did not.** The
verdict the buffer moves on comes from the facade's detector of speech,
which holds speech for 200 ms after the tone, and the buffer only
stretches what is called a pause; at 500 000 ppm, which needs every pull of
a pause stretched, the first ten of each pause ran dry instead. Proved
before the budget, on the code the lab had measured 122 at: the crate's
simulation with exact verdicts ran dry 31 times in two minutes, the same
simulation through the facade's own detector 123 (95 of them in pauses),
and with exact verdicts held ten frames past the tone 133 — the lab's
figure, from the one difference between them. After the budget the second
and third agree to the frame, 1 255 each; exact verdicts give 1 125. At any
skew a device runs at the hangover costs nothing: up to 10 000 ppm no
frame ran dry either way.

## 29 September 2026 — `0.0.1`, an hour on six calls, again

`scripts/lab.sh drift` with nothing shortened, at `d85bcb9`, the wave
that brings ABI 0.29: six calls to Asterisk's echo held for sixty minutes,
a report every five, the earpieces 250 ppm slow, true and 250 ppm fast,
each once taking one frame a callback and once two. The same Linux x86-64
lab machine as the hour above (Intel Xeon E5-2698 v4 at 2.2 GHz, Debian
13), the harness built with `rustc 1.95.0` in `rust:1.95-trixie`, release
profile, against Asterisk 22.10.1; G.711, 20 ms frames, the lab's cadenced
tone. The flow passed.

| After an hour | Slow, one | Slow, two | Control, one and two | Fast, one | Fast, two |
|---|---|---|---|---|---|
| Frames played | 179 455 | 179 454 | 179 500 | 179 545 | 179 544 |
| Skew measured | −250.7 ppm | −256.3 ppm | 0.0 ppm | +250.7 ppm | +245.1 ppm |
| Frames of drift absorbed (44.9 due) | 45 | 46 | 0 | 45 | 44 |
| Dropped from a pause (shrunk) | 44 | 44 | 0 | 0 | 0 |
| Stretched into a pause | 0 | 0 | 0 | 45 | 45 |
| Played as silence, the buffer run dry | 0 | 0 | 0 | 0 | 0 |
| Concealed, discarded late, discarded for overflow | 0, 0, 0 | 0, 0, 0 | 0, 0, 0 | 0, 0, 0 | 0, 0, 0 |
| Buffer depth at every report, target 20 ms | 40 ms | 40–60 ms | 20 ms | 20 ms | 20–40 ms |
| Jitter at every report | 1 ms | 1 ms | 1 ms | 1 ms | 1 ms |
| Score at every report | 92 | 88–92 | 96 | 96 | 92–96 |
| R factor, MOS-LQ, at every report | 93, 4.4 | 93, 4.4 | 93, 4.4 | 93, 4.4 | 93, 4.4 |
| Session changes, stalls | 0, 0 | 0, 0 | 0, 0 | 0, 0 | 0, 0 |

Every report heard between 9 669 and 10 019 audible frames against 9 664
to 10 003 due. The one-frame earpieces' measured skew settled as the frames
added up: −275.9, −271.2, −269.7 and −252.1 ppm for the slow one at five,
ten, fifteen and twenty minutes, +206.9, +237.3, +247.2 and +252.1 for the
fast one, and within 9 ppm of the given skew from the twentieth minute on.

Set beside the hour of 24 September, what changed is the fast earpiece:
there, none of its 44 frames of drift was stretched into a pause and all
of them ran dry; here, 45 were stretched and none ran dry, on either
callback size: the changes of 25 and 27 September above, measured then on
the reviews' runs of a few minutes, held for the full hour. The slow
earpieces read one frame above the 20 ms target at every report, and the
two-frame one at times two; nothing was discarded for overflow.

## 29 September 2026 — `0.0.1`, five and ten thousand calls held

`scripts/bench.sh scale` (`interop/harness/src/scale.rs`), at `708ca99` with the
harness committed beside this section. Two processes of the lab harness on one
machine, both on 127.0.0.1: one places the calls at 500 a second, the other
answers every INVITE; once all are up they are held sixty seconds and hung up
at the same rate. Every call is G.711 over a UDP socket of its own at each end,
a 400 Hz tone sent both ways every twenty milliseconds and played out of the
jitter buffer. Each end is laid out as a server on this stack would be: one
thread owns the user agent and the media engine and runs all the signalling,
reading SIP, draining `MediaEngine::poll_event`, and every twenty milliseconds
running `MediaEngine::handle_timeout`, `UserAgent::handle_timeout` and a drain
of `MediaEngine::poll_rtcp`; `SIPRAL_SCALE_THREADS` others carry the audio,
each reading its calls' sockets, then taking each call's own lock through a
`SessionShare` for its frame, then sending. Everything is this end's, the
calling one, read from `/proc/self` over the sixty seconds of the hold; each
cost of a call into the stack is wall-clock time on the signalling thread.

Both ends raise the limits past the calls asked for: `max_dialogs` to the
calls and 64 more, `max_server_transactions` to twice the calls and 256 more.
At the defaults, 128 and 256, the 129th call is refused both ways: one placed
is `SendError::LimitReached` in Rust and `SIPRAL_STATUS_LIMIT_REACHED` (16)
over the C ABI, with nothing sent, and an INVITE that arrives is answered
`503 Service Unavailable`, counted in
`sipral_counters_t::requests_refused_at_limit`; it carried no `Retry-After`
when this was run, and carries `Retry-After: 2` since 2 October
(`docs/08-ffi.md`, "Limits, and what went out twice", says why).

The Linux x86-64 lab machine (Intel Xeon E5-2698 v4 at 2.2 GHz, 32 vCPUs,
Debian 13, kernel 6.12, socket buffers at the default 212 992 bytes), the
harness built with `rustc 1.95.0` in `rust:1.95-trixie`, release profile; both
ends on it, and nothing else running. Reproduce, on a machine with the cores:

```bash
./scripts/bench.sh scale                           # 5 000, then 10 000
SIPRAL_SCALE_THREADS=12 ./scripts/bench.sh scale 10000
# a harness built elsewhere, e.g. in a container: SIPRAL_HARNESS=<path> ...
```

| This end, over the hold | 5 000 calls, 8 audio threads | 10 000, 8 threads | 10 000, 12 threads |
|---|---|---|---|
| Calls up | 5 000 | 10 000 | 10 000 |
| Setup rate, first INVITE to last 2xx | 500 a second | 499 a second | 379 a second |
| Setup, INVITE to 2xx: p50, p90, max | 2.6, 6.3, 54.6 ms | 7.5, 95.6, 642.5 ms | 13.5, 241.3, 7 445 ms |
| Processor | 5.32 cores: 113.8 s user, 205.4 s system | 8.48 cores: 182.1 s, 326.5 s | 11.20 cores: 257.8 s, 414.3 s |
| Resident memory, peak | 363 MB | 718 MB | 719 MB |
| Packets a second, out and in (due: 50 a call) | 249 980, 250 011 | 407 085, 403 591 | 477 278, 481 537 |
| Frames played with the buffer run dry | 50 of 14 998 922 | 420 865 of 24 425 392 (1.7 %) | 287 466 of 28 637 055 (1.0 %) |
| Audio ticks started a frame late, and the slowest | 3, 47 ms | 3 854, 48 ms | 1 434, 60 ms |
| `poll_event`, each | 0.42 µs | 0.44 µs | 0.52 µs |
| `MediaEngine::handle_timeout`, each | 1.73 ms | 3.66 ms | 3.30 ms |
| `UserAgent::handle_timeout`, each | 1.10 ms | 2.19 ms | 2.32 ms |
| A drain of `poll_rtcp`, each (reports) | 1.55 ms (59 965) | 3.44 ms (119 939) | 3.61 ms (119 733) |
| SIP sent again here, and by the far end | none, none | none; 113 responses | 527 requests; 1 495 responses |

No SIP transaction timed out at either end in any run, and every BYE reached
the answering end, which counted every call ended.

Read together:

- **A call costs about 72 KB of resident memory at this end**, the harness's
  own share included, and about a thousandth of a core while it carries
  audio: 5 000 calls held on 5.3 cores. Two thirds of that is system
  time: two `recvfrom`s and a `sendto` a call every frame, on sockets of its
  own. That is the application's input and output rather than the library's,
  and it is where a machine runs out first.
- **Past five thousand calls it is the audio threads that break.** At ten
  thousand, eight threads carry 1 250 calls each every twenty milliseconds,
  sixteen microseconds a call, and cannot: 3 854 ticks started late, 1.7 % of
  frames played dry, 407 000 of the 500 000 packets a second due went out.
  Twelve threads, with the answering end's twelve beside them on the same 32
  vCPUs, bring it to 1.0 % and 477 000. A server past this point wants its
  sockets read in batches (`recvmmsg`) or fewer of them — one port for many
  calls, told apart by SSRC — rather than more threads.
- **The signalling thread has room to spare, and is linear.** At ten thousand
  calls its three sweeps take about 9.3 ms of every 20: 46 %, growing with the calls
  held, so one engine thread on this machine reaches its end near twenty
  thousand. Each sweep locks every session or visits every call; they are the
  next thing to make proportional to what is due rather than to what is held.
- **`poll_event` no longer grows with the calls held.** 0.42 µs with five
  thousand and 0.44 µs with ten thousand: it reads the sessions that raised
  an event, where before this change it locked every session to ask.
- **What broke before this change.** The same ten thousand calls, with
  `poll_rtcp` still starting from the first session for every report and the
  sweeps every five milliseconds: a drain took 8.3 ms, more than the interval
  between them, the signalling loop turned 77 times a second, INVITEs went
  again 5 680 times, 269 transactions timed out and 4 034 of the 10 000 calls
  failed. With the drain fixed but before the 2xx fix, the caller's socket
  buffer overflowed during the busiest seconds and 243 200 OKs were lost for
  good — nothing repeated them — so 243 calls never came up. The far end's
  113 repeated 2xx in the second column are the same kind of loss, recovered.
- **The setup rate held at the rate asked for** up to ten thousand calls with
  eight threads; with twelve, the machine was busy enough that the 2xx went
  again 1 495 times and the slowest call took 7.4 s to come up, every one of
  them up in the end.

## 2 October 2026 — `0.0.1`, the library at ABI 0.35

Apple M-series, macOS, `rustc 1.95.0`, `cargo build --release -p sipral-ffi`
with the crate's default features (`opus`, `dtls`, `ice`, `stun`, `stir`),
measured the way `scripts/bench.sh` measures it.

| | Value | Note |
|---|---|---|
| Shared library, `libsipral_ffi.dylib` | 5.18 MB | 5 184 736 bytes as built; the release profile already strips it. 2.99 MB on 24 September |

Only the size was taken that day. The machine was running other builds at a
load average above a hundred on eight cores, so the per-frame and set-up
times above were not measured again: a wall-clock figure read on it would
say more about the machine than about the library.

## 2 October 2026 — `1.0.0`, the release, at ABI 0.36

Apple M-series, macOS, `rustc 1.95.0`, release profile, `./scripts/bench.sh`
as it stands, on the release tree (the code the `v1.0.0` tag carries). The
load average was 4.7 when the run started and 10.5 when it ended, on eight
cores shared with other work.

| What | Number | How |
|---|---|---|
| Shared library, `libsipral_ffi.dylib` | 5.20 MB | 5 201 264 bytes as built, the crate's default features; stripping again changes nothing |
| Audio, per frame of 20 ms, 200 calls on 4 threads | 7.6 µs of wall time | the load test as `bench.sh` runs it: a minute of G.711 per call, in-band digit detection running on every frame (below) |
| The same, one call | 7.1 µs | the same per frame as with two hundred: no call waited on another (0 busy) |
| Opening a stack | 0.1–1.0 ms | the first stack in a process pays for its own lazy initialisation |
| Bringing one call up | 144–414 µs | the load test's own, placing the INVITE, reading the answer, opening the session |
| Memory per call, the load test | 94.6 KB | peak resident memory with 200 calls against one, over 199 |
| Signalling, a call set up | 146–243 µs caller, 369–442 µs callee | a hundred and then a thousand calls, each challenged, answered with a reliable 180 and PRACK, held, resumed and hung up |
| Signalling, per transaction | 41.6–56.5 µs caller, 107.9–112.7 µs callee | the same two runs |
| Signalling, messages a second | 62 000–84 000 caller, 31 000–32 000 callee | the same two runs |
| A live call's memory, counted by the test's allocator | 16.3–18.6 KB signalling and 48.4–48.5 KB media per end | settled, once the transactions that set it up are gone |
| A frame of codec, one call | PCMU 0.51 µs, PCMA 0.31 µs, G.722 18.5 µs, Opus 94.9 µs, G.729 99.6 µs | encode and decode together, the codec layer alone |

**The per-frame figure is not the 23 September one, and the difference is
one feature.** The load test answers its calls with G.711 and no
`telephone-event`, and since 29 September a call that negotiated no
telephone event listens for keypad digits in the far end's audio itself
(`sipral_stack_config_t::dtmf_detection`, `docs/05-media.md`): a windowed
Goertzel filter bank over a sliding window, on every frame. A profile of the
load test (`sample`, a build with line tables) puts about nine in ten of the
samples taken in the library's own code in that analyser
(`sipral_media::inband::analysis`). The same test with `telephone-event`
added to its answer — a local change for the measurement, not committed — so
that detection stays off, read 0.54–0.60 µs a frame with two hundred calls
and 0.30–0.34 µs with one at a load average of 5 (1.4–1.8 µs and 0.32–0.34
µs at 22 to 26), at or under the 23 September figures; the unchanged test,
run again at that load average of 5, read 7.7 µs. So a call whose far end
sends digits as RTP events costs what it did, and a call that has to be
listened to costs about 7 µs a frame more: about a third of a millisecond of
one core a second, per call.

Not measured again: five and ten thousand calls held (`bench.sh scale`,
29 September), which wants the machine to itself.

## What would make these numbers worse

A codec that is not G.711: Opus and G.729 both cost two hundred and fifty
times G.711's own per frame, below. Recording a call writes every frame to
disk. SRTP adds a pass over each packet. Each of the last two is worth
measuring separately before anybody plans around the figures here.
