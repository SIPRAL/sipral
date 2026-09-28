<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Testing

The sans-I/O core exists so that this document can be short and the tests can be
boring. Almost everything is deterministic and runs without a network.

## Time is given, never read

A guarantee rather than a habit, because everything else here rests on it:
**no library code in `sipral-core`, `sipral-ua`, `sipral-rtp`, `sipral-media`,
`sipral-nat` or `sipral-dtls` reads the machine's clock.** Time arrives as a
parameter — `receive(input, now)`, `handle_timeout(now)` — and leaves as
`poll_timeout()`. The one exception in library code is `sipral_ua::Runtime`,
the reference loop over real sockets, which is where a clock belongs and
which is behind the `reference-loop` feature, off by default, so that
nothing links it by accident.

`scripts/check.sh` enforces it. Everything from a file's first `#[cfg(test)]`
is cut, modules that are nothing but tests are skipped by name, and a single
`Instant::now()` anywhere else fails the gate with the file and line. Tests may
read the clock; they have to get a starting point somewhere.

Two things follow, and they are the reason it is worth a check. A test drives a
week of registration refreshes in a millisecond, so retransmission schedules are
verified rather than waited for. And a recorded session replays to the same
bytes, which is what makes a failure caught in the field into a test that stays
(`docs/13-client-requirements.md`, D2).

## Bad networks are fixtures, not arguments

`interop/impairment/` holds the shapes of bad link a call is measured over, one
file each, and `scripts/lab.sh netem` runs them. They are committed rather than
typed because a threshold measured against a profile that lives in somebody's
shell history is a threshold nobody can reproduce.

Four of them: bursty loss with jitter and reordering; a mobile leg losing two
per cent in bursts on a link whose delay moves; a geostationary carrier, where
the interesting failure is arithmetic rather than audio, since a retransmission
schedule tuned on a fast path gives up before a satellite answers; and a link
that disappears for eight seconds in the middle of the call.

The last is the one worth having, and it is the one an easy simulator does not
produce. Loss and delay held constant for the length of a call are a bad line,
not an interruption. What it asks is not whether audio survived — eight seconds
of nothing cannot be concealed — but whether the stack is still there
afterwards: the dialog kept, no timer having fired into the gap and torn the
session down, and a buffer that goes back to the target it had rather than
staying where the gap left it.

**A profile declares what must be true after it is applied, and the runner reads
it back.** `tc` accepts settings the kernel then discards in silence: on a 3.10
kernel `delay` goes and `loss` stays. A run whose impairment never happened is
byte for byte a clean run, and it passes. That is worse than no run, so the
runner refuses to report a pass when what the profile asked for is not in the
qdisc, and says the run proves nothing instead.

For the outage, reading the qdisc back is not enough, and it was the only check
until a run on a 6.12 kernel passed without the outage touching the call. The
eight seconds were timed from the container starting; that host took longer to
get the call sending, so they fell on the REGISTER and the INVITE, whose
retransmissions outlasted them, and the call ran clean. The qdisc said `loss`
throughout, because the loss was applied — to nothing. So the outage now waits
until audio is visibly leaving through the qdisc before it cuts the link, and
afterwards netem's own drop counter has to show that it took at least four
seconds of the call's packets. A run where it did not says so and proves
nothing; it is never reported as a pass.

`lossy`, `mobile` and `satellite` do apply on a 6.12 kernel — `tc`'s own
distribution tables (`normal.dist` and the rest) ship at a multiarch path
(`/usr/lib/x86_64-linux-gnu/tc/`, not `/usr/lib/tc/`) that a current
`iproute2` finds without help, and a run's own qdisc read-back, `REQUIRE`,
confirms it every time. What did not apply, on any kernel, was the
impairment reaching the audio these three profiles measure — see below.

## The audio quality gate

Packet counts say a call connected and ended; they say nothing about whether
what crossed it was still the tone. `interop/harness/src/quality.rs` does:
segmental SNR on the frames that arrived, and a check for a discontinuity at
either edge of a concealment gap, against the lab's own fixed 350 Hz + 440 Hz
tone (`Playtones`/`tone_stream`, see the module's own doc for why that and not
an echo of what this end sent). `scripts/lab.sh netem` turns it on
(`SIPRAL_AUDIO_GATE`) for `Flow::Call`, and a profile whose audio does not
hold up fails the same way a connection that never came up does — the result
line names which: a click, or a segmental SNR under the floor.

Building it surfaced the reason `lossy`, `mobile` and `satellite` had never
actually exercised it. `tc netem` only ever shapes egress, and the comment
above this section used to read that as enough on the strength of an echo
that does not exist (`quality.rs`'s own module doc says why one was tried at
the far end and abandoned). Shaping only this container's own egress never
touched a single frame of the tone it received: every run of the three
non-outage profiles passed with the same audio a clean run has, because the
call it measured was, in every way that mattered, a clean one. `scripts/lab.sh`
now redirects this container's own ingress through an `ifb` device
(`interop/impairment/README.md`'s own "Both directions" section) and applies
the same `NETEM` there, so the link is bad both ways, the way a real one is —
and only once that redirect existed did any of the three ever produce a
concealed frame, a lost packet the far end's own tone shows on this end's
receive side, or a click.

**Segmental SNR**, `MIN_SEGMENTAL_SNR_DB` in `quality.rs`: **10 dB.** Measured
on the lab VM, several runs of each profile, `Flow::Call` alone: a clean run
and `satellite` (0.5% loss) sit at 34.4 dB every time — the fitted tone's own
residual, not measured degradation. `lossy` (4% bursty loss) stayed at
32–34 dB across a dozen runs. `mobile` (2% bursty loss on a link whose delay
moves) is the one that varies, 15–34 dB depending on how the loss bursts land
against the spurts, with one run down to 14.8 dB the lowest of everything
measured. The floor sits under that by four decibels, and clearly above what
a run actually broken produces: a synthetic 60% loss profile, run only to see
where the gate gives out, scored 9.4 dB and clicked besides.

**Splice continuity**, `CLICK_FLOOR` and `CLICK_MARGIN_FRACTION`: **900 and
0.6**, making the threshold at a splice `steepest + 900 + 0.6 * steepest`,
`steepest` the largest step the fitted tone takes anywhere in its cycle
(`2·A·sin(ω/2)` per sinusoid, summed). The first version measured a splice
against the reference's own step *at that instant*, and failed four `mobile`
calls in ten. Every flagged splice, read sample by sample, was smooth: one
played 1442 across the splice and then 1786, 1762 and 1721, another 2008 and
then 1834 and 1416 — steps as large as the ones after them, against a
reference step of 165 and 193 because the reference happened to sit at a
peak there. Concealment is not phase-locked to the tone, so by the time a gap
ends the audio played can be a quarter of a cycle from the reference, and a
threshold built from the reference's slope at that point is measuring where
the reference is in its cycle, not whether the audio jumped. A jump no larger
than the tone's own slope is not a discontinuity wherever it falls; a real
one, the played signal leaping by something of the order of its amplitude,
clears the steepest-step threshold. `quality.rs` carries both shapes as
tests, the smooth resume at a peak among them. Measured after the change on
the lab VM: 31 calls on `mobile` and `lossy`, 176 splices checked, no click,
segmental SNR between 18.9 and 34.4 dB.

**A click shows its waveform.** The result line carries `worst splice N% of
its threshold`, how near the call came to clicking, and a call that fails on
a click prints each one under the failure: the eight samples before the
splice and sixteen from it, as played and as the fitted tone, and the twelve
frames that led up to it — `P` a packet loud enough to be the tone, `p` one
that is not, `C` a lost packet concealed, `S` a pause stretched by the
jitter buffer (`Playback` reports both as `Concealed`; the harness tells them
apart by the buffer's own count), `N` comfort noise, `_` silence — each with
its loudness, and the splice's own frame in brackets. The list ends on the
frame the splice was scored on, which is its own only once a run's fit is
complete: a splice in a run's first five frames is scored with them, when
the fit is, so the frames after it are listed too.

A `lossy` run on 25 September failed on one click and the three runs after
it passed, the day the jitter buffer had changed how it holds a frame in
pauses, so the two playouts were measured against each other on the lab VM:
the harness built at the commit before that change and at the one after it,
the same lab and the same evidence, alternating build by batch of five
`lossy` and five `mobile` calls, one `scripts/lab.sh netem` at a time. A
short call checks only a handful of splices, so the same comparison was also
run on thirty-second calls — the two profiles with `DWELL_MS=30000`, copies
kept off the tree for the measurement — which check ten times as many. Then
the build with the fix below, the same way. Each cell is calls that failed on
a click, of calls run:

| build | `lossy` | `mobile` | `lossy`, 30 s | `mobile`, 30 s | splices checked | clicks | nearest smooth splice |
|---|---|---|---|---|---|---|---|
| before the playout change | 1 of 30 | 0 of 30 | 0 of 9 | 0 of 9 | 1508 | 1 | 57% |
| after it | 0 of 30 | 0 of 30 | 1 of 9 | 0 of 9 | 1624 | 2 | 54% |
| after it, with the fix | 0 of 29 | 0 of 29 | 0 of 24 | 0 of 24 | 3515 | 0 | 50% |

Two more calls on the fixed build, one per profile, are not in the table:
the proxy refused both with `482 Request merged` before any audio flowed.

The playout change made no difference: one `lossy` call in 39 failed on a
click on either build (Fisher's exact test, two-sided, p = 1.0; per splice,
1 in 1508 against 2 in 1624, p = 1.0, though the two are the way into and
out of one gap), no `mobile` call did on either, and
the two failures were two shapes of one fault older than both builds. The
one before the change:

```text
splice into concealment: jump 6396 against a threshold of 5744 (the tone's steepest step 3027)
  played -132 -2108 -4092 -5628 -6908 -7420 -7420 -6396 | 0 8 69 217 445 678 948 1056 ...
  tone   -144 -2036 -3886 -5487 -6645 -7205 -7067 -6203 | -4661 -2566 -110 2470 4915 ...
  frames C2378 P3704 P4446 P4157 P3954 P3927 C3692 C2329 C720 C0 P3343 [C2808]
```

Four frames lost, one received, one more lost; the played audio drops from
-6396 to 0 in one sample and climbs back through a fade, where the tone went
on to -4661. The one after it:

```text
splice into concealment: jump 7992 against a threshold of 5696 (the tone's steepest step 2998)
  played -5884 -8316 -9340 -9852 -9340 -8316 -5884 -3132 | 4860 6648 7405 7642 6855 ...
  tone   -5930 -7909 -9156 -9532 -8988 -7567 -5402 -2701 | 270 3217 5851 7911 9198 ...
  frames P4446 P4157 P3954 _0 _0 _0 _0 P3954 [C3362] P3848 P4446 C3388
```

Four frames of silence while the jitter buffer ran dry, one received, one
lost — the three frames after it are there because the run had only just
begun, and its splices were scored when its fit completed; the concealment opens at 4860 where the tone was at 270, and the
splice out of it clicked as well (6659), since the extension the stream was
cross-faded back from restarted its one-frame period on that same jump. Both
are real clicks, and both are the G.711 concealer's
(`crates/sipral-media/src/plc.rs`): it
kept the audio from before a hole — frames it concealed, or silence it never
saw — and joined the frame after the hole straight on. The lab's tone repeats
every five frames, so after a hole of four the resumed frame matched the one
before the hole exactly, one frame back in that joined history; the next loss
took that as a one-frame period and opened on the resumed frame's first
sample instead of continuing from its last — after a gap long enough to fade
to silence, the start of the fade. The frame after any hole now starts the
history again (`Concealer::received` after a gap, `Coder::interrupted` for
silence and comfort noise), and `plc.rs` and `crates/sipral/src/tests.rs`
carry both shapes as tests over the tone's phases, and the same hole filled
with comfort noise packets, each failing without the fix by a jump of the
order the lab measured.

The rate a single full lab run meets this is low — one `lossy` call in 60
short ones before the fix, 1.7%, under 9% at 95% confidence — but it was
never noise: each flagged splice, read sample by sample, is a jump of about
the tone's whole amplitude, clearing the threshold by 11%, 40% and 17%,
while no smooth splice in any of these calls came nearer than 57% of it. The
thresholds stay as they are; loosening them would have hidden this. With
only two calls that clicked before the fix, the calls after it cannot show a
lower rate at any useful confidence on their own (no click in 3515 splices
against three in 3132 before it, p = 0.10 — and two of the three are one
gap, so counted by gap it is two against none, p = 0.22); what shows the fix is the
mechanism, reproduced in the tests and read off the evidence above.

`blackout` is different in kind: the outage silences the far end's tone for
whole seconds at once, which `MediaSession` reports as `Playback::Silence`
rather than concealment, so no splice is checked either side of it and
segmental SNR is unaffected on whatever does arrive — a long gap is not what
this gate is for, `interop/impairment/blackout.sh` is. Redirecting ingress
through `ifb` changed that profile too, in a different way: its own outage
check used to cut and read `$link` alone, which — once `$link` also carried
the ingress `handle ffff:` qdisc this section's own fix added beside the
netem one — made `tc -s qdisc show dev "$link"` print two "Sent" lines where
the check expected one, failing the arithmetic outright rather than the
impairment. `blackout.sh` now cuts both `$link` and `$ifb` and reads the
outage back from `$ifb` alone, the ingress side, which is what governs
whether this end actually heard the silence rather than merely failed to
send into it.

## Layers of testing

**Unit, with a fake clock.** Every transaction and dialog state machine is
driven by feeding bytes and advancing time explicitly. Timer A retransmission,
timer B timeout, the `CANCEL` versus `200 OK` race, a fork producing three early
dialogs: all of these are ordinary tests, not integration scenarios.

**Corpus.** The 49 RFC 4475 torture messages under `fixtures/rfc4475/`, byte for
byte from the archive in the RFC's Appendix A, one directory per section and a
manifest with the expected outcome of each. The 13 valid parser cases must parse
and round trip byte for byte; the 22 invalid ones must be rejected without a
panic and without unbounded work; the 14 semantic cases are well formed and test
what the transaction and UA layers do with them, not the parser.

A rejection is either the parser refusing the message or `RawMessage::validate`
refusing a field in it, and the corpus does not distinguish: both end with the
message not acted on, and which one happens depends on whether the fault is in
the framing or in a field. What a live endpoint does with the second kind is
answer 400 naming the field, before anything matches a transaction to it
(RFC 3261 §8.2.x); an ACK is dropped instead, because nothing answers an ACK.
The corpus test calls `validate` directly rather than through an endpoint, so
what it proves is the judgement, and `endpoint::tests` proves the answer. Three messages carry a per-message outcome that differs
from their group's — `insuf`, `multi01` and `mcl01` sit in the application
section but their RFC text asks for a 400 outright — with the reason written
beside them in the manifest.

The semantic cases, and those three, are also fed whole to a user agent in
`crates/sipral-ua/src/rfc4475_tests.rs`, over the transport each one's `Via`
names, and what goes back on the wire is held to the RFC's paragraph for it:
416 for the two Request-URI schemes, 405 for the five REGISTERs (this stack is
not a registrar), 420 for `bext01`, 415 for `invut`, 406 for `sdp01`, 400 for
`multi01` and for `inv2543` (it names no `Contact`), 200 for `zeromf` and
`badbranch`, 400 for `mcl01` over UDP (refused as a message, then answered
statelessly from the fields that can still be read; over a stream the
connection goes instead), 400 for `insuf` (it has no `From`, `To` or
`Call-ID` to copy, so the answer carries the `Via` that routes it and the
`CSeq` the client matches it on, and invents nothing for the rest), and
nothing at all for `bcast`.

`scripts/check.sh` verifies every file's hash, so the corpus cannot drift, and
`crates/sipral-core/tests/rfc4475.rs` reads the manifest rather than repeating
it. The hash check runs near the top of the gate, before anything is built.

**Recorded-session replay.** Sessions captured in the lab or in the field,
replayed against the stack byte for byte in the format `docs/18-replay.md`
defines. `fixtures/replay/` holds the first of them; an interoperability bug
found in the field joins it on the day it is found, and does not regress
again.

**Fuzzing.** `cargo fuzz` (libFuzzer). The fuzz crate lives under `fuzz/`,
outside the workspace, with its own `rust-toolchain.toml` pinned to a nightly
date and its own lockfile, so the rest of the tree keeps its stable pin.

Thirty targets, one per door an attacker's bytes come through.

The four over SIP itself. `parse` walks every typed accessor after a
successful parse, because a message that parses can still hold a field nobody
can read and reading it is what the stack does next. `framer` takes the first
byte of the input as its read size, so one input covers both "the whole
message at once" and "one byte at a time". `builder` feeds arbitrary bytes in
as header values and asserts the result parses back with exactly the fields
that went in: what it is really testing is that a caller's data cannot become
structure. `sdp` asserts that a description which parses, written back out,
parses again into exactly the same description — a body travels through a call
inside messages that get forwarded, so one that changes meaning by passing
through here is a bug even when nothing crashes — and then answers the offer,
since an answer is derived from the offer and a strange offer is the shortest
way to a strange answer.

Ten more, added once it was clear how much of the receive path the first four
never reached. `crypto` takes an `a=crypto` line through the syntax parser and
then through the policy reader that decodes its key material, which `sdp`
never calls into. `replay` takes the recording format, which is a text file a
person hand-edits and mails as an attachment. `dialoginfo` takes the
`application/dialog-info+xml` body a SUBSCRIBE gets back, through a
hand-rolled reader with bounds of its own on nesting, element count and value
length. `mwi` takes the `application/simple-message-summary` body a
`message-summary` NOTIFY carries, through the same shape of reader, bounded on
the document, the line, the class name and the message counts instead.
`headless` takes the control channel a voice agent connects on, frame
reassembly and JSON decode together, cut into arbitrary reads. `rtcp` takes a
compound packet and every typed accessor the receive path calls on one.
`rtp_dtmf` takes a stream of datagrams through the packet parser and the RFC
4733 event receiver behind it, where the timestamps, the end bits and the
reordering are all the sender's to choose. `srtp_unprotect` takes forged and
truncated packets through SRTP and SRTCP unprotect with a fixed key: almost
everything fails authentication, which is the point — what is under test is
the length arithmetic, the header parse, the rollover estimate and the replay
window, all of which run before the check. Its input is a run of datagrams,
an octet of length in front of each, driven through one unprotector per
suite rather than one packet through a fresh one: the window and the
estimate are the only state an unprotector keeps between packets, and a
fresh one for every input reaches neither of them. `stun` takes a datagram
through the message parser and every accessor a binding client or an ICE
agent calls, since STUN and media share a port by design. `turn` takes the stream framer
and ChannelData both ways they arrive, delimited and self-delimiting.

Two for DTLS, whose peer's bytes are read before anything in them is
authenticated. Neither covers the seam a call goes through now that the
handshake is joined to one: `sipral_nat::classify` sorting a hostile datagram
on the media port and `MediaSession::receive` routing it. A target for that —
a session opened awaiting its keys, and a run of datagrams from alternating
addresses — is the one that should exist and does not. `dtls_record` takes a run of datagrams, two octets of length in
front of each, through the record reader, the handshake fragment reader and
one reassembler kept across the run, through AES-GCM open behind one replay
window, and into a server and a client `Connection` built from fixed keys —
the server without a cookie exchange, so a ClientHello the fuzzer finds
reaches the handshake. Its seeds are the two sides of a real handshake between
those same two ends, so a seed takes the server, or the client, to its
Finished before the fuzzer has changed an octet. `dtls_handshake` takes a
message type and a body through the message parser and asserts that a body
which parses writes back as the same octets, since a handshake signs a hash of
what it received; then through what a handshake reads next from that message:
the cookie check, the certificate's key and fingerprint, the key exchange
point, the signatures.

One more, added for `sipral-ua`'s own INFO-based DTMF (`docs/04-ua.md`).
`dtmf_info` takes
a `Content-Type` and a body — the first byte says how many of the rest name
the header, capped at what is left, and the remainder is the body — through
`sipral_ua::dtmf::parse_info`, the reader an incoming INFO answers 200, 415
or 400 with. Neither body it reads has an RFC of its own (`docs/04-ua.md`),
so nothing but this parser's own bound on the accepted characters and on how
long a tone lasts says what a peer may claim, and this is what proves it
never panics on a claim that breaks it.

And one for the ICE agent itself. `stun` and `turn` above read a message;
`ice` drives the state machine over them, where a datagram is not merely
parsed but changes what the agent believes about its peer. It builds an agent
the way the agent insists on being built — `new`, `add_stream`, `gather`,
`set_remote`, none of which is fuzzed, because an agent that never reached
`gather` answers `Received::Foreign` to everything and would fuzz nothing —
and then feeds it arbitrary datagrams from a source the input chooses, topping
up the transaction-id pool and taking the clock forward between them. It
asserts what the agent must never do rather than only that it does not panic:
every probe leaves from a socket it was given, `send` appends to the caller's
buffer instead of overwriting it, and a datagram the agent reports as
`Foreign` has not moved the selected pair.

And one for the lite role's own state machine, which `ice` above never
drives directly: `IceAgent` reaches `LiteAgent` only across a simulated
network in `sipral-nat`'s own tests, not with a fuzzer's bytes. `ice_lite`
builds a `LiteAgent` the way the crate insists on being built — `new`, and
`restart` on the input's say-so, mid-run, under credentials the target keeps
signing requests against, old and new — and feeds `answer_binding_request`
arbitrary datagrams for both components from a source the input chooses. Past
authentication is the same seam `ice` fuzzes for the full role: every byte of
it runs before anything has proven who the peer is. What it asserts beyond
not panicking is the one invariant a lite agent has no checklist to fall back
on for: an answer parses back as STUN, a datagram this agent did not answer
has not moved the component's valid pair, and a session that started
controlled never becomes controlling, since RFC 8445 §6.1.1 makes a full
peer's role controlling unconditionally and this is the only peer a lite
agent's answering side ever hears from at all (§8.2 — two lite agents
exchange no connectivity checks).

And one for the TURN client, since `turn` reads only its
framing. `turn_client` is a program: a configuration byte, then instructions
that answer the last request the client sent, hand it a datagram of the
fuzzer's own, move the clock, or ask it to permit, bind or send. An answer is
written with the request's own method and transaction id, so no input is
spent guessing ninety-six random bits, and it can be signed with the key the
configured credential derives under either password algorithm, so the paths
behind the integrity check are reached — allocation, refresh, permissions,
channels, stale nonces, the algorithm a challenge offers. It asserts that
every control message the client writes parses, that a range handed back
indexes the datagram it came from, that a send appends to the caller's buffer,
and that no instruction raises events without end. A configuration over TCP
takes every answer and every datagram of the fuzzer's as a stream instead, in
two reads cut where the input's first byte says, so the reassembly decides
where one message ends; a range handed back must index the frame it came in,
and a stream that stops making sense must have lost the allocation.

The `ice` target's seeds are the reason it reaches anything. A connectivity check is
authenticated before it is acted on, so an unsigned datagram dies at the door
and a coverage-guided fuzzer will not forge an HMAC to get past it: the seeds
carry checks signed with the same password the harness publishes, one of them
nominating, plus a response and a role conflict answering the first
transaction id the harness hands out. Those six seeds alone reach more of the
agent than several hundred thousand random runs did before they existed.

Ten more cover the media path, each driving one piece through its public
entry point rather than through a call: `media_resample` the resampler,
`media_plc` the loss concealer, `media_drift` the drift corrector,
`media_comfort_noise` the comfort-noise payload's decoder, encoder and
generator, `media_vad` the voice-activity detector, `media_g722`,
`media_g729` and `media_opus` each codec's decoder on octets no encoder
produced (and G.722's encoder too), `media_mix` the local mixer's sums, and
`headless_media` the facade's `HeadlessSession` between the socket's frames
and a codec's.

```sh
./scripts/fuzz.sh 600 parse        # one target, ten minutes
./scripts/fuzz.sh 600              # every target, ten minutes each
```

That is the command to reach for, and it works on a clone that has never
fuzzed. What it runs, for one target, is this — and the `mkdir` is part of
it rather than a detail, because libFuzzer refuses a corpus directory that
does not exist instead of creating one, and on a fresh tree the first of the
two does not:

```sh
cd fuzz
mkdir -p target/corpus/parse       # where the run puts what it finds
cargo fuzz run parse target/corpus/parse corpus/parse -- \
    -max_total_time=600 -max_len=65535 -rss_limit_mb=2048
```

Seeds are committed, under `fuzz/corpus/<target>/`, so that a clone gets
targets with something to start from rather than thirty runs beginning at
the empty input. `tools/fuzz-seeds` writes them out of the library's own
builders and encoders and puts each one through the reader its target puts
it through — the framer seeds through the framer, the protected runs through
an unprotector holding the target's own key, the DTLS runs through ends built
as the target builds them — so a seed that is not what it claims to be fails
the generator rather than sitting in the corpus doing nothing — the
`turn_client` programs through a client driven the way the target drives
one, each required to end with an allocation. Twenty-nine of
the thirty families go through that check; the one that does not is `builder`,
whose input is not a message but the five field
values the target cuts it into, so what is checked there is the cut. The
generator also owns the directory: what it does not write, it removes, since
a seed dropped from the generator and left on disk would otherwise pass a
check that only asks whether every target has a directory.

That is also what makes their origin sayable: `fuzz/corpus/README.md` says
where every byte came from, and `scripts/check.sh` holds the directory to
it, shape and content both — every subdirectory a target and every target a
subdirectory, the whole of it under 200 KB, and every byte of every seed
read for an address, a forbidden project's name, an assistant trace and
Romanian, the same four things the rest of the tree is read for. What a run
finds goes somewhere else — the first corpus directory on the command line
above is a scratch under `fuzz/target/`, which is ignored, so a corpus that
grows without bound is not the committed one. The RFC 4475 corpus is a
second seed source worth pointing a long run at; it stays in
`fixtures/rfc4475/`, where its licence is declared.

Bounds: a memory limit and a time limit per run, so a hang is a failure rather
than something to wait out.

The phase 1 exit gate is 24 hours on each target with no crash and no timeout,
counted in CPU-hours. It was run on 21 and 22 September 2026 on a 32-core
Linux machine: every target 48 runs of 30 minutes each, 24 CPU-hours a target
and 432 in all, the eighteen sharing a corpus per target and queued
round-robin so that each had the same share of the machine. About 37 billion
executions, and no crash, no timeout and no run out of memory on any target.
The eight media targets, added after that run, had the same gate on 23
September 2026: 48 runs of 30 minutes each per target, 192 CPU-hours in all,
about 24 billion executions, and nothing found on any of them.
`headless_media`, `media_g729` and `turn_client`, the newest three, had it on
25 September 2026, the same way: 144 runs of 30 minutes, 72 CPU-hours in all,
and not one run that exited with an error or left an input behind. The
executions say how differently those three spend a CPU-hour: about 231
million for `turn_client`, 42 million for `headless_media`, and 0.67 million
for `media_g729`, which decodes every input and encodes the result again, so
its 24 hours reached a far smaller share of its input space than any other
target's did. `ice_lite`, the newest, had it on 27 September 2026, the same
way: 48 runs of 30 minutes, 24 CPU-hours, about 254 million executions, and
not one run that exited with an error or left an input behind. Outside that gate, `scripts/fuzz.sh` runs each target for as long as it is
given, five minutes each by default — before a release and overnight, not
before every commit, which would add an hour to buy very little. What the gate does
do on every run is **build** all thirty, under the nightly that `fuzz/` pins, so
that a target cannot rot uncompiled between releases; `cargo test --workspace`
never looks inside `fuzz/`, which is a workspace of its own. Every crashing
input will be minimised and committed under `fixtures/regressions/` with the
fix, and the test suite will replay that directory forever. No input has
crashed a target yet, so the directory does not exist — and the whitelist in
the "provenance" step of `scripts/check.sh` widens on the day it does.

**Media measurement.** Impairment profiles built with `tc netem` and committed
alongside the tests, so a quality claim is reproducible rather than remembered.
Loss, burst loss, jitter, reordering, and combinations of them.

**Live interoperability.** The matrix below, run by hand before a release.

## Fixtures

`fixtures/rfc4475/` holds the IETF corpus. It is public material and is
committed.

`fixtures/replay/` holds recorded sessions in the format `docs/18-replay.md`
defines: the inbound messages of a session, their timing and the seed the run
was drawn from. Each one is a test — replayed, and the bytes, events and
diagnostic record compared against the run that produced it — so a failure
captured once is a failure that cannot come back unnoticed. The format is text
with no binary spelling at all, which is what keeps audio structurally out of
it rather than merely absent; a recording is still a *transcript of what a peer
sent*, so one made against a live system is reviewed by hand before it is
committed, exactly as a capture would be.

Captures from live traffic hold real numbers, real IP addresses and real
Call-IDs. **They are never committed to this repository.** They live in a
separate, permanently private repository, and only anonymised subsets reach this
tree, each one reviewed by hand. `.gitignore` blocks capture files outside
`fixtures/rfc4475/`, and `scripts/check.sh` fails if one appears anyway.

## Interoperability matrix

Run before each release, and recorded with the version of each peer.

| Peer | Configuration | What it proves |
|---|---|---|
| Kamailio | lab, as deployed | registration and routing through a proxy |
| OpenSIPS | lab, its own step only | a second opinion on the same: Kamailio and OpenSIPS share an ancestor but have diverged for fifteen years, so a rule both of them route the same way is not one implementation's private reading of it |
| FreeSWITCH | lab, as deployed | full call features, transfer, hold |
| Asterisk | `chan_pjsip`, container, defaults | the configuration most integrators actually have; transfer against a second implementation |
| baresip | built from source (`interop/baresip/Dockerfile`), registered at Kamailio as a second lab user | phone to phone: a call whose dialog and media run end to end against a second client stack, not a server, since Kamailio is a proxy and never joins either |
| Carrier A | Romanian, paid account | real trunking, real codecs |
| Carrier B | international, paid account | a second opinion on everything carrier A does |
| Commercial SBC | where access exists | the strict end of the spectrum |

Two carriers rather than one, because the first carrier's quirks are
indistinguishable from correct behaviour until a second one disagrees.

The table above is what the peers are and why each one is here. What each one
actually did, the last time `scripts/lab.sh` ran, is generated rather than
remembered: `scripts/interop-matrix.py` reads a run's own output and writes
the block below, peer by flow by result, with the version of everything it
reached and the day it reached it. `scripts/lab.sh --matrix` regenerates it
after a live run; `scripts/check.sh` regenerates it from
`interop/fixtures/lab-run.log` and fails if what that produces is not what is
committed here. Edit `interop/features.toml` for the feature table below, or
the generator itself — never the block, which the next run overwrites.

<!-- BEGIN GENERATED interop-matrix -->

*Generated by `scripts/interop-matrix.py` from `lab-run.log`, a `scripts/lab.sh` run recorded 2026-09-27. Edit `interop/features.toml` or the source data, then regenerate with `scripts/lab.sh --matrix` — not this block, which `scripts/check.sh` checks against `interop/fixtures/lab-run.log` and overwrites otherwise.*

### Results

| Peer | Version | Flow | Result | Date |
|---|---|---|---|---|
| Kamailio → FreeSWITCH | 6.1.4 (proxy) / 1.10.12 (FreeSWITCH) | register | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 (proxy) / 1.10.12 (FreeSWITCH) | call | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 (proxy) / 1.10.12 (FreeSWITCH) | hold and resume | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 (proxy) / 1.10.12 (FreeSWITCH) | blind transfer | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 (proxy) / 1.10.12 (FreeSWITCH) | attended transfer | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 (proxy) / 1.10.12 (FreeSWITCH) | DTLS-SRTP, held and resumed | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 (proxy) / 1.10.12 (FreeSWITCH) | forked, the second phone answering first | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 (proxy) / 1.10.12 (FreeSWITCH) | register (C ABI) | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 (proxy) / 1.10.12 (FreeSWITCH) | call (C ABI) | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 (proxy) / 1.10.12 (FreeSWITCH) | hold and resume (C ABI) | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 (proxy) / 1.10.12 (FreeSWITCH) | blind transfer (C ABI) | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 (proxy) / 1.10.12 (FreeSWITCH) | attended transfer (C ABI) | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 (proxy) / 1.10.12 (FreeSWITCH) | DTLS-SRTP, held and resumed (C ABI) | pass | 2026-09-27 |
| OpenSIPS → FreeSWITCH | 4.0.2 (proxy) / 1.10.12 (FreeSWITCH) | register | pass | 2026-09-27 |
| OpenSIPS → FreeSWITCH | 4.0.2 (proxy) / 1.10.12 (FreeSWITCH) | call | pass | 2026-09-27 |
| OpenSIPS → FreeSWITCH | 4.0.2 (proxy) / 1.10.12 (FreeSWITCH) | hold and resume | pass | 2026-09-27 |
| OpenSIPS → FreeSWITCH | 4.0.2 (proxy) / 1.10.12 (FreeSWITCH) | blind transfer | pass | 2026-09-27 |
| OpenSIPS → FreeSWITCH | 4.0.2 (proxy) / 1.10.12 (FreeSWITCH) | attended transfer | pass | 2026-09-27 |
| OpenSIPS → FreeSWITCH | 4.0.2 (proxy) / 1.10.12 (FreeSWITCH) | DTLS-SRTP, held and resumed | pass | 2026-09-27 |
| OpenSIPS → FreeSWITCH | 4.0.2 (proxy) / 1.10.12 (FreeSWITCH) | register (C ABI) | pass | 2026-09-27 |
| OpenSIPS → FreeSWITCH | 4.0.2 (proxy) / 1.10.12 (FreeSWITCH) | call (C ABI) | pass | 2026-09-27 |
| OpenSIPS → FreeSWITCH | 4.0.2 (proxy) / 1.10.12 (FreeSWITCH) | hold and resume (C ABI) | pass | 2026-09-27 |
| OpenSIPS → FreeSWITCH | 4.0.2 (proxy) / 1.10.12 (FreeSWITCH) | blind transfer (C ABI) | pass | 2026-09-27 |
| OpenSIPS → FreeSWITCH | 4.0.2 (proxy) / 1.10.12 (FreeSWITCH) | attended transfer (C ABI) | pass | 2026-09-27 |
| OpenSIPS → FreeSWITCH | 4.0.2 (proxy) / 1.10.12 (FreeSWITCH) | DTLS-SRTP, held and resumed (C ABI) | pass | 2026-09-27 |
| Asterisk | 22.10.1 | register | pass | 2026-09-27 |
| Asterisk | 22.10.1 | call | pass | 2026-09-27 |
| Asterisk | 22.10.1 | hold and resume | pass | 2026-09-27 |
| Asterisk | 22.10.1 | blind transfer | pass | 2026-09-27 |
| Asterisk | 22.10.1 | attended transfer | pass | 2026-09-27 |
| Asterisk | 22.10.1 | DTMF, RFC 4733 | pass | 2026-09-27 |
| Asterisk | 22.10.1 | DTMF, SIP INFO | pass | 2026-09-27 |
| Asterisk | 22.10.1 | SRTP | pass | 2026-09-27 |
| Asterisk | 22.10.1 | hold with a codec change | pass | 2026-09-27 |
| Asterisk | 22.10.1 | MESSAGE, echoed | pass | 2026-09-27 |
| Asterisk | 22.10.1 | message waiting indication | pass | 2026-09-27 |
| Asterisk | 22.10.1 | G.729, echoed | pass | 2026-09-27 |
| Asterisk | 22.10.1 | DTLS-SRTP, held and resumed | pass | 2026-09-27 |
| Asterisk | 22.10.1 | local conference | pass | 2026-09-27 |
| Asterisk | 22.10.1 | register (C ABI) | pass | 2026-09-27 |
| Asterisk | 22.10.1 | call (C ABI) | pass | 2026-09-27 |
| Asterisk | 22.10.1 | hold and resume (C ABI) | pass | 2026-09-27 |
| Asterisk | 22.10.1 | blind transfer (C ABI) | pass | 2026-09-27 |
| Asterisk | 22.10.1 | attended transfer (C ABI) | pass | 2026-09-27 |
| Asterisk | 22.10.1 | DTMF, RFC 4733 (C ABI) | pass | 2026-09-27 |
| Asterisk | 22.10.1 | DTMF, SIP INFO (C ABI) | pass | 2026-09-27 |
| Asterisk | 22.10.1 | SRTP (C ABI) | pass | 2026-09-27 |
| Asterisk | 22.10.1 | hold with a codec change (C ABI) | pass | 2026-09-27 |
| Asterisk | 22.10.1 | MESSAGE, echoed (C ABI) | pass | 2026-09-27 |
| Asterisk | 22.10.1 | message waiting indication (C ABI) | pass | 2026-09-27 |
| Asterisk | 22.10.1 | G.729, echoed (C ABI) | pass | 2026-09-27 |
| Asterisk | 22.10.1 | DTLS-SRTP, held and resumed (C ABI) | pass | 2026-09-27 |
| Asterisk | 22.10.1 | local conference (C ABI) | pass | 2026-09-27 |
| Asterisk | 22.10.1 | Python agent example | pass | 2026-09-27 |
| Asterisk | 22.10.1 | headless socket agent example | pass | 2026-09-27 |
| Asterisk | 22.10.1 | Swift agent example | pass | 2026-09-27 |
| Asterisk | 22.10.1 | Kotlin agent example | pass | 2026-09-27 |
| Asterisk | 22.10.1 | .NET agent example | pass | 2026-09-27 |
| Asterisk | 22.10.1 | a REFER from outside any call, referraloff — refused 403 in 2030 ms, nothing after it (C ABI) | pass | 2026-09-27 |
| Asterisk | 22.10.1 | a REFER from outside any call, referral — 202, then 3 NOTIFYs from 100 to 200 in 55 ms (C ABI) | pass | 2026-09-27 |
| baresip (phone to phone, via Kamailio) | 4.11.0 (baresip) / 6.1.4 (proxy) | call | pass | 2026-09-27 |
| baresip (phone to phone, via Kamailio) | 4.11.0 (baresip) / 6.1.4 (proxy) | hold and resume | pass | 2026-09-27 |
| baresip (phone to phone, via Kamailio) | 4.11.0 (baresip) / 6.1.4 (proxy) | SRTP, phone to phone | pass | 2026-09-27 |
| baresip (phone to phone, via Kamailio) | 4.11.0 (baresip) / 6.1.4 (proxy) | DTLS-SRTP, phone to phone | pass | 2026-09-27 |
| baresip (phone to phone, via Kamailio) | 4.11.0 (baresip) / 6.1.4 (proxy) | call (C ABI) | pass | 2026-09-27 |
| baresip (phone to phone, via Kamailio) | 4.11.0 (baresip) / 6.1.4 (proxy) | hold and resume (C ABI) | pass | 2026-09-27 |
| baresip (phone to phone, via Kamailio) | 4.11.0 (baresip) / 6.1.4 (proxy) | SRTP, phone to phone (C ABI) | pass | 2026-09-27 |
| baresip (phone to phone, via Kamailio) | 4.11.0 (baresip) / 6.1.4 (proxy) | DTLS-SRTP, phone to phone (C ABI) | pass | 2026-09-27 |
| Asterisk, from behind a NAT (STUN) | 22.10.1 | behind a NAT, through STUN (C ABI) | pass | 2026-09-27 |
| Asterisk, from behind a NAT (STUN) | 22.10.1 | called behind a NAT, through STUN (C ABI) | pass | 2026-09-27 |
| headless agent (ICE-lite) | n/a | ICE required, against 172.18.0.5 | pass | 2026-09-27 |
| Asterisk | 22.10.1 | ICE-lite, Asterisk's ICE calling in | pass | 2026-09-27 |
| headless agent (ICE-lite) | n/a | ICE required, against 172.18.0.5 (C ABI) | pass | 2026-09-27 |
| sipral, self-to-self (each behind its own NAT) | n/a | full ICE through two NATs, calling | pass | 2026-09-27 |
| sipral, self-to-self (each behind its own NAT) | n/a | full ICE through two NATs, calling, blocked without TURN | pass | 2026-09-27 |
| sipral, self-to-self (each behind its own NAT) | n/a | full ICE through two NATs, calling, via TURN | pass | 2026-09-27 |
| sipral, self-to-self (each behind its own NAT) | n/a | full ICE through two NATs, calling, blocked without TURN (C ABI) | pass | 2026-09-27 |
| sipral, self-to-self (each behind its own NAT) | n/a | full ICE through two NATs, calling, via TURN (C ABI) | pass | 2026-09-27 |
| sipral, self-to-self (each behind its own NAT) | n/a | full ICE through two NATs, calling, via TURN, caller relay only (C ABI) | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 | register, over a bad link (lossy) | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 | call, over a bad link (lossy) | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 | register, over a bad link (mobile) | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 | call, over a bad link (mobile) | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 | register, over a bad link (satellite) | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 | call, over a bad link (satellite) | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 | register, over a bad link (blackout) | pass | 2026-09-27 |
| Kamailio → FreeSWITCH | 6.1.4 | call, over a bad link (blackout) | pass | 2026-09-27 |
| Carrier A | — | — | untested | — |
| Carrier B | — | — | untested | — |
| Commercial SBC | — | — | untested | — |
| 3CX | — | — | untested | — |
| Teams Direct Routing | — | — | untested | — |
| AudioCodes | — | — | untested | — |
| Ribbon | — | — | untested | — |

### Feature status

| Feature | Implemented | Unit-tested | Interop-tested |
|---|---|---|---|
| Registration and refresh | yes | yes | yes |
| Call setup and teardown | yes | yes | yes |
| Hold and resume | yes | yes | yes |
| Blind transfer | yes | yes | yes |
| Attended transfer | yes | yes | yes |
| REFER from outside any call (RFC 3515 §4.1), off unless asked for | yes | yes | not yet |
| DTMF, RFC 4733 | yes | yes | yes |
| DTMF, SIP INFO | yes | yes | yes |
| SRTP (SDES) | yes | yes | yes |
| DTLS-SRTP | yes | yes | yes |
| Codec change while held | yes | yes | yes |
| SIP MESSAGE | yes | yes | yes |
| Message waiting indication | yes | yes | yes |
| Forked call, the second phone answering first | yes | yes | yes |
| Local conference (three-party mix) | yes | yes | yes |
| G.729 (Annex A), offered when named | yes | yes | yes |
| Narrowed inbound offer | yes | yes | not yet |
| Python binding | yes | yes | yes |
| Bad-network resilience (audio quality gate) | yes | yes | yes |
| STUN (RFC 5389), from behind a NAT | yes | yes | yes |
| ICE-lite (RFC 8445 §2.5), harness and Asterisk | yes | yes | yes |
| ICE (RFC 8445, full agent role) | yes | yes | yes |
| TURN relay (RFC 8656) | yes | yes | yes |
| G.729 Annex B (SID/DTX) | yes | yes | n/a |
| Headless socket agent | yes | yes | yes |
| Swift binding | yes | yes | yes |
| Kotlin binding | yes | yes | yes |
| .NET binding | yes | yes | yes |
| PipeWire audio backend | yes | yes | n/a |
| WASAPI audio backend | yes | yes | n/a |

<!-- END GENERATED interop-matrix -->

Known peer behaviours worth writing down rather than rediscovering:

- FreeSWITCH ships with 100rel disabled. PRACK is implemented for carriers, not
  for the lab.
- Asterisk `res_pjsip` defaults `max_contacts=0`, which refuses every
  registration. Server misconfiguration, always blamed on the client.
- baresip's `menu` application module, not its core, reads an account's
  `answermode` and answers a call on its own; naming `account.so` without
  `menu.so` in `interop/baresip/config/config` gets a registered peer that
  never picks up.
- The official OpenSIPS 4.0 image leaves digest authentication out: `auth.so`
  is in the `opensips-auth-modules` package, and it will not load without
  `signaling.so`. `proto_udp` is built into the binary and still has to be
  named with `loadmodule`, or the proxy has no transport and exits.
- Asterisk renegotiates DTLS on every re-INVITE and drops its RTP until the
  new handshake is done. With a hold and a resume a few milliseconds apart,
  its ClientHello carrying the cookie comes a full retransmission timer later,
  about a second of audio that never reaches the wire.
- FreeSWITCH, at the start of a DTLS-SRTP call, sends two packets, pauses, and
  resumes with a timestamp that has not moved, against RFC 3550 §5.1.
- `MinivmMWI()` publishes a mailbox count rather than adding to one.

## Interoperability procedure

Each live exit criterion in `10-roadmap.md` is one scripted flow, driven by
`interop/harness` (`sipral-interop`) against the container lab. Since the
harness moved onto the facade, it drives every flow through the `sipral`
facade — `MediaEngine` and
`MediaSession` for RTP, codecs, DTMF and SRTP — the same seam a real
application links, rather than through a second RTP/codec pipeline written
for the lab alone: **a phase whose proof runs on a path no customer uses has
not exited** (`10-roadmap.md`). `crate::audio` in the harness is what a real
application still has to write for itself either way — a socket and a
tone — not a second media join. Pass and fail are defined per flow, not
judged at the time; a flow that did four things out of five is a failure
naming the fifth, printed as `FAIL <flow> — <what did not hold>`.

The same flows run **a second time, through the C ABI**, driven by
`interop/harness-c`. That is not redundancy. The Rust driver reaches
`MediaEngine` and `UserAgent` as Rust types, which is not how anybody outside
this repository will ever reach them, so it is structurally incapable of
noticing a defect that lives in the boundary: a struct whose length the header
and the library disagree about, a handle that goes stale, an entry point that
wants a clock nobody passes it, a sequence that cannot be expressed from C at
all. Those are what an integrator meets on the first afternoon, and this is
what meets them first. It is C99 with warnings fatal and nothing linked but
libc and the library, it learns what happened from `sipral_event_t` and from
nothing else, and it prints and exits exactly as the Rust driver does so that
`scripts/lab.sh` reads both with one parser. `scripts/check.sh` compiles it on
every run without running it — what it needs is four servers — so an ABI
change that would stop an integrator's program building fails at the moment it
is made. **This is the phase-1 exit criterion and the precondition for
freezing the ABI** (`10-roadmap.md`, `08-ffi.md`).

Both drivers seed every flow's stack with a pattern fixed per flow — `seed`/
`media_seed` in `interop/harness/src/main.rs`, `seeds_for` in
`interop/harness-c/main.c`, and the Rust driver's steps outside the flow
table (`fork`, `join`, `pair`, `drift`, `latency`, `volume`, `ice_lite`,
`ice_nat`, `pipewire`, `wasapi`) with constants of their own through
`run_folded` — folded by XOR
with thirty-two bytes of entropy
drawn fresh from the operating system once per run and printed at its start
(`seed: <64 hex digits>`), so two runs of the same flow never mint the same
`Call-ID`, `From` tag or first branch: a server that still held the previous
run's transaction or dialog otherwise read the new one as the same request
arrived twice and answered 482 Request Merged. `SIPRAL_HARNESS_SEED`, the
same 64 hex digits, pins the run seed instead of drawing one, so a run that
hit a failure can be repeated exactly; the per-flow pattern is unaffected,
so flows within a repeated run still differ from each other the way they
always did. The harnesses' own unit tests keep the fixed pattern with no
run seed folded in, through `interop/harness/src/main.rs`'s own
`tests::scripted`, since what they want is the reproducible pattern rather
than a fresh one on every `cargo test`.

It runs the same fifteen flows the Rust driver runs, against the same
servers, the two phone-to-phone ones against baresip among them, and the
G.729 call among those on Asterisk — its codec chosen by the call's own
`sipral_call_config_t::codecs`, with the stack's order left at G.711. The codec
change was the one the C surface could not express until
`sipral_call_change_codecs` existed — and the Rust driver could not either,
through the facade: it wrote that re-offer itself until
`MediaEngine::change_codecs` did. MESSAGE and message waiting indication
run in C too, driven by `sipral_account_message` and
`sipral_account_subscribe`. The local-conference flow (below) runs in C as
well, driven by `sipral_call_join`, `sipral_call_leave` and
`sipral_media_mix` — it needs two calls on one account rather than a second
account, which is the shape `interop/harness-c`'s one-endpoint-at-a-time
design already has, unlike the opt-in narrowed-inbound flow at the bottom of
the table, which stays the Rust driver's alone since it needs a second
account registered at once. The relayed call through TURN (below) places its
calling half from C as well, with the Rust driver answering behind the other
NAT: the TURN server and its credential go in through
`sipral_stack_config_t`, and everything the relay does after that is read off
the same ABI.

Run through Kamailio to FreeSWITCH, through OpenSIPS to the same FreeSWITCH,
and straight at Asterisk (`scripts/lab.sh kamailio` / `opensips` / `asterisk`),
unless a column below says one server only. OpenSIPS is started for its own
step alone and torn down right after — see the note in `interop/compose.yaml`
— so its results are read off `scripts/lab.sh`'s own output, not off a
container left running beside the other three. "baresip only" is
`scripts/lab.sh baresip`: the same proxy as the plain kamailio run,
`kamailio`, but the call is placed at baresip's own AOR rather than at
FreeSWITCH, and Kamailio relays the dialog without ever joining it — the one
place in this table where the far end is a second client stack rather than a
server:

| Flow | Pass condition | Servers |
|---|---|---|
| register | bound, one binding round trip observed, then given back | all three |
| call | connected, hung up by this end, ended | all three |
| hold and resume | as call, plus the hold and the resume both agreed | all three |
| blind transfer | connected, the transfer completed (its own status read from the `NOTIFY` sipfrag), the far end ended it | all three |
| attended transfer | as blind, plus the consultation leg itself connected first | all three |
| DTMF, RFC 4733 | connected, a digit sent as a named telephone event named back the same way by the lab's own dialplan (`interop/asterisk/extensions.conf`'s 9003), hung up, ended. Not run through the proxy to FreeSWITCH yet: its 9003 in `interop/freeswitch/lab.xml` never named the digit back, dialled at once or after a pause, and a flow is not run where it is known not to pass until the reason is found | Asterisk only |
| DTMF, SIP INFO | connected, the same digit sent by `UserAgent::send_dtmf_info` instead, answered with success (`UaEvent::DtmfSent`) and named back the same way by extension 9003 — against the lab's own `labuser-infodtmf` endpoint (`interop/asterisk/pjsip.conf`, `dtmf_mode=info`), so `SendDTMF()`'s own echo goes back over INFO too and this end's receiving half is exercised against a real peer as well as its sending one — hung up, ended | Asterisk only |
| SRTP | connected under SDES against the lab's own SDES endpoint (`interop/asterisk/pjsip.conf`'s `labuser-srtp`, extension 9004) — refused rather than answered plainly if the far end will not key it | Asterisk only |
| DTLS-SRTP, held and resumed | connected against the lab's own DTLS endpoint — on Asterisk `interop/asterisk/pjsip.conf`'s `labuser-dtls`, on FreeSWITCH extension 9005 of `interop/freeswitch/lab.xml`, which makes secure media mandatory for that call alone and certifies with the RSA-4096 key FreeSWITCH generates for itself, so the flow is also the proof that a peer's RSA certificate keys a call in either role — keyed by its own handshake — `SIPRAL_EVENT_KIND_MEDIA_SECURED` for that call, not `MEDIA_STARTED`: a DTLS call is still waiting for its keys there — then held and resumed, both agreed, hung up by this end, ended. A handshake that fails is named from `MEDIA_FAILED`'s own reason and ends the flow at once. Audio is required only *after* the resume, not merely after the call connects: the hold and the resume are both re-offers that hand the DTLS roles back with `a=setup:actpass` (RFC 8842 §5.5), so audio heard once they are agreed says the far end answered with the roles already in force (§5.3) and the association that keyed the call still carries it | all three |
| call, phone to phone | `Flow::Call` again, dialled at baresip's own AOR instead of an extension — connected, hung up by this end, ended, audio required both ways exactly as the plain call above | baresip only |
| hold and resume, phone to phone | `Flow::Hold` again, same peer: as the row above, plus the hold and the resume both agreed by baresip's own `menu` module | baresip only |
| SRTP, phone to phone | connected under SDES against baresip's own `baresip-srtp` account (`interop/baresip/config/accounts`, `mediaenc=srtp-mand`) — refused rather than answered plainly if that peer will not key it either | baresip only |
| DTLS-SRTP, phone to phone | connected against baresip's own `baresip-dtls` account, keyed by its own handshake exactly as the DTLS-SRTP row above asks of a server — baresip's `dtls_srtp` module self-signs its own certificate at startup and is checked by fingerprint alone, the same RFC 8122 §5 / RFC 5763 §5 check Asterisk's `dtls_auto_generate_cert=yes` stands in for — a third independent DTLS-SRTP implementation, on the far side of a call this stack placed rather than answered | baresip only |
| call, ended by the far end (`Flow::PeerHangup`, key `peerhangup`) | dialled at a fifth baresip peer of its own, `baresip-hangup` (`interop/baresip/config-hangup`) — connected, then only waited on: no `listen_until` ever schedules this flow's own hangup, unlike every other row in this table but the two transfers. `scripts/lab.sh`'s own `baresip_ctrl_hangup` sends `{"command":"hangup"}` to that peer's `ctrl_tcp` port a couple of seconds in, which is baresip ending the call through its own control interface — nothing in its account or call configuration can end an already-answered one by itself, `call_local_timeout` being cancelled the instant a call is answered (`interop/baresip/config-hangup/config`'s own reasoning). Passes on `CallEndReason::RemoteHangup` alone (`Fact::RemoteEnded`); `Fact::Ours` must stay unset. The C ABI runs the same flow as `FLOW_PEER_HANGUP` (key `peerhangup`), waiting on `end_reason == SIPRAL_CALL_END_REASON_REMOTE_HANGUP` the same way | baresip only |
| hold with a codec change | as hold, but between the hold and the resume the call is moved onto a narrower codec list while it stays held (`MediaEngine::change_codecs`): the far end's answer names a different codec than the one the call held on, the hold survives the change, and the resume keeps the new codec | Asterisk only |
| local conference | two calls placed on one account — one to the lab's own tone extension (9000), one to its echo extension (9008, `Answer(); Echo();`) — joined with `MediaEngine::join` and driven a frame at a time with `MediaEngine::mix`; passes once several frames are audible while the tone extension's own cadence says it should be silent, which only the echo extension playing back what this end had just relayed to it can produce (`interop/harness/src/join.rs`'s own module documentation has the reasoning) | Asterisk only |
| forked, the second phone answering first | three stacks in one harness run (`interop/harness/src/fork.rs`): a desk and a mobile register as the one user `interop/kamailio/kamailio.cfg` forks — `forked`, looked up and relayed to every binding in parallel, which no other flow dials — the mobile second; a third calls that user. The desk rings at once and never answers, the mobile rings 400 ms later and answers at 1.2 s, so the call placed is the desk's early dialog and the mobile's is the sibling `UaEvent::CallForked` announced, and the first 2xx is the sibling's. Passes when `ForkPolicy::KeepFirst` kept the sibling (`CallConfirmed` on it), the branch placed ended `ForkLost`, the desk saw Kamailio's CANCEL (its call ended `Cancelled`), the mobile's call lasted until the caller hung up three seconds later, and at least ten frames of tone crossed each way on the branch kept. A run where the desk's branch answered instead fails as proving nothing. Run with `scripts/lab.sh kamailio`, or alone with `SIPRAL_FLOWS=fork`. On 25 September 2026, on the Linux x86-64 lab machine, it passed with 118 audible frames at the caller and 119 at the mobile; the same step built with the user agent as it was before the fix failed it, the mobile's branch hung up by the caller the moment it answered | Kamailio only |
| MESSAGE, echoed | an out-of-dialog MESSAGE (`UserAgent::message`) sent to the lab's own echo extension (`interop/asterisk/extensions.conf`'s 9006, `MessageSend()`), answered with success (`UaEvent::MessageSent`), and a MESSAGE of the dialplan's own arriving back (`UaEvent::MessageReceived`) — proving both directions, not only that this end's own send was accepted | Asterisk only |
| message waiting indication | a subscription to `message-summary` for this account's own mailbox (`labuser-mwi`, whose AOR in `interop/asterisk/pjsip.conf` has `mailboxes=9007@default` — on the AOR, since that is what a SUBSCRIBE is matched against; on the endpoint it means unsolicited NOTIFYs and every SUBSCRIBE is answered 404), read once before anything is left in it; a call into the lab's own mailbox extension (9007), whose hangup handler raises the mailbox's new-message count by one with `MinivmMWI()`, keeping the count itself since `MinivmMWI()` publishes a count rather than adding to one, so each driver's flow in the same lab run sees its own call raise it — not `VoiceMail()`, which cannot record in this image because it ships no sound files and the greeting fails; and the mailbox's `new` count (`UaEvent::MessagesWaiting`) read higher once Asterisk's own `res_pjsip_mwi` reports it — not that it starts at zero, since an earlier run may have left mail behind | Asterisk only |
| behind a NAT, through STUN (C ABI only; `scripts/lab.sh nat`) | the C harness on a network of its own (`inside`, `interop/compose.yaml`) whose only way out is `interop/nat`'s masquerading NAT, with `SIPRAL_NAT_STUN` against coturn on the lab network: both sockets' answers have to differ from the addresses they are bound to, in the host and in the port — the NAT moves the harness's two fixed ports to others, so a `Contact` or an `m=` that kept the socket's own port reaches nothing; otherwise the run fails as proving nothing — the harness holds the STUN server's answers on the signalling socket back until the account has registered its private address and Asterisk's 200 lists that binding (the REGISTER a phone sends before a slow STUN server answers), then lets the answer in: the mapping event has to count the one account it moved, and Asterisk's own 200 to the REGISTER that follows has to list the public address among its bindings and no longer the private one, which only the `expires=0` that REGISTER carries for it removes; the tone has to come back (Asterisk sends RTP only where `c=` says, and the private address is on a network it has no route to), and a hold's re-offer, read back from `SIPRAL_EVENT_KIND_SESSION_CHANGED`, has to name the public address in `c=` and `m=` | Asterisk only |
| called behind a NAT, through STUN (C ABI only; `scripts/lab.sh nat`) | the same harness behind the same NAT, called instead of calling: it registers `labuser` with `SIPRAL_NAT_STUN`, waits until Asterisk's own 200 lists the address coturn reported, and prints that binding's URI; `scripts/lab.sh` has Asterisk call exactly that URI (`channel originate PJSIP/labuser/<URI>`, since the account keeps ten bindings) into extension 9010, which echoes for eight seconds and hangs up. The INVITE has to be recognised as this account's; the media socket is named with `sipral_stack_nat_map` as the call rings and the call answered on it with `sipral_call_answer_media`, what the Kotlin and Swift layers do; the 2xx that leaves has to name the public address in its `Contact`, the one address Asterisk's ACK and BYE go to (RFC 3261 §12.1.2, Asterisk as UAC), and both have to arrive — the call confirmed by the ACK, ended by the far end's BYE; the echo has to come back to the `c=` it answered with | Asterisk only |
| ICE required, against a lite peer (`scripts/lab.sh ice`) | the harness, as the full agent, places a call under `IcePolicy::Required` straight at `headless-socket-agent --ice-lite` on the lab network, with no server between them (`interop/harness/src/ice_lite.rs`): answered, media started, a path chosen by the checks (`MediaEvent::PathChosen`, with the time from the offer to it printed), and at least ten frames of the tone back through the reference agent's echo; the application's own log has to show the pair it was nominated (`path chosen`) and audio sent on it. A lite end that did nothing leaves the harness with `IceRequired` or no path, never with audio. Then Asterisk's own ICE: an endpoint with `ice_support=yes` (`interop/ice/`, mounted over the empty `pjsip_local.conf` for this step only) calls the same agent registered to it, which has to report a nominated pair, the dialplan's `#`, and audio both ways; and Asterisk's own RTP debug has to show at least ten of its packets sent "(via ICE)" — the application's log alone cannot tell, because Asterisk nominates as it checks and sends its audio to the lite end's candidate, which is also its `c=`, whether or not a check ever succeeded, and with the lite end's answers suppressed it shows none | the harness and Asterisk |
| ICE required, against a lite C ABI stack (`scripts/lab.sh icelite`, and in `ice`) | the same call from the same harness, placed at `harness-c listen` answering under `SIPRAL_ICE_LITE` and echoing what it hears, frame for frame: the harness has to choose a path and hear at least ten frames of its tone back, and the listener has to report the pair it was nominated (`path chosen`) and audio sent on it | none; the C harness |
| a REFER from outside any call, referraloff / referral (C ABI only; `scripts/lab.sh referral`, and in `asterisk`) | the Rust harness as a switchboard, writing RFC 3515 §4.1's REFER by hand on a plain socket (`interop/harness/src/referral.rs`), at `harness-c listen`: with the listener's `referrals` off, answered 403 and nothing after it, the listener never hearing of it; with them on, answered 202, a first NOTIFY carrying `SIP/2.0 100 Trying` in `message/sipfrag` with an `active;expires=` subscription, and a last one carrying the placed call's `200 OK` with `terminated;reason=noresource` — while the listener took the referral through `sipral_call_accept_transfer`, placed the call through Asterisk to its echo (9008) and heard at least 25 frames of its own tone back | Asterisk |
| full ICE through two NATs (`scripts/lab.sh ice`) | the Rust harness twice, as caller behind `natbox` on `inside` and as callee behind a second NAT, `natbox2`, on `inside2`, both under `IcePolicy::Required` (`interop/harness/src/ice_nat.rs`): each asks coturn where its media socket appears first, and fails the run if the answer is its own address; the callee's NAT forwards its SIP port and nothing else. Both have to report a chosen path and at least ten frames of the other's tone, and the caller's path has to end at the callee's NAT — its host candidate is on a network the caller has no route to. Both print the time from the offer, and from the answer, to the chosen path | coturn and the two NATs, no server |
| full ICE through a TURN relay (`scripts/lab.sh turn`, and in `ice`) | the same two harnesses behind the same two NATs, each NAT now dropping every datagram to or from the other's outside address that is not SIP, and coturn turned into a TURN server with long-term credentials by `interop/turn/compose.override.yaml` (a user and password drawn for the run, so none is written down). First the same call without TURN has to fail with no path chosen, which is what proves the block holds; then each end allocates a relay for its media socket (`SIPRAL_TURN_*`, `sipral::Relays`, `CallMedia::relay`) and the call has to complete with ten frames of tone each way, the caller failing a path that does not go through coturn; last, coturn's own log has to show both allocations and a Refresh of lifetime zero for each, given back when the call ended. Both print the path, how long the Allocate took and the time to the chosen path. Then the same two calls with the C harness as the caller (`interop/harness-c`'s own `FLOW_ICE_NAT`, the same `icenat` key and the same `SIPRAL_TURN_*` variables) and the Rust one still answering: its stack gets `SIPRAL_NAT_STUN` and the TURN server, user and password through `sipral_stack_config_t`, names its media socket with `sipral_stack_nat_map` and places the call under `SIPRAL_ICE_REQUIRED` only once `SIPRAL_EVENT_KIND_NAT_MAPPING` and `SIPRAL_EVENT_KIND_NAT_RELAY` have both arrived, the relay allocated. Without TURN it has to find no path, as the Rust caller did; with it, `SIPRAL_EVENT_KIND_MEDIA_PATH_CHOSEN` has to arrive, ten frames of the callee's tone have to come back, and the audio the library addresses afterwards has to go to coturn's host (the event carries no addresses; every packet names its own destination). This end hangs up, and a TURN Refresh whose `LIFETIME` is zero, read off the wire format, has to have left for coturn — through `sipral_media_poll_transmit` three seconds after ICE settled on a pair that does not use this end's relay, or through `sipral_stack_poll_farewell` when the call's end released it; coturn's log then has to count four allocations in all and as many given back. With both ends relayed, ICE settles on the callee's relay and the C caller's own goes back unused, so one more call gives TURN to the C caller alone: the block leaves no path but through its own relay, so its audio is addressed to coturn's own port, wrapped for the relay and unwrapped from it by the library behind `sipral_media_poll_transmit` and `sipral_media_receive`, and coturn has to count five allocations, all given back. A C flow that fails between `sipral_stack_nat_map` and placing its call unmaps the socket before its stack goes, so a relay it holds is given back too. Then the caller's NAT drops every datagram to or from coturn as well, and the C caller alone is given TURN over TCP (`SIPRAL_TURN_TRANSPORT=tcp`, `turn_transport` on `sipral_stack_config_t`): its media socket's STUN mapping has to go unanswered, which is what proves the block holds; the relay has to be allocated on the connection `SIPRAL_EVENT_KIND_TURN_STREAM` asks the harness to open (`sipral_stack_turn_connected`, `sipral_stack_turn_receive`), the tone has to come back through it, the audio the library hands out has to be marked for it (`protocol` on `sipral_media_packet_t`) and the Refresh of lifetime zero has to be written on it, and coturn has to count six allocations, all given back. After the Python agent's own pair of calls over UDP (eight), the same agent places the call over TLS to coturn's 5349 (`SIPRAL_TURN_TRANSPORT=tls`), trusting the certificate `scripts/lab.sh` made for the run and checking it against the name it was made for (`SIPRAL_TURN_CA`, `SIPRAL_TURN_NAME`); coturn has to count nine, all given back | coturn as TURN and the two NATs, no server |
| G.729, echoed | a call offering G.729 and nothing else (`CodecCatalog::with_codecs(&["G729"])`, so `a=fmtp:18 annexb=yes` in the offer), as the lab's own `labuser-g729` — the one endpoint in `interop/asterisk/pjsip.conf` that allows the codec, and it allows nothing else — to the echo extension (9008); connected on G.729 (a call that settled on anything else fails the flow by name), hung up by this end, ended, and at least half a second of this end's own cadenced tone heard back. The image carries `format_g729` and `res_format_attr_g729` and no G.729 translator, so Asterisk cannot have decoded and re-encoded the frames: what comes back is what this end's encoder wrote, handed back by `Echo()`, decoded by this end's decoder. Asterisk 22.10.1 answers the offer's `annexb=yes` with `annexb=no`, so the call runs with Annex B off — every frame goes out as speech, none as a SID — which is the answer being followed, seen in the flow's capture; were a server to answer yes, the flow's line would add the SID frames sent and taken back. Through the C ABI the stack's order stays `PCMU,PCMA` and the call alone is offered `G729`, through `sipral_call_config_t::codecs`; the codec is read off `SIPRAL_EVENT_KIND_MEDIA_STARTED`, and the same twenty-five audible frames are asked of the echo | Asterisk only |
| inbound, narrowed (opt-in: `SIPRAL_USER_WIDE`/`SIPRAL_PASS_WIDE`) | a wide offer from the server narrowed to G.711 by `MediaEngine::answer`, read back through `MediaSession::codec_candidates` rather than the offer's own list | as configured |
| a call on PipeWire's devices (opt-in: `scripts/lab.sh pipewire`) | a call to the echo extension (9008) whose microphone and earpiece are `sipral-io-pipewire` streams on a real PipeWire graph, paced by the graph rather than by a timer: the lab's cadenced tone is played into one virtual cable, the call's microphone reads the other end of it, the call's earpiece plays into a second cable, and the tone has to come back out of that second cable — at least half a second of it, at its own pitch — which it can only do by crossing the whole path. `interop/harness/src/pipewire.rs` has the reasoning; `interop/pipewire/run.sh` builds the graph, in `interop/pipewire/Dockerfile`'s image, and runs the crate's own tests against it first | Asterisk only |
| an hour on one call (opt-in: `scripts/lab.sh drift`) | six calls to the echo extension (9008) held for sixty minutes, identical but for the earpiece, which plays on a clock 250 ppm slow, true, or 250 ppm fast, and takes one frame at each device callback on three of them and two at once on the other three, as a 40 ms device period on 20 ms packets does (`interop/harness/src/drift.rs`): the lab's two ends read one host's clock and would otherwise drift by nothing, so the skew is made, of a known size, and the two with none are the controls. Every five minutes each call prints its buffer's depth and target, jitter, frames shrunk, stretched, played as silence because the buffer ran dry (and how many of those cut the tone off), concealed, discarded late or for overflow, frames played and audible, the skew all of that comes to — the ratio of the two clocks, over the frames that arrived — the stack's own count of those frames run dry (`Quality::underruns`), its score and whether it calls the call suffering, and its R factor and MOS-LQ. Fails if a call ends early, the stack reports its audio stalled, a report's audible frames fall under half of what the tone's cadence gives, a call's skew at the end is more than a quarter of the run's skew from the one it was given, the controls included, or the frames the earpiece played as silence and the stack's count of under-runs differ by more than the run of silence that can be going on when a report falls. Up to 5000 ppm, twice the widest a device's clock may be off (USB 2.0 §7.1.11), it also fails if a buffer ever holds more than 250 ms or runs dry in the middle of the tone, which is a gap the ear hears however well the count balances. Past it the skew is a stream played at the wrong rate, and the call is judged on what the product does with one (`docs/05-media.md`): it fails on a buffer deeper than its own two-second ring, on one deeper than 250 ms that the stack still scores at half or more, and on a call that ran dry on a twentieth of its frames that the stack never called suffering. `SIPRAL_DRIFT_MS`, `SIPRAL_DRIFT_REPORT_MS` and `SIPRAL_DRIFT_PPM` shorten it for review — three minutes at 2000 ppm, since 250 ppm is two frames in three minutes. That run, 24 September 2026, measured −2000.0, 0.0 and +2000.0 ppm and failed on the fast earpiece, whose buffer ran dry 17 times, 11 of them in the tone; on 25 September, once a pause kept a frame in hand (`docs/05-media.md`), the same run passed, the fast earpiece's 17 frames all stretched into pauses and none run dry (`docs/19-numbers.md`). On 27 September, with the two-frame earpieces and the stack's count added, three minutes at 2000 ppm and at 5000 ppm passed with no frame run dry on any of the six, and two minutes at 500 000 ppm passed as a skew no device runs at: the fast earpieces held 80 ms at most, ran dry 1 714 and 1 742 times, each counted by the stack, and were scored 0 and suffering at every report (`docs/19-numbers.md`). Last full run, 24 September 2026, `0.0.1`, the Linux x86-64 lab machine, before the check on the tone was added: passed, the slow earpiece measured at −245.1 ppm (44 frames shrunk from pauses), the fast one at +250.7 ppm (44 frames of silence where its buffer ran dry, none stretched — the gaps the flow now fails on, `docs/05-media.md`), the control at 0.0, every buffer at 0–20 ms against its 20 ms target at every report, R 93 and MOS-LQ 4.4 throughout (`docs/19-numbers.md`) | Asterisk only |
| the same, over a bad link (opt-in: `scripts/lab.sh drift-netem`) | the same six calls, shaped both ways by an `interop/impairment/*.sh` profile (`lossy` unless `PROFILE` says otherwise) the way `netem` shapes the ordinary calls, with `SIPRAL_AUDIO_GATE=1` throughout so each leg's own report also carries `interop/harness/src/quality.rs`'s segmental SNR and splice clicks, and a leg whose gate clicked fails even if every count above balances. `docs/19-numbers.md` has a run at `SIPRAL_DRIFT_MS=180000` | Asterisk only |
| a marker's round trip, microphone to earpiece (opt-in: `scripts/lab.sh latency`) | one call to the echo extension, a marker frame — full scale, unmistakable for the tone — in place of whatever this end would otherwise have sent, every `SIPRAL_LATENCY_MARK_MS` for `SIPRAL_LATENCY_MS` (`interop/harness/src/latency.rs`); the same call's own playback watches for the echo and halves the round trip into a one-way figure, reading the wait for the next captured frame and the jitter buffer's own target off `sipral` directly and folding everything else — Asterisk's own turnaround, the network, the next playback tick — into what is left. Fails if the call never starts, more than half the markers sent never come back, or the stack reports the stream stalled. `docs/19-numbers.md` has the distribution this measures | Asterisk only |
| a hundred calls at once (opt-in: `scripts/lab.sh volume`) | `SIPRAL_VOLUME_CALLS` calls (a hundred unless told otherwise) placed `SIPRAL_VOLUME_STAGGER_MS` apart, held on the tone for `SIPRAL_VOLUME_HOLD_MS` once every one that came up has started its media, then hung up together (`interop/harness/src/volume.rs`); run twice, straight at Asterisk and through Kamailio to FreeSWITCH — this lab's `kamailio.cfg` has no route to Asterisk. Reports how many the far end answered, each answered call's own setup time to its first frame, how many the far end left in early media without ever answering, and why any that truly failed did — a call the far end only promised early media on in a `183` and then sent no RTP for is the server declining to complete it under the offered rate, seen at the edge of FreeSWITCH's own session-rate throttle, not this end's stream stalling, so it is counted apart and does not fail the run; a stall on a call that was answered still does. `/usr/bin/time -v` around the whole run is this end's own CPU and peak memory, and the real server's own peak channel count is read over its console. `docs/19-numbers.md` has a run of both | Asterisk and (through Kamailio) FreeSWITCH |
| a call on WASAPI's devices (opt-in: `scripts/lab.sh wasapi up`, then `interop/wasapi/run.ps1` on a Windows machine) | a call to the echo extension whose microphone and earpiece are `sipral-io-wasapi` streams on VB-CABLE's two real endpoints, each resampled at the boundary (`sipral-media`'s own resampler) between the call's own rate and whatever rate the endpoint actually delivers at — one cable, not two, so the earpiece and the microphone are a direct physical loop rather than a room's mouth and ear. A tone is written onto the call's own send path for the first second to start that loop, then nothing feeds the call anything but what the microphone actually captures for the rest of it: the loop only keeps carrying the tone — at least half a second of it once the seed has stopped, at its own pitch — if the whole path from the earpiece's endpoint, through the cable, to the microphone's endpoint, is real. The two endpoints are found by matching VB-Audio's cable identity in the endpoint's own name rather than one fixed string, since Windows shows the same cable under more than one naming variant (`interop/harness/src/wasapi.rs`'s `is_vb_cable_endpoint`); a machine where that does not find exactly one endpoint per direction needs `SIPRAL_WASAPI_EARPIECE_ID`/`_MIC_ID` (or `_NAME`) set, and `interop/wasapi/run.ps1 -ListDevices` names what to set them to. `interop/harness/src/wasapi.rs` has the reasoning; `interop/wasapi/compose.override.yaml` is what makes the lab reachable from the Windows machine's LAN, since `interop/compose.yaml` itself publishes no ports, and `scripts/lab.sh wasapi up` reads the lab's own Docker bridge subnet before writing the NAT fields Asterisk needs — a wider guess (`192.168.0.0/16`, say) can overlap the LAN itself and leave the SDP still advertising Asterisk's container-internal address — and moves Asterisk's own SIP socket onto 5062, published one to one, then asks Asterisk which port it is on: a request Asterisk starts, an INVITE to a registered phone, leaves from that socket, and a phone behind a filtering NAT takes it only from the port it registered to | Asterisk only, and only from a Windows machine with VB-CABLE, which the lab's own containers are not |

After the C driver on Asterisk, the lab runs the Python binding's example
agent (`bindings/python/examples/agent.py`) exactly as its docstring says to
run it, against the same shared library, with its own account
(`labuser-agent` in `interop/asterisk/pjsip.conf`). Asterisk originates a call
to it into `[agent-call]` in `interop/asterisk/extensions.conf`: a tone for
three seconds, then `SendDTMF(12#)`. It passes when the agent registered,
answered, received and sent audio (its own `sipral_media_statistics` line), and
heard the `#` it hangs up on. What this proves that the loopback test in
`bindings/python/tests` cannot is that what the agent advertises, its Contact
and its answer's SDP, is somewhere a real server can reach.

The same call then goes to `sipral-headless`'s socket path, with an account of
its own (`labuser-agent-headless`) so neither call can land on the other's
registration. `crates/sipral/examples/headless-socket-agent.rs` registers with
Asterisk, carries the call, and speaks the wire protocol over TCP to
`crates/sipral-headless/examples/agent.rs`, a separate process that echoes what
it hears a frame later and hangs up on `#` — two containers, as an application
and its agent would be. It passes when the application answered, reported the
`#`, and ended the call with packets both received and sent. Like the Python
flow this proves both directions are live against a real server, not what
the audio contains: that the caller's tone comes back through the resampling
and the queues is `crates/sipral/tests/headless_bridge.rs`'s to show, in
process.

The four `baresip only` rows above the fifth are all hung up by this end,
the same shape every other flow in this table but the two transfers takes.
The fifth, `call, ended by the far end`, is the opposite: baresip's own
`call_local_timeout` cannot make it, since `src/call.c`'s own timer for it
is cancelled the instant a call is answered — a ring timeout, not a call
duration limit, whatever its name suggests — so that row's own peer loads
`ctrl_tcp` instead, a module none of the other three's config does, and
`scripts/lab.sh` sends it one command through a container of its own
(`interop/baresip/config-hangup`) so it can never land on whichever of the
other three's own calls happens to be active at the time. Still owed: the
same flow through the C ABI, which has no `FLOW_PEER_HANGUP` of its own.

Every audible flow's result line carries the harness's own tally — sent, come
back, audible, refused, and the session's own `Quality` (loss, jitter, delay
against target, how much the buffer shrank or stretched) — read off what
`MediaSession::capture`, `receive` and `playback` actually did on the wire,
frame by frame, the same as a real application watching its own socket would
read it. The same line also carries the R factor and the two
mean opinion scores `StreamStatistics::voip_metrics` reports — "n/a" for
G.722 and Opus, which G.113 tabulates no `Ie`/`Bpl` for, rather than a
guessed number — so every flow that negotiates PCMU or PCMA reads a MOS.
`SIPRAL_REQUIRE_AUDIO=1` makes the plain call and the SRTP call — and their
own phone-to-phone counterparts against baresip — fail outright if nothing
came back audible, the flows in this table that dwell on the far end's tone;
`scripts/lab.sh` sets it, and every impairment profile's "audio survived it"
rests on it.

A flow passes only if every condition holds; a partial run is a failure with
the failing condition named. The event log and the capture of each passing run
are kept with the run, so the pass is reproducible and later regressions have a
reference; a session worth replaying afterwards is anonymised, reviewed by hand
and committed under `fixtures/replay/`. SIPp is used separately, as a scripted
*peer* for regression scenarios; it is not how the live matrix is judged.

The lessons the harness's own former media join encoded by hand — offer both
G.711 laws, since the first real PBX this stack met allowed A-law only, and
accept a peer that answers with one law and sends the other rather than
refusing its audio as an unnegotiated payload type — are now tests of
`sipral::MediaSession` itself (`crates/sipral/src/tests.rs`), not of the
harness: `a_call_still_connects_against_a_peer_that_keeps_only_a_law` and
`a_peer_that_negotiated_one_g711_law_and_sends_the_other_is_still_heard`.
`interop/harness/src/local.rs` covers what only the harness's own real
sockets can — a call placed and answered, audio measured, and a codec change
carried, all over loopback `UdpSocket`s rather than delivered byte for byte —
since the real lab is not reachable from every machine this runs on.

## Tooling

SIPp for scripted scenarios, Wireshark for traces, `tc netem` for impairment.
All of them are things Sipral is tested with. None of them is linked into it or
shipped with it, and their licences do not reach the product.

## Where the checks run

On our own machines, and nowhere else. There is no hosted CI and no
`.github/workflows/`: a runner that builds, signs or publishes needs
credentials on hardware that is not ours, and for Apple signing there is no way
to give it one at all — a runner has no keychain. So the gate is a script.

`scripts/check.sh` is it: `cargo fmt`, `cargo clippy` with warnings as errors,
the test suite, `rustdoc` with warnings as errors, a release build, the symbols
in the C library that build produces, `bindings/c/smoke.c` compiled against the
header and run, the C that ships or drives the lab — that test, the Swift
package's translation unit, the JNI shim and its thread helper, and the lab's C
driver — compiled again against glibc's own headers for x86_64 and aarch64
Linux with `zig cc` — glibc hides POSIX under a
strict `-std` and the Apple SDK does not, so the compiler here alone passes a
file that fails on the machine it runs on — `clippy` and `rustdoc` over the Windows half of the audio I/O,
`clippy` over the lab harness's own WASAPI flow, which no other step
compiles, and `clippy` over the iOS half of the CoreAudio one, for two targets this
machine cannot execute, `cargo fmt --check`, `clippy` and `cargo fuzz build`
over all thirty fuzz targets under their own nightly — which nothing else
here reaches, since `fuzz/` is a workspace of its own and `--workspace` stops
at its edge — `cargo deny` for dependency licences, `gitleaks` over the
history, and the tree checks — SPDX headers, provenance references,
language, whether an internal file or a capture has reached the tree,
whether a name on the private list kept outside it (in the ignored `intern/`,
so that the list does not publish what it guards) appears in a file or in a
commit message not yet pushed, and
whether the seed corpus still matches the targets it belongs to and holds
only what the rest of the tree is allowed to hold, the dotnet and Kotlin/JVM
bindings built and tested, the Swift package built and tested, and a
`package --dry-run` over `scripts/package/*.sh`. A tool that
is missing fails the step rather than skipping it: a gate that goes green
without the scanner has not looked. The exceptions are the toolchains a
plain Rust clone will not have: the fuzz nightly and `cargo-fuzz`, a JDK (the
JNI shim), the .NET SDK, a Kotlin compiler and a full Xcode for SwiftPM. Each
of those steps says `skip` and names what to install, and a run with any
skip has not checked that binding. It must exit zero before a commit
exists. `--hygiene-only` skips the build for a fast pass.

The linux-arm64 native cross-compiles in an unprivileged Docker container
(`scripts/package/aarch64-cross.sh`), so what the gate proves of it depends
on the machine. On a host with Docker, `package --dry-run` runs
`scripts/package/wheels.sh --linux-arm64 --dry-run` and
`scripts/package/nuget.sh collect --rid linux-arm64` for real. On a host
without it, the step neither skips nor pretends: it lints `sipral-ffi` for
`aarch64-unknown-linux-gnu` with the default package's features, and checks
that every file the cross path names is there and every script on it
parses. The container build, its manylinux_2_28 glibc check and the run
under qemu are then the Linux lab machine's step, run there before a
release or after a change to anything under `scripts/package/`:
`scripts/package/wheels.sh --out DIR --linux-arm64` (the wheel, then
`scripts/package/qemu-verify.sh` running `bindings/c/smoke.c` and
`bindings/python/tests` against it) and `scripts/package/nuget.sh collect
--out DIR --rid linux-arm64` (the native `nuget.sh pack` then places under
`runtimes/linux-arm64/native/`).

The Swift suite also runs on the iOS Simulator, outside the gate: against
the XCFramework's simulator slice, from the distribution package
`scripts/package/xcframework.sh` prints, with `xcodebuild test` on a
simulator device made for the run. `docs/15-mobile.md`, "The Swift package on
iOS", has the commands and what the last runs showed: thirty-one tests on
iOS 26.5, and the two that need a peer outside the process run on their own —
a call from the simulator to `SipralLabAgent` on the Mac, and, through the
lab's Asterisk published by `scripts/lab.sh wasapi up`, a registration and
a call both ways, with REGISTER, INVITE, ACK, BYE and RTP seen at the
simulator and at Asterisk. Those two are opt-in, through `SIPRAL_PEER` and
`SIPRAL_REGISTRAR`, and `swift test` in the gate reports them skipped,
saying why. The Android sample was run the same way, on an emulator
registered with the same Asterisk, placing a call and answering one
(`docs/15-mobile.md`, "Android, run on an emulator"). The CallKit tests
compile and run only on iOS; the simulator refuses a real `CXProvider`, so
the system's own delivery of CallKit actions and VoIP pushes is a device's to
show.

`scripts/lab.sh` runs the container lab: the four servers, the flows against
each, and the same call again over a link made bad with `tc netem`. It needs
Docker and nothing else, so it runs on any machine of ours that has a Linux
kernel under it.

`scripts/lab.sh wasapi up` and `scripts/lab.sh wasapi down` take
`/var/lock/sipral-lab.lock` themselves, so two runs on the same host never
race each other's `docker compose`. A caller that already holds that lock,
to keep the stack in one state across several of these calls, sets
`SIPRAL_LAB_LOCK_HELD=1` first: `flock` is not re-entrant, so wrapping these
two in an outer `flock` on the same file without also setting that variable
deadlocks the caller against its own hold. With the variable set, the two
skip taking the lock again and trust the caller's.

`scripts/fuzz.sh` runs every fuzz target for as long as it is given, five
minutes each by default. Before a release, and overnight.

Two things that a three-runner matrix gave and a single machine does not: the
suite on an operating system this one is not, and the lab where there is no
Docker. Both are answered by running the same two scripts on a second machine
rather than by handing the keys to somebody else's.
