<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Testing

The sans-I/O core exists so that this document can be short and the tests can be
boring. Almost everything is deterministic and runs without a network.

## Time is given, never read

A guarantee rather than a habit, because everything else here rests on it:
**no library code in `sipral-core`, `sipral-ua`, `sipral-rtp`, `sipral-media`
or `sipral-nat` reads the machine's clock.** Time arrives as a parameter —
`receive(input, now)`, `handle_timeout(now)` — and leaves as `poll_timeout()`.
The one exception in library code is `sipral_ua::Runtime`, the reference loop
over real sockets, which is where a clock belongs and which is behind a feature
so that nothing links it by accident.

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
refusing a field in it, and the corpus does not distinguish: both are the stack
answering 400, and which one happens depends on whether the fault is in the
framing or in a field. Three messages carry a per-message outcome that differs
from their group's — `insuf`, `multi01` and `mcl01` sit in the application
section but their RFC text asks for a 400 outright — with the reason written
beside them in the manifest.

`scripts/check.sh` verifies every file's hash, so the corpus cannot drift, and
`crates/sipral-core/tests/rfc4475.rs` reads the manifest rather than repeating
it. This is the first thing `scripts/check.sh` runs.

**Capture replay.** Recorded exchanges from the lab PBX and from carriers,
replayed against the stack byte for byte. Every interoperability bug found in
the field becomes a fixture here on the day it is found, and it never regresses
again.

**Fuzzing.** `cargo fuzz` (libFuzzer). The fuzz crate lives under `fuzz/`,
outside the workspace, with its own `rust-toolchain.toml` pinned to a nightly
date and its own lockfile, so the rest of the tree keeps its stable pin.

Four targets: `parse`, `framer`, `builder`, `sdp`. `parse` walks every typed
accessor after a successful parse, because a message that parses can still hold
a field nobody can read and reading it is what the stack does next. `framer`
takes the first byte of the input as its read size, so one input covers both
"the whole message at once" and "one byte at a time". `builder` feeds arbitrary
bytes in as header values and asserts the result parses back with exactly the
fields that went in: what it is really testing is that a caller's data cannot
become structure. `sdp` asserts that a description which parses, written back
out, parses again into exactly the same description — a body travels through a
call inside messages that get forwarded, so one that changes meaning by passing
through here is a bug even when nothing crashes — and then answers the offer,
since an answer is derived from the offer and a strange offer is the shortest
way to a strange answer.

```sh
cd fuzz
cp ../fixtures/rfc4475/*/*.dat corpus/parse/     # seeds
cargo fuzz run parse -- -max_total_time=600 -max_len=65535 -rss_limit_mb=2048
```

Seeds are the RFC 4475 corpus plus every anonymised capture; `fuzz/corpus/` is
not committed, since it is generated and grows without bound. Bounds: a memory
limit and a time limit per run, so a hang is a failure rather than something to
wait out.

The phase 1 exit gate is 24 hours on each target with no crash and no timeout.
Until then, `scripts/fuzz.sh` runs each target for as long as it is given,
five minutes each by default — before a release and overnight, not before every
commit, which would add half an hour to buy very little. Every crashing input is minimised and
committed under `fixtures/regressions/` with the fix, and the test suite
replays that directory forever.

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
| FreeSWITCH | lab, as deployed | full call features, transfer, hold |
| Asterisk | `chan_pjsip`, container, defaults | the configuration most integrators actually have; transfer against a second implementation |
| Carrier A | Romanian, paid account | real trunking, real codecs |
| Carrier B | international, paid account | a second opinion on everything carrier A does |
| Commercial SBC | where access exists | the strict end of the spectrum |

Two carriers rather than one, because the first carrier's quirks are
indistinguishable from correct behaviour until a second one disagrees.

Known peer behaviours worth writing down rather than rediscovering:

- FreeSWITCH ships with 100rel disabled. PRACK is implemented for carriers, not
  for the lab.
- Asterisk `res_pjsip` defaults `max_contacts=0`, which refuses every
  registration. Server misconfiguration, always blamed on the client.

## Interoperability procedure

Each live exit criterion in `10-roadmap.md` is one scripted flow, driven by
the reference loop from `sipral-ua` through a small test driver that phase 1
builds alongside the crates. Pass and fail are defined per flow, not judged at
the time:

| Flow | Pass condition | Evidence kept |
|---|---|---|
| register | `Registration::Registered` with the registrar's granted expiry, one refresh observed before expiry, `Unregistered` after `Expires: 0` | event log, capture |
| bidirectional call | 200 to INVITE, ACK seen by the peer, RTP flowing in both directions in the capture, G.711 audio audible both ways, BYE answered with 200 | event log, capture |
| blind transfer | REFER accepted with 202, `NOTIFY` sequence ending in `200 OK` sipfrag, the transferee's new call established | event log, capture |
| attended transfer | as blind, plus `Replaces` honoured: the replaced dialog terminated by the target | event log, capture |

A flow passes only if every condition holds; a partial run is a failure with
the failing condition named. The event log and the anonymised capture of each
passing run are committed as fixtures, so the pass is reproducible and later
regressions have a reference. SIPp is used separately, as a scripted *peer*
for regression scenarios; it is not how the live matrix is judged.

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
header and run, `clippy` and `rustdoc` over the Windows half of the audio I/O
and `clippy` over the iOS half of the CoreAudio one, for two targets this
machine cannot execute, `cargo deny` for dependency licences, `gitleaks`
over the history, and the tree checks — SPDX headers, provenance references,
language, and whether an internal file or a capture has reached the tree. A
tool that is missing fails the step rather than skipping it: a gate that goes
green without the scanner has not looked. It must exit zero before a commit
exists. `--hygiene-only` skips the build for a fast pass.

`scripts/lab.sh` runs the container lab: the three servers, the flows against
each, and the same call again over a link made bad with `tc netem`. It needs
Docker and nothing else, so it runs on any machine of ours that has a Linux
kernel under it.

`scripts/fuzz.sh` runs every fuzz target for as long as it is given, five
minutes each by default. Before a release, and overnight.

Two things that a three-runner matrix gave and a single machine does not: the
suite on an operating system this one is not, and the lab where there is no
Docker. Both are answered by running the same two scripts on a second machine
rather than by handing the keys to somebody else's.
