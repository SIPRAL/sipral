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

Seventeen targets, one per door an attacker's bytes come through.

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

One more, added for 8.3.11's incoming DTMF over signalling. `dtmf_info` takes
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

Its seeds are the reason it reaches anything. A connectivity check is
authenticated before it is acted on, so an unsigned datagram dies at the door
and a coverage-guided fuzzer will not forge an HMAC to get past it: the seeds
carry checks signed with the same password the harness publishes, one of them
nominating, plus a response and a role conflict answering the first
transaction id the harness hands out. Those six seeds alone reach more of the
agent than several hundred thousand random runs did before they existed.

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
targets with something to start from rather than eighteen runs beginning at
the empty input. `tools/fuzz-seeds` writes them out of the library's own
builders and encoders and puts each one through the reader its target puts
it through — the framer seeds through the framer, the protected runs through
an unprotector holding the target's own key, the DTLS runs through ends built
as the target builds them — so a seed that is not what it claims to be fails
the generator rather than sitting in the corpus doing nothing. Seventeen of the
eighteen families go through that check; the one that does not is `builder`,
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

The phase 1 exit gate is 24 hours on each target with no crash and no timeout.
Until then, `scripts/fuzz.sh` runs each target for as long as it is given,
five minutes each by default — before a release and overnight, not before
every commit, which would add an hour to buy very little. What the gate does
do on every run is **build** all eighteen, under the nightly that `fuzz/` pins, so
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
`interop/harness` (`sipral-interop`) against the container lab. Since 8.5.1
the harness drives every flow through the `sipral` facade — `MediaEngine` and
`MediaSession` for RTP, codecs, DTMF and SRTP — the same seam a real
application links, rather than through a second RTP/codec pipeline written
for the lab alone: **a phase whose proof runs on a path no customer uses has
not exited** (`10-roadmap.md`). `crate::audio` in the harness is what a real
application still has to write for itself either way — a socket and a
tone — not a second media join. Pass and fail are defined per flow, not
judged at the time; a flow that did four things out of five is a failure
naming the fifth, printed as `FAIL <flow> — <what did not hold>`.

Since 8.5.2 the same flows run **a second time, through the C ABI**, driven by
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
every run without running it — what it needs is three servers — so an ABI
change that would stop an integrator's program building fails at the moment it
is made. **This is the phase-1 exit criterion and the precondition for
freezing the ABI** (`10-roadmap.md`, `08-ffi.md`).

It runs the same twelve call-and-transfer flows the Rust driver runs, against
the same servers. The codec change was the one the C surface could not
express until `sipral_call_change_codecs` existed — and the Rust driver could
not either, through the facade: it wrote that re-offer itself until
`MediaEngine::change_codecs` did. MESSAGE and message waiting indication
(8.6.5) run in C too, driven by `sipral_account_message` and
`sipral_account_subscribe`; only the opt-in narrowed-inbound flow at the
bottom of the table stays the Rust driver's alone, since it needs a second
account registered at once and `interop/harness-c` drives one endpoint at a
time.

Run through Kamailio to FreeSWITCH and straight at Asterisk (`scripts/lab.sh
kamailio` / `asterisk`), unless a column below says one server only:

| Flow | Pass condition | Servers |
|---|---|---|
| register | bound, one binding round trip observed, then given back | both |
| call | connected, hung up by this end, ended | both |
| hold and resume | as call, plus the hold and the resume both agreed | both |
| blind transfer | connected, the transfer completed (its own status read from the `NOTIFY` sipfrag), the far end ended it | both |
| attended transfer | as blind, plus the consultation leg itself connected first | both |
| DTMF, RFC 4733 | connected, a digit sent as a named telephone event named back the same way by the lab's own dialplan (`interop/asterisk/extensions.conf`'s 9003), hung up, ended. Not run through the proxy to FreeSWITCH yet: its 9003 in `interop/freeswitch/lab.xml` never named the digit back, dialled at once or after a pause, and a flow is not run where it is known not to pass until the reason is found | Asterisk only |
| DTMF, SIP INFO | connected, the same digit sent by `UserAgent::send_dtmf_info` (8.3.11) instead, answered with success (`UaEvent::DtmfSent`) and named back the same way by extension 9003 — against the lab's own `labuser-infodtmf` endpoint (`interop/asterisk/pjsip.conf`, `dtmf_mode=info`), so `SendDTMF()`'s own echo goes back over INFO too and this end's receiving half is exercised against a real peer as well as its sending one — hung up, ended | Asterisk only |
| SRTP | connected under SDES against the lab's own SDES endpoint (`interop/asterisk/pjsip.conf`'s `labuser-srtp`, extension 9004) — refused rather than answered plainly if the far end will not key it | Asterisk only |
| DTLS-SRTP, held and resumed | connected against the lab's own DTLS endpoint — on Asterisk `interop/asterisk/pjsip.conf`'s `labuser-dtls`, on FreeSWITCH extension 9005 of `interop/freeswitch/lab.xml`, which makes secure media mandatory for that call alone and certifies with the RSA-4096 key FreeSWITCH generates for itself, so the flow is also the proof that a peer's RSA certificate keys a call in either role — keyed by its own handshake — `SIPRAL_EVENT_KIND_MEDIA_SECURED` for that call, not `MEDIA_STARTED`: a DTLS call is still waiting for its keys there — then held and resumed, both agreed, hung up by this end, ended. A handshake that fails is named from `MEDIA_FAILED`'s own reason and ends the flow at once. Audio is required only *after* the resume, not merely after the call connects: the hold and the resume are both re-offers that hand the DTLS roles back with `a=setup:actpass` (RFC 8842 §5.5), so audio heard once they are agreed says the far end answered with the roles already in force (§5.3) and the association that keyed the call still carries it | both |
| hold with a codec change | as hold, but between the hold and the resume the call is moved onto a narrower codec list while it stays held (`MediaEngine::change_codecs`, the 8.2.1 case): the far end's answer names a different codec than the one the call held on, the hold survives the change, and the resume keeps the new codec | Asterisk only |
| MESSAGE, echoed | an out-of-dialog MESSAGE (`UserAgent::message`) sent to the lab's own echo extension (`interop/asterisk/extensions.conf`'s 9006, `MessageSend()`), answered with success (`UaEvent::MessageSent`), and a MESSAGE of the dialplan's own arriving back (`UaEvent::MessageReceived`) — proving both directions, not only that this end's own send was accepted | Asterisk only |
| message waiting indication | a subscription to `message-summary` for this account's own mailbox (`labuser-mwi`, whose AOR in `interop/asterisk/pjsip.conf` has `mailboxes=9007@default` — on the AOR, since that is what a SUBSCRIBE is matched against; on the endpoint it means unsolicited NOTIFYs and every SUBSCRIBE is answered 404), read once before anything is left in it; a call into the lab's own mailbox extension (9007), whose hangup handler announces one new message with `MinivmMWI()` — not `VoiceMail()`, which cannot record in this image because it ships no sound files and the greeting fails; and the mailbox's `new` count (`UaEvent::MessagesWaiting`) read higher once Asterisk's own `res_pjsip_mwi` reports it — not that it starts at zero, since an earlier run may have left mail behind | Asterisk only |
| inbound, narrowed (opt-in: `SIPRAL_USER_WIDE`/`SIPRAL_PASS_WIDE`) | a wide offer from the server narrowed to G.711 by `MediaEngine::answer`, read back through `MediaSession::codec_candidates` rather than the offer's own list | as configured |

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

Every audible flow's result line carries the harness's own tally — sent, come
back, audible, refused, and the session's own `Quality` (loss, jitter, delay
against target, how much the buffer shrank or stretched) — read off what
`MediaSession::capture`, `receive` and `playback` actually did on the wire,
frame by frame, the same as a real application watching its own socket would
read it. Since 8.6.9 the same line also carries the R factor and the two
mean opinion scores `StreamStatistics::voip_metrics` reports — "n/a" for
G.722 and Opus, which G.113 tabulates no `Ie`/`Bpl` for, rather than a
guessed number — so every flow that negotiates PCMU or PCMA reads a MOS.
`SIPRAL_REQUIRE_AUDIO=1` makes the plain call and the SRTP call —
the two that dwell on the far end's tone — fail outright if nothing came back
audible; `scripts/lab.sh` sets it, and every impairment profile's "audio
survived it" rests on it.

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
file that fails on the machine it runs on — `clippy` and `rustdoc` over the Windows half of the audio I/O
and `clippy` over the iOS half of the CoreAudio one, for two targets this
machine cannot execute, `cargo fmt --check`, `clippy` and `cargo fuzz build`
over all eighteen fuzz targets under their own nightly — which nothing else
here reaches, since `fuzz/` is a workspace of its own and `--workspace` stops
at its edge — `cargo deny` for dependency licences, `gitleaks` over the
history, and the tree checks — SPDX headers, provenance references,
language, whether an internal file or a capture has reached the tree, and
whether the seed corpus still matches the targets it belongs to and holds
only what the rest of the tree is allowed to hold. A tool that
is missing fails the step rather than skipping it: a gate that goes green
without the scanner has not looked. The one exception is `cargo fuzz`, which
needs a nightly toolchain and a cargo subcommand a clone will not have: that
step says `skip` and names what is missing, because the alternative is a gate
nobody outside this machine can run at all. It must exit zero before a commit
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
