<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Sytek
-->

# Impairment profiles

The shapes of bad network the lab runs a call over. `scripts/lab.sh netem`
takes one by name, or runs all of them.

They are files rather than arguments for one reason: a measurement is only
comparable to another measurement of the same thing, and a threshold committed
against a profile that lives in somebody's shell history is a threshold nobody
can reproduce. These are the fixtures those numbers are measured against.

| Profile | What it is |
|---|---|
| `lossy` | bursty loss, jitter and reordering together — the general case |
| `mobile` | two per cent loss arriving in bursts, on a link whose delay moves |
| `satellite` | a geostationary carrier: half a second of round trip, and steady |
| `blackout` | the link disappears for eight seconds in the middle of the call |

`blackout` is the one worth having. Every report that says the call froze is
this shape, and it is the one an easy simulator does not produce: loss and
delay applied uniformly for the length of a call are a bad line, not an
interruption, and a jitter buffer that copes with the first can still fail the
second by never recovering its target after the gap.

## Both directions

`tc netem` only ever shapes egress, and for a long time that was read as
enough: the far end was assumed to echo, and a packet delayed or dropped on
the way out would come back late or not at all. It does not echo —
`interop/harness/src/quality.rs`'s own module doc says why one was tried and
abandoned — so it plays its own fixed tone regardless of what arrives from
here, and shaping only this container's egress never touched a single frame
of the audio actually measured: `lossy`, `mobile` and `satellite` all passed
every run on a link that was bad in name only. `scripts/lab.sh`'s own
`bad_network` now redirects this container's ingress through an `ifb` device
(`ip link add ifb0 type ifb`, a `tc filter ... action mirred egress redirect`)
and applies the same `NETEM` there as `root netem`, so a profile is bad both
ways, the way a real link is. `$link` is still the egress interface `DURING`
and `REQUIRE` read; `$ifb` is the ingress redirect, and both are checked and
both are worth reading back from — see below.

## What a profile file is

A shell fragment, sourced by the runner. Four names, of which two are optional:

- `WHY` — one line, what this shape is and where it comes from.
- `NETEM` — the arguments to `tc qdisc ... root netem`, or empty. Applied to
  `$link` (egress) and `$ifb` (ingress) alike.
- `REQUIRE` — a word that must appear in `tc qdisc show` on **both** `$link`
  and `$ifb` once the profile is applied. **This is not decoration.** `tc`
  accepts settings the kernel then discards in silence — on a 3.10 kernel
  `delay` goes and `loss` stays — so a run whose impairment never happened
  reads exactly like a clean one and passes. The runner reads both qdiscs
  back and refuses to report a pass when what was asked for is missing from
  either.
- `DWELL_MS` — how long the call stays up, when the default two seconds is not
  long enough to contain what the profile does.
- `DURING` — a shell fragment run in the background while the call is up, for a
  profile that changes the link mid-call rather than setting it once. `$link`
  and `$ifb` are both there to change. It must do its own read-back and echo
  `IMPAIRMENT-NOT-APPLIED` if what it asked for did not happen — and "did not
  happen" includes a change that was applied but landed on nothing. A qdisc
  that reads `loss 100%` for eight seconds before the call starts sending is
  exactly as useless as one that never read it. `blackout.sh` is the worked
  example: it waits until audio is visibly leaving through the egress qdisc,
  cuts both `$link` and `$ifb`, and afterwards reads `$ifb`'s own drop
  counter — the ingress side, what this end actually received — to show the
  outage took the call's packets rather than only its own attempts to send.
  Whatever it echoes before the marker is printed with the note.

## The audio quality gate

`scripts/lab.sh netem` also turns on `SIPRAL_AUDIO_GATE`, the harness's own
segmental-SNR and splice-continuity check against the lab's fixed tone
(`interop/harness/src/quality.rs`), and fails a profile whose call connects
and ends but whose audio does not hold up. `docs/11-testing.md` has the
method and the measured numbers each profile was calibrated against.

## Reading the numbers

`gemodel p r 1-h 1-k` is the four-state Gilbert-Elliott model, and it is what
makes loss bursty rather than uniform: `p` is the chance of falling into the
bad state, `r` of climbing out, and the last two are the loss rates inside each
state. Uniform loss at the same average is a different network and a much
kinder one — it never takes a whole talk spurt.
