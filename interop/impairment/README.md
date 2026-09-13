<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
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

## What a profile file is

A shell fragment, sourced by the runner. Four names, of which two are optional:

- `WHY` — one line, what this shape is and where it comes from.
- `NETEM` — the arguments to `tc qdisc ... root netem`, or empty.
- `REQUIRE` — a word that must appear in `tc qdisc show` once the profile is
  applied. **This is not decoration.** `tc` accepts settings the kernel then
  discards in silence — on a 3.10 kernel `delay` goes and `loss` stays — so a
  run whose impairment never happened reads exactly like a clean one and
  passes. The runner reads the qdisc back and refuses to report a pass when
  what was asked for is not there.
- `DWELL_MS` — how long the call stays up, when the default two seconds is not
  long enough to contain what the profile does.
- `DURING` — a shell fragment run in the background while the call is up, for a
  profile that changes the link mid-call rather than setting it once. `$link`
  is the interface. It must do its own read-back and echo
  `IMPAIRMENT-NOT-APPLIED` if what it asked for did not happen — and "did not
  happen" includes a change that was applied but landed on nothing. A qdisc
  that reads `loss 100%` for eight seconds before the call starts sending is
  exactly as useless as one that never read it. `blackout.sh` is the worked
  example: it waits until audio is visibly leaving through the qdisc, and
  afterwards reads netem's own drop counter to show the outage took the call's
  packets. Whatever it echoes before the marker is printed with the note.

## Reading the numbers

`gemodel p r 1-h 1-k` is the four-state Gilbert-Elliott model, and it is what
makes loss bursty rather than uniform: `p` is the chance of falling into the
bad state, `r` of climbing out, and the last two are the loss rates inside each
state. Uniform loss at the same average is a different network and a much
kinder one — it never takes a whole talk spurt.
