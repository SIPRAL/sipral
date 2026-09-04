<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Testing

The sans-I/O core exists so that this document can be short and the tests can be
boring. Almost everything is deterministic and runs without a network.

## Layers of testing

**Unit, with a fake clock.** Every transaction and dialog state machine is
driven by feeding bytes and advancing time explicitly. Timer A retransmission,
timer B timeout, the `CANCEL` versus `200 OK` race, a fork producing three early
dialogs: all of these are ordinary tests, not integration scenarios.

**Corpus.** RFC 4475 torture messages under `fixtures/rfc4475/`. Valid messages
must parse and round trip; invalid messages must be rejected without a panic and
without unbounded work. This is the first thing that runs in CI.

**Capture replay.** Recorded exchanges from the lab PBX and from carriers,
replayed against the stack byte for byte. Every interoperability bug found in
the field becomes a fixture here on the day it is found, and it never regresses
again.

**Fuzzing.** Continuous, on the parser and on the SDP layer. A crash or a hang
is a release blocker, not an issue.

**Media measurement.** Impairment profiles built with `tc netem` and committed
alongside the tests, so a quality claim is reproducible rather than remembered.
Loss, burst loss, jitter, reordering, and combinations of them.

**Live interoperability.** The matrix below, run by hand before a release.

## Fixtures

`fixtures/rfc4475/` holds the IETF corpus. It is public material and is
committed.

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
| Asterisk | `chan_pjsip`, container, defaults | the configuration most integrators actually have |
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

## Tooling

SIPp for scripted scenarios, Wireshark for traces, `tc netem` for impairment.
All of them are things Sipral is tested with. None of them is linked into it or
shipped with it, and their licences do not reach the product.

## What CI runs

`cargo fmt`, `cargo clippy` with warnings as errors, the test suite and a release
build, on Linux, macOS and Windows. `cargo deny` for dependency licences.
`scripts/check.sh --hygiene-only` for SPDX headers, provenance references,
language, and for internal files or captures having reached the tree. `gitleaks`
over the history.

`scripts/check.sh` with no argument runs everything, locally, and is what runs
before a commit exists.
