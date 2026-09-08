<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Third-party notices

Ship this file, or an equivalent notice screen, with any binary that contains
Sipral. Both licence arms require it, because the components below require it
themselves.

The protocol core is written from the RFCs and depends on nothing. Components
are added only as the phases in `docs/10-roadmap.md` reach them, and each
addition lands here in the same commit that adds it to a `Cargo.toml`.

## Components linked into Sipral

### Opus

`sipral-media` links libopus. It is the only codec in that crate that is not
written in-tree, for the reason `docs/05-media.md` gives: a competitive Opus
implementation is years of signal-processing work, and the reference one is
permissively licensed. Three components, one chain, each licence read from the
component's own file:

| Component | What it is | Licence |
|---|---|---|
| `opus` 0.4.0 | safe Rust bindings, the only thing `sipral-media` names | MIT OR Apache-2.0 |
| `opusic-sys` 0.7.5 | the raw declarations, and the build that produces the library | BSD-3-Clause |
| libopus 1.6.1 | the codec itself, vendored inside `opusic-sys` | BSD-3-Clause |

The `opus` crate declares its licence in the deprecated `MIT/Apache-2.0` form,
which is the dual licence and is read as such; its own `LICENSE-MIT` and
`LICENSE-APACHE` files are both present.

libopus's `COPYING` is a **single BSD-3-Clause block**, not one licence per
contributor. Its copyright line reads:

> Copyright 2001-2023 Xiph.Org, Skype Limited, Octasic, Jean-Marc Valin,
> Timothy B. Terriberry, CSIRO, Gregory Maxwell, Mark Borgerding,
> Erik de Castro Lopo, Mozilla, Amazon

So one reproduction of that notice and the three BSD conditions discharges the
obligation for all of them at once. `opusic-sys` ships the same block as its
own `LICENSE`. A binary containing Sipral must reproduce it, which is what the
"or an equivalent notice screen" at the top of this file means.

`opusic-sys` builds the vendored source with CMake; a build host needs `cmake`
on its path. Its `build-bindgen` feature is deliberately left off — the
bindings ship pre-generated, and enabling it would pull `bindgen` and a
libclang dependency into every build for nothing.

#### Patent position

This is the question a commercial licensee's lawyer asks, so it is written
down rather than assumed.

libopus's `COPYING` points at three IPR disclosures on the IETF datatracker:
Xiph.Org (1524), Broadcom (1526) and Microsoft (1914). The Xiph.Org and
Broadcom grants are word for word the same: a perpetual, worldwide,
non-exclusive, no-charge, royalty-free, irrevocable licence to make, have made,
use, offer to sell, sell, import, transfer, run, modify and reproduce any
implementation that complies with the specification. Both terminate
retroactively if the licensee files a patent infringement claim against an
implementation — defensive termination, and the reason the grants are safe to
rely on. Microsoft's grant, which came with its purchase of Skype, is worded
differently and split between the decoder specification and the reference
implementation, but is likewise perpetual, worldwide, no-charge, royalty-free
and irrevocable, and terminates on litigation or on an attempt to license the
same claims on a royalty-bearing basis.

Four companies that did not take part in developing Opus — Qualcomm, Huawei,
France Telecom and Ericsson — filed IPR disclosures with potentially
royalty-bearing terms. The only statement worth recording about those is the
one that is attributable: the licence page at `opus-codec.org/license` states
that external counsel Dergosits & Noah advised the Opus authors that Opus can
be implemented without needing to license the patents disclosed by those four.
That is advice given to them, not to this project, and it is recorded here as
what it is. IETF rules require a disclosure to name actual patent numbers, so a
licensee who needs more than that can have their own counsel read them.

#### Build-time only

`cmake` 0.1.58, `cc` 1.4.5, `shlex` 2.0.1 and `find-msvc-tools` 0.1.12 arrive
through `opusic-sys`. All four are MIT OR Apache-2.0, all four run during the
build, and none of them is linked into anything that ships.

## Allowed licences

`deny.toml` holds the machine-readable allow-list, enforced in CI. It permits
MIT, MIT-0, BSD-2-Clause, BSD-3-Clause, Apache-2.0 (including the
`WITH LLVM-exception` variant), ISC, Zlib, Unicode-3.0, CC0-1.0 and BSL-1.0
(Boost, not Business Source).

Anything under GPL, LGPL, MPL, SSPL, BUSL, CDDL or a non-commercial clause is
refused. A single LGPL dependency would make the commercial arm undeliverable,
which is why the check fails the build rather than warning.

## Components planned, and why each one is safe

These are the components the roadmap intends to link. None of them is present
yet. Each is listed with the licence verified from its own LICENSE file.

| Component | Use | Licence |
|---|---|---|
| libsrtp2 | SRTP | BSD-3-Clause (Cisco) |
| webrtc-audio-processing | AEC3, AGC, noise suppression | BSD-3-Clause |
| sippy/libg722 | G.722 | CMU 1993 portion unrestricted; Sippy Software portion BSD-2-Clause with attribution |
| miniaudio or PortAudio | baseline audio device I/O | MIT-0 / MIT |
| rustls or OpenSSL | TLS transport | Apache-2.0 + MIT + ISC / Apache-2.0 |

G.711 is written in-tree; it is a couple hundred lines and is public domain as
an algorithm. G.729 patents expired in January 2017, but the common
implementation, bcg729, is GPL-3; if G.729 is ever shipped it will be written
in-tree, not linked.

## Test tooling

SIPp, Wireshark, Kamailio, FreeSWITCH and Asterisk are used to test Sipral.
None of them is linked into it, none ships with it, and their licences do not
reach the product.

The fuzz harness under `fuzz/` links `libfuzzer-sys` and, through it,
`arbitrary`, `libc`, `cc`, `jobserver` and `shlex`. That crate is a separate
workspace with its own lockfile and its own nightly pin, it is never published
and never linked into anything shipped, and `scripts/check.sh` runs
`cargo deny` over it too. All of them are MIT or Apache-2.0, except
`libfuzzer-sys` itself, which is `(MIT OR Apache-2.0) AND NCSA` — NCSA is
LLVM's old permissive licence, and `deny.toml` allows it by name for that one
crate rather than opening the allow-list.

The RFC 4475 torture test corpus under `fixtures/rfc4475/` is IETF Trust
material, reproduced under the IETF Trust Legal Provisions.
