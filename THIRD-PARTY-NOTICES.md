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

Since December 2025 that picture is no longer complete, and a licensee should
know it before shipping. **Dolby Laboratories and Fraunhofer IIS are asserting
patents against Opus implementations**, through a licensing vehicle trading as
Vectis at `opuspool.com`, reading on RFC 6716, 8251 and 8486 and on the
reference software. The actions on record are Dolby against Acer, filed at the
Unified Patent Court's local division in The Hague on 10 December 2025 and
pending; Dolby against Arçelik, pending; and settlements with Optoma and with
Epson, the latter in September 2025. The programme is aimed at **manufacturers
of devices** — handsets, tablets, computers, televisions, smart speakers,
consoles and IP telephones — and its published position excludes open source
software distributed independently of hardware.

What that means for the two arms of this project is not the same thing. A
library distributed on its own is outside what the programme says it targets.
**A licensee who puts Sipral into a device is inside it**, and that is their
exposure rather than ours, which is why it is written here rather than left to
be discovered. Nothing in this file, and nothing in either licence, is a
representation that Sipral infringes no patent; see `LICENSE-COMMERCIAL.md`.

Opus is therefore built behind a feature rather than linked unconditionally, so
that a product which cannot take that exposure can ship G.711 and G.722 and
link nothing. The feature is on by default, because for everyone else Opus is
the codec worth having.

### AES

`sipral-rtp` links the `aes` crate, and nothing else of SRTP is borrowed:
SHA-1, HMAC, counter mode, f8, the key derivation, the packet index and the
replay list are written in-tree from RFC 3711, RFC 3174 and RFC 2104, and
proved against those documents' own test vectors.

The block cipher is the exception because a table-driven AES leaks its key
through the CPU cache, and the headless mode is meant to run on machines
shared with strangers. This crate reaches for the AES-NI and ARMv8 crypto
instructions and falls back to a bitsliced implementation, so it is
constant-time on every target Sipral ships to. Writing that by hand would be
slower and worse.

| Component | What it is | Licence |
|---|---|---|
| `aes` 0.9.3 | the block cipher | MIT OR Apache-2.0 |
| `cipher` 0.5.2 | the traits `aes` implements | MIT OR Apache-2.0 |
| `crypto-common` 0.2.2 | shared key and block types | MIT OR Apache-2.0 |
| `hybrid-array` 0.4.15 | const-generic arrays behind those types | MIT OR Apache-2.0 |
| `typenum` 1.20.1 | type-level integers `hybrid-array` uses | MIT OR Apache-2.0 |
| `inout` 0.2.2 | in-place buffer views | MIT OR Apache-2.0 |
| `cpufeatures` 0.3.1 | runtime detection of the AES instructions | MIT OR Apache-2.0 |
| `cpubits` 0.1.1 | the bit twiddling that detection needs | MIT OR Apache-2.0 |
| `libc` 0.2.189 | how `cpufeatures` asks the operating system | MIT OR Apache-2.0 |
| `zeroize` 1.9.0 | wiping keys on drop | Apache-2.0 OR MIT |

All ten are permissive and dual-licensed the same way, so one MIT notice
covers the set. `zeroize` is named directly as well as through `aes`: keys
have to be wiped where they are held, and the write that survives the
optimiser needs `unsafe`, which `sipral-rtp` denies.

#### Build-time only

`cmake` 0.1.58, `cc` 1.4.5, `shlex` 2.0.1 and `find-msvc-tools` 0.1.12 arrive
through `opusic-sys`. All four are MIT OR Apache-2.0, all four run during the
build, and none of them is linked into anything that ships.

## Allowed licences

`deny.toml` holds the machine-readable allow-list, which `scripts/check.sh`
enforces. It permits
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
| webrtc-audio-processing | AEC3, AGC, noise suppression, as an optional crate attached at the processor seam | BSD-3-Clause |
| p256, aes-gcm, sha2, hmac (RustCrypto) | the primitives under the in-tree DTLS 1.2, for DTLS-SRTP | MIT OR Apache-2.0 |
| libpipewire | Linux audio device I/O, through hand-written bindings; the ALSA and PulseAudio client libraries are LGPL and stay out | MIT |
| libvpx, libaom | video codecs, phase 6, after 1.0 | BSD-3-Clause / BSD-2-Clause |
| rustls | the TLS example only; the transport, and its TLS, belong to the application | Apache-2.0 OR ISC OR MIT |

Audio device I/O is written in-tree per platform rather than taken from a
portable library, because the render-to-capture delay and the device-loss
behaviour the design needs are per platform.

G.711 and G.722 are written in-tree. G.711 is a couple hundred lines and is
public domain as an algorithm; G.722 is written from the ITU Recommendation,
because the C implementation everyone links is one the clean-room rules forbid
and the Rust crate that looks free of it is that implementation with the
comments intact. G.729 is phase 2, written in-tree the same way: its base
patents are reported expired since January 2017, which is confirmed in
writing before the codec ships under the commercial licence; the common
implementation, bcg729, is GPL-3 and is never opened.

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
