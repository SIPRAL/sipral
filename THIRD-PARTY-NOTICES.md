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
know it before shipping. **Dolby Laboratories, Fraunhofer IIS and NTT are
asserting patents against Opus implementations**, through a licensing vehicle
trading as Vectis at `opuspool.com`, reading on RFC 6716, 8251 and 8486 and on
the reference software. The pool publishes its patent list: as it stood on
1 June 2026 it ran to several hundred entries across more than forty
jurisdictions, Romania among them. The published rate is **0.15 € per unit**.
The actions on record are Dolby against Acer, filed at the Unified Patent
Court's local division in The Hague on 10 December 2025 and pending; Dolby
against Arçelik, pending; and settlements with Optoma and with Epson, the
latter in September 2025.

The programme names **manufacturers of devices** as its targets — handsets,
tablets, computers, televisions, smart speakers, consoles, and **IP telephones
by name**. It also says it does not aim at open source software distributed
independently of hardware.

That last sentence is worth reading carefully, because it is easy to mistake
for something it is not. **It describes who the programme chooses to approach.
It is not a licence, and it grants nobody anything.** A statement of aim can be
revised, and it binds no one; a patent licence is an instrument, and this is
not one. Treat it as useful context and not as cover.

So the two arms of this project are not in the same position, and neither is
safe by virtue of a policy. A library distributed on its own is outside what
the programme says it currently pursues. **A licensee who puts Sipral into an
IP telephone is inside a category it names**, at a rate that turns into real
money on any volume: a hundred thousand handsets is fifteen thousand euro a
year. That is their exposure rather than ours, and it is written here so that
it is a decision they make rather than a thing they discover. Nothing in this
file, and nothing in either licence, is a representation that Sipral infringes
no patent; see `LICENSE-COMMERCIAL.md`.

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
optimiser needs `unsafe`, which `sipral-rtp` denies. `sipral` itself names the
same version directly too, for the SRTP master key and salt `draw_key` hands
out in `crates/sipral/src/engine.rs`, for the same reason: this crate also
denies `unsafe`.

#### Build-time only

`cmake` 0.1.58, `cc` 1.4.5, `shlex` 2.0.1 and `find-msvc-tools` 0.1.12 arrive
through `opusic-sys`. All four are MIT OR Apache-2.0, all four run during the
build, and none of them is linked into anything that ships.

### The primitives under DTLS

`sipral-dtls` is DTLS 1.2 for DTLS-SRTP, and everything in it that is protocol
— the record layer, the handshake framing and messages, the PRF and the
exporter, the certificate writer and reader — is written in-tree from the
RFCs. The primitives are not: P-256 for ECDHE and ECDSA, AES-GCM, SHA-256 and
HMAC come from the same RustCrypto family that supplies `aes`, because a
constant-time elliptic curve is the one place an implementation of our own
would be a risk rather than a virtue. SHA-1, used only to read an old
certificate fingerprint, is written in-tree like the other two copies.

The facade depends on `sipral-dtls` behind the `dtls` feature, which is on by
default, so these five crates are in a binary built from it unless that
feature is turned off. A build with `--no-default-features` has none of them:
`cargo tree` is where that is checked, and `scripts/check.sh` checks it there
on every run.

The crate names four of them — `p256`, `aes-gcm`, `sha2`, `hmac` — and
`zeroize`; the rest arrive through those. Every licence below was read from
the component's own manifest, and every component ships its licence files
beside it.

| Component | What it is | Licence |
|---|---|---|
| `p256` 0.14.0 | the NIST P-256 curve: ECDH and ECDSA | Apache-2.0 OR MIT |
| `ecdsa` 0.17.0 | ECDSA, with the deterministic nonces of RFC 6979 | Apache-2.0 OR MIT |
| `rfc6979` 0.6.0 | those nonces | Apache-2.0 OR MIT |
| `elliptic-curve` 0.14.1 | keys, points and ECDH over any curve | Apache-2.0 OR MIT |
| `primeorder` 0.14.0 | complete point formulas for prime-order curves | Apache-2.0 OR MIT |
| `primefield` 0.14.0 | arithmetic in the curve's prime fields | Apache-2.0 OR MIT |
| `wnaf` 0.14.1 | windowed scalar multiplication | Apache-2.0 OR MIT |
| `ff` 0.14.0 | finite field traits | MIT OR Apache-2.0 |
| `group` 0.14.0 | elliptic curve group traits | MIT OR Apache-2.0 |
| `crypto-bigint` 0.7.5 | constant-time big integers | Apache-2.0 OR MIT |
| `num-traits` 0.2.19 | numeric traits `crypto-bigint` uses | MIT OR Apache-2.0 |
| `sec1` 0.8.1 | SEC1 point encoding | Apache-2.0 OR MIT |
| `der` 0.8.2 | the DER types `sec1` and `ecdsa` use | Apache-2.0 OR MIT |
| `base16ct` 1.0.0 | constant-time hexadecimal `sec1` uses | Apache-2.0 OR MIT |
| `hkdf` 0.13.0 | HKDF, arriving with the curve crates' ECDH; unused here | MIT OR Apache-2.0 |
| `signature` 3.0.0 | the signing and verifying traits | Apache-2.0 OR MIT |
| `aes-gcm` 0.11.1 | AES-GCM record protection | Apache-2.0 OR MIT |
| `aead` 0.6.1 | AEAD traits | MIT OR Apache-2.0 |
| `ctr` 0.10.1 | counter mode | MIT OR Apache-2.0 |
| `ghash` 0.6.0 | GHASH, GCM's authenticator | Apache-2.0 OR MIT |
| `polyval` 0.7.3 | POLYVAL, which `ghash` is built on | Apache-2.0 OR MIT |
| `universal-hash` 0.6.1 | universal hash traits | MIT OR Apache-2.0 |
| `sha2` 0.11.0 | SHA-256 | MIT OR Apache-2.0 |
| `hmac` 0.13.0 | HMAC | MIT OR Apache-2.0 |
| `digest` 0.11.3 | hash function traits | MIT OR Apache-2.0 |
| `block-buffer` 0.12.1 | the block buffering of the hashes | MIT OR Apache-2.0 |
| `const-oid` 0.10.2 | object identifiers the hash traits carry | Apache-2.0 OR MIT |
| `cfg-if` 1.0.4 | compile-time selection inside `sha2` | MIT OR Apache-2.0 |
| `ctutils` 0.4.2 | constant-time comparison and selection | Apache-2.0 OR MIT |
| `cmov` 0.5.4 | constant-time conditional moves `ctutils` uses | Apache-2.0 OR MIT |
| `rand_core` 0.10.1 | randomness traits the curve crates name; no generator is linked | MIT OR Apache-2.0 |
| `subtle` 2.6.1 | constant-time comparison and selection | BSD-3-Clause |

`ff` and `group` write their licence in the deprecated `MIT/Apache-2.0` form,
which is the dual licence and is read as such. `aes`, `cipher`,
`crypto-common`, `hybrid-array`, `typenum`, `inout`, `cpufeatures`, `cpubits`
and `zeroize` are shared with SRTP and listed above.

All but one are dual-licensed like the rest, and one MIT notice covers them.
`subtle` is the exception: BSD-3-Clause, whose second condition requires a
binary to reproduce its notice. Its `LICENSE` reads:

> Copyright (c) 2016-2017 Isis Agora Lovecruft, Henry de Valence. All rights
> reserved.
> Copyright (c) 2016-2024 Isis Agora Lovecruft. All rights reserved.

followed by the three BSD conditions and the disclaimer, which a binary
containing Sipral must carry once this crate is linked into it.

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

**What is implemented of G.722 is the 1988 base and nothing else**, and that
boundary is deliberate rather than incidental. The base is clean on primary
sources rather than on inference: the declarations filed with the ITU in 1986,
and AT&T's express waiver of July 2001 of any essential patent right in it.
It is the one codec here whose patent position can be stated with the documents
in hand. The parts added later are a different question — the
superwideband extension, the two appendices carrying loss concealment, and the
2012 amendment attracted patent declarations as late as 2014, on applications
filed between 2009 and 2011, which on the ordinary term would run into the
2029 to 2031 range. None of that is here: the tree carries the filter pair of
§5, the two sub-bands of §6 at six bits and two, and the three modes of 64, 56
and 48 kbit/s, all of which are in the original Recommendation. The loss
concealment in `sipral-media` is written for linear PCM from G.711 and derives
from no ITU appendix. Anyone extending this codec should know they would be
crossing out of the clean part.

## Test tooling

SIPp, Wireshark, Kamailio, FreeSWITCH and Asterisk are used to test Sipral.
None of them is linked into it, none ships with it, and their licences do not
reach the product.

The fuzz harness under `fuzz/` links `libfuzzer-sys` and, through it,
`arbitrary`, `libc`, `cc`, `jobserver` and `shlex`. That crate is a separate
workspace with its own lockfile and its own nightly pin, it is never published
and never linked into anything shipped, and `scripts/check.sh` runs
`cargo deny` over it too. Its targets also reach into the workspace they test,
so that lockfile carries whatever those crates carry as well — today `aes`,
`zeroize` and the RustCrypto support crates named further up. None of that is
new to the product: every one is already in the shipped graph and already
attributed above, which is why the five named at the start of this
paragraph are the harness's own and not a second copy of that list. All of them are MIT or Apache-2.0, except
`libfuzzer-sys` itself, which is `(MIT OR Apache-2.0) AND NCSA` — NCSA is
LLVM's old permissive licence, and `deny.toml` allows it by name for that one
crate rather than opening the allow-list.

The RFC 4475 torture test corpus under `fixtures/rfc4475/` is IETF Trust
material, reproduced under the IETF Trust Legal Provisions.
