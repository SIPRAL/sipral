<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Third-party notices

Ship this file, or an equivalent notice screen, with any binary that contains
Sipral. Both licence arms require it, because the components below require it
themselves.

**Sipral has no third-party dependencies at this commit.** The list is empty on
purpose: the protocol core is written from the RFCs. Components are added only
as the phases in `docs/10-roadmap.md` reach them, and each addition lands here in
the same commit that adds it to a `Cargo.toml`.

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
| Opus | wideband codec | BSD-3-Clause, with patent grants from Xiph, Broadcom and Microsoft |
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

The RFC 4475 torture test corpus under `fixtures/rfc4475/` is IETF Trust
material, reproduced under the IETF Trust Legal Provisions.
