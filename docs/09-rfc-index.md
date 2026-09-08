<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Specifications

Everything Sipral implements comes from this list. Nothing in the tree is
derived from another implementation; see [02-clean-room.md](02-clean-room.md).

Status: **done** is implemented and covered by tests. **phase N** is scheduled,
per [10-roadmap.md](10-roadmap.md). Nothing is marked done at this commit.

## Signalling

| RFC | Title | Crate | Status |
|---|---|---|---|
| 3261 | SIP: Session Initiation Protocol | sipral-core | phase 1 |
| 3263 | Locating SIP servers: transport selection, the `maddr` target, the default port, and what counts as a failed hop | sipral-core | phase 1 |
| 3263 | Locating SIP servers: the NAPTR, SRV and A queries themselves | caller; the reference loop does the A query only | phase 1 |
| 2782 | SRV records: ordering candidates by priority and weight | caller; `std::net` cannot ask for SRV | phase 1 |
| 3264 | Offer/answer model with SDP | sipral-core | phase 1 |
| 4566 | SDP | sipral-core | phase 1 |
| 3581 | Symmetric response routing (`rport`) | sipral-core | phase 1 |
| 3262 | Reliability of provisional responses (PRACK) | sipral-core | phase 1 |
| 3311 | The UPDATE method | sipral-ua | phase 1 |
| 4028 | Session timers | sipral-ua | phase 1 |
| 8760 | Digest with SHA-256 and SHA-512/256 | sipral-core | phase 1 |
| 3515 | The REFER method | sipral-ua | phase 1 |
| 3891 | The Replaces header | sipral-ua | phase 1 |
| 3892 | The Referred-By mechanism | sipral-ua | phase 1 |
| 6665 | Event notification framework | sipral-ua | phase 2 |
| 3842 | Message waiting indication | sipral-ua | phase 2 |
| 4235 | Dialog event package (what busy lamp field is built on) | sipral-ua | phase 2 |
| 3856 | Presence event package | sipral-ua | phase 2 |
| 6026 | Correct transaction handling for 2xx | sipral-core | phase 1 |
| 5626 | Outbound: managing client connections | sipral-ua | phase 2 |
| 3327 | The Path header, which Outbound registrations travel on | sipral-ua | phase 2 |
| 5627 | Globally routable UA URIs (GRUU) | sipral-ua | phase 2 |
| 8599 | Push notification bindings: `pn-provider`, `pn-prid`, `pn-param`, and the 555 refusal | sipral-ua | phase 4 |
| 7118 | SIP over WebSocket | sipral-core | phase 2 |
| 3323 / 3325 | Privacy, and asserted identity | sipral-ua | phase 2 |
| 4475 | SIP torture test messages | test corpus | phase 1 |

## Media

| RFC | Title | Crate | Status |
|---|---|---|---|
| 3550 | RTP and RTCP | sipral-rtp | phase 1 (send/receive), phase 2 (adaptive buffer) |
| 3551 | RTP profile for audio and video | sipral-rtp | phase 1 |
| 4733 | RTP payload for DTMF | sipral-rtp | phase 2 |
| 3711 | SRTP | sipral-rtp | phase 2 |
| 4568 | SDES key exchange in SDP | sipral-core | phase 2 |
| 5764 | DTLS-SRTP | sipral-rtp | phase 2 |
| 5761 | Multiplexing RTP and RTCP | sipral-rtp | phase 2 |
| 6716 | Opus | sipral-media | phase 2 |
| 7587 | RTP payload format for Opus | sipral-media | phase 2 |
| 3389 | Comfort noise payload | sipral-media | phase 2 |
| ITU-T G.711 | A-law and µ-law | sipral-media | phase 1 |
| ITU-T G.722 | 7 kHz at 64 kbit/s | sipral-media | phase 2 |

## NAT

| RFC | Title | Crate | Status |
|---|---|---|---|
| 8489 | STUN | sipral-nat | phase 2 |
| 5389 | STUN, previous version, for compatibility | sipral-nat | phase 2 |
| 8656 | TURN | sipral-nat | phase 2 |
| 8445 | ICE, lite role only | sipral-nat | phase 2 |
| 5245 | ICE, previous version, for compatibility | sipral-nat | phase 2 |
| 8839 | SDP offer/answer procedures for ICE (`a=ice-lite`, `a=candidate`) | sipral-core | phase 2 |
| 7362 | Latching: hosted NAT traversal for media | sipral-rtp | phase 1 |

## Deliberately not implemented

| Area | Why |
|---|---|
| Full ICE (aggressive nomination, trickle) | ICE-lite completes sessions against full-ICE peers. The rest earns its place in a browser, not a SIP endpoint |
| Video and its payload formats | Would make the audio path shallow |
| SIP server roles: proxy, registrar, B2BUA | Sipral is an endpoint |
| SIMPLE instant messaging, MSRP | Out of scope |
| SIP-T, SIP-I, ISUP encapsulation | Carrier interconnect, not endpoints |
| IMS: 3GPP registration, `P-Access-Network-Info` | Different product |
| iLBC (RFC 3951) | Opus covers the same ground — speech over a lossy link — and covers it better. Nothing in the field asks for iLBC and refuses Opus |
| AMR and AMR-WB (RFC 4867) | Mobile radio codecs, and patented. On the IP leg an operator offers G.711 or Opus; carrying AMR through would mean licensing it to reach a peer that already speaks something else |

Anything moving out of this table needs a written reason in a design document
before code exists.
