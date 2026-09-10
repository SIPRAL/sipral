<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Specifications

Everything Sipral implements comes from this list. Nothing in the tree is
derived from another implementation; see [02-clean-room.md](02-clean-room.md).

Status names the phase from [10-roadmap.md](10-roadmap.md) that delivers the
row. Whether a phase's rows are met is recorded there, not repeated here. A row
marked *written, not linked* is implemented and tested in its crate and reached
by no call yet.

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
| 6665 | Event notification framework: the subscriber, with the dialog the NOTIFY opens, refresh, expiry, Timer N, forking and re-subscription. The notifier role is `refer` alone (RFC 3515), and `Allow-Events` is read but not yet advertised | sipral-ua | phase 1 |
| 3842 | Message waiting indication: the subscription is the framework's, and the `application/simple-message-summary` body reaches the application whole; parsed to a count in phase 2 | sipral-ua | phase 2 |
| 3428 | The MESSAGE method, pager-mode instant messaging in both directions | sipral-ua | phase 2 |
| 3608 | Service-Route, learned from the 200 OK to REGISTER and placed on the requests that follow | sipral-ua | phase 2 |
| 4235 | Dialog event package, and the `application/dialog-info+xml` reader a busy lamp field is built on | sipral-ua | phase 1 |
| 3856 | Presence event package: the subscription is the framework's, and the PIDF body reaches the application whole | sipral-ua | phase 2 |
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
| 4733 | RTP payload for DTMF, both directions. The packet and the timestamp rules are `sipral-rtp`'s; the schedule is the facade's, because a packet per captured frame needs a frame boundary and the layer that writes the packet never sees one | sipral-rtp, sipral | phase 2 |
| 3711 | SRTP | sipral-rtp | phase 2 |
| 4568 | SDES key exchange in SDP | sipral-core | phase 2 |
| 5764 | DTLS-SRTP: the `use_srtp` extension and the keys it exports | sipral-dtls, sipral-rtp | phase 2 |
| 6347 | DTLS 1.2, both roles, written in-tree over permissively licensed primitives; no renegotiation, no resumption | sipral-dtls | phase 2 |
| 4145 | `a=setup`, which end starts the handshake | sipral-core | phase 2 |
| 5705 | Keying material exporter, for the SRTP keys | sipral-dtls | phase 2 |
| 8122 | `a=fingerprint`, the only thing a peer's certificate is checked against | sipral-core, sipral-dtls | phase 2 |
| 7983 | Telling DTLS, STUN and RTP apart on one socket | sipral-nat | phase 2 |
| 5761 | Multiplexing RTP and RTCP | sipral-rtp | phase 2 |
| 6716 | Opus | sipral-media | phase 2 |
| 7587 | RTP payload format for Opus | sipral-media | phase 2 |
| 3389 | Comfort noise payload | sipral-media | phase 2 |
| ITU-T G.711 | A-law and µ-law | sipral-media | phase 1 |
| ITU-T G.722 | 7 kHz at 64 kbit/s | sipral-media | phase 2 |
| ITU-T G.729 | 8 kbit/s CS-ACELP, base with Annex A and Annex B, written from the Recommendation. The base patents are reported expired since 2017 and that is confirmed before it ships; G.729.1 and the later annexes stay out | sipral-media | phase 2 |
| 3611 | RTCP-XR, the VoIP metrics block, with the R factor and MOS from ITU-T G.107 | sipral-rtp, sipral-media | phase 2 |
| 6035 | Quality reports published as `vq-rtcpxr` when an account names a collector | sipral-ua | phase 2 |

## NAT

| RFC | Title | Crate | Status |
|---|---|---|---|
| 8489 | STUN | sipral-nat | phase 2; written, not linked |
| 5389 | STUN, previous version, for compatibility | sipral-nat | phase 2; written, not linked |
| 8656 | TURN | sipral-nat | phase 2; written, not linked |
| 8445 | ICE, lite role | sipral-nat | phase 2; written, not linked |
| 8445 | ICE, full role: gathering, checks, nomination, role conflicts, restarts. Off by default on a desktop | sipral-nat | phase 4 |
| 7675 | STUN consent freshness, for a session ICE established | sipral-nat | phase 4 |
| 5245 | ICE, previous version, for compatibility | sipral-nat | phase 2; written, not linked |
| 8839 | SDP offer/answer procedures for ICE (`a=ice-lite`, `a=candidate`) | sipral-core | phase 2 |
| 7362 | Latching: hosted NAT traversal for media | sipral-rtp | phase 1 |

## Deliberately not implemented

| Area | Why |
|---|---|
| Trickle ICE (RFC 8838, RFC 8840) | Rare between SIP endpoints, which exchange candidates in the offer and the answer. Excluded until a peer needs it |
| Video and its payload formats | Not before 1.0, so the audio path stays deep; phase 6 after it, per [10-roadmap.md](10-roadmap.md) |
| SIP server roles: proxy, registrar, B2BUA | Sipral is an endpoint |
| MSRP (RFC 4975), session-mode messaging | Out of scope. Pager-mode messaging, the MESSAGE method, is phase 2 |
| SIP-T, SIP-I, ISUP encapsulation | Carrier interconnect, not endpoints |
| IMS: 3GPP registration, `P-Access-Network-Info` | Different product |
| iLBC (RFC 3951) | Opus covers the same ground — speech over a lossy link — and covers it better. Nothing in the field asks for iLBC and refuses Opus |
| AMR and AMR-WB (RFC 4867) | Mobile radio codecs, and patented. On the IP leg an operator offers G.711 or Opus; carrying AMR through would mean licensing it to reach a peer that already speaks something else |

Anything moving out of this table needs a written reason in a design document
before code exists.
