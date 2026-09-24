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
| 3892 | The `Referred-By` header, copied onto the INVITE a REFER triggers (§2.2). The signed token that would authenticate it is not implemented, so the header proves nothing | sipral-ua | phase 1 |
| 6665 | Event notification framework: the subscriber, with the dialog the NOTIFY opens, refresh, expiry, Timer N, forking and re-subscription. The notifier role is `refer` alone (RFC 3515), and `Allow-Events` is read but not yet advertised | sipral-ua | phase 2 |
| 3842 | Message waiting indication: the subscription is the framework's, and the `application/simple-message-summary` body is parsed into per-class counts, `UaEvent::MessagesWaiting` reporting the `voice-message` one | sipral-ua | phase 2, built |
| 3428 | The MESSAGE method, pager-mode instant messaging in both directions, in and out of a dialog, with the §8 size policy and 200/202/415/413 | sipral-ua | phase 2, built |
| 3608 | Service-Route, learned from the 200 OK to REGISTER and preloaded on the INVITEs and SUBSCRIBEs the account starts towards its registrar; not on the REGISTER itself | sipral-ua | phase 2, built |
| 4235 | Dialog event package, and the `application/dialog-info+xml` reader a busy lamp field is built on | sipral-ua | phase 2 |
| 3856 | Presence event package: the subscription is the framework's, and the PIDF body reaches the application whole | sipral-ua | phase 2 |
| 6026 | Correct transaction handling for 2xx | sipral-core | phase 1 |
| 5057 | Multiple dialog usages in one call: read for the one point this stack needs — a 503 that answers a single non-INVITE transaction ends only that transaction, not the dialog — to decide that the per-dialog ceiling on those refuses the transaction and nothing else | sipral-core | phase 1 |
| 5626 | Outbound: managing client connections | sipral-ua | phase 2 |
| 3327 | The Path header, which Outbound registrations travel on | sipral-ua | phase 2 |
| 5627 | Globally routable UA URIs (GRUU): asked for on REGISTER, learned from this instance's `Contact`, and used as the `Contact` of what opens a dialog, public or temporary as §3.3 says. Self-made GRUUs and the RFC 5628 event extension are not | sipral-ua | phase 2, built |
| 7315 | P-Associated-URI, reported from the 200 OK to REGISTER and not acted on (obsoletes RFC 3455) | sipral-ua | phase 2, built |
| 8599 | Push notification bindings: `pn-provider`, `pn-prid`, `pn-param`, and the 555 refusal | sipral-ua | phase 4 |
| 7118 | SIP over WebSocket | sipral-core | phase 1, in part |
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
| 5764 | DTLS-SRTP: the `use_srtp` extension and the keys it exports. Negotiated by the handshake in `sipral-dtls` — required in both hellos, the profile chosen by the server from the client's list, no MKI agreed — and the key layout of §4.2 for `SRTP_AES128_CM_HMAC_SHA1_80` and `_32` exported once both Finished messages are verified; keying `sipral-rtp` with them is not written | sipral-dtls, sipral-rtp | phase 2; done, and keying `sipral-rtp` with the export is `sipral`'s `dtls` feature |
| 5763 | The DTLS-SRTP framework: a certificate from both ends, each checked against the fingerprint the other's signalling carried, and `a=setup` deciding which end sends the ClientHello. The handshake half is in `sipral-dtls` | sipral-dtls | phase 2; done, both halves — the facade writes the fingerprint and the role and starts the handshake |
| 8827 | WebRTC security, §6.5 only: the suite and curve every peer supports, no NULL SRTP profile, no MKI, renegotiation refused with `no_renegotiation` | sipral-dtls | phase 2; done |
| 6347 | DTLS 1.2, both roles, written in-tree over permissively licensed primitives; no renegotiation, no resumption. The record layer with its epoch, 48-bit sequence number and anti-replay window; handshake fragmentation and bounded reassembly; the client and server state machines with the server's stateless HelloVerifyRequest cookie; flight retransmission on the timer of §4.2.4.1; alerts and closure | sipral-dtls | phase 2; done, driven from `MediaSession` |
| 5246 | TLS 1.2, where DTLS 1.2 defers to it: the PRF with SHA-256, the master secret, `verify_data`, the key block, AEAD record protection, the hello and key exchange messages and their checks, the alert protocol | sipral-dtls | phase 2; done |
| 7627 | The extended master secret, required in both hellos: a peer without it is refused, and the exporter refuses a master secret made without it, since §5.4 requires such a session to disable RFC 5705 | sipral-dtls | phase 2; done |
| 5288 | AES-GCM cipher suites: the nonce and the additional data of each protected record | sipral-dtls | phase 2; done |
| 5289 | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, the suite a server negotiates, and `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, which a client also offers for a server certified with RSA | sipral-dtls | phase 2; done |
| 8422 | ECC cipher suites: named curves and point formats, the ServerKeyExchange and ClientKeyExchange of ECDHE, ECDSA signatures in DER, public key validation | sipral-dtls | phase 2; done |
| 5746 | `renegotiation_info`, empty on the initial handshake, which is the only one performed: sent empty by a client, echoed by a server, refused when it is not empty | sipral-dtls | phase 2; done |
| 4145 | `a=setup`, which end starts the handshake. The role it gives — the active end is the DTLS client, `actpass` decided by the answer — is `setup::dtls_role` in `sipral-dtls`; the attribute itself is read and written by `sipral-core` | sipral-core, sipral-dtls | phase 2; done — the facade remembers what it wrote, since the role reads the offer's value and the answer's together |
| 5705 | Keying material exporter, for the SRTP keys | sipral-dtls | phase 2; done |
| 8122 | `a=fingerprint`, the only thing a peer's certificate is checked against. `sha-256` fingerprints are written and `sha-1` ones read, and compared in constant time, in `sipral-dtls` | sipral-core, sipral-dtls | phase 2; done, and every `a=fingerprint` of a description is carried rather than the first |
| 5280 | X.509 v3: a self-signed certificate written, a peer's read as far as its public key | sipral-dtls | phase 2; done |
| 5480 / 5758 / 3279 | An ECDSA P-256 key and signature in a certificate: `id-ecPublicKey` with the named curve, `ecdsa-with-SHA256`, `Ecdsa-Sig-Value` | sipral-dtls | phase 2; done |
| 3279 §2.3.1 / 8017 | An RSA key in a peer's certificate, `rsaEncryption` with NULL parameters, and RSASSA-PKCS1-v1_5 over SHA-256, verified only — this end never signs with RSA — under a modulus of 2048 to 8192 bits (RFC 9325 §4.5) | sipral-dtls | phase 2; done — proven in the lab against FreeSWITCH's own RSA-4096 certificate |
| 7983 | Telling DTLS, STUN and RTP apart on one socket | sipral-nat | phase 2; done — `Demux::Dtls` on the first octet, read by `MediaSession::receive` |
| 5761 | Multiplexing RTP and RTCP | sipral-rtp | phase 2 |
| 6716 | Opus | sipral-media | phase 2 |
| 7587 | RTP payload format for Opus | sipral-media | phase 2 |
| 3389 | Comfort noise payload | sipral-media | phase 2 |
| ITU-T G.711 | A-law and µ-law | sipral-media | phase 1 |
| ITU-T G.722 | 7 kHz at 64 kbit/s | sipral-media | phase 2 |
| ITU-T G.729 | 8 kbit/s CS-ACELP, written from the Recommendation and G.Imp729: Annex A's encoder and decoder, and Annex B over them — the voice activity detector, DTX with SID frames, and comfort noise — bit-exact against every ITU Annex A and Annex B conformance stream and input; RTP payload type 18 with any number of 10 ms frames a packet and at most one SID frame after them (RFC 3551 §4.5.6), offered only when an order names it. Annex B is used where the catalogue allows it and both descriptions say so; a SID frame received is always played as Annex B's comfort noise. The base patents are reported expired since 2017 and that is confirmed before it ships; G.729.1 and the later annexes stay out | sipral-media, sipral | phase 2; built, interoperable — the lab's `g729` flow, through Asterisk's echo extension untranscoded |
| 4856 | Media type registrations for the RTP audio payloads, among them `audio/G729` and its `annexb` parameter (§2.1.9, carried over from RFC 3555 §4.1.9): absent means yes | sipral | phase 2; done for G.729 — an offer states `annexb=yes` (or `no`, per `CodecCatalog::with_g729_annex_b`), an answer follows the offer, and the encoder uses Annex B only where both said yes; a re-offer the user agent answers by itself echoes the offer's value |
| 3611 | RTCP-XR: the XR packet and the VoIP Metrics report block (§4.7), including the Appendix A.2 burst/gap classification, negotiated with `a=rtcp-xr` (§5) on both offer and answer. The R factor and the two MOS fields come from a simplified ITU-T G.107 E-model, with the codec's own G.113 Appendix I `Ie`/`Bpl` mapped in `sipral`; a codec G.113 does not tabulate reports its own §4.7.5 "unavailable" sentinel rather than a guess | sipral-rtp, sipral-core, sipral | phase 2; done |
| 6035 | Quality reports published as `vq-rtcpxr` over a PUBLISH (RFC 3903) when an account names a collector, once per call on call end. Only the `LocalMetrics` set is written; `RemoteMetrics` needs a channel to the far end's own measurement that does not exist | sipral-ua, sipral | phase 2; done |

## NAT

| RFC | Title | Crate | Status |
|---|---|---|---|
| 8489 | STUN | sipral-nat, sipral, sipral-ua | phase 2; done — the Binding client reached through `sipral::Mappings` and `SIPRAL_NAT_STUN`, its answer in the `Contact` and in `c=`/`m=` |
| 5389 | STUN, previous version, for compatibility | sipral-nat | phase 2; the same client, which reads a server that has not moved |
| 8656 | TURN | sipral-nat | phase 2; written, not linked |
| 8445 | ICE, lite role | sipral-nat | phase 2; written, not linked |
| 8445 | ICE, full role: gathering, checks, nomination, role conflicts, restarts. Off by default on a desktop | sipral-nat, sipral | phase 4; a host candidate, and a server-reflexive one from the stack's own STUN mapping of the socket; the agent asks no STUN or TURN server itself |
| 7675 | STUN consent freshness, for a session ICE established | sipral-nat, sipral | phase 4 |
| 5245 | ICE, previous version, for compatibility | sipral-nat | phase 2; written, not linked |
| 8863 | ICE patiently awaiting connectivity: a checklist with nothing left to check is waited on, not failed | sipral-nat, sipral | phase 4 |
| 8839 | SDP offer/answer procedures for ICE (`a=ice-lite`, `a=candidate`, `a=ice-pacing`, `a=ice-mismatch`); `a=remote-candidates` waits for an offer that would carry one | sipral-nat, sipral, sipral-ua | phase 2; the facade writes the attributes and the user agent carries them onto an answer it writes itself |
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
