<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# sipral-nat: traversal

## The order that matters

Most of the NAT problem in SIP telephony is solved before ICE is reached:

1. **`rport` on every request** (RFC 3581), and honour `received`. The registrar
   tells us where we actually appear from.
2. **Symmetric RTP with latching** (RFC 7362 describes the technique from the
   media relay's side; an endpoint applies the same rule). Send from the receive
   port, learn the peer's real address from the first valid packet.
3. **Keepalive** frequent enough to hold the binding: double-CRLF or `OPTIONS`
   on signalling, and RTP itself on media once flowing.
4. **STUN** where the local address must be known before media starts.
5. **TURN** as the relay of last resort.

Steps 1 to 3 cover the large majority of carrier and PBX paths, and they are in
phase 1. Steps 4 and 5 are phase 2. Full ICE is not planned; ICE-lite is
implemented so that a peer running full ICE, typically a WebRTC gateway, can
complete a session against us.

That is a deliberate narrowing. Full ICE with aggressive nomination is a large
amount of code that earns its place in a browser, not in a SIP endpoint whose
peer is a carrier.

## STUN

RFC 8489, and RFC 5389 compatibility for servers that have not moved.

Binding requests, `XOR-MAPPED-ADDRESS`, `FINGERPRINT`, long-term credentials with
`MESSAGE-INTEGRITY` and `MESSAGE-INTEGRITY-SHA256`, and the retransmission
schedule from the RFC. Multiplexed on the RTP socket, demultiplexed from RTP by
the first two bits.

No NAT type classification. RFC 5389 removed it when it obsoleted RFC 3489: the
classification algorithm proved faulty because real NATs do not fit the classic
types, and the technique was too brittle across the variety of devices in the
field (RFC 5389 §2 and §19).

## TURN

RFC 8656. Allocate, refresh, permissions, channel binding for the data path
because the 4-byte channel header beats the 36-byte Send indication on every
packet.

TCP and TLS to the TURN server where UDP is blocked, which is the case this
whole component exists for: a corporate network that lets nothing out but 443.

## ICE-lite

RFC 8445 for the lite role's behaviour; the SDP side, `a=ice-lite` and the
candidate lines, comes from RFC 8839, which RFC 8445 explicitly leaves to a
companion document. Advertise `a=ice-lite`, respond to connectivity checks with
the right credentials, accept the peer's nomination. Never gather beyond the
host candidates, never check, never nominate.

## IPv6

Dual stack throughout. Address family follows the SDP `c=` line. Happy Eyeballs
is not implemented for media: the SDP already said which family the session uses.
