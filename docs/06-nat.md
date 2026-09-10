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
phase 1. Steps 4 and 5 are phase 2.

That is a deliberate ordering, not a refusal. Full ICE — gathering, checks,
nomination, role conflicts, restarts, consent — is phase 4, on top of the
pieces already written here, because the place it earns its keep is a phone on
a carrier-grade NAT, or a peer that requires it; on a desktop whose peer is a
carrier it adds setup time and packets for nothing, and it stays off there by
default.

### ICE-lite is for one of the two products, not both

RFC 8445 Appendix A is unambiguous: a lite implementation "is only appropriate
for devices that will *always* be connected to the public Internet and have a
public IP address", and "ICE will not function when a lite implementation is
placed behind a NAT". Advertising `a=ice-lite` from behind a NAT is worse than
advertising no ICE at all — the peer stops doing the work that would have found
a path, and commits to host candidates that are unreachable.

So the switch is not a preference:

| Deployment | ICE |
|---|---|
| Headless agent on a server with a public address | `a=ice-lite`. A full-ICE peer, typically a WebRTC gateway, can then complete a session against it — which is the entire reason the role exists here |
| Softphone behind a NAT | None by default. No `a=ice-lite`, no candidate lines. `rport`, symmetric RTP with latching and keepalive are what carry that path, and steps 1 to 3 above are what make them enough |
| Phone on a carrier-grade NAT, or any endpoint whose peer requires ICE | Full ICE with TURN, phase 4, switched on per stack or per call. Off by default everywhere else |

The endpoint does not guess which it is. A public address is not something a
host can read off an interface — a machine with a private address and a 1:1 NAT
in front of it has one, and a machine with a routable address in a filtered
network does not — so the build says, and the default is off.

## The default profile, and what each option costs on the wire

The deployment this stack is aimed at is a softphone behind consumer NAT
talking to an Asterisk-family PBX. That is not one deployment among several to
be catered for evenly — it is the overwhelming majority, and the defaults are
chosen for it rather than for the general case.

**What is on, and why it is the right default there:**

| Mechanism | Default | On the wire |
|---|---|---|
| `rport` on every `Via` (RFC 3581) | **on** | 6 bytes per request |
| Symmetric RTP with latching | **on**, not configurable | nothing |
| Double-CRLF keepalive on a stream | on where there is a stream | 4 bytes per 25 s |

**What is off, and why:**

| Mechanism | Default | On the wire if turned on |
|---|---|---|
| ICE, in any role | **off** | **143 bytes** per candidate, at a floor of one |
| STUN | off | its own packets; nothing on a request |
| TURN | off | a 4-byte channel header per media packet |

The 143 is measured, not estimated, and pinned by
`what_declaring_ice_costs_on_the_wire` in `crates/sipral-nat/src/ice/sdp.rs` so
that this table cannot quietly stop being true. It is the floor: one address,
one component, one candidate. A laptop with Wi-Fi, Ethernet and a VPN, offering
RTP and RTCP with a reflexive candidate for each, writes nine of those lines,
and an offer that carried them would no longer fit the 1300-byte datagram floor
RFC 3261 §18.1.1 sets. That is not hypothetical: a request that outgrew its path
and was silently dropped by a NAT is the most expensive failure this project has
a record of, and NAT-traversal attributes were four hundred of the bytes that did
it — against a peer that did not speak the protocol at all.

Which is the rule the table exists to state: **a mechanism that only helps
against a peer that supports it is negotiated or detected, never assumed.** ICE
against a PBX that learns the caller's real address from the media it receives
buys nothing and costs the call.

**Off has to be a decision, not an accident.** At this commit `sipral-nat` is
linked by nothing — not by `sipral-ua`, not by the facade, not by the C ABI — so
ICE is absent because no code path reaches it. That is the right behaviour
arrived at the wrong way, and it is worth writing down, because a default that
holds only because nobody wired the alternative is a default that changes the
first time somebody does. When the facade grows an ICE seam, the switch is
explicit and this table is what it defaults to.

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

Only where the table above allows it, and §5.2 narrows it further: "For each IP
address, independent of an IP address family, there MUST be zero or one
candidate", so a host with several public addresses advertises one per family
and no more. That constraint, and the one about NAT, are why this role belongs
to the headless build and not to the softphone.

## IPv6

Dual stack throughout. Address family follows the SDP `c=` line. Happy Eyeballs
is not implemented for media: the SDP already said which family the session uses.
