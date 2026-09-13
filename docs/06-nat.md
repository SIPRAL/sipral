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
nomination, role conflicts, restarts, consent — is written, on top of the pieces
here, and described under *ICE, full role* below; nothing reaches it from a
call yet, and that wiring is phase 4. The place it earns its keep is a phone on
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

## ICE, full role

RFC 8445 in the full role, RFC 7675 for consent freshness, and the SDP side
from RFC 8839: `IceAgent` in `sipral-nat`. Written and tested, and **not yet
reached from a call** — the facade, `MediaConfig` and the C ABI do not know it
exists, so the defaults in the tables above hold because nothing else is
possible yet. It has the shape of the STUN and TURN clients: the application
binds the sockets and names them, supplies transaction ids and the time, hands
in every datagram, and takes back what to send from which socket to where.

What it does, in the order a session meets it:

- **Gathering.** Host candidates from the sockets the application names, in
  its order of preference; addresses RFC 8445 §5.1.1.1 rules out (loopback,
  site-local, the deprecated IPv6 forms) are left out. Each host candidate is
  paired with every configured STUN server of its family for a server-reflexive
  candidate, and every TURN server for a relayed one plus the server-reflexive
  address the Allocate reports. The transactions are paced by Ta. Gathering
  ends when all of them have answered or after `gathering_timeout`, five
  seconds by default: a dead STUN server would otherwise hold the offer for the
  39.5 seconds of a whole STUN transaction.
- **No trickle, deliberately.** Candidates are gathered to completion before
  the description is written. Trickle ICE for SIP (RFC 8840) needs INFO packages
  the PBXs this stack is aimed at do not carry; the cost is the bounded wait
  above.
- **Checklists.** One per data stream. Pairs of the same component and family,
  link-local only with link-local, prioritised by §6.1.2.3, reflexive local
  candidates replaced by their base and pruned, and held to `max_pairs` (100)
  across the set, taken off the longest checklists first and only from pairs
  no check has touched yet, so that a later exchange of candidates cannot
  discard a pair the valid list or a nomination depends on. The frozen algorithm
  starts one pair per foundation, lowest component first.
- **Checks.** Paced by Ta — the larger of the two agents' `a=ice-pacing`, a
  peer that writes none (every lite peer) counting as the default 50 ms,
  bounded at ten seconds — carrying PRIORITY, USE-CANDIDATE when nominating,
  ICE-CONTROLLING or ICE-CONTROLLED with the tiebreaker, MESSAGE-INTEGRITY
  under the short-term credential, and FINGERPRINT. The RTO is RFC 5245's
  `Ta × (Waiting + In-Progress)`, floored at 500 ms and capped at five seconds,
  rather than RFC 8445 §14.3's formula with the extra factor N, which grows with
  the square of the checklist and reaches minutes at the default pair limit;
  §14.3 allows other mechanisms above the floor.
- **Responses.** Symmetric, or the pair fails. A success, a 487 and a 403 are
  believed only when signed with the peer's password. A mapped address nobody
  knew is a peer-reflexive local candidate; a check from a source nobody knew
  is a peer-reflexive remote candidate and triggers a check back on the same
  pair. A check that arrives before the answer is answered at once, and its
  triggered check waits for the peer's credentials. A nomination the
  controlled side will not follow — its source over the remote-candidate
  bound, its pair over the pair limit, no place left among the checks waiting
  for the answer, a checklist that has Failed, a peer fragment the stream does
  not hold, or a component the stream no longer has — is refused with a signed
  400 rather than answered and dropped (§7.3.1.5).
- **Roles.** Both halves of the conflict rules: the larger tiebreaker
  controls, a 487 switches the role and draws a new tiebreaker, and every pair
  priority is recomputed.
- **Nomination.** Regular only. A controlling agent nominates a component's
  best valid pair once no pair of higher priority can still succeed, or
  `nomination_wait` (one second) after its first valid pair, whichever comes
  first. A later, higher nomination from a peer written to RFC 5245 is
  followed, as §8.1.1 asks. A stream whose checklist Failed sends nothing on
  any component and selects nothing more (§12.1); the application removes it
  or restarts.
- **Restarts.** New credentials, flushed state, the same role and candidates.
  The pair selected before keeps carrying data, and stays under consent with
  the old credentials, until the new session selects.
- **Consent and keepalives.** A consent check every four to six seconds on each
  selected pair, never retransmitted; thirty seconds without an authenticated
  answer, or an authenticated 403, ends consent and sending, and only a restart
  brings it back. A Binding indication goes out after Tr (15 s) without
  traffic, which consent at its default interval never lets happen.
  Server-reflexive mappings are refreshed every Tr until ICE concludes, and
  relayed candidates nobody selected are given back three seconds after it
  does.
- **RTP and RTCP multiplexed.** A stream normally has one component. The agent
  works over component ids, but pairs only the components both ends offered,
  which with `a=rtcp-mux` on both is component 1 alone (RFC 5761 §5.1.3).
  `ice_mismatch` reads `a=rtcp` (RFC 3605) for the RTCP default destination
  when RTCP is not multiplexed.
- **Bounds on the peer.** Remote candidates per stream (32), pairs (100), checks
  remembered from before the answer (32), cancelled transactions, and the
  pacing a peer may ask for. No input panics the agent.

Not done yet: TURN over TCP or TLS (the TURN client has the framing; the
agent's datagram model does not carry it), `a=remote-candidates` (RFC 8839
§4.4.1.2.2, which the offer written after nomination will need), and the wait
RFC 8863 bounds for a checklist that never had a pair — such a checklist simply
stays Running.

It is proven against itself and against the lite agent over a simulated
network: endpoint-independent mapping with address-dependent filtering, a
symmetric NAT on both sides that leaves only the relay, a symmetric NAT facing
a filtering one that meets on a peer-reflexive candidate, role conflicts from
both starting roles, a restart, consent lost and revoked, and a path losing 30%
of its packets. The lab flows against coturn and Asterisk come with the wiring.

## IPv6

Dual stack throughout. Address family follows the SDP `c=` line. Happy Eyeballs
is not implemented for media: the SDP already said which family the session uses.
