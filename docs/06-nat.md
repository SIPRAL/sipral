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
phase 1. Step 4 is in the facade and the C ABI, off unless asked for — *STUN,
from a softphone behind a NAT* below. Step 5 waits for a phone to prove it on
(phase 4).

That is a deliberate ordering, not a refusal. Full ICE — gathering, checks,
nomination, role conflicts, restarts, consent — is written on top of the pieces
here, described under *ICE, full role* below, and reached from a call through
`IcePolicy` on the codec catalogue. The place it earns its keep is a phone on
a carrier-grade NAT, or a peer that requires it; on a desktop whose peer is a
carrier it adds setup time and packets for nothing, and it stays off there by
default — which is the default everywhere, since a policy is per call and this
one starts off.

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
| ICE, in any role | **off** | **143 bytes** per candidate, at a floor of one, plus a round of checks before the first audio packet |
| STUN | off | one 28-byte Binding request per socket (the header and FINGERPRINT), again every 25 s on the signalling socket; nothing on a request |
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

**Off has to be a decision, not an accident.** The facade reaches the full
agent now — `IcePolicy` on `CodecCatalog`, `SIPRAL_ICE_*` in the header — and
the default is still the table above. The switch decides what an offer
carries; the feature `ice` decides whether the agent is compiled in at all,
and `Capabilities::ice` says which before a call is placed.

What the switch turns on is a host candidate, and a server-reflexive one
beside it when the call's media socket was mapped by STUN first (below). The
agent itself is configured with no STUN and no TURN server. That cut is what
keeps an offer a single pass of work — with no server to wait for, gathering
finishes before the call that started it returns — so neither the Rust API nor
the C ABI grew a two-phase description to accommodate it. The reflexive
candidate costs one more 143-byte line; it does not cost a second question to
the server, because it is the answer the stack already has for the `c=` line a
peer without ICE reads.

**A peer that does not do ICE is not a peer that loses its call.** Three
conditions each drop the agent and leave the stream on `c=`/`m=` and symmetric
RTP: a description with no ICE attributes at all, candidates none of which can
be paired, and a description whose own default destinations are missing from
its candidate lines — RFC 8839 §4.2.5's ICE mismatch, which is what an ALG
rewriting `c=` and the `m=` port without touching `a=candidate` looks like
from this end. RFC 8445 §2.6 requires the fallback, and without it turning ICE
on against an Asterisk with `ice_support=no` — its default — would turn a call
that works into a call with no audio. `IcePolicy::Required` is the setting for
a deployment that would rather have neither, and it ends the media with
`MediaError::IceRequired` instead of falling back.

Two things follow from having the agent, and both are visible from outside.
Offering ICE asks for `a=rtcp-mux` whatever the catalogue said, because a
stream with a second component needs a second address and the facade knows
one; a peer that takes the attribute back out is `MediaError::IceNeedsRtcpMux`
rather than a stream with an unaddressable half. And the latches follow the
pair the agent selects, symmetric RTP's and the DTLS-SRTP handshake's alike:
the agent has already checked that path with a signed transaction, and a latch
is the poor version of the same question — leaving either armed on the old
address would cut the audio, or the handshake, for good the first time a
mid-call re-selection moved the pair.

The handshake's latch still does its own work on every call that is not using
ICE, which is most of them. A DTLS-SRTP handshake is authenticated by a
fingerprint the signalling carried, and the fatal alert that can end it
arrives before there is any key to authenticate *it* with. The media session
latches on the address the first handshake record came from — only from the
host the signalling named, any port on it, the rule RTCP already keeps — and
refuses every other; a far end that moves its media address in a
re-negotiation opens it again. This end's own flights go to that address
while the stream has no RTP latch, which it cannot have before there are keys,
so a far end whose port the path moved is still answered. It narrows the race
and does not close it: without ICE, a far end behind a NAT that hides its
address is one this end cannot key by handshake at all, and an attacker who
can send from the far end's own address can still win the latch. Closing both
is what the candidate exchange is for (`docs/20-security-model.md`), and now
there is one.

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

### STUN, from a softphone behind a NAT

`rport` and symmetric RTP carry a path when the far end corrects what it was
told. STUN is for the far end that does not: a registrar with no NAT helper
that sends the INVITE to the `Contact` it holds, a peer that sends its audio
to `c=` and nowhere else. For those this end has to write its public address
in the first place, and a Binding request from the socket in question is how
it learns it. Off by default everywhere; on with `SIPRAL_NAT_STUN` and a
`stun_server` in `sipral_stack_config_t`, or with `sipral::Mappings` from Rust.
`Capabilities::stun` and `SIPRAL_FEATURE_STUN` say whether the build has it.

The decisions, and why each one is what it is:

- **Where the transaction lives.** In `sipral::Mappings`, sans-I/O like
  everything else: it hands out datagrams for the application's socket to send
  and takes back what arrives, and it reads no clock. One transaction per
  socket against one server, because each socket is its own NAT binding and a
  NAT that maps them to different public ports — most do — answers
  differently for each. The C ABI keeps one on the stack.
- **Which address goes where.** The signalling socket's answer goes into the
  `Contact` of every account on that transport whose `Contact` names the
  socket's own address (`UserAgent::readdress`), and a media socket's answer
  into the `c=` line and the `m=` port of the call described on it
  (`CallMedia::public_address`). They are never mixed: the SIP socket's
  mapping says nothing about the RTP socket's. The `Via` `sent-by` stays the
  local address. `rport` already brings the response back along the path the
  request took, and a `Via` naming an address this host does not own is a lie
  a strict server can catch.
- **How the signalling socket is sent from.** Its requests leave through the
  transport's own queue (`sipral_stack_poll_transmit`) and its answers come
  back through the transport's own receive call, taken out before the SIP
  parser sees them. An application's loop does not change at all.
- **How a media socket is sent from.** It is the application's, bound for one
  call, and it exists before the call does. So the application names it
  (`sipral_stack_nat_map`), sends what `sipral_stack_poll_stun` hands out from
  it — the record says which socket, since sending from any other learns the
  wrong mapping — and hands back what arrives until
  `SIPRAL_EVENT_KIND_NAT_MAPPING` says the answer is in. That is the one wait
  STUN adds, and it is the application's, before the call: the offer itself is
  still written in one pass. A call described on a socket still being asked
  about is refused with `SIPRAL_STATUS_WRONG_STATE` rather than written with an
  address nobody outside can reach. The answer is spent by the call it
  describes; a socket used again is asked again.
- **How long to wait.** Four requests at RFC 8489's 500 ms RTO and two more
  seconds for the last: five and a half seconds, the same order as ICE's own
  gathering timeout. The RFC's default Rc of seven waits 39.5 seconds, which
  for the first answer is a REGISTER or a call held that long for a server that
  is not there.
- **When the server does not answer.** The socket is described by its own
  address, exactly as it would have been with STUN off — the fallback is the
  configuration that already worked — and the event says so.
- **Refresh.** The signalling socket is asked again every 25 seconds for as
  long as it is bound: the figure the endpoint's own stream keepalive uses,
  short enough for the NATs that release an idle UDP mapping after thirty
  seconds, which RFC 4787 §4.3 forbids and which are deployed all the same.
  The same request is the keepalive: RFC 5626 §4.4.2's STUN keepalive is this
  exchange addressed to the edge proxy, and this one is addressed to the STUN
  server, which keeps the mapping open for a NAT whose mapping is
  endpoint-independent (RFC 4787 REQ-1). It does not open a NAT's filter
  towards the registrar; the registration's own refreshes do that. A media
  socket is asked once. Once a call runs on it, RTP every frame and RTCP every
  few seconds hold its binding, and a STUN request beside them would only
  compete with them for the same mapping.
- **When the mapping changes.** A refresh that answers with a different
  address is `SIPRAL_NAT_MAPPING_MOVED`: every account is moved onto the new
  address and each one holding a binding registers it at once, superseding the
  one in flight. The old binding is not removed first; it expires on its own,
  and a registrar holding the account's `+sip.instance` replaces it at once
  (RFC 5626 §6). A call already up is not re-INVITEd just for this. Its next
  re-INVITE or UPDATE — a hold, a resume, the session timer's own refresh —
  carries the account's `Contact` as it is then, which is the target refresh
  RFC 3261 §12.2 describes, and until then the far end reaches this end along
  the flow the dialog is already on. A media mapping is not watched during a
  call: nothing refreshes it, and a far end that latches follows it, while one
  that does not is the case ICE, or TURN, exists for. Rebinding a transport at
  the same address — what an application does after a network change — asks
  again at once rather than at the next refresh.
- **Multiplexing.** A call described by a public address asks for
  `a=rtcp-mux`, because one mapping describes one port. A far end that
  declines sends RTCP to the public port plus one, which a NAT that keeps ports
  in step maps and another does not; what is lost then is the reports, never
  the audio.
- **With ICE on.** The same public address is the call's server-reflexive
  candidate (RFC 8445 §5.1.1.2), with the host candidate as its base and
  related address, and the default candidate RFC 8839 §4.2.1.2 puts in `c=` —
  so a peer running §4.2.5's mismatch check finds it among the candidates. The
  agent is not asked to query the server a second time. An address equal to
  the host's own — a host with no NAT in front of it — adds nothing, as §5.1.3
  asks.
- **Who is believed.** Only the configured server's address, and only an
  answer carrying the id of a request this end sent. The ids come from the
  media engine's generator, the one SRTP keys come from: an attacker off the
  path who could guess one could answer first and have this end advertise an
  address of the attacker's choosing, in every `Contact` and every offer. An
  unsigned 400 is not an answer: RFC 8489 §9.2.5 has it discarded and the
  request retransmitted, and so it is.

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
from RFC 8839: `IceAgent` in `sipral-nat`, reached from a call through
`IcePolicy` on the catalogue. It has the shape of the STUN and TURN clients:
the application binds the sockets and names them, supplies transaction ids and
the time, hands in every datagram, and takes back what to send from which
socket to where. The facade does all four for it — the socket is the one the
call was placed on, the ids come from a `KeySource` of the call's own, and
every datagram goes through the agent before anything else reads it.

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
  bounded at ten seconds, and **for one session**: a restart goes back to this
  agent's own proposal, because otherwise a peer that once asked for the ten
  seconds RFC 8839 §5.5 allows would slow every check this agent sends for the
  rest of its life, including across the restart a network change causes —
  carrying PRIORITY, USE-CANDIDATE when nominating,
  ICE-CONTROLLING or ICE-CONTROLLED with the tiebreaker, MESSAGE-INTEGRITY
  under the short-term credential, and FINGERPRINT. The RTO is RFC 5245's
  `Ta × (Waiting + In-Progress)`, floored at 500 ms and capped at five seconds,
  rather than RFC 8445 §14.3's formula with the extra factor N, which grows with
  the square of the checklist and reaches minutes at the default pair limit;
  §14.3 allows other mechanisms above the floor.
- **Responses.** Symmetric, or the pair fails. A response of any class is
  believed only when signed with the peer's password: an unsigned one, a 400
  or a 401 included, is discarded as if it never came (RFC 8489 §9.1.4),
  because anybody who saw the check could have written it, and the check
  retransmits until a signed answer or its timeout. A mapped address nobody
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

- **What a datagram comes back as.** `Received::Data` answers with a position
  in the datagram that was handed in, not with a borrow of it. A borrow would
  hold the caller's buffer shared for as long as it held the answer, and what
  a caller does next with a relayed packet is unprotect it in place — so the
  type that said "here it is" would be the type that stopped it. `TurnClient`
  answers the same way underneath, and the position comes from the layers that
  already knew it rather than from arithmetic on addresses.
- **Patience, and what it is not.** A checklist with nothing left to check is
  not a checklist that has failed. RFC 8863 is written for exactly that: the
  peer may still arrive with a check that forms a peer-reflexive pair and
  carries the call (§7.3.1.3), and the commonest reason there is nothing left
  to check is that it has not got here yet. So a checklist Fails
  `IceConfig::patience` after it was formed, not when its last pair does — the
  default being one whole STUN transaction, 39.5 seconds, long enough that a
  peer whose first check was lost has retransmitted every time it is going to.
  A checklist that never had a pair at all goes through the same door: it used
  to stay Running for the life of the call with `deadline()` answering `None`,
  so a caller that slept until the agent next had something to do slept for
  ever, on a call that was never going to carry a packet.

Not done yet: TURN over TCP or TLS (the TURN client has the framing; the
agent's datagram model does not carry it), and `a=remote-candidates` (RFC 8839
§4.4.1.2.2). The second is not written because nothing yet writes an offer it
would go in: it belongs in the updated offer a controlling agent sends after
nomination, when the selected pair differs from the default candidate pair.
With a reflexive candidate that can now happen in address — `c=` names the
reflexive address and the selected pair's local candidate is its base, the
same socket — and on the remote side whenever the peer offered more than one
candidate; a later re-offer from this stack (a hold, a codec change) still
names the reflexive address as default and carries no `a=remote-candidates`.
It comes with the pass that writes the updated offer.

It is proven against itself and against the lite agent over a simulated
network: endpoint-independent mapping with address-dependent filtering, a
symmetric NAT on both sides that leaves only the relay, a symmetric NAT facing
a filtering one that meets on a peer-reflexive candidate, role conflicts from
both starting roles, a restart, consent lost and revoked, and a path losing 30%
of its packets. `fuzz/fuzz_targets/ice.rs` drives the same agent from the other
side — arbitrary datagrams from arbitrary sources on the media port, which is
what this port is open to before any key exists — seeded with checks signed the
way the agent will check them, because an unsigned datagram dies in the
authenticator and reaches none of the state machine. The lab flows against
coturn and Asterisk come with the wiring.

## IPv6

Dual stack throughout. Address family follows the SDP `c=` line. Happy Eyeballs
is not implemented for media: the SDP already said which family the session uses.
