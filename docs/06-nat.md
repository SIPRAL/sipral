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
| TURN | off | a 4-byte channel header per media packet on a relayed pair, 36 bytes of Send indication until the channel is bound; one more candidate line; an Allocate (two round trips) before the offer |

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

What the switch turns on is a host candidate, a server-reflexive one beside it
when the call's media socket was mapped by STUN first (below), and a relayed
one when the socket was given a relay on a TURN server first ([TURN](#turn)).
The agent itself is configured with no STUN and no TURN server. That cut is
what keeps an offer a single pass of work — with no server to wait for,
gathering finishes before the call that started it returns — so neither the
Rust API nor the C ABI grew a two-phase description to accommodate it. The
reflexive candidate costs one more 143-byte line; it does not cost a second
question to the server, because it is the answer the stack already has for the
`c=` line a peer without ICE reads. The relayed one is asked for before the
call in the same way, from the same socket.

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
  wrong mapping — and hands back what arrives, the first answer being
  `SIPRAL_EVENT_KIND_NAT_MAPPING`. That is the one wait
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
  socket is asked on the same schedule while it waits for its call — an
  application that maps the next call's socket when the last call ends may
  place that call many minutes later, and nothing else crosses the binding in
  between, so the answer a call is described with is never older than one
  refresh. At most one request per socket waits in `sipral_stack_poll_stun`'s
  queue. Once a call runs on it, RTP every frame and RTCP every few seconds
  hold its binding, a STUN request beside them would only compete with them
  for the same mapping, and the socket is asked nothing more.
- **When the mapping changes.** A refresh that answers with a different
  address is `SIPRAL_NAT_MAPPING_MOVED`. For the signalling socket every
  account is moved onto the new address and each one holding a binding, or on
  its way to one, registers it at once, superseding the one in flight — and
  that REGISTER also carries the `Contact` it replaces with `expires=0`, so
  the registrar drops the old binding instead of forking calls to it until it
  expires (RFC 3261 §10.2.2). That includes the private address a REGISTER
  sent before the first answer arrived. The old `Contact` goes as its URI
  alone, without `+sip.instance`: RFC 3261 §10.3 matches a removal to a
  binding by URI, but Kamailio matches by instance, and given the new
  `Contact` and the old one with `expires=0` under the same tag it keeps
  neither. For a media socket still waiting, the call is
  described by the new address. A call already up is not re-INVITEd just for this. Its next
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
  address of the attacker's choosing, in every `Contact` and every offer. A
  400 is the server's refusal and ends the request at once (RFC 8489 §6.3.4):
  the rule that discards an unsigned one belongs to the long-term credential
  mechanism (§9.2.5), which a mapping asked without credentials does not run,
  and it would protect nothing there, since nothing an unauthenticated
  exchange receives can be told from what anyone on the path writes.

## TURN

RFC 8656. Allocate, refresh, permissions, channel binding for the data path
because the 4-byte channel header beats the 36-byte Send indication on every
packet.

TCP and TLS to the TURN server where UDP is blocked, which is the case this
whole component exists for: a corporate network that lets nothing out but 443.

`TurnClient` is not told the server's address, so whoever holds it hands in
only what came from there: ChannelData and Data indications carry no proof of
who wrote them beyond the relay's 5-tuple. The full ICE agent does. Long-term
credentials follow RFC 8489 §9.2: the first request goes out bare, a 401 is
answered once per transaction, a 438 once per new nonce and at most three
times, and a server that rotates its nonce without saying stale costs one
retry per request rather than a loop. The derived key is overwritten as it is
dropped, with the password's own best effort — no volatile write without
`unsafe`, and a move leaves the bytes it moved from — and neither it nor the
password reaches a `Debug`.

### Joined to a call

The facade reaches it the way it reaches STUN: the application asks before the
call, from the socket the call will use, and hands the answer to the call.
`sipral::Relays` allocates a relay on one TURN server for each media socket it
is given — `MediaEngine::relays` draws its transaction ids from the engine's
own generator, since a guessed id is a forged Allocate response naming a relay
of the attacker's choosing — the application's socket sends what it hands back
and hands in what arrives, and `CallMedia::relay` gives the finished
allocation to the call. The C ABI does the same with `turn_server`,
`turn_username` and `turn_password` beside `stun_server`: every socket
`sipral_stack_nat_map` names gets a relay too, through the same two calls
that carry its Binding request, and `SIPRAL_EVENT_KIND_NAT_RELAY` says what
the server gave (`docs/08-ffi.md`). One coturn is usually both servers, from
one address; a Binding answer goes to the mapping and every other answer to
the relay.

Before the call, and not by the agent while it gathers, for the reason the
reflexive candidate above is: an Allocate under long-term credentials is two
round trips, the first answered 401, and an agent that ran them would hold the
offer until they came back — the two-phase description the STUN step avoided,
and still avoids. An application that allocates when it binds the socket, while
the user is still dialling, has the relay when the offer is written.

Under a full `IcePolicy` the relay is the call's relayed candidate
(`IceAgent::add_relayed`), with the server-reflexive address the Allocate
response named beside it; that address also goes into `c=` and `m=` when the
call was not given a STUN answer, since it is the same answer from the same
socket. The relayed address is never the default candidate, although RFC 8445
§5.1.4 recommends it: a peer that does no ICE drops the agent — the fallback
above — and with it every permission the relay would need before anything the
peer sent reached this end, so `c=` naming the relay would hand that peer an
address that delivers nothing. ICE ranks a relayed candidate last (type
preference 0), and uses it only when nothing cheaper answers.

From the description on the allocation is the agent's, exactly as one it had
gathered: a permission for every address among the peer's candidates as soon
as they arrive, a channel bound for the pair it uses (Send indications until
the binding is confirmed), the allocation, the permissions and the channel
refreshed before they lapse, and a Binding indication towards the server every
Tr so that the NAT binding under all of it survives. It is given back — a
Refresh with a lifetime of zero (RFC 8656 §8) — three seconds after ICE
concludes on a pair that does not use it (RFC 8445 §8.3.1), when the call
ends, and at once when the call cannot use it: a peer that answered without
ICE, a catalogue that offers none, the lite role. A relay left to lapse holds a
port and the account's quota on the server for up to ten minutes, and a user
whose quota is a handful of allocations cannot place the next call until then.
What the giving back sends leaves among the call's farewells
(`MediaEngine::poll_farewell`, `sipral_stack_poll_farewell`), from the call's
own socket.

The credential is a `LongTermCredentials` from the moment it is read: its
password is overwritten when it is dropped, with the same best effort as the
derived key, and no `Debug`, event or error text carries it. The C ABI reads it
out of the caller's configuration once, straight into that.

Between the call being described and its session opening — a caller waiting
for the 200, a callee ringing — the agent that holds the relay waits in the
engine rather than being rebuilt from the description, as every other call's
agent is: an allocation is state on a server, and nothing written down can
make it again. `MediaEngine::handle_timeout` and `MediaEngine::poll_transmit`
drive it while it waits, so a Rust application that polls them keeps the NAT
binding towards the server alive through a long ring. The C ABI drives its
timer too but has no queue that sends from a call's socket before the call's
media handle exists, so there its Binding indications wait with it and leave
when the session opens. The allocation itself lasts ten minutes and outlives
any ring; a NAT that drops an idle binding after thirty seconds, in front of a
C ABI phone rung for longer than that, is the case not covered yet.

Not done yet: TURN over TCP or TLS to the server, for the network that lets
nothing out but 443. The client has the framing; the agent's datagram model
does not carry a stream. And a forked INVITE: one allocation serves one agent,
which stays with the branch the call was placed on, so a second branch a proxy
forks off runs an agent rebuilt from the description, without the relay its
offer named, and finds only the paths that need none.

### Proven in the lab

`scripts/lab.sh turn`, and the `ice` word after the step above, puts the two
stacks of that step behind the same two NATs and tells each NAT to drop every
datagram to or from the other's outside address that is not SIP: host
candidates have no route and server-reflexive ones are dropped, so only a path
through a third party can connect. coturn becomes a TURN server with long-term
credentials for that step alone (`interop/turn/compose.override.yaml`, a user
and a password drawn for the run, so none is written down). The same call
without TURN has to find no path, and finds none; that is what proves the
block holds. With a relay allocated on each end, the call completes with the
tone crossing both ways, the caller failing any path that does not go through
coturn, and coturn's own log has to show both allocations given back with a
Refresh of lifetime zero by the time the call has ended, rather than left to
lapse. The path ICE chose and what the relay cost the call's start are under
[What ICE costs a call's start, measured](#what-ice-costs-a-calls-start-measured).

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

It is reached from a call as `IcePolicy::Lite`, and that value exists only in
a build with both `ice` and `headless`: the softphone's build, and the C ABI
built on it, cannot name it, so the rule in the table is kept by the compiler
rather than by a default somebody could change. Nothing turns it on but the
application asking, per call or on the engine's catalogue;
`headless-socket-agent --ice-lite` is the reference. What it does, in the
order a call meets it:

- **The description.** `a=ice-lite` at session level (RFC 8839 §4.2.1.4) and
  no `a=ice-pacing` (§4.3.1 forbids a lite end one); a username fragment and
  a password drawn per call from the media engine's key source, as the full
  role draws them; and one host candidate. The candidate is the address the
  media socket is bound to, or `CallMedia::public_address` for a server behind
  a one-to-one NAT — which is most clouds — where the public address is
  forwarded to the host unchanged and is, to every peer, the host's own. It
  is a host candidate even then, with no related address: a lite end has no
  other kind to write (§5.2). The same §5.1.1.1 refusals as the full role
  apply to it, so a loopback or link-local address is refused by name rather
  than advertised. One component, as in the full role: a peer that offers
  ICE without `a=rtcp-mux` leaves RTCP a component with no candidate, and the
  call's media fails with `MediaError::IceNeedsRtcpMux` rather than running
  half checked — which is why the lab's Asterisk endpoint sets `rtcp_mux`.
- **Answering a peer without ICE.** An offer that carries no ICE is answered
  with none — "the answerer MUST NOT include any ICE-related SDP attributes in
  the answer" (§4.3.2), which now holds for every policy — and the call runs
  on `c=`/`m=` and symmetric RTP, as the full role's fallback does. A peer
  that is lite too is the same fallback: neither end checks, and RFC 8445
  §6.1.1 leaves both on the default candidates.
- **Checks.** Every STUN request on the media socket is authenticated with
  the call's short-term credential — USERNAME names this end's fragment first,
  MESSAGE-INTEGRITY (or its SHA-256 form) is verified under this end's
  password, and a request whose FINGERPRINT does not check out is dropped
  unanswered, while one that carries none is judged by its integrity alone —
  and answered with XOR-MAPPED-ADDRESS, signed the way the request was, with
  FINGERPRINT. One that fails authentication is refused unsigned
  (RFC 8489 §9.1.3). The role rules are §7.3.1.1's: a lite end facing a full
  one starts controlled (§6.1.1), and a peer that claims the same role is
  settled by the tiebreaker. The answers wait for `poll_transmit` under the
  full role's ceiling and drop policy (below, "The outbox").
- **The path.** The pair a check carrying USE-CANDIDATE arrives on is the
  media path (§7.3.2), and it is reported as `MediaEvent::PathChosen` —
  event 33, the one the full role uses — with the advertised address as its
  local half. Nothing is sent before there is one (§12.1): a frame captured
  earlier is not sent anywhere. A later nomination moves the path, and the
  session's latches with it, as a full agent's re-selection does.
- **Consent.** RFC 7675 needs nothing of a lite end but answers: "No changes
  are required to ICE-lite implementations in order to respond to consent
  checks, as they are processed as normal ICE connectivity checks" (§1).
  They are answered like any other check. A lite end has no consent of its
  own to lose, so it has no timer: it asks the application to wake it for
  nothing, and spends no transaction id.
- **Restart.** A re-offer whose `ice-ufrag` and `ice-pwd` both changed is an
  ICE restart (§4.4.1.1.1). The user agent hands it up rather than answering
  it from a copy of the last description, and the answer carries new
  credentials of this end's own, as §4.4.2.1 requires of an answerer that
  accepts one; the candidate stays what it was (§4.4.1.3). The pair already
  selected keeps carrying the audio, and checks under the old credentials on
  it — the peer's consent checks — go on being answered, until the peer
  nominates under the new ones (RFC 8445 §9).

Proven three ways. `sipral-nat`'s own tests drive the lite agent through
authentication, role conflicts, nomination and a restart. In process, a
facade under `IcePolicy::Required` calls one under `IcePolicy::Lite`
(`crates/sipral/src/tests.rs`): the full end opens a stream only because the
answer said `a=ice-lite` and carried a candidate, both ends report the pair
the full end nominated, audio crosses it both ways, and a restart moves it.
And in the lab (`scripts/lab.sh ice`): the interop harness, as the full agent
a WebRTC gateway would be, places a call that requires ICE straight at
`headless-socket-agent --ice-lite` and the reference agent's echo comes back
on the chosen pair; then Asterisk's own ICE (`ice_support=yes` on an endpoint
of its own, in `interop/ice/`, mounted only for that step) calls the same
agent registered to it, and Asterisk's RTP debug has to show its audio going
out through its completed ICE session ("via ICE"). The application's own log
cannot show that: Asterisk nominates as it checks, and it sends to the lite
end's candidate, which is also its `c=`, whether its checks succeeded or not.

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
- **The outbox, and a flood nobody drains.** Every Binding request that
  reaches a candidate is answered, a stranger's unsigned one with a 400, so
  what waits for `poll_transmit` grows with whatever anybody sends the port
  unless the application takes it. It is held to `TRANSMIT_CEILING`, 256
  datagrams; past that the datagram being queued is dropped, what is already
  queued goes out in order, and `IceAgent::transmits_dropped` counts it. The
  newest gives way rather than the oldest because every datagram there is
  sent again anyway: the peer's check comes again, the agent's own checks
  are retransmitted on their timer, and a consent check or a keepalive, sent
  once, is followed by the next. The refusals of requests that failed
  authentication — all a stranger can make it write — stop earlier, at
  `REFUSAL_CEILING`, half of it, so a flood that lands while the application
  is slow to drain never takes the room the call's own datagrams need: the
  answers carrying the peer's nomination and consent, and the agent's own
  checks and consent requests. An application that drains after every call,
  as it is told to, never reaches either. The facade's lite end holds its
  answers to the same two ceilings, telling a stranger's refusal from a
  signed answer by `LiteAgent::answer_binding_request`, and
  `MediaSession::ice_transmits_dropped` reads either count.

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
agent's datagram model does not carry it), a restart from the facade in the
full role — a peer's restart offer reaches the engine, and its answer keeps
the credentials the running agent holds, since answering with new ones the
agent does not would stop the checks it depends on — and
`a=remote-candidates` (RFC 8839 §4.4.1.2.2). The last is not written because
nothing yet writes an offer it would go in: it belongs in the updated offer a controlling agent sends after
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
authenticator and reaches none of the state machine.

And it is proven in the lab (`scripts/lab.sh ice`), between two stacks each
behind a NAT of its own: the interop harness as caller behind `interop/nat`'s
NAT on one network, and again as callee behind a second NAT on another, with
coturn on the lab network between them. Both require ICE, and each asks
coturn where its media socket appears before the call, so each offers a host
candidate the other has no route to and a server-reflexive one. The callee's
NAT forwards its SIP port and nothing else. The call finds its path on the two
reflexive candidates — the caller fails any path that does not end at the
callee's NAT — and the tone crosses it both ways. The NATs map endpoint-
independently and filter by address and port, and they drop an unsolicited
datagram rather than let it into their own connection table: Linux's NAT
otherwise gives the inside host a new port for a peer whose check arrived
first, which is exactly what two agents checking each other at once produce
(`interop/nat/route.sh` says how).

### What ICE costs a call's start, measured

Nothing goes out on a call using ICE until a pair is selected, so the time
from the offer to `MediaEvent::PathChosen` is the audio a call does not have
at its start. The lab harness prints it on every ICE flow, twice: from the
moment `place_with` wrote the offer, and from the answer arriving. Measured on
the lab VM (Debian 13, 32 cores, Docker bridges, no impairment), 24 September
2026, seven runs of the lite flow, five of the two-NAT one and six of the
relayed one:

| Peer | Offer to path | Answer to path |
|---|---|---|
| ICE-lite (`headless-socket-agent --ice-lite`), same network | 66–70 ms | 57–59 ms |
| Full, each end behind a NAT of its own | 1115–1116 ms | 1112–1113 ms |
| Full, the two NATs blocking each other, through a TURN relay | 1114–1121 ms | 1112–1116 ms |

The relayed call chose the same path all six times: the caller's
server-reflexive candidate to the callee's relayed one, so the audio crossed
coturn once, on a channel bound on the callee's allocation — one relay is all
a path needs, and ICE ranks a pair with one relayed end above a pair with two.
The caller's own relay carried nothing and was given back. The relay adds
nothing measurable to ICE's own start-up, for the reason below; what it adds
is the Allocate, two round trips before the offer — 6 ms on this bridge on
every run at both ends, and twice the round trip to the TURN server on a real
network. The harness allocates just before it places the call, so there it is
added to the call's start; an application that allocates when it binds the
socket, while the user is still dialling, pays it before anyone is waiting.

The two differ by one setting, not by the network. Against a lite peer there
is one pair, and a controlling agent nominates it as soon as its check comes
back: one pacing interval for the check and one for the nomination, 50 ms
each. Through two NATs each end has two candidates, and the pair of host
candidates — unreachable here, but ranked above every reflexive pair — is
still being checked when the reflexive pair succeeds, so regular nomination
waits `nomination_wait`, one second, before settling for the pair it has
(RFC 8445 §8.1.1 leaves the wait to the agent). That second is the cost of ICE
in the full role between two NATted ends, and it is what a shorter
`nomination_wait` would buy back at the price of nominating a pair a better
one might have replaced.

## IPv6

Dual stack throughout. Address family follows the SDP `c=` line. Happy Eyeballs
is not implemented for media: the SDP already said which family the session uses.
