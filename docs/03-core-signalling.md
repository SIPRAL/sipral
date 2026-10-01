<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# sipral-core: signalling

Four sublayers, bottom to top: syntax, transport rules, transactions, dialogs.
Plus SDP and authentication, which sit beside them.

## 1. Syntax

### Parsing

Zero-copy over the input buffer. A parsed message holds offsets into the caller's
bytes; header values are only materialised when read, and only copied when the
caller keeps them past the buffer.

Two levels of strictness, chosen by the caller:

- **Lenient** (default for received traffic). Accept anything that can be
  understood. Unknown headers are preserved as opaque and passed through in
  responses where the RFC requires. Real deployments emit malformed messages
  daily, and a stack that rejects them loses calls a competitor completes.
  One thing is refused here too: a CR in the head of a message that neither
  ends a line nor begins a fold. It has no reading, and a request carrying one
  could never be answered, because the response copies the fields it sits in
  and no header line can be written with it.
- **Strict** (for our own output, and for the torture corpus). Reject anything
  not conforming.

What a public SIP port receives is hostile by default. The parser is written on
that assumption: no recursion on untrusted input, every length checked, no
panic path, bounded work per message. Fuzzing is a phase 1 exit criterion, not
a phase 3 nicety.

### Limits, and what a refused message gets

`msg::Limits` bounds one message: 65,535 bytes in all, 128 header fields, and
16,384 bytes in any one field's value. The message bound is the largest UDP
payload there is, so no datagram is refused for its size alone. The value
bound is sized for the longest fields real traffic puts on one line — an RFC
8224 `Identity` carrying a full PASSporT with rich call data, a `History-Info`
that has been through a few dozen retargets, a display name the caller's
switch filled — with room to spare, and still a quarter of the message. It
was 4,096 until an INVITE with a 6,000-byte display name was refused outright.
All three are `EndpointConfig::limits`, and a deployment that wants them
tighter sets them there.

A message past a bound, or not well formed enough to parse, is never dropped
without a trace. RFC 3261 §8.2 has a UAS answer what it cannot process rather
than leave the client retransmitting until timer B or F gives up, so a request
is answered — statelessly, from what can still be recovered of it — whenever
its top `Via` can be read, since that is where the answer goes (§18.2.2) and
what the client matches it on (§17.1.3). The answer copies the `Via` and
whichever of `From`, `To`, `Call-ID` and `CSeq` — the other four fields every
response copies (§8.2.6.2) — the request carried, and invents nothing for
the ones it did not:

- **513 Message Too Large** (§21.5.14) for one longer than the message bound,
  with the bound in the reason phrase: `Message Too Large (limit 65535 bytes)`.
- **400 Bad Request** (§21.4.1) for everything else, with a reason phrase that
  names the fault: `From Too Long (limit 16384 bytes)`, `Too Many Header
  Fields (limit 128)`, `Content-Length Exceeds Message` (§18.3's own SHOULD
  for a datagram shorter than its `Content-Length`), `Malformed Header Line`.

The field that was too long can be one of the five — the display name in
`From` is exactly where the 6,000 bytes above were — and it goes back whole,
because a response that changed it would match nothing at the client. Inside
a dialog the answer carries the dialog's own tags and the dialog stands;
nothing about the call changes because one request in it could not be read.

The same holds for a request that parsed but lacks those fields: RFC 4475
§3.3.1's `insuf`, with no `From`, `To` or `Call-ID`, is refused by
`RawMessage::validate` and answered `400 Bad Call-ID` carrying its `Via` and
its `CSeq` (`ResponseBuilder::build_refusal`).

What cannot be answered is dropped: a response, an ACK (never answered,
§17.1.1.3), a request with no `Via` that reads, or one whose request line
cannot be read. So is one whose top `Via` is itself past the value
bound, or holds a CR that ends no line: that `Via` routes the answer
(§18.2.2), and a field the parser refused, or would have, does not get to say
where this end sends anything — nor does the `Via` below one left out. An
answer that would come out past the message bound — the copied fields, the
longer status line and the tag added up — is dropped too. Every refusal,
answered or not, moves `Endpoint::unreadable`, and leaves an entry in the
endpoint's diagnostic record — `request.refused.unreadable` for one that was
answered,
`message.dropped.unreadable` for one that was not, with the size and the bound
when a bound on bytes was what refused it (`docs/14-diagnostics.md`). The
datagram's own `receive` still returns `ReceiveError::Malformed`, which is the
per-message signal to a caller that logs; `sipral_stack_receive_datagram`
answers it as `SIPRAL_STATUS_INVALID_ARGUMENT` with the parser's reason.

On a stream the same message costs the connection only when its framing is
lost with it. The framer knows where a refused message ends as long as its
head ended and named exactly one `Content-Length` (§18.3), and then it hands
the head up to be answered and reads on after it — one oversized `Subject` on
a trunk carrying a hundred calls over one TLS connection does not end the
other ninety-nine. A message whose declared length is past the bound is
answered 513 as soon as its head is in, and the rest of its body is passed over
as it arrives without ever being held. Framing that is lost — a head past the
bound that never ends, or one that names no length or two different ones — is
the one refusal that is final: nothing says where the next message starts, the
connection is retired, and `receive` returns the error.

### Serialization

Deterministic byte-for-byte output, so tests can compare against fixtures.
Compact header forms are accepted on receive and never written on send. A
request near the MTU is moved to a stream transport instead (§2 below), not
shortened.

### The things that are always got wrong

- Header names are case-insensitive, and compact forms (`i`, `m`, `e`, `l`,
  `c`, `f`, `t`, `v`, `k`, `s`) are the same headers.
- Header values are case-sensitive except where the grammar says otherwise.
- Multi-value headers may be folded onto one line or repeated; both must round
  trip. Order matters for `Via`, `Record-Route`, `Route`.
- URI parameters, header parameters and escaping differ. `user=phone`,
  `transport=`, `maddr=`, `lr` all have specific meaning.
- `Content-Length` may lie. On TCP, trust it and frame on it; on UDP, prefer
  the datagram.
- Line folding is legal. So are absurd but conforming constructions: this is
  what RFC 4475 exists to prove.

## 2. Transport rules

`sipral-core` decides *what* to send over *which* transport; it does not open
the socket.

- **UDP, TCP, TLS, WS and WSS** (RFC 7118 for the last two). All five are
  transports the endpoint has the protocol logic for — the `Via` token, the
  framing rule, the timers — and all five are what an application is told this
  build supports, through `sipral::Capabilities` and through the C ABI's
  `SIPRAL_TRANSPORT_BIT_*`. The socket is the caller's on every one of them.
  The transport is picked from the URI, the `Via`, the NAPTR/SRV result the
  caller supplied, or configuration. WebSocket is not a byte stream to the SIP
  layer: RFC 7118 §4.2 puts exactly one SIP message in each WebSocket
  message, so a frame is handed to the core whole, like a datagram, and never
  goes through the `Content-Length` framer that TCP and TLS need. What is not
  here is the rest of RFC 7118: the handshake, the `ws` URI scheme and the
  `transport=ws` parameter on `Contact` and `Route` are phase 2, and
  `crates/sipral-core/src/endpoint/transport.rs` says so at the declaration.
  An application that binds a WebSocket today does the handshake itself.
- **Write it compact first.** A request bound for a datagram that is over the
  line below is written in RFC 3261 §7.3.3's compact form before anything
  else: the one-letter names RFC 3261 gives `Via`, `From`, `To`, `Call-ID`,
  `Contact`, `Supported`, `Subject`, `Content-Type`, `Content-Encoding` and
  `Content-Length`, no space after a colon, and lists of tokens without
  spaces — about ninety bytes off an INVITE, and the same message to every
  parser, since §7.3.3 makes accepting both forms a MUST. The compact forms
  extensions registered later (`o`, `u`, `r`, `b`, `x`, `y`) are not used: a
  peer's module for that extension may look for the long name only, and miss
  the field rather than refuse the message. A request still over the line
  then goes without its `Allow`, which §20.5 lets a UA leave out and §13.2.1
  asks an INVITE to carry; only what is still over after that moves to a
  stream, where it is written in full again. The first send, the answer to a
  challenge, a request inside a dialog and a request moved to another server
  are all held to this. `DatagramLimit::compaction` turns it off
  (`Compaction::Never`) or on for every datagram (`Compaction::Always`, for
  a path known to be narrower than the line, a 1280-byte tunnel say); each
  request written compact because of its size is recorded as
  `transport.compacted.size`, with the size it went at.
- **Switch to TCP** when a request is within 200 bytes of a known path MTU, or
  larger than 1300 bytes when the path MTU is unknown (RFC 3261 §18.1.1). The
  request moves onto a TCP transport the caller has already bound to the same
  destination. If there is none, nothing is sent: the call returns
  `SendError::NeedsStreamTransport`, and `Event::TransportWanted {
  protocol, destination, request_bytes, limit_bytes }` asks the caller to open one and
  send again. The size the event and the record carry is the one the line
  was drawn against, the compact one unless compaction is off. Both figures
  are configurable (`EndpointConfig::datagram_limit`).
- **`Via` handling.** `branch` with the `z9hG4bK` magic cookie, `rport` per RFC
  3581 always requested, `received` and `rport` honoured on responses. Symmetric
  behaviour: responses go back where the request came from, not where the `Via`
  claims.
- **Keepalive.** Double-CRLF on connection-oriented transports (RFC 5626
  §4.4.1). The interval is an upper bound, not a period: §4.4.1 requires it to
  be drawn at random between the bound and 20% below it, so that a server does
  not receive every client's ping at the same instant. The bound is 25 s by
  default rather than the 120 s the RFC suggests, because that figure assumes
  a network which leaves an idle TCP connection alone for over two minutes and
  carrier-grade NATs routinely do not; a softphone that notices a dead flow
  two minutes late has missed the call it exists for. The cost is four bytes
  per connection per interval. Tunable per endpoint. The core owns the CRLF
  timer and emits the keepalive as a `Transmit`. There is no `OPTIONS`
  keepalive and no per-account keepalive policy; on UDP, a flow is kept open
  only by registration refreshes (and the STUN refresh when STUN is on).
- **Dead-flow detection**, which is what the keepalive is for. §4.4.1: "If a
  pong is not received within 10 seconds after sending a ping ... then the
  client MUST treat the flow as failed." The framer counts the answering CRLF
  apart from the ping, ten seconds without one takes the flow down and reports
  `Event::FlowFailed`, and everything running on it fails with the transport.
  The ten seconds apply only once the flow has answered a ping: §4.4 lets a UA
  that did not register with outbound expect a pong only on "an explicit
  indication that CRLF keep-alives are supported", and a pong already received
  is the indication. Asterisk answers none, and a call it carries on a
  connection held to the pong would end half a minute in. Until then the pings
  still go (RFC 3261 §7.5 allows them on any stream) and keep the NAT binding
  open. Each ping also closes the framer's CRLF run, so the pong to the next
  one is not paired with the pong to this one and read as a ping.
  The ten seconds are not configurable — the interval between pings is a
  trade-off the RFC leaves open and this is the MUST, and a setting for it would
  be a setting that turns conformance off. Opening the replacement flow is the
  caller's, here as everywhere; `sipral-ua` puts the registration that was on it
  back on the §4.5 back-off rather than retrying at once.
- **A ceiling on what a peer can make the endpoint hold.** Once the parser has
  refused what it can refuse, an arriving request is a well-formed request, and
  a peer that sends a thousand a second costs a server transaction each. So
  `max_server_transactions` and `max_dialogs` are configuration with defaults an
  order of magnitude past what a softphone reaches (256 and 128), and past
  either one a request that belongs to no dialog we already hold is answered
  §21.5.4's 503 — statelessly, so that refusing costs nothing — and counted, so
  that an operator can watch the number climb. An incoming call counts against
  `max_dialogs` from the moment its INVITE is let in, not from the 180 or 2xx
  that makes its dialog, so INVITEs that arrive faster than they are answered
  cannot all be let in and then answered past the ceiling. A call this end
  places counts from its INVITE on, for the same reason, and one placed at the
  ceiling is `SendError::LimitReached` with nothing sent; a refusal or timer B
  gives the room back at once. A fork is held to
  it as well: past the first dialog of an INVITE this end sent and the first
  2xx to it, a branch that finds no room is reported without a dialog, and its
  2xx is not acknowledged here — the far end gives it up with a BYE of its own,
  and the drop leaves a `dialog.fork.dropped` entry in the diagnostic record
  (`docs/14-diagnostics.md`) — a call that vanishes leaves no other trace.
  A request inside a
  dialog that exists is never refused, whatever the count says: a BYE turned
  away leaves the call standing for the life of the process. That exemption
  has a ceiling of its own instead: at most sixteen non-INVITE server
  transactions per dialog at once, past which the request is answered 503
  with a `Retry-After` rather than left to grow without bound — a peer
  already inside a dialog must not be able to reproduce the same flood from a
  friendlier address. RFC 5057 classes that 503 as ending only the
  transaction, so the dialog underneath it stands. A BYE in order never draws
  from this ceiling either, however many of the sixteen are already open:
  §15.1.1 has the caller consider the session over the moment it sends one,
  whatever answer comes back, so refusing it does not slow a flood down — it
  only leaves the far end holding a dialog the other side has already hung up
  on, and only one BYE is ever worth answering per dialog regardless. A BYE
  whose `CSeq` runs backwards is held to the ceiling like any other request:
  §12.2.2 answers it 500 and it ends nothing, so exempting it would let a peer
  open transactions without limit by numbering its BYEs low. The
  `Retry-After` on this 503 is one second, deliberately short, because the
  budget it answers for frees again as soon as any one of the sixteen open
  transactions retires — on a reliable transport the moment this end answers
  it, and over UDP `64 · T1` after that answer, when §17.2.2's Timer J lets
  the transaction go. One this end never answers at all is answered 408 by
  the endpoint's own 64·T1 deadline (below) and then waits out Timer J like
  any other, so over UDP the slot is back within `128 · T1` at the latest.
  Room can reappear at any instant up to that bound, so a caller told to
  wait longer than a second would be idled on an otherwise healthy call for
  room that may already be there.
- **Connection reuse** on TCP and TLS, with the connection keyed so that a
  registration and its calls share it.

## 3. Transactions

Four state machines from RFC 3261 §17, implemented from the diagrams in the RFC:

| Machine | Timers |
|---|---|
| INVITE client | A, B, D, and M (RFC 6026) |
| non-INVITE client | E, F, K |
| INVITE server | G (for a 2xx too, until its ACK), H, I, and L (RFC 6026) |
| non-INVITE server | J |

RFC 6026's `Accepted` state keeps both INVITE machines alive for 64·T1 after
a 2xx. On the server side over UDP, timer G sends that 2xx again until its ACK
arrives (§13.3.1.4 asks it of the layer above; the endpoint does it for every
layer there is). A 2xx that reaches an INVITE client in `Completed` — another branch
answering after one refused, which a proxy forwards whatever it has already
sent upstream (RFC 3261 §16.7 step 5) — goes up like one in `Accepted`,
without an ACK: RFC 6026 §8.4 re-sends the stored ACK only for a
retransmitted 300-699, and the ACK for a 2xx is the dialog's (§13.2.2.4).

`T1 = 500 ms`, `T2 = 4 s`, `T4 = 5 s`, all configurable, because carriers exist
where they must be. `t1` and `t2` are the two the endpoint refuses to be
built on at zero: §17.1.1.2's retransmit interval is `t1` doubled, capped at
`t2`, and either at zero makes it re-arm at the instant it just fired, which
would never let `handle_timeout` return. `Endpoint::new` returns
`Err(TimerConfigError)` rather than build one that would hang, and does the
same for a `keepalive_interval` of zero, whose next ping would fall due at the
instant the last one went.

The layer owns retransmission, absorbs duplicate requests, and matches responses
to requests by `branch`. It reports timeouts and transport failures upward as
events, never as an error return from an unrelated call.

§17.2.2 gives a non-INVITE server transaction's `Trying`/`Proceeding` states
no timer at all, on the assumption that the application answers. One that
never does would hold its slot for the life of the process, and enough of
them exhaust `max_server_transactions` for every stranger after. So the
endpoint keeps a deadline of its own, outside the RFC's machine: 64·T1 after
the request arrived — by when the client's own Timer F has given it up
anyway — an application that has not sent a final response gets 408 written
on its behalf, and the transaction retires the ordinary way from there. An
INVITE server transaction gets no such deadline: it already counts against
`max_dialogs` from the moment its INVITE is let in, which is the ceiling for
exactly this failure mode.

Two cases that must be right from the first version because they are the ones
that break in production:

- **Forking.** One INVITE, several provisional and final responses, distinct
  `To` tags. Each becomes its own early dialog. The stack must not confuse them.
- **`CANCEL` racing a `200 OK`.** The RFC prescribes the answer; the test suite
  contains it as a scripted scenario from day one.

A request without the RFC 3261 magic cookie — a peer that predates it —
falls back to §17.2.3's field-by-field match, one rule for the INVITE that
created the transaction, one for the ACK that follows it, one for every
other method; `crates/sipral-core/src/transaction/matching.rs` documents
which fields each of the three compares and the two simplifications made
deliberately rather than silently. A branch that is the cookie and nothing
after it (RFC 4475 §3.2.1) takes the same fallback, since it identifies
nothing and every request its sender writes the same way would otherwise be
one transaction. A `From` with no tag is matched as a tag of null rather than
refused (§12.1.1: a UAS "MUST be prepared to receive a request without a tag
in the From field"), and a dialog opened by such a request has a remote tag
of null. What such a peer usually also leaves out cannot be made up for: an
INVITE that names no `Contact` gives a dialog no remote target (§8.1.1.8,
§12.1.1), so it is answered `400 Missing Contact` on a transaction of its
own rather than rung and answered into a dialog nobody could reach. §8.2.2.2 is the other side of the same
fallback's absence: a request with no `To` tag whose `From` tag, `Call-ID`
and `CSeq` already belong to a transaction it does not itself match by
§17.2.3 has reached this end by a second path, almost always a fork, and is
answered 482 on a transaction of its own rather than handed up a second
time — a second call for an INVITE, a second request for any other method. A
request whose `To` carries a tag, even one naming no dialog here, is
§12.2.2's case rather than this one.

### PRACK

RFC 3262 reliable provisional responses. Not needed for FreeSWITCH, where 100rel
is off by default. Needed for carriers that mandate it, which is why it is in
phase 1 rather than deferred. `100rel` in `Supported` or `Require`, `RSeq` and
`RAck` accounting, and the retransmission of the reliable provisional response
until PRACK arrives, doubling from T1 with no cap — unlike a 2xx, because a
PRACK is not triggered by receiving one.

One reading is written down rather than left implicit. §4 keeps the received
sequence number "for the initial request", which predates a clean answer for
forking: one INVITE that a proxy forks is answered by several user agents, each
numbering its own series from its own transaction (§3: "The RSeq numbering space
is within a single transaction"). Kept per request, two branches would look to
each other like a series full of gaps and every response after the first would
be discarded, so it is kept per dialog instead.

## 4. Dialogs

A dialog is Call-ID plus both tags. The layer maintains:

- local and remote tags, and the transition of an early dialog to confirmed;
- local and remote CSeq, with the special case that a re-INVITE and its
  in-dialog requests share the sequence space while `CANCEL` and `ACK` do not
  increment it;
- the route set from `Record-Route`, in the right order, with `lr` handling and
  the strict-router rewrite for the ones that still exist;
- the remote target from `Contact`, set when the early dialog is established
  (RFC 3261 §12.1) and afterwards changed only by the two target-refresh
  requests, re-INVITE (§12.2) and UPDATE (RFC 3311 §5.1);
- the ACK for a 2xx, which is outside the INVITE transaction (RFC 3261
  §13.2.2.4). The caller sends it once, because it may carry the answer and
  because the caller decides when media is ready; after that the dialog layer
  keeps it and answers every retransmitted 2xx itself. The ACK for a non-2xx
  is the transaction's own business (§17.1.1.3) and never reaches the caller.
  An incoming ACK is matched to the dialog by its `To`/`From` tags and then
  by its `CSeq` number against the INVITE whose 2xx this end sent last
  (§13.2.2.4, §17.1.1.3: "the same CSeq as the INVITE being acknowledged") —
  not against the dialog's remote sequence number, which a PRACK or an UPDATE
  sent before the ACK has already moved on. It is reported once: an ACK that
  names an earlier INVITE, a stale one for a re-INVITE this dialog has since
  moved past most often, and a repeat of one already reported are absorbed.

A re-INVITE (§14) is an INVITE inside a dialog and is handled apart from one
that opens a call, because "unlike an INVITE, which can fork, a re-INVITE will
never fork" (§14.1). Its answer is not offered to a set of dialogs looking for
branches; it feeds the one dialog it was sent in, refreshes the remote target,
and is acknowledged by an ACK carrying *its* sequence number rather than the
original INVITE's.

Two INVITEs crossing in one dialog — both ends putting the call on hold at the
same instant — is answered here and never handed up, because §14.2 leaves no
decision in it: 491 when the crossing one arrived while ours was outstanding,
500 with a randomly drawn `Retry-After` when the far end sent a second before
we answered its first, and the same 500 for a second UPDATE (RFC 3311 §5.2).
The end that receives the 491 is told how long to wait — 2.1 to 4 seconds if it
generated the `Call-ID`, 0 to 2 if it did not, so that the two do not collide
again — and decides for itself whether the change is still wanted. RFC 3311's
other glare rules turn on whether an offer is outstanding, which is offer/answer
state and belongs to `sipral-ua`.

## SDP

Offer/answer per RFC 3264, as a value type: parse, inspect, build. No policy.
`sipral` (the facade: `MediaEngine` and its `CodecCatalog`) decides which
codecs to offer; `sipral-core` only encodes the result.

Every line is kept, including the ones this stack has no use for: a body
travels through a call inside messages that get forwarded, and a stack that
drops what it does not understand breaks the next extension somebody adds.
Attributes are held generically — name and value — with typed access for the
ones the stack acts on.

Typed today: `m=audio` with RTP/AVP and RTP/SAVP, `a=rtpmap`, `a=fmtp`,
`a=ptime`, `a=sendrecv|sendonly|recvonly|inactive`, `a=rtcp`, `a=rtcp-xr`,
`a=rtcp-mux`, `c=` with IPv4 and IPv6, and `a=crypto` for SDES (RFC 4568): the
suite as a value rather than a token, the master key and salt decoded out of
the key parameter, and the lifetime and key identifier that travel beside them.

`a=fingerprint` for DTLS-SRTP is read into the plan and written into an offer,
exactly as the value stands, and **every** line is kept rather than the first:
RFC 8122 §5 lets a description carry one per hash function so that a peer
which knows only one of them can still check it, and taking the first would
fail a call over which hash the other end happened to write first. Nothing
here acts on them — no handshake, no certificate, no key lives in this crate —
but the facade does, behind its `dtls` feature (`docs/05-media.md`).

Carried but not typed here: the `a=candidate` lines ICE needs. They survive a
parse and a round trip like every other attribute, and reading one still means
reading a name and a value. The typed reading belongs to the crate that acts on
them, and that is where it is: `sipral-nat` writes and reads them over this
model ([06-nat.md](06-nat.md)). Writing a second one here would be an accessor
with no caller.

Hold is `a=sendonly` with `a=recvonly` in the answer. The `c=0.0.0.0` form is
accepted on receive because old equipment sends it, and never sent.

## Authentication

Digest per RFC 3261 §22 and RFC 8760: MD5, MD5-sess, SHA-256, SHA-256-sess,
SHA-512-256, SHA-512-256-sess, `qop=auth`, correct `nc` and `cnonce`
accounting, and re-use of a valid challenge without a round trip once one is
known.

`WWW-Authenticate` and `Proxy-Authenticate` are separate credential spaces and
are tracked separately. Credentials are held zeroised on drop and never
logged, not even at trace level.

The endpoint reads a challenge and says so; it never answers one on its own.
The password is the one thing this layer must not hold, and answering with the
wrong one is how an account gets locked, so *whether* to answer is the caller's
decision. What the endpoint does own is the bookkeeping the RFC is exact about:
`nc` moves by one per request and never skips, because a skipped number looks
to a server like a replay; it starts again only for a new nonce value, so the
same nonce coming back marked `stale` carries its count on (RFC 7616 §3.4
counts the requests sent "with the nonce value"); the `CSeq` moves too
(§22.2); and the same nonce coming back without `stale` is read as a refusal
rather than a fresh challenge, because §22.1 does not re-try credentials that
were just rejected.

A challenge outlives the transaction that earned it — the refusal is a final
response, so the transaction ends on its timer while the password is still
being typed. The set of remembered challenges is capped, so that a peer which
refuses everything and a caller which never retries cannot grow it.
