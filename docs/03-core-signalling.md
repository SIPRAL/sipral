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

### Serialization

Deterministic byte-for-byte output, so tests can compare against fixtures.
Compact header forms are supported on receive and not used on send: readable
traces are worth more than the bytes saved, except on UDP near the MTU, where
the transport layer may switch.

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
- **Automatic switch to TCP** when a request is within 200 bytes of a known
  path MTU, or, when the path MTU is unknown, larger than 1300 bytes, per RFC
  3261 §18.1.1. Both figures are configurable, because some carriers perform
  worse than the RFC's assumed 1500-byte Ethernet MTU.
- **`Via` handling.** `branch` with the `z9hG4bK` magic cookie, `rport` per RFC
  3581 always requested, `received` and `rport` honoured on responses. Symmetric
  behaviour: responses go back where the request came from, not where the `Via`
  claims.
- **Keepalive.** Double-CRLF on connection-oriented transports (RFC 5626
  §4.4.1), or `OPTIONS` where a registrar wants a request. The interval is an
  upper bound, not a period: §4.4.1 requires it to be drawn at random between
  the bound and 20% below it, so that a server does not receive every client's
  ping at the same instant. The bound is 25 s by default rather than the 120 s
  the RFC suggests, because that figure assumes a network which leaves an idle
  TCP connection alone for over two minutes and carrier-grade NATs routinely do
  not; a softphone that notices a dead flow two minutes late has missed the call
  it exists for. The cost is four bytes per connection per interval. Tunable per
  endpoint. The core owns the CRLF timer and emits the keepalive as a
  `Transmit`; the `OPTIONS` variant, and any per-account policy, live in
  `sipral-ua`, which has accounts and the core does not.
- **Dead-flow detection**, which is what the keepalive is for. §4.4.1: "If a
  pong is not received within 10 seconds after sending a ping ... then the
  client MUST treat the flow as failed." The framer counts the answering CRLF
  apart from the ping, ten seconds without one takes the flow down and reports
  `Event::FlowFailed`, and everything running on it fails with the transport.
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
  cannot all be let in and then answered past the ceiling. A fork is held to
  it as well: past the first dialog of an INVITE this end sent and the first
  2xx to it, a branch that finds no room is reported without a dialog, and its
  2xx is not acknowledged here — the far end gives it up with a BYE of its own.
  A request inside a
  dialog that exists is never refused, whatever the count says: a BYE turned
  away leaves the call standing for the life of the process.
- **Connection reuse** on TCP and TLS, with the connection keyed so that a
  registration and its calls share it.

## 3. Transactions

Four state machines from RFC 3261 §17, implemented from the diagrams in the RFC:

| Machine | Timers |
|---|---|
| INVITE client | A, B, D |
| non-INVITE client | E, F, K |
| INVITE server | G, H, I |
| non-INVITE server | J |

`T1 = 500 ms`, `T2 = 4 s`, `T4 = 5 s`, all configurable, because carriers exist
where they must be.

The layer owns retransmission, absorbs duplicate requests, and matches responses
to requests by `branch`. It reports timeouts and transport failures upward as
events, never as an error return from an unrelated call.

Two cases that must be right from the first version because they are the ones
that break in production:

- **Forking.** One INVITE, several provisional and final responses, distinct
  `To` tags. Each becomes its own early dialog. The stack must not confuse them.
- **`CANCEL` racing a `200 OK`.** The RFC prescribes the answer; the test suite
  contains it as a scripted scenario from day one.

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
`sipral-ua` decides which codecs to offer; `sipral-core` only encodes the
result.

Every line is kept, including the ones this stack has no use for: a body
travels through a call inside messages that get forwarded, and a stack that
drops what it does not understand breaks the next extension somebody adds.
Attributes are held generically — name and value — with typed access for the
ones the stack acts on.

Typed today: `m=audio` with RTP/AVP and RTP/SAVP, `a=rtpmap`, `a=fmtp`,
`a=ptime`/`a=maxptime`, `a=sendrecv|sendonly|recvonly|inactive`, `a=rtcp`,
`a=rtcp-mux`, `c=` with IPv4 and IPv6, and `a=crypto` for SDES (RFC 4568): the
suite as a value rather than a token, the master key and salt decoded out of
the key parameter, and the lifetime and key identifier that travel beside them.

`a=fingerprint` for DTLS-SRTP is read into the plan and written into an offer,
both exactly as the value stands. There is no DTLS anywhere in this tree — no
handshake, no certificate, nothing that could produce a key — so the line is
carried for whoever does one rather than acted on here.

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
to a server like a replay; the `CSeq` moves too (§22.2); and the same nonce
coming back without `stale` is read as a refusal rather than a fresh challenge,
because §22.1 does not re-try credentials that were just rejected.

A challenge outlives the transaction that earned it — the refusal is a final
response, so the transaction ends on its timer while the password is still
being typed. The set of remembered challenges is capped, so that a peer which
refuses everything and a caller which never retries cannot grow it.
