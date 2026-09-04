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

- **UDP, TCP and TLS in phase 1; WS and WSS in phase 2** (RFC 7118). The
  transport is picked from the URI, the `Via`, the NAPTR/SRV result the caller
  supplied, or configuration. WebSocket is not a byte stream to the SIP layer:
  RFC 7118 §4.2 puts exactly one SIP message in each WebSocket message, so a
  frame is handed to the core whole, like a datagram, and never goes through
  the `Content-Length` framer that TCP and TLS need.
- **Automatic switch to TCP** when a request is within 200 bytes of a known
  path MTU, or, when the path MTU is unknown, larger than 1300 bytes, per RFC
  3261 §18.1.1. Both figures are configurable, because some carriers perform
  worse than the RFC's assumed 1500-byte Ethernet MTU.
- **`Via` handling.** `branch` with the `z9hG4bK` magic cookie, `rport` per RFC
  3581 always requested, `received` and `rport` honoured on responses. Symmetric
  behaviour: responses go back where the request came from, not where the `Via`
  claims.
- **Keepalive.** Double-CRLF on connection-oriented transports (RFC 5626
  §4.4.1), or `OPTIONS` where a registrar wants a request. The interval is a
  design choice, not a spec value: 25 s by default, because typical NAT UDP
  bindings expire at 30 s and the RFC 5626 default of 120 s for TCP would drop
  most of them; tunable per endpoint. The core owns the CRLF timer and emits
  the keepalive as a `Transmit`; the `OPTIONS` variant, and any per-account
  policy, live in `sipral-ua`, which has accounts and the core does not.
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
until PRACK arrives.

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
  requests, re-INVITE (§12.2) and UPDATE (RFC 3311 §5.2);
- the ACK for a 2xx, which is outside the INVITE transaction (RFC 3261
  §13.2.2.4). The caller sends it once, because it may carry the answer and
  because the caller decides when media is ready; after that the dialog layer
  keeps it and answers every retransmitted 2xx itself. The ACK for a non-2xx
  is the transaction's own business (§17.1.1.3) and never reaches the caller.

## SDP

Offer/answer per RFC 3264, as a value type: parse, inspect, build. No policy.
`sipral-ua` decides which codecs to offer; `sipral-core` only encodes the
result.

Supported: `m=audio` with RTP/AVP and RTP/SAVP, `a=rtpmap`, `a=fmtp`,
`a=ptime`/`a=maxptime`, `a=sendrecv|sendonly|recvonly|inactive`, `a=rtcp`,
`a=rtcp-mux`, `c=` with IPv4 and IPv6, `a=crypto` for SDES, `a=fingerprint`
for DTLS-SRTP, and the `a=candidate` lines ICE needs.

Hold is `a=sendonly` with `a=recvonly` in the answer. The `c=0.0.0.0` form is
accepted on receive because old equipment sends it, and never sent.

## Authentication

Digest per RFC 3261 §22 and RFC 8760: MD5, MD5-sess, SHA-256, SHA-256-sess,
`qop=auth`, correct `nc` and `cnonce` accounting, and re-use of a valid
challenge without a round trip once one is known.

`WWW-Authenticate` and `Proxy-Authenticate` are separate credential spaces and
are tracked separately. Credentials are held zeroised on drop and never
logged, not even at trace level.
