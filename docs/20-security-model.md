<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# 20 — Security model

A SIP endpoint listens on a port anyone on the internet can write to, and reads
what arrives before it knows who sent it. This is the threat model that follows
from that fact, written against this tree rather than against SIP in general:
every claim below names the file it lives in, and a claim this document cannot
point at code for does not appear.

## What reaches this stack, and what happens to it

| Who | What they can do | What answers it | Where |
|---|---|---|---|
| A hostile peer on the open port | Send anything: truncated, oversized, absurd but conforming (RFC 4475), or simply wrong | Bounded parsing, no panic, a 400 or a silent drop depending on how the message failed | `crates/sipral-core/src/msg/`, below |
| A proxy or B2BUA in the path | Rewrite `Via`, `Route`, `Contact`, the body | Loose-routing rules (RFC 3261 §§12, 19.1.4) read what a proxy is allowed to change; nothing here checks that a proxy did *not* change what it wasn't allowed to — SIP has no header integrity of its own, and this stack adds none | `crates/sipral-core/src/msg/route.rs`, `docs/03-core-signalling.md` |
| A peer, or a scanner, that floods | Many INVITEs, one source or many, faster than they can be answered | A token-bucket admission ladder before a dialog is even opened | `crates/sipral-ua/src/screening.rs` |
| A peer that replays a captured exchange | Resend a request, a digest response, a media packet | Transaction-layer duplicate absorption; digest `nc`/nonce bookkeeping; the SRTP replay window | `crates/sipral-core/src/transaction/`, `crates/sipral-core/src/endpoint/auth.rs`, `crates/sipral-rtp/src/srtp/` |
| A network that drops, reorders, duplicates | Ordinary UDP behaviour, not an attack, but a peer can make it worse | Retransmission timers per RFC 3261 §17; a jitter buffer that treats reordering as normal and drops duplicates by sequence number | `crates/sipral-core/src/transaction/`, `crates/sipral-rtp/` (`docs/05-media.md`) |

The proxy row is the one worth dwelling on, because it is the one place this
stack knowingly trusts what it cannot verify. `docs/04-ua.md`'s own words on
the related `Replaces` check state the limit plainly: behind an outbound proxy
"every inbound INVITE arrives from that one address, so the check authorises
whatever the proxy relays, and the real boundary is the proxy's, not ours."
That sentence generalises: nothing in this tree signs or MACs a SIP header, so
a proxy that is allowed to touch `Via` and `Route` is trusted not to touch
anything else, and a compromised one is indistinguishable from a well-behaved
one at this layer. RFC 3261 gives no better answer, and this stack does not
invent one — see "What this stack deliberately does not do", below.

## What is parsed before anything is trusted

`crates/sipral-core/src/msg/` is eighteen files: a zero-copy parser
(`parse.rs`), a stream reassembler (`framer.rs`), the message view and its
field accessors (`message.rs`), and one file per header shape (`uri.rs`,
`via.rs`, `addr.rs`, `route.rs`, `auth.rs`, `scalar.rs`, `events.rs`,
`header.rs`, `lex.rs`, `tokens.rs`, `method.rs`) plus the outbound builder
(`builder.rs`). Nothing is copied on the way in; a parsed message holds spans
into the caller's own buffer, and a header value is only materialised when
something reads it (`docs/03-core-signalling.md`).

**Bounds come first.** `msg::Limits` (`crates/sipral-core/src/msg/parse.rs:25`)
caps the whole message at 64 KiB (`max_message_bytes: 65_535`), the header
count at 128, and one header's value at 16 KiB — each an independent,
tunable ceiling checked before the byte count behind it is trusted for
anything else. The value ceiling was 4 KiB until it refused a real shape of
traffic: an INVITE with a 6,000-byte display name got no answer at all. It is
sized now against the longest fields that legitimately travel on one line —
a full RFC 8224 `Identity`, a long `History-Info` — and it costs no memory of
its own, since a value is a span into the message rather than a copy. What
a ceiling refuses is answered rather than dropped when it can be: a request
whose top `Via` can still be read gets 513 or a 400 naming the bound,
statelessly; the rest is counted and recorded
(`docs/03-core-signalling.md`, "Limits, and what a refused message gets").
The answer is the `Via` and whichever of `From`, `To`, `Call-ID` and `CSeq`
the request carried, as they came, plus a status line, a tag when there is a
`To` to put it in, and a `Content-Length`, so a forged source address gets
back about what was sent for any request carrying more than those, and
under two and a half times it for the smallest ones that can be answered at
all — every name compact, 66 bytes with all five fields answered with 156,
and 37 bytes with the `Via` alone answered with 76. Where the answer goes is
never read from a field past a bound: a request whose top `Via` is longer than the value bound, or
whose `Via` had to be left out, is not answered, since that `Via`'s `maddr`
and port would decide where the answer lands. A second, separate `sdp::Limits`
(`crates/sipral-core/src/sdp/parse.rs:41`) does the same for a body once it
is one: 16 KiB total, 2 KiB per line, 16 media blocks, 256 attributes overall
and 64 per section. Neither is a courtesy default: both are sized against
what a real offer carries — ICE candidates and an `a=crypto` key included —
with room to spare and nothing like room for an attacker's megabyte of `a=`
lines.

**Work is bounded per byte, not just per message.** `StreamFramer` resumes its
search for the end of a message's headers from where it last stopped
(`crates/sipral-core/src/msg/framer.rs`, documented at its own top: "a peer
that feeds one byte at a time cannot make this re-scan the whole pending
buffer each time"), so a connection fed one byte at a time costs the same
total work as one fed all at once, rather than the quadratic cost a naive
rescan would pay. The accumulation buffer itself is held to `max_message_bytes`
as it grows, not only once a message is complete, so a peer cannot hold an
unbounded amount of "almost a message" in memory by never finishing it: a head
that passes the bound without ending ends the connection, and a message whose
declared body would pass it is refused as soon as its head is in and the body
is discarded as it arrives rather than buffered. The one slack is a single
read: several complete messages that arrive together may briefly sum past the
bound, since each of them keeps it and each is taken off the front before
anything more is read. There
is no separate wall-clock or step-count budget inside the parser — the
protection is entirely the fixed size ceilings above, which already bound the
worst case to a small constant.

**`Content-Length` is read the way RFC 3261 §18.3 and RFC 4475 need it read,
not the way a sender writes it.** Two conflicting `Content-Length` headers is
a parse error (the RFC 4475 `mcl01` case) rather than a choice between them; a
declared length longer than what actually arrived is `BodyTruncated`, waited
for on a stream and refused on a datagram, with the 400 §18.3 asks of a
request; a declared length shorter than the
buffer cuts the body there and leaves the rest for whoever reads the next
message — the classic smuggling shape, answered by never reading past the
boundary the sender itself named. A message on a stream transport with no
`Content-Length` at all cannot be framed (§18.3 makes the header mandatory
there); on a datagram, where the RFC allows the omission, the rest of the
datagram is read as the body.

**`RawMessage::validate`** (`crates/sipral-core/src/msg/message.rs:537`) is
the single place every structural field — `Via`, `Call-ID`, `CSeq` against the
start line's method, `From`/`To`, `Contact`, `Route`/`Record-Route`, the
authentication headers — is checked at once and named on failure. It is
exhaustively tested against the RFC 4475 corpus
(`crates/sipral-core/tests/rfc4475.rs`) and against both fuzz targets that
touch a whole message (`fuzz/fuzz_targets/parse.rs`, `framer.rs`). **It is not
called from the live receive path.** `Endpoint::dispatch`
(`crates/sipral-core/src/endpoint/inbound.rs`) routes a message straight to its
handler once framing has succeeded, and each handler reads the one or two
fields it needs through the same accessors `validate` calls — so a field
`validate` would have named is instead read lazily, and a `HeaderError` from
it is handled locally, almost always by dropping the message rather than by
building a 400. That is weaker than "a malformed request draws a 400" reads
as a blanket claim: what actually happens to a message that frames correctly
but fails one field is ad hoc per call site, and mostly silent. Nothing about
this is a memory-safety or availability problem — the parser still never
panics and never does unbounded work on the field itself — but it is a real
gap between what `validate` proves in a test and what the dispatcher does with
a live message, and it is worth closing rather than assuming closed.

**Fuzzing covers the doors an attacker's bytes come through.** Twenty-nine
`cargo fuzz` targets under `fuzz/fuzz_targets/` (`docs/11-testing.md`): four
over SIP itself (`parse`, `framer`, `builder`, `sdp`), ten added once it was
clear how much of the receive path the first four never reached (`crypto`,
`replay`, `dialoginfo`, `mwi`, `headless`, `rtcp`, `rtp_dtmf`,
`srtp_unprotect`, `stun`, `turn`), two for DTLS (`dtls_record`,
`dtls_handshake`), one for
DTMF over SIP INFO (`dtmf_info`), one for the ICE agent (`ice`), one for the
TURN client driven by a relay that answers anything (`turn_client`), nine
over `sipral-media`'s DSP once it was the turn of the codec and audio layer
downstream of RTP (`media_resample`, `media_plc`, `media_drift`,
`media_comfort_noise`, `media_vad`, `media_g722`, `media_g729`, `media_mix`,
`media_opus`), and one for what the headless socket's messages do to a
bridged session (`headless_media`). The exit gate is 24 hours per target
with no crash and no hang, and every target but `headless_media`,
`media_g729` and `turn_client` has had it run: the first eighteen on 21 and
22 September 2026, about 37 billion executions, and the eight media ones
before `media_g729` on 23 September, about 24 billion, nothing found on any
(`docs/11-testing.md`). `media_g729` covers the G.729 decoder — speech
frames, Annex B's SID frames, frames not sent and frames lost — the payload
reader and an encoder with Annex B's DTX; it, `turn_client` and
`headless_media` have not had that gate yet, and `scripts/check.sh` builds
all twenty-nine on every run so none of them rots uncompiled between
releases.

`ice` covers the one seam that is open to anybody before a
key exists at all: an ICE agent binds the media port and answers connectivity
checks on it, so `handle_datagram` runs on bytes from an unauthenticated
stranger earlier than SRTP, earlier than the DTLS handshake, earlier than
anything that could say who the peer is. Its seeds carry checks signed the way
the agent will check them, which is the difference between fuzzing the state
machine and fuzzing the authenticator in front of it: the seeds alone reach
more of the agent than several hundred thousand random runs did.

## The refusals that exist on purpose

**Screening.** Before an INVITE becomes a ringing phone it goes down a ladder
in `crates/sipral-ua/src/screening.rs`. First, a token bucket keyed by source
address, not address and port — changing a port costs an attacker nothing,
while the address is what they must own to hear an answer back. The default
(`Rate::DEFAULT`, `screening.rs:189`) is a burst of ten and one more every two
seconds, deliberately loose, because in most deployments every legitimate call
already arrives from the one address the phone registered with. The table of
watched sources is a fixed 64 entries (`const WATCHED: usize = 64`,
`screening.rs:87`); once every seat is spent by a source still spending, a
stranger is refused rather than admitted untracked. Second, an application
policy hook (`trait Screen`, `screening.rs:380`) is asked about every INVITE
that survives the rate limit, before a `CallHandle` exists and before the
application's own `IncomingCall` event fires. Every refusal this stack decides
by itself is **480 Temporarily Unavailable** — never 404 (would prove the
number exists), never 503 (would take the whole line off a proxy's air), never
6xx (would speak for the whole person rather than one device) — and it is
answered rather than dropped, because an INVITE nobody answers is retransmitted
for 32 seconds and holds a server transaction open for all of it. A policy
answers with the status it chose, here and through `sipral_stack_screen`, since
an application may know a truer reason than this stack can; the paragraph above
is the advice that comes with that freedom, and `docs/04-ua.md` gives it in
full. The one default that is not 480 is `Screen::on_replaces`, which refuses
403: an INVITE claiming a call it has no standing to take is not one this end
is unavailable for. Nothing about a refusal is
otherwise observable: no event fires (an event queue anyone on the internet
can fill is the same attack one layer up), only four cumulative counters
(`UserAgent::refusals()`).

**The challenge counter.** A registrar, or any server, that draws a fresh
nonce for every refusal and never marks it `stale` defeats RFC 3261 §22.1's
own guard against retrying a rejected password. The defence underneath it is
`const ANSWERS: u8 = 3` (`crates/sipral-core/src/endpoint/auth.rs:60`): one
request is answered with credentials at most three times, whatever nonce
comes back, before the stack calls the password wrong and stops — "a correct
exchange needs one, a nonce that aged out between the request and the answer
needs two, and a third is already generous" (the constant's own comment). The
allowance is per request, and the set of challenges still waiting for an
answer is itself capped at 32 (`const REMEMBERED`, `auth.rs:43`), so a peer
that refuses everything cannot grow it without bound.

**The RFC 3261 §18.1.1 size promotion.** `DatagramLimit`
(`crates/sipral-core/src/endpoint/config.rs:19`) carries the RFC's own rule
verbatim in its doc comment — within 200 bytes of a known path MTU, or past
1300 bytes when the MTU is unknown, a request goes on a stream instead of a
datagram — and both figures are configurable. This is not documentation of an
intention: `crates/sipral-core/src/endpoint/driver.rs` checks every request
against it before it is handed out as a `Transmit`, reuses an already-open
stream to the destination if one exists, and otherwise emits
`Event::TransportWanted` and refuses to emit the oversized datagram at all.
A credential-bearing retry that grew past the limit is held rather than sent
in the clear at the smaller size or dropped silently.

**The 482 for a merged request.** RFC 3261 §8.2.2.2's case — a forked INVITE
answered by more than one branch, so the same `From`-tag/`Call-ID`/`CSeq`
arrives twice with different `Via branch` values and no `To` tag naming an
existing dialog. `Transactions` tracks a refcounted `MergeKey`
(`crates/sipral-core/src/transaction/store.rs:117`) per those four fields;
`merged_with()` (`store.rs:369`) is asked on every new INVITE and non-INVITE
request, and a second one that matches an existing key while itself carrying
no `To` tag is answered `StatusCode::LOOP_DETECTED` (482) on a transaction of
its own, in `refuse_merged_invite` and its non-INVITE sibling
(`crates/sipral-core/src/endpoint/inbound.rs`), rather than delivered to the
application a second time.

**The per-dialog transaction budget.** Past the parser, a well-formed request
still costs a server transaction, and a peer that owns a dialog can otherwise
reproduce a flood from inside it — which the source-address rate limit above
never sees, because it runs before a dialog exists. `endpoint/inbound.rs`
holds a dialog to at most sixteen non-INVITE server transactions open at once
(`const MAX_DIALOG_NON_INVITE_TRANSACTIONS: usize = 16`); past it, a request
is answered 503 with `Retry-After: 1` rather than left to grow the dialog's
own table without bound. An INVITE and an in-order `BYE` are exempt — RFC 5057
already has a request like that ending only the transaction it arrived on,
never the dialog, and refusing a `BYE` would only leave the far end holding a
call this end has already given up. Underneath that per-dialog ceiling sit the
endpoint-wide ones, `max_server_transactions` (256) and `max_dialogs` (128,
counted from the moment an INVITE is let in, not from the dialog it eventually
makes), past which a stranger's request is answered 503 statelessly — refusing
costs nothing more than the response itself (`docs/03-core-signalling.md`).

## The keys

**Where an SRTP key comes from.** `MediaEngine::new` takes a 32-byte media
seed of its own, entirely apart from whatever entropy the rest of the
endpoint runs on. `draw_key` (`crates/sipral/src/engine.rs`) turns one block of
`SHA-256(media_seed || counter)` into a `KeySalt`, copied byte by byte into
buffers that zeroise themselves rather than through a bulk copy that could
leave a duplicate in a stack slot the compiler does not clear. The counter
never repeats, which is also what RFC 4568 §7.1.2 needs when it requires an
answer's key to differ from the offer's.

**Why a second seed rather than a slice of the first.** The endpoint's own
seed is written in clear into every replay recording
(`crates/sipral-core/src/replay/recording.rs`; `docs/18-replay.md` says so in
as many words: a recording is meant to reproduce a session, not decrypt one).
One generator for both would have put every SRTP key this stack will ever
offer into every recording it makes — including one taken to diagnose
something unrelated, by somebody told the file holds only what a capture
holds. Because both are visible in exactly one place,
`sipral_stack_create` (`crates/sipral-ffi/src/stack.rs`) is where they are
compared, and creation is refused outright if an application ever hands over
the same 32 bytes for both. The diagnostic record — the structured, always-safe-to-forward
account of what the stack decided (`docs/14-diagnostics.md`) — holds neither
seed and no key material of any kind; it is deliberately a different artefact
from a replay recording, with a different, narrower, safety promise.

**Nothing that holds key material derives `Debug`.** Six types —
`KeySalt` (`crates/sipral-core/src/sdp/crypto.rs`), `Attribute` and `KeyLine`
(`crates/sipral-core/src/sdp/session.rs`), `Push`
(`crates/sipral-ua/src/account.rs`, the RFC 8599 wake-up token, the same shape
of secret), and the two ends of ICE's short-term credential, `Credentials`
(`crates/sipral-nat/src/ice/full/mod.rs`) and `RemoteIce`
(`crates/sipral-nat/src/ice/sdp.rs`) — each has a hand-written `Debug` that
prints `<redacted>` in place of the material and nothing derived, and
`KeySalt` additionally zeroises on `Drop`. `scripts/check.sh` asserts both
properties for exactly these six named types: no `#[derive(..., Debug, ...)]`
immediately above the struct, and a hand-written `impl fmt::Debug for` it
somewhere in the file — so a future edit that adds the derive back, or removes
the hand-written impl without noticing, fails the gate rather than shipping a
build that prints every key on the machine the first time something logs a
call.

The last two are worth saying separately, because they are the same secret
twice and only one of them was remembered. ICE signs every connectivity check
with a password each end draws and publishes in its own description (RFC 8445
§7.1.2.3), so the credential exists on both sides of the call: `Credentials`
is this end's and `RemoteIce` is the peer's, read off the network.
`Credentials` wrote its `Debug` by hand from the start; `RemoteIce` derived
one, and the half that leaked was the half that came in from outside. Whoever
holds an ICE password can sign a check the peer believes, and a check the peer
believes is how the media gets pointed somewhere. `a=ice-pwd` is redacted one
layer down as well, in `Attribute`, so a `{:?}` on a whole description is
covered whether or not anything has parsed it into a `RemoteIce` yet.

**What SDES does and does not protect.** `a=crypto` (RFC 4568) carries the
master key inside the SDP body, in the SIP message, in the clear as far as
this layer is concerned — RFC 4568 §7 makes the whole mechanism depend on the
signalling itself being protected, and whether it is, this crate cannot see:
`sipral-ua` offers no way to ask which protocol a bound transport speaks, and
only the application, which bound it, knows. That is why `SrtpPolicy::NotOffered`
is the default (`crates/sipral/src/keying.rs`, table in `docs/05-media.md`):
an offer with a key on a transport this stack cannot verify is protected would
be a plaintext key sent believing it is not one. `Offered` and `Required` both
write the same secure offer and differ only in what they do with a plain
answer or re-offer — `Required` refuses one outright (488 on a live re-offer,
never a silent downgrade), `Offered` accepts a plainer call over none at all.
Every policy still answers a secure offer *from a peer* with a key of this
end's own, because refusing an offer the peer already secured buys nothing.
In short: SDES is exactly as protected as the transport carrying the SDP,
never more, and this layer will not pretend otherwise by turning itself on
without being told the transport is safe.

**The push token stays off every request but `REGISTER`.** RFC 8599 §4.1's own
requirement. `Account::contact_value` (`crates/sipral-ua/src/account.rs`)
builds a `Contact` with no push parameters at all and is what every in-dialog
and dialog-opening request uses; `register_contact_value`, the only function
that can reach `Push::write`, is called from nowhere but the `REGISTER`
builder in `agent.rs`. The split is structural rather than a check that could
be skipped: a caller cannot leak `pn-prid` onto an INVITE without going
through the one function that never runs for one.

## What this stack does not authenticate, and what that costs a transfer

**This stack answers challenges and issues none.** It is a user agent, never a
registrar or a proxy (`docs/01-architecture.md`: "No SIP server, proxy,
registrar or B2BUA. Sipral is an endpoint."), so there is no digest-response
*verification* anywhere in the tree — `crates/sipral-core/src/auth/digest.rs`
computes and formats an outgoing `Authorization`, and nothing compares a
received response against an expected one, because nothing here ever issues
the challenge a response would answer. That is a correct absence for what this
crate is, not an oversight, but it has a real consequence stated in the
tree's own words: "this stack answers challenges without ever issuing one, so
there is no authenticated peer to compare against"
(`crates/sipral-ua/src/transfer.rs`).

**REFER.** `on_refer` (`crates/sipral-ua/src/transfer.rs`) requires a REFER to
match an existing dialog and to carry exactly one `Refer-To`; it does not, and
cannot, check who sent it. `Referred-By` (RFC 3892) is copied onto the INVITE
a transfer places because the RFC requires it, not because it proves anything
here — the signed token that would make it proof (RFC 3892 §3) is not
implemented, and the field is a plain header a sender writes like any other.
Anyone who can reach an existing dialog can ask this stack to call a third
party on that dialog's behalf.

**`Replaces`.** RFC 3891 §3 asks a UA to verify that whoever sent a `Replaces`
is authorised to take over the dialog it names, and §8 wants that only over an
authenticated peer — which this stack, per the paragraph above, never has. So
the check it can actually make is address-based: a matched `Replaces` is
honoured only when the INVITE carrying it arrives from the same place the
named call's own signalling does (`Replacing::strict`,
`crates/sipral-ua/src/screening.rs`; the rule and its reasoning are written out
in `docs/04-ua.md`). Refusal is 403, counted separately
(`refusals().by_replaces`). Three limits on that check are stated plainly
rather than left to be discovered: behind an outbound proxy every inbound
INVITE arrives from the one proxy address, so the check authorises whatever
the proxy relays; on a datagram transport the source address is not
authenticated, so a forger who cannot receive the answer can still reach the
state machine and tear a dialog down from a packet they never held a
conversation over; and on a byte stream bound without a named far end, there
is no source to compare against, and anything arriving matches. The
application has the last word — `Screen::on_replaces` — for the one legitimate
case the strict rule refuses: an attended transfer whose transferee reaches
this end directly rather than through the line's own proxy.

## What this stack deliberately does not do

- **It does not open a socket.** The core is sans-I/O by construction
  (`docs/01-architecture.md`): it cannot bind a privileged port, leak a file
  descriptor, or be blocked on, because there is no socket here to do any of
  that. The one exception, confirmed by grep across every crate below
  `sipral-ffi`, is `sipral_ua::Runtime`, a reference event loop behind the
  `reference-loop` feature and off by default, which is where `std::net`'s
  socket types and `thread::spawn` actually appear
  (`crates/sipral-ua/src/runtime.rs`).
- **It does not read a clock.** No `Instant::now()` in production code in
  `sipral-core`, `sipral-ua`, `sipral-rtp`, `sipral-media` or `sipral-nat`,
  the same `Runtime` exception aside; `scripts/check.sh` fails a build on one
  found outside a test (`docs/11-testing.md`, D9 in
  `docs/13-client-requirements.md`).
- **It does not run a thread of its own**, again outside `Runtime`.
- **It has no TLS of its own.** `TransportProtocol::Tls` describes a transport
  the caller has already secured; no TLS implementation is linked, and none is
  planned, because a stack that picked one would impose it on every embedder
  (`docs/01-architecture.md`, `docs/03-core-signalling.md`). Whatever
  protection SDES's key exchange needs from the signalling transport (above)
  is therefore entirely the application's to provide.
- **It is not a proxy, a registrar or a B2BUA.** It never rewrites a message
  on someone else's behalf and never terminates one signalling leg to
  originate another, so the class of attack that targets those roles has
  nothing here to land on (`docs/01-architecture.md`, `docs/09-rfc-index.md`).
- **DTLS-SRTP is reachable from a call, and has had an internal adversarial
  review, not an external one.** The handshake in `crates/sipral-dtls` — both
  roles, the record layer, fingerprint checking in constant time — is joined
  to the facade behind the `dtls` feature, which is on by default
  (`docs/05-media.md`). Its own documentation commits it to an adversarial
  cryptography review "before it ships under the commercial licence". The
  project's own has been done, area by area — the two handshake state
  machines, the record layer and its replay window, the key schedule and the
  RFC 5705 export, certificates and the fingerprint binding, and the join to
  the media path — each read by a reviewer asked only to find how it breaks,
  and every finding then argued against by another.

  It found no way to read, forge or replay media, to downgrade the protocol or
  its suite, or to be taken for the far end: the certificate is checked
  against the signalled fingerprint before anything derived from the handshake
  is trusted, the GCM nonces never repeat under a key, and the SRTP keys are
  exported to the directions the roles give them. It found seven defects of
  availability and interoperability, and all seven are fixed: a latch any
  stranger could close with one datagram (below); a handshake's flights sent
  to the signalled port rather than the one the far end's records came from; a
  latch left behind when ICE moved the pair or a re-negotiation moved the far
  end; a certificate renewal that handed a ringing call's handshake a
  certificate its offer never named; a re-negotiation that changed a running
  stream's kind of keying, or reset what later certificates were compared
  against, and was adopted rather than refused; and a forged epoch-0
  retransmission that kept a bare `sipral_dtls::Connection` from ever giving
  up. The lab then found an eighth, against Asterisk: a far end that begins a
  new association on a re-negotiation (RFC 6347 §4.2.8) had its ClientHello
  ignored and the call went silent; the new handshake now runs beside the old
  one and replaces it only once it has finished, the far end's certificate
  checked again. The lab found a ninth against FreeSWITCH, which certifies
  with RSA and could not be keyed with at all; a peer's RSA signatures are now
  verified — never made — with the `rsa` crate, and that path came after the
  review above, so it has only had its own. What the review is not is a review by a specialist outside the project, which
  the commercial licence still waits on. Until there is one, the honest
  statement is that this protocol is written from the RFCs, tested against
  itself and attacked by its own project — not by anyone independent of it.

  One limit is known and is a property of the design rather than of the code.
  A DTLS connection ends on any fatal alert, and an alert arriving before the
  keys exist cannot be authenticated, because there is nothing yet to
  authenticate it with. `MediaSession` therefore latches on the address the
  first *handshake* record arrives from and refuses records from any other —
  and, without ICE, only from the host the signalling named, since one octet
  from anywhere used to be enough to take the latch and keep the call from
  ever keying. That narrows the window to an attacker who can send from the
  far end's own address and beat its first flight. Closing it needs the
  candidate exchange of ICE, which this stack negotiates and does not assume
  (`docs/06-nat.md`) — and which is now there to be asked for: on a call whose
  checks have chosen a pair, the latch follows the pair and the agent's
  signed transaction is what says whose datagram this is. On every call that
  has not, which is every call at the default policy, the latch is still the
  whole of the answer. RTP's own latch is the one thing ICE loosens: until a
  pair is selected it follows the far end rather than holding, because the
  far end may send on any pair it has proved (RFC 8445 §12.1) and a latch
  that held refused a second of its audio. A packet moves it only after
  passing SRTP's authentication, so on a secured call nobody without the keys
  can; on a call in clear, anybody who can reach the socket before the
  selection can have a packet played, which is no more than the first packet
  of any call in clear could always do.

## The unsafe surface

`unsafe_code = "deny"` at the workspace root (`Cargo.toml:25`) is overridden
in exactly four crates, each in its own manifest: `sipral-ffi`,
`sipral-io-coreaudio`, `sipral-io-wasapi`, `sipral-io-pipewire`
(`unsafe_code = "allow"` in each crate's `[lints.rust]`). Everything else in the workspace is denied `unsafe`
outright, including the two crates that write cryptographic primitives
in-tree, SRTP and DTLS.

**Nothing unwinds across the C boundary.** `crates/sipral-ffi/src/error.rs`'s
`catch` wraps `panic::catch_unwind` once, and `guard`/`guard_quiet`/`guard_value`
build on it for the three shapes an entry point can return. The `entry!` macro
(`error.rs`) is the *only* way to declare something crossing the boundary, and
every one of its expansions runs the body through one of those wrappers before
anything reaches C — a panic becomes `SipralStatus::Panic` rather than an abort
of the host process. `scripts/check.sh` fails the build if any file outside
the macro's own module exports a symbol, so a hand-written `#[no_mangle]`
cannot skip the guard. This is also why the release profile keeps
`panic = "unwind"`: with `panic = "abort"` there is nothing for `catch_unwind`
to catch, and Cargo gives no per-crate override of that setting
(`docs/08-ffi.md`).

**A handle is checked, never dereferenced from.** `crates/sipral-ffi/src/handle.rs`
packs a 24-bit slot, a 4-bit kind, an 8-bit stack tag and a 28-bit generation
into 64 bits; nothing about a handle is ever read as an address. Looking one
up (`HandleTable::get`) checks the tag against the stack that minted it, the
kind against the table being asked, and the generation against the slot's
current one, in that order, and answers `SIPRAL_STATUS_INVALID_HANDLE` or
`SIPRAL_STATUS_STALE_HANDLE` before any slot's data is touched. A handle
forged, reused across stacks, or aimed at the wrong kind of table is refused
by construction rather than by a check somebody could forget to add at a new
call site.

**A struct crossing the boundary carries its own size.** Every `#[repr(C)]`
struct that crosses is `Versioned`: its first member is `size: usize`, set by
the caller from its own header. `declared_size` (`crates/sipral-ffi/src/versioned.rs`)
refuses anything below that struct's pinned `MIN_SIZE` — the length the struct
had in the first published header, a literal that never moves even as the
struct grows — and refuses a declared size whose extra bytes are not all
zero, rather than reading past what the linked library actually knows about.
An old binary built against a shorter struct still works; a struct read with
the wrong shape is caught at the boundary instead of read as whatever
happened to follow it in memory.

## What is not covered yet

**`sipral-media`'s DSP stages are now fuzzed, but only against garbage
input, not against a live call.** Resampling, drift correction, packet-loss
concealment, comfort noise, voice-activity detection, the in-tree G.722
and G.729 codecs, and the mixer — `crates/sipral-media/src/resample.rs`,
`drift.rs`, `plc.rs`, `comfort_noise.rs`, `vad.rs`, `g722/`, `g729/`,
`mix.rs`, and the `opus.rs` wrapper over libopus — all run on audio derived
from an RTP payload the far end chose, once a call is negotiated, and each
now has its own target under `fuzz/fuzz_targets/` (`media_resample`,
`media_plc`, `media_drift`, `media_comfort_noise`, `media_vad`,
`media_g722`, `media_g729`, `media_mix`, `media_opus`) feeding it samples,
octets and wire payloads no encoder produced. What that
buys is the same property the SIP and RTP targets buy for their own layers:
no panic, and every documented bound — a reconstructed G.722 sample inside
ITU-T G.722 §5.1's range, a resampled frame no longer than
`output_capacity` promised — held under adversarial input rather than only
under a tone a test built by hand. What it does not buy is a target that
walks a whole call: the nine targets each exercise one stage in isolation,
seeded from its own history and its own state, not from a jitter buffer
handing it packets an attacker actually sent over a negotiated codec: that
seam — RTP payload straight through the jitter buffer into the codec and
DSP chain in one target — is still open.

**`sipral-nat`.** The wire formats are fuzzed — `stun`, `turn` and `ice`
targets exist and exercise the message parsers, their accessors and the
agent's own handling of a datagram — but the state machines that act on what
those parsers decode have not had a dedicated adversarial reading.

**This stopped costing nothing.** Until the ICE seam, the answer here was that
`sipral-nat` was linked by nothing and none of it was reachable from a live
call regardless of how it was written. That is no longer true of the ICE
agent: with `IcePolicy` anything but `Off`, the agent binds the call's media
socket and `handle_datagram` runs on bytes from an unauthenticated stranger
before SRTP and before the DTLS handshake — it is now the *first* code in this
stack that adversarial input on the media path reaches. The `ice` fuzz target
exists for exactly that and has run without a crash, and the agent's own
authenticator refuses anything not signed under the short-term credential
(`stun/message.rs`, `constant_time_eq`); what has not happened is a person
reading the checklist and nomination machinery with an attacker's eye. The
default is `Off`, so a deployment that has not asked for ICE is where it was.
`IcePolicy::Lite`, on a headless build, puts the lite agent there instead: a
much smaller surface — no checklist, no timers, nothing sent but answers —
behind the same authenticator (`ice/server.rs`, which the `ice` target
reaches through the full agent), with nothing past it but a nomination. It has
no fuzz target of its own. Both roles answer every check, a stranger's
unsigned one included, so what they queue for the application to send is
held to `TRANSMIT_CEILING` (256, `crates/sipral-nat/src/ice/full/mod.rs`):
past it the answer being queued is dropped and counted, and a flood the
application is slow to drain costs 256 short answers' worth of memory rather
than whatever the flood is. A stranger's refusals stop at `REFUSAL_CEILING`,
half of that, so the flood cannot crowd out the answers to the peer's own
checks, which carry its nomination and its consent (`docs/06-nat.md`, "The
outbox").

The STUN Binding client is reachable now too, on a stack configured with
`SIPRAL_NAT_STUN`, and what it believes goes into every `Contact` and every
offer. It believes only the configured server's address and only an answer
carrying the id of a request it sent, and the ids are drawn from the media
engine's generator, the one SRTP keys come from (`docs/06-nat.md`). An
attacker on the path between this end and the server can still answer with
an address of its choosing — unauthenticated STUN has no defence against that,
and RFC 8489 §16 says so — which moves this end's `Contact` and `c=` somewhere
the attacker chose; what that buys is calls and audio that do not arrive, the
same as dropping the packets would.

The TURN client (`crates/sipral-nat/src/turn/client.rs`, 2,893 lines) is still
reachable from nothing: the agent is configured with no TURN server. That
reading has to happen before the step that adds one.

**`RawMessage::validate`'s absence from the live dispatch path**, described
above under parsing, is a gap in wiring rather than in reading: the code that
would close it already exists and is already tested, and taking it from a
test-only call to a production one is what remains.

**Everything upstream of this layer is the application's.** No identity
verification beyond source address and dialog matching exists anywhere in
this tree (above), so an application that needs to know who is really calling
— rather than merely which dialog a message claims — has to bring that itself,
the same way it has to bring TLS for the signalling transport SDES depends on.
Treating "this stack answered" as "this stack vouched for the caller" is the
mistake this document exists to prevent.
