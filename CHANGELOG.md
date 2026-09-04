<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is semantic once 1.0 exists; before that, minor versions may break.

## [Unreleased]

### Changed

- Phase 1 readiness review, nine gaps closed: WebSocket scoped to phase 2 and
  its framing corrected (one SIP message per WebSocket message, never the
  `Content-Length` framer); keepalive given a home in `EndpointConfig`; the
  `sipral-ua` call handle renamed away from the core's `CallId`; a fuzzing
  plan and a per-flow interoperability pass bar in `docs/11-testing.md`; the
  `sipral` facade crate inheriting version, licence and lints from the
  workspace; `scripts/check.sh` failing on version drift between the
  workspace and the .NET package.
- Design and licensing documents checked claim by claim against the RFC text
  and the primary sources; 20 corrections applied. The ones that change
  behaviour: the release profile no longer sets `panic = "abort"`, because the
  FFI layer has to catch unwinding at the C boundary; `sipral-ffi` and
  `sipral-io-coreaudio` now carry the `unwrap`/`expect`/`panic`/indexing lints
  they were silently missing; phase 1 explicitly includes the minimal RTP and
  G.711 slice a bidirectional call needs; `LICENSING.md` no longer implies that
  charging for a product is by itself what triggers the commercial arm. CI
  installs the toolchain from `rust-toolchain.toml` instead of pinning a second
  time in the workflow, and runs the gitleaks binary (pinned, checksum
  verified) instead of the marketplace action, which requires a paid licence
  on organisation repositories.

### Added

- Workspace skeleton: the eight crates from `docs/01-architecture.md`, each with
  its scope documented and nothing implemented.
- Design documents for phase 0: architecture, clean-room rules, signalling
  core, user agent, media, NAT, headless endpoint, FFI, RFC index, roadmap,
  testing.
- Licensing set: AGPL-3.0-only alongside a commercial arm, with `LICENSING.md`,
  `LICENSE-COMMERCIAL.md`, `TRADEMARK.md`, `AUTHORS`, `THIRD-PARTY-NOTICES.md`,
  and SPDX headers on every source file.
- `deny.toml` with a permissive-only allow-list, enforced in CI.
- `scripts/check.sh`: licence headers, provenance, published-tree language,
  internal files and captures, build, lints, tests, dependency licences,
  secrets.
- CI on Linux, macOS and Windows, plus separate licence and hygiene jobs.
- `sipral-core::msg`: the message layer's foundation. `Span`, `HeaderSlot` and
  a reusable `ParseScratch`; `Method` and `StatusCode`; `RawMessage` as a view
  over the caller's buffer; and a parser that locates the start line, the
  header fields and the body without copying any of them. Folded values are one
  slot with their interior CRLF intact, repeated headers are one slot each in
  wire order, and `Content-Length` frames the body so trailing octets in a
  datagram are ignored. Bounded by a `Limits` struct so a hostile peer cannot
  make it do unbounded work, and written so that no input reaches a panic.
  37 tests, several of them RFC 4475 cases the corpus will assert in full later.
- `sipral-core::msg::HeaderName`: the 38 header fields the stack knows, matched
  whatever their case and in either form. Fifteen compact forms, each read out
  of the RFC that defines it rather than from memory. `RawMessage` gains
  `header`, `header_values`, `header_count` and `header_names`, so asking for
  `Via` finds a `v:` line and asking for an extension is case-insensitive too.
- `sipral-core::msg::UriRef`: SIP URIs in parts, borrowed from the buffer.
  An enum rather than a struct, because only `sip:` and `sips:` have a
  hostport: a `tel:` URI and an unknown scheme are kept whole instead of being
  forced into a shape they do not have. The userinfo boundary is settled before
  parameters or headers are looked for, since `user` may contain `;` and `?`
  unescaped. Parameters and headers are walked on demand, and `unescape`
  handles `%` escapes including `%00`, leaving a stray `%` alone because the
  corpus has one in a message that is valid.
- `sipral-core::msg::lex`: the lexical rules every header value obeys, in one
  place instead of once per field. Unfolding, comma-separated values, and
  `;name=value` parameters, all of which stop at a quoted string or a `<...>`
  URI. `Contact: "Smith, John" <sip:j@x>` is one value; `qop="auth=1,auth-int"`
  is one parameter.
- `sipral-core::msg::OwnedMessage`: the same bytes and header index behind two
  `Arc`s, so a message the stack keeps costs one copy and a clone costs none.
  Bytes past the body are left behind, so a second request sharing a datagram
  is not carried along.
- `sipral-core::msg::scalar`: the fields that carry a number, and `CSeq`, which
  carries one and a method. The separator inside `CSeq` and `RAck` is `LWS`, so
  a fold between the digits and the method still reads. Overflow is two rules,
  not one: a `CSeq` that does not fit in 32 bits is refused, while an `Expires`
  parses and reports that it did not fit, because the RFC lets an element fall
  back to its default there. Nothing is truncated, so a hundred-digit `Expires`
  cannot become a plausible small number.
- `sipral-core::msg::ViaRef`: the field that decides where a response goes.
  `SLASH` and `COLON` absorb surrounding whitespace, so the two slashes are
  located before anything else; `received` carries an IPv6 address without
  brackets, unlike everywhere else, and accepts them anyway because they are
  sent; `ttl` is `1*3DIGIT`, so `;ttl=1234` is not a ttl at all; `rport` has
  three states and `;rport=` is none of them. A `Via` with no branch is an RFC
  2543 peer to be matched per §17.2.3, not a malformed header.
- `sipral-core::msg::NameAddrRef`: `From`, `To` and `Contact`. The angle
  brackets decide who owns the parameters — inside them `;transport=tcp` is on
  the URI, outside them it is on the header field — and RFC 4475 `cparam01` and
  `cparam02` are one address written both ways to catch a stack that cannot
  tell. Whitespace lives outside the brackets, so `< sip:a@b >` is refused; a
  display name is a token run or a quoted string and nothing else, so
  `Bell, Alexander <sip:...>` is refused while `caller<sip:...>` is accepted as
  the documented grammar defect it is; an unterminated quoted string is refused
  rather than guessed at. `Contact: *` is the whole field or nothing.
  `RawMessage` gains `from`, `to`, `contact` and `field_values`, the last
  walking a comma-separated field across its lines and its commas alike.
- `sipral-core::msg::RouteRef`: `Route` and `Record-Route`. A route entry is a
  `name-addr` with no bracket-less alternative, so `Route: sip:p1;lr` is
  refused rather than guessed at — without the `>` there is nothing to say
  where the URI ends. `is_loose_route()` reads `;lr` on the URI and not on the
  header field, because `<sip:p1>;lr` is a strict router carrying a parameter
  that happens to be spelled the same, and getting that backwards sends the
  request to a strict router with a Request-URI it cannot use. Entries come
  back in wire order, never sorted or deduplicated.
- `sipral-core::msg::ChallengeRef` and `CredentialsRef`: digest challenges and
  credentials, as two types rather than one, because `qop` is a quoted comma
  list in a challenge and a bare token in credentials and the RFC's own worked
  example writes both. `realm`, `nonce`, `cnonce`, `username` and `opaque` come
  back unescaped; `uri` and `response` come back exactly as written, since
  neither is a `quoted-string` and a Request-URI is no place to resolve
  backslashes. `response` has no fixed length, per RFC 8760. Each header line
  is one value: RFC 3261 §20.7 and §20.28 exempt these fields from
  comma-joining, and several challenges are several lines in preference order.
- `sipral-core::msg::TokenIter` and `MediaTypeRef`: `Require`, `Proxy-Require`,
  `Supported`, `Unsupported`, `Content-Encoding`, `Accept`, `Allow` and
  `Content-Type`. Option tags are matched without case; methods are not,
  because the six RFC 3261 verbs are fixed-case literals in the grammar and
  `Allow: invite` is an extension method that happens to be spelled like one
  of them.
- `sipral-core::msg::RequestBuilder` and `ResponseBuilder`: writing a message
  out. Deterministic — same inputs, same bytes, whatever order the setters were
  called in — because a retransmission has to be the identical datagram and a
  byte-comparing test is worth nothing otherwise. `Via` goes first, then the
  routing and dialog fields, then whatever else the caller added, then the
  body's two fields; `Content-Length` is always written, since a stream
  transport has no other way to find the end of a message. A response copies
  what RFC 3261 §8.2.6.2 says must be equal, adds a `To` tag only when the
  request carried none, and copies `Record-Route` only when asked, because
  §12.1.1 requires that of a response establishing a dialog and only the
  caller knows whether this is one. No value may hold CR or LF: a header value
  goes out on one line, and a caller's data with a line break in it would
  otherwise write headers of its own.
- `sipral-core::msg::StreamFramer`: reassembling TCP and TLS into messages, and
  the one place in the receive path that copies. A message without
  `Content-Length` is refused rather than read to the end of the buffer, since
  RFC 3261 §18.3 makes the field mandatory on a stream and guessing would
  swallow whatever followed. Keep-alives (RFC 5626 §4.4.1) are skipped between
  messages and counted, so the connection's owner can send the single CRLF a
  double CRLF is owed. Work is bounded per byte received rather than per call:
  a peer feeding one byte at a time cannot make reassembly quadratic.
- `RawMessage::validate`: the question a UAS asks before answering — is this a
  message the stack can act on, or one that draws a 400? A message can be
  framed correctly and still carry a `From` whose display name is not one, a
  `CSeq` naming a different method than the start line, or a `Date` in a zone
  nobody can read. The parser has no business refusing those, since it does not
  know which fields the caller will read, so the question is asked once, here,
  by whoever is about to answer.
- `SipDate` and `RawMessage::date`: RFC 3261 §20.17, which narrows RFC 1123 to
  GMT and says outright that the names are case-sensitive. `EST` is not a zone
  this reads, and neither is `UT`, `UTC` or `gmt`.
- `sipral-core::transaction`: the handles the transaction layer is addressed
  by. Typed by machine, so answering a PRACK with an INVITE server transaction
  handle is a compile error rather than a runtime one, and the guarantee
  survives into C as one struct per kind. Generational, so a handle issued
  before a transaction died never answers to whoever took its slot — which is
  what a late retransmission is holding. The four state enums carry RFC 6026's
  `Accepted` on both INVITE machines.
- The INVITE client transaction (RFC 3261 §17.1.1, RFC 6026 §7.2), and the ACK
  a client transaction builds for a final response that is not a 2xx. A 2xx
  does not end the transaction: the machine moves to `Accepted` and stays there
  for timer M, so a retransmitted 2xx or one from another fork is passed up
  rather than dropped as a stray. A provisional response stops both timer A and
  timer B, because how long to wait for a ringing phone is the user's decision.
  A retransmitted final response re-sends the ACK and is not reported twice.
  On UDP the request goes out seven times in 64·T1, which is what the RFC says
  that number is for.
- The non-INVITE client transaction (RFC 3261 §17.1.2), which is what REGISTER,
  OPTIONS, BYE and MESSAGE run on. Retransmissions cap at T2 rather than
  doubling forever, and a provisional response does not stop them — it moves
  the machine to `Proceeding`, where the interval is T2 flat and timer F still
  ends the transaction. Only an INVITE gets to ring indefinitely.
- The two server transactions (RFC 3261 §17.2, RFC 6026 §8.1). The INVITE one
  sends a 100 Trying at once — the transaction layer never knows whether the
  user will answer within 200 ms, and a redundant 100 costs one datagram while
  a missing one costs six retransmitted INVITEs. A 2xx puts it in `Accepted`,
  where retransmitted INVITEs are absorbed rather than answered again and an
  arriving ACK is passed up rather than swallowed, because after a 2xx the ACK
  belongs to the dialog. A non-2xx final response is retransmitted by timer G,
  but only on an unreliable transport. The non-INVITE one sends nothing until
  the user says so: in `Trying` a retransmitted request is discarded, since
  inventing a response the user never wrote is worse than silence.
- Message matching (RFC 3261 §17.1.3 and §17.2.3). A response finds its client
  transaction by branch and `CSeq` method — the method matters because a CANCEL
  borrows the branch of the request it cancels while being a transaction of its
  own. A request finds its server transaction by branch, the `Via`'s sent-by
  and the method, with an ACK keyed as the INVITE it answers. A peer without
  the magic cookie is matched the pre-3261 way instead, on the Request-URI,
  From tag, `Call-ID`, `CSeq` number and top `Via`.
- CANCEL (RFC 3261 §9.1): built to look exactly like the INVITE it cancels so
  the two can be paired, with `Route` copied for stateless proxies and
  `Require`/`Proxy-Require` deliberately dropped. Asking to cancel is always
  accepted while the transaction is open: a CANCEL may not be sent before a
  provisional response has arrived — the server could otherwise receive it
  before the INVITE and have nothing to cancel — so one asked for too early is
  held and released at the first provisional rather than refused.
- Dialogs (RFC 3261 §12): route set, remote target, the two sequence spaces,
  the `secure` flag and both ways of opening one — from the response to a
  request we sent, and from a request we are answering. The route set is
  reversed for the caller and kept in order for the callee, because the two
  ends face opposite ways down the same path, and it is built from the bytes as
  they arrived so that every URI parameter survives. Requests come out through
  §12.2.1.1, including the strict-router rewrite for proxies that predate loose
  routing: the request is addressed to the first hop and the real target is
  pushed to the end of the `Route`, where a loose router lifts it back. ACK and
  CANCEL are refused there — their number belongs to the request they answer.
  The remote target moves only for a re-INVITE or an UPDATE (RFC 3311 §5.1),
  never for an ACK; a request whose `CSeq` runs backwards is answered 500 and
  changes nothing.
- Digest authentication (RFC 3261 §22, RFC 8760): MD5, MD5-sess, SHA-256,
  SHA-256-sess, SHA-512-256 and SHA-512-256-sess, with `qop=auth` and the
  counter that makes a captured response useless a second time. The three hash
  functions are written out here, because the crate has no dependencies, and
  each is checked against published digests — including the SHA-256 of the
  empty string that RFC 8760 §2.6 prints — before anything is built on it.
  `AuthCache` keeps a challenge per protection domain so a later request can
  carry credentials without a round trip, answers the topmost challenge it
  understands per realm, keeps the 401 and 407 spaces apart, and refuses to
  answer the same nonce twice after a refusal: §22.1 forbids re-attempting
  credentials that were just rejected, and repeating them only locks the
  account. A `-sess` algorithm without `qop` is treated as unanswerable rather
  than guessed at, which is what §22.4 rule 8 leaves. The password lives in a
  `Secret` with no `Debug` and no way out of its module, overwritten on drop as
  far as safe Rust can promise.
- SDP (RFC 4566) and offer/answer (RFC 3264). A description that is read and
  written back comes out as it went in, down to the lines the stack has no use
  for — an SDP body travels through a call inside messages that get forwarded,
  so quietly dropping what is not understood breaks the next extension somebody
  adds. Ordering is enforced the way §5 fixes it, and a type letter that is not
  one of the fourteen refuses the whole description rather than the line, which
  is what §5 asks for. `answer()` builds the answer from the offer: the same
  number of streams in the same order, the same `t=` line, the payload mappings
  the offer defined, and a direction narrowed to what the offer allows — an
  offer of `sendonly` can only be answered `recvonly` or `inactive`. Which
  codecs to keep and which streams to take arrive as arguments; there is no
  policy here. The RFC 3264 §10.1 exchange is a test, byte for byte, and a
  fourth fuzz target asserts that writing a description out and reading it back
  yields the same description.
- Forking and the ACK for a 2xx (RFC 3261 §13.2.2). One INVITE can produce
  several dialogs — a proxy rings the desk phone, the mobile and the voicemail,
  and each branch that answers is told apart by its `To` tag. `DialogSet` keeps
  them all and chooses between none of them: which fork to keep is policy, and
  policy does not live in the core. A non-2xx final ends every dialog still
  early and leaves an already confirmed one alone; a 2xx arriving after that is
  still taken, because dropping it would leave a call standing at the far end
  with nobody able to hang it up. The 2xx confirming an early dialog recomputes
  its route set, which RFC 2543 compatibility requires and which nothing else
  in a dialog's life does. The ACK for a 2xx belongs to the dialog rather than
  the transaction: the caller builds it once, since only the caller knows
  whether there is an answer to put in it, and every retransmitted 2xx after
  that is answered from the stored bytes.
- `Uri`, a URI that outlives the buffer it arrived in: the text held once in an
  `Arc<str>` with the parts as offsets into it, so borrowing the parsed form
  back is free and a clone shares the bytes. It carries RFC 3261 §19.1.4
  comparison as `equivalent()` rather than `PartialEq`, because §19.1.4
  equivalence is not transitive and the RFC says so itself. `Tag` and `CallId`
  compare the way the RFC compares them, which is not the same way: byte for
  byte for a `Call-ID` (§20.8), without case for a tag, which is a token
  (§7.3.1).
- `TimerConfig` and the timer schedule: T1, T2 and T4 from RFC 3261 Table 4,
  with every other timer derived from them, and a schedule that answers "when
  do I have to come back" through a shared reference. Nothing reads a clock —
  the caller says what time it is — so a timer diagram from §17 is an ordinary
  test that runs in microseconds. The absorbing timers are zero on a reliable
  transport, because nothing retransmits there.
- Fuzzing under `fuzz/`: three libFuzzer targets over the parser and every
  typed accessor, the stream framer fed at arbitrary read sizes, and the
  builder fed arbitrary bytes as header values to prove a caller's data cannot
  become structure. Outside the workspace with its own lockfile and nightly
  pin, and covered by `cargo deny` too.
- The RFC 4475 corpus is now a test, and it passes: all 49 messages behave as
  `fixtures/rfc4475/manifest.toml` says, and every valid one round trips byte
  for byte. Three messages moved from `semantic` to `reject` — `insuf`,
  `multi01` and `mcl01` sit in the application group but their RFC sections ask
  for a 400 outright — so the split is 13 parse, 22 reject, 14 semantic.
- `StatusCode::reason`: the reason phrases RFC 3261 §21 registers, plus 422
  from RFC 4028, so nobody has to invent one.
- `RawMessage::transaction_lookup_method`: the key §17 matches on. An ACK
  answers INVITE, since the INVITE server transaction absorbs the ACK to a
  non-2xx and an ACK to a 2xx finds nothing under that key and belongs to the
  dialog; a response answers with its `CSeq` method, having none of its own.
- `crates/sipral`: the facade crate, for now a name reservation on crates.io
  that exports a version constant. The only crate with `publish = true`.
- `bindings/dotnet/Sipral`: the .NET package, for now a name reservation
  published to NuGet as `Sipral` 0.0.1.
- `docs/12-core-api.md`: the public surface of `sipral-core` as signatures,
  merged from four independent proposals scored by three reviewers, with
  register, call, CANCEL-race and fork walkthroughs, a fake-clock test, the C
  projection, and a record of what was rejected and why. Adds the RFC 6026
  `Accepted` state to both INVITE machines, which every proposal had missed on
  the client side.
- RFC 4475 torture corpus under `fixtures/rfc4475/`: the 49 messages decoded
  byte for byte from the archive in Appendix A, laid out by RFC section, with
  a manifest carrying section, title, expected outcome and SHA-256 per file.
  `scripts/check.sh` verifies the hashes so line-ending normalisation cannot
  silently alter a test.
- `SECURITY.md`, pointing at GitHub private vulnerability reporting, and an
  issue template for commercial licence enquiries. No email address appears
  anywhere in the repository, by design: `scripts/check.sh` fails on one, in a
  file or in commit metadata.
