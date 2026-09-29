<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# sipral-core: the public API

This is `sipral-core`'s public surface as implemented. It was chosen from
four independent proposals scored by three reviewers with different concerns
(implementer, binding author, protocol reviewer), and then merged by hand.
What was taken from where, and what was rejected, is at the end, so that the
next person to disagree with a decision can see what it was weighed against.

Anything the code changes is changed here in the same commit.

## The contract in five calls

```rust
impl Endpoint {
    pub fn receive(&mut self, input: Input<'_>, now: Instant) -> Result<(), ReceiveError>;
    pub fn handle_timeout(&mut self, now: Instant);
    pub fn poll_transmit(&mut self) -> Option<Transmit>;
    pub fn poll_event(&mut self) -> Option<Event>;
    pub fn poll_timeout(&self) -> Option<Instant>;
}
```

Bytes and time in, bytes and events out. `handle_timeout` is separate from
`receive` because a caller waking on a bare deadline has no bytes in hand, and
a fake-clock test reads more clearly when advancing time is its own call. The
caller drains `poll_transmit` and `poll_event` to empty after every call that
can produce output, and comes back by `poll_timeout` even if nothing arrives.

Everything the endpoint hands out is a `Copy` handle with no lifetime.
Everything the caller hands in that must be retained is already owned.

## Handles

```rust
/// Slot plus generation. A handle into a slot that has since been reused for
/// something else never compares equal to the new occupant.
struct Raw { slot: u32, generation: u32 }

pub trait TransactionKind: sealed::Sealed + 'static {
    const ROLE: Role;
    type State: Copy + Eq + fmt::Debug;
    const NAME: &'static str;
}
pub enum InviteClient {}      // RFC 3261 §17.1.1: timers A, B, D; RFC 6026: M
pub enum NonInviteClient {}   // §17.1.2: E, F, K
pub enum InviteServer {}      // §17.2.1: G, H, I; RFC 6026: L
pub enum NonInviteServer {}   // §17.2.2: J

pub struct TransactionId<K: TransactionKind> { raw: Raw, _kind: PhantomData<fn() -> K> }

pub enum AnyTransactionId {
    InviteClient(TransactionId<InviteClient>),
    NonInviteClient(TransactionId<NonInviteClient>),
    InviteServer(TransactionId<InviteServer>),
    NonInviteServer(TransactionId<NonInviteServer>),
}

/// Call-ID plus both tags (RFC 3261 §12). Not parameterised: which transaction
/// created a dialog is not part of its identity.
pub struct DialogId { raw: Raw }

/// One reliable provisional response (RFC 3262) awaiting PRACK. It carries the
/// dialog it belongs to, so a PRACK cannot be aimed at the wrong dialog.
pub struct ProvisionalResponseId { dialog: DialogId, raw: Raw }
impl ProvisionalResponseId {
    pub fn dialog(&self) -> DialogId;
    pub fn rseq(&self) -> u32;
}

/// Caller-assigned. The endpoint never opens a socket and never owns one.
/// Lives in the endpoint module rather than with the transaction handles: a
/// transport outlives every transaction that ever used it.
pub struct TransportId(pub u32);
```

Typing the transaction handle by machine kind means "respond to a PRACK using
an INVITE server transaction handle" is a compile error rather than a runtime
`Err`. That guarantee holds for Rust callers of `sipral-core`; the C ABI does
not expose transaction handles. Generational identity means a stale handle
yields a typed error, never a different transaction.

## State machines

```rust
pub enum InviteClientState    { Calling, Proceeding, Accepted, Completed, Terminated }
pub enum NonInviteClientState { Trying, Proceeding, Completed, Terminated }
pub enum InviteServerState    { Proceeding, Accepted, Completed, Confirmed, Terminated }
pub enum NonInviteServerState { Trying, Proceeding, Completed, Terminated }
```

`Accepted` on both INVITE machines is RFC 6026's correction to RFC 3261: a 2xx
does not terminate the INVITE transaction outright. The client transaction sits
in `Accepted` for timer M (64·T1) and passes every further 2xx, including those
from other forks, up to the dialog layer instead of treating them as strays.
The server transaction sits in `Accepted` for timer L and absorbs
retransmissions of the INVITE, and over UDP it sends the 2xx again on timer G's
schedule — T1 doubling up to T2 — until the ACK arrives, which §13.3.1.4 asks
of the layer above and which the endpoint does on its behalf. The ACK is sent
under a branch of its own, so the dialog that takes it tells the transaction.
Three reviewers flagged the absence of this
state independently; it is the corner that produces "the call connected but the
app thinks it failed" in the field.

```rust
pub struct TimerConfig { pub t1: Duration, pub t2: Duration, pub t4: Duration }
impl Default for TimerConfig {}   // 500 ms, 4 s, 5 s, RFC 3261 §17.1.1.1
impl TimerConfig {
    // `t1` or `t2` zero makes timer A, E or G re-arm at the instant it
    // fired; `Endpoint::new` refuses a config that fails this.
    pub fn validate(&self) -> Result<(), TimerConfigError>;
}
// the second is `EndpointConfig::keepalive_interval` at zero, which
// `Endpoint::new` refuses for the same reason
pub enum TimerConfigError { Unarmable, KeepaliveUnarmable }
```

## Messages: zero-copy with one copy seam

```rust
pub struct Span { pub start: u32, pub end: u32 }

/// A value folded across lines (RFC 3261 §7.3.1) is one slot whose value span
/// covers the continuation lines, interior CRLF included; unfolding is the
/// typed accessors' job. A header repeated on several lines is one slot per
/// line, in wire order.
pub struct HeaderSlot { pub name: Span, pub value: Span }

/// Reused across parses. Cleared, not freed.
pub struct ParseScratch { /* Vec<HeaderSlot> */ }

pub enum ParseMode { Lenient, Strict }

/// Bounds that stop a hostile peer from making the parser do unbounded work.
pub struct Limits {
    pub max_message_bytes: u32,       // 65 535
    pub max_headers: u16,             // 128
    pub max_header_value_bytes: u32,  // 16 384
}

pub fn parse<'a>(buf: &'a [u8], scratch: &'a mut ParseScratch, mode: ParseMode)
    -> Result<RawMessage<'a>, ParseError>;
pub fn parse_with_limits<'a>(buf: &'a [u8], scratch: &'a mut ParseScratch, mode: ParseMode, limits: Limits)
    -> Result<RawMessage<'a>, ParseError>;

/// A view over the caller's buffer. Every accessor locates and validates a
/// span; none allocates. Never outlives the call that produced it.
pub struct RawMessage<'a> { /* buf, start-line spans, &'a [HeaderSlot], body span */ }

impl<'a> RawMessage<'a> {
    pub fn kind(&self) -> MessageKind<'a>;
    pub fn method(&self) -> Option<Method<'a>>;
    pub fn status(&self) -> Option<StatusCode>;
    pub fn request_uri(&self) -> Option<Result<UriRef<'a>, UriError>>;
    pub fn request_uri_bytes(&self) -> Option<&'a [u8]>;
    pub fn body(&self) -> &'a [u8];
    pub fn header(&self, name: HeaderName<'_>) -> Option<&'a [u8]>;
    pub fn header_values<'n>(&self, name: HeaderName<'n>) -> impl Iterator<Item = &'a [u8]>;
    pub fn header_count(&self, name: HeaderName<'_>) -> usize;
    pub fn header_names(&self) -> impl Iterator<Item = HeaderName<'a>>;
    pub fn raw_headers(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])>;
    pub fn header_slots(&self) -> &'a [HeaderSlot];

    /// Values of a comma-separated field: line by line, and within each line
    /// comma by comma, with quotes and `<...>` respected. RFC 3261 §7.3.1
    /// makes the two spellings the same message.
    pub fn field_values(&self, name: HeaderName<'a>) -> FieldValues<'a>;

    pub fn via(&self) -> impl Iterator<Item = Result<ViaRef<'a>, HeaderError>>;
    pub fn top_via(&self) -> Result<ViaRef<'a>, HeaderError>;
    pub fn call_id(&self) -> Result<&'a [u8], HeaderError>;
    pub fn from(&self) -> Result<NameAddrRef<'a>, HeaderError>;
    pub fn to(&self) -> Result<NameAddrRef<'a>, HeaderError>;
    pub fn cseq(&self) -> Result<CSeq<'a>, HeaderError>;
    pub fn contact(&self) -> Result<Contacts<'a>, HeaderError>;
    pub fn route(&self) -> RouteIter<'a>;
    pub fn record_route(&self) -> RouteIter<'a>;
    pub fn max_forwards(&self) -> Result<Digits, HeaderError>;
    pub fn content_length(&self) -> Result<Digits, HeaderError>;
    pub fn content_type(&self) -> Result<MediaTypeRef<'a>, HeaderError>;
    pub fn expires(&self) -> Result<Digits, HeaderError>;
    pub fn rseq(&self) -> Result<u32, HeaderError>;
    pub fn rack(&self) -> Result<RAck<'a>, HeaderError>;
    pub fn date(&self) -> Result<SipDate, HeaderError>;
    pub fn require(&self) -> TokenIter<'a>;
    pub fn proxy_require(&self) -> TokenIter<'a>;
    pub fn supported(&self) -> TokenIter<'a>;
    pub fn unsupported(&self) -> TokenIter<'a>;
    pub fn content_encoding(&self) -> TokenIter<'a>;
    pub fn accept(&self) -> TokenIter<'a>;
    pub fn allow(&self) -> impl Iterator<Item = Method<'a>>;

    /// One line each: RFC 3261 §20.7 and §20.28 exempt these from
    /// comma-joining, and RFC 8760 §2.3 sends several algorithms as several
    /// lines in preference order. WWW/Proxy are separate credential spaces.
    pub fn www_authenticate(&self) -> impl Iterator<Item = Result<ChallengeRef<'a>, HeaderError>>;
    pub fn proxy_authenticate(&self) -> impl Iterator<Item = Result<ChallengeRef<'a>, HeaderError>>;
    pub fn authorization(&self) -> impl Iterator<Item = Result<CredentialsRef<'a>, HeaderError>>;
    pub fn proxy_authorization(&self) -> impl Iterator<Item = Result<CredentialsRef<'a>, HeaderError>>;

    /// One value of a field that may appear only once. `Missing` when it is
    /// absent, `UnexpectedRepeat` when it is not; RFC 4475 §3.3.8 is a message
    /// that repeats `Call-ID`, and picking one value silently is how a stack
    /// ends up disagreeing with the proxy in front of it.
    pub fn single(&self, name: HeaderName<'_>) -> Result<&'a [u8], HeaderError>;

    /// Whether this is a message the stack can act on, or one that draws a
    /// 400. A message can be framed correctly and still be unusable, and the
    /// parser has no business deciding: it does not know which fields the
    /// caller will read.
    pub fn validate(&self) -> Result<(), Invalid>;

    /// The method the transaction table is keyed on for this inbound message.
    /// Equal to the start line's method except for an ACK to a non-2xx, which
    /// maps to INVITE because the INVITE server transaction absorbs it
    /// (RFC 3261 §17.2.1).
    pub fn transaction_lookup_method(&self) -> Method<'a>;

    /// The one place a view becomes something the stack can keep: the bytes
    /// are copied once into a refcounted buffer and the header index rebuilt
    /// over it. Nothing else in the receive path copies.
    pub fn to_owned(&self) -> OwnedMessage;
}

/// Same shape as `RawMessage` over an `Arc<[u8]>`. Every accessor works
/// unchanged through `as_raw()`. Retransmission clones the `Arc`, never the
/// bytes.
pub struct OwnedMessage { /* Arc<[u8]>, start line, Vec<HeaderSlot>, body span */ }
impl OwnedMessage {
    pub fn as_raw(&self) -> RawMessage<'_>;
    pub fn bytes(&self) -> Arc<[u8]>;
}
```

A URI is an enum, not a struct, because only `sip:` and `sips:` have the
`userinfo hostport parameters headers` shape:

```rust
pub enum UriRef<'a> {
    Sip(SipUriRef<'a>),
    /// tel:, or a scheme we have never heard of. Kept whole.
    Other { scheme: UriScheme<'a>, opaque: &'a str },
}

pub struct SipUriRef<'a> {
    pub scheme: UriScheme<'a>,   // Sip or Sips
    pub user: Option<&'a str>,   // still escaped
    pub password: Option<&'a str>,
    pub host: HostRef<'a>,       // Name, Ipv4 or Ipv6
    pub port: Option<u16>,
    // params and headers kept raw, walked on demand
}

pub fn unescape(bytes: &[u8]) -> Cow<'_, [u8]>;
```

`tel:+1-201-555-0123` has no host, and RFC 4475 §3.3.2 and §3.3.4 are
well-formed messages carrying schemes a parser has no business refusing.
Forcing either into a hostport is how a stack ends up rejecting traffic it
should have passed upward.

The userinfo boundary is found before anything else, because `user` may
contain `;` and `?` unescaped (RFC 3261 §25.1 `user-unreserved`). In
`sip:user;par=u%40example.net@example.com` the user is
`user;par=u%40example.net` and the host is `example.com`; splitting on the
first `;` gets both wrong. That URI is in the corpus for exactly this reason.

What a URI may not hold is refused before any of that: a space, a control
byte, `"`, `<` or `>`, unescaped (`UriError::IllegalByte`). RFC 3261 §19.1.2
has them escaped, and every URI kept from a peer — a remote target, a route, a
`Refer-To` target — is written into another message later, where each of those
bytes ends something early: the Request-URI, the header line, the brackets of
a `name-addr`, or the quoted string a `"` opens. Refusing them once at the
parser is what lets every writer put a kept URI between `<` and `>` as it is.
Other bytes the grammar excludes but that shape nothing, such as `#` or
non-ASCII, are still accepted.

An address is the URI plus what surrounds it, and the angle brackets are the
part that carries meaning:

```rust
pub struct NameAddrRef<'a> {
    // display name, URI and header parameters, all borrowed
}

impl<'a> NameAddrRef<'a> {
    pub fn parse(value: &'a [u8]) -> Result<Self, HeaderError>;
    pub fn display_name(&self) -> Option<Cow<'a, [u8]>>;   // unfolded, unquoted
    pub fn display_name_raw(&self) -> Option<&'a [u8]>;
    pub fn uri(&self) -> UriRef<'a>;
    pub fn uri_bytes(&self) -> &'a [u8];
    pub fn is_name_addr(&self) -> bool;                    // came in <...>
    pub fn params(&self) -> Params<'a>;                    // header's, never the URI's
    pub fn tag(&self) -> Option<Cow<'a, [u8]>>;
    pub fn expires(&self) -> Result<Option<Digits>, HeaderError>;
    pub fn q(&self) -> Result<Option<u16>, HeaderError>;   // thousandths: 0.7 is 700
}

pub enum Contacts<'a> {
    Star,                       // Contact: *
    Addrs(ContactIter<'a>),
}
```

With brackets, `;transport=tcp` before the `>` belongs to the URI; without
them the same text is a parameter of the header field (RFC 3261 §20.10). RFC
4475 `cparam01` and `cparam02` are one address written both ways, and
`is_name_addr()` is how a caller tells which object to ask. The whitespace
lives outside the brackets — `LAQUOT` is `SWS "<"` — so `< sip:a@b >` is
refused, which is all of RFC 4475 §3.1.2.14.

`q` is thousandths rather than a float because `qvalue` is at most three
decimals and at most 1.0: every legal value is exact, and nothing rounds.

`Route` and `Record-Route` reuse that address, with two rules of their own:

```rust
pub struct RouteRef<'a> { /* a NameAddrRef that had to be bracketed */ }

impl<'a> RouteRef<'a> {
    pub fn parse(value: &'a [u8]) -> Result<Self, HeaderError>;
    pub fn addr(&self) -> NameAddrRef<'a>;
    pub fn uri(&self) -> UriRef<'a>;
    pub fn is_loose_route(&self) -> bool;   // ;lr on the URI, not on the field
    pub fn params(&self) -> Params<'a>;     // rr-param
}
```

`route-param` is `name-addr`, with no bracket-less alternative, so
`Route: sip:p1.example.com;lr` is refused rather than guessed at. And `;lr`
counts only inside the brackets: `<sip:p1.example.com>;lr` is a *strict*
router carrying a header parameter that happens to be spelled `lr`, which is
the branch §12.2.1.1 and §16.6 take. Entries come back in wire order, never
sorted or deduplicated — §7.3.1 gives three `Route` rows and calls the same
three in another order "valid but not equivalent".

Digest challenges and credentials are two types, not one:

```rust
pub struct ChallengeRef<'a> { /* WWW-Authenticate, Proxy-Authenticate */ }
pub struct CredentialsRef<'a> { /* Authorization, Proxy-Authorization */ }
```

They share a scheme and a comma-separated parameter list, and differ where it
matters. `qop` is a quoted comma list in a challenge and one bare token in
credentials, so `ChallengeRef::qop` iterates and `CredentialsRef::qop` does
not. `realm`, `nonce`, `cnonce`, `username` and `opaque` are `quoted-string`
and come back unescaped; `uri` and `response` are quoted without being
`quoted-string` (§22.4) and come back exactly as written, because a
Request-URI is not a place to resolve backslashes. `response` has no fixed
length — RFC 8760 §2.7 replaced `32LHEX` with `*LHEX` so SHA-256 fits, and
allows an empty value before the first challenge.

A parameter that the grammar names twice — once typed, once through the
`auth-param` catch-all — parses either way, and the typed accessor is what
objects: `nc=0000001` is not `8LHEX` but is a good token, so the field parses
and `CredentialsRef::nc` returns `Malformed`. Rejecting the message there is
a policy RFC 3261 does not ask for.

Numbers are `Digits { value: Option<u32>, written: usize }` rather than a bare
`u32`, because a field of legal digits too large for 32 bits is not the same
as a malformed one. `CSeq` refuses it (RFC 3261 §8.1.1.5 requires 32 bits, and
RFC 4475 §3.1.2.4 wants a 400); `Expires` parses and reports that it did not
fit, since §20 lets an element fall back to its default. Truncating would turn
RFC 4475 `scalar02`'s hundred-digit `Expires` into a plausible small number.

The borrowed/owned pairs follow one pattern: `UriRef<'a>` / `Uri`, and the
tags and `Call-ID` a dialog is named by as `Tag` and `CallId`. An owned form
appears when something has to keep the value past the buffer it arrived in,
not before — that is why the list is shorter than the one this document
carried while it was still on paper.

`Uri` holds the text once, in an `Arc<str>`, and records the parts as offsets
into it: borrowing the parsed form back out is free and cannot fail, and a
clone shares the text, so a route set costs one allocation per hop for the
life of the call. It has no `PartialEq`. "Same bytes" and "same resource" are
different questions, `==` can only answer one, and the second is not even
transitive — RFC 3261 §19.1.4 says so itself, with a URI equivalent to both
itself plus `;security=on` and itself plus `;security=off` while those two are
not equivalent to each other. So `as_str()` compares bytes and `equivalent()`
applies §19.1.4.

`Tag` and `CallId` are compared the way the RFC compares them, which is not
the same way: a `Call-ID` is "case-sensitive and ... simply compared
byte-by-byte" (§20.8), while a tag is a token and "Tokens are always
case-insensitive" (§7.3.1). `Tag` therefore hashes on one case, so a peer that
echoes our tag back in different case still lands in the same dialog.

A tag has to be a token to be read at all: `RawMessage::from` and
`RawMessage::to` refuse one that is not as a malformed field. The dialog writes
the remote tag back after `;tag=` on every request it sends, so a quoted value
holding a `;`, or an unquoted one running on to a comma, would come back out as
parameters or an address the peer added. A quoted token, `tag="a1"`, is not
the grammar either, but it reads as the one value it holds and is kept.

```rust
pub enum Method<'a> {
    Invite, Ack, Bye, Cancel, Options, Register, Prack, Subscribe, Notify,
    Refer, Info, Update, Message, Publish, Extension(&'a str),
}

pub enum HeaderName<'a> {
    Accept, AcceptContact, Allow, AllowEvents, Authorization, CallId, Contact,
    ContentEncoding, ContentLength, ContentType, CSeq, Date, Event, Expires,
    From, Identity, MaxForwards, MinExpires, MinSe, ProxyAuthenticate,
    ProxyAuthorization, ProxyRequire, RAck, RecordRoute, ReferTo, ReferredBy,
    RejectContact, Replaces, RequestDisposition, Require, RetryAfter, Route,
    RSeq, SessionExpires, Subject, SubscriptionState, Supported, To,
    Unsupported, UserAgent, Via, Warning, WwwAuthenticate,
    Extension(&'a str),
}
// Equality is ASCII case-insensitive and treats a compact form as the field
// it abbreviates, so `Via`, `via` and `v` are one value. Nineteen fields have
// one: i m e l c f t v k s (RFC 3261 §7.3.3), u and o (RFC 6665 §8.2),
// r (RFC 3515), b (RFC 3892), x (RFC 4028), a j and d (RFC 3841 §12), y
// (RFC 8224 §13.1). `Extension` compares case-insensitively too, and keeps
// the spelling it arrived with.
//
// `HeaderName::KNOWN` lists every recognised field, so a test can assert that
// the long form, the compact form and the table cannot drift apart.

// The sent-protocol is three open tokens, not an enum: protocol-name and
// protocol-version are `token` in the grammar and other-transport is an
// extension point RFC 4475 `transports` exercises.
pub struct ViaRef<'a> {
    pub protocol_name: &'a str,
    pub protocol_version: &'a str,
    pub transport: &'a str,
    pub host: HostRef<'a>,
    pub port: Option<u16>,
}

impl<'a> ViaRef<'a> {
    pub fn branch(&self) -> Option<Cow<'a, [u8]>>;
    pub fn has_magic_cookie(&self) -> bool;
    pub fn received(&self) -> Option<IpAddr>;          // bare IPv6 here, unlike sent-by
    pub fn rport(&self) -> Result<Rport, HeaderError>;
    pub fn ttl(&self) -> Result<Option<u8>, HeaderError>;
    pub fn maddr(&self) -> Option<Cow<'a, [u8]>>;
    pub fn params(&self) -> Params<'a>;
}

/// RFC 3581. `;rport` asks, `;rport=n` answers, and `;rport=` is neither.
pub enum Rport { Absent, Requested, Given(u16) }

pub struct RequestBuilder<'a> { /* borrowed inputs, copied once at build */ }
impl<'a> RequestBuilder<'a> {
    pub fn new(method: Method<'a>, request_uri: &'a [u8]) -> Self;
    pub fn via(self, value: &'a [u8]) -> Self;        // again for another, topmost first
    pub fn from(self, value: &'a [u8]) -> Self;
    pub fn to(self, value: &'a [u8]) -> Self;
    pub fn call_id(self, value: &'a [u8]) -> Self;
    pub fn cseq(self, seq: u32) -> Self;              // method taken from the request
    pub fn max_forwards(self, n: u32) -> Self;
    pub fn contact(self, value: &'a [u8]) -> Self;
    pub fn route(self, value: &'a [u8]) -> Self;      // again for the next hop, in order
    pub fn header(self, name: HeaderName<'a>, value: &'a [u8]) -> Self;
    pub fn body(self, content_type: &'a [u8], body: &'a [u8]) -> Self;
    pub fn build(self) -> Result<OwnedMessage, BuildError>;
}

pub struct ResponseBuilder<'a> { /* seeded from the request per RFC 3261 §8.2.6.2 */ }
impl<'a> ResponseBuilder<'a> {
    pub fn for_request(request: &RawMessage<'a>, status: StatusCode) -> Self;
    pub fn to_tag(self, tag: &'a [u8]) -> Self;       // only if the request had none
    pub fn copy_record_route(self, request: &RawMessage<'a>) -> Self;
    pub fn reason(self, reason: &'a [u8]) -> Self;
    pub fn contact(self, value: &'a [u8]) -> Self;
    pub fn header(self, name: HeaderName<'a>, value: &'a [u8]) -> Self;
    pub fn body(self, content_type: &'a [u8], body: &'a [u8]) -> Self;
    pub fn build(self) -> Result<OwnedMessage, BuildError>;
    /// A stateless refusal of a request missing some of what a response
    /// copies: only the `Via` is required, the rest is copied when present.
    pub fn build_refusal(self) -> Result<OwnedMessage, BuildError>;
}

pub enum BuildError { MissingField(&'static str), IllegalValue(&'static str), OwnedField(&'static str), NotWellFormed(ParseError) }

/// Reassembles TCP and TLS bytes into messages. The one place inbound bytes
/// must be copied into an accumulation buffer, because a message can arrive
/// split across reads. Frames on Content-Length (RFC 3261 §18.3).
///
/// WebSocket (phase 2, RFC 7118) does not use this: each WebSocket message
/// carries exactly one SIP message, so the caller feeds a frame as
/// `Input::Datagram` on a transport bound with `TransportProtocol::Ws`/`Wss`.
pub struct StreamFramer { /* buffer, its own scratch, cursor, limits */ }
impl StreamFramer {
    pub fn new(max_message_bytes: u32) -> Self;
    pub fn with_limits(limits: Limits) -> Self;
    /// `Err` only when the head in front has passed the bound without ending.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), ParseError>;
    /// `Err` only when the framing is lost; a message the parser refuses but
    /// whose end is known comes out as `Framed::Refused`, and the stream
    /// reads on past it.
    pub fn next_message(&mut self, mode: ParseMode) -> Result<Option<Framed<'_>>, ParseError>;
    /// RFC 5626 §4.4.1: a double CRLF arrived and a single CRLF owes it an answer.
    pub fn take_ping(&mut self) -> bool;
    /// And the other half: a single CRLF arrived, so a ping of ours was answered.
    pub fn take_pong(&mut self) -> bool;
    pub fn pending(&self) -> usize;
    pub fn reset(&mut self);
}

pub enum Framed<'a> {
    Message(RawMessage<'a>),
    /// The head only — what an answer is written from — and how long the
    /// whole message said it was. A body past the bound is never held.
    Refused { head: &'a [u8], length: usize, error: ParseError },
}

/// The request line and the five fields every response copies (`Via`,
/// `From`, `To`, `Call-ID`, `CSeq`) out of a request the parser refused, so
/// that the refusal can be answered 400 or 513 (docs/03, "Limits, and what a
/// refused message gets"). One pass, no allocation beyond the index.
pub fn salvage_request<'a>(buf: &'a [u8], scratch: &'a mut ParseScratch, max_fields: u16)
    -> Option<RawMessage<'a>>;
```

Bounds are configuration, and every one has a default that stops a hostile
peer from making the parser do unbounded work: message size, header count,
header value length.

The builders take borrowed input and copy once at `build()`. The owned forms
are for state a dialog keeps between calls; a builder lives inside one step of
a state machine, and making it own its inputs would only mean allocating them
twice. What comes out is deterministic — same inputs, same bytes, whatever
order the setters were called in — because a retransmission has to be the
identical datagram (§17.1.1.2) and a byte-comparing test is worth nothing
otherwise. Field order is fixed: `Via` first, then routing and dialog fields,
then whatever else the caller added in the order it was added, then
`Content-Type` and `Content-Length` around the body. `Content-Length` is
always written, since a stream transport has no other way to find the end.

A header value goes out on one line. The one line break a value may hold is a
fold, and it is written as the single space RFC 3261 §7.3.1 says it is: a
response copies `Via`, `From`, `To`, `Call-ID` and `CSeq` as they arrived, and
a request is free to have folded any of them. Any other CR or LF is refused,
because a caller's data with a line break in it would be writing headers of
its own.
`build()` parses what it wrote and hands back the failure rather than
shipping a message the far end will reject.

The framer owns its scratch rather than borrowing one, because it has to hold
the cursor and the parse index together anyway, and a caller passing a second
scratch would only be able to get the lifetimes wrong. A message without
`Content-Length` is `MissingContentLength`, not a body read to the end of the
buffer: §18.3 makes the field mandatory on a stream, and guessing would
swallow whatever came after it. Keep-alives (RFC 5626 §4.4.1) are skipped
between messages and counted, pings apart from pongs, so the layer that owns
the connection can send the single CRLF a ping is owed and can see the one that
answered its own. A pair is a ping and the odd CRLF left over is a pong,
reported the moment it arrives rather than held to see whether a second follows
it: on an idle connection the second one may never come, and the pong is the
only thing that says the flow is alive. The cost is that a ping torn in half by
the network counts as a pong and then as the ping it was — still answered, one
keep-alive interval late.

Work is bounded per byte received rather than per call: the search for the end
of the headers resumes where it stopped, and once the body's length is known
nothing is parsed again until that many bytes have arrived. A peer feeding one
byte at a time therefore cannot turn reassembly into quadratic work.

## Dialogs

```rust
pub struct DialogKey { /* CallId, Tag, Option<Tag> */ }
impl DialogKey {
    pub fn as_uac(message: &RawMessage<'_>) -> Result<Self, DialogError>;
    pub fn as_uas(message: &RawMessage<'_>) -> Result<Self, DialogError>;
}

pub enum DialogState { Early, Confirmed, Terminated }
pub enum Incoming { Accepted, OutOfOrder }

impl Dialog {
    pub fn from_response(request: &RawMessage<'_>, response: &RawMessage<'_>, over_tls: bool) -> Result<Self, DialogError>;
    pub fn from_request(request: &RawMessage<'_>, local_tag: &[u8], status: StatusCode, over_tls: bool) -> Result<Self, DialogError>;

    pub fn next_request(&mut self, method: Method<'_>) -> Result<InDialogRequest, DialogError>;
    pub fn on_response(&mut self, response: &RawMessage<'_>) -> Result<DialogState, DialogError>;
    pub fn on_request(&mut self, request: &RawMessage<'_>) -> Result<Incoming, DialogError>;
    pub fn terminate(&mut self);
}
```

`DialogKey` is the name a message carries; `DialogId` above is the handle the
endpoint hands out. Two types because they answer different questions: the key
is what a lookup is done by, and the handle is what survives being passed to
another language and back.

A dialog does not remember which side of it we were, and does not need to.
Which tag is ours follows from who started the transaction the message belongs
to: our requests and the responses to them carry our tag in `From`, everything
the peer sends carries it in `To`. That is `as_uac` and `as_uas`, and it means
an incoming request is always looked up one way and an incoming response
always the other.

`next_request` consumes a sequence number and hands back an `InDialogRequest`
holding the Request-URI, the `Route` values, both addresses with their tags,
the `Call-ID` and the number — and a `builder()` carrying all of it. What is
missing is deliberate: the `Via` belongs to the transport that will carry the
message, the `Contact` to whoever knows this host's address, and the body to
the layer that has one. ACK and CANCEL are refused there, because §12.2.1.1
gives them the number of the request they answer rather than one of their own.

```rust
pub enum Fork { Opened(DialogKey), Advanced(DialogKey), Refused, Ignored }

impl DialogSet {
    pub fn new(invite: OwnedMessage, over_tls: bool) -> Self;
    pub fn on_response(&mut self, response: &RawMessage<'_>) -> Result<Fork, DialogError>;
    pub fn no_more_answers(&mut self);                       // 64*T1 after the first 2xx

    pub fn ack_2xx(&self, key: &DialogKey) -> Result<InDialogRequest, DialogError>;
    pub fn keep_ack(&mut self, key: &DialogKey, ack: OwnedMessage) -> Result<(), DialogError>;
    pub fn ack_for(&self, key: &DialogKey) -> Option<&OwnedMessage>;
}
```

`DialogSet` is one INVITE and every dialog it produced. A forking proxy rings
the desk phone, the mobile and the voicemail; each branch that answers is a
distinct dialog told apart by its `To` tag, and the core picks none of them.
A non-2xx final ends every dialog still early and leaves a confirmed one
alone. A 2xx that arrives after that is still taken: §13.2.2.3 says to ignore
subsequent finals "which would only arrive under error conditions", and a 2xx
is not one — dropping it would leave a call standing at the other end with
nobody to hang it up.

The ACK for a 2xx lives here rather than in the transaction, because
§13.2.2.4 puts it outside one: it follows the dialog's route set, it may carry
the answer to an offer, and "the UAC core handles retransmissions of the ACK,
not the transaction layer". So the caller builds it once — it is the caller
who knows whether there is an answer to put in it — hands it back with
`keep_ack`, and every retransmitted 2xx after that is answered from the stored
bytes without asking again. The ACK for a non-2xx is the transaction's
(§17.1.1.3) and never reaches the caller.

## Input and output

```rust
/// UDP, TCP and TLS in phase 1. WS and WSS are named because RFC 7118
/// registers them as `sent-protocol` transports and a `Via` carrying one is
/// not malformed; the rest of RFC 7118 is phase 2.
pub enum TransportProtocol { Udp, Tcp, Tls, Ws, Wss }
impl TransportProtocol {
    pub fn as_str(self) -> &'static str;              // the Via token: UDP, TCP, TLS, WS, WSS
    pub fn from_token(token: &[u8]) -> Option<Self>;  // case-insensitive, §7.3.1
    pub fn is_reliable(self) -> bool;                 // what §17 keys timers D, I, J, K on
    pub fn is_stream(self) -> bool;                   // needs Content-Length framing: TCP, TLS
    pub fn is_secure(self) -> bool;                   // what a sips: URI asks for
    pub fn default_port(self) -> Option<u16>;         // 5060/5061 (§18.1.1); none for WS
}

/// A host that outlived the message it was read out of, because resolution
/// happens outside and the answer comes back later.
pub enum Host { Name(Arc<str>), Ip(IpAddr) }

// There is no `ResolveId`. The only thing the core ever needs resolved is a
// dialog's next hop, so the dialog is the question and the handle both.

pub enum Input<'a> {
    Datagram { transport: TransportId, remote: SocketAddr, local: SocketAddr, data: &'a [u8] },
    StreamData { transport: TransportId, data: &'a [u8] },
    StreamClosed { transport: TransportId },
    /// `local` is what goes into the `Via` of everything sent on this
    /// transport, so a caller bound to a wildcard address says here which
    /// address the far end can reach it at. `remote` is the far end of a
    /// connection and `None` for a datagram socket, which has many.
    ///
    /// Binding an identifier that is already bound replaces what was there,
    /// which is what a caller that reconnected wants. RFC 5626 §4.4.1 is
    /// about a flow rather than about a name, so the keep-alive and the
    /// pong deadline of the connection that is gone are cancelled with it:
    /// the replacement is not called dead ten seconds later for a ping it
    /// was never sent.
    TransportBound { transport: TransportId, protocol: TransportProtocol, local: SocketAddr, remote: Option<SocketAddr> },
    TransportFailed { transport: TransportId, error: TransportErrorKind },
}

/// Coarse on purpose: §17 has one reaction to all of them — tell the user,
/// terminate — and the real message is still in the caller's log.
pub enum TransportErrorKind { ConnectionRefused, ConnectionReset, Unreachable, TimedOut, Closed, Other }

pub struct Transmit {
    pub transport: TransportId,
    pub destination: SocketAddr,
    /// Which of the transport's local addresses to send from, when it has more
    /// than one. RFC 3581 §4: "The response MUST be sent from the same address
    /// and port that the corresponding request was received on", which a
    /// caller listening on a wildcard address cannot work out for itself.
    /// `None` for everything this endpoint originates.
    pub source: Option<SocketAddr>,
    /// Refcounted. A retransmission is an `Arc` clone.
    pub payload: Arc<[u8]>,
    /// May differ from the request's nominal transport after the RFC 3261
    /// §18.1.1 switch to TCP.
    pub protocol: TransportProtocol,
}

/// The endpoint does not resolve names. It asks.
/// (Emitted as `Event::ResolveNeeded`, answered with `Endpoint::resolved`.)
```

Name resolution, including NAPTR and SRV per RFC 3263, stays outside: it is
I/O, and the platform (or the binding) usually has a better resolver than a
library would.

The endpoint therefore never needs an address it was not given. Every
destination it uses is either one the caller supplied on an `OutgoingRequest`,
or the source of a message that arrived — a response goes back where the
request came from (§18.2.2), and a dialog keeps the flow its first message
travelled on. What it does do is *say* when the next hop a dialog names is not
where its requests are going (`Event::ResolveNeeded`), so a caller with a
resolver can correct it with `resolved`. §12.2.1.1 computes that address by the
RFC 3263 procedures, and §8.1.2 in the same breath allows "an alternate
address (such as a default outbound proxy not represented in the route set)",
which is exactly what keeping the flow is — and the only thing that survives
the NAT nearly every softphone sits behind.

This fires again whenever a target refresh moves the remote target
(§12.2.1.2, §12.2.2), not only at dialog creation — nothing else compares the
new target to the flow, so before this a re-INVITE could move the target while
the Request-URI named one host and the datagram went to another, with nothing
said about it.

What it does **not** do is move the flow itself, even when the new target is a
literal address that needs no resolver. A far end behind a NAT writes its own
private address into `Contact` — that is the ordinary case, not the exotic one
— and following it would take the call off the only address that reaches it.
Nothing at this layer can tell that apart from a far end that genuinely moved.
So the event goes out, the flow stands, and the caller decides with
`resolved`. That is what the event is for.

## Endpoint operations

```rust
/// RFC 3261 §18.1.1 as two numbers: "within 200 bytes of the path MTU, or
/// larger than 1300 bytes and the path MTU is unknown".
pub struct DatagramLimit {
    pub path_mtu: Option<u32>,                 // None: use the 1300-byte rule
    pub headroom_bytes: u32,                   // 200: room for a larger response
    pub max_datagram_bytes: u32,               // 1 300
}
impl DatagramLimit {
    pub fn too_big_for_a_datagram(&self, request_bytes: usize) -> bool;
}

pub struct EndpointConfig {
    pub timers: TimerConfig,
    pub parse_mode: ParseMode,                 // Lenient
    pub limits: Limits,                        // the parser's bounds, above
    pub sdp_limits: sdp::Limits,               // the same, for an SDP body
    pub datagram_limit: DatagramLimit,
    pub always_request_rport: bool,            // true, RFC 3581 (a MAY, chosen)
    /// Double-CRLF keepalive on stream transports (RFC 5626 §4.4.1), emitted
    /// as a `Transmit` when due. `None` disables it. An upper bound rather
    /// than a period: §4.4.1 requires the interval to be drawn at random
    /// between it and 20% below it. Default 25 s, see `03`.
    pub keepalive_interval: Option<Duration>,
    /// The ceiling on what a peer can make this endpoint hold. Past either
    /// one, a request from outside every dialog we already have is answered
    /// 503 statelessly (§21.5.4) and `Event::Overloaded` says so. Defaults
    /// 256 and 128 — an order of magnitude past what a softphone reaches. An
    /// incoming call counts against `max_dialogs` from the moment its INVITE
    /// is let in, not from the response of ours that makes its dialog, and a
    /// call placed here from the moment its INVITE is sent — one placed at
    /// the ceiling is `SendError::LimitReached`; each branch of a fork past
    /// the first dialog of our own INVITE, and past the first 2xx to it,
    /// opens only while there is room.
    pub max_server_transactions: usize,
    pub max_dialogs: usize,
    /// How much of the diagnostic record to keep: entries per call, and calls
    /// at once. Both are bounds rather than budgets — past either one the
    /// record says what it dropped instead of quietly becoming a lie.
    /// `docs/14-diagnostics.md`.
    pub diagnostics: RecordLimits,
}

/// What the caller describes. The endpoint fills in the branch, the sent-by,
/// the sequence number, the `Call-ID` and the tags, because a caller that
/// writes those writes a branch that repeats — and a repeated branch is a
/// response delivered to the wrong transaction. `to` and `from` are required;
/// a `From` without a tag gets one.
///
/// The transport and the address are the caller's: RFC 3263 resolution is
/// I/O, and the endpoint asks (`Event::ResolveNeeded`) only about targets it
/// found inside a message, never about one the caller handed it.
pub struct OutgoingRequest { /* owned */ }
impl OutgoingRequest {
    pub fn new(method: Method<'_>, request_uri: Uri, transport: TransportId, remote: SocketAddr) -> Self;
    pub fn to(self, value: &[u8]) -> Self;            // required
    pub fn from(self, value: &[u8]) -> Self;          // required
    pub fn call_id(self, call_id: CallId) -> Self;    // §10.2: registrations reuse one
    pub fn cseq(self, seq: u32) -> Self;
    pub fn route(self, value: &[u8]) -> Self;
    pub fn contact(self, value: &[u8]) -> Self;
    pub fn header(self, name: HeaderName<'_>, value: &[u8]) -> Self;
    pub fn body(self, content_type: &[u8], body: Arc<[u8]>) -> Self;
    pub fn max_forwards(self, hops: u32) -> Self;
}

/// The fields the endpoint writes itself — `Via`, `From`, `To`, `Call-ID`,
/// `CSeq`, `Max-Forwards`, `Contact`, `Route`, `Record-Route`, `Content-Type`,
/// `Content-Length` — and so refuses from `header` on all three of these, with
/// `BuildError::OwnedField` from the call that sends, rather than writing a
/// second line of one. A name that is not a token is `BuildError::IllegalValue`
/// the same way, not a field quietly left out.
pub const ENDPOINT_FIELDS: &[HeaderName<'static>];

/// Shorter, because §12.2.1.1 already decides the Request-URI, the route, both
/// addresses with their tags, the `Call-ID` and the number.
pub struct OutgoingInDialogRequest { /* method, contact, headers, body */ }

/// Everything a response echoes from its request (§8.2.6.2) comes from the
/// request. The tag does too: one per server transaction, on every response
/// but the 100.
pub struct OutgoingResponse { /* status, reason, to_tag, contact, headers, body */ }

impl Endpoint {
    /// `seed` is thirty-two bytes of entropy, and every branch, tag,
    /// `Call-ID` and `cnonce` this endpoint writes is `SHA-256(seed ||
    /// counter)`. The caller supplies it for the same reason it supplies the
    /// clock and the sockets — and a test that supplies a fixed one can
    /// assert on bytes. Refuses `config.timers` with `t1` or `t2` at zero, and
    /// a `keepalive_interval` of zero, either of which would make a timer
    /// re-arm at the instant it fired and hang `handle_timeout` forever.
    pub fn new(config: EndpointConfig, seed: [u8; 32]) -> Result<Self, TimerConfigError>;

    // -- UAC ------------------------------------------------------------------
    pub fn invite(&mut self, request: &OutgoingRequest, now: Instant)
        -> Result<TransactionId<InviteClient>, SendError>;

    /// RFC 3261 §9.1. Always accepted while the transaction is live. If no
    /// provisional has arrived yet the CANCEL is held and sent the moment one
    /// does; the caller never has to time it. Returns the CANCEL transaction
    /// once it exists, through `Event::CancelSent`.
    pub fn cancel(&mut self, invite: TransactionId<InviteClient>, now: Instant)
        -> Result<(), CancelError>;

    /// ACK for a 2xx (RFC 3261 §13.2.2.4). Called once by the caller, because
    /// the ACK may carry the answer when the offer came in the 2xx, and because
    /// the caller decides when media is ready. After that the endpoint keeps
    /// the ACK and resends it itself on every retransmitted 2xx for as long as
    /// the dialog lives.
    ///
    /// No transaction carries it, and §18.1.1 applies to it all the same: an
    /// ACK too large for a datagram goes on a stream to the same address, and
    /// every retransmitted 2xx is answered on that stream rather than on the
    /// flow the 2xx came in on, for as long as the stream is open. Once it has
    /// closed, the ACK goes on another stream to that address, or waits for
    /// the one `Event::TransportWanted` asks for. With no stream open the call
    /// itself is refused with
    /// `AckError::Build(SendError::NeedsStreamTransport)`, nothing is kept, and
    /// the same call sends it once one is bound.
    pub fn ack_2xx(&mut self, dialog: DialogId, answer: Option<&[u8]>, now: Instant)
        -> Result<(), AckError>;

    /// RFC 3262. The dialog is read out of the handle. The body is the answer
    /// when the response carried an offer, which §5 makes a MUST for a UAC
    /// that sent an INVITE without one.
    ///
    /// `Supported: 100rel` goes on every outgoing INVITE (§4), merged with
    /// whatever the caller listed, so the far end is always allowed to answer
    /// reliably.
    pub fn prack(&mut self, provisional: ProvisionalResponseId, body: Option<Arc<[u8]>>, now: Instant)
        -> Result<TransactionId<NonInviteClient>, PrackError>;

    /// Anything but an INVITE: BYE, INFO, NOTIFY, UPDATE, REFER. An INVITE is
    /// refused with `SendError::WrongMethod`, because it needs an INVITE
    /// client transaction and an ACK of its own.
    ///
    /// §18.1.1 is applied here exactly as on the first send, and to
    /// `reinvite`, `prack` and both ACKs with it: a request too large for a
    /// datagram goes on a stream open to the dialog's next hop, or is refused
    /// with `SendError::NeedsStreamTransport`. The dialog keeps its own flow,
    /// because the rule is about one request's size and the next may fit.
    pub fn request_in_dialog(&mut self, dialog: DialogId, request: &OutgoingInDialogRequest, now: Instant)
        -> Result<TransactionId<NonInviteClient>, SendError>;

    /// Hold, resume, a codec change (§14.1). The `Contact` is required and not
    /// defaulted: §8.1.1.8 makes it a MUST on anything that can establish a
    /// dialog, and the endpoint was told a transport and a peer address, not a
    /// public URI to advertise.
    ///
    /// Refused with `SendError::InviteInProgress` when another INVITE is
    /// already running in the dialog in either direction — §14.1 makes a
    /// second one a MUST NOT, and that rule is what glare comes from.
    ///
    /// A re-INVITE never forks, so its answer is not a fork: it arrives as
    /// `Event::ReinviteAnswered` and is acknowledged with `ack_reinvite`.
    pub fn reinvite(&mut self, dialog: DialogId, request: &OutgoingInDialogRequest, now: Instant)
        -> Result<TransactionId<InviteClient>, SendError>;

    /// ACK for the 2xx to a re-INVITE. Separate from `ack_2xx` because the two
    /// acknowledge different things: that one names which of several forked
    /// dialogs answered, this one is a request inside a dialog that already
    /// exists, and its `CSeq` is the re-INVITE's rather than the original
    /// INVITE's. Kept and resent on every retransmission of the 2xx, on the
    /// flow it first left on while that is open, as above.
    pub fn ack_reinvite(&mut self, invite: TransactionId<InviteClient>, answer: Option<&[u8]>, now: Instant)
        -> Result<(), AckError>;
    /// §15.1.1: the dialog is over as soon as the BYE is passed to the
    /// transaction, whatever the far end answers, so this also emits
    /// `Event::DialogTerminated`. A BYE refused for want of a stream has not
    /// been passed to one, and the dialog stays up.
    pub fn bye(&mut self, dialog: DialogId, now: Instant)
        -> Result<TransactionId<NonInviteClient>, SendError>;
    /// The same, with a BYE of the caller's own, which is how a hangup carries
    /// the fields an application added. Anything but a BYE is
    /// `SendError::WrongMethod`, because what follows the send ends the dialog.
    pub fn bye_with(&mut self, dialog: DialogId, request: &OutgoingInDialogRequest, now: Instant)
        -> Result<TransactionId<NonInviteClient>, SendError>;

    /// REGISTER, OPTIONS, SUBSCRIBE, and any out-of-dialog non-INVITE request.
    pub fn request(&mut self, request: &OutgoingRequest, now: Instant)
        -> Result<TransactionId<NonInviteClient>, SendError>;

    /// Resend a challenged request with credentials computed against the
    /// challenge the endpoint captured for it (RFC 3261 §22, RFC 8760).
    /// Consumes the stored challenge, so a second call with the same handle is
    /// refused rather than replaying a nonce count. The nonce count, the
    /// cnonce and the `CSeq` (§22.2) are the endpoint's business; the retry is
    /// the original request again, header for header and body included, with
    /// a new branch.
    ///
    /// The challenge outlives the transaction that earned it — a refusal is
    /// final, and the password comes from a person. The set of them is capped,
    /// so a peer that refuses everything cannot grow it.
    ///
    /// One exception to "consumes the stored challenge", and it is the one
    /// error the endpoint raises to ask the caller to act: when §18.1.1
    /// refuses to send the retry over a datagram and asks for a stream, the
    /// challenge stays and the same handle works again once the transport is
    /// bound.
    ///
    /// One request goes again with credentials at most three times. The
    /// fourth challenge on the same request is a refusal whatever nonce it
    /// carries, and is reported the way the same-nonce refusal is: by no
    /// `Event::Challenged` following the response.
    pub fn retry_with_credentials(&mut self, failed: AnyTransactionId, credentials: &Credentials, now: Instant)
        -> Result<AnyTransactionId, AuthRetryError>;

    /// The same as `request` and `invite`, carrying credentials for a
    /// challenge this destination has already made (§22.2). Nothing goes on
    /// the request unless it has, so these are safe for the first request as
    /// well as the tenth; what they save is the 401 and the round trip after
    /// it. The password is borrowed and not kept — the nonce, the cnonce and
    /// the count are the endpoint's, and have to have one owner.
    pub fn request_with_credentials(&mut self, request: &OutgoingRequest, credentials: &Credentials, now: Instant)
        -> Result<TransactionId<NonInviteClient>, SendError>;
    pub fn invite_with_credentials(&mut self, request: &OutgoingRequest, credentials: &Credentials, now: Instant)
        -> Result<TransactionId<InviteClient>, SendError>;

    /// Point a dialog's requests at an address resolved outside, and at the
    /// protocol the answer names (`None` keeps the flow's own, which is what
    /// an answer from a plain A record has to say). The first address there
    /// is a bound transport for is taken and the rest are kept, so a
    /// transport failure or a timeout moves to the next SRV target without a
    /// second round trip. No `now`: every other mutating call takes the time
    /// because something it does is timed, and this one only writes down an
    /// address.
    pub fn resolved(
        &mut self,
        dialog: DialogId,
        addresses: &[SocketAddr],
        protocol: Option<TransportProtocol>,
    );

    // -- UAS ------------------------------------------------------------------
    /// 100, or any final response. Rejected with `MustBeReliable` if the
    /// INVITE carried `Require: 100rel` and the status is a non-100 1xx.
    /// A 101-199 or a 2xx opens the dialog and hands it back; anything else
    /// does not (§12.1.1).
    pub fn respond_invite(&mut self, transaction: TransactionId<InviteServer>, response: &OutgoingResponse, now: Instant)
        -> Result<Option<DialogId>, RespondError>;
    /// Reliable 101–199 (RFC 3262). The endpoint retransmits it until PRACK
    /// arrives or the transaction is abandoned.
    pub fn respond_reliable(&mut self, transaction: TransactionId<InviteServer>, response: &OutgoingResponse, now: Instant)
        -> Result<ProvisionalResponseId, RespondError>;
    pub fn respond(&mut self, transaction: TransactionId<NonInviteServer>, response: &OutgoingResponse, now: Instant)
        -> Result<(), RespondError>;
    /// Builds the subscriber's dialog from a NOTIFY; call it before answering.
    pub fn open_dialog(&mut self, transaction: TransactionId<NonInviteServer>, local_seq: Option<u32>) -> Option<DialogId>;
    pub fn close_dialog(&mut self, dialog: DialogId);

    // -- introspection ----------------------------------------------------------
    /// An unguessable token from the stream the branches, tags and `Call-ID`s
    /// come from. The layer above needs them too — §10.2.4 wants one `Call-ID`
    /// for every registration of a boot cycle — and drawing from this one
    /// guarantees the values never collide with a branch.
    ///
    /// This stream is for what goes on the wire in clear, and only for that.
    /// Media keys come from a generator of their own, seeded separately,
    /// because this seed is written into every replay recording.
    pub fn token(&mut self) -> Box<[u8]>;
    pub fn transaction_state<K: TransactionKind>(&self, id: TransactionId<K>) -> Option<K::State>;
    pub fn dialog(&self, id: DialogId) -> Option<DialogSnapshot>;
    /// Live transactions and live dialogs, for a caller deciding whether it
    /// can shut down.
    pub fn in_flight(&self) -> (usize, usize);
    /// How many requests have been refused with a 503 for want of room, for a
    /// caller that would rather sample a gauge than watch events go by.
    pub fn refused(&self) -> u64;
    /// How many messages the parser refused, whether they were answered 400
    /// or 513 or could not be answered at all; the record says which.
    pub const fn unreadable(&self) -> u64;
    /// Requests and responses sent again, and transactions that timed out,
    /// since the endpoint was created (`docs/17-observability.md`).
    pub const fn retransmissions(&self) -> Retransmissions;
    /// The same count of one live transaction's own repeats.
    pub fn transaction_retransmissions(&self, id: impl Into<AnyTransactionId>) -> Option<u32>;
    /// What the endpoint was configured with.
    pub const fn config(&self) -> &EndpointConfig;

    // -- the diagnostic record --------------------------------------------------
    /// What this endpoint decided about one call, in order, with a stable code
    /// per decision and the size on the wire where there was one. Readable at
    /// any point during the call, not only when it has gone wrong.
    pub fn call_record(&self, call: &CallId) -> Option<&Record>;
    /// And the decisions that belong to no call yet: a request refused before
    /// it could be placed, a transport chosen for something out of dialog.
    /// Never evicted, so that a flood of strangers cannot push a live call's
    /// record out of the set.
    pub const fn endpoint_record(&self) -> &Record;
    pub fn recorded_calls(&self) -> impl Iterator<Item = &CallId>;
    /// Records dropped for want of room. A bound that lies about having been
    /// reached is worse than no bound.
    pub const fn records_dropped(&self) -> u64;
    /// Every record as one JSON document, which is the artefact a bug report
    /// carries. `docs/14-diagnostics.md` has the shape and the stability rule.
    pub fn diagnostics_json(&self) -> String;
    /// A decision a layer above made about a message this endpoint handed it,
    /// recorded alongside the send and the arrival around it.
    pub fn note_arrival(&mut self, message: &RawMessage<'_>, reason: Reason, now: Instant);
}

pub struct DialogSnapshot {
    pub state: DialogState,          // Early, Confirmed, Terminated
    pub call_id: CallId,
    pub local_tag: Tag,
    pub remote_tag: Option<Tag>,     // null for a peer that predates RFC 3261
    pub local_cseq: Option<u32>,     // empty until this end sends a request
    pub remote_cseq: Option<u32>,
    pub route_set: Arc<[Uri]>,
    pub remote_target: Uri,
    pub secure: bool,
}
```

Both sequence numbers are optional and for the same reason: §12.1.1 and
§12.1.2 each leave one of them empty at creation, because a dialog only has a
number in a direction once something has been sent in it.

The endpoint never resolves a fork. It reports every 2xx per dialog and lets
the layer above decide which to keep. Baking "ACK and BYE the loser" into the
core would forbid a legal and occasionally wanted sequence (keep both), and
would put policy in the layer that is supposed to have none.

The one limit it applies is `max_dialogs`, and only past the first dialog of
the INVITE and the first 2xx to it, which between them are the call the
application placed: a forking proxy can ring the desk phone and have the
mobile answer. A further branch that
finds no room opens nothing: its provisional is reported with no dialog, and
its 2xx is not reported or acknowledged, so the far end gives it up with a BYE
of its own (§13.3.1.4). Acknowledging and hanging it up from here would turn
every forged 2xx into two requests, retransmitted, to a Contact its sender
chose.

## Events

```rust
#[non_exhaustive]
pub enum Event {
    // UAC, fork-aware: one early dialog per distinct To-tag, while
    // `max_dialogs` has room past the INVITE's first dialog and first 2xx
    /// `dialog: None` for a 100, and for a provisional with no tag to name a
    /// dialog by; neither of those opens one.
    Provisional { invite: TransactionId<InviteClient>, dialog: Option<DialogId>, status: StatusCode, response: OwnedMessage },
    ReliableProvisional { invite: TransactionId<InviteClient>, dialog: DialogId, provisional: ProvisionalResponseId, status: StatusCode, response: OwnedMessage },
    /// A 2xx for this dialog. Caller must `ack_2xx`. Several of these may
    /// follow one INVITE; the endpoint does not pick a winner. A retransmitted
    /// 2xx is answered from the stored ACK and reported to nobody.
    Established { invite: TransactionId<InviteClient>, dialog: DialogId, status: StatusCode, response: OwnedMessage },
    /// The call will not connect: refused, timed out, or the transport died.
    /// Every dialog it had opened is reported terminated separately. The
    /// refusal rides whole, because a 3xx names where to try instead and a
    /// status code alone cannot say it.
    Failed { invite: TransactionId<InviteClient>, status: Option<StatusCode>, reason: FailureReason, response: Option<OwnedMessage> },

    // UAC, inside a dialog: a re-INVITE never forks (§14.1), so none of these
    // carries a set of dialogs to choose between
    /// `provisional` is set when the response asked to be sent reliably
    /// (RFC 3262 §3 puts a re-INVITE's provisionals in scope exactly like an
    /// initial INVITE's); use it with `prack` the same way as for
    /// `ReliableProvisional`.
    ReinviteProgress { invite: TransactionId<InviteClient>, dialog: DialogId, status: StatusCode, provisional: Option<ProvisionalResponseId>, response: OwnedMessage },
    /// Caller must `ack_reinvite`. The remote target has already been
    /// refreshed from the `Contact` of this response (§12.2.1.2).
    ReinviteAnswered { invite: TransactionId<InviteClient>, dialog: DialogId, status: StatusCode, response: OwnedMessage },
    /// §14.1: "the session parameters MUST remain unchanged, as if no
    /// re-INVITE had been issued". The dialog stands unless a
    /// `DialogTerminated` follows, which it does for the three cases §12.2.1.2
    /// names: a 481, a 408, and nothing at all.
    ReinviteFailed { invite: TransactionId<InviteClient>, dialog: DialogId, status: Option<StatusCode>, reason: FailureReason, response: Option<OwnedMessage> },
    /// Two re-INVITEs crossed and the far end answered 491 (§14.2). `retry_in`
    /// is this end's draw from the range §14.1 gives it — 2.1 to 4 seconds for
    /// the end that generated the `Call-ID`, 0 to 2 for the other, so that the
    /// two do not collide again. Retrying is the caller's decision.
    ReinviteGlare { invite: TransactionId<InviteClient>, dialog: DialogId, retry_in: Duration, response: OwnedMessage },
    CancelSent { invite: TransactionId<InviteClient>, cancel: TransactionId<NonInviteClient> },
    /// The CANCEL was honoured: 487 arrived.
    Cancelled { invite: TransactionId<InviteClient> },
    /// The CANCEL lost the race: the dialog confirmed anyway. It is a live
    /// dialog; the caller ACKs and, if it still wants out, sends BYE.
    CancelLostRace { invite: TransactionId<InviteClient>, dialog: DialogId },

    // UAS
    /// A call coming in. The dialog is minted by the first response that opens
    /// one, and handed back by `respond_invite`.
    IncomingInvite { transaction: TransactionId<InviteServer>, request: OwnedMessage },
    /// The caller gave up. The 200 for the CANCEL and the 487 for the INVITE
    /// have already gone out — §9.2 makes both unconditional — so what is left
    /// is to stop ringing. An early dialog a provisional had opened ends with
    /// the 487 (§12.3): `DialogTerminated { Refused }` follows this event, as
    /// it follows any refusal of an INVITE that had rung. While a reliable
    /// provisional of that INVITE is still unacknowledged it follows the end
    /// of the INVITE transaction instead, because a PRACK for it is still
    /// answered (RFC 3262 §3). A CANCEL that crosses a final response already
    /// sent changes nothing and is not reported.
    IncomingCancel { invite: TransactionId<InviteServer> },
    IncomingPrack { transaction: TransactionId<NonInviteServer>, provisional: ProvisionalResponseId, request: OwnedMessage },
    IncomingAck { dialog: DialogId, request: OwnedMessage },
    IncomingBye { transaction: TransactionId<NonInviteServer>, dialog: DialogId },
    IncomingReinvite { transaction: TransactionId<InviteServer>, dialog: DialogId, request: OwnedMessage },
    IncomingInDialog { transaction: TransactionId<NonInviteServer>, dialog: DialogId, request: OwnedMessage },
    IncomingOutOfDialog { transaction: TransactionId<NonInviteServer>, request: OwnedMessage },

    // non-INVITE client
    Challenged { transaction: AnyTransactionId, realm: Arc<str>, proxy: bool, algorithm: DigestAlgorithm, stale: bool },
    Response { transaction: TransactionId<NonInviteClient>, status: StatusCode, response: OwnedMessage },
    RequestFailed { transaction: TransactionId<NonInviteClient>, reason: FailureReason },

    // plumbing
    /// The next hop a dialog names is not where its requests are going.
    /// Answering retargets it; ignoring it keeps the flow the call is on,
    /// which §8.1.2 allows as "an alternate address" and which is the only
    /// thing that survives a NAT.
    ResolveNeeded { dialog: DialogId, host: Host, port: Option<u16>, protocol: Option<TransportProtocol> },
    /// A request is too large for a datagram (§18.1.1) and no stream transport
    /// is open to move it to — any request, inside a dialog or out of one, the
    /// ACK to a 2xx included. Opening one is the caller's; the request is not
    /// held, and goes when it is sent again. Both sizes travel with it,
    /// because a request that fragments and is dropped by a NAT looks from
    /// above like nothing happening at all.
    TransportWanted {
        protocol: TransportProtocol,
        destination: SocketAddr,
        request_bytes: usize,
        limit_bytes: u32,
    },
    /// A keep-alive went ten seconds unanswered, so RFC 5626 §4.4.1 calls the
    /// flow dead and the endpoint has taken it down. Everything that was
    /// running on it has already failed. Closing the socket and opening a
    /// replacement is the caller's; binding the new one under the same
    /// `TransportId` is what puts a registration back where it was.
    FlowFailed { transport: TransportId },
    /// A request from outside every dialog we hold arrived with no room for
    /// it, and was answered 503 statelessly. `refused` is cumulative.
    Overloaded { refused: u64 },
    TransactionTerminated { transaction: AnyTransactionId, reason: TerminationReason },
    DialogTerminated { dialog: DialogId, reason: DialogEndReason },
}

pub enum FailureReason { Timeout, TransportFailed, Refused }
pub enum TerminationReason { Completed, TimedOut, TransportFailed }
pub enum DialogEndReason { LocalBye, RemoteBye, Refused, Abandoned, Failed, Gone, Closed }
```

`Gone` is §12.2.1.2's case: a 481 or a 408 to a request inside the dialog, or
no answer at all. No BYE goes out for it — the far end has just said there is
no such dialog, and a BYE would earn the same 481.

`Closed` is `close_dialog`: a usage that ended with nothing on the wire to end
it (RFC 6665 §4.4.1).

**What a response says is reported before the transaction that carried it
ends.** `Failed`, `Cancelled`, `Response`, `Challenged`, `ReinviteFailed` and
the `DialogTerminated` that goes with a refusal all come out ahead of
`TransactionTerminated`, and the transport makes no difference to that. It
matters because the two coincide on TCP and TLS and do not on UDP: §17.1.1.2
gives timer D a value of zero on a reliable transport and §17.1.2.2 does the
same for timer K, so a 486 over TCP ends the client transaction in the same
call that delivered it, while over UDP the transaction stands for another
32 seconds. An application may therefore forget everything it holds against a
transaction when it sees `TransactionTerminated`, and will not lose the reason
the call failed by doing so.

`TerminationReason::TimedOut` on an INVITE server transaction means one of two
things, told apart by what was answered. After a non-2xx it is §17.2.1's timer
H: the ACK the transaction was owed never came, and nothing follows. After a
2xx it is RFC 6026's timer L, and it is the only moment anyone can learn that
the ACK never arrived — which §13.3.1.4 answers with a BYE. The core does not
send that BYE, because it does not know whether the dialog is still wanted;
`sipral-ua` does.

An INVITE that arrives inside a dialog while another is in flight is answered
by the endpoint and never reaches the caller, because §14.2 makes both answers
MUSTs and neither is a decision: 491 when the crossing one is ours, and 500
with a drawn `Retry-After` when the far end sent a second before we answered
its first. RFC 3311 §5.2 says the same about a second UPDATE and that one is
answered here too; its sibling rules turn on whether an offer is outstanding,
which is offer/answer state and lives in `sipral-ua`.

"In flight" there means what §14.1 means by it — the transaction has not
reached "completed or terminated" — and not "the transaction handle still
exists". A refusal completes it at once, because the ACK for a non-2xx belongs
to the transaction rather than to the dialog; a 2xx completes it when
`ack_reinvite` has been called. Reading it the other way would hold the dialog
shut for the timer that only absorbs duplicates, and §14.1 asks for a change
refused with 491 to be offered again after two to four seconds.

`OwnedMessage` rides in events rather than a summary struct, so the layer above
can read any header, including ones the core has no opinion about, without the
core growing a field for each.

## Authentication and SDP

```rust
pub enum DigestAlgorithm { Md5, Md5Sess, Sha256, Sha256Sess, Sha512_256, Sha512_256Sess }

/// The password. No `Debug`, no `Display`, no way out of the module, and the
/// bytes are overwritten on drop.
pub struct Secret(/* private */);
pub struct Credentials { pub username: Arc<str>, /* Secret */ }

pub struct Challenge { pub realm: Arc<str>, pub nonce: Arc<str>, pub opaque: Option<Arc<str>>, pub algorithm: DigestAlgorithm, pub qop_auth: bool, pub stale: bool, pub proxy: bool }
impl Challenge {
    pub fn read(challenge: &ChallengeRef<'_>, proxy: bool) -> Option<Self>;
    pub fn respond(&self, credentials: &Credentials, method: Method<'_>, uri: &[u8], count: u32, cnonce: &str) -> String;
    pub fn header(&self) -> HeaderName<'static>;   // Authorization or Proxy-Authorization
}

pub enum Learned { Retry, Refused, Unusable }

/// Cached per (realm, credential space) so a later request can carry
/// `Authorization` without a 401 round trip (RFC 3261 §22.1).
pub struct AuthCache { /* per-realm Challenge + nc */ }
impl AuthCache {
    pub fn learn(&mut self, response: &RawMessage<'_>, cnonce: &str) -> Learned;
    pub fn authorize(&mut self, credentials: &Credentials, method: Method<'_>, uri: &[u8]) -> Vec<(HeaderName<'static>, String)>;
}
```

`Credentials` does have a `Debug`, which prints the user name and `<redacted>`
where the password would be. `Secret` has none at all: a value that cannot be
printed cannot be printed by accident, which is the only kind of leak that
actually happens. Overwriting on drop is best effort and says so — only a
volatile write is guaranteed to survive an optimiser, and that needs `unsafe`,
which this crate denies.

The same overwrite runs one level down. `respond` builds A1 —
`user:realm:password` — in a `Secret`, and then hands it to a digest written in
this crate, which copies the last part-block of it into a buffer of its own and
reads that block back as words. MD5, SHA-256 and SHA-512/256 each overwrite
both before returning, so the password does not outlive the digest of it in a
stack frame nobody owns any more. What is *not* wiped is HA1, which is
password-equivalent for answering a challenge and is a `String`: wiping it
needs `hash` to hand back raw bytes with the hexadecimal done at the edge,
which is every caller of `hash`. That is a scope decision, written here so it
is a decision rather than an oversight.

The cache draws no client nonce and reads no clock; both arrive from the
caller. It answers the topmost challenge it understands per realm (RFC 8760
§2.4), keeps the 401 and the 407 spaces apart, counts `nc` per challenge, and
refuses to answer the same nonce twice after a refusal — §22.1 forbids
re-attempting credentials that were just rejected, and `Learned::Refused` is
how the endpoint hears that the password is wrong rather than missing.

SDP is a value type in `sipral_core::sdp`: `SessionDescription`,
`MediaDescription`, `parse`, `to_bytes` (deterministic), and
`offer.answer(origin, connection, streams)` for RFC 3264. The endpoint carries
SDP bodies as opaque bytes, which is why its signatures say `Arc<[u8]>` and not
`SessionDescription`; whoever wants the parsed form asks for it.

## Errors

One enum per operation family, `Display` by hand, no panics, no bare
booleans:

`ParseError`, `HeaderError`, `BuildError`, `ReceiveError`, `SendError`,
`CancelError`, `AckError`, `PrackError`, `RespondError`, `AuthRetryError`.

`RespondError` carries the four refusals RFC 3262 §3 asks for:
`MustBeReliable` when the INVITE required `100rel` and the response is a
non-100 provisional, `NotProvisional` for anything outside 101-199,
`NotOffered` when the far end never listed the option tag, and
`StillUnacknowledged` while a previous reliable response is outstanding.

`CancelError` has no "too early" variant. The only ways to fail are an unknown
or already-final transaction.

`SendError::NeedsStreamTransport` is the one refusal that asks the caller to
act, and every door a request leaves by can return it: `request`, `invite`,
`request_in_dialog`, `bye` and `reinvite` as it is, `prack` inside
`PrackError::Send`, both ACKs inside `AckError::Build`, and
`retry_with_credentials` inside `AuthRetryError::Unsendable`. Nothing goes out
and nothing is started; the caller binds the stream `Event::TransportWanted`
names and asks again. A request inside a dialog leaves the sequence number it
drew unused, which §12.2.2 allows.

## Walkthrough: register

1. `request(&OutgoingRequest::new(Register, ..).to(..).from(..))` → `TransactionId<NonInviteClient>`; `poll_transmit` yields the REGISTER, with a fresh branch, a `From` tag and `;rport`.
2. 401 arrives → `Event::Challenged { transaction, realm, proxy: false, .. }`. The transaction terminates normally.
3. `retry_with_credentials(transaction, &creds, now)` → a new transaction; `poll_transmit` yields the REGISTER with `Authorization`.
4. 200 arrives → `Event::Response { status: 200, response }`. `sipral-ua` reads `Contact`/`Expires` from `response` and schedules the refresh; the core has no opinion about expiry.
5. The refresh goes through `request_with_credentials`, and carries the
   `Authorization` from step 3 with the next `nc`. §22.2: "UAs SHOULD cache the
   credentials for a given value of the To header field and 'realm' and attempt
   to re-use these values on the next request for that destination." Steps 2
   and 3 happen once per boot rather than once per refresh.

**What the endpoint remembers, and for how long.** The nonce, the client nonce
and the count, per destination — the To URI — and inside that, per protection
domain. Never the password: it is borrowed for the length of one call. A
registrar's or a callee's own challenge (401) is re-used on any request to that
destination; a proxy's (407) only inside the `Call-ID` it was made in, which is
what §22.3 allows and no more. Both are dropped when a nonce comes back a
second time without `stale`, because §22.1 makes that a rejected password
rather than a fresh challenge, and the request that follows goes out bare
rather than repeating it. The table of destinations is capped at thirty-two.

**When the same nonce never comes back.** §22.1's guard turns on the nonce
being the same, and a server that draws a fresh one for every refusal and
never marks it `stale` walks straight past it — one wrong password per round
trip, for as long as the process lives, which is how an account gets locked
out. Nothing on the wire tells that apart from a server ageing its nonces
honestly, so the count is the defence: one request is answered at most three
times, and the fourth challenge on it is a refusal whatever nonce it carries.
The credentials are then marked refused as well, so §22.2's pre-emptive answer
stops offering a password three refusals old on every later request to that
destination. It is not permanent — a challenge carrying a nonce this cache has
not answered starts the entry again, which is what lets a password corrected
while the process runs take effect.

**The nonce count belongs to the request that leaves.** Working out an answer
does not move the count; sending it does. A request that is built and then
refused — §18.1.1 asking for a stream is the one that happens — takes no
number with it, so the next one does not step over a value the server never
saw.

## Walkthrough: call, race, fork

**Happy path.** `invite(..)` → `TransactionId<InviteClient>` (state `Calling`,
timer A at T1 on UDP, timer B at 64·T1). 180 with a To-tag arrives → dialog
minted, `Event::Provisional`, state `Proceeding`. 200 arrives → state
`Accepted` (timer M), dialog `Confirmed`, `Event::Established`. Caller calls
`ack_2xx(dialog, None, now)`; the ACK goes out with a fresh branch and the
dialog's route set, and the endpoint keeps it. A retransmitted 200 is answered
with the same ACK, with no event. `bye(dialog, now)` → non-INVITE client
transaction; its 200 → `Event::Response`, `DialogTerminated { LocalBye }`.

**CANCEL racing a 200.** `cancel(invite, now)` before any provisional: accepted,
nothing sent, flag set. 180 arrives: `Provisional`, then the CANCEL goes out on
the same branch, `Event::CancelSent`. Two outcomes:

- 487 arrives on the INVITE: the transaction builds and sends the ACK itself
  (§17.1.1.3, transaction-owned because it is a non-2xx), `Event::Cancelled`,
  dialog terminated. The CANCEL's own 200 is absorbed by the CANCEL transaction.
- 200 arrives first: `Event::Established` then `Event::CancelLostRace`. The
  caller ACKs and sends BYE. The endpoint does not do either on its own.

**Fork.** One INVITE, two 180s with different To-tags on the same branch: two
early dialogs, two `Provisional` events, one transaction. Leg 1's 200 →
`Established { dialog: d1 }`, state `Accepted`. Leg 2's 200 arrives while still
in `Accepted` → passed up as `Established { dialog: d2 }`. The layer above
ACKs both (RFC 3261 §13.2.2.4 requires it) and applies its policy: keep the
first and BYE the second, or keep both.

## Fake clock

```rust
let mut ep = Endpoint::new(EndpointConfig::default(), [7; 32]).unwrap();   // a fixed seed
let t0 = Instant::now();               // any fixed instant; never read again
ep.receive(Input::TransportBound { transport: T, protocol: Udp, local, remote: None }, t0).unwrap();
let inv = ep.invite(&invite_to("sip:bob@example.com"), t0).unwrap();
assert_eq!(ep.poll_transmit().unwrap().payload.len(), bytes_of_invite);
assert_eq!(ep.poll_timeout(), Some(t0 + T1));            // timer A

ep.handle_timeout(t0 + T1);
assert!(ep.poll_transmit().is_some());                    // first retransmission
assert_eq!(ep.poll_timeout(), Some(t0 + 3 * T1));         // A doubles

ep.handle_timeout(t0 + 64 * T1);                          // timer B
assert!(matches!(ep.poll_event(), Some(Event::Failed { reason: FailureReason::Timeout, .. })));
assert_eq!(ep.transaction_state(inv), None); // terminated and freed: the handle is stale
```

No socket, no thread, no sleep. Every RFC 3261 timer diagram becomes a test of
this shape, and the test suite for phase 1 is mostly this.

## Caller loop, reference shape

```rust
loop {
    while let Some(tx) = ep.poll_transmit() { sockets[tx.transport].send_to(&tx.payload, tx.destination)?; }
    while let Some(ev) = ep.poll_event() { app.handle(ev); }
    let deadline = ep.poll_timeout();
    match wait_for_datagram_until(deadline) {
        Some((transport, remote, local, buf)) => ep.receive(Input::Datagram { transport, remote, local, data: &buf }, Instant::now())?,
        None => ep.handle_timeout(Instant::now()),
    }
}
```

`sipral-ua` ships this over `std::net` behind the `reference-loop` feature,
off by default.
Each binding ships the idiomatic version for its runtime.

## Layering above

`sipral-ua` wraps one `Endpoint` and exposes the same five-call shape with a
call vocabulary: `AccountId`, `CallHandle`, `SubscriptionHandle`, one typed
method per operation (`register`, `call`, `answer`, `hangup`, `hold`,
`transfer`, `subscribe`, ...) rather than a command enum, and a `UaEvent` enum
(`Registered`, `IncomingCall`, `CallProgress`, `CallConfirmed`, `CallEnded`,
...). It owns the policy the core refuses to
have: registration refresh, automatic credential retry, `ForkPolicy`
for forks, hold via re-INVITE or UPDATE, transfer sequencing. Every type it
exposes is fully owned; no lifetime parameter leaves `sipral-core`.

`CallHandle` is deliberately not called `CallId`: the core's `CallId` is the
RFC 3261 `Call-ID` header value, and one of those spawns several `DialogId`s in
a fork. A `CallHandle` names one dialog the application is talking to, so a
forked INVITE yields several handles under one dial attempt and the application
is told which one survived. Placing a call mints the first before any dialog
exists — there has to be something to cancel with — and the first early dialog
adopts it; each one after that is a sibling.

## Projection onto C

- Handles: the C ABI is built over `sipral-ua`, so no transaction or dialog
  handle crosses it. Stacks, accounts, calls and media are opaque generational
  `sipral_handle_t` values (docs/08-ffi.md), and a stale one is
  `SIPRAL_STATUS_STALE_HANDLE`.
- Events: one tagged struct with `size` as its first field, so a struct can
  grow at the end across ABI versions. Borrowed buffers (`OwnedMessage` bytes)
  are valid for the callback's duration only; every binding copies out.
- Every entry point runs under `catch_unwind` and maps a caught panic to
  `SIPRAL_STATUS_PANIC`.
- The ABI is built over `sipral-ua`, not over `sipral-core`. The core's
  surface is public because sibling crates need it, but the compatibility
  promise at 1.0 is made for `sipral-ua` and the C ABI.

## What was taken, and what was rejected

Four proposals were generated independently from `01`, `03` and `04`, each
from a different starting constraint: endpoint-poll shape, typed handles,
minimal surface, zero-copy ownership. Three reviewers scored them; no single
proposal won on every lens, and the merge is deliberate.

**Taken.** The message layer, `to_owned()` seam, `StreamFramer`, builders and
refcounted `Transmit` from the zero-copy proposal. Generational
`TransactionId<K>`, `DialogId`, `ProvisionalResponseId`, per-kind methods and
the introspection function from the typed-handles proposal. The separate
`handle_timeout` and the shared Input/Transmit vocabulary across both layers
from the endpoint-poll proposal. The 1.0 stability policy, `#[non_exhaustive]`
everywhere and `ForkPolicy` from the minimal-surface proposal. The
pending-cancel flag for RFC 3261 §9.1 from the zero-copy proposal, in place of
a `NoProvisionalYet` error.

**Corrected.** `Accepted` on both INVITE machines (RFC 6026), which none of the
four had on the client side. `Sha512_256` variants (RFC 8760).

**Rejected.** Automatic ACK-then-BYE of a losing fork inside the core: policy
in the wrong layer. `bytes` and `thiserror` as core dependencies: `Arc<[u8]>`
and hand-written `Display` keep `sipral-core` on `std` alone, which `01`
promises. Making the caller retransmit the 2xx ACK by hand on every
retransmitted 2xx: one explicit call, then the endpoint owns it. Leaving PRACK
out of the base surface: it is a phase 1 requirement, carriers demand it.
Hand-written C event unions with no generator: the header is generated from
the Rust source, per `08`.
