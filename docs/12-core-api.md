<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# sipral-core: the public API, agreed on paper

This is the surface phase 1 implements. It was chosen from four independent
proposals scored by three reviewers with different concerns (implementer,
binding author, protocol reviewer), and then merged by hand. What was taken
from where, and what was rejected, is at the end, so that the next person to
disagree with a decision can see what it was weighed against.

Signatures only. Bodies come in phase 1. Anything here that phase 1 proves
wrong is changed here in the same commit.

## The contract in four calls

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
pub struct TransportId(pub u32);
```

Typing the transaction handle by machine kind means "respond to a PRACK using
an INVITE server transaction handle" is a compile error rather than a runtime
`Err`. That guarantee survives translation into a C struct per kind, and from
there into Swift, .NET and Kotlin types. Generational identity means a stale
handle yields a typed error, never a different transaction.

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
retransmissions of the INVITE. Three reviewers flagged the absence of this
state independently; it is the corner that produces "the call connected but the
app thinks it failed" in the field.

```rust
pub struct TimerConfig { pub t1: Duration, pub t2: Duration, pub t4: Duration }
impl Default for TimerConfig {}   // 500 ms, 4 s, 5 s, RFC 3261 §17.1.1.1
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
    pub max_header_value_bytes: u32,  // 4 096
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

```rust
pub enum Method<'a> {
    Invite, Ack, Bye, Cancel, Options, Register, Prack, Subscribe, Notify,
    Refer, Info, Update, Message, Publish, Extension(&'a str),
}

pub enum HeaderName<'a> {
    Accept, Allow, AllowEvents, Authorization, CallId, Contact,
    ContentEncoding, ContentLength, ContentType, CSeq, Date, Event, Expires,
    From, MaxForwards, MinExpires, MinSe, ProxyAuthenticate,
    ProxyAuthorization, ProxyRequire, RAck, RecordRoute, ReferTo, ReferredBy,
    Replaces, Require, Route, RSeq, SessionExpires, Subject,
    SubscriptionState, Supported, To, Unsupported, UserAgent, Via, Warning,
    WwwAuthenticate,
    Extension(&'a str),
}
// Equality is ASCII case-insensitive and treats a compact form as the field
// it abbreviates, so `Via`, `via` and `v` are one value. Fifteen fields have
// one: i m e l c f t v k s (RFC 3261 §7.3.3), u and o (RFC 6665 §8.2),
// r (RFC 3515), b (RFC 3892), x (RFC 4028). `Extension` compares
// case-insensitively too, and keeps the spelling it arrived with.
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
}

pub enum BuildError { MissingField(&'static str), IllegalValue(&'static str), NotWellFormed(ParseError) }

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
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), ParseError>;
    pub fn next_message(&mut self, mode: ParseMode) -> Result<Option<RawMessage<'_>>, ParseError>;
    /// RFC 5626 §4.4.1: a double CRLF arrived and a single CRLF owes it an answer.
    pub fn take_ping(&mut self) -> bool;
    pub fn pending(&self) -> usize;
    pub fn reset(&mut self);
}
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

No value may contain CR or LF: a header value goes out on one line, so a
caller's data with a line break in it would be writing headers of its own.
`build()` parses what it wrote and hands back the failure rather than
shipping a message the far end will reject.

The framer owns its scratch rather than borrowing one, because it has to hold
the cursor and the parse index together anyway, and a caller passing a second
scratch would only be able to get the lifetimes wrong. A message without
`Content-Length` is `MissingContentLength`, not a body read to the end of the
buffer: §18.3 makes the field mandatory on a stream, and guessing would
swallow whatever came after it. Keep-alives (RFC 5626 §4.4.1) are skipped
between messages and counted, so the layer that owns the connection can send
the single CRLF a ping is owed.

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
pub enum Input<'a> {
    Datagram { transport: TransportId, remote: SocketAddr, local: SocketAddr, data: &'a [u8] },
    StreamData { transport: TransportId, data: &'a [u8] },
    StreamClosed { transport: TransportId },
    TransportBound { transport: TransportId, protocol: TransportProtocol, local: SocketAddr },
    TransportFailed { transport: TransportId, error: TransportErrorKind },
}

pub struct Transmit {
    pub transport: TransportId,
    pub destination: SocketAddr,
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
library would. The endpoint asks for a host and receives addresses.

## Endpoint operations

```rust
pub struct EndpointConfig {
    pub timers: TimerConfig,
    pub parse_mode: ParseMode,                 // Lenient
    pub limits: Limits,                        // the parser's bounds, above
    pub mtu_known: Option<u32>,                // None: use the 1300-byte rule
    pub udp_to_tcp_switch_bytes: u32,          // 1 300, RFC 3261 §18.1.1
    pub always_request_rport: bool,            // true, RFC 3581 (a MAY, chosen)
    /// Double-CRLF keepalive on stream transports (RFC 5626 §4.4.1), emitted
    /// as a `Transmit` when due. `None` disables it. Default 25 s, see `03`.
    pub keepalive_interval: Option<Duration>,
}

impl Endpoint {
    pub fn new(config: EndpointConfig) -> Self;

    // -- UAC ------------------------------------------------------------------
    pub fn invite(&mut self, request: OutgoingInvite, now: Instant)
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
    pub fn ack_2xx(&mut self, dialog: DialogId, answer: Option<Arc<[u8]>>, now: Instant)
        -> Result<(), AckError>;

    /// RFC 3262. The dialog is read out of the handle.
    pub fn prack(&mut self, provisional: ProvisionalResponseId, body: Option<Arc<[u8]>>, now: Instant)
        -> Result<TransactionId<NonInviteClient>, PrackError>;

    pub fn request_in_dialog(&mut self, dialog: DialogId, request: OutgoingInDialogRequest, now: Instant)
        -> Result<TransactionId<NonInviteClient>, SendError>;
    pub fn reinvite(&mut self, dialog: DialogId, offer: Option<Arc<[u8]>>, now: Instant)
        -> Result<TransactionId<InviteClient>, SendError>;
    pub fn bye(&mut self, dialog: DialogId, now: Instant)
        -> Result<TransactionId<NonInviteClient>, SendError>;

    /// REGISTER, OPTIONS, SUBSCRIBE, and any out-of-dialog non-INVITE request.
    pub fn request(&mut self, request: OutgoingRequest, now: Instant)
        -> Result<TransactionId<NonInviteClient>, SendError>;

    /// Resend a challenged request with credentials computed against the
    /// challenge the endpoint captured for it (RFC 3261 §22, RFC 8760).
    /// Consumes the stored challenge. The nonce count and cnonce are the
    /// endpoint's business.
    pub fn retry_with_credentials(&mut self, failed: AnyTransactionId, credentials: &Credentials, now: Instant)
        -> Result<AnyTransactionId, AuthRetryError>;

    pub fn resolved(&mut self, request: ResolveId, addresses: &[SocketAddr], now: Instant);

    // -- UAS ------------------------------------------------------------------
    /// 100, or any final response. Rejected with `MustBeReliable` if the
    /// INVITE carried `Require: 100rel` and the status is a non-100 1xx.
    pub fn respond_invite(&mut self, transaction: TransactionId<InviteServer>, response: OutgoingResponse, now: Instant)
        -> Result<(), RespondError>;
    /// Reliable 101–199 (RFC 3262). The endpoint retransmits it until PRACK
    /// arrives or the transaction is abandoned.
    pub fn respond_reliable(&mut self, transaction: TransactionId<InviteServer>, response: OutgoingResponse, now: Instant)
        -> Result<ProvisionalResponseId, RespondError>;
    pub fn respond(&mut self, transaction: TransactionId<NonInviteServer>, response: OutgoingResponse, now: Instant)
        -> Result<(), RespondError>;

    // -- introspection ----------------------------------------------------------
    pub fn transaction_state<K: TransactionKind>(&self, id: TransactionId<K>) -> Option<K::State>;
    pub fn dialog(&self, id: DialogId) -> Option<DialogSnapshot>;
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

## Events

```rust
#[non_exhaustive]
pub enum Event {
    // UAC, fork-aware: one early dialog per distinct To-tag
    Provisional { invite: TransactionId<InviteClient>, dialog: DialogId, status: StatusCode, body: Option<Arc<[u8]>> },
    ReliableProvisional { invite: TransactionId<InviteClient>, dialog: DialogId, provisional: ProvisionalResponseId, status: StatusCode, body: Option<Arc<[u8]>> },
    /// A 2xx for this dialog. Caller must `ack_2xx`. Several of these may
    /// follow one INVITE; the endpoint does not pick a winner.
    Established { invite: TransactionId<InviteClient>, dialog: DialogId, status: StatusCode, body: Option<Arc<[u8]>> },
    /// `dialog: Some` when one fork failed while others continue; `None` when
    /// the transaction failed before any dialog existed.
    Failed { invite: TransactionId<InviteClient>, dialog: Option<DialogId>, status: Option<StatusCode>, reason: FailureReason },
    CancelSent { invite: TransactionId<InviteClient>, cancel: TransactionId<NonInviteClient> },
    /// The CANCEL was honoured: 487 arrived on this dialog.
    Cancelled { invite: TransactionId<InviteClient>, dialog: DialogId },
    /// The CANCEL lost the race: the dialog confirmed anyway. It is a live
    /// dialog; the caller ACKs and, if it still wants out, sends BYE.
    CancelLostRace { invite: TransactionId<InviteClient>, dialog: DialogId },

    // UAS
    /// Early dialog and INVITE server transaction are minted together.
    IncomingInvite { transaction: TransactionId<InviteServer>, dialog: DialogId, request: OwnedMessage },
    IncomingCancel { cancel: TransactionId<NonInviteServer>, invite: TransactionId<InviteServer>, dialog: DialogId },
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
    ResolveNeeded { request: ResolveId, host: Host, port: Option<u16>, protocol: Option<TransportProtocol> },
    TransportWanted { protocol: TransportProtocol, destination: SocketAddr },
    TransactionTerminated { transaction: AnyTransactionId, reason: TerminationReason },
    DialogTerminated { dialog: DialogId, reason: DialogEndReason },
}
```

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

`CancelError` has no "too early" variant. The only ways to fail are an unknown
or already-final transaction.

## Walkthrough: register

1. `request(OutgoingRequest { method: Register, .. })` → `TransactionId<NonInviteClient>`; `poll_transmit` yields the REGISTER.
2. 401 arrives → `Event::Challenged { transaction, realm, proxy: false, .. }`. The transaction terminates normally.
3. `retry_with_credentials(transaction, &creds, now)` → a new transaction; `poll_transmit` yields the REGISTER with `Authorization`.
4. 200 arrives → `Event::Response { status: 200, response }`. `sipral-ua` reads `Contact`/`Expires` from `response` and schedules the refresh; the core has no opinion about expiry.

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
let mut ep = Endpoint::new(EndpointConfig::default());
let t0 = Instant::now();               // any fixed instant; never read again
ep.receive(Input::TransportBound { transport: T, protocol: Udp, local }, t0).unwrap();
let inv = ep.invite(invite_to("sip:bob@example.com"), t0).unwrap();
assert_eq!(ep.poll_transmit().unwrap().payload.len(), bytes_of_invite);
assert_eq!(ep.poll_timeout(), Some(t0 + T1));            // timer A

ep.handle_timeout(t0 + T1);
assert!(ep.poll_transmit().is_some());                    // first retransmission
assert_eq!(ep.poll_timeout(), Some(t0 + 3 * T1));         // A doubles

ep.handle_timeout(t0 + 64 * T1);                          // timer B
assert!(matches!(ep.poll_event(), Some(Event::Failed { reason: FailureReason::Timeout, .. })));
assert_eq!(ep.transaction_state(inv), Some(InviteClientState::Terminated));
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

`sipral-ua` ships this over `std::net` behind a feature flag, off by default.
Each binding ships the idiomatic version for its runtime.

## Layering above

`sipral-ua` wraps one `Endpoint` and exposes the same five-call shape with a
call vocabulary: `AccountId`, `CallHandle`, `SubscriptionId`, a `Command` enum
(`Register`, `Call`, `Answer`, `Hangup`, `Hold`, `Transfer`, `Subscribe`, ...)
and a `UaEvent` enum (`Registration`, `IncomingCall`, `CallProgress`,
`CallConfirmed`, `CallEnded`, ...). It owns the policy the core refuses to
have: registration refresh, automatic credential retry, `MultipleAnswerPolicy`
for forks, hold via re-INVITE or UPDATE, transfer sequencing. Every type it
exposes is fully owned; no lifetime parameter leaves `sipral-core`.

`CallHandle` is deliberately not called `CallId`: the core's `CallId` is the
RFC 3261 `Call-ID` header value, and one of those spawns several `DialogId`s in
a fork. A `CallHandle` names one dialog the application is talking to, minted
per early dialog, so a forked INVITE yields several handles under one dial
attempt and the application is told which one survived.

## Projection onto C

- Handles: one POD struct per transaction kind (`sipral_invite_client_txn`,
  ...), `sipral_dialog`, `sipral_provisional`. Eight bytes each, generational,
  never a raw index.
- Events: one tagged struct with `size` as its first field, so a struct can
  grow at the end across ABI versions. Borrowed buffers (`OwnedMessage` bytes)
  are valid for the callback's duration only; every binding copies out.
- Every entry point runs under `catch_unwind` and maps a caught panic to
  `SIPRAL_ERR_PANIC`. Reaching that code path is itself the bug report.
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
everywhere and `MultipleAnswerPolicy` from the minimal-surface proposal. The
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
