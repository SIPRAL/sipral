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
pub struct HeaderSlot { pub name: Span, pub value: Span }

/// Reused across parses. Cleared, not freed.
pub struct ParseScratch { /* Vec<HeaderSlot> */ }

pub enum ParseMode { Lenient, Strict }

pub fn parse<'a>(buf: &'a [u8], scratch: &'a mut ParseScratch, mode: ParseMode)
    -> Result<RawMessage<'a>, ParseError>;

/// A view over the caller's buffer. Every accessor locates and validates a
/// span; none allocates. Never outlives the call that produced it.
pub struct RawMessage<'a> { /* buf, start-line spans, &'a [HeaderSlot], body span */ }

impl<'a> RawMessage<'a> {
    pub fn kind(&self) -> MessageKind<'a>;
    pub fn method(&self) -> Option<Method<'a>>;
    pub fn status(&self) -> Option<StatusCode>;
    pub fn request_uri(&self) -> Option<UriRef<'a>>;
    pub fn body(&self) -> &'a [u8];
    pub fn header(&self, name: HeaderName<'_>) -> Option<&'a [u8]>;
    pub fn raw_headers(&self) -> RawHeaderIter<'a, '_>;

    pub fn via(&self) -> ViaIter<'a, '_>;
    pub fn call_id(&self) -> Result<CallIdRef<'a>, HeaderError>;
    pub fn from(&self) -> Result<NameAddrRef<'a>, HeaderError>;
    pub fn to(&self) -> Result<NameAddrRef<'a>, HeaderError>;
    pub fn cseq(&self) -> Result<CSeqRef<'a>, HeaderError>;
    pub fn contact(&self) -> ContactIter<'a, '_>;
    pub fn route(&self) -> RouteIter<'a, '_>;
    pub fn record_route(&self) -> RouteIter<'a, '_>;
    pub fn max_forwards(&self) -> Option<Result<u8, HeaderError>>;
    pub fn content_length(&self) -> Option<Result<u32, HeaderError>>;
    pub fn content_type(&self) -> Option<Result<&'a str, HeaderError>>;
    pub fn expires(&self) -> Option<Result<u32, HeaderError>>;
    pub fn require(&self) -> TokenIter<'a, '_>;
    pub fn supported(&self) -> TokenIter<'a, '_>;

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

The borrowed/owned pairs follow one pattern throughout: `UriRef<'a>` / `Uri`,
`NameAddrRef<'a>` / `NameAddr`, `ViaRef<'a>` / `ViaBuf`, `TagRef<'a>` / `Tag`,
`CallIdRef<'a>` / `CallId`, `BranchRef<'a>` / `Branch`, `Method<'a>` /
`OwnedMethod`. Each `*Ref` has `to_owned()`. Owned strings are `Arc<str>` so a
dialog's route set and remote target can be shared with events without
copying.

```rust
pub enum Method<'a> {
    Invite, Ack, Bye, Cancel, Options, Register, Prack, Subscribe, Notify,
    Refer, Info, Update, Message, Publish, Extension(&'a str),
}

pub enum HeaderName<'a> {
    Via, From, To, CallId, CSeq, Contact, MaxForwards, ContentLength,
    ContentType, Route, RecordRoute, Expires, Allow, Supported, Require,
    Unsupported, Authorization, WwwAuthenticate, ProxyAuthenticate,
    ProxyAuthorization, Event, SubscriptionState, ReferTo, ReferredBy,
    Replaces, SessionExpires, MinSe, RSeq, RAck, UserAgent, Warning,
    Extension(&'a str),
}
// Equality is ASCII case-insensitive and treats compact forms as the same
// name (RFC 3261 §7.3.3): i, m, e, l, c, f, t, v, k, s.

pub struct ViaRef<'a> {
    pub transport: TransportProtocol,
    pub sent_by_host: HostRef<'a>,
    pub sent_by_port: Option<u16>,
    pub branch: Option<BranchRef<'a>>,
    pub received: Option<HostRef<'a>>,
    /// RFC 3581. `Some(None)`: rport requested. `Some(Some(p))`: echoed back.
    pub rport: Option<Option<u16>>,
}

pub struct RequestBuilder { /* owned inputs only */ }
impl RequestBuilder {
    pub fn new(method: OwnedMethod, request_uri: Uri) -> Self;
    pub fn via(self, via: ViaBuf) -> Self;
    pub fn from(self, from: NameAddr) -> Self;
    pub fn to(self, to: NameAddr) -> Self;
    pub fn call_id(self, call_id: CallId) -> Self;
    pub fn cseq(self, seq: u32) -> Self;
    pub fn max_forwards(self, n: u8) -> Self;
    pub fn contact(self, contact: NameAddr) -> Self;
    pub fn route(self, route_set: impl IntoIterator<Item = Uri>) -> Self;
    pub fn header(self, name: HeaderName<'_>, value: impl Into<HeaderValue>) -> Self;
    pub fn body(self, content_type: &str, body: Arc<[u8]>) -> Self;
    pub fn build(self) -> Result<OwnedMessage, BuildError>;
}

pub struct ResponseBuilder { /* seeded from the request: Via in order, From, Call-ID, CSeq, RFC 3261 §8.2.6.2 */ }
impl ResponseBuilder {
    pub fn for_request(request: &RawMessage<'_>, status: StatusCode, local_tag: Option<Tag>) -> Self;
    pub fn contact(self, contact: NameAddr) -> Self;
    pub fn header(self, name: HeaderName<'_>, value: impl Into<HeaderValue>) -> Self;
    pub fn body(self, content_type: &str, body: Arc<[u8]>) -> Self;
    pub fn build(self) -> Result<OwnedMessage, BuildError>;
}

/// Reassembles TCP and TLS bytes into messages. The one place inbound bytes
/// must be copied into an accumulation buffer, because a message can arrive
/// split across reads. Frames on Content-Length (RFC 3261 §18.3).
///
/// WebSocket (phase 2, RFC 7118) does not use this: each WebSocket message
/// carries exactly one SIP message, so the caller feeds a frame as
/// `Input::Datagram` on a transport bound with `TransportProtocol::Ws`/`Wss`.
pub struct StreamFramer { /* buffer, cursor, max */ }
impl StreamFramer {
    pub fn new(max_message_bytes: u32) -> Self;
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), ParseError>;
    pub fn next_message<'s>(&'s mut self, scratch: &'s mut ParseScratch, mode: ParseMode)
        -> Result<Option<RawMessage<'s>>, ParseError>;
}
```

Bounds are configuration, and every one has a default that stops a hostile
peer from making the parser do unbounded work: message size, header count,
header value length.

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
    pub max_message_bytes: u32,                // 65 535
    pub max_headers: u16,                      // 128
    pub max_header_value_bytes: u16,           // 4 096
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
    pub remote_tag: Tag,
    pub local_cseq: u32,
    pub remote_cseq: Option<u32>,
    pub route_set: Arc<[Uri]>,
    pub remote_target: Uri,
    pub secure: bool,
}
```

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

/// Password zeroised on drop. No `Debug`, no `Display`, never logged.
pub struct Credentials { pub username: Arc<str>, /* private */ }

pub struct Challenge { pub realm: Arc<str>, pub nonce: Arc<str>, pub opaque: Option<Arc<str>>, pub algorithm: DigestAlgorithm, pub qop_auth: bool, pub stale: bool, pub proxy: bool }

/// Cached per (realm, credential space) so a later request can carry
/// `Authorization` without a 401 round trip (RFC 3261 §22.1).
pub struct AuthCache { /* per-realm Challenge + nc */ }
```

SDP is a value type in `sipral_core::sdp`: `SessionDescription`,
`MediaDescription`, `parse`, `to_bytes` (deterministic), and the RFC 3264
`answer(offer, preference)` computation. The core carries SDP bodies as opaque
bytes; interpreting them is `sipral-ua`'s job, which is why the endpoint's
signatures say `Arc<[u8]>` and not `SessionDescription`.

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
