// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Keeping a binding alive, and knowing when to stop trying.
//!
//! Registration is the one part of SIP that a user agent has to keep doing for
//! as long as it is switched on, and the two numbers that decide whether it
//! works are both policy rather than protocol: when to refresh, and how long to
//! wait after a failure.
//!
//! **When to refresh.** RFC 3261 §10.2.4 says only "before the expiration
//! interval has elapsed". Cutting it fine is how a phone stops receiving calls
//! for thirty seconds every hour: one lost datagram and the binding is gone
//! before the retransmission arrives. So the refresh goes at 0.85 of what the
//! registrar granted, and never later than thirty seconds before it lapses,
//! which leaves room for a lost REGISTER and a full retransmission round. Never
//! sooner than halfway either, so that a registrar handing out very short
//! bindings does not turn the client into a metronome.
//!
//! **How long to wait.** RFC 5626 §4.5 has the schedule, and it is used here
//! for the same reason it exists there: a thousand phones that lost the same
//! server must not come back in the same second. `W = min(max, base · 2^n)`,
//! and the actual wait is drawn uniformly between half of W and W.
//!
//! What is *not* retried is the other half of this. A registrar that says 403
//! will say 403 again, and a password that was refused will be refused again —
//! and re-sending it is how an account gets locked out. Those stop, and say so.
//!
//! **Freezing and thawing.** A device that sleeps pays for a whole
//! registration every time it wakes, and most of that is avoidable: the
//! `Call-ID` and the sequence number are what make the next REGISTER a refresh
//! of the binding the registrar still holds rather than a new one, and both
//! are cheap to write down. What is *not* restored is the belief that the
//! binding works. A cached registration that still read as valid while name
//! resolution had gone is one of the failures this stack exists to stop, so a
//! thawed account comes back as [`RegistrationState::Restored`] and reaches
//! [`RegistrationState::Registered`] only when a registrar has answered.

use core::fmt;
use std::borrow::Cow;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral_core::diag::Reason;
use sipral_core::dialog::CallId;
use sipral_core::endpoint::TransportId;
use sipral_core::msg::{
    Contacts, HeaderError, HeaderName, NameAddrRef, OwnedMessage, Params, RawMessage, RouteRef,
    Uri, digits, is_quoted, trim, unfold, unquote,
};
use sipral_core::transaction::{AnyTransactionId, NonInviteClient, TransactionId};

use crate::account::{Account, AccountId, Extra};
use crate::agent::UserAgent;
use crate::event::RegistrationState;

/// The fraction of the granted interval at which the refresh goes.
const REFRESH_FRACTION: u64 = 85;
/// And how long before the binding lapses it must go at the latest.
const REFRESH_MARGIN: u64 = 30;
/// RFC 5626 §4.5: "base-time (if all failed) with a default of 30 seconds".
const BACKOFF_BASE: u64 = 30;
/// "max-time with a default of 1800 seconds".
const BACKOFF_MAX: u64 = 1_800;
/// The doubling stops mattering here; going higher only risks the shift.
const BACKOFF_CEILING: u32 = 16;
/// What every snapshot starts with, so that a file of anything else is
/// refused rather than read as a registration.
const MAGIC: &[u8; 4] = b"SPRG";
/// The only snapshot layout that exists. See [`freeze`].
const SNAPSHOT_VERSION: u16 = 1;
/// Magic, version, sequence number, granted seconds, remaining seconds and
/// the length of the `Call-ID` that follows them.
const SNAPSHOT_HEAD: usize = 20;
/// RFC 3608's field. It has no compact form and no variant of its own.
const SERVICE_ROUTE: HeaderName<'static> = HeaderName::Extension("Service-Route");
/// RFC 7315 §4.1's.
const P_ASSOCIATED_URI: HeaderName<'static> = HeaderName::Extension("P-Associated-URI");
/// The most `Service-Route` entries taken from one response. Every one of them
/// rides on every request the account starts, so a long list makes every
/// INVITE longer, and past a handful it makes one that no longer fits a
/// datagram (RFC 3261 §18.1.1). RFC 3608's own examples have two.
const MAX_SERVICE_ROUTE: usize = 8;
/// The most associated identities kept from one response.
const MAX_ASSOCIATED: usize = 32;
/// The longest route entry or URI taken from a registrar.
const MAX_LEARNED_BYTES: usize = 512;

/// Everything one account's registration is doing.
#[derive(Debug)]
pub(crate) struct Registration {
    pub(crate) state: RegistrationState,
    /// §10.2.4: "A UA SHOULD use the same Call-ID for all registrations during
    /// a single boot cycle."
    pub(crate) call_id: CallId,
    /// §10.2: the number grows across refreshes, so a registrar can tell a
    /// refresh from a replay.
    pub(crate) cseq: u32,
    /// The REGISTER in flight, when there is one.
    pub(crate) transaction: Option<TransactionId<NonInviteClient>>,
    /// The interval being asked for, which a 423 may raise once (§10.2.8).
    pub(crate) asking: Duration,
    /// Whether a 423 has already raised it. A second one is the registrar
    /// contradicting itself, and is not chased.
    pub(crate) raised: bool,
    /// When the next thing happens: a refresh, or a retry.
    pub(crate) due: Option<Instant>,
    /// Consecutive failures worth retrying, which is what the back-off counts.
    pub(crate) failures: u32,
    /// A de-registration is in flight, so its 200 is not read as a binding.
    pub(crate) unregistering: bool,
    /// A challenge came back and it is not yet known whether anything could
    /// read it. The refusal is kept for the event that says so.
    pub(crate) unanswered: Option<OwnedMessage>,
    /// What the registrar said about push in its last 2xx, when it said
    /// anything (RFC 8599 §4.1.1).
    pub(crate) echo: Option<PushEcho>,
    /// When the binding the registrar granted stops being a binding. What the
    /// snapshot carries across a sleep, and the only thing in it with a time
    /// in it.
    pub(crate) lapses_at: Option<Instant>,
    /// How long this account took to become reachable, measured from the cold
    /// start the application declared.
    pub(crate) ready: Option<Duration>,
    /// A push asked for a refresh that could not be sent, because there was no
    /// transport yet. It goes the moment the application hands one over.
    pub(crate) owed: bool,
    /// The challenged REGISTER whose answer §18.1.1 would not let out over a
    /// datagram, waiting for the connection the endpoint asked for.
    ///
    /// The transaction is kept here rather than read back out of the agent's
    /// map of owners, because a refresh clears that account's entries there
    /// on every new attempt and one can fall between the park and the bind.
    /// While this is set the refusal held in `unanswered` is not a refusal
    /// yet, so nothing settles it.
    pub(crate) waiting_for_stream: Option<AnyTransactionId>,
    /// What the registrar's last 2xx said beside the binding's lifetime.
    /// `None` until one has, and again once the binding it came with is given
    /// up. Read through [`Registration::learned`], which also stops answering
    /// the moment that binding lapses.
    pub(crate) learned: Option<RegistrarInfo>,
}

impl Registration {
    pub(crate) fn new(call_id: CallId, asking: Duration) -> Self {
        Self {
            state: RegistrationState::Idle,
            call_id,
            cseq: 0,
            transaction: None,
            asking,
            raised: false,
            due: None,
            failures: 0,
            unregistering: false,
            unanswered: None,
            echo: None,
            lapses_at: None,
            ready: None,
            owed: false,
            waiting_for_stream: None,
            learned: None,
        }
    }

    /// What the registrar last said, for as long as the binding it said it
    /// about still stands.
    ///
    /// RFC 5627 §4.4: a UA "MUST NOT reuse a GRUU learned through a previous
    /// registration that has lapsed"; RFC 3608 §6.1 discards the service route
    /// when "an existing registration expires and the UA chooses not to
    /// re-register". The lapse is what both turn on, so it is checked here, at
    /// the moment of use, rather than by a timer that could fire late.
    pub(crate) fn learned(&self, now: Instant) -> Option<&RegistrarInfo> {
        let info = self.learned.as_ref()?;
        self.lapses_at.is_some_and(|at| now < at).then_some(info)
    }

    /// The registrar refused this registration.
    ///
    /// RFC 3608 §6.1: "If the re-registration request is refused ... the UA
    /// SHOULD discard any stored service route". The GRUUs stay: RFC 5627 §4.2
    /// says a non-2xx "does not remove, delete, or otherwise invalidate" one,
    /// and the binding they route to stands at the registrar until it lapses.
    pub(crate) fn refused(&mut self) {
        if let Some(info) = self.learned.as_mut() {
            info.service_route.clear();
        }
    }

    /// Whether a binding is believed to be live, which is what a refresh has
    /// to protect and a first registration does not.
    ///
    /// A restored one is not among them, deliberately. It is a binding on
    /// paper, and the whole point of naming it separately is that the wire has
    /// not confirmed it.
    pub(crate) const fn is_bound(&self) -> bool {
        matches!(
            self.state,
            RegistrationState::Registered | RegistrationState::Refreshing
        )
    }

    /// The registrar granted `granted`: note when it lapses, how long the cold
    /// start took, and answer with when to refresh.
    pub(crate) fn bound(
        &mut self,
        granted: Duration,
        cold: Option<Instant>,
        now: Instant,
    ) -> Duration {
        self.lapses_at = Some(now + granted);
        // the first time an account becomes reachable after a cold start is
        // the number the product cares about; every refresh after it is not a
        // cold start and does not overwrite it
        if let Some(cold) = cold
            && self.ready.is_none()
        {
            self.ready = Some(now.saturating_duration_since(cold));
        }
        refresh_within(granted, self.lead())
    }

    /// How long before the binding lapses the refresh has to be sent.
    ///
    /// Thirty seconds is ours, and it is a floor rather than a value: RFC 8599
    /// §4.1.4 lets the network demand more with a `sip.pnsreg` indicator, and
    /// a UA that gets one "MUST send a binding-refresh REGISTER request prior
    /// to binding expiration" at least that long before it. Taking the larger
    /// of the two is the only reading that satisfies both.
    fn lead(&self) -> u64 {
        self.echo
            .and_then(PushEcho::refresh_lead)
            .map_or(REFRESH_MARGIN, |lead| lead.as_secs().max(REFRESH_MARGIN))
    }
}

/// What the registrar said about push notifications in a 2xx to a REGISTER.
///
/// Nothing here changes whether the REGISTER worked. What it changes is what
/// the application may rely on afterwards: a phone that lets itself be
/// suspended because it believes the network will wake it, when the network
/// never said so, is a phone that stops ringing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PushEcho {
    accepted: bool,
    lead: Option<Duration>,
}

impl PushEcho {
    /// Whether the network said it will ask for notifications of the type this
    /// account asked for.
    ///
    /// §4.1.1: a 2xx carrying `sip.pns` "with an indicator value identifying
    /// the same type of PNS that was identified by the 'pn-provider' URI
    /// parameter" means another proxy will request them. Anything else — a
    /// different type, no indicator at all — means the UA "MUST NOT assume"
    /// they are coming.
    #[must_use]
    pub const fn accepted(self) -> bool {
        self.accepted
    }

    /// How long before the binding lapses the network insists on seeing a
    /// refresh, from a `sip.pnsreg` indicator (§4.1.4).
    ///
    /// Absent when the network sent none, which §4.1.4 turns into advice
    /// rather than a rule: a UA that can refresh on its own timer "SHOULD only
    /// send a binding-refresh REGISTER request when it receives a push
    /// notification". That advice is not taken here. It trades reachability
    /// for battery on the strength of a SHOULD, and nothing in this crate can
    /// tell whether the wake-ups are actually arriving — so the refresh timer
    /// keeps running, and an application that knows better stops it by taking
    /// the account down.
    #[must_use]
    pub const fn refresh_lead(self) -> Option<Duration> {
        self.lead
    }
}

/// What a 2xx to a REGISTER says about push, for an account that asked.
///
/// `Feature-Caps` is RFC 6809's, and RFC 8599 §8.2 puts the indicators in it:
/// `*;+sip.pns="apns";+sip.pnsreg="121"`. Several rows and one row with commas
/// are the same message (§7.3.1), so both are walked.
pub(crate) fn echoed(response: &RawMessage<'_>, account: &Account) -> Option<PushEcho> {
    let push = account.push.as_ref()?;
    let mut echo = PushEcho {
        accepted: false,
        lead: None,
    };
    for value in response.field_values(HeaderName::Extension("Feature-Caps")) {
        let (_, params) = Params::split(value);
        if let Some(named) = params.get("+sip.pns")
            && named.eq_ignore_ascii_case(push.provider().as_bytes())
        {
            echo.accepted = true;
        }
        if let Some(seconds) = params
            .get("+sip.pnsreg")
            .and_then(|value| digits(&value).ok())
            .and_then(|value| value.require().ok())
        {
            echo.lead = Some(Duration::from_secs(u64::from(seconds)));
        }
    }
    Some(echo)
}

/// What a registrar's 2xx said beyond how long the binding lasts.
///
/// Three things, each from its own RFC, and every one of them arrives from a
/// peer. Each is read with the core's parsers and bounded before it is kept,
/// and one that does not survive that is left out and written into the
/// REGISTER's diagnostic record rather than trusted: a value that goes back
/// out in this account's own requests is one that could otherwise stop every
/// one of them. None of it outlives the binding it came with; see
/// [`UserAgent::registrar_info`].
#[derive(Clone, Debug, Default)]
pub struct RegistrarInfo {
    service_route: Vec<Box<[u8]>>,
    public_gruu: Option<Uri>,
    temporary_gruu: Option<Uri>,
    associated: Vec<Uri>,
}

impl RegistrarInfo {
    /// The service route (RFC 3608) in the registrar's order, the first hop
    /// first, each entry a `Route` value as it goes out: angle brackets and
    /// parameters included.
    ///
    /// It is placed as a preloaded route on the requests this account starts
    /// towards the address it registers with — an INVITE, a SUBSCRIBE — and
    /// not on the REGISTER that refreshes the binding. §3 hands the route out
    /// "to request services from the system it just registered with", and a
    /// refresh sent along it would make a stale route unrecoverable: the one
    /// request that can replace it would have to travel it.
    #[must_use]
    pub fn service_route(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.service_route.iter().map(|hop| &**hop)
    }

    /// The public GRUU (RFC 5627 §3.1.1): the address of record with a `gr`
    /// parameter naming this instance, the same across registrations.
    #[must_use]
    pub const fn public_gruu(&self) -> Option<&Uri> {
        self.public_gruu.as_ref()
    }

    /// The temporary GRUU from this 2xx (RFC 5627 §3.1.2), which names neither
    /// the address of record nor the instance, and is new on every refresh.
    #[must_use]
    pub const fn temporary_gruu(&self) -> Option<&Uri> {
        self.temporary_gruu.as_ref()
    }

    /// The other identities the provider has given this user (RFC 7315 §4.1),
    /// in the order they were sent.
    ///
    /// Reported and not acted on. §4.1 says a UAC "MUST NOT assume that the
    /// associated URIs are registered", so none of them changes what this
    /// account sends.
    #[must_use]
    pub fn associated(&self) -> &[Uri] {
        &self.associated
    }

    /// Which GRUU a dialog opens with.
    ///
    /// RFC 5627 §3.3: "use one of its temporary GRUUs for anonymous calls, and
    /// use its public GRUU otherwise", and §4.4 lets either be used where the
    /// other is missing — except that an anonymous request never falls back to
    /// the public one, which names the address of record it is trying not to.
    const fn gruu_for(&self, anonymous: bool) -> Option<&Uri> {
        if anonymous {
            return self.temporary_gruu.as_ref();
        }
        match self.public_gruu {
            Some(ref public) => Some(public),
            None => self.temporary_gruu.as_ref(),
        }
    }
}

/// Everything a 2xx to a REGISTER says beyond the binding, and the codes for
/// what in it could not be read.
pub(crate) fn read_registrar_info(
    response: &RawMessage<'_>,
    account: &Account,
) -> (RegistrarInfo, Vec<Reason>) {
    let mut ignored = Vec::new();
    let service_route = read_service_route(response).unwrap_or_else(|| {
        ignored.push(Reason::ServiceRouteIgnored);
        Vec::new()
    });
    let (public, temporary) = offered_gruus(response, account);
    if matches!(public, Offered::Garbled) || matches!(temporary, Offered::Garbled) {
        ignored.push(Reason::GruuIgnored);
    }
    let associated = read_associated(response).unwrap_or_else(|| {
        ignored.push(Reason::AssociatedUriIgnored);
        Vec::new()
    });
    let info = RegistrarInfo {
        service_route,
        public_gruu: public.readable(),
        temporary_gruu: temporary.readable(),
        associated,
    };
    (info, ignored)
}

/// RFC 3608 §5: `Service-Route = "Service-Route" HCOLON sr-value *(COMMA
/// sr-value)`, each value a `Route` element that "MUST include the
/// loose-routing indicator parameter".
///
/// `None` when any of it cannot be taken. A route is an order of hops, and one
/// with a hop left out of it goes somewhere else.
fn read_service_route(response: &RawMessage<'_>) -> Option<Vec<Box<[u8]>>> {
    let mut hops = Vec::new();
    for value in response.field_values(SERVICE_ROUTE) {
        if hops.len() == MAX_SERVICE_ROUTE {
            return None;
        }
        let flat = one_line(value)?;
        let entry = RouteRef::parse(&flat).ok()?;
        // a strict router would need the Request-URI rewritten (§12.2.1.1),
        // which nothing does for a preloaded route here, and §5 rules one out
        let hop = entry.uri().sip()?;
        if !hop.is_loose_route()
            || hop.headers().next().is_some()
            || !uri_bytes_only(entry.addr().uri_bytes())
        {
            return None;
        }
        hops.push(Box::from(&*flat));
    }
    Some(hops)
}

/// Whether every byte is one a SIP URI is written with (RFC 3261 §25.1):
/// `alphanum`, the `mark` characters, `%` for an escape, the `reserved` set,
/// and the square brackets of an IPv6 reference and of `param-unreserved`.
///
/// The core's URI reader splits a URI at its delimiters and leaves the bytes
/// between them alone, which is right for a message that is only being read.
/// A value kept here is written back into this account's own requests, and a
/// `<`, `>`, `"` or space inside it would change where the header it sits in
/// ends.
fn uri_bytes_only(text: &[u8]) -> bool {
    text.iter()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.!~*'()%;/?:@&=+$,[]".contains(byte))
}

/// What the registrar's `Contact` for this instance says about one GRUU.
enum Offered {
    Absent,
    Readable(Uri),
    Garbled,
}

impl Offered {
    fn readable(self) -> Option<Uri> {
        match self {
            Self::Readable(uri) => Some(uri),
            Self::Absent | Self::Garbled => None,
        }
    }
}

/// The GRUUs on the `Contact` the registrar returned for this instance
/// (RFC 5627 §4.2), public first.
///
/// The response lists every binding the address of record has, and another
/// device's GRUUs are not this one's to use, so the entry is found by its
/// `+sip.instance` rather than by its address — which is also what survives a
/// registrar that rewrote the address behind a NAT. An entry that does not
/// parse cannot be shown to be this instance's, and is passed over.
fn offered_gruus(response: &RawMessage<'_>, account: &Account) -> (Offered, Offered) {
    let nothing = (Offered::Absent, Offered::Absent);
    let Some(ref instance) = account.instance_id else {
        return nothing;
    };
    let Ok(Contacts::Addrs(addrs)) = response.contact() else {
        return nothing;
    };
    for addr in addrs.flatten() {
        let params = addr.params();
        let ours = params
            .get("+sip.instance")
            .is_some_and(|echoed| same_instance(&echoed, instance));
        // a stated zero is a binding the registrar removed, and §5.3 removes
        // its GRUUs with it
        let removed = addr
            .expires()
            .ok()
            .flatten()
            .is_some_and(|seconds| seconds.value == Some(0));
        if ours && !removed {
            return (
                gruu_param(&params, "pub-gruu"),
                gruu_param(&params, "temp-gruu"),
            );
        }
    }
    nothing
}

/// Whether an echoed `+sip.instance` names this instance.
///
/// RFC 5626 §4.1: the instance identifier is "extracted" from the value, out
/// of the angle brackets RFC 3840 §9 wraps a string value in, and "equality
/// comparisons are performed using the rules for URN equality that are
/// specific to the scheme in the URN", or lexically by RFC 2141 where the
/// scheme is not understood. Lexically, `urn:` and the namespace identifier are
/// compared without regard to case and the rest exactly; `uuid` is the one
/// namespace understood here, and RFC 4122 §3 makes its hexadecimal case
/// insensitive as well. The account may be configured with or without the
/// brackets, so they are taken off both sides.
fn same_instance(echoed: &[u8], ours: &str) -> bool {
    let (theirs, mine) = (bare_urn(echoed), bare_urn(ours.as_bytes()));
    match (urn_parts(theirs), urn_parts(mine)) {
        (Some((their_namespace, their_rest)), Some((my_namespace, my_rest))) => {
            let uuid = my_namespace.eq_ignore_ascii_case(b"uuid");
            their_namespace.eq_ignore_ascii_case(my_namespace)
                && (their_rest == my_rest || (uuid && their_rest.eq_ignore_ascii_case(my_rest)))
        }
        _ => theirs == mine,
    }
}

/// `urn:<namespace>:<rest>`, split, or `None` for what is not a URN.
fn urn_parts(value: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = value.iter().position(|byte| *byte == b':')?;
    if !value.get(..colon)?.eq_ignore_ascii_case(b"urn") {
        return None;
    }
    let rest = value.get(colon + 1..)?;
    let colon = rest.iter().position(|byte| *byte == b':')?;
    Some((rest.get(..colon)?, rest.get(colon + 1..)?))
}

fn bare_urn(value: &[u8]) -> &[u8] {
    value
        .strip_prefix(b"<")
        .and_then(|inner| inner.strip_suffix(b">"))
        .unwrap_or(value)
}

/// One of `pub-gruu` and `temp-gruu`: `EQUAL quoted-string`, and the quoted
/// string "MUST contain a SIP URI" (RFC 5627 §7). A GRUU is known by its `gr`
/// parameter (§4.5), so a URI without one is not taken for one.
fn gruu_param(params: &Params<'_>, name: &str) -> Offered {
    let mut named = params
        .clone()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name.as_bytes()));
    let Some((_, written)) = named.next() else {
        return Offered::Absent;
    };
    // two values for one GRUU are two answers to one question, and taking
    // either is guessing which one the registrar meant
    if named.next().is_some() {
        return Offered::Garbled;
    }
    let Some(written) = written.filter(|value| is_quoted(value)) else {
        return Offered::Garbled;
    };
    gruu_uri(&unquote(written)).map_or(Offered::Garbled, Offered::Readable)
}

fn gruu_uri(text: &[u8]) -> Option<Uri> {
    let flat = one_line(text)?;
    // the value came out of a quoted string and goes back in angle brackets,
    // where a `>` it held would end the Contact and whatever followed would
    // become a second one
    if !uri_bytes_only(&flat) {
        return None;
    }
    let uri = Uri::parse(&flat).ok()?;
    let usable = uri
        .sip()
        .is_some_and(|sip| sip.has_param("gr") && sip.headers().next().is_none());
    usable.then_some(uri)
}

/// RFC 7315 §4.1: `P-Associated-URI = "P-Associated-URI" HCOLON
/// [p-aso-uri-spec] *(COMMA p-aso-uri-spec)`, `p-aso-uri-spec = name-addr
/// *(SEMI ai-param)`. A field with nothing in it is the grammar's own way of
/// saying there are none.
///
/// `None` when an entry cannot be read, or when there are more than are kept.
/// The response rides on the event whole, so nothing is lost to the
/// application by refusing the list rather than guessing at part of it.
fn read_associated(response: &RawMessage<'_>) -> Option<Vec<Uri>> {
    let values = response.field_values(P_ASSOCIATED_URI);
    if values.clone().all(<[u8]>::is_empty) {
        return Some(Vec::new());
    }
    let mut uris = Vec::new();
    for value in values {
        if uris.len() == MAX_ASSOCIATED {
            return None;
        }
        let flat = one_line(value)?;
        let addr = NameAddrRef::parse(&flat).ok()?;
        if !addr.is_name_addr() {
            return None;
        }
        uris.push(Uri::parse(addr.uri_bytes()).ok()?);
    }
    Some(uris)
}

/// A value from the wire as one line: a fold becomes the space it stands for
/// (§7.3.1), and anything else that could end or corrupt a header this stack
/// writes is refused.
///
/// What is kept here goes back out in the account's own requests, and a byte
/// that made the builder refuse one would stop every INVITE the account sends
/// until the next registration replaced it.
fn one_line(value: &[u8]) -> Option<Cow<'_, [u8]>> {
    if value.len() > MAX_LEARNED_BYTES {
        return None;
    }
    let flat = unfold(value);
    if flat
        .iter()
        .any(|&byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
    {
        return None;
    }
    Some(flat)
}

/// The `Contact` of a request or a response that opens a dialog for `account`.
///
/// RFC 5627 §4.4: "A UA SHOULD use a GRUU when populating the Contact header
/// field of dialog-forming and target refresh requests and responses", which
/// is the INVITE, the 18x and 2xx that answer one, and the SUBSCRIBE. The GRUU
/// goes out bare, without `+sip.instance`: §9's examples write it so, the
/// public one carries the instance in its `gr` already, and on a temporary one
/// the instance is exactly what §10.3 says a correspondent must not be able to
/// read.
pub(crate) fn dialog_contact(
    account: &Account,
    learned: Option<&RegistrarInfo>,
    anonymous: bool,
) -> Box<[u8]> {
    let Some(gruu) = learned.and_then(|info| info.gruu_for(anonymous)) else {
        return account.contact_value();
    };
    let text = gruu.as_bytes();
    let mut out = Vec::with_capacity(text.len() + 2);
    out.push(b'<');
    out.extend_from_slice(text);
    out.push(b'>');
    out.into_boxed_slice()
}

/// Whether a request asks for privacy (RFC 3323 §4.2): a `Privacy` field with
/// any value but `none` among the ones the application added.
pub(crate) fn anonymous(extra: &[Extra]) -> bool {
    extra
        .iter()
        .filter(|one| one.name.eq_ignore_ascii_case(b"Privacy"))
        .flat_map(|one| one.value.split(|byte| *byte == b';'))
        .map(trim)
        .any(|value| !value.is_empty() && !value.eq_ignore_ascii_case(b"none"))
}

/// When to send the next request for something granted for `granted`, with
/// this crate's own margin.
///
/// See the module note. Zero in means the binding or the subscription was
/// removed, and there is nothing to refresh.
pub(crate) fn refresh_after(granted: Duration) -> Duration {
    refresh_within(granted, REFRESH_MARGIN)
}

/// The same, for a registration the network insists on seeing refreshed
/// `lead` seconds before it lapses (RFC 8599 §4.1.4).
///
/// A `lead` longer than the binding itself is a network contradicting itself,
/// and the floor answers it: halfway, which is the soonest this is willing to
/// turn into a metronome.
fn refresh_within(granted: Duration, lead: u64) -> Duration {
    let seconds = granted.as_secs();
    if seconds == 0 {
        return Duration::ZERO;
    }
    let fraction = seconds.saturating_mul(REFRESH_FRACTION) / 100;
    let margin = seconds.saturating_sub(lead);
    // never sooner than halfway, and never zero: a binding of a second or two
    // is a registrar being strange, and answering it with a spin is worse
    let floor = (seconds / 2).max(1);
    Duration::from_secs(fraction.min(margin).max(floor))
}

/// RFC 5626 §4.5's upper bound after `failures` consecutive failures.
///
/// `W = min(max-time, base-time · 2^consecutive-failures)`.
pub(crate) fn backoff_bound(failures: u32) -> Duration {
    let doublings = failures.min(BACKOFF_CEILING);
    let scaled = BACKOFF_BASE.saturating_mul(1_u64 << doublings);
    Duration::from_secs(scaled.min(BACKOFF_MAX))
}

/// "a uniform random time between 50 and 100% of the upper-bound wait time",
/// spread by `entropy`.
///
/// `entropy` is a token from the endpoint's own stream, which is hexadecimal;
/// its first eight characters are thirty-two bits drawn from that stream. The
/// modulo is biased by less than one part in a hundred million over these
/// ranges, which is far below the second this value is rounded to.
pub(crate) fn backoff_delay(failures: u32, entropy: &[u8]) -> Duration {
    let bound = backoff_bound(failures).as_secs();
    let half = bound / 2;
    let span = bound - half;
    if span == 0 {
        return Duration::from_secs(bound);
    }
    Duration::from_secs(half + u64::from(spread(entropy)) % (span + 1))
}

/// Thirty-two bits off the front of a hexadecimal token.
pub(crate) fn spread(entropy: &[u8]) -> u32 {
    let mut value = 0_u32;
    for byte in entropy.iter().take(8) {
        let digit = match *byte {
            b'0'..=b'9' => u32::from(*byte - b'0'),
            b'a'..=b'f' => u32::from(*byte - b'a') + 10,
            b'A'..=b'F' => u32::from(*byte - b'A') + 10,
            _ => 0,
        };
        value = (value << 4) | digit;
    }
    value
}

/// How long the registrar says the binding lasts (§10.2.4).
///
/// The `expires` parameter of the `Contact` it echoed back for us wins, then
/// the `Expires` header field, then what was asked for. Our own contact is
/// found by §19.1.4 equivalence rather than by byte comparison, because a
/// registrar is allowed to normalise what it stores.
///
/// A contact list that does not name us is not read as a removal. Registrars
/// rewrite addresses behind a NAT, and concluding "the binding was refused"
/// from an address that no longer matches would drop a working registration.
/// Only a stated zero means removed.
pub(crate) fn granted_expiry(
    response: &RawMessage<'_>,
    ours: &Uri,
    asked: Duration,
) -> Option<Duration> {
    if let Some(seconds) = ours_in(response, ours) {
        return Some(Duration::from_secs(u64::from(seconds)));
    }
    match response.expires() {
        Ok(value) => value
            .require()
            .ok()
            .map(|seconds| Duration::from_secs(u64::from(seconds))),
        Err(HeaderError::Missing) => Some(asked),
        Err(_) => None,
    }
}

/// The `expires` parameter on the contact the registrar echoed back for us.
fn ours_in(response: &RawMessage<'_>, ours: &Uri) -> Option<u32> {
    let Ok(Contacts::Addrs(addrs)) = response.contact() else {
        return None;
    };
    for addr in addrs {
        let Ok(addr) = addr else {
            continue;
        };
        let Ok(uri) = Uri::parse(addr.uri_bytes()) else {
            continue;
        };
        if !ours.equivalent(&uri) {
            continue;
        }
        return addr.expires().ok().flatten().and_then(|d| d.require().ok());
    }
    None
}

/// The `Min-Expires` of a 423, which §10.2.8 asks the next attempt to meet.
pub(crate) fn min_expires(response: &RawMessage<'_>) -> Option<Duration> {
    let value = response.header(sipral_core::msg::HeaderName::MinExpires)?;
    digits(value)
        .ok()?
        .require()
        .ok()
        .map(|seconds| Duration::from_secs(u64::from(seconds)))
}

/// A `Retry-After` in seconds, which RFC 5626 §4.5 lets extend the back-off.
///
/// Only the delta-seconds are read. The header can also carry a comment and
/// parameters, and neither changes when to come back.
pub(crate) fn retry_after(response: &RawMessage<'_>) -> Option<Duration> {
    let value = response.header(sipral_core::msg::HeaderName::RetryAfter)?;
    let seconds = value
        .iter()
        .copied()
        .skip_while(u8::is_ascii_whitespace)
        .take_while(u8::is_ascii_digit)
        .collect::<Vec<u8>>();
    digits(&seconds)
        .ok()?
        .require()
        .ok()
        .map(|seconds| Duration::from_secs(u64::from(seconds)))
}

/// Why a snapshot could not be read back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SnapshotError {
    /// It does not begin with what every snapshot begins with. Whatever those
    /// bytes are, they are not a registration.
    NotASnapshot,
    /// Written by a version of this stack that knows a layout this one does
    /// not. Read as far as it goes and the fields land in the wrong places,
    /// so it is refused instead.
    FromTheFuture {
        /// The version it claims to be.
        version: u16,
    },
    /// It ends inside a field, or has bytes left over after the last one.
    Malformed,
    /// The address of record in it is not this account's. A binding belongs to
    /// one identity, and restoring somebody else's would register this device
    /// as them.
    AnotherAccount,
    /// The account never registers
    /// ([`Account::unregistered`](crate::Account::unregistered)), so there is
    /// no binding for a snapshot to continue.
    NotRegistering,
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NotASnapshot => f.write_str("not a registration snapshot"),
            Self::FromTheFuture { version } => {
                write!(f, "snapshot version {version} is newer than this build")
            }
            Self::Malformed => f.write_str("the snapshot is truncated or has trailing bytes"),
            Self::AnotherAccount => {
                f.write_str("the snapshot belongs to another address of record")
            }
            Self::NotRegistering => {
                f.write_str("the account never registers, so there is no binding to restore")
            }
        }
    }
}

impl core::error::Error for SnapshotError {}

/// A registration written down, so that waking up does not cost a whole
/// handshake.
///
/// One layout, version 1, every number big-endian:
///
/// | bytes | what |
/// |---|---|
/// | 4 | `SPRG` |
/// | 2 | version |
/// | 4 | the sequence number the next REGISTER continues from |
/// | 4 | seconds the registrar granted |
/// | 4 | seconds the binding still had when this was written |
/// | 2 + n | the `Call-ID`, and its length |
/// | 2 + m | the address of record, and its length |
///
/// The rule about versions is the whole reason there is a version. A reader
/// takes every layout it was built to understand and refuses every other one,
/// which means a snapshot from a newer build is an error and never a
/// misreading: fields that moved would still parse, into the wrong meanings,
/// and a sequence number read out of a length would produce REGISTERs the
/// registrar answers with 400 for as long as the file exists. Adding a field
/// means version 2, never a longer version 1.
///
/// It is written by hand because that is the only way to promise the above.
/// There is no schema language in this workspace and no dependency that brings
/// one, and a format whose compatibility rule is enforced by twenty lines that
/// can be read in one sitting is worth more than one where it is implied.
fn freeze(reg: &Registration, aor: &Uri, now: Instant) -> Vec<u8> {
    let call_id = reg.call_id.as_bytes();
    let aor = aor.as_bytes();
    let left = reg
        .lapses_at
        .map_or(Duration::ZERO, |at| at.saturating_duration_since(now));
    let mut out = Vec::with_capacity(SNAPSHOT_HEAD + call_id.len() + aor.len() + 2);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&SNAPSHOT_VERSION.to_be_bytes());
    out.extend_from_slice(&reg.cseq.to_be_bytes());
    out.extend_from_slice(&seconds_of(reg.asking).to_be_bytes());
    out.extend_from_slice(&seconds_of(left).to_be_bytes());
    out.extend_from_slice(&length_of(call_id).to_be_bytes());
    out.extend_from_slice(call_id);
    out.extend_from_slice(&length_of(aor).to_be_bytes());
    out.extend_from_slice(aor);
    out
}

/// What one holds, checked as far as the bytes go.
struct Thawed {
    cseq: u32,
    granted: Duration,
    left: Duration,
    call_id: CallId,
    aor: Uri,
}

fn thaw(snapshot: &[u8]) -> Result<Thawed, SnapshotError> {
    let head = snapshot
        .get(..SNAPSHOT_HEAD)
        .ok_or(SnapshotError::NotASnapshot)?;
    if head.get(..4) != Some(MAGIC) {
        return Err(SnapshotError::NotASnapshot);
    }
    let version = be16(head, 4).ok_or(SnapshotError::Malformed)?;
    if version != SNAPSHOT_VERSION {
        return Err(SnapshotError::FromTheFuture { version });
    }
    let cseq = be32(head, 6).ok_or(SnapshotError::Malformed)?;
    let granted = be32(head, 10).ok_or(SnapshotError::Malformed)?;
    let left = be32(head, 14).ok_or(SnapshotError::Malformed)?;
    let call_id_len = usize::from(be16(head, 18).ok_or(SnapshotError::Malformed)?);

    let rest = snapshot
        .get(SNAPSHOT_HEAD..)
        .ok_or(SnapshotError::Malformed)?;
    let call_id = rest.get(..call_id_len).ok_or(SnapshotError::Malformed)?;
    let rest = rest.get(call_id_len..).ok_or(SnapshotError::Malformed)?;
    let aor_len = usize::from(be16(rest, 0).ok_or(SnapshotError::Malformed)?);
    let aor = rest.get(2..2 + aor_len).ok_or(SnapshotError::Malformed)?;
    // bytes after the last field mean this is not the document it says it is,
    // and reading the part that parsed would be reading half of something else
    if rest.len() != 2 + aor_len {
        return Err(SnapshotError::Malformed);
    }
    Ok(Thawed {
        cseq,
        granted: Duration::from_secs(u64::from(granted)),
        left: Duration::from_secs(u64::from(left)),
        call_id: CallId::new(call_id),
        aor: Uri::parse(aor).map_err(|_| SnapshotError::Malformed)?,
    })
}

fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]))
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *bytes.get(at)?,
        *bytes.get(at + 1)?,
        *bytes.get(at + 2)?,
        *bytes.get(at + 3)?,
    ]))
}

/// Seconds that fit the field. A binding longer than a hundred and thirty-six
/// years is a registrar being strange, and the snapshot says so rather than
/// wrapping.
fn seconds_of(duration: Duration) -> u32 {
    u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
}

fn length_of(bytes: &[u8]) -> u16 {
    u16::try_from(bytes.len()).unwrap_or(u16::MAX)
}

impl UserAgent {
    /// Write an account's registration down, so a later start can continue it.
    ///
    /// `None` when there is nothing worth keeping: an account that has never
    /// registered, one that never will, or one whose registration failed, has
    /// no binding for a snapshot to be about.
    ///
    /// What comes back is opaque bytes with a version in them. Storing them is
    /// the application's, and so is protecting them — a snapshot names an
    /// address of record and is not a secret, but it is a record of who uses
    /// this device.
    #[must_use]
    pub fn freeze_registration(&self, account: AccountId, now: Instant) -> Option<Vec<u8>> {
        let config = self.accounts.get(&account)?;
        let reg = self.registrations.get(&account)?;
        if !reg.is_bound() && reg.state != RegistrationState::Restored {
            return None;
        }
        Some(freeze(reg, &config.aor, now))
    }

    /// Read one back, for an account that has been added and has not
    /// registered.
    ///
    /// `asleep` is how long the snapshot sat unused. This crate never reads a
    /// clock, and a monotonic instant does not survive the process that minted
    /// it, so the only honest source for that number is the application: it
    /// has the wall clock, and it is the one that knows whether this is a wake
    /// from suspend or a cold launch a week later.
    ///
    /// **What is restored, and what is not.** The `Call-ID` and the sequence
    /// number come back, and they are what make the next REGISTER a refresh of
    /// the binding the registrar is still holding rather than a second
    /// registration for the same device — that is the whole saving. The
    /// binding's remaining life comes back too, and only as a schedule: the
    /// refresh is booked for where it would have fallen, or for now if it has
    /// already passed.
    ///
    /// What does not come back is any belief that this device is reachable.
    /// The account is [`RegistrationState::Restored`], never `Registered`, and
    /// nothing may be inferred from it — not that the registrar still has the
    /// binding, not that the address in the `Contact` is still this device's,
    /// not that the registrar's name still resolves. A restored registration
    /// that read as valid while name resolution had gone is a failure this
    /// project has actually had, and the distinction between these two states
    /// is what makes it un-representable.
    ///
    /// # Errors
    /// [`SnapshotError`], and the account is left exactly as it was.
    pub fn thaw_registration(
        &mut self,
        account: AccountId,
        snapshot: &[u8],
        asleep: Duration,
        now: Instant,
    ) -> Result<(), SnapshotError> {
        let thawed = thaw(snapshot)?;
        let config = self
            .accounts
            .get(&account)
            .ok_or(SnapshotError::AnotherAccount)?;
        // restored, it would book a refresh that can never be sent, and the
        // back-off would retry that refusal for the life of the process
        if config.registrar.is_none() {
            return Err(SnapshotError::NotRegistering);
        }
        if !config.aor.equivalent(&thawed.aor) {
            return Err(SnapshotError::AnotherAccount);
        }
        let left = thawed.left.saturating_sub(asleep);
        let Some(reg) = self.registrations.get_mut(&account) else {
            return Err(SnapshotError::AnotherAccount);
        };
        reg.call_id = thawed.call_id;
        reg.cseq = thawed.cseq;
        reg.asking = thawed.granted;
        reg.state = RegistrationState::Restored;
        reg.failures = 0;
        reg.raised = false;
        reg.lapses_at = Some(now + left);
        reg.ready = None;
        // a thaw puts the snapshot's Call-ID in place of the one the GRUUs
        // were learned under, and RFC 5627 §4.2 has a UA on another Call-ID
        // "discard all temporary GRUUs learned through prior REGISTER
        // responses"; a restored registration proves nothing either, so it
        // carries nothing until the next 2xx says it all again
        reg.learned = None;
        // the same schedule a fresh grant of what is left would have earned,
        // which is now when there is nothing left
        reg.due = Some(now + refresh_after(left));
        Ok(())
    }

    /// How long the binding an account holds is believed to last.
    ///
    /// Believed, and no stronger than that: for a restored registration this
    /// is what a registrar said before the device went to sleep, and nothing
    /// has spoken to it since.
    ///
    /// `None` for an account that holds no binding at all, which includes one
    /// that has just given its up — the last grant it was told about is not
    /// news about a binding that no longer exists.
    #[must_use]
    pub fn binding_expires_in(&self, account: AccountId, now: Instant) -> Option<Duration> {
        let reg = self.registrations.get(&account)?;
        if !reg.is_bound() && reg.state != RegistrationState::Restored {
            return None;
        }
        reg.lapses_at.map(|at| at.saturating_duration_since(now))
    }

    /// A cold start began now.
    ///
    /// The stack cannot know this by itself. The process was launched, or
    /// woken, before any of this existed, and reading a clock to find out is
    /// the one thing the protocol crates may not do — so the instant comes
    /// from the application, which has it.
    ///
    /// Every account's [`UserAgent::time_to_ready`] is cleared, and each is
    /// measured again the next time it registers.
    pub fn cold_start(&mut self, now: Instant) {
        self.cold = Some(now);
        for reg in self.registrations.values_mut() {
            reg.ready = None;
        }
    }

    /// How long this account took to become reachable, measured from
    /// [`UserAgent::cold_start`].
    ///
    /// This is the number a queue needs. How long it rings each agent before
    /// giving up and trying the next one has to be longer than this, or a
    /// phone that was asleep is skipped every time and its owner is told the
    /// queue was quiet. `None` until an account has registered; `None` always
    /// for an account that never registers, because nothing marks the moment
    /// one of those became reachable; and `None` always if no cold start was
    /// ever declared.
    #[must_use]
    pub fn time_to_ready(&self, account: AccountId) -> Option<Duration> {
        self.registrations.get(&account)?.ready
    }

    /// What the registrar last said about push notifications (RFC 8599
    /// §4.1.1).
    ///
    /// `None` for an account that did not ask for any, and for one that has
    /// asked and not yet been answered.
    #[must_use]
    pub fn push_echo(&self, account: AccountId) -> Option<PushEcho> {
        self.registrations.get(&account)?.echo
    }

    /// What an account's registrar said beside the binding: the service route,
    /// the GRUUs, the associated identities.
    ///
    /// `None` while no binding it said them about is standing — none granted
    /// yet, one given up, or one that has lapsed — because none of the three
    /// means anything once the binding is gone, and RFC 5627 §4.4 forbids
    /// using a GRUU from one that has.
    #[must_use]
    pub fn registrar_info(&self, account: AccountId, now: Instant) -> Option<&RegistrarInfo> {
        self.registrations.get(&account)?.learned(now)
    }

    /// The same, for something this account sends to `destination`, where
    /// `None` is the address the account registers with.
    ///
    /// Nothing when it goes anywhere else. Both halves are about that path: a
    /// service route is the rest of the route behind the proxy the account
    /// registers through (RFC 3608 §6.1 appends it "to any locally configured
    /// route needed to egress the access proxy chain"), and a GRUU is reached
    /// through the registrar's domain. A request the application sent
    /// somewhere else on purpose would be pulled back through the network it
    /// chose not to use, and so would everything the far end sent back to it.
    pub(crate) fn learned_for(
        &self,
        account: AccountId,
        destination: Option<(TransportId, SocketAddr)>,
        now: Instant,
    ) -> Option<&RegistrarInfo> {
        let config = self.accounts.get(&account)?;
        if destination.is_some_and(|path| path != (config.transport, config.remote)) {
            return None;
        }
        self.registrar_info(account, now)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BACKOFF_MAX, MAGIC, Registration, SNAPSHOT_VERSION, SnapshotError, backoff_bound,
        backoff_delay, freeze, refresh_after, refresh_within, spread, thaw,
    };
    use crate::event::RegistrationState;
    use sipral_core::dialog::CallId;
    use sipral_core::msg::Uri;
    use std::time::{Duration, Instant};

    fn frozen(now: Instant) -> Vec<u8> {
        let mut reg = Registration::new(CallId::new(b"boot-cycle-1"), Duration::from_hours(1));
        reg.state = RegistrationState::Registered;
        reg.cseq = 7;
        reg.lapses_at = Some(now + Duration::from_secs(3_000));
        freeze(
            &reg,
            &Uri::parse_str("sip:alice@example.com").expect("an address of record"),
            now,
        )
    }

    #[test]
    fn a_snapshot_carries_the_call_id_and_the_sequence_number_a_refresh_needs() {
        let now = Instant::now();
        let bytes = frozen(now);
        let back = thaw(&bytes).expect("a snapshot this build wrote");
        assert_eq!(back.call_id.as_bytes(), b"boot-cycle-1");
        assert_eq!(back.cseq, 7);
        assert_eq!(back.granted, Duration::from_hours(1));
        assert_eq!(back.left, Duration::from_secs(3_000));
        assert_eq!(back.aor.as_bytes(), b"sip:alice@example.com");
    }

    #[test]
    fn a_snapshot_from_a_later_version_is_refused_rather_than_read() {
        let now = Instant::now();
        let mut bytes = frozen(now);
        let next = SNAPSHOT_VERSION + 1;
        bytes.splice(4..6, next.to_be_bytes());
        assert_eq!(
            thaw(&bytes).err(),
            Some(SnapshotError::FromTheFuture { version: next })
        );
    }

    #[test]
    fn anything_that_is_not_a_snapshot_is_not_read_as_one() {
        assert_eq!(thaw(b"").err(), Some(SnapshotError::NotASnapshot));
        assert_eq!(
            thaw(b"not a snapshot at all").err(),
            Some(SnapshotError::NotASnapshot)
        );
        // the magic is right and the rest is missing
        let mut short = MAGIC.to_vec();
        short.extend_from_slice(&SNAPSHOT_VERSION.to_be_bytes());
        assert_eq!(thaw(&short).err(), Some(SnapshotError::NotASnapshot));
    }

    #[test]
    fn a_snapshot_that_ends_early_or_runs_long_is_refused() {
        let now = Instant::now();
        let bytes = frozen(now);
        let cut = bytes.len() - 3;
        assert_eq!(
            thaw(bytes.get(..cut).expect("a shorter snapshot")).err(),
            Some(SnapshotError::Malformed)
        );
        let mut extra = bytes;
        extra.push(0);
        assert_eq!(thaw(&extra).err(), Some(SnapshotError::Malformed));
    }

    #[test]
    fn a_refresh_leaves_room_for_a_lost_register_and_a_retransmission() {
        // an hour: 0.85 of it, well clear of the last thirty seconds
        assert_eq!(
            refresh_after(Duration::from_secs(3_600)),
            Duration::from_secs(3_060)
        );
        // two minutes: the thirty-second margin bites before the fraction does
        assert_eq!(
            refresh_after(Duration::from_secs(120)),
            Duration::from_secs(90)
        );
        // one minute: both agree
        assert_eq!(
            refresh_after(Duration::from_secs(60)),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn a_network_that_demands_a_longer_lead_gets_an_earlier_refresh() {
        // RFC 8599 4.1.4's example: sip.pnsreg="121" on a two-hour binding
        assert_eq!(
            refresh_within(Duration::from_secs(7_200), 121),
            Duration::from_secs(6_120),
            "the fraction is still earlier than the lead demands"
        );
        assert_eq!(
            refresh_within(Duration::from_secs(400), 121),
            Duration::from_secs(279),
            "the lead bites before the fraction does"
        );
        assert_eq!(
            refresh_within(Duration::from_secs(120), 121),
            Duration::from_secs(60),
            "a lead longer than the binding is answered by the floor"
        );
    }

    #[test]
    fn a_very_short_binding_does_not_turn_the_client_into_a_metronome() {
        // the margin would ask for a refresh at once, and the floor stops it
        for seconds in [1_u64, 5, 20, 30, 45] {
            let granted = Duration::from_secs(seconds);
            let after = refresh_after(granted);
            assert!(
                after.as_secs() >= seconds / 2 && !after.is_zero(),
                "{seconds}s granted refreshes after {after:?}"
            );
            assert!(after <= granted, "{seconds}s granted refreshes too late");
        }
    }

    #[test]
    fn a_removed_binding_has_nothing_to_refresh() {
        assert_eq!(refresh_after(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn the_backoff_doubles_and_then_stops() {
        // RFC 5626 4.5's worked example: base 30, three failures, 240 seconds
        assert_eq!(backoff_bound(0), Duration::from_secs(30));
        assert_eq!(backoff_bound(3), Duration::from_secs(240));
        assert_eq!(backoff_bound(6), Duration::from_secs(1_800));
        assert_eq!(
            backoff_bound(u32::MAX),
            Duration::from_secs(BACKOFF_MAX),
            "no shift overflow, however long the outage"
        );
    }

    #[test]
    fn the_wait_lands_between_half_the_bound_and_the_bound() {
        // "a uniform random time between 50 and 100% of the upper-bound"
        let mut seen = std::collections::HashSet::new();
        for nonce in 0_u32..500 {
            let token = format!("{nonce:08x}{nonce:08x}").into_bytes();
            let delay = backoff_delay(3, &token);
            assert!(delay >= Duration::from_secs(120), "{delay:?}");
            assert!(delay <= Duration::from_secs(240), "{delay:?}");
            seen.insert(delay);
        }
        assert!(seen.len() > 100, "the draw is barely moving");
    }

    #[test]
    fn the_first_retry_after_a_boot_failure_lands_where_the_rfc_says() {
        // "the first retry happens somewhere between 30 and 60 seconds after
        // the failure of the first registration request" - one failure, so the
        // bound has doubled once
        for nonce in 0_u32..200 {
            let token = format!("{nonce:016x}").into_bytes();
            let delay = backoff_delay(1, &token);
            assert!(delay >= Duration::from_secs(30), "{delay:?}");
            assert!(delay <= Duration::from_secs(60), "{delay:?}");
        }
    }

    #[test]
    fn a_token_that_is_not_hexadecimal_still_yields_a_number() {
        assert_eq!(spread(b"0000000f"), 15);
        assert_eq!(spread(b"ffffffff"), u32::MAX);
        assert_eq!(spread(b""), 0);
    }
}
