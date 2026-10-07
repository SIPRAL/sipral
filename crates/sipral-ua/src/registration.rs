// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Keeping a binding alive, and knowing when to stop trying.
//!
//! **When to refresh.** RFC 3261 §10.2.4 says only "before the expiration
//! interval has elapsed". Cutting it fine loses the binding to one lost
//! datagram. So the refresh goes at 0.85 of the grant, no later than 30 s
//! before it lapses (room for a lost REGISTER and a retransmission round),
//! and no sooner than halfway, so very short bindings do not make the client
//! spin.
//!
//! **How long to wait.** RFC 5626 §4.5: `W = min(max, base · 2^n)`, the wait
//! drawn uniformly between W/2 and W, so phones that lost the same server do
//! not all come back in the same second. A 403 or a refused password is not
//! retried: re-sending it gets accounts locked out.
//!
//! **Freezing and thawing.** The `Call-ID` and CSeq are what make the next
//! REGISTER a refresh rather than a new binding, so they are saved across a
//! sleep. The belief that the binding works is not: a thawed account is
//! [`RegistrationState::Restored`] and becomes
//! [`RegistrationState::Registered`] only when a registrar answers.

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
/// Past this the doubling no longer matters; higher only risks the shift.
const BACKOFF_CEILING: u32 = 16;
const MAGIC: &[u8; 4] = b"SPRG";
/// The only snapshot layout. See [`freeze`].
const SNAPSHOT_VERSION: u16 = 1;
/// Magic, version, CSeq, granted, remaining, `Call-ID` length.
const SNAPSHOT_HEAD: usize = 20;
/// RFC 3608.
const SERVICE_ROUTE: HeaderName<'static> = HeaderName::Extension("Service-Route");
/// RFC 7315 §4.1.
const P_ASSOCIATED_URI: HeaderName<'static> = HeaderName::Extension("P-Associated-URI");
/// The most `Service-Route` entries taken from one response. Each rides on
/// every request, and a long list overflows a datagram (RFC 3261 §18.1.1).
const MAX_SERVICE_ROUTE: usize = 8;
/// The most associated identities kept from one response.
const MAX_ASSOCIATED: usize = 32;
/// The longest route entry or URI taken from a registrar.
const MAX_LEARNED_BYTES: usize = 512;

/// Everything one account's registration is doing.
#[derive(Debug)]
pub(crate) struct Registration {
    pub(crate) state: RegistrationState,
    /// Same for all registrations in a boot cycle (§10.2.4).
    pub(crate) call_id: CallId,
    /// Grows across refreshes, so a registrar can tell one from a replay.
    pub(crate) cseq: u32,
    pub(crate) transaction: Option<TransactionId<NonInviteClient>>,
    /// The interval asked for; a 423 may raise it once (§10.2.8).
    pub(crate) asking: Duration,
    /// A 423 already raised it; a second one is not chased.
    pub(crate) raised: bool,
    /// The next refresh or retry.
    pub(crate) due: Option<Instant>,
    /// Consecutive retryable failures, for the back-off.
    pub(crate) failures: u32,
    /// A de-registration is in flight or waiting to go: its 200 is not a
    /// binding, and whatever goes next is a de-registration too.
    pub(crate) unregistering: bool,
    /// A challenge nobody has answered yet, kept for the event that says so.
    pub(crate) unanswered: Option<OwnedMessage>,
    /// Push echo of the last 2xx (RFC 8599 §4.1.1).
    pub(crate) echo: Option<PushEcho>,
    /// When the granted binding lapses.
    pub(crate) lapses_at: Option<Instant>,
    /// Time from the declared cold start to reachable.
    pub(crate) ready: Option<Duration>,
    /// A push asked for a refresh before there was a transport; it goes as
    /// soon as one is handed over.
    pub(crate) owed: bool,
    /// The challenged REGISTER whose answer is too big for a datagram
    /// (§18.1.1), waiting for a connection.
    ///
    /// Kept here, not in the agent's owner map, because a refresh clears that
    /// account's entries there. While set, `unanswered` is not a refusal yet.
    pub(crate) waiting_for_stream: Option<AnyTransactionId>,
    /// What the last 2xx said beside the lifetime. Read through
    /// [`Registration::learned`], which stops answering once the binding
    /// lapses.
    pub(crate) learned: Option<RegistrarInfo>,
    /// Old `Contact`s left by `UserAgent::readdress`, sent again with
    /// `expires=0` until a 2xx confirms (RFC 3261 §10.2.2).
    pub(crate) retired: Vec<Box<[u8]>>,
}

/// Cap on retired `Contact`s, so a NAT that moves on every refresh does not
/// grow the request.
const MAX_RETIRED: usize = 4;

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
            retired: Vec::new(),
        }
    }

    /// Ask the registrar to drop `old`, never `current` (a mapping can move
    /// back).
    pub(crate) fn retire(&mut self, old: Box<[u8]>, current: &[u8]) {
        self.retired
            .retain(|kept| **kept != *current && *kept != old);
        if self.retired.len() >= MAX_RETIRED {
            self.retired.remove(0);
        }
        self.retired.push(old);
    }

    /// What the registrar last said, for as long as the binding it said it
    /// about still stands.
    ///
    /// RFC 5627 §4.4 and RFC 3608 §6.1 both drop what was learned once the
    /// binding lapses. Checked at use rather than by a timer that could fire
    /// late.
    pub(crate) fn learned(&self, now: Instant) -> Option<&RegistrarInfo> {
        let info = self.learned.as_ref()?;
        self.lapses_at.is_some_and(|at| now < at).then_some(info)
    }

    /// The registrar refused this registration.
    ///
    /// The service route goes (RFC 3608 §6.1); the GRUUs stay, since a
    /// non-2xx does not invalidate them (RFC 5627 §4.2).
    pub(crate) fn refused(&mut self) {
        if let Some(info) = self.learned.as_mut() {
            info.service_route.clear();
        }
    }

    /// Whether a binding is believed live. A restored one is not: the wire
    /// has not confirmed it.
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
        // only the first binding after a cold start counts
        if let Some(cold) = cold
            && self.ready.is_none()
        {
            self.ready = Some(now.saturating_duration_since(cold));
        }
        refresh_within(granted, self.lead())
    }

    /// How long before the binding lapses the refresh has to be sent.
    ///
    /// Our 30 s, or more if the network demands it with `sip.pnsreg` (RFC
    /// 8599 §4.1.4).
    fn lead(&self) -> u64 {
        self.echo
            .and_then(PushEcho::refresh_lead)
            .map_or(REFRESH_MARGIN, |lead| lead.as_secs().max(REFRESH_MARGIN))
    }
}

/// What the registrar said about push notifications in a 2xx to a REGISTER.
///
/// It does not change whether the REGISTER worked, only whether the
/// application may suspend and rely on a push to wake it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PushEcho {
    accepted: bool,
    lead: Option<Duration>,
}

impl PushEcho {
    /// Whether the network said it will ask for notifications of the type this
    /// account asked for.
    ///
    /// True only when the 2xx's `sip.pns` names the same provider as
    /// `pn-provider` (§4.1.1); otherwise pushes must not be assumed.
    #[must_use]
    pub const fn accepted(self) -> bool {
        self.accepted
    }

    /// How long before the binding lapses the network insists on seeing a
    /// refresh, from a `sip.pnsreg` indicator (§4.1.4).
    ///
    /// Absent when the network sent none. §4.1.4 then advises refreshing
    /// only on a push; that is not followed, since this crate cannot tell
    /// whether pushes arrive. The refresh timer keeps running unless the
    /// application takes the account down.
    #[must_use]
    pub const fn refresh_lead(self) -> Option<Duration> {
        self.lead
    }
}

/// What a 2xx to a REGISTER says about push, for an account that asked.
///
/// Read from `Feature-Caps` (RFC 6809, RFC 8599 §8.2), every row and every
/// comma-separated value (§7.3.1).
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
/// Each value is parsed and bounded before it is kept; one that fails is
/// left out and noted in the REGISTER's diagnostics, since it would go back
/// out in every request of the account. None of it outlives its binding; see
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
    /// Preloaded on requests the account starts toward its registrar (§3),
    /// but not on the REGISTER: a refresh sent along a stale route could
    /// never replace it.
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
    /// Reported only: §4.1 says they must not be assumed registered.
    #[must_use]
    pub fn associated(&self) -> &[Uri] {
        &self.associated
    }

    /// Which GRUU a dialog opens with.
    ///
    /// Temporary for anonymous calls, public otherwise (RFC 5627 §3.3), each
    /// standing in for the other (§4.4), except that an anonymous call never
    /// falls back to the public one, which names the address of record.
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

/// RFC 3608 §5: each value a loose-routed `Route` entry.
///
/// `None` when any hop cannot be taken: a route missing a hop goes elsewhere.
fn read_service_route(response: &RawMessage<'_>) -> Option<Vec<Box<[u8]>>> {
    let mut hops = Vec::new();
    for value in response.field_values(SERVICE_ROUTE) {
        if hops.len() == MAX_SERVICE_ROUTE {
            return None;
        }
        let flat = one_line(value)?;
        let entry = RouteRef::parse(&flat).ok()?;
        // no strict routers: §5 rules them out, and nothing here would
        // rewrite the Request-URI (§12.2.1.1)
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

/// Whether every byte is a SIP URI character (RFC 3261 §25.1).
///
/// The core parser does not check the bytes between delimiters. A value kept
/// here is written back out, where a `<`, `>`, `"` or space would end the
/// header early.
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
/// The entry is found by `+sip.instance`, not by address: the response lists
/// other devices too, and a registrar may rewrite the address behind a NAT.
/// An entry that does not parse is skipped.
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
        // expires=0: removed, and its GRUUs with it (§5.3)
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
/// URN equality (RFC 5626 §4.1, RFC 2141): `urn:` and the namespace ignore
/// case, the rest is exact, except `uuid` whose hex ignores case too (RFC
/// 4122 §3). Angle brackets (RFC 3840 §9) come off both sides.
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

/// `pub-gruu` or `temp-gruu`: a quoted SIP URI (RFC 5627 §7) with a `gr`
/// parameter (§4.5).
fn gruu_param(params: &Params<'_>, name: &str) -> Offered {
    let mut named = params
        .clone()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name.as_bytes()));
    let Some((_, written)) = named.next() else {
        return Offered::Absent;
    };
    // two values: no guessing which one was meant
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
    // it goes back in angle brackets, where a `>` would split the Contact
    if !uri_bytes_only(&flat) {
        return None;
    }
    let uri = Uri::parse(&flat).ok()?;
    let usable = uri
        .sip()
        .is_some_and(|sip| sip.has_param("gr") && sip.headers().next().is_none());
    usable.then_some(uri)
}

/// RFC 7315 §4.1: name-addr entries; an empty field means none.
///
/// `None` when an entry cannot be read or there are too many. The whole
/// response rides on the event, so refusing loses nothing.
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

/// A wire value as one line: folds unfolded (§7.3.1), control bytes refused.
/// A bad byte kept here would make the builder refuse every later INVITE.
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
/// The GRUU when there is one (RFC 5627 §4.4), bare, without
/// `+sip.instance`: the public one has it in `gr`, and a temporary one must
/// not reveal it (§10.3).
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
/// Zero in means removed: nothing to refresh.
pub(crate) fn refresh_after(granted: Duration) -> Duration {
    refresh_within(granted, REFRESH_MARGIN)
}

/// The same, for a registration the network insists on seeing refreshed
/// `lead` seconds before it lapses (RFC 8599 §4.1.4).
///
/// A `lead` longer than the binding falls to the halfway floor.
fn refresh_within(granted: Duration, lead: u64) -> Duration {
    let seconds = granted.as_secs();
    if seconds == 0 {
        return Duration::ZERO;
    }
    let fraction = seconds.saturating_mul(REFRESH_FRACTION) / 100;
    let margin = seconds.saturating_sub(lead);
    // never zero, even for a one-second binding
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
/// `entropy` is a hex token; its first 32 bits are used. The modulo bias is
/// negligible at these ranges.
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
/// Our `Contact`'s `expires` wins, then `Expires`, then what was asked for.
/// Our contact is matched by §19.1.4 equivalence, since registrars normalise.
///
/// A list that does not name us is not a removal: registrars rewrite
/// addresses behind a NAT. Only a stated zero means removed.
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
/// Only the delta-seconds are read.
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
    /// It does not start with the snapshot magic.
    NotASnapshot,
    /// Written by a newer build, in a layout this one does not know.
    FromTheFuture {
        /// The version it claims to be.
        version: u16,
    },
    /// It ends inside a field, or has bytes left over after the last one.
    Malformed,
    /// The address of record in it is not this account's.
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

/// A registration written down, so waking up does not cost a handshake.
///
/// Version 1, big-endian:
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
/// A reader refuses every layout it does not know, so a newer snapshot is an
/// error, never a misreading (a CSeq read out of a length would get 400s for
/// as long as the file exists). Adding a field means version 2, never a
/// longer version 1.
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
    // trailing bytes: not what it claims to be
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

/// Seconds that fit the field, saturating rather than wrapping.
fn seconds_of(duration: Duration) -> u32 {
    u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
}

fn length_of(bytes: &[u8]) -> u16 {
    u16::try_from(bytes.len()).unwrap_or(u16::MAX)
}

impl UserAgent {
    /// Write an account's registration down, so a later start can continue it.
    ///
    /// `None` when there is no binding: never registered, never will, or
    /// failed.
    ///
    /// The bytes are opaque and versioned. Storing and protecting them is the
    /// application's: not a secret, but they name who uses this device.
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
    /// `asleep` is how long the snapshot sat unused. The application supplies
    /// it: this crate reads no clock, and a monotonic instant does not
    /// survive the process.
    ///
    /// The `Call-ID` and CSeq come back, so the next REGISTER refreshes the
    /// binding the registrar still holds. The remaining life comes back as a
    /// schedule only: the refresh is booked where it would have fallen, or
    /// now if that has passed.
    ///
    /// Reachability does not come back. The account is
    /// [`RegistrationState::Restored`], never `Registered`, until a registrar
    /// answers: the binding, the `Contact` address and the registrar's name
    /// may all have gone stale.
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
        // it would book a refresh that can never be sent, retried forever
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
        // a new Call-ID discards temporary GRUUs (RFC 5627 §4.2), and a
        // restored registration proves nothing until the next 2xx
        reg.learned = None;
        // as if what is left were a fresh grant; now when nothing is left
        reg.due = Some(now + refresh_after(left));
        Ok(())
    }

    /// How long the binding an account holds is believed to last.
    ///
    /// For a restored registration this is what the registrar said before
    /// the sleep. `None` when no binding is held, including one just given
    /// up.
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
    /// The application declares it, since the stack reads no clock. Every
    /// account's [`UserAgent::time_to_ready`] is cleared, and each is
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
    /// A queue's ring time per agent must exceed this, or a sleeping phone
    /// is always skipped. `None` until registered, and always `None` for an
    /// account that never registers or with no declared cold start.
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
    /// `None` unless their binding stands (none yet, given up, or lapsed);
    /// RFC 5627 §4.4 forbids a GRUU from a lapsed one.
    #[must_use]
    pub fn registrar_info(&self, account: AccountId, now: Instant) -> Option<&RegistrarInfo> {
        self.registrations.get(&account)?.learned(now)
    }

    /// The same, for something this account sends to `destination`, where
    /// `None` is the address the account registers with.
    ///
    /// Nothing when it goes anywhere else: the service route (RFC 3608 §6.1)
    /// and the GRUU both belong to the registrar's path, and would pull a
    /// request sent elsewhere on purpose back through it.
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
        // RFC 5626 §4.5: first retry between 30 and 60 seconds
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
