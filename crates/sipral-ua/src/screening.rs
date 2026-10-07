// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Turning an INVITE away before anybody hears it.
//!
//! A phone reachable from the internet is dialled by scanners walking default
//! extension numbers; a ring at 3 a.m. tells them the number is live.
//!
//! **The hook runs before the call exists:** before
//! [`UaEvent::IncomingCall`](crate::UaEvent) is queued and before a
//! [`CallHandle`](crate::CallHandle) is minted. That is why it sits above the
//! call handler in [`crate::agent`]; consulted later, it could only notify.
//!
//! **A refusal is counted, not reported.** An event queue anyone can fill is
//! the same attack one layer up, and operators want a counter, like
//! [`Endpoint::refused`](sipral_core::endpoint::Endpoint::refused).
//!
//! **The rate limit is per source address, and loose.** Most legitimate calls
//! come from one address, the registrar proxy, so a tight limit would throttle
//! your own switchboard. The policy hook is the precise tool;
//! [`UserAgent::limit_invites`] tunes a busy address. A byte stream bound
//! without a named far end is counted per connection.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use sipral_core::endpoint::{Event, Input, OutgoingResponse, TransportId, TransportProtocol};
use sipral_core::msg::{HeaderName, OwnedMessage, StatusCode};

use crate::agent::UserAgent;
use crate::call::CallHandle;
use crate::transfer::FORBIDDEN;

/// What this layer answers when it refuses an INVITE itself.
///
/// 480 (§21.4.18) is what a switched-off phone says, so a scanner cannot tell
/// a guarded number from an idle one. 404 would be an enumeration oracle
/// (§21.4.5); 503 makes a proxy stop using this server (§21.5.4), taking the
/// phone off the air; 6xx speaks for every device of the user (§21.6).
///
/// No `Retry-After`: it would only tell a scanner when to come back.
const UNAVAILABLE: StatusCode = match StatusCode::new(480) {
    Ok(status) => status,
    // unreachable; `new` is fallible and this crate does not panic
    Err(_) => StatusCode::BUSY_HERE,
};

/// Sources watched at once. Fixed, because a table keyed by any arriving
/// address would itself be the attack.
const WATCHED: usize = 64;

/// How fast one source may offer calls.
///
/// A token bucket: `burst` at once, then one more per `every`. Unlike a
/// sliding window it holds no per-call memory the sender controls, and
/// "a few, then a trickle" is how real use looks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rate {
    burst: u32,
    /// `None` is no limit; zero is refused so a rounded-down division cannot
    /// silently mean unlimited.
    every: Option<Duration>,
}

/// Why a [`Rate`] was refused, rather than silently adjusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RateError {
    /// A burst of zero would admit nothing, ever.
    NoBurst,
    /// An interval of zero never limits; use [`Rate::unlimited`].
    NoInterval,
}

impl fmt::Display for RateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::NoBurst => "a burst of zero would refuse every call",
            Self::NoInterval => "an interval of zero is no limit; say Rate::unlimited",
        })
    }
}

impl std::error::Error for RateError {}

impl Rate {
    /// `burst` calls at once, then one more every `every`.
    ///
    /// # Errors
    /// [`RateError`] for a `burst` or an `every` of zero.
    pub const fn new(burst: u32, every: Duration) -> Result<Self, RateError> {
        if burst == 0 {
            return Err(RateError::NoBurst);
        }
        if every.is_zero() {
            return Err(RateError::NoInterval);
        }
        Ok(Self {
            burst,
            every: Some(every),
        })
    }

    /// No limit: every INVITE reaches the policy hook.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            burst: u32::MAX,
            every: None,
        }
    }

    /// 128 at once, then one every 50 ms: the preset for a voice agent.
    ///
    /// Such a service takes dozens of calls at once from one trunk; the
    /// default would answer the twelfth 480. The burst equals the default
    /// `EndpointConfig::max_dialogs`, so in a rush the dialog ceiling (503,
    /// countable) refuses first, not the rate.
    #[must_use]
    pub const fn voice_agent() -> Self {
        Self {
            burst: 128,
            every: Some(Duration::from_millis(50)),
        }
    }

    /// How many calls this rate lets arrive at once.
    #[must_use]
    pub const fn burst(self) -> u32 {
        self.burst
    }

    /// How long one call costs, or `None` for [`Rate::unlimited`].
    #[must_use]
    pub const fn every(self) -> Option<Duration> {
        self.every
    }

    /// `None` when unlimited.
    fn earned(self, elapsed: Duration) -> Option<u32> {
        let whole = elapsed.as_nanos().checked_div(self.every?.as_nanos())?;
        Some(u32::try_from(whole).unwrap_or(u32::MAX))
    }
}

impl Default for Rate {
    /// Ten at once, then one every two seconds. Loose on purpose (see the
    /// module docs).
    fn default() -> Self {
        Self {
            burst: 10,
            every: Some(Duration::from_secs(2)),
        }
    }
}

/// What has been refused since the agent was made; never reset.
///
/// An out-of-dialog REFER refused by the floor or policy
/// ([`crate::referral`]) counts as the INVITE it would have become.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Refusals {
    /// INVITEs a [`Screen`] refused.
    pub by_policy: u64,
    /// INVITEs from a source faster than [`Rate`] allows.
    pub by_rate: u64,
    /// INVITEs refused because every watched-source slot was busy.
    ///
    /// Separate from [`Refusals::by_rate`]: one fast source calls for
    /// [`UserAgent::limit_invites`], many addresses at once for a firewall.
    pub by_crowding: u64,
    /// INVITEs refused 403 for a `Replaces` naming a live call they had no
    /// standing to take (RFC 3891 §3), whether by the default rule or by
    /// [`Screen::on_replaces`] returning 403.
    pub by_replaces: u64,
}

/// An INVITE that has been read and not yet acted on.
#[derive(Clone, Copy, Debug)]
pub struct Incoming<'a> {
    source: Option<SocketAddr>,
    request: &'a OwnedMessage,
}

impl Incoming<'_> {
    /// The far end of the transport, not what `Via` claims.
    ///
    /// `None` for a byte stream bound without naming its far end (see
    /// [`Input::TransportBound`]); a policy may refuse such a caller.
    #[must_use]
    pub const fn source(&self) -> Option<SocketAddr> {
        self.source
    }

    /// The request, whole.
    #[must_use]
    pub const fn request(&self) -> &OwnedMessage {
        self.request
    }

    /// `Referred-By`, when the request carries exactly one (RFC 3892 §2.1).
    ///
    /// **Context, never authority.** On an attended transfer it names the
    /// transferor (§2.2), but the sender wrote it like `From`, and the signed
    /// token of §3 is not implemented. Use it to recognise an expected
    /// transfer, not as permission.
    #[must_use]
    pub fn referred_by(&self) -> Option<&[u8]> {
        let request = self.request.as_raw();
        if request.header_count(HeaderName::ReferredBy) != 1 {
            return None;
        }
        request.header(HeaderName::ReferredBy)
    }
}

/// The call an incoming `Replaces` names, and how its INVITE got here, for
/// [`Screen::on_replaces`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Replacing {
    call: CallHandle,
    same_flow: bool,
}

impl Replacing {
    pub(crate) const fn new(call: CallHandle, same_flow: bool) -> Self {
        Self { call, same_flow }
    }

    /// The call that would be hung up if this INVITE is answered, matched on
    /// `Call-ID` and both tags (RFC 3891 §3).
    #[must_use]
    pub const fn call(self) -> CallHandle {
        self.call
    }

    /// Whether the INVITE arrived from the same place the named call's own
    /// signalling does.
    ///
    /// The one thing about a `Replaces` the sender did not write. `true` when
    /// neither address is known (an unnamed bound stream).
    #[must_use]
    pub const fn same_flow(self) -> bool {
        self.same_flow
    }

    /// What this gets when no policy says otherwise: the call when
    /// [`Replacing::same_flow`], and 403 when not.
    ///
    /// The default of [`Screen::on_replaces`], also used with no [`Screen`].
    /// Public so a policy that widens one case can delegate the rest.
    #[must_use]
    pub const fn strict(self) -> Screening {
        if self.same_flow {
            Screening::Take
        } else {
            Screening::Refuse(FORBIDDEN)
        }
    }
}

/// What a [`Screen`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screening {
    /// Let it through as if there were no policy.
    Take,
    /// Answer with this status. No call, no event.
    Refuse(StatusCode),
}

/// What the application decides about an INVITE nobody has heard yet.
///
/// Set with [`UserAgent::screen`]. It runs before ringing and before any
/// event, so a refusal leaves no trace outside [`UserAgent::refusals`]. A
/// closure of the same shape works too.
///
/// Called once per INVITE that passes the rate limit, on the thread driving
/// the agent; keep it fast.
///
/// [`Screen::on_replaces`] defaults to the strict RFC 3891 §3 rule.
pub trait Screen {
    /// An INVITE has arrived, or an out-of-dialog REFER once
    /// [`UserAgent::allow_referrals`] is on (`invite.request()` tells which).
    fn on_invite(&mut self, invite: &Incoming<'_>) -> Screening;

    /// Its `Replaces` names one of this end's live calls (RFC 3891 §3);
    /// answering it hangs that call up.
    ///
    /// The default, [`Replacing::strict`], takes it only from the named
    /// call's own flow: `Call-ID` and tags travel in every packet, and there
    /// is no authenticated peer to compare instead.
    ///
    /// **Override where that is wrong.** A transferee reaching this end
    /// directly, not via the line's proxy, is refused by default. A policy
    /// can accept it (source address, [`Incoming::referred_by`],
    /// [`Replacing::call`]) or tighten further.
    ///
    /// Runs after [`Screen::on_invite`] took the INVITE, and only for a
    /// matched call: an unmatched `Replaces` is 481 and never gets here. A
    /// call that has already ended is still declined 603 (§3).
    fn on_replaces(&mut self, invite: &Incoming<'_>, named: Replacing) -> Screening {
        let _ = invite;
        named.strict()
    }
}

impl<F: FnMut(&Incoming<'_>) -> Screening> Screen for F {
    fn on_invite(&mut self, invite: &Incoming<'_>) -> Screening {
        self(invite)
    }
}

/// What an allowance is kept against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Origin {
    /// Without the port: ports are free to change, so per-port counting would
    /// read one scanner as thousands of strangers.
    Address(IpAddr),
    /// An unnamed bound byte stream: the connection is the sender.
    Stream(TransportId),
}

#[derive(Clone, Copy, Debug)]
struct Watched {
    source: Origin,
    tokens: u32,
    /// Where tokens were last counted from, not the last call: keeps the
    /// partial token, or a source just under the limit would gain one free
    /// on every arrival.
    since: Instant,
}

impl Watched {
    /// First sighting; spends the call that revealed it.
    fn new(source: Origin, rate: Rate, now: Instant) -> Self {
        Self {
            source,
            tokens: rate.burst.saturating_sub(1),
            since: now,
        }
    }

    fn refill(&mut self, rate: Rate, now: Instant) {
        let elapsed = now.saturating_duration_since(self.since);
        let Some(earned) = rate.earned(elapsed) else {
            self.tokens = rate.burst;
            self.since = now;
            return;
        };
        if earned == 0 {
            return;
        }
        self.tokens = self.tokens.saturating_add(earned).min(rate.burst);
        self.since = rate
            .every
            .and_then(|every| every.checked_mul(earned))
            .and_then(|counted| self.since.checked_add(counted))
            .unwrap_or(now);
    }

    fn spend(&mut self) -> bool {
        let Some(left) = self.tokens.checked_sub(1) else {
            return false;
        };
        self.tokens = left;
        true
    }

    /// Fully refilled, so indistinguishable from a source never seen.
    fn quiet(&self, rate: Rate) -> bool {
        self.tokens >= rate.burst
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Admission {
    Take,
    TooFast,
    /// No free slot to track the source in.
    NoRoom,
}

#[derive(Debug, Default)]
struct Sources {
    /// A linear scan of at most [`WATCHED`]; eviction scans anyway.
    watched: Vec<Watched>,
}

impl Sources {
    fn admit(&mut self, source: Origin, rate: Rate, now: Instant) -> Admission {
        if let Some(known) = self.watched.iter_mut().find(|seat| seat.source == source) {
            known.refill(rate, now);
            return if known.spend() {
                Admission::Take
            } else {
                Admission::TooFast
            };
        }
        if self.watched.len() < WATCHED {
            self.watched.push(Watched::new(source, rate, now));
            return Admission::Take;
        }

        // a fully refilled source is as good as unseen: evict it
        for seat in &mut self.watched {
            seat.refill(rate, now);
        }
        let Some(seat) = self.watched.iter_mut().find(|seat| seat.quiet(rate)) else {
            // a flood from many addresses: refuse rather than admit untracked,
            // since that would be a hole exactly when it matters
            return Admission::NoRoom;
        };
        *seat = Watched::new(source, rate, now);
        Admission::Take
    }

    /// A closed stream's id may be reused; the next connection must not
    /// inherit its spending.
    fn forget(&mut self, source: Origin) {
        self.watched.retain(|seat| seat.source != source);
    }
}

/// The policy an INVITE meets before anything else does.
#[derive(Default)]
pub(crate) struct Guard {
    policy: Option<Box<dyn Screen + Send>>,
    rate: Rate,
    sources: Sources,
    refusals: Refusals,
    /// Far end of the current input; set before every [`UserAgent::receive`].
    source: Option<SocketAddr>,
    /// What the rate limit counts by when `source` is `None`.
    stream: Option<TransportId>,
    /// Far end per connected stream. Bounded by the transports the
    /// application opened, not by strangers.
    connected: HashMap<TransportId, SocketAddr>,
    /// This end's address for the current input: the true `Contact` for an
    /// INVITE addressed to no account.
    arrival: Option<(SocketAddr, TransportProtocol)>,
    /// The flow a request is matched to its account by.
    arrived_on: Option<TransportId>,
    /// Local address and protocol per bound transport, bounded like
    /// `connected`.
    bound: HashMap<TransportId, (SocketAddr, TransportProtocol)>,
}

impl fmt::Debug for Guard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Guard")
            .field("policy", &self.policy.is_some())
            .field("rate", &self.rate)
            .field("watching", &self.sources.watched.len())
            .field("refusals", &self.refusals)
            .field("source", &self.source)
            .field("connected", &self.connected)
            .finish_non_exhaustive()
    }
}

impl Guard {
    /// Bytes have arrived, or a transport has come or gone.
    pub(crate) fn arrived(&mut self, input: &Input<'_>) {
        self.arrival = match *input {
            Input::Datagram {
                transport, local, ..
            } => {
                let protocol = self
                    .bound
                    .get(&transport)
                    .map_or(TransportProtocol::Udp, |&(_, protocol)| protocol);
                Some((local, protocol))
            }
            Input::StreamData { transport, .. } => self.bound.get(&transport).copied(),
            Input::TransportBound {
                transport,
                protocol,
                local,
                ..
            } => {
                self.bound.insert(transport, (local, protocol));
                None
            }
            Input::StreamClosed { transport } | Input::TransportFailed { transport, .. } => {
                self.bound.remove(&transport);
                None
            }
            _ => None,
        };
        self.source = match *input {
            Input::Datagram { remote, .. } => Some(remote),
            Input::StreamData { transport, .. } => self.connected.get(&transport).copied(),
            Input::TransportBound {
                transport, remote, ..
            } => {
                if let Some(remote) = remote {
                    self.connected.insert(transport, remote);
                }
                None
            }
            Input::StreamClosed { transport } | Input::TransportFailed { transport, .. } => {
                self.connected.remove(&transport);
                self.sources.forget(Origin::Stream(transport));
                None
            }
            _ => None,
        };
        self.stream = match *input {
            Input::StreamData { transport, .. } => Some(transport),
            _ => None,
        };
        self.arrived_on = match *input {
            Input::Datagram { transport, .. } | Input::StreamData { transport, .. } => {
                Some(transport)
            }
            _ => None,
        };
    }

    fn origin(&self) -> Option<Origin> {
        self.source
            .map(|source| Origin::Address(source.ip()))
            .or_else(|| self.stream.map(Origin::Stream))
    }

    pub(crate) const fn source(&self) -> Option<SocketAddr> {
        self.source
    }

    /// `None` between arrivals and for a transport never bound.
    pub(crate) const fn arrival(&self) -> Option<(SocketAddr, TransportProtocol)> {
        self.arrival
    }

    pub(crate) const fn arrived_on(&self) -> Option<TransportId> {
        self.arrived_on
    }

    /// A `Replaces` naming a live call (RFC 3891 §3); without a policy,
    /// [`Replacing::strict`].
    pub(crate) fn screen_replaces(
        &mut self,
        request: &OwnedMessage,
        named: Replacing,
    ) -> Screening {
        let invite = Incoming {
            source: self.source,
            request,
        };
        self.policy.as_mut().map_or_else(
            || named.strict(),
            |policy| policy.on_replaces(&invite, named),
        )
    }

    pub(crate) const fn refused_replaces(&mut self) {
        self.refusals.by_replaces = self.refusals.by_replaces.saturating_add(1);
    }

    /// `None` to let it through, or the status to refuse with. Out-of-dialog
    /// REFERs ([`crate::referral`]) are rationed the same way.
    pub(crate) fn decide(&mut self, request: &OwnedMessage, now: Instant) -> Option<StatusCode> {
        // the cheap floor first, so a flood cannot drive application code
        if let Some(origin) = self.origin() {
            match self.sources.admit(origin, self.rate, now) {
                Admission::Take => (),
                Admission::TooFast => {
                    self.refusals.by_rate = self.refusals.by_rate.saturating_add(1);
                    return Some(UNAVAILABLE);
                }
                Admission::NoRoom => {
                    self.refusals.by_crowding = self.refusals.by_crowding.saturating_add(1);
                    return Some(UNAVAILABLE);
                }
            }
        }
        let invite = Incoming {
            source: self.source,
            request,
        };
        match self.policy.as_mut()?.on_invite(&invite) {
            Screening::Take => None,
            Screening::Refuse(status) => {
                self.refusals.by_policy = self.refusals.by_policy.saturating_add(1);
                Some(status)
            }
        }
    }
}

impl UserAgent {
    /// Decide what happens to an incoming INVITE before anybody hears it.
    ///
    /// Runs before ringing and before any event; a refusal leaves no call or
    /// handle behind. Setting a second policy replaces the first.
    ///
    /// To judge takeovers, override [`Screen::on_replaces`] (a closure
    /// cannot).
    pub fn screen(&mut self, policy: impl Screen + Send + 'static) {
        self.guard.policy = Some(Box::new(policy));
    }

    /// Take the screening policy off, if one is set.
    ///
    /// The rate limit ([`UserAgent::limit_invites`]) stays in force.
    pub fn unscreen(&mut self) {
        self.guard.policy = None;
    }

    /// How fast one source address may offer calls.
    ///
    /// The default is loose since legitimate calls usually share the
    /// registrar's address. Tighten it for a phone facing the internet.
    pub const fn limit_invites(&mut self, rate: Rate) {
        self.guard.rate = rate;
    }

    /// The limit in force, exactly as set.
    #[must_use]
    pub const fn invite_limit(&self) -> Rate {
        self.guard.rate
    }

    /// What has been refused, cumulative.
    #[must_use]
    pub const fn refusals(&self) -> Refusals {
        self.guard.refusals
    }

    /// `None` when the INVITE was refused here; the event back otherwise.
    pub(crate) fn on_screening_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        let Event::IncomingInvite {
            transaction,
            ref request,
        } = event
        else {
            return Some(event);
        };
        let Some(refused) = self.guard.decide(request, now) else {
            return Some(event);
        };

        // answered, not dropped: an unanswered INVITE is retransmitted for 32 s
        // and holds a server transaction the whole time
        self.endpoint
            .respond_invite(transaction, &OutgoingResponse::new(refused), now)
            .ok();
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{Admission, Origin, Rate, RateError, Sources, UNAVAILABLE, WATCHED};
    use std::net::IpAddr;
    use std::time::{Duration, Instant};

    fn source(last: u8) -> Origin {
        Origin::Address(IpAddr::from([192, 0, 2, last]))
    }

    fn rate(burst: u32, every: Duration) -> Rate {
        Rate::new(burst, every).expect("a usable rate")
    }

    #[test]
    fn the_refusal_is_the_one_a_phone_that_is_not_answering_sends() {
        assert_eq!(UNAVAILABLE.get(), 480);
        assert_eq!(UNAVAILABLE.reason(), Some("Temporarily Unavailable"));
    }

    #[test]
    fn a_burst_is_admitted_and_the_call_after_it_is_not() {
        let t0 = Instant::now();
        let rate = rate(3, Duration::from_secs(2));
        let mut sources = Sources::default();
        for attempt in 0..3 {
            assert_eq!(
                sources.admit(source(9), rate, t0),
                Admission::Take,
                "call {attempt} is inside the burst"
            );
        }
        assert_eq!(
            sources.admit(source(9), rate, t0),
            Admission::TooFast,
            "and the fourth is not"
        );
    }

    #[test]
    fn a_token_comes_back_when_the_source_goes_quiet() {
        let t0 = Instant::now();
        let rate = rate(1, Duration::from_secs(2));
        let mut sources = Sources::default();
        assert_eq!(sources.admit(source(9), rate, t0), Admission::Take);
        assert_eq!(sources.admit(source(9), rate, t0), Admission::TooFast);
        assert_eq!(
            sources.admit(source(9), rate, t0 + Duration::from_secs(1)),
            Admission::TooFast,
            "half an interval earns nothing"
        );
        assert_eq!(
            sources.admit(source(9), rate, t0 + Duration::from_secs(2)),
            Admission::Take
        );
    }

    #[test]
    fn the_remainder_of_an_interval_is_not_given_away_twice() {
        let t0 = Instant::now();
        let rate = rate(1, Duration::from_secs(2));
        let mut sources = Sources::default();
        assert_eq!(sources.admit(source(9), rate, t0), Admission::Take);
        let mut at = t0;
        for _ in 0..4 {
            at += Duration::from_millis(1500);
            sources.admit(source(9), rate, at);
        }
        // 4.5 intervals, five calls offered: at most three admitted
        at += Duration::from_millis(1500);
        assert_eq!(
            sources.admit(source(9), rate, at),
            Admission::TooFast,
            "the leftover time was banked, not repeated"
        );
    }

    #[test]
    fn one_source_keeps_one_seat_however_often_it_calls() {
        let t0 = Instant::now();
        let rate = rate(2, Duration::from_secs(2));
        let mut sources = Sources::default();
        assert_eq!(sources.admit(source(9), rate, t0), Admission::Take);
        assert_eq!(sources.admit(source(9), rate, t0), Admission::Take);
        assert_eq!(sources.admit(source(9), rate, t0), Admission::TooFast);
        assert_eq!(sources.watched.len(), 1, "one address, one seat");
    }

    #[test]
    fn nobody_can_grow_the_table_by_calling_from_everywhere() {
        let t0 = Instant::now();
        let rate = rate(2, Duration::from_secs(2));
        let mut sources = Sources::default();
        for last in 0..=255u8 {
            sources.admit(
                Origin::Address(IpAddr::from([198, 51, 100, last])),
                rate,
                t0,
            );
        }
        assert_eq!(sources.watched.len(), WATCHED);
    }

    #[test]
    fn a_stranger_arriving_while_everybody_is_spending_is_refused() {
        let t0 = Instant::now();
        let rate = rate(2, Duration::from_secs(60));
        let mut sources = Sources::default();
        for last in 0..WATCHED {
            let filling = Origin::Address(IpAddr::from([
                198,
                51,
                100,
                u8::try_from(last).unwrap_or(0),
            ]));
            // twice each, so that no seat has anything left
            assert_eq!(sources.admit(filling, rate, t0), Admission::Take);
            assert_eq!(sources.admit(filling, rate, t0), Admission::Take);
        }
        assert_eq!(
            sources.admit(source(9), rate, t0),
            Admission::NoRoom,
            "there is no room to watch it, and what cannot be limited is not admitted"
        );
    }

    #[test]
    fn a_seat_frees_itself_once_its_source_goes_quiet() {
        let t0 = Instant::now();
        let rate = rate(2, Duration::from_secs(60));
        let mut sources = Sources::default();
        for last in 0..WATCHED {
            let filling = Origin::Address(IpAddr::from([
                198,
                51,
                100,
                u8::try_from(last).unwrap_or(0),
            ]));
            assert_eq!(sources.admit(filling, rate, t0), Admission::Take);
            assert_eq!(sources.admit(filling, rate, t0), Admission::Take);
        }
        assert_eq!(
            sources.admit(source(9), rate, t0 + Duration::from_secs(120)),
            Admission::Take,
            "two minutes of quiet refilled every bucket, and a full one holds no news"
        );
        assert_eq!(
            sources.watched.len(),
            WATCHED,
            "and took a seat, not a new one"
        );
    }

    #[test]
    fn a_rate_that_says_it_is_no_limit_is_no_limit() {
        let t0 = Instant::now();
        let mut sources = Sources::default();
        for _ in 0..1000 {
            assert_eq!(
                sources.admit(source(9), Rate::unlimited(), t0),
                Admission::Take
            );
        }
    }

    #[test]
    fn a_burst_of_none_is_refused_where_it_is_set_and_not_read_as_one() {
        assert_eq!(
            Rate::new(0, Duration::from_secs(2)),
            Err(RateError::NoBurst)
        );
    }

    #[test]
    fn an_interval_of_none_is_refused_rather_than_taken_for_no_limit() {
        assert_eq!(Rate::new(1, Duration::ZERO), Err(RateError::NoInterval));
        assert_eq!(Rate::unlimited().every(), None);
    }

    #[test]
    fn the_rate_that_took_effect_is_the_one_that_reads_back() {
        let asked = rate(4, Duration::from_secs(7));
        assert_eq!(asked.burst(), 4);
        assert_eq!(asked.every(), Some(Duration::from_secs(7)));
        assert_eq!(Rate::default().burst(), 10);
        assert_eq!(Rate::default().every(), Some(Duration::from_secs(2)));
    }

    /// A campaign's first minute from one trunk: the default refuses the
    /// eleventh call, the preset takes the rush.
    #[test]
    fn the_voice_agent_preset_takes_a_trunks_rush_that_the_default_refuses() {
        let t0 = Instant::now();
        let mut guarded = Sources::default();
        let refused = (0..40)
            .filter(|_| guarded.admit(source(9), Rate::default(), t0) != Admission::Take)
            .count();
        assert_eq!(refused, 30, "ten at once and no more");

        let preset = Rate::voice_agent();
        assert_eq!(preset.burst(), 128);
        assert_eq!(preset.every(), Some(Duration::from_millis(50)));
        let mut agent = Sources::default();
        for call in 0..128 {
            assert_eq!(
                agent.admit(source(9), preset, t0),
                Admission::Take,
                "call {call} is inside the rush"
            );
        }
        assert_eq!(agent.admit(source(9), preset, t0), Admission::TooFast);
        let second = t0 + Duration::from_secs(1);
        let taken = (0..25)
            .filter(|_| agent.admit(source(9), preset, second) == Admission::Take)
            .count();
        assert_eq!(taken, 20, "twenty a second once the rush is spent");
    }
}
