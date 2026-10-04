// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Turning an INVITE away before anybody hears it.
//!
//! A phone reachable from the internet is dialled by machines that are not
//! calling anybody. They walk the extension numbers every PBX ships with, at
//! every hour, and what they are after is an effect — a telephone that rings
//! at three in the morning is proof that the number is live and that somebody
//! is behind it. Everything else in this crate turns an INVITE into a call as
//! quickly as it can, which is exactly the wrong instinct here.
//!
//! **Where the hook runs is the whole of it.** The policy is consulted before
//! the call exists: before [`UaEvent::IncomingCall`](crate::UaEvent) is
//! queued, before a [`CallHandle`](crate::CallHandle) is minted, before one
//! map has an entry that a caller could later observe. That is why it sits
//! above the call handler in the chain in [`crate::agent`] rather than inside
//! it — by the time that one has run, the effect the policy exists to prevent
//! has already happened, and a hook consulted afterwards is a notification
//! wearing a decision's clothes.
//!
//! **A refusal is counted, not reported.** There is no event for one, and that
//! is deliberate twice over: an event queue that anybody on the internet can
//! fill is the same attack one layer up, and the number an operator wants is
//! "how often has this happened", which is a counter. It is the same shape
//! [`Endpoint::refused`](sipral_core::endpoint::Endpoint::refused) already
//! uses for the requests the core turns away.
//!
//! **The rate limit is per source address, and it is deliberately loose.** In
//! most deployments every legitimate call arrives from one address — the proxy
//! the phone registered with — so a limit tuned to a scanner is a limit on
//! your own switchboard. What the default buys is the difference between a
//! phone that rings fifty times a second and one that rings a few times a
//! minute; the precise answer is the policy hook, which knows things this
//! layer cannot, and [`UserAgent::limit_invites`] is there for a deployment
//! whose one address is genuinely busy. A byte stream the application bound
//! without naming its far end has no address to count by, and is counted as
//! itself — one allowance per connection, for as long as it stays open —
//! rather than not counted at all.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use sipral_core::endpoint::{Event, Input, OutgoingResponse, TransportId, TransportProtocol};
use sipral_core::msg::{HeaderName, OwnedMessage, StatusCode};

use crate::agent::UserAgent;
use crate::call::CallHandle;
use crate::transfer::FORBIDDEN;

/// What this layer answers with when it refuses an INVITE of its own accord.
///
/// §21.4.18: "the callee's end system was contacted successfully but the
/// callee is currently unavailable (for example, is not logged in, logged in
/// but in a state that precludes communication with the callee, or has
/// activated the 'do not disturb' feature)". A screened INVITE is the third of
/// those, and the answer is the same one a phone that has been switched off
/// gives, so a scanner cannot tell a number that is guarded from one that is
/// simply not answering.
///
/// The alternatives were read and each says something worth more than it
/// costs. 404 claims "definitive information that the user does not exist"
/// (§21.4.5), which is untrue and, sent for some numbers and not others, is an
/// oracle for enumerating the ones that do. 503 is what the core sends when it
/// is out of room, and §21.5.4 has a proxy that receives one stop sending to
/// that server entirely — a rate limit answering 503 would take the phone off
/// the air, which is what the scanner wanted. 603 and every other 6xx claim
/// knowledge of "a particular user, not just the particular instance"
/// (§21.6), so refusing here would silence the desk phone the same person is
/// registered on.
///
/// No `Retry-After` goes with it, although §21.4.18 allows one: it would tell
/// a scanner when to come back and tells a real caller nothing they would act
/// on.
const UNAVAILABLE: StatusCode = match StatusCode::new(480) {
    Ok(status) => status,
    // 480 is in range, so this arm never runs; it exists because `new` is
    // fallible and nothing in this crate panics to say otherwise
    Err(_) => StatusCode::BUSY_HERE,
};

/// How many sources are watched at once.
///
/// A phone talks to a proxy and a handful of peers, so this is far past what
/// an honest deployment needs. It is a fixed cost rather than a growing one
/// because a table keyed by whatever address arrives, on a port the whole
/// internet can reach, is itself the attack.
const WATCHED: usize = 64;

/// How fast one source may offer calls.
///
/// A token bucket: `burst` calls may arrive at once, and one more token is
/// earned every `every` after that. The shape was chosen over a sliding window
/// because a window has to remember when each call arrived — which is memory
/// the sender controls — while a bucket is two numbers whatever the traffic,
/// and because "a few at once, then a trickle" is what a telephone that is
/// being used looks like, whereas a scanner is a flat unrelenting rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rate {
    burst: u32,
    /// `None` is no limit at all. Zero says the same thing arithmetically — a
    /// token earned in no time is a token always available — but a deployment
    /// that wants no limit says so with [`Rate::unlimited`], and an interval
    /// that came out of a division and rounded to nothing meant no such thing.
    every: Option<Duration>,
}

/// Why a [`Rate`] was refused.
///
/// Both values are arithmetically meaningful and neither is what anybody
/// wants, so they are answered here rather than quietly turned into something
/// else. A setting is applied, rejected with a reason, or unsupported; there is
/// no fourth answer where the value that took effect is not the value that was
/// given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RateError {
    /// A burst of zero admits nothing, ever — not the first call of the day
    /// and not the one after a week of quiet, because a bucket that holds no
    /// tokens can never be refilled to one.
    NoBurst,
    /// An interval of zero earns a token in no time, which is a limit that
    /// never limits. [`Rate::unlimited`] is how a deployment asks for that on
    /// purpose.
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
    /// [`RateError`] for a `burst` or an `every` of zero, each of which means
    /// something other than what the deployment setting it meant.
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

    /// No limit: every INVITE reaches the policy hook, however fast they come.
    ///
    /// For a deployment whose one address is genuinely that busy, and which
    /// has something better than a token bucket to say about it.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            burst: u32::MAX,
            every: None,
        }
    }

    /// A hundred and twenty-eight at once, then one every fifty milliseconds:
    /// the preset for a voice agent or a headless answering service.
    ///
    /// Such a service takes every call from one trunk or proxy, dozens at a
    /// time when a campaign starts, and the default's one call every two
    /// seconds from that one address would answer the twelfth caller 480.
    /// The burst is the default ceiling on calls held at once
    /// (`EndpointConfig::max_dialogs`), so that at the start of a rush it is
    /// the ceiling that turns calls away, with a 503 an operator can count,
    /// and not the rate; twenty a second after that is well past what a trunk
    /// offers and still far short of what a flood sends.
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

    /// How many tokens a quiet spell of `elapsed` earned, or `None` when this
    /// rate is no limit.
    fn earned(self, elapsed: Duration) -> Option<u32> {
        let whole = elapsed.as_nanos().checked_div(self.every?.as_nanos())?;
        Some(u32::try_from(whole).unwrap_or(u32::MAX))
    }
}

impl Default for Rate {
    /// Ten at once, then one every two seconds.
    ///
    /// Loose on purpose: see the note at the top of this module about the one
    /// address every legitimate call arrives from. Written out rather than
    /// built through [`Rate::new`], which answers with a `Result` that a
    /// default has nowhere to put.
    fn default() -> Self {
        Self {
            burst: 10,
            every: Some(Duration::from_secs(2)),
        }
    }
}

/// What has been refused, cumulative since the agent was made.
///
/// Only ever grows, because the question an operator has is "how often has
/// this happened", not "how often since somebody last looked". A REFER
/// outside any dialog that the floor or the policy turned away
/// ([`crate::referral`]) is counted as the INVITE it would have become.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Refusals {
    /// INVITEs a [`Screen`] refused.
    pub by_policy: u64,
    /// INVITEs refused because their source was offering them faster than
    /// [`Rate`] allows.
    pub by_rate: u64,
    /// INVITEs refused because every seat in the table of watched sources
    /// belonged to a source still spending, so this one could not be limited
    /// and was not let in.
    ///
    /// Counted apart from [`Refusals::by_rate`] because the two are one
    /// refusal from the far end and two different things to do about it: one
    /// source calling too fast is [`UserAgent::limit_invites`], while many
    /// addresses arriving at once is a flood that wants a firewall.
    pub by_crowding: u64,
    /// INVITEs refused 403 for naming one of this end's live calls in a
    /// `Replaces` they had no standing to take (RFC 3891 §3).
    ///
    /// An attempt at taking over a call, or a transfer arriving by a route
    /// this end cannot recognise. Either way it is a number an operator
    /// wants, and one a stranger cannot turn into an event queue. It counts
    /// what [`Screen::on_replaces`] refused with 403 as well as what the
    /// default rule did, because to an operator they are the same event; a
    /// policy refusing with some other status is that policy's to count.
    pub by_replaces: u64,
}

/// An INVITE that has been read and not yet acted on.
///
/// What a decision needs and nothing else: where it came from, and what it
/// says.
#[derive(Clone, Copy, Debug)]
pub struct Incoming<'a> {
    source: Option<SocketAddr>,
    request: &'a OwnedMessage,
}

impl Incoming<'_> {
    /// The far end of the bytes this INVITE arrived in — not what the `Via`
    /// claims, which is whatever the sender typed.
    ///
    /// `None` in one case: a byte stream the application bound without saying
    /// who was at the other end of it. Naming the far end in
    /// [`Input::TransportBound`] is how that is closed, and a policy that
    /// cannot identify a caller may refuse it.
    #[must_use]
    pub const fn source(&self) -> Option<SocketAddr> {
        self.source
    }

    /// The request, whole.
    ///
    /// Everything else a policy might read is one call away on it:
    /// `request().as_raw().from()` for who the sender says it is,
    /// `request().as_raw().header(..)` for anything else.
    #[must_use]
    pub const fn request(&self) -> &OwnedMessage {
        self.request
    }

    /// `Referred-By`, when the request carries exactly one (RFC 3892 §2.1).
    ///
    /// **It is context, never authority.** RFC 3892 §2.2 has a transferee
    /// copy this field from the REFER that asked for the transfer, so on a
    /// legitimate attended transfer it names the transferor — which is
    /// exactly what a policy deciding about an off-path transferee wants to
    /// see. But it is a plain header field on the request being judged, and
    /// so is `From`: whoever wrote one wrote the other, and RFC 3892 §3's
    /// signed token, which is the only thing that would make either of them
    /// proof, is not implemented here. Read it to recognise a transfer you
    /// were expecting; do not read it as permission.
    ///
    /// `None` for a request with none and for one with more than one, which
    /// §2.1 forbids and which leaves nothing to read that the sender did not
    /// choose for us.
    #[must_use]
    pub fn referred_by(&self) -> Option<&[u8]> {
        let request = self.request.as_raw();
        if request.header_count(HeaderName::ReferredBy) != 1 {
            return None;
        }
        request.header(HeaderName::ReferredBy)
    }
}

/// The call an incoming `Replaces` names, and how its INVITE got here.
///
/// What [`Screen::on_replaces`] decides about. It is `non_exhaustive` because
/// what a policy needs in order to judge a takeover is exactly the kind of
/// thing that grows: an implementation reads the accessors it cares about and
/// is not broken by the next one.
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

    /// The call that would be hung up if this INVITE is answered.
    ///
    /// It is one of this end's own, matched on the `Call-ID` and both tags
    /// (RFC 3891 §3), and the application knows what it is and who it is
    /// with — which is the other half of deciding whether this takeover is
    /// the transfer it was expecting.
    #[must_use]
    pub const fn call(self) -> CallHandle {
        self.call
    }

    /// Whether the INVITE arrived from the same place the named call's own
    /// signalling does.
    ///
    /// The one thing about a `Replaces` the sender did not write. `true` also
    /// when neither address is known, which is a call received over a byte
    /// stream the application bound without naming its far end: nothing was
    /// recorded, so nothing is compared.
    #[must_use]
    pub const fn same_flow(self) -> bool {
        self.same_flow
    }

    /// What this gets when no policy says otherwise: the call when
    /// [`Replacing::same_flow`], and 403 when not.
    ///
    /// The default body of [`Screen::on_replaces`], and what runs when there
    /// is no [`Screen`] at all. It is public so that a policy which only
    /// wants to widen the rule for the one case it recognises can hand
    /// everything else back to it, rather than writing the strict half again
    /// and getting it subtly different.
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
    /// Let it through. The application hears about it exactly as it would
    /// have with no policy at all.
    Take,
    /// Answer it with this and let it go no further. No call is created and no
    /// event is emitted, so nothing downstream ever learns that it arrived.
    Refuse(StatusCode),
}

/// What the application decides about an INVITE nobody has heard yet.
///
/// Set with [`UserAgent::screen`]. It runs before ringing and before any
/// event, so what it refuses leaves no trace outside [`UserAgent::refusals`].
/// A closure of the same shape is a policy too, for a rule that needs no state
/// of its own.
///
/// It is called once per INVITE that survives the rate limit, on the thread
/// driving the agent, and it must not take long: it is between a packet and
/// the answer to it.
///
/// [`Screen::on_replaces`] is the second question, asked only of an INVITE
/// that names one of this end's live calls, and it is defaulted: a policy that
/// implements [`Screen::on_invite`] and nothing else — a closure included —
/// gets the strict rule RFC 3891 §3 is read as here, unchanged.
pub trait Screen {
    /// An INVITE has arrived.
    ///
    /// Or a REFER outside any dialog, once
    /// [`UserAgent::allow_referrals`] is on: somebody asking this end to
    /// place a call is screened as a call arriving is, and
    /// `invite.request()` says which of the two this is.
    fn on_invite(&mut self, invite: &Incoming<'_>) -> Screening;

    /// And its `Replaces` names one of this end's live calls (RFC 3891 §3).
    ///
    /// Answering it hangs that call up, so this is the last word on a
    /// takeover — and the rule underneath it is deliberately strict: a
    /// `Replaces` is honoured only when the INVITE carrying it arrived from
    /// the same place the named call's own signalling does, because the
    /// `Call-ID` and both tags travel in every packet of the call they name
    /// and this stack has no authenticated peer to compare instead. That is
    /// [`Replacing::strict`], it is what this method does by default, and an
    /// implementation that does not override it behaves exactly as one
    /// written before this method existed.
    ///
    /// **Override it where the strict rule is wrong, and it is wrong in a
    /// real deployment.** An attended transfer whose transferee reaches this
    /// end directly rather than through the line's proxy arrives from an
    /// address no call here was placed to, and the default refuses it. A
    /// policy that knows the deployment can take it — from the source
    /// address, from [`Incoming::referred_by`], from what
    /// [`Replacing::call`] is and who it is with — and the same hook can
    /// tighten as well as loosen: refusing a `Replaces` that did arrive on
    /// the call's own flow is a decision this returns, not one it overrides.
    ///
    /// It runs after [`Screen::on_invite`] has taken the same INVITE, and
    /// only once a call has actually been matched — a `Replaces` that names
    /// nothing is 481 and never reaches here, so guessing identifiers does
    /// not reach application code. What it returns is answered as it stands,
    /// except that the state of the matched call still has the last word
    /// afterwards: §3 declines a dialog that has already ended with 603
    /// however much anybody wants the takeover.
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
    /// The address without the port. A source port costs an attacker nothing
    /// to change, and counting per port would read one scanner as sixty
    /// thousand polite strangers.
    Address(IpAddr),
    /// A byte stream the application bound without saying who was at the
    /// other end of it. Nothing on its bytes names a sender, so the
    /// connection is the sender: every INVITE on it spends from one bucket,
    /// and it is the one thing a caller on it cannot change without opening
    /// another connection, which is the application's to accept or not.
    Stream(TransportId),
}

/// One source, and how much of its allowance is left.
#[derive(Clone, Copy, Debug)]
struct Watched {
    /// Who is spending.
    source: Origin,
    /// Tokens left.
    tokens: u32,
    /// What the tokens were last counted from. Not "when it last called": the
    /// part of a token that has been earned but not completed stays here, or a
    /// source calling just under the limit would be given a free one on every
    /// arrival.
    since: Instant,
}

impl Watched {
    /// A source seen for the first time, spending the call that revealed it.
    fn new(source: Origin, rate: Rate, now: Instant) -> Self {
        Self {
            source,
            tokens: rate.burst.saturating_sub(1),
            since: now,
        }
    }

    /// Give back what the quiet earned.
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

    /// Spend one, if there is one to spend.
    fn spend(&mut self) -> bool {
        let Some(left) = self.tokens.checked_sub(1) else {
            return false;
        };
        self.tokens = left;
        true
    }

    /// Whether this source has spent nothing that has not since been earned
    /// back, which makes it indistinguishable from one never seen.
    fn quiet(&self, rate: Rate) -> bool {
        self.tokens >= rate.burst
    }
}

/// What the floor made of one INVITE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Admission {
    /// There was a token, and it has been spent.
    Take,
    /// The source has spent its allowance and has not earned it back.
    TooFast,
    /// There is no seat left to keep an allowance in.
    NoRoom,
}

/// The sources being watched, at most [`WATCHED`] of them.
#[derive(Debug, Default)]
struct Sources {
    /// A linear scan of at most [`WATCHED`] beats a map plus something to
    /// order it by, and the scan is what the eviction needs anyway.
    watched: Vec<Watched>,
}

impl Sources {
    /// Whether this source may offer one more call, spending a token if so.
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

        // A source whose bucket has refilled completely says nothing that a
        // source never seen does not, so its seat is the one worth taking.
        for seat in &mut self.watched {
            seat.refill(rate, now);
        }
        let Some(seat) = self.watched.iter_mut().find(|seat| seat.quiet(rate)) else {
            // Every seat belongs to a source that is still spending, which is
            // what a flood from many addresses looks like from in here. The
            // stranger is refused rather than admitted untracked: admitting
            // what cannot be limited is a hole exactly when it matters, and a
            // quiet phone is the better failure at three in the morning. The
            // seats free themselves as their sources go quiet.
            return Admission::NoRoom;
        };
        *seat = Watched::new(source, rate, now);
        Admission::Take
    }

    /// A stream has closed, and the allowance kept against it with it: its
    /// identifier names nobody from here on, and one handed to the next
    /// connection must not come with what the last one spent.
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
    /// The far end of the bytes being worked through. Set before every
    /// [`UserAgent::receive`], and an INVITE only ever arrives during one.
    source: Option<SocketAddr>,
    /// The stream the bytes being worked through arrived on, set beside
    /// `source`: what the rate limit counts by when `source` is `None`.
    stream: Option<TransportId>,
    /// The far end of each connected transport, for the INVITEs that arrive on
    /// a stream where the address is not on the packet. Bounded by the
    /// transports the application opened, which is not something a stranger
    /// can grow.
    connected: HashMap<TransportId, SocketAddr>,
    /// This end of the bytes being worked through, and what carried them.
    /// Set beside `source`, and for the same kind of reader: an INVITE
    /// addressed to no account still needs a `Contact` naming where this end
    /// can be reached, and this is the one address that is true of it.
    arrival: Option<(SocketAddr, TransportProtocol)>,
    /// The transport the bytes being worked through arrived on: the flow an
    /// incoming request is matched to its account by.
    arrived_on: Option<TransportId>,
    /// Each bound transport's own address and protocol, for the bytes that
    /// arrive on a stream with neither on them. Bounded as `connected` is.
    bound: HashMap<TransportId, (SocketAddr, TransportProtocol)>,
}

impl fmt::Debug for Guard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // the policy is the application's own type, and its innards are its
        // own business
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
            // the enum is non-exhaustive across crate versions, and a source
            // this one cannot read is one it will not pretend to know
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

    /// What the rate limit counts the bytes being worked through against:
    /// the address they came from, or failing that the stream they came on.
    fn origin(&self) -> Option<Origin> {
        self.source
            .map(|source| Origin::Address(source.ip()))
            .or_else(|| self.stream.map(Origin::Stream))
    }

    /// Where the bytes being worked through came from, as far as the
    /// transport said. `None` on a byte stream the application bound without
    /// naming its far end.
    pub(crate) const fn source(&self) -> Option<SocketAddr> {
        self.source
    }

    /// Where on this end the bytes being worked through arrived, and over
    /// what. `None` between arrivals and for a transport never bound.
    pub(crate) const fn arrival(&self) -> Option<(SocketAddr, TransportProtocol)> {
        self.arrival
    }

    /// The transport the bytes being worked through arrived on. `None`
    /// between arrivals.
    pub(crate) const fn arrived_on(&self) -> Option<TransportId> {
        self.arrived_on
    }

    /// What the application says about an INVITE whose `Replaces` names one
    /// of this end's live calls (RFC 3891 §3).
    ///
    /// The same answer with no policy set as with one that does not override
    /// [`Screen::on_replaces`], which is the rule written down in
    /// [`Replacing::strict`] and nowhere else.
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

    /// One more INVITE refused because its `Replaces` named a call the sender
    /// was not the peer of (RFC 3891 §3).
    pub(crate) const fn refused_replaces(&mut self) {
        self.refusals.by_replaces = self.refusals.by_replaces.saturating_add(1);
    }

    /// What happens to this INVITE: `None` to let it through, or the status to
    /// refuse it with.
    ///
    /// A REFER outside any dialog is asked the same, once the application
    /// takes them at all ([`crate::referral`]): it is a call this end would
    /// place, which is what the floor and the policy both ration.
    pub(crate) fn decide(&mut self, request: &OwnedMessage, now: Instant) -> Option<StatusCode> {
        // The floor comes first. It is two numbers and a short scan, where the
        // policy is arbitrary application code — and code called once per
        // INVITE by whoever is sending them is the second attack.
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
    /// The policy runs before ringing and before any event, and what it
    /// refuses is answered and forgotten: no call, no handle, nothing to drain
    /// and nothing to clean up. One policy at a time; setting a second
    /// replaces the first.
    ///
    /// The same policy is what [`Screen::on_replaces`] is asked of, so an
    /// application that wants a say in who may take one of its calls over
    /// sets it here and overrides that method — a closure cannot, which is
    /// the price of a policy that carries no state.
    pub fn screen(&mut self, policy: impl Screen + Send + 'static) {
        self.guard.policy = Some(Box::new(policy));
    }

    /// Take the screening policy off, if one is set.
    ///
    /// What arrives afterwards reaches the application exactly as it would
    /// if [`UserAgent::screen`] had never been called. The rate limit set by
    /// [`UserAgent::limit_invites`] answers a different question and is left
    /// exactly where it was — removing the policy is not a reason to stop
    /// counting how fast one source is calling.
    pub fn unscreen(&mut self) {
        self.guard.policy = None;
    }

    /// How fast one source address may offer calls.
    ///
    /// The default is loose, because in most deployments every legitimate call
    /// arrives from the one address the phone registered with. Tighten it for
    /// a phone that faces the internet directly; loosen it for a switchboard
    /// that really does ring this extension that often.
    pub const fn limit_invites(&mut self, rate: Rate) {
        self.guard.rate = rate;
    }

    /// The limit that is in force, which is the one that was set.
    ///
    /// Here because a setting nobody can read back is a setting nobody can
    /// tell apart from one that was quietly changed on the way in.
    #[must_use]
    pub const fn invite_limit(&self) -> Rate {
        self.guard.rate
    }

    /// What has been refused, cumulative.
    #[must_use]
    pub const fn refusals(&self) -> Refusals {
        self.guard.refusals
    }

    /// `None` when the INVITE was refused here and the application will never
    /// hear of it; the event back when it may go on.
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

        // Answered rather than dropped, although silence would tell a scanner
        // even less. An INVITE nobody answers is retransmitted for thirty-two
        // seconds and holds a server transaction here for all of it, so
        // silence is the caller growing our table for free — and a refusal
        // that costs the defender more than the attacker is not a defence.
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

    /// A rate that is not one of the two the constructor refuses.
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
        // a source calling just under the limit must not be credited with the
        // fraction of a token it has earned, over and over
        let t0 = Instant::now();
        let rate = rate(1, Duration::from_secs(2));
        let mut sources = Sources::default();
        assert_eq!(sources.admit(source(9), rate, t0), Admission::Take);
        let mut at = t0;
        for _ in 0..4 {
            at += Duration::from_millis(1500);
            sources.admit(source(9), rate, at);
        }
        // four and a half intervals have passed and five calls were offered,
        // so at most three of them can have been admitted
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
        // B2: a setting is applied, rejected with a reason, or unsupported.
        // Reading a zero as a one is the fourth answer, which does not exist
        assert_eq!(
            Rate::new(0, Duration::from_secs(2)),
            Err(RateError::NoBurst)
        );
    }

    #[test]
    fn an_interval_of_none_is_refused_rather_than_taken_for_no_limit() {
        // it does mean no limit arithmetically, which is exactly why it has to
        // be said on purpose: an interval that came out of a division and
        // rounded to nothing would otherwise disable the floor without a word
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

    /// A trunk handing a voice agent a campaign's first minute: the default
    /// answers the eleventh call 480, the preset takes the whole rush and
    /// twenty a second after it.
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
