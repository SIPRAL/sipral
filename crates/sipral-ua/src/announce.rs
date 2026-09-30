// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A call that was announced before it arrived.
//!
//! On a phone the order of events is inverted. A push notification wakes the
//! process and the platform gives it one run loop to raise the system call
//! screen — no delay, no exceptions, and an application that misses the
//! deadline stops being woken at all. So the user is looking at a ringing call
//! before there is a transport, before the registration has been refreshed, and
//! long before an INVITE exists. Everything here follows from that one
//! sentence.
//!
//! What the application can say at that moment is all it knows: a call is
//! expected on this account, from this caller, announced now. What this module
//! owes it back is three things — the binding refreshed at once so the network
//! will deliver the INVITE, the INVITE recognised as the one that was
//! announced, and a plain statement when nothing ever came.
//!
//! **The matching rule, and why it is this one.** RFC 8599 gives a push no
//! payload to carry: §13 says the mechanism "does not require a proxy to
//! insert any payload", and §5.6.2 has the proxy hold the SIP request in a
//! bucket and forward it only after the REGISTER it triggered has been
//! answered. There is no `Call-ID` in a push, and there is no way to put one
//! there. What is left is the account and the caller, so that is what is
//! matched: the account, and the user and host of the `From` URI.
//!
//! Nothing else about the URI is compared. A proxy rewrites the parameters and
//! the display name on the way through, and requiring §19.1.4 equivalence
//! would fail to match almost every real call — which sounds like the safe
//! direction and is not, because the failure mode is a second call screen for
//! a call the user is already looking at.
//!
//! Time is only a tie-break. Two announcements outstanding for two different
//! callers are told apart by who is calling, whichever arrived first; matching
//! first-come would show the user the wrong name half the time. Two
//! announcements that name the *same* caller on the *same* account are
//! genuinely indistinguishable, and there the oldest is taken first — not
//! because it is more likely to be right, but because when nothing
//! distinguishes them there is no wrong answer about who is calling, and the
//! pushes and the INVITEs are both in the order the proxy made them.
//!
//! An announcement is used once and then gone. Two calls from the same person
//! in ten seconds need two pushes, which is what the proxy sends.

use std::time::{Duration, Instant};

use sipral_core::endpoint::{Input, TransportId};
use sipral_core::msg::{HostRef, OwnedMessage, Uri, UriRef, unescape};

use crate::account::AccountId;
use crate::agent::UserAgent;
use crate::call::CallHandle;
use crate::error::UaError;
use crate::event::{RegistrationState, UaEvent};

/// How long an announced call is waited for before it is called missing.
///
/// The far end's own INVITE transaction gives up after 64·T1, thirty-two
/// seconds, so a window longer than that would be waiting for a caller who has
/// already hung up. Twenty leaves room for the whole cold path — a name
/// resolved, a connection built, a challenge answered, a REGISTER
/// retransmitted on a radio that was idle — and still ends while somebody is
/// looking at the screen rather than after they have given up on it.
pub(crate) const WINDOW: Duration = Duration::from_secs(20);

/// The name of one announcement inside one [`UserAgent`].
///
/// Minted by [`UserAgent::announce`] and never reused, so a handle to an
/// announcement that has been fulfilled or has expired names nothing rather
/// than naming the next one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnnouncementId(pub(crate) u32);

/// A call the application was told to expect.
#[derive(Clone, Debug)]
pub struct Announcement {
    pub(crate) id: AnnouncementId,
    pub(crate) account: AccountId,
    pub(crate) caller: Uri,
    pub(crate) at: Instant,
}

impl Announcement {
    /// Its name.
    #[must_use]
    pub const fn id(&self) -> AnnouncementId {
        self.id
    }

    /// The account the call was announced on.
    #[must_use]
    pub const fn account(&self) -> AccountId {
        self.account
    }

    /// Who the push said is calling.
    #[must_use]
    pub const fn caller(&self) -> &Uri {
        &self.caller
    }

    /// When the application said it had been announced.
    ///
    /// The instant the wake-up was handled, not the instant the push was sent:
    /// the delay between those two is the notification service's and nothing
    /// here can see it.
    #[must_use]
    pub const fn at(&self) -> Instant {
        self.at
    }
}

/// What [`UserAgent::announce`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Announced {
    /// Nothing has arrived yet. The INVITE that matches will be reported as a
    /// [`UaEvent::CallAnnounced`] naming this announcement, immediately before
    /// the [`UaEvent::IncomingCall`] for the same call.
    Waiting(AnnouncementId),
    /// The INVITE beat the push, and this is the call it announced.
    ///
    /// Nothing further is coming: the call screen the application has just
    /// raised belongs to this handle, and no announcement was recorded.
    Arrived(CallHandle),
}

/// An incoming call, as much of it as matching needs.
///
/// Kept beside the call rather than inside it, because none of this is
/// anything the call itself does: it exists so that a push arriving a moment
/// late can still find the INVITE that beat it.
#[derive(Clone, Debug)]
pub(crate) struct Arrival {
    at: Instant,
    account: Option<AccountId>,
    caller: Option<Uri>,
    matched: bool,
}

impl UserAgent {
    /// A call is expected on `account`, from `caller`, announced now.
    ///
    /// Two things happen. The binding is refreshed at once, on whatever path
    /// exists — RFC 8599 §4.1.3 makes that a MUST for a woken UA, and it is
    /// also what tells the proxy holding the INVITE in its bucket (§5.6.2)
    /// that this device is here. And the announcement is remembered, so that
    /// the INVITE which follows is reported as the one that was expected
    /// rather than as a second call.
    ///
    /// The caller is not optional and cannot be. An announcement with nobody
    /// in it could only match whatever arrived next, and a wrong match puts
    /// somebody else's name on the screen the user is already looking at.
    ///
    /// If the INVITE got here first — which happens, and RFC 8599 §4.1.3 says
    /// so: "depending on which transport protocol is used, the SIP request
    /// might reach the UA before the REGISTER response" — the answer is
    /// [`Announced::Arrived`] with the call that is already ringing, and
    /// nothing is recorded.
    ///
    /// An account with no registrar has no binding to refresh, so for one of
    /// those only the second half happens: matching the INVITE that follows
    /// is about the account and the caller, not about a binding.
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`].
    pub fn announce(
        &mut self,
        account: AccountId,
        caller: Uri,
        now: Instant,
    ) -> Result<Announced, UaError> {
        if !self.accounts.contains_key(&account) {
            return Err(UaError::NoSuchAccount);
        }
        let already = self.ringing_already(account, &caller, now);
        let announcement = self.mint(account, caller, now);
        let answer = if let Some(call) = already {
            if let Some(arrival) = self.arrivals.get_mut(&call) {
                arrival.matched = true;
            }
            self.attach(call, announcement);
            Announced::Arrived(call)
        } else {
            let id = announcement.id;
            self.announcements.push(announcement);
            Announced::Waiting(id)
        };
        // §4.1.3 asks for the refresh whatever else happened, and a transport
        // that is not up yet is the ordinary shape of a wake-up: the
        // application is still opening a socket. The REGISTER is owed and goes
        // the moment it hands one over, and the announcement stands either way
        self.refresh_binding(account, now).ok();
        Ok(answer)
    }

    /// Send a binding-refresh REGISTER now, without waiting for the scheduled
    /// one (RFC 8599 §4.1.3).
    ///
    /// For a push that announces nothing — the periodic wake-up a proxy sends
    /// to keep a suspended device's binding alive (§5.5). A push is evidence
    /// that the path to the proxy is working, so a back-off earned by an
    /// earlier outage is not what to wait for now and is dropped.
    ///
    /// Nothing is sent when a REGISTER is already in flight, which is already
    /// the fastest path, or when the registration has failed in a way that
    /// trying again cannot fix — repeating a password that was refused is how
    /// an account gets locked out, and a push does not change that.
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`]; [`UaError::NoRegistrar`] for an account
    /// that never registers, which has no binding to refresh and is owed
    /// nothing; or [`UaError::Send`] when there is no transport yet. The last
    /// is not fatal: the refresh is remembered and sent when a transport is
    /// bound.
    pub fn refresh_binding(&mut self, account: AccountId, now: Instant) -> Result<(), UaError> {
        let config = self.accounts.get(&account).ok_or(UaError::NoSuchAccount)?;
        // turned away before the refresh can be remembered as owed: one owed
        // to an account with no registrar would be tried again, and refused
        // again, on every transport the application ever binds
        if config.registrar.is_none() {
            return Err(UaError::NoRegistrar);
        }
        let reg = self
            .registrations
            .get_mut(&account)
            .ok_or(UaError::NoSuchAccount)?;
        if reg.transaction.is_some() || reg.state == RegistrationState::Failed {
            return Ok(());
        }
        reg.failures = 0;
        match self.send_register(account, false, now) {
            Ok(()) => {
                self.drain(now);
                Ok(())
            }
            Err(error) => {
                if let Some(reg) = self.registrations.get_mut(&account) {
                    reg.owed = true;
                }
                Err(error)
            }
        }
    }

    /// What was announced and has not been answered by an INVITE yet.
    #[must_use]
    pub fn announcement(&self, id: AnnouncementId) -> Option<&Announcement> {
        self.announcements
            .iter()
            .find(|announcement| announcement.id == id)
    }

    /// Stop expecting a call: the user dismissed the screen, or the
    /// application decided the wake-up was stale.
    ///
    /// `false` when it had already been fulfilled or had already expired.
    pub fn forget_announcement(&mut self, id: AnnouncementId) -> bool {
        let before = self.announcements.len();
        self.announcements
            .retain(|announcement| announcement.id != id);
        self.announcements.len() != before
    }

    /// How long an announced call is waited for. Twenty seconds unless this
    /// says otherwise: inside the 64·T1 the caller's own INVITE transaction
    /// gives up after, and long enough for the whole cold path.
    ///
    /// Worth changing while a wake-up chain is being tuned, and worth changing
    /// in only one direction afterwards: a long window keeps a call screen up
    /// for a call that will never come, and a short one reports a call missing
    /// that is still on its way.
    pub const fn expect_within(&mut self, window: Duration) {
        self.announce_window = window;
    }

    fn mint(&mut self, account: AccountId, caller: Uri, at: Instant) -> Announcement {
        let id = AnnouncementId(self.next_announcement);
        self.next_announcement = self.next_announcement.wrapping_add(1);
        Announcement {
            id,
            account,
            caller,
            at,
        }
    }

    /// A call that is already ringing and that this announcement names.
    ///
    /// Only one that arrived inside the window and that no earlier
    /// announcement has claimed. Oldest first, for the reason in the module
    /// note.
    fn ringing_already(
        &self,
        account: AccountId,
        caller: &Uri,
        now: Instant,
    ) -> Option<CallHandle> {
        let window = self.announce_window;
        let mut best: Option<(Instant, CallHandle)> = None;
        for (call, arrival) in &self.arrivals {
            if arrival.matched
                || arrival.account != Some(account)
                || arrival.at + window < now
                || !arrival
                    .caller
                    .as_ref()
                    .is_some_and(|from| same_caller(caller, from))
            {
                continue;
            }
            if best.is_none_or(|(at, _)| arrival.at < at) {
                best = Some((arrival.at, *call));
            }
        }
        best.map(|(_, call)| call)
    }

    /// Say that `call` is what `announcement` announced.
    ///
    /// The event goes in front of the [`UaEvent::IncomingCall`] for the same
    /// call when that one has not been read yet, so an application walking the
    /// queue in order knows the call belongs to a screen it has already raised
    /// before it is told the call exists. When the application has already
    /// read it — which is the only way the INVITE can have beaten the push —
    /// the answer from [`UserAgent::announce`] is what told it, and repeating
    /// the news afterwards would say nothing new.
    fn attach(&mut self, call: CallHandle, announcement: Announcement) {
        let at = self.events.iter().position(|event| {
            matches!(*event, UaEvent::IncomingCall { call: waiting, .. } if waiting == call)
        });
        let Some(at) = at else {
            return;
        };
        self.events
            .insert(at, UaEvent::CallAnnounced { call, announcement });
    }

    /// Match every incoming call that has just been reported to whatever
    /// announced it.
    ///
    /// This runs at the end of the drain rather than where the INVITE becomes
    /// a call, because matching is not a property of the call: it is a
    /// question about everything outstanding, and asking it once per drain is
    /// the only place where the answer cannot depend on the order two INVITEs
    /// happened to be parsed in.
    pub(crate) fn settle_announcements(&mut self, now: Instant) {
        // an arrival is only ever needed while a push could still be late, and
        // only while the call it is about exists
        let window = self.announce_window;
        self.arrivals
            .retain(|call, arrival| arrival.at + window >= now && self.calls.contains_key(call));

        let fresh: Vec<(usize, CallHandle, Option<AccountId>, Option<Uri>)> = self
            .events
            .iter()
            .enumerate()
            .filter_map(|(at, event)| match *event {
                UaEvent::IncomingCall {
                    call,
                    account,
                    ref request,
                    ..
                } if !self.arrivals.contains_key(&call) => {
                    Some((at, call, account, caller_of(request)))
                }
                _ => None,
            })
            .collect();

        // back to front, so that inserting an event does not move the ones
        // that have not been looked at yet
        for (at, call, account, caller) in fresh.into_iter().rev() {
            let matched = account
                .zip(caller.as_ref())
                .and_then(|(account, caller)| self.claim(account, caller, now));
            self.arrivals.insert(
                call,
                Arrival {
                    at: now,
                    account,
                    caller,
                    matched: matched.is_some(),
                },
            );
            if let Some(announcement) = matched {
                self.events
                    .insert(at, UaEvent::CallAnnounced { call, announcement });
            }
        }
    }

    /// Take the announcement an INVITE from `caller` on `account` fulfils.
    fn claim(&mut self, account: AccountId, caller: &Uri, now: Instant) -> Option<Announcement> {
        let window = self.announce_window;
        let mut best: Option<usize> = None;
        for (at, announcement) in self.announcements.iter().enumerate() {
            if announcement.account != account
                || announcement.at + window < now
                || !same_caller(&announcement.caller, caller)
            {
                continue;
            }
            let older = best.is_none_or(|chosen| {
                self.announcements
                    .get(chosen)
                    .is_some_and(|held| announcement.at < held.at)
            });
            if older {
                best = Some(at);
            }
        }
        best.map(|at| self.announcements.remove(at))
    }

    /// The announcements whose window has run out.
    pub(crate) fn fire_announce_timers(&mut self, now: Instant) {
        let window = self.announce_window;
        let mut missed = Vec::new();
        self.announcements.retain(|announcement| {
            let alive = announcement.at + window > now;
            if !alive {
                missed.push(announcement.clone());
            }
            alive
        });
        for announcement in missed {
            self.events.push_back(UaEvent::AnnouncedCallMissing {
                announcement,
                waited: window,
            });
        }
        self.arrivals
            .retain(|call, arrival| arrival.at + window >= now && self.calls.contains_key(call));
    }

    /// When the earliest outstanding announcement stops being one.
    pub(crate) fn announce_deadline(&self) -> Option<Instant> {
        self.announcements
            .iter()
            .map(|announcement| announcement.at + self.announce_window)
            .min()
    }

    /// A transport has been bound: send whatever a push asked for and could
    /// not have.
    ///
    /// This is the other half of the pre-warm. The stack cannot open a socket
    /// — it has none of the platform's opinions about which interface, which
    /// certificate or which of them survived the sleep — so the fastest it can
    /// be is to have the REGISTER ready and send it in the same call in which
    /// the application hands it a transport.
    pub(crate) fn on_transport_bound(&mut self, transport: TransportId, now: Instant) {
        let owed: Vec<AccountId> = self
            .accounts
            .iter()
            .filter(|(id, account)| {
                account.transport == transport
                    && self.registrations.get(id).is_some_and(|reg| reg.owed)
            })
            .map(|(id, _)| *id)
            .collect();
        for account in owed {
            self.refresh_binding(account, now).ok();
        }
        // And the retries RFC 3261 §18.1.1 would not let out over a datagram.
        // This runs before the drain that follows it, which is what keeps a
        // parked retry from being settled as a refusal in the same round: by
        // the time the settle passes look, the answer is already in flight.
        //
        // None of them filters on `transport`. At the moment a retry parks
        // there is no bound stream — that is why it parked — so which one
        // will carry it is not known until one exists. Anything the endpoint
        // still will not send simply parks again.
        self.resume_parked_registrations(now);
        self.resume_parked_calls(now);
        self.resume_parked_requests(now);
        self.resume_parked_offers(now);
        self.resume_parked_subscriptions(now);
        self.resume_parked_messages(now);
        self.resume_parked_publications(now);
        // Then what this layer sends inside a dialog by itself, last because
        // hanging a call up drains on its way out
        self.resume_parked_sends(now);
    }
}

/// The `From` URI of an INVITE, which is the only identity a push can be
/// matched against.
fn caller_of(request: &OwnedMessage) -> Option<Uri> {
    let raw = request.as_raw();
    let from = raw.from().ok()?;
    Uri::parse(from.uri_bytes()).ok()
}

/// Whether a push and an INVITE name the same caller.
///
/// User and host, and deliberately nothing else. §19.1.4's full equivalence is
/// wrong here in both directions: it insists that a parameter present in one
/// URI be present in the other, which a proxy breaks on the way through, and
/// it says nothing about the display name, which is the part a push payload
/// usually carries instead of a URI. The user part is compared unescaped and
/// case-sensitively, as §19.1.4 requires; the host without regard to case, as
/// §19.1.4 also requires. `sip:` and `sips:` are not told apart either,
/// although §19.1.4 says they are never equivalent: whether the leg that
/// reached us was encrypted says nothing about who is on it, and refusing the
/// match would put a second screen in front of the user rather than a wrong
/// name.
///
/// A URI of any other scheme falls back to whole-URI equivalence, because
/// there is no user and host to take apart and guessing at one would be the
/// wrong-caller failure again.
fn same_caller(announced: &Uri, invited: &Uri) -> bool {
    match (announced.as_uri_ref(), invited.as_uri_ref()) {
        (UriRef::Sip(a), UriRef::Sip(b)) => {
            let user = match (a.user, b.user) {
                (Some(a), Some(b)) => unescape(a.as_bytes()) == unescape(b.as_bytes()),
                (None, None) => true,
                _ => false,
            };
            user && same_host(a.host, b.host)
        }
        _ => announced.equivalent(invited),
    }
}

fn same_host(a: HostRef<'_>, b: HostRef<'_>) -> bool {
    match (a, b) {
        (HostRef::Name(a), HostRef::Name(b)) => a.eq_ignore_ascii_case(b),
        (HostRef::Ipv4(a), HostRef::Ipv4(b)) => a == b,
        (HostRef::Ipv6(a), HostRef::Ipv6(b)) => a == b,
        _ => false,
    }
}

/// The transport an input announces, when the input is the announcement of
/// one.
pub(crate) const fn bound_transport(input: &Input<'_>) -> Option<TransportId> {
    match *input {
        Input::TransportBound { transport, .. } => Some(transport),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{Announced, WINDOW, same_caller};
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, RawMessage, parse};

    use crate::account::{Account, AccountId, Push};
    use crate::agent::UserAgent;
    use crate::call::CallHandle;
    use crate::event::{RegistrationState, UaEvent};
    use crate::{EndpointConfig, Input, TransportId, TransportProtocol, UaError, Uri};

    const UDP: TransportId = TransportId(1);

    fn local() -> SocketAddr {
        "192.0.2.1:5060".parse().expect("a local address")
    }

    fn registrar() -> SocketAddr {
        "192.0.2.9:5060".parse().expect("the registrar's address")
    }

    fn uri(text: &str) -> Uri {
        Uri::parse_str(text).expect("a URI")
    }

    fn account() -> Account {
        Account::new(
            uri("sip:alice@example.com"),
            uri("sip:example.com"),
            uri("sip:alice@192.0.2.1"),
            UDP,
            registrar(),
        )
    }

    /// The same address of record with no registrar, whose requests go to a
    /// proxy.
    fn trunk() -> Account {
        Account::unregistered(
            uri("sip:alice@example.com"),
            uri("sip:alice@192.0.2.1"),
            UDP,
            "198.51.100.20:5060".parse().expect("the proxy's address"),
        )
    }

    /// A user agent with nothing bound yet, which is what a phone woken by a
    /// push actually has.
    fn asleep(seed: u8) -> UserAgent {
        UserAgent::new(EndpointConfig::default(), [seed; 32]).unwrap()
    }

    fn bind(agent: &mut UserAgent, now: Instant) {
        agent
            .receive(
                Input::TransportBound {
                    transport: UDP,
                    protocol: TransportProtocol::Udp,
                    local: local(),
                    remote: None,
                },
                now,
            )
            .expect("binding a transport");
    }

    fn awake(now: Instant) -> UserAgent {
        let mut agent = asleep(11);
        bind(&mut agent, now);
        agent
    }

    fn transmits(agent: &mut UserAgent) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(transmit) = agent.poll_transmit() {
            out.push(transmit.payload.to_vec());
        }
        out
    }

    fn sent(agent: &mut UserAgent) -> Vec<u8> {
        let mut all = transmits(agent);
        assert_eq!(all.len(), 1, "expected exactly one message out");
        all.pop().unwrap_or_default()
    }

    fn events(agent: &mut UserAgent) -> Vec<UaEvent> {
        let mut out = Vec::new();
        while let Some(event) = agent.poll_event() {
            out.push(event);
        }
        out
    }

    fn with<T>(bytes: &[u8], f: impl FnOnce(&RawMessage<'_>) -> T) -> T {
        let mut scratch = ParseScratch::new();
        f(&parse(bytes, &mut scratch, ParseMode::Lenient).expect("a message"))
    }

    fn header(bytes: &[u8], name: HeaderName<'_>) -> Vec<u8> {
        with(bytes, |message| {
            message.header(name).unwrap_or_default().to_vec()
        })
    }

    fn text(bytes: &[u8], name: HeaderName<'_>) -> String {
        String::from_utf8_lossy(&header(bytes, name)).into_owned()
    }

    fn reply(request: &[u8], status: u16, reason: &str, extra: &str) -> Vec<u8> {
        let mut out = format!("SIP/2.0 {status} {reason}\r\n").into_bytes();
        for (name, value) in [
            ("Via", header(request, HeaderName::Via)),
            ("From", header(request, HeaderName::From)),
            ("To", header(request, HeaderName::To)),
            ("Call-ID", header(request, HeaderName::CallId)),
            ("CSeq", header(request, HeaderName::CSeq)),
        ] {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(extra.as_bytes());
        out.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        out
    }

    fn deliver(agent: &mut UserAgent, bytes: &[u8], now: Instant) {
        agent
            .receive(
                Input::Datagram {
                    transport: UDP,
                    remote: registrar(),
                    local: local(),
                    data: bytes,
                },
                now,
            )
            .expect("a well formed datagram");
    }

    /// An INVITE from `from`, which is the identity a push has to be matched
    /// against.
    fn invite_from(from: &str, branch: &str) -> Vec<u8> {
        format!(
            "INVITE sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK{branch};rport\r\n\
Max-Forwards: 70\r\n\
From: <{from}>;tag=tag{branch}\r\n\
To: Alice <sip:alice@example.com>\r\n\
Call-ID: incoming-{branch}\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:caller@192.0.2.9>\r\n\
Content-Length: 0\r\n\r\n"
        )
        .into_bytes()
    }

    /// An agent with a live binding, and everything it said on the way there
    /// drained.
    fn registered(now: Instant) -> (UserAgent, AccountId) {
        let mut agent = awake(now);
        let id = agent.add_account(account());
        agent.register(id, now).expect("a REGISTER goes");
        let request = sent(&mut agent);
        deliver(
            &mut agent,
            &reply(
                &request,
                200,
                "OK",
                "Contact: <sip:alice@192.0.2.1>;expires=3600\r\n",
            ),
            now,
        );
        events(&mut agent);
        (agent, id)
    }

    fn announced(events: &[UaEvent]) -> Vec<(CallHandle, u32)> {
        events
            .iter()
            .filter_map(|event| match *event {
                UaEvent::CallAnnounced {
                    call,
                    ref announcement,
                } => Some((call, announcement.id().0)),
                _ => None,
            })
            .collect()
    }

    fn incoming(events: &[UaEvent]) -> Vec<CallHandle> {
        events
            .iter()
            .filter_map(|event| match *event {
                UaEvent::IncomingCall { call, .. } => Some(call),
                _ => None,
            })
            .collect()
    }

    fn waiting(answer: Announced) -> super::AnnouncementId {
        match answer {
            Announced::Waiting(id) => id,
            Announced::Arrived(call) => panic!("nothing had arrived, but {call:?} did"),
        }
    }

    #[test]
    fn an_announcement_refreshes_the_binding_without_waiting_for_the_schedule() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        // the scheduled refresh is fifty-one minutes away, and the call is now
        agent.handle_timeout(t0 + Duration::from_secs(60));
        assert!(
            transmits(&mut agent).is_empty(),
            "nothing was due on the schedule"
        );

        agent
            .announce(id, uri("sip:bob@example.com"), t0 + Duration::from_secs(60))
            .expect("an announcement");
        let refresh = sent(&mut agent);
        assert!(refresh.starts_with(b"REGISTER sip:example.com SIP/2.0\r\n"));
        assert_eq!(
            agent.registration_state(id),
            Some(RegistrationState::Refreshing)
        );
    }

    #[test]
    fn a_push_that_arrives_before_the_invite_names_the_call_that_follows() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let announcement = waiting(
            agent
                .announce(id, uri("sip:bob@example.com"), t0)
                .expect("an announcement"),
        );
        transmits(&mut agent);
        events(&mut agent);

        deliver(&mut agent, &invite_from("sip:bob@example.com", "one"), t0);
        transmits(&mut agent);
        let seen = events(&mut agent);

        assert_eq!(
            announced(&seen),
            vec![(
                *incoming(&seen).first().expect("somebody is calling"),
                announcement.0
            )],
            "the call is the one that was announced"
        );
        let first = seen
            .iter()
            .position(|event| matches!(*event, UaEvent::CallAnnounced { .. }))
            .expect("the announcement is reported");
        let then = seen
            .iter()
            .position(|event| matches!(*event, UaEvent::IncomingCall { .. }))
            .expect("the call is reported");
        assert!(
            first < then,
            "the application is told which screen this is before it is told there is a call"
        );
        assert!(agent.announcement(announcement).is_none(), "used once");
    }

    #[test]
    fn an_announced_call_that_never_arrives_is_reported_rather_than_forgotten() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        agent
            .announce(id, uri("sip:bob@example.com"), t0)
            .expect("an announcement");
        transmits(&mut agent);
        events(&mut agent);

        assert!(
            agent.poll_timeout().is_some_and(|at| at <= t0 + WINDOW),
            "the agent asks to be woken no later than the window"
        );
        agent.handle_timeout(t0 + WINDOW);
        let missing = events(&mut agent)
            .into_iter()
            .find_map(|event| match event {
                UaEvent::AnnouncedCallMissing {
                    announcement,
                    waited,
                } => Some((announcement, waited)),
                _ => None,
            })
            .expect("the diagnosis");
        assert_eq!(missing.0.caller().as_bytes(), b"sip:bob@example.com");
        assert_eq!(missing.1, WINDOW);
    }

    #[test]
    fn a_call_the_far_end_gave_up_on_before_the_wake_up_matches_nothing_afterwards() {
        // the first race: the caller hung up while the phone was still waking,
        // so the announcement is fulfilled by nothing. The INVITE that arrives
        // later is a different call and must not inherit the dead screen
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        agent
            .announce(id, uri("sip:bob@example.com"), t0)
            .expect("an announcement");
        transmits(&mut agent);
        agent.handle_timeout(t0 + WINDOW);
        assert!(
            events(&mut agent)
                .iter()
                .any(|event| matches!(*event, UaEvent::AnnouncedCallMissing { .. }))
        );

        let later = t0 + WINDOW + Duration::from_secs(30);
        deliver(
            &mut agent,
            &invite_from("sip:bob@example.com", "two"),
            later,
        );
        transmits(&mut agent);
        let seen = events(&mut agent);
        assert_eq!(incoming(&seen).len(), 1, "the second call still arrives");
        assert!(
            announced(&seen).is_empty(),
            "and it is nobody's announcement"
        );
    }

    #[test]
    fn an_announcement_past_its_window_is_not_claimed_by_an_invite_that_woke_us_first() {
        // the same race, on the path where nothing has expired anything yet:
        // a datagram can arrive before the timeout the agent asked for, so the
        // window has to be checked where the match is made and not only where
        // the sweep runs
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let stale = waiting(
            agent
                .announce(id, uri("sip:bob@example.com"), t0)
                .expect("an announcement"),
        );
        transmits(&mut agent);
        events(&mut agent);

        let late = t0 + WINDOW + Duration::from_secs(1);
        deliver(&mut agent, &invite_from("sip:bob@example.com", "b1"), late);
        transmits(&mut agent);
        let seen = events(&mut agent);
        assert_eq!(incoming(&seen).len(), 1, "the call still arrives");
        assert!(
            announced(&seen).is_empty(),
            "and it is not the one that was announced twenty seconds ago"
        );
        assert!(
            agent.announcement(stale).is_some(),
            "which is still outstanding, and still owed the diagnosis"
        );
    }

    #[test]
    fn two_calls_in_quick_succession_each_find_the_announcement_that_named_them() {
        // the second race, and the reason matching is not first-come: Carol's
        // INVITE arrives first and must take Carol's announcement even though
        // Bob's was made earlier
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let bob = waiting(
            agent
                .announce(id, uri("sip:bob@example.com"), t0)
                .expect("Bob is announced"),
        );
        let carol = waiting(
            agent
                .announce(
                    id,
                    uri("sip:carol@example.com"),
                    t0 + Duration::from_millis(400),
                )
                .expect("Carol is announced"),
        );
        transmits(&mut agent);
        events(&mut agent);

        let t1 = t0 + Duration::from_secs(1);
        deliver(&mut agent, &invite_from("sip:carol@example.com", "c1"), t1);
        transmits(&mut agent);
        let seen = events(&mut agent);
        let first = *incoming(&seen).first().expect("Carol is calling");
        assert_eq!(announced(&seen), vec![(first, carol.0)]);

        let t2 = t0 + Duration::from_secs(2);
        deliver(&mut agent, &invite_from("sip:bob@example.com", "b1"), t2);
        transmits(&mut agent);
        let seen = events(&mut agent);
        let second = *incoming(&seen).first().expect("Bob is calling");
        assert_eq!(announced(&seen), vec![(second, bob.0)]);
        assert_ne!(first, second, "two calls, not one");
    }

    #[test]
    fn two_announcements_nothing_tells_apart_are_taken_oldest_first() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let first = waiting(
            agent
                .announce(id, uri("sip:bob@example.com"), t0)
                .expect("the first"),
        );
        let second = waiting(
            agent
                .announce(
                    id,
                    uri("sip:bob@example.com"),
                    t0 + Duration::from_millis(200),
                )
                .expect("the second"),
        );
        transmits(&mut agent);
        events(&mut agent);

        let t1 = t0 + Duration::from_secs(1);
        deliver(&mut agent, &invite_from("sip:bob@example.com", "b1"), t1);
        transmits(&mut agent);
        let seen = events(&mut agent);
        assert_eq!(
            announced(&seen).first().map(|(_, id)| *id),
            Some(first.0),
            "the older one goes first"
        );
        assert!(agent.announcement(second).is_some(), "the other one stands");
    }

    #[test]
    fn an_invite_that_beats_its_push_is_attached_rather_than_counted_twice() {
        // the third race. The application wakes, raises a screen and tells the
        // stack about it, and the stack already has the call
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        deliver(&mut agent, &invite_from("sip:bob@example.com", "b1"), t0);
        transmits(&mut agent);
        let seen = events(&mut agent);
        let call = *incoming(&seen).first().expect("somebody is calling");
        assert!(announced(&seen).is_empty(), "nothing announced it yet");

        let answer = agent
            .announce(id, uri("sip:bob@example.com"), t0 + Duration::from_secs(1))
            .expect("the push, late");
        assert_eq!(answer, Announced::Arrived(call));
        let after = events(&mut agent);
        assert!(
            incoming(&after).is_empty(),
            "no second call is invented for it"
        );
    }

    #[test]
    fn a_push_for_somebody_else_does_not_take_the_call_already_ringing() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        deliver(&mut agent, &invite_from("sip:bob@example.com", "b1"), t0);
        transmits(&mut agent);
        events(&mut agent);

        let answer = agent
            .announce(id, uri("sip:carol@example.com"), t0)
            .expect("Carol is announced");
        assert!(
            matches!(answer, Announced::Waiting(_)),
            "Bob's call is not Carol's"
        );
        transmits(&mut agent);
        agent.handle_timeout(t0 + WINDOW);
        assert!(
            events(&mut agent)
                .iter()
                .any(|event| matches!(*event, UaEvent::AnnouncedCallMissing { .. })),
            "it expires harmlessly"
        );
    }

    #[test]
    fn a_call_screen_the_user_dismissed_stops_being_expected() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let expected = waiting(
            agent
                .announce(id, uri("sip:bob@example.com"), t0)
                .expect("an announcement"),
        );
        assert!(agent.forget_announcement(expected));
        assert!(!agent.forget_announcement(expected), "only once");
        transmits(&mut agent);
        events(&mut agent);

        deliver(&mut agent, &invite_from("sip:bob@example.com", "b1"), t0);
        transmits(&mut agent);
        let seen = events(&mut agent);
        assert_eq!(incoming(&seen).len(), 1);
        assert!(announced(&seen).is_empty());
    }

    #[test]
    fn announcing_on_an_account_that_was_never_added_is_refused() {
        let t0 = Instant::now();
        let mut agent = awake(t0);
        assert_eq!(
            agent.announce(AccountId(7), uri("sip:bob@example.com"), t0),
            Err(UaError::NoSuchAccount)
        );
    }

    #[test]
    fn a_wake_up_with_no_transport_yet_registers_the_moment_one_arrives() {
        // what C1 says actually happens: the screen is up before the network
        // session exists, so the pre-warm has nowhere to go and must not be
        // lost
        let t0 = Instant::now();
        let mut agent = asleep(23);
        let id = agent.add_account(account());
        agent
            .announce(id, uri("sip:bob@example.com"), t0)
            .expect("an announcement");
        assert!(transmits(&mut agent).is_empty(), "there is no socket yet");
        assert_eq!(agent.registration_state(id), Some(RegistrationState::Idle));

        bind(&mut agent, t0 + Duration::from_millis(300));
        let register = sent(&mut agent);
        assert!(register.starts_with(b"REGISTER sip:example.com SIP/2.0\r\n"));
        assert_eq!(
            agent.registration_state(id),
            Some(RegistrationState::Registering)
        );
    }

    #[test]
    fn a_push_drops_the_back_off_an_earlier_outage_earned() {
        let t0 = Instant::now();
        let mut agent = awake(t0);
        let id = agent.add_account(account());
        agent.register(id, t0).expect("a REGISTER goes");
        let request = sent(&mut agent);
        deliver(
            &mut agent,
            &reply(&request, 503, "Service Unavailable", ""),
            t0,
        );
        assert_eq!(
            agent.registration_state(id),
            Some(RegistrationState::Retrying)
        );
        events(&mut agent);

        agent
            .announce(id, uri("sip:bob@example.com"), t0 + Duration::from_secs(5))
            .expect("an announcement");
        assert!(
            sent(&mut agent).starts_with(b"REGISTER "),
            "the wait is over: the proxy just reached us"
        );
    }

    #[test]
    fn the_push_parameters_go_on_the_register_and_never_on_a_call() {
        let t0 = Instant::now();
        let mut agent = awake(t0);
        let id = agent.add_account(
            account()
                .instance_id("urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6")
                .push(
                    Push::new("apns", "ZTY4ZDJlMzODE1NmUgKi0K=")
                        .param("com.example.phone.voip")
                        .wakes_itself(),
                ),
        );
        agent.register(id, t0).expect("a REGISTER goes");
        let register = sent(&mut agent);
        assert_eq!(
            text(&register, HeaderName::Contact),
            "<sip:alice@192.0.2.1;pn-provider=apns;pn-param=com.example.phone.voip;\
             pn-prid=ZTY4ZDJlMzODE1NmUgKi0K%3D>;\
             +sip.instance=\"<urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>\";+sip.pnsreg"
        );
        deliver(
            &mut agent,
            &reply(
                &register,
                200,
                "OK",
                "Contact: <sip:alice@192.0.2.1>;expires=3600\r\n",
            ),
            t0,
        );
        events(&mut agent);

        deliver(&mut agent, &invite_from("sip:bob@example.com", "b1"), t0);
        transmits(&mut agent);
        let call = *incoming(&events(&mut agent))
            .first()
            .expect("somebody is calling");
        agent.ring(call, None, t0).expect("180 goes");
        let ringing = sent(&mut agent);
        assert_eq!(
            text(&ringing, HeaderName::Contact),
            "<sip:alice@192.0.2.1>;+sip.instance=\"<urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>\"",
            "§4.1 forbids the push identifier anywhere the far end can read it"
        );
    }

    #[test]
    fn giving_up_a_binding_leaves_the_push_identifier_out_of_it() {
        let t0 = Instant::now();
        let mut agent = awake(t0);
        let id = agent
            .add_account(account().push(Push::new("fcm", "cV6vv-wxyz").param("com.example.phone")));
        agent.register(id, t0).expect("a REGISTER goes");
        let register = sent(&mut agent);
        deliver(
            &mut agent,
            &reply(
                &register,
                200,
                "OK",
                "Contact: <sip:alice@192.0.2.1>;expires=3600\r\n",
            ),
            t0,
        );
        events(&mut agent);

        agent.unregister(id, t0).expect("a de-registration goes");
        let removing = sent(&mut agent);
        let contact = text(&removing, HeaderName::Contact);
        assert!(
            contact.contains("pn-provider=fcm") && contact.contains("pn-param=com.example.phone"),
            "the network still has to know which subscription this was: {contact}"
        );
        assert!(
            !contact.contains("pn-prid"),
            "§4.1.2 says its absence is how the notifications are turned off: {contact}"
        );
        assert_eq!(text(&removing, HeaderName::Expires), "0");
    }

    #[test]
    fn a_registrar_that_says_nothing_about_push_is_not_taken_to_have_agreed() {
        let t0 = Instant::now();
        let mut agent = awake(t0);
        let id = agent.add_account(account().push(Push::new("apns", "prid-1")));
        agent.register(id, t0).expect("a REGISTER goes");
        let register = sent(&mut agent);
        deliver(
            &mut agent,
            &reply(
                &register,
                200,
                "OK",
                "Contact: <sip:alice@192.0.2.1>;expires=3600\r\n",
            ),
            t0,
        );
        let echo = agent.push_echo(id).expect("an account that asked");
        assert!(!echo.accepted(), "§4.1.1: a UA MUST NOT assume");
        assert_eq!(echo.refresh_lead(), None);
    }

    #[test]
    fn a_registrar_that_echoes_the_service_and_a_lead_is_believed_about_both() {
        let t0 = Instant::now();
        let mut agent = awake(t0);
        let id = agent.add_account(account().push(Push::new("apns", "prid-1")));
        agent.register(id, t0).expect("a REGISTER goes");
        let register = sent(&mut agent);
        deliver(
            &mut agent,
            &reply(
                &register,
                200,
                "OK",
                "Contact: <sip:alice@192.0.2.1>;expires=400\r\n\
                 Feature-Caps: *;+sip.pns=\"apns\";+sip.pnsreg=\"121\"\r\n",
            ),
            t0,
        );
        let echo = agent.push_echo(id).expect("an account that asked");
        assert!(echo.accepted());
        assert_eq!(echo.refresh_lead(), Some(Duration::from_secs(121)));
        // 0.85 of four hundred seconds is three hundred and forty, which is
        // inside the lead the network demanded; the refresh moves back to meet
        // it
        agent.handle_timeout(t0 + Duration::from_secs(278));
        assert!(transmits(&mut agent).is_empty());
        agent.handle_timeout(t0 + Duration::from_secs(279));
        assert!(sent(&mut agent).starts_with(b"REGISTER "));
    }

    #[test]
    fn a_registrar_that_names_another_service_has_not_agreed_to_ours() {
        let t0 = Instant::now();
        let mut agent = awake(t0);
        let id = agent.add_account(account().push(Push::new("apns", "prid-1")));
        agent.register(id, t0).expect("a REGISTER goes");
        let register = sent(&mut agent);
        deliver(
            &mut agent,
            &reply(
                &register,
                200,
                "OK",
                "Contact: <sip:alice@192.0.2.1>;expires=3600\r\n\
                 Feature-Caps: *;+sip.pns=\"webpush\"\r\n",
            ),
            t0,
        );
        assert!(
            !agent
                .push_echo(id)
                .expect("an account that asked")
                .accepted()
        );
    }

    #[test]
    fn a_registration_freezes_and_thaws_into_a_state_that_claims_nothing() {
        let t0 = Instant::now();
        let (agent, id) = registered(t0);
        let call_id = String::from_utf8_lossy(
            agent
                .registrations
                .get(&id)
                .expect("a registration")
                .call_id
                .as_bytes(),
        )
        .into_owned();
        let snapshot = agent
            .freeze_registration(id, t0 + Duration::from_secs(600))
            .expect("a binding worth writing down");

        let t1 = t0 + Duration::from_secs(4_000);
        let mut woken = awake(t1);
        let restored = woken.add_account(account());
        woken
            .thaw_registration(restored, &snapshot, Duration::from_secs(1_200), t1)
            .expect("a snapshot this build wrote");
        assert_eq!(
            woken.registration_state(restored),
            Some(RegistrationState::Restored),
            "a binding on paper is not a binding"
        );
        assert_eq!(
            woken.binding_expires_in(restored, t1),
            Some(Duration::from_secs(1_800)),
            "three thousand seconds were left and twelve hundred of them were slept through"
        );

        woken.register(restored, t1).expect("a REGISTER goes");
        let register = sent(&mut woken);
        assert_eq!(
            text(&register, HeaderName::CallId),
            call_id,
            "the registrar reads it as the same client it already has a binding for"
        );
        assert_eq!(
            text(&register, HeaderName::CSeq),
            "2 REGISTER",
            "and as a later request from it, not a replay"
        );
        assert_eq!(
            woken.registration_state(restored),
            Some(RegistrationState::Registering),
            "the wire saves the work; the state claims nothing until it is answered"
        );
    }

    #[test]
    fn a_thawed_binding_that_slept_through_its_own_expiry_registers_at_once() {
        let t0 = Instant::now();
        let (agent, id) = registered(t0);
        let snapshot = agent.freeze_registration(id, t0).expect("a binding");

        let t1 = t0 + Duration::from_secs(90_000);
        let mut woken = awake(t1);
        let restored = woken.add_account(account());
        woken
            .thaw_registration(restored, &snapshot, Duration::from_secs(86_400), t1)
            .expect("a snapshot this build wrote");
        assert_eq!(woken.binding_expires_in(restored, t1), Some(Duration::ZERO));
        assert_eq!(woken.poll_timeout(), Some(t1));
        woken.handle_timeout(t1);
        assert!(sent(&mut woken).starts_with(b"REGISTER "));
    }

    #[test]
    fn a_snapshot_of_another_address_of_record_is_not_restored_onto_this_one() {
        let t0 = Instant::now();
        let (agent, id) = registered(t0);
        let snapshot = agent.freeze_registration(id, t0).expect("a binding");

        let mut other = awake(t0);
        let elsewhere = other.add_account(Account::new(
            uri("sip:carol@example.com"),
            uri("sip:example.com"),
            uri("sip:carol@192.0.2.1"),
            UDP,
            registrar(),
        ));
        assert_eq!(
            other.thaw_registration(elsewhere, &snapshot, Duration::ZERO, t0),
            Err(crate::SnapshotError::AnotherAccount)
        );
        assert_eq!(
            other.registration_state(elsewhere),
            Some(RegistrationState::Idle),
            "and the account it was offered to is untouched"
        );
    }

    #[test]
    fn a_snapshot_is_not_restored_onto_an_account_that_never_registers() {
        let t0 = Instant::now();
        let (agent, id) = registered(t0);
        let snapshot = agent.freeze_registration(id, t0).expect("a binding");

        let mut other = awake(t0);
        let line = other.add_account(trunk());
        assert_eq!(
            other.thaw_registration(line, &snapshot, Duration::ZERO, t0),
            Err(crate::SnapshotError::NotRegistering)
        );
        assert_eq!(
            other.registration_state(line),
            Some(RegistrationState::NotRegistering)
        );
        assert_eq!(
            other.poll_timeout(),
            None,
            "a refresh was booked that can never be sent"
        );
        other.handle_timeout(t0 + Duration::from_secs(3_600));
        assert!(transmits(&mut other).is_empty());
        assert!(
            events(&mut other).is_empty(),
            "a refusal was retried on the back-off"
        );
        assert!(
            other.freeze_registration(line, t0).is_none(),
            "and there is nothing to write down either"
        );
    }

    #[test]
    fn a_push_for_an_account_that_never_registers_refreshes_nothing_and_owes_nothing() {
        let t0 = Instant::now();
        let mut agent = asleep(11);
        let id = agent.add_account(trunk());
        let answer = agent
            .announce(id, uri("sip:bob@example.com"), t0)
            .expect("an account that exists");
        waiting(answer);
        assert_eq!(agent.refresh_binding(id, t0), Err(UaError::NoRegistrar));
        assert!(
            agent.registrations.get(&id).is_some_and(|reg| !reg.owed),
            "a refresh was remembered for an account with no binding"
        );

        bind(&mut agent, t0);
        assert!(
            transmits(&mut agent).is_empty(),
            "the transport arriving sent something for an account with no registrar"
        );
        assert_eq!(
            agent.registration_state(id),
            Some(RegistrationState::NotRegistering)
        );
    }

    #[test]
    fn there_is_nothing_to_freeze_before_there_is_a_binding() {
        let t0 = Instant::now();
        let mut agent = awake(t0);
        let id = agent.add_account(account());
        assert!(agent.freeze_registration(id, t0).is_none());
        agent.register(id, t0).expect("a REGISTER goes");
        assert!(
            agent.freeze_registration(id, t0).is_none(),
            "one in flight is not one that was granted"
        );
    }

    #[test]
    fn a_binding_that_was_given_up_stops_being_one_that_expires() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        assert_eq!(
            agent.binding_expires_in(id, t0),
            Some(Duration::from_secs(3_600))
        );

        agent.unregister(id, t0).expect("a de-registration goes");
        let removing = sent(&mut agent);
        deliver(&mut agent, &reply(&removing, 200, "OK", ""), t0);
        assert_eq!(
            agent.registration_state(id),
            Some(RegistrationState::Unregistered)
        );
        assert_eq!(
            agent.binding_expires_in(id, t0),
            None,
            "the last grant is not news about a binding that is gone"
        );
        assert!(agent.freeze_registration(id, t0).is_none());
    }

    #[test]
    fn time_to_ready_is_measured_from_the_cold_start_the_application_declared() {
        let t0 = Instant::now();
        let mut agent = asleep(31);
        agent.cold_start(t0);
        let id = agent.add_account(account());
        assert_eq!(agent.time_to_ready(id), None);

        bind(&mut agent, t0 + Duration::from_millis(120));
        agent
            .register(id, t0 + Duration::from_millis(140))
            .expect("a REGISTER goes");
        let register = sent(&mut agent);
        let ready_at = t0 + Duration::from_millis(880);
        deliver(
            &mut agent,
            &reply(
                &register,
                200,
                "OK",
                "Contact: <sip:alice@192.0.2.1>;expires=3600\r\n",
            ),
            ready_at,
        );
        assert_eq!(agent.time_to_ready(id), Some(Duration::from_millis(880)));

        agent.handle_timeout(ready_at + Duration::from_secs(3_060));
        let refresh = sent(&mut agent);
        deliver(
            &mut agent,
            &reply(
                &refresh,
                200,
                "OK",
                "Contact: <sip:alice@192.0.2.1>;expires=3600\r\n",
            ),
            ready_at + Duration::from_secs(3_061),
        );
        assert_eq!(
            agent.time_to_ready(id),
            Some(Duration::from_millis(880)),
            "an hourly refresh is not a cold start"
        );
    }

    #[test]
    fn without_a_declared_cold_start_there_is_no_number_to_report() {
        let t0 = Instant::now();
        let (agent, id) = registered(t0);
        assert_eq!(
            agent.time_to_ready(id),
            None,
            "the launch happened before any of this existed"
        );
    }

    #[test]
    fn a_caller_is_the_same_caller_whatever_the_proxy_did_to_the_uri() {
        assert!(same_caller(
            &uri("sip:bob@example.com"),
            &uri("sip:bob@example.com;user=phone;transport=tcp")
        ));
        // the host without regard to case, §19.1.4. On a URI with no user
        // part, so that nothing in this file reads as an address to harvest
        assert!(same_caller(
            &uri("sip:example.com"),
            &uri("sip:EXAMPLE.COM")
        ));
        assert!(same_caller(
            &uri("sip:+40721000000@carrier.example.net"),
            &uri("sip:%2B40721000000@carrier.example.net")
        ));
        assert!(!same_caller(
            &uri("sip:bob@example.com"),
            &uri("sip:Bob@example.com")
        ));
        assert!(!same_caller(
            &uri("sip:bob@example.com"),
            &uri("sip:bob@example.net")
        ));
        assert!(!same_caller(
            &uri("sip:bob@example.com"),
            &uri("sip:example.com")
        ));
        assert!(same_caller(
            &uri("tel:+40721000000"),
            &uri("tel:+40721000000")
        ));
        assert!(!same_caller(
            &uri("tel:+40721000000"),
            &uri("sip:+40721000000@example.com")
        ));
    }
}
