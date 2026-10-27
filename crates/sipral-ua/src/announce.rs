// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A call that was announced before it arrived.
//!
//! On a phone, a push wakes the process and the platform demands the call
//! screen at once, so the user sees a ringing call before there is a
//! transport, a fresh registration or an INVITE. This module refreshes the
//! binding at once, recognises the INVITE as the announced call, and reports
//! when nothing came.
//!
//! **Matching.** RFC 8599 asks a push for no payload (§13), so a push need
//! not carry a `Call-ID`, and the rule that always applies is the account
//! plus the user and host of the `From` URI. Nothing else: proxies rewrite
//! parameters and display names, and a missed match means a second call
//! screen for a call the user already sees.
//!
//! A proxy that holds the INVITE while it pushes (§5.6.2) has the INVITE in
//! hand and can put its `Call-ID` in the push. When the application passes it
//! on ([`UserAgent::announce_call`]), the INVITE with that `Call-ID` on the
//! same account takes the announcement first, whoever it says is calling;
//! only when no INVITE carries it does the caller rule decide. So a `Call-ID`
//! tells two calls from one caller apart, and never leaves unmatched a call
//! the caller rule would have matched: an intermediary that changed the
//! `Call-ID` after the push was sent costs the exact match, not a second
//! screen.
//!
//! Time is only a tie-break. Different callers are matched by caller, not
//! arrival order. For the same caller on the same account the oldest goes
//! first; without a `Call-ID` nothing tells them apart, and both sides keep
//! the proxy's order.
//!
//! **The account alone.** A push may name nobody: §13 asks for no payload,
//! and one sealed for the application may not open on the device. Such a
//! push still demands a call screen, so [`UserAgent::announce_any`] expects
//! the call on the account alone: the INVITE with the push's `Call-ID` when
//! it carried one, else the oldest INVITE on the account that no
//! announcement naming its caller takes. An announcement that names a
//! caller always goes before one that does not, so the account rule only
//! takes what the caller rule leaves. Two such calls ringing together on
//! one account may be swapped; nothing in the push tells them apart.
//!
//! An announcement is used once. Two calls need two pushes.

use std::time::{Duration, Instant};

use sipral_core::endpoint::{Input, TransportId};
use sipral_core::msg::{HostRef, OwnedMessage, Uri, UriRef, unescape};

use crate::account::AccountId;
use crate::agent::UserAgent;
use crate::call::CallHandle;
use crate::error::UaError;
use crate::event::{RegistrationState, UaEvent};

/// How long an announced call is waited for before it is called missing.
/// Under the caller's 64·T1 (32 s) INVITE timeout, with room for a cold
/// start: DNS, connection, challenge, REGISTER retransmits.
pub(crate) const WINDOW: Duration = Duration::from_secs(20);

/// One announcement. Never reused, so a stale handle names nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnnouncementId(pub(crate) u32);

/// A call the application was told to expect.
#[derive(Clone, Debug)]
pub struct Announcement {
    pub(crate) id: AnnouncementId,
    pub(crate) account: AccountId,
    pub(crate) caller: Uri,
    /// Whether the push named `caller`, or it stands for nobody.
    pub(crate) named: bool,
    pub(crate) call_id: Option<String>,
    pub(crate) at: Instant,
}

impl Announcement {
    /// Its id.
    #[must_use]
    pub const fn id(&self) -> AnnouncementId {
        self.id
    }

    /// The account the call was announced on.
    #[must_use]
    pub const fn account(&self) -> AccountId {
        self.account
    }

    /// Who the push said is calling. RFC 3323's
    /// `sip:anonymous@anonymous.invalid` ([`Uri::anonymous`]) when it named
    /// nobody ([`UserAgent::announce_any`]).
    #[must_use]
    pub const fn caller(&self) -> &Uri {
        &self.caller
    }

    /// Whether the push named the caller. `false` for an announcement on the
    /// account alone, which any caller's INVITE can fulfil.
    #[must_use]
    pub const fn names_caller(&self) -> bool {
        self.named
    }

    /// The `Call-ID` the push named, when it named one.
    #[must_use]
    pub fn call_id(&self) -> Option<&str> {
        self.call_id.as_deref()
    }

    /// When the application handled the wake-up, not when the push was sent.
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
    /// The INVITE beat the push; the raised screen belongs to this call.
    /// Nothing was recorded and no further event comes.
    Arrived(CallHandle),
}

/// What matching needs of an incoming call, so a late push can still find
/// the INVITE that beat it.
#[derive(Clone, Debug)]
pub(crate) struct Arrival {
    at: Instant,
    account: Option<AccountId>,
    caller: Option<Uri>,
    call_id: Option<String>,
    matched: bool,
}

impl UserAgent {
    /// A call is expected on `account`, from `caller`, announced now.
    ///
    /// The binding is refreshed at once (RFC 8599 §4.1.3), which also tells
    /// the proxy holding the INVITE (§5.6.2) that this device is back; an
    /// account without a registrar skips this. The announcement is kept so
    /// the INVITE that follows is reported as this call, not a second one.
    ///
    /// The caller is required: without one any next call would match and
    /// show the wrong name.
    ///
    /// If the INVITE already arrived (§4.1.3 allows it), the answer is
    /// [`Announced::Arrived`] and nothing is recorded.
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`].
    pub fn announce(
        &mut self,
        account: AccountId,
        caller: Uri,
        now: Instant,
    ) -> Result<Announced, UaError> {
        self.announce_call(account, caller, None, now)
    }

    /// [`UserAgent::announce`], with the `Call-ID` the push carried when it
    /// carried one.
    ///
    /// The INVITE with that `Call-ID` on `account` is this call, whoever it
    /// says is calling; with none carrying it, the caller decides, as in
    /// [`UserAgent::announce`]. The `Call-ID` is compared as written, case
    /// and all (RFC 3261 §20.8). `None`, or an empty one, is
    /// [`UserAgent::announce`] exactly.
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`].
    pub fn announce_call(
        &mut self,
        account: AccountId,
        caller: Uri,
        call_id: Option<&str>,
        now: Instant,
    ) -> Result<Announced, UaError> {
        self.announce_by(account, Some(caller), call_id, now)
    }

    /// A call is expected on `account` from a caller the push did not name:
    /// a push with no payload (RFC 8599 §13), or one whose sealed payload
    /// would not open.
    ///
    /// The INVITE with `call_id` on `account` is this call, when one carries
    /// it; else the oldest INVITE on `account` that no announcement naming
    /// its caller takes (module documentation, "The account alone"). The
    /// binding is refreshed and a late push finds the INVITE that beat it,
    /// as for [`UserAgent::announce`]. [`Announcement::names_caller`] is
    /// `false` on what this records.
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`].
    pub fn announce_any(
        &mut self,
        account: AccountId,
        call_id: Option<&str>,
        now: Instant,
    ) -> Result<Announced, UaError> {
        self.announce_by(account, None, call_id, now)
    }

    /// What every announcing entry point does; `caller` is `None` when the
    /// push named nobody.
    fn announce_by(
        &mut self,
        account: AccountId,
        caller: Option<Uri>,
        call_id: Option<&str>,
        now: Instant,
    ) -> Result<Announced, UaError> {
        if !self.accounts.contains_key(&account) {
            return Err(UaError::NoSuchAccount);
        }
        let call_id = call_id.filter(|id| !id.is_empty()).map(str::to_owned);
        let already = self.ringing_already(account, caller.as_ref(), call_id.as_deref(), now);
        let announcement = self.mint(account, caller, call_id, now);
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
        // no transport yet is normal on wake-up: the REGISTER is owed and
        // goes when one is bound
        self.refresh_binding(account, now).ok();
        Ok(answer)
    }

    /// Send a binding-refresh REGISTER now, without waiting for the scheduled
    /// one (RFC 8599 §4.1.3).
    ///
    /// For a keep-alive push (§5.5). A push proves the path works, so any
    /// back-off is dropped. Nothing is sent while a REGISTER is in flight or
    /// after a permanent failure: retrying a refused password risks a
    /// lockout.
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`]; [`UaError::NoRegistrar`] for an account
    /// that never registers; or [`UaError::Send`] with no transport yet, in
    /// which case the refresh is sent when one is bound.
    pub fn refresh_binding(&mut self, account: AccountId, now: Instant) -> Result<(), UaError> {
        let config = self.accounts.get(&account).ok_or(UaError::NoSuchAccount)?;
        // before marking it owed, or it would be retried on every bind
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

    /// An announcement still waiting for its INVITE.
    #[must_use]
    pub fn announcement(&self, id: AnnouncementId) -> Option<&Announcement> {
        self.announcements
            .iter()
            .find(|announcement| announcement.id == id)
    }

    /// Stop expecting a call. `false` if already fulfilled or expired.
    pub fn forget_announcement(&mut self, id: AnnouncementId) -> bool {
        let before = self.announcements.len();
        self.announcements
            .retain(|announcement| announcement.id != id);
        self.announcements.len() != before
    }

    /// How long an announced call is waited for; 20 s by default. Too long
    /// keeps a screen up for a call that never comes; too short reports a
    /// call missing that is still on its way.
    pub const fn expect_within(&mut self, window: Duration) {
        self.announce_window = window;
    }

    fn mint(
        &mut self,
        account: AccountId,
        caller: Option<Uri>,
        call_id: Option<String>,
        at: Instant,
    ) -> Announcement {
        let id = AnnouncementId(self.next_announcement);
        self.next_announcement = self.next_announcement.wrapping_add(1);
        let named = caller.is_some();
        Announcement {
            id,
            account,
            caller: caller.unwrap_or_else(Uri::anonymous),
            named,
            call_id,
            at,
        }
    }

    /// An unclaimed call ringing within the window: the one with this
    /// `Call-ID` when one is given and rings, otherwise the oldest from this
    /// caller, or from anybody when `caller` is `None`.
    fn ringing_already(
        &self,
        account: AccountId,
        caller: Option<&Uri>,
        call_id: Option<&str>,
        now: Instant,
    ) -> Option<CallHandle> {
        let window = self.announce_window;
        if let Some(call_id) = call_id {
            let named = self.arrivals.iter().find(|(_, arrival)| {
                !arrival.matched
                    && arrival.account == Some(account)
                    && arrival.at + window >= now
                    && arrival.call_id.as_deref() == Some(call_id)
            });
            if let Some((call, _)) = named {
                return Some(*call);
            }
        }
        let mut best: Option<(Instant, CallHandle)> = None;
        for (call, arrival) in &self.arrivals {
            let from_caller = caller.is_none_or(|caller| {
                arrival
                    .caller
                    .as_ref()
                    .is_some_and(|from| same_caller(caller, from))
            });
            if arrival.matched
                || arrival.account != Some(account)
                || arrival.at + window < now
                || !from_caller
            {
                continue;
            }
            if best.is_none_or(|(at, _)| arrival.at < at) {
                best = Some((arrival.at, *call));
            }
        }
        best.map(|(_, call)| call)
    }

    /// Queue [`UaEvent::CallAnnounced`] just before the call's unread
    /// [`UaEvent::IncomingCall`]. If that was already read,
    /// [`UserAgent::announce`]'s answer said it, so nothing is queued.
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

    /// Match newly reported incoming calls to announcements. Done once per
    /// drain so the result does not depend on INVITE parse order.
    pub(crate) fn settle_announcements(&mut self, now: Instant) {
        // keep arrivals only while a push could still be late
        let window = self.announce_window;
        self.arrivals
            .retain(|call, arrival| arrival.at + window >= now && self.calls.contains_key(call));

        let fresh: Vec<Fresh> = self
            .events
            .iter()
            .enumerate()
            .filter_map(|(at, event)| match *event {
                UaEvent::IncomingCall {
                    call,
                    account,
                    ref request,
                    ..
                } if !self.arrivals.contains_key(&call) => Some(Fresh {
                    at,
                    call,
                    account,
                    caller: caller_of(request),
                    call_id: call_id_of(request),
                }),
                _ => None,
            })
            .collect();

        // back to front so insertions do not shift pending indices
        for Fresh {
            at,
            call,
            account,
            caller,
            call_id,
        } in fresh.into_iter().rev()
        {
            let matched = account
                .and_then(|account| self.claim(account, caller.as_ref(), call_id.as_deref(), now));
            self.arrivals.insert(
                call,
                Arrival {
                    at: now,
                    account,
                    caller,
                    call_id,
                    matched: matched.is_some(),
                },
            );
            if let Some(announcement) = matched {
                self.events
                    .insert(at, UaEvent::CallAnnounced { call, announcement });
            }
        }
    }

    /// The announcement an INVITE on `account` fulfils: the one naming its
    /// `Call-ID`, or else the oldest naming its caller, or else the oldest
    /// that named nobody.
    fn claim(
        &mut self,
        account: AccountId,
        caller: Option<&Uri>,
        call_id: Option<&str>,
        now: Instant,
    ) -> Option<Announcement> {
        let window = self.announce_window;
        let open = |announcement: &Announcement| {
            announcement.account == account && announcement.at + window >= now
        };
        if let Some(call_id) = call_id {
            let named = self.announcements.iter().position(|announcement| {
                open(announcement) && announcement.call_id.as_deref() == Some(call_id)
            });
            if let Some(at) = named {
                return Some(self.announcements.remove(at));
            }
        }
        let by_caller = caller.and_then(|caller| {
            self.oldest_announcement(|announcement| {
                open(announcement)
                    && announcement.named
                    && same_caller(&announcement.caller, caller)
            })
        });
        by_caller
            .or_else(|| {
                self.oldest_announcement(|announcement| open(announcement) && !announcement.named)
            })
            .map(|at| self.announcements.remove(at))
    }

    /// Where the oldest announcement that `fits` sits; the first of equals.
    fn oldest_announcement(&self, fits: impl Fn(&Announcement) -> bool) -> Option<usize> {
        self.announcements
            .iter()
            .enumerate()
            .filter(|(_, announcement)| fits(announcement))
            .min_by_key(|(_, announcement)| announcement.at)
            .map(|(at, _)| at)
    }

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

    pub(crate) fn announce_deadline(&self) -> Option<Instant> {
        self.announcements
            .iter()
            .map(|announcement| announcement.at + self.announce_window)
            .min()
    }

    /// A transport was bound: send what waited for one. The stack cannot
    /// open sockets, so the fastest it can be is to send the owed REGISTER
    /// in the same call.
    pub(crate) fn on_transport_bound(&mut self, transport: TransportId, now: Instant) {
        // an account waiting for its own connection may take this one
        self.adopt_flows(now);
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
        // RFC 3261 §18.1.1 retries, before the drain so they are not settled
        // as refusals this round. Not filtered on `transport`: when a retry
        // parks no stream exists yet; one that still cannot go parks again.
        self.resume_what_waited_for_a_stream(now);
    }

    /// Resend what §18.1.1 held for a stream: challenge answers first, then
    /// this layer's own in-dialog sends last, since a hangup drains.
    pub(crate) fn resume_what_waited_for_a_stream(&mut self, now: Instant) {
        self.resume_parked_registrations(now);
        self.resume_parked_calls(now);
        self.resume_parked_requests(now);
        self.resume_parked_offers(now);
        self.resume_parked_subscriptions(now);
        self.resume_parked_messages(now);
        self.resume_parked_publications(now);
        self.resume_parked_sends(now);
    }
}

/// One incoming call not yet looked at for an announcement.
struct Fresh {
    at: usize,
    call: CallHandle,
    account: Option<AccountId>,
    caller: Option<Uri>,
    call_id: Option<String>,
}

fn call_id_of(request: &OwnedMessage) -> Option<String> {
    let id = request.as_raw().call_id().ok()?;
    String::from_utf8(id.to_vec()).ok()
}

fn caller_of(request: &OwnedMessage) -> Option<Uri> {
    let raw = request.as_raw();
    let from = raw.from().ok()?;
    Uri::parse(from.uri_bytes()).ok()
}

/// Whether a push and an INVITE name the same caller.
///
/// User and host only, not §19.1.4 equivalence: proxies change parameters.
/// User unescaped and case-sensitive, host case-insensitive (§19.1.4).
/// `sip:` and `sips:` match each other: encryption on the last leg says
/// nothing about who is calling. Other schemes use whole-URI equivalence.
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

    /// The same AOR with no registrar.
    fn trunk() -> Account {
        Account::unregistered(
            uri("sip:alice@example.com"),
            uri("sip:alice@192.0.2.1"),
            UDP,
            "198.51.100.20:5060".parse().expect("the proxy's address"),
        )
    }

    /// Nothing bound yet, as on a phone woken by a push.
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

    /// An INVITE from `from`.
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

    /// Registered, with its output drained.
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
        // the caller hung up during wake-up: a later INVITE is another call
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
        // before the sweep ran: the window is checked at match time too
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
        // Carol's INVITE takes Carol's announcement although Bob's is older
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
    fn a_call_id_tells_two_calls_from_one_caller_apart() {
        // the caller rule would hand the older announcement to whichever
        // INVITE came first; the Call-ID hands each its own
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let older = waiting(
            agent
                .announce_call(id, uri("sip:bob@example.com"), Some("incoming-b1"), t0)
                .expect("the first call is announced"),
        );
        let newer = waiting(
            agent
                .announce_call(
                    id,
                    uri("sip:bob@example.com"),
                    Some("incoming-b2"),
                    t0 + Duration::from_millis(300),
                )
                .expect("the second call is announced"),
        );
        assert_eq!(
            agent.announcement(newer).and_then(|held| held.call_id()),
            Some("incoming-b2")
        );
        transmits(&mut agent);
        events(&mut agent);

        let t1 = t0 + Duration::from_secs(1);
        deliver(&mut agent, &invite_from("sip:bob@example.com", "b2"), t1);
        transmits(&mut agent);
        let seen = events(&mut agent);
        let second = *incoming(&seen).first().expect("the second call rings");
        assert_eq!(announced(&seen), vec![(second, newer.0)]);

        deliver(&mut agent, &invite_from("sip:bob@example.com", "b1"), t1);
        transmits(&mut agent);
        let seen = events(&mut agent);
        let first = *incoming(&seen).first().expect("the first call rings");
        assert_eq!(announced(&seen), vec![(first, older.0)]);
    }

    #[test]
    fn a_call_id_matches_whoever_the_invite_says_is_calling() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let announcement = waiting(
            agent
                .announce_call(
                    id,
                    uri("sip:switchboard@example.com"),
                    Some("incoming-x1"),
                    t0,
                )
                .expect("an announcement"),
        );
        transmits(&mut agent);
        events(&mut agent);
        deliver(&mut agent, &invite_from("sip:dave@example.com", "x1"), t0);
        transmits(&mut agent);
        let seen = events(&mut agent);
        let call = *incoming(&seen).first().expect("Dave is calling");
        assert_eq!(announced(&seen), vec![(call, announcement.0)]);
    }

    #[test]
    fn a_call_id_no_invite_carries_falls_back_to_the_caller() {
        // something between the push and this device changed the Call-ID:
        // the exact match is lost, the call screen is not
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let announcement = waiting(
            agent
                .announce_call(id, uri("sip:bob@example.com"), Some("rewritten-away"), t0)
                .expect("an announcement"),
        );
        transmits(&mut agent);
        events(&mut agent);
        deliver(&mut agent, &invite_from("sip:bob@example.com", "y1"), t0);
        transmits(&mut agent);
        let seen = events(&mut agent);
        let call = *incoming(&seen).first().expect("Bob is calling");
        assert_eq!(announced(&seen), vec![(call, announcement.0)]);
    }

    #[test]
    fn a_call_id_finds_the_invite_that_beat_its_push() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let mut calls = Vec::new();
        for (branch, after) in [("z1", 0), ("z2", 5)] {
            deliver(
                &mut agent,
                &invite_from("sip:bob@example.com", branch),
                t0 + Duration::from_millis(after),
            );
            transmits(&mut agent);
            calls.extend(incoming(&events(&mut agent)));
        }
        assert_eq!(calls.len(), 2);
        let t1 = t0 + Duration::from_millis(10);
        // the caller rule would pick the older; the Call-ID names the second
        let answer = agent
            .announce_call(id, uri("sip:bob@example.com"), Some("incoming-z2"), t1)
            .expect("an announcement");
        assert_eq!(answer, Announced::Arrived(calls[1]));
        let answer = agent
            .announce_call(id, uri("sip:bob@example.com"), Some(""), t1)
            .expect("an announcement without a usable Call-ID");
        assert_eq!(
            answer,
            Announced::Arrived(calls[0]),
            "an empty Call-ID is none at all"
        );
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
    fn a_push_that_names_nobody_is_answered_by_the_next_call_on_its_account() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        // past the first REGISTER's transaction, which a refresh waits for
        let t0 = t0 + Duration::from_secs(60);
        agent.handle_timeout(t0);
        transmits(&mut agent);
        let announcement = waiting(agent.announce_any(id, None, t0).expect("an announcement"));
        let held = agent.announcement(announcement).expect("it waits");
        assert!(!held.names_caller());
        assert_eq!(
            held.caller().as_str(),
            "sip:anonymous@anonymous.invalid",
            "RFC 3323's nobody, not somebody's name"
        );
        assert!(
            sent(&mut agent).starts_with(b"REGISTER "),
            "§4.1.3 applies to a push that says nothing just the same"
        );
        events(&mut agent);

        let t1 = t0 + Duration::from_secs(2);
        deliver(&mut agent, &invite_from("sip:dave@example.com", "d1"), t1);
        transmits(&mut agent);
        let seen = events(&mut agent);
        let call = *incoming(&seen).first().expect("Dave is calling");
        assert_eq!(announced(&seen), vec![(call, announcement.0)]);
        assert!(agent.announcement(announcement).is_none(), "used once");

        deliver(&mut agent, &invite_from("sip:dave@example.com", "d2"), t1);
        transmits(&mut agent);
        let seen = events(&mut agent);
        assert_eq!(incoming(&seen).len(), 1, "the second call still arrives");
        assert!(announced(&seen).is_empty(), "with no push left to claim it");
    }

    #[test]
    fn a_push_that_names_nobody_takes_only_what_a_push_naming_the_caller_leaves() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        // the push that names nobody is the older, and still loses Bob's call
        let anybody = waiting(agent.announce_any(id, None, t0).expect("anybody"));
        let bob = waiting(
            agent
                .announce(
                    id,
                    uri("sip:bob@example.com"),
                    t0 + Duration::from_millis(300),
                )
                .expect("Bob is announced"),
        );
        transmits(&mut agent);
        events(&mut agent);

        let t1 = t0 + Duration::from_secs(1);
        deliver(&mut agent, &invite_from("sip:bob@example.com", "b1"), t1);
        transmits(&mut agent);
        let seen = events(&mut agent);
        let first = *incoming(&seen).first().expect("Bob is calling");
        assert_eq!(announced(&seen), vec![(first, bob.0)]);

        deliver(&mut agent, &invite_from("sip:carol@example.com", "c1"), t1);
        transmits(&mut agent);
        let seen = events(&mut agent);
        let second = *incoming(&seen).first().expect("Carol is calling");
        assert_eq!(announced(&seen), vec![(second, anybody.0)]);
    }

    #[test]
    fn a_call_id_on_a_push_that_names_nobody_picks_its_call_out_of_two() {
        let t0 = Instant::now();
        let (mut agent, id) = registered(t0);
        let mut calls = Vec::new();
        for (branch, after) in [("e1", 0), ("e2", 5)] {
            deliver(
                &mut agent,
                &invite_from("sip:erin@example.com", branch),
                t0 + Duration::from_millis(after),
            );
            transmits(&mut agent);
            calls.extend(incoming(&events(&mut agent)));
        }
        assert_eq!(calls.len(), 2);
        let t1 = t0 + Duration::from_millis(10);
        assert_eq!(
            agent
                .announce_any(id, Some("incoming-e2"), t1)
                .expect("an announcement"),
            Announced::Arrived(calls[1]),
            "the Call-ID names the second"
        );
        assert_eq!(
            agent.announce_any(id, None, t1).expect("an announcement"),
            Announced::Arrived(calls[0]),
            "and with none, the oldest left goes"
        );
        assert!(
            matches!(
                agent.announce_any(id, None, t1).expect("an announcement"),
                Announced::Waiting(_)
            ),
            "no call is claimed twice"
        );
    }

    #[test]
    fn a_push_that_names_nobody_on_an_unknown_account_is_refused() {
        let t0 = Instant::now();
        let mut agent = awake(t0);
        assert_eq!(
            agent.announce_any(AccountId(7), None, t0),
            Err(UaError::NoSuchAccount)
        );
    }

    #[test]
    fn an_invite_that_beats_its_push_is_attached_rather_than_counted_twice() {
        // the INVITE is already here when the push is handled
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
        // no transport yet: the refresh must wait, not be lost
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
        // 0.85 * 400 s = 340 s is inside the requested lead, so it moves back
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
        // host case-insensitive (§19.1.4); no user part, nothing to harvest
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
