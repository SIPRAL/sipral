// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One call, two phones: a proxy forks it, and the second phone answers first.
//!
//! Two stacks register as one user at Kamailio, from two sockets, and a third
//! calls that user. `interop/kamailio/kamailio.cfg` relays the INVITE to both
//! bindings in parallel, which is what a desk phone and a mobile on one
//! extension look like to the caller: two early dialogs from one INVITE.
//!
//! The desk rings at once and never answers; the mobile rings a moment later
//! and then picks up. So the call the caller placed is the desk's early
//! dialog, the mobile arrives as its sibling under `UaEvent::CallForked`, and
//! the first 2xx is the sibling's. `sipral::ForkPolicy::KeepFirst` has to keep
//! it — the proxy has already forwarded it and is cancelling the desk — and
//! the call has to go on, on the mobile's dialog, with audio both ways. The
//! desk has to see the proxy's CANCEL, and the branch the caller placed has
//! to end as `ForkLost`, which is how the application learns which branch
//! won.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::{
    AccountId, CallEndReason, CallHandle, CallMedia, Event, MediaConfig, OutgoingCall, UaEvent,
};

use crate::join::give_back;
use crate::{Endpoint, catalog, place_call, uri};

/// How long the whole flow may take before it is a failure.
const PATIENCE: Duration = Duration::from_secs(30);

/// How long the call stays up once it is answered.
const DWELL: Duration = Duration::from_secs(3);

/// How long after the INVITE the mobile rings: long enough that the desk's
/// 180 reaches the caller first, so the call placed is the desk's dialog and
/// the mobile's is the sibling.
const MOBILE_RINGS_AFTER: Duration = Duration::from_millis(400);

/// And how long after the INVITE it picks up.
const MOBILE_ANSWERS_AFTER: Duration = Duration::from_millis(1_200);

/// Audible frames each end has to hear from the other: a fifth of a second.
const AUDIBLE_WANTED: u32 = 10;

/// The user both phones register as, and its password: the lab's own, in
/// `interop/kamailio/kamailio.cfg`.
const FORK_USER: &str = "forked";
const FORK_PASS: &str = "forkedpass";

/// How far a phone has gone with the call it was given.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Waiting,
    Rung,
    Answered,
}

/// One of the two phones the call is forked to.
struct Phone {
    name: &'static str,
    endpoint: Endpoint,
    account: AccountId,
    remote: SocketAddr,
    /// When it rings, and when it answers, counted from the INVITE; `None`
    /// for an answer is a phone nobody picks up.
    rings_after: Duration,
    answers_after: Option<Duration>,
    registered: bool,
    call: Option<(CallHandle, Instant)>,
    stage: Stage,
    confirmed: bool,
    ended: Option<CallEndReason>,
}

impl Phone {
    fn turn(&mut self, now: Instant) {
        for event in self.endpoint.pump(now) {
            self.on_event(&event, now);
        }
        if let Some((call, arrived)) = self.call
            && self.ended.is_none()
        {
            let since = now.saturating_duration_since(arrived);
            if self.stage == Stage::Waiting && since >= self.rings_after {
                self.stage = Stage::Rung;
                let _ = self.endpoint.agent.ring(call, None, now);
            }
            if self.stage == Stage::Rung && self.answers_after.is_some_and(|after| since >= after) {
                self.stage = Stage::Answered;
                if let Ok(local) = self.endpoint.open_media(call, self.remote, now) {
                    let _ = self
                        .endpoint
                        .engine
                        .answer(&mut self.endpoint.agent, call, local, now);
                }
            }
        }
        self.endpoint.run_media(now);
        self.endpoint.timers(now);
        self.endpoint.flush();
    }

    fn on_event(&mut self, event: &Event, now: Instant) {
        let Event::Signalling(said) = event else {
            return;
        };
        match *said {
            UaEvent::Registered { .. } => self.registered = true,
            UaEvent::IncomingCall { call, .. } if self.call.is_none() => {
                self.call = Some((call, now));
            }
            UaEvent::CallConfirmed { .. } => self.confirmed = true,
            UaEvent::CallEnded { call, reason, .. }
                if self.call.is_some_and(|(ours, _)| ours == call) =>
            {
                self.ended = Some(reason);
            }
            _ => {}
        }
    }

    fn audible(&self) -> u32 {
        self.call
            .and_then(|(call, _)| self.endpoint.media.get(&call))
            .map_or(0, |media| media.heard().audible)
    }
}

/// The phone that places the call.
struct Caller {
    endpoint: Endpoint,
    account: AccountId,
    target: sipral::Uri,
    remote: SocketAddr,
    placed: Option<CallHandle>,
    forked: Option<CallHandle>,
    kept: Option<CallHandle>,
    placed_ended: Option<CallEndReason>,
    kept_ended: Option<CallEndReason>,
    hang_up_at: Option<Instant>,
    /// Every call event, in order, for the diagnosis of a flow that failed.
    saw: Vec<String>,
}

impl Caller {
    fn turn(&mut self, phones_registered: bool, now: Instant) {
        if phones_registered && self.placed.is_none() {
            let media = CallMedia::new(catalog(), MediaConfig::default());
            let outgoing = OutgoingCall::new(self.target.clone())
                .to_address(self.endpoint.transport, self.remote);
            match place_call(
                &mut self.endpoint,
                self.account,
                outgoing,
                media,
                self.remote,
                now,
            ) {
                Ok(call) => self.placed = Some(call),
                Err(why) => self.saw.push(format!("not placed: {why}")),
            }
        }
        for event in self.endpoint.pump(now) {
            self.on_event(event, now);
        }
        if self.hang_up_at.is_some_and(|due| now >= due)
            && let Some(call) = self.kept
        {
            self.hang_up_at = None;
            let _ = self.endpoint.agent.hangup(call, now);
        }
        self.endpoint.run_media(now);
        self.endpoint.timers(now);
        self.endpoint.flush();
    }

    fn on_event(&mut self, event: Event, now: Instant) {
        let Event::Signalling(said) = event else {
            return;
        };
        match said {
            UaEvent::CallProgress { call, state, .. } => {
                self.saw.push(format!("{} {state:?}", self.name(call)));
            }
            UaEvent::CallForked { sibling, .. } => {
                self.forked = Some(sibling);
                self.saw.push("forked".to_owned());
            }
            UaEvent::CallConfirmed { call, .. } => {
                self.saw.push(format!("{} confirmed", self.name(call)));
                if self.kept.is_none() {
                    self.kept = Some(call);
                    self.hang_up_at = Some(now + DWELL);
                    // the socket was opened for the call placed, and the
                    // branch kept runs its session on the same address: it
                    // follows the branch, the way an application's audio
                    // path would
                    if let Some(placed) = self.placed
                        && placed != call
                        && let Some(media) = self.endpoint.media.remove(&placed)
                    {
                        self.endpoint.media.insert(call, media);
                    }
                }
            }
            UaEvent::CallEnded { call, reason, .. } => {
                self.saw.push(format!("{} ended {reason}", self.name(call)));
                if Some(call) == self.placed {
                    self.placed_ended = Some(reason);
                }
                if Some(call) == self.kept {
                    self.kept_ended = Some(reason);
                }
            }
            _ => {}
        }
    }

    fn name(&self, call: CallHandle) -> &'static str {
        if Some(call) == self.placed {
            "the desk's branch"
        } else if Some(call) == self.forked {
            "the mobile's branch"
        } else {
            "another branch"
        }
    }

    fn audible(&self) -> u32 {
        self.kept
            .and_then(|call| self.endpoint.media.get(&call))
            .map_or(0, |media| media.heard().audible)
    }

    fn done(&self) -> bool {
        self.kept_ended.is_some() || (self.kept.is_none() && self.placed_ended.is_some())
    }
}

/// Register the two phones, have the third call the user they share, and
/// judge what each of the three saw.
///
/// # Errors
/// The first thing that was not as it has to be.
pub(crate) fn run(server: &str, remote: SocketAddr) -> Result<String, String> {
    let bind = SocketAddr::new(crate::route_to(remote), 0);
    let now = Instant::now();
    let phone = |name, seed: u8, rings_after, answers_after| -> Result<Phone, String> {
        let mut endpoint = Endpoint::bind([seed; 32], [seed ^ 0x5a; 32], bind, catalog(), now)
            .map_err(|error| format!("cannot bind the {name}: {error}"))?;
        let account = endpoint.account(FORK_USER, FORK_PASS, server, remote)?;
        Ok(Phone {
            name,
            endpoint,
            account,
            remote,
            rings_after,
            answers_after,
            registered: false,
            call: None,
            stage: Stage::Waiting,
            confirmed: false,
            ended: None,
        })
    };
    // the desk registers first and the mobile second: "the second contact"
    // is the one that answers
    let mut desk = phone("desk", 151, Duration::ZERO, None)?;
    let mut mobile = phone(
        "mobile",
        157,
        MOBILE_RINGS_AFTER,
        Some(MOBILE_ANSWERS_AFTER),
    )?;
    let mut caller_endpoint = Endpoint::bind([163; 32], [167; 32], bind, catalog(), now)
        .map_err(|error| format!("cannot bind the caller: {error}"))?;
    // the proxy relays an INVITE without asking who sent it, so the caller
    // needs an account to place the call from and no binding
    let caller_account = caller_endpoint.account("labuser", "labpass", server, remote)?;
    let mut caller = Caller {
        endpoint: caller_endpoint,
        account: caller_account,
        target: uri(&format!("sip:{FORK_USER}@{server}"))?,
        remote,
        placed: None,
        forked: None,
        kept: None,
        placed_ended: None,
        kept_ended: None,
        hang_up_at: None,
        saw: Vec::new(),
    };

    // one at a time, so the mobile's binding is the later one
    let _ = desk.endpoint.agent.register(desk.account, now);
    let mut mobile_asked = false;
    let started = Instant::now();
    loop {
        let now = Instant::now();
        if now > started + PATIENCE {
            break;
        }
        desk.turn(now);
        if desk.registered && !mobile_asked {
            mobile_asked = true;
            let _ = mobile.endpoint.agent.register(mobile.account, now);
        }
        mobile.turn(now);
        caller.turn(desk.registered && mobile.registered, now);
        let desk_over = desk.ended.is_some() || (desk.call.is_none() && caller.done());
        if caller.done() && desk_over && (mobile.ended.is_some() || mobile.call.is_none()) {
            break;
        }
        let read = [
            desk.endpoint.read_sip(Instant::now()),
            mobile.endpoint.read_sip(Instant::now()),
            caller.endpoint.read_sip(Instant::now()),
        ];
        if !read.contains(&true) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    caller.endpoint.flush();
    // measured before the two bindings are given back, while every socket
    // still holds what it counted
    let verdict = verdict(&caller, &desk, &mobile);
    give_back(&mut desk.endpoint, desk.account);
    give_back(&mut mobile.endpoint, mobile.account);
    verdict
}

/// What the flow proved, or the first thing it did not.
fn verdict(caller: &Caller, desk: &Phone, mobile: &Phone) -> Result<String, String> {
    let story = || caller.saw.join(", ");
    for phone in [desk, mobile] {
        if !phone.registered {
            return Err(format!("the {} never registered", phone.name));
        }
        if phone.call.is_none() {
            return Err(format!(
                "the proxy never forked the call to the {} [{}]",
                phone.name,
                story()
            ));
        }
    }
    let Some(sibling) = caller.forked else {
        return Err(format!(
            "the caller saw one branch, not a fork [{}]",
            story()
        ));
    };
    match caller.kept {
        Some(kept) if kept == sibling => {}
        Some(_) => {
            return Err(format!(
                "the desk's branch was answered, so the flow proved nothing \
                 about a sibling answering first [{}]",
                story()
            ));
        }
        None => {
            return Err(format!(
                "the caller kept no branch: the mobile that answered was lost [{}]",
                story()
            ));
        }
    }
    if caller.placed_ended != Some(CallEndReason::ForkLost) {
        return Err(format!(
            "the branch the caller placed did not end as a fork lost: {:?} [{}]",
            caller.placed_ended,
            story()
        ));
    }
    if desk.ended != Some(CallEndReason::Cancelled) {
        return Err(format!(
            "the desk never saw the proxy's CANCEL: it ended {:?}",
            desk.ended
        ));
    }
    if !mobile.confirmed {
        return Err("the mobile's answer was never acknowledged".to_owned());
    }
    if mobile.ended != Some(CallEndReason::RemoteHangup) || caller.kept_ended.is_none() {
        return Err(format!(
            "the call did not last until the caller hung up: the mobile's \
             ended {:?}, the caller's {:?} [{}]",
            mobile.ended,
            caller.kept_ended,
            story()
        ));
    }
    let (to_mobile, to_caller) = (mobile.audible(), caller.audible());
    if to_mobile < AUDIBLE_WANTED || to_caller < AUDIBLE_WANTED {
        return Err(format!(
            "audio did not cross both ways: {to_caller} audible frames at the \
             caller, {to_mobile} at the mobile"
        ));
    }
    Ok(format!(
        "   (the mobile kept, the desk cancelled; {to_caller} audible frames at \
         the caller, {to_mobile} at the mobile)"
    ))
}
