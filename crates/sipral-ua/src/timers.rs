// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The session timer (RFC 4028), and why a call needs one.
//!
//! A dialog can outlive the call it describes. A phone loses power mid-call, a
//! NAT drops the binding, a proxy restarts: the BYE never arrives and both
//! ends keep a session that no longer exists. On a carrier that is a line
//! billed for nothing; on a PBX it is an extension that stays busy until
//! somebody reboots it. RFC 4028 answers it by making the session expire
//! unless somebody keeps saying it is still there.
//!
//! Two numbers and one role. `Session-Expires` is how long the session lives
//! without a refresh, `Min-SE` is the shortest anybody on the path will accept,
//! and the `refresher` parameter says which end sends the refresh. All three
//! are negotiated: the UAC asks, every proxy on the path may shorten the
//! interval or raise the floor, and the UAS settles it in the 2xx.
//!
//! The two ends do different things with the same interval. The refresher
//! sends a request at half of it — §7.2's "once half the session interval has
//! elapsed" — which leaves a whole second attempt before anything expires. The
//! other end waits, and if nothing has arrived shortly before expiry it hangs
//! up: §10 puts that "slightly before the session expiration", and recommends
//! the smaller of 32 seconds and a third of the interval as how much before.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::endpoint::OutgoingInDialogRequest;
use sipral_core::msg::{HeaderName, Method, Params, RawMessage, digits};
use sipral_core::transaction::AnyTransactionId;

use crate::agent::UserAgent;
use crate::call::{Author, CallHandle, Direction, Offer};

/// §4: "1800 seconds (30 minutes) is RECOMMENDED as the value for the
/// Session-Expires header field."
pub(crate) const RECOMMENDED: Duration = Duration::from_secs(1_800);
/// §4 and §5 both put the floor here, and it is the default `Min-SE`.
pub(crate) const FLOOR: Duration = Duration::from_secs(90);
/// §10: the non-refresher gives up "slightly before the session expiration",
/// by "the minimum of 32 seconds and one third of the session interval".
const GIVE_UP_MARGIN: Duration = Duration::from_secs(32);

/// Which end sends the refresh (§4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Refresher {
    /// This one.
    Us,
    /// The other one.
    Them,
}

impl Refresher {
    /// The token as it goes on the wire, from the writer's point of view.
    ///
    /// The parameter names the two ends of the *dialog*, not of the message,
    /// so which token means "us" depends on which end placed the call.
    const fn token(self, we_called: bool) -> &'static [u8] {
        match (self, we_called) {
            (Self::Us, true) | (Self::Them, false) => b"uac",
            (Self::Us, false) | (Self::Them, true) => b"uas",
        }
    }

    /// And back again.
    fn read(token: &[u8], we_called: bool) -> Option<Self> {
        let uac = if token.eq_ignore_ascii_case(b"uac") {
            true
        } else if token.eq_ignore_ascii_case(b"uas") {
            false
        } else {
            return None;
        };
        Some(if uac == we_called {
            Self::Us
        } else {
            Self::Them
        })
    }
}

/// What was agreed for one call, and when it next needs attention.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionTimer {
    /// How long the session lives without a refresh.
    pub(crate) interval: Duration,
    /// Which end refreshes it.
    pub(crate) refresher: Refresher,
    /// When this end acts: a refresh if it is ours, a BYE if it is not.
    pub(crate) due: Instant,
    /// The largest `Min-SE` anyone on the path has demanded, which §7.4 makes
    /// this end carry in every refresh from then on.
    pub(crate) floor: Duration,
    /// Whether a 422 has already raised the interval once. A second one is the
    /// far end contradicting itself, and asking again would loop.
    pub(crate) raised: bool,
}

impl SessionTimer {
    /// Start it, or start it again after a refresh was answered.
    pub(crate) fn armed(interval: Duration, refresher: Refresher, now: Instant) -> Self {
        Self {
            interval,
            refresher,
            due: now + wait_for(interval, refresher),
            floor: FLOOR,
            raised: false,
        }
    }

    /// The clock has moved and the session is still alive.
    pub(crate) fn rearm(&mut self, now: Instant) {
        self.due = now + wait_for(self.interval, self.refresher);
    }

    /// Whether this end is the one that has to send something.
    pub(crate) const fn is_ours(&self) -> bool {
        matches!(self.refresher, Refresher::Us)
    }

    /// The header value to write, from the point of view of the end that
    /// placed the call or the one that answered it.
    pub(crate) fn value(&self, we_called: bool) -> Box<[u8]> {
        write_value(self.interval, Some(self.refresher), we_called)
    }
}

/// How long this end waits before it does anything.
fn wait_for(interval: Duration, refresher: Refresher) -> Duration {
    match refresher {
        // §7.2: "once half the session interval has elapsed", which leaves a
        // second attempt before the far end gives up on us
        Refresher::Us => interval / 2,
        // §10, and the margin is what is left of the interval when it is
        // shorter than the margin itself
        Refresher::Them => interval.saturating_sub(GIVE_UP_MARGIN.min(interval / 3)),
    }
}

/// `Session-Expires`, and who it says refreshes (§4).
///
/// The refresher is `None` when the parameter is absent, which is what §7.1
/// recommends a UAC send so that the negotiation can settle it.
pub(crate) fn session_expires(
    message: &RawMessage<'_>,
    we_called: bool,
) -> Option<(Duration, Option<Refresher>)> {
    let raw = message.header(HeaderName::SessionExpires)?;
    let (head, params) = Params::split(raw);
    let seconds = digits(head).ok()?.require().ok()?;
    let refresher = params
        .get("refresher")
        .and_then(|token| Refresher::read(&token, we_called));
    Some((Duration::from_secs(u64::from(seconds)), refresher))
}

/// `Min-SE` (§5).
pub(crate) fn min_se(message: &RawMessage<'_>) -> Option<Duration> {
    let raw = message.header(HeaderName::MinSe)?;
    let (head, _) = Params::split(raw);
    let seconds = digits(head).ok()?.require().ok()?;
    Some(Duration::from_secs(u64::from(seconds)))
}

/// The `Session-Expires` value to write.
pub(crate) fn write_value(
    interval: Duration,
    refresher: Option<Refresher>,
    we_called: bool,
) -> Box<[u8]> {
    let mut out = interval.as_secs().to_string().into_bytes();
    if let Some(refresher) = refresher {
        out.extend_from_slice(b";refresher=");
        out.extend_from_slice(refresher.token(we_called));
    }
    out.into_boxed_slice()
}

/// Whole seconds, for `Min-SE`.
pub(crate) fn seconds(interval: Duration) -> Box<[u8]> {
    interval
        .as_secs()
        .to_string()
        .into_bytes()
        .into_boxed_slice()
}

/// What the far end demanded in a 422, kept no lower than the floor §5 sets.
pub(crate) fn demanded(response: &RawMessage<'_>) -> Option<Duration> {
    min_se(response).map(|floor| floor.max(FLOOR))
}

/// Whether a message says it understands session timers (§7.1).
pub(crate) fn supports_timer(message: &RawMessage<'_>) -> bool {
    lists(message, HeaderName::Supported) || lists(message, HeaderName::Require)
}

fn lists(message: &RawMessage<'_>, name: HeaderName<'_>) -> bool {
    message
        .field_values(name)
        .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"timer"))
}

// -- what the user agent does with them --------------------------------------

impl UserAgent {
    /// The headers that negotiate a timer on an outgoing request.
    ///
    /// §7.1 puts `Supported: timer` on every request but ACK, whether or not
    /// this end wants a timer, because that is what tells the far end it may
    /// ask for one.
    pub(crate) fn asking_for(
        &self,
        call: CallHandle,
        interval: Option<Duration>,
    ) -> Vec<(HeaderName<'static>, Box<[u8]>)> {
        // RFC 3891 §6.2: "UAs which support the Replaces header MUST include
        // the replaces option tag in a Supported header field"
        let mut out = vec![(HeaderName::Supported, Box::from(&b"timer, replaces"[..]))];
        let Some(interval) = interval else {
            return out;
        };
        let held = self.calls.get(&call);
        let we_called = held.is_none_or(|held| held.direction == Direction::Outgoing);
        // §7.1 has the initial request leave the refresher out so that the
        // negotiation settles it, and §7.4 has a request inside the dialog say
        // who is doing the work now. A 422 is answered with a second attempt
        // at the initial request, so it belongs to the first rule
        let refresher = held
            .filter(|held| held.dialog.is_some())
            .and_then(|held| held.timer)
            .map(|timer| timer.refresher);
        out.push((
            HeaderName::SessionExpires,
            write_value(interval, refresher, we_called),
        ));
        // §7.4: once a floor has been demanded on this dialog it rides on
        // every refresh from then on
        let floor = held.and_then(|held| held.timer).map(|timer| timer.floor);
        if let Some(floor) = floor.filter(|floor| *floor > FLOOR) {
            out.push((HeaderName::MinSe, seconds(floor)));
        }
        out
    }

    /// What the far end settled on, read off the 2xx (§7.2).
    pub(crate) fn on_timer_answer(
        &mut self,
        call: CallHandle,
        response: &RawMessage<'_>,
        now: Instant,
    ) {
        let Some(held) = self.calls.get(&call) else {
            return;
        };
        let we_called = held.direction == Direction::Outgoing;
        let asked = held.asked;
        let settled = session_expires(response, we_called);

        let (interval, refresher) = match (settled, asked) {
            (Some((interval, refresher)), _) => (interval, refresher.unwrap_or(Refresher::Us)),
            // §7.2: a far end that does not support this drops the header, and
            // an end that still wants a timer carries on "as if the
            // Session-Expires header field were in the 2xx response"
            (None, Some(interval)) => (interval, Refresher::Us),
            (None, None) => return,
        };
        if let Some(held) = self.calls.get_mut(&call) {
            held.timer = Some(SessionTimer::armed(interval, refresher, now));
        }
    }

    /// A 422: ask again with the interval the far end demands (§7.3).
    ///
    /// `true` when a second INVITE went out, which is what stops the refusal
    /// being reported as a call that failed.
    pub(crate) fn on_session_too_brief(
        &mut self,
        call: CallHandle,
        response: &RawMessage<'_>,
        now: Instant,
    ) -> bool {
        let Some(floor) = demanded(response) else {
            // a 422 with no Min-SE is the far end refusing without saying what
            // it would accept, and asking again would be guessing
            return false;
        };
        let again = {
            let Some(held) = self.calls.get_mut(&call) else {
                return false;
            };
            // once. A second 422 after the first was obeyed is the far end
            // contradicting itself
            if held.timer.is_some_and(|timer| timer.raised) {
                return false;
            }
            let Some(placed) = held.placed.clone() else {
                return false;
            };
            held.asked = Some(floor);
            held.cseq = held.cseq.saturating_add(1);
            held.timer = Some(SessionTimer {
                floor,
                raised: true,
                ..SessionTimer::armed(floor, Refresher::Us, now)
            });
            (placed, held.account)
        };
        let (placed, account) = again;
        let Some(account) = account else {
            return false;
        };
        self.dial(account, &placed, call, now).is_ok()
    }

    /// What the 2xx to an INVITE that came in should say about timers (§9).
    ///
    /// `None` when the far end said nothing about them, because §9 only has a
    /// UAS put a `Session-Expires` in a response to a request that supports
    /// the extension.
    pub(crate) fn timer_for_answer(
        &mut self,
        call: CallHandle,
        request: &RawMessage<'_>,
        now: Instant,
    ) -> Option<(Box<[u8]>, bool)> {
        if !supports_timer(request) {
            return None;
        }
        let asked = session_expires(request, false);
        let wanted = self
            .calls
            .get(&call)
            .and_then(|held| held.account)
            .and_then(|id| self.accounts.get(&id))
            .and_then(|config| config.session_interval);
        let interval = match (asked, wanted) {
            // §9: "The UAS MUST NOT increase the value of the Session-Expires
            // header field", so the request's interval is a ceiling
            (Some((theirs, _)), Some(ours)) => theirs.min(ours).max(FLOOR),
            (Some((theirs, _)), None) => theirs,
            (None, Some(ours)) => ours,
            (None, None) => return None,
        };
        // honour a preference the far end expressed; otherwise take the work,
        // because the end that refreshes needs a timer that runs and this one
        // is known to
        let refresher = asked.and_then(|(_, who)| who).unwrap_or(Refresher::Us);
        if let Some(held) = self.calls.get_mut(&call) {
            held.timer = Some(SessionTimer::armed(interval, refresher, now));
        }
        // §9: refresher=uac obliges a Require, refresher=uas only recommends
        // one, and there is nothing to gain by demanding what is already agreed
        let demand = matches!(refresher, Refresher::Them);
        Some((write_value(interval, Some(refresher), false), demand))
    }

    /// A refresh arrived. Rearm, and say what the answer should echo (§7.4).
    pub(crate) fn on_refresh_in(
        &mut self,
        call: CallHandle,
        request: &RawMessage<'_>,
        now: Instant,
    ) -> Option<Box<[u8]>> {
        let we_called = self
            .calls
            .get(&call)
            .is_some_and(|held| held.direction == Direction::Outgoing);
        let asked = session_expires(request, we_called);
        let held = self.calls.get_mut(&call)?;
        let timer = held.timer.as_mut()?;
        if let Some((interval, refresher)) = asked {
            timer.interval = interval.max(FLOOR);
            if let Some(refresher) = refresher {
                timer.refresher = refresher;
            }
        }
        timer.rearm(now);
        Some(timer.value(we_called))
    }

    /// What a response to a request inside the dialog should say about the
    /// timer, once [`UserAgent::on_refresh_in`] has read the request.
    pub(crate) fn timer_echo(&self, call: CallHandle) -> Option<Box<[u8]>> {
        let held = self.calls.get(&call)?;
        let timer = held.timer?;
        Some(timer.value(held.direction == Direction::Outgoing))
    }

    /// Whether an incoming request asks for less than anyone may accept (§9).
    pub(crate) fn too_brief(request: &RawMessage<'_>) -> bool {
        session_expires(request, false).is_some_and(|(interval, _)| interval < FLOOR)
    }

    /// The clock came round: refresh the session, or hang it up.
    pub(crate) fn fire_session_timers(&mut self, now: Instant) {
        let due: Vec<CallHandle> = self
            .calls
            .iter()
            .filter(|(_, held)| held.timer.is_some_and(|timer| timer.due <= now))
            .map(|(handle, _)| *handle)
            .collect();
        for call in due {
            let ours = self
                .calls
                .get(&call)
                .and_then(|held| held.timer)
                .is_some_and(|timer| timer.is_ours());
            if ours {
                self.send_refresh(call, false, now);
            } else {
                // §10: "it SHOULD send a BYE to terminate the session,
                // slightly before the session expiration". Nothing has come
                // from the far end for most of an interval, so the dialog is
                // one nobody is in any more
                self.expire(call, now);
            }
        }
    }

    /// Keep the session alive (§7.4).
    ///
    /// `retried` when this is the second attempt RFC 3261 §14.1 allows after
    /// a 491: it is built exactly as the first was — a refresh still carries
    /// `Session-Expires` and still offers the session unchanged — and a
    /// second 491 is reported rather than chased.
    pub(crate) fn send_refresh(&mut self, call: CallHandle, retried: bool, now: Instant) {
        let Some(state) = self.calls.get(&call) else {
            return;
        };
        let (Some(dialog), Some(timer)) = (state.dialog, state.timer) else {
            // no dialog to send a refresh in: the retry after a 422 has not
            // had a provisional that opened one, or the one it opened was
            // refused while the INVITE is still being answered. The call gets
            // a dialog or ends, and until then the timer waits a quarter of
            // the interval at a time. Dropping it would forget the floor and
            // the mark a second 422 is judged by; leaving `due` where it was
            // would have fire_session_timers pick it again on every turn
            if let Some(timer) = self
                .calls
                .get_mut(&call)
                .and_then(|held| held.timer.as_mut())
            {
                timer.due = now + timer.interval / 4;
            }
            return;
        };
        if state.changing() {
            // something else is already renegotiating, and it will rearm the
            // timer when it is answered; a second request now would be glare
            // we caused ourselves
            if let Some(held) = self.calls.get_mut(&call) {
                held.timer = Some(SessionTimer {
                    due: now + timer.interval / 4,
                    ..timer
                });
            }
            return;
        }
        let (confirmed, allows_update, description) = (
            state.state.is_confirmed(),
            state.update_allowed,
            state.session.repeat(),
        );
        let contact = self.current_contact(call, now);
        if !confirmed {
            // not up yet: a retry after a 422 still ringing, or a 2xx this end
            // sent whose ACK has not arrived. §7.2 and §9 run the session
            // expiration from the 2xx and want the refresh before it, and
            // nothing re-arms the timer when the ACK comes, so it is kept and
            // waits a quarter of the interval, as it does when a request
            // cannot go
            if let Some(held) = self.calls.get_mut(&call) {
                held.timer = Some(SessionTimer {
                    due: now + timer.interval / 4,
                    ..timer
                });
            }
            return;
        }

        // §7.4 recommends UPDATE, which carries no offer and so cannot fail on
        // one. A re-INVITE is the fallback, and then the offer has to be the
        // one already agreed, unchanged
        let over_update = allows_update;
        let mut request = OutgoingInDialogRequest::new(if over_update {
            Method::Update
        } else {
            Method::Invite
        })
        .contact(&contact);
        let mut asked_for = self.asking_for(call, Some(timer.interval));
        if !over_update {
            // a refresh sent as a re-INVITE is an INVITE, and carries
            // `Supported: gruu` the way the one that opened the call did
            self.fold_gruu(call, &mut asked_for);
        }
        for (name, value) in &asked_for {
            request = request.header(*name, value);
        }
        let body = if over_update {
            None
        } else {
            description.clone()
        };
        if let Some(ref description) = body {
            request = request.body(b"application/sdp", Arc::from(description.to_bytes()));
        }

        let sent = if over_update {
            self.endpoint
                .request_in_dialog(dialog, &request, now)
                .map(AnyTransactionId::NonInviteClient)
        } else {
            self.endpoint
                .reinvite(dialog, &request, now)
                .map(AnyTransactionId::InviteClient)
        };
        let Ok(transaction) = sent else {
            // the dialog is gone, or an INVITE is already running in it. The
            // timer stays armed and the next turn will try again
            if let Some(held) = self.calls.get_mut(&call) {
                held.timer = Some(SessionTimer {
                    due: now + timer.interval / 4,
                    ..timer
                });
            }
            return;
        };
        if let Some(held) = self.calls.get_mut(&call) {
            held.offering = Some(Offer {
                transaction: Some(transaction),
                description: body,
                held: held.session.hold.local,
                retried,
                author: Author::Refresh,
                overtaken: false,
            });
            if let Some(timer) = held.timer.as_mut() {
                timer.rearm(now);
            }
        }
        self.by_offer.insert(transaction, call);
    }

    /// The session ran out. §10 answers that with a BYE.
    fn expire(&mut self, call: CallHandle, now: Instant) {
        if let Some(held) = self.calls.get_mut(&call) {
            held.timer = None;
        }
        let dialog = self.calls.get(&call).and_then(|held| held.dialog);
        if let Some(dialog) = dialog {
            self.bye_by_itself(dialog, now);
        }
        self.finish_expired(call, now);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FLOOR, RECOMMENDED, Refresher, SessionTimer, demanded, min_se, session_expires,
        supports_timer, write_value,
    };
    use sipral_core::msg::{ParseMode, ParseScratch, RawMessage, parse};
    use std::time::{Duration, Instant};

    fn message(extra: &str) -> Vec<u8> {
        format!(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: timers\r\n\
CSeq: 1 INVITE\r\n\
{extra}Content-Length: 0\r\n\
\r\n"
        )
        .into_bytes()
    }

    fn with<T>(bytes: &[u8], f: impl FnOnce(&RawMessage<'_>) -> T) -> T {
        let mut scratch = ParseScratch::new();
        f(&parse(bytes, &mut scratch, ParseMode::Lenient).expect("a message"))
    }

    #[test]
    fn the_refresher_token_names_an_end_of_the_dialog_not_of_the_message() {
        // 4: the parameter is uac or uas, so which one means "us" depends on
        // which end placed the call
        assert_eq!(
            &*write_value(RECOMMENDED, Some(Refresher::Us), true),
            b"1800;refresher=uac"
        );
        assert_eq!(
            &*write_value(RECOMMENDED, Some(Refresher::Us), false),
            b"1800;refresher=uas"
        );
        assert_eq!(
            &*write_value(RECOMMENDED, Some(Refresher::Them), true),
            b"1800;refresher=uas"
        );
        assert_eq!(
            &*write_value(RECOMMENDED, Some(Refresher::Them), false),
            b"1800;refresher=uac"
        );
    }

    #[test]
    fn a_value_read_back_names_the_same_end_it_was_written_for() {
        for we_called in [true, false] {
            for refresher in [Refresher::Us, Refresher::Them] {
                let value = write_value(RECOMMENDED, Some(refresher), we_called);
                let bytes = message(&format!(
                    "Session-Expires: {}\r\n",
                    String::from_utf8_lossy(&value)
                ));
                let read = with(&bytes, |m| session_expires(m, we_called));
                assert_eq!(read, Some((RECOMMENDED, Some(refresher))));
            }
        }
    }

    #[test]
    fn an_interval_with_no_refresher_leaves_the_choice_open() {
        // 7.1: "it is RECOMMENDED that the parameter be omitted so that it can
        // be selected by the negotiation mechanisms"
        let bytes = message("Session-Expires: 600\r\n");
        assert_eq!(
            with(&bytes, |m| session_expires(m, true)),
            Some((Duration::from_secs(600), None))
        );
        assert_eq!(&*write_value(Duration::from_secs(600), None, true), b"600");
    }

    #[test]
    fn a_demanded_floor_is_never_read_below_the_one_the_rfc_fixes() {
        // 5: "its value MUST NOT be less than 90 seconds"
        let bytes = message("Min-SE: 30\r\n");
        assert_eq!(with(&bytes, min_se), Some(Duration::from_secs(30)));
        assert_eq!(with(&bytes, demanded), Some(FLOOR));
    }

    #[test]
    fn the_refresher_acts_at_half_the_interval_and_the_other_end_waits() {
        let t0 = Instant::now();
        let ours = SessionTimer::armed(Duration::from_secs(1_800), Refresher::Us, t0);
        // 7.2: "once half the session interval has elapsed"
        assert_eq!(ours.due, t0 + Duration::from_secs(900));

        let theirs = SessionTimer::armed(Duration::from_secs(1_800), Refresher::Them, t0);
        // 10: the minimum of 32 seconds and a third of the interval, before
        // the interval runs out
        assert_eq!(theirs.due, t0 + Duration::from_secs(1_768));
    }

    #[test]
    fn a_short_interval_takes_a_third_of_itself_as_the_margin() {
        let t0 = Instant::now();
        let theirs = SessionTimer::armed(Duration::from_secs(90), Refresher::Them, t0);
        assert_eq!(theirs.due, t0 + Duration::from_secs(60));
    }

    #[test]
    fn the_option_tag_is_read_from_either_list() {
        assert!(with(&message("Supported: timer\r\n"), supports_timer));
        assert!(with(&message("Require: timer\r\n"), supports_timer));
        assert!(with(
            &message("Supported: 100rel, timer\r\n"),
            supports_timer
        ));
        assert!(!with(&message("Supported: 100rel\r\n"), supports_timer));
        assert!(!with(&message(""), supports_timer));
    }
}
