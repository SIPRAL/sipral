// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The INVITE client transaction (RFC 3261 §17.1.1, RFC 6026 §7.2).
//!
//! ```text
//!                            |INVITE from TU
//!          Timer A fires     |INVITE sent
//!          Reset A,          V                      Timer B fires
//!          INVITE sent +-----------+                or Transport Err.
//!            +---------|           |---------------+inform TU
//!            |         |  Calling  |               |
//!            +-------->|           |-------------->|
//!                      +-----------+ 2xx           |
//!                         |  |       2xx to TU     |
//!                         |  |1xx                  |
//! 300-699 +---------------+  |1xx to TU            |
//! ACK sent |                  |                    |
//! ```
//!
//! A 2xx does not end the transaction. RFC 6026's `Accepted` state passes up
//! a retransmitted 2xx, or one from another fork, instead of dropping it as a
//! stray ("the call connected but the app thinks it failed"). It waits there
//! for timer M and never ACKs a 2xx itself: that ACK is the dialog's (§13).
//!
//! A provisional response stops timer A and timer B. After 180 and silence,
//! how long to wait is the user's decision.
//!
//! In `Completed`, a retransmitted non-2xx final response re-sends the ACK and
//! is not passed up again. A 2xx there is another branch answering after one
//! refused: it goes up without an ACK, as in `Accepted`.

use std::time::Instant;

use super::super::msg::{OwnedMessage, RawMessage, StatusCode};
use super::ack::ack_for_response;
use super::cancel::CancelDisposition;
use super::effect::{Effects, Notify};
use super::handle::InviteClientState;
use super::timer::{TimerConfig, TimerName};

/// The machine.
#[derive(Debug)]
pub(crate) struct InviteClientMachine {
    state: InviteClientState,
    request: OwnedMessage,
    /// Built on the first non-2xx final response, re-sent for each
    /// retransmission of it.
    ack: Option<OwnedMessage>,
    config: TimerConfig,
    reliable: bool,
    /// Retransmissions so far; timer A's doubling counts these.
    attempt: u32,
    timer_a: Option<Instant>,
    timer_b: Option<Instant>,
    timer_d: Option<Instant>,
    timer_m: Option<Instant>,
    /// Cancel asked for before any response; the CANCEL waits for the first
    /// provisional (RFC 3261 §9.1).
    cancel_pending: bool,
}

impl InviteClientMachine {
    /// Start the transaction: the request goes out, timer B starts, and timer
    /// A starts too unless the transport retransmits for us.
    pub(crate) fn start(
        request: OwnedMessage,
        reliable: bool,
        config: TimerConfig,
        now: Instant,
    ) -> (Self, Effects) {
        let machine = Self {
            state: InviteClientState::Calling,
            ack: None,
            timer_a: (!reliable).then(|| now + config.retransmit(0, None)),
            timer_b: Some(now + config.sixty_four_t1()),
            timer_d: None,
            timer_m: None,
            cancel_pending: false,
            attempt: 0,
            config,
            reliable,
            request: request.clone(),
        };
        let effects = Effects {
            send: Some(request),
            ..Effects::default()
        };
        (machine, effects)
    }

    /// Which state the machine is in.
    pub(crate) const fn state(&self) -> InviteClientState {
        self.state
    }

    /// The request as it went out, which is what a CANCEL is built from.
    pub(crate) const fn request(&self) -> &OwnedMessage {
        &self.request
    }

    /// When the machine next needs the clock, if it does.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        [self.timer_a, self.timer_b, self.timer_d, self.timer_m]
            .into_iter()
            .flatten()
            .min()
    }

    /// Fire whichever timer is due, earliest first. Call until it returns
    /// `None`: a late caller may have several due, and one can arm another.
    pub(crate) fn handle_timeout(&mut self, now: Instant) -> Option<(TimerName, Effects)> {
        let due = self.next_deadline().filter(|at| *at <= now)?;

        if self.timer_a == Some(due) {
            // "reset the timer with a value of 2*T1", doubling while Calling
            self.attempt = self.attempt.saturating_add(1);
            self.timer_a = Some(now + self.config.retransmit(self.attempt, None));
            return Some((
                TimerName::A,
                Effects {
                    send: Some(self.request.clone()),
                    ..Effects::default()
                },
            ));
        }
        if self.timer_b == Some(due) {
            // "the client transaction MUST NOT generate an ACK"
            self.terminate();
            return Some((
                TimerName::B,
                Effects {
                    notify: Some(Notify::TimedOut),
                    terminated: true,
                    ..Effects::default()
                },
            ));
        }
        if self.timer_d == Some(due) {
            self.terminate();
            return Some((TimerName::D, Effects::terminated()));
        }
        if self.timer_m == Some(due) {
            self.terminate();
            return Some((TimerName::M, Effects::terminated()));
        }
        None
    }

    /// A response that has already been matched to this transaction.
    pub(crate) fn on_response(&mut self, response: &RawMessage<'_>, now: Instant) -> Effects {
        let Some(status) = response.status() else {
            return Effects::default();
        };
        match self.state {
            InviteClientState::Calling | InviteClientState::Proceeding => {
                self.on_response_while_open(status, response, now)
            }
            InviteClientState::Accepted if status.is_success() => {
                // a retransmission or another fork's 2xx: up, and stay
                Effects::notify(Notify::Response)
            }
            InviteClientState::Completed if status.is_success() => {
                // another branch's dialog, not a retransmission: proxies
                // forward every 2xx (§16.7 step 5). RFC 6026 §8.4 re-sends the
                // ACK only for 300-699 retransmissions; the ACK for a 2xx is
                // the TU's (§13.2.2.4), which must hear of it to send one and
                // end the unwanted dialog
                Effects::notify(Notify::Response)
            }
            InviteClientState::Completed if !status.is_provisional() => {
                // "Any retransmissions of a response with status code 300-699
                // that are received while in the "Completed" state MUST cause
                // the ACK to be re-passed to the transport layer for
                // retransmission, but the newly received response MUST NOT be
                // passed up to the TU" (RFC 6026 §8.4)
                Effects {
                    send: self.ack.clone(),
                    ..Effects::default()
                }
            }
            InviteClientState::Accepted
            | InviteClientState::Completed
            | InviteClientState::Terminated => Effects::default(),
        }
    }

    /// The user wants the call given up on.
    ///
    /// Always accepted while the transaction is open. A CANCEL may not go
    /// before a provisional (RFC 3261 §9.1), so an early one is held and
    /// [`InviteClientMachine::take_deferred_cancel`] says when it may go.
    pub(crate) fn request_cancel(&mut self) -> CancelDisposition {
        match self.state {
            InviteClientState::Calling => {
                self.cancel_pending = true;
                CancelDisposition::Deferred
            }
            InviteClientState::Proceeding => CancelDisposition::Now,
            // "a CANCEL has no effect on requests that have already generated
            // a final response"
            InviteClientState::Accepted
            | InviteClientState::Completed
            | InviteClientState::Terminated => CancelDisposition::TooLate,
        }
    }

    /// Whether a held CANCEL may now go. Ask after feeding a response; true at
    /// most once.
    pub(crate) fn take_deferred_cancel(&mut self) -> bool {
        let due = self.cancel_pending && self.state == InviteClientState::Proceeding;
        if due {
            self.cancel_pending = false;
        }
        due
    }

    /// The transport could not deliver the request.
    pub(crate) fn on_transport_error(&mut self) -> Effects {
        if self.state == InviteClientState::Terminated {
            return Effects::default();
        }
        self.terminate();
        Effects {
            notify: Some(Notify::TransportFailed),
            terminated: true,
            ..Effects::default()
        }
    }

    fn on_response_while_open(
        &mut self,
        status: StatusCode,
        response: &RawMessage<'_>,
        now: Instant,
    ) -> Effects {
        if status.is_provisional() {
            // no retransmissions and no timeout: how long a phone may ring is
            // the user's decision
            self.state = InviteClientState::Proceeding;
            self.timer_a = None;
            self.timer_b = None;
            return Effects::notify(Notify::Response);
        }

        self.timer_a = None;
        self.timer_b = None;

        if status.is_success() {
            // RFC 6026 7.2: wait for timer M so retransmissions and other
            // forks' 2xx are recognised. The 2xx ACK is the dialog's
            self.state = InviteClientState::Accepted;
            self.timer_m = Some(now + self.config.sixty_four_t1());
            return Effects::notify(Notify::Response);
        }

        self.state = InviteClientState::Completed;
        self.ack = ack_for_response(&self.request.as_raw(), response).ok();
        let wait = self.config.d(self.reliable);
        self.timer_d = Some(now + wait);
        Effects {
            send: self.ack.clone(),
            notify: Some(Notify::Response),
            // reliable transport: nothing to absorb, timer D is zero
            terminated: wait.is_zero(),
        }
    }

    fn terminate(&mut self) {
        self.state = InviteClientState::Terminated;
        self.cancel_pending = false;
        self.timer_a = None;
        self.timer_b = None;
        self.timer_d = None;
        self.timer_m = None;
    }
}

#[cfg(test)]
mod tests {
    use super::InviteClientMachine;
    use crate::msg::{
        HeaderName, Method, OwnedMessage, ParseMode, ParseScratch, RequestBuilder, ResponseBuilder,
        StatusCode, parse,
    };
    use crate::transaction::cancel::CancelDisposition;
    use crate::transaction::effect::{Effects, Notify};
    use crate::transaction::{InviteClientState, TimerConfig, TimerName};
    use std::time::{Duration, Instant};

    fn invite() -> OwnedMessage {
        RequestBuilder::new(Method::Invite, b"sip:bob@example.com")
            .via(b"SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1")
            .max_forwards(70)
            .from(b"<sip:alice@example.com>;tag=1")
            .to(b"<sip:bob@example.com>")
            .call_id(b"a84b4c76e66710")
            .cseq(314_159)
            .build()
            .expect("an INVITE")
    }

    fn response(status: u16, tag: Option<&[u8]>) -> OwnedMessage {
        let request = invite();
        let mut scratch = ParseScratch::new();
        let parsed = parse(request.as_raw().as_bytes(), &mut scratch, ParseMode::Strict)
            .expect("the request");
        let mut builder =
            ResponseBuilder::for_request(&parsed, StatusCode::new(status).expect("a status"));
        if let Some(tag) = tag {
            builder = builder.to_tag(tag);
        }
        builder.build().expect("a response")
    }

    fn feed(machine: &mut InviteClientMachine, message: &OwnedMessage, now: Instant) -> Effects {
        let mut scratch = ParseScratch::new();
        let parsed = parse(message.as_raw().as_bytes(), &mut scratch, ParseMode::Strict)
            .expect("a response");
        machine.on_response(&parsed, now)
    }

    fn start(reliable: bool) -> (InviteClientMachine, Effects, Instant, TimerConfig) {
        let now = Instant::now();
        let config = TimerConfig::default();
        let (machine, effects) = InviteClientMachine::start(invite(), reliable, config, now);
        (machine, effects, now, config)
    }

    #[test]
    fn starting_sends_the_request_and_arms_a_and_b() {
        let (machine, effects, now, config) = start(false);
        assert!(effects.send.is_some());
        assert_eq!(machine.state(), InviteClientState::Calling);
        assert_eq!(machine.next_deadline(), Some(now + config.t1));
    }

    #[test]
    fn on_a_reliable_transport_nothing_is_retransmitted() {
        // "If a reliable transport is being used, the client transaction
        // SHOULD NOT start timer A"
        let (machine, _, now, config) = start(true);
        assert_eq!(
            machine.next_deadline(),
            Some(now + config.sixty_four_t1()),
            "only timer B"
        );
    }

    #[test]
    fn timer_a_doubles_and_each_firing_sends_the_request_again() {
        // T1, then 2*T1 from that firing, then 4*T1, and so on
        let (mut machine, _, now, _) = start(false);
        let mut at = now;
        for interval in [500_u64, 1000, 2000, 4000, 8000] {
            at += Duration::from_millis(interval);
            assert_eq!(machine.next_deadline(), Some(at), "interval {interval} ms");
            let (name, effects) = machine.handle_timeout(at).expect("timer A");
            assert_eq!(name, TimerName::A);
            assert!(effects.send.is_some(), "the request goes out again");
            assert!(!effects.terminated);
        }
        assert_eq!(machine.state(), InviteClientState::Calling);
    }

    #[test]
    fn timer_b_ends_the_transaction_and_sends_no_ack() {
        // "the client transaction MUST NOT generate an ACK"
        let (mut machine, _, now, config) = start(true);
        let (name, effects) = machine
            .handle_timeout(now + config.sixty_four_t1())
            .expect("timer B");
        assert_eq!(name, TimerName::B);
        assert_eq!(effects.notify, Some(Notify::TimedOut));
        assert!(effects.terminated);
        assert!(effects.send.is_none(), "no ACK for a timeout");
        assert_eq!(machine.state(), InviteClientState::Terminated);
        assert_eq!(machine.next_deadline(), None);
    }

    #[test]
    fn on_udp_the_retransmissions_run_out_before_timer_b() {
        // 64*T1 is "the amount of time required to send seven requests"
        let (mut machine, _, _, _) = start(false);
        let mut sent = 1;
        let mut last = None;
        // step to each deadline as a real clock would; jumping straight to
        // 64*T1 would merge the retransmissions
        while let Some(at) = machine.next_deadline() {
            let (name, effects) = machine.handle_timeout(at).expect("a timer");
            if effects.send.is_some() {
                sent += 1;
            }
            last = Some(name);
        }
        assert_eq!(sent, 7, "seven transmissions in all");
        assert_eq!(last, Some(TimerName::B));
        assert_eq!(machine.state(), InviteClientState::Terminated);
    }

    #[test]
    fn a_provisional_response_stops_both_timers() {
        let (mut machine, _, now, _) = start(false);
        let effects = feed(&mut machine, &response(180, Some(b"a6c85cf")), now);
        assert_eq!(effects.notify, Some(Notify::Response));
        assert_eq!(machine.state(), InviteClientState::Proceeding);
        assert_eq!(
            machine.next_deadline(),
            None,
            "no retransmit and no timeout: waiting is the user's decision"
        );

        // further provisionals keep going up
        let again = feed(&mut machine, &response(183, Some(b"a6c85cf")), now);
        assert_eq!(again.notify, Some(Notify::Response));
        assert_eq!(machine.state(), InviteClientState::Proceeding);
    }

    #[test]
    fn a_2xx_does_not_end_the_transaction() {
        // RFC 6026 7.2, and the whole reason the Accepted state exists
        let (mut machine, _, now, config) = start(false);
        let effects = feed(&mut machine, &response(200, Some(b"a6c85cf")), now);
        assert_eq!(effects.notify, Some(Notify::Response));
        assert!(!effects.terminated);
        assert!(effects.send.is_none(), "the ACK for a 2xx is the dialog's");
        assert_eq!(machine.state(), InviteClientState::Accepted);
        assert_eq!(machine.next_deadline(), Some(now + config.sixty_four_t1()));

        // a second 2xx (retransmission or another fork) goes up too
        let second = feed(&mut machine, &response(200, Some(b"other-fork")), now);
        assert_eq!(second.notify, Some(Notify::Response));
        assert_eq!(machine.state(), InviteClientState::Accepted);

        let (name, done) = machine
            .handle_timeout(now + config.sixty_four_t1())
            .expect("timer M");
        assert_eq!(name, TimerName::M);
        assert!(done.terminated);
        assert_eq!(machine.state(), InviteClientState::Terminated);
    }

    #[test]
    fn a_final_response_that_is_not_a_2xx_is_acknowledged_here() {
        let (mut machine, _, now, _) = start(false);
        let busy = response(486, Some(b"a6c85cf"));
        let effects = feed(&mut machine, &busy, now);

        assert_eq!(effects.notify, Some(Notify::Response));
        assert_eq!(machine.state(), InviteClientState::Completed);
        let ack = effects.send.expect("an ACK");
        let ack = ack.as_raw();
        assert_eq!(ack.method(), Some(Method::Ack));
        assert_eq!(
            ack.to().expect("To").tag().as_deref(),
            Some(&b"a6c85cf"[..]),
            "the tag comes from the response"
        );
        assert_eq!(ack.header_count(HeaderName::Via), 1);
        assert_eq!(machine.next_deadline(), Some(now + Duration::from_secs(32)));
    }

    #[test]
    fn a_retransmitted_final_response_is_acknowledged_again_and_not_reported_again() {
        let (mut machine, _, now, _) = start(false);
        let busy = response(486, Some(b"a6c85cf"));
        let first = feed(&mut machine, &busy, now);
        let first_ack = first.send.expect("an ACK");

        let again = feed(&mut machine, &busy, now + Duration::from_millis(700));
        let second_ack = again.send.expect("the ACK once more");
        assert_eq!(
            second_ack.as_raw().as_bytes(),
            first_ack.as_raw().as_bytes(),
            "the same ACK, byte for byte"
        );
        assert_eq!(
            again.notify, None,
            "the user heard about this response already"
        );
        assert_eq!(machine.state(), InviteClientState::Completed);
    }

    #[test]
    fn a_2xx_after_a_refusal_goes_up_and_is_not_answered_with_the_refusals_ack() {
        // RFC 6026 §8.4 re-sends the ACK only for 300-699. A 2xx after a 486
        // is another branch's dialog (§16.7 step 5), whose ACK is the TU's
        // (§13.2.2.4)
        let (mut machine, _, now, _) = start(false);
        let busy = feed(&mut machine, &response(486, Some(b"a6c85cf")), now);
        let refusal_ack = busy.send.expect("the refusal is acknowledged here");

        let late = feed(
            &mut machine,
            &response(200, Some(b"other-fork")),
            now + Duration::from_millis(40),
        );
        assert_eq!(late.notify, Some(Notify::Response), "the 2xx goes up");
        assert!(
            late.send.is_none(),
            "not the ACK built for the 486: {:?}",
            late.send.map(|ack| ack.as_raw().as_bytes().to_vec())
        );
        assert!(!late.terminated);
        assert_eq!(machine.state(), InviteClientState::Completed);

        // and the refusal retransmitted after it is still the refusal
        let again = feed(
            &mut machine,
            &response(486, Some(b"a6c85cf")),
            now + Duration::from_millis(500),
        );
        assert_eq!(again.notify, None);
        assert_eq!(
            again.send.map(|ack| ack.as_raw().as_bytes().to_vec()),
            Some(refusal_ack.as_raw().as_bytes().to_vec())
        );
    }

    #[test]
    fn on_a_reliable_transport_the_machine_is_done_as_soon_as_the_ack_is_out() {
        // timer D is zero there: nothing to absorb
        let (mut machine, _, now, _) = start(true);
        let effects = feed(&mut machine, &response(486, Some(b"a6c85cf")), now);
        assert!(effects.send.is_some());
        assert!(effects.terminated);
    }

    #[test]
    fn timer_d_ends_a_completed_transaction() {
        let (mut machine, _, now, _) = start(false);
        feed(&mut machine, &response(486, Some(b"a6c85cf")), now);
        let (name, effects) = machine
            .handle_timeout(now + Duration::from_secs(32))
            .expect("timer D");
        assert_eq!(name, TimerName::D);
        assert!(effects.terminated);
        assert_eq!(machine.state(), InviteClientState::Terminated);
    }

    #[test]
    fn a_transport_error_ends_it_the_way_timer_b_would() {
        let (mut machine, _, _, _) = start(false);
        let effects = machine.on_transport_error();
        assert_eq!(effects.notify, Some(Notify::TransportFailed));
        assert!(effects.terminated);
        assert_eq!(machine.state(), InviteClientState::Terminated);
        // and once is enough
        assert_eq!(machine.on_transport_error().notify, None);
    }

    #[test]
    fn a_cancel_asked_for_too_early_is_held_rather_than_refused() {
        // 9.1: "If no provisional response has been received, the CANCEL
        // request MUST NOT be sent; rather, the client MUST wait"
        let (mut machine, _, now, _) = start(false);
        assert_eq!(machine.request_cancel(), CancelDisposition::Deferred);
        assert!(!machine.take_deferred_cancel(), "nothing has come back yet");

        feed(&mut machine, &response(180, Some(b"a6c85cf")), now);
        assert!(machine.take_deferred_cancel(), "now it may go");
        assert!(
            !machine.take_deferred_cancel(),
            "and it is its own transaction from here"
        );
    }

    #[test]
    fn a_cancel_asked_for_after_a_provisional_goes_at_once() {
        let (mut machine, _, now, _) = start(false);
        feed(&mut machine, &response(180, Some(b"a6c85cf")), now);
        assert_eq!(machine.request_cancel(), CancelDisposition::Now);
        assert!(
            !machine.take_deferred_cancel(),
            "it was not held, so there is nothing to release"
        );
    }

    #[test]
    fn a_cancel_asked_for_after_the_answer_is_too_late() {
        // "CANCEL has no effect on requests that have already generated a
        // final response"
        for status in [200_u16, 486] {
            let (mut machine, _, now, _) = start(false);
            feed(&mut machine, &response(status, Some(b"a6c85cf")), now);
            assert_eq!(machine.request_cancel(), CancelDisposition::TooLate);
        }
    }

    #[test]
    fn a_held_cancel_is_dropped_when_the_transaction_ends_without_one() {
        let (mut machine, _, now, config) = start(true);
        assert_eq!(machine.request_cancel(), CancelDisposition::Deferred);
        machine
            .handle_timeout(now + config.sixty_four_t1())
            .expect("timer B");
        assert!(!machine.take_deferred_cancel());
    }

    #[test]
    fn nothing_is_due_before_its_deadline() {
        let (mut machine, _, now, _) = start(false);
        assert!(machine.handle_timeout(now).is_none());
        assert!(
            machine
                .handle_timeout(now + Duration::from_millis(499))
                .is_none()
        );
        assert!(
            machine
                .handle_timeout(now + Duration::from_millis(500))
                .is_some()
        );
    }
}
