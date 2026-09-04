// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

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
//! Three things here are where implementations go wrong.
//!
//! A 2xx does not end the transaction. RFC 6026 added the `Accepted` state so
//! that a retransmitted 2xx, or a 2xx from another branch of a downstream
//! fork, is passed up rather than dropped as a stray — which is the corner
//! that produces "the call connected but the app thinks it failed". The
//! machine sits there for timer M and never ACKs a 2xx itself: that ACK
//! belongs to the dialog (§13).
//!
//! A provisional response stops both timers. Retransmissions stop because the
//! far end is clearly alive, and timer B goes with them, so an INVITE that is
//! answered with 180 and then nothing does not time out here — waiting is the
//! user's decision, not the transaction's.
//!
//! A retransmitted final response in `Completed` re-sends the ACK and is *not*
//! passed up again. The far end did not hear the ACK; the user does not need
//! to hear about it twice.

use std::time::Instant;

use super::super::msg::{OwnedMessage, RawMessage, StatusCode};
use super::ack::ack_for_response;
use super::handle::InviteClientState;
use super::timer::{TimerConfig, TimerName};

/// What the layer above has to do after feeding something in.
///
/// At most one message goes out per input, so this is one `Option` rather
/// than a queue: the request, or the ACK, or nothing.
#[derive(Clone, Debug, Default)]
pub(crate) struct Effects {
    /// Hand these bytes to the transport.
    pub send: Option<OwnedMessage>,
    /// Tell the transaction user.
    pub notify: Option<Notify>,
    /// The machine is finished and can be dropped.
    pub terminated: bool,
}

/// What the transaction user is told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Notify {
    /// The response just fed in is for the user to see.
    Response,
    /// Timer B: nothing came back at all.
    TimedOut,
    /// The transport gave up on the request.
    TransportFailed,
}

/// The machine.
#[derive(Debug)]
pub(crate) struct InviteClientMachine {
    state: InviteClientState,
    request: OwnedMessage,
    /// Built once, on the first non-2xx final response, and re-sent for every
    /// retransmission of it.
    ack: Option<OwnedMessage>,
    config: TimerConfig,
    reliable: bool,
    /// How many times the request has been retransmitted, which is what timer
    /// A's doubling counts.
    attempt: u32,
    timer_a: Option<Instant>,
    timer_b: Option<Instant>,
    timer_d: Option<Instant>,
    timer_m: Option<Instant>,
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

    /// When the machine next needs the clock, if it does.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        [self.timer_a, self.timer_b, self.timer_d, self.timer_m]
            .into_iter()
            .flatten()
            .min()
    }

    /// Fire whichever timer is due, earliest first.
    ///
    /// Call until nothing is returned: a caller that comes back late may have
    /// several to work through, and firing one can arm another.
    pub(crate) fn handle_timeout(&mut self, now: Instant) -> Option<(TimerName, Effects)> {
        let due = self.next_deadline().filter(|at| *at <= now)?;

        if self.timer_a == Some(due) {
            // "reset the timer with a value of 2*T1", and again with double
            // that, for as long as we are still in Calling
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
                // a retransmission, or another fork's 2xx: both go up, and the
                // machine stays where it is
                Effects::notify(Notify::Response)
            }
            InviteClientState::Completed if !status.is_provisional() => {
                // the far end did not hear the ACK. Send it again and say
                // nothing: the user heard about this response already
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
            // no more retransmissions, and no timeout either: how long to wait
            // for a ringing phone is the user's decision, not ours
            self.state = InviteClientState::Proceeding;
            self.timer_a = None;
            self.timer_b = None;
            return Effects::notify(Notify::Response);
        }

        self.timer_a = None;
        self.timer_b = None;

        if status.is_success() {
            // RFC 6026 7.2: sit here for timer M so that retransmissions and
            // other forks' 2xx are recognised rather than dropped as strays.
            // The ACK for a 2xx is the dialog's, not ours
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
            // on a reliable transport there is nothing to absorb, so timer D
            // is zero and the machine is done as soon as the ACK is out
            terminated: wait.is_zero(),
        }
    }

    fn terminate(&mut self) {
        self.state = InviteClientState::Terminated;
        self.timer_a = None;
        self.timer_b = None;
        self.timer_d = None;
        self.timer_m = None;
    }
}

impl Effects {
    fn notify(notify: Notify) -> Self {
        Self {
            notify: Some(notify),
            ..Self::default()
        }
    }

    fn terminated() -> Self {
        Self {
            terminated: true,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Effects, InviteClientMachine, Notify};
    use crate::msg::{
        HeaderName, Method, OwnedMessage, ParseMode, ParseScratch, RequestBuilder, ResponseBuilder,
        StatusCode, parse,
    };
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
        // step to each deadline in turn, the way a caller with a real clock
        // does; jumping straight to 64*T1 would collapse the retransmissions
        // into one, which is also right and is not what this measures
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

        // a second 2xx, from a retransmission or from another fork, goes up
        // too rather than being dropped as a stray
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
    fn on_a_reliable_transport_the_machine_is_done_as_soon_as_the_ack_is_out() {
        // timer D is zero there: nothing retransmits, so there is nothing to
        // absorb
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
