// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The INVITE server transaction (RFC 3261 §17.2.1, RFC 6026 §8.1).
//!
//! The answering side. Four things here are the ones that go wrong.
//!
//! A 100 Trying goes out immediately. The RFC lets a transaction skip it if it
//! *knows* the user will answer within 200 ms, but the transaction layer never
//! knows that — only the user does — and the 100 is what "quenches request
//! retransmissions rapidly in order to avoid network congestion". A redundant
//! 100 costs one datagram; a missing one costs six retransmitted INVITEs.
//!
//! A 2xx does not end this transaction either. RFC 6026 puts it in `Accepted`
//! for timer L, where retransmissions of the INVITE are absorbed rather than
//! answered again — the far end is retransmitting because it has not seen the
//! 2xx. §13.3.1.4 has the user retransmit that 2xx until the ACK arrives, and
//! this machine does it on the user's behalf, on timer G's schedule, because
//! every layer above would otherwise have to and none did: a 2xx lost on UDP
//! left the caller ringing until it gave up. The ACK stops it, whether it
//! reaches this transaction or, sent under a branch of its own as §17.1.1.3
//! has it, the dialog, which tells the transaction. A fresh copy the user
//! passes down is still sent as it comes.
//!
//! An ACK means two different things depending on where the machine is. After
//! a non-2xx final response it is the transaction's own, and it moves to
//! `Confirmed` without the user ever seeing it. After a 2xx it belongs to the
//! dialog, and RFC 6026 says it "MUST be passed directly to the TU and not
//! absorbed".
//!
//! And a final response that is not a 2xx *is* retransmitted here, by timer G,
//! doubling up to T2 — but only on an unreliable transport. RFC 2543
//! retransmitted over TCP too; RFC 3261 stopped.

use std::time::Instant;

use super::super::msg::{OwnedMessage, RawMessage, ResponseBuilder, StatusCode};
use super::effect::{Effects, Notify};
use super::handle::InviteServerState;
use super::timer::{TimerConfig, TimerName};

/// The machine.
#[derive(Debug)]
pub(crate) struct InviteServerMachine {
    state: InviteServerState,
    /// The last thing sent, which is what a retransmitted INVITE gets back:
    /// the most recent provisional while proceeding, the final response after
    /// that.
    last_response: Option<OwnedMessage>,
    config: TimerConfig,
    reliable: bool,
    attempt: u32,
    timer_g: Option<Instant>,
    timer_h: Option<Instant>,
    timer_i: Option<Instant>,
    timer_l: Option<Instant>,
    /// Whether the ACK for a 2xx arrived. §13.3.1.4 has the user send a BYE
    /// when it never does, and timer L running out is the only moment anyone
    /// can know that.
    acked: bool,
}

impl InviteServerMachine {
    /// Take the INVITE. The 100 Trying goes out at once.
    pub(crate) fn start(
        request: &RawMessage<'_>,
        reliable: bool,
        config: TimerConfig,
        _now: Instant,
    ) -> (Self, Effects) {
        // "constructed according to the procedures in Section 8.2.6, except
        // that the insertion of tags in the To header field ... is downgraded
        // from MAY to SHOULD NOT" — so no tag here
        let trying = ResponseBuilder::for_request(request, StatusCode::TRYING)
            .build()
            .ok();
        let machine = Self {
            state: InviteServerState::Proceeding,
            last_response: trying.clone(),
            config,
            reliable,
            attempt: 0,
            timer_g: None,
            timer_h: None,
            timer_i: None,
            timer_l: None,
            acked: false,
        };
        let effects = Effects {
            send: trying,
            ..Effects::default()
        };
        (machine, effects)
    }

    /// Which state the machine is in.
    pub(crate) const fn state(&self) -> InviteServerState {
        self.state
    }

    /// When the machine next needs the clock, if it does.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        [self.timer_g, self.timer_h, self.timer_i, self.timer_l]
            .into_iter()
            .flatten()
            .min()
    }

    /// The user has a response to send.
    pub(crate) fn respond(&mut self, response: OwnedMessage, now: Instant) -> Effects {
        let Some(status) = response.as_raw().status() else {
            return Effects::default();
        };
        match self.state {
            InviteServerState::Proceeding => self.respond_while_proceeding(status, response, now),
            // "Any retransmission of the 2xx response passed from the TU to
            // the transaction while in the Accepted state MUST be passed to
            // the transport layer for transmission"
            InviteServerState::Accepted if status.is_success() => Effects {
                send: Some(response),
                ..Effects::default()
            },
            InviteServerState::Accepted
            | InviteServerState::Completed
            | InviteServerState::Confirmed
            | InviteServerState::Terminated => Effects::default(),
        }
    }

    /// A retransmission of the INVITE arrived.
    pub(crate) fn on_request(&mut self) -> Effects {
        match self.state {
            // the most recent provisional, or the final response: whatever was
            // last sent is what the far end failed to hear
            InviteServerState::Proceeding | InviteServerState::Completed => Effects {
                send: self.last_response.clone(),
                ..Effects::default()
            },
            // RFC 6026 8.1: absorbed, and not passed to the user. The user is
            // the one retransmitting the 2xx
            InviteServerState::Accepted
            | InviteServerState::Confirmed
            | InviteServerState::Terminated => Effects::default(),
        }
    }

    /// An ACK arrived.
    pub(crate) fn on_ack(&mut self, now: Instant) -> Effects {
        match self.state {
            InviteServerState::Completed => {
                // the transaction's own ACK: timer G stops, and Confirmed sits
                // out the retransmissions of it
                self.state = InviteServerState::Confirmed;
                self.timer_g = None;
                self.timer_h = None;
                let wait = self.config.t4_or_zero(self.reliable);
                self.timer_i = Some(now + wait);
                Effects {
                    terminated: wait.is_zero(),
                    ..Effects::default()
                }
            }
            // the dialog's ACK, for a 2xx: "MUST be passed directly to the TU
            // and not absorbed"
            InviteServerState::Accepted => {
                self.acked = true;
                self.timer_g = None;
                Effects::notify(Notify::Ack)
            }
            InviteServerState::Proceeding
            | InviteServerState::Confirmed
            | InviteServerState::Terminated => Effects::default(),
        }
    }

    /// The dialog took the ACK to this transaction's 2xx, which arrived under
    /// a branch of its own and so never reached [`Self::on_ack`]: the 2xx
    /// stops going out again, and timer L ends the transaction quietly
    /// rather than as a 2xx nobody acknowledged.
    pub(crate) const fn acknowledged_elsewhere(&mut self) {
        if matches!(self.state, InviteServerState::Accepted) {
            self.acked = true;
            self.timer_g = None;
        }
    }

    /// Fire whichever timer is due, earliest first.
    pub(crate) fn handle_timeout(&mut self, now: Instant) -> Option<(TimerName, Effects)> {
        let due = self.next_deadline().filter(|at| *at <= now)?;

        if self.timer_g == Some(due) {
            self.attempt = self.attempt.saturating_add(1);
            self.timer_g = Some(now + self.config.retransmit(self.attempt, Some(self.config.t2)));
            return Some((
                TimerName::G,
                Effects {
                    send: self.last_response.clone(),
                    ..Effects::default()
                },
            ));
        }
        if self.timer_h == Some(due) {
            // "it implies that the ACK was never received"
            self.terminate();
            return Some((
                TimerName::H,
                Effects {
                    notify: Some(Notify::TimedOut),
                    terminated: true,
                    ..Effects::default()
                },
            ));
        }
        if self.timer_i == Some(due) {
            self.terminate();
            return Some((TimerName::I, Effects::terminated()));
        }
        if self.timer_l == Some(due) {
            // §13.3.1.4: "If the UAS generates a 2xx response and never
            // receives an ACK, it SHOULD generate a BYE" — which the user can
            // only do if it is told, and this is the moment it can be
            let acked = self.acked;
            self.terminate();
            return Some((
                TimerName::L,
                if acked {
                    Effects::terminated()
                } else {
                    Effects {
                        notify: Some(Notify::TimedOut),
                        terminated: true,
                        ..Effects::default()
                    }
                },
            ));
        }
        None
    }

    /// The transport could not deliver a response.
    ///
    /// The machine stays where it is: RFC 6026 §8.2 says a server transaction
    /// "MUST NOT discard transaction state based only on encountering a
    /// non-recoverable transport error", because the far end may still be
    /// reachable by another route and the timers will end it anyway.
    pub(crate) fn on_transport_error(&self) -> Effects {
        if self.state == InviteServerState::Terminated {
            return Effects::default();
        }
        Effects::notify(Notify::TransportFailed)
    }

    fn respond_while_proceeding(
        &mut self,
        status: StatusCode,
        response: OwnedMessage,
        now: Instant,
    ) -> Effects {
        self.last_response = Some(response.clone());
        let send = Some(response);

        if status.is_provisional() {
            // sent, not retransmitted, and the state does not move
            return Effects {
                send,
                ..Effects::default()
            };
        }
        if status.is_success() {
            self.state = InviteServerState::Accepted;
            self.timer_l = Some(now + self.config.sixty_four_t1());
            // §13.3.1.4: the 2xx goes again, T1 doubling up to T2, until its
            // ACK arrives; over a reliable transport the transport sees to it
            self.attempt = 0;
            self.timer_g =
                (!self.reliable).then(|| now + self.config.retransmit(0, Some(self.config.t2)));
            return Effects {
                send,
                ..Effects::default()
            };
        }

        self.state = InviteServerState::Completed;
        self.attempt = 0;
        // "For unreliable transports, timer G is set to fire in T1 seconds,
        // and is not set to fire for reliable transports"
        self.timer_g =
            (!self.reliable).then(|| now + self.config.retransmit(0, Some(self.config.t2)));
        self.timer_h = Some(now + self.config.sixty_four_t1());
        Effects {
            send,
            ..Effects::default()
        }
    }

    fn terminate(&mut self) {
        self.state = InviteServerState::Terminated;
        self.timer_g = None;
        self.timer_h = None;
        self.timer_i = None;
        self.timer_l = None;
    }
}

#[cfg(test)]
mod tests {
    use super::InviteServerMachine;
    use crate::msg::{OwnedMessage, ParseMode, ParseScratch, ResponseBuilder, StatusCode, parse};
    use crate::transaction::effect::{Effects, Notify};
    use crate::transaction::{InviteServerState, TimerConfig, TimerName};
    use std::time::{Duration, Instant};

    const INVITE: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

    fn response(status: u16) -> OwnedMessage {
        let mut scratch = ParseScratch::new();
        let request = parse(INVITE, &mut scratch, ParseMode::Strict).expect("the INVITE");
        ResponseBuilder::for_request(&request, StatusCode::new(status).expect("a status"))
            .to_tag(b"a6c85cf")
            .build()
            .expect("a response")
    }

    fn start(reliable: bool) -> (InviteServerMachine, Effects, Instant, TimerConfig) {
        let now = Instant::now();
        let config = TimerConfig::default();
        let mut scratch = ParseScratch::new();
        let request = parse(INVITE, &mut scratch, ParseMode::Strict).expect("the INVITE");
        let (machine, effects) = InviteServerMachine::start(&request, reliable, config, now);
        (machine, effects, now, config)
    }

    #[test]
    fn the_hundred_trying_goes_out_at_once_and_carries_no_tag() {
        let (machine, effects, _, _) = start(false);
        let trying = effects.send.expect("a 100 Trying");
        let trying = trying.as_raw();
        assert_eq!(trying.status(), Some(StatusCode::TRYING));
        assert_eq!(
            trying.to().expect("To").tag(),
            None,
            "17.2.1 downgrades inserting a tag here to SHOULD NOT"
        );
        assert_eq!(machine.state(), InviteServerState::Proceeding);
        assert_eq!(machine.next_deadline(), None, "nothing is on a timer yet");
    }

    #[test]
    fn a_retransmitted_invite_gets_the_most_recent_provisional_back() {
        let (mut machine, _, now, _) = start(false);
        let echoed = machine.on_request().send.expect("the 100 again");
        assert_eq!(echoed.as_raw().status(), Some(StatusCode::TRYING));

        machine.respond(response(180), now);
        let echoed = machine.on_request().send.expect("the 180");
        assert_eq!(echoed.as_raw().status(), Some(StatusCode::RINGING));
        assert_eq!(machine.state(), InviteServerState::Proceeding);
    }

    #[test]
    fn provisional_responses_go_out_without_moving_the_machine() {
        let (mut machine, _, now, _) = start(false);
        for status in [180_u16, 183, 180] {
            let effects = machine.respond(response(status), now);
            assert!(effects.send.is_some());
            assert!(!effects.terminated);
            assert_eq!(machine.state(), InviteServerState::Proceeding);
        }
        assert_eq!(
            machine.next_deadline(),
            None,
            "provisionals are not retried"
        );
    }

    #[test]
    fn a_2xx_goes_to_accepted_and_absorbs_the_retransmitted_invites() {
        // RFC 6026 8.1
        let (mut machine, _, now, config) = start(false);
        let effects = machine.respond(response(200), now);
        assert!(effects.send.is_some());
        assert!(!effects.terminated);
        assert_eq!(machine.state(), InviteServerState::Accepted);
        assert_eq!(
            machine.next_deadline(),
            Some(now + config.t1),
            "the 2xx goes again T1 later unless its ACK arrives"
        );

        let absorbed = machine.on_request();
        assert!(absorbed.send.is_none(), "not answered again");
        assert!(absorbed.notify.is_none(), "and not passed up");

        // a fresh copy the user passes down goes on the wire, and the
        // machine stays where it is
        let again = machine.respond(response(200), now);
        assert!(again.send.is_some());
        assert_eq!(machine.state(), InviteServerState::Accepted);

        machine.on_ack(now);
        assert_eq!(machine.next_deadline(), Some(now + config.sixty_four_t1()));
        let (name, done) = machine
            .handle_timeout(now + config.sixty_four_t1())
            .expect("timer L");
        assert_eq!(name, TimerName::L);
        assert!(done.terminated);
    }

    #[test]
    fn a_2xx_goes_again_on_timer_g_until_its_ack_arrives() {
        // §13.3.1.4: "an interval that starts at T1 seconds and doubles for
        // each retransmission until it reaches T2 seconds ... Response
        // retransmissions cease when an ACK request for the response is
        // received"
        let (mut machine, _, now, config) = start(false);
        let sent = machine
            .respond(response(200), now)
            .send
            .map(|message| message.bytes().to_vec());
        let mut at = now;
        for gap in [
            config.t1,
            2 * config.t1,
            4 * config.t1,
            config.t2,
            config.t2,
        ] {
            at += gap;
            let (name, effects) = machine.handle_timeout(at).expect("timer G");
            assert_eq!(name, TimerName::G);
            assert_eq!(
                effects.send.map(|message| message.bytes().to_vec()),
                sent,
                "the same 2xx"
            );
        }
        machine.acknowledged_elsewhere();
        let (name, done) = machine
            .handle_timeout(now + config.sixty_four_t1())
            .expect("only timer L is left");
        assert_eq!(name, TimerName::L);
        assert_eq!(done.notify, None, "acknowledged, so nothing went wrong");

        // and over a reliable transport the transport sees to it
        let (mut machine, _, now, config) = start(true);
        machine.respond(response(200), now);
        assert_eq!(machine.next_deadline(), Some(now + config.sixty_four_t1()));
    }

    #[test]
    fn an_ack_after_a_2xx_belongs_to_the_dialog_and_is_passed_up() {
        // "Any ACKs received from the network while in the Accepted state
        // MUST be passed directly to the TU and not absorbed"
        let (mut machine, _, now, _) = start(false);
        machine.respond(response(200), now);
        let effects = machine.on_ack(now);
        assert_eq!(effects.notify, Some(Notify::Ack));
        assert!(!effects.terminated);
        assert_eq!(machine.state(), InviteServerState::Accepted);
    }

    #[test]
    fn a_2xx_that_is_never_acknowledged_says_so_when_the_wait_runs_out() {
        // 13.3.1.4: "If the UAS generates a 2xx response and never receives an
        // ACK, it SHOULD generate a BYE" — which needs somebody to be told
        let (mut machine, _, now, config) = start(false);
        machine.respond(response(200), now);
        let mut fired = Vec::new();
        let done = loop {
            let (name, effects) = machine
                .handle_timeout(now + config.sixty_four_t1())
                .expect("timer G until timer L");
            fired.push(name);
            if name == TimerName::L {
                break effects;
            }
        };
        assert!(fired.len() > 1, "{fired:?}: the 2xx went again first");
        assert_eq!(done.notify, Some(Notify::TimedOut));
        assert!(done.terminated);
    }

    #[test]
    fn one_that_is_acknowledged_ends_quietly() {
        let (mut machine, _, now, config) = start(false);
        machine.respond(response(200), now);
        machine.on_ack(now);
        let (_, done) = machine
            .handle_timeout(now + config.sixty_four_t1())
            .expect("timer L");
        assert_eq!(done.notify, None, "nothing went wrong");
        assert!(done.terminated);
    }

    #[test]
    fn a_final_response_that_is_not_a_2xx_is_retransmitted_by_timer_g() {
        let (mut machine, _, now, config) = start(false);
        machine.respond(response(486), now);
        assert_eq!(machine.state(), InviteServerState::Completed);
        assert_eq!(machine.next_deadline(), Some(now + config.t1));

        let mut at = now;
        for interval in [500_u64, 1000, 2000, 4000, 4000] {
            at += Duration::from_millis(interval);
            let (name, effects) = machine.handle_timeout(at).expect("timer G");
            assert_eq!(name, TimerName::G);
            assert_eq!(
                effects.send.expect("the response again").as_raw().status(),
                StatusCode::new(486).ok()
            );
        }
    }

    #[test]
    fn on_a_reliable_transport_the_final_response_is_sent_once() {
        // a change from RFC 2543, which retransmitted over TCP too
        let (mut machine, _, now, config) = start(true);
        machine.respond(response(486), now);
        assert_eq!(
            machine.next_deadline(),
            Some(now + config.sixty_four_t1()),
            "timer H only"
        );
    }

    #[test]
    fn an_ack_after_a_non_2xx_is_the_transactions_own() {
        let (mut machine, _, now, config) = start(false);
        machine.respond(response(486), now);
        let effects = machine.on_ack(now);
        assert!(effects.notify.is_none(), "the user does not need to see it");
        assert_eq!(machine.state(), InviteServerState::Confirmed);
        assert_eq!(machine.next_deadline(), Some(now + config.t4));

        // retransmissions of the response stop, and further ACKs are absorbed
        assert!(machine.on_ack(now).notify.is_none());
        let (name, done) = machine.handle_timeout(now + config.t4).expect("timer I");
        assert_eq!(name, TimerName::I);
        assert!(done.terminated);
    }

    #[test]
    fn timer_h_says_the_ack_never_came() {
        let (mut machine, _, now, _) = start(false);
        machine.respond(response(486), now);
        let mut last = None;
        let mut when = now;
        while let Some(at) = machine.next_deadline() {
            last = machine.handle_timeout(at);
            when = at;
        }
        let (name, effects) = last.expect("timer H");
        assert_eq!(name, TimerName::H);
        // §17.2.1: "timer H MUST be set to fire in 64*T1 seconds for all
        // transports" when the response takes the transaction to Completed;
        // 32 s at the default T1 of 500 ms
        assert_eq!(when - now, Duration::from_secs(32), "timer H fired then");
        assert_eq!(effects.notify, Some(Notify::TimedOut));
        assert!(effects.terminated);
        assert_eq!(machine.state(), InviteServerState::Terminated);
    }

    #[test]
    fn a_transport_error_does_not_throw_the_transaction_away() {
        // RFC 6026 8.2: the timers end it, not the error
        let (mut machine, _, now, _) = start(false);
        machine.respond(response(486), now);
        let effects = machine.on_transport_error();
        assert_eq!(effects.notify, Some(Notify::TransportFailed));
        assert!(!effects.terminated);
        assert_eq!(machine.state(), InviteServerState::Completed);
    }

    #[test]
    fn on_a_reliable_transport_the_ack_ends_it_at_once() {
        let (mut machine, _, now, _) = start(true);
        machine.respond(response(486), now);
        let effects = machine.on_ack(now);
        assert!(effects.terminated, "timer I is zero on TCP");
    }
}
