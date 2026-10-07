// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The non-INVITE server transaction (RFC 3261 §17.2.2).
//!
//! One timer, no ACK, no automatic response. In `Trying` a retransmitted
//! request is discarded: there is nothing to answer with yet, and a made-up
//! 100 would be a response the user never wrote.
//!
//! In `Completed` the final response is resent for every retransmission until
//! timer J, and anything else the user sends is discarded.

use std::time::Instant;

use super::super::msg::OwnedMessage;
use super::effect::Effects;
use super::handle::NonInviteServerState;
use super::timer::{TimerConfig, TimerName};

/// The machine.
#[derive(Debug)]
pub(crate) struct NonInviteServerMachine {
    state: NonInviteServerState,
    /// The last thing sent, which is what a retransmitted request gets back.
    last_response: Option<OwnedMessage>,
    config: TimerConfig,
    reliable: bool,
    timer_j: Option<Instant>,
}

impl NonInviteServerMachine {
    /// Take the request. Nothing is sent: the user decides what to say.
    pub(crate) const fn start(reliable: bool, config: TimerConfig) -> Self {
        Self {
            state: NonInviteServerState::Trying,
            last_response: None,
            config,
            reliable,
            timer_j: None,
        }
    }

    /// Which state the machine is in.
    pub(crate) const fn state(&self) -> NonInviteServerState {
        self.state
    }

    /// When the machine next needs the clock, if it does.
    pub(crate) const fn next_deadline(&self) -> Option<Instant> {
        self.timer_j
    }

    /// The user has a response to send.
    pub(crate) fn respond(&mut self, response: OwnedMessage, now: Instant) -> Effects {
        let Some(status) = response.as_raw().status() else {
            return Effects::default();
        };
        match self.state {
            NonInviteServerState::Trying | NonInviteServerState::Proceeding => {
                self.last_response = Some(response.clone());
                if status.is_provisional() {
                    self.state = NonInviteServerState::Proceeding;
                    return Effects {
                        send: Some(response),
                        ..Effects::default()
                    };
                }
                self.state = NonInviteServerState::Completed;
                let wait = self.config.j(self.reliable);
                self.timer_j = Some(now + wait);
                Effects {
                    send: Some(response),
                    // reliable transport: no reason to sit in Completed
                    terminated: wait.is_zero(),
                    ..Effects::default()
                }
            }
            // "Any other final responses passed by the TU to the server
            // transaction MUST be discarded while in the Completed state"
            NonInviteServerState::Completed | NonInviteServerState::Terminated => {
                Effects::default()
            }
        }
    }

    /// A retransmission of the request arrived.
    pub(crate) fn on_request(&self) -> Effects {
        match self.state {
            // "Once in the Trying state, any further request retransmissions
            // are discarded"
            NonInviteServerState::Trying | NonInviteServerState::Terminated => Effects::default(),
            NonInviteServerState::Proceeding | NonInviteServerState::Completed => Effects {
                send: self.last_response.clone(),
                ..Effects::default()
            },
        }
    }

    /// Fire timer J, if it is due.
    pub(crate) fn handle_timeout(&mut self, now: Instant) -> Option<(TimerName, Effects)> {
        self.timer_j.filter(|at| *at <= now)?;
        self.state = NonInviteServerState::Terminated;
        self.timer_j = None;
        Some((TimerName::J, Effects::terminated()))
    }
}

#[cfg(test)]
mod tests {
    use super::NonInviteServerMachine;
    use crate::msg::{OwnedMessage, ParseMode, ParseScratch, ResponseBuilder, StatusCode, parse};
    use crate::transaction::{NonInviteServerState, TimerConfig, TimerName};
    use std::time::Instant;

    const OPTIONS: &[u8] = b"OPTIONS sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\
\r\n";

    fn response(status: u16) -> OwnedMessage {
        let mut scratch = ParseScratch::new();
        let request = parse(OPTIONS, &mut scratch, ParseMode::Strict).expect("the request");
        ResponseBuilder::for_request(&request, StatusCode::new(status).expect("a status"))
            .to_tag(b"a6c85cf")
            .build()
            .expect("a response")
    }

    fn start(reliable: bool) -> (NonInviteServerMachine, Instant, TimerConfig) {
        let config = TimerConfig::default();
        (
            NonInviteServerMachine::start(reliable, config),
            Instant::now(),
            config,
        )
    }

    #[test]
    fn nothing_goes_out_until_the_user_says_so() {
        let (machine, _, _) = start(false);
        assert_eq!(machine.state(), NonInviteServerState::Trying);
        assert_eq!(machine.next_deadline(), None);
        assert!(
            machine.on_request().send.is_none(),
            "a retransmission in Trying is discarded, not answered"
        );
    }

    #[test]
    fn a_provisional_response_makes_retransmissions_worth_answering() {
        let (mut machine, now, _) = start(false);
        let effects = machine.respond(response(100), now);
        assert!(effects.send.is_some());
        assert_eq!(machine.state(), NonInviteServerState::Proceeding);

        let echoed = machine.on_request().send.expect("the provisional again");
        assert_eq!(echoed.as_raw().status(), StatusCode::new(100).ok());
        assert_eq!(
            machine.next_deadline(),
            None,
            "provisionals are not retried"
        );
    }

    #[test]
    fn a_final_response_completes_it_and_is_re_sent_on_every_retransmission() {
        let (mut machine, now, config) = start(false);
        let effects = machine.respond(response(200), now);
        assert!(effects.send.is_some());
        assert!(!effects.terminated);
        assert_eq!(machine.state(), NonInviteServerState::Completed);
        assert_eq!(machine.next_deadline(), Some(now + config.sixty_four_t1()));

        for _ in 0..3 {
            let echoed = machine.on_request().send.expect("the final again");
            assert_eq!(echoed.as_raw().status(), StatusCode::new(200).ok());
        }

        let (name, done) = machine
            .handle_timeout(now + config.sixty_four_t1())
            .expect("timer J");
        assert_eq!(name, TimerName::J);
        assert!(done.terminated);
        assert_eq!(machine.state(), NonInviteServerState::Terminated);
    }

    #[test]
    fn a_second_final_response_is_discarded() {
        // the answer has been given
        let (mut machine, now, _) = start(false);
        machine.respond(response(200), now);
        let late = machine.respond(response(500), now);
        assert!(late.send.is_none());
        let echoed = machine.on_request().send.expect("the first answer");
        assert_eq!(echoed.as_raw().status(), StatusCode::new(200).ok());
    }

    #[test]
    fn on_a_reliable_transport_it_is_done_when_the_answer_is_out() {
        let (mut machine, now, _) = start(true);
        let effects = machine.respond(response(404), now);
        assert!(effects.send.is_some());
        assert!(effects.terminated, "timer J is zero on TCP");
    }

    #[test]
    fn nothing_fires_before_timer_j() {
        let (mut machine, now, config) = start(false);
        machine.respond(response(200), now);
        assert!(machine.handle_timeout(now).is_none());
        assert!(
            machine
                .handle_timeout(now + config.sixty_four_t1())
                .is_some()
        );
    }
}
