// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The non-INVITE client transaction (RFC 3261 §17.1.2).
//!
//! Everything a REGISTER, OPTIONS, BYE, MESSAGE or CANCEL runs on. Simpler
//! than the INVITE machine: no ACK, no `Accepted` state, and a final response
//! of any class does the same thing.
//!
//! Two differences from the INVITE machine are easy to miss.
//!
//! Retransmissions cap at T2 rather than doubling forever —
//! `MIN(2*T1, T2)`, then `MIN(4*T1, T2)` — which for the default values is
//! 500 ms, 1 s, 2 s, 4 s, 4 s, 4 s. T2 is "the amount of time a non-INVITE
//! server transaction will take to respond to a request, if it does not
//! respond immediately", so there is no point spacing them wider.
//!
//! And a provisional response does *not* stop the retransmissions. It moves
//! the machine to `Proceeding`, where timer E is reset to T2 flat and keeps
//! going, and timer F still ends the transaction. A non-INVITE request has to
//! finish; only an INVITE gets to ring indefinitely.

use std::time::Instant;

use super::super::msg::{OwnedMessage, RawMessage};
use super::effect::{Effects, Notify};
use super::handle::NonInviteClientState;
use super::timer::{TimerConfig, TimerName};

/// The machine.
#[derive(Debug)]
pub(crate) struct NonInviteClientMachine {
    state: NonInviteClientState,
    request: OwnedMessage,
    config: TimerConfig,
    reliable: bool,
    /// How many times the request has been retransmitted, which is what the
    /// doubling counts.
    attempt: u32,
    timer_e: Option<Instant>,
    timer_f: Option<Instant>,
    timer_k: Option<Instant>,
}

impl NonInviteClientMachine {
    /// Start the transaction: the request goes out, timer F starts, and timer
    /// E starts too unless the transport retransmits for us.
    pub(crate) fn start(
        request: OwnedMessage,
        reliable: bool,
        config: TimerConfig,
        now: Instant,
    ) -> (Self, Effects) {
        let machine = Self {
            state: NonInviteClientState::Trying,
            timer_e: (!reliable).then(|| now + config.retransmit(0, Some(config.t2))),
            timer_f: Some(now + config.sixty_four_t1()),
            timer_k: None,
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
    pub(crate) const fn state(&self) -> NonInviteClientState {
        self.state
    }

    /// The request as it went out, which a retry with credentials is built
    /// from.
    pub(crate) const fn request(&self) -> &OwnedMessage {
        &self.request
    }

    /// When the machine next needs the clock, if it does.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        [self.timer_e, self.timer_f, self.timer_k]
            .into_iter()
            .flatten()
            .min()
    }

    /// Fire whichever timer is due, earliest first.
    pub(crate) fn handle_timeout(&mut self, now: Instant) -> Option<(TimerName, Effects)> {
        let due = self.next_deadline().filter(|at| *at <= now)?;

        if self.timer_e == Some(due) {
            self.attempt = self.attempt.saturating_add(1);
            let interval = match self.state {
                // in Proceeding the interval is T2 flat: the server has said
                // it is working on it, so the doubling has done its job
                NonInviteClientState::Proceeding => self.config.t2,
                _ => self.config.retransmit(self.attempt, Some(self.config.t2)),
            };
            self.timer_e = Some(now + interval);
            return Some((
                TimerName::E,
                Effects {
                    send: Some(self.request.clone()),
                    ..Effects::default()
                },
            ));
        }
        if self.timer_f == Some(due) {
            self.terminate();
            return Some((
                TimerName::F,
                Effects {
                    notify: Some(Notify::TimedOut),
                    terminated: true,
                    ..Effects::default()
                },
            ));
        }
        if self.timer_k == Some(due) {
            self.terminate();
            return Some((
                TimerName::K,
                Effects {
                    terminated: true,
                    ..Effects::default()
                },
            ));
        }
        None
    }

    /// A response that has already been matched to this transaction.
    pub(crate) fn on_response(&mut self, response: &RawMessage<'_>, now: Instant) -> Effects {
        let Some(status) = response.status() else {
            return Effects::default();
        };
        match self.state {
            NonInviteClientState::Trying | NonInviteClientState::Proceeding => {
                if status.is_provisional() {
                    if self.state == NonInviteClientState::Trying {
                        self.state = NonInviteClientState::Proceeding;
                        // reset to T2 flat rather than cancelled: a non-INVITE
                        // request still has to finish
                        self.timer_e = self.timer_e.map(|_| now + self.config.t2);
                    }
                    return Effects {
                        notify: Some(Notify::Response),
                        ..Effects::default()
                    };
                }
                self.state = NonInviteClientState::Completed;
                self.timer_e = None;
                self.timer_f = None;
                let wait = self.config.t4_or_zero(self.reliable);
                self.timer_k = Some(now + wait);
                Effects {
                    notify: Some(Notify::Response),
                    // nothing retransmits on a reliable transport, so there is
                    // nothing for Completed to buffer
                    terminated: wait.is_zero(),
                    ..Effects::default()
                }
            }
            // Completed exists to swallow retransmissions of the response
            NonInviteClientState::Completed | NonInviteClientState::Terminated => {
                Effects::default()
            }
        }
    }

    /// The transport could not deliver the request.
    pub(crate) fn on_transport_error(&mut self) -> Effects {
        if self.state == NonInviteClientState::Terminated {
            return Effects::default();
        }
        self.terminate();
        Effects {
            notify: Some(Notify::TransportFailed),
            terminated: true,
            ..Effects::default()
        }
    }

    fn terminate(&mut self) {
        self.state = NonInviteClientState::Terminated;
        self.timer_e = None;
        self.timer_f = None;
        self.timer_k = None;
    }
}

#[cfg(test)]
mod tests {
    use super::NonInviteClientMachine;
    use crate::msg::{
        Method, OwnedMessage, ParseMode, ParseScratch, RequestBuilder, ResponseBuilder, StatusCode,
        parse,
    };
    use crate::transaction::{NonInviteClientState, TimerConfig, TimerName};
    use std::time::{Duration, Instant};

    fn options() -> OwnedMessage {
        RequestBuilder::new(Method::Options, b"sip:bob@example.com")
            .via(b"SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1")
            .max_forwards(70)
            .from(b"<sip:alice@example.com>;tag=1")
            .to(b"<sip:bob@example.com>")
            .call_id(b"a84b4c76e66710")
            .cseq(1)
            .build()
            .expect("an OPTIONS")
    }

    fn response(status: u16) -> OwnedMessage {
        let request = options();
        let mut scratch = ParseScratch::new();
        let parsed =
            parse(request.as_raw().as_bytes(), &mut scratch, ParseMode::Strict).expect("a request");
        ResponseBuilder::for_request(&parsed, StatusCode::new(status).expect("a status"))
            .to_tag(b"a6c85cf")
            .build()
            .expect("a response")
    }

    fn feed(
        machine: &mut NonInviteClientMachine,
        message: &OwnedMessage,
        now: Instant,
    ) -> super::Effects {
        let mut scratch = ParseScratch::new();
        let parsed = parse(message.as_raw().as_bytes(), &mut scratch, ParseMode::Strict)
            .expect("a response");
        machine.on_response(&parsed, now)
    }

    fn start(reliable: bool) -> (NonInviteClientMachine, Instant, TimerConfig) {
        let now = Instant::now();
        let config = TimerConfig::default();
        let (machine, effects) = NonInviteClientMachine::start(options(), reliable, config, now);
        assert!(effects.send.is_some());
        (machine, now, config)
    }

    #[test]
    fn the_retransmit_interval_caps_at_t2() {
        // "500 ms, 1 s, 2 s, 4 s, 4 s, 4 s, etc."
        let (mut machine, now, _) = start(false);
        let mut at = now;
        for interval in [500_u64, 1000, 2000, 4000, 4000, 4000] {
            at += Duration::from_millis(interval);
            assert_eq!(machine.next_deadline(), Some(at), "interval {interval} ms");
            let (name, effects) = machine.handle_timeout(at).expect("timer E");
            assert_eq!(name, TimerName::E);
            assert!(effects.send.is_some());
        }
        assert_eq!(machine.state(), NonInviteClientState::Trying);
    }

    #[test]
    fn a_provisional_response_does_not_stop_the_retransmissions() {
        // unlike the INVITE machine: a non-INVITE request has to finish
        let (mut machine, now, config) = start(false);
        let effects = feed(&mut machine, &response(100), now);
        assert!(effects.notify.is_some());
        assert_eq!(machine.state(), NonInviteClientState::Proceeding);
        assert_eq!(machine.next_deadline(), Some(now + config.t2));

        let at = now + config.t2;
        let (name, again) = machine.handle_timeout(at).expect("timer E");
        assert_eq!(name, TimerName::E);
        assert!(again.send.is_some());
        assert_eq!(machine.next_deadline(), Some(at + config.t2), "T2 flat");
    }

    #[test]
    fn timer_f_ends_it_from_either_open_state() {
        for provisional in [false, true] {
            let (mut machine, now, config) = start(true);
            if provisional {
                feed(&mut machine, &response(100), now);
            }
            let (name, effects) = machine
                .handle_timeout(now + config.sixty_four_t1())
                .expect("timer F");
            assert_eq!(name, TimerName::F);
            assert!(effects.terminated);
            assert_eq!(machine.state(), NonInviteClientState::Terminated);
        }
    }

    #[test]
    fn a_final_response_of_any_class_completes_it() {
        for status in [200_u16, 404, 500, 603] {
            let (mut machine, now, config) = start(false);
            let effects = feed(&mut machine, &response(status), now);
            assert!(effects.notify.is_some(), "{status} goes up");
            assert!(effects.send.is_none(), "a non-INVITE client never ACKs");
            assert_eq!(machine.state(), NonInviteClientState::Completed);
            assert_eq!(machine.next_deadline(), Some(now + config.t4));
        }
    }

    #[test]
    fn completed_swallows_the_retransmissions_it_exists_for() {
        let (mut machine, now, config) = start(false);
        feed(&mut machine, &response(404), now);
        let again = feed(&mut machine, &response(404), now + Duration::from_secs(1));
        assert_eq!(again.notify, None);
        assert!(again.send.is_none());

        let (name, done) = machine.handle_timeout(now + config.t4).expect("timer K");
        assert_eq!(name, TimerName::K);
        assert!(done.terminated);
    }

    #[test]
    fn on_a_reliable_transport_there_is_nothing_to_buffer() {
        let (mut machine, now, _) = start(true);
        assert_eq!(machine.next_deadline(), Some(now + Duration::from_secs(32)));
        let effects = feed(&mut machine, &response(200), now);
        assert!(effects.terminated, "timer K is zero on TCP");
    }

    #[test]
    fn a_transport_error_ends_it() {
        let (mut machine, _, _) = start(false);
        let effects = machine.on_transport_error();
        assert!(effects.terminated);
        assert_eq!(machine.state(), NonInviteClientState::Terminated);
    }
}
