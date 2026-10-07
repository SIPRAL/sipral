// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Asking an account's server whether it is there, without registering and
//! without calling anybody: an `OPTIONS` (RFC 3261 §11) on the account's own
//! transport, timed.
//!
//! Any final response proves the path works and is reported as it came. A
//! 401 or 407 is not answered: spending a challenge could count against the
//! account on a server that locks accounts after failures.
//!
//! The request goes to the registrar's URI, or the address of record for an
//! unregistered account, via the account's destination
//! ([`Account::destination`](crate::Account)): the same path as a REGISTER or
//! an INVITE.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use sipral_core::dialog::CallId;
use sipral_core::endpoint::{Event, FailureReason, OutgoingRequest};
use sipral_core::msg::{Method, StatusCode};
use sipral_core::transaction::AnyTransactionId;

use crate::account::AccountId;
use crate::agent::UserAgent;
use crate::error::UaError;
use crate::event::UaEvent;

/// One probe of an account's server, named before the request is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProbeHandle(pub(crate) u32);

/// What became of a probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The server answered with a final `status` after `round_trip`
    /// (retransmissions included).
    Answered {
        /// The final status, whatever it was.
        status: StatusCode,
        /// From sending to the answer.
        round_trip: Duration,
    },
    /// Nothing answered before the transaction timed out (§17.1.2.2's
    /// Timer F, 32 seconds unless the endpoint was told otherwise).
    TimedOut,
    /// The transport refused the request, or failed under it.
    TransportFailed,
}

/// The probes this agent has sent and not reported.
#[derive(Debug, Default)]
pub(crate) struct Probes {
    next: u32,
    pending: HashMap<AnyTransactionId, (ProbeHandle, AccountId, Instant)>,
    /// Probes answered with a challenge, whose `Challenged` the endpoint
    /// raises after the response: taken here so nothing else answers it.
    challenged: HashSet<AnyTransactionId>,
}

impl UserAgent {
    /// Send an `OPTIONS` to `account`'s server on the account's own
    /// transport. The answer, or the absence of one, arrives as
    /// [`UaEvent::ServerProbed`] under the handle returned.
    ///
    /// # Errors
    ///
    /// [`UaError::NoSuchAccount`]; [`UaError::NotLocated`] for an account
    /// whose server has not been located yet; [`UaError::Send`] when the
    /// request could not be built or handed over.
    pub fn probe_server(
        &mut self,
        account: AccountId,
        now: Instant,
    ) -> Result<ProbeHandle, UaError> {
        let config = self.accounts.get(&account).ok_or(UaError::NoSuchAccount)?;
        let (transport, remote) = config.destination().ok_or(UaError::NotLocated)?;
        let target = config
            .registrar
            .clone()
            .unwrap_or_else(|| config.aor.clone());
        let mut to = Vec::with_capacity(target.as_bytes().len() + 2);
        to.push(b'<');
        to.extend_from_slice(target.as_bytes());
        to.push(b'>');
        let call_id = CallId::new(&self.endpoint.token());
        let request = OutgoingRequest::new(Method::Options, target, transport, remote)
            .to(&to)
            .from(&config.sender_value())
            .call_id(call_id);
        let id = self.endpoint.request(&request, now)?;
        let handle = ProbeHandle(self.probes.next);
        self.probes.next = self.probes.next.wrapping_add(1);
        self.probes.pending.insert(
            AnyTransactionId::NonInviteClient(id),
            (handle, account, now),
        );
        self.drain(now);
        Ok(handle)
    }

    /// `None` when the event was about a probe and has been dealt with.
    pub(crate) fn on_probe_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        match event {
            Event::Response {
                transaction,
                status,
                ..
            } => {
                let key = AnyTransactionId::NonInviteClient(transaction);
                if !self.probes.pending.contains_key(&key) {
                    return Some(event);
                }
                if status.is_provisional() {
                    return None;
                }
                if matches!(status.get(), 401 | 407) {
                    self.probes.challenged.insert(key);
                }
                let (probe, account, sent) = self.probes.pending.remove(&key)?;
                self.events.push_back(UaEvent::ServerProbed {
                    probe,
                    account,
                    outcome: ProbeOutcome::Answered {
                        status,
                        round_trip: now.saturating_duration_since(sent),
                    },
                });
                None
            }
            Event::RequestFailed {
                transaction,
                reason,
            } => {
                let key = AnyTransactionId::NonInviteClient(transaction);
                let Some((probe, account, _)) = self.probes.pending.remove(&key) else {
                    return Some(event);
                };
                let outcome = match reason {
                    FailureReason::TransportFailed => ProbeOutcome::TransportFailed,
                    _ => ProbeOutcome::TimedOut,
                };
                self.events.push_back(UaEvent::ServerProbed {
                    probe,
                    account,
                    outcome,
                });
                None
            }
            Event::Challenged { transaction, .. } | Event::TokenChallenged { transaction, .. }
                if self.probes.challenged.remove(&transaction) =>
            {
                self.endpoint.abandon_challenge(transaction);
                None
            }
            other => Some(other),
        }
    }

    /// A challenge the endpoint did not raise for a probe it answered is not
    /// waited for past the drain that brought the answer.
    pub(crate) fn settle_probe_challenges(&mut self) {
        self.probes.challenged.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use sipral_core::msg::StatusCode;

    use super::ProbeOutcome;
    use crate::UaEvent;
    use crate::tests::{account, agent, deliver, events, reply, sent, transmits};

    fn probed(seen: &[UaEvent]) -> Vec<ProbeOutcome> {
        seen.iter()
            .filter_map(|event| match event {
                UaEvent::ServerProbed { outcome, .. } => Some(*outcome),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn an_options_goes_to_the_registrar_and_its_answer_is_timed() {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(account());
        let probe = agent.probe_server(id, t0).expect("the OPTIONS goes");
        let request = sent(&mut agent);
        let text = String::from_utf8_lossy(&request);
        assert!(text.starts_with("OPTIONS sip:"), "{text}");
        let later = t0 + Duration::from_millis(42);
        deliver(&mut agent, &reply(&request, 200, "OK", ""), later);
        let seen = events(&mut agent);
        assert_eq!(
            probed(&seen),
            [ProbeOutcome::Answered {
                status: StatusCode::OK,
                round_trip: Duration::from_millis(42),
            }]
        );
        assert!(seen.iter().any(|event| matches!(
            event,
            UaEvent::ServerProbed { probe: p, account, .. } if *p == probe && *account == id
        )));
    }

    #[test]
    fn a_challenge_is_a_server_that_is_there_and_is_not_answered() {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(account());
        agent.probe_server(id, t0).expect("the OPTIONS goes");
        let request = sent(&mut agent);
        deliver(
            &mut agent,
            &reply(
                &request,
                401,
                "Unauthorized",
                "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"abc\"\r\n",
            ),
            t0,
        );
        assert!(
            transmits(&mut agent).is_empty(),
            "no credentials spent on it"
        );
        let seen = events(&mut agent);
        assert!(matches!(
            probed(&seen)[..],
            [ProbeOutcome::Answered { status, .. }] if status.get() == 401
        ));
        assert!(
            !seen.iter().any(|event| matches!(
                event,
                UaEvent::ChallengeDeclined { .. } | UaEvent::Unclaimed(_)
            )),
            "the challenge was the probe's, and nothing else heard of it: {seen:?}"
        );
    }

    #[test]
    fn a_server_that_never_answers_is_reported_timed_out() {
        let t0 = Instant::now();
        let mut agent = agent(t0);
        let id = agent.add_account(account());
        agent.probe_server(id, t0).expect("the OPTIONS goes");
        let _ = sent(&mut agent);
        let mut now = t0;
        for _ in 0..80 {
            now += Duration::from_millis(500);
            agent.handle_timeout(now);
        }
        assert_eq!(probed(&events(&mut agent)), [ProbeOutcome::TimedOut]);
    }
}
