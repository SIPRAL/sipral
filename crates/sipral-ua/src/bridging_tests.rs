// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What an application bridging two calls needs to hear: a REFER of its own
//! refused (RFC 3515 §2.4.2), the far end's BYE whole, and a REFER taken
//! with a call it placed itself (§2.4.4, §2.4.5).

use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::msg::HeaderName;

use crate::agent::UserAgent;
use crate::call::{CallHandle, CallState};
use crate::error::UaError;
use crate::event::UaEvent;
use crate::tests::{
    ANSWER, OFFER, account, agent, answered, call_arriving, call_up, deliver, events, header,
    in_dialog, incoming_invite, outgoing, plus, reply, reversed, sent, transmits, uri,
};

fn done(agent: &mut UserAgent) -> Vec<(CallHandle, u16)> {
    events(agent)
        .into_iter()
        .filter_map(|event| match event {
            UaEvent::TransferDone { call, status } => Some((call, status.get())),
            _ => None,
        })
        .collect()
}

#[test]
fn a_refer_refused_outright_is_reported_once_and_the_call_stays() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);
    agent
        .transfer(call, &uri("sip:carol@example.com"), t0)
        .expect("the REFER goes");
    let refer = sent(&mut agent);
    deliver(&mut agent, &reply(&refer, 603, "Decline", ""), t0);
    assert_eq!(
        done(&mut agent),
        vec![(call, 603)],
        "§2.4.2: a refusal opens no subscription, so it is the only news"
    );
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
    // a retransmission of the same refusal is not a second outcome
    deliver(&mut agent, &reply(&refer, 603, "Decline", ""), t0);
    transmits(&mut agent);
    assert!(done(&mut agent).is_empty());
    // and the call is free to ask again
    agent
        .transfer(call, &uri("sip:dave@example.com"), t0)
        .expect("a second REFER goes after a refused one");
}

#[test]
fn a_refer_nobody_answers_is_reported_as_a_timeout() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);
    agent
        .transfer(call, &uri("sip:carol@example.com"), t0)
        .expect("the REFER goes");
    transmits(&mut agent);
    let mut at = t0;
    let mut outcomes = Vec::new();
    for _ in 0..80 {
        at += Duration::from_secs(1);
        agent.handle_timeout(at);
        transmits(&mut agent);
        outcomes.extend(done(&mut agent));
    }
    assert_eq!(outcomes, vec![(call, 408)]);
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

#[test]
fn a_refer_taken_is_not_reported_until_its_notify() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);
    agent
        .transfer(call, &uri("sip:carol@example.com"), t0)
        .expect("the REFER goes");
    let refer = sent(&mut agent);
    deliver(&mut agent, &reply(&refer, 202, "Accepted", ""), t0);
    assert!(done(&mut agent).is_empty());
}

#[test]
fn the_far_ends_bye_reaches_the_application_whole() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, ack) = call_up(&mut agent, id, t0);
    let bye = plus(
        &reversed(&ack, "BYE", "byeout", 1, None),
        "X-Sipral-Outcome: resolved\r\n",
    );
    deliver(&mut agent, &bye, t0);
    transmits(&mut agent);
    let request = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::CallEnded {
                call: ended,
                request,
                response,
                ..
            } if ended == call => {
                assert!(response.is_none());
                Some(request)
            }
            _ => None,
        })
        .expect("the call ended")
        .expect("with the BYE that ended it");
    assert_eq!(
        header(
            request.as_raw().as_bytes(),
            HeaderName::Extension("X-Sipral-Outcome")
        ),
        b"resolved"
    );
}

#[test]
fn a_call_this_end_hung_up_carries_no_request() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);
    agent.hangup(call, t0).expect("the BYE goes");
    let bye = sent(&mut agent);
    deliver(&mut agent, &reply(&bye, 200, "OK", ""), t0);
    let request = events(&mut agent)
        .into_iter()
        .find_map(|event| match event {
            UaEvent::CallEnded { request, .. } => Some(request),
            _ => None,
        });
    assert!(matches!(request, Some(None)), "{request:?}");
}

/// A call answered here, and a REFER arriving in it.
fn referred(agent: &mut UserAgent, branch: &str, now: Instant) -> CallHandle {
    let call = call_arriving(agent, &incoming_invite(branch, Some(OFFER)), now);
    agent
        .answer(call, Some(Arc::from(ANSWER)), now)
        .expect("200 goes");
    let ok = sent(agent);
    deliver(agent, &in_dialog(&ok, "ACK", &format!("{branch}ack"), 1), now);
    events(agent);
    let refer = plus(
        &in_dialog(&ok, "REFER", &format!("{branch}refer"), 2),
        "Refer-To: <sip:carol@example.com>\r\n",
    );
    deliver(agent, &refer, now);
    assert!(
        events(agent)
            .iter()
            .any(|event| matches!(event, UaEvent::TransferRequested { .. }))
    );
    call
}

/// Each NOTIFY written: its body and its `Subscription-State`.
fn sipfrags(written: &[Vec<u8>]) -> Vec<String> {
    written
        .iter()
        .filter(|bytes| bytes.starts_with(b"NOTIFY "))
        .map(|bytes| {
            let text = String::from_utf8_lossy(bytes).into_owned();
            let state = text
                .lines()
                .find(|line| line.starts_with("Subscription-State:"))
                .unwrap_or_default()
                .to_owned();
            let body = text
                .split("\r\n\r\n")
                .nth(1)
                .unwrap_or_default()
                .trim()
                .to_owned();
            format!("{body} | {state}")
        })
        .collect()
}

#[test]
fn a_refer_taken_with_a_call_of_the_applications_reports_that_call() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = referred(&mut agent, "own1", t0);

    let placed = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    agent
        .accept_transfer_placed(call, placed, t0)
        .expect("the REFER is taken");
    let written = transmits(&mut agent);
    assert!(
        written
            .iter()
            .any(|bytes| bytes.starts_with(b"SIP/2.0 202 ")),
        "§2.4.2's 202"
    );
    assert!(
        !written.iter().any(|bytes| bytes.starts_with(b"INVITE ")),
        "and no call of the stack's own"
    );
    let notes = sipfrags(&written);
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].starts_with("SIP/2.0 100 Trying | Subscription-State: active"),
        "{notes:?}"
    );

    deliver(
        &mut agent,
        &answered(&invite, 180, "Ringing", "carol", None),
        t0,
    );
    let notes = sipfrags(&transmits(&mut agent));
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].starts_with("SIP/2.0 180 Ringing | Subscription-State: active"),
        "{notes:?}"
    );

    deliver(
        &mut agent,
        &answered(&invite, 200, "OK", "carol", Some(ANSWER)),
        t0,
    );
    let notes = sipfrags(&transmits(&mut agent));
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].starts_with("SIP/2.0 200 OK | Subscription-State: terminated"),
        "{notes:?}"
    );
    assert_eq!(agent.call_state(placed), Some(CallState::Confirmed));
    assert_eq!(
        agent.call_state(call),
        Some(CallState::Confirmed),
        "the call the REFER came in is the application's to end"
    );
}

#[test]
fn a_call_already_answered_is_reported_at_once() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = referred(&mut agent, "own2", t0);
    let (placed, _ack) = call_up(&mut agent, id, t0);
    agent
        .accept_transfer_placed(call, placed, t0)
        .expect("the REFER is taken");
    let notes = sipfrags(&transmits(&mut agent));
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert!(
        notes[1].starts_with("SIP/2.0 200 OK | Subscription-State: terminated"),
        "{notes:?}"
    );
}

#[test]
fn a_call_that_fails_ends_the_subscription_with_its_refusal() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = referred(&mut agent, "own3", t0);
    let placed = agent.call(id, &outgoing(), t0).expect("the INVITE goes");
    let invite = sent(&mut agent);
    agent
        .accept_transfer_placed(call, placed, t0)
        .expect("the REFER is taken");
    transmits(&mut agent);
    deliver(
        &mut agent,
        &answered(&invite, 486, "Busy Here", "carol", None),
        t0,
    );
    let notes = sipfrags(&transmits(&mut agent));
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].starts_with("SIP/2.0 486 Busy Here | Subscription-State: terminated"),
        "{notes:?}"
    );
    assert_eq!(agent.call_state(call), Some(CallState::Confirmed));
}

#[test]
fn nothing_is_answered_until_the_placed_call_can_report() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let call = referred(&mut agent, "own4", t0);
    assert!(matches!(
        agent.accept_transfer_placed(call, call, t0),
        Err(UaError::WrongState(_))
    ));
    assert!(matches!(
        agent.accept_transfer_placed(call, CallHandle(0xdead), t0),
        Err(UaError::NoSuchCall)
    ));
    assert!(transmits(&mut agent).is_empty(), "the REFER still waits");
    let (placed, _ack) = call_up(&mut agent, id, t0);
    agent
        .accept_transfer_placed(call, placed, t0)
        .expect("the REFER is taken after the refusals");
    transmits(&mut agent);
    // and there is nothing left to take a second time
    let (other, _ack) = call_up(&mut agent, id, t0);
    assert!(matches!(
        agent.accept_transfer_placed(call, other, t0),
        Err(UaError::WrongState(_))
    ));
}

#[test]
fn a_call_with_no_refer_waiting_takes_nothing() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    let (call, _ack) = call_up(&mut agent, id, t0);
    let (placed, _ack) = call_up(&mut agent, id, t0);
    assert!(matches!(
        agent.accept_transfer_placed(call, placed, t0),
        Err(UaError::WrongState(_))
    ));
    assert!(transmits(&mut agent).is_empty());
}
