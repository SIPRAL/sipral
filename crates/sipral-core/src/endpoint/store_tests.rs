// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What a peer can make the transaction and dialog stores hold, and what it
//! can make them believe.
//!
//! Every test here is one way a message from outside reaches a store: an entry
//! it creates, an entry it is matched to, or an entry it should have ended.

use super::tests::{deliver, endpoint, events, header, incoming, sent, transmits, with};
use super::{DialogEndReason, Endpoint, Event, OutgoingResponse, SendError};
use crate::dialog::DialogState;
use crate::msg::{HeaderName, StatusCode};
use crate::transaction::{DialogId, InviteServer, TransactionId};
use std::time::Instant;

/// An incoming call answered with a 180: its transaction, the early dialog
/// the 180 opened, and the tag this end put in `To`.
fn rung(
    endpoint: &mut Endpoint,
    request: &[u8],
    now: Instant,
) -> (TransactionId<InviteServer>, DialogId, String) {
    deliver(endpoint, request, now);
    transmits(endpoint);
    let transaction = events(endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingInvite { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("an incoming call");
    let dialog = endpoint
        .respond_invite(
            transaction,
            &OutgoingResponse::new(StatusCode::RINGING).contact(b"<sip:alice@192.0.2.1>"),
            now,
        )
        .expect("the 180 goes")
        .expect("an early dialog");
    let ringing = sent(endpoint);
    let to = String::from_utf8_lossy(&header(&ringing, HeaderName::To)).into_owned();
    let tag = to
        .rsplit(";tag=")
        .next()
        .expect("a tag on the 180")
        .to_owned();
    events(endpoint);
    (transaction, dialog, tag)
}

// -- ACK ---------------------------------------------------------------------

#[test]
fn an_ack_for_a_2xx_that_was_never_sent_confirms_nothing() {
    // §13.3.1.4: the ACK a UAS waits for is the one "for the response", and
    // an early dialog has had no 2xx to acknowledge. The tag it names went out
    // in the 180, so anyone who saw the 180 can write this ACK.
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, dialog, tag) = rung(&mut endpoint, &incoming("INVITE", "early", ""), t0);

    let ack = format!(
        "ACK sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKearlyack;rport\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bobtag\r\n\
To: Alice <sip:alice@192.0.2.1>;tag={tag}\r\n\
Call-ID: incoming-1\r\n\
CSeq: 1 ACK\r\n\
Content-Length: 0\r\n\
\r\n"
    );
    deliver(&mut endpoint, ack.as_bytes(), t0);

    let events = events(&mut endpoint);
    assert!(
        !events
            .iter()
            .any(|event| matches!(*event, Event::IncomingAck { .. })),
        "the call was reported up before anyone answered it: {events:?}"
    );
    assert_eq!(
        endpoint.dialog(dialog).map(|snapshot| snapshot.state),
        Some(DialogState::Early),
        "an ACK moved a dialog no 2xx had confirmed"
    );
}

// -- an early dialog ends with the INVITE that opened it ---------------------

/// Whether `events` ended `dialog` because the INVITE that opened it was
/// refused, and where in the list that was.
fn refused_at(events: &[Event], dialog: DialogId) -> Option<usize> {
    events.iter().position(|event| {
        matches!(
            event,
            Event::DialogTerminated { dialog: ended, reason: DialogEndReason::Refused }
                if *ended == dialog
        )
    })
}

#[test]
fn a_call_cancelled_while_it_rings_takes_its_early_dialog_with_it() {
    // §12.3: "if a request outside of a dialog generates a non-2xx final
    // response, any early dialogs created through provisional responses to
    // that request are terminated" -- and a 487 is one
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, dialog, _) = rung(&mut endpoint, &incoming("INVITE", "cancelled", ""), t0);

    deliver(&mut endpoint, &incoming("CANCEL", "cancelled", ""), t0);
    let events = events(&mut endpoint);
    let ended = refused_at(&events, dialog).expect("the early dialog is still standing");
    let cancelled = events
        .iter()
        .position(|event| matches!(*event, Event::IncomingCancel { .. }))
        .expect("the CANCEL is reported");
    assert!(
        cancelled < ended,
        "the dialog ended before the caller heard why: {events:?}"
    );
    assert_eq!(endpoint.in_flight().1, 0);
    assert!(endpoint.dialog(dialog).is_none());
}

#[test]
fn a_call_refused_after_it_rang_takes_its_early_dialog_with_it() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (transaction, dialog, _) = rung(&mut endpoint, &incoming("INVITE", "busy", ""), t0);

    endpoint
        .respond_invite(
            transaction,
            &OutgoingResponse::new(StatusCode::new(486).expect("486")),
            t0,
        )
        .expect("the 486 goes");
    assert!(
        refused_at(&events(&mut endpoint), dialog).is_some(),
        "the early dialog is still standing"
    );
    assert_eq!(endpoint.in_flight().1, 0);
}

#[test]
fn calls_that_ring_and_are_cancelled_do_not_use_up_the_dialog_ceiling() {
    // the flood this is about costs a peer an INVITE and a CANCEL per round,
    // and used to leave an early dialog behind every time: at the ceiling
    // every call after that was refused with a 503 for the life of the process
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.config.max_dialogs = 2;
    // a distinct Call-ID per round, as a genuine second call would carry one:
    // §8.2.2.2 answers a request that repeats another ongoing transaction's
    // From tag, Call-ID and CSeq under a different branch with 482 rather
    // than a new call, and `incoming`'s fixed Call-ID would make round 2 look
    // like a forked copy of round 1's still-lingering (cancelled but not yet
    // timed out) transaction rather than the separate call this test is about
    for round in 1..=2 {
        rung(&mut endpoint, &stranger_with(round, "INVITE", ""), t0);
        deliver(&mut endpoint, &stranger_with(round, "CANCEL", ""), t0);
        transmits(&mut endpoint);
        events(&mut endpoint);
    }

    deliver(&mut endpoint, &stranger_with(3, "INVITE", ""), t0);
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::IncomingInvite { .. })),
        "a call was turned away with no call standing"
    );
    assert_eq!(endpoint.refused(), 0);
}

#[test]
fn a_call_whose_invite_names_a_dialog_nobody_has_still_loses_its_early_dialog() {
    // §12.2.2 lets a UAS take a request whose To tag matches no dialog as a new
    // one, and this endpoint does. A tag in that INVITE says nothing about
    // whether it created the early dialog, and a peer that adds one to every
    // INVITE it floods must not keep what the refusal ends.
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let named = |method: &str| {
        String::from_utf8_lossy(&stranger_with(7, method, ""))
            .replace(
                "To: Alice <sip:alice@192.0.2.1>\r\n",
                "To: Alice <sip:alice@192.0.2.1>;tag=nosuchdialog\r\n",
            )
            .into_bytes()
    };
    let (_, dialog, _) = rung(&mut endpoint, &named("INVITE"), t0);

    deliver(&mut endpoint, &named("CANCEL"), t0);
    assert!(
        refused_at(&events(&mut endpoint), dialog).is_some(),
        "the early dialog is still standing"
    );
    assert_eq!(endpoint.in_flight().1, 0);
}

#[test]
fn a_refused_reinvite_inside_an_early_dialog_leaves_it_standing() {
    // §12.3 ends the early dialog when the request that created it is
    // refused, not when a request inside it is
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, dialog, tag) = rung(&mut endpoint, &incoming("INVITE", "opened", ""), t0);

    let inside = format!(
        "INVITE sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKinside;rport\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bobtag\r\n\
To: Alice <sip:alice@192.0.2.1>;tag={tag}\r\n\
Call-ID: incoming-1\r\n\
CSeq: 2 INVITE\r\n\
Contact: <sip:bob@192.0.2.9>\r\n\
Content-Length: 0\r\n\
\r\n"
    );
    deliver(&mut endpoint, inside.as_bytes(), t0);
    transmits(&mut endpoint);
    let transaction = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingReinvite { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("the request inside the dialog");

    endpoint
        .respond_invite(
            transaction,
            &OutgoingResponse::new(StatusCode::new(488).expect("488")),
            t0,
        )
        .expect("the 488 goes");
    assert!(refused_at(&events(&mut endpoint), dialog).is_none());
    assert_eq!(
        endpoint.dialog(dialog).map(|snapshot| snapshot.state),
        Some(DialogState::Early)
    );
}

#[test]
fn a_call_given_up_on_for_want_of_a_prack_takes_its_early_dialog_with_it() {
    // RFC 3262 §3 refuses the INVITE with a 5xx once 64*T1 pass without a
    // PRACK, and that refusal ends what the reliable 180 opened
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    deliver(
        &mut endpoint,
        &incoming("INVITE", "unpracked", "Supported: 100rel\r\n"),
        t0,
    );
    transmits(&mut endpoint);
    let transaction = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingInvite { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("an incoming call");
    let provisional = endpoint
        .respond_reliable(transaction, &OutgoingResponse::new(StatusCode::RINGING), t0)
        .expect("the 180 goes reliably");
    transmits(&mut endpoint);
    events(&mut endpoint);

    endpoint.handle_timeout(t0 + crate::transaction::TimerConfig::DEFAULT.sixty_four_t1());
    assert!(
        refused_at(&events(&mut endpoint), provisional.dialog()).is_some(),
        "the early dialog is still standing"
    );
    assert_eq!(endpoint.in_flight().1, 0);
}

// -- ten thousand live transactions -------------------------------------------

#[test]
fn ten_thousand_calls_whose_timers_fire_at_once_cost_two_sweeps_and_no_more() {
    // The bound the timers are held to: finding the next deadline visits each
    // transaction slot once, handle_timeout sweeps the slots at most twice
    // (once for what is due, once to see that firing it made nothing else due
    // at the same instant), and retiring a transaction visits nothing that is
    // not its own call. Counted in slots visited rather than timed, so that a
    // loaded machine can make this slow but can never make it fail.
    const CALLS: usize = 10_000;
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.config.max_dialogs = CALLS;
    for _ in 0..CALLS {
        let invite = placed(&mut endpoint, t0);
        deliver(
            &mut endpoint,
            &super::tests::respond_to(&invite, 200, "OK", Some("desk")),
            t0,
        );
        events(&mut endpoint);
        transmits(&mut endpoint);
    }
    assert_eq!(
        endpoint.in_flight(),
        (CALLS, CALLS),
        "every call answered, and every INVITE waiting out timer M"
    );
    let slots = u64::try_from(CALLS).expect("a count that fits");
    let timer_m = t0 + crate::transaction::TimerConfig::DEFAULT.sixty_four_t1();

    crate::transaction::slab::take_visits();
    assert_eq!(endpoint.poll_timeout(), Some(timer_m));
    assert_eq!(
        crate::transaction::slab::take_visits(),
        slots,
        "finding the next deadline"
    );

    let just_before = timer_m
        .checked_sub(std::time::Duration::from_millis(1))
        .expect("an instant before timer M");
    endpoint.handle_timeout(just_before);
    assert_eq!(
        crate::transaction::slab::take_visits(),
        slots,
        "an instant at which nothing is due is one sweep"
    );

    endpoint.handle_timeout(timer_m);
    let visits = crate::transaction::slab::take_visits();
    assert_eq!(
        endpoint.in_flight(),
        (0, CALLS),
        "timer M ended every INVITE transaction and none of the calls"
    );
    assert!(
        visits <= 2 * slots,
        "retiring {CALLS} transactions at one instant visited {visits} slots"
    );
}

// -- one key, one transaction ---------------------------------------------------

#[test]
fn asking_to_cancel_twice_puts_one_cancel_on_the_wire() {
    // §17.1.3 finds a response's transaction by the branch and the CSeq
    // method, and a second CANCEL for one INVITE carries both of the first's.
    // Two of them in the store under one key left the first unreachable: its
    // 200 went to the second, and it retransmitted until timer F reported a
    // CANCEL that had been answered as failed.
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let invite = endpoint
        .invite(&super::tests::invite_request(), t0)
        .expect("the INVITE goes");
    let bytes = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &super::tests::respond_to(&bytes, 180, "Ringing", Some("desk")),
        t0,
    );
    events(&mut endpoint);

    endpoint.cancel(invite, t0).expect("the CANCEL goes");
    endpoint
        .cancel(invite, t0)
        .expect("asking again is not an error");
    let cancels: Vec<Vec<u8>> = transmits(&mut endpoint)
        .into_iter()
        .map(|transmit| transmit.payload.to_vec())
        .filter(|payload| payload.starts_with(b"CANCEL "))
        .collect();
    assert_eq!(cancels.len(), 1, "one INVITE, two CANCELs on the wire");
    let cancel = cancels.first().expect("the CANCEL");

    deliver(
        &mut endpoint,
        &super::tests::respond_to(cancel, 200, "OK", Some("desk")),
        t0,
    );
    events(&mut endpoint);
    endpoint.handle_timeout(t0 + crate::transaction::TimerConfig::DEFAULT.sixty_four_t1());
    assert!(
        !transmits(&mut endpoint)
            .iter()
            .any(|transmit| transmit.payload.starts_with(b"CANCEL ")),
        "a CANCEL that was answered went out again"
    );
    assert!(
        !events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::RequestFailed { .. })),
        "a CANCEL that was answered was reported as failed"
    );
}

// -- a CANCEL is matched to the INVITE it cancels, and to nothing else ----------

#[test]
fn a_cancel_that_arrives_after_the_call_was_answered_is_not_reported_as_one() {
    // §9.2: once a final response has gone out, "the CANCEL request has no
    // effect on the processing of the original request, no effect on any
    // session state, and no effect on the responses generated for the
    // original request". IncomingCancel says the 487 went out and the caller
    // gave up, and the layer above ends the call when it hears it.
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let transaction = let_in(&mut endpoint, &stranger(3), t0).expect("a call");
    let dialog = endpoint
        .respond_invite(
            transaction,
            &OutgoingResponse::new(StatusCode::OK).contact(b"<sip:alice@192.0.2.1>"),
            t0,
        )
        .expect("the 200 goes")
        .expect("a dialog");
    transmits(&mut endpoint);
    events(&mut endpoint);

    deliver(&mut endpoint, &stranger_with(3, "CANCEL", ""), t0);
    let statuses: Vec<_> = transmits(&mut endpoint)
        .iter()
        .map(|transmit| {
            super::tests::with(&transmit.payload, |message| {
                message.status().map(StatusCode::get)
            })
        })
        .collect();
    assert_eq!(statuses, [Some(200)], "only the CANCEL is answered");
    let events = events(&mut endpoint);
    assert!(
        !events
            .iter()
            .any(|event| matches!(*event, Event::IncomingCancel { .. })),
        "a call that is up was reported cancelled: {events:?}"
    );
    assert_eq!(
        endpoint.dialog(dialog).map(|snapshot| snapshot.state),
        Some(DialogState::Confirmed)
    );
}

#[test]
fn a_cancel_that_matches_no_call_is_answered_481() {
    // §9.2: "If the UAS did not find a matching transaction for the CANCEL
    // according to the procedure above, it SHOULD respond to the CANCEL with
    // a 481"; the 200 is for a CANCEL that "matched an existing transaction"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    deliver(&mut endpoint, &stranger_with(4, "CANCEL", ""), t0);
    let answer = sent(&mut endpoint);
    assert!(
        answer.starts_with(b"SIP/2.0 481 "),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert!(
        !events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::IncomingCancel { .. }))
    );
}

// -- a fork opens no more dialogs than there is room for ----------------------

/// Place a call and hand back the INVITE as it went out.
fn placed(endpoint: &mut Endpoint, now: Instant) -> Vec<u8> {
    endpoint
        .invite(&super::tests::invite_request(), now)
        .expect("the INVITE goes");
    sent(endpoint)
}

#[test]
fn a_fork_opens_no_more_dialogs_than_the_ceiling_has_room_for() {
    // Every distinct To tag that answers one INVITE is a dialog of its own
    // (§13.2.2), and whoever can answer the INVITE decides how many tags that
    // is. Nothing held the number to max_dialogs.
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.config.max_dialogs = 2;
    let invite = placed(&mut endpoint, t0);
    for branch in 0..6 {
        let tag = format!("fork{branch}");
        deliver(
            &mut endpoint,
            &super::tests::respond_to(&invite, 180, "Ringing", Some(&tag)),
            t0,
        );
    }
    // the first answer is the call's, and opens; a second is a branch the
    // far end multiplied, and finds no room
    for tag in ["late", "later"] {
        deliver(
            &mut endpoint,
            &super::tests::respond_to(&invite, 200, "OK", Some(tag)),
            t0,
        );
    }

    let events = events(&mut endpoint);
    let ringing = events
        .iter()
        .filter(|event| matches!(**event, Event::Provisional { .. }))
        .count();
    let opened = events
        .iter()
        .filter(|event| {
            matches!(
                **event,
                Event::Provisional {
                    dialog: Some(_),
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        endpoint.in_flight().1,
        3,
        "one INVITE made more dialogs than the ceiling and its answer"
    );
    assert_eq!(ringing, 6, "every provisional is still reported");
    assert_eq!(opened, 2);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(**event, Event::Established { .. }))
            .count(),
        1,
        "a second 2xx from a branch there was no room for opened a call"
    );
}

#[test]
fn a_2xx_dropped_at_the_fork_limit_leaves_a_trace() {
    // §13.3.1.4: this end never acknowledges it, and the far end gives the
    // call up with a BYE of its own — silent by design, but not untraceable
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.config.max_dialogs = 1;
    let invite = placed(&mut endpoint, t0);
    let call_id = header(&invite, HeaderName::CallId);

    deliver(
        &mut endpoint,
        &super::tests::respond_to(&invite, 200, "OK", Some("first")),
        t0,
    );
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::Established { .. })),
        "the call the caller placed always opens"
    );

    deliver(
        &mut endpoint,
        &super::tests::respond_to(&invite, 200, "OK", Some("second")),
        t0,
    );
    assert!(
        events(&mut endpoint)
            .iter()
            .all(|event| !matches!(*event, Event::Established { .. })),
        "a second branch found no room and must not open a second call"
    );

    let record = endpoint
        .call_record(&crate::dialog::CallId::new(&call_id))
        .expect("a record for this call");
    assert!(
        record
            .decisions()
            .any(|decision| decision.reason == crate::diag::Reason::ForkDroppedAtLimit),
        "{record:?}"
    );
}

#[test]
fn a_2xx_that_names_no_dialog_is_not_recorded_as_a_fork_dropped_at_the_limit() {
    // a 2xx with no To tag is ignored as well, with all the room in the world;
    // recording it as a fork the ceiling dropped points whoever reads the
    // record at max_dialogs for a fault that is the far end's
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let invite = placed(&mut endpoint, t0);
    let call_id = header(&invite, HeaderName::CallId);
    deliver(
        &mut endpoint,
        &super::tests::respond_to(&invite, 200, "OK", None),
        t0,
    );
    let record = endpoint
        .call_record(&crate::dialog::CallId::new(&call_id))
        .expect("a record for this call");
    assert!(
        record
            .decisions()
            .all(|decision| decision.reason != crate::diag::Reason::ForkDroppedAtLimit),
        "{record:?}"
    );
}

#[test]
fn a_merged_request_that_is_not_an_invite_is_answered_482_and_handed_up_once() {
    // §8.2.2.2 is about any request with no To tag: a MESSAGE or a SUBSCRIBE
    // a proxy forked reaches the application twice otherwise
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    deliver(&mut endpoint, &incoming("MESSAGE", "path1", ""), t0);
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::IncomingOutOfDialog { .. })),
        "the first copy is handed up"
    );
    transmits(&mut endpoint);

    deliver(&mut endpoint, &incoming("MESSAGE", "path2", ""), t0);
    let second = events(&mut endpoint);
    assert!(
        second
            .iter()
            .all(|event| !matches!(event, Event::IncomingOutOfDialog { .. })),
        "a merged copy was handed up a second time: {second:?}"
    );
    let out = transmits(&mut endpoint);
    assert!(
        out.iter()
            .any(|t| status_of(&t.payload) == Some(StatusCode::LOOP_DETECTED)),
        "{:?}",
        out.iter()
            .map(|t| String::from_utf8_lossy(&t.payload).into_owned())
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_request_that_carries_a_to_tag_is_not_a_merged_request() {
    // §8.2.2.2 opens "If the request has no tag in the To header field"; one
    // whose tag names no dialog here is §12.2.2's to decide, not a copy of a
    // request already being processed
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    deliver(&mut endpoint, &incoming("INVITE", "untagged", ""), t0);
    transmits(&mut endpoint);
    events(&mut endpoint);

    let tagged = String::from_utf8_lossy(&incoming("INVITE", "tagged", "")).replace(
        "To: Alice <sip:alice@192.0.2.1>\r\n",
        "To: Alice <sip:alice@192.0.2.1>;tag=elsewhere\r\n",
    );
    deliver(&mut endpoint, tagged.as_bytes(), t0);
    let out = transmits(&mut endpoint);
    assert!(
        out.iter()
            .all(|t| status_of(&t.payload) != Some(StatusCode::LOOP_DETECTED)),
        "a request with a To tag was answered as a merged copy"
    );
}

/// The status of a response on the wire, or `None` for a request.
fn status_of(bytes: &[u8]) -> Option<StatusCode> {
    // a bare method reference does not satisfy `with`'s higher-ranked bound
    #[allow(clippy::redundant_closure_for_method_calls)]
    with(bytes, |message| message.status())
}

#[test]
fn the_call_this_end_placed_opens_its_first_dialog_however_full_the_endpoint_is() {
    // the ceiling bounds what a peer can make the endpoint hold, and the extra
    // branches of a fork are the peer's; the first dialog of an INVITE this
    // end sent is the call the application asked for, placed while there was
    // room, and the ceiling coming down under it does not take it away
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let invite = placed(&mut endpoint, t0);
    endpoint.config.max_dialogs = 0;
    deliver(
        &mut endpoint,
        &super::tests::respond_to(&invite, 200, "OK", Some("desk")),
        t0,
    );
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::Established { .. })),
        "the call was answered and this end never heard"
    );
    assert_eq!(endpoint.in_flight().1, 1);
}

#[test]
fn a_call_placed_past_the_ceiling_is_refused_before_anything_goes_out() {
    // max_dialogs holds in both directions: a call this end places is a
    // dialog the moment anything answers it, so it is counted from the
    // INVITE on, and the one that would pass the ceiling is not sent at all
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.config.max_dialogs = 2;
    let first = placed(&mut endpoint, t0);
    placed(&mut endpoint, t0);
    assert_eq!(
        endpoint.invite(&super::tests::invite_request(), t0),
        Err(SendError::LimitReached { limit: 2 })
    );
    assert!(transmits(&mut endpoint).is_empty(), "nothing went out");

    // a refusal gives the room back at once, while its transaction still
    // stands for timer D: the call it placed is over
    deliver(
        &mut endpoint,
        &super::tests::respond_to(&first, 486, "Busy Here", Some("desk")),
        t0,
    );
    events(&mut endpoint);
    transmits(&mut endpoint);
    endpoint
        .invite(&super::tests::invite_request(), t0)
        .expect("the refused call's room is free again");
}

#[test]
fn a_call_nothing_answers_gives_its_room_back_at_timer_b_and_is_counted() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.config.max_dialogs = 1;
    placed(&mut endpoint, t0);
    assert_eq!(
        endpoint.invite(&super::tests::invite_request(), t0),
        Err(SendError::LimitReached { limit: 1 })
    );
    // timer B: 64·T1 of silence ends the INVITE
    endpoint.handle_timeout(t0 + std::time::Duration::from_secs(32));
    events(&mut endpoint);
    transmits(&mut endpoint);
    assert_eq!(endpoint.retransmissions().timeouts, 1);
    endpoint
        .invite(
            &super::tests::invite_request(),
            t0 + std::time::Duration::from_secs(32),
        )
        .expect("the call nothing answered is over, and its room free");
}

#[test]
fn a_call_answered_and_hung_up_gives_its_room_back_before_its_invite_ends() {
    // RFC 6026 keeps the INVITE's transaction for 64·T1 after the 2xx, and a
    // call over before then is over: it does not go on holding a place under
    // the ceiling for the rest of those 32 seconds
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.config.max_dialogs = 1;
    let invite = placed(&mut endpoint, t0);
    deliver(
        &mut endpoint,
        &super::tests::respond_to(&invite, 200, "OK", Some("desk")),
        t0,
    );
    let dialog = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::Established { dialog, .. } => Some(dialog),
            _ => None,
        })
        .expect("the call is up");
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);
    endpoint.bye(dialog, t0).expect("the BYE goes");
    let bye = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &super::tests::respond_to(&bye, 200, "OK", None),
        t0,
    );
    events(&mut endpoint);
    assert_eq!(endpoint.in_flight().1, 0, "the dialog is gone");
    endpoint
        .invite(&super::tests::invite_request(), t0)
        .expect("the call that ended left its room free");
}

#[test]
fn a_stranger_is_refused_503_while_the_calls_this_end_placed_fill_the_ceiling() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.config.max_dialogs = 1;
    placed(&mut endpoint, t0);
    deliver(&mut endpoint, &stranger(1), t0);
    let answer = sent(&mut endpoint);
    assert!(answer.starts_with(b"SIP/2.0 503 "), "{answer:?}");
    assert!(
        !String::from_utf8_lossy(&answer).contains("Retry-After"),
        "an endpoint-wide refusal names no delay"
    );
    assert_eq!(endpoint.refused(), 1);
}

// -- a merged copy of one request is not a second call ------------------------

#[test]
fn a_merged_invite_is_answered_482_and_opens_no_second_call() {
    // RFC 3261 §8.2.2.2: the same INVITE, forwarded by a second path
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    deliver(&mut endpoint, &incoming("INVITE", "path1", ""), t0);
    let first = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingInvite { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("the first copy opens a call");
    transmits(&mut endpoint);

    // same From tag, Call-ID and CSeq as the first, under a different branch
    deliver(&mut endpoint, &incoming("INVITE", "path2", ""), t0);
    assert!(
        events(&mut endpoint)
            .iter()
            .all(|event| !matches!(event, Event::IncomingInvite { .. })),
        "a merged copy must not open a second call"
    );
    let out = transmits(&mut endpoint);
    // a bare method reference does not satisfy `with`'s higher-ranked bound
    #[allow(clippy::redundant_closure_for_method_calls)]
    let status_of = |bytes: &[u8]| with(bytes, |message| message.status());
    assert!(
        out.iter()
            .any(|t| status_of(&t.payload) == Some(StatusCode::LOOP_DETECTED)),
        "{:?}",
        out.iter()
            .map(|t| String::from_utf8_lossy(&t.payload).into_owned())
            .collect::<Vec<_>>()
    );

    // the first copy is untouched by the second's arrival
    endpoint
        .respond_invite(
            first,
            &OutgoingResponse::new(StatusCode::RINGING).contact(b"<sip:alice@192.0.2.1>"),
            t0,
        )
        .expect("the original call can still be answered");
    assert_eq!(endpoint.in_flight().1, 1, "one early dialog, not two");
}

// -- a call counts against the ceiling from the moment it is let in -----------

/// An INVITE from a caller of its own: its own branch, `Call-ID` and tag.
fn stranger(n: usize) -> Vec<u8> {
    stranger_with(n, "INVITE", "")
}

/// A request of that caller's, with `extra` (CRLF terminated) in it. A CANCEL
/// written this way is the one that matches its INVITE.
fn stranger_with(n: usize, method: &str, extra: &str) -> Vec<u8> {
    format!(
        "{method} sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKstranger{n};rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:caller{n}@example.com>;tag=caller{n}\r\n\
To: Alice <sip:alice@192.0.2.1>\r\n\
Call-ID: stranger-{n}\r\n\
CSeq: 1 {method}\r\n\
Contact: <sip:caller{n}@192.0.2.9>\r\n\
{extra}\
Content-Length: 0\r\n\
\r\n"
    )
    .into_bytes()
}

/// Deliver `request` and say whether it was let in as a call.
fn let_in(
    endpoint: &mut Endpoint,
    request: &[u8],
    now: Instant,
) -> Option<TransactionId<InviteServer>> {
    deliver(endpoint, request, now);
    transmits(endpoint);
    events(endpoint).into_iter().find_map(|event| match event {
        Event::IncomingInvite { transaction, .. } => Some(transaction),
        _ => None,
    })
}

/// A 180 with the `Contact` a dialog needs.
fn ringing() -> OutgoingResponse {
    OutgoingResponse::new(StatusCode::RINGING).contact(b"<sip:alice@192.0.2.1>")
}

#[test]
fn a_call_that_rang_holds_one_place_under_the_ceiling_not_two() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.config.max_dialogs = 2;
    let first = let_in(&mut endpoint, &stranger(1), t0).expect("the first call");
    endpoint
        .respond_invite(first, &ringing(), t0)
        .expect("the 180 goes");
    assert!(
        let_in(&mut endpoint, &stranger(2), t0).is_some(),
        "one dialog under a ceiling of two, and the second call was refused"
    );
}

#[test]
fn a_call_that_rang_reliably_holds_one_place_under_the_ceiling_not_two() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.config.max_dialogs = 2;
    let offers = stranger_with(1, "INVITE", "Supported: 100rel\r\n");
    let first = let_in(&mut endpoint, &offers, t0).expect("the first call");
    endpoint
        .respond_reliable(first, &ringing(), t0)
        .expect("the 180 goes reliably");
    assert!(
        let_in(&mut endpoint, &stranger(2), t0).is_some(),
        "one dialog under a ceiling of two, and the second call was refused"
    );
}

#[test]
fn a_call_refused_before_it_rang_gives_its_place_back() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.config.max_dialogs = 1;
    let first = let_in(&mut endpoint, &stranger(1), t0).expect("the first call");
    endpoint
        .respond_invite(
            first,
            &OutgoingResponse::new(StatusCode::new(486).expect("486")),
            t0,
        )
        .expect("the 486 goes");
    assert!(
        let_in(&mut endpoint, &stranger(2), t0).is_some(),
        "a refused call still held the only place"
    );
}

#[test]
fn a_call_cancelled_before_it_rang_gives_its_place_back() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.config.max_dialogs = 1;
    let_in(&mut endpoint, &stranger(1), t0).expect("the first call");
    deliver(&mut endpoint, &stranger_with(1, "CANCEL", ""), t0);
    transmits(&mut endpoint);
    events(&mut endpoint);
    assert!(
        let_in(&mut endpoint, &stranger(2), t0).is_some(),
        "a cancelled call still held the only place"
    );
}

#[test]
fn calls_let_in_before_any_of_them_rings_are_held_to_the_dialog_ceiling() {
    // The dialog is created by this end's own 180 or 2xx, and the ceiling is
    // applied when the INVITE arrives, before either exists. Counting only the
    // dialogs already made let in every INVITE that arrived ahead of the first
    // answer, and answering them took the store past its ceiling.
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.config.max_dialogs = 1;
    for caller in 1..=3 {
        deliver(&mut endpoint, &stranger(caller), t0);
    }
    let statuses: Vec<_> = transmits(&mut endpoint)
        .iter()
        .map(|transmit| {
            super::tests::with(&transmit.payload, |message| {
                message.status().map(StatusCode::get)
            })
        })
        .collect();
    let admitted: Vec<_> = events(&mut endpoint)
        .into_iter()
        .filter_map(|event| match event {
            Event::IncomingInvite { transaction, .. } => Some(transaction),
            _ => None,
        })
        .collect();
    for transaction in &admitted {
        endpoint
            .respond_invite(
                *transaction,
                &OutgoingResponse::new(StatusCode::RINGING).contact(b"<sip:alice@192.0.2.1>"),
                t0,
            )
            .expect("the 180 goes");
    }

    assert_eq!(
        endpoint.in_flight().1,
        1,
        "the ceiling is one dialog and the answers made more"
    );
    assert_eq!(admitted.len(), 1, "one call is all there is room for");
    assert_eq!(statuses, [Some(100), Some(503), Some(503)]);
}

#[test]
fn a_placed_call_answered_by_another_branch_than_the_first_to_ring_is_established() {
    // A forking proxy rings the desk and the mobile, and the mobile answers:
    // the 2xx that answers the call the application placed comes from another
    // branch than the first to ring. A stranger's call waiting to be answered
    // is all it takes to fill a ceiling of one, once the call is placed.
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let invite = placed(&mut endpoint, t0);
    endpoint.config.max_dialogs = 2;
    let_in(&mut endpoint, &stranger(1), t0).expect("a stranger's call");
    endpoint.config.max_dialogs = 1;
    deliver(
        &mut endpoint,
        &super::tests::respond_to(&invite, 180, "Ringing", Some("desk")),
        t0,
    );
    deliver(
        &mut endpoint,
        &super::tests::respond_to(&invite, 200, "OK", Some("mobile")),
        t0,
    );
    let events = events(&mut endpoint);
    assert!(
        events
            .iter()
            .any(|event| matches!(*event, Event::Established { .. })),
        "the call was answered and this end never heard: {events:?}"
    );
}

// -- a CANCEL is answered 200 whatever the method it matched ------------------

#[test]
fn a_cancel_that_matches_a_request_other_than_an_invite_is_answered_200() {
    // §9.2: "Regardless of the method of the original request, as long as the
    // CANCEL matched an existing transaction, the UAS answers the CANCEL
    // request itself with a 200 (OK) response", and the match is made
    // "assuming that the request method is anything but CANCEL or ACK"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    deliver(&mut endpoint, &stranger_with(5, "OPTIONS", ""), t0);
    transmits(&mut endpoint);
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::IncomingOutOfDialog { .. })),
        "the OPTIONS is waiting for an answer"
    );

    deliver(&mut endpoint, &stranger_with(5, "CANCEL", ""), t0);
    let answer = sent(&mut endpoint);
    assert!(
        answer.starts_with(b"SIP/2.0 200 "),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert!(
        !events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::IncomingCancel { .. })),
        "a CANCEL has no impact on a transaction that is not an INVITE"
    );
}

// -- a PRACK crossing a refusal is still answered -----------------------------

/// The `RSeq` a reliable provisional response carried, and the tag in its `To`.
fn rseq_and_tag(response: &[u8]) -> (String, String) {
    let rseq = String::from_utf8_lossy(&header(response, HeaderName::RSeq)).into_owned();
    let to = String::from_utf8_lossy(&header(response, HeaderName::To)).into_owned();
    let tag = to
        .rsplit(";tag=")
        .next()
        .expect("a tag on the provisional")
        .to_owned();
    (rseq, tag)
}

/// The PRACK a stranger's call sends for the reliable provisional response it
/// was given.
fn prack_from(n: usize, tag: &str, rseq: &str) -> Vec<u8> {
    format!(
        "PRACK sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKprack{n};rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:caller{n}@example.com>;tag=caller{n}\r\n\
To: Alice <sip:alice@192.0.2.1>;tag={tag}\r\n\
Call-ID: stranger-{n}\r\n\
CSeq: 2 PRACK\r\n\
RAck: {rseq} 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n"
    )
    .into_bytes()
}

/// The status of every response in `transmits`, in order.
fn statuses(transmits: &[super::Transmit]) -> Vec<Option<u16>> {
    transmits
        .iter()
        .map(|transmit| {
            super::tests::with(&transmit.payload, |message| {
                message.status().map(StatusCode::get)
            })
        })
        .collect()
}

#[test]
fn a_prack_that_crosses_the_refusal_of_its_call_is_still_answered() {
    // RFC 3262 §3: a UAS that sends a final response while reliable
    // provisional responses are still unacknowledged "MUST be prepared to
    // process PRACK requests for those outstanding responses". The early
    // dialog still goes, once the INVITE transaction does.
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let offers = stranger_with(8, "INVITE", "Supported: 100rel\r\n");
    let transaction = let_in(&mut endpoint, &offers, t0).expect("a call");
    endpoint
        .respond_reliable(transaction, &ringing(), t0)
        .expect("the 180 goes reliably");
    let (rseq, tag) = rseq_and_tag(&sent(&mut endpoint));
    endpoint
        .respond_invite(
            transaction,
            &OutgoingResponse::new(StatusCode::BUSY_HERE),
            t0,
        )
        .expect("the 486 goes");
    transmits(&mut endpoint);
    events(&mut endpoint);

    deliver(&mut endpoint, &prack_from(8, &tag, &rseq), t0);
    let answered = statuses(&transmits(&mut endpoint));
    assert!(
        !answered.contains(&Some(481)),
        "a PRACK for an outstanding response was answered as matching nothing: {answered:?}"
    );
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::IncomingPrack { .. })),
        "the PRACK was not handed up to be answered"
    );

    // the ACK for the 486, and timer I after it, end the INVITE transaction;
    // the PRACK's own is still waiting for the answer it was handed up for
    deliver(&mut endpoint, &stranger_with(8, "ACK", ""), t0);
    endpoint.handle_timeout(t0 + crate::transaction::TimerConfig::DEFAULT.t4);
    assert!(endpoint.transaction_state(transaction).is_none());
    assert_eq!(
        endpoint.in_flight().1,
        0,
        "the early dialog outlived the transaction of the call that was refused"
    );
}

#[test]
fn a_prack_that_crosses_a_cancel_is_still_answered_and_the_provisional_stops() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let offers = stranger_with(9, "INVITE", "Supported: 100rel\r\n");
    let transaction = let_in(&mut endpoint, &offers, t0).expect("a call");
    endpoint
        .respond_reliable(transaction, &ringing(), t0)
        .expect("the 180 goes reliably");
    let (rseq, tag) = rseq_and_tag(&sent(&mut endpoint));
    deliver(&mut endpoint, &stranger_with(9, "CANCEL", ""), t0);
    transmits(&mut endpoint);
    events(&mut endpoint);

    // §3: "it SHOULD NOT continue to retransmit the unacknowledged reliable
    // provisional responses"
    endpoint.handle_timeout(t0 + crate::transaction::TimerConfig::DEFAULT.t1);
    let repeated = statuses(&transmits(&mut endpoint));
    assert!(
        !repeated.contains(&Some(180)),
        "the provisional went out again after the 487: {repeated:?}"
    );

    deliver(&mut endpoint, &prack_from(9, &tag, &rseq), t0);
    let answered = statuses(&transmits(&mut endpoint));
    assert!(
        !answered.contains(&Some(481)),
        "a PRACK for an outstanding response was answered as matching nothing: {answered:?}"
    );
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::IncomingPrack { .. })),
        "the PRACK was not handed up to be answered"
    );
}

// -- ten thousand calls ringing reliably ---------------------------------------

#[test]
fn ten_thousand_calls_given_up_on_for_want_of_a_prack_at_once_cost_two_sweeps_and_no_more() {
    // RFC 3262 §3 refuses every call whose reliable provisional response went
    // unacknowledged for 64*T1, and a burst of calls that rang together gives
    // up together. Each refusal ends an early dialog, and ending a dialog
    // looked for its reliable provisional responses by visiting every one the
    // endpoint had ever held.
    const CALLS: usize = 10_000;
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.config.max_server_transactions = CALLS;
    endpoint.config.max_dialogs = CALLS;
    for caller in 0..CALLS {
        let offers = stranger_with(caller, "INVITE", "Supported: 100rel\r\n");
        let transaction = let_in(&mut endpoint, &offers, t0).expect("a call");
        endpoint
            .respond_reliable(transaction, &ringing(), t0)
            .expect("the 180 goes reliably");
        transmits(&mut endpoint);
    }
    assert_eq!(endpoint.in_flight(), (CALLS, CALLS));
    let slots = u64::try_from(CALLS).expect("a count that fits");

    crate::transaction::slab::take_visits();
    endpoint.handle_timeout(t0 + crate::transaction::TimerConfig::DEFAULT.sixty_four_t1());
    let visits = crate::transaction::slab::take_visits();
    assert_eq!(
        endpoint.in_flight(),
        (CALLS, 0),
        "every call refused, and every early dialog ended with it"
    );
    assert!(
        visits <= 2 * slots,
        "giving up on {CALLS} calls at one instant visited {visits} slots"
    );
}

#[test]
fn ten_thousand_calls_refused_after_ringing_reliably_are_quieted_without_a_quadratic_path() {
    // A final response quiets whatever reliable provisional response of its
    // INVITE is still outstanding (RFC 3262 §3), and quieting looked for it by
    // visiting every reliable response the endpoint had ever held. None of
    // these dialogs is forgotten before its transaction retires, since a
    // reliable provisional is still outstanding when each is refused (the
    // same rule `a_prack_that_crosses_the_refusal_of_its_call_is_still_answered`
    // checks for one call), so by the last of them the endpoint is holding ten
    // thousand. Quieting the Nth used to cost a scan of the N-1 already held.
    const CALLS: usize = 10_000;
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.config.max_server_transactions = CALLS;
    endpoint.config.max_dialogs = CALLS;

    crate::transaction::slab::take_visits();
    for caller in 0..CALLS {
        let offers = stranger_with(caller, "INVITE", "Supported: 100rel\r\n");
        let transaction = let_in(&mut endpoint, &offers, t0).expect("a call");
        endpoint
            .respond_reliable(transaction, &ringing(), t0)
            .expect("the 180 goes reliably");
        transmits(&mut endpoint);
        endpoint
            .respond_invite(
                transaction,
                &OutgoingResponse::new(StatusCode::BUSY_HERE),
                t0,
            )
            .expect("the 486 goes");
        transmits(&mut endpoint);
        events(&mut endpoint);
    }
    let visits = crate::transaction::slab::take_visits();
    let slots = u64::try_from(CALLS).expect("a count that fits");
    assert_eq!(
        endpoint.in_flight().1,
        CALLS,
        "a reliable provisional is still outstanding on every one of them, so \
         none of the early dialogs is forgotten yet"
    );
    assert!(
        visits <= 2 * slots,
        "ringing and refusing {CALLS} calls visited {visits} slots"
    );
}

#[test]
fn a_stale_ack_for_an_earlier_re_invite_is_absorbed() {
    // 13.2.2.4 and 17.1.1.3: the ACK's CSeq number has to be the INVITE it
    // answers, not merely any INVITE this dialog has ever seen a 2xx to
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (transaction, _, tag) = rung(&mut endpoint, &incoming("INVITE", "1", ""), t0);
    endpoint
        .respond_invite(
            transaction,
            &OutgoingResponse::new(StatusCode::OK).contact(b"<sip:alice@192.0.2.1>"),
            t0,
        )
        .expect("the 200 goes");
    sent(&mut endpoint);

    let reinvite = format!(
        "INVITE sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKreinvite;rport\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bobtag\r\n\
To: Alice <sip:alice@192.0.2.1>;tag={tag}\r\n\
Call-ID: incoming-1\r\n\
CSeq: 2 INVITE\r\n\
Contact: <sip:bob@192.0.2.9>\r\n\
Content-Length: 0\r\n\
\r\n"
    );
    deliver(&mut endpoint, reinvite.as_bytes(), t0);
    transmits(&mut endpoint);
    let re_transaction = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingReinvite { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("the re-INVITE");
    endpoint
        .respond_invite(
            re_transaction,
            &OutgoingResponse::new(StatusCode::OK).contact(b"<sip:alice@192.0.2.1>"),
            t0,
        )
        .expect("the 200 goes");
    sent(&mut endpoint);

    let ack = |cseq: u32, branch: &str| {
        format!(
            "ACK sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK{branch};rport\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bobtag\r\n\
To: Alice <sip:alice@192.0.2.1>;tag={tag}\r\n\
Call-ID: incoming-1\r\n\
CSeq: {cseq} ACK\r\n\
Content-Length: 0\r\n\
\r\n"
        )
    };

    // the original INVITE's number, not the re-INVITE's: stale, or a repeat
    // of the ACK the first 2xx already had
    deliver(&mut endpoint, ack(1, "ack1").as_bytes(), t0);
    assert!(
        events(&mut endpoint)
            .iter()
            .all(|event| !matches!(event, Event::IncomingAck { .. })),
        "an ACK for an earlier INVITE must not be reported as this one's"
    );

    // the re-INVITE's own number is still answered
    deliver(&mut endpoint, ack(2, "ack2").as_bytes(), t0);
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::IncomingAck { .. })),
        "the ACK that actually answers the re-INVITE must still be reported"
    );
}
