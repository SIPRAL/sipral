// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! RFC 3262 driven from both ends, on the same fake clock as everything else.

use super::tests::{
    deliver, endpoint, events, header, incoming, invite_request, options_request, sent, transmits,
    with,
};
use super::{Endpoint, Event, OutgoingResponse, RespondError};
use crate::msg::{HeaderName, StatusCode};
use crate::transaction::{InviteServer, ProvisionalResponseId, TransactionId};
use std::time::{Duration, Instant};

const T1: Duration = Duration::from_millis(500);

/// A 180 sent reliably, as the far end would write it: `Require: 100rel` and
/// an `RSeq`, echoing the fields of the request.
fn reliable_ringing(request: &[u8], tag: &str, rseq: u32) -> Vec<u8> {
    let to = String::from_utf8_lossy(&header(request, HeaderName::To)).into_owned();
    let mut out = b"SIP/2.0 180 Ringing\r\n".to_vec();
    for (name, value) in [
        ("Via", header(request, HeaderName::Via)),
        ("From", header(request, HeaderName::From)),
        ("To", format!("{to};tag={tag}").into_bytes()),
        ("Call-ID", header(request, HeaderName::CallId)),
        ("CSeq", header(request, HeaderName::CSeq)),
    ] {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Contact: <sip:bob@192.0.2.9>\r\n");
    out.extend_from_slice(b"Require: 100rel\r\n");
    out.extend_from_slice(format!("RSeq: {rseq}\r\n").as_bytes());
    out.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    out
}

/// Place a call and take the first reliable provisional response.
fn ringing_reliably(
    endpoint: &mut Endpoint,
    now: Instant,
    rseq: u32,
) -> (Vec<u8>, ProvisionalResponseId) {
    endpoint
        .invite(&invite_request(), now)
        .expect("the INVITE goes");
    let invite = sent(endpoint);
    deliver(endpoint, &reliable_ringing(&invite, "desk", rseq), now);
    let provisional = events(endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::ReliableProvisional { provisional, .. } => Some(provisional),
            _ => None,
        })
        .expect("a reliable provisional response");
    (invite, provisional)
}

/// Take an incoming INVITE that offers 100rel and return its transaction.
fn incoming_call(endpoint: &mut Endpoint, now: Instant) -> TransactionId<InviteServer> {
    deliver(
        endpoint,
        &incoming("INVITE", "rel1", "Supported: 100rel\r\n"),
        now,
    );
    transmits(endpoint);
    events(endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingInvite { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("an incoming call")
}

// -- what we send ------------------------------------------------------------

#[test]
fn an_invite_says_it_can_take_a_reliable_provisional_response() {
    // §4: "The UAC SHOULD include this in all INVITE requests"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .invite(&invite_request(), t0)
        .expect("the INVITE goes");
    let bytes = sent(&mut endpoint);
    assert_eq!(header(&bytes, HeaderName::Supported), b"100rel");
}

#[test]
fn what_the_caller_already_supports_is_kept_and_not_written_twice() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let with_timer = invite_request().header(HeaderName::Supported, b"timer");
    endpoint.invite(&with_timer, t0).expect("the INVITE goes");
    let bytes = sent(&mut endpoint);
    assert_eq!(header(&bytes, HeaderName::Supported), b"timer, 100rel");
    assert_eq!(
        with(&bytes, |m| m.header_count(HeaderName::Supported)),
        1,
        "one field, not two lines of it"
    );
}

#[test]
fn a_caller_that_already_asked_for_it_is_left_alone() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let already = invite_request().header(HeaderName::Supported, b"100rel, timer");
    endpoint.invite(&already, t0).expect("the INVITE goes");
    let bytes = sent(&mut endpoint);
    assert_eq!(header(&bytes, HeaderName::Supported), b"100rel, timer");
}

#[test]
fn a_request_that_is_not_an_invite_is_not_touched() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .request(&options_request(), t0)
        .expect("the request goes");
    let bytes = sent(&mut endpoint);
    assert!(bytes.is_empty() || header(&bytes, HeaderName::Supported).is_empty());
}

// -- what we hear ------------------------------------------------------------

#[test]
fn a_reliable_provisional_response_is_reported_with_a_handle_to_answer_it() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, provisional) = ringing_reliably(&mut endpoint, t0, 776_656);
    assert_eq!(provisional.rseq(), 776_656);
    assert!(endpoint.dialog(provisional.dialog()).is_some());
}

#[test]
fn a_prack_carries_the_three_numbers_of_the_response_it_answers() {
    // §7.2: "RAck: 776656 1 INVITE"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, provisional) = ringing_reliably(&mut endpoint, t0, 776_656);

    endpoint
        .prack(provisional, None, t0)
        .expect("the PRACK goes");
    let bytes = sent(&mut endpoint);
    assert!(bytes.starts_with(b"PRACK sip:bob@192.0.2.9 SIP/2.0"));
    assert_eq!(header(&bytes, HeaderName::RAck), b"776656 1 INVITE");
    assert_eq!(header(&bytes, HeaderName::CSeq), b"2 PRACK");
}

#[test]
fn a_prack_can_carry_the_answer_to_an_offer_that_arrived_in_the_1xx() {
    // §5: if the INVITE had no offer, the first reliable 1xx carries one and
    // the PRACK "MUST generate an answer"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, provisional) = ringing_reliably(&mut endpoint, t0, 700);
    let answer = std::sync::Arc::from(&b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\n"[..]);

    endpoint
        .prack(provisional, Some(answer), t0)
        .expect("the PRACK goes");
    let bytes = sent(&mut endpoint);
    assert_eq!(header(&bytes, HeaderName::ContentType), b"application/sdp");
    assert!(with(&bytes, |m| m.body().starts_with(b"v=0")));
}

#[test]
fn acknowledging_the_same_response_twice_is_refused() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, provisional) = ringing_reliably(&mut endpoint, t0, 700);
    endpoint
        .prack(provisional, None, t0)
        .expect("the PRACK goes");
    assert!(endpoint.prack(provisional, None, t0).is_err());
}

#[test]
fn a_retransmitted_reliable_response_is_discarded_rather_than_answered_again() {
    // §4: "Once a reliable provisional response is received, retransmissions
    // of that response MUST be discarded"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (invite, _) = ringing_reliably(&mut endpoint, t0, 700);

    deliver(&mut endpoint, &reliable_ringing(&invite, "desk", 700), t0);
    assert!(events(&mut endpoint).is_empty(), "reported twice");
    assert!(transmits(&mut endpoint).is_empty(), "a second PRACK");
}

#[test]
fn a_response_that_skips_a_number_is_not_processed_further() {
    // §4: "if ... its RSeq value is not one higher than the value of the
    // sequence number, that response MUST NOT be acknowledged with a PRACK,
    // and MUST NOT be processed further"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (invite, _) = ringing_reliably(&mut endpoint, t0, 700);

    deliver(&mut endpoint, &reliable_ringing(&invite, "desk", 702), t0);
    assert!(events(&mut endpoint).is_empty(), "a gap was taken");

    // and the one that fills the gap is taken
    deliver(&mut endpoint, &reliable_ringing(&invite, "desk", 701), t0);
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::ReliableProvisional { .. })),
        "the next in order was refused"
    );
}

#[test]
fn each_branch_of_a_fork_numbers_its_own_series() {
    // §3 puts the RSeq space inside one transaction, and a forked INVITE is
    // answered by several user agents with a transaction each
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .invite(&invite_request(), t0)
        .expect("the INVITE goes");
    let invite = sent(&mut endpoint);

    deliver(&mut endpoint, &reliable_ringing(&invite, "desk", 900), t0);
    deliver(&mut endpoint, &reliable_ringing(&invite, "mobile", 12), t0);
    let dialogs: Vec<_> = events(&mut endpoint)
        .into_iter()
        .filter_map(|event| match event {
            Event::ReliableProvisional { dialog, .. } => Some(dialog),
            _ => None,
        })
        .collect();
    assert_eq!(
        dialogs.len(),
        2,
        "one branch's numbering swallowed the other"
    );
    assert_ne!(dialogs.first(), dialogs.get(1));
}

#[test]
fn an_unreliable_provisional_response_is_still_an_ordinary_one() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .invite(&invite_request(), t0)
        .expect("the INVITE goes");
    let invite = sent(&mut endpoint);
    let plain = String::from_utf8_lossy(&reliable_ringing(&invite, "desk", 700))
        .replace("Require: 100rel\r\n", "")
        .into_bytes();
    deliver(&mut endpoint, &plain, t0);
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::Provisional { .. })),
        "a 180 without 100rel is not reliable"
    );
}

// -- what we answer ----------------------------------------------------------

#[test]
fn a_reliable_response_carries_require_and_rseq_and_opens_the_dialog() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let transaction = incoming_call(&mut endpoint, t0);

    let provisional = endpoint
        .respond_reliable(transaction, &OutgoingResponse::new(StatusCode::RINGING), t0)
        .expect("180 goes reliably");
    let bytes = sent(&mut endpoint);
    assert!(bytes.starts_with(b"SIP/2.0 180 Ringing"));
    assert_eq!(header(&bytes, HeaderName::Require), b"100rel");
    let rseq = String::from_utf8_lossy(&header(&bytes, HeaderName::RSeq))
        .parse::<u32>()
        .expect("a number");
    assert_eq!(rseq, provisional.rseq());
    assert!((1..=2_147_483_647).contains(&rseq), "outside 1..2**31-1");
    assert!(endpoint.dialog(provisional.dialog()).is_some());
}

#[test]
fn a_reliable_response_is_retransmitted_on_a_doubling_interval() {
    // §3: "an interval that starts at T1 seconds and doubles for each
    // retransmission", with no cap, unlike a 2xx
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let transaction = incoming_call(&mut endpoint, t0);
    endpoint
        .respond_reliable(transaction, &OutgoingResponse::new(StatusCode::RINGING), t0)
        .expect("180 goes reliably");
    let first = sent(&mut endpoint);
    assert_eq!(endpoint.poll_timeout(), Some(t0 + T1));

    endpoint.handle_timeout(t0 + T1);
    assert_eq!(sent(&mut endpoint), first, "the same bytes");
    assert_eq!(endpoint.poll_timeout(), Some(t0 + T1 + 2 * T1));

    endpoint.handle_timeout(t0 + 3 * T1);
    assert_eq!(sent(&mut endpoint), first);
    assert_eq!(endpoint.poll_timeout(), Some(t0 + 3 * T1 + 4 * T1));
    assert_eq!(
        endpoint.retransmissions().responses,
        2,
        "each repeat is a response sent again"
    );
    assert_eq!(endpoint.transaction_retransmissions(transaction), Some(2));
}

#[test]
fn a_second_reliable_response_waits_for_the_first_to_be_acknowledged() {
    // §3: "The UAS MUST NOT send a second reliable provisional response until
    // the first is acknowledged"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let transaction = incoming_call(&mut endpoint, t0);
    endpoint
        .respond_reliable(transaction, &OutgoingResponse::new(StatusCode::RINGING), t0)
        .expect("180 goes reliably");
    transmits(&mut endpoint);

    assert_eq!(
        endpoint.respond_reliable(
            transaction,
            &OutgoingResponse::new(StatusCode::SESSION_PROGRESS),
            t0
        ),
        Err(RespondError::StillUnacknowledged)
    );
}

#[test]
fn a_prack_stops_the_retransmissions_and_is_handed_up_to_be_answered() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let transaction = incoming_call(&mut endpoint, t0);
    let provisional = endpoint
        .respond_reliable(transaction, &OutgoingResponse::new(StatusCode::RINGING), t0)
        .expect("180 goes reliably");
    let ringing = sent(&mut endpoint);
    let rseq = String::from_utf8_lossy(&header(&ringing, HeaderName::RSeq)).into_owned();
    let tag = String::from_utf8_lossy(&header(&ringing, HeaderName::To))
        .rsplit(";tag=")
        .next()
        .unwrap_or_default()
        .to_owned();

    let prack = format!(
        "PRACK sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKprack1;rport\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bobtag\r\n\
To: Alice <sip:alice@192.0.2.1>;tag={tag}\r\n\
Call-ID: incoming-1\r\n\
CSeq: 2 PRACK\r\n\
RAck: {rseq} 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n"
    );
    deliver(&mut endpoint, prack.as_bytes(), t0);

    let reported = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingPrack {
                transaction,
                provisional,
                ..
            } => Some((transaction, provisional)),
            _ => None,
        })
        .expect("the PRACK");
    assert_eq!(reported.1.dialog(), provisional.dialog());
    assert_eq!(
        endpoint.poll_timeout(),
        Some(t0 + T1 * 64),
        "the reliable retransmissions should have stopped, leaving only the \
         PRACK's own transaction's 64*T1 deadline for an application that \
         never answers it"
    );

    endpoint
        .respond(reported.0, &OutgoingResponse::new(StatusCode::OK), t0)
        .expect("the 200 for the PRACK goes");
    assert!(sent(&mut endpoint).starts_with(b"SIP/2.0 200 OK"));
}

#[test]
fn the_ack_for_a_call_that_was_pracked_before_it_was_answered_is_reported() {
    // the PRACK takes the dialog's next number from the caller, so by the
    // time the 2xx is acknowledged the dialog has seen CSeq 2; the ACK still
    // carries the INVITE's own 1 (§13.2.2.4), and it is the one that says the
    // call is up
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let transaction = incoming_call(&mut endpoint, t0);
    endpoint
        .respond_reliable(transaction, &OutgoingResponse::new(StatusCode::RINGING), t0)
        .expect("180 goes reliably");
    let ringing = sent(&mut endpoint);
    let rseq = String::from_utf8_lossy(&header(&ringing, HeaderName::RSeq)).into_owned();
    let tag = String::from_utf8_lossy(&header(&ringing, HeaderName::To))
        .rsplit(";tag=")
        .next()
        .unwrap_or_default()
        .to_owned();

    let prack = format!(
        "PRACK sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKprack3;rport\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bobtag\r\n\
To: Alice <sip:alice@192.0.2.1>;tag={tag}\r\n\
Call-ID: incoming-1\r\n\
CSeq: 2 PRACK\r\n\
RAck: {rseq} 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n"
    );
    deliver(&mut endpoint, prack.as_bytes(), t0);
    let pracked = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingPrack { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("the PRACK");
    endpoint
        .respond(pracked, &OutgoingResponse::new(StatusCode::OK), t0)
        .expect("the 200 for the PRACK goes");
    transmits(&mut endpoint);

    let dialog = endpoint
        .respond_invite(
            transaction,
            &OutgoingResponse::new(StatusCode::OK).contact(b"<sip:alice@192.0.2.1>"),
            t0,
        )
        .expect("the 200 goes")
        .expect("the dialog");
    transmits(&mut endpoint);
    events(&mut endpoint);

    let ack = format!(
        "ACK sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKrelack;rport\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bobtag\r\n\
To: Alice <sip:alice@192.0.2.1>;tag={tag}\r\n\
Call-ID: incoming-1\r\n\
CSeq: 1 ACK\r\n\
Content-Length: 0\r\n\
\r\n"
    );
    deliver(&mut endpoint, ack.as_bytes(), t0);
    let heard = events(&mut endpoint);
    assert!(
        heard.iter().any(|event| matches!(
            event,
            Event::IncomingAck { dialog: acked, .. } if *acked == dialog
        )),
        "the ACK for the INVITE's 2xx was absorbed because a PRACK came first: {heard:?}"
    );
}

/// A PRACK for the 180 `respond_reliable` just sent, with the branch and the
/// `CSeq` given, and what the endpoint reported it as.
fn prack_for(
    endpoint: &mut Endpoint,
    ringing: &[u8],
    branch: &str,
    cseq: u32,
    now: Instant,
) -> Option<(
    TransactionId<crate::transaction::NonInviteServer>,
    ProvisionalResponseId,
)> {
    let rseq = String::from_utf8_lossy(&header(ringing, HeaderName::RSeq)).into_owned();
    let tag = String::from_utf8_lossy(&header(ringing, HeaderName::To))
        .rsplit(";tag=")
        .next()
        .unwrap_or_default()
        .to_owned();
    let prack = format!(
        "PRACK sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch={branch};rport\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bobtag\r\n\
To: Alice <sip:alice@192.0.2.1>;tag={tag}\r\n\
Call-ID: incoming-1\r\n\
CSeq: {cseq} PRACK\r\n\
RAck: {rseq} 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n"
    );
    deliver(endpoint, prack.as_bytes(), now);
    events(endpoint).into_iter().find_map(|event| match event {
        Event::IncomingPrack {
            transaction,
            provisional,
            ..
        } => Some((transaction, provisional)),
        _ => None,
    })
}

#[test]
fn a_refused_prack_acknowledges_nothing_and_its_retry_is_matched() {
    // §3 answers a matching PRACK 2xx only once §8.2 of RFC 3261 has let it
    // through; a PRACK refused there (a 420 here) acknowledged nothing, the
    // far end retries it with the same RAck (§8.1.3.5), and that retry has
    // to be matched rather than answered 481, which ends the dialog
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let transaction = incoming_call(&mut endpoint, t0);
    endpoint
        .respond_reliable(transaction, &OutgoingResponse::new(StatusCode::RINGING), t0)
        .expect("180 goes reliably");
    let ringing = sent(&mut endpoint);

    let (first, provisional) =
        prack_for(&mut endpoint, &ringing, "z9hG4bKrefused", 2, t0).expect("the PRACK");
    let refusal =
        OutgoingResponse::new(StatusCode::BAD_EXTENSION).header(HeaderName::Unsupported, b"foo");
    endpoint
        .refuse_prack(first, provisional, &refusal, t0)
        .expect("the 420 goes");
    assert!(sent(&mut endpoint).starts_with(b"SIP/2.0 420 "));
    // still unacknowledged: a second reliable response waits for it, and it
    // is retransmitted again
    assert_eq!(
        endpoint.respond_reliable(
            transaction,
            &OutgoingResponse::new(StatusCode::SESSION_PROGRESS),
            t0
        ),
        Err(RespondError::StillUnacknowledged)
    );
    let due = endpoint.poll_timeout().expect("a retransmission");
    assert!(due < t0 + 64 * T1, "{:?}", due - t0);
    endpoint.handle_timeout(due);
    assert_eq!(sent(&mut endpoint), ringing, "the 180 again");

    let (retry, matched) = prack_for(&mut endpoint, &ringing, "z9hG4bKretried", 3, due)
        .expect("the retry is matched, not answered 481");
    assert_eq!(matched.rseq(), provisional.rseq());
    endpoint
        .refuse_prack(retry, matched, &OutgoingResponse::new(StatusCode::OK), due)
        .expect("the 200 goes");
    assert!(sent(&mut endpoint).starts_with(b"SIP/2.0 200 "));
    // a 2xx through the same door acknowledges it for good
    assert!(
        endpoint
            .respond_reliable(
                transaction,
                &OutgoingResponse::new(StatusCode::SESSION_PROGRESS),
                due
            )
            .is_ok()
    );
}

#[test]
fn a_refused_prack_after_the_final_response_is_not_retransmitted_again() {
    // §3: after a final response the provisional "SHOULD NOT" be
    // retransmitted, and taking its acknowledgement back does not change that
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let transaction = incoming_call(&mut endpoint, t0);
    endpoint
        .respond_reliable(transaction, &OutgoingResponse::new(StatusCode::RINGING), t0)
        .expect("180 goes reliably");
    let ringing = sent(&mut endpoint);
    endpoint
        .respond_invite(
            transaction,
            &OutgoingResponse::new(StatusCode::BUSY_HERE),
            t0,
        )
        .expect("486 goes");
    transmits(&mut endpoint);

    let (prack, provisional) =
        prack_for(&mut endpoint, &ringing, "z9hG4bKlate", 2, t0).expect("the PRACK");
    endpoint
        .refuse_prack(
            prack,
            provisional,
            &OutgoingResponse::new(StatusCode::UNSUPPORTED_MEDIA_TYPE),
            t0,
        )
        .expect("the 415 goes");
    transmits(&mut endpoint);
    for _ in 0..8 {
        let Some(due) = endpoint.poll_timeout() else {
            break;
        };
        endpoint.handle_timeout(due);
        assert!(
            transmits(&mut endpoint)
                .iter()
                .all(|transmit| with(&transmit.payload, |m| {
                    m.status().map(StatusCode::get) != Some(180)
                })),
            "the provisional was retransmitted after the final response"
        );
    }
}

#[test]
fn a_prack_that_matches_nothing_is_answered_481() {
    // §3: "the UAS MUST respond to the PRACK with a 481 response"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let transaction = incoming_call(&mut endpoint, t0);
    endpoint
        .respond_reliable(transaction, &OutgoingResponse::new(StatusCode::RINGING), t0)
        .expect("180 goes reliably");
    let ringing = sent(&mut endpoint);
    let tag = String::from_utf8_lossy(&header(&ringing, HeaderName::To))
        .rsplit(";tag=")
        .next()
        .unwrap_or_default()
        .to_owned();

    let stray = format!(
        "PRACK sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKprack2;rport\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bobtag\r\n\
To: Alice <sip:alice@192.0.2.1>;tag={tag}\r\n\
Call-ID: incoming-1\r\n\
CSeq: 2 PRACK\r\n\
RAck: 999999 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n"
    );
    deliver(&mut endpoint, stray.as_bytes(), t0);
    let out = transmits(&mut endpoint);
    assert_eq!(
        out.last()
            .and_then(|t| with(&t.payload, |m| m.status().map(StatusCode::get))),
        Some(481)
    );
}

#[test]
fn nothing_acknowledges_it_and_the_call_is_refused() {
    // §3: "If a reliable provisional response is retransmitted for 64*T1
    // seconds without reception of a corresponding PRACK, the UAS SHOULD
    // reject the original request with a 5xx response."
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let transaction = incoming_call(&mut endpoint, t0);
    endpoint
        .respond_reliable(transaction, &OutgoingResponse::new(StatusCode::RINGING), t0)
        .expect("180 goes reliably");
    transmits(&mut endpoint);

    endpoint.handle_timeout(t0 + 64 * T1);
    let out = transmits(&mut endpoint);
    assert_eq!(
        out.last()
            .and_then(|t| with(&t.payload, |m| m.status().map(StatusCode::get))),
        Some(500),
        "{out:?}"
    );
    assert_eq!(
        endpoint.retransmissions().timeouts,
        1,
        "a reliable response never PRACKed is a timeout"
    );
}

#[test]
fn a_final_response_stops_the_retransmissions_without_forgetting_the_prack() {
    // §3: "it SHOULD NOT continue to retransmit ... but it MUST be prepared to
    // process PRACK requests for those outstanding responses"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let transaction = incoming_call(&mut endpoint, t0);
    endpoint
        .respond_reliable(transaction, &OutgoingResponse::new(StatusCode::RINGING), t0)
        .expect("180 goes reliably");
    transmits(&mut endpoint);
    assert!(endpoint.poll_timeout().is_some());

    endpoint
        .respond_invite(
            transaction,
            &OutgoingResponse::new(StatusCode::BUSY_HERE),
            t0,
        )
        .expect("486 goes");
    transmits(&mut endpoint);
    // timer G is now the only reason to come back, and it is not the
    // provisional's
    let due = endpoint.poll_timeout().expect("timer G");
    endpoint.handle_timeout(due);
    let out = transmits(&mut endpoint);
    assert!(
        out.iter().all(|transmit| with(&transmit.payload, |m| {
            m.status().map(StatusCode::get) != Some(180)
        })),
        "the provisional was still being retransmitted"
    );
}

// -- what we refuse ----------------------------------------------------------

#[test]
fn a_hundred_trying_cannot_be_sent_reliably() {
    // §3: "A UAS MUST NOT attempt to send a 100 (Trying) response reliably"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let transaction = incoming_call(&mut endpoint, t0);
    assert_eq!(
        endpoint.respond_reliable(transaction, &OutgoingResponse::new(StatusCode::TRYING), t0),
        Err(RespondError::NotProvisional)
    );
    assert_eq!(
        endpoint.respond_reliable(transaction, &OutgoingResponse::new(StatusCode::OK), t0),
        Err(RespondError::NotProvisional)
    );
}

#[test]
fn a_peer_that_never_offered_it_is_not_answered_reliably() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    deliver(&mut endpoint, &incoming("INVITE", "rel2", ""), t0);
    transmits(&mut endpoint);
    let transaction = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingInvite { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("an incoming call");
    assert_eq!(
        endpoint.respond_reliable(transaction, &OutgoingResponse::new(StatusCode::RINGING), t0),
        Err(RespondError::NotOffered)
    );
}

#[test]
fn an_invite_that_requires_it_refuses_an_unreliable_provisional_response() {
    // §3: "The UAS MUST send any non-100 provisional response reliably if the
    // initial request contained a Require header field with the option tag"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    deliver(
        &mut endpoint,
        &incoming("INVITE", "rel3", "Require: 100rel\r\n"),
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

    assert_eq!(
        endpoint.respond_invite(transaction, &OutgoingResponse::new(StatusCode::RINGING), t0),
        Err(RespondError::MustBeReliable)
    );
    // a final response is not a provisional one, and goes
    assert!(
        endpoint
            .respond_invite(transaction, &OutgoingResponse::new(StatusCode::OK), t0)
            .is_ok()
    );
}
