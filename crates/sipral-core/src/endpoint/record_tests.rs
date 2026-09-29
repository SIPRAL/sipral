// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The record, read back off an endpoint that was driven the ordinary way.
//!
//! Nothing here inspects a decision the endpoint did not have to make anyway.
//! Each test drives the exchange that a support incident would have started
//! from, and then asks the record the question the incident asked: what size
//! was it, what did it go over, what did the far end say, and when.

use super::tests::{
    deliver, endpoint, events, header, incoming, invite_request, local, options_request, peer,
    register_request, sent, transmits,
};
use super::{
    DialogEndReason, Endpoint, EndpointConfig, Event, Input, OutgoingResponse, Retransmissions,
    TransportId, TransportProtocol,
};
use crate::auth::Credentials;
use crate::diag::{Decision, Direction, RecordLimits, Wire};
use crate::dialog::CallId;
use crate::msg::{HeaderName, StatusCode};
use std::time::{Duration, Instant};

const UDP: TransportId = TransportId(1);
const TCP: TransportId = TransportId(2);
const T1: Duration = Duration::from_millis(500);

/// The decisions written down for the call a message belongs to.
fn record_of(endpoint: &Endpoint, message: &[u8]) -> Vec<Decision> {
    let call = CallId::new(&header(message, HeaderName::CallId));
    endpoint
        .call_record(&call)
        .expect("a record for the call")
        .decisions()
        .cloned()
        .collect()
}

fn reasons(decisions: &[Decision]) -> Vec<&'static str> {
    decisions
        .iter()
        .map(|decision| decision.reason.as_str())
        .collect()
}

fn only(decisions: &[Decision], reason: &str) -> Decision {
    let mut found = decisions
        .iter()
        .filter(|decision| decision.reason.as_str() == reason);
    let one = found
        .next()
        .unwrap_or_else(|| panic!("no {reason} in {:?}", reasons(decisions)))
        .clone();
    assert!(found.next().is_none(), "more than one {reason}");
    one
}

fn bind_tcp(endpoint: &mut Endpoint, now: Instant) {
    endpoint
        .receive(
            Input::TransportBound {
                transport: TCP,
                protocol: TransportProtocol::Tcp,
                local: local(),
                remote: Some(peer()),
            },
            now,
        )
        .expect("binding TCP");
}

/// A response to a request the endpoint wrote, echoing what §8.2.6.2 wants.
fn answer(request: &[u8], status: u16, tag: &str) -> Vec<u8> {
    let mut to = header(request, HeaderName::To);
    to.extend_from_slice(format!(";tag={tag}").as_bytes());
    let mut out = format!("SIP/2.0 {status} Testing\r\n").into_bytes();
    for (name, value) in [
        ("Via", header(request, HeaderName::Via)),
        ("From", header(request, HeaderName::From)),
        ("To", to),
        ("Call-ID", header(request, HeaderName::CallId)),
        ("CSeq", header(request, HeaderName::CSeq)),
    ] {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&value);
        out.extend_from_slice(b"\r\n");
    }
    if (100..300).contains(&status) {
        out.extend_from_slice(b"Contact: <sip:bob@192.0.2.9>\r\n");
    }
    out.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    out
}

// -- B1: the size of every request, without a capture ------------------------

#[test]
fn every_request_that_went_out_is_in_the_record_at_its_size_on_the_wire() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .request(&options_request(), t0)
        .expect("the request goes");
    let bytes = sent(&mut endpoint);

    let decisions = record_of(&endpoint, &bytes);
    assert_eq!(
        reasons(&decisions),
        vec!["transport.selected", "request.sent"]
    );
    let out = only(&decisions, "request.sent");
    let wire = out.wire.expect("the message that caused it");
    assert_eq!(wire.bytes, bytes.len(), "the size written, not an estimate");
    assert_eq!(wire.direction, Direction::Outbound);
    assert!(matches!(wire.message, Wire::Request(ref method) if method.as_str() == "OPTIONS"));
    assert_eq!(out.address, Some(peer()));
    assert_eq!(out.protocol, Some(TransportProtocol::Udp));
    assert_eq!(out.at, Duration::ZERO);
}

#[test]
fn a_request_promoted_to_a_stream_carries_the_size_and_the_limit_together() {
    // the incident: 1785 bytes on a 1500-byte path, dropped by a NAT that
    // could not translate a non-initial fragment, and nothing anywhere said so
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    bind_tcp(&mut endpoint, t0);
    transmits(&mut endpoint);

    let padding = vec![b'x'; 1_400];
    let big = options_request().header(HeaderName::Subject, &padding);
    endpoint.request(&big, t0).expect("the request goes");
    let bytes = sent(&mut endpoint);

    let decisions = record_of(&endpoint, &bytes);
    assert_eq!(
        reasons(&decisions),
        vec![
            "transport.selected",
            "transport.promoted.size",
            "request.sent"
        ]
    );
    let promoted = only(&decisions, "transport.promoted.size");
    let measure = promoted.measure.expect("a size and a limit");
    assert_eq!(measure.limit, 1_300, "the figure from 18.1.1");
    assert!(measure.size > 1_300, "{} did fit", measure.size);
    assert_eq!(promoted.protocol, Some(TransportProtocol::Tcp));

    // and the request that did go is the one the record measured
    let out = only(&decisions, "request.sent");
    assert_eq!(out.wire.map(|wire| wire.bytes), Some(bytes.len()));
    assert_eq!(out.protocol, Some(TransportProtocol::Tcp));
}

#[test]
fn a_request_that_cannot_arrive_is_written_down_rather_than_emitted() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let padding = vec![b'x'; 1_400];
    let big = options_request().header(HeaderName::Subject, &padding);
    assert!(endpoint.request(&big, t0).is_err());
    assert!(transmits(&mut endpoint).is_empty(), "nothing may go out");

    let call = endpoint
        .recorded_calls()
        .next()
        .cloned()
        .expect("a record even though nothing was sent");
    let decisions: Vec<Decision> = endpoint
        .call_record(&call)
        .expect("the record")
        .decisions()
        .cloned()
        .collect();
    assert_eq!(
        reasons(&decisions),
        vec!["transport.selected", "transport.refused.size"]
    );
    let refused = only(&decisions, "transport.refused.size");
    let measure = refused.measure.expect("a size and a limit");
    assert_eq!(measure.limit, 1_300);
    assert!(measure.size > 1_300);
    assert_eq!(refused.address, Some(peer()));
}

// -- what a timer does -------------------------------------------------------

#[test]
fn a_retransmission_is_an_entry_of_its_own() {
    // six of these and a thirty-two second silence is the shape of every
    // report that says nothing happened
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .request(&options_request(), t0)
        .expect("the request goes");
    let bytes = sent(&mut endpoint);

    endpoint.handle_timeout(t0 + T1);
    let repeated = sent(&mut endpoint);
    assert_eq!(repeated, bytes, "17.1.2.2 repeats the identical request");

    let decisions = record_of(&endpoint, &bytes);
    assert_eq!(
        reasons(&decisions),
        vec![
            "transport.selected",
            "request.sent",
            "request.retransmitted"
        ]
    );
    let again = only(&decisions, "request.retransmitted");
    assert_eq!(again.wire.map(|wire| wire.bytes), Some(bytes.len()));
    assert_eq!(again.at, T1, "measured from the first entry in the record");
}

#[test]
fn a_call_nothing_answered_is_recorded_as_a_timeout() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .invite(&invite_request(), t0)
        .expect("the call goes");
    let bytes = sent(&mut endpoint);

    // timer B, 64*T1
    endpoint.handle_timeout(t0 + 64 * T1);
    let decisions = record_of(&endpoint, &bytes);
    assert!(
        reasons(&decisions).contains(&"failure.timeout"),
        "{:?}",
        reasons(&decisions)
    );
}

// -- what the far end says ---------------------------------------------------

#[test]
fn a_call_the_far_end_refused_is_recorded_with_the_status_that_refused_it() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .invite(&invite_request(), t0)
        .expect("the call goes");
    let bytes = sent(&mut endpoint);
    let refusal = answer(&bytes, 486, "bob");
    deliver(&mut endpoint, &refusal, t0);

    let decisions = record_of(&endpoint, &bytes);
    let failed = only(&decisions, "failure.refused");
    let wire = failed.wire.expect("the refusal that caused it");
    assert_eq!(wire.message, Wire::Response(StatusCode::BUSY_HERE));
    assert_eq!(wire.direction, Direction::Inbound);
    assert_eq!(wire.bytes, refusal.len());
}

#[test]
fn a_request_the_far_end_refused_is_recorded_with_the_status_that_refused_it() {
    // the same sentence the call above gets, for a request that never opens
    // a dialog -- a REGISTER a registrar turned away for want of room
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .request(&register_request(), t0)
        .expect("the REGISTER goes");
    let bytes = sent(&mut endpoint);
    let refusal = answer(&bytes, 503, "registrar");
    deliver(&mut endpoint, &refusal, t0);

    let decisions = record_of(&endpoint, &bytes);
    let failed = only(&decisions, "failure.refused");
    let wire = failed.wire.expect("the refusal that caused it");
    assert_eq!(
        wire.message,
        Wire::Response(StatusCode::SERVICE_UNAVAILABLE)
    );
    assert_eq!(wire.direction, Direction::Inbound);
    assert_eq!(wire.bytes, refusal.len());
}

#[test]
fn a_dialog_is_written_down_when_it_opens_and_when_it_is_over() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .invite(&invite_request(), t0)
        .expect("the call goes");
    let bytes = sent(&mut endpoint);

    deliver(&mut endpoint, &answer(&bytes, 180, "bob"), t0);
    let opened = record_of(&endpoint, &bytes);
    assert!(reasons(&opened).contains(&"dialog.created"), "{opened:?}");

    deliver(&mut endpoint, &answer(&bytes, 486, "bob"), t0);
    let closed = record_of(&endpoint, &bytes);
    assert!(
        reasons(&closed).contains(&"dialog.destroyed"),
        "{:?}",
        reasons(&closed)
    );
    // the events say the same thing, and the record is the ordered version
    assert!(events(&mut endpoint).iter().any(|event| matches!(
        *event,
        Event::DialogTerminated {
            reason: DialogEndReason::Refused,
            ..
        }
    )));
}

// -- answering, and being left unanswered ------------------------------------

#[test]
fn a_refusal_the_far_end_never_acknowledged_is_written_down_as_that() {
    // timer H is the one failure on this path that reaches nothing above: the
    // 486 went out seven times and no ACK ever came, and the only place that
    // sentence exists is the record
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    deliver(&mut endpoint, &incoming("INVITE", "1", ""), t0);
    let transaction = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingInvite { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("the call arrived");
    transmits(&mut endpoint);

    endpoint
        .respond_invite(
            transaction,
            &OutgoingResponse::new(StatusCode::BUSY_HERE),
            t0,
        )
        .expect("the refusal goes");
    transmits(&mut endpoint);
    // timer G doubles from T1 up to T2 and timer H ends it at 64*T1
    for step in 1..=64_u32 {
        endpoint.handle_timeout(t0 + step * T1);
    }
    transmits(&mut endpoint);

    let call = CallId::new(b"incoming-1");
    let decisions: Vec<Decision> = endpoint
        .call_record(&call)
        .expect("a record for the call that arrived")
        .decisions()
        .cloned()
        .collect();
    let written = reasons(&decisions);
    assert!(written.contains(&"response.sent"), "{written:?}");
    assert!(written.contains(&"response.retransmitted"), "{written:?}");
    assert!(
        written.contains(&"transaction.unacknowledged"),
        "{written:?}"
    );

    let repeated = decisions
        .iter()
        .filter(|decision| decision.reason.as_str() == "response.retransmitted")
        .count();
    assert!(repeated > 1, "17.2.1 repeats until the ACK or timer H");
}

// -- authentication ----------------------------------------------------------

#[test]
fn the_challenge_and_the_answer_to_it_are_two_entries_in_one_call() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let id = endpoint
        .request(&register_request(), t0)
        .expect("the REGISTER goes");
    let bytes = sent(&mut endpoint);

    let mut refusal = answer(&bytes, 401, "registrar");
    let challenge = "WWW-Authenticate: Digest realm=\"atlanta.example.com\", \
nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth\"\r\n";
    // the header goes in before the blank line that ends the head
    let head = refusal.len() - 2;
    refusal.splice(head..head, challenge.bytes());
    deliver(&mut endpoint, &refusal, t0);

    endpoint
        .retry_with_credentials(
            crate::transaction::AnyTransactionId::NonInviteClient(id),
            &Credentials::new("alice", "the password"),
            t0,
        )
        .expect("the retry goes");
    let retried = sent(&mut endpoint);

    let decisions = record_of(&endpoint, &bytes);
    assert_eq!(
        reasons(&decisions),
        vec![
            "transport.selected",
            "request.sent",
            "auth.challenge.received",
            "auth.challenge.answered",
            "request.sent"
        ]
    );
    let answered = only(&decisions, "auth.challenge.answered");
    assert_eq!(
        answered.wire.map(|wire| wire.bytes),
        Some(retried.len()),
        "the credentials are what made it large, so the size has to be the retry's"
    );
    let received = only(&decisions, "auth.challenge.received");
    assert_eq!(
        received.wire.map(|wire| wire.message),
        Some(Wire::Response(StatusCode::UNAUTHORIZED))
    );
}

// -- what belongs to no call -------------------------------------------------

#[test]
fn a_transport_that_goes_away_is_written_where_no_call_can_evict_it() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    bind_tcp(&mut endpoint, t0);
    endpoint
        .receive(Input::StreamClosed { transport: TCP }, t0)
        .expect("a closed stream");

    let decisions: Vec<Decision> = endpoint.endpoint_record().decisions().cloned().collect();
    let lost = only(&decisions, "transport.lost");
    assert_eq!(lost.address, Some(peer()));
    assert_eq!(lost.protocol, Some(TransportProtocol::Tcp));
    assert!(endpoint.recorded_calls().next().is_none());
}

#[test]
fn a_flood_of_strangers_cannot_push_a_call_out_of_the_set() {
    // a refusal with a fresh Call-ID every time is exactly what a scanner
    // sends, and records of its own would be the eviction it was after
    let t0 = Instant::now();
    let config = EndpointConfig {
        max_server_transactions: 0,
        ..EndpointConfig::default()
    };
    let mut endpoint = Endpoint::new(config, [7; 32]).unwrap();
    endpoint
        .receive(
            Input::TransportBound {
                transport: UDP,
                protocol: TransportProtocol::Udp,
                local: local(),
                remote: None,
            },
            t0,
        )
        .expect("binding a transport");
    endpoint
        .request(&options_request(), t0)
        .expect("the request goes");
    let ours = sent(&mut endpoint);

    for branch in 0..100_u32 {
        deliver(
            &mut endpoint,
            &incoming("OPTIONS", &branch.to_string(), ""),
            t0,
        );
    }

    assert_eq!(endpoint.recorded_calls().count(), 1, "only our own call");
    assert_eq!(endpoint.records_dropped(), 0);
    assert!(!record_of(&endpoint, &ours).is_empty());
    let refused: Vec<Decision> = endpoint.endpoint_record().decisions().cloned().collect();
    assert!(
        reasons(&refused).contains(&"request.refused.overload"),
        "{:?}",
        reasons(&refused)
    );
}

// -- the bound, and the document ---------------------------------------------

#[test]
fn a_record_evicted_for_want_of_room_is_counted_rather_than_forgotten() {
    let t0 = Instant::now();
    let config = EndpointConfig {
        diagnostics: RecordLimits {
            max_decisions: 8,
            max_records: 1,
        },
        ..EndpointConfig::default()
    };
    let mut endpoint = Endpoint::new(config, [7; 32]).unwrap();
    endpoint
        .receive(
            Input::TransportBound {
                transport: UDP,
                protocol: TransportProtocol::Udp,
                local: local(),
                remote: None,
            },
            t0,
        )
        .expect("binding a transport");
    endpoint.request(&options_request(), t0).ok();
    let first = sent(&mut endpoint);
    endpoint.request(&options_request(), t0).ok();
    sent(&mut endpoint);

    assert_eq!(endpoint.recorded_calls().count(), 1);
    assert_eq!(endpoint.records_dropped(), 1);
    let gone = CallId::new(&header(&first, HeaderName::CallId));
    assert!(endpoint.call_record(&gone).is_none());
    assert!(
        endpoint
            .diagnostics_json()
            .contains("\"records_dropped\":1")
    );
}

#[test]
fn the_whole_endpoint_serialises_to_one_document() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .request(&options_request(), t0)
        .expect("the request goes");
    let bytes = sent(&mut endpoint);

    let json = endpoint.diagnostics_json();
    let call = String::from_utf8_lossy(&header(&bytes, HeaderName::CallId)).into_owned();
    assert!(
        json.starts_with("{\"records_dropped\":0,\"records\":["),
        "{json}"
    );
    assert!(
        json.contains("\"call_id\":null"),
        "the endpoint's own: {json}"
    );
    assert!(json.contains(&format!("\"call_id\":\"{call}\"")), "{json}");
    assert!(json.contains("\"reason\":\"request.sent\""), "{json}");
    assert!(json.contains("\"method\":\"OPTIONS\""), "{json}");
    assert!(json.ends_with("]}"), "{json}");
}

// -- counted, for an application that samples numbers ------------------------

#[test]
fn a_request_nothing_answers_is_counted_twice_over_and_then_as_a_timeout() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let options = endpoint
        .request(&options_request(), t0)
        .expect("the request goes");
    transmits(&mut endpoint);
    assert_eq!(endpoint.retransmissions(), Retransmissions::default());
    assert_eq!(endpoint.transaction_retransmissions(options), Some(0));

    // timer E: T1, then 2·T1 after that
    endpoint.handle_timeout(t0 + T1);
    endpoint.handle_timeout(t0 + 3 * T1);
    assert_eq!(transmits(&mut endpoint).len(), 2);
    let counted = endpoint.retransmissions();
    assert_eq!(counted.requests, 2);
    assert_eq!(counted.responses, 0);
    assert_eq!(counted.timeouts, 0);
    assert_eq!(endpoint.transaction_retransmissions(options), Some(2));

    // timer F ends it, and the transaction's own count goes with it
    endpoint.handle_timeout(t0 + 64 * T1);
    let counted = endpoint.retransmissions();
    assert_eq!(counted.timeouts, 1);
    assert!(counted.requests >= 2, "nothing counted is ever taken back");
    assert_eq!(endpoint.transaction_retransmissions(options), None);
}

#[test]
fn a_response_sent_again_is_counted_whichever_side_asked_for_it() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let invite = incoming("INVITE", "1", "");
    deliver(&mut endpoint, &invite, t0);
    let transaction = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingInvite { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("the call arrived");
    transmits(&mut endpoint);

    // the INVITE again, before anything was decided: the 100 goes back,
    // because the far end has not heard it
    deliver(&mut endpoint, &invite, t0 + T1);
    assert_eq!(transmits(&mut endpoint).len(), 1);
    assert_eq!(endpoint.retransmissions().responses, 1);
    assert_eq!(endpoint.transaction_retransmissions(transaction), Some(1));

    endpoint
        .respond_invite(
            transaction,
            &OutgoingResponse::new(StatusCode::BUSY_HERE),
            t0 + T1,
        )
        .expect("the refusal goes");
    transmits(&mut endpoint);
    for step in 2..=65_u32 {
        endpoint.handle_timeout(t0 + step * T1);
    }
    let repeated = transmits(&mut endpoint).len();
    assert!(repeated > 1, "timer G repeats the refusal until timer H");

    let counted = endpoint.retransmissions();
    assert_eq!(
        counted.responses,
        u64::try_from(repeated).expect("a count") + 1,
        "every refusal timer G sent, and the 100 before them"
    );
    assert_eq!(counted.requests, 0);
    assert_eq!(counted.timeouts, 1, "timer H: the ACK never came");
    // and the record agrees, entry for entry
    let recorded = endpoint
        .call_record(&CallId::new(b"incoming-1"))
        .expect("a record for the call that arrived")
        .decisions()
        .filter(|decision| decision.reason.as_str() == "response.retransmitted")
        .count();
    assert_eq!(u64::try_from(recorded).expect("a count"), counted.responses);
}
