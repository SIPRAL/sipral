// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What a request the parser refuses gets back.
//!
//! RFC 3261 §8.2 has a UAS answer what it cannot process rather than let the
//! client retransmit into silence until timer B or F gives up: 400 for a
//! request it cannot read (§21.4.1), 513 for one longer than it can take
//! (§21.5.14). Both are written from what can still be recovered of the
//! request — `Via`, `From`, `To`, `Call-ID`, `CSeq` — and what cannot be
//! answered is dropped with a count and a diagnostic entry, never without a
//! trace.

use super::tests::{
    deliver, endpoint, events, header, incoming, invite_request, local, peer, respond_to, sent,
    transmits,
};
use super::{Endpoint, EndpointConfig, Event, Input, ReceiveError, TransportId, TransportProtocol};
use crate::diag::Decision;
use crate::msg::{
    HeaderName, Limits, ParseError, ParseMode, ParseScratch, RawMessage, StatusCode,
    parse_with_limits,
};
use std::time::Instant;

const UDP: TransportId = TransportId(1);
const TCP: TransportId = TransportId(2);

/// `incoming`, with a header value `length` bytes long.
fn with_a_long_subject(method: &str, branch: &str, length: usize) -> Vec<u8> {
    incoming(
        method,
        branch,
        &format!("Subject: {}\r\n", "s".repeat(length)),
    )
}

/// Feed a datagram in, and hand back what `receive` said about it.
fn arrive(endpoint: &mut Endpoint, bytes: &[u8], now: Instant) -> Result<(), ReceiveError> {
    endpoint.receive(
        Input::Datagram {
            transport: UDP,
            remote: peer(),
            local: local(),
            data: bytes,
        },
        now,
    )
}

/// An answer, read back with no bound on one value: it may carry the very
/// field the request was refused for.
fn read_back<T>(bytes: &[u8], f: impl FnOnce(&RawMessage<'_>) -> T) -> T {
    let mut scratch = ParseScratch::new();
    let limits = Limits {
        max_header_value_bytes: Limits::DEFAULT.max_message_bytes,
        ..Limits::DEFAULT
    };
    let message = parse_with_limits(bytes, &mut scratch, ParseMode::Strict, limits)
        .expect("a well formed response");
    f(&message)
}

/// The status line and the reason phrase of a response.
fn status_of(bytes: &[u8]) -> (Option<StatusCode>, String) {
    read_back(bytes, |message| {
        (
            message.status(),
            String::from_utf8_lossy(message.reason().unwrap_or_default()).into_owned(),
        )
    })
}

fn endpoint_decisions(endpoint: &Endpoint) -> Vec<Decision> {
    endpoint.endpoint_record().decisions().cloned().collect()
}

fn one_of<'a>(decisions: &'a [Decision], code: &str) -> &'a Decision {
    let found: Vec<&Decision> = decisions
        .iter()
        .filter(|decision| decision.reason.as_str() == code)
        .collect();
    assert_eq!(found.len(), 1, "one {code} in {decisions:?}");
    found.first().copied().expect("counted above")
}

/// An endpoint on a connected TCP transport to the peer.
fn on_a_stream(config: EndpointConfig, now: Instant) -> Endpoint {
    let mut endpoint = Endpoint::new(config, [9; 32]).expect("an endpoint");
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
    transmits(&mut endpoint);
    endpoint
}

fn stream(endpoint: &mut Endpoint, bytes: &[u8], now: Instant) -> Result<(), ReceiveError> {
    endpoint.receive(
        Input::StreamData {
            transport: TCP,
            data: bytes,
        },
        now,
    )
}

#[test]
fn an_invite_with_a_display_name_thousands_of_bytes_long_is_taken() {
    // the headless audit's INVITE, whole: nothing came back to it at all
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let invite = incoming(
        "INVITE",
        "big1",
        &format!(
            "P-Asserted-Identity: \"{}\" <sip:bob@example.com>\r\n",
            "a".repeat(9_000)
        ),
    );
    arrive(&mut endpoint, &invite, t0).expect("a request within the bounds");
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::IncomingInvite { .. })),
        "the call rings"
    );
}

#[test]
fn a_request_whose_header_is_past_the_bound_is_answered_400_naming_it() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let limit = Limits::DEFAULT.max_header_value_bytes as usize;
    let invite = with_a_long_subject("INVITE", "long1", limit + 1);

    let refused = arrive(&mut endpoint, &invite, t0);
    assert!(
        matches!(
            refused,
            Err(ReceiveError::Malformed(
                ParseError::HeaderValueTooLong { .. }
            ))
        ),
        "{refused:?}"
    );

    let out = transmits(&mut endpoint);
    assert_eq!(out.len(), 1, "one answer");
    let answer = out.first().expect("counted above");
    assert_eq!(answer.destination, peer(), "rport: back where it came from");
    let (status, phrase) = status_of(&answer.payload);
    assert_eq!(status, Some(StatusCode::BAD_REQUEST));
    assert_eq!(phrase, format!("Subject Too Long (limit {limit} bytes)"));
    for name in [
        HeaderName::Via,
        HeaderName::From,
        HeaderName::CallId,
        HeaderName::CSeq,
    ] {
        assert_eq!(
            header(&answer.payload, name),
            header(&incoming("INVITE", "long1", ""), name),
            "{name:?} is the request's own (§8.2.6.2)"
        );
    }
    assert!(
        String::from_utf8_lossy(&header(&answer.payload, HeaderName::To)).contains(";tag="),
        "a final response carries a tag (§8.2.6.2)"
    );
    assert!(events(&mut endpoint).is_empty(), "nothing rings");
    assert_eq!(endpoint.unreadable(), 1);

    let decisions = endpoint_decisions(&endpoint);
    let refusal = one_of(&decisions, "request.refused.unreadable");
    assert_eq!(refusal.address, Some(peer()));
    assert_eq!(
        refusal.measure.map(|measure| measure.limit),
        Some(Limits::DEFAULT.max_header_value_bytes)
    );
}

#[test]
fn a_field_the_answer_copies_may_itself_be_the_one_past_the_bound() {
    // the audit's own shape: the display name in `From`, which the answer has
    // to carry back whole or it answers nobody
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let limit = Limits::DEFAULT.max_header_value_bytes as usize;
    let from = format!("\"{}\" <sip:bob@example.com>;tag=bobtag", "a".repeat(limit));
    let invite = format!(
        "INVITE sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKfrom1;rport\r\n\
From: {from}\r\n\
To: Alice <sip:alice@192.0.2.1>\r\n\
Call-ID: incoming-from\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n"
    );
    let _ = arrive(&mut endpoint, invite.as_bytes(), t0);
    let answer = sent(&mut endpoint);
    assert_eq!(status_of(&answer).0, Some(StatusCode::BAD_REQUEST));
    assert_eq!(
        read_back(&answer, |message| message
            .header(HeaderName::From)
            .map(<[u8]>::to_vec)),
        Some(from.into_bytes())
    );
    assert_eq!(
        status_of(&answer).1,
        format!("From Too Long (limit {limit} bytes)")
    );
}

#[test]
fn a_datagram_longer_than_the_message_bound_is_answered_513() {
    let t0 = Instant::now();
    let config = EndpointConfig {
        limits: Limits {
            max_message_bytes: 2_048,
            ..Limits::DEFAULT
        },
        ..EndpointConfig::default()
    };
    let mut endpoint = Endpoint::new(config, [5; 32]).expect("an endpoint");
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
        .expect("binding UDP");

    let refused = arrive(
        &mut endpoint,
        &with_a_long_subject("MESSAGE", "m1", 3_000),
        t0,
    );
    assert_eq!(
        refused,
        Err(ReceiveError::Malformed(ParseError::MessageTooLarge {
            limit: 2_048
        }))
    );
    let (status, phrase) = status_of(&sent(&mut endpoint));
    assert_eq!(status, Some(StatusCode::MESSAGE_TOO_LARGE));
    assert_eq!(phrase, "Message Too Large (limit 2048 bytes)");
}

#[test]
fn a_request_with_more_fields_than_the_bound_is_answered_400() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let many = (0..Limits::DEFAULT.max_headers)
        .map(|n| format!("X-Field-{n}: {n}\r\n"))
        .collect::<Vec<_>>()
        .concat();
    let _ = arrive(&mut endpoint, &incoming("OPTIONS", "many1", &many), t0);
    let (status, phrase) = status_of(&sent(&mut endpoint));
    assert_eq!(status, Some(StatusCode::BAD_REQUEST));
    assert_eq!(
        phrase,
        format!(
            "Too Many Header Fields (limit {})",
            Limits::DEFAULT.max_headers
        )
    );
}

#[test]
fn a_datagram_shorter_than_its_content_length_is_answered_400() {
    // §18.3: "If the message is a request, the UAS SHOULD generate a 400"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let short = String::from_utf8(incoming("OPTIONS", "cl1", ""))
        .expect("text")
        .replace("Content-Length: 0", "Content-Length: 400");
    let _ = arrive(&mut endpoint, short.as_bytes(), t0);
    let (status, phrase) = status_of(&sent(&mut endpoint));
    assert_eq!(status, Some(StatusCode::BAD_REQUEST));
    assert_eq!(phrase, "Content-Length Exceeds Message");
}

#[test]
fn a_request_inside_a_dialog_is_answered_in_it_and_the_dialog_stands() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .invite(&invite_request(), t0)
        .expect("the INVITE goes");
    let invite = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &respond_to(&invite, 200, "OK", Some("desk")),
        t0,
    );
    let dialog = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::Established { dialog, .. } => Some(dialog),
            _ => None,
        })
        .expect("the call connected");
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    let ack = sent(&mut endpoint);

    // their BYE, carrying a field past the bound
    let their_from = String::from_utf8_lossy(&header(&ack, HeaderName::To)).into_owned();
    let their_to = String::from_utf8_lossy(&header(&ack, HeaderName::From)).into_owned();
    let call_id = String::from_utf8_lossy(&header(&ack, HeaderName::CallId)).into_owned();
    let bye = format!(
        "BYE sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKbye1;rport\r\n\
From: {their_from}\r\n\
To: {their_to}\r\n\
Call-ID: {call_id}\r\n\
CSeq: 7 BYE\r\n\
Reason: SIP;text=\"{}\"\r\n\
Content-Length: 0\r\n\
\r\n",
        "r".repeat(Limits::DEFAULT.max_header_value_bytes as usize)
    );
    let _ = arrive(&mut endpoint, bye.as_bytes(), t0);
    let answer = sent(&mut endpoint);
    assert_eq!(status_of(&answer).0, Some(StatusCode::BAD_REQUEST));
    assert_eq!(
        header(&answer, HeaderName::To),
        their_to.as_bytes(),
        "the dialog's own tag, and no second one (§8.2.6.2)"
    );
    assert!(events(&mut endpoint).is_empty(), "the call is not ended");
    assert!(endpoint.dialog(dialog).is_some(), "the dialog stands");
}

#[test]
fn an_ack_the_parser_refuses_is_never_answered_and_is_still_counted() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let _ = arrive(
        &mut endpoint,
        &with_a_long_subject("ACK", "ack1", 20_000),
        t0,
    );
    assert!(transmits(&mut endpoint).is_empty(), "§17.1.1.3");
    assert_eq!(endpoint.unreadable(), 1);
    one_of(&endpoint_decisions(&endpoint), "message.dropped.unreadable");
}

#[test]
fn a_response_the_parser_refuses_is_dropped_and_counted() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let response = format!(
        "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnothing\r\n\
Subject: {}\r\n\
\r\n",
        "s".repeat(20_000)
    );
    assert!(arrive(&mut endpoint, response.as_bytes(), t0).is_err());
    assert!(transmits(&mut endpoint).is_empty());
    assert_eq!(endpoint.unreadable(), 1);
    one_of(&endpoint_decisions(&endpoint), "message.dropped.unreadable");
}

#[test]
fn a_request_with_nowhere_to_send_an_answer_is_dropped_and_counted() {
    // no `Via`: §18.2.2 sends a response where the top one says, and there is
    // none
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let request = format!(
        "OPTIONS sip:alice@192.0.2.1 SIP/2.0\r\n\
From: <sip:bob@example.com>;tag=1\r\n\
To: <sip:alice@192.0.2.1>\r\n\
Call-ID: novia\r\n\
CSeq: 1 OPTIONS\r\n\
Subject: {}\r\n\
\r\n",
        "s".repeat(20_000)
    );
    assert!(arrive(&mut endpoint, request.as_bytes(), t0).is_err());
    assert!(transmits(&mut endpoint).is_empty());
    assert_eq!(endpoint.unreadable(), 1);
    let decisions = endpoint_decisions(&endpoint);
    let dropped = one_of(&decisions, "message.dropped.unreadable");
    assert_eq!(dropped.address, Some(peer()));
}

/// An OPTIONS whose head begins with `head` — its `Via` lines, and whatever
/// else a test puts in front of them — and then the other four fields an
/// answer copies.
fn options(head: &str) -> Vec<u8> {
    format!(
        "OPTIONS sip:alice@192.0.2.1 SIP/2.0\r\n\
{head}\
From: <sip:bob@example.com>;tag=1\r\n\
To: <sip:alice@192.0.2.1>\r\n\
Call-ID: via-refused\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\
\r\n"
    )
    .into_bytes()
}

/// A field line whose value is one byte past the bound.
fn past_the_bound(name: &str) -> String {
    format!(
        "{name}: {}\r\n",
        "x".repeat(Limits::DEFAULT.max_header_value_bytes as usize + 1)
    )
}

/// A top `Via` past the bound, with a `maddr` and a port of its own choosing.
fn a_via_past_the_bound() -> String {
    let via = "Via: SIP/2.0/UDP 192.0.2.9:5099;branch=z9hG4bKvia1;maddr=198.51.100.7;x=";
    let pad = Limits::DEFAULT.max_header_value_bytes as usize + 1 - (via.len() - "Via: ".len());
    format!("{via}{}\r\n", "v".repeat(pad))
}

/// That a refusal went nowhere, and left its trace.
fn dropped_unanswered(endpoint: &mut Endpoint) {
    let out = transmits(endpoint);
    assert!(
        out.is_empty(),
        "answered to {:?}",
        out.iter().map(|t| t.destination).collect::<Vec<_>>()
    );
    assert_eq!(endpoint.unreadable(), 1);
    let decisions = endpoint_decisions(endpoint);
    one_of(&decisions, "message.dropped.unreadable");
    assert!(
        decisions
            .iter()
            .all(|decision| decision.reason.as_str() != "request.refused.unreadable")
    );
}

#[test]
fn a_via_past_the_bound_routes_no_answer() {
    // the one field the answer is routed by is the one the parser refused:
    // its `maddr` and its port are a stranger's say, read past every bound
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let refused = arrive(&mut endpoint, &options(&a_via_past_the_bound()), t0);
    assert!(
        matches!(
            refused,
            Err(ReceiveError::Malformed(ParseError::HeaderValueTooLong {
                name_at: 37,
                ..
            }))
        ),
        "{refused:?}"
    );
    dropped_unanswered(&mut endpoint);
}

#[test]
fn a_via_the_parser_never_reached_is_held_to_the_same_bound() {
    // refused for a field in front of it, so the parser never measured it
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let head = format!("{}{}", past_the_bound("Subject"), a_via_past_the_bound());
    let _ = arrive(&mut endpoint, &options(&head), t0);
    dropped_unanswered(&mut endpoint);
}

#[test]
fn a_via_left_out_for_a_lone_cr_takes_the_answer_with_it() {
    // without the top `Via` the next one down would route the answer, to an
    // address that hop never asked to be answered at
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let _ = arrive(
        &mut endpoint,
        &options(
            "Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKcr1\r;rport\r\n\
Via: SIP/2.0/UDP 203.0.113.4:5070;branch=z9hG4bKcr2;maddr=198.51.100.7\r\n",
        ),
        t0,
    );
    dropped_unanswered(&mut endpoint);
}

#[test]
fn an_answer_that_cannot_be_written_is_recorded_as_dropped_not_as_sent() {
    // a request at the message bound whose `From` is past the value bound:
    // the answer carries that `From` back, a longer status line and a tag,
    // and passes the message bound the builder still holds it to. Nothing
    // goes out, and the record must not say it did
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let bound = Limits::DEFAULT.max_message_bytes as usize;
    let shape = |name: usize| {
        String::from_utf8(options(
            "Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKfull1;rport\r\n",
        ))
        .expect("text")
        .replace(
            "From: <sip:bob@example.com>",
            &format!("From: \"{}\" <sip:bob@example.com>", "a".repeat(name)),
        )
    };
    let request = shape(bound - shape(0).len());
    assert_eq!(request.len(), bound);
    let refused = arrive(&mut endpoint, request.as_bytes(), t0);
    assert!(
        matches!(
            refused,
            Err(ReceiveError::Malformed(
                ParseError::HeaderValueTooLong { .. }
            ))
        ),
        "{refused:?}"
    );
    dropped_unanswered(&mut endpoint);
}

#[test]
fn the_smallest_answerable_request_gets_back_under_two_and_a_half_times_its_size() {
    // a forged source address aims the answer at whoever owns it. The answer
    // is the request's own five fields plus a status line, a tag and a
    // `Content-Length`, so only a request of little else than those comes
    // back larger, and this one is as little as can be answered: compact
    // names, one bad line, 66 bytes answered with 156
    // (`docs/20-security-model.md`)
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let request = b"A a:b SIP/2.0\r\n\
v:SIP/2.0/UDP a\r\n\
f:a:b\r\n\
t:a:b\r\n\
i:c\r\n\
CSeq:1 A\r\n\
x\r\n\
\r\n";
    assert!(arrive(&mut endpoint, request, t0).is_err());
    let answer = sent(&mut endpoint);
    assert_eq!(status_of(&answer).0, Some(StatusCode::BAD_REQUEST));
    assert!(
        2 * answer.len() < 5 * request.len(),
        "{} bytes answered with {}",
        request.len(),
        answer.len()
    );
}

#[test]
fn a_via_inside_the_bound_still_routes_the_answer_as_section_18_2_2_says() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let head = format!(
        "Via: SIP/2.0/UDP 192.0.2.9:5070;branch=z9hG4bKok1\r\n{}",
        past_the_bound("Subject")
    );
    let _ = arrive(&mut endpoint, &options(&head), t0);
    let out = transmits(&mut endpoint);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out.first().map(|t| t.destination),
        Some("192.0.2.9:5070".parse().expect("an address")),
        "the source's address, sent-by's port"
    );
}

#[test]
fn a_refused_request_on_a_stream_is_answered_and_the_connection_reads_on() {
    let t0 = Instant::now();
    let mut endpoint = on_a_stream(EndpointConfig::default(), t0);
    let tcp = |bytes: Vec<u8>| {
        String::from_utf8(bytes)
            .expect("text")
            .replace("SIP/2.0/UDP", "SIP/2.0/TCP")
            .into_bytes()
    };
    let mut bytes = tcp(with_a_long_subject("OPTIONS", "t1", 20_000));
    bytes.extend_from_slice(&tcp(incoming("OPTIONS", "t2", "")));
    // in pieces, the way a socket reads them
    for piece in bytes.chunks(1_500) {
        stream(&mut endpoint, piece, t0).expect("the connection stays");
    }

    let (status, phrase) = status_of(&sent(&mut endpoint));
    assert_eq!(status, Some(StatusCode::BAD_REQUEST));
    assert_eq!(
        phrase,
        format!(
            "Subject Too Long (limit {} bytes)",
            Limits::DEFAULT.max_header_value_bytes
        )
    );
    let taken = events(&mut endpoint)
        .iter()
        .filter(|event| matches!(event, Event::IncomingOutOfDialog { .. }))
        .count();
    assert_eq!(taken, 1, "the request behind it is read");
    assert_eq!(endpoint.unreadable(), 1);
}

#[test]
fn a_request_on_a_stream_longer_than_the_bound_is_answered_513_and_its_body_passed_over() {
    let t0 = Instant::now();
    let config = EndpointConfig {
        limits: Limits {
            max_message_bytes: 4_096,
            ..Limits::DEFAULT
        },
        ..EndpointConfig::default()
    };
    let mut endpoint = on_a_stream(config, t0);
    let body = vec![b'x'; 10_000];
    let mut bytes = String::from_utf8(incoming("MESSAGE", "big", ""))
        .expect("text")
        .replace("SIP/2.0/UDP", "SIP/2.0/TCP")
        .replace(
            "Content-Length: 0",
            &format!("Content-Type: text/plain\r\nContent-Length: {}", body.len()),
        )
        .into_bytes();
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(
        String::from_utf8(incoming("OPTIONS", "after", ""))
            .expect("text")
            .replace("SIP/2.0/UDP", "SIP/2.0/TCP")
            .as_bytes(),
    );
    for piece in bytes.chunks(1_000) {
        stream(&mut endpoint, piece, t0).expect("the connection stays");
    }

    let (status, phrase) = status_of(&sent(&mut endpoint));
    assert_eq!(status, Some(StatusCode::MESSAGE_TOO_LARGE));
    assert_eq!(phrase, "Message Too Large (limit 4096 bytes)");
    let taken = events(&mut endpoint)
        .iter()
        .filter(|event| matches!(event, Event::IncomingOutOfDialog { .. }))
        .count();
    assert_eq!(taken, 1, "the OPTIONS after the body is read, and only it");
}
