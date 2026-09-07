// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The endpoint, driven the way a caller drives it.
//!
//! Every test here is a scripted exchange on a fake clock: bytes in, bytes and
//! events out, time advanced by hand. No socket is opened and nothing sleeps,
//! so a timer diagram from RFC 3261 §17 runs in microseconds and a race that
//! happens once a month in the field happens on demand.
//!
//! The responses are fabricated from the bytes the endpoint actually wrote —
//! the `Via` is copied from the request rather than composed — because a test
//! that writes its own `Via` is a test that passes while the branch is wrong.

use super::{
    DialogEndReason, Endpoint, EndpointConfig, Event, FailureReason, Input,
    OutgoingInDialogRequest, OutgoingRequest, OutgoingResponse, TerminationReason, Transmit,
    TransportId, TransportProtocol,
};
use crate::msg::{HeaderName, Method, ParseMode, ParseScratch, RawMessage, StatusCode, Uri, parse};
use crate::transaction::{
    AnyTransactionId, DialogId, InviteClientState, NonInviteClientState, TransactionId,
};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const UDP: TransportId = TransportId(1);
const TCP: TransportId = TransportId(2);
const T1: Duration = Duration::from_millis(500);

pub(super) fn local() -> SocketAddr {
    "192.0.2.1:5060".parse().expect("a local address")
}

pub(super) fn peer() -> SocketAddr {
    "192.0.2.9:5060".parse().expect("a peer address")
}

/// An endpoint with one UDP transport bound, at `t0`.
pub(super) fn endpoint(now: Instant) -> Endpoint {
    let mut endpoint = Endpoint::new(EndpointConfig::default(), [7; 32]);
    endpoint
        .receive(
            Input::TransportBound {
                transport: UDP,
                protocol: TransportProtocol::Udp,
                local: local(),
                remote: None,
            },
            now,
        )
        .expect("binding a transport");
    endpoint
}

fn uri(text: &str) -> Uri {
    Uri::parse_str(text).expect("a URI")
}

/// An INVITE to the peer, with the two fields the endpoint insists on.
pub(super) fn invite_request() -> OutgoingRequest {
    request(Method::Invite)
}

/// An OPTIONS to the peer.
pub(super) fn options_request() -> OutgoingRequest {
    request(Method::Options)
}

/// A REGISTER to the registrar at `example.com`.
pub(super) fn register_request() -> OutgoingRequest {
    OutgoingRequest::new(Method::Register, uri("sip:example.com"), UDP, peer())
        .to(b"<sip:alice@example.com>")
        .from(b"Alice <sip:alice@example.com>")
        .contact(b"<sip:alice@192.0.2.1>")
}

fn request(method: Method<'_>) -> OutgoingRequest {
    OutgoingRequest::new(method, uri("sip:bob@example.com"), UDP, peer())
        .to(b"<sip:bob@example.com>")
        .from(b"Alice <sip:alice@example.com>")
}

/// Everything the endpoint wants written, drained.
pub(super) fn transmits(endpoint: &mut Endpoint) -> Vec<Transmit> {
    let mut out = Vec::new();
    while let Some(transmit) = endpoint.poll_transmit() {
        out.push(transmit);
    }
    out
}

/// Everything the endpoint wants said, drained.
pub(super) fn events(endpoint: &mut Endpoint) -> Vec<Event> {
    let mut out = Vec::new();
    while let Some(event) = endpoint.poll_event() {
        out.push(event);
    }
    out
}

/// The one message the endpoint wanted written.
pub(super) fn sent(endpoint: &mut Endpoint) -> Vec<u8> {
    let mut all = transmits(endpoint);
    assert_eq!(all.len(), 1, "expected exactly one message out");
    all.pop().map(|t| t.payload.to_vec()).unwrap_or_default()
}

pub(super) fn with<T>(bytes: &[u8], f: impl FnOnce(&RawMessage<'_>) -> T) -> T {
    let mut scratch = ParseScratch::new();
    let message = parse(bytes, &mut scratch, ParseMode::Lenient).expect("a message");
    f(&message)
}

pub(super) fn header(bytes: &[u8], name: HeaderName<'_>) -> Vec<u8> {
    with(bytes, |message| {
        message.header(name).unwrap_or_default().to_vec()
    })
}

/// A response to a request the endpoint wrote, echoing the fields §8.2.6.2
/// requires and nothing else.
fn respond_to(request: &[u8], status: u16, reason: &str, tag: Option<&str>) -> Vec<u8> {
    let to = {
        let base = String::from_utf8_lossy(&header(request, HeaderName::To)).into_owned();
        match tag {
            Some(tag) => format!("{base};tag={tag}"),
            None => base,
        }
    };
    let mut out = format!("SIP/2.0 {status} {reason}\r\n").into_bytes();
    for (name, value) in [
        ("Via", header(request, HeaderName::Via)),
        ("From", header(request, HeaderName::From)),
        ("To", to.into_bytes()),
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

/// Feed a datagram in from the peer.
pub(super) fn deliver(endpoint: &mut Endpoint, bytes: &[u8], now: Instant) {
    endpoint
        .receive(
            Input::Datagram {
                transport: UDP,
                remote: peer(),
                local: local(),
                data: bytes,
            },
            now,
        )
        .expect("a well formed datagram");
}

/// A request arriving from the peer, with a branch of its own.
pub(super) fn incoming(method: &str, branch: &str, extra: &str) -> Vec<u8> {
    format!(
        "{method} sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK{branch};rport\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bobtag\r\n\
To: Alice <sip:alice@192.0.2.1>\r\n\
{extra}\
Call-ID: incoming-1\r\n\
CSeq: 1 {method}\r\n\
Contact: <sip:bob@192.0.2.9>\r\n\
Content-Length: 0\r\n\
\r\n"
    )
    .into_bytes()
}

// -- the shape of the surface ------------------------------------------------

#[test]
fn a_request_goes_out_with_a_via_the_endpoint_wrote() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let id = endpoint
        .request(&request(Method::Register), t0)
        .expect("the request goes");

    let bytes = sent(&mut endpoint);
    let via = header(&bytes, HeaderName::Via);
    let via = String::from_utf8_lossy(&via);
    assert!(
        via.starts_with("SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK"),
        "{via}"
    );
    assert!(
        via.ends_with(";rport"),
        "RFC 3581 asks on every request: {via}"
    );

    // 8.1.1.3: a request carries a From tag whether or not the caller thought
    // to supply one
    let from = header(&bytes, HeaderName::From);
    assert!(
        String::from_utf8_lossy(&from).contains(";tag="),
        "no From tag"
    );
    assert!(!header(&bytes, HeaderName::CallId).is_empty());
    assert_eq!(
        endpoint.transaction_state(id),
        Some(NonInviteClientState::Trying)
    );
}

#[test]
fn two_requests_never_share_a_branch_or_a_call_id() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.request(&request(Method::Options), t0).ok();
    let first = sent(&mut endpoint);
    endpoint.request(&request(Method::Options), t0).ok();
    let second = sent(&mut endpoint);

    assert_ne!(
        header(&first, HeaderName::Via),
        header(&second, HeaderName::Via)
    );
    assert_ne!(
        header(&first, HeaderName::CallId),
        header(&second, HeaderName::CallId)
    );
}

#[test]
fn a_registration_can_pin_its_call_id_and_its_sequence_number() {
    // 10.2: one Call-ID for every registration to the same registrar, with an
    // increasing CSeq, is how a registrar tells a refresh from a second device
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let call_id = crate::dialog::CallId::new(b"the-registration");
    endpoint
        .request(
            &request(Method::Register).call_id(call_id.clone()).cseq(4),
            t0,
        )
        .expect("the request goes");
    let bytes = sent(&mut endpoint);
    assert_eq!(header(&bytes, HeaderName::CallId), b"the-registration");
    assert_eq!(header(&bytes, HeaderName::CSeq), b"4 REGISTER");
}

#[test]
fn a_request_without_a_to_is_refused_before_anything_is_sent() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let bare = OutgoingRequest::new(Method::Options, uri("sip:bob@example.com"), UDP, peer())
        .from(b"<sip:alice@example.com>");
    assert!(endpoint.request(&bare, t0).is_err());
    assert!(transmits(&mut endpoint).is_empty());
}

#[test]
fn a_request_on_a_transport_nobody_opened_is_refused() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let elsewhere = OutgoingRequest::new(
        Method::Options,
        uri("sip:bob@example.com"),
        TransportId(9),
        peer(),
    )
    .to(b"<sip:bob@example.com>")
    .from(b"<sip:alice@example.com>");
    assert!(endpoint.request(&elsewhere, t0).is_err());
}

// -- responses ---------------------------------------------------------------

#[test]
fn a_final_response_is_reported_and_ends_the_transaction() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let id = endpoint
        .request(&request(Method::Register), t0)
        .expect("the request goes");
    let bytes = sent(&mut endpoint);

    deliver(&mut endpoint, &respond_to(&bytes, 200, "OK", Some("r")), t0);
    let reported = events(&mut endpoint);
    assert!(
        matches!(
            reported.first(),
            Some(Event::Response { transaction, status, .. })
                if *transaction == id && status.get() == 200
        ),
        "{reported:?}"
    );

    // timer K absorbs retransmissions for T4 on UDP, so it is not over yet
    assert_eq!(
        endpoint.transaction_state(id),
        Some(NonInviteClientState::Completed)
    );
    endpoint.handle_timeout(t0 + Duration::from_secs(5));
    assert_eq!(endpoint.transaction_state(id), None);
    assert!(events(&mut endpoint).iter().any(|event| matches!(
        event,
        Event::TransactionTerminated {
            reason: TerminationReason::Completed,
            ..
        }
    )));
}

#[test]
fn a_response_addressed_to_somebody_else_is_discarded() {
    // 18.1.2: "If the value does not match, the response MUST be discarded"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .request(&request(Method::Options), t0)
        .expect("the request goes");
    let bytes = sent(&mut endpoint);

    let mut forged = respond_to(&bytes, 200, "OK", Some("r"));
    forged = String::from_utf8_lossy(&forged)
        .replace("192.0.2.1:5060", "203.0.113.5:5060")
        .into_bytes();
    deliver(&mut endpoint, &forged, t0);
    assert!(events(&mut endpoint).is_empty(), "a stray was taken");
}

#[test]
fn a_response_for_a_branch_nobody_sent_is_ignored() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .request(&request(Method::Options), t0)
        .expect("the request goes");
    let bytes = sent(&mut endpoint);
    let stray = String::from_utf8_lossy(&respond_to(&bytes, 200, "OK", Some("r")))
        .replace("branch=z9hG4bK", "branch=z9hG4bKnope")
        .into_bytes();
    deliver(&mut endpoint, &stray, t0);
    assert!(events(&mut endpoint).is_empty());
}

#[test]
fn a_datagram_that_is_not_a_message_costs_one_packet_and_nothing_else() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    assert!(
        endpoint
            .receive(
                Input::Datagram {
                    transport: UDP,
                    remote: peer(),
                    local: local(),
                    data: b"not a SIP message at all",
                },
                t0,
            )
            .is_err()
    );
    assert!(transmits(&mut endpoint).is_empty());
    assert!(events(&mut endpoint).is_empty());
}

// -- time --------------------------------------------------------------------

#[test]
fn an_invite_retransmits_on_timer_a_and_gives_up_on_timer_b() {
    // the walkthrough in docs/12, run on a fake clock
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let id = endpoint
        .invite(&request(Method::Invite), t0)
        .expect("the INVITE goes");
    let first = sent(&mut endpoint);
    assert_eq!(endpoint.poll_timeout(), Some(t0 + T1));

    endpoint.handle_timeout(t0 + T1);
    let again = sent(&mut endpoint);
    assert_eq!(first, again, "a retransmission has to be the same datagram");
    assert_eq!(
        endpoint.poll_timeout(),
        Some(t0 + 3 * T1),
        "timer A doubles"
    );

    endpoint.handle_timeout(t0 + 64 * T1);
    let events = events(&mut endpoint);
    assert!(
        events.iter().any(|event| matches!(
            event,
            Event::Failed {
                reason: FailureReason::Timeout,
                ..
            }
        )),
        "{events:?}"
    );
    assert_eq!(endpoint.transaction_state(id), None);
}

#[test]
fn a_provisional_response_stops_the_retransmissions_and_the_timeout() {
    // how long to wait for a ringing phone is the user's decision
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let id = endpoint
        .invite(&request(Method::Invite), t0)
        .expect("the INVITE goes");
    let bytes = sent(&mut endpoint);

    deliver(
        &mut endpoint,
        &respond_to(&bytes, 180, "Ringing", Some("desk")),
        t0,
    );
    assert_eq!(endpoint.poll_timeout(), None, "nothing is still ticking");
    assert_eq!(
        endpoint.transaction_state(id),
        Some(InviteClientState::Proceeding)
    );
}

#[test]
fn a_transport_that_fails_takes_its_transactions_with_it() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let id = endpoint
        .request(&request(Method::Options), t0)
        .expect("the request goes");
    transmits(&mut endpoint);

    endpoint
        .receive(
            Input::TransportFailed {
                transport: UDP,
                error: super::TransportErrorKind::ConnectionRefused,
            },
            t0,
        )
        .expect("news about a transport");
    let events = events(&mut endpoint);
    assert!(
        events.iter().any(|event| matches!(
            event,
            Event::RequestFailed {
                reason: FailureReason::TransportFailed,
                ..
            }
        )),
        "{events:?}"
    );
    assert_eq!(endpoint.transaction_state(id), None);
}

// -- a call ------------------------------------------------------------------

/// Place a call and take it to confirmed. Returns the INVITE bytes, the
/// transaction and the dialog.
fn call(
    endpoint: &mut Endpoint,
    now: Instant,
) -> (
    Vec<u8>,
    TransactionId<crate::transaction::InviteClient>,
    DialogId,
) {
    let id = endpoint
        .invite(&request(Method::Invite), now)
        .expect("the INVITE goes");
    let bytes = sent(endpoint);
    deliver(endpoint, &respond_to(&bytes, 200, "OK", Some("desk")), now);

    let dialog = events(endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::Established { dialog, .. } => Some(dialog),
            _ => None,
        })
        .expect("a dialog");
    (bytes, id, dialog)
}

#[test]
fn a_call_is_placed_answered_acknowledged_and_hung_up() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, invite, dialog) = call(&mut endpoint, t0);

    assert_eq!(
        endpoint.transaction_state(invite),
        Some(InviteClientState::Accepted),
        "RFC 6026: a 2xx does not end the transaction"
    );
    assert_eq!(
        endpoint.dialog(dialog).map(|d| d.state),
        Some(crate::dialog::DialogState::Confirmed)
    );

    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    let ack = sent(&mut endpoint);
    assert!(
        ack.starts_with(b"ACK sip:bob@192.0.2.9 SIP/2.0"),
        "the ACK goes to the Contact"
    );
    assert_eq!(header(&ack, HeaderName::CSeq), b"1 ACK");

    let bye = endpoint.bye(dialog, t0).expect("the BYE goes");
    let bytes = sent(&mut endpoint);
    assert!(bytes.starts_with(b"BYE sip:bob@192.0.2.9 SIP/2.0"));
    assert_eq!(header(&bytes, HeaderName::CSeq), b"2 BYE");
    deliver(
        &mut endpoint,
        &respond_to(&bytes, 200, "OK", Some("desk")),
        t0,
    );
    assert!(events(&mut endpoint).iter().any(|event| matches!(
        event,
        Event::Response { transaction, .. } if *transaction == bye
    )));
}

#[test]
fn a_request_inside_a_dialog_takes_its_target_route_and_numbering_from_it() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);

    let info = OutgoingInDialogRequest::new(Method::Extension("INFO")).body(
        b"application/dtmf-relay",
        std::sync::Arc::from(&b"Signal=1"[..]),
    );
    endpoint
        .request_in_dialog(dialog, &info, t0)
        .expect("the request goes");
    let bytes = sent(&mut endpoint);
    assert!(
        bytes.starts_with(b"INFO sip:bob@192.0.2.9 SIP/2.0"),
        "the remote target"
    );
    assert_eq!(header(&bytes, HeaderName::CSeq), b"2 INFO");
    assert_eq!(
        header(&bytes, HeaderName::ContentType),
        b"application/dtmf-relay"
    );
    let snapshot = endpoint.dialog(dialog).expect("a dialog");
    assert_eq!(snapshot.local_seq, Some(2));
}

#[test]
fn a_retransmitted_2xx_is_answered_with_the_same_ack_and_reported_once() {
    // 13.2.2.4: "The ACK MUST be passed to the client transport every time a
    // retransmission of the 2xx final response ... arrives"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (invite_bytes, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    let ack = sent(&mut endpoint);

    let ok = respond_to(&invite_bytes, 200, "OK", Some("desk"));
    deliver(&mut endpoint, &ok, t0);
    let again = transmits(&mut endpoint);
    assert_eq!(again.len(), 1, "the ACK should have gone again");
    assert_eq!(
        again.first().map(|t| t.payload.to_vec()),
        Some(ack),
        "the same bytes, not a new ACK"
    );
    assert!(
        !events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::Established { .. })),
        "the caller heard about this call twice"
    );
}

#[test]
fn acknowledging_twice_is_refused() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    assert!(endpoint.ack_2xx(dialog, None, t0).is_err());
}

#[test]
fn a_fork_produces_one_dialog_per_tag_and_no_winner_is_chosen() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .invite(&request(Method::Invite), t0)
        .expect("the INVITE goes");
    let bytes = sent(&mut endpoint);

    for tag in ["desk", "mobile"] {
        deliver(
            &mut endpoint,
            &respond_to(&bytes, 180, "Ringing", Some(tag)),
            t0,
        );
    }
    let ringing: Vec<_> = events(&mut endpoint)
        .into_iter()
        .filter_map(|event| match event {
            Event::Provisional { dialog, .. } => dialog,
            _ => None,
        })
        .collect();
    assert_eq!(ringing.len(), 2, "two phones are ringing");
    assert_ne!(ringing.first(), ringing.get(1));

    for tag in ["desk", "mobile"] {
        deliver(&mut endpoint, &respond_to(&bytes, 200, "OK", Some(tag)), t0);
    }
    let answered: Vec<_> = events(&mut endpoint)
        .into_iter()
        .filter_map(|event| match event {
            Event::Established { dialog, .. } => Some(dialog),
            _ => None,
        })
        .collect();
    assert_eq!(answered.len(), 2, "both answers have to be acknowledged");
    for dialog in answered {
        endpoint.ack_2xx(dialog, None, t0).expect("each is ACKed");
    }
    assert_eq!(transmits(&mut endpoint).len(), 2);
}

#[test]
fn a_refused_call_is_acknowledged_by_the_transaction_and_reported_once() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let id = endpoint
        .invite(&request(Method::Invite), t0)
        .expect("the INVITE goes");
    let bytes = sent(&mut endpoint);

    let busy = respond_to(&bytes, 486, "Busy Here", Some("desk"));
    deliver(&mut endpoint, &busy, t0);
    let ack = sent(&mut endpoint);
    assert!(ack.starts_with(b"ACK "), "17.1.1.3 builds this one");
    assert!(events(&mut endpoint).iter().any(|event| matches!(
        event,
        Event::Failed { status: Some(status), reason: FailureReason::Refused, .. }
            if status.get() == 486
    )));

    // a retransmission of the refusal is acknowledged again and not reported
    deliver(&mut endpoint, &busy, t0);
    assert_eq!(transmits(&mut endpoint).len(), 1);
    assert!(events(&mut endpoint).is_empty());
    assert_eq!(
        endpoint.transaction_state(id),
        Some(InviteClientState::Completed)
    );
}

#[test]
fn a_cancel_asked_for_too_early_waits_for_the_first_provisional() {
    // 9.1: the server could receive the CANCEL before the INVITE
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let id = endpoint
        .invite(&request(Method::Invite), t0)
        .expect("the INVITE goes");
    let bytes = sent(&mut endpoint);

    endpoint.cancel(id, t0).expect("asking is always accepted");
    assert!(transmits(&mut endpoint).is_empty(), "it went too early");

    deliver(
        &mut endpoint,
        &respond_to(&bytes, 180, "Ringing", Some("desk")),
        t0,
    );
    let cancel = sent(&mut endpoint);
    assert!(cancel.starts_with(b"CANCEL "));
    assert_eq!(
        header(&cancel, HeaderName::Via),
        header(&bytes, HeaderName::Via),
        "the CANCEL shares the INVITE's branch"
    );
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::CancelSent { .. }))
    );

    deliver(
        &mut endpoint,
        &respond_to(&bytes, 487, "Request Terminated", Some("desk")),
        t0,
    );
    let events = events(&mut endpoint);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::Cancelled { .. })),
        "{events:?}"
    );
}

#[test]
fn a_cancel_that_loses_the_race_leaves_a_live_call() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let id = endpoint
        .invite(&request(Method::Invite), t0)
        .expect("the INVITE goes");
    let bytes = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &respond_to(&bytes, 180, "Ringing", Some("desk")),
        t0,
    );
    events(&mut endpoint);
    endpoint.cancel(id, t0).expect("the CANCEL goes");
    transmits(&mut endpoint);
    events(&mut endpoint);

    deliver(
        &mut endpoint,
        &respond_to(&bytes, 200, "OK", Some("desk")),
        t0,
    );
    let events = events(&mut endpoint);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::CancelLostRace { .. })),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::Established { .. }))
    );
}

#[test]
fn cancelling_a_call_that_has_already_been_answered_is_refused() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, invite, _) = call(&mut endpoint, t0);
    assert!(endpoint.cancel(invite, t0).is_err());
}

// -- answering ---------------------------------------------------------------

#[test]
fn a_request_out_of_dialog_is_handed_up_and_answered_where_it_came_from() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    deliver(&mut endpoint, &incoming("OPTIONS", "in1", ""), t0);

    let transaction = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingOutOfDialog { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("an incoming request");

    endpoint
        .respond(transaction, &OutgoingResponse::new(StatusCode::OK), t0)
        .expect("the response goes");
    let out = transmits(&mut endpoint);
    let answer = out.first().expect("one response");
    assert!(answer.payload.starts_with(b"SIP/2.0 200 OK"));
    // rport was asked for, so the answer goes to the port it came from
    assert_eq!(answer.destination, peer());
    assert_eq!(
        answer.source,
        Some(local()),
        "RFC 3581 4: from the same address"
    );
    assert!(
        String::from_utf8_lossy(&header(&answer.payload, HeaderName::To)).contains(";tag="),
        "8.2.6.2 wants a tag on every response but a 100"
    );
}

#[test]
fn a_retransmitted_request_is_answered_from_what_was_already_sent() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let options = incoming("OPTIONS", "in1", "");
    deliver(&mut endpoint, &options, t0);
    let transaction = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingOutOfDialog { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("an incoming request");
    endpoint
        .respond(transaction, &OutgoingResponse::new(StatusCode::OK), t0)
        .expect("the response goes");
    let first = sent(&mut endpoint);

    deliver(&mut endpoint, &options, t0);
    let again = sent(&mut endpoint);
    assert_eq!(first, again, "the same bytes, not a second answer");
    assert!(
        events(&mut endpoint).is_empty(),
        "a retransmission is not a new request"
    );
}

#[test]
fn a_call_that_comes_in_is_answered_and_confirmed_by_its_ack() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let invite = incoming("INVITE", "in2", "");
    deliver(&mut endpoint, &invite, t0);

    // 17.2.1: the 100 Trying goes out at once, without waiting for the user
    let trying = sent(&mut endpoint);
    assert!(trying.starts_with(b"SIP/2.0 100 Trying"));

    let transaction = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingInvite { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("an incoming call");

    endpoint
        .respond_invite(
            transaction,
            &OutgoingResponse::new(StatusCode::RINGING).contact(b"<sip:alice@192.0.2.1>"),
            t0,
        )
        .expect("180 goes");
    let ringing = sent(&mut endpoint);
    assert!(ringing.starts_with(b"SIP/2.0 180 Ringing"));

    let dialog = endpoint
        .respond_invite(
            transaction,
            &OutgoingResponse::new(StatusCode::OK).contact(b"<sip:alice@192.0.2.1>"),
            t0,
        )
        .expect("200 goes")
        .expect("a dialog");
    let ok = sent(&mut endpoint);
    let tag = String::from_utf8_lossy(&header(&ok, HeaderName::To)).into_owned();
    assert!(tag.contains(";tag="), "{tag}");
    assert_eq!(
        header(&ringing, HeaderName::To),
        header(&ok, HeaderName::To),
        "every response of one transaction carries the same tag"
    );

    let our_tag = tag.rsplit(";tag=").next().unwrap_or_default().to_owned();
    let ack = format!(
        "ACK sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKin2ack;rport\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bobtag\r\n\
To: Alice <sip:alice@192.0.2.1>;tag={our_tag}\r\n\
Call-ID: incoming-1\r\n\
CSeq: 1 ACK\r\n\
Content-Length: 0\r\n\
\r\n"
    );
    deliver(&mut endpoint, ack.as_bytes(), t0);
    let events = events(&mut endpoint);
    assert!(
        events.iter().any(|event| matches!(
            event,
            Event::IncomingAck { dialog: acked, .. } if *acked == dialog
        )),
        "{events:?}"
    );
}

#[test]
fn a_cancel_that_arrives_is_answered_and_the_call_is_terminated() {
    // 9.2: 200 for the CANCEL, 487 for the INVITE, both unconditional
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    deliver(&mut endpoint, &incoming("INVITE", "in3", ""), t0);
    transmits(&mut endpoint);
    events(&mut endpoint);

    deliver(&mut endpoint, &incoming("CANCEL", "in3", ""), t0);
    let out = transmits(&mut endpoint);
    let statuses: Vec<_> = out
        .iter()
        .map(|transmit| with(&transmit.payload, |m| m.status().map(StatusCode::get)))
        .collect();
    assert_eq!(statuses, vec![Some(200), Some(487)], "{statuses:?}");
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::IncomingCancel { .. }))
    );
}

#[test]
fn a_bye_that_arrives_ends_the_dialog() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);

    let snapshot = endpoint.dialog(dialog).expect("a dialog");
    let bye = format!(
        "BYE sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKbye1;rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:bob@example.com>;tag=desk\r\n\
To: Alice <sip:alice@example.com>;tag={}\r\n\
Call-ID: {}\r\n\
CSeq: 7 BYE\r\n\
Content-Length: 0\r\n\
\r\n",
        String::from_utf8_lossy(snapshot.local_tag.as_bytes()),
        String::from_utf8_lossy(snapshot.call_id.as_bytes()),
    );
    deliver(&mut endpoint, bye.as_bytes(), t0);

    let events = events(&mut endpoint);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::IncomingBye { .. })),
        "{events:?}"
    );
    assert!(events.iter().any(|event| matches!(
        event,
        Event::DialogTerminated {
            reason: DialogEndReason::RemoteBye,
            ..
        }
    )));
    assert!(endpoint.dialog(dialog).is_none());
}

#[test]
fn an_in_dialog_request_that_runs_backwards_is_answered_500() {
    // 12.2.2: "the request is out of order and MUST be rejected with a 500"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);
    let snapshot = endpoint.dialog(dialog).expect("a dialog");

    let info = |seq: u32| {
        format!(
            "INFO sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKinfo{seq};rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:bob@example.com>;tag=desk\r\n\
To: Alice <sip:alice@example.com>;tag={}\r\n\
Call-ID: {}\r\n\
CSeq: {seq} INFO\r\n\
Content-Length: 0\r\n\
\r\n",
            String::from_utf8_lossy(snapshot.local_tag.as_bytes()),
            String::from_utf8_lossy(snapshot.call_id.as_bytes()),
        )
    };

    deliver(&mut endpoint, info(9).as_bytes(), t0);
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::IncomingInDialog { .. }))
    );
    transmits(&mut endpoint);

    deliver(&mut endpoint, info(3).as_bytes(), t0);
    let out = transmits(&mut endpoint);
    assert_eq!(
        out.first()
            .and_then(|t| with(&t.payload, |m| m.status().map(StatusCode::get))),
        Some(500)
    );
}

// -- transports --------------------------------------------------------------

#[test]
fn a_request_too_large_for_a_datagram_moves_to_a_stream() {
    // 18.1.1: "the request MUST be sent using an RFC 2914 congestion
    // controlled transport protocol, such as TCP"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .receive(
            Input::TransportBound {
                transport: TCP,
                protocol: TransportProtocol::Tcp,
                local: local(),
                remote: Some(peer()),
            },
            t0,
        )
        .expect("binding TCP");
    transmits(&mut endpoint);

    let padding = vec![b'x'; 1_400];
    let big = request(Method::Options).header(HeaderName::Subject, &padding);
    endpoint.request(&big, t0).expect("the request goes");
    let out = transmits(&mut endpoint);
    let sent = out.first().expect("one message");
    assert_eq!(sent.transport, TCP);
    assert_eq!(sent.protocol, TransportProtocol::Tcp);
    assert!(
        String::from_utf8_lossy(&header(&sent.payload, HeaderName::Via)).contains("SIP/2.0/TCP"),
        "the top Via has to say which transport it went over"
    );
}

#[test]
fn a_request_too_large_with_nowhere_to_move_it_asks_for_a_transport() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let padding = vec![b'x'; 1_400];
    let big = request(Method::Options).header(HeaderName::Subject, &padding);
    assert!(endpoint.request(&big, t0).is_err());
    let events = events(&mut endpoint);
    assert!(
        events.iter().any(|event| matches!(
            event,
            Event::TransportWanted {
                protocol: TransportProtocol::Tcp,
                ..
            }
        )),
        "{events:?}"
    );
}

#[test]
fn two_messages_in_one_read_are_both_taken() {
    let t0 = Instant::now();
    let mut endpoint = Endpoint::new(EndpointConfig::default(), [3; 32]);
    endpoint
        .receive(
            Input::TransportBound {
                transport: TCP,
                protocol: TransportProtocol::Tcp,
                local: local(),
                remote: Some(peer()),
            },
            t0,
        )
        .expect("binding TCP");
    transmits(&mut endpoint);

    let mut stream = incoming("OPTIONS", "s1", "");
    stream.extend_from_slice(&incoming("MESSAGE", "s2", ""));
    endpoint
        .receive(
            Input::StreamData {
                transport: TCP,
                data: &stream,
            },
            t0,
        )
        .expect("two whole messages");
    let events = events(&mut endpoint);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::IncomingOutOfDialog { .. }))
            .count(),
        2,
        "{events:?}"
    );
}

#[test]
fn a_ping_on_a_stream_is_answered_with_a_single_crlf() {
    // RFC 5626 4.4.1 makes the pong a MUST
    let t0 = Instant::now();
    let mut endpoint = Endpoint::new(EndpointConfig::default(), [4; 32]);
    endpoint
        .receive(
            Input::TransportBound {
                transport: TCP,
                protocol: TransportProtocol::Tcp,
                local: local(),
                remote: Some(peer()),
            },
            t0,
        )
        .expect("binding TCP");
    transmits(&mut endpoint);

    endpoint
        .receive(
            Input::StreamData {
                transport: TCP,
                data: b"\r\n\r\n",
            },
            t0,
        )
        .expect("a ping");
    let out = transmits(&mut endpoint);
    assert_eq!(
        out.first().map(|t| t.payload.to_vec()),
        Some(b"\r\n".to_vec())
    );
}

#[test]
fn a_stream_transport_is_pinged_on_a_jittered_interval() {
    let t0 = Instant::now();
    let mut endpoint = Endpoint::new(EndpointConfig::default(), [5; 32]);
    endpoint
        .receive(
            Input::TransportBound {
                transport: TCP,
                protocol: TransportProtocol::Tcp,
                local: local(),
                remote: Some(peer()),
            },
            t0,
        )
        .expect("binding TCP");

    let due = endpoint.poll_timeout().expect("a keepalive is due");
    assert!(due <= t0 + Duration::from_secs(25), "above the bound");
    assert!(due >= t0 + Duration::from_secs(20), "more than 20% below");

    endpoint.handle_timeout(due);
    let out = transmits(&mut endpoint);
    assert_eq!(
        out.first().map(|t| t.payload.to_vec()),
        Some(b"\r\n\r\n".to_vec())
    );
    let next = endpoint.poll_timeout().expect("and again");
    assert!(next > due, "the keepalive rearmed itself");
}

#[test]
fn a_datagram_transport_is_never_pinged() {
    // "MUST only be used with connection oriented transports"
    let t0 = Instant::now();
    let endpoint = endpoint(t0);
    assert_eq!(endpoint.poll_timeout(), None);
}

#[test]
fn a_lost_transport_takes_its_keepalive_deadline_with_it() {
    let t0 = Instant::now();
    let mut endpoint = Endpoint::new(EndpointConfig::default(), [6; 32]);
    endpoint
        .receive(
            Input::TransportBound {
                transport: TCP,
                protocol: TransportProtocol::Tcp,
                local: local(),
                remote: Some(peer()),
            },
            t0,
        )
        .expect("binding TCP");
    assert!(endpoint.poll_timeout().is_some());

    endpoint
        .receive(Input::StreamClosed { transport: TCP }, t0)
        .expect("news about a transport");
    assert_eq!(
        endpoint.poll_timeout(),
        None,
        "a deadline was left on a transport that is gone"
    );
}

#[test]
fn nothing_is_left_in_flight_when_a_call_is_over() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);

    let bye = endpoint.bye(dialog, t0).expect("the BYE goes");
    let bytes = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &respond_to(&bytes, 200, "OK", Some("desk")),
        t0,
    );
    let _ = bye;

    // timer M on the INVITE, timer K on the BYE
    endpoint.handle_timeout(t0 + Duration::from_secs(64));
    events(&mut endpoint);
    assert_eq!(endpoint.in_flight(), (0, 0));
}

#[test]
fn a_stale_handle_answers_to_nothing() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let id = endpoint
        .request(&request(Method::Options), t0)
        .expect("the request goes");
    transmits(&mut endpoint);
    endpoint.handle_timeout(t0 + Duration::from_secs(64));
    events(&mut endpoint);

    assert_eq!(endpoint.transaction_state(id), None);
    let stale: AnyTransactionId = id.into();
    assert_eq!(stale.kind_name(), "non-INVITE client");
}
