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
    DatagramLimit, DialogEndReason, DialogSnapshot, Endpoint, EndpointConfig, Event, FailureReason,
    Input, OutgoingInDialogRequest, OutgoingRequest, OutgoingResponse, TerminationReason, Transmit,
    TransportId, TransportProtocol,
};
use crate::msg::{HeaderName, Method, ParseMode, ParseScratch, RawMessage, StatusCode, Uri, parse};
use crate::transaction::{
    AnyTransactionId, DialogId, InviteClient, InviteClientState, NonInviteClientState,
    NonInviteServerState, TimerConfigError, TransactionId,
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
    let mut endpoint = Endpoint::new(EndpointConfig::default(), [7; 32]).unwrap();
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
pub(super) fn respond_to(request: &[u8], status: u16, reason: &str, tag: Option<&str>) -> Vec<u8> {
    respond_with(request, status, reason, tag, "")
}

/// The same, with `extra` — already CRLF terminated — after the fields
/// §8.2.6.2 requires.
fn respond_with(
    request: &[u8],
    status: u16,
    reason: &str,
    tag: Option<&str>,
    extra: &str,
) -> Vec<u8> {
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
    out.extend_from_slice(extra.as_bytes());
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
    assert_eq!(
        endpoint.retransmissions().requests,
        1,
        "the ACK sent again is counted as a request sent again"
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
fn a_2xx_after_a_refusal_is_reported_as_the_dialog_it_opened() {
    // a proxy forwards every 2xx, even after it has sent a final response
    // upstream (§16.7 step 5), and RFC 6026 §8.4 re-sends the refusal's ACK
    // only for a retransmitted 300-699. This one opens a dialog the layer
    // above has to acknowledge and end (§13.2.2.4); answering it with the
    // 486's ACK left it retransmitting at the far end with nobody told
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let id = endpoint
        .invite(&request(Method::Invite), t0)
        .expect("the INVITE goes");
    let bytes = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &respond_to(&bytes, 486, "Busy Here", Some("desk")),
        t0,
    );
    transmits(&mut endpoint);
    events(&mut endpoint);

    deliver(
        &mut endpoint,
        &respond_to(&bytes, 200, "OK", Some("mobile")),
        t0,
    );
    assert!(
        transmits(&mut endpoint).is_empty(),
        "the 486's ACK is not an ACK for a 2xx"
    );
    let dialog = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::Established { invite, dialog, .. } if invite == id => Some(dialog),
            _ => None,
        })
        .expect("the 2xx is reported");
    endpoint
        .ack_2xx(dialog, None, t0)
        .expect("the dialog it opened takes its ACK");
    let ack = sent(&mut endpoint);
    assert!(ack.starts_with(b"ACK "));
    assert!(
        String::from_utf8_lossy(&header(&ack, HeaderName::To)).contains("tag=mobile"),
        "{}",
        String::from_utf8_lossy(&ack)
    );
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

    // RFC 6026's timer L ends the transaction the 2xx left in Accepted. The
    // ACK came under a branch of its own and never matched it, and it is
    // still the ACK: nothing timed out, and the record does not say one did
    endpoint.handle_timeout(t0 + 64 * T1);
    assert!(
        transmits(&mut endpoint).is_empty(),
        "the 2xx does not go again once its ACK has come"
    );
    assert_eq!(endpoint.in_flight().0, 0, "timer L ended the transaction");
    assert_eq!(endpoint.retransmissions().timeouts, 0);
    let unacknowledged = endpoint
        .call_record(&crate::dialog::CallId::new(b"incoming-1"))
        .expect("a record for the call")
        .decisions()
        .filter(|decision| decision.reason.as_str() == "transaction.unacknowledged")
        .count();
    assert_eq!(unacknowledged, 0);
}

#[test]
fn a_2xx_goes_again_until_timer_l_and_is_then_a_timeout() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    deliver(&mut endpoint, &incoming("INVITE", "in3", ""), t0);
    let transaction = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingInvite { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("an incoming call");
    transmits(&mut endpoint);
    endpoint
        .respond_invite(
            transaction,
            &OutgoingResponse::new(StatusCode::OK).contact(b"<sip:alice@192.0.2.1>"),
            t0,
        )
        .expect("200 goes");
    let ok = sent(&mut endpoint);

    // §13.3.1.4: lost on the way, the 2xx goes again T1 later, the same bytes
    endpoint.handle_timeout(t0 + T1);
    assert_eq!(sent(&mut endpoint), ok);
    assert_eq!(endpoint.retransmissions().responses, 1);

    for step in 2..=64_u32 {
        endpoint.handle_timeout(t0 + step * T1);
    }
    assert!(
        transmits(&mut endpoint).len() > 1,
        "on timer G's schedule until timer L"
    );
    assert_eq!(endpoint.retransmissions().timeouts, 1);
}

#[test]
fn the_same_ack_arriving_twice_is_reported_once() {
    // §13.2.2.4 has the caller send its ACK again for every copy of the 2xx it
    // sees, so a 2xx repeated before the first ACK arrived earns a second one;
    // it acknowledges nothing new
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    deliver(&mut endpoint, &incoming("INVITE", "twice", ""), t0);
    transmits(&mut endpoint);
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
            &OutgoingResponse::new(StatusCode::OK).contact(b"<sip:alice@192.0.2.1>"),
            t0,
        )
        .expect("200 goes")
        .expect("a dialog");
    let ok = sent(&mut endpoint);
    let to = String::from_utf8_lossy(&header(&ok, HeaderName::To)).into_owned();
    let our_tag = to.rsplit(";tag=").next().unwrap_or_default().to_owned();
    let ack = format!(
        "ACK sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKtwiceack;rport\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bobtag\r\n\
To: Alice <sip:alice@192.0.2.1>;tag={our_tag}\r\n\
Call-ID: incoming-1\r\n\
CSeq: 1 ACK\r\n\
Content-Length: 0\r\n\
\r\n"
    );

    deliver(&mut endpoint, ack.as_bytes(), t0);
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::IncomingAck { .. })),
        "the first ACK confirms the call"
    );
    deliver(&mut endpoint, ack.as_bytes(), t0 + T1);
    let again = events(&mut endpoint);
    assert!(
        again
            .iter()
            .all(|event| !matches!(event, Event::IncomingAck { .. })),
        "a repeat of the ACK already reported was reported again: {again:?}"
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
fn the_200_to_a_cancel_carries_the_tag_of_the_invites_own_responses() {
    // §9.2: "The To tag of the response to the CANCEL and the To tag in the
    // response to the original request SHOULD be the same"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    deliver(&mut endpoint, &incoming("INVITE", "in9", ""), t0);
    transmits(&mut endpoint);
    let invite = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingInvite { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("the INVITE is handed up");
    endpoint
        .respond_invite(
            invite,
            &OutgoingResponse::new(StatusCode::RINGING).contact(b"<sip:alice@192.0.2.1>"),
            t0,
        )
        .expect("it rings");
    let ringing = sent(&mut endpoint);

    deliver(&mut endpoint, &incoming("CANCEL", "in9", ""), t0);
    let out = transmits(&mut endpoint);
    let tag_of = |bytes: &[u8]| {
        with(bytes, |m| {
            m.to().ok().and_then(|to| to.tag().map(|t| t.to_vec()))
        })
    };
    let tags: Vec<_> = out
        .iter()
        .map(|transmit| tag_of(&transmit.payload))
        .collect();
    let rung = tag_of(&ringing).expect("the 180 is tagged");
    assert_eq!(
        tags,
        vec![Some(rung.clone()), Some(rung)],
        "200 to the CANCEL, then 487"
    );

    // and a CANCEL for an INVITE nothing but a 100 has answered shares the
    // tag with the 487 all the same
    let mut endpoint = self::endpoint(t0);
    deliver(&mut endpoint, &incoming("INVITE", "in10", ""), t0);
    transmits(&mut endpoint);
    events(&mut endpoint);
    deliver(&mut endpoint, &incoming("CANCEL", "in10", ""), t0);
    let out = transmits(&mut endpoint);
    let tags: Vec<_> = out
        .iter()
        .map(|transmit| tag_of(&transmit.payload))
        .collect();
    assert_eq!(tags.len(), 2);
    assert!(tags.first().is_some_and(Option::is_some));
    assert_eq!(tags.first(), tags.get(1), "{tags:?}");
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

#[test]
fn a_dialog_full_of_non_invite_transactions_is_refused_with_a_retryable_503() {
    // each dialog's own budget, distinct from the endpoint-wide ceiling a
    // request inside a dialog is exempt from
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);
    let snapshot = endpoint.dialog(dialog).expect("a dialog");

    // sixteen fresh branches fill the dialog's own budget, and every one of
    // them is handed up rather than refused
    let mut transactions = Vec::new();
    for seq in 1..=16_u32 {
        deliver(
            &mut endpoint,
            dialog_info(&snapshot, &format!("full{seq}"), seq).as_bytes(),
            t0,
        );
        let transaction = events(&mut endpoint)
            .into_iter()
            .find_map(|event| match event {
                Event::IncomingInDialog { transaction, .. } => Some(transaction),
                _ => None,
            })
            .unwrap_or_else(|| panic!("INFO {seq} should have been handed up"));
        transactions.push(transaction);
        assert!(
            transmits(&mut endpoint).is_empty(),
            "INFO {seq} was refused"
        );
    }

    // the seventeenth finds no room in this dialog's own budget and is
    // answered 503 with a Retry-After, unlike the endpoint-wide ceiling's
    // refusal, because RFC 5057 has that end only the transaction
    deliver(
        &mut endpoint,
        dialog_info(&snapshot, "over", 17).as_bytes(),
        t0,
    );
    assert!(
        events(&mut endpoint)
            .iter()
            .all(|event| !matches!(event, Event::IncomingInDialog { .. })),
        "the seventeenth should have been refused, not handed up"
    );
    let refusal = sent(&mut endpoint);
    assert!(
        refusal.starts_with(b"SIP/2.0 503 "),
        "{}",
        String::from_utf8_lossy(&refusal)
    );
    assert_eq!(
        header(&refusal, HeaderName::RetryAfter),
        b"1",
        "the call underneath this refusal is not one to be sent away from"
    );
    assert_eq!(
        endpoint.dialog(dialog).map(|d| d.state),
        Some(crate::dialog::DialogState::Confirmed),
        "RFC 5057: a 503 on the transaction leaves the dialog standing"
    );

    // once the first of the sixteen actually retires - answered, and its
    // absorbing timer run out - the next fresh branch is accepted
    endpoint
        .respond(transactions[0], &OutgoingResponse::new(StatusCode::OK), t0)
        .expect("the INFO is answered");
    transmits(&mut endpoint);
    endpoint.handle_timeout(t0 + T1 * 64);
    transmits(&mut endpoint);

    deliver(
        &mut endpoint,
        dialog_info(&snapshot, "after", 18).as_bytes(),
        t0 + T1 * 64,
    );
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::IncomingInDialog { .. })),
        "a slot given back by retirement should have been accepted"
    );
}

/// An in-dialog INFO from `bobtag`, addressed to whichever dialog `snapshot`
/// names, with a fresh branch and sequence number.
fn dialog_info(snapshot: &DialogSnapshot, branch: &str, seq: u32) -> String {
    format!(
        "INFO sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK{branch};rport\r\n\
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
}

/// RFC 3261 §15.1.1: the caller considers the session terminated the moment
/// it sends a BYE, whatever answer comes back — so a BYE draws from no
/// per-dialog budget at all, unlike every other non-INVITE request, which
/// the seventeenth INFO here still finds refused.
#[test]
fn a_bye_is_accepted_even_when_the_dialogs_non_invite_budget_is_full() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);
    let snapshot = endpoint.dialog(dialog).expect("a dialog");

    // sixteen fresh branches fill the dialog's own budget
    for seq in 1..=16_u32 {
        deliver(
            &mut endpoint,
            dialog_info(&snapshot, &format!("full{seq}"), seq).as_bytes(),
            t0,
        );
        events(&mut endpoint);
        transmits(&mut endpoint);
    }

    // a seventeenth INFO still finds no room: the budget itself is
    // unmoved, only BYE is exempt from it
    deliver(
        &mut endpoint,
        dialog_info(&snapshot, "over", 17).as_bytes(),
        t0,
    );
    assert!(
        events(&mut endpoint)
            .iter()
            .all(|event| !matches!(event, Event::IncomingInDialog { .. })),
        "a seventeenth INFO should still be refused while the budget is full"
    );
    let refusal = sent(&mut endpoint);
    assert!(
        refusal.starts_with(b"SIP/2.0 503 "),
        "{}",
        String::from_utf8_lossy(&refusal)
    );

    // the BYE that ends the same dialog, with the same sixteen still open,
    // is accepted rather than refused
    let bye = format!(
        "BYE sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKbye1;rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:bob@example.com>;tag=desk\r\n\
To: Alice <sip:alice@example.com>;tag={}\r\n\
Call-ID: {}\r\n\
CSeq: 18 BYE\r\n\
Content-Length: 0\r\n\
\r\n",
        String::from_utf8_lossy(snapshot.local_tag.as_bytes()),
        String::from_utf8_lossy(snapshot.call_id.as_bytes()),
    );
    deliver(&mut endpoint, bye.as_bytes(), t0);

    let raised = events(&mut endpoint);
    let transaction = raised
        .iter()
        .find_map(|event| match event {
            Event::IncomingBye { transaction, .. } => Some(*transaction),
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!("the BYE should have been handed up rather than refused: {raised:?}")
        });
    assert!(
        endpoint.dialog(dialog).is_none(),
        "the dialog should already be gone once the BYE is handed up (§15.1.2)"
    );

    endpoint
        .respond(transaction, &OutgoingResponse::new(StatusCode::OK), t0)
        .expect("the BYE is answered");
    let answered = sent(&mut endpoint);
    assert!(
        answered.starts_with(b"SIP/2.0 200 "),
        "{}",
        String::from_utf8_lossy(&answered)
    );
}

/// A BYE is let past a full budget only because it ends the dialog, and the
/// budget with it. One whose `CSeq` runs backwards ends nothing — §12.2.2
/// answers it 500 and leaves the dialog as it was — so a peer inside the
/// dialog that keeps sending those would otherwise open server transactions
/// without any ceiling at all, the flood the budget exists to stop.
#[test]
fn a_bye_that_runs_backwards_is_held_to_the_dialogs_budget() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);
    let snapshot = endpoint.dialog(dialog).expect("a dialog");

    for seq in 1..=16_u32 {
        deliver(
            &mut endpoint,
            dialog_info(&snapshot, &format!("full{seq}"), seq).as_bytes(),
            t0,
        );
        events(&mut endpoint);
        transmits(&mut endpoint);
    }

    // numbered below the sixteen the dialog has already seen: each one is
    // refused statelessly, and none of them opens a transaction
    for stale in 1..=8_u32 {
        deliver(
            &mut endpoint,
            dialog_bye(&snapshot, &format!("stale{stale}"), 1).as_bytes(),
            t0,
        );
        assert!(
            events(&mut endpoint)
                .iter()
                .all(|event| !matches!(event, Event::IncomingBye { .. })),
            "a BYE that runs backwards ends nothing"
        );
        let refusal = sent(&mut endpoint);
        assert!(
            refusal.starts_with(b"SIP/2.0 503 "),
            "stale BYE {stale} should find the budget full: {}",
            String::from_utf8_lossy(&refusal)
        );
    }
    assert_eq!(
        endpoint.dialog(dialog).map(|d| d.state),
        Some(crate::dialog::DialogState::Confirmed),
        "nothing so far ended the dialog"
    );

    // the BYE that is in order still ends it, full budget or not
    deliver(
        &mut endpoint,
        dialog_bye(&snapshot, "bye", 17).as_bytes(),
        t0,
    );
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::IncomingBye { .. })),
        "the BYE in order should have been handed up"
    );
    assert!(endpoint.dialog(dialog).is_none());
}

/// Over UDP a transaction holds its place in the dialog's budget until Timer
/// J retires it, 64·T1 after its final response (§17.2.2). One the
/// application never answers holds it for 64·T1 until the endpoint's own 408
/// and another 64·T1 after that — 128·T1 in all, the latest docs/03 says
/// room behind the per-dialog 503 can reappear.
#[test]
fn over_udp_an_unanswered_transaction_holds_its_place_until_timer_j() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);
    let snapshot = endpoint.dialog(dialog).expect("a dialog");

    for seq in 1..=16_u32 {
        deliver(
            &mut endpoint,
            dialog_info(&snapshot, &format!("full{seq}"), seq).as_bytes(),
            t0,
        );
        events(&mut endpoint);
        transmits(&mut endpoint);
    }

    // the endpoint answers all sixteen 408 on the application's behalf
    endpoint.handle_timeout(t0 + T1 * 64);
    assert_eq!(
        transmits(&mut endpoint).len(),
        16,
        "one 408 for each unanswered INFO"
    );

    // answered now, but each is still absorbing retransmissions in Completed
    deliver(
        &mut endpoint,
        dialog_info(&snapshot, "answered", 17).as_bytes(),
        t0 + T1 * 64,
    );
    assert!(
        events(&mut endpoint)
            .iter()
            .all(|event| !matches!(event, Event::IncomingInDialog { .. })),
        "a 408 alone gives no place back while Timer J still runs"
    );
    let refusal = sent(&mut endpoint);
    assert!(
        refusal.starts_with(b"SIP/2.0 503 "),
        "{}",
        String::from_utf8_lossy(&refusal)
    );

    // Timer J has let every one of them go
    endpoint.handle_timeout(t0 + T1 * 128);
    transmits(&mut endpoint);
    deliver(
        &mut endpoint,
        dialog_info(&snapshot, "retired", 18).as_bytes(),
        t0 + T1 * 128,
    );
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::IncomingInDialog { .. })),
        "room should be back once Timer J has retired the sixteen"
    );
}

/// An in-dialog BYE from `bobtag`, addressed to whichever dialog `snapshot`
/// names, with a fresh branch and the given sequence number.
fn dialog_bye(snapshot: &DialogSnapshot, branch: &str, seq: u32) -> String {
    dialog_info(snapshot, branch, seq)
        .replacen("INFO sip:", "BYE sip:", 1)
        .replace(" INFO\r\n", " BYE\r\n")
}

#[test]
fn another_dialogs_budget_is_unaffected_by_a_full_one() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, full) = call(&mut endpoint, t0);
    endpoint.ack_2xx(full, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);
    let snapshot = endpoint.dialog(full).expect("a dialog");
    for seq in 1..=16_u32 {
        deliver(
            &mut endpoint,
            dialog_info(&snapshot, &format!("full{seq}"), seq).as_bytes(),
            t0,
        );
        events(&mut endpoint);
        transmits(&mut endpoint);
    }

    let (_, _, other) = call(&mut endpoint, t0);
    endpoint.ack_2xx(other, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);
    let other_snapshot = endpoint.dialog(other).expect("a dialog");
    deliver(
        &mut endpoint,
        dialog_info(&other_snapshot, "other1", 1).as_bytes(),
        t0,
    );
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::IncomingInDialog { .. })),
        "another dialog must not be affected by the first one's budget"
    );
}

#[test]
fn a_non_invite_request_the_application_never_answers_gets_a_408() {
    // §17.2.2 gives Trying/Proceeding no timer of its own, so an application
    // that never answers would otherwise hold the slot for the life of the
    // process
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    deliver(&mut endpoint, &incoming("OPTIONS", "unanswered", ""), t0);
    let transaction = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingOutOfDialog { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("an out-of-dialog OPTIONS");
    assert!(
        transmits(&mut endpoint).is_empty(),
        "nothing answers it until the application does, or the deadline does"
    );

    // well before 64*T1 nothing happens: the client itself would still be
    // retrying at this point
    endpoint.handle_timeout(t0 + T1 * 63);
    assert!(transmits(&mut endpoint).is_empty());
    assert_eq!(
        endpoint.transaction_state(transaction),
        Some(NonInviteServerState::Trying)
    );

    endpoint.handle_timeout(t0 + T1 * 64);
    let answer = sent(&mut endpoint);
    assert!(
        answer.starts_with(b"SIP/2.0 408 "),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert_eq!(
        endpoint.transaction_state(transaction),
        Some(NonInviteServerState::Completed)
    );

    let record = endpoint
        .call_record(&crate::dialog::CallId::new(b"incoming-1"))
        .expect("a record for this call-id");
    assert!(
        record
            .decisions()
            .any(|decision| decision.reason == crate::diag::Reason::RequestAnsweredByTimeout),
        "{record:?}"
    );

    // an application that did answer in time is left alone: firing the same
    // deadline against an already-completed transaction is a no-op. A
    // Call-ID of its own, or §8.2.2.2 would take it for a second copy of the
    // first OPTIONS, whose transaction is still absorbing retransmissions
    let answered_options = String::from_utf8_lossy(&incoming("OPTIONS", "answered", ""))
        .replace("Call-ID: incoming-1", "Call-ID: incoming-2");
    deliver(&mut endpoint, answered_options.as_bytes(), t0);
    let answered = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingOutOfDialog { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("a second OPTIONS");
    endpoint
        .respond(answered, &OutgoingResponse::new(StatusCode::OK), t0)
        .expect("answered in time");
    transmits(&mut endpoint);
    endpoint.handle_timeout(t0 + T1 * 64);
    assert!(
        transmits(&mut endpoint).is_empty(),
        "an already-answered transaction must not be answered a second time"
    );
}

// -- transports --------------------------------------------------------------

#[test]
fn cancels_that_match_nothing_inside_a_dialog_draw_on_its_budget() {
    // a CANCEL naming a dialog of ours but no transaction in it is a server
    // transaction all the same, answered 481 and held for timer J, and a
    // request inside a dialog is exempt from the endpoint-wide ceiling
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);
    let snapshot = endpoint.dialog(dialog).expect("a dialog");
    for n in 1..=32_u32 {
        let cancel = format!(
            "CANCEL sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKstray{n};rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:bob@example.com>;tag=desk\r\n\
To: Alice <sip:alice@example.com>;tag={}\r\n\
Call-ID: {}\r\n\
CSeq: {n} CANCEL\r\n\
Content-Length: 0\r\n\
\r\n",
            String::from_utf8_lossy(snapshot.local_tag.as_bytes()),
            String::from_utf8_lossy(snapshot.call_id.as_bytes()),
        );
        deliver(&mut endpoint, cancel.as_bytes(), t0);
        transmits(&mut endpoint);
        events(&mut endpoint);
    }
    assert!(
        endpoint.store().servers_len() <= 16,
        "a peer inside the dialog made the endpoint hold {} server transactions",
        endpoint.store().servers_len()
    );
}

#[test]
fn a_request_answered_at_once_over_a_stream_leaves_no_deadline_behind() {
    // timer J is zero on a stream, so a transaction answered at once retires
    // at once; the 64*T1 deadline hung on it for an application that never
    // answers has to go with it, or every request the endpoint answers
    // itself leaves an entry on the schedule for 64*T1, whatever
    // max_server_transactions says
    const REQUESTS: u32 = 64;
    let t0 = Instant::now();
    let mut endpoint = connected(t0);
    for n in 0..REQUESTS {
        let prack = format!(
            "PRACK sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.9:5060;branch=z9hG4bKleak{n}\r\n\
Max-Forwards: 70\r\n\
From: Bob <sip:bob@example.com>;tag=bobtag\r\n\
To: Alice <sip:alice@192.0.2.1>\r\n\
Call-ID: leak-{n}\r\n\
CSeq: 1 PRACK\r\n\
RAck: 1 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n"
        );
        endpoint
            .receive(
                Input::StreamData {
                    transport: TCP,
                    data: prack.as_bytes(),
                },
                t0,
            )
            .expect("a well formed request");
        transmits(&mut endpoint);
        events(&mut endpoint);
    }
    assert_eq!(
        endpoint.store().servers_len(),
        0,
        "every one was answered 481 and retired"
    );

    let mut left = 0;
    while let Some(deadline) = endpoint.deadlines.fire(t0 + T1 * 64) {
        if matches!(deadline, super::driver::Deadline::UnansweredNonInvite(_)) {
            left += 1;
        }
    }
    assert_eq!(
        left, 0,
        "{left} deadlines outlived the transactions they were hung on"
    );
}

#[test]
fn an_endpoint_refuses_a_keepalive_interval_of_zero() {
    // the hang the next test shows, refused before an endpoint is built on it
    let broken = EndpointConfig {
        keepalive_interval: Some(Duration::ZERO),
        ..EndpointConfig::default()
    };
    assert!(Endpoint::new(broken, [23; 32]).is_err());
    let off = EndpointConfig {
        keepalive_interval: None,
        ..EndpointConfig::default()
    };
    assert!(
        Endpoint::new(off, [24; 32]).is_ok(),
        "no keep-alive is fine"
    );
}

#[test]
fn a_zero_keepalive_interval_would_have_pinged_at_the_same_instant_forever() {
    // RFC 5626 §4.4.1's next ping is armed at `now` plus a jitter of the
    // interval, and a jitter of nothing is nothing, so the deadline that just
    // fired is due again at the same instant. Driven the way handle_timeout
    // drives its deadlines, for a bounded number of rounds rather than until
    // it stops, because it never does
    const ROUNDS: u32 = 1_000;
    let t0 = Instant::now();
    let mut endpoint = connected(t0);
    endpoint.config.keepalive_interval = Some(Duration::ZERO);
    endpoint.send_keepalive(TCP, t0);

    let mut fired = 0;
    for _ in 0..ROUNDS {
        let Some(deadline) = endpoint.deadlines.fire(t0) else {
            break;
        };
        if let super::driver::Deadline::Keepalive(transport) = deadline {
            endpoint.send_keepalive(transport, t0);
            fired += 1;
        }
    }
    assert_eq!(
        fired, ROUNDS,
        "the keep-alive stopped re-arming at the same instant on its own"
    );
}

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

/// §18.1.1 at its edge, a few octets either side of it: every request of
/// 1300 bytes or fewer goes in a datagram, and every one of 1301 or more goes
/// on the stream open to the same place — the line drawn on the bytes the
/// datagram would have carried, not on an estimate of them. A stack that
/// rounds, or measures the request before its `Via` is written, sends a
/// message a few bytes over the line as a datagram, which is the one that
/// arrives in fragments and is dropped by the NAT in front of the phone.
#[test]
fn the_move_to_a_stream_happens_at_1301_bytes_and_not_one_byte_sooner() {
    let t0 = Instant::now();
    let mut seen = Vec::new();
    for padding in 940..1_000 {
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
        let big = request(Method::Options).header(HeaderName::Subject, &vec![b'x'; padding]);
        endpoint.request(&big, t0).expect("the request goes");
        let out = transmits(&mut endpoint);
        let sent = out.first().expect("one message");
        // what the datagram would have carried: the same message with the
        // transport its `Via` names put back to UDP
        let as_datagram = String::from_utf8_lossy(&sent.payload)
            .replacen("SIP/2.0/TCP", "SIP/2.0/UDP", 1)
            .len();
        seen.push((as_datagram, sent.protocol));
    }
    for &(size, protocol) in &seen {
        let expected = if size <= 1_300 {
            TransportProtocol::Udp
        } else {
            TransportProtocol::Tcp
        };
        assert_eq!(protocol, expected, "{size} bytes went over {protocol:?}");
    }
    for size in 1_296..=1_305 {
        assert!(
            seen.iter().any(|&(seen, _)| seen == size),
            "no request of exactly {size} bytes was tried: {:?}",
            seen.iter().map(|&(size, _)| size).collect::<Vec<_>>()
        );
    }
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

/// The two sizes on the one `TransportWanted` an endpoint produced.
fn sizes_wanted(endpoint: &mut Endpoint) -> (usize, u32) {
    events(endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::TransportWanted {
                request_bytes,
                limit_bytes,
                ..
            } => Some((request_bytes, limit_bytes)),
            _ => None,
        })
        .expect("a transport was asked for")
}

#[test]
fn the_request_that_did_not_fit_is_reported_at_its_size_on_the_wire() {
    // the failure this exists for read as "authentication is broken" for two
    // days, because nothing anywhere said 1785 and nothing said 1300
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let padding = vec![b'x'; 1_400];
    let big = request(Method::Options).header(HeaderName::Subject, &padding);
    assert!(endpoint.request(&big, t0).is_err());
    let (request_bytes, limit_bytes) = sizes_wanted(&mut endpoint);
    assert_eq!(limit_bytes, 1_300);

    // and it is the size of the message, not an estimate of it: the same
    // request, once there is a stream to put it on, is exactly that long
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
    endpoint.request(&big, t0).expect("the request goes");
    let sent = transmits(&mut endpoint);
    assert_eq!(
        sent.first().map(|t| t.payload.len()),
        Some(request_bytes),
        "the size reported has to be the size written"
    );
}

#[test]
fn a_known_path_mtu_is_the_limit_that_gets_reported() {
    // an access network whose real MTU is nowhere near Ethernet's is the case
    // the figure is configurable for, and a report of 1300 there would send
    // whoever reads it looking in the wrong place
    let t0 = Instant::now();
    let config = EndpointConfig {
        datagram_limit: DatagramLimit {
            path_mtu: Some(900),
            ..DatagramLimit::DEFAULT
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

    let padding = vec![b'x'; 800];
    let big = request(Method::Options).header(HeaderName::Subject, &padding);
    assert!(endpoint.request(&big, t0).is_err());
    let (request_bytes, limit_bytes) = sizes_wanted(&mut endpoint);
    assert_eq!(limit_bytes, 699, "900 less the 200 the response needs");
    assert!(request_bytes > 699, "{request_bytes}");
}

#[test]
fn a_connection_to_somebody_else_is_not_the_stream_this_request_wanted() {
    // 18.1.1 reuses a connection open to where the request is going. One open
    // somewhere else would deliver the request somewhere else, which is worse
    // than not sending it
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let elsewhere: SocketAddr = "198.51.100.7:5060".parse().expect("another peer");
    endpoint
        .receive(
            Input::TransportBound {
                transport: TCP,
                protocol: TransportProtocol::Tcp,
                local: local(),
                remote: Some(elsewhere),
            },
            t0,
        )
        .expect("binding TCP");
    transmits(&mut endpoint);

    let padding = vec![b'x'; 1_400];
    let big = request(Method::Options).header(HeaderName::Subject, &padding);
    assert!(endpoint.request(&big, t0).is_err());
    assert!(
        transmits(&mut endpoint).is_empty(),
        "nothing may go to the wrong peer"
    );
    let events = events(&mut endpoint);
    assert!(
        events.iter().any(|event| matches!(
            event,
            Event::TransportWanted {
                destination,
                ..
            } if *destination == peer()
        )),
        "{events:?}"
    );
}

#[test]
fn two_messages_in_one_read_are_both_taken() {
    let t0 = Instant::now();
    let mut endpoint = Endpoint::new(EndpointConfig::default(), [3; 32]).unwrap();
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
fn a_tapped_stream_hands_over_each_message_whole_however_the_reads_cut_it() {
    let t0 = Instant::now();
    let mut endpoint = Endpoint::new(EndpointConfig::default(), [3; 32]).unwrap();
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

    let first = incoming("OPTIONS", "s1", "");
    let second = incoming("MESSAGE", "s2", "");
    let mut stream = first.clone();
    stream.extend_from_slice(&second);
    let read = |endpoint: &mut Endpoint, data: &[u8]| {
        endpoint
            .receive(
                Input::StreamData {
                    transport: TCP,
                    data,
                },
                t0,
            )
            .expect("a read");
    };

    // untapped, nothing is kept
    read(&mut endpoint, &first);
    assert!(endpoint.take_stream_messages().is_empty());

    // one read ending in the middle of the second message, one finishing it
    endpoint.tap_streams(true);
    let cut = first.len() + 10;
    read(&mut endpoint, &stream[..cut]);
    let taken = endpoint.take_stream_messages();
    assert_eq!(taken.len(), 1);
    assert_eq!(&*taken[0].bytes, &first[..]);
    assert_eq!((taken[0].transport, taken[0].remote), (TCP, Some(peer())));
    read(&mut endpoint, &stream[cut..]);
    let taken = endpoint.take_stream_messages();
    assert_eq!(
        taken
            .iter()
            .map(|message| &*message.bytes)
            .collect::<Vec<_>>(),
        [&second[..]]
    );
    assert!(endpoint.take_stream_messages().is_empty(), "taken once");

    endpoint.tap_streams(false);
    read(&mut endpoint, &first);
    assert!(endpoint.take_stream_messages().is_empty());
}

#[test]
fn a_ping_on_a_stream_is_answered_with_a_single_crlf() {
    // RFC 5626 4.4.1 makes the pong a MUST
    let t0 = Instant::now();
    let mut endpoint = Endpoint::new(EndpointConfig::default(), [4; 32]).unwrap();
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
fn a_segment_full_of_pings_is_answered_in_one_write() {
    // §5.4 owes a CRLF to every double-CRLF that arrives and says nothing
    // about how many writes that is. One write per ping would let a peer turn
    // a single 64 KB segment into thousands of two-byte sends, which is a
    // better amplifier than it is a keep-alive
    const PINGS: usize = 4096;
    let t0 = Instant::now();
    let mut endpoint = Endpoint::new(EndpointConfig::default(), [15; 32]).unwrap();
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

    let burst = b"\r\n\r\n".repeat(PINGS);
    stream(&mut endpoint, &burst, t0);

    let out = transmits(&mut endpoint);
    assert_eq!(out.len(), 1, "one segment in, one write out");
    assert_eq!(
        out.first().map(|t| t.payload.to_vec()),
        Some(b"\r\n".repeat(PINGS)),
        "and still one pong per ping, on the same connection"
    );
}

#[test]
fn a_stream_transport_is_pinged_on_a_jittered_interval() {
    let t0 = Instant::now();
    let mut endpoint = Endpoint::new(EndpointConfig::default(), [5; 32]).unwrap();
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

/// The instants the pings on `transport` go out at, from `from` up to
/// `until`, running every deadline on the way.
fn pings_until(endpoint: &mut Endpoint, from: Instant, until: Instant) -> Vec<Instant> {
    let mut at = Vec::new();
    let mut now = from;
    while let Some(due) = endpoint.poll_timeout() {
        if due > until {
            break;
        }
        now = due.max(now);
        endpoint.handle_timeout(now);
        for transmit in transmits(endpoint) {
            if &*transmit.payload == b"\r\n\r\n" {
                at.push(now);
            }
        }
    }
    at
}

fn bound_tcp(config: EndpointConfig, now: Instant) -> Endpoint {
    let mut endpoint = Endpoint::new(config, [7; 32]).unwrap();
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
    endpoint
}

#[test]
fn a_stream_given_its_own_interval_is_pinged_at_it_and_not_at_the_endpoints() {
    // an account whose NAT forgets a connection in 15 s asks for more than
    // the endpoint's 25 s; RFC 5626 §4.4.1's jitter still applies
    let t0 = Instant::now();
    let mut endpoint = bound_tcp(EndpointConfig::default(), t0);
    endpoint
        .keep_stream_alive(TCP, Some(Duration::from_secs(10)), t0)
        .expect("ten seconds");
    assert_eq!(
        endpoint.stream_keepalive(TCP),
        Some(Duration::from_secs(10))
    );
    let pings = pings_until(&mut endpoint, t0, t0 + Duration::from_secs(100));
    assert!((10..=12).contains(&pings.len()), "{} pings", pings.len());
    let mut last = t0;
    for at in pings {
        let gap = at - last;
        assert!(
            gap >= Duration::from_secs(8) && gap <= Duration::from_secs(10),
            "{gap:?}"
        );
        last = at;
    }

    // and back to the endpoint's own when the owner lets go of it
    let later = t0 + Duration::from_secs(100);
    endpoint
        .keep_stream_alive(TCP, None, later)
        .expect("none is always taken");
    let pings = pings_until(&mut endpoint, later, later + Duration::from_secs(100));
    assert!((4..=5).contains(&pings.len()), "{} pings", pings.len());
}

#[test]
fn a_stream_given_its_own_interval_is_pinged_with_the_endpoints_keep_alive_off() {
    let t0 = Instant::now();
    let config = EndpointConfig {
        keepalive_interval: None,
        ..EndpointConfig::default()
    };
    let mut endpoint = bound_tcp(config, t0);
    assert_eq!(endpoint.poll_timeout(), None, "nothing pings with it off");
    endpoint
        .keep_stream_alive(TCP, Some(Duration::from_secs(15)), t0)
        .expect("fifteen seconds");
    let pings = pings_until(&mut endpoint, t0, t0 + Duration::from_secs(60));
    assert!((4..=5).contains(&pings.len()), "{} pings", pings.len());
}

#[test]
fn a_streams_own_interval_outlives_a_rebind_and_zero_is_refused() {
    let t0 = Instant::now();
    let mut endpoint = bound_tcp(EndpointConfig::default(), t0);
    assert_eq!(
        endpoint.keep_stream_alive(TCP, Some(Duration::ZERO), t0),
        Err(TimerConfigError::KeepaliveUnarmable)
    );
    assert_eq!(
        endpoint.stream_keepalive(TCP),
        Some(Duration::from_secs(25))
    );
    endpoint
        .keep_stream_alive(TCP, Some(Duration::from_secs(5)), t0)
        .expect("five seconds");
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
        .expect("the same name, bound again");
    let due = endpoint.poll_timeout().expect("a ping is due");
    assert!(due <= t0 + Duration::from_secs(5), "{:?}", due - t0);
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
    let mut endpoint = Endpoint::new(EndpointConfig::default(), [6; 32]).unwrap();
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

/// An endpoint with one TCP transport bound and its first keep-alive on the
/// wire, the far end not having answered it.
fn first_ping(seed: u8, now: Instant) -> (Endpoint, Instant) {
    let mut endpoint = Endpoint::new(EndpointConfig::default(), [seed; 32]).unwrap();
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
    let due = endpoint.poll_timeout().expect("a keepalive is due");
    endpoint.handle_timeout(due);
    assert_eq!(
        transmits(&mut endpoint).first().map(|t| t.payload.to_vec()),
        Some(b"\r\n\r\n".to_vec()),
        "the ping went"
    );
    (endpoint, due)
}

/// An endpoint whose TCP flow answered its first keep-alive — the explicit
/// indication RFC 5626 §4.4 asks for — with its second one on the wire.
fn pinged(seed: u8, now: Instant) -> (Endpoint, Instant) {
    let (mut endpoint, first) = first_ping(seed, now);
    stream(&mut endpoint, b"\r\n", first + Duration::from_millis(40));
    let due = endpoint.poll_timeout().expect("the next keepalive");
    endpoint.handle_timeout(due);
    assert_eq!(
        transmits(&mut endpoint).first().map(|t| t.payload.to_vec()),
        Some(b"\r\n\r\n".to_vec()),
        "the second ping went"
    );
    (endpoint, due)
}

#[test]
fn a_flow_that_never_answered_a_ping_is_not_held_to_the_pong() {
    // §4.4: a UA that did not register with outbound "cannot expect a CRLF in
    // response (a \"pong\") unless the UA has an explicit indication that
    // CRLF keep-alives are supported". Asterisk answers none, and a call it
    // carries on this connection must outlive the first ping by more than ten
    // seconds.
    let t0 = Instant::now();
    let (mut endpoint, pinged_at) = first_ping(14, t0);
    let mut now = pinged_at;
    for round in 0..6 {
        now += Duration::from_secs(11);
        endpoint.handle_timeout(now);
        let seen = events(&mut endpoint);
        assert!(
            !seen
                .iter()
                .any(|event| matches!(*event, Event::FlowFailed { .. })),
            "round {round}: a flow that never ponged was called dead: {seen:?}"
        );
        transmits(&mut endpoint);
    }
    // the pings still go, keeping the NAT binding the flow crosses open
    let next = endpoint
        .poll_timeout()
        .expect("the keepalive is still armed");
    endpoint.handle_timeout(next);
    assert_eq!(
        transmits(&mut endpoint).first().map(|t| t.payload.to_vec()),
        Some(b"\r\n\r\n".to_vec()),
    );
}

/// Feed bytes in on the stream transport.
pub(super) fn stream(endpoint: &mut Endpoint, bytes: &[u8], now: Instant) {
    endpoint
        .receive(
            Input::StreamData {
                transport: TCP,
                data: bytes,
            },
            now,
        )
        .expect("bytes on a stream");
}

#[test]
fn a_ping_that_is_never_answered_fails_the_flow_after_ten_seconds() {
    // 4.4.1: "If a pong is not received within 10 seconds after sending a ping
    // ... then the client MUST treat the flow as failed"
    let t0 = Instant::now();
    let (mut endpoint, pinged_at) = pinged(9, t0);

    endpoint.handle_timeout(pinged_at + Duration::from_secs(9));
    assert!(
        !events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::FlowFailed { .. })),
        "nine seconds is not ten"
    );

    endpoint.handle_timeout(pinged_at + Duration::from_secs(10));
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::FlowFailed { transport } if transport == TCP)),
        "ten seconds with no pong is a dead flow"
    );
    // and the flow is gone rather than reported and kept
    assert_eq!(endpoint.poll_timeout(), None);
}

#[test]
fn a_pong_stops_the_clock_and_the_next_ping_starts_it_again() {
    let t0 = Instant::now();
    let (mut endpoint, pinged_at) = pinged(10, t0);

    stream(&mut endpoint, b"\r\n", pinged_at + Duration::from_secs(1));
    endpoint.handle_timeout(pinged_at + Duration::from_secs(20));
    assert!(
        !events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::FlowFailed { .. })),
        "the far end answered"
    );

    // the ping after it arms the deadline afresh, and this one goes unanswered
    let next = endpoint.poll_timeout().expect("the next keepalive");
    endpoint.handle_timeout(next);
    transmits(&mut endpoint);
    endpoint.handle_timeout(next + Duration::from_secs(10));
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::FlowFailed { .. })),
    );
}

#[test]
fn a_message_is_not_a_pong() {
    // §4.4.1 asks for the CRLF, and a busy connection that never answers one
    // is exactly the flow this is meant to catch
    let t0 = Instant::now();
    let (mut endpoint, pinged_at) = pinged(11, t0);

    let mut request = incoming("OPTIONS", "streamed", "");
    // §18.3 makes Content-Length the framing on a stream, and it is there
    let at = pinged_at + Duration::from_secs(1);
    stream(&mut endpoint, &request, at);
    request.clear();
    transmits(&mut endpoint);
    events(&mut endpoint);

    endpoint.handle_timeout(pinged_at + Duration::from_secs(10));
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::FlowFailed { .. })),
        "traffic is not an answer"
    );
}

/// Bind the stream transport again under the name it already has, the way an
/// application that reconnected does.
fn rebind_tcp(endpoint: &mut Endpoint, now: Instant) {
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
        .expect("binding TCP again");
}

#[test]
fn rebinding_a_transport_does_not_leave_the_old_flows_pong_timer_armed() {
    // §4.4.1 is about a flow, not about a name: the ping went out on a
    // connection that is gone, and the ten seconds it armed are not a verdict
    // on the connection that took its place.
    let t0 = Instant::now();
    let (mut endpoint, pinged_at) = pinged(13, t0);

    // the application noticed the connection was broken on a write of its
    // own, reconnected, and reused the name — which `Transports::bind`
    // documents as replacing what was there
    let rebound_at = pinged_at + Duration::from_secs(1);
    rebind_tcp(&mut endpoint, rebound_at);

    // and the new connection answers every ping it is asked
    let mut now = rebound_at;
    for step in 0..8 {
        now += Duration::from_secs(2);
        endpoint.handle_timeout(now);
        let seen = events(&mut endpoint);
        assert!(
            !seen
                .iter()
                .any(|event| matches!(event, Event::FlowFailed { .. })),
            "step {step}, {:?} after the rebind: the flow that was rebound is \
             alive and has been given no reason to fail: {seen:?}",
            now.saturating_duration_since(pinged_at)
        );
        stream(&mut endpoint, b"\r\n", now);
    }

    // and one keep-alive is left on the name rather than two. The one the
    // rebind armed is eighty to a hundred per cent of the twenty-five seconds
    // away from it, and the one the old connection was carrying would have
    // fired before that.
    transmits(&mut endpoint);
    let next = endpoint.poll_timeout().expect("a keepalive is due");
    assert!(
        next >= rebound_at + Duration::from_secs(20),
        "a keepalive from the connection that is gone is still armed"
    );
    assert!(
        next <= rebound_at + Duration::from_secs(25),
        "the keepalive the rebind armed is the one that is due"
    );
    endpoint.handle_timeout(next);
    assert_eq!(
        transmits(&mut endpoint)
            .iter()
            .filter(|transmit| &*transmit.payload == b"\r\n\r\n")
            .count(),
        1,
        "one flow, one ping"
    );
}

#[test]
fn a_flow_that_failed_takes_what_was_running_on_it_down_too() {
    let t0 = Instant::now();
    let (mut endpoint, pinged_at) = pinged(12, t0);
    let id = endpoint
        .request(
            &OutgoingRequest::new(Method::Options, uri("sip:bob@example.com"), TCP, peer())
                .to(b"<sip:bob@example.com>")
                .from(b"Alice <sip:alice@example.com>"),
            t0,
        )
        .expect("the request goes");
    transmits(&mut endpoint);
    events(&mut endpoint);

    endpoint.handle_timeout(pinged_at + Duration::from_secs(10));
    let events = events(&mut endpoint);
    assert!(
        events
            .iter()
            .any(|event| matches!(*event, Event::FlowFailed { .. })),
    );
    assert!(
        events.iter().any(|event| matches!(
            *event,
            Event::RequestFailed { transaction, reason }
                if transaction == id && reason == FailureReason::TransportFailed
        )),
        "{events:?}"
    );
}

// -- the ceiling on what a stranger may create -------------------------------

#[test]
fn a_stranger_past_the_transaction_ceiling_is_refused_with_a_503() {
    // §21.5.4: "temporarily unable to process the request due to a temporary
    // overloading"
    let t0 = Instant::now();
    let mut endpoint = Endpoint::new(
        EndpointConfig {
            max_server_transactions: 2,
            ..EndpointConfig::DEFAULT
        },
        [13; 32],
    )
    .unwrap();
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

    for branch in ["one", "two"] {
        deliver(&mut endpoint, &incoming("MESSAGE", branch, ""), t0);
    }
    assert_eq!(endpoint.in_flight().0, 2);
    events(&mut endpoint);
    transmits(&mut endpoint);

    deliver(&mut endpoint, &incoming("MESSAGE", "three", ""), t0);
    let refusal = sent(&mut endpoint);
    assert!(
        refusal.starts_with(b"SIP/2.0 503 "),
        "{}",
        String::from_utf8_lossy(&refusal)
    );
    // §8.2.6.2: a tag on every response but a 100
    assert!(
        String::from_utf8_lossy(&header(&refusal, HeaderName::To)).contains(";tag="),
        "no To tag on the refusal"
    );
    assert_eq!(
        endpoint.in_flight().0,
        2,
        "the refusal kept nothing, which is the point of it"
    );
    assert_eq!(endpoint.refused(), 1);
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::Overloaded { refused: 1 })),
    );
}

#[test]
fn a_call_past_the_dialog_ceiling_is_refused_before_it_rings() {
    let t0 = Instant::now();
    let mut endpoint = Endpoint::new(
        EndpointConfig {
            max_dialogs: 0,
            ..EndpointConfig::DEFAULT
        },
        [14; 32],
    )
    .unwrap();
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

    deliver(&mut endpoint, &incoming("INVITE", "call", ""), t0);
    let refusal = sent(&mut endpoint);
    assert!(
        refusal.starts_with(b"SIP/2.0 503 "),
        "{}",
        String::from_utf8_lossy(&refusal)
    );
    assert!(
        !events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::IncomingInvite { .. })),
        "the application was not troubled with a call it has no room for"
    );
}

#[test]
fn a_bye_is_never_refused_however_full_the_endpoint_is() {
    // a dialog that cannot be ended is a dialog that stands for the life of the
    // process, which is worse than anything the ceiling protects against
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);
    events(&mut endpoint);

    endpoint.config.max_server_transactions = 0;
    endpoint.config.max_dialogs = 0;
    let snapshot = endpoint.dialog(dialog).expect("a dialog");
    let bye = format!(
        "BYE sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKfullbye;rport\r\n\
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
            .any(|event| matches!(*event, Event::IncomingBye { .. })),
        "{events:?}"
    );
    assert_eq!(endpoint.refused(), 0);
}

#[test]
fn a_cancel_that_matches_is_never_refused_either() {
    // 9.2: "the UAS MUST immediately respond to the CANCEL with a 200", and a
    // CANCEL ends a transaction rather than starting one worth counting
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    deliver(&mut endpoint, &incoming("INVITE", "full1", ""), t0);
    transmits(&mut endpoint);
    events(&mut endpoint);

    endpoint.config.max_server_transactions = 0;
    deliver(&mut endpoint, &incoming("CANCEL", "full1", ""), t0);
    let statuses: Vec<_> = transmits(&mut endpoint)
        .iter()
        .map(|transmit| with(&transmit.payload, |m| m.status().map(StatusCode::get)))
        .collect();
    assert_eq!(statuses, vec![Some(200), Some(487)], "{statuses:?}");
    assert_eq!(endpoint.refused(), 0);

    // one that matches nothing is a stranger like any other
    deliver(&mut endpoint, &incoming("CANCEL", "nosuch", ""), t0);
    assert!(sent(&mut endpoint).starts_with(b"SIP/2.0 503 "));
    assert_eq!(endpoint.refused(), 1);
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
fn a_dialog_whose_next_hop_is_a_name_says_so() {
    // §12.2.1.1 computes the address from the route set or the target by the
    // RFC 3263 procedures; §8.1.2 allows an alternate address instead, which
    // is the flow the call is already on
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .invite(&invite_request(), t0)
        .expect("the INVITE goes");
    let bytes = sent(&mut endpoint);
    let named = String::from_utf8_lossy(&respond_to(&bytes, 200, "OK", Some("desk")))
        .replace("<sip:bob@192.0.2.9>", "<sip:bob@bob.example.com>")
        .into_bytes();
    deliver(&mut endpoint, &named, t0);

    let reported = events(&mut endpoint);
    let asked = reported
        .iter()
        .find_map(|event| match event {
            Event::ResolveNeeded {
                dialog,
                host,
                port,
                protocol,
            } => Some((*dialog, host.to_string(), *port, *protocol)),
            _ => None,
        })
        .expect("a host to resolve");
    assert_eq!(asked.1, "bob.example.com");
    assert_eq!(asked.2, None, "no port, so RFC 3263 4.2 picks one");
    assert_eq!(asked.3, None);

    // ignoring it leaves the call on the flow that worked
    endpoint.ack_2xx(asked.0, None, t0).expect("the ACK goes");
    let out = transmits(&mut endpoint);
    assert_eq!(out.first().map(|t| t.destination), Some(peer()));

    // answering it moves the dialog's requests
    let elsewhere: SocketAddr = "198.51.100.7:5080".parse().expect("an address");
    endpoint.resolved(asked.0, &[elsewhere], None);
    endpoint.bye(asked.0, t0).expect("the BYE goes");
    let out = transmits(&mut endpoint);
    assert_eq!(out.first().map(|t| t.destination), Some(elsewhere));
}

#[test]
fn a_target_the_call_is_already_pointed_at_is_not_worth_reporting() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, _) = call(&mut endpoint, t0);
    assert!(
        !events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::ResolveNeeded { .. })),
        "the Contact is the address the 2xx came from"
    );
}

#[test]
fn an_answer_for_a_dialog_that_has_ended_is_dropped() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);
    endpoint.bye(dialog, t0).expect("the BYE goes");
    transmits(&mut endpoint);

    let elsewhere: SocketAddr = "198.51.100.7:5080".parse().expect("an address");
    endpoint.resolved(dialog, &[elsewhere], None);
    assert!(endpoint.dialog(dialog).is_none());
}

#[test]
fn a_resolved_answer_that_names_tcp_moves_a_dialog_off_udp() {
    // RFC 3263 4.1: the transport comes out of the lookup along with the
    // address, and a SRV target naming TCP has to be able to say so
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);

    endpoint
        .receive(
            Input::TransportBound {
                transport: TCP,
                protocol: TransportProtocol::Tcp,
                local: local(),
                remote: None,
            },
            t0,
        )
        .expect("binding TCP");

    let elsewhere: SocketAddr = "198.51.100.7:5060".parse().expect("an address");
    endpoint.resolved(dialog, &[elsewhere], Some(TransportProtocol::Tcp));

    endpoint.bye(dialog, t0).expect("the BYE goes");
    let out = transmits(&mut endpoint);
    let sent = out.first().expect("the BYE went somewhere");
    assert_eq!(sent.transport, TCP, "the flow moved to the TCP transport");
    assert_eq!(sent.protocol, TransportProtocol::Tcp);
    assert_eq!(sent.destination, elsewhere);
}

#[test]
fn a_resolved_answer_naming_an_unbound_transport_changes_nothing() {
    // this layer never opens a transport; a protocol nothing here speaks is
    // not something `resolved` can invent, so the flow stands until the
    // caller opens what RFC 3263 asked for and answers again
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);

    let elsewhere: SocketAddr = "198.51.100.7:5060".parse().expect("an address");
    endpoint.resolved(dialog, &[elsewhere], Some(TransportProtocol::Tls));

    endpoint.bye(dialog, t0).expect("the BYE goes");
    let out = transmits(&mut endpoint);
    let sent = out.first().expect("the BYE still goes, on the old flow");
    assert_eq!(
        sent.protocol,
        TransportProtocol::Udp,
        "nothing speaks TLS here"
    );
    assert_eq!(
        sent.destination,
        peer(),
        "the address nothing could reach it by is not taken either"
    );
}

#[test]
fn a_second_resolved_address_is_kept_and_used_after_the_first_times_out() {
    // RFC 3263 4.3: a client that fails on one SRV target retries the next
    // one, and "fails" is a transport failure or a timeout -- never a
    // refusal the far end signed
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);

    let first: SocketAddr = "198.51.100.7:5060".parse().expect("an address");
    let second: SocketAddr = "198.51.100.8:5060".parse().expect("another address");
    endpoint.resolved(dialog, &[first, second], None);

    let info = OutgoingInDialogRequest::new(Method::Extension("INFO"));
    endpoint
        .request_in_dialog(dialog, &info, t0)
        .expect("the first INFO goes");
    let out = transmits(&mut endpoint);
    assert_eq!(
        out.first().map(|t| t.destination),
        Some(first),
        "the first address is the one taken"
    );

    // 64*T1: timer F, nothing ever came back. Everything up to and
    // including it retransmits the first INFO to `first` a handful of
    // times, and those retransmissions -- not the request this test cares
    // about -- are what a plain `poll_transmit` would hand back first
    let t1 = t0 + Duration::from_secs(32);
    endpoint.handle_timeout(t1);
    let seen = events(&mut endpoint);
    assert!(
        seen.iter().any(|event| matches!(
            event,
            Event::RequestFailed {
                reason: FailureReason::Timeout,
                ..
            }
        )),
        "{seen:?}"
    );
    transmits(&mut endpoint);

    let info = OutgoingInDialogRequest::new(Method::Extension("INFO"));
    endpoint
        .request_in_dialog(dialog, &info, t1)
        .expect("the second INFO goes");
    let out = transmits(&mut endpoint);
    assert_eq!(
        out.first().map(|t| t.destination),
        Some(second),
        "the timeout moved the dialog to the address kept for it"
    );
}

#[test]
fn a_refusal_at_the_sip_layer_does_not_move_a_dialog_to_the_next_address() {
    // a 404 from the address this reached is an answer from the right
    // server, and RFC 3263 4.3's failover is not for it
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);

    let first: SocketAddr = "198.51.100.7:5060".parse().expect("an address");
    let second: SocketAddr = "198.51.100.8:5060".parse().expect("another address");
    endpoint.resolved(dialog, &[first, second], None);

    let info = OutgoingInDialogRequest::new(Method::Extension("INFO"));
    endpoint
        .request_in_dialog(dialog, &info, t0)
        .expect("the INFO goes");
    let bytes = transmits(&mut endpoint)
        .pop()
        .expect("the INFO went")
        .payload
        .to_vec();
    deliver(
        &mut endpoint,
        &respond_to(&bytes, 404, "Not Found", Some("desk")),
        t0,
    );
    events(&mut endpoint);

    endpoint.bye(dialog, t0).expect("the BYE goes");
    let out = transmits(&mut endpoint);
    assert_eq!(
        out.first().map(|t| t.destination),
        Some(first),
        "the server that answered is still the right one to ask"
    );
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

// -- a transport with nothing to absorb --------------------------------------
//
// §17.1.1.2 gives timer D a value of zero on a reliable transport, and
// §17.1.2.2 does the same for timer K: a final response ends the client
// transaction in the same breath as it arrives. Both sections still make
// passing that response up a MUST, so what a caller is told about a call must
// not depend on which transport carried the refusal. These are the same
// exchanges as above, over TCP.

/// An endpoint whose only transport is a stream to the peer, at `now`.
pub(super) fn connected(now: Instant) -> Endpoint {
    let mut endpoint = Endpoint::new(EndpointConfig::default(), [13; 32]).unwrap();
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
    endpoint
}

/// The request the datagram tests send, on the stream instead.
pub(super) fn streamed(method: Method<'_>) -> OutgoingRequest {
    OutgoingRequest::new(method, uri("sip:bob@example.com"), TCP, peer())
        .to(b"<sip:bob@example.com>")
        .from(b"Alice <sip:alice@example.com>")
}

/// A REGISTER on the stream, for the handshake tests next door.
pub(super) fn streamed_register() -> OutgoingRequest {
    OutgoingRequest::new(Method::Register, uri("sip:example.com"), TCP, peer())
        .to(b"<sip:alice@example.com>")
        .from(b"Alice <sip:alice@example.com>")
        .contact(b"<sip:alice@192.0.2.1>")
}

/// A call up on the stream, acknowledged, with nothing left to drain.
pub(super) fn streamed_call(endpoint: &mut Endpoint, now: Instant) -> DialogId {
    endpoint
        .invite(&streamed(Method::Invite), now)
        .expect("the INVITE goes");
    let bytes = sent(endpoint);
    stream(endpoint, &respond_to(&bytes, 200, "OK", Some("desk")), now);
    let dialog = events(endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::Established { dialog, .. } => Some(dialog),
            _ => None,
        })
        .expect("the call");
    endpoint.ack_2xx(dialog, None, now).expect("the ACK goes");
    transmits(endpoint);
    dialog
}

/// An INVITE on the stream, already refused with `status`.
fn refused_over_tcp(status: u16, reason: &str) -> (Endpoint, TransactionId<InviteClient>) {
    let t0 = Instant::now();
    let mut endpoint = connected(t0);
    let id = endpoint
        .invite(&streamed(Method::Invite), t0)
        .expect("the INVITE goes");
    let bytes = sent(&mut endpoint);
    stream(
        &mut endpoint,
        &respond_to(&bytes, status, reason, Some("desk")),
        t0,
    );
    (endpoint, id)
}

#[test]
fn a_refusal_on_a_stream_is_reported_exactly_as_it_is_on_a_datagram() {
    let (mut endpoint, id) = refused_over_tcp(486, "Busy Here");

    let seen = events(&mut endpoint);
    assert!(
        seen.iter().any(|event| matches!(
            event,
            Event::Failed { invite, status: Some(status), reason: FailureReason::Refused, .. }
                if *invite == id && status.get() == 486
        )),
        "{seen:?}"
    );
}

#[test]
fn every_class_of_final_refusal_on_a_stream_reaches_the_caller() {
    // one class at a time, because a proxy that redirects, a busy phone, a
    // broken registrar and a whole busy user are four different things to do
    // next and the caller is the one who decides which
    for (status, reason) in [
        (302, "Moved Temporarily"),
        (404, "Not Found"),
        (486, "Busy Here"),
        (500, "Server Internal Error"),
        (603, "Decline"),
    ] {
        let (mut endpoint, id) = refused_over_tcp(status, reason);
        let seen = events(&mut endpoint);
        assert!(
            seen.iter().any(|event| matches!(
                event,
                Event::Failed {
                    invite,
                    status: Some(code),
                    reason: FailureReason::Refused,
                    response: Some(_),
                } if *invite == id && code.get() == status
            )),
            "a {status} said nothing: {seen:?}"
        );
    }
}

#[test]
fn the_failure_is_reported_before_the_transaction_that_carried_it_ends() {
    // the other order is the same two events and a caller that has already
    // forgotten the call by the time it is told why it failed
    let (mut endpoint, _) = refused_over_tcp(486, "Busy Here");

    let seen = events(&mut endpoint);
    let failed = seen
        .iter()
        .position(|event| matches!(event, Event::Failed { .. }))
        .expect("the refusal");
    let ended = seen
        .iter()
        .position(|event| matches!(event, Event::TransactionTerminated { .. }))
        .expect("the transaction ends in the same call on a stream");
    assert!(failed < ended, "{seen:?}");
}

#[test]
fn a_redirect_on_a_stream_still_carries_the_contact_to_try_instead() {
    // a 3xx reduced to a number is a 3xx nobody can follow
    let t0 = Instant::now();
    let mut endpoint = connected(t0);
    endpoint
        .invite(&streamed(Method::Invite), t0)
        .expect("the INVITE goes");
    let bytes = sent(&mut endpoint);

    stream(
        &mut endpoint,
        &respond_with(
            &bytes,
            302,
            "Moved Temporarily",
            Some("proxy"),
            "Contact: <sip:bob@192.0.2.8>\r\n",
        ),
        t0,
    );
    let moved = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::Failed {
                response: Some(response),
                ..
            } => Some(response),
            _ => None,
        })
        .expect("the redirect");
    assert_eq!(
        header(&moved.bytes(), HeaderName::Contact),
        b"<sip:bob@192.0.2.8>"
    );
}

#[test]
fn an_early_dialog_a_refusal_ends_on_a_stream_says_it_was_refused() {
    // "abandoned" is what a dialog is when the answer window closes on it;
    // this one was told no
    let t0 = Instant::now();
    let mut endpoint = connected(t0);
    endpoint
        .invite(&streamed(Method::Invite), t0)
        .expect("the INVITE goes");
    let bytes = sent(&mut endpoint);
    stream(
        &mut endpoint,
        &respond_to(&bytes, 180, "Ringing", Some("desk")),
        t0,
    );
    events(&mut endpoint);

    stream(
        &mut endpoint,
        &respond_to(&bytes, 486, "Busy Here", Some("desk")),
        t0,
    );
    let seen = events(&mut endpoint);
    assert!(
        seen.iter().any(|event| matches!(
            event,
            Event::DialogTerminated {
                reason: DialogEndReason::Refused,
                ..
            }
        )),
        "{seen:?}"
    );
}

#[test]
fn a_cancelled_call_refused_on_a_stream_is_reported_as_cancelled() {
    // §9.1: the 487 is the answer to the CANCEL, not a call that failed on
    // its own, and the difference is what the caller shows the user
    let t0 = Instant::now();
    let mut endpoint = connected(t0);
    let id = endpoint
        .invite(&streamed(Method::Invite), t0)
        .expect("the INVITE goes");
    let bytes = sent(&mut endpoint);
    stream(
        &mut endpoint,
        &respond_to(&bytes, 180, "Ringing", Some("desk")),
        t0,
    );
    endpoint.cancel(id, t0).expect("the CANCEL goes");
    transmits(&mut endpoint);
    events(&mut endpoint);

    stream(
        &mut endpoint,
        &respond_to(&bytes, 487, "Request Terminated", Some("desk")),
        t0,
    );
    let seen = events(&mut endpoint);
    assert!(
        seen.iter()
            .any(|event| matches!(event, Event::Cancelled { invite } if *invite == id)),
        "{seen:?}"
    );
}

#[test]
fn a_second_2xx_from_a_fork_that_lost_the_race_is_still_a_call_on_a_stream() {
    // a 2xx does not end the client transaction — RFC 6026 keeps it in
    // Accepted for 64*T1 — so both answers have to be reported and both ACKed
    let t0 = Instant::now();
    let mut endpoint = connected(t0);
    endpoint
        .invite(&streamed(Method::Invite), t0)
        .expect("the INVITE goes");
    let bytes = sent(&mut endpoint);

    for tag in ["desk", "mobile"] {
        stream(&mut endpoint, &respond_to(&bytes, 200, "OK", Some(tag)), t0);
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
fn a_reinvite_refused_on_a_stream_leaves_the_call_standing_and_says_so() {
    let t0 = Instant::now();
    let mut endpoint = connected(t0);
    endpoint
        .invite(&streamed(Method::Invite), t0)
        .expect("the INVITE goes");
    let bytes = sent(&mut endpoint);
    stream(
        &mut endpoint,
        &respond_to(&bytes, 200, "OK", Some("desk")),
        t0,
    );
    let dialog = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::Established { dialog, .. } => Some(dialog),
            _ => None,
        })
        .expect("the call");
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    transmits(&mut endpoint);

    let again = endpoint
        .reinvite(
            dialog,
            &OutgoingInDialogRequest::new(Method::Invite).contact(b"<sip:alice@192.0.2.1>"),
            t0,
        )
        .expect("the re-INVITE goes");
    let sent_again = sent(&mut endpoint);
    stream(
        &mut endpoint,
        &respond_to(&sent_again, 488, "Not Acceptable Here", Some("desk")),
        t0,
    );
    let seen = events(&mut endpoint);
    assert!(
        seen.iter().any(|event| matches!(
            event,
            Event::ReinviteFailed { invite, status: Some(status), .. }
                if *invite == again && status.get() == 488
        )),
        "{seen:?}"
    );
    assert!(
        endpoint.dialog(dialog).is_some(),
        "§14.1 leaves the session as it was"
    );
}

#[test]
fn a_non_invite_request_refused_on_a_stream_reports_the_response_first() {
    // a REGISTER, a SUBSCRIBE and a REFER are one state machine (§17.1.2),
    // and timer K is zero on all three here
    for method in [Method::Register, Method::Subscribe, Method::Refer] {
        let t0 = Instant::now();
        let mut endpoint = connected(t0);
        let id = endpoint
            .request(&streamed(method), t0)
            .expect("the request goes");
        let bytes = sent(&mut endpoint);

        stream(
            &mut endpoint,
            &respond_to(&bytes, 403, "Forbidden", Some("registrar")),
            t0,
        );
        let seen = events(&mut endpoint);
        let reported = seen
            .iter()
            .position(|event| {
                matches!(
                    event,
                    Event::Response { transaction, status, .. }
                        if *transaction == id && status.get() == 403
                )
            })
            .unwrap_or_else(|| panic!("{method:?} said nothing: {seen:?}"));
        let ended = seen
            .iter()
            .position(|event| matches!(event, Event::TransactionTerminated { .. }))
            .unwrap_or_else(|| panic!("{method:?} never ended: {seen:?}"));
        assert!(reported < ended, "{method:?}: {seen:?}");
    }
}

// -- fields added by name ----------------------------------------------------

#[test]
fn a_field_the_endpoint_writes_is_refused_rather_than_written_twice() {
    for &owned in super::ENDPOINT_FIELDS {
        let t0 = Instant::now();
        let mut endpoint = endpoint(t0);
        let refused = endpoint.request(&request(Method::Options).header(owned, b"1"), t0);
        assert_eq!(
            refused,
            Err(super::SendError::Build(crate::msg::BuildError::OwnedField(
                owned.canonical()
            ))),
            "{owned} was taken by name"
        );
        assert!(
            transmits(&mut endpoint).is_empty(),
            "{owned}: a refused request left something on the wire"
        );
    }
}

#[test]
fn a_response_refuses_a_field_the_endpoint_writes() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    deliver(&mut endpoint, &incoming("INVITE", "owned", ""), t0);
    let _ = sent(&mut endpoint);
    let transaction = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingInvite { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("an incoming call");

    // a second Record-Route in a 180 is a route set the caller's end reads
    // off a line this end never meant to write
    let refused = endpoint.respond_invite(
        transaction,
        &OutgoingResponse::new(StatusCode::RINGING)
            .contact(b"<sip:alice@192.0.2.1>")
            .header(HeaderName::RecordRoute, b"<sip:elsewhere.example.net;lr>"),
        t0,
    );
    assert_eq!(
        refused,
        Err(super::RespondError::Build(
            crate::msg::BuildError::OwnedField("Record-Route")
        ))
    );
    assert!(transmits(&mut endpoint).is_empty());
}

#[test]
fn a_request_inside_a_dialog_refuses_a_field_the_endpoint_writes() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    let _ = sent(&mut endpoint);

    let refused = endpoint.request_in_dialog(
        dialog,
        &OutgoingInDialogRequest::new(Method::Info).header(HeaderName::CSeq, b"9 INFO"),
        t0,
    );
    assert_eq!(
        refused,
        Err(super::SendError::Build(crate::msg::BuildError::OwnedField(
            "CSeq"
        )))
    );
    assert!(transmits(&mut endpoint).is_empty());
}

#[test]
fn a_name_that_is_not_a_token_is_refused_rather_than_dropped() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let refused = endpoint.request(
        &request(Method::Options).header(HeaderName::Extension("X-Two Words"), b"1"),
        t0,
    );
    assert!(
        matches!(
            refused,
            Err(super::SendError::Build(
                crate::msg::BuildError::IllegalValue(_)
            ))
        ),
        "{refused:?}"
    );
    assert!(transmits(&mut endpoint).is_empty());
}

#[test]
fn a_bye_of_the_callers_own_carries_its_fields_and_ends_the_dialog() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    let _ = sent(&mut endpoint);
    let _ = events(&mut endpoint);

    endpoint
        .bye_with(
            dialog,
            &OutgoingInDialogRequest::new(Method::Bye)
                .header(HeaderName::Extension("X-Conversation-Id"), b"c-7"),
            t0,
        )
        .expect("the BYE goes");
    let bytes = sent(&mut endpoint);
    assert!(bytes.starts_with(b"BYE "));
    assert_eq!(
        header(&bytes, HeaderName::Extension("X-Conversation-Id")),
        b"c-7"
    );
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::DialogTerminated { .. })),
        "§15.1.1: the dialog is over once the BYE is passed to its transaction"
    );
}

#[test]
fn a_bye_of_the_callers_own_that_is_not_a_bye_is_refused_and_ends_nothing() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, _, dialog) = call(&mut endpoint, t0);
    endpoint.ack_2xx(dialog, None, t0).expect("the ACK goes");
    let _ = sent(&mut endpoint);

    let refused = endpoint.bye_with(dialog, &OutgoingInDialogRequest::new(Method::Info), t0);
    assert_eq!(refused, Err(super::SendError::WrongMethod));
    assert!(transmits(&mut endpoint).is_empty());
    assert_eq!(
        endpoint.dialog(dialog).map(|d| d.state),
        Some(crate::dialog::DialogState::Confirmed),
        "an INFO handed to the call that hangs up does not hang up"
    );
}

#[test]
fn an_endpoint_refuses_timers_that_would_never_stop_rearming() {
    // t1 zero makes timer A's own interval zero, which is the hang
    // `TimerConfig::validate` exists to refuse before an endpoint is ever
    // built on it
    let broken = EndpointConfig {
        timers: crate::transaction::TimerConfig {
            t1: Duration::ZERO,
            ..crate::transaction::TimerConfig::DEFAULT
        },
        ..EndpointConfig::default()
    };
    assert_eq!(
        Endpoint::new(broken, [21; 32]).unwrap_err(),
        crate::transaction::TimerConfigError::Unarmable
    );

    // and a config nobody touched stays accepted
    assert!(Endpoint::new(EndpointConfig::default(), [22; 32]).is_ok());
}

// -- what the front door refuses ---------------------------------------------

/// A request that arrived whole and cannot be read is answered 400, naming the
/// field, before anything matches a transaction to it.
///
/// The fault here is RFC 4475 §3.1.2.17's: a `CSeq` whose method is not the
/// start line's. It is the one worth testing of the several
/// `RawMessage::validate` catches, because it is the one that could otherwise
/// be acted on: the transaction table keys a request on its own method and a
/// response on its `CSeq`'s, so a message where the two disagree is a message
/// that means one thing on the way in and another on the way back.
#[test]
fn a_request_whose_cseq_disagrees_with_its_start_line_is_answered_400() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let malformed = String::from_utf8(incoming("OPTIONS", "malformed-cseq", ""))
        .expect("ascii")
        .replace("CSeq: 1 OPTIONS", "CSeq: 1 INVITE")
        .into_bytes();

    deliver(&mut endpoint, &malformed, t0);

    let answer = sent(&mut endpoint);
    let text = String::from_utf8_lossy(&answer);
    assert!(text.starts_with("SIP/2.0 400 Bad CSeq"), "{text}");
    assert!(
        events(&mut endpoint).is_empty(),
        "a message that could not be read reached the application"
    );
    // and nothing was made for it: a second copy earns the same stateless
    // answer rather than being matched to something
    deliver(&mut endpoint, &malformed, t0);
    let again = String::from_utf8_lossy(&sent(&mut endpoint)).into_owned();
    assert!(again.starts_with("SIP/2.0 400 Bad CSeq"), "{again}");
}

/// RFC 4475 §3.3.1's `insuf`: a request with no `From`, `To` or `Call-ID` is
/// "ideally" answered 400, and the answer copies what the request had — the
/// `Via` it is routed by and the `CSeq` it is matched on — and invents
/// nothing in place of the rest.
#[test]
fn a_request_missing_the_fields_a_response_copies_is_answered_400_with_what_it_had() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let insufficient = b"INVITE sip:alice@192.0.2.1 SIP/2.0\r\n\
CSeq: 193942 INVITE\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKinsuf1\r\n\
Content-Length: 0\r\n\
\r\n";

    deliver(&mut endpoint, insufficient, t0);

    let answer = sent(&mut endpoint);
    let text = String::from_utf8_lossy(&answer).into_owned();
    assert!(text.starts_with("SIP/2.0 400 Bad Call-ID\r\n"), "{text}");
    assert_eq!(
        header(&answer, HeaderName::Via),
        b"SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKinsuf1".to_vec()
    );
    assert_eq!(header(&answer, HeaderName::CSeq), b"193942 INVITE".to_vec());
    for name in [HeaderName::From, HeaderName::To, HeaderName::CallId] {
        assert!(header(&answer, name).is_empty(), "{name:?} was invented");
    }
    assert!(events(&mut endpoint).is_empty());

    // and with no `Via` there is nowhere to send one
    let nowhere = b"INVITE sip:alice@192.0.2.1 SIP/2.0\r\n\
CSeq: 193942 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
    deliver(&mut endpoint, nowhere, t0);
    assert!(transmits(&mut endpoint).is_empty());
}

/// The same fault in an ACK is dropped rather than answered: §17.1.1.3 has no
/// response to an ACK, and inventing one would be a message the far end has
/// no transaction for.
#[test]
fn a_malformed_ack_is_dropped_rather_than_answered() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let malformed = String::from_utf8(incoming("ACK", "malformed-ack", ""))
        .expect("ascii")
        .replace("CSeq: 1 ACK", "CSeq: 1 INVITE")
        .into_bytes();

    deliver(&mut endpoint, &malformed, t0);

    assert!(
        transmits(&mut endpoint).is_empty(),
        "an ACK was answered, and nothing answers an ACK"
    );
    assert!(events(&mut endpoint).is_empty());
}

// -- RFC 3263 §4.3: a request outside a dialog sent to the next server -------

/// A MESSAGE answered 503 is kept, and goes to the next address as itself
/// with a new branch; a 404 is an answer and keeps nothing; a request inside
/// a dialog is never kept.
#[test]
fn a_request_that_found_no_server_is_kept_and_sent_elsewhere_as_itself() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let elsewhere: SocketAddr = "198.51.100.7:5060".parse().unwrap();
    let id = endpoint.request(&request(Method::Message), t0).unwrap();
    let first = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &respond_to(&first, 503, "Service Unavailable", None),
        t0,
    );
    let failed = AnyTransactionId::NonInviteClient(id);
    let unreached = endpoint.unreached(failed).expect("kept");
    assert_eq!(unreached.destination, peer());
    assert_eq!(unreached.transport, UDP);
    assert!(!unreached.register && !unreached.invite);
    let again = endpoint.send_elsewhere(failed, elsewhere, t0).unwrap();
    assert_ne!(again, failed);
    let out = transmits(&mut endpoint);
    let moved = out.last().expect("sent again");
    assert_eq!(moved.destination, elsewhere);
    for name in [
        HeaderName::CallId,
        HeaderName::From,
        HeaderName::To,
        HeaderName::CSeq,
    ] {
        assert_eq!(header(&moved.payload, name), header(&first, name));
    }
    assert_ne!(
        header(&moved.payload, HeaderName::Via),
        header(&first, HeaderName::Via)
    );
    assert!(endpoint.unreached(failed).is_none(), "consumed");

    let answered = endpoint.request(&request(Method::Message), t0).unwrap();
    let request_bytes = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &respond_to(&request_bytes, 404, "Not Found", None),
        t0,
    );
    assert!(
        endpoint
            .unreached(AnyTransactionId::NonInviteClient(answered))
            .is_none(),
        "the right server's answer"
    );
}

/// Timer F and timer B keep what timed out, an INVITE among them.
#[test]
fn a_request_that_timed_out_is_kept_for_the_next_server() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let message = endpoint.request(&request(Method::Message), t0).unwrap();
    let invite = endpoint.invite(&invite_request(), t0).unwrap();
    let _ = transmits(&mut endpoint);
    while let Some(due) = endpoint.poll_timeout() {
        if due > t0 + 64 * T1 {
            break;
        }
        endpoint.handle_timeout(due);
    }
    assert!(
        endpoint
            .unreached(AnyTransactionId::NonInviteClient(message))
            .is_some()
    );
    let kept = endpoint
        .unreached(AnyTransactionId::InviteClient(invite))
        .expect("the INVITE");
    assert!(kept.invite);
}

/// RFC 3261 §26.2.2: a request that names a `sips:` URI where that asks for
/// TLS — the Request-URI, the first `Route`, the `Contact`, a REGISTER's
/// address of record — is refused on a transport that is not TLS, before
/// anything is drawn or written; the same request on a TLS connection goes,
/// and a `sip:` one goes on UDP as it always did.
#[test]
fn a_sips_request_never_leaves_on_a_transport_that_is_not_tls() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let tls = TransportId(3);
    endpoint
        .receive(
            Input::TransportBound {
                transport: tls,
                protocol: TransportProtocol::Tls,
                local: local(),
                remote: Some(peer()),
            },
            t0,
        )
        .expect("binding a TLS connection");
    let _ = transmits(&mut endpoint);

    let secure_target = || {
        OutgoingRequest::new(Method::Invite, uri("sips:bob@example.com"), UDP, peer())
            .to(b"<sips:bob@example.com>")
            .from(b"Alice <sips:alice@example.com>")
    };
    let refusals = [
        endpoint.invite(&secure_target(), t0).err(),
        endpoint
            .request(&options_request().route(b"<sips:proxy.example.com;lr>"), t0)
            .err(),
        endpoint
            .request(&options_request().contact(b"<sips:alice@192.0.2.1>"), t0)
            .err(),
        endpoint
            .request(
                &OutgoingRequest::new(Method::Register, uri("sip:example.com"), UDP, peer())
                    .to(b"<sips:alice@example.com>")
                    .from(b"<sips:alice@example.com>")
                    .contact(b"<sip:alice@192.0.2.1>"),
                t0,
            )
            .err(),
    ];
    for refusal in refusals {
        assert_eq!(refusal, Some(super::SendError::SipsNeedsTls));
    }
    assert!(transmits(&mut endpoint).is_empty(), "something went in clear");

    let mut over_tls = secure_target();
    over_tls.transport = tls;
    endpoint.invite(&over_tls, t0).expect("the INVITE goes over TLS");
    endpoint
        .request(&options_request(), t0)
        .expect("a sip: request goes over UDP");
    let out = transmits(&mut endpoint);
    assert_eq!(out.len(), 2);
    assert!(out[0].payload.starts_with(b"INVITE sips:bob@example.com SIP/2.0\r\n"));
    assert_eq!(out[0].protocol, TransportProtocol::Tls);
}
