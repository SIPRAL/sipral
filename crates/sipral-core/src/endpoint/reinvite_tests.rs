// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! RFC 3261 §14 driven from both ends: hold, resume, and the moment both ends
//! ask at once.

use super::tests::{deliver, endpoint, events, header, incoming, invite_request, sent, transmits};
use super::{
    DialogEndReason, Endpoint, Event, FailureReason, OutgoingInDialogRequest, OutgoingResponse,
    SendError,
};
use crate::msg::{HeaderName, Method, StatusCode};
use crate::transaction::{DialogId, InviteClient, InviteServer, TransactionId};
use std::sync::Arc;
use std::time::{Duration, Instant};

const T1: Duration = Duration::from_millis(500);
const HOLD: &[u8] = b"v=0\r\no=- 1 2 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n\
t=0 0\r\nm=audio 8000 RTP/AVP 0\r\na=sendonly\r\n";

/// A response to a request the endpoint wrote, echoing what §8.2.6.2 requires.
///
/// The `To` tag is added only when the request has none: inside a dialog it is
/// already there, and a second one would name a dialog nobody has.
fn reply(request: &[u8], status: u16, reason: &str, tag: &str, contact: Option<&str>) -> Vec<u8> {
    let to = String::from_utf8_lossy(&header(request, HeaderName::To)).into_owned();
    let to = if to.contains(";tag=") {
        to
    } else {
        format!("{to};tag={tag}")
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
    if let Some(contact) = contact {
        out.extend_from_slice(format!("Contact: {contact}\r\n").as_bytes());
    }
    out.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    out
}

/// The same dialog seen from the other end: our `To` is their `From`, and our
/// `From` is their `To`.
fn reversed(ours: &[u8], method: &str, branch: &str, cseq: u32) -> Vec<u8> {
    let from = String::from_utf8_lossy(&header(ours, HeaderName::To)).into_owned();
    let to = String::from_utf8_lossy(&header(ours, HeaderName::From)).into_owned();
    let call_id = String::from_utf8_lossy(&header(ours, HeaderName::CallId)).into_owned();
    format!(
        "{method} sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK{branch};rport\r\n\
Max-Forwards: 70\r\n\
From: {from}\r\n\
To: {to}\r\n\
Call-ID: {call_id}\r\n\
CSeq: {cseq} {method}\r\n\
Contact: <sip:bob@192.0.2.9>\r\n\
Content-Length: 0\r\n\
\r\n"
    )
    .into_bytes()
}

/// A re-INVITE with the `Contact` §8.1.1.8 makes mandatory.
fn renegotiation() -> OutgoingInDialogRequest {
    OutgoingInDialogRequest::new(Method::Invite).contact(b"<sip:alice@192.0.2.1>")
}

/// The last message the endpoint wrote, which is the answer when a 100 Trying
/// went out in front of it.
fn answered(endpoint: &mut Endpoint) -> Vec<u8> {
    transmits(endpoint)
        .pop()
        .map(|out| out.payload.to_vec())
        .expect("a response")
}

/// Place a call, take the 200, acknowledge it. Returns the dialog and the ACK,
/// which is the one message so far that carries both tags — what a request
/// from the far end inside this dialog has to mirror.
fn call_up(endpoint: &mut Endpoint, now: Instant) -> (DialogId, Vec<u8>) {
    endpoint
        .invite(&invite_request(), now)
        .expect("the INVITE goes");
    let invite = sent(endpoint);
    deliver(
        endpoint,
        &reply(&invite, 200, "OK", "desk", Some("<sip:bob@192.0.2.9>")),
        now,
    );
    let dialog = events(endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::Established { dialog, .. } => Some(dialog),
            _ => None,
        })
        .expect("the call connected");
    endpoint.ack_2xx(dialog, None, now).expect("the ACK goes");
    (dialog, sent(endpoint))
}

/// Take a call, answer it 200, and take the ACK. Returns the dialog and the
/// 200 as it went out, which is where our tag can be read off.
fn call_taken(endpoint: &mut Endpoint, now: Instant) -> (DialogId, Vec<u8>) {
    deliver(endpoint, &incoming("INVITE", "in1", ""), now);
    transmits(endpoint);
    let transaction = events(endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingInvite { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("somebody called");
    let dialog = endpoint
        .respond_invite(
            transaction,
            &OutgoingResponse::new(StatusCode::OK).contact(b"<sip:alice@192.0.2.1>"),
            now,
        )
        .expect("the 200 goes")
        .expect("a dialog");
    let answer = sent(endpoint);
    events(endpoint);
    (dialog, answer)
}

/// Send a re-INVITE and return the transaction and the bytes.
fn renegotiate(
    endpoint: &mut Endpoint,
    dialog: DialogId,
    now: Instant,
) -> (TransactionId<InviteClient>, Vec<u8>) {
    let id = endpoint
        .reinvite(
            dialog,
            &renegotiation().body(b"application/sdp", Arc::from(HOLD)),
            now,
        )
        .expect("the re-INVITE goes");
    (id, sent(endpoint))
}

fn cseq(bytes: &[u8]) -> Vec<u8> {
    header(bytes, HeaderName::CSeq)
}

// -- what we send ------------------------------------------------------------

#[test]
fn a_reinvite_takes_the_next_number_in_the_dialog_and_names_the_remote_target() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, ack) = call_up(&mut endpoint, t0);
    assert_eq!(cseq(&ack), b"1 ACK");

    let (_, reinvite) = renegotiate(&mut endpoint, dialog, t0);
    assert_eq!(cseq(&reinvite), b"2 INVITE");
    assert!(
        reinvite.starts_with(b"INVITE sip:bob@192.0.2.9 SIP/2.0\r\n"),
        "the Request-URI is the remote target the 200 named"
    );
    // 8.1.1.8: "The Contact header field MUST be present ... in any request
    // that can result in the establishment of a dialog"
    assert_eq!(
        header(&reinvite, HeaderName::Contact),
        b"<sip:alice@192.0.2.1>"
    );
    assert!(
        reinvite.ends_with(HOLD),
        "the offer travels in the re-INVITE"
    );
}

#[test]
fn a_reinvite_without_a_contact_is_refused_before_anything_is_sent() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_up(&mut endpoint, t0);
    assert_eq!(
        endpoint.reinvite(dialog, &OutgoingInDialogRequest::new(Method::Invite), t0),
        Err(SendError::MissingField("Contact"))
    );
    assert!(transmits(&mut endpoint).is_empty());
}

#[test]
fn an_invite_does_not_go_out_through_the_call_that_sends_everything_else() {
    // it needs an INVITE client transaction and an ACK of its own; a
    // non-INVITE transaction would neither retransmit nor acknowledge it
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_up(&mut endpoint, t0);
    assert_eq!(
        endpoint.request_in_dialog(dialog, &renegotiation(), t0),
        Err(SendError::WrongMethod)
    );
}

#[test]
fn the_answer_to_a_reinvite_reaches_the_caller() {
    // the regression this whole module exists for: the response to a
    // re-INVITE is not a fork, and looking for one dropped it in silence
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_up(&mut endpoint, t0);
    let (id, reinvite) = renegotiate(&mut endpoint, dialog, t0);

    deliver(
        &mut endpoint,
        &reply(&reinvite, 200, "OK", "desk", Some("<sip:bob@192.0.2.9>")),
        t0,
    );
    let answered = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::ReinviteAnswered {
                invite,
                dialog,
                status,
                ..
            } => Some((invite, dialog, status)),
            _ => None,
        })
        .expect("the renegotiation was answered");
    assert_eq!(answered, (id, dialog, StatusCode::OK));
}

#[test]
fn the_ack_for_a_reinvite_carries_the_reinvites_own_number() {
    // 13.2.2.4: "The sequence number of the CSeq header field MUST be the
    // same as the INVITE being acknowledged" - which is this one, not the
    // INVITE that opened the call
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_up(&mut endpoint, t0);
    let (id, reinvite) = renegotiate(&mut endpoint, dialog, t0);
    deliver(
        &mut endpoint,
        &reply(&reinvite, 200, "OK", "desk", Some("<sip:bob@192.0.2.9>")),
        t0,
    );
    events(&mut endpoint);

    endpoint
        .ack_reinvite(id, None, t0)
        .expect("the ACK for the renegotiation");
    let ack = sent(&mut endpoint);
    assert_eq!(cseq(&ack), b"2 ACK");
    assert!(ack.starts_with(b"ACK sip:bob@192.0.2.9 SIP/2.0\r\n"));
}

#[test]
fn a_retransmitted_answer_gets_the_same_ack_again_and_is_not_reported_twice() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_up(&mut endpoint, t0);
    let (id, reinvite) = renegotiate(&mut endpoint, dialog, t0);
    let ok = reply(&reinvite, 200, "OK", "desk", Some("<sip:bob@192.0.2.9>"));

    deliver(&mut endpoint, &ok, t0);
    events(&mut endpoint);
    endpoint.ack_reinvite(id, None, t0).expect("the ACK");
    let first = sent(&mut endpoint);

    deliver(&mut endpoint, &ok, t0 + T1);
    let again = sent(&mut endpoint);
    assert_eq!(first, again, "the same bytes, not a new ACK");
    assert!(
        events(&mut endpoint).is_empty(),
        "the caller heard about this answer already"
    );
}

#[test]
fn acknowledging_a_renegotiation_twice_is_refused() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_up(&mut endpoint, t0);
    let (id, reinvite) = renegotiate(&mut endpoint, dialog, t0);
    assert_eq!(
        endpoint.ack_reinvite(id, None, t0),
        Err(super::AckError::NotAnswered),
        "nothing has come back yet"
    );
    deliver(
        &mut endpoint,
        &reply(&reinvite, 200, "OK", "desk", Some("<sip:bob@192.0.2.9>")),
        t0,
    );
    events(&mut endpoint);
    endpoint.ack_reinvite(id, None, t0).expect("the ACK");
    transmits(&mut endpoint);
    assert_eq!(
        endpoint.ack_reinvite(id, None, t0),
        Err(super::AckError::AlreadyAcknowledged)
    );
}

#[test]
fn a_2xx_to_a_reinvite_moves_the_remote_target() {
    // 12.2.1.2: "When a UAC receives a 2xx response to a target refresh
    // request, it MUST replace the dialog's remote target URI"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_up(&mut endpoint, t0);
    let (id, reinvite) = renegotiate(&mut endpoint, dialog, t0);
    deliver(
        &mut endpoint,
        &reply(&reinvite, 200, "OK", "desk", Some("<sip:bob@192.0.2.77>")),
        t0,
    );
    events(&mut endpoint);
    endpoint.ack_reinvite(id, None, t0).expect("the ACK");
    let ack = sent(&mut endpoint);
    assert!(
        ack.starts_with(b"ACK sip:bob@192.0.2.77 SIP/2.0\r\n"),
        "the ACK already goes to the new target"
    );
    assert_eq!(
        endpoint.dialog(dialog).map(|d| d.remote_target.to_string()),
        Some("sip:bob@192.0.2.77".to_owned())
    );
}

#[test]
fn a_refused_renegotiation_leaves_the_call_standing() {
    // 14.1: "the session parameters MUST remain unchanged, as if no re-INVITE
    // had been issued"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_up(&mut endpoint, t0);
    let (id, reinvite) = renegotiate(&mut endpoint, dialog, t0);
    deliver(
        &mut endpoint,
        &reply(&reinvite, 488, "Not Acceptable Here", "desk", None),
        t0,
    );

    let seen = events(&mut endpoint);
    let failed = seen
        .iter()
        .find_map(|event| match *event {
            Event::ReinviteFailed {
                invite,
                status,
                reason,
                ref response,
                ..
            } => Some((invite, status, reason, response.is_some())),
            _ => None,
        })
        .expect("the renegotiation was refused");
    assert_eq!(
        failed,
        (id, StatusCode::new(488).ok(), FailureReason::Refused, true)
    );
    assert!(
        !seen
            .iter()
            .any(|event| matches!(*event, Event::DialogTerminated { .. })),
        "the call is still up"
    );
    assert!(endpoint.dialog(dialog).is_some());
}

#[test]
fn a_481_to_a_renegotiation_takes_the_dialog_with_it() {
    // 12.2.1.2: "If the response for a request within a dialog is a 481 ... or
    // a 408 ..., the UAC SHOULD terminate the dialog." No BYE goes out: the
    // far end has just said there is no such dialog
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_up(&mut endpoint, t0);
    let (_, reinvite) = renegotiate(&mut endpoint, dialog, t0);
    deliver(
        &mut endpoint,
        &reply(
            &reinvite,
            481,
            "Call/Transaction Does Not Exist",
            "desk",
            None,
        ),
        t0,
    );

    let ended = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::DialogTerminated { dialog, reason } => Some((dialog, reason)),
            _ => None,
        })
        .expect("the dialog went with it");
    assert_eq!(ended, (dialog, DialogEndReason::Gone));
    assert!(endpoint.dialog(dialog).is_none());
    assert!(
        transmits(&mut endpoint)
            .iter()
            .all(|out| !out.payload.starts_with(b"BYE ")),
        "no BYE to a peer that says the dialog is not there"
    );
}

#[test]
fn a_renegotiation_that_is_never_answered_ends_the_call() {
    // 12.2.1.2: "A UAC SHOULD also terminate a dialog if no response at all is
    // received for the request"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_up(&mut endpoint, t0);
    let (id, _) = renegotiate(&mut endpoint, dialog, t0);

    endpoint.handle_timeout(t0 + 64 * T1);
    let seen = events(&mut endpoint);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            Event::ReinviteFailed {
                invite,
                reason: FailureReason::Timeout,
                status: None,
                ..
            } if invite == id
        )),
        "{seen:?}"
    );
    assert!(seen.iter().any(|event| matches!(
        *event,
        Event::DialogTerminated {
            reason: DialogEndReason::Gone,
            ..
        }
    )));
}

#[test]
fn a_second_renegotiation_is_refused_while_the_first_is_unacknowledged() {
    // 14.1: "a UAC MUST NOT initiate a new INVITE transaction within a dialog
    // while another INVITE transaction is in progress in either direction"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_up(&mut endpoint, t0);
    let (id, reinvite) = renegotiate(&mut endpoint, dialog, t0);
    assert_eq!(
        endpoint.reinvite(dialog, &renegotiation(), t0),
        Err(SendError::InviteInProgress)
    );

    deliver(
        &mut endpoint,
        &reply(&reinvite, 200, "OK", "desk", Some("<sip:bob@192.0.2.9>")),
        t0,
    );
    events(&mut endpoint);
    assert_eq!(
        endpoint.reinvite(dialog, &renegotiation(), t0),
        Err(SendError::InviteInProgress),
        "answered but not yet acknowledged"
    );

    endpoint.ack_reinvite(id, None, t0).expect("the ACK");
    transmits(&mut endpoint);
    endpoint
        .reinvite(dialog, &renegotiation(), t0)
        .expect("the dialog is free again");
}

#[test]
fn a_call_that_has_just_connected_can_be_put_on_hold_at_once() {
    // RFC 6026 keeps the INVITE client transaction alive for 64*T1 after the
    // 2xx so that a retransmission is not read as a stray. Reading that as
    // "an INVITE is in progress" would make the first hold wait half a minute
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_up(&mut endpoint, t0);
    endpoint
        .reinvite(dialog, &renegotiation(), t0)
        .expect("hold goes out straight away");
}

// -- glare -------------------------------------------------------------------

#[test]
fn an_invite_that_crosses_ours_is_answered_491() {
    // 14.2: "A UAS that receives an INVITE on a dialog while an INVITE it had
    // sent on that dialog is in progress MUST return a 491"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_up(&mut endpoint, t0);
    let (_, reinvite) = renegotiate(&mut endpoint, dialog, t0);

    deliver(
        &mut endpoint,
        &reversed(&reinvite, "INVITE", "cross", 9),
        t0,
    );
    let refusal = answered(&mut endpoint);
    assert!(
        refusal.starts_with(b"SIP/2.0 491 Request Pending\r\n"),
        "{}",
        String::from_utf8_lossy(&refusal)
    );
    assert!(
        !events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::IncomingReinvite { .. })),
        "the RFC answers this one, not the caller"
    );
}

#[test]
fn a_491_says_how_long_to_wait_and_the_call_stays_up() {
    // 14.1: the end that owns the Call-ID waits between 2.1 and 4 seconds
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_up(&mut endpoint, t0);
    let (id, reinvite) = renegotiate(&mut endpoint, dialog, t0);
    deliver(
        &mut endpoint,
        &reply(&reinvite, 491, "Request Pending", "desk", None),
        t0,
    );

    let glare = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::ReinviteGlare {
                invite, retry_in, ..
            } => Some((invite, retry_in)),
            _ => None,
        })
        .expect("the two crossed");
    assert_eq!(glare.0, id);
    assert!(
        glare.1 >= Duration::from_millis(2_100) && glare.1 <= Duration::from_secs(4),
        "{:?} is outside the range for the end that owns the Call-ID",
        glare.1
    );
    assert!(endpoint.dialog(dialog).is_some());
}

#[test]
fn a_refusal_frees_the_dialog_before_the_transaction_is_over() {
    // 14.1: "the TU MUST wait until the transaction reaches the completed or
    // terminated state before initiating the new INVITE" — completed, which a
    // refusal reaches at once. Waiting for terminated would be waiting 32
    // seconds for timer D, and the 491 above asks for the change again after
    // four
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_up(&mut endpoint, t0);
    let (_, reinvite) = renegotiate(&mut endpoint, dialog, t0);
    deliver(
        &mut endpoint,
        &reply(&reinvite, 491, "Request Pending", "desk", None),
        t0,
    );
    events(&mut endpoint);
    transmits(&mut endpoint);

    let again = endpoint
        .reinvite(dialog, &renegotiation(), t0 + Duration::from_secs(3))
        .expect("the dialog is free once the refusal has arrived");
    assert_ne!(
        endpoint.transaction_state(again),
        None,
        "and the second one is running"
    );
}

#[test]
fn the_end_that_did_not_place_the_call_waits_less() {
    // the two ranges do not overlap, which is what stops the second collision
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_taken(&mut endpoint, t0);
    let (_, reinvite) = renegotiate(&mut endpoint, dialog, t0);
    deliver(
        &mut endpoint,
        &reply(&reinvite, 491, "Request Pending", "bobtag", None),
        t0,
    );

    let waited = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::ReinviteGlare { retry_in, .. } => Some(retry_in),
            _ => None,
        })
        .expect("the two crossed");
    assert!(
        waited <= Duration::from_secs(2),
        "{waited:?} is the owner's range, and this end is not the owner"
    );
}

#[test]
fn a_second_invite_before_the_first_is_answered_gets_500_and_a_retry_after() {
    // 14.2: "A UAS that receives a second INVITE before it sends the final
    // response to a first INVITE with a lower CSeq ... MUST return a 500 ...
    // and MUST include a Retry-After header field"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, ack) = call_up(&mut endpoint, t0);

    deliver(&mut endpoint, &reversed(&ack, "INVITE", "theirs1", 4), t0);
    transmits(&mut endpoint);
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::IncomingReinvite { .. })),
        "the first one is the caller's to answer"
    );

    deliver(&mut endpoint, &reversed(&ack, "INVITE", "theirs2", 5), t0);
    let refusal = answered(&mut endpoint);
    assert!(
        refusal.starts_with(b"SIP/2.0 500 Server Internal Error\r\n"),
        "{}",
        String::from_utf8_lossy(&refusal)
    );
    let after = header(&refusal, HeaderName::RetryAfter);
    let seconds: u32 = String::from_utf8_lossy(&after)
        .parse()
        .expect("a delta-seconds");
    assert!(seconds <= 10, "{seconds} is outside 0 to 10");
}

#[test]
fn a_second_update_before_the_first_is_answered_gets_500_and_a_retry_after() {
    // RFC 3311 5.2, the half that turns on transaction state rather than on
    // whether an offer is outstanding
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, ack) = call_up(&mut endpoint, t0);

    deliver(&mut endpoint, &reversed(&ack, "UPDATE", "upd1", 4), t0);
    transmits(&mut endpoint);
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(*event, Event::IncomingInDialog { .. })),
        "the first one is handed up"
    );

    deliver(&mut endpoint, &reversed(&ack, "UPDATE", "upd2", 5), t0);
    let refusal = answered(&mut endpoint);
    assert!(
        refusal.starts_with(b"SIP/2.0 500 Server Internal Error\r\n"),
        "{}",
        String::from_utf8_lossy(&refusal)
    );
    assert!(!header(&refusal, HeaderName::RetryAfter).is_empty());
}

#[test]
fn answering_their_renegotiation_frees_the_dialog_for_ours() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, ack) = call_up(&mut endpoint, t0);
    deliver(&mut endpoint, &reversed(&ack, "INVITE", "theirs", 4), t0);
    transmits(&mut endpoint);
    let transaction: TransactionId<InviteServer> = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::IncomingReinvite { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("they asked first");

    assert_eq!(
        endpoint.reinvite(dialog, &renegotiation(), t0),
        Err(SendError::InviteInProgress),
        "theirs is in progress"
    );

    endpoint
        .respond_invite(
            transaction,
            &OutgoingResponse::new(StatusCode::OK).contact(b"<sip:alice@192.0.2.1>"),
            t0,
        )
        .expect("the 200 goes");
    transmits(&mut endpoint);
    events(&mut endpoint);
    endpoint
        .reinvite(dialog, &renegotiation(), t0)
        .expect("now it is our turn");
}

// -- what a refusal carries --------------------------------------------------

#[test]
fn a_refused_call_reaches_the_caller_whole() {
    // a 302 names where to try instead, and a status code alone cannot say it
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .invite(&invite_request(), t0)
        .expect("the INVITE goes");
    let invite = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &reply(
            &invite,
            302,
            "Moved Temporarily",
            "desk",
            Some("<sip:bob@192.0.2.55>"),
        ),
        t0,
    );

    let refusal = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::Failed { response, .. } => response,
            _ => None,
        })
        .expect("the refusal, whole");
    assert_eq!(
        refusal.as_raw().header(HeaderName::Contact),
        Some(&b"<sip:bob@192.0.2.55>"[..]),
        "the redirect target survived"
    );
}

// -- 8.3.8 / 8.3.9: target refresh, and a reliable provisional on a re-INVITE

/// The same as `reply`, with extra header lines before `Content-Length`.
fn reply_with(
    request: &[u8],
    status: u16,
    reason: &str,
    tag: &str,
    contact: Option<&str>,
    extra: &str,
) -> Vec<u8> {
    let base = reply(request, status, reason, tag, contact);
    let text = String::from_utf8(base).expect("utf-8");
    text.replace(
        "Content-Length: 0\r\n",
        &format!("{extra}Content-Length: 0\r\n"),
    )
    .into_bytes()
}

#[test]
fn a_reliable_provisional_to_a_reinvite_can_be_prackd() {
    // RFC 3262 §3: a UAS may send any 101-199 reliably when the request offers
    // 100rel, and this very endpoint does that for a re-INVITE —
    // `respond_reliable` takes any InviteServer transaction. The sender
    // retransmits until a PRACK arrives and gives up on the request after
    // 64·T1, so a reliable 183 to a re-INVITE has to reach the caller with a
    // handle to acknowledge it by.
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_up(&mut endpoint, t0);
    let (_, reinvite) = renegotiate(&mut endpoint, dialog, t0);

    deliver(
        &mut endpoint,
        &reply_with(
            &reinvite,
            183,
            "Session Progress",
            "desk",
            Some("<sip:bob@192.0.2.9>"),
            "Require: 100rel\r\nRSeq: 314\r\n",
        ),
        t0,
    );

    let seen = events(&mut endpoint);
    assert!(
        seen.iter().any(|event| matches!(
            *event,
            Event::ReinviteProgress {
                provisional: Some(_),
                ..
            }
        )),
        "a reliable provisional to a re-INVITE reaches the caller with no way to PRACK it: {seen:?}"
    );
}

#[test]
fn a_retransmitted_2xx_before_the_ack_is_not_reported_twice() {
    // the 2xx to a re-INVITE is retransmitted every T1 until the ACK goes out.
    // The caller builds that ACK — it may carry the answer — so it can take
    // longer than T1.
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_up(&mut endpoint, t0);
    let (_, reinvite) = renegotiate(&mut endpoint, dialog, t0);
    let ok = reply(&reinvite, 200, "OK", "desk", Some("<sip:bob@192.0.2.9>"));

    deliver(&mut endpoint, &ok, t0);
    let first = events(&mut endpoint);
    assert_eq!(
        first
            .iter()
            .filter(|event| matches!(**event, Event::ReinviteAnswered { .. }))
            .count(),
        1
    );

    deliver(&mut endpoint, &ok, t0 + T1);
    let again = events(&mut endpoint);
    assert!(
        !again
            .iter()
            .any(|event| matches!(*event, Event::ReinviteAnswered { .. })),
        "the caller heard about this answer already: {again:?}"
    );
}

#[test]
fn a_target_refresh_that_moves_the_far_end_asks_the_caller_to_resolve() {
    // §12.2.1.2 makes the 2xx to a target refresh replace the remote target,
    // and it does. Nothing moved the flow the dialog's requests go out on, so
    // from here on the Request-URI named one host and the datagram was
    // addressed to another, with nothing said about it.
    //
    // Moving the flow here would be the wrong repair, and the flow standing
    // is asserted below rather than left to chance: the literal address in a
    // Contact from behind a NAT is private and unreachable, which is the
    // ordinary case, and nothing at this layer can tell it from a far end
    // that genuinely moved. What was missing is the asking.
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, _) = call_up(&mut endpoint, t0);
    let (id, reinvite) = renegotiate(&mut endpoint, dialog, t0);
    deliver(
        &mut endpoint,
        &reply(
            &reinvite,
            200,
            "OK",
            "desk",
            Some("<sip:bob@198.51.100.7:5060>"),
        ),
        t0,
    );
    let seen = events(&mut endpoint);
    assert!(
        seen.iter()
            .any(|event| matches!(*event, Event::ResolveNeeded { .. })),
        "the next hop moved and nothing said so: {seen:?}"
    );

    endpoint.ack_reinvite(id, None, t0).expect("the ACK");
    let out = transmits(&mut endpoint).pop().expect("the ACK went out");
    assert!(
        out.payload.starts_with(b"ACK sip:bob@198.51.100.7"),
        "the Request-URI moved"
    );
    assert_eq!(
        out.destination.to_string(),
        "192.0.2.9:5060",
        "the flow moved on its own, before the caller had answered"
    );

    // and once the caller has answered, it moves
    endpoint.resolved(dialog, &["198.51.100.7:5060".parse().expect("an address")]);
    endpoint
        .reinvite(
            dialog,
            &renegotiation().body(b"application/sdp", Arc::from(HOLD)),
            t0,
        )
        .expect("the re-INVITE goes");
    let out = transmits(&mut endpoint)
        .pop()
        .expect("the re-INVITE went out");
    assert_eq!(
        out.destination.to_string(),
        "198.51.100.7:5060",
        "the caller answered and the flow did not follow"
    );
}

/// The other half of the same decision, and the one that is easy to break
/// while fixing the first: a far end behind a NAT puts its private address in
/// `Contact`, and the flow the call actually travelled on is the only thing
/// that reaches it. Applying the literal address because it needs no resolver
/// sends the ACK to 10.0.0.5 and the call dies on connect.
#[test]
fn a_private_contact_address_does_not_take_the_call_off_the_flow_that_works() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .invite(&invite_request(), t0)
        .expect("the INVITE goes");
    let invite = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &reply(&invite, 200, "OK", "desk", Some("<sip:bob@10.0.0.5>")),
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
    let out = transmits(&mut endpoint).pop().expect("the ACK went out");
    assert!(
        out.payload.starts_with(b"ACK sip:bob@10.0.0.5"),
        "§12.2.1.1 puts the remote target in the Request-URI"
    );
    assert_eq!(
        out.destination.to_string(),
        "192.0.2.9:5060",
        "the ACK went to the private address the far end believes it has"
    );
}

#[test]
fn an_incoming_target_refresh_asks_the_caller_to_resolve() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (dialog, ack) = call_up(&mut endpoint, t0);
    let mut theirs = String::from_utf8(reversed(&ack, "INVITE", "moved", 4)).expect("utf-8");
    theirs = theirs.replace(
        "Contact: <sip:bob@192.0.2.9>",
        "Contact: <sip:bob@203.0.113.5>",
    );
    deliver(&mut endpoint, theirs.as_bytes(), t0);
    transmits(&mut endpoint);
    let seen = events(&mut endpoint);
    assert_eq!(
        endpoint
            .dialog(dialog)
            .map(|d| d.remote_target.to_string())
            .as_deref(),
        Some("sip:bob@203.0.113.5"),
        "§12.2.2 moved the target"
    );
    assert!(
        seen.iter()
            .any(|event| matches!(*event, Event::ResolveNeeded { .. })),
        "the next hop moved and nothing said so: {seen:?}"
    );
}
