// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The registration handshake, end to end on a fake clock.
//!
//! The realm is on a reserved domain (RFC 2606) rather than the one the RFC's
//! own example prints, because a realm that looks like an address is a realm
//! `scripts/check.sh` refuses to let into the tree.

use super::tests::{
    connected, deliver, endpoint, events, header, local, peer, register_request, sent, stream,
    streamed_call, streamed_register, transmits, with,
};
use super::{
    AuthRetryError, Compaction, DatagramLimit, Endpoint, EndpointConfig, Event, Input,
    OutgoingInDialogRequest, OutgoingRequest, SendError, Transmit, TransportId, TransportProtocol,
};
use crate::auth::{Credentials, DigestAlgorithm};
use crate::dialog::CallId;
use crate::msg::{HeaderName, Method, StatusCode, Uri};
use crate::transaction::AnyTransactionId;
use std::time::Instant;

const REALM: &str = "atlanta.example.com";
const NONCE: &str = "dcd98b7102dd2f0e8b11d0f600bfb0c093";

/// A refusal carrying a challenge, echoing the request's own fields.
fn challenge(request: &[u8], status: u16, field: &str, value: &str) -> Vec<u8> {
    let mut out = format!("SIP/2.0 {status} Unauthorized\r\n").into_bytes();
    for (name, bytes) in [
        ("Via", header(request, HeaderName::Via)),
        ("From", header(request, HeaderName::From)),
        ("To", {
            let mut to = header(request, HeaderName::To);
            to.extend_from_slice(b";tag=registrar");
            to
        }),
        ("Call-ID", header(request, HeaderName::CallId)),
        ("CSeq", header(request, HeaderName::CSeq)),
    ] {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&bytes);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("{field}: {value}\r\n").as_bytes());
    out.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    out
}

fn digest(nonce: &str, algorithm: Option<&str>) -> String {
    let algorithm = algorithm.map_or_else(String::new, |name| format!(", algorithm={name}"));
    format!("Digest realm=\"{REALM}\", nonce=\"{nonce}\", qop=\"auth\"{algorithm}")
}

fn credentials() -> Credentials {
    Credentials::new("alice", "the password")
}

/// Send a REGISTER and have it refused with a 401.
fn refused(endpoint: &mut Endpoint, now: Instant) -> (Vec<u8>, AnyTransactionId) {
    let id = endpoint
        .request(&register_request(), now)
        .expect("the REGISTER goes");
    let bytes = sent(endpoint);
    deliver(
        endpoint,
        &challenge(&bytes, 401, "WWW-Authenticate", &digest(NONCE, None)),
        now,
    );
    (bytes, AnyTransactionId::NonInviteClient(id))
}

#[test]
fn a_refusal_that_can_be_answered_is_reported_as_one() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, id) = refused(&mut endpoint, t0);

    let reported = events(&mut endpoint);
    assert!(
        reported
            .iter()
            .any(|event| matches!(event, Event::Response { status, .. } if status.get() == 401)),
        "the response itself should be reported too: {reported:?}"
    );
    let challenged = reported
        .iter()
        .find_map(|event| match event {
            Event::Challenged {
                transaction,
                realm,
                proxy,
                algorithm,
                stale,
            } => Some((*transaction, realm.clone(), *proxy, *algorithm, *stale)),
            _ => None,
        })
        .expect("a challenge");
    assert_eq!(challenged.0, id);
    assert_eq!(&*challenged.1, REALM);
    assert!(!challenged.2, "a 401 is not a proxy");
    assert_eq!(challenged.3, DigestAlgorithm::Md5, "the default algorithm");
    assert!(!challenged.4);
}

#[test]
fn the_retry_carries_credentials_a_new_branch_and_the_next_sequence_number() {
    // §22.2: "it MUST increment the CSeq header field value as it would
    // normally when sending an updated request"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (first, id) = refused(&mut endpoint, t0);
    events(&mut endpoint);

    endpoint
        .retry_with_credentials(id, &credentials(), t0)
        .expect("the retry goes");
    let second = sent(&mut endpoint);

    assert_eq!(header(&second, HeaderName::CSeq), b"2 REGISTER");
    assert_ne!(
        header(&second, HeaderName::Via),
        header(&first, HeaderName::Via),
        "a retry is a new transaction and needs a branch of its own"
    );
    assert_eq!(
        header(&second, HeaderName::CallId),
        header(&first, HeaderName::CallId),
        "§10.2 keeps one Call-ID per registrar"
    );

    let authorization =
        String::from_utf8_lossy(&header(&second, HeaderName::Authorization)).into_owned();
    assert!(authorization.starts_with("Digest "), "{authorization}");
    for expected in [
        "username=\"alice\"",
        &format!("realm=\"{REALM}\""),
        &format!("nonce=\"{NONCE}\""),
        "uri=\"sip:example.com\"",
        "qop=auth",
        "nc=00000001",
        "response=\"",
        "cnonce=\"",
    ] {
        assert!(
            authorization.contains(expected),
            "{expected} in {authorization}"
        );
    }
    assert!(
        !authorization.contains("the password"),
        "the password went on the wire"
    );
}

#[test]
fn a_proxy_challenge_is_answered_in_the_other_header_field() {
    // §22.3: the 401 and 407 spaces are separate, and so are their fields
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let id = endpoint
        .request(&register_request(), t0)
        .expect("the REGISTER goes");
    let bytes = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &challenge(&bytes, 407, "Proxy-Authenticate", &digest(NONCE, None)),
        t0,
    );
    let proxy = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::Challenged { proxy, .. } => Some(proxy),
            _ => None,
        })
        .expect("a challenge");
    assert!(proxy);

    endpoint
        .retry_with_credentials(AnyTransactionId::NonInviteClient(id), &credentials(), t0)
        .expect("the retry goes");
    let second = sent(&mut endpoint);
    assert!(!header(&second, HeaderName::ProxyAuthorization).is_empty());
    assert!(header(&second, HeaderName::Authorization).is_empty());
}

#[test]
fn the_nonce_count_moves_by_one_and_never_repeats() {
    // a skipped or repeated nc looks to the server like a replay
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, id) = refused(&mut endpoint, t0);
    events(&mut endpoint);
    endpoint
        .retry_with_credentials(id, &credentials(), t0)
        .expect("the retry goes");
    let first = sent(&mut endpoint);

    // the same nonce again, marked stale, so §22.1 allows another attempt
    let stale = challenge(
        &first,
        401,
        "WWW-Authenticate",
        &format!("{}, stale=true", digest(NONCE, None)),
    );
    deliver(&mut endpoint, &stale, t0);
    let retried = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::Challenged { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("a second challenge");
    endpoint
        .retry_with_credentials(retried, &credentials(), t0)
        .expect("the second retry goes");
    let second = sent(&mut endpoint);

    let count = |bytes: &[u8]| {
        String::from_utf8_lossy(&header(bytes, HeaderName::Authorization))
            .split("nc=")
            .nth(1)
            .and_then(|rest| rest.split(',').next())
            .map(str::to_owned)
            .unwrap_or_default()
    };
    assert_eq!(count(&first), "00000001");
    // RFC 7616 §3.4 counts "the number of requests ... sent with the nonce
    // value in this request", and the stale challenge named the same nonce:
    // this is the second request with it, and a second 00000001 would read
    // at the server as the first one replayed
    assert_eq!(
        count(&second),
        "00000002",
        "the same nonce, marked stale, carries on its count"
    );
    assert_eq!(header(&second, HeaderName::CSeq), b"3 REGISTER");
}

#[test]
fn the_same_nonce_without_stale_is_a_refusal_and_not_answered_again() {
    // §22.1: credentials that were just rejected are not worth repeating, and
    // repeating them only locks the account
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, id) = refused(&mut endpoint, t0);
    events(&mut endpoint);
    endpoint
        .retry_with_credentials(id, &credentials(), t0)
        .expect("the retry goes");
    let retried = sent(&mut endpoint);

    deliver(
        &mut endpoint,
        &challenge(&retried, 401, "WWW-Authenticate", &digest(NONCE, None)),
        t0,
    );
    let reported = events(&mut endpoint);
    assert!(
        !reported
            .iter()
            .any(|event| matches!(event, Event::Challenged { .. })),
        "the same nonce was offered for a second attempt: {reported:?}"
    );
}

#[test]
fn a_challenge_this_stack_cannot_answer_is_not_reported() {
    // RFC 8760 §2.4: "The client MUST ignore any challenge it does not
    // understand"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let id = endpoint
        .request(&register_request(), t0)
        .expect("the REGISTER goes");
    let bytes = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &challenge(&bytes, 401, "WWW-Authenticate", "Basic realm=\"nope\""),
        t0,
    );
    assert!(
        !events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::Challenged { .. }))
    );
    assert_eq!(
        endpoint.retry_with_credentials(AnyTransactionId::NonInviteClient(id), &credentials(), t0),
        Err(AuthRetryError::NoChallenge)
    );
}

#[test]
fn a_stronger_algorithm_is_taken_over_the_one_below_it() {
    // RFC 8760 §2.4: the client uses "the topmost header field that it
    // supports", and the server lists them in the order it prefers
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let id = endpoint
        .request(&register_request(), t0)
        .expect("the REGISTER goes");
    let bytes = sent(&mut endpoint);
    let mut refusal = challenge(
        &bytes,
        401,
        "WWW-Authenticate",
        &digest(NONCE, Some("SHA-256")),
    );
    // a second line below it, the way a server offering both writes it
    refusal = String::from_utf8_lossy(&refusal)
        .replace(
            "Content-Length: 0\r\n",
            &format!(
                "WWW-Authenticate: {}\r\nContent-Length: 0\r\n",
                digest(NONCE, Some("MD5"))
            ),
        )
        .into_bytes();
    deliver(&mut endpoint, &refusal, t0);

    let algorithm = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::Challenged { algorithm, .. } => Some(algorithm),
            _ => None,
        })
        .expect("a challenge");
    assert_eq!(algorithm, DigestAlgorithm::Sha256);

    endpoint
        .retry_with_credentials(AnyTransactionId::NonInviteClient(id), &credentials(), t0)
        .expect("the retry goes");
    let second = sent(&mut endpoint);
    let authorization =
        String::from_utf8_lossy(&header(&second, HeaderName::Authorization)).into_owned();
    assert!(
        authorization.contains("algorithm=SHA-256"),
        "{authorization}"
    );
}

#[test]
fn answering_the_same_challenge_twice_is_refused() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, id) = refused(&mut endpoint, t0);
    events(&mut endpoint);
    endpoint
        .retry_with_credentials(id, &credentials(), t0)
        .expect("the retry goes");
    assert_eq!(
        endpoint.retry_with_credentials(id, &credentials(), t0),
        Err(AuthRetryError::NoChallenge),
        "a second answer would replay the nonce count"
    );
}

#[test]
fn a_call_a_uas_challenges_is_reported_as_refused_and_then_as_challenged() {
    // a PBX challenges as a UAS, with 401 and WWW-Authenticate (§22.2), and
    // the refusal is reported before the note about what can be done with it.
    // sipral-ua depends on that order: it parks the refusal and lets the
    // challenge cancel it, the way it already did for a registration. Change
    // the order here and a challenged call ends instead of being retried
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let invite = endpoint
        .invite(&super::tests::invite_request(), t0)
        .expect("the INVITE goes");
    let bytes = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &challenge(&bytes, 401, "WWW-Authenticate", &digest(NONCE, None)),
        t0,
    );

    let order: Vec<&'static str> = events(&mut endpoint)
        .iter()
        .filter_map(|event| match *event {
            Event::Failed { .. } => Some("failed"),
            Event::Challenged { transaction, .. } => {
                assert_eq!(transaction, AnyTransactionId::InviteClient(invite));
                Some("challenged")
            }
            _ => None,
        })
        .collect();
    assert_eq!(order, ["failed", "challenged"]);
}

#[test]
fn a_challenged_call_is_retried_as_a_call() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let invite = endpoint
        .invite(&super::tests::invite_request(), t0)
        .expect("the INVITE goes");
    let bytes = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &challenge(&bytes, 407, "Proxy-Authenticate", &digest(NONCE, None)),
        t0,
    );
    let ack = sent(&mut endpoint);
    assert!(
        ack.starts_with(b"ACK "),
        "§17.1.1.3 acknowledges the refusal"
    );
    events(&mut endpoint);

    let retried = endpoint
        .retry_with_credentials(AnyTransactionId::InviteClient(invite), &credentials(), t0)
        .expect("the retry goes");
    assert!(matches!(retried, AnyTransactionId::InviteClient(_)));
    let second = sent(&mut endpoint);
    assert!(second.starts_with(b"INVITE "));
    assert_eq!(header(&second, HeaderName::CSeq), b"2 INVITE");
    assert!(!header(&second, HeaderName::ProxyAuthorization).is_empty());
    assert_eq!(
        with(&second, |m| m.header_count(HeaderName::Supported)),
        1,
        "the retry is the request again, not a second one"
    );
}

#[test]
fn the_body_and_the_headers_of_the_original_survive_the_retry() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let with_body = register_request()
        .header(HeaderName::UserAgent, b"sipral")
        .body(b"application/sdp", std::sync::Arc::from(&b"v=0\r\n"[..]));
    let id = endpoint.request(&with_body, t0).expect("the REGISTER goes");
    let bytes = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &challenge(&bytes, 401, "WWW-Authenticate", &digest(NONCE, None)),
        t0,
    );
    events(&mut endpoint);

    endpoint
        .retry_with_credentials(AnyTransactionId::NonInviteClient(id), &credentials(), t0)
        .expect("the retry goes");
    let second = sent(&mut endpoint);
    assert_eq!(header(&second, HeaderName::UserAgent), b"sipral");
    assert_eq!(header(&second, HeaderName::ContentType), b"application/sdp");
    assert!(with(&second, |m| m.body() == b"v=0\r\n"));
    assert_eq!(
        with(&second, |m| m.header_count(HeaderName::Authorization)),
        1,
        "credentials stacked up"
    );
}

#[test]
fn a_refusal_that_is_not_a_challenge_is_just_a_refusal() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let id = endpoint
        .request(&register_request(), t0)
        .expect("the REGISTER goes");
    let bytes = sent(&mut endpoint);
    let mut refusal = challenge(&bytes, 403, "Warning", "399 example \"no\"");
    refusal = String::from_utf8_lossy(&refusal)
        .replace("401 Unauthorized", "403 Forbidden")
        .into_bytes();
    deliver(&mut endpoint, &refusal, t0);

    let reported = events(&mut endpoint);
    assert!(
        reported
            .iter()
            .any(|event| matches!(event, Event::Response { status, .. } if status.get() == 403))
    );
    assert!(
        !reported
            .iter()
            .any(|event| matches!(event, Event::Challenged { .. }))
    );
    assert_eq!(
        endpoint.retry_with_credentials(AnyTransactionId::NonInviteClient(id), &credentials(), t0),
        Err(AuthRetryError::NoChallenge)
    );
    let _ = transmits(&mut endpoint);
    assert_eq!(StatusCode::UNAUTHORIZED.get(), 401);
}

// -- credentials that go out ahead of the challenge --------------------------
//
// §22.2: "UAs SHOULD cache the credentials for a given value of the To header
// field and 'realm' and attempt to re-use these values on the next request for
// that destination." Without it every request to a registrar that authenticates
// costs two round trips instead of one, for ever.

/// The `Authorization` on the last message written, as text.
fn authorization(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&header(bytes, HeaderName::Authorization)).into_owned()
}

/// The `nc` out of an `Authorization`.
fn count(bytes: &[u8]) -> String {
    authorization(bytes)
        .split("nc=")
        .nth(1)
        .and_then(|rest| rest.split(',').next())
        .map(str::to_owned)
        .unwrap_or_default()
}

/// A registrar that has challenged once and been answered, with the endpoint
/// ready to send the next REGISTER.
fn registered(endpoint: &mut Endpoint, now: Instant) {
    let (_, id) = refused(endpoint, now);
    events(endpoint);
    endpoint
        .retry_with_credentials(id, &credentials(), now)
        .expect("the retry goes");
    transmits(endpoint);
}

#[test]
fn the_next_request_to_a_registrar_that_challenged_once_carries_the_answer() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    registered(&mut endpoint, t0);

    endpoint
        .request_with_credentials(&register_request(), &credentials(), t0)
        .expect("the refresh goes");
    let refresh = sent(&mut endpoint);

    let sent = authorization(&refresh);
    assert!(sent.starts_with("Digest "), "{sent}");
    assert!(sent.contains(&format!("nonce=\"{NONCE}\"")), "{sent}");
    assert!(sent.contains(&format!("realm=\"{REALM}\"")), "{sent}");
    assert!(sent.contains("response=\""), "{sent}");
}

#[test]
fn the_nonce_count_moves_on_when_the_credentials_go_out_ahead_of_the_challenge() {
    // §22.4 rule 8: `nc` "MUST" differ on every request sent with one nonce,
    // and the count has one owner however the credentials leave
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    registered(&mut endpoint, t0);

    let mut counts = Vec::new();
    for _ in 0..3 {
        endpoint
            .request_with_credentials(&register_request(), &credentials(), t0)
            .expect("the refresh goes");
        counts.push(count(&sent(&mut endpoint)));
    }
    assert_eq!(counts, ["00000002", "00000003", "00000004"]);
}

#[test]
fn a_destination_that_has_never_challenged_is_sent_nothing_to_answer_with() {
    // credentials offered where none were asked for are a password hash given
    // to whoever happened to be listening
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint
        .request_with_credentials(&register_request(), &credentials(), t0)
        .expect("the REGISTER goes");
    let first = sent(&mut endpoint);
    assert_eq!(header(&first, HeaderName::Authorization), b"");
    assert_eq!(header(&first, HeaderName::ProxyAuthorization), b"");
}

#[test]
fn a_nonce_the_server_has_expired_is_answered_once_with_the_one_it_sent_instead() {
    // RFC 7616 §3.3: `stale` TRUE means the nonce is old and the credentials
    // were not the problem, so the request goes again rather than stopping
    const FRESH: &str = "b2fa1e0d9c8347a6f5310e2d4b7c9081";

    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    registered(&mut endpoint, t0);
    endpoint
        .request_with_credentials(&register_request(), &credentials(), t0)
        .expect("the refresh goes");
    let refresh = sent(&mut endpoint);

    deliver(
        &mut endpoint,
        &challenge(
            &refresh,
            401,
            "WWW-Authenticate",
            &format!("{}, stale=true", digest(FRESH, None)),
        ),
        t0,
    );
    let again = events(&mut endpoint)
        .into_iter()
        .find_map(|event| match event {
            Event::Challenged {
                transaction, stale, ..
            } => Some((transaction, stale)),
            _ => None,
        })
        .expect("a stale nonce is worth answering");
    assert!(again.1, "the challenge said so");

    endpoint
        .retry_with_credentials(again.0, &credentials(), t0)
        .expect("the answer to the new nonce goes");
    let answered = sent(&mut endpoint);
    let sent = authorization(&answered);
    assert!(sent.contains(&format!("nonce=\"{FRESH}\"")), "{sent}");
    assert_eq!(count(&answered), "00000001", "a fresh nonce starts again");
}

#[test]
fn a_password_the_server_refuses_ahead_of_a_challenge_is_not_offered_twice() {
    // §22.1: "A UAC MUST NOT re-attempt requests with the credentials that
    // have just been rejected". The guard has to hold for credentials that
    // went out before the refusal as well as after it, or a refresh that
    // carries a wrong password locks the account instead of failing once
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    registered(&mut endpoint, t0);
    endpoint
        .request_with_credentials(&register_request(), &credentials(), t0)
        .expect("the refresh goes");
    let refresh = sent(&mut endpoint);

    deliver(
        &mut endpoint,
        &challenge(&refresh, 401, "WWW-Authenticate", &digest(NONCE, None)),
        t0,
    );
    let reported = events(&mut endpoint);
    assert!(
        !reported
            .iter()
            .any(|event| matches!(event, Event::Challenged { .. })),
        "the same nonce came back: the password is wrong, not missing: {reported:?}"
    );

    // and the one after it goes out bare rather than repeating what was just
    // rejected
    endpoint
        .request_with_credentials(&register_request(), &credentials(), t0)
        .expect("the next one goes");
    let after = sent(&mut endpoint);
    assert_eq!(header(&after, HeaderName::Authorization), b"");
}

#[test]
fn a_proxy_that_challenged_one_call_is_not_answered_on_another() {
    // §22.3: "it should incorporate credentials for that realm in all
    // subsequent requests that contain the same Call-ID. These credentials
    // MUST NOT be cached across dialogs"
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let id = endpoint
        .request(&register_request(), t0)
        .expect("the REGISTER goes");
    let bytes = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &challenge(&bytes, 407, "Proxy-Authenticate", &digest(NONCE, None)),
        t0,
    );
    events(&mut endpoint);
    endpoint
        .retry_with_credentials(AnyTransactionId::NonInviteClient(id), &credentials(), t0)
        .expect("the retry goes");
    let retried = sent(&mut endpoint);
    assert!(
        !header(&retried, HeaderName::ProxyAuthorization).is_empty(),
        "the retry is the conversation the proxy challenged"
    );

    // the same destination, a different Call-ID: §10.2 gives a registration
    // one, and this is a request that is not it
    endpoint
        .request_with_credentials(&register_request(), &credentials(), t0)
        .expect("another request goes");
    let elsewhere = sent(&mut endpoint);
    assert_eq!(
        header(&elsewhere, HeaderName::ProxyAuthorization),
        b"",
        "a proxy's credentials do not travel to another conversation"
    );
}

#[test]
fn the_endpoints_own_answer_replaces_one_the_caller_wrote_by_hand() {
    // two sets of credentials for one realm is one of them ignored, and which
    // one is the server's guess
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    registered(&mut endpoint, t0);

    let request = register_request().header(HeaderName::Authorization, b"Digest realm=\"mine\"");
    endpoint
        .request_with_credentials(&request, &credentials(), t0)
        .expect("the refresh goes");
    let refresh = sent(&mut endpoint);
    let written = String::from_utf8_lossy(&refresh).into_owned();
    assert_eq!(written.matches("Authorization:").count(), 1, "{written}");
    assert!(!written.contains("realm=\"mine\""), "{written}");
}

#[test]
fn a_proxy_that_challenged_a_registration_is_answered_on_its_refreshes() {
    // §10.2.4 keeps one Call-ID for every registration of a boot cycle, which
    // is exactly the span §22.3 lets a proxy's credentials travel
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let booked = || register_request().call_id(CallId::new(b"one-boot-cycle"));
    let id = endpoint.request(&booked(), t0).expect("the REGISTER goes");
    let bytes = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &challenge(&bytes, 407, "Proxy-Authenticate", &digest(NONCE, None)),
        t0,
    );
    events(&mut endpoint);
    endpoint
        .retry_with_credentials(AnyTransactionId::NonInviteClient(id), &credentials(), t0)
        .expect("the retry goes");
    transmits(&mut endpoint);

    endpoint
        .request_with_credentials(&booked(), &credentials(), t0)
        .expect("the refresh goes");
    let refresh = sent(&mut endpoint);
    let carried =
        String::from_utf8_lossy(&header(&refresh, HeaderName::ProxyAuthorization)).into_owned();
    assert!(carried.contains(&format!("nonce=\"{NONCE}\"")), "{carried}");
    assert!(carried.contains("nc=00000002"), "{carried}");
}

#[test]
fn a_challenge_from_one_destination_is_not_answered_to_another() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    registered(&mut endpoint, t0);

    let elsewhere = OutgoingRequest::new(
        Method::Register,
        Uri::parse_str("sip:elsewhere.example").expect("a URI"),
        TransportId(1),
        peer(),
    )
    .to(b"<sip:alice@elsewhere.example>")
    .from(b"Alice <sip:alice@example.com>")
    .contact(b"<sip:alice@192.0.2.1>");
    endpoint
        .request_with_credentials(&elsewhere, &credentials(), t0)
        .expect("the REGISTER goes");
    let stranger = sent(&mut endpoint);
    assert_eq!(header(&stranger, HeaderName::Authorization), b"");
}

// -- the same handshake on a stream ------------------------------------------
//
// Timer K is zero on a reliable transport (§17.1.2.2), so the 401 that starts
// the handshake also ends the transaction that earned it. What the endpoint
// learned from it has to survive that, or the handshake is only a handshake
// over UDP.

/// Send a REGISTER on the stream and have it refused with a 401.
fn refused_over_tcp(endpoint: &mut Endpoint, now: Instant) -> AnyTransactionId {
    let id = endpoint
        .request(&streamed_register(), now)
        .expect("the REGISTER goes");
    let bytes = sent(endpoint);
    stream(
        endpoint,
        &challenge(&bytes, 401, "WWW-Authenticate", &digest(NONCE, None)),
        now,
    );
    AnyTransactionId::NonInviteClient(id)
}

#[test]
fn a_challenge_on_a_stream_is_reported_before_the_transaction_it_refused_ends() {
    let t0 = Instant::now();
    let mut endpoint = connected(t0);
    let id = refused_over_tcp(&mut endpoint, t0);

    let reported = events(&mut endpoint);
    let challenged = reported
        .iter()
        .position(
            |event| matches!(event, Event::Challenged { transaction, .. } if *transaction == id),
        )
        .unwrap_or_else(|| panic!("{reported:?}"));
    let ended = reported
        .iter()
        .position(|event| matches!(event, Event::TransactionTerminated { .. }))
        .unwrap_or_else(|| panic!("{reported:?}"));
    assert!(challenged < ended, "{reported:?}");
    endpoint
        .retry_with_credentials(id, &credentials(), t0)
        .expect("the retry goes");
}

#[test]
fn the_same_nonce_without_stale_is_not_answered_again_on_a_stream_either() {
    // §22.1 again: what stops the second attempt is knowing which nonce the
    // first one answered, and that is remembered against a transaction the
    // stream has already ended
    let t0 = Instant::now();
    let mut endpoint = connected(t0);
    let id = refused_over_tcp(&mut endpoint, t0);
    events(&mut endpoint);
    endpoint
        .retry_with_credentials(id, &credentials(), t0)
        .expect("the retry goes");
    let retried = sent(&mut endpoint);

    stream(
        &mut endpoint,
        &challenge(&retried, 401, "WWW-Authenticate", &digest(NONCE, None)),
        t0,
    );
    let reported = events(&mut endpoint);
    assert!(
        !reported
            .iter()
            .any(|event| matches!(event, Event::Challenged { .. })),
        "the same nonce was offered for a second attempt: {reported:?}"
    );
}

#[test]
fn a_challenged_request_inside_a_call_on_a_stream_takes_its_sequence_from_the_dialog() {
    // §22.2's "increment the CSeq as it would normally" means asking the
    // dialog, which is what hands out the next number to everything else in
    // the call
    let t0 = Instant::now();
    let mut endpoint = connected(t0);
    let dialog = streamed_call(&mut endpoint, t0);

    let info = endpoint
        .request_in_dialog(dialog, &OutgoingInDialogRequest::new(Method::Info), t0)
        .expect("the INFO goes");
    let bytes = sent(&mut endpoint);
    stream(
        &mut endpoint,
        &challenge(&bytes, 407, "Proxy-Authenticate", &digest(NONCE, None)),
        t0,
    );
    events(&mut endpoint);
    endpoint
        .retry_with_credentials(AnyTransactionId::NonInviteClient(info), &credentials(), t0)
        .expect("the retry goes");
    let retry = sent(&mut endpoint);

    endpoint
        .request_in_dialog(dialog, &OutgoingInDialogRequest::new(Method::Info), t0)
        .expect("a second INFO goes");
    let next = sent(&mut endpoint);
    // not only different: §12.2.1.1 has the local sequence number
    // "incremented by one" for each request, and §22.2 has the retry take
    // the next one "as it would normally" — so the three are consecutive
    let number = |bytes: &[u8]| -> u32 {
        String::from_utf8_lossy(&header(bytes, HeaderName::CSeq))
            .split(' ')
            .next()
            .and_then(|digits| digits.parse().ok())
            .expect("a CSeq number")
    };
    assert_eq!(
        number(&retry),
        number(&bytes) + 1,
        "the retry did not take the next number"
    );
    assert_eq!(
        number(&next),
        number(&retry) + 1,
        "the dialog handed the retry's number out twice, or skipped one"
    );
}

// -- the allowance, and the attempt §18.1.1 would not send ------------------

/// UDP bound, and a datagram limit the plain REGISTER fits under but the same
/// request carrying credentials does not.
fn cramped(now: Instant) -> Endpoint {
    let config = EndpointConfig {
        datagram_limit: DatagramLimit {
            path_mtu: None,
            headroom_bytes: 200,
            max_datagram_bytes: 450,
            without_stream_bytes: None,
            // the line is drawn for the request written in full
            compaction: Compaction::Never,
        },
        ..EndpointConfig::default()
    };
    let mut endpoint = Endpoint::new(config, [7; 32]).unwrap();
    endpoint
        .receive(
            Input::TransportBound {
                transport: TransportId(1),
                protocol: TransportProtocol::Udp,
                local: local(),
                remote: None,
            },
            now,
        )
        .expect("binding UDP");
    endpoint
}

/// The stream the endpoint asked for, opened.
fn open_the_stream(endpoint: &mut Endpoint, now: Instant) {
    endpoint
        .receive(
            Input::TransportBound {
                transport: TransportId(2),
                protocol: TransportProtocol::Tcp,
                local: local(),
                remote: Some(peer()),
            },
            now,
        )
        .expect("binding TCP");
}

#[test]
fn a_challenged_request_that_outgrew_a_datagram_goes_once_a_stream_is_open() {
    let t0 = Instant::now();
    let mut endpoint = cramped(t0);
    let id = endpoint
        .request(&register_request(), t0)
        .expect("the REGISTER goes");
    let first = sent(&mut endpoint);
    assert!(
        first.len() <= 450,
        "the first send has to fit, or this is not a test about the retry: {}",
        first.len()
    );
    deliver(
        &mut endpoint,
        &challenge(&first, 401, "WWW-Authenticate", &digest(NONCE, None)),
        t0,
    );
    events(&mut endpoint);

    let id = AnyTransactionId::NonInviteClient(id);
    let refused = endpoint.retry_with_credentials(id, &credentials(), t0);
    assert!(
        matches!(
            refused,
            Err(AuthRetryError::Unsendable(SendError::NeedsStreamTransport))
        ),
        "the credentials should push it over §18.1.1's line: {refused:?}"
    );
    assert!(
        events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::TransportWanted { .. })),
        "the endpoint asked for a stream"
    );
    assert!(
        transmits(&mut endpoint).is_empty(),
        "nothing should have gone out"
    );

    // the caller does what it was asked, and asks again with the same handle
    open_the_stream(&mut endpoint, t0);
    endpoint
        .retry_with_credentials(id, &credentials(), t0)
        .expect("the retry the endpoint itself asked for");
    let over_the_stream = sent(&mut endpoint);
    assert!(
        !authorization(&over_the_stream).is_empty(),
        "the second attempt carries the credentials"
    );
    assert_eq!(
        count(&over_the_stream),
        "00000001",
        "the attempt that never left spent nothing, so this is the first"
    );
}

/// A REGISTER answered under a datagram limit of `largest` bytes and
/// `compaction`: what went out with the credentials, and over what.
fn answered_under(largest: u32, compaction: Compaction, now: Instant) -> Option<Transmit> {
    let config = EndpointConfig {
        datagram_limit: DatagramLimit {
            max_datagram_bytes: largest,
            compaction,
            ..DatagramLimit::DEFAULT
        },
        ..EndpointConfig::default()
    };
    let mut endpoint = Endpoint::new(config, [7; 32]).unwrap();
    endpoint
        .receive(
            Input::TransportBound {
                transport: TransportId(1),
                protocol: TransportProtocol::Udp,
                local: local(),
                remote: None,
            },
            now,
        )
        .expect("binding UDP");
    let id = endpoint
        .request(&register_request(), now)
        .expect("the REGISTER goes");
    let first = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &challenge(&first, 401, "WWW-Authenticate", &digest(NONCE, None)),
        now,
    );
    events(&mut endpoint);
    endpoint
        .retry_with_credentials(AnyTransactionId::NonInviteClient(id), &credentials(), now)
        .ok()?;
    transmits(&mut endpoint).pop()
}

#[test]
fn an_answer_to_a_challenge_over_the_line_goes_compact_when_that_is_enough() {
    // the request certain to grow is the one carrying credentials, and it is
    // rebuilt from the refused one: the rebuild is held to the same ladder as
    // a first send, compact before a stream
    let t0 = Instant::now();
    let full = answered_under(1_300, Compaction::Never, t0)
        .expect("the answer fits the default line")
        .payload
        .len();
    let line = u32::try_from(full - 10).expect("a size");
    assert!(
        answered_under(line, Compaction::Never, t0).is_none(),
        "in full, the answer is over a line ten bytes short of it"
    );
    let compact = answered_under(line, Compaction::WhenOversize, t0)
        .expect("written compact, the answer goes over the datagram");
    assert_eq!(compact.protocol, TransportProtocol::Udp);
    assert!(
        compact.payload.len() <= full - 10,
        "{}",
        compact.payload.len()
    );
    let text = String::from_utf8_lossy(&compact.payload);
    assert!(text.contains("\r\nv:SIP/2.0/UDP "), "{text}");
    assert!(!authorization(&compact.payload).is_empty(), "{text}");
    assert_eq!(count(&compact.payload), "00000001");
}

#[test]
fn a_server_drawing_a_new_nonce_every_time_is_answered_three_times_and_no_more() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let mut handle = AnyTransactionId::NonInviteClient(
        endpoint
            .request(&register_request(), t0)
            .expect("the REGISTER goes"),
    );
    let mut bytes = sent(&mut endpoint);
    let mut answered = 0_u32;

    // a registrar that never repeats a nonce and never says `stale`, which is
    // what walks past §22.1's guard
    for round in 0..8_u32 {
        deliver(
            &mut endpoint,
            &challenge(
                &bytes,
                401,
                "WWW-Authenticate",
                &digest(&format!("nonce-{round}"), None),
            ),
            t0,
        );
        let challenged = events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::Challenged { .. }));
        if !challenged {
            break;
        }
        handle = endpoint
            .retry_with_credentials(handle, &credentials(), t0)
            .expect("the retry goes");
        answered += 1;
        bytes = sent(&mut endpoint);
    }

    assert_eq!(
        answered, 3,
        "one wrong password per round trip is how an account gets locked out"
    );
}

#[test]
fn the_password_the_allowance_ran_out_on_is_not_offered_ahead_of_the_next_request() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let mut handle = AnyTransactionId::NonInviteClient(
        endpoint
            .request(&register_request(), t0)
            .expect("the REGISTER goes"),
    );
    let mut bytes = sent(&mut endpoint);
    for round in 0..4_u32 {
        deliver(
            &mut endpoint,
            &challenge(
                &bytes,
                401,
                "WWW-Authenticate",
                &digest(&format!("nonce-{round}"), None),
            ),
            t0,
        );
        if !events(&mut endpoint)
            .iter()
            .any(|event| matches!(event, Event::Challenged { .. }))
        {
            break;
        }
        handle = endpoint
            .retry_with_credentials(handle, &credentials(), t0)
            .expect("the retry goes");
        bytes = sent(&mut endpoint);
    }

    // §22.2 would put the answer on the next request to this destination
    // without waiting to be asked. A password three refusals old is not one
    // to keep offering: that is the same lock-out, one round trip at a time.
    endpoint
        .request(&register_request(), t0)
        .expect("a fresh REGISTER goes");
    let fresh = sent(&mut endpoint);
    assert!(
        authorization(&fresh).is_empty(),
        "the credentials the allowance ran out on went out again: {}",
        authorization(&fresh)
    );
}

#[test]
fn a_challenged_call_retried_after_another_took_its_room_is_held_to_the_ceiling() {
    // the refusal gives the call's room back, so another call can take it
    // before the retry goes; the retry is a call as far as the ceiling is
    // concerned, and one past max_dialogs is refused like any other
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    endpoint.config.max_dialogs = 1;
    let invite = endpoint
        .invite(&super::tests::invite_request(), t0)
        .expect("the INVITE goes");
    let bytes = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &challenge(&bytes, 407, "Proxy-Authenticate", &digest(NONCE, None)),
        t0,
    );
    transmits(&mut endpoint);
    events(&mut endpoint);
    endpoint
        .invite(&super::tests::invite_request(), t0)
        .expect("the refused call's room is free for another");
    let other = sent(&mut endpoint);

    let failed = AnyTransactionId::InviteClient(invite);
    assert_eq!(
        endpoint.retry_with_credentials(failed, &credentials(), t0),
        Err(AuthRetryError::Unsendable(SendError::LimitReached {
            limit: 1
        }))
    );
    assert!(transmits(&mut endpoint).is_empty(), "nothing went out");
    assert_eq!(endpoint.dialogs_held(), 1, "no second call is held");

    // the challenge was kept: once the other call is over, the same handle
    // answers it
    deliver(
        &mut endpoint,
        &super::tests::respond_to(&other, 486, "Busy Here", Some("desk")),
        t0,
    );
    events(&mut endpoint);
    transmits(&mut endpoint);
    endpoint
        .retry_with_credentials(failed, &credentials(), t0)
        .expect("the retry goes once there is room");
    assert!(sent(&mut endpoint).starts_with(b"INVITE "));
}

#[test]
fn a_challenged_request_goes_again_with_the_body_it_was_reshaped_to() {
    // the last resort before a retry §18.1.1 refused a datagram is given up
    // on: a smaller body, under the same handle and the same rules
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let with_body = register_request()
        .header(HeaderName::UserAgent, b"sipral")
        .body(
            b"application/sdp",
            std::sync::Arc::from(&b"v=0\r\na=long\r\na=short\r\n"[..]),
        );
    let id = AnyTransactionId::NonInviteClient(
        endpoint.request(&with_body, t0).expect("the REGISTER goes"),
    );
    let bytes = sent(&mut endpoint);
    deliver(
        &mut endpoint,
        &challenge(&bytes, 401, "WWW-Authenticate", &digest(NONCE, None)),
        t0,
    );
    events(&mut endpoint);

    let mut seen = Vec::new();
    assert!(endpoint.reshape_challenged_body(id, |body| {
        seen = body.to_vec();
        Some(b"v=0\r\na=short\r\n".to_vec())
    }));
    assert_eq!(
        seen, b"v=0\r\na=long\r\na=short\r\n",
        "handed the body as sent"
    );
    // declining leaves what is there
    assert!(!endpoint.reshape_challenged_body(id, |_| None));

    endpoint
        .retry_with_credentials(id, &credentials(), t0)
        .expect("the retry goes");
    let second = sent(&mut endpoint);
    assert!(with(&second, |m| m.body() == b"v=0\r\na=short\r\n"));
    assert_eq!(
        header(&second, HeaderName::ContentLength),
        b"14",
        "the length follows the body"
    );
    assert_eq!(header(&second, HeaderName::ContentType), b"application/sdp");
    assert_eq!(header(&second, HeaderName::UserAgent), b"sipral");
    assert_eq!(header(&second, HeaderName::CSeq), b"2 REGISTER");
    assert_eq!(
        with(&second, |m| m.header_count(HeaderName::Authorization)),
        1
    );
    assert!(
        !endpoint.reshape_challenged_body(id, |_| Some(Vec::new())),
        "nothing is held under a handle that has been retried"
    );
}

#[test]
fn a_challenge_abandoned_cannot_be_answered_any_more() {
    let t0 = Instant::now();
    let mut endpoint = endpoint(t0);
    let (_, id) = refused(&mut endpoint, t0);
    events(&mut endpoint);
    assert!(endpoint.abandon_challenge(id));
    assert!(!endpoint.abandon_challenge(id), "once");
    assert!(matches!(
        endpoint.retry_with_credentials(id, &credentials(), t0),
        Err(AuthRetryError::NoChallenge)
    ));
    assert!(transmits(&mut endpoint).is_empty());
}
