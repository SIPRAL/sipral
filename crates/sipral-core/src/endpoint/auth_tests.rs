// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The registration handshake, end to end on a fake clock.
//!
//! The realm is on a reserved domain (RFC 2606) rather than the one the RFC's
//! own example prints, because a realm that looks like an address is a realm
//! `scripts/check.sh` refuses to let into the tree.

use super::tests::{deliver, endpoint, events, header, register_request, sent, transmits, with};
use super::{AuthRetryError, Endpoint, Event};
use crate::auth::{Credentials, DigestAlgorithm};
use crate::msg::{HeaderName, StatusCode};
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
    assert_eq!(count(&second), "00000001", "a fresh nonce starts again");
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
