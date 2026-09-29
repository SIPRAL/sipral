// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! STIR/SHAKEN in calls, end to end between two agents: one signs what it
//! places, the other verifies what arrives, with the certificate fetched in
//! between by the test the way an application fetches it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::msg::HeaderName;
use sipral_stir::testing::{Credentials, credentials};
use sipral_stir::{Signer, Tn, TrustAnchors};

use crate::tests::{UDP, agent, deliver, events, header, registrar, sent, transmits, uri};
use crate::{
    Account, AccountId, Attestation, CallEndReason, CallHandle, CallerVerification, OutgoingCall,
    StirConfig, StirSigning, StirVerification, UaError, UaEvent, UserAgent, VerificationFailure,
    VerificationOutcome,
};

const CALLER: &str = "12155551212";
const CALLED: &str = "12125551213";
const X5U: &str = "https://cert.example.org/passport.pem";

fn caller_account(credentials: &Credentials) -> Account {
    let signer = Signer::new(&credentials.key, X5U).expect("a signer");
    Account::new(
        uri("sip:+1-215-555-1212@example.com"),
        uri("sip:example.com"),
        uri("sip:caller@192.0.2.1"),
        UDP,
        registrar(),
    )
    .stir_signing(StirSigning::new(signer, Tn::new(CALLER).expect("a number")))
}

fn called_account(verification: StirVerification) -> Account {
    Account::new(
        uri(&format!("sip:{CALLED}@example.com")),
        uri("sip:example.com"),
        uri("sip:called@192.0.2.1"),
        UDP,
        registrar(),
    )
    .stir_verification(verification)
}

/// When both agents believe it is: inside every certificate's validity.
fn wall(credentials: &Credentials) -> u64 {
    credentials.not_before + 1_000
}

/// The INVITE the calling agent sends, signed.
fn signed_invite(credentials: &Credentials, t0: Instant) -> Vec<u8> {
    let mut caller = agent(t0);
    caller.set_wall_clock(t0, wall(credentials));
    let id = caller.add_account(caller_account(credentials));
    caller
        .call(
            id,
            &OutgoingCall::new(uri(&format!("sip:{CALLED}@example.com"))),
            t0,
        )
        .expect("a signed call goes");
    sent(&mut caller)
}

/// The called agent, trusting `anchors`, with one account.
fn called(
    credentials: &Credentials,
    anchors: bool,
    verification: StirVerification,
    t0: Instant,
) -> (UserAgent, AccountId) {
    let mut called = agent(t0);
    called.set_wall_clock(t0, wall(credentials));
    let mut trusted = TrustAnchors::new();
    if anchors {
        trusted
            .add(credentials.anchor.as_bytes())
            .expect("the test root");
    }
    called.set_stir(StirConfig::new(trusted));
    let id = called.add_account(called_account(verification));
    (called, id)
}

fn wanted(seen: &[UaEvent]) -> Option<(CallHandle, String)> {
    seen.iter().find_map(|event| match event {
        UaEvent::CertificateWanted { call, url } => Some((*call, url.to_string())),
        _ => None,
    })
}

fn verdict(seen: &[UaEvent]) -> Option<Arc<CallerVerification>> {
    seen.iter().find_map(|event| match event {
        UaEvent::CallerVerified { verification, .. } => Some(Arc::clone(verification)),
        _ => None,
    })
}

fn incoming(seen: &[UaEvent]) -> Option<CallHandle> {
    seen.iter().find_map(|event| match event {
        UaEvent::IncomingCall { call, .. } => Some(*call),
        _ => None,
    })
}

fn ended(seen: &[UaEvent]) -> Option<(CallEndReason, Option<u16>)> {
    seen.iter().find_map(|event| match event {
        UaEvent::CallEnded { reason, status, .. } => {
            Some((*reason, status.map(crate::StatusCode::get)))
        }
        _ => None,
    })
}

/// The status line of the final answer the called agent sent.
fn refusal(called: &mut UserAgent) -> String {
    transmits(called)
        .into_iter()
        .map(|bytes| {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            text.lines().next().unwrap_or_default().to_owned()
        })
        .find(|line| line.starts_with("SIP/2.0 4"))
        .expect("a refusal went out")
}

#[test]
fn a_signed_call_is_verified_before_the_phone_rings() {
    let t0 = Instant::now();
    let credentials = credentials(&[CALLER]);
    let invite = signed_invite(&credentials, t0);
    let identity = String::from_utf8_lossy(&header(&invite, HeaderName::Identity)).into_owned();
    assert!(identity.contains(&format!(";info=<{X5U}>")), "{identity}");
    assert!(identity.contains(";ppt=shaken"), "{identity}");
    assert!(
        !header(&invite, HeaderName::Date).is_empty(),
        "RFC 8224 §6.1 Step 3: a Date beside the Identity"
    );

    let (mut called, id) = called(&credentials, true, StirVerification::Report, t0);
    deliver(&mut called, &invite, t0);
    let seen = events(&mut called);
    let (call, url) = wanted(&seen).expect("the certificate is wanted first");
    assert_eq!(url, X5U);
    assert!(
        incoming(&seen).is_none(),
        "the application is not told of the call before its verdict"
    );
    assert_eq!(
        called.answer(call, None, t0).unwrap_err(),
        UaError::WrongState(crate::CallState::Incoming),
        "a call held for its verdict cannot be answered unchecked"
    );

    called
        .stir_certificate(call, Some(credentials.chain.as_bytes()), t0)
        .expect("the call was waiting");
    let seen = events(&mut called);
    let verification = verdict(&seen).expect("the verdict is announced");
    assert_eq!(verification.outcome, VerificationOutcome::Valid);
    assert_eq!(verification.attestation, Some(Attestation::A));
    assert_eq!(verification.orig.as_deref(), Some(CALLER));
    assert_eq!(verification.certificate_url.as_deref(), Some(X5U));
    assert!(verification.origid.is_some());
    assert_eq!(verification.verstat(), crate::Verstat::Passed);
    let delivered = incoming(&seen).expect("then the call rings");
    assert_eq!(delivered, call);
    let at = |wanted: fn(&UaEvent) -> bool| seen.iter().position(wanted);
    assert!(
        at(|event| matches!(event, UaEvent::CallerVerified { .. }))
            < at(|event| matches!(event, UaEvent::IncomingCall { .. })),
        "the verdict comes first"
    );
    let carried = called
        .call_identity(call)
        .and_then(|identity| identity.caller.verification)
        .expect("the identity carries the verdict");
    assert_eq!(carried.outcome, VerificationOutcome::Valid);
    // and the call itself is an ordinary one from here on
    called.answer(call, None, t0).expect("answered");
    let _ = id;
}

#[test]
fn a_call_with_no_identity_is_reported_and_delivered_or_refused_428() {
    let t0 = Instant::now();
    let credentials = credentials(&[CALLER]);
    let plain = String::from_utf8(crate::tests::incoming_invite("plain", None))
        .expect("text")
        .replace("sip:alice@192.0.2.1", "sip:called@192.0.2.1")
        .replace(
            "sip:alice@example.com",
            &format!("sip:{CALLED}@example.com"),
        )
        .into_bytes();

    let (mut reporting, _) = called(&credentials, true, StirVerification::Report, t0);
    deliver(&mut reporting, &plain, t0);
    let seen = events(&mut reporting);
    let verification = verdict(&seen).expect("reported");
    assert_eq!(verification.outcome, VerificationOutcome::Absent);
    assert_eq!(verification.failure, Some(VerificationFailure::NoIdentity));
    assert_eq!(verification.verstat(), crate::Verstat::NotValidated);
    assert!(!verification.refused);
    assert!(
        incoming(&seen).is_some(),
        "report delivers whatever it says"
    );

    let (mut strict, _) = called(&credentials, true, StirVerification::Strict, t0);
    deliver(&mut strict, &plain, t0);
    let seen = events(&mut strict);
    assert!(incoming(&seen).is_none(), "strict refuses it");
    let verification = verdict(&seen).expect("the refusal is reported");
    assert!(verification.refused);
    assert_eq!(
        verification.response.as_ref().map(|(code, _)| *code),
        Some(428)
    );
    assert_eq!(ended(&seen), Some((CallEndReason::LocalHangup, Some(428))));
    assert_eq!(refusal(&mut strict), "SIP/2.0 428 Use Identity Header");
}

#[test]
fn a_certificate_that_cannot_be_had_is_436_under_strict() {
    let t0 = Instant::now();
    let credentials = credentials(&[CALLER]);
    let invite = signed_invite(&credentials, t0);
    let (mut strict, _) = called(&credentials, true, StirVerification::Strict, t0);
    deliver(&mut strict, &invite, t0);
    let (call, _) = wanted(&events(&mut strict)).expect("wanted");
    strict
        .stir_certificate(call, None, t0)
        .expect("the call was waiting");
    let seen = events(&mut strict);
    let verification = verdict(&seen).expect("verdict");
    assert_eq!(
        verification.failure,
        Some(VerificationFailure::CertificateUnavailable)
    );
    assert_eq!(refusal(&mut strict), "SIP/2.0 436 Bad Identity Info");
    assert_eq!(
        strict.stir_certificate(call, None, t0).unwrap_err(),
        UaError::NoSuchCall,
        "answered once"
    );
}

#[test]
fn a_fetch_that_never_comes_back_is_given_up_on_and_the_call_delivered() {
    let t0 = Instant::now();
    let credentials = credentials(&[CALLER]);
    let invite = signed_invite(&credentials, t0);
    let (mut reporting, _) = called(&credentials, true, StirVerification::Report, t0);
    deliver(&mut reporting, &invite, t0);
    let (call, _) = wanted(&events(&mut reporting)).expect("wanted");
    let due = reporting.poll_timeout().expect("the wait is on the clock");
    assert!(due <= t0 + crate::DEFAULT_CERTIFICATE_WAIT);
    reporting.handle_timeout(t0 + crate::DEFAULT_CERTIFICATE_WAIT);
    let seen = events(&mut reporting);
    let verification = verdict(&seen).expect("the verdict without a certificate");
    assert_eq!(
        verification.failure,
        Some(VerificationFailure::CertificateUnavailable)
    );
    assert_eq!(incoming(&seen), Some(call));
}

#[test]
fn a_certificate_nobody_trusts_is_437_and_a_stale_one_403() {
    let t0 = Instant::now();
    let credentials = credentials(&[CALLER]);
    let invite = signed_invite(&credentials, t0);

    // strict with no anchors at all: nothing verifies
    let (mut untrusting, _) = called(&credentials, false, StirVerification::Strict, t0);
    deliver(&mut untrusting, &invite, t0);
    let (call, _) = wanted(&events(&mut untrusting)).expect("wanted");
    untrusting
        .stir_certificate(call, Some(credentials.chain.as_bytes()), t0)
        .expect("waiting");
    assert_eq!(
        verdict(&events(&mut untrusting)).and_then(|verdict| verdict.failure),
        Some(VerificationFailure::Untrusted)
    );
    assert_eq!(
        refusal(&mut untrusting),
        "SIP/2.0 437 Unsupported Credential"
    );

    // two minutes after it was signed, past RFC 8224's sixty seconds
    let late = t0 + Duration::from_secs(120);
    let (mut strict, _) = called(&credentials, true, StirVerification::Strict, t0);
    deliver(&mut strict, &invite, late);
    let (call, _) = wanted(&events(&mut strict)).expect("wanted");
    strict
        .stir_certificate(call, Some(credentials.chain.as_bytes()), late)
        .expect("waiting");
    assert_eq!(
        verdict(&events(&mut strict)).and_then(|verdict| verdict.failure),
        Some(VerificationFailure::Stale)
    );
    assert_eq!(refusal(&mut strict), "SIP/2.0 403 Stale Date");
}

/// RFC 8224 §6.2.4: the originating identity is the request's, never the
/// PASSporT's. A valid signature for another number is a cut-and-paste.
#[test]
fn a_passport_for_another_caller_does_not_vouch_for_this_one() {
    let t0 = Instant::now();
    let credentials = credentials(&[CALLER]);
    let invite = signed_invite(&credentials, t0);
    let text = String::from_utf8(invite).expect("text");
    let pasted = text.replace(
        "sip:+1-215-555-1212@example.com",
        "sip:+12155559999@example.com",
    );
    assert_ne!(pasted, text, "the From was rewritten");
    let (mut reporting, _) = called(&credentials, true, StirVerification::Report, t0);
    deliver(&mut reporting, pasted.as_bytes(), t0);
    let (call, _) = wanted(&events(&mut reporting)).expect("wanted");
    reporting
        .stir_certificate(call, Some(credentials.chain.as_bytes()), t0)
        .expect("waiting");
    let verification = verdict(&events(&mut reporting)).expect("verdict");
    assert_eq!(verification.outcome, VerificationOutcome::Invalid);
    assert_eq!(
        verification.failure,
        Some(VerificationFailure::OrigMismatch)
    );
    assert_eq!(
        verification.response.as_ref().map(|(code, _)| *code),
        Some(438)
    );
}

#[test]
fn nothing_is_verified_for_an_account_that_is_off_or_an_agent_with_no_anchors() {
    let t0 = Instant::now();
    let credentials = credentials(&[CALLER]);
    let invite = signed_invite(&credentials, t0);
    for (anchors, mode) in [
        (true, StirVerification::Off),
        (false, StirVerification::Report),
    ] {
        let (mut called, _) = called(&credentials, anchors, mode, t0);
        deliver(&mut called, &invite, t0);
        let seen = events(&mut called);
        assert!(wanted(&seen).is_none(), "{mode:?}: nothing fetched");
        assert!(verdict(&seen).is_none(), "{mode:?}: nothing announced");
        let call = incoming(&seen).expect("delivered at once");
        assert!(
            called
                .call_identity(call)
                .and_then(|identity| identity.caller.verification)
                .is_none()
        );
    }
}

#[test]
fn a_caller_that_hangs_up_while_the_certificate_is_fetched_ends_the_call() {
    let t0 = Instant::now();
    let credentials = credentials(&[CALLER]);
    let invite = signed_invite(&credentials, t0);
    let (mut reporting, _) = called(&credentials, true, StirVerification::Report, t0);
    deliver(&mut reporting, &invite, t0);
    let (call, _) = wanted(&events(&mut reporting)).expect("wanted");
    transmits(&mut reporting);
    let text = String::from_utf8(invite).expect("text");
    let branch = text
        .lines()
        .find(|line| line.starts_with("Via:"))
        .expect("a Via")
        .to_owned();
    let call_id = text
        .lines()
        .find(|line| line.starts_with("Call-ID:"))
        .expect("a Call-ID")
        .to_owned();
    let from = text
        .lines()
        .find(|line| line.starts_with("From:"))
        .expect("a From")
        .to_owned();
    let cancel = format!(
        "CANCEL sip:{CALLED}@example.com SIP/2.0\r\n{branch}\r\nMax-Forwards: 70\r\n{from}\r\n\
         To: <sip:{CALLED}@example.com>\r\n{call_id}\r\nCSeq: 1 CANCEL\r\nContent-Length: 0\r\n\r\n"
    );
    deliver(&mut reporting, cancel.as_bytes(), t0);
    let seen = events(&mut reporting);
    assert_eq!(
        ended(&seen).map(|(reason, _)| reason),
        Some(CallEndReason::Cancelled)
    );
    assert!(incoming(&seen).is_none());
    assert_eq!(
        reporting
            .stir_certificate(call, Some(credentials.chain.as_bytes()), t0)
            .unwrap_err(),
        UaError::NoSuchCall
    );
    // and the wait it was on is gone with it: nothing is verified later
    reporting.handle_timeout(t0 + crate::DEFAULT_CERTIFICATE_WAIT);
    assert!(verdict(&events(&mut reporting)).is_none());
}

#[test]
fn an_account_that_signs_needs_the_time() {
    let t0 = Instant::now();
    let credentials = credentials(&[CALLER]);
    let mut caller = agent(t0);
    let id = caller.add_account(caller_account(&credentials));
    assert_eq!(
        caller
            .call(id, &OutgoingCall::new(uri("sip:alice@example.com")), t0)
            .unwrap_err(),
        UaError::NoWallClock
    );
    assert!(transmits(&mut caller).is_empty(), "nothing went unsigned");

    // and a call to a name rather than a number is signed for the URI
    caller.set_wall_clock(t0, wall(&credentials));
    caller
        .call(id, &OutgoingCall::new(uri("sip:alice@example.com")), t0)
        .expect("signed for the URI");
    let invite = sent(&mut caller);
    assert!(!header(&invite, HeaderName::Identity).is_empty());
}
