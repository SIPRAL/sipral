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
    signed_invite_to(credentials, &format!("sip:{CALLED}@example.com"), t0)
}

/// The INVITE the calling agent sends to `target`, signed.
fn signed_invite_to(credentials: &Credentials, target: &str, t0: Instant) -> Vec<u8> {
    let mut caller = agent(t0);
    caller.set_wall_clock(t0, wall(credentials));
    let id = caller.add_account(caller_account(credentials));
    caller
        .call(id, &OutgoingCall::new(uri(target)), t0)
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

/// The verdict a reporting agent trusting `credentials`' root reaches on
/// `invite`, its certificate fetched, under `config`.
fn verdict_on(
    credentials: &Credentials,
    invite: &[u8],
    config: impl FnOnce(StirConfig) -> StirConfig,
    t0: Instant,
) -> Arc<CallerVerification> {
    let (mut reporting, _) = called(credentials, true, StirVerification::Report, t0);
    let mut trusted = TrustAnchors::new();
    trusted
        .add(credentials.anchor.as_bytes())
        .expect("the test root");
    reporting.set_stir(config(StirConfig::new(trusted)));
    deliver(&mut reporting, invite, t0);
    let (call, _) = wanted(&events(&mut reporting)).expect("wanted");
    reporting
        .stir_certificate(call, Some(credentials.chain.as_bytes()), t0)
        .expect("waiting");
    verdict(&events(&mut reporting)).expect("verdict")
}

/// The claims of the INVITE's full-form PASSporT, as JSON text.
fn signed_claims(invite: &[u8]) -> String {
    let identity = String::from_utf8(header(invite, HeaderName::Identity)).expect("text");
    let segment = identity.split('.').nth(1).expect("a full form");
    // base64url without padding (RFC 7515 §2), six bits a character
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut json = Vec::new();
    let (mut bits, mut held) = (0_u32, 0);
    for c in segment.bytes() {
        let value = alphabet.iter().position(|a| *a == c).expect("base64url");
        bits = (bits << 6) | u32::try_from(value).expect("six bits");
        held += 6;
        if held >= 8 {
            held -= 8;
            json.push(u8::try_from((bits >> held) & 0xff).expect("a byte"));
        }
    }
    String::from_utf8(json).expect("JSON")
}

/// RFC 8224 §8.5: a call to a name is signed for the canonical form of the
/// URI it is to, whatever parameters, port or case the target carried.
#[test]
fn a_call_to_a_name_is_signed_for_its_canonical_uri() {
    let t0 = Instant::now();
    let credentials = credentials(&[CALLER]);
    let invite = signed_invite_to(
        &credentials,
        "sip:Alice@Biloxi.example.com:5070;transport=udp",
        t0,
    );
    let claims = signed_claims(&invite);
    assert!(
        claims.contains(r#""dest":{"uri":["sip:alice@biloxi.example.com"]}"#),
        "{claims}"
    );
}

/// RFC 8224 §6.2: the called party is compared in every case. A PASSporT
/// signed for a SIP URI holds for a request to that URI and not for a
/// request to anyone else, which a `To` that is not a number used to let
/// through unchecked.
#[test]
fn a_passport_for_a_sip_uri_holds_only_for_a_request_to_that_uri() {
    let t0 = Instant::now();
    let credentials = credentials(&[CALLER]);
    let invite = signed_invite_to(&credentials, "sip:alice@example.com", t0);

    let matching = verdict_on(&credentials, &invite, |config| config, t0);
    assert_eq!(matching.outcome, VerificationOutcome::Valid, "{matching:?}");

    let text = String::from_utf8(invite).expect("text");
    let pasted = text.replace("sip:alice@example.com", "sip:mallory@example.com");
    assert_ne!(pasted, text, "the To and the Request-URI were rewritten");
    let other = verdict_on(&credentials, pasted.as_bytes(), |config| config, t0);
    assert_eq!(other.outcome, VerificationOutcome::Invalid);
    assert_eq!(other.failure, Some(VerificationFailure::DestMismatch));
    assert_eq!(other.response.as_ref().map(|(code, _)| *code), Some(438));
    let detail = other.detail.as_deref().expect("a reason");
    assert!(
        detail.contains("signed for uri sip:alice@example.com")
            && detail.contains("uri sip:mallory@example.com"),
        "{detail}"
    );
}

/// A number in a SIP URI with `user=phone` (RFC 8224 §8.1) is signed as a
/// number and compared as one: the same number written another way holds,
/// another number does not.
#[test]
fn a_number_in_a_sip_uri_with_user_phone_is_compared_as_a_number() {
    let t0 = Instant::now();
    let credentials = credentials(&[CALLER]);
    let invite = signed_invite_to(
        &credentials,
        "sip:+1-212-555-1213@example.com;user=phone",
        t0,
    );
    let claims = signed_claims(&invite);
    assert!(
        claims.contains(&format!(r#""dest":{{"tn":["{CALLED}"]}}"#)),
        "{claims}"
    );
    let text = String::from_utf8(invite).expect("text");

    let rewritten = text.replace("+1-212-555-1213", "+12125551213");
    assert_ne!(rewritten, text);
    let same = verdict_on(&credentials, rewritten.as_bytes(), |config| config, t0);
    assert_eq!(same.outcome, VerificationOutcome::Valid, "{same:?}");

    let other = text.replace("+1-212-555-1213", "+1-212-555-9999");
    let refused = verdict_on(&credentials, other.as_bytes(), |config| config, t0);
    assert_eq!(refused.failure, Some(VerificationFailure::DestMismatch));
    let detail = refused.detail.as_deref().expect("a reason");
    assert!(
        detail.contains(&format!("signed for tn {CALLED}")) && detail.contains("tn 12125559999"),
        "{detail}"
    );
}

/// A certificate naming only a service provider code covers no number
/// unless the verification service is told to take codes as covering any.
#[test]
fn a_service_provider_code_covers_numbers_only_when_the_application_says_so() {
    let t0 = Instant::now();
    let credentials = sipral_stir::testing::provider_credentials("709J");
    let invite = signed_invite(&credentials, t0);

    let numbers_only = verdict_on(&credentials, &invite, |config| config, t0);
    assert_eq!(
        numbers_only.failure,
        Some(VerificationFailure::NumberNotCovered)
    );

    let providers = verdict_on(
        &credentials,
        &invite,
        |config| config.accept_service_provider_codes(true),
        t0,
    );
    assert_eq!(
        providers.outcome,
        VerificationOutcome::Valid,
        "{providers:?}"
    );
}

/// The same INVITE as a new request: another branch, another Call-ID, the
/// `Identity` it carried left as it was — what someone who captured a signed
/// call sends again.
fn replayed(invite: &[u8], tag: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(invite).into_owned();
    let branch = text
        .split("branch=")
        .nth(1)
        .and_then(|rest| rest.split([';', '\r']).next())
        .expect("a branch")
        .to_owned();
    let call_id = String::from_utf8_lossy(&header(invite, HeaderName::CallId)).into_owned();
    text.replace(&branch, &format!("z9hG4bK{tag}"))
        .replace(&call_id, &format!("{tag}@192.0.2.66"))
        .into_bytes()
}

/// The verdict `called` reaches on `invite`, its certificate fetched.
fn verified(
    called: &mut UserAgent,
    credentials: &Credentials,
    invite: &[u8],
    t0: Instant,
) -> Arc<CallerVerification> {
    deliver(called, invite, t0);
    let (call, _) = wanted(&events(called)).expect("the certificate is wanted");
    called
        .stir_certificate(call, Some(credentials.chain.as_bytes()), t0)
        .expect("the call was waiting");
    verdict(&events(called)).expect("a verdict")
}

/// RFC 8224 §12.1: a PASSporT already found valid, presented again in
/// another request inside its freshness window, is a replay, and the agent
/// remembers what it verified across calls to say so.
#[test]
fn a_passport_verified_once_is_refused_when_it_comes_again() {
    let t0 = Instant::now();
    let credentials = credentials(&[CALLER]);
    let invite = signed_invite(&credentials, t0);

    let (mut verifier, _) = called(&credentials, true, StirVerification::Report, t0);
    let first = verified(&mut verifier, &credentials, &invite, t0);
    assert_eq!(first.outcome, VerificationOutcome::Valid, "{first:?}");

    let again = verified(&mut verifier, &credentials, &replayed(&invite, "again"), t0);
    assert_eq!(again.outcome, VerificationOutcome::Invalid);
    assert_eq!(again.failure, Some(VerificationFailure::Stale));
    let detail = again.detail.as_deref().unwrap_or_default();
    assert!(detail.contains("already verified"), "{detail}");

    // another agent has seen nothing, and finds it valid
    let (mut elsewhere, _) = called(&credentials, true, StirVerification::Report, t0);
    let fresh = verified(
        &mut elsewhere,
        &credentials,
        &replayed(&invite, "again"),
        t0,
    );
    assert_eq!(fresh.outcome, VerificationOutcome::Valid);
}

/// A strict account refuses the replay with RFC 8224 §6.2.2's 403 Stale
/// Date, as it would a PASSporT too old.
#[test]
fn a_strict_account_refuses_a_replayed_passport_403() {
    let t0 = Instant::now();
    let credentials = credentials(&[CALLER]);
    let invite = signed_invite(&credentials, t0);

    let (mut called, _) = called(&credentials, true, StirVerification::Strict, t0);
    let first = verified(&mut called, &credentials, &invite, t0);
    assert_eq!(first.outcome, VerificationOutcome::Valid);
    transmits(&mut called);

    let again = verified(&mut called, &credentials, &replayed(&invite, "again"), t0);
    assert!(again.refused);
    assert_eq!(refusal(&mut called), "SIP/2.0 403 Stale Date");
}

/// The memory is the size the configuration names: with room for one, a
/// second PASSporT verified pushes the first out, and the first verifies
/// again; a configuration that keeps the size keeps what was remembered.
#[test]
fn the_agent_remembers_as_many_passports_as_it_is_told() {
    let t0 = Instant::now();
    let credentials = credentials(&[CALLER]);
    let one = signed_invite(&credentials, t0);
    // signed a second later: another PASSporT, in a request of its own
    let other = {
        let mut caller = agent(t0);
        caller.set_wall_clock(t0, wall(&credentials) + 1);
        let id = caller.add_account(caller_account(&credentials));
        caller
            .call(
                id,
                &OutgoingCall::new(uri(&format!("sip:{CALLED}@example.com"))),
                t0,
            )
            .expect("a signed call goes");
        replayed(&sent(&mut caller), "other")
    };
    let anchors = || {
        let mut trusted = TrustAnchors::new();
        trusted
            .add(credentials.anchor.as_bytes())
            .expect("the test root");
        trusted
    };

    let (mut called, _) = called(&credentials, true, StirVerification::Report, t0);
    called.set_stir(StirConfig::new(anchors()).remember(1));
    let first = verified(&mut called, &credentials, &one, t0);
    assert_eq!(first.outcome, VerificationOutcome::Valid);
    // the same size again keeps what it holds
    called.set_stir(StirConfig::new(anchors()).remember(1));
    let replay = verified(&mut called, &credentials, &replayed(&one, "kept"), t0);
    assert_eq!(replay.failure, Some(VerificationFailure::Stale));

    let second = verified(&mut called, &credentials, &other, t0);
    assert_eq!(second.outcome, VerificationOutcome::Valid, "{second:?}");
    let pushed_out = verified(&mut called, &credentials, &replayed(&one, "late"), t0);
    assert_eq!(
        pushed_out.outcome,
        VerificationOutcome::Valid,
        "{pushed_out:?}"
    );
}

/// RFC 8224 §8.3 under a dialling plan: a call placed to a national number
/// is signed for its international form, and the verifier reading the same
/// national number under the same plan finds the PASSporT names it. Without
/// the plan the verifier reads the number as written, and it is not the one
/// signed.
#[test]
fn a_dialling_plan_puts_a_national_number_in_international_form_both_ways() {
    let t0 = Instant::now();
    let credentials = credentials(&[CALLER]);
    // the North American plan, for ten-digit numbers
    let plan =
        || crate::NumberPlan::new(|number| (number.len() == 10).then(|| format!("1{number}")));
    let national = "sip:2125551213@example.com";

    let mut caller = agent(t0);
    caller.set_wall_clock(t0, wall(&credentials));
    caller.set_number_plan(Some(plan()));
    let id = caller.add_account(caller_account(&credentials));
    caller
        .call(id, &OutgoingCall::new(uri(national)), t0)
        .expect("a signed call goes");
    let invite = sent(&mut caller);
    let claims = signed_claims(&invite);
    assert!(
        claims.contains(&format!("\"tn\":[\"{CALLED}\"]")),
        "signed for the international number: {claims}"
    );

    let (mut planned, _) = called(&credentials, true, StirVerification::Report, t0);
    planned.set_number_plan(Some(plan()));
    let valid = verified(&mut planned, &credentials, &invite, t0);
    assert_eq!(valid.outcome, VerificationOutcome::Valid, "{valid:?}");

    let (mut unplanned, _) = called(&credentials, true, StirVerification::Report, t0);
    let mismatched = verified(&mut unplanned, &credentials, &invite, t0);
    assert_eq!(
        mismatched.failure,
        Some(VerificationFailure::DestMismatch),
        "{mismatched:?}"
    );
}

#[test]
fn a_number_plan_converts_only_what_is_not_international_already() {
    let plan = crate::NumberPlan::new(|number| {
        number
            .strip_prefix('0')
            .map(|national| format!("40{national}"))
    });
    let tn = |written: &str| plan.canonical(written).map(|tn| tn.as_str().to_owned());
    assert_eq!(tn("0721 234 567").as_deref(), Some("40721234567"));
    assert_eq!(tn("+40 721 234 567").as_deref(), Some("40721234567"));
    assert_eq!(tn("1001").as_deref(), Some("1001"), "the plan kept it");
    assert_eq!(tn("alice"), None);
    let wrong = crate::NumberPlan::new(|_| Some("not a number".to_owned()));
    assert_eq!(wrong.canonical("0721234567"), None);
}
