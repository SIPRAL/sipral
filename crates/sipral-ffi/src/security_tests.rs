// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! STIR/SHAKEN, the SRTP policy per account and the encryption report,
//! through the C ABI: two stacks in one process, one signing the call it
//! places and the other verifying it, driven the way C drives them.

use std::ffi::{c_char, c_void};
use std::ptr;

use sipral_stir::testing::{Credentials, credentials};

use crate::account::{SipralAccountConfig, sipral_account_add};
use crate::call::tests::{
    accepted, call_config, deliver, invitation, managed_config, media_line, one, place, sent,
};
use crate::call::{sipral_call_answer, sipral_call_answer_media};
use crate::error::last_error_text;
use crate::event::{SipralEvent, SipralEventKind};
use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
use crate::identity::{SipralIdentityText, sipral_call_identity_text};
use crate::media::{SipralSrtp, SipralSrtpSuite, sipral_call_media};
use crate::security::{
    SipralAttestation, SipralKeyExchange, SipralMediaKind, SipralStirConfig,
    SipralStreamEncryption, SipralVerificationFailure, SipralVerificationOutcome,
    SipralVerificationStage, sipral_call_stir_certificate, sipral_media_encryption_at,
    sipral_media_encryption_count, sipral_stack_stir,
};
use crate::stack::sipral_stack_destroy;
use crate::stack::tests::{Observed, config, create, poll, record};
use crate::status::SipralStatus;

const CALLER: &str = "12155551212";
const CALLED: &str = "sip:12125551213@example.com";
const X5U: &str = "https://cert.example.org/passport.pem";

/// A second stack's entropy, so that its tags and branches are not the
/// first one's.
static OTHER_SEED: [u8; 32] = [91; 32];

fn text(value: &str) -> (*const c_char, usize) {
    (value.as_ptr().cast::<c_char>(), value.len())
}

/// What one verification event said.
#[derive(Clone, Debug, Default)]
struct Verified {
    call: SipralHandle,
    stage: u32,
    outcome: u32,
    failure: u32,
    attestation: u32,
    response_code: u32,
    refused: u32,
    certificate_url: String,
    orig: String,
    message_len: usize,
}

/// What a stack under test said, read inside its callback.
#[derive(Default)]
struct Heard {
    kinds: Vec<SipralEventKind>,
    verified: Vec<Verified>,
    /// Every call event: the call, its kind, and the verdict it carried.
    calls: Vec<(SipralHandle, SipralEventKind, u32, u32, u32)>,
    /// Every media event that carries the encryption report.
    media: Vec<(SipralEventKind, u32, u32, u32, u32)>,
}

fn copied(pointer: *const c_char, len: usize) -> String {
    if pointer.is_null() {
        return String::new();
    }
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), len) };
    String::from_utf8_lossy(bytes).into_owned()
}

unsafe extern "C" fn listen(event: *const SipralEvent, user_data: *mut c_void) {
    let heard = unsafe { &mut *user_data.cast::<Heard>() };
    let event = unsafe { &*event };
    heard.kinds.push(event.kind);
    match event.kind {
        SipralEventKind::CallerVerification => {
            let payload = unsafe { event.payload.verification };
            heard.verified.push(Verified {
                call: event.call,
                stage: payload.stage,
                outcome: payload.outcome,
                failure: payload.failure,
                attestation: payload.attestation,
                response_code: payload.response_code,
                refused: payload.refused,
                certificate_url: copied(payload.certificate_url, payload.certificate_url_len),
                orig: copied(payload.orig, payload.orig_len),
                message_len: event.message_len,
            });
        }
        SipralEventKind::IncomingCall | SipralEventKind::CallEnded => {
            let payload = unsafe { event.payload.call };
            heard.calls.push((
                event.call,
                event.kind,
                payload.verification,
                payload.attestation,
                payload.verification_failure,
            ));
        }
        SipralEventKind::MediaStarted | SipralEventKind::MediaSecured => {
            let payload = unsafe { event.payload.media };
            heard.media.push((
                event.kind,
                payload.key_exchange,
                payload.encrypted,
                payload.authenticated,
                payload.suite,
            ));
        }
        _ => {}
    }
}

/// A stack reporting to `heard`, whose wall clock reads inside every test
/// certificate's validity.
fn stack_hearing(heard: &mut Heard, credentials: &Credentials, second: bool) -> SipralHandle {
    let mut unused = Observed::default();
    let mut config = config(record, &mut unused);
    config.event_callback = Some(listen);
    config.event_user_data = ptr::from_mut(heard).cast::<c_void>();
    if second {
        config.entropy = OTHER_SEED.as_ptr();
    }
    let (status, handle) = create(&config);
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    stir(handle, &[], credentials.not_before + 1_000);
    handle
}

/// `sipral_stack_stir` with these anchors and this wall clock at `now_ms`
/// zero.
fn stir(handle: SipralHandle, anchors: &[u8], unix_seconds: u64) {
    let config = stir_config(anchors, unix_seconds);
    let status = unsafe { sipral_stack_stir(handle, ptr::from_ref(&config), 0) };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
}

/// A `sipral_stir_config_t` with these anchors and this wall clock, the rest
/// zero.
fn stir_config(anchors: &[u8], unix_seconds: u64) -> SipralStirConfig {
    SipralStirConfig {
        size: size_of::<SipralStirConfig>(),
        anchors: if anchors.is_empty() {
            ptr::null()
        } else {
            anchors.as_ptr()
        },
        anchors_len: anchors.len(),
        freshness_seconds: 0,
        certificate_wait_ms: 0,
        unix_seconds,
        accept_service_provider_codes: 0,
    }
}

/// The verdict a stack trusting `credentials`' root reaches on `invite`,
/// with `accept_service_provider_codes` set to `providers`.
fn verdict_on(credentials: &Credentials, invite: &[u8], providers: u32) -> Verified {
    let mut heard = Heard::default();
    let callee = stack_hearing(&mut heard, credentials, true);
    let mut config = stir_config(credentials.anchor.as_bytes(), 0);
    config.accept_service_provider_codes = providers;
    let status = unsafe { sipral_stack_stir(callee, ptr::from_ref(&config), 0) };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    let (status, _) = account(callee, &called_account(0));
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    deliver(callee, invite, 20);
    poll(callee, 20);
    let wanted = heard
        .verified
        .first()
        .cloned()
        .expect("the certificate is wanted");
    let chain = credentials.chain.as_bytes();
    let status = unsafe {
        sipral_call_stir_certificate(callee, wanted.call, chain.as_ptr(), chain.len(), 30)
    };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    poll(callee, 30);
    let verdict = heard.verified.get(1).cloned().expect("the verdict");
    assert_eq!(unsafe { sipral_stack_destroy(callee) }, SipralStatus::Ok);
    verdict
}

/// ABI 0.32: a certificate that names a service provider code and no number
/// covers the caller only when the stack's STIR configuration says codes
/// count, and a value the toggle has no word for is refused.
#[test]
fn a_service_provider_code_covers_the_caller_only_when_the_stack_says_so() {
    let credentials = sipral_stir::testing::provider_credentials("709J");
    let invite = signed_invite(&credentials);
    let numbers_only = verdict_on(&credentials, &invite, 0);
    assert_eq!(
        numbers_only.outcome,
        SipralVerificationOutcome::Invalid as u32
    );
    assert_eq!(
        numbers_only.failure,
        SipralVerificationFailure::NumberNotCovered as u32
    );
    let providers = verdict_on(&credentials, &invite, crate::media::SipralToggle::On as u32);
    assert_eq!(providers.outcome, SipralVerificationOutcome::Valid as u32);

    let mut heard = Heard::default();
    let stack = stack_hearing(&mut heard, &credentials, false);
    let mut config = stir_config(&[], 0);
    config.accept_service_provider_codes = 3;
    let status = unsafe { sipral_stack_stir(stack, ptr::from_ref(&config), 0) };
    assert_eq!(status, SipralStatus::InvalidArgument);
    assert!(
        last_error_text().contains("accept_service_provider_codes"),
        "{}",
        last_error_text()
    );
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
}

/// ABI 0.32: an account says whether its encrypted calls may be recorded to
/// a recording server in the clear, off unless it does, and a value the
/// toggle has no word for is refused before the account is added.
#[test]
fn an_account_says_whether_its_encrypted_calls_may_be_recorded_in_the_clear() {
    let credentials = credentials(&[CALLER]);
    let mut heard = Heard::default();
    let stack = stack_hearing(&mut heard, &credentials, false);
    let in_clear = |handle: SipralHandle| {
        crate::stack::with_stack(stack, |state| {
            let id = state.accounts.get(handle).expect("the account");
            Ok(state
                .engine
                .account_srtp(id)
                .is_some_and(|srtp| srtp.recording_in_clear))
        })
        .expect("the stack")
    };
    let mut config = crate::account::tests::account_config();
    let (status, quiet) = account(stack, &config);
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    assert!(!in_clear(quiet), "off unless said");
    config.recording_in_clear = u64::from(crate::media::SipralToggle::On as u32);
    (config.aor, config.aor_len) = text("sip:open@example.com");
    let (status, open) = account(stack, &config);
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    assert!(in_clear(open));
    config.recording_in_clear = 9;
    let (status, _) = account(stack, &config);
    assert_eq!(status, SipralStatus::InvalidArgument);
    assert!(
        last_error_text().contains("recording_in_clear"),
        "{}",
        last_error_text()
    );
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
}

/// A caller built against ABI 0.31 declares the 384 bytes that header gave
/// `sipral_account_config_t`, whose last four were padding then and may be
/// left unwritten. Whatever they hold is not read as `recording_in_clear`:
/// the account is added, and its encrypted calls are recorded encrypted.
#[test]
fn padding_a_0_31_caller_left_unwritten_is_not_read_as_recording_in_clear() {
    const LENGTH_0_31: usize = 384;
    let credentials = credentials(&[CALLER]);
    let mut heard = Heard::default();
    let stack = stack_hearing(&mut heard, &credentials, false);
    let mut config = crate::account::tests::account_config();
    config.size = LENGTH_0_31;
    for garbage in [0xA5_u8, 0x01] {
        let bytes = ptr::from_mut(&mut config).cast::<u8>();
        for offset in LENGTH_0_31 - 4..LENGTH_0_31 {
            // the padding a 0.31 caller never wrote, whatever its stack held
            let byte = if offset == LENGTH_0_31 - 4 {
                garbage
            } else {
                0
            };
            unsafe { bytes.add(offset).write(byte) };
        }
        (config.aor, config.aor_len) = text(if garbage == 1 {
            "sip:one@example.com"
        } else {
            "sip:noise@example.com"
        });
        let (status, added) = account(stack, &config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let in_clear = crate::stack::with_stack(stack, |state| {
            let id = state.accounts.get(added).expect("the account");
            Ok(state
                .engine
                .account_srtp(id)
                .is_some_and(|srtp| srtp.recording_in_clear))
        })
        .expect("the stack");
        assert!(
            !in_clear,
            "padding holding {garbage:#x} was read as a toggle"
        );
    }
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
}

/// A stack created with no media clock dates its sender reports by the wall
/// clock `sipral_stack_stir` pairs with `now_ms`, and one created with a
/// media clock keeps it.
#[test]
fn a_stack_with_no_media_clock_takes_the_one_stir_is_given() {
    let credentials = credentials(&[CALLER]);
    let unix = credentials.not_before + 1_000;
    for (media_clock, expected) in [(0, unix), (unix - 500, unix - 500)] {
        let mut unused = Observed::default();
        let mut config = config(record, &mut unused);
        config.media_clock_unix_seconds = media_clock;
        let (status, stack) = create(&config);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        stir(stack, &[], unix);
        let read = crate::stack::with_stack(stack, |state| {
            let now = state.last_instant();
            Ok(state.engine.wall_clock().unix_at(now))
        })
        .expect("the stack");
        assert_eq!(read, expected, "media clock {media_clock}");
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }
}

fn account(handle: SipralHandle, config: &SipralAccountConfig) -> (SipralStatus, SipralHandle) {
    let mut account = SIPRAL_HANDLE_NONE;
    let status = unsafe { sipral_account_add(handle, ptr::from_ref(config), &raw mut account) };
    (status, account)
}

fn called_account(verification: u32) -> SipralAccountConfig {
    let mut config = crate::account::tests::account_config();
    (config.aor, config.aor_len) = text(CALLED);
    config.stir_verification = verification;
    config
}

fn trust(handle: SipralHandle, credentials: &Credentials) {
    // zero keeps the wall clock the stack was already given
    stir(handle, credentials.anchor.as_bytes(), 0);
}

/// The INVITE a signing account on its own stack places to [`CALLED`].
fn signed_invite(credentials: &Credentials) -> Vec<u8> {
    let mut heard = Heard::default();
    let caller = stack_hearing(&mut heard, credentials, false);
    let mut config = crate::account::tests::account_config();
    let aor = format!("sip:+{CALLER}@example.com");
    (config.aor, config.aor_len) = text(&aor);
    config.stir_key = credentials.key.as_ptr();
    config.stir_key_len = credentials.key.len();
    (config.stir_certificate_url, config.stir_certificate_url_len) = text(X5U);
    let (status, line) = account(caller, &config);
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    let mut call = call_config();
    (call.target, call.target_len) = text(CALLED);
    let (status, _) = place(caller, line, &call, 10);
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    let invite = one(caller);
    assert_eq!(unsafe { sipral_stack_destroy(caller) }, SipralStatus::Ok);
    invite
}

#[test]
fn a_signed_call_is_verified_through_the_c_abi_before_it_rings() {
    let credentials = credentials(&[CALLER]);
    let invite = signed_invite(&credentials);
    let written = String::from_utf8_lossy(&invite).into_owned();
    assert!(written.contains("\r\nIdentity: "), "{written}");
    assert!(written.contains(";ppt=shaken"), "{written}");

    let mut heard = Heard::default();
    let callee = stack_hearing(&mut heard, &credentials, true);
    trust(callee, &credentials);
    let (status, _) = account(callee, &called_account(0));
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    deliver(callee, &invite, 20);
    poll(callee, 20);

    let wanted = heard
        .verified
        .first()
        .cloned()
        .expect("the certificate is wanted");
    assert_eq!(
        wanted.stage,
        SipralVerificationStage::CertificateWanted as u32
    );
    assert_eq!(wanted.certificate_url, X5U);
    assert!(
        !heard.kinds.contains(&SipralEventKind::IncomingCall),
        "not before its verdict"
    );

    let chain = credentials.chain.as_bytes();
    let status = unsafe {
        sipral_call_stir_certificate(callee, wanted.call, chain.as_ptr(), chain.len(), 30)
    };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    poll(callee, 30);
    let verdict = heard.verified.get(1).cloned().expect("the verdict");
    assert_eq!(verdict.stage, SipralVerificationStage::Verified as u32);
    assert_eq!(verdict.outcome, SipralVerificationOutcome::Valid as u32);
    assert_eq!(verdict.attestation, SipralAttestation::A as u32);
    assert_eq!(verdict.orig, CALLER);
    assert_eq!(verdict.refused, 0);
    assert_ne!(verdict.message_len, 0, "the INVITE rides along");
    let verified_at = heard
        .kinds
        .iter()
        .rposition(|kind| *kind == SipralEventKind::CallerVerification);
    let rang_at = heard
        .kinds
        .iter()
        .position(|kind| *kind == SipralEventKind::IncomingCall);
    assert!(
        verified_at < rang_at,
        "the verdict first: {:?}",
        heard.kinds
    );
    let incoming = heard
        .calls
        .iter()
        .find(|(_, kind, ..)| *kind == SipralEventKind::IncomingCall)
        .copied()
        .expect("then the call");
    assert_eq!(incoming.0, wanted.call, "the same handle all along");
    assert_eq!(incoming.2, SipralVerificationOutcome::Valid as u32);
    assert_eq!(incoming.3, SipralAttestation::A as u32);

    // and the typed identity reads the number it was signed for
    let mut buffer = [0 as c_char; 64];
    let mut needed = 0usize;
    let status = unsafe {
        sipral_call_identity_text(
            callee,
            incoming.0,
            SipralIdentityText::VerifiedOrig as u32,
            0,
            buffer.as_mut_ptr(),
            buffer.len(),
            &raw mut needed,
        )
    };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    assert_eq!(needed, CALLER.len() + 1);
    // the call answers like any other
    let status = unsafe {
        sipral_call_answer(
            callee,
            incoming.0,
            crate::call::tests::ANSWER.as_ptr(),
            crate::call::tests::ANSWER.len(),
            40,
        )
    };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    assert_eq!(unsafe { sipral_stack_destroy(callee) }, SipralStatus::Ok);
}

#[test]
fn a_strict_account_refuses_an_unsigned_call_with_428_and_says_so() {
    let credentials = credentials(&[CALLER]);
    let mut heard = Heard::default();
    let callee = stack_hearing(&mut heard, &credentials, true);
    trust(callee, &credentials);
    let (status, _) = account(callee, &called_account(3));
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    let plain = String::from_utf8_lossy(&invitation())
        .replace("To: <sip:alice@example.com>", &format!("To: <{CALLED}>"))
        .into_bytes();
    deliver(callee, &plain, 20);
    poll(callee, 20);
    let verdict = heard.verified.first().cloned().expect("the verdict");
    assert_eq!(verdict.outcome, SipralVerificationOutcome::Absent as u32);
    assert_eq!(
        verdict.failure,
        SipralVerificationFailure::NoIdentity as u32
    );
    assert_eq!(verdict.response_code, 428);
    assert_eq!(verdict.refused, 1);
    assert!(
        heard
            .calls
            .iter()
            .any(|(_, kind, ..)| *kind == SipralEventKind::CallEnded),
        "{:?}",
        heard.kinds
    );
    assert!(!heard.kinds.contains(&SipralEventKind::IncomingCall));
    let refusal = sent(callee)
        .into_iter()
        .find(|bytes| bytes.starts_with(b"SIP/2.0 4"))
        .expect("a refusal");
    assert!(refusal.starts_with(b"SIP/2.0 428 Use Identity Header\r\n"));
    assert_eq!(unsafe { sipral_stack_destroy(callee) }, SipralStatus::Ok);
}

#[test]
fn what_an_account_says_about_stir_is_checked_before_it_is_added() {
    let credentials = credentials(&[CALLER]);
    let mut heard = Heard::default();
    let handle = stack_hearing(&mut heard, &credentials, false);
    let mut half = called_account(0);
    half.stir_key = credentials.key.as_ptr();
    half.stir_key_len = credentials.key.len();
    assert_eq!(account(handle, &half).0, SipralStatus::InvalidArgument);
    let mut unknown = called_account(9);
    unknown.stir_verification = 9;
    assert_eq!(account(handle, &unknown).0, SipralStatus::InvalidArgument);
    let mut bad_key = called_account(0);
    let zero = [0u8; 32];
    bad_key.stir_key = zero.as_ptr();
    bad_key.stir_key_len = zero.len();
    (
        bad_key.stir_certificate_url,
        bad_key.stir_certificate_url_len,
    ) = text(X5U);
    assert_eq!(account(handle, &bad_key).0, SipralStatus::InvalidArgument);
    assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);

    // a stack that was never told the time cannot sign; the media clock's
    // seconds go with no `now_ms`, and are not taken for the time
    let mut unused = Observed::default();
    let mut created = config(record, &mut unused);
    created.media_clock_unix_seconds = credentials.not_before + 1_000;
    let (status, clockless) = create(&created);
    assert_eq!(status, SipralStatus::Ok);
    let mut signing = called_account(0);
    signing.stir_key = credentials.key.as_ptr();
    signing.stir_key_len = credentials.key.len();
    (
        signing.stir_certificate_url,
        signing.stir_certificate_url_len,
    ) = text(X5U);
    assert_eq!(account(clockless, &signing).0, SipralStatus::WrongState);
    let stir = SipralStirConfig {
        size: size_of::<SipralStirConfig>(),
        anchors: ptr::null(),
        anchors_len: 0,
        freshness_seconds: 0,
        certificate_wait_ms: 0,
        unix_seconds: 0,
        accept_service_provider_codes: 0,
    };
    assert_eq!(
        unsafe { sipral_stack_stir(clockless, ptr::from_ref(&stir), 0) },
        SipralStatus::WrongState
    );
    assert_eq!(unsafe { sipral_stack_destroy(clockless) }, SipralStatus::Ok);
}

/// 8.10: the account's own SRTP policy, and a call that asks for less.
#[test]
fn an_account_that_requires_srtp_refuses_a_plain_invite_and_a_call_that_asks_for_less() {
    let mut observed = Observed::default();
    let (handle, _) = media_line(&mut observed, |_| {});
    // a second account beside the stack's own, with a line of its own
    let mut strict = crate::account::tests::account_config();
    (strict.aor, strict.aor_len) = text("sip:carol@example.com");
    (strict.contact, strict.contact_len) = text("sip:carol@192.0.2.10:5060");
    strict.srtp = SipralSrtp::Required as u32;
    let (suites, suites_len) = text("AES_CM_128_HMAC_SHA1_80");
    strict.srtp_suites = suites;
    strict.srtp_suites_len = suites_len;
    let (status, line) = account(handle, &strict);
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());

    // an INVITE for it in the clear: 488, and the status that says why
    let for_carol = String::from_utf8_lossy(&invitation())
        .replace("sip:alice@", "sip:carol@")
        .into_bytes();
    deliver(handle, &for_carol, 1_000);
    poll(handle, 1_000);
    let call = observed
        .named
        .iter()
        .zip(&observed.events)
        .find(|(_, event)| event.1 == SipralEventKind::IncomingCall)
        .map(|(named, _)| named.1)
        .expect("the INVITE arrived");
    let _ = sent(handle);
    let (address, address_len) = text(crate::call::tests::MEDIA);
    let status = unsafe { sipral_call_answer_media(handle, call, address, address_len, 1_100) };
    assert_eq!(
        status,
        SipralStatus::SecurityPolicy,
        "{}",
        last_error_text()
    );
    assert!(one(handle).starts_with(b"SIP/2.0 488 "));

    // a call it places may not ask for less than the account requires
    let mut plain = managed_config();
    plain.srtp = SipralSrtp::NotOffered as u32;
    let (status, _) = place(handle, line, &plain, 1_200);
    assert_eq!(
        status,
        SipralStatus::SecurityPolicy,
        "{}",
        last_error_text()
    );
    assert!(sent(handle).is_empty(), "nothing left");

    // and what it places offers its own suite, required
    let (status, _) = place(handle, line, &managed_config(), 1_300);
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    let offer = String::from_utf8_lossy(&one(handle)).into_owned();
    assert!(offer.contains("RTP/SAVP"), "{offer}");
    assert!(
        offer.contains("a=crypto:1 AES_CM_128_HMAC_SHA1_80 "),
        "{offer}"
    );
    assert!(!offer.contains("AEAD_AES_256_GCM"), "{offer}");

    let mut unknown = crate::account::tests::account_config();
    let (suites, suites_len) = text("AES_CM_128_HMAC_SHA1_80,NULL");
    unknown.srtp_suites = suites;
    unknown.srtp_suites_len = suites_len;
    assert_eq!(account(handle, &unknown).0, SipralStatus::InvalidArgument);
    assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
}

#[test]
fn the_encryption_report_says_how_an_sdes_call_is_protected() {
    let credentials = credentials(&[CALLER]);
    let mut heard = Heard::default();
    let handle = stack_hearing(&mut heard, &credentials, false);
    let mut keyed = crate::account::tests::account_config();
    keyed.srtp = SipralSrtp::Required as u32;
    let (status, line) = account(handle, &keyed);
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    let (status, call) = place(handle, line, &managed_config(), 1_000);
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    let invite = one(handle);
    let answer = "v=0\r\no=bob 1 1 IN IP4 203.0.113.5\r\ns=-\r\nc=IN IP4 203.0.113.5\r\nt=0 0\r\n\
                  m=audio 41000 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
                  a=crypto:2 AES_CM_128_HMAC_SHA1_80 \
                  inline:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\r\na=sendrecv\r\n";
    deliver(handle, &accepted(&invite, answer.as_bytes(), true), 1_050);
    poll(handle, 1_050);
    let started = heard
        .media
        .iter()
        .find(|(kind, ..)| *kind == SipralEventKind::MediaStarted)
        .copied()
        .expect("media started");
    assert_eq!(started.1, SipralKeyExchange::Sdes as u32);
    assert_eq!(started.2, 1, "encrypted from the start");
    assert_eq!(started.3, 0, "SDES authenticates nothing");
    assert_eq!(started.4, SipralSrtpSuite::AesCm80 as u32);

    let mut media = SIPRAL_HANDLE_NONE;
    let status = unsafe { sipral_call_media(handle, call, &raw mut media) };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    let mut count = usize::MAX;
    let status = unsafe { sipral_media_encryption_count(media, &raw mut count) };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    assert_eq!(count, 1);
    let mut stream = SipralStreamEncryption {
        size: size_of::<SipralStreamEncryption>(),
        media: u32::MAX,
        encrypted: u32::MAX,
        key_exchange: u32::MAX,
        suite: u32::MAX,
        authenticated: u32::MAX,
        awaiting_keys: u32::MAX,
    };
    let status = unsafe { sipral_media_encryption_at(media, 0, &raw mut stream) };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    assert_eq!(stream.media, SipralMediaKind::Audio as u32);
    assert_eq!(stream.encrypted, 1);
    assert_eq!(stream.key_exchange, SipralKeyExchange::Sdes as u32);
    assert_eq!(stream.suite, SipralSrtpSuite::AesCm80 as u32);
    assert_eq!(stream.authenticated, 0);
    assert_eq!(stream.awaiting_keys, 0);
    assert_eq!(
        unsafe { sipral_media_encryption_at(media, 1, &raw mut stream) },
        SipralStatus::InvalidArgument
    );
    assert_eq!(
        unsafe { crate::media::sipral_media_release(media) },
        SipralStatus::Ok
    );
    assert_eq!(unsafe { sipral_stack_destroy(handle) }, SipralStatus::Ok);
}

/// The four layers prove a service provider code's coverage with the files
/// in `bindings/fixtures/stir-provider-709J`, having no certificate
/// authority of their own: those files are the credentials
/// `sipral_stir::testing` issues for the code `709J`, and stay so.
#[test]
fn the_layers_provider_fixture_is_the_testing_provider_credentials() {
    let issued = sipral_stir::testing::provider_credentials("709J");
    assert_eq!(
        include_str!("../../../bindings/fixtures/stir-provider-709J/anchor.pem"),
        issued.anchor
    );
    assert_eq!(
        include_str!("../../../bindings/fixtures/stir-provider-709J/chain.pem"),
        issued.chain
    );
    let hex = include_str!("../../../bindings/fixtures/stir-provider-709J/signing-scalar.hex")
        .trim_end()
        .as_bytes();
    let scalar: Vec<u8> = hex
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16).expect("hex"))
        .collect();
    assert_eq!(scalar, issued.key);
}
