// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Who is calling, as a signature says, and how a call's media is protected,
//! across the boundary (ABI 0.31).
//!
//! # STIR/SHAKEN
//!
//! An account given a P-256 key and the URL of its certificate
//! (`stir_key`, `stir_certificate_url` in `sipral_account_config_t`) signs
//! every call it places (RFC 8224 §6.1, with RFC 8588's SHAKEN claims). A
//! stack given trust anchors ([`sipral_stack_stir`]) verifies the callers of
//! the calls its accounts receive (§6.2): the certificate is the
//! application's to fetch, from its cache or over HTTPS, when
//! `SIPRAL_EVENT_KIND_CALLER_VERIFICATION` asks for it with
//! `SIPRAL_VERIFICATION_STAGE_CERTIFICATE_WANTED`, and to hand over with
//! [`sipral_call_stir_certificate`]. The verdict follows as the same kind of
//! event with `SIPRAL_VERIFICATION_STAGE_VERIFIED`, just before
//! `SIPRAL_EVENT_KIND_INCOMING_CALL`, and rides on every event of the call
//! (`sipral_call_event_t::verification`). An account set to
//! `SIPRAL_STIR_VERIFICATION_STRICT` refuses a call that does not verify with
//! the response RFC 8224 §6.2.2 prescribes; every other account reports and
//! delivers.
//!
//! # The encryption report
//!
//! [`sipral_media_encryption_at`] says, for each stream of a call, whether
//! it is encrypted, how its keys were exchanged, which suite it runs, and
//! whether the exchange authenticated the far end — the same facts
//! `SIPRAL_EVENT_KIND_MEDIA_STARTED` and `SIPRAL_EVENT_KIND_MEDIA_SECURED`
//! carry in `sipral_media_event_t`.

use std::ffi::c_char;
use std::slice;

use sipral::{SrtpKeying, SrtpSuite, StreamEncryption};
use sipral_ua::{
    Attestation, CallerVerification, StirVerification, VerificationFailure, VerificationOutcome,
};

use crate::abi::{codes, record};
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::media::{SipralSrtpSuite, with_media};
use crate::stack::{handle_failed, with_stack_at};
use crate::status::SipralStatus;
use crate::versioned::{Versioned, read_versioned, write_versioned};

codes! {
    /// How a stream's SRTP keys were exchanged. Names for
    /// `sipral_stream_encryption_t::key_exchange` and
    /// `sipral_media_event_t::key_exchange`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralKeyExchange: u32 {
        /// None: the stream was never meant to be encrypted, or the event is
        /// not about one.
        None = 0,
        /// In the session description (RFC 4568's `a=crypto`): as protected
        /// as the signalling transport that carried it.
        Sdes = 1,
        /// By a DTLS handshake on the media path (RFC 5764), the far end's
        /// certificate checked against the fingerprint its signalling named.
        Dtls = 2,
    }
}

codes! {
    /// What a stream carries. Names for `sipral_stream_encryption_t::media`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralMediaKind: u32 {
        /// Something this ABI has no word for.
        Unknown = 0,
        /// `m=audio`.
        Audio = 1,
    }
}

codes! {
    /// What an account does with the `Identity` header fields of the calls
    /// it receives (RFC 8224 §6.2). Names for
    /// `sipral_account_config_t::stir_verification`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralStirVerification: u32 {
        /// This build's default, which is `REPORT`.
        Default = 0,
        /// Verify nothing.
        Off = 1,
        /// Verify, report the verdict on the call, and deliver every call
        /// whatever it says. In force once the stack has trust anchors
        /// (`sipral_stack_stir`); without any, nothing is fetched or
        /// verified.
        Report = 2,
        /// Verify, and refuse a call that does not verify with the response
        /// RFC 8224 §6.2.2 prescribes: 428 with no `Identity`, 436 for a
        /// certificate that cannot be had, 437 for one nobody trusted, 438
        /// for a signature that does not hold, 403 "Stale Date". In force
        /// with or without trust anchors: with none, nothing verifies.
        Strict = 3,
    }
}

codes! {
    /// The attestation level of a SHAKEN PASSporT (RFC 8588 §4). Names for
    /// `sipral_account_config_t::stir_attestation`,
    /// `sipral_verification_event_t::attestation` and
    /// `sipral_call_event_t::attestation`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralAttestation: u32 {
        /// None said: on an account, full attestation; on a verdict, a
        /// PASSporT with no SHAKEN claims, or no valid one.
        None = 0,
        /// Full: the signer knows the caller and that the number is theirs.
        A = 1,
        /// Partial: the signer knows the caller, not the number.
        B = 2,
        /// Gateway: the signer knows only where the call entered its
        /// network.
        C = 3,
    }
}

codes! {
    /// What a verification came to. Names for
    /// `sipral_verification_event_t::outcome` and
    /// `sipral_call_event_t::verification`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralVerificationOutcome: u32 {
        /// Nothing was verified: the account does not verify, or the stack
        /// has no trust anchors and the account only reports.
        None = 0,
        /// A PASSporT signed by a certificate with authority over the calling
        /// number, fresh, for the numbers the request names.
        Valid = 1,
        /// One was there and does not hold: `failure` says why.
        Invalid = 2,
        /// Nothing this end could verify: no `Identity`, or only ones naming
        /// a PASSporT extension it does not support.
        Absent = 3,
    }
}

codes! {
    /// Why a verification did not hold. Names for
    /// `sipral_verification_event_t::failure` and
    /// `sipral_call_event_t::verification_failure`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralVerificationFailure: u32 {
        /// Nothing failed.
        None = 0,
        /// No `Identity` header field.
        NoIdentity = 1,
        /// Only ones naming a `ppt` this end does not support.
        UnsupportedPpt = 2,
        /// The header field or its PASSporT is not well formed.
        Malformed = 3,
        /// Signed with an algorithm other than ES256.
        UnsupportedAlgorithm = 4,
        /// `iat` outside the freshness window.
        Stale = 5,
        /// The certificate could not be fetched, or did not arrive in time.
        CertificateUnavailable = 6,
        /// What the `info` URL yielded is not a chain this end can read.
        CertificateUnreadable = 7,
        /// The chain leads to no trust anchor.
        Untrusted = 8,
        /// A certificate in it is outside its validity period.
        Expired = 9,
        /// The chain breaks a rule of path validation.
        InvalidChain = 10,
        /// The signature does not verify.
        BadSignature = 11,
        /// The certificate has no authority over the calling number.
        NumberNotCovered = 12,
        /// Signed for another calling number than the request names.
        OrigMismatch = 13,
        /// Signed for another called number.
        DestMismatch = 14,
    }
}

codes! {
    /// Which half of a caller's verification an event reports. Names for
    /// `sipral_verification_event_t::stage`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralVerificationStage: u32 {
        /// Never sent.
        Unknown = 0,
        /// The certificate at `certificate_url` is wanted: fetch it and hand
        /// it to `sipral_call_stir_certificate`, or hand over nothing to say
        /// it could not be had. The call waits, unannounced, until then or
        /// until `certificate_wait_ms` runs out.
        CertificateWanted = 1,
        /// The verdict is in. `SIPRAL_EVENT_KIND_INCOMING_CALL` follows, or,
        /// when `refused` is set, `SIPRAL_EVENT_KIND_CALL_ENDED`.
        Verified = 2,
    }
}

record! {
    /// How a stack verifies the callers of the calls its accounts receive.
    ///
    /// Set `size` to `sizeof(sipral_stir_config_t)` and zero the rest before
    /// filling anything in.
    #[derive(Clone, Copy)]
    pub struct SipralStirConfig {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// The trust anchors — the STI-PA's approved roots in a SHAKEN
        /// deployment — as PEM or DER certificates, one after another. Null
        /// and zero for none, which turns verification off for every account
        /// that only reports.
        pub anchors: *const u8,
        /// How many bytes of them.
        pub anchors_len: usize,
        /// How far a PASSporT's `iat` may be from now, either way, in
        /// seconds; zero for RFC 8224 §6.2's sixty.
        pub freshness_seconds: u64,
        /// How long a call waits for `sipral_call_stir_certificate` before
        /// its certificate counts as one that could not be had, in
        /// milliseconds; zero for four seconds.
        pub certificate_wait_ms: u64,
        /// The wall clock at `now_ms`, in seconds since 1970, or zero to keep
        /// the one an earlier call gave. A PASSporT is signed and judged by
        /// the time, and only the caller can say which `now_ms` a time goes
        /// with, so the first call must give it.
        /// (`sipral_stack_config_t::media_clock_unix_seconds` goes with no
        /// `now_ms` at all, and is not taken for it.)
        pub unix_seconds: u64,
    }
}

// Safety: integers and one pointer beside its length, and all-zero is valid:
// no anchors, the defaults, and the stack's own clock.
unsafe impl Versioned for SipralStirConfig {
    const NAME: &'static str = "sipral_stir_config";
    const MIN_SIZE: usize = crate::versioned::min_size::STIR_CONFIG;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// How one stream of a call is protected: one entry of the encryption
    /// report.
    ///
    /// Set `size` to `sizeof(sipral_stream_encryption_t)` before the call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralStreamEncryption {
        /// How many bytes of this struct the library filled in.
        pub size: usize,
        /// A [`SipralMediaKind`]: what the stream carries.
        pub media: u32,
        /// Whether what it sends is encrypted and what it takes
        /// authenticated, now. Zero while it waits for the handshake that
        /// keys it.
        pub encrypted: u32,
        /// A [`SipralKeyExchange`]: how its keys were exchanged.
        pub key_exchange: u32,
        /// A [`SipralSrtpSuite`]: the transform it runs, once it runs one.
        pub suite: u32,
        /// Whether the key exchange authenticated the far end: set for a
        /// DTLS-SRTP stream once its handshake finished, the far end's
        /// certificate having matched its signalled fingerprint; never for
        /// SDES, whose key is exactly as authentic as the signalling
        /// transport, which this library cannot see.
        pub authenticated: u32,
        /// Whether it agreed to be encrypted and is still waiting for its
        /// keys.
        pub awaiting_keys: u32,
    }
}

// Safety: integers, and zero is a valid value of each.
unsafe impl Versioned for SipralStreamEncryption {
    const NAME: &'static str = "sipral_stream_encryption";
    const MIN_SIZE: usize = crate::versioned::min_size::STREAM_ENCRYPTION;

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// The transform a suite names, in the ABI's words.
pub(crate) const fn suite_code(suite: SrtpSuite) -> SipralSrtpSuite {
    match suite {
        SrtpSuite::AesCm80 => SipralSrtpSuite::AesCm80,
        SrtpSuite::AesCm32 => SipralSrtpSuite::AesCm32,
        SrtpSuite::AesF8 => SipralSrtpSuite::AesF8,
        SrtpSuite::Aes256Cm80 => SipralSrtpSuite::Aes256Cm80,
        SrtpSuite::Aes256Cm32 => SipralSrtpSuite::Aes256Cm32,
        SrtpSuite::AeadAes128Gcm => SipralSrtpSuite::AeadAes128Gcm,
        SrtpSuite::AeadAes256Gcm => SipralSrtpSuite::AeadAes256Gcm,
    }
}

/// A key exchange, in the ABI's words.
pub(crate) const fn key_exchange_code(keying: Option<SrtpKeying>) -> SipralKeyExchange {
    match keying {
        Some(SrtpKeying::Sdes) => SipralKeyExchange::Sdes,
        Some(SrtpKeying::Dtls) => SipralKeyExchange::Dtls,
        _ => SipralKeyExchange::None,
    }
}

/// One entry of a report, as C reads it.
pub(crate) fn stream_encryption(stream: &StreamEncryption) -> SipralStreamEncryption {
    SipralStreamEncryption {
        size: size_of::<SipralStreamEncryption>(),
        media: if stream.media == "audio" {
            SipralMediaKind::Audio as u32
        } else {
            SipralMediaKind::Unknown as u32
        },
        encrypted: u32::from(stream.encrypted),
        key_exchange: key_exchange_code(stream.key_exchange) as u32,
        suite: stream.suite.map_or(0, |suite| suite_code(suite) as u32),
        authenticated: u32::from(stream.authenticated),
        awaiting_keys: u32::from(stream.awaiting_keys),
    }
}

/// A verdict's outcome, in the ABI's words; `None` for no verdict.
pub(crate) const fn outcome_code(
    verification: Option<&CallerVerification>,
) -> SipralVerificationOutcome {
    match verification {
        None => SipralVerificationOutcome::None,
        Some(verdict) => match verdict.outcome {
            VerificationOutcome::Valid => SipralVerificationOutcome::Valid,
            VerificationOutcome::Invalid => SipralVerificationOutcome::Invalid,
            _ => SipralVerificationOutcome::Absent,
        },
    }
}

/// Why a verdict did not hold, in the ABI's words.
pub(crate) const fn failure_code(
    failure: Option<VerificationFailure>,
) -> SipralVerificationFailure {
    match failure {
        None => SipralVerificationFailure::None,
        Some(VerificationFailure::NoIdentity) => SipralVerificationFailure::NoIdentity,
        Some(VerificationFailure::UnsupportedPpt) => SipralVerificationFailure::UnsupportedPpt,
        Some(VerificationFailure::UnsupportedAlgorithm) => {
            SipralVerificationFailure::UnsupportedAlgorithm
        }
        Some(VerificationFailure::Stale) => SipralVerificationFailure::Stale,
        Some(VerificationFailure::CertificateUnavailable) => {
            SipralVerificationFailure::CertificateUnavailable
        }
        Some(VerificationFailure::CertificateUnreadable) => {
            SipralVerificationFailure::CertificateUnreadable
        }
        Some(VerificationFailure::Untrusted) => SipralVerificationFailure::Untrusted,
        Some(VerificationFailure::Expired) => SipralVerificationFailure::Expired,
        Some(VerificationFailure::InvalidChain) => SipralVerificationFailure::InvalidChain,
        Some(VerificationFailure::BadSignature) => SipralVerificationFailure::BadSignature,
        Some(VerificationFailure::NumberNotCovered) => SipralVerificationFailure::NumberNotCovered,
        Some(VerificationFailure::OrigMismatch) => SipralVerificationFailure::OrigMismatch,
        Some(VerificationFailure::DestMismatch) => SipralVerificationFailure::DestMismatch,
        // `Malformed`, and a failure the layer below learned to name after
        // this ABI did, which is still a failure and reads as the broadest
        // one there is
        Some(_) => SipralVerificationFailure::Malformed,
    }
}

/// An attestation level, in the ABI's words.
pub(crate) const fn attestation_code(attestation: Option<Attestation>) -> SipralAttestation {
    match attestation {
        Some(Attestation::A) => SipralAttestation::A,
        Some(Attestation::B) => SipralAttestation::B,
        Some(Attestation::C) => SipralAttestation::C,
        _ => SipralAttestation::None,
    }
}

/// An account's `stir_verification`, as the policy it names.
pub(crate) fn stir_verification(value: u32) -> Result<StirVerification, Fail> {
    match value {
        0 | 2 => Ok(StirVerification::Report),
        1 => Ok(StirVerification::Off),
        3 => Ok(StirVerification::Strict),
        other => Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "stir_verification is {other}, and it is 0 for the default, 1 for off, 2 to \
                 report or 3 to refuse what does not verify"
            ),
        )),
    }
}

/// An account's `srtp_suites`: the names RFC 4568 §6.2 and RFC 7714 §14.2
/// give the transforms, separated by commas, most preferred first.
pub(crate) fn srtp_suites(names: Option<&str>) -> Result<Option<Vec<SrtpSuite>>, Fail> {
    let Some(names) = names else {
        return Ok(None);
    };
    let mut suites = Vec::new();
    for name in names.split(',').map(str::trim) {
        let suite = match name {
            "AES_CM_128_HMAC_SHA1_80" => SrtpSuite::AesCm80,
            "AES_CM_128_HMAC_SHA1_32" => SrtpSuite::AesCm32,
            "F8_128_HMAC_SHA1_80" => SrtpSuite::AesF8,
            "AES_256_CM_HMAC_SHA1_80" => SrtpSuite::Aes256Cm80,
            "AES_256_CM_HMAC_SHA1_32" => SrtpSuite::Aes256Cm32,
            "AEAD_AES_128_GCM" => SrtpSuite::AeadAes128Gcm,
            "AEAD_AES_256_GCM" => SrtpSuite::AeadAes256Gcm,
            other => {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    format!(
                        "srtp_suites names {other:?}, which is not one of the seven SRTP suites \
                         this library runs: AEAD_AES_256_GCM, AEAD_AES_128_GCM, \
                         AES_256_CM_HMAC_SHA1_80, AES_256_CM_HMAC_SHA1_32, \
                         AES_CM_128_HMAC_SHA1_80, AES_CM_128_HMAC_SHA1_32, F8_128_HMAC_SHA1_80"
                    ),
                ));
            }
        };
        if suites.contains(&suite) {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("srtp_suites names {name} twice"),
            ));
        }
        suites.push(suite);
    }
    Ok(Some(suites))
}

/// Bytes a caller supplied that may be longer than any text this ABI takes:
/// a certificate chain, or a bundle of trust anchors.
///
/// # Safety
///
/// `pointer`, when it is not null, must be readable for `len` bytes and
/// stay so for as long as the returned slice is used.
unsafe fn blob<'a>(
    pointer: *const u8,
    len: usize,
    most: usize,
    name: &'static str,
) -> Result<Option<&'a [u8]>, Fail> {
    if len > most {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!("{name} is {len} bytes, and this ABI takes at most {most}"),
        ));
    }
    match (pointer.is_null(), len) {
        (_, 0) => Ok(None),
        (true, _) => Err(fail(
            SipralStatus::InvalidArgument,
            format!("{name} is null and says it is {len} bytes long"),
        )),
        (false, _) => Ok(Some(unsafe { slice::from_raw_parts(pointer, len) })),
    }
}

/// The most trust anchors one call takes, in bytes: a store of several
/// hundred roots in PEM.
const MAX_ANCHORS: usize = 4 * 1024 * 1024;

entry! {
    /// Verify the callers of the calls this stack's accounts receive, against
    /// `config`'s trust anchors, from now on (RFC 8224 §6.2).
    ///
    /// Replaces whatever an earlier call set. Every account that reports —
    /// the default — verifies once there is at least one anchor, and none
    /// does with none; an account set to `SIPRAL_STIR_VERIFICATION_STRICT`
    /// verifies either way. `config.unix_seconds` is the wall clock at
    /// `now_ms`, and the stack signs and verifies by it from here on; zero
    /// keeps what an earlier call gave, and is `SIPRAL_STATUS_WRONG_STATE`
    /// on the first. A stack whose accounts only sign calls makes this call
    /// too, with no anchors.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for anchors that are not
    /// certificates, or whose key is not P-256; `SIPRAL_STATUS_NOT_SUPPORTED`
    /// in a build without `SIPRAL_FEATURE_STIR`.
    ///
    /// # Safety
    ///
    /// `config` must point at a `sipral_stir_config_t` whose `size` member
    /// says how long it is, with `anchors` readable for `anchors_len` bytes.
    fn sipral_stack_stir(stack: SipralHandle, config: *const SipralStirConfig, now_ms: u64) {
        let config = unsafe { read_versioned(config) }?;
        let anchors = unsafe { blob(config.anchors, config.anchors_len, MAX_ANCHORS, "anchors") }?;
        with_stack_at(stack, now_ms, |state, now| {
            configure_stir(state, &config, anchors, now)
        })
    }
}

#[cfg(feature = "stir")]
fn configure_stir(
    state: &mut crate::stack::StackState,
    config: &SipralStirConfig,
    anchors: Option<&[u8]>,
    now: std::time::Instant,
) -> Result<(), Fail> {
    let mut trusted = sipral::stir::TrustAnchors::new();
    if let Some(anchors) = anchors {
        trusted
            .add(anchors)
            .map_err(|error| fail(SipralStatus::InvalidArgument, format!("anchors: {error}")))?;
    }
    if config.unix_seconds != 0 {
        state.agent.set_wall_clock(now, config.unix_seconds);
    } else if !state.agent.knows_the_time() {
        return Err(fail(
            SipralStatus::WrongState,
            "no wall clock yet, and a PASSporT is judged against the time: set unix_seconds",
        ));
    }
    let mut stir = sipral::StirConfig::new(trusted);
    if config.freshness_seconds != 0 {
        stir = stir.freshness(config.freshness_seconds);
    }
    if config.certificate_wait_ms != 0 {
        stir = stir.certificate_wait(std::time::Duration::from_millis(config.certificate_wait_ms));
    }
    state.agent.set_stir(stir);
    Ok(())
}

#[cfg(not(feature = "stir"))]
fn configure_stir(
    _state: &mut crate::stack::StackState,
    _config: &SipralStirConfig,
    _anchors: Option<&[u8]>,
    _now: std::time::Instant,
) -> Result<(), Fail> {
    Err(fail(
        SipralStatus::NotSupported,
        "this build has no STIR/SHAKEN: SIPRAL_FEATURE_STIR is clear in sipral_capabilities",
    ))
}

entry! {
    /// The certificate chain a call's `Identity` named, as fetched from the
    /// URL `SIPRAL_EVENT_KIND_CALLER_VERIFICATION` gave with
    /// `SIPRAL_VERIFICATION_STAGE_CERTIFICATE_WANTED` — PEM or DER, the
    /// signing certificate first — or null and zero for one that could not
    /// be fetched.
    ///
    /// The call's verdict is reached here and reported, and the call
    /// delivered or refused, before this returns; the events come out of the
    /// next `sipral_stack_poll`. `SIPRAL_STATUS_STALE_HANDLE` for a call no
    /// longer waiting: it was already answered, its wait ran out, or the
    /// caller gave up.
    ///
    /// # Safety
    ///
    /// `chain` must be readable for `chain_len` bytes, or null with a length
    /// of zero.
    fn sipral_call_stir_certificate(
        stack: SipralHandle,
        call: SipralHandle,
        chain: *const u8,
        chain_len: usize,
        now_ms: u64,
    ) {
        let chain = unsafe { blob(chain, chain_len, MAX_ANCHORS, "chain") }?;
        with_stack_at(stack, now_ms, |state, now| {
            let id = state.calls.get(call).map_err(handle_failed)?;
            certificate(state, id, chain, now)
        })
    }
}

#[cfg(feature = "stir")]
fn certificate(
    state: &mut crate::stack::StackState,
    call: sipral_ua::CallHandle,
    chain: Option<&[u8]>,
    now: std::time::Instant,
) -> Result<(), Fail> {
    state
        .agent
        .stir_certificate(call, chain, now)
        .map_err(|error| crate::call::ua_failed(&error))
}

#[cfg(not(feature = "stir"))]
fn certificate(
    _state: &mut crate::stack::StackState,
    _call: sipral_ua::CallHandle,
    _chain: Option<&[u8]>,
    _now: std::time::Instant,
) -> Result<(), Fail> {
    Err(fail(
        SipralStatus::NotSupported,
        "this build has no STIR/SHAKEN: SIPRAL_FEATURE_STIR is clear in sipral_capabilities",
    ))
}

entry! {
    /// How many streams one call's encryption report has: one per stream
    /// the call carries, which for this library is its one audio stream.
    ///
    /// # Safety
    ///
    /// `out_count` must point at one `size_t`.
    fn sipral_media_encryption_count(media: SipralHandle, out_count: *mut usize) {
        if out_count.is_null() {
            return Err(fail(SipralStatus::InvalidArgument, "out_count is null"));
        }
        let count = with_media(media, |session, _| Ok(session.encryption().len()))?;
        unsafe { out_count.write(count) };
        Ok(())
    }
}

entry! {
    /// How one stream of a call is protected, now: whether it is encrypted,
    /// how its keys were exchanged, which suite it runs, and whether the
    /// exchange authenticated the far end. An index past the end is
    /// `SIPRAL_STATUS_INVALID_ARGUMENT`.
    ///
    /// # Safety
    ///
    /// `out_stream` must point at a `sipral_stream_encryption_t` whose `size`
    /// member says how long it is.
    fn sipral_media_encryption_at(
        media: SipralHandle,
        index: usize,
        out_stream: *mut SipralStreamEncryption,
    ) {
        unsafe { crate::versioned::declared_size(out_stream.cast_const()) }?;
        let stream = with_media(media, |session, _| {
            let report = session.encryption();
            report
                .get(index)
                .map(stream_encryption)
                .ok_or_else(|| {
                    fail(
                        SipralStatus::InvalidArgument,
                        format!("index {index} is past the {} streams there are", report.len()),
                    )
                })
        })?;
        unsafe { write_versioned(out_stream, stream) }
    }
}

/// The verification an account asks for, and how it signs, from what crossed
/// the boundary.
///
/// # Safety
///
/// Every `stir_*` pointer in `config` must be readable for the length beside
/// it.
pub(crate) unsafe fn with_stir(
    state: &crate::stack::StackState,
    mut account: sipral_ua::Account,
    config: &crate::account::SipralAccountConfig,
) -> Result<sipral_ua::Account, Fail> {
    account = account.stir_verification(stir_verification(config.stir_verification)?);
    let key = unsafe { blob(config.stir_key, config.stir_key_len, 64 * 1024, "stir_key") }?;
    let url = unsafe {
        crate::text::text(
            config.stir_certificate_url,
            config.stir_certificate_url_len,
            "stir_certificate_url",
        )
    }?;
    let orig = unsafe { crate::text::text(config.stir_orig, config.stir_orig_len, "stir_orig") }?;
    let origid =
        unsafe { crate::text::text(config.stir_origid, config.stir_origid_len, "stir_origid") }?;
    match (key, url) {
        (None, None) => {
            if orig.is_some() || origid.is_some() || config.stir_attestation != 0 {
                return Err(fail(
                    SipralStatus::InvalidArgument,
                    "stir_orig, stir_origid and stir_attestation say how an account signs, and \
                     this one has no stir_key and stir_certificate_url to sign with",
                ));
            }
            Ok(account)
        }
        (Some(key), Some(url)) => signing(state, account, key, url, orig, origid, config),
        _ => Err(fail(
            SipralStatus::InvalidArgument,
            "stir_key and stir_certificate_url go together: a key with nowhere to find its \
             certificate, or a certificate with no key, signs nothing",
        )),
    }
}

#[cfg(feature = "stir")]
#[allow(clippy::too_many_arguments)]
fn signing(
    state: &crate::stack::StackState,
    account: sipral_ua::Account,
    key: &[u8],
    url: &str,
    orig: Option<&str>,
    origid: Option<&str>,
    config: &crate::account::SipralAccountConfig,
) -> Result<sipral_ua::Account, Fail> {
    use sipral::stir::{OrigId, Signer, Tn};
    let signer = Signer::from_key(key, url).map_err(|error| {
        fail(
            SipralStatus::InvalidArgument,
            format!("stir_key and stir_certificate_url: {error}"),
        )
    })?;
    let number = match orig {
        Some(orig) => Tn::canonical(orig).map_err(|_| {
            fail(
                SipralStatus::InvalidArgument,
                format!("stir_orig is {orig:?}, which is not a telephone number"),
            )
        })?,
        None => account
            .aor()
            .sip()
            .and_then(|sip| sip.user)
            .and_then(|user| Tn::canonical(user.split(';').next().unwrap_or(user)).ok())
            .ok_or_else(|| {
                fail(
                    SipralStatus::InvalidArgument,
                    "the account's aor has no telephone number in it to sign as: name one in \
                     stir_orig",
                )
            })?,
    };
    let attestation = match config.stir_attestation {
        0 | 1 => Attestation::A,
        2 => Attestation::B,
        3 => Attestation::C,
        other => {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("stir_attestation is {other}, and it is 0 or 1 for A, 2 for B, 3 for C"),
            ));
        }
    };
    let mut signing = sipral::StirSigning::new(signer, number).attestation(attestation);
    if let Some(origid) = origid {
        signing = signing.origid(OrigId::parse(origid).map_err(|_| {
            fail(
                SipralStatus::InvalidArgument,
                format!("stir_origid is {origid:?}, which is not a UUID"),
            )
        })?);
    }
    if !state.agent.knows_the_time() {
        return Err(fail(
            SipralStatus::WrongState,
            "an account that signs needs the wall clock a PASSporT carries: give \
             sipral_stack_stir the time first",
        ));
    }
    Ok(account.stir_signing(signing))
}

#[cfg(not(feature = "stir"))]
#[allow(clippy::too_many_arguments)]
fn signing(
    _state: &crate::stack::StackState,
    _account: sipral_ua::Account,
    _key: &[u8],
    _url: &str,
    _orig: Option<&str>,
    _origid: Option<&str>,
    _config: &crate::account::SipralAccountConfig,
) -> Result<sipral_ua::Account, Fail> {
    Err(fail(
        SipralStatus::NotSupported,
        "this build has no STIR/SHAKEN: SIPRAL_FEATURE_STIR is clear in sipral_capabilities",
    ))
}

/// A text a verdict carries, as a pointer and a length C reads; null and
/// zero for none.
pub(crate) fn text_of(text: Option<&str>) -> (*const c_char, usize) {
    text.map_or((std::ptr::null(), 0), |text| {
        (text.as_ptr().cast::<c_char>(), text.len())
    })
}
