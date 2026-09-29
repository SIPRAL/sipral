// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! STIR/SHAKEN in calls: the authentication service of RFC 8224 §6.1 on the
//! INVITEs an account places, and the verification service of §6.2 on the
//! ones it receives, both over `sipral-stir`.
//!
//! # Signing
//!
//! An account given a [`StirSigning`] signs every call it places: a full-form
//! PASSporT (RFC 8225) with the SHAKEN claims of RFC 8588, for the number
//! the account signs as and the number the call is to, dated by the agent's
//! wall clock ([`UserAgent::set_wall_clock`]), in an `Identity` header field
//! beside the `Date` §6.1 Step 3 has the authentication service add. The
//! full form, because §4.1 requires it of a signer that takes `iat` from its
//! own clock; a call to something that is not a number is signed for the
//! URI it is to (§4.1's `dest.uri`).
//!
//! # Verifying
//!
//! An INVITE for an account whose [`StirVerification`] is in force is held
//! back from the application until its verdict is in: the verdict rides on
//! [`UaEvent::IncomingCall`]'s identity and is announced just before it by
//! [`UaEvent::CallerVerified`]. The certificate is the application's to
//! fetch — the cache, the HTTP client and its timeouts belong there — so a
//! PASSporT that needs one raises [`UaEvent::CertificateWanted`] with the URL,
//! and the call waits for [`UserAgent::stir_certificate`], or for the wait
//! [`StirConfig::certificate_wait`] sets, after which the certificate counts
//! as one that could not be had.
//!
//! What the crate below leaves to its caller is done here: the calling
//! number the request names (the asserted identity from a trusted peer,
//! otherwise `From`) must be the PASSporT's `orig`, and the called number in
//! `To` one of its `dest` (§6.2 Step 2, §6.2.4). Of several `Identity`
//! header fields the first that can be started on is verified; one naming a
//! `ppt` this end does not support is ignored (§6.2 Step 1).
//!
//! An account set to [`StirVerification::Strict`] refuses a call that does
//! not verify with the response §6.2.2 prescribes; every other call is
//! delivered, whatever its verdict.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::endpoint::OutgoingResponse;
use sipral_core::msg::{HeaderName, OwnedMessage, RawMessage, StatusCode, Uri, UriRef, UriScheme};
use sipral_stir::{
    Attest, Claims, Config, Dest, Failure, InfoProblem, OrigId, Pending, Shaken, Signer, Tn,
    TrustAnchors, Verdict, Verified, Verifier,
};

use crate::call::{IDENTITY, SignedHeaders};
use crate::verification::{
    Attestation, CallerVerification, StirVerification, VerificationFailure, VerificationOutcome,
};
use crate::{AccountId, CallEndReason, CallHandle, CallIdentity, UaError, UaEvent, UserAgent};

/// How long a call waits for its certificate unless told otherwise.
///
/// Four seconds: RFC 8224 sets no figure, and the caller hears nothing
/// while the call waits — no ringing is sent before the verdict — so the
/// wait is sized against a fetch that goes to the network, not a cache hit,
/// and kept under the five a person waits for a ring before redialling.
pub const DEFAULT_CERTIFICATE_WAIT: Duration = Duration::from_secs(4);

/// The verification service's configuration, one per agent: the trust
/// anchors, how fresh a PASSporT has to be, and how long a call waits for
/// the application to fetch a certificate.
#[derive(Clone)]
pub struct StirConfig {
    pub(crate) anchors: TrustAnchors,
    pub(crate) freshness: u64,
    pub(crate) certificate_wait: Duration,
}

impl StirConfig {
    /// Verify against `anchors` — the STI-PA's approved roots, in a SHAKEN
    /// deployment — with the sixty seconds of freshness RFC 8224 §6.2 Step 4
    /// recommends and [`DEFAULT_CERTIFICATE_WAIT`].
    #[must_use]
    pub fn new(anchors: TrustAnchors) -> Self {
        Self {
            anchors,
            freshness: sipral_stir::DEFAULT_FRESHNESS,
            certificate_wait: DEFAULT_CERTIFICATE_WAIT,
        }
    }

    /// How far `iat` may be from the time of verification, either way.
    #[must_use]
    pub const fn freshness(mut self, seconds: u64) -> Self {
        self.freshness = seconds;
        self
    }

    /// How long a call waits for [`UserAgent::stir_certificate`] before the
    /// certificate counts as one that could not be had.
    #[must_use]
    pub const fn certificate_wait(mut self, wait: Duration) -> Self {
        self.certificate_wait = wait;
        self
    }
}

impl fmt::Debug for StirConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StirConfig")
            .field("anchors", &self.anchors.len())
            .field("freshness", &self.freshness)
            .field("certificate_wait", &self.certificate_wait)
            .finish()
    }
}

/// What an account signs its calls with: the key and the URL of its
/// certificate (in the [`Signer`]), the number it signs as, and the SHAKEN
/// claims of RFC 8588.
#[derive(Clone, Debug)]
pub struct StirSigning {
    pub(crate) signer: Arc<Signer>,
    pub(crate) orig: Tn,
    pub(crate) attestation: Attestation,
    pub(crate) origid: Option<OrigId>,
}

impl StirSigning {
    /// Sign as `orig`, the canonical number (RFC 8224 §8.3) the certificate
    /// behind `signer` has authority over, with full attestation — what a
    /// user agent signing for its own user knows — and an origination
    /// identifier the agent draws once for the account.
    #[must_use]
    pub fn new(signer: Signer, orig: Tn) -> Self {
        Self {
            signer: Arc::new(signer),
            orig,
            attestation: Attestation::A,
            origid: None,
        }
    }

    /// The attestation level to claim (RFC 8588 §4).
    #[must_use]
    pub const fn attestation(mut self, attestation: Attestation) -> Self {
        self.attestation = attestation;
        self
    }

    /// The origination identifier to claim (RFC 8588 §5), instead of the one
    /// the agent would draw.
    #[must_use]
    pub const fn origid(mut self, origid: OrigId) -> Self {
        self.origid = Some(origid);
        self
    }

    /// The number this signs as.
    #[must_use]
    pub const fn orig(&self) -> &Tn {
        &self.orig
    }
}

/// The verification service's state: what it was configured with, and the
/// calls waiting for a certificate.
#[derive(Debug, Default)]
pub(crate) struct Service {
    config: Option<StirConfig>,
    waiting: HashMap<CallHandle, Waiting>,
}

/// A call held back until its certificate arrives.
#[derive(Debug)]
struct Waiting {
    pending: Pending,
    deadline: Instant,
    held: Held,
}

/// What delivering a held call needs.
#[derive(Debug)]
struct Held {
    account: Option<AccountId>,
    mode: StirVerification,
    request: OwnedMessage,
    identity: Option<Arc<CallIdentity>>,
    numbers: Numbers,
}

/// The numbers a request names: who it says is calling, and who it is for.
#[derive(Debug, Clone, Default)]
struct Numbers {
    orig: Option<Tn>,
    dest: Option<Tn>,
}

/// Where an incoming INVITE goes next.
enum Gate {
    /// To the application now, with this verdict or none.
    Deliver(Option<CallerVerification>),
    /// Nowhere yet: the certificate is wanted first.
    Wait(Box<Pending>),
}

impl UserAgent {
    /// Verify the calls that arrive against `config` from now on, for every
    /// account whose [`StirVerification`] asks for it.
    ///
    /// The wall clock must be set too ([`UserAgent::set_wall_clock`]): a
    /// verifier with no idea of the time finds every PASSporT stale.
    pub fn set_stir(&mut self, config: StirConfig) {
        self.stir.config = Some(config);
    }

    /// The certificate chain the `info` URL of a call's `Identity` yielded —
    /// PEM or DER, the signing certificate first — or `None` for one that
    /// could not be fetched, in answer to [`UaEvent::CertificateWanted`].
    ///
    /// The call's verdict is reached here, and the call delivered or
    /// refused as its account asks ([`UaEvent::CallerVerified`], then
    /// [`UaEvent::IncomingCall`] or the refusal's [`UaEvent::CallEnded`]).
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`] for a call that is not waiting for one: it
    /// never was, it was already answered, the wait ran out, or it ended.
    pub fn stir_certificate(
        &mut self,
        call: CallHandle,
        chain: Option<&[u8]>,
        now: Instant,
    ) -> Result<(), UaError> {
        let waiting = self.stir.waiting.remove(&call).ok_or(UaError::NoSuchCall)?;
        let unix = self.unix_at(now).unwrap_or(0);
        let verdict = match (chain, self.stir.config.as_ref()) {
            (Some(chain), Some(config)) => waiting.pending.verify(chain, &config.anchors, unix),
            (Some(chain), None) => waiting.pending.verify(chain, &TrustAnchors::new(), unix),
            (None, _) => waiting.pending.unavailable(),
        };
        let verification = judged(&verdict, &waiting.held.numbers);
        self.release(call, waiting.held, verification, now);
        self.drain(now);
        Ok(())
    }

    /// The calls whose wait for a certificate ran out: verified as having
    /// none.
    pub(crate) fn fire_stir_timers(&mut self, now: Instant) {
        let due: Vec<CallHandle> = self
            .stir
            .waiting
            .iter()
            .filter(|(_, waiting)| waiting.deadline <= now)
            .map(|(call, _)| *call)
            .collect();
        for call in due {
            if let Some(waiting) = self.stir.waiting.remove(&call) {
                let verdict = waiting.pending.unavailable();
                let verification = judged(&verdict, &waiting.held.numbers);
                self.release(call, waiting.held, verification, now);
            }
        }
    }

    /// When the next wait for a certificate runs out.
    pub(crate) fn stir_deadline(&self) -> Option<Instant> {
        self.stir
            .waiting
            .values()
            .map(|waiting| waiting.deadline)
            .min()
    }

    /// Whether `call` is held back waiting for its certificate.
    pub(crate) fn verifying(&self, call: CallHandle) -> bool {
        self.stir.waiting.contains_key(&call)
    }

    /// A call that ended while it waited has nothing left to wait for.
    pub(crate) fn stop_verifying(&mut self, call: CallHandle) {
        self.stir.waiting.remove(&call);
    }

    /// An INVITE that has just become `call`: delivered at once, held for its
    /// certificate, or refused, as its account's verification asks.
    pub(crate) fn screen_identity(
        &mut self,
        call: CallHandle,
        account: Option<AccountId>,
        request: &OwnedMessage,
        identity: Option<Arc<CallIdentity>>,
        now: Instant,
    ) {
        let mode = account
            .and_then(|id| self.accounts.get(&id))
            .map_or(StirVerification::default(), |config| {
                config.stir_verification
            });
        let numbers = numbers_of(&request.as_raw(), identity.as_deref());
        let held = Held {
            account,
            mode,
            request: request.clone(),
            identity,
            numbers,
        };
        match self.gate(&held, now) {
            Gate::Deliver(verification) => self.release_now(call, held, verification, now),
            Gate::Wait(pending) => {
                let wait = self
                    .stir
                    .config
                    .as_ref()
                    .map_or(DEFAULT_CERTIFICATE_WAIT, |config| config.certificate_wait);
                let url = Box::from(pending.certificate_url());
                // a wait too long for the clock to add is the default one
                let deadline = now
                    .checked_add(wait)
                    .unwrap_or_else(|| now + DEFAULT_CERTIFICATE_WAIT);
                self.stir.waiting.insert(
                    call,
                    Waiting {
                        pending: *pending,
                        deadline,
                        held,
                    },
                );
                self.events
                    .push_back(UaEvent::CertificateWanted { call, url });
            }
        }
    }

    /// Whether and how far verification goes for a call, before any
    /// certificate is needed.
    fn gate(&self, held: &Held, now: Instant) -> Gate {
        let anchored = self
            .stir
            .config
            .as_ref()
            .is_some_and(|config| !config.anchors.is_empty());
        match held.mode {
            StirVerification::Off => return Gate::Deliver(None),
            StirVerification::Report if !anchored => return Gate::Deliver(None),
            _ => {}
        }
        let config = self.stir.config.as_ref();
        let verifier = Verifier::new(Config {
            freshness: config.map_or(sipral_stir::DEFAULT_FRESHNESS, |config| config.freshness),
            accept_service_provider_codes: true,
        });
        let raw = held.request.as_raw();
        let unix = self.unix_at(now).unwrap_or(0);
        let rebuilt = held
            .numbers
            .orig
            .clone()
            .zip(held.numbers.dest.clone())
            .map(|(orig, dest)| Claims {
                orig,
                dest: Dest::tn(dest),
                iat: raw
                    .header(HeaderName::Date)
                    .and_then(date_of)
                    .unwrap_or(unix),
                shaken: None,
            });
        let mut seen = false;
        let mut unsupported = false;
        let mut first: Option<Failure> = None;
        for value in raw.header_values(IDENTITY) {
            seen = true;
            let text = std::str::from_utf8(value).unwrap_or("");
            match verifier.start(text.trim(), rebuilt.as_ref()) {
                Ok(pending) => return Gate::Wait(Box::new(pending)),
                Err(Failure::UnsupportedPpt) => unsupported = true,
                Err(failure) => {
                    first.get_or_insert(failure);
                }
            }
        }
        let failure = match first {
            Some(failure) => failure,
            None if seen && unsupported => Failure::UnsupportedPpt,
            None => Failure::MissingIdentity,
        };
        Gate::Deliver(Some(judged(&Verdict::Invalid(failure), &held.numbers)))
    }

    /// Deliver a call whose verdict was reached without waiting.
    fn release_now(
        &mut self,
        call: CallHandle,
        held: Held,
        verification: Option<CallerVerification>,
        now: Instant,
    ) {
        match verification {
            Some(verification) => self.release(call, held, verification, now),
            None => self.events.push_back(UaEvent::IncomingCall {
                call,
                account: held.account,
                request: held.request,
                identity: held.identity,
            }),
        }
    }

    /// The verdict is in: say so, then deliver the call, or refuse it when
    /// its account is strict and the verdict is not valid.
    fn release(
        &mut self,
        call: CallHandle,
        held: Held,
        mut verification: CallerVerification,
        now: Instant,
    ) {
        let refuse = held.mode == StirVerification::Strict
            && verification.outcome != VerificationOutcome::Valid;
        let refusal = verification
            .response
            .as_ref()
            .filter(|_| refuse)
            .and_then(|(code, reason)| Some((StatusCode::new(*code).ok()?, reason.clone())));
        verification.refused = refusal.is_some();
        let verification = Arc::new(verification);
        let identity = held.identity.map(|identity| {
            let mut read = (*identity).clone();
            read.caller.verification = Some((*verification).clone());
            Arc::new(read)
        });
        if let Some(held_call) = self.calls.get_mut(&call) {
            held_call.identity.clone_from(&identity);
        }
        self.events.push_back(UaEvent::CallerVerified {
            call,
            account: held.account,
            verification,
            request: held.request.clone(),
        });
        match refusal {
            Some((status, reason)) => {
                if let Ok(transaction) = self.answerable(call) {
                    let response = OutgoingResponse::new(status).reason(reason.as_bytes());
                    // a refusal that cannot be sent leaves the transaction to
                    // time out on its own, and the call is over either way
                    let _ = self.endpoint.respond_invite(transaction, &response, now);
                }
                self.finish(call, CallEndReason::LocalHangup, Some(status), None, now);
            }
            None => self.events.push_back(UaEvent::IncomingCall {
                call,
                account: held.account,
                request: held.request,
                identity,
            }),
        }
    }

    /// Sign what `account` places toward `target`, when it signs anything.
    ///
    /// # Errors
    /// [`UaError::NoWallClock`] when the account signs and the agent was
    /// never told the time, and [`UaError::Signing`] when the PASSporT cannot
    /// be made.
    pub(crate) fn sign_for(
        &self,
        account: AccountId,
        target: &Uri,
        own_date: bool,
        now: Instant,
    ) -> Result<Option<SignedHeaders>, UaError> {
        let Some(signing) = self
            .accounts
            .get(&account)
            .and_then(|config| config.stir_signing.as_ref())
        else {
            return Ok(None);
        };
        let iat = self.unix_at(now).ok_or(UaError::NoWallClock)?;
        let dest = match number_of(target) {
            Some(number) => Dest::tn(number),
            None => Dest {
                tn: Vec::new(),
                uri: vec![target.as_str().to_owned()],
            },
        };
        let claims = Claims {
            orig: signing.orig.clone(),
            dest,
            iat,
            shaken: Some(Shaken {
                attest: attest_of(signing.attestation),
                // drawn when the account was added, so never missing here
                origid: signing.origid.ok_or(UaError::Signing)?,
            }),
        };
        let identity = signing
            .signer
            .identity(&claims)
            .map_err(|_| UaError::Signing)?;
        Ok(Some(SignedHeaders {
            identity: Box::from(identity.as_bytes()),
            date: (!own_date).then(|| Box::from(http_date(iat).as_bytes())),
        }))
    }

    /// An origination identifier for an account that signs and named none:
    /// sixteen octets off the endpoint's own stream, as a version 4 UUID
    /// (RFC 4122 §4.4), drawn once when the account is added.
    pub(crate) fn draw_origid(&mut self) -> OrigId {
        let token = self.endpoint.token();
        let mut bytes = [0u8; 16];
        for (slot, pair) in bytes.iter_mut().zip(token.chunks(2)) {
            let high = pair.first().copied().map_or(0, nibble);
            let low = pair.get(1).copied().map_or(0, nibble);
            *slot = (high << 4) | low;
        }
        if let Some(version) = bytes.get_mut(6) {
            *version = (*version & 0x0f) | 0x40;
        }
        if let Some(variant) = bytes.get_mut(8) {
            *variant = (*variant & 0x3f) | 0x80;
        }
        OrigId::from_bytes(bytes)
    }
}

/// One hexadecimal digit's value.
const fn nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        b'A'..=b'F' => digit - b'A' + 10,
        _ => 0,
    }
}

const fn attest_of(attestation: Attestation) -> Attest {
    match attestation {
        Attestation::A => Attest::A,
        Attestation::B => Attest::B,
        Attestation::C => Attest::C,
    }
}

const fn attestation_of(attest: Attest) -> Attestation {
    match attest {
        Attest::A => Attestation::A,
        Attest::B => Attestation::B,
        Attest::C => Attestation::C,
    }
}

/// The numbers a request names, canonical: the caller the application will
/// be shown — the asserted identity from a trusted peer, otherwise `From` —
/// and the number in `To`.
fn numbers_of(request: &RawMessage<'_>, identity: Option<&CallIdentity>) -> Numbers {
    let asserted = identity
        .map(|identity| &identity.caller.asserted)
        .and_then(|asserted| {
            asserted
                .iter()
                .find_map(|party| Uri::parse(&party.uri).ok().as_ref().and_then(number_of))
        });
    let from = || {
        request
            .from()
            .ok()
            .and_then(|from| Uri::parse(from.uri_bytes()).ok())
            .as_ref()
            .and_then(number_of)
    };
    let dest = request
        .to()
        .ok()
        .and_then(|to| Uri::parse(to.uri_bytes()).ok())
        .as_ref()
        .and_then(number_of);
    Numbers {
        orig: asserted.or_else(from),
        dest,
    }
}

/// The telephone number a URI names, canonical (RFC 8224 §8.1, §8.3): a
/// `tel:` URI's number, or a SIP URI's user part when it is made of digits
/// and visual separators — `user=phone` or not, which §8.1 leaves to local
/// policy, since a PBX's extensions are numbers without it.
pub(crate) fn number_of(uri: &Uri) -> Option<Tn> {
    let written = match uri.as_uri_ref() {
        UriRef::Sip(sip) => sip.user?,
        UriRef::Other {
            scheme: UriScheme::Tel,
            opaque,
        } => opaque,
        UriRef::Other { .. } => return None,
    };
    // a telephone-subscriber's own parameters follow the number (RFC 3966
    // §3), in a SIP user part as in a tel URI
    let number = written.split(';').next().unwrap_or(written);
    Tn::canonical(number).ok()
}

/// A verdict as the call carries it, the request's own numbers held
/// against a valid PASSporT's first.
fn judged(verdict: &Verdict, numbers: &Numbers) -> CallerVerification {
    match verdict {
        Verdict::Valid(verified) => match mismatch(verified, numbers) {
            None => CallerVerification {
                outcome: VerificationOutcome::Valid,
                failure: None,
                detail: None,
                attestation: verified.attest.map(attestation_of),
                orig: Some(Box::from(verified.orig.as_str())),
                origid: verified
                    .origid
                    .map(|origid| origid.to_string().into_boxed_str()),
                certificate_url: Some(Box::from(verified.x5u.as_str())),
                response: None,
                refused: false,
            },
            Some(failure) => CallerVerification {
                outcome: VerificationOutcome::Invalid,
                failure: Some(failure),
                detail: Some(failure.to_string().into_boxed_str()),
                attestation: None,
                orig: None,
                origid: None,
                certificate_url: Some(Box::from(verified.x5u.as_str())),
                // RFC 8224 §6.2.4: a PASSporT for other numbers is one whose
                // signature does not cover this request
                response: Some((438, Box::from("Invalid Identity Header"))),
                refused: false,
            },
        },
        Verdict::Invalid(failure) => {
            let response = failure.sip_response();
            CallerVerification {
                outcome: if matches!(failure, Failure::MissingIdentity | Failure::UnsupportedPpt) {
                    VerificationOutcome::Absent
                } else {
                    VerificationOutcome::Invalid
                },
                failure: Some(failure_of(*failure)),
                detail: Some(failure.to_string().into_boxed_str()),
                attestation: None,
                orig: None,
                origid: None,
                certificate_url: None,
                response: Some((response.code, Box::from(response.reason))),
                refused: false,
            }
        }
    }
}

/// Which of the request's numbers a valid PASSporT was not signed for.
fn mismatch(verified: &Verified, numbers: &Numbers) -> Option<VerificationFailure> {
    if numbers.orig.as_ref() != Some(&verified.orig) {
        return Some(VerificationFailure::OrigMismatch);
    }
    match numbers.dest.as_ref() {
        Some(dest) if !verified.dest.tn.contains(dest) => Some(VerificationFailure::DestMismatch),
        _ => None,
    }
}

const fn failure_of(failure: Failure) -> VerificationFailure {
    match failure {
        Failure::MissingIdentity => VerificationFailure::NoIdentity,
        Failure::UnsupportedPpt => VerificationFailure::UnsupportedPpt,
        Failure::Malformed(_) => VerificationFailure::Malformed,
        Failure::UnsupportedAlgorithm => VerificationFailure::UnsupportedAlgorithm,
        Failure::Stale { .. } => VerificationFailure::Stale,
        Failure::BadInfo(InfoProblem::Unavailable) => VerificationFailure::CertificateUnavailable,
        Failure::BadInfo(_) => VerificationFailure::CertificateUnreadable,
        Failure::Untrusted => VerificationFailure::Untrusted,
        Failure::Expired { .. } | Failure::NotYetValid { .. } => VerificationFailure::Expired,
        Failure::InvalidChain(_) => VerificationFailure::InvalidChain,
        Failure::BadSignature => VerificationFailure::BadSignature,
        Failure::TnNotCovered => VerificationFailure::NumberNotCovered,
    }
}

const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Days since 1970-01-01 as a civil date, proleptic Gregorian.
const fn civil(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

/// A civil date as days since 1970-01-01; `None` before it.
fn days_from_civil(year: u64, month: u64, day: u64) -> Option<u64> {
    let year = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = year / 400;
    let yoe = year - era * 400;
    let shifted = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * shifted + 2) / 5 + day.checked_sub(1)?;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe).checked_sub(719_468)
}

/// `unix` as the `rfc1123-date` a `Date` header field carries (RFC 3261
/// §20.17, §25.1): `Sat, 13 Nov 2010 23:29:00 GMT`.
pub(crate) fn http_date(unix: u64) -> String {
    let days = unix / 86_400;
    let seconds = unix % 86_400;
    let (year, month, day) = civil(days);
    let weekday = WEEKDAYS
        .get(usize::try_from(days % 7).unwrap_or(0))
        .copied()
        .unwrap_or("Thu");
    let month_name = usize::try_from(month.saturating_sub(1))
        .ok()
        .and_then(|index| MONTHS.get(index))
        .copied()
        .unwrap_or("Jan");
    format!(
        "{weekday}, {day:02} {month_name} {year:04} {:02}:{:02}:{:02} GMT",
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60
    )
}

/// The time a `Date` header field names, as seconds since the Unix epoch;
/// `None` for anything but the `rfc1123-date` RFC 3261 §25.1 allows.
///
/// Each number is held to the digits the grammar gives it — `2DIGIT` for
/// the day and the three fields of the time, `4DIGIT` for the year — which
/// is also what keeps the arithmetic below inside a `u64` whatever a
/// request says: the header field is the far end's.
pub(crate) fn date_of(value: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(value).ok()?.trim();
    let (_weekday, rest) = text.split_once(", ")?;
    let mut parts = rest.split(' ');
    let day = digits_of(parts.next()?, 2)?;
    let month_name = parts.next()?;
    let month = MONTHS.iter().position(|name| *name == month_name)?;
    let year = digits_of(parts.next()?, 4)?;
    let clock = parts.next()?;
    if parts.next()? != "GMT" || parts.next().is_some() {
        return None;
    }
    let mut fields = clock.split(':').map(|field| digits_of(field, 2));
    let (hour, minute, second) = (fields.next()??, fields.next()??, fields.next()??);
    if fields.next().is_some()
        || hour > 23
        || minute > 59
        || second > 60
        || !(1..=31).contains(&day)
    {
        return None;
    }
    let month = u64::try_from(month).ok()? + 1;
    let days = days_from_civil(year, month, day)?;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}

/// A field of exactly `count` ASCII digits, as a number.
fn digits_of(field: &str, count: usize) -> Option<u64> {
    (field.len() == count && field.bytes().all(|b| b.is_ascii_digit()))
        .then(|| field.parse().ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::{date_of, http_date, number_of};
    use sipral_core::msg::Uri;

    #[test]
    fn a_date_is_written_as_rfc_3261_section_25_1_writes_it_and_read_back() {
        // RFC 3261 §20.17's own example
        assert_eq!(
            date_of(b"Sat, 13 Nov 2010 23:29:00 GMT"),
            Some(1_289_690_940)
        );
        assert_eq!(http_date(1_289_690_940), "Sat, 13 Nov 2010 23:29:00 GMT");
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
        for unix in [0, 59, 86_399, 951_782_400, 1_790_000_000, 4_102_444_800] {
            assert_eq!(date_of(http_date(unix).as_bytes()), Some(unix), "{unix}");
        }
        assert_eq!(date_of(b"13 Nov 2010 23:29:00 GMT"), None);
        assert_eq!(date_of(b"Sat, 13 Nov 2010 23:29:00 UTC"), None);
        assert_eq!(date_of(b"Sat, 13 Foo 2010 23:29:00 GMT"), None);
        assert_eq!(date_of(b"Sat, 13 Nov 2010 24:29:00 GMT"), None);
    }

    /// The header field is the far end's: a year, day or time field wider
    /// than RFC 3261 §25.1's `4DIGIT` and `2DIGIT` is refused rather than
    /// multiplied past what a `u64` holds.
    #[test]
    fn a_date_with_a_field_too_wide_for_the_grammar_is_not_a_date() {
        for bad in [
            &b"Sat, 13 Nov 18446744073709551615 23:29:00 GMT"[..],
            b"Sat, 13 Nov 99999999999999999999 23:29:00 GMT",
            b"Sat, 13 Nov 02010 23:29:00 GMT",
            b"Sat, 013 Nov 2010 23:29:00 GMT",
            b"Sat, 13 Nov 2010 023:29:00 GMT",
            b"Sat, 13 Nov 2010 23:29:99999999999999999999 GMT",
            b"Sat, +3 Nov 2010 23:29:00 GMT",
        ] {
            assert_eq!(date_of(bad), None, "{}", String::from_utf8_lossy(bad));
        }
        assert_eq!(
            date_of(b"Fri, 31 Dec 9999 23:59:59 GMT"),
            Some(253_402_300_799)
        );
    }

    #[test]
    fn a_number_is_read_out_of_a_tel_uri_or_a_numeric_user_part() {
        let tn = |text: &str| {
            number_of(&Uri::parse_str(text).expect("a URI")).map(|tn| tn.as_str().to_owned())
        };
        assert_eq!(tn("tel:+1-215-555-1212").as_deref(), Some("12155551212"));
        assert_eq!(
            tn("sip:+12155551212;npdi@example.com;user=phone").as_deref(),
            Some("12155551212")
        );
        assert_eq!(tn("sip:1001@example.com").as_deref(), Some("1001"));
        assert_eq!(tn("sip:alice@example.com"), None);
        assert_eq!(tn("sip:example.com"), None);
    }
}
