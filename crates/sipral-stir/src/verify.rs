// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The verification service of RFC 8224 §6.2, in two steps with the fetch
//! between them left to the application.
//!
//! [`Verifier::start`] reads the Identity header field and the PASSporT in
//! it and says which certificate it needs ([`Pending::certificate_url`]).
//! The application fetches it, from a cache or over HTTPS, and hands what it
//! got to [`Pending::verify`] together with its trust anchors and the time;
//! or, if it got nothing, calls [`Pending::unavailable`]. Either way the
//! result is a [`Verdict`].
//!
//! What a request's own time says is held to the same window as `iat`: the
//! Date header field, given with [`Pending::dated`], has to be fresh and
//! close to `iat` (RFC 8224 §6.2, Step 4). And a verifier that keeps a
//! [`ReplayCache`] and finishes with [`Pending::verify_once`] refuses a
//! PASSporT it has already verified inside its window (§12.1);
//! [`Pending::verify_arrival`] does the same while letting one request
//! forked to several lines of one verifier through on each of them.

use std::collections::VecDeque;

use p256::ecdsa::Signature;
use p256::ecdsa::signature::Verifier as _;

use crate::base64;
use crate::cert::{self, TrustAnchors};
use crate::identity::{Identity, Token};
use crate::passport::{ALG, Claims, Dest, Header, PPT_SHAKEN, Tn, header_value};
use crate::verdict::{Failure, InfoProblem, Malformed, Staleness, Verdict, Verified};

/// How far `iat` may be from the time of verification, in seconds, unless
/// configured otherwise: the sixty seconds RFC 8224 §6.2 (Step 4)
/// recommends.
pub const DEFAULT_FRESHNESS: u64 = 60;

/// The schemes an `info` URI may name unless configured otherwise: `https`
/// alone.
pub const DEFAULT_INFO_SCHEMES: &[&str] = &["https"];

/// A verifier's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// How far `iat` may be from the time of verification, either way, in
    /// seconds, before the request is stale.
    pub freshness: u64,
    /// Whether a service provider code in the TNAuthList covers any
    /// originating number. Off by default: only a number or a range naming
    /// the originating number gives a certificate authority over it.
    ///
    /// A SHAKEN certificate names its provider rather than the numbers, and
    /// whether that provider may vouch for a given number is known only to
    /// whoever decided to trust it — the application, with the roots of a
    /// SHAKEN deployment, which turns this on. On, a certificate carrying
    /// any code vouches for every number there is.
    pub accept_service_provider_codes: bool,
    /// The schemes an `info` URI may name, compared without regard to case
    /// (RFC 3986 §3.1): [`DEFAULT_INFO_SCHEMES`], `https` alone, by default.
    ///
    /// The hook for a deployment whose certificates are reached some other
    /// way: one that fetches over plain `http` from a repository whose
    /// content it authenticates by the chain alone, say, adds `"http"`
    /// here. Anything else is refused with [`InfoProblem::Scheme`] before
    /// the application is asked to fetch it, so that a request cannot have a
    /// verifier reach for a `file:`, `ldap:` or `data:` URI of its choosing.
    pub info_schemes: &'static [&'static str],
}

impl Default for Config {
    fn default() -> Self {
        Config {
            freshness: DEFAULT_FRESHNESS,
            accept_service_provider_codes: false,
            info_schemes: DEFAULT_INFO_SCHEMES,
        }
    }
}

/// Verifies Identity header fields under one [`Config`].
#[derive(Debug, Clone, Default)]
pub struct Verifier {
    config: Config,
}

impl Verifier {
    /// A verifier with this policy.
    #[must_use]
    pub fn new(config: Config) -> Self {
        Verifier { config }
    }

    /// Read one Identity header field value, up to the point where the
    /// certificate is needed.
    ///
    /// `from_request` are the claims as the request itself states them: the
    /// originating and destination numbers from its From and To (or
    /// P-Asserted-Identity and Request-URI) as RFC 8224 §8.3 canonicalises
    /// them, the time from its Date header field, and, for a `shaken`
    /// PASSporT, `attest` and `origid` from wherever the deployment carries
    /// them. They are needed for the compact form (RFC 8225 §7), whose
    /// header and claims are rebuilt from them; a full form carries its own,
    /// and `from_request` is not looked at. Comparing a full form's claims
    /// with the request is the application's, with [`Verified::orig`] and
    /// [`Verified::dest`] in hand.
    ///
    /// # Errors
    ///
    /// The [`Failure`] that ends verification before any certificate is
    /// needed.
    pub fn start(&self, identity: &str, from_request: Option<&Claims>) -> Result<Pending, Failure> {
        let identity = Identity::parse(identity)?;
        let scheme = identity
            .info
            .split_once(':')
            .map_or("", |(scheme, _)| scheme);
        if !self
            .config
            .info_schemes
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(scheme))
        {
            return Err(Failure::BadInfo(InfoProblem::Scheme));
        }
        let (signing_input, claims) = match &identity.token {
            Token::Full { header, claims, .. } => full(&identity, header, claims)?,
            Token::Compact { .. } => compact(&identity, from_request)?,
        };
        let signature = match &identity.token {
            Token::Full { signature, .. } | Token::Compact { signature } => signature,
        };
        let signature = base64::decode_url(signature.as_bytes())
            .map_err(|_| Failure::Malformed(Malformed::Encoding))?;
        // RFC 7518 §3.4: R and S, 32 octets each, not a DER sequence
        if signature.len() != 64 {
            return Err(Failure::Malformed(Malformed::Signature));
        }
        let signature = Signature::from_slice(&signature).map_err(|_| Failure::BadSignature)?;
        Ok(Pending {
            config: self.config,
            x5u: identity.info,
            signing_input,
            signature,
            claims,
            date: None,
        })
    }
}

fn decode_json(segment: &str) -> Result<Vec<u8>, Failure> {
    base64::decode_url(segment.as_bytes()).map_err(|_| Failure::Malformed(Malformed::Encoding))
}

fn full(identity: &Identity, header: &str, claims: &str) -> Result<(Vec<u8>, Claims), Failure> {
    // RFC 8224 §6.2, Step 1, before anything else: a `ppt` parameter this
    // verifier does not support means the header field is ignored, whatever
    // the PASSporT inside it says
    if identity.ppt.as_deref().is_some_and(|ppt| ppt != PPT_SHAKEN) {
        return Err(Failure::UnsupportedPpt);
    }
    let parsed = Header::from_json(&decode_json(header)?)?;
    if identity.alg.as_deref().is_some_and(|alg| alg != ALG) {
        return Err(Failure::Malformed(Malformed::AlgMismatch));
    }
    match (identity.ppt.as_deref(), parsed.shaken) {
        (None, _) | (Some(PPT_SHAKEN), true) => {}
        _ => return Err(Failure::Malformed(Malformed::PptMismatch)),
    }
    if parsed.x5u.as_ref().is_some_and(|x5u| *x5u != identity.info) {
        return Err(Failure::BadInfo(InfoProblem::Mismatch));
    }
    let claims_value = Claims::from_json(&decode_json(claims)?, parsed.shaken)?;
    Ok((format!("{header}.{claims}").into_bytes(), claims_value))
}

fn compact(
    identity: &Identity,
    from_request: Option<&Claims>,
) -> Result<(Vec<u8>, Claims), Failure> {
    let without = Failure::Malformed(Malformed::CompactWithoutClaims);
    let claims = from_request.ok_or(without)?;
    if identity.alg.as_deref().is_some_and(|alg| alg != ALG) {
        return Err(Failure::UnsupportedAlgorithm);
    }
    let shaken = match identity.ppt.as_deref() {
        None => false,
        Some(PPT_SHAKEN) => true,
        Some(_) => return Err(Failure::UnsupportedPpt),
    };
    if shaken && claims.shaken.is_none() {
        return Err(without);
    }
    if claims.dest.is_empty() {
        return Err(Failure::Malformed(Malformed::Claims));
    }
    let header = header_value(&identity.info, shaken).canonical();
    let payload = claims.value(shaken).canonical();
    let signing_input = format!(
        "{}.{}",
        base64::encode_url(header.as_bytes()),
        base64::encode_url(payload.as_bytes())
    );
    let mut claims = claims.clone();
    if !shaken {
        claims.shaken = None;
    }
    Ok((signing_input.into_bytes(), claims))
}

/// A PASSporT read and waiting for its certificate.
#[derive(Debug, Clone)]
pub struct Pending {
    config: Config,
    x5u: String,
    signing_input: Vec<u8>,
    signature: Signature,
    claims: Claims,
    date: Option<u64>,
}

impl Pending {
    /// The request's Date header field, in seconds since the Unix epoch:
    /// held, when [`Pending::verify`] runs, to the freshness window around
    /// the time of verification, and `iat` to the same window around it
    /// (RFC 8224 §6.2, Step 4). A full-form PASSporT carries its own `iat`,
    /// and without this nothing ties it to the time the request says it was
    /// sent; for a compact form the Date is `iat` already.
    #[must_use]
    pub fn dated(mut self, date: u64) -> Self {
        self.date = Some(date);
        self
    }

    /// The URI to fetch the signer's certificate chain from: the `info`
    /// parameter.
    #[must_use]
    pub fn certificate_url(&self) -> &str {
        &self.x5u
    }

    /// The claims the signature covers, not yet verified.
    #[must_use]
    pub fn claims(&self) -> &Claims {
        &self.claims
    }

    /// The verdict for a certificate the application could not fetch.
    #[must_use]
    pub fn unavailable(&self) -> Verdict {
        Verdict::Invalid(Failure::BadInfo(InfoProblem::Unavailable))
    }

    /// Finish, with the chain fetched from [`Pending::certificate_url`] —
    /// PEM or DER, the signing certificate first — the application's trust
    /// anchors, and `now` in seconds since the Unix epoch, which should be
    /// when the request arrived.
    ///
    /// Freshness is checked first — `iat`, then the Date given with
    /// [`Pending::dated`] — then the chain, then the signature, then the
    /// TNAuthList's authority over the originating number.
    #[must_use]
    pub fn verify(&self, chain: &[u8], anchors: &TrustAnchors, now: u64) -> Verdict {
        match self.check(chain, anchors, now) {
            Ok(verified) => Verdict::Valid(verified),
            Err(failure) => Verdict::Invalid(failure),
        }
    }

    /// As [`Pending::verify`], and then, for a PASSporT that verifies, a
    /// check against `seen` (RFC 8224 §12.1): one already verified there is
    /// [`Failure::Stale`] with [`Staleness::Replayed`], and one that is not
    /// is recorded. Only a PASSporT whose signature verifies is ever
    /// recorded, so nothing forged takes room in `seen`.
    #[must_use]
    pub fn verify_once(
        &self,
        chain: &[u8],
        anchors: &TrustAnchors,
        now: u64,
        seen: &mut ReplayCache,
    ) -> Verdict {
        self.verify_against(chain, anchors, now, seen, None)
    }

    /// As [`Pending::verify_once`], for a PASSporT that came in the request
    /// `arrival` names, on the line it names.
    ///
    /// A proxy that forks one INVITE to several contacts sends each branch
    /// the same `Identity`, and two of those contacts can be two lines of
    /// one verifier — two accounts of one stack, the members of a ring
    /// group. Each branch is the same request, not a replay of it, so a
    /// PASSporT already recorded is taken again when every time it was
    /// recorded was for the same request ([`Arrival::request`]) on another
    /// line. The same PASSporT in another request (another `Call-ID`), or
    /// the same request again on a line that already took it, is still a
    /// replay (RFC 8224 §12.1).
    #[must_use]
    pub fn verify_arrival(
        &self,
        chain: &[u8],
        anchors: &TrustAnchors,
        now: u64,
        seen: &mut ReplayCache,
        arrival: &Arrival,
    ) -> Verdict {
        self.verify_against(chain, anchors, now, seen, Some(arrival))
    }

    fn verify_against(
        &self,
        chain: &[u8],
        anchors: &TrustAnchors,
        now: u64,
        seen: &mut ReplayCache,
        arrival: Option<&Arrival>,
    ) -> Verdict {
        match self.check(chain, anchors, now) {
            Ok(verified) => {
                let entry = Seen {
                    orig: self.claims.orig.clone(),
                    dest: self.claims.dest.clone(),
                    iat: self.claims.iat,
                    signature: self.signature.to_bytes().to_vec(),
                    arrival: arrival.cloned(),
                };
                if seen.admit(entry, now, self.config.freshness) {
                    Verdict::Valid(verified)
                } else {
                    Verdict::Invalid(Failure::Stale {
                        iat: self.claims.iat,
                        now,
                        what: Staleness::Replayed,
                    })
                }
            }
            Err(failure) => Verdict::Invalid(failure),
        }
    }

    fn check(&self, chain: &[u8], anchors: &TrustAnchors, now: u64) -> Result<Verified, Failure> {
        let iat = self.claims.iat;
        let window = self.config.freshness;
        if now.abs_diff(iat) > window {
            return Err(Failure::Stale {
                iat,
                now,
                what: Staleness::Iat,
            });
        }
        if let Some(date) = self.date {
            if now.abs_diff(date) > window {
                return Err(Failure::Stale {
                    iat,
                    now,
                    what: Staleness::Date { date },
                });
            }
            if iat.abs_diff(date) > window {
                return Err(Failure::Stale {
                    iat,
                    now,
                    what: Staleness::DateMismatch { date },
                });
            }
        }
        let leaf = cert::validate(chain, anchors, now)?;
        leaf.key
            .verify(&self.signing_input, &self.signature)
            .map_err(|_| Failure::BadSignature)?;
        let coverage = leaf
            .tn_auth_list
            .and_then(|list| {
                list.covers(&self.claims.orig, self.config.accept_service_provider_codes)
            })
            .ok_or(Failure::TnNotCovered)?;
        Ok(Verified {
            orig: self.claims.orig.clone(),
            dest: self.claims.dest.clone(),
            iat,
            attest: self.claims.shaken.map(|shaken| shaken.attest),
            origid: self.claims.shaken.map(|shaken| shaken.origid),
            x5u: self.x5u.clone(),
            coverage,
        })
    }
}

/// The PASSporTs a verifier has found valid recently, so that one presented
/// again inside its freshness window is refused as a replay (RFC 8224
/// §12.1): see [`Pending::verify_once`].
///
/// Optional, and the application's to keep, one per verifier: a request is
/// verified in two steps with a fetch between them, so the state cannot live
/// in a [`Verifier`] that is made afresh for each. Bounded twice over: an
/// entry goes once its `iat` has left the window, after which the PASSporT
/// is refused as stale anyway, and when `capacity` entries are still inside
/// it the oldest goes to make room. Only verified PASSporTs are recorded, so
/// only a signer this verifier trusts can fill it, and it would have to sign
/// `capacity` calls inside one window to push a recorded one out early.
#[derive(Debug, Clone)]
pub struct ReplayCache {
    capacity: usize,
    seen: VecDeque<Seen>,
}

/// What identifies one PASSporT to [`ReplayCache`]: `orig`, `dest`, `iat`
/// and the signature; and where it was taken, when the verifier said.
#[derive(Debug, Clone)]
struct Seen {
    orig: Tn,
    dest: Dest,
    iat: u64,
    signature: Vec<u8>,
    arrival: Option<Arrival>,
}

impl Seen {
    /// Whether the two are the same PASSporT, wherever each was taken.
    fn same_passport(&self, other: &Self) -> bool {
        self.iat == other.iat
            && self.signature == other.signature
            && self.orig == other.orig
            && self.dest == other.dest
    }
}

/// The request a PASSporT came in and the line it reached, for
/// [`Pending::verify_arrival`].
///
/// `request` is whatever names one request across the branches a proxy
/// forks it into and nothing else: its `Call-ID`, `From` tag and `CSeq`,
/// which a fork keeps and a new request does not (RFC 3261 §8.2.2.2). `line`
/// is which of the verifier's own lines it reached — an account — in any
/// numbering the caller keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arrival {
    request: Box<str>,
    line: u64,
}

impl Arrival {
    /// The request named by `request`, reaching `line`.
    #[must_use]
    pub fn new(request: &str, line: u64) -> Self {
        Arrival {
            request: Box::from(request),
            line,
        }
    }

    /// What names the request.
    #[must_use]
    pub fn request(&self) -> &str {
        &self.request
    }

    /// Which line it reached.
    #[must_use]
    pub const fn line(&self) -> u64 {
        self.line
    }
}

impl ReplayCache {
    /// How many PASSporTs [`ReplayCache::default`] remembers.
    pub const DEFAULT_CAPACITY: usize = 1024;

    /// A cache remembering at most `capacity` PASSporTs, at least one.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        ReplayCache {
            capacity: capacity.max(1),
            seen: VecDeque::new(),
        }
    }

    /// How many PASSporTs it holds now.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether it holds none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Record `entry` and say so, or say it was already there. What has left
    /// the window around `now` is dropped first.
    ///
    /// Already there means recorded before, unless every time it was
    /// recorded was for the same request as `entry` on another line: a
    /// branch of one forked request, which is taken on each line once.
    fn admit(&mut self, entry: Seen, now: u64, window: u64) -> bool {
        self.seen
            .retain(|seen| seen.iat.saturating_add(window) >= now);
        let mut earlier = self
            .seen
            .iter()
            .filter(|seen| seen.same_passport(&entry))
            .peekable();
        if earlier.peek().is_some() {
            let Some(arrival) = entry.arrival.as_ref() else {
                return false;
            };
            let another_branch = earlier.all(|seen| {
                seen.arrival.as_ref().is_some_and(|taken| {
                    taken.request == arrival.request && taken.line != arrival.line
                })
            });
            if !another_branch {
                return false;
            }
        }
        if self.seen.len() >= self.capacity {
            self.seen.pop_front();
        }
        self.seen.push_back(entry);
        true
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        ReplayCache::new(Self::DEFAULT_CAPACITY)
    }
}
