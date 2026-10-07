// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What a call does about SRTP: what it offers, what it answers, and how the negotiated keying
//! opens the stream.
//!
//! `sipral-rtp` has RFC 3711 and `sipral-core` the RFC 4568 `a=crypto` line; this module connects
//! them: one policy per call, one master key per description, and [`opening`], which turns
//! [`MediaPlan::keying`] into the [`Security`] a session opens with.
//!
//! # Two ways to a key
//!
//! SDES puts the key in the body, so the stream is protected from its first packet. DTLS-SRTP gets
//! it from a handshake on the media path, so the stream has agreed to protection but is not keyed
//! yet; that is why [`opening`] has three outcomes. Without the `dtls` feature such a plan is
//! refused, not opened in the clear, and [`Capabilities`](crate::Capabilities) reports it before a
//! call is placed.
//!
//! # What is refused
//!
//! One master key per line and RFC 4568 §6.3's defaults (everything encrypted and authenticated,
//! one key derivation). Anything else is not answered: a wrong derivation rate produces packets the
//! far end silently drops, which looks like a network fault.

use sipral_core::sdp::{
    Crypto, CryptoPolicy, CryptoSuite, KeySalt, Keying, MediaDescription, MediaPlan,
};
use sipral_rtp::srtp::{Master, Mki, Policy, Security, Suite};

use crate::error::MediaError;

/// The suites this end offers, one line each, tagged from 1 in this order (RFC 4568 §4 only needs
/// tags unique per media line).
///
/// Strongest first (8.2.4): `AEAD_AES_256_GCM`, then `AES_CM_128_HMAC_SHA1_80`, which every
/// implementation has. An answerer preferring strength picks the first (§5.1.2 leaves its own
/// policy free); an older peer still finds the second. Each has its own master key (§6.1: unique
/// "with respect to other master keys in the entire SDP message").
///
/// Only two, because with all four the INVITE that answers a digest challenge exceeds RFC 3261
/// §18.1.1's 1300 octets and needs TCP, which a phone registered over UDP lacks, so the call is
/// never placed (seen on the lab Asterisk). All seven suites are still accepted when offered
/// (`from_name`).
pub(crate) const OFFERED: [CryptoSuite; 2] = [CryptoSuite::AeadAes256Gcm, CryptoSuite::AesCm80];

/// What a call does about SRTP.
///
/// On [`CodecCatalog`](crate::CodecCatalog), not [`MediaConfig`](crate::MediaConfig), because it
/// shapes the offer. Not the same as [`SrtpSupport`](sipral_core::sdp::SrtpSupport), which
/// describes one offer: this policy answers differently for the offer we write and the offer we
/// receive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SrtpPolicy {
    /// Do not offer SRTP. An incoming offer on the secure profile is still answered with keys.
    ///
    /// The default because, as with ICE in `docs/06-nat.md`, it is negotiated, not assumed:
    /// `RTP/SAVP` to a PBX without SRTP gets the stream refused and the call has no audio. It only
    /// governs what this end writes; refusing a peer that asked for encryption would gain nothing.
    #[default]
    NotOffered,
    /// Offer SDES on `RTP/SAVP`, and answer a plain offer plainly. For callers who prefer a plain
    /// call to none.
    Offered,
    /// Offer SDES on plain `RTP/AVP`: encrypted if the answer takes an `a=crypto` line, plain if
    /// not. The "SRTP optional" of desk phones.
    ///
    /// A server without SRTP rejects `RTP/SAVP` with 488 (RFC 4568 §7.4), but on `RTP/AVP` it
    /// ignores the unknown lines, while an SDES-capable one answers a line. RFC 4568 defines the
    /// attribute only for secure profiles, so this is an interoperability practice, not a standard.
    ///
    /// Answering: a secure offer is answered with keys as under [`SrtpPolicy::Offered`], a plain
    /// offer with a usable line is answered with one, and a plain offer without lines is answered
    /// plainly. A re-offer that would switch between keyed and plain is refused, as on every call.
    BestEffort,
    /// Offer SDES and carry no unencrypted audio on this call.
    ///
    /// A plain INVITE is not answered: [`MediaEngine::answer`](crate::MediaEngine::answer) returns
    /// [`MediaError::SrtpRequired`] so the application can reject with its own status. A plain
    /// re-offer in a live call is refused; that silent mid-call downgrade is the reason this
    /// setting exists.
    ///
    /// The offer is the same as under [`SrtpPolicy::Offered`]; a peer refusing it leaves the call
    /// without audio, and no plain re-offer follows.
    Required,
    /// Offer DTLS-SRTP on `UDP/TLS/RTP/SAVP` (RFC 5764), and answer a plain offer plainly.
    ///
    /// The key never travels in the body, so this is the one policy that is sound over readable SIP
    /// (RFC 4568 §7 says the reverse about SDES). Costs a round trip of silence per call while the
    /// handshake runs; a PBX without DTLS-SRTP refuses the stream.
    #[cfg(feature = "dtls")]
    DtlsOffered,
    /// Offer DTLS-SRTP and carry audio no other way: [`SrtpPolicy::Required`]'s refusals, plus
    /// refusing an `a=crypto` answer, since its keys travelled in a message body.
    #[cfg(feature = "dtls")]
    DtlsRequired,
    /// Offer DTLS-SRTP with SDES as fallback, and carry no unencrypted audio.
    ///
    /// One `RTP/SAVP` stream with `a=fingerprint`, `a=setup` and `a=crypto`: a DTLS peer answers
    /// its fingerprint, an SDES-only peer answers a crypto line. `RTP/SAVP` rather than
    /// `UDP/TLS/RTP/SAVP` (RFC 5764 §8) because SDES-only peers refuse an unknown profile, while
    /// DTLS peers read the fingerprint either way.
    ///
    /// Answering: a fingerprint offer gets ours and a handshake, crypto lines alone get SDES, a
    /// plain offer is refused as under [`SrtpPolicy::Required`]. Calls that fall back carry RFC
    /// 4568 §7's risk over readable transports.
    #[cfg(feature = "dtls")]
    DtlsOrSdes,
}

impl SrtpPolicy {
    /// Whether an offer under this policy carries keying: `a=crypto` for SDES, `a=fingerprint` and
    /// `a=setup` for DTLS-SRTP.
    #[must_use]
    pub(crate) const fn offers(self) -> bool {
        match self {
            Self::NotOffered => false,
            #[cfg(feature = "dtls")]
            Self::DtlsOffered | Self::DtlsRequired | Self::DtlsOrSdes => true,
            Self::Offered | Self::Required | Self::BestEffort => true,
        }
    }

    /// Whether an SDES offer under this policy goes on plain `RTP/AVP` and
    /// an answer takes crypto lines offered there
    /// ([`SrtpPolicy::BestEffort`]).
    #[must_use]
    pub(crate) const fn on_plain_profile(self) -> bool {
        matches!(self, Self::BestEffort)
    }

    /// Whether a call under this policy prefers no audio to unencrypted audio. A predicate, so new
    /// variants cannot slip past a guard written as `== Required`.
    #[must_use]
    pub(crate) const fn requires(self) -> bool {
        match self {
            Self::NotOffered | Self::Offered | Self::BestEffort => false,
            #[cfg(feature = "dtls")]
            Self::DtlsOffered => false,
            #[cfg(feature = "dtls")]
            Self::DtlsRequired | Self::DtlsOrSdes => true,
            Self::Required => true,
        }
    }

    /// Whether keys come from a media-path handshake instead of a message body. Always false
    /// without `dtls`.
    #[must_use]
    #[cfg_attr(not(feature = "dtls"), allow(dead_code))]
    pub(crate) const fn wants_dtls(self) -> bool {
        match self {
            Self::NotOffered | Self::Offered | Self::Required | Self::BestEffort => false,
            #[cfg(feature = "dtls")]
            Self::DtlsOffered | Self::DtlsRequired | Self::DtlsOrSdes => true,
        }
    }

    /// Whether an offer under this policy carries SDES beside a
    /// DTLS-SRTP fingerprint, and an answer takes whichever the offer
    /// carried ([`SrtpPolicy::DtlsOrSdes`]).
    #[must_use]
    #[cfg_attr(not(feature = "dtls"), allow(dead_code))]
    pub(crate) const fn falls_back(self) -> bool {
        match self {
            #[cfg(feature = "dtls")]
            Self::DtlsOrSdes => true,
            _ => false,
        }
    }

    /// Whether this policy refuses everything `other` refuses. A call may name its own policy, but
    /// one looser than its account's is refused (8.10).
    ///
    /// [`SrtpPolicy::DtlsRequired`] also refuses keys sent in a body, so only itself is at least as
    /// strict as it: [`SrtpPolicy::Required`] takes an SDES answer and [`SrtpPolicy::DtlsOrSdes`]
    /// falls back to one.
    #[must_use]
    pub const fn at_least(self, other: Self) -> bool {
        match other {
            #[cfg(feature = "dtls")]
            Self::DtlsRequired => matches!(self, Self::DtlsRequired),
            _ => !other.requires() || self.requires(),
        }
    }
}

/// Whether an SDES key may travel in unencrypted signalling.
///
/// RFC 4568 §8.3 requires the message carrying an `inline:` key to be encrypted (TLS for SIP). Over
/// UDP or TCP the key is readable on every hop, so the media is safe only from listeners on the
/// media path. Many PBXs offer SDES over UDP only, so the default allows it and reports it;
/// [`SdesSignalling::SecureOnly`] refuses.
///
/// Secure means TLS or secure WebSocket
/// ([`UserAgent::call_signalling_secure`](sipral_ua::UserAgent::call_signalling_secure)); a `sips:`
/// target counts only through that.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SdesSignalling {
    /// SDES is written and taken whatever carries the signalling. When the
    /// signalling is not encrypted, the call is marked
    /// ([`MediaEngine::keys_in_clear`](crate::MediaEngine::keys_in_clear) is
    /// `Some(true)`) and the engine's log says so at warning level.
    #[default]
    AnyTransport,
    /// SDES only over encrypted signalling. A description that would carry an `a=crypto` key (offer
    /// or answer) over unencrypted signalling is refused before anything is sent, with
    /// [`MediaError::KeysWouldTravelInClear`]: placing returns it and sends nothing; answering
    /// returns it so the application can reject (488 per RFC 3261). DTLS-SRTP is unaffected; under
    /// `SrtpPolicy::DtlsOrSdes` the SDES lines are refused, so for DTLS over plain signalling use
    /// `DtlsOffered` or `DtlsRequired`.
    SecureOnly,
}

/// One account's SRTP settings, applied over the engine catalogue
/// ([`MediaEngine::set_account_srtp`](crate::MediaEngine::set_account_srtp)).
///
/// A `None` half keeps the engine's value. A call placed with its own catalogue
/// ([`MediaEngine::place_with`](crate::MediaEngine::place_with)) decides the rest itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountSrtp {
    /// The account's policy.
    pub policy: Option<SrtpPolicy>,
    /// The account's suites, most preferred first — see
    /// [`CodecCatalog::with_srtp_suites`](crate::CodecCatalog::with_srtp_suites).
    pub suites: Option<Vec<Suite>>,
    /// Whether an encrypted call of this account may be recorded
    /// ([`MediaEngine::record_to`](crate::MediaEngine::record_to)) in the clear. Off by default:
    /// copies are offered as SRTP keyed in the recording session's offer (RFC 4568), and a stream
    /// the server will not take that way gets nothing (RFC 7866 §12.2). On, they go as plain RTP.
    pub recording_in_clear: bool,
    /// Whether the account's SDES keys may travel in unencrypted signalling ([`SdesSignalling`]);
    /// `None` keeps the engine's. Applies to its recording sessions too.
    pub sdes_signalling: Option<SdesSignalling>,
}

impl AccountSrtp {
    /// `catalog` with this laid over it.
    ///
    /// # Errors
    /// What [`CodecCatalog::with_srtp_suites`](crate::CodecCatalog::with_srtp_suites)
    /// refuses.
    pub(crate) fn over(
        &self,
        mut catalog: crate::CodecCatalog,
    ) -> Result<crate::CodecCatalog, MediaError> {
        if let Some(policy) = self.policy {
            catalog = catalog.with_srtp(policy);
        }
        if let Some(suites) = self.suites.as_deref() {
            catalog = catalog.with_srtp_suites(suites)?;
        }
        if let Some(sdes) = self.sdes_signalling {
            catalog = catalog.with_sdes_signalling(sdes);
        }
        Ok(catalog)
    }
}

/// The `a=crypto` lines this end offers, one per suite in order, tagged from 1.
///
/// Each key in `keys` already has its suite's width (`draw_key_for` in [`crate::engine`]), in offer
/// order, so tag, suite and key line up.
pub(crate) fn offer_lines(keys: Vec<(CryptoSuite, KeySalt)>) -> Vec<Crypto> {
    keys.into_iter()
        .enumerate()
        .map(|(index, (suite, key))| {
            // tags start at 1; at most seven suites, so it fits
            let tag = u32::try_from(index).unwrap_or(0) + 1;
            CryptoPolicy::new(tag, suite, key).to_crypto()
        })
        .collect()
}

/// The suites an SDES offer under `suites` names, in that order: the
/// catalogue's own list, or [`OFFERED`] when it named none.
pub(crate) fn sdes_suites(suites: Option<&[Suite]>) -> Vec<CryptoSuite> {
    suites.map_or_else(
        || OFFERED.to_vec(),
        |named| named.iter().copied().map(crypto_suite).collect(),
    )
}

/// The answer's line: the accepted tag and suite (§5.1.2) with our own key, since §7.1.2 forbids
/// reusing the offerer's.
///
/// `None` if the key is not the suite's width: §6.1 makes such a line invalid and the stream would
/// have no keys, so it is refused instead.
pub(crate) fn answer_line(accepted: &CryptoPolicy, keys: KeySalt) -> Option<Crypto> {
    let fits = keys.key().len() == accepted.suite.key_len()
        && keys.salt().len() == accepted.suite.salt_len();
    fits.then(|| CryptoPolicy::new(accepted.tag, accepted.suite, keys).to_crypto())
}

/// How a stream is keyed, as a kind: clear, SDES from the descriptions, or a DTLS-SRTP handshake.
///
/// A running stream cannot switch kind; each is a different `RtpSession` state. A renegotiation
/// asking for it is refused, since adopting it would leave us on the old kind while the far end
/// runs the new.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Shape {
    Clear,
    Sdes,
    Dtls,
}

impl Shape {
    /// The kind a negotiated plan's keying is.
    pub(crate) const fn of(keying: Option<&Keying>) -> Self {
        match keying {
            None => Self::Clear,
            Some(Keying::Sdes { .. }) => Self::Sdes,
            Some(Keying::Dtls { .. }) => Self::Dtls,
        }
    }
}

/// The suite and key a running stream sends under, from its plan, or `None` if not SDES-keyed.
///
/// Read from the plan because our offer carries one line per suite and the far end may have taken
/// any; the plan has the agreed one by tag (RFC 4568 §5.1.3).
pub(crate) fn key_in_force(keying: Option<&Keying>) -> Option<(CryptoSuite, KeySalt)> {
    let Some(Keying::Sdes { local, .. }) = keying else {
        return None;
    };
    let inline = local.keys.first()?;
    Some((local.suite, inline.keys.clone()))
}

/// Whether a master key used under `was` may continue under `now`: only if the cipher mode is the
/// same (counter mode for the four `AES_CM` suites, f8, or GCM for the two AEAD ones), so only the
/// tag length changes. RFC 3711 §8.1 keys one context per transform, and RFC 4568 §7.1.2 wants keys
/// "appropriate for the selected crypto algorithm".
pub(crate) fn key_carries_over(was: CryptoSuite, now: CryptoSuite) -> bool {
    fn mode(suite: CryptoSuite) -> u8 {
        match suite {
            CryptoSuite::AesF8 => 1,
            CryptoSuite::AeadAes128Gcm | CryptoSuite::AeadAes256Gcm => 2,
            _ => 0,
        }
    }
    mode(was) == mode(now)
}

/// The offered line this end answers: "the first valid supported crypto attribute in the list"
/// (§5.1.2), in the offerer's order.
///
/// `None` when none is acceptable; the stream is then refused (§7.1.2). `allowed` is the
/// catalogue's suite list if set; other suites are skipped. `None` accepts every suite this build
/// runs.
pub(crate) fn acceptable(
    offered: &MediaDescription,
    allowed: Option<&[Suite]>,
) -> Option<CryptoPolicy> {
    crypto_lines(offered).filter(understood).find_map(|line| {
        line.policy().filter(usable).filter(|policy| {
            allowed.is_none_or(|allowed| allowed.contains(&transform(policy.suite)))
        })
    })
}

/// Whether a stream uses a secure profile, which makes a key required. `sipral-core` decides this
/// internally, so the facade repeats the rule.
pub(crate) fn is_secure(proto: &str) -> bool {
    proto
        .split('/')
        .any(|token| token.eq_ignore_ascii_case("SAVP") || token.eq_ignore_ascii_case("SAVPF"))
}

/// Whether the peer's line at `tag` is one this build can honour.
///
/// Read from the description because §6.3.7 asks whether every session parameter is known, and the
/// parser drops unknown ones before the plan exists.
pub(crate) fn peer_line_holds(stream: &MediaDescription, tag: u32) -> bool {
    crypto_lines(stream)
        .filter(|line| line.tag == tag)
        .any(|line| understood(&line) && line.policy().is_some_and(|policy| usable(&policy)))
}

/// How a session opens once the negotiation settled. Three variants because DTLS-SRTP agrees on
/// protection before it has keys: [`Opening::Awaiting`] carries nothing until then.
// used once and never stored; boxing would allocate on every secured call for nothing
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum Opening {
    /// Not secured; the common case.
    Clear,
    /// Secured and keyed by SDES.
    Keyed(Security),
    /// Secured, waiting for the handshake. The policy is the most expensive possible; see
    /// [`RtpSession::awaiting`](sipral_rtp::RtpSession::awaiting).
    #[cfg(feature = "dtls")]
    Awaiting(Policy),
}

/// How a plan opens a session.
///
/// # Errors
/// [`MediaError::NoDtlsSrtp`] when the keys were to come from a DTLS
/// handshake and this build has none, and [`MediaError::UnusableKeying`] for
/// a crypto line this build will not be held to.
pub(crate) fn opening(plan: &MediaPlan) -> Result<Opening, MediaError> {
    match &plan.keying {
        None => Ok(Opening::Clear),
        #[cfg(feature = "dtls")]
        Some(Keying::Dtls { .. }) => Ok(Opening::Awaiting(crate::dtls::MOST)),
        #[cfg(not(feature = "dtls"))]
        Some(Keying::Dtls { .. }) => Err(MediaError::NoDtlsSrtp),
        Some(Keying::Sdes { local, remote }) => {
            // ours protects outgoing, theirs opens incoming: each end keys its own transmission
            // (§7.1.1)
            let (sending, sending_key) = context(local)?;
            let (receiving, receiving_key) = context(remote)?;
            Ok(Opening::Keyed(Security::new(
                sending,
                sending_key,
                receiving,
                receiving_key,
            )))
        }
    }
}

/// One direction's transform and master key. [`security`] builds both; a running session re-keys
/// one direction at a time from `MediaSession::adopt`.
///
/// # Errors
///
/// As [`security`], for one direction.
pub(crate) fn context(negotiated: &CryptoPolicy) -> Result<(Policy, Master), MediaError> {
    let inline = negotiated
        .keys
        .first()
        .filter(|_| usable(negotiated))
        .ok_or(MediaError::UnusableKeying)?;
    let identifier = match inline.mki {
        None => None,
        Some(mki) => {
            Some(Mki::new(mki.value, usize::from(mki.length)).ok_or(MediaError::UnusableKeying)?)
        }
    };
    // the key lifetime its owner wrote (§6.1) applies in the direction that key protects
    let policy = Policy {
        mki: identifier,
        lifetime: inline.lifetime,
        ..Policy::new(transform(negotiated.suite))
    };
    Ok((policy, Master::new(inline.keys.key(), inline.keys.salt())))
}

/// Whether a line names keys and terms this build can open a stream with.
///
/// One master key only, since a peer using a second would have that traffic dropped as forged.
/// Otherwise RFC 4568 §6.3 defaults: `UNENCRYPTED_SRTP`/`UNENCRYPTED_SRTCP` would put cleartext on
/// a secure profile, `UNAUTHENTICATED_SRTP` is "NOT RECOMMENDED" (§6.4.1), and a key derivation
/// rate would have to be echoed. `WSH` is ignored, which §6.3.6 allows.
fn usable(policy: &CryptoPolicy) -> bool {
    let params = policy.params;
    policy.keys.len() == 1
        && policy.keys.iter().all(|key| {
            key.mki
                .is_none_or(|mki| Mki::new(mki.value, usize::from(mki.length)).is_some())
        })
        && !params.unencrypted_rtp
        && !params.unencrypted_rtcp
        && !params.unauthenticated_rtp
        && params.kdr.is_none()
}

/// Whether every session parameter on a line is known. §6.3.7: an unknown parameter without a
/// leading '-' makes the attribute "MUST be considered invalid".
fn understood(line: &Crypto) -> bool {
    line.session_params.iter().all(|parameter| {
        parameter.starts_with('-')
            || parameter.eq_ignore_ascii_case("UNENCRYPTED_SRTP")
            || parameter.eq_ignore_ascii_case("UNENCRYPTED_SRTCP")
            || parameter.eq_ignore_ascii_case("UNAUTHENTICATED_SRTP")
            || starts_with_ignore_case(parameter, "KDR=")
            || starts_with_ignore_case(parameter, "WSH=")
    })
}

fn starts_with_ignore_case(text: &str, prefix: &str) -> bool {
    text.len() >= prefix.len()
        && text
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// A stream's `a=crypto` lines as written. Only media level is checked, since the attribute "MUST
/// only appear at the SDP media level".
fn crypto_lines(stream: &MediaDescription) -> impl Iterator<Item = Crypto> + '_ {
    stream
        .attributes
        .iter()
        .filter(|attribute| attribute.name == "crypto")
        .filter_map(|attribute| Crypto::parse(attribute.value.as_deref()?))
}

/// Whether a stream has any `a=crypto` line, parseable or not. Distinguishes a peer that wrote no
/// keys from one whose keys we could not read.
pub(crate) fn wrote_crypto(stream: &MediaDescription) -> bool {
    stream
        .attributes
        .iter()
        .any(|attribute| attribute.name == "crypto")
}

/// [`SrtpPolicy::BestEffort`]'s one failure: a plain-profile offer whose `a=crypto` lines are all
/// unusable (unparseable, disallowed suite, unsupported terms). The offerer wanted keys, so a plain
/// answer would be a plain call nobody chose; it is refused. An offer with no lines is answered
/// plainly.
pub(crate) fn best_effort_unkeyable(
    policy: SrtpPolicy,
    allowed: Option<&[Suite]>,
    offered: &MediaDescription,
) -> bool {
    policy.on_plain_profile()
        && !offered.is_rejected()
        && !is_secure(&offered.proto)
        && wrote_crypto(offered)
        && acceptable(offered, allowed).is_none()
}

/// The SDP name of a transform: [`transform`] the other way.
pub(crate) const fn crypto_suite(suite: Suite) -> CryptoSuite {
    match suite {
        Suite::AesCm80 => CryptoSuite::AesCm80,
        Suite::AesCm32 => CryptoSuite::AesCm32,
        Suite::AesF8 => CryptoSuite::AesF8,
        Suite::Aes256Cm80 => CryptoSuite::Aes256Cm80,
        Suite::Aes256Cm32 => CryptoSuite::Aes256Cm32,
        Suite::AeadAes128Gcm => CryptoSuite::AeadAes128Gcm,
        Suite::AeadAes256Gcm => CryptoSuite::AeadAes256Gcm,
    }
}

/// Whether `suite` protects at least as well as `floor`: key and tag both at least as long (RFC
/// 4568 §6.2, RFC 6188, RFC 7714). Longer in one and shorter in the other does not count, so
/// `AES_256_CM_HMAC_SHA1_32` is not as strong as `AES_CM_128_HMAC_SHA1_80`.
pub(crate) const fn at_least_as_strong(suite: Suite, floor: Suite) -> bool {
    suite.key_len() >= floor.key_len() && suite.tag() >= floor.tag()
}

/// The media-side transform for an SDP suite. Two enumerations because the SDP crate and the SRTP
/// crate do not depend on each other.
pub(crate) const fn transform(suite: CryptoSuite) -> Suite {
    match suite {
        CryptoSuite::AesCm80 => Suite::AesCm80,
        CryptoSuite::AesCm32 => Suite::AesCm32,
        CryptoSuite::AesF8 => Suite::AesF8,
        CryptoSuite::Aes256Cm80 => Suite::Aes256Cm80,
        CryptoSuite::Aes256Cm32 => Suite::Aes256Cm32,
        CryptoSuite::AeadAes128Gcm => Suite::AeadAes128Gcm,
        CryptoSuite::AeadAes256Gcm => Suite::AeadAes256Gcm,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        OFFERED, Opening, SrtpPolicy, acceptable, answer_line, is_secure, key_in_force,
        offer_lines, opening, peer_line_holds, usable,
    };
    use sipral_core::sdp::{Crypto, CryptoSuite, KeySalt, Keying, MediaPlan, parse};
    use sipral_core::sdp::{Direction, NegotiatedCodec, RtcpPlan, RtpMap};

    #[cfg(not(feature = "dtls"))]
    #[cfg(not(feature = "dtls"))]
    use crate::error::MediaError;

    /// Thirty arbitrary octets; the tests care where a key ends up, not its value.
    fn keys(fill: u8) -> KeySalt {
        KeySalt::new(&[fill; 16], &[fill.wrapping_add(1); 14])
    }

    /// One key per [`OFFERED`] suite at its own width, filled from `fill` so they differ.
    fn offer_keys(fill: u8) -> Vec<(CryptoSuite, KeySalt)> {
        OFFERED
            .iter()
            .map(|suite| {
                (
                    *suite,
                    KeySalt::new(
                        &vec![fill; suite.key_len()],
                        &vec![fill.wrapping_add(1); suite.salt_len()],
                    ),
                )
            })
            .collect()
    }

    fn stream(text: &str) -> sipral_core::sdp::MediaDescription {
        let description = format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n{text}"
        );
        parse(description.as_bytes())
            .expect("the description parses")
            .media
            .pop()
            .expect("one stream")
    }

    fn plan(keying: Option<Keying>) -> MediaPlan {
        MediaPlan {
            local: "192.0.2.1:40000".parse().expect("an address"),
            remote: "192.0.2.2:40002".parse().expect("an address"),
            codec: NegotiatedCodec::new(RtpMap {
                payload: 0,
                encoding: "PCMU".to_owned(),
                clock_rate: 8_000,
                parameters: None,
            }),
            direction: Direction::SendRecv,
            dtmf: None,
            dtmf_in: None,
            codec_in: 0,
            rtcp: RtcpPlan::Off,
            keying,
            voip_metrics_xr: false,
        }
    }

    #[test]
    fn the_default_policy_writes_no_crypto_line() {
        assert_eq!(SrtpPolicy::default(), SrtpPolicy::NotOffered);
        assert!(!SrtpPolicy::NotOffered.offers());
        assert!(SrtpPolicy::Offered.offers());
        assert!(SrtpPolicy::Required.offers());
    }

    /// A call may ask for more than its account, never less: no clear audio where SRTP is required,
    /// no body keys where the handshake is required.
    #[test]
    fn a_policy_is_at_least_as_strict_as_one_that_refuses_no_more_than_it() {
        use SrtpPolicy::{NotOffered, Offered, Required};
        assert!(Required.at_least(Required));
        assert!(Required.at_least(Offered));
        assert!(Required.at_least(NotOffered));
        assert!(Offered.at_least(NotOffered));
        assert!(NotOffered.at_least(Offered));
        assert!(!Offered.at_least(Required));
        assert!(!NotOffered.at_least(Required));
        #[cfg(feature = "dtls")]
        {
            use SrtpPolicy::{DtlsOffered, DtlsOrSdes, DtlsRequired};
            assert!(DtlsRequired.at_least(DtlsRequired));
            assert!(DtlsRequired.at_least(Required));
            assert!(DtlsRequired.at_least(DtlsOrSdes));
            assert!(DtlsOrSdes.at_least(Required));
            assert!(Required.at_least(DtlsOrSdes));
            assert!(!Required.at_least(DtlsRequired), "an SDES answer is taken");
            assert!(!DtlsOrSdes.at_least(DtlsRequired), "it falls back to one");
            assert!(!DtlsOffered.at_least(DtlsRequired));
            assert!(!DtlsOffered.at_least(Required));
        }
    }

    #[test]
    fn the_offer_is_one_line_per_offered_suite_tagged_in_order_strongest_first() {
        let lines = offer_lines(offer_keys(7));
        assert_eq!(lines.len(), OFFERED.len());
        for (index, (line, suite)) in lines.iter().zip(OFFERED).enumerate() {
            let tag = u32::try_from(index).expect("two fits") + 1;
            assert_eq!(line.tag, tag, "{}", suite.name());
            assert_eq!(line.suite, suite.name());
            assert!(line.key_params.starts_with("inline:"), "{}", suite.name());
            assert!(line.session_params.is_empty(), "{}", suite.name());
        }
        assert_eq!(
            lines
                .iter()
                .map(|line| line.suite.as_str())
                .collect::<Vec<_>>(),
            ["AEAD_AES_256_GCM", "AES_CM_128_HMAC_SHA1_80"]
        );
    }

    /// §5.1.2: the answerer takes the offerer's first supported choice, not its own.
    #[test]
    fn the_line_answered_is_the_first_one_this_build_supports() {
        let offered = stream(
            "m=audio 5004 RTP/SAVP 0\r\n\
             a=crypto:1 SOMETHING_ELSE inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
             a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
             a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n",
        );
        let taken = acceptable(&offered, None).expect("one of the three is supported");
        assert_eq!(taken.tag, 2);
        assert_eq!(taken.suite, CryptoSuite::AesCm32);
    }

    /// §7.1.2: an answerer that accepts no line refuses the stream.
    #[test]
    fn a_stream_whose_every_line_asks_for_the_impossible_is_answered_with_none() {
        let unencrypted = stream(
            "m=audio 5004 RTP/SAVP 0\r\n\
             a=crypto:1 AES_CM_128_HMAC_SHA1_80 \
             inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA UNENCRYPTED_SRTP\r\n",
        );
        assert!(acceptable(&unencrypted, None).is_none());

        // §6.3.7: an unknown parameter with no leading dash invalidates the
        // line, and one with a dash may be ignored
        let unknown = stream(
            "m=audio 5004 RTP/SAVP 0\r\n\
             a=crypto:1 AES_CM_128_HMAC_SHA1_80 \
             inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA FEC_ORDER=FEC_SRTP\r\n",
        );
        assert!(acceptable(&unknown, None).is_none());

        let optional = stream(
            "m=audio 5004 RTP/SAVP 0\r\n\
             a=crypto:1 AES_CM_128_HMAC_SHA1_80 \
             inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA -SOMETHING WSH=128\r\n",
        );
        assert!(
            acceptable(&optional, None).is_some(),
            "a hint is not a refusal"
        );
    }

    #[test]
    fn the_secure_profiles_are_the_ones_that_make_a_key_compulsory() {
        assert!(is_secure("RTP/SAVP"));
        assert!(is_secure("RTP/SAVPF"));
        assert!(is_secure("UDP/TLS/RTP/SAVP"));
        assert!(!is_secure("RTP/AVP"));
        assert!(!is_secure("RTP/AVPF"));
    }

    #[test]
    fn a_line_this_build_will_not_be_held_to_is_not_a_line_it_answers() {
        let two_keys = Crypto::parse(
            "1 AES_CM_128_HMAC_SHA1_80 \
             inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|2^20|1:4;\
             inline:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB|2^20|2:4",
        )
        .expect("a line")
        .policy()
        .expect("two keys with identifiers are a valid line");
        assert_eq!(two_keys.keys.len(), 2);
        assert!(
            !usable(&two_keys),
            "one context opens one key, so two is refused rather than half used"
        );
    }

    /// A value too wide for its identifier field makes the line unusable; refused when read.
    #[test]
    fn a_line_whose_identifier_does_not_fit_its_width_is_not_answered() {
        let line = Crypto::parse(
            "1 AES_CM_128_HMAC_SHA1_80 \
             inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|2^20|1066:1",
        )
        .expect("a line")
        .policy()
        .expect("the parser takes the identifier as written");
        assert!(
            !usable(&line),
            "1066 does not fit in the one octet the line gives it"
        );
    }

    /// The peer's line is re-read because the plan cannot show a dropped parameter.
    #[test]
    fn a_peers_line_with_an_unknown_parameter_does_not_hold() {
        let good = stream(
            "m=audio 5004 RTP/SAVP 0\r\n\
             a=crypto:4 AES_CM_128_HMAC_SHA1_80 \
             inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n",
        );
        assert!(peer_line_holds(&good, 4));
        assert!(!peer_line_holds(&good, 1), "no line carries that tag");

        let bad = stream(
            "m=audio 5004 RTP/SAVP 0\r\n\
             a=crypto:4 AES_CM_128_HMAC_SHA1_80 \
             inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA MKI_UNKNOWN\r\n",
        );
        assert!(!peer_line_holds(&bad, 4));
    }

    /// Both builds report DTLS support honestly.
    #[test]
    fn a_plan_keyed_by_a_handshake_opens_waiting_or_not_at_all() {
        let keyed = plan(Some(Keying::Dtls {
            fingerprints: vec!["sha-256 00:11:22".to_owned()],
            setup: Some("active".to_owned()),
        }));
        #[cfg(feature = "dtls")]
        assert!(
            matches!(opening(&keyed), Ok(Opening::Awaiting(_))),
            "a stream that agreed to be keyed by a handshake opened some other way"
        );
        #[cfg(not(feature = "dtls"))]
        assert_eq!(
            opening(&keyed).err(),
            Some(MediaError::NoDtlsSrtp),
            "a build with no handshake opened a stream keyed by one"
        );
    }

    #[test]
    fn a_plain_stream_opens_with_no_keys_and_that_is_not_a_failure() {
        assert!(matches!(
            opening(&plan(None)).expect("a plain plan"),
            Opening::Clear
        ));
    }

    /// The two contexts must be the right way round: ours for sending, theirs for receiving. The
    /// overhead is the only thing visible from outside.
    #[test]
    fn each_direction_takes_the_key_of_the_end_that_wrote_it() {
        let ours = sipral_core::sdp::CryptoPolicy::new(1, CryptoSuite::AesCm32, keys(1));
        let theirs = sipral_core::sdp::CryptoPolicy::new(1, CryptoSuite::AesCm32, keys(9));
        let built = opening(&plan(Some(Keying::Sdes {
            local: ours,
            remote: theirs,
        })))
        .expect("both lines are usable");
        let Opening::Keyed(built) = built else {
            panic!("a secured plan opened something other than a pair of contexts");
        };
        // the overhead comes from the sending half; the short suite has a 4-octet tag
        assert_eq!(built.rtp_overhead(), 4);
        assert_eq!(built.rtcp_overhead(), 14);
    }

    /// RFC 4568 §6.1: an answer never carries a key of the wrong width for its suite, such as a
    /// 44-octet GCM key under an `AES_CM_128_HMAC_SHA1_80` tag.
    #[test]
    fn an_answer_line_is_never_written_with_a_key_of_another_suites_width() {
        let accepted = sipral_core::sdp::CryptoPolicy::new(2, CryptoSuite::AesCm80, keys(1));
        let gcm = KeySalt::new(&[3; 32], &[4; 12]);
        assert_eq!(answer_line(&accepted, gcm), None);
        let short_salt = KeySalt::new(&[3; 16], &[4; 12]);
        assert_eq!(answer_line(&accepted, short_salt), None);

        let line = answer_line(&accepted, keys(5)).expect("a key of the suite's own width");
        assert_eq!(
            (line.tag, line.suite.as_str()),
            (2, "AES_CM_128_HMAC_SHA1_80")
        );
        let read = line.policy().expect("a line its reader can take");
        assert_eq!(read.keys.first().map(|inline| &inline.keys), Some(&keys(5)));
    }

    /// The key in force is the agreed line's, with its suite, not our first line.
    #[test]
    fn the_key_in_force_is_the_agreed_lines() {
        let ours = sipral_core::sdp::CryptoPolicy::new(2, CryptoSuite::AesCm80, keys(1));
        let theirs = sipral_core::sdp::CryptoPolicy::new(2, CryptoSuite::AesCm80, keys(9));
        let keying = Keying::Sdes {
            local: ours,
            remote: theirs,
        };
        assert_eq!(
            key_in_force(Some(&keying)),
            Some((CryptoSuite::AesCm80, keys(1)))
        );
        assert_eq!(key_in_force(None), None);
    }

    /// D5: a line's declared lifetime reaches its context; without one, RFC 3711 limits apply.
    #[test]
    fn a_declared_lifetime_reaches_the_context() {
        let mut line = sipral_core::sdp::CryptoPolicy::new(1, CryptoSuite::AesCm80, keys(3));
        let (policy, _) = super::context(&line).expect("a context");
        assert_eq!(policy.lifetime, None);
        if let Some(inline) = line.keys.first_mut() {
            inline.lifetime = Some(1 << 4);
        }
        let (policy, _) = super::context(&line).expect("a context");
        assert_eq!(policy.lifetime, Some(16));
    }
}
