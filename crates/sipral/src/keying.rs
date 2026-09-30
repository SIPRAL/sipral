// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What a call does about SRTP: what it offers, what it will answer, and what
//! the negotiation's outcome opens the stream with.
//!
//! `sipral-rtp` has RFC 3711 and `sipral-core` has RFC 4568's `a=crypto`, and
//! neither had ever met the other. An offer named `RTP/AVP`, an answer was
//! never read for keys, and every call this stack placed went out in the
//! clear although both halves of the encryption were written and tested. This
//! is the joint: one policy per call, one master key drawn per description,
//! and one function that turns [`MediaPlan::keying`] into the [`Security`] a
//! session is opened with.
//!
//! # Two ways to a key, and one of them is not finished when the call is
//!
//! SDES puts the key in the body, so a plan keyed that way opens a stream
//! that is protected from its first packet. DTLS-SRTP puts it in a handshake
//! on the media path, so a plan keyed *that* way opens a stream that has
//! agreed to be protected and cannot be yet — which is why [`opening`] has
//! three answers where a pair of keys would have been two.
//!
//! Without the `dtls` feature there is no handshake, no certificate and
//! nothing that could produce a key on the media path; a plan that arrives
//! keyed that way is refused rather than opened unprotected, and
//! [`Capabilities`](crate::Capabilities) says so before a call is placed
//! rather than after one has failed.
//!
//! # What is refused rather than half-honoured
//!
//! One master key to a line, and RFC 4568 §6.3's defaults: everything
//! encrypted, everything authenticated, one key derivation. A line asking for
//! anything else is not answered and a plan carrying anything else does not
//! open a session, because a stream opened with the wrong derivation rate
//! produces packets the far end drops, and that looks like a network fault
//! for as long as somebody is prepared to keep looking.

use sipral_core::sdp::{
    Crypto, CryptoPolicy, CryptoSuite, KeySalt, Keying, MediaDescription, MediaPlan,
};
use sipral_rtp::srtp::{Master, Mki, Policy, Security, Suite};

use crate::error::MediaError;

/// The suites this end offers, one line each, tagged in this order starting
/// from 1 — RFC 4568 §4 only asks that a tag be unique among a media line's
/// own crypto attributes. Strongest first (8.2.4): `AEAD_AES_256_GCM`, then
/// `AES_CM_128_HMAC_SHA1_80` — RFC 7714's stronger suite named ahead of the
/// one suite every implementation has, so an answerer that itself prefers
/// strength (§5.1.2 leaves the answerer's own policy free; it binds only the
/// offerer's own *order*) settles on it, and a peer with nothing but the
/// original suite still finds that, last in the list. Each carries a master
/// key of its own (§6.1: every key "MUST be unique ... with respect to other
/// master keys in the entire SDP message").
///
/// Two and not all four the stack runs, because every line is in the
/// INVITE, and so in the INVITE that answers a server's digest challenge:
/// with `AEAD_AES_128_GCM` and `AES_256_CM_HMAC_SHA1_80` as well, that
/// request passes RFC 3261 §18.1.1's 1300 octets and needs a stream a phone
/// registered over UDP alone does not have, and the call is never placed —
/// the lab's Asterisk showed it. The other five suites are still accepted
/// when a peer offers them (`from_name` reads all seven).
pub(crate) const OFFERED: [CryptoSuite; 2] = [CryptoSuite::AeadAes256Gcm, CryptoSuite::AesCm80];

/// What a call does about SRTP.
///
/// This lives on [`CodecCatalog`](crate::CodecCatalog) rather than on
/// [`MediaConfig`](crate::MediaConfig) because it decides what goes into an
/// offer, and the catalogue is where the rest of that lives; a
/// [`MediaConfig`](crate::MediaConfig) value is a choice about behaviour that
/// no negotiation can move.
///
/// Not to be confused with [`SrtpSupport`](sipral_core::sdp::SrtpSupport),
/// which is the description a single offer carries. This is the policy a call
/// holds, and the two answers it gives — one for the offer this end writes,
/// one for the offer that arrives — are not the same answer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SrtpPolicy {
    /// Do not offer it. An offer that arrives on the secure profile is still
    /// answered with keys.
    ///
    /// The default, and the reason is the same one `docs/06-nat.md` gives for
    /// ICE: a mechanism that only helps against a peer that supports it is
    /// negotiated, never assumed. An offer on `RTP/SAVP` to a PBX that does
    /// not do SRTP has its stream refused, and the PBX this stack is tested
    /// against is such a PBX — so the call that was meant to be encrypted is
    /// a call with no audio in it.
    ///
    /// The default is about what this end *writes*. It says nothing about
    /// what this end will take: a peer that has already asked for encryption
    /// gets it, because refusing there would turn a working secure call into
    /// a silent one for no gain.
    #[default]
    NotOffered,
    /// Offer SDES on `RTP/SAVP`, and answer a plain offer plainly.
    ///
    /// What a caller who would rather have a plain call than none asks for.
    Offered,
    /// Offer SDES, and let no stream on this call carry audio unencrypted.
    ///
    /// A plain INVITE is not answered ([`MediaError::SrtpRequired`] comes
    /// back from [`MediaEngine::answer`](crate::MediaEngine::answer), so the
    /// application can reject the call with a status code of its choosing),
    /// and a plain re-offer inside a live call is refused rather than
    /// accepted. That second one is the whole reason this is a separate
    /// setting: a stack that offers SDES and then answers a mid-call plain
    /// re-offer in the clear has fallen back silently, which is the worst of
    /// the outcomes available.
    ///
    /// It does not change what an offer this end writes: both this and
    /// [`SrtpPolicy::Offered`] write `RTP/SAVP` with one `a=crypto` line, and
    /// a peer that refuses that stream leaves the call with no audio either
    /// way. This stack does not follow a refusal with a plain re-offer.
    Required,
    /// Offer DTLS-SRTP on `UDP/TLS/RTP/SAVP` (RFC 5764), and answer a plain
    /// offer plainly.
    ///
    /// What [`SrtpPolicy::Offered`] is for SDES, with the difference that
    /// matters: the key never travels in the body, so this is the one policy
    /// here that is sound over a SIP transport somebody else can read. RFC
    /// 4568 §7 says the same thing the other way round about SDES.
    ///
    /// The cost is a round trip of silence at the start of every call while
    /// the handshake runs, and a PBX that does not do DTLS-SRTP refuses the
    /// stream outright rather than falling back.
    #[cfg(feature = "dtls")]
    DtlsOffered,
    /// Offer DTLS-SRTP, and let no stream on this call carry audio any other
    /// way.
    ///
    /// [`SrtpPolicy::Required`]'s refusals, and one more: a peer that answers
    /// with `a=crypto` has answered with keys that travelled in the body of a
    /// message this policy exists to avoid trusting, so that answer is
    /// refused too.
    #[cfg(feature = "dtls")]
    DtlsRequired,
    /// Offer DTLS-SRTP with SDES beside it for a peer that has no DTLS, and
    /// let no stream on this call carry audio unencrypted.
    ///
    /// The offer is one stream on `RTP/SAVP` carrying both `a=fingerprint`
    /// and `a=setup` and the `a=crypto` lines: a peer that does DTLS-SRTP
    /// answers with its own fingerprint and the call is keyed by the
    /// handshake, and a peer that knows only SDES ignores the fingerprint
    /// and answers a crypto line, as RFC 4568 has it answer any. `RTP/SAVP`
    /// rather than `UDP/TLS/RTP/SAVP` (RFC 5764 §8), because the SDES-only
    /// peer this fallback exists for refuses a stream on a profile it does
    /// not know, and a DTLS-SRTP peer reads the fingerprint either way.
    ///
    /// Answering, an offer carrying a fingerprint is answered with this
    /// end's own and keyed by the handshake, one carrying only crypto lines
    /// with SDES, and a plain one is refused as under
    /// [`SrtpPolicy::Required`]. What the key costs over a transport somebody
    /// else can read is RFC 4568 §7's, for the calls that fall back.
    #[cfg(feature = "dtls")]
    DtlsOrSdes,
}

impl SrtpPolicy {
    /// Whether an offer written under this policy carries keying at all —
    /// `a=crypto` for SDES, `a=fingerprint` and `a=setup` for DTLS-SRTP.
    #[must_use]
    pub(crate) const fn offers(self) -> bool {
        match self {
            Self::NotOffered => false,
            #[cfg(feature = "dtls")]
            Self::DtlsOffered | Self::DtlsRequired | Self::DtlsOrSdes => true,
            Self::Offered | Self::Required => true,
        }
    }

    /// Whether a call under this policy would rather have no audio than
    /// unencrypted audio.
    ///
    /// A predicate and not an equality test, because the one thing a fourth
    /// and fifth variant must not do is walk past a guard that was written
    /// as `== Required`.
    #[must_use]
    pub(crate) const fn requires(self) -> bool {
        match self {
            Self::NotOffered | Self::Offered => false,
            #[cfg(feature = "dtls")]
            Self::DtlsOffered => false,
            #[cfg(feature = "dtls")]
            Self::DtlsRequired | Self::DtlsOrSdes => true,
            Self::Required => true,
        }
    }

    /// Whether this policy asks for the keys to come from a handshake on the
    /// media path rather than from the body of a message.
    ///
    /// Never true in a build without the `dtls` feature, which has no variant
    /// that could make it so — the method stays so that the one caller does
    /// not have to be written twice.
    #[must_use]
    #[cfg_attr(not(feature = "dtls"), allow(dead_code))]
    pub(crate) const fn wants_dtls(self) -> bool {
        match self {
            Self::NotOffered | Self::Offered | Self::Required => false,
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

    /// Whether this policy is at least as strict as `other`: whatever
    /// `other` refuses, this refuses too. A call placed on an account may
    /// name its own policy, and one that would carry audio the account's
    /// would not is refused as the account's security policy (8.10).
    ///
    /// [`SrtpPolicy::DtlsRequired`] refuses one thing more than the other
    /// policies that require encryption: keys that travelled in the body of
    /// a message. So nothing but itself is at least as strict as it —
    /// [`SrtpPolicy::Required`] takes an SDES answer, and
    /// [`SrtpPolicy::DtlsOrSdes`] falls back to one.
    #[must_use]
    pub const fn at_least(self, other: Self) -> bool {
        match other {
            #[cfg(feature = "dtls")]
            Self::DtlsRequired => matches!(self, Self::DtlsRequired),
            _ => !other.requires() || self.requires(),
        }
    }
}

/// What one account's calls do about SRTP, laid over the engine's own
/// catalogue ([`MediaEngine::set_account_srtp`](crate::MediaEngine::set_account_srtp)):
/// the SRTP policy per account.
///
/// Either half left `None` keeps what the engine's catalogue says; a call
/// placed with a catalogue of its own
/// ([`MediaEngine::place_with`](crate::MediaEngine::place_with)) says the
/// rest for itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountSrtp {
    /// The account's policy.
    pub policy: Option<SrtpPolicy>,
    /// The account's suites, most preferred first — see
    /// [`CodecCatalog::with_srtp_suites`](crate::CodecCatalog::with_srtp_suites).
    pub suites: Option<Vec<Suite>>,
    /// Whether an encrypted call of this account may be recorded to a
    /// recording server ([`MediaEngine::record_to`](crate::MediaEngine::record_to))
    /// in the clear. Off unless said: the copies of an encrypted call are
    /// offered to the server as SRTP, keyed in the recording session's own
    /// offer (RFC 4568), and a stream the server will not take that way gets
    /// nothing (RFC 7866 §12.2). On, they go as plain RTP, as an unencrypted
    /// call's always do.
    pub recording_in_clear: bool,
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
        Ok(catalog)
    }
}

/// The `a=crypto` lines this end offers, one per suite in the order given,
/// tagged from 1, each carrying the key drawn for it.
///
/// `keys` is one key per offered suite, each already the width that suite's
/// own `key_len`/`salt_len` calls for — [`crate::engine`]'s `draw_key_for`
/// draws them that way — in the order they are offered in, so the tag, the
/// suite name and the key line up without this function having to ask which
/// is which.
pub(crate) fn offer_lines(keys: Vec<(CryptoSuite, KeySalt)>) -> Vec<Crypto> {
    keys.into_iter()
        .enumerate()
        .map(|(index, (suite, key))| {
            // tags start at 1; a catalogue names at most the seven suites
            // there are, so this always fits
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

/// The line an answer carries: the tag and suite of the accepted offer
/// (§5.1.2), and this end's own key rather than the offerer's, because
/// §7.1.2 makes reusing the offerer's key across both directions the one
/// thing an answerer must not do.
pub(crate) fn answer_line(accepted: &CryptoPolicy, keys: KeySalt) -> Crypto {
    CryptoPolicy::new(accepted.tag, accepted.suite, keys).to_crypto()
}

/// How a stream is keyed, as a kind rather than as keys: in the clear, by
/// SDES keys out of the descriptions, or by a DTLS-SRTP handshake on the
/// media path.
///
/// What a running stream cannot turn into another of. Each is a different
/// state of `RtpSession` — no context, a context from the description, a
/// context still being waited for — and a stream that has sent under one has
/// no way to carry on under another; a re-negotiation that asks for it is
/// refused rather than adopted, since adopting the plan would leave the
/// stream running the old kind while the far end runs the new.
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

/// The key a stream this end described is sending under: the first key of
/// its first crypto line that reads, or `None` where it carries none.
///
/// This end's own description, which carries one line — the one it offered,
/// or the one it answered with — so there is no choosing between lines here.
pub(crate) fn key_in_force(stream: &MediaDescription) -> Option<KeySalt> {
    let policy = crypto_lines(stream).find_map(|line| line.policy())?;
    policy.keys.into_iter().next().map(|inline| inline.keys)
}

/// The offered line this end will answer: "the first valid supported crypto
/// attribute in the list" (§5.1.2), which is the offerer's own order of
/// preference.
///
/// `None` where §7.1.2's other branch applies — no line is acceptable, and
/// the stream is refused rather than taken on terms nobody agreed.
///
/// `allowed` is the catalogue's own list of suites, when it named one: a
/// line under any other suite is passed over as unsupported, which is what
/// an account that set its suites asked for. `None` takes every suite this
/// build runs.
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

/// Whether a stream is described on one of the secure profiles, which is what
/// makes a key required rather than optional.
///
/// `sipral-core` decides the same thing for its own negotiation and keeps the
/// answer to itself, so this is the facade's own reading of the same rule.
pub(crate) fn is_secure(proto: &str) -> bool {
    proto
        .split('/')
        .any(|token| token.eq_ignore_ascii_case("SAVP") || token.eq_ignore_ascii_case("SAVPF"))
}

/// Whether the peer's own line at `tag` is one this build can be held to.
///
/// Read off the description rather than off the plan, because the two
/// questions §6.3.7 asks — is every session parameter known, and is every
/// known one something we do — cannot both be asked of a
/// [`CryptoPolicy`](sipral_core::sdp::CryptoPolicy): the parser drops a
/// parameter it does not recognise instead of invalidating the line, so by
/// the time the plan exists the evidence is gone.
pub(crate) fn peer_line_holds(stream: &MediaDescription, tag: u32) -> bool {
    crypto_lines(stream)
        .filter(|line| line.tag == tag)
        .any(|line| understood(&line) && line.policy().is_some_and(|policy| usable(&policy)))
}

/// How a session is opened, once the negotiation has settled.
///
/// Three and not two, because DTLS-SRTP agrees in the signalling that a
/// stream is protected and produces the keys a round trip later: a stream in
/// [`Opening::Awaiting`] is neither in the clear nor able to carry anything.
// moved once, from the negotiation into the session being opened, and never
// stored: the keys were already this wide as the `Option<Security>` this
// replaced, and boxing them here would allocate on every secured call to even
// up a value that has nowhere to sit.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum Opening {
    /// Never meant to be secured, which is most of them.
    Clear,
    /// Secured, and keyed: SDES, whose keys were in the body.
    Keyed(Security),
    /// Secured, and waiting for the handshake that keys it. The policy is the
    /// most expensive the handshake could settle on; see
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
            // ours protects what goes out and theirs opens what arrives:
            // §7.1.1 has each end key its own transmission and nothing else
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

/// One direction's transform and master key.
///
/// [`security`] builds both halves at once for a session being opened; a
/// session already running re-keys one direction at a time, so this is reached
/// on its own from `MediaSession::adopt`.
///
/// # Errors
/// As [`security`], for the one direction.
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
    let policy = Policy {
        mki: identifier,
        ..Policy::new(transform(negotiated.suite))
    };
    Ok((policy, Master::new(inline.keys.key(), inline.keys.salt())))
}

/// Whether a line names keys and terms this build can open a stream with.
///
/// One master key, because one context opens one key and a peer that keyed
/// half its stream with the second one would have that half dropped as
/// forged. Otherwise RFC 4568 §6.3's defaults: `UNENCRYPTED_SRTP` and
/// `UNENCRYPTED_SRTCP` ask for a secure profile carrying cleartext, §6.4.1
/// calls `UNAUTHENTICATED_SRTP` "NOT RECOMMENDED" in its own words, and a key
/// derivation rate is a parameter an answer would then have to echo back for
/// the offerer to believe it was honoured. `WSH` is allowed through and
/// ignored: §6.3.6 makes it "only ... a hint to the receiver of the SDP that
/// MAY choose to ignore the value provided".
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

/// Whether every session parameter on a line is one this build knows.
///
/// §6.3.7: "If an SDP crypto attribute is received with an unknown session
/// parameter that is not prefixed with a '-' character, that crypto attribute
/// MUST be considered invalid." A parameter that has to be honoured and
/// cannot be read is the one case where taking the line is worse than
/// refusing it.
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

/// The `a=crypto` lines of a stream, as they were written. "The crypto
/// attribute MUST only appear at the SDP media level", so nowhere else is
/// looked at.
fn crypto_lines(stream: &MediaDescription) -> impl Iterator<Item = Crypto> + '_ {
    stream
        .attributes
        .iter()
        .filter(|attribute| attribute.name == "crypto")
        .filter_map(|attribute| Crypto::parse(attribute.value.as_deref()?))
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

/// Whether `suite` protects at least as well as `floor`: a key at least as
/// long and an authentication tag at least as long. The two measures are
/// the ones the suites differ by (RFC 4568 §6.2, RFC 6188, RFC 7714), and a
/// suite longer in one and shorter in the other is not counted as at least
/// as strong — `AES_256_CM_HMAC_SHA1_32` is not, against
/// `AES_CM_128_HMAC_SHA1_80`.
pub(crate) const fn at_least_as_strong(suite: Suite, floor: Suite) -> bool {
    suite.key_len() >= floor.key_len() && suite.tag() >= floor.tag()
}

/// The transform a suite names, on the media side of the boundary. Two
/// enumerations of the same seven suites, because the crate that reads SDP
/// and the crate that encrypts packets do not depend on each other.
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
        OFFERED, Opening, SrtpPolicy, acceptable, is_secure, offer_lines, opening, peer_line_holds,
        usable,
    };
    use sipral_core::sdp::{Crypto, CryptoSuite, KeySalt, Keying, MediaPlan, parse};
    use sipral_core::sdp::{Direction, NegotiatedCodec, RtcpPlan, RtpMap};

    #[cfg(not(feature = "dtls"))]
    #[cfg(not(feature = "dtls"))]
    use crate::error::MediaError;

    /// Thirty octets of nothing in particular; what matters in these tests is
    /// which key ends up where, not what is in it.
    fn keys(fill: u8) -> KeySalt {
        KeySalt::new(&[fill; 16], &[fill.wrapping_add(1); 14])
    }

    /// One key per suite [`OFFERED`] names, each the width its own suite
    /// calls for, filled from `fill` on so the four are never the same
    /// bytes.
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

    /// A call may ask for more than its account and never for less: not
    /// for audio in the clear where the account requires SRTP, and not for
    /// keys in the body where the account requires the handshake.
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

    /// §5.1.2 has the answerer take the offerer's own first choice among the
    /// ones it supports, not its own.
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

    /// §7.1.2's other branch: an answerer that can accept none of them
    /// refuses the stream rather than falling back to something nobody
    /// offered.
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

    /// An identifier travels in a field of the width its line names, so a
    /// value that field cannot carry is a line no stream can be opened with.
    /// It is refused where it is read, not answered and then failed.
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

    /// The peer's line is read off the description a second time because the
    /// plan cannot say whether a parameter was dropped on the way in.
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

    /// The one thing this module exists to be honest about, in both builds.
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

    /// The two contexts have to be built the right way round: what we send is
    /// keyed with our own line, and what arrives with theirs. Reading it
    /// through the overhead is the only observation available from outside,
    /// since neither key can be read back.
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
        // the sending half is the one an overhead is quoted from, and the
        // short suite is four octets of tag rather than ten
        assert_eq!(built.rtp_overhead(), 4);
        assert_eq!(built.rtcp_overhead(), 14);
    }
}
