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
//! # SDES, and nothing else
//!
//! [`Keying::Dtls`] is parsed by the layers below and carried through, and
//! there is no DTLS anywhere in this tree — no handshake, no certificate,
//! nothing that could produce a key on the media path. A plan that arrives
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

/// The tag on the one line this end offers. RFC 4568 §4 only asks that a tag
/// be unique among a media line's own crypto attributes, and with one line
/// there is nothing to be unique against.
const TAG: u32 = 1;

/// The suite this end offers.
///
/// One line rather than three. `AES_CM_128_HMAC_SHA1_80` is the suite every
/// implementation has, each further line would need a master key of its own
/// (§6.1: every key "MUST be unique ... with respect to other master keys in
/// the entire SDP message"), and each costs about eighty octets in a body
/// that `docs/06-nat.md` already argues has to fit a datagram. All three
/// suites are accepted when a peer offers them; only the offer is narrow.
const OFFERED: CryptoSuite = CryptoSuite::AesCm80;

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
}

impl SrtpPolicy {
    /// Whether an offer written under this policy carries `a=crypto`.
    #[must_use]
    pub(crate) const fn offers(self) -> bool {
        matches!(self, Self::Offered | Self::Required)
    }
}

/// The `a=crypto` line this end offers, carrying `keys`.
pub(crate) fn offer_line(keys: KeySalt) -> Crypto {
    CryptoPolicy::new(TAG, OFFERED, keys).to_crypto()
}

/// The line an answer carries: the tag and suite of the accepted offer
/// (§5.1.2), and this end's own key rather than the offerer's, because
/// §7.1.2 makes reusing the offerer's key across both directions the one
/// thing an answerer must not do.
pub(crate) fn answer_line(accepted: &CryptoPolicy, keys: KeySalt) -> Crypto {
    CryptoPolicy::new(accepted.tag, accepted.suite, keys).to_crypto()
}

/// The offered line this end will answer: "the first valid supported crypto
/// attribute in the list" (§5.1.2), which is the offerer's own order of
/// preference.
///
/// `None` where §7.1.2's other branch applies — no line is acceptable, and
/// the stream is refused rather than taken on terms nobody agreed.
pub(crate) fn acceptable(offered: &MediaDescription) -> Option<CryptoPolicy> {
    crypto_lines(offered)
        .filter(understood)
        .find_map(|line| line.policy().filter(usable))
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

/// The keys a plan settled on, as the pair of contexts a session opens with.
///
/// `Ok(None)` is a stream that was never meant to be secured, which is most
/// of them.
///
/// # Errors
/// [`MediaError::NoDtlsSrtp`] when the keys were to come from a DTLS
/// handshake, and [`MediaError::UnusableKeying`] for a crypto line this build
/// will not be held to.
pub(crate) fn security(plan: &MediaPlan) -> Result<Option<Security>, MediaError> {
    match &plan.keying {
        None => Ok(None),
        Some(Keying::Dtls { .. }) => Err(MediaError::NoDtlsSrtp),
        Some(Keying::Sdes { local, remote }) => {
            // ours protects what goes out and theirs opens what arrives:
            // §7.1.1 has each end key its own transmission and nothing else
            let (sending, sending_key) = context(local)?;
            let (receiving, receiving_key) = context(remote)?;
            Ok(Some(Security::new(
                sending,
                sending_key,
                receiving,
                receiving_key,
            )))
        }
    }
}

/// One direction's transform and master key.
fn context(negotiated: &CryptoPolicy) -> Result<(Policy, Master), MediaError> {
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
        && policy
            .keys
            .iter()
            .all(|key| key.mki.is_none_or(|mki| (1..=16).contains(&mki.length)))
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

/// The transform a suite names, on the media side of the boundary. Two
/// enumerations of the same three suites, because the crate that reads SDP
/// and the crate that encrypts packets do not depend on each other.
const fn transform(suite: CryptoSuite) -> Suite {
    match suite {
        CryptoSuite::AesCm80 => Suite::AesCm80,
        CryptoSuite::AesCm32 => Suite::AesCm32,
        CryptoSuite::AesF8 => Suite::AesF8,
    }
}

#[cfg(test)]
mod tests {
    use super::{SrtpPolicy, acceptable, is_secure, offer_line, peer_line_holds, security, usable};
    use sipral_core::sdp::{Crypto, CryptoSuite, KeySalt, Keying, MediaPlan, parse};
    use sipral_core::sdp::{Direction, NegotiatedCodec, RtcpPlan, RtpMap};

    use crate::error::MediaError;

    /// Thirty octets of nothing in particular; what matters in these tests is
    /// which key ends up where, not what is in it.
    fn keys(fill: u8) -> KeySalt {
        KeySalt::new([fill; 16], [fill.wrapping_add(1); 14])
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
            rtcp: RtcpPlan::Off,
            keying,
        }
    }

    #[test]
    fn the_default_policy_writes_no_crypto_line() {
        assert_eq!(SrtpPolicy::default(), SrtpPolicy::NotOffered);
        assert!(!SrtpPolicy::NotOffered.offers());
        assert!(SrtpPolicy::Offered.offers());
        assert!(SrtpPolicy::Required.offers());
    }

    #[test]
    fn the_offered_line_is_one_line_at_tag_one() {
        let line = offer_line(keys(7));
        assert_eq!(line.tag, 1);
        assert_eq!(line.suite, "AES_CM_128_HMAC_SHA1_80");
        assert!(line.key_params.starts_with("inline:"));
        assert!(line.session_params.is_empty());
        // thirty octets of key and salt, base64 without padding characters
        // left over: RFC 4568 §6.2.1 fixes the decoded length at thirty
        assert_eq!(line.key_params.len(), "inline:".len() + 40);
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
        let taken = acceptable(&offered).expect("one of the three is supported");
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
        assert!(acceptable(&unencrypted).is_none());

        // §6.3.7: an unknown parameter with no leading dash invalidates the
        // line, and one with a dash may be ignored
        let unknown = stream(
            "m=audio 5004 RTP/SAVP 0\r\n\
             a=crypto:1 AES_CM_128_HMAC_SHA1_80 \
             inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA FEC_ORDER=FEC_SRTP\r\n",
        );
        assert!(acceptable(&unknown).is_none());

        let optional = stream(
            "m=audio 5004 RTP/SAVP 0\r\n\
             a=crypto:1 AES_CM_128_HMAC_SHA1_80 \
             inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA -SOMETHING WSH=128\r\n",
        );
        assert!(acceptable(&optional).is_some(), "a hint is not a refusal");
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

    /// The one thing this module exists to be honest about.
    #[test]
    fn a_plan_keyed_by_a_handshake_this_build_has_no_code_for_is_refused() {
        let keyed = plan(Some(Keying::Dtls {
            fingerprint: "sha-256 00:11:22".to_owned(),
            setup: Some("active".to_owned()),
        }));
        assert_eq!(security(&keyed).err(), Some(MediaError::NoDtlsSrtp));
    }

    #[test]
    fn a_plain_stream_opens_with_no_keys_and_that_is_not_a_failure() {
        assert!(security(&plan(None)).expect("a plain plan").is_none());
    }

    /// The two contexts have to be built the right way round: what we send is
    /// keyed with our own line, and what arrives with theirs. Reading it
    /// through the overhead is the only observation available from outside,
    /// since neither key can be read back.
    #[test]
    fn each_direction_takes_the_key_of_the_end_that_wrote_it() {
        let ours = sipral_core::sdp::CryptoPolicy::new(1, CryptoSuite::AesCm32, keys(1));
        let theirs = sipral_core::sdp::CryptoPolicy::new(1, CryptoSuite::AesCm32, keys(9));
        let built = security(&plan(Some(Keying::Sdes {
            local: ours,
            remote: theirs,
        })))
        .expect("both lines are usable")
        .expect("a secured plan opens a pair of contexts");
        // the sending half is the one an overhead is quoted from, and the
        // short suite is four octets of tag rather than ten
        assert_eq!(built.rtp_overhead(), 4);
        assert_eq!(built.rtcp_overhead(), 14);
    }
}
