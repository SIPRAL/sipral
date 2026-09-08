// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The ICE side of a session description (RFC 8839 §5), on top of the
//! generic SDP model `sipral-core` already parses and writes.
//!
//! Everything here is a thin reading or writing of `a=` lines. The lines
//! themselves — `ice-lite`, `ice-ufrag`, `ice-pwd`, `ice-options`,
//! `candidate` — go into or come out of a real
//! [`sipral_core::sdp::SessionDescription`], so a caller never sees them as
//! strings assembled by hand.

use sipral_core::sdp::{Attribute, MediaDescription, SessionDescription};

use super::agent::LiteAgent;
use super::candidate::Candidate;

/// Mark the session as a lite implementation (RFC 8839 §4.2.1.4: "An
/// ICE-lite implementation MUST include an SDP 'ice-lite' attribute").
///
/// Session-level only — §5.3 defines it that way, so there is nowhere else to
/// put it and no per-stream override to consider.
pub fn write_session(session: &mut SessionDescription) {
    session.attributes.push(Attribute::flag("ice-lite"));
}

/// Write one stream's `ice-ufrag`, `ice-pwd`, `ice-options` and `candidate`
/// lines (RFC 8839 §5.1, §5.4, §5.6).
///
/// Media-level, so a data stream with its own agent never depends on what a
/// session-level line happens to say — RFC 8839 §5.4 makes the media-level
/// value the one that wins when both are present, which this simply never
/// leaves ambiguous.
pub fn write_media(media: &mut MediaDescription, agent: &LiteAgent, candidates: &[Candidate]) {
    media
        .attributes
        .push(Attribute::with_value("ice-ufrag", agent.local_ufrag()));
    media
        .attributes
        .push(Attribute::with_value("ice-pwd", agent.local_pwd()));
    media
        .attributes
        .push(Attribute::with_value("ice-options", "ice2"));
    for candidate in candidates {
        media.attributes.push(candidate.to_attribute());
    }
}

/// What the peer said about ICE for one data stream, read out of its offer
/// or answer (RFC 8839 §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteIce {
    /// The username fragment this stream's checks must be signed against.
    pub ufrag: String,
    /// The password those checks are signed with.
    pub pwd: String,
    /// Whether the peer declared `a=ice-lite` — the fact role determination
    /// turns on (RFC 8445 §6.1.1).
    pub lite: bool,
    /// Whether the peer declared `ice2` in `a=ice-options`, meaning it speaks
    /// this specification rather than RFC 5245 (RFC 8445 §10).
    pub ice2: bool,
    /// Every `a=candidate` line this stream carried that this agent could
    /// parse. A line it could not — an FQDN, a transport that is not UDP, a
    /// type it does not know — is simply absent, per RFC 8839 §5.1.
    pub candidates: Vec<Candidate>,
}

/// Read one stream's ICE parameters, falling back to the session level for
/// `ice-ufrag` and `ice-pwd` where the stream has none of its own (RFC 8839
/// §5.4).
///
/// `None` when the stream carries neither an `ice-ufrag` nor an `ice-pwd` at
/// either level — RFC 8839 §4.2.5 makes their presence the definition of ICE
/// support, so their absence means this stream is not using ICE at all.
#[must_use]
pub fn parse_remote(session: &SessionDescription, media: &MediaDescription) -> Option<RemoteIce> {
    let ufrag = attribute_value(media, session, "ice-ufrag")?;
    let pwd = attribute_value(media, session, "ice-pwd")?;
    let lite = session.attribute("ice-lite").is_some();
    let ice2 = declares_option(media.attribute("ice-options"), "ice2")
        || declares_option(session.attribute("ice-options"), "ice2");
    let candidates = media
        .attributes
        .iter()
        .filter(|attribute| attribute.name == "candidate")
        .filter_map(|attribute| attribute.value.as_deref())
        .filter_map(Candidate::parse)
        .collect();
    Some(RemoteIce {
        ufrag,
        pwd,
        lite,
        ice2,
        candidates,
    })
}

fn attribute_value(
    media: &MediaDescription,
    session: &SessionDescription,
    name: &str,
) -> Option<String> {
    media
        .attribute(name)
        .or_else(|| session.attribute(name))
        .and_then(|attribute| attribute.value.clone())
}

fn declares_option(attribute: Option<&Attribute>, option: &str) -> bool {
    attribute
        .and_then(|attribute| attribute.value.as_deref())
        .is_some_and(|value| value.split_whitespace().any(|token| token == option))
}

#[cfg(test)]
mod tests {
    use super::{parse_remote, write_media, write_session};
    use crate::ice::agent::{LiteAgent, Role};
    use crate::ice::candidate::{ComponentId, HostAddresses, gather};
    use sipral_core::sdp::{Attribute, Connection, MediaDescription, Origin, SessionDescription};
    use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

    fn session() -> SessionDescription {
        let address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        SessionDescription::new(Origin::new(1, 1, address), Connection::new(address))
    }

    fn audio_media() -> MediaDescription {
        MediaDescription::new("audio", 9000, "RTP/AVP", vec!["0".to_owned()])
    }

    #[test]
    fn ice_lite_is_session_level_and_a_bare_flag() {
        let mut description = session();
        write_session(&mut description);
        let attribute = description.attribute("ice-lite").expect("the flag");
        assert_eq!(attribute.value, None);
    }

    #[test]
    fn a_written_stream_round_trips_through_parse_remote() {
        let mut description = session();
        write_session(&mut description);
        let agent = LiteAgent::new(
            "8hhY".to_owned(),
            "asd88fgpdd777uzjYhagZg".to_owned(),
            Role::Controlled,
            42,
        );
        let candidates = gather(&[(
            ComponentId::RTP,
            HostAddresses {
                v4: Some(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 9000)),
                v6: None,
            },
        )]);
        let mut media = audio_media();
        write_media(&mut media, &agent, &candidates);
        description.media.push(media);

        let remote = parse_remote(&description, &description.media[0]).expect("ICE is declared");
        assert_eq!(remote.ufrag, "8hhY");
        assert_eq!(remote.pwd, "asd88fgpdd777uzjYhagZg");
        assert!(remote.lite);
        assert!(remote.ice2);
        assert_eq!(remote.candidates.len(), 1);
    }

    #[test]
    fn a_media_level_credential_overrides_the_session_level_one() {
        let mut description = session();
        description
            .attributes
            .push(Attribute::with_value("ice-ufrag", "session"));
        description
            .attributes
            .push(Attribute::with_value("ice-pwd", "sessionpassword0000000"));
        let mut media = audio_media();
        media
            .attributes
            .push(Attribute::with_value("ice-ufrag", "media"));
        media
            .attributes
            .push(Attribute::with_value("ice-pwd", "mediapassword00000000000"));
        description.media.push(media);

        let remote = parse_remote(&description, &description.media[0]).expect("ICE is declared");
        assert_eq!(remote.ufrag, "media");
    }

    #[test]
    fn a_session_level_credential_is_used_when_the_stream_has_none() {
        let mut description = session();
        description
            .attributes
            .push(Attribute::with_value("ice-ufrag", "session"));
        description
            .attributes
            .push(Attribute::with_value("ice-pwd", "sessionpassword0000000"));
        description.media.push(audio_media());

        let remote = parse_remote(&description, &description.media[0]).expect("ICE is declared");
        assert_eq!(remote.ufrag, "session");
    }

    #[test]
    fn no_ice_ufrag_anywhere_means_the_stream_is_not_using_ice() {
        let mut description = session();
        description.media.push(audio_media());
        assert!(parse_remote(&description, &description.media[0]).is_none());
    }

    #[test]
    fn ice_options_with_several_tokens_still_finds_ice2() {
        let mut description = session();
        description
            .attributes
            .push(Attribute::with_value("ice-ufrag", "8hhY"));
        description
            .attributes
            .push(Attribute::with_value("ice-pwd", "asd88fgpdd777uzjYhagZg"));
        description
            .attributes
            .push(Attribute::with_value("ice-options", "trickle ice2"));
        description.media.push(audio_media());

        let remote = parse_remote(&description, &description.media[0]).expect("ICE is declared");
        assert!(remote.ice2);
    }

    #[test]
    fn a_full_peer_did_not_write_ice_lite() {
        let mut description = session();
        description
            .attributes
            .push(Attribute::with_value("ice-ufrag", "8hhY"));
        description
            .attributes
            .push(Attribute::with_value("ice-pwd", "asd88fgpdd777uzjYhagZg"));
        description.media.push(audio_media());

        let remote = parse_remote(&description, &description.media[0]).expect("ICE is declared");
        assert!(!remote.lite);
    }
}
