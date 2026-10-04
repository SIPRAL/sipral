// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The ICE side of a session description (RFC 8839 §5), on top of the
//! generic SDP model `sipral-core` already parses and writes.
//!
//! Everything here is a thin reading or writing of `a=` lines. The lines
//! themselves — `ice-lite`, `ice-ufrag`, `ice-pwd`, `ice-options`,
//! `candidate` — go into or come out of a real
//! [`sipral_core::sdp::SessionDescription`], so a caller never sees them as
//! strings assembled by hand.

use core::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use sipral_core::sdp::{Attribute, Connection, MediaDescription, SessionDescription};

use super::agent::LiteAgent;
use super::candidate::{Candidate, ComponentId};
use super::full::Credentials;

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
    write_lines(media, agent.local_ufrag(), agent.local_pwd(), candidates);
}

/// Write a full agent's stream: the same four kinds of line as
/// [`write_media`], with credentials from [`super::IceAgent::local_credentials`]
/// and candidates from [`super::IceAgent::local_candidates`].
pub fn write_stream(
    media: &mut MediaDescription,
    credentials: &Credentials,
    candidates: &[Candidate],
) {
    write_lines(media, credentials.ufrag(), credentials.pwd(), candidates);
}

fn write_lines(media: &mut MediaDescription, ufrag: &str, pwd: &str, candidates: &[Candidate]) {
    media
        .attributes
        .push(Attribute::with_value("ice-ufrag", ufrag));
    media.attributes.push(Attribute::with_value("ice-pwd", pwd));
    media
        .attributes
        .push(Attribute::with_value("ice-options", "ice2"));
    for candidate in candidates {
        media.attributes.push(candidate.to_attribute());
    }
}

/// Write a full agent's pacing, in milliseconds (RFC 8839 §5.5). Session-level
/// only; "If the offerer is a full ICE implementation, it SHOULD include an
/// 'ice-pacing' attribute", and a lite one "MUST NOT" (§4.3.1), which is why
/// [`write_session`] does not.
pub fn write_pacing(session: &mut SessionDescription, ta: Duration) {
    session.attributes.push(Attribute::with_value(
        "ice-pacing",
        &ta.as_millis().to_string(),
    ));
}

/// Whether a stream's default destinations are missing from its candidate
/// lines — an ICE mismatch, which RFC 8839 §4.2.5 makes the condition for
/// not using ICE on the stream: an ALG somewhere rewrote the addresses.
///
/// The RTP destination is `c=` and the `m=` port. `rtcp_muxed` says whether
/// RTP and RTCP were negotiated onto one port; if so RTCP has no destination
/// of its own to look for (RFC 5761 §5.1.3). If not, and the stream does not
/// switch RTCP off with `b=RS:0` and `b=RR:0`, the RTCP destination is the one
/// `a=rtcp` names (RFC 3605) or, without it, the port after RTP's, and it has
/// to appear as a component-2 candidate. The two exceptions §4.2.5 lists are
/// honoured: `0.0.0.0` or `::` with port 9, and a `c=` address that is a
/// name rather than an address.
#[must_use]
pub fn ice_mismatch(
    session: &SessionDescription,
    media: &MediaDescription,
    remote: &RemoteIce,
    rtcp_muxed: bool,
) -> bool {
    let Some(ip) = session.connection_of(media).and_then(Connection::ip) else {
        return false;
    };
    let rtp = SocketAddr::new(ip, media.port);
    if !listed(remote, ComponentId::RTP, rtp) {
        return true;
    }
    if rtcp_muxed || rtcp_switched_off(session, media) {
        return false;
    }
    match rtcp_destination(media, rtp) {
        Some(control) => !listed(remote, ComponentId::RTCP, control),
        None => false,
    }
}

fn listed(remote: &RemoteIce, component: ComponentId, destination: SocketAddr) -> bool {
    (destination.ip().is_unspecified() && destination.port() == 9)
        || remote
            .candidates
            .iter()
            .any(|candidate| candidate.component == component && candidate.address == destination)
}

/// "If the agent does not utilize RTCP, it indicates that by including 'RS:0'
/// and 'RR:0' SDP attributes" (RFC 8839 §4.2.2).
fn rtcp_switched_off(session: &SessionDescription, media: &MediaDescription) -> bool {
    let zero = |modifier: &str| {
        media
            .bandwidth
            .iter()
            .chain(&session.bandwidth)
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                (name == modifier).then(|| value.trim() == "0")
            })
            .unwrap_or(false)
    };
    zero("RS") && zero("RR")
}

/// `a=rtcp:<port> [<nettype> <addrtype> <address>]` (RFC 3605 §2.1), or the
/// port after RTP's when the attribute is absent.
fn rtcp_destination(media: &MediaDescription, rtp: SocketAddr) -> Option<SocketAddr> {
    let Some(value) = media
        .attribute("rtcp")
        .and_then(|attribute| attribute.value.as_deref())
    else {
        return Some(SocketAddr::new(rtp.ip(), rtp.port().checked_add(1)?));
    };
    let mut parts = value.split_ascii_whitespace();
    let port = parts.next()?.parse().ok()?;
    let ip = match (parts.next(), parts.next(), parts.next()) {
        (Some(network), Some(address_type), Some(address)) => Connection {
            network: network.to_owned(),
            address_type: address_type.to_owned(),
            address: address.to_owned(),
        }
        .ip()?,
        _ => rtp.ip(),
    };
    Some(SocketAddr::new(ip, port))
}

/// What the peer said about ICE for one data stream, read out of its offer
/// or answer (RFC 8839 §5).
///
/// [`Debug`] leaves the password out, the way [`Credentials`] does on this
/// end's own. It is the same secret seen from the other side: whoever holds
/// it can sign a connectivity check the peer will believe, and a check the
/// peer believes is how the media gets pointed somewhere. This type derived
/// its `Debug` while `Credentials` wrote one by hand, which is the usual
/// shape of this mistake — one end is remembered and the other is not, and
/// the half that leaks is the half that came in off the network.
#[derive(Clone, PartialEq, Eq)]
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
    /// The pacing the peer asked for with the session-level `a=ice-pacing`
    /// (RFC 8839 §5.5), when it wrote one that parses: one to ten digits of
    /// milliseconds.
    pub pacing: Option<Duration>,
    /// Whether the stream carries `a=ice-mismatch` (RFC 8839 §5.3): the peer
    /// does ICE, just not on this stream.
    pub mismatch: bool,
}

impl fmt::Debug for RemoteIce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteIce")
            .field("ufrag", &self.ufrag)
            .field("lite", &self.lite)
            .field("ice2", &self.ice2)
            .field("candidates", &self.candidates)
            .field("pacing", &self.pacing)
            .field("mismatch", &self.mismatch)
            .finish_non_exhaustive()
    }
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
    let pacing = session
        .attribute("ice-pacing")
        .and_then(|attribute| attribute.value.as_deref())
        .and_then(parse_pacing);
    Some(RemoteIce {
        ufrag,
        pwd,
        lite,
        ice2,
        candidates,
        pacing,
        mismatch: media.has_flag("ice-mismatch"),
    })
}

/// `pacing-value = 1*10DIGIT` (RFC 8839 §5.5), in milliseconds.
fn parse_pacing(value: &str) -> Option<Duration> {
    if value.is_empty() || value.len() > 10 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u64>().ok().map(Duration::from_millis)
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
    use super::{
        RemoteIce, ice_mismatch, parse_remote, write_media, write_pacing, write_session,
        write_stream,
    };
    use crate::ice::agent::{LiteAgent, Role};
    use crate::ice::candidate::{ComponentId, HostAddresses, gather};
    use crate::ice::full::Credentials;
    use sipral_core::sdp::{Attribute, Connection, MediaDescription, Origin, SessionDescription};
    use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
    use std::time::Duration;

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

    /// What declaring ICE adds to an offer, in bytes on the wire.
    ///
    /// Measured rather than estimated, and pinned here rather than written
    /// into a document that would stop being true. A request that outgrew the
    /// path and was dropped by a NAT is the most expensive failure this
    /// project has a record of — silent, and two days to find — and the
    /// attributes below were four hundred of the bytes that did it, against a
    /// peer that did not speak ICE at all. `docs/06-nat.md` quotes this test.
    ///
    /// One address and one component is the floor: 143 bytes, fixed
    /// attributes and one candidate line together (`docs/06-nat.md`). A
    /// laptop with Wi-Fi, Ethernet and a VPN, offering both components and a
    /// reflexive candidate for each, adds eight more candidate lines to that
    /// floor — not eight more copies of the fixed attributes, which are
    /// written once regardless of how many candidates follow. What a whole
    /// INVITE with the facade's own candidates comes to is measured beside
    /// the facade, in `crates/sipral/src/tests.rs`.
    #[test]
    fn what_declaring_ice_costs_on_the_wire() {
        // `n` identical candidates, so every candidate line this writes is
        // byte-for-byte the same one: what grows with `n` is only the count
        // of lines, never their width.
        fn declared(n: usize) -> usize {
            let mut description = session();
            write_session(&mut description);
            let agent = LiteAgent::new(
                "8hhY".to_owned(),
                "asd88fgpdd777uzjYhagZg".to_owned(),
                Role::Controlled,
                42,
            );
            let one = (
                ComponentId::RTP,
                HostAddresses {
                    v4: Some(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 9000)),
                    v6: None,
                },
            );
            let candidates = gather(&vec![one; n]);
            let mut media = audio_media();
            write_media(&mut media, &agent, &candidates);
            description.media.push(media);
            description.to_string().len()
        }

        let bare = {
            let mut description = session();
            description.media.push(audio_media());
            description.to_string().len()
        };

        let one_candidate = declared(1) - bare;
        assert_eq!(
            one_candidate, 143,
            "one candidate, one address: {one_candidate} bytes. If this \
             changed, the figure in docs/06-nat.md changed with it."
        );

        // the marginal cost of one more candidate line, measured rather than
        // assumed, since it is not the 143 divided any particular way
        let per_extra_line = declared(2) - bare - one_candidate;
        let nine_candidates = declared(9) - bare;
        assert_eq!(
            nine_candidates,
            one_candidate + 8 * per_extra_line,
            "each candidate past the first adds one candidate line, not \
             another copy of the 143-byte floor"
        );
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

    fn with_credentials(description: &mut SessionDescription) {
        description
            .attributes
            .push(Attribute::with_value("ice-ufrag", "8hhY"));
        description
            .attributes
            .push(Attribute::with_value("ice-pwd", "asd88fgpdd777uzjYhagZg"));
    }

    #[test]
    fn ice_pacing_is_written_and_read_at_the_session_level_in_milliseconds() {
        let mut description = session();
        with_credentials(&mut description);
        write_pacing(&mut description, Duration::from_millis(80));
        description.media.push(audio_media());
        assert_eq!(
            description
                .attribute("ice-pacing")
                .and_then(|attribute| attribute.value.as_deref()),
            Some("80")
        );
        let remote = parse_remote(&description, &description.media[0]).expect("ICE is declared");
        assert_eq!(remote.pacing, Some(Duration::from_millis(80)));
    }

    #[test]
    fn a_pacing_value_that_is_not_one_to_ten_digits_is_ignored() {
        for bad in ["", "12345678901", "50ms", "-5", " 5"] {
            let mut description = session();
            with_credentials(&mut description);
            description
                .attributes
                .push(Attribute::with_value("ice-pacing", bad));
            description.media.push(audio_media());
            let remote =
                parse_remote(&description, &description.media[0]).expect("ICE is declared");
            assert_eq!(remote.pacing, None, "{bad:?}");
        }
        let mut description = session();
        with_credentials(&mut description);
        description.media.push(audio_media());
        let remote = parse_remote(&description, &description.media[0]).expect("ICE is declared");
        assert_eq!(remote.pacing, None);
    }

    #[test]
    fn an_ice_mismatch_flag_on_the_stream_is_read() {
        let mut description = session();
        with_credentials(&mut description);
        let mut media = audio_media();
        media.attributes.push(Attribute::flag("ice-mismatch"));
        description.media.push(media);
        let remote = parse_remote(&description, &description.media[0]).expect("ICE is declared");
        assert!(remote.mismatch);
    }

    /// A description at 198.51.100.7, RTP on port 9000, with these candidate
    /// lines and whatever else `extra` adds to the stream.
    fn described(
        candidates: &[&str],
        extra: impl FnOnce(&mut MediaDescription),
    ) -> (SessionDescription, RemoteIce) {
        let mut description = session();
        with_credentials(&mut description);
        let mut media = audio_media();
        for line in candidates {
            media
                .attributes
                .push(Attribute::with_value("candidate", line));
        }
        extra(&mut media);
        description.media.push(media);
        let remote = parse_remote(&description, &description.media[0]).expect("ICE is declared");
        (description, remote)
    }

    const RTP_LINE: &str = "1 1 UDP 2130706431 198.51.100.7 9000 typ host";
    const RTCP_LINE: &str = "1 2 UDP 2130706430 198.51.100.7 9001 typ host";

    #[test]
    fn a_default_destination_that_is_not_a_candidate_is_a_mismatch() {
        let (description, remote) = described(&[RTP_LINE], |_| {});
        assert!(!ice_mismatch(
            &description,
            &description.media[0],
            &remote,
            true
        ));

        // what an ALG that rewrote c= would leave behind
        let (description, remote) =
            described(&["1 1 UDP 2130706431 10.0.0.2 9000 typ host"], |_| {});
        assert!(ice_mismatch(
            &description,
            &description.media[0],
            &remote,
            true
        ));
    }

    #[test]
    fn without_rtcp_mux_the_rtcp_destination_has_to_be_a_candidate_too() {
        // the port after RTP's, when there is no a=rtcp
        let (description, remote) = described(&[RTP_LINE, RTCP_LINE], |_| {});
        assert!(!ice_mismatch(
            &description,
            &description.media[0],
            &remote,
            false
        ));
        let (description, remote) = described(&[RTP_LINE], |_| {});
        assert!(ice_mismatch(
            &description,
            &description.media[0],
            &remote,
            false
        ));
        // multiplexed, RTCP has no destination of its own to look for
        assert!(!ice_mismatch(
            &description,
            &description.media[0],
            &remote,
            true
        ));
    }

    #[test]
    fn the_rtcp_attribute_names_the_rtcp_destination() {
        let port_only = |media: &mut MediaDescription| {
            media.attributes.push(Attribute::with_value("rtcp", "9500"));
        };
        let listed = "1 2 UDP 2130706430 198.51.100.7 9500 typ host";
        let (description, remote) = described(&[RTP_LINE, listed], port_only);
        assert!(!ice_mismatch(
            &description,
            &description.media[0],
            &remote,
            false
        ));
        let (description, remote) = described(&[RTP_LINE, RTCP_LINE], port_only);
        assert!(ice_mismatch(
            &description,
            &description.media[0],
            &remote,
            false
        ));

        let elsewhere = |media: &mut MediaDescription| {
            media
                .attributes
                .push(Attribute::with_value("rtcp", "9500 IN IP4 198.51.100.8"));
        };
        let there = "1 2 UDP 2130706430 198.51.100.8 9500 typ host";
        let (description, remote) = described(&[RTP_LINE, there], elsewhere);
        assert!(!ice_mismatch(
            &description,
            &description.media[0],
            &remote,
            false
        ));
        let (description, remote) = described(&[RTP_LINE, listed], elsewhere);
        assert!(ice_mismatch(
            &description,
            &description.media[0],
            &remote,
            false
        ));
    }

    #[test]
    fn a_stream_that_switches_rtcp_off_needs_no_rtcp_candidate() {
        let (description, remote) = described(&[RTP_LINE], |media| {
            media.bandwidth.push("RS:0".to_owned());
            media.bandwidth.push("RR:0".to_owned());
        });
        assert!(!ice_mismatch(
            &description,
            &description.media[0],
            &remote,
            false
        ));
    }

    #[test]
    fn the_unspecified_address_with_port_nine_is_not_a_mismatch() {
        let address = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let mut description =
            SessionDescription::new(Origin::new(1, 1, address), Connection::new(address));
        with_credentials(&mut description);
        description.media.push(MediaDescription::new(
            "audio",
            9,
            "RTP/AVP",
            vec!["0".to_owned()],
        ));
        let remote = parse_remote(&description, &description.media[0]).expect("ICE is declared");
        assert!(!ice_mismatch(
            &description,
            &description.media[0],
            &remote,
            true
        ));
    }

    #[test]
    fn a_full_agent_stream_round_trips_through_parse_remote() {
        let credentials = Credentials::new("8hhY", "asd88fgpdd777uzjYhagZg").expect("shape");
        let candidates = gather(&[(
            ComponentId::RTP,
            HostAddresses {
                v4: Some(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 9000)),
                v6: None,
            },
        )]);
        let mut description = session();
        let mut media = audio_media();
        write_stream(&mut media, &credentials, &candidates);
        description.media.push(media);
        let remote = parse_remote(&description, &description.media[0]).expect("ICE is declared");
        assert_eq!(remote.ufrag, "8hhY");
        assert_eq!(remote.pwd, "asd88fgpdd777uzjYhagZg");
        assert!(remote.ice2);
        assert!(!remote.lite);
        assert_eq!(remote.candidates, candidates);
    }

    /// The peer's password is the peer's half of the same secret, and a
    /// description read off the network is exactly the thing a reader reaches
    /// for `{:?}` on when a call will not connect.
    #[test]
    fn the_peers_password_does_not_reach_a_log_either() {
        let credentials = Credentials::new("9uB6", "YH75Fviy6338Vbrhrlp8Yh").expect("shape");
        let mut description = session();
        let mut media = audio_media();
        write_stream(&mut media, &credentials, &[]);
        description.media.push(media);
        let remote = parse_remote(&description, &description.media[0]).expect("ICE is declared");

        let printed = format!("{remote:?}");
        assert!(!printed.contains("YH75Fviy6338Vbrhrlp8Yh"), "{printed}");
        assert!(printed.contains("9uB6"), "{printed}");
    }

    /// And so does the description it came out of, which carries the same
    /// password one layer down as an `a=ice-pwd` attribute.
    #[test]
    fn nor_does_the_description_it_was_read_from() {
        let credentials = Credentials::new("9uB6", "YH75Fviy6338Vbrhrlp8Yh").expect("shape");
        let mut media = audio_media();
        write_stream(&mut media, &credentials, &[]);

        let printed = format!("{media:?}");
        assert!(!printed.contains("YH75Fviy6338Vbrhrlp8Yh"), "{printed}");
    }
}
