// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The session inside a call, and which way it is held.
//!
//! Hold is only SDP direction (RFC 3264 §8.4): `sendrecv` becomes
//! `sendonly`, `recvonly` becomes `inactive`. Each end's last description is
//! kept, plus each stream's direction before any hold, so a stream that
//! started `recvonly` resumes as `recvonly`, not `sendrecv`.

use sipral_core::sdp::{
    AcceptedStream, Attribute, Connection, Direction, MediaDescription, Origin, SessionDescription,
    StreamAnswer,
};

/// Which way a call is held (RFC 3264 §8.4).
///
/// Two flags because each direction is held separately: music plays for
/// whoever was put on hold, not for whoever pressed the button.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Hold {
    /// This end asked the far end to stop sending.
    pub local: bool,
    /// The far end asked this one to.
    pub remote: bool,
}

impl Hold {
    /// Whether media is stopped in either direction.
    #[must_use]
    pub const fn is_held(self) -> bool {
        self.local || self.remote
    }
}

impl core::fmt::Display for Hold {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match (self.local, self.remote) {
            (false, false) => "not held",
            (true, false) => "held here",
            (false, true) => "held there",
            (true, true) => "held at both ends",
        })
    }
}

/// What the two ends of one call have described to each other.
#[derive(Clone, Debug, Default)]
pub(crate) struct Session {
    /// The description this end last had accepted.
    local: Option<SessionDescription>,
    /// The one the far end last sent.
    remote: Option<SessionDescription>,
    /// Each stream's direction when nothing is held, from this end's first
    /// description.
    base: Vec<Direction>,
    /// The next `o=` version. It climbs across a refused offer too (§8).
    version: u64,
    pub(crate) hold: Hold,
    /// This end offered and awaits the answer; after a 2xx it comes in the
    /// ACK (§13.2.2.4).
    pub(crate) answer_owed: bool,
}

impl Session {
    /// For an outgoing call: whether the INVITE carried an offer.
    pub(crate) const fn has_local(&self) -> bool {
        self.local.is_some()
    }

    /// Decides whether what this end writes next is an offer or an answer.
    pub(crate) const fn has_remote(&self) -> bool {
        self.remote.is_some()
    }

    pub(crate) fn set_local(&mut self, description: SessionDescription) {
        if self.base.is_empty() {
            self.base = description
                .media
                .iter()
                .map(|media| description.direction_of(media))
                .collect();
        }
        self.version = self.version.max(description.origin.version);
        self.local = Some(description);
    }

    /// Also reads whether the far end is holding us.
    pub(crate) fn set_remote(&mut self, description: SessionDescription) {
        self.hold.remote = holds_us(&description);
        self.remote = Some(description);
    }

    /// Bump the `o=` version of an offer (RFC 3264 §8), unless the caller
    /// already numbered it past ours. An unchanged version promises
    /// unchanged bytes, so the application cannot be trusted with it.
    pub(crate) fn stamp(&mut self, description: &mut SessionDescription) {
        if description.origin.version > self.version {
            self.version = description.origin.version;
            return;
        }
        self.version = self.version.saturating_add(1);
        description.origin.version = self.version;
    }

    /// The description already agreed, byte for byte.
    ///
    /// For a session-timer refresh (RFC 4028 §7.4): the version stays, which
    /// is how RFC 3264 §8 says "unchanged".
    pub(crate) fn repeat(&self) -> Option<SessionDescription> {
        self.local.clone()
    }

    /// The description this end would offer, held or not (RFC 3264 §8.4).
    ///
    /// DTLS streams are offered `actpass` (RFC 8842 §5.5) even if the last
    /// local description was an answer with a fixed role; the answerer keeps
    /// the roles in force (§5.3).
    pub(crate) fn offer(&mut self, held: bool) -> Option<SessionDescription> {
        let mut offer = self.local.clone()?;
        self.version = self.version.saturating_add(1);
        offer.origin.version = self.version;
        self.direct(&mut offer, held);
        for media in &mut offer.media {
            media.offer_roles_again();
        }
        Some(offer)
    }

    pub(crate) fn direct(&self, description: &mut SessionDescription, held: bool) {
        for (index, media) in description.media.iter_mut().enumerate() {
            set_direction(media, self.wanted(index, held));
        }
    }

    /// Whether a description this end is about to offer asks the far end to
    /// stop sending. Measured against each stream's unheld direction: one
    /// that started `sendonly` or `inactive` cannot be held and is skipped.
    pub(crate) fn holds_them(&self, description: &SessionDescription) -> bool {
        let mut any = false;
        for (index, media) in description.media.iter().enumerate() {
            let unheld = self.wanted(index, false);
            if media.is_rejected() || holding(unheld) == unheld {
                continue;
            }
            any = true;
            if matches!(
                description.direction_of(media),
                Direction::SendRecv | Direction::RecvOnly
            ) {
                return false;
            }
        }
        any
    }

    /// The answer to an offer, when this end can write one: our own ports
    /// and formats, direction per §6.1.
    pub(crate) fn answer(
        &mut self,
        offer: &SessionDescription,
        held: bool,
    ) -> Option<SessionDescription> {
        let ours = self.local.as_ref()?;
        let connection = ours
            .connection
            .clone()
            .or_else(|| ours.media.iter().find_map(|media| media.connection.clone()))?;
        let streams: Vec<StreamAnswer> = offer
            .media
            .iter()
            .enumerate()
            .map(|(index, offered)| self.take(index, offered, held))
            .collect();
        self.version = self.version.saturating_add(1);
        let origin = Origin {
            version: self.version,
            ..self.local.as_ref()?.origin.clone()
        };
        offer.answer(origin, connection, &streams).ok()
    }

    /// Whether this layer can answer an offer itself instead of handing it
    /// to the application.
    ///
    /// Yes for hold, resume, or a moved media address. No for a codec or
    /// stream change, which needs the device. No for a changed transport
    /// profile or an `a=crypto` that came or went: that may be a downgrade,
    /// and only `crates/sipral` knows whether encryption was required.
    ///
    /// No for any stream on a secure profile, even a hold: the answer needs
    /// this end's own key (RFC 4568 §5.1.2) or fingerprint and role
    /// (RFC 8842 §5.3), which this layer does not hold.
    ///
    /// No for an ICE restart (RFC 8839 §4.4.1.1.1): the answer needs fresh
    /// credentials (§4.4.2.1).
    pub(crate) fn is_same_media(&self, offer: &SessionDescription) -> bool {
        let Some(previous) = self.remote.as_ref() else {
            return false;
        };
        let credentials = |description: &SessionDescription, media: &MediaDescription| {
            ["ice-ufrag", "ice-pwd"].map(|name| {
                media
                    .attribute(name)
                    .or_else(|| description.attribute(name))
                    .and_then(|attribute| attribute.value.clone())
            })
        };
        previous.media.len() == offer.media.len()
            && previous
                .media
                .iter()
                .zip(&offer.media)
                .all(|(before, now)| credentials(previous, before) == credentials(offer, now))
            && previous
                .media
                .iter()
                .zip(&offer.media)
                .all(|(before, now)| {
                    before.media == now.media
                        && before.formats == now.formats
                        // case-insensitive, like `keying::is_secure`
                        && before.proto.eq_ignore_ascii_case(&now.proto)
                        && !now.is_secured()
                        && before.attribute("crypto").is_some()
                            == now.attribute("crypto").is_some()
                })
    }

    /// Keep the hold this end asked for in an answer somebody else wrote.
    ///
    /// The application answers re-offers `sendrecv`, which would silently
    /// unhold a call held here. Each stream is narrowed to what the hold
    /// allows; narrowing still honours the offer (§6.1). Returns `false`
    /// when nothing changed.
    pub(crate) fn keep_hold(&self, answer: &mut SessionDescription) -> bool {
        if !self.hold.local {
            return false;
        }
        let written: Vec<Direction> = answer
            .media
            .iter()
            .map(|media| answer.direction_of(media))
            .collect();
        let mut rewritten = false;
        for (index, (media, now)) in answer.media.iter_mut().zip(written).enumerate() {
            if media.is_rejected() {
                continue;
            }
            let kept = narrowed(now, self.wanted(index, true));
            if kept != now {
                set_direction(media, kept);
                rewritten = true;
            }
        }
        rewritten
    }

    /// Local and remote, as bytes.
    pub(crate) fn described(&self) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        (
            self.local.as_ref().map(SessionDescription::to_bytes),
            self.remote.as_ref().map(SessionDescription::to_bytes),
        )
    }

    fn wanted(&self, index: usize, held: bool) -> Direction {
        let base = self.base.get(index).copied().unwrap_or(Direction::SendRecv);
        if held { holding(base) } else { base }
    }

    /// Rejected when this end has no matching stream or no common format.
    fn take(&self, index: usize, offered: &MediaDescription, held: bool) -> StreamAnswer {
        let Some(ours) = self.local.as_ref().and_then(|local| local.media.get(index)) else {
            return StreamAnswer::Reject;
        };
        if ours.media != offered.media || ours.is_rejected() {
            return StreamAnswer::Reject;
        }
        let supported: Vec<&str> = ours.formats.iter().map(String::as_str).collect();
        let mut accepted = AcceptedStream::in_offer_order(ours.port, offered, &supported);
        if accepted.formats.is_empty() {
            return StreamAnswer::Reject;
        }
        accepted.attributes = carried(ours, offered);
        StreamAnswer::Accept(accepted.with_direction(self.wanted(index, held)))
    }
}

/// Attributes an answer must repeat from this end's last description;
/// leaving one out withdraws it (e.g. a hold would silently drop
/// `rtcp-mux` and move RTCP to a dead port).
///
/// `rtcp-mux` (RFC 5761 §5.1.1) and `rtcp-xr` (RFC 3611 §5.2, our request
/// for the far end's reports) only while the offer still carries them.
/// `ptime`, `maxptime` and ICE (RFC 8839 §4.4: on every description) are
/// ours regardless; there can be several `candidate` lines.
///
/// `crypto`, `fingerprint` and `setup` are never copied: secure streams are
/// not answered here ([`Session::is_same_media`]).
fn carried(ours: &MediaDescription, offered: &MediaDescription) -> Vec<Attribute> {
    let mutual = ["rtcp-mux", "rtcp-xr"]
        .iter()
        .filter(|name| offered.attribute(name).is_some());
    let ours_alone = ["ptime", "maxptime", "ice-ufrag", "ice-pwd", "ice-options"].iter();
    let single = mutual
        .chain(ours_alone)
        .filter_map(|name| ours.attribute(name).cloned());
    let candidates = ours
        .attributes
        .iter()
        .filter(|attribute| attribute.name == "candidate")
        .cloned();
    single.chain(candidates).collect()
}

/// §8.4: `sendrecv` holds as `sendonly`, `recvonly` as `inactive`.
const fn holding(base: Direction) -> Direction {
    match base {
        Direction::SendRecv | Direction::SendOnly => Direction::SendOnly,
        Direction::RecvOnly | Direction::Inactive => Direction::Inactive,
    }
}

/// The intersection of two directions.
const fn narrowed(now: Direction, most: Direction) -> Direction {
    match (sends(now) && sends(most), receives(now) && receives(most)) {
        (true, true) => Direction::SendRecv,
        (true, false) => Direction::SendOnly,
        (false, true) => Direction::RecvOnly,
        (false, false) => Direction::Inactive,
    }
}

const fn sends(direction: Direction) -> bool {
    matches!(direction, Direction::SendRecv | Direction::SendOnly)
}

const fn receives(direction: Direction) -> bool {
    matches!(direction, Direction::SendRecv | Direction::RecvOnly)
}

/// Whether a description the far end wrote refuses what this end sends.
///
/// `sendonly`, `inactive`, or the old RFC 2543 `0.0.0.0` address, which
/// §8.4 still requires us to accept. Every live stream must say it: that is
/// §8.4's "held SDP". Per-stream hold waits for video.
fn holds_us(description: &SessionDescription) -> bool {
    let mut any = false;
    for media in description
        .media
        .iter()
        .filter(|media| !media.is_rejected())
    {
        any = true;
        let refused = matches!(
            description.direction_of(media),
            Direction::SendOnly | Direction::Inactive
        ) || description
            .connection_of(media)
            .is_some_and(Connection::is_black_hole);
        if !refused {
            return false;
        }
    }
    any
}

fn set_direction(media: &mut MediaDescription, direction: Direction) {
    media
        .attributes
        .retain(|attribute| Direction::from_name(&attribute.name).is_none());
    media.attributes.push(Attribute::flag(direction.as_str()));
}

#[cfg(test)]
mod tests {
    use super::{Session, set_direction};
    use sipral_core::sdp::{
        Attribute, Connection, Direction, MediaDescription, Origin, SessionDescription,
    };
    use std::net::{IpAddr, Ipv4Addr};

    fn address() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    }

    /// One audio stream carrying PCMU, plus whatever the caller adds.
    fn description(port: u16, attributes: Vec<Attribute>) -> SessionDescription {
        secured(port, "RTP/AVP", attributes)
    }

    fn secured(port: u16, proto: &str, attributes: Vec<Attribute>) -> SessionDescription {
        let mut description =
            SessionDescription::new(Origin::new(1, 1, address()), Connection::new(address()));
        let mut media = MediaDescription::new("audio", port, proto, vec!["0".to_owned()]);
        media.attributes = attributes;
        set_direction(&mut media, Direction::SendRecv);
        description.media.push(media);
        description
    }

    fn crypto() -> Vec<Attribute> {
        vec![Attribute::with_value(
            "crypto",
            "1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )]
    }

    fn answered(ours: Vec<Attribute>, offered: Vec<Attribute>) -> MediaDescription {
        let mut session = Session::default();
        session.set_local(description(40_000, ours));
        let offer = description(40_002, offered);
        session.set_remote(offer.clone());
        let answer = session.answer(&offer, false).expect("this end can answer");
        answer
            .media
            .first()
            .cloned()
            .expect("the answer has the stream")
    }

    /// RFC 8839 §4.4: ICE goes on every description of the session.
    #[test]
    fn an_answer_this_layer_writes_does_not_withdraw_ice() {
        let ours = vec![
            Attribute::with_value("ice-ufrag", "8hhY"),
            Attribute::with_value("ice-pwd", "asd88fgpdd777uzjYhagZg"),
            Attribute::with_value("ice-options", "ice2"),
            Attribute::with_value("candidate", "1 1 UDP 2130706431 192.0.2.1 40000 typ host"),
            Attribute::with_value("candidate", "2 1 UDP 2130706430 192.0.2.9 40004 typ host"),
        ];
        let theirs = vec![
            Attribute::with_value("ice-ufrag", "9uB6"),
            Attribute::with_value("ice-pwd", "YH75Fviy6338Vbrhrlp8Yh"),
        ];
        let answer = answered(ours, theirs);
        assert_eq!(
            answer
                .attribute("ice-ufrag")
                .and_then(|line| line.value.as_deref()),
            Some("8hhY"),
            "this end's own fragment, not the peer's"
        );
        assert_eq!(
            answer
                .attribute("ice-pwd")
                .and_then(|line| line.value.as_deref()),
            Some("asd88fgpdd777uzjYhagZg")
        );
        assert_eq!(
            answer
                .attribute("ice-options")
                .and_then(|line| line.value.as_deref()),
            Some("ice2")
        );
        // both, not one per name
        assert_eq!(
            answer
                .attributes
                .iter()
                .filter(|attribute| attribute.name == "candidate")
                .count(),
            2
        );
    }

    #[test]
    fn an_answer_does_not_invent_ice_a_call_never_had() {
        let answer = answered(Vec::new(), Vec::new());
        assert!(answer.attribute("ice-ufrag").is_none());
        assert!(answer.attribute("ice-pwd").is_none());
        assert!(answer.attribute("candidate").is_none());
    }

    fn negotiated(remote: SessionDescription) -> Session {
        let mut session = Session::default();
        session.set_remote(remote);
        session
    }

    /// The `a=crypto` line stays on the offer so only the profile differs.
    #[test]
    fn a_re_offer_that_takes_the_transport_profile_down_is_not_the_same_media() {
        let session = negotiated(secured(40_000, "RTP/SAVP", crypto()));
        assert!(!session.is_same_media(&secured(40_000, "RTP/AVP", crypto())));
    }

    /// What a profile check alone would miss (RFC 4568 §5.1.2).
    #[test]
    fn a_re_offer_that_keeps_the_profile_and_drops_the_key_is_not_the_same_media() {
        let session = negotiated(secured(40_000, "RTP/SAVP", crypto()));
        assert!(!session.is_same_media(&secured(40_000, "RTP/SAVP", Vec::new())));
    }

    /// Its answer needs this end's own key or fingerprint and role.
    #[test]
    fn a_re_offer_on_a_secure_profile_goes_up_even_when_nothing_moved() {
        let session = negotiated(secured(40_000, "RTP/SAVP", crypto()));
        assert!(!session.is_same_media(&secured(40_000, "RTP/SAVP", crypto())));

        let dtls = || {
            vec![
                Attribute::with_value("fingerprint", "sha-256 AB:CD"),
                Attribute::with_value("setup", "actpass"),
            ]
        };
        let session = negotiated(secured(40_000, "UDP/TLS/RTP/SAVP", dtls()));
        assert!(!session.is_same_media(&secured(40_000, "UDP/TLS/RTP/SAVP", dtls())));
    }

    /// RFC 8839 §4.4.2.1. The same credentials again stay here.
    #[test]
    fn an_ice_restart_is_not_the_same_media() {
        let ice = |ufrag: &str, pwd: &str| {
            vec![
                Attribute::with_value("ice-ufrag", ufrag),
                Attribute::with_value("ice-pwd", pwd),
            ]
        };
        let session = negotiated(secured(
            40_000,
            "RTP/AVP",
            ice("abcd", "abcdefghijklmnopqrstuv"),
        ));
        assert!(session.is_same_media(&secured(
            40_000,
            "RTP/AVP",
            ice("abcd", "abcdefghijklmnopqrstuv")
        )));
        assert!(!session.is_same_media(&secured(
            40_000,
            "RTP/AVP",
            ice("wxyz", "zyxwvutsrqponmlkjihgfe")
        )));
    }

    #[test]
    fn the_transport_profile_is_compared_without_regard_to_case() {
        let session = negotiated(secured(40_000, "RTP/AVP", Vec::new()));
        assert!(session.is_same_media(&secured(40_000, "rtp/avp", Vec::new())));
    }

    /// RFC 8842 §5.5.
    #[test]
    fn a_hold_written_from_an_answer_offers_the_dtls_roles_back() {
        let mut session = Session::default();
        session.set_local(secured(
            40_000,
            "UDP/TLS/RTP/SAVP",
            vec![
                Attribute::with_value("fingerprint", "sha-256 AB:CD"),
                Attribute::with_value("setup", "active"),
            ],
        ));
        let offer = session.offer(true).expect("an offer");
        let media = offer.media.first().expect("the stream");
        assert_eq!(
            media.attribute("setup").and_then(|a| a.value.as_deref()),
            Some("actpass")
        );
        assert_eq!(
            media
                .attribute("fingerprint")
                .and_then(|a| a.value.as_deref()),
            Some("sha-256 AB:CD"),
            "the certificate moved"
        );
        assert_eq!(offer.direction_of(media), Direction::SendOnly);
    }

    #[test]
    fn an_answer_written_elsewhere_keeps_the_hold_this_end_asked_for() {
        let mut session = Session::default();
        session.set_local(description(40_000, Vec::new()));

        let mut answer = description(40_000, Vec::new());
        let before = answer.clone();
        assert!(!session.keep_hold(&mut answer), "nothing is held here");
        assert_eq!(answer, before);

        session.hold.local = true;
        assert!(session.keep_hold(&mut answer));
        let media = answer.media.first().expect("the stream");
        assert_eq!(answer.direction_of(media), Direction::SendOnly);

        assert!(!session.keep_hold(&mut answer));

        let mut listening = description(40_000, Vec::new());
        set_direction(
            listening.media.first_mut().expect("the stream"),
            Direction::RecvOnly,
        );
        assert!(session.keep_hold(&mut listening));
        let media = listening.media.first().expect("the stream");
        assert_eq!(listening.direction_of(media), Direction::Inactive);
    }

    /// Dropping it would move RTCP back to a port nobody listens on.
    #[test]
    fn an_answer_repeats_the_multiplexing_the_first_negotiation_settled() {
        let mut session = Session::default();
        session.set_local(description(40_000, vec![Attribute::flag("rtcp-mux")]));
        let offer = description(40_002, vec![Attribute::flag("rtcp-mux")]);
        session.set_remote(offer.clone());

        let answer = session.answer(&offer, true).expect("an answer");
        let media = answer.media.first().expect("the stream");
        assert!(
            media.attribute("rtcp-mux").is_some(),
            "the hold took multiplexing away: {media:?}"
        );
    }

    /// RFC 5761 §5.1.1: mutual.
    #[test]
    fn an_offer_that_no_longer_asks_to_multiplex_is_not_answered_as_if_it_did() {
        let mut session = Session::default();
        session.set_local(description(40_000, vec![Attribute::flag("rtcp-mux")]));
        let offer = description(40_002, Vec::new());
        session.set_remote(offer.clone());

        let answer = session.answer(&offer, false).expect("an answer");
        let media = answer.media.first().expect("the stream");
        assert!(media.attribute("rtcp-mux").is_none());
    }

    /// This end's own line is repeated: it asks the far end for XR
    /// (RFC 3611 §5.2).
    #[test]
    fn an_answer_repeats_this_ends_own_request_for_voip_metrics_xr() {
        let mut session = Session::default();
        session.set_local(description(
            40_000,
            vec![Attribute::with_value("rtcp-xr", "voip-metrics")],
        ));
        let offer = description(
            40_002,
            vec![Attribute::with_value("rtcp-xr", "voip-metrics")],
        );
        session.set_remote(offer.clone());

        let answer = session.answer(&offer, true).expect("an answer");
        let media = answer.media.first().expect("the stream");
        assert_eq!(
            media.attribute("rtcp-xr").and_then(|a| a.value.as_deref()),
            Some("voip-metrics")
        );
    }

    #[test]
    fn an_offer_that_does_not_ask_for_voip_metrics_xr_is_not_answered_with_it() {
        let mut session = Session::default();
        session.set_local(description(
            40_000,
            vec![Attribute::with_value("rtcp-xr", "voip-metrics")],
        ));
        let offer = description(40_002, Vec::new());
        session.set_remote(offer.clone());

        let answer = session.answer(&offer, false).expect("an answer");
        let media = answer.media.first().expect("the stream");
        assert!(media.attribute("rtcp-xr").is_none());
    }

    #[test]
    fn the_packet_length_this_end_asked_for_survives_a_re_offer() {
        let mut session = Session::default();
        session.set_local(description(
            40_000,
            vec![Attribute::with_value("ptime", "30")],
        ));
        let offer = description(40_002, Vec::new());
        session.set_remote(offer.clone());

        let answer = session.answer(&offer, false).expect("an answer");
        let media = answer.media.first().expect("the stream");
        assert_eq!(
            media.attribute("ptime").and_then(|a| a.value.as_deref()),
            Some("30")
        );
    }

    /// RFC 4568 §5.1.2 wants this end's own key, which this layer lacks.
    #[test]
    fn a_crypto_line_is_not_repeated_by_a_layer_that_never_read_one() {
        let mut session = Session::default();
        session.set_local(description(
            40_000,
            vec![Attribute::with_value(
                "crypto",
                "1 AES_CM_128_HMAC_SHA1_80 inline:x",
            )],
        ));
        let offer = description(
            40_002,
            vec![Attribute::with_value(
                "crypto",
                "1 AES_CM_128_HMAC_SHA1_80 inline:y",
            )],
        );
        session.set_remote(offer.clone());

        let answer = session.answer(&offer, false).expect("an answer");
        let media = answer.media.first().expect("the stream");
        assert!(
            media.attribute("crypto").is_none(),
            "a key was copied forward rather than negotiated"
        );
    }
}
