// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The session inside a call, and which way it is held.
//!
//! Hold is not a SIP feature. It is a session description with its direction
//! attributes changed, carried by whatever request the dialog allows, and
//! RFC 3264 §8.4 is the whole of it: a stream that was `sendrecv` is held by
//! marking it `sendonly`, one that was `recvonly` by marking it `inactive`.
//! Each direction is held separately, and the rule that the answerer must not
//! echo held SDP back needs no code of its own — §6.1 already leaves
//! `recvonly` as the only sensible answer to `sendonly`.
//!
//! So what is kept here is what each end last described, plus the direction
//! every stream had before anybody pressed hold. That last one earns its
//! place: a stream that started `recvonly` — an announcement, a recorder —
//! is resumed to `recvonly`, not promoted to `sendrecv` by a user who never
//! asked for it.

use sipral_core::sdp::{
    AcceptedStream, Attribute, Connection, Direction, MediaDescription, Origin, SessionDescription,
    StreamAnswer,
};

/// Which way a call is held (RFC 3264 §8.4).
///
/// Two flags rather than one, because "a stream is placed on hold separately
/// in each direction" and the two are not the same event. Music plays for
/// whoever was put on hold; it does not play for whoever pressed the button.
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
    /// The direction each stream has when nothing is held, taken from the
    /// first description this end wrote.
    base: Vec<Direction>,
    /// The next `o=` version to write. It climbs across a refused offer too:
    /// §8 makes the number the way an end says "this is different from what I
    /// said before", and a description that was turned down was still said.
    version: u64,
    /// Which way it is held.
    pub(crate) hold: Hold,
    /// Whether this end has offered and is still owed the answer, which for a
    /// 2xx means the answer travels in the ACK (§13.2.2.4).
    pub(crate) answer_owed: bool,
}

impl Session {
    /// Whether this end has described anything, which for an outgoing call is
    /// the same question as whether the INVITE carried an offer.
    pub(crate) const fn has_local(&self) -> bool {
        self.local.is_some()
    }

    /// Whether the far end has described anything yet, which is what decides
    /// whether a description this end writes is an offer or an answer.
    pub(crate) const fn has_remote(&self) -> bool {
        self.remote.is_some()
    }

    /// Take a description this end has put on the wire and had accepted.
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

    /// Take one the far end sent, and read from it whether it is holding us.
    pub(crate) fn set_remote(&mut self, description: SessionDescription) {
        self.hold.remote = holds_us(&description);
        self.remote = Some(description);
    }

    /// Give a description this end is about to offer a version that has
    /// moved (RFC 3264 §8), leaving one the caller has already numbered past
    /// ours alone.
    ///
    /// §8 makes the number the way an end says "this differs from what I said
    /// before", and pairs it with the other half of the rule: an unchanged
    /// number promises unchanged bytes. An application that hands us the same
    /// version twice with different content would be making that promise
    /// falsely, so the number is ours to write.
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
    /// RFC 4028 §7.4 has a session-timer refresh carry an offer "even if the
    /// details of the session have not changed. In that case, the offer MUST
    /// indicate that it has not changed" — and RFC 3264 §8 says an unchanged
    /// `o=` version is exactly how that is said. So this deliberately does not
    /// move the version.
    pub(crate) fn repeat(&self) -> Option<SessionDescription> {
        self.local.clone()
    }

    /// The description this end would offer, held or not (RFC 3264 §8.4).
    pub(crate) fn offer(&mut self, held: bool) -> Option<SessionDescription> {
        let mut offer = self.local.clone()?;
        self.version = self.version.saturating_add(1);
        offer.origin.version = self.version;
        for (index, media) in offer.media.iter_mut().enumerate() {
            set_direction(media, self.wanted(index, held));
        }
        Some(offer)
    }

    /// The answer to an offer that arrived, when this end can write one.
    ///
    /// The ports and the formats are this end's own, because an answer does
    /// not move them; the direction is what §6.1 leaves of what this end wants
    /// once the offer has had its say.
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

    /// Whether an offer that arrived asks for nothing this layer would have to
    /// hand to the application.
    ///
    /// Hold, resume, and a peer moving its media address all keep the streams,
    /// the formats, the transport profile and the keying that were negotiated.
    /// A codec change, a stream added or one taken away do not, and those need
    /// a device this layer does not have.
    ///
    /// Neither does a transport profile that moved, or an `a=crypto` that
    /// appeared or disappeared. Those are a change to the security of a call
    /// in progress, and answering one here would settle it in a layer that
    /// has never read a crypto line and holds no policy: `RTP/AVP` where
    /// `RTP/SAVP` was agreed is the whole of a downgrade, and this is the only
    /// place that can tell it is happening. So it is handed up, and
    /// `crates/sipral` — which knows whether the account required encryption —
    /// decides. Keeping it: the `a=crypto` value, deliberately. A peer is
    /// entitled to re-key on a re-offer (RFC 4568 §7.1.4) and that reaches the
    /// media session through its own path; only presence is a change of shape.
    pub(crate) fn is_same_media(&self, offer: &SessionDescription) -> bool {
        let Some(previous) = self.remote.as_ref() else {
            return false;
        };
        previous.media.len() == offer.media.len()
            && previous
                .media
                .iter()
                .zip(&offer.media)
                .all(|(before, now)| {
                    before.media == now.media
                        && before.formats == now.formats
                        // folded the way `keying::is_secure` folds it, so that
                        // a peer writing `rtp/savp` is not pushed off the fast
                        // path for nothing; it still parts AVP from SAVP,
                        // which is the whole point
                        && before.proto.eq_ignore_ascii_case(&now.proto)
                        && before.attribute("crypto").is_some()
                            == now.attribute("crypto").is_some()
                })
    }

    /// The bytes of what each end last described.
    pub(crate) fn described(&self) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        (
            self.local.as_ref().map(SessionDescription::to_bytes),
            self.remote.as_ref().map(SessionDescription::to_bytes),
        )
    }

    /// The direction stream `index` gets from this end while `held`.
    fn wanted(&self, index: usize, held: bool) -> Direction {
        let base = self.base.get(index).copied().unwrap_or(Direction::SendRecv);
        if held { holding(base) } else { base }
    }

    /// What to do with one offered stream: keep it on this end's terms, or
    /// refuse it because there is nothing of ours to match it with.
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

/// What this end said about a stream last time and has to go on saying.
///
/// An answer is not a fresh description. Everything a previous negotiation
/// settled that the offer still asks for belongs in it, because an answer that
/// leaves it out is an answer that withdrew it — and a hold arriving from the
/// far end would then take multiplexing away from a call that had it, moving
/// RTCP to a port nothing is listening on, without either end saying anything.
/// RFC 5761 §5.1.1 makes `rtcp-mux` mutual, so it is repeated only where the
/// offer still carries it; `ptime` and `maxptime` are this end's own statement
/// about what it wants to receive and stand whatever the offer says.
///
/// **`crypto` is deliberately not here.** RFC 4568 §5.1.2 wants an answer to
/// name the tag it accepted and carry a key of this end's own, and §7.1.4
/// makes a re-offer an opportunity to re-key; neither is a line that can be
/// copied forward, and copying one would be answering a negotiation this layer
/// had not read. A secured call re-offered to a user agent writing its own
/// answers is the gap `docs/05-media.md` names, and it is a gap rather than a
/// silence.
///
/// **ICE is here, and for exactly the reason the paragraph above gives about
/// multiplexing.** RFC 8839 §4.4 wants the username fragment, the password
/// and the candidates on every description of a session; an answer that left
/// them out is a peer reading that ICE has been withdrawn in the middle of a
/// call, which takes a checked path away from a call that had one and puts
/// the media back on whatever the signalling says — silently, and from a
/// layer that never read a candidate. Copying them forward is safe in a way
/// copying a key is not: they are this end's own published values, unchanged
/// for the life of the session unless a restart changes both at once, and a
/// restart is a new offer rather than an answer. `ice-ufrag` and `ice-pwd`
/// are this end's whatever the offer says; `candidate` and `ice-options` go
/// with them, and there is more than one candidate line, so they are taken by
/// name rather than one to a name.
fn carried(ours: &MediaDescription, offered: &MediaDescription) -> Vec<Attribute> {
    let mutual = ["rtcp-mux"]
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

/// §8.4: "If the stream to be placed on hold was previously a sendrecv media
/// stream, it is placed on hold by marking it as sendonly. If the stream to be
/// placed on hold was previously a recvonly media stream, it is placed on hold
/// by marking it inactive."
const fn holding(base: Direction) -> Direction {
    match base {
        Direction::SendRecv | Direction::SendOnly => Direction::SendOnly,
        Direction::RecvOnly | Direction::Inactive => Direction::Inactive,
    }
}

/// Whether a description the far end wrote refuses what this end sends.
///
/// `sendonly` and `inactive` both say the writer will not receive, which is
/// what putting somebody on hold means. So does an address of `0.0.0.0`:
/// RFC 2543 held calls that way, §8.4 no longer recommends it, and "an agent
/// MUST be capable of receiving SDP with a connection address of 0.0.0.0".
///
/// Every live stream has to say it, because that is §8.4's own definition —
/// "an SDP with all streams on hold is referred to as held SDP" — and one
/// flag for the call cannot mean anything else. A call with two streams held
/// separately needs a flag per stream, and there will be two streams when
/// there is video, which is phase 2.
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

/// Write one direction on a stream, replacing whatever it said before.
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

    /// The same, with the transport profile named rather than assumed.
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

    /// What an answer this layer writes itself carries forward from what
    /// this end said last time, given an offer that still asks for it.
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

    /// RFC 8839 §4.4: the attributes go on every description of the session.
    ///
    /// The user agent answers a hold, a resume and a peer moving its address
    /// without handing the description up, so if this did not carry ICE
    /// forward the peer would read an answer with no credentials in it as ICE
    /// being withdrawn part-way through a call — taking a checked path away
    /// from a call that had one, silently, from a layer that has never read a
    /// candidate.
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
        // both of them, and a helper that took one attribute per name would
        // have kept only the first
        assert_eq!(
            answer
                .attributes
                .iter()
                .filter(|attribute| attribute.name == "candidate")
                .count(),
            2
        );
    }

    /// And the other half: a call that never used ICE does not grow any of it
    /// because the far end re-offered.
    #[test]
    fn an_answer_does_not_invent_ice_a_call_never_had() {
        let answer = answered(Vec::new(), Vec::new());
        assert!(answer.attribute("ice-ufrag").is_none());
        assert!(answer.attribute("ice-pwd").is_none());
        assert!(answer.attribute("candidate").is_none());
    }

    /// Only a session that has heard from the far end can compare anything.
    fn negotiated(remote: SessionDescription) -> Session {
        let mut session = Session::default();
        session.set_remote(remote);
        session
    }

    /// A downgrade keeps every format the first negotiation settled and
    /// changes the profile. It is not "the same media", and this layer holds
    /// no policy with which to answer it, so it has to go up.
    ///
    /// The `a=crypto` line is deliberately left on the offer. Without it the
    /// keying check below would catch this one too, and then nothing here
    /// would be testing the profile at all — which is what the first version
    /// of this test did.
    #[test]
    fn a_re_offer_that_takes_the_transport_profile_down_is_not_the_same_media() {
        let session = negotiated(secured(40_000, "RTP/SAVP", crypto()));
        assert!(!session.is_same_media(&secured(40_000, "RTP/AVP", crypto())));
    }

    /// The half a profile check alone would miss: `RTP/SAVP` with the key
    /// taken out. RFC 4568 §5.1.2 requires the attribute on a secure profile,
    /// so this is not a stream anyone can open — and answering it here would
    /// settle that in a layer that never read a crypto line.
    #[test]
    fn a_re_offer_that_keeps_the_profile_and_drops_the_key_is_not_the_same_media() {
        let session = negotiated(secured(40_000, "RTP/SAVP", crypto()));
        assert!(!session.is_same_media(&secured(40_000, "RTP/SAVP", Vec::new())));
    }

    /// And the one the rule must not catch. RFC 4568 §7.1.4 makes a re-offer
    /// an opportunity to re-key; the key that arrives is a different key, and
    /// a comparison on the value rather than the presence would push every
    /// ordinary re-key off the fast path and up to an application that has
    /// nothing to decide about it.
    #[test]
    fn a_peer_that_re_keys_on_a_re_offer_is_still_the_same_media() {
        let session = negotiated(secured(40_000, "RTP/SAVP", crypto()));
        let fresh = vec![Attribute::with_value(
            "crypto",
            "1 AES_CM_128_HMAC_SHA1_80 inline:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        )];
        assert!(session.is_same_media(&secured(40_000, "RTP/SAVP", fresh)));
    }

    /// A peer that writes the profile in lower case has not changed it.
    #[test]
    fn the_transport_profile_is_compared_without_regard_to_case() {
        let session = negotiated(secured(40_000, "RTP/SAVP", crypto()));
        assert!(session.is_same_media(&secured(40_000, "rtp/savp", crypto())));
    }

    /// The far end putting a call on hold re-offers the session it already
    /// negotiated. An answer that dropped what the first one settled would be
    /// this end withdrawing it, and for multiplexing that means RTCP moving
    /// back to a port nobody is listening on, silently.
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

    /// And it is mutual, so an offer that stopped asking for it gets an answer
    /// that stops promising it (RFC 5761 §5.1.1).
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

    /// `ptime` is this end's own statement about what it wants to receive, so
    /// it stands whether or not the offer repeated it.
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

    /// A key is not copied forward. §5.1.2 wants an answer to name the tag it
    /// accepted and carry a key of this end's own, and a layer that has never
    /// read a crypto line cannot do either — so it says nothing rather than
    /// repeating a line it did not negotiate.
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
