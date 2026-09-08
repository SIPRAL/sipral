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
    /// Hold, resume, and a peer moving its media address all keep the streams
    /// and the formats that were negotiated. A codec change, a stream added or
    /// one taken away do not, and those need a device this layer does not
    /// have.
    pub(crate) fn is_same_media(&self, offer: &SessionDescription) -> bool {
        let Some(previous) = self.remote.as_ref() else {
            return false;
        };
        previous.media.len() == offer.media.len()
            && previous
                .media
                .iter()
                .zip(&offer.media)
                .all(|(before, now)| before.media == now.media && before.formats == now.formats)
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
        let accepted = AcceptedStream::in_offer_order(ours.port, offered, &supported);
        if accepted.formats.is_empty() {
            return StreamAnswer::Reject;
        }
        StreamAnswer::Accept(accepted.with_direction(self.wanted(index, held)))
    }
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
