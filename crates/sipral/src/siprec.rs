// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Recording a call to a recording server (SIPREC, RFC 7866): the recording
//! session's offer and metadata, and the copies of a call's audio that go to
//! it.
//!
//! [`crate::MediaEngine::record_to`] places a recording session for a call
//! whose audio is running: a call of its own, to the recording server (the
//! SRS), whose INVITE carries `Require: siprec`, `+sip.src` and, beside its
//! offer, RFC 7865 metadata naming the call and its two parties
//! (`sipral_ua::siprec`). The offer has two sendonly streams (RFC 7866
//! §7.1.1), one per party, labelled `1` for this end and `2` for the far end,
//! each on a socket of its own and on the codec the call is using.
//!
//! **The audio is copied, not re-encoded.** Once the server has answered, the
//! recorded call's session sends every packet it puts on the wire again to the
//! first stream, and every packet it takes from the far end again to the
//! second (RFC 7866 §8.2.1.1, the SRC as a forwarding translator): the same
//! payload, the same payload type, the same timing, under a source and a
//! numbering of each stream's own. What the application sends from which
//! socket comes out of [`crate::MediaSession::poll_recording`]. A stream the
//! server refused (a port of zero) gets nothing.
//!
//! **The recording follows the call.** A hold changes which parties send, and
//! the server is told in fresh metadata (RFC 7866 §7.1.1.1: "Media stream
//! direction changes in the CS are conveyed in the metadata by the SRC"); a
//! call that replaces the recorded one ([`sipral_ua::UaEvent::CallReplaced`],
//! RFC 3891) takes the recording over, with the new far end as the second
//! party. When the recorded call ends the recording session is hung up, and
//! when the server hangs up the copies stop.
//!
//! **An encrypted call is recorded encrypted** (RFC 7866 §12.2). Its two
//! streams are offered as `RTP/SAVP` with SDES keys of their own (RFC 4568),
//! different from the call's, and each copy goes out under this end's key
//! for the line the server took; a stream the server will not take as SRTP
//! gets nothing, unless the account allows its encrypted calls to be recorded
//! in the clear ([`crate::AccountSrtp::recording_in_clear`]). Copies that move
//! — to a call that replaced the recorded one, or to a stream the server took
//! back — carry their numbering on, so no SRTP index goes out twice under one
//! key.

use std::collections::VecDeque;
use std::net::SocketAddr;

use sipral_core::endpoint::TransportId;
use sipral_core::msg::{OwnedMessage, Uri};
use sipral_core::sdp::{
    Attribute, Connection, Crypto, CryptoPolicy, CryptoSuite, Direction, KeySalt, MediaDescription,
    NegotiatedCodec, Origin, SessionDescription,
};
use sipral_rtp::srtp::Protector;
use sipral_rtp::{PacketBuilder, RtpHeader, RtpPacket};

use crate::keying;
use sipral_ua::siprec::{RecordedCall, RecordedParty, RecordedStream, RecordingMetadata};

/// The label of the stream that carries this end's audio.
pub(crate) const THIS_END: &str = "1";
/// The label of the stream that carries the far end's audio.
pub(crate) const FAR_END: &str = "2";

/// The most copies waiting to be sent before the oldest are dropped: a
/// second of both directions at twenty milliseconds a frame.
const QUEUE: usize = 100;

/// Where to record a call, and from where.
#[derive(Clone, Debug)]
pub struct RecordTo {
    /// The recording server's URI: the INVITE's target.
    pub server: Uri,
    /// Where to send the INVITE, when not where the call's account sends.
    pub destination: Option<(TransportId, SocketAddr)>,
    /// The socket the copy of this end's audio is sent from, and the address
    /// the offer names for the stream labelled `1`.
    pub this_end: SocketAddr,
    /// The same for the far end's audio, labelled `2`.
    pub far_end: SocketAddr,
}

impl RecordTo {
    /// Record to `server`, sending this end's audio from `this_end` and the
    /// far end's from `far_end`, two sockets the application bound.
    #[must_use]
    pub const fn new(server: Uri, this_end: SocketAddr, far_end: SocketAddr) -> Self {
        Self {
            server,
            destination: None,
            this_end,
            far_end,
        }
    }

    /// Send the INVITE somewhere other than where the call's account sends.
    #[must_use]
    pub const fn to_address(mut self, transport: TransportId, remote: SocketAddr) -> Self {
        self.destination = Some((transport, remote));
        self
    }
}

/// One copy of a call's audio on its way to a recording server.
#[derive(Clone, Copy, Debug)]
pub struct RecordingDatagram<'a> {
    /// The socket to send it from: [`RecordTo::this_end`] for this end's
    /// audio, [`RecordTo::far_end`] for the far end's.
    pub from: SocketAddr,
    /// Where the recording server receives that stream.
    pub destination: SocketAddr,
    /// Whether it is a copy of the far end's audio, the stream labelled `2`,
    /// rather than this end's: which of the two sockets `from` is, for a
    /// caller that keeps them by role.
    pub far_end: bool,
    /// The RTP packet.
    pub payload: &'a [u8],
}

/// The SDES keys a recording session's two streams are offered with, this
/// end's stream first: one per suite, in the order they are offered.
pub(crate) type StreamKeys = [Vec<(CryptoSuite, KeySalt)>; 2];

/// The offer of a recording session: two sendonly streams on `codec`, one per
/// party, labelled for the metadata (RFC 7866 §7.1.1). With `keys`, each
/// stream is offered as SRTP (`RTP/SAVP`) with an RFC 4568 line per key.
pub(crate) fn offer(
    codec: &NegotiatedCodec,
    to: &RecordTo,
    session_id: u64,
    keys: Option<&StreamKeys>,
) -> SessionDescription {
    let mut description = SessionDescription::new(
        Origin::new(session_id, 1, to.this_end.ip()),
        Connection::new(to.this_end.ip()),
    );
    for (index, (socket, label)) in [(to.this_end, THIS_END), (to.far_end, FAR_END)]
        .into_iter()
        .enumerate()
    {
        let proto = if keys.is_some() {
            "RTP/SAVP"
        } else {
            "RTP/AVP"
        };
        let mut stream = MediaDescription::new(
            "audio",
            socket.port(),
            proto,
            vec![codec.payload().to_string()],
        );
        if socket.ip() != to.this_end.ip() {
            stream.connection = Some(Connection::new(socket.ip()));
        }
        stream
            .attributes
            .push(Attribute::with_value("rtpmap", &codec.rtpmap.to_value()));
        if let Some(fmtp) = &codec.fmtp {
            stream.attributes.push(Attribute::with_value(
                "fmtp",
                &format!("{} {fmtp}", codec.payload()),
            ));
        }
        stream
            .attributes
            .push(Attribute::flag(Direction::SendOnly.as_str()));
        stream
            .attributes
            .push(Attribute::with_value("label", label));
        if let Some(offered) = keys.and_then(|keys| keys.get(index)) {
            stream.attributes.extend(
                keying::offer_lines(offered.clone())
                    .iter()
                    .map(Crypto::attribute),
            );
        }
        description.media.push(stream);
    }
    description
}

/// What protects each stream's copies, read off the server's answer to an
/// offer of `offered`: the transform and this end's key under the line the
/// server took (RFC 4568 §5.1.2), with the tag of that line. `None` for a
/// stream the server refused, answered off SRTP, or answered with a line
/// this end did not offer or cannot be held to.
pub(crate) fn protection(
    answer: &SessionDescription,
    offered: &StreamKeys,
) -> [Option<(u32, Protector)>; 2] {
    let one = |index: usize| {
        let stream = answer.media.get(index)?;
        if stream.is_rejected() || !keying::is_secure(&stream.proto) {
            return None;
        }
        let keys = offered.get(index)?;
        stream
            .attributes
            .iter()
            .filter(|attribute| attribute.name == "crypto")
            .filter_map(|attribute| Crypto::parse(attribute.value.as_deref()?))
            .find_map(|line| {
                let (suite, key) = keys.get(usize::try_from(line.tag).ok()?.checked_sub(1)?)?;
                let answered = line.policy()?;
                if answered.suite != *suite || !keying::peer_line_holds(stream, line.tag) {
                    return None;
                }
                let ours = CryptoPolicy::new(line.tag, *suite, key.clone());
                let (policy, master) = keying::context(&ours).ok()?;
                Some((line.tag, Protector::new(policy, master)))
            })
    };
    [one(0), one(1)]
}

/// Where the recording server receives each of the two streams, read off its
/// answer: `None` for a stream it refused, or one it named no address for.
pub(crate) fn destinations(answer: &SessionDescription) -> [Option<SocketAddr>; 2] {
    let at = |index: usize| {
        let stream = answer.media.get(index)?;
        if stream.is_rejected() {
            return None;
        }
        let ip = answer.connection_of(stream)?.ip()?;
        Some(SocketAddr::new(ip, stream.port))
    };
    [at(0), at(1)]
}

/// The session description a recording server's response carried: the body
/// itself, or its `application/sdp` part when it answered in multipart.
pub(crate) fn answer_in(message: &OwnedMessage) -> Option<SessionDescription> {
    let raw = message.as_raw();
    let kind = raw.content_type().ok()?;
    if kind.is("application", "sdp") {
        return sipral_core::sdp::parse(raw.body()).ok();
    }
    let body = sipral_core::msg::Multipart::parse(&kind, raw.body()).ok()?;
    let part = body.find("application", "sdp")?;
    sipral_core::sdp::parse(part.body()).ok()
}

/// The two parties of a recorded call as the metadata names them: identifiers
/// drawn once, addresses of record, display names.
#[derive(Clone, Debug)]
pub(crate) struct Parties {
    pub(crate) call: RecordedCall,
}

/// Which of the two parties is sending, as the recorded call's direction
/// says: `(this end, far end)`.
pub(crate) const fn sending(direction: Direction) -> (bool, bool) {
    match direction {
        Direction::SendRecv => (true, true),
        Direction::SendOnly => (true, false),
        Direction::RecvOnly => (false, true),
        Direction::Inactive => (false, false),
    }
}

impl Parties {
    /// The metadata of the call as it stands: complete, with a party that is
    /// not sending listed as sending nothing and nobody receiving from it.
    pub(crate) fn metadata(&self, direction: Direction) -> RecordingMetadata {
        let mut metadata = self.call.metadata();
        let (ours, theirs) = sending(direction);
        let quiet: Vec<String> = self
            .call
            .parties
            .iter()
            .zip([ours, theirs])
            .filter(|(_, sends)| !sends)
            .flat_map(|(party, _)| party.sends.iter().map(|stream| stream.id.clone()))
            .collect();
        for association in &mut metadata.participant_streams {
            association.send.retain(|stream| !quiet.contains(stream));
            association.recv.retain(|stream| !quiet.contains(stream));
        }
        metadata
    }

    /// A new far end: the party the call now talks to, under a new
    /// identifier, as a call that replaced the recorded one has.
    pub(crate) fn replace_far_end(&mut self, id: String, aor: String, name: Option<String>) {
        if let Some(far) = self.call.parties.get_mut(1) {
            far.id = id;
            far.aor = aor;
            far.name = name;
        }
    }
}

/// A metadata identifier (RFC 7865 §7: a UUID in base64) drawn from the user
/// agent's own token stream, which is what every tag and branch it writes is
/// drawn from too.
pub(crate) fn draw_id(agent: &mut sipral_ua::UserAgent) -> String {
    let token = agent.endpoint().token();
    let mut uuid = [0_u8; 16];
    let digits = token
        .iter()
        .filter_map(|byte| char::from(*byte).to_digit(16))
        .filter_map(|digit| u8::try_from(digit).ok());
    for (index, digit) in digits.take(32).enumerate() {
        if let Some(byte) = uuid.get_mut(index / 2) {
            *byte = (*byte << 4) | digit;
        }
    }
    sipral_ua::siprec::metadata_id(uuid)
}

/// One end of a call as the metadata names it: an address of record, and a
/// display name when one is known.
pub(crate) type End = (String, Option<String>);

/// The two parties of a call, with this end first.
pub(crate) fn parties(
    session_id: String,
    ids: [String; 4],
    (this_end, far_end): (End, End),
) -> Parties {
    let [this_party, far_party, this_stream, far_stream] = ids;
    Parties {
        call: RecordedCall {
            session_id,
            sip_session_id: None,
            group_id: None,
            started: None,
            parties: vec![
                RecordedParty {
                    id: this_party,
                    aor: this_end.0,
                    name: this_end.1,
                    sends: vec![RecordedStream {
                        id: this_stream,
                        label: THIS_END.to_owned(),
                    }],
                },
                RecordedParty {
                    id: far_party,
                    aor: far_end.0,
                    name: far_end.1,
                    sends: vec![RecordedStream {
                        id: far_stream,
                        label: FAR_END.to_owned(),
                    }],
                },
            ],
        },
    }
}

/// One of the two copies: where it goes and how it is numbered.
#[derive(Clone, Copy, Debug)]
struct Copy {
    from: SocketAddr,
    destination: SocketAddr,
    ssrc: u32,
    /// Added to the original's sequence number and timestamp, fixed by the
    /// first packet copied, so that loss, reordering and pauses in the
    /// original stay where they were.
    sequence: Option<u16>,
    timestamp: Option<u32>,
    base: (u16, u32),
}

impl Copy {
    /// The copy of a packet with `header` and `payload`, carrying
    /// `payload_type`: the number the server was offered the codec under.
    /// With it, the sequence number and timestamp it went out with.
    fn packet(
        &mut self,
        header: RtpHeader,
        payload: &[u8],
        payload_type: u8,
    ) -> Option<(Vec<u8>, (u16, u32))> {
        let sequence = *self
            .sequence
            .get_or_insert(self.base.0.wrapping_sub(header.sequence));
        let timestamp = *self
            .timestamp
            .get_or_insert(self.base.1.wrapping_sub(header.timestamp));
        let header = RtpHeader {
            marker: header.marker,
            payload_type,
            sequence: header.sequence.wrapping_add(sequence),
            timestamp: header.timestamp.wrapping_add(timestamp),
            ssrc: self.ssrc,
        };
        let builder = PacketBuilder::new(header, payload);
        let mut out = vec![0; builder.encoded_len()];
        let written = builder.write(&mut out).ok()?;
        out.truncate(written);
        Some((out, (header.sequence, header.timestamp)))
    }

    /// Carry on from `next` with whatever audio comes next, rather than with
    /// the numbering the audio copied so far fixed.
    const fn resume(&mut self, next: (u16, u32)) {
        self.sequence = None;
        self.timestamp = None;
        self.base = next;
    }
}

/// How the copies are protected: whether they have to be, every protector each
/// stream has had with the tag of the line it keys, and which line keys it
/// now.
///
/// A protector is kept for the life of the recording, not for as long as its
/// line is the one in use. The keys are drawn once per recording and a line's
/// tag names the same key for as long as the recording runs, so a server
/// that moves a stream to another line and back is keying it again with a
/// key that has already protected packets: a protector built afresh for it
/// would start its rollover counter at zero, and once the sequence numbers
/// had wrapped it would send an index the key had already covered — the one
/// thing SRTP must never do (RFC 3711 §9.1). The kept protector carries its
/// counter on.
#[derive(Default)]
struct Protection {
    required: bool,
    kept: [Vec<(u32, Protector)>; 2],
    active: [Option<u32>; 2],
}

impl Protection {
    /// The protector of the line keying `stream` now.
    fn of(&mut self, stream: usize) -> Option<&mut Protector> {
        let tag = (*self.active.get(stream)?)?;
        self.kept
            .get_mut(stream)?
            .iter_mut()
            .find(|(kept, _)| *kept == tag)
            .map(|(_, protector)| protector)
    }
}

impl std::fmt::Debug for Protection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Protection")
            .field("required", &self.required)
            .field("tags", &self.active)
            .finish_non_exhaustive()
    }
}

/// What a recorded call's session copies to the recording server.
#[derive(Debug)]
pub(crate) struct Tap {
    /// This end's audio, then the far end's.
    copies: [Option<Copy>; 2],
    /// The payload type copied: the call's codec, under the number the
    /// server was offered it with, which is the one this end sends it with.
    /// Named events and comfort noise are not offered to the server, so they
    /// are not sent to it.
    payload_type: u8,
    /// The number the far end sends the codec with: this end's own for it,
    /// which differs from `payload_type` where an answer renumbered it (RFC
    /// 3264 §6.1). The far end's copies are sent under `payload_type`.
    received_payload_type: u8,
    /// The sockets the copies go from, this end's first.
    sockets: [SocketAddr; 2],
    /// What each stream's copies are protected with, when the recording
    /// session is SRTP, and under which of the offered lines.
    protection: Protection,
    /// The source, sequence number and timestamp each stream starts from.
    numbers: [(u32, u16, u32); 2],
    /// The sequence number and timestamp each stream carries on from once
    /// anything was copied on it: a stream the server took back, or one
    /// that moved to a call that replaced the recorded one, starts there
    /// rather than over — which on an SRTP recording session would send a
    /// second packet under an index the key has already covered (RFC 3711
    /// §9.1).
    next: [Option<(u16, u32)>; 2],
    queue: VecDeque<(usize, SocketAddr, SocketAddr, Vec<u8>)>,
    out: Vec<u8>,
}

impl Tap {
    /// Copies of the codec to the two destinations the server answered
    /// with, sent from the two sockets `to` names, numbered from `numbers`
    /// (a source, a sequence number and a timestamp per stream).
    /// `payload_types` is the number this end sends the codec with, which the
    /// server was offered, then the one the far end sends it with.
    pub(crate) fn new(
        to: &RecordTo,
        destinations: [Option<SocketAddr>; 2],
        payload_types: (u8, u8),
        numbers: [(u32, u16, u32); 2],
    ) -> Self {
        let mut tap = Self {
            copies: [None, None],
            payload_type: payload_types.0,
            received_payload_type: payload_types.1,
            sockets: [to.this_end, to.far_end],
            protection: Protection::default(),
            numbers,
            next: [None, None],
            queue: VecDeque::new(),
            out: Vec::new(),
        };
        tap.redirect(destinations);
        tap
    }

    /// The server answered again: a stream may have moved, been refused, or
    /// been taken back. One that carries on keeps its numbering.
    pub(crate) fn redirect(&mut self, destinations: [Option<SocketAddr>; 2]) {
        for (stream, destination) in destinations.into_iter().enumerate() {
            let (Some(slot), Some(&from), Some(&(ssrc, sequence, timestamp)), Some(next)) = (
                self.copies.get_mut(stream),
                self.sockets.get(stream),
                self.numbers.get(stream),
                self.next.get(stream),
            ) else {
                continue;
            };
            match (slot.as_mut(), destination) {
                (Some(copy), Some(destination)) => copy.destination = destination,
                (_, None) => *slot = None,
                (None, Some(destination)) => {
                    *slot = Some(Copy {
                        from,
                        destination,
                        ssrc,
                        sequence: None,
                        timestamp: None,
                        base: next.unwrap_or((sequence, timestamp)),
                    });
                }
            }
        }
    }

    /// Copy another session's audio from here on — a call that replaced the
    /// recorded one — carrying each stream on from where its copies got to.
    pub(crate) fn follow(&mut self) {
        for (copy, next) in self.copies.iter_mut().zip(self.next) {
            if let (Some(copy), Some(next)) = (copy.as_mut(), next) {
                copy.resume(next);
            }
        }
    }

    /// Protect the copies as the server's answer said ([`protection`]), for
    /// a recording session offered as SRTP: from here on a stream is copied
    /// only while it has a protector, and never in the clear. A stream keyed
    /// by a line that has keyed it before — the one it had, or one it had
    /// earlier and went back to — takes up the protector that line had, and
    /// with it its place in the keystream; the one `answered` built afresh
    /// is dropped.
    pub(crate) fn protect(&mut self, answered: [Option<(u32, Protector)>; 2]) {
        self.protection.required = true;
        for ((kept, active), answered) in self
            .protection
            .kept
            .iter_mut()
            .zip(self.protection.active.iter_mut())
            .zip(answered)
        {
            *active = answered.map(|(tag, fresh)| {
                if !kept.iter().any(|(known, _)| *known == tag) {
                    kept.push((tag, fresh));
                }
                tag
            });
        }
    }

    /// The recorded call moved to the codec this end sends on
    /// `payload_types.0` and takes on `payload_types.1`, and the server was
    /// offered it under the first: copy that from here on.
    pub(crate) const fn copy_payload_type(&mut self, payload_types: (u8, u8)) {
        self.payload_type = payload_types.0;
        self.received_payload_type = payload_types.1;
    }

    /// This end sent `wire`, whose payload before protection was `payload`.
    /// The header is read off what went out, which SRTP leaves in the clear.
    pub(crate) fn sent(&mut self, wire: &[u8], payload: &[u8]) {
        let Ok(packet) = RtpPacket::parse(wire) else {
            return;
        };
        self.copy(0, packet.header(), payload);
    }

    /// This end took `plain` from the far end, already verified and
    /// decrypted.
    pub(crate) fn received(&mut self, plain: &[u8]) {
        let Ok(packet) = RtpPacket::parse(plain) else {
            return;
        };
        self.copy(1, packet.header(), packet.payload());
    }

    fn copy(&mut self, stream: usize, header: RtpHeader, payload: &[u8]) {
        let expected = if stream == 0 {
            self.payload_type
        } else {
            self.received_payload_type
        };
        if header.payload_type != expected {
            return;
        }
        let Some(copy) = self.copies.get_mut(stream).and_then(Option::as_mut) else {
            return;
        };
        let Some((mut packet, (sequence, timestamp))) =
            copy.packet(header, payload, self.payload_type)
        else {
            return;
        };
        if self.protection.required {
            let Some(protector) = self.protection.of(stream) else {
                return;
            };
            let length = packet.len();
            packet.resize(length + protector.rtp_overhead(), 0);
            let Ok(written) = protector.protect_rtp(&mut packet, length) else {
                return;
            };
            packet.truncate(written);
        }
        // a packet the original stream reordered moves nothing back
        if let Some(next) = self.next.get_mut(stream)
            && next.is_none_or(|(after, _)| sequence.wrapping_sub(after) < 0x8000)
        {
            *next = Some((sequence.wrapping_add(1), timestamp.wrapping_add(1)));
        }
        let (from, destination) = (copy.from, copy.destination);
        // the oldest goes first: a copy nobody collected for a second is
        // audio the server would play late, and the newest is what it wants
        if self.queue.len() >= QUEUE {
            self.queue.pop_front();
        }
        self.queue.push_back((stream, from, destination, packet));
    }

    /// The next copy to send.
    pub(crate) fn poll(&mut self) -> Option<RecordingDatagram<'_>> {
        let (stream, from, destination, packet) = self.queue.pop_front()?;
        self.out = packet;
        Some(RecordingDatagram {
            from,
            destination,
            far_end: stream == 1,
            payload: &self.out,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{RecordTo, Tap};
    use sipral_core::msg::Uri;
    use sipral_rtp::{PacketBuilder, RtpHeader, RtpPacket};
    use std::net::SocketAddr;

    fn address(text: &str) -> SocketAddr {
        text.parse().expect("an address")
    }

    fn packet(payload_type: u8, sequence: u16) -> Vec<u8> {
        let header = RtpHeader {
            marker: false,
            payload_type,
            sequence,
            timestamp: u32::from(sequence) * 320,
            ssrc: 0x0102_0304,
        };
        let builder = PacketBuilder::new(header, &[7; 40]);
        let mut out = vec![0; builder.encoded_len()];
        let written = builder.write(&mut out).expect("room");
        out.truncate(written);
        out
    }

    fn record_to() -> RecordTo {
        RecordTo::new(
            Uri::parse_str("sip:srs@example.com").expect("a URI"),
            address("192.0.2.1:42000"),
            address("192.0.2.1:42002"),
        )
    }

    fn destinations() -> [Option<SocketAddr>; 2] {
        [
            Some(address("192.0.2.3:30000")),
            Some(address("192.0.2.3:30002")),
        ]
    }

    /// Every copy waiting: whether it is the far end's, and its payload
    /// type.
    fn drained(tap: &mut Tap) -> Vec<(bool, u8)> {
        let mut copied = Vec::new();
        while let Some(copy) = tap.poll() {
            let header = RtpPacket::parse(copy.payload).expect("RTP").header();
            copied.push((copy.far_end, header.payload_type));
        }
        copied
    }

    /// A call whose answer renumbered its codec (RFC 3264 §6.1) sends it on
    /// one number and takes it on another. Both parties' copies are the
    /// codec, and both go to the server under the number it was offered.
    #[test]
    fn the_far_ends_audio_on_this_ends_own_number_is_copied_under_the_offered_one() {
        let mut tap = Tap::new(
            &record_to(),
            destinations(),
            (99, 97),
            [(1, 10, 100), (2, 20, 200)],
        );
        tap.sent(&packet(99, 1), &[7; 40]);
        tap.received(&packet(97, 1));
        assert_eq!(drained(&mut tap), [(false, 99), (true, 99)]);
        // the send number arriving from the far end is not this call's codec
        tap.received(&packet(99, 2));
        assert_eq!(drained(&mut tap), []);
    }

    /// The sequence numbers of this end's copies, as they went.
    fn sequences(tap: &mut Tap) -> Vec<u16> {
        let mut sent = Vec::new();
        while let Some(copy) = tap.poll() {
            sent.push(
                RtpPacket::parse(copy.payload)
                    .expect("RTP")
                    .header()
                    .sequence,
            );
        }
        sent
    }

    /// Under one SRTP key a sequence number goes out once (RFC 3711 §9.1):
    /// copies that move to a call that replaced the recorded one, or to a
    /// stream the server took back, carry on from where they got to rather
    /// than starting their numbering over.
    #[test]
    fn copies_that_move_carry_their_numbering_on_under_the_same_key() {
        use sipral_rtp::srtp::{Master, Policy, Protector, Suite};
        let mut tap = Tap::new(
            &record_to(),
            destinations(),
            (0, 0),
            [(1, 10, 100), (2, 20, 200)],
        );
        let key = || Protector::new(Policy::new(Suite::AesCm80), Master::new(&[1; 16], &[2; 14]));
        tap.protect([Some((2, key())), Some((2, key()))]);
        for sequence in [1_000, 1_001] {
            tap.sent(&packet(0, sequence), &[7; 40]);
        }
        assert_eq!(sequences(&mut tap), [10, 11]);

        // the call that replaced the recorded one numbers its own packets
        tap.follow();
        tap.sent(&packet(0, 5_000), &[7; 40]);
        assert_eq!(sequences(&mut tap), [12]);

        // refused, then taken back
        tap.redirect([None, None]);
        tap.sent(&packet(0, 5_001), &[7; 40]);
        assert_eq!(sequences(&mut tap), []);
        tap.redirect(destinations());
        tap.sent(&packet(0, 9_000), &[7; 40]);
        assert_eq!(sequences(&mut tap), [13]);

        // and a stream the server's answer left without a key gets nothing
        tap.protect([None, Some((2, key()))]);
        tap.sent(&packet(0, 9_001), &[7; 40]);
        assert_eq!(sequences(&mut tap), []);
    }

    /// A server that moves a stream to another line and back keys it again
    /// with a key that has protected packets before, and past a wrap of the
    /// sequence numbers a protector built afresh for it would send indices
    /// that key already covered (RFC 3711 §9.1). Every copy here carries the
    /// same payload, so an index protected twice under one key would show as
    /// the same ciphertext twice.
    #[test]
    fn a_stream_moved_to_another_line_and_back_never_protects_an_index_twice_under_one_key() {
        use sipral_rtp::srtp::{Master, Policy, Protector, Suite};
        use std::collections::HashSet;

        let key = |tag: u8| {
            Protector::new(
                Policy::new(Suite::AesCm80),
                Master::new(&[tag; 16], &[tag; 14]),
            )
        };
        let mut tap = Tap::new(&record_to(), destinations(), (0, 0), [(1, 0, 0), (2, 0, 0)]);
        let mut seen = HashSet::new();
        let mut copied = 0_u32;
        let mut sequence = 0_u16;
        let mut send = |tap: &mut Tap, count: u32| {
            for _ in 0..count {
                tap.sent(&packet(0, sequence), &[7; 40]);
                sequence = sequence.wrapping_add(1);
                while let Some(copy) = tap.poll() {
                    // the forty bytes of ciphertext, without the tag after
                    let payload = RtpPacket::parse(copy.payload)
                        .expect("RTP")
                        .payload()
                        .get(..40)
                        .expect("the payload, encrypted")
                        .to_vec();
                    assert!(
                        seen.insert(payload),
                        "copy {copied} went under an index its key had already covered"
                    );
                    copied += 1;
                }
            }
        };

        // under line 1 past a wrap of the sequence numbers
        tap.protect([Some((1, key(1))), None]);
        send(&mut tap, 65_536 + 10);
        // the server moves the stream to line 2, and then back to line 1
        tap.protect([Some((2, key(2))), None]);
        send(&mut tap, 5);
        tap.protect([Some((1, key(1))), None]);
        send(&mut tap, 20);
        assert_eq!(copied, 65_536 + 35, "every packet was copied");
    }
}
