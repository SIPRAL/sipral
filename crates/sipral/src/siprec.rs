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

use std::collections::VecDeque;
use std::net::SocketAddr;

use sipral_core::endpoint::TransportId;
use sipral_core::msg::{OwnedMessage, Uri};
use sipral_core::sdp::{
    Attribute, Connection, Direction, MediaDescription, NegotiatedCodec, Origin, SessionDescription,
};
use sipral_rtp::{PacketBuilder, RtpHeader, RtpPacket};
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

/// The offer of a recording session: two sendonly streams on `codec`, one per
/// party, labelled for the metadata (RFC 7866 §7.1.1).
pub(crate) fn offer(codec: &NegotiatedCodec, to: &RecordTo, session_id: u64) -> SessionDescription {
    let mut description = SessionDescription::new(
        Origin::new(session_id, 1, to.this_end.ip()),
        Connection::new(to.this_end.ip()),
    );
    for (socket, label) in [(to.this_end, THIS_END), (to.far_end, FAR_END)] {
        let mut stream = MediaDescription::new(
            "audio",
            socket.port(),
            "RTP/AVP",
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
        description.media.push(stream);
    }
    description
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
    fn packet(&mut self, header: RtpHeader, payload: &[u8]) -> Option<Vec<u8>> {
        let sequence = *self
            .sequence
            .get_or_insert(self.base.0.wrapping_sub(header.sequence));
        let timestamp = *self
            .timestamp
            .get_or_insert(self.base.1.wrapping_sub(header.timestamp));
        let header = RtpHeader {
            marker: header.marker,
            payload_type: header.payload_type,
            sequence: header.sequence.wrapping_add(sequence),
            timestamp: header.timestamp.wrapping_add(timestamp),
            ssrc: self.ssrc,
        };
        let builder = PacketBuilder::new(header, payload);
        let mut out = vec![0; builder.encoded_len()];
        let written = builder.write(&mut out).ok()?;
        out.truncate(written);
        Some(out)
    }
}

/// What a recorded call's session copies to the recording server.
#[derive(Debug)]
pub(crate) struct Tap {
    /// This end's audio, then the far end's.
    copies: [Option<Copy>; 2],
    /// The payload type copied: the call's codec. Named events and comfort
    /// noise are not offered to the server, so they are not sent to it.
    payload_type: u8,
    /// The sockets the copies go from, this end's first.
    sockets: [SocketAddr; 2],
    /// The source, sequence number and timestamp each stream starts from.
    numbers: [(u32, u16, u32); 2],
    queue: VecDeque<(usize, SocketAddr, SocketAddr, Vec<u8>)>,
    out: Vec<u8>,
}

impl Tap {
    /// Copies of `payload_type` to the two destinations the server answered
    /// with, sent from the two sockets `to` names, numbered from `numbers`
    /// (a source, a sequence number and a timestamp per stream).
    pub(crate) fn new(
        to: &RecordTo,
        destinations: [Option<SocketAddr>; 2],
        payload_type: u8,
        numbers: [(u32, u16, u32); 2],
    ) -> Self {
        let mut tap = Self {
            copies: [None, None],
            payload_type,
            sockets: [to.this_end, to.far_end],
            numbers,
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
            let (Some(slot), Some(&from), Some(&(ssrc, sequence, timestamp))) = (
                self.copies.get_mut(stream),
                self.sockets.get(stream),
                self.numbers.get(stream),
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
                        base: (sequence, timestamp),
                    });
                }
            }
        }
    }

    /// The recorded call moved to the codec on `payload_type`, and the server
    /// was offered it: copy that from here on.
    pub(crate) const fn copy_payload_type(&mut self, payload_type: u8) {
        self.payload_type = payload_type;
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
        if header.payload_type != self.payload_type {
            return;
        }
        let Some(copy) = self.copies.get_mut(stream).and_then(Option::as_mut) else {
            return;
        };
        let Some(packet) = copy.packet(header, payload) else {
            return;
        };
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
