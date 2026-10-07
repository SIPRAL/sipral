// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Recording a call to a recording server (SIPREC, RFC 7866): the recording session's offer and
//! metadata, and the audio copies sent to it.
//!
//! [`crate::MediaEngine::record_to`] places a recording session for a call with running audio: a
//! separate call to the recording server (SRS), whose INVITE carries `Require: siprec`, `+sip.src`
//! and RFC 7865 metadata naming the call and its two parties (`sipral_ua::siprec`). The offer has
//! two sendonly streams (RFC 7866 §7.1.1), labelled `1` for this end and `2` for the far end, each
//! on its own socket and the call's codec.
//!
//! **Audio is copied, not re-encoded.** Once answered, every packet the call sends is resent to
//! stream 1 and every packet it receives to stream 2 (RFC 7866 §8.2.1.1, forwarding translator):
//! same payload, type and timing, with each stream's own source and numbering. The application
//! sends what [`crate::MediaSession::poll_recording`] returns. A refused stream (port zero) gets
//! nothing.
//!
//! **The recording follows the call.** A hold changes who sends, reported in new metadata (RFC 7866
//! §7.1.1.1). A call replacing the recorded one ([`sipral_ua::UaEvent::CallReplaced`], RFC 3891)
//! takes over the recording with its far end as party two. The recording session is hung up when
//! the call ends; copying stops when the server hangs up.
//!
//! **Encrypted calls are recorded encrypted** (RFC 7866 §12.2): both streams are offered as
//! `RTP/SAVP` with their own SDES keys (RFC 4568), and each copy goes out under our key for the
//! line the server took. A stream the server will not take as SRTP gets nothing, unless the account
//! allows clear recording ([`crate::AccountSrtp::recording_in_clear`]). Copies that move (to a
//! replacing call, or a stream taken back) keep their numbering, so no SRTP index is reused under
//! one key.

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

/// Most copies queued before the oldest are dropped: one second of both directions at 20 ms frames.
const QUEUE: usize = 100;

/// Where to record a call, and from where.
#[derive(Clone, Debug)]
pub struct RecordTo {
    /// The recording server's URI: the INVITE's target.
    pub server: Uri,
    /// Where to send the INVITE, when not where the call's account sends.
    pub destination: Option<(TransportId, SocketAddr)>,
    /// The socket this end's copy is sent from, and the address the offer names for stream `1`.
    pub this_end: SocketAddr,
    /// The same for the far end's audio, labelled `2`.
    pub far_end: SocketAddr,
}

impl RecordTo {
    /// Record to `server`, sending this end's audio from `this_end` and the far end's from
    /// `far_end`, two sockets the application bound.
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
    /// Whether this copies the far end's audio (stream `2`), i.e. which socket `from` is, for
    /// callers that keep sockets by role.
    pub far_end: bool,
    /// The RTP packet.
    pub payload: &'a [u8],
}

/// SDES keys offered for the two streams, this end's first: one per suite, in offer order.
pub(crate) type StreamKeys = [Vec<(CryptoSuite, KeySalt)>; 2];

/// A recording session offer: two sendonly streams on `codec`, labelled for the metadata (RFC 7866
/// §7.1.1). With `keys`, each is `RTP/SAVP` with one RFC 4568 line per key.
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

/// Each stream's copy protection, from the server's answer to `offered`: the transform and our key
/// under the line the server took (RFC 4568 §5.1.2), with its tag. `None` for a refused stream, one
/// answered without SRTP, or with a line we did not offer or cannot honour.
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

/// Where the server receives each stream, from its answer; `None` if refused or without an address.
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

/// The SDP in a recording server's response: the body, or its `application/sdp` part if multipart.
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

/// The recorded call's two parties as the metadata names them: identifiers drawn once, addresses of
/// record, display names.
#[derive(Clone, Debug)]
pub(crate) struct Parties {
    pub(crate) call: RecordedCall,
}

/// Which parties send, given the call's direction: `(this end, far end)`.
pub(crate) const fn sending(direction: Direction) -> (bool, bool) {
    match direction {
        Direction::SendRecv => (true, true),
        Direction::SendOnly => (true, false),
        Direction::RecvOnly => (false, true),
        Direction::Inactive => (false, false),
    }
}

impl Parties {
    /// The complete current metadata; a party not sending is listed as sending nothing.
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

    /// Replace the far end with a new party under a new identifier, as after a replacing call.
    pub(crate) fn replace_far_end(&mut self, id: String, aor: String, name: Option<String>) {
        if let Some(far) = self.call.parties.get_mut(1) {
            far.id = id;
            far.aor = aor;
            far.name = name;
        }
    }
}

/// A metadata identifier (RFC 7865 §7: a base64 UUID) from the user agent's token stream.
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

/// One end as the metadata names it: address of record and optional display name.
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
    /// Offset added to the original's sequence number and timestamp, fixed by the first copied
    /// packet, so loss, reordering and pauses keep their place.
    sequence: Option<u16>,
    timestamp: Option<u32>,
    base: (u16, u32),
    /// The source that fixed the numbering, on an SRTP recording session; another source renumbers.
    source: Option<u32>,
}

impl Copy {
    /// The copy of a packet with `header` and `payload` under `payload_type` (the number offered to
    /// the server), plus its sequence number and timestamp.
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

    /// Continue from `next` with whatever audio comes, dropping the previous numbering offset.
    const fn resume(&mut self, next: (u16, u32)) {
        self.sequence = None;
        self.timestamp = None;
        self.base = next;
        self.source = None;
    }
}

/// How copies are protected: whether they must be, every protector each stream has had with its
/// line tag, and which line keys it now.
///
/// Protectors live for the whole recording. Keys are drawn once and a tag always names the same
/// key, so a server that moves a stream to another line and back reuses a key; a fresh protector
/// would restart its rollover counter and, after a sequence wrap, repeat an index (RFC 3711 §9.1).
/// The kept one continues its counter.
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
    /// The copied payload type: the call's codec under the number offered to the server, which is
    /// the one this end sends with. Named events and comfort noise are not offered, so not sent.
    payload_type: u8,
    /// The number the far end sends the codec with (our own), which differs from `payload_type`
    /// when an answer renumbered it (RFC 3264 §6.1). Far-end copies go out under `payload_type`.
    received_payload_type: u8,
    /// The sockets the copies go from, this end's first.
    sockets: [SocketAddr; 2],
    /// Each stream's protection on an SRTP recording session, and which offered line keys it.
    protection: Protection,
    /// The source, sequence number and timestamp each stream starts from.
    numbers: [(u32, u16, u32); 2],
    /// Where each stream continues once something was copied: a stream taken back or moved to a
    /// replacing call starts there, not over, or SRTP would reuse an index (RFC 3711 §9.1).
    next: [Option<(u16, u32)>; 2],
    queue: VecDeque<(usize, SocketAddr, SocketAddr, Vec<u8>)>,
    out: Vec<u8>,
}

impl Tap {
    /// Copies to the server's two destinations, from the sockets in `to`, numbered from `numbers`
    /// (source, sequence, timestamp per stream). `payload_types` is the number we send the codec
    /// with (the one offered) then the far end's.
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

    /// The server answered again: streams may have moved, been refused or taken back. Continuing
    /// streams keep their numbering.
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
                        source: None,
                    });
                }
            }
        }
    }

    /// Copy a replacing call's audio from now on, each stream continuing its numbering.
    pub(crate) fn follow(&mut self) {
        for (copy, next) in self.copies.iter_mut().zip(self.next) {
            if let (Some(copy), Some(next)) = (copy.as_mut(), next) {
                copy.resume(next);
            }
        }
    }

    /// Apply the server's answer ([`protection`]) on an SRTP recording session: a stream is copied
    /// only while it has a protector, never in the clear. A line that keyed the stream before gets
    /// its old protector back, keystream position included; the fresh one in `answered` is dropped.
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

    /// The call moved to a codec we send on `payload_types.0` and receive on `payload_types.1`; the
    /// server was offered the first. Copy it from now on.
    pub(crate) const fn copy_payload_type(&mut self, payload_types: (u8, u8)) {
        self.payload_type = payload_types.0;
        self.received_payload_type = payload_types.1;
    }

    /// This end sent `wire`, whose plaintext payload was `payload`. The header is read from the
    /// wire, which SRTP leaves in clear.
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
        let after = self.next.get(stream).copied().flatten();
        // RFC 3711 §3.3.1: an SRTP index only moves forward and receivers derive it from sequence
        // numbers, so another source continues our numbering without a jump
        if self.protection.required {
            if copy.source.is_some_and(|source| source != header.ssrc)
                && let Some(after) = after
            {
                copy.resume(after);
            }
            copy.source = Some(header.ssrc);
        }
        let Some((mut packet, (sequence, timestamp))) =
            copy.packet(header, payload, self.payload_type)
        else {
            return;
        };
        if self.protection.required {
            // a packet arriving after a higher-numbered one is not copied: it would repeat an index
            // (§9.1) or look like a rollover the server never saw, breaking every later check
            if after.is_some_and(|(after, _)| sequence.wrapping_sub(after) >= 0x8000) {
                return;
            }
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
        // reordered packets move nothing back
        if let Some(next) = self.next.get_mut(stream)
            && next.is_none_or(|(after, _)| sequence.wrapping_sub(after) < 0x8000)
        {
            *next = Some((sequence.wrapping_add(1), timestamp.wrapping_add(1)));
        }
        let (from, destination) = (copy.from, copy.destination);
        // drop the oldest: copies uncollected for a second would play late
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

    /// Every queued copy: whether it is the far end's, and its payload type.
    fn drained(tap: &mut Tap) -> Vec<(bool, u8)> {
        let mut copied = Vec::new();
        while let Some(copy) = tap.poll() {
            let header = RtpPacket::parse(copy.payload).expect("RTP").header();
            copied.push((copy.far_end, header.payload_type));
        }
        copied
    }

    /// When an answer renumbered the codec (RFC 3264 §6.1), both parties' copies go to the server
    /// under the offered number.
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

    /// Under one SRTP key a sequence number goes out once (RFC 3711 §9.1): copies moving to a
    /// replacing call or a taken-back stream continue their numbering.
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

        // the replacing call numbers its own packets
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

        // a stream left without a key gets nothing
        tap.protect([None, Some((2, key()))]);
        tap.sent(&packet(0, 9_001), &[7; 40]);
        assert_eq!(sequences(&mut tap), []);
    }

    /// A stream moved to another line and back reuses a key; after a sequence wrap a fresh
    /// protector would repeat indices (RFC 3711 §9.1). Identical payloads would then show identical
    /// ciphertext.
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
                    // the 40 bytes of ciphertext, without the tag
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

        // under line 1, past a sequence wrap
        tap.protect([Some((1, key(1))), None]);
        send(&mut tap, 65_536 + 10);
        // moved to line 2, then back to line 1
        tap.protect([Some((2, key(2))), None]);
        send(&mut tap, 5);
        tap.protect([Some((1, key(1))), None]);
        send(&mut tap, 20);
        assert_eq!(copied, 65_536 + 35, "every packet was copied");
    }

    /// Far-end packets as the network delivers them (one late, one duplicated, then a new source):
    /// a keyed server can open every copy it gets, not only those before the late packet.
    #[test]
    fn the_far_end_reordered_or_renumbered_leaves_every_protected_copy_open_to_the_server() {
        use sipral_rtp::srtp::{Master, Policy, Protector, Suite, Unprotector};

        let master = || Master::new(&[3; 16], &[4; 14]);
        let mut tap = Tap::new(
            &record_to(),
            destinations(),
            (0, 0),
            [(1, 0, 0), (2, 100, 0)],
        );
        tap.protect([
            None,
            Some((1, Protector::new(Policy::new(Suite::AesCm80), master()))),
        ]);
        let mut server = Unprotector::new(Policy::new(Suite::AesCm80), master());
        let from = |source: u32, sequence: u16| {
            let mut bytes = packet(0, sequence);
            if let Some(field) = bytes.get_mut(8..12) {
                field.copy_from_slice(&source.to_be_bytes());
            }
            bytes
        };
        let arriving = [
            (1, 10),
            (1, 11),
            (1, 13),
            (1, 12),
            (1, 14),
            (1, 14),
            (1, 15),
            (7, 40_000),
            (7, 40_001),
            (9, 2),
            (9, 3),
        ];
        let mut opened = Vec::new();
        for (source, sequence) in arriving {
            tap.received(&from(source, sequence));
            while let Some(copy) = tap.poll() {
                let mut bytes = copy.payload.to_vec();
                assert!(
                    server.unprotect_rtp(&mut bytes).is_ok(),
                    "the copy of {sequence} from {source} does not open"
                );
                opened.push(RtpPacket::parse(&bytes).expect("RTP").header().sequence);
            }
        }
        assert_eq!(
            opened,
            [100, 101, 103, 104, 105, 106, 107, 108, 109],
            "the late and the repeated packets are left out, and a new source carries on"
        );
    }
}
