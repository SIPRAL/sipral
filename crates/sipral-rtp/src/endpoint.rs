// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One stream in each direction, and everything that has to be true before a
//! datagram is believed.

use std::net::SocketAddr;
use std::time::Duration;

use crate::playout::{Insert, JitterBuffer, Pull, StreamStats};
use crate::source::{SeqUpdate, SequenceState};
use crate::wire::{BuildError, PacketBuilder, PacketError, PayloadTypes, RtpHeader, RtpPacket};

/// Everything one stream needs before it can start.
///
/// The SSRC, the first sequence number and the first timestamp arrive from the
/// caller because RFC 3550 §5.1 wants all three unpredictable and nothing here
/// draws a random number. Every other field comes out of the offer and the
/// answer.
#[derive(Clone, Copy, Debug)]
pub struct StreamConfig {
    /// Our synchronization source identifier.
    pub ssrc: u32,
    /// The payload type we send.
    pub payload_type: u8,
    /// The payload types we will accept.
    pub accepted: PayloadTypes,
    /// Timestamp ticks per second, from the payload format (RFC 3551 §4.1).
    pub clock_rate: u32,
    /// The first sequence number we send.
    pub sequence: u16,
    /// The first timestamp we send.
    pub timestamp: u32,
    /// Where the answer said the peer is.
    pub remote: SocketAddr,
    /// Whether we stop sending during silence. It decides what the marker bit
    /// may say: RFC 3551 §4.1 has applications without silence suppression set
    /// it to zero on every packet.
    pub silence_suppression: bool,
    /// De-jitter buffer depth, in packets.
    pub depth: u16,
    /// Packets held before playout starts.
    pub prefill: u16,
}

/// What became of a datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Received {
    /// Held for playout.
    Queued,
    /// Dropped, and why.
    Dropped(Discard),
}

/// Why a datagram was not used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Discard {
    /// It is not a well-formed packet.
    Malformed(PacketError),
    /// A payload type nobody negotiated. §5.1: "A receiver MUST ignore packets
    /// with payload types that it does not understand."
    PayloadType(u8),
    /// From somewhere other than the address this stream latched onto.
    ForeignAddress,
    /// A different synchronization source than the one being listened to.
    SecondSource(u32),
    /// The source has not yet sent two packets in a row, so its audio is not
    /// played (RFC 3550 A.1).
    ///
    /// Its address and its SSRC are taken all the same, and deliberately: the
    /// latch has to close on the first packet that is shaped right, or there
    /// is a window two packets wide in which any address on the network is
    /// still a candidate. Probation decides whether a stream is worth
    /// listening to, not whose stream it is.
    Probation,
    /// A sequence number too far from the stream to belong to it.
    BadSequence,
    /// A sequence number already held.
    Duplicate,
    /// Behind the playout point.
    Late,
}

/// One RTP stream in each direction.
///
/// Sans-I/O throughout: the caller reads datagrams off a socket and hands them
/// over with the address they came from, pulls frames at whatever pace its
/// audio device sets, and gets back bytes to send and the address to send them
/// to.
#[derive(Debug)]
pub struct RtpSession {
    outbound: Outbound,
    inbound: Inbound,
}

#[derive(Debug)]
struct Outbound {
    ssrc: u32,
    payload_type: u8,
    clock_rate: u32,
    sequence: u16,
    timestamp: u32,
    silence_suppression: bool,
    spurt_start: bool,
}

#[derive(Debug)]
struct Inbound {
    accepted: PayloadTypes,
    signalled: SocketAddr,
    latch: Option<SocketAddr>,
    source: Option<u32>,
    sequence: SequenceState,
    buffer: JitterBuffer,
}

impl RtpSession {
    /// Open a stream. Nothing is sent and nothing is expected until the caller
    /// says so.
    #[must_use]
    pub fn new(config: &StreamConfig) -> Self {
        Self {
            outbound: Outbound {
                ssrc: config.ssrc,
                payload_type: config.payload_type,
                clock_rate: config.clock_rate,
                sequence: config.sequence,
                timestamp: config.timestamp,
                silence_suppression: config.silence_suppression,
                // the first packet of the call is the first packet of a talk
                // spurt, since there is nothing contiguous behind it
                spurt_start: true,
            },
            inbound: Inbound {
                accepted: config.accepted,
                signalled: config.remote,
                latch: None,
                source: None,
                sequence: SequenceState::new(),
                buffer: JitterBuffer::new(config.depth, config.prefill),
            },
        }
    }

    /// Take in a datagram and the address it came from.
    ///
    /// The checks are in the order that costs least: the shape of the packet,
    /// then the payload type, then where it came from, then who sent it, then
    /// whether its sequence number belongs to the stream. A packet only
    /// reaches the buffer once all five agree.
    ///
    /// The third and fourth of those also *decide* the address and the source,
    /// on the first packet that gets that far — before probation, which is
    /// the fifth. That order is deliberate: closing the latch late would leave
    /// a window in which every address is still a candidate, which is wider
    /// than the one it would close.
    pub fn receive(&mut self, datagram: &[u8], from: SocketAddr) -> Received {
        let packet = match RtpPacket::parse(datagram) {
            Ok(packet) => packet,
            Err(error) => return Received::Dropped(Discard::Malformed(error)),
        };
        let header = packet.header();

        if !self.inbound.accepted.contains(header.payload_type) {
            return Received::Dropped(Discard::PayloadType(header.payload_type));
        }

        // Symmetric RTP. The answer carries the address the peer believes it
        // has, which behind a NAT is a private one nothing can reach; its
        // packets arrive instead from whatever the NAT allocated on the way
        // out. Sending back to that address, from the port we receive on,
        // means our datagrams take the pinhole the peer's own packets opened,
        // and the call works with no relay and nothing to configure. The rport
        // parameter (RFC 3581) does the same for signalling, and between them
        // they are why most calls need no NAT traversal at all.
        //
        // The other half of the rule matters as much: after latching, a packet
        // from any other address is dropped rather than merged. Merging is how
        // someone who can guess a port gets their audio into the call.
        match self.inbound.latch {
            Some(latched) if latched != from => {
                return Received::Dropped(Discard::ForeignAddress);
            }
            Some(_) => {}
            None => self.inbound.latch = Some(from),
        }

        // A second SSRC on a two-party stream is either the far end restarting
        // or someone else's audio. Which of the two is a question the
        // signalling can answer and this cannot, so it is reported and the
        // application decides, with `follow` or `resync`.
        match self.inbound.source {
            Some(known) if known != header.ssrc => {
                return Received::Dropped(Discard::SecondSource(header.ssrc));
            }
            Some(_) => {}
            None => self.inbound.source = Some(header.ssrc),
        }

        match self.inbound.sequence.update(header.sequence) {
            SeqUpdate::Probation => return Received::Dropped(Discard::Probation),
            SeqUpdate::Rejected => return Received::Dropped(Discard::BadSequence),
            SeqUpdate::Restarted => self.inbound.buffer.restart(),
            SeqUpdate::InOrder | SeqUpdate::Misordered => {}
        }

        match self.inbound.buffer.insert(&packet) {
            Insert::Accepted | Insert::Displaced(_) => Received::Queued,
            Insert::Duplicate => Received::Dropped(Discard::Duplicate),
            Insert::Late => Received::Dropped(Discard::Late),
        }
    }

    /// Take the next frame due for playout.
    pub fn pull(&mut self) -> Pull<'_> {
        self.inbound.buffer.pull()
    }

    /// Write the next packet into `out` and say how long it is.
    ///
    /// `samples` is how many sampling periods this payload covers — 160 for
    /// twenty milliseconds of eight kilohertz audio. The timestamp advances by
    /// that much whether or not a packet goes out, so that a gap in the stream
    /// still means the same amount of time (§5.1).
    ///
    /// # Errors
    /// [`BuildError::Short`] when `out` cannot hold the packet, and
    /// [`BuildError::PayloadType`] for a payload type this stream was
    /// configured with that does not fit the field. Either way nothing has been
    /// written and no sequence number has been spent.
    pub fn send(
        &mut self,
        payload: &[u8],
        samples: u32,
        out: &mut [u8],
    ) -> Result<usize, BuildError> {
        let header = RtpHeader {
            marker: self.outbound.silence_suppression && self.outbound.spurt_start,
            payload_type: self.outbound.payload_type,
            sequence: self.outbound.sequence,
            timestamp: self.outbound.timestamp,
            ssrc: self.outbound.ssrc,
        };
        let written = PacketBuilder::new(header, payload).write(out)?;
        self.outbound.spurt_start = false;
        self.outbound.sequence = self.outbound.sequence.wrapping_add(1);
        self.outbound.timestamp = self.outbound.timestamp.wrapping_add(samples);
        Ok(written)
    }

    /// Account for `samples` of silence that were not sent.
    ///
    /// The timestamp moves and the sequence number does not, which is what
    /// tells the far end that time passed rather than packets being lost. The
    /// next packet carries the marker bit: "the first packet of a talkspurt
    /// ... SHOULD be distinguished by setting the marker bit in the RTP data
    /// header to one" (RFC 3551 §4.1).
    pub fn suppress(&mut self, samples: u32) {
        self.outbound.timestamp = self.outbound.timestamp.wrapping_add(samples);
        self.outbound.spurt_start = true;
    }

    /// Where to send: the address packets are actually arriving from once one
    /// has, and the address the answer gave until then.
    #[must_use]
    pub fn destination(&self) -> SocketAddr {
        self.inbound.latch.unwrap_or(self.inbound.signalled)
    }

    /// The address this stream has latched onto, if a packet has arrived.
    #[must_use]
    pub const fn latched(&self) -> Option<SocketAddr> {
        self.inbound.latch
    }

    /// The synchronization source being listened to.
    #[must_use]
    pub const fn remote_ssrc(&self) -> Option<u32> {
        self.inbound.source
    }

    /// Our own synchronization source.
    #[must_use]
    pub const fn local_ssrc(&self) -> u32 {
        self.outbound.ssrc
    }

    /// The counters for the receiving direction.
    #[must_use]
    pub const fn stats(&self) -> StreamStats {
        self.inbound.buffer.stats()
    }

    /// How many timestamp ticks `span` is at the negotiated clock rate.
    ///
    /// Saturates rather than wrapping, so a span no audio packet would ever
    /// carry cannot quietly turn into a small one.
    #[must_use]
    pub fn ticks(&self, span: Duration) -> u32 {
        let ticks = span
            .as_nanos()
            .saturating_mul(u128::from(self.outbound.clock_rate))
            / 1_000_000_000;
        u32::try_from(ticks).unwrap_or(u32::MAX)
    }

    /// Point the stream at a new address and forget the latch, for a
    /// re-INVITE that moved the far end. The next valid packet latches again.
    pub fn relocate(&mut self, remote: SocketAddr) {
        self.inbound.signalled = remote;
        self.inbound.latch = None;
    }

    /// Listen to a different synchronization source, for a far end that has
    /// been told to change it. Everything held for the old one is dropped,
    /// since it belongs to a stream that has ended.
    pub fn follow(&mut self, ssrc: u32) {
        self.inbound.source = Some(ssrc);
        self.inbound.sequence.reset();
        self.inbound.buffer.restart();
    }

    /// Listen to whichever source arrives next. For a stream that has been
    /// re-negotiated, where what the far end will call itself is not known in
    /// advance.
    pub fn resync(&mut self) {
        self.inbound.source = None;
        self.inbound.sequence.reset();
        self.inbound.buffer.restart();
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use super::{Discard, Received, RtpSession, StreamConfig};
    use crate::playout::Pull;
    use crate::wire::{PacketBuilder, PacketError, RtpHeader, RtpPacket};

    const PEER: &str = "198.51.100.7:16384";
    const IMPOSTOR: &str = "203.0.113.9:40000";

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("a socket address")
    }

    fn config() -> StreamConfig {
        StreamConfig {
            ssrc: 0x0102_0304,
            payload_type: 8,
            accepted: [0_u8, 8].into_iter().collect(),
            clock_rate: 8000,
            sequence: 1000,
            timestamp: 500_000,
            remote: addr("192.0.2.10:5004"),
            silence_suppression: true,
            depth: 8,
            prefill: 1,
        }
    }

    fn session() -> RtpSession {
        RtpSession::new(&config())
    }

    /// A packet from the far end, with the sequence number in the payload.
    fn datagram(ssrc: u32, sequence: u16, payload_type: u8) -> Vec<u8> {
        let header = RtpHeader {
            marker: false,
            payload_type,
            sequence,
            timestamp: u32::from(sequence).wrapping_mul(160),
            ssrc,
        };
        let payload = sequence.to_be_bytes();
        let mut out = vec![0; 32];
        let n = PacketBuilder::new(header, &payload)
            .write(&mut out)
            .expect("room");
        out.truncate(n);
        out
    }

    /// Two packets in a row, which is what A.1 asks for before a source counts.
    fn establish(session: &mut RtpSession, ssrc: u32, from: SocketAddr) -> u16 {
        assert_eq!(
            session.receive(&datagram(ssrc, 100, 8), from),
            Received::Dropped(Discard::Probation)
        );
        assert_eq!(
            session.receive(&datagram(ssrc, 101, 8), from),
            Received::Queued
        );
        102
    }

    #[test]
    fn the_stream_latches_onto_the_source_of_the_first_packet_it_believes() {
        let mut session = session();
        assert_eq!(session.latched(), None);
        assert_eq!(
            session.destination(),
            addr("192.0.2.10:5004"),
            "until a packet arrives, the answer is all there is to go on"
        );

        session.receive(&datagram(7, 100, 8), addr(PEER));
        assert_eq!(session.latched(), Some(addr(PEER)));
        assert_eq!(
            session.destination(),
            addr(PEER),
            "and after it, where the packets actually come from"
        );
    }

    #[test]
    fn a_packet_from_another_address_after_latching_is_dropped_not_merged() {
        let mut session = session();
        let next = establish(&mut session, 7, addr(PEER));

        assert_eq!(
            session.receive(&datagram(7, next, 8), addr(IMPOSTOR)),
            Received::Dropped(Discard::ForeignAddress)
        );
        assert_eq!(
            session.latched(),
            Some(addr(PEER)),
            "the latch does not move"
        );
        assert_eq!(session.destination(), addr(PEER));
        assert_eq!(
            session.stats().received,
            1,
            "nothing of it reached the buffer"
        );

        // and the real peer carries on unaffected
        assert_eq!(
            session.receive(&datagram(7, next, 8), addr(PEER)),
            Received::Queued
        );
    }

    #[test]
    fn a_second_synchronization_source_is_reported_rather_than_mixed_in() {
        let mut session = session();
        let next = establish(&mut session, 7, addr(PEER));
        assert_eq!(session.remote_ssrc(), Some(7));

        // same address, different SSRC: one machine, two streams
        assert_eq!(
            session.receive(&datagram(9, next, 8), addr(PEER)),
            Received::Dropped(Discard::SecondSource(9))
        );
        assert_eq!(session.remote_ssrc(), Some(7));

        // the application decides, because only the signalling knows whether
        // the far end was replaced
        session.follow(9);
        assert_eq!(session.remote_ssrc(), Some(9));
        assert_eq!(
            session.receive(&datagram(7, next, 8), addr(PEER)),
            Received::Dropped(Discard::SecondSource(7))
        );
        establish(&mut session, 9, addr(PEER));
    }

    #[test]
    fn resync_takes_whichever_source_arrives_next() {
        let mut session = session();
        establish(&mut session, 7, addr(PEER));
        session.resync();
        assert_eq!(session.remote_ssrc(), None);
        establish(&mut session, 4242, addr(PEER));
        assert_eq!(session.remote_ssrc(), Some(4242));
    }

    #[test]
    fn a_payload_type_nobody_negotiated_is_ignored() {
        // §5.1: "A receiver MUST ignore packets with payload types that it
        // does not understand"
        let mut session = session();
        assert_eq!(
            session.receive(&datagram(7, 100, 96), addr(PEER)),
            Received::Dropped(Discard::PayloadType(96))
        );
        assert_eq!(
            session.latched(),
            None,
            "and it is not the packet a stream latches onto"
        );
    }

    #[test]
    fn a_datagram_that_is_not_a_packet_never_gets_as_far_as_the_latch() {
        let mut session = session();
        assert_eq!(
            session.receive(b"not rtp", addr(IMPOSTOR)),
            Received::Dropped(Discard::Malformed(PacketError::TooShort { got: 7 }))
        );
        assert_eq!(session.latched(), None);
    }

    #[test]
    fn the_first_packet_of_a_new_source_is_not_believed_on_its_own() {
        // RFC 3550 A.1: two in a row before a source counts
        let mut session = session();
        assert_eq!(
            session.receive(&datagram(7, 100, 8), addr(PEER)),
            Received::Dropped(Discard::Probation)
        );
        assert!(matches!(session.pull(), Pull::Empty));
        assert_eq!(
            session.receive(&datagram(7, 101, 8), addr(PEER)),
            Received::Queued
        );
    }

    #[test]
    fn a_sequence_number_from_nowhere_is_refused_until_it_repeats() {
        let mut session = session();
        let next = establish(&mut session, 7, addr(PEER));
        assert_eq!(
            session.receive(&datagram(7, 40000, 8), addr(PEER)),
            Received::Dropped(Discard::BadSequence)
        );
        // the second one says the far end restarted, and the stream follows it
        assert_eq!(
            session.receive(&datagram(7, 40001, 8), addr(PEER)),
            Received::Queued
        );
        assert_eq!(
            session.receive(&datagram(7, next, 8), addr(PEER)),
            Received::Dropped(Discard::BadSequence),
            "the old numbering is gone with the stream it belonged to"
        );
    }

    #[test]
    fn a_repeated_packet_is_dropped_and_a_late_one_is_told_apart_from_it() {
        let mut session = session();
        let next = establish(&mut session, 7, addr(PEER));
        assert_eq!(
            session.receive(&datagram(7, next, 8), addr(PEER)),
            Received::Queued
        );
        assert_eq!(
            session.receive(&datagram(7, next, 8), addr(PEER)),
            Received::Dropped(Discard::Duplicate)
        );

        while matches!(session.pull(), Pull::Packet(_) | Pull::Missing) {}
        assert_eq!(
            session.receive(&datagram(7, next, 8), addr(PEER)),
            Received::Dropped(Discard::Late)
        );
        assert_eq!(session.stats().duplicated, 1);
        assert_eq!(session.stats().discarded, 1);
    }

    #[test]
    fn what_goes_in_comes_out_in_order_with_the_payload_intact() {
        let mut session = session();
        establish(&mut session, 7, addr(PEER));
        for sequence in [104_u16, 102, 103] {
            assert_eq!(
                session.receive(&datagram(7, sequence, 8), addr(PEER)),
                Received::Queued
            );
        }
        for expected in [101_u16, 102, 103, 104] {
            let Pull::Packet(frame) = session.pull() else {
                panic!("a packet");
            };
            assert_eq!(frame.sequence, expected);
            assert_eq!(frame.payload, expected.to_be_bytes());
            assert_eq!(frame.timestamp, u32::from(expected) * 160);
        }
        assert_eq!(
            session.stats().reordered,
            2,
            "both 102 and 103 came after 104"
        );
        assert_eq!(
            session.stats().lost,
            0,
            "reordering inside the window is not loss"
        );
    }

    #[test]
    fn sending_advances_the_sequence_number_by_one_and_the_timestamp_by_the_frame() {
        let mut out = [0_u8; 256];
        let mut session = session();
        let payload = [0xD5_u8; 160];

        let n = session.send(&payload, 160, &mut out).expect("room");
        let first = RtpPacket::parse(&out[..n]).expect("a packet");
        assert_eq!(first.header().sequence, 1000);
        assert_eq!(first.header().timestamp, 500_000);
        assert_eq!(first.header().ssrc, 0x0102_0304);
        assert_eq!(first.header().payload_type, 8);
        assert_eq!(first.payload(), payload);

        let n = session.send(&payload, 160, &mut out).expect("room");
        let second = RtpPacket::parse(&out[..n]).expect("a packet");
        assert_eq!(second.header().sequence, 1001);
        assert_eq!(second.header().timestamp, 500_160);
    }

    #[test]
    fn the_marker_bit_says_a_talk_spurt_is_starting_and_nothing_else() {
        // RFC 3551 §4.1: "the first packet of a talkspurt, that is, the first
        // packet after a silence period during which packets have not been
        // transmitted contiguously, SHOULD be distinguished by setting the
        // marker bit"
        let mut out = [0_u8; 256];
        let mut session = session();
        let payload = [0_u8; 160];

        let n = session.send(&payload, 160, &mut out).expect("room");
        assert!(
            RtpPacket::parse(&out[..n])
                .expect("a packet")
                .header()
                .marker,
            "there is nothing contiguous behind the first packet of a call"
        );

        let n = session.send(&payload, 160, &mut out).expect("room");
        assert!(
            !RtpPacket::parse(&out[..n])
                .expect("a packet")
                .header()
                .marker
        );

        // a second of silence goes by unsent
        session.suppress(8000);
        let n = session.send(&payload, 160, &mut out).expect("room");
        let resumed = RtpPacket::parse(&out[..n]).expect("a packet");
        assert!(resumed.header().marker, "and the spurt starts again");
        assert_eq!(
            resumed.header().sequence,
            1002,
            "silence costs no sequence number"
        );
        assert_eq!(
            resumed.header().timestamp,
            500_000 + 160 + 160 + 8000,
            "but it costs the time it took"
        );
    }

    #[test]
    fn an_application_that_never_stops_sending_never_sets_the_marker() {
        // RFC 3551 §4.1: "Applications without silence suppression MUST set
        // the marker bit to zero"
        let mut out = [0_u8; 256];
        let mut session = RtpSession::new(&StreamConfig {
            silence_suppression: false,
            ..config()
        });
        for _ in 0..3 {
            let n = session.send(&[0; 160], 160, &mut out).expect("room");
            assert!(
                !RtpPacket::parse(&out[..n])
                    .expect("a packet")
                    .header()
                    .marker
            );
        }
    }

    #[test]
    fn a_send_that_does_not_fit_spends_nothing() {
        let mut small = [0_u8; 16];
        let mut session = session();
        assert!(session.send(&[0; 160], 160, &mut small).is_err());

        let mut out = [0_u8; 256];
        let n = session.send(&[0; 160], 160, &mut out).expect("room");
        assert_eq!(
            RtpPacket::parse(&out[..n])
                .expect("a packet")
                .header()
                .sequence,
            1000,
            "the failed attempt left no gap in the numbering"
        );
    }

    #[test]
    fn a_span_becomes_ticks_at_the_negotiated_clock_rate() {
        let session = session();
        assert_eq!(session.ticks(Duration::from_millis(20)), 160);
        assert_eq!(session.ticks(Duration::from_secs(1)), 8000);
        assert_eq!(session.ticks(Duration::ZERO), 0);
        assert_eq!(session.ticks(Duration::MAX), u32::MAX);
    }

    #[test]
    fn a_re_invite_that_moves_the_far_end_lets_the_stream_latch_again() {
        let mut session = session();
        establish(&mut session, 7, addr(PEER));
        assert_eq!(session.latched(), Some(addr(PEER)));

        session.relocate(addr(IMPOSTOR));
        assert_eq!(session.latched(), None);
        assert_eq!(session.destination(), addr(IMPOSTOR));
        session.receive(&datagram(7, 102, 8), addr(IMPOSTOR));
        assert_eq!(session.latched(), Some(addr(IMPOSTOR)));
    }
}
