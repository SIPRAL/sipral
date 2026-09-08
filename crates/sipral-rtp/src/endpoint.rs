// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One stream in each direction, and everything that has to be true before a
//! datagram is believed.

use std::net::SocketAddr;
use std::time::Duration;

use crate::playout::{Activity, BufferConfig, Insert, JitterBuffer, Pull, Quality, clock_ticks};
use crate::rtcp::{
    CNAME, ChunkBuilder, CompoundBuilder, CompoundPacket, GoodbyeBuilder, ReceiverReportBuilder,
    ReportBlock, RtcpBuildError, RtcpError, RtcpPacket, SdesItem, SenderInfo, SenderOrReceiver,
    SenderReportBuilder, SourceDescriptionBuilder,
};
use crate::rtcp_stats::{ReceptionTracker, round_trip_time};
use crate::rtcp_timer::{Due, IntervalTimer};
use crate::source::{SeqUpdate, SequenceState};
use crate::wire::{BuildError, PacketBuilder, PacketError, PayloadTypes, RtpHeader, RtpPacket};

/// Everything one stream needs before it can start.
///
/// The SSRC, the first sequence number and the first timestamp arrive from the
/// caller because RFC 3550 §5.1 wants all three unpredictable and nothing here
/// draws a random number. Every other field comes out of the offer and the
/// answer.
#[derive(Clone, Debug)]
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
    /// How the de-jitter buffer is sized and how far it may move its delay.
    pub playout: BufferConfig,
    /// This stream's CNAME, sent in every SDES (RFC 3550 §6.5.1): "user@host",
    /// or "host" alone with no user to name.
    pub cname: String,
    /// This session's share of the call's RTCP bandwidth, in octets per
    /// second (§6.2). "RECOMMENDED that the fraction of the session
    /// bandwidth added for RTCP be fixed at 5%".
    pub rtcp_bandwidth: f64,
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

/// What an incoming compound RTCP packet said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtcpReceived<'a> {
    /// An SR or RR was read; any reception statistics or round-trip time it
    /// carried about this session were folded in
    /// ([`RtpSession::round_trip_time`]).
    Report,
    /// The remote source said it is leaving.
    Goodbye {
        /// Why, if it said (RFC 3550 §6.6).
        reason: &'a [u8],
    },
    /// Not a well-formed compound RTCP packet.
    Malformed(RtcpError),
}

/// One RTP stream in each direction, plus the RTCP that goes with it.
///
/// Sans-I/O throughout: the caller reads datagrams off a socket and hands them
/// over with the address they came from, pulls frames at whatever pace its
/// audio device sets, and gets back bytes to send and the address to send them
/// to. RTCP works the same way: [`RtpSession::rtcp_due`] says when to build a
/// report, and this crate reads no clock and draws no random number to decide
/// that, so `now`, the wall-clock NTP timestamp a sender report carries, and
/// the random draw §6.2 asks for all arrive from the caller.
#[derive(Debug)]
pub struct RtpSession {
    outbound: Outbound,
    inbound: Inbound,
    cname: String,
    timer: IntervalTimer,
    round_trip: Option<Duration>,
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
    packets_sent: u32,
    octets_sent: u32,
    sent_since_report: bool,
}

#[derive(Debug)]
struct Inbound {
    accepted: PayloadTypes,
    signalled: SocketAddr,
    latch: Option<SocketAddr>,
    source: Option<u32>,
    sequence: SequenceState,
    buffer: JitterBuffer,
    rtcp: ReceptionTracker,
    /// Whether §6.3's member table already has an entry for the remote
    /// side, so it is only counted once.
    member_known: bool,
    /// Whether the remote side has been heard sending RTP, for the sender
    /// count §6.3.1's interval calculation splits out from members.
    sender_known: bool,
}

impl RtpSession {
    /// Open a stream. Nothing is sent and nothing is expected until the caller
    /// says so.
    ///
    /// `unit_interval` is the random draw §6.2 asks for when scheduling the
    /// first RTCP report, uniform on `[0, 1)`.
    #[must_use]
    pub fn new(config: &StreamConfig, unit_interval: f64) -> Self {
        let cname_item = [SdesItem {
            kind: CNAME,
            text: config.cname.as_bytes(),
        }];
        let sdes = SourceDescriptionBuilder {
            chunks: &[ChunkBuilder {
                ssrc: config.ssrc,
                items: &cname_item,
            }],
        };
        let rr = ReceiverReportBuilder {
            ssrc: config.ssrc,
            reports: &[],
        };
        // §6.3.2: "avg_rtcp_size [set] to the probable size of the first
        // RTCP packet that the application will later construct" — this is
        // exactly that packet, an empty RR plus this session's own CNAME
        let first_report_size =
            CompoundBuilder::new(SenderOrReceiver::Receiver(rr), sdes).encoded_len();

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
                packets_sent: 0,
                octets_sent: 0,
                sent_since_report: false,
            },
            inbound: Inbound {
                accepted: config.accepted,
                signalled: config.remote,
                latch: None,
                source: None,
                sequence: SequenceState::new(),
                buffer: JitterBuffer::new(config.clock_rate, &config.playout),
                rtcp: ReceptionTracker::new(),
                member_known: false,
                sender_known: false,
            },
            cname: config.cname.clone(),
            timer: IntervalTimer::new(config.rtcp_bandwidth, first_report_size, unit_interval),
            round_trip: None,
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
    ///
    /// `now` is this stream's own clock, on whatever timeline the caller
    /// likes, and feeds only the interarrival jitter estimate (§6.4.1): nothing
    /// here reads a clock of its own, so a caller that does not care about
    /// RTCP may pass anything monotonic.
    pub fn receive(&mut self, datagram: &[u8], from: SocketAddr, now: Duration) -> Received {
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
            SeqUpdate::Restarted => {
                self.inbound.buffer.restart();
                // the loss and jitter bookkeeping describe a stream that no
                // longer exists once the far end has restarted, the same
                // reasoning `SequenceState::rebase` already applies to itself
                self.inbound.rtcp.restart();
            }
            SeqUpdate::InOrder | SeqUpdate::Misordered => {}
        }

        if !self.inbound.member_known {
            self.inbound.member_known = true;
            self.timer.note_member();
        }
        if !self.inbound.sender_known {
            self.inbound.sender_known = true;
            self.timer.note_sender();
        }
        self.inbound
            .rtcp
            .on_packet(header.timestamp, clock_ticks(self.outbound.clock_rate, now));

        match self.inbound.buffer.insert(&packet, now) {
            Insert::Accepted | Insert::Displaced(_) => Received::Queued,
            Insert::Duplicate => Received::Dropped(Discard::Duplicate),
            Insert::Late => Received::Dropped(Discard::Late),
        }
    }

    /// Take the next frame due for playout.
    ///
    /// `activity` says whether what was played a frame ago was speech or a
    /// pause, which is what decides whether the buffer is allowed to move its
    /// delay right now. A caller with no voice activity detector passes
    /// [`Activity::Speech`] and gets a buffer that never adapts after it has
    /// started, which is worse but not wrong.
    pub fn pull(&mut self, activity: Activity) -> Pull<'_> {
        self.inbound.buffer.pull(activity)
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
        if self.outbound.packets_sent == 0 {
            self.timer.note_local_sender();
        }
        self.outbound.packets_sent = self.outbound.packets_sent.wrapping_add(1);
        self.outbound.octets_sent = self
            .outbound
            .octets_sent
            .wrapping_add(u32::try_from(payload.len()).unwrap_or(u32::MAX));
        self.outbound.sent_since_report = true;
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

    /// What the receiving direction has cost so far, and what it is costing
    /// now.
    #[must_use]
    pub fn quality(&self) -> Quality {
        self.inbound.buffer.quality()
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
        self.inbound.rtcp = ReceptionTracker::new();
    }

    /// Listen to whichever source arrives next. For a stream that has been
    /// re-negotiated, where what the far end will call itself is not known in
    /// advance.
    pub fn resync(&mut self) {
        self.inbound.source = None;
        self.inbound.sequence.reset();
        self.inbound.buffer.restart();
        self.inbound.rtcp = ReceptionTracker::new();
    }

    /// Whether a periodic RTCP report is due, or how long to wait (§6.3.6).
    /// Call again no earlier than a returned [`Due::Wait`] says; on
    /// [`Due::Send`], build the report with [`RtpSession::build_report`].
    ///
    /// `unit_interval` is a fresh random draw on `[0, 1)`, independent of
    /// any other this session has been given (§6.3.1 point 4).
    pub fn rtcp_due(&mut self, now: Duration, unit_interval: f64) -> Due {
        self.timer.due(now, unit_interval)
    }

    /// Build the compound RTCP report [`RtpSession::rtcp_due`] said was due,
    /// and schedule the next one, returning the octets written and that
    /// deadline.
    ///
    /// An SR is sent if this session has sent RTP since the last report, an
    /// RR otherwise (§6.4); either way a reception report block about the
    /// remote source is included once one is known, and an SDES with this
    /// session's own CNAME always is (§6.1). `ntp` is the wall clock at this
    /// instant, in the 64-bit form §6.4.1 asks a sender report to carry.
    ///
    /// # Errors
    /// [`RtcpBuildError`], for a buffer too small. Nothing is scheduled and
    /// nothing is sent when this returns an error.
    pub fn build_report(
        &mut self,
        out: &mut [u8],
        now: Duration,
        ntp: u64,
        unit_interval: f64,
    ) -> Result<(usize, Duration), RtcpBuildError> {
        let sequence = self.inbound.sequence;
        let block = self
            .inbound
            .source
            .map(|ssrc| self.inbound.rtcp.block(ssrc, &sequence, ntp));
        let reports: &[ReportBlock] = block.as_slice();

        let cname_item = [SdesItem {
            kind: CNAME,
            text: self.cname.as_bytes(),
        }];
        let sdes = SourceDescriptionBuilder {
            chunks: &[ChunkBuilder {
                ssrc: self.outbound.ssrc,
                items: &cname_item,
            }],
        };
        let report = if self.outbound.sent_since_report {
            SenderOrReceiver::Sender(SenderReportBuilder {
                ssrc: self.outbound.ssrc,
                info: SenderInfo {
                    ntp,
                    rtp_timestamp: self.outbound.timestamp,
                    packet_count: self.outbound.packets_sent,
                    octet_count: self.outbound.octets_sent,
                },
                reports,
            })
        } else {
            SenderOrReceiver::Receiver(ReceiverReportBuilder {
                ssrc: self.outbound.ssrc,
                reports,
            })
        };

        let written = CompoundBuilder::new(report, sdes).write(out)?;
        self.outbound.sent_since_report = false;
        let next = self.timer.sent(now, written, unit_interval);
        Ok((written, next))
    }

    /// Build a BYE for this stream's own SSRC, to send on hangup, and fold
    /// its size into the schedule the way any other RTCP packet's would be
    /// (§6.3.7). Always sends immediately rather than backing off — see
    /// [`RtpSession::bye_should_back_off`] for when that would not be
    /// correct.
    ///
    /// # Errors
    /// [`RtcpBuildError`], for a buffer too small.
    pub fn send_bye(
        &mut self,
        out: &mut [u8],
        now: Duration,
        reason: &[u8],
        unit_interval: f64,
    ) -> Result<usize, RtcpBuildError> {
        let cname_item = [SdesItem {
            kind: CNAME,
            text: self.cname.as_bytes(),
        }];
        let sdes = SourceDescriptionBuilder {
            chunks: &[ChunkBuilder {
                ssrc: self.outbound.ssrc,
                items: &cname_item,
            }],
        };
        let rr = ReceiverReportBuilder {
            ssrc: self.outbound.ssrc,
            reports: &[],
        };
        let bye = GoodbyeBuilder {
            sources: &[self.outbound.ssrc],
            reason,
        };
        let compound = CompoundBuilder::new(SenderOrReceiver::Receiver(rr), sdes).with_bye(bye);
        let written = compound.write(out)?;
        self.timer.leaving(now, written, unit_interval);
        Ok(written)
    }

    /// Take in a compound RTCP datagram, whichever socket it arrived on
    /// (§6.3.3, RFC 5761 for a socket shared with RTP).
    pub fn rtcp_receive<'a>(
        &mut self,
        datagram: &'a [u8],
        now: Duration,
        ntp: u64,
    ) -> RtcpReceived<'a> {
        self.timer.observe(datagram.len());
        let compound = match CompoundPacket::parse(datagram) {
            Ok(compound) => compound,
            Err(error) => return RtcpReceived::Malformed(error),
        };
        if !self.inbound.member_known {
            self.inbound.member_known = true;
            self.timer.note_member();
        }

        let mut goodbye = None;
        for packet in compound.packets() {
            match packet {
                RtcpPacket::SenderReport(sr) => {
                    if Some(sr.ssrc()) == self.inbound.source {
                        self.inbound.rtcp.on_sender_report(sr.info().ntp, ntp);
                    }
                    self.note_round_trip(sr.reports(), ntp);
                }
                RtcpPacket::ReceiverReport(rr) => self.note_round_trip(rr.reports(), ntp),
                RtcpPacket::Goodbye(bye) => {
                    if bye.sources().any(|ssrc| Some(ssrc) == self.inbound.source) {
                        self.timer.remove_member(now);
                        if self.inbound.sender_known {
                            self.timer.remove_sender();
                        }
                        goodbye = Some(bye.reason().unwrap_or_default());
                    }
                }
                RtcpPacket::SourceDescription(_) | RtcpPacket::Other { .. } => {}
            }
        }
        match goodbye {
            Some(reason) => RtcpReceived::Goodbye { reason },
            None => RtcpReceived::Report,
        }
    }

    /// Whichever of a report's blocks describes this session's own SSRC
    /// carries the round trip to whoever sent it (§6.4.1, A.3: LSR and
    /// DLSR).
    fn note_round_trip(&mut self, reports: impl Iterator<Item = ReportBlock>, arrival_ntp: u64) {
        for block in reports {
            if block.ssrc == self.outbound.ssrc {
                self.round_trip = round_trip_time(&block, arrival_ntp);
            }
        }
    }

    /// The most recently measured round-trip time to the remote side, from
    /// the last reception report block it sent describing this session's own
    /// SSRC. `None` until one has, or if it never received an SR to measure
    /// from.
    #[must_use]
    pub const fn round_trip_time(&self) -> Option<Duration> {
        self.round_trip
    }

    /// When the next periodic RTCP report is scheduled, without the side
    /// effect [`RtpSession::rtcp_due`] has of updating `pmembers` — for a
    /// caller that only wants to know, such as arming a wakeup timer.
    #[must_use]
    pub const fn next_rtcp_deadline(&self) -> Duration {
        self.timer.next_deadline()
    }

    /// Whether §6.3.7's BYE backoff would apply if this session left the
    /// call right now: "a participant MUST execute the following algorithm
    /// if the number of members is more than 50 when the participant
    /// chooses to leave." [`RtpSession::send_bye`] always sends immediately
    /// regardless, which §6.3.7 also allows below that threshold — a
    /// two-party call never reaches it, so this is here for a caller built
    /// on top of a session with a larger membership than this crate assumes.
    #[must_use]
    pub fn bye_should_back_off(&self) -> bool {
        self.timer.should_back_off_bye()
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use super::{Discard, Received, RtcpReceived, RtpSession, StreamConfig};
    use crate::playout::{Activity, BufferConfig, Pull};
    use crate::rtcp::{
        CNAME, ChunkBuilder, CompoundBuilder, CompoundPacket, GoodbyeBuilder,
        ReceiverReportBuilder, ReportBlock, RtcpPacket, SdesItem, SenderOrReceiver,
        SourceDescriptionBuilder,
    };
    use crate::rtcp_timer::Due;
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
            playout: BufferConfig {
                depth: 8,
                packet_samples: 160,
                min_delay: 1,
                start_delay: 1,
                max_delay: 4,
            },
            cname: "tester@203.0.113.1".to_string(),
            rtcp_bandwidth: 800.0,
        }
    }

    fn session() -> RtpSession {
        RtpSession::new(&config(), 0.5)
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
            session.receive(&datagram(ssrc, 100, 8), from, Duration::ZERO),
            Received::Dropped(Discard::Probation)
        );
        assert_eq!(
            session.receive(&datagram(ssrc, 101, 8), from, Duration::ZERO),
            Received::Queued
        );
        102
    }

    /// One SDES chunk naming `ssrc` with only a CNAME, the least a compound
    /// packet arriving from a peer needs to be accepted.
    fn cname_chunk(ssrc: u32) -> ChunkBuilder<'static> {
        const ITEMS: &[SdesItem<'static>] = &[SdesItem {
            kind: CNAME,
            text: b"peer@198.51.100.7",
        }];
        ChunkBuilder { ssrc, items: ITEMS }
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

        session.receive(&datagram(7, 100, 8), addr(PEER), Duration::ZERO);
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
            session.receive(&datagram(7, next, 8), addr(IMPOSTOR), Duration::ZERO),
            Received::Dropped(Discard::ForeignAddress)
        );
        assert_eq!(
            session.latched(),
            Some(addr(PEER)),
            "the latch does not move"
        );
        assert_eq!(session.destination(), addr(PEER));
        assert_eq!(
            session.quality().received,
            1,
            "nothing of it reached the buffer"
        );

        // and the real peer carries on unaffected
        assert_eq!(
            session.receive(&datagram(7, next, 8), addr(PEER), Duration::ZERO),
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
            session.receive(&datagram(9, next, 8), addr(PEER), Duration::ZERO),
            Received::Dropped(Discard::SecondSource(9))
        );
        assert_eq!(session.remote_ssrc(), Some(7));

        // the application decides, because only the signalling knows whether
        // the far end was replaced
        session.follow(9);
        assert_eq!(session.remote_ssrc(), Some(9));
        assert_eq!(
            session.receive(&datagram(7, next, 8), addr(PEER), Duration::ZERO),
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
            session.receive(&datagram(7, 100, 96), addr(PEER), Duration::ZERO),
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
            session.receive(b"not rtp", addr(IMPOSTOR), Duration::ZERO),
            Received::Dropped(Discard::Malformed(PacketError::TooShort { got: 7 }))
        );
        assert_eq!(session.latched(), None);
    }

    #[test]
    fn the_first_packet_of_a_new_source_is_not_believed_on_its_own() {
        // RFC 3550 A.1: two in a row before a source counts
        let mut session = session();
        assert_eq!(
            session.receive(&datagram(7, 100, 8), addr(PEER), Duration::ZERO),
            Received::Dropped(Discard::Probation)
        );
        assert!(matches!(session.pull(Activity::Speech), Pull::Empty));
        assert_eq!(
            session.receive(&datagram(7, 101, 8), addr(PEER), Duration::ZERO),
            Received::Queued
        );
    }

    #[test]
    fn a_sequence_number_from_nowhere_is_refused_until_it_repeats() {
        let mut session = session();
        let next = establish(&mut session, 7, addr(PEER));
        assert_eq!(
            session.receive(&datagram(7, 40000, 8), addr(PEER), Duration::ZERO),
            Received::Dropped(Discard::BadSequence)
        );
        // the second one says the far end restarted, and the stream follows it
        assert_eq!(
            session.receive(&datagram(7, 40001, 8), addr(PEER), Duration::ZERO),
            Received::Queued
        );
        assert_eq!(
            session.receive(&datagram(7, next, 8), addr(PEER), Duration::ZERO),
            Received::Dropped(Discard::BadSequence),
            "the old numbering is gone with the stream it belonged to"
        );
    }

    #[test]
    fn a_repeated_packet_is_dropped_and_a_late_one_is_told_apart_from_it() {
        let mut session = session();
        let next = establish(&mut session, 7, addr(PEER));
        assert_eq!(
            session.receive(&datagram(7, next, 8), addr(PEER), Duration::ZERO),
            Received::Queued
        );
        assert_eq!(
            session.receive(&datagram(7, next, 8), addr(PEER), Duration::ZERO),
            Received::Dropped(Discard::Duplicate)
        );

        while matches!(
            session.pull(Activity::Speech),
            Pull::Packet(_) | Pull::Conceal
        ) {}
        assert_eq!(
            session.receive(&datagram(7, next, 8), addr(PEER), Duration::ZERO),
            Received::Dropped(Discard::Late)
        );
        assert_eq!(session.quality().duplicates, 1);
        assert_eq!(session.quality().discarded_late, 1);
    }

    #[test]
    fn what_goes_in_comes_out_in_order_with_the_payload_intact() {
        let mut session = session();
        establish(&mut session, 7, addr(PEER));
        for sequence in [104_u16, 102, 103] {
            assert_eq!(
                session.receive(&datagram(7, sequence, 8), addr(PEER), Duration::ZERO),
                Received::Queued
            );
        }
        for expected in [101_u16, 102, 103, 104] {
            let Pull::Packet(frame) = session.pull(Activity::Speech) else {
                panic!("a packet");
            };
            assert_eq!(frame.sequence, expected);
            assert_eq!(frame.payload, expected.to_be_bytes());
            assert_eq!(frame.timestamp, u32::from(expected) * 160);
        }
        assert_eq!(
            session.quality().reordered,
            2,
            "both 102 and 103 came after 104"
        );
        assert_eq!(
            session.quality().lost,
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
        let mut session = RtpSession::new(
            &StreamConfig {
                silence_suppression: false,
                ..config()
            },
            0.5,
        );
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
        session.receive(&datagram(7, 102, 8), addr(IMPOSTOR), Duration::ZERO);
        assert_eq!(session.latched(), Some(addr(IMPOSTOR)));
    }

    #[test]
    fn a_new_session_has_nothing_to_report_but_an_empty_rr_and_its_own_cname() {
        let mut session = session();
        let mut out = [0_u8; 256];
        let (n, next) = session
            .build_report(&mut out, Duration::ZERO, 0, 0.5)
            .expect("room");
        assert!(next > Duration::ZERO, "a deadline was scheduled");

        let compound = CompoundPacket::parse(&out[..n]).expect("a compound packet");
        let mut packets = compound.packets();
        let Some(RtcpPacket::ReceiverReport(rr)) = packets.next() else {
            panic!("an RR first: nothing has been sent yet");
        };
        assert_eq!(rr.ssrc(), 0x0102_0304);
        assert_eq!(rr.report_count(), 0, "no remote source is known yet");
        let Some(RtcpPacket::SourceDescription(sdes)) = packets.next() else {
            panic!("an SDES second");
        };
        assert_eq!(sdes.cname(), Some(&b"tester@203.0.113.1"[..]));
        assert!(packets.next().is_none());
    }

    #[test]
    fn a_session_that_has_sent_reports_itself_as_a_sender() {
        let mut session = session();
        session
            .send(&[0_u8; 160], 160, &mut [0_u8; 256])
            .expect("room");
        session
            .send(&[0_u8; 160], 160, &mut [0_u8; 256])
            .expect("room");

        let mut out = [0_u8; 256];
        let (n, _) = session
            .build_report(&mut out, Duration::ZERO, 0x0102_0304_0506_0708, 0.5)
            .expect("room");
        let compound = CompoundPacket::parse(&out[..n]).expect("a compound packet");
        let Some(RtcpPacket::SenderReport(sr)) = compound.packets().next() else {
            panic!("an SR: this session has sent");
        };
        assert_eq!(sr.info().packet_count, 2);
        assert_eq!(sr.info().octet_count, 320);
        assert_eq!(sr.info().ntp, 0x0102_0304_0506_0708);
        assert_eq!(sr.info().rtp_timestamp, 500_320);
    }

    #[test]
    fn a_report_carries_a_reception_block_once_a_remote_source_is_known() {
        let mut session = session();
        establish(&mut session, 7, addr(PEER));

        let mut out = [0_u8; 256];
        let (n, _) = session
            .build_report(&mut out, Duration::ZERO, 0, 0.5)
            .expect("room");
        let compound = CompoundPacket::parse(&out[..n]).expect("a compound packet");
        let Some(RtcpPacket::ReceiverReport(rr)) = compound.packets().next() else {
            panic!("an RR");
        };
        assert_eq!(rr.report_count(), 1);
        let block = rr.reports().next().expect("one block");
        assert_eq!(block.ssrc, 7);
    }

    #[test]
    fn an_incoming_report_about_this_sessions_own_ssrc_yields_a_round_trip_time() {
        let mut session = session();
        assert_eq!(session.round_trip_time(), None);

        // §6.4.1 Figure 2's own worked example: A - LSR - DLSR = 6.125s
        let block = ReportBlock {
            ssrc: 0x0102_0304, // this session's own SSRC
            last_sr: 0xb705_2000,
            delay_since_last_sr: 0x0005_4000,
            ..ReportBlock::default()
        };
        let rr = ReceiverReportBuilder {
            ssrc: 99,
            reports: &[block],
        };
        let sdes = SourceDescriptionBuilder {
            chunks: &[cname_chunk(99)],
        };
        let mut incoming = [0_u8; 256];
        let n = CompoundBuilder::new(SenderOrReceiver::Receiver(rr), sdes)
            .write(&mut incoming)
            .expect("room");

        let arrival_ntp = 0xb710_8000_u64 << 16;
        assert_eq!(
            session.rtcp_receive(&incoming[..n], Duration::ZERO, arrival_ntp),
            RtcpReceived::Report
        );
        assert_eq!(
            session.round_trip_time(),
            Some(Duration::new(6, 125_000_000))
        );
    }

    #[test]
    fn a_goodbye_from_the_established_source_is_reported_with_its_reason() {
        let mut session = session();
        establish(&mut session, 7, addr(PEER));

        let rr = ReceiverReportBuilder {
            ssrc: 7,
            reports: &[],
        };
        let sdes = SourceDescriptionBuilder {
            chunks: &[cname_chunk(7)],
        };
        let bye = GoodbyeBuilder {
            sources: &[7],
            reason: b"call ended",
        };
        let mut incoming = [0_u8; 256];
        let n = CompoundBuilder::new(SenderOrReceiver::Receiver(rr), sdes)
            .with_bye(bye)
            .write(&mut incoming)
            .expect("room");

        assert_eq!(
            session.rtcp_receive(&incoming[..n], Duration::ZERO, 0),
            RtcpReceived::Goodbye {
                reason: b"call ended"
            }
        );
    }

    #[test]
    fn a_malformed_rtcp_datagram_is_reported_rather_than_panicking() {
        let mut session = session();
        assert!(matches!(
            session.rtcp_receive(b"not rtcp", Duration::ZERO, 0),
            RtcpReceived::Malformed(_)
        ));
    }

    #[test]
    fn send_bye_writes_a_compound_packet_with_the_reason_and_this_sessions_ssrc() {
        let mut session = session();
        let mut out = [0_u8; 256];
        let n = session
            .send_bye(&mut out, Duration::ZERO, b"hanging up", 0.5)
            .expect("room");

        let compound = CompoundPacket::parse(&out[..n]).expect("a compound packet");
        let mut packets = compound.packets();
        assert!(matches!(
            packets.next(),
            Some(RtcpPacket::ReceiverReport(_))
        ));
        assert!(matches!(
            packets.next(),
            Some(RtcpPacket::SourceDescription(_))
        ));
        let Some(RtcpPacket::Goodbye(bye)) = packets.next() else {
            panic!("a goodbye third");
        };
        assert_eq!(bye.sources().collect::<Vec<_>>(), [0x0102_0304]);
        assert_eq!(bye.reason(), Some(&b"hanging up"[..]));
    }

    #[test]
    fn rtcp_due_waits_until_its_own_deadline_and_then_says_send() {
        let mut session = session();
        let Due::Wait(deadline) = session.rtcp_due(Duration::ZERO, 0.5) else {
            panic!("a brand new session has nothing due yet");
        };
        assert_eq!(session.rtcp_due(Duration::ZERO, 0.5), Due::Wait(deadline));
        assert_eq!(session.rtcp_due(deadline, 0.5), Due::Send);
    }

    #[test]
    fn building_a_report_reschedules_the_next_deadline_forward() {
        let mut session = session();
        let Due::Wait(first) = session.rtcp_due(Duration::ZERO, 0.5) else {
            panic!("not due yet");
        };
        let (_, next) = session
            .build_report(&mut [0_u8; 256], first, 0, 0.5)
            .expect("room");
        assert!(next > first, "the schedule moves forward, not back");
    }

    #[test]
    fn is_rtcp_tells_a_built_report_apart_from_an_rtp_packet_for_rtcp_mux() {
        // RFC 5761 §4: demultiplexing a socket carrying both by payload type
        let mut session = session();
        let mut out = [0_u8; 256];
        let (n, _) = session
            .build_report(&mut out, Duration::ZERO, 0, 0.5)
            .expect("room");
        assert!(crate::rtcp::is_rtcp(&out[..n]));

        let rtp = datagram(7, 100, 8);
        assert!(!crate::rtcp::is_rtcp(&rtp));
    }
}
