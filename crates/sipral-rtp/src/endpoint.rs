// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! One stream in each direction, and everything that has to be true before a
//! datagram is believed.

use std::net::SocketAddr;
use std::time::Duration;

use crate::dtmf::{EVENT_LEN, EventSender, HALF_CLOCK, Outgoing};
use crate::emodel::{self, BurstRatio, CodecQualityModel, EModelInputs};
use crate::playout::{Activity, BufferConfig, Insert, JitterBuffer, Pull, Quality, clock_ticks};
use crate::rtcp::{
    CNAME, ChunkBuilder, CompoundBuilder, CompoundPacket, GoodbyeBuilder, ReceiverReportBuilder,
    ReportBlock, RtcpBuildError, RtcpError, RtcpPacket, SdesItem, SenderInfo, SenderOrReceiver,
    SenderReportBuilder, SourceDescriptionBuilder,
};
use crate::rtcp_stats::{ReceptionTracker, round_trip_time};
use crate::rtcp_timer::{Due, IntervalTimer};
use crate::rtcp_xr::{
    JitterBufferAdaptive, PacketLossConcealment, RxConfig, UNAVAILABLE, VoipMetricsBlock,
    XrPacketBuilder,
};
use crate::source::{SeqUpdate, SequenceState};
use crate::srtp::{Master, Policy, Rekeyed, Security, SrtpError};
use crate::wire::{
    BuildError, FIXED_HEADER_LEN, PacketBuilder, PacketError, PayloadTypes, RtpHeader, RtpPacket,
};

/// What a re-negotiation onto a different codec changes about a stream that
/// is going to carry on regardless.
///
/// Deliberately not a [`StreamConfig`]. That one opens a stream and therefore
/// carries the three fields RFC 3550 §5.1 wants drawn once and never redrawn —
/// the synchronization source, the first sequence number, the first timestamp.
/// A stream being re-formatted has all three already, and the whole point of
/// [`RtpSession::reformat`] is that it must not be handed the chance to take
/// them again: a source that restarts its counters reads as a different source
/// (§5.1), and under SRTP it reads as a repeated packet index under a key that
/// has already sent.
#[derive(Clone, Debug)]
pub struct StreamFormat {
    /// The payload type we send from here on.
    pub payload_type: u8,
    /// The payload types we will accept from here on.
    pub accepted: PayloadTypes,
    /// Timestamp ticks per second, from the new payload format.
    pub clock_rate: u32,
    /// Where the fresh pair of descriptions says the peer is.
    pub remote: SocketAddr,
    /// Whether we stop sending during silence.
    pub silence_suppression: bool,
    /// How the de-jitter buffer is sized at the new packet length.
    pub playout: BufferConfig,
}

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
    /// Whether the offer/answer exchange negotiated RTCP XR VoIP Metrics
    /// reporting for this stream: an `a=rtcp-xr` attribute carrying the
    /// `voip-metrics` metrics token (§5.1) was in the offer and answer,
    /// per the direction-dependent rules of §5.2. [`RtpSession::build_report`]
    /// includes a VoIP Metrics block only when this is set: §5.1 "When
    /// the 'rtcp-xr' attribute is present, participants SHOULD NOT send
    /// XR blocks other than the ones indicated by the parameters", and
    /// this stack sends no XR block this stream was never asked for.
    pub voip_metrics_xr: bool,
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
    /// SRTP refused it: a bad tag, a replay, or a packet too short to be one.
    /// On a secured stream this is also what a plain RTP packet becomes, and
    /// deliberately — falling back to the clear is worse than dropping the
    /// audio.
    Insecure(SrtpError),
    /// The stream agreed to be secured and its keys have not arrived, so
    /// there is nothing to verify the packet with (see
    /// [`RtpSession::awaiting`]). A peer that starts sending before its own
    /// handshake finishes is the ordinary way this happens.
    NotKeyed,
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
    /// From somewhere other than the peer this session is talking to, so
    /// nothing in it was believed.
    ForeignAddress,
    /// Not a well-formed compound RTCP packet.
    Malformed(RtcpError),
    /// SRTCP refused it, so nothing in it was read.
    Insecure(SrtpError),
    /// The stream agreed to be secured and its keys have not arrived, so
    /// nothing in it could be verified and nothing in it was read — not even
    /// the size, which §6.3.3 would otherwise fold into this session's own
    /// report interval.
    NotKeyed,
}

/// A [`Duration`] into the whole-millisecond field every RFC 3611 §4.7.3
/// delay carries, saturating rather than wrapping a path slower than
/// sixteen bits of milliseconds can name (65.535 seconds — no call is
/// waiting that long for an RTCP round trip).
fn duration_to_field_ms(duration: Duration) -> u16 {
    u16::try_from(duration.as_millis()).unwrap_or(u16::MAX)
}

/// RFC 3611 §4.7.3's own worked conversion: "one way symmetric voice path
/// delay = (RTD + ESD(A) + ESD(B)) / 2" — halved here because this stack
/// only ever knows one of the two end-system delays the note assumes, its
/// own, and the algebra collapses to a single division by the same two.
fn one_way_symmetric_delay_ms(round_trip_delay_ms: u16, end_system_delay_ms: u16) -> u32 {
    u32::midpoint(
        u32::from(round_trip_delay_ms),
        u32::from(end_system_delay_ms),
    )
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
    /// The last RFC 3611 §4.7 VoIP Metrics block the far end sent about this
    /// session's own stream: what it measured of the audio it received from
    /// here.
    far_voip_metrics: Option<VoipMetricsBlock>,
    /// The SRTP contexts, when the negotiation produced keys. Held here
    /// rather than left to the caller so that the order of §3.3 — protect
    /// after building, verify before believing — is not something a caller
    /// can get wrong.
    security: Protection,
}

/// Whether this stream is secured, and whether it can be yet.
///
/// Two of these are the whole of SDES: a stream is either keyed from the
/// moment it opens or it was never meant to be. The third is what DTLS-SRTP
/// needs, and it is the reason this is an enumeration rather than an
/// `Option`: RFC 5764 puts the key exchange on the media path, so a stream
/// agreed on `UDP/TLS/RTP/SAVP` exists — with an address, a codec and a
/// sequence number — for as long as a handshake takes before any key is
/// available to it.
///
/// What must not happen in that window is a packet in the clear. A stream
/// that agreed to be secured and sent one unprotected packet has leaked the
/// audio it was asked to protect, and it has done it while looking like a
/// working call. So the window is a state of its own rather than an absence,
/// and every path out of this type goes through it.
// One of these lives inside one `RtpSession` and nothing moves it, so the
// difference between the variants costs nothing: the enumeration is exactly
// as wide as the `Option<Security>` it replaced, which is what a session has
// always carried. Boxing the keys to even them up would put an indirection on
// the path every packet takes, to save nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum Protection {
    /// The stream was never meant to be secured.
    Clear,
    /// The description agreed that this stream is secured, and the keys have
    /// not arrived.
    ///
    /// The policy held here is not the one that will be installed — RFC 5764
    /// §4.1.2 has the profile chosen inside the handshake rather than in the
    /// signalling — but the most expensive one that could be, so that a
    /// caller sizing a buffer against [`RtpSession::rtp_overhead`] before the
    /// keys arrive sizes it for whichever profile the handshake settles on.
    Awaited(Policy),
    /// Keys.
    Open(Security),
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

// each bool here is an independent yes/no fact learned about the remote
// side at a different point in the stream's life, not a state a caller
// steps through, which is what the lint is guarding against
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug)]
struct Inbound {
    accepted: PayloadTypes,
    signalled: SocketAddr,
    latch: Option<SocketAddr>,
    /// Whether the latch follows the far end rather than holding: a packet
    /// from another address is taken, and moves the latch there, once it has
    /// passed everything a packet from the latched address would have to.
    /// See [`RtpSession::set_following`].
    following: bool,
    /// Where RTCP is heard from, latched the way `latch` is but only onto a
    /// host this session already had reason to expect. Separate because
    /// RFC 3550 §11 puts RTCP on its own port, so the port differs from the
    /// RTP one even when the host does not.
    rtcp_latch: Option<SocketAddr>,
    source: Option<u32>,
    /// The SSRC an SR or RR has named itself with, latched the way
    /// `source` is but from RTCP instead of RTP.
    ///
    /// A source that never sends RTP — recvonly, or a call on hold — is
    /// still a member by §6.3.3's own rule ("received from a
    /// participant" says nothing about which protocol), but `source`
    /// never learns its SSRC, since only RTP sets that one. Kept
    /// separately from `source` rather than merged into it because the
    /// two answer different questions once both are known: `source` is
    /// who §6.4.1's reception report describes and whose sequence numbers
    /// feed the jitter buffer, while this is only ever read to match a
    /// BYE against whichever identifier this session actually has for
    /// the remote side.
    rtcp_source: Option<u32>,
    sequence: SequenceState,
    buffer: JitterBuffer,
    rtcp: ReceptionTracker,
    /// Whether §6.3's member table already has an entry for the remote
    /// side, so it is only counted once.
    member_known: bool,
    /// Whether the remote side has been heard sending RTP, for the sender
    /// count §6.3.1's interval calculation splits out from members.
    sender_known: bool,
    /// Whether a BYE naming the remote source has already been taken in.
    ///
    /// §6.2.1: "Entries MAY be deleted from the table when an RTCP BYE
    /// packet with the corresponding SSRC identifier is received... the
    /// entry SHOULD be marked as having received a BYE". §6.3.4 removes a
    /// table entry, and the count with it, only "if present" — so a second
    /// BYE for a source already gone finds no entry left to remove and must
    /// leave `members` and `senders` alone rather than repeat the departure
    /// against a group that no longer includes it.
    departed: bool,
    /// Whether RFC 3611 XR VoIP Metrics reporting was negotiated for this
    /// stream. See [`StreamConfig::voip_metrics_xr`].
    voip_metrics_xr: bool,
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
                following: false,
                rtcp_latch: None,
                source: None,
                rtcp_source: None,
                sequence: SequenceState::new(),
                buffer: JitterBuffer::new(config.clock_rate, &config.playout),
                rtcp: ReceptionTracker::new(),
                member_known: false,
                sender_known: false,
                departed: false,
                voip_metrics_xr: config.voip_metrics_xr,
            },
            cname: config.cname.clone(),
            timer: IntervalTimer::new(config.rtcp_bandwidth, first_report_size, unit_interval),
            round_trip: None,
            far_voip_metrics: None,
            security: Protection::Clear,
        }
    }

    /// The same stream, with SRTP over it.
    ///
    /// Everything sent is protected on the way out and everything arriving is
    /// verified before any of it is believed, in the order RFC 3711 §3.3 sets
    /// out. A packet that fails is dropped as [`Discard::Insecure`]; a plain
    /// RTP packet arriving here fails too, because it cannot carry a tag.
    ///
    /// The keys come from the key management the signalling did — SDES, in
    /// practice — and never from here: this crate draws no random numbers.
    #[must_use]
    pub fn protected(config: &StreamConfig, unit_interval: f64, security: Security) -> Self {
        Self {
            security: Protection::Open(security),
            ..Self::new(config, unit_interval)
        }
    }

    /// The same stream, secured by keys that have not arrived yet.
    ///
    /// DTLS-SRTP (RFC 5764) agrees in the signalling that a stream is
    /// protected and then runs the handshake that keys it on the media path,
    /// so there is a window — a round trip at best, two minutes of
    /// retransmissions at worst — in which the stream exists and has no key.
    ///
    /// A stream opened this way sends nothing and believes nothing until
    /// [`RtpSession::keyed`] hands it the keys: [`BuildError::NotKeyed`]
    /// comes back from every builder and [`Discard::NotKeyed`] from
    /// everything that arrives. That is the point of the constructor. The
    /// alternative — opening in the clear and turning protection on when the
    /// handshake finishes — is a call that sends the first seconds of its
    /// audio unencrypted and reports itself as secure.
    ///
    /// `most` is the most expensive policy the handshake could settle on.
    /// RFC 5764 §4.1.2 has the profile chosen inside the handshake rather
    /// than in the signalling, so the overhead a caller sizes a buffer
    /// against before the keys arrive has to be an upper bound on whichever
    /// one it settles on — see [`RtpSession::rtp_overhead`].
    #[must_use]
    pub fn awaiting(config: &StreamConfig, unit_interval: f64, most: Policy) -> Self {
        Self {
            security: Protection::Awaited(most),
            ..Self::new(config, unit_interval)
        }
    }

    /// Hand a stream that was opened awaiting its keys the keys it was
    /// waiting for, and say whether it took them.
    ///
    /// `false` for a stream that is not waiting, and that is the whole of the
    /// safety here: this is not a path by which a plain stream becomes
    /// secured, nor one by which a running secured stream is re-keyed behind
    /// the caller's back. A stream in the clear stays in the clear —
    /// encryption appearing mid-call is not something the far end agreed to —
    /// and a stream already open re-keys through [`RtpSession::rekey_local`]
    /// and [`RtpSession::rekey_remote`], which keep the packet index RFC 3711
    /// §9.1 requires them to keep.
    ///
    /// The index does not restart here either: nothing was ever sent under
    /// the old state, because there was no old state to send under.
    ///
    /// The receiving context starts at a rollover counter of zero, which RFC
    /// 3711 §3.3.1 would otherwise want supplied out of band for a stream
    /// already in flight. It is right here because of what the far end is
    /// doing while this waits: it cannot protect anything before its own half
    /// of the same handshake finishes, and a handshake finishes in a round
    /// trip or gives up in two minutes — either way long before the 65 536
    /// packets a rollover takes, which at twenty milliseconds apiece is
    /// twenty-two.
    pub fn keyed(&mut self, security: Security) -> bool {
        if !matches!(self.security, Protection::Awaited(_)) {
            return false;
        }
        self.security = Protection::Open(security);
        true
    }

    /// Whether this stream agreed to be secured and has no keys yet.
    #[must_use]
    pub const fn awaiting_keys(&self) -> bool {
        matches!(self.security, Protection::Awaited(_))
    }

    /// Whether what this stream sends is protected and what it believes was.
    ///
    /// The state and not the negotiation: a stream that agreed to be secured
    /// and is still waiting for its keys answers `false`, because nothing has
    /// been encrypted yet and a padlock drawn from this would be lying for
    /// the length of a handshake.
    #[must_use]
    pub const fn is_protected(&self) -> bool {
        matches!(self.security, Protection::Open(_))
    }

    /// Octets every packet sent on this stream is longer than the packet the
    /// builders produce, which is what a caller has to add to its buffer.
    /// Zero when the stream is not secured.
    ///
    /// A stream still waiting for its keys answers with the most its
    /// handshake could cost rather than with nothing, so that a buffer sized
    /// once at the start of a call is still big enough after the keys land.
    #[must_use]
    pub const fn rtp_overhead(&self) -> usize {
        match &self.security {
            Protection::Open(security) => security.rtp_overhead(),
            Protection::Awaited(most) => most.rtp_overhead(),
            Protection::Clear => 0,
        }
    }

    /// The same for RTCP, whose overhead is larger: the index word travels
    /// alongside the tag.
    #[must_use]
    pub const fn rtcp_overhead(&self) -> usize {
        match &self.security {
            Protection::Open(security) => security.rtcp_overhead(),
            Protection::Awaited(most) => most.rtcp_overhead(),
            Protection::Clear => 0,
        }
    }

    /// The room a builder is given: the buffer, less what SRTP will add to
    /// what it writes. `need` is the whole protected packet, so a buffer that
    /// is too small is refused in the caller's terms rather than in the
    /// builder's.
    fn room(out: &mut [u8], need: usize, overhead: usize) -> Option<&mut [u8]> {
        if out.len() < need {
            return None;
        }
        let room = out.len().checked_sub(overhead)?;
        out.get_mut(..room)
    }

    fn protect_rtp(&mut self, out: &mut [u8], built: usize) -> Result<usize, BuildError> {
        match &mut self.security {
            Protection::Open(security) => security
                .protect_rtp(out, built)
                .map_err(BuildError::Secured),
            Protection::Awaited(_) => Err(BuildError::NotKeyed),
            Protection::Clear => Ok(built),
        }
    }

    fn protect_rtcp(&mut self, out: &mut [u8], built: usize) -> Result<usize, RtcpBuildError> {
        match &mut self.security {
            Protection::Open(security) => security
                .protect_rtcp(out, built)
                .map_err(RtcpBuildError::Secured),
            Protection::Awaited(_) => Err(RtcpBuildError::NotKeyed),
            Protection::Clear => Ok(built),
        }
    }

    /// Take in a datagram and the address it came from.
    ///
    /// The checks are in the order that costs least: the shape of the packet,
    /// then the payload type, then where it came from, then who sent it, then
    /// whether its sequence number belongs to the stream. A packet only
    /// reaches the buffer once all five agree.
    ///
    /// One of them is taken early. Once the stream has latched, a datagram
    /// from any other address is refused before anything else looks at it,
    /// SRTP included. That check reads nothing out of the datagram, and SRTP
    /// records an index the moment a tag verifies, so a copy refused only
    /// afterwards would already have spent the index of the genuine packet and
    /// turned the genuine one into the replay.
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
    pub fn receive(&mut self, datagram: &mut [u8], from: SocketAddr, now: Duration) -> Received {
        if !self.inbound.following && self.inbound.latch.is_some_and(|latched| latched != from) {
            return Received::Dropped(Discard::ForeignAddress);
        }

        // §3.3: verify, then decrypt, then believe. Nothing below this line
        // sees a packet whose tag did not check out
        let plain = match &mut self.security {
            Protection::Open(security) => match security.unprotect_rtp(datagram) {
                Ok(len) => datagram.get(..len).unwrap_or_default(),
                Err(error) => return Received::Dropped(Discard::Insecure(error)),
            },
            // there is no key to verify it with, and a packet believed
            // without one is the same fallback in the other direction: a peer
            // that sends audio before the handshake finishes gets it dropped,
            // not played
            Protection::Awaited(_) => return Received::Dropped(Discard::NotKeyed),
            Protection::Clear => &*datagram,
        };
        let packet = match RtpPacket::parse(plain) {
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
        // from any other address is dropped rather than merged, which is the
        // first thing this function does. Merging is how someone who can guess
        // a port gets their audio into the call. A stream told to follow
        // (`set_following`) moves an already closed latch too, but only at the
        // very end, for a packet the stream took
        if self.inbound.latch.is_none() {
            self.inbound.latch = Some(from);
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
            Insert::Accepted | Insert::Displaced(_) => {
                // a packet from another address moves a following latch only
                // once it has passed everything: the source, the sequence and
                // the buffer as well as SRTP, so a stranger's packet under an
                // SSRC it guessed wrong, or a copy of one already heard, does
                // not move it
                if self.inbound.following {
                    self.inbound.latch = Some(from);
                }
                Received::Queued
            }
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
    /// [`BuildError::Short`] when `out` cannot hold the packet,
    /// [`BuildError::PayloadType`] for a payload type this stream was
    /// configured with that does not fit the field, and
    /// [`BuildError::NotKeyed`] on a stream still waiting for a handshake's
    /// keys. In every case nothing has been written and no sequence number
    /// has been spent — which is why the last of them is decided here rather
    /// than left to the protection step, where the packet would already be
    /// sitting in the caller's buffer in the clear.
    pub fn send(
        &mut self,
        payload: &[u8],
        samples: u32,
        out: &mut [u8],
    ) -> Result<usize, BuildError> {
        if self.awaiting_keys() {
            return Err(BuildError::NotKeyed);
        }
        let header = RtpHeader {
            marker: self.outbound.silence_suppression && self.outbound.spurt_start,
            payload_type: self.outbound.payload_type,
            sequence: self.outbound.sequence,
            timestamp: self.outbound.timestamp,
            ssrc: self.outbound.ssrc,
        };
        let overhead = self.rtp_overhead();
        let need = FIXED_HEADER_LEN + payload.len() + overhead;
        let offered = out.len();
        let room =
            Self::room(out, need, overhead).ok_or(BuildError::Short { need, got: offered })?;
        let built = PacketBuilder::new(header, payload).write(room)?;
        let written = self.protect_rtp(out, built)?;
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

    /// Begin a named telephone event at the timestamp the next packet would
    /// have carried.
    ///
    /// An event begins at the instant its RTP timestamp names (RFC 4733
    /// §2.2.1), and that instant is the audio stream's to give: §2.1 has
    /// events "use the same sequence number and timestamp base as the regular
    /// audio channel". Drive the sender this returns with
    /// [`EventSender::update`] while the digit is held, [`EventSender::end`]
    /// when it is released and [`EventSender::retransmit`] twice after that,
    /// putting each packet on the wire with [`RtpSession::send_event`].
    #[must_use]
    pub const fn start_event(&self, event: u8, volume: u8) -> EventSender {
        EventSender::new(event, volume, self.outbound.timestamp)
    }

    /// Write one packet of an outgoing named telephone event into `out` and
    /// say how long it is.
    ///
    /// `payload_type` is the one the answer settled on: the format "does not
    /// have a static payload type number, but uses an RTP payload type number
    /// established dynamically and out-of-band" (§2.1), so it is neither this
    /// stream's audio payload type nor anything a configuration could have
    /// fixed in advance.
    ///
    /// Everything else comes from the stream, because §2.1 says it must. The
    /// event carries the audio SSRC and spends the next sequence number, each
    /// packet as an audio packet would — retransmissions included, "to permit
    /// the receiver to detect lost packets" (§2.5.1.6).
    ///
    /// The audio timestamp does not move for the event's own packets, which
    /// all carry the instant the event began (§2.5.1.2). It moves across the
    /// event instead: one that began at `t` and reports a duration of `d`
    /// ended at `t + d`, the arithmetic §2.5.1.3 does for itself when a long
    /// event starts a new segment "with the RTP timestamp set to the time at
    /// which the previous segment ended". That is where the audio after the
    /// digit resumes. The two retransmissions of the final packet report the
    /// same duration and so add nothing to it; the real time they take is
    /// silence like any other, and [`RtpSession::suppress`] is what accounts
    /// for that.
    ///
    /// # Errors
    /// [`BuildError::Short`] when `out` cannot hold the packet,
    /// [`BuildError::PayloadType`] for an event payload type too wide for the
    /// field, and [`BuildError::EventVolume`] for a volume too wide for its
    /// own. Either way nothing has been written and no sequence number has
    /// been spent.
    pub fn send_event(
        &mut self,
        event: Outgoing,
        payload_type: u8,
        out: &mut [u8],
    ) -> Result<usize, BuildError> {
        if self.awaiting_keys() {
            return Err(BuildError::NotKeyed);
        }
        let mut payload = [0_u8; EVENT_LEN];
        if event.report.write(&mut payload).is_err() {
            // the buffer is exactly as wide as the payload, so the volume is
            // the only thing left that can refuse to be written
            return Err(BuildError::EventVolume(event.report.volume));
        }
        let header = RtpHeader {
            marker: event.marker,
            payload_type,
            sequence: self.outbound.sequence,
            timestamp: event.timestamp,
            ssrc: self.outbound.ssrc,
        };
        let overhead = self.rtp_overhead();
        let need = FIXED_HEADER_LEN + EVENT_LEN + overhead;
        let offered = out.len();
        let room =
            Self::room(out, need, overhead).ok_or(BuildError::Short { need, got: offered })?;
        let built = PacketBuilder::new(header, &payload).write(room)?;
        let written = self.protect_rtp(out, built)?;
        self.outbound.sequence = self.outbound.sequence.wrapping_add(1);

        let ended = event
            .timestamp
            .wrapping_add(u32::from(event.report.duration));
        // timestamps wrap, so "past where the stream has already reached" is
        // the half of the circle ahead of it. An event ending behind that —
        // a caller that kept sending audio after the digit started — must not
        // drag the audio clock backwards.
        if (1..HALF_CLOCK).contains(&ended.wrapping_sub(self.outbound.timestamp)) {
            self.outbound.timestamp = ended;
        }
        // no audio went out for as long as the event lasted, so whatever
        // follows it begins a talk spurt (RFC 3551 §4.1)
        self.outbound.spurt_start = true;

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

    /// Whether this stream stops sending during silence from now on, which
    /// is what lets the marker bit say a talk spurt starts (RFC 3551 §4.1):
    /// a stream that began with every frame sent and was then renegotiated
    /// into one that is not.
    pub fn set_silence_suppression(&mut self, on: bool) {
        self.outbound.silence_suppression = on;
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
        self.inbound.rtcp_latch = None;
    }

    /// Let the latch follow the far end, or hold it again.
    ///
    /// While following, a packet from an address other than the latched one
    /// is not refused for that: it is checked like any other — SRTP, shape,
    /// payload type, source, sequence, a copy already heard — and moves the
    /// latch to its address only once the stream has taken it.
    /// For a far end that may legitimately send from more than one address
    /// before anything has settled which one it will keep: an ICE agent's,
    /// which sends on any pair its checks have proved until a pair is
    /// selected (RFC 8445 §12.1). Held again, the latch stays where the last
    /// packet put it. A stream starts out holding.
    pub fn set_following(&mut self, following: bool) {
        self.inbound.following = following;
    }

    /// Listen to a different synchronization source, for a far end that has
    /// been told to change it. Everything held for the old one is dropped,
    /// since it belongs to a stream that has ended.
    ///
    /// §6.3's membership bookkeeping goes with it only when the old source
    /// left by BYE. A far end that said goodbye under its old SSRC and came
    /// back under a new one — what a re-INVITE or an ICE restart produces —
    /// was taken out of the count, so the source followed now is counted
    /// afresh. A far end that changed its SSRC without a BYE is still the one
    /// remote participant it was, already in the count; counting it again
    /// would add a member for every change and stretch the report interval
    /// with each one.
    pub fn follow(&mut self, ssrc: u32) {
        self.inbound.source = Some(ssrc);
        self.inbound.rtcp_source = None;
        self.inbound.sequence.reset();
        self.inbound.buffer.restart();
        self.inbound.buffer.begin_source();
        self.inbound.rtcp = ReceptionTracker::new();
        self.forget_departed();
    }

    /// The membership flags start again for the next source only if the one
    /// they describe has left; see [`RtpSession::follow`].
    fn forget_departed(&mut self) {
        if self.inbound.departed {
            self.inbound.member_known = false;
            self.inbound.sender_known = false;
            self.inbound.departed = false;
        }
    }

    /// Listen to whichever source arrives next. For a stream that has been
    /// re-negotiated, where what the far end will call itself is not known in
    /// advance.
    ///
    /// As with [`RtpSession::follow`], the §6.3 membership flags start again
    /// only when the source they describe left by BYE.
    pub fn resync(&mut self) {
        self.inbound.source = None;
        self.inbound.rtcp_source = None;
        self.inbound.sequence.reset();
        self.inbound.buffer.restart();
        self.inbound.buffer.begin_source();
        self.inbound.rtcp = ReceptionTracker::new();
        self.forget_departed();
    }

    /// Carry this stream on under a different codec.
    ///
    /// Everything that belongs to the stream stays: the synchronization
    /// source, the sequence number and timestamp it has reached, both SRTP
    /// contexts with their rollover counter and SRTCP index, the octet and
    /// packet totals, the reception tracker, the RTCP interval and the CNAME.
    /// Everything measured in the old codec's units is rebuilt, because a
    /// clock rate and a packet length are what those units are.
    ///
    /// Two of those are not housekeeping. RFC 3550 §5.1 has a source that
    /// resets its counters read as a different source, so a stream whose
    /// sequence number rewound would be heard as somebody else arriving. And
    /// under SRTP the packet index is `2^16 · ROC + sequence`, so a rewound
    /// sequence under an unchanged master key hands the same keystream to a
    /// second packet — the reuse RFC 3711 §9.1 exists to forbid. Neither is
    /// visible in a capture until it is too late to ask.
    ///
    /// The timestamp carries on in the new clock rate rather than being
    /// converted (RFC 7160's case). The source has not changed, so a receiver
    /// reads the discontinuity as one, and drawing a fresh source to signal it
    /// would cost more than it explains.
    ///
    /// A peer that also moved its address is relocated and re-synchronised,
    /// for the reason [`RtpSession::relocate`] gives.
    pub fn reformat(&mut self, format: &StreamFormat) {
        self.outbound.payload_type = format.payload_type;
        self.outbound.clock_rate = format.clock_rate;
        self.outbound.silence_suppression = format.silence_suppression;
        // the first packet of the new format starts a talkspurt: §4.1's
        // marker bit says "the first packet after a silence", and a decoder
        // that has just been replaced is exactly that
        self.outbound.spurt_start = true;
        self.inbound.accepted = format.accepted;
        self.inbound
            .buffer
            .reformat(format.clock_rate, &format.playout);
        if self.inbound.signalled != format.remote {
            self.relocate(format.remote);
            self.resync();
        }
    }

    /// Protect what this stream sends under what a re-negotiation settled on,
    /// for one that moved this endpoint's own `a=crypto` line.
    ///
    /// Nothing else about the stream moves: the same sequence numbers, the
    /// same timestamps, the same source. As [`Security::rekey_local`], and
    /// [`Rekeyed`] is what decides the packet index.
    ///
    /// A stream that was never given keys is left alone. A negotiation cannot
    /// arrive here having turned encryption on — that is a different session,
    /// opened rather than re-keyed — so there is nothing to do and no error to
    /// report. A stream still waiting for a handshake's keys is left alone
    /// too: its first keys arrive through [`RtpSession::keyed`], and a
    /// re-negotiation that reaches it before they do has nothing to move.
    pub fn rekey_local(&mut self, policy: Policy, master: Master, what: Rekeyed) {
        if let Protection::Open(security) = &mut self.security {
            security.rekey_local(policy, master, what);
        }
    }

    /// Open what arrives under what a re-negotiation settled on, for one in
    /// which the far end moved its own `a=crypto` line.
    ///
    /// A key being replaced keeps opening packets for a short while, because
    /// the far end's answer arrives before the far end's first packet under
    /// the key it names. As [`Security::rekey_remote`].
    pub fn rekey_remote(&mut self, policy: Policy, master: Master, what: Rekeyed) {
        if let Protection::Open(security) = &mut self.security {
            security.rekey_remote(policy, master, what);
        }
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

    /// This stream's VoIP Metrics Report Block (RFC 3611 §4.7), from what
    /// its jitter buffer has classified so far and, if `codec` names one
    /// G.113 Appendix I tabulates, the simplified E-model of ITU-T G.107.
    /// Available whenever an inbound source is known,
    /// independent of whether RTCP XR reporting was negotiated
    /// ([`StreamConfig::voip_metrics_xr`]) — that flag gates only whether
    /// [`RtpSession::build_report`] puts this on the wire as an XR packet;
    /// the same figures are what an RFC 6035 quality report sends on call
    /// end regardless.
    ///
    /// `None` when this stream has not yet identified a source to report
    /// on ([`RtpSession::remote_ssrc`]).
    #[must_use]
    pub fn voip_metrics(&self, codec: Option<CodecQualityModel>) -> Option<VoipMetricsBlock> {
        let ssrc = self.inbound.source?;
        let burst_gap = self.inbound.buffer.burst_gap_metrics();
        let round_trip_delay_ms = duration_to_field_ms(self.round_trip.unwrap_or_default());
        // §4.7.3: "This value SHOULD be provided in all VoIP metrics
        // reports. If an implementation is unable to provide the data,
        // the value 0 MUST be used." This stack has no visibility into
        // the sending side's own accumulation and encoding delay, so it
        // cannot assemble the end-to-end figure §4.7.3 defines and uses
        // that fallback rather than reporting only its own jitter-buffer
        // half of it as though it were the whole thing.
        let end_system_delay_ms = 0;
        let one_way_delay_ms = one_way_symmetric_delay_ms(round_trip_delay_ms, end_system_delay_ms);
        // §4.7.1 keeps loss and jitter-buffer discards apart only to say
        // where the damage was done: "Both have equal effect on the quality
        // of the voice stream". A packet the buffer threw out is as missing
        // from the earpiece as one the network lost, so `Ppl` is the two
        // together.
        let missing = u16::from(burst_gap.loss_rate) + u16::from(burst_gap.discard_rate);
        let report = emodel::evaluate(EModelInputs {
            one_way_delay_ms,
            packet_loss_percent: f64::from(missing) * (100.0 / 256.0),
            // No separate measurement of loss burstiness feeds this yet,
            // so G.107's own §7.5 default applies: "when packet loss is
            // random (i.e., independent) BurstR = 1".
            burst_ratio: BurstRatio::RANDOM,
            codec,
        });
        let quality = self.inbound.buffer.quality();
        Some(VoipMetricsBlock {
            ssrc,
            loss_rate: burst_gap.loss_rate,
            discard_rate: burst_gap.discard_rate,
            burst_density: burst_gap.burst_density,
            gap_density: burst_gap.gap_density,
            burst_duration_ms: burst_gap.burst_duration_ms,
            gap_duration_ms: burst_gap.gap_duration_ms,
            round_trip_delay_ms,
            end_system_delay_ms,
            // §4.7.4: no signal-level detector runs over decoded audio in
            // this crate, so every signal-related field it defines stays
            // at the sentinel rather than a fabricated reading.
            signal_level_dbm0: UNAVAILABLE.cast_signed(),
            noise_level_dbm0: UNAVAILABLE.cast_signed(),
            rerl_db: UNAVAILABLE,
            gmin: self.inbound.buffer.gmin(),
            r_factor: report.r_factor,
            ext_r_factor: report.ext_r_factor,
            mos_lq: report.mos_lq,
            mos_cq: report.mos_cq,
            // §4.7.6: this stack's jitter buffer adapts its delay
            // (`crate::playout`'s own module documentation) but does not
            // itself perform packet loss concealment — that lives with
            // the codec, above this crate, and is not visible here.
            rx_config: RxConfig {
                plc: PacketLossConcealment::Unspecified,
                jba: JitterBufferAdaptive::Adaptive,
                jb_rate: 0,
            },
            jb_nominal_ms: duration_to_field_ms(quality.target_delay),
            jb_maximum_ms: duration_to_field_ms(quality.delay),
            // §4.7.7: "For a fixed jitter buffer, this SHOULD be the same
            // as the Maximum Jitter Buffer Delay." This buffer's ceiling
            // is fixed at its own configured maximum, not the momentary
            // depth `jb_maximum_ms` reports.
            jb_abs_max_ms: self.inbound.buffer.max_delay_ms(),
        })
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
    /// `codec`, forwarded to [`RtpSession::voip_metrics`], is only read
    /// when this stream negotiated RTCP XR VoIP Metrics reporting
    /// ([`StreamConfig::voip_metrics_xr`]); a stream that did not never
    /// builds the block at all, let alone spends bytes sending it.
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
        codec: Option<CodecQualityModel>,
    ) -> Result<(usize, Duration), RtcpBuildError> {
        if self.awaiting_keys() {
            return Err(RtcpBuildError::NotKeyed);
        }
        let sequence = self.inbound.sequence;
        let block = self
            .inbound
            .source
            .map(|ssrc| self.inbound.rtcp.block(ssrc, &sequence, ntp));
        let reports: &[ReportBlock] = block.as_slice();
        let voip_metrics = self
            .inbound
            .voip_metrics_xr
            .then(|| self.voip_metrics(codec))
            .flatten();

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

        let mut compound = CompoundBuilder::new(report, sdes);
        if let Some(voip_metrics) = voip_metrics {
            compound = compound.with_xr(XrPacketBuilder {
                ssrc: self.outbound.ssrc,
                voip_metrics: Some(voip_metrics),
            });
        }
        let overhead = self.rtcp_overhead();
        let need = compound.encoded_len() + overhead;
        let offered = out.len();
        let room =
            Self::room(out, need, overhead).ok_or(RtcpBuildError::Short { need, got: offered })?;
        let built = compound.write(room)?;
        let written = self.protect_rtcp(out, built)?;
        self.outbound.sent_since_report = false;
        // §6.3.3 counts what goes on the wire, which is the protected packet
        let next = self.timer.sent(now, written, unit_interval);
        Ok((written, next))
    }

    /// Build a BYE for this stream's own SSRC, to send on hangup, and fold
    /// its size into the schedule (§6.3.7). Always writes the packet
    /// immediately — nothing in this crate queues one for later — but
    /// which bookkeeping applies depends on which of §6.3.7's two branches
    /// a session this size is in, per [`RtpSession::bye_should_back_off`]:
    ///
    /// * Past the fifty-member threshold, bullet one's reset applies —
    ///   "the participant MUST execute the following algorithm" — done by
    ///   `IntervalTimer::leaving`: `members`, `senders` and `pmembers`
    ///   collapse to just this participant.
    /// * At or below it, this reads the RFC's other branch — "the
    ///   participant MAY send a BYE packet immediately" — as skipping
    ///   that reset entirely and transmitting the BYE exactly like any
    ///   other RTCP packet (bullet three), through
    ///   `IntervalTimer::sent_bye`: `members` and `senders` are left as
    ///   they were, since nothing here says a session too small to need
    ///   the backoff algorithm should also forget who is in it.
    ///
    /// Either branch marks the session as leaving. §6.3.4's rule for a
    /// *received* BYE carves out "the case when an RTCP BYE is to be
    /// transmitted" without conditioning that on group size, so from here
    /// on [`RtpSession::rtcp_receive`]'s BYE handling follows §6.3.7
    /// bullet two instead — a BYE from someone else counts `members` up,
    /// not down — regardless of which branch this call took.
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
        if self.awaiting_keys() {
            return Err(RtcpBuildError::NotKeyed);
        }
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
        let overhead = self.rtcp_overhead();
        let need = compound.encoded_len() + overhead;
        let offered = out.len();
        let room =
            Self::room(out, need, overhead).ok_or(RtcpBuildError::Short { need, got: offered })?;
        let built = compound.write(room)?;
        let written = self.protect_rtcp(out, built)?;
        if self.timer.should_back_off_bye() {
            self.timer.leaving(now, written, unit_interval);
        } else {
            self.timer.sent_bye(now, written, unit_interval);
        }
        Ok(written)
    }

    /// Take in a compound RTCP datagram and the address it came from,
    /// whichever socket it arrived on (§6.3.3, RFC 5761 for a socket shared
    /// with RTP).
    ///
    /// The origin is checked before anything in the packet is believed, for
    /// the same reason [`RtpSession::receive`] checks it: SSRCs travel in
    /// the clear in every packet of the call, so anyone who can watch the
    /// stream can name ours in a report block and move this session's
    /// round-trip estimate and its report cadence from off to the side.
    /// Only the parse comes first, so that a datagram that is not RTCP at
    /// all never decides where RTCP is heard from.
    ///
    /// On a secured stream the refusal comes earlier still, ahead of SRTCP,
    /// for the reason [`RtpSession::receive`] refuses a foreign address
    /// before SRTP: SRTCP records a report's index the moment its tag
    /// verifies, so a copy refused only afterwards would already have spent
    /// the index of the genuine report. Only the refusal moves; the latch is
    /// still taken after the parse.
    pub fn rtcp_receive<'a>(
        &mut self,
        datagram: &'a mut [u8],
        from: SocketAddr,
        now: Duration,
        ntp: u64,
    ) -> RtcpReceived<'a> {
        if !matches!(self.security, Protection::Clear) && !self.rtcp_origin_possible(from) {
            return RtcpReceived::ForeignAddress;
        }
        // what §6.3.3 folds into the report interval is the size on the wire,
        // which is the protected one
        let wire = datagram.len();
        let plain = match &mut self.security {
            Protection::Open(security) => match security.unprotect_rtcp(datagram) {
                Ok(len) => len,
                Err(error) => return RtcpReceived::Insecure(error),
            },
            // as on the RTP side: nothing arriving before the keys is
            // believed, and a report folded in from an unverified packet
            // would move this session's own report interval
            Protection::Awaited(_) => return RtcpReceived::NotKeyed,
            Protection::Clear => wire,
        };
        let datagram = datagram.get(..plain).unwrap_or_default();
        let compound = match CompoundPacket::parse(datagram) {
            Ok(compound) => compound,
            Err(error) => return RtcpReceived::Malformed(error),
        };
        if !self.rtcp_origin_accepted(from) {
            return RtcpReceived::ForeignAddress;
        }
        // §6.3.3 folds in the size of "each compound RTCP packet received",
        // which is this one and not a datagram that failed to be one:
        // avg_rtcp_size is the numerator of §6.3.1's interval, so anything
        // counted here moves this session's own reporting cadence.
        self.timer.observe(wire);
        // §6.3.3 counts a source once it is heard from at all, by RTP or
        // RTCP, and does not require RTP to know who it was: the SSRC an
        // SR or RR names itself with is the only identifier a recvonly
        // peer, or a call on hold, ever gives this session, since RTP
        // never arrives from either to set `inbound.source`. Read before
        // the loop below so a compound naming the same source in both its
        // report and its BYE — the common shape [`RtpSession::send_bye`]
        // itself builds — has the identifier in hand by the time the BYE
        // is checked, whichever order the two are in.
        if let Some(reporter) = compound.packets().find_map(|packet| match packet {
            RtcpPacket::SenderReport(sr) => Some(sr.ssrc()),
            RtcpPacket::ReceiverReport(rr) => Some(rr.ssrc()),
            RtcpPacket::Goodbye(_)
            | RtcpPacket::SourceDescription(_)
            | RtcpPacket::ExtendedReport(_)
            | RtcpPacket::Other { .. } => None,
        }) {
            self.inbound.rtcp_source = Some(reporter);
        }
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
                    // Matched against whichever identifier this session
                    // actually has for the remote side — `source` when
                    // RTP set one, `rtcp_source` when only RTCP ever has
                    // (recvonly, or on hold). Matching `source` alone left
                    // such a peer's BYE unmatched forever, since RTP was
                    // never going to teach this session that SSRC.
                    if bye.sources().any(|ssrc| {
                        Some(ssrc) == self.inbound.source || Some(ssrc) == self.inbound.rtcp_source
                    }) {
                        // §6.3.4 removes the member (and sender) table entry
                        // "if present"; a source already marked departed has
                        // no entry left, so a repeated BYE — a retransmission
                        // or a duplicate on the wire — must not remove one a
                        // second time. Left unguarded, a peer that repeats
                        // its BYE would drive `members` past the local
                        // participant and reverse reconsideration would pull
                        // the next report to the instant the repeat arrived.
                        if !self.inbound.departed {
                            self.inbound.departed = true;
                            if self.timer.is_departing() {
                                // §6.3.4's own removal rule excludes "the
                                // case when an RTCP BYE is to be
                                // transmitted": once this session has sent
                                // its own BYE ([`RtpSession::send_bye`],
                                // either of its branches), a BYE received
                                // from someone else no longer shrinks
                                // `members` — §6.3.7 bullet two counts it
                                // up instead.
                                self.timer.note_bye_while_departing();
                            } else {
                                self.timer.remove_member(now);
                                if self.inbound.sender_known {
                                    self.timer.remove_sender();
                                }
                            }
                        }
                        goodbye = Some(bye.reason().unwrap_or_default());
                    }
                }
                // §4.7: the block names the source it reports on in its own
                // "SSRC of source" field, and only one about this session's
                // own stream is the far end's measure of what it sent
                RtcpPacket::ExtendedReport(xr) => {
                    if let Some(block) = xr.voip_metrics()
                        && block.ssrc == self.outbound.ssrc
                    {
                        self.far_voip_metrics = Some(block);
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

    /// Whether RTCP from `from` belongs to this call, latching onto the
    /// first sender that does.
    ///
    /// The latch is the RTP one's counterpart and starts from the same
    /// address [`RtpSession::destination`] does: where the audio is actually
    /// coming from once it is coming from anywhere, and the address the
    /// answer named until then. Only the host is compared, because the port
    /// is the part that legitimately differs — the classic pair puts RTCP one
    /// above the RTP port (§11) and RFC 5761 puts it on the RTP port itself.
    /// Once a report has arrived the full address is pinned, and a later one
    /// from anywhere else is dropped rather than merged.
    ///
    /// Falling back to the answer's address rather than to whoever speaks
    /// first is the safe half of a trade, and not a free one. A peer behind
    /// a NAT sends its reports from an address the answer never named, so on
    /// a stream that receives no RTP to latch onto — one-way paging, a held
    /// call, listen-only monitoring — its reports are refused for the whole
    /// call, and this session goes without a round-trip estimate and counts
    /// one member fewer. The cost is paid in statistics. The other way round
    /// it would be paid in the call itself: those are exactly the streams
    /// where nothing ever arrives to correct a wrong guess.
    ///
    /// A latch taken before RTP arrived was taken on the weaker of the two
    /// addresses, so RTP overrules it: when the media turns out to come from
    /// another host, that earlier latch is dropped instead of kept, or one
    /// early report would shut the real peer out of its own call.
    fn rtcp_origin_accepted(&mut self, from: SocketAddr) -> bool {
        if !self.rtcp_origin_possible(from) {
            return false;
        }
        // a latch on the expected host is `from` itself by now; one on any
        // other host was taken before RTP settled elsewhere, and gives way
        let expected = self.destination().ip();
        if self
            .inbound
            .rtcp_latch
            .is_none_or(|latched| latched.ip() != expected)
        {
            self.inbound.rtcp_latch = Some(from);
        }
        true
    }

    /// Whether [`RtpSession::rtcp_origin_accepted`] would take RTCP from
    /// `from`, without latching onto it: the latched address when the latch
    /// is on the host expected, and otherwise any port on that host.
    fn rtcp_origin_possible(&self, from: SocketAddr) -> bool {
        let expected = self.destination().ip();
        match self.inbound.rtcp_latch {
            Some(latched) if latched.ip() == expected => latched == from,
            _ => from.ip() == expected,
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

    /// What the far end measured of the audio this session sent it: the last
    /// RFC 3611 §4.7 VoIP Metrics block it sent whose "SSRC of source" is
    /// this session's own ([`RtpSession::local_ssrc`]). `None` until one
    /// has arrived, which a far end that does not send RTCP XR never sends;
    /// this session's own measure of what it receives is
    /// [`RtpSession::voip_metrics`].
    #[must_use]
    pub const fn far_voip_metrics(&self) -> Option<VoipMetricsBlock> {
        self.far_voip_metrics
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
    use crate::dtmf::{EventReceiver, EventReport, Outcome, Outgoing, Reported};
    use crate::playout::{Activity, BufferConfig, Frame, Pull};
    use crate::rtcp::{
        CNAME, ChunkBuilder, CompoundBuilder, CompoundPacket, GoodbyeBuilder,
        ReceiverReportBuilder, ReportBlock, RtcpBuildError, RtcpPacket, SdesItem, SenderOrReceiver,
        SourceDescriptionBuilder,
    };
    use crate::rtcp_timer::Due;
    use crate::rtcp_xr::{
        JitterBufferAdaptive, PacketLossConcealment, RxConfig, UNAVAILABLE, VoipMetricsBlock,
        XrPacketBuilder,
    };
    use crate::srtp::{Master, Policy, Security, SrtpError, Suite};
    use crate::wire::{BuildError, PacketBuilder, PacketError, RtpHeader, RtpPacket};

    const PEER: &str = "198.51.100.7:16384";
    /// The peer's RTCP port: the RTP one plus one, as RFC 3550 §11 pairs
    /// them, so its reports arrive from a port its audio never uses.
    const PEER_RTCP: &str = "198.51.100.7:16385";
    /// Where the answer said the peer is, which is not where its packets
    /// come from: a NAT rewrote the address on the way out, as one usually
    /// has.
    const SIGNALLED: &str = "192.0.2.10:5004";
    /// The RTCP port beside it, for a peer nothing rewrote.
    const SIGNALLED_RTCP: &str = "192.0.2.10:5005";
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
            remote: addr(SIGNALLED),
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
            voip_metrics_xr: false,
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
            session.receive(&mut datagram(ssrc, 100, 8), from, Duration::ZERO),
            Received::Dropped(Discard::Probation)
        );
        assert_eq!(
            session.receive(&mut datagram(ssrc, 101, 8), from, Duration::ZERO),
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

    /// A compound RR sent by `ssrc`, carrying one block about this session's
    /// own SSRC with the LSR and DLSR of §6.4.1 Figure 2's worked example,
    /// where A - LSR - DLSR comes to 6.125 seconds. This is the packet that
    /// sets the round-trip estimate.
    fn round_trip_report(out: &mut [u8], ssrc: u32) -> usize {
        let block = ReportBlock {
            ssrc: 0x0102_0304,
            last_sr: 0xb705_2000,
            delay_since_last_sr: 0x0005_4000,
            ..ReportBlock::default()
        };
        let rr = ReceiverReportBuilder {
            ssrc,
            reports: &[block],
        };
        let sdes = SourceDescriptionBuilder {
            chunks: &[cname_chunk(ssrc)],
        };
        CompoundBuilder::new(SenderOrReceiver::Receiver(rr), sdes)
            .write(out)
            .expect("room")
    }

    /// A compound RTCP packet from `ssrc`, carrying only its own CNAME and a
    /// BYE naming `ssrc`, the shape a hangup produces.
    fn goodbye_packet(out: &mut [u8], ssrc: u32, reason: &[u8]) -> usize {
        let rr = ReceiverReportBuilder { ssrc, reports: &[] };
        let sdes = SourceDescriptionBuilder {
            chunks: &[cname_chunk(ssrc)],
        };
        let bye = GoodbyeBuilder {
            sources: &[ssrc],
            reason,
        };
        CompoundBuilder::new(SenderOrReceiver::Receiver(rr), sdes)
            .with_bye(bye)
            .write(out)
            .expect("room")
    }

    /// The telephone-event payload type this call negotiated: dynamic, as
    /// RFC 4733 §2.1 requires, and nothing like the audio one beside it.
    const EVENT_PT: u8 = 101;

    /// One event packet, as far as the wire is concerned.
    fn event_packet(session: &mut RtpSession, outgoing: Outgoing) -> Vec<u8> {
        let mut out = vec![0; 64];
        let n = session
            .send_event(outgoing, EVENT_PT, &mut out)
            .expect("room");
        out.truncate(n);
        out
    }

    /// A whole digit, driven the way §2.5.1 asks: two updates while it is held
    /// down, then the final packet three times over (§2.5.1.4). Twenty
    /// milliseconds apart at eight kilohertz, so the digit lasts 480 ticks.
    fn digit(session: &mut RtpSession, event: u8, volume: u8) -> Vec<Vec<u8>> {
        let mut sender = session.start_event(event, volume);
        let mut packets = vec![
            event_packet(session, sender.update(160)),
            event_packet(session, sender.update(320)),
            event_packet(session, sender.end(480)),
        ];
        while let Some(again) = sender.retransmit() {
            packets.push(event_packet(session, again));
        }
        packets
    }

    /// What a receiver downstream of the jitter buffer sees for a datagram
    /// this session wrote.
    fn frame(datagram: &[u8]) -> Frame<'_> {
        let packet = RtpPacket::parse(datagram).expect("a packet");
        Frame {
            sequence: packet.header().sequence,
            timestamp: packet.header().timestamp,
            payload_type: packet.header().payload_type,
            marker: packet.header().marker,
            payload: packet.payload(),
        }
    }

    #[test]
    fn the_stream_latches_onto_the_source_of_the_first_packet_it_believes() {
        let mut session = session();
        assert_eq!(session.latched(), None);
        assert_eq!(
            session.destination(),
            addr(SIGNALLED),
            "until a packet arrives, the answer is all there is to go on"
        );

        session.receive(&mut datagram(7, 100, 8), addr(PEER), Duration::ZERO);
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
            session.receive(&mut datagram(7, next, 8), addr(IMPOSTOR), Duration::ZERO),
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
            session.receive(&mut datagram(7, next, 8), addr(PEER), Duration::ZERO),
            Received::Queued
        );
    }

    #[test]
    fn a_following_latch_moves_with_the_far_end_and_holds_again_when_told() {
        let mut session = session();
        let next = establish(&mut session, 7, addr(PEER));
        session.set_following(true);

        // the same source from another address is taken, and moves the latch
        assert_eq!(
            session.receive(&mut datagram(7, next, 8), addr(IMPOSTOR), Duration::ZERO),
            Received::Queued
        );
        assert_eq!(session.latched(), Some(addr(IMPOSTOR)));
        // but only a packet that passed: one with a payload type nobody
        // agreed to leaves it where it is
        assert_eq!(
            session.receive(&mut datagram(7, next + 1, 99), addr(PEER), Duration::ZERO),
            Received::Dropped(Discard::PayloadType(99))
        );
        assert_eq!(session.latched(), Some(addr(IMPOSTOR)));
        assert_eq!(
            session.receive(&mut datagram(7, next + 1, 8), addr(PEER), Duration::ZERO),
            Received::Queued
        );
        assert_eq!(session.latched(), Some(addr(PEER)));

        // held again, the latch stays where the last packet put it
        session.set_following(false);
        assert_eq!(
            session.receive(
                &mut datagram(7, next + 2, 8),
                addr(IMPOSTOR),
                Duration::ZERO
            ),
            Received::Dropped(Discard::ForeignAddress)
        );
        assert_eq!(session.latched(), Some(addr(PEER)));
    }

    /// Following moves the latch only for a packet the stream took: one that
    /// passed the source and sequence checks too, not only the ones before
    /// the latch. Otherwise a stranger who cannot know the far end's SSRC
    /// still moves the latch with a packet that is then refused, and a
    /// replayed copy of the far end's own packet does the same.
    #[test]
    fn a_following_latch_is_not_moved_by_a_packet_the_stream_refuses() {
        let mut session = session();
        let next = establish(&mut session, 7, addr(PEER));
        session.set_following(true);

        assert_eq!(
            session.receive(&mut datagram(8, next, 8), addr(IMPOSTOR), Duration::ZERO),
            Received::Dropped(Discard::SecondSource(8))
        );
        assert_eq!(session.latched(), Some(addr(PEER)));
        assert_eq!(
            session.receive(
                &mut datagram(7, next - 1, 8),
                addr(IMPOSTOR),
                Duration::ZERO
            ),
            Received::Dropped(Discard::Duplicate)
        );
        assert_eq!(session.latched(), Some(addr(PEER)));

        // and what the stream does take still moves it
        assert_eq!(
            session.receive(&mut datagram(7, next, 8), addr(IMPOSTOR), Duration::ZERO),
            Received::Queued
        );
        assert_eq!(session.latched(), Some(addr(IMPOSTOR)));
    }

    #[test]
    fn a_second_synchronization_source_is_reported_rather_than_mixed_in() {
        let mut session = session();
        let next = establish(&mut session, 7, addr(PEER));
        assert_eq!(session.remote_ssrc(), Some(7));

        // same address, different SSRC: one machine, two streams
        assert_eq!(
            session.receive(&mut datagram(9, next, 8), addr(PEER), Duration::ZERO),
            Received::Dropped(Discard::SecondSource(9))
        );
        assert_eq!(session.remote_ssrc(), Some(7));

        // the application decides, because only the signalling knows whether
        // the far end was replaced
        session.follow(9);
        assert_eq!(session.remote_ssrc(), Some(9));
        assert_eq!(
            session.receive(&mut datagram(7, next, 8), addr(PEER), Duration::ZERO),
            Received::Dropped(Discard::SecondSource(7))
        );
        establish(&mut session, 9, addr(PEER));
    }

    #[test]
    fn packets_the_buffer_threw_out_cost_the_call_its_rating() {
        // two calls that received the same forty-eight packets from a clean
        // network: one earpiece kept up with them, the other stopped pulling
        // and the buffer pushed the oldest out to make room for the newest.
        // RFC 3611 §4.7.1: loss and discard "have equal effect on the
        // quality of the voice stream"
        let g711 = Some(crate::emodel::codec_quality_model(
            crate::emodel::CodecFamily::G711,
        ));
        let mut kept_up = session();
        let mut stalled = session();
        let next = establish(&mut kept_up, 7, addr(PEER));
        establish(&mut stalled, 7, addr(PEER));
        for step in 0..48_u16 {
            let sequence = next + step;
            kept_up.receive(&mut datagram(7, sequence, 8), addr(PEER), Duration::ZERO);
            kept_up.pull(Activity::Speech);
            stalled.receive(&mut datagram(7, sequence, 8), addr(PEER), Duration::ZERO);
        }
        while matches!(stalled.pull(Activity::Speech), Pull::Packet(_)) {}
        assert!(stalled.quality().discarded_overflow >= 40);

        let clean = kept_up.voip_metrics(g711).expect("a source");
        let overflowed = stalled.voip_metrics(g711).expect("a source");
        assert_eq!(overflowed.loss_rate, 0, "the network lost nothing");
        assert!(overflowed.discard_rate > 128, "most of it was thrown out");
        assert!(
            overflowed.r_factor + 30 < clean.r_factor,
            "R {} against {} for the same call heard whole",
            overflowed.r_factor,
            clean.r_factor
        );
        assert!(overflowed.mos_lq < clean.mos_lq);
    }

    #[test]
    fn a_new_source_is_rated_on_its_own_packets_and_not_the_last_ones() {
        // RFC 3611 §4.7.1's rates are the fraction of packets "from the
        // source ... since the beginning of reception", and the block names
        // the source it describes: what the buffer threw out of the old
        // source's stream is not the new one's to answer for
        for change in [
            RtpSession::follow as fn(&mut RtpSession, u32),
            |session, _| {
                session.resync();
            },
        ] {
            let mut session = session();
            let next = establish(&mut session, 7, addr(PEER));
            for step in 0..24_u16 {
                session.receive(&mut datagram(7, next + step, 8), addr(PEER), Duration::ZERO);
            }
            while matches!(session.pull(Activity::Speech), Pull::Packet(_)) {}
            let before = session.voip_metrics(None).expect("a source");
            assert!(before.discard_rate > 0, "the old source overflowed");

            change(&mut session, 9);
            let next = establish(&mut session, 9, addr(PEER));
            for step in 0..24_u16 {
                session.receive(&mut datagram(9, next + step, 8), addr(PEER), Duration::ZERO);
                assert!(matches!(session.pull(Activity::Speech), Pull::Packet(_)));
            }
            let after = session.voip_metrics(None).expect("a source");
            assert_eq!(after.ssrc, 9);
            assert_eq!((after.loss_rate, after.discard_rate), (0, 0));
        }
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
            session.receive(&mut datagram(7, 100, 96), addr(PEER), Duration::ZERO),
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
            session.receive(&mut b"not rtp".to_owned(), addr(IMPOSTOR), Duration::ZERO),
            Received::Dropped(Discard::Malformed(PacketError::TooShort { got: 7 }))
        );
        assert_eq!(session.latched(), None);
    }

    #[test]
    fn the_first_packet_of_a_new_source_is_not_believed_on_its_own() {
        // RFC 3550 A.1: two in a row before a source counts
        let mut session = session();
        assert_eq!(
            session.receive(&mut datagram(7, 100, 8), addr(PEER), Duration::ZERO),
            Received::Dropped(Discard::Probation)
        );
        assert!(matches!(session.pull(Activity::Speech), Pull::Empty));
        assert_eq!(
            session.receive(&mut datagram(7, 101, 8), addr(PEER), Duration::ZERO),
            Received::Queued
        );
    }

    #[test]
    fn a_sequence_number_from_nowhere_is_refused_until_it_repeats() {
        let mut session = session();
        let next = establish(&mut session, 7, addr(PEER));
        assert_eq!(
            session.receive(&mut datagram(7, 40000, 8), addr(PEER), Duration::ZERO),
            Received::Dropped(Discard::BadSequence)
        );
        // the second one says the far end restarted, and the stream follows it
        assert_eq!(
            session.receive(&mut datagram(7, 40001, 8), addr(PEER), Duration::ZERO),
            Received::Queued
        );
        assert_eq!(
            session.receive(&mut datagram(7, next, 8), addr(PEER), Duration::ZERO),
            Received::Dropped(Discard::BadSequence),
            "the old numbering is gone with the stream it belonged to"
        );
    }

    #[test]
    fn a_repeated_packet_is_dropped_and_a_late_one_is_told_apart_from_it() {
        let mut session = session();
        let next = establish(&mut session, 7, addr(PEER));
        assert_eq!(
            session.receive(&mut datagram(7, next, 8), addr(PEER), Duration::ZERO),
            Received::Queued
        );
        assert_eq!(
            session.receive(&mut datagram(7, next, 8), addr(PEER), Duration::ZERO),
            Received::Dropped(Discard::Duplicate)
        );

        while matches!(
            session.pull(Activity::Speech),
            Pull::Packet(_) | Pull::Conceal
        ) {}
        assert_eq!(
            session.receive(&mut datagram(7, next, 8), addr(PEER), Duration::ZERO),
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
                session.receive(&mut datagram(7, sequence, 8), addr(PEER), Duration::ZERO),
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

    /// A stream renegotiated into stopping in its pauses marks the first
    /// packet after one from then on, and one renegotiated out of it stops.
    #[test]
    fn suppression_switched_on_later_marks_the_next_spurt() {
        let mut out = [0_u8; 256];
        let mut session = RtpSession::new(
            &StreamConfig {
                silence_suppression: false,
                ..config()
            },
            0.5,
        );
        let marked = |session: &mut RtpSession, out: &mut [u8; 256]| {
            let n = session.send(&[0; 160], 160, out).expect("room");
            RtpPacket::parse(&out[..n])
                .expect("a packet")
                .header()
                .marker
        };
        session.suppress(160);
        assert!(!marked(&mut session, &mut out));
        session.set_silence_suppression(true);
        session.suppress(160);
        assert!(marked(&mut session, &mut out));
        assert!(!marked(&mut session, &mut out));
        session.set_silence_suppression(false);
        session.suppress(160);
        assert!(!marked(&mut session, &mut out));
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
    fn a_digit_goes_out_on_its_own_payload_type_in_the_streams_sequence_space() {
        // §2.1: named events are "carried as part of the audio stream and MUST
        // use the same sequence number and timestamp base as the regular audio
        // channel", on a payload type "established dynamically and
        // out-of-band"
        let mut out = [0_u8; 256];
        let mut session = session();
        session.send(&[0xD5; 160], 160, &mut out).expect("room");

        let packets = digit(&mut session, 5, 10);
        assert_eq!(
            packets.len(),
            5,
            "two updates, then the final packet three times"
        );

        for (offset, datagram) in packets.iter().enumerate() {
            let packet = RtpPacket::parse(datagram).expect("a packet");
            let header = packet.header();
            assert_eq!(
                header.payload_type, EVENT_PT,
                "the negotiated event type, not the stream's audio one"
            );
            assert_eq!(header.ssrc, 0x0102_0304, "the audio stream's own source");
            assert_eq!(
                header.sequence,
                1001 + u16::try_from(offset).expect("five packets"),
                "§2.5.1.6: every packet spends the next sequence number"
            );
            assert_eq!(
                header.marker,
                offset == 0,
                "§2.5.1.2: the first packet for an event, and only that one"
            );
            let report = EventReport::parse(packet.payload()).expect("an event");
            assert_eq!(report.event, 5);
            assert_eq!(report.volume, 10);
        }
    }

    #[test]
    fn every_packet_of_one_digit_carries_the_instant_it_began_and_a_longer_duration() {
        // §2.5.1.2: "The update packets MUST have the same RTP timestamp value
        // as the initial packet for the event, but the duration MUST be
        // increased to reflect the total cumulative duration since the
        // beginning of the event"
        let mut out = [0_u8; 256];
        let mut session = session();
        session.send(&[0xD5; 160], 160, &mut out).expect("room");

        let durations: Vec<u16> = digit(&mut session, 5, 10)
            .iter()
            .map(|datagram| {
                let packet = RtpPacket::parse(datagram).expect("a packet");
                assert_eq!(
                    packet.header().timestamp,
                    500_160,
                    "the instant the digit began, unmoving for as long as it lasts"
                );
                EventReport::parse(packet.payload())
                    .expect("an event")
                    .duration
            })
            .collect();
        assert_eq!(durations, [160, 320, 480, 480, 480]);
    }

    #[test]
    fn the_final_packet_goes_out_three_times_with_only_its_sequence_number_moving() {
        // §2.5.1.4: "sent a total of three times", so the end of a digit
        // survives a lost packet -- while §2.5.1.6 has the sequence number
        // increment anyway, "to permit the receiver to detect lost packets"
        let mut session = session();
        let packets = digit(&mut session, 5, 10);
        let ends = &packets[2..];

        let first = RtpPacket::parse(&packets[2]).expect("a packet");
        for (offset, datagram) in ends.iter().enumerate() {
            let packet = RtpPacket::parse(datagram).expect("a packet");
            assert_eq!(
                packet.payload(),
                first.payload(),
                "the same four octets, retransmission and all"
            );
            assert!(
                EventReport::parse(packet.payload()).expect("an event").end,
                "§2.5.1.4: once the E bit is set it stays set"
            );
            assert_eq!(
                RtpHeader {
                    sequence: first.header().sequence,
                    ..packet.header()
                },
                first.header(),
                "nothing but the sequence number differs"
            );
            assert_eq!(
                packet.header().sequence,
                1002 + u16::try_from(offset).expect("three packets")
            );
        }
    }

    #[test]
    fn the_audio_after_a_digit_resumes_where_the_digit_ended() {
        // Every packet of the event carries the instant it began (§2.5.1.2),
        // so the audio clock cannot advance packet by packet; the event still
        // occupies the ticks its duration counts (§2.3.5), and §2.5.1.3 does
        // the arithmetic itself when a long event starts its next segment
        // "with the RTP timestamp set to the time at which the previous
        // segment ended". Either mistake is a drift of frames that nothing
        // hears until a codec stops keeping sync.
        let mut out = [0_u8; 256];
        let mut session = session();
        session.send(&[0xD5; 160], 160, &mut out).expect("room");

        assert_eq!(digit(&mut session, 5, 10).len(), 5);

        let n = session.send(&[0xD5; 160], 160, &mut out).expect("room");
        let resumed = RtpPacket::parse(&out[..n]).expect("a packet");
        assert_eq!(resumed.header().payload_type, 8, "audio again");
        assert_eq!(
            resumed.header().timestamp,
            500_160 + 480,
            "the digit began at 500_160 and lasted 480 ticks; the two \
             retransmissions of its final packet added none of their own"
        );
        assert_eq!(
            resumed.header().sequence,
            1006,
            "five event packets, five sequence numbers"
        );
        assert!(
            resumed.header().marker,
            "no audio went out while the digit did, so this starts a spurt"
        );
    }

    #[test]
    fn a_digit_that_ended_behind_the_stream_does_not_rewind_the_audio_clock() {
        let mut out = [0_u8; 256];
        let mut session = session();
        // the event is claimed at 500_000 and then outrun by the audio, which
        // is a caller confusing itself; the clock still only goes forward
        let mut sender = session.start_event(1, 0);
        session.send(&[0xD5; 160], 160, &mut out).expect("room");
        session
            .send_event(sender.end(80), EVENT_PT, &mut out)
            .expect("room");

        let n = session.send(&[0xD5; 160], 160, &mut out).expect("room");
        let resumed = RtpPacket::parse(&out[..n]).expect("a packet");
        assert_eq!(
            resumed.header().timestamp,
            500_160,
            "an event ending at 500_080 cannot pull the stream back to it"
        );
    }

    #[test]
    fn a_digit_this_session_sent_is_one_digit_to_a_receiver() {
        let mut out = [0_u8; 256];
        let mut session = session();
        let n = session.send(&[0xD5; 160], 160, &mut out).expect("room");
        let mut stream = vec![out[..n].to_vec()];
        stream.extend(digit(&mut session, 5, 10));
        let n = session.send(&[0xD5; 160], 160, &mut out).expect("room");
        stream.push(out[..n].to_vec());

        let mut rx = EventReceiver::new(EVENT_PT);
        let mut reported = Vec::new();
        for datagram in &stream {
            if let Outcome::Reported(digit) = rx.receive(frame(datagram)).expect("a whole event") {
                reported.push(digit);
            }
        }

        assert_eq!(
            reported,
            [Reported {
                event: 5,
                digit: Some('5'),
                volume: 10,
                duration: 480,
                timestamp: 500_160,
            }],
            "one digit, however many packets it took to say it"
        );
        assert_eq!(rx.flush(), None, "and nothing left half-open behind it");
    }

    #[test]
    fn an_event_that_does_not_fit_spends_nothing() {
        let mut small = [0_u8; 8];
        let mut session = session();
        let mut sender = session.start_event(5, 10);
        let first = sender.update(160);
        assert!(matches!(
            session.send_event(first, EVENT_PT, &mut small),
            Err(BuildError::Short { .. })
        ));

        let mut out = [0_u8; 64];
        let n = session.send_event(first, EVENT_PT, &mut out).expect("room");
        let packet = RtpPacket::parse(&out[..n]).expect("a packet");
        assert_eq!(
            packet.header().sequence,
            1000,
            "the failed attempt left no gap in the numbering"
        );
        assert_eq!(
            packet.header().timestamp,
            500_000,
            "nor did it move the clock the digit begins on"
        );
    }

    #[test]
    fn an_event_volume_wider_than_six_bits_is_refused_before_the_stream_moves() {
        // §2.3.4 gives the volume six bits, so 64 has nowhere to go
        let mut out = [0_u8; 256];
        let mut session = session();
        let mut sender = session.start_event(5, 64);
        let first = sender.update(160);
        assert_eq!(
            session.send_event(first, EVENT_PT, &mut out),
            Err(BuildError::EventVolume(64))
        );

        let n = session.send(&[0xD5; 160], 160, &mut out).expect("room");
        let audio = RtpPacket::parse(&out[..n]).expect("a packet");
        assert_eq!(audio.header().sequence, 1000);
        assert_eq!(audio.header().timestamp, 500_000);
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
        session.receive(&mut datagram(7, 102, 8), addr(IMPOSTOR), Duration::ZERO);
        assert_eq!(session.latched(), Some(addr(IMPOSTOR)));
    }

    #[test]
    fn a_new_session_has_nothing_to_report_but_an_empty_rr_and_its_own_cname() {
        let mut session = session();
        let mut out = [0_u8; 256];
        let (n, next) = session
            .build_report(&mut out, Duration::ZERO, 0, 0.5, None)
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
            .build_report(&mut out, Duration::ZERO, 0x0102_0304_0506_0708, 0.5, None)
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
            .build_report(&mut out, Duration::ZERO, 0, 0.5, None)
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
        establish(&mut session, 7, addr(PEER));
        assert_eq!(session.round_trip_time(), None);

        let mut incoming = [0_u8; 256];
        let n = round_trip_report(&mut incoming, 99);
        let arrival_ntp = 0xb710_8000_u64 << 16;
        assert_eq!(
            session.rtcp_receive(
                &mut incoming[..n],
                addr(PEER_RTCP),
                Duration::ZERO,
                arrival_ntp
            ),
            RtcpReceived::Report
        );
        assert_eq!(
            session.round_trip_time(),
            Some(Duration::new(6, 125_000_000))
        );
    }

    /// A compound RTCP packet from `ssrc` carrying an XR VoIP Metrics block
    /// (RFC 3611 §4.7) about `about`.
    fn far_metrics_report(out: &mut [u8], ssrc: u32, about: u32) -> (usize, VoipMetricsBlock) {
        let block = VoipMetricsBlock {
            ssrc: about,
            loss_rate: 12,
            discard_rate: 3,
            burst_density: 84,
            gap_density: 10,
            burst_duration_ms: 120,
            gap_duration_ms: 520,
            round_trip_delay_ms: 45,
            end_system_delay_ms: 0,
            signal_level_dbm0: UNAVAILABLE.cast_signed(),
            noise_level_dbm0: UNAVAILABLE.cast_signed(),
            rerl_db: UNAVAILABLE,
            gmin: 16,
            r_factor: 82,
            ext_r_factor: UNAVAILABLE,
            mos_lq: 38,
            mos_cq: 36,
            rx_config: RxConfig {
                plc: PacketLossConcealment::Standard,
                jba: JitterBufferAdaptive::Adaptive,
                jb_rate: 5,
            },
            jb_nominal_ms: 40,
            jb_maximum_ms: 60,
            jb_abs_max_ms: 500,
        };
        let rr = ReceiverReportBuilder { ssrc, reports: &[] };
        let sdes = SourceDescriptionBuilder {
            chunks: &[cname_chunk(ssrc)],
        };
        let n = CompoundBuilder::new(SenderOrReceiver::Receiver(rr), sdes)
            .with_xr(XrPacketBuilder {
                ssrc,
                voip_metrics: Some(block),
            })
            .write(out)
            .expect("room");
        (n, block)
    }

    #[test]
    fn the_far_ends_own_voip_metrics_about_this_stream_are_kept() {
        let mut session = session();
        establish(&mut session, 7, addr(PEER));
        assert_eq!(session.far_voip_metrics(), None, "nothing has said yet");

        // a block about some other source is not a measure of this stream
        let mut incoming = [0_u8; 256];
        let (n, _) = far_metrics_report(&mut incoming, 7, 0x0bad_f00d);
        assert_eq!(
            session.rtcp_receive(&mut incoming[..n], addr(PEER_RTCP), Duration::ZERO, 0),
            RtcpReceived::Report
        );
        assert_eq!(session.far_voip_metrics(), None);

        let (n, block) = far_metrics_report(&mut incoming, 7, session.local_ssrc());
        assert_eq!(
            session.rtcp_receive(&mut incoming[..n], addr(PEER_RTCP), Duration::ZERO, 0),
            RtcpReceived::Report
        );
        assert_eq!(session.far_voip_metrics(), Some(block));
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
            session.rtcp_receive(&mut incoming[..n], addr(PEER_RTCP), Duration::ZERO, 0),
            RtcpReceived::Goodbye {
                reason: b"call ended"
            }
        );
    }

    /// §6.3.4 removes a member (and sender) table entry "if present"; a
    /// second BYE for a source already marked departed (§6.2.1: "the entry
    /// SHOULD be marked as having received a BYE") has no entry left to
    /// remove.
    ///
    /// `members` alone cannot prove this: [`IntervalTimer::remove_member`]
    /// floors the count at the local participant regardless of `departed`,
    /// since a two-party session never has a third member to lose. Sending
    /// on the call too gives the far end's repeat something the floor does
    /// not also guard — this end's own sender entry — so a bandwidth low
    /// enough for §6.3.1's size-derived interval to set the cadence (rather
    /// than the 2.5s/5s floor) turns a second, wrongly-taken sender entry
    /// into a schedule that moves again.
    #[test]
    fn a_repeated_bye_for_the_same_source_does_not_leave_the_group_twice() {
        let mut session = RtpSession::new(
            &StreamConfig {
                rtcp_bandwidth: 1.0,
                ..config()
            },
            0.5,
        );
        establish(&mut session, 7, addr(PEER));
        let mut out = [0_u8; 64];
        session.send(&[0_u8; 20], 160, &mut out).expect("room");

        let mut first = [0_u8; 256];
        let n = goodbye_packet(&mut first, 7, b"call ended");
        assert_eq!(
            session.rtcp_receive(&mut first[..n], addr(PEER_RTCP), Duration::ZERO, 0),
            RtcpReceived::Goodbye {
                reason: b"call ended"
            }
        );
        let Due::Wait(after_first) = session.rtcp_due(Duration::ZERO, 0.5) else {
            panic!("nothing is due at the instant the session opened");
        };

        let mut second = [0_u8; 256];
        let n = goodbye_packet(&mut second, 7, b"call ended again");
        assert_eq!(
            session.rtcp_receive(&mut second[..n], addr(PEER_RTCP), Duration::ZERO, 0),
            RtcpReceived::Goodbye {
                reason: b"call ended again"
            },
            "the far end saying goodbye twice is still goodbye, reason and all"
        );
        let Due::Wait(after_second) = session.rtcp_due(Duration::ZERO, 0.5) else {
            panic!("nothing is due at the instant the session opened");
        };
        // the repeat still folds its size into the average (§6.3.3), which
        // moves the interval by a sixteenth of the difference at most;
        // losing this end's own sender entry a second time would cut it to
        // the 2.5s floor instead
        assert!(
            after_second * 2 > after_first,
            "a repeated BYE moved the schedule again: {after_first:?} became {after_second:?}"
        );

        // a third repeat has to be just as idempotent as the second — the
        // guard is "has this source departed", not "has it departed exactly
        // once already"
        let mut third = [0_u8; 256];
        let n = goodbye_packet(&mut third, 7, b"call ended a third time");
        assert_eq!(
            session.rtcp_receive(&mut third[..n], addr(PEER_RTCP), Duration::ZERO, 0),
            RtcpReceived::Goodbye {
                reason: b"call ended a third time"
            }
        );
        let Due::Wait(after_third) = session.rtcp_due(Duration::ZERO, 0.5) else {
            panic!("nothing is due at the instant the session opened");
        };
        assert!(
            after_third * 2 > after_second,
            "a third repeated BYE moved the schedule again: {after_second:?} became {after_third:?}"
        );
    }

    /// The same repeated BYE on a call this end is sending on: §6.3.4 takes
    /// the far end out of the sender table once, and a second pass would take
    /// this end's own entry with it. With an RTCP bandwidth low enough that
    /// §6.3.1's size-derived interval rather than the floor sets the cadence,
    /// one sender left against none is the whole budget against a quarter of
    /// it spent on nobody — the interval collapses to the floor.
    #[test]
    fn a_repeated_bye_does_not_take_this_ends_own_sending_with_it() {
        let mut session = RtpSession::new(
            &StreamConfig {
                rtcp_bandwidth: 1.0,
                ..config()
            },
            0.5,
        );
        let mut out = [0_u8; 64];
        session.send(&[0_u8; 20], 160, &mut out).expect("room");
        establish(&mut session, 7, addr(PEER));

        let mut first = [0_u8; 256];
        let n = goodbye_packet(&mut first, 7, b"call ended");
        assert_eq!(
            session.rtcp_receive(&mut first[..n], addr(PEER_RTCP), Duration::ZERO, 0),
            RtcpReceived::Goodbye {
                reason: b"call ended"
            }
        );
        let Due::Wait(after_first) = session.rtcp_due(Duration::ZERO, 0.5) else {
            panic!("nothing is due at the instant the session opened");
        };

        let mut second = [0_u8; 256];
        let n = goodbye_packet(&mut second, 7, b"call ended");
        assert_eq!(
            session.rtcp_receive(&mut second[..n], addr(PEER_RTCP), Duration::ZERO, 0),
            RtcpReceived::Goodbye {
                reason: b"call ended"
            }
        );
        let Due::Wait(after_second) = session.rtcp_due(Duration::ZERO, 0.5) else {
            panic!("nothing is due at the instant the session opened");
        };
        // the repeat still folds its size into the average (§6.3.3), which
        // moves the interval by a sixteenth of the difference at most; losing
        // this end's own sender entry would cut it to the 2.5 s floor
        assert!(
            after_second * 2 > after_first,
            "a repeated BYE removed this end's own sender entry: {after_first:?} became {after_second:?}"
        );
    }

    /// §6.3.2 puts this participant in its own member table for as long as
    /// the session lasts, and no BYE from anyone else takes it out. Saying
    /// goodbye first resets the count to that one member (§6.3.7), so the far
    /// end's own BYE crossing ours on the wire has nobody left to remove: if
    /// it took the count to zero, reverse reconsideration would pull the next
    /// deadline to the instant it arrived.
    #[test]
    fn a_goodbye_crossing_our_own_leaves_the_local_participant_counted() {
        let mut session = session();
        establish(&mut session, 7, addr(PEER));

        let mut out = [0_u8; 256];
        session
            .send_bye(&mut out, Duration::from_secs(10), b"hanging up", 0.5)
            .expect("room");
        let scheduled = session.next_rtcp_deadline();

        let mut incoming = [0_u8; 256];
        let n = goodbye_packet(&mut incoming, 7, b"hanging up too");
        let arrived = Duration::from_millis(10_100);
        assert_eq!(
            session.rtcp_receive(&mut incoming[..n], addr(PEER_RTCP), arrived, 0),
            RtcpReceived::Goodbye {
                reason: b"hanging up too"
            }
        );
        assert_eq!(
            session.next_rtcp_deadline(),
            scheduled,
            "the far end's goodbye removed this participant from its own session"
        );
    }

    /// (a) `follow` and `resync` used to leave `member_known`,
    /// `sender_known` and `departed` untouched, so once a source had
    /// departed by BYE, this session never counted it as a member or a
    /// sender again -- not even under a fresh SSRC, the shape a
    /// re-INVITE or an ICE restart gives a far end that comes back.
    /// Counting has to follow whichever source is actually being
    /// received (§6.3.3), not the one that left.
    #[test]
    fn a_source_that_returns_under_a_new_ssrc_after_a_bye_is_counted_again() {
        let quiet = StreamConfig {
            rtcp_bandwidth: 0.01,
            ..config()
        };
        let mut session = RtpSession::new(&quiet, 0.5);
        establish(&mut session, 7, addr(PEER));

        let mut incoming = [0_u8; 256];
        let n = goodbye_packet(&mut incoming, 7, b"restarting");
        assert_eq!(
            session.rtcp_receive(&mut incoming[..n], addr(PEER_RTCP), Duration::ZERO, 0),
            RtcpReceived::Goodbye {
                reason: b"restarting"
            }
        );
        let Due::Wait(after_bye) = session.rtcp_due(Duration::ZERO, 0.5) else {
            panic!("nothing is due at the instant the session opened");
        };

        session.follow(99);
        establish(&mut session, 99, addr(PEER));
        let Due::Wait(after_return) = session.rtcp_due(Duration::ZERO, 0.5) else {
            panic!("nothing is due at the instant the session opened");
        };

        assert!(
            after_return > after_bye,
            "the source that returned under a new SSRC was not counted as \
             a member again: {after_bye:?} became {after_return:?}"
        );
    }

    /// The other side of the same reset: a far end that changes its SSRC
    /// without a BYE is still the one remote participant a call has, so
    /// following its new SSRC must not add it to the count a second time.
    /// Were it added, every change would stretch the report interval.
    #[test]
    fn a_source_that_changes_its_ssrc_without_a_bye_is_not_counted_twice() {
        let quiet = StreamConfig {
            rtcp_bandwidth: 0.01,
            ..config()
        };
        let mut session = RtpSession::new(&quiet, 0.5);
        establish(&mut session, 7, addr(PEER));
        let Due::Wait(before) = session.rtcp_due(Duration::ZERO, 0.5) else {
            panic!("nothing is due at the instant the session opened");
        };

        for ssrc in [99, 100, 101] {
            session.follow(ssrc);
            establish(&mut session, ssrc, addr(PEER));
        }
        let Due::Wait(after) = session.rtcp_due(Duration::ZERO, 0.5) else {
            panic!("nothing is due at the instant the session opened");
        };

        assert_eq!(
            after, before,
            "three changes of SSRC with no BYE were counted as three more members"
        );
    }

    /// (b) a recvonly peer, or a call put on hold, never sends RTP -- so
    /// `inbound.source` never learns its SSRC -- yet `rtcp_receive`
    /// already counts it as a member the moment its first report
    /// arrives. A BYE matched only against `inbound.source` was never
    /// recognized as that member's departure.
    #[test]
    fn a_bye_from_a_source_known_only_through_rtcp_is_still_a_departure() {
        let mut session = session();
        assert_eq!(session.remote_ssrc(), None, "nothing has arrived over RTP");

        let mut report = [0_u8; 256];
        let n = round_trip_report(&mut report, 7);
        assert_eq!(
            session.rtcp_receive(&mut report[..n], addr(SIGNALLED_RTCP), Duration::ZERO, 0),
            RtcpReceived::Report,
            "the recvonly peer's report is heard, and counts it as a member"
        );

        let mut incoming = [0_u8; 256];
        let n = goodbye_packet(&mut incoming, 7, b"never sent a packet");
        assert_eq!(
            session.rtcp_receive(
                &mut incoming[..n],
                addr(SIGNALLED_RTCP),
                Duration::from_millis(1),
                0
            ),
            RtcpReceived::Goodbye {
                reason: b"never sent a packet"
            },
            "a source known only through RTCP still has to be recognized as departed"
        );
    }

    /// (c) once this session has sent its own BYE, a BYE received from the
    /// far end no longer removes it the way §6.3.4 ordinarily would:
    /// §6.3.4's own text excludes "the case when an RTCP BYE is to be
    /// transmitted" from the removal it otherwise describes, handing that
    /// case to §6.3.7 bullet two instead, which counts BYEs up rather
    /// than down for as long as this participant is leaving.
    #[test]
    fn a_bye_received_after_this_session_has_left_grows_membership_rather_than_shrinking_it() {
        let quiet = StreamConfig {
            rtcp_bandwidth: 0.01,
            ..config()
        };
        let mut session = RtpSession::new(&quiet, 0.5);
        establish(&mut session, 7, addr(PEER));

        let mut out = [0_u8; 256];
        session
            .send_bye(&mut out, Duration::from_millis(1), b"hanging up", 0.5)
            .expect("room");
        let Due::Wait(before) = session.rtcp_due(Duration::from_millis(2), 0.5) else {
            panic!("nothing is due the instant after hanging up");
        };

        let mut incoming = [0_u8; 256];
        let n = goodbye_packet(&mut incoming, 7, b"hanging up too");
        assert_eq!(
            session.rtcp_receive(
                &mut incoming[..n],
                addr(PEER_RTCP),
                Duration::from_millis(3),
                0
            ),
            RtcpReceived::Goodbye {
                reason: b"hanging up too"
            }
        );

        let Due::Wait(after) = session.rtcp_due(Duration::from_millis(4), 0.5) else {
            panic!("nothing is due right after the crossing goodbye");
        };
        assert!(
            after > before,
            "a bye crossing this session's own should have grown, not \
             shrunk, the membership the next interval is computed from: \
             {before:?} became {after:?}"
        );
    }

    #[test]
    fn a_malformed_rtcp_datagram_is_reported_rather_than_panicking() {
        let mut session = session();
        assert!(matches!(
            session.rtcp_receive(
                &mut b"not rtcp".to_owned(),
                addr(PEER_RTCP),
                Duration::ZERO,
                0
            ),
            RtcpReceived::Malformed(_)
        ));
    }

    #[test]
    fn an_rtcp_report_from_another_address_is_dropped_not_believed() {
        // an SSRC is in the clear in every packet of the call, so naming
        // ours in a report block proves nothing about who is sending it
        let mut session = session();
        establish(&mut session, 7, addr(PEER));

        let mut incoming = [0_u8; 256];
        let n = round_trip_report(&mut incoming, 99);
        let arrival_ntp = 0xb710_8000_u64 << 16;

        assert_eq!(
            session.rtcp_receive(
                &mut incoming[..n],
                addr(IMPOSTOR),
                Duration::ZERO,
                arrival_ntp
            ),
            RtcpReceived::ForeignAddress
        );
        assert_eq!(
            session.round_trip_time(),
            None,
            "nothing in it was believed"
        );

        // while the same report from the peer's own RTCP port is: §11 puts
        // it one above the RTP port, so the port differs and the host does
        // not
        assert_eq!(
            session.rtcp_receive(
                &mut incoming[..n],
                addr(PEER_RTCP),
                Duration::ZERO,
                arrival_ntp
            ),
            RtcpReceived::Report
        );
        assert_eq!(
            session.round_trip_time(),
            Some(Duration::new(6, 125_000_000))
        );
    }

    #[test]
    fn rtcp_pins_the_port_its_first_report_arrived_from() {
        let mut session = session();
        establish(&mut session, 7, addr(PEER));
        let mut incoming = [0_u8; 256];
        let n = round_trip_report(&mut incoming, 99);

        assert_eq!(
            session.rtcp_receive(&mut incoming[..n], addr(PEER_RTCP), Duration::ZERO, 0),
            RtcpReceived::Report
        );
        // same host, another port: one peer sends its reports from one
        // socket, so this is somebody else
        assert_eq!(
            session.rtcp_receive(
                &mut incoming[..n],
                addr("198.51.100.7:40001"),
                Duration::ZERO,
                0
            ),
            RtcpReceived::ForeignAddress
        );

        // a re-INVITE that moves the far end opens the latch again
        session.relocate(addr(IMPOSTOR));
        assert_eq!(
            session.rtcp_receive(&mut incoming[..n], addr(IMPOSTOR), Duration::ZERO, 0),
            RtcpReceived::Report
        );
    }

    #[test]
    fn a_stream_that_never_receives_rtp_does_not_hand_rtcp_to_whoever_speaks_first() {
        // one-way paging, a held call, listen-only monitoring: no inbound
        // audio ever arrives, so the RTP latch stays open for the whole
        // call and there is no race to win -- the first speaker would
        // simply keep the session
        let mut session = session();
        let mut incoming = [0_u8; 256];
        let n = round_trip_report(&mut incoming, 99);
        let arrival_ntp = 0xb710_8000_u64 << 16;

        assert_eq!(
            session.rtcp_receive(
                &mut incoming[..n],
                addr(IMPOSTOR),
                Duration::ZERO,
                arrival_ntp
            ),
            RtcpReceived::ForeignAddress
        );
        assert_eq!(
            session.latched(),
            None,
            "and nothing is coming to settle it"
        );
        assert_eq!(session.round_trip_time(), None);

        // the address the answer named is heard, since with no media it is
        // the only thing the session knows about the far end
        assert_eq!(
            session.rtcp_receive(
                &mut incoming[..n],
                addr(SIGNALLED_RTCP),
                Duration::ZERO,
                arrival_ntp
            ),
            RtcpReceived::Report
        );
        assert_eq!(
            session.round_trip_time(),
            Some(Duration::new(6, 125_000_000))
        );
    }

    #[test]
    fn an_impostor_ahead_of_the_first_rtp_packet_does_not_win_the_race() {
        // §6.3.1 holds the first report back 2.5 seconds while audio starts
        // at once, so anyone who has read the answer has that long to get a
        // report in before the media settles where the peer is
        let mut session = session();
        let mut incoming = [0_u8; 256];
        let n = round_trip_report(&mut incoming, 99);
        let arrival_ntp = 0xb710_8000_u64 << 16;

        assert_eq!(
            session.rtcp_receive(
                &mut incoming[..n],
                addr(IMPOSTOR),
                Duration::ZERO,
                arrival_ntp
            ),
            RtcpReceived::ForeignAddress
        );
        assert_eq!(session.round_trip_time(), None);

        establish(&mut session, 7, addr(PEER));
        assert_eq!(
            session.rtcp_receive(
                &mut incoming[..n],
                addr(PEER_RTCP),
                Duration::ZERO,
                arrival_ntp
            ),
            RtcpReceived::Report,
            "and the peer it tried to impersonate is not shut out by it"
        );
        assert_eq!(
            session.round_trip_time(),
            Some(Duration::new(6, 125_000_000))
        );
    }

    #[test]
    fn an_rtcp_latch_taken_before_rtp_gives_way_to_where_the_media_turned_out_to_be() {
        let mut session = session();
        let mut incoming = [0_u8; 256];
        let n = round_trip_report(&mut incoming, 99);
        let arrival_ntp = 0xb710_8000_u64 << 16;

        // a report arrives from the answer's address before any audio does
        assert_eq!(
            session.rtcp_receive(&mut incoming[..n], addr(SIGNALLED_RTCP), Duration::ZERO, 0),
            RtcpReceived::Report
        );

        // and then the media turns up from the address the peer's NAT
        // allocated, which is the better of the two
        establish(&mut session, 7, addr(PEER));
        assert_eq!(
            session.rtcp_receive(
                &mut incoming[..n],
                addr(PEER_RTCP),
                Duration::ZERO,
                arrival_ntp
            ),
            RtcpReceived::Report
        );
        assert_eq!(
            session.round_trip_time(),
            Some(Duration::new(6, 125_000_000))
        );

        // the earlier address does not speak for the call any more
        assert_eq!(
            session.rtcp_receive(
                &mut incoming[..n],
                addr(SIGNALLED_RTCP),
                Duration::ZERO,
                arrival_ntp
            ),
            RtcpReceived::ForeignAddress
        );
    }

    // The address a latch gives way to is pinned exactly, port included, the
    // same as one taken from nothing: a second port on the very host RTP
    // just settled on does not inherit the trust the first one earned.
    #[test]
    fn a_latch_that_gave_way_to_rtp_still_pins_the_exact_port_it_moved_to() {
        const PEER_OTHER_PORT: &str = "198.51.100.7:16386";

        let mut session = session();
        let mut incoming = [0_u8; 256];
        let n = round_trip_report(&mut incoming, 99);
        let arrival_ntp = 0xb710_8000_u64 << 16;

        // a report arrives from the answer's address before any audio does
        assert_eq!(
            session.rtcp_receive(&mut incoming[..n], addr(SIGNALLED_RTCP), Duration::ZERO, 0),
            RtcpReceived::Report
        );

        // RTP settles the call on the peer's real address, which moves the
        // latch there too
        establish(&mut session, 7, addr(PEER));
        assert_eq!(
            session.rtcp_receive(
                &mut incoming[..n],
                addr(PEER_RTCP),
                Duration::ZERO,
                arrival_ntp
            ),
            RtcpReceived::Report
        );

        // a report from another port on that same host is not the address
        // that just earned the latch
        assert_eq!(
            session.rtcp_receive(
                &mut incoming[..n],
                addr(PEER_OTHER_PORT),
                Duration::ZERO,
                arrival_ntp
            ),
            RtcpReceived::ForeignAddress,
            "a second port on the host RTP settled on was let through \
             without ever having reported"
        );
    }

    #[test]
    fn rtcp_multiplexed_onto_the_rtp_port_arrives_from_the_address_the_audio_uses() {
        // RFC 5761 §4: one socket for both, so the reports come from the
        // very address the audio does, ports and all
        let mut session = session();
        establish(&mut session, 7, addr(PEER));
        let mut incoming = [0_u8; 256];
        let n = round_trip_report(&mut incoming, 99);
        let arrival_ntp = 0xb710_8000_u64 << 16;

        assert_eq!(
            session.rtcp_receive(&mut incoming[..n], addr(PEER), Duration::ZERO, arrival_ntp),
            RtcpReceived::Report
        );
        assert_eq!(
            session.round_trip_time(),
            Some(Duration::new(6, 125_000_000))
        );
        assert_eq!(
            session.rtcp_receive(
                &mut incoming[..n],
                addr(IMPOSTOR),
                Duration::ZERO,
                arrival_ntp
            ),
            RtcpReceived::ForeignAddress
        );
    }

    #[test]
    fn a_datagram_that_is_not_rtcp_does_not_move_the_reporting_interval() {
        // §6.3.3 folds "each compound RTCP packet received" into
        // avg_rtcp_size, and §6.3.1 divides by it -- so a datagram that
        // never parsed must not reach it, or a peer sets this session's own
        // report cadence with 1200 octets of nothing
        let quiet = StreamConfig {
            // low enough that the five-second floor is not what decides the
            // interval, leaving avg_rtcp_size the only thing that can move it
            rtcp_bandwidth: 1.0,
            ..config()
        };
        let mut untouched = RtpSession::new(&quiet, 0.5);
        let mut fed = RtpSession::new(&quiet, 0.5);

        for _ in 0..8 {
            assert!(matches!(
                fed.rtcp_receive(&mut [0_u8; 1200], addr(PEER_RTCP), Duration::ZERO, 0),
                RtcpReceived::Malformed(_)
            ));
        }

        assert_eq!(
            fed.rtcp_due(Duration::ZERO, 0.5),
            untouched.rtcp_due(Duration::ZERO, 0.5)
        );
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
            .build_report(&mut [0_u8; 256], first, 0, 0.5, None)
            .expect("room");
        assert!(next > first, "the schedule moves forward, not back");
    }

    #[test]
    fn is_rtcp_tells_a_built_report_apart_from_an_rtp_packet_for_rtcp_mux() {
        // RFC 5761 §4: demultiplexing a socket carrying both by payload type
        let mut session = session();
        let mut out = [0_u8; 256];
        let (n, _) = session
            .build_report(&mut out, Duration::ZERO, 0, 0.5, None)
            .expect("room");
        assert!(crate::rtcp::is_rtcp(&out[..n]));

        let rtp = datagram(7, 100, 8);
        assert!(!crate::rtcp::is_rtcp(&rtp));
    }

    /// The two ends of a secured call, each with the key the other will use
    /// to open what it sends — RFC 4568 §7.1.1's two master keys.
    fn secured_pair() -> (RtpSession, RtpSession) {
        let policy = Policy::new(Suite::AesCm80);
        let ours = || Master::new([0x11; 16], [0x22; 14]);
        let theirs = || Master::new([0x33; 16], [0x44; 14]);

        let mut caller_config = config();
        caller_config.remote = addr(PEER);
        let caller = RtpSession::protected(
            &caller_config,
            0.5,
            Security::new(policy, ours(), policy, theirs()),
        );

        let mut peer_config = config();
        peer_config.ssrc = 0x0a0b_0c0d;
        peer_config.remote = addr(SIGNALLED);
        peer_config.cname = "peer@198.51.100.7".to_string();
        let peer = RtpSession::protected(
            &peer_config,
            0.5,
            Security::new(policy, theirs(), policy, ours()),
        );
        (caller, peer)
    }

    #[test]
    fn a_secured_stream_carries_audio_end_to_end() {
        let (mut caller, mut peer) = secured_pair();
        assert_eq!(caller.rtp_overhead(), 10);

        let mut wire = vec![0_u8; 64];
        for packet in 0..4 {
            let len = caller
                .send(b"eight ok", 160, &mut wire)
                .expect("room for the tag");
            assert_eq!(len, 12 + 8 + 10);
            assert_ne!(
                wire.get(12..20),
                Some(&b"eight ok"[..]),
                "the payload went out in the clear"
            );
            let mut received = wire.get(..len).unwrap_or_default().to_vec();
            let outcome = peer.receive(&mut received, addr(SIGNALLED), Duration::ZERO);
            // A.1's probation: the first packet of a source is decrypted and
            // authenticated but not yet played
            let expected = if packet == 0 {
                Received::Dropped(Discard::Probation)
            } else {
                Received::Queued
            };
            assert_eq!(outcome, expected, "packet {packet}");
        }
        let Pull::Packet(frame) = peer.pull(Activity::Speech) else {
            panic!("nothing came out of the buffer");
        };
        assert_eq!(frame.payload, b"eight ok");
    }

    // "Unencrypted RTP arriving on a secured session is dropped, never
    // accepted as a fallback" — a plain packet has no tag, so what it does
    // have gets read as one and fails
    #[test]
    fn a_plain_packet_on_a_secured_stream_is_dropped() {
        let (_, mut peer) = secured_pair();
        // too short to hold a tag at all once one is subtracted
        assert_eq!(
            peer.receive(&mut datagram(7, 100, 8), addr(SIGNALLED), Duration::ZERO),
            Received::Dropped(Discard::Insecure(SrtpError::Malformed))
        );
        // and long enough that its last ten octets are read as a tag, which
        // is not one
        let mut plain = RtpSession::new(&config(), 0.5);
        let mut wire = vec![0_u8; 64];
        let len = plain
            .send(b"sixteen bytes ok", 160, &mut wire)
            .expect("room");
        let mut received = wire.get(..len).unwrap_or_default().to_vec();
        assert_eq!(
            peer.receive(&mut received, addr(SIGNALLED), Duration::ZERO),
            Received::Dropped(Discard::Insecure(SrtpError::NotAuthentic))
        );
    }

    /// A stream opened the way DTLS-SRTP opens one: the description agreed it
    /// is secured, and the handshake that keys it has not finished.
    fn awaiting_session() -> RtpSession {
        let mut waiting = config();
        waiting.remote = addr(PEER);
        RtpSession::awaiting(&waiting, 0.5, Policy::new(Suite::AesCm80))
    }

    #[test]
    fn a_stream_waiting_for_its_keys_sends_no_audio() {
        let mut session = awaiting_session();
        let mut wire = vec![0_u8; 64];
        assert_eq!(
            session.send(b"eight ok", 160, &mut wire),
            Err(BuildError::NotKeyed)
        );
        assert!(session.awaiting_keys());
        assert!(
            wire.iter().all(|&octet| octet == 0),
            "a refused packet still wrote itself into the caller's buffer"
        );
    }

    #[test]
    fn a_stream_waiting_for_its_keys_sends_no_reports_and_no_goodbye() {
        // a report carries this end's canonical name (RFC 3550 §6.5.1) and a
        // goodbye says who is leaving: neither goes out in the clear on a
        // stream that asked to be encrypted
        let mut session = awaiting_session();
        let mut out = [0_u8; 256];
        assert_eq!(
            session.build_report(&mut out, Duration::ZERO, 0, 0.5, None),
            Err(RtcpBuildError::NotKeyed)
        );
        assert_eq!(
            session.send_bye(&mut out, Duration::ZERO, b"", 0.5),
            Err(RtcpBuildError::NotKeyed)
        );
    }

    #[test]
    fn a_stream_waiting_for_its_keys_believes_nothing_that_arrives() {
        let mut session = awaiting_session();
        assert_eq!(
            session.receive(&mut datagram(7, 100, 8), addr(PEER), Duration::ZERO),
            Received::Dropped(Discard::NotKeyed)
        );
        let mut report = [0_u8; 256];
        let n = round_trip_report(&mut report, 0x0a0b_0c0d);
        assert_eq!(
            session.rtcp_receive(
                report.get_mut(..n).expect("the report"),
                addr(PEER_RTCP),
                Duration::ZERO,
                0
            ),
            RtcpReceived::NotKeyed
        );
    }

    #[test]
    fn a_stream_waiting_for_its_keys_sizes_a_buffer_for_the_profile_it_will_get() {
        // the profile is chosen inside the handshake, so the overhead a
        // caller sizes against before it finishes is the most it could be —
        // and it does not grow when the keys land
        let mut session = awaiting_session();
        assert_eq!(session.rtp_overhead(), 10);
        assert_eq!(session.rtcp_overhead(), 14);
        let policy = Policy::new(Suite::AesCm80);
        assert!(session.keyed(Security::new(
            policy,
            Master::new([0x11; 16], [0x22; 14]),
            policy,
            Master::new([0x33; 16], [0x44; 14]),
        )));
        assert_eq!(session.rtp_overhead(), 10);
        assert_eq!(session.rtcp_overhead(), 14);
    }

    #[test]
    fn keys_arriving_open_a_stream_that_was_waiting_for_them() {
        let policy = Policy::new(Suite::AesCm80);
        let ours = || Master::new([0x11; 16], [0x22; 14]);
        let theirs = || Master::new([0x33; 16], [0x44; 14]);

        let mut caller = awaiting_session();
        assert!(caller.keyed(Security::new(policy, ours(), policy, theirs())));
        assert!(!caller.awaiting_keys());

        let mut peer_config = config();
        peer_config.ssrc = 0x0a0b_0c0d;
        peer_config.remote = addr(SIGNALLED);
        peer_config.cname = "peer@198.51.100.7".to_string();
        let mut peer = RtpSession::protected(
            &peer_config,
            0.5,
            Security::new(policy, theirs(), policy, ours()),
        );

        let mut wire = vec![0_u8; 64];
        for packet in 0..2 {
            let len = caller.send(b"eight ok", 160, &mut wire).expect("room");
            let mut received = wire.get(..len).unwrap_or_default().to_vec();
            let expected = if packet == 0 {
                Received::Dropped(Discard::Probation)
            } else {
                Received::Queued
            };
            assert_eq!(
                peer.receive(&mut received, addr(SIGNALLED), Duration::ZERO),
                expected,
                "packet {packet}"
            );
        }
        let Pull::Packet(frame) = peer.pull(Activity::Speech) else {
            panic!("nothing came out of the buffer");
        };
        assert_eq!(frame.payload, b"eight ok");
    }

    #[test]
    fn the_first_packet_after_the_keys_is_the_first_packet_of_the_stream() {
        // nothing was spent while the stream waited, so the sequence number
        // and the timestamp are still the ones it was configured with: there
        // is no gap for the far end to read as loss
        let mut session = awaiting_session();
        let mut wire = vec![0_u8; 64];
        for _ in 0..3 {
            assert!(session.send(b"eight ok", 160, &mut wire).is_err());
        }
        let policy = Policy::new(Suite::AesCm80);
        assert!(session.keyed(Security::new(
            policy,
            Master::new([0x11; 16], [0x22; 14]),
            policy,
            Master::new([0x33; 16], [0x44; 14]),
        )));

        let mut plain = RtpSession::new(&config(), 0.5);
        let mut reference = vec![0_u8; 64];
        let plain_len = plain.send(b"eight ok", 160, &mut reference).expect("room");
        let len = session.send(b"eight ok", 160, &mut wire).expect("room");
        assert_eq!(len, plain_len + 10, "the tag, and nothing else, differs");
        // the header is the part that must match: sequence number and
        // timestamp, in the clear in both
        assert_eq!(wire.get(2..12), reference.get(2..12));
    }

    #[test]
    fn a_stream_that_never_agreed_to_be_secured_refuses_keys() {
        // the one thing this path must not become: a way for encryption to
        // appear on a call the far end negotiated in the clear
        let mut session = session();
        let policy = Policy::new(Suite::AesCm80);
        assert!(!session.keyed(Security::new(
            policy,
            Master::new([0x11; 16], [0x22; 14]),
            policy,
            Master::new([0x33; 16], [0x44; 14]),
        )));
        assert_eq!(session.rtp_overhead(), 0, "it took them anyway");
        let mut wire = vec![0_u8; 64];
        assert!(
            session.send(b"eight ok", 160, &mut wire).is_ok(),
            "a plain stream stopped sending"
        );
    }

    #[test]
    fn a_stream_that_already_has_keys_refuses_more() {
        // re-keying is RtpSession::rekey_local and rekey_remote, which keep
        // the packet index RFC 3711 §9.1 requires them to keep; this path
        // would restart it
        let (mut caller, _) = secured_pair();
        let policy = Policy::new(Suite::AesCm32);
        assert!(!caller.keyed(Security::new(
            policy,
            Master::new([0x55; 16], [0x66; 14]),
            policy,
            Master::new([0x77; 16], [0x88; 14]),
        )));
        assert_eq!(caller.rtp_overhead(), 10, "the shorter tag was installed");
    }

    #[test]
    fn a_packet_from_the_wrong_key_never_reaches_the_buffer() {
        let (mut caller, _) = secured_pair();
        let policy = Policy::new(Suite::AesCm80);
        let mut stranger = RtpSession::protected(
            &config(),
            0.5,
            Security::new(
                policy,
                Master::new([0x55; 16], [0x66; 14]),
                policy,
                Master::new([0x77; 16], [0x88; 14]),
            ),
        );

        let mut wire = vec![0_u8; 64];
        let len = caller.send(b"eight ok", 160, &mut wire).expect("room");
        let mut received = wire.get(..len).unwrap_or_default().to_vec();
        assert_eq!(
            stranger.receive(&mut received, addr(SIGNALLED), Duration::ZERO),
            Received::Dropped(Discard::Insecure(SrtpError::NotAuthentic))
        );
        assert!(matches!(stranger.pull(Activity::Speech), Pull::Empty));
    }

    // A datagram from an address this stream has not latched onto is refused
    // either way. Refused only after SRTP has taken it, it has already spent
    // its index in the replay list, so a copy sent from anywhere ahead of the
    // genuine packet turns the genuine one into a replay
    #[test]
    fn a_copy_from_another_address_does_not_spend_the_genuine_packets_index() {
        let (mut caller, mut peer) = secured_pair();
        flow(&mut caller, &mut peer, 2);

        let mut wire = vec![0_u8; 64];
        let len = caller.send(b"eight ok", 160, &mut wire).expect("room");
        let mut copy = wire[..len].to_vec();
        assert_eq!(
            peer.receive(&mut copy, addr(IMPOSTOR), Duration::ZERO),
            Received::Dropped(Discard::ForeignAddress)
        );
        let mut genuine = wire[..len].to_vec();
        assert_eq!(
            peer.receive(&mut genuine, addr(SIGNALLED), Duration::ZERO),
            Received::Queued,
            "the packet from the peer was refused because a copy of it had \
             arrived from somewhere else first"
        );
    }

    #[test]
    fn a_buffer_with_no_room_for_the_tag_is_refused_before_anything_is_spent() {
        let (mut caller, _) = secured_pair();
        // twelve of header and eight of payload fit; the ten of tag do not,
        // and the refusal is stated in the caller's terms rather than in what
        // the builder saw after SRTP's share was set aside
        let mut cramped = vec![0_u8; 20];
        assert_eq!(
            caller.send(b"eight ok", 160, &mut cramped),
            Err(BuildError::Short { need: 30, got: 20 })
        );

        // the sequence number travels in the clear, so what the refused call
        // did or did not spend can be read straight off the wire
        let mut roomy = vec![0_u8; 64];
        caller.send(b"eight ok", 160, &mut roomy).expect("room");
        assert_eq!(roomy.get(2..4), Some(&1000_u16.to_be_bytes()[..]));
        caller.send(b"eight ok", 160, &mut roomy).expect("room");
        assert_eq!(roomy.get(2..4), Some(&1001_u16.to_be_bytes()[..]));
    }

    #[test]
    fn a_secured_report_is_read_at_the_other_end() {
        let (mut caller, mut peer) = secured_pair();
        assert_eq!(caller.rtcp_overhead(), 14);

        let mut wire = vec![0_u8; 256];
        let (len, _) = caller
            .build_report(&mut wire, Duration::ZERO, 0x1234_5678_9abc_def0, 0.5, None)
            .expect("room");
        assert_ne!(
            wire.get(8..12),
            Some(&[0_u8; 4][..]),
            "the sender info went out in the clear"
        );
        let mut received = wire.get(..len).unwrap_or_default().to_vec();
        assert_eq!(
            peer.rtcp_receive(&mut received, addr(SIGNALLED_RTCP), Duration::ZERO, 0),
            RtcpReceived::Report
        );
    }

    // The RTCP half of the copy above. SRTCP records a report's index the
    // moment its tag verifies, so a copy from a host the origin check refuses
    // anyway, let through SRTCP first, turns the genuine report into a replay
    #[test]
    fn a_report_copied_from_another_address_does_not_spend_the_genuine_reports_index() {
        let (mut caller, mut peer) = secured_pair();
        flow(&mut caller, &mut peer, 2);

        let mut wire = vec![0_u8; 256];
        let (len, _) = caller
            .build_report(&mut wire, Duration::ZERO, 0, 0.5, None)
            .expect("room");
        let mut copy = wire.get(..len).unwrap_or_default().to_vec();
        assert_eq!(
            peer.rtcp_receive(&mut copy, addr(IMPOSTOR), Duration::ZERO, 0),
            RtcpReceived::ForeignAddress
        );
        let mut genuine = wire.get(..len).unwrap_or_default().to_vec();
        assert_eq!(
            peer.rtcp_receive(&mut genuine, addr(SIGNALLED_RTCP), Duration::ZERO, 0),
            RtcpReceived::Report,
            "the report from the peer was refused because a copy of it had \
             arrived from another host first"
        );
    }

    #[test]
    fn a_plain_report_on_a_secured_stream_is_refused() {
        let (_, mut peer) = secured_pair();
        let mut plain = RtpSession::new(&config(), 0.5);
        let mut wire = vec![0_u8; 256];
        let (len, _) = plain
            .build_report(&mut wire, Duration::ZERO, 0, 0.5, None)
            .expect("room");
        let mut received = wire.get(..len).unwrap_or_default().to_vec();
        assert!(matches!(
            peer.rtcp_receive(&mut received, addr(SIGNALLED_RTCP), Duration::ZERO, 0),
            RtcpReceived::Insecure(_)
        ));
    }

    /// Pass `packets` of protected audio from one end to the other, which is
    /// what makes the receiver latch onto the sender's SSRC — without that,
    /// a BYE names a source it has never heard of.
    fn flow(caller: &mut RtpSession, peer: &mut RtpSession, packets: usize) {
        let mut wire = vec![0_u8; 64];
        for _ in 0..packets {
            let len = caller.send(b"eight ok", 160, &mut wire).expect("room");
            let mut received = wire.get(..len).unwrap_or_default().to_vec();
            peer.receive(&mut received, addr(SIGNALLED), Duration::ZERO);
        }
    }

    #[test]
    fn a_secured_goodbye_is_read_at_the_other_end() {
        let (mut caller, mut peer) = secured_pair();
        flow(&mut caller, &mut peer, 2);
        let mut wire = vec![0_u8; 256];
        let len = caller
            .send_bye(&mut wire, Duration::ZERO, b"done", 0.5)
            .expect("room");
        let mut received = wire.get(..len).unwrap_or_default().to_vec();
        assert_eq!(
            peer.rtcp_receive(&mut received, addr(SIGNALLED_RTCP), Duration::ZERO, 0),
            RtcpReceived::Goodbye { reason: b"done" }
        );
    }

    #[test]
    fn a_secured_event_carries_the_digit() {
        let (mut caller, mut peer) = secured_pair();
        let mut wire = vec![0_u8; 64];
        let event = Outgoing {
            report: EventReport {
                event: 5,
                end: false,
                volume: 10,
                duration: 160,
            },
            timestamp: 500_000,
            marker: true,
        };
        let len = caller.send_event(event, 101, &mut wire).expect("room");
        assert_eq!(len, 12 + 4 + 10);
        let mut received = wire.get(..len).unwrap_or_default().to_vec();
        // the event's payload type has to be one this stream believes
        assert!(matches!(
            peer.receive(&mut received, addr(SIGNALLED), Duration::ZERO),
            Received::Dropped(Discard::PayloadType(101))
        ));
    }

    #[test]
    fn an_unsecured_stream_is_exactly_what_it_was() {
        let mut session = session();
        assert_eq!(session.rtp_overhead(), 0);
        assert_eq!(session.rtcp_overhead(), 0);
        let mut wire = vec![0_u8; 64];
        let len = session.send(b"eight ok", 160, &mut wire).expect("room");
        assert_eq!(len, 20);
        assert_eq!(wire.get(12..20), Some(&b"eight ok"[..]));
    }
}
