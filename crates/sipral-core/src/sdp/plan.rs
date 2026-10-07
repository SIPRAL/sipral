// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What crosses between signalling and media.
//!
//! [`MediaCapabilities`] goes in before an offer is written, so the stack
//! writes the description. [`MediaPlan`] comes back once the answer is in.
//! Neither names a socket, device or codec implementation, so a softphone
//! and a headless agent drive the same user agent.
//!
//! RFC 3264 §6.1 gives offerer and answerer the same rule: the peer's
//! order decides, our list filters. So [`SessionDescription::media_plan`]
//! does not care which side made the offer.

use std::net::SocketAddr;

use super::crypto::CryptoPolicy;
use super::error::SdpError;
use super::media::{Direction, MediaDescription, RtpMap};
use super::session::{Attribute, Connection, SessionDescription};

/// RFC 4733 named events, carried beside a codec.
const TELEPHONE_EVENT: &str = "telephone-event";

/// RFC 3551 payload type 13, likewise not the codec of the stream.
const COMFORT_NOISE: &str = "CN";

/// The dynamic payload type range: "96-127 dynamic" (RFC 3551 table 5).
const DYNAMIC_PAYLOADS: core::ops::RangeInclusive<u8> = 96..=127;

/// One codec: agreed with a peer, or merely on offer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiatedCodec {
    /// Payload type, encoding name, clock rate and, for audio, the channel
    /// count.
    pub rtpmap: RtpMap,
    /// The `a=fmtp` parameters, as written. Their meaning is the codec's
    /// business (RFC 3264 §6.1).
    pub fmtp: Option<String>,
}

impl NegotiatedCodec {
    /// A codec with no parameters.
    #[must_use]
    pub const fn new(rtpmap: RtpMap) -> Self {
        Self { rtpmap, fmtp: None }
    }

    /// The same, with `a=fmtp` parameters.
    #[must_use]
    pub fn with_fmtp(mut self, fmtp: &str) -> Self {
        self.fmtp = Some(fmtp.to_owned());
        self
    }

    /// Its payload type.
    #[must_use]
    pub const fn payload(&self) -> u8 {
        self.rtpmap.payload
    }

    /// Its RTP timestamp clock, in hertz.
    #[must_use]
    pub const fn clock_rate(&self) -> u32 {
        self.rtpmap.clock_rate
    }

    /// The channel count; absent means mono (RFC 4566 §6).
    #[must_use]
    pub fn channels(&self) -> u16 {
        self.rtpmap
            .parameters
            .as_deref()
            .and_then(|parameters| parameters.split('/').next())
            .and_then(|channels| channels.parse().ok())
            .unwrap_or(1)
    }

    /// Whether this is that encoding. Case-insensitive: these are media
    /// subtype names (RFC 4566 §6).
    #[must_use]
    pub fn is_encoding(&self, name: &str) -> bool {
        self.rtpmap.encoding.eq_ignore_ascii_case(name)
    }
}

/// Where RTCP goes, once the descriptions have been read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtcpPlan {
    /// One port carries both (RFC 5761), only when both sides asked for it.
    Muxed,
    /// A port of its own at each end: media port plus one, or `a=rtcp`.
    SeparatePort {
        /// Where we receive it.
        local: SocketAddr,
        /// Where we send it.
        remote: SocketAddr,
    },
    /// None: the peer is not using RTCP.
    Off,
}

/// The keys, or what will produce them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Keying {
    /// SDES (RFC 4568). Each end sends its own transmission keys, so there
    /// are two.
    Sdes {
        /// Our own line, read as values: the keys that protect what we send.
        /// Tag and suite are shared with the peer's line (§6.1).
        local: CryptoPolicy,
        /// The peer's, which opens what arrives.
        remote: CryptoPolicy,
    },
    /// DTLS-SRTP (RFC 5764). The keys come from a handshake outside this
    /// crate; the description carries fingerprints and the role, passed
    /// through as written.
    Dtls {
        /// Every `a=fingerprint` the peer wrote, in order. RFC 8122 §5 allows one
        /// per hash function, so keeping only the first could fail a good call.
        /// Never empty.
        fingerprints: Vec<String>,
        /// The value of its `a=setup`, when it wrote one.
        setup: Option<String>,
    },
}

/// One `a=crypto` line: `<tag> <crypto-suite> <key-params> [<session-params>]`
/// (RFC 4568 §4). `key_params` is key material: the caller produces it
/// and keeps it out of logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Crypto {
    /// The tag, unique among the crypto attributes of one media line.
    pub tag: u32,
    /// `AES_CM_128_HMAC_SHA1_80` and the rest (§4.2).
    pub suite: String,
    /// A key method, a colon, and the keying information. `inline:` is the
    /// only method §4.3 defines.
    pub key_params: String,
    /// Whatever else the line carried (§4.4).
    pub session_params: Vec<String>,
}

impl Crypto {
    /// One crypto attribute with no session parameters.
    #[must_use]
    pub fn new(tag: u32, suite: &str, key_params: &str) -> Self {
        Self {
            tag,
            suite: suite.to_owned(),
            key_params: key_params.to_owned(),
            session_params: Vec::new(),
        }
    }

    /// Read the value of an `a=crypto` line.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let mut parts = value.split_ascii_whitespace();
        let tag = parts.next()?;
        if !tag.bytes().all(|b| b.is_ascii_digit()) || super::crypto::leading_zero(tag) {
            return None;
        }
        Some(Self {
            tag: tag.parse().ok()?,
            suite: parts.next()?.to_owned(),
            key_params: parts.next()?.to_owned(),
            session_params: parts.map(str::to_owned).collect(),
        })
    }

    /// The line's value, as it goes back on the wire.
    #[must_use]
    pub fn to_value(&self) -> String {
        let mut out = format!("{} {} {}", self.tag, self.suite, self.key_params);
        for parameter in &self.session_params {
            out.push(' ');
            out.push_str(parameter);
        }
        out
    }

    /// The attribute it becomes.
    #[must_use]
    pub fn attribute(&self) -> Attribute {
        Attribute::with_value("crypto", &self.to_value())
    }
}

/// What a build does about SRTP, and so which transport its offer names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum SrtpSupport {
    /// None: plain `RTP/AVP` with no keys in the body.
    #[default]
    None,
    /// SDES on `RTP/SAVP` (RFC 4568), lines in order of preference. The key
    /// travels in the body, so per §7 the caller offers this only over
    /// protected signalling.
    Sdes(Vec<Crypto>),
    /// The same `a=crypto` lines on plain `RTP/AVP`: keyed if the answer takes
    /// one, plain otherwise.
    ///
    /// Not defined by RFC 4568, but the desk phones' "SRTP optional", for
    /// peers that reject secure profiles (§7.4) and ignore unknown attributes.
    SdesOnAvp(Vec<Crypto>),
    /// DTLS-SRTP on `UDP/TLS/RTP/SAVP` (RFC 5764 §4.1): our fingerprint and
    /// role in the offer; keys from a handshake outside this crate.
    Dtls {
        /// The value for `a=fingerprint`.
        fingerprint: String,
        /// The value for `a=setup`.
        setup: String,
    },
}

impl SrtpSupport {
    /// The transport token an offer of this carries.
    #[must_use]
    pub const fn proto(&self) -> &'static str {
        match self {
            Self::None | Self::SdesOnAvp(_) => "RTP/AVP",
            Self::Sdes(_) => "RTP/SAVP",
            Self::Dtls { .. } => "UDP/TLS/RTP/SAVP",
        }
    }
}

/// What this build can do, said before an offer is written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaCapabilities {
    /// Most preferred first, the order RFC 3264 §6.1 reads.
    pub codecs: Vec<NegotiatedCodec>,
    /// Whether to offer RFC 4733 named events.
    pub dtmf: bool,
    /// Whether to ask for RFC 5761 multiplexing.
    pub rtcp_mux: bool,
    /// Whether to secure the stream, and how.
    pub srtp: SrtpSupport,
    /// Whether to ask the peer for RFC 3611 XR VoIP Metrics reports (§5.1).
    /// On by default.
    pub voip_metrics_xr: bool,
}

impl MediaCapabilities {
    /// A build that does these codecs, in this order, and nothing else.
    #[must_use]
    pub fn new(codecs: Vec<NegotiatedCodec>) -> Self {
        Self {
            codecs,
            dtmf: false,
            rtcp_mux: false,
            srtp: SrtpSupport::None,
            voip_metrics_xr: true,
        }
    }

    /// Say whether named events are offered.
    #[must_use]
    pub const fn with_dtmf(mut self, dtmf: bool) -> Self {
        self.dtmf = dtmf;
        self
    }

    /// Say whether multiplexing is asked for.
    #[must_use]
    pub const fn with_rtcp_mux(mut self, rtcp_mux: bool) -> Self {
        self.rtcp_mux = rtcp_mux;
        self
    }

    /// Say what to do about SRTP.
    #[must_use]
    pub fn with_srtp(mut self, srtp: SrtpSupport) -> Self {
        self.srtp = srtp;
        self
    }

    /// Say whether to ask for RFC 3611 XR VoIP Metrics reports.
    #[must_use]
    pub const fn with_voip_metrics_xr(mut self, voip_metrics_xr: bool) -> Self {
        self.voip_metrics_xr = voip_metrics_xr;
        self
    }

    /// The payload type of the first named event: the first free dynamic
    /// number. `None` without DTMF, or when codecs took all 32 numbers.
    #[must_use]
    pub fn dtmf_payload(&self) -> Option<u8> {
        self.dtmf_payloads().first().map(|&(payload, _)| payload)
    }

    /// Every named-event payload type an offer carries, with its clock rate:
    /// one per codec clock rate, in codec order, each on the next free
    /// dynamic number.
    ///
    /// Events share the audio's timestamp base (RFC 4733 §2.5.1.2), so each
    /// rate needs its own. G.722's RTP clock is 8 kHz (RFC 3551 §4.5.2).
    /// Empty without DTMF; short when the dynamic range runs out.
    #[must_use]
    pub fn dtmf_payloads(&self) -> Vec<(u8, u32)> {
        if !self.dtmf {
            return Vec::new();
        }
        let mut clocks: Vec<u32> = Vec::new();
        for clock in self.codecs.iter().map(NegotiatedCodec::clock_rate) {
            if !clocks.contains(&clock) {
                clocks.push(clock);
            }
        }
        if clocks.is_empty() {
            clocks.push(8_000);
        }
        let mut free = DYNAMIC_PAYLOADS
            .clone()
            .filter(|payload| !self.codecs.iter().any(|codec| codec.payload() == *payload));
        clocks
            .into_iter()
            .map_while(|clock| free.next().map(|payload| (payload, clock)))
            .collect()
    }

    /// The `m=` block for one stream of an offer.
    #[must_use]
    pub fn offer(&self, media: &str, port: u16, direction: Direction) -> MediaDescription {
        let dtmf = self.dtmf_payloads();
        let mut formats: Vec<String> = self
            .codecs
            .iter()
            .map(|codec| codec.payload().to_string())
            .collect();
        formats.extend(dtmf.iter().map(|(payload, _)| payload.to_string()));

        let mut stream = MediaDescription::new(media, port, self.srtp.proto(), formats);
        for codec in &self.codecs {
            stream
                .attributes
                .push(Attribute::with_value("rtpmap", &codec.rtpmap.to_value()));
            if let Some(fmtp) = &codec.fmtp {
                stream.attributes.push(Attribute::with_value(
                    "fmtp",
                    &format!("{} {fmtp}", codec.payload()),
                ));
            }
        }
        for (payload, clock_rate) in dtmf {
            // RFC 4733 §2.5.1.2: events share the audio's timestamp base, so one
            // set per clock rate
            let map = RtpMap {
                payload,
                encoding: TELEPHONE_EVENT.to_owned(),
                clock_rate,
                parameters: None,
            };
            stream
                .attributes
                .push(Attribute::with_value("rtpmap", &map.to_value()));
            // RFC 4733: no events parameter means 0-15, written anyway
            stream
                .attributes
                .push(Attribute::with_value("fmtp", &format!("{payload} 0-15")));
        }
        if self.rtcp_mux {
            stream.attributes.push(Attribute::flag("rtcp-mux"));
        }
        if self.voip_metrics_xr {
            // RFC 3611 §5.1: our line asks the answerer for this block
            stream
                .attributes
                .push(Attribute::with_value("rtcp-xr", "voip-metrics"));
        }
        match &self.srtp {
            SrtpSupport::None => {}
            SrtpSupport::Sdes(offered) | SrtpSupport::SdesOnAvp(offered) => {
                stream
                    .attributes
                    .extend(offered.iter().map(Crypto::attribute));
            }
            SrtpSupport::Dtls { fingerprint, setup } => {
                stream
                    .attributes
                    .push(Attribute::with_value("fingerprint", fingerprint));
                stream
                    .attributes
                    .push(Attribute::with_value("setup", setup));
            }
        }
        stream.attributes.push(Attribute::flag(direction.as_str()));
        stream
    }
}

/// What the negotiation settled on for one stream, recomputed after every
/// re-INVITE or UPDATE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaPlan {
    /// Where to receive. The caller chose it; this only reads it back.
    pub local: SocketAddr,
    /// Where to send, from the peer's `c=` and `m=`.
    pub remote: SocketAddr,
    /// The codec, under the payload type to send it with: the peer's number
    /// (RFC 3264 §5.1).
    pub codec: NegotiatedCodec,
    /// The payload type the codec arrives with: our own number, which may
    /// differ from [`MediaPlan::codec`]'s after renumbering (§6.1).
    pub codec_in: u8,
    /// Which way media may flow, as seen from here.
    pub direction: Direction,
    /// The named-event payload type to send with: the peer's number.
    pub dtmf: Option<u8>,
    /// The named-event payload type events arrive with: this end's number.
    pub dtmf_in: Option<u8>,
    /// Where RTCP goes.
    pub rtcp: RtcpPlan,
    /// The keys, when the stream is secured.
    pub keying: Option<Keying>,
    /// Whether this stream should send RFC 3611 XR VoIP Metrics reports. Per
    /// §5.2 each side's `a=rtcp-xr` asks the other, so the peer's description
    /// decides (media level, else session level).
    pub voip_metrics_xr: bool,
}

impl SessionDescription {
    /// The plan for one stream, given the peer's description of the same
    /// session. `self` is ours, `remote` theirs, whichever was the offer.
    /// `Ok(None)` when either end refused the stream (port zero).
    ///
    /// # Errors
    /// [`SdpError::NoSuchStream`] when either description is shorter than the
    /// index; [`SdpError::NoAddress`] when a `c=` names a host; [`SdpError::NoCodec`]
    /// when there is no codec in common; and the two keying errors when a
    /// secured stream did not end up with keys.
    pub fn media_plan(&self, remote: &Self, stream: usize) -> Result<Option<MediaPlan>, SdpError> {
        let ours = self
            .media
            .get(stream)
            .ok_or(SdpError::NoSuchStream { stream })?;
        let theirs = remote
            .media
            .get(stream)
            .ok_or(SdpError::NoSuchStream { stream })?;
        if ours.is_rejected() || theirs.is_rejected() {
            return Ok(None);
        }

        let local = socket_addr(self.connection_of(ours), ours.port, stream)?;
        let peer_connection = remote.connection_of(theirs);
        let remote_addr = socket_addr(peer_connection, theirs.port, stream)?;

        let payloads = common_payloads(ours, theirs);
        let (codec, codec_in) =
            agreed_codec(ours, theirs, &payloads).ok_or(SdpError::NoCodec { stream })?;
        let dtmf = agreed_dtmf(ours, theirs, &payloads, codec.clock_rate());

        // RFC 3264 §8.4: 0.0.0.0 means send nothing (old-style hold)
        let black_hole = peer_connection.is_some_and(Connection::is_black_hole);
        let theirs_says = remote.direction_of(theirs);
        let theirs_says = if black_hole {
            not_receiving(theirs_says)
        } else {
            theirs_says
        };
        let direction = Direction::answer_to(theirs_says, self.direction_of(ours));

        let rtcp = if black_hole {
            RtcpPlan::Off
        } else {
            rtcp_plan(self, ours, local, remote, theirs, remote_addr)
        };

        Ok(Some(MediaPlan {
            local,
            remote: remote_addr,
            codec,
            codec_in,
            direction,
            dtmf: dtmf.map(|common| common.theirs),
            dtmf_in: dtmf.map(|common| common.ours),
            rtcp,
            keying: keying(ours, remote, theirs, stream)?,
            voip_metrics_xr: remote.wants_voip_metrics_xr(theirs),
        }))
    }

    /// A plan for every stream, in order, `None` where a stream was refused.
    ///
    /// # Errors
    /// [`SdpError::StreamMismatch`] when the `m=` counts differ (RFC 3264 §6),
    /// and whatever [`SessionDescription::media_plan`] returns for one stream.
    pub fn media_plans(&self, remote: &Self) -> Result<Vec<Option<MediaPlan>>, SdpError> {
        if self.media.len() != remote.media.len() {
            return Err(SdpError::StreamMismatch {
                local: self.media.len(),
                remote: remote.media.len(),
            });
        }
        (0..self.media.len())
            .map(|stream| self.media_plan(remote, stream))
            .collect()
    }
}

/// The mapping a static payload type has by definition (RFC 3551 tables 4
/// and 5), for descriptions that omit `a=rtpmap`. Reserved and unassigned
/// types get none.
#[must_use]
pub fn static_rtpmap(payload: u8) -> Option<RtpMap> {
    let (encoding, clock_rate, parameters) = match payload {
        0 => ("PCMU", 8_000, None),
        3 => ("GSM", 8_000, None),
        4 => ("G723", 8_000, None),
        5 => ("DVI4", 8_000, None),
        6 => ("DVI4", 16_000, None),
        7 => ("LPC", 8_000, None),
        8 => ("PCMA", 8_000, None),
        9 => ("G722", 8_000, None),
        10 => ("L16", 44_100, Some("2")),
        11 => ("L16", 44_100, None),
        12 => ("QCELP", 8_000, None),
        13 => (COMFORT_NOISE, 8_000, None),
        // table 4 leaves the channel count of MPA to the payload format
        14 => ("MPA", 90_000, None),
        15 => ("G728", 8_000, None),
        16 => ("DVI4", 11_025, None),
        17 => ("DVI4", 22_050, None),
        18 => ("G729", 8_000, None),
        25 => ("CelB", 90_000, None),
        26 => ("JPEG", 90_000, None),
        28 => ("nv", 90_000, None),
        31 => ("H261", 90_000, None),
        32 => ("MPV", 90_000, None),
        33 => ("MP2T", 90_000, None),
        34 => ("H263", 90_000, None),
        _ => return None,
    };
    Some(RtpMap {
        payload,
        encoding: encoding.to_owned(),
        clock_rate,
        parameters: parameters.map(str::to_owned),
    })
}

/// A direction with the receiving taken out of it.
const fn not_receiving(direction: Direction) -> Direction {
    match direction {
        Direction::SendRecv | Direction::SendOnly => Direction::SendOnly,
        Direction::RecvOnly | Direction::Inactive => Direction::Inactive,
    }
}

fn socket_addr(
    connection: Option<&Connection>,
    port: u16,
    stream: usize,
) -> Result<SocketAddr, SdpError> {
    let address = connection
        .and_then(Connection::ip)
        .ok_or(SdpError::NoAddress { stream })?;
    Ok(SocketAddr::new(address, port))
}

/// One format both `m=` lines carry, under the number each end gave it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Common {
    /// The number in our description: what arrives here (RFC 3264 §5.1).
    ours: u8,
    /// The number in the peer's: what we send with (§5.1, §6.1).
    theirs: u8,
}

/// The formats both `m=` lines carry, in the peer's order of preference.
///
/// A dynamic number only the peer lists is matched by encoding, clock and
/// channels: §6.1 keeps the offer's number only as a SHOULD, and RFC 4317
/// §2.3 answers iLBC as 99 for an offered 97.
fn common_payloads(ours: &MediaDescription, theirs: &MediaDescription) -> Vec<Common> {
    let mine: Vec<u8> = ours.payload_types().collect();
    let mut common: Vec<Common> = Vec::new();
    for payload in theirs.payload_types() {
        let found = if mine.contains(&payload) {
            Some(payload)
        } else {
            theirs
                .rtpmap(payload)
                .filter(|_| DYNAMIC_PAYLOADS.contains(&payload))
                .and_then(|map| {
                    mine.iter().copied().find(|&candidate| {
                        DYNAMIC_PAYLOADS.contains(&candidate)
                            && !common.iter().any(|taken| taken.ours == candidate)
                            && ours
                                .rtpmap(candidate)
                                .is_some_and(|mapped| same_format(&mapped, &map))
                    })
                })
        };
        if let Some(found) = found
            && !common.iter().any(|taken| taken.ours == found)
        {
            common.push(Common {
                ours: found,
                theirs: payload,
            });
        }
    }
    common
}

/// Whether two mappings name one format: encoding (any case, RFC 4855 §3),
/// clock rate and channel count (absent = one, RFC 4566 §6).
fn same_format(a: &RtpMap, b: &RtpMap) -> bool {
    let channels = |map: &RtpMap| map.parameters.clone().unwrap_or_else(|| "1".to_owned());
    a.encoding.eq_ignore_ascii_case(&b.encoding)
        && a.clock_rate == b.clock_rate
        && channels(a) == channels(b)
}

/// What a payload type maps to: the peer's line, then ours, then the
/// profile's table.
fn mapping(ours: &MediaDescription, theirs: &MediaDescription, payload: u8) -> Option<RtpMap> {
    theirs
        .rtpmap(payload)
        .or_else(|| ours.rtpmap(payload))
        .or_else(|| static_rtpmap(payload))
}

/// The first common format that is a codec, under the peer's number, and
/// the number it arrives with.
fn agreed_codec(
    ours: &MediaDescription,
    theirs: &MediaDescription,
    payloads: &[Common],
) -> Option<(NegotiatedCodec, u8)> {
    payloads.iter().find_map(|common| {
        let codec = NegotiatedCodec {
            rtpmap: mapping(ours, theirs, common.theirs)?,
            fmtp: theirs
                .fmtp(common.theirs)
                .or_else(|| ours.fmtp(common.ours))
                .map(str::to_owned),
        };
        (!codec.is_encoding(TELEPHONE_EVENT) && !codec.is_encoding(COMFORT_NOISE))
            .then_some((codec, common.ours))
    })
}

/// The named events both carry: the peer's number, and ours.
///
/// Prefers events on the agreed codec's clock (RFC 4733 §2.5.1.2), else
/// falls back to the first pair, for peers that name a single rate.
fn agreed_dtmf(
    ours: &MediaDescription,
    theirs: &MediaDescription,
    payloads: &[Common],
    clock_rate: u32,
) -> Option<Common> {
    let events: Vec<(Common, u32)> = payloads
        .iter()
        .filter_map(|common| {
            mapping(ours, theirs, common.theirs)
                .filter(|map| map.encoding.eq_ignore_ascii_case(TELEPHONE_EVENT))
                .map(|map| (*common, map.clock_rate))
        })
        .collect();
    events
        .iter()
        .find(|(_, clock)| *clock == clock_rate)
        .or_else(|| events.first())
        .map(|&(common, _)| common)
}

fn rtcp_plan(
    ours: &SessionDescription,
    our_stream: &MediaDescription,
    local: SocketAddr,
    theirs: &SessionDescription,
    their_stream: &MediaDescription,
    remote: SocketAddr,
) -> RtcpPlan {
    if rtcp_refused(ours, our_stream) || rtcp_refused(theirs, their_stream) {
        return RtcpPlan::Off;
    }
    if our_stream.has_rtcp_mux() && their_stream.has_rtcp_mux() {
        return RtcpPlan::Muxed;
    }
    match (
        rtcp_address(our_stream, local),
        rtcp_address(their_stream, remote),
    ) {
        (Some(local), Some(remote)) => RtcpPlan::SeparatePort { local, remote },
        // a media port of 65535 with no a=rtcp leaves no port for RTCP to use
        _ => RtcpPlan::Off,
    }
}

/// Whether a description says RTCP is off: b=RS:0 and b=RR:0 (RFC 5245
/// §9.1, RFC 3556).
fn rtcp_refused(session: &SessionDescription, stream: &MediaDescription) -> bool {
    bandwidth(session, stream, "RS") == Some(0) && bandwidth(session, stream, "RR") == Some(0)
}

/// A `b=` figure, the stream's own overriding the session's.
fn bandwidth(
    session: &SessionDescription,
    stream: &MediaDescription,
    modifier: &str,
) -> Option<u64> {
    stream
        .bandwidth
        .iter()
        .chain(&session.bandwidth)
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name == modifier).then(|| value.parse().ok())?
        })
}

/// Where one end's RTCP goes: `a=rtcp`, else the next port up (RFC 3264
/// §6.1, RFC 4566 §5.14).
fn rtcp_address(stream: &MediaDescription, rtp: SocketAddr) -> Option<SocketAddr> {
    match stream.attribute("rtcp").and_then(|a| a.value.as_deref()) {
        Some(value) => signalled_rtcp(value, rtp),
        None => Some(SocketAddr::new(rtp.ip(), rtp.port().checked_add(1)?)),
    }
}

/// `a=rtcp:<port>`; an address after the port is read like a `c=` line.
fn signalled_rtcp(value: &str, rtp: SocketAddr) -> Option<SocketAddr> {
    let mut parts = value.split_ascii_whitespace();
    let port = parts.next()?.parse().ok()?;
    let address = match (parts.next(), parts.next(), parts.next()) {
        (Some(network), Some(address_type), Some(address)) => Connection {
            network: network.to_owned(),
            address_type: address_type.to_owned(),
            address: address.to_owned(),
        }
        .ip()?,
        _ => rtp.ip(),
    };
    Some(SocketAddr::new(address, port))
}

/// The keys for one stream. Only the peer's description falls back to
/// session level: `a=crypto` is media-level only, and the fingerprint
/// that matters authenticates the far end.
fn keying(
    our_stream: &MediaDescription,
    theirs: &SessionDescription,
    their_stream: &MediaDescription,
    stream: usize,
) -> Result<Option<Keying>, SdpError> {
    let mine = crypto_lines(our_stream);
    let peers = crypto_lines(their_stream);
    if let Some((local, remote)) = agreed_crypto(&mine, &peers) {
        // §7.1.2: the answer's keys must differ from the offer's; one key on both
        // directions is insecure (§7.1.1)
        if local
            .keys
            .iter()
            .any(|ours| remote.keys.iter().any(|theirs| theirs.keys == ours.keys))
        {
            return Err(SdpError::CryptoKeyReused { stream });
        }
        return Ok(Some(Keying::Sdes {
            local: local.clone(),
            remote: remote.clone(),
        }));
    }
    // RFC 4568 §5.1.2: the answer carries an offered tag and suite. No
    // common tag means no agreement, and guessing means a wrong key.
    if !mine.is_empty() && !peers.is_empty() {
        return Err(SdpError::CryptoNotOffered { stream });
    }

    let fingerprints = attribute_values(theirs, their_stream, "fingerprint");
    if !fingerprints.is_empty() {
        return Ok(Some(Keying::Dtls {
            fingerprints,
            setup: attribute_value(theirs, their_stream, "setup").map(str::to_owned),
        }));
    }

    if our_stream.is_secured() || their_stream.is_secured() {
        return Err(SdpError::CryptoMissing { stream });
    }
    Ok(None)
}

/// The `a=crypto` lines of a stream, media level only (RFC 4568). Lines
/// that do not parse are skipped.
fn crypto_lines(stream: &MediaDescription) -> Vec<CryptoPolicy> {
    stream
        .attributes
        .iter()
        .filter(|a| a.name == "crypto")
        .filter_map(|a| Crypto::parse(a.value.as_deref()?)?.policy())
        .collect()
}

/// The pair both descriptions agree on, in the peer's order. Suites must
/// match as well as tags (RFC 4568 §6.1).
fn agreed_crypto<'a>(
    mine: &'a [CryptoPolicy],
    peers: &'a [CryptoPolicy],
) -> Option<(&'a CryptoPolicy, &'a CryptoPolicy)> {
    peers.iter().find_map(|peer| {
        let ours = mine.iter().find(|ours| ours.tag == peer.tag)?;
        (ours.suite == peer.suite).then_some((ours, peer))
    })
}

/// Every value a stream carries for `name`, else the session level's, as
/// [`attribute_value`] does. Media level replaces, not adds (§5.13).
fn attribute_values(
    session: &SessionDescription,
    stream: &MediaDescription,
    name: &str,
) -> Vec<String> {
    let from = |attributes: &[Attribute]| -> Vec<String> {
        attributes
            .iter()
            .filter(|attribute| attribute.name == name)
            .filter_map(|attribute| attribute.value.clone())
            .collect()
    };
    let own = from(&stream.attributes);
    if own.is_empty() {
        from(&session.attributes)
    } else {
        own
    }
}

/// An attribute of a stream, falling back to the session level (RFC 4566
/// §5.13).
fn attribute_value<'a>(
    session: &'a SessionDescription,
    stream: &'a MediaDescription,
    name: &str,
) -> Option<&'a str> {
    stream
        .attribute(name)
        .or_else(|| session.attribute(name))?
        .value
        .as_deref()
}

#[cfg(test)]
mod tests {
    use super::{
        Crypto, Keying, MediaCapabilities, NegotiatedCodec, RtcpPlan, SrtpSupport, static_rtpmap,
    };
    use crate::sdp::{
        AcceptedStream, Connection, CryptoSuite, Direction, Origin, RtpMap, SdpError,
        SessionDescription, StreamAnswer, parse,
    };
    use std::net::SocketAddr;

    fn sdp(body: &str) -> SessionDescription {
        parse(body.as_bytes()).expect("a session description")
    }

    /// One audio stream at 192.0.2.1, with whatever lines the test needs.
    fn ours(port: u16, formats: &str, lines: &str) -> SessionDescription {
        sdp(&format!(
            "v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio {port} RTP/AVP {formats}\r\n{lines}"
        ))
    }

    /// The same at 198.51.100.9.
    fn theirs(port: u16, formats: &str, lines: &str) -> SessionDescription {
        sdp(&format!(
            "v=0\r\n\
o=- 2 2 IN IP4 198.51.100.9\r\n\
s=-\r\n\
c=IN IP4 198.51.100.9\r\n\
t=0 0\r\n\
m=audio {port} RTP/AVP {formats}\r\n{lines}"
        ))
    }

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("a socket address")
    }

    fn pcmu() -> NegotiatedCodec {
        NegotiatedCodec::new(RtpMap::parse("0 PCMU/8000").expect("PCMU"))
    }

    fn opus() -> NegotiatedCodec {
        NegotiatedCodec::new(RtpMap::parse("111 opus/48000/2").expect("opus"))
            .with_fmtp("useinbandfec=1")
    }

    /// A peer that renumbers a dynamic codec and its events is matched by
    /// mapping; each direction uses its receiver's number (RFC 3264 §5.1).
    #[test]
    fn a_renumbered_dynamic_codec_and_its_events_are_found_by_what_they_map_to() {
        let offer = ours(
            4000,
            "111 101",
            "a=rtpmap:111 opus/48000/2\r\na=fmtp:111 useinbandfec=1\r\n\
             a=rtpmap:101 telephone-event/48000\r\na=fmtp:101 0-15\r\n",
        );
        let answer = theirs(
            5000,
            "107 110",
            "a=rtpmap:107 OPUS/48000/2\r\na=rtpmap:110 telephone-event/48000\r\n",
        );
        let plan = offer.media_plan(&answer, 0).expect("a plan").expect("up");
        assert_eq!(plan.codec.rtpmap.encoding, "OPUS");
        assert_eq!((plan.codec.payload(), plan.codec_in), (107, 111));
        assert_eq!(
            plan.codec.fmtp.as_deref(),
            Some("useinbandfec=1"),
            "ours stands in for the parameters the peer left out"
        );
        assert_eq!((plan.dtmf, plan.dtmf_in), (Some(110), Some(101)));

        let back = answer.media_plan(&offer, 0).expect("a plan").expect("up");
        assert_eq!((back.codec.payload(), back.codec_in), (111, 107));
        assert_eq!((back.dtmf, back.dtmf_in), (Some(101), Some(110)));

        // a different clock rate or channel count is a different format
        let mono = theirs(5000, "107", "a=rtpmap:107 opus/48000\r\n");
        assert_eq!(
            offer.media_plan(&mono, 0),
            Err(SdpError::NoCodec { stream: 0 })
        );
        let narrow = theirs(5000, "0 110", "a=rtpmap:110 telephone-event/8000\r\n");
        let plan = ours(4000, "0 101", "a=rtpmap:101 telephone-event/48000\r\n")
            .media_plan(&narrow, 0)
            .expect("a plan")
            .expect("up");
        assert_eq!((plan.dtmf, plan.dtmf_in), (None, None));
        let same = theirs(5000, "111", "a=rtpmap:111 opus/48000/2\r\n")
            .media_plan(&offer, 0)
            .expect("a plan")
            .expect("up");
        assert_eq!((same.codec.payload(), same.codec_in), (111, 111));
    }

    /// Opus, G.722 and PCMU offer events at 48 and 8 kHz; the agreed codec
    /// picks the set on its clock (RFC 4733 §2.5.1.2), in either role.
    #[test]
    fn the_named_events_agreed_are_the_ones_on_the_codecs_clock() {
        let written = MediaCapabilities::new(vec![
            opus(),
            NegotiatedCodec::new(RtpMap::parse("9 G722/8000").expect("G722")),
            pcmu(),
        ])
        .with_dtmf(true)
        .offer("audio", 4000, Direction::SendRecv);
        let mut offer = ours(4000, "0", "");
        offer.media = vec![written];
        let events = |description: &SessionDescription| {
            description.media[0]
                .attributes
                .iter()
                .filter_map(|attribute| attribute.value.clone())
                .filter(|value| value.contains("telephone-event"))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            events(&offer),
            ["96 telephone-event/48000", "97 telephone-event/8000"]
        );

        // a PBX that takes PCMU and names its events at 8 kHz on its own number
        let pcmu_answer = theirs(5000, "0 101", "a=rtpmap:101 telephone-event/8000\r\n");
        let plan = offer
            .media_plan(&pcmu_answer, 0)
            .expect("a plan")
            .expect("up");
        assert_eq!(plan.codec.rtpmap.encoding, "PCMU");
        assert_eq!((plan.dtmf, plan.dtmf_in), (Some(101), Some(97)));

        let g722_answer = theirs(
            5000,
            "9 96 97",
            "a=rtpmap:96 telephone-event/48000\r\na=rtpmap:97 telephone-event/8000\r\n",
        );
        let plan = offer
            .media_plan(&g722_answer, 0)
            .expect("a plan")
            .expect("up");
        assert_eq!(plan.codec.rtpmap.encoding, "G722");
        assert_eq!((plan.dtmf, plan.dtmf_in), (Some(97), Some(97)));

        let opus_answer = theirs(
            5000,
            "111 97 96",
            "a=rtpmap:111 opus/48000/2\r\na=rtpmap:97 telephone-event/8000\r\n\
             a=rtpmap:96 telephone-event/48000\r\n",
        );
        let plan = offer
            .media_plan(&opus_answer, 0)
            .expect("a plan")
            .expect("up");
        assert_eq!((plan.dtmf, plan.dtmf_in), (Some(96), Some(96)));
        let back = opus_answer
            .media_plan(&offer, 0)
            .expect("a plan")
            .expect("up");
        assert_eq!((back.dtmf, back.dtmf_in), (Some(96), Some(96)));
    }

    #[test]
    fn the_plan_says_where_to_send_and_what_to_send() {
        let local = ours(
            5004,
            "0 8",
            "a=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n",
        );
        let remote = theirs(49_170, "8 0", "a=rtpmap:8 PCMA/8000\r\n");
        let plan = local
            .media_plan(&remote, 0)
            .expect("a plan")
            .expect("not rejected");

        assert_eq!(plan.local, addr("192.0.2.1:5004"));
        assert_eq!(plan.remote, addr("198.51.100.9:49170"));
        // RFC 3264 §6.1: use the answer's top preference
        assert_eq!(plan.codec.payload(), 8);
        assert!(plan.codec.is_encoding("PCMA"));
        assert_eq!(plan.direction, Direction::SendRecv);
        assert_eq!(plan.dtmf, None);
        assert_eq!(plan.keying, None);
        assert_eq!(
            plan.rtcp,
            RtcpPlan::SeparatePort {
                local: addr("192.0.2.1:5005"),
                remote: addr("198.51.100.9:49171"),
            }
        );
    }

    #[test]
    fn a_format_the_peer_did_not_list_is_not_a_choice() {
        let local = ours(5004, "0 8 9", "");
        let remote = theirs(49_170, "9 8", "");
        let plan = local
            .media_plan(&remote, 0)
            .expect("a plan")
            .expect("not rejected");
        assert_eq!(plan.codec.payload(), 9, "the peer's first, which we listed");

        let nothing_shared = theirs(49_170, "18", "");
        assert_eq!(
            local.media_plan(&nothing_shared, 0).unwrap_err(),
            SdpError::NoCodec { stream: 0 }
        );
    }

    #[test]
    fn voip_metrics_xr_follows_the_peers_media_level_line() {
        let local = ours(5004, "0", "");
        let asked = theirs(49_170, "0", "a=rtcp-xr:voip-metrics\r\n");
        let plan = local
            .media_plan(&asked, 0)
            .expect("a plan")
            .expect("not rejected");
        assert!(
            plan.voip_metrics_xr,
            "the peer's own document asked for it, so this end sends"
        );

        let silent = theirs(49_170, "0", "");
        let plan = local
            .media_plan(&silent, 0)
            .expect("a plan")
            .expect("not rejected");
        assert!(!plan.voip_metrics_xr, "nothing asked for it");
    }

    #[test]
    fn voip_metrics_xr_falls_back_to_the_peers_session_level_line_but_not_past_a_media_level_one() {
        let local = ours(5004, "0", "");

        // a session-level line applies when the stream has none of its own
        let session_level = sdp("v=0\r\n\
o=- 2 2 IN IP4 198.51.100.9\r\n\
s=-\r\n\
c=IN IP4 198.51.100.9\r\n\
t=0 0\r\n\
a=rtcp-xr:voip-metrics\r\n\
m=audio 49170 RTP/AVP 0\r\n");
        let plan = local
            .media_plan(&session_level, 0)
            .expect("a plan")
            .expect("not rejected");
        assert!(plan.voip_metrics_xr);

        // RFC 3611 §5.1: a media-level line replaces the session one, even empty
        let overridden = sdp("v=0\r\n\
o=- 2 2 IN IP4 198.51.100.9\r\n\
s=-\r\n\
c=IN IP4 198.51.100.9\r\n\
t=0 0\r\n\
a=rtcp-xr:voip-metrics\r\n\
m=audio 49170 RTP/AVP 0\r\n\
a=rtcp-xr:\r\n");
        let plan = local
            .media_plan(&overridden, 0)
            .expect("a plan")
            .expect("not rejected");
        assert!(
            !plan.voip_metrics_xr,
            "the stream's own (empty) line replaces the session-level one"
        );
    }

    #[test]
    fn a_static_payload_type_needs_no_rtpmap() {
        // m=audio 49170 RTP/AVP 0, and not another line: a complete offer
        let local = ours(5004, "0", "");
        let remote = theirs(49_170, "0", "");
        let plan = local
            .media_plan(&remote, 0)
            .expect("a plan")
            .expect("not rejected");
        assert!(plan.codec.is_encoding("pcmu"), "case does not distinguish");
        assert_eq!(plan.codec.clock_rate(), 8_000);
        assert_eq!(plan.codec.channels(), 1);
    }

    #[test]
    fn the_profiles_own_table_is_what_a_static_type_means() {
        for (payload, encoding, clock_rate, channels) in [
            (0_u8, "PCMU", 8_000_u32, 1_u16),
            (8, "PCMA", 8_000, 1),
            (9, "G722", 8_000, 1),
            (10, "L16", 44_100, 2),
            (18, "G729", 8_000, 1),
            (31, "H261", 90_000, 1),
        ] {
            let map = static_rtpmap(payload).expect("a mapping");
            assert_eq!(map.encoding, encoding);
            assert_eq!(map.clock_rate, clock_rate);
            assert_eq!(NegotiatedCodec::new(map).channels(), channels);
        }
        for unmapped in [1_u8, 2, 19, 20, 24, 96, 127] {
            assert!(static_rtpmap(unmapped).is_none(), "{unmapped}");
        }
    }

    #[test]
    fn a_rejected_stream_yields_no_plan() {
        let local = ours(5004, "0", "");
        let refused = theirs(0, "0", "");
        assert_eq!(local.media_plan(&refused, 0).expect("a result"), None);

        let we_refused = ours(0, "0", "");
        let remote = theirs(49_170, "0", "");
        assert_eq!(we_refused.media_plan(&remote, 0).expect("a result"), None);
    }

    #[test]
    fn a_stream_that_is_not_there_is_not_a_plan() {
        let local = ours(5004, "0", "");
        let remote = theirs(49_170, "0", "");
        assert_eq!(
            local.media_plan(&remote, 1).unwrap_err(),
            SdpError::NoSuchStream { stream: 1 }
        );
    }

    #[test]
    fn the_two_descriptions_have_to_be_of_the_same_session() {
        let local = sdp("v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 5004 RTP/AVP 0\r\n\
m=video 5006 RTP/AVP 31\r\n");
        let remote = theirs(49_170, "0", "");
        assert_eq!(
            local.media_plans(&remote).unwrap_err(),
            SdpError::StreamMismatch {
                local: 2,
                remote: 1
            }
        );
    }

    #[test]
    fn a_connection_that_is_a_name_cannot_be_planned_for() {
        // the RFC 3264 §10.1 example uses host names, which cannot be resolved here
        let local = ours(5004, "0", "");
        let named = sdp("v=0\r\n\
o=bob 2890844730 2890844730 IN IP4 host.example.com\r\n\
s=-\r\n\
c=IN IP4 host.example.com\r\n\
t=0 0\r\n\
m=audio 49920 RTP/AVP 0\r\n");
        assert_eq!(
            local.media_plan(&named, 0).unwrap_err(),
            SdpError::NoAddress { stream: 0 }
        );
    }

    #[test]
    fn the_direction_is_what_both_sides_left_room_for() {
        use Direction::{Inactive, RecvOnly, SendOnly, SendRecv};
        for (mine, peers, expected) in [
            (SendRecv, SendRecv, SendRecv),
            (SendRecv, SendOnly, RecvOnly),
            (SendRecv, RecvOnly, SendOnly),
            (SendRecv, Inactive, Inactive),
            (SendOnly, SendRecv, SendOnly),
            (SendOnly, SendOnly, Inactive),
            (RecvOnly, RecvOnly, Inactive),
            (RecvOnly, SendOnly, RecvOnly),
            (Inactive, SendRecv, Inactive),
        ] {
            let local = ours(5004, "0", &format!("a={mine}\r\n"));
            let remote = theirs(49_170, "0", &format!("a={peers}\r\n"));
            let plan = local
                .media_plan(&remote, 0)
                .expect("a plan")
                .expect("not rejected");
            assert_eq!(
                plan.direction, expected,
                "we said {mine}, they said {peers}"
            );
        }
    }

    #[test]
    fn the_old_black_hole_stops_both_rtp_and_rtcp() {
        // RFC 3264 §8.4: 0.0.0.0 means send nothing
        let local = ours(5004, "0", "");
        let held = sdp("v=0\r\n\
o=- 2 2 IN IP4 198.51.100.9\r\n\
s=-\r\n\
c=IN IP4 0.0.0.0\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n");
        let plan = local
            .media_plan(&held, 0)
            .expect("a plan")
            .expect("not rejected");
        assert_eq!(plan.direction, Direction::RecvOnly);
        assert_eq!(plan.rtcp, RtcpPlan::Off);
        assert_eq!(plan.remote, addr("0.0.0.0:49170"));
    }

    #[test]
    fn multiplexing_takes_both_ends_asking() {
        let asked = ours(5004, "0", "a=rtcp-mux\r\n");
        let agreed = theirs(49_170, "0", "a=rtcp-mux\r\n");
        assert_eq!(
            asked
                .media_plan(&agreed, 0)
                .expect("a plan")
                .expect("not rejected")
                .rtcp,
            RtcpPlan::Muxed
        );

        // RFC 5761: no rtcp-mux in the answer, no multiplexing
        let silent = theirs(49_170, "0", "");
        assert_eq!(
            asked
                .media_plan(&silent, 0)
                .expect("a plan")
                .expect("not rejected")
                .rtcp,
            RtcpPlan::SeparatePort {
                local: addr("192.0.2.1:5005"),
                remote: addr("198.51.100.9:49171"),
            }
        );
    }

    #[test]
    fn a_signalled_rtcp_port_beats_the_one_above_the_media_port() {
        let local = ours(5004, "0", "a=rtcp:6000\r\n");
        let remote = theirs(49_171, "0", "a=rtcp:53000 IN IP4 198.51.100.10\r\n");
        let plan = local
            .media_plan(&remote, 0)
            .expect("a plan")
            .expect("not rejected");
        assert_eq!(
            plan.rtcp,
            RtcpPlan::SeparatePort {
                local: addr("192.0.2.1:6000"),
                remote: addr("198.51.100.10:53000"),
            }
        );
        // RFC 3605: with a=rtcp present, an odd port is not adjusted
        assert_eq!(plan.remote, addr("198.51.100.9:49171"));
    }

    #[test]
    fn the_last_port_there_is_leaves_no_room_for_rtcp() {
        let local = ours(65_535, "0", "");
        let remote = theirs(49_170, "0", "");
        assert_eq!(
            local
                .media_plan(&remote, 0)
                .expect("a plan")
                .expect("not rejected")
                .rtcp,
            RtcpPlan::Off
        );
    }

    #[test]
    fn a_peer_that_says_it_runs_no_rtcp_is_believed() {
        let local = ours(5004, "0", "");
        let quiet = sdp("v=0\r\n\
o=- 2 2 IN IP4 198.51.100.9\r\n\
s=-\r\n\
c=IN IP4 198.51.100.9\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
b=RS:0\r\n\
b=RR:0\r\n");
        assert_eq!(
            local
                .media_plan(&quiet, 0)
                .expect("a plan")
                .expect("not rejected")
                .rtcp,
            RtcpPlan::Off
        );

        let sender_only = sdp("v=0\r\n\
o=- 2 2 IN IP4 198.51.100.9\r\n\
s=-\r\n\
c=IN IP4 198.51.100.9\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
b=RS:0\r\n\
b=RR:800\r\n");
        assert!(matches!(
            local
                .media_plan(&sender_only, 0)
                .expect("a plan")
                .expect("not rejected")
                .rtcp,
            RtcpPlan::SeparatePort { .. }
        ));
    }

    #[test]
    fn named_events_take_a_number_both_ends_listed() {
        let local = ours(
            5004,
            "0 101",
            "a=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\n",
        );
        let remote = theirs(
            49_170,
            "0 101",
            "a=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n",
        );
        let plan = local
            .media_plan(&remote, 0)
            .expect("a plan")
            .expect("not rejected");
        assert_eq!(plan.dtmf, Some(101));
        assert_eq!(plan.codec.payload(), 0, "the events are not the codec");

        let without = theirs(49_170, "0", "a=rtpmap:0 PCMU/8000\r\n");
        assert_eq!(
            local
                .media_plan(&without, 0)
                .expect("a plan")
                .expect("not rejected")
                .dtmf,
            None
        );
    }

    #[test]
    fn comfort_noise_is_not_the_codec_of_a_stream() {
        let local = ours(5004, "13 0", "a=rtpmap:0 PCMU/8000\r\n");
        let remote = theirs(49_170, "13 0", "a=rtpmap:0 PCMU/8000\r\n");
        let plan = local
            .media_plan(&remote, 0)
            .expect("a plan")
            .expect("not rejected");
        assert_eq!(plan.codec.payload(), 0);
    }

    #[test]
    fn the_peers_parameters_configure_what_we_send_it() {
        let local = ours(
            5004,
            "111",
            "a=rtpmap:111 opus/48000/2\r\na=fmtp:111 maxplaybackrate=48000\r\n",
        );
        let remote = theirs(
            49_170,
            "111",
            "a=rtpmap:111 opus/48000/2\r\na=fmtp:111 maxplaybackrate=16000\r\n",
        );
        let plan = local
            .media_plan(&remote, 0)
            .expect("a plan")
            .expect("not rejected");
        assert_eq!(plan.codec.fmtp.as_deref(), Some("maxplaybackrate=16000"));
        assert_eq!(plan.codec.channels(), 2);
        assert_eq!(plan.codec.clock_rate(), 48_000);
    }

    #[test]
    fn sdes_carries_one_key_in_each_direction() {
        const MINE: &str = "inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:32";
        const THEIRS: &str = "inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^20|1:32";
        let local = sdp(&format!(
            "v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 5004 RTP/SAVP 0\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 {MINE}\r\n\
a=crypto:2 AES_CM_128_HMAC_SHA1_32 {MINE}\r\n"
        ));
        let remote = sdp(&format!(
            "v=0\r\n\
o=- 2 2 IN IP4 198.51.100.9\r\n\
s=-\r\n\
c=IN IP4 198.51.100.9\r\n\
t=0 0\r\n\
m=audio 49170 RTP/SAVP 0\r\n\
a=crypto:2 AES_CM_128_HMAC_SHA1_32 {THEIRS}\r\n"
        ));
        let plan = local
            .media_plan(&remote, 0)
            .expect("a plan")
            .expect("not rejected");
        let Some(Keying::Sdes { local, remote }) = plan.keying else {
            panic!("expected SDES, got {:?}", plan.keying);
        };
        assert_eq!(local.tag, 2);
        assert_eq!(remote.tag, 2);
        assert_eq!(local.suite, CryptoSuite::AesCm32);
        assert_eq!(remote.suite, CryptoSuite::AesCm32);
        assert_eq!(local.to_crypto().key_params, MINE);
        assert_eq!(remote.to_crypto().key_params, THEIRS);
    }

    // §7.1.2: the answer's keys must differ from the offer's
    #[test]
    fn a_key_that_comes_back_to_us_is_refused() {
        const KEY: &str = "inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:32";
        let local = sdp(&format!(
            "v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 5004 RTP/SAVP 0\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 {KEY}\r\n"
        ));
        let echo = sdp(&format!(
            "v=0\r\n\
o=- 2 2 IN IP4 198.51.100.9\r\n\
s=-\r\n\
c=IN IP4 198.51.100.9\r\n\
t=0 0\r\n\
m=audio 49170 RTP/SAVP 0\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 {KEY}\r\n"
        ));
        assert_eq!(
            local.media_plan(&echo, 0),
            Err(SdpError::CryptoKeyReused { stream: 0 })
        );
    }

    // §7.1.2: a line with a wrong-length key is invalid, so its tag answers
    // nothing
    #[test]
    fn an_invalid_crypto_line_is_not_a_line_to_agree_with() {
        const MINE: &str = "inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR";
        const SHORT: &str = "inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX0=";
        let local = sdp(&format!(
            "v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 5004 RTP/SAVP 0\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 {MINE}\r\n"
        ));
        let short = sdp(&format!(
            "v=0\r\n\
o=- 2 2 IN IP4 198.51.100.9\r\n\
s=-\r\n\
c=IN IP4 198.51.100.9\r\n\
t=0 0\r\n\
m=audio 49170 RTP/SAVP 0\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 {SHORT}\r\n"
        ));
        assert_eq!(
            local.media_plan(&short, 0),
            Err(SdpError::CryptoMissing { stream: 0 }),
            "a stream on a secure profile with nothing valid on it is refused"
        );
    }

    #[test]
    fn keys_we_never_offered_are_refused_rather_than_guessed_at() {
        const KEY: &str = "inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:32";
        let local = sdp(&format!(
            "v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 5004 RTP/SAVP 0\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 {KEY}\r\n"
        ));
        let wrong_tag = sdp(&format!(
            "v=0\r\n\
o=- 2 2 IN IP4 198.51.100.9\r\n\
s=-\r\n\
c=IN IP4 198.51.100.9\r\n\
t=0 0\r\n\
m=audio 49170 RTP/SAVP 0\r\n\
a=crypto:7 AES_CM_128_HMAC_SHA1_80 {KEY}\r\n"
        ));
        assert_eq!(
            local.media_plan(&wrong_tag, 0).unwrap_err(),
            SdpError::CryptoNotOffered { stream: 0 }
        );

        let wrong_suite = sdp(&format!(
            "v=0\r\n\
o=- 2 2 IN IP4 198.51.100.9\r\n\
s=-\r\n\
c=IN IP4 198.51.100.9\r\n\
t=0 0\r\n\
m=audio 49170 RTP/SAVP 0\r\n\
a=crypto:1 F8_128_HMAC_SHA1_80 {KEY}\r\n"
        ));
        assert_eq!(
            local.media_plan(&wrong_suite, 0).unwrap_err(),
            SdpError::CryptoNotOffered { stream: 0 }
        );
    }

    #[test]
    fn a_secure_transport_without_a_key_is_not_quietly_downgraded() {
        let local = sdp("v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 5004 RTP/SAVP 0\r\n");
        let remote = sdp("v=0\r\n\
o=- 2 2 IN IP4 198.51.100.9\r\n\
s=-\r\n\
c=IN IP4 198.51.100.9\r\n\
t=0 0\r\n\
m=audio 49170 RTP/SAVP 0\r\n");
        assert_eq!(
            local.media_plan(&remote, 0).unwrap_err(),
            SdpError::CryptoMissing { stream: 0 }
        );
    }

    #[test]
    fn a_dtls_fingerprint_is_carried_through_as_written() {
        const PRINT: &str = "sha-256 12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:\
12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0";
        let local = sdp("v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 5004 UDP/TLS/RTP/SAVP 0\r\n\
a=setup:actpass\r\n");
        let remote = sdp(&format!(
            "v=0\r\n\
o=- 2 2 IN IP4 198.51.100.9\r\n\
s=-\r\n\
c=IN IP4 198.51.100.9\r\n\
t=0 0\r\n\
a=fingerprint:{PRINT}\r\n\
m=audio 49170 UDP/TLS/RTP/SAVP 0\r\n\
a=setup:active\r\n"
        ));
        let plan = local
            .media_plan(&remote, 0)
            .expect("a plan")
            .expect("not rejected");
        assert_eq!(
            plan.keying,
            Some(Keying::Dtls {
                fingerprints: vec![PRINT.to_owned()],
                setup: Some("active".to_owned()),
            })
        );
    }

    #[test]
    fn every_fingerprint_a_peer_wrote_is_carried_through_in_its_own_order() {
        // RFC 8122 §5: one fingerprint per hash function, all kept
        const SHA1: &str = "sha-1 12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78";
        const SHA256: &str = "sha-256 12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:\
12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0";
        let local = sdp("v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 5004 UDP/TLS/RTP/SAVP 0\r\n\
a=setup:actpass\r\n");
        let remote = sdp(&format!(
            "v=0\r\n\
o=- 2 2 IN IP4 198.51.100.9\r\n\
s=-\r\n\
c=IN IP4 198.51.100.9\r\n\
t=0 0\r\n\
m=audio 49170 UDP/TLS/RTP/SAVP 0\r\n\
a=fingerprint:{SHA1}\r\n\
a=fingerprint:{SHA256}\r\n\
a=setup:active\r\n"
        ));
        let plan = local
            .media_plan(&remote, 0)
            .expect("a plan")
            .expect("not rejected");
        assert_eq!(
            plan.keying,
            Some(Keying::Dtls {
                fingerprints: vec![SHA1.to_owned(), SHA256.to_owned()],
                setup: Some("active".to_owned()),
            })
        );
    }

    #[test]
    fn a_fingerprint_on_the_stream_replaces_every_one_above_it() {
        // §5.13: a media-level attribute replaces the session one, not adds to it
        const SESSION: &str = "sha-1 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD";
        const STREAM: &str = "sha-256 12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:\
12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0";
        let local = sdp("v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 5004 UDP/TLS/RTP/SAVP 0\r\n\
a=setup:actpass\r\n");
        let remote = sdp(&format!(
            "v=0\r\n\
o=- 2 2 IN IP4 198.51.100.9\r\n\
s=-\r\n\
c=IN IP4 198.51.100.9\r\n\
t=0 0\r\n\
a=fingerprint:{SESSION}\r\n\
m=audio 49170 UDP/TLS/RTP/SAVP 0\r\n\
a=fingerprint:{STREAM}\r\n\
a=setup:active\r\n"
        ));
        let plan = local
            .media_plan(&remote, 0)
            .expect("a plan")
            .expect("not rejected");
        assert_eq!(
            plan.keying,
            Some(Keying::Dtls {
                fingerprints: vec![STREAM.to_owned()],
                setup: Some("active".to_owned()),
            })
        );
    }

    #[test]
    fn a_crypto_line_survives_the_round_trip() {
        for value in [
            "1 AES_CM_128_HMAC_SHA1_80 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:32",
            "2 F8_128_HMAC_SHA1_80 inline:MTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5QUJjZGVm|2^20|1:4 \
KDR=1 UNENCRYPTED_SRTCP",
        ] {
            let crypto = Crypto::parse(value).expect("a crypto line");
            assert_eq!(crypto.to_value(), value);
        }
        assert_eq!(
            Crypto::parse("3 AES_CM_128_HMAC_SHA1_80 inline:abcd")
                .expect("a crypto line")
                .session_params,
            Vec::<String>::new()
        );
        for bad in [
            "",
            "1",
            "1 SUITE",
            "x SUITE inline:abcd",
            "-1 SUITE inline:a",
            "01 AES_CM_128_HMAC_SHA1_80 inline:abcd",
        ] {
            assert!(Crypto::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn an_offer_written_from_capabilities_says_what_the_build_can_do() {
        let capabilities = MediaCapabilities::new(vec![opus(), pcmu()])
            .with_dtmf(true)
            .with_rtcp_mux(true);
        let stream = capabilities.offer("audio", 5004, Direction::SendRecv);

        assert_eq!(stream.proto, "RTP/AVP");
        assert_eq!(stream.port, 5004);
        assert_eq!(stream.payload_types().collect::<Vec<_>>(), [111, 0, 96, 97]);
        assert_eq!(stream.rtpmap(111).expect("opus").encoding, "opus");
        assert_eq!(stream.fmtp(111), Some("useinbandfec=1"));
        assert_eq!(stream.rtpmap(0).expect("PCMU").encoding, "PCMU");
        assert!(stream.fmtp(0).is_none());
        for (payload, clock) in [(96, 48_000), (97, 8_000)] {
            let events = stream.rtpmap(payload).expect("telephone-event");
            assert_eq!(events.encoding, "telephone-event");
            assert_eq!(events.clock_rate, clock);
            assert_eq!(stream.fmtp(payload), Some("0-15"));
        }
        assert!(stream.has_rtcp_mux());
        assert_eq!(
            stream.attribute("rtcp-xr").and_then(|a| a.value.as_deref()),
            Some("voip-metrics"),
            "RFC 3611 SS5.1: every build of this stack asks for VoIP Metrics XR by default"
        );
        assert_eq!(stream.direction(), Some(Direction::SendRecv));
    }

    #[test]
    fn a_build_that_declines_voip_metrics_xr_writes_no_rtcp_xr_line() {
        let stream = MediaCapabilities::new(vec![pcmu()])
            .with_voip_metrics_xr(false)
            .offer("audio", 5004, Direction::SendRecv);
        assert!(stream.attribute("rtcp-xr").is_none());
    }

    #[test]
    fn the_named_event_number_is_one_no_codec_took() {
        let taken = MediaCapabilities::new(vec![
            NegotiatedCodec::new(RtpMap::parse("96 opus/48000/2").expect("opus")),
            NegotiatedCodec::new(RtpMap::parse("97 G722/8000").expect("G722")),
        ])
        .with_dtmf(true);
        assert_eq!(taken.dtmf_payload(), Some(98));
        // G.722's RTP clock is 8 kHz (RFC 3551 §4.5.2)
        assert_eq!(taken.dtmf_payloads(), [(98, 48_000), (99, 8_000)]);
        assert_eq!(
            taken
                .offer("audio", 5004, Direction::SendRecv)
                .formats
                .len(),
            4
        );

        let none = MediaCapabilities::new(vec![pcmu()]);
        assert_eq!(none.dtmf_payload(), None);
        assert_eq!(
            none.offer("audio", 5004, Direction::SendRecv)
                .payload_types()
                .collect::<Vec<_>>(),
            [0]
        );

        // all dynamic numbers taken: no events, no panic
        let crowded = MediaCapabilities::new(
            (96_u8..=127)
                .map(|payload| {
                    NegotiatedCodec::new(
                        RtpMap::parse(&format!("{payload} opus/48000/2")).expect("opus"),
                    )
                })
                .collect(),
        )
        .with_dtmf(true);
        assert_eq!(crowded.dtmf_payload(), None);
    }

    #[test]
    fn securing_a_stream_changes_the_transport_it_is_offered_on() {
        let key = "inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:32";
        let sdes = MediaCapabilities::new(vec![pcmu()])
            .with_srtp(SrtpSupport::Sdes(vec![Crypto::new(
                1,
                "AES_CM_128_HMAC_SHA1_80",
                key,
            )]))
            .offer("audio", 5004, Direction::SendRecv);
        assert_eq!(sdes.proto, "RTP/SAVP");
        assert_eq!(
            sdes.attribute("crypto").expect("a=crypto").value.as_deref(),
            Some(format!("1 AES_CM_128_HMAC_SHA1_80 {key}").as_str())
        );

        let optional = MediaCapabilities::new(vec![pcmu()])
            .with_srtp(SrtpSupport::SdesOnAvp(vec![Crypto::new(
                1,
                "AES_CM_128_HMAC_SHA1_80",
                key,
            )]))
            .offer("audio", 5004, Direction::SendRecv);
        assert_eq!(optional.proto, "RTP/AVP");
        assert_eq!(
            optional
                .attribute("crypto")
                .expect("a=crypto")
                .value
                .as_deref(),
            Some(format!("1 AES_CM_128_HMAC_SHA1_80 {key}").as_str())
        );

        let dtls = MediaCapabilities::new(vec![pcmu()])
            .with_srtp(SrtpSupport::Dtls {
                fingerprint: "sha-256 AA:BB".to_owned(),
                setup: "actpass".to_owned(),
            })
            .offer("audio", 5004, Direction::SendRecv);
        assert_eq!(dtls.proto, "UDP/TLS/RTP/SAVP");
        assert_eq!(
            dtls.attribute("fingerprint")
                .expect("a=fingerprint")
                .value
                .as_deref(),
            Some("sha-256 AA:BB")
        );
        assert_eq!(
            dtls.attribute("setup").expect("a=setup").value.as_deref(),
            Some("actpass")
        );
    }

    #[test]
    fn an_offer_this_crate_wrote_is_one_it_can_answer_and_then_plan_for() {
        let capabilities = MediaCapabilities::new(vec![pcmu(), opus()])
            .with_dtmf(true)
            .with_rtcp_mux(true);
        let mut offer = SessionDescription::new(
            Origin::new(1, 1, "192.0.2.1".parse().expect("an address")),
            Connection::new("192.0.2.1".parse().expect("an address")),
        );
        offer
            .media
            .push(capabilities.offer("audio", 5004, Direction::SendRecv));

        let offered = offer.media.first().expect("audio");
        let answer = offer
            .answer(
                Origin::new(2, 2, "198.51.100.9".parse().expect("an address")),
                Connection::new("198.51.100.9".parse().expect("an address")),
                &[StreamAnswer::Accept(
                    AcceptedStream::in_offer_order(49_170, offered, &["0", "96"])
                        .with_attribute(crate::sdp::Attribute::flag("rtcp-mux")),
                )],
            )
            .expect("an answer");

        let plans = offer.media_plans(&answer).expect("plans");
        let plan = plans
            .first()
            .expect("one stream")
            .as_ref()
            .expect("not rejected");
        assert_eq!(plan.codec.payload(), 0);
        assert!(plan.codec.is_encoding("PCMU"));
        assert_eq!(plan.dtmf, Some(96));
        assert_eq!(plan.rtcp, RtcpPlan::Muxed);
        assert_eq!(plan.direction, Direction::SendRecv);
        assert_eq!(plan.local, addr("192.0.2.1:5004"));
        assert_eq!(plan.remote, addr("198.51.100.9:49170"));

        // the answerer reaches the same plan
        let mirrored = answer
            .media_plan(&offer, 0)
            .expect("a plan")
            .expect("not rejected");
        assert_eq!(mirrored.codec.payload(), plan.codec.payload());
        assert_eq!(mirrored.dtmf, plan.dtmf);
        assert_eq!(mirrored.local, plan.remote);
        assert_eq!(mirrored.remote, plan.local);
    }

    #[test]
    fn a_plan_is_made_per_stream_and_a_refused_one_is_a_hole_in_the_list() {
        let local = sdp("v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 5004 RTP/AVP 0\r\n\
m=video 5006 RTP/AVP 31\r\n\
m=audio 5008 RTP/AVP 8\r\n");
        let remote = sdp("v=0\r\n\
o=- 2 2 IN IP4 198.51.100.9\r\n\
s=-\r\n\
c=IN IP4 198.51.100.9\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
m=video 0 RTP/AVP 31\r\n\
m=audio 49174 RTP/AVP 8\r\n");
        let plans = local.media_plans(&remote).expect("plans");
        assert_eq!(plans.len(), 3);
        assert!(plans.first().expect("audio").is_some());
        assert!(plans.get(1).expect("video").is_none());
        assert_eq!(
            plans
                .get(2)
                .expect("audio")
                .as_ref()
                .expect("not rejected")
                .codec
                .payload(),
            8
        );
    }
}
