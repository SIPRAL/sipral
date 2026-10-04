// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A D2 recording, turned into pcapng packets.
//!
//! Every [`Arrival::Datagram`] and [`Arrival::StreamData`] frame the
//! recording holds becomes one packet, addressed and timed the way the
//! frame was recorded; [`Arrival::TransportBound`] is not a packet, it is
//! where a stream transport's two ends come from, since a `StreamData`
//! frame carries none of its own. `Arrival::StreamClosed` and
//! `Arrival::TransportFailed` are not on the wire and produce nothing.
//!
//! [`export_replayed`] adds the other direction: the recording is fed back
//! into a live layer through [`Replayed`], and every message that layer
//! writes in answer becomes a packet from this end, so one file holds both
//! halves of the session, each packet marked inbound or outbound.

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use sipral_core::endpoint::{Endpoint, ReceiveError, Transmit};
use sipral_core::replay::{Arrival, Driven, Played, Recording, Replay, Step};

use crate::packet;
use crate::pcapng::{Direction, Writer};
use crate::redact::{RedactError, Redactor, redact_message};

/// An arbitrary origin so timestamps read as a plausible wall-clock moment;
/// nothing checks it against anything, the way nothing in `docs/18-replay.md`
/// checks a recording's own offsets against a clock either.
const TIMESTAMP_ORIGIN_US: u64 = 1_700_000_000_000_000;

#[derive(Clone, Copy)]
struct Bound {
    local: SocketAddr,
    remote: Option<SocketAddr>,
}

/// Turn `recording` into a pcapng file.
///
/// With `redactor`, every message is redacted (see [`crate::redact`]) before
/// it becomes a packet, and the packet's own source and destination
/// addresses are rewritten the same way the message's own header addresses
/// are, so the two agree. Without one, the export carries the recording
/// exactly as it was written — for the organisation's own use, never for
/// anything that leaves it.
///
/// This is the far end's half of the conversation only, because that is all
/// a recording holds; [`export_replayed`] adds this end's half.
///
/// # Errors
/// [`RedactError`] when `redactor` is given and a frame's bytes are not a
/// message the parser can read: the export stops rather than write a frame
/// nobody has redacted.
pub fn export(recording: &Recording, redactor: Option<Redactor>) -> Result<Vec<u8>, RedactError> {
    let mut capture = Capture::new(redactor);
    for frame in recording.frames() {
        if let Step::Arrived(arrival) = &frame.step {
            capture.arrived(arrival, frame.at)?;
        }
    }
    Ok(capture.finish())
}

/// A layer a recording can be replayed into for [`export_replayed`]: driven
/// the way [`Driven`] says, asked after every frame what it wrote, and told
/// when the application acted on its own.
pub trait Replayed: Driven {
    /// The next message this layer wants written, or `None` once it has
    /// nothing more to say for now — `Endpoint::poll_transmit` and
    /// `UserAgent::poll_transmit` both answer exactly this.
    fn poll_transmit(&mut self) -> Option<Transmit>;

    /// The application did something of its own here, under `label` — the
    /// name a [`Recorder::cue`](sipral_core::replay::Recorder::cue) wrote.
    ///
    /// Only the application knows what a label means, so a replay that is to
    /// write the requests that action sent does it again here: places the
    /// call, answers it, registers the account. A layer that ignores a cue
    /// replays a session in which the application never did it, and the
    /// capture shows exactly that.
    fn cue(&mut self, label: &str, now: Instant);
}

impl Replayed for Endpoint {
    fn poll_transmit(&mut self) -> Option<Transmit> {
        Self::poll_transmit(self)
    }

    /// An endpoint has no policy of its own for anything an application
    /// does, so a cue asks nothing of it.
    fn cue(&mut self, _label: &str, _now: Instant) {}
}

/// Why [`export_replayed`] stopped.
#[derive(Debug)]
#[non_exhaustive]
pub enum ExportError {
    /// A message could not be redacted — see [`export`].
    Redact(RedactError),
    /// The layer the recording was replayed into refused a frame. A
    /// recording holds what arrived, malformed messages included, and a
    /// capture that skipped the refusal would hide the very thing it is
    /// exported to show.
    Replay(ReceiveError),
}

impl core::fmt::Display for ExportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Redact(error) => write!(f, "redacting a message: {error}"),
            Self::Replay(error) => write!(f, "replaying a frame: {error}"),
        }
    }
}

impl core::error::Error for ExportError {}

impl From<RedactError> for ExportError {
    fn from(error: RedactError) -> Self {
        Self::Redact(error)
    }
}

/// Replay `recording` into `target` and turn the whole session — what
/// arrived, and what `target` wrote in answer — into one pcapng file.
///
/// Every frame is fed to `target` at its recorded offset from `origin`, the
/// way [`Replay`] feeds it; a cue is handed to [`Replayed::cue`]; and after
/// each frame everything `target` wants written becomes a packet from this
/// end, stamped with that frame's offset. So the file holds both directions
/// in the order they happened: the far end's messages exactly as recorded,
/// and this end's exactly as the engine writes them — the same bytes the
/// recorded stack wrote, since the recording carries the seed every branch,
/// tag and `Call-ID` is derived from (`docs/18-replay.md`). Each packet is
/// marked inbound or outbound, so Wireshark's direction column and filters
/// read it as a capture made at this end.
///
/// `target` must be built with [`Recording::seed`] and the configuration the
/// recorded stack ran with: a replay under different timers is a different
/// run, and the capture is of that run.
///
/// Redaction is [`export`]'s, applied to both directions with one
/// [`Redactor`], so an address or a user reads as the same pseudonym whichever
/// way the packet went; this end's own `Authorization` is dropped like any
/// other.
///
/// A message this end writes on a transport the recording never bound has no
/// address to be sent from, and is left out rather than given an invented
/// one.
///
/// # Errors
/// [`ExportError::Replay`] when `target` refuses a frame, and
/// [`ExportError::Redact`] when `redactor` is given and a message cannot be
/// read to be redacted. Nothing is returned then.
pub fn export_replayed<T: Replayed>(
    recording: &Recording,
    target: &mut T,
    origin: Instant,
    redactor: Option<Redactor>,
) -> Result<Vec<u8>, ExportError> {
    let mut capture = Capture::new(redactor);
    let mut replay = Replay::new(recording, origin);
    for frame in recording.frames() {
        if let Step::Arrived(arrival) = &frame.step {
            capture.arrived(arrival, frame.at)?;
        }
        let now = origin + frame.at;
        match replay.step(target).map_err(ExportError::Replay)? {
            Some(Played::Cue(label)) => target.cue(label, now),
            Some(Played::Fed) | None => {}
        }
        while let Some(transmit) = target.poll_transmit() {
            capture.sent(&transmit, frame.at)?;
        }
    }
    Ok(capture.finish())
}

/// The packets of one export, and what they need remembered between frames.
struct Capture {
    writer: Writer,
    redactor: Option<Redactor>,
    bound: HashMap<u32, Bound>,
    /// Next TCP sequence number, per transport and direction: `true` is
    /// this end's.
    tcp_seq: HashMap<(u32, bool), u32>,
    ident: u16,
}

impl Capture {
    fn new(redactor: Option<Redactor>) -> Self {
        Self {
            writer: Writer::new(),
            redactor,
            bound: HashMap::new(),
            tcp_seq: HashMap::new(),
            ident: 0,
        }
    }

    fn finish(self) -> Vec<u8> {
        self.writer.finish()
    }

    /// One recorded arrival: a packet from the far end, or where a transport's
    /// two ends are.
    fn arrived(&mut self, arrival: &Arrival, at: Duration) -> Result<(), RedactError> {
        match arrival {
            Arrival::TransportBound {
                transport,
                local,
                remote,
                ..
            } => {
                self.bound.insert(
                    transport.0,
                    Bound {
                        local: *local,
                        remote: *remote,
                    },
                );
                Ok(())
            }
            Arrival::Datagram {
                remote,
                local,
                data,
                ..
            } => self.packet(
                at,
                *remote,
                *local,
                data.as_bytes(),
                None,
                Direction::Inbound,
            ),
            Arrival::StreamData { transport, data } => {
                let Some(b) = self.bound.get(&transport.0).copied() else {
                    return Ok(());
                };
                let Some(remote) = b.remote else {
                    return Ok(()); // no far end was ever bound for this connection
                };
                self.packet(
                    at,
                    remote,
                    b.local,
                    data.as_bytes(),
                    Some((transport.0, false)),
                    Direction::Inbound,
                )
            }
            Arrival::StreamClosed { .. } | Arrival::TransportFailed { .. } => Ok(()),
        }
    }

    /// One message this end wrote in the replay.
    fn sent(&mut self, transmit: &Transmit, at: Duration) -> Result<(), RedactError> {
        let Some(b) = self.bound.get(&transmit.transport.0).copied() else {
            return Ok(());
        };
        let source = transmit.source.unwrap_or(b.local);
        let (destination, stream) = if transmit.protocol.is_reliable() {
            (
                b.remote.unwrap_or(transmit.destination),
                Some((transmit.transport.0, true)),
            )
        } else {
            (transmit.destination, None)
        };
        self.packet(
            at,
            source,
            destination,
            &transmit.payload,
            stream,
            Direction::Outbound,
        )
    }

    /// One packet: UDP when `stream` is `None`, else TCP on that transport
    /// and direction's own sequence.
    fn packet(
        &mut self,
        at: Duration,
        src: SocketAddr,
        dst: SocketAddr,
        data: &[u8],
        stream: Option<(u32, bool)>,
        direction: Direction,
    ) -> Result<(), RedactError> {
        let timestamp_us = TIMESTAMP_ORIGIN_US.saturating_add(duration_to_us(at));
        let payload = match self.redactor.as_mut() {
            Some(r) => redact_message(data, r)?,
            None => data.to_vec(),
        };
        let (src, dst) = match self.redactor.as_mut() {
            Some(r) => (redact_addr(src, r), redact_addr(dst, r)),
            None => (src, dst),
        };
        self.ident = self.ident.wrapping_add(1);
        let frame = match stream {
            None => build_udp(src, dst, &payload, self.ident),
            Some(key) => {
                let seq = self.tcp_seq.entry(key).or_insert(1);
                let frame = build_tcp(src, dst, &payload, self.ident, *seq);
                *seq = seq.wrapping_add(u32::try_from(payload.len()).unwrap_or(u32::MAX));
                frame
            }
        };
        self.writer.packet_in(timestamp_us, &frame, direction);
        Ok(())
    }
}

fn duration_to_us(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

fn redact_addr(addr: SocketAddr, red: &mut Redactor) -> SocketAddr {
    match addr {
        SocketAddr::V4(a) => SocketAddr::new(red.ipv4(*a.ip()).into(), a.port()),
        SocketAddr::V6(a) => SocketAddr::new(red.ipv6(*a.ip()).into(), a.port()),
    }
}

fn to_v6(addr: SocketAddr) -> (Ipv6Addr, u16) {
    match addr {
        SocketAddr::V6(a) => (*a.ip(), a.port()),
        SocketAddr::V4(a) => (a.ip().to_ipv6_mapped(), a.port()),
    }
}

fn build_udp(remote: SocketAddr, local: SocketAddr, payload: &[u8], ident: u16) -> Vec<u8> {
    if let (SocketAddr::V4(r), SocketAddr::V4(l)) = (remote, local) {
        return packet::ipv4_udp(*r.ip(), r.port(), *l.ip(), l.port(), payload, ident);
    }
    let (rip, rport) = to_v6(remote);
    let (lip, lport) = to_v6(local);
    packet::ipv6_udp(rip, rport, lip, lport, payload)
}

fn build_tcp(
    remote: SocketAddr,
    local: SocketAddr,
    payload: &[u8],
    ident: u16,
    seq: u32,
) -> Vec<u8> {
    if let (SocketAddr::V4(r), SocketAddr::V4(l)) = (remote, local) {
        return packet::ipv4_tcp(*r.ip(), r.port(), *l.ip(), l.port(), payload, ident, seq);
    }
    let (rip, rport) = to_v6(remote);
    let (lip, lport) = to_v6(local);
    packet::ipv6_tcp(rip, rport, lip, lport, payload, seq)
}

#[cfg(test)]
mod tests {
    use super::{ExportError, Replayed, export, export_replayed};
    use crate::redact::{Mode, Redactor};
    use sipral_core::endpoint::{Endpoint, EndpointConfig, Input, TransportId, TransportProtocol};
    use sipral_core::replay::{Driven, Recorder, Recording};
    use sipral_ua::{Account, Credentials, Uri, UserAgent};
    use std::time::{Duration, Instant};

    fn seed() -> [u8; 32] {
        [7u8; 32]
    }

    fn a_recording() -> sipral_core::replay::Recording {
        let mut recorder = Recorder::new(seed()).about("a REGISTER challenged and retried");
        let mut now = Instant::now();
        let local: std::net::SocketAddr = "192.0.2.1:5060".parse().expect("addr");
        let remote: std::net::SocketAddr = "192.0.2.9:5060".parse().expect("addr");
        let bound = Input::TransportBound {
            transport: TransportId(1),
            protocol: TransportProtocol::Udp,
            local,
            remote: None,
        };
        recorder.arrived(&bound, now);
        now += Duration::from_millis(40);
        let response = b"SIP/2.0 401 Unauthorized\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
From: \"Alice Example\" <sip:alice@example.com>;tag=abc\r\n\
To: <sip:alice@example.com>;tag=def\r\n\
Call-ID: e49c8d74a73c5bdf49b1186b53e0e547\r\n\
CSeq: 1 REGISTER\r\n\
WWW-Authenticate: Digest realm=\"example.com\", nonce=\"n\"\r\n\
Content-Length: 0\r\n\r\n";
        let datagram = Input::Datagram {
            transport: TransportId(1),
            remote,
            local,
            data: response,
        };
        recorder.arrived(&datagram, now);
        recorder.finish().expect("a whole recording")
    }

    #[test]
    fn every_datagram_arrival_becomes_one_pcapng_packet() {
        let recording = a_recording();
        let bytes = export(&recording, None).expect("no redaction, nothing to fail on");
        // two IDB+SHB header blocks plus one EPB for the one Datagram frame
        // (the TransportBound frame produces no packet of its own)
        assert!(bytes.len() > 48 + 12);
        let sip_text = "SIP/2.0 401";
        assert!(
            bytes
                .windows(sip_text.len())
                .any(|w| w == sip_text.as_bytes()),
            "the SIP message is in the capture unmodified"
        );
    }

    #[test]
    fn redaction_removes_the_caller_from_the_capture_and_still_produces_packets() {
        let recording = a_recording();
        let redactor = Redactor::new(Mode::Delete);
        let bytes = export(&recording, Some(redactor)).expect("a well-formed message redacts");
        assert!(bytes.len() > 48 + 12);
        let leaked = b"alice";
        assert!(
            !bytes
                .windows(leaked.len())
                .any(|w| w.eq_ignore_ascii_case(leaked)),
            "the user part must not appear in the redacted capture"
        );
    }

    #[test]
    fn a_stream_frame_with_no_bound_remote_is_skipped_rather_than_guessed_at() {
        let mut recorder = Recorder::new(seed());
        let now = Instant::now();
        let data = Input::StreamData {
            transport: TransportId(9),
            data: b"partial",
        };
        recorder.arrived(&data, now);
        let recording = recorder.finish().expect("a whole recording");
        let bytes = export(&recording, None).expect("nothing to fail on");
        // section + interface blocks only, 48 bytes, no packet block
        assert_eq!(bytes.len(), 48);
    }

    /// The recording in the tree: a registration challenged, granted and
    /// refreshed.
    const FIXTURE: &str =
        include_str!("../../../fixtures/replay/registration-challenged.sipralrec");

    /// The phone that recording was taken from, as a replay drives it: the
    /// agent, and the one thing its application did on its own.
    struct Phone {
        agent: UserAgent,
    }

    impl Driven for Phone {
        fn receive(
            &mut self,
            input: Input<'_>,
            now: Instant,
        ) -> Result<(), sipral_core::endpoint::ReceiveError> {
            self.agent.receive(input, now)
        }

        fn handle_timeout(&mut self, now: Instant) {
            self.agent.handle_timeout(now);
        }

        fn resolved(
            &mut self,
            dialog: sipral_core::transaction::DialogId,
            addresses: &[std::net::SocketAddr],
            protocol: Option<TransportProtocol>,
        ) {
            Driven::resolved(&mut self.agent, dialog, addresses, protocol);
        }
    }

    impl Replayed for Phone {
        fn poll_transmit(&mut self) -> Option<sipral_core::endpoint::Transmit> {
            self.agent.poll_transmit()
        }

        fn cue(&mut self, label: &str, now: Instant) {
            assert_eq!(
                label, "register",
                "the only thing this session's application did"
            );
            let uri = |text: &str| Uri::parse_str(text).expect("a URI");
            let account = self.agent.add_account(
                Account::new(
                    uri("sip:alice@example.com"),
                    uri("sip:example.com"),
                    uri("sip:alice@192.0.2.1"),
                    TransportId(1),
                    "192.0.2.9:5060".parse().expect("the registrar"),
                )
                .credentials(Credentials::new("alice", "open sesame")),
            );
            self.agent
                .register(account, now)
                .expect("the REGISTER goes");
        }
    }

    fn phone(recording: &sipral_core::replay::Recording) -> Phone {
        Phone {
            agent: UserAgent::new(EndpointConfig::default(), recording.seed()).expect("an agent"),
        }
    }

    /// Every Enhanced Packet Block in a capture: its packet data and the
    /// direction its `epb_flags` names, `0` when it names none.
    fn packets(capture: &[u8]) -> Vec<(Vec<u8>, u32)> {
        let word =
            |at: usize| u32::from_le_bytes(capture[at..at + 4].try_into().expect("four bytes"));
        let mut found = Vec::new();
        let mut at = 0;
        while at < capture.len() {
            let (kind, total) = (word(at), word(at + 4) as usize);
            assert_eq!(
                word(at + total - 4) as usize,
                total,
                "a block's two lengths agree"
            );
            if kind == 6 {
                let captured = word(at + 20) as usize;
                let data = capture[at + 28..at + 28 + captured].to_vec();
                let options = at + 28 + captured.div_ceil(4) * 4;
                let mut direction = 0;
                if options < at + total - 4 {
                    let code = u16::from_le_bytes([capture[options], capture[options + 1]]);
                    assert_eq!(code, 2, "the one option written is epb_flags");
                    direction = word(options + 4);
                }
                found.push((data, direction));
            }
            at += total;
        }
        found
    }

    fn holds(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    }

    #[test]
    fn a_replayed_session_is_captured_in_both_directions_in_the_order_it_happened() {
        let recording = Recording::parse(FIXTURE).expect("the fixture reads");
        let mut target = phone(&recording);
        let capture = export_replayed(&recording, &mut target, Instant::now(), None)
            .expect("the session replays");
        let seen = packets(&capture);
        let directions: Vec<u32> = seen.iter().map(|(_, direction)| *direction).collect();
        // REGISTER, 401, REGISTER with credentials, 200, and the refresh
        assert_eq!(directions, [2, 1, 2, 1, 2], "outbound 2, inbound 1");
        let (first, _) = &seen[0];
        assert!(holds(first, "REGISTER sip:example.com SIP/2.0"));
        assert!(
            holds(first, "Call-ID: e49c8d74a73c5bdf49b1186b53e0e547"),
            "the seed in the file writes the Call-ID the recorded answers echo"
        );
        assert!(holds(&seen[2].0, "Authorization: Digest"));
        assert!(holds(&seen[3].0, "SIP/2.0 200 OK"));
    }

    #[test]
    fn a_recording_exported_without_a_replay_is_the_far_end_alone() {
        let recording = Recording::parse(FIXTURE).expect("the fixture reads");
        let capture = export(&recording, None).expect("nothing to redact");
        let directions: Vec<u32> = packets(&capture).iter().map(|(_, d)| *d).collect();
        assert_eq!(directions, [1, 1]);
    }

    #[test]
    fn a_replayed_capture_is_redacted_in_both_directions() {
        let recording = Recording::parse(FIXTURE).expect("the fixture reads");
        let mut target = phone(&recording);
        let capture = export_replayed(
            &recording,
            &mut target,
            Instant::now(),
            Some(Redactor::new(Mode::Delete)),
        )
        .expect("every message redacts");
        let seen = packets(&capture);
        assert_eq!(seen.len(), 5);
        for (data, _) in &seen {
            assert!(!holds(data, "alice"), "{}", String::from_utf8_lossy(data));
            assert!(!holds(data, "192.0.2.9"));
            assert!(!holds(data, "response="), "this end's digest never leaves");
        }
        assert!(holds(&seen[2].0, "Authorization: REDACTED"));
    }

    #[test]
    fn a_replay_the_layer_refuses_stops_the_export() {
        let mut recorder = Recorder::new(seed());
        let now = Instant::now();
        recorder.arrived(
            &Input::StreamData {
                transport: TransportId(3),
                data: b"INVITE",
            },
            now,
        );
        let recording = recorder.finish().expect("a whole recording");
        let mut endpoint = Endpoint::new(EndpointConfig::default(), seed()).expect("an endpoint");
        let outcome = export_replayed(&recording, &mut endpoint, now, None);
        assert!(
            matches!(outcome, Err(ExportError::Replay(_))),
            "{outcome:?}"
        );
    }
}
