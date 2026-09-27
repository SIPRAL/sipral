// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A D2 recording, turned into pcapng packets.
//!
//! Every [`Arrival::Datagram`] and [`Arrival::StreamData`] frame the
//! recording holds becomes one packet, addressed and timed the way the
//! frame was recorded; [`Arrival::TransportBound`] is not a packet, it is
//! where a stream transport's two ends come from, since a `StreamData`
//! frame carries none of its own. `Arrival::StreamClosed` and
//! `Arrival::TransportFailed` are not on the wire and produce nothing.

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;

use sipral_core::replay::{Arrival, Recording, Step};

use crate::packet;
use crate::pcapng::Writer;
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
/// # Errors
/// [`RedactError`] when `redactor` is given and a frame's bytes are not a
/// message the parser can read: the export stops rather than write a frame
/// nobody has redacted.
pub fn export(
    recording: &Recording,
    mut redactor: Option<Redactor>,
) -> Result<Vec<u8>, RedactError> {
    let mut writer = Writer::new();
    let mut bound: HashMap<u32, Bound> = HashMap::new();
    let mut tcp_seq: HashMap<u32, u32> = HashMap::new();
    let mut ident: u16 = 0;

    for frame in recording.frames() {
        let Step::Arrived(arrival) = &frame.step else {
            continue;
        };
        let timestamp_us = TIMESTAMP_ORIGIN_US.saturating_add(duration_to_us(frame.at));
        match arrival {
            Arrival::TransportBound {
                transport,
                local,
                remote,
                ..
            } => {
                bound.insert(
                    transport.0,
                    Bound {
                        local: *local,
                        remote: *remote,
                    },
                );
            }
            Arrival::Datagram {
                remote,
                local,
                data,
                ..
            } => {
                let payload = match redactor.as_mut() {
                    Some(r) => redact_message(data.as_bytes(), r)?,
                    None => data.as_bytes().to_vec(),
                };
                let (src, dst) = match redactor.as_mut() {
                    Some(r) => (redact_addr(*remote, r), redact_addr(*local, r)),
                    None => (*remote, *local),
                };
                ident = ident.wrapping_add(1);
                writer.packet(timestamp_us, &build_udp(src, dst, &payload, ident));
            }
            Arrival::StreamData { transport, data } => {
                let Some(b) = bound.get(&transport.0) else {
                    continue;
                };
                let Some(remote) = b.remote else {
                    continue; // no far end was ever bound for this connection
                };
                let payload = match redactor.as_mut() {
                    Some(r) => redact_message(data.as_bytes(), r)?,
                    None => data.as_bytes().to_vec(),
                };
                let (src, dst) = match redactor.as_mut() {
                    Some(r) => (redact_addr(remote, r), redact_addr(b.local, r)),
                    None => (remote, b.local),
                };
                ident = ident.wrapping_add(1);
                let seq = tcp_seq.entry(transport.0).or_insert(1);
                writer.packet(timestamp_us, &build_tcp(src, dst, &payload, ident, *seq));
                *seq = seq.wrapping_add(u32::try_from(data.as_bytes().len()).unwrap_or(u32::MAX));
            }
            Arrival::StreamClosed { .. } | Arrival::TransportFailed { .. } => {}
        }
    }

    Ok(writer.finish())
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
    use super::export;
    use crate::redact::{Mode, Redactor};
    use sipral_core::endpoint::{Input, TransportId, TransportProtocol};
    use sipral_core::replay::Recorder;
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
}
