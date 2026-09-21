// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Where a SIP domain says its server is: the SRV lookup of RFC 3263 §4.2, as
//! little of it as an example needs.
//!
//! The library leaves DNS to the application (`docs/04-ua.md`), and
//! `std::net` resolves a name to addresses and nothing else. That is not
//! enough for a real domain: `sip2sip.info`'s own address refuses SIP
//! outright, and the server is the one its `_sip._udp` record names. So this
//! asks the system's resolver for that record directly — one query, one
//! answer, over UDP — and falls back to the plain address when there is no
//! record, no resolver to ask, or no answer, which is what §4.2 says to do
//! when SRV finds nothing.
//!
//! Not a resolver: no retries, no TCP fallback for a truncated answer, no
//! NAPTR, no cache, and of several targets only the first in RFC 2782's
//! order — lowest priority, then highest weight rather than a weighted draw.
//! An application should use its platform's resolver; this is here so the
//! examples can be run as they are.

use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// `SRV` (RFC 2782).
const TYPE_SRV: u16 = 33;
/// `IN`.
const CLASS_IN: u16 = 1;
/// How long one nameserver gets to answer.
const PATIENCE: Duration = Duration::from_secs(3);
/// Labels followed through compression pointers before a name is given up
/// on: a pointer loop in a hostile answer would otherwise never end.
const MAX_JUMPS: usize = 16;

/// The address `domain`'s `service` record names (`"_sip._udp"`,
/// `"_sips._tcp"`), or `domain` itself on `port` when it has none.
pub(crate) fn resolve(domain: &str, service: &str, port: u16) -> io::Result<SocketAddr> {
    let named = format!("{service}.{domain}");
    if let Some((target, target_port)) = nameservers()
        .into_iter()
        .find_map(|server| query(server, &named).ok().flatten())
        && let Some(address) = (target.as_str(), target_port).to_socket_addrs()?.next()
    {
        return Ok(address);
    }
    (domain, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("cannot resolve {domain}")))
}

/// The nameservers `/etc/resolv.conf` lists, where there is one.
fn nameservers() -> Vec<SocketAddr> {
    std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver"))
        .filter_map(|rest| rest.trim().parse().ok())
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
}

/// Ask `server` for `name`'s SRV records, and pick one.
fn query(server: SocketAddr, name: &str) -> io::Result<Option<(String, u16)>> {
    let socket = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    socket.set_read_timeout(Some(PATIENCE))?;
    socket.connect(server)?;

    // an identifier that is not the same on every run is all an example
    // needs from it; the answer is also checked against the question
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| u16::try_from(since.subsec_nanos() & 0xFFFF).ok())
        .unwrap_or(0x5a5a);
    let mut question = Vec::with_capacity(64);
    for label in name.split('.').filter(|label| !label.is_empty()) {
        let length = u8::try_from(label.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "label too long"))?;
        question.push(length);
        question.extend_from_slice(label.as_bytes());
    }
    question.push(0);
    question.extend_from_slice(&TYPE_SRV.to_be_bytes());
    question.extend_from_slice(&CLASS_IN.to_be_bytes());

    let mut request = Vec::with_capacity(12 + question.len());
    request.extend_from_slice(&id.to_be_bytes());
    request.extend_from_slice(&[0x01, 0x00]); // a standard query, recursion desired
    request.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // one question
    request.extend_from_slice(&question);
    socket.send(&request)?;

    let mut answer = [0u8; 1500];
    let length = socket.recv(&mut answer)?;
    Ok(pick(
        answer.get(..length).unwrap_or_default(),
        id,
        &question,
    ))
}

/// The SRV target to use out of a DNS answer, if it is one to `id` and holds
/// any.
fn pick(message: &[u8], id: u16, question: &[u8]) -> Option<(String, u16)> {
    let flags = message.get(2..4)?;
    // an answer (QR set) to this query, with no error, to the one question
    if be16(message, 0)? != id
        || flags.first()? & 0x80 == 0
        || flags.get(1)? & 0x0F != 0
        || be16(message, 4)? != 1
        || message.get(12..12 + question.len())? != question
    {
        return None;
    }
    let answers = be16(message, 6)?;
    let mut at = 12 + question.len();
    let mut best: Option<(u16, u16, String, u16)> = None;
    for _ in 0..answers {
        at = skip_name(message, at)?;
        let kind = be16(message, at)?;
        let data_length = usize::from(be16(message, at + 8)?);
        let data_at = at + 10;
        at = data_at + data_length;
        if kind != TYPE_SRV || message.len() < at {
            continue;
        }
        let (priority, weight, port) = (
            be16(message, data_at)?,
            be16(message, data_at + 2)?,
            be16(message, data_at + 4)?,
        );
        let target = read_name(message, data_at + 6)?;
        // RFC 2782: a target of "." means the service is not offered here
        if target.is_empty() {
            continue;
        }
        let better = best
            .as_ref()
            .is_none_or(|(best_priority, best_weight, _, _)| {
                (priority, u16::MAX - weight) < (*best_priority, u16::MAX - *best_weight)
            });
        if better {
            best = Some((priority, weight, target, port));
        }
    }
    best.map(|(_, _, target, port)| (target, port))
}

/// The big-endian sixteen bits at `at`, when the message has them.
fn be16(message: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *message.get(at)?,
        *message.get(at + 1)?,
    ]))
}

/// Where the name starting at `at` ends.
fn skip_name(message: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let length = *message.get(at)?;
        match length {
            0 => return Some(at + 1),
            // a compression pointer ends the name in two octets
            0xC0..=0xFF => return Some(at + 2),
            _ => at += 1 + usize::from(length),
        }
    }
}

/// The name starting at `at`, pointers followed, as dotted text without the
/// root's trailing dot.
fn read_name(message: &[u8], mut at: usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumps = 0;
    loop {
        let length = *message.get(at)?;
        match length {
            0 => return Some(labels.join(".")),
            0xC0..=0xFF => {
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return None;
                }
                at = usize::from(u16::from_be_bytes([length & 0x3F, *message.get(at + 1)?]));
            }
            _ => {
                let label = message.get(at + 1..at + 1 + usize::from(length))?;
                labels.push(String::from_utf8_lossy(label).into_owned());
                at += 1 + usize::from(length);
            }
        }
    }
}
