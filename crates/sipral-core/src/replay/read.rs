// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Reading a recording back.
//!
//! Strict on purpose, and the version line is the reason. A recording is fed
//! into a state machine, so a reader that shrugged at a line it did not
//! understand would replay a session that nobody recorded and report the
//! result as if it meant something. Every line either says what it says or
//! stops the read.
//!
//! A carriage return at the end of a line is dropped before anything else
//! looks at it. That is not laxity: the file travels by mail and through
//! ticket systems, and a payload's own carriage returns are spelled `\r` and
//! are never the last character of a line of the file.

use std::net::SocketAddr;
use std::time::Duration;

use super::error::ReadError;
use super::frame::{Arrival, Frame, Payload, Step, failure_kind};
use super::recording::Recording;
use super::text::{one_line, read_payload};
use crate::endpoint::{TransportId, TransportProtocol};
use crate::transaction::{DialogId, Raw};

/// A frame whose payload lines have not all arrived yet.
struct Pending {
    at: Duration,
    line: usize,
    kind: Kind,
    data: Vec<u8>,
}

/// The two frames that carry bytes.
enum Kind {
    Datagram {
        transport: TransportId,
        remote: SocketAddr,
        local: SocketAddr,
    },
    Stream {
        transport: TransportId,
    },
}

/// The whole file.
pub(super) fn read(text: &str) -> Result<Recording, ReadError> {
    let mut lines = text.split('\n').map(|line| line.trim_end_matches('\r'));
    let banner = lines.next().ok_or(ReadError::NotARecording)?;
    version(banner)?;

    let mut seed = None;
    let mut note = None;
    let mut frames = Vec::new();
    let mut pending: Option<Pending> = None;

    for (offset, line) in lines.enumerate() {
        // the header line was line one, and the enumeration starts at the one
        // after it
        let at = offset + 2;
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('|') {
            let text = rest.strip_prefix(' ').unwrap_or(rest);
            let held = pending
                .as_mut()
                .ok_or(ReadError::StrayPayload { line: at })?;
            if !read_payload(text, &mut held.data) {
                return Err(ReadError::NotText { line: at });
            }
            continue;
        }
        if let Some(frame) = pending.take() {
            frames.push(settle(&frame)?);
        }
        if line.starts_with('+') {
            let last = frames
                .last()
                .map_or(Duration::ZERO, |frame: &Frame| frame.at);
            match frame(line, at, last)? {
                Taken::Done(frame) => frames.push(frame),
                Taken::Pending(held) => pending = Some(held),
            }
            continue;
        }
        if !frames.is_empty() {
            // a header after the transcript has started is either a file that
            // was pasted into another one or a version this reader is not
            // reading correctly
            return Err(ReadError::Syntax { line: at });
        }
        match line.split_once(' ') {
            Some(("seed", value)) => {
                seed = Some(hex32(value).ok_or(ReadError::Syntax { line: at })?);
            }
            Some(("note", value)) => {
                if !one_line(value) {
                    return Err(ReadError::NotText { line: at });
                }
                note = Some(Box::from(value));
            }
            _ => return Err(ReadError::Syntax { line: at }),
        }
    }
    if let Some(frame) = pending.take() {
        frames.push(settle(&frame)?);
    }

    Ok(Recording::new(seed.ok_or(ReadError::NoSeed)?, note, frames))
}

/// The first line, which is the only thing read before the version is known.
fn version(banner: &str) -> Result<(), ReadError> {
    let value = banner
        .strip_prefix(Recording::MAGIC)
        .and_then(|rest| rest.strip_prefix(' '))
        .and_then(|rest| rest.parse::<u32>().ok())
        .filter(|found| *found > 0)
        .ok_or(ReadError::NotARecording)?;
    if value > Recording::VERSION {
        return Err(ReadError::Version {
            found: value,
            supported: Recording::VERSION,
        });
    }
    Ok(())
}

/// A frame line, either finished or waiting for its payload.
enum Taken {
    Done(Frame),
    Pending(Pending),
}

/// One `+` line.
fn frame(line: &str, at: usize, last: Duration) -> Result<Taken, ReadError> {
    let bad = ReadError::Syntax { line: at };
    let (stamp, rest) = line.split_once(' ').ok_or(bad)?;
    let when = offset(stamp).ok_or(bad)?;
    if when < last {
        return Err(ReadError::Backwards { line: at });
    }
    let (keyword, args) = rest.split_once(' ').unwrap_or((rest, ""));
    // the two frames whose argument is prose the application wrote, taken
    // whole before anything starts splitting on spaces
    match keyword {
        "wake" if args.is_empty() => {
            return Ok(Taken::Done(Frame {
                at: when,
                step: Step::Woke,
            }));
        }
        "cue" => {
            if !one_line(args) {
                return Err(ReadError::NotText { line: at });
            }
            return Ok(Taken::Done(Frame {
                at: when,
                step: Step::Cue(Box::from(args)),
            }));
        }
        _ => {}
    }
    let mut word = args.split(' ').filter(|word| !word.is_empty());
    let step = match keyword {
        "datagram" => {
            let transport = word.next().and_then(transport).ok_or(bad)?;
            let remote = word.next().and_then(address).ok_or(bad)?;
            let local = word.next().and_then(address).ok_or(bad)?;
            return Ok(Taken::Pending(Pending {
                at: when,
                line: at,
                kind: Kind::Datagram {
                    transport,
                    remote,
                    local,
                },
                data: Vec::new(),
            }));
        }
        "stream" => {
            let transport = word.next().and_then(transport).ok_or(bad)?;
            return Ok(Taken::Pending(Pending {
                at: when,
                line: at,
                kind: Kind::Stream { transport },
                data: Vec::new(),
            }));
        }
        "resolved" => {
            return Ok(Taken::Done(Frame {
                at: when,
                step: resolved(&mut word, bad)?,
            }));
        }
        "closed" => Step::Arrived(Arrival::StreamClosed {
            transport: word.next().and_then(transport).ok_or(bad)?,
        }),
        "bound" => {
            let transport = word.next().and_then(transport).ok_or(bad)?;
            let protocol = word
                .next()
                .and_then(|token| TransportProtocol::from_token(token.as_bytes()))
                .ok_or(bad)?;
            let local = word.next().and_then(address).ok_or(bad)?;
            let remote = match word.next().ok_or(bad)? {
                "-" => None,
                text => Some(address(text).ok_or(bad)?),
            };
            Step::Arrived(Arrival::TransportBound {
                transport,
                protocol,
                local,
                remote,
            })
        }
        "failed" => Step::Arrived(Arrival::TransportFailed {
            transport: word.next().and_then(transport).ok_or(bad)?,
            error: word.next().and_then(failure_kind).ok_or(bad)?,
        }),
        _ => return Err(bad),
    };
    if word.next().is_some() {
        return Err(bad);
    }
    Ok(Taken::Done(Frame { at: when, step }))
}

/// A `resolved` line's own words: the dialog it answers for, the protocol
/// (`-` for none), then the addresses
/// [`Recorder::resolved`](super::Recorder::resolved) was handed.
fn resolved<'a>(
    word: &mut impl Iterator<Item = &'a str>,
    bad: ReadError,
) -> Result<Step, ReadError> {
    let dialog = word.next().and_then(dialog_id).ok_or(bad)?;
    let protocol = match word.next().ok_or(bad)? {
        "-" => None,
        token => Some(TransportProtocol::from_token(token.as_bytes()).ok_or(bad)?),
    };
    let mut addresses = Vec::new();
    for token in word {
        addresses.push(address(token).ok_or(bad)?);
    }
    Ok(Step::Resolved {
        dialog,
        addresses: addresses.into(),
        protocol,
    })
}

/// A frame whose payload lines are all in.
fn settle(held: &Pending) -> Result<Frame, ReadError> {
    let data = Payload::new(&held.data).ok_or(ReadError::NotText { line: held.line })?;
    let arrival = match held.kind {
        Kind::Datagram {
            transport,
            remote,
            local,
        } => Arrival::Datagram {
            transport,
            remote,
            local,
            data,
        },
        Kind::Stream { transport } => Arrival::StreamData { transport, data },
    };
    Ok(Frame {
        at: held.at,
        step: Step::Arrived(arrival),
    })
}

/// `+12.000000000`, to the nanosecond, which is the resolution an `Instant`
/// has and therefore the resolution a session was driven at.
fn offset(stamp: &str) -> Option<Duration> {
    let (secs, nanos) = stamp.strip_prefix('+')?.split_once('.')?;
    if nanos.len() != 9 || !nanos.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(Duration::new(secs.parse().ok()?, nanos.parse().ok()?))
}

fn transport(text: &str) -> Option<TransportId> {
    text.parse().ok().map(TransportId)
}

/// `3.0`, slot and generation, as [`Recorder::resolved`](super::Recorder::resolved)
/// wrote it.
fn dialog_id(text: &str) -> Option<DialogId> {
    let (slot, generation) = text.split_once('.')?;
    Some(DialogId::new(Raw {
        slot: slot.parse().ok()?,
        generation: generation.parse().ok()?,
    }))
}

fn address(text: &str) -> Option<SocketAddr> {
    text.parse().ok()
}

/// The seed, as sixty-four hexadecimal digits.
fn hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut seed = [0_u8; 32];
    let mut digits = text.chars();
    for byte in &mut seed {
        let high = digits.next()?.to_digit(16)?;
        let low = digits.next()?.to_digit(16)?;
        *byte = u8::try_from(high * 16 + low).ok()?;
    }
    Some(seed)
}
