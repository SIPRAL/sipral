// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A hook that sees every SIP message just before it leaves and just after it arrives.
//!
//! For a PBX or a carrier that needs a header no option covers, or sends one that has to go
//! before the endpoint reads the message. The hook gets the whole message as bytes and keeps it,
//! replaces it, or drops it. Outgoing, it runs in [`super::Endpoint::poll_transmit`], so a
//! retransmission passes through it again and a deterministic hook sends the identical bytes
//! (RFC 3261 §17.1.1.2); incoming, it runs on each datagram and on each message framed off a
//! connection, before the parser. Keep-alives (RFC 5626 §3.5.1's CRLF pings and pongs) are not
//! messages and never reach it.
//!
//! [`Rewrite`] edits a message's header fields and body and keeps `Content-Length` true.

use std::net::SocketAddr;

use super::transport::TransportProtocol;

/// Which way a message is going.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Direction {
    /// About to be handed to the transport.
    Outgoing,
    /// Just read from the transport, not yet parsed.
    Incoming,
}

/// One message as the hook sees it.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct HookedMessage<'a> {
    /// Which way it is going.
    pub direction: Direction,
    /// The message, from its start line to the end of its body.
    pub bytes: &'a [u8],
    /// The far end: where it goes, or where it came from. On a connection, the address the
    /// connection was bound to, or this end's own when none was named.
    pub remote: SocketAddr,
    /// What it travels over.
    pub protocol: TransportProtocol,
}

/// What the hook decided.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    /// The message goes on as it is.
    Keep,
    /// The message goes on as these bytes instead. Incoming, they are parsed as if they had
    /// arrived; outgoing, they are sent as they are, so `Content-Length` must match the body
    /// ([`Rewrite`] keeps it so).
    Replace(Box<[u8]>),
    /// The message goes no further: not sent, or not read. A transaction whose message is dropped
    /// retransmits and times out as if it were lost.
    Drop,
}

/// The hook itself. It runs on the thread that drives the endpoint and must not block.
pub type MessageHook = Box<dyn FnMut(&HookedMessage<'_>) -> Verdict + Send>;

/// The hook an endpoint holds; a closure has no `Debug` of its own.
pub(super) struct Installed(pub(super) MessageHook);

impl core::fmt::Debug for Installed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MessageHook")
    }
}

/// Whether `bytes` are only the CRLFs of a keep-alive (RFC 5626 §3.5.1), not a message.
pub(super) fn is_keepalive(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| matches!(byte, b'\r' | b'\n'))
}

/// A message taken apart into its start line, header fields and body, to change and put back.
///
/// Field names match case-insensitively (RFC 3261 §7.3.1), compact forms included: removing
/// `Contact` also removes `m`. A field folded over several lines is one field. Setting a field
/// replaces every instance of it with one, at the place of the first, or appends it at the end of
/// the header. [`Rewrite::finish`] writes `Content-Length` for the body as it is then.
#[derive(Clone, Debug)]
pub struct Rewrite {
    start: Vec<u8>,
    fields: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
}

/// The compact forms of RFC 3261 §7.3.3 and the extensions that define one.
const COMPACT: &[(&[u8], &[u8])] = &[
    (b"accept-contact", b"a"),
    (b"allow-events", b"u"),
    (b"call-id", b"i"),
    (b"contact", b"m"),
    (b"content-encoding", b"e"),
    (b"content-length", b"l"),
    (b"content-type", b"c"),
    (b"event", b"o"),
    (b"from", b"f"),
    (b"identity", b"y"),
    (b"refer-to", b"r"),
    (b"referred-by", b"b"),
    (b"reject-contact", b"j"),
    (b"request-disposition", b"d"),
    (b"session-expires", b"x"),
    (b"subject", b"s"),
    (b"supported", b"k"),
    (b"to", b"t"),
    (b"via", b"v"),
];

/// The full name of a field, lower case, whichever form it was written in.
fn canonical(name: &[u8]) -> Vec<u8> {
    let lower = name.to_ascii_lowercase();
    COMPACT
        .iter()
        .find(|(_, compact)| *compact == lower.as_slice())
        .map_or(lower, |(full, _)| full.to_vec())
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |last| last + 1);
    bytes.get(start..end).unwrap_or_default()
}

/// Why a message could not be taken apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RewriteError {
    /// No empty line ends the header.
    NoEndOfHeader,
    /// A header line is neither a field nor the continuation of one.
    BadHeaderLine,
}

impl core::fmt::Display for RewriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NoEndOfHeader => "no empty line ends the header",
            Self::BadHeaderLine => "a header line is neither a field nor a continuation",
        })
    }
}

impl std::error::Error for RewriteError {}

impl Rewrite {
    /// Take `message` apart. The body is everything after the empty line; a `Content-Length` that
    /// says otherwise is rewritten by [`Rewrite::finish`].
    ///
    /// # Errors
    /// [`RewriteError`] when the bytes have no header to edit.
    pub fn parse(message: &[u8]) -> Result<Self, RewriteError> {
        let end = message
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or(RewriteError::NoEndOfHeader)?;
        let head = message.get(..end).unwrap_or_default();
        let body = message.get(end + 4..).unwrap_or_default().to_vec();
        let mut lines = head
            .split(|byte| *byte == b'\n')
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
        let start = lines.next().unwrap_or_default().to_vec();
        let mut fields: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for line in lines {
            if line
                .first()
                .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
            {
                // RFC 3261 §7.3.1: a folded line continues the field above it
                let (_, value) = fields.last_mut().ok_or(RewriteError::BadHeaderLine)?;
                value.push(b' ');
                value.extend_from_slice(trim(line));
                continue;
            }
            let colon = line
                .iter()
                .position(|byte| *byte == b':')
                .ok_or(RewriteError::BadHeaderLine)?;
            let (name, value) = line.split_at(colon);
            let name = trim(name);
            if name.is_empty() {
                return Err(RewriteError::BadHeaderLine);
            }
            fields.push((
                name.to_vec(),
                trim(value.get(1..).unwrap_or_default()).to_vec(),
            ));
        }
        Ok(Self {
            start,
            fields,
            body,
        })
    }

    /// The start line: request line or status line.
    #[must_use]
    pub fn start_line(&self) -> &[u8] {
        &self.start
    }

    /// Replace the start line.
    pub fn set_start_line(&mut self, line: &[u8]) -> &mut Self {
        self.start = line.to_vec();
        self
    }

    /// The value of each instance of the field `name`, in order.
    pub fn values<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a [u8]> + 'a {
        let wanted = canonical(name.as_bytes());
        self.fields
            .iter()
            .filter(move |(field, _)| canonical(field) == wanted)
            .map(|(_, value)| value.as_slice())
    }

    /// Put `value` in the field `name`: every instance of it becomes one, at the first one's
    /// place, or a new field at the end of the header.
    pub fn set(&mut self, name: &str, value: &[u8]) -> &mut Self {
        let wanted = canonical(name.as_bytes());
        let first = self
            .fields
            .iter()
            .position(|(field, _)| canonical(field) == wanted);
        match first {
            Some(at) => {
                if let Some(slot) = self.fields.get_mut(at) {
                    *slot = (name.as_bytes().to_vec(), value.to_vec());
                }
                let mut index = 0usize;
                self.fields.retain(|(field, _)| {
                    let keep = index <= at || canonical(field) != wanted;
                    index += 1;
                    keep
                });
            }
            None => self.fields.push((name.as_bytes().to_vec(), value.to_vec())),
        }
        self
    }

    /// Add another instance of the field `name`, after every field already there.
    pub fn add(&mut self, name: &str, value: &[u8]) -> &mut Self {
        self.fields.push((name.as_bytes().to_vec(), value.to_vec()));
        self
    }

    /// Take out every instance of the field `name`.
    pub fn remove(&mut self, name: &str) -> &mut Self {
        let wanted = canonical(name.as_bytes());
        self.fields.retain(|(field, _)| canonical(field) != wanted);
        self
    }

    /// The body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Replace the body; `Content-Type` is the caller's to set.
    pub fn set_body(&mut self, body: &[u8]) -> &mut Self {
        self.body = body.to_vec();
        self
    }

    /// The message again, `Content-Length` written for the body at the place of the old one, or
    /// at the end of the header.
    #[must_use]
    pub fn finish(mut self) -> Box<[u8]> {
        let length = self.body.len().to_string();
        self.set("Content-Length", length.as_bytes());
        let mut out = Vec::with_capacity(
            self.start.len() + self.body.len() + self.fields.len().saturating_mul(32) + 4,
        );
        out.extend_from_slice(&self.start);
        out.extend_from_slice(b"\r\n");
        for (name, value) in &self.fields {
            out.extend_from_slice(name);
            out.extend_from_slice(b": ");
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out.into_boxed_slice()
    }
}
