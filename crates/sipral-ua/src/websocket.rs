// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! SIP over a WebSocket this stack opens itself (RFC 7118 on RFC 6455).
//!
//! The application still owns the socket. What it hands over is a TCP
//! connection, or a TLS one it secured with whatever TLS it already uses for
//! `sips:`, and it binds that connection as a `Ws` or `Wss` transport *with
//! the far end named*. From then on the connection is this module's: the
//! opening handshake goes out as the first bytes to write, the server's
//! answer is checked, every SIP message leaves as one masked frame and every
//! frame that arrives is unmasked, reassembled and handed to the endpoint as
//! the one message RFC 7118 §4.2 says it is. Pings are answered, pings are
//! sent, a close from the server is answered, and
//! [`UserAgent::close_websocket`] closes one from this end.
//!
//! An application that binds a WebSocket transport *without* a far end keeps
//! what it had before this module existed: it does the handshake and the
//! framing itself and feeds each message in as a datagram.
//!
//! # The handshake (RFC 6455 §4.1, RFC 7118 §4.1)
//!
//! `GET` on the resource with `Upgrade: websocket`, `Connection: Upgrade`, a
//! fresh sixteen-byte `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13` and
//! `Sec-WebSocket-Protocol: sip`. The server's answer has to be a 101 whose
//! `Upgrade` and `Connection` agree, whose `Sec-WebSocket-Accept` is the
//! SHA-1 of the key and the protocol's GUID in base64, which selects `sip`
//! as the subprotocol and which turns on no extension, since none was
//! offered. Anything else fails the connection (§4.1: "the client MUST
//! _Fail the WebSocket Connection_"). SIP that the endpoint writes before the
//! answer arrives waits for it, in order.
//!
//! The resource and the `Host` are [`WebSocketTarget`]'s, set per far end
//! with [`UserAgent::set_websocket_target`]. Left unset, the `Host` is the
//! far end's address and the resource is `/ws` — the path Asterisk serves
//! SIP on and one that Kamailio, OpenSIPS and FreeSWITCH accept as readily
//! as any other — so a connection made through the C ABI, which has no field
//! for either yet, reaches the common servers as it stands.
//!
//! # Frames (RFC 6455 §5)
//!
//! Every frame this end sends is masked with a key drawn for it (§5.3), and
//! every frame the server sends must not be (§5.1). A SIP message goes out
//! as one text frame when it is UTF-8 and as one binary frame when it is
//! not (RFC 7118 §4.2); both kinds are accepted coming in. A fragmented
//! message is put back together before it is handed on, a control frame may
//! arrive between its fragments, and nothing larger than
//! [`MAX_MESSAGE_BYTES`] is ever held. A frame that breaks the protocol
//! closes the connection with the status §7.4.1 names for it.
//!
//! # Keeping it alive, and noticing it died
//!
//! A ping goes every [`PING_EVERY`] while the connection is quiet in that
//! direction, and a pong has [`PONG_WAIT`] to come back; a server that
//! answers nothing for that long is a connection that is gone, and it is
//! failed the way RFC 5626 §4.4.1 fails a flow that stops answering CRLF.
//! A handshake that is not answered within [`OPENING_WAIT`] fails too.
//!
//! A connection that fails or closes is told the way a TCP or TLS one is:
//! the transport is retired, the transactions on it fail, an account on a
//! connection of its own asks for a new one (the `flow` module), and
//! [`Event::FlowFailed`] tells the application to close its socket.
//! [`UserAgent::websocket_failure`] says why.
//!
//! # The `.invalid` host (RFC 7118 Appendix B.1)
//!
//! A WebSocket client cannot be reached at the address its socket has, so
//! the `Via` of everything it sends names a random host under `.invalid`
//! (RFC 2606), and so does the `Contact` of an account that would otherwise
//! name the bound address. The same far end keeps the same name across
//! reconnections, so a binding refreshed on a new connection is the same
//! binding.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha1::{Digest, Sha1};
use sipral_core::endpoint::{
    Event, Input, ReceiveError, Transmit, TransportErrorKind, TransportId, TransportProtocol,
};

use crate::agent::UserAgent;
use crate::event::UaEvent;

/// RFC 6455 §1.3's GUID, appended to the key before it is hashed.
const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The largest SIP message one WebSocket message may carry. Four times the
/// 65 535 bytes a datagram can, and far past anything a SIP message is.
pub const MAX_MESSAGE_BYTES: usize = 262_144;

/// The largest handshake answer read before it is given up on.
const MAX_HEAD_BYTES: usize = 8_192;

/// How long the server has to answer the opening handshake.
pub const OPENING_WAIT: Duration = Duration::from_secs(10);

/// How long a connection goes without this end sending anything before a
/// ping is sent on it.
pub const PING_EVERY: Duration = Duration::from_secs(25);

/// How long a ping waits for its pong.
pub const PONG_WAIT: Duration = Duration::from_secs(10);

/// The resource asked for when nothing else was set.
pub const DEFAULT_RESOURCE: &str = "/ws";

// -- frames ------------------------------------------------------------------

/// What one frame, or one reassembled message, carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// A whole text message, checked to be UTF-8.
    Text(Vec<u8>),
    /// A whole binary message.
    Binary(Vec<u8>),
    /// A ping, with its application data.
    Ping(Vec<u8>),
    /// A pong, with its application data.
    Pong(Vec<u8>),
    /// A close, with the status code when it carried one and the reason.
    Close {
        /// The status code (§7.4), when the frame had a body.
        code: Option<u16>,
        /// The reason, UTF-8.
        reason: Vec<u8>,
    },
}

/// Why the frames coming in cannot be read on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameError {
    /// RSV1, RSV2 or RSV3 set with no extension negotiated (§5.2).
    Reserved,
    /// An opcode §5.2 reserves.
    UnknownOpcode(u8),
    /// A frame from the server that was masked (§5.1).
    Masked,
    /// A control frame longer than 125 bytes, or fragmented (§5.5).
    BadControl,
    /// A continuation with no message to continue, or a new message
    /// started before the last one ended (§5.4).
    BadFragment,
    /// A length with its top bit set, or written longer than it had to be
    /// (§5.2: "the minimal number of bytes MUST be used").
    BadLength,
    /// A message longer than [`MAX_MESSAGE_BYTES`].
    TooLarge,
    /// A text message, or a close reason, that is not UTF-8 (§8.1).
    NotUtf8,
    /// A close body of one byte, or with a code §7.4 does not allow on the
    /// wire.
    BadClose,
}

impl FrameError {
    /// The status the connection is closed with (§7.4.1).
    #[must_use]
    pub const fn close_code(self) -> u16 {
        match self {
            Self::TooLarge => 1009,
            Self::NotUtf8 => 1007,
            Self::Reserved
            | Self::UnknownOpcode(_)
            | Self::Masked
            | Self::BadControl
            | Self::BadFragment
            | Self::BadLength
            | Self::BadClose => 1002,
        }
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Reserved => f.write_str("a reserved bit set with no extension agreed"),
            Self::UnknownOpcode(code) => write!(f, "opcode {code:#x}, which is reserved"),
            Self::Masked => f.write_str("a masked frame from the server"),
            Self::BadControl => f.write_str("a control frame fragmented or over 125 bytes"),
            Self::BadFragment => f.write_str("a fragment out of order"),
            Self::BadLength => f.write_str("a payload length not written in its minimal form"),
            Self::TooLarge => write!(f, "a message over {MAX_MESSAGE_BYTES} bytes"),
            Self::NotUtf8 => f.write_str("text that is not UTF-8"),
            Self::BadClose => f.write_str("a close frame with a body no close may carry"),
        }
    }
}

impl core::error::Error for FrameError {}

const CONTINUATION: u8 = 0x0;
const TEXT: u8 = 0x1;
const BINARY: u8 = 0x2;
const CLOSE: u8 = 0x8;
const PING: u8 = 0x9;
const PONG: u8 = 0xA;

/// The frames a server sends, read off the bytes in whatever pieces they
/// arrive.
///
/// Push what was read, then take frames until there are none. A message
/// sent in fragments comes out whole, once its last fragment is in; control
/// frames come out as they arrive, between the fragments if that is where
/// they were. After an error nothing more is read: the connection has to be
/// closed.
#[derive(Debug, Default)]
pub struct FrameReader {
    buffer: Vec<u8>,
    /// A message whose first fragments are in: whether it is text, and what
    /// it holds so far.
    partial: Option<(bool, Vec<u8>)>,
    broken: Option<FrameError>,
}

impl FrameReader {
    /// A reader with nothing in it.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buffer: Vec::new(),
            partial: None,
            broken: None,
        }
    }

    /// Bytes read off the connection.
    pub fn push(&mut self, data: &[u8]) {
        if self.broken.is_none() {
            self.buffer.extend_from_slice(data);
        }
    }

    /// How many bytes are held: read and not yet a frame, and the fragments
    /// of a message not yet whole. Never more than a frame's header and
    /// [`MAX_MESSAGE_BYTES`] past what the last [`FrameReader::push`] added.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buffer.len() + self.partial.as_ref().map_or(0, |(_, held)| held.len())
    }

    /// The next frame, `None` when what is held is not a whole one yet.
    ///
    /// # Errors
    /// The first thing that breaks RFC 6455, and the same error on every
    /// call after it.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        if let Some(broken) = self.broken {
            return Err(broken);
        }
        loop {
            match self.one() {
                Ok(Some(Step::Frame(frame))) => return Ok(Some(frame)),
                Ok(Some(Step::Fragment)) => {}
                Ok(None) => return Ok(None),
                Err(error) => {
                    self.broken = Some(error);
                    self.buffer = Vec::new();
                    self.partial = None;
                    return Err(error);
                }
            }
        }
    }

    fn one(&mut self) -> Result<Option<Step>, FrameError> {
        let Some(head) = Head::read(&self.buffer)? else {
            return Ok(None);
        };
        let already = self.partial.as_ref().map_or(0, |(_, held)| held.len());
        let control = head.opcode & 0x8 != 0;
        if !control && already.saturating_add(head.length) > MAX_MESSAGE_BYTES {
            return Err(FrameError::TooLarge);
        }
        let end = head.header.saturating_add(head.length);
        let Some(payload) = self.buffer.get(head.header..end) else {
            return Ok(None);
        };
        let payload = payload.to_vec();
        self.buffer.drain(..end);
        match head.opcode {
            PING => Ok(Some(Step::Frame(Frame::Ping(payload)))),
            PONG => Ok(Some(Step::Frame(Frame::Pong(payload)))),
            CLOSE => close_of(&payload).map(|frame| Some(Step::Frame(frame))),
            TEXT | BINARY => {
                if self.partial.is_some() {
                    return Err(FrameError::BadFragment);
                }
                let text = head.opcode == TEXT;
                if head.fin {
                    return whole(text, payload).map(|frame| Some(Step::Frame(frame)));
                }
                self.partial = Some((text, payload));
                Ok(Some(Step::Fragment))
            }
            CONTINUATION => {
                let Some((text, mut so_far)) = self.partial.take() else {
                    return Err(FrameError::BadFragment);
                };
                so_far.extend_from_slice(&payload);
                if head.fin {
                    return whole(text, so_far).map(|frame| Some(Step::Frame(frame)));
                }
                self.partial = Some((text, so_far));
                Ok(Some(Step::Fragment))
            }
            other => Err(FrameError::UnknownOpcode(other)),
        }
    }
}

enum Step {
    Frame(Frame),
    Fragment,
}

/// A frame's first bytes, read.
struct Head {
    fin: bool,
    opcode: u8,
    /// How many bytes the header takes.
    header: usize,
    length: usize,
}

impl Head {
    /// The header at the front of `buffer`, `None` until all of it is there.
    fn read(buffer: &[u8]) -> Result<Option<Self>, FrameError> {
        let (Some(&first), Some(&second)) = (buffer.first(), buffer.get(1)) else {
            return Ok(None);
        };
        if first & 0x70 != 0 {
            return Err(FrameError::Reserved);
        }
        let opcode = first & 0x0F;
        if !matches!(opcode, CONTINUATION | TEXT | BINARY | CLOSE | PING | PONG) {
            return Err(FrameError::UnknownOpcode(opcode));
        }
        let fin = first & 0x80 != 0;
        if second & 0x80 != 0 {
            return Err(FrameError::Masked);
        }
        let short = second & 0x7F;
        let control = opcode & 0x8 != 0;
        if control && (!fin || short > 125) {
            return Err(FrameError::BadControl);
        }
        let (header, length) = match short {
            126 => {
                let Some(bytes) = buffer.get(2..4) else {
                    return Ok(None);
                };
                let length = usize::from(u16::from_be_bytes([
                    bytes.first().copied().unwrap_or_default(),
                    bytes.get(1).copied().unwrap_or_default(),
                ]));
                if length < 126 {
                    return Err(FrameError::BadLength);
                }
                (4, length)
            }
            127 => {
                let Some(bytes) = buffer.get(2..10) else {
                    return Ok(None);
                };
                let mut be = [0_u8; 8];
                be.copy_from_slice(bytes);
                let length = u64::from_be_bytes(be);
                if length >> 63 != 0 || length <= 0xFFFF {
                    return Err(FrameError::BadLength);
                }
                // anything that does not fit in memory is over the limit too
                let length = usize::try_from(length).map_err(|_| FrameError::TooLarge)?;
                (10, length)
            }
            short => (2, usize::from(short)),
        };
        if !control && length > MAX_MESSAGE_BYTES {
            return Err(FrameError::TooLarge);
        }
        Ok(Some(Self {
            fin,
            opcode,
            header,
            length,
        }))
    }
}

fn whole(text: bool, payload: Vec<u8>) -> Result<Frame, FrameError> {
    if text {
        if core::str::from_utf8(&payload).is_err() {
            return Err(FrameError::NotUtf8);
        }
        return Ok(Frame::Text(payload));
    }
    Ok(Frame::Binary(payload))
}

/// A close frame's body (§5.5.1): nothing, or a code and a UTF-8 reason.
fn close_of(payload: &[u8]) -> Result<Frame, FrameError> {
    match payload {
        [] => Ok(Frame::Close {
            code: None,
            reason: Vec::new(),
        }),
        [_] => Err(FrameError::BadClose),
        [high, low, reason @ ..] => {
            let code = u16::from_be_bytes([*high, *low]);
            // §7.4.1 and §7.4.2: the codes an endpoint may send. 1004, 1005,
            // 1006 and 1015 are reserved, and nothing below 1000 is used
            let allowed = matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999);
            if !allowed {
                return Err(FrameError::BadClose);
            }
            if core::str::from_utf8(reason).is_err() {
                return Err(FrameError::NotUtf8);
            }
            Ok(Frame::Close {
                code: Some(code),
                reason: reason.to_vec(),
            })
        }
    }
}

/// One frame as a client sends it: final, masked with `mask` (§5.3).
#[must_use]
pub fn client_frame(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | (opcode & 0x0F));
    match payload.len() {
        short @ 0..=125 => out.push(0x80 | u8::try_from(short).unwrap_or(125)),
        medium @ 126..=0xFFFF => {
            out.push(0x80 | 0x7E);
            out.extend_from_slice(&u16::try_from(medium).unwrap_or(u16::MAX).to_be_bytes());
        }
        long => {
            out.push(0x80 | 0x7F);
            out.extend_from_slice(&(long as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(&mask);
    out.extend(
        payload
            .iter()
            .zip(mask.iter().cycle())
            .map(|(byte, key)| byte ^ key),
    );
    out
}

/// The opcode a SIP message goes out under: text when it is UTF-8, binary
/// when it is not (RFC 7118 §4.2).
#[must_use]
pub fn opcode_for(message: &[u8]) -> u8 {
    if core::str::from_utf8(message).is_ok() {
        TEXT
    } else {
        BINARY
    }
}

/// The opcode of a text frame, for a caller writing frames of its own.
pub const OPCODE_TEXT: u8 = TEXT;
/// The opcode of a binary frame.
pub const OPCODE_BINARY: u8 = BINARY;
/// The opcode of a close frame.
pub const OPCODE_CLOSE: u8 = CLOSE;
/// The opcode of a ping.
pub const OPCODE_PING: u8 = PING;
/// The opcode of a pong.
pub const OPCODE_PONG: u8 = PONG;

// -- the handshake -----------------------------------------------------------

/// The `Sec-WebSocket-Accept` a server owes for `key` (§4.2.2): the SHA-1 of
/// the key and the GUID, in base64.
#[must_use]
pub fn accept_for(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(GUID);
    base64(hasher.finalize().as_slice())
}

/// RFC 4648 §4 base64, with padding.
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let symbol = |index: u32| {
        ALPHABET
            .get(usize::try_from(index & 0x3F).unwrap_or_default())
            .map_or('=', |byte| char::from(*byte))
    };
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let a = u32::from(chunk.first().copied().unwrap_or_default());
        let b = u32::from(chunk.get(1).copied().unwrap_or_default());
        let c = u32::from(chunk.get(2).copied().unwrap_or_default());
        let triple = (a << 16) | (b << 8) | c;
        out.push(symbol(triple >> 18));
        out.push(symbol(triple >> 12));
        out.push(if chunk.len() > 1 {
            symbol(triple >> 6)
        } else {
            '='
        });
        out.push(if chunk.len() > 2 { symbol(triple) } else { '=' });
    }
    out
}

/// Where a WebSocket connection to one far end asks to go: the `Host` it
/// names and the resource it asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebSocketTarget {
    host: String,
    resource: String,
}

/// Why a [`WebSocketTarget`] was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetError {
    /// The host is empty or holds a character a `Host` header cannot.
    Host,
    /// The resource does not start with `/`, or holds a space, a control
    /// character or a `#` (RFC 6455 §3: no fragment).
    Resource,
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Host => "not a host a Host header can carry",
            Self::Resource => "not a resource name: a path from /, with no space or fragment",
        })
    }
}

impl core::error::Error for TargetError {}

impl WebSocketTarget {
    /// `host` (a name or an address, with a port when it is not the
    /// scheme's) and `resource` (the path and query of the `ws-URI`).
    ///
    /// # Errors
    /// [`TargetError`] for a host or a resource that cannot go in the
    /// request as written.
    pub fn new(host: &str, resource: &str) -> Result<Self, TargetError> {
        let printable = |text: &str| text.bytes().all(|byte| byte.is_ascii_graphic());
        if host.is_empty() || !printable(host) || host.contains('/') {
            return Err(TargetError::Host);
        }
        if !resource.starts_with('/') || !printable(resource) || resource.contains('#') {
            return Err(TargetError::Resource);
        }
        Ok(Self {
            host: host.to_owned(),
            resource: resource.to_owned(),
        })
    }

    /// The `Host`.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The resource.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    fn default_for(remote: SocketAddr) -> Self {
        Self {
            host: remote.to_string(),
            resource: DEFAULT_RESOURCE.to_owned(),
        }
    }
}

/// The opening handshake (§4.1).
fn request(target: &WebSocketTarget, key: &str) -> Vec<u8> {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: sip\r\n\r\n",
        target.resource, target.host
    )
    .into_bytes()
}

/// Check the server's answer to the handshake (§4.1, the list after "If the
/// server's response does not conform").
fn check_answer(head: &[u8], accept: &str) -> Result<(), String> {
    let text = core::str::from_utf8(head).map_err(|_| "an answer that is not text".to_owned())?;
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let mut words = status.split(' ');
    let version = words.next().unwrap_or_default();
    let code = words.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") || code != "101" {
        return Err(format!("the server answered \"{status}\", not 101"));
    }
    let mut fields: HashMap<String, Vec<&str>> = HashMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(format!("a header line with no colon: \"{line}\""));
        };
        fields
            .entry(name.trim().to_ascii_lowercase())
            .or_default()
            .push(value.trim());
    }
    let has_token = |name: &str, token: &str| {
        fields.get(name).is_some_and(|values| {
            values
                .iter()
                .flat_map(|value| value.split(','))
                .any(|item| item.trim().eq_ignore_ascii_case(token))
        })
    };
    if !has_token("upgrade", "websocket") {
        return Err("the answer's Upgrade is not websocket".to_owned());
    }
    if !has_token("connection", "upgrade") {
        return Err("the answer's Connection is not Upgrade".to_owned());
    }
    match fields.get("sec-websocket-accept").map(Vec::as_slice) {
        Some([given]) if *given == accept => {}
        Some(_) => return Err("the answer's Sec-WebSocket-Accept is not the key's".to_owned()),
        None => return Err("the answer has no Sec-WebSocket-Accept".to_owned()),
    }
    match fields.get("sec-websocket-protocol").map(Vec::as_slice) {
        Some([chosen]) if chosen.eq_ignore_ascii_case("sip") => {}
        // RFC 7118 §4.1: a server that did not pick "sip" is one this end
        // cannot speak SIP to
        _ => return Err("the server did not agree to the sip subprotocol".to_owned()),
    }
    if fields.contains_key("sec-websocket-extensions") {
        return Err("the server turned on an extension nobody offered".to_owned());
    }
    Ok(())
}

// -- one connection ----------------------------------------------------------

/// Bytes drawn for keys, masks and names: SHA-1 over a seed taken once from
/// the endpoint's own stream and a counter. Kept apart from that stream so
/// that the masks a connection draws, which depend on when the stack writes,
/// never move the branches and tags the endpoint draws after them.
#[derive(Debug)]
struct Draw {
    seed: Box<[u8]>,
    counter: u64,
}

impl Draw {
    fn block(&mut self) -> [u8; 20] {
        let mut hasher = Sha1::new();
        hasher.update(&self.seed);
        hasher.update(self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        let mut out = [0_u8; 20];
        out.copy_from_slice(hasher.finalize().as_slice());
        out
    }

    fn mask(&mut self) -> [u8; 4] {
        let block = self.block();
        let mut mask = [0_u8; 4];
        mask.copy_from_slice(block.get(..4).unwrap_or(&[0; 4]));
        mask
    }

    fn key(&mut self) -> String {
        let block = self.block();
        base64(block.get(..16).unwrap_or_default())
    }

    /// Twelve lower-case letters and digits under `.invalid`.
    fn name(&mut self) -> String {
        const SYMBOLS: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let block = self.block();
        let mut name: String = block
            .iter()
            .take(12)
            .map(|byte| {
                SYMBOLS
                    .get(usize::from(*byte) % SYMBOLS.len())
                    .map_or('x', |symbol| char::from(*symbol))
            })
            .collect();
        name.push_str(".invalid");
        name
    }
}

#[derive(Debug)]
enum State {
    /// The handshake is out; its answer is being read.
    Opening { accept: String, until: Instant },
    /// Frames go both ways.
    Open,
    /// This end sent a close and waits for the server's (§7.1.2); nothing
    /// more is sent.
    Closing { until: Instant },
}

/// One connection this module runs.
#[derive(Debug)]
struct Link {
    protocol: TransportProtocol,
    remote: SocketAddr,
    local: SocketAddr,
    name: String,
    state: State,
    head: Vec<u8>,
    reader: FrameReader,
    draw: Draw,
    /// SIP written before the handshake was answered, in order.
    held: Vec<Arc<[u8]>>,
    /// When the next ping is due, unless something is sent first.
    ping_at: Instant,
    /// When a ping already sent stops waiting for its pong.
    pong_by: Option<Instant>,
}

/// What a connection did with what it was given.
enum Happened {
    /// Bytes to write to the socket.
    Send(Vec<u8>),
    /// A SIP message.
    Message(Vec<u8>),
    /// The connection is over: failed, or closed by the far end.
    Over {
        why: String,
        kind: TransportErrorKind,
    },
}

impl Link {
    /// One frame on this connection, masked; sending it puts the next ping
    /// off, when the time is known.
    fn frame(&mut self, opcode: u8, payload: &[u8], now: Option<Instant>) -> Vec<u8> {
        if let Some(now) = now {
            self.ping_at = now + PING_EVERY;
        }
        let mask = self.draw.mask();
        client_frame(opcode, payload, mask)
    }

    fn read(&mut self, data: &[u8], now: Instant) -> Vec<Happened> {
        let mut out = Vec::new();
        let mut data = data;
        if let State::Opening { ref accept, .. } = self.state {
            self.head.extend_from_slice(data);
            let Some(end) = self.head.windows(4).position(|four| four == b"\r\n\r\n") else {
                if self.head.len() > MAX_HEAD_BYTES {
                    out.push(Happened::Over {
                        why: format!("a handshake answer longer than {MAX_HEAD_BYTES} bytes"),
                        kind: TransportErrorKind::Other,
                    });
                }
                return out;
            };
            let head = core::mem::take(&mut self.head);
            let (answer, rest) = head.split_at(end + 4);
            if let Err(why) = check_answer(answer, accept) {
                out.push(Happened::Over {
                    why: format!("the WebSocket handshake failed: {why}"),
                    kind: TransportErrorKind::Other,
                });
                return out;
            }
            self.state = State::Open;
            self.ping_at = now + PING_EVERY;
            for message in core::mem::take(&mut self.held) {
                let opcode = opcode_for(&message);
                out.push(Happened::Send(self.frame(opcode, &message, Some(now))));
            }
            self.reader.push(rest);
            data = &[];
        }
        self.reader.push(data);
        loop {
            match self.reader.next_frame() {
                Ok(Some(Frame::Text(message) | Frame::Binary(message))) => {
                    out.push(Happened::Message(message));
                }
                Ok(Some(Frame::Ping(payload))) => {
                    if !matches!(self.state, State::Closing { .. }) {
                        out.push(Happened::Send(self.frame(PONG, &payload, Some(now))));
                    }
                }
                Ok(Some(Frame::Pong(_))) => self.pong_by = None,
                Ok(Some(Frame::Close { .. })) if matches!(self.state, State::Closing { .. }) => {
                    // the answer to this end's own close (§7.1.2): done
                    out.push(Happened::Over {
                        why: "closed by this end".to_owned(),
                        kind: TransportErrorKind::Closed,
                    });
                    return out;
                }
                Ok(Some(Frame::Close { code, reason })) => {
                    // §5.5.1: answer with a close, echoing the code
                    let echo = code.map(u16::to_be_bytes).unwrap_or_default();
                    let body = if code.is_some() { &echo[..] } else { &[][..] };
                    out.push(Happened::Send(self.frame(CLOSE, body, Some(now))));
                    out.push(Happened::Over {
                        why: format!(
                            "the server closed the WebSocket ({}{})",
                            code.map_or_else(|| "no code".to_owned(), |code| code.to_string()),
                            if reason.is_empty() {
                                String::new()
                            } else {
                                format!(": {}", String::from_utf8_lossy(&reason))
                            }
                        ),
                        kind: TransportErrorKind::Closed,
                    });
                    return out;
                }
                Ok(None) => return out,
                Err(error) => {
                    let code = error.close_code().to_be_bytes();
                    out.push(Happened::Send(self.frame(CLOSE, &code, Some(now))));
                    out.push(Happened::Over {
                        why: format!("the server broke the WebSocket protocol: {error}"),
                        kind: TransportErrorKind::Other,
                    });
                    return out;
                }
            }
        }
    }

    fn deadline(&self) -> Instant {
        match self.state {
            State::Opening { until, .. } | State::Closing { until } => until,
            State::Open => self.pong_by.map_or(self.ping_at, |by| by.min(self.ping_at)),
        }
    }
}

// -- the user agent's side ---------------------------------------------------

/// Every connection this module runs, and what it keeps between them.
#[derive(Debug, Default)]
pub(crate) struct WebSockets {
    links: BTreeMap<TransportId, Link>,
    targets: HashMap<SocketAddr, WebSocketTarget>,
    names: HashMap<SocketAddr, String>,
    out: VecDeque<Transmit>,
    failures: HashMap<TransportId, (TransportErrorKind, String)>,
    /// The latest moment this agent was told of. A frame written from
    /// [`UserAgent::poll_transmit`], which is given no time, puts the next
    /// ping off from here: nothing in this crate reads a clock.
    clock: Option<Instant>,
}

impl WebSockets {
    /// The name a transport advertises, when it is one of these.
    pub(crate) fn name_of(&self, transport: TransportId) -> Option<&str> {
        self.links.get(&transport).map(|link| link.name.as_str())
    }

    /// The earliest moment any connection needs attention.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.links.values().map(Link::deadline).min()
    }

    fn send(
        &mut self,
        transport: TransportId,
        link_remote: SocketAddr,
        protocol: TransportProtocol,
        bytes: Vec<u8>,
    ) {
        self.out.push_back(Transmit {
            transport,
            destination: link_remote,
            source: None,
            payload: Arc::from(bytes),
            protocol,
        });
    }
}

impl UserAgent {
    /// Where WebSocket connections to `remote` ask to go: the `Host` they
    /// name and the resource they ask for. Read when a connection to that
    /// far end is bound, so set it before; until it is set, the `Host` is
    /// the address and the resource is [`DEFAULT_RESOURCE`].
    pub fn set_websocket_target(&mut self, remote: SocketAddr, target: WebSocketTarget) {
        self.websockets.targets.insert(remote, target);
    }

    /// Why the WebSocket on `transport` was last given up on — a handshake
    /// the server refused, a frame that broke the protocol, a close, a pong
    /// that never came — and how to file it: [`TransportErrorKind::Closed`]
    /// for a close from the server, [`TransportErrorKind::TimedOut`] for a
    /// handshake or a pong that never came, [`TransportErrorKind::Other`]
    /// for the rest. `None` when nothing has gone wrong on it since it was
    /// last bound.
    #[must_use]
    pub fn websocket_failure(&self, transport: TransportId) -> Option<(TransportErrorKind, &str)> {
        self.websockets
            .failures
            .get(&transport)
            .map(|(kind, why)| (*kind, why.as_str()))
    }

    /// Whether `transport` is a WebSocket this agent runs: bound as `Ws` or
    /// `Wss` with its far end named.
    #[must_use]
    pub fn runs_websocket(&self, transport: TransportId) -> bool {
        self.websockets.links.contains_key(&transport)
    }

    /// The input, if it is this module's to take; `None` sends it on as it
    /// was.
    pub(crate) fn websocket_input(
        &mut self,
        input: Input<'_>,
        now: Instant,
    ) -> Option<Result<(), ReceiveError>> {
        self.websockets.clock = Some(now);
        match input {
            Input::TransportBound {
                transport,
                protocol,
                local,
                remote,
            } => {
                self.websockets.links.remove(&transport);
                let remote = remote.filter(|_| {
                    matches!(protocol, TransportProtocol::Ws | TransportProtocol::Wss)
                })?;
                self.open_websocket(transport, protocol, local, remote, now);
                None
            }
            Input::StreamData { transport, data } if self.runs_websocket(transport) => {
                Some(self.read_websocket(transport, data, now))
            }
            Input::StreamClosed { transport } | Input::TransportFailed { transport, .. } => {
                self.websockets.links.remove(&transport);
                None
            }
            _ => None,
        }
    }

    fn open_websocket(
        &mut self,
        transport: TransportId,
        protocol: TransportProtocol,
        local: SocketAddr,
        remote: SocketAddr,
        now: Instant,
    ) {
        let mut draw = Draw {
            seed: self.endpoint.token(),
            counter: 0,
        };
        let name = self
            .websockets
            .names
            .entry(remote)
            .or_insert_with(|| draw.name())
            .clone();
        let target = self
            .websockets
            .targets
            .get(&remote)
            .cloned()
            .unwrap_or_else(|| WebSocketTarget::default_for(remote));
        let key = draw.key();
        let handshake = request(&target, &key);
        self.websockets.failures.remove(&transport);
        self.websockets.links.insert(
            transport,
            Link {
                protocol,
                remote,
                local,
                name: name.clone(),
                state: State::Opening {
                    accept: accept_for(&key),
                    until: now + OPENING_WAIT,
                },
                head: Vec::new(),
                reader: FrameReader::new(),
                draw,
                held: Vec::new(),
                ping_at: now + PING_EVERY,
                pong_by: None,
            },
        );
        self.websockets.send(transport, remote, protocol, handshake);
        self.name_contacts(transport, protocol, local, remote, &name);
    }

    /// Point the `Contact` of every account that goes out on this
    /// connection, and that names the address the connection is bound at,
    /// at the connection's `.invalid` name instead (RFC 7118 Appendix B.1).
    /// A `Contact` the application wrote with a name of its own is its
    /// choice and stays as written.
    fn name_contacts(
        &mut self,
        transport: TransportId,
        protocol: TransportProtocol,
        local: SocketAddr,
        remote: SocketAddr,
        name: &str,
    ) {
        for config in self.accounts.values_mut() {
            let on_it = config.transport == transport
                || (config.own_stream == Some(protocol) && config.remote == remote);
            if !on_it || !crate::contact::contact_names(&config.contact, local) {
                continue;
            }
            if let Some(contact) = crate::contact::contact_on_name(&config.contact, name, protocol)
            {
                config.contact = contact;
            }
        }
    }

    fn read_websocket(
        &mut self,
        transport: TransportId,
        data: &[u8],
        now: Instant,
    ) -> Result<(), ReceiveError> {
        let Some(link) = self.websockets.links.get_mut(&transport) else {
            return Err(ReceiveError::UnknownTransport);
        };
        let (remote, local, protocol) = (link.remote, link.local, link.protocol);
        let happened = link.read(data, now);
        let mut outcome = Ok(());
        for happening in happened {
            match happening {
                Happened::Send(bytes) => self.websockets.send(transport, remote, protocol, bytes),
                Happened::Message(message) => {
                    let taken = self.take(
                        Input::Datagram {
                            transport,
                            remote,
                            local,
                            data: &message,
                        },
                        now,
                    );
                    if taken.is_err() {
                        outcome = taken;
                    }
                }
                Happened::Over { why, kind } => {
                    self.websocket_over(transport, why, kind, now);
                }
            }
        }
        outcome
    }

    /// The connection is over: retired the way a TCP or TLS one is, and the
    /// application told to close its socket.
    fn websocket_over(
        &mut self,
        transport: TransportId,
        why: String,
        kind: TransportErrorKind,
        now: Instant,
    ) {
        self.websockets.links.remove(&transport);
        self.websockets.failures.insert(transport, (kind, why));
        let input = if kind == TransportErrorKind::Closed {
            Input::StreamClosed { transport }
        } else {
            Input::TransportFailed {
                transport,
                error: kind,
            }
        };
        let _ = self.take(input, now);
        self.events
            .push_back(UaEvent::Unclaimed(Event::FlowFailed { transport }));
    }

    /// What goes out on a connection this module runs, framed; `None` when
    /// it waits for the handshake. Anything else passes through as it was.
    pub(crate) fn websocket_frame(&mut self, transmit: Transmit) -> Option<Transmit> {
        let now = self.websockets.clock;
        let Some(link) = self.websockets.links.get_mut(&transmit.transport) else {
            return Some(transmit);
        };
        match link.state {
            State::Opening { .. } => {
                link.held.push(transmit.payload);
                return None;
            }
            // §5.5.1: nothing goes after a close; what the endpoint still
            // wrote finds out by its own timers, as on a closed TCP stream
            State::Closing { .. } => return None,
            State::Open => {}
        }
        let opcode = opcode_for(&transmit.payload);
        let framed = link.frame(opcode, &transmit.payload, now);
        Some(Transmit {
            payload: Arc::from(framed),
            ..transmit
        })
    }

    /// The next thing a connection wants written on its own account: the
    /// handshake, a pong, a ping, a close.
    pub(crate) fn poll_websocket(&mut self) -> Option<Transmit> {
        self.websockets.out.pop_front()
    }

    /// Handshakes that went unanswered, pings that are due, and pongs that
    /// never came.
    pub(crate) fn fire_websockets(&mut self, now: Instant) {
        self.websockets.clock = Some(now);
        let due: Vec<TransportId> = self
            .websockets
            .links
            .iter()
            .filter(|(_, link)| link.deadline() <= now)
            .map(|(transport, _)| *transport)
            .collect();
        for transport in due {
            let Some(link) = self.websockets.links.get_mut(&transport) else {
                continue;
            };
            let (remote, protocol) = (link.remote, link.protocol);
            match link.state {
                State::Opening { .. } => {
                    let why = format!(
                        "the WebSocket handshake was not answered within {} s",
                        OPENING_WAIT.as_secs()
                    );
                    self.websocket_over(transport, why, TransportErrorKind::TimedOut, now);
                }
                State::Open if link.pong_by.is_some_and(|by| by <= now) => {
                    let why = format!(
                        "no pong within {} s of a ping (RFC 6455 section 5.5.2)",
                        PONG_WAIT.as_secs()
                    );
                    self.websocket_over(transport, why, TransportErrorKind::TimedOut, now);
                }
                State::Open => {
                    let ping = link.frame(PING, &[], Some(now));
                    if link.pong_by.is_none() {
                        link.pong_by = Some(now + PONG_WAIT);
                    }
                    self.websockets.send(transport, remote, protocol, ping);
                }
                State::Closing { .. } => {
                    let why = "closed by this end; the server never answered the close".to_owned();
                    self.websocket_over(transport, why, TransportErrorKind::Closed, now);
                }
            }
        }
    }

    /// Close the WebSocket on `transport` the way RFC 6455 §7.1.2 does: a
    /// close frame with status 1000 is the next thing to write, nothing is
    /// sent after it, and once the server's own close comes back — or
    /// [`PONG_WAIT`] has gone by without one — the transport is retired and
    /// [`Event::FlowFailed`] says the socket can be closed. `false` for a
    /// transport that is not a WebSocket this agent runs, or one already
    /// closing.
    pub fn close_websocket(&mut self, transport: TransportId, now: Instant) -> bool {
        self.websockets.clock = Some(now);
        let Some(link) = self.websockets.links.get_mut(&transport) else {
            return false;
        };
        if matches!(link.state, State::Closing { .. }) {
            return false;
        }
        let frame = link.frame(CLOSE, &1000_u16.to_be_bytes(), Some(now));
        link.state = State::Closing {
            until: now + PONG_WAIT,
        };
        link.held.clear();
        let (remote, protocol) = (link.remote, link.protocol);
        self.websockets.send(transport, remote, protocol, frame);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_accept_value_is_the_one_rfc_6455_works_through() {
        // §1.3's own example
        assert_eq!(
            accept_for("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn base64_pads_each_remainder() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    /// A frame as a server writes it: unmasked.
    fn server_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![u8::from(fin) << 7 | opcode];
        match payload.len() {
            short @ 0..=125 => out.push(u8::try_from(short).unwrap()),
            medium @ 126..=0xFFFF => {
                out.push(126);
                out.extend_from_slice(&u16::try_from(medium).unwrap().to_be_bytes());
            }
            long => {
                out.push(127);
                out.extend_from_slice(&(long as u64).to_be_bytes());
            }
        }
        out.extend_from_slice(payload);
        out
    }

    fn read_all(bytes: &[u8], chunk: usize) -> Result<Vec<Frame>, FrameError> {
        let mut reader = FrameReader::new();
        let mut frames = Vec::new();
        for piece in bytes.chunks(chunk.max(1)) {
            reader.push(piece);
            while let Some(frame) = reader.next_frame()? {
                frames.push(frame);
            }
        }
        Ok(frames)
    }

    #[test]
    fn frames_come_out_whole_however_the_reads_fall() {
        let mut stream = server_frame(true, TEXT, b"OPTIONS sip:a SIP/2.0\r\n\r\n");
        stream.extend(server_frame(true, BINARY, &[0xFF, 0x00]));
        stream.extend(server_frame(true, TEXT, &vec![b'x'; 300]));
        stream.extend(server_frame(true, TEXT, &vec![b'y'; 70_000]));
        for chunk in [1, 2, 3, 7, 1000, 100_000] {
            let frames = read_all(&stream, chunk).unwrap();
            assert_eq!(frames.len(), 4, "read {chunk} at a time");
            assert_eq!(
                frames[0],
                Frame::Text(b"OPTIONS sip:a SIP/2.0\r\n\r\n".to_vec())
            );
            assert_eq!(frames[1], Frame::Binary(vec![0xFF, 0x00]));
            assert_eq!(frames[3], Frame::Text(vec![b'y'; 70_000]));
        }
    }

    #[test]
    fn fragments_are_put_back_together_around_a_ping() {
        let mut stream = server_frame(false, TEXT, b"INVITE ");
        stream.extend(server_frame(true, PING, b"are you there"));
        stream.extend(server_frame(false, CONTINUATION, b"sip:b "));
        stream.extend(server_frame(true, CONTINUATION, b"SIP/2.0"));
        let frames = read_all(&stream, 1).unwrap();
        assert_eq!(
            frames,
            [
                Frame::Ping(b"are you there".to_vec()),
                Frame::Text(b"INVITE sip:b SIP/2.0".to_vec()),
            ]
        );
    }

    #[test]
    fn what_breaks_the_protocol_is_named_with_its_close_code() {
        let cases: [(Vec<u8>, FrameError, u16); 9] = [
            (vec![0x81 | 0x40, 0], FrameError::Reserved, 1002),
            (vec![0x83, 0], FrameError::UnknownOpcode(3), 1002),
            (vec![0x81, 0x80, 1, 2, 3, 4], FrameError::Masked, 1002),
            (server_frame(false, PING, b""), FrameError::BadControl, 1002),
            (
                server_frame(true, CONTINUATION, b"x"),
                FrameError::BadFragment,
                1002,
            ),
            (vec![0x81, 126, 0, 5], FrameError::BadLength, 1002),
            (
                server_frame(true, TEXT, &[0xC3, 0x28]),
                FrameError::NotUtf8,
                1007,
            ),
            (server_frame(true, CLOSE, &[3]), FrameError::BadClose, 1002),
            (
                server_frame(true, BINARY, &vec![0; MAX_MESSAGE_BYTES + 1]),
                FrameError::TooLarge,
                1009,
            ),
        ];
        for (bytes, error, code) in cases {
            assert_eq!(read_all(&bytes, 4096), Err(error), "{bytes:02x?}");
            assert_eq!(error.close_code(), code);
        }
        // and a fragmented message cannot have another started inside it
        let mut two = server_frame(false, TEXT, b"a");
        two.extend(server_frame(true, TEXT, b"b"));
        assert_eq!(read_all(&two, 1), Err(FrameError::BadFragment));
    }

    #[test]
    fn a_reader_that_broke_stays_broken() {
        let mut reader = FrameReader::new();
        reader.push(&[0x83, 0]);
        assert!(reader.next_frame().is_err());
        reader.push(&server_frame(true, TEXT, b"fine"));
        assert_eq!(reader.next_frame(), Err(FrameError::UnknownOpcode(3)));
        assert_eq!(reader.pending(), 0);
    }

    #[test]
    fn a_close_carries_its_code_and_reason() {
        let mut body = 1001_u16.to_be_bytes().to_vec();
        body.extend_from_slice(b"going away");
        assert_eq!(
            read_all(&server_frame(true, CLOSE, &body), 3).unwrap(),
            [Frame::Close {
                code: Some(1001),
                reason: b"going away".to_vec()
            }]
        );
        assert_eq!(
            read_all(&server_frame(true, CLOSE, &1005_u16.to_be_bytes()), 3),
            Err(FrameError::BadClose)
        );
    }

    #[test]
    fn a_client_frame_is_masked_and_unmasks_to_what_was_sent() {
        let payload = vec![b'z'; 200];
        let mask = [0x37, 0xFA, 0x21, 0x3D];
        let frame = client_frame(TEXT, &payload, mask);
        assert_eq!(frame[0], 0x81);
        assert_eq!(frame[1], 0x80 | 0x7E);
        assert_eq!(&frame[2..4], &200_u16.to_be_bytes());
        assert_eq!(&frame[4..8], &mask);
        let unmasked: Vec<u8> = frame[8..]
            .iter()
            .zip(mask.iter().cycle())
            .map(|(byte, key)| byte ^ key)
            .collect();
        assert_eq!(unmasked, payload);
        // §5.7's own single-frame masked text example, "Hello"
        assert_eq!(
            client_frame(TEXT, b"Hello", mask),
            [
                0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58
            ]
        );
    }

    fn answer(accept: &str) -> String {
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: sip\r\n\r\n"
        )
    }

    #[test]
    fn the_handshake_answer_is_checked_point_by_point() {
        let accept = accept_for("dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(check_answer(answer(&accept).as_bytes(), &accept), Ok(()));
        let refused = [
            answer(&accept).replace("101 Switching Protocols", "404 Not Found"),
            answer(&accept).replace("Upgrade: websocket", "Upgrade: h2c"),
            answer(&accept).replace("Connection: Upgrade", "Connection: close"),
            answer("AAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            answer(&accept).replace("Sec-WebSocket-Protocol: sip\r\n", ""),
            answer(&accept).replace("Protocol: sip", "Protocol: xmpp"),
            answer(&accept).replace(
                "\r\n\r\n",
                "\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
            ),
        ];
        for text in refused {
            assert!(check_answer(text.as_bytes(), &accept).is_err(), "{text}");
        }
    }

    #[test]
    fn the_request_asks_for_sip_on_the_resource() {
        let target = WebSocketTarget::new("pbx.example.com:8088", "/ws").unwrap();
        let text = String::from_utf8(request(&target, "a2V5")).unwrap();
        assert!(text.starts_with("GET /ws HTTP/1.1\r\nHost: pbx.example.com:8088\r\n"));
        for line in [
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Key: a2V5\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "Sec-WebSocket-Protocol: sip\r\n\r\n",
        ] {
            assert!(text.contains(line), "{line}");
        }
        assert_eq!(WebSocketTarget::new("a b", "/"), Err(TargetError::Host));
        assert_eq!(WebSocketTarget::new("a", "ws"), Err(TargetError::Resource));
        assert_eq!(
            WebSocketTarget::new("a", "/x#y"),
            Err(TargetError::Resource)
        );
    }

    #[test]
    fn a_drawn_name_is_a_host_under_invalid() {
        let mut draw = Draw {
            seed: Box::from(&b"seed"[..]),
            counter: 0,
        };
        let name = draw.name();
        assert!(name.ends_with(".invalid"));
        assert_eq!(name.len(), 12 + ".invalid".len());
        assert!(
            name.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.')
        );
        assert_ne!(draw.mask(), draw.mask(), "each frame its own mask");
        assert_eq!(draw.key().len(), 24, "sixteen bytes in base64");
    }
}
