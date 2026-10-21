// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! One HTTP/2 request on a connection of its own (RFC 9113), over TLS with
//! ALPN `h2` (RFC 7301).
//!
//! APNs speaks nothing older (Apple's "Sending notification requests to
//! APNs"), and Google's endpoints speak it too, so one client serves the
//! three requests this crate makes. It is as small as a single stream
//! allows: the preface and a SETTINGS frame, a HEADERS frame and the body in
//! DATA frames, then frames read until the stream ends -- SETTINGS and PING
//! acknowledged, WINDOW_UPDATE and PRIORITY ignored, RST_STREAM and GOAWAY
//! reported. No connection is kept: Apple recommends keeping one open, and a
//! provider sending at volume should, but the lab sends a handful.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crate::hpack;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PUSH_PROMISE: u8 = 0x5;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const CONTINUATION: u8 = 0x9;

const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY_FLAG: u8 = 0x20;

/// SETTINGS_ENABLE_PUSH (§6.5.2): this client takes no pushed streams.
const ENABLE_PUSH: u16 = 0x2;

/// The largest frame this client reads: the default it never raises.
const MAX_FRAME: usize = 16_384;

/// The stream the request goes on: the first a client opens.
const STREAM: u32 = 1;

/// A POST.
#[derive(Clone, Debug)]
pub(crate) struct Request {
    /// `:authority`.
    pub(crate) authority: String,
    /// `:path`.
    pub(crate) path: String,
    /// The other fields, names in lower case.
    pub(crate) headers: Vec<(String, String)>,
    /// The body.
    pub(crate) body: Vec<u8>,
}

/// What came back.
#[derive(Clone, Debug)]
pub(crate) struct Response {
    /// `:status`.
    pub(crate) status: u16,
    /// The other fields.
    pub(crate) headers: Vec<(String, String)>,
    /// The body.
    pub(crate) body: Vec<u8>,
}

impl Response {
    /// A field's value.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(9 + payload.len());
    out.extend_from_slice(&length.to_be_bytes()[1..]);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&(stream & 0x7FFF_FFFF).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Everything the client writes before it reads: the preface, its
/// SETTINGS, the request's HEADERS and its DATA.
pub(crate) fn request_bytes(request: &Request) -> Vec<u8> {
    let mut out = PREFACE.to_vec();
    let mut settings = Vec::new();
    settings.extend_from_slice(&ENABLE_PUSH.to_be_bytes());
    settings.extend_from_slice(&0u32.to_be_bytes());
    out.extend(frame(SETTINGS, 0, 0, &settings));

    let length = request.body.len().to_string();
    let mut fields: Vec<(&str, &str)> = vec![
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", &request.authority),
        (":path", &request.path),
    ];
    for (name, value) in &request.headers {
        fields.push((name, value));
    }
    fields.push(("content-length", &length));
    let block = hpack::encode(&fields);
    let mut chunks = block.chunks(MAX_FRAME).peekable();
    let mut first = true;
    let body_flag = if request.body.is_empty() {
        END_STREAM
    } else {
        0
    };
    while let Some(chunk) = chunks.next() {
        let last = chunks.peek().is_none();
        let flags = if last { END_HEADERS } else { 0 };
        if first {
            out.extend(frame(HEADERS, flags | body_flag, STREAM, chunk));
            first = false;
        } else {
            out.extend(frame(CONTINUATION, flags, STREAM, chunk));
        }
    }
    let mut parts = request.body.chunks(MAX_FRAME).peekable();
    while let Some(part) = parts.next() {
        let flags = if parts.peek().is_none() {
            END_STREAM
        } else {
            0
        };
        out.extend(frame(DATA, flags, STREAM, part));
    }
    out
}

/// The first four bytes as a big-endian number, zero when there are fewer.
fn word(payload: &[u8]) -> u32 {
    payload
        .get(..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map_or(0, u32::from_be_bytes)
}

/// A frame's payload with its padding, and a HEADERS frame's priority
/// fields, taken off (§6.1, §6.2).
fn unpadded(flags: u8, kind: u8, payload: &[u8]) -> Result<&[u8], String> {
    let mut body = payload;
    let mut pad = 0usize;
    if flags & PADDED != 0 {
        let (&length, rest) = body.split_first().ok_or("a padded frame with no length")?;
        pad = usize::from(length);
        body = rest;
    }
    if kind == HEADERS && flags & PRIORITY_FLAG != 0 {
        body = body
            .get(5..)
            .ok_or("a HEADERS frame too short for its priority")?;
    }
    let keep = body
        .len()
        .checked_sub(pad)
        .ok_or("padding longer than the frame")?;
    body.get(..keep).ok_or_else(|| "padding".to_owned())
}

/// Write the request on `stream` and read until its stream ends.
pub(crate) fn exchange<S: Read + Write>(
    stream: &mut S,
    request: &Request,
) -> Result<Response, String> {
    stream
        .write_all(&request_bytes(request))
        .map_err(|error| format!("writing the request: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("writing: {error}"))?;
    let mut decoder = hpack::Decoder::new(4096);
    let mut block = Vec::new();
    let mut fields: Option<Vec<(String, String)>> = None;
    let mut body = Vec::new();
    loop {
        let mut head = [0u8; 9];
        stream
            .read_exact(&mut head)
            .map_err(|error| format!("reading a frame: {error}"))?;
        let length = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
        let kind = head[3];
        let flags = head[4];
        let id = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7FFF_FFFF;
        if length > MAX_FRAME {
            return Err(format!(
                "a frame of {length} bytes, past the {MAX_FRAME} allowed"
            ));
        }
        let mut payload = vec![0u8; length];
        stream
            .read_exact(&mut payload)
            .map_err(|error| format!("reading a frame: {error}"))?;
        match kind {
            SETTINGS if flags & ACK == 0 => {
                stream
                    .write_all(&frame(SETTINGS, ACK, 0, &[]))
                    .map_err(|error| format!("acknowledging SETTINGS: {error}"))?;
            }
            PING if flags & ACK == 0 => {
                stream
                    .write_all(&frame(PING, ACK, 0, &payload))
                    .map_err(|error| format!("answering PING: {error}"))?;
            }
            GOAWAY => {
                let last = word(&payload) & 0x7FFF_FFFF;
                if last < STREAM {
                    let debug = String::from_utf8_lossy(payload.get(8..).unwrap_or_default());
                    return Err(format!("the server went away before the request: {debug}"));
                }
            }
            RST_STREAM if id == STREAM => {
                let code = word(&payload);
                return Err(format!("the server reset the request (error {code})"));
            }
            PUSH_PROMISE => return Err("a pushed stream, which this client refused".to_owned()),
            HEADERS | CONTINUATION if id == STREAM => {
                block.extend_from_slice(unpadded(flags, kind, &payload)?);
                if flags & END_HEADERS != 0 {
                    let block_fields = decoder
                        .decode(&block)
                        .map_err(|_| "a header block that does not decode".to_owned())?;
                    block.clear();
                    // a 1xx is followed by the real response's own block
                    let informational = block_fields
                        .iter()
                        .any(|(name, value)| name == ":status" && value.starts_with('1'));
                    if !informational {
                        fields = Some(block_fields);
                    }
                }
                if flags & END_STREAM != 0 {
                    break;
                }
            }
            DATA if id == STREAM => {
                body.extend_from_slice(unpadded(flags, kind, &payload)?);
                if flags & END_STREAM != 0 {
                    break;
                }
            }
            _ => {}
        }
    }
    let fields = fields.ok_or("the stream ended without a response")?;
    let status = fields
        .iter()
        .find(|(name, _)| name == ":status")
        .and_then(|(_, value)| value.parse().ok())
        .ok_or("a response with no :status")?;
    Ok(Response {
        status,
        headers: fields
            .into_iter()
            .filter(|(name, _)| !name.starts_with(':'))
            .collect(),
        body,
    })
}

/// The TLS side: the platform's trust store, ALPN `h2` and nothing else.
pub(crate) struct Tls {
    config: Arc<rustls::ClientConfig>,
}

impl Tls {
    /// Read the platform's trust store. An empty one is an error: nothing
    /// could be verified.
    pub(crate) fn new() -> Result<Self, String> {
        let mut roots = rustls::RootCertStore::empty();
        let found = rustls_native_certs::load_native_certs();
        for certificate in found.certs {
            let _ = roots.add(certificate);
        }
        if roots.is_empty() {
            return Err("the platform trust store is empty (install ca-certificates)".to_owned());
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| format!("TLS versions: {error}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Self {
            config: Arc::new(config),
        })
    }

    /// One request to `host:port` over a connection of its own.
    pub(crate) fn send(
        &self,
        host: &str,
        port: u16,
        request: &Request,
    ) -> Result<Response, String> {
        let address = (host, port)
            .to_socket_addrs()
            .map_err(|error| format!("resolving {host}: {error}"))?
            .next()
            .ok_or_else(|| format!("{host} has no address"))?;
        let mut tcp = TcpStream::connect_timeout(&address, Duration::from_secs(10))
            .map_err(|error| format!("connecting to {host}:{port}: {error}"))?;
        tcp.set_read_timeout(Some(Duration::from_secs(15)))
            .and_then(|()| tcp.set_write_timeout(Some(Duration::from_secs(15))))
            .map_err(|error| format!("socket: {error}"))?;
        let name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|error| format!("{host}: {error}"))?;
        let mut connection = rustls::ClientConnection::new(Arc::clone(&self.config), name)
            .map_err(|error| format!("TLS: {error}"))?;
        while connection.is_handshaking() {
            connection
                .complete_io(&mut tcp)
                .map_err(|error| format!("TLS handshake with {host}: {error}"))?;
        }
        if connection.alpn_protocol() != Some(b"h2") {
            return Err(format!("{host} did not agree to HTTP/2"));
        }
        let mut stream = rustls::StreamOwned::new(connection, tcp);
        exchange(&mut stream, request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server that has already said everything: what it reads is kept.
    struct Scripted {
        answer: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.answer.read(buf)
        }
    }

    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn request() -> Request {
        Request {
            authority: "api.sandbox.push.apple.com".into(),
            path: "/3/device/00ff".into(),
            headers: vec![("apns-push-type".into(), "voip".into())],
            body: br#"{"kind":"call"}"#.to_vec(),
        }
    }

    /// Every frame in `bytes`, after the preface: type, flags, stream, payload.
    fn frames(mut bytes: &[u8]) -> Vec<(u8, u8, u32, Vec<u8>)> {
        let mut out = Vec::new();
        while bytes.len() >= 9 {
            let length =
                usize::from(bytes[0]) << 16 | usize::from(bytes[1]) << 8 | usize::from(bytes[2]);
            let id = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);
            out.push((bytes[3], bytes[4], id, bytes[9..9 + length].to_vec()));
            bytes = &bytes[9 + length..];
        }
        out
    }

    #[test]
    fn the_request_is_a_preface_settings_headers_and_data() {
        let bytes = request_bytes(&request());
        assert!(bytes.starts_with(PREFACE));
        let sent = frames(&bytes[PREFACE.len()..]);
        assert_eq!(sent.len(), 3);
        assert_eq!((sent[0].0, sent[0].1, sent[0].2), (SETTINGS, 0, 0));
        assert_eq!(sent[0].3, [0, 2, 0, 0, 0, 0]);
        assert_eq!((sent[1].0, sent[1].1, sent[1].2), (HEADERS, END_HEADERS, 1));
        let fields = hpack::Decoder::new(4096)
            .decode(&sent[1].3)
            .expect("decodes");
        let named: Vec<(&str, &str)> = fields
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            named,
            [
                (":method", "POST"),
                (":scheme", "https"),
                (":authority", "api.sandbox.push.apple.com"),
                (":path", "/3/device/00ff"),
                ("apns-push-type", "voip"),
                ("content-length", "15")
            ]
        );
        assert_eq!((sent[2].0, sent[2].1, sent[2].2), (DATA, END_STREAM, 1));
        assert_eq!(sent[2].3, br#"{"kind":"call"}"#);
    }

    #[test]
    fn a_response_is_read_through_settings_ping_and_padding() {
        let mut answer = Vec::new();
        answer.extend(frame(SETTINGS, 0, 0, &[0, 3, 0, 0, 0, 100]));
        answer.extend(frame(PING, 0, 0, b"12345678"));
        answer.extend(frame(0x8, 0, 0, &[0, 0, 0, 10]));
        // :status 400 indexed (static 12), apns-id as a literal, padded by two
        let mut block = vec![2, 0x8c];
        block.extend(hpack::encode(&[(
            "apns-id",
            "eabeae54-14a8-11e5-b60b-1697f925ec7b",
        )]));
        block.extend([0, 0]);
        answer.extend(frame(HEADERS, END_HEADERS | PADDED, 1, &block));
        answer.extend(frame(
            DATA,
            END_STREAM,
            1,
            br#"{"reason":"BadDeviceToken"}"#,
        ));
        let mut server = Scripted {
            answer: std::io::Cursor::new(answer),
            written: Vec::new(),
        };
        let response = exchange(&mut server, &request()).expect("a response");
        assert_eq!(response.status, 400);
        assert_eq!(
            response.header("apns-id"),
            Some("eabeae54-14a8-11e5-b60b-1697f925ec7b")
        );
        assert_eq!(response.body, br#"{"reason":"BadDeviceToken"}"#);
        let replies = frames(&server.written[request_bytes(&request()).len()..]);
        assert_eq!(replies[0].0, SETTINGS);
        assert_eq!(replies[0].1, ACK);
        assert_eq!((replies[1].0, replies[1].1), (PING, ACK));
        assert_eq!(replies[1].3, b"12345678");
    }

    #[test]
    fn going_away_before_the_request_is_an_error_with_its_reason() {
        let mut payload = vec![0, 0, 0, 0, 0, 0, 0, 0];
        payload.extend_from_slice(br#"{"reason":"BadCertificate"}"#);
        let mut server = Scripted {
            answer: std::io::Cursor::new(frame(GOAWAY, 0, 0, &payload)),
            written: Vec::new(),
        };
        let error = exchange(&mut server, &request()).expect_err("an error");
        assert!(error.contains("BadCertificate"), "{error}");
    }
}
