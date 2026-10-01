// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Taking the personal data out of one SIP message (RFC 3261) and the SDP
//! (RFC 4566) it may carry, before a diagnostics export leaves the
//! organisation.
//!
//! GDPR's usual list for SIP traffic: a URI's user part, a display name, a
//! phone number written as either, and every IP literal in a header or in
//! SDP. [`Redactor`] turns each into a pseudonym — a keyed HMAC-SHA256 by
//! default, so a call flow stays correlatable to whoever holds the key and
//! to nobody else, or, in [`Mode::Delete`], a placeholder that is stable only
//! for the run that produced it. Credentials are never pseudonymised: an
//! `Authorization`/`Proxy-Authorization` value and an SDES `inline:` key are
//! dropped outright, in both modes, because a hash of a password is still a
//! password a large enough dictionary reverses.
//!
//! What this rewrites, precisely: the display name and the URI user part of
//! `From`, `To`, every `Contact`, every `Record-Route`/`Route` entry,
//! `P-Asserted-Identity`, `P-Preferred-Identity`, `Remote-Party-ID`,
//! `Diversion`, and the Request-URI; a `tel:` URI's subscriber number the
//! same way; and, in every header and in the SDP body, every IPv4 or IPv6
//! literal, wherever it is written — a header's host, an SDP `c=` or `o=`
//! line, a `received=` parameter — each scanned once, out of the original
//! bytes it arrived in, so an already-pseudonymised address is never mistaken
//! for a second real one and hashed again. What it deliberately leaves alone:
//! `Call-ID` and every `tag` (the file has to keep correlating a dialog's own
//! messages to remain a call flow), and a domain name that is not a literal
//! address (nothing here resolves one to find out what it names).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use sipral_core::diag::Record;
use sipral_core::msg::{
    self, CommaList, HeaderName, HostRef, MessageKind, NameAddrRef, ParseError, ParseMode,
    ParseScratch, RouteRef, UriRef, UriScheme,
};

type HmacSha256 = Hmac<Sha256>;

/// Why a message could not be redacted: it is not one this build's parser can
/// read, so nothing here can promise every identifier in it was found.
#[derive(Debug)]
pub struct RedactError(ParseError);

impl core::fmt::Display for RedactError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "not a message the parser can read, so it was not redacted: {}",
            self.0
        )
    }
}

impl core::error::Error for RedactError {}

impl From<ParseError> for RedactError {
    fn from(error: ParseError) -> Self {
        Self(error)
    }
}

/// What a redacted identifier becomes.
#[derive(Clone)]
pub enum Mode {
    /// HMAC-SHA256 keyed with the organisation's own secret, truncated: the
    /// same input always becomes the same output under one key, so a call's
    /// messages stay correlatable to each other and to nothing else.
    Hash(Vec<u8>),
    /// No durable identifier at all. Every distinct value seen in one export
    /// gets the next placeholder in sequence — stable within that export, so
    /// the flow is still legible, and reproducing nothing across two of them.
    Delete,
}

// the organisation's HMAC key lives in `Hash`'s payload, so a derived `Debug`
// would print it in full the first time anything logs a `Mode` or an error
// context that carries one; `crates/sipral-core/src/sdp/crypto.rs`'s
// `KeySalt` redacts itself the same way, for the same reason
impl core::fmt::Debug for Mode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Mode::Hash(_) => f.write_str("Hash(<redacted>)"),
            Mode::Delete => f.write_str("Delete"),
        }
    }
}

/// Rewrites identifiers as a recording's messages are redacted, remembering
/// every value it has already replaced so the same input keeps the same
/// output within one export — required for [`Mode::Hash`] to correlate at
/// all, and for [`Mode::Delete`] to stay internally consistent.
#[derive(Debug)]
pub struct Redactor {
    mode: Mode,
    identifiers: HashMap<Vec<u8>, String>,
    ipv4: HashMap<Ipv4Addr, Ipv4Addr>,
    ipv6: HashMap<Ipv6Addr, Ipv6Addr>,
    next_identifier: u32,
    next_v4: u32,
    next_v6: u32,
}

impl Redactor {
    /// A redactor that pseudonymises under `mode` for the life of one export.
    #[must_use]
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            identifiers: HashMap::new(),
            ipv4: HashMap::new(),
            ipv6: HashMap::new(),
            next_identifier: 0,
            next_v4: 0,
            next_v6: 0,
        }
    }

    /// A user part, a display name or a phone number, pseudonymised.
    pub(crate) fn identifier(&mut self, value: &[u8]) -> String {
        if let Some(existing) = self.identifiers.get(value) {
            return existing.clone();
        }
        let token = if let Mode::Hash(key) = &self.mode {
            let key = key.clone();
            hex(&hmac(&key, value)[..8])
        } else {
            self.next_identifier += 1;
            format!("anon{}", self.next_identifier)
        };
        self.identifiers.insert(value.to_vec(), token.clone());
        token
    }

    /// An IPv4 literal, pseudonymised into another IPv4 literal so the
    /// message it came from still parses as one.
    pub(crate) fn ipv4(&mut self, addr: Ipv4Addr) -> Ipv4Addr {
        if let Some(existing) = self.ipv4.get(&addr) {
            return *existing;
        }
        let mapped = if let Mode::Hash(key) = &self.mode {
            let key = key.clone();
            let mac = hmac(&key, &addr.octets());
            Ipv4Addr::new(mac[0], mac[1], mac[2], mac[3])
        } else {
            self.next_v4 += 1;
            placeholder_ipv4(self.next_v4)
        };
        self.ipv4.insert(addr, mapped);
        mapped
    }

    /// An IPv6 literal, pseudonymised the same way.
    pub(crate) fn ipv6(&mut self, addr: Ipv6Addr) -> Ipv6Addr {
        if let Some(existing) = self.ipv6.get(&addr) {
            return *existing;
        }
        let mapped = if let Mode::Hash(key) = &self.mode {
            let key = key.clone();
            let mac = hmac(&key, &addr.octets());
            let mut segments = [0u8; 16];
            segments.copy_from_slice(&mac[..16]);
            Ipv6Addr::from(segments)
        } else {
            self.next_v6 += 1;
            Ipv6Addr::new(
                0x2001,
                0x0db8,
                0,
                0,
                0,
                0,
                0,
                u16::try_from(self.next_v6).unwrap_or(u16::MAX),
            )
        };
        self.ipv6.insert(addr, mapped);
        mapped
    }
}

/// RFC 5737's three documentation ranges, cycled through by a per-run
/// counter: valid, routable-looking IPv4 addresses that are guaranteed to
/// name nothing real, which is what a placeholder for a deleted address has
/// to be.
fn placeholder_ipv4(n: u32) -> Ipv4Addr {
    const BLOCKS: [(u8, u8, u8); 3] = [(192, 0, 2), (198, 51, 100), (203, 0, 113)];
    let index = ((n - 1) / 256) as usize % BLOCKS.len();
    let (b0, b1, b2) = BLOCKS.get(index).copied().unwrap_or((192, 0, 2));
    let host = u8::try_from((n - 1) % 256).unwrap_or(0);
    Ipv4Addr::new(b0, b1, b2, host)
}

/// HMAC-SHA256(`key`, `data`). RFC 2104 §2 replaces a key longer than the
/// 64-octet block with its own hash and pads every key with zeros to the
/// block; doing both here by hand hands the primitive a block-sized key, the
/// one form of keying it offers that cannot fail on a key of arbitrary
/// length (`crates/sipral-dtls/src/prf.rs` keys HMAC the same way).
fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block_key = hmac::digest::Key::<HmacSha256>::default();
    let hashed: [u8; 32];
    let material: &[u8] = if key.len() > block_key.len() {
        hashed = Sha256::digest(key).into();
        &hashed
    } else {
        key
    };
    for (slot, byte) in block_key.iter_mut().zip(material) {
        *slot = *byte;
    }
    let mut mac = <HmacSha256 as KeyInit>::new(&block_key);
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Redact one SIP message: RFC 3261 identifiers structurally, then every IP
/// literal the body and the headers still carry — an SDP `c=`/`o=` line reads
/// the same way as any other IP literal, so it needs no separate parser.
///
/// # Errors
/// [`RedactError`] when `bytes` does not parse as a SIP message.
pub fn redact_message(bytes: &[u8], red: &mut Redactor) -> Result<Vec<u8>, RedactError> {
    let mut scratch = ParseScratch::new();
    let message = msg::parse(bytes, &mut scratch, ParseMode::Lenient)?;

    // the body is redacted, and its IP literals scanned, before anything
    // downstream reads its length: Content-Length has to match the body
    // this function is about to emit, not the one the message arrived with
    let new_body = scan_ip_literals(&redact_body(message.body(), red), red);

    let start_line = match message.kind() {
        MessageKind::Request(method) => {
            let uri_bytes = message.request_uri_bytes().unwrap_or(b"");
            let uri_text = match UriRef::parse(uri_bytes) {
                Ok(uri) => redact_uri(uri, red),
                Err(_) => String::from_utf8_lossy(uri_bytes).into_owned(),
            };
            format!("{method} {uri_text} SIP/2.0")
        }
        MessageKind::Response(status) => {
            let reason = String::from_utf8_lossy(message.reason().unwrap_or(b""));
            format!("SIP/2.0 {status} {reason}")
        }
    };

    let mut text = String::with_capacity(bytes.len());
    text.push_str(&start_line);
    text.push_str("\r\n");
    for slot in message.header_slots() {
        let name_bytes = slot.name.slice(bytes);
        let value_bytes = slot.value.slice(bytes);
        let Some(name) = HeaderName::from_bytes(name_bytes) else {
            continue; // never hit: the parser only ever locates a token name
        };
        text.push_str(&String::from_utf8_lossy(name_bytes));
        text.push_str(": ");
        text.push_str(&redact_header_value(name, value_bytes, new_body.len(), red));
        text.push_str("\r\n");
    }
    text.push_str("\r\n");

    // every header value above is already fully redacted — structurally, or
    // by its own IP-literal scan against the bytes it arrived with — so
    // nothing here needs a second pass over the assembled text
    let mut out = text.into_bytes();
    out.extend_from_slice(&new_body);
    Ok(out)
}

/// Redact one D1 record (`docs/14-diagnostics.md`), returned as the same
/// JSON [`Record::to_json`] writes.
///
/// A record names no user, no display name and no body — that is its own
/// rule — so what it carries of GDPR's list is IP literals: the socket
/// address of every decision that has one, and any address a `Call-ID`
/// was written with. Each goes through `red` exactly as it does in
/// [`redact_message`], so one [`Redactor`] handed a call's record and then
/// its D2 recording gives an address the same pseudonym in both, and the
/// two still line up. The `Call-ID` otherwise stays, for the reason it
/// stays in a redacted message.
#[must_use]
pub fn redact_record(record: &Record, red: &mut Redactor) -> String {
    redact_record_json(&record.to_json(), red)
}

/// [`redact_record`] over a record already serialised, or over the whole
/// document `Endpoint::diagnostics_json` writes, which is the same shape
/// around several records.
///
/// JSON can be scanned as it stands: every key and every string value is
/// quoted, and a quotation mark ends a run of address characters, so a run
/// that parses as an address is one a decision or a `Call-ID` carried and
/// never a key, a reason code or an offset.
#[must_use]
pub fn redact_record_json(json: &str, red: &mut Redactor) -> String {
    String::from_utf8(scan_ip_literals(json.as_bytes(), red)).unwrap_or_else(|_| json.to_owned())
}

/// Free text — a log line, an error sentence, a state report — with what
/// [`redact_message`] takes out of a message taken out of it too, for text
/// that is not a message and cannot be parsed as one.
///
/// Three passes, each the same rule [`redact_message`] applies structurally:
///
/// - **Credentials are dropped, not pseudonymised.** Everything on a line
///   after `Authorization:`, `Proxy-Authorization:` or `Digest ` becomes
///   `REDACTED`, and an SDES `inline:` key is cut out the way it is in an SDP
///   body.
/// - **A SIP, SIPS or tel URI's user part** — the name or the number — is
///   pseudonymised wherever a `sip:`, `sips:` or `tel:` is written, so a URI
///   an application handed in and an error sentence quoted back reads as the
///   same pseudonym the redacted messages carry.
/// - **Every IPv4 or IPv6 literal** is pseudonymised, scanned out of the
///   original text and never out of a pseudonym already written.
///
/// A display name written loose in a sentence is not recognisable as one and
/// is not touched; nothing this crate's callers write puts one there.
#[must_use]
pub fn redact_text(text: &str, red: &mut Redactor) -> String {
    let mut out = String::with_capacity(text.len());
    let mut folding = false;
    for line in text.split_inclusive('\n') {
        if folded(line, &mut folding) {
            continue;
        }
        let (kept, secret) = split_credentials(line);
        folding = secret.is_some();
        redact_uris_and_addresses(kept, red, &mut out);
        if let Some(tail) = secret {
            if kept.to_ascii_lowercase().ends_with("authorization:") {
                out.push(' ');
            }
            out.push_str("REDACTED");
            out.push_str(tail);
        }
    }
    out
}

/// Whether `line` continues a credential the line before it was cut at —
/// RFC 3261 §7.3.1's folding, a line that starts with a space or a tab — and
/// so goes with it. A line that does not continue one ends the folding.
fn folded(line: &str, folding: &mut bool) -> bool {
    let continues = *folding && line.starts_with([' ', '\t']);
    *folding = continues;
    continues
}

/// A line cut where a credential starts: what may be kept, and — when a
/// credential was found — the line ending that follows it, so the output
/// keeps the line structure the input had.
fn split_credentials(line: &str) -> (&str, Option<&str>) {
    // the three RFC 4566 §5.12 methods that carry a key, and RFC 4567's
    // key management attribute, beside the credentials and the SDES key
    const MARKERS: [&str; 8] = [
        "proxy-authorization:",
        "authorization:",
        "digest ",
        "inline:",
        "k=clear:",
        "k=base64:",
        "k=uri:",
        "a=key-mgmt:",
    ];
    let lower = line.to_ascii_lowercase();
    let cut = MARKERS
        .iter()
        .filter_map(|marker| lower.find(marker).map(|at| at + marker.len()))
        .min();
    let Some(cut) = cut else {
        return (line, None);
    };
    let ending = if line.ends_with("\r\n") {
        "\r\n"
    } else if line.ends_with('\n') {
        "\n"
    } else {
        ""
    };
    (line.get(..cut).unwrap_or(line), Some(ending))
}

/// The URI and address passes of [`redact_text`] over one piece of a line,
/// appended to `out`.
fn redact_uris_and_addresses(text: &str, red: &mut Redactor, out: &mut String) {
    let lower = text.to_ascii_lowercase();
    let mut plain_from = 0;
    let mut at = 0;
    while at < text.len() {
        let Some((scheme_len, tel)) = uri_scheme_at(&lower, at) else {
            at += lower
                .get(at..)
                .and_then(|rest| rest.chars().next())
                .map_or(1, char::len_utf8);
            continue;
        };
        let user_start = at + scheme_len;
        let rest = text.get(user_start..).unwrap_or("");
        let run = rest
            .find(|c: char| c.is_whitespace() || matches!(c, '>' | '<' | '"' | ',' | ')' | '\''))
            .unwrap_or(rest.len());
        let candidate = rest.get(..run).unwrap_or("");
        let user_len = if tel {
            candidate.find(';').unwrap_or(candidate.len())
        } else {
            candidate.find('@').unwrap_or(0)
        };
        if user_len == 0 {
            at = user_start;
            continue;
        }
        out.push_str(&scan_ip_literals_str(
            text.get(plain_from..user_start).unwrap_or(""),
            red,
        ));
        let user = candidate.get(..user_len).unwrap_or("");
        out.push_str(&red.identifier(user.as_bytes()));
        plain_from = user_start + user_len;
        at = plain_from;
    }
    out.push_str(&scan_ip_literals_str(
        text.get(plain_from..).unwrap_or(""),
        red,
    ));
}

/// Whether a `sip:`, `sips:` or `tel:` scheme starts at `at` in `lower` — and
/// is not the tail of a longer word — with its length and whether it is
/// `tel:`.
fn uri_scheme_at(lower: &str, at: usize) -> Option<(usize, bool)> {
    let preceded_by_word = lower
        .get(..at)
        .and_then(|before| before.chars().next_back())
        .is_some_and(|c| c.is_ascii_alphanumeric());
    if preceded_by_word {
        return None;
    }
    let rest = lower.get(at..)?;
    [("sips:", false), ("sip:", false), ("tel:", true)]
        .into_iter()
        .find(|(scheme, _)| rest.starts_with(scheme))
        .map(|(scheme, tel)| (scheme.len(), tel))
}

/// SDES key material dropped from an `a=crypto:` line, and the user name of
/// an `o=` line (RFC 4566 §5.2: "the user's login on the originating host")
/// pseudonymised like any other user part — `-`, which is what a host with
/// no notion of users writes, is left as it is. Everything else in the body
/// passes through unchanged here, and picks up its IP redaction from
/// [`scan_ip_literals`] over the whole message afterwards.
fn redact_body(body: &[u8], red: &mut Redactor) -> Vec<u8> {
    let text = String::from_utf8_lossy(body);
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let lower = line.trim_start().to_ascii_lowercase();
        if let Some(stripped) = strip_key_line(line) {
            out.push_str(&stripped);
        } else if lower.starts_with("o=") {
            out.push_str(&redact_origin_line(line, red));
        } else {
            out.push_str(line);
        }
    }
    out.into_bytes()
}

fn redact_origin_line(line: &str, red: &mut Redactor) -> String {
    let Some(start) = line.find("o=").map(|at| at + 2) else {
        return line.to_string();
    };
    let rest = line.get(start..).unwrap_or("");
    let end = rest.find(' ').unwrap_or(rest.len());
    let user = rest.get(..end).unwrap_or("");
    if user.is_empty() || user == "-" {
        return line.to_string();
    }
    format!(
        "{}{}{}",
        line.get(..start).unwrap_or(""),
        red.identifier(user.as_bytes()),
        rest.get(end..).unwrap_or("")
    )
}

/// A session description line with the key material it carries dropped, or
/// `None` for a line that carries none.
///
/// - `a=crypto:` (RFC 4568 §9.1): every `inline:` key-salt, however many
///   key parameters the line lists after `;`, keeping each one's lifetime
///   and `MKI:length` after its `|`.
/// - `k=` (RFC 4566 §5.12): the key after the method, or the whole value
///   when no method is written; `k=prompt` carries none and is kept.
/// - `a=key-mgmt:` (RFC 4567 §3): the key management data after the
///   protocol identifier, which for MIKEY carries the keys themselves.
fn strip_key_line(line: &str) -> Option<String> {
    let indent = line.len() - line.trim_start().len();
    let (lead, body) = line.split_at(indent);
    let ending = &body[body.trim_end_matches(['\r', '\n']).len()..];
    let content = body.trim_end_matches(['\r', '\n']);
    let lower = content.to_ascii_lowercase();
    let stripped = if lower.starts_with("a=crypto:") {
        let mut out = String::with_capacity(content.len());
        let mut rest = content;
        while let Some(at) = rest.to_ascii_lowercase().find("inline:") {
            let (before, marked) = rest.split_at(at + "inline:".len());
            out.push_str(before);
            out.push_str("REDACTED");
            // a key written after a space is a key all the same
            let marked = marked.trim_start();
            let end = marked
                .find(|c: char| c.is_whitespace() || matches!(c, '|' | ';'))
                .unwrap_or(marked.len());
            rest = marked.get(end..).unwrap_or("");
        }
        out.push_str(rest);
        out
    } else if lower.starts_with("k=") {
        let value = content.get(2..).unwrap_or("");
        match value.split_once(':') {
            _ if value.trim().eq_ignore_ascii_case("prompt") => content.to_string(),
            Some((method, _)) => format!("k={method}:REDACTED"),
            None => "k=REDACTED".to_string(),
        }
    } else if lower.starts_with("a=key-mgmt:") {
        let value = content.get("a=key-mgmt:".len()..).unwrap_or("");
        let protocol = value.split_whitespace().next().unwrap_or("");
        format!("a=key-mgmt:{protocol} REDACTED")
    } else {
        return None;
    };
    Some(format!("{lead}{stripped}{ending}"))
}

/// A whole SIP message with its secrets taken out and nothing else touched:
/// the value of every `Authorization` and `Proxy-Authorization` field, folded
/// continuation lines included, and every key a session description carries
/// (`a=crypto` `inline:` keys, `k=`, `a=key-mgmt`; see [`redact_message`]'s
/// body pass), and the password of any `sip:` or `sips:` URI that carries
/// one. Users, display names and addresses stay as they are.
///
/// For a diagnostic trace an operator turned on to compare two runs of the
/// same installation, where a pseudonym would hide exactly what is being
/// compared. It reads lines rather than parsing, so bytes the parser refuses
/// — which is when a trace is wanted most — are stripped the same way: a
/// credential field is recognised by its name at the start of any line, in
/// any case, and a key line anywhere in the body, a multipart one included.
/// `Content-Length` is left as it arrived, so a body whose keys were taken
/// out is shorter than it says.
#[must_use]
pub fn strip_secrets(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len());
    let mut folding = false;
    for line in message.split_inclusive(|byte| *byte == b'\n') {
        let continues = line
            .first()
            .is_some_and(|byte| matches!(*byte, b' ' | b'\t'));
        if folding && continues {
            continue;
        }
        folding = false;
        if let Some(name) = credential_field(line) {
            out.extend_from_slice(name);
            out.extend_from_slice(b": REDACTED");
            out.extend_from_slice(line_ending(line));
            folding = true;
            continue;
        }
        match std::str::from_utf8(line).ok().and_then(strip_key_line) {
            Some(stripped) => out.extend_from_slice(stripped.as_bytes()),
            None => strip_uri_passwords(line, &mut out),
        }
    }
    out
}

/// Free text with its credentials cut and nothing pseudonymised:
/// [`redact_text`]'s credential pass alone, for the lines of a diagnostic
/// trace.
#[must_use]
pub fn strip_secrets_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut folding = false;
    for line in text.split_inclusive('\n') {
        if folded(line, &mut folding) {
            continue;
        }
        let (kept, secret) = split_credentials(line);
        folding = secret.is_some();
        let mut clean = Vec::with_capacity(kept.len());
        strip_uri_passwords(kept.as_bytes(), &mut clean);
        // only ASCII between an ASCII colon and an ASCII `@` was replaced, so
        // what is left is as valid as what came in
        out.push_str(&String::from_utf8_lossy(&clean));
        if let Some(tail) = secret {
            if kept.to_ascii_lowercase().ends_with("authorization:") {
                out.push(' ');
            }
            out.push_str("REDACTED");
            out.push_str(tail);
        }
    }
    out
}

/// `text` onto `out`, with the password of every `sip:` or `sips:` URI in it
/// replaced: RFC 3261 §19.1.1's `user:password@host`, whose password the RFC
/// calls "NOT RECOMMENDED" because carrying it "in clear text (such as URIs)
/// has proven to be a security risk". The user is kept.
///
/// The user part ends at the `@` before any `>`, `<`, `"` or white space; a
/// colon in it starts the password. A URI with no `@` there has no user
/// part, and its colon is the port's.
fn strip_uri_passwords(text: &[u8], out: &mut Vec<u8>) {
    let mut at = 0;
    while let Some(rest) = text.get(at..).filter(|rest| !rest.is_empty()) {
        let scheme = [b"sips:".as_slice(), b"sip:"]
            .into_iter()
            .find(|scheme| {
                rest.get(..scheme.len())
                    .is_some_and(|start| start.eq_ignore_ascii_case(scheme))
            })
            .map_or(0, <[u8]>::len);
        if scheme == 0 {
            out.extend_from_slice(rest.get(..1).unwrap_or_default());
            at += 1;
            continue;
        }
        out.extend_from_slice(rest.get(..scheme).unwrap_or_default());
        at += scheme;
        let after = rest.get(scheme..).unwrap_or_default();
        let end = after
            .iter()
            .position(|byte| {
                matches!(byte, b'@' | b'>' | b'<' | b'"') || byte.is_ascii_whitespace()
            })
            .unwrap_or(after.len());
        let userinfo = after.get(..end).unwrap_or_default();
        if after.get(end) == Some(&b'@')
            && let Some(colon) = userinfo.iter().position(|byte| *byte == b':')
        {
            out.extend_from_slice(userinfo.get(..=colon).unwrap_or_default());
            out.extend_from_slice(b"REDACTED@");
            at += end + 1;
        }
    }
}

/// The name of an `Authorization` or `Proxy-Authorization` field starting
/// `line`, as written, when it is one: the name, optional whitespace, then
/// the colon (RFC 3261 §7.3.1).
fn credential_field(line: &[u8]) -> Option<&[u8]> {
    let colon = line.iter().position(|byte| *byte == b':')?;
    let name = line.get(..colon)?.trim_ascii_end();
    (name.eq_ignore_ascii_case(b"authorization")
        || name.eq_ignore_ascii_case(b"proxy-authorization"))
    .then_some(name)
}

/// The `\r\n` or `\n` a line ends with, or nothing for the last one.
fn line_ending(line: &[u8]) -> &[u8] {
    if line.ends_with(b"\r\n") {
        b"\r\n"
    } else if line.ends_with(b"\n") {
        b"\n"
    } else {
        b""
    }
}

fn redact_header_value(
    name: HeaderName<'_>,
    value: &[u8],
    new_body_len: usize,
    red: &mut Redactor,
) -> String {
    match name {
        HeaderName::ContentLength => new_body_len.to_string(),
        HeaderName::Authorization | HeaderName::ProxyAuthorization => "REDACTED".to_string(),
        HeaderName::From | HeaderName::To => redact_single_addr(value, red),
        HeaderName::Contact => redact_addr_list(value, red),
        HeaderName::RecordRoute | HeaderName::Route => redact_route_list(value, red),
        HeaderName::Extension(ext) if is_identity_header(ext) => redact_single_addr(value, red),
        // everything else keeps its shape and gets only the IP-literal pass —
        // scanned from the ORIGINAL bytes, never from another header's own
        // output: an already-pseudonymised IPv4 is itself a valid dotted-quad,
        // and scanning it a second time would hash the pseudonym instead of
        // correlating it with the address that produced it
        _ => String::from_utf8_lossy(&scan_ip_literals(value, red)).into_owned(),
    }
}

fn is_identity_header(name: &str) -> bool {
    const NAMES: [&str; 4] = [
        "P-Asserted-Identity",
        "P-Preferred-Identity",
        "Remote-Party-ID",
        "Diversion",
    ];
    NAMES.iter().any(|known| known.eq_ignore_ascii_case(name))
}

fn redact_single_addr(value: &[u8], red: &mut Redactor) -> String {
    match NameAddrRef::parse(value) {
        Ok(addr) => redact_name_addr(addr, red),
        Err(_) => String::from_utf8_lossy(value).into_owned(),
    }
}

fn redact_addr_list(value: &[u8], red: &mut Redactor) -> String {
    if value.trim_ascii() == b"*" {
        return "*".to_string();
    }
    CommaList::new(value)
        .map(|item| redact_single_addr(item, red))
        .collect::<Vec<_>>()
        .join(", ")
}

fn redact_route_list(value: &[u8], red: &mut Redactor) -> String {
    CommaList::new(value)
        .map(|item| match RouteRef::parse(item) {
            Ok(route) => redact_name_addr(route.addr(), red),
            Err(_) => String::from_utf8_lossy(item).into_owned(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn redact_name_addr(addr: NameAddrRef<'_>, red: &mut Redactor) -> String {
    let mut out = String::new();
    if let Some(display) = addr.display_name() {
        out.push_str(&red.identifier(&display));
        out.push(' ');
    }
    if addr.is_name_addr() {
        out.push('<');
    }
    out.push_str(&redact_uri(addr.uri(), red));
    if addr.is_name_addr() {
        out.push('>');
    }
    for (name, value) in addr.params() {
        out.push(';');
        out.push_str(&String::from_utf8_lossy(name));
        if let Some(v) = value {
            out.push('=');
            out.push_str(&scan_ip_literals_str(&String::from_utf8_lossy(v), red));
        }
    }
    out
}

fn redact_uri(uri: UriRef<'_>, red: &mut Redactor) -> String {
    match uri {
        UriRef::Sip(u) => {
            let mut out = format!("{}:", u.scheme);
            if let Some(user) = u.user {
                out.push_str(&red.identifier(user.as_bytes()));
                out.push('@');
            }
            match u.host {
                HostRef::Name(n) => out.push_str(n),
                HostRef::Ipv4(a) => {
                    let _ = write!(out, "{}", red.ipv4(a));
                }
                HostRef::Ipv6(a) => {
                    let _ = write!(out, "[{}]", red.ipv6(a));
                }
            }
            if let Some(port) = u.port {
                let _ = write!(out, ":{port}");
            }
            if !u.params_raw().is_empty() {
                out.push(';');
                out.push_str(&scan_ip_literals_str(u.params_raw(), red));
            }
            if !u.headers_raw().is_empty() {
                out.push('?');
                out.push_str(&scan_ip_literals_str(u.headers_raw(), red));
            }
            out
        }
        UriRef::Other {
            scheme: UriScheme::Tel,
            opaque,
        } => {
            let (number, rest) = split_tel_params(opaque);
            format!("tel:{}{rest}", red.identifier(number.as_bytes()))
        }
        UriRef::Other { scheme, opaque } => format!("{scheme}:{opaque}"),
    }
}

fn split_tel_params(opaque: &str) -> (&str, &str) {
    opaque
        .find(';')
        .map_or((opaque, ""), |i| opaque.split_at(i))
}

/// Every IPv4 or IPv6 literal in `bytes`, pseudonymised — the second pass
/// that reaches an address in a header this crate does not otherwise
/// structurally rewrite (`Via`'s `sent-by` and `received=`, `Record-Route`'s
/// host when it is not the entry redacted above and any extension header) and
/// every address in the SDP body, without needing to parse either.
///
/// Uses `std`'s own [`Ipv4Addr`]/[`Ipv6Addr`] parsers as the validator on a
/// maximal run of candidate characters, rather than a hand-written pattern:
/// they already reject the false positives that matter here — a version
/// number, a timestamp's `HH:MM:SS`, a byte count — because none of those is
/// a well-formed address.
fn scan_ip_literals(bytes: &[u8], red: &mut Redactor) -> Vec<u8> {
    let text = String::from_utf8_lossy(bytes);
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        if c.is_ascii_hexdigit() || c == ':' {
            let end = run_end(&chars, i, |c| c.is_ascii_hexdigit() || c == ':');
            let candidate: String = chars.get(i..end).unwrap_or(&[]).iter().collect();
            if candidate.contains(':')
                && let Ok(addr) = candidate.parse::<Ipv6Addr>()
            {
                out.push_str(&red.ipv6(addr).to_string());
                i = end;
                continue;
            }
        }
        if c.is_ascii_digit() {
            let end = run_end(&chars, i, |c| c.is_ascii_digit() || c == '.');
            let candidate: String = chars.get(i..end).unwrap_or(&[]).iter().collect();
            if candidate.contains('.')
                && let Ok(addr) = candidate.parse::<Ipv4Addr>()
            {
                out.push_str(&red.ipv4(addr).to_string());
                i = end;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out.into_bytes()
}

fn run_end(chars: &[char], start: usize, class: impl Fn(char) -> bool) -> usize {
    let mut end = start;
    while chars.get(end).is_some_and(|&c| class(c)) {
        end += 1;
    }
    end
}

/// [`scan_ip_literals`] over a `&str` rather than raw bytes, for the pieces of
/// a structurally-parsed address that are copied through as text: a URI's own
/// parameters (`maddr`, and any extension a gateway adds) and headers, and a
/// name-addr's parameters (`fs_path` and similar carry a whole embedded URI).
/// None of those is parsed further here, so an IP literal inside one would
/// otherwise survive a structural redaction untouched — this is the same
/// safety net [`scan_ip_literals`] is for everything else.
fn scan_ip_literals_str(text: &str, red: &mut Redactor) -> String {
    String::from_utf8(scan_ip_literals(text.as_bytes(), red)).unwrap_or_else(|_| text.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        Mode, Redactor, redact_message, redact_record_json, redact_text, strip_secrets,
        strip_secrets_text,
    };

    fn hash_redactor() -> Redactor {
        Redactor::new(Mode::Hash(b"organisation-secret".to_vec()))
    }

    fn redact(msg: &[u8], red: &mut Redactor) -> String {
        String::from_utf8(redact_message(msg, red).expect("a well-formed message")).expect("utf-8")
    }

    #[test]
    fn the_user_part_of_from_and_to_is_replaced() {
        let msg = b"INVITE sip:bob@example.com SIP/2.0\r\n\
From: Alice <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a@b\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let out = redact(msg, &mut hash_redactor());
        assert!(!out.contains("alice@"));
        assert!(!out.contains("bob@"));
        assert!(!out.contains("Alice"));
        assert!(out.contains("example.com")); // the host is not a user identifier
        assert!(out.contains(";tag=1")); // correlation survives redaction
    }

    #[test]
    fn a_display_name_is_replaced_and_a_bare_addr_spec_stays_unbracketed() {
        let msg = b"OPTIONS sip:example.com SIP/2.0\r\n\
From: \"Carol Example\" <sip:carol@example.com>;tag=1\r\n\
To: sip:example.com\r\n\
Call-ID: a@b\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";
        let out = redact(msg, &mut hash_redactor());
        assert!(!out.contains("Carol"));
        assert!(out.contains("To: sip:example.com"));
    }

    #[test]
    fn a_phone_number_in_a_tel_uri_is_replaced() {
        let msg = b"INVITE tel:+15551234567 SIP/2.0\r\n\
From: <sip:a@example.com>;tag=1\r\n\
To: <tel:+15551234567>\r\n\
Call-ID: a@b\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let out = redact(msg, &mut hash_redactor());
        assert!(!out.contains("+15551234567"));
    }

    #[test]
    fn a_digit_only_sip_user_part_is_replaced_the_same_way_as_a_phone_number() {
        let msg = b"INVITE sip:15551234567@gw.example.com SIP/2.0\r\n\
From: <sip:a@example.com>;tag=1\r\n\
To: <sip:15551234567@gw.example.com>\r\n\
Call-ID: a@b\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let out = redact(msg, &mut hash_redactor());
        assert!(!out.contains("15551234567"));
    }

    #[test]
    fn an_ipv4_literal_in_via_and_in_sdp_becomes_the_same_pseudonym_in_both_places() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\nt=0 0\r\n";
        let msg = format!(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK1\r\n\
From: <sip:a@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a@b\r\n\
CSeq: 1 INVITE\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\r\n{sdp}",
            sdp.len()
        );
        let out = redact(msg.as_bytes(), &mut hash_redactor());
        assert!(!out.contains("192.0.2.9"));
        let via_start =
            out.find("Via: SIP/2.0/UDP ").expect("a Via line") + "Via: SIP/2.0/UDP ".len();
        let after_start = &out[via_start..];
        let via_host = &after_start[..after_start.find(':').expect("a port separator")];
        assert!(
            out.matches(via_host).count() >= 2,
            "the same host is redacted the same way in Via and in the SDP"
        );
    }

    #[test]
    fn a_host_structurally_redacted_in_contact_matches_the_same_host_scanned_in_via() {
        // Contact's host goes through redact_uri (structural); Via's host,
        // untouched by the structural pass, goes through scan_ip_literals —
        // the two must still agree, and must not compound: scanning Contact's
        // own already-pseudonymised, still IP-shaped output would hash the
        // pseudonym instead of correlating it with the real address
        let msg = b"REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: a@b\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:alice@192.0.2.1>;expires=3600\r\n\
Content-Length: 0\r\n\r\n";
        let out = redact(msg, &mut hash_redactor());
        assert!(!out.contains("192.0.2.1"));
        let via_start =
            out.find("Via: SIP/2.0/UDP ").expect("a Via line") + "Via: SIP/2.0/UDP ".len();
        let via_host = &out[via_start
            ..out[via_start..]
                .find(':')
                .map(|i| via_start + i)
                .expect("a port separator")];
        let contact_at =
            out.find("Contact: <sip:").expect("a Contact line") + "Contact: <sip:".len();
        let after_at = out[contact_at..]
            .find('@')
            .map(|i| contact_at + i + 1)
            .expect("an @");
        let contact_host = &out[after_at
            ..out[after_at..]
                .find('>')
                .map(|i| after_at + i)
                .expect("a closing >")];
        assert_eq!(
            via_host, contact_host,
            "the same real address gets the same pseudonym everywhere"
        );
    }

    #[test]
    fn an_ipv6_literal_is_replaced_and_still_parses_after_redaction() {
        let msg = b"INVITE sip:bob@[2001:db8::1]:5060 SIP/2.0\r\n\
From: <sip:a@example.com>;tag=1\r\n\
To: <sip:bob@[2001:db8::1]:5060>\r\n\
Call-ID: a@b\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\r\n";
        let out = redact(msg, &mut hash_redactor());
        assert!(!out.contains("2001:db8::1"));
    }

    #[test]
    fn authorization_is_dropped_not_hashed() {
        let msg = b"REGISTER sip:example.com SIP/2.0\r\n\
From: <sip:a@example.com>;tag=1\r\n\
To: <sip:a@example.com>\r\n\
Call-ID: a@b\r\n\
CSeq: 2 REGISTER\r\n\
Authorization: Digest username=\"alice\", realm=\"example.com\", nonce=\"n\", uri=\"sip:example.com\", response=\"deadbeef\"\r\n\
Content-Length: 0\r\n\r\n";
        let out = redact(msg, &mut hash_redactor());
        assert!(!out.contains("alice"));
        assert!(!out.contains("deadbeef"));
        assert!(out.contains("Authorization: REDACTED"));
    }

    #[test]
    fn an_sdes_key_is_dropped_and_the_rest_of_the_crypto_line_survives() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\nt=0 0\r\n\
m=audio 40000 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:d0RmdmcmVCspeE6PJ5+cJVEDBRLM|2^20|1:32\r\n";
        let msg = format!(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
From: <sip:a@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a@b\r\n\
CSeq: 1 INVITE\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\r\n{sdp}",
            sdp.len()
        );
        let out = redact(msg.as_bytes(), &mut hash_redactor());
        assert!(!out.contains("d0RmdmcmVCspeE6PJ5+cJVEDBRLM"));
        assert!(out.contains("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:REDACTED|2^20|1:32"));
    }

    /// A session description carrying every kind of key this stack knows of:
    /// two key parameters on one `a=crypto` line (RFC 4568 §9.1 allows a
    /// list), a `k=` line and a MIKEY `a=key-mgmt`.
    const KEYED_SDP: &str = "v=0\r\no=alice 1 1 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\n\
t=0 0\r\nk=base64:S0VZLUxJTkUtU0VDUkVU\r\n\
a=key-mgmt:mikey AQAFgM0XflABAAAAAAAAAAAAAAsAyO7-SECRET-MIKEY\r\n\
m=audio 40000 RTP/SAVP 0\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Rmlyc3RLZXlTZWNyZXQx|2^20|1:4;inline:U2Vjb25kS2V5U2VjcmV0|2^20|2:4\r\n\
a=crypto:2 AES_CM_128_HMAC_SHA1_32 INLINE:VGhpcmRLZXlTZWNyZXQz\r\n";

    const KEYS: [&str; 5] = [
        "Rmlyc3RLZXlTZWNyZXQx",
        "U2Vjb25kS2V5U2VjcmV0",
        "VGhpcmRLZXlTZWNyZXQz",
        "S0VZLUxJTkUtU0VDUkVU",
        "SECRET-MIKEY",
    ];

    fn keyed_invite() -> String {
        format!(
            "INVITE sip:bob@198.51.100.4 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK1\r\n\
From: \"Alice\" <sip:alice@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a@b\r\n\
CSeq: 1 INVITE\r\n\
Authorization: Digest username=\"alice\", realm=\"pbx\", nonce=\"n1\",\r\n\x20\
uri=\"sip:bob@198.51.100.4\", response=\"0badc0ffee\"\r\n\
proxy-authorization  : Digest username=\"alice\", response=\"feedface\"\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\r\n{KEYED_SDP}",
            KEYED_SDP.len()
        )
    }

    #[test]
    fn every_key_on_a_line_and_every_kind_of_key_line_is_dropped() {
        // the redaction every export and every trace line goes through
        let out = redact(keyed_invite().as_bytes(), &mut hash_redactor());
        for key in KEYS {
            assert!(!out.contains(key), "{key} in {out}");
        }
        assert!(
            out.contains("inline:REDACTED|2^20|1:4;inline:REDACTED|2^20|2:4"),
            "{out}"
        );
        assert!(out.contains("k=base64:REDACTED\r\n"), "{out}");
        assert!(out.contains("a=key-mgmt:mikey REDACTED\r\n"), "{out}");
    }

    #[test]
    fn stripping_takes_the_secrets_and_leaves_everyone_in_the_message() {
        let message = keyed_invite();
        let out = String::from_utf8(strip_secrets(message.as_bytes())).unwrap();
        for secret in KEYS
            .iter()
            .chain(&["0badc0ffee", "feedface", "nonce=", "uri=\"sip"])
        {
            assert!(!out.contains(secret), "{secret} in {out}");
        }
        // the whole message otherwise: users, names and addresses as sent
        for kept in [
            "INVITE sip:bob@198.51.100.4 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK1\r\n",
            "From: \"Alice\" <sip:alice@example.com>;tag=1\r\n",
            "Authorization: REDACTED\r\nproxy-authorization: REDACTED\r\nContent-Type",
            "o=alice 1 1 IN IP4 192.0.2.9\r\n",
            "a=crypto:2 AES_CM_128_HMAC_SHA1_32 INLINE:REDACTED\r\n",
        ] {
            assert!(out.contains(kept), "{kept:?} not in {out}");
        }
    }

    #[test]
    fn stripping_reads_lines_so_a_message_the_parser_refuses_loses_its_secrets_too() {
        let garbage = b"NOT SIP AT ALL\nAUTHORIZATION:Digest response=\"cafebabe\"\n\
\tresponse2=\"deadbeef\"\nsomething: else\n\xff\xfe\na=crypto:1 X inline:QUJDREVG\nk=prompt\nk=Y2xlYXJrZXk";
        let out = strip_secrets(garbage);
        let text = String::from_utf8_lossy(&out);
        for secret in ["cafebabe", "deadbeef", "QUJDREVG", "Y2xlYXJrZXk"] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
        assert!(
            text.contains("AUTHORIZATION: REDACTED\nsomething: else\n"),
            "{text}"
        );
        assert!(
            text.contains("k=prompt\n"),
            "a key the user types is no key"
        );
        assert!(text.ends_with("k=REDACTED"), "{text}");
        assert!(
            out.windows(2).any(|pair| pair == b"\xff\xfe"),
            "bytes kept as they were"
        );
    }

    #[test]
    fn free_text_loses_a_folded_credential_and_every_sdp_key() {
        // a message logged as prose: the second line of a folded
        // Authorization value, and the key lines, go with it
        let text = "Authorization: Digest username=\"a\",\r\n\tresponse=\"f00dcafe\"\r\n\
Via: next\r\nk=base64:S0VZS0VZ\r\na=key-mgmt:mikey TUlLRVk=\r\n k=clear:cGxhaW4=\r\n";
        for out in [
            redact_text(text, &mut hash_redactor()),
            strip_secrets_text(text),
        ] {
            for secret in ["f00dcafe", "S0VZS0VZ", "TUlLRVk", "cGxhaW4"] {
                assert!(!out.contains(secret), "{secret} in {out}");
            }
            assert!(out.contains("Via: next\r\n"), "{out}");
        }
    }

    #[test]
    fn stripping_free_text_cuts_credentials_and_pseudonymises_nothing() {
        let text = "refused sip:alice@192.0.2.7 with Authorization: Digest response=\"f00d\"\n\
SDES inline:QUJD|2^20\nplain line";
        let out = strip_secrets_text(text);
        assert_eq!(
            out,
            "refused sip:alice@192.0.2.7 with Authorization: REDACTED\nSDES inline:REDACTED\n\
plain line"
        );
    }

    /// RFC 3261 §19.1.1's `sip:user:password@host`: the user stays, as
    /// everything else in a diagnostic trace does, and the password goes.
    #[test]
    fn stripping_takes_a_password_out_of_a_uri_and_keeps_the_rest_of_it() {
        let message = "REGISTER sips:alice:pw1SECRET@pbx.example SIP/2.0\r\n\
From: \"Alice\" <SIP:alice:pw2SECRET@pbx.example>;tag=1\r\n\
To: <sip:alice@pbx.example>\r\n\
Contact: <sip:alice@192.0.2.1:5060;ob>\r\n\
Route: <sip:pbx.example:5060;lr>\r\n\r\n";
        let out = String::from_utf8(strip_secrets(message.as_bytes())).unwrap();
        let prose = strip_secrets_text(message);
        for out in [&out, &prose] {
            assert!(!out.contains("SECRET"), "{out}");
            for kept in [
                "REGISTER sips:alice:REDACTED@pbx.example SIP/2.0\r\n",
                "From: \"Alice\" <SIP:alice:REDACTED@pbx.example>;tag=1\r\n",
                "To: <sip:alice@pbx.example>\r\n",
                "Contact: <sip:alice@192.0.2.1:5060;ob>\r\n",
                "Route: <sip:pbx.example:5060;lr>\r\n",
            ] {
                assert!(out.contains(kept), "{kept:?} not in {out}");
            }
        }
    }

    /// RFC 4568 §9.1 writes no space after `inline:`, and a key written with
    /// one is a key all the same.
    #[test]
    fn a_key_after_a_space_is_still_a_key() {
        let line = "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:  S3CRETKEY|2^20\r\n";
        let out = String::from_utf8(strip_secrets(line.as_bytes())).unwrap();
        assert!(!out.contains("S3CRETKEY"), "{out}");
        assert!(out.ends_with("inline:REDACTED|2^20\r\n"), "{out}");
    }

    #[test]
    fn content_length_is_recomputed_after_the_body_is_redacted() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\nt=0 0\r\n";
        let msg = format!(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
From: <sip:a@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a@b\r\n\
CSeq: 1 INVITE\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\r\n{sdp}",
            sdp.len()
        );
        let out = redact(msg.as_bytes(), &mut hash_redactor());
        let (headers, body) = out.split_once("\r\n\r\n").expect("a header/body split");
        let stated: usize = headers
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .and_then(|v| v.parse().ok())
            .expect("a Content-Length header");
        assert_eq!(stated, body.len());
    }

    #[test]
    fn the_same_input_hashes_to_the_same_pseudonym_twice() {
        let mut red = hash_redactor();
        let a = red.identifier(b"alice");
        let b = red.identifier(b"alice");
        assert_eq!(a, b);
        let c = red.identifier(b"bob");
        assert_ne!(a, c);
    }

    #[test]
    fn delete_mode_is_consistent_within_one_export_and_carries_no_hash_of_the_value() {
        let mut red = Redactor::new(Mode::Delete);
        let a1 = red.identifier(b"alice");
        let a2 = red.identifier(b"alice");
        assert_eq!(
            a1, a2,
            "the same value within one export gets the same placeholder"
        );
        let b = red.identifier(b"bob");
        assert_ne!(
            a1, b,
            "two distinct values never collide on one placeholder"
        );
        // the placeholder is a position in this run, not a function of the
        // bytes redacted, unlike Mode::Hash's HMAC — nothing here lets a
        // reader of the placeholder alone recover or match the original value
        assert!(!a1.contains("alice"));
    }

    #[test]
    fn debug_formatting_a_hash_mode_never_prints_the_organisation_key() {
        let mode = Mode::Hash(b"organisation-secret".to_vec());
        let printed = format!("{mode:?}");
        assert!(!printed.contains("organisation-secret"));
        assert_eq!(printed, "Hash(<redacted>)");
    }

    #[test]
    fn a_version_string_and_a_timestamp_are_not_mistaken_for_addresses() {
        let msg = b"OPTIONS sip:example.com SIP/2.0\r\n\
From: <sip:a@example.com>;tag=1\r\n\
To: <sip:example.com>\r\n\
Call-ID: a@b\r\n\
CSeq: 1 OPTIONS\r\n\
Date: Tue, 15 Sep 2026 20:30:00 GMT\r\n\
User-Agent: Sipral/0.0.1\r\n\
Content-Length: 0\r\n\r\n";
        let out = redact(msg, &mut hash_redactor());
        assert!(out.contains("Date: Tue, 15 Sep 2026 20:30:00 GMT"));
        assert!(out.contains("User-Agent: Sipral/0.0.1"));
    }

    #[test]
    fn a_maddr_uri_param_ip_literal_is_redacted() {
        let msg = b"INVITE sip:bob@example.com SIP/2.0\r\n\
From: <sip:a@example.com>;tag=1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a@b\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@example.com;maddr=192.0.2.55>\r\n\
Content-Length: 0\r\n\r\n";
        let out = redact(msg, &mut hash_redactor());
        assert!(!out.contains("192.0.2.55"), "maddr IP leaked: {out}");
    }

    #[test]
    fn a_d1_record_loses_its_addresses_and_keeps_everything_else() {
        let record = r#"{"call_id":"f222a20b@192.0.2.44","dropped":0,"decisions":[{"at_us":0,"reason":"transport.selected","address":"192.0.2.9:5060","protocol":"UDP"},{"at_us":38000,"reason":"request.sent","direction":"out","method":"INVITE","bytes":1216,"address":"[2001:db8::7]:5061","protocol":"TLS","size":1216,"limit":1300}]}"#;
        let out = redact_record_json(record, &mut hash_redactor());
        for real in ["192.0.2.44", "192.0.2.9", "2001:db8::7"] {
            assert!(!out.contains(real), "{real} leaked: {out}");
        }
        for kept in [
            r#""call_id":"f222a20b@"#,
            r#""at_us":38000"#,
            r#""reason":"transport.selected""#,
            r#""method":"INVITE""#,
            r#""bytes":1216"#,
            r#""size":1216,"limit":1300"#,
            ":5060\"",
            "]:5061\"",
        ] {
            assert!(out.contains(kept), "{kept} lost: {out}");
        }
    }

    #[test]
    fn a_d1_record_and_a_message_redacted_together_agree_on_an_address() {
        let mut red = hash_redactor();
        let record = redact_record_json(r#"{"address":"192.0.2.9:5060"}"#, &mut red);
        let message = redact(
            b"OPTIONS sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK1\r\n\
From: <sip:a@example.com>;tag=1\r\n\
To: <sip:example.com>\r\n\
Call-ID: a@b\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n",
            &mut red,
        );
        let pseudonym = record
            .trim_start_matches(r#"{"address":""#)
            .trim_end_matches(r#":5060"}"#);
        assert!(
            message.contains(&format!("UDP {pseudonym}:5060")),
            "{record} / {message}"
        );
    }

    #[test]
    fn free_text_loses_its_user_parts_addresses_and_credentials() {
        let mut red = hash_redactor();
        let line = "placing sip:alice@192.0.2.9:5060 from 2001:db8::7 for tel:+40721000111;phone-context=x \
                    Authorization: Digest username=\"alice\", response=\"f00d\"";
        let out = redact_text(line, &mut red);
        assert!(!out.contains("alice"), "{out}");
        assert!(!out.contains("192.0.2.9"), "{out}");
        assert!(!out.contains("2001:db8::7"), "{out}");
        assert!(!out.contains("+40721000111"), "{out}");
        assert!(!out.contains("f00d"), "{out}");
        assert!(
            out.contains(":5060 from "),
            "the shape of the sentence stays: {out}"
        );
        assert!(out.contains(";phone-context=x"), "{out}");
        assert!(out.ends_with("Authorization: REDACTED"), "{out}");
    }

    #[test]
    fn free_text_and_a_message_agree_on_a_user_and_an_address() {
        let mut red = hash_redactor();
        let text = redact_text("sip:a@192.0.2.9", &mut red);
        let message = redact(
            b"OPTIONS sip:a@192.0.2.9 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bK1\r\n\
From: <sip:a@example.com>;tag=1\r\n\
To: <sip:example.com>\r\n\
Call-ID: a@b\r\n\
CSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n",
            &mut red,
        );
        assert!(
            message.starts_with(&format!("OPTIONS {text} SIP/2.0")),
            "{text} / {message}"
        );
    }

    #[test]
    fn a_word_that_merely_ends_in_a_scheme_is_not_a_uri() {
        let mut red = hash_redactor();
        assert_eq!(
            redact_text("hotel:lobby@desk", &mut red),
            "hotel:lobby@desk"
        );
        assert_eq!(
            redact_text("an SDES inline:secretkey|2^20", &mut red),
            "an SDES inline:REDACTED"
        );
    }

    #[test]
    fn the_user_name_of_an_sdp_origin_line_is_replaced_and_a_dash_is_kept() {
        let invite = |user: &str| {
            let body = format!("v=0\r\no={user} 1 1 IN IP4 192.0.2.4\r\ns=-\r\n");
            format!(
                "INVITE sip:a@example.com SIP/2.0\r\n\
From: <sip:b@example.com>;tag=1\r\n\
To: <sip:a@example.com>\r\n\
Call-ID: a@b\r\n\
CSeq: 1 INVITE\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\r\n{body}",
                body.len()
            )
        };
        let out = redact(invite("bob").as_bytes(), &mut hash_redactor());
        assert!(!out.contains("o=bob"), "{out}");
        assert!(out.contains(" 1 1 IN IP4 "), "{out}");
        let anonymous = redact(invite("-").as_bytes(), &mut hash_redactor());
        assert!(anonymous.contains("o=- 1 1 IN IP4"), "{anonymous}");
    }

    #[test]
    fn a_message_the_parser_refuses_is_an_error_rather_than_a_silent_pass_through() {
        let mut red = hash_redactor();
        assert!(redact_message(b"not a sip message at all", &mut red).is_err());
    }
}
