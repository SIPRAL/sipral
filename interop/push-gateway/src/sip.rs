// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A SIP message a proxy can edit: parsed with the stack's own parser, then
//! held as a start line, a list of header fields and a body.
//!
//! A proxy adds and removes whole field values -- a `Via` on top, a `Route`
//! taken off, a `Feature-Caps` added, a `Contact` replaced -- and never
//! rewrites the inside of one it does not own. So the fields that RFC 3261
//! §7.3.1 allows to be combined on one line with commas (`Via`, `Route`,
//! `Record-Route`, `Contact`) are split into one value per field when the
//! message is read, which is the same message on the wire, and everything
//! else is kept as it arrived. `Content-Length` is written from the body,
//! never copied.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};

use sipral_core::msg::{
    CommaList, HeaderName, MessageKind, NameAddrRef, ParseMode, ParseScratch, SipUriRef, Uri,
    UriRef, ViaRef, parse, unescape, unfold,
};

/// The first line of a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StartLine {
    /// `METHOD Request-URI SIP/2.0`.
    Request {
        /// The method, as written.
        method: String,
        /// The Request-URI, as written.
        uri: String,
    },
    /// `SIP/2.0 code reason`.
    Response {
        /// The status code.
        code: u16,
        /// The reason phrase.
        reason: String,
    },
}

/// One message, ready to be edited and written out again.
#[derive(Clone, Debug)]
pub(crate) struct Message {
    /// The request line or the status line.
    pub(crate) start: StartLine,
    /// Every field but `Content-Length`, in order, with canonical names.
    pub(crate) headers: Vec<(String, String)>,
    /// The body, as many bytes as `Content-Length` said.
    pub(crate) body: Vec<u8>,
}

/// Fields whose comma-separated values are split one to a line.
const LISTS: [&str; 4] = ["Via", "Route", "Record-Route", "Contact"];

impl Message {
    /// Read one message, or `None` for anything that is not one -- a
    /// keep-alive, a STUN packet, garbage.
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        let mut scratch = ParseScratch::new();
        let raw = parse(bytes, &mut scratch, ParseMode::Lenient).ok()?;
        raw.validate().ok()?;
        let start = match raw.kind() {
            MessageKind::Request(method) => StartLine::Request {
                method: method.as_str().to_owned(),
                uri: String::from_utf8(raw.request_uri_bytes()?.to_vec()).ok()?,
            },
            MessageKind::Response(code) => StartLine::Response {
                code: code.get(),
                reason: String::from_utf8_lossy(raw.reason().unwrap_or_default()).into_owned(),
            },
        };
        let mut headers = Vec::new();
        for (name, value) in raw.raw_headers() {
            let name = HeaderName::from_bytes(name)?;
            let canonical = name.canonical().to_owned();
            if canonical == "Content-Length" {
                continue;
            }
            let value = String::from_utf8(unfold(value).into_owned()).ok()?;
            if LISTS.contains(&canonical.as_str()) && value.trim() != "*" {
                for one in CommaList::new(value.as_bytes()) {
                    headers.push((canonical.clone(), String::from_utf8(one.to_vec()).ok()?));
                }
            } else {
                headers.push((canonical, value.trim().to_owned()));
            }
        }
        Some(Self {
            start,
            headers,
            body: raw.body().to_vec(),
        })
    }

    /// The bytes on the wire.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out = match &self.start {
            StartLine::Request { method, uri } => format!("{method} {uri} SIP/2.0\r\n"),
            StartLine::Response { code, reason } => format!("SIP/2.0 {code} {reason}\r\n"),
        };
        for (name, value) in &self.headers {
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            out.push_str("\r\n");
        }
        let _ = write!(out, "Content-Length: {}\r\n\r\n", self.body.len());
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }

    /// The method of a request, or of the request a response answers.
    pub(crate) fn method(&self) -> Option<&str> {
        match &self.start {
            StartLine::Request { method, .. } => Some(method),
            StartLine::Response { .. } => self.cseq_method(),
        }
    }

    /// Whether this is a request.
    pub(crate) const fn is_request(&self) -> bool {
        matches!(self.start, StartLine::Request { .. })
    }

    /// The status code of a response.
    pub(crate) const fn status(&self) -> Option<u16> {
        match self.start {
            StartLine::Response { code, .. } => Some(code),
            StartLine::Request { .. } => None,
        }
    }

    /// The Request-URI of a request.
    pub(crate) fn request_uri(&self) -> Option<&str> {
        match &self.start {
            StartLine::Request { uri, .. } => Some(uri),
            StartLine::Response { .. } => None,
        }
    }

    /// Replace the Request-URI of a request.
    pub(crate) fn set_request_uri(&mut self, new: &str) {
        if let StartLine::Request { uri, .. } = &mut self.start {
            new.clone_into(uri);
        }
    }

    /// The method named in `CSeq`.
    pub(crate) fn cseq_method(&self) -> Option<&str> {
        self.first("CSeq")?.split_whitespace().nth(1)
    }

    /// The first value of a field.
    pub(crate) fn first(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Every value of a field, in order.
    pub(crate) fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Remove the first value of a field and answer it.
    pub(crate) fn take_first(&mut self, name: &str) -> Option<String> {
        let at = self
            .headers
            .iter()
            .position(|(n, _)| n.eq_ignore_ascii_case(name))?;
        Some(self.headers.remove(at).1)
    }

    /// Put a value in front of every other value of its field, and in front
    /// of every other field when there are none.
    pub(crate) fn push_front(&mut self, name: &str, value: String) {
        let at = self
            .headers
            .iter()
            .position(|(n, _)| n.eq_ignore_ascii_case(name))
            .unwrap_or(0);
        self.headers.insert(at, (name.to_owned(), value));
    }

    /// Add a value after every other field.
    pub(crate) fn push_back(&mut self, name: &str, value: String) {
        self.headers.push((name.to_owned(), value));
    }

    /// Replace every value of a field with the ones `edit` gives back for
    /// each of them, in place.
    pub(crate) fn map_values(&mut self, name: &str, mut edit: impl FnMut(&str) -> String) {
        for (n, v) in &mut self.headers {
            if n.eq_ignore_ascii_case(name) {
                *v = edit(v);
            }
        }
    }

    /// The `tag` on `To`, when there is one: a request with one is inside a
    /// dialog (RFC 3261 §12.2).
    pub(crate) fn to_tag(&self) -> Option<String> {
        let to = self.first("To")?;
        let parsed = NameAddrRef::parse(to.as_bytes()).ok()?;
        parsed
            .tag()
            .map(|tag| String::from_utf8_lossy(&tag).into_owned())
    }

    /// The `From` URI.
    pub(crate) fn caller_uri(&self) -> Option<String> {
        let from = self.first("From")?;
        let parsed = NameAddrRef::parse(from.as_bytes()).ok()?;
        String::from_utf8(parsed.uri_bytes().to_vec()).ok()
    }

    /// The display name on `From`, unquoted.
    pub(crate) fn caller_name(&self) -> Option<String> {
        let from = self.first("From")?;
        let parsed = NameAddrRef::parse(from.as_bytes()).ok()?;
        parsed
            .display_name()
            .map(|name| String::from_utf8_lossy(&name).into_owned())
            .filter(|name| !name.is_empty())
    }

    /// A response to this request, carrying what RFC 3261 §8.2.6.2 says a
    /// response copies, with `tag` put on `To` when it has none.
    pub(crate) fn response(&self, code: u16, reason: &str, tag: &str) -> Self {
        let mut headers = Vec::new();
        for (name, value) in &self.headers {
            match name.as_str() {
                "Via" | "From" | "Call-ID" | "CSeq" => headers.push((name.clone(), value.clone())),
                "To" => {
                    let tagged = if self.to_tag().is_some() {
                        value.clone()
                    } else {
                        format!("{value};tag={tag}")
                    };
                    headers.push((name.clone(), tagged));
                }
                _ => {}
            }
        }
        Self {
            start: StartLine::Response {
                code,
                reason: reason.to_owned(),
            },
            headers,
            body: Vec::new(),
        }
    }
}

/// The parts of one `Via` value a proxy reads.
pub(crate) struct Via {
    /// `branch`, as written.
    pub(crate) branch: String,
    /// Where a response goes by the rules of RFC 3261 §18.2.2 and RFC 3581
    /// §4: `received` and `rport` when they are there, the sent-by otherwise.
    /// `None` when that is a name rather than an address.
    pub(crate) reply_to: Option<SocketAddr>,
    /// The sent-by, as written.
    pub(crate) sent_by: String,
}

impl Via {
    /// Read one `Via` value.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        let via = ViaRef::parse(value.as_bytes()).ok()?;
        let branch = String::from_utf8(via.branch()?.into_owned()).ok()?;
        let port = via.port.unwrap_or(5060);
        let host = host_ip(via.host);
        let sent_by = match via.port {
            Some(port) => format!("{}:{port}", host_text(via.host)),
            None => host_text(via.host),
        };
        let reply_port = match via.rport() {
            Ok(sipral_core::msg::Rport::Given(port)) => port,
            _ => port,
        };
        let reply_ip = via.received().or(host);
        Some(Self {
            branch,
            reply_to: reply_ip.map(|ip| SocketAddr::new(ip, reply_port)),
            sent_by,
        })
    }
}

/// A `Via` value with `received` and `rport` filled in for the address it
/// really came from (RFC 3261 §18.2.1, RFC 3581 §4), or unchanged when the
/// sent-by already says so and no `rport` was asked for.
pub(crate) fn stamp_received(value: &str, source: SocketAddr) -> String {
    let Ok(via) = ViaRef::parse(value.as_bytes()) else {
        return value.to_owned();
    };
    let asked_rport = matches!(via.rport(), Ok(sipral_core::msg::Rport::Requested));
    let same_host = host_ip(via.host) == Some(source.ip());
    let mut out = String::new();
    for (index, piece) in split_params(value).into_iter().enumerate() {
        if index > 0 {
            let name = piece.split('=').next().unwrap_or_default().trim();
            if name.eq_ignore_ascii_case("received")
                || (asked_rport && name.eq_ignore_ascii_case("rport"))
            {
                continue;
            }
            out.push(';');
        }
        out.push_str(piece.trim());
    }
    if !same_host || asked_rport {
        let _ = write!(out, ";received={}", source.ip());
    }
    if asked_rport {
        let _ = write!(out, ";rport={}", source.port());
    }
    out
}

/// A value split at its top-level semicolons: the value first, then each
/// parameter as written. A semicolon inside angle brackets or quotes is the
/// URI's, not the field's.
fn split_params(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0u32;
    let mut quoted = false;
    let mut escaped = false;
    let mut start = 0;
    for (i, c) in value.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = false;
            }
            continue;
        }
        match c {
            '"' => quoted = true,
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            ';' if depth == 0 => {
                out.push(value.get(start..i).unwrap_or_default());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(value.get(start..).unwrap_or_default());
    out
}

fn host_ip(host: sipral_core::msg::HostRef<'_>) -> Option<IpAddr> {
    match host {
        sipral_core::msg::HostRef::Ipv4(ip) => Some(IpAddr::V4(ip)),
        sipral_core::msg::HostRef::Ipv6(ip) => Some(IpAddr::V6(ip)),
        sipral_core::msg::HostRef::Name(_) => None,
    }
}

fn host_text(host: sipral_core::msg::HostRef<'_>) -> String {
    match host {
        sipral_core::msg::HostRef::Ipv4(ip) => ip.to_string(),
        sipral_core::msg::HostRef::Ipv6(ip) => format!("[{ip}]"),
        sipral_core::msg::HostRef::Name(name) => name.to_owned(),
    }
}

/// `host:port` written the way a URI writes it.
pub(crate) fn hostport(address: SocketAddr) -> String {
    match address.ip() {
        IpAddr::V4(ip) => format!("{ip}:{}", address.port()),
        IpAddr::V6(ip) => format!("[{ip}]:{}", address.port()),
    }
}

/// One SIP or SIPS URI taken apart into what a proxy rewrites.
#[derive(Clone, Debug)]
pub(crate) struct SipUri {
    /// `sip` or `sips`.
    pub(crate) scheme: &'static str,
    /// The userinfo before `@`, as written, or empty.
    pub(crate) userinfo: String,
    /// The host, as written (brackets kept).
    pub(crate) host: String,
    /// The port, when written.
    pub(crate) port: Option<u16>,
    /// Every URI parameter, as written, in order: name and value.
    pub(crate) params: Vec<(String, Option<String>)>,
    /// The `?headers`, as written, without the `?`.
    pub(crate) headers: String,
}

impl SipUri {
    /// Read a SIP or SIPS URI; `None` for anything else.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let uri = SipUriRef::parse_str(text.trim()).ok()?;
        let scheme = if uri.scheme.is_secure() {
            "sips"
        } else {
            "sip"
        };
        let userinfo = match (uri.user, uri.password) {
            (Some(user), Some(password)) => format!("{user}:{password}"),
            (Some(user), None) => user.to_owned(),
            _ => String::new(),
        };
        let params = uri
            .params()
            .map(|(name, value)| (name.to_owned(), value.map(str::to_owned)))
            .collect();
        Some(Self {
            scheme,
            userinfo,
            host: host_text(uri.host),
            port: uri.port,
            params,
            headers: uri.headers_raw().to_owned(),
        })
    }

    /// The address the host and port name, when the host is a literal.
    pub(crate) fn address(&self) -> Option<SocketAddr> {
        let host = self.host.trim_start_matches('[').trim_end_matches(']');
        let ip: IpAddr = host.parse().ok()?;
        Some(SocketAddr::new(ip, self.port.unwrap_or(5060)))
    }

    /// One parameter's value, unescaped (RFC 3261 §19.1.2); `Some("")` for
    /// one written without a value.
    pub(crate) fn param(&self, name: &str) -> Option<String> {
        self.params
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| {
                v.as_deref().map_or_else(String::new, |v| {
                    String::from_utf8_lossy(&unescape(v.as_bytes())).into_owned()
                })
            })
    }

    /// Whether a parameter is present.
    pub(crate) fn has_param(&self, name: &str) -> bool {
        self.params
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(name))
    }

    /// Drop a parameter.
    pub(crate) fn remove_param(&mut self, name: &str) {
        self.params.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
    }

    /// Set a parameter, replacing any with that name, at the end.
    pub(crate) fn set_param(&mut self, name: &str, value: &str) {
        self.remove_param(name);
        self.params.push((name.to_owned(), Some(value.to_owned())));
    }

    /// The URI written out.
    pub(crate) fn render(&self) -> String {
        let mut out = format!("{}:", self.scheme);
        if !self.userinfo.is_empty() {
            out.push_str(&self.userinfo);
            out.push('@');
        }
        out.push_str(&self.host);
        if let Some(port) = self.port {
            let _ = write!(out, ":{port}");
        }
        for (name, value) in &self.params {
            out.push(';');
            out.push_str(name);
            if let Some(value) = value {
                out.push('=');
                out.push_str(value);
            }
        }
        if !self.headers.is_empty() {
            out.push('?');
            out.push_str(&self.headers);
        }
        out
    }

    /// The same URI at another host and port.
    pub(crate) fn moved_to(&self, address: SocketAddr) -> Self {
        let mut moved = self.clone();
        match address.ip() {
            IpAddr::V4(ip) => moved.host = ip.to_string(),
            IpAddr::V6(ip) => moved.host = format!("[{ip}]"),
        }
        moved.port = Some(address.port());
        moved
    }
}

/// Whether two URIs are the same resource by RFC 3261 §19.1.4.
pub(crate) fn equivalent(one: &str, other: &str) -> bool {
    match (Uri::parse_str(one.trim()), Uri::parse_str(other.trim())) {
        (Ok(one), Ok(other)) => one.equivalent(&other),
        _ => false,
    }
}

/// One `Contact` value taken apart: display name, URI, field parameters.
#[derive(Clone, Debug)]
pub(crate) struct ContactValue {
    /// The display name, as written, or empty.
    pub(crate) display: String,
    /// The URI, as written.
    pub(crate) uri: String,
    /// The field's own parameters (`expires`, `+sip.instance`, ...), as
    /// written, each without its leading `;`.
    pub(crate) params: Vec<String>,
}

impl ContactValue {
    /// Read one `Contact` value; `None` for `*` or anything unreadable.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        let parsed = NameAddrRef::parse(value.as_bytes()).ok()?;
        if !matches!(parsed.uri(), UriRef::Sip(_)) {
            return None;
        }
        let uri = String::from_utf8(parsed.uri_bytes().to_vec()).ok()?;
        let display = parsed
            .display_name_raw()
            .map(|raw| String::from_utf8_lossy(raw).trim().to_owned())
            .unwrap_or_default();
        let params = parsed
            .params()
            .map(|(name, value)| {
                let name = String::from_utf8_lossy(name).into_owned();
                match value {
                    Some(value) => format!("{name}={}", String::from_utf8_lossy(value)),
                    None => name,
                }
            })
            .collect();
        Some(Self {
            display,
            uri,
            params,
        })
    }

    /// The value written out, always in the name-addr form.
    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        if !self.display.is_empty() {
            out.push_str(&self.display);
            out.push(' ');
        }
        out.push('<');
        out.push_str(&self.uri);
        out.push('>');
        for param in &self.params {
            out.push(';');
            out.push_str(param);
        }
        out
    }

    /// One field parameter's value, unquoted.
    pub(crate) fn param(&self, name: &str) -> Option<String> {
        self.params.iter().find_map(|param| {
            let (n, v) = param.split_once('=').unwrap_or((param.as_str(), ""));
            n.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().trim_matches('"').to_owned())
        })
    }

    /// Whether a field parameter is present.
    pub(crate) fn has_param(&self, name: &str) -> bool {
        self.param(name).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITE: &str = "INVITE sip:bob@192.0.2.4 SIP/2.0\r\n\
        Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKone, SIP/2.0/UDP 192.0.2.9;branch=z9hG4bKtwo\r\n\
        Max-Forwards: 70\r\n\
        f: \"Alice, A.\" <sip:alice@example.com>;tag=1\r\n\
        t: <sip:bob@example.com>\r\n\
        i: call@1\r\n\
        CSeq: 1 INVITE\r\n\
        m: <sip:alice@192.0.2.1;transport=udp>;expires=60, <sip:alice@198.51.100.7>\r\n\
        Content-Length: 4\r\n\r\nbody";

    #[test]
    fn list_fields_are_split_and_the_length_is_written_from_the_body() {
        let message = Message::parse(INVITE.as_bytes()).expect("parses");
        assert_eq!(message.all("Via").count(), 2);
        assert_eq!(message.all("Contact").count(), 2);
        assert_eq!(message.caller_name().as_deref(), Some("Alice, A."));
        let written = String::from_utf8(message.to_bytes()).expect("utf-8");
        assert!(written.ends_with("Content-Length: 4\r\n\r\nbody"));
        assert!(written.contains("From: \"Alice, A.\" <sip:alice@example.com>;tag=1\r\n"));
        let again = Message::parse(written.as_bytes()).expect("parses again");
        assert_eq!(again.headers, message.headers);
    }

    #[test]
    fn a_response_copies_what_it_must_and_tags_to() {
        let message = Message::parse(INVITE.as_bytes()).expect("parses");
        let answer = message.response(480, "Temporarily Unavailable", "gw1");
        assert_eq!(answer.status(), Some(480));
        assert_eq!(answer.all("Via").count(), 2);
        assert_eq!(answer.first("To"), Some("<sip:bob@example.com>;tag=gw1"));
        assert_eq!(answer.method(), Some("INVITE"));
        assert!(answer.first("Contact").is_none());
    }

    #[test]
    fn received_and_rport_are_stamped() {
        let source: SocketAddr = "203.0.113.5:40000".parse().expect("address");
        let stamped = stamp_received("SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKx;rport", source);
        assert_eq!(
            stamped,
            "SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKx;received=203.0.113.5;rport=40000"
        );
        let via = Via::parse(&stamped).expect("via");
        assert_eq!(via.reply_to, Some(source));
        let plain = stamp_received("SIP/2.0/UDP 203.0.113.5:40000;branch=z9hG4bKy", source);
        assert_eq!(plain, "SIP/2.0/UDP 203.0.113.5:40000;branch=z9hG4bKy");
    }

    #[test]
    fn a_uri_moves_and_keeps_its_parameters() {
        let uri =
            SipUri::parse("sip:alice@10.0.0.2:5062;pn-provider=apns;pn-prid=ab%3Dcd").expect("uri");
        assert_eq!(uri.param("pn-prid").as_deref(), Some("ab=cd"));
        let moved = uri.moved_to("192.0.2.7:5060".parse().expect("address"));
        assert_eq!(
            moved.render(),
            "sip:alice@192.0.2.7:5060;pn-provider=apns;pn-prid=ab%3Dcd"
        );
        assert!(equivalent(
            &moved.render(),
            "sip:alice@192.0.2.7:5060;pn-prid=ab%3dcd;pn-provider=apns"
        ));
    }

    #[test]
    fn a_contact_keeps_its_field_parameters() {
        let contact = ContactValue::parse(
            "\"A\" <sip:alice@10.0.0.2;pn-provider=fcm>;expires=300;+sip.pnsreg;+sip.instance=\"<urn:uuid:1>\"",
        )
        .expect("contact");
        assert_eq!(contact.param("expires").as_deref(), Some("300"));
        assert!(contact.has_param("+sip.pnsreg"));
        assert_eq!(
            contact.render(),
            "\"A\" <sip:alice@10.0.0.2;pn-provider=fcm>;expires=300;+sip.pnsreg;+sip.instance=\"<urn:uuid:1>\""
        );
    }
}
