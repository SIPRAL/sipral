// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A whole session description (RFC 4566 §5).

use core::fmt;
use std::net::IpAddr;

use super::media::{Direction, MediaDescription};

/// RFC 3611 §5.1 `xr-format` token for the VoIP Metrics block (§4.7), the
/// only one this stack uses.
const VOIP_METRICS_XR_FORMAT: &str = "voip-metrics";

/// `o=<username> <sess-id> <sess-version> <nettype> <addrtype> <address>`
/// (§5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    /// The login of whoever wrote it, or `-`.
    pub username: String,
    /// With the address, what makes the description globally unique.
    pub session_id: u64,
    /// Raised whenever the description changes (RFC 3264 §8).
    pub version: u64,
    /// `IN`.
    pub network: String,
    /// `IP4` or `IP6`.
    pub address_type: String,
    /// The host that wrote the description.
    pub address: String,
}

impl Origin {
    /// An origin for one of our addresses. The user name is `-`, which §5.2
    /// allows; the local login is nobody else's business.
    #[must_use]
    pub fn new(session_id: u64, version: u64, address: IpAddr) -> Self {
        Self {
            username: "-".to_owned(),
            session_id,
            version,
            network: "IN".to_owned(),
            address_type: address_type_of(address).to_owned(),
            address: address.to_string(),
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "o={} {} {} {} {} {}\r\n",
            self.username,
            self.session_id,
            self.version,
            self.network,
            self.address_type,
            self.address
        )
    }
}

/// `c=<nettype> <addrtype> <connection-address>` (§5.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connection {
    /// `IN`.
    pub network: String,
    /// `IP4` or `IP6`.
    pub address_type: String,
    /// As written: a multicast address carries TTL and count here, so the text
    /// is kept whole. [`Connection::ip`] reads the address out of it.
    pub address: String,
}

impl Connection {
    /// A connection line for one of our addresses.
    #[must_use]
    pub fn new(address: IpAddr) -> Self {
        Self {
            network: "IN".to_owned(),
            address_type: address_type_of(address).to_owned(),
            address: address.to_string(),
        }
    }

    /// The address, when it is one we can read.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        let address = self.address.split('/').next()?;
        address.parse().ok()
    }

    /// Whether this is the old hold: an address that goes nowhere. RFC 3264
    /// §8.4 replaced it, but older peers still send it.
    #[must_use]
    pub fn is_black_hole(&self) -> bool {
        self.ip().is_some_and(|ip| ip.is_unspecified())
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "c={} {} {}\r\n",
            self.network, self.address_type, self.address
        )
    }
}

/// `t=<start-time> <stop-time>` and the `r=` lines that belong to it (§5.9,
/// §5.10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timing {
    /// NTP seconds, or zero.
    pub start: u64,
    /// NTP seconds, or zero.
    pub stop: u64,
    /// `r=` lines, kept as written.
    pub repeats: Vec<String>,
}

impl Timing {
    /// `t=0 0`: unbounded, which is what a call is.
    #[must_use]
    pub const fn permanent() -> Self {
        Self {
            start: 0,
            stop: 0,
            repeats: Vec::new(),
        }
    }
}

impl fmt::Display for Timing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t={} {}\r\n", self.start, self.stop)?;
        for repeat in &self.repeats {
            write!(f, "r={repeat}\r\n")?;
        }
        Ok(())
    }
}

/// `a=<name>` or `a=<name>:<value>` (§5.13).
#[derive(Clone, PartialEq, Eq)]
pub struct Attribute {
    /// The part before the colon.
    pub name: String,
    /// The part after it, when there is one.
    pub value: Option<String>,
}

impl fmt::Debug for Attribute {
    /// Everything as read, except the master key of `a=crypto` and the
    /// password of `a=ice-pwd`, which must never reach a log (RFC 4568 §9.2).
    ///
    /// Done here rather than on the descriptions, so no caller can forget it.
    /// An `a=crypto` keeps its tag and suite, which are not secret and help
    /// debugging. An `a=ice-pwd` is only the password (RFC 8839 §5.4), the
    /// credential that signs every connectivity check (RFC 8445 §7.1.2.3).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut shown = f.debug_struct("Attribute");
        shown.field("name", &self.name);
        match self.value.as_deref() {
            Some(value) if self.name == "crypto" => {
                let named: Vec<&str> = value.split_ascii_whitespace().take(2).collect();
                shown.field("value", &Some(format!("{} <redacted>", named.join(" "))))
            }
            Some(_) if self.name == "ice-pwd" => shown.field("value", &Some("<redacted>")),
            other => shown.field("value", &other),
        }
        .finish()
    }
}

/// The value of a `k=` line (§5.12), kept as read and never printed.
///
/// The line is deprecated and unused here, but a parsed description keeps
/// every line, and this one is the peer's key. `Display` writes it (wire
/// format); `Debug` does not.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyLine(String);

impl KeyLine {
    /// Take a `k=` value as it was written.
    #[must_use]
    pub fn new(value: &str) -> Self {
        Self(value.to_owned())
    }

    /// The value, for a caller that has decided it needs it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for KeyLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyLine(<redacted>)")
    }
}

impl Attribute {
    /// `a=<name>`, an attribute that is true by being there.
    #[must_use]
    pub fn flag(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            value: None,
        }
    }

    /// `a=<name>:<value>`.
    #[must_use]
    pub fn with_value(name: &str, value: &str) -> Self {
        Self {
            name: name.to_owned(),
            value: Some(value.to_owned()),
        }
    }

    /// The direction attribute, when this is one.
    #[must_use]
    pub fn direction(&self) -> Option<Direction> {
        self.value
            .is_none()
            .then(|| Direction::from_name(&self.name))?
    }

    /// Whether this is an `a=rtcp-xr` line (RFC 3611 §5.1) listing the bare
    /// token `format`. Whole tokens only, so `name=value` tokens never match.
    #[must_use]
    pub fn requests_xr_format(&self, format: &str) -> bool {
        self.name == "rtcp-xr"
            && self
                .value
                .as_deref()
                .is_some_and(|value| value.split_whitespace().any(|token| token == format))
    }
}

impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            Some(value) => write!(f, "a={}:{value}\r\n", self.name),
            None => write!(f, "a={}\r\n", self.name),
        }
    }
}

/// A session description.
///
/// Fields follow §5's line order and are written in it, so output is
/// deterministic. Unused lines are kept and round-trip unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionDescription {
    /// `o=`
    pub origin: Origin,
    /// `s=`, which §5.3 says "MUST NOT be empty"; `-` when there is nothing.
    pub name: String,
    /// `i=`
    pub information: Option<String>,
    /// `u=`
    pub uri: Option<String>,
    /// `e=`
    pub contacts: Vec<String>,
    /// `p=`
    pub phones: Vec<String>,
    /// `c=` at session level, which each stream may override.
    pub connection: Option<Connection>,
    /// `b=`
    pub bandwidth: Vec<String>,
    /// `t=`, at least one.
    pub timing: Vec<Timing>,
    /// `z=`
    pub timezones: Option<String>,
    /// `k=`
    pub key: Option<KeyLine>,
    /// `a=` at session level.
    pub attributes: Vec<Attribute>,
    /// The `m=` blocks in written order, which an answer keeps (RFC 3264 §6).
    pub media: Vec<MediaDescription>,
}

impl SessionDescription {
    /// A description with one permanent time and nothing else said.
    #[must_use]
    pub fn new(origin: Origin, connection: Connection) -> Self {
        Self {
            origin,
            name: "-".to_owned(),
            information: None,
            uri: None,
            contacts: Vec::new(),
            phones: Vec::new(),
            connection: Some(connection),
            bandwidth: Vec::new(),
            timing: vec![Timing::permanent()],
            timezones: None,
            key: None,
            attributes: Vec::new(),
            media: Vec::new(),
        }
    }

    /// The first attribute of that name at session level.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.name == name)
    }

    /// The direction written at session level, if one is.
    #[must_use]
    pub fn direction(&self) -> Option<Direction> {
        self.attributes.iter().find_map(Attribute::direction)
    }

    /// The direction for one stream: its own, else the session's, else
    /// `sendrecv` (RFC 3264 §6.1).
    #[must_use]
    pub fn direction_of(&self, media: &MediaDescription) -> Direction {
        media
            .direction()
            .or_else(|| self.direction())
            .unwrap_or(Direction::SendRecv)
    }

    /// Where one stream's media goes: its own `c=` if it has one, else the
    /// session's (§5.7).
    #[must_use]
    pub fn connection_of<'a>(&'a self, media: &'a MediaDescription) -> Option<&'a Connection> {
        media.connection.as_ref().or(self.connection.as_ref())
    }

    /// Whether one stream asks for the RFC 3611 `voip-metrics` XR block. A
    /// media-level `a=rtcp-xr` replaces the session one (§5.1), whatever it lists.
    #[must_use]
    pub fn wants_voip_metrics_xr(&self, media: &MediaDescription) -> bool {
        media.attribute("rtcp-xr").map_or_else(
            || {
                self.attributes
                    .iter()
                    .any(|a| a.requests_xr_format(VOIP_METRICS_XR_FORMAT))
            },
            |a| a.requests_xr_format(VOIP_METRICS_XR_FORMAT),
        )
    }

    /// The bytes, ready to go into a message body.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_string().into_bytes()
    }
}

impl fmt::Display for SessionDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("v=0\r\n")?;
        write!(f, "{}", self.origin)?;
        write!(f, "s={}\r\n", self.name)?;
        if let Some(information) = &self.information {
            write!(f, "i={information}\r\n")?;
        }
        if let Some(uri) = &self.uri {
            write!(f, "u={uri}\r\n")?;
        }
        for contact in &self.contacts {
            write!(f, "e={contact}\r\n")?;
        }
        for phone in &self.phones {
            write!(f, "p={phone}\r\n")?;
        }
        if let Some(connection) = &self.connection {
            write!(f, "{connection}")?;
        }
        for bandwidth in &self.bandwidth {
            write!(f, "b={bandwidth}\r\n")?;
        }
        for timing in &self.timing {
            write!(f, "{timing}")?;
        }
        if let Some(timezones) = &self.timezones {
            write!(f, "z={timezones}\r\n")?;
        }
        if let Some(key) = &self.key {
            write!(f, "k={key}\r\n")?;
        }
        for attribute in &self.attributes {
            write!(f, "{attribute}")?;
        }
        for media in &self.media {
            write!(f, "{media}")?;
        }
        Ok(())
    }
}

fn address_type_of(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "IP4",
        IpAddr::V6(_) => "IP6",
    }
}

#[cfg(test)]
mod tests {
    use super::Attribute;

    /// A key that would open the media if logged, in RFC 4568 §9.1 form.
    const KEY: &str =
        "1 AES_CM_128_HMAC_SHA1_80 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:32";

    /// RFC 8839 §5.4 gives the password 22 to 256 characters of `ice-char`.
    const PWD: &str = "asd88fgpdd777uzjYhagZg";

    #[test]
    fn an_inline_key_does_not_reach_a_log() {
        let printed = format!("{:?}", Attribute::with_value("crypto", KEY));
        assert!(
            !printed.contains("PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR"),
            "{printed}"
        );
        assert!(printed.contains("<redacted>"), "{printed}");
    }

    #[test]
    fn what_an_inline_key_keeps_is_what_a_reader_needs() {
        let printed = format!("{:?}", Attribute::with_value("crypto", KEY));
        assert!(printed.contains('1'), "{printed}");
        assert!(printed.contains("AES_CM_128_HMAC_SHA1_80"), "{printed}");
    }

    #[test]
    fn an_ice_password_does_not_reach_a_log() {
        let printed = format!("{:?}", Attribute::with_value("ice-pwd", PWD));
        assert!(!printed.contains(PWD), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
    }

    /// A username fragment is not secret: it is on every check on the wire.
    #[test]
    fn a_username_fragment_is_not_a_secret_and_stays() {
        let printed = format!("{:?}", Attribute::with_value("ice-ufrag", "8hhY"));
        assert!(printed.contains("8hhY"), "{printed}");
    }

    /// Redaction goes by name, at either level: RFC 8839 §5.4 allows
    /// `a=ice-pwd` at session level.
    #[test]
    fn an_ordinary_attribute_is_printed_as_it_was_read() {
        let printed = format!("{:?}", Attribute::with_value("rtpmap", "0 PCMU/8000"));
        assert!(printed.contains("0 PCMU/8000"), "{printed}");
    }
}
