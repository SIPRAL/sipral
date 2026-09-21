// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A whole session description (RFC 4566 §5).

use core::fmt;
use std::net::IpAddr;

use super::media::{Direction, MediaDescription};

/// RFC 3611 §5.1's `xr-format` token for the VoIP Metrics Report Block
/// (§4.7): `"voip-metrics"`, the only one this stack ever writes or reads
/// out of an `a=rtcp-xr` line.
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
    /// An origin for one of our addresses.
    ///
    /// The user name is `-`, which §5.2 allows when "the originating host does
    /// not support the concept of user IDs" — and which is the only sane thing
    /// for a softphone to write, since whoever is logged in to this machine is
    /// nobody else's business.
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
    /// As written. A multicast address carries its TTL and count here, and
    /// dropping them would change the line's meaning, so the text is kept
    /// whole and [`Connection::ip`] reads the address out of it.
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

    /// Whether this is the old way of putting a call on hold: an address that
    /// goes nowhere.
    ///
    /// RFC 3264 §8.4 replaced it with `a=sendonly` and `a=inactive`, but a
    /// peer that predates that convention still says it this way, and a stack
    /// that does not recognise it will send audio into the dark.
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
    /// `t=0 0`: "the session is not bounded, though it will not become active
    /// until after the `<start-time>`" — which is what a call is.
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
    /// Everything as it was read, except the two things an attribute can
    /// carry that must never reach a log: the master key on an `a=crypto`
    /// line, and the password on an `a=ice-pwd` one.
    ///
    /// Written here rather than on the descriptions above it because there is
    /// no way to hold one of those without holding these: a redaction on
    /// `SessionDescription` is one a user agent, a call, an engine and an
    /// event each have to remember to route through, and the first one that
    /// forgets prints every key on the machine. RFC 4568 §9.2 is explicit —
    /// "the SDP MUST be protected" — and a `{:?}` on a live stack is not
    /// protection.
    ///
    /// The two are redacted differently because they are shaped differently.
    /// An `a=crypto` line names a tag and a suite before its key, and both are
    /// what a reader needs when a negotiation has gone wrong; neither is
    /// secret, so both stay. An `a=ice-pwd` line is the password and nothing
    /// else (RFC 8839 §5.4), so there is nothing in it to keep. It is the
    /// short-term credential every connectivity check on the call is signed
    /// with (RFC 8445 §7.1.2.3): a reader who has it can answer checks as
    /// either end and can steer the media to itself, which is the whole of
    /// what ICE decides.
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

/// The value of a `k=` line (§5.12), kept as it was read and never printed.
///
/// The line is deprecated — §5.12 says so itself, and this stack neither
/// writes one nor reads any meaning from one — but a description parsed from a
/// peer keeps every line it arrived with, and this one is by definition the
/// peer's key. `Display` writes it, because that is the wire format and the
/// wire format is what it came from; `Debug` does not, because a log is not
/// the wire.
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

    /// Whether this is an `a=rtcp-xr` line (RFC 3611 §5.1) that lists
    /// `format` among its space-separated `xr-format` tokens — `format`
    /// bare, such as `"voip-metrics"`, never one of the tokens that takes
    /// its own `=` argument (`"rcvr-rtt"`, `"stat-summary"`, ...), which
    /// this never matches since it compares whole tokens.
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
/// The fields are in the order §5 puts the lines in, and writing one out walks
/// them in that order, so the same description always produces the same bytes.
/// Everything that was read is kept, including the lines this stack has no use
/// for: a description that is parsed and written back comes out as it went in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionDescription {
    /// `o=`
    pub origin: Origin,
    /// `s=`, which §5.3 says "MUST NOT be empty"; `-` when there is nothing
    /// to say.
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
    /// The `m=` blocks, in the order they were written — which is the order
    /// an answer has to keep (RFC 3264 §6).
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

    /// The direction that applies to one stream: the stream's own, else the
    /// session's, else `sendrecv` — "if there is no direction attribute at the
    /// media or session level ... the stream is sendrecv by default"
    /// (RFC 3264 §6.1).
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

    /// Whether this description asks for the RFC 3611 `voip-metrics` XR
    /// block on one stream: RFC 3611 §5.1, "It is both a session and a
    /// media level attribute ... Any media level specification MUST
    /// replace a session level specification, if one is present, for
    /// that media block" — so a stream with its own `a=rtcp-xr` line
    /// (whatever it lists) never falls back to the session's.
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
        // "v=0", and the order below is the one §5 fixes
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

    /// A key that would open the media if it reached a log, written the way
    /// RFC 4568 §9.1 writes one.
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

    /// The tag and the suite are what a reader needs when a negotiation has
    /// gone wrong, and neither is secret.
    #[test]
    fn what_an_inline_key_keeps_is_what_a_reader_needs() {
        let printed = format!("{:?}", Attribute::with_value("crypto", KEY));
        assert!(printed.contains('1'), "{printed}");
        assert!(printed.contains("AES_CM_128_HMAC_SHA1_80"), "{printed}");
    }

    /// The short-term credential every connectivity check on the call is
    /// signed with. A reader who has it can answer checks as either end.
    #[test]
    fn an_ice_password_does_not_reach_a_log() {
        let printed = format!("{:?}", Attribute::with_value("ice-pwd", PWD));
        assert!(!printed.contains(PWD), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
    }

    /// Only the password. A username fragment is carried in every check on
    /// the wire and is how a reader tells one session's checks from another's.
    #[test]
    fn a_username_fragment_is_not_a_secret_and_stays() {
        let printed = format!("{:?}", Attribute::with_value("ice-ufrag", "8hhY"));
        assert!(printed.contains("8hhY"), "{printed}");
    }

    /// The redaction is on the name, so a description a peer sent is covered
    /// as surely as one this stack wrote, and at whichever level it sits:
    /// RFC 8839 §5.4 allows `a=ice-pwd` at the session level too.
    #[test]
    fn an_ordinary_attribute_is_printed_as_it_was_read() {
        let printed = format!("{:?}", Attribute::with_value("rtpmap", "0 PCMU/8000"));
        assert!(printed.contains("0 PCMU/8000"), "{printed}");
    }
}
