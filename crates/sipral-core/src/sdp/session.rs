// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A whole session description (RFC 4566 §5).

use core::fmt;
use std::net::IpAddr;

use super::media::{Direction, MediaDescription};

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute {
    /// The part before the colon.
    pub name: String,
    /// The part after it, when there is one.
    pub value: Option<String>,
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
    pub key: Option<String>,
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
