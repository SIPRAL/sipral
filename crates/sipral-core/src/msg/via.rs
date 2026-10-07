// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! `Via`, the field that decides where a response goes.
//!
//! RFC 3261 §25.1:
//!
//! ```text
//! via-parm      =  sent-protocol LWS sent-by *( SEMI via-params )
//! sent-protocol =  protocol-name SLASH protocol-version SLASH transport
//! sent-by       =  host [ COLON port ]
//! via-received  =  "received" EQUAL (IPv4address / IPv6address)
//! ttl           =  1*3DIGIT ; 0 to 255
//! ```
//!
//! `SLASH` and `COLON` allow whitespace around them (`SIP / 2.0 / UDP h : 5060`
//! is legal). `via-received` is a bare IP, so IPv6 comes without brackets.
//! `ttl` is `1*3DIGIT`, so `;ttl=1234` is no ttl at all. The `branch` MUSTs of
//! §8.1.1.7 bind the writer: a Via without a branch or cookie is an RFC 2543
//! peer (§17.2.3), not a malformed header.

use core::fmt;
use std::borrow::Cow;
use std::net::IpAddr;

use super::error::HeaderError;
use super::lex::{Params, trim};
use super::uri::{HostRef, parse_hostport};

/// Whether the sender asked for, or was told, a port to answer on (RFC 3581).
///
/// ```text
/// response-port = "rport" [EQUAL 1*DIGIT]
/// ```
///
/// `;rport` asks, `;rport=5060` answers, `;rport=` is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rport {
    /// No `rport` parameter.
    Absent,
    /// `;rport`, asking the far end to fill it in.
    Requested,
    /// `;rport=n`, filled in.
    Given(u16),
}

/// One `Via` value, borrowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViaRef<'a> {
    /// `SIP`, normally. `protocol-name = "SIP" / token`, so not always.
    pub protocol_name: &'a str,
    /// `2.0`, normally. The grammar says `token`, with no special case for it.
    pub protocol_version: &'a str,
    /// `UDP`, `TCP`, `TLS`, `SCTP`, or any token (RFC 4475 `transports`).
    pub transport: &'a str,
    /// Where the sender wants the response.
    pub host: HostRef<'a>,
    /// The port, if one was written. Absent means 5060, or 5061 for TLS.
    pub port: Option<u16>,
    raw: &'a [u8],
}

/// The magic cookie every RFC 3261 branch starts with (§8.1.1.7).
pub const MAGIC_COOKIE: &[u8] = b"z9hG4bK";

impl<'a> ViaRef<'a> {
    /// Read one `Via` value. Split a header line into values with
    /// [`super::CommaList`] first.
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] on a grammar mismatch,
    /// [`HeaderError::NotUtf8`] when the protocol or host is not text.
    pub fn parse(value: &'a [u8]) -> Result<Self, HeaderError> {
        let (head, _) = Params::split(value);

        // the SLASHes first: whitespace may surround them
        let first = head
            .iter()
            .position(|&b| b == b'/')
            .ok_or(HeaderError::Malformed("Via has no sent-protocol"))?;
        let rest = head
            .get(first + 1..)
            .ok_or(HeaderError::Malformed("Via has no sent-protocol"))?;
        let second = rest
            .iter()
            .position(|&b| b == b'/')
            .ok_or(HeaderError::Malformed("Via has no transport"))?;

        let protocol_name = as_str(trim(head.get(..first).unwrap_or_default()))?;
        let protocol_version = as_str(trim(rest.get(..second).unwrap_or_default()))?;
        let tail = rest.get(second + 1..).unwrap_or_default();

        // the transport, then the sent-by, which may have whitespace around ':'
        let is_ws = |b: u8| matches!(b, b' ' | b'\t' | b'\r' | b'\n');
        let start = tail
            .iter()
            .position(|&b| !is_ws(b))
            .ok_or(HeaderError::Malformed("Via has no transport"))?;
        let t = tail.get(start..).unwrap_or_default();
        let end = t.iter().position(|&b| is_ws(b)).unwrap_or(t.len());
        let transport = as_str(t.get(..end).unwrap_or_default())?;
        let sent_by = trim(t.get(end..).unwrap_or_default());

        if protocol_name.is_empty() || protocol_version.is_empty() || transport.is_empty() {
            return Err(HeaderError::Malformed("Via sent-protocol is incomplete"));
        }
        if sent_by.is_empty() {
            return Err(HeaderError::Malformed("Via has no sent-by"));
        }
        let (host, port) =
            parse_hostport(as_str(sent_by)?).map_err(|_| HeaderError::Malformed("Via sent-by"))?;

        Ok(Self {
            protocol_name,
            protocol_version,
            transport,
            host,
            port,
            raw: value,
        })
    }

    /// The `branch` parameter, if any. RFC 2543 peers send none (§17.2.3).
    #[must_use]
    pub fn branch(&self) -> Option<Cow<'a, [u8]>> {
        self.params().get("branch")
    }

    /// Whether the branch carries the RFC 3261 magic cookie. Case-sensitive:
    /// §8.1.1.7 gives the characters literally.
    #[must_use]
    pub fn has_magic_cookie(&self) -> bool {
        self.branch().is_some_and(|b| b.starts_with(MAGIC_COOKIE))
    }

    /// The `received` parameter (RFC 3261 §18.2.1).
    ///
    /// The grammar wants a bare IPv6 address; brackets are accepted since
    /// peers send them.
    #[must_use]
    pub fn received(&self) -> Option<IpAddr> {
        let v = self.params().get("received")?;
        let s = core::str::from_utf8(&v).ok()?;
        let s = s
            .strip_prefix('[')
            .and_then(|r| r.strip_suffix(']'))
            .unwrap_or(s);
        s.parse().ok()
    }

    /// The `rport` parameter (RFC 3581).
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] for `;rport=` with no value, or a port that is
    /// not a number.
    pub fn rport(&self) -> Result<Rport, HeaderError> {
        let mut found = None;
        for (name, value) in self.params() {
            if name.eq_ignore_ascii_case(b"rport") {
                found = Some(value);
            }
        }
        match found {
            None => Ok(Rport::Absent),
            Some(None) => Ok(Rport::Requested),
            Some(Some(v)) => {
                let v = trim(v);
                if v.is_empty() || !v.iter().all(u8::is_ascii_digit) {
                    return Err(HeaderError::Malformed("rport is not a port"));
                }
                core::str::from_utf8(v)
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .map(Rport::Given)
                    .ok_or(HeaderError::Malformed("rport does not fit"))
            }
        }
    }

    /// The `ttl` parameter, for a request sent to a multicast address.
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] when not `1*3DIGIT`.
    pub fn ttl(&self) -> Result<Option<u8>, HeaderError> {
        let Some(v) = self.params().get("ttl") else {
            return Ok(None);
        };
        let v = trim(&v);
        if v.is_empty() || v.len() > 3 || !v.iter().all(u8::is_ascii_digit) {
            return Err(HeaderError::Malformed("ttl is 1*3DIGIT"));
        }
        let n = v.iter().fold(0_u16, |a, &d| a * 10 + u16::from(d - b'0'));
        u8::try_from(n)
            .map(Some)
            .map_err(|_| HeaderError::Malformed("ttl is 0 to 255"))
    }

    /// The `maddr` parameter.
    #[must_use]
    pub fn maddr(&self) -> Option<Cow<'a, [u8]>> {
        self.params().get("maddr")
    }

    /// Every parameter, in the order written.
    #[must_use]
    pub fn params(&self) -> Params<'a> {
        Params::split(self.raw).1
    }
}

impl fmt::Display for ViaRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{} ",
            self.protocol_name, self.protocol_version, self.transport
        )?;
        match self.host {
            HostRef::Name(n) => f.write_str(n)?,
            HostRef::Ipv4(a) => write!(f, "{a}")?,
            HostRef::Ipv6(a) => write!(f, "[{a}]")?,
        }
        if let Some(p) = self.port {
            write!(f, ":{p}")?;
        }
        for (name, value) in self.params() {
            f.write_str(";")?;
            f.write_str(&String::from_utf8_lossy(name))?;
            if let Some(v) = value {
                write!(f, "={}", String::from_utf8_lossy(v))?;
            }
        }
        Ok(())
    }
}

fn as_str(v: &[u8]) -> Result<&str, HeaderError> {
    core::str::from_utf8(v).map_err(|_| HeaderError::NotUtf8)
}

#[cfg(test)]
mod tests {
    use super::{MAGIC_COOKIE, Rport, ViaRef};
    use crate::msg::{CommaList, HeaderError, HostRef};
    use std::net::Ipv4Addr;

    fn via(v: &[u8]) -> ViaRef<'_> {
        ViaRef::parse(v).expect("a Via")
    }

    #[test]
    fn a_plain_via() {
        let v = via(b"SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnashds8");
        assert_eq!(v.protocol_name, "SIP");
        assert_eq!(v.protocol_version, "2.0");
        assert_eq!(v.transport, "UDP");
        assert_eq!(v.host, HostRef::Ipv4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(v.port, Some(5060));
        assert_eq!(v.branch().as_deref(), Some(&b"z9hG4bKnashds8"[..]));
        assert!(v.has_magic_cookie());
    }

    #[test]
    fn whitespace_may_sit_around_the_slashes_and_the_colon() {
        // SLASH = SWS "/" SWS, COLON = SWS ":" SWS
        let v = via(b"SIP / 2.0 / UDP  host.example.com : 5060 ;branch=z9hG4bK1");
        assert_eq!(v.protocol_name, "SIP");
        assert_eq!(v.protocol_version, "2.0");
        assert_eq!(v.transport, "UDP");
        assert_eq!(v.host, HostRef::Name("host.example.com"));
        assert_eq!(v.port, Some(5060));
        assert_eq!(v.branch().as_deref(), Some(&b"z9hG4bK1"[..]));
    }

    #[test]
    fn a_fold_inside_the_value_is_just_more_whitespace() {
        let v = via(b"SIP/2.0/UDP\r\n  host.example.com;branch=z9hG4bK2");
        assert_eq!(v.transport, "UDP");
        assert_eq!(v.host, HostRef::Name("host.example.com"));
    }

    #[test]
    fn the_transport_is_an_open_set() {
        // RFC 4475 3.1.1.10 transports: other-transport = token
        assert_eq!(via(b"SIP/2.0/UDP host").transport, "UDP");
        assert_eq!(via(b"SIP/2.0/TLS host").transport, "TLS");
        assert_eq!(via(b"SIP/2.0/SCTP host").transport, "SCTP");
        assert_eq!(
            via(b"SIP/2.0/UNKNOWNTRANSPORT host").transport,
            "UNKNOWNTRANSPORT"
        );
        assert_eq!(via(b"SIP/7.0/UDP host").protocol_version, "7.0");
        assert_eq!(via(b"OTHER/2.0/UDP host").protocol_name, "OTHER");
    }

    #[test]
    fn an_ipv6_sent_by_is_bracketed_but_received_is_not() {
        let v = via(b"SIP/2.0/UDP [2001:db8::1]:5060;received=2001:db8::2");
        assert!(matches!(v.host, HostRef::Ipv6(_)));
        assert_eq!(v.port, Some(5060));
        assert_eq!(v.received(), Some("2001:db8::2".parse().expect("ip")));
    }

    #[test]
    fn a_bracketed_received_is_accepted_anyway_because_it_is_sent() {
        let v = via(b"SIP/2.0/UDP host;received=[2001:db8::2]");
        assert_eq!(v.received(), Some("2001:db8::2".parse().expect("ip")));
    }

    #[test]
    fn received_carries_an_ipv4_address_too() {
        let v = via(b"SIP/2.0/UDP bobspc.biloxi.com:5060;received=192.0.2.4");
        assert_eq!(v.received(), Some("192.0.2.4".parse().expect("ip")));
    }

    #[test]
    fn rport_has_three_states_and_an_empty_one_is_refused() {
        assert_eq!(via(b"SIP/2.0/UDP h").rport(), Ok(Rport::Absent));
        assert_eq!(via(b"SIP/2.0/UDP h;rport").rport(), Ok(Rport::Requested));
        assert_eq!(
            via(b"SIP/2.0/UDP h;rport=5060").rport(),
            Ok(Rport::Given(5060))
        );
        assert!(matches!(
            via(b"SIP/2.0/UDP h;rport=").rport(),
            Err(HeaderError::Malformed(_))
        ));
        assert!(matches!(
            via(b"SIP/2.0/UDP h;rport=abc").rport(),
            Err(HeaderError::Malformed(_))
        ));
    }

    #[test]
    fn ttl_is_three_digits_at_most() {
        assert_eq!(via(b"SIP/2.0/UDP h;ttl=1").ttl(), Ok(Some(1)));
        assert_eq!(via(b"SIP/2.0/UDP h;ttl=255").ttl(), Ok(Some(255)));
        assert_eq!(via(b"SIP/2.0/UDP h").ttl(), Ok(None));
        // four digits is not an out-of-range ttl, it is not a ttl
        assert!(matches!(
            via(b"SIP/2.0/UDP h;ttl=1234").ttl(),
            Err(HeaderError::Malformed(_))
        ));
        assert!(matches!(
            via(b"SIP/2.0/UDP h;ttl=256").ttl(),
            Err(HeaderError::Malformed(_))
        ));
    }

    #[test]
    fn a_via_with_no_branch_is_an_old_peer_not_a_bad_header() {
        // RFC 3261 17.2.3 says how to match these; refusing them loses calls
        let v = via(b"SIP/2.0/UDP host.example.com");
        assert_eq!(v.branch(), None);
        assert!(!v.has_magic_cookie());
    }

    #[test]
    fn a_branch_that_is_only_the_cookie_is_syntactically_fine() {
        // RFC 4475 3.1.2.1 badbranch: just the cookie; uniqueness is not checked here
        let v = via(b"SIP/2.0/UDP host;branch=z9hG4bK");
        assert_eq!(v.branch().as_deref(), Some(MAGIC_COOKIE));
        assert!(v.has_magic_cookie());
    }

    #[test]
    fn a_quoted_extension_parameter_keeps_its_commas() {
        let line = br#"SIP/2.0/UDP a;x="1,2";branch=z9hG4bK1, SIP/2.0/TCP b;branch=z9hG4bK2"#;
        let values: Vec<_> = CommaList::new(line).collect();
        assert_eq!(values.len(), 2);
        let v = via(values.first().copied().expect("first"));
        assert_eq!(v.params().get("x").as_deref(), Some(&b"1,2"[..]));
        assert_eq!(v.branch().as_deref(), Some(&b"z9hG4bK1"[..]));
    }

    #[test]
    fn several_via_values_on_one_line_keep_their_order() {
        let line = b"SIP/2.0/UDP first;branch=z9hG4bK1, SIP/2.0/TCP second;branch=z9hG4bK2";
        let hosts: Vec<_> = CommaList::new(line).map(|v| via(v).host).collect();
        assert_eq!(hosts, vec![HostRef::Name("first"), HostRef::Name("second")]);
    }

    #[test]
    fn a_malformed_via_is_refused() {
        assert!(ViaRef::parse(b"").is_err());
        assert!(ViaRef::parse(b"SIP/2.0/UDP").is_err());
        assert!(ViaRef::parse(b"SIP/2.0 host").is_err());
        assert!(ViaRef::parse(b"host").is_err());
        assert!(ViaRef::parse(b"SIP/2.0/UDP h:99999").is_err());
    }

    #[test]
    fn display_round_trips_the_pieces() {
        let v = via(b"SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1;rport");
        assert_eq!(
            v.to_string(),
            "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1;rport"
        );
    }

    #[test]
    fn nothing_makes_the_via_parser_panic() {
        for len in 0..14_usize {
            for seed in 0..80_u8 {
                let v: Vec<u8> = (0..len)
                    .map(|i| {
                        let b = seed
                            .wrapping_mul(23)
                            .wrapping_add(u8::try_from(i).unwrap_or(0));
                        match b % 7 {
                            0 => b'/',
                            1 => b';',
                            2 => b' ',
                            3 => b':',
                            4 => b'=',
                            5 => b'[',
                            _ => b,
                        }
                    })
                    .collect();
                if let Ok(parsed) = ViaRef::parse(&v) {
                    let _ = parsed.branch();
                    let _ = parsed.received();
                    let _ = parsed.rport();
                    let _ = parsed.ttl();
                }
            }
        }
    }
}
