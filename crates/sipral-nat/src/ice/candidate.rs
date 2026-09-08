// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Host candidates: the only kind a lite agent ever gathers or reads
//! (RFC 8445 §5.2, RFC 8839 §5.1).
//!
//! A candidate here is either something this agent generated from a socket it
//! owns, or something read out of the peer's `a=candidate` line. Neither path
//! resolves a name, opens a socket or chooses between addresses: gathering
//! takes the addresses the caller already bound to, one per family per
//! component, and parsing keeps whatever the peer wrote, including the types
//! this agent will never itself produce.

use core::fmt;
use core::fmt::Write as _;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

use sipral_core::sdp::Attribute;

/// The one transport this stack's candidates ever use.
const TRANSPORT: &str = "UDP";

/// `(2^24) * type preference`, with the type preference RFC 8445 §5.2
/// recommends for a lite agent's host candidates.
const TYPE_PREFERENCE_HOST: u32 = 126;

/// A data-stream component: 1 for RTP, 2 for RTCP when it is not multiplexed
/// onto the RTP port (RFC 8445 §4, RFC 8839 §5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComponentId(u16);

impl ComponentId {
    /// RTCP's own component, when it does not share a port with RTP.
    pub const RTCP: Self = Self(2);
    /// RTP's component, and the only one a muxed stream needs.
    pub const RTP: Self = Self(1);

    /// The component with this number, if it falls in the range the grammar
    /// allows: `1*3DIGIT`, 1 to 256 inclusive (RFC 8839 §5.1).
    #[must_use]
    pub const fn new(id: u16) -> Option<Self> {
        if id == 0 || id > 256 {
            return None;
        }
        Some(Self(id))
    }

    /// The number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl fmt::Display for ComponentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A candidate's foundation: equal for two candidates from the same base
/// address, different otherwise (RFC 8445 §4, §5.1.1.3).
///
/// This agent numbers its own; a foundation read from the peer is kept as the
/// opaque string it arrived as, since nothing here compares it to anything.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Foundation(String);

impl Foundation {
    fn numbered(n: u32) -> Self {
        Self(n.to_string())
    }

    /// Read a foundation token: 1 to 32 of `ALPHA / DIGIT / "+" / "/"`
    /// (RFC 8839 §5.1, `ice-char`).
    fn parse(token: &str) -> Option<Self> {
        if token.is_empty() || token.len() > 32 {
            return None;
        }
        if !token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
        {
            return None;
        }
        Some(Self(token.to_owned()))
    }
}

impl fmt::Display for Foundation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What kind of transport address a candidate names (RFC 8839 §5.1,
/// `candidate-types`).
///
/// A lite agent generates `Host` only. The other three exist here so a
/// server-reflexive or relayed line from a full peer still parses; this agent
/// never acts on the difference, since it never chooses among candidates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateType {
    /// Bound directly to a local address.
    Host,
    /// Learned from a STUN server.
    ServerReflexive,
    /// Learned from a connectivity check, never gathered up front.
    PeerReflexive,
    /// Allocated on a TURN server.
    Relay,
}

impl CandidateType {
    const fn token(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::ServerReflexive => "srflx",
            Self::PeerReflexive => "prflx",
            Self::Relay => "relay",
        }
    }

    fn parse(token: &str) -> Option<Self> {
        Some(match token {
            "host" => Self::Host,
            "srflx" => Self::ServerReflexive,
            "prflx" => Self::PeerReflexive,
            "relay" => Self::Relay,
            // an extension type (RFC 8839 §5.1 allows `token` here); this
            // agent has no use for a candidate it cannot act on
            _ => return None,
        })
    }
}

impl fmt::Display for CandidateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// One `a=candidate` line, generated or parsed (RFC 8839 §5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// Shared by every candidate this agent gathered from the same address.
    pub foundation: Foundation,
    /// Which piece of the data stream this reaches.
    pub component: ComponentId,
    /// Higher wins. RFC 8445 §5.1.2.1.
    pub priority: u32,
    /// Where it listens.
    pub address: SocketAddr,
    /// Host, unless this came from a peer that gathers more.
    pub kind: CandidateType,
    /// The base a reflexive or relayed candidate was learned from. Always
    /// absent on a host candidate, which is its own base.
    pub related: Option<SocketAddr>,
}

impl Candidate {
    /// This candidate as an `a=candidate` attribute (RFC 8839 §5.1).
    #[must_use]
    pub fn to_attribute(&self) -> Attribute {
        let mut value = format!(
            "{} {} {TRANSPORT} {} {} {} typ {}",
            self.foundation,
            self.component,
            self.priority,
            self.address.ip(),
            self.address.port(),
            self.kind
        );
        if let Some(related) = self.related {
            let _ = write!(value, " raddr {} rport {}", related.ip(), related.port());
        }
        Attribute::with_value("candidate", &value)
    }

    /// Read the value of an `a=candidate` line (everything after the colon).
    ///
    /// A line this agent cannot use — a name instead of an address (RFC 8839
    /// §5.1 requires ignoring those), a transport other than UDP, a type this
    /// agent does not know — comes back `None` rather than an error: the peer
    /// is entitled to offer candidates in forms a lite agent has no use for,
    /// and one bad line should not cost the whole exchange.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let mut tokens = value.split_whitespace();
        let foundation = Foundation::parse(tokens.next()?)?;
        let component = ComponentId::new(tokens.next()?.parse().ok()?)?;
        if !tokens.next()?.eq_ignore_ascii_case(TRANSPORT) {
            return None;
        }
        let priority: u32 = tokens.next()?.parse().ok()?;
        if priority == 0 {
            return None;
        }
        let ip: IpAddr = tokens.next()?.parse().ok()?;
        let port: u16 = tokens.next()?.parse().ok()?;
        if tokens.next()? != "typ" {
            return None;
        }
        let kind = CandidateType::parse(tokens.next()?)?;

        let mut related = None;
        let mut lookahead = tokens.clone();
        if lookahead.next() == Some("raddr")
            && let Some(rip) = lookahead.next().and_then(|t| t.parse::<IpAddr>().ok())
            && lookahead.next() == Some("rport")
            && let Some(rport) = lookahead.next().and_then(|t| t.parse::<u16>().ok())
        {
            related = Some(SocketAddr::new(rip, rport));
        }
        // extension name/value pairs, and rel-addr/rel-port if this line had
        // none of the above, are ignored either way (RFC 8839 §5.1)

        Some(Self {
            foundation,
            component,
            priority,
            address: SocketAddr::new(ip, port),
            kind,
            related,
        })
    }
}

/// At most one address per IP version, for one component (RFC 8445 §5.2:
/// "For each IP address, independent of an IP address family, there MUST be
/// zero or one candidate"). The type carries that limit instead of checking
/// for it: there is nowhere to put a second `SocketAddrV4`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostAddresses {
    /// The IPv4 address this component listens on, if it has one.
    pub v4: Option<SocketAddrV4>,
    /// The IPv6 address this component listens on, if it has one.
    pub v6: Option<SocketAddrV6>,
}

/// Local preference for an IPv4-only host, and for the IPv6 address of a
/// dual-stack one (RFC 8445 §5.2 says the single-family case gets 65535, and
/// recommends the address a dual-stack host prefers get it too).
const LOCAL_PREFERENCE_PRIMARY: u32 = 65_535;

/// Local preference for the IPv4 address of a dual-stack host. RFC 8445 §5.2
/// asks for RFC 6724's precedence value here; this agent never chooses among
/// its own candidates, so what matters is only that the two families are
/// distinguishable, and IPv6 is given the edge RFC 6724's default table gives
/// native IPv6 over IPv4.
const LOCAL_PREFERENCE_SECONDARY: u32 = 65_534;

fn priority(component: ComponentId, local_preference: u32) -> u32 {
    (TYPE_PREFERENCE_HOST << 24) + (local_preference << 8) + (256 - u32::from(component.get()))
}

/// Host candidates for one or more components, from the addresses this agent
/// is already listening on (RFC 8445 §5.1.1.1, narrowed by §5.2 to host
/// candidates only).
///
/// Candidates that share an address get the same foundation, in the order
/// their address was first seen; nothing here draws that order from anywhere
/// but the input.
#[must_use]
pub fn gather(components: &[(ComponentId, HostAddresses)]) -> Vec<Candidate> {
    let dual_stack = components.iter().any(|(_, a)| a.v4.is_some())
        && components.iter().any(|(_, a)| a.v6.is_some());
    let v4_preference = if dual_stack {
        LOCAL_PREFERENCE_SECONDARY
    } else {
        LOCAL_PREFERENCE_PRIMARY
    };

    let mut seen: Vec<(IpAddr, Foundation)> = Vec::new();
    let mut candidates = Vec::new();
    for (component, addresses) in components {
        if let Some(v4) = addresses.v4 {
            let foundation = foundation_for(&mut seen, IpAddr::V4(*v4.ip()));
            candidates.push(Candidate {
                foundation,
                component: *component,
                priority: priority(*component, v4_preference),
                address: SocketAddr::V4(v4),
                kind: CandidateType::Host,
                related: None,
            });
        }
        if let Some(v6) = addresses.v6 {
            let foundation = foundation_for(&mut seen, IpAddr::V6(*v6.ip()));
            candidates.push(Candidate {
                foundation,
                component: *component,
                priority: priority(*component, LOCAL_PREFERENCE_PRIMARY),
                address: SocketAddr::V6(v6),
                kind: CandidateType::Host,
                related: None,
            });
        }
    }
    candidates
}

fn foundation_for(seen: &mut Vec<(IpAddr, Foundation)>, address: IpAddr) -> Foundation {
    if let Some((_, foundation)) = seen.iter().find(|(known, _)| *known == address) {
        return foundation.clone();
    }
    let foundation = Foundation::numbered(u32::try_from(seen.len() + 1).unwrap_or(u32::MAX));
    seen.push((address, foundation.clone()));
    foundation
}

#[cfg(test)]
mod tests {
    use super::{Candidate, CandidateType, ComponentId, HostAddresses, gather};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    fn v4(port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), port)
    }

    fn v6(port: u16) -> SocketAddrV6 {
        SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), port, 0, 0)
    }

    #[test]
    fn a_generated_candidate_round_trips_through_its_own_line() {
        let candidates = gather(&[(
            ComponentId::RTP,
            HostAddresses {
                v4: Some(v4(9000)),
                v6: None,
            },
        )]);
        let candidate = candidates.first().expect("one candidate");
        let attribute = candidate.to_attribute();
        assert_eq!(attribute.name, "candidate");
        let value = attribute.value.expect("a value");
        let parsed = Candidate::parse(&value).expect("parses back");
        assert_eq!(parsed, *candidate);
    }

    #[test]
    fn the_example_line_from_rfc_8839_section_5_1_parses() {
        let candidate = Candidate::parse(
            "2 1 UDP 1694498815 192.0.2.3 45664 typ srflx raddr 203.0.113.141 rport 8998",
        )
        .expect("a well-formed line");
        assert_eq!(candidate.component, ComponentId::new(1).expect("valid"));
        assert_eq!(candidate.priority, 1_694_498_815);
        assert_eq!(
            candidate.address,
            SocketAddr::new("192.0.2.3".parse().expect("ip"), 45664)
        );
        assert_eq!(candidate.kind, CandidateType::ServerReflexive);
        assert_eq!(
            candidate.related,
            Some(SocketAddr::new("203.0.113.141".parse().expect("ip"), 8998))
        );
    }

    #[test]
    fn a_host_candidate_has_no_related_address() {
        let candidate = Candidate::parse("1 1 UDP 2130706431 198.51.100.7 9000 typ host")
            .expect("a well-formed line");
        assert_eq!(candidate.related, None);
    }

    #[test]
    fn an_fqdn_is_ignored_rather_than_refused() {
        // RFC 8839 SS5.1: "An agent processing remote candidates MUST ignore
        // 'candidate' lines that include candidates with FQDNs"
        assert!(Candidate::parse("1 1 UDP 2130706431 media.example.com 9000 typ host").is_none());
    }

    #[test]
    fn a_transport_that_is_not_udp_is_ignored() {
        assert!(Candidate::parse("1 1 TCP 2130706431 198.51.100.7 9000 typ host").is_none());
    }

    #[test]
    fn an_unrecognised_candidate_type_is_ignored() {
        assert!(Candidate::parse("1 1 UDP 2130706431 198.51.100.7 9000 typ quic").is_none());
    }

    #[test]
    fn a_priority_of_zero_is_out_of_range() {
        // RFC 8839 SS5.1: priority is "a positive integer"
        assert!(Candidate::parse("1 1 UDP 0 198.51.100.7 9000 typ host").is_none());
    }

    #[test]
    fn a_component_id_of_zero_or_above_256_is_out_of_range() {
        assert!(Candidate::parse("1 0 UDP 1 198.51.100.7 9000 typ host").is_none());
        assert!(Candidate::parse("1 257 UDP 1 198.51.100.7 9000 typ host").is_none());
        assert!(ComponentId::new(0).is_none());
        assert!(ComponentId::new(257).is_none());
        assert!(ComponentId::new(256).is_some());
    }

    #[test]
    fn a_foundation_over_thirty_two_characters_is_out_of_range() {
        let long: String = "1".repeat(33);
        let line = format!("{long} 1 UDP 1 198.51.100.7 9000 typ host");
        assert!(Candidate::parse(&line).is_none());
    }

    #[test]
    fn trailing_extension_pairs_do_not_stop_the_parse() {
        let candidate = Candidate::parse("1 1 UDP 1 198.51.100.7 9000 typ host generation 0")
            .expect("extensions are ignored, not rejected");
        assert_eq!(candidate.component, ComponentId::RTP);
    }

    #[test]
    fn candidates_from_the_same_address_share_a_foundation() {
        let addresses = HostAddresses {
            v4: Some(v4(9000)),
            v6: None,
        };
        let candidates = gather(&[
            (ComponentId::RTP, addresses),
            (ComponentId::RTCP, addresses),
        ]);
        assert_eq!(candidates.len(), 2);
        let first = candidates.first().expect("rtp");
        let second = candidates.get(1).expect("rtcp");
        assert_eq!(first.foundation, second.foundation);
        assert_ne!(first.component, second.component);
    }

    #[test]
    fn a_different_address_gets_a_different_foundation() {
        let candidates = gather(&[(
            ComponentId::RTP,
            HostAddresses {
                v4: Some(v4(9000)),
                v6: Some(v6(9000)),
            },
        )]);
        assert_eq!(candidates.len(), 2);
        let first = candidates.first().expect("v4");
        let second = candidates.get(1).expect("v6");
        assert_ne!(first.foundation, second.foundation);
    }

    #[test]
    fn every_candidate_of_a_data_stream_has_a_unique_priority() {
        let candidates = gather(&[
            (
                ComponentId::RTP,
                HostAddresses {
                    v4: Some(v4(9000)),
                    v6: Some(v6(9000)),
                },
            ),
            (
                ComponentId::RTCP,
                HostAddresses {
                    v4: Some(v4(9001)),
                    v6: Some(v6(9001)),
                },
            ),
        ]);
        let mut priorities: Vec<u32> = candidates.iter().map(|c| c.priority).collect();
        priorities.sort_unstable();
        priorities.dedup();
        assert_eq!(priorities.len(), candidates.len());
    }

    #[test]
    fn dual_stack_gives_ipv6_the_higher_local_preference() {
        let candidates = gather(&[(
            ComponentId::RTP,
            HostAddresses {
                v4: Some(v4(9000)),
                v6: Some(v6(9000)),
            },
        )]);
        let v4_candidate = candidates.iter().find(|c| c.address.is_ipv4()).expect("v4");
        let v6_candidate = candidates.iter().find(|c| c.address.is_ipv6()).expect("v6");
        assert!(v6_candidate.priority > v4_candidate.priority);
    }

    #[test]
    fn an_ipv4_only_host_gets_the_full_local_preference() {
        let candidates = gather(&[(
            ComponentId::RTP,
            HostAddresses {
                v4: Some(v4(9000)),
                v6: None,
            },
        )]);
        let only = candidates.first().expect("one candidate");
        // (2^24)*126 + (2^8)*65535 + (256 - 1)
        assert_eq!(only.priority, 2_130_706_431);
    }

    #[test]
    fn a_component_with_no_addresses_gathers_nothing() {
        assert!(gather(&[(ComponentId::RTP, HostAddresses::default())]).is_empty());
    }
}
