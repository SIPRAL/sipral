// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! `Route` and `Record-Route`: where a request goes, hop by hop.
//!
//! RFC 3261 §25.1:
//!
//! ```text
//! Record-Route  =  "Record-Route" HCOLON rec-route *(COMMA rec-route)
//! rec-route     =  name-addr *( SEMI rr-param )
//! rr-param      =  generic-param
//! Route         =  "Route" HCOLON route-param *(COMMA route-param)
//! route-param   =  name-addr *( SEMI rr-param )
//! ```
//!
//! `name-addr`, not `(name-addr / addr-spec)`. Unlike `Contact`, `From` and
//! `To`, a route entry has no bracket-less form: `Route: sip:p1.example.com;lr`
//! is not a lenient spelling of anything, it is a field with no way to tell a
//! URI parameter from a header parameter, and that distinction is the whole
//! job here.
//!
//! Which is the second trap. `;lr` inside the brackets is the `lr-param` of
//! §19.1.1 and marks a loose router; `;lr` after the `>` is an ordinary
//! `rr-param` that happens to be spelled the same and marks nothing. So
//! `<sip:p1.example.com>;lr` denotes a *strict* router, and §12.2.1.1 and
//! §16.6 both branch on it: a stack that looks for the text `lr` anywhere in
//! the value skips the rewrite and sends the request to the wrong Request-URI.
//! Parameter names are case-insensitive (§7.3.1), so `;LR` counts.
//!
//! Order is data. RFC 3261 §7.3.1 gives three `Route` rows and says that the
//! same three entries in a different order are "valid but not equivalent", so
//! nothing here sorts, dedupes or normalises.

use core::fmt;

use super::addr::NameAddrRef;
use super::error::HeaderError;
use super::lex::Params;
use super::message::FieldValues;
use super::uri::UriRef;

/// One `Route` or `Record-Route` entry, borrowed.
#[derive(Clone, Copy, Debug)]
pub struct RouteRef<'a> {
    addr: NameAddrRef<'a>,
}

impl<'a> RouteRef<'a> {
    /// Read one entry.
    ///
    /// # Errors
    /// [`HeaderError::Malformed`] for anything [`NameAddrRef::parse`] refuses,
    /// and for an entry that arrived without angle brackets, which the
    /// grammar does not offer here.
    pub fn parse(value: &'a [u8]) -> Result<Self, HeaderError> {
        let addr = NameAddrRef::parse(value)?;
        if !addr.is_name_addr() {
            return Err(HeaderError::Malformed(
                "a route entry has to be in angle brackets",
            ));
        }
        Ok(Self { addr })
    }

    /// The entry as an address, for its display name and parameters.
    #[must_use]
    pub const fn addr(&self) -> NameAddrRef<'a> {
        self.addr
    }

    /// The hop.
    #[must_use]
    pub const fn uri(&self) -> UriRef<'a> {
        self.addr.uri()
    }

    /// Whether the *URI* carries `;lr` (RFC 3261 §19.1.1).
    ///
    /// The parameter has to be inside the brackets. `<sip:p1.example.com>;lr`
    /// is a strict router with a header parameter named `lr`, and answering
    /// `true` there is how a request ends up at a strict router with a
    /// Request-URI it cannot use.
    #[must_use]
    pub fn is_loose_route(&self) -> bool {
        self.uri().sip().is_some_and(|u| u.is_loose_route())
    }

    /// The `rr-param` list, which is the header's own, after the `>`.
    #[must_use]
    pub fn params(&self) -> Params<'a> {
        self.addr.params()
    }
}

impl fmt::Display for RouteRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.addr.fmt(f)
    }
}

/// Every entry of one route field, in wire order across lines and commas.
#[derive(Clone, Debug)]
pub struct RouteIter<'a> {
    values: FieldValues<'a>,
}

impl<'a> RouteIter<'a> {
    pub(super) const fn new(values: FieldValues<'a>) -> Self {
        Self { values }
    }
}

impl<'a> Iterator for RouteIter<'a> {
    type Item = Result<RouteRef<'a>, HeaderError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.values.next().map(RouteRef::parse)
    }
}

#[cfg(test)]
mod tests {
    use super::RouteRef;
    use crate::msg::{CommaList, HeaderError, HostRef, UriScheme};

    fn route(v: &[u8]) -> RouteRef<'_> {
        RouteRef::parse(v).expect("a route entry")
    }

    fn entries(line: &[u8]) -> Vec<Result<RouteRef<'_>, HeaderError>> {
        CommaList::new(line).map(RouteRef::parse).collect()
    }

    fn refused(v: &[u8]) -> bool {
        matches!(RouteRef::parse(v), Err(HeaderError::Malformed(_)))
    }

    #[test]
    fn the_worked_example_folded_across_two_lines() {
        // RFC 3261 20.34
        let line = b"<sip:bigbox3.site3.example.com;lr>,\r\n       <sip:server10.example.com;lr>";
        let hops: Vec<_> = entries(line)
            .into_iter()
            .map(|r| r.expect("an entry"))
            .collect();
        assert_eq!(hops.len(), 2);
        assert_eq!(
            hops.first().map(|h| h.uri().sip().expect("sip parts").host),
            Some(HostRef::Name("bigbox3.site3.example.com"))
        );
        assert_eq!(
            hops.get(1).map(|h| h.uri().sip().expect("sip parts").host),
            Some(HostRef::Name("server10.example.com"))
        );
        assert!(hops.iter().all(RouteRef::is_loose_route));
        // the fold before the second '<' is whitespace, not a display name
        assert!(hops.iter().all(|h| h.addr().display_name().is_none()));
    }

    #[test]
    fn unknown_uri_parameters_are_kept_in_order() {
        // RFC 4475 3.1.1.1 wsinv, whose Route value sits entirely on a
        // continuation line
        let r = route(b"<sip:services.example.com;lr;unknownwith=value;unknown-no-value>");
        let params: Vec<_> = r.uri().sip().expect("sip parts").params().collect();
        assert_eq!(
            params,
            vec![
                ("lr", None),
                ("unknownwith", Some("value")),
                ("unknown-no-value", None),
            ]
        );
        assert_eq!(r.params().count(), 0);
    }

    #[test]
    fn an_entry_without_lr_is_a_strict_router() {
        // RFC 4475 3.4.1 inv2543: an RFC 2543 Record-Route, maddr and no lr
        let r = route(b"<sip:UserB@example.com;maddr=ss1.example.com>");
        assert!(!r.is_loose_route());
        assert_eq!(
            r.uri().sip().expect("sip parts").maddr(),
            Some("ss1.example.com")
        );
    }

    #[test]
    fn lr_outside_the_brackets_marks_nothing() {
        // the trap: legal, and it means the opposite of what it looks like
        let r = route(b"<sip:p1.example.com>;lr");
        assert!(!r.is_loose_route());
        assert!(r.params().has("lr"));
        assert_eq!(r.uri().sip().expect("sip parts").params().count(), 0);

        let inside = route(b"<sip:p1.example.com;lr>");
        assert!(inside.is_loose_route());
        assert_eq!(inside.params().count(), 0);
    }

    #[test]
    fn the_lr_parameter_is_matched_without_case() {
        // 7.3.1: parameter names are case-insensitive
        assert!(route(b"<sip:p1.example.com;LR>").is_loose_route());
        assert!(route(b"<sip:p1.example.com;Lr>").is_loose_route());
    }

    #[test]
    fn only_the_first_entry_decides_the_rewrite() {
        // the shape 12.2.1.1 and 16.6 item 6 test against
        let hops: Vec<_> = entries(b"<sip:strict.example.com>,<sip:loose.example.com;lr>")
            .into_iter()
            .map(|r| r.expect("an entry").is_loose_route())
            .collect();
        assert_eq!(hops, vec![false, true]);
    }

    #[test]
    fn a_route_entry_may_carry_a_display_name() {
        assert_eq!(
            route(br#""Loose Router" <sip:p1.example.com;lr>"#)
                .addr()
                .display_name()
                .as_deref(),
            Some(&b"Loose Router"[..])
        );
        assert_eq!(
            route(b"Loose Router <sip:p1.example.com;lr>")
                .addr()
                .display_name()
                .as_deref(),
            Some(&b"Loose Router"[..])
        );
    }

    #[test]
    fn a_quoted_parameter_value_is_one_parameter() {
        let r = route(br#"<sip:p1.example.com;lr>;foo="a;b,c""#);
        assert!(r.is_loose_route());
        assert_eq!(r.params().count(), 1);
        assert_eq!(r.params().get("foo").as_deref(), Some(&b"a;b,c"[..]));
    }

    #[test]
    fn a_bracketed_ipv6_host_is_not_the_end_of_the_entry() {
        let r = route(b"<sip:[2001:db8::1]:5060;lr>");
        let u = r.uri().sip().expect("sip parts");
        assert!(matches!(u.host, HostRef::Ipv6(_)));
        assert_eq!(u.port, Some(5060));
        assert!(r.is_loose_route());
    }

    #[test]
    fn the_userinfo_keeps_its_escapes() {
        let r = route(b"<sip:alice%20smith&co@atlanta.example.com;lr>");
        assert_eq!(
            r.uri().sip().expect("sip parts").user,
            Some("alice%20smith&co")
        );
    }

    #[test]
    fn a_scheme_that_cannot_be_routed_to_is_still_syntax() {
        // addr-spec's third alternative is absoluteURI, and 16.6 item 4's
        // SIP-or-SIPS MUST binds the proxy that inserts a value, not a
        // receiver reading one
        let r = route(b"<tel:+12015550123>");
        assert_eq!(r.uri().scheme(), UriScheme::Tel);
        assert!(!r.is_loose_route());
    }

    #[test]
    fn an_entry_without_brackets_is_refused() {
        // route-param is name-addr, with no addr-spec alternative
        assert!(refused(b"sip:p1.example.com;lr"));
        assert!(refused(b"sip:p1.example.com"));
    }

    #[test]
    fn a_malformed_entry_is_refused() {
        assert!(refused(b""));
        assert!(refused(b"<sip:p1.example.com;lr"));
        assert!(refused(b"<not a valid uri at all>"));
        assert!(refused(b"<>"));
        // a fold inside the URI: uri-parameters has no SWS, unlike SEMI
        assert!(refused(b"<sip:p1.example.com\r\n ;lr>"));
    }

    #[test]
    fn an_empty_entry_between_two_commas_is_refused() {
        // route-param *(COMMA route-param): every comma is followed by an
        // entry, so this is a rejection rather than a phantom hop
        let got = entries(b"<sip:p1.example.com;lr>,,<sip:p2.example.com;lr>");
        assert_eq!(got.len(), 3);
        assert!(got.first().is_some_and(Result::is_ok));
        assert!(got.get(1).is_some_and(Result::is_err));
        assert!(got.get(2).is_some_and(Result::is_ok));
    }

    #[test]
    fn display_round_trips_the_entry() {
        for s in [
            &b"<sip:p1.example.com;lr>"[..],
            &b"<sip:p1.example.com>;lr"[..],
            &br#""Loose Router" <sip:p1.example.com;lr>"#[..],
        ] {
            assert_eq!(route(s).to_string().as_bytes(), s);
        }
    }
}
