// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Methods and status codes.

use core::fmt;

/// A request method. Well-known verbs are recognised; anything else is an
/// extension carried as a borrowed slice of the start line.
///
/// Methods are case-sensitive tokens (RFC 3261 §7.1), so `Invite` and an
/// `Extension("invite")` are deliberately different values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method<'a> {
    /// RFC 3261.
    Invite,
    /// RFC 3261.
    Ack,
    /// RFC 3261.
    Bye,
    /// RFC 3261.
    Cancel,
    /// RFC 3261.
    Options,
    /// RFC 3261.
    Register,
    /// RFC 3262.
    Prack,
    /// RFC 6665.
    Subscribe,
    /// RFC 6665.
    Notify,
    /// RFC 3515.
    Refer,
    /// RFC 6086.
    Info,
    /// RFC 3311.
    Update,
    /// RFC 3428.
    Message,
    /// RFC 3903.
    Publish,
    /// Anything else that is a valid token.
    Extension(&'a str),
}

impl<'a> Method<'a> {
    /// Recognise a method from its bytes. `None` if they are not a token.
    #[must_use]
    pub fn from_bytes(bytes: &'a [u8]) -> Option<Self> {
        if bytes.is_empty() || !bytes.iter().copied().all(is_token_byte) {
            return None;
        }
        Some(match bytes {
            b"INVITE" => Self::Invite,
            b"ACK" => Self::Ack,
            b"BYE" => Self::Bye,
            b"CANCEL" => Self::Cancel,
            b"OPTIONS" => Self::Options,
            b"REGISTER" => Self::Register,
            b"PRACK" => Self::Prack,
            b"SUBSCRIBE" => Self::Subscribe,
            b"NOTIFY" => Self::Notify,
            b"REFER" => Self::Refer,
            b"INFO" => Self::Info,
            b"UPDATE" => Self::Update,
            b"MESSAGE" => Self::Message,
            b"PUBLISH" => Self::Publish,
            // a token is ASCII by construction, so this cannot fail
            other => Self::Extension(core::str::from_utf8(other).ok()?),
        })
    }

    /// The wire form.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        match *self {
            Self::Invite => "INVITE",
            Self::Ack => "ACK",
            Self::Bye => "BYE",
            Self::Cancel => "CANCEL",
            Self::Options => "OPTIONS",
            Self::Register => "REGISTER",
            Self::Prack => "PRACK",
            Self::Subscribe => "SUBSCRIBE",
            Self::Notify => "NOTIFY",
            Self::Refer => "REFER",
            Self::Info => "INFO",
            Self::Update => "UPDATE",
            Self::Message => "MESSAGE",
            Self::Publish => "PUBLISH",
            Self::Extension(s) => s,
        }
    }

    /// Whether this is a method Sipral does not know.
    #[must_use]
    pub const fn is_extension(&self) -> bool {
        matches!(*self, Self::Extension(_))
    }
}

impl fmt::Display for Method<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// RFC 3261 §7.2 status code: exactly three digits, 100 through 699.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct StatusCode(u16);

/// A number that is not a SIP status code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidStatusCode(pub u16);

impl fmt::Display for InvalidStatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is not a SIP status code", self.0)
    }
}

impl core::error::Error for InvalidStatusCode {}

impl StatusCode {
    /// 100 Trying.
    pub const TRYING: Self = Self(100);
    /// 180 Ringing.
    pub const RINGING: Self = Self(180);
    /// 183 Session Progress.
    pub const SESSION_PROGRESS: Self = Self(183);
    /// 200 OK.
    pub const OK: Self = Self(200);
    /// 401 Unauthorized.
    pub const UNAUTHORIZED: Self = Self(401);
    /// 407 Proxy Authentication Required.
    pub const PROXY_AUTH_REQUIRED: Self = Self(407);
    /// 486 Busy Here.
    pub const BUSY_HERE: Self = Self(486);
    /// 487 Request Terminated.
    pub const REQUEST_TERMINATED: Self = Self(487);
    /// 488, which refuses a session description rather than the request that
    /// carried it (RFC 3264 §6, RFC 3311 §5.2).
    pub const NOT_ACCEPTABLE_HERE: Self = Self(488);
    /// 422, which refuses a session interval as too short and says in
    /// `Min-SE` what would be accepted (RFC 4028 §6).
    pub const SESSION_INTERVAL_TOO_SMALL: Self = Self(422);
    /// 491, which §14.2 answers an INVITE that crossed one of our own inside
    /// the same dialog with.
    pub const REQUEST_PENDING: Self = Self(491);
    /// 481, which answers a request naming a dialog or a transaction that is
    /// not there (§12.2.2, RFC 3262 §3).
    pub const CALL_DOES_NOT_EXIST: Self = Self(481);
    /// 420, which §8.2.2.3 makes the only answer to a `Require` naming an
    /// extension this end has not implemented.
    pub const BAD_EXTENSION: Self = Self(420);
    /// 500, which §12.2.2 answers a request whose `CSeq` runs backwards with.
    pub const SERVER_ERROR: Self = Self(500);
    /// 503, "temporarily unable to process the request due to a temporary
    /// overloading" (§21.5.4).
    pub const SERVICE_UNAVAILABLE: Self = Self(503);
    /// 504 Server Time-out.
    pub const SERVER_TIMEOUT: Self = Self(504);

    /// Build from a number in 100..=699.
    ///
    /// # Errors
    /// Returns the offending number if it is outside that range.
    pub const fn new(code: u16) -> Result<Self, InvalidStatusCode> {
        if code >= 100 && code <= 699 {
            Ok(Self(code))
        } else {
            Err(InvalidStatusCode(code))
        }
    }

    /// The numeric value.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    /// 1xx.
    #[must_use]
    pub const fn is_provisional(self) -> bool {
        self.0 < 200
    }

    /// 2xx.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.0 >= 200 && self.0 < 300
    }

    /// Anything that is not 1xx.
    #[must_use]
    pub const fn is_final(self) -> bool {
        !self.is_provisional()
    }

    /// The reason phrase RFC 3261 §21 registers for this code, if it
    /// registers one.
    ///
    /// The phrase is for a person to read (§7.2), so a caller is free to send
    /// something else; this is the default so that nobody has to invent one.
    /// 422 comes from RFC 4028 §6.
    #[must_use]
    #[expect(
        clippy::match_same_arms,
        reason = "the table stays in the RFC's order so it can be read against §21; 406 and 606 do share a phrase"
    )]
    pub const fn reason(self) -> Option<&'static str> {
        Some(match self.0 {
            100 => "Trying",
            180 => "Ringing",
            181 => "Call Is Being Forwarded",
            182 => "Queued",
            183 => "Session Progress",
            200 => "OK",
            300 => "Multiple Choices",
            301 => "Moved Permanently",
            302 => "Moved Temporarily",
            305 => "Use Proxy",
            380 => "Alternative Service",
            400 => "Bad Request",
            401 => "Unauthorized",
            402 => "Payment Required",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            406 => "Not Acceptable",
            407 => "Proxy Authentication Required",
            408 => "Request Timeout",
            410 => "Gone",
            413 => "Request Entity Too Large",
            414 => "Request-URI Too Long",
            415 => "Unsupported Media Type",
            416 => "Unsupported URI Scheme",
            420 => "Bad Extension",
            421 => "Extension Required",
            422 => "Session Interval Too Small",
            423 => "Interval Too Brief",
            480 => "Temporarily Unavailable",
            481 => "Call/Transaction Does Not Exist",
            482 => "Loop Detected",
            483 => "Too Many Hops",
            484 => "Address Incomplete",
            485 => "Ambiguous",
            486 => "Busy Here",
            487 => "Request Terminated",
            488 => "Not Acceptable Here",
            491 => "Request Pending",
            493 => "Undecipherable",
            500 => "Server Internal Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Server Time-out",
            505 => "Version Not Supported",
            513 => "Message Too Large",
            600 => "Busy Everywhere",
            603 => "Decline",
            604 => "Does Not Exist Anywhere",
            606 => "Not Acceptable",
            _ => return None,
        })
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Whether a byte may appear in a token (RFC 3261 §25.1).
#[must_use]
pub(crate) const fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

#[cfg(test)]
mod tests {
    use super::{InvalidStatusCode, Method, StatusCode};

    #[test]
    fn well_known_methods_are_recognised() {
        assert_eq!(Method::from_bytes(b"INVITE"), Some(Method::Invite));
        assert_eq!(Method::from_bytes(b"PRACK"), Some(Method::Prack));
        assert_eq!(Method::from_bytes(b"REFER"), Some(Method::Refer));
    }

    #[test]
    fn methods_are_case_sensitive() {
        assert_eq!(
            Method::from_bytes(b"Invite"),
            Some(Method::Extension("Invite"))
        );
        assert!(Method::from_bytes(b"Invite").is_some_and(|m| m.is_extension()));
    }

    #[test]
    fn unknown_token_is_an_extension() {
        // RFC 4475 3.1.1.1 uses an unknown method in an otherwise valid request
        assert_eq!(
            Method::from_bytes(b"NEWMETHOD"),
            Some(Method::Extension("NEWMETHOD"))
        );
    }

    #[test]
    fn non_token_bytes_are_not_a_method() {
        assert_eq!(Method::from_bytes(b"IN VITE"), None);
        assert_eq!(Method::from_bytes(b"IN\x00VITE"), None);
        assert_eq!(Method::from_bytes(b""), None);
    }

    #[test]
    fn round_trips_through_as_str() {
        for m in [Method::Invite, Method::Bye, Method::Extension("FOO")] {
            assert_eq!(Method::from_bytes(m.as_str().as_bytes()), Some(m));
        }
    }

    #[test]
    fn status_code_range_is_enforced() {
        assert_eq!(StatusCode::new(100).map(StatusCode::get), Ok(100));
        assert_eq!(StatusCode::new(699).map(StatusCode::get), Ok(699));
        assert_eq!(StatusCode::new(99), Err(InvalidStatusCode(99)));
        assert_eq!(StatusCode::new(700), Err(InvalidStatusCode(700)));
    }

    #[test]
    fn status_classes() {
        assert!(StatusCode::TRYING.is_provisional());
        assert!(!StatusCode::TRYING.is_final());
        assert!(StatusCode::OK.is_success());
        assert!(StatusCode::BUSY_HERE.is_final());
        assert!(!StatusCode::BUSY_HERE.is_success());
    }

    #[test]
    fn the_registered_reason_phrases_come_from_the_rfc() {
        assert_eq!(StatusCode::TRYING.reason(), Some("Trying"));
        assert_eq!(StatusCode::OK.reason(), Some("OK"));
        assert_eq!(StatusCode::SERVER_TIMEOUT.reason(), Some("Server Time-out"));
        // RFC 4028 6
        assert_eq!(
            StatusCode::new(422).expect("a status").reason(),
            Some("Session Interval Too Small")
        );
        // 406 and 606 share a phrase, and both are registered
        assert_eq!(
            StatusCode::new(406).expect("a status").reason(),
            Some("Not Acceptable")
        );
        assert_eq!(
            StatusCode::new(606).expect("a status").reason(),
            Some("Not Acceptable")
        );
        // a code nobody registered has no phrase to offer
        assert_eq!(StatusCode::new(499).expect("a status").reason(), None);
    }
}
