// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Why a request was sent: the `Reason` header field (RFC 3326).
//!
//! Two uses matter: a forking proxy cancels losing branches with
//! `SIP ;cause=200` (§3.1), so they show "answered elsewhere" rather than a
//! missed call; and gateways carry the Q.850 cause (16 normal, 17 busy), also
//! on responses (RFC 6432).
//!
//! It never changes protocol processing (§2): it is read, handed up with the
//! call's end, and written where this end knows why it ends something.

use sipral_core::msg::{HeaderName, Params, RawMessage, trim};

use crate::account::Extra;

/// The field's name, which RFC 3261's own table does not have.
pub(crate) const REASON: HeaderName<'static> = HeaderName::Extension("Reason");

/// Whose number a [`Reason`]'s cause is (RFC 3326 §2's `protocol`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReasonProtocol {
    /// A SIP status code.
    Sip,
    /// An ITU-T Q.850 cause value, in decimal.
    Q850,
    /// Any other protocol token, as written.
    Other(Box<str>),
}

impl ReasonProtocol {
    /// The token as it goes on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Sip => "SIP",
            Self::Q850 => "Q.850",
            Self::Other(token) => token,
        }
    }

    fn of_token(token: &[u8]) -> Option<Self> {
        if token.eq_ignore_ascii_case(b"SIP") {
            return Some(Self::Sip);
        }
        if token.eq_ignore_ascii_case(b"Q.850") {
            return Some(Self::Q850);
        }
        let text = std::str::from_utf8(token).ok()?;
        (!text.is_empty() && text.bytes().all(is_token_byte)).then(|| Self::Other(Box::from(text)))
    }
}

/// One reason-value: a protocol, the cause it names, and the text beside it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Reason {
    /// Whose number `cause` is.
    pub protocol: ReasonProtocol,
    /// The cause, when the value carried one that reads as a number.
    pub cause: Option<u16>,
    /// The `text` parameter, unquoted. `None` when there was none.
    pub text: Option<Box<str>>,
}

impl Reason {
    /// A SIP status code as a reason.
    #[must_use]
    pub fn sip(status: u16, text: &str) -> Self {
        Self {
            protocol: ReasonProtocol::Sip,
            cause: Some(status),
            text: (!text.is_empty()).then(|| Box::from(text)),
        }
    }

    /// A Q.850 cause as a reason.
    #[must_use]
    pub fn q850(cause: u16, text: &str) -> Self {
        Self {
            protocol: ReasonProtocol::Q850,
            cause: Some(cause),
            text: (!text.is_empty()).then(|| Box::from(text)),
        }
    }

    /// RFC 3326 §3.1's own example: another branch of the same call was
    /// answered.
    #[must_use]
    pub fn completed_elsewhere() -> Self {
        Self::sip(200, "Call completed elsewhere")
    }

    /// Whether this is a SIP 200, which is what a forking proxy writes on
    /// the CANCEL of every branch that lost.
    #[must_use]
    pub fn is_completed_elsewhere(&self) -> bool {
        self.protocol == ReasonProtocol::Sip && self.cause == Some(200)
    }

    /// Read one reason-value. `None` for one whose protocol is not a token.
    #[must_use]
    pub fn parse(value: &[u8]) -> Option<Self> {
        let (head, params) = Params::split(value);
        let protocol = ReasonProtocol::of_token(trim(head))?;
        let cause = params
            .get("cause")
            .and_then(|digits| std::str::from_utf8(&digits).ok()?.parse::<u16>().ok());
        let text = params.get("text").and_then(|quoted| {
            std::str::from_utf8(&quoted)
                .ok()
                .map(|text| Box::from(text.trim()))
        });
        Some(Self {
            protocol,
            cause,
            text,
        })
    }

    /// Every reason-value a message carries, in the order written.
    ///
    /// A repeated protocol keeps the first (§2); unreadable values are
    /// skipped.
    #[must_use]
    pub fn all_in(message: &RawMessage<'_>) -> Box<[Self]> {
        let mut read: Vec<Self> = Vec::new();
        for value in message.field_values(REASON) {
            if let Some(reason) = Self::parse(value)
                && !read.iter().any(|seen| seen.protocol == reason.protocol)
            {
                read.push(reason);
            }
        }
        read.into_boxed_slice()
    }

    /// The reason-value as it goes on the wire:
    /// `SIP;cause=200;text="Call completed elsewhere"`.
    ///
    /// The text is quoted (RFC 3261 §25.1); bytes not allowed in a
    /// quoted-string are dropped.
    #[must_use]
    pub fn to_value(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        out.extend_from_slice(self.protocol.as_str().as_bytes());
        if let Some(cause) = self.cause {
            out.extend_from_slice(b";cause=");
            out.extend_from_slice(cause.to_string().as_bytes());
        }
        if let Some(text) = self.text.as_deref() {
            out.extend_from_slice(b";text=\"");
            for byte in text.bytes() {
                match byte {
                    b'"' | b'\\' => {
                        out.push(b'\\');
                        out.push(byte);
                    }
                    0x20..=0x7e | 0x80..=0xff => out.push(byte),
                    b'\t' => out.push(b' '),
                    _ => {}
                }
            }
            out.push(b'"');
        }
        out
    }

    /// Several reason-values as one field value, comma-separated, with a
    /// later value of a protocol already written left out (§2).
    #[must_use]
    pub fn field(reasons: &[Self]) -> Option<Vec<u8>> {
        let mut written: Vec<&ReasonProtocol> = Vec::new();
        let mut out = Vec::new();
        for reason in reasons {
            if written.contains(&&reason.protocol) {
                continue;
            }
            if !out.is_empty() {
                out.extend_from_slice(b", ");
            }
            out.extend_from_slice(&reason.to_value());
            written.push(&reason.protocol);
        }
        (!out.is_empty()).then_some(out)
    }
}

impl core::fmt::Display for Reason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.protocol.as_str())?;
        if let Some(cause) = self.cause {
            write!(f, " {cause}")?;
        }
        if let Some(text) = self.text.as_deref() {
            write!(f, " ({text})")?;
        }
        Ok(())
    }
}

/// `headers` with `reasons` replacing any `Reason` the application wrote;
/// unchanged when `reasons` is empty.
pub(crate) fn with_reason(headers: &[Extra], reasons: &[Reason]) -> Vec<Extra> {
    let mut out = headers.to_vec();
    if let Some(value) = Reason::field(reasons) {
        out.retain(|header| !header.name.eq_ignore_ascii_case(b"Reason"));
        out.push(Extra {
            name: Box::from(&b"Reason"[..]),
            value: value.into_boxed_slice(),
        });
    }
    out
}

/// RFC 3261 §25.1's `token` characters.
const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
        )
}

#[cfg(test)]
mod tests {
    use super::{Reason, ReasonProtocol};
    use sipral_core::msg::{CommaList, ParseMode, ParseScratch, parse};

    /// Every value of a comma-separated field written as one line, split the
    /// way `RawMessage::field_values` splits one that arrived.
    fn values_of(line: &[u8]) -> Vec<&[u8]> {
        CommaList::new(line).collect()
    }

    /// One of RFC 3326's examples, and what it has to read as.
    type Example<'a> = (&'a [u8], ReasonProtocol, Option<u16>, Option<&'a str>);

    #[test]
    fn the_rfcs_own_examples_read_as_they_mean() {
        let cases: [Example<'_>; 4] = [
            (
                b"SIP ;cause=200 ;text=\"Call completed elsewhere\"",
                ReasonProtocol::Sip,
                Some(200),
                Some("Call completed elsewhere"),
            ),
            (
                b"Q.850 ;cause=16 ;text=\"Terminated\"",
                ReasonProtocol::Q850,
                Some(16),
                Some("Terminated"),
            ),
            (
                b"SIP ;cause=600 ;text=\"Busy Everywhere\"",
                ReasonProtocol::Sip,
                Some(600),
                Some("Busy Everywhere"),
            ),
            (
                b"preemption ;cause=1",
                ReasonProtocol::Other("preemption".into()),
                Some(1),
                None,
            ),
        ];
        for (value, protocol, cause, text) in cases {
            let reason = Reason::parse(value).expect("a reason");
            assert_eq!(reason.protocol, protocol);
            assert_eq!(reason.cause, cause);
            assert_eq!(reason.text.as_deref(), text);
        }
        assert!(
            Reason::parse(b"SIP;cause=200")
                .expect("a reason")
                .is_completed_elsewhere()
        );
        assert!(
            !Reason::parse(b"Q.850;cause=200")
                .expect("a reason")
                .is_completed_elsewhere()
        );
    }

    #[test]
    fn a_protocol_that_is_not_a_token_is_no_reason_and_a_cause_that_is_not_a_number_is_none() {
        assert!(Reason::parse(b"\"SIP\";cause=200").is_none());
        assert!(Reason::parse(b"").is_none());
        let reason = Reason::parse(b"SIP;cause=two hundred").expect("a reason");
        assert_eq!(reason.cause, None);
    }

    #[test]
    fn written_it_reads_back_the_same_with_its_quotes_escaped() {
        let reason = Reason::q850(16, "said \"bye\" \\ left\r\n");
        let value = reason.to_value();
        assert_eq!(
            value,
            b"Q.850;cause=16;text=\"said \\\"bye\\\" \\\\ left\"".to_vec()
        );
        let back = Reason::parse(&value).expect("it reads back");
        assert_eq!(back.protocol, ReasonProtocol::Q850);
        assert_eq!(back.cause, Some(16));
        assert_eq!(back.text.as_deref(), Some("said \"bye\" \\ left"));
    }

    #[test]
    fn a_field_carries_one_value_per_protocol() {
        let field = Reason::field(&[
            Reason::completed_elsewhere(),
            Reason::sip(486, ""),
            Reason::q850(16, ""),
        ])
        .expect("a field");
        let values = values_of(&field);
        assert_eq!(values.len(), 2, "{}", String::from_utf8_lossy(&field));
        assert!(Reason::field(&[]).is_none());
    }

    #[test]
    fn a_message_with_a_repeated_protocol_keeps_the_first_and_skips_what_it_cannot_read() {
        let message = b"CANCEL sip:bob@192.0.2.2 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bKone\r\n\
From: <sip:alice@example.com>;tag=a\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: reasons\r\n\
CSeq: 1 CANCEL\r\n\
Reason: SIP ;cause=200 ;text=\"Call completed elsewhere\", \"bad\"\r\n\
Reason: SIP ;cause=487, Q.850 ;cause=16\r\n\
Content-Length: 0\r\n\r\n";
        let mut scratch = ParseScratch::new();
        let raw = parse(message, &mut scratch, ParseMode::Lenient).expect("a message");
        let read = Reason::all_in(&raw);
        assert_eq!(read.len(), 2);
        assert!(read[0].is_completed_elsewhere());
        assert_eq!(read[1].protocol, ReasonProtocol::Q850);
        assert_eq!(read[1].cause, Some(16));
    }
}
