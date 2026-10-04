// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Sending a call somewhere else: a 3xx answer with the places to try
//! (RFC 3261 §21.3), and the `Diversion` that says why (RFC 5806).
//!
//! What a phone's call forwarding does when the phone does it itself rather
//! than the switch: the INVITE is answered 302 with a `Contact` naming the
//! new target, the caller's proxy — or the caller — sends the INVITE there,
//! and the `Diversion` carried back names this end as the one that diverted
//! the call and says why, so the phone that finally rings can show "forwarded
//! from Alice, no answer". The `Diversion` values the INVITE already carried
//! follow this end's own, most recent first (RFC 5806 §3).

use sipral_core::msg::{StatusCode, Uri};

use crate::error::UaError;

/// A 3xx answer to a call that came in.
#[derive(Clone, Debug)]
pub struct Redirect {
    pub(crate) status: StatusCode,
    pub(crate) targets: Vec<(Uri, Option<u16>)>,
    pub(crate) reason: Option<Box<str>>,
}

impl Redirect {
    /// 302 Moved Temporarily: call forwarding.
    #[must_use]
    pub const fn moved_temporarily() -> Self {
        Self {
            status: StatusCode::MOVED_TEMPORARILY,
            targets: Vec::new(),
            reason: None,
        }
    }

    /// Any redirection status: 300 to 399.
    ///
    /// # Errors
    /// [`UaError::NotARedirection`] for anything else.
    pub fn with_status(status: StatusCode) -> Result<Self, UaError> {
        if !(300..400).contains(&status.get()) {
            return Err(UaError::NotARedirection(status));
        }
        Ok(Self {
            status,
            targets: Vec::new(),
            reason: None,
        })
    }

    /// Somewhere to try, in the order given.
    #[must_use]
    pub fn to(mut self, target: Uri) -> Self {
        self.targets.push((target, None));
        self
    }

    /// Somewhere to try, with a preference (RFC 3261 §20.10's `q`) in
    /// thousandths: 1000 is `q=1`, 500 `q=0.5`. Above 1000 is 1000.
    #[must_use]
    pub fn to_preferred(mut self, target: Uri, thousandths: u16) -> Self {
        self.targets.push((target, Some(thousandths.min(1000))));
        self
    }

    /// Say why the call was diverted (RFC 5806 §4's `reason`): `user-busy`,
    /// `no-answer`, `unconditional`, `deflection`, `do-not-disturb`, or any
    /// other token. A `Diversion` naming this end goes on the answer.
    #[must_use]
    pub fn diverted(mut self, reason: &str) -> Self {
        self.reason = Some(Box::from(reason));
        self
    }

    /// The `Contact` value: every target, `<uri>` with its `q`, comma-separated.
    pub(crate) fn contact_value(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (target, q) in &self.targets {
            if !out.is_empty() {
                out.extend_from_slice(b", ");
            }
            out.push(b'<');
            out.extend_from_slice(target.as_bytes());
            out.push(b'>');
            if let Some(q) = q {
                out.extend_from_slice(format!(";q={}", q_text(*q)).as_bytes());
            }
        }
        out
    }

    /// The `Diversion` value naming `diverting` as the party that diverted
    /// the call, or `None` when no reason was given.
    pub(crate) fn diversion_value(&self, diverting: &[u8]) -> Option<Vec<u8>> {
        let reason = self.reason.as_deref()?;
        let mut out = Vec::with_capacity(diverting.len() + reason.len() + 24);
        out.push(b'<');
        out.extend_from_slice(diverting);
        out.extend_from_slice(b">;reason=");
        if !reason.is_empty() && reason.bytes().all(is_token_byte) {
            out.extend_from_slice(reason.as_bytes());
        } else {
            out.push(b'"');
            for byte in reason.bytes().filter(|byte| *byte >= 0x20 && *byte != 0x7f) {
                if matches!(byte, b'"' | b'\\') {
                    out.push(b'\\');
                }
                out.push(byte);
            }
            out.push(b'"');
        }
        out.extend_from_slice(b";counter=1");
        Some(out)
    }
}

/// `q` as §20.10 writes it: at most three decimals, and no trailing zeros
/// beyond the first.
fn q_text(thousandths: u16) -> String {
    if thousandths >= 1000 {
        return "1".to_owned();
    }
    let text = format!("0.{thousandths:03}");
    let trimmed = text.trim_end_matches('0');
    if trimmed.ends_with('.') {
        format!("{trimmed}0")
    } else {
        trimmed.to_owned()
    }
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
    use super::{Redirect, q_text};
    use sipral_core::msg::{StatusCode, Uri};

    #[test]
    fn a_preference_reads_the_way_the_grammar_writes_it() {
        assert_eq!(q_text(1000), "1");
        assert_eq!(q_text(1500), "1");
        assert_eq!(q_text(500), "0.5");
        assert_eq!(q_text(125), "0.125");
        assert_eq!(q_text(0), "0.0");
    }

    #[test]
    fn only_a_redirection_status_makes_a_redirect() {
        assert!(Redirect::with_status(StatusCode::new(301).expect("a status")).is_ok());
        assert!(Redirect::with_status(StatusCode::new(486).expect("a status")).is_err());
        assert!(Redirect::with_status(StatusCode::OK).is_err());
    }

    #[test]
    fn a_reason_that_is_not_a_token_is_quoted() {
        let redirect = Redirect::moved_temporarily()
            .to(Uri::parse_str("sip:carol@example.com").expect("a URI"))
            .diverted("out to \"lunch\"");
        assert_eq!(
            redirect
                .diversion_value(b"sip:alice@example.com")
                .as_deref(),
            Some(&b"<sip:alice@example.com>;reason=\"out to \\\"lunch\\\"\";counter=1"[..])
        );
    }
}
