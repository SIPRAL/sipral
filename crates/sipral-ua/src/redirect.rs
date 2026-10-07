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
//!
//! And the other side of it: a call this end placed that comes back 3xx is
//! sent on to the targets the answer names ([`Redirection`]).

use std::time::Instant;

use sipral_core::msg::{Contacts, OwnedMessage, RawMessage, StatusCode, Uri, UriScheme};
use sipral_core::transaction::{InviteClient, TransactionId};

use crate::agent::UserAgent;
use crate::call::{CallHandle, CallState};
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

/// How many INVITEs one call places on the strength of redirects before it
/// gives up: §8.1.3.4 leaves the bound to the client, and it only has to
/// stop a pair of servers that send a call back and forth between them.
pub(crate) const MOST_REDIRECTS: usize = 8;

/// Where a 3xx sent a call this end placed (RFC 3261 §8.1.3.4): "the
/// client SHOULD use the Contact header field values of the response to
/// generate a new request".
///
/// The target set is kept on the call, so a target that fails is followed by
/// the next one before the call is given up on, and a target already tried
/// is never tried again — the loop §8.1.3.4 warns of ends at the second
/// visit, not at the bound.
#[derive(Clone, Debug, Default)]
pub(crate) struct Redirection {
    /// The Request-URI the call's INVITE goes to now, once a 3xx moved it.
    /// `To` stays the address the application called.
    pub(crate) target: Option<Uri>,
    /// Every Request-URI already tried, the one placed first among them.
    tried: Vec<Uri>,
    /// What is left of the target set, best first.
    pending: Vec<Uri>,
}

impl Redirection {
    /// Add a 3xx's `Contact` addresses to what is left to try, most
    /// preferred first (§8.1.3.4: "in order of their q-values").
    fn learn(&mut self, placed: &Uri, response: &RawMessage<'_>) {
        if self.tried.is_empty() {
            self.tried.push(placed.clone());
        }
        let Ok(Contacts::Addrs(addrs)) = response.contact() else {
            return;
        };
        let mut found: Vec<(u16, Uri)> = Vec::new();
        for addr in addrs.flatten() {
            if !matches!(addr.uri().scheme(), UriScheme::Sip | UriScheme::Sips) {
                continue;
            }
            let Some(target) = requestable(&addr.uri().to_string()) else {
                continue;
            };
            let known = |uri: &Uri| uri.as_bytes() == target.as_bytes();
            if self.tried.iter().any(known)
                || self.pending.iter().any(known)
                || found.iter().any(|(_, uri)| known(uri))
            {
                continue;
            }
            // §20.10: no q is the same as q=1
            found.push((addr.q().ok().flatten().unwrap_or(1000), target));
        }
        // stable, so equal preferences keep the order they were written in
        found.sort_by_key(|(q, _)| std::cmp::Reverse(*q));
        self.pending.extend(found.into_iter().map(|(_, uri)| uri));
    }

    /// The next target, now counted as tried; `None` once the set is spent
    /// or the bound reached.
    fn next(&mut self) -> Option<Uri> {
        if self.pending.is_empty() || self.tried.len() > MOST_REDIRECTS {
            return None;
        }
        let target = self.pending.remove(0);
        self.tried.push(target.clone());
        self.target = Some(target.clone());
        Some(target)
    }
}

/// A `Contact` URI as a Request-URI: §8.1.3.4 copies "the entire URI ...
/// except for the "method-param" and "header" URI parameters".
fn requestable(contact: &str) -> Option<Uri> {
    let without_headers = contact.split('?').next().unwrap_or_default();
    let kept: Vec<&str> = without_headers
        .split(';')
        .enumerate()
        .filter(|(at, part)| *at == 0 || !part.to_ascii_lowercase().starts_with("method="))
        .map(|(_, part)| part)
        .collect();
    Uri::parse_str(&kept.join(";")).ok()
}

impl UserAgent {
    /// A call this end placed was refused. Whether the refusal is a
    /// redirect to follow, or the failure of one target in a set a redirect
    /// gave with others still to try, and if so the INVITE that goes next:
    /// the same `Call-ID`, `From` and `To`, the next number, and the target
    /// as the Request-URI (§8.1.3.4). `true` when one went, and the refusal
    /// is then not the call's end.
    ///
    /// A 380 names its alternative in its body and is not followed; a 6xx
    /// is a global failure, which §8.1.3.4 has end the search. A call that
    /// forked is not followed either: its branches are calls of their own
    /// already. Where the INVITE goes is where every INVITE of the account
    /// goes — its outbound proxy or server, or the destination the call was
    /// placed to — since resolving a name is the application's.
    pub(crate) fn follow_redirect(
        &mut self,
        call: CallHandle,
        invite: TransactionId<InviteClient>,
        status: Option<StatusCode>,
        response: Option<&OwnedMessage>,
        now: Instant,
    ) -> bool {
        let code = status.map_or(0, StatusCode::get);
        if code == 380 || code >= 600 {
            return false;
        }
        let branches = self
            .calls
            .values()
            .filter(|held| held.invite == Some(invite))
            .count();
        if branches != 1 {
            return false;
        }
        let (placed, account) = {
            let Some(held) = self.calls.get_mut(&call) else {
                return false;
            };
            let Some(placed) = held.placed.clone() else {
                return false;
            };
            if (300..400).contains(&code)
                && let Some(response) = response
            {
                held.redirection.learn(&placed.target, &response.as_raw());
            }
            if held.redirection.next().is_none() {
                return false;
            }
            held.cseq = held.cseq.saturating_add(1);
            held.state = CallState::Calling;
            (placed, held.account)
        };
        let Some(account) = account else {
            return false;
        };
        self.by_invite.remove(&invite);
        if let Some(dialog) = self
            .calls
            .get_mut(&call)
            .and_then(|held| held.dialog.take())
        {
            self.by_dialog.remove(&dialog);
        }
        self.dial(account, &placed, call, now).is_ok()
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
