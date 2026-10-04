// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What the engine is holding, all at once, for a crash report.
//!
//! A log says what happened; a crash report wants to know what was going on
//! at the moment it was written: which accounts were registered, which calls
//! were up and in what state, which media was flowing where, and the health
//! counters. [`crate::MediaEngine::state`] takes that as an [`EngineState`],
//! and [`EngineState::render`] writes it as text a report can carry, with
//! two promises:
//!
//! - **Bounded.** At most [`LISTED`] rows per section, the rest counted
//!   rather than listed, and the whole text cut at the byte limit the caller
//!   gives, on a character boundary, with a line saying so.
//! - **Redacted.** Every user part, number and IP literal goes through
//!   [`sipral_diag::redact_text`] before the text is handed back, so the
//!   report can be attached to a ticket without being read first — the rule
//!   `docs/14-diagnostics.md` holds a diagnostic record to.
//!
//! Taking it never waits: a call's session that another thread is in the
//! middle of a frame on is reported as busy rather than waited for, so a
//! snapshot taken from a crash handler's thread cannot hang on the thread
//! that crashed.

use std::fmt::Write as _;
use std::net::SocketAddr;

use sipral_diag::{Redactor, redact_text};
use sipral_ua::{AccountId, CallHandle, RegistrationState};

use crate::{Codec, Counters};

/// Rows per section a rendered report lists before it only counts.
pub const LISTED: usize = 32;

/// One account, as a snapshot saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AccountState {
    /// Which account.
    pub account: AccountId,
    /// Its address of record, unredacted until rendered.
    pub aor: String,
    /// Where its registration was.
    pub registration: Option<RegistrationState>,
}

/// One call, as a snapshot saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CallSnapshot {
    /// Which call.
    pub call: CallHandle,
    /// Where its signalling was.
    pub state: Option<sipral_ua::CallState>,
    /// The local address its media was described at, when this engine
    /// describes it.
    pub media_address: Option<SocketAddr>,
}

/// One call's media session, as a snapshot saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct MediaState {
    /// Which call.
    pub call: CallHandle,
    /// `None` when another thread was inside the session and the snapshot
    /// did not wait for it.
    pub stream: Option<StreamState>,
}

/// What a media session was doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamState {
    /// The codec it was carrying.
    pub codec: Codec,
    /// Where it was sending.
    pub destination: SocketAddr,
    /// RTP packets sent.
    pub packets_sent: u64,
    /// RTP packets received.
    pub packets_received: u64,
    /// RTP packets the far end sent that never arrived.
    pub packets_lost: u64,
}

/// Everything an engine and its agent were holding, at one moment.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct EngineState {
    /// Every account, oldest first.
    pub accounts: Vec<AccountState>,
    /// Every call the agent still held.
    pub calls: Vec<CallSnapshot>,
    /// Every media session the engine held.
    pub media: Vec<MediaState>,
    /// D3's health counters.
    pub counters: Counters,
}

impl EngineState {
    pub(crate) const fn new(
        accounts: Vec<AccountState>,
        calls: Vec<CallSnapshot>,
        media: Vec<MediaState>,
        counters: Counters,
    ) -> Self {
        Self {
            accounts,
            calls,
            media,
            counters,
        }
    }

    /// The snapshot as text for a crash report, redacted with `redactor` and
    /// at most `limit` bytes long.
    ///
    /// `extra` is appended before the text is redacted and bounded: a layer
    /// above this one — the C ABI's transports and last errors — adds its own
    /// sections there and gets the same two promises for them.
    #[must_use]
    pub fn render(&self, extra: &str, redactor: &mut Redactor, limit: usize) -> String {
        let mut text = String::new();
        self.write(&mut text);
        text.push_str(extra);
        bounded(redact_text(&text, redactor), limit)
    }

    fn write(&self, out: &mut String) {
        out.push_str("sipral engine state\n");
        section(out, "accounts", &self.accounts, |out, account| {
            let registration = account
                .registration
                .map_or_else(|| "unknown".to_owned(), |state| state.to_string());
            let _ = write!(
                out,
                "account {}: {registration}, {}",
                number(account.account),
                account.aor
            );
        });
        section(out, "calls", &self.calls, |out, call| {
            let state = call
                .state
                .map_or_else(|| "unknown".to_owned(), |state| state.to_string());
            let _ = write!(out, "call {}: {state}", number(call.call));
            if let Some(address) = call.media_address {
                let _ = write!(out, ", media at {address}");
            }
        });
        section(out, "media sessions", &self.media, |out, media| {
            let _ = write!(out, "call {}: ", number(media.call));
            match media.stream {
                Some(stream) => {
                    let _ = write!(
                        out,
                        "{} to {}, sent {}, received {}, lost {}",
                        stream.codec,
                        stream.destination,
                        stream.packets_sent,
                        stream.packets_received,
                        stream.packets_lost
                    );
                }
                None => out.push_str("busy on another thread, not waited for"),
            }
        });
        let c = &self.counters;
        let failed = &c.registrations_failed;
        let ended = &c.calls_ended;
        let _ = writeln!(
            out,
            "counters: registrations attempted {}, succeeded {}, failed {} (rejected {}, bad \
             credentials {}, unreachable {}, redirected {}); calls ended {} (local hangup {}, \
             remote hangup {}, refused {}, cancelled {}, unreachable {}, fork lost {}, \
             abandoned {}, expired {}); media gaps {}; jitter buffer events {}; stream transport \
             wanted {}; active calls {}",
            c.registrations_attempted.get(),
            c.registrations_succeeded.get(),
            [
                failed.rejected,
                failed.bad_credentials,
                failed.unreachable,
                failed.redirected
            ]
            .iter()
            .map(|n| n.get())
            .sum::<u64>(),
            failed.rejected.get(),
            failed.bad_credentials.get(),
            failed.unreachable.get(),
            failed.redirected.get(),
            [
                ended.local_hangup,
                ended.remote_hangup,
                ended.refused,
                ended.cancelled,
                ended.unreachable,
                ended.fork_lost,
                ended.abandoned,
                ended.expired,
            ]
            .iter()
            .map(|n| n.get())
            .sum::<u64>(),
            ended.local_hangup.get(),
            ended.remote_hangup.get(),
            ended.refused.get(),
            ended.cancelled.get(),
            ended.unreachable.get(),
            ended.fork_lost.get(),
            ended.abandoned.get(),
            ended.expired.get(),
            c.media_gaps.get(),
            c.jitter_buffer_events.get(),
            c.stream_transport_wanted.get(),
            c.active_calls.get(),
        );
    }
}

/// A handle's number, without the type name `Debug` puts round it.
fn number(handle: impl std::fmt::Debug) -> String {
    format!("{handle:?}")
        .chars()
        .filter(char::is_ascii_digit)
        .collect()
}

/// One section: a header with the count, then up to [`LISTED`] rows.
fn section<T>(out: &mut String, name: &str, rows: &[T], row: impl Fn(&mut String, &T)) {
    let _ = writeln!(out, "{name}: {}", rows.len());
    for one in rows.iter().take(LISTED) {
        out.push_str("  ");
        row(out, one);
        out.push('\n');
    }
    if rows.len() > LISTED {
        let _ = writeln!(out, "  ... and {} more", rows.len() - LISTED);
    }
}

/// The text, cut to `limit` bytes on a character boundary with a marker
/// line when it did not fit.
pub(crate) fn bounded(text: String, limit: usize) -> String {
    const CUT: &str = "\n[truncated]\n";
    if text.len() <= limit {
        return text;
    }
    let mut end = limit.saturating_sub(CUT.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut cut = text.get(..end).unwrap_or("").to_owned();
    if limit >= CUT.len() {
        cut.push_str(CUT);
    }
    cut
}

#[cfg(test)]
mod tests {
    use super::bounded;

    #[test]
    fn a_report_is_cut_to_its_limit_on_a_character_boundary() {
        let text = "é".repeat(100);
        let cut = bounded(text, 51);
        assert!(cut.len() <= 51);
        assert!(cut.ends_with("[truncated]\n"));
        assert_eq!(bounded("short".to_owned(), 51), "short");
    }
}
