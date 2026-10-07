// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A call's diagnostics, redacted before they leave the organisation.
//!
//! `docs/14-diagnostics.md` defines the D1 record (the stack's decisions about a call, as JSON) and
//! the D2 recording (every message received, replayable, exportable as pcapng). Both contain
//! personal data: addresses, user parts, display names, phone numbers.
//!
//! These functions export either with that data removed by `sipral-diag` under a [`Redactor`] built
//! once per export: [`RedactionMode::Hash`] with the organisation's key gives stable pseudonyms the
//! key holder can correlate; [`RedactionMode::Delete`] gives placeholders meaningful only within
//! the export. Credentials and SDES keys are always dropped.
//!
//! Use one redactor for both halves of a report, record first, so an address gets the same
//! pseudonym in each.

use sipral_core::dialog::CallId;
pub use sipral_diag::{
    ExportError, Mode as RedactionMode, RedactError, Redactor, Replayed, redact_text,
};
use std::time::Instant;

use sipral_ua::{CallHandle, Recording, UserAgent};

/// One call's D1 record, redacted, as the JSON `docs/14-diagnostics.md` describes.
///
/// `None` if `agent` no longer knows the call, or it has no record (no message was ever sent or
/// received). Read it while the call is still held, like [`UserAgent::call_identity`].
#[must_use]
pub fn redacted_call_record(
    agent: &mut UserAgent,
    call: CallHandle,
    redactor: &mut Redactor,
) -> Option<String> {
    let identity = agent.call_identity(call)?;
    let record = agent
        .endpoint()
        .call_record(&CallId::new(&identity.call_id))?;
    Some(sipral_diag::redact_record(record, redactor))
}

/// A D2 recording (from [`UserAgent::stop_recording`]) as pcapng, with every message and packet
/// address redacted.
///
/// # Errors
///
/// [`RedactError`] when a message cannot be parsed. Nothing is returned then, rather than a file
/// with an unredacted message.
pub fn redacted_recording(
    recording: &Recording,
    redactor: Redactor,
) -> Result<Vec<u8>, RedactError> {
    sipral_diag::export(recording, Some(redactor))
}

/// A D2 recording replayed into `target`, as one pcapng with both directions, every message
/// redacted.
///
/// A recording holds only what arrived ([`redacted_recording`] exports that). This replays it into
/// a live layer built from [`Recording::seed`] and the recorded configuration, and adds every
/// message the layer writes as outbound, so the NOC sees the call as a local capture would.
/// Application actions come back to [`Replayed::cue`] under their recorded names for the caller to
/// repeat; see `sipral_diag::export_replayed`.
///
/// # Errors
///
/// [`ExportError::Replay`] when `target` refuses a frame, [`ExportError::Redact`] when a message
/// cannot be parsed for redaction.
pub fn replayed_capture<T: Replayed>(
    recording: &Recording,
    target: &mut T,
    origin: Instant,
    redactor: Redactor,
) -> Result<Vec<u8>, ExportError> {
    sipral_diag::export_replayed(recording, target, origin, Some(redactor))
}
