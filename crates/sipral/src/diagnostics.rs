// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A call's diagnostics, redacted before they leave the organisation.
//!
//! `docs/14-diagnostics.md` has two artefacts a support incident is worked
//! from: the D1 record — what the stack decided about a call, as JSON — and
//! the D2 recording — every message that arrived, replayable, and exported
//! as pcapng for the tools a NOC already has. Both carry personal data: the
//! record the addresses a call was carried between, the recording that and
//! every user part, display name and phone number the messages name.
//!
//! These two functions hand either one over with that data taken out by
//! `sipral-diag`'s redaction, under a [`Redactor`] the application builds
//! once per export: [`RedactionMode::Hash`] with the organisation's own key,
//! so the same address or user always becomes the same pseudonym and a
//! report stays correlatable to whoever holds the key, or
//! [`RedactionMode::Delete`] for placeholders that mean nothing outside the
//! one export. Credentials and SDES keys are dropped in either mode.
//!
//! One redactor for both halves of a report, the record first and then the
//! recording, gives an address the same pseudonym in the two, so the
//! decision that names a far end and the packets from it still line up.

use sipral_core::dialog::CallId;
pub use sipral_diag::{
    ExportError, Mode as RedactionMode, RedactError, Redactor, Replayed, redact_text,
};
use std::time::Instant;

use sipral_ua::{CallHandle, Recording, UserAgent};

/// One call's D1 record, redacted, as the JSON `docs/14-diagnostics.md`
/// describes.
///
/// `None` when the call is not known to `agent` any more, or has no record:
/// one that never sent or received a message has had nothing decided about
/// it. Read it while the call is still held, as with
/// [`UserAgent::call_identity`], which is how the record is found.
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

/// A D2 recording — what [`UserAgent::stop_recording`] hands back — as a
/// pcapng file with every message redacted, and every packet's own
/// addresses with it.
///
/// # Errors
/// [`RedactError`] when a message in the recording is not one the parser
/// can read. Nothing is returned then, rather than a file with a message in
/// it nobody redacted.
pub fn redacted_recording(
    recording: &Recording,
    redactor: Redactor,
) -> Result<Vec<u8>, RedactError> {
    sipral_diag::export(recording, Some(redactor))
}

/// A D2 recording replayed into `target`, as one pcapng file with both
/// directions of the session in it, every message redacted.
///
/// A recording holds only what arrived; [`redacted_recording`] exports
/// that. This feeds it back into a live layer built with
/// [`Recording::seed`] and the configuration the recorded stack ran with,
/// and places every message the layer writes in answer beside what arrived,
/// marked outbound — so the NOC reads the call the way a capture taken at
/// this end would show it. What the application did on its own comes back
/// to [`Replayed::cue`], under the name the recording gave it, for the
/// caller to do again; see `sipral_diag::export_replayed`.
///
/// # Errors
/// [`ExportError::Replay`] when `target` refuses a frame, and
/// [`ExportError::Redact`] when a message cannot be read to be redacted.
pub fn replayed_capture<T: Replayed>(
    recording: &Recording,
    target: &mut T,
    origin: Instant,
    redactor: Redactor,
) -> Result<Vec<u8>, ExportError> {
    sipral_diag::export_replayed(recording, target, origin, Some(redactor))
}
