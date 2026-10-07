// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Diagnostics a NOC can act on, built from D1 (`docs/14-diagnostics.md`)
//! and D2 (`docs/18-replay.md`) output.
//!
//! - [`export()`]: a D2 recording as a pcapng file that Wireshark reads as a call.
//! - [`export_replayed()`]: the same, plus the messages this end writes when
//!   the recording is replayed into a live layer.
//! - [`redact`]: strips personal data and credentials so a recording can
//!   leave the organisation.
//!
//! A recording holds only what *arrived*, never what was sent, so
//! [`export()`] gives the far end's half; [`export_replayed()`] regenerates
//! the other half by replaying under the recorded seed. Recordings carry no
//! RTP (see [`Arrival`](sipral_core::replay::Arrival)).

// tests say what they mean; the no-panic discipline is for the library
#![cfg_attr(
    test,
    allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )
)]

pub mod export;
pub mod packet;
pub mod pcapng;
pub mod redact;

pub use export::{ExportError, Replayed, export, export_replayed};
pub use redact::{
    Mode, RedactError, Redactor, derive_key, redact_message, redact_record, redact_record_json,
    redact_text, strip_secrets, strip_secrets_text,
};
