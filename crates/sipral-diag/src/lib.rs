// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Diagnostics a NOC can act on, out of what `docs/14-diagnostics.md` (D1)
//! and `docs/18-replay.md` (D2) already produce.
//!
//! Two things live here:
//!
//! - [`export()`]: a D2 recording, read back and turned into a pcapng file —
//!   every message the recording holds, as a UDP or TCP packet between the
//!   addresses and at the offsets the recording carries, so Wireshark's own
//!   SIP dissector reads it as a call.
//! - [`redact`]: the same messages with the personal data RFC 3261 and SDP
//!   carry taken out first — user parts, display names, phone numbers and IP
//!   literals become a stable pseudonym or a placeholder, and credentials are
//!   dropped outright — so a recording can leave the organisation.
//!
//! # What a D2 recording is, for this crate's purposes
//!
//! `docs/18-replay.md` is the source of truth. The one fact this crate leans
//! on throughout: a recording holds what *arrived* at the recorded stack and
//! nothing it sent, because nothing here ever offered the recorder a
//! transmitted byte to keep (`crates/sipral-ffi/src/diagnostics.rs`). A
//! pcapng built from one is therefore the far end's half of the
//! conversation — the truth of what is in the file, not a limitation of this
//! exporter. Turning that into a full two-way flow needs the messages this
//! end would have sent replayed back out through the actual engine
//! (`sipral_core::replay::Driven`), which is a second, larger piece of work
//! this crate does not attempt yet.
//!
//! It also never contains audio — RTP arrives at `sipral-rtp` on another
//! socket and is never part of a D2 [`Arrival`](sipral_core::replay::Arrival)
//! — so there is no RTP or RTCP summary for this crate to place in a pcapng
//! today; the day the format gains one, [`export::export`]'s exhaustive match
//! over `Arrival` will refuse to compile until it is taught what to do with
//! it, rather than silently dropping it.

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

pub use export::export;
pub use redact::{Mode, RedactError, Redactor, redact_message, redact_record, redact_record_json};
