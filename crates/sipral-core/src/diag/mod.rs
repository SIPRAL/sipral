// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What the stack decided, and why: the diagnostic record.
//!
//! Every call carries an ordered [`Record`]. Each entry is a [`Decision`] with
//! a [`Reason`] a program can match on, the message that caused it, its offset
//! into the call, and the sizes and addresses it turned on. The record can be
//! read while the call is up, outlives it, and serialises to JSON for a bug
//! report.
//!
//! A trace says what arrived; a record says what was decided about it. In the
//! incident `docs/13-client-requirements.md` calls B1, the request was 1785
//! bytes and the path allowed 1299: one entry here, and in no log at all.
//!
//! # Design
//!
//! **Stable codes.** A [`Reason`]'s wire form never changes and is never
//! reused for a different decision. The rules are beside the type.
//!
//! **Bounded memory.** A record holds a fixed number of decisions and an
//! endpoint a fixed number of records ([`RecordLimits`]). Past either limit
//! the oldest goes, and the number dropped is kept and serialised, so a
//! truncated record does not pass for a complete one.
//!
//! **No clock.** Time arrives at the endpoint's entry points. An entry carries
//! a [`Duration`](core::time::Duration) from the record's first entry, and all
//! decisions made in one call into the endpoint share one offset.
//!
//! # Not recorded
//!
//! No bodies, headers, credentials or audio: a method, a status, a size, an
//! address and a `Call-ID`. A user must be able to send a record without
//! reading it first.

mod decision;
mod json;
mod reason;
mod record;

pub use decision::{Decision, Direction, Measure, MethodName, Wire, WireEvent};
pub use reason::Reason;
pub use record::{Record, RecordLimits};

pub(crate) use record::Records;
