// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What the stack decided, and why: the diagnostic record.
//!
//! A call that failed is diagnosed today by asking somebody who does not read
//! logs for a text log, often megabytes of it, and then correlating timestamps
//! by eye until the shape of the failure appears. The expensive part of that
//! is not the bug. It is the reconstruction.
//!
//! So the stack writes its decisions down as it makes them. Every call carries
//! an ordered [`Record`]; every entry is a [`Decision`] with a [`Reason`] a
//! program can match on, the message that caused it, how far into the call it
//! happened, and the sizes and addresses it turned on. The record is readable
//! while the call is still up, it outlives the call, and it serialises to JSON
//! that goes into a bug report unchanged.
//!
//! This is not a message trace. A trace says what arrived, which a capture
//! also says; a record says what was *decided* about it, which nothing else
//! does. The two numbers that mattered in the incident
//! `docs/13-client-requirements.md` calls B1 — the request measured 1785
//! bytes, the path allowed 1299 — are one entry here and are in no log at all.
//!
//! # Three properties, and they are the whole design
//!
//! **The codes are stable.** A [`Reason`]'s wire form never changes and is
//! never handed to a different decision. The rules, and how a variant is added
//! without breaking them, are written beside the type.
//!
//! **The memory is bounded, and the bound is honest.** A record holds a fixed
//! number of decisions and an endpoint holds a fixed number of records
//! ([`RecordLimits`]). Past either ceiling the oldest goes — and the count of
//! what went is kept and serialised, because a record that quietly forgot its
//! first twenty entries answers "what happened first?" with a lie.
//!
//! **No clock is read.** Time arrives at the endpoint's entry points like
//! everything else, and an entry carries a [`Duration`](core::time::Duration)
//! from the record's own first entry rather than an instant. Inside one call
//! into the endpoint no time passes, so every decision that call makes shares
//! one offset — which is not an approximation, it is what a sans-I/O core
//! means.
//!
//! # What is deliberately not in here
//!
//! No message bodies, no headers, no credentials, no audio. A record names a
//! method, a status, a size, an address and a `Call-ID`, and that is the whole
//! list. It is meant to be sent to somebody by a user who cannot be asked to
//! read it first, so it must be safe to send without being read.

mod decision;
mod json;
mod reason;
mod record;

pub use decision::{Decision, Direction, Measure, MethodName, Wire, WireEvent};
pub use reason::Reason;
pub use record::{Record, RecordLimits};

pub(crate) use record::Records;
