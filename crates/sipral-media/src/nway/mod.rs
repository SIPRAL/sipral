// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! An N-way conference: every participant hears everyone else.
//!
//! [`limiter`] keeps the sum of many legs inside the range a sample has.

pub mod limiter;

pub use limiter::Limiter;
