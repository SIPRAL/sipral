// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Audio for a SIP call.
//!
//! What is here is G.711: the two companding laws every carrier still accepts,
//! in both directions, with the arithmetic a caller needs to cut a frame.
//!
//! Nothing here opens a device or a socket. Samples arrive in a slice and
//! leave in one, so the whole crate is testable without either.

#![doc(
    html_logo_url = "https://sipral.org/brand/sipral-mark-256.png",
    html_favicon_url = "https://sipral.org/brand/favicon.svg"
)]
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

pub mod g711;
