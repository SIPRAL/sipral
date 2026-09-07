// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Audio pipeline.
//!
//! Resampling, mixing, codec framing, and the seam where an external echo
//! canceller, gain control and noise suppressor are attached.
//!
//! Echo cancellation itself is signal processing research, not product, and is
//! linked from a permissively licensed implementation rather than written here.

#![doc(
    html_logo_url = "https://sipral.org/brand/sipral-mark-256.png",
    html_favicon_url = "https://sipral.org/brand/favicon.svg"
)]
