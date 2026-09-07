// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Stable C ABI.
//!
//! The single surface that the Swift Package, the NuGet package and the AAR are
//! generated over. Kept deliberately narrow: handles, opaque pointers, and an
//! event callback. Everything expressive lives on the language side.
//!
//! ABI stability rules are in `docs/08-ffi.md`.

#![doc(
    html_logo_url = "https://sipral.org/brand/sipral-mark-256.png",
    html_favicon_url = "https://sipral.org/brand/favicon.svg"
)]
