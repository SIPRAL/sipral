// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! NAT traversal.
//!
//! STUN and TURN clients and ICE-lite. Symmetric RTP with rport covers most
//! carriers on its own; the rest is what this crate is for.

#![doc(
    html_logo_url = "https://sipral.org/brand/sipral-mark-256.png",
    html_favicon_url = "https://sipral.org/brand/favicon.svg"
)]
