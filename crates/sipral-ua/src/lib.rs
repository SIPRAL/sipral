// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! User agent layer.
//!
//! Registration with refresh, outgoing and incoming calls, hold and resume,
//! blind and attended transfer, and the SUBSCRIBE/NOTIFY subscriptions behind
//! message waiting and busy lamp field.
//!
//! Also sans-I/O: this is policy and sequencing over [`sipral_core`], not
//! transport.

#![doc(
    html_logo_url = "https://sipral.org/brand/sipral-mark-256.png",
    html_favicon_url = "https://sipral.org/brand/favicon.svg"
)]
