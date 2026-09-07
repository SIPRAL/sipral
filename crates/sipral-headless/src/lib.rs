// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Headless media endpoint.
//!
//! Bidirectional PCM over a local socket or a WebSocket, with no audio device
//! and no media server in the path. This is what an AI voice agent binds to in
//! order to answer a phone call: raw frames in, raw frames out, and barge-in
//! that does not wait on a room abstraction.
//!
//! Protocol in `docs/07-headless.md`.

#![doc(
    html_logo_url = "https://sipral.org/brand/sipral-mark-256.png",
    html_favicon_url = "https://sipral.org/brand/favicon.svg"
)]
