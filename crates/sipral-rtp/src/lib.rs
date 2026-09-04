// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Media transport.
//!
//! RTP and RTCP, the adaptive jitter buffer and packet loss concealment, DTMF
//! events per RFC 4733, and SRTP.
//!
//! The jitter buffer is the part of Sipral that decides whether a call sounds
//! good, so it is written here rather than taken from elsewhere. Its design is
//! in `docs/05-media.md`.
