// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The wall clock an example's media engine dates its RTCP sender reports by.
//!
//! The library reads no clock, so a program that runs it reads this one once:
//! RFC 3550 §6.4.1 has a sender report carry "the wall clock time when this
//! report was sent", and a reading paired with the instant it was taken is
//! what [`WallClock`] carries on from.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use sipral::WallClock;

/// What the system's wall clock reads at `now`.
pub(crate) fn at(now: Instant) -> WallClock {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    WallClock::from_unix(now, since.as_secs(), since.subsec_nanos())
}
