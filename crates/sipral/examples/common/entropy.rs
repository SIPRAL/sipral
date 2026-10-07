// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The seeds for a `UserAgent` and a `MediaEngine`, drawn from the OS.
//!
//! Neither reads randomness itself; every unpredictable value comes from its seed: tags, branches
//! and Call-IDs from the signalling seed, SSRCs, SDES keys and DTLS randomness from the media seed.
//! A seed must be fresh per run: a constant repeats the Call-ID, which a server reads as a
//! retransmission and ignores. The two are drawn separately, as `MediaEngine::new` requires, so a
//! signalling recording never contains the media key source.

use std::io;

/// Thirty-two octets from the operating system's entropy.
pub(crate) fn seed() -> io::Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|error| io::Error::other(error.to_string()))?;
    Ok(seed)
}
