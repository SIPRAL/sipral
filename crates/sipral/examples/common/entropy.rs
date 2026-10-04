// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The seeds a `UserAgent` and a `MediaEngine` are built with, drawn from the
//! operating system.
//!
//! Neither reads randomness of its own: the application hands each a seed,
//! and everything unpredictable the stack makes comes out of it — tags,
//! branches and Call-IDs from the signalling one, SSRCs, SDES keys and DTLS
//! randomness from the media one. So a seed has to be as unpredictable as
//! those need to be, and a fresh one per run: a constant would send the same
//! Call-ID every time, which a server that remembers the last attempt reads
//! as a retransmission of it and answers with nothing at all. The two are
//! drawn separately, as `MediaEngine::new` asks, so that a recording of the
//! signalling never carries what the media keys were drawn from.

use std::io;

/// Thirty-two octets from the operating system's entropy.
pub(crate) fn seed() -> io::Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|error| io::Error::other(error.to_string()))?;
    Ok(seed)
}
