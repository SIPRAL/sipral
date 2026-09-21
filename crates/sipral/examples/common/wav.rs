// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The smallest WAV file that holds what a call was heard saying: PCM, mono,
//! sixteen-bit, at whatever rate the call negotiated.
//!
//! No dependency for this — a RIFF header is nine fields, and pulling in a
//! WAV-writing crate for `examples/` to prove a machine with no audio device
//! still heard something would be a stranger dependency than the one it
//! replaced.

use std::io::{self, Write};

/// Write `samples` as a mono, sixteen-bit PCM WAV file at `sample_rate_hz`.
pub(crate) fn write(path: &str, sample_rate_hz: u32, samples: &[i16]) -> io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    let sample_count = u32::try_from(samples.len()).unwrap_or(u32::MAX);
    let data_len = sample_count.saturating_mul(2);
    let byte_rate = sample_rate_hz.saturating_mul(2);

    file.write_all(b"RIFF")?;
    file.write_all(&36_u32.saturating_add(data_len).to_le_bytes())?;
    file.write_all(b"WAVE")?;

    file.write_all(b"fmt ")?;
    file.write_all(&16_u32.to_le_bytes())?; // this chunk's own length
    file.write_all(&1_u16.to_le_bytes())?; // PCM, uncompressed
    file.write_all(&1_u16.to_le_bytes())?; // one channel
    file.write_all(&sample_rate_hz.to_le_bytes())?;
    file.write_all(&byte_rate.to_le_bytes())?;
    file.write_all(&2_u16.to_le_bytes())?; // block align: bytes per frame
    file.write_all(&16_u16.to_le_bytes())?; // bits per sample

    file.write_all(b"data")?;
    file.write_all(&data_len.to_le_bytes())?;
    for sample in samples {
        file.write_all(&sample.to_le_bytes())?;
    }
    Ok(())
}
