// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Reading the RFC's test vectors, which are printed as hexadecimal.

/// The bytes a run of hexadecimal digits stands for.
pub(crate) fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .filter_map(|pair| {
            let high = digit(*pair.first()?)?;
            let low = digit(*pair.get(1)?)?;
            Some(high << 4 | low)
        })
        .collect()
}

/// The same, into a fixed sixteen octets, which is every key in the vectors.
pub(crate) fn unhex16(text: &str) -> [u8; 16] {
    let mut out = [0_u8; 16];
    let bytes = unhex(text);
    if let Some(slot) = out.get_mut(..bytes.len().min(16)) {
        slot.copy_from_slice(bytes.get(..bytes.len().min(16)).unwrap_or_default());
    }
    out
}

/// Lower-case hexadecimal, so a failing assertion prints something that can
/// be compared with the RFC by eye.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(nibble(byte >> 4)));
        out.push(char::from(nibble(byte & 0x0f)));
    }
    out
}

const fn nibble(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + value - 10,
    }
}

const fn digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
