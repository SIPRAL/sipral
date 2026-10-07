// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The alphabet, which is why a recording cannot hold audio.
//!
//! Text, one message line per file line, four escapes: `\\`, `\r`, `\n`,
//! `\t`. No `\x`, no base64, no blob, so a non-text byte has no spelling.
//! [`Payload`](super::Payload) can only be built through here. A binary SIP
//! body cannot be recorded either (`docs/18-replay.md`).

/// Whether a character may stand for itself in the file.
///
/// UTF-8 passes (display names); control characters do not, since in a
/// line-oriented file they would lie about where a line ends.
fn plain(ch: char) -> bool {
    !ch.is_control()
}

/// How a character is spelled when it cannot stand for itself, and `None`
/// when it can.
const fn escape(ch: char) -> Option<&'static str> {
    match ch {
        '\\' => Some("\\\\"),
        '\r' => Some("\\r"),
        '\n' => Some("\\n"),
        '\t' => Some("\\t"),
        _ => None,
    }
}

/// Whether bytes can be written in the format at all; the only door into
/// [`Payload`](super::Payload).
pub(super) fn writable(bytes: &[u8]) -> bool {
    core::str::from_utf8(bytes)
        .is_ok_and(|text| text.chars().all(|ch| escape(ch).is_some() || plain(ch)))
}

/// The payload of one frame, as `|` lines.
///
/// `split_inclusive` keeps each line ending, so concatenating the lines gives
/// the bytes back. No bytes means no lines.
pub(super) fn write_payload(out: &mut String, payload: &[u8]) {
    for line in String::from_utf8_lossy(payload).split_inclusive('\n') {
        out.push_str("| ");
        for ch in line.chars() {
            match escape(ch) {
                Some(spelled) => out.push_str(spelled),
                None => out.push(ch),
            }
        }
        out.push('\n');
    }
}

/// One `|` line, appended to the payload it belongs to.
///
/// False on anything the writer could not have produced.
pub(super) fn read_payload(line: &str, out: &mut Vec<u8>) -> bool {
    let mut chars = line.chars();
    while let Some(ch) = chars.next() {
        let decoded = match ch {
            '\\' => match chars.next() {
                Some('\\') => '\\',
                Some('r') => '\r',
                Some('n') => '\n',
                Some('t') => '\t',
                _ => return false,
            },
            other if plain(other) => other,
            _ => return false,
        };
        let mut buffer = [0_u8; 4];
        out.extend_from_slice(decoded.encode_utf8(&mut buffer).as_bytes());
    }
    true
}

/// Whether a note or cue label fits on one line as it stands.
///
/// Not escaped: people read and compare them.
pub(super) fn one_line(text: &str) -> bool {
    !text.is_empty() && text.chars().all(plain)
}
