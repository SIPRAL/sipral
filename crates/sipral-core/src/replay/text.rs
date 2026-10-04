// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The alphabet, which is the whole of the promise that a recording holds no
//! audio.
//!
//! A payload is written as text, one line of the message to a line of the
//! file, with four escapes and no others: `\\`, `\r`, `\n` and `\t`. There is
//! no `\x`, no `\u`, no base64 and no length-prefixed blob anywhere in the
//! format, so a byte outside text has no spelling at all. That is not a rule
//! the writer follows, it is the absence of a way to break it, and
//! [`Payload`](super::Payload) is where the absence is enforced: the only way
//! to make one is from bytes that pass through here.
//!
//! SIP is a text protocol, so this costs nothing on the traffic a recording
//! exists for. What it does cost is stated where it belongs, in
//! `docs/18-replay.md`: a message with a binary body cannot be recorded, and
//! the recorder says so rather than losing the body quietly.

/// Whether a character may stand for itself in the file.
///
/// Above ASCII goes through as it is — a display name in UTF-8 is an ordinary
/// thing to find in a `From` — and everything below a space does not, because
/// a control character in a line-oriented file is either a lie about where the
/// line ends or a byte that got there by accident.
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

/// Whether bytes can be written in the format at all.
///
/// The one predicate the whole promise rests on, and the only door into
/// [`Payload`](super::Payload).
pub(super) fn writable(bytes: &[u8]) -> bool {
    core::str::from_utf8(bytes)
        .is_ok_and(|text| text.chars().all(|ch| escape(ch).is_some() || plain(ch)))
}

/// The payload of one frame, as `|` lines.
///
/// The lines are broken where the message breaks: `split_inclusive` keeps the
/// line ending with the line it ends, so one line of the file is one line of
/// the message. Nothing is added by the split — a reader concatenates the
/// lines and has the bytes back — so a payload with no line ending in it is
/// one long line, and a payload with no bytes is no lines.
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
/// Returns false on anything the writer could not have produced: an escape
/// that does not exist, a reverse solidus with nothing after it, or a control
/// character standing for itself.
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

/// Whether prose the application wrote — a note, a cue label — goes in a
/// line-oriented file as it stands.
///
/// Neither is escaped: they are the application's own words, they are read by
/// a person, and a label that had to be decoded before it could be compared
/// would be a label nobody would trust.
pub(super) fn one_line(text: &str) -> bool {
    !text.is_empty() && text.chars().all(plain)
}
