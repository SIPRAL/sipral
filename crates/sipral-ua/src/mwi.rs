// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! `application/simple-message-summary` (RFC 3842 §3.5, §5.2).
//!
//! A text format, not XML, but the same threat model as
//! [`crate::dialoginfo`]: the bytes arrive over UDP from whoever answered a
//! SUBSCRIBE to `message-summary`, and every bound here exists because there
//! is no version of "read a bit further" that is safe on that path. The
//! grammar is small — one status line, one optional account line, and zero
//! or more `class: new/old (urgent-new/urgent-old)` summary lines, each
//! ending in CRLF — and §5.2's `opt-msg-headers` production makes a blank
//! line the end of what this reads: RFC 2822-style headers about individual
//! new messages may follow it, and this parser stops there rather than
//! reading them, because the plan never asked for them and a bound that
//! stops at a blank line is one attacker-controlled "headers" cannot grow
//! past.
//!
//! **A repeated field wins the last write**, the same leniency
//! [`crate::dialoginfo`] gives a version that repeats: nothing in §5.2 says
//! two `Voice-Message` lines in one body are wrong, and refusing the whole
//! document over it would throw away a lamp's actual count for a
//! notifier's formatting quirk.

use core::fmt;

/// The largest body that is read at all. A message-summary body is a
/// handful of short lines; this is an order of magnitude above the largest
/// real one, the way [`crate::dialoginfo::MAX_BYTES`] is.
const MAX_BYTES: usize = 16 * 1024;
/// How many lines of the status/account/summary block are read before the
/// document is refused. Real bodies have one status line, at most one
/// account line and a handful of message-context-classes (RFC 3458 §6.2
/// lists six); this is generous room for extension classes and still a
/// bound on the loop.
const MAX_LINES: usize = 64;
/// The longest one line may be.
const MAX_LINE_BYTES: usize = 512;
/// The longest a message-context-class token may be.
const MAX_CLASS_BYTES: usize = 64;
/// The longest `Message-Account` value kept.
const MAX_ACCOUNT_BYTES: usize = 256;
/// §5.2's `msgcount = 1*DIGIT ; MUST NOT exceed 2^32-1`: ten digits holds
/// every legal value, and two more is room to notice a longer run is not one
/// of them without parsing an unbounded string of digits first.
const MAX_COUNT_DIGITS: usize = 12;

/// Why a message-summary body could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MessageSummaryError {
    /// The body is not UTF-8. §5.2 writes the grammar in ASCII throughout,
    /// and a `Message-Account` naming a non-ASCII address of record is still
    /// UTF-8 by construction.
    NotUtf8,
    /// One of the bounds in this module was reached.
    TooLarge(&'static str),
    /// The body does not follow §5.2's grammar.
    Malformed(&'static str),
}

impl fmt::Display for MessageSummaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NotUtf8 => f.write_str("not UTF-8"),
            Self::TooLarge(what) => write!(f, "too large: {what}"),
            Self::Malformed(what) => write!(f, "malformed message summary: {what}"),
        }
    }
}

impl core::error::Error for MessageSummaryError {}

/// One message-context-class's counts (§5.2's `msg-summary-line`).
///
/// RFC 3458 §6.2 names six: `voice-message`, `fax-message`, `pager-message`,
/// `multimedia-message`, `text-message` and `none`; a notifier may report a
/// class this build has never heard the name of, and it is kept the same as
/// any other — the class name is not this stack's to judge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageClass {
    /// The class token, as written.
    pub name: Box<str>,
    /// New messages of this class.
    pub new: u32,
    /// Old ones.
    pub old: u32,
    /// New ones flagged urgent. §5.2's urgent counts are optional; absent,
    /// both are zero.
    pub new_urgent: u32,
    /// Old ones flagged urgent.
    pub old_urgent: u32,
}

/// One `application/simple-message-summary` document (§3.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageSummary {
    /// The status line: "the traditional boolean message waiting
    /// notification" (§3.5), and the one field every notifier sends, even
    /// one with nothing more detailed to report.
    pub waiting: bool,
    /// `Message-Account`, when the notifier sent one. §3.5 makes it
    /// mandatory only when the SUBSCRIBE named "a group or collection of
    /// individual messaging accounts"; a subscription to one address of
    /// record usually gets none.
    pub account: Option<Box<str>>,
    /// Every class the body reported, in the order it listed them.
    pub classes: Vec<MessageClass>,
}

impl MessageSummary {
    /// Read one document.
    ///
    /// # Errors
    /// [`MessageSummaryError`].
    pub fn parse(body: &[u8]) -> Result<Self, MessageSummaryError> {
        if body.len() > MAX_BYTES {
            return Err(MessageSummaryError::TooLarge("document"));
        }
        let text = core::str::from_utf8(body).map_err(|_| MessageSummaryError::NotUtf8)?;

        let mut lines = text.lines();
        let first = lines
            .next()
            .ok_or(MessageSummaryError::Malformed("empty body"))?;
        checked(first)?;
        let waiting = status_line(first)?;

        let mut account = None;
        let mut classes: Vec<MessageClass> = Vec::new();
        for (seen, line) in lines.enumerate() {
            if seen >= MAX_LINES {
                return Err(MessageSummaryError::TooLarge("lines"));
            }
            // §5.2's `opt-msg-headers` starts with a CRLF of its own: a
            // blank line is where the summary block ends and the optional
            // per-message RFC 2822 headers this reader never wants begin
            if line.trim().is_empty() {
                break;
            }
            checked(line)?;
            let (name, value) = split_field(line)?;
            if name.eq_ignore_ascii_case("Message-Account") {
                let value = value.trim();
                if value.len() > MAX_ACCOUNT_BYTES {
                    return Err(MessageSummaryError::TooLarge("Message-Account"));
                }
                account = Some(Box::from(value));
                continue;
            }
            if classes.len() >= MAX_LINES {
                return Err(MessageSummaryError::TooLarge("classes"));
            }
            classes.push(summary_line(name, value)?);
        }

        Ok(Self {
            waiting,
            account,
            classes,
        })
    }

    /// The `voice-message` class (RFC 3458 §6.2), which is the one a phone's
    /// message-waiting light is about. `None` when the body carried no
    /// summary line for it — a notifier that only ever sends the boolean
    /// status line is within §3.5.
    ///
    /// The last line of that class wins when a body repeats it: see this
    /// module's doc comment.
    #[must_use]
    pub fn voice_message(&self) -> Option<&MessageClass> {
        self.classes
            .iter()
            .rev()
            .find(|class| class.name.eq_ignore_ascii_case("voice-message"))
    }
}

/// A line within the bounds this reader holds every line to.
fn checked(line: &str) -> Result<(), MessageSummaryError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(MessageSummaryError::TooLarge("line"));
    }
    Ok(())
}

/// `Messages-Waiting: yes` or `Messages-Waiting: no` (§5.2's
/// `msg-status-line`), which must be the first line (§5.2's grammar has
/// nothing else be).
fn status_line(line: &str) -> Result<bool, MessageSummaryError> {
    let (name, value) = split_field(line)?;
    if !name.eq_ignore_ascii_case("Messages-Waiting") {
        return Err(MessageSummaryError::Malformed(
            "the first line is not Messages-Waiting",
        ));
    }
    let value = value.trim();
    if value.eq_ignore_ascii_case("yes") {
        Ok(true)
    } else if value.eq_ignore_ascii_case("no") {
        Ok(false)
    } else {
        Err(MessageSummaryError::Malformed(
            "msg-status is neither yes nor no",
        ))
    }
}

/// `name: value`, split on the first colon (§5.2's `HCOLON`, read leniently:
/// this is a body, not a SIP header field, and nothing here needs the
/// folding rules a real header field has).
fn split_field(line: &str) -> Result<(&str, &str), MessageSummaryError> {
    let colon = line
        .find(':')
        .ok_or(MessageSummaryError::Malformed("a line with no colon"))?;
    let name = line.get(..colon).unwrap_or_default().trim();
    let value = line.get(colon + 1..).unwrap_or_default();
    if name.is_empty() {
        return Err(MessageSummaryError::Malformed("a line with no field name"));
    }
    Ok((name, value))
}

/// One `msg-summary-line`: `class: new/old` or `class: new/old (nu/ou)`.
fn summary_line(name: &str, value: &str) -> Result<MessageClass, MessageSummaryError> {
    if name.is_empty() || name.len() > MAX_CLASS_BYTES {
        return Err(MessageSummaryError::TooLarge("message-context-class"));
    }
    let value = value.trim();
    let (counts, urgent) = match value.split_once('(') {
        Some((counts, rest)) => {
            let urgent =
                rest.trim_end()
                    .strip_suffix(')')
                    .ok_or(MessageSummaryError::Malformed(
                        "the urgent counts never close",
                    ))?;
            (counts.trim(), Some(urgent.trim()))
        }
        None => (value, None),
    };
    let (new, old) = split_counts(counts)?;
    let (new_urgent, old_urgent) = match urgent {
        Some(pair) => split_counts(pair)?,
        None => (0, 0),
    };
    Ok(MessageClass {
        name: Box::from(name),
        new,
        old,
        new_urgent,
        old_urgent,
    })
}

/// `newmsgs SLASH oldmsgs`, or the urgent pair inside the parentheses — the
/// same shape either way.
fn split_counts(text: &str) -> Result<(u32, u32), MessageSummaryError> {
    let (left, right) = text
        .split_once('/')
        .ok_or(MessageSummaryError::Malformed("counts need a slash"))?;
    Ok((msgcount(left.trim())?, msgcount(right.trim())?))
}

/// §5.2's `msgcount = 1*DIGIT ; MUST NOT exceed 2^32-1`, and its own rule for
/// the far side of that: "Subscribers MUST treat a larger value as
/// 2^32-1" — so an oversized count saturates rather than erroring, the one
/// place this reader is asked to accept a value it cannot represent exactly.
fn msgcount(text: &str) -> Result<u32, MessageSummaryError> {
    if text.is_empty()
        || text.len() > MAX_COUNT_DIGITS
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(MessageSummaryError::Malformed("not a message count"));
    }
    Ok(text
        .parse::<u64>()
        .map_or(u32::MAX, |value| u32::try_from(value).unwrap_or(u32::MAX)))
}

#[cfg(test)]
mod tests {
    use super::{MAX_BYTES, MAX_LINE_BYTES, MessageSummary, MessageSummaryError};

    /// RFC 3842 §4.1's message A3, verbatim (CRLF line endings, as it
    /// travels on the wire).
    const SAMPLE: &[u8] = b"Messages-Waiting: yes\r\n\
Message-Account: sip:alice@vmail.example.com\r\n\
Voice-Message: 2/8 (0/2)\r\n";

    #[test]
    fn the_rfcs_own_sample_reads_as_the_rfc_describes_it() {
        let summary = MessageSummary::parse(SAMPLE).expect("a document");
        assert!(summary.waiting);
        assert_eq!(
            summary.account.as_deref(),
            Some("sip:alice@vmail.example.com")
        );
        let voice = summary.voice_message().expect("a voice-message line");
        assert_eq!(voice.new, 2);
        assert_eq!(voice.old, 8);
        assert_eq!(voice.new_urgent, 0);
        assert_eq!(voice.old_urgent, 2);
    }

    #[test]
    fn message_a5s_body_with_headers_after_the_blank_line_stops_at_the_blank_line() {
        let body = b"Messages-Waiting: yes\r\n\
Message-Account: sip:alice@vmail.example.com\r\n\
Voice-Message: 4/8 (1/2)\r\n\
\r\n\
To: <alice@atlanta.example.com>\r\n\
From: <bob@biloxi.example.com>\r\n";
        let summary = MessageSummary::parse(body).expect("a document");
        let voice = summary.voice_message().expect("a voice-message line");
        assert_eq!((voice.new, voice.old), (4, 8));
        assert_eq!((voice.new_urgent, voice.old_urgent), (1, 2));
    }

    #[test]
    fn a_boolean_only_body_is_legal_and_names_no_class() {
        let summary = MessageSummary::parse(b"Messages-Waiting: no\r\n").expect("a document");
        assert!(!summary.waiting);
        assert_eq!(summary.account, None);
        assert!(summary.voice_message().is_none());
    }

    #[test]
    fn a_count_without_a_urgent_pair_leaves_it_at_zero() {
        let summary = MessageSummary::parse(b"Messages-Waiting: yes\r\nFax-Message: 1/0\r\n")
            .expect("a document");
        let fax = summary
            .classes
            .iter()
            .find(|class| &*class.name == "Fax-Message")
            .expect("a fax-message line");
        assert_eq!((fax.new, fax.old), (1, 0));
        assert_eq!((fax.new_urgent, fax.old_urgent), (0, 0));
    }

    #[test]
    fn a_count_past_2_32_minus_1_saturates_rather_than_erroring() {
        let summary =
            MessageSummary::parse(b"Messages-Waiting: yes\r\nVoice-Message: 99999999999/0\r\n")
                .expect("a document");
        assert_eq!(summary.voice_message().expect("a line").new, u32::MAX);
    }

    #[test]
    fn the_first_line_must_be_the_status_line() {
        assert_eq!(
            MessageSummary::parse(b"Voice-Message: 1/0\r\n"),
            Err(MessageSummaryError::Malformed(
                "the first line is not Messages-Waiting"
            ))
        );
    }

    #[test]
    fn a_status_that_is_not_yes_or_no_is_refused() {
        assert_eq!(
            MessageSummary::parse(b"Messages-Waiting: maybe\r\n"),
            Err(MessageSummaryError::Malformed(
                "msg-status is neither yes nor no"
            ))
        );
    }

    #[test]
    fn malformed_bodies_are_refused_rather_than_guessed_at() {
        for body in [
            &b""[..],
            &b"not a message summary at all"[..],
            &b"Messages-Waiting yes\r\n"[..],
            &b"Messages-Waiting: yes\r\nVoice-Message: 1\r\n"[..],
            &b"Messages-Waiting: yes\r\nVoice-Message: a/b\r\n"[..],
            &b"Messages-Waiting: yes\r\nVoice-Message: 1/2 (0\r\n"[..],
            &b"Messages-Waiting: yes\r\n: 1/2\r\n"[..],
            b"Messages-Waiting: yes\r\n\xff\xfe\r\n",
        ] {
            assert!(
                MessageSummary::parse(body).is_err(),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn a_document_over_the_byte_bound_is_refused_before_it_is_read() {
        let mut body = b"Messages-Waiting: yes\r\n".to_vec();
        body.extend(std::iter::repeat_n(b'x', MAX_BYTES));
        assert_eq!(
            MessageSummary::parse(&body),
            Err(MessageSummaryError::TooLarge("document"))
        );
    }

    #[test]
    fn a_single_line_over_its_own_bound_is_refused() {
        // one absurdly long class name on the second line: still under
        // MAX_BYTES, but the per-line bound catches it first
        let mut long = b"Messages-Waiting: yes\r\n".to_vec();
        long.extend(std::iter::repeat_n(b'a', MAX_LINE_BYTES + 1));
        long.extend_from_slice(b": 1/0\r\n");
        assert_eq!(
            MessageSummary::parse(&long),
            Err(MessageSummaryError::TooLarge("line"))
        );
    }

    #[test]
    fn several_classes_are_all_kept_in_order() {
        let summary = MessageSummary::parse(
            b"Messages-Waiting: yes\r\nVoice-Message: 1/0\r\nFax-Message: 0/2\r\n",
        )
        .expect("a document");
        assert_eq!(summary.classes.len(), 2);
        assert_eq!(&*summary.classes[0].name, "Voice-Message");
        assert_eq!(&*summary.classes[1].name, "Fax-Message");
    }

    #[test]
    fn a_repeated_field_keeps_the_last_write() {
        // several PBXs are lenient about ordering; nothing in 5.2 forbids
        // two lines for the same class, and losing the count would be worse
        // than keeping whichever one arrived last
        let summary = MessageSummary::parse(
            b"Messages-Waiting: yes\r\nVoice-Message: 1/0\r\nVoice-Message: 2/1\r\n",
        )
        .expect("a document");
        assert_eq!(summary.classes.len(), 2, "both lines are kept, unmerged");
        assert_eq!(
            summary.voice_message().map(|class| class.new),
            Some(2),
            "the last line of a repeated class is the one read back"
        );
    }
}
