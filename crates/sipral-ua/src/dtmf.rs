// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A digit sent or received by SIP INFO (RFC 6086), and the validation every
//! way a digit crosses this stack's boundary shares.
//!
//! Neither body has an RFC: `application/dtmf-relay` (`Signal=`,
//! `Duration=`) comes from an expired draft, `application/dtmf` (a bare
//! character) is a convention. The lab's `Flow::DtmfInfo` exercises the
//! relay form against Asterisk; see `docs/04-ua.md`.
//!
//! [`digit`](crate::dtmf::digit) validates every path (RFC 4733, INFO out,
//! INFO in). [`duration_ms`](crate::dtmf::duration_ms) gives every sending
//! form the same floor, ceiling and 100 ms default.
//! [`received_duration_ms`](crate::dtmf::received_duration_ms) checks only
//! the ceiling: a peer's `Duration=0` means zero, not the default.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use sipral_core::endpoint::{Event, OutgoingInDialogRequest, OutgoingResponse};
use sipral_core::msg::{HeaderName, MediaTypeRef, Method, RawMessage, StatusCode, digits, trim};
use sipral_core::transaction::AnyTransactionId;

use crate::agent::UserAgent;
use crate::call::CallHandle;
use crate::error::UaError;
use crate::event::UaEvent;

/// The sixteen events a keypad has (RFC 4733 §3.2, Table 3).
pub const KEYPAD: &[u8] = b"0123456789*#ABCD";

/// Tone length when none is given, the same for RTP, both INFO bodies and
/// the C ABI. RFC 4733 §2.5.2.2 gives no figure; 100 ms is well above the
/// floor and keeps a run of keys short.
pub const DEFAULT_DTMF_MS: u32 = 100;

/// Shortest tone equipment recognises (RFC 4733 §2.5.2.1, citing ITU-T Q.24
/// Table A-1). INFO digits become tones too, so it applies to every form.
pub const MIN_DTMF_MS: u32 = 40;

/// Longer than any real key press; catches seconds passed as milliseconds.
pub const MAX_DTMF_MS: u32 = 10_000;

/// `Signal=` and `Duration=` lines.
pub const RELAY: &[u8] = b"application/dtmf-relay";
/// The body is the character alone.
pub const PLAIN: &[u8] = b"application/dtmf";

/// One digit needs under 30 octets; the rest is room for whitespace.
const MAX_INFO_BODY: usize = 256;

/// Why a digit or a duration was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DtmfError {
    /// Not one of the sixteen keys a keypad has.
    UnknownDigit,
    /// Longer than any key is actually held.
    ToneTooLong(u32),
    /// Shorter than [`MIN_DTMF_MS`], which equipment does not recognise.
    ToneTooShort(u32),
}

impl core::fmt::Display for DtmfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::UnknownDigit => f.write_str("not one of the sixteen keys a keypad has"),
            Self::ToneTooLong(held) => {
                write!(f, "a tone of {held} ms is longer than any key is held")
            }
            Self::ToneTooShort(held) => write!(
                f,
                "a tone of {held} ms is shorter than the {MIN_DTMF_MS} ms equipment recognises"
            ),
        }
    }
}

impl core::error::Error for DtmfError {}

/// The upper-cased key `pressed` names, or which one it is not.
///
/// # Errors
/// [`DtmfError::UnknownDigit`] for a byte none of the sixteen keys is.
pub fn digit(pressed: u8) -> Result<u8, DtmfError> {
    let upper = pressed.to_ascii_uppercase();
    if KEYPAD.contains(&upper) {
        Ok(upper)
    } else {
        Err(DtmfError::UnknownDigit)
    }
}

/// `asked`, or the default when it is zero, or which bound it broke.
///
/// # Errors
/// [`DtmfError::ToneTooShort`] under [`MIN_DTMF_MS`] and
/// [`DtmfError::ToneTooLong`] past [`MAX_DTMF_MS`].
pub fn duration_ms(asked: u32) -> Result<u32, DtmfError> {
    match asked {
        0 => Ok(DEFAULT_DTMF_MS),
        held if held < MIN_DTMF_MS => Err(DtmfError::ToneTooShort(held)),
        held if held <= MAX_DTMF_MS => Ok(held),
        held => Err(DtmfError::ToneTooLong(held)),
    }
}

/// A peer's `Duration=`. Only the ceiling applies: the floor and the zero
/// default exist for tones this end generates, and a peer's zero means zero.
///
/// # Errors
/// [`DtmfError::ToneTooLong`] past [`MAX_DTMF_MS`].
pub fn received_duration_ms(asked: u32) -> Result<u32, DtmfError> {
    if asked > MAX_DTMF_MS {
        Err(DtmfError::ToneTooLong(asked))
    } else {
        Ok(asked)
    }
}

/// Which of the two bodies an INFO this end sends carries.
///
/// Chosen per send: which one a peer takes is found by trying (see
/// [`UserAgent::send_dtmf_info`](crate::UserAgent::send_dtmf_info)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DtmfInfoForm {
    /// `application/dtmf-relay`: `Signal=` and `Duration=` lines.
    Relay,
    /// `application/dtmf`: the whole body is the character.
    Plain,
}

pub(crate) fn relay_body(key: u8, held_ms: u32) -> Arc<[u8]> {
    let mut body = Vec::with_capacity(32);
    body.extend_from_slice(b"Signal=");
    body.push(key);
    body.extend_from_slice(b"\r\nDuration=");
    body.extend_from_slice(held_ms.to_string().as_bytes());
    body.extend_from_slice(b"\r\n");
    Arc::from(body)
}

/// A digit read from an INFO body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DtmfInfo {
    /// The key, upper-cased.
    pub digit: char,
    /// The relay form's `Duration=`, if present; never in the plain form.
    pub held_ms: Option<u32>,
}

/// Why an incoming INFO's body was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InfoRefusal {
    /// No `Content-Type`, or one that is not `application/dtmf-relay` or
    /// `application/dtmf` (RFC 3261 §21.4.13).
    UnsupportedType,
    /// Not exactly one readable digit, too long, or a duration over the
    /// ceiling (RFC 3261 §21.4.1).
    Malformed,
}

impl InfoRefusal {
    /// The status this refusal is answered with.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::UnsupportedType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::Malformed => StatusCode::BAD_REQUEST,
        }
    }
}

fn is_dtmf_media(media: &MediaTypeRef<'_>) -> bool {
    media.kind().eq_ignore_ascii_case(b"application")
        && (media.subtype().eq_ignore_ascii_case(b"dtmf-relay")
            || media.subtype().eq_ignore_ascii_case(b"dtmf"))
}

/// Whether this module claims the INFO. RFC 6086 INFO is not only for DTMF
/// (e.g. RFC 5168), so any other `Content-Type`, or no body, is left for
/// the application. A malformed DTMF body is still ours and gets a 400.
#[must_use]
pub(crate) fn names_a_dtmf_body(content_type: Option<&[u8]>) -> bool {
    content_type
        .and_then(|value| MediaTypeRef::parse(value).ok())
        .is_some_and(|media| is_dtmf_media(&media))
}

/// Read an incoming INFO's DTMF body, never panicking on any input.
///
/// `content_type` is the header value, if any; `body` the whole body.
/// [`MediaTypeRef::parse`] and [`digits`] are the stack's shared bounded
/// readers.
///
/// # Errors
/// [`InfoRefusal`] naming which of RFC 3261 §21.4.13 or §21.4.1 applies.
pub fn parse_info(content_type: Option<&[u8]>, body: &[u8]) -> Result<DtmfInfo, InfoRefusal> {
    let Some(content_type) = content_type else {
        return Err(InfoRefusal::UnsupportedType);
    };
    let media = MediaTypeRef::parse(content_type).map_err(|_| InfoRefusal::UnsupportedType)?;
    if !is_dtmf_media(&media) {
        return Err(InfoRefusal::UnsupportedType);
    }
    let relay = media.subtype().eq_ignore_ascii_case(b"dtmf-relay");
    // right type, so too long is malformed, not unsupported
    if body.len() > MAX_INFO_BODY {
        return Err(InfoRefusal::Malformed);
    }
    if relay {
        parse_relay(body)
    } else {
        parse_plain(body)
    }
}

/// [`parse_info`] on a whole request.
///
/// # Errors
/// As [`parse_info`].
pub fn parse_incoming(request: &RawMessage<'_>) -> Result<DtmfInfo, InfoRefusal> {
    parse_info(request.header(HeaderName::ContentType), request.body())
}

fn parse_plain(body: &[u8]) -> Result<DtmfInfo, InfoRefusal> {
    let trimmed = trim(body);
    let mut bytes = trimmed.iter();
    let Some(&byte) = bytes.next() else {
        return Err(InfoRefusal::Malformed);
    };
    if bytes.next().is_some() {
        return Err(InfoRefusal::Malformed);
    }
    let key = digit(byte).map_err(|_| InfoRefusal::Malformed)?;
    Ok(DtmfInfo {
        digit: char::from(key),
        held_ms: None,
    })
}

fn parse_relay(body: &[u8]) -> Result<DtmfInfo, InfoRefusal> {
    let mut signal: Option<u8> = None;
    let mut held_ms: Option<u32> = None;
    for line in body.split(|&byte| byte == b'\n') {
        let line = trim(line);
        if line.is_empty() {
            continue;
        }
        let Some(at) = line.iter().position(|&byte| byte == b'=') else {
            continue;
        };
        let name = trim(line.get(..at).unwrap_or_default());
        let value = trim(line.get(at + 1..).unwrap_or_default());
        if name.eq_ignore_ascii_case(b"signal") {
            let mut bytes = value.iter();
            let Some(&byte) = bytes.next() else {
                return Err(InfoRefusal::Malformed);
            };
            // a second key in the same body names no one digit
            if bytes.next().is_some() || signal.is_some() {
                return Err(InfoRefusal::Malformed);
            }
            signal = Some(byte);
        } else if name.eq_ignore_ascii_case(b"duration") {
            if held_ms.is_some() {
                return Err(InfoRefusal::Malformed);
            }
            let read = digits(value).map_err(|_| InfoRefusal::Malformed)?;
            let asked = read.require().map_err(|_| InfoRefusal::Malformed)?;
            held_ms = Some(received_duration_ms(asked).map_err(|_| InfoRefusal::Malformed)?);
        }
    }
    let Some(raw) = signal else {
        return Err(InfoRefusal::Malformed);
    };
    let key = digit(raw).map_err(|_| InfoRefusal::Malformed)?;
    Ok(DtmfInfo {
        digit: char::from(key),
        held_ms,
    })
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct QueuedKey {
    pub(crate) key: u8,
    pub(crate) form: DtmfInfoForm,
    pub(crate) held_ms: u32,
}

/// A call's INFO digits waiting behind the one in flight. Exists from the
/// first send until the last final answer, so no two INFOs of a call
/// overlap.
#[derive(Debug)]
pub(crate) struct DtmfQueue {
    pub(crate) waiting: VecDeque<QueuedKey>,
}

/// Cap on the digit in flight plus [`DtmfQueue::waiting`]: plenty for a
/// keypad, small enough to stop a runaway caller.
const MAX_QUEUED_DIGITS: usize = 64;

impl UserAgent {
    /// Send a string of digits over signalling instead of the media (RFC
    /// 6086's INFO), in whichever of the two bodies `form` names.
    ///
    /// The whole string is validated first; one bad character sends nothing.
    /// One INFO per digit, each sent only after the previous one's final
    /// answer, since UDP may reorder overlapping transactions. A 2xx sends
    /// the next; a refusal, timeout or transport failure ends the sequence
    /// and drops the rest unreported, with [`UaEvent::DtmfSent`] naming the
    /// digit that ended it.
    ///
    /// A string given while digits are pending queues behind them, each key
    /// keeping its own `form` and `duration_ms`.
    ///
    /// Each answer arrives as [`UaEvent::DtmfSent`] with its status; a 415
    /// tells the application to try the other form.
    ///
    /// `duration_ms` has the RFC 4733 bounds; zero means [`DEFAULT_DTMF_MS`].
    /// A string that would push the queue past `MAX_QUEUED_DIGITS` is
    /// refused whole.
    ///
    /// # Errors
    /// [`UaError::InvalidDtmf`] for a digit no keypad has, anywhere in
    /// `digits`, a duration outside [`MIN_DTMF_MS`] to [`MAX_DTMF_MS`], or a
    /// string that would take the call's queue past `MAX_QUEUED_DIGITS`;
    /// [`UaError::NoSuchCall`]; [`UaError::WrongState`] for a call with no
    /// dialog to send an INFO in yet; or [`UaError::Send`]. Any of these
    /// leaves the whole string unsent.
    pub fn send_dtmf_info(
        &mut self,
        call: CallHandle,
        digits: &str,
        form: DtmfInfoForm,
        duration_ms: u32,
        now: Instant,
    ) -> Result<(), UaError> {
        let held_ms = self::duration_ms(duration_ms).map_err(UaError::InvalidDtmf)?;
        // in flight plus waiting
        let occupied = self
            .dtmf_queue
            .get(&call)
            .map_or(0, |queue| queue.waiting.len() + 1);
        if occupied.saturating_add(digits.chars().count()) > MAX_QUEUED_DIGITS {
            return Err(UaError::InvalidDtmf(DtmfError::UnknownDigit));
        }
        let mut keys = VecDeque::with_capacity(digits.len());
        for pressed in digits.chars() {
            let byte =
                u8::try_from(pressed).map_err(|_| UaError::InvalidDtmf(DtmfError::UnknownDigit))?;
            keys.push_back(QueuedKey {
                key: self::digit(byte).map_err(UaError::InvalidDtmf)?,
                form,
                held_ms,
            });
        }
        let Some(first) = keys.pop_front() else {
            return Err(UaError::InvalidDtmf(DtmfError::UnknownDigit));
        };
        // pending digits: queue behind them (`forget` drops the entry with
        // the call, so the call still exists)
        if let Some(queue) = self.dtmf_queue.get_mut(&call) {
            queue.waiting.push_back(first);
            queue.waiting.extend(keys);
            return Ok(());
        }
        // before sending: the send's own drain may already bring the answer
        self.dtmf_queue.insert(call, DtmfQueue { waiting: keys });
        if let Err(error) = self.send_one_dtmf_info(call, first, now) {
            self.dtmf_queue.remove(&call);
            return Err(error);
        }
        Ok(())
    }

    /// One validated key as one INFO; also run when a 2xx sends the next.
    pub(crate) fn send_one_dtmf_info(
        &mut self,
        call: CallHandle,
        queued: QueuedKey,
        now: Instant,
    ) -> Result<(), UaError> {
        let QueuedKey { key, form, held_ms } = queued;
        let dialog = {
            let held = self.calls.get(&call).ok_or(UaError::NoSuchCall)?;
            held.dialog.ok_or(UaError::WrongState(held.state))?
        };
        let (content_type, body): (&[u8], Arc<[u8]>) = match form {
            DtmfInfoForm::Plain => (PLAIN, Arc::from(vec![key])),
            DtmfInfoForm::Relay => (RELAY, relay_body(key, held_ms)),
        };
        let request = OutgoingInDialogRequest::new(Method::Info).body(content_type, body);
        let transaction = self.endpoint.request_in_dialog(dialog, &request, now)?;
        let id = AnyTransactionId::NonInviteClient(transaction);
        self.remember_request(call, id, Method::Info);
        self.by_dtmf_info.insert(id, char::from(key));
        self.drain(now);
        Ok(())
    }
}

impl UserAgent {
    /// Hand non-DTMF INFOs in a call to the application unanswered, as
    /// [`UaEvent::Unclaimed`](crate::UaEvent::Unclaimed), to answer through
    /// [`UserAgent::endpoint`]. Off by default.
    ///
    /// Off, they are answered here per RFC 6086 §4.2.2: 469 for an Info
    /// Package, 415 for an unreadable body, 200 with no body (see
    /// `crate::admission`). Turn it on only if every INFO will be answered:
    /// an unanswered INFO is retransmitted for 32 s and then the far end
    /// ends the call (RFC 3261 §12.2.1.2). The C ABI cannot answer them.
    pub const fn hand_over_info(&mut self, handed_over: bool) {
        self.info_handed_over = handed_over;
    }

    /// `None` when this handled a DTMF INFO; the event back otherwise. Other
    /// INFOs go down the chain (see [`UserAgent::hand_over_info`]).
    pub(crate) fn on_dtmf_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        let Event::IncomingInDialog {
            transaction,
            dialog,
            ref request,
        } = event
        else {
            return Some(event);
        };
        let raw = request.as_raw();
        if raw.method() != Some(Method::Info) {
            return Some(event);
        }
        if !names_a_dtmf_body(raw.header(HeaderName::ContentType)) {
            return Some(event);
        }
        // not a call (e.g. a subscription dialog): leave it for the 481
        let Some(call) = self.by_dialog.get(&dialog).copied() else {
            return Some(event);
        };
        match parse_incoming(&raw) {
            Ok(info) => {
                self.endpoint
                    .respond(transaction, &OutgoingResponse::new(StatusCode::OK), now)
                    .ok();
                self.events.push_back(UaEvent::DtmfReceived {
                    call,
                    digit: info.digit,
                    held_ms: info.held_ms,
                });
            }
            Err(refusal) => {
                // only `Malformed` here: the gate above filtered the type
                let answer = OutgoingResponse::new(refusal.status());
                self.endpoint.respond(transaction, &answer, now).ok();
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_DTMF_MS, DtmfError, DtmfInfo, InfoRefusal, MAX_DTMF_MS, MIN_DTMF_MS, digit,
        duration_ms, names_a_dtmf_body, parse_info, received_duration_ms, relay_body,
    };
    use sipral_core::msg::StatusCode;

    /// The DTMF events are Table 3 in RFC 4733's 3.2; generated bindings
    /// copy doc comments verbatim. The needle is built at runtime so the
    /// test does not match itself.
    #[test]
    fn the_keypad_doc_cites_a_section_rfc_4733_actually_has() {
        // CRLF on a Windows checkout
        let source = include_str!("dtmf.rs").replace("\r\n", "\n");
        let section = '\u{a7}';
        assert!(
            source.contains(&format!("(RFC 4733 {section}3.2, Table 3)")),
            "the KEYPAD constant should point at Table 3 in §3.2"
        );
    }

    /// 415 is RFC 3261's 21.4.13; 21.4.16 is 421.
    #[test]
    fn the_415_is_cited_where_rfc_3261_numbers_it() {
        let source = include_str!("dtmf.rs").replace("\r\n", "\n");
        let section = '\u{a7}';
        assert!(
            !source.contains(&format!("{section}21.4.{}", 16)),
            "421 Extension Required is cited for a 415"
        );
        assert!(
            source.contains(&format!("RFC 3261 {section}21.4.{}", 13)),
            "the 415 should point at §21.4.13"
        );
    }

    /// A body naming two keys names no one digit, and reporting whichever
    /// came last would take a side the far end never took.
    #[test]
    fn a_relay_body_naming_two_signals_or_two_durations_is_400() {
        for body in [
            &b"Signal=5\r\nSignal=6\r\n"[..],
            b"Signal=5\r\nDuration=160\r\nDuration=200\r\n",
        ] {
            assert_eq!(
                parse_info(Some(b"application/dtmf-relay"), body),
                Err(InfoRefusal::Malformed),
                "{body:?}"
            );
        }
    }

    #[test]
    fn only_the_sixteen_keys_a_keypad_has_are_digits() {
        for key in *b"0123456789*#ABCD" {
            assert_eq!(digit(key), Ok(key));
            assert_eq!(digit(key.to_ascii_lowercase()), Ok(key));
        }
        for refused in [b' ', b'E', b'+', 0xE9] {
            assert!(digit(refused).is_err(), "{refused} was taken for a keypad");
        }
    }

    #[test]
    fn a_tone_nobody_holds_a_key_for_is_refused() {
        assert_eq!(duration_ms(0), Ok(DEFAULT_DTMF_MS));
        assert_eq!(
            duration_ms(MIN_DTMF_MS - 1),
            Err(DtmfError::ToneTooShort(39))
        );
        assert_eq!(duration_ms(MIN_DTMF_MS), Ok(MIN_DTMF_MS));
        assert_eq!(duration_ms(100), Ok(100));
        assert_eq!(duration_ms(MAX_DTMF_MS), Ok(MAX_DTMF_MS));
        assert!(duration_ms(MAX_DTMF_MS + 1).is_err());
        assert!(duration_ms(u32::MAX).is_err());
    }

    #[test]
    fn one_key_is_two_lines() {
        assert_eq!(
            relay_body(b'5', 160).as_ref(),
            b"Signal=5\r\nDuration=160\r\n"
        );
    }

    #[test]
    fn a_relay_body_names_the_signal_and_the_duration() {
        assert_eq!(
            parse_info(
                Some(b"application/dtmf-relay"),
                b"Signal=5\r\nDuration=160\r\n"
            ),
            Ok(DtmfInfo {
                digit: '5',
                held_ms: Some(160)
            })
        );
        assert_eq!(
            parse_info(
                Some(b"application/dtmf-relay;charset=utf-8"),
                b"Signal=A\r\n"
            ),
            Ok(DtmfInfo {
                digit: 'A',
                held_ms: None
            })
        );
    }

    #[test]
    fn a_plain_body_is_the_key_and_nothing_else() {
        assert_eq!(
            parse_info(Some(b"application/dtmf"), b"5"),
            Ok(DtmfInfo {
                digit: '5',
                held_ms: None
            })
        );
        // trailing whitespace is not a second key
        assert_eq!(
            parse_info(Some(b"application/dtmf"), b"5\r\n"),
            Ok(DtmfInfo {
                digit: '5',
                held_ms: None
            })
        );
    }

    #[test]
    fn a_content_type_neither_form_uses_is_415() {
        for content_type in [None, Some(&b"application/sdp"[..]), Some(b"text/plain")] {
            assert_eq!(
                parse_info(content_type, b"5"),
                Err(InfoRefusal::UnsupportedType)
            );
        }
        assert_eq!(
            InfoRefusal::UnsupportedType.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[test]
    fn a_body_that_names_no_digit_is_400() {
        let bad: &[&[u8]] = &[
            b"",
            b"Signal=",
            b"Signal=55",
            b"Signal=E",
            b"Duration=160",
            b"garbage",
        ];
        for body in bad {
            assert_eq!(
                parse_info(Some(b"application/dtmf-relay"), body),
                Err(InfoRefusal::Malformed),
                "{body:?}"
            );
        }
        for body in [&b""[..], b"55", b"E", b" "] {
            assert_eq!(
                parse_info(Some(b"application/dtmf"), body),
                Err(InfoRefusal::Malformed),
                "{body:?}"
            );
        }
        assert_eq!(InfoRefusal::Malformed.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn a_relay_duration_out_of_the_bound_a_send_would_also_refuse_is_400() {
        assert_eq!(
            parse_info(
                Some(b"application/dtmf-relay"),
                b"Signal=5\r\nDuration=999999999\r\n"
            ),
            Err(InfoRefusal::Malformed)
        );
        assert_eq!(
            parse_info(
                Some(b"application/dtmf-relay"),
                b"Signal=5\r\nDuration=abc\r\n"
            ),
            Err(InfoRefusal::Malformed)
        );
    }

    #[test]
    fn a_received_duration_of_zero_is_reported_as_zero() {
        assert_eq!(
            parse_info(
                Some(b"application/dtmf-relay"),
                b"Signal=5\r\nDuration=0\r\n"
            ),
            Ok(DtmfInfo {
                digit: '5',
                held_ms: Some(0)
            })
        );
        assert_eq!(received_duration_ms(0), Ok(0));
        assert_eq!(received_duration_ms(MIN_DTMF_MS - 1), Ok(MIN_DTMF_MS - 1));
        assert_eq!(received_duration_ms(MAX_DTMF_MS), Ok(MAX_DTMF_MS));
        assert_eq!(
            received_duration_ms(MAX_DTMF_MS + 1),
            Err(DtmfError::ToneTooLong(MAX_DTMF_MS + 1))
        );
    }

    #[test]
    fn only_the_two_dtmf_content_types_are_named_a_dtmf_body() {
        assert!(names_a_dtmf_body(Some(b"application/dtmf-relay")));
        assert!(names_a_dtmf_body(Some(b"application/dtmf")));
        assert!(names_a_dtmf_body(Some(b"APPLICATION/DTMF-RELAY")));
        assert!(names_a_dtmf_body(Some(
            b"application/dtmf-relay;charset=utf-8"
        )));
        assert!(!names_a_dtmf_body(Some(b"application/media_control+xml")));
        assert!(!names_a_dtmf_body(Some(b"text/plain")));
        assert!(!names_a_dtmf_body(None));
    }

    /// Spot checks; `fuzz/fuzz_targets/dtmf_info.rs` is the exhaustive one.
    #[test]
    fn the_parser_never_panics() {
        let cases: &[&[u8]] = &[
            b"",
            b"\0",
            b"=",
            b"==",
            b"Signal",
            b"Signal=",
            &[0xff; 4096],
            b"Signal=5\r\nDuration=\r\n",
            b"Signal=5\nDuration=160",
            b"signal=5\r\nsignal=6\r\n",
        ];
        for body in cases {
            let _ = parse_info(None, body);
            let _ = parse_info(Some(b""), body);
            let _ = parse_info(Some(b"application/dtmf"), body);
            let _ = parse_info(Some(b"application/dtmf-relay"), body);
            let _ = parse_info(Some(body), body);
        }
    }
}
