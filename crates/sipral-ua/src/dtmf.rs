// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A digit sent or received by SIP INFO (RFC 6086), and the validation every
//! way a digit crosses this stack's boundary shares.
//!
//! Neither body this module reads or writes has an RFC of its own.
//! `application/dtmf-relay`'s `Signal=`/`Duration=` lines came from an
//! Internet-Draft that expired years before this was written, and
//! `application/dtmf`'s bare character is a convention rather than a
//! document. What is implemented here is what the lab's servers are expected
//! to take: `interop/harness`'s own `Flow::DtmfInfo` sends the relay form to
//! the lab's Asterisk and reads its dialplan's echo back in whichever form
//! that sends, and no lab flow sends the plain form. Neither has been run
//! against the real container yet; the lab run is what confirms it, and
//! `docs/04-ua.md` says the same.
//!
//! [`digit`](crate::dtmf::digit) and [`duration_ms`](crate::dtmf::duration_ms)
//! are the one validation RFC 4733 sending, INFO sending and INFO receiving
//! all read through, so a digit no keypad has and a tone nothing holds a key
//! for are refused the same way by every one of the three.

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

/// What one DTMF tone lasts when nobody says (RFC 4733 §2.5.2.2 has no
/// figure; every switch that generates one uses about this).
pub const DEFAULT_DTMF_MS: u32 = 160;

/// Shorter than equipment recognises. RFC 4733 §2.5.2.1, citing ITU-T Q.24
/// Table A-1: the switching equipment surveyed "expects a minimum
/// recognizable signal duration of 40 ms". A digit sent by INFO is played out
/// as a tone somewhere past the far end all the same, so the floor is one
/// for every form.
pub const MIN_DTMF_MS: u32 = 40;

/// Longer than any key is actually held, and short enough that a caller who
/// passed milliseconds where it meant seconds finds out.
pub const MAX_DTMF_MS: u32 = 10_000;

/// `application/dtmf-relay`'s two lines: which signal, and for how long.
pub const RELAY: &[u8] = b"application/dtmf-relay";
/// `application/dtmf`'s whole body: the character alone.
pub const PLAIN: &[u8] = b"application/dtmf";

/// The longest body either form is read from. One key and a duration inside
/// the bound take under thirty octets in the relay form and one in the plain
/// one; this leaves room for the whitespace senders put around them, and
/// nothing a single digit needs beyond that.
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

/// Which of the two bodies an INFO this end sends carries.
///
/// Chosen per send rather than per call: which one a peer takes is a fact
/// about the peer, discovered by trying — see
/// [`UserAgent::send_dtmf_info`](crate::UserAgent::send_dtmf_info).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DtmfInfoForm {
    /// `application/dtmf-relay`: `Signal=` and `Duration=` lines.
    Relay,
    /// `application/dtmf`: the whole body is the character.
    Plain,
}

/// One key, in the two lines every switch that reads `application/dtmf-relay`
/// takes.
pub(crate) fn relay_body(key: u8, held_ms: u32) -> Arc<[u8]> {
    let mut body = Vec::with_capacity(32);
    body.extend_from_slice(b"Signal=");
    body.push(key);
    body.extend_from_slice(b"\r\nDuration=");
    body.extend_from_slice(held_ms.to_string().as_bytes());
    body.extend_from_slice(b"\r\n");
    Arc::from(body)
}

/// What a digit named on the wire — by `Signal=` or by a bare body — read
/// out, and how long it was held when the body said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DtmfInfo {
    /// The key, upper-cased.
    pub digit: char,
    /// `application/dtmf-relay`'s `Duration=`, when the body carried one.
    /// `application/dtmf` never does.
    pub held_ms: Option<u32>,
}

/// Why an incoming INFO's body was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InfoRefusal {
    /// No `Content-Type`, or one that is not `application/dtmf-relay` or
    /// `application/dtmf` (RFC 3261 §21.4.13).
    UnsupportedType,
    /// The right `Content-Type`, but a body that does not name exactly one
    /// digit this stack can read, is longer than any one digit needs, or
    /// carries a duration outside the bound every send validates against too
    /// (RFC 3261 §21.4.1).
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

/// Read an incoming INFO's DTMF body, never panicking on any input.
///
/// `content_type` is the request's `Content-Type` header value, when it had
/// one; `body` is the whole of it, whatever `content_type` said. Two-thirds
/// of what makes this safe against a hostile peer is already proven
/// elsewhere: [`MediaTypeRef::parse`] and [`digits`] are the same reader
/// every header in this stack goes through, and neither indexes, unwraps, or
/// allocates without a bound the input itself sets.
///
/// # Errors
/// [`InfoRefusal`] naming which of RFC 3261 §21.4.13 or §21.4.1 applies.
pub fn parse_info(content_type: Option<&[u8]>, body: &[u8]) -> Result<DtmfInfo, InfoRefusal> {
    let Some(content_type) = content_type else {
        return Err(InfoRefusal::UnsupportedType);
    };
    let media = MediaTypeRef::parse(content_type).map_err(|_| InfoRefusal::UnsupportedType)?;
    if !media.kind().eq_ignore_ascii_case(b"application") {
        return Err(InfoRefusal::UnsupportedType);
    }
    let relay = media.subtype().eq_ignore_ascii_case(b"dtmf-relay");
    if !relay && !media.subtype().eq_ignore_ascii_case(b"dtmf") {
        return Err(InfoRefusal::UnsupportedType);
    }
    // the right type, so a body too long for any one digit is malformed
    // rather than unsupported, and it is refused before a line of it is read
    if body.len() > MAX_INFO_BODY {
        return Err(InfoRefusal::Malformed);
    }
    if relay {
        parse_relay(body)
    } else {
        parse_plain(body)
    }
}

/// The `Content-Type` and the body of an incoming INFO, read together because
/// a missing header and an absent one are the same refusal.
///
/// # Errors
/// As [`parse_info`].
pub fn parse_incoming(request: &RawMessage<'_>) -> Result<DtmfInfo, InfoRefusal> {
    parse_info(request.header(HeaderName::ContentType), request.body())
}

/// `application/dtmf`: the whole body, trimmed, is the key and nothing else.
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

/// `application/dtmf-relay`: `Signal=` names the key, and an optional
/// `Duration=` how long it was held, each on its own line.
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
            // the same bound a send validates against, so a peer's Duration=
            // is never trusted further than this end trusts its own
            held_ms = Some(duration_ms(asked).map_err(|_| InfoRefusal::Malformed)?);
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

/// The `Accept` a 415 carries, naming the two bodies this end reads (RFC
/// 3261 §8.2.3: "The response MUST contain an Accept header field listing the
/// types of all bodies it understands"; §21.4.13 says the same of a 415).
const ACCEPTED_TYPES: &[u8] = b"application/dtmf-relay, application/dtmf";

// -- sending -------------------------------------------------------------

impl UserAgent {
    /// Send one digit over signalling instead of the media (RFC 6086's
    /// INFO), in whichever of the two bodies `form` names.
    ///
    /// The far end's answer arrives as [`UaEvent::DtmfSent`], carrying
    /// `digit` and whatever status it gave — a 415 from a switch that does
    /// not read this `Content-Type` included, so the application learns
    /// which of the two forms to try without guessing from silence.
    ///
    /// `digit` and `duration_ms` are checked against the same bound RFC 4733
    /// sending and INFO receiving both read through, and refused before
    /// anything is built or sent.
    ///
    /// # Errors
    /// [`UaError::InvalidDtmf`] for a digit no keypad has or a duration
    /// outside [`MIN_DTMF_MS`] to [`MAX_DTMF_MS`]; [`UaError::NoSuchCall`]; [`UaError::WrongState`]
    /// for a call with no dialog to send an INFO in yet; or [`UaError::Send`].
    pub fn send_dtmf_info(
        &mut self,
        call: CallHandle,
        digit: char,
        form: DtmfInfoForm,
        duration_ms: u32,
        now: Instant,
    ) -> Result<(), UaError> {
        let byte =
            u8::try_from(digit).map_err(|_| UaError::InvalidDtmf(DtmfError::UnknownDigit))?;
        let key = self::digit(byte).map_err(UaError::InvalidDtmf)?;
        let held_ms = self::duration_ms(duration_ms).map_err(UaError::InvalidDtmf)?;
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

// -- receiving -------------------------------------------------------------

impl UserAgent {
    /// `None` when the event was an incoming INFO this handled; the event
    /// back otherwise.
    pub(crate) fn on_dtmf_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        let Event::IncomingInDialog {
            transaction,
            dialog,
            ref request,
        } = event
        else {
            return Some(event);
        };
        if request.as_raw().method() != Some(Method::Info) {
            return Some(event);
        }
        // an INFO in a dialog that is not a call belongs to nobody here —
        // there is no other kind of dialog this layer keeps in `by_dialog`,
        // but a subscription's own dialog is not one, and swallowing this
        // would leave a legitimate 481 unanswered
        let Some(call) = self.by_dialog.get(&dialog).copied() else {
            return Some(event);
        };
        let raw = request.as_raw();
        // RFC 3261 §8.2.3 refuses a body of a type this end does not read,
        // and an INFO with no body has none to refuse: RFC 6086 §4.2.2
        // answers one that is well formed 200. It names no digit, so nothing
        // is reported for it
        if raw.body().is_empty() && raw.header(HeaderName::ContentType).is_none() {
            self.endpoint
                .respond(transaction, &OutgoingResponse::new(StatusCode::OK), now)
                .ok();
            return None;
        }
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
                let mut answer = OutgoingResponse::new(refusal.status());
                if refusal == InfoRefusal::UnsupportedType {
                    answer = answer.header(HeaderName::Accept, ACCEPTED_TYPES);
                }
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
        duration_ms, parse_info, relay_body,
    };
    use sipral_core::msg::StatusCode;

    /// RFC 4733's section 3 has only 3.1, 3.2 and 3.3; the sixteen DTMF
    /// event codes are Table 3 in 3.2. A doc comment pointing at a section
    /// that does not exist is a defect a generator built on this crate would
    /// copy verbatim, so it is checked here rather than left to be noticed
    /// by eye — this constant used to live in `sipral-ffi`, and carried this
    /// exact test with it.
    ///
    /// The needle is assembled at runtime, not written as one literal, so
    /// this test inspecting its own file does not just match itself.
    #[test]
    fn the_keypad_doc_cites_a_section_rfc_4733_actually_has() {
        // the needle spans a line break, and a Windows checkout puts a CR in
        // front of it
        let source = include_str!("dtmf.rs").replace("\r\n", "\n");
        let section = '\u{a7}';
        assert!(
            source.contains(&format!("(RFC 4733 {section}3.2, Table 3)")),
            "the KEYPAD constant should point at Table 3 in §3.2"
        );
    }

    /// RFC 3261 numbers 415 Unsupported Media Type as §21.4.13; three
    /// sections further on is 421 Extension Required. A doc comment citing
    /// the wrong one sends its reader to a status this module never answers.
    ///
    /// The needles are assembled at runtime for the same reason as above.
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
        // parameters after the type, and a signal a keypad does not have in
        // upper case already
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
        // trailing linear whitespace some senders leave on is not a second
        // key
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

    /// Nothing here indexes, unwraps or allocates without a bound the input
    /// itself sets, so nothing here panics — tried against the inputs most
    /// likely to trip a hand-rolled parser rather than a property test,
    /// because the fuzz target under `fuzz/fuzz_targets/dtmf_info.rs` is the
    /// exhaustive version of this.
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
