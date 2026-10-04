// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
//! [`digit`](crate::dtmf::digit) is the one validation RFC 4733 sending, INFO
//! sending and INFO receiving all read through, so a digit no keypad has is
//! refused the same way by every one of the three. Duration is not shared the
//! same way: sending generates a tone, so
//! [`duration_ms`](crate::dtmf::duration_ms) holds every sending form — RTP,
//! `application/dtmf-relay`'s own `Duration=`, and the C ABI's `duration_ms`
//! — to the same floor and ceiling, and to the same hundred-millisecond
//! default when nothing is asked for. Receiving reports a length the peer
//! already held rather than one this end is about to generate, so
//! [`received_duration_ms`](crate::dtmf::received_duration_ms) checks only
//! the ceiling, and `Duration=0` is exactly what it looks like rather than
//! the sending default in disguise (8.3.11-bis).

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

/// What one DTMF tone lasts when nobody says: the one default RTP, both INFO
/// bodies and the C ABI's own `duration_ms` all fall back to, so that no form
/// of DTMF holds a key longer than another when the application does not
/// name a length (8.3.11-bis). RFC 4733 §2.5.2.2 has no figure of its own for
/// this; a hundred milliseconds is comfortably above the floor equipment
/// needs and short enough that four keys pressed in a row do not queue for
/// long.
pub const DEFAULT_DTMF_MS: u32 = 100;

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

/// `asked`, read off a peer's own `Duration=`, or which bound it broke.
///
/// Sending checks a floor because it is about to generate a tone equipment
/// has to recognise, and treats zero as "say nothing" because a sender never
/// has a reason to ask for a tone of no length. Neither applies to reading
/// what a peer already held a key for: zero there means the peer said zero,
/// and nothing shorter than that is this end's to second-guess. Only the
/// ceiling every sending form also refuses is — ten seconds is not a real key
/// press regardless of which end is reporting it (8.3.11-bis).
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
    /// carries a duration past the ceiling every sending form also refuses
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

/// Whether `media` is one of the two bodies this module reads.
fn is_dtmf_media(media: &MediaTypeRef<'_>) -> bool {
    media.kind().eq_ignore_ascii_case(b"application")
        && (media.subtype().eq_ignore_ascii_case(b"dtmf-relay")
            || media.subtype().eq_ignore_ascii_case(b"dtmf"))
}

/// Whether an INFO whose `Content-Type` is `content_type` is this stack's to
/// answer at all.
///
/// The gate `agent.rs`'s dispatcher checks before claiming an INFO in a call's
/// dialog (8.3.11-bis): only `application/dtmf-relay` and `application/dtmf`
/// belong here. RFC 6086 does not reserve INFO for DTMF — any Info-Package can
/// use it, RFC 5168's media control body among them — so every other
/// `Content-Type`, and an INFO with no body at all, is the application's, not
/// answered by this stack at all rather than refused by it. A malformed body
/// of the right type is still this module's: [`parse_info`] answers that one
/// 400 rather than passing it on half read.
#[must_use]
pub(crate) fn names_a_dtmf_body(content_type: Option<&[u8]>) -> bool {
    content_type
        .and_then(|value| MediaTypeRef::parse(value).ok())
        .is_some_and(|media| is_dtmf_media(&media))
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
    if !is_dtmf_media(&media) {
        return Err(InfoRefusal::UnsupportedType);
    }
    let relay = media.subtype().eq_ignore_ascii_case(b"dtmf-relay");
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
            // only the ceiling every sending form also refuses -- reading how
            // long a peer already held a key needs no floor of its own, and
            // zero means the peer said zero (8.3.11-bis)
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

// -- sending -------------------------------------------------------------

/// One key waiting to go out by INFO, with the body and length it was asked
/// for.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueuedKey {
    pub(crate) key: u8,
    pub(crate) form: DtmfInfoForm,
    pub(crate) held_ms: u32,
}

/// A call's digits sent by INFO: present from the moment one goes out until
/// the last of them has its final answer, holding the keys still waiting
/// behind the one in flight.
///
/// One entry per call. A string handed to [`UserAgent::send_dtmf_info`] while
/// the entry exists goes behind the keys already waiting rather than out at
/// once, the same way a second `dial` in the media queues behind the digits
/// already going, so that no two of a call's INFOs are ever outstanding
/// together.
#[derive(Debug)]
pub(crate) struct DtmfQueue {
    pub(crate) waiting: VecDeque<QueuedKey>,
}

/// The most one call may have outstanding at once — the digit in flight and
/// everything [`DtmfQueue::waiting`] behind it.
///
/// Only the application can grow this, by handing [`UserAgent::send_dtmf_info`]
/// strings faster than the far end answers them, and nothing else here paces
/// it or drops a digit silently. Sixty-four is far more than one press of a
/// keypad ever needs and far short of a mistake — a runaway loop, a whole
/// file fed in at once — turning into a queue the size of whatever the caller
/// handed over (8.3.11-ter(e)).
const MAX_QUEUED_DIGITS: usize = 64;

impl UserAgent {
    /// Send a string of digits over signalling instead of the media (RFC
    /// 6086's INFO), in whichever of the two bodies `form` names.
    ///
    /// `digits` is validated as a whole before anything is sent: one
    /// character no keypad has, anywhere in the string, refuses the call and
    /// sends nothing, not even the keys ahead of it. What goes out is still
    /// one INFO per digit, but not all at once — over UDP, overlapping
    /// non-INVITE transactions can arrive in any order, so the first digit is
    /// the only one sent here, and every one after it waits for the one
    /// ahead of it to reach a final answer (8.3.11-bis). A 2xx sends the
    /// next; a refusal, a timeout or a transport failure ends the sequence
    /// there instead, and the digits still waiting are discarded rather than
    /// sent out of order — the digit that ended it is what
    /// [`UaEvent::DtmfSent`] names, and nothing is reported for the ones it
    /// took down with it.
    ///
    /// A string handed over while a digit of this call is still waiting for
    /// its answer — a keypad handing over one key per press does this all the
    /// time — is not sent at once either: it goes behind the digits already
    /// waiting, each key keeping its own `form` and `duration_ms`, and a
    /// refusal, a timeout or a transport failure ahead of it discards it with
    /// the rest.
    ///
    /// The far end's answer to each INFO arrives as [`UaEvent::DtmfSent`],
    /// carrying `digit` and whatever status it gave — a 415 from a switch
    /// that does not read this `Content-Type` included, so the application
    /// learns which of the two forms to try without guessing from silence.
    ///
    /// `duration_ms` is checked against the same bound RFC 4733 sending
    /// reads through, and zero asks for [`DEFAULT_DTMF_MS`].
    ///
    /// A string that would leave the call holding more than
    /// `MAX_QUEUED_DIGITS` is refused whole, before anything of it is sent
    /// or queued, the same as one with a bad character in it (8.3.11-ter(e)).
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
        // the digit in flight, when there is one, plus everything already
        // waiting behind it — what this call already holds before this
        // string adds to it
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
        // a digit of this call is still waiting for its answer, so the whole
        // string goes behind it; the call and its dialog are known to exist,
        // because `forget` takes the entry with the call
        if let Some(queue) = self.dtmf_queue.get_mut(&call) {
            queue.waiting.push_back(first);
            queue.waiting.extend(keys);
            return Ok(());
        }
        // in place before the INFO goes, so that an answer the send's own
        // drain already brought finds the digits it has to move on or drop
        self.dtmf_queue.insert(call, DtmfQueue { waiting: keys });
        if let Err(error) = self.send_one_dtmf_info(call, first, now) {
            self.dtmf_queue.remove(&call);
            return Err(error);
        }
        Ok(())
    }

    /// One already-validated key, sent as one INFO. The half of
    /// [`Self::send_dtmf_info`] that also runs when a digit's own 2xx sends
    /// the next one waiting behind it.
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

// -- receiving -------------------------------------------------------------

impl UserAgent {
    /// Hand every INFO in a call that is not one of the two DTMF forms to
    /// the application, unanswered, as
    /// [`UaEvent::Unclaimed`](crate::UaEvent::Unclaimed) — RFC 5168's media
    /// control, a vendor's Info Package — for it to answer through
    /// [`UserAgent::endpoint`]. Off by default.
    ///
    /// Off, each one is answered here by RFC 6086 §4.2.2: 469 when it names
    /// an Info Package, 415 for a body this agent cannot read, 200 for one
    /// with no body (see `crate::admission`). That is the only answer an
    /// application with no way to answer can give, and the C ABI is one: an
    /// INFO it counts as unclaimed and never answers is retransmitted for
    /// thirty-two seconds, and RFC 3261 §12.2.1.2 then has the far end
    /// terminate the call. Turn this on only with something that answers
    /// every INFO it is handed.
    pub const fn hand_over_info(&mut self, handed_over: bool) {
        self.info_handed_over = handed_over;
    }

    /// `None` when the event was an incoming INFO this handled; the event
    /// back otherwise.
    ///
    /// Only an INFO whose `Content-Type` is `application/dtmf-relay` or
    /// `application/dtmf` is this stack's to read (8.3.11-bis): RFC 6086
    /// does not reserve INFO for DTMF, so every other one — RFC 5168's media
    /// control, a vendor Info-Package, one with no body at all — is left for
    /// the event chain below this, which answers it by RFC 6086 §4.2.2 at
    /// its end unless [`UserAgent::hand_over_info`] gave it to the
    /// application.
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
        // an INFO in a dialog that is not a call belongs to nobody here —
        // there is no other kind of dialog this layer keeps in `by_dialog`,
        // but a subscription's own dialog is not one, and swallowing this
        // would leave a legitimate 481 unanswered
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
                // never `UnsupportedType`: the gate above already turned
                // every other `Content-Type` back before `parse_incoming`
                // saw it, so the only refusal this arm can carry is a body
                // of the right type this stack still could not read
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

    /// 8.3.11-bis(c): reading how long a peer already held a key needs no
    /// floor of its own, and zero means the peer said zero rather than the
    /// hundred-millisecond default sending falls back to.
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

    /// 8.3.11-bis(a): only the two bodies this module reads gate the
    /// dispatch in `agent.rs`; everything else, no body at all included, is
    /// left for the application to see and answer for itself.
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
