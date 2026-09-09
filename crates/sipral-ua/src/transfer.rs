// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Transfer: REFER, the subscription it opens, and `Replaces` (RFC 3515,
//! RFC 3891).
//!
//! A transfer is three parties and two of them never speak to each other. The
//! transferor is in a call and asks the other end to call somebody else; the
//! transferee does, and reports back; the target knows nothing about any of it
//! unless a `Replaces` tells it which of its own calls is being taken over.
//!
//! **REFER is not fire and forget.** §2.4.4 makes it open a subscription, and
//! the transferee has to say what happened: a NOTIFY carrying a
//! `message/sipfrag` whose first line is a SIP status line, `100` while it is
//! trying and the real answer when there is one. That is what lets a phone
//! show "transferring" and then either hang up or take the call back. The
//! subscription ends with a NOTIFY marked `terminated;reason=noresource`,
//! which §2.4.7 makes the last word.
//!
//! **Blind and attended differ by one URI parameter.** A blind transfer sends
//! `Refer-To: <sip:carol@example.com>`. An attended one sends the target's own
//! contact with a `Replaces` in it, naming a dialog the transferee already has
//! with the target — so the target replaces a call it is already in rather
//! than getting a second one. Everything else is the same code.
//!
//! **The attended one needs a second call first**, to the target, and that call
//! is not an ordinary one: it exists so that the transferor can speak to the
//! target before handing the caller over, and it is the dialog the `Replaces`
//! will name. So it is placed with [`UserAgent::consult`] and it says what it
//! is — [`CallState::Consulting`] — rather than being an ordinary confirmed
//! call the application has to remember the purpose of.
//!
//! **What `Replaces` matches, and what it does not.** §3 is exact about it,
//! and every branch is a different status code: no match is 481, a dialog that
//! has already ended is 603, an early dialog this end did not originate is
//! 481, and only a confirmed dialog or an early one of our own is replaced.
//! Getting that wrong hands somebody else's call to whoever asks.

use std::sync::Arc;
use std::time::Instant;

use sipral_core::endpoint::{Event, OutgoingInDialogRequest, OutgoingResponse};
use sipral_core::msg::{HeaderName, Method, OwnedMessage, Params, RawMessage, StatusCode, Uri};
use sipral_core::transaction::{AnyTransactionId, InviteServer, TransactionId};

use crate::agent::UserAgent;
use crate::call::{CallHandle, CallState, Direction, OutgoingCall};
use crate::error::UaError;
use crate::event::UaEvent;

/// The event package a REFER subscribes to (§3.1).
const REFER: &[u8] = b"refer";
/// §2.4.7: the last NOTIFY says the subscription is over and why.
const FINISHED: &[u8] = b"terminated;reason=noresource";
/// And every one before it says it is still going.
const RUNNING: &[u8] = b"active";
/// §2.4.5: "If a NOTIFY is generated when the subscription state is pending,
/// its body should consist of a status line containing a response code of 100."
const TRYING: &[u8] = b"SIP/2.0 100 Trying\r\n";

/// One this end received and agreed to act on.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Referred {
    /// The transaction to answer, until it is answered.
    pub(crate) transaction: Option<TransactionId<sipral_core::transaction::NonInviteServer>>,
    /// The call placed because of it, once there is one.
    pub(crate) placed: Option<CallHandle>,
    /// Whether the closing NOTIFY has gone.
    pub(crate) finished: bool,
}

/// What a `Refer-To` asks for.
#[derive(Clone, Debug)]
pub(crate) struct ReferTo {
    /// Where to call.
    pub(crate) target: Uri,
    /// The `Replaces` it carried, as it should go on the new INVITE.
    pub(crate) replaces: Option<Box<[u8]>>,
}

// -- what the application asks for -------------------------------------------

impl UserAgent {
    /// Ask the far end to call somebody else, and hang up when it has
    /// (RFC 3515).
    ///
    /// The far end reports progress, which arrives as
    /// [`UaEvent::TransferProgress`] and then [`UaEvent::TransferDone`]. This
    /// end does not hang up until the transfer has succeeded: §2.4.4 leaves
    /// that open, and hanging up first turns a transfer that failed into a
    /// call that vanished.
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`], [`UaError::WrongState`] for a call that is not
    /// up or is already transferring, or [`UaError::Send`].
    pub fn transfer(
        &mut self,
        call: CallHandle,
        target: &Uri,
        now: Instant,
    ) -> Result<(), UaError> {
        let mut value = Vec::with_capacity(target.as_bytes().len() + 2);
        value.push(b'<');
        value.extend_from_slice(target.as_bytes());
        value.push(b'>');
        self.refer(call, &value, now)
    }

    /// Call the transfer target, so that there is somebody to hand the call to.
    ///
    /// This is the second leg of an attended transfer — the consultation call —
    /// and it is placed here rather than with
    /// [`call`](crate::UserAgent::call) so that the two legs know about each
    /// other. It is answered like any other call, and while it is up its state
    /// is [`CallState::Consulting`]: a confirmed dialog whose reason for
    /// existing is the transfer that follows. [`UserAgent::transfer_to`] is
    /// what follows.
    ///
    /// Putting `call` on hold first is the application's, because it is a
    /// session change and this layer does not make those uninvited. If the
    /// consultation ends without a transfer, hanging it up leaves `call`
    /// exactly where it was.
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`], [`UaError::WrongState`] when `call` is not up,
    /// is already consulting somebody, or is itself a consultation,
    /// [`UaError::NoSuchAccount`], or [`UaError::Send`].
    pub fn consult(
        &mut self,
        call: CallHandle,
        outgoing: &OutgoingCall,
        now: Instant,
    ) -> Result<CallHandle, UaError> {
        let held = self.calls.get(&call).ok_or(UaError::NoSuchCall)?;
        let state = held.state;
        // one consultation at a time, and a consultation is not a call to
        // consult from: a chain of them names no transfer at all
        if !state.is_confirmed() || held.consulting.is_some() || held.consulting_for.is_some() {
            return Err(UaError::WrongState(state));
        }
        let account = held.account.ok_or(UaError::NoSuchAccount)?;
        let placed = self.call(account, outgoing, now)?;
        if let Some(second) = self.calls.get_mut(&placed) {
            second.consulting_for = Some(call);
        }
        if let Some(first) = self.calls.get_mut(&call) {
            first.consulting = Some(placed);
        }
        Ok(placed)
    }

    /// Hand this call to the far end of another one (RFC 3891).
    ///
    /// The `Replaces` names the dialog `other` is in, so the party at its far
    /// end replaces the call it already has rather than answering a second.
    /// `other` is normally the consultation call [`UserAgent::consult`] placed,
    /// and any other call that is up may be named instead — RFC 3891 replaces a
    /// dialog, not a role.
    ///
    /// # Errors
    /// As [`UserAgent::transfer`], and [`UaError::WrongState`] when `other` is
    /// not up or has no dialog to name.
    pub fn transfer_to(
        &mut self,
        call: CallHandle,
        other: CallHandle,
        now: Instant,
    ) -> Result<(), UaError> {
        let held = self.calls.get(&other).ok_or(UaError::NoSuchCall)?;
        let state = held.state;
        // an early dialog is not something to hand over: §3 has the far end
        // refuse a Replaces naming one it did not originate, and this end
        // would have hung up a call that was never taken
        if !state.is_confirmed() {
            return Err(UaError::WrongState(state));
        }
        let dialog = held.dialog.ok_or(UaError::WrongState(state))?;
        let snapshot = self
            .endpoint
            .dialog(dialog)
            .ok_or(UaError::WrongState(state))?;
        let remote_tag = snapshot
            .remote_tag
            .as_ref()
            .ok_or(UaError::WrongState(state))?;

        // §6.1: exactly one to-tag and one from-tag, and they name the dialog
        // from the point of view of the end that is being replaced — so ours
        // is its remote and its local is ours
        let mut replaces = Vec::new();
        replaces.extend_from_slice(snapshot.call_id.as_bytes());
        replaces.extend_from_slice(b";to-tag=");
        replaces.extend_from_slice(remote_tag.as_bytes());
        replaces.extend_from_slice(b";from-tag=");
        replaces.extend_from_slice(snapshot.local_tag.as_bytes());

        let mut value = Vec::new();
        value.push(b'<');
        value.extend_from_slice(snapshot.remote_target.as_bytes());
        value.extend_from_slice(b"?Replaces=");
        escape(&replaces, &mut value);
        value.push(b'>');
        self.refer(call, &value, now)
    }

    /// Take a transfer that was asked for, and place the call it names.
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`], [`UaError::WrongState`] when nothing was
    /// asked, [`UaError::NoSuchAccount`], or [`UaError::Send`].
    pub fn accept_transfer(
        &mut self,
        call: CallHandle,
        now: Instant,
    ) -> Result<CallHandle, UaError> {
        let (transaction, wanted, account) = {
            let held = self.calls.get_mut(&call).ok_or(UaError::NoSuchCall)?;
            let state = held.state;
            let asked = held
                .asked_to_refer
                .take()
                .ok_or(UaError::WrongState(state))?;
            let account = held.account.ok_or(UaError::NoSuchAccount)?;
            let referred = held.referred.as_mut().ok_or(UaError::WrongState(state))?;
            (
                referred
                    .transaction
                    .take()
                    .ok_or(UaError::WrongState(state))?,
                asked,
                account,
            )
        };
        // §2.4.2: "the UA MUST return a 202 Accepted response before the REFER
        // transaction expires"
        let Ok(accepted) = StatusCode::new(202) else {
            return Err(UaError::NoSuchCall);
        };
        self.endpoint
            .respond(transaction, &OutgoingResponse::new(accepted), now)?;
        // §2.4.5: while it is only trying, the body is a 100
        self.notify(call, TRYING, RUNNING, now);

        let mut placed = OutgoingCall::new(wanted.target.clone());
        if let Some(ref replaces) = wanted.replaces {
            placed = placed.header(HeaderName::Replaces, replaces);
        }
        let new = self.call(account, &placed, now)?;
        if let Some(held) = self.calls.get_mut(&call)
            && let Some(referred) = held.referred.as_mut()
        {
            referred.placed = Some(new);
        }
        if let Some(held) = self.calls.get_mut(&new) {
            held.reporting_to = Some(call);
        }
        self.drain(now);
        Ok(new)
    }

    /// Refuse one.
    ///
    /// # Errors
    /// As [`UserAgent::accept_transfer`].
    pub fn reject_transfer(
        &mut self,
        call: CallHandle,
        status: StatusCode,
        now: Instant,
    ) -> Result<(), UaError> {
        let transaction = {
            let held = self.calls.get_mut(&call).ok_or(UaError::NoSuchCall)?;
            let state = held.state;
            held.asked_to_refer = None;
            let referred = held.referred.as_mut().ok_or(UaError::WrongState(state))?;
            referred
                .transaction
                .take()
                .ok_or(UaError::WrongState(state))?
        };
        self.endpoint
            .respond(transaction, &OutgoingResponse::new(status), now)?;
        if let Some(held) = self.calls.get_mut(&call) {
            held.referred = None;
        }
        self.drain(now);
        Ok(())
    }
}

// -- sending -----------------------------------------------------------------

impl UserAgent {
    fn refer(&mut self, call: CallHandle, refer_to: &[u8], now: Instant) -> Result<(), UaError> {
        let (dialog, contact, state) = {
            let held = self.calls.get(&call).ok_or(UaError::NoSuchCall)?;
            if held.referring.is_some() {
                return Err(UaError::WrongState(held.state));
            }
            (
                held.dialog.ok_or(UaError::WrongState(held.state))?,
                held.contact.clone(),
                held.state,
            )
        };
        if !state.is_confirmed() {
            return Err(UaError::WrongState(state));
        }
        // §2: "REFER creates a dialog, and MAY be Record-Routed, hence MUST
        // contain a single Contact header field value."
        let request = OutgoingInDialogRequest::new(Method::Refer)
            .contact(&contact)
            .header(HeaderName::ReferTo, refer_to)
            .header(HeaderName::ReferredBy, &contact);
        let transaction = self.endpoint.request_in_dialog(dialog, &request, now)?;
        if let Some(held) = self.calls.get_mut(&call) {
            held.referring = Some(AnyTransactionId::NonInviteClient(transaction));
        }
        self.remember_request(call, AnyTransactionId::NonInviteClient(transaction));
        self.drain(now);
        Ok(())
    }

    /// Say how the referred call is going (§2.4.4, §2.4.5).
    fn notify(&mut self, call: CallHandle, sipfrag: &[u8], state: &[u8], now: Instant) {
        let Some(held) = self.calls.get(&call) else {
            return;
        };
        let (Some(dialog), contact) = (held.dialog, held.contact.clone()) else {
            return;
        };
        let request = OutgoingInDialogRequest::new(Method::Notify)
            .contact(&contact)
            .header(HeaderName::Event, REFER)
            .header(HeaderName::SubscriptionState, state)
            .body(b"message/sipfrag;version=2.0", Arc::from(sipfrag.to_vec()));
        if let Ok(id) = self.endpoint.request_in_dialog(dialog, &request, now) {
            self.remember_request(call, AnyTransactionId::NonInviteClient(id));
        }
    }

    /// The referred call reached a final answer, so the subscription is over.
    pub(crate) fn report_transfer(&mut self, placed: CallHandle, status: StatusCode, now: Instant) {
        let Some(reporting_to) = self.calls.get(&placed).and_then(|held| held.reporting_to) else {
            return;
        };
        let finished = status.is_final();
        let already = self
            .calls
            .get(&reporting_to)
            .and_then(|held| held.referred)
            .is_some_and(|referred| referred.finished);
        if already {
            return;
        }
        let line = status_line(status);
        self.notify(
            reporting_to,
            &line,
            if finished { FINISHED } else { RUNNING },
            now,
        );
        if finished
            && let Some(held) = self.calls.get_mut(&reporting_to)
            && let Some(referred) = held.referred.as_mut()
        {
            referred.finished = true;
        }
    }
}

// -- what comes back ---------------------------------------------------------

impl UserAgent {
    /// `None` when the event was about a transfer.
    pub(crate) fn on_transfer_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        match event {
            Event::IncomingInDialog {
                transaction,
                dialog,
                ref request,
            } if request.as_raw().method() == Some(Method::Refer) => {
                let call = self.by_dialog.get(&dialog).copied()?;
                let request = request.clone();
                self.on_refer(call, transaction, &request, now);
                None
            }
            Event::IncomingInDialog {
                transaction,
                dialog,
                ref request,
            } if request.as_raw().method() == Some(Method::Notify) => {
                let call = self.by_dialog.get(&dialog).copied()?;
                let request = request.clone();
                self.on_notify(call, transaction, &request, now);
                None
            }
            other => Some(other),
        }
    }

    /// A REFER arrived (§2.4.2).
    fn on_refer(
        &mut self,
        call: CallHandle,
        transaction: TransactionId<sipral_core::transaction::NonInviteServer>,
        request: &OwnedMessage,
        now: Instant,
    ) {
        let raw = request.as_raw();
        // §2.4.1: "A REFER request MUST contain exactly one Refer-To header
        // field value", and §2.4.2 answers anything else with a 400
        let Some(wanted) = refer_to(&raw) else {
            let Ok(bad) = StatusCode::new(400) else {
                return;
            };
            self.endpoint
                .respond(transaction, &OutgoingResponse::new(bad), now)
                .ok();
            return;
        };
        if let Some(held) = self.calls.get_mut(&call) {
            held.referred = Some(Referred {
                transaction: Some(transaction),
                placed: None,
                finished: false,
            });
            held.asked_to_refer = Some(wanted.clone());
        }
        self.events.push_back(UaEvent::TransferRequested {
            call,
            target: wanted.target,
            attended: wanted.replaces.is_some(),
            request: request.clone(),
        });
    }

    /// One of the NOTIFYs a REFER of ours asked for (§2.4.4).
    fn on_notify(
        &mut self,
        call: CallHandle,
        transaction: TransactionId<sipral_core::transaction::NonInviteServer>,
        request: &OwnedMessage,
        now: Instant,
    ) {
        // §4.1.3 of RFC 6665 has an answer go out before anything else, and
        // never after asking a person
        self.endpoint
            .respond(transaction, &OutgoingResponse::new(StatusCode::OK), now)
            .ok();
        let raw = request.as_raw();
        let Some(status) = sipfrag_status(raw.body()) else {
            return;
        };
        let over = raw
            .header(HeaderName::SubscriptionState)
            .is_some_and(|value| Params::split(value).0.eq_ignore_ascii_case(b"terminated"));

        if status.is_provisional() {
            self.events
                .push_back(UaEvent::TransferProgress { call, status });
            return;
        }
        self.events
            .push_back(UaEvent::TransferDone { call, status });
        if let Some(held) = self.calls.get_mut(&call) {
            held.referring = None;
        }
        // the transfer worked, so this end is not in the call any more. A
        // failed one leaves it exactly where it was, which is the point of
        // waiting for the answer rather than hanging up when the REFER went
        if status.is_success() && over {
            self.hangup(call, now).ok();
        }
    }
}

// -- Replaces ----------------------------------------------------------------

impl UserAgent {
    /// Which of this end's calls an incoming `Replaces` names, and what §3
    /// says to do about it.
    ///
    /// `Ok(None)` when the request carries no `Replaces` at all.
    pub(crate) fn replaced_by(
        &self,
        request: &RawMessage<'_>,
    ) -> Result<Option<CallHandle>, StatusCode> {
        let Some(value) = request.header(HeaderName::Replaces) else {
            return Ok(None);
        };
        let (call_id, params) = Params::split(value);
        // §6.1: "A Replaces header field MUST contain exactly one to-tag and
        // exactly one from-tag, as they are required for unique dialog
        // matching"
        let (Some(to_tag), Some(from_tag)) = (params.get("to-tag"), params.get("from-tag")) else {
            return Err(StatusCode::new(400).unwrap_or(StatusCode::SERVER_ERROR));
        };
        let early_only = params.get("early-only").is_some();

        let mut found = None;
        for (handle, held) in &self.calls {
            let Some(dialog) = held.dialog else {
                continue;
            };
            let Some(snapshot) = self.endpoint.dialog(dialog) else {
                continue;
            };
            let ours = snapshot.local_tag.as_bytes() == &*to_tag
                && snapshot
                    .remote_tag
                    .as_ref()
                    .is_some_and(|tag| tag.as_bytes() == &*from_tag)
                && snapshot.call_id.as_bytes() == call_id;
            if !ours {
                continue;
            }
            // §3: "If the Replaces header field matches more than one dialog,
            // the UA MUST act as if no match is found."
            if found.is_some() {
                return Err(StatusCode::CALL_DOES_NOT_EXIST);
            }
            found = Some((*handle, held.state, held.direction));
        }

        let Some((handle, state, direction)) = found else {
            return Err(StatusCode::CALL_DOES_NOT_EXIST);
        };
        match state {
            CallState::Terminating | CallState::Terminated => {
                // §3: "the UA SHOULD decline the request with a 603 Declined"
                Err(StatusCode::new(603).unwrap_or(StatusCode::BUSY_HERE))
            }
            CallState::Confirmed | CallState::Consulting if early_only => {
                // §3: "If the flag is present, the UA rejects the request with
                // a 486 Busy response."
                Err(StatusCode::BUSY_HERE)
            }
            CallState::Confirmed | CallState::Consulting => Ok(Some(handle)),
            // §3: an early dialog this end did not originate cannot be
            // replaced by this end at all
            _ if direction == Direction::Outgoing => Ok(Some(handle)),
            _ => Err(StatusCode::CALL_DOES_NOT_EXIST),
        }
    }

    /// The call that was replaced is over, now that the one replacing it is
    /// answered (§3).
    pub(crate) fn shut_down_replaced(&mut self, call: CallHandle, now: Instant) {
        let replaced = self.calls.get(&call).and_then(|held| held.replaces);
        let Some(replaced) = replaced else {
            return;
        };
        if let Some(held) = self.calls.get_mut(&call) {
            held.replaces = None;
        }
        self.events
            .push_back(UaEvent::CallReplaced { call, replaced });
        // a confirmed dialog goes with a BYE and an early one of ours with a
        // CANCEL; hanging up is the one call that already knows which
        self.hangup(replaced, now).ok();
    }

    /// Refuse an INVITE whose `Replaces` names nothing this end can give up.
    pub(crate) fn refuse_replaces(
        &mut self,
        transaction: TransactionId<InviteServer>,
        status: StatusCode,
        now: Instant,
    ) {
        self.endpoint
            .respond_invite(transaction, &OutgoingResponse::new(status), now)
            .ok();
    }
}

/// The `Refer-To` of a REFER, when it has exactly one that can be read.
fn refer_to(request: &RawMessage<'_>) -> Option<ReferTo> {
    if request.header_count(HeaderName::ReferTo) != 1 {
        return None;
    }
    let value = request.header(HeaderName::ReferTo)?;
    let inside = between_angles(value).unwrap_or(value);
    let (uri, replaces) = split_replaces(inside);
    Some(ReferTo {
        target: Uri::parse(uri).ok()?,
        replaces,
    })
}

/// `<...>`, when the value has them.
fn between_angles(value: &[u8]) -> Option<&[u8]> {
    let start = value.iter().position(|byte| *byte == b'<')? + 1;
    let end = value.iter().rposition(|byte| *byte == b'>')?;
    value.get(start..end)
}

/// A URI and the `Replaces` header it carries in its own header part, unescaped
/// so that it can go straight into the new INVITE.
fn split_replaces(uri: &[u8]) -> (&[u8], Option<Box<[u8]>>) {
    let Some(at) = uri.iter().position(|byte| *byte == b'?') else {
        return (uri, None);
    };
    let head = uri.get(..at).unwrap_or_default();
    let query = uri.get(at + 1..).unwrap_or_default();
    for field in query.split(|byte| *byte == b'&') {
        let Some(split) = field.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        let name = field.get(..split).unwrap_or_default();
        if !name.eq_ignore_ascii_case(b"Replaces") {
            continue;
        }
        let value = field.get(split + 1..).unwrap_or_default();
        return (head, Some(unescape(value)));
    }
    (head, None)
}

/// Percent-encode what a URI header value may not carry literally.
fn escape(value: &[u8], out: &mut Vec<u8>) {
    for byte in value {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(*byte),
            other => {
                out.push(b'%');
                out.extend_from_slice(format!("{other:02X}").as_bytes());
            }
        }
    }
}

/// And back.
fn unescape(value: &[u8]) -> Box<[u8]> {
    let mut out = Vec::with_capacity(value.len());
    let mut rest = value;
    while let Some(&byte) = rest.first() {
        if byte == b'%'
            && let Some(pair) = rest.get(1..3)
            && let Ok(text) = core::str::from_utf8(pair)
            && let Ok(decoded) = u8::from_str_radix(text, 16)
        {
            out.push(decoded);
            rest = rest.get(3..).unwrap_or_default();
            continue;
        }
        out.push(byte);
        rest = rest.get(1..).unwrap_or_default();
    }
    out.into_boxed_slice()
}

/// The status a `message/sipfrag` reports (§2.4.5).
fn sipfrag_status(body: &[u8]) -> Option<StatusCode> {
    let line = body.split(|byte| *byte == b'\n').next()?;
    let mut fields = line.split(|byte| *byte == b' ').filter(|f| !f.is_empty());
    let version = fields.next()?;
    if !version.starts_with(b"SIP/") {
        return None;
    }
    let code = core::str::from_utf8(fields.next()?).ok()?;
    StatusCode::new(code.parse().ok()?).ok()
}

/// A status line to put in one.
fn status_line(status: StatusCode) -> Vec<u8> {
    let reason = status.reason().unwrap_or("Unknown");
    format!("SIP/2.0 {} {reason}\r\n", status.get()).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::{escape, sipfrag_status, split_replaces, status_line, unescape};
    use sipral_core::msg::StatusCode;

    #[test]
    fn a_replaces_survives_being_put_in_a_uri_and_taken_out_again() {
        let original = b"a84b4c76e66710;to-tag=abc;from-tag=def";
        let mut escaped = Vec::new();
        escape(original, &mut escaped);
        assert!(
            !escaped.contains(&b';'),
            "a semicolon in a URI header would end the header: {}",
            String::from_utf8_lossy(&escaped)
        );
        assert_eq!(&*unescape(&escaped), original);
    }

    #[test]
    fn a_refer_to_with_a_replaces_gives_back_both_halves() {
        let uri = b"sip:bob@192.0.2.9?Replaces=call%3Bto-tag%3Dx%3Bfrom-tag%3Dy";
        let (target, replaces) = split_replaces(uri);
        assert_eq!(target, b"sip:bob@192.0.2.9");
        assert_eq!(
            replaces.as_deref(),
            Some(&b"call;to-tag=x;from-tag=y"[..]),
            "and it is unescaped, ready for the new INVITE"
        );
    }

    #[test]
    fn a_refer_to_without_one_is_a_plain_target() {
        let (target, replaces) = split_replaces(b"sip:carol@example.com");
        assert_eq!(target, b"sip:carol@example.com");
        assert!(replaces.is_none());
    }

    #[test]
    fn a_sipfrag_says_what_happened_and_nothing_else_does() {
        // 2.4.5: "The body of a NOTIFY MUST begin with a SIP Response
        // Status-Line"
        assert_eq!(
            sipfrag_status(b"SIP/2.0 100 Trying\r\n"),
            Some(StatusCode::TRYING)
        );
        assert_eq!(sipfrag_status(b"SIP/2.0 200 OK\r\n"), Some(StatusCode::OK));
        assert_eq!(
            sipfrag_status(b"SIP/2.0 486 Busy Here\r\n\r\n"),
            Some(StatusCode::BUSY_HERE)
        );
        assert_eq!(sipfrag_status(b"INVITE sip:x SIP/2.0\r\n"), None);
        assert_eq!(sipfrag_status(b""), None);
    }

    #[test]
    fn a_status_line_reads_back_as_the_status_it_was_written_from() {
        for status in [StatusCode::TRYING, StatusCode::RINGING, StatusCode::OK] {
            assert_eq!(sipfrag_status(&status_line(status)), Some(status));
        }
    }
}
