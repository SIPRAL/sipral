// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! SIP MESSAGE (RFC 3428): instant messages that stand alone, pager-style.
//!
//! No dialog is created (§3), so no `Contact` goes on one (§4).
//! [`UserAgent::message_in_call`] sends one inside an existing dialog.
//!
//! Incoming: 200 when delivered; this stack never sends 202, which is for
//! relays (§7), but reads one. 415 with an `Accept` (§21.4.13) for a
//! `Content-Type` not declared via [`Account::accepts_message_type`]; 413
//! over the local size limit.
//!
//! Outgoing, §8: a body over 1300 bytes is refused with
//! [`UaError::MessageTooLarge`] unless [`Account::transport_protocol`] names
//! a congestion-controlled transport. A second out-of-dialog MESSAGE to the
//! same target, or a second in-dialog one on an unsafe route, is refused
//! with [`UaError::MessagePending`] until the first settles.

use std::sync::Arc;
use std::time::Instant;

use sipral_core::dialog::CallId;
use sipral_core::endpoint::{
    Event, FailureReason, OutgoingInDialogRequest, OutgoingRequest, OutgoingResponse,
    TransportProtocol,
};
use sipral_core::msg::{HeaderName, Method, OwnedMessage, StatusCode, Uri};
use sipral_core::transaction::{AnyTransactionId, NonInviteClient, NonInviteServer, TransactionId};

use crate::account::{Account, AccountId};
use crate::agent::UserAgent;
use crate::call::CallHandle;
use crate::error::UaError;
use crate::event::UaEvent;

/// RFC 3428 §8's ceiling for a MESSAGE this end cannot prove will stay off a
/// congestion-unsafe hop. Checked against the body only; the headers add a
/// few hundred bytes at most.
pub const MAX_UNSAFE_BODY_BYTES: usize = 1300;

/// Largest incoming MESSAGE body; above it the answer is 413 (§21.4.11).
/// A local policy, well under the largest UDP datagram.
const MAX_INCOMING_BODY_BYTES: usize = 32 * 1024;

/// One MESSAGE this layer sent. Minted before anything reaches a transport,
/// so a send that never leaves can still report [`UaEvent::MessageSent`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageHandle(pub(crate) u32);

/// What is remembered about a MESSAGE this layer sent, until its answer.
#[derive(Debug)]
pub(crate) struct SentMessage {
    /// Whose credentials answer a challenge, when there are any.
    account: Option<AccountId>,
    /// The out-of-dialog target as it went in `To`, for §8's one pending
    /// MESSAGE per URI. `None` inside a dialog.
    target: Option<Box<[u8]>>,
    /// A 401/407 not yet known to be answerable. Held until the end of the
    /// drain: a following [`Event::Challenged`] turns it into a retry.
    unanswered: Option<OwnedMessage>,
    /// The challenged transaction whose retry waits for a stream
    /// (RFC 3261 §18.1.1, [`crate::oversize`]). Not settled meanwhile.
    waiting_for_stream: Option<AnyTransactionId>,
    /// The call, for an in-dialog send on a route not known to be
    /// congestion-controlled, so §8's no-overlap rule can be checked.
    overlap_call: Option<CallHandle>,
}

// -- sending -------------------------------------------------------------

impl UserAgent {
    /// Send an instant message outside any dialog (RFC 3428 §3), addressed
    /// to `target`.
    ///
    /// The handle comes back whether or not the MESSAGE reached a
    /// transport. The outcome arrives as [`UaEvent::MessageSent`]: 200, 202
    /// from a relay, a refusal, or a synthesised 408/503 for no answer
    /// (RFC 3261 §8.1.3.1). The handle is dead after that.
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`]; [`UaError::MessageTooLarge`] over §8's
    /// 1300-byte ceiling, unless [`Account::transport_protocol`] said this
    /// account's transport is congestion-controlled;
    /// [`UaError::MessagePending`] while an earlier out-of-dialog MESSAGE to
    /// the same target has not been answered; or [`UaError::Send`].
    pub fn message(
        &mut self,
        account: AccountId,
        target: Uri,
        content_type: &[u8],
        body: &[u8],
        now: Instant,
    ) -> Result<MessageHandle, UaError> {
        let config = self.accounts.get(&account).ok_or(UaError::NoSuchAccount)?;
        check_outgoing_size(config.protocol, body.len())?;
        let target_key = bracketed(&target);
        if self
            .messages
            .values()
            .any(|sent| sent.target.as_deref() == Some(&*target_key))
        {
            return Err(UaError::MessagePending);
        }
        let (transport, remote) = config.destination().ok_or(UaError::NotLocated)?;
        let call_id = CallId::new(&self.endpoint.token());
        let request = OutgoingRequest::new(Method::Message, target, transport, remote)
            .to(&target_key)
            .from(&config.sender_value())
            .call_id(call_id)
            .body(content_type, Arc::from(body));
        // §22.2: reuse credentials from an earlier challenge to skip a 401
        let id = match config.credentials.clone() {
            Some(credentials) => {
                self.endpoint
                    .request_with_credentials(&request, &credentials, now)?
            }
            None => self.endpoint.request(&request, now)?,
        };
        let handle = self.mint_message();
        self.messages.insert(
            handle,
            SentMessage {
                account: Some(account),
                target: Some(target_key),
                unanswered: None,
                waiting_for_stream: None,
                overlap_call: None,
            },
        );
        self.by_message
            .insert(AnyTransactionId::NonInviteClient(id), handle);
        self.drain(now);
        Ok(handle)
    }

    /// Send an instant message inside `call`'s dialog (§4's MAY).
    ///
    /// The dialog is not refreshed. Unless [`Account::transport_protocol`]
    /// names a byte-stream transport, a second MESSAGE on `call` while one
    /// is unanswered is refused (§8, no overlapping in-dialog MESSAGEs).
    ///
    /// # Errors
    /// [`UaError::NoSuchCall`]; [`UaError::WrongState`] for a call with no
    /// dialog to send one in yet; [`UaError::MessageTooLarge`], as
    /// [`UserAgent::message`]; [`UaError::MessagePending`] for a second
    /// in-dialog MESSAGE on a route not known to be congestion-controlled;
    /// or [`UaError::Send`].
    pub fn message_in_call(
        &mut self,
        call: CallHandle,
        content_type: &[u8],
        body: &[u8],
        now: Instant,
    ) -> Result<MessageHandle, UaError> {
        let held = self.calls.get(&call).ok_or(UaError::NoSuchCall)?;
        let dialog = held.dialog.ok_or(UaError::WrongState(held.state))?;
        let account = held.account;
        // no account means no proof of congestion control: §8's default
        let protocol = account
            .and_then(|id| self.accounts.get(&id))
            .and_then(|config| config.protocol);
        check_outgoing_size(protocol, body.len())?;
        let congestion_controlled = is_congestion_controlled(protocol);
        if !congestion_controlled
            && self
                .messages
                .values()
                .any(|sent| sent.overlap_call == Some(call))
        {
            return Err(UaError::MessagePending);
        }
        let request =
            OutgoingInDialogRequest::new(Method::Message).body(content_type, Arc::from(body));
        let id = self.endpoint.request_in_dialog(dialog, &request, now)?;
        let handle = self.mint_message();
        self.messages.insert(
            handle,
            SentMessage {
                account,
                target: None,
                unanswered: None,
                waiting_for_stream: None,
                overlap_call: (!congestion_controlled).then_some(call),
            },
        );
        self.by_message
            .insert(AnyTransactionId::NonInviteClient(id), handle);
        self.drain(now);
        Ok(handle)
    }

    fn mint_message(&mut self) -> MessageHandle {
        let handle = MessageHandle(self.next_message);
        self.next_message = self.next_message.wrapping_add(1);
        handle
    }
}

/// A byte-stream transport: §8's "positive knowledge" of congestion control.
const fn is_congestion_controlled(protocol: Option<TransportProtocol>) -> bool {
    matches!(
        protocol,
        Some(
            TransportProtocol::Tcp
                | TransportProtocol::Tls
                | TransportProtocol::Ws
                | TransportProtocol::Wss
        )
    )
}

fn check_outgoing_size(protocol: Option<TransportProtocol>, len: usize) -> Result<(), UaError> {
    if !is_congestion_controlled(protocol) && len > MAX_UNSAFE_BODY_BYTES {
        return Err(UaError::MessageTooLarge {
            size: len,
            limit: MAX_UNSAFE_BODY_BYTES,
        });
    }
    Ok(())
}

/// `<uri>`, so URI parameters are not read as `To` parameters.
fn bracketed(uri: &Uri) -> Box<[u8]> {
    let mut out = Vec::with_capacity(uri.as_bytes().len() + 2);
    out.push(b'<');
    out.extend_from_slice(uri.as_bytes());
    out.push(b'>');
    out.into_boxed_slice()
}

// -- what comes back about a MESSAGE this end sent ------------------------

impl UserAgent {
    fn message_of(&self, transaction: TransactionId<NonInviteClient>) -> Option<MessageHandle> {
        self.by_message
            .get(&AnyTransactionId::NonInviteClient(transaction))
            .copied()
    }

    fn on_message_response(
        &mut self,
        message: MessageHandle,
        status: StatusCode,
        response: &OwnedMessage,
    ) {
        if status.is_provisional() {
            return;
        }
        if matches!(status.get(), 401 | 407) {
            if let Some(held) = self.messages.get_mut(&message) {
                held.unanswered = Some(response.clone());
            }
            return;
        }
        self.finish_message(message, status, Some(response.clone()));
    }

    fn on_message_failed(&mut self, message: MessageHandle, reason: FailureReason) {
        let status = unanswered(reason);
        self.finish_message(message, status, None);
    }

    fn on_message_challenged(
        &mut self,
        message: MessageHandle,
        transaction: AnyTransactionId,
        now: Instant,
    ) {
        let account = self.messages.get(&message).and_then(|held| held.account);
        let Some(credentials) = self.credentials_for_challenge(account, transaction) else {
            // `settle_message_challenges` reports the refusal
            return;
        };
        match self
            .endpoint
            .retry_with_credentials(transaction, &credentials, now)
        {
            Ok(retried) => self.message_retry_went(message, transaction, retried),
            // §18.1.1: needs a connection first
            Err(error) if crate::agent::wants_a_stream(&error) => {
                if let Some(held) = self.messages.get_mut(&message) {
                    held.waiting_for_stream = Some(transaction);
                }
            }
            // the refusal held above stands
            Err(_) => {}
        }
    }

    /// The retry is a transaction now, and the handle names it.
    pub(crate) fn message_retry_went(
        &mut self,
        message: MessageHandle,
        transaction: AnyTransactionId,
        retried: AnyTransactionId,
    ) {
        self.by_message.remove(&transaction);
        self.by_message.insert(retried, message);
        if let Some(held) = self.messages.get_mut(&message) {
            held.unanswered = None;
            held.waiting_for_stream = None;
        }
    }

    /// Send the MESSAGE retries §18.1.1 held back, now that there is a
    /// connection.
    pub(crate) fn resume_parked_messages(&mut self, now: Instant) {
        let waiting: Vec<(MessageHandle, AnyTransactionId)> = self
            .messages
            .iter()
            .filter_map(|(handle, held)| held.waiting_for_stream.map(|failed| (*handle, failed)))
            .collect();
        for (message, failed) in waiting {
            let account = self.messages.get(&message).and_then(|held| held.account);
            let credentials = self.credentials_for_challenge(account, failed);
            let outcome = credentials.map(|credentials| {
                self.endpoint
                    .retry_with_credentials(failed, &credentials, now)
            });
            match outcome {
                Some(Ok(retried)) => self.message_retry_went(message, failed, retried),
                Some(Err(error)) if crate::agent::wants_a_stream(&error) => {}
                // the next settle reports the refusal it still carries
                _ => {
                    if let Some(held) = self.messages.get_mut(&message) {
                        held.waiting_for_stream = None;
                    }
                }
            }
        }
    }

    /// No stream is coming: each MESSAGE waiting for one is reported with
    /// `status` (513), not the 401/407 its credentials never answered.
    pub(crate) fn give_up_messages(&mut self, status: StatusCode) {
        let waiting: Vec<(MessageHandle, AnyTransactionId)> = self
            .messages
            .iter()
            .filter_map(|(handle, held)| held.waiting_for_stream.map(|failed| (*handle, failed)))
            .collect();
        for (message, failed) in waiting {
            self.endpoint.abandon_challenge(failed);
            self.finish_message(message, status, None);
        }
    }

    /// Whether a MESSAGE's answer to a challenge waits for a stream.
    pub(crate) fn messages_wait_for_a_stream(&self) -> bool {
        self.messages
            .values()
            .any(|held| held.waiting_for_stream.is_some())
    }

    /// A challenge with no retry is a refusal. Called at the end of every
    /// drain.
    pub(crate) fn settle_message_challenges(&mut self) {
        let refused: Vec<(MessageHandle, OwnedMessage)> = self
            .messages
            .iter_mut()
            // its retry waits for a connection, not refused yet
            .filter(|(_, held)| held.waiting_for_stream.is_none())
            .filter_map(|(handle, held)| held.unanswered.take().map(|response| (*handle, response)))
            .collect();
        for (message, response) in refused {
            let status = response
                .as_raw()
                .status()
                .unwrap_or(StatusCode::UNAUTHORIZED);
            self.finish_message(message, status, Some(response));
        }
    }

    fn finish_message(
        &mut self,
        message: MessageHandle,
        status: StatusCode,
        response: Option<OwnedMessage>,
    ) {
        self.messages.remove(&message);
        self.by_message.retain(|_, owner| *owner != message);
        self.events.push_back(UaEvent::MessageSent {
            message,
            status,
            response,
        });
    }
}

/// RFC 3261 §8.1.3.1: a timeout is a 408, a dead transport a 503.
const fn unanswered(reason: FailureReason) -> StatusCode {
    match reason {
        FailureReason::TransportFailed => StatusCode::SERVICE_UNAVAILABLE,
        // `Refused` arrives as `Event::Response`, never here
        FailureReason::Timeout | FailureReason::Refused | _ => StatusCode::REQUEST_TIMEOUT,
    }
}

// -- a MESSAGE that arrived -------------------------------------------------

impl UserAgent {
    /// `None` when the event was about a MESSAGE and has been dealt with;
    /// the event back otherwise.
    pub(crate) fn on_message_event(&mut self, event: Event, now: Instant) -> Option<Event> {
        match event {
            Event::IncomingOutOfDialog {
                transaction,
                ref request,
            } if request.as_raw().method() == Some(Method::Message) => {
                let request = request.clone();
                self.on_incoming_message(None, transaction, &request, now);
                None
            }
            Event::IncomingInDialog {
                transaction,
                dialog,
                ref request,
            } if request.as_raw().method() == Some(Method::Message) => {
                let call = self.by_dialog.get(&dialog).copied();
                let request = request.clone();
                self.on_incoming_message(call, transaction, &request, now);
                None
            }
            Event::Response {
                transaction,
                status,
                ref response,
            } => {
                let Some(message) = self.message_of(transaction) else {
                    return Some(event);
                };
                let response = response.clone();
                self.on_message_response(message, status, &response);
                None
            }
            Event::RequestFailed {
                transaction,
                reason,
            } => {
                let Some(message) = self.message_of(transaction) else {
                    return Some(event);
                };
                self.on_message_failed(message, reason);
                None
            }
            Event::Challenged { transaction, .. } | Event::TokenChallenged { transaction, .. } => {
                let Some(message) = self.by_message.get(&transaction).copied() else {
                    return Some(event);
                };
                self.on_message_challenged(message, transaction, now);
                None
            }
            other => Some(other),
        }
    }

    /// Answered at once: §7 wants an immediate final response, not tied to
    /// displaying the message.
    fn on_incoming_message(
        &mut self,
        call: Option<CallHandle>,
        transaction: TransactionId<NonInviteServer>,
        request: &OwnedMessage,
        now: Instant,
    ) {
        let raw = request.as_raw();
        let body = raw.body();
        if body.len() > MAX_INCOMING_BODY_BYTES {
            self.answer_message(transaction, StatusCode::REQUEST_ENTITY_TOO_LARGE, &[], now);
            return;
        }
        let account = self.line_for(&raw);
        // `text/plain` is mandatory (§4); the rest must be declared
        let kind = raw.content_type().ok();
        let accepted = kind.is_none_or(|kind| {
            kind.is("text", "plain")
                || account
                    .and_then(|id| self.accounts.get(&id))
                    .is_some_and(|config| accepts(config, kind.kind(), kind.subtype()))
        });
        if !accepted {
            let accept = accept_header(account.and_then(|id| self.accounts.get(&id)));
            self.answer_message(
                transaction,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                &accept,
                now,
            );
            return;
        }
        self.answer_message(transaction, StatusCode::OK, &[], now);
        self.events.push_back(UaEvent::MessageReceived {
            account,
            call,
            request: request.clone(),
        });
    }

    fn answer_message(
        &mut self,
        transaction: TransactionId<NonInviteServer>,
        status: StatusCode,
        accept: &[u8],
        now: Instant,
    ) {
        let mut response = OutgoingResponse::new(status);
        if !accept.is_empty() {
            response = response.header(HeaderName::Accept, accept);
        }
        // a vanished transaction leaves the far end's timer to decide
        self.endpoint.respond(transaction, &response, now).ok();
    }
}

/// Whether `kind/subtype` is one `account` declared with
/// [`Account::accepts_message_type`].
fn accepts(account: &Account, kind: &[u8], subtype: &[u8]) -> bool {
    account.message_types.iter().any(|configured| {
        let Some(slash) = configured.iter().position(|byte| *byte == b'/') else {
            return false;
        };
        let (their_kind, their_subtype) = configured.split_at(slash);
        let their_subtype = their_subtype.get(1..).unwrap_or_default();
        their_kind.eq_ignore_ascii_case(kind) && their_subtype.eq_ignore_ascii_case(subtype)
    })
}

/// `Accept: text/plain, ...` for a 415 (§21.4.13).
fn accept_header(account: Option<&Account>) -> Vec<u8> {
    let mut out = Vec::from(&b"text/plain"[..]);
    for extra in account
        .into_iter()
        .flat_map(|config| config.message_types.iter())
    {
        out.extend_from_slice(b", ");
        out.extend_from_slice(extra);
    }
    out
}
