// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! SIP MESSAGE (RFC 3428): instant messages that stand alone, pager-style.
//!
//! **No dialog.** §3: "MESSAGE requests do not themselves initiate a SIP
//! dialog", and §4 forbids a `Contact` on one for the same reason — nothing
//! here is ever addressed later by anything but a fresh request. A UAC "MAY
//! associate a MESSAGE request with an existing dialog" (§4), which is
//! [`UserAgent::message_in_call`]; the two share everything but where the
//! request travels.
//!
//! **What this stack answers with, and why.** §7: a UAS that delivers a
//! message to the user answers 200; 202 is for "a message relay, storing the
//! message and forwarding it later on" — this stack is neither, so it never
//! sends one, though it reads one correctly when a relay in front of the far
//! end sends it back for a MESSAGE this end sent. 415 answers a
//! `Content-Type` the application never declared it takes
//! ([`Account::accepts_message_type`]), with an `Accept` built from what it
//! did declare, because §21.4.13 asks for exactly that. 413 answers a body
//! over the policy limit this stack holds an incoming MESSAGE to.
//!
//! **The size ceiling is §8's, and it is this stack's to enforce on the way
//! out, not the network's.** "The size of MESSAGE requests outside of a
//! media session MUST NOT exceed 1300 bytes, unless the UAC has positive
//! knowledge that the message will not traverse a congestion-unsafe link at
//! any hop." Nothing in this crate has that knowledge unless the
//! application says so ([`Account::transport_protocol`]), so the default is
//! to refuse a larger body outright with [`UaError::MessageTooLarge`] rather
//! than let the core fragment it over UDP.
//!
//! **Not more than one out-of-dialog MESSAGE per target at a time.** §8:
//! "A UAC MUST NOT initiate a new out-of-dialog MESSAGE transaction to a
//! given URI if there is a previous out-of-dialog transaction pending for
//! the same URI." [`UserAgent::message`] refuses a second one with
//! [`UaError::MessagePending`] until the first settles.
//!
//! **Nor more than one in-dialog MESSAGE on a congestion-unsafe route.** The
//! same sentence of §8 continues: "Similarly, A UAC SHOULD NOT initiate
//! overlapping MESSAGE transactions inside a dialog, and MUST NOT do so
//! unless the route set for that dialog uses a congestion-controlled
//! transport at every hop." [`UserAgent::message_in_call`] holds every call
//! to that MUST NOT the same way [`Account::transport_protocol`] lifts the
//! size ceiling: unset, or set to anything but a byte-stream protocol, a
//! second in-dialog MESSAGE is refused with [`UaError::MessagePending`]
//! while the first has not been answered.

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
/// congestion-unsafe hop. Checked against the body alone: the headers a
/// MESSAGE carries without a `Contact` are a couple of hundred bytes at
/// most, and a policy meant to keep this end off a fragmented UDP datagram
/// is not made safer by counting them exactly.
pub const MAX_UNSAFE_BODY_BYTES: usize = 1300;

/// The largest body this stack accepts from a MESSAGE it did not send,
/// answered with a 413 above it (§21.4.11). An order of magnitude past
/// anything the pager model in §2 describes, small enough that reading one
/// all the way through before answering costs nothing worth measuring, and
/// well under the largest UDP datagram a transport ever hands this stack —
/// a policy limit this stack enforces on purpose, not a side effect of the
/// wire's own ceiling.
const MAX_INCOMING_BODY_BYTES: usize = 32 * 1024;

/// One MESSAGE this layer sent. Minted before anything reaches a transport,
/// for the reason [`crate::SubscriptionHandle`] is: a send that never leaves
/// still needs a name to report [`UaEvent::MessageSent`] under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageHandle(pub(crate) u32);

/// What is remembered about a MESSAGE this layer sent, until its answer.
#[derive(Debug)]
pub(crate) struct SentMessage {
    /// Whose credentials answer a challenge, when there are any.
    account: Option<AccountId>,
    /// The out-of-dialog target, `<uri>` as it went in `To`, kept so the
    /// "one pending transaction per URI" rule (§8) can be lifted once this
    /// handle settles. `None` for one sent inside a dialog, which the rule
    /// does not name — it is about a destination, not about a dialog that
    /// already exists.
    target: Option<Box<[u8]>>,
    /// A challenge came back and it is not yet known whether anything could
    /// answer it. Mirrors `Registration::unanswered`: held until the end of
    /// the drain, because whether this is a refusal or the first half of a
    /// retry is decided by whether a [`Event::Challenged`] follows it.
    unanswered: Option<OwnedMessage>,
    /// The refused transaction whose answer RFC 3261 §18.1.1 took off the
    /// datagram, held by the endpoint until a stream is bound or the wait for
    /// one ends ([`crate::oversize`]). Its refusal is not settled meanwhile:
    /// the challenge has not been answered yet, so it says nothing about the
    /// credentials.
    waiting_for_stream: Option<AnyTransactionId>,
    /// The call this MESSAGE rode inside, for one sent by
    /// [`UserAgent::message_in_call`] on a route that is not known to be
    /// congestion-controlled — kept so §8's "MUST NOT [initiate overlapping
    /// MESSAGE transactions inside a dialog] unless the route set for that
    /// dialog uses a congestion-controlled transport at every hop" can be
    /// checked against every other one still outstanding on the same call.
    /// `None` for an out-of-dialog send, and for one on a route this layer
    /// was told is congestion-controlled, which the rule does not bind.
    overlap_call: Option<CallHandle>,
}

// -- sending -------------------------------------------------------------

impl UserAgent {
    /// Send an instant message outside any dialog (RFC 3428 §3), addressed
    /// to `target`.
    ///
    /// The handle comes back whether or not the MESSAGE reached a
    /// transport. Its outcome — a 200, a 202 from a relay, a refusal, or the
    /// 408/503 this stack synthesises for one that got no answer at all,
    /// RFC 3261 §8.1.3.1's own reading of a timeout and a dead transport —
    /// arrives as [`UaEvent::MessageSent`], and the handle names nothing
    /// after that.
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
        // §22.2's caching: nothing goes on unless this destination has
        // challenged this account before, so the first MESSAGE of a session
        // is unaffected and a later one skips the round trip a fresh 401
        // would cost
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
    /// Nothing about the dialog changes: a MESSAGE never refreshes a
    /// session and is never mistaken for one. §8's per-URI rule does not
    /// apply here — the destination is the dialog's own, already settled.
    /// But §8 also has "A UAC SHOULD NOT initiate overlapping MESSAGE
    /// transactions inside a dialog, and MUST NOT do so unless the route
    /// set for that dialog uses a congestion-controlled transport at every
    /// hop", which does apply: unless [`Account::transport_protocol`] says
    /// this call's account is on a byte-stream transport, a second in-dialog
    /// MESSAGE on `call` while an earlier one has not been answered is
    /// refused the same as a second out-of-dialog one to a busy target.
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
        // a call answered without a matching line has nothing that could say
        // its transport is congestion-controlled, so §8's conservative
        // default applies exactly as it does for an account with nothing set
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

/// Whether `protocol` names a byte-stream transport, the "positive
/// knowledge" §8 asks for before either relaxing the size ceiling or
/// allowing overlapping in-dialog transactions.
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

/// A body §8's ceiling refuses, unless `protocol` says the transport it
/// would leave on is congestion-controlled.
fn check_outgoing_size(protocol: Option<TransportProtocol>, len: usize) -> Result<(), UaError> {
    if !is_congestion_controlled(protocol) && len > MAX_UNSAFE_BODY_BYTES {
        return Err(UaError::MessageTooLarge {
            size: len,
            limit: MAX_UNSAFE_BODY_BYTES,
        });
    }
    Ok(())
}

/// `<uri>`, which is how a URI goes into `To` without its parameters being
/// read as the header field's own (mirrors `crate::calls`'s own helper).
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
        let credentials = self
            .messages
            .get(&message)
            .and_then(|held| held.account)
            .and_then(|account| self.accounts.get(&account))
            .and_then(|config| config.credentials.clone());
        let Some(credentials) = credentials else {
            // nothing to answer with; the refusal held above stands, and
            // `settle_message_challenges` reports it once the drain ends
            return;
        };
        match self
            .endpoint
            .retry_with_credentials(transaction, &credentials, now)
        {
            Ok(retried) => self.message_retry_went(message, transaction, retried),
            // §18.1.1 wants a connection first, and the endpoint is still
            // holding the challenge
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
            let credentials = self
                .messages
                .get(&message)
                .and_then(|held| held.account)
                .and_then(|account| self.accounts.get(&account))
                .and_then(|config| config.credentials.clone());
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

    /// No stream is coming for the MESSAGEs whose answer to a challenge
    /// outgrew the datagram: each is reported with `status`, the 513 that
    /// stands for this end's own verdict, rather than as the 401 or 407 its
    /// credentials never got to answer.
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

    /// A refusal that carried a challenge and got no retry was a refusal.
    /// Called at the end of every drain, the same as
    /// `settle_subscription_challenges`.
    pub(crate) fn settle_message_challenges(&mut self) {
        let refused: Vec<(MessageHandle, OwnedMessage)> = self
            .messages
            .iter_mut()
            // except one the endpoint is holding until a connection exists:
            // its answer has not been sent yet
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

/// RFC 3261 §8.1.3.1's reading of a request nobody answered: a timeout is a
/// 408 and a dead transport is a 503, the same as `send_dtmf_info` reports
/// for an INFO that got no answer at all.
const fn unanswered(reason: FailureReason) -> StatusCode {
    match reason {
        FailureReason::TransportFailed => StatusCode::SERVICE_UNAVAILABLE,
        // `Refused` never reaches here: a refusal carries its own status
        // and arrives as `Event::Response`, not `Event::RequestFailed`
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
            Event::Challenged { transaction, .. } => {
                let Some(message) = self.by_message.get(&transaction).copied() else {
                    return Some(event);
                };
                self.on_message_challenged(message, transaction, now);
                None
            }
            other => Some(other),
        }
    }

    /// A MESSAGE arrived, in or out of a dialog. Answered here and now: §7
    /// asks for a final response immediately, and "not obliged to display
    /// the message to the user either before or after" it.
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
        // §4 has the UAS mandatory for `text/plain`; anything else is
        // answered against what the account declared with
        // `Account::accepts_message_type`, which is nothing for an account
        // this agent does not recognise
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
        // nothing useful to do if the transaction has gone: a MESSAGE
        // nobody answers is not retransmitted the way an INVITE is (it is a
        // non-INVITE transaction, and the far end's own timer decides what
        // it does next)
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

/// `Accept: text/plain, ...`, for the 415 a `Content-Type` this stack
/// refuses gets (§21.4.13 asks for it, so the far end knows what would have
/// worked).
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
