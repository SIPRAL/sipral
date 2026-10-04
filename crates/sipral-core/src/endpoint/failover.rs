// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A request outside any dialog that found no server, sent to the next one
//! (RFC 3263 §4.3).
//!
//! "Failure occurs if the transaction layer reports a 503 error response or
//! a transport failure of some sort", or "if the transaction layer times out
//! without ever having received any response", and then "the client SHOULD
//! create a new request, which is identical to the previous, but has a
//! different value of the Via branch ID than the previous (and therefore
//! constitutes a new SIP transaction)", sent "to the next element in the
//! list". The list is the caller's — the locator runs above this layer, and
//! the addresses it found are the account's — so what this module keeps is
//! the other half: every request outside a dialog that failed one of those
//! three ways, as it went out, so that [`Endpoint::send_elsewhere`] can send
//! it again to whichever address the caller names.
//!
//! A dialog's own requests fail over inside the dialog (`resolve.rs`), and a
//! re-INVITE's failure ends its dialog, so neither is kept here. The store is
//! capped as the challenge store is: a caller that never sends anything
//! elsewhere leaves the oldest to fall out.

use std::net::SocketAddr;
use std::time::Instant;

use super::driver::Endpoint;
use super::error::SendError;
use super::table::Flow;
use super::transport::TransportId;
use crate::msg::{Method, OwnedMessage};
use crate::transaction::AnyTransactionId;

/// How many failed requests are kept at once.
const KEPT: usize = 32;

/// The requests that found no server, by the transaction that carried them.
#[derive(Debug, Default)]
pub(super) struct Unreached {
    entries: Vec<(AnyTransactionId, OwnedMessage, Flow)>,
}

impl Unreached {
    pub(super) const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn keep(&mut self, id: AnyTransactionId, request: OwnedMessage, flow: Flow) {
        self.entries.retain(|(known, _, _)| *known != id);
        if self.entries.len() >= KEPT {
            self.entries.remove(0);
        }
        self.entries.push((id, request, flow));
    }

    fn get(&self, id: AnyTransactionId) -> Option<&(AnyTransactionId, OwnedMessage, Flow)> {
        self.entries.iter().find(|(known, _, _)| *known == id)
    }

    fn take(&mut self, id: AnyTransactionId) -> Option<(OwnedMessage, Flow)> {
        let at = self.entries.iter().position(|(known, _, _)| *known == id)?;
        let (_, request, flow) = self.entries.remove(at);
        Some((request, flow))
    }
}

/// A request outside any dialog that timed out, lost its transport or was
/// answered 503: where it went, and what it was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnreachedRequest {
    /// The address it was sent to.
    pub destination: SocketAddr,
    /// The transport it went out on.
    pub transport: TransportId,
    /// Whether it was a REGISTER, which a registration fails over by sending
    /// a REGISTER of its own rather than this one again.
    pub register: bool,
    /// Whether it was an INVITE.
    pub invite: bool,
}

impl Endpoint {
    /// Keep a request outside a dialog that just failed in one of §4.3's
    /// three ways, for [`Endpoint::send_elsewhere`].
    pub(super) fn keep_unreached(
        &mut self,
        id: AnyTransactionId,
        request: &OwnedMessage,
        flow: Flow,
    ) {
        if self.dialog_of(id).is_some() {
            return;
        }
        if let AnyTransactionId::InviteClient(invite) = id
            && self.reinvites.dialog_of(invite).is_some()
        {
            return;
        }
        self.unreached.keep(id, request.clone(), flow);
    }

    /// [`Endpoint::keep_unreached`] for a client transaction still in the
    /// table, its request read out of it: a timeout or a transport failure,
    /// read before the effects that retire it are applied.
    pub(super) fn keep_unreached_in_flight(&mut self, id: AnyTransactionId, flow: Flow) {
        let sent = match id {
            AnyTransactionId::InviteClient(inner) => self
                .transactions
                .invite_client(inner)
                .map(|entry| entry.machine.request().clone()),
            AnyTransactionId::NonInviteClient(inner) => self
                .transactions
                .non_invite_client(inner)
                .map(|entry| entry.machine.request().clone()),
            AnyTransactionId::InviteServer(_) | AnyTransactionId::NonInviteServer(_) => None,
        };
        if let Some(sent) = sent {
            self.keep_unreached(id, &sent, flow);
        }
    }

    /// The request `failed` carried, when it went outside a dialog and timed
    /// out, lost its transport, or was answered 503 — and has not been sent
    /// elsewhere or pushed out of the store since.
    #[must_use]
    pub fn unreached(&self, failed: AnyTransactionId) -> Option<UnreachedRequest> {
        let (_, request, flow) = self.unreached.get(failed)?;
        let method = request.as_raw().method();
        Some(UnreachedRequest {
            destination: flow.destination,
            transport: flow.transport,
            register: method == Some(Method::Register),
            invite: method == Some(Method::Invite),
        })
    }

    /// Stop keeping a failed request nobody will send elsewhere. `true` when
    /// there was one.
    pub fn forget_unreached(&mut self, failed: AnyTransactionId) -> bool {
        self.unreached.take(failed).is_some()
    }

    /// Send the request `failed` carried again, to `destination`: RFC 3263
    /// §4.3's new request, identical to the one that failed but for the
    /// `Via` branch, which makes it a new transaction — whose id this
    /// returns. On the transport it went out on when that one can reach
    /// `destination`, and otherwise on any open transport of the same
    /// protocol that can; credentials it carried for the server that failed
    /// are left off, since the next one challenges with its own.
    ///
    /// The kept request is consumed either way.
    ///
    /// # Errors
    /// [`SendError::UnknownTransport`] when nothing was kept under `failed`
    /// or no open transport of its protocol reaches `destination`;
    /// [`SendError::LimitReached`] for an INVITE when another call has taken
    /// the room since; and anything building it again runs into.
    pub fn send_elsewhere(
        &mut self,
        failed: AnyTransactionId,
        destination: SocketAddr,
        now: Instant,
    ) -> Result<AnyTransactionId, SendError> {
        self.mark(now);
        let (request, flow) = self
            .unreached
            .take(failed)
            .ok_or(SendError::UnknownTransport)?;
        let raw = request.as_raw();
        let method = raw.method().ok_or(SendError::MissingField("method"))?;
        if method == Method::Invite && self.dialogs_held() >= self.config.max_dialogs {
            return Err(SendError::LimitReached {
                limit: self.config.max_dialogs,
            });
        }
        let reaches = self.transports.get(flow.transport).is_some_and(|bound| {
            bound.protocol == flow.protocol
                && bound.remote.is_none_or(|remote| remote == destination)
        });
        let transport = if reaches {
            flow.transport
        } else {
            self.transports
                .speaking_to(flow.protocol, destination)
                .ok_or(SendError::UnknownTransport)?
        };
        let local = self
            .transports
            .get(transport)
            .ok_or(SendError::UnknownTransport)?
            .local;
        let cseq = raw.cseq().map_err(|_| SendError::MissingField("CSeq"))?.seq;
        let branch = self.tokens.branch();
        let via = super::via::local_via(
            flow.protocol,
            local,
            &branch,
            self.config.always_request_rport,
        );
        let message = super::auth::rebuild(&raw, &via, cseq, &[]).map_err(SendError::Build)?;
        let moved = Flow {
            transport,
            destination,
            source: None,
            ..flow
        };
        // the request was written compact to fit the datagram it first went
        // in, and the rebuild above writes every field long again
        let message = self.written_for_the_datagram(moved, message)?;
        self.start_retry(method, message, moved, None, now)
            .map_err(|error| match error {
                super::error::AuthRetryError::Unsendable(error) => error,
                _ => SendError::UnknownTransport,
            })
    }
}
