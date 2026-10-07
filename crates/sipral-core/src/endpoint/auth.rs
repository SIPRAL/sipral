// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Answering a challenge (RFC 3261 §22, RFC 8760).
//!
//! The endpoint never holds the password and never decides to answer: a
//! wrong answer can lock the account. It owns the bookkeeping: the nonce
//! count, the client nonce, the 401/407 split and the `CSeq` (§22.2).
//!
//! A challenge outlives its transaction, since the answer may wait on a
//! person. The store is capped so a hostile peer cannot grow it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use super::driver::Endpoint;
use super::error::AuthRetryError;
use super::event::Event;
use super::outgoing::OutgoingRequest;
use super::table::Flow;
use crate::auth::{Answered, AuthCache, Credentials, Learned};
use crate::diag::{Direction, Reason};
use crate::msg::{HeaderName, Method, OwnedMessage, RawMessage, RequestBuilder, StatusCode};
use crate::transaction::{AnyTransactionId, DialogId};

/// How many challenged requests are remembered at once.
///
/// Capped against a peer that refuses everything.
const REMEMBERED: usize = 32;

/// How many times one request goes again with credentials before the stack
/// calls the password wrong.
///
/// §22.1's same-nonce guard fails against a server that rotates its nonce
/// without `stale`; this count stops the lock-out. One answer is normal, two
/// cover an aged nonce. Per request, not per destination.
const ANSWERS: u8 = 3;

/// A request that was refused, and the challenge it was refused with.
#[derive(Debug)]
pub(super) struct Challenged {
    /// The request as it went out, which the retry is built from.
    pub(super) request: OwnedMessage,
    /// Where it went.
    pub(super) flow: Flow,
    /// The dialog it belonged to; §22.2's new `CSeq` must come from it.
    pub(super) dialog: Option<DialogId>,
    /// How many times this request has already gone again with credentials.
    /// Kept here because it must outlive the transaction.
    pub(super) spent: u8,
    /// The realms asked for, each with whether a proxy (407) asked
    /// ([`Endpoint::challenge_origin`]).
    pub(super) realms: Vec<(bool, Arc<str>)>,
}

/// Who asked for credentials: where the request went and the realms named.
///
/// An answer enables an offline password search (RFC 7616 §5.10, §5.11), so
/// a password should answer only its own server's realm (RFC 3261 §22.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeOrigin {
    /// Where the request that was refused went.
    pub destination: SocketAddr,
    /// The realms asked for, each once, in the order the refusal named them.
    pub realms: Vec<Arc<str>>,
    /// Whether any of them was a proxy's (407).
    pub proxy: bool,
}

/// The challenges waiting for an answer.
#[derive(Debug, Default)]
pub(super) struct Challenges {
    /// Oldest first; a scan of at most [`REMEMBERED`] beats a map.
    entries: Vec<(AnyTransactionId, Challenged)>,
    /// Answers spent per request in flight, keyed by its latest retry's
    /// transaction and handed on to the next one.
    spent: Vec<(AnyTransactionId, u8)>,
}

impl Challenges {
    /// Nothing challenged yet.
    pub(super) const fn new() -> Self {
        Self {
            entries: Vec::new(),
            spent: Vec::new(),
        }
    }

    /// Hand the allowance a request has already spent to the transaction its
    /// retry just created.
    ///
    /// [`Self::take_answered`] or [`Self::forget`] removes it.
    pub(super) fn carry(&mut self, retried: AnyTransactionId, spent: u8) {
        self.spent.retain(|(known, _)| *known != retried);
        if self.spent.len() >= REMEMBERED {
            self.spent.remove(0);
        }
        self.spent.push((retried, spent));
    }

    /// The transaction is over. Only the allowance goes; the challenge stays.
    pub(super) fn forget(&mut self, id: AnyTransactionId) {
        self.spent.retain(|(known, _)| *known != id);
    }

    /// How many answers the request behind this transaction has spent, taken
    /// out on the way.
    ///
    /// Taken, not read: stale entries would push live chains out and reset
    /// their allowance.
    pub(super) fn take_answered(&mut self, id: AnyTransactionId) -> u8 {
        let Some(at) = self.spent.iter().position(|(known, _)| *known == id) else {
            return 0;
        };
        self.spent.remove(at).1
    }

    /// Remember one, evicting the oldest if there is no room.
    pub(super) fn remember(&mut self, id: AnyTransactionId, challenged: Challenged) {
        self.entries.retain(|(known, _)| *known != id);
        if self.entries.len() >= REMEMBERED {
            self.entries.remove(0);
        }
        self.entries.push((id, challenged));
    }

    /// Take one out to answer it.
    pub(super) fn take(&mut self, id: AnyTransactionId) -> Option<Challenged> {
        let at = self.entries.iter().position(|(known, _)| *known == id)?;
        Some(self.entries.remove(at).1)
    }

    /// The one held under `id`, left where it is.
    pub(super) fn get(&self, id: AnyTransactionId) -> Option<&Challenged> {
        self.entries
            .iter()
            .find(|(known, _)| *known == id)
            .map(|(_, held)| held)
    }

    /// How many are waiting.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// How many destinations are remembered at once.
///
/// Far above an honest deployment; capped against hostile peers.
const DESTINATIONS: usize = 32;

/// What each destination has already challenged with.
///
/// §22.2 caches credentials per `To` and realm; [`AuthCache`] keys the realm,
/// this keys the destination. It spares a refresh the extra 401 round trip.
#[derive(Debug, Default)]
pub(super) struct Known {
    /// Oldest first; a scan of at most [`DESTINATIONS`] beats a map.
    entries: Vec<(Box<[u8]>, AuthCache)>,
}

impl Known {
    pub(super) const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// What this destination has challenged with, opening an empty one for a
    /// destination not seen before.
    ///
    /// `None` cannot happen; it would cost a round trip, not a panic.
    fn at(&mut self, destination: &[u8]) -> Option<&mut AuthCache> {
        let known = self
            .entries
            .iter()
            .position(|(known, _)| **known == *destination);
        let at = if let Some(at) = known {
            at
        } else {
            if self.entries.len() >= DESTINATIONS {
                self.entries.remove(0);
            }
            self.entries
                .push((Box::from(destination), AuthCache::new()));
            self.entries.len().saturating_sub(1)
        };
        self.entries.get_mut(at).map(|(_, cache)| cache)
    }

    /// What this destination has challenged with, if it ever has, to read.
    fn peek(&self, destination: &[u8]) -> Option<&AuthCache> {
        self.entries
            .iter()
            .find(|(known, _)| **known == *destination)
            .map(|(_, cache)| cache)
    }

    /// The same, to write. Opens nothing new.
    fn peek_mut(&mut self, destination: &[u8]) -> Option<&mut AuthCache> {
        self.entries
            .iter_mut()
            .find(|(known, _)| **known == *destination)
            .map(|(_, cache)| cache)
    }

    /// How many destinations are remembered.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// The destination a challenge belongs to (§22.2's "value of the To header
/// field").
///
/// Only the URI: display name and tag do not change the registrar.
pub(super) fn destination(to: &[u8]) -> Option<Box<[u8]>> {
    crate::msg::NameAddrRef::parse(to)
        .ok()
        .map(|addr| Box::from(addr.uri_bytes()))
}

impl Endpoint {
    /// Send a challenged request again, with credentials.
    ///
    /// The endpoint draws `nc` and the client nonce, and moves the `CSeq`
    /// (§22.2). The challenge is consumed, so a second call with the same
    /// handle is refused, except when §18.1.1 asks for a
    /// stream: then the same handle works once the transport is bound.
    ///
    /// At most three retries per request; the fourth challenge is a refusal
    /// whatever its nonce (§22.1).
    ///
    /// # Errors
    /// [`AuthRetryError`] when there is no challenge, the credentials do not
    /// apply, or the retry cannot be sent.
    pub fn retry_with_credentials(
        &mut self,
        failed: AnyTransactionId,
        credentials: &Credentials,
        now: Instant,
    ) -> Result<AnyTransactionId, AuthRetryError> {
        self.mark(now);
        let held = self
            .challenges
            .take(failed)
            .ok_or(AuthRetryError::NoChallenge)?;
        self.send_retry(failed, held, credentials, now)
    }

    /// Rewrite the body a challenged request will go again with.
    ///
    /// For a retry too large for a datagram (§18.1.1) with no stream.
    /// `reshape` returns the new body, or `None`. The retry still goes through
    /// [`Self::retry_with_credentials`]. `true` when the body was replaced;
    /// `false` when no challenge is held, `reshape` declined, or the request
    /// could not be rebuilt around the new body.
    pub fn reshape_challenged_body(
        &mut self,
        failed: AnyTransactionId,
        reshape: impl FnOnce(&[u8]) -> Option<Vec<u8>>,
    ) -> bool {
        let Some(mut held) = self.challenges.take(failed) else {
            return false;
        };
        let reshaped = {
            let raw = held.request.as_raw();
            match (raw.header(HeaderName::Via), raw.cseq()) {
                (Some(via), Ok(cseq)) => reshape(raw.body())
                    .and_then(|body| rebuild_with(&raw, via, cseq.seq, &[], &body).ok()),
                _ => None,
            }
        };
        let replaced = reshaped.is_some();
        if let Some(message) = reshaped {
            held.request = message;
        }
        self.challenges.remember(failed, held);
        replaced
    }

    /// Stop holding a challenge nobody is going to answer.
    ///
    /// For a retry held for a stream that never came. `true` when there
    /// was one.
    pub fn abandon_challenge(&mut self, failed: AnyTransactionId) -> bool {
        self.challenges.take(failed).is_some()
    }

    /// Who is asking, for the challenge held under `failed`
    /// ([`ChallengeOrigin`]), before anything answers it. `None` when no
    /// challenge is held there.
    #[must_use]
    pub fn challenge_origin(&self, failed: AnyTransactionId) -> Option<ChallengeOrigin> {
        let held = self.challenges.get(failed)?;
        let mut realms: Vec<Arc<str>> = Vec::new();
        for (_, realm) in &held.realms {
            if !realms.contains(realm) {
                realms.push(Arc::clone(realm));
            }
        }
        Some(ChallengeOrigin {
            destination: held.flow.destination,
            realms,
            proxy: held.realms.iter().any(|(proxy, _)| *proxy),
        })
    }

    /// The `Bearer` challenge (RFC 8898) under `failed` that `credentials`
    /// cannot answer, so a new token can be fetched. `None` when all are
    /// answerable or nothing is held.
    #[must_use]
    pub fn token_wanted(
        &self,
        failed: AnyTransactionId,
        credentials: Option<&Credentials>,
    ) -> Option<crate::auth::BearerChallenge> {
        let held = self.challenges.get(failed)?;
        let to = held
            .request
            .as_raw()
            .header(HeaderName::To)
            .and_then(destination)?;
        self.known
            .peek(&to)?
            .token_wanted(credentials)
            .filter(|challenge| {
                held.realms
                    .iter()
                    .any(|(proxy, realm)| *proxy == challenge.proxy && *realm == challenge.realm)
            })
            .cloned()
    }

    /// Answer the challenge held under `failed` with nothing, ever: the
    /// caller decided its password is not for whoever asked.
    ///
    /// Like [`Self::abandon_challenge`], and the realms are also closed in the
    /// destination cache so §22.2 does not answer them unasked. Recorded as
    /// `auth.challenge.declined`. `true` when there was one.
    pub fn decline_challenge(&mut self, failed: AnyTransactionId) -> bool {
        let Some(held) = self.challenges.take(failed) else {
            return false;
        };
        let raw = held.request.as_raw();
        if let Some(cache) = raw
            .header(HeaderName::To)
            .and_then(destination)
            .and_then(|to| self.known.peek_mut(&to))
        {
            for (proxy, realm) in &held.realms {
                cache.refuse_realm(*proxy, realm);
            }
        }
        let call = raw.call_id().ok();
        self.note(
            call,
            crate::diag::Decision::of(Reason::ChallengeDeclined)
                .at_address(held.flow.destination)
                .over(held.flow.protocol),
        );
        true
    }

    /// The retry itself, with the challenge already out of the store.
    fn send_retry(
        &mut self,
        failed: AnyTransactionId,
        held: Challenged,
        credentials: &Credentials,
        now: Instant,
    ) -> Result<AnyTransactionId, AuthRetryError> {
        let method = held
            .request
            .as_raw()
            .method()
            .ok_or(AuthRetryError::NoChallenge)?;
        // a retry outside a dialog is a new call under max_dialogs; the room
        // may be gone, and the challenge goes back
        if method == Method::Invite
            && held.dialog.is_none()
            && self.dialogs_held() >= self.config.max_dialogs
        {
            let limit = self.config.max_dialogs;
            self.challenges.remember(failed, held);
            return Err(AuthRetryError::Unsendable(
                super::error::SendError::LimitReached { limit },
            ));
        }
        let answers = self.answers_for(&held.request, credentials);
        if answers.is_empty() {
            return Err(AuthRetryError::NothingToAnswer);
        }

        // §22.2: increment the CSeq; inside a dialog, the dialog hands it out
        let cseq = match held.dialog.and_then(|dialog| self.dialogs.get_mut(dialog)) {
            Some(state) => state
                .next_request(method)
                .map_err(|_| AuthRetryError::NoSuchDialog)?
                .cseq(),
            // no dialog, or a challenged BYE whose dialog is gone (§15.1.1)
            None => held
                .request
                .as_raw()
                .cseq()
                .map_err(|_| AuthRetryError::NoChallenge)?
                .seq
                .saturating_add(1),
        };

        let bound = self
            .transports
            .get(held.flow.transport)
            .ok_or(AuthRetryError::Unsendable(
                super::error::SendError::UnknownTransport,
            ))?;
        let mut local = bound.local;
        let branch = self.tokens.branch();
        let mut flow = held.flow;
        let mut via = self.via_on(flow.transport, flow.protocol, local, &branch);

        let mut message = rebuild(&held.request.as_raw(), &via, cseq, answers.fields())
            .map_err(|error| AuthRetryError::Unsendable(error.into()))?;
        message = self
            .written_for_the_datagram(flow, message)
            .map_err(AuthRetryError::Unsendable)?;

        // the credentials grew it, so §18.1.1 applies again
        let promoted = {
            let call = held.request.as_raw().call_id().ok();
            self.promote_if_too_big(flow, message.len(), call)
        };
        let promoted = match promoted {
            Ok(promoted) => promoted,
            // §18.1.1 wants a stream: the challenge goes back. What was drawn
            // is dropped; a gap is allowed, an out-of-order number is not.
            Err(super::error::SendError::NeedsStreamTransport) => {
                self.challenges.remember(failed, held);
                return Err(AuthRetryError::Unsendable(
                    super::error::SendError::NeedsStreamTransport,
                ));
            }
            Err(error) => return Err(AuthRetryError::Unsendable(error)),
        };
        if let Some((stream, stream_local)) = promoted {
            flow = stream;
            local = stream_local;
            via = self.via_on(flow.transport, flow.protocol, local, &branch);
            message = rebuild(&held.request.as_raw(), &via, cseq, answers.fields())
                .map_err(|error| AuthRetryError::Unsendable(error.into()))?;
        }

        self.note_wire(
            &message.as_raw(),
            Reason::ChallengeAnswered,
            Direction::Outbound,
            flow,
        );
        let dialog = held.dialog;
        let retried = self.start_retry(method, message, flow, dialog, now)?;
        if let Some(dialog) = dialog {
            self.remember_dialog(retried, dialog);
        }
        // both counts move only once the transaction has started; the
        // allowance follows the request, not the transaction
        if let Some(to) = held
            .request
            .as_raw()
            .header(HeaderName::To)
            .and_then(destination)
        {
            self.spend_answer(&to, &answers);
        }
        self.challenges.carry(retried, held.spent.saturating_add(1));
        Ok(retried)
    }

    /// Put the rebuilt request in a transaction of its own.
    ///
    /// A new branch, so a new transaction (§17.1.3).
    pub(super) fn start_retry(
        &mut self,
        method: Method<'_>,
        message: OwnedMessage,
        flow: Flow,
        dialog: Option<DialogId>,
        now: Instant,
    ) -> Result<AnyTransactionId, AuthRetryError> {
        let timers = self.config.timers;
        if method != Method::Invite {
            let (id, effects) = self
                .transactions
                .start_non_invite_client(message, flow, timers, now)
                .map_err(|error| AuthRetryError::Unsendable(error.into()))?;
            self.apply_client(effects, flow);
            return Ok(AnyTransactionId::NonInviteClient(id));
        }
        let secure = flow.protocol.is_secure();
        let (id, effects) = self
            .transactions
            .start_invite_client(message.clone(), flow, timers, now)
            .map_err(|error| AuthRetryError::Unsendable(error.into()))?;
        match dialog {
            // §14.1: a re-INVITE never forks and gets no dialog set
            Some(dialog) => self.watch_reinvite(id, dialog, message),
            None => {
                self.dialogs
                    .watch(crate::dialog::DialogSet::new(message, secure), id);
            }
        }
        self.apply_client(effects, flow);
        Ok(AnyTransactionId::InviteClient(id))
    }

    /// A refusal that carries a challenge worth answering.
    ///
    /// Reported after the response itself.
    pub(super) fn on_challenge(
        &mut self,
        id: AnyTransactionId,
        response: &RawMessage<'_>,
        request: OwnedMessage,
        flow: Flow,
    ) {
        let Some(status) = response.status() else {
            return;
        };
        if status != StatusCode::UNAUTHORIZED && status != StatusCode::PROXY_AUTH_REQUIRED {
            return;
        }

        // read before the cache is borrowed
        let cnonce = String::from_utf8_lossy(&self.tokens.token()).into_owned();
        let raw = request.as_raw();
        let (Some(to), Ok(_)) = (
            raw.header(HeaderName::To).and_then(destination),
            raw.call_id(),
        ) else {
            return;
        };
        let spent = self.challenges.take_answered(id);
        let Some(cache) = self.known.at(&to) else {
            return;
        };
        if spent >= ANSWERS {
            // Allowance gone (§22.1). The credentials are marked refused too,
            // or §22.2's pre-emptive answer would keep sending the wrong
            // password.
            cache.refuse(response);
            // reported by sending no `Event::Challenged`
            return;
        }
        if cache.learn(response, &raw, &cnonce) != Learned::Retry {
            // nothing answerable (RFC 8760 §2.4), or the same nonce without
            // `stale` (§22.1)
            return;
        }
        let answering: Vec<_> = cache
            .challenges()
            .map(|challenge| {
                (
                    challenge.realm.clone(),
                    challenge.proxy,
                    challenge.algorithm,
                    challenge.stale,
                )
            })
            .collect();
        let tokens: Vec<_> = cache.bearer_challenges().cloned().collect();

        self.note_wire(
            response,
            Reason::ChallengeReceived,
            Direction::Inbound,
            flow,
        );
        let realms = answering
            .iter()
            .map(|(realm, proxy, _, _)| (*proxy, Arc::clone(realm)))
            .chain(
                tokens
                    .iter()
                    .map(|challenge| (challenge.proxy, Arc::clone(&challenge.realm))),
            )
            .collect();
        for challenge in tokens {
            self.events.push_back(Event::TokenChallenged {
                transaction: id,
                challenge,
            });
        }
        for (realm, proxy, algorithm, stale) in answering {
            self.events.push_back(Event::Challenged {
                transaction: id,
                realm,
                proxy,
                algorithm,
                stale,
            });
        }
        let dialog = self.dialog_of(id);
        self.challenges.remember(
            id,
            Challenged {
                request,
                flow,
                dialog,
                spent,
                realms,
            },
        );
    }

    /// The credential header fields for a request that has not been challenged
    /// yet, when this destination has challenged before (§22.2).
    ///
    /// Empty when nothing usable is remembered (§22.3). The nonce count is
    /// spent only by [`Self::spend_answer`], once the request leaves.
    pub(super) fn answer_ahead(
        &self,
        request: &OutgoingRequest,
        credentials: &Credentials,
        call_id: &[u8],
    ) -> Answered {
        let Some(to) = request.to.as_deref().and_then(destination) else {
            return Answered::default();
        };
        let Some(method) = Method::from_bytes(&request.method) else {
            return Answered::default();
        };
        let uri = request.request_uri.as_bytes().to_vec();
        self.known
            .peek(&to)
            .map(|cache| cache.authorize(credentials, method, &uri, call_id))
            .unwrap_or_default()
    }

    /// The same, for a request that has already been refused once.
    fn answers_for(&self, request: &OwnedMessage, credentials: &Credentials) -> Answered {
        let raw = request.as_raw();
        let (Some(method), Some(uri)) = (raw.method(), raw.request_uri_bytes()) else {
            return Answered::default();
        };
        let uri = uri.to_vec();
        let (Some(to), Ok(call_id)) = (
            raw.header(HeaderName::To).and_then(destination),
            raw.call_id(),
        ) else {
            return Answered::default();
        };
        let call_id = call_id.to_vec();
        self.known
            .peek(&to)
            .map(|cache| cache.authorize(credentials, method, &uri, &call_id))
            .unwrap_or_default()
    }

    /// Move the nonce count on, now that the request carrying the answer is
    /// committed.
    pub(super) fn spend_answer(&mut self, to: &[u8], answered: &Answered) {
        if let Some(cache) = self.known.peek_mut(to) {
            cache.spend(answered);
        }
    }
}

/// The request again, with a new `Via`, a new `CSeq` and credentials.
///
/// Everything else is copied in its original order.
pub(super) fn rebuild(
    request: &RawMessage<'_>,
    via: &[u8],
    cseq: u32,
    credentials: &[(HeaderName<'static>, String)],
) -> Result<OwnedMessage, crate::msg::BuildError> {
    rebuild_with(request, via, cseq, credentials, request.body())
}

/// [`rebuild`], carrying `body` in place of the one the request had, under
/// the `Content-Type` it had.
fn rebuild_with(
    request: &RawMessage<'_>,
    via: &[u8],
    cseq: u32,
    credentials: &[(HeaderName<'static>, String)],
    body: &[u8],
) -> Result<OwnedMessage, crate::msg::BuildError> {
    use crate::msg::BuildError;

    let method = request.method().ok_or(BuildError::MissingField("method"))?;
    let uri = request
        .request_uri_bytes()
        .ok_or(BuildError::MissingField("Request-URI"))?;
    let from = request
        .header(HeaderName::From)
        .ok_or(BuildError::MissingField("From"))?;
    let to = request
        .header(HeaderName::To)
        .ok_or(BuildError::MissingField("To"))?;
    let call_id = request
        .header(HeaderName::CallId)
        .ok_or(BuildError::MissingField("Call-ID"))?;

    let mut builder = RequestBuilder::new(method, uri)
        .via(via)
        .from(from)
        .to(to)
        .call_id(call_id)
        .cseq(cseq);
    builder = match request.header(HeaderName::MaxForwards) {
        Some(value) => builder.header(HeaderName::MaxForwards, value),
        None => builder.max_forwards(70),
    };
    for hop in request.header_values(HeaderName::Route) {
        builder = builder.route(hop);
    }

    for (name, value) in request.raw_headers() {
        let Some(name) = HeaderName::from_bytes(name) else {
            continue;
        };
        if matches!(
            name,
            HeaderName::Via
                | HeaderName::CSeq
                | HeaderName::From
                | HeaderName::To
                | HeaderName::CallId
                | HeaderName::MaxForwards
                | HeaderName::Route
                | HeaderName::ContentLength
                | HeaderName::ContentType
                // replaced, so credentials do not stack
                | HeaderName::Authorization
                | HeaderName::ProxyAuthorization
        ) {
            continue;
        }
        builder = builder.header(name, value);
    }
    for (name, value) in credentials {
        builder = builder.header(*name, value.as_bytes());
    }

    if !body.is_empty()
        && let Some(kind) = request.header(HeaderName::ContentType)
    {
        builder = builder.body(kind, body);
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::{Challenged, Challenges, DESTINATIONS, Known, REMEMBERED, destination};
    use crate::endpoint::table::Flow;
    use crate::endpoint::{TransportId, TransportProtocol};
    use crate::msg::{OwnedMessage, ParseMode, ParseScratch, parse};
    use crate::transaction::{AnyTransactionId, NonInviteClient, Raw, TransactionId};
    use std::net::SocketAddr;

    const REGISTER: &[u8] = b"REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=a\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: c\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\
\r\n";

    fn held() -> Challenged {
        let mut scratch = ParseScratch::new();
        let request: OwnedMessage = parse(REGISTER, &mut scratch, ParseMode::Lenient)
            .unwrap()
            .to_owned();
        Challenged {
            request,
            flow: Flow {
                transport: TransportId(1),
                destination: "192.0.2.9:5060".parse::<SocketAddr>().unwrap(),
                source: None,
                protocol: TransportProtocol::Udp,
            },
            dialog: None,
            spent: 0,
            realms: Vec::new(),
        }
    }

    fn id(slot: u32) -> AnyTransactionId {
        AnyTransactionId::NonInviteClient(TransactionId::<NonInviteClient>::new(Raw {
            slot,
            generation: 0,
        }))
    }

    #[test]
    fn a_challenge_is_found_by_the_transaction_that_earned_it() {
        let mut challenges = Challenges::new();
        challenges.remember(id(0), held());
        challenges.remember(id(1), held());
        assert!(challenges.take(id(0)).is_some());
        assert!(challenges.take(id(0)).is_none(), "taken twice");
        assert!(challenges.take(id(1)).is_some());
    }

    #[test]
    fn challenging_the_same_transaction_twice_replaces_what_was_there() {
        let mut challenges = Challenges::new();
        challenges.remember(id(0), held());
        challenges.remember(id(0), held());
        assert_eq!(challenges.len(), 1);
    }

    #[test]
    fn a_chain_that_is_over_gives_its_slot_back() {
        // a stale entry would push a live chain out; both exits remove it
        let mut challenges = Challenges::new();

        challenges.carry(id(1), 2);
        assert_eq!(challenges.take_answered(id(1)), 2, "the count is handed on");
        assert_eq!(
            challenges.take_answered(id(1)),
            0,
            "and is gone: from here it travels on the challenge itself"
        );

        challenges.carry(id(2), 3);
        challenges.forget(id(2));
        assert_eq!(
            challenges.take_answered(id(2)),
            0,
            "a transaction that ended without being challenged keeps no slot"
        );

        challenges.carry(id(3), 2);
        for slot in 100..200 {
            challenges.carry(id(slot), 1);
            challenges.forget(id(slot));
        }
        assert_eq!(
            challenges.take_answered(id(3)),
            2,
            "a hundred finished conversations did not cost the live one its count"
        );
    }

    #[test]
    fn a_peer_that_refuses_everything_cannot_grow_the_set() {
        let mut challenges = Challenges::new();
        for slot in 0..200 {
            challenges.remember(id(slot), held());
        }
        assert_eq!(challenges.len(), REMEMBERED);
        // the oldest went first
        assert!(challenges.take(id(0)).is_none());
        assert!(challenges.take(id(199)).is_some());
    }

    #[test]
    fn a_challenge_outlives_the_transaction_that_earned_it() {
        // the transaction ends on timer K while the password is typed
        let mut challenges = Challenges::new();
        challenges.remember(id(0), held());
        assert_eq!(challenges.len(), 1);
        assert!(challenges.take(id(0)).is_some());
    }

    #[test]
    fn a_destination_is_named_by_its_uri_and_not_by_how_it_was_written() {
        // the same registrar, spelled three ways a caller might spell it
        let plain = destination(b"sip:alice@example.com");
        assert_eq!(destination(b"<sip:alice@example.com>"), plain);
        assert_eq!(destination(b"Alice <sip:alice@example.com>"), plain);
        assert_eq!(
            destination(b"<sip:alice@example.com>;tag=registrar"),
            plain,
            "a tag names one end of a dialog, not another registrar"
        );
        assert_ne!(destination(b"<sip:alice@elsewhere.example>"), plain);
    }

    #[test]
    fn nobody_can_grow_the_table_of_destinations_by_being_challenged_from_everywhere() {
        let mut known = Known::new();
        for last in 0..200u32 {
            let to = format!("<sip:alice@{last}.example>").into_bytes();
            assert!(known.at(&to).is_some());
        }
        assert_eq!(known.len(), DESTINATIONS);
        // the oldest went first
        assert!(known.peek(b"<sip:alice@0.example>").is_none());
        assert!(known.peek(b"<sip:alice@199.example>").is_some());
    }
}
