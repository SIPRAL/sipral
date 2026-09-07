// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Answering a challenge (RFC 3261 §22, RFC 8760).
//!
//! A registrar refuses the first REGISTER it ever sees, and a proxy refuses
//! the first INVITE. That is not a failure, it is the handshake: the refusal
//! carries a nonce, and the request goes again with a hash of the nonce, the
//! password and what the request is asking for.
//!
//! The endpoint does none of that on its own. It reads the challenge, says so,
//! and waits: the password is the one thing this layer must never hold on to,
//! and *whether* to answer at all is a decision with a locked account at the
//! other end of it. What it does own is the bookkeeping the RFC is exact
//! about — the nonce count, which has to move by one per request and never
//! skip; the client nonce; the separation of the 401 and 407 spaces; and the
//! `CSeq`, which §22.2 makes the client increment "as it would normally when
//! sending an updated request".
//!
//! The challenge outlives the transaction that earned it, because the
//! transaction ends the moment the refusal is final and the answer comes from
//! a person who may take a while. The set is capped rather than unbounded: a
//! peer that challenges everything and a caller that never retries must not
//! be able to grow it.

use std::time::Instant;

use super::driver::Endpoint;
use super::error::AuthRetryError;
use super::event::Event;
use super::table::Flow;
use crate::auth::{AuthCache, Credentials, Learned};
use crate::msg::{HeaderName, Method, OwnedMessage, RawMessage, RequestBuilder, StatusCode};
use crate::transaction::{AnyTransactionId, DialogId};

/// How many challenged requests are remembered at once.
///
/// One per account being registered, plus whatever is in flight, is a handful.
/// The cap is what stops a peer that refuses everything from turning this into
/// a place to put memory.
const REMEMBERED: usize = 32;

/// A request that was refused, and the challenge it was refused with.
#[derive(Debug)]
pub(super) struct Challenged {
    /// The request as it went out, which the retry is built from.
    pub(super) request: OwnedMessage,
    /// Where it went.
    pub(super) flow: Flow,
    /// The dialog it belonged to, when it had one: §22.2's "increment the
    /// CSeq" has to come from the dialog there, or the next request in it
    /// reuses the number.
    pub(super) dialog: Option<DialogId>,
    /// What was learned from the refusal.
    pub(super) cache: AuthCache,
}

/// The challenges waiting for an answer.
#[derive(Debug, Default)]
pub(super) struct Challenges {
    /// In the order they were learned, so that the oldest goes first when the
    /// cap is reached. A linear scan of at most [`REMEMBERED`] is cheaper than
    /// a map plus a queue to order it.
    entries: Vec<(AnyTransactionId, Challenged)>,
}

impl Challenges {
    /// Nothing challenged yet.
    pub(super) const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
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

    /// How many are waiting.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}

impl Endpoint {
    /// Send a challenged request again, with credentials.
    ///
    /// The nonce count and the client nonce are the endpoint's: `nc` "MUST" be
    /// different for every request sent with the same nonce, and a skipped
    /// number looks to the server like a replay it should refuse. The `CSeq`
    /// moves on too (§22.2).
    ///
    /// The stored challenge is consumed, so a second call with the same handle
    /// is refused rather than replaying a nonce count.
    ///
    /// # Errors
    /// [`AuthRetryError`] when there is no challenge under this handle, when
    /// the credentials cannot be applied to it, or when the retry cannot be
    /// sent.
    pub fn retry_with_credentials(
        &mut self,
        failed: AnyTransactionId,
        credentials: &Credentials,
        now: Instant,
    ) -> Result<AnyTransactionId, AuthRetryError> {
        let mut held = self
            .challenges
            .take(failed)
            .ok_or(AuthRetryError::NoChallenge)?;

        let raw = held.request.as_raw();
        let method = raw.method().ok_or(AuthRetryError::NoChallenge)?;
        let uri = raw
            .request_uri_bytes()
            .ok_or(AuthRetryError::NoChallenge)?
            .to_vec();
        let answers = held.cache.authorize(credentials, method, &uri);
        if answers.is_empty() {
            return Err(AuthRetryError::NothingToAnswer);
        }

        // §22.2: "it MUST increment the CSeq header field value as it would
        // normally when sending an updated request" — which inside a dialog
        // means asking the dialog, so that the number it hands out next does
        // not collide with this one
        let cseq = match held.dialog {
            Some(dialog) => self
                .dialogs
                .get_mut(dialog)
                .ok_or(AuthRetryError::NoSuchDialog)?
                .next_request(method)
                .map_err(|_| AuthRetryError::NoSuchDialog)?
                .cseq(),
            None => raw
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
        let local = bound.local;
        let branch = self.tokens.branch();
        let via = super::via::local_via(
            held.flow.protocol,
            local,
            &branch,
            self.config.always_request_rport,
        );

        let message = rebuild(&held.request.as_raw(), &via, cseq, &answers)
            .map_err(|error| AuthRetryError::Unsendable(error.into()))?;

        let flow = held.flow;
        let dialog = held.dialog;
        let timers = self.config.timers;
        let retried = if method == Method::Invite {
            let secure = flow.protocol.is_secure();
            let set = crate::dialog::DialogSet::new(message.clone(), secure);
            let (id, effects) = self
                .transactions
                .start_invite_client(message, flow, timers, now)
                .map_err(|error| AuthRetryError::Unsendable(error.into()))?;
            self.dialogs.watch(set, id);
            self.apply_client(effects, flow);
            AnyTransactionId::InviteClient(id)
        } else {
            let (id, effects) = self
                .transactions
                .start_non_invite_client(message, flow, timers, now)
                .map_err(|error| AuthRetryError::Unsendable(error.into()))?;
            self.apply_client(effects, flow);
            AnyTransactionId::NonInviteClient(id)
        };
        if let Some(dialog) = dialog {
            self.remember_dialog(retried, dialog);
        }
        // the retry carries what it answered, so that the same nonce coming
        // back a second time is read as a refusal rather than a new challenge
        self.carried_auth.insert(retried, held.cache);
        Ok(retried)
    }

    /// A refusal that carries a challenge worth answering.
    ///
    /// Reported after the response itself, so that the caller sees the whole
    /// message first and this as a note about what can be done with it.
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

        let mut cache = self.carried_auth.remove(&id).unwrap_or_default();
        let cnonce = String::from_utf8_lossy(&self.tokens.token()).into_owned();
        if cache.learn(response, &cnonce) != Learned::Retry {
            // either nothing here can be answered (RFC 8760 §2.4: "The client
            // MUST ignore any challenge it does not understand"), or the same
            // nonce came back without `stale`, which §22.1 says not to answer
            // twice
            return;
        }

        for challenge in cache.challenges() {
            self.events.push_back(Event::Challenged {
                transaction: id,
                realm: challenge.realm.clone(),
                proxy: challenge.proxy,
                algorithm: challenge.algorithm,
                stale: challenge.stale,
            });
        }
        let dialog = self.dialog_of(id);
        self.challenges.remember(
            id,
            Challenged {
                request,
                flow,
                dialog,
                cache,
            },
        );
    }
}

/// The request again, with a new `Via`, a new `CSeq` and credentials.
///
/// Everything else is copied in the order it arrived, so that the retry is the
/// request the far end already saw rather than a different one that happens to
/// ask for the same thing.
fn rebuild(
    request: &RawMessage<'_>,
    via: &[u8],
    cseq: u32,
    credentials: &[(HeaderName<'static>, String)],
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
                // replaced by the ones being added, so that a second refusal
                // does not stack two sets of credentials on one request
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

    let body = request.body();
    if !body.is_empty()
        && let Some(kind) = request.header(HeaderName::ContentType)
    {
        builder = builder.body(kind, body);
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::{Challenged, Challenges, REMEMBERED};
    use crate::auth::AuthCache;
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
            cache: AuthCache::new(),
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
        // the refusal is final, so the transaction ends on timer K while the
        // password is still being typed
        let mut challenges = Challenges::new();
        challenges.remember(id(0), held());
        assert_eq!(challenges.len(), 1);
        assert!(challenges.take(id(0)).is_some());
    }
}
