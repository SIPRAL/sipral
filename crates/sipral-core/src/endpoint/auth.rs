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
use super::outgoing::OutgoingRequest;
use super::table::Flow;
use crate::auth::{AuthCache, Credentials, Learned};
use crate::diag::{Direction, Reason};
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

/// How many destinations are remembered at once.
///
/// A phone registers with one registrar and calls a handful of people, so this
/// is far past what an honest deployment reaches. It is a ceiling rather than
/// a growing table because the destination is whatever the caller last sent
/// to, and a peer that challenges everything must not be able to make this a
/// place to put memory.
const DESTINATIONS: usize = 32;

/// What each destination has already challenged with.
///
/// §22.2: "UAs SHOULD cache the credentials for a given value of the To header
/// field and 'realm' and attempt to re-use these values on the next request
/// for that destination." The realm half of that is inside [`AuthCache`],
/// which keeps one entry per protection domain; what is left to key by is the
/// destination, and this is where it is kept.
///
/// Per destination rather than per transaction, which is the whole point: a
/// registration that refreshes every hour was paying for a 401 and a second
/// round trip every hour, for the life of the process, because the challenge
/// it had already answered died with the transaction that earned it.
#[derive(Debug, Default)]
pub(super) struct Known {
    /// In the order they were first challenged, so the oldest goes when the
    /// cap is reached. A scan of at most [`DESTINATIONS`] is cheaper than a
    /// map plus the queue that orders it, and the scan is what the eviction
    /// needs anyway.
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
    /// `None` only if the entry just pushed cannot be read back, which cannot
    /// happen; this crate says so by carrying on without a cache rather than
    /// by panicking, and the cost of that is one round trip.
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

    /// What this destination has challenged with, if it ever has.
    fn get(&mut self, destination: &[u8]) -> Option<&mut AuthCache> {
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
/// The URI out of it rather than the whole value: a display name is
/// decoration, and a tag names one end of a dialog rather than a different
/// registrar. Getting this wrong in the forgiving direction costs a round
/// trip; getting it wrong in the other would answer one destination with
/// another's challenge, which the realm check inside [`AuthCache`] would then
/// have to catch.
fn destination(to: &[u8]) -> Option<Box<[u8]>> {
    crate::msg::NameAddrRef::parse(to)
        .ok()
        .map(|addr| Box::from(addr.uri_bytes()))
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
        self.mark(now);
        let held = self
            .challenges
            .take(failed)
            .ok_or(AuthRetryError::NoChallenge)?;

        let method = held
            .request
            .as_raw()
            .method()
            .ok_or(AuthRetryError::NoChallenge)?;
        let answers = self.answers_for(&held.request, credentials);
        if answers.is_empty() {
            return Err(AuthRetryError::NothingToAnswer);
        }

        // §22.2: "it MUST increment the CSeq header field value as it would
        // normally when sending an updated request" — which inside a dialog
        // means asking the dialog, so that the number it hands out next does
        // not collide with this one
        let cseq = match held.dialog.and_then(|dialog| self.dialogs.get_mut(dialog)) {
            Some(state) => state
                .next_request(method)
                .map_err(|_| AuthRetryError::NoSuchDialog)?
                .cseq(),
            // Either there was no dialog, or there is no longer one because
            // the request was the BYE that ended it — §15.1.1 leaves nothing
            // behind, and a challenged BYE still has to go again or the far
            // end keeps a call this end has hung up. Both want the number
            // after the one that was refused, and in the second case nothing
            // will ever ask this dialog for another.
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
        let mut via = super::via::local_via(
            flow.protocol,
            local,
            &branch,
            self.config.always_request_rport,
        );

        let mut message = rebuild(&held.request.as_raw(), &via, cseq, &answers)
            .map_err(|error| AuthRetryError::Unsendable(error.into()))?;

        // The credentials are what made it large. §18.1.1 has to be applied
        // here as well as on the first send, or the one request in a call that
        // is certain to have grown is the one request nobody checked.
        let call = held.request.as_raw().call_id().ok();
        if let Some((stream, stream_local)) = self
            .promote_if_too_big(flow, message.len(), call)
            .map_err(AuthRetryError::Unsendable)?
        {
            flow = stream;
            local = stream_local;
            via = super::via::local_via(
                flow.protocol,
                local,
                &branch,
                self.config.always_request_rport,
            );
            message = rebuild(&held.request.as_raw(), &via, cseq, &answers)
                .map_err(|error| AuthRetryError::Unsendable(error.into()))?;
        }

        self.note_wire(
            &message.as_raw(),
            Reason::ChallengeAnswered,
            Direction::Outbound,
            flow,
        );
        let dialog = held.dialog;
        let timers = self.config.timers;
        let retried = if method == Method::Invite {
            let secure = flow.protocol.is_secure();
            let (id, effects) = self
                .transactions
                .start_invite_client(message.clone(), flow, timers, now)
                .map_err(|error| AuthRetryError::Unsendable(error.into()))?;
            match dialog {
                // §14.1: an INVITE inside a dialog is a re-INVITE and never
                // forks, so it gets no dialog set. Watching one here would
                // open a second, parallel view of a call that already exists
                Some(dialog) => self.watch_reinvite(id, dialog, message),
                None => {
                    self.dialogs
                        .watch(crate::dialog::DialogSet::new(message, secure), id);
                }
            }
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

        // both are read before the cache is borrowed, which the borrow
        // checker insists on and which also keeps the token draw in one place
        let cnonce = String::from_utf8_lossy(&self.tokens.token()).into_owned();
        let raw = request.as_raw();
        let (Some(to), Ok(call_id)) = (
            raw.header(HeaderName::To).and_then(destination),
            raw.call_id(),
        ) else {
            return;
        };
        let call_id = call_id.to_vec();
        let Some(cache) = self.known.at(&to) else {
            return;
        };
        if cache.learn(response, &cnonce, &call_id) != Learned::Retry {
            // either nothing here can be answered (RFC 8760 §2.4: "The client
            // MUST ignore any challenge it does not understand"), or the same
            // nonce came back without `stale`, which §22.1 says not to answer
            // twice
            return;
        }
        // collected while the cache is borrowed and reported after, because
        // reporting takes the whole endpoint
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

        self.note_wire(
            response,
            Reason::ChallengeReceived,
            Direction::Inbound,
            flow,
        );
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
            },
        );
    }

    /// The credential header fields for a request that has not been challenged
    /// yet, when this destination has challenged before (§22.2).
    ///
    /// Empty when nothing is remembered, when what is remembered was refused,
    /// or when it belongs to a proxy and this is a different conversation
    /// (§22.3). A caller that asks has to send what it gets back: the nonce
    /// count is spent here, and `nc` "MUST" differ on every request that
    /// carries the same nonce.
    pub(super) fn answer_ahead(
        &mut self,
        request: &OutgoingRequest,
        credentials: &Credentials,
        call_id: &[u8],
    ) -> Vec<(HeaderName<'static>, String)> {
        let Some(to) = request.to.as_deref().and_then(destination) else {
            return Vec::new();
        };
        let Some(method) = Method::from_bytes(&request.method) else {
            return Vec::new();
        };
        let uri = request.request_uri.as_bytes().to_vec();
        self.known
            .get(&to)
            .map(|cache| cache.authorize(credentials, method, &uri, call_id))
            .unwrap_or_default()
    }

    /// The same, for a request that has already been refused once: what the
    /// destination's cache says to answer with, drawn from the one place the
    /// nonce count lives.
    fn answers_for(
        &mut self,
        request: &OwnedMessage,
        credentials: &Credentials,
    ) -> Vec<(HeaderName<'static>, String)> {
        let raw = request.as_raw();
        let (Some(method), Some(uri)) = (raw.method(), raw.request_uri_bytes()) else {
            return Vec::new();
        };
        let uri = uri.to_vec();
        let (Some(to), Ok(call_id)) = (
            raw.header(HeaderName::To).and_then(destination),
            raw.call_id(),
        ) else {
            return Vec::new();
        };
        let call_id = call_id.to_vec();
        self.known
            .get(&to)
            .map(|cache| cache.authorize(credentials, method, &uri, &call_id))
            .unwrap_or_default()
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
        assert!(known.get(b"<sip:alice@0.example>").is_none());
        assert!(known.get(b"<sip:alice@199.example>").is_some());
    }
}
