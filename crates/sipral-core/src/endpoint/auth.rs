// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
/// One per account being registered, plus whatever is in flight, is a handful.
/// The cap is what stops a peer that refuses everything from turning this into
/// a place to put memory.
const REMEMBERED: usize = 32;

/// How many times one request goes again with credentials before the stack
/// calls the password wrong.
///
/// §22.1's guard — the same nonce coming back without `stale` means the
/// credentials were rejected — turns on the nonce being the same. A server
/// that draws a fresh one for every refusal and never marks it `stale` walks
/// straight past that guard, and the exchange then runs one wrong password
/// per round trip for as long as the process lives, which is how an account
/// gets locked out. Nothing on the wire tells that apart from a server ageing
/// its nonces honestly, so the count is the defence.
///
/// Three, because a correct exchange needs one, a nonce that aged out between
/// the request and the answer needs two, and a third is already generous. The
/// allowance is per request, not per destination: a fresh request gets the
/// whole of it again, since a password can be corrected while a process runs.
const ANSWERS: u8 = 3;

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
    /// How many times this request has already gone again with credentials.
    ///
    /// Kept here rather than in a ledger of its own because this record
    /// outlives the transaction that earned it, and the allowance has to
    /// outlive it too: a server that draws a fresh nonce every time is
    /// exactly a server that keeps making new transactions.
    pub(super) spent: u8,
    /// The protection domains the refusal asked to be answered for, each
    /// with whether a proxy (407) asked: what the caller weighs before it
    /// lets a password near the challenge ([`Endpoint::challenge_origin`]).
    pub(super) realms: Vec<(bool, Arc<str>)>,
}

/// Who asked for credentials, as far as this end can tell: where the
/// challenged request went — the address the refusal came back from — and
/// the realms it named.
///
/// What a user agent needs to decide whether a password is for this
/// challenge at all. RFC 3261 §22.1: "each such protection domain has its
/// own set of usernames and passwords", and an answer is material for an
/// offline search of the password whoever chose the nonce can run (RFC 7616
/// §5.10, §5.11), so a password answers its own server's realm and nobody
/// else's.
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
    /// In the order they were learned, so that the oldest goes first when the
    /// cap is reached. A linear scan of at most [`REMEMBERED`] is cheaper than
    /// a map plus a queue to order it.
    entries: Vec<(AnyTransactionId, Challenged)>,
    /// How many answers each request still in flight has spent, keyed by the
    /// transaction its latest retry created.
    ///
    /// Keyed by transaction and not by request because a request has no
    /// identity the endpoint keeps: every retry starts a new transaction, and
    /// the allowance belongs to the request, so it is handed from the
    /// transaction that is ending to the one replacing it. Nothing is ever
    /// reused: a transaction id is a slot and a generation, so a freed slot
    /// comes back as a different id.
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
    /// One entry per chain, and only between the retry going out and its
    /// answer coming back: [`Self::take_answered`] takes it from here the
    /// moment a challenge arrives, and [`Self::forget`] drops it when the
    /// transaction ends any other way.
    pub(super) fn carry(&mut self, retried: AnyTransactionId, spent: u8) {
        self.spent.retain(|(known, _)| *known != retried);
        if self.spent.len() >= REMEMBERED {
            self.spent.remove(0);
        }
        self.spent.push((retried, spent));
    }

    /// The transaction is over, so whatever it was carrying is not coming
    /// back. Only the allowance is dropped; the challenge itself outlives
    /// the transaction on purpose.
    pub(super) fn forget(&mut self, id: AnyTransactionId) {
        self.spent.retain(|(known, _)| *known != id);
    }

    /// How many answers the request behind this transaction has spent, taken
    /// out on the way.
    ///
    /// Taken and not read, because the count is moving: whoever asks is
    /// about to put it somewhere that outlives this ledger. Leaving it here
    /// would keep an entry per chain that ever ran, successful ones
    /// included, and thirty-two of those would push a live chain out and let
    /// its allowance start again — which is the whole defence, failing
    /// open, under nothing worse than ordinary traffic.
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

    /// What this destination has challenged with, if it ever has, to read.
    fn peek(&self, destination: &[u8]) -> Option<&AuthCache> {
        self.entries
            .iter()
            .find(|(known, _)| **known == *destination)
            .map(|(_, cache)| cache)
    }

    /// The same, to write: only for spending a count on an answer already
    /// drawn, which is why it opens nothing that is not already there.
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
/// The URI out of it rather than the whole value: a display name is
/// decoration, and a tag names one end of a dialog rather than a different
/// registrar. Getting this wrong in the forgiving direction costs a round
/// trip; getting it wrong in the other would answer one destination with
/// another's challenge, which the realm check inside [`AuthCache`] would then
/// have to catch.
pub(super) fn destination(to: &[u8]) -> Option<Box<[u8]>> {
    crate::msg::NameAddrRef::parse(to)
        .ok()
        .map(|addr| Box::from(addr.uri_bytes()))
}

impl Endpoint {
    /// Send a challenged request again, with credentials.
    ///
    /// The nonce count and the client nonce are the endpoint's: `nc` "MUST"
    /// be different for every request sent with the same nonce. The `CSeq`
    /// moves on too (§22.2).
    ///
    /// The stored challenge is consumed, so a second call with the same
    /// handle is refused rather than replaying a nonce count. There is one
    /// exception, and it is the one error the endpoint raises to ask the
    /// caller to do something: when §18.1.1 refuses to send the retry over a
    /// datagram and asks for a stream, the challenge stays where it is and
    /// the same handle works again once the transport is bound. What the
    /// refused attempt had drawn is dropped and drawn again then — a number
    /// the server never saw leaves a gap, which it tolerates, while holding
    /// one back risks putting it on the wire behind a higher one, which it
    /// does not.
    ///
    /// One request goes again with credentials at most three times. The
    /// fourth challenge on the same request is reported as a refusal
    /// whatever nonce it carries, because a server that rotates its nonce
    /// defeats §22.1's guard and one wrong password per round trip is how an
    /// account gets locked out.
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
        self.send_retry(failed, held, credentials, now)
    }

    /// Rewrite the body a challenged request will go again with.
    ///
    /// For a caller that has to make the retry smaller: RFC 3261 §18.1.1
    /// refused it a datagram, and no stream came to carry it instead.
    /// `reshape` is handed the body the request went out with and returns the
    /// one to send in its place, or `None` to leave it as it is. The retry
    /// still goes through [`Self::retry_with_credentials`], under the same
    /// handle and held to the same rules; §22.2 makes it a new request, and
    /// nothing about answering a challenge ties it to the body the refused
    /// one carried.
    ///
    /// `true` when the body was replaced; `false` when there is no challenge
    /// under this handle, `reshape` left it alone, or the request could not
    /// be written again around the new body.
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
    /// A retry §18.1.1 held back for a stream that never came is the one
    /// case: the challenge would otherwise sit in the store until newer ones
    /// pushed it out. `true` when there was one.
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

    /// The `Bearer` challenge (RFC 8898) behind the request held under
    /// `failed` that `credentials` cannot answer — they hold no access
    /// token, or only the one that protection domain has already refused —
    /// so that the application can be asked for a new one. `None` when no
    /// challenge is held there, or every `Bearer` one in it is answerable.
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
    /// The challenge is dropped as [`Self::abandon_challenge`] drops it, and
    /// the realms it named are closed in the destination's cache as well,
    /// so that §22.2's answer ahead of a challenge does not hand the same
    /// party an answer on the next request without being asked. The refusal
    /// stands, and is recorded as `auth.challenge.declined`. `true` when
    /// there was one.
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
    ///
    /// Split from [`Self::retry_with_credentials`] only so that the one error
    /// which puts the challenge back has somewhere to put it back from.
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
        // The refusal gave the call's room under max_dialogs back, and
        // another call may have taken it since: a retry outside a dialog is
        // a call placed again, held to the same ceiling as the first INVITE.
        // Nothing has been drawn yet, so the challenge goes back and the
        // same handle works once a call ends.
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

        let mut message = rebuild(&held.request.as_raw(), &via, cseq, answers.fields())
            .map_err(|error| AuthRetryError::Unsendable(error.into()))?;
        message = self
            .written_for_the_datagram(flow, message)
            .map_err(AuthRetryError::Unsendable)?;

        // The credentials are what made it large. §18.1.1 has to be applied
        // here as well as on the first send, or the one request in a call that
        // is certain to have grown is the one request nobody checked.
        let promoted = {
            let call = held.request.as_raw().call_id().ok();
            self.promote_if_too_big(flow, message.len(), call)
        };
        let promoted = match promoted {
            Ok(promoted) => promoted,
            // §18.1.1 refused to send this one and asked the caller for a
            // stream. That is the one error here the caller is expected to
            // act on, so the challenge goes back where it was and the same
            // handle works again once the connection is open. Everything
            // drawn for the attempt that could not leave — the nonce count,
            // the branch, and inside a dialog the CSeq — is dropped with it
            // and drawn again next time: a number the server never saw
            // leaves a gap, which is allowed, while keeping it would let a
            // request that goes out meanwhile carry a higher one and put
            // this one on the wire out of order, which is not.
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
            via = super::via::local_via(
                flow.protocol,
                local,
                &branch,
                self.config.always_request_rport,
            );
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
        // Both counts move here and nowhere earlier, because the transaction
        // has now actually started: an attempt §18.1.1 refused to send
        // returned above without reaching this, and so costs nothing.
        //
        // The nonce count is the server's bookkeeping, one per request that
        // carries a given nonce. The allowance is ours, and travels with the
        // request rather than with the transaction: every retry gets a new
        // id, and a server drawing a fresh nonce each time would otherwise
        // restart the count on every round trip.
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
    /// A retry is a new transaction, not a continuation: a new branch went
    /// into the `Via` above, and §17.1.3 matches responses on that.
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
            // §14.1: an INVITE inside a dialog is a re-INVITE and never
            // forks, so it gets no dialog set. Watching one here would open a
            // second, parallel view of a call that already exists
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
        let (Some(to), Ok(_)) = (
            raw.header(HeaderName::To).and_then(destination),
            raw.call_id(),
        ) else {
            return;
        };
        // taken before the cache is borrowed, for the same reason the cnonce
        // is read there; and taken rather than read because from here it
        // travels on the record below, which outlives this ledger
        let spent = self.challenges.take_answered(id);
        let Some(cache) = self.known.at(&to) else {
            return;
        };
        if spent >= ANSWERS {
            // The allowance is gone. §22.1 stops a client answering the same
            // nonce twice, and a server that draws a new one for every
            // refusal walks straight past that, so the count is what closes
            // it: the fourth challenge on one request is a refusal whatever
            // nonce it carries.
            //
            // The credentials are marked refused as well, not just this
            // request stopped. Otherwise §22.2's pre-emptive answer would go
            // on offering the same password, now known wrong, on every later
            // request to this destination — the same lock-out, one round trip
            // at a time instead of three.
            cache.refuse(response);
            // Said by saying nothing: no `Event::Challenged` follows the
            // response, which is exactly how the same-nonce refusal below
            // reports itself and what every caller already reads as the end
            // of the exchange.
            return;
        }
        if cache.learn(response, &raw, &cnonce) != Learned::Retry {
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
    /// Empty when nothing is remembered, when what is remembered was refused,
    /// or when it belongs to a proxy and this is a different conversation
    /// (§22.3).
    ///
    /// The nonce count is not spent here. What comes back has to be handed to
    /// [`Self::spend_answer`] once the request carrying it is on its way, and
    /// dropped without that if it never goes: `nc` "MUST" differ on every
    /// request that carries the same nonce, so the number belongs to the
    /// request that reaches the wire.
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

    /// The same, for a request that has already been refused once: what the
    /// destination's cache says to answer with, drawn from the one place the
    /// nonce count lives.
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
    ///
    /// Takes the destination again rather than holding a borrow across the
    /// build: the answer was drawn from one cache and goes back to the same
    /// one, and between the two the whole endpoint has to be free.
    pub(super) fn spend_answer(&mut self, to: &[u8], answered: &Answered) {
        if let Some(cache) = self.known.peek_mut(to) {
            cache.spend(answered);
        }
    }
}

/// The request again, with a new `Via`, a new `CSeq` and credentials.
///
/// Everything else is copied in the order it arrived, so that the retry is the
/// request the far end already saw rather than a different one that happens to
/// ask for the same thing.
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
        // The ledger that bridges a retry and the next challenge has as many
        // slots as the set above. If an entry outlived its chain, ordinary
        // traffic would push a live one out and the allowance would start
        // again — the whole defence failing open. So there are exactly two
        // ways in and both take the entry with them.
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

        // so a live chain is still there after more traffic than the ledger
        // holds, because none of that traffic left anything behind
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
        assert!(known.peek(b"<sip:alice@0.example>").is_none());
        assert!(known.peek(b"<sip:alice@199.example>").is_some());
    }
}
