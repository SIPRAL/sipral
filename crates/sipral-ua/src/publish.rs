// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Publishing event state: the PUBLISH client of RFC 3903.
//!
//! A [`Publication`] is one piece of event state this end keeps at a state
//! compositor — one presence document for one address of record, say —
//! through the four requests §4 defines: the initial PUBLISH that creates it,
//! with a body and an `Expires`; the refresh that keeps it, carrying the
//! entity tag the compositor handed back in `SIP-If-Match` and no body; the
//! modification that replaces it, with the entity tag and a new body; and the
//! removal, with the entity tag and `Expires: 0`.
//!
//! **Sans-I/O, like the rest of this crate.** Nothing here owns a socket, a
//! transaction or a clock. What to send comes out of
//! [`Publication::poll_transmit`] as a [`PublishRequest`], which the caller
//! lays over an out-of-dialog request of its own addressing
//! ([`PublishRequest::apply`]) and hands to the endpoint; the final response
//! goes back in through [`Publication::handle_response`] (or
//! [`Publication::handle_failure`] when there was none); the refresh is due
//! at [`Publication::poll_timeout`] and fires in
//! [`Publication::handle_timeout`]; and what happened comes out of
//! [`Publication::poll_event`]. The same five calls every other machine in
//! this crate is driven by.
//!
//! **One request at a time.** §4 does not let a publisher send a new PUBLISH
//! for the same state before the previous one has a final response — each one
//! names the entity tag the previous one produced. A modification or a
//! removal asked for while one is in flight waits for its answer and goes
//! then, the latest of them winning.
//!
//! **The refresh goes at the margin a registration's does**: whichever is
//! sooner of 85% of the granted lifetime and thirty seconds before it ends,
//! never sooner than halfway. One that fails is reported and not repeated by
//! itself: the state stands at the compositor until it lapses, and
//! [`Publication::refresh`] is how the caller tries again before then.
//!
//! **Three answers are the compositor asking for something**, not failing:
//! 412 Conditional Request Failed means it no longer knows the entity tag, so
//! the state is published afresh, without one and with the whole body; 423
//! Interval Too Brief means it wants a longer lifetime, so the same request
//! goes again asking for its `Min-Expires`; and 401 or 407 is a challenge the
//! caller answers with credentials. 489 Bad Event, the compositor not knowing
//! the event package at all, is final and says so.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::endpoint::OutgoingRequest;
use sipral_core::msg::{HeaderName, RawMessage, StatusCode};

use crate::presence::{PIDF_TYPE, Presence, PresenceError};
use crate::registration::{min_expires, refresh_after};
use crate::subscription::DEFAULT_EXPIRES;

/// The entity tag a 2xx hands back (RFC 3903 §11.3.1).
const SIP_ETAG: HeaderName<'static> = HeaderName::Extension("SIP-ETag");
/// The entity tag a refresh, modification or removal names (RFC 3903
/// §11.3.2).
const SIP_IF_MATCH: HeaderName<'static> = HeaderName::Extension("SIP-If-Match");
/// The longest entity tag kept. The grammar makes it a token and sets no
/// bound; a compositor's are short, and this is the bound on what one can
/// make every later request carry.
const MAX_ETAG: usize = 128;

/// Which of RFC 3903 §4's requests a PUBLISH is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PublishKind {
    /// Creates the state: a body, and no entity tag.
    Initial,
    /// Keeps it: an entity tag, and no body.
    Refresh,
    /// Replaces it: an entity tag and a new body.
    Modify,
    /// Removes it: an entity tag and `Expires: 0`.
    Remove,
}

/// A body and its type.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Document {
    content_type: Box<str>,
    body: Arc<[u8]>,
}

/// One PUBLISH to send, as far as this machine decides it.
///
/// The Request-URI, `To`, `From`, transport and destination are the
/// caller's: [`PublishRequest::apply`] adds what is this machine's to a
/// request that already has them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishRequest {
    kind: PublishKind,
    event: Box<str>,
    expires: Duration,
    if_match: Option<Box<str>>,
    body: Option<Document>,
}

impl PublishRequest {
    /// Which request it is.
    #[must_use]
    pub const fn kind(&self) -> PublishKind {
        self.kind
    }

    /// The `Event` value.
    #[must_use]
    pub fn event(&self) -> &str {
        &self.event
    }

    /// The `Expires` it asks for.
    #[must_use]
    pub const fn expires(&self) -> Duration {
        self.expires
    }

    /// The `SIP-If-Match` value, on everything but an initial PUBLISH.
    #[must_use]
    pub fn if_match(&self) -> Option<&str> {
        self.if_match.as_deref()
    }

    /// The body's type, on an initial PUBLISH and a modification.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.body.as_ref().map(|document| &*document.content_type)
    }

    /// The body, on an initial PUBLISH and a modification.
    #[must_use]
    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_ref().map(|document| &*document.body)
    }

    /// Add `Event`, `Expires`, `SIP-If-Match` and the body to `request`,
    /// which the caller built with [`sipral_core::msg::Method::Publish`] and
    /// its own addressing.
    #[must_use]
    pub fn apply(&self, request: OutgoingRequest) -> OutgoingRequest {
        let seconds = self.expires.as_secs().to_string();
        let mut request = request
            .header(HeaderName::Event, self.event.as_bytes())
            .header(HeaderName::Expires, seconds.as_bytes());
        if let Some(ref etag) = self.if_match {
            request = request.header(SIP_IF_MATCH, etag.as_bytes());
        }
        if let Some(ref document) = self.body {
            request = request.body(document.content_type.as_bytes(), Arc::clone(&document.body));
        }
        request
    }
}

/// Why a publication did not do what it was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PublishFailure {
    /// 489 Bad Event: the compositor does not know the event package. The
    /// publication is over; asking again gets the same answer.
    BadEvent,
    /// 423 Interval Too Brief with no `Min-Expires` this machine could meet.
    IntervalTooBrief,
    /// A 2xx without the `SIP-ETag` every 2xx must carry, or with one that is
    /// not a token: nothing could ever refresh, modify or remove the state.
    NoEntityTag,
    /// The compositor refused: a 4xx, 5xx or 6xx not listed above. What
    /// was published before, if anything, stands until it lapses.
    Refused,
    /// No response at all: a timeout or a transport that failed.
    Unreachable,
}

impl core::fmt::Display for PublishFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::BadEvent => "event package not supported",
            Self::IntervalTooBrief => "interval too brief",
            Self::NoEntityTag => "no entity tag",
            Self::Refused => "refused",
            Self::Unreachable => "compositor unreachable",
        })
    }
}

/// What happened to a publication.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublishEvent {
    /// A 2xx: the state is at the compositor under `etag`, for `expires`,
    /// and will be refreshed in `refresh_in`.
    Published {
        /// The entity tag every later request names.
        etag: Box<str>,
        /// What the compositor granted.
        expires: Duration,
        /// When the refresh goes.
        refresh_in: Duration,
    },
    /// The state is gone at the compositor: a removal succeeded, or a removal
    /// found it already gone (412).
    Removed,
    /// The granted lifetime ran out with no successful refresh, or a 2xx
    /// granted none at all. The next [`Publication::publish`] starts afresh.
    Expired,
    /// A 401 or 407. The request in flight is still in flight: answer the
    /// challenge, send `request` again with credentials, and hand its
    /// response to [`Publication::handle_response`].
    Challenged {
        /// The request to send again.
        request: PublishRequest,
        /// 401 or 407.
        status: StatusCode,
    },
    /// It did not work.
    Failed {
        /// Why.
        reason: PublishFailure,
        /// The status, when a response said so.
        status: Option<StatusCode>,
    },
}

/// A call this machine cannot act on as it stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublishError {
    /// A removal or a refresh with nothing published to name.
    NothingPublished,
    /// A presence document that cannot be written.
    Unwritable(PresenceError),
}

impl core::fmt::Display for PublishError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::NothingPublished => f.write_str("nothing is published"),
            Self::Unwritable(ref error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for PublishError {}

/// What a call asked for while a request was in flight.
#[derive(Clone, Debug)]
enum Intent {
    Publish(Document),
    Remove,
}

/// One piece of event state published to a compositor (RFC 3903).
#[derive(Debug)]
pub struct Publication {
    event: Box<str>,
    asking: Duration,
    /// The compositor's name for the state, from the last 2xx.
    etag: Option<Box<str>>,
    /// The last body asked to be published, kept for the fresh initial
    /// PUBLISH a 412 asks for.
    document: Option<Document>,
    in_flight: Option<PublishRequest>,
    queued: Option<Intent>,
    refresh_at: Option<Instant>,
    lapses_at: Option<Instant>,
    outbox: VecDeque<PublishRequest>,
    events: VecDeque<PublishEvent>,
}

impl Publication {
    /// State for the event package `event` (`presence` for RFC 3856's),
    /// asking for [`crate::DEFAULT_EXPIRES`].
    #[must_use]
    pub fn new(event: &str) -> Self {
        Self {
            event: Box::from(event),
            asking: DEFAULT_EXPIRES,
            etag: None,
            document: None,
            in_flight: None,
            queued: None,
            refresh_at: None,
            lapses_at: None,
            outbox: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// Ask for `expires` instead, in the whole seconds `Expires` carries, and
    /// at most the 2^32 - 1 it can say (RFC 3261 §20.19). Less than a second
    /// is not a lifetime — `Expires: 0` is what a removal says — and leaves
    /// the one already asked for.
    #[must_use]
    pub fn expires(mut self, expires: Duration) -> Self {
        let seconds = expires.as_secs().min(u64::from(u32::MAX));
        if seconds != 0 {
            self.asking = Duration::from_secs(seconds);
        }
        self
    }

    /// The entity tag the state is held under, once a 2xx has named one.
    #[must_use]
    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }

    /// Whether a request is waiting for its final response.
    #[must_use]
    pub const fn is_in_flight(&self) -> bool {
        self.in_flight.is_some()
    }

    /// Publish `body`: the initial PUBLISH when nothing is published, a
    /// modification when something is (§4).
    pub fn publish(&mut self, content_type: &str, body: Arc<[u8]>) {
        self.dispatch(Intent::Publish(Document {
            content_type: Box::from(content_type),
            body,
        }));
    }

    /// Publish a presence document as `application/pidf+xml`.
    ///
    /// # Errors
    /// [`PublishError::Unwritable`], and nothing is sent.
    pub fn publish_presence(&mut self, presence: &Presence) -> Result<(), PublishError> {
        let body = presence.to_xml().map_err(PublishError::Unwritable)?;
        self.publish(PIDF_TYPE, Arc::from(body));
        Ok(())
    }

    /// Remove the state: `SIP-If-Match` and `Expires: 0` (§4).
    ///
    /// # Errors
    /// [`PublishError::NothingPublished`] when there is neither an entity tag
    /// nor a request in flight that could produce one.
    pub fn remove(&mut self) -> Result<(), PublishError> {
        if self.etag.is_none() && self.in_flight.is_none() {
            return Err(PublishError::NothingPublished);
        }
        self.dispatch(Intent::Remove);
        Ok(())
    }

    /// Refresh now rather than at [`Publication::poll_timeout`] — after a
    /// refresh that failed, say. One already in flight is not doubled.
    ///
    /// # Errors
    /// [`PublishError::NothingPublished`].
    pub fn refresh(&mut self) -> Result<(), PublishError> {
        let Some(etag) = self.etag.clone() else {
            return Err(PublishError::NothingPublished);
        };
        if self.in_flight.is_none() {
            self.send(PublishKind::Refresh, Some(etag), None);
        }
        Ok(())
    }

    /// The next PUBLISH to send.
    pub fn poll_transmit(&mut self) -> Option<PublishRequest> {
        self.outbox.pop_front()
    }

    /// The next thing that happened.
    pub fn poll_event(&mut self) -> Option<PublishEvent> {
        self.events.pop_front()
    }

    /// When [`Publication::handle_timeout`] next has something to do.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        let refresh = self.refresh_at.filter(|_| self.in_flight.is_none());
        match (refresh, self.lapses_at) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (left, right) => left.or(right),
        }
    }

    /// Refresh when it is time, and notice when the state has lapsed.
    pub fn handle_timeout(&mut self, now: Instant) {
        if self.lapses_at.is_some_and(|at| at <= now) {
            self.forget();
            self.events.push_back(PublishEvent::Expired);
            return;
        }
        if self.in_flight.is_none()
            && self.refresh_at.is_some_and(|at| at <= now)
            && let Some(etag) = self.etag.clone()
        {
            self.send(PublishKind::Refresh, Some(etag), None);
        }
    }

    /// The final response to the PUBLISH in flight, or a provisional one,
    /// which changes nothing.
    ///
    /// A response when nothing is in flight is not this machine's and is
    /// ignored.
    pub fn handle_response(&mut self, response: &RawMessage<'_>, now: Instant) {
        let Some(status) = response.status() else {
            return;
        };
        let etag = response.header(SIP_ETAG).and_then(entity_tag);
        let expires = response
            .expires()
            .ok()
            .and_then(|value| value.require().ok())
            .map(|seconds| Duration::from_secs(u64::from(seconds)));
        self.answer(status, etag, expires, min_expires(response), now);
    }

    /// The PUBLISH in flight got no response: its transaction timed out, or
    /// its transport failed.
    pub fn handle_failure(&mut self) {
        if self.in_flight.take().is_none() {
            return;
        }
        self.events.push_back(PublishEvent::Failed {
            reason: PublishFailure::Unreachable,
            status: None,
        });
        self.after_answer();
    }

    /// The 401 or 407 that answered the PUBLISH in flight could not be
    /// answered: there were no credentials, or the retry could not be sent.
    /// It is a refusal like any other ([`PublishFailure::Refused`]), and
    /// whatever was asked for while it was in flight goes next.
    pub fn challenge_unanswered(&mut self, status: StatusCode) {
        if self.in_flight.take().is_none() {
            return;
        }
        self.fail(PublishFailure::Refused, Some(status));
        self.after_answer();
    }

    /// The answer to the 401 or 407 that refused the PUBLISH in flight
    /// outgrew the datagram, and no stream came to carry it (RFC 3261
    /// §18.1.1). The compositor was never reached with credentials, so this
    /// is [`PublishFailure::Unreachable`] with `status`, the 513 that stands
    /// for this end's own verdict, rather than a refusal.
    pub(crate) fn too_large(&mut self, status: StatusCode) {
        if self.in_flight.take().is_none() {
            return;
        }
        self.fail(PublishFailure::Unreachable, Some(status));
        self.after_answer();
    }

    fn answer(
        &mut self,
        status: StatusCode,
        etag: Option<Box<str>>,
        expires: Option<Duration>,
        min_expires: Option<Duration>,
        now: Instant,
    ) {
        if status.is_provisional() {
            return;
        }
        let Some(sent) = self.in_flight.take() else {
            return;
        };
        match status.get() {
            200..=299 => self.accepted(&sent, etag, expires, now),
            401 | 407 => {
                self.events.push_back(PublishEvent::Challenged {
                    request: sent.clone(),
                    status,
                });
                self.in_flight = Some(sent);
                return;
            }
            // a 412 answers a condition, and an initial PUBLISH names none:
            // publishing afresh would be the very request just refused
            412 if sent.if_match.is_none() => self.fail(PublishFailure::Refused, Some(status)),
            // §4: the entity tag is not
            // one it knows any more, so the state is not there to refresh,
            // modify or remove
            412 => {
                self.etag = None;
                self.refresh_at = None;
                self.lapses_at = None;
                if sent.kind == PublishKind::Remove {
                    self.document = None;
                    self.events.push_back(PublishEvent::Removed);
                } else if !matches!(self.queued, Some(Intent::Remove))
                    && let Some(document) = self.document.clone()
                {
                    // the whole state again, as an initial publication. A
                    // modification queued behind the refused request is newer
                    // still, and goes in its place
                    let document = match self.queued.take() {
                        Some(Intent::Publish(newer)) => newer,
                        _ => document,
                    };
                    self.document = Some(document.clone());
                    self.send(PublishKind::Initial, None, Some(document));
                    return;
                } else if self.queued.is_none() {
                    // nothing to publish afresh: the state is simply gone
                    self.events.push_back(PublishEvent::Expired);
                }
            }
            // RFC 3261 §10.2.8's rule, which RFC 3903 §4 applies to PUBLISH:
            // the same request again, asking for at least `Min-Expires`
            423 => match min_expires {
                Some(floor) if floor > sent.expires && sent.kind != PublishKind::Remove => {
                    self.asking = floor;
                    self.send(sent.kind, sent.if_match, sent.body);
                    return;
                }
                _ => self.fail(PublishFailure::IntervalTooBrief, Some(status)),
            },
            489 => {
                // the package is unknown there: nothing queued can succeed
                self.forget();
                self.queued = None;
                self.fail(PublishFailure::BadEvent, Some(status));
                return;
            }
            _ => self.fail(PublishFailure::Refused, Some(status)),
        }
        self.after_answer();
    }

    fn accepted(
        &mut self,
        sent: &PublishRequest,
        etag: Option<Box<str>>,
        expires: Option<Duration>,
        now: Instant,
    ) {
        if sent.kind == PublishKind::Remove {
            self.forget();
            self.document = None;
            self.events.push_back(PublishEvent::Removed);
            return;
        }
        // the compositor's number wins over the one asked for, and one it
        // left out means it granted what was asked
        let granted = expires.unwrap_or(sent.expires);
        if granted.is_zero() {
            self.forget();
            self.events.push_back(PublishEvent::Expired);
            return;
        }
        let Some(etag) = etag else {
            self.forget();
            self.fail(PublishFailure::NoEntityTag, None);
            return;
        };
        let refresh_in = refresh_after(granted);
        self.etag = Some(etag.clone());
        self.refresh_at = Some(now + refresh_in);
        self.lapses_at = Some(now + granted);
        self.events.push_back(PublishEvent::Published {
            etag,
            expires: granted,
            refresh_in,
        });
    }

    /// Whatever was asked for while the last request was in flight.
    fn after_answer(&mut self) {
        if let Some(intent) = self.queued.take() {
            match intent {
                Intent::Remove if self.etag.is_none() => {
                    // nothing was ever created, or it is already gone: the
                    // removal has nothing to do, and the state is not there
                    self.document = None;
                    self.events.push_back(PublishEvent::Removed);
                }
                intent => self.dispatch(intent),
            }
        }
    }

    fn dispatch(&mut self, intent: Intent) {
        if self.in_flight.is_some() {
            self.queued = Some(intent);
            return;
        }
        match intent {
            Intent::Publish(document) => {
                self.document = Some(document.clone());
                match self.etag.clone() {
                    Some(etag) => self.send(PublishKind::Modify, Some(etag), Some(document)),
                    None => self.send(PublishKind::Initial, None, Some(document)),
                }
            }
            Intent::Remove => {
                if let Some(etag) = self.etag.clone() {
                    self.refresh_at = None;
                    self.send(PublishKind::Remove, Some(etag), None);
                }
            }
        }
    }

    fn send(&mut self, kind: PublishKind, if_match: Option<Box<str>>, body: Option<Document>) {
        let expires = if kind == PublishKind::Remove {
            Duration::ZERO
        } else {
            self.asking
        };
        // whatever this sends, the refresh it was scheduled for is either
        // this request or made moot by it; a 2xx schedules the next one, and
        // a refresh that fails is not sent again on a deadline already past
        self.refresh_at = None;
        let request = PublishRequest {
            kind,
            event: self.event.clone(),
            expires,
            if_match,
            body,
        };
        self.in_flight = Some(request.clone());
        self.outbox.push_back(request);
    }

    fn fail(&mut self, reason: PublishFailure, status: Option<StatusCode>) {
        self.events
            .push_back(PublishEvent::Failed { reason, status });
    }

    /// The compositor holds nothing under a name this end knows.
    fn forget(&mut self) {
        self.etag = None;
        self.refresh_at = None;
        self.lapses_at = None;
    }
}

/// A `SIP-ETag` value: RFC 3903 §12's `entity-tag = token`, bounded.
fn entity_tag(value: &[u8]) -> Option<Box<str>> {
    let value = value.trim_ascii();
    let token = |byte: u8| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
            )
    };
    if value.is_empty() || value.len() > MAX_ETAG || !value.iter().copied().all(token) {
        return None;
    }
    core::str::from_utf8(value).ok().map(Box::from)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use sipral_core::endpoint::{Endpoint, OutgoingRequest};
    use sipral_core::msg::{HeaderName, Method, ParseMode, ParseScratch, parse};

    use super::{
        Publication, PublishError, PublishEvent, PublishFailure, PublishKind, PublishRequest,
    };
    use crate::presence::{Basic, Presence, PresenceError, Tuple};
    use crate::registration::refresh_after;
    use crate::{EndpointConfig, Input, StatusCode, TransportId, TransportProtocol, Uri};

    const HOUR: Duration = Duration::from_hours(1);

    /// A final or provisional response carrying `extra` header lines.
    fn answer(publication: &mut Publication, status: u16, extra: &str, now: Instant) {
        let text = format!(
            "SIP/2.0 {status} Whatever\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKpub\r\n\
From: <sip:alice@example.com>;tag=a\r\nTo: <sip:alice@example.com>;tag=b\r\n\
Call-ID: pub@example.com\r\nCSeq: 1 PUBLISH\r\n{extra}Content-Length: 0\r\n\r\n"
        );
        let mut scratch = ParseScratch::new();
        let response =
            parse(text.as_bytes(), &mut scratch, ParseMode::Lenient).expect("a response");
        publication.handle_response(&response, now);
    }

    fn only(publication: &mut Publication) -> PublishRequest {
        let request = publication.poll_transmit().expect("a PUBLISH");
        assert!(publication.poll_transmit().is_none(), "exactly one PUBLISH");
        request
    }

    fn events(publication: &mut Publication) -> Vec<PublishEvent> {
        let mut out = Vec::new();
        while let Some(event) = publication.poll_event() {
            out.push(event);
        }
        out
    }

    fn body(text: &str) -> Arc<[u8]> {
        Arc::from(text.as_bytes())
    }

    /// Published once, under `etag`, for an hour.
    fn published(etag: &str, now: Instant) -> Publication {
        let mut publication = Publication::new("presence");
        publication.publish("application/pidf+xml", body("<presence/>"));
        only(&mut publication);
        answer(
            &mut publication,
            200,
            &format!("SIP-ETag: {etag}\r\nExpires: 3600\r\n"),
            now,
        );
        events(&mut publication);
        publication
    }

    #[test]
    fn the_initial_publish_carries_the_body_and_no_entity_tag() {
        let t0 = Instant::now();
        let mut publication = Publication::new("presence");
        publication.publish("application/pidf+xml", body("<presence/>"));
        let request = only(&mut publication);
        assert_eq!(request.kind(), PublishKind::Initial);
        assert_eq!(request.event(), "presence");
        assert_eq!(request.expires(), HOUR);
        assert_eq!(request.if_match(), None);
        assert_eq!(request.content_type(), Some("application/pidf+xml"));
        assert_eq!(request.body(), Some(&b"<presence/>"[..]));
        assert!(publication.is_in_flight());

        answer(
            &mut publication,
            200,
            "SIP-ETag: dx200xyz\r\nExpires: 1800\r\n",
            t0,
        );
        let granted = Duration::from_secs(1_800);
        assert_eq!(
            events(&mut publication),
            vec![PublishEvent::Published {
                etag: "dx200xyz".into(),
                expires: granted,
                refresh_in: refresh_after(granted),
            }]
        );
        assert_eq!(publication.etag(), Some("dx200xyz"));
        assert_eq!(
            publication.poll_timeout(),
            Some(t0 + refresh_after(granted))
        );
    }

    #[test]
    fn the_refresh_names_the_entity_tag_carries_no_body_and_goes_at_the_margin() {
        let t0 = Instant::now();
        let mut publication = published("dx200xyz", t0);
        let due = t0 + refresh_after(HOUR);
        assert_eq!(due, t0 + Duration::from_secs(3_060), "85% of an hour");
        publication.handle_timeout(t0 + Duration::from_secs(3_059));
        assert!(
            publication.poll_transmit().is_none(),
            "not before it is due"
        );

        publication.handle_timeout(due);
        let refresh = only(&mut publication);
        assert_eq!(refresh.kind(), PublishKind::Refresh);
        assert_eq!(refresh.if_match(), Some("dx200xyz"));
        assert_eq!(refresh.body(), None);
        assert_eq!(refresh.content_type(), None);
        assert_eq!(refresh.expires(), HOUR);
        publication.handle_timeout(due + Duration::from_secs(1));
        assert!(
            publication.poll_transmit().is_none(),
            "one refresh in flight at a time"
        );

        answer(&mut publication, 200, "SIP-ETag: kwj449x\r\n", due);
        assert_eq!(
            publication.etag(),
            Some("kwj449x"),
            "the new tag replaces the old"
        );
        assert!(matches!(
            events(&mut publication)[..],
            [PublishEvent::Published { expires, .. }] if expires == HOUR
        ));
    }

    #[test]
    fn a_modification_names_the_entity_tag_and_carries_the_new_body() {
        let t0 = Instant::now();
        let mut publication = published("dx200xyz", t0);
        publication.publish("application/pidf+xml", body("<presence>2</presence>"));
        let modify = only(&mut publication);
        assert_eq!(modify.kind(), PublishKind::Modify);
        assert_eq!(modify.if_match(), Some("dx200xyz"));
        assert_eq!(modify.body(), Some(&b"<presence>2</presence>"[..]));
        assert_eq!(modify.expires(), HOUR);
    }

    #[test]
    fn a_removal_names_the_entity_tag_with_expires_zero_and_leaves_nothing() {
        let t0 = Instant::now();
        let mut publication = published("dx200xyz", t0);
        publication.remove().expect("something is published");
        let remove = only(&mut publication);
        assert_eq!(remove.kind(), PublishKind::Remove);
        assert_eq!(remove.if_match(), Some("dx200xyz"));
        assert_eq!(remove.expires(), Duration::ZERO);
        assert_eq!(remove.body(), None);

        answer(
            &mut publication,
            200,
            "SIP-ETag: gone\r\nExpires: 0\r\n",
            t0,
        );
        assert_eq!(events(&mut publication), vec![PublishEvent::Removed]);
        assert_eq!(publication.etag(), None);
        assert_eq!(publication.poll_timeout(), None);
        assert_eq!(publication.remove(), Err(PublishError::NothingPublished));
    }

    #[test]
    fn a_lifetime_that_is_zero_on_the_wire_is_not_asked_for() {
        for expires in [Duration::ZERO, Duration::from_millis(999)] {
            let mut publication = Publication::new("presence").expires(expires);
            publication.publish("application/pidf+xml", body("<presence/>"));
            let request = only(&mut publication);
            assert_eq!(request.expires(), HOUR, "{expires:?}");
        }
        let mut publication = Publication::new("presence").expires(Duration::from_millis(1_500));
        publication.publish("application/pidf+xml", body("<presence/>"));
        assert_eq!(only(&mut publication).expires(), Duration::from_secs(1));
        // RFC 3261 §20.19: delta-seconds up to 2^32 - 1
        let mut publication = Publication::new("presence").expires(Duration::MAX);
        publication.publish("application/pidf+xml", body("<presence/>"));
        assert_eq!(
            only(&mut publication).expires(),
            Duration::from_secs(u64::from(u32::MAX))
        );
    }

    #[test]
    fn nothing_published_cannot_be_removed_or_refreshed() {
        let mut publication = Publication::new("presence");
        assert_eq!(publication.remove(), Err(PublishError::NothingPublished));
        assert_eq!(publication.refresh(), Err(PublishError::NothingPublished));
        assert!(publication.poll_transmit().is_none());
    }

    #[test]
    fn a_412_publishes_the_whole_state_afresh_without_an_entity_tag() {
        let t0 = Instant::now();
        let mut publication = published("dx200xyz", t0);
        publication.refresh().expect("something is published");
        only(&mut publication);
        answer(&mut publication, 412, "", t0);
        let fresh = only(&mut publication);
        assert_eq!(fresh.kind(), PublishKind::Initial);
        assert_eq!(fresh.if_match(), None);
        assert_eq!(fresh.body(), Some(&b"<presence/>"[..]));
        assert_eq!(publication.etag(), None);
        assert!(events(&mut publication).is_empty(), "not a failure");
    }

    #[test]
    fn a_412_to_a_modification_publishes_the_modified_state_afresh() {
        let t0 = Instant::now();
        let mut publication = published("dx200xyz", t0);
        publication.publish("text/plain", body("new"));
        only(&mut publication);
        answer(&mut publication, 412, "", t0);
        let fresh = only(&mut publication);
        assert_eq!(fresh.kind(), PublishKind::Initial);
        assert_eq!(fresh.body(), Some(&b"new"[..]));
    }

    #[test]
    fn a_412_to_a_removal_means_the_state_is_already_gone() {
        let t0 = Instant::now();
        let mut publication = published("dx200xyz", t0);
        publication.remove().expect("something is published");
        only(&mut publication);
        answer(&mut publication, 412, "", t0);
        assert!(publication.poll_transmit().is_none());
        assert_eq!(events(&mut publication), vec![PublishEvent::Removed]);
    }

    #[test]
    fn a_412_to_a_publish_that_named_no_entity_tag_is_a_refusal() {
        let t0 = Instant::now();
        let mut publication = Publication::new("presence");
        publication.publish("application/pidf+xml", body("<presence/>"));
        assert_eq!(only(&mut publication).kind(), PublishKind::Initial);
        // there was no condition to fail: publishing afresh would send the
        // same request again, and the same answer back, for as long as the
        // compositor keeps answering
        answer(&mut publication, 412, "", t0);
        assert!(publication.poll_transmit().is_none());
        assert!(!publication.is_in_flight());
        assert_eq!(
            events(&mut publication),
            vec![PublishEvent::Failed {
                reason: PublishFailure::Refused,
                status: StatusCode::new(412).ok(),
            }]
        );
    }

    #[test]
    fn a_423_asks_again_for_the_minimum_the_compositor_named() {
        let t0 = Instant::now();
        let mut publication = Publication::new("presence").expires(Duration::from_secs(60));
        publication.publish("application/pidf+xml", body("<presence/>"));
        assert_eq!(only(&mut publication).expires(), Duration::from_secs(60));
        answer(&mut publication, 423, "Min-Expires: 600\r\n", t0);
        let again = only(&mut publication);
        assert_eq!(again.kind(), PublishKind::Initial);
        assert_eq!(again.expires(), Duration::from_secs(600));
        assert_eq!(again.body(), Some(&b"<presence/>"[..]));
        assert!(events(&mut publication).is_empty());

        // and the refresh asks for it too
        answer(&mut publication, 200, "SIP-ETag: a1\r\n", t0);
        publication.refresh().expect("published");
        assert_eq!(only(&mut publication).expires(), Duration::from_secs(600));
    }

    #[test]
    fn a_423_that_names_nothing_this_end_can_meet_is_a_failure() {
        let t0 = Instant::now();
        for extra in ["", "Min-Expires: 3600\r\n", "Min-Expires: 10\r\n"] {
            let mut publication = Publication::new("presence");
            publication.publish("application/pidf+xml", body("<presence/>"));
            only(&mut publication);
            answer(&mut publication, 423, extra, t0);
            assert!(publication.poll_transmit().is_none(), "{extra}");
            assert_eq!(
                events(&mut publication),
                vec![PublishEvent::Failed {
                    reason: PublishFailure::IntervalTooBrief,
                    status: StatusCode::new(423).ok(),
                }],
                "{extra}"
            );
        }
    }

    #[test]
    fn a_423_to_a_removal_is_a_failure_not_a_loop() {
        // a removal asks for zero whatever the compositor's floor: sending it
        // again would be the same request
        let t0 = Instant::now();
        let mut publication = published("dx200xyz", t0);
        publication.remove().expect("something is published");
        only(&mut publication);
        answer(&mut publication, 423, "Min-Expires: 600\r\n", t0);
        assert!(publication.poll_transmit().is_none());
        assert_eq!(
            events(&mut publication),
            vec![PublishEvent::Failed {
                reason: PublishFailure::IntervalTooBrief,
                status: StatusCode::new(423).ok(),
            }]
        );
    }

    #[test]
    fn a_removal_queued_behind_a_request_the_compositor_forgot_is_done() {
        let t0 = Instant::now();
        let mut publication = published("dx200xyz", t0);
        publication.publish("text/plain", body("new"));
        only(&mut publication);
        publication.remove().expect("in flight");
        answer(&mut publication, 412, "", t0);
        assert!(
            publication.poll_transmit().is_none(),
            "nothing is published afresh only to be removed"
        );
        assert_eq!(events(&mut publication), vec![PublishEvent::Removed]);
        assert_eq!(publication.etag(), None);
    }

    #[test]
    fn a_refresh_asked_for_twice_goes_once() {
        let t0 = Instant::now();
        let mut publication = published("dx200xyz", t0);
        publication.refresh().expect("published");
        publication.refresh().expect("published");
        assert_eq!(only(&mut publication).kind(), PublishKind::Refresh);
    }

    #[test]
    fn an_entity_tag_past_the_bound_is_not_kept() {
        let t0 = Instant::now();
        for (length, kept) in [(128, true), (129, false)] {
            let etag = "e".repeat(length);
            let mut publication = Publication::new("presence");
            publication.publish("text/plain", body("x"));
            only(&mut publication);
            answer(&mut publication, 200, &format!("SIP-ETag: {etag}\r\n"), t0);
            assert_eq!(publication.etag().is_some(), kept, "{length}");
        }
    }

    #[test]
    fn nothing_queued_behind_a_489_goes_later() {
        let t0 = Instant::now();
        let mut publication = published("dx200xyz", t0);
        publication.publish("text/plain", body("1"));
        only(&mut publication);
        publication.publish("text/plain", body("2"));
        answer(&mut publication, 489, "", t0);
        events(&mut publication);
        // the caller tries again, somewhere that knows the package
        publication.publish("text/plain", body("3"));
        assert_eq!(only(&mut publication).kind(), PublishKind::Initial);
        answer(&mut publication, 200, "SIP-ETag: e1\r\n", t0);
        assert!(
            publication.poll_transmit().is_none(),
            "what the 489 answered for stays answered"
        );
    }

    #[test]
    fn a_489_is_final_and_surfaced() {
        let t0 = Instant::now();
        let mut publication = published("dx200xyz", t0);
        publication.publish("application/pidf+xml", body("1"));
        only(&mut publication);
        publication.publish("application/pidf+xml", body("2"));
        answer(&mut publication, 489, "", t0);
        assert_eq!(
            events(&mut publication),
            vec![PublishEvent::Failed {
                reason: PublishFailure::BadEvent,
                status: StatusCode::new(489).ok(),
            }]
        );
        assert!(
            publication.poll_transmit().is_none(),
            "what was queued behind it goes nowhere"
        );
        assert_eq!(publication.etag(), None);
        assert_eq!(publication.poll_timeout(), None);
    }

    #[test]
    fn what_is_asked_for_while_a_request_is_in_flight_waits_for_its_answer() {
        let t0 = Instant::now();
        let mut publication = Publication::new("presence");
        publication.publish("text/plain", body("first"));
        only(&mut publication);
        publication.publish("text/plain", body("second"));
        publication.publish("text/plain", body("third"));
        assert!(publication.poll_transmit().is_none(), "one at a time (§4)");

        answer(&mut publication, 200, "SIP-ETag: e1\r\n", t0);
        let modify = only(&mut publication);
        assert_eq!(modify.kind(), PublishKind::Modify);
        assert_eq!(
            modify.if_match(),
            Some("e1"),
            "named by the answer it waited for"
        );
        assert_eq!(modify.body(), Some(&b"third"[..]), "the latest wins");

        publication.remove().expect("in flight");
        assert!(publication.poll_transmit().is_none());
        answer(&mut publication, 200, "SIP-ETag: e2\r\n", t0);
        let remove = only(&mut publication);
        assert_eq!(remove.kind(), PublishKind::Remove);
        assert_eq!(remove.if_match(), Some("e2"));
    }

    #[test]
    fn a_removal_queued_behind_an_initial_publish_that_failed_has_nothing_to_do() {
        let t0 = Instant::now();
        let mut publication = Publication::new("presence");
        publication.publish("text/plain", body("x"));
        only(&mut publication);
        publication.remove().expect("in flight");
        answer(&mut publication, 403, "", t0);
        assert!(publication.poll_transmit().is_none());
        assert_eq!(
            events(&mut publication),
            vec![
                PublishEvent::Failed {
                    reason: PublishFailure::Refused,
                    status: StatusCode::new(403).ok(),
                },
                PublishEvent::Removed,
            ]
        );
    }

    #[test]
    fn state_nothing_refreshed_expires() {
        let t0 = Instant::now();
        let mut publication = published("dx200xyz", t0);
        publication.handle_timeout(t0 + refresh_after(HOUR));
        only(&mut publication);
        publication.handle_failure();
        assert_eq!(
            events(&mut publication),
            vec![PublishEvent::Failed {
                reason: PublishFailure::Unreachable,
                status: None,
            }]
        );
        assert_eq!(
            publication.etag(),
            Some("dx200xyz"),
            "it stands until it lapses"
        );
        assert_eq!(publication.poll_timeout(), Some(t0 + HOUR));
        publication.handle_timeout(t0 + HOUR);
        assert_eq!(events(&mut publication), vec![PublishEvent::Expired]);
        assert_eq!(publication.etag(), None);
        assert_eq!(publication.poll_timeout(), None);
    }

    #[test]
    fn a_2xx_without_a_usable_entity_tag_is_a_failure() {
        let t0 = Instant::now();
        for extra in ["", "SIP-ETag: two words\r\n", "SIP-ETag: \r\n"] {
            let mut publication = Publication::new("presence");
            publication.publish("text/plain", body("x"));
            only(&mut publication);
            answer(&mut publication, 200, extra, t0);
            assert_eq!(
                events(&mut publication),
                vec![PublishEvent::Failed {
                    reason: PublishFailure::NoEntityTag,
                    status: None,
                }],
                "{extra:?}"
            );
            assert_eq!(publication.etag(), None);
            assert_eq!(publication.poll_timeout(), None);
        }
    }

    #[test]
    fn a_2xx_granting_nothing_leaves_nothing_published() {
        let t0 = Instant::now();
        let mut publication = Publication::new("presence");
        publication.publish("text/plain", body("x"));
        only(&mut publication);
        answer(&mut publication, 200, "SIP-ETag: e1\r\nExpires: 0\r\n", t0);
        assert_eq!(events(&mut publication), vec![PublishEvent::Expired]);
        assert_eq!(publication.etag(), None);
    }

    #[test]
    fn a_challenge_leaves_the_request_in_flight_for_the_caller_to_answer() {
        let t0 = Instant::now();
        let mut publication = Publication::new("presence");
        publication.publish("text/plain", body("x"));
        let sent = only(&mut publication);
        answer(&mut publication, 407, "", t0);
        assert_eq!(
            events(&mut publication),
            vec![PublishEvent::Challenged {
                request: sent,
                status: StatusCode::PROXY_AUTH_REQUIRED,
            }]
        );
        assert!(publication.is_in_flight());
        assert!(publication.poll_transmit().is_none());
        answer(&mut publication, 200, "SIP-ETag: e1\r\n", t0);
        assert_eq!(publication.etag(), Some("e1"));
    }

    #[test]
    fn provisional_responses_and_strays_change_nothing() {
        let t0 = Instant::now();
        let mut publication = Publication::new("presence");
        answer(&mut publication, 200, "SIP-ETag: stray\r\n", t0);
        publication.handle_failure();
        assert!(events(&mut publication).is_empty());
        assert_eq!(publication.etag(), None);

        publication.publish("text/plain", body("x"));
        only(&mut publication);
        answer(&mut publication, 100, "", t0);
        assert!(publication.is_in_flight());
        assert!(events(&mut publication).is_empty());
    }

    #[test]
    fn a_presence_document_is_published_as_pidf() {
        let mut publication = Publication::new("presence");
        let mut presence = Presence::new("pres:alice@example.com");
        presence.tuples.push(Tuple::new("t1", Basic::Open));
        publication
            .publish_presence(&presence)
            .expect("a writable document");
        let request = only(&mut publication);
        assert_eq!(request.content_type(), Some("application/pidf+xml"));
        assert_eq!(
            Presence::parse(request.body().expect("a body")).expect("it reads"),
            presence
        );

        let unwritable = Presence::new("");
        assert_eq!(
            Publication::new("presence").publish_presence(&unwritable),
            Err(PublishError::Unwritable(PresenceError::Unwritable(
                "an empty entity"
            )))
        );
    }

    #[test]
    fn what_goes_on_the_wire_is_what_the_request_says() {
        let t0 = Instant::now();
        let local: SocketAddr = "192.0.2.1:5060".parse().expect("an address");
        let compositor: SocketAddr = "192.0.2.9:5060".parse().expect("an address");
        let udp = TransportId(1);
        let mut endpoint = Endpoint::new(EndpointConfig::default(), [5; 32]).expect("an endpoint");
        endpoint
            .receive(
                Input::TransportBound {
                    transport: udp,
                    protocol: TransportProtocol::Udp,
                    local,
                    remote: None,
                },
                t0,
            )
            .expect("binding a transport");

        let mut publication = published("dx200xyz", t0);
        publication.publish("application/pidf+xml", body("<presence/>"));
        let modify = only(&mut publication);
        let aor = Uri::parse_str("sip:alice@example.com").expect("a URI");
        let request = modify.apply(
            OutgoingRequest::new(Method::Publish, aor, udp, compositor)
                .to(b"<sip:alice@example.com>")
                .from(b"<sip:alice@example.com>"),
        );
        endpoint.request(&request, t0).expect("it goes");
        let wire = endpoint
            .poll_transmit()
            .expect("a datagram")
            .payload
            .to_vec();
        let mut scratch = ParseScratch::new();
        let sent = parse(&wire, &mut scratch, ParseMode::Strict).expect("a request");
        assert!(wire.starts_with(b"PUBLISH sip:alice@example.com SIP/2.0\r\n"));
        assert_eq!(sent.header(HeaderName::Event), Some(&b"presence"[..]));
        assert_eq!(sent.header(HeaderName::Expires), Some(&b"3600"[..]));
        assert_eq!(
            sent.header(HeaderName::Extension("SIP-If-Match")),
            Some(&b"dx200xyz"[..])
        );
        assert_eq!(
            sent.header(HeaderName::ContentType),
            Some(&b"application/pidf+xml"[..])
        );
        assert_eq!(sent.body(), b"<presence/>");
    }
}
