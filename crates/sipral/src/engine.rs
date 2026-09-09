// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The join: a call the user agent reports gets audio, and a call that ends
//! gives it up.
//!
//! `docs/01-architecture.md` states the rule this keeps: **`sipral-ua` never
//! depends on `sipral-media`, `sipral-rtp` or `sipral-nat`, and none of those
//! depends on `sipral-ua`.** Signalling and media never call each other. What
//! passes between them is a description — [`MediaCapabilities`] out of a
//! catalogue and into an offer, [`MediaPlan`] out of the negotiation and into
//! a stream — and until this crate existed, nothing carried it, so every
//! application wrote the join itself and each one wrote it differently.
//!
//! This is that carrier, and it is deliberately not a wrapper around
//! [`UserAgent`]. Wrapping would mean restating twenty-five methods whose
//! semantics live somewhere else, and every one of them would be a place to
//! get registration or transfer subtly wrong. What is here instead is the
//! small number of operations that genuinely need both halves — placing a call
//! with an offer in it, answering one, and draining the events so that media
//! is attached before the application sees the news — and the user agent is
//! passed in for those. Everything else an application does, it does on the
//! user agent directly.
//!
//! # One drain
//!
//! [`MediaEngine::poll_event`] is the one place events come from, and it takes
//! the user agent because it drains it. That is not a convenience: an
//! application that polled the user agent itself would take the events this
//! engine needs in order to know a call has been answered, and the failure
//! would look like a call that rings, answers, and is silent.
//!
//! # What a call has to be for this to manage it
//!
//! Placed with [`MediaEngine::place`] or answered with
//! [`MediaEngine::answer`]. A call placed straight on the user agent is one
//! this engine has never described anything for, and it is left alone rather
//! than guessed at.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use sipral_core::msg::OwnedMessage;
use sipral_core::sdp::{
    AcceptedStream, Attribute, Connection, Direction, MediaDescription, MediaPlan, NegotiatedCodec,
    Origin, SessionDescription, StreamAnswer, parse, static_rtpmap,
};
use sipral_ua::{AccountId, CallHandle, OutgoingCall, StatusCode, UaEvent, UserAgent};

use crate::clock::WallClock;
use crate::codec::{Codec, CodecCatalog};
use crate::error::MediaError;
use crate::event::{Event, MediaEvent};
use crate::session::{Datagram, MediaConfig, MediaSession, StreamIdentity};

/// The media type this stack negotiates. There is no video, deliberately, and
/// an offered stream of anything else is refused rather than half-taken.
const AUDIO: &str = "audio";

/// RFC 4733's named events, which ride alongside a codec rather than being
/// one, and which an answer therefore keeps without there being a codec behind
/// them.
const TELEPHONE_EVENT: &str = "telephone-event";

/// RFC 3389 comfort noise, likewise.
const COMFORT_NOISE: &str = "CN";

/// What this engine knows about one call.
#[derive(Clone, Debug)]
struct Managed {
    /// What this end has described. Absent for an incoming call between the
    /// INVITE arriving and it being answered.
    local: Option<SessionDescription>,
    /// What the far end has.
    remote: Option<SessionDescription>,
    /// Where this end receives media, which the application chose because it
    /// owns the socket.
    address: Option<SocketAddr>,
    identity: StreamIdentity,
    session_id: u64,
    /// The `o=` version this end is up to. RFC 3264 §8 makes it the way one
    /// end says "this differs from what I said before".
    version: u64,
}

/// Signalling joined to media, for as many calls as there are.
#[derive(Debug)]
pub struct MediaEngine {
    catalog: CodecCatalog,
    config: MediaConfig,
    clock: WallClock,
    /// Ordered rather than hashed so that two runs of the same test drain
    /// events in the same order.
    sessions: BTreeMap<CallHandle, MediaSession>,
    calls: BTreeMap<CallHandle, Managed>,
    events: VecDeque<(CallHandle, MediaEvent)>,
}

impl MediaEngine {
    /// An engine that will offer what `catalog` holds.
    ///
    /// `clock` is what the RTCP sender reports need and the only thing here
    /// that a monotonic instant cannot supply; see [`WallClock`].
    #[must_use]
    pub fn new(catalog: CodecCatalog, config: MediaConfig, clock: WallClock) -> Self {
        Self {
            catalog,
            config,
            clock,
            sessions: BTreeMap::new(),
            calls: BTreeMap::new(),
            events: VecDeque::new(),
        }
    }

    /// What this build offers, in the order it offers it. A4's first half.
    #[must_use]
    pub const fn catalog(&self) -> &CodecCatalog {
        &self.catalog
    }

    /// One call's media, once there is any.
    #[must_use]
    pub fn session(&mut self, call: CallHandle) -> Option<&mut MediaSession> {
        self.sessions.get_mut(&call)
    }

    /// The calls that have media running.
    pub fn active(&self) -> impl Iterator<Item = CallHandle> + '_ {
        self.sessions.keys().copied()
    }
}

// -- placing and answering ---------------------------------------------------

impl MediaEngine {
    /// Place a call with an offer in it.
    ///
    /// `local` is where this end will receive media: the application owns the
    /// socket, so it is the only one that can say. Any offer already set on
    /// `outgoing` is replaced — writing the description is what this method is
    /// for, and two of them would be one too many.
    ///
    /// # Errors
    /// [`MediaError::Signalling`] when the user agent refuses the call.
    pub fn place(
        &mut self,
        agent: &mut UserAgent,
        account: AccountId,
        outgoing: OutgoingCall,
        local: SocketAddr,
        now: Instant,
    ) -> Result<CallHandle, MediaError> {
        let (identity, session_id) = draw(agent);
        let offer = self.write_offer(local, session_id, 1);
        let placing = outgoing.offer(Arc::from(offer.to_bytes()));
        let call = agent.call(account, &placing, now)?;
        self.calls.insert(
            call,
            Managed {
                local: Some(offer),
                remote: None,
                address: Some(local),
                identity,
                session_id,
                version: 1,
            },
        );
        Ok(call)
    }

    /// Answer a call that came in, with the answer to the offer it carried.
    ///
    /// # Errors
    /// [`MediaError::NoSuchCall`] for a call this engine never saw arrive,
    /// [`MediaError::Description`] when the answer cannot be built, and
    /// [`MediaError::Signalling`] when the user agent refuses to send it.
    ///
    /// An INVITE that carried no offer is answered with one of ours instead,
    /// which is legal (§13.2.2.4) and half-supported here: the far end's
    /// answer to it travels in the ACK, and the user agent does not report
    /// what an ACK carried. Such a call is answered, is up, and reports
    /// [`MediaEvent::Failed`] with [`MediaError::NoDescription`] rather than
    /// starting audio it has no plan for.
    pub fn answer(
        &mut self,
        agent: &mut UserAgent,
        call: CallHandle,
        local: SocketAddr,
        now: Instant,
    ) -> Result<(), MediaError> {
        let managed = self.calls.get(&call).ok_or(MediaError::NoSuchCall)?;
        let (session_id, version) = (managed.session_id, managed.version.saturating_add(1));
        let description = match managed.remote.clone() {
            Some(offer) => self.write_answer(&offer, local, session_id, version)?,
            None => self.write_offer(local, session_id, version),
        };
        let bytes = description.to_bytes();
        agent.answer(call, Some(Arc::from(bytes)), now)?;
        if let Some(managed) = self.calls.get_mut(&call) {
            managed.local = Some(description);
            managed.address = Some(local);
            managed.version = version;
        }
        Ok(())
    }
}

// -- draining ----------------------------------------------------------------

impl MediaEngine {
    /// The next thing the application has to know, with media already
    /// attached.
    ///
    /// Drain to empty, as with any of the polls in this tree. Media events
    /// come out after the signalling event that produced them, so an
    /// application that acts on [`UaEvent::CallConfirmed`] and then on
    /// [`MediaEvent::Started`] sees them in the order they happened.
    pub fn poll_event(&mut self, agent: &mut UserAgent, now: Instant) -> Option<Event> {
        if let Some((call, event)) = self.events.pop_front() {
            return Some(Event::Media { call, event });
        }
        if let Some((call, event)) = self.session_event() {
            return Some(Event::Media { call, event });
        }
        let signalling = agent.poll_event()?;
        self.absorb(&signalling, agent, now);
        Some(Event::Signalling(signalling))
    }

    /// Time has passed: every session's stall watchdog gets a look.
    pub fn handle_timeout(&mut self, now: Instant) {
        for session in self.sessions.values_mut() {
            session.handle_timeout(now);
        }
    }

    /// When to call [`MediaEngine::handle_timeout`] or
    /// [`MediaEngine::poll_rtcp`], if nothing arrives first.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.sessions
            .values()
            .filter_map(MediaSession::poll_timeout)
            .min()
    }

    /// A control datagram that is due, and the call to send it for.
    ///
    /// One at a time, like every other poll here. A caller loops until it
    /// answers `None`.
    #[must_use]
    pub fn poll_rtcp(&mut self, now: Instant) -> Option<(CallHandle, Datagram<'_>)> {
        let due = self
            .sessions
            .iter()
            .find(|(_, session)| session.rtcp_deadline_passed(now))
            .map(|(call, _)| *call)?;
        let session = self.sessions.get_mut(&due)?;
        session.poll_rtcp(now).map(|datagram| (due, datagram))
    }

    /// The first event any session has to report.
    fn session_event(&mut self) -> Option<(CallHandle, MediaEvent)> {
        for (call, session) in &mut self.sessions {
            if let Some(event) = session.poll_event() {
                return Some((*call, event));
            }
        }
        None
    }

    /// Act on what the user agent said.
    fn absorb(&mut self, event: &UaEvent, agent: &mut UserAgent, now: Instant) {
        match event {
            UaEvent::IncomingCall { call, request, .. } => self.arrived(*call, request, agent),
            UaEvent::CallForked { call, sibling } => self.forked(*call, *sibling, agent),
            UaEvent::CallProgress { call, response, .. } => {
                // a 183 with a description is early media: a network
                // announcement the caller has to hear before anybody answers
                self.take_body(*call, Some(response), now);
            }
            UaEvent::CallConfirmed { call, response, .. } => {
                self.take_body(*call, response.as_ref(), now);
            }
            UaEvent::SessionChanged {
                call,
                local,
                remote,
                ..
            } => self.redescribed(*call, local.as_deref(), remote.as_deref(), now),
            UaEvent::Reoffer { call, request } => self.answer_reoffer(*call, request, agent, now),
            UaEvent::CallEnded { call, .. } => self.release(*call, now),
            _ => {}
        }
    }
}

// -- what each event does ----------------------------------------------------

impl MediaEngine {
    /// A call came in: keep whatever offer it carried, and mint the numbers
    /// its stream will start from.
    fn arrived(&mut self, call: CallHandle, request: &OwnedMessage, agent: &mut UserAgent) {
        let (identity, session_id) = draw(agent);
        self.calls.insert(
            call,
            Managed {
                local: None,
                remote: body_description(Some(request)),
                address: None,
                identity,
                session_id,
                version: 1,
            },
        );
    }

    /// A proxy forked the INVITE: the new branch was offered exactly what the
    /// old one was, so it inherits the description and gets a stream of its
    /// own to start from.
    fn forked(&mut self, call: CallHandle, sibling: CallHandle, agent: &mut UserAgent) {
        let Some(parent) = self.calls.get(&call).cloned() else {
            return;
        };
        let (identity, session_id) = draw(agent);
        self.calls.insert(
            sibling,
            Managed {
                identity,
                session_id,
                ..parent
            },
        );
    }

    /// A response arrived: if it described a session, that is the far end's
    /// half of the negotiation and the plan can be worked out.
    fn take_body(&mut self, call: CallHandle, message: Option<&OwnedMessage>, now: Instant) {
        if !self.calls.contains_key(&call) {
            return;
        }
        if let Some(described) = body_description(message)
            && let Some(managed) = self.calls.get_mut(&call)
        {
            managed.remote = Some(described);
        }
        self.settle(call, now);
    }

    /// The user agent rewrote the session: a hold, a resume, or a change it
    /// answered on our behalf. Both descriptions come with it, because some of
    /// them are the user agent's own writing.
    fn redescribed(
        &mut self,
        call: CallHandle,
        local: Option<&[u8]>,
        remote: Option<&[u8]>,
        now: Instant,
    ) {
        let Some(managed) = self.calls.get_mut(&call) else {
            return;
        };
        if let Some(described) = local.and_then(|bytes| parse(bytes).ok()) {
            managed.version = managed.version.max(described.origin.version);
            managed.local = Some(described);
        }
        if let Some(described) = remote.and_then(|bytes| parse(bytes).ok()) {
            managed.remote = Some(described);
        }
        self.settle(call, now);
    }

    /// The far end offered something the user agent has no policy for, which
    /// in practice means a codec change. It has one here: the same answer any
    /// offer gets.
    fn answer_reoffer(
        &mut self,
        call: CallHandle,
        request: &OwnedMessage,
        agent: &mut UserAgent,
        now: Instant,
    ) {
        let Some(managed) = self.calls.get(&call) else {
            return;
        };
        let (Some(address), Some(offer)) = (managed.address, body_description(Some(request)))
        else {
            // an offer this engine cannot answer is refused rather than left
            // to be retransmitted until the call dies
            let _ = agent.reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
            return;
        };
        let version = managed.version.saturating_add(1);
        let session_id = managed.session_id;
        match self.write_answer(&offer, address, session_id, version) {
            Ok(answer) => {
                let bytes = answer.to_bytes();
                if agent.accept_reoffer(call, Some(&bytes), now).is_ok()
                    && let Some(managed) = self.calls.get_mut(&call)
                {
                    managed.version = version;
                    // the descriptions themselves arrive back as
                    // UaEvent::SessionChanged, which is what settles the plan
                }
            }
            Err(error) => {
                self.events.push_back((call, MediaEvent::Failed(error)));
                let _ = agent.reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
            }
        }
    }

    /// The call is over: let the stream go, close any recording, and say what
    /// it cost.
    fn release(&mut self, call: CallHandle, now: Instant) {
        self.calls.remove(&call);
        let Some(mut session) = self.sessions.remove(&call) else {
            return;
        };
        // a recording that is not closed here is a file with zeroes where its
        // two lengths should be
        if let Err(error) = session.stop_recording()
            && !matches!(error, MediaError::NotRecording)
        {
            self.events.push_back((call, MediaEvent::Failed(error)));
        }
        self.events
            .push_back((call, MediaEvent::Ended(session.statistics(now))));
    }
}

// -- the plan ----------------------------------------------------------------

impl MediaEngine {
    /// Work out what the two descriptions agreed and make the stream match it.
    fn settle(&mut self, call: CallHandle, now: Instant) {
        let Some(managed) = self.calls.get(&call) else {
            return;
        };
        let (Some(local), Some(remote)) = (managed.local.as_ref(), managed.remote.as_ref()) else {
            // one half of the negotiation is missing, which before the answer
            // arrives is the ordinary state of affairs
            return;
        };
        let plan = match local.media_plan(remote, 0) {
            Ok(Some(plan)) => plan,
            Ok(None) => {
                self.fail(call, MediaError::StreamRefused);
                return;
            }
            Err(error) => {
                self.fail(call, MediaError::from(error));
                return;
            }
        };
        let codec = match Codec::of_plan(&plan) {
            Ok(codec) => codec,
            Err(error) => {
                self.fail(call, error);
                return;
            }
        };
        match self.sessions.get_mut(&call) {
            // the same codec on a session that is already running: a hold, a
            // resume, or a peer that moved its address
            Some(session) if session.codec() == codec => {
                session.adopt(&plan, now);
                self.events.push_back((
                    call,
                    MediaEvent::Changed {
                        codec,
                        direction: plan.direction,
                    },
                ));
            }
            // a different codec needs a different encoder, a different decoder
            // and a different frame length, so it needs a different session
            _ => self.start(call, &plan, codec, now),
        }
    }

    /// Open the stream for a plan, replacing whatever was there.
    fn start(&mut self, call: CallHandle, plan: &MediaPlan, codec: Codec, now: Instant) {
        let Some(managed) = self.calls.get(&call) else {
            return;
        };
        let replacing = self.sessions.contains_key(&call);
        let opened = MediaSession::open(
            plan,
            self.catalog.frame_length(),
            &self.config,
            managed.identity,
            self.clock,
            now,
        );
        match opened {
            Ok(session) => {
                self.sessions.insert(call, session);
                let event = if replacing {
                    MediaEvent::Changed {
                        codec,
                        direction: plan.direction,
                    }
                } else {
                    MediaEvent::Started {
                        codec,
                        direction: plan.direction,
                    }
                };
                self.events.push_back((call, event));
            }
            Err(error) => self.fail(call, error),
        }
    }

    /// Media could not be started. The call is untouched: whether to hang up
    /// over it is a decision with a person on the other end.
    fn fail(&mut self, call: CallHandle, error: MediaError) {
        self.events.push_back((call, MediaEvent::Failed(error)));
    }
}

// -- writing descriptions ----------------------------------------------------

impl MediaEngine {
    /// The offer this catalogue makes, for media arriving at `address`.
    fn write_offer(
        &self,
        address: SocketAddr,
        session_id: u64,
        version: u64,
    ) -> SessionDescription {
        let mut description = SessionDescription::new(
            Origin::new(session_id, version, address.ip()),
            Connection::new(address.ip()),
        );
        description.media.push(self.catalog.capabilities().offer(
            AUDIO,
            address.port(),
            Direction::SendRecv,
        ));
        description
    }

    /// The answer to an offer that arrived.
    ///
    /// One stream is taken and every other is refused, whatever it is. This
    /// end has one media address, and a second audio stream would need a
    /// second one; RFC 3264 §6 wants the refusal written as a port of zero in
    /// the same position rather than a stream left out, which is what
    /// [`StreamAnswer::Reject`] produces.
    fn write_answer(
        &self,
        offer: &SessionDescription,
        address: SocketAddr,
        session_id: u64,
        version: u64,
    ) -> Result<SessionDescription, MediaError> {
        let mut taken = false;
        let streams: Vec<StreamAnswer> = offer
            .media
            .iter()
            .map(|offered| {
                if taken {
                    return StreamAnswer::Reject;
                }
                let answer = self.take_stream(offered, address);
                taken = matches!(answer, StreamAnswer::Accept(_));
                answer
            })
            .collect();
        offer
            .answer(
                Origin::new(session_id, version, address.ip()),
                Connection::new(address.ip()),
                &streams,
            )
            .map_err(MediaError::from)
    }

    /// What to do with one offered stream.
    fn take_stream(&self, offered: &MediaDescription, address: SocketAddr) -> StreamAnswer {
        if offered.media != AUDIO || offered.is_rejected() {
            return StreamAnswer::Reject;
        }
        let (formats, any_codec) = self.keepable(offered);
        if !any_codec {
            return StreamAnswer::Reject;
        }
        let names: Vec<&str> = formats.iter().map(String::as_str).collect();
        let mut accepted = AcceptedStream::in_offer_order(address.port(), offered, &names)
            .with_direction(Direction::SendRecv);
        // RFC 5761 §5.1.1: multiplexing happens only where both ends asked for
        // it, so the answer says so only if the offer did and this build wants
        // it
        if self.catalog.capabilities().rtcp_mux && offered.has_rtcp_mux() {
            accepted = accepted.with_attribute(Attribute::flag("rtcp-mux"));
        }
        StreamAnswer::Accept(accepted)
    }

    /// The formats of an offer this build would keep, and whether any of them
    /// is a codec.
    ///
    /// The numbers are the offer's own, which is the whole reason this is not
    /// a comparison against our own payload types: a dynamic type means
    /// whatever the offer's `a=rtpmap` called it, and a peer that numbers Opus
    /// 111 has said the same thing we say with 96.
    fn keepable(&self, offered: &MediaDescription) -> (Vec<String>, bool) {
        let mut formats = Vec::with_capacity(offered.formats.len());
        let mut any_codec = false;
        for format in &offered.formats {
            let Ok(payload) = format.parse::<u8>() else {
                continue;
            };
            let Some(rtpmap) = offered.rtpmap(payload).or_else(|| static_rtpmap(payload)) else {
                continue;
            };
            let named = NegotiatedCodec::new(rtpmap);
            if named.is_encoding(TELEPHONE_EVENT) {
                if self.catalog.capabilities().dtmf {
                    formats.push(format.clone());
                }
                continue;
            }
            if named.is_encoding(COMFORT_NOISE) {
                formats.push(format.clone());
                continue;
            }
            if Codec::of(&named).is_some_and(|codec| self.catalog.codecs().contains(&codec)) {
                formats.push(format.clone());
                any_codec = true;
            }
        }
        (formats, any_codec)
    }
}

/// The session description in a message body, when it has one this stack can
/// read.
fn body_description(message: Option<&OwnedMessage>) -> Option<SessionDescription> {
    let message = message?;
    let raw = message.as_raw();
    let body = raw.body();
    if body.is_empty() {
        return None;
    }
    parse(body).ok()
}

/// The numbers one stream starts from, out of the same seeded token stream the
/// branches, tags and `Call-ID`s come from.
///
/// One token is 128 bits of material that no other call gets, and these are
/// four views of it. None of them needs to be independent of the others: an
/// SSRC has to be unpredictable and unique, a starting sequence number and
/// timestamp have to be unpredictable (RFC 3550 §5.1), and a session
/// identifier has to be unique (RFC 4566 §5.2). A single unique token
/// satisfies all four at once.
fn draw(agent: &mut UserAgent) -> (StreamIdentity, u64) {
    let token = agent.endpoint().token();
    let identity = StreamIdentity {
        ssrc: u32::try_from(hex(&token, 0, 8)).unwrap_or(0),
        sequence: u16::try_from(hex(&token, 16, 4)).unwrap_or(0),
        timestamp: u32::try_from(hex(&token, 8, 8)).unwrap_or(0),
        seed: hex(&token, 20, 12),
    };
    (identity, hex(&token, 0, 16))
}

/// `len` hexadecimal characters of `token`, starting at `at`, as a number.
fn hex(token: &[u8], at: usize, len: usize) -> u64 {
    token
        .get(at..at.saturating_add(len))
        .unwrap_or_default()
        .iter()
        .fold(0_u64, |value, digit| {
            (value << 4) | u64::from(nibble(*digit))
        })
}

/// One hexadecimal character. A token is produced by this workspace and is
/// hexadecimal by construction; anything else reads as zero rather than
/// refusing, because a stream identifier that is one bit weaker than intended
/// is a far smaller problem than a call that cannot start.
const fn nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        b'A'..=b'F' => digit - b'A' + 10,
        _ => 0,
    }
}
