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
//! Placed with [`MediaEngine::place`], answered with [`MediaEngine::answer`],
//! or taken from a transfer with [`MediaEngine::accept_transfer`]. A call
//! placed straight on the user agent is one this engine has never described
//! anything for, and it is left alone rather than guessed at.
//!
//! An incoming call may also be rung with [`MediaEngine::ring`] before it is
//! answered: the far end hears the answer to its offer, and this end's
//! session, before anybody picks up. [`MediaEngine::answer`] on a call rung
//! this way does not negotiate a second time — it reuses the session and the
//! description [`MediaEngine::ring`] already wrote, and RFC 3262 §5 together
//! with RFC 6337 §3.1.1 decide what, if anything, the 200 OK repeats.
//!
//! # One call, its own catalogue
//!
//! [`MediaEngine::place`] and [`MediaEngine::answer`] draw the codec
//! catalogue and the [`MediaConfig`] a call opens with from this engine's own
//! defaults, but neither is copied into the call as a standing reference to
//! them — a call keeps what it started with even if the engine's defaults
//! change under it later. [`MediaEngine::place_with`], [`MediaEngine::ring_with`]
//! and [`MediaEngine::answer_with`] take a [`CallMedia`] naming both for one
//! call alone, which is what an attended transfer needs: `UserAgent::consult`
//! holds two calls at once, and a global codec order or a global render delay
//! would make the second one a race against whichever call touches it last.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::auth::KeySource;
use sipral_core::msg::OwnedMessage;
#[cfg(feature = "dtls")]
use sipral_core::sdp::RtcpPlan;
use sipral_core::sdp::{
    AcceptedStream, Attribute, Connection, Direction, KeySalt, Keying, MASTER_KEY, MASTER_SALT,
    MediaDescription, MediaPlan, NegotiatedCodec, Origin, SessionDescription, StreamAnswer, parse,
    static_rtpmap,
};
#[cfg(feature = "dtls")]
use sipral_dtls::setup::{Party, Setup};
use sipral_ua::{
    AccountId, CallHandle, CallState, OutgoingCall, OutgoingExtras, StatusCode, UaError, UaEvent,
    UserAgent,
};
use zeroize::Zeroizing;

use crate::clock::WallClock;
use crate::codec::{Codec, CodecCandidate, CodecCatalog, Keyed};
use crate::counters::Counters;
#[cfg(feature = "dtls")]
use crate::dtls::Identity;
use crate::dtmf::Digit;
use crate::error::MediaError;
use crate::event::{DigitSource, Event, MediaEvent};
#[cfg(feature = "dtls")]
use crate::keying::SrtpPolicy;
use crate::keying::{self};
use crate::session::{MediaConfig, MediaSession, Start, StreamIdentity};
use crate::share::{self, Held, SessionGuard, SessionShare};

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
    /// D6: what this call offers and in what order — this engine's default
    /// unless [`MediaEngine::place_with`] or [`MediaEngine::answer_with`] was
    /// asked for something else, but this call's own from here on regardless
    /// of what the engine's default becomes afterwards.
    catalog: CodecCatalog,
    /// D6: how this call's session is opened — this engine's default unless
    /// overridden the same way.
    config: MediaConfig,
    /// What this end wrote for DTLS-SRTP in the description it last sent:
    /// which side of the exchange it was on, and the `a=setup` it wrote.
    ///
    /// Kept because [`dtls_role`](sipral_dtls::setup::dtls_role) reads the
    /// offer's value and the answer's together, and only one of the two ever
    /// arrives from the far end. `None` on every call not keyed this way.
    dtls: Option<(Side, String)>,
    /// Whether [`MediaEngine::ring_with`] has already described and opened
    /// this call's session, before it was answered.
    ///
    /// What [`MediaEngine::answer_with`] reads to tell early media it wrote
    /// itself from a call answered without ever ringing: the first writes
    /// `local` and starts the session on the spot, since there is no later
    /// event to hang that on the way there is for an answer, so `local` alone
    /// cannot say which one happened. Once true, it stays true for the life
    /// of the call — this is a one-way door, and ringing with media a second
    /// time is refused rather than reopened.
    rung_with_media: bool,
}

/// What one call opens with, when it is not this engine's defaults.
///
/// [`MediaEngine::place_with`] and [`MediaEngine::answer_with`] take one of
/// these rather than a catalogue and a configuration as two loose parameters:
/// D6's whole point is that the two travel together as one call's own
/// choice, and a caller overriding one nearly always has something to say
/// about the other too — a consultation leg to a gateway that only speaks
/// one codec is also a call whose render delay and device belong to that
/// gateway's headset, not to whatever the primary call is using.
#[derive(Clone, Debug, PartialEq)]
pub struct CallMedia {
    /// What to offer, in what order.
    pub catalog: CodecCatalog,
    /// How to open the session.
    pub config: MediaConfig,
}

impl CallMedia {
    /// Bundle a catalogue and a configuration for one call.
    #[must_use]
    pub fn new(catalog: CodecCatalog, config: MediaConfig) -> Self {
        Self { catalog, config }
    }
}

/// Signalling joined to media, for as many calls as there are.
#[derive(Debug)]
pub struct MediaEngine {
    /// The site policy: what a call offers and how its session is opened
    /// unless [`MediaEngine::place_with`] or [`MediaEngine::answer_with`]
    /// named something else for it. D6: kept here as the default a call is
    /// drawn from at the moment it starts, never read again on its behalf
    /// afterwards — a call's own copy lives in [`Managed`], so changing this
    /// engine's default cannot move a call already in progress.
    catalog: CodecCatalog,
    config: MediaConfig,
    clock: WallClock,
    /// Ordered rather than hashed so that two runs of the same test drain
    /// events in the same order.
    ///
    /// Each behind a lock of its own, and this is the one strong reference to
    /// each: a thread that carries a call's audio reaches it through a
    /// [`SessionShare`], which works for as long as the entry is here.
    sessions: BTreeMap<CallHandle, Held>,
    calls: BTreeMap<CallHandle, Managed>,
    events: VecDeque<(CallHandle, MediaEvent)>,
    /// The RTCP goodbyes of calls that have ended, waiting to be polled.
    ///
    /// Owned bytes rather than a borrow of a session's scratch buffer,
    /// because the session they came from is gone by the time anyone asks.
    farewells: VecDeque<(CallHandle, SocketAddr, Vec<u8>)>,
    /// D3's health counters, fed from the same drain that hands events to
    /// the application — see `crate::counters`.
    counters: Counters,
    /// Where every SRTP master key comes from, and every DTLS secret with
    /// them, and nothing else does.
    ///
    /// Its own stream, separate from the endpoint's, because the endpoint's
    /// seed is written in clear into every replay recording. A recording must
    /// be able to reproduce a session byte for byte without carrying the
    /// means to decrypt any of the media that went with it — nor, since the
    /// certificate key is drawn from the same stream, the means to be
    /// mistaken for the stack that made it.
    keys: KeySource,
    /// The key and certificate this stack presents for DTLS-SRTP, made on the
    /// first call that needs one and re-made when it is close to running out.
    ///
    /// `None` until then, because a stack that never places an encrypted call
    /// should not spend a P-256 key pair on starting up.
    #[cfg(feature = "dtls")]
    identity: Option<Identity>,
}

impl MediaEngine {
    /// An engine that will offer what `catalog` holds.
    ///
    /// `media_seed` is thirty-two bytes of entropy this engine derives every
    /// SRTP master key from. **It must not be the bytes handed to
    /// `UserAgent::new`, and no two engines may be given the same ones.**
    /// Neither rule can be enforced here — both are a caller's to keep, the
    /// way the seed itself is — and the first one is what keeps a replay
    /// recording, which carries the signalling seed in clear, from carrying
    /// the means to derive every key this stack will ever offer.
    ///
    /// `clock` is what the RTCP sender reports need and the only thing here
    /// that a monotonic instant cannot supply; see [`WallClock`].
    #[must_use]
    pub fn new(
        catalog: CodecCatalog,
        config: MediaConfig,
        clock: WallClock,
        media_seed: [u8; 32],
    ) -> Self {
        Self {
            catalog,
            config,
            clock,
            sessions: BTreeMap::new(),
            calls: BTreeMap::new(),
            events: VecDeque::new(),
            farewells: VecDeque::new(),
            counters: Counters::default(),
            keys: KeySource::new(media_seed),
            #[cfg(feature = "dtls")]
            identity: None,
        }
    }

    /// The key and certificate this stack presents, making one if there is
    /// none or if the one there is has nearly run out.
    ///
    /// # Errors
    /// [`MediaError::DtlsIdentity`], which a sound media seed does not
    /// produce.
    #[cfg(feature = "dtls")]
    fn identity(&mut self, now: Instant) -> Result<&Identity, MediaError> {
        let unix = self.clock.unix_at(now);
        if self.identity.as_ref().is_none_or(|had| had.is_stale(unix)) {
            // a fresh one rather than a refused call: `MediaEngine` is made
            // once and a desk phone runs for months, so a certificate that
            // outlives its own period is the ordinary case rather than a
            // fault
            self.identity = Some(Identity::new(&mut self.keys, unix)?);
        }
        self.identity.as_ref().ok_or(MediaError::DtlsIdentity)
    }

    /// The `a=fingerprint` this end writes into the description it is about
    /// to send and the `a=setup` beside it, or `None` for a call that is not
    /// keyed by a handshake.
    ///
    /// Owned strings rather than a borrow, because the call remembers what it
    /// wrote: [`dtls_role`](sipral_dtls::setup::dtls_role) needs both halves
    /// of the exchange, and only one of them ever arrives from the far end.
    ///
    /// # Errors
    /// As [`MediaEngine::identity`], and [`MediaError::DtlsRole`] for an
    /// offer whose `a=setup` cannot be read.
    #[cfg(feature = "dtls")]
    fn dtls_lines(
        &mut self,
        catalog: &CodecCatalog,
        side: Side,
        offered: Option<&SessionDescription>,
        now: Instant,
    ) -> Result<Option<(String, String)>, MediaError> {
        if !catalog.srtp().wants_dtls() {
            return Ok(None);
        }
        let theirs = offered.and_then(peer_setup);
        let setup = crate::dtls::setup_to_write(side.party(), theirs.as_deref())?;
        let fingerprint = self.identity(now)?.fingerprint().to_owned();
        Ok(Some((fingerprint, setup.name().to_owned())))
    }

    /// Without the feature there is no handshake to describe, and every
    /// description this engine writes is keyed by SDES or not at all.
    #[cfg(not(feature = "dtls"))]
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn dtls_lines(
        &mut self,
        _catalog: &CodecCatalog,
        _side: Side,
        _offered: Option<&SessionDescription>,
        _now: Instant,
    ) -> Result<Option<(String, String)>, MediaError> {
        Ok(None)
    }

    /// The handshake a settled plan calls for, ready to be driven.
    ///
    /// `Ok(None)` for a call not keyed this way, and for one whose peer
    /// answered `holdconn`.
    ///
    /// # Errors
    /// As [`crate::dtls::Handshake::start`], and [`MediaError::DtlsRole`]
    /// when this call has no record of what it wrote — which cannot happen
    /// for a plan that came back keyed by a handshake, since the same
    /// description carried both.
    #[cfg(feature = "dtls")]
    fn handshake_for(
        &mut self,
        call: CallHandle,
        plan: &MediaPlan,
        now: Instant,
    ) -> Result<Option<crate::dtls::Handshake>, MediaError> {
        let Some(keying @ Keying::Dtls { .. }) = plan.keying.as_ref() else {
            return Ok(None);
        };
        let Some((side, ours)) = self
            .calls
            .get(&call)
            .and_then(|managed| managed.dtls.clone())
        else {
            return Err(MediaError::DtlsRole);
        };
        let ours = Setup::parse(&ours).map_err(|_| MediaError::DtlsRole)?;
        // minted first, so that the split borrow below sees a certificate
        // that is already there
        self.identity(now)?;
        let Self { identity, keys, .. } = self;
        let identity = identity.as_ref().ok_or(MediaError::DtlsIdentity)?;
        crate::dtls::Handshake::start(identity, keying, side.party(), ours, keys, now)
    }

    /// A record of the DTLS-SRTP handshake that one call owes the far end,
    /// the call it belongs to, and where it goes.
    ///
    /// One at a time, like every other poll here. **A caller loops until it
    /// answers `None`, after every datagram delivered and at every deadline
    /// [`MediaEngine::poll_timeout`] named.** A handshake that is never
    /// drained is a ClientHello that never leaves, and a call that is up with
    /// no audio, no encryption and no error.
    ///
    /// The octets are copied out rather than lent, for the reason
    /// [`MediaEngine::poll_rtcp`] gives: a handshake is a few datagrams once
    /// per call.
    #[cfg(feature = "dtls")]
    #[must_use]
    pub fn poll_transmit(&mut self) -> Option<(CallHandle, SocketAddr, Vec<u8>)> {
        for (call, held) in &self.sessions {
            let mut slot = share::lock(held);
            if let Some(datagram) = slot.session.poll_transmit() {
                return Some((*call, datagram.destination, datagram.payload.to_vec()));
            }
        }
        None
    }

    /// What this engine offers by default, in the order it offers it — A4's
    /// first half. A call placed or answered with [`MediaEngine::place_with`]
    /// or [`MediaEngine::answer_with`] may be running a different one; see
    /// [`MediaEngine::call_catalog`] for what one specific call is actually
    /// using.
    #[must_use]
    pub const fn catalog(&self) -> &CodecCatalog {
        &self.catalog
    }

    /// What one call is actually offering, once it exists — this engine's
    /// default unless [`MediaEngine::place_with`] or
    /// [`MediaEngine::answer_with`] gave it its own, and that call's own from
    /// then on regardless of what [`MediaEngine::catalog`] becomes
    /// afterwards. `None` for a call this engine has never described anything
    /// for.
    #[must_use]
    pub fn call_catalog(&self, call: CallHandle) -> Option<&CodecCatalog> {
        self.calls.get(&call).map(|managed| &managed.catalog)
    }

    /// D3's flat set of health counters, kept since this engine was created.
    ///
    /// One struct copy: nothing here walks the call table or the session
    /// map, so this is cheap enough to sample on a timer and ship as
    /// telemetry.
    #[must_use]
    pub const fn counters(&self) -> Counters {
        self.counters
    }

    /// One call's media, once there is any, held until the guard is dropped.
    ///
    /// Waits for a thread that is working on the session through a
    /// [`SessionShare`] to finish its frame. `None` as well for a thread that
    /// is already inside this call's session through a share, which would
    /// otherwise wait for itself for ever.
    ///
    /// The guard keeps the engine borrowed exclusively, so nothing else can be
    /// asked of the engine while it is alive: every other way into the engine
    /// may take the same session's lock, and a thread that did so while holding
    /// the guard would be waiting for itself.
    ///
    /// ```compile_fail
    /// fn next_wake(engine: &mut sipral::MediaEngine, call: sipral::CallHandle) {
    ///     let session = engine.session(call);
    ///     let _ = engine.poll_timeout();
    ///     drop(session);
    /// }
    /// ```
    #[must_use]
    pub fn session(&mut self, call: CallHandle) -> Option<SessionGuard<'_>> {
        self.sessions.get(&call).and_then(SessionGuard::of)
    }

    /// A way to one call's media for a thread that does not have this
    /// engine — the one that carries the call's audio, while signalling runs
    /// on another.
    ///
    /// `None` until the negotiation has settled and the session exists. The
    /// share stops reaching the session when the call ends or this engine is
    /// dropped, and a change of codec, a hold or a resume leave it working:
    /// those change the session rather than replace it.
    #[must_use]
    pub fn share(&self, call: CallHandle) -> Option<SessionShare> {
        self.sessions.get(&call).map(SessionShare::of)
    }

    /// The calls that have media running.
    pub fn active(&self) -> impl Iterator<Item = CallHandle> + '_ {
        self.sessions.keys().copied()
    }
}

impl Drop for MediaEngine {
    /// Every session this engine still holds ends with it.
    ///
    /// Two things have to happen here and cannot happen later. A WAVE header
    /// carries two lengths that are only known when a recording stops, so a
    /// recording whose recorder was dropped rather than closed is a file a
    /// player calls corrupt, and this is the last moment anything can patch
    /// them — however the engine goes, including with a stack destroyed from
    /// inside its own event callback. And a [`SessionShare`] handed to a thread
    /// that carries audio has to stop reaching its session once the engine
    /// that ran the call's signalling is gone, including a share already
    /// waiting for the lock while this runs.
    fn drop(&mut self) {
        for held in self.sessions.values() {
            let mut slot = share::lock(held);
            slot.ended = true;
            // there is nobody left to tell, and a failure here means the sink
            // was already refusing the audio it was given
            let _ = slot.session.stop_recording();
        }
    }
}

// -- placing and answering ---------------------------------------------------

impl MediaEngine {
    /// Place a call with an offer in it, offered from this engine's default
    /// catalogue and opened on its default [`MediaConfig`].
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
        let media = CallMedia::new(self.catalog.clone(), self.config.clone());
        self.place_with(agent, account, outgoing, local, media, now)
    }

    /// The same as [`MediaEngine::place`], offering and opening the session
    /// on `media` instead of this engine's defaults.
    ///
    /// D6: what an attended transfer needs. `UserAgent::consult` holds a
    /// second call while the first is still up, and the consultation leg may
    /// have to reach a different codec, a different render delay or a
    /// different device than the call it is standing in for — without moving
    /// what every other call this engine places gets.
    ///
    /// # Errors
    /// [`MediaError::Signalling`] when the user agent refuses the call.
    pub fn place_with(
        &mut self,
        agent: &mut UserAgent,
        account: AccountId,
        outgoing: OutgoingCall,
        local: SocketAddr,
        media: CallMedia,
        now: Instant,
    ) -> Result<CallHandle, MediaError> {
        let CallMedia { catalog, config } = media;
        let (identity, session_id) = draw(agent);
        // drawn after the identity, so that the same call placed with and
        // without SDES starts from the same SSRC and the same sequence number
        let keys = catalog.srtp().offers().then(|| draw_key(&mut self.keys));
        let dtls = self.dtls_lines(&catalog, Side::Offering, None, now)?;
        let offer = write_offer(&catalog, local, session_id, 1, keys, keyed(dtls.as_ref()));
        let dtls = dtls.map(|(_, setup)| (Side::Offering, setup));
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
                catalog,
                config,
                dtls,
                // an outgoing call rings the far end's phone, not this one's
                rung_with_media: false,
            },
        );
        Ok(call)
    }

    /// Take a transfer that was asked for, and place the call it names the
    /// way [`MediaEngine::place`] places one: an offer from this engine's
    /// default catalogue, opened on its default [`MediaConfig`].
    ///
    /// `extra` means what it means on [`UserAgent::accept_transfer`], which
    /// this passes it straight to — a destination other than the account's,
    /// which forks to keep, and header fields of the caller's own, carried
    /// separately from the offer because the target itself is not this
    /// call's to give: `accept_transfer` draws it from the REFER that was
    /// accepted, the same way [`MediaEngine::place`]'s caller draws its own
    /// from a directory.
    ///
    /// The new call is managed exactly as one [`MediaEngine::place`] placed:
    /// its session opens once the 2xx is acknowledged, and
    /// [`MediaEvent::Started`] follows.
    ///
    /// # Errors
    /// [`MediaError::Signalling`] when the user agent refuses the call.
    pub fn accept_transfer(
        &mut self,
        agent: &mut UserAgent,
        call: CallHandle,
        local: SocketAddr,
        extra: OutgoingExtras<'_>,
        now: Instant,
    ) -> Result<CallHandle, MediaError> {
        let media = CallMedia::new(self.catalog.clone(), self.config.clone());
        self.accept_transfer_with(agent, call, local, extra, media, now)
    }

    /// The same as [`MediaEngine::accept_transfer`], offering and opening the
    /// session on `media` instead of this engine's defaults — D6, the same
    /// reason [`MediaEngine::place_with`] takes one.
    ///
    /// # Errors
    /// [`MediaError::Signalling`] when the user agent refuses the call.
    pub fn accept_transfer_with(
        &mut self,
        agent: &mut UserAgent,
        call: CallHandle,
        local: SocketAddr,
        extra: OutgoingExtras<'_>,
        media: CallMedia,
        now: Instant,
    ) -> Result<CallHandle, MediaError> {
        let CallMedia { catalog, config } = media;
        let (identity, session_id) = draw(agent);
        let keys = catalog.srtp().offers().then(|| draw_key(&mut self.keys));
        let dtls = self.dtls_lines(&catalog, Side::Offering, None, now)?;
        let offer = write_offer(&catalog, local, session_id, 1, keys, keyed(dtls.as_ref()));
        let dtls = dtls.map(|(_, setup)| (Side::Offering, setup));
        let new = agent.accept_transfer(call, Some(Arc::from(offer.to_bytes())), extra, now)?;
        self.calls.insert(
            new,
            Managed {
                local: Some(offer),
                remote: None,
                address: Some(local),
                identity,
                session_id,
                version: 1,
                catalog,
                config,
                dtls,
                // an outgoing call rings the far end's phone, not this one's
                rung_with_media: false,
            },
        );
        Ok(new)
    }

    /// Say a call that came in is ringing, with the answer to the offer it
    /// carried written from this call's own catalogue and the session opened
    /// on this engine's default [`MediaConfig`] — before anybody answers.
    ///
    /// # Errors
    /// The same as [`MediaEngine::ring_with`].
    pub fn ring(
        &mut self,
        agent: &mut UserAgent,
        call: CallHandle,
        local: SocketAddr,
        now: Instant,
    ) -> Result<(), MediaError> {
        let catalog = self
            .calls
            .get(&call)
            .ok_or(MediaError::NoSuchCall)?
            .catalog
            .clone();
        let media = CallMedia::new(catalog, self.config.clone());
        self.ring_with(agent, call, local, media, now)
    }

    /// The same as [`MediaEngine::ring`], keeping `media`'s catalogue for this
    /// call from here on and opening the session on `media`'s configuration
    /// instead of this engine's default.
    ///
    /// The session opens the moment this returns, not when the call is later
    /// confirmed: a 183 is never acknowledged the way a 2xx is, so there is no
    /// later event for [`MediaEngine::answer_with`]'s own way of opening one —
    /// off the ACK — to hang on, and the whole point of early media is that
    /// the far end hears it before anybody answers. [`MediaEvent::Started`]
    /// follows here, the same as it does after [`MediaEngine::answer`].
    ///
    /// [`UserAgent::ring`] decides, from the INVITE's own `Require` or
    /// `Supported`, whether the 183 carrying this description goes out
    /// reliably (RFC 3262 §3). That choice is also what decides what a later
    /// [`MediaEngine::answer`] or [`MediaEngine::answer_with`] on this call
    /// may put in the 200 OK (RFC 3262 §5, RFC 6337 §3.1.1): sent reliably,
    /// this description is already the real answer and the 200 OK must not
    /// repeat it; sent unreliably, it was only a preview, and the 200 OK — the
    /// exchange's first reliable non-failure response — still owes the far
    /// end the same answer, unchanged. Either way that later call reuses this
    /// session and this description rather than negotiating a second one: the
    /// same `o=` id and version, described once.
    ///
    /// # Errors
    /// [`MediaError::NoSuchCall`] for a call this engine never saw arrive,
    /// [`MediaError::Signalling`] wrapping [`sipral_ua::UaError::WrongState`]
    /// for a call this has already been called on — once is all a call gets,
    /// though a plain [`UserAgent::ring`] with no description first is no
    /// obstacle — and the same for a call whose provisional response already
    /// carried a description [`UserAgent::ring`] was handed, since RFC 3261
    /// §13.2.1 allows only "that same exact answer" in any response after it,
    /// [`MediaError::NoDescription`] for an INVITE that carried no
    /// offer, since the offer this end would make instead belongs in no
    /// provisional response this engine can follow up (RFC 3261 §13.2.1,
    /// RFC 6337 §3.1.2), [`MediaError::Description`] when the answer cannot be
    /// built, [`MediaError::SrtpRequired`] when `media`'s catalogue requires
    /// SRTP and the INVITE offered a stream that cannot carry it, and
    /// [`MediaError::Signalling`] for whatever else the user agent refuses to
    /// send it over.
    pub fn ring_with(
        &mut self,
        agent: &mut UserAgent,
        call: CallHandle,
        local: SocketAddr,
        media: CallMedia,
        now: Instant,
    ) -> Result<(), MediaError> {
        let CallMedia { catalog, config } = media;
        let managed = self.calls.get(&call).ok_or(MediaError::NoSuchCall)?;
        if managed.rung_with_media || agent.has_described(call) {
            let state = agent.call_state(call).unwrap_or(CallState::EarlyMedia);
            return Err(MediaError::from(UaError::WrongState(state)));
        }
        let (session_id, version) = (managed.session_id, managed.version);
        // an INVITE with no offer leaves this end to make one, and RFC 3261
        // §13.2.1 puts it in "the first reliable non-failure message" while
        // RFC 6337 §3.1.2 keeps it out of every other response; sent reliably,
        // the answer to it comes back in the PRACK (RFC 3262 §5), and nothing
        // hands a PRACK's body to this engine
        let Some(offer) = managed.remote.clone() else {
            return Err(MediaError::NoDescription);
        };
        if !keying_allows(&catalog, Some(&offer)) {
            return Err(MediaError::SrtpRequired);
        }
        let keys = will_key(&catalog, Some(&offer)).then(|| draw_key(&mut self.keys));
        let dtls = self.dtls_lines(&catalog, Side::Answering, Some(&offer), now)?;
        let description = write_answer(
            &catalog,
            &offer,
            local,
            session_id,
            version,
            keys.as_ref(),
            keyed(dtls.as_ref()),
        )?;
        let bytes = description.to_bytes();
        agent.ring(call, Some(Arc::from(bytes)), now)?;
        if let Some(managed) = self.calls.get_mut(&call) {
            managed.local = Some(description);
            managed.address = Some(local);
            managed.version = version;
            managed.catalog = catalog;
            managed.config = config;
            managed.dtls = dtls.map(|(_, setup)| (Side::Answering, setup));
            managed.rung_with_media = true;
        }
        // no event tells this engine when a 183 has gone out the way
        // `UaEvent::CallConfirmed` tells `answer_with` when a 2xx has, so
        // this is the one call in this module that settles a call itself
        // rather than waiting to be told to
        self.settle(call, now);
        Ok(())
    }

    /// Answer a call that came in, with the answer to the offer it carried,
    /// kept to what this call has already recorded as its catalogue, and
    /// opened on this engine's default [`MediaConfig`].
    ///
    /// # Errors
    /// [`MediaError::NoSuchCall`] for a call this engine never saw arrive,
    /// [`MediaError::Description`] when the answer cannot be built,
    /// [`MediaError::SrtpRequired`] when this call requires SRTP and the
    /// INVITE offered a stream that cannot carry it, and
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
        let catalog = self
            .calls
            .get(&call)
            .ok_or(MediaError::NoSuchCall)?
            .catalog
            .clone();
        let media = CallMedia::new(catalog, self.config.clone());
        self.answer_with(agent, call, local, media, now)
    }

    /// The same as [`MediaEngine::answer`], keeping `media`'s catalogue for
    /// this call from here on and opening the session on `media`'s
    /// configuration instead of this engine's default.
    ///
    /// # Errors
    /// The same as [`MediaEngine::answer`], plus [`MediaError::SrtpRequired`]
    /// when the catalogue is set to [`SrtpPolicy::Required`] and the INVITE
    /// offered a stream that cannot be keyed. Nothing is sent in that case:
    /// the call is still ringing, and rejecting it with a status code of the
    /// application's choosing is the next move.
    ///
    /// For a call [`MediaEngine::ring_with`] already described, `local` and
    /// `media` are not read: there is no second negotiation, and reusing that
    /// session and that description is the whole point. What the 200 OK
    /// carries then is decided by how the 183 went out, not by anything
    /// passed here — see [`MediaEngine::ring_with`].
    pub fn answer_with(
        &mut self,
        agent: &mut UserAgent,
        call: CallHandle,
        local: SocketAddr,
        media: CallMedia,
        now: Instant,
    ) -> Result<(), MediaError> {
        let managed = self.calls.get(&call).ok_or(MediaError::NoSuchCall)?;
        if managed.rung_with_media {
            return self.answer_after_ring(agent, call, now);
        }
        let CallMedia { catalog, config } = media;
        let managed = self.calls.get(&call).ok_or(MediaError::NoSuchCall)?;
        let (session_id, version) = (managed.session_id, managed.version.saturating_add(1));
        let offered = managed.remote.clone();
        if !keying_allows(&catalog, offered.as_ref()) {
            return Err(MediaError::SrtpRequired);
        }
        let keys = will_key(&catalog, offered.as_ref()).then(|| draw_key(&mut self.keys));
        // an INVITE with no offer leaves this end offering, so which side it
        // is on is decided by what arrived rather than by which method was
        // called
        let side = if offered.is_some() {
            Side::Answering
        } else {
            Side::Offering
        };
        let dtls = self.dtls_lines(&catalog, side, offered.as_ref(), now)?;
        let description = match offered {
            Some(offer) => write_answer(
                &catalog,
                &offer,
                local,
                session_id,
                version,
                keys.as_ref(),
                keyed(dtls.as_ref()),
            )?,
            None => write_offer(
                &catalog,
                local,
                session_id,
                version,
                keys,
                keyed(dtls.as_ref()),
            ),
        };
        let bytes = description.to_bytes();
        agent.answer(call, Some(Arc::from(bytes)), now)?;
        if let Some(managed) = self.calls.get_mut(&call) {
            managed.local = Some(description);
            managed.address = Some(local);
            managed.version = version;
            managed.catalog = catalog;
            managed.config = config;
            managed.dtls = dtls.map(|(_, setup)| (side, setup));
        }
        Ok(())
    }

    /// The 200 OK for a call [`MediaEngine::ring_with`] already described: no
    /// new description is written, no new session opened — the session
    /// `ring_with` opened is still the one running, on the same `o=` id and
    /// version it opened with.
    ///
    /// What goes in the body is RFC 3262 §5 and RFC 6337 §3.1.1's rule, and
    /// [`UserAgent::reliably`] is the one fact it turns on: the 183 sent
    /// reliably already carried the real answer, and nothing after it may
    /// repeat it (RFC 6337 §3.1.1, UAS behaviour #2); sent unreliably, that
    /// description was only a preview, and the 2xx — the exchange's first
    /// reliable non-failure response — still owes the far end the same
    /// answer, unchanged (§3.1.1, UAS behaviour #1: every SDP in a response to
    /// one INVITE has to be identical). Either way [`UserAgent::answer`]
    /// itself still holds the 2xx for an unacknowledged reliable provisional
    /// (RFC 3262 §5) — this passes it what to send once that gate opens, not
    /// whether to.
    fn answer_after_ring(
        &mut self,
        agent: &mut UserAgent,
        call: CallHandle,
        now: Instant,
    ) -> Result<(), MediaError> {
        let repeated = if agent.reliably(call) {
            None
        } else {
            self.calls
                .get(&call)
                .and_then(|managed| managed.local.as_ref())
                .map(|description| Arc::from(description.to_bytes()))
        };
        agent.answer(call, repeated, now)?;
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
            self.counters.observe_media(&event);
            return Some(Event::Media { call, event });
        }
        if let Some((call, event)) = self.session_event() {
            self.counters.observe_media(&event);
            return Some(Event::Media { call, event });
        }
        let signalling = agent.poll_event()?;
        self.counters.observe_signalling(&signalling);
        self.absorb(&signalling, agent, now);
        // folded into a media event by `absorb`, above, rather than forwarded
        // as this one: the next turn of this same loop returns what that just
        // queued, since the media checks at the top of this function run
        // before the signalling drain does
        if matches!(signalling, UaEvent::DtmfReceived { .. }) {
            return self.poll_event(agent, now);
        }
        Some(Event::Signalling(signalling))
    }

    /// Time has passed: every session's stall watchdog gets a look.
    ///
    /// One session at a time, each for as long as a look takes, so a thread
    /// in the middle of a frame on one call holds this up by that frame and
    /// holds up no other call's.
    pub fn handle_timeout(&mut self, now: Instant) {
        for held in self.sessions.values() {
            share::lock(held).session.handle_timeout(now);
        }
    }

    /// When to call [`MediaEngine::handle_timeout`] or
    /// [`MediaEngine::poll_rtcp`], if nothing arrives first.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.sessions
            .values()
            .filter_map(|held| share::lock(held).session.poll_timeout())
            .min()
    }

    /// The RTCP goodbye of a call that has ended (RFC 3550 §6.6).
    ///
    /// Separate from [`MediaEngine::poll_rtcp`] because by the time there is
    /// one to send there is no session left to ask: a call that ends is taken
    /// out of the engine in the same breath as the event that reports it, and
    /// a packet held in a session that no longer exists is a packet nobody can
    /// reach. So it is copied out at that moment and waits here.
    ///
    /// The handle it comes with names a call that has already ended. It is
    /// there so an application that keeps its own sockets per call knows which
    /// one to send from, not because anything else can still be done with it.
    ///
    /// One at a time, like every other poll here. A caller loops until it
    /// answers `None`, and should do so after draining events — a goodbye that
    /// is never polled is a far end left waiting out its own timeout.
    #[must_use]
    pub fn poll_farewell(&mut self) -> Option<(CallHandle, SocketAddr, Vec<u8>)> {
        self.farewells.pop_front()
    }

    /// A control datagram that is due, the call to send it for, and where it
    /// goes.
    ///
    /// One at a time, like every other poll here. A caller loops until it
    /// answers `None`.
    ///
    /// The octets are copied out rather than lent, because they are written
    /// into the session's own buffer and the session is only held for as long
    /// as this call runs. A report is due a few times a minute per call, so
    /// the copy costs nothing the audio path would notice; a thread that
    /// carries one call's audio can ask that call alone with
    /// [`MediaSession::poll_rtcp`] through a [`SessionShare`] instead.
    #[must_use]
    pub fn poll_rtcp(&mut self, now: Instant) -> Option<(CallHandle, SocketAddr, Vec<u8>)> {
        for (call, held) in &self.sessions {
            let mut slot = share::lock(held);
            if !slot.session.rtcp_deadline_passed(now) {
                continue;
            }
            return slot
                .session
                .poll_rtcp(now)
                .map(|datagram| (*call, datagram.destination, datagram.payload.to_vec()));
        }
        None
    }

    /// The first event any session has to report.
    fn session_event(&self) -> Option<(CallHandle, MediaEvent)> {
        for (call, held) in &self.sessions {
            if let Some(event) = share::lock(held).session.poll_event() {
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
            UaEvent::DtmfReceived {
                call,
                digit,
                held_ms,
            } => self.dtmf_received(*call, *digit, *held_ms),
            _ => {}
        }
    }

    /// A digit arrived by SIP INFO. Folded into the same
    /// [`MediaEvent::DigitReceived`] the media reports RFC 4733 events with —
    /// `crate::event`'s own module doc says why — rather than forwarded as
    /// its own [`UaEvent`].
    fn dtmf_received(&mut self, call: CallHandle, digit: char, held_ms: Option<u32>) {
        // an INFO's digit always names one of the sixteen keys RFC 4733
        // §3.2 does too, because `sipral_ua`'s own parser refused anything
        // else before this ever arrived; the fallback exists so this reads
        // an event code rather than reaching for one it cannot get
        let event = Digit::from_char(digit).map_or(0, Digit::event);
        self.events.push_back((
            call,
            MediaEvent::DigitReceived {
                digit: Some(digit),
                event,
                held: held_ms.map(|ms| Duration::from_millis(u64::from(ms))),
                source: DigitSource::Info,
            },
        ));
    }
}

// -- what each event does ----------------------------------------------------

impl MediaEngine {
    /// A call came in: keep whatever offer it carried, and mint the numbers
    /// its stream will start from.
    ///
    /// This engine's default catalogue and configuration are recorded for the
    /// call now, before the application has had a chance to say anything
    /// about it — [`MediaEngine::answer_with`] replaces them for this call
    /// alone when it is asked to.
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
                catalog: self.catalog.clone(),
                config: self.config.clone(),
                // nothing has been written for this call yet: what it will
                // say about DTLS-SRTP is decided when it is rung or answered
                dtls: None,
                rung_with_media: false,
            },
        );
    }

    /// A proxy forked the INVITE: the new branch was offered exactly what the
    /// old one was, so it inherits the description and gets a stream of its
    /// own to start from — the catalogue and configuration included, since a
    /// fork is the same call reaching two destinations, not two calls that
    /// happen to have started together.
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
        let catalog = managed.catalog.clone();
        // a live call that required SRTP and is re-offered a stream without
        // it is where a silent downgrade would happen, so it is where the
        // refusal has to be
        if !keying_allows(&catalog, Some(&offer)) {
            self.events
                .push_back((call, MediaEvent::Failed(MediaError::SrtpRequired)));
            let _ = agent.reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
            return;
        }
        let keys = will_key(&catalog, Some(&offer)).then(|| draw_key(&mut self.keys));
        let dtls = match self.dtls_lines(&catalog, Side::Answering, Some(&offer), now) {
            Ok(lines) => lines,
            Err(error) => {
                self.events.push_back((call, MediaEvent::Failed(error)));
                let _ = agent.reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
                return;
            }
        };
        match write_answer(
            &catalog,
            &offer,
            address,
            session_id,
            version,
            keys.as_ref(),
            keyed(dtls.as_ref()),
        ) {
            Ok(answer) => {
                let bytes = answer.to_bytes();
                if agent.accept_reoffer(call, Some(&bytes), now).is_ok()
                    && let Some(managed) = self.calls.get_mut(&call)
                {
                    managed.version = version;
                    managed.dtls = dtls.map(|(_, setup)| (Side::Answering, setup));
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
        let Some(held) = self.sessions.remove(&call) else {
            return;
        };
        let mut slot = share::lock(&held);
        // first, and under the lock: a share that was already waiting for it
        // finds a call that has ended rather than a stream half taken apart,
        // and cannot put a frame on the wire after the goodbye below
        slot.ended = true;
        let session = &mut slot.session;
        // a recording that is not closed here is a file with zeroes where its
        // two lengths should be
        if let Err(error) = session.stop_recording()
            && !matches!(error, MediaError::NotRecording)
        {
            self.events.push_back((call, MediaEvent::Failed(error)));
        }
        // RFC 3550 §6.6: "If a BYE packet is received ... the participant
        // SHOULD be removed". Saying so is the last thing this stream owes the
        // far end, and the only moment it can: the session is already out of
        // the map and marked ended, so nothing an application does afterwards
        // can reach it. It is freed when the last reference to it goes, which
        // is at the end of this function unless a share is mid-frame on it.
        if let Some(datagram) = session.goodbye(now) {
            self.farewells
                .push_back((call, datagram.destination, datagram.payload.to_vec()));
        }
        // and the same courtesy to the far end's DTLS stack. It comes after
        // the BYE because a stream that never keyed has no BYE to send —
        // `send_bye` refuses to write one in the clear — and this is then the
        // only thing that tells the peer to stop retransmitting.
        #[cfg(feature = "dtls")]
        {
            session.close_handshake();
            while let Some(datagram) = session.poll_transmit() {
                self.farewells
                    .push_back((call, datagram.destination, datagram.payload.to_vec()));
            }
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
        if let Err(error) = keying_holds(&managed.catalog, &plan, remote) {
            self.fail(call, error);
            return;
        }
        let codec = match Codec::of_plan(&plan) {
            Ok(codec) => codec,
            Err(error) => {
                self.fail(call, error);
                return;
            }
        };
        // D5: recorded here, at the point the negotiation is worked out, from
        // the far end's own description and this call's own catalogue —
        // never reconstructed later from state that may have moved on
        let candidates = remote
            .media
            .first()
            .map_or_else(Vec::new, |stream| managed.catalog.candidates(stream, codec));
        let running = self.sessions.get(&call).map(Arc::clone);
        if let Some(held) = running {
            let mut slot = share::lock(&held);
            // the same codec on a session that is already running: a hold, a
            // resume, or a peer that moved its address — but settle is also
            // reached from events that carry no new information at all, an
            // ACK with no body chief among them, and a plan identical to the
            // one already running is not a change to report
            if slot.session.codec() == codec {
                let unchanged = *slot.session.plan() == plan;
                let adopted = slot.session.adopt(&plan, candidates, now);
                drop(slot);
                match adopted {
                    Ok(()) if unchanged => {}
                    Ok(()) => self.events.push_back((
                        call,
                        MediaEvent::Changed {
                            codec,
                            direction: plan.direction,
                        },
                    )),
                    // a fresh crypto line this build cannot open: the session
                    // is still running on the keys it had, and the call is
                    // told rather than left to wonder why nothing arrives
                    Err(error) => self.fail(call, error),
                }
                return;
            }
        }
        // a different codec needs a different encoder, a different decoder
        // and a different frame length, so it needs a different session
        self.start(call, &plan, codec, candidates, now);
    }

    /// Open the stream for a plan, or carry the one that is running onto a
    /// codec the negotiation has moved to.
    ///
    /// A session already on this call is re-formatted rather than replaced, so
    /// that the stream, its SRTP contexts and everything the call has
    /// accumulated survive a codec change. [`MediaSession::reformat`] says
    /// what that is and why each piece of it matters.
    fn start(
        &mut self,
        call: CallHandle,
        plan: &MediaPlan,
        codec: Codec,
        candidates: Vec<CodecCandidate>,
        now: Instant,
    ) {
        let Some(managed) = self.calls.get(&call) else {
            return;
        };
        let frame_length = managed.catalog.frame_length();
        let config = managed.config.clone();
        let identity = managed.identity;
        let running = self.sessions.get(&call).map(Arc::clone);
        let replacing = running.is_some();
        let outcome = match running {
            Some(held) => {
                let mut slot = share::lock(&held);
                slot.session
                    .reformat(plan, frame_length, &config, candidates, now)
            }
            None => {
                #[cfg(feature = "dtls")]
                let handshake = match self.handshake_for(call, plan, now) {
                    Ok(handshake) => handshake,
                    Err(error) => {
                        self.fail(call, error);
                        return;
                    }
                };
                MediaSession::open(
                    plan,
                    frame_length,
                    &config,
                    candidates,
                    Start {
                        identity,
                        clock: self.clock,
                        #[cfg(feature = "dtls")]
                        handshake,
                        now,
                    },
                )
            }
            .map(|session| {
                self.sessions.insert(call, share::hold(session));
            }),
        };
        match outcome {
            Ok(()) => {
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

/// The borrowed form the description writers take, from the owned pair the
/// engine keeps.
#[cfg(feature = "dtls")]
fn keyed(lines: Option<&(String, String)>) -> Option<Keyed<'_>> {
    lines.map(|(fingerprint, setup)| Keyed { fingerprint, setup })
}

/// Without the feature nothing is ever keyed by a handshake, and the writers
/// still name the type.
#[cfg(not(feature = "dtls"))]
#[allow(clippy::needless_pass_by_value)]
const fn keyed(_lines: Option<&(String, String)>) -> Option<Keyed<'static>> {
    None
}

/// Which side of an offer/answer exchange this end is writing.
///
/// Known here and nowhere below, and it has to be: RFC 4145 §4.1 reads the
/// pair of `a=setup` values as a table, and which row a value is on depends
/// on whether it was written in the offer or in the answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    /// This end is writing the offer.
    Offering,
    /// This end is writing the answer to one that arrived.
    Answering,
}

#[cfg(feature = "dtls")]
impl Side {
    const fn party(self) -> Party {
        match self {
            Self::Offering => Party::Offerer,
            Self::Answering => Party::Answerer,
        }
    }
}

/// The `a=setup` an offer carried, at media level or, as RFC 4566 §5.13 lets
/// a media-level attribute override, at session level.
#[cfg(feature = "dtls")]
fn peer_setup(offer: &SessionDescription) -> Option<String> {
    offer
        .media
        .first()
        .and_then(|stream| stream.attribute("setup"))
        .or_else(|| offer.attribute("setup"))?
        .value
        .clone()
}

// -- writing descriptions -----------------------------------------------------
//
// Free functions rather than methods, because D6 made the catalogue a
// property of the call rather than of the engine: what these write depends on
// which catalogue a caller hands them, and a method on `MediaEngine` would
// have made `self.catalog` too easy to reach for by habit where a call's own
// belongs instead.

/// The offer `catalog` makes, for media arriving at `address`, keyed with
/// `keys` where the catalogue offers SDES.
fn write_offer(
    catalog: &CodecCatalog,
    address: SocketAddr,
    session_id: u64,
    version: u64,
    keys: Option<KeySalt>,
    dtls: Option<Keyed<'_>>,
) -> SessionDescription {
    let mut description = SessionDescription::new(
        Origin::new(session_id, version, address.ip()),
        Connection::new(address.ip()),
    );
    description.media.push(catalog.offering(keys, dtls).offer(
        AUDIO,
        address.port(),
        Direction::SendRecv,
    ));
    description
}

/// Whether this call will let a stream described like this carry audio.
///
/// The one place [`SrtpPolicy::Offered`] and [`SrtpPolicy::Required`] differ:
/// an offer that named no secure profile is answered plainly under the first
/// and not answered at all under the second. An INVITE that carried no offer
/// is answered with one of ours, which carries a key, so it passes either
/// way.
fn keying_allows(catalog: &CodecCatalog, offered: Option<&SessionDescription>) -> bool {
    !catalog.srtp().requires() || offered.is_none_or(any_secure_stream)
}

/// Whether the description this end is about to write will carry a key: it
/// offers one, or it answers an offer that asked for one.
fn will_key(catalog: &CodecCatalog, offered: Option<&SessionDescription>) -> bool {
    catalog.srtp().offers() || offered.is_some_and(any_secure_stream)
}

/// Whether any live stream of a description is on one of the secure profiles.
fn any_secure_stream(description: &SessionDescription) -> bool {
    description
        .media
        .iter()
        .any(|stream| !stream.is_rejected() && keying::is_secure(&stream.proto))
}

/// Whether the keys a plan settled on are ones this call will run with.
///
/// Two questions the plan cannot answer on its own. Whether an unkeyed stream
/// is allowed at all is this call's policy and not the negotiation's, and
/// whether the peer's line carries a session parameter that has to be
/// honoured has to be read off the description, because `sipral-core`'s
/// parser drops a parameter it does not recognise rather than invalidating
/// the line RFC 4568 §6.3.7 says it must.
fn keying_holds(
    catalog: &CodecCatalog,
    plan: &MediaPlan,
    remote: &SessionDescription,
) -> Result<(), MediaError> {
    match &plan.keying {
        None if catalog.srtp().requires() => Err(MediaError::SrtpRequired),
        // a policy that named a way to key is not answered with the other
        // way. `DtlsRequired` exists because the key must not travel in the
        // body of a message, and an answer carrying `a=crypto` has put it
        // there; `Required` is the mirror of it, and a peer that answered a
        // `RTP/SAVP` offer with a fingerprint has answered something this
        // call did not ask for.
        #[cfg(feature = "dtls")]
        Some(Keying::Sdes { .. }) if catalog.srtp() == SrtpPolicy::DtlsRequired => {
            Err(MediaError::SrtpRequired)
        }
        #[cfg(feature = "dtls")]
        Some(Keying::Dtls { .. }) if catalog.srtp() == SrtpPolicy::Required => {
            Err(MediaError::SrtpRequired)
        }
        // RFC 5764 §4.2: with RTP and RTCP on separate ports there are two
        // DTLS-SRTP associations, one per port. This stack runs one, on the
        // media port, so a call that did not agree to multiplex its control
        // traffic is refused rather than opened with an SRTCP half nothing
        // will ever key. The offer asks for `a=rtcp-mux` whenever the policy
        // is a DTLS one, so this is a peer that took the attribute out.
        #[cfg(feature = "dtls")]
        Some(Keying::Dtls { .. }) if matches!(plan.rtcp, RtcpPlan::SeparatePort { .. }) => {
            Err(MediaError::DtlsNeedsRtcpMux)
        }
        Some(Keying::Sdes { remote: theirs, .. })
            if !remote
                .media
                .first()
                .is_some_and(|stream| keying::peer_line_holds(stream, theirs.tag)) =>
        {
            Err(MediaError::UnusableKeying)
        }
        _ => Ok(()),
    }
}

/// The answer to an offer that arrived, kept to what `catalog` holds.
///
/// One stream is taken and every other is refused, whatever it is. This
/// end has one media address, and a second audio stream would need a
/// second one; RFC 3264 §6 wants the refusal written as a port of zero in
/// the same position rather than a stream left out, which is what
/// [`StreamAnswer::Reject`] produces.
fn write_answer(
    catalog: &CodecCatalog,
    offer: &SessionDescription,
    address: SocketAddr,
    session_id: u64,
    version: u64,
    keys: Option<&KeySalt>,
    dtls: Option<Keyed<'_>>,
) -> Result<SessionDescription, MediaError> {
    let mut taken = false;
    let streams: Vec<StreamAnswer> = offer
        .media
        .iter()
        .map(|offered| {
            if taken {
                return StreamAnswer::Reject;
            }
            let answer = take_stream(catalog, offered, address, keys, dtls);
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

/// What to do with one offered stream, kept to what `catalog` holds.
fn take_stream(
    catalog: &CodecCatalog,
    offered: &MediaDescription,
    address: SocketAddr,
    keys: Option<&KeySalt>,
    #[cfg_attr(not(feature = "dtls"), allow(unused_variables))] dtls: Option<Keyed<'_>>,
) -> StreamAnswer {
    if offered.media != AUDIO || offered.is_rejected() {
        return StreamAnswer::Reject;
    }
    let (formats, any_codec) = keepable(catalog, offered);
    if !any_codec {
        return StreamAnswer::Reject;
    }
    // an offer keyed by a handshake is answered by naming this end's own
    // certificate and the role it will take, and never by a crypto line: the
    // two are different key management protocols and a description carrying
    // both has agreed to neither
    #[cfg(feature = "dtls")]
    let handshake = dtls.filter(|_| keying::is_secure(&offered.proto));
    #[cfg(not(feature = "dtls"))]
    let handshake: Option<Keyed<'_>> = None;
    // RFC 4568 §7.1.2: a stream on the secure profile is answered by
    // accepting exactly one of its crypto lines, or it is refused. There is
    // no third answer, and a stream taken without a key would be one both
    // ends believe is encrypted
    let crypto = if keying::is_secure(&offered.proto) && handshake.is_none() {
        match (keying::acceptable(offered), keys) {
            (Some(line), Some(keys)) => Some(keying::answer_line(&line, keys.clone())),
            _ => return StreamAnswer::Reject,
        }
    } else {
        None
    };
    let names: Vec<&str> = formats.iter().map(String::as_str).collect();
    let mut accepted = AcceptedStream::in_offer_order(address.port(), offered, &names)
        .with_direction(Direction::SendRecv);
    // RFC 5761 §5.1.1: multiplexing happens only where both ends asked for
    // it, so the answer says so only if the offer did and this catalogue
    // wants it — or if this answer is keyed by a handshake, since RFC 5764
    // §4.2 would otherwise need a second one on the RTCP port
    if (catalog.capabilities().rtcp_mux || handshake.is_some()) && offered.has_rtcp_mux() {
        accepted = accepted.with_attribute(Attribute::flag("rtcp-mux"));
    }
    if let Some(line) = crypto {
        accepted = accepted.with_attribute(line.attribute());
    }
    #[cfg(feature = "dtls")]
    if let Some(keyed) = handshake {
        accepted = accepted
            .with_attribute(Attribute::with_value("fingerprint", keyed.fingerprint))
            .with_attribute(Attribute::with_value("setup", keyed.setup));
    }
    StreamAnswer::Accept(accepted)
}

/// The formats of an offer `catalog` would keep, and whether any of them is a
/// codec.
///
/// The numbers are the offer's own, which is the whole reason this is not
/// a comparison against our own payload types: a dynamic type means
/// whatever the offer's `a=rtpmap` called it, and a peer that numbers Opus
/// 111 has said the same thing we say with 96.
fn keepable(catalog: &CodecCatalog, offered: &MediaDescription) -> (Vec<String>, bool) {
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
            if catalog.capabilities().dtmf {
                formats.push(format.clone());
            }
            continue;
        }
        if named.is_encoding(COMFORT_NOISE) {
            formats.push(format.clone());
            continue;
        }
        if Codec::of(&named).is_some_and(|codec| catalog.codecs().contains(&codec)) {
            formats.push(format.clone());
            any_codec = true;
        }
    }
    (formats, any_codec)
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
        // RFC 4568 §6.4 asks a secured stream to start below 2^15, so that a
        // run of losses at the very start cannot leave the two ends
        // disagreeing about the rollover counter — "unless all the first 2^15
        // packets are lost". It costs one bit of a number that only has to be
        // unpredictable, and it is spent on every stream rather than on the
        // ones that turn out to be keyed, because this is drawn before
        // anybody has negotiated anything
        sequence: u16::try_from(hex(&token, 16, 4)).unwrap_or(0) & 0x7fff,
        timestamp: u32::try_from(hex(&token, 8, 8)).unwrap_or(0),
        seed: hex(&token, 20, 12),
    };
    (identity, hex(&token, 0, 16))
}

/// The master key and salt for one description, out of the engine's own seed.
///
/// Its own and not the endpoint's, which is the whole point: the endpoint's
/// seed is written in clear into every replay recording, so a recording made
/// from a stack that shared one generator would carry the means to derive
/// every key that stack had ever offered and every key it ever would.
///
/// One block of `SHA-256(media seed || counter)` covers both halves — thirty
/// of its thirty-two bytes — and the counter never repeats, which is what
/// RFC 4568 §7.1.2 needs when it says "the master key(s) in the answer MUST
/// be different from those in the offer". **What a poor media seed costs is
/// the whole of the encryption**, and it costs it silently: SDES then
/// protects the media against nobody while every message still looks right.
///
/// The block, and the key and salt sliced from it, live in [`Zeroizing`]
/// rather than a plain array (8.2.9). A buffer that is merely dropped is a
/// buffer that stays on the stack for whatever runs next; `Zeroizing` wipes
/// its bytes in its own `Drop`, which a later edit to this function cannot
/// silently stop doing the way it could stop a `fill(0)` written by hand.
///
/// Both halves are copied out a byte at a time rather than sliced, because
/// this is the one function in the tree where reading past the end must not
/// be recoverable: a fallible slice with a zero-filled fallback would hand
/// out a key of zeros, and the paragraph above is about exactly how quiet
/// that failure is. The assertion beside it holds the two lengths to the
/// block, so a later change to either one stops the build rather than
/// shortening a key.
const _: () = assert!(
    MASTER_KEY + MASTER_SALT <= 32,
    "the key and the salt come out of one thirty-two byte block"
);

fn draw_key(keys: &mut KeySource) -> KeySalt {
    let block = Zeroizing::new(keys.block());
    let mut key = Zeroizing::new([0_u8; MASTER_KEY]);
    let mut salt = Zeroizing::new([0_u8; MASTER_SALT]);
    for (slot, byte) in key.iter_mut().zip(block.iter()) {
        *slot = *byte;
    }
    for (slot, byte) in salt.iter_mut().zip(block.iter().skip(MASTER_KEY)) {
        *slot = *byte;
    }
    KeySalt::new(*key, *salt)
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

// -- the two guards a two-stack harness cannot reach -------------------------

#[cfg(test)]
mod keying_guards {
    //! [`keying_allows`] and [`keying_holds`] are both about a description
    //! this end would never write, so `crates/sipral/src/tests.rs`'s pair of
    //! real stacks can only get at one of the four branches: the other end of
    //! that harness is this same engine, and it does not write a `RTP/SAVP`
    //! line with a session parameter nobody knows, or answer a plain offer to
    //! a call that required keys. They are exercised here instead, against
    //! descriptions written by hand the way a peer would write them.

    use sipral_core::sdp::{
        CryptoPolicy, CryptoSuite, Direction, KeySalt, Keying, MediaPlan, NegotiatedCodec,
        RtcpPlan, RtpMap, SessionDescription, parse,
    };

    use super::{keying_allows, keying_holds};
    use crate::codec::CodecCatalog;
    use crate::error::MediaError;
    use crate::keying::SrtpPolicy;

    const KEY: &str = "inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn described(stream: &str) -> SessionDescription {
        let text = format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n{stream}"
        );
        parse(text.as_bytes()).expect("the description parses")
    }

    fn plan(keying: Option<Keying>) -> MediaPlan {
        MediaPlan {
            local: "192.0.2.1:40000".parse().expect("an address"),
            remote: "192.0.2.2:40002".parse().expect("an address"),
            codec: NegotiatedCodec::new(RtpMap {
                payload: 0,
                encoding: "PCMU".to_owned(),
                clock_rate: 8_000,
                parameters: None,
            }),
            direction: Direction::SendRecv,
            dtmf: None,
            rtcp: RtcpPlan::Off,
            keying,
        }
    }

    /// RFC 5764 §4.2: with RTP and RTCP on separate ports there are two
    /// DTLS-SRTP associations, one per port, and this stack runs one. An
    /// offer under a DTLS policy always asks for `a=rtcp-mux`, so a plan that
    /// comes back without it is a peer that took the attribute out — and
    /// opening the stream anyway would leave its SRTCP half keyed by nothing,
    /// which reads from the outside as a call whose reports simply never
    /// arrive.
    #[cfg(feature = "dtls")]
    #[test]
    fn a_dtls_call_whose_peer_took_the_multiplexing_out_is_refused_by_name() {
        let catalog = CodecCatalog::new().with_srtp(SrtpPolicy::DtlsOffered);
        let theirs = described(
            "m=audio 40002 UDP/TLS/RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
             a=fingerprint:sha-256 AA:BB\r\na=setup:active\r\n",
        );
        let keyed = || {
            Some(Keying::Dtls {
                fingerprints: vec!["sha-256 AA:BB".to_owned()],
                setup: Some("active".to_owned()),
            })
        };

        let mut muxed = plan(keyed());
        muxed.rtcp = RtcpPlan::Muxed;
        assert!(keying_holds(&catalog, &muxed, &theirs).is_ok());

        let mut split = plan(keyed());
        split.rtcp = RtcpPlan::SeparatePort {
            local: "192.0.2.1:40001".parse().expect("an address"),
            remote: "192.0.2.2:40003".parse().expect("an address"),
        };
        assert_eq!(
            keying_holds(&catalog, &split, &theirs),
            Err(MediaError::DtlsNeedsRtcpMux)
        );

        // and a call with no RTCP at all is not a call with RTCP somewhere
        // else: one association covers everything there is
        assert!(keying_holds(&catalog, &plan(keyed()), &theirs).is_ok());
    }

    /// The other half of the same rule: a policy that named one way to key is
    /// not answered with the other. Both refusals exist because the key
    /// travelling in a body is exactly what `DtlsRequired` was chosen to
    /// avoid, and a fingerprint is exactly what `Required` did not ask for.
    #[cfg(feature = "dtls")]
    #[test]
    fn a_policy_that_named_one_way_to_key_refuses_the_other() {
        let sdes = Some(Keying::Sdes {
            local: sipral_core::sdp::CryptoPolicy::new(
                1,
                sipral_core::sdp::CryptoSuite::AesCm80,
                KeySalt::new([1; 16], [2; 14]),
            ),
            remote: sipral_core::sdp::CryptoPolicy::new(
                1,
                sipral_core::sdp::CryptoSuite::AesCm80,
                KeySalt::new([3; 16], [4; 14]),
            ),
        });
        let handshake = Some(Keying::Dtls {
            fingerprints: vec!["sha-256 AA:BB".to_owned()],
            setup: Some("active".to_owned()),
        });
        let anything = described("m=audio 40002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n");

        assert_eq!(
            keying_holds(
                &CodecCatalog::new().with_srtp(SrtpPolicy::DtlsRequired),
                &plan(sdes),
                &anything
            ),
            Err(MediaError::SrtpRequired)
        );
        assert_eq!(
            keying_holds(
                &CodecCatalog::new().with_srtp(SrtpPolicy::Required),
                &plan(handshake),
                &anything
            ),
            Err(MediaError::SrtpRequired)
        );
    }

    #[test]
    fn a_call_that_requires_keys_answers_only_a_description_that_can_carry_them() {
        let required = CodecCatalog::new().with_srtp(SrtpPolicy::Required);
        let optional = CodecCatalog::new().with_srtp(SrtpPolicy::Offered);
        let plain = described("m=audio 40002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n");
        let secure = described(
            "m=audio 40002 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\r\n",
        );

        assert!(!keying_allows(&required, Some(&plain)));
        assert!(keying_allows(&required, Some(&secure)));
        assert!(
            keying_allows(&required, None),
            "an INVITE with no offer is answered with one of ours, which carries a key"
        );
        assert!(
            keying_allows(&optional, Some(&plain)),
            "offering keys is not the same as demanding them"
        );
    }

    #[test]
    fn a_stream_that_would_run_unkeyed_does_not_open_on_a_call_that_required_keys() {
        let required = CodecCatalog::new().with_srtp(SrtpPolicy::Required);
        let plain = described("m=audio 40002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n");
        assert_eq!(
            keying_holds(&required, &plan(None), &plain),
            Err(MediaError::SrtpRequired)
        );
        assert!(keying_holds(&CodecCatalog::new(), &plan(None), &plain).is_ok());
    }

    /// The peer's own line is read a second time because `sipral-core` drops
    /// a session parameter it does not recognise instead of invalidating the
    /// line, and §6.3.7 says an unknown one that is not prefixed with a dash
    /// makes the whole attribute invalid.
    #[test]
    fn a_peer_line_carrying_a_parameter_nobody_read_does_not_open_a_stream() {
        let keyed = Some(Keying::Sdes {
            local: CryptoPolicy::new(1, CryptoSuite::AesCm80, KeySalt::new([1; 16], [2; 14])),
            remote: CryptoPolicy::new(1, CryptoSuite::AesCm80, KeySalt::new([3; 16], [4; 14])),
        });
        let catalog = CodecCatalog::new().with_srtp(SrtpPolicy::Offered);

        let honest = described(&format!(
            "m=audio 40002 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
             a=crypto:1 AES_CM_128_HMAC_SHA1_80 {KEY}\r\n"
        ));
        assert!(keying_holds(&catalog, &plan(keyed.clone()), &honest).is_ok());

        let unread = described(&format!(
            "m=audio 40002 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
             a=crypto:1 AES_CM_128_HMAC_SHA1_80 {KEY} FEC_ORDER=FEC_SRTP\r\n"
        ));
        assert_eq!(
            keying_holds(&catalog, &plan(keyed), &unread),
            Err(MediaError::UnusableKeying)
        );
    }
}

// -- D3's counters are fed from both of poll_event's Media branches ---------

#[cfg(test)]
mod counter_wiring {
    //! `poll_event` hands out a media event from two places: the queue
    //! `self.events` fills (a call starting, changing or ending) and
    //! [`MediaEngine::session_event`], which asks each session directly for
    //! what it has queued on its own (a stall, a resume, a recording that
    //! stopped). `crates/sipral/src/counters.rs` is thorough about what
    //! `Counters::observe_media` does with a [`MediaEvent`] once it has one;
    //! what only a test through this module can show is that both places
    //! that hand one out actually call it. This is the one that goes through
    //! `session_event`, built without a SIP exchange because the negotiation
    //! is not what is under test — the plan is written by hand and the
    //! session opened directly, the way `crates/sipral/src/tests.rs`'s own
    //! harness does it with two real stacks instead of one hand-written plan.

    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use sipral_core::sdp::{Direction, MediaPlan, NegotiatedCodec, RtcpPlan, RtpMap};
    use sipral_ua::{
        Account, CallHandle, EndpointConfig, Input, OutgoingCall, TransportId, TransportProtocol,
        Uri, UserAgent,
    };

    use super::MediaEngine;
    use crate::clock::WallClock;
    use crate::codec::CodecCatalog;
    use crate::event::{Event, MediaEvent};
    use crate::session::{MediaConfig, MediaSession, Start, StreamIdentity};
    use crate::share::SessionUnavailable;

    const TRANSPORT: TransportId = TransportId(3);

    fn local() -> SocketAddr {
        "192.0.2.20:5060".parse().expect("an address")
    }

    fn media_local() -> SocketAddr {
        "192.0.2.20:40000".parse().expect("an address")
    }

    fn media_remote() -> SocketAddr {
        "203.0.113.9:40010".parse().expect("an address")
    }

    /// A call this engine has never negotiated anything for, with a session
    /// inserted directly: enough to reach [`MediaEngine::session_event`]
    /// without an offer, an answer or a second stack.
    fn call_with_a_stalling_session(
        engine: &mut MediaEngine,
        now: Instant,
    ) -> (UserAgent, CallHandle) {
        let mut agent = UserAgent::new(EndpointConfig::default(), [5; 32]).expect("a user agent");
        agent
            .receive(
                Input::TransportBound {
                    transport: TRANSPORT,
                    protocol: TransportProtocol::Udp,
                    local: local(),
                    remote: None,
                },
                now,
            )
            .expect("binding a transport");
        let account = agent.add_account(Account::new(
            Uri::parse_str("sip:wired@example.com").expect("a URI"),
            Uri::parse_str("sip:example.com").expect("a URI"),
            Uri::parse_str("sip:wired@192.0.2.20").expect("a URI"),
            TRANSPORT,
            "192.0.2.99:5060".parse().expect("an address"),
        ));
        let call = agent
            .call(
                account,
                &OutgoingCall::new(Uri::parse_str("sip:bob@example.com").expect("a URI")),
                now,
            )
            .expect("the INVITE can be built now that a transport is bound");

        let plan = MediaPlan {
            local: media_local(),
            remote: media_remote(),
            codec: NegotiatedCodec::new(RtpMap {
                payload: 0,
                encoding: "PCMU".to_owned(),
                clock_rate: 8_000,
                parameters: None,
            }),
            direction: Direction::SendRecv,
            dtmf: None,
            rtcp: RtcpPlan::Off,
            keying: None,
        };
        let config = MediaConfig {
            // short enough that the test does not need to fake a ten-second
            // clock jump to reach it
            stall_after: Some(Duration::from_millis(50)),
            ..MediaConfig::default()
        };
        let identity = StreamIdentity {
            ssrc: 1,
            sequence: 0,
            timestamp: 0,
            seed: 1,
        };
        let session = MediaSession::open(
            &plan,
            20,
            &config,
            Vec::new(),
            Start {
                identity,
                clock: WallClock::from_unix(now, 1_700_000_000, 0),
                #[cfg(feature = "dtls")]
                handshake: None,
                now,
            },
        )
        .expect("PCMU is always in this build's catalogue");
        engine.sessions.insert(call, crate::share::hold(session));
        (agent, call)
    }

    /// `MediaEngine::drop` marks every session ended before it lets its own
    /// reference go. Dropping the map alone already answers `Ended` once
    /// nothing else keeps a session alive, so that much would pass whether or
    /// not the flag were ever set; this is the one case the flag actually
    /// decides — a share that reaches the lock while something else (here,
    /// this test's own clone, standing in for a thread already inside
    /// `SessionShare::with`) still holds the session up.
    #[test]
    fn a_share_outlives_the_engine_that_minted_it_even_while_something_else_keeps_the_session_alive()
     {
        let now = Instant::now();
        let mut engine = MediaEngine::new(
            CodecCatalog::new(),
            MediaConfig::default(),
            WallClock::from_unix(now, 1_700_000_000, 0),
            [7; 32],
        );
        let (_agent, call) = call_with_a_stalling_session(&mut engine, now);
        let share = engine.share(call).expect("the session was inserted above");
        let kept_alive = engine
            .sessions
            .get(&call)
            .cloned()
            .expect("the session is still in the map");

        drop(engine);

        let mut touched = false;
        let outcome = share.with(|_session| touched = true);
        assert_eq!(outcome, Err(SessionUnavailable::Ended));
        assert!(
            !touched,
            "the session was acted on after the engine that ran its signalling was gone"
        );
        drop(kept_alive);
    }

    /// `MediaEngine::release` — the call-ended path, as opposed to the whole
    /// engine going away — marks the same flag for the same reason: a share
    /// already on its way to the lock when a call ends must find out rather
    /// than touch a session mid-teardown, even though something else (again,
    /// this test's own clone) is still keeping that session allocated.
    #[test]
    fn releasing_a_call_ends_its_share_even_while_something_else_keeps_the_session_alive() {
        let now = Instant::now();
        let mut engine = MediaEngine::new(
            CodecCatalog::new(),
            MediaConfig::default(),
            WallClock::from_unix(now, 1_700_000_000, 0),
            [9; 32],
        );
        let (_agent, call) = call_with_a_stalling_session(&mut engine, now);
        let share = engine.share(call).expect("the session was inserted above");
        let kept_alive = engine
            .sessions
            .get(&call)
            .cloned()
            .expect("the session is still in the map");

        engine.release(call, now);

        let mut touched = false;
        let outcome = share.with(|_session| touched = true);
        assert_eq!(outcome, Err(SessionUnavailable::Ended));
        assert!(
            !touched,
            "the session was acted on after its call had ended"
        );
        drop(kept_alive);
    }

    #[test]
    fn a_stall_reached_through_session_event_still_moves_the_counters() {
        let now = Instant::now();
        let mut engine = MediaEngine::new(
            CodecCatalog::new(),
            MediaConfig::default(),
            WallClock::from_unix(now, 1_700_000_000, 0),
            [23; 32],
        );
        let (mut agent, _call) = call_with_a_stalling_session(&mut engine, now);
        assert_eq!(
            engine.counters().media_gaps.get(),
            0,
            "nothing has stalled yet"
        );

        let later = now + Duration::from_millis(200);
        engine.handle_timeout(later);

        let mut saw_stalled = false;
        while let Some(event) = engine.poll_event(&mut agent, later) {
            if let Event::Media {
                event: MediaEvent::Stalled { .. },
                ..
            } = event
            {
                saw_stalled = true;
            }
        }
        assert!(
            saw_stalled,
            "the session's own stall never reached poll_event's session_event branch"
        );
        assert_eq!(
            engine.counters().media_gaps.get(),
            1,
            "session_event's branch of poll_event has to feed the counters too, not only \
             the branch that drains self.events"
        );
    }
}

#[cfg(test)]
mod key_source_tests {
    use super::{KeySource, draw_key};

    #[test]
    fn the_media_key_follows_the_media_seed_and_nothing_else() {
        // The whole of the fix, in three lines: two stacks given the same
        // signalling entropy — which a replay recording carries in clear —
        // must not be derivable from it to the same media keys.
        let mut one = KeySource::new([1; 32]);
        let mut other = KeySource::new([2; 32]);
        let mut same_again = KeySource::new([1; 32]);

        let first = draw_key(&mut one);
        assert_ne!(
            first.key(),
            draw_key(&mut other).key(),
            "two media seeds, two keys"
        );
        assert_eq!(
            first.key(),
            draw_key(&mut same_again).key(),
            "and a seed is a stream, so the same one still reproduces"
        );
    }

    #[test]
    fn no_two_keys_from_one_seed_are_the_same() {
        // RFC 4568 section 7.1.2: "the master key(s) in the answer MUST be
        // different from those in the offer". The counter is what provides
        // that, and it provides it for the salt too.
        let mut keys = KeySource::new([0; 32]);
        let mut seen = Vec::new();
        for _ in 0..64 {
            let drawn = draw_key(&mut keys);
            let pair = (drawn.key(), drawn.salt());
            assert!(!seen.contains(&pair), "a key repeated");
            seen.push(pair);
        }
    }

    /// The block `draw_key` reads and the key and salt sliced out of it
    /// (8.2.9) hold the SRTP master key and salt, so all three have to be the
    /// type that wipes itself on drop rather than a plain array left to be
    /// merely dropped, or a `Vec` that leaves its last copy in freed memory.
    /// A wipe is not observable from safe Rust and Miri cannot be pointed at
    /// this, so what is asserted is the one thing that is visible: which type
    /// the function declares its buffers as. The needles are assembled at
    /// runtime, so the test cannot pass by matching its own assertion — the
    /// same check `sipral-core` runs on `A1` in
    /// `auth::digest::tests::the_password_is_never_built_in_a_buffer_that_is_not_wiped`.
    #[test]
    fn the_media_key_and_salt_are_never_built_in_a_buffer_that_is_not_wiped() {
        let source = include_str!("engine.rs").replace("\r\n", "\n");
        let opens = "fn draw_key(keys: &mut KeySource) -> KeySalt {";
        let from = source.find(opens).expect("draw_key is in this file");
        let rest = source.get(from..).expect("the rest of the file");
        let to = rest.find("\n}\n").map_or(rest.len(), |at| at + 1);
        let body = rest.get(..to).expect("the body of draw_key");
        assert!(
            body.len() > opens.len(),
            "the slice is the function, not the signature"
        );

        let wiping = format!("{}::{}", "Zeroizing", "new");
        assert!(
            body.matches(&wiping).count() >= 3,
            "the block, the key and the salt all hold key material and must \
             each be built with {wiping}: {body}"
        );
        for grown in [
            format!("{}::{}", "Vec", "new"),
            format!("{}::{}", "Vec", "with_capacity"),
            format!("{}{}", "to_", "vec()"),
        ] {
            assert!(
                !body.contains(&grown),
                "the key material must not pass through {grown}"
            );
        }
    }
}
