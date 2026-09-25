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
#[cfg(any(feature = "dtls", feature = "ice"))]
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
use crate::codec::{Codec, CodecCandidate, CodecCatalog, Keyed, annex_b_allowed};
use crate::counters::Counters;
#[cfg(feature = "dtls")]
use crate::dtls::Identity;
use crate::dtmf::Digit;
use crate::error::MediaError;
use crate::event::{DigitSource, Event, MediaEvent};
#[cfg(feature = "dtls")]
use crate::keying::SrtpPolicy;
use crate::keying::{self, Shape};
use crate::payloads::Payloads;
use crate::session::{MediaConfig, MediaSession, Start, StreamIdentity};
use crate::share::{self, Held, SessionGuard, SessionShare};

/// The media type this stack negotiates. There is no video, deliberately, and
/// an offered stream of anything else is refused rather than half-taken.
pub(crate) const AUDIO: &str = "audio";

/// RFC 4733's named events, which ride alongside a codec rather than being
/// one, and which an answer therefore keeps without there being a codec behind
/// them.
const TELEPHONE_EVENT: &str = "telephone-event";

/// RFC 3389 comfort noise, likewise.
const COMFORT_NOISE: &str = "CN";

/// How many of the far end's connectivity checks one socket keeps while the
/// call described on it has no session yet ([`MediaEngine::receive_early`]).
///
/// A peer paces its checks at one per Ta, fifty milliseconds unless both ends
/// agree on less (RFC 8445 §14.2), and starts them when it sends its answer,
/// so what reaches the socket before that answer is read is a handful: this
/// holds most of a second of them. One more pushes out the oldest, since the
/// newest are the checks the far end is still waiting on; a retransmission
/// takes the place of the copy it repeats rather than a second one.
#[cfg(feature = "ice")]
const EARLY_CHECKS: usize = 16;

/// How long a kept check is still worth answering: RFC 8489 §6.2.1's
/// defaults — Rc of 7, Rm of 16, an RTO of 500 ms — end the far end's
/// transaction 39.5 seconds after its first request, and an answer after
/// that reaches nobody. A check kept longer, on a call whose session is slow
/// to open, is dropped rather than answered.
#[cfg(feature = "ice")]
const EARLY_CHECK_LIFETIME: Duration = Duration::from_millis(39_500);

/// One of the far end's connectivity checks, kept for a call that has no
/// session yet ([`MediaEngine::receive_early`]).
#[cfg(feature = "ice")]
#[derive(Debug)]
struct EarlyCheck {
    /// Where it came from, which is where the answer goes.
    from: SocketAddr,
    /// The whole datagram, as it arrived.
    data: Vec<u8>,
    /// When it arrived, for [`EARLY_CHECK_LIFETIME`].
    at: Instant,
}

#[cfg(feature = "ice")]
impl EarlyCheck {
    /// The STUN transaction id (RFC 8489 §5), which a retransmission repeats.
    fn transaction(&self) -> Option<&[u8]> {
        self.data.get(8..20)
    }

    /// Whether it is still worth answering at `now`.
    fn live(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.at) < EARLY_CHECK_LIFETIME
    }
}

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
    ///
    /// Also what tells a call this engine describes from one it only heard
    /// about: it is set by the calls that write a description — placing,
    /// ringing with media, answering — and by nothing else. An incoming call
    /// the application answered with a description of its own keeps `None`
    /// for its whole life, and its re-offers and session changes are the
    /// application's; see [`MediaEngine::answer_reoffer`].
    address: Option<SocketAddr>,
    /// Where that socket appears from outside, when the call was given it
    /// ([`CallMedia::public_address`]): what every description of the call
    /// names in `c=` and `m=` instead of `address`.
    public: Option<SocketAddr>,
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
    /// The key and certificate this call named in its first description
    /// under a DTLS policy, kept for the rest of the call: its handshake is
    /// started with them and every later description writes their
    /// fingerprint, whatever this engine has renewed to since. `None` until
    /// that description is written, and on every call not keyed this way.
    #[cfg(feature = "dtls")]
    dtls_identity: Option<Arc<Identity>>,
    /// What this end has settled about ICE on this call: its credentials, its
    /// role, its tiebreaker and its candidates.
    ///
    /// Written when the call's first description is, and then repeated on
    /// every later one — RFC 8839 §4.4.1.1.1 wants the attributes on each,
    /// and a hold re-offer that drew fresh credentials would read to the peer
    /// as an ICE restart nobody asked for. `None` on every call not using it,
    /// which is every call whose catalogue leaves [`IcePolicy`] off.
    ///
    /// [`IcePolicy`]: crate::IcePolicy
    #[cfg(feature = "ice")]
    ice: Option<crate::ice::LocalIce>,
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
    /// Every dynamic payload type number either end has written on this
    /// call's stream, and the codec it named — what RFC 3264 §8.3.2 says a
    /// number goes on naming for as long as the session lasts, and what
    /// [`MediaEngine::change_codecs`] numbers its offer against.
    payloads: Payloads,
    /// The codecs [`MediaEngine::change_codecs`] offered and the far end has
    /// not answered yet. They become [`Managed::catalog`] when it accepts;
    /// until then a refusal leaves the call on the list it had, as RFC 3261
    /// §14.1 leaves the session.
    pending: Option<Pending>,
}

/// A codec change on its way to the far end.
#[derive(Clone, Debug)]
struct Pending {
    /// What the call's catalogue becomes once the offer is accepted.
    catalog: CodecCatalog,
    /// The formats the offer listed, which is how the description that comes
    /// back is told apart from one describing something else.
    formats: Vec<String>,
}

impl Managed {
    /// Remember the numbers both halves of the negotiation bind.
    fn note_payloads(&mut self) {
        if let Some(local) = self.local.as_ref() {
            self.payloads.note(local);
        }
        if let Some(remote) = self.remote.as_ref() {
            self.payloads.note(remote);
        }
    }
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
///
/// Not `Clone`: it can carry a [`Relay`](crate::Relay), which is an
/// allocation on a server, and one call is all it can serve.
#[derive(Debug)]
pub struct CallMedia {
    /// What to offer, in what order.
    pub catalog: CodecCatalog,
    /// How to open the session.
    pub config: MediaConfig,
    /// Where the call's media socket appears from outside, when that is not
    /// where it is bound — see [`CallMedia::public_address`].
    pub public: Option<SocketAddr>,
    /// A relay on a TURN server, allocated from the call's media socket —
    /// see [`CallMedia::relay`].
    #[cfg(feature = "ice")]
    pub relay: Option<crate::Relay>,
}

impl CallMedia {
    /// Bundle a catalogue and a configuration for one call.
    #[must_use]
    pub fn new(catalog: CodecCatalog, config: MediaConfig) -> Self {
        Self {
            catalog,
            config,
            public: None,
            #[cfg(feature = "ice")]
            relay: None,
        }
    }

    /// Give the call a relay on a TURN server, allocated from its media
    /// socket with [`Relays`](crate::Relays) before the call.
    ///
    /// Under an [`IcePolicy`](crate::IcePolicy) that offers full ICE, the
    /// relay is the call's relayed candidate (RFC 8445 §5.1.1.2), and the
    /// server-reflexive address the Allocate response named goes beside it —
    /// and into `c=` and `m=`, as [`CallMedia::public_address`] would put it,
    /// when the call was not given one of those. ICE uses the relay only
    /// when no cheaper pair answers. From the moment the call is described
    /// the allocation is the call's agent's: it installs the permissions and
    /// binds the channel the media needs, keeps the allocation and the NAT
    /// binding under it alive, and gives it back to the server (a Refresh
    /// with a lifetime of zero, RFC 8656 §8) when the call ends, ICE settles
    /// on another pair, or the peer turns out to do no ICE at all. What that
    /// sends comes out of [`MediaEngine::poll_transmit`] while the call is
    /// being set up and [`MediaEngine::poll_farewell`] once it is over, for
    /// the socket the relay was allocated from.
    ///
    /// A call that cannot use it — its catalogue offers no ICE, or only the
    /// lite role, or the relay is of the other address family — gives it
    /// back at once, the same way. A description that is refused —
    /// [`MediaEngine::place_with`] or [`MediaEngine::accept_transfer_with`]
    /// refused by the user agent, [`MediaEngine::ring_with`] or
    /// [`MediaEngine::answer_with`] refused for a call already described or
    /// a handle that names no call, or anything else any of them answers with
    /// an error — sent nothing that named the relay, and hands it back whole
    /// through [`MediaEngine::poll_returned_relay`], still live on its
    /// server, for [`Relays::put_back`](crate::Relays::put_back) to keep for
    /// the next call on the socket.
    #[cfg(feature = "ice")]
    #[must_use]
    pub fn relay(mut self, relay: crate::Relay) -> Self {
        self.relay = Some(relay);
        self
    }

    /// The call's media without its relay, and the relay on its own, for the
    /// description to hold until it can no longer be refused.
    #[cfg(feature = "ice")]
    fn handing_over(mut self) -> (Self, Handed) {
        let handed = Handed {
            relay: self.relay.take(),
            kept: None,
        };
        (self, handed)
    }

    /// Without the feature a call is handed no relay.
    #[cfg(not(feature = "ice"))]
    const fn handing_over(self) -> (Self, Handed) {
        (self, Handed)
    }

    /// Describe the call's media socket by the address it appears at from
    /// outside rather than the one it is bound to.
    ///
    /// What `Mappings` learns from a STUN server for a
    /// socket behind a NAT, or what a one-to-one NAT's configuration says.
    /// Every description of the call names it in `c=` and `m=` — the offer,
    /// the answer and every re-offer after them — while the session keeps
    /// the bound address for everything that is local: the socket, and the
    /// base of the call's ICE candidates.
    ///
    /// Two further things follow, and both are for the same reason — one
    /// mapping describes one port. The description asks for `a=rtcp-mux`
    /// (RFC 5761), as an ICE offer does, since RTCP on a port of its own
    /// would need a mapping of its own; a peer that declines leaves RTCP on
    /// the public port plus one, which a NAT that preserves ports maps
    /// correctly and another does not, and what is lost then is the reports,
    /// never the audio. And under an [`IcePolicy`](crate::IcePolicy) that
    /// offers ICE, the address is a server-reflexive candidate beside the
    /// host one, and the default candidate RFC 8839 §4.2.1.2 puts in `c=`.
    #[must_use]
    pub fn public_address(mut self, public: SocketAddr) -> Self {
        self.public = Some(public);
        self
    }

    /// The catalogue this call offers from: its own, asking for multiplexing
    /// when the call is described by a public address.
    fn offering(catalog: CodecCatalog, public: Option<SocketAddr>) -> CodecCatalog {
        if public.is_some() {
            catalog.with_rtcp_mux(true)
        } else {
            catalog
        }
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
    /// Every call currently in a local conference of two, both directions:
    /// `a` maps to `b` and `b` maps to `a`, so [`MediaEngine::joined_with`]
    /// answers either call without knowing which one
    /// [`MediaEngine::join`] was given first. Nothing outside `crate::join`
    /// reads a value out of this beyond the partner it names — the mixing
    /// itself is [`crate::join::mix_two`], which touches sessions and not
    /// this map.
    joins: BTreeMap<CallHandle, CallHandle>,
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
    ///
    /// Shared rather than owned, because a call keeps the one it first
    /// described itself with ([`Managed::dtls_identity`]) for as long as it
    /// lasts, and a renewal here must not take it away from under the call.
    #[cfg(feature = "dtls")]
    identity: Option<Arc<Identity>>,
    /// The ICE agents of calls that were described with a relay
    /// ([`CallMedia::relay`]) and have no session yet, waiting for the
    /// negotiation to settle.
    ///
    /// Kept here rather than rebuilt from [`Managed::ice`] when the session
    /// opens, the way every other call's agent is: the allocation inside it
    /// is state on the TURN server, and nothing written into a description
    /// can make it again. Driven by [`MediaEngine::handle_timeout`] and
    /// [`MediaEngine::poll_transmit`] while it waits, so that the NAT binding
    /// towards the server outlives a phone that rings for a minute.
    #[cfg(feature = "ice")]
    gathered: BTreeMap<CallHandle, crate::ice::Ice>,
    /// The far end's connectivity checks that reached a socket a call was
    /// described on before that call's session opened, by the socket, oldest
    /// first: what [`MediaEngine::receive_early`] kept for the agent the
    /// session opens with, which answers them then (RFC 8445 §7.3).
    #[cfg(feature = "ice")]
    early: BTreeMap<SocketAddr, VecDeque<EarlyCheck>>,
    /// Relays handed to descriptions that were refused before there was a
    /// call to hold them, whole and live on their servers, waiting for
    /// [`MediaEngine::poll_returned_relay`].
    #[cfg(feature = "ice")]
    returned: VecDeque<crate::Relay>,
    /// Every branch a proxy forked off a call this engine placed, and the
    /// call the first description was written for: which of them may take
    /// the relay that description named ([`MediaEngine::claim_relay`]).
    #[cfg(feature = "ice")]
    branches: BTreeMap<CallHandle, CallHandle>,
}

/// The relay a description was handed, for as long as the description can
/// still be refused: in `relay` until it is drawn into the call's ICE, and in
/// `kept` from then until the user agent has taken what it was drawn for.
/// Whatever is left in it when the description is refused goes back to the
/// application whole ([`MediaEngine::hand_back`]).
#[cfg(feature = "ice")]
struct Handed {
    relay: Option<crate::Relay>,
    kept: Option<Kept>,
}

#[cfg(feature = "ice")]
impl Handed {
    /// Where the relay's server saw the socket from, when it said.
    fn mapped(&self) -> Option<SocketAddr> {
        self.relay.as_ref().and_then(crate::Relay::mapped)
    }

    /// The relay is one this call has no use for, and goes back to its
    /// server with the call's farewells.
    fn unusable(&mut self) {
        if let Some(relay) = self.relay.take() {
            self.kept = Some(Kept::Unused(Box::new(relay)));
        }
    }
}

/// Without the feature a description is handed no relay.
#[cfg(not(feature = "ice"))]
struct Handed;

#[cfg(not(feature = "ice"))]
impl Handed {
    #[allow(clippy::unused_self)]
    const fn mapped(&self) -> Option<SocketAddr> {
        None
    }

    #[allow(clippy::unused_self)]
    const fn unusable(&mut self) {}
}

/// What a call's first description left of the relay it was given.
#[cfg(feature = "ice")]
enum Kept {
    /// The agent that holds it, for the session to run.
    Agent(crate::ice::Ice),
    /// The relay itself, which this call cannot use: its catalogue offers no
    /// ICE, or only the lite role, or the relay is of the other address
    /// family. It goes back to the server at once. Boxed, since it carries a
    /// whole TURN client and the agent beside it is boxed already.
    Unused(Box<crate::relay::Relay>),
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
            joins: BTreeMap::new(),
            counters: Counters::default(),
            keys: KeySource::new(media_seed),
            #[cfg(feature = "dtls")]
            identity: None,
            #[cfg(feature = "ice")]
            gathered: BTreeMap::new(),
            #[cfg(feature = "ice")]
            early: BTreeMap::new(),
            #[cfg(feature = "ice")]
            returned: VecDeque::new(),
            #[cfg(feature = "ice")]
            branches: BTreeMap::new(),
        }
    }

    /// STUN mappings against `server`, whose transaction ids are drawn from
    /// this engine's own generator.
    ///
    /// The generator every SRTP key comes from, and the reason it is used
    /// here rather than a seed of the application's: a transaction id is the
    /// whole of what stops an attacker off the path from answering first and
    /// naming an address of its choosing as this end's own, so it needs the
    /// same unpredictability a key does, and this is the one place in a stack
    /// that already has it. Drawing from it moves the keys this engine makes
    /// afterwards along, the same as any other draw does, and reveals none of
    /// them.
    #[cfg(feature = "stun")]
    #[must_use]
    pub fn mappings(&mut self, server: SocketAddr) -> crate::Mappings {
        crate::Mappings::new(server, self.keys.block())
    }

    /// Relays on the TURN server at `server`, which knows this end by
    /// `username` and `password`, whose transaction ids are drawn from this
    /// engine's own generator — for the reason [`MediaEngine::mappings`]
    /// gives, which a forged Allocate response naming a relay of an
    /// attacker's choosing makes no weaker.
    #[cfg(feature = "ice")]
    #[must_use]
    pub fn relays(&mut self, server: SocketAddr, username: &str, password: &str) -> crate::Relays {
        crate::Relays::new(server, username, password, self.keys.block())
    }

    /// The key and certificate this stack presents, making one if there is
    /// none or if the one there is has nearly run out.
    ///
    /// # Errors
    /// [`MediaError::DtlsIdentity`], which a sound media seed does not
    /// produce.
    #[cfg(feature = "dtls")]
    fn identity(&mut self, now: Instant) -> Result<Arc<Identity>, MediaError> {
        let unix = self.clock.unix_at(now);
        if self.identity.as_ref().is_none_or(|had| had.is_stale(unix)) {
            // a fresh one rather than a refused call: `MediaEngine` is made
            // once and a desk phone runs for months, so a certificate that
            // outlives its own period is the ordinary case rather than a
            // fault. Calls already described keep the one they named
            self.identity = Some(Arc::new(Identity::new(&mut self.keys, unix)?));
        }
        self.identity.clone().ok_or(MediaError::DtlsIdentity)
    }

    /// The identity a description just written for a call named, when it was
    /// written under a DTLS policy: this engine's own, which `dtls_lines` has
    /// just made sure is there and current. What the call keeps.
    #[cfg(feature = "dtls")]
    fn named(&self, keyed: bool) -> Option<Arc<Identity>> {
        if keyed { self.identity.clone() } else { None }
    }

    /// The identity a call named in the first description it wrote under a
    /// DTLS policy, or this engine's own for one that has not written one
    /// yet.
    ///
    /// A renewal between a call's offer and its handshake used to hand the
    /// handshake the new certificate, whose hash was not the fingerprint the
    /// far end had been given — RFC 8122 §5.1's "MUST NOT establish the
    /// connection", once a month, on every call ringing at the time — and a
    /// running call's next re-offer or answer then wrote a fingerprint that
    /// read as a new association (RFC 8842 §3.1).
    #[cfg(feature = "dtls")]
    fn identity_for(
        &mut self,
        call: Option<CallHandle>,
        now: Instant,
    ) -> Result<Arc<Identity>, MediaError> {
        match call
            .and_then(|call| self.calls.get(&call))
            .and_then(|managed| managed.dtls_identity.clone())
        {
            Some(bound) => Ok(bound),
            None => self.identity(now),
        }
    }

    /// The `a=fingerprint` this end writes into the description it is about
    /// to send and the `a=setup` beside it, or `None` for a call that is not
    /// keyed by a handshake.
    ///
    /// Owned strings rather than a borrow, because the call remembers what it
    /// wrote: [`dtls_role`](sipral_dtls::setup::dtls_role) needs both halves
    /// of the exchange, and only one of them ever arrives from the far end.
    ///
    /// `running` names the call an answer is for once it already has an
    /// association, which is every re-offer on a keyed call. Its answer then
    /// takes the role the association gives this end rather than the one a
    /// fresh answer would (RFC 8842 §5.3): to the `actpass` every re-offer
    /// carries (§5.5), a fresh answer says `active` every time, and a server
    /// that said so would be asking to become the client.
    ///
    /// # Errors
    /// As [`MediaEngine::identity`]; [`MediaError::DtlsRole`] for an offer
    /// whose `a=setup` cannot be read; and [`MediaError::DtlsRoleChanged`]
    /// for a re-offer whose `a=setup` leaves this end only the role it does
    /// not have.
    #[cfg(feature = "dtls")]
    fn dtls_lines(
        &mut self,
        catalog: &CodecCatalog,
        side: Side,
        offered: Option<&SessionDescription>,
        running: Option<CallHandle>,
        now: Instant,
    ) -> Result<Option<(String, String)>, MediaError> {
        if !catalog.srtp().wants_dtls() {
            return Ok(None);
        }
        let theirs = offered.and_then(setup_in);
        let role = running
            .and_then(|call| self.sessions.get(&call))
            .and_then(|held| share::lock(held).session.dtls_role());
        let setup = match (side, role) {
            (Side::Answering, Some(role)) => crate::dtls::setup_to_keep(role, theirs.as_deref())?,
            _ => crate::dtls::setup_to_write(side.party(), theirs.as_deref())?,
        };
        let fingerprint = self.identity_for(running, now)?.fingerprint().to_owned();
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
        _running: Option<CallHandle>,
        _now: Instant,
    ) -> Result<Option<(String, String)>, MediaError> {
        Ok(None)
    }

    /// Whether answering `offer` with `answer` would move a running stream
    /// onto another kind of keying ([`Shape`]).
    ///
    /// Read off the plan the two would settle, which is the one `settle`
    /// will work out once they are agreed, rather than off either
    /// description alone: an offer carrying both an `a=crypto` and an
    /// `a=fingerprint` settles on whichever the answer took. A call with no
    /// stream running yet has nothing to move, and a pair that settles no
    /// plan at all is refused where the plan is worked out.
    fn changes_keying(
        &self,
        call: CallHandle,
        answer: &SessionDescription,
        offer: &SessionDescription,
    ) -> bool {
        let Some(held) = self.sessions.get(&call) else {
            return false;
        };
        let running = Shape::of(share::lock(held).session.plan().keying.as_ref());
        matches!(
            answer.media_plan(offer, 0),
            Ok(Some(plan)) if Shape::of(plan.keying.as_ref()) != running
        )
    }

    /// Whether a re-offer keeps the certificate the call's association was
    /// checked against.
    ///
    /// RFC 8842 §3.1 has a fingerprint "modified, added, or removed" ask for a
    /// new association, and §5.3 has an answerer that will not start one
    /// refuse the offer. A re-offer that names no fingerprint at all is not
    /// judged here: it has moved off DTLS-SRTP altogether, and whether that is
    /// allowed is the call's policy, which `keying_allows` and `keying_holds`
    /// already read.
    ///
    /// # Errors
    /// [`MediaError::DtlsFingerprintChanged`] for one that names another.
    #[cfg(feature = "dtls")]
    fn keeps_certificate(
        &self,
        call: CallHandle,
        offer: &SessionDescription,
    ) -> Result<(), MediaError> {
        let Some(held) = self.sessions.get(&call) else {
            return Ok(());
        };
        let slot = share::lock(held);
        let Some(Keying::Dtls {
            fingerprints: had, ..
        }) = slot.session.plan().keying.as_ref()
        else {
            return Ok(());
        };
        let offered = fingerprints_in(offer);
        if offered.is_empty() || crate::dtls::same_fingerprints(had, &offered) {
            Ok(())
        } else {
            Err(MediaError::DtlsFingerprintChanged)
        }
    }

    /// What this call says about ICE in the description about to be written.
    ///
    /// `Ok(None)` for a catalogue that does not offer it, which is the
    /// default. For one that does, the credentials and candidates this call
    /// already has if it has any, and a fresh draw if it does not: RFC 8839
    /// §4.4.1.1.1 puts the attributes on every description of a session, and
    /// drawing again part-way through is how an ICE restart is announced.
    ///
    /// # Errors
    ///
    /// As [`crate::ice::LocalIce::draw`]: an address RFC 8445 §5.1.1.1 rules
    /// out of a candidate is refused here rather than offered as one no peer
    /// can reach.
    #[cfg(feature = "ice")]
    fn ice_lines(
        &mut self,
        call: Option<CallHandle>,
        catalog: &CodecCatalog,
        address: SocketAddr,
        public: Option<SocketAddr>,
        we_are_offerer: bool,
        now: Instant,
    ) -> Result<Option<crate::ice::LocalIce>, MediaError> {
        if !catalog.ice().offers() {
            return Ok(None);
        }
        if let Some(existing) = call
            .and_then(|call| self.calls.get(&call))
            .and_then(|managed| managed.ice.clone())
        {
            return Ok(Some(existing));
        }
        crate::ice::LocalIce::draw(
            &mut self.keys,
            address,
            public,
            we_are_offerer,
            catalog.ice().lite(),
            now,
        )
        .map(Some)
    }

    /// What a call's first description says about ICE, when the call was
    /// given a relay: [`MediaEngine::ice_lines`], with the relayed candidate
    /// among the ones drawn, and what is left of the relay in `handed` for
    /// [`MediaEngine::keep`] to put away once the user agent has taken the
    /// description.
    ///
    /// The relay is taken into a full agent only when the call will run one:
    /// a catalogue that offers ICE in the full role, a call that has not
    /// already drawn its candidates, and a relay of the socket's own address
    /// family. Anything else leaves it as [`Kept::Unused`]. A refusal here
    /// leaves it where it was, for [`MediaEngine::hand_back`].
    ///
    /// # Errors
    ///
    /// As [`MediaEngine::ice_lines`].
    #[cfg(feature = "ice")]
    #[allow(clippy::too_many_arguments)]
    fn first_ice(
        &mut self,
        call: Option<CallHandle>,
        catalog: &CodecCatalog,
        address: SocketAddr,
        public: Option<SocketAddr>,
        handed: &mut Handed,
        we_are_offerer: bool,
        now: Instant,
    ) -> Result<Option<crate::ice::LocalIce>, MediaError> {
        let Some(relay) = handed.relay.as_ref() else {
            return self.ice_lines(call, catalog, address, public, we_are_offerer, now);
        };
        let drawn = call
            .and_then(|call| self.calls.get(&call))
            .is_some_and(|managed| managed.ice.is_some());
        let usable = catalog.ice().offers()
            && !catalog.ice().lite()
            && !drawn
            && relay
                .relayed()
                .is_some_and(|relayed| relayed.is_ipv4() == address.is_ipv4());
        if usable
            && let Some((local, ice)) = crate::ice::LocalIce::draw_relayed(
                &mut self.keys,
                address,
                public,
                &mut handed.relay,
                we_are_offerer,
                now,
            )?
        {
            handed.kept = Some(Kept::Agent(ice));
            return Ok(Some(local));
        }
        let ice = self.ice_lines(call, catalog, address, public, we_are_offerer, now)?;
        handed.unusable();
        Ok(ice)
    }

    /// Without the feature there is no relay to draw, and a call's first
    /// description says what [`MediaEngine::ice_lines`] says.
    #[cfg(not(feature = "ice"))]
    #[allow(clippy::too_many_arguments)]
    fn first_ice(
        &mut self,
        call: Option<CallHandle>,
        catalog: &CodecCatalog,
        address: SocketAddr,
        public: Option<SocketAddr>,
        _handed: &mut Handed,
        we_are_offerer: bool,
        now: Instant,
    ) -> Result<Option<crate::ice::LocalIce>, MediaError> {
        self.ice_lines(call, catalog, address, public, we_are_offerer, now)
    }

    /// Put away what a call's first description left of its relay, once the
    /// user agent has taken the description: the agent until the session
    /// opens, or the relay's farewell at once.
    #[cfg(feature = "ice")]
    fn keep(&mut self, call: CallHandle, handed: &mut Handed, now: Instant) {
        match handed.kept.take() {
            Some(Kept::Agent(ice)) => {
                // `first_ice` draws a relayed agent only for a call that has
                // drawn no candidates yet, so none is waiting here; were one
                // ever replaced, its allocation goes back rather than being
                // dropped with nothing sent
                if let Some(mut before) = self.gathered.insert(call, ice) {
                    for (destination, payload) in before.release(now) {
                        self.farewells.push_back((call, destination, payload));
                    }
                }
            }
            Some(Kept::Unused(relay)) => {
                let server = relay.server();
                for payload in relay.release(now) {
                    self.farewells.push_back((call, server, payload));
                }
            }
            None => {}
        }
    }

    /// Without the feature there is nothing to put away.
    #[cfg(not(feature = "ice"))]
    #[allow(clippy::unused_self)]
    const fn keep(&mut self, _call: CallHandle, _handed: &mut Handed, _now: Instant) {}

    /// What a refused description leaves of the relay it was handed goes
    /// back to the application, whole and still live on its server: the
    /// relay itself if it was never drawn into anything, and out of the
    /// agent it was drawn into if it was. Nothing was sent that named it but
    /// the description that was refused, so nothing was promised to a peer,
    /// and the socket it was allocated from can offer it to the next call.
    #[cfg(feature = "ice")]
    fn hand_back(&mut self, handed: Handed) {
        let Handed { relay, kept } = handed;
        self.returned.extend(relay);
        match kept {
            Some(Kept::Agent(ice)) => self.returned.extend(ice.into_relays()),
            Some(Kept::Unused(relay)) => self.returned.push_back(*relay),
            None => {}
        }
    }

    /// Without the feature a description is handed nothing to give back.
    #[cfg(not(feature = "ice"))]
    #[allow(clippy::unused_self, clippy::needless_pass_by_value)]
    const fn hand_back(&mut self, _handed: Handed) {}

    /// Give back the relay a call's waiting agent holds, among the call's
    /// farewells: for a call that ended before its session opened, and for
    /// one whose peer turned out to do no ICE.
    #[cfg(feature = "ice")]
    fn let_go(&mut self, call: CallHandle, now: Instant) {
        if let Some(mut ice) = self.gathered.remove(&call) {
            for (destination, payload) in ice.release(now) {
                self.farewells.push_back((call, destination, payload));
            }
        }
    }

    /// What this call says about ICE in its answer to a re-offer: what
    /// [`MediaEngine::ice_lines`] says, unless the offer is an ICE restart
    /// and this end is lite.
    ///
    /// RFC 8839 §4.4.1.1.1 signals a restart by a change of both `ice-ufrag`
    /// and `ice-pwd`, and §4.4.2.1 has an answerer that accepts one "change
    /// the SDP "ice-pwd" and "ice-ufrag" attribute values". A lite end
    /// follows it, keeping the pair it has until the peer nominates under the
    /// new ones ([`sipral_nat::ice::LiteAgent::restart`]). The full role does
    /// not restart from here yet: answering it with new credentials the
    /// running agent does not hold would stop the checks it depends on, so
    /// its answer keeps the ones it has.
    ///
    /// # Errors
    ///
    /// As [`MediaEngine::ice_lines`].
    #[cfg(feature = "ice")]
    fn reoffer_ice(
        &mut self,
        call: CallHandle,
        catalog: &CodecCatalog,
        (address, public): (SocketAddr, Option<SocketAddr>),
        offer: &SessionDescription,
        now: Instant,
    ) -> Result<Option<crate::ice::LocalIce>, MediaError> {
        let Some(held) = self.ice_lines(Some(call), catalog, address, public, false, now)? else {
            return Ok(None);
        };
        if !held.is_lite() {
            return Ok(Some(held));
        }
        let credentials = |description: &SessionDescription| {
            description
                .media
                .iter()
                .find(|media| !media.is_rejected())
                .and_then(|stream| sipral_nat::ice::parse_remote(description, stream))
                .map(|remote| (remote.ufrag, remote.pwd))
        };
        let before = self
            .calls
            .get(&call)
            .and_then(|managed| managed.remote.as_ref())
            .and_then(credentials);
        match (before, credentials(offer)) {
            (Some(before), Some(offered)) if before.0 != offered.0 && before.1 != offered.1 => {
                held.restarted(&mut self.keys).map(Some)
            }
            _ => Ok(Some(held)),
        }
    }

    /// Without the feature there is no restart to follow.
    #[cfg(not(feature = "ice"))]
    fn reoffer_ice(
        &mut self,
        call: CallHandle,
        catalog: &CodecCatalog,
        (address, public): (SocketAddr, Option<SocketAddr>),
        _offer: &SessionDescription,
        now: Instant,
    ) -> Result<Option<crate::ice::LocalIce>, MediaError> {
        self.ice_lines(Some(call), catalog, address, public, false, now)
    }

    /// Without the feature there is nothing to gather and no attribute to
    /// write, and every description this engine writes names one address.
    #[cfg(not(feature = "ice"))]
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn ice_lines(
        &mut self,
        _call: Option<CallHandle>,
        _catalog: &CodecCatalog,
        _address: SocketAddr,
        _public: Option<SocketAddr>,
        _we_are_offerer: bool,
        _now: Instant,
    ) -> Result<Option<crate::ice::LocalIce>, MediaError> {
        Ok(None)
    }

    /// The ICE agent a settled plan calls for, gathered and told what the
    /// peer said — or `None` for a call that is not using ICE.
    ///
    /// N7, written out: three different peers end here with `None`, and the
    /// stream then runs on `c=`/`m=` and symmetric RTP exactly as it did
    /// before this engine knew what ICE was. A peer that wrote no ICE
    /// attributes at all — an Asterisk with `ice_support=no`, which is the
    /// default — is the first and the commonest. A peer whose candidates are
    /// all unusable is the second. A description whose own default
    /// destinations are missing from its candidate lines is the third: RFC
    /// 8839 §4.2.5's ICE mismatch, which is what an ALG rewriting `c=` and
    /// the `m=` port without touching `a=candidate` looks like from here.
    ///
    /// Under [`IcePolicy::Required`] each of the three is
    /// [`MediaError::IceRequired`] instead. That is the whole difference
    /// between the two policies.
    ///
    /// # Errors
    ///
    /// [`MediaError::IceRequired`] as above, [`MediaError::IceNeedsRtcpMux`]
    /// for a peer that took `a=rtcp-mux` out of its answer, and
    /// [`MediaError::Ice`] for credentials the agent refuses.
    ///
    /// [`IcePolicy::Required`]: crate::IcePolicy::Required
    #[cfg(feature = "ice")]
    fn ice_for(
        &mut self,
        call: CallHandle,
        plan: &MediaPlan,
        now: Instant,
    ) -> Result<Option<crate::ice::Ice>, MediaError> {
        // a call described with a relay kept the agent that holds it; any
        // way out of here that does not run it gives the relay back, since a
        // stream on `c=`/`m=` and symmetric RTP has no use for one
        let mut held = self.gathered.remove(&call);
        let built = self.build_ice(call, plan, &mut held, now);
        if let Some(mut unused) = held {
            for (destination, payload) in unused.release(now) {
                self.farewells.push_back((call, destination, payload));
            }
        }
        built
    }

    /// [`MediaEngine::ice_for`]'s decision, running `held` when the call has
    /// one and taking it out of the option only when it is the agent
    /// returned.
    ///
    /// # Errors
    ///
    /// As [`MediaEngine::ice_for`].
    #[cfg(feature = "ice")]
    fn build_ice(
        &mut self,
        call: CallHandle,
        plan: &MediaPlan,
        held: &mut Option<crate::ice::Ice>,
        now: Instant,
    ) -> Result<Option<crate::ice::Ice>, MediaError> {
        let Some(managed) = self.calls.get(&call) else {
            return Ok(None);
        };
        let Some(local) = managed.ice.clone() else {
            return Ok(None);
        };
        let required = managed.catalog.ice().requires();
        let refuse = |()| {
            if required {
                Err(MediaError::IceRequired)
            } else {
                Ok(None)
            }
        };
        let (Some(address), Some(remote)) = (managed.address, managed.remote.as_ref()) else {
            return refuse(());
        };
        let Some(stream) = remote.media.iter().find(|media| !media.is_rejected()) else {
            return refuse(());
        };
        // whether the peer does ICE at all is asked first, and before
        // anything is held against it. A peer that described none did not
        // "take `a=rtcp-mux` out of an ICE answer" — it answered a call it
        // never agreed to run this way, and `a=rtcp-mux` is a thing such a
        // peer does not ask for either. Complaining about the multiplexing
        // there would report the second-order fault and hide the first
        let Some(peer) = sipral_nat::ice::parse_remote(remote, stream) else {
            return refuse(());
        };
        let muxed = matches!(plan.rtcp, RtcpPlan::Muxed | RtcpPlan::Off);
        // two lite ends: neither checks, so there is no pair to wait for, and
        // RFC 8445 §6.1.1 leaves both on the default candidates — which is
        // `c=`/`m=` and symmetric RTP here, the same fallback as a peer that
        // does no ICE at all
        if (local.is_lite() && peer.lite)
            || peer.mismatch
            || peer.candidates.is_empty()
            || sipral_nat::ice::ice_mismatch(remote, stream, &peer, muxed)
        {
            return refuse(());
        }
        // and only now: a peer that did agree to ICE and took `a=rtcp-mux`
        // out left this stream a second ICE component, and this facade knows
        // one local address. The offer asked for multiplexing —
        // `CodecCatalog::capabilities` makes an ICE policy force it — so this
        // is a peer that answered something else
        if matches!(plan.rtcp, RtcpPlan::SeparatePort { .. }) {
            return Err(MediaError::IceNeedsRtcpMux);
        }
        let mut ice = if let Some(ice) = held.take() {
            ice
        } else {
            let seed = self.keys.block();
            local.agent(address, seed, now)?
        };
        if let Err(error) = ice.set_remote(&peer, now) {
            *held = Some(ice);
            return Err(error);
        }
        Ok(Some(ice))
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
        // the certificate the call's own description named, whatever this
        // engine presents to calls described since
        let identity = self.identity_for(Some(call), now)?;
        crate::dtls::Handshake::start(&identity, keying, side.party(), ours, &mut self.keys, now)
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
    #[cfg(any(feature = "dtls", feature = "ice"))]
    #[must_use]
    pub fn poll_transmit(&mut self, now: Instant) -> Option<(CallHandle, SocketAddr, Vec<u8>)> {
        for (call, held) in &self.sessions {
            let mut slot = share::lock(held);
            if let Some(datagram) = slot.session.poll_transmit(now) {
                return Some((*call, datagram.destination, datagram.payload.to_vec()));
            }
        }
        // a call described with a relay and still waiting for its session:
        // the keepalives that hold the NAT binding towards the TURN server
        #[cfg(feature = "ice")]
        for (call, ice) in &mut self.gathered {
            if let Some(destination) = ice.take_probe() {
                return Some((*call, destination, ice.probe().to_vec()));
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
    /// [`MediaError::Signalling`] when the user agent refuses the call. A
    /// relay `media` carried then comes back from
    /// [`MediaEngine::poll_returned_relay`].
    pub fn place_with(
        &mut self,
        agent: &mut UserAgent,
        account: AccountId,
        outgoing: OutgoingCall,
        local: SocketAddr,
        media: CallMedia,
        now: Instant,
    ) -> Result<CallHandle, MediaError> {
        let (media, mut handed) = media.handing_over();
        let placed = self.place_handed(agent, account, outgoing, local, media, &mut handed, now);
        self.hand_back(handed);
        placed
    }

    /// [`MediaEngine::place_with`], with the relay the call was handed in
    /// `handed` for as long as the call can still be refused.
    #[allow(clippy::too_many_arguments)]
    fn place_handed(
        &mut self,
        agent: &mut UserAgent,
        account: AccountId,
        outgoing: OutgoingCall,
        local: SocketAddr,
        media: CallMedia,
        handed: &mut Handed,
        now: Instant,
    ) -> Result<CallHandle, MediaError> {
        let CallMedia {
            catalog,
            config,
            public,
            ..
        } = media;
        let public = public.or_else(|| handed.mapped());
        let catalog = CallMedia::offering(catalog, public);
        let (identity, session_id) = draw(agent);
        // drawn after the identity, so that the same call placed with and
        // without SDES starts from the same SSRC and the same sequence number
        let keys = catalog.srtp().offers().then(|| draw_key(&mut self.keys));
        let dtls = self.dtls_lines(&catalog, Side::Offering, None, None, now)?;
        let ice = self.first_ice(None, &catalog, local, public, handed, true, now)?;
        let described = public.unwrap_or(local);
        let mut offer = write_offer(
            &catalog,
            described,
            session_id,
            1,
            keys,
            keyed(dtls.as_ref()),
        );
        describe_ice(&mut offer, ice.as_ref(), None);
        let dtls = dtls.map(|(_, setup)| (Side::Offering, setup));
        let placing = outgoing.offer(Arc::from(offer.to_bytes()));
        let call = agent.call(account, &placing, now)?;
        self.keep(call, handed, now);
        self.calls.insert(
            call,
            Managed {
                local: Some(offer),
                remote: None,
                address: Some(local),
                public,
                identity,
                session_id,
                version: 1,
                catalog,
                config,
                #[cfg(feature = "dtls")]
                dtls_identity: self.named(dtls.is_some()),
                dtls,
                #[cfg(feature = "ice")]
                ice,
                // an outgoing call rings the far end's phone, not this one's
                rung_with_media: false,
                payloads: Payloads::default(),
                pending: None,
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
    /// [`MediaError::Signalling`] when the user agent refuses the call. A
    /// relay `media` carried then comes back from
    /// [`MediaEngine::poll_returned_relay`].
    pub fn accept_transfer_with(
        &mut self,
        agent: &mut UserAgent,
        call: CallHandle,
        local: SocketAddr,
        extra: OutgoingExtras<'_>,
        media: CallMedia,
        now: Instant,
    ) -> Result<CallHandle, MediaError> {
        let (media, mut handed) = media.handing_over();
        let placed = self.transfer_handed(agent, call, local, extra, media, &mut handed, now);
        self.hand_back(handed);
        placed
    }

    /// [`MediaEngine::accept_transfer_with`], with the relay the call was
    /// handed in `handed` for as long as the call can still be refused.
    #[allow(clippy::too_many_arguments)]
    fn transfer_handed(
        &mut self,
        agent: &mut UserAgent,
        call: CallHandle,
        local: SocketAddr,
        extra: OutgoingExtras<'_>,
        media: CallMedia,
        handed: &mut Handed,
        now: Instant,
    ) -> Result<CallHandle, MediaError> {
        let CallMedia {
            catalog,
            config,
            public,
            ..
        } = media;
        let public = public.or_else(|| handed.mapped());
        let catalog = CallMedia::offering(catalog, public);
        let (identity, session_id) = draw(agent);
        let keys = catalog.srtp().offers().then(|| draw_key(&mut self.keys));
        let dtls = self.dtls_lines(&catalog, Side::Offering, None, None, now)?;
        let ice = self.first_ice(None, &catalog, local, public, handed, true, now)?;
        let described = public.unwrap_or(local);
        let mut offer = write_offer(
            &catalog,
            described,
            session_id,
            1,
            keys,
            keyed(dtls.as_ref()),
        );
        describe_ice(&mut offer, ice.as_ref(), None);
        let dtls = dtls.map(|(_, setup)| (Side::Offering, setup));
        let new = agent.accept_transfer(call, Some(Arc::from(offer.to_bytes())), extra, now)?;
        self.keep(new, handed, now);
        self.calls.insert(
            new,
            Managed {
                local: Some(offer),
                remote: None,
                address: Some(local),
                public,
                identity,
                session_id,
                version: 1,
                catalog,
                config,
                #[cfg(feature = "dtls")]
                dtls_identity: self.named(dtls.is_some()),
                dtls,
                #[cfg(feature = "ice")]
                ice,
                // an outgoing call rings the far end's phone, not this one's
                rung_with_media: false,
                payloads: Payloads::default(),
                pending: None,
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
    /// send it over. Whichever it is, a relay `media` carried comes back from
    /// [`MediaEngine::poll_returned_relay`].
    pub fn ring_with(
        &mut self,
        agent: &mut UserAgent,
        call: CallHandle,
        local: SocketAddr,
        media: CallMedia,
        now: Instant,
    ) -> Result<(), MediaError> {
        let (media, mut handed) = media.handing_over();
        let rung = self.ring_handed(agent, call, local, media, &mut handed, now);
        self.hand_back(handed);
        rung
    }

    /// [`MediaEngine::ring_with`], with the relay the call was handed in
    /// `handed` for as long as the ring can still be refused.
    fn ring_handed(
        &mut self,
        agent: &mut UserAgent,
        call: CallHandle,
        local: SocketAddr,
        media: CallMedia,
        handed: &mut Handed,
        now: Instant,
    ) -> Result<(), MediaError> {
        let CallMedia {
            catalog,
            config,
            public,
            ..
        } = media;
        let public = public.or_else(|| handed.mapped());
        let catalog = CallMedia::offering(catalog, public);
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
        let dtls = self.dtls_lines(&catalog, Side::Answering, Some(&offer), None, now)?;
        let ice = self.first_ice(Some(call), &catalog, local, public, handed, false, now)?;
        let mut description = write_answer(
            &catalog,
            &offer,
            public.unwrap_or(local),
            session_id,
            version,
            keys.as_ref(),
            keyed(dtls.as_ref()),
        )?;
        describe_ice(&mut description, ice.as_ref(), Some(&offer));
        let bytes = description.to_bytes();
        agent.ring(call, Some(Arc::from(bytes)), now)?;
        self.keep(call, handed, now);
        #[cfg(feature = "dtls")]
        let named = self.named(dtls.is_some());
        if let Some(managed) = self.calls.get_mut(&call) {
            managed.local = Some(description);
            managed.address = Some(local);
            managed.public = public;
            managed.version = version;
            managed.catalog = catalog;
            managed.config = config;
            #[cfg(feature = "dtls")]
            {
                managed.dtls_identity = managed.dtls_identity.take().or(named);
            }
            managed.dtls = dtls.map(|(_, setup)| (Side::Answering, setup));
            #[cfg(feature = "ice")]
            {
                managed.ice = ice;
            }
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
        let (media, mut handed) = media.handing_over();
        let answered = self.answer_handed(agent, call, local, media, &mut handed, now);
        self.hand_back(handed);
        answered
    }

    /// [`MediaEngine::answer_with`], with the relay the call was handed in
    /// `handed` for as long as the answer can still be refused.
    fn answer_handed(
        &mut self,
        agent: &mut UserAgent,
        call: CallHandle,
        local: SocketAddr,
        media: CallMedia,
        handed: &mut Handed,
        now: Instant,
    ) -> Result<(), MediaError> {
        let managed = self.calls.get(&call).ok_or(MediaError::NoSuchCall)?;
        if managed.rung_with_media {
            // the call was described when it rang, relay and all; a second
            // one handed in here has nothing to be and goes back
            handed.unusable();
            self.keep(call, handed, now);
            return self.answer_after_ring(agent, call, now);
        }
        let CallMedia {
            catalog,
            config,
            public,
            ..
        } = media;
        let public = public.or_else(|| handed.mapped());
        let catalog = CallMedia::offering(catalog, public);
        let described = public.unwrap_or(local);
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
        let dtls = self.dtls_lines(&catalog, side, offered.as_ref(), None, now)?;
        let ice = self.first_ice(
            Some(call),
            &catalog,
            local,
            public,
            handed,
            offered.is_none(),
            now,
        )?;
        let mut description = match offered.as_ref() {
            Some(offer) => write_answer(
                &catalog,
                offer,
                described,
                session_id,
                version,
                keys.as_ref(),
                keyed(dtls.as_ref()),
            )?,
            None => write_offer(
                &catalog,
                described,
                session_id,
                version,
                keys,
                keyed(dtls.as_ref()),
            ),
        };
        describe_ice(&mut description, ice.as_ref(), offered.as_ref());
        let bytes = description.to_bytes();
        agent.answer(call, Some(Arc::from(bytes)), now)?;
        self.keep(call, handed, now);
        #[cfg(feature = "dtls")]
        let named = self.named(dtls.is_some());
        if let Some(managed) = self.calls.get_mut(&call) {
            managed.local = Some(description);
            managed.address = Some(local);
            managed.public = public;
            managed.version = version;
            managed.catalog = catalog;
            managed.config = config;
            #[cfg(feature = "dtls")]
            {
                managed.dtls_identity = managed.dtls_identity.take().or(named);
            }
            managed.dtls = dtls.map(|(_, setup)| (side, setup));
            #[cfg(feature = "ice")]
            {
                managed.ice = ice;
            }
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

// -- changing a call in progress ---------------------------------------------

impl MediaEngine {
    /// Offer a call again on `codecs`, in that order, instead of the list it
    /// was placed or answered with (RFC 3264 §8.3.2).
    ///
    /// Only the codecs change. Everything else is the description this end
    /// last wrote for the call, carried across as it was: the media address,
    /// the transport profile, the SRTP key or the DTLS fingerprint, the ICE
    /// credentials and candidates, multiplexing. So the answer re-keys
    /// nothing, restarts no handshake and no connectivity check, and moves
    /// nothing the call did not ask to move — a key drawn afresh here would
    /// be a re-key nobody asked for, and a fingerprint written afresh would
    /// be one RFC 8842 §3.1 reads as a new DTLS association. It is also what
    /// a hold does, which is the other re-offer this end sends.
    ///
    /// The one line that is rewritten is `a=setup`, which goes as `actpass`
    /// whatever role the call has (RFC 8842 §5.5): the last description may
    /// have been an answer. An answer that keeps the association comes back
    /// with the roles already in force (§5.3), and one that takes the other
    /// role is refused by name — [`MediaError::DtlsRoleChanged`] — with the
    /// stream left on the association it has.
    ///
    /// Which way the call flows is the user agent's to write
    /// ([`UserAgent::change_formats`]): a call held here stays held through
    /// the change, and [`UserAgent::resume`] takes it off hold on the new
    /// list. Every dynamic payload type keeps the codec it has named on this
    /// call, from either end, and a codec new to it gets a number nothing has
    /// had — the MUST in §8.3.2 that an offer numbered from the catalogue
    /// alone would break the moment a codec left the front of the list.
    ///
    /// The list is this call's own once the far end accepts it, and a
    /// refusal leaves the call on the list it had, as RFC 3261 §14.1 leaves
    /// the session. What the answer settled on arrives the way any
    /// renegotiation's does: [`MediaEvent::Changed`], carrying the codec.
    ///
    /// # Errors
    /// [`MediaError::NoSuchCall`] for a call this engine does not manage;
    /// [`MediaError::NoDescription`] before this end has described it;
    /// [`MediaError::StreamRefused`] for a call whose stream was refused,
    /// which a change of codecs does not bring back; what
    /// [`CodecCatalog::with_codecs`] refuses; [`MediaError::NoPayloadType`];
    /// and [`MediaError::Signalling`] when the user agent will not send it —
    /// [`UaError::ChangeInProgress`] while another change is on its way,
    /// chiefly.
    pub fn change_codecs(
        &mut self,
        agent: &mut UserAgent,
        call: CallHandle,
        codecs: &[&str],
        now: Instant,
    ) -> Result<(), MediaError> {
        let managed = self.calls.get(&call).ok_or(MediaError::NoSuchCall)?;
        let catalog = managed.catalog.clone().with_codecs(codecs)?;
        let mut offer = managed.local.clone().ok_or(MediaError::NoDescription)?;
        let mut payloads = managed.payloads.clone();
        if let Some(remote) = managed.remote.as_ref() {
            payloads.note(remote);
        }
        payloads.note(&offer);
        let version = managed.version.saturating_add(1);

        let stream = offer
            .media
            .iter_mut()
            .find(|stream| stream.media == AUDIO && !stream.is_rejected())
            .ok_or(MediaError::StreamRefused)?;
        let mut written = catalog
            .capabilities()
            .offer(AUDIO, stream.port, Direction::SendRecv);
        payloads.renumber(&mut written)?;
        let codec_line =
            |attribute: &Attribute| attribute.name == "rtpmap" || attribute.name == "fmtp";
        stream.attributes.retain(|attribute| !codec_line(attribute));
        let lines: Vec<Attribute> = written
            .attributes
            .into_iter()
            .filter(|attribute| codec_line(attribute))
            .collect();
        stream.attributes.splice(0..0, lines);
        stream.formats = written.formats;
        let formats = stream.formats.clone();
        for stream in &mut offer.media {
            stream.offer_roles_again();
        }
        offer.origin.version = version;

        agent.change_formats(call, &offer.to_bytes(), now)?;
        // bound from the moment it is written, whatever the far end says
        payloads.note(&offer);
        if let Some(managed) = self.calls.get_mut(&call) {
            managed.payloads = payloads;
            managed.pending = Some(Pending { catalog, formats });
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
        // and the agents of calls described with a relay that have no
        // session yet: the keepalive towards the TURN server is on their
        // clock, and what it sends comes out of `poll_transmit`
        #[cfg(feature = "ice")]
        for ice in self.gathered.values_mut() {
            ice.top_up();
            ice.handle_timeout(now);
        }
    }

    /// When to call [`MediaEngine::handle_timeout`] or
    /// [`MediaEngine::poll_rtcp`], if nothing arrives first.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        let sessions = self
            .sessions
            .values()
            .filter_map(|held| share::lock(held).session.poll_timeout())
            .min();
        #[cfg(feature = "ice")]
        let waiting = self
            .gathered
            .values()
            .filter_map(crate::ice::Ice::deadline)
            .min();
        #[cfg(not(feature = "ice"))]
        let waiting = None;
        [sessions, waiting].into_iter().flatten().min()
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
    ///
    /// A call given a relay ([`CallMedia::relay`]) gives it back here too:
    /// the Refresh with a lifetime of zero that deletes the allocation (RFC
    /// 8656 §8), addressed to the TURN server, when the call ends — whether
    /// or not its session ever opened — or as soon as the call is known not
    /// to use it.
    #[must_use]
    pub fn poll_farewell(&mut self) -> Option<(CallHandle, SocketAddr, Vec<u8>)> {
        self.farewells.pop_front()
    }

    /// A relay handed to a call ([`CallMedia::relay`]) whose description was
    /// refused before there was a call to hold it, handed back whole and
    /// still live on its server.
    ///
    /// Nothing that named it left: the description that did was refused, so
    /// no peer was offered it and nothing about it has to be undone. Given
    /// to [`Relays::put_back`](crate::Relays::put_back) it is kept alive for
    /// the socket it was allocated from ([`crate::Relay::local`]) and handed
    /// to the next call there, as if it had never been taken. One at a time,
    /// like every other poll here; ask after any of
    /// [`MediaEngine::place_with`], [`MediaEngine::accept_transfer_with`],
    /// [`MediaEngine::ring_with`] and [`MediaEngine::answer_with`] answers
    /// with an error. A relay nobody asks for is refreshed by nothing, and
    /// lapses at its server in the lifetime it was granted.
    #[cfg(feature = "ice")]
    #[must_use]
    pub fn poll_returned_relay(&mut self) -> Option<crate::Relay> {
        self.returned.pop_front()
    }

    /// What a call described with a relay, and still waiting for its session,
    /// has to send: the Binding indications that keep the NAT binding
    /// towards the TURN server open, and the refresh that keeps the
    /// allocation, each with the socket to send it from.
    ///
    /// The same datagrams [`MediaEngine::poll_transmit`] hands out for such a
    /// call, for an application that drives each session through its own
    /// [`SessionShare`] and so never calls that — the C ABI is one — and has
    /// no session yet to ask for this one. Once the session opens, the agent
    /// is the session's and sends through it. One at a time; loop until
    /// `None` after [`MediaEngine::handle_timeout`] and after
    /// [`MediaEngine::receive_waiting`].
    #[cfg(feature = "ice")]
    #[must_use]
    pub fn poll_waiting_transmit(&mut self) -> Option<(CallHandle, crate::RelayDatagram)> {
        for (call, ice) in &mut self.gathered {
            if let Some(destination) = ice.take_probe() {
                return Some((
                    *call,
                    crate::RelayDatagram {
                        local: ice.local(),
                        destination,
                        payload: ice.probe().to_vec(),
                    },
                ));
            }
        }
        None
    }

    /// Hand in a datagram that arrived on `local` from `from` while a call
    /// described there with a relay is still waiting for its session, and
    /// say whether it was for that call's agent — the TURN server's answer
    /// to a refresh above all, without which the allocation is lost to a
    /// phone that rings for longer than its lifetime less a minute.
    ///
    /// Every other datagram on the socket is a session's, or a
    /// [`Relays`](crate::Relays)' or a [`Mappings`](crate::Mappings)' before
    /// any call was described there, and `false` leaves it for them. The
    /// agent decides what is its own exactly as it does once the session is
    /// open: from its TURN server, only answers to requests it sent.
    #[cfg(feature = "ice")]
    pub fn receive_waiting(
        &mut self,
        local: SocketAddr,
        from: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> bool {
        for ice in self.gathered.values_mut() {
            if ice.local() != local {
                continue;
            }
            ice.top_up();
            if matches!(
                ice.handle_datagram(from, data, now),
                crate::ice::Taken::Consumed
            ) {
                return true;
            }
        }
        false
    }

    /// Hand in a datagram that arrived on `local`, the socket a call was
    /// described on, from `from`, before the application reads that socket
    /// through the call's own session, and say whether the call took it.
    ///
    /// For an application that reads a call's socket before it holds the
    /// call's [`SessionShare`] — the C ABI's loop, which hands everything
    /// arriving on a media socket to the stack until the call's media handle
    /// exists, since a relay's refresh is answered there. The far end starts
    /// its connectivity checks the moment it sends its answer, so the first
    /// of them can reach this end's socket before the answer does, or between
    /// the session opening and the application taking its share. Refused
    /// there, they are gone: the far end sends a check again no sooner than
    /// half a second later (RFC 8445 §14.3), and until one gets through, or
    /// this end's own checks get round to the pair, the far end has no pair
    /// proved to send its audio on. Kept, they are answered as RFC 8445 §7.3
    /// asks of a check that arrives before the agent has the peer's
    /// candidates.
    ///
    /// In this order, the first that takes it:
    ///
    /// - the agent of a call described there with a relay and still waiting
    ///   for its session, as [`MediaEngine::receive_waiting`] — which answers
    ///   the far end's checks itself, as well as its TURN server;
    /// - the session of a call described there that has one: everything goes
    ///   to it, audio and checks alike, exactly as through the share, and
    ///   `false` is a datagram the session dropped;
    /// - a call described there using ICE that has no session yet: a Binding
    ///   request whose `USERNAME` names this call's fragment and whose
    ///   `MESSAGE-INTEGRITY` checks out under the password its description
    ///   gave out is kept, the newest sixteen for the socket, and handed to
    ///   the session's agent the moment the session opens, which answers it
    ///   and checks back on the same pair. One kept longer than the far end's
    ///   transaction for it lasts, 39.5 seconds, is dropped instead, and so is
    ///   everything kept for a call that ends first. Anything else is not the
    ///   call's.
    ///
    /// `false` leaves the datagram for whoever else the socket answers to —
    /// a [`Mappings`](crate::Mappings) or a [`Relays`](crate::Relays)
    /// transaction — and is otherwise a datagram nobody wanted.
    pub fn receive_early(
        &mut self,
        local: SocketAddr,
        from: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> bool {
        #[cfg(feature = "ice")]
        if self.receive_waiting(local, from, data, now) {
            return true;
        }
        let open = self.calls.iter().find_map(|(call, managed)| {
            (managed.address == Some(local))
                .then(|| self.sessions.get(call))
                .flatten()
        });
        if let Some(held) = open {
            let mut datagram = data.to_vec();
            let arrival = share::lock(held).session.receive(&mut datagram, from, now);
            return !matches!(
                arrival,
                crate::session::Arrival::Dropped(_) | crate::session::Arrival::ControlRefused
            );
        }
        #[cfg(feature = "ice")]
        {
            self.keep_early(local, from, data, now)
        }
        #[cfg(not(feature = "ice"))]
        {
            false
        }
    }

    /// Keep a connectivity check for the call described on `local` that has
    /// no session yet, when it is one ([`MediaEngine::receive_early`]).
    #[cfg(feature = "ice")]
    fn keep_early(
        &mut self,
        local: SocketAddr,
        from: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> bool {
        let for_a_call = self.calls.iter().any(|(call, managed)| {
            managed.address == Some(local)
                && !self.sessions.contains_key(call)
                && managed
                    .ice
                    .as_ref()
                    .is_some_and(|ice| ice.is_check_for(data))
        });
        if !for_a_call {
            return false;
        }
        let check = EarlyCheck {
            from,
            data: data.to_vec(),
            at: now,
        };
        let kept = self.early.entry(local).or_default();
        kept.retain(|held| held.transaction() != check.transaction());
        while kept.len() >= EARLY_CHECKS {
            kept.pop_front();
        }
        kept.push_back(check);
        true
    }

    /// Hand a session that has just opened the checks kept for its socket
    /// before it did and still worth answering, when it runs ICE; the kept
    /// checks go either way, since they were for this session or for nobody.
    #[cfg(feature = "ice")]
    fn replay_early(&mut self, call: CallHandle, now: Instant) {
        let Some(address) = self.calls.get(&call).and_then(|managed| managed.address) else {
            return;
        };
        let Some(kept) = self.early.remove(&address) else {
            return;
        };
        let Some(held) = self.sessions.get(&call) else {
            return;
        };
        let mut slot = share::lock(held);
        if !slot.session.runs_ice() {
            return;
        }
        for mut check in kept {
            if check.live(now) {
                let _ = slot.session.receive(&mut check.data, check.from, now);
            }
        }
    }

    /// Without the feature no check was kept.
    #[cfg(not(feature = "ice"))]
    #[allow(clippy::unused_self)]
    const fn replay_early(&mut self, _call: CallHandle, _now: Instant) {}

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
                #[cfg(feature = "ice")]
                self.claim_relay(*call, agent);
                self.take_body(*call, response.as_ref(), now);
            }
            UaEvent::SessionChanged {
                call,
                local,
                remote,
                ..
            } => self.redescribed(*call, local.as_deref(), remote.as_deref(), now),
            UaEvent::Reoffer { call, request } => self.answer_reoffer(*call, request, agent, now),
            // §14.1: the session stands exactly as it was, so the list it
            // stands on is the one it had. A 491 is going out again by
            // itself, and the change is still on its way.
            UaEvent::SessionChangeFailed {
                call,
                retry_in: None,
                ..
            } => {
                if let Some(managed) = self.calls.get_mut(call) {
                    managed.pending = None;
                }
            }
            UaEvent::CallEnded { call, .. } => self.release(*call, agent, now),
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
                public: None,
                identity,
                session_id,
                version: 1,
                catalog: self.catalog.clone(),
                config: self.config.clone(),
                // nothing has been written for this call yet: what it will
                // say about DTLS-SRTP, and about ICE, is decided when it is
                // rung or answered
                dtls: None,
                #[cfg(feature = "dtls")]
                dtls_identity: None,
                #[cfg(feature = "ice")]
                ice: None,
                rung_with_media: false,
                payloads: Payloads::default(),
                pending: None,
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
        #[cfg(feature = "ice")]
        {
            let first = self.branches.get(&call).copied().unwrap_or(call);
            self.branches.insert(sibling, first);
        }
    }

    /// A branch a proxy forked off was answered and kept: when the agent
    /// holding the relay the offer named is still waiting on another branch
    /// that has no session, it moves to this one.
    ///
    /// One offer went to every branch, with one relayed candidate in it, and
    /// one allocation stands behind that candidate: the server relays for the
    /// one client that holds it, so only one branch's agent can answer the
    /// checks the candidate draws. It waits with the branch the call was
    /// placed on, the one whose early media runs on it, and goes to the first
    /// other branch that is answered and kept before that one has opened a
    /// session — two phones ringing and the second picked up, which
    /// [`ForkPolicy::KeepFirst`] keeps as surely as `KeepAll` does. The user
    /// agent reports that branch up before it ends the one the call was
    /// placed on, so the relay has moved by the time that ending would give
    /// it back. A branch that answers after another was kept never becomes a
    /// call.
    ///
    /// [`ForkPolicy::KeepFirst`]: sipral_ua::ForkPolicy::KeepFirst
    #[cfg(feature = "ice")]
    fn claim_relay(&mut self, call: CallHandle, agent: &UserAgent) {
        let Some(first) = self.branches.get(&call).copied() else {
            return;
        };
        if self.gathered.contains_key(&call)
            || self.sessions.contains_key(&call)
            || agent.call_state(call) != Some(CallState::Confirmed)
        {
            return;
        }
        let holder = std::iter::once(first)
            .chain(
                self.branches
                    .iter()
                    .filter(|(_, root)| **root == first)
                    .map(|(branch, _)| *branch),
            )
            .find(|branch| *branch != call && self.gathered.contains_key(branch));
        if let Some(ice) = holder.and_then(|holder| self.gathered.remove(&holder)) {
            self.gathered.insert(call, ice);
        }
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
        // a call the application describes runs its own audio: settling a
        // plan for it here would open a second stream on it, with this
        // engine's own numbers, beside the one the application is running
        if managed.address.is_none() {
            return;
        }
        if let Some(described) = local.and_then(|bytes| parse(bytes).ok()) {
            managed.version = managed.version.max(described.origin.version);
            // the change this end offered, accepted: the list it named is
            // this call's own from here on, and the plan below is worked out
            // against it
            if managed
                .pending
                .as_ref()
                .is_some_and(|pending| Some(&pending.formats) == live_formats(&described))
                && let Some(pending) = managed.pending.take()
            {
                managed.catalog = pending.catalog;
            }
            managed.local = Some(described);
        }
        if let Some(described) = remote.and_then(|bytes| parse(bytes).ok()) {
            managed.remote = Some(described);
        }
        self.settle(call, now);
    }

    /// The far end offered something the user agent has no policy for: a
    /// codec change, or anything at all on a secured stream — a hold and a
    /// session refresh among them, since their answers need this end's key or
    /// its certificate and role, which the user agent does not hold. It has
    /// one here: the same answer any offer gets, keyed the way the call
    /// already is.
    ///
    /// Only on a call this engine describes. One the application answered
    /// with a description of its own is left alone: the event goes on to the
    /// application untouched, which holds the only description there is and
    /// answers with `UserAgent::accept_reoffer`. Refusing it here instead
    /// would answer 488 to every hold the far end puts on such a call — every
    /// re-offer on a secured one is handed up — and leave the application's
    /// own answer failing for want of a request to answer.
    fn answer_reoffer(
        &mut self,
        call: CallHandle,
        request: &OwnedMessage,
        agent: &mut UserAgent,
        now: Instant,
    ) {
        let offered = body_description(Some(request));
        let Some(managed) = self.calls.get_mut(&call) else {
            return;
        };
        let Some(address) = managed.address else {
            return;
        };
        let public = managed.public;
        // §8.3.2 binds a number from the moment either end writes it, and an
        // offer about to be refused was still written
        if let Some(offer) = offered.as_ref() {
            managed.payloads.note(offer);
        }
        let Some(offer) = offered else {
            // an offer this engine cannot answer is refused rather than left
            // to be retransmitted until the call dies
            let _ = agent.reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
            return;
        };
        let version = managed.version.saturating_add(1);
        let session_id = managed.session_id;
        let catalog = managed.catalog.clone();
        // RFC 4568 §7.1.4 lets an answerer change its master key and warns in
        // the same breath that "the offerer will not be able to process
        // packets secured via this master key until the answer is received".
        // A hold, a resume or a session refresh is no reason to open that
        // window, so the answer repeats the key this end already sends under,
        // and one is drawn only where there is none to repeat
        let in_force = managed
            .local
            .as_ref()
            .and_then(live_stream)
            .and_then(keying::key_in_force);
        // a live call that required SRTP and is re-offered a stream without
        // it is where a silent downgrade would happen, so it is where the
        // refusal has to be
        if !keying_allows(&catalog, Some(&offer)) {
            self.events
                .push_back((call, MediaEvent::Failed(MediaError::SrtpRequired)));
            let _ = agent.reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
            return;
        }
        // RFC 8842 §5.3: an answerer that will not start the new association
        // an offer asks for refuses the offer, and the session stands (RFC
        // 3261 §14.2). Answering it and then declining to follow is the
        // other thing a stack could do, and it leaves the far end on an
        // association this end never joined
        #[cfg(feature = "dtls")]
        if let Err(error) = self.keeps_certificate(call, &offer) {
            self.events.push_back((call, MediaEvent::Failed(error)));
            let _ = agent.reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
            return;
        }
        let keys = will_key(&catalog, Some(&offer))
            .then(|| in_force.unwrap_or_else(|| draw_key(&mut self.keys)));
        let dtls = match self.dtls_lines(&catalog, Side::Answering, Some(&offer), Some(call), now) {
            Ok(lines) => lines,
            Err(error) => {
                self.events.push_back((call, MediaEvent::Failed(error)));
                let _ = agent.reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
                return;
            }
        };
        let ice = match self.reoffer_ice(call, &catalog, (address, public), &offer, now) {
            Ok(ice) => ice,
            Err(error) => {
                self.events.push_back((call, MediaEvent::Failed(error)));
                let _ = agent.reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
                return;
            }
        };
        match write_answer(
            &catalog,
            &offer,
            public.unwrap_or(address),
            session_id,
            version,
            keys.as_ref(),
            keyed(dtls.as_ref()),
        ) {
            // RFC 3261 §14.2: "If the new session description is not
            // acceptable, the UAS can reject it by returning a 488", and the
            // session stands exactly as it was. Answering with every stream
            // refused would be accepting it instead — and a call whose one
            // stream is refused carries no audio for the rest of its life,
            // over a codec the far end merely proposed. An offer that took
            // the stream away itself is still answered: that one asked for it
            Ok(answer)
                if offer.media.iter().any(|stream| !stream.is_rejected())
                    && answer.media.iter().all(MediaDescription::is_rejected) =>
            {
                let _ = agent.reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
            }
            Ok(mut answer) => {
                // RFC 8839 §4.4: an answer that left the attributes out is a
                // peer reading that ICE has been withdrawn mid-session
                describe_ice(&mut answer, ice.as_ref(), Some(&offer));
                // the plan this answer would settle, read the way `settle`
                // will read it: a running stream cannot change the kind of
                // keying it runs under, so a re-offer asking for that is
                // refused here, with the session standing, rather than
                // answered and then not followed
                if self.changes_keying(call, &answer, &offer) {
                    self.events
                        .push_back((call, MediaEvent::Failed(MediaError::KeyingChanged)));
                    let _ = agent.reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
                    return;
                }
                #[cfg(feature = "dtls")]
                let named = self.named(dtls.is_some());
                let bytes = answer.to_bytes();
                if agent.accept_reoffer(call, Some(&bytes), now).is_ok()
                    && let Some(managed) = self.calls.get_mut(&call)
                {
                    managed.version = version;
                    #[cfg(feature = "dtls")]
                    {
                        managed.dtls_identity = managed.dtls_identity.take().or(named);
                    }
                    managed.dtls = dtls.map(|(_, setup)| (Side::Answering, setup));
                    #[cfg(feature = "ice")]
                    {
                        managed.ice = ice;
                    }
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

    /// The call is over: let the stream go, close any recording, say what
    /// it cost, and publish the RFC 6035 report the account may have asked
    /// for.
    fn release(&mut self, call: CallHandle, agent: &mut UserAgent, now: Instant) {
        // a call that ends while joined takes the pair down with it: the
        // partner is told with `MediaEvent::Unjoined` because nothing else
        // ever will be, and it is told before anything else about this call
        // so it never reaches `MediaEngine::mix` with a partner already gone
        if let Some(partner) = self.joins.remove(&call) {
            self.joins.remove(&partner);
            self.events.push_back((partner, MediaEvent::Unjoined));
        }
        let address = self.calls.remove(&call).and_then(|managed| managed.address);
        // checks kept for a socket no call is described on any more were for
        // the call that just ended, or for nobody
        #[cfg(feature = "ice")]
        if let Some(address) = address
            && !self
                .calls
                .values()
                .any(|managed| managed.address == Some(address))
        {
            self.early.remove(&address);
        }
        #[cfg(not(feature = "ice"))]
        let _ = address;
        // a call that ends before its session opened — cancelled while it
        // rang, refused, never answered — still holds the relay it was
        // described with, and the server would hold it for minutes more
        #[cfg(feature = "ice")]
        {
            self.let_go(call, now);
            self.branches.remove(&call);
        }
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
            while let Some(datagram) = session.poll_transmit(now) {
                self.farewells
                    .push_back((call, datagram.destination, datagram.payload.to_vec()));
            }
        }
        // and last, because the goodbyes above may have left through it: the
        // relay goes back to its server (RFC 8656 §8), rather than holding a
        // port and the account's quota there until its lifetime runs out
        #[cfg(feature = "ice")]
        for (destination, payload) in session.release_relays(now) {
            self.farewells.push_back((call, destination, payload));
        }
        // Best effort, and never fatal: a call that has already ended is
        // not going to un-end because a collector could not be reached.
        // `Ok(false)` is `send_quality_report`'s own silent no-op for an
        // account that named no collector, which raises nothing here
        // either — there was never an attempt for the application to hear
        // about.
        if let Some(metrics) = session.quality_report_metrics(now) {
            match agent.send_quality_report(call, &metrics, now) {
                Ok(true) => self
                    .events
                    .push_back((call, MediaEvent::QualityReportSent { ok: true })),
                Ok(false) => {}
                Err(_) => self
                    .events
                    .push_back((call, MediaEvent::QualityReportSent { ok: false })),
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
        if let Some(managed) = self.calls.get_mut(&call) {
            managed.note_payloads();
        }
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
        let annex_b = annex_b_in_use(&managed.catalog, local, remote, &plan);
        // D5: recorded here, at the point the negotiation is worked out, from
        // the far end's own description and this call's own catalogue —
        // never reconstructed later from state that may have moved on
        let candidates = remote
            .media
            .first()
            .map_or_else(Vec::new, |stream| managed.catalog.candidates(stream, codec));
        #[cfg(feature = "dtls")]
        let ours = setup_in(local);
        #[cfg(feature = "ice")]
        let settled_ice = managed.ice.clone();
        let running = self.sessions.get(&call).map(Arc::clone);
        if let Some(held) = running {
            let mut slot = share::lock(&held);
            // a restart this end's answer accepted: the running agent takes
            // up the credentials that answer carried, before anything the
            // peer signs with them arrives
            #[cfg(feature = "ice")]
            slot.session.follow_ice(settled_ice.as_ref());
            // an answer that took the other role asks for a new association
            // this end does not start, the way a moved certificate does, and
            // is refused the same way: by name, before anything is adopted,
            // so the stream keeps running on the association it has
            #[cfg(feature = "dtls")]
            if let Err(error) = roles_hold(slot.session.dtls_role(), ours.as_deref(), &plan) {
                drop(slot);
                self.fail(call, error);
                return;
            }
            // the same codec on a session that is already running: a hold, a
            // resume, or a peer that moved its address — but settle is also
            // reached from events that carry no new information at all, an
            // ACK with no body chief among them, and a plan identical to the
            // one already running is not a change to report
            if slot.session.codec() == codec {
                let unchanged = *slot.session.plan() == plan;
                let adopted = slot.session.adopt(&plan, candidates, annex_b, now);
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
        self.start(call, &plan, codec, annex_b, candidates, now);
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
        annex_b: bool,
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
                    .reformat(plan, frame_length, &config, candidates, annex_b, now)
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
                #[cfg(feature = "ice")]
                let ice = match self.ice_for(call, plan, now) {
                    Ok(ice) => ice,
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
                        #[cfg(feature = "ice")]
                        ice,
                        annex_b,
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
                if !replacing {
                    self.replay_early(call, now);
                }
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

// -- a local conference of two calls -----------------------------------------

impl MediaEngine {
    /// The call `call` is currently joined with, if any.
    #[must_use]
    pub fn joined_with(&self, call: CallHandle) -> Option<CallHandle> {
        self.joins.get(&call).copied()
    }

    /// Join two active calls into a local conference of three: from here on,
    /// each call's far end hears the other's far end and this end's own
    /// microphone, mixed — [`MediaEngine::mix`] is what drives one frame of
    /// it, a call at a time, and [`mix_two`](crate::mix_two) says what
    /// "joined" means and why the two calls have to match.
    /// [`MediaEngine::leave`] ends the pairing, and a call that ends while
    /// it is still in one takes the pairing down with it.
    ///
    /// # Errors
    /// [`MediaError::SameCall`] for `a == b`; [`MediaError::NoSuchCall`] for
    /// a call with no running session — placed or answered and negotiated,
    /// the same requirement [`MediaEngine::session`] has;
    /// [`MediaError::AlreadyJoined`] for a call already paired with another;
    /// and [`MediaError::JoinIncompatible`] for two calls whose sessions do
    /// not share a sample rate and a frame length.
    pub fn join(&mut self, a: CallHandle, b: CallHandle) -> Result<(), MediaError> {
        if a == b {
            return Err(MediaError::SameCall);
        }
        if self.joins.contains_key(&a) || self.joins.contains_key(&b) {
            return Err(MediaError::AlreadyJoined);
        }
        let held_a = self.sessions.get(&a).ok_or(MediaError::NoSuchCall)?;
        let held_b = self.sessions.get(&b).ok_or(MediaError::NoSuchCall)?;
        let matches = {
            let slot_a = share::lock(held_a);
            let slot_b = share::lock(held_b);
            slot_a.session.sample_rate() == slot_b.session.sample_rate()
                && slot_a.session.frame_samples() == slot_b.session.frame_samples()
        };
        if !matches {
            return Err(MediaError::JoinIncompatible);
        }
        self.joins.insert(a, b);
        self.joins.insert(b, a);
        Ok(())
    }

    /// Take `call` back out of the pair it is in, and hand back which call
    /// it was paired with.
    ///
    /// Nothing has to be told to either session: [`MediaEngine::mix`] read
    /// and wrote both of them from the outside, on every frame it was asked
    /// to, and stopping is only a matter of not calling it again — each call
    /// carries on with whatever [`MediaSession::playback`] and
    /// [`MediaSession::capture`] it is next given directly, exactly as an
    /// unjoined call always has.
    ///
    /// # Errors
    /// [`MediaError::NotJoined`] for a call that is not currently joined to
    /// another.
    pub fn leave(&mut self, call: CallHandle) -> Result<CallHandle, MediaError> {
        let partner = self.joins.remove(&call).ok_or(MediaError::NotJoined)?;
        self.joins.remove(&partner);
        Ok(partner)
    }

    /// One frame of the pair `call` is in: decode both far ends, mix what
    /// each of the three parties is owed, and send the two frames the far
    /// ends are owed. `mic` is this end's own frame and `local_out` is
    /// filled with what this end's own loudspeaker is owed —
    /// [`crate::join::mix_two`] has the arithmetic and the reasoning behind
    /// it.
    ///
    /// # Errors
    /// [`MediaError::NotJoined`] for a call not currently paired;
    /// [`MediaError::NoSuchCall`] should either session have gone, which
    /// this engine's own call-ended handling already unjoins the moment it
    /// happens, so this is reached only by a caller that kept driving a pair
    /// past the [`MediaEvent::Unjoined`] that said so; and whatever
    /// [`MediaSession::capture`] refuses on either leg.
    pub fn mix(
        &mut self,
        call: CallHandle,
        mic: &[i16],
        local_out: &mut [i16],
        now: Instant,
    ) -> Result<crate::join::MixOutcome, MediaError> {
        let partner = self
            .joins
            .get(&call)
            .copied()
            .ok_or(MediaError::NotJoined)?;
        let held_call = self.sessions.get(&call).ok_or(MediaError::NoSuchCall)?;
        let held_partner = self.sessions.get(&partner).ok_or(MediaError::NoSuchCall)?;
        // two distinct sessions, each behind its own lock: this cannot
        // deadlock against another call into this engine, since `&mut self`
        // already rules out a second one running at the same time, and
        // nothing reached through a `SessionShare` in another thread ever
        // holds more than one session's lock at once
        let mut slot_call = share::lock(held_call);
        let mut slot_partner = share::lock(held_partner);
        crate::join::mix_two(
            &mut slot_call.session,
            &mut slot_partner.session,
            mic,
            local_out,
            now,
        )
    }
}

/// The stream this facade carries, as a description has it.
fn live_stream(description: &SessionDescription) -> Option<&MediaDescription> {
    description
        .media
        .iter()
        .find(|stream| stream.media == AUDIO && !stream.is_rejected())
}

/// The formats of the stream this facade carries, as a description lists
/// them.
fn live_formats(description: &SessionDescription) -> Option<&Vec<String>> {
    live_stream(description).map(|stream| &stream.formats)
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

/// The `a=setup` a description carries, at media level or, as RFC 4566
/// §5.13 lets a media-level attribute override, at session level.
///
/// The first stream's, because that is the one the negotiation plans
/// (`media_plan(.., 0)`) — whichever end wrote the description.
#[cfg(feature = "dtls")]
fn setup_in(description: &SessionDescription) -> Option<String> {
    description
        .media
        .first()
        .and_then(|stream| stream.attribute("setup"))
        .or_else(|| description.attribute("setup"))?
        .value
        .clone()
}

/// Whether a re-negotiated plan leaves the DTLS roles where the running
/// association has them (RFC 8842 §3.1).
///
/// `running` is the role the association gave this end, `ours` the `a=setup`
/// this end wrote on its side of the exchange just settled, and the far end's
/// is in the plan. Nothing to compare — no association, or a plan not keyed
/// by a handshake — is nothing to refuse.
///
/// # Errors
/// [`MediaError::DtlsRoleChanged`] for a plan that gives this end the other
/// role, and [`MediaError::DtlsRole`] for a pair of values RFC 4145 §4.1 does
/// not allow together.
#[cfg(feature = "dtls")]
fn roles_hold(
    running: Option<sipral_dtls::Role>,
    ours: Option<&str>,
    plan: &MediaPlan,
) -> Result<(), MediaError> {
    let (Some(running), Some(ours), Some(Keying::Dtls { setup: theirs, .. })) =
        (running, ours, plan.keying.as_ref())
    else {
        return Ok(());
    };
    let ours = Setup::parse(ours).map_err(|_| MediaError::DtlsRole)?;
    let theirs = match theirs {
        Some(written) => Some(Setup::parse(written).map_err(|_| MediaError::DtlsRole)?),
        None => None,
    };
    match crate::dtls::role_after(ours, theirs)? {
        Some(role) if role != running => Err(MediaError::DtlsRoleChanged),
        _ => Ok(()),
    }
}

/// The `a=fingerprint` values a description names for its first stream, read
/// the way the negotiation reads them: the stream's own lines, or the
/// session's where the stream has none, since a media-level attribute
/// replaces the session-level ones rather than adding to them (RFC 4566
/// §5.13).
#[cfg(feature = "dtls")]
fn fingerprints_in(description: &SessionDescription) -> Vec<String> {
    let of = |attributes: &[Attribute]| -> Vec<String> {
        attributes
            .iter()
            .filter(|attribute| attribute.name == "fingerprint")
            .filter_map(|attribute| attribute.value.clone())
            .collect()
    };
    let own = description
        .media
        .first()
        .map(|stream| of(&stream.attributes))
        .unwrap_or_default();
    if own.is_empty() {
        of(&description.attributes)
    } else {
        own
    }
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
/// Put a call's ICE attributes on a description that has just been written.
///
/// Media-level for the credentials and the candidates (RFC 8839 §5.1, §5.4,
/// §5.6), session-level for the pacing (§5.5) — and both go on *after* the
/// description is built rather than into the vocabulary that builds it,
/// because [`SessionDescription::answer`] constructs a fresh description and
/// carries only the timing across. An `a=ice-pacing` written before that call
/// would not survive it.
///
/// One stream, because this facade describes one: [`write_answer`] says why.
///
/// A lite end writes `a=ice-lite` at session level where a full one writes
/// its pacing: RFC 8839 §4.2.1.4 requires the first of a lite implementation,
/// and §4.3.1 forbids it the second. `answering` is the offer when the
/// description is an answer, and an offer that did not mention ICE is
/// answered without it — "the answerer MUST NOT include any ICE-related SDP
/// attributes in the answer" (§4.3.2); the call then runs on `c=`/`m=`, as
/// [`MediaEngine::ice_for`] decides for such a peer anyway.
#[cfg(feature = "ice")]
fn describe_ice(
    description: &mut SessionDescription,
    local: Option<&crate::ice::LocalIce>,
    answering: Option<&SessionDescription>,
) {
    let Some(local) = local else {
        return;
    };
    if let Some(offer) = answering
        && !offer
            .media
            .iter()
            .any(|stream| sipral_nat::ice::parse_remote(offer, stream).is_some())
    {
        return;
    }
    let Some(stream) = description
        .media
        .iter_mut()
        .find(|media| !media.is_rejected())
    else {
        return;
    };
    sipral_nat::ice::write_stream(stream, local.credentials(), local.candidates());
    if local.is_lite() {
        sipral_nat::ice::write_session(description);
    } else {
        // the Ta this agent proposes, which `IceConfig::default` is built with
        // and `crate::ice` does not move
        sipral_nat::ice::write_pacing(description, sipral_nat::ice::DEFAULT_TA);
    }
}

/// Without the feature there is no agent, so there is nothing to write.
#[cfg(not(feature = "ice"))]
const fn describe_ice(
    _description: &mut SessionDescription,
    _local: Option<&crate::ice::LocalIce>,
    _answering: Option<&SessionDescription>,
) {
}

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
    // a format whose parameters this end states rather than echoes —
    // G.729's `annexb`, which follows the offer only as far as this
    // catalogue allows — gets its own line, which the answer then writes in
    // place of the offer's
    for line in formats
        .iter()
        .filter_map(|format| stated_fmtp(catalog, offered, format))
    {
        accepted = accepted.with_attribute(line);
    }
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

/// The `a=fmtp` line this end writes for one offered format in its answer,
/// when the codec behind it has parameters this end states rather than
/// echoes ([`CodecCatalog::answered_fmtp`]).
fn stated_fmtp(
    catalog: &CodecCatalog,
    offered: &MediaDescription,
    format: &str,
) -> Option<Attribute> {
    let payload: u8 = format.parse().ok()?;
    let rtpmap = offered.rtpmap(payload).or_else(|| static_rtpmap(payload))?;
    let codec = Codec::of(&NegotiatedCodec::new(rtpmap))?;
    let fmtp = catalog.answered_fmtp(codec, offered.fmtp(payload))?;
    Some(Attribute::with_value("fmtp", &format!("{payload} {fmtp}")))
}

/// Whether this end's G.729 encoder runs Annex B's DTX on `plan`: the
/// catalogue's own word first — a description this layer did not write, a
/// re-offer the user agent answered by echoing it, can say yes where this
/// end would have said no — and then both descriptions'.
fn annex_b_in_use(
    catalog: &CodecCatalog,
    local: &SessionDescription,
    remote: &SessionDescription,
    plan: &MediaPlan,
) -> bool {
    catalog.g729_annex_b() && annex_b_agreed(local, remote, plan)
}

/// Whether both descriptions of a G.729 stream allowed Annex B, which is
/// what turns its encoder's DTX on: each end's `annexb` says what that end
/// will take, and one that says `no` is not sent SID frames. `false` for
/// every other codec.
fn annex_b_agreed(
    local: &SessionDescription,
    remote: &SessionDescription,
    plan: &MediaPlan,
) -> bool {
    if Codec::of(&plan.codec) != Some(Codec::G729) {
        return false;
    }
    let payload = plan.codec.payload();
    let said = |description: &SessionDescription| {
        description
            .media
            .first()
            .and_then(|stream| stream.fmtp(payload))
            .map(str::to_owned)
    };
    annex_b_allowed(said(local).as_deref()) && annex_b_allowed(said(remote).as_deref())
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
            voip_metrics_xr: false,
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

// -- what an answer states rather than echoes --------------------------------

#[cfg(test)]
mod answer_parameters {
    //! An offer of G.729 from a peer that is not this stack: every form a
    //! real one writes it in, including the one with no parameters at all,
    //! which the two-stack harness never produces because this end's own
    //! offers always say `annexb` one way or the other.

    use std::net::SocketAddr;

    use sipral_core::sdp::{SessionDescription, parse};

    use super::{annex_b_in_use, write_answer};
    use crate::codec::CodecCatalog;

    fn described(stream: &str) -> SessionDescription {
        let text = format!(
            "v=0\r\no=- 1 1 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n{stream}"
        );
        parse(text.as_bytes()).expect("the description parses")
    }

    fn answered(catalog: &CodecCatalog, stream: &str) -> SessionDescription {
        let address: SocketAddr = "192.0.2.1:40000".parse().expect("an address");
        write_answer(catalog, &described(stream), address, 1, 1, None, None)
            .expect("the offer is answered")
    }

    /// RFC 4856 §2.1.9 reads G.729 with no `annexb` as G.729 with Annex B.
    /// The answer follows the offer — `yes` where it said yes or nothing,
    /// `no` where it said no — on one line of its own, and says `no` to
    /// every offer when the catalogue has Annex B off.
    #[test]
    fn an_answer_that_keeps_g729_follows_the_offer_on_annex_b() {
        let catalog = CodecCatalog::with_order(&["G729", "PCMU"]).expect("an order");
        let off = catalog.clone().with_g729_annex_b(false);
        for (stream, said) in [
            ("m=audio 40002 RTP/AVP 18 0\r\n", "annexb=yes"),
            (
                "m=audio 40002 RTP/AVP 18 0\r\na=rtpmap:18 G729/8000\r\na=fmtp:18 annexb=yes\r\n",
                "annexb=yes",
            ),
            (
                "m=audio 40002 RTP/AVP 18 0\r\na=fmtp:18 annexb=no\r\n",
                "annexb=no",
            ),
        ] {
            for (catalog, said) in [(&catalog, said), (&off, "annexb=no")] {
                let answer = answered(catalog, stream);
                let media = answer.media.first().expect("one stream");
                assert_eq!(media.formats, ["18", "0"], "{stream}");
                assert_eq!(media.fmtp(18), Some(said), "{stream}");
                assert_eq!(
                    media.attributes.iter().filter(|a| a.name == "fmtp").count(),
                    1,
                    "{stream}"
                );
            }
        }
    }

    /// And a catalogue without G.729 answers as it always did: the format
    /// is not kept, so there is nothing to say about it.
    #[test]
    fn an_answer_that_drops_g729_says_nothing_about_it() {
        let answer = answered(
            &CodecCatalog::new(),
            "m=audio 40002 RTP/AVP 18 0\r\na=fmtp:18 annexb=yes\r\n",
        );
        let media = answer.media.first().expect("one stream");
        assert_eq!(media.formats, ["0"]);
        assert_eq!(media.fmtp(18), None);
    }

    /// Whether this end's encoder runs Annex B, from the two descriptions a
    /// negotiation ends with: only where each allowed it — a description with
    /// no `annexb` allows it (RFC 4856 §2.1.9), whichever end wrote it — and
    /// never with the catalogue's Annex B off, even where both descriptions
    /// say yes, as a re-offer the user agent answered by echoing it can.
    #[test]
    fn the_encoder_runs_annex_b_only_where_both_descriptions_and_the_catalogue_allow_it() {
        let on = CodecCatalog::with_order(&["G729", "PCMU"]).expect("an order");
        let off = on.clone().with_g729_annex_b(false);
        let g729 = |fmtp: &str| described(&format!("m=audio 40002 RTP/AVP 18\r\n{fmtp}"));
        let yes = "a=fmtp:18 annexb=yes\r\n";
        let no = "a=fmtp:18 annexb=no\r\n";
        for (local, remote, on_uses) in [
            (yes, yes, true),
            (yes, "", true),
            ("", yes, true),
            ("", "", true),
            (yes, no, false),
            (no, yes, false),
            (no, "", false),
            ("", no, false),
        ] {
            let (ours, theirs) = (g729(local), g729(remote));
            let plan = ours
                .media_plan(&theirs, 0)
                .expect("a plan")
                .expect("the stream is kept");
            assert_eq!(
                annex_b_in_use(&on, &ours, &theirs, &plan),
                on_uses,
                "ours {local:?}, theirs {remote:?}"
            );
            assert!(
                !annex_b_in_use(&off, &ours, &theirs, &plan),
                "ours {local:?}, theirs {remote:?}"
            );
        }

        // and nothing of it for another codec, whatever a line for 18 says
        let pcmu = |fmtp: &str| described(&format!("m=audio 40002 RTP/AVP 0\r\n{fmtp}"));
        let (ours, theirs) = (pcmu(yes), pcmu(yes));
        let plan = ours
            .media_plan(&theirs, 0)
            .expect("a plan")
            .expect("the stream is kept");
        assert!(!annex_b_in_use(&on, &ours, &theirs, &plan));
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
            voip_metrics_xr: false,
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
                #[cfg(feature = "ice")]
                ice: None,
                annex_b: false,
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
        let (mut agent, call) = call_with_a_stalling_session(&mut engine, now);
        let share = engine.share(call).expect("the session was inserted above");
        let kept_alive = engine
            .sessions
            .get(&call)
            .cloned()
            .expect("the session is still in the map");

        engine.release(call, &mut agent, now);

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
