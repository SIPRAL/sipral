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
use std::ops::Bound;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sipral_core::auth::KeySource;
use sipral_core::msg::OwnedMessage;
#[cfg(any(feature = "dtls", feature = "ice"))]
use sipral_core::sdp::RtcpPlan;
use sipral_core::sdp::{
    AcceptedStream, Attribute, Connection, CryptoSuite, Direction, KeySalt, Keying,
    MediaDescription, MediaPlan, NegotiatedCodec, Origin, SdpError, SessionDescription,
    StreamAnswer, parse, static_rtpmap,
};
#[cfg(feature = "dtls")]
use sipral_dtls::setup::{Party, Setup};
use sipral_ua::{
    AccountId, CallHandle, CallState, OutgoingCall, OutgoingExtras, Reason, StatusCode, UaError,
    UaEvent, UserAgent,
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
use crate::keying::{self, AccountSrtp, Shape};
use crate::payloads::Payloads;
use crate::ports::{PortsExhausted, RtpPorts};
use crate::session::{MediaConfig, MediaSession, Start, StreamIdentity};
use crate::share::{self, Held, Ready, SessionGuard, SessionShare};

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
    /// The ICE an ICE restart this end offered ([`MediaEngine::restart_ice`])
    /// runs on once the far end accepts it: new credentials, and the
    /// candidates the agent still held when it was written.
    ///
    /// It becomes [`Managed::ice`] with the session change that carries its
    /// credentials, and a refusal drops it: "Should a subsequent offer fail,
    /// ICE processing continues as if the subsequent offer had never been
    /// made" (RFC 8839 §4.4), so nothing of it reaches the running agent
    /// before the answer does.
    #[cfg(feature = "ice")]
    restarting: Option<crate::ice::LocalIce>,
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
    /// Whether the far end answered this end's offer in a way the call's
    /// SRTP policy refuses ([`MediaError::SrtpRequired`]): a call placed from
    /// here that is to be hung up, with a `Reason` saying why, once its 2xx
    /// has been acknowledged.
    refused_keying: bool,
    /// Where this call's real-time text arrives, when it was given a socket
    /// for it ([`CallMedia::text`]).
    text: Option<SocketAddr>,
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
    /// Where the call's real-time text arrives, when it offers or takes one
    /// — see [`CallMedia::text`].
    pub text: Option<SocketAddr>,
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
            text: None,
        }
    }

    /// Give the call real-time text (RFC 4103), on a second socket the
    /// application bound at `address`: an offer carries an `m=text` stream
    /// beside the audio, and an offer that carries one is answered with it.
    /// Once both descriptions agree it, [`MediaSession::send_text`] sends,
    /// [`MediaSession::poll_text`] and [`MediaSession::receive_text`] carry
    /// the packets on this socket, and [`MediaEvent::TextReceived`] says
    /// what the far end typed (`crate::text` has the whole of it).
    ///
    /// Text runs on plain `RTP/AVP` with no RTCP, so a call whose catalogue
    /// offers SRTP or ICE, or an offer whose audio is keyed, leaves it out
    /// rather than send typed text in the clear beside encrypted audio, or
    /// a stream no candidate describes. The address goes into the
    /// description as the call's own `c=` with this socket's port.
    #[must_use]
    pub const fn text(mut self, address: SocketAddr) -> Self {
        self.text = Some(address);
        self
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
    /// on another pair, or the peer turns out to do no ICE at all — though
    /// the branches of a forked call each hold it with an agent of their
    /// own, and it goes back only when the last of them lets go. What that
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
    /// the next call on the socket. So does [`MediaEngine::answer_with`] on a
    /// call [`MediaEngine::ring_with`] already described: the 200 OK carries
    /// the description the 183 did, which named the ring's relay or none.
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
    /// What each account's calls do about SRTP, where the account said
    /// something of its own ([`MediaEngine::set_account_srtp`]): laid over
    /// [`MediaEngine::catalog`] when a call of that account is placed or
    /// arrives, and never read again on the call's behalf afterwards.
    accounts: BTreeMap<AccountId, AccountSrtp>,
    config: MediaConfig,
    clock: WallClock,
    /// Ordered rather than hashed so that two runs of the same test drain
    /// events in the same order.
    ///
    /// Each behind a lock of its own, and this is the one strong reference to
    /// each: a thread that carries a call's audio reaches it through a
    /// [`SessionShare`], which works for as long as the entry is here.
    sessions: BTreeMap<CallHandle, Held>,
    /// The calls in `sessions` that have an event waiting, raised by the
    /// session itself: what makes [`MediaEngine::poll_event`] cost the
    /// sessions with something to say rather than every session held.
    ready: Arc<Ready>,
    /// How many sessions [`MediaEngine::poll_event`] has locked, all told:
    /// the figure the test of its cost counts.
    #[cfg(test)]
    sessions_polled: usize,
    /// Where the drain of [`MediaEngine::poll_rtcp`] under way picks up: the
    /// call it last answered for, or `None` to start from the first.
    rtcp_after: Option<CallHandle>,
    /// How many sessions [`MediaEngine::poll_rtcp`] has locked, all told.
    #[cfg(test)]
    rtcp_looked: usize,
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
    /// call the first description was written for: the fork the branch is
    /// one of.
    #[cfg(feature = "ice")]
    branches: BTreeMap<CallHandle, CallHandle>,
    /// The allocation a call's first description named, by that call, for
    /// as long as any branch of its fork is left: what the agent of every
    /// branch holds beside the others ([`crate::ice::LocalIce::shared_agent`]).
    #[cfg(feature = "ice")]
    fork_relays: BTreeMap<CallHandle, sipral_nat::ice::SharedRelay>,
    /// What calls wrote for a relay's TCP or TLS connection to its TURN
    /// server, out of what [`MediaEngine::poll_transmit`],
    /// [`MediaEngine::poll_rtcp`] and the farewells would otherwise have
    /// handed out as datagrams, waiting for
    /// [`MediaEngine::poll_turn_stream`].
    #[cfg(feature = "ice")]
    streamed: VecDeque<(CallHandle, crate::RelayDatagram)>,
    /// The range [`MediaEngine::reserve_rtp_port`] hands ports out of, when
    /// the deployment set one.
    rtp_ports: Option<RtpPorts>,
    /// The RTP ports handed out and not yet let go, each with whether a call
    /// has since been seen describing its media there: a reservation a call
    /// took and then stopped using — the call ended, or moved — is over.
    reserved_ports: BTreeMap<u16, bool>,
    /// Which pair of the range the next reservation starts looking at: round
    /// the range rather than lowest first, so a port a call has just let go
    /// is the last to be handed out again while its stragglers still arrive.
    next_pair: u16,
    /// Where this engine's log lines go, once the application installed one.
    #[cfg(feature = "redaction")]
    log: Option<crate::Log>,
    /// How many decisions of each diagnostic record have already been
    /// logged, by `Call-ID` (`None` for the endpoint's own record), so a
    /// decision is logged once.
    #[cfg(feature = "redaction")]
    logged: BTreeMap<Option<Vec<u8>>, u64>,
    /// The recording sessions this engine placed (`crate::siprec`), by the
    /// handle of the recording session itself.
    recordings: BTreeMap<CallHandle, Recording>,
}

/// One recording session, and the call it records.
#[derive(Debug)]
struct Recording {
    /// The call whose audio is copied: the one recorded, or the one that
    /// replaced it.
    recorded: CallHandle,
    to: crate::siprec::RecordTo,
    parties: crate::siprec::Parties,
    /// The call's codec, which is what the two streams were offered.
    payload_type: u8,
    /// The `o=` session id the recording session's descriptions carry (RFC
    /// 4566 §5.2 keeps it for the life of the session).
    session_id: u64,
    /// Where each stream's copies start their numbering.
    numbers: [(u32, u16, u32); 2],
    /// Where the server receives each stream, once it has answered.
    destinations: Option<[Option<SocketAddr>; 2]>,
    /// The SDES keys the two streams were offered with, for a recorded call
    /// that is encrypted: its copies go to the server as SRTP (RFC 7866
    /// §12.2), and a stream the server will not take as SRTP gets nothing.
    /// `None` copies in the clear.
    keys: Option<crate::siprec::StreamKeys>,
    /// Whether the recorded call's account lets an encrypted call be copied
    /// in the clear ([`AccountSrtp::recording_in_clear`]).
    in_clear: bool,
    /// The server's last answer, which says which offered line keys each
    /// stream.
    answer: Option<SessionDescription>,
    /// The copies taken off a recorded call that another replaced, waiting
    /// for that call's session to carry on in.
    parked: Option<crate::siprec::Tap>,
    /// The direction the metadata last told the server about, and whether
    /// new metadata is waiting for a change in the recording session to end.
    told: Option<Direction>,
    owed: bool,
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
}

/// Who a datagram on a socket calls were described on goes to
/// ([`MediaEngine::branch_for`]).
#[cfg(feature = "ice")]
enum Branch {
    /// A call's session.
    Session(share::Held),
    /// An agent still waiting for its session.
    Waiting,
    /// Nobody described there has a session or an agent yet.
    None,
}

/// Which call reads the messages back off a relay's connection, once its
/// bytes went in through that call ([`MediaEngine::receive_stream`]).
#[cfg(feature = "ice")]
enum StreamReader {
    /// An agent waiting for its session, by the call it was described for.
    Waiting(CallHandle),
    /// A call's session.
    Session(share::Held),
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
            accounts: BTreeMap::new(),
            config,
            clock,
            sessions: BTreeMap::new(),
            ready: Arc::default(),
            #[cfg(test)]
            sessions_polled: 0,
            rtcp_after: None,
            #[cfg(test)]
            rtcp_looked: 0,
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
            #[cfg(feature = "ice")]
            fork_relays: BTreeMap::new(),
            #[cfg(feature = "ice")]
            streamed: VecDeque::new(),
            rtp_ports: None,
            reserved_ports: BTreeMap::new(),
            next_pair: 0,
            #[cfg(feature = "redaction")]
            log: None,
            #[cfg(feature = "redaction")]
            logged: BTreeMap::new(),
            recordings: BTreeMap::new(),
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
        // a call whose suites leave the handshake nothing to offer is
        // refused before any description names a fingerprint
        crate::dtls::profiles(catalog.srtp_suites())?;
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
                // the offer that named the relay goes to every branch a proxy
                // forks it to, and each branch's agent holds the one
                // allocation beside the others
                if let Some(relay) = ice.shared_relay() {
                    self.fork_relays.insert(call, relay);
                }
                // `first_ice` draws a relayed agent only for a call that has
                // drawn no candidates yet, so none is waiting here; were one
                // ever replaced, its allocation goes back rather than being
                // dropped with nothing sent
                if let Some(before) = self.gathered.insert(call, ice) {
                    self.release_ice(call, before, now);
                }
            }
            Some(Kept::Unused(relay)) => self.relay_farewell(call, *relay, now),
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

    /// The agent a call described with a relay was waiting with, for a call
    /// that ended before its session opened: it lets go of the relay, which
    /// goes back to its server among the call's farewells unless another
    /// branch of its fork still holds it (RFC 8445 §8.3.1).
    #[cfg(feature = "ice")]
    fn let_go(&mut self, call: CallHandle, now: Instant) {
        let Some(ice) = self.gathered.remove(&call) else {
            return;
        };
        self.release_ice(call, ice, now);
    }

    /// The fork `call` is a branch of: the call its first description was
    /// written for.
    #[cfg(feature = "ice")]
    fn root_of(&self, call: CallHandle) -> CallHandle {
        self.branches.get(&call).copied().unwrap_or(call)
    }

    /// An agent for a branch of a forked call, holding the relay the fork's
    /// offer named beside every other branch's agent — or `None` when the
    /// fork has no relay left for it.
    ///
    /// One offer went to every branch, with one relayed candidate in it, and
    /// one allocation stands behind it: the server knows an allocation by
    /// the addresses it runs between, and "If the client wishes to allocate
    /// a second relayed transport address, it must create a second
    /// allocation using a different 5-tuple" (RFC 8656 §3.2), while the
    /// offer named the one socket. It serves them all the same — "TURN
    /// supports multiple peers per relayed transport address" (RFC 8656 §1)
    /// — and each branch runs its own ICE session over it (RFC 8839 §7).
    #[cfg(feature = "ice")]
    fn branch_agent(
        &mut self,
        call: CallHandle,
        now: Instant,
    ) -> Result<Option<crate::ice::Ice>, MediaError> {
        let root = self.root_of(call);
        let Some(relay) = self.fork_relays.get(&root).cloned() else {
            return Ok(None);
        };
        let Some((local, address)) = self
            .calls
            .get(&call)
            .and_then(|managed| Some((managed.ice.clone()?, managed.address?)))
        else {
            return Ok(None);
        };
        local.shared_agent(address, &relay, &mut self.keys, now)
    }

    /// Forget a branch of a fork that has ended, and the fork's relay with
    /// the last of its branches. The allocation itself went back, or not,
    /// with the agents that held it.
    #[cfg(feature = "ice")]
    fn forget_branch(&mut self, call: CallHandle) {
        let root = self.root_of(call);
        self.branches.remove(&call);
        let left =
            self.calls.contains_key(&root) || self.branches.values().any(|first| *first == root);
        if !left {
            self.fork_relays.remove(&root);
        }
    }

    /// One of `call`'s own datagrams as a farewell, `local` being the socket
    /// the call was described on: among the rest, or with
    /// [`MediaEngine::poll_turn_stream`]'s when it goes through a relay's
    /// connection to its TURN server.
    fn say_farewell(
        &mut self,
        call: CallHandle,
        local: Option<SocketAddr>,
        datagram: crate::session::Datagram<'_>,
    ) {
        #[cfg(feature = "ice")]
        if let Some(local) = local.filter(|_| datagram.transport.is_stream()) {
            let said = vec![(
                datagram.destination,
                datagram.transport,
                datagram.payload.to_vec(),
            )];
            self.farewells_of(call, local, said);
            return;
        }
        #[cfg(not(feature = "ice"))]
        let _ = local;
        self.farewells
            .push_back((call, datagram.destination, datagram.payload.to_vec()));
    }

    /// Give a relay back to its server among `call`'s farewells.
    #[cfg(feature = "ice")]
    fn relay_farewell(&mut self, call: CallHandle, relay: crate::Relay, now: Instant) {
        let (local, server, transport) = (relay.local(), relay.server(), relay.transport());
        let released = relay
            .release(now)
            .into_iter()
            .map(|payload| (server, transport, payload))
            .collect();
        self.farewells_of(call, local, released);
    }

    /// Give back every relay `ice` holds among `call`'s farewells, from the
    /// socket it runs on.
    #[cfg(feature = "ice")]
    fn release_ice(&mut self, call: CallHandle, mut ice: crate::ice::Ice, now: Instant) {
        let local = ice.local();
        let said = ice.release(now);
        self.farewells_of(call, local, said);
    }

    /// `call`'s farewells from the socket `local`, each where it goes and
    /// how: a datagram among the rest, and what is for a relay's connection
    /// to its TURN server with [`MediaEngine::poll_turn_stream`]'s.
    #[cfg(feature = "ice")]
    fn farewells_of(
        &mut self,
        call: CallHandle,
        local: SocketAddr,
        said: Vec<(SocketAddr, crate::TurnTransport, Vec<u8>)>,
    ) {
        for (destination, transport, payload) in said {
            if transport.is_stream() {
                self.streamed.push_back((
                    call,
                    crate::RelayDatagram {
                        local,
                        destination,
                        payload,
                        transport,
                    },
                ));
            } else {
                self.farewells.push_back((call, destination, payload));
            }
        }
    }

    /// What this call says about ICE in its answer to a re-offer: what
    /// [`MediaEngine::ice_lines`] says, unless the offer is an ICE restart.
    ///
    /// RFC 8839 §4.4.1.1.1 signals a restart by a change of both `ice-ufrag`
    /// and `ice-pwd`, and §4.4.2.1 has an answerer that accepts one "change
    /// the SDP "ice-pwd" and "ice-ufrag" attribute values". The answer
    /// carries new credentials of this end's own, and candidates the running
    /// agent still holds ([`crate::ice::LocalIce::restarted`]); the agent
    /// takes both up once the answer has gone
    /// ([`crate::ice::Ice::follow`]), a full one flushing its checklist and
    /// checking again, a lite one keeping its pair until the peer nominates
    /// under the new ones ([`sipral_nat::ice::LiteAgent::restart`]).
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
                let running = self
                    .sessions
                    .get(&call)
                    .and_then(|held| share::lock(held).session.ice_candidates());
                held.restarted(&mut self.keys, running).map(Some)
            }
            _ => Ok(Some(held)),
        }
    }

    /// What this call says about ICE from the answer to a re-offer on: the
    /// lines [`MediaEngine::reoffer_ice`] wrote into it.
    ///
    /// When they are a restart this end has just accepted, the far end
    /// checks under this end's new credentials as soon as the answer reaches
    /// it — possibly before the exchange is complete here and the agent has
    /// taken the restart up — so the agent is told of them, and keeps those
    /// checks for that moment rather than refusing them.
    #[cfg(feature = "ice")]
    fn answered_ice(&mut self, call: CallHandle, ice: Option<crate::ice::LocalIce>) {
        let Some(managed) = self.calls.get_mut(&call) else {
            return;
        };
        let restarted = match (&managed.ice, &ice) {
            (Some(before), Some(after)) => before.credentials() != after.credentials(),
            _ => false,
        };
        managed.ice = ice;
        if restarted && let Some(held) = self.sessions.get(&call) {
            share::lock(held)
                .session
                .expect_ice_restart(managed.ice.as_ref());
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
        if let Some(unused) = held {
            self.release_ice(call, unused, now);
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
        // the agent that waited with the relay, one holding the relay the
        // fork's offer named beside the other branches', or one built from
        // what was written down
        let mut ice = if let Some(ice) = held.take() {
            ice
        } else if let Some(ice) = self.branch_agent(call, now)? {
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
        let profiles = self.calls.get(&call).map_or(Ok(Vec::new()), |managed| {
            crate::dtls::profiles(managed.catalog.srtp_suites())
        })?;
        crate::dtls::Handshake::start(
            &identity,
            keying,
            side.party(),
            ours,
            profiles,
            &mut self.keys,
            now,
        )
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
    ///
    /// What goes through a relay's TCP or TLS connection to its TURN server
    /// is not handed out here but set aside for
    /// [`MediaEngine::poll_turn_stream`], so drain that after this.
    #[cfg(any(feature = "dtls", feature = "ice"))]
    #[must_use]
    pub fn poll_transmit(&mut self, now: Instant) -> Option<(CallHandle, SocketAddr, Vec<u8>)> {
        #[cfg(feature = "ice")]
        let (calls, streamed) = (&self.calls, &mut self.streamed);
        for (call, held) in &self.sessions {
            let mut slot = share::lock(held);
            #[cfg(feature = "ice")]
            while let Some(datagram) = slot.session.poll_transmit(now) {
                if datagram.transport.is_stream() {
                    set_aside(streamed, calls, *call, &datagram);
                    continue;
                }
                return Some((*call, datagram.destination, datagram.payload.to_vec()));
            }
            // without a relay there is no connection to set anything aside
            // for, and the first datagram is the one handed out
            #[cfg(not(feature = "ice"))]
            if let Some(datagram) = slot.session.poll_transmit(now) {
                return Some((*call, datagram.destination, datagram.payload.to_vec()));
            }
        }
        // a call described with a relay and still waiting for its session:
        // the keepalives that hold the NAT binding towards the TURN server
        #[cfg(feature = "ice")]
        for (call, ice) in &mut self.gathered {
            while let Some((destination, transport)) = ice.take_probe() {
                if transport.is_stream() {
                    self.streamed.push_back((
                        *call,
                        crate::RelayDatagram {
                            local: ice.local(),
                            destination,
                            payload: ice.probe().to_vec(),
                            transport,
                        },
                    ));
                    continue;
                }
                return Some((*call, destination, ice.probe().to_vec()));
            }
        }
        None
    }

    /// Whether a call is described on the media socket `local`: placed, rung
    /// or answered there, and not ended.
    ///
    /// What an application that opened a TCP or TLS connection to a TURN
    /// server for the socket ([`crate::Relays::over`]) asks after a call on
    /// it ends: while one is still described there — another branch of a
    /// forked call, which may inherit the relay — the connection has a relay
    /// to carry, and once none is, and the farewells are sent, it has
    /// nothing left.
    #[must_use]
    pub fn describes(&self, local: SocketAddr) -> bool {
        self.calls
            .values()
            .any(|managed| managed.address == Some(local))
    }

    /// What a call wrote for its relay's TCP or TLS connection to the TURN
    /// server ([`crate::Relays::over`]), set aside by
    /// [`MediaEngine::poll_transmit`], [`MediaEngine::poll_rtcp`] and a
    /// call's ending rather than handed out as datagrams: the connection is
    /// the one from [`crate::RelayDatagram::local`], and the bytes are
    /// written on it as they are, in the order they come out here. One at a
    /// time; loop until `None` after each of those.
    #[cfg(feature = "ice")]
    #[must_use]
    pub fn poll_turn_stream(&mut self) -> Option<(CallHandle, crate::RelayDatagram)> {
        self.streamed.pop_front()
    }

    /// Hand in bytes read off the TCP or TLS connection from the media
    /// socket `local` to the TURN server a call's relay runs over, in
    /// whatever pieces it delivered them, and say whether a call's relay
    /// runs over it.
    ///
    /// The connection is one per socket and server, and the branches of a
    /// forked call hold the one allocation over it, so its bytes are put
    /// back together once and every whole message goes to the call it is
    /// for, as a datagram from the server would ([`MediaEngine::receive_early`]
    /// says how a branch is found): a session, as
    /// [`MediaSession::receive_stream`](crate::MediaSession::receive_stream)
    /// takes one, or the agent of a call described there and waiting for its
    /// session — the refresh's answer above all, as
    /// [`MediaEngine::receive_waiting`] takes it off a datagram. Drain
    /// [`MediaEngine::poll_transmit`] and [`MediaEngine::poll_turn_stream`]
    /// after it. `Ok(false)` leaves the bytes to
    /// [`crate::Relays::receive_stream`], for a socket no call has taken the
    /// relay of yet.
    ///
    /// # Errors
    ///
    /// The connection carried something that is not a TURN message, and the
    /// relay is lost with it; the application closes the connection.
    #[cfg(feature = "ice")]
    pub fn receive_stream(
        &mut self,
        local: SocketAddr,
        bytes: &[u8],
        now: Instant,
    ) -> Result<bool, crate::TurnStreamError> {
        let Some((reader, server)) = self.push_stream(local, bytes) else {
            return Ok(false);
        };
        let mut frame = Vec::new();
        loop {
            let whole = match &reader {
                StreamReader::Waiting(call) => match self.gathered.get_mut(call) {
                    Some(ice) => {
                        ice.top_up();
                        ice.next_stream_frame(&mut frame, now)?
                    }
                    None => false,
                },
                StreamReader::Session(held) => share::lock(held)
                    .session
                    .next_stream_frame(&mut frame, now)?,
            };
            if !whole {
                return Ok(true);
            }
            match self.branch_for(local, server, &frame) {
                Branch::Session(held) => share::lock(&held)
                    .session
                    .take_stream_frame(&mut frame, now),
                Branch::Waiting => self.take_waiting_frame(local, server, &frame, now),
                Branch::None => {}
            }
        }
    }

    /// Put `bytes` from the connection on `local` into the relay that runs
    /// over it, through the first call there that holds one — an agent
    /// waiting for its session before a session — and say which call reads
    /// the messages back, and the server the connection goes to.
    #[cfg(feature = "ice")]
    fn push_stream(
        &mut self,
        local: SocketAddr,
        bytes: &[u8],
    ) -> Option<(StreamReader, SocketAddr)> {
        for (call, ice) in &mut self.gathered {
            if ice.local() != local {
                continue;
            }
            let Some(server) = ice.stream_server() else {
                continue;
            };
            ice.top_up();
            if ice.push_stream(bytes) {
                return Some((StreamReader::Waiting(*call), server));
            }
        }
        self.calls
            .iter()
            .filter(|(_, managed)| managed.address == Some(local))
            .filter_map(|(call, _)| self.sessions.get(call))
            .find_map(|held| {
                let server = share::lock(held).session.push_stream(bytes)?;
                Some((StreamReader::Session(Arc::clone(held)), server))
            })
    }

    /// A whole message off the relay's connection on `local` for the agents
    /// waiting there for their sessions: the one that claims it, or failing
    /// that the first whose relay runs over the connection. What a peer sent
    /// through the relay has nowhere to play before a session, and the peer
    /// sends it again once the answer lands; the agent's own answers are
    /// what matter here.
    #[cfg(feature = "ice")]
    fn take_waiting_frame(
        &mut self,
        local: SocketAddr,
        server: SocketAddr,
        frame: &[u8],
        now: Instant,
    ) {
        use sipral_nat::ice::Claim;

        let over =
            |ice: &crate::ice::Ice| ice.local() == local && ice.stream_server() == Some(server);
        let claiming = self
            .gathered
            .iter()
            .find(|(_, ice)| over(ice) && ice.claims(server, frame) == Claim::Mine)
            .or_else(|| self.gathered.iter().find(|(_, ice)| over(ice)))
            .map(|(call, _)| *call);
        if let Some(ice) = claiming.and_then(|call| self.gathered.get_mut(&call)) {
            ice.top_up();
            let _ = ice.take_stream_frame(frame, now);
        }
    }

    /// The TCP or TLS connection from the media socket `local` to the TURN
    /// server a call's relay ran over closed, and the relay is gone with it
    /// ([`MediaSession::stream_closed`](crate::MediaSession::stream_closed)).
    /// A call still waiting for its session opens it without the relay.
    #[cfg(feature = "ice")]
    pub fn stream_closed(&mut self, local: SocketAddr, now: Instant) {
        for ice in self.gathered.values_mut() {
            if ice.local() == local {
                ice.stream_closed(now);
            }
        }
        for (call, managed) in &self.calls {
            if managed.address == Some(local)
                && let Some(held) = self.sessions.get(call)
            {
                share::lock(held).session.stream_closed(now);
            }
        }
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

    /// Say what the wall clock reads, when the reading [`MediaEngine::new`]
    /// was given was none worth having — an application that only learns the
    /// time later. Every call's sender reports, the running ones' included,
    /// carry it from here on (RFC 3550 §6.4.1), and so do the certificates a
    /// DTLS-SRTP call makes.
    pub fn set_wall_clock(&mut self, clock: WallClock) {
        self.clock = clock;
        for held in self.sessions.values() {
            share::lock(held).session.set_wall_clock(clock);
        }
    }

    /// The wall clock this engine dates its reports by.
    #[must_use]
    pub const fn wall_clock(&self) -> WallClock {
        self.clock
    }

    /// Give `account`'s calls an SRTP policy and suites of their own, laid
    /// over this engine's catalogue: the policy a call placed from it offers
    /// and holds its answer to, and the one an INVITE that arrives for it is
    /// answered under. [`AccountSrtp::default`] takes the account back to the
    /// engine's own.
    ///
    /// A call already in progress keeps the catalogue it started with.
    ///
    /// # Errors
    /// What [`CodecCatalog::with_srtp_suites`] refuses, with nothing kept.
    pub fn set_account_srtp(
        &mut self,
        account: AccountId,
        srtp: AccountSrtp,
    ) -> Result<(), MediaError> {
        srtp.over(self.catalog.clone())?;
        if srtp == AccountSrtp::default() {
            self.accounts.remove(&account);
        } else {
            self.accounts.insert(account, srtp);
        }
        Ok(())
    }

    /// What `account` said about SRTP of its own, if anything
    /// ([`MediaEngine::set_account_srtp`]).
    #[must_use]
    pub fn account_srtp(&self, account: AccountId) -> Option<&AccountSrtp> {
        self.accounts.get(&account)
    }

    /// The catalogue a call of `account` starts from: this engine's own, with
    /// whatever the account said about SRTP laid over it.
    #[must_use]
    pub fn account_catalog(&self, account: AccountId) -> CodecCatalog {
        self.accounts
            .get(&account)
            .and_then(|srtp| srtp.over(self.catalog.clone()).ok())
            .unwrap_or_else(|| self.catalog.clone())
    }

    /// How each stream of a call is protected, now: the encryption report
    /// ([`MediaSession::encryption`]). `None` for a call with no session.
    #[must_use]
    pub fn encryption(&self, call: CallHandle) -> Option<Vec<crate::StreamEncryption>> {
        self.sessions
            .get(&call)
            .map(|held| share::lock(held).session.encryption())
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

    /// Listen for call progress on `call` and decide who answers it, or stop
    /// with `None` — before its media exists as well as after.
    ///
    /// Meant for a call this end placed, straight after placing it: the
    /// tones are listened for from the first frame of early media, and the
    /// decision about who answered starts from the 2xx. A call's
    /// [`MediaConfig::progress`](crate::MediaConfig::progress) is the same
    /// setting made when it is placed.
    ///
    /// # Errors
    /// [`MediaError::NoSuchCall`] for a call this engine does not describe.
    pub fn detect_progress(
        &mut self,
        call: CallHandle,
        detection: Option<crate::ProgressDetection>,
    ) -> Result<(), MediaError> {
        let managed = self.calls.get_mut(&call).ok_or(MediaError::NoSuchCall)?;
        managed.config.progress = detection;
        if let Some(held) = self.sessions.get(&call) {
            share::lock(held).session.detect_progress(detection);
        }
        Ok(())
    }

    /// When to listen for keypad digits in `call`'s far-end audio, before
    /// its media exists as well as after.
    ///
    /// # Errors
    /// [`MediaError::NoSuchCall`] for a call this engine does not describe.
    pub fn set_dtmf_detection(
        &mut self,
        call: CallHandle,
        detection: crate::DtmfDetection,
    ) -> Result<(), MediaError> {
        let managed = self.calls.get_mut(&call).ok_or(MediaError::NoSuchCall)?;
        managed.config.dtmf_detection = detection;
        if let Some(held) = self.sessions.get(&call) {
            share::lock(held).session.set_dtmf_detection(detection);
        }
        Ok(())
    }

    /// Beep on `call` while it is recorded, or stop with `None`, before its
    /// media exists as well as after.
    ///
    /// # Errors
    /// [`MediaError::NoSuchCall`] for a call this engine does not describe,
    /// and [`MediaError::ConsentTone`] for a tone that is not a beep, which
    /// changes nothing.
    pub fn set_consent_tone(
        &mut self,
        call: CallHandle,
        tone: Option<crate::ConsentTone>,
    ) -> Result<(), MediaError> {
        if let Some(tone) = tone.as_ref() {
            tone.check()?;
        }
        let managed = self.calls.get_mut(&call).ok_or(MediaError::NoSuchCall)?;
        managed.config.consent_tone = tone;
        if let Some(held) = self.sessions.get(&call) {
            share::lock(held).session.set_consent_tone(tone)?;
        }
        Ok(())
    }

    /// A call this end placed was answered: its media, if it has any yet,
    /// starts deciding who answered.
    fn answered(&self, call: CallHandle) {
        if let Some(held) = self.sessions.get(&call) {
            share::lock(held).session.answered();
        }
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
        let media = CallMedia::new(self.account_catalog(account), self.config.clone());
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
            text,
            ..
        } = media;
        let public = public.or_else(|| handed.mapped());
        let catalog = CallMedia::offering(catalog, public);
        let (identity, session_id) = draw(agent);
        // drawn after the identity, so that the same call placed with and
        // without SDES starts from the same SSRC and the same sequence number
        let keys = catalog
            .srtp()
            .offers()
            .then(|| self.draw_offer_keys(&catalog));
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
            text,
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
                #[cfg(feature = "ice")]
                restarting: None,
                // an outgoing call rings the far end's phone, not this one's
                rung_with_media: false,
                payloads: Payloads::default(),
                pending: None,
                refused_keying: false,
                text,
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
        let catalog = agent.call_account(call).map_or_else(
            || self.catalog.clone(),
            |account| self.account_catalog(account),
        );
        let media = CallMedia::new(catalog, self.config.clone());
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
            text,
            ..
        } = media;
        let public = public.or_else(|| handed.mapped());
        let catalog = CallMedia::offering(catalog, public);
        let (identity, session_id) = draw(agent);
        let keys = catalog
            .srtp()
            .offers()
            .then(|| self.draw_offer_keys(&catalog));
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
            text,
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
                #[cfg(feature = "ice")]
                restarting: None,
                // an outgoing call rings the far end's phone, not this one's
                rung_with_media: false,
                payloads: Payloads::default(),
                pending: None,
                refused_keying: false,
                text,
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
            text,
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
            return Err(refuse_insecure(agent, call, now));
        }
        let keys = will_key(&catalog, Some(&offer))
            .then(|| draw_key_for(suite_for_own_key(Some(&offer), &catalog), &mut self.keys));
        let dtls = self.dtls_lines(&catalog, Side::Answering, Some(&offer), None, now)?;
        let ice = self.first_ice(Some(call), &catalog, local, public, handed, false, now)?;
        let mut description = write_answer(
            &catalog,
            &offer,
            public.unwrap_or(local),
            (session_id, version),
            keys.as_ref(),
            keyed(dtls.as_ref()),
            text,
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
            managed.text = text;
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
    /// passed here — see [`MediaEngine::ring_with`]. A relay `media` carried
    /// then was named by nothing that left, and comes back whole from
    /// [`MediaEngine::poll_returned_relay`], whether the answer went or not.
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
            // the call was described when it rang, relay and all. A second
            // relay handed in here was named by nothing that left, so it
            // stays in `handed` and goes back to the application whole from
            // `answer_with`, as a refused description's does: deleting it
            // would spend an allocation the socket's next call can use
            return self.answer_after_ring(agent, call, now);
        }
        let CallMedia {
            catalog,
            config,
            public,
            text,
            ..
        } = media;
        let public = public.or_else(|| handed.mapped());
        let catalog = CallMedia::offering(catalog, public);
        let described = public.unwrap_or(local);
        let managed = self.calls.get(&call).ok_or(MediaError::NoSuchCall)?;
        let (session_id, version) = (managed.session_id, managed.version.saturating_add(1));
        let offered = managed.remote.clone();
        if !keying_allows(&catalog, offered.as_ref()) {
            return Err(refuse_insecure(agent, call, now));
        }
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
        let mut description = if let Some(offer) = offered.as_ref() {
            let keys = self.reoffer_keys(&catalog, offer, None);
            write_answer(
                &catalog,
                offer,
                described,
                (session_id, version),
                keys.as_ref(),
                keyed(dtls.as_ref()),
                text,
            )?
        } else {
            let keys = catalog
                .srtp()
                .offers()
                .then(|| self.draw_offer_keys(&catalog));
            write_offer(
                &catalog,
                described,
                session_id,
                version,
                keys,
                keyed(dtls.as_ref()),
                text,
            )
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
            managed.text = text;
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

    /// Restart ICE on a call (RFC 8445 §9): offer it again with new ICE
    /// credentials, so that both ends flush their checklists and check every
    /// pair again.
    ///
    /// What a call whose path has gone needs: consent lost or revoked
    /// ([`MediaError::IcePathLost`]), since RFC 7675 §5.1 forbids the same
    /// credentials on that pair again, or a network change the application
    /// saw before the agent did, since only a restart may "change the
    /// destinations of data streams" (§9).
    ///
    /// Everything but ICE is the description this end last wrote, carried
    /// across the way [`MediaEngine::change_codecs`] carries it: the codecs,
    /// the key or the fingerprint, multiplexing, and which way the call
    /// flows, with `a=setup` offered again as `actpass`. The ICE lines are
    /// written as for a first offer (RFC 8839 §4.4.1.1.1): new credentials,
    /// the role and tiebreaker the call has, and the candidates its agent
    /// still holds — a relay ICE gave back when it concluded on another pair
    /// is not offered again.
    ///
    /// The running agent is not touched until the far end answers. The pair
    /// it selected carries the audio meanwhile, and from the answer on as
    /// well, until the restarted agents have checked their way to a new one
    /// (RFC 8839 §4.4.3.1.1), reported as another [`MediaEvent::PathChosen`].
    /// A refusal leaves ICE exactly as it was: "Should a subsequent offer
    /// fail, ICE processing continues as if the subsequent offer had never
    /// been made" (§4.4).
    ///
    /// # Errors
    /// [`MediaError::NoSuchCall`] for a call this engine does not manage;
    /// [`MediaError::NoIce`] for one that runs no ICE agent;
    /// [`MediaError::NoDescription`] before this end has described it;
    /// [`MediaError::Ice`] should new credentials fail to draw; and
    /// [`MediaError::Signalling`] when the user agent will not send it —
    /// [`UaError::ChangeInProgress`] while another change is on its way,
    /// chiefly.
    #[cfg(feature = "ice")]
    pub fn restart_ice(
        &mut self,
        agent: &mut UserAgent,
        call: CallHandle,
        now: Instant,
    ) -> Result<(), MediaError> {
        let managed = self.calls.get(&call).ok_or(MediaError::NoSuchCall)?;
        let (Some(ice), Some(held)) = (managed.ice.clone(), self.sessions.get(&call)) else {
            return Err(MediaError::NoIce);
        };
        let running = {
            let slot = share::lock(held);
            if !slot.session.runs_ice() {
                return Err(MediaError::NoIce);
            }
            slot.session.ice_candidates()
        };
        let mut offer = managed.local.clone().ok_or(MediaError::NoDescription)?;
        let version = managed.version.saturating_add(1);
        let restarted = ice.restarted(&mut self.keys, running)?;

        withdraw_ice(&mut offer);
        describe_ice(&mut offer, Some(&restarted), None);
        for stream in &mut offer.media {
            stream.offer_roles_again();
        }
        offer.origin.version = version;

        agent.change_formats(call, &offer.to_bytes(), now)?;
        // the far end checks under the new credentials from the moment it
        // has answered, and its first checks can arrive before its answer
        // does: the agent keeps them for the moment the restart is taken up
        if let Some(held) = self.sessions.get(&call) {
            share::lock(held)
                .session
                .expect_ice_restart(Some(&restarted));
        }
        if let Some(managed) = self.calls.get_mut(&call) {
            managed.restarting = Some(restarted);
        }
        Ok(())
    }

    /// Describe a call's media at the socket the application bound for it
    /// after the network changed, and offer that to the far end (RFC 3264
    /// §8.3.1).
    ///
    /// What a call in progress needs once the address it was placed or
    /// answered from is gone: [`UaEvent::CallAddressWanted`] says which
    /// calls, the application binds a media socket on the new network and
    /// hands its address over here. `public` is where that socket appears
    /// from outside, as [`CallMedia::public_address`] takes it, when the
    /// application has learned one for the new socket; `None` describes the
    /// call by `local` itself.
    ///
    /// The offer is the description this end last wrote with only the
    /// address moved: `c=` wherever it appears and the port on `m=`, with
    /// the codecs, the direction, the key or the fingerprint carried across
    /// the way [`MediaEngine::change_codecs`] carries them. The `o=` line
    /// keeps its address, since §8 wants it identical but for the version.
    /// A DTLS association outlives the move — a datagram transport lets one
    /// span several 5-tuples (RFC 8842 §3.2) — so `a=setup` is offered
    /// again as `actpass` and the fingerprint is the one the call already
    /// has.
    ///
    /// The re-INVITE carries the account's `Contact` as it is when this is
    /// called, so [`UserAgent::rebind`] goes first: the far end addresses
    /// the rest of the dialog to that target (RFC 3261 §12.2). The new
    /// socket is this call's from here on, whatever the far end answers —
    /// the old one names an address the network no longer has. Audio from
    /// the far end arrives at the new socket once it has taken the offer,
    /// and [`MediaEvent::Changed`] follows that answer like any other.
    ///
    /// A call whose session runs ICE is not moved this way: its candidates
    /// were gathered on the old socket, and moving it is a restart gathered
    /// on the new one. A call that offered ICE to a peer that answered
    /// without any is an ordinary call, and the offer leaves the ICE lines
    /// out.
    ///
    /// # Errors
    /// [`MediaError::NoSuchCall`] for a call this engine does not manage;
    /// [`MediaError::NoDescription`] before this end has described it;
    /// [`MediaError::MovesWithIce`] for one that runs ICE; and
    /// [`MediaError::Signalling`] when the user agent will not send it —
    /// [`UaError::ChangeInProgress`] while another change is on its way,
    /// chiefly, which leaves the call where it was, to be moved again once
    /// that change is answered.
    pub fn readdress(
        &mut self,
        agent: &mut UserAgent,
        call: CallHandle,
        local: SocketAddr,
        public: Option<SocketAddr>,
        now: Instant,
    ) -> Result<(), MediaError> {
        let managed = self.calls.get(&call).ok_or(MediaError::NoSuchCall)?;
        if managed.address.is_none() {
            return Err(MediaError::NoDescription);
        }
        #[cfg(feature = "ice")]
        let offered_ice = managed.ice.is_some();
        #[cfg(feature = "ice")]
        if self
            .sessions
            .get(&call)
            .is_some_and(|held| share::lock(held).session.runs_ice())
        {
            return Err(MediaError::MovesWithIce);
        }
        let mut offer = managed.local.clone().ok_or(MediaError::NoDescription)?;
        let version = managed.version.saturating_add(1);
        let described = public.unwrap_or(local);

        #[cfg(feature = "ice")]
        if offered_ice {
            withdraw_ice(&mut offer);
        }
        let connection = Connection::new(described.ip());
        if offer.connection.is_some() {
            offer.connection = Some(connection.clone());
        }
        for stream in &mut offer.media {
            if stream.connection.is_some() {
                stream.connection = Some(connection.clone());
            }
            if !stream.is_rejected() {
                stream.port = described.port();
            }
            stream.offer_roles_again();
        }
        offer.origin.version = version;

        agent.change_formats(call, &offer.to_bytes(), now)?;
        if let Some(managed) = self.calls.get_mut(&call) {
            managed.address = Some(local);
            managed.public = public;
            #[cfg(feature = "ice")]
            {
                managed.ice = None;
                managed.restarting = None;
            }
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
        self.claim_ports();
        if let Some((call, event)) = self.events.pop_front() {
            self.counters.observe_media(&event);
            #[cfg(feature = "redaction")]
            self.log_media(call, &event, now);
            return Some(Event::Media { call, event });
        }
        if let Some((call, event)) = self.session_event() {
            self.counters.observe_media(&event);
            #[cfg(feature = "redaction")]
            self.log_media(call, &event, now);
            return Some(Event::Media { call, event });
        }
        let Some(signalling) = agent.poll_event() else {
            #[cfg(feature = "redaction")]
            self.log_decisions(agent, now);
            return None;
        };
        self.counters.observe_signalling(&signalling);
        #[cfg(feature = "redaction")]
        self.log_signalling(&signalling, now);
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
    /// or not its session ever opened, and unless another branch of its fork
    /// still holds the relay — or as soon as the call is known not to use it.
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
    /// with an error, and after [`MediaEngine::answer_with`] on a call
    /// [`MediaEngine::ring_with`] already described, which reads no relay
    /// because its description has already left. A relay nobody asks for is
    /// refreshed by nothing, and lapses at its server in the lifetime it was
    /// granted.
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
            if let Some((destination, transport)) = ice.take_probe() {
                return Some((
                    *call,
                    crate::RelayDatagram {
                        local: ice.local(),
                        destination,
                        payload: ice.probe().to_vec(),
                        transport,
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
    /// It is also how the datagrams on a socket the branches of a forked
    /// call share find their branch, sessions and all, for as long as the
    /// branches last: one offer described them all on the one socket, and
    /// only the datagram says which phone it came from (RFC 8839 §7.3). A
    /// session claims a check naming its own peer's fragment, an answer to
    /// its own check, and anything else from an address among its peer's
    /// candidates, what the TURN server relays from such an address
    /// included; one running no ICE claims what comes from the address its
    /// description named.
    ///
    /// In this order, the first that takes it:
    ///
    /// - the session of a call described there that claims it; with one
    ///   session there and no agent waiting beside it, that session takes
    ///   everything, audio and checks alike, exactly as through the share,
    ///   and `false` is a datagram the session dropped;
    /// - the agent of a call described there with a relay and still waiting
    ///   for its session, as [`MediaEngine::receive_waiting`] — which answers
    ///   the far end's checks itself, as well as its TURN server — for what
    ///   it claims, for its TURN server's answers when no session holds the
    ///   same relay, and for a check no session claims: a branch whose phone
    ///   has not answered yet;
    /// - the first session of a call described there, for anything nobody
    ///   claims;
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
        let open = match self.branch_for(local, from, data) {
            Branch::Session(held) => Some(held),
            Branch::Waiting => return self.receive_waiting(local, from, data, now),
            Branch::None => None,
        };
        #[cfg(not(feature = "ice"))]
        let open = self
            .calls
            .iter()
            .find_map(|(call, managed)| {
                (managed.address == Some(local))
                    .then(|| self.sessions.get(call))
                    .flatten()
            })
            .map(Arc::clone);
        if let Some(held) = open {
            let mut datagram = data.to_vec();
            let arrival = share::lock(&held).session.receive(&mut datagram, from, now);
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

    /// Which of the calls described on `local` a datagram from `from` is
    /// for — a session, or an agent still waiting for its session — when
    /// there may be more than one: the branches of a forked call, which one
    /// offer described on one socket.
    ///
    /// "The connectivity checks which occur prior to transmission of media
    /// carry username fragments which in turn are correlated to a specific
    /// callee. Subsequent media packets that arrive on the same candidate
    /// pair as the connectivity check will be associated with that same
    /// callee" (RFC 8839 §7.3). So a session's ICE agent claims a check that
    /// names its own peer's fragment, an answer to its own check, and
    /// anything else from an address among its peer's candidates — what the
    /// TURN server relays from such an address included — and a session
    /// running no ICE claims what comes from the address its description
    /// named. The TURN server's answers to the requests of the allocation
    /// the branches share go to whichever of them holds it. A check no
    /// session claims is a branch's that has not been answered yet, and goes
    /// to an agent still waiting for its session, which answers it (RFC 8445
    /// §7.3); anything else nobody claims goes where it always went, the
    /// first session described there.
    #[cfg(feature = "ice")]
    fn branch_for(&self, local: SocketAddr, from: SocketAddr, data: &[u8]) -> Branch {
        use sipral_nat::ice::Claim;

        let sessions: Vec<&share::Held> = self
            .calls
            .iter()
            .filter(|(_, managed)| managed.address == Some(local))
            .filter_map(|(call, _)| self.sessions.get(call))
            .collect();
        let waiting: Vec<&crate::ice::Ice> = self
            .gathered
            .values()
            .filter(|ice| ice.local() == local)
            .collect();
        let session_claiming = |wanted: Claim| {
            sessions
                .iter()
                .find(|held| share::lock(held).session.claims(from, data) == wanted)
                .map(|held| Arc::clone(held))
        };
        if let Some(held) = session_claiming(Claim::Mine) {
            return Branch::Session(held);
        }
        if waiting
            .iter()
            .any(|ice| ice.claims(from, data) == Claim::Mine)
        {
            return Branch::Waiting;
        }
        if let Some(held) = session_claiming(Claim::Shared) {
            return Branch::Session(held);
        }
        if !waiting.is_empty() {
            return Branch::Waiting;
        }
        sessions
            .first()
            .map_or(Branch::None, |held| Branch::Session(Arc::clone(held)))
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
    /// answers `None`. Each call picks up after the call the last one
    /// answered for, so one such drain looks at every session once, however
    /// many reports are due in it; a report that comes due behind the drain
    /// is found by the next one, which starts from the first call again.
    ///
    /// The octets are copied out rather than lent, because they are written
    /// into the session's own buffer and the session is only held for as long
    /// as this call runs. A report is due a few times a minute per call, so
    /// the copy costs nothing the audio path would notice; a thread that
    /// carries one call's audio can ask that call alone with
    /// [`MediaSession::poll_rtcp`] through a [`SessionShare`] instead.
    ///
    /// A report that goes through a relay's TCP or TLS connection is set
    /// aside for [`MediaEngine::poll_turn_stream`] instead.
    #[must_use]
    pub fn poll_rtcp(&mut self, now: Instant) -> Option<(CallHandle, SocketAddr, Vec<u8>)> {
        #[cfg(feature = "ice")]
        let (calls, streamed) = (&self.calls, &mut self.streamed);
        let from = self
            .rtcp_after
            .take()
            .map_or(Bound::Unbounded, Bound::Excluded);
        for (call, held) in self.sessions.range((from, Bound::Unbounded)) {
            #[cfg(test)]
            {
                self.rtcp_looked += 1;
            }
            let mut slot = share::lock(held);
            if !slot.session.rtcp_deadline_passed(now) {
                continue;
            }
            let Some(datagram) = slot.session.poll_rtcp(now) else {
                continue;
            };
            #[cfg(feature = "ice")]
            if datagram.transport.is_stream() {
                set_aside(streamed, calls, *call, &datagram);
                continue;
            }
            self.rtcp_after = Some(*call);
            return Some((*call, datagram.destination, datagram.payload.to_vec()));
        }
        None
    }

    /// The next real-time text datagram any call has due, and where: sent
    /// from that call's text socket ([`CallMedia::text`]), never its audio
    /// one. A thread that carries one call's media asks that call alone with
    /// [`MediaSession::poll_text`] instead.
    #[must_use]
    pub fn poll_text(&mut self, now: Instant) -> Option<(CallHandle, SocketAddr, Vec<u8>)> {
        self.sessions.iter().find_map(|(call, held)| {
            let mut slot = share::lock(held);
            slot.session
                .poll_text(now)
                .map(|datagram| (*call, datagram.destination, datagram.payload.to_vec()))
        })
    }

    /// The next event a session has to report.
    ///
    /// Taken from the list of calls whose sessions raised one, so the
    /// sessions locked are the ones on it and no others. A call that has
    /// ended since it was raised, or whose events were drained another way
    /// (`MediaSession::poll_event` through [`MediaEngine::session`]), is on
    /// the list once more than it needs to be and costs one look.
    fn session_event(&mut self) -> Option<(CallHandle, MediaEvent)> {
        while let Some(call) = self.ready.take() {
            let Some(held) = self.sessions.get(&call) else {
                continue;
            };
            #[cfg(test)]
            {
                self.sessions_polled += 1;
            }
            let mut slot = share::lock(held);
            let (event, more) = slot.session.take_for_engine();
            if more {
                self.ready.put_back(call);
            }
            if let Some(event) = event {
                return Some((call, event));
            }
        }
        None
    }

    /// Take a session that has just opened into the table, where its events
    /// reach [`MediaEngine::poll_event`].
    fn keep_session(&mut self, call: CallHandle, mut session: MediaSession) {
        session.report_to(call, Arc::clone(&self.ready));
        self.sessions.insert(call, share::hold(session));
    }

    /// Act on what the user agent said.
    fn absorb(&mut self, event: &UaEvent, agent: &mut UserAgent, now: Instant) {
        self.absorb_call(event, agent, now);
        // after the call's own media has taken the event in, so that a
        // recording reads the session as the event left it
        self.absorb_recording(event, agent, now);
    }

    /// Act on what the user agent said about a call this engine describes.
    fn absorb_call(&mut self, event: &UaEvent, agent: &mut UserAgent, now: Instant) {
        match event {
            UaEvent::IncomingCall {
                call,
                account,
                request,
                ..
            } => self.arrived(*call, *account, request, agent),
            UaEvent::CallForked { call, sibling } => self.forked(*call, *sibling, agent, now),
            UaEvent::CallProgress { call, response, .. } => {
                // a 183 with a description is early media: a network
                // announcement the caller has to hear before anybody answers
                self.take_body(*call, Some(response), now);
            }
            UaEvent::CallConfirmed { call, response, .. } => {
                self.take_body(*call, response.as_ref(), now);
                self.hang_up_insecure(*call, agent, now);
                // a 2xx is a call this end placed being answered, and who
                // answered it is decided from here; a call this end answered
                // confirms with an ACK and no response
                if response.is_some() {
                    self.answered(*call);
                }
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
                    // and an ICE restart refused is one that never happened
                    // (RFC 8839 §4.4): the agent goes on as it was, and keeps
                    // nothing for credentials that will never be in force
                    #[cfg(feature = "ice")]
                    if managed.restarting.take().is_some()
                        && let Some(held) = self.sessions.get(call)
                    {
                        share::lock(held).session.expect_ice_restart(None);
                    }
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

    /// A call this end placed whose answer the call's SRTP policy refused:
    /// acknowledged by now, since the 2xx that carried the answer is what
    /// confirmed it, and hung up (RFC 3261 §13.2.2.4: a UAC that does not
    /// want the dialog an acknowledged 2xx made sends a BYE), the `Reason`
    /// saying 488 so the far end's logs say why (RFC 3326).
    fn hang_up_insecure(&mut self, call: CallHandle, agent: &mut UserAgent, now: Instant) {
        let refused = self
            .calls
            .get_mut(&call)
            .is_some_and(|managed| core::mem::take(&mut managed.refused_keying));
        if refused {
            let reason = Reason::sip(488, "SRTP required");
            // a call already ending needs no second goodbye
            let _ = agent.hangup_for(call, &[reason], now);
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
    fn arrived(
        &mut self,
        call: CallHandle,
        account: Option<AccountId>,
        request: &OwnedMessage,
        agent: &mut UserAgent,
    ) {
        let (identity, session_id) = draw(agent);
        let catalog = account.map_or_else(|| self.catalog.clone(), |id| self.account_catalog(id));
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
                catalog,
                config: self.config.clone(),
                // nothing has been written for this call yet: what it will
                // say about DTLS-SRTP, and about ICE, is decided when it is
                // rung or answered
                dtls: None,
                #[cfg(feature = "dtls")]
                dtls_identity: None,
                #[cfg(feature = "ice")]
                ice: None,
                #[cfg(feature = "ice")]
                restarting: None,
                rung_with_media: false,
                payloads: Payloads::default(),
                pending: None,
                refused_keying: false,
                // a text socket is the application's to give, when it rings
                // or answers
                text: None,
            },
        );
    }

    /// A proxy forked the INVITE: the new branch was offered exactly what the
    /// old one was, so it inherits the description and gets a stream of its
    /// own to start from — the catalogue and configuration included, since a
    /// fork is the same call reaching two destinations, not two calls that
    /// happen to have started together.
    ///
    /// The offer named the fork's relay to this branch as much as to the
    /// first, so the branch takes it up at once, with an agent of its own
    /// waiting for its session beside the first branch's
    /// ([`MediaEngine::branch_agent`]): it keeps the allocation from going
    /// back to the server while this phone rings though every other branch
    /// may end or settle on a pair that needs no relay (RFC 8445 §8.3.1), and
    /// its session opens holding it.
    fn forked(
        &mut self,
        call: CallHandle,
        sibling: CallHandle,
        agent: &mut UserAgent,
        now: Instant,
    ) {
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
            let first = self.root_of(call);
            self.branches.insert(sibling, first);
            if let Ok(Some(ice)) = self.branch_agent(sibling, now) {
                self.gathered.insert(sibling, ice);
            }
        }
        #[cfg(not(feature = "ice"))]
        let _ = now;
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
            // the ICE restart this end offered, accepted: the credentials it
            // named are this call's from here on, and `settle` below hands
            // them to the running agent with the peer's new ones
            #[cfg(feature = "ice")]
            if managed
                .restarting
                .as_ref()
                .is_some_and(|restarting| restarting.written_in(&described))
            {
                managed.ice = managed.restarting.take();
            }
            managed.local = Some(described);
        }
        if let Some(described) = remote.and_then(|bytes| parse(bytes).ok()) {
            managed.remote = Some(described);
        }
        self.settle(call, now);
    }

    /// The key the answer to a re-offer carries: `in_force` repeated where
    /// there is one, since RFC 4568 §7.1.4 warns that changing it opens a
    /// window where the offerer cannot process what this end sends; one drawn
    /// fresh, at the width of whichever suite `offer` will be answered under,
    /// only where there is none to repeat. `None` where the stream will not
    /// be keyed at all.
    fn reoffer_keys(
        &mut self,
        catalog: &CodecCatalog,
        offer: &SessionDescription,
        in_force: Option<KeySalt>,
    ) -> Option<KeySalt> {
        will_key(catalog, Some(offer)).then(|| {
            in_force.unwrap_or_else(|| {
                draw_key_for(suite_for_own_key(Some(offer), catalog), &mut self.keys)
            })
        })
    }

    /// Keys for one stream of a recording session's offer: the suites
    /// `catalog` offers that protect at least as well as `call`, the suite
    /// the recorded call runs, and the call's own suite alone when none of
    /// them does.
    ///
    /// RFC 7866 §12.2: the SRC "SHOULD" protect the recording at least as
    /// well as the communication session it records, and a recording server
    /// offered a weaker suite beside the call's is free to take it (RFC 4568
    /// §5.1.2 leaves the answerer its own choice). Offering only suites at
    /// least as strong leaves it no weaker one to take. A call whose suite
    /// is not known yet — one waiting for its handshake — is offered what
    /// `catalog` offers.
    fn draw_recording_keys(
        &mut self,
        catalog: &CodecCatalog,
        call: Option<sipral_rtp::srtp::Suite>,
    ) -> Vec<(CryptoSuite, KeySalt)> {
        let Some(call) = call else {
            return self.draw_offer_keys(catalog);
        };
        let mut suites: Vec<CryptoSuite> = catalog
            .sdes_offered()
            .into_iter()
            .filter(|suite| keying::at_least_as_strong(keying::transform(*suite), call))
            .collect();
        if suites.is_empty() {
            suites.push(keying::crypto_suite(call));
        }
        suites
            .into_iter()
            .map(|suite| (suite, draw_key_for(suite, &mut self.keys)))
            .collect()
    }

    /// One key per suite `catalog` offers, in that order, for a fresh offer
    /// this end is about to write. Each width matches the suite it is drawn
    /// for, and RFC 4568 §6.1's "MUST be unique ... with respect to other
    /// master keys in the entire SDP message" holds because every draw
    /// moves this engine's own counter on.
    fn draw_offer_keys(&mut self, catalog: &CodecCatalog) -> Vec<(CryptoSuite, KeySalt)> {
        catalog
            .sdes_offered()
            .into_iter()
            .map(|suite| (suite, draw_key_for(suite, &mut self.keys)))
            .collect()
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
        let text = managed.text;
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
        let keys = self.reoffer_keys(&catalog, &offer, in_force);
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
            (session_id, version),
            keys.as_ref(),
            keyed(dtls.as_ref()),
            text,
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
                if agent.accept_reoffer(call, &bytes, now).is_ok()
                    && let Some(managed) = self.calls.get_mut(&call)
                {
                    managed.version = version;
                    #[cfg(feature = "dtls")]
                    {
                        managed.dtls_identity = managed.dtls_identity.take().or(named);
                    }
                    managed.dtls = dtls.map(|(_, setup)| (Side::Answering, setup));
                    #[cfg(feature = "ice")]
                    self.answered_ice(call, ice);
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
        // described with, and the server would hold it for minutes more,
        // unless another branch of its fork still holds it too
        #[cfg(feature = "ice")]
        {
            self.let_go(call, now);
            self.forget_branch(call);
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
            self.say_farewell(call, address, datagram);
        }
        // and the same courtesy to the far end's DTLS stack. It comes after
        // the BYE because a stream that never keyed has no BYE to send —
        // `send_bye` refuses to write one in the clear — and this is then the
        // only thing that tells the peer to stop retransmitting.
        #[cfg(feature = "dtls")]
        {
            session.close_handshake();
            while let Some(datagram) = session.poll_transmit(now) {
                self.say_farewell(call, address, datagram);
            }
        }
        // and last, because the goodbyes above may have left through it: the
        // relay goes back to its server (RFC 8656 §8) rather than holding a
        // port and the account's quota there until its lifetime runs out —
        // or, while another branch of the fork still holds it, stays theirs,
        // and stops letting this branch's peer through
        #[cfg(feature = "ice")]
        {
            let said = session.release_relays(now);
            match address {
                Some(local) => self.farewells_of(call, local, said),
                // with no socket to name, what is for a relay's connection
                // has no connection to go on, and the datagrams still leave
                None => self.farewells.extend(
                    said.into_iter()
                        .filter(|(_, transport, _)| !transport.is_stream())
                        .map(|(destination, _, payload)| (call, destination, payload)),
                ),
            }
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

/// Set aside a datagram `call`'s session wrote for its relay's connection to
/// the TURN server, from the socket the call was described on, for
/// [`MediaEngine::poll_turn_stream`].
#[cfg(feature = "ice")]
fn set_aside(
    streamed: &mut VecDeque<(CallHandle, crate::RelayDatagram)>,
    calls: &BTreeMap<CallHandle, Managed>,
    call: CallHandle,
    datagram: &crate::session::Datagram<'_>,
) {
    let Some(local) = calls.get(&call).and_then(|managed| managed.address) else {
        return;
    };
    streamed.push_back((
        call,
        crate::RelayDatagram {
            local,
            destination: datagram.destination,
            payload: datagram.payload.to_vec(),
            transport: datagram.transport,
        },
    ));
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
        let plan = match keyed_plan(&managed.catalog, local, remote) {
            Ok(plan) => plan,
            Err((error, refused)) => {
                // the policy's own refusal: a call this end placed is hung
                // up for it
                if refused && let Some(managed) = self.calls.get_mut(&call) {
                    managed.refused_keying = true;
                }
                self.fail(call, error);
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
        let annex_b = annex_b_in_use(&managed.catalog, local, remote, &plan);
        let feedback = match (live_stream(local), live_stream(remote)) {
            (Some(ours), Some(theirs)) => {
                crate::feedback::negotiated(ours, theirs, (plan.codec_in, plan.codec.payload()))
            }
            _ => None,
        };
        let text = crate::text::plan(local, remote);
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
        #[cfg(feature = "ice")]
        let peer_ice = remote
            .media
            .iter()
            .find(|stream| !stream.is_rejected())
            .and_then(|stream| sipral_nat::ice::parse_remote(remote, stream));
        let running = self.sessions.get(&call).map(Arc::clone);
        if let Some(held) = running {
            let mut slot = share::lock(&held);
            // a restart either end offered, now answered: the running agent
            // takes up the credentials this end's half carried and the
            // peer's new ones, and checks again, while the pair it had goes
            // on carrying the audio
            #[cfg(feature = "ice")]
            if let Err(error) =
                slot.session
                    .follow_ice(settled_ice.as_ref(), peer_ice.as_ref(), now)
            {
                self.fail(call, error);
            }
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
                if let Some(agreed) = feedback {
                    slot.session.use_feedback(agreed, now);
                }
                slot.session.set_text(text, now);
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
        self.start(
            call,
            &plan,
            codec,
            (annex_b, feedback, text),
            candidates,
            now,
        );
    }

    /// Open the stream for a plan, or carry the one that is running onto a
    /// codec the negotiation has moved to.
    ///
    /// A session already on this call is re-formatted rather than replaced, so
    /// that the stream, its SRTP contexts and everything the call has
    /// accumulated survive a codec change. [`MediaSession::reformat`] says
    /// what that is and why each piece of it matters.
    ///
    /// `agreed` is whether G.729's Annex B is in use, what RTCP feedback the
    /// descriptions agreed, which the stream runs from its first report, and
    /// what they agreed about real-time text.
    fn start(
        &mut self,
        call: CallHandle,
        plan: &MediaPlan,
        codec: Codec,
        agreed: (
            bool,
            Option<sipral_rtp::avpf::Negotiated>,
            Option<crate::text::TextPlan>,
        ),
        candidates: Vec<CodecCandidate>,
        now: Instant,
    ) {
        let (annex_b, feedback, text) = agreed;
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
                let reformatted =
                    slot.session
                        .reformat(plan, frame_length, &config, candidates, annex_b, now);
                if let Some(agreed) = feedback {
                    slot.session.use_feedback(agreed, now);
                }
                slot.session.set_text(text, now);
                reformatted
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
            .map(|mut session| {
                if let Some(agreed) = feedback {
                    session.use_feedback(agreed, now);
                }
                session.set_text(text, now);
                self.keep_session(call, session);
                self.tap_new_session(call);
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

// -- recording a call to a recording server (RFC 7866) -----------------------

impl MediaEngine {
    /// Record `call` to a recording server (SIPREC, RFC 7866): place a
    /// recording session from the call's own account, and once the server
    /// answers, copy the call's audio to it — this end's on one stream, the
    /// far end's on the other (`crate::siprec` has the whole of it).
    ///
    /// The handle that comes back is the recording session's own, an
    /// ordinary call to the user agent: its answer, its refusal and its end
    /// are [`UaEvent`]s like any call's, and hanging it up
    /// ([`MediaEngine::stop_recording_to`]) stops the recording. The copies
    /// come out of [`MediaSession::poll_recording`] on the recorded call, or
    /// [`MediaEngine::poll_recording`] for every call at once. The recording
    /// session ends by itself when the recorded call does, and follows a call
    /// that replaces it.
    ///
    /// # Errors
    /// [`MediaError::NoDescription`] for a call whose audio is not running,
    /// [`MediaError::AlreadyRecording`] for one already being recorded to a
    /// server, [`MediaError::Signalling`] when the user agent refuses the
    /// recording session or the call has no account to place it from.
    pub fn record_to(
        &mut self,
        agent: &mut UserAgent,
        call: CallHandle,
        to: crate::RecordTo,
        now: Instant,
    ) -> Result<CallHandle, MediaError> {
        if self.recordings.values().any(|held| held.recorded == call) {
            return Err(MediaError::AlreadyRecording);
        }
        let (codec, direction, encrypted, suite) = {
            let held = self.sessions.get(&call).ok_or(MediaError::NoDescription)?;
            let slot = share::lock(held);
            let plan = slot.session.plan();
            // the transform the call runs: the one a handshake keyed, or
            // failing that the one its SDES line names
            let suite = slot
                .session
                .encryption()
                .iter()
                .find_map(|stream| stream.suite)
                .or(match plan.keying {
                    Some(Keying::Sdes { ref local, .. }) => Some(keying::transform(local.suite)),
                    _ => None,
                });
            (
                plan.codec.clone(),
                plan.direction,
                plan.keying.is_some(),
                suite,
            )
        };
        let account = agent
            .call_account(call)
            .ok_or(MediaError::Signalling(UaError::NoSuchAccount))?;
        // RFC 7866 §12.2: the recording carries what the call did, and a call
        // kept from eavesdroppers is not copied past them in the clear unless
        // the account said it may be
        let in_clear = self
            .accounts
            .get(&account)
            .is_some_and(|srtp| srtp.recording_in_clear);
        let keys = (encrypted && !in_clear).then(|| {
            let catalog = self.account_catalog(account);
            [
                self.draw_recording_keys(&catalog, suite),
                self.draw_recording_keys(&catalog, suite),
            ]
        });
        let ends = call_ends(agent, call).ok_or(MediaError::NoSuchCall)?;
        let ids = [(); 5].map(|()| crate::siprec::draw_id(agent));
        let [session, this_party, far_party, this_stream, far_stream] = ids;
        let parties = crate::siprec::parties(
            session,
            [this_party, far_party, this_stream, far_stream],
            ends,
        );
        let (identity, session_id) = draw(agent);
        let (other, _) = draw(agent);
        let offer = crate::siprec::offer(&codec, &to, session_id, keys.as_ref());
        let mut outgoing = OutgoingCall::new(to.server.clone())
            .offer(Arc::from(offer.to_bytes()))
            .recording_session(&parties.metadata(direction))?;
        if let Some((transport, remote)) = to.destination {
            outgoing = outgoing.to_address(transport, remote);
        }
        let recording = agent.call(account, &outgoing, now)?;
        self.recordings.insert(
            recording,
            Recording {
                recorded: call,
                to,
                parties,
                payload_type: codec.payload(),
                session_id,
                numbers: [
                    (identity.ssrc, identity.sequence, identity.timestamp),
                    (other.ssrc, other.sequence, other.timestamp),
                ],
                destinations: None,
                keys,
                in_clear,
                answer: None,
                parked: None,
                told: Some(direction),
                owed: false,
            },
        );
        Ok(recording)
    }

    /// The recording session recording `call`, if one is.
    #[must_use]
    pub fn recording_of(&self, call: CallHandle) -> Option<CallHandle> {
        self.recordings
            .iter()
            .find(|(_, held)| held.recorded == call)
            .map(|(recording, _)| *recording)
    }

    /// Stop recording `call` to its recording server: the copies stop at
    /// once, and the recording session is hung up (RFC 7866 §6.1: it is a
    /// SIP session like any other, and it ends like one).
    ///
    /// # Errors
    /// [`MediaError::NotRecording`] for a call nothing records, and
    /// [`MediaError::Signalling`] for a BYE that could not be sent.
    pub fn stop_recording_to(
        &mut self,
        agent: &mut UserAgent,
        call: CallHandle,
        now: Instant,
    ) -> Result<(), MediaError> {
        let recording = self.recording_of(call).ok_or(MediaError::NotRecording)?;
        drop(self.untap(call));
        self.recordings.remove(&recording);
        agent.hangup(recording, now)?;
        Ok(())
    }

    /// The next copy of any recorded call's audio, to send from the socket
    /// it names: the recording session it is for, the socket, the recording
    /// server's address for the stream, and the packet.
    #[must_use]
    pub fn poll_recording(&mut self) -> Option<(CallHandle, SocketAddr, SocketAddr, Vec<u8>)> {
        self.recordings.iter().find_map(|(recording, held)| {
            let session = self.sessions.get(&held.recorded)?;
            let mut slot = share::lock(session);
            slot.session.poll_recording().map(|datagram| {
                (
                    *recording,
                    datagram.from,
                    datagram.destination,
                    datagram.payload.to_vec(),
                )
            })
        })
    }

    /// What the user agent said about a recording session, or about a call
    /// one records.
    fn absorb_recording(&mut self, event: &UaEvent, agent: &mut UserAgent, now: Instant) {
        match event {
            UaEvent::CallConfirmed {
                call,
                response: Some(response),
                ..
            } if self.recordings.contains_key(call) => {
                let answer = crate::siprec::answer_in(response);
                self.server_answered(*call, answer.as_ref());
            }
            UaEvent::SessionChanged { call, remote, .. } if self.recordings.contains_key(call) => {
                let answer = remote
                    .as_deref()
                    .and_then(|body| sipral_core::sdp::parse(body).ok());
                self.server_answered(*call, answer.as_ref());
                self.send_metadata(*call, agent, now);
                self.codec_owed(*call, agent, now);
            }
            UaEvent::SessionChangeFailed { call, .. } if self.recordings.contains_key(call) => {
                self.send_metadata(*call, agent, now);
                self.codec_owed(*call, agent, now);
            }
            UaEvent::SessionChanged { call, hold, .. } => {
                let direction = match (!hold.remote, !hold.local) {
                    (true, true) => Direction::SendRecv,
                    (true, false) => Direction::SendOnly,
                    (false, true) => Direction::RecvOnly,
                    (false, false) => Direction::Inactive,
                };
                self.recorded_codec(*call, agent, now);
                self.recorded_moved(*call, Some(direction), agent, now);
            }
            UaEvent::CallReplaced { call, replaced } => {
                self.recording_follows(*replaced, *call, agent, now);
            }
            UaEvent::CallEnded { call, .. } => {
                if self.recordings.remove(call).is_some() {
                    // the server hung up: nothing more is copied to it
                    return;
                }
                if let Some(recording) = self.recording_of(*call) {
                    self.recordings.remove(&recording);
                    let _ = agent.hangup(recording, now);
                }
            }
            _ => {}
        }
    }

    /// The recording server answered the recording session, or answered a
    /// change to it: point the copies where it said.
    fn server_answered(&mut self, recording: CallHandle, answer: Option<&SessionDescription>) {
        let Some(held) = self.recordings.get_mut(&recording) else {
            return;
        };
        let Some(answer) = answer else {
            return;
        };
        let mut destinations = crate::siprec::destinations(answer);
        if let Some(keys) = held.keys.as_ref() {
            // a stream the server did not take as SRTP under a line this end
            // offered is one this end sends nothing to
            let keyed = crate::siprec::protection(answer, keys);
            for (destination, keyed) in destinations.iter_mut().zip(keyed) {
                if keyed.is_none() {
                    *destination = None;
                }
            }
        }
        held.destinations = Some(destinations);
        held.answer = Some(answer.clone());
        self.attach_tap(recording, true);
    }

    /// Copy the recorded call's audio to where the server receives it, on
    /// the session running now; one already copying is pointed there, and
    /// copies taken off a call this one replaced carry on here. `answered`
    /// when the server has just answered, which may have moved the line that
    /// keys an SRTP stream.
    fn attach_tap(&mut self, recording: CallHandle, answered: bool) {
        let Some(held) = self.recordings.get_mut(&recording) else {
            return;
        };
        let Some(destinations) = held.destinations else {
            return;
        };
        let Some(session) = self.sessions.get(&held.recorded) else {
            return;
        };
        let mut slot = share::lock(session);
        // a recording session that went in the clear, for a call that was
        // not encrypted then, copies nothing of an encrypted call that
        // replaced it unless the account said it may (RFC 7866 §12.2); the
        // copies wait, numbered as they were, for audio they may carry
        if held.keys.is_none() && !held.in_clear && slot.session.plan().keying.is_some() {
            if let Some(running) = slot.session.tap_to(None) {
                held.parked = Some(running);
            }
            return;
        }
        let keyed = || {
            held.keys
                .as_ref()
                .zip(held.answer.as_ref())
                .map(|(keys, answer)| crate::siprec::protection(answer, keys))
        };
        if let Some(tap) = slot.session.tap() {
            tap.redirect(destinations);
            if let Some(keyed) = keyed().filter(|_| answered) {
                tap.protect(keyed);
            }
            return;
        }
        let received = slot.session.plan().codec_in;
        let (mut tap, fresh) = match held.parked.take() {
            Some(mut tap) => {
                tap.follow();
                tap.copy_payload_type((held.payload_type, received));
                tap.redirect(destinations);
                (tap, false)
            }
            None => (
                crate::siprec::Tap::new(
                    &held.to,
                    destinations,
                    (held.payload_type, received),
                    held.numbers,
                ),
                true,
            ),
        };
        if let Some(keyed) = keyed().filter(|_| answered || fresh) {
            tap.protect(keyed);
        }
        slot.session.tap_to(Some(tap));
    }

    /// Stop copying `call`'s audio, and hand back the copies that ran.
    fn untap(&mut self, call: CallHandle) -> Option<crate::siprec::Tap> {
        self.sessions
            .get(&call)
            .and_then(|session| share::lock(session).session.tap_to(None))
    }

    /// A recorded call moved to another codec: offer the server its two
    /// streams on it (RFC 7866 §7.1.1.1 has an SRC change a recorded stream
    /// with a new offer), and copy the new codec from here on.
    fn recorded_codec(&mut self, call: CallHandle, agent: &mut UserAgent, now: Instant) {
        let Some(recording) = self.recording_of(call) else {
            return;
        };
        let Some((codec, received)) = self.sessions.get(&call).map(|session| {
            let slot = share::lock(session);
            let plan = slot.session.plan();
            (plan.codec.clone(), plan.codec_in)
        }) else {
            return;
        };
        let Some(held) = self.recordings.get_mut(&recording) else {
            return;
        };
        if held.payload_type == codec.payload() {
            return;
        }
        let offer = crate::siprec::offer(&codec, &held.to, held.session_id, held.keys.as_ref());
        // `reoffer` moves the `o=` version on (RFC 3264 §8)
        if agent.reoffer(recording, &offer.to_bytes(), now).is_ok() {
            held.payload_type = codec.payload();
            if let Some(session) = self.sessions.get(&call)
                && let Some(tap) = share::lock(session).session.tap()
            {
                tap.copy_payload_type((codec.payload(), received));
            }
        }
    }

    /// A recorded call's media moved: tell the server who sends now.
    fn recorded_moved(
        &mut self,
        call: CallHandle,
        direction: Option<Direction>,
        agent: &mut UserAgent,
        now: Instant,
    ) {
        let Some(recording) = self.recording_of(call) else {
            return;
        };
        let Some(held) = self.recordings.get_mut(&recording) else {
            return;
        };
        if held.told == direction {
            return;
        }
        held.told = direction;
        held.owed = true;
        self.send_metadata(recording, agent, now);
    }

    /// A call that replaced a recorded one takes the recording over (RFC
    /// 3891): its far end is the recorded call's second party from here on,
    /// the server is told, and the copies move to its audio once it runs.
    fn recording_follows(
        &mut self,
        replaced: CallHandle,
        call: CallHandle,
        agent: &mut UserAgent,
        now: Instant,
    ) {
        let Some(recording) = self.recording_of(replaced) else {
            return;
        };
        let Some(((_, _), (far, name))) = call_ends(agent, call) else {
            return;
        };
        let id = crate::siprec::draw_id(agent);
        let running = self.untap(replaced);
        if let Some(held) = self.recordings.get_mut(&recording) {
            held.recorded = call;
            held.parties.replace_far_end(id, far, name);
            held.owed = true;
            // the copies carry on, numbered and keyed as they were
            held.parked = running;
        }
        self.attach_tap(recording, false);
        self.send_metadata(recording, agent, now);
        self.recorded_codec(call, agent, now);
    }

    /// A change of codec the recording session could not offer when the
    /// recorded call moved, because another change was running in it: offer
    /// it now that that change is over.
    fn codec_owed(&mut self, recording: CallHandle, agent: &mut UserAgent, now: Instant) {
        if let Some(recorded) = self.recordings.get(&recording).map(|held| held.recorded) {
            self.recorded_codec(recorded, agent, now);
        }
    }

    /// Send the server the metadata it is owed, now or once the change
    /// running in the recording session is over.
    fn send_metadata(&mut self, recording: CallHandle, agent: &mut UserAgent, now: Instant) {
        let Some(held) = self.recordings.get_mut(&recording) else {
            return;
        };
        if !held.owed {
            return;
        }
        let metadata = held
            .parties
            .metadata(held.told.unwrap_or(Direction::SendRecv));
        held.owed = matches!(
            agent.update_recording_metadata(recording, &metadata, now),
            Err(UaError::ChangeInProgress)
        );
    }

    /// A session that has just opened for a call being recorded starts
    /// copying at once: the call that replaced a recorded one, most often.
    fn tap_new_session(&mut self, call: CallHandle) {
        if let Some(recording) = self.recording_of(call) {
            self.attach_tap(recording, false);
        }
    }
}

/// This end's address of record and display name on `call`, and the far
/// end's: the `From` of a call placed here and the `To` of one answered here
/// are this end's.
fn call_ends(
    agent: &UserAgent,
    call: CallHandle,
) -> Option<(crate::siprec::End, crate::siprec::End)> {
    let identity = agent.call_identity(call)?;
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    let named = |bytes: &[u8]| (!bytes.is_empty()).then(|| text(bytes));
    let from = (text(&identity.from_uri), named(&identity.from_display));
    let to = (text(&identity.to_uri), None);
    Some(
        if agent.call_direction(call) == Some(sipral_ua::Direction::Outgoing) {
            (from, to)
        } else {
            (to, from)
        },
    )
}

// -- a local conference of two calls -----------------------------------------

impl MediaEngine {
    /// The call `call` is currently joined with, if any.
    #[must_use]
    pub fn joined_with(&self, call: CallHandle) -> Option<CallHandle> {
        self.joins.get(&call).copied()
    }

    /// A local conference for this engine's calls: any number of them, each
    /// on its own codec, with or without this end —
    /// [`LocalConference`](crate::LocalConference) says what it does and how
    /// it is driven. The engine keeps nothing of it; the serial numbers of
    /// its Ogg recordings are drawn from this engine's own randomness, as a
    /// call's are.
    ///
    /// # Errors
    /// Those of [`LocalConference::new`](crate::LocalConference::new).
    pub fn local_conference(
        &mut self,
        config: crate::LocalConferenceConfig,
    ) -> Result<crate::LocalConference, MediaError> {
        let block = self.keys.block();
        let mut seed = [0_u8; 8];
        for (to, from) in seed.iter_mut().zip(block) {
            *to = from;
        }
        crate::LocalConference::new(config, u64::from_le_bytes(seed))
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

/// Take every ICE line out of a description this end wrote, for
/// [`describe_ice`] to write a restart's in their place: the stream's
/// credentials, options and candidates, and the session's pacing and
/// `a=ice-lite` (RFC 8839 §5).
#[cfg(feature = "ice")]
fn withdraw_ice(description: &mut SessionDescription) {
    const STREAM: [&str; 7] = [
        "ice-ufrag",
        "ice-pwd",
        "ice-options",
        "candidate",
        "remote-candidates",
        "end-of-candidates",
        "ice-mismatch",
    ];
    const SESSION: [&str; 5] = [
        "ice-ufrag",
        "ice-pwd",
        "ice-options",
        "ice-pacing",
        "ice-lite",
    ];
    description
        .attributes
        .retain(|attribute| !SESSION.contains(&attribute.name.as_str()));
    for stream in &mut description.media {
        stream
            .attributes
            .retain(|attribute| !STREAM.contains(&attribute.name.as_str()));
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
    keys: Option<Vec<(CryptoSuite, KeySalt)>>,
    dtls: Option<Keyed<'_>>,
    text: Option<SocketAddr>,
) -> SessionDescription {
    let mut description = SessionDescription::new(
        Origin::new(session_id, version, address.ip()),
        Connection::new(address.ip()),
    );
    let mut stream = catalog
        .offering(keys, dtls)
        .offer(AUDIO, address.port(), Direction::SendRecv);
    if catalog.feedback() {
        crate::feedback::offer(&mut stream);
    }
    description.media.push(fall_back(stream, catalog, dtls));
    if let Some(text) = text.filter(|_| text_offered(catalog)) {
        description.media.push(crate::text::offer(text.port()));
    }
    description
}

/// `SrtpPolicy::DtlsOrSdes`: the SDES offer, with the fingerprint and the
/// role beside its crypto lines, so that a DTLS-SRTP peer answers one and an
/// SDES-only peer the other. Every other policy's offer is left as written.
#[cfg(feature = "dtls")]
fn fall_back(
    mut stream: MediaDescription,
    catalog: &CodecCatalog,
    dtls: Option<Keyed<'_>>,
) -> MediaDescription {
    if let Some(keyed) = dtls.filter(|_| catalog.srtp().falls_back()) {
        let at = stream
            .attributes
            .iter()
            .position(|attribute| attribute.name == "crypto")
            .unwrap_or(stream.attributes.len());
        stream.attributes.splice(
            at..at,
            [
                Attribute::with_value("fingerprint", keyed.fingerprint),
                Attribute::with_value("setup", keyed.setup),
            ],
        );
    }
    stream
}

/// Without the feature there is no fingerprint to fall back from.
#[cfg(not(feature = "dtls"))]
const fn fall_back(
    stream: MediaDescription,
    _catalog: &CodecCatalog,
    _dtls: Option<Keyed<'_>>,
) -> MediaDescription {
    stream
}

/// Refuse an INVITE whose offer this call's SRTP policy will not carry
/// audio on: 488 Not Acceptable Here (RFC 3261 §21.4.26), the answer to an
/// offer whose terms this end cannot take. The error to return with it.
fn refuse_insecure(agent: &mut UserAgent, call: CallHandle, now: Instant) -> MediaError {
    // a call already answered or gone has nothing left to refuse, and the
    // error still says why it was not answered here
    let _ = agent.reject(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
    MediaError::SrtpRequired
}

/// Whether a call on `catalog` offers real-time text: only on plain RTP and
/// without ICE, since the text stream is neither keyed nor given candidates
/// (`crate::text`).
fn text_offered(catalog: &CodecCatalog) -> bool {
    !catalog.srtp().offers() && !catalog.ice().offers()
}

/// Whether a call on `catalog` takes the text stream `offer` carries: the
/// same, and only beside audio the offer did not key.
fn text_answered(catalog: &CodecCatalog, offer: &SessionDescription) -> bool {
    !any_secure_stream(offer) && !catalog.srtp().requires() && !catalog.ice().offers()
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

/// The suite this end's own SDES key is drawn for: the suite
/// `keying::acceptable` would take from the peer's offer, the same suite
/// `take_stream` accepts a few frames later, or this end's own offered suite
/// when there is no peer description to read one from — an INVITE with no
/// body leaves this end offering rather than answering, and a description
/// with no crypto line at all leaves nothing for `acceptable` to read either,
/// in which case the width is never used since `will_key` said no key is
/// wanted (8.2.4).
///
/// Computed here rather than threaded down from `take_stream` because the
/// key has to exist before that function is reached: `write_answer` takes the
/// key already drawn, not a suite to draw one from.
fn suite_for_own_key(offered: Option<&SessionDescription>, catalog: &CodecCatalog) -> CryptoSuite {
    offered
        .and_then(|offer| offer.media.first())
        .and_then(|stream| keying::acceptable(stream, catalog.srtp_suites()))
        .map_or(CryptoSuite::AesCm80, |policy| policy.suite)
}

/// Whether any live stream of a description is on one of the secure profiles.
fn any_secure_stream(description: &SessionDescription) -> bool {
    description
        .media
        .iter()
        .any(|stream| !stream.is_rejected() && keying::is_secure(&stream.proto))
}

/// What the two descriptions agreed, held to the call's SRTP policy: the
/// plan, or the error to end the call's media with and whether it is the
/// policy's own refusal ([`MediaError::SrtpRequired`]).
fn keyed_plan(
    catalog: &CodecCatalog,
    local: &SessionDescription,
    remote: &SessionDescription,
) -> Result<MediaPlan, (MediaError, bool)> {
    let plan = match local.media_plan(remote, 0) {
        Ok(Some(plan)) => plan,
        Ok(None) => return Err((MediaError::StreamRefused, false)),
        // a secured stream the far end described with no key: under a
        // policy that requires one, that is the policy's refusal
        Err(SdpError::CryptoMissing { .. }) if catalog.srtp().requires() => {
            return Err((MediaError::SrtpRequired, true));
        }
        Err(error) => return Err((MediaError::from(error), false)),
    };
    keying_holds(catalog, &plan, remote).map_err(|error| {
        let refused = error == MediaError::SrtpRequired;
        (error, refused)
    })?;
    Ok(plan)
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
///
/// The one exception is real-time text: a call given a text socket
/// ([`CallMedia::text`]) takes the first `m=text` stream on it, when
/// [`text_answered`] allows, and says it runs no RTCP.
fn write_answer(
    catalog: &CodecCatalog,
    offer: &SessionDescription,
    address: SocketAddr,
    (session_id, version): (u64, u64),
    keys: Option<&KeySalt>,
    dtls: Option<Keyed<'_>>,
    text: Option<SocketAddr>,
) -> Result<SessionDescription, MediaError> {
    let mut taken = false;
    let mut text = text.filter(|_| text_answered(catalog, offer));
    let mut text_at = None;
    let streams: Vec<StreamAnswer> = offer
        .media
        .iter()
        .enumerate()
        .map(|(index, offered)| {
            if offered.media == crate::text::TEXT && !offered.is_rejected() {
                let Some(socket) = text.take() else {
                    return StreamAnswer::Reject;
                };
                let answer = crate::text::answer(offered, socket.port());
                if matches!(answer, StreamAnswer::Accept(_)) {
                    text_at = Some(index);
                }
                return answer;
            }
            if taken {
                return StreamAnswer::Reject;
            }
            let answer = take_stream(catalog, offered, address, keys, dtls);
            taken = matches!(answer, StreamAnswer::Accept(_));
            answer
        })
        .collect();
    let mut answer = offer
        .answer(
            Origin::new(session_id, version, address.ip()),
            Connection::new(address.ip()),
            &streams,
        )
        .map_err(MediaError::from)?;
    if let Some(index) = text_at {
        crate::text::no_rtcp(&mut answer, index);
    }
    Ok(answer)
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
    // Under `SrtpPolicy::DtlsOrSdes` the answer follows the offer: a
    // fingerprint is answered with ours, and crypto lines alone with SDES
    #[cfg(feature = "dtls")]
    let handshake = dtls.filter(|_| {
        keying::is_secure(&offered.proto)
            && (!catalog.srtp().falls_back() || offered.attribute("fingerprint").is_some())
    });
    #[cfg(not(feature = "dtls"))]
    let handshake: Option<Keyed<'_>> = None;
    // RFC 4568 §7.1.2: a stream on the secure profile is answered by
    // accepting exactly one of its crypto lines, or it is refused. There is
    // no third answer, and a stream taken without a key would be one both
    // ends believe is encrypted
    let crypto = if keying::is_secure(&offered.proto) && handshake.is_none() {
        match (keying::acceptable(offered, catalog.srtp_suites()), keys) {
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
    let capabilities = catalog.capabilities();
    if (capabilities.rtcp_mux || handshake.is_some()) && offered.has_rtcp_mux() {
        accepted = accepted.with_attribute(Attribute::flag("rtcp-mux"));
    }
    // RFC 3611 §5.2: "For 'sendrecv' offers, the answerer MAY include the
    // 'rtcp-xr' attribute in its response, and specify any unilateral
    // parameters in order to request that the offerer send the
    // corresponding XR blocks. The offerer SHOULD send these blocks." The
    // offer's own line only asks this end to send; without this one a call
    // this end answered never hears what the far end measured of its audio,
    // and its quality report has no `RemoteMetrics` set to write
    if capabilities.voip_metrics_xr {
        accepted = accepted.with_attribute(Attribute::with_value("rtcp-xr", "voip-metrics"));
    }
    // RFC 4585 §4.2: an answerer keeps the feedback it will do and leaves
    // the rest out. The profile itself is the offer's either way, since an
    // answer does not change the transport of a stream it accepts
    if catalog.feedback() {
        for line in crate::feedback::answer(offered, &formats) {
            accepted = accepted.with_attribute(line);
        }
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

/// The widest key and salt any suite this stack offers or answers needs
/// together: `Aes256Cm80`'s thirty-two-octet key and fourteen-octet salt
/// (8.2.4). Held apart from `CryptoSuite::key_len() + salt_len()` so the
/// block-count arithmetic below reads as what it is — two of the engine's
/// thirty-two byte blocks always cover it — rather than a suite lookup on
/// every draw.
const MAX_KEY_SALT: usize = 46;

/// The master key and salt for one description under `suite`, out of the
/// engine's own seed.
///
/// Its own and not the endpoint's, which is the whole point: the endpoint's
/// seed is written in clear into every replay recording, so a recording made
/// from a stack that shared one generator would carry the means to derive
/// every key that stack had ever offered and every key it ever would.
///
/// One or two blocks of `SHA-256(media seed || counter)` cover the width
/// `suite` calls for — one for everything up to thirty-two octets, which is
/// every suite but `Aes256Cm80`'s forty-six, and RFC 4568 §7.1.2's "the
/// master key(s) in the answer MUST be different from those in the offer"
/// holds because the counter behind each block never repeats. **What a poor
/// media seed costs is the whole of the encryption**, and it costs it
/// silently: SDES then protects the media against nobody while every message
/// still looks right.
///
/// The blocks, and the key and salt sliced from them, live in [`Zeroizing`]
/// rather than a plain array (8.2.9). A buffer that is merely dropped is a
/// buffer that stays on the stack for whatever runs next; `Zeroizing` wipes
/// its bytes in its own `Drop`, which a later edit to this function cannot
/// silently stop doing the way it could stop a `fill(0)` written by hand.
///
/// Every octet is copied out one at a time rather than sliced, because this
/// is the one function in the tree where reading past the end must not be
/// recoverable: a fallible slice with a zero-filled fallback would hand out a
/// key of zeros, and the paragraph above is about exactly how quiet that
/// failure is. `MAX_KEY_SALT` holds the width no suite here exceeds, so a
/// later suite wider than that stops the build rather than silently handing
/// out a truncated key.
const _: () = assert!(
    MAX_KEY_SALT <= 64,
    "two of the engine's own blocks must cover the widest suite"
);

fn draw_key_for(suite: CryptoSuite, keys: &mut KeySource) -> KeySalt {
    let first = Zeroizing::new(keys.block());
    let mut block = Zeroizing::new([0_u8; 64]);
    for (slot, byte) in block.iter_mut().zip(first.iter()) {
        *slot = *byte;
    }
    if suite.key_salt_len() > 32 {
        let second = Zeroizing::new(keys.block());
        for (slot, byte) in block.iter_mut().skip(32).zip(second.iter()) {
            *slot = *byte;
        }
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    let mut salt = Zeroizing::new([0_u8; 14]);
    for (slot, byte) in key.iter_mut().zip(block.iter()) {
        *slot = *byte;
    }
    for (slot, byte) in salt.iter_mut().zip(block.iter().skip(suite.key_len())) {
        *slot = *byte;
    }
    KeySalt::new(
        key.get(..suite.key_len()).unwrap_or_default(),
        salt.get(..suite.salt_len()).unwrap_or_default(),
    )
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

// -- the RTP port range ------------------------------------------------------

impl MediaEngine {
    /// Hand RTP ports out of `ports` from now on, or stop with `None`.
    ///
    /// The application owns every socket, so the range opens nothing: it is
    /// the rule [`MediaEngine::reserve_rtp_port`] follows, and the one a
    /// firewall in front of the deployment is written to. Reservations already
    /// held are kept.
    pub const fn set_rtp_ports(&mut self, ports: Option<RtpPorts>) {
        self.rtp_ports = ports;
    }

    /// The range ports are handed out of, when one was set.
    #[must_use]
    pub const fn rtp_ports(&self) -> Option<RtpPorts> {
        self.rtp_ports
    }

    /// A free even port from the range for a call's RTP, with the odd port
    /// above it kept for its RTCP; `None` when no range was set.
    ///
    /// Free means: not handed out already, and not the port a call this
    /// engine holds describes its media at. The port is the caller's to bind
    /// and to describe a call at, by [`MediaEngine::place`],
    /// [`MediaEngine::ring`] or [`MediaEngine::answer`]; it stays reserved
    /// for as long as that call describes its media there, and is free again
    /// once the call ends or moves off it. One that no call ever took — the
    /// bind failed, the call was refused — is handed back with
    /// [`MediaEngine::release_rtp_port`].
    ///
    /// # Errors
    /// [`PortsExhausted`] when every pair in the range is in use. Nothing is
    /// reserved then, and the call that wanted a port cannot be given one
    /// until another lets its go.
    pub fn reserve_rtp_port(&mut self) -> Option<Result<u16, PortsExhausted>> {
        let range = self.rtp_ports?;
        self.claim_ports();
        let in_use: std::collections::BTreeSet<u16> = self
            .calls
            .values()
            .filter_map(|managed| managed.address.map(|address| address.port()))
            .chain(self.reserved_ports.keys().copied())
            .collect();
        let pairs = range.pairs();
        let start = self.next_pair % pairs;
        for step in 0..pairs {
            let index = (start + step) % pairs;
            let port = range.pair(index);
            if !in_use.contains(&port) && !in_use.contains(&port.saturating_add(1)) {
                self.reserved_ports.insert(port, false);
                self.next_pair = (index + 1) % pairs;
                return Some(Ok(port));
            }
        }
        Some(Err(PortsExhausted { range }))
    }

    /// Hand back a port [`MediaEngine::reserve_rtp_port`] gave out and no
    /// call is using, and say whether it was one.
    pub fn release_rtp_port(&mut self, port: u16) -> bool {
        self.reserved_ports.remove(&port).is_some()
    }

    /// How many ports are reserved right now, a call's included.
    #[must_use]
    pub fn rtp_ports_reserved(&self) -> usize {
        self.reserved_ports.len()
    }

    /// Mark every reservation a call now describes its media at as taken,
    /// and let go of every one a call took and no call describes any more.
    ///
    /// Run at the top of every [`MediaEngine::poll_event`] — before this
    /// engine can learn that a call ended — so a call that took a port is
    /// seen holding it before the event that ends it is read, and the port
    /// comes back when it should rather than staying reserved for good.
    fn claim_ports(&mut self) {
        if self.reserved_ports.is_empty() {
            return;
        }
        let described: std::collections::BTreeSet<u16> = self
            .calls
            .values()
            .filter_map(|managed| managed.address.map(|address| address.port()))
            .collect();
        self.reserved_ports.retain(|port, claimed| {
            if described.contains(port) {
                *claimed = true;
                true
            } else {
                !*claimed
            }
        });
    }
}

// -- the log and the state snapshot -----------------------------------------

#[cfg(feature = "redaction")]
impl MediaEngine {
    /// Write this engine's lines to `log` from now on: every event
    /// [`MediaEngine::poll_event`] hands out, and every decision the
    /// diagnostic record writes down, at the levels `crate::log` gives them.
    ///
    /// The engine only queues lines. Whoever drives it calls
    /// [`crate::Log::flush`] once it holds nothing the sink could need.
    pub fn set_log(&mut self, log: crate::Log) {
        self.log = Some(log);
    }

    /// The log this engine writes to, if one was set.
    #[must_use]
    pub const fn log(&self) -> Option<&crate::Log> {
        self.log.as_ref()
    }

    fn log_line(
        &self,
        level: crate::LogLevel,
        target: &'static str,
        now: Instant,
        line: impl FnOnce() -> String,
    ) {
        if let Some(log) = &self.log {
            log.line(level, target, now, line);
        }
    }

    fn log_signalling(&self, event: &UaEvent, now: Instant) {
        use crate::LogLevel::{Debug, Info, Warn};
        use core::fmt::Write as _;
        let Some(log) = &self.log else {
            return;
        };
        if !log.enabled(Warn) {
            return;
        }
        match event {
            UaEvent::Registered {
                account,
                expires,
                refresh_in,
                ..
            } => self.log_line(Info, "registration", now, || {
                format!(
                    "account {}: registered for {} s, refreshing in {} s",
                    number(account),
                    expires.as_secs(),
                    refresh_in.as_secs()
                )
            }),
            UaEvent::RegistrationFailed {
                account,
                reason,
                status,
                retry_in,
                ..
            } => self.log_line(Warn, "registration", now, || {
                let mut line = format!(
                    "account {}: registration failed, {reason:?}",
                    number(account)
                );
                if let Some(status) = status {
                    let _ = write!(line, ", status {}", status.get());
                }
                match retry_in {
                    Some(after) => {
                        let _ = write!(line, ", retrying in {} s", after.as_secs());
                    }
                    None => line.push_str(", not retrying"),
                }
                line
            }),
            UaEvent::Unregistered { account, .. } => {
                self.log_line(Info, "registration", now, || {
                    format!("account {}: unregistered", number(account))
                });
            }
            UaEvent::IncomingCall { call, account, .. } => self.log_line(Info, "call", now, || {
                account.map_or_else(
                    || format!("call {}: incoming", number(call)),
                    |account| {
                        format!(
                            "call {}: incoming on account {}",
                            number(call),
                            number(account)
                        )
                    },
                )
            }),
            UaEvent::CallConfirmed { call, .. } => self.log_line(Info, "call", now, || {
                format!("call {}: confirmed", number(call))
            }),
            UaEvent::CallEnded {
                call,
                reason,
                status,
                ..
            } => self.log_line(Info, "call", now, || {
                let mut line = format!("call {}: ended, {reason:?}", number(call));
                if let Some(status) = status {
                    let _ = write!(line, ", status {}", status.get());
                }
                line
            }),
            UaEvent::CallerVerified {
                call, verification, ..
            } => self.log_verification(*call, verification, now),
            other => self.log_line(Debug, "signalling", now, || variant(other)),
        }
    }

    /// The verdict on a caller and why, never the numbers: what a log may
    /// carry about a caller is the redactor's to decide, and it is not handed
    /// these.
    fn log_verification(
        &self,
        call: CallHandle,
        verification: &sipral_ua::CallerVerification,
        now: Instant,
    ) {
        use crate::LogLevel::{Info, Warn};
        use core::fmt::Write as _;
        let level = if verification.refused { Warn } else { Info };
        self.log_line(level, "identity", now, || {
            let mut line = format!("call {}: caller {:?}", number(call), verification.outcome);
            if let Some(attestation) = verification.attestation {
                let _ = write!(line, ", attestation {}", attestation.as_str());
            }
            if let Some(failure) = verification.failure {
                let _ = write!(line, ", {failure}");
            }
            if let Some((code, _)) = verification
                .response
                .as_ref()
                .filter(|_| verification.refused)
            {
                let _ = write!(line, ", refused {code}");
            }
            line
        });
    }

    fn log_media(&self, call: CallHandle, event: &MediaEvent, now: Instant) {
        use crate::LogLevel::{Debug, Info, Warn};
        let Some(log) = &self.log else {
            return;
        };
        if !log.enabled(Warn) {
            return;
        }
        let call = number(call);
        match event {
            MediaEvent::Started { .. } => {
                self.log_line(Info, "media", now, || format!("call {call}: media started"));
            }
            MediaEvent::Stalled { .. } => self.log_line(Warn, "media", now, || {
                format!("call {call}: inbound audio stopped arriving")
            }),
            MediaEvent::Resumed { .. } => self.log_line(Info, "media", now, || {
                format!("call {call}: inbound audio resumed")
            }),
            MediaEvent::Ended(statistics) => self.log_line(Info, "media", now, || {
                format!(
                    "call {call}: media ended, {}, sent {}, received {}, lost {}",
                    statistics.codec,
                    statistics.packets_sent,
                    statistics.quality.received,
                    statistics.quality.lost
                )
            }),
            other => self.log_line(Debug, "media", now, || {
                format!("call {call}: {}", variant(other))
            }),
        }
    }

    /// Every decision the diagnostic record has written since the last time
    /// this looked, one debug line each — `docs/14-diagnostics.md`'s reason
    /// code and the sizes and addresses it turned on.
    fn log_decisions(&mut self, agent: &mut UserAgent, now: Instant) {
        let Some(log) = self.log.clone() else {
            return;
        };
        if !log.enabled(crate::LogLevel::Debug) {
            self.logged.clear();
            return;
        }
        let endpoint = agent.endpoint();
        let mut records: Vec<(Option<Vec<u8>>, &sipral_core::diag::Record)> =
            vec![(None, endpoint.endpoint_record())];
        for call in endpoint.recorded_calls() {
            if let Some(record) = endpoint.call_record(call) {
                records.push((Some(call.as_bytes().to_vec()), record));
            }
        }
        let mut seen = BTreeMap::new();
        for (key, record) in records {
            let written = record.dropped().saturating_add(record.len() as u64);
            let before = self.logged.get(&key).copied().unwrap_or(0);
            let fresh = usize::try_from(written.saturating_sub(before))
                .unwrap_or(usize::MAX)
                .min(record.len());
            for decision in record.decisions().skip(record.len() - fresh) {
                log.line(crate::LogLevel::Debug, "decision", now, || {
                    decision_line(key.as_deref(), decision)
                });
            }
            seen.insert(key, written);
        }
        // a record the endpoint evicted is forgotten here too
        self.logged = seen;
    }

    /// What this engine and `agent` are holding right now, for a crash
    /// report: see [`crate::EngineState`]. Never waits: a session another
    /// thread is inside is reported as busy.
    #[must_use]
    pub fn state(&self, agent: &UserAgent, now: Instant) -> crate::EngineState {
        use crate::state::{AccountState, CallSnapshot, MediaState, StreamState};
        let accounts = agent
            .accounts()
            .into_iter()
            .map(|account| AccountState {
                account,
                aor: agent
                    .account(account)
                    .map(|held| held.aor().to_string())
                    .unwrap_or_default(),
                registration: agent.registration_state(account),
            })
            .collect();
        let calls = agent
            .calls()
            .into_iter()
            .map(|call| CallSnapshot {
                call,
                state: agent.call_state(call),
                media_address: self.calls.get(&call).and_then(|managed| managed.address),
            })
            .collect();
        let media = self
            .sessions
            .iter()
            .map(|(call, held)| MediaState {
                call: *call,
                stream: held.try_lock().ok().map(|slot| {
                    let statistics = slot.session.statistics(now);
                    StreamState {
                        codec: statistics.codec,
                        destination: slot.session.destination(),
                        packets_sent: statistics.packets_sent,
                        packets_received: statistics.quality.received,
                        packets_lost: statistics.quality.lost,
                    }
                }),
            })
            .collect();
        crate::EngineState::new(accounts, calls, media, self.counters)
    }
}

/// A handle's number, without the type name `Debug` puts round it.
#[cfg(feature = "redaction")]
fn number(handle: impl core::fmt::Debug) -> String {
    format!("{handle:?}")
        .chars()
        .filter(char::is_ascii_digit)
        .collect()
}

/// The name of an enum variant, from its `Debug` form, and nothing it
/// carries: an event's fields can hold whole messages, and a debug line
/// names what happened without them.
#[cfg(feature = "redaction")]
fn variant(value: &impl core::fmt::Debug) -> String {
    let written = format!("{value:?}");
    written
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// One decision as a log line.
#[cfg(feature = "redaction")]
fn decision_line(call_id: Option<&[u8]>, decision: &sipral_core::diag::Decision) -> String {
    use core::fmt::Write as _;
    use sipral_core::diag::Wire;
    let mut line = decision.reason.as_str().to_owned();
    match call_id {
        Some(call_id) => {
            let _ = write!(line, " call-id {}", String::from_utf8_lossy(call_id));
        }
        None => line.push_str(" endpoint"),
    }
    if let Some(wire) = &decision.wire {
        let _ = write!(line, " {}", wire.direction.as_str());
        match &wire.message {
            Wire::Request(method) => {
                let _ = write!(line, " {}", method.as_str());
            }
            Wire::Response(status) => {
                let _ = write!(line, " {}", status.get());
            }
        }
        let _ = write!(line, " {} bytes", wire.bytes);
    }
    if let Some(address) = decision.address {
        let _ = write!(line, " {address}");
    }
    if let Some(protocol) = decision.protocol {
        let _ = write!(line, " {}", protocol.as_str());
    }
    if let Some(measure) = decision.measure {
        let _ = write!(line, " size {} limit {}", measure.size, measure.limit);
    }
    line
}

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
            dtmf_in: None,
            codec_in: 0,
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
                KeySalt::new(&[1; 16], &[2; 14]),
            ),
            remote: sipral_core::sdp::CryptoPolicy::new(
                1,
                sipral_core::sdp::CryptoSuite::AesCm80,
                KeySalt::new(&[3; 16], &[4; 14]),
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
            local: CryptoPolicy::new(1, CryptoSuite::AesCm80, KeySalt::new(&[1; 16], &[2; 14])),
            remote: CryptoPolicy::new(1, CryptoSuite::AesCm80, KeySalt::new(&[3; 16], &[4; 14])),
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
        write_answer(
            catalog,
            &described(stream),
            address,
            (1, 1),
            None,
            None,
            None,
        )
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
    //! [`MediaEngine::session_event`], which takes from the sessions that
    //! raised one what each has queued on its own (a stall, a resume, a
    //! recording that stopped). `crates/sipral/src/counters.rs` is thorough about what
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
        // room for the thousand calls the cost of a poll is measured over
        let mut config = EndpointConfig::default();
        config.max_dialogs = 2_000;
        let mut agent = UserAgent::new(config, [5; 32]).expect("a user agent");
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
        // short enough that the test does not need to fake a ten-second
        // clock jump to reach it
        open_session(
            engine,
            call,
            (Some(Duration::from_millis(50)), RtcpPlan::Off),
            now,
        );
        (agent, call)
    }

    /// Open a session for `call` by hand and give it to the engine, with a
    /// stall watchdog of `stall_after`, or none.
    fn open_session(
        engine: &mut MediaEngine,
        call: CallHandle,
        (stall_after, rtcp): (Option<Duration>, RtcpPlan),
        now: Instant,
    ) {
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
            dtmf_in: None,
            codec_in: 0,
            rtcp,
            keying: None,
            voip_metrics_xr: false,
        };
        let config = MediaConfig {
            stall_after,
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
        engine.keep_session(call, session);
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

    /// `poll_event` used to lock every session in turn to ask whether it had
    /// something to say, so a stack holding thousands of calls paid for all
    /// of them on every event it handed out, signalling ones included. It
    /// now reads the list of calls whose sessions raised an event: here a
    /// thousand sessions are held, one of them stalls, and draining the
    /// engine locks that one session and no other.
    /// An engine holding `sessions` sessions, the first of them with a stall
    /// watchdog of 50 ms and every other with `rtcp`, and the signalling
    /// events of setting them up drained.
    fn many_sessions(
        sessions: usize,
        rtcp: RtcpPlan,
        now: Instant,
    ) -> (MediaEngine, UserAgent, CallHandle) {
        let mut engine = MediaEngine::new(
            CodecCatalog::new(),
            MediaConfig::default(),
            WallClock::from_unix(now, 1_700_000_000, 0),
            [31; 32],
        );
        let (mut agent, stalling) = call_with_a_stalling_session(&mut engine, now);
        let account = agent.add_account(Account::new(
            Uri::parse_str("sip:many@example.com").expect("a URI"),
            Uri::parse_str("sip:example.com").expect("a URI"),
            Uri::parse_str("sip:many@192.0.2.20").expect("a URI"),
            TRANSPORT,
            "192.0.2.99:5060".parse().expect("an address"),
        ));
        for _ in 1..sessions {
            let call = agent
                .call(
                    account,
                    &OutgoingCall::new(Uri::parse_str("sip:carol@example.com").expect("a URI")),
                    now,
                )
                .expect("the INVITE can be built");
            open_session(&mut engine, call, (None, rtcp), now);
        }
        // the INVITEs themselves are signalling, drained here so that what
        // is counted afterwards is media alone
        while engine.poll_event(&mut agent, now).is_some() {}
        assert_eq!(engine.sessions.len(), sessions);
        (engine, agent, stalling)
    }

    #[test]
    fn a_poll_looks_only_at_the_sessions_that_have_an_event() {
        const SESSIONS: usize = 1_000;
        let now = Instant::now();
        let (mut engine, mut agent, stalling) = many_sessions(SESSIONS, RtcpPlan::Off, now);
        let before = engine.sessions_polled;

        let later = now + Duration::from_millis(200);
        engine.handle_timeout(later);
        let mut stalled = Vec::new();
        while let Some(event) = engine.poll_event(&mut agent, later) {
            if let Event::Media {
                call,
                event: MediaEvent::Stalled { .. },
            } = event
            {
                stalled.push(call);
            }
        }
        assert_eq!(
            stalled,
            [stalling],
            "the one session with a watchdog stalled"
        );
        assert_eq!(
            engine.sessions_polled - before,
            1,
            "draining one event from one session of {SESSIONS} locked more than that session"
        );

        // and with nothing raised, asking again locks none at all
        assert!(engine.poll_event(&mut agent, later).is_none());
        assert_eq!(engine.sessions_polled - before, 1);
    }

    /// `poll_rtcp` used to start from the first session on every call, so
    /// draining k due reports out of n sessions looked at up to k·n of them:
    /// ten thousand calls, each reporting every five seconds, cost the
    /// signalling thread more than the five milliseconds between its sweeps
    /// on the lab machine. A drain now picks up where the last report came
    /// from, and looks at each session once.
    #[test]
    fn a_drain_of_rtcp_looks_at_each_session_once() {
        const SESSIONS: usize = 500;
        let now = Instant::now();
        let rtcp = RtcpPlan::SeparatePort {
            local: "192.0.2.20:40001".parse().expect("an address"),
            remote: "203.0.113.9:40011".parse().expect("an address"),
        };
        let (mut engine, _agent, _) = many_sessions(SESSIONS, rtcp, now);

        // past every session's first report, however §6.3 drew it
        let later = now + Duration::from_secs(10);
        let before = engine.rtcp_looked;
        let mut reports = 0;
        while engine.poll_rtcp(later).is_some() {
            reports += 1;
        }
        assert_eq!(reports, SESSIONS - 1, "every session with RTCP reported");
        assert!(
            engine.rtcp_looked - before <= SESSIONS,
            "{} sessions looked at to drain {reports} reports from {SESSIONS}",
            engine.rtcp_looked - before
        );

        // and the next drain starts from the first call again: nothing is
        // due, and every session is looked at once to say so
        let before = engine.rtcp_looked;
        assert!(engine.poll_rtcp(later).is_none());
        assert_eq!(engine.rtcp_looked - before, SESSIONS);
    }

    /// Events a session queues while the engine is taking one of them out
    /// still come out, in order: the call goes back at the head of the list
    /// for as long as it has more, and is raised afresh once it had none.
    #[test]
    fn a_session_with_several_events_is_drained_in_order_and_raised_again_later() {
        let now = Instant::now();
        let mut engine = MediaEngine::new(
            CodecCatalog::new(),
            MediaConfig::default(),
            WallClock::from_unix(now, 1_700_000_000, 0),
            [37; 32],
        );
        let (mut agent, call) = call_with_a_stalling_session(&mut engine, now);
        while engine.poll_event(&mut agent, now).is_some() {}
        let pushed = |engine: &MediaEngine, gaps: &[u64]| {
            let held = engine.sessions.get(&call).expect("the session");
            let mut slot = crate::share::lock(held);
            for gap in gaps {
                slot.session.push_event_for_test(MediaEvent::Resumed {
                    silent_for: Duration::from_millis(*gap),
                });
            }
        };
        pushed(&engine, &[1, 2, 3]);
        let mut seen = Vec::new();
        while let Some(event) = engine.poll_event(&mut agent, now) {
            if let Event::Media {
                event: MediaEvent::Resumed { silent_for },
                ..
            } = event
            {
                seen.push(silent_for.as_millis());
            }
        }
        assert_eq!(seen, [1, 2, 3]);

        pushed(&engine, &[4]);
        assert!(
            matches!(
                engine.poll_event(&mut agent, now),
                Some(Event::Media {
                    event: MediaEvent::Resumed { silent_for },
                    ..
                }) if silent_for == Duration::from_millis(4)
            ),
            "a session drained once is raised again by its next event"
        );
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
    use super::{CryptoSuite, KeySource, draw_key_for};

    fn draw(keys: &mut KeySource) -> sipral_core::sdp::KeySalt {
        draw_key_for(CryptoSuite::AesCm80, keys)
    }

    #[test]
    fn the_media_key_follows_the_media_seed_and_nothing_else() {
        // The whole of the fix, in three lines: two stacks given the same
        // signalling entropy — which a replay recording carries in clear —
        // must not be derivable from it to the same media keys.
        let mut one = KeySource::new([1; 32]);
        let mut other = KeySource::new([2; 32]);
        let mut same_again = KeySource::new([1; 32]);

        let first = draw(&mut one);
        assert_ne!(
            first.key(),
            draw(&mut other).key(),
            "two media seeds, two keys"
        );
        assert_eq!(
            first.key(),
            draw(&mut same_again).key(),
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
            let drawn = draw(&mut keys);
            let pair = (drawn.key().to_vec(), drawn.salt().to_vec());
            assert!(!seen.contains(&pair), "a key repeated");
            seen.push(pair);
        }
    }

    /// Every suite this end can answer with draws a key and salt of its own
    /// width, and two different suites drawn from the same point in the
    /// stream do not share the octets each takes as its key (8.2.4).
    #[test]
    fn every_suite_draws_its_own_width() {
        for suite in CryptoSuite::STRENGTH {
            let mut keys = KeySource::new([7; 32]);
            let drawn = draw_key_for(suite, &mut keys);
            assert_eq!(drawn.key().len(), suite.key_len(), "{}", suite.name());
            assert_eq!(drawn.salt().len(), suite.salt_len(), "{}", suite.name());
        }
    }

    /// The block(s) `draw_key_for` reads and the key and salt sliced out of
    /// them (8.2.9, generalised in 8.2.4) hold the SRTP master key and salt,
    /// so all three have to be the type that wipes itself on drop rather than
    /// a plain array left to be merely dropped, or a `Vec` that leaves its
    /// last copy in freed memory. A wipe is not observable from safe Rust and
    /// Miri cannot be pointed at this, so what is asserted is the one thing
    /// that is visible: which type the function declares its buffers as. The
    /// needles are assembled at runtime, so the test cannot pass by matching
    /// its own assertion — the same check `sipral-core` runs on `A1` in
    /// `auth::digest::tests::the_password_is_never_built_in_a_buffer_that_is_not_wiped`.
    #[test]
    fn the_media_key_and_salt_are_never_built_in_a_buffer_that_is_not_wiped() {
        let source = include_str!("engine.rs").replace("\r\n", "\n");
        let opens = "fn draw_key_for(suite: CryptoSuite, keys: &mut KeySource) -> KeySalt {";
        let from = source.find(opens).expect("draw_key_for is in this file");
        let rest = source.get(from..).expect("the rest of the file");
        let to = rest.find("\n}\n").map_or(rest.len(), |at| at + 1);
        let body = rest.get(..to).expect("the body of draw_key_for");
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
