// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Joins signalling to media: a call the user agent reports gets audio, and a call that ends gives
//! it up.
//!
//! `docs/01-architecture.md` keeps `sipral-ua` and the media crates independent of each other. What
//! passes between them is a description: [`MediaCapabilities`] into an offer, [`MediaPlan`] out of
//! the negotiation and into a stream. This is not a wrapper around [`UserAgent`]. It holds only the
//! operations that need both halves (placing, ringing, answering, draining events); everything else
//! is done on the user agent directly.
//!
//! # One drain
//!
//! [`MediaEngine::poll_event`] drains the user agent itself. An application that polled the user
//! agent on its own would steal the events this engine needs, and the call would ring, answer and
//! stay silent.
//!
//! # Which calls it manages
//!
//! Calls placed with [`MediaEngine::place`], rung with [`MediaEngine::ring`], answered with
//! [`MediaEngine::answer`] or taken from a transfer with [`MediaEngine::accept_transfer`]. A call
//! placed straight on the user agent is left alone. Answering a rung call reuses the session and
//! description the ring wrote; RFC 3262 §5 and RFC 6337 §3.1.1 decide what the 200 OK repeats.
//!
//! # Per-call catalogue
//!
//! Each call copies the catalogue and [`MediaConfig`] it starts with, so later changes to the
//! engine defaults do not move it. The `_with` variants take a [`CallMedia`] for one call; an
//! attended transfer needs this, since `UserAgent::consult` holds two calls at once.

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
    AcceptedStream, Attribute, Connection, CryptoPolicy, CryptoSuite, Direction, KeySalt, Keying,
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
use crate::keying::{self, AccountSrtp, SdesSignalling, Shape};
use crate::payloads::Payloads;
use crate::ports::{PortsExhausted, RtpPorts};
use crate::session::{MediaConfig, MediaSession, Start, StreamIdentity};
use crate::share::{self, Held, Ready, SessionGuard, SessionShare};

/// The media type this stack negotiates. There is no video; any other stream is refused.
pub(crate) const AUDIO: &str = "audio";

/// RFC 4733 named events. An answer keeps them even though no codec is behind them.
const TELEPHONE_EVENT: &str = "telephone-event";

/// RFC 3389 comfort noise, likewise.
const COMFORT_NOISE: &str = "CN";

/// How many early connectivity checks one socket keeps while its call has no session yet
/// ([`MediaEngine::receive_early`]).
///
/// Checks arrive one per Ta, 50 ms by default (RFC 8445 §14.2), so this covers most of a second.
/// The oldest is dropped first, and a retransmission replaces the copy it repeats.
#[cfg(feature = "ice")]
const EARLY_CHECKS: usize = 16;

/// How long a kept check is still worth answering. With the RFC 8489 §6.2.1 defaults (Rc 7, Rm 16,
/// RTO 500 ms) the far end gives up after 39.5 s.
#[cfg(feature = "ice")]
const EARLY_CHECK_LIFETIME: Duration = Duration::from_millis(39_500);

/// One of the far end's connectivity checks, kept for a call that has no
/// session yet ([`MediaEngine::receive_early`]).
#[cfg(feature = "ice")]
#[derive(Debug)]
struct EarlyCheck {
    from: SocketAddr,
    data: Vec<u8>,
    at: Instant,
}

#[cfg(feature = "ice")]
impl EarlyCheck {
    /// The STUN transaction id (RFC 8489 §5), which a retransmission repeats.
    fn transaction(&self) -> Option<&[u8]> {
        self.data.get(8..20)
    }

    fn live(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.at) < EARLY_CHECK_LIFETIME
    }
}

/// What this engine knows about one call.
#[derive(Clone, Debug)]
struct Managed {
    /// What this end has described. `None` for an incoming call until it is answered.
    local: Option<SessionDescription>,
    remote: Option<SessionDescription>,
    /// Where this end receives media. Set only by the calls that write a description (place, ring
    /// with media, answer), so `None` marks a call whose media the application handles itself; see
    /// [`MediaEngine::answer_reoffer`].
    address: Option<SocketAddr>,
    /// The socket's address as seen from outside ([`CallMedia::public_address`]), written in `c=`
    /// and `m=` instead of `address`.
    public: Option<SocketAddr>,
    identity: StreamIdentity,
    session_id: u64,
    /// The `o=` version this end is up to (RFC 3264 §8).
    version: u64,
    /// What this call offers, in order. Copied from the engine default or the `_with` override when
    /// the call starts, and never re-read from the engine.
    catalog: CodecCatalog,
    /// How this call's session is opened, copied the same way as `catalog`.
    config: MediaConfig,
    /// The DTLS side and `a=setup` this end wrote in its last description.
    /// [`dtls_role`](sipral_dtls::setup::dtls_role) needs both offer and answer values, and only
    /// one arrives from the far end.
    dtls: Option<(Side, String)>,
    /// The DTLS key and certificate this call named in its first description. Kept for the whole
    /// call so the fingerprint never changes, even after the engine renews its own.
    #[cfg(feature = "dtls")]
    dtls_identity: Option<Arc<Identity>>,
    /// This call's ICE credentials, role, tiebreaker and candidates.
    ///
    /// Repeated on every later description (RFC 8839 §4.4.1.1.1). Fresh credentials on a hold
    /// re-offer would look like an unrequested ICE restart.
    #[cfg(feature = "ice")]
    ice: Option<crate::ice::LocalIce>,
    /// The ICE for a restart this end offered ([`MediaEngine::restart_ice`]). Becomes
    /// [`Managed::ice`] once accepted; a refusal drops it (RFC 8839 §4.4).
    #[cfg(feature = "ice")]
    restarting: Option<crate::ice::LocalIce>,
    /// Whether [`MediaEngine::ring_with`] already described the call and opened its session.
    /// One-way: ringing with media twice is refused.
    rung_with_media: bool,
    /// Every dynamic payload type either end has written on this call. RFC 3264 §8.3.2 keeps a
    /// number bound to its codec for the whole session; [`MediaEngine::change_codecs`] numbers
    /// against this.
    payloads: Payloads,
    /// Codecs offered by [`MediaEngine::change_codecs`] and not answered yet. A refusal leaves the
    /// old list (RFC 3261 §14.1).
    pending: Option<Pending>,
    /// The far end answered with keying the call's SRTP policy refuses. The call is hung up with a
    /// `Reason` once its 2xx is acknowledged.
    refused_keying: bool,
    /// Who besides the far end may hold the SDES key this end wrote.
    exposure: Exposure,
    /// Where this call's real-time text arrives, when it was given a socket
    /// for it ([`CallMedia::text`]).
    text: Option<SocketAddr>,
}

/// Who besides the far end may hold the SDES key this end wrote for a call.
#[derive(Clone, Copy, Debug, Default)]
struct Exposure {
    /// Whether the key went out in unencrypted signalling ([`MediaEngine::keys_in_clear`]).
    in_clear: bool,
    /// Whether the INVITE forked, so other user agents hold the offered key. Cleared by
    /// [`MediaEngine::rekey_after_fork`].
    forked: bool,
}

/// A codec change on its way to the far end.
#[derive(Clone, Debug)]
struct Pending {
    /// What the call's catalogue becomes once the offer is accepted.
    catalog: CodecCatalog,
    /// The offered formats, used to recognise the answer to this change.
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

/// What one call opens with when it does not use the engine defaults.
///
/// Not `Clone`: it can carry a [`Relay`](crate::Relay), which is a server allocation for one call.
#[derive(Debug)]
pub struct CallMedia {
    /// What to offer, in what order.
    pub catalog: CodecCatalog,
    /// How to open the session.
    pub config: MediaConfig,
    /// Where the media socket appears from outside; see [`CallMedia::public_address`].
    pub public: Option<SocketAddr>,
    /// A TURN relay allocated from the media socket; see [`CallMedia::relay`].
    #[cfg(feature = "ice")]
    pub relay: Option<crate::Relay>,
    /// Where real-time text arrives; see [`CallMedia::text`].
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

    /// Give the call real-time text (RFC 4103) on a second socket bound at `address`. An offer
    /// carries an `m=text` stream, and an offer with one is answered with it. `crate::text` has the
    /// details.
    ///
    /// Text runs on plain `RTP/AVP` without RTCP, so it is left out when the catalogue offers SRTP
    /// or ICE, or when the offered audio is keyed.
    #[must_use]
    pub const fn text(mut self, address: SocketAddr) -> Self {
        self.text = Some(address);
        self
    }

    /// Give the call a TURN relay, allocated from its media socket with [`Relays`](crate::Relays).
    ///
    /// With an [`IcePolicy`](crate::IcePolicy) that offers full ICE, the relay becomes the relayed
    /// candidate (RFC 8445 §5.1.1.2) and the server-reflexive address goes beside it, also into
    /// `c=` and `m=` unless the call has a public address. Once the call is described, its ICE
    /// agent owns the allocation: permissions, channel binding, keepalives, and the final Refresh
    /// with lifetime zero (RFC 8656 §8). Forked branches share it; it goes back when the last one
    /// lets go. Those datagrams come out of [`MediaEngine::poll_transmit`] and
    /// [`MediaEngine::poll_farewell`].
    ///
    /// A call that cannot use the relay (no ICE, lite role, other address family) gives it back at
    /// once. If the description is refused, nothing named the relay, and it comes back live through
    /// [`MediaEngine::poll_returned_relay`] for [`Relays::put_back`](crate::Relays::put_back). The
    /// same happens on [`MediaEngine::answer_with`] after [`MediaEngine::ring_with`], since the 183
    /// already carried the description.
    #[cfg(feature = "ice")]
    #[must_use]
    pub fn relay(mut self, relay: crate::Relay) -> Self {
        self.relay = Some(relay);
        self
    }

    /// Split off the relay so the description can hold it until it can no longer be refused.
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

    /// Describe the media socket by its public address instead of the bound one.
    ///
    /// The address comes from a STUN mapping or a static one-to-one NAT. Every description uses it
    /// in `c=` and `m=`; the bound address stays for the socket and the ICE candidate base. Because
    /// one mapping covers one port, the description asks for `a=rtcp-mux` (RFC 5761). Under an
    /// [`IcePolicy`](crate::IcePolicy) that offers ICE, the address is also a server-reflexive
    /// candidate and the default candidate in `c=` (RFC 8839 §4.2.1.2).
    #[must_use]
    pub fn public_address(mut self, public: SocketAddr) -> Self {
        self.public = Some(public);
        self
    }

    /// The catalogue a call offers from, asking for multiplexing when it uses a public address.
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
    /// The default catalogue for new calls. Each call keeps its own copy in [`Managed`], so
    /// changing this does not affect calls in progress.
    catalog: CodecCatalog,
    /// Per-account SRTP settings ([`MediaEngine::set_account_srtp`]), applied over
    /// [`MediaEngine::catalog`] when a call starts.
    accounts: BTreeMap<AccountId, AccountSrtp>,
    config: MediaConfig,
    clock: WallClock,
    /// A `BTreeMap` so tests drain events in a stable order.
    ///
    /// Each session sits behind its own lock, and this is its only strong reference. An audio
    /// thread reaches it through a [`SessionShare`].
    sessions: BTreeMap<CallHandle, Held>,
    /// Calls whose sessions have an event waiting, so [`MediaEngine::poll_event`] only locks those.
    ready: Arc<Ready>,
    /// Sessions locked by [`MediaEngine::poll_event`], for the cost test.
    #[cfg(test)]
    sessions_polled: usize,
    /// Where the current [`MediaEngine::poll_rtcp`] drain resumes.
    rtcp_after: Option<CallHandle>,
    /// Sessions locked by [`MediaEngine::poll_rtcp`], for the cost test.
    #[cfg(test)]
    rtcp_looked: usize,
    calls: BTreeMap<CallHandle, Managed>,
    events: VecDeque<(CallHandle, MediaEvent)>,
    /// RTCP goodbyes of ended calls. Owned bytes, since the session is gone by the time they are
    /// polled.
    farewells: VecDeque<(CallHandle, SocketAddr, Vec<u8>)>,
    /// Calls in a two-call local conference, mapped both ways so [`MediaEngine::joined_with`] works
    /// from either side.
    joins: BTreeMap<CallHandle, CallHandle>,
    /// Health counters; see `crate::counters`.
    counters: Counters,
    /// Source of every SRTP master key and DTLS secret.
    ///
    /// Separate from the endpoint's generator because a replay recording carries the endpoint seed
    /// in clear. A recording must not carry the means to decrypt its media or to impersonate the
    /// stack.
    keys: KeySource,
    /// The DTLS-SRTP key and certificate, made on the first call that needs one and renewed near
    /// expiry.
    ///
    /// `None` until then, so a stack without encrypted calls never generates a P-256 key. Shared
    /// because each call keeps the identity it described ([`Managed::dtls_identity`]).
    #[cfg(feature = "dtls")]
    identity: Option<Arc<Identity>>,
    /// ICE agents of calls described with a relay and still waiting for a session.
    ///
    /// Kept rather than rebuilt from [`Managed::ice`], because the TURN allocation is server state.
    /// They are driven by [`MediaEngine::handle_timeout`] and [`MediaEngine::poll_transmit`] so the
    /// NAT binding survives a long ring.
    #[cfg(feature = "ice")]
    gathered: BTreeMap<CallHandle, crate::ice::Ice>,
    /// Early connectivity checks per socket, oldest first, kept for the session's agent (RFC 8445
    /// §7.3).
    #[cfg(feature = "ice")]
    early: BTreeMap<SocketAddr, VecDeque<EarlyCheck>>,
    /// Relays from refused descriptions, waiting for [`MediaEngine::poll_returned_relay`].
    #[cfg(feature = "ice")]
    returned: VecDeque<crate::Relay>,
    /// Each branch of a forked call, mapped to the call the first description was written for.
    #[cfg(feature = "ice")]
    branches: BTreeMap<CallHandle, CallHandle>,
    /// The relay allocation a fork shares, kept while any branch is left
    /// ([`crate::ice::LocalIce::shared_agent`]).
    #[cfg(feature = "ice")]
    fork_relays: BTreeMap<CallHandle, sipral_nat::ice::SharedRelay>,
    /// Bytes for a relay's TCP or TLS connection, waiting for [`MediaEngine::poll_turn_stream`].
    #[cfg(feature = "ice")]
    streamed: VecDeque<(CallHandle, crate::RelayDatagram)>,
    /// The range [`MediaEngine::reserve_rtp_port`] hands out, if set.
    rtp_ports: Option<RtpPorts>,
    /// Reserved RTP ports, each flagged once a call is seen using it. A flagged port no call uses
    /// any more is released.
    reserved_ports: BTreeMap<u16, bool>,
    /// Where the next reservation starts searching. Round-robin, so a just-released port is reused
    /// last.
    next_pair: u16,
    /// Where this engine's log lines go, once the application installed one.
    #[cfg(feature = "redaction")]
    log: Option<crate::Log>,
    /// How many decisions of each diagnostic record were already logged, by `Call-ID` (`None` for
    /// the endpoint record).
    #[cfg(feature = "redaction")]
    logged: BTreeMap<Option<Vec<u8>>, u64>,
    /// Recording sessions this engine placed (`crate::siprec`), by recording session handle.
    recordings: BTreeMap<CallHandle, Recording>,
}

/// One recording session, and the call it records.
#[derive(Debug)]
struct Recording {
    /// The recorded call, or the call that replaced it.
    recorded: CallHandle,
    to: crate::siprec::RecordTo,
    parties: crate::siprec::Parties,
    payload_type: u8,
    /// The `o=` session id of the recording session (RFC 4566 §5.2).
    session_id: u64,
    /// Where each stream's sequence numbers and timestamps start.
    numbers: [(u32, u16, u32); 2],
    /// Where the server receives each stream, once it has answered.
    destinations: Option<[Option<SocketAddr>; 2]>,
    /// SDES keys offered for the two streams when the recorded call is encrypted (RFC 7866 §12.2).
    /// `None` copies in the clear.
    keys: Option<crate::siprec::StreamKeys>,
    /// Whether the recorded call's account lets an encrypted call be copied
    /// in the clear ([`AccountSrtp::recording_in_clear`]).
    in_clear: bool,
    /// Whether `keys` went to the server in signalling that is not
    /// encrypted ([`MediaEngine::keys_in_clear`]).
    keys_in_clear: bool,
    /// The server's last answer, which says which offered line keys each stream.
    answer: Option<SessionDescription>,
    /// Copies taken off a replaced call, waiting for the new call's session.
    parked: Option<crate::siprec::Tap>,
    /// The direction last reported in the metadata.
    told: Option<Direction>,
    owed: bool,
}

/// The relay a description was handed, kept while the description can still be refused. Whatever is
/// left on refusal goes back via [`MediaEngine::hand_back`].
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

    /// The call has no use for the relay; it goes back with the call's farewells.
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

/// Who a datagram on a described socket goes to ([`MediaEngine::branch_for`]).
#[cfg(feature = "ice")]
enum Branch {
    /// A call's session.
    Session(share::Held),
    /// An agent still waiting for its session.
    Waiting,
    /// No session or agent there yet.
    None,
}

/// Which call reads messages off a relay connection ([`MediaEngine::receive_stream`]).
#[cfg(feature = "ice")]
enum StreamReader {
    /// An agent waiting for its session.
    Waiting(CallHandle),
    /// A call's session.
    Session(share::Held),
}

/// What a call's first description left of its relay.
#[cfg(feature = "ice")]
enum Kept {
    /// The agent that holds it, for the session to run.
    Agent(crate::ice::Ice),
    /// A relay this call cannot use (no ICE, lite role, other address family). It goes back to the
    /// server at once. Boxed because it carries a full TURN client.
    Unused(Box<crate::relay::Relay>),
}

impl MediaEngine {
    /// An engine that offers what `catalog` holds.
    ///
    /// `media_seed` is 32 bytes of entropy for every SRTP master key. **It must differ from the
    /// seed given to `UserAgent::new`, and no two engines may share one.** A replay recording
    /// carries the signalling seed in clear, so sharing it would leak every key.
    ///
    /// `clock` is needed for RTCP sender reports; see [`WallClock`].
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
            // forward secure: a later memory read cannot recover keys already drawn
            keys: KeySource::forward_secure(media_seed),
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

    /// STUN mappings against `server`, with transaction ids from this engine's key generator.
    ///
    /// The transaction id is all that stops an off-path attacker from answering first with an
    /// address of its choosing, so it needs key-grade randomness. Drawing from the generator
    /// reveals no keys.
    #[cfg(feature = "stun")]
    #[must_use]
    pub fn mappings(&mut self, server: SocketAddr) -> crate::Mappings {
        crate::Mappings::new(server, self.keys.block())
    }

    /// Relays on the TURN server at `server`, with transaction ids from this engine's key
    /// generator, for the same reason as [`MediaEngine::mappings`].
    #[cfg(feature = "ice")]
    #[must_use]
    pub fn relays(&mut self, server: SocketAddr, username: &str, password: &str) -> crate::Relays {
        crate::Relays::new(server, username, password, self.keys.block())
    }

    /// The DTLS key and certificate, made or renewed if missing or nearly expired.
    ///
    /// # Errors
    ///
    /// [`MediaError::DtlsIdentity`], which a sound media seed does not produce.
    #[cfg(feature = "dtls")]
    fn identity(&mut self, now: Instant) -> Result<Arc<Identity>, MediaError> {
        let unix = self.clock.unix_at(now);
        if self.identity.as_ref().is_none_or(|had| had.is_stale(unix)) {
            // renew instead of refusing: a desk phone runs for months, longer than a certificate.
            // Calls already described keep theirs
            self.identity = Some(Arc::new(Identity::new(&mut self.keys, unix)?));
        }
        self.identity.clone().ok_or(MediaError::DtlsIdentity)
    }

    /// The identity a just-written DTLS description named; the call keeps it.
    #[cfg(feature = "dtls")]
    fn named(&self, keyed: bool) -> Option<Arc<Identity>> {
        if keyed { self.identity.clone() } else { None }
    }

    /// The identity `call` named in its first DTLS description, or the engine's current one if it
    /// has none yet.
    ///
    /// A renewal between offer and handshake must not change the certificate, or the fingerprint
    /// check fails (RFC 8122 §5.1) and later re-offers look like a new association (RFC 8842 §3.1).
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

    /// The `a=fingerprint` and `a=setup` for the description about to be sent, or `None` if the
    /// call is not DTLS-keyed.
    ///
    /// Owned, because the call remembers what it wrote for
    /// [`dtls_role`](sipral_dtls::setup::dtls_role). `running` is the existing association for a
    /// re-offer answer: the answer keeps that role (RFC 8842 §5.3) instead of answering `active` to
    /// the `actpass` every re-offer carries (§5.5).
    ///
    /// # Errors
    ///
    /// As [`MediaEngine::identity`]; [`MediaError::DtlsRole`] for an unreadable `a=setup`;
    /// [`MediaError::DtlsRoleChanged`] for a re-offer that leaves this end only the other role.
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
        // refuse before any description names a fingerprint
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

    /// Without the feature every description is keyed by SDES or not at all.
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

    /// Whether answering `offer` with `answer` would move a running stream to another kind of
    /// keying ([`Shape`]).
    ///
    /// Read from the plan the pair would settle, since an offer with both `a=crypto` and
    /// `a=fingerprint` settles on whichever the answer took.
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

    /// Whether a re-offer keeps the certificate the association was checked against.
    ///
    /// A changed fingerprint asks for a new association (RFC 8842 §3.1), which this end refuses
    /// (§5.3). A re-offer without any fingerprint is judged by `keying_allows` and `keying_holds`
    /// instead.
    ///
    /// # Errors
    ///
    /// [`MediaError::DtlsFingerprintChanged`] for a different fingerprint.
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

    /// The ICE lines for the description about to be written.
    ///
    /// `Ok(None)` when the catalogue does not offer ICE. Otherwise the call's existing credentials
    /// and candidates, or a fresh draw. RFC 8839 §4.4.1.1.1 repeats them on every description;
    /// drawing again means a restart.
    ///
    /// # Errors
    ///
    /// As [`crate::ice::LocalIce::draw`]: an address RFC 8445 §5.1.1.1 rules out is refused.
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

    /// ICE lines for a call's first description when the call has a relay. The relay is drawn into
    /// a full agent only if the catalogue offers full ICE, no candidates exist yet, and the address
    /// family matches; otherwise it stays [`Kept::Unused`]. What remains goes in `handed` for
    /// [`MediaEngine::keep`].
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

    /// Without the feature there is no relay.
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

    /// Store what the first description left of the relay once the user agent took it: the agent
    /// until the session opens, or the relay's farewell now.
    #[cfg(feature = "ice")]
    fn keep(&mut self, call: CallHandle, handed: &mut Handed, now: Instant) {
        match handed.kept.take() {
            Some(Kept::Agent(ice)) => {
                // every fork branch gets the same offer, so each branch agent holds the one
                // allocation
                if let Some(relay) = ice.shared_relay() {
                    self.fork_relays.insert(call, relay);
                }
                // `first_ice` only draws a relayed agent for a call with no candidates yet, so
                // nothing should be here; if it is, return its allocation
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

    /// Return a refused description's relay to the application, still live. Nothing that named it
    /// was accepted, so the socket can offer it to the next call.
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

    /// The waiting agent of a call that ended before its session opened. Its relay goes back with
    /// the farewells unless another branch still holds it (RFC 8445 §8.3.1).
    #[cfg(feature = "ice")]
    fn let_go(&mut self, call: CallHandle, now: Instant) {
        let Some(ice) = self.gathered.remove(&call) else {
            return;
        };
        self.release_ice(call, ice, now);
    }

    /// The fork `call` belongs to.
    #[cfg(feature = "ice")]
    fn root_of(&self, call: CallHandle) -> CallHandle {
        self.branches.get(&call).copied().unwrap_or(call)
    }

    /// An agent for a fork branch that shares the fork's relay, or `None` if the fork has no relay
    /// left.
    ///
    /// One offer with one relayed candidate went to every branch. A second allocation would need
    /// another 5-tuple (RFC 8656 §3.2), but one allocation serves many peers (§1), and each branch
    /// runs its own ICE session (RFC 8839 §7).
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

    /// Forget an ended fork branch, and the fork's relay with the last branch.
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

    /// Queue one farewell datagram of `call` from socket `local`, or route it to
    /// [`MediaEngine::poll_turn_stream`] if it goes over a relay connection.
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

    /// Give back every relay `ice` holds among `call`'s farewells.
    #[cfg(feature = "ice")]
    fn release_ice(&mut self, call: CallHandle, mut ice: crate::ice::Ice, now: Instant) {
        let local = ice.local();
        let said = ice.release(now);
        self.farewells_of(call, local, said);
    }

    /// Queue `call`'s farewells from socket `local`, routing relay-connection traffic to
    /// [`MediaEngine::poll_turn_stream`].
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

    /// ICE lines for the answer to a re-offer: as [`MediaEngine::ice_lines`], unless the offer is a
    /// restart.
    ///
    /// A restart changes both `ice-ufrag` and `ice-pwd` (RFC 8839 §4.4.1.1.1), and the answer then
    /// carries new credentials too (§4.4.2.1) with the candidates the agent still holds. The agent
    /// adopts them after the answer has gone ([`crate::ice::Ice::follow`]).
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

    /// Tell the agent about a restart this end just accepted. The far end may check under the new
    /// credentials before the exchange completes here, so the agent keeps those checks.
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

    /// Without the feature there is no restart.
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

    /// Without the feature there is no ICE, and every description names one address.
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

    /// The ICE agent a settled plan calls for, or `None` if the call does not use ICE.
    ///
    /// Three peers end up with `None` and run on `c=`/`m=` with symmetric RTP: one that wrote no
    /// ICE lines (Asterisk's default), one whose candidates are all unusable, and one whose default
    /// destination is missing from its candidates (the ICE mismatch of RFC 8839 §4.2.5, typical of
    /// an ALG). Under [`IcePolicy::Required`] each is [`MediaError::IceRequired`].
    ///
    /// # Errors
    ///
    /// [`MediaError::IceRequired`] as above, [`MediaError::IceNeedsRtcpMux`] when the peer dropped
    /// `a=rtcp-mux`, [`MediaError::Ice`] for credentials the agent refuses.
    ///
    /// [`IcePolicy::Required`]: crate::IcePolicy::Required
    #[cfg(feature = "ice")]
    fn ice_for(
        &mut self,
        call: CallHandle,
        plan: &MediaPlan,
        now: Instant,
    ) -> Result<Option<crate::ice::Ice>, MediaError> {
        // a relayed agent that is not used gives its relay back
        let mut held = self.gathered.remove(&call);
        let built = self.build_ice(call, plan, &mut held, now);
        if let Some(unused) = held {
            self.release_ice(call, unused, now);
        }
        built
    }

    /// [`MediaEngine::ice_for`] with the call's held agent, taken out of `held` only when it is the
    /// one returned.
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
        // check for ICE first: a peer without ICE never agreed to rtcp-mux, so complaining about
        // that would hide the real reason
        let Some(peer) = sipral_nat::ice::parse_remote(remote, stream) else {
            return refuse(());
        };
        let muxed = matches!(plan.rtcp, RtcpPlan::Muxed | RtcpPlan::Off);
        // two lite ends never check; RFC 8445 §6.1.1 leaves both on the default candidates
        if (local.is_lite() && peer.lite)
            || peer.mismatch
            || peer.candidates.is_empty()
            || sipral_nat::ice::ice_mismatch(remote, stream, &peer, muxed)
        {
            return refuse(());
        }
        // a peer that agreed to ICE but dropped rtcp-mux would need a second component, which this
        // facade does not have
        if matches!(plan.rtcp, RtcpPlan::SeparatePort { .. }) {
            return Err(MediaError::IceNeedsRtcpMux);
        }
        // the agent that waited with the relay, one sharing the fork's relay, or a new one
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

    /// The DTLS handshake a settled plan calls for.
    ///
    /// `Ok(None)` when the call is not DTLS-keyed or the peer answered `holdconn`.
    ///
    /// # Errors
    ///
    /// As [`crate::dtls::Handshake::start`], and [`MediaError::DtlsRole`] if the call has no record
    /// of what it wrote.
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
        // the certificate this call's description named, not the engine's latest
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

    /// The next DTLS-SRTP handshake record a call owes the far end, with the call and destination.
    ///
    /// **Loop until `None` after every datagram and at every [`MediaEngine::poll_timeout`]
    /// deadline.** An undrained handshake means a call that is up with no audio and no error.
    ///
    /// Records for a relay's TCP or TLS connection are set aside for
    /// [`MediaEngine::poll_turn_stream`]; drain that afterwards.
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
            // no relay connection without the feature
            #[cfg(not(feature = "ice"))]
            if let Some(datagram) = slot.session.poll_transmit(now) {
                return Some((*call, datagram.destination, datagram.payload.to_vec()));
            }
        }
        // keepalives toward the TURN server for a call still waiting for its session
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

    /// Whether a call is described on media socket `local` and has not ended.
    ///
    /// An application with a TCP or TLS connection to a TURN server ([`crate::Relays::over`]) asks
    /// this after a call ends: once nothing is described there and the farewells are sent, the
    /// connection can close.
    #[must_use]
    pub fn describes(&self, local: SocketAddr) -> bool {
        self.calls
            .values()
            .any(|managed| managed.address == Some(local))
    }

    /// Bytes a call wrote for its relay's TCP or TLS connection ([`crate::Relays::over`]), on the
    /// connection from [`crate::RelayDatagram::local`]. Write them in order. Loop until `None`
    /// after [`MediaEngine::poll_transmit`], [`MediaEngine::poll_rtcp`] and call endings.
    #[cfg(feature = "ice")]
    #[must_use]
    pub fn poll_turn_stream(&mut self) -> Option<(CallHandle, crate::RelayDatagram)> {
        self.streamed.pop_front()
    }

    /// Feed bytes read off the TCP or TLS connection from media socket `local` to a call's TURN
    /// server, and say whether a call's relay runs over it.
    ///
    /// Bytes are reassembled once per connection and each message goes to its call, routed as in
    /// [`MediaEngine::receive_early`]: to a session via
    /// [`MediaSession::receive_stream`](crate::MediaSession::receive_stream), or to a waiting
    /// agent. Drain [`MediaEngine::poll_transmit`] and [`MediaEngine::poll_turn_stream`]
    /// afterwards. `Ok(false)` leaves the bytes to [`crate::Relays::receive_stream`].
    ///
    /// # Errors
    ///
    /// The connection carried something that is not TURN; the relay is lost and the application
    /// should close the connection.
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

    /// Feed connection bytes into the first relay on `local` (a waiting agent before a session),
    /// and return the call that reads the messages and the server address.
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

    /// Deliver one message from the relay connection on `local` to a waiting agent: the one that
    /// claims it, else the first whose relay uses the connection. Peer media has nowhere to play
    /// yet and will be resent.
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

    /// The TCP or TLS connection from `local` to a call's TURN server closed, and the relay is lost
    /// ([`MediaSession::stream_closed`](crate::MediaSession::stream_closed)). A waiting call opens
    /// its session without the relay.
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

    /// The default catalogue. A call may use its own; see [`MediaEngine::call_catalog`].
    #[must_use]
    pub const fn catalog(&self) -> &CodecCatalog {
        &self.catalog
    }

    /// Set the wall clock, for an application that learns the time after [`MediaEngine::new`].
    /// Sender reports of all calls (RFC 3550 §6.4.1) and new DTLS certificates use it from now on.
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

    /// Give `account`'s calls their own SRTP policy and suites, applied over the engine catalogue
    /// for calls placed from or arriving for it. [`AccountSrtp::default`] restores the engine's.
    /// Calls in progress are not affected.
    ///
    /// # Errors
    ///
    /// What [`CodecCatalog::with_srtp_suites`] refuses; nothing is kept then.
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

    /// The SRTP settings `account` set ([`MediaEngine::set_account_srtp`]).
    #[must_use]
    pub fn account_srtp(&self, account: AccountId) -> Option<&AccountSrtp> {
        self.accounts.get(&account)
    }

    /// The catalogue a call of `account` starts from.
    #[must_use]
    pub fn account_catalog(&self, account: AccountId) -> CodecCatalog {
        self.accounts
            .get(&account)
            .and_then(|srtp| srtp.over(self.catalog.clone()).ok())
            .unwrap_or_else(|| self.catalog.clone())
    }

    /// The current encryption report ([`MediaSession::encryption`]). `None` for a call with no
    /// session.
    #[must_use]
    pub fn encryption(&self, call: CallHandle) -> Option<Vec<crate::StreamEncryption>> {
        self.sessions
            .get(&call)
            .map(|held| share::lock(held).session.encryption())
    }

    /// The catalogue one call is using. `None` for a call this engine has not described.
    #[must_use]
    pub fn call_catalog(&self, call: CallHandle) -> Option<&CodecCatalog> {
        self.calls.get(&call).map(|managed| &managed.catalog)
    }

    /// The health counters since this engine was created. A plain copy, cheap enough to sample on a
    /// timer.
    #[must_use]
    pub const fn counters(&self) -> Counters {
        self.counters
    }

    /// One call's media session, locked until the guard is dropped.
    ///
    /// Waits for a thread working through a [`SessionShare`] to finish its frame. Also `None` for a
    /// thread that is already inside this session through a share, which would otherwise deadlock.
    ///
    /// The guard borrows the engine exclusively, since every other engine call may take the same
    /// lock:
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

    /// A handle to one call's media for a thread that does not own the engine, such as the audio
    /// thread.
    ///
    /// `None` until the session exists. The share stops working when the call ends or the engine is
    /// dropped; codec changes, hold and resume keep it valid.
    #[must_use]
    pub fn share(&self, call: CallHandle) -> Option<SessionShare> {
        self.sessions.get(&call).map(SessionShare::of)
    }

    /// The calls that have media running.
    pub fn active(&self) -> impl Iterator<Item = CallHandle> + '_ {
        self.sessions.keys().copied()
    }

    /// Listen for call progress on `call` and decide who answered, or stop with `None`. Works
    /// before the media exists too. Meant for outgoing calls; the same as setting
    /// [`MediaConfig::progress`](crate::MediaConfig::progress) when placing.
    ///
    /// # Errors
    ///
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
    /// Every session still held ends with the engine.
    ///
    /// Two things cannot wait. A WAVE recording gets its length fields only when it is closed, so
    /// this patches them. And every [`SessionShare`] must stop reaching its session, including one
    /// already waiting for the lock.
    fn drop(&mut self) {
        for held in self.sessions.values() {
            let mut slot = share::lock(held);
            slot.ended = true;
            // nobody left to tell
            let _ = slot.session.stop_recording();
        }
    }
}

impl MediaEngine {
    /// Place a call with an offer from the default catalogue, opened with the default
    /// [`MediaConfig`].
    ///
    /// `local` is where this end receives media. Any offer already on `outgoing` is replaced.
    ///
    /// # Errors
    ///
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

    /// Like [`MediaEngine::place`], with `media` instead of the engine defaults. Used for an
    /// attended transfer, whose consultation leg may need another codec or device.
    ///
    /// # Errors
    ///
    /// [`MediaError::Signalling`] when the user agent refuses the call. A relay in `media` then
    /// comes back from [`MediaEngine::poll_returned_relay`].
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

    /// [`MediaEngine::place_with`], holding the handed relay while the call can still be refused.
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
        // drawn after the identity so the same call with and without SDES starts from the same SSRC
        // and sequence number
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
        let keys_in_clear =
            sdes_in_clear(&catalog, &offer, agent.placing_securely(account, &outgoing))?;
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
                rung_with_media: false,
                payloads: Payloads::default(),
                pending: None,
                refused_keying: false,
                exposure: Exposure::default(),
                text,
            },
        );
        if keys_in_clear {
            self.mark_keys_in_clear(call, now);
        }
        Ok(call)
    }

    /// Mark `call` as having sent SDES keys over unencrypted signalling, and log a warning once.
    fn mark_keys_in_clear(&mut self, call: CallHandle, now: Instant) {
        let Some(managed) = self.calls.get_mut(&call) else {
            return;
        };
        if core::mem::replace(&mut managed.exposure.in_clear, true) {
            return;
        }
        #[cfg(feature = "redaction")]
        self.log_line(crate::LogLevel::Warn, "media", now, || {
            format!(
                "call {}: its SDES keys travel in signalling that is not encrypted, readable on \
                 every hop that carries it (RFC 4568 8.3)",
                number(call)
            )
        });
        #[cfg(not(feature = "redaction"))]
        let _ = now;
    }

    /// Whether an SDES key this end wrote for `call` went out over unencrypted signalling, readable
    /// on every hop (RFC 4568 §8.3). `Some(false)` over TLS or secure WebSocket, or when no key was
    /// written; `None` for an unknown call. Works for recording sessions too.
    ///
    /// A UI reads this together with [`StreamEncryption`](crate::StreamEncryption) before showing a
    /// call as secure. [`CodecCatalog::with_sdes_signalling`] refuses such calls instead.
    #[must_use]
    pub fn keys_in_clear(&self, call: CallHandle) -> Option<bool> {
        self.calls
            .get(&call)
            .map(|managed| managed.exposure.in_clear)
            .or_else(|| self.recordings.get(&call).map(|held| held.keys_in_clear))
    }

    /// Accept a requested transfer and place the new call like [`MediaEngine::place`].
    ///
    /// `extra` is passed to [`UserAgent::accept_transfer`] unchanged. The new call opens its
    /// session when the 2xx is acknowledged, followed by [`MediaEvent::Started`].
    ///
    /// # Errors
    ///
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

    /// Like [`MediaEngine::accept_transfer`], with `media` instead of the engine defaults.
    ///
    /// # Errors
    ///
    /// [`MediaError::Signalling`] when the user agent refuses the call. A relay in `media` then
    /// comes back from [`MediaEngine::poll_returned_relay`].
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

    /// [`MediaEngine::accept_transfer_with`], holding the handed relay while the call can still be
    /// refused.
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
        // the new call inherits the transferred call's signalling security
        let keys_in_clear = sdes_in_clear(&catalog, &offer, agent.call_signalling_secure(call))?;
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
                rung_with_media: false,
                payloads: Payloads::default(),
                pending: None,
                refused_keying: false,
                exposure: Exposure::default(),
                text,
            },
        );
        if keys_in_clear {
            self.mark_keys_in_clear(new, now);
        }
        Ok(new)
    }

    /// Ring an incoming call with an answer from its own catalogue and the default [`MediaConfig`],
    /// before anybody picks up.
    ///
    /// # Errors
    ///
    /// As [`MediaEngine::ring_with`].
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

    /// Like [`MediaEngine::ring`], with `media` instead of the engine defaults.
    ///
    /// The session opens when this returns: a 183 is never acknowledged, so there is no later event
    /// to open it on. [`MediaEvent::Started`] follows.
    ///
    /// [`UserAgent::ring`] decides from `Require`/`Supported` whether the 183 is sent reliably (RFC
    /// 3262 §3). That decides what a later answer's 200 OK carries (RFC 3262 §5, RFC 6337 §3.1.1):
    /// nothing if reliable, the same answer again if not. Either way the session and description
    /// are reused.
    ///
    /// # Errors
    ///
    /// [`MediaError::NoSuchCall`] for an unknown call; [`MediaError::Signalling`] wrapping
    /// [`sipral_ua::UaError::WrongState`] if already rung with a description (RFC 3261 §13.2.1
    /// allows only the same answer afterwards); [`MediaError::NoDescription`] for an INVITE without
    /// an offer (RFC 3261 §13.2.1, RFC 6337 §3.1.2); [`MediaError::Description`] when the answer
    /// cannot be built; [`MediaError::SrtpRequired`] when SRTP is required and not offered;
    /// [`MediaError::Signalling`] for other user agent refusals. In every error case a relay in
    /// `media` comes back from [`MediaEngine::poll_returned_relay`].
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

    /// [`MediaEngine::ring_with`], holding the handed relay while the ring can still be refused.
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
        // with no offer this end would have to offer, and RFC 3261 §13.2.1 / RFC 6337 §3.1.2 keep
        // that out of a provisional; the answer would come in a PRACK this engine never sees
        let Some(offer) = managed.remote.clone() else {
            return Err(MediaError::NoDescription);
        };
        if !keying_allows(&catalog, Some(&offer)) {
            return Err(refuse_insecure(agent, call, now));
        }
        if best_effort_refuses(&catalog, Some(&offer)) {
            return Err(refuse_unkeyable(agent, call, now));
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
        let keys_in_clear =
            sdes_in_clear(&catalog, &description, agent.call_signalling_secure(call))?;
        let bytes = description.to_bytes();
        agent.ring(call, Some(Arc::from(bytes)), now)?;
        self.keep(call, handed, now);
        if keys_in_clear {
            self.mark_keys_in_clear(call, now);
        }
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
        // no event reports a 183 going out, so this is the one place that settles a call directly
        self.settle(call, now);
        Ok(())
    }

    /// Answer an incoming call from its recorded catalogue, opened with the default
    /// [`MediaConfig`].
    ///
    /// # Errors
    ///
    /// [`MediaError::NoSuchCall`] for an unknown call, [`MediaError::Description`] when the answer
    /// cannot be built, [`MediaError::SrtpRequired`] when SRTP is required and not offered,
    /// [`MediaError::Signalling`] when the user agent refuses.
    ///
    /// An INVITE without an offer is answered with one of ours (RFC 3261 §13.2.2.4), but the far
    /// end's answer comes in the ACK, which the user agent does not report. The call comes up and
    /// reports [`MediaEvent::Failed`] with [`MediaError::NoDescription`].
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

    /// Like [`MediaEngine::answer`], with `media` instead of the engine defaults.
    ///
    /// # Errors
    ///
    /// As [`MediaEngine::answer`]. On [`MediaError::SrtpRequired`] nothing is sent and the call is
    /// still ringing, so the application can reject it.
    ///
    /// For a call already described by [`MediaEngine::ring_with`], `local` and `media` are ignored:
    /// the ring's session and description are reused (see there). A relay in `media` then comes
    /// back from [`MediaEngine::poll_returned_relay`].
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

    /// [`MediaEngine::answer_with`], holding the handed relay while the answer can still be
    /// refused.
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
            // already described at ring time; a second relay was never sent, so it stays in
            // `handed` and goes back to the application
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
        if best_effort_refuses(&catalog, offered.as_ref()) {
            return Err(refuse_unkeyable(agent, call, now));
        }
        // with no offer this end is the offerer, whichever method was called
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
        let keys_in_clear =
            sdes_in_clear(&catalog, &description, agent.call_signalling_secure(call))?;
        let bytes = description.to_bytes();
        agent.answer(call, Some(Arc::from(bytes)), now)?;
        self.keep(call, handed, now);
        if keys_in_clear {
            self.mark_keys_in_clear(call, now);
        }
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

    /// The 200 OK for a call [`MediaEngine::ring_with`] already described. The ring's session keeps
    /// running with the same `o=` id and version.
    ///
    /// RFC 3262 §5 and RFC 6337 §3.1.1 decide the body via [`UserAgent::reliably`]: after a
    /// reliable 183 the 2xx carries no SDP; after an unreliable one it repeats the same answer.
    /// [`UserAgent::answer`] still holds the 2xx until a reliable provisional is acknowledged.
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

impl MediaEngine {
    /// Offer the call again with `codecs`, in that order (RFC 3264 §8.3.2).
    ///
    /// Only the codecs change. Address, profile, SDES key or DTLS fingerprint, ICE and multiplexing
    /// are copied from the last description, so nothing is re-keyed or restarted (a new fingerprint
    /// would mean a new association, RFC 8842 §3.1). `a=setup` goes as `actpass` (§5.5); an answer
    /// that switches role is refused with [`MediaError::DtlsRoleChanged`] and the stream keeps its
    /// association.
    ///
    /// Direction is the user agent's ([`UserAgent::change_formats`]): a held call stays held.
    /// Dynamic payload types keep their codec, and new codecs get unused numbers, as §8.3.2
    /// requires. The list becomes the call's once accepted; a refusal leaves the old one (RFC 3261
    /// §14.1). The result arrives as [`MediaEvent::Changed`].
    ///
    /// # Errors
    ///
    /// [`MediaError::NoSuchCall`]; [`MediaError::NoDescription`] before the call is described;
    /// [`MediaError::StreamRefused`] for a refused stream; what [`CodecCatalog::with_codecs`]
    /// refuses; [`MediaError::NoPayloadType`]; [`MediaError::Signalling`], mainly
    /// [`UaError::ChangeInProgress`].
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
        // bound once written, whatever the answer
        payloads.note(&offer);
        if let Some(managed) = self.calls.get_mut(&call) {
            managed.payloads = payloads;
            managed.pending = Some(Pending { catalog, formats });
        }
        Ok(())
    }

    /// Restart ICE on a call (RFC 8445 §9) by offering new credentials, so both ends check every
    /// pair again.
    ///
    /// Use it when the path is lost ([`MediaError::IcePathLost`]; RFC 7675 §5.1 forbids reusing the
    /// credentials) or after a network change, since only a restart may change destinations (§9).
    ///
    /// Everything else is copied from the last description as in [`MediaEngine::change_codecs`].
    /// ICE lines are written as for a first offer (RFC 8839 §4.4.1.1.1) with the agent's current
    /// candidates. The running agent is untouched until the answer; the old pair carries audio
    /// until a new one is chosen (RFC 8839 §4.4.3.1.1, reported as [`MediaEvent::PathChosen`]). A
    /// refusal leaves ICE as it was (§4.4).
    ///
    /// # Errors
    ///
    /// [`MediaError::NoSuchCall`]; [`MediaError::NoIce`] for a call without an ICE agent;
    /// [`MediaError::NoDescription`]; [`MediaError::Ice`] if credentials fail to draw;
    /// [`MediaError::Signalling`], mainly [`UaError::ChangeInProgress`].
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
        // checks under the new credentials may arrive before the answer; the agent keeps them until
        // the restart is taken up
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

    /// Move a call's media to a new socket after a network change and offer that to the far end
    /// (RFC 3264 §8.3.1).
    ///
    /// [`UaEvent::CallAddressWanted`] names the calls; the application binds a new socket and
    /// passes its address. `public` is its outside address, as in [`CallMedia::public_address`];
    /// `None` uses `local`.
    ///
    /// Only `c=` and the `m=` port change. An SDES stream gets a new master key under the agreed
    /// tag and suite (RFC 4568 §7.1.4). The `o=` address stays (§8). A DTLS association survives
    /// the move (RFC 8842 §3.2), so `a=setup` is `actpass` and the fingerprint is unchanged.
    ///
    /// Call [`UserAgent::rebind`] first so the re-INVITE carries the new `Contact` (RFC 3261
    /// §12.2). The new socket is the call's from now on, whatever the answer. Calls running ICE
    /// must be restarted instead.
    ///
    /// # Errors
    ///
    /// [`MediaError::NoSuchCall`]; [`MediaError::NoDescription`]; [`MediaError::MovesWithIce`] for
    /// a call running ICE; [`MediaError::Signalling`], mainly [`UaError::ChangeInProgress`], which
    /// leaves the call to be moved again later.
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
        let moved = managed.public.or(managed.address) != Some(described);

        #[cfg(feature = "ice")]
        if offered_ice {
            withdraw_ice(&mut offer);
        }
        // RFC 4568 §7.1.4: a moved stream gets a new master key, so both ends restart with ROC zero
        if moved {
            let _ = self.fresh_key_line(call, &mut offer);
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

impl MediaEngine {
    /// The next event for the application, with media already attached.
    ///
    /// Drain until `None`. Media events follow the signalling event that caused them.
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
        // `absorb` already turned this into a media event, which the next loop iteration returns
        if matches!(signalling, UaEvent::DtmfReceived { .. }) {
            return self.poll_event(agent, now);
        }
        Some(Event::Signalling(signalling))
    }

    /// Run every session's stall watchdog. Sessions are locked one at a time, so a busy audio
    /// thread delays only its own call.
    pub fn handle_timeout(&mut self, now: Instant) {
        for held in self.sessions.values() {
            share::lock(held).session.handle_timeout(now);
        }
        // and relayed agents still waiting for a session, whose TURN keepalives run on this clock
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

    /// The RTCP BYE of an ended call (RFC 3550 §6.6).
    ///
    /// Separate from [`MediaEngine::poll_rtcp`] because the session is already gone, so the packet
    /// is copied out when the call ends. The handle names the ended call so the application knows
    /// which socket to use.
    ///
    /// Loop until `None` after draining events. A call with a relay ([`CallMedia::relay`]) also
    /// queues here the Refresh with lifetime zero that deletes the allocation (RFC 8656 §8), unless
    /// another fork branch still holds it.
    #[must_use]
    pub fn poll_farewell(&mut self) -> Option<(CallHandle, SocketAddr, Vec<u8>)> {
        self.farewells.pop_front()
    }

    /// A relay from a refused description, returned live.
    ///
    /// Nothing that named it was accepted, so [`Relays::put_back`](crate::Relays::put_back) can
    /// keep it for the next call on [`crate::Relay::local`]. Ask after any `_with` call fails, and
    /// after [`MediaEngine::answer_with`] on a rung call. A relay nobody collects lapses at its
    /// server.
    #[cfg(feature = "ice")]
    #[must_use]
    pub fn poll_returned_relay(&mut self) -> Option<crate::Relay> {
        self.returned.pop_front()
    }

    /// Keepalives and refreshes for calls described with a relay and still waiting for a session,
    /// with the socket to send from.
    ///
    /// The same datagrams [`MediaEngine::poll_transmit`] returns, for applications that drive
    /// sessions through [`SessionShare`] (like the C ABI). Loop until `None` after
    /// [`MediaEngine::handle_timeout`] and [`MediaEngine::receive_waiting`].
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

    /// Feed a datagram from `from` on `local` to a relayed call still waiting for its session, and
    /// say whether its agent took it. Without the refresh answers the allocation would expire
    /// during a long ring.
    ///
    /// `false` leaves it for a session, [`Relays`](crate::Relays) or [`Mappings`](crate::Mappings).
    /// From the TURN server, the agent takes only answers to its own requests.
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

    /// Feed a datagram from `from` on `local` (a socket a call was described on) before the
    /// application reads through the call's session, and say whether a call took it.
    ///
    /// For applications that read a call's socket before holding its [`SessionShare`], like the C
    /// ABI. The far end starts checks when it sends its answer, so they can arrive early; dropped,
    /// they are retried no sooner than 500 ms later (RFC 8445 §14.3). Kept, they are answered as
    /// §7.3 describes.
    ///
    /// It also routes datagrams to the branches of a forked call sharing the socket (RFC 8839
    /// §7.3). In order, the first that takes it:
    ///
    /// - a session there that claims it (if it is the only one with no waiting agent, it takes
    ///   everything);
    /// - a relayed agent still waiting for its session, as [`MediaEngine::receive_waiting`];
    /// - the first session there;
    /// - an ICE call without a session yet: an authenticated Binding request for its fragment is
    ///   kept (newest sixteen per socket, at most 39.5 s) and handed to the agent when the session
    ///   opens.
    ///
    /// `false` leaves it for [`Mappings`](crate::Mappings) or [`Relays`](crate::Relays).
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

    /// Which call on `local` a datagram from `from` is for, when a fork put several there.
    ///
    /// RFC 8839 §7.3 ties media to the branch whose checks used the same pair. A session claims
    /// checks for its peer's fragment, answers to its own checks, and traffic from its peer's
    /// candidates (relayed included); a non-ICE session claims its described address. TURN answers
    /// go to the holder of the shared allocation. Unclaimed checks go to a waiting agent (RFC 8445
    /// §7.3); anything else to the first session.
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

    /// Give a just-opened ICE session the checks kept for its socket that are still fresh. The rest
    /// are dropped.
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

    /// The next due RTCP datagram, with its call and destination.
    ///
    /// Loop until `None`. Each call resumes after the last one, so one drain visits each session
    /// once. The bytes are copied because the session is only locked during the call; a few reports
    /// a minute cost nothing. An audio thread can use [`MediaSession::poll_rtcp`] instead. Reports
    /// over a relay connection go to [`MediaEngine::poll_turn_stream`].
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

    /// The next due real-time text datagram, sent from the call's text socket
    /// ([`CallMedia::text`]). An audio thread can use [`MediaSession::poll_text`] instead.
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
    /// Taken from the list of calls that raised one, so only those sessions are locked. A stale
    /// entry costs one extra look.
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

    /// Put a newly opened session into the table.
    fn keep_session(&mut self, call: CallHandle, mut session: MediaSession) {
        session.report_to(call, Arc::clone(&self.ready));
        self.sessions.insert(call, share::hold(session));
    }

    /// Act on what the user agent said.
    fn absorb(&mut self, event: &UaEvent, agent: &mut UserAgent, now: Instant) {
        self.absorb_call(event, agent, now);
        // after the call's own media, so the recording sees the updated session
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
                // a 183 with SDP is early media the caller must hear
                self.take_body(*call, Some(response), now);
            }
            UaEvent::CallConfirmed { call, response, .. } => {
                self.take_body(*call, response.as_ref(), now);
                self.hang_up_insecure(*call, agent, now);
                // a 2xx answers an outgoing call; an incoming call confirms with an ACK and no
                // response
                if response.is_some() {
                    self.answered(*call);
                    self.rekey_after_fork(*call, agent, now);
                }
            }
            UaEvent::SessionChanged {
                call,
                hold,
                local,
                remote,
            } => {
                self.redescribed(*call, local.as_deref(), remote.as_deref(), now);
                // tell the stream whether this end holds the far end; direction attributes alone
                // cannot say
                if let Some(held) = self.sessions.get(call) {
                    share::lock(held).session.set_holding(hold.local);
                }
            }
            UaEvent::Reoffer { call, request } => self.answer_reoffer(*call, request, agent, now),
            // RFC 3261 §14.1: the session stands as it was. A 491 retry is pending
            UaEvent::SessionChangeFailed {
                call,
                retry_in: None,
                ..
            } => {
                if let Some(managed) = self.calls.get_mut(call) {
                    managed.pending = None;
                    // a refused ICE restart never happened (RFC 8839 §4.4)
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

    /// RFC 4568 §7.3 after a fork: every UA the offer reached knows its SDES key, and RFC 3711 §9.1
    /// forbids one master key for two sessions. Once a branch is answered and acknowledged,
    /// re-offer it with a fresh key under the agreed tag and suite.
    ///
    /// Once per call, SDES calls only. If another change is in progress the call is left alone and
    /// that is logged.
    fn rekey_after_fork(&mut self, call: CallHandle, agent: &mut UserAgent, now: Instant) {
        let Some(managed) = self.calls.get_mut(&call) else {
            return;
        };
        if !core::mem::take(&mut managed.exposure.forked) || managed.address.is_none() {
            return;
        }
        let Some(managed) = self.calls.get(&call) else {
            return;
        };
        let Some(mut offer) = managed.local.clone() else {
            return;
        };
        let version = managed.version.saturating_add(1);
        if !self.fresh_key_line(call, &mut offer) {
            return;
        }
        for stream in &mut offer.media {
            stream.offer_roles_again();
        }
        offer.origin.version = version;
        let sent = agent.change_formats(call, &offer.to_bytes(), now);
        #[cfg(feature = "redaction")]
        self.log_line(
            if sent.is_ok() {
                crate::LogLevel::Info
            } else {
                crate::LogLevel::Warn
            },
            "media",
            now,
            || match &sent {
                Ok(()) => format!(
                    "call {}: its INVITE forked; offering the branch that answered a key of \
                     its own (RFC 4568 7.3)",
                    number(call)
                ),
                Err(error) => format!(
                    "call {}: its INVITE forked, and the re-offer with a key of its own did \
                     not go: {error}",
                    number(call)
                ),
            },
        );
        #[cfg(not(feature = "redaction"))]
        let _ = sent;
    }

    /// Replace the audio crypto lines of `offer` with one fresh key under the call's tag and suite.
    /// `false`, leaving `offer` untouched, if the call is not SDES-keyed.
    fn fresh_key_line(&mut self, call: CallHandle, offer: &mut SessionDescription) -> bool {
        let agreed = self.sessions.get(&call).and_then(|held| {
            match share::lock(held).session.plan().keying {
                Some(Keying::Sdes { ref local, .. }) => Some((local.tag, local.suite)),
                _ => None,
            }
        });
        let Some((tag, suite)) = agreed else {
            return false;
        };
        let Some(stream) = offer
            .media
            .iter_mut()
            .find(|stream| stream.media == AUDIO && !stream.is_rejected())
        else {
            return false;
        };
        let line = CryptoPolicy::new(tag, suite, draw_key_for(suite, &mut self.keys))
            .to_crypto()
            .attribute();
        let at = stream
            .attributes
            .iter()
            .position(|attribute| attribute.name == "crypto")
            .unwrap_or(stream.attributes.len());
        stream
            .attributes
            .retain(|attribute| attribute.name != "crypto");
        stream
            .attributes
            .insert(at.min(stream.attributes.len()), line);
        true
    }

    /// Hang up an outgoing call whose answer the SRTP policy refused, with `Reason` 488 (RFC 3261
    /// §13.2.2.4, RFC 3326).
    fn hang_up_insecure(&mut self, call: CallHandle, agent: &mut UserAgent, now: Instant) {
        let refused = self.calls.get_mut(&call).and_then(|managed| {
            core::mem::take(&mut managed.refused_keying).then(|| managed.catalog.srtp())
        });
        if let Some(policy) = refused {
            // best effort only ends a call over keys both ends wrote and neither could use
            let text = if policy.on_plain_profile() {
                "No usable SRTP key"
            } else {
                "SRTP required"
            };
            let reason = Reason::sip(488, text);
            // already ending
            let _ = agent.hangup_for(call, &[reason], now);
        }
    }

    /// A digit arrived by SIP INFO. Reported as the same [`MediaEvent::DigitReceived`] as RFC 4733
    /// digits (see `crate::event`).
    fn dtmf_received(&mut self, call: CallHandle, digit: char, held_ms: Option<u32>) {
        // the parser only accepts the sixteen RFC 4733 §3.2 keys; the fallback just avoids a panic
        // path
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

impl MediaEngine {
    /// A call came in: keep its offer and draw its stream numbers. The default catalogue and
    /// configuration are recorded now; [`MediaEngine::answer_with`] can replace them.
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
                // DTLS and ICE are decided at ring or answer time
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
                exposure: Exposure::default(),
                text: None,
            },
        );
    }

    /// A proxy forked the INVITE. The new branch inherits the description, catalogue and
    /// configuration, with its own stream numbers.
    ///
    /// It also takes up the fork's relay at once with its own waiting agent
    /// ([`MediaEngine::branch_agent`]), so the allocation survives while this phone rings (RFC 8445
    /// §8.3.1).
    fn forked(
        &mut self,
        call: CallHandle,
        sibling: CallHandle,
        agent: &mut UserAgent,
        now: Instant,
    ) {
        let Some(parent) = self.calls.get_mut(&call) else {
            return;
        };
        // every branch holds the offered key, so the answering one is rekeyed later
        parent.exposure.forked = true;
        let parent = parent.clone();
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

    /// The user agent rewrote the session: a hold, a resume, or a change it answered itself. Both
    /// descriptions are passed because the user agent wrote some of them.
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
        // the application runs this call's audio; settling here would start a second stream
        if managed.address.is_none() {
            return;
        }
        if let Some(described) = local.and_then(|bytes| parse(bytes).ok()) {
            managed.version = managed.version.max(described.origin.version);
            // our codec change was accepted; its list is the call's from now on
            if managed
                .pending
                .as_ref()
                .is_some_and(|pending| Some(&pending.formats) == live_formats(&described))
                && let Some(pending) = managed.pending.take()
            {
                managed.catalog = pending.catalog;
            }
            // our ICE restart was accepted; `settle` passes the new credentials to the agent
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

    /// Whether `offer` would have this end take the far end's running SDES
    /// key under a suite whose cipher runs in another mode
    /// ([`keying::key_carries_over`]).
    fn moves_key_across_modes(
        &self,
        call: CallHandle,
        catalog: &CodecCatalog,
        offer: &SessionDescription,
    ) -> bool {
        let Some(running) = self.sessions.get(&call).and_then(|held| {
            match share::lock(held).session.plan().keying {
                Some(Keying::Sdes { ref remote, .. }) => Some(remote.clone()),
                _ => None,
            }
        }) else {
            return false;
        };
        let Some(taken) =
            live_stream(offer).and_then(|stream| keying::acceptable(stream, catalog.srtp_suites()))
        else {
            return false;
        };
        let same_key = running
            .keys
            .iter()
            .map(|inline| &inline.keys)
            .eq(taken.keys.iter().map(|inline| &inline.keys));
        same_key && !keying::key_carries_over(running.suite, taken.suite)
    }

    /// The key for the answer to a re-offer.
    ///
    /// Under the same suite, repeat the key in force: RFC 4568 §7.1.4 warns a new one leaves a
    /// window where the offerer cannot decrypt. Otherwise draw one at the new suite's width
    /// (§5.1.2, §6.1). `None` if the stream is not keyed.
    fn reoffer_keys(
        &mut self,
        catalog: &CodecCatalog,
        offer: &SessionDescription,
        in_force: Option<(CryptoSuite, KeySalt)>,
    ) -> Option<KeySalt> {
        if !will_key(catalog, Some(offer)) {
            return None;
        }
        let suite = suite_for_own_key(Some(offer), catalog);
        Some(match in_force {
            Some((running, keys)) if running == suite => keys,
            _ => draw_key_for(suite, &mut self.keys),
        })
    }

    /// Keys for one stream of a recording offer: the suites in `catalog` at least as strong as the
    /// call's, or the call's own suite if none is.
    ///
    /// RFC 7866 §12.2 says the recording should be protected at least as well as the call, and the
    /// server may pick any offered suite (RFC 4568 §5.1.2). A call waiting for its handshake has no
    /// known suite yet and gets `catalog`'s.
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

    /// One key per suite in `catalog`, in order, for a fresh offer. Each draw advances the counter,
    /// so keys are unique within the SDP (RFC 4568 §6.1).
    fn draw_offer_keys(&mut self, catalog: &CodecCatalog) -> Vec<(CryptoSuite, KeySalt)> {
        catalog
            .sdes_offered()
            .into_iter()
            .map(|suite| (suite, draw_key_for(suite, &mut self.keys)))
            .collect()
    }

    /// Answer a re-offer the user agent cannot: a codec change, or anything on a secured stream
    /// (hold and session refresh included), since the answer needs keys or a certificate only this
    /// engine holds.
    ///
    /// Only for calls this engine describes. For a call the application described, the event goes
    /// to the application, which answers with `UserAgent::accept_reoffer`; refusing here would 488
    /// every hold.
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
        // §8.3.2 binds numbers even in an offer that is refused
        if let Some(offer) = offered.as_ref() {
            managed.payloads.note(offer);
        }
        let Some(offer) = offered else {
            // refuse rather than let the offer retransmit until the call dies
            let _ = agent.reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
            return;
        };
        let version = managed.version.saturating_add(1);
        let session_id = managed.session_id;
        let catalog = managed.catalog.clone();
        let text = managed.text;
        // repeat the running key (RFC 4568 §7.1.4 warns a new one opens a decrypt gap). It comes
        // from the running plan, since the far end may have taken any of our offered lines
        let in_force = self.sessions.get(&call).and_then(|held| {
            keying::key_in_force(share::lock(held).session.plan().keying.as_ref())
        });
        // refuse here, or an SRTP-required call silently downgrades
        if let Some(error) = keying_refusal(&catalog, &offer) {
            self.events.push_back((call, MediaEvent::Failed(error)));
            let _ = agent.reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
            return;
        }
        // the far end's key under a suite with another cipher mode would be one key under two
        // transforms
        if self.moves_key_across_modes(call, &catalog, &offer) {
            self.events
                .push_back((call, MediaEvent::Failed(MediaError::UnusableKeying)));
            let _ = agent.reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
            return;
        }
        // RFC 8842 §5.3: refuse an offer for a new association we will not start, and the session
        // stands (RFC 3261 §14.2)
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
            // RFC 3261 §14.2: reject with 488 and the session stands. Answering with every stream
            // refused would kill the audio for good. An offer that removed the stream itself is
            // still answered
            Ok(answer)
                if offer.media.iter().any(|stream| !stream.is_rejected())
                    && answer.media.iter().all(MediaDescription::is_rejected) =>
            {
                let _ = agent.reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
            }
            Ok(mut answer) => {
                // RFC 8839 §4.4: leaving the attributes out would read as ICE withdrawn
                describe_ice(&mut answer, ice.as_ref(), Some(&offer));
                // a running stream cannot change its kind of keying, so refuse instead of answering
                // and not following
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
                    // the result comes back as UaEvent::SessionChanged, which settles the plan
                }
            }
            Err(error) => {
                self.events.push_back((call, MediaEvent::Failed(error)));
                let _ = agent.reject_reoffer(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
            }
        }
    }

    /// The call is over: release the stream, close any recording, report its cost, and publish the
    /// RFC 6035 report if the account asked for one.
    fn release(&mut self, call: CallHandle, agent: &mut UserAgent, now: Instant) {
        // tell the partner first, so `MediaEngine::mix` never sees a partner that is gone
        if let Some(partner) = self.joins.remove(&call) {
            self.joins.remove(&partner);
            self.events.push_back((partner, MediaEvent::Unjoined));
        }
        let address = self.calls.remove(&call).and_then(|managed| managed.address);
        // early checks for this socket were for this call or nobody
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
        // a call that ended before its session opened still holds its relay, unless another fork
        // branch does
        #[cfg(feature = "ice")]
        {
            self.let_go(call, now);
            self.forget_branch(call);
        }
        let Some(held) = self.sessions.remove(&call) else {
            return;
        };
        let mut slot = share::lock(&held);
        // mark ended first, under the lock, so a waiting share sees an ended call and cannot send
        // after the BYE
        slot.ended = true;
        let session = &mut slot.session;
        // otherwise the WAVE length fields stay zero
        if let Err(error) = session.stop_recording()
            && !matches!(error, MediaError::NotRecording)
        {
            self.events.push_back((call, MediaEvent::Failed(error)));
        }
        // RFC 3550 §6.6. The session is already out of the map, so this is the last chance to send
        // the BYE
        if let Some(datagram) = session.goodbye(now) {
            self.say_farewell(call, address, datagram);
        }
        // DTLS close_notify after the BYE: an unkeyed stream sends no BYE, and this is what stops
        // the peer retransmitting
        #[cfg(feature = "dtls")]
        {
            session.close_handshake();
            while let Some(datagram) = session.poll_transmit(now) {
                self.say_farewell(call, address, datagram);
            }
        }
        // last, since the goodbyes above may have used the relay. Return it (RFC 8656 §8) unless
        // another fork branch still holds it
        #[cfg(feature = "ice")]
        {
            let said = session.release_relays(now);
            match address {
                Some(local) => self.farewells_of(call, local, said),
                // with no socket the relay connection cannot be named; the datagrams still go
                None => self.farewells.extend(
                    said.into_iter()
                        .filter(|(_, transport, _)| !transport.is_stream())
                        .map(|(destination, _, payload)| (call, destination, payload)),
                ),
            }
        }
        // best effort; `Ok(false)` means the account named no collector
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

/// Queue a datagram for the relay connection of `call` for [`MediaEngine::poll_turn_stream`].
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
            // one half is still missing, which is normal before the answer
            return;
        };
        let plan = match keyed_plan(&managed.catalog, local, remote) {
            Ok(plan) => plan,
            Err((error, refused)) => {
                // the policy refused it: hang up an outgoing call
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
        // recorded now from the far end's description and this call's catalogue, never rebuilt
        // later
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
            // a restart now answered: the agent takes the new credentials and checks again while
            // the old pair carries audio
            #[cfg(feature = "ice")]
            if let Err(error) =
                slot.session
                    .follow_ice(settled_ice.as_ref(), peer_ice.as_ref(), now)
            {
                self.fail(call, error);
            }
            // an answer taking the other DTLS role asks for a new association; refuse it before
            // adopting anything
            #[cfg(feature = "dtls")]
            if let Err(error) = roles_hold(slot.session.dtls_role(), ours.as_deref(), &plan) {
                drop(slot);
                self.fail(call, error);
                return;
            }
            // same codec on a running session: hold, resume, moved address, or nothing at all (an
            // ACK without a body); identical plans are not reported
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
                    // new crypto line this build cannot open: the old keys still run, and the call
                    // is told
                    Err(error) => self.fail(call, error),
                }
                return;
            }
        }
        // a new codec needs a new session
        self.start(
            call,
            &plan,
            codec,
            (annex_b, feedback, text),
            candidates,
            now,
        );
    }

    /// Open the stream for a plan, or move the running one to a new codec.
    ///
    /// A running session is reformatted rather than replaced, so its SRTP contexts and history
    /// survive ([`MediaSession::reformat`]). `agreed` carries G.729 Annex B, RTCP feedback and
    /// real-time text settings.
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

    /// Media could not be started. The call is left up: hanging up is the application's decision.
    fn fail(&mut self, call: CallHandle, error: MediaError) {
        self.events.push_back((call, MediaEvent::Failed(error)));
    }
}

impl MediaEngine {
    /// Record `call` to a SIPREC server (RFC 7866): place a recording session from the call's
    /// account, and once answered copy this end's audio on one stream and the far end's on the
    /// other (`crate::siprec`).
    ///
    /// The returned handle is the recording session, an ordinary call reported through
    /// [`UaEvent`]s. [`MediaEngine::stop_recording_to`] hangs it up. Copies come from
    /// [`MediaSession::poll_recording`] or [`MediaEngine::poll_recording`]. The recording ends with
    /// the recorded call and follows a call that replaces it.
    ///
    /// # Errors
    ///
    /// [`MediaError::NoDescription`] if the call's audio is not running,
    /// [`MediaError::AlreadyRecording`], [`MediaError::Signalling`] if the user agent refuses or
    /// the call has no account.
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
            // the call's transform: from the handshake, else from its SDES line
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
        // RFC 7866 §12.2: an encrypted call is copied in clear only if the account allows it
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
        // RFC 4568 §8.3 applies to the recording's keys too
        let keys_in_clear = sdes_in_clear(
            &self.account_catalog(account),
            &offer,
            agent.placing_securely(account, &outgoing),
        )?;
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
                keys_in_clear,
                answer: None,
                parked: None,
                told: Some(direction),
                owed: false,
            },
        );
        if keys_in_clear {
            #[cfg(feature = "redaction")]
            self.log_line(crate::LogLevel::Warn, "media", now, || {
                format!(
                    "recording {} of call {}: its SDES keys travel in signalling that is not \
                     encrypted, readable on every hop that carries it (RFC 4568 8.3)",
                    number(recording),
                    number(call)
                )
            });
        }
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

    /// Stop recording `call` to its server: copying stops and the recording session is hung up (RFC
    /// 7866 §6.1).
    ///
    /// # Errors
    ///
    /// [`MediaError::NotRecording`], and [`MediaError::Signalling`] if the BYE could not be sent.
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

    /// The next copy of recorded audio: the recording session, the socket to send from, the
    /// server's address and the packet.
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
                    // the server hung up
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

    /// The server answered the recording session or a change to it: send the copies where it says.
    fn server_answered(&mut self, recording: CallHandle, answer: Option<&SessionDescription>) {
        let Some(held) = self.recordings.get_mut(&recording) else {
            return;
        };
        let Some(answer) = answer else {
            return;
        };
        let mut destinations = crate::siprec::destinations(answer);
        if let Some(keys) = held.keys.as_ref() {
            // a stream the server did not accept as SRTP gets nothing
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

    /// Start copying the recorded call's audio to the server on the current session, redirecting an
    /// existing copy and resuming copies from a replaced call. `answered` means the server just
    /// answered, which may change the keying line.
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
        // RFC 7866 §12.2: a cleartext recording copies nothing of an encrypted replacement call
        // unless the account allows it; copies wait with their numbering
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

    /// A recorded call changed codec: re-offer the server both streams (RFC 7866 §7.1.1.1) and copy
    /// the new codec.
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
        // `reoffer` bumps the `o=` version (RFC 3264 §8)
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

    /// A call that replaced a recorded one takes over the recording (RFC 3891): the server is told
    /// and copies move to its audio.
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
            // the copies continue with the same numbering and keys
            held.parked = running;
        }
        self.attach_tap(recording, false);
        self.send_metadata(recording, agent, now);
        self.recorded_codec(call, agent, now);
    }

    /// Offer a codec change that was blocked by another change in the recording session.
    fn codec_owed(&mut self, recording: CallHandle, agent: &mut UserAgent, now: Instant) {
        if let Some(recorded) = self.recordings.get(&recording).map(|held| held.recorded) {
            self.recorded_codec(recorded, agent, now);
        }
    }

    /// Send the server pending metadata, now or after the running change.
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

    /// Start copying for a newly opened session of a recorded call, usually a replacing call.
    fn tap_new_session(&mut self, call: CallHandle) {
        if let Some(recording) = self.recording_of(call) {
            self.attach_tap(recording, false);
        }
    }
}

/// This end's and the far end's address of record and display name on `call`.
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

impl MediaEngine {
    /// The call `call` is currently joined with, if any.
    #[must_use]
    pub fn joined_with(&self, call: CallHandle) -> Option<CallHandle> {
        self.joins.get(&call).copied()
    }

    /// A local conference for this engine's calls, any number, each on its own codec, with or
    /// without this end. See [`LocalConference`](crate::LocalConference). The engine keeps no state
    /// for it.
    ///
    /// # Errors
    ///
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

    /// Join two active calls into a three-way local conference: each far end hears the other plus
    /// this end's microphone. [`MediaEngine::mix`] drives each frame; [`mix_two`](crate::mix_two)
    /// explains the matching rules. [`MediaEngine::leave`] ends it, and so does either call ending.
    ///
    /// # Errors
    ///
    /// [`MediaError::SameCall`]; [`MediaError::NoSuchCall`] for a call without a running session;
    /// [`MediaError::AlreadyJoined`]; [`MediaError::JoinIncompatible`] when sample rate or frame
    /// length differ.
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

    /// Take `call` out of its pair and return the partner. The sessions need no change; just stop
    /// calling [`MediaEngine::mix`].
    ///
    /// # Errors
    ///
    /// [`MediaError::NotJoined`].
    pub fn leave(&mut self, call: CallHandle) -> Result<CallHandle, MediaError> {
        let partner = self.joins.remove(&call).ok_or(MediaError::NotJoined)?;
        self.joins.remove(&partner);
        Ok(partner)
    }

    /// One frame of the pair `call` is in: decode both far ends, mix what each party should hear,
    /// send the two far-end frames, and write this end's playback into `local_out`. See
    /// [`crate::join::mix_two`].
    ///
    /// # Errors
    ///
    /// [`MediaError::NotJoined`]; [`MediaError::NoSuchCall`] if a session is gone (only after
    /// ignoring [`MediaEvent::Unjoined`]); whatever [`MediaSession::capture`] refuses.
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
        // two locks at once cannot deadlock: `&mut self` excludes other engine calls, and share
        // holders never take more than one session lock
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

/// The formats of the stream this facade carries.
fn live_formats(description: &SessionDescription) -> Option<&Vec<String>> {
    live_stream(description).map(|stream| &stream.formats)
}

/// Borrowed form of the owned DTLS pair, for the description writers.
#[cfg(feature = "dtls")]
fn keyed(lines: Option<&(String, String)>) -> Option<Keyed<'_>> {
    lines.map(|(fingerprint, setup)| Keyed { fingerprint, setup })
}

/// Without the feature nothing is DTLS-keyed; the writers still name the type.
#[cfg(not(feature = "dtls"))]
#[allow(clippy::needless_pass_by_value)]
const fn keyed(_lines: Option<&(String, String)>) -> Option<Keyed<'static>> {
    None
}

/// Which side of the offer/answer exchange this end is writing. RFC 4145 §4.1 reads `a=setup`
/// values differently in offer and answer.
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

/// The first stream's `a=setup`, or the session-level one (RFC 4566 §5.13).
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

/// Whether a renegotiated plan keeps the running association's DTLS roles (RFC 8842 §3.1).
/// `running` is this end's role, `ours` the `a=setup` this end just wrote. No association, or no
/// DTLS, is accepted.
///
/// # Errors
///
/// [`MediaError::DtlsRoleChanged`] for the other role, [`MediaError::DtlsRole`] for a pair RFC 4145
/// §4.1 does not allow.
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

/// The first stream's `a=fingerprint` values, or the session-level ones if the stream has none (RFC
/// 4566 §5.13).
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

// Free functions so the call's own catalogue is passed in, not `self.catalog` by habit.

/// Put a call's ICE attributes on a freshly written description.
///
/// Credentials and candidates at media level (RFC 8839 §5.1, §5.4, §5.6), pacing at session level
/// (§5.5). Added after building, because [`SessionDescription::answer`] builds a fresh description
/// and would drop them. One stream only; see [`write_answer`].
///
/// A lite end writes `a=ice-lite` instead of pacing (§4.2.1.4, §4.3.1). `answering` is the offer
/// for an answer; an offer without ICE gets none back (§4.3.2).
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
        // the Ta `IceConfig::default` uses
        sipral_nat::ice::write_pacing(description, sipral_nat::ice::DEFAULT_TA);
    }
}

/// Remove every ICE line from a description this end wrote, so [`describe_ice`] can write a
/// restart's (RFC 8839 §5).
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

/// Without the feature there is nothing to write.
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

/// `SrtpPolicy::DtlsOrSdes`: add the fingerprint and role beside the SDES crypto lines, so either
/// kind of peer can answer. Other policies are left as written.
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

/// Without the feature there is no fingerprint.
#[cfg(not(feature = "dtls"))]
const fn fall_back(
    stream: MediaDescription,
    _catalog: &CodecCatalog,
    _dtls: Option<Keyed<'_>>,
) -> MediaDescription {
    stream
}

/// Refuse an INVITE the SRTP policy cannot carry audio on, with 488 (RFC 3261 §21.4.26), and return
/// the error.
fn refuse_insecure(agent: &mut UserAgent, call: CallHandle, now: Instant) -> MediaError {
    // already answered or gone; the error still explains
    let _ = agent.reject(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
    MediaError::SrtpRequired
}

/// RFC 4568 §8.3 for a description about to be sent; `secure` is how the signalling travels
/// (`None`: unknown, treated as clear). `Ok(true)` if it carries an SDES key in clear, `Ok(false)`
/// if not, and [`MediaError::KeysWouldTravelInClear`] if `catalog` allows SDES only over encrypted
/// signalling.
fn sdes_in_clear(
    catalog: &CodecCatalog,
    description: &SessionDescription,
    secure: Option<bool>,
) -> Result<bool, MediaError> {
    let keyed = description.media.iter().any(|stream| {
        !stream.is_rejected()
            && stream
                .attributes
                .iter()
                .any(|attribute| attribute.name.eq_ignore_ascii_case("crypto"))
    });
    if !keyed || secure == Some(true) {
        return Ok(false);
    }
    match catalog.sdes_signalling() {
        SdesSignalling::SecureOnly => Err(MediaError::KeysWouldTravelInClear),
        _ => Ok(true),
    }
}

/// Whether `catalog` offers real-time text: only on plain RTP without ICE (`crate::text`).
fn text_offered(catalog: &CodecCatalog) -> bool {
    !catalog.srtp().offers() && !catalog.ice().offers()
}

/// Whether `catalog` accepts the text stream in `offer`: same rule, and only beside unkeyed audio.
fn text_answered(catalog: &CodecCatalog, offer: &SessionDescription) -> bool {
    !any_secure_stream(offer) && !catalog.srtp().requires() && !catalog.ice().offers()
}

/// Whether this call lets such a stream carry audio.
///
/// This is where [`SrtpPolicy::Offered`] and [`SrtpPolicy::Required`] differ: a plain offer is
/// answered under the first and refused under the second. An INVITE without an offer is answered
/// with our keyed offer and passes.
fn keying_allows(catalog: &CodecCatalog, offered: Option<&SessionDescription>) -> bool {
    !catalog.srtp().requires() || offered.is_none_or(any_secure_stream)
}

/// Whether [`SrtpPolicy::BestEffort`] refuses the offer: it has `a=crypto` lines on the plain
/// profile and none is usable (`keying::best_effort_unkeyable`).
fn best_effort_refuses(catalog: &CodecCatalog, offered: Option<&SessionDescription>) -> bool {
    offered
        .and_then(|offer| offer.media.first())
        .is_some_and(|stream| {
            keying::best_effort_unkeyable(catalog.srtp(), catalog.srtp_suites(), stream)
        })
}

/// Why a re-offer in a live call is refused for its keys, if it is.
fn keying_refusal(catalog: &CodecCatalog, offer: &SessionDescription) -> Option<MediaError> {
    if keying_allows(catalog, Some(offer)) {
        best_effort_refuses(catalog, Some(offer)).then_some(MediaError::UnusableKeying)
    } else {
        Some(MediaError::SrtpRequired)
    }
}

/// Refuse an INVITE whose keys the best-effort policy cannot use, with 488 like
/// [`refuse_insecure`].
fn refuse_unkeyable(agent: &mut UserAgent, call: CallHandle, now: Instant) -> MediaError {
    let _ = agent.reject(call, StatusCode::NOT_ACCEPTABLE_HERE, now);
    MediaError::UnusableKeying
}

/// Whether the next description will carry a key.
fn will_key(catalog: &CodecCatalog, offered: Option<&SessionDescription>) -> bool {
    catalog.srtp().offers() || offered.is_some_and(any_secure_stream)
}

/// The suite this end's own SDES key is drawn for: what `keying::acceptable` would pick from the
/// peer's offer, or our first offered suite when there is no offer. If there is no crypto line,
/// `will_key` already said no key is needed (8.2.4).
///
/// Computed here because `write_answer` takes an already drawn key.
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

/// The plan the two descriptions agreed, checked against the SRTP policy, or the error and whether
/// it is the policy's own refusal ([`MediaError::SrtpRequired`]).
fn keyed_plan(
    catalog: &CodecCatalog,
    local: &SessionDescription,
    remote: &SessionDescription,
) -> Result<MediaPlan, (MediaError, bool)> {
    let plan = match local.media_plan(remote, 0) {
        Ok(Some(plan)) => plan,
        Ok(None) => return Err((MediaError::StreamRefused, false)),
        // no key on a secured stream under a key-requiring policy is the policy's refusal
        Err(SdpError::CryptoMissing { .. }) if catalog.srtp().requires() => {
            return Err((MediaError::SrtpRequired, true));
        }
        // best effort, answered with a tag or key never offered: fails like an unparsable line
        // below
        Err(
            SdpError::CryptoNotOffered { .. }
            | SdpError::CryptoMissing { .. }
            | SdpError::CryptoKeyReused { .. },
        ) if catalog.srtp().on_plain_profile() => {
            return Err((MediaError::UnusableKeying, true));
        }
        Err(error) => return Err((MediaError::from(error), false)),
    };
    keying_holds(catalog, &plan, remote).map_err(|error| {
        let refused = error == MediaError::SrtpRequired;
        (error, refused)
    })?;
    // best effort: both ends wrote crypto lines and no key resulted, so end the call rather than go
    // plain
    if plan.keying.is_none()
        && catalog.srtp().on_plain_profile()
        && local.media.first().is_some_and(keying::wrote_crypto)
        && remote
            .media
            .first()
            .is_some_and(|stream| !stream.is_rejected() && keying::wrote_crypto(stream))
    {
        return Err((MediaError::UnusableKeying, true));
    }
    Ok(plan)
}

/// Whether the plan's keys are ones this call accepts.
///
/// The policy decides if an unkeyed stream is allowed. Session parameters are re-read from the
/// description because the `sipral-core` parser drops unknown ones, while RFC 4568 §6.3.7 says they
/// invalidate the line.
fn keying_holds(
    catalog: &CodecCatalog,
    plan: &MediaPlan,
    remote: &SessionDescription,
) -> Result<(), MediaError> {
    match &plan.keying {
        None if catalog.srtp().requires() => Err(MediaError::SrtpRequired),
        // a policy that named one keying method is not answered with the other: `DtlsRequired`
        // keeps keys out of the body, and `Required` did not ask for a fingerprint
        #[cfg(feature = "dtls")]
        Some(Keying::Sdes { .. }) if catalog.srtp() == SrtpPolicy::DtlsRequired => {
            Err(MediaError::SrtpRequired)
        }
        #[cfg(feature = "dtls")]
        Some(Keying::Dtls { .. }) if catalog.srtp() == SrtpPolicy::Required => {
            Err(MediaError::SrtpRequired)
        }
        // RFC 5764 §4.2: without rtcp-mux there would be two DTLS associations; this stack runs
        // one, and the offer always asked for mux
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

/// Answer an offer that arrived, limited to `catalog`.
///
/// One audio stream is taken and every other is refused with port zero in the same position (RFC
/// 3264 §6, [`StreamAnswer::Reject`]). The exception is real-time text: with a text socket
/// ([`CallMedia::text`]) the first `m=text` is taken when [`text_answered`] allows.
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
    // answer a DTLS offer with our certificate and role, never a crypto line. Under
    // `SrtpPolicy::DtlsOrSdes` the answer follows the offer
    #[cfg(feature = "dtls")]
    let handshake = dtls.filter(|_| {
        keying::is_secure(&offered.proto)
            && (!catalog.srtp().falls_back() || offered.attribute("fingerprint").is_some())
    });
    #[cfg(not(feature = "dtls"))]
    let handshake: Option<Keyed<'_>> = None;
    // RFC 4568 §7.1.2: accept exactly one crypto line on a secure profile, or refuse the stream
    let crypto = if keying::is_secure(&offered.proto) && handshake.is_none() {
        match (keying::acceptable(offered, catalog.srtp_suites()), keys) {
            (Some(line), Some(keys)) => match keying::answer_line(&line, keys.clone()) {
                Some(answered) => Some(answered),
                None => return StreamAnswer::Reject,
            },
            _ => return StreamAnswer::Reject,
        }
    } else if catalog.srtp().on_plain_profile() {
        // best effort: a usable line on the plain profile keys the stream, none means plain;
        // unusable lines refuse the stream rather than downgrade
        match (keying::acceptable(offered, catalog.srtp_suites()), keys) {
            (Some(line), Some(keys)) => match keying::answer_line(&line, keys.clone()) {
                Some(answered) => Some(answered),
                None => return StreamAnswer::Reject,
            },
            _ if keying::wrote_crypto(offered) => return StreamAnswer::Reject,
            _ => None,
        }
    } else {
        None
    };
    let names: Vec<&str> = formats.iter().map(String::as_str).collect();
    let mut accepted = AcceptedStream::in_offer_order(address.port(), offered, &names)
        .with_direction(Direction::SendRecv);
    // formats with parameters this end states (G.729 `annexb`) get their own fmtp line
    for line in formats
        .iter()
        .filter_map(|format| stated_fmtp(catalog, offered, format))
    {
        accepted = accepted.with_attribute(line);
    }
    // RFC 5761 §5.1.1: mux only if offered and wanted, or if DTLS-keyed (RFC 5764 §4.2)
    let capabilities = catalog.capabilities();
    if (capabilities.rtcp_mux || handshake.is_some()) && offered.has_rtcp_mux() {
        accepted = accepted.with_attribute(Attribute::flag("rtcp-mux"));
    }
    // RFC 3611 §5.2: the answerer may add rtcp-xr so the offerer sends XR blocks; without it we
    // never get the far end's metrics
    if capabilities.voip_metrics_xr {
        accepted = accepted.with_attribute(Attribute::with_value("rtcp-xr", "voip-metrics"));
    }
    // RFC 4585 §4.2: keep only the feedback we do; the profile stays the offer's
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

/// The `a=fmtp` this end states for one offered format, if its codec has such parameters
/// ([`CodecCatalog::answered_fmtp`]).
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

/// Whether our G.729 encoder runs Annex B DTX on `plan`: the catalogue first, then both
/// descriptions. An echoed re-offer can say yes where we would say no.
fn annex_b_in_use(
    catalog: &CodecCatalog,
    local: &SessionDescription,
    remote: &SessionDescription,
    plan: &MediaPlan,
) -> bool {
    catalog.g729_annex_b() && annex_b_agreed(local, remote, plan)
}

/// Whether both descriptions of a G.729 stream allow Annex B. `false` for other codecs.
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

/// The offered formats `catalog` would keep, and whether any is a codec. Numbers are the offer's
/// own, since a dynamic type means whatever its `a=rtpmap` says.
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

/// The session description in a message body, if readable.
fn body_description(message: Option<&OwnedMessage>) -> Option<SessionDescription> {
    let message = message?;
    let raw = message.as_raw();
    let body = raw.body();
    if body.is_empty() {
        return None;
    }
    parse(body).ok()
}

/// The starting numbers for one stream, from the user agent's token stream.
///
/// One 128-bit token is unique per call. SSRC, sequence and timestamp need to be unpredictable (RFC
/// 3550 §5.1) and the session id unique (RFC 4566 §5.2), so four views of one token are enough.
fn draw(agent: &mut UserAgent) -> (StreamIdentity, u64) {
    let token = agent.endpoint().token();
    let identity = StreamIdentity {
        ssrc: u32::try_from(hex(&token, 0, 8)).unwrap_or(0),
        // RFC 4568 §6.4: start below 2^15 so early losses cannot desync the rollover counter.
        // Applied to every stream, since keying is not known yet
        sequence: u16::try_from(hex(&token, 16, 4)).unwrap_or(0) & 0x7fff,
        timestamp: u32::try_from(hex(&token, 8, 8)).unwrap_or(0),
        seed: hex(&token, 20, 12),
    };
    (identity, hex(&token, 0, 16))
}

/// The widest key plus salt any suite needs: `Aes256Cm80`, 32 + 14 octets (8.2.4). Two 32-byte
/// blocks always cover it.
const MAX_KEY_SALT: usize = 46;

/// The master key and salt for one description under `suite`, from the engine's own seed.
///
/// Not the endpoint's: its seed is written in clear into replay recordings.
///
/// One or two `SHA-256(media seed || counter)` blocks cover the suite width. The counter never
/// repeats, so offer and answer keys differ (RFC 4568 §7.1.2). **A poor media seed silently costs
/// all of the encryption.**
///
/// Buffers are [`Zeroizing`] (8.2.9) so they are wiped on drop. Bytes are copied one by one instead
/// of sliced, so an out-of-range read cannot fall back to a zero key; the assertion above stops the
/// build if a suite exceeds `MAX_KEY_SALT`.
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

/// One hex digit. Tokens are hex by construction; anything else reads as zero, since a slightly
/// weaker identifier is better than a call that cannot start.
const fn nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        b'A'..=b'F' => digit - b'A' + 10,
        _ => 0,
    }
}

impl MediaEngine {
    /// Hand out RTP ports from `ports` from now on, or stop with `None`. Opens nothing; it is the
    /// rule [`MediaEngine::reserve_rtp_port`] follows and the firewall is written to. Existing
    /// reservations are kept.
    pub const fn set_rtp_ports(&mut self, ports: Option<RtpPorts>) {
        self.rtp_ports = ports;
    }

    /// The range ports are handed out of, when one was set.
    #[must_use]
    pub const fn rtp_ports(&self) -> Option<RtpPorts> {
        self.rtp_ports
    }

    /// A free even port from the range for RTP, with the odd port above kept for RTCP; `None` if no
    /// range is set.
    ///
    /// Free means not reserved and not used by a call. The caller binds it and passes it to place,
    /// ring or answer; it stays reserved while a call uses it. Return an unused one with
    /// [`MediaEngine::release_rtp_port`].
    ///
    /// # Errors
    ///
    /// [`PortsExhausted`] when every pair is in use. Nothing is reserved then.
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

    /// Return a reserved port no call is using, and say whether it was one.
    pub fn release_rtp_port(&mut self, port: u16) -> bool {
        self.reserved_ports.remove(&port).is_some()
    }

    /// How many ports are reserved right now, a call's included.
    #[must_use]
    pub fn rtp_ports_reserved(&self) -> usize {
        self.reserved_ports.len()
    }

    /// Mark reservations a call now uses as taken, and release ones a call used and no longer does.
    ///
    /// Run at the top of [`MediaEngine::poll_event`], before the engine learns a call ended, so the
    /// port is seen in use first and released later.
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

#[cfg(feature = "redaction")]
impl MediaEngine {
    /// Write this engine's log lines to `log`: every event from [`MediaEngine::poll_event`] and
    /// every diagnostic decision, at the levels in `crate::log`. Lines are queued; the driver calls
    /// [`crate::Log::flush`].
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

    /// Log the caller verification verdict and reason, never the numbers.
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

    /// Log every new diagnostic decision as one debug line with its reason code
    /// (`docs/14-diagnostics.md`).
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
        // forget records the endpoint evicted
        self.logged = seen;
    }

    /// What this engine and `agent` hold right now, for a crash report ([`crate::EngineState`]).
    /// Never waits: a locked session is reported as busy.
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

/// An enum variant's name from its `Debug` form, without its fields (which may hold whole
/// messages).
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
    //! [`keying_allows`] and [`keying_holds`] judge descriptions this stack never writes, so the
    //! two-stack tests in `tests.rs` cannot reach most branches. These tests use hand-written peer
    //! descriptions.

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

    /// RFC 5764 §4.2: one DTLS association needs rtcp-mux. A plan without it under a DTLS policy is
    /// refused, or SRTCP would never be keyed.
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

        // a call with no RTCP needs no second association
        assert!(keying_holds(&catalog, &plan(keyed()), &theirs).is_ok());
    }

    /// A policy that named one keying method is not answered with the other.
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

    /// The peer's line is re-read because `sipral-core` drops unknown session parameters, while RFC
    /// 4568 §6.3.7 says they invalidate the line.
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

#[cfg(test)]
mod answer_parameters {
    //! G.729 offers as other stacks write them, including with no parameters, which our own offers
    //! never produce.

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

    /// RFC 4856 §2.1.9: no `annexb` means Annex B. The answer follows the offer on its own line,
    /// and says `no` when the catalogue has Annex B off.
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

    /// A catalogue without G.729 does not keep the format.
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

    /// Annex B runs only where both descriptions allow it (RFC 4856 §2.1.9) and never with the
    /// catalogue's Annex B off.
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

        // no Annex B for other codecs
        let pcmu = |fmtp: &str| described(&format!("m=audio 40002 RTP/AVP 0\r\n{fmtp}"));
        let (ours, theirs) = (pcmu(yes), pcmu(yes));
        let plan = ours
            .media_plan(&theirs, 0)
            .expect("a plan")
            .expect("the stream is kept");
        assert!(!annex_b_in_use(&on, &ours, &theirs, &plan));
    }
}

#[cfg(test)]
mod counter_wiring {
    //! `poll_event` returns media events from `self.events` and from
    //! [`MediaEngine::session_event`]. This checks the second path also feeds the counters, with a
    //! hand-built session instead of a SIP exchange.

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

    /// A call with a session inserted directly, to reach [`MediaEngine::session_event`] without
    /// negotiation.
    fn call_with_a_stalling_session(
        engine: &mut MediaEngine,
        now: Instant,
    ) -> (UserAgent, CallHandle) {
        // room for the thousand calls of the cost test
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
        // short enough that no ten-second clock jump is needed
        open_session(
            engine,
            call,
            (Some(Duration::from_millis(50)), RtcpPlan::Off),
            now,
        );
        (agent, call)
    }

    /// Open a session for `call` by hand, with an optional stall watchdog.
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

    /// `MediaEngine::drop` must mark sessions ended: this test holds an extra reference, standing
    /// in for a thread inside `SessionShare::with`, so only the flag can tell the share the call is
    /// over.
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

    /// The same for `MediaEngine::release` when one call ends.
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

    /// An engine with `sessions` sessions; the first has a 50 ms stall watchdog, the rest use
    /// `rtcp`. Setup events are drained.
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
        // drain the INVITEs so only media is counted
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

        // nothing raised, nothing locked
        assert!(engine.poll_event(&mut agent, later).is_none());
        assert_eq!(engine.sessions_polled - before, 1);
    }

    /// A `poll_rtcp` drain visits each session once, resuming where the last report came from.
    #[test]
    fn a_drain_of_rtcp_looks_at_each_session_once() {
        const SESSIONS: usize = 500;
        let now = Instant::now();
        let rtcp = RtcpPlan::SeparatePort {
            local: "192.0.2.20:40001".parse().expect("an address"),
            remote: "203.0.113.9:40011".parse().expect("an address"),
        };
        let (mut engine, _agent, _) = many_sessions(SESSIONS, rtcp, now);

        // past every first report
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

        // a fresh drain starts from the first call and looks at each session once
        let before = engine.rtcp_looked;
        assert!(engine.poll_rtcp(later).is_none());
        assert_eq!(engine.rtcp_looked - before, SESSIONS);
    }

    /// Events queued while one is being taken still come out in order.
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
        // two stacks with the same signalling entropy must not derive the same media keys
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

    /// G2: the engine's first key comes from the forward-secure stream.
    #[test]
    fn the_engine_draws_from_a_forward_secure_source() {
        let now = std::time::Instant::now();
        let mut engine = super::MediaEngine::new(
            crate::CodecCatalog::new(),
            crate::MediaConfig::default(),
            crate::WallClock::from_unix(now, 1_700_000_000, 0),
            [5; 32],
        );
        let drawn = draw(&mut engine.keys);
        assert_eq!(
            drawn.key(),
            draw(&mut KeySource::forward_secure([5; 32])).key()
        );
        assert_ne!(drawn.key(), draw(&mut KeySource::new([5; 32])).key());
    }

    #[test]
    fn no_two_keys_from_one_seed_are_the_same() {
        // RFC 4568 §7.1.2: offer and answer keys must differ; the counter guarantees it, salt
        // included
        let mut keys = KeySource::new([0; 32]);
        let mut seen = Vec::new();
        for _ in 0..64 {
            let drawn = draw(&mut keys);
            let pair = (drawn.key().to_vec(), drawn.salt().to_vec());
            assert!(!seen.contains(&pair), "a key repeated");
            seen.push(pair);
        }
    }

    /// Each suite draws key and salt of its own width, and two suites from the same point do not
    /// share key octets (8.2.4).
    #[test]
    fn every_suite_draws_its_own_width() {
        for suite in CryptoSuite::STRENGTH {
            let mut keys = KeySource::new([7; 32]);
            let drawn = draw_key_for(suite, &mut keys);
            assert_eq!(drawn.key().len(), suite.key_len(), "{}", suite.name());
            assert_eq!(drawn.salt().len(), suite.salt_len(), "{}", suite.name());
        }
    }

    /// The key buffers in `draw_key_for` must be `Zeroizing` (8.2.9, 8.2.4). A wipe is not
    /// observable from safe Rust, so the test checks the declared types in the source. Needles are
    /// built at runtime so the test cannot match itself; `sipral-core` does the same in
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
