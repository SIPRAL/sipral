// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! ICE for a call: the full role, and the lite role for a headless agent on a public address.
//!
//! `sipral-nat` has the RFC 8445 agent; this module connects it to calls.
//!
//! # What crosses the boundary
//!
//! - **Credentials.** A username fragment and password per call, drawn from the engine's
//!   [`KeySource`] and written into every description. RFC 8445 §5.3 needs real entropy.
//! - **Role and tiebreaker** (RFC 8445 §7.3.1.1), fixed with the first description, since
//!   [`Role::initial_full`] depends on who offered.
//! - **Candidates.** One host candidate from the bound address, plus a server-reflexive one when
//!   the call has a public address
//!   ([`CallMedia::public_address`](crate::CallMedia::public_address)). [`LocalIce`] remembers them
//!   so later descriptions repeat them.
//! - **Transaction ids**, from a per-call [`KeySource`]. RFC 7675 §5.1 makes consent only as strong
//!   as their unpredictability.
//!
//! # What it does not do
//!
//! The agent contacts no server, so [`IceAgent::gather`] finishes before returning and an offer is
//! still written in one pass. The reflexive address comes from the application's earlier STUN
//! mapping ([`IceAgent::add_server_reflexive`]). A relay comes from the application's TURN
//! allocation ([`crate::Relays`], [`CallMedia::relay`](crate::CallMedia::relay)) via
//! [`IceAgent::add_relayed`]; a call with one keeps its agent, since the allocation is server
//! state.
//!
//! There is no silent failure: a peer without ICE, with unusable candidates, or whose description
//! an ALG rewrote gets a call on `c=`/`m=` and symmetric RTP (RFC 8445 §2.6). Otherwise enabling
//! ICE would silence calls to an Asterisk with the default `ice_support=no`.
//!
//! # The lite role
//!
//! [`IcePolicy::Lite`] is for a headless agent on a reachable server answering a full-ICE peer,
//! typically a WebRTC gateway. RFC 8445 Appendix A limits lite to such hosts, so the policy exists
//! only with the `ice-lite` feature or `headless` with `ice`. `sipral-ffi` enables `ice-lite`, but
//! only the application can select `SIPRAL_ICE_LITE`.
//!
//! A lite end writes `a=ice-lite`, credentials and one host candidate (the bound address, or the
//! public address of a one-to-one NAT). It answers authenticated checks with `FINGERPRINT`, follows
//! the role rules of RFC 8445 §6.1.1 and §7.3.1.1, and takes the pair of a `USE-CANDIDATE` check as
//! the media path (§7.3.2), reported as [`MediaEvent::PathChosen`]. Consent checks (RFC 7675) are
//! ordinary checks. On a restart it answers with new credentials (RFC 8839 §4.4.2.1) and keeps the
//! old pair until the peer nominates under the new ones.
//!
//! # Restarts
//!
//! Either end may restart (RFC 8445 §9): the peer by re-offer, this end with
//! [`MediaEngine::restart_ice`]. The restart takes effect only after the exchange completes (RFC
//! 8839 §4.4). The full agent then rebuilds its checklist and checks again on its remaining
//! candidates, while the old pair carries audio (§4.4.3.1.1).
//!
//! [`MediaEvent::PathChosen`]: crate::MediaEvent::PathChosen
//! [`MediaEngine::restart_ice`]: crate::MediaEngine::restart_ice

#[cfg(feature = "ice")]
use std::collections::VecDeque;
#[cfg(feature = "ice")]
use std::net::SocketAddr;
#[cfg(feature = "ice")]
use std::ops::Range;
#[cfg(feature = "ice")]
use std::time::Instant;

#[cfg(feature = "ice")]
use sipral_core::auth::KeySource;
#[cfg(feature = "ice")]
use sipral_core::sdp::SessionDescription;
#[cfg(feature = "ice")]
use sipral_nat::ice::{
    Candidate, CandidateType, CheckAnswer, Claim, ComponentId, Credentials, IceAgent, IceConfig,
    IceEvent, LiteAgent, PairOutcome, REFUSAL_CEILING, Received, RelayOutcome, RemoteIce, Role,
    Route, SelectedPair, SendError, SharedRelay, StreamId, TRANSMIT_CEILING, Transmit,
};
#[cfg(feature = "ice")]
use sipral_nat::stun::{Class, Integrity, Message, Method, TransactionId};
#[cfg(feature = "ice")]
use sipral_nat::turn::{FrameError, Transport};

#[cfg(feature = "ice")]
use crate::error::MediaError;

/// What a call does about ICE.
///
/// Lives on [`CodecCatalog`](crate::CodecCatalog) because it shapes the offer, like
/// [`SrtpPolicy`](crate::SrtpPolicy). The values describe a stance, not candidate types.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum IcePolicy {
    /// Do not offer ICE and do not answer it. The default: `docs/06-nat.md` explains why it costs
    /// more than it gives against a PBX that latches on media.
    #[default]
    Off,
    /// Offer ICE and use it with a peer that answers with it. Peers without ICE get symmetric RTP,
    /// so it is safe to enable.
    #[cfg(feature = "ice")]
    Offered,
    /// Offer ICE and carry no audio without it, like
    /// [`SrtpPolicy::Required`](crate::SrtpPolicy::Required). A peer without ICE, or a description
    /// an ALG rewrote, ends the call with [`MediaError::IceRequired`].
    #[cfg(feature = "ice")]
    Required,
    /// Be an ICE-lite endpoint (RFC 8445 §2.5): write `a=ice-lite` and a host candidate, answer the
    /// full peer's checks, and use the pair it nominates.
    ///
    /// Only for a host always reachable at its advertised address, its own or
    /// [`CallMedia::public_address`] behind a one-to-one NAT. Never a softphone: RFC 8445 Appendix
    /// A says lite "will not function when a lite implementation is placed behind a NAT". Available
    /// only with `ice-lite`, or `headless` with `ice`. A peer without ICE, or lite itself, gets
    /// `c=`/`m=` and symmetric RTP.
    ///
    /// [`CallMedia::public_address`]: crate::CallMedia::public_address
    #[cfg(any(feature = "ice-lite", all(feature = "ice", feature = "headless")))]
    Lite,
}

impl IcePolicy {
    /// Whether a description written under this policy carries ICE at all.
    #[must_use]
    pub(crate) const fn offers(self) -> bool {
        match self {
            Self::Off => false,
            #[cfg(feature = "ice")]
            Self::Offered | Self::Required => true,
            #[cfg(any(feature = "ice-lite", all(feature = "ice", feature = "headless")))]
            Self::Lite => true,
        }
    }

    /// Whether this end is the lite implementation.
    #[cfg(feature = "ice")]
    #[must_use]
    pub(crate) const fn lite(self) -> bool {
        match self {
            #[cfg(any(feature = "ice-lite", feature = "headless"))]
            Self::Lite => true,
            Self::Off | Self::Offered | Self::Required => false,
        }
    }

    /// Whether a call prefers no audio to audio on an unchecked path. Only the engine's `ice_for`
    /// asks.
    #[cfg(feature = "ice")]
    #[must_use]
    pub(crate) const fn requires(self) -> bool {
        match self {
            #[cfg(feature = "ice")]
            Self::Required => true,
            #[cfg(feature = "ice")]
            Self::Offered => false,
            #[cfg(any(feature = "ice-lite", feature = "headless"))]
            Self::Lite => false,
            Self::Off => false,
        }
    }
}

/// One path a call's ICE agent tried (a checked pair or a held relay) and its outcome: the
/// transport half of D5, beside [`CodecCandidate`](crate::CodecCandidate).
///
/// Recorded as each outcome happens, because RFC 8445 §8.1.2 removes losing pairs once one is
/// selected. A restart (RFC 8445 §9) starts a new list.
#[cfg(feature = "ice")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathCandidate {
    /// A pair or a relay.
    pub kind: PathKind,
    /// For a pair, the local candidate checks left from (host or relayed; a reflexive candidate
    /// pairs as its base, RFC 8445 §6.1.2.4). For a relay, its relayed address, while it has one.
    pub local: Option<SocketAddr>,
    /// The kind of `local`; [`CandidateKind::Relayed`] for a relay.
    pub local_kind: CandidateKind,
    /// For a pair, the far end's candidate; for a relay, the TURN server.
    pub remote: SocketAddr,
    /// The kind of `remote`: [`CandidateKind::PeerReflexive`] for an address the far end's checks
    /// revealed (RFC 8445 §7.3.1.3). `None` for a relay's server and for a lite end's pair.
    pub remote_kind: Option<CandidateKind>,
    /// Pair priority (RFC 8445 §6.1.2.3) as this end computes it; zero for a relay.
    pub priority: u64,
    /// What became of it.
    pub outcome: PathOutcome,
}

/// Whether a [`PathCandidate`] is a candidate pair or a relay.
#[cfg(feature = "ice")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathKind {
    /// A candidate pair the checklist held (RFC 8445 §6.1.2).
    Pair,
    /// An allocation on a TURN server (RFC 8656), the relayed candidate's.
    Relay,
}

/// The kind of an ICE candidate (RFC 8445 §5.1.1).
#[cfg(feature = "ice")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateKind {
    /// An address a socket of the host's own is bound to.
    Host,
    /// The NAT mapping of the host's socket, as a STUN or TURN server saw it.
    ServerReflexive,
    /// An address a connectivity check revealed.
    PeerReflexive,
    /// An address on a TURN server that relays for the host.
    Relayed,
}

/// What became of one [`PathCandidate`].
#[cfg(feature = "ice")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathOutcome {
    /// The media path: the selected pair (RFC 8445 §8.1.2) or the relay it uses.
    Selected,
    /// A pair whose check succeeded, with nothing selected yet.
    Valid,
    /// Undecided: a pair frozen, waiting or in flight; a relay being allocated.
    Waiting,
    /// Succeeded, but a higher-priority pair was selected.
    Outranked,
    /// Removed by a nomination before its check finished (RFC 8445 §8.1.2), or succeeded after a
    /// lower-priority nomination.
    NominatedElsewhere,
    /// A pair whose check was never answered (RFC 8489 §6.2.1).
    TimedOut,
    /// A pair the far end refused, with this STUN error code (RFC 8445
    /// §7.2.5.2.4).
    Refused(u16),
    /// The answer came from another address than the check went to (RFC 8445 §7.2.5.2.1): a NAT
    /// rewrote it.
    NotSymmetric,
    /// A pair whose answer named no address to form a valid pair from.
    Unusable,
    /// The relay would not let the far end through, or the server refused the allocation (RFC 8656
    /// §9, §7.3).
    RelayRefused(crate::TurnFailure),
    /// Never checked: discarded by the pair limit (RFC 8445 §6.1.2.5) or the checklist ended first.
    NotChecked,
    /// A relay no selected pair uses, or none selected yet.
    Held,
    /// A relay given back: ICE chose a pair without it (RFC 8445 §8.3.1), or this fork branch let
    /// go.
    Released,
    /// A relay the server took back: a refresh refused or unanswered (RFC 8656 §8).
    Lost(crate::TurnFailure),
}

#[cfg(feature = "ice")]
const fn kind_of(kind: CandidateType) -> CandidateKind {
    match kind {
        CandidateType::Host => CandidateKind::Host,
        CandidateType::ServerReflexive => CandidateKind::ServerReflexive,
        CandidateType::PeerReflexive => CandidateKind::PeerReflexive,
        CandidateType::Relay => CandidateKind::Relayed,
    }
}

#[cfg(feature = "ice")]
const fn outcome_of(outcome: PairOutcome) -> PathOutcome {
    match outcome {
        PairOutcome::Waiting => PathOutcome::Waiting,
        PairOutcome::Valid => PathOutcome::Valid,
        PairOutcome::Selected => PathOutcome::Selected,
        PairOutcome::Outranked => PathOutcome::Outranked,
        PairOutcome::NominatedElsewhere => PathOutcome::NominatedElsewhere,
        PairOutcome::TimedOut => PathOutcome::TimedOut,
        PairOutcome::Refused { code } => PathOutcome::Refused(code),
        PairOutcome::NotSymmetric => PathOutcome::NotSymmetric,
        PairOutcome::Unusable => PathOutcome::Unusable,
        PairOutcome::RelayRefused(why) => PathOutcome::RelayRefused(why),
        PairOutcome::NotChecked => PathOutcome::NotChecked,
    }
}

#[cfg(feature = "ice")]
const fn relay_outcome_of(outcome: RelayOutcome) -> PathOutcome {
    match outcome {
        RelayOutcome::Waiting => PathOutcome::Waiting,
        RelayOutcome::Held => PathOutcome::Held,
        RelayOutcome::Selected => PathOutcome::Selected,
        RelayOutcome::Released => PathOutcome::Released,
        RelayOutcome::Refused(why) => PathOutcome::RelayRefused(why),
        RelayOutcome::Lost(why) => PathOutcome::Lost(why),
    }
}

/// Username fragment length in `ice-char`s: 8, i.e. 48 bits. RFC 8445 §5.3 wants at least 24; RFC
/// 8839 §5.4 allows 4 to 32.
#[cfg(feature = "ice")]
const UFRAG_CHARS: usize = 8;

/// Password length in `ice-char`s: 24, i.e. 144 bits. §5.3 wants at least 128; §5.4 allows 22 to
/// 256.
#[cfg(feature = "ice")]
const PWD_CHARS: usize = 24;

/// The 64 `ice-char`s of RFC 8839 §5.4, so six bits map to one without modulo bias.
#[cfg(feature = "ice")]
const ICE_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// No agent in this build. The type exists so the description writers have one shape; it is always
/// `None`.
#[cfg(not(feature = "ice"))]
#[derive(Clone, Debug)]
pub(crate) struct LocalIce;

/// What one call has settled about ICE and repeats on every description (RFC 8839 §4.4.1.1.1).
/// Leaving them out of a hold re-offer would read as ICE withdrawn.
///
/// `Debug` is safe to derive: the password redacts itself.
#[cfg(feature = "ice")]
#[derive(Clone, Debug)]
pub(crate) struct LocalIce {
    credentials: Credentials,
    role: Role,
    tiebreaker: u64,
    /// The socket's public address, if given: a server-reflexive candidate, kept so
    /// [`LocalIce::agent`] rebuilds it. For a lite end it is the host candidate.
    public: Option<SocketAddr>,
    candidates: Vec<Candidate>,
    /// Whether this end is the lite implementation ([`IcePolicy::Lite`]).
    lite: bool,
}

#[cfg(feature = "ice")]
impl LocalIce {
    /// Draw a call's credentials and tiebreaker and gather its candidates.
    ///
    /// `we_are_offerer` sets the RFC 8445 §6.1.1 role; [`IceAgent::set_remote`] adjusts it for a
    /// lite peer. `public` adds a server-reflexive candidate, which is also the default candidate
    /// for `c=` and `m=` (RFC 8839 §4.2.1.2).
    ///
    /// `lite` draws for [`IcePolicy::Lite`]: controlled role, and one host candidate at `public` if
    /// given, else `address`. Behind a one-to-one NAT the public address is the host address to any
    /// peer, and a lite end has host candidates only (RFC 8445 §5.2).
    ///
    /// # Errors
    ///
    /// [`MediaError::Ice`] for an address RFC 8445 §5.1.1.1 rules out, such as loopback or
    /// link-local.
    pub(crate) fn draw(
        keys: &mut KeySource,
        address: SocketAddr,
        public: Option<SocketAddr>,
        we_are_offerer: bool,
        lite: bool,
        now: Instant,
    ) -> Result<Self, MediaError> {
        let credentials = draw_credentials(keys)?;
        let tiebreaker = u64::from_be_bytes(keys.block()[..8].try_into().unwrap_or([0; 8]));
        if lite {
            // same gathering and §5.1.1.1 checks as the full role, on the address peers reach
            let advertised = public.unwrap_or(address);
            let (agent, stream) = new_agent(
                &credentials,
                Role::Controlled,
                tiebreaker,
                advertised,
                None,
                now,
            )?;
            let candidates = agent.local_candidates(stream);
            return Ok(Self {
                credentials,
                role: Role::Controlled,
                tiebreaker,
                public,
                candidates,
                lite: true,
            });
        }
        // a lite peer is only known from its description; the agent adjusts the role then
        let role = Role::initial_full(we_are_offerer, false);
        let (agent, stream) = new_agent(&credentials, role, tiebreaker, address, public, now)?;
        let candidates = agent.local_candidates(stream);
        Ok(Self {
            credentials,
            role,
            tiebreaker,
            public,
            candidates,
            lite: false,
        })
    }

    /// Like [`LocalIce::draw`] in the full role, adding the relayed candidate from `relay`.
    ///
    /// The returned agent is the one the call runs, since the allocation inside cannot be rebuilt
    /// by [`LocalIce::agent`].
    ///
    /// # Errors
    ///
    /// As [`LocalIce::draw`], and [`MediaError::Ice`] for a relay of another address family.
    /// `relay` is taken only after gathering succeeds, so on error it stays for the caller; `None`
    /// when the slot was empty.
    pub(crate) fn draw_relayed(
        keys: &mut KeySource,
        address: SocketAddr,
        public: Option<SocketAddr>,
        relay: &mut Option<crate::relay::Relay>,
        we_are_offerer: bool,
        now: Instant,
    ) -> Result<Option<(Self, Ice)>, MediaError> {
        let credentials = draw_credentials(keys)?;
        let tiebreaker = u64::from_be_bytes(keys.block()[..8].try_into().unwrap_or([0; 8]));
        let role = Role::initial_full(we_are_offerer, false);
        let (agent, stream) = new_agent(&credentials, role, tiebreaker, address, public, now)?;
        let Some(ice) = with_relay(agent, stream, address, relay, keys, now)? else {
            return Ok(None);
        };
        let candidates = ice.gathered().unwrap_or_default();
        Ok(Some((
            Self {
                credentials,
                role,
                tiebreaker,
                public,
                candidates,
                lite: false,
            },
            ice,
        )))
    }

    /// The agent for a fork branch: [`LocalIce::agent`] plus the fork's shared allocation
    /// ([`IceAgent::add_shared_relay`]).
    ///
    /// Every branch got the same offer, so the agent rebuilds the same candidates on the same
    /// allocation. RFC 8839 §7 runs each answer as an independent exchange, and RFC 8656 §1 lets
    /// one relayed address serve many peers. Each agent permits its own peer and releases the
    /// allocation when its branch ends or ICE picks another pair (RFC 8445 §8.3.1); the server gets
    /// it back when no branch holds it.
    ///
    /// `None` when the allocation is gone or of another family.
    ///
    /// # Errors
    ///
    /// As [`LocalIce::agent`].
    pub(crate) fn shared_agent(
        &self,
        address: SocketAddr,
        relay: &SharedRelay,
        keys: &mut KeySource,
        now: Instant,
    ) -> Result<Option<Ice>, MediaError> {
        if self.lite || relay.relayed(address).is_none() {
            return Ok(None);
        }
        let (mut agent, stream) = new_agent(
            &self.credentials,
            self.role,
            self.tiebreaker,
            address,
            self.public,
            now,
        )?;
        if agent
            .add_shared_relay(stream, ComponentId::RTP, address, relay, now)
            .is_err()
        {
            return Ok(None);
        }
        let mut ice = Ice {
            local: address,
            stream: relay.transport().is_stream().then(|| relay.server()),
            out: Vec::new(),
            probe: Vec::new(),
            running: Running::Full(Box::new(Full {
                agent,
                stream,
                keys: KeySource::new(keys.block()),
            })),
        };
        ice.top_up();
        Ok(Some(ice))
    }

    /// The call's ICE after a restart (RFC 8445 §9): new credentials (RFC 8839 §4.4.1.1.1,
    /// §4.4.2.1), same role and tiebreaker, since §9 keeps the roles.
    ///
    /// Candidates are those `running` still holds (host, reflexive, and the relay unless released).
    /// `None` keeps the old ones, which is all a lite end has: it must not add host candidates
    /// (§4.4.1.3).
    ///
    /// # Errors
    ///
    /// As [`LocalIce::draw`].
    pub(crate) fn restarted(
        &self,
        keys: &mut KeySource,
        running: Option<Vec<Candidate>>,
    ) -> Result<Self, MediaError> {
        Ok(Self {
            credentials: draw_credentials(keys)?,
            candidates: running.unwrap_or_else(|| self.candidates.clone()),
            ..self.clone()
        })
    }

    /// Whether this end is the lite implementation.
    pub(crate) const fn is_lite(&self) -> bool {
        self.lite
    }

    /// Whether `description` carries these credentials on its stream.
    pub(crate) fn written_in(&self, description: &SessionDescription) -> bool {
        description
            .media
            .iter()
            .find(|stream| !stream.is_rejected())
            .and_then(|stream| sipral_nat::ice::parse_remote(description, stream))
            .is_some_and(|written| {
                written.ufrag == self.credentials.ufrag() && written.pwd == self.credentials.pwd()
            })
    }
}

/// A username fragment and a password, drawn from `keys`.
#[cfg(feature = "ice")]
fn draw_credentials(keys: &mut KeySource) -> Result<Credentials, MediaError> {
    let block = keys.block();
    let chars: Vec<u8> = block
        .iter()
        .take(UFRAG_CHARS + PWD_CHARS)
        // six bits always index the 64 characters; `get` avoids a panic path while describing a
        // call
        .map(|byte| {
            ICE_CHARS
                .get(usize::from(byte & 0x3F))
                .copied()
                .unwrap_or(b'A')
        })
        .collect();
    let (ufrag, pwd) = chars.split_at(UFRAG_CHARS);
    // both halves are `ice-char`s, so only a wrong length here could fail
    Credentials::new(
        core::str::from_utf8(ufrag).unwrap_or_default(),
        core::str::from_utf8(pwd).unwrap_or_default(),
    )
    .map_err(MediaError::Ice)
}

#[cfg(feature = "ice")]
impl LocalIce {
    /// The credentials to write into a description.
    pub(crate) const fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// The candidates to write into a description.
    pub(crate) fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    /// Whether `data` is a check the far end sent this call: a Binding request with `USERNAME` of
    /// our fragment, a colon and theirs, signed with our password (RFC 8445 §7.2.2, RFC 8489 §9.1).
    ///
    /// Lets checks be kept before the agent exists; only someone who read the description can
    /// produce one. The agent authenticates it again later.
    pub(crate) fn is_check_for(&self, data: &[u8]) -> bool {
        signed_for(data, &self.credentials)
    }

    /// The agent this call runs, rebuilt from what was written down.
    ///
    /// Gathering is deterministic without servers, so the rebuilt candidates match the offer
    /// (`a_rebuilt_agent_gathers_the_candidates_that_were_offered`). `seed` comes from the engine's
    /// [`KeySource`], not the session's `Draws` mixer, because guessable ids would defeat consent
    /// (RFC 7675 §5.1).
    ///
    /// # Errors
    ///
    /// As [`LocalIce::draw`]. A lite end needs only the credentials: no checklist, no own requests.
    pub(crate) fn agent(
        &self,
        address: SocketAddr,
        seed: [u8; 32],
        now: Instant,
    ) -> Result<Ice, MediaError> {
        if self.lite {
            let advertised = self.public.unwrap_or(address);
            return Ok(Ice {
                local: address,
                stream: None,
                out: Vec::new(),
                probe: Vec::new(),
                running: Running::Lite(Box::new(Lite {
                    agent: LiteAgent::new(
                        self.credentials.ufrag().to_owned(),
                        self.credentials.pwd().to_owned(),
                        self.role,
                        self.tiebreaker,
                    ),
                    advertised,
                    outbox: VecDeque::new(),
                    dropped: 0,
                    selected: None,
                    news: None,
                    pending: None,
                    awaiting: VecDeque::new(),
                })),
            });
        }
        let (agent, stream) = new_agent(
            &self.credentials,
            self.role,
            self.tiebreaker,
            address,
            self.public,
            now,
        )?;
        let mut ice = Ice {
            local: address,
            stream: None,
            out: Vec::new(),
            probe: Vec::new(),
            running: Running::Full(Box::new(Full {
                agent,
                stream,
                keys: KeySource::new(seed),
            })),
        };
        ice.top_up();
        Ok(ice)
    }
}

/// One gathered agent with one stream and one component, plus the reflexive candidate `public`.
#[cfg(feature = "ice")]
fn new_agent(
    credentials: &Credentials,
    role: Role,
    tiebreaker: u64,
    address: SocketAddr,
    public: Option<SocketAddr>,
    now: Instant,
) -> Result<(IceAgent, StreamId), MediaError> {
    // no STUN or TURN server, so `gather` finishes immediately
    let mut agent = IceAgent::new(IceConfig::default(), credentials.clone(), role, tiebreaker)
        .map_err(MediaError::Ice)?;
    // one component: `IcePolicy::offers` forces rtcp-mux
    let stream = agent
        .add_stream(&[(ComponentId::RTP, address)])
        .map_err(MediaError::Ice)?;
    agent.gather(now).map_err(MediaError::Ice)?;
    // no server to name and at most one reflexive candidate, so the foundation needs nothing to
    // distinguish
    if let Some(public) = public {
        agent
            .add_server_reflexive(stream, ComponentId::RTP, address, public, None)
            .map_err(MediaError::Ice)?;
    }
    Ok((agent, stream))
}

/// A gathered agent with the allocation from `relay` as its relayed candidate, using ids from
/// `keys`; `None` when the slot was empty.
#[cfg(feature = "ice")]
fn with_relay(
    mut agent: IceAgent,
    stream: StreamId,
    address: SocketAddr,
    relay: &mut Option<crate::relay::Relay>,
    keys: &mut KeySource,
    now: Instant,
) -> Result<Option<Ice>, MediaError> {
    let Some((server, client)) = relay.take().map(crate::relay::Relay::into_parts) else {
        return Ok(None);
    };
    let over = client.transport().is_stream().then_some(server);
    agent
        .add_relayed(stream, ComponentId::RTP, address, server, client, now)
        .map_err(MediaError::Ice)?;
    let mut ice = Ice {
        local: address,
        stream: over,
        out: Vec::new(),
        probe: Vec::new(),
        running: Running::Full(Box::new(Full {
            agent,
            stream,
            keys: KeySource::new(keys.block()),
        })),
    };
    ice.top_up();
    Ok(Some(ice))
}

/// The running agent, owned by the media session.
///
/// Neither `Clone` nor `Debug`: it holds the peer's password.
#[cfg(feature = "ice")]
pub(crate) struct Ice {
    /// The socket the application bound for this call.
    local: SocketAddr,
    /// The TURN server reached over TCP or TLS from `local`, if the relay uses a connection.
    stream: Option<SocketAddr>,
    /// Reusable buffer for outgoing application data, with a channel header on a relayed pair.
    out: Vec<u8>,
    /// The agent's own outgoing datagram, kept while the caller borrows it.
    probe: Vec<u8>,
    running: Running,
}

/// Which of the two roles this call plays.
#[cfg(feature = "ice")]
enum Running {
    // both boxed: very different sizes, and most sessions hold neither
    Full(Box<Full>),
    Lite(Box<Lite>),
}

/// The full role: RFC 8445's whole agent.
#[cfg(feature = "ice")]
struct Full {
    agent: IceAgent,
    /// The call's only stream; `write_answer` explains why there is one.
    stream: StreamId,
    /// Source of transaction ids, seeded from the engine's, so the media thread can refill without
    /// the engine.
    keys: KeySource,
}

/// The lite role: a STUN responder and the nominated pair. No checklist, timer or transaction ids.
#[cfg(feature = "ice")]
struct Lite {
    agent: LiteAgent,
    /// The advertised host candidate: the socket address or the forwarded public one.
    advertised: SocketAddr,
    /// Answers to checks, capped at [`TRANSMIT_CEILING`], and refusals to strangers, capped at
    /// [`REFUSAL_CEILING`], as in the full agent.
    outbox: VecDeque<(SocketAddr, Vec<u8>)>,
    /// Answers dropped by the ceiling.
    dropped: u64,
    /// The pair the peer nominated, as the media path.
    selected: Option<SelectedPair>,
    /// A nomination the session has not been told about yet.
    news: Option<SelectedPair>,
    /// The credentials of a restart this end offered and has not taken up.
    pending: Option<Credentials>,
    /// Checks signed with the pending credentials, with source and time, until the restart is taken
    /// up: the newest [`AWAITING`].
    awaiting: VecDeque<(SocketAddr, Vec<u8>, Instant)>,
}

/// How many restart checks a lite end keeps, as many as the full agent.
#[cfg(feature = "ice")]
const AWAITING: usize = 32;

/// What a datagram handed to [`Ice::handle_datagram`] turned out to be.
#[cfg(feature = "ice")]
pub(crate) enum Taken {
    /// Application data, at this position in the datagram.
    Data(Range<usize>),
    /// ICE's own traffic, already dealt with.
    Consumed,
    /// Not on the socket the agent was given.
    Foreign,
}

/// What the session has to act on.
#[cfg(feature = "ice")]
pub(crate) enum PathNews {
    /// A pair was selected, or a later one replaced it.
    Selected(SelectedPair),
    /// Nothing may be sent on the path: consent lost or checks failed.
    Lost,
}

#[cfg(feature = "ice")]
impl Ice {
    /// Give the agent the peer's side and say whether ICE is on. A lite end ignores it.
    ///
    /// # Errors
    ///
    /// [`MediaError::Ice`] for credentials outside RFC 8839 §5.4, or changed without a restart.
    pub(crate) fn set_remote(
        &mut self,
        remote: &RemoteIce,
        now: Instant,
    ) -> Result<(), MediaError> {
        match &mut self.running {
            Running::Full(full) => full
                .agent
                .set_remote(full.stream, remote, now)
                .map_err(MediaError::Ice),
            Running::Lite(_) => Ok(()),
        }
    }

    /// Adopt a completed restart's credentials, if new, and the peer's side `remote`.
    ///
    /// Only after the exchange completes, since a failed offer leaves ICE unchanged (RFC 8839
    /// §4.4). The full agent restarts (RFC 8445 §9): it rebuilds the checklist from `remote` and
    /// checks again, while the old pair keeps carrying audio and consent under the old credentials
    /// until a new one is selected (RFC 8839 §4.4.3.1.1, RFC 7675 §5.1). The role is unchanged. A
    /// lite end keeps its pair until the peer nominates under the new credentials.
    ///
    /// # Errors
    ///
    /// [`MediaError::Ice`] for peer credentials outside RFC 8839 §5.4; the old pair continues while
    /// consent lasts.
    pub(crate) fn follow(
        &mut self,
        local: &LocalIce,
        remote: Option<&RemoteIce>,
        now: Instant,
    ) -> Result<(), MediaError> {
        match &mut self.running {
            Running::Lite(lite) => {
                if lite.agent.local_ufrag() != local.credentials().ufrag() {
                    lite.agent.restart(
                        local.credentials().ufrag().to_owned(),
                        local.credentials().pwd().to_owned(),
                    );
                    // answer checks kept for these credentials; others were for another offer
                    if lite.pending.take().as_ref() == Some(local.credentials()) {
                        lite.replay(self.local, now);
                    } else {
                        lite.awaiting.clear();
                    }
                }
                Ok(())
            }
            Running::Full(full) => {
                if full.agent.local_credentials() == local.credentials() {
                    return Ok(());
                }
                full.agent
                    .restart(local.credentials().clone())
                    .map_err(MediaError::Ice)?;
                self.top_up();
                let (Running::Full(full), Some(remote)) = (&mut self.running, remote) else {
                    return Ok(());
                };
                let set = full.agent.set_remote(full.stream, remote, now);
                self.top_up();
                set.map_err(MediaError::Ice)
            }
        }
    }

    /// Refill the agent's transaction id pool from a cryptographic source.
    ///
    /// Called right before anything that moves the agent. An empty pool puts [`IceAgent::deadline`]
    /// in the past and spins the caller while consent runs out.
    pub(crate) fn top_up(&mut self) {
        let Running::Full(full) = &mut self.running else {
            return;
        };
        let mut wanted = full.agent.transaction_ids_wanted();
        while wanted > 0 {
            // 32-byte block, 12-byte ids: two per block, the last 8 bytes unused
            let block = full.keys.block();
            for chunk in block.as_chunks::<12>().0.iter().take(wanted.min(2)) {
                let mut id = [0_u8; 12];
                id.copy_from_slice(chunk);
                full.agent.supply_transaction_id(TransactionId::new(id));
                wanted -= 1;
            }
        }
    }

    /// Feed a datagram from the media socket.
    ///
    /// A lite end answers checks; anything not STUN is application data from any source, as for the
    /// full agent (RFC 8445 §12.2). The session's latch follows the nominated pair.
    pub(crate) fn handle_datagram(&mut self, from: SocketAddr, data: &[u8], now: Instant) -> Taken {
        match &mut self.running {
            Running::Full(full) => match full.agent.handle_datagram(self.local, from, data, now) {
                Received::Data { range, .. } => Taken::Data(range),
                Received::Consumed => Taken::Consumed,
                Received::Foreign => Taken::Foreign,
            },
            Running::Lite(lite) => {
                if sipral_nat::classify(data) != sipral_nat::Demux::Stun {
                    return Taken::Data(0..data.len());
                }
                // signed for our offered restart: keep it for later instead of refusing it as a
                // stranger's
                if lite
                    .pending
                    .as_ref()
                    .is_some_and(|pending| signed_for(data, pending))
                {
                    if lite.awaiting.len() >= AWAITING {
                        lite.awaiting.pop_front();
                    }
                    lite.awaiting.push_back((from, data.to_vec(), now));
                    return Taken::Consumed;
                }
                lite.answer(self.local, from, data);
                Taken::Consumed
            }
        }
    }
}

#[cfg(feature = "ice")]
impl Lite {
    /// Answer a check as RFC 8445 §7.3 describes for a lite end, and take a nomination as the media
    /// path.
    fn answer(&mut self, local: SocketAddr, from: SocketAddr, data: &[u8]) {
        if let Some(answer) = self
            .agent
            .answer_binding_request(ComponentId::RTP, local, from, data)
        {
            // every check is answered, so cap the queue against floods; dropping the new answer
            // looks like loss to the peer. Strangers' refusals stop at half, leaving room for the
            // peer
            let (reply, ceiling) = match answer {
                CheckAnswer::Signed(reply) => (reply, TRANSMIT_CEILING),
                CheckAnswer::Refused(reply) => (reply, REFUSAL_CEILING),
            };
            if self.outbox.len() < ceiling {
                self.outbox.push_back((from, reply));
            } else {
                self.dropped = self.dropped.saturating_add(1);
            }
        }
        if let Some(pair) = self.agent.valid_pair(ComponentId::RTP) {
            let chosen = SelectedPair {
                local: self.advertised,
                local_kind: CandidateType::Host,
                remote: pair.remote,
                // a lite end never learns the peer's candidate type
                remote_kind: CandidateType::Host,
            };
            if self.selected.map(|held| held.remote) != Some(chosen.remote) {
                self.selected = Some(chosen);
                self.news = Some(chosen);
            }
        }
    }

    /// Answer checks kept for the restart just adopted, except those older than the peer's 39.5 s
    /// transaction (RFC 8489 §6.2.1).
    fn replay(&mut self, local: SocketAddr, now: Instant) {
        for (from, data, at) in core::mem::take(&mut self.awaiting) {
            if at
                .checked_add(sipral_nat::turn::DEFAULT_TI)
                .is_some_and(|until| now < until)
            {
                self.answer(local, from, &data);
            }
        }
    }
}

/// Whether `data` is a Binding request signed with `credentials`: USERNAME starting with their
/// fragment and a colon, and valid MESSAGE-INTEGRITY (RFC 8445 §7.2.2).
#[cfg(feature = "ice")]
fn signed_for(data: &[u8], credentials: &Credentials) -> bool {
    let Ok(message) = Message::parse(data) else {
        return false;
    };
    if message.class() != Class::Request || message.method() != Method::BINDING {
        return false;
    }
    let names = message.username().is_some_and(|username| {
        username
            .strip_prefix(credentials.ufrag().as_bytes())
            .and_then(|rest| rest.strip_prefix(b":"))
            .is_some_and(|theirs| !theirs.is_empty())
    });
    if !names {
        return false;
    }
    let key = credentials.pwd().as_bytes();
    match message.verify_integrity_sha256(key) {
        Integrity::Valid => true,
        Integrity::Invalid => false,
        Integrity::Absent => message.verify_integrity(key) == Integrity::Valid,
    }
}

#[cfg(feature = "ice")]
impl Ice {
    /// The TURN server the relay reaches over TCP or TLS, if any.
    pub(crate) const fn stream_server(&self) -> Option<SocketAddr> {
        self.stream
    }

    /// Feed bytes from the relay's TURN connection, and say whether the relay uses one. Messages
    /// come out of [`Ice::next_stream_frame`].
    pub(crate) fn push_stream(&mut self, bytes: &[u8]) -> bool {
        let (Some(server), Running::Full(full)) = (self.stream, &mut self.running) else {
            return false;
        };
        full.agent.push_stream(self.local, server, bytes)
    }

    /// Copy the next whole relay-connection message into `frame`, for whichever fork branch it
    /// belongs to ([`IceAgent::next_stream_frame`]). `Ok(false)` when none is waiting.
    ///
    /// # Errors
    ///
    /// The connection broke framing; the relay is lost ([`IceAgent::poll_stream`]).
    pub(crate) fn next_stream_frame(
        &mut self,
        frame: &mut Vec<u8>,
        now: Instant,
    ) -> Result<bool, FrameError> {
        let (Some(server), Running::Full(full)) = (self.stream, &mut self.running) else {
            frame.clear();
            return Ok(false);
        };
        full.agent.next_stream_frame(self.local, server, frame, now)
    }

    /// Take a message read by [`Ice::next_stream_frame`]: peer data as [`Taken::Data`], relay
    /// traffic as [`Taken::Consumed`] ([`IceAgent::take_stream_frame`]).
    pub(crate) fn take_stream_frame(&mut self, frame: &[u8], now: Instant) -> Taken {
        let (Some(server), Running::Full(full)) = (self.stream, &mut self.running) else {
            return Taken::Foreign;
        };
        match full.agent.take_stream_frame(self.local, server, frame, now) {
            Received::Data { range, .. } => Taken::Data(range),
            Received::Consumed => Taken::Consumed,
            Received::Foreign => Taken::Foreign,
        }
    }

    /// The relay's TURN connection closed and the relay is lost ([`IceAgent::stream_closed`]).
    pub(crate) fn stream_closed(&mut self, now: Instant) {
        if let (Some(server), Running::Full(full)) = (self.stream, &mut self.running) {
            full.agent.stream_closed(self.local, server, now);
        }
    }

    /// Take the passing of time. A lite end has no timer.
    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        if let Running::Full(full) = &mut self.running {
            full.agent.handle_timeout(now);
        }
    }

    /// When the agent next has work; never for a lite end.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        match &self.running {
            Running::Full(full) => full.agent.deadline(),
            Running::Lite(_) => None,
        }
    }

    /// Take the agent's next datagram and say where and how it goes: from the socket, or on the
    /// relay's TURN connection.
    ///
    /// The bytes are read with [`Ice::probe`]. Two calls, because returning an address ends the
    /// mutable borrow while a byte borrow would keep it.
    pub(crate) fn take_probe(&mut self) -> Option<(SocketAddr, Transport)> {
        let (destination, data, transport) = match &mut self.running {
            Running::Full(full) => {
                let Transmit {
                    destination,
                    data,
                    transport,
                    ..
                } = full.agent.poll_transmit()?;
                (destination, data, transport)
            }
            Running::Lite(lite) => {
                let (destination, data) = lite.outbox.pop_front()?;
                (destination, data, Transport::Udp)
            }
        };
        self.probe = data;
        Some((destination, transport))
    }

    /// The bytes [`Ice::take_probe`] last took.
    pub(crate) fn probe(&self) -> &[u8] {
        &self.probe
    }

    /// Agent datagrams dropped because [`TRANSMIT_CEILING`] were already waiting for
    /// [`Ice::take_probe`].
    pub(crate) fn transmits_dropped(&self) -> u64 {
        match &self.running {
            Running::Full(full) => full.agent.transmits_dropped(),
            Running::Lite(lite) => lite.dropped,
        }
    }

    /// The next thing about the path the session has to act on.
    pub(crate) fn poll_news(&mut self) -> Option<PathNews> {
        match &mut self.running {
            Running::Full(full) => loop {
                match full.agent.poll_event()? {
                    IceEvent::Selected { pair, .. } => return Some(PathNews::Selected(pair)),
                    // RFC 7675 §5: stop sending on the pair; its credentials are spent
                    IceEvent::ConsentLost { .. }
                    | IceEvent::Failed
                    | IceEvent::StreamFailed { .. } => return Some(PathNews::Lost),
                    IceEvent::GatheringComplete
                    | IceEvent::Completed
                    | IceEvent::RoleChanged(_) => {}
                }
            },
            Running::Lite(lite) => lite.news.take().map(PathNews::Selected),
        }
    }

    /// Where a datagram would go, without sending. Producers ask first, because once a frame is
    /// built or a record taken it cannot be undone.
    pub(crate) fn route(&self) -> Option<Route> {
        match &self.running {
            Running::Full(full) => full.agent.route(full.stream, ComponentId::RTP).ok(),
            Running::Lite(lite) => lite.selected.map(|pair| Route {
                source: self.local,
                destination: pair.remote,
                transport: Transport::Udp,
            }),
        }
    }

    /// Wrap a datagram for the selected pair and say where and how it goes.
    ///
    /// # Errors
    ///
    /// [`SendError`] when there is no pair, consent is gone, or the relay refused. A lite end can
    /// only lack a pair (RFC 8445 §12.1).
    pub(crate) fn send(
        &mut self,
        data: &[u8],
        now: Instant,
    ) -> Result<(SocketAddr, Transport, &[u8]), SendError> {
        self.out.clear();
        let (destination, transport) = match &mut self.running {
            Running::Full(full) => {
                let route =
                    full.agent
                        .send(full.stream, ComponentId::RTP, data, &mut self.out, now)?;
                (route.destination, route.transport)
            }
            Running::Lite(lite) => {
                let pair = lite.selected.ok_or(SendError::NoRoute)?;
                self.out.extend_from_slice(data);
                (pair.remote, Transport::Udp)
            }
        };
        Ok((destination, transport, &self.out))
    }

    /// Release every relay this call holds: the Refresh with lifetime zero (RFC 8656 §8) for each,
    /// with destination and transport.
    ///
    /// For the end of a call or a call that ended up without ICE. Other queued agent traffic goes
    /// too. A lite end holds no relay.
    pub(crate) fn release(&mut self, now: Instant) -> Vec<(SocketAddr, Transport, Vec<u8>)> {
        self.top_up();
        let Running::Full(full) = &mut self.running else {
            return Vec::new();
        };
        full.agent.release_relays(now);
        let mut out = Vec::new();
        while let Some(Transmit {
            destination,
            data,
            transport,
            ..
        }) = full.agent.poll_transmit()
        {
            out.push((destination, transport, data));
        }
        out
    }

    /// The relays this agent holds, still live, for an agent whose description was refused. A lite
    /// end holds none.
    pub(crate) fn into_relays(self) -> Vec<crate::relay::Relay> {
        let local = self.local;
        match self.running {
            Running::Full(full) => full
                .agent
                .into_relays()
                .into_iter()
                .map(|(server, client)| crate::relay::Relay::from_parts(local, server, client))
                .collect(),
            Running::Lite(_) => Vec::new(),
        }
    }

    /// The socket the application bound for this call.
    pub(crate) const fn local(&self) -> SocketAddr {
        self.local
    }

    /// The pair the agent selected, once it has one.
    pub(crate) fn selected_pair(&self) -> Option<SelectedPair> {
        match &self.running {
            Running::Full(full) => full.agent.selected_pair(full.stream, ComponentId::RTP),
            Running::Lite(lite) => lite.selected,
        }
    }

    /// Candidates this agent still holds: what it gathered, minus a relay released after choosing
    /// another pair (RFC 8445 §8.3.1). `None` for a lite end.
    ///
    /// Descriptions use [`LocalIce::candidates`]; this is only for restarts
    /// ([`LocalIce::restarted`]), so a released candidate is not offered again.
    pub(crate) fn gathered(&self) -> Option<Vec<Candidate>> {
        match &self.running {
            Running::Full(full) => Some(full.agent.local_candidates(full.stream)),
            Running::Lite(_) => None,
        }
    }

    /// The allocation as a handle other fork branches can share ([`LocalIce::shared_agent`]);
    /// `None` if none is held.
    pub(crate) fn shared_relay(&self) -> Option<SharedRelay> {
        match &self.running {
            Running::Full(full) => full.agent.shared_relays().into_iter().next(),
            Running::Lite(_) => None,
        }
    }

    /// Whose a datagram on a shared fork socket is ([`IceAgent::claims`]). A lite end claims what
    /// comes from its nominated pair.
    pub(crate) fn claims(&self, from: SocketAddr, data: &[u8]) -> Claim {
        match &self.running {
            Running::Full(full) => full.agent.claims(self.local, from, data),
            Running::Lite(lite) => {
                let signed = lite
                    .pending
                    .as_ref()
                    .is_some_and(|pending| signed_for(data, pending));
                if signed || lite.selected.is_some_and(|pair| pair.remote == from) {
                    Claim::Mine
                } else {
                    Claim::Not
                }
            }
        }
    }

    /// Record the credentials of a restart offered or answered, or `None` if it will not happen, so
    /// early peer checks under them are kept until [`Ice::follow`] instead of refused
    /// ([`IceAgent::expect_restart`]).
    pub(crate) fn expect_restart(&mut self, restarting: Option<&LocalIce>) {
        let pending = restarting.map(|local| local.credentials().clone());
        match &mut self.running {
            Running::Full(full) => full.agent.expect_restart(pending),
            Running::Lite(lite) => {
                if lite.pending != pending {
                    lite.awaiting.clear();
                }
                lite.pending = pending;
            }
        }
    }

    /// Every pair formed and relay held, with outcomes (the path half of D5). A lite end reports
    /// only its nominated pair.
    pub(crate) fn path_candidates(&self) -> Vec<PathCandidate> {
        match &self.running {
            Running::Full(full) => {
                let pairs =
                    full.agent
                        .pair_report(full.stream)
                        .into_iter()
                        .map(|pair| PathCandidate {
                            kind: PathKind::Pair,
                            local: Some(pair.local),
                            local_kind: kind_of(pair.local_kind),
                            remote: pair.remote,
                            remote_kind: Some(kind_of(pair.remote_kind)),
                            priority: pair.priority,
                            outcome: outcome_of(pair.outcome),
                        });
                let relays = full
                    .agent
                    .relay_report()
                    .into_iter()
                    .map(|relay| PathCandidate {
                        kind: PathKind::Relay,
                        local: relay.relayed,
                        local_kind: CandidateKind::Relayed,
                        remote: relay.server,
                        remote_kind: None,
                        priority: 0,
                        outcome: relay_outcome_of(relay.outcome),
                    });
                pairs.chain(relays).collect()
            }
            Running::Lite(lite) => lite
                .selected
                .map(|pair| PathCandidate {
                    kind: PathKind::Pair,
                    local: Some(pair.local),
                    local_kind: CandidateKind::Host,
                    remote: pair.remote,
                    remote_kind: None,
                    priority: 0,
                    outcome: PathOutcome::Selected,
                })
                .into_iter()
                .collect(),
        }
    }

    /// [`Ice::gathered`], empty for a lite end, for tests.
    #[cfg(test)]
    pub(crate) fn local_candidates(&self) -> Vec<Candidate> {
        self.gathered().unwrap_or_default()
    }
}

/// Written by hand, because a derived one would print the peer's password and the transaction id
/// source (RFC 7675 §5.1).
#[cfg(feature = "ice")]
impl core::fmt::Debug for Ice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut out = f.debug_struct("Ice");
        out.field("local", &self.local);
        match &self.running {
            Running::Full(full) => out.field("state", &full.agent.state()),
            Running::Lite(lite) => out.field("lite", &lite.selected),
        };
        out.finish_non_exhaustive()
    }
}

#[cfg(all(test, feature = "ice"))]
mod tests {
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use sipral_core::auth::KeySource;
    use sipral_nat::ice::CandidateType;

    use super::{ICE_CHARS, IcePolicy, LocalIce, PWD_CHARS, UFRAG_CHARS};

    fn address() -> SocketAddr {
        "192.0.2.7:40000".parse().expect("a literal address")
    }

    fn drawn(seed: u8) -> LocalIce {
        LocalIce::draw(
            &mut KeySource::new([seed; 32]),
            address(),
            None,
            true,
            false,
            Instant::now(),
        )
        .expect("an ordinary address gathers")
    }

    #[test]
    fn the_credentials_a_call_draws_are_the_shape_the_grammar_allows() {
        let ice = drawn(1);
        let ufrag = ice.credentials().ufrag();
        let pwd = ice.credentials().pwd();
        assert_eq!(ufrag.len(), UFRAG_CHARS);
        assert_eq!(pwd.len(), PWD_CHARS);
        // RFC 8839 §5.4 `ice-char`, which `Credentials::new` checks
        for byte in ufrag.bytes().chain(pwd.bytes()) {
            assert!(ICE_CHARS.contains(&byte), "{byte} is not an ice-char");
        }
    }

    #[test]
    fn two_calls_do_not_draw_the_same_password() {
        let one = drawn(1);
        let other = drawn(2);
        assert_ne!(one.credentials().pwd(), other.credentials().pwd());
        assert_ne!(one.credentials().ufrag(), other.credentials().ufrag());
    }

    #[test]
    fn a_rebuilt_agent_gathers_the_candidates_that_were_offered() {
        // the offer's candidates must match what the checking agent believes it owns, foundation
        // and priority included
        let ice = drawn(3);
        let now = Instant::now();
        let rebuilt = ice
            .agent(address(), [9; 32], now)
            .expect("the same address gathers");
        let offered = ice.candidates();
        let held = rebuilt.local_candidates();
        assert_eq!(offered.len(), 1, "one component, one host candidate");
        assert_eq!(offered, held.as_slice());
    }

    #[test]
    fn a_call_given_its_public_address_offers_it_as_a_reflexive_candidate() {
        let public: SocketAddr = "203.0.113.7:41000".parse().expect("a literal address");
        let now = Instant::now();
        let ice = LocalIce::draw(
            &mut KeySource::new([6; 32]),
            address(),
            Some(public),
            true,
            false,
            now,
        )
        .expect("an ordinary address gathers");
        let offered = ice.candidates();
        assert_eq!(offered.len(), 2, "a host candidate and a reflexive one");
        assert_eq!(offered[0].kind, CandidateType::Host);
        assert_eq!(offered[0].address, address());
        assert_eq!(offered[1].kind, CandidateType::ServerReflexive);
        assert_eq!(offered[1].address, public);
        assert_eq!(offered[1].related, Some(address()));
        let rebuilt = ice
            .agent(address(), [9; 32], now)
            .expect("the same address gathers");
        assert_eq!(offered, rebuilt.local_candidates().as_slice());
    }

    #[test]
    fn a_public_address_that_is_the_local_one_adds_no_candidate() {
        let ice = LocalIce::draw(
            &mut KeySource::new([6; 32]),
            address(),
            Some(address()),
            true,
            false,
            Instant::now(),
        )
        .expect("an ordinary address gathers");
        assert_eq!(ice.candidates().len(), 1);
    }

    #[test]
    fn a_lite_end_offers_one_host_candidate_on_the_address_a_peer_reaches() {
        let public: SocketAddr = "203.0.113.7:41000".parse().expect("a literal address");
        // bound to its own address
        let bound = LocalIce::draw(
            &mut KeySource::new([7; 32]),
            address(),
            None,
            false,
            true,
            Instant::now(),
        )
        .expect("an ordinary address gathers");
        assert!(bound.is_lite());
        assert_eq!(bound.candidates().len(), 1);
        assert_eq!(bound.candidates()[0].kind, CandidateType::Host);
        assert_eq!(bound.candidates()[0].address, address());
        // behind a one-to-one NAT the public address is the host candidate, with no reflexive one
        // (RFC 8445 §5.2)
        let forwarded = LocalIce::draw(
            &mut KeySource::new([7; 32]),
            address(),
            Some(public),
            false,
            true,
            Instant::now(),
        )
        .expect("a public address gathers");
        assert_eq!(forwarded.candidates().len(), 1);
        assert_eq!(forwarded.candidates()[0].kind, CandidateType::Host);
        assert_eq!(forwarded.candidates()[0].address, public);
        assert_eq!(forwarded.candidates()[0].related, None);
        // a restart changes only the credentials
        let restarted = forwarded
            .restarted(&mut KeySource::new([8; 32]), None)
            .expect("a restart draws");
        assert_ne!(
            restarted.credentials().ufrag(),
            forwarded.credentials().ufrag()
        );
        assert_ne!(restarted.credentials().pwd(), forwarded.credentials().pwd());
        assert_eq!(restarted.candidates(), forwarded.candidates());
        assert!(restarted.is_lite());
    }

    #[test]
    fn a_lite_end_refuses_an_address_no_peer_could_reach() {
        let loopback = "127.0.0.1:40000".parse().expect("a literal address");
        assert!(
            LocalIce::draw(
                &mut KeySource::new([4; 32]),
                loopback,
                None,
                false,
                true,
                Instant::now(),
            )
            .is_err()
        );
    }

    #[test]
    fn an_address_no_peer_could_reach_is_refused_rather_than_offered() {
        let loopback = "127.0.0.1:40000".parse().expect("a literal address");
        let drawn = LocalIce::draw(
            &mut KeySource::new([4; 32]),
            loopback,
            None,
            true,
            false,
            Instant::now(),
        );
        assert!(
            drawn.is_err(),
            "RFC 8445 §5.1.1.1 rules a loopback address out of a candidate"
        );
    }

    #[test]
    fn a_fresh_agent_has_nothing_to_send_before_it_hears_the_peer() {
        // N4: with no servers nothing is sent before a description arrives
        let ice = drawn(5);
        let now = Instant::now();
        let mut agent = ice
            .agent(address(), [9; 32], now)
            .expect("the same address gathers");
        assert!(agent.take_probe().is_none());
        agent.handle_timeout(now + Duration::from_secs(1));
        assert!(agent.take_probe().is_none());
        assert!(agent.route().is_none(), "and nowhere to send it if it had");
    }

    #[test]
    fn the_default_policy_is_the_one_the_nat_document_tabulates() {
        assert_eq!(IcePolicy::default(), IcePolicy::Off);
        assert!(!IcePolicy::default().offers());
        assert!(!IcePolicy::default().requires());
        assert!(IcePolicy::Offered.offers());
        assert!(!IcePolicy::Offered.requires());
        assert!(IcePolicy::Required.offers());
        assert!(IcePolicy::Required.requires());
    }
}
