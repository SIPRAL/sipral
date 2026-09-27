// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! ICE in the full role, and in the lite role for a headless agent on a
//! public address, joined to a call.
//!
//! `sipral-nat` has RFC 8445's agent — gathering, checklists, pacing,
//! nomination, role conflicts, restarts, keepalives and consent — and until
//! this module nothing reached it. An offer could not carry a candidate, a
//! connectivity check arriving on the media socket was read as a broken RTP
//! packet and thrown away, and the agent's own documentation said so. This is
//! the joint.
//!
//! # What crosses the boundary
//!
//! - **Credentials.** A username fragment and a password per call, drawn from
//!   the media engine's [`KeySource`] and written into every description this
//!   end sends for that call. Not policy and not configuration: RFC 8445 §5.3
//!   wants entropy, and the agent cannot tell a hundred and twenty-eight bits
//!   of it from twenty-two letter *a*s.
//! - **A role and a tiebreaker.** Who nominates, and how a conflict is settled
//!   (RFC 8445 §7.3.1.1). Both are fixed when the call's first description is
//!   written, because [`Role::initial_full`] reads which end offered.
//! - **Candidates.** One host candidate per component, from the address the
//!   application bound, and a server-reflexive one beside it when the call
//!   was given the address that socket appears at from outside — which is
//!   what `Mappings` learns from a STUN server, and what
//!   [`CallMedia::public_address`](crate::CallMedia::public_address) hands a
//!   call. What [`LocalIce`] remembers, so that the second and every later
//!   description of a call says the same thing as the first.
//! - **Transaction ids.** Every check, consent request and keepalive spends
//!   one, and RFC 7675 §5.1 makes consent worth exactly as much as their
//!   unpredictability: an off-path attacker who can guess one can kill a pair
//!   with an unsigned error and never needs the password. They come from a
//!   [`KeySource`] of the call's own, seeded from the engine's.
//!
//! # What this module does not do, and why it is not a gap
//!
//! **The agent asks no server itself.** Its configuration names no STUN and
//! no TURN server, which is what makes gathering finish inside the call that
//! started it: with nothing to wait for, [`IceAgent::gather`] completes before
//! it returns, so an offer is still written in one pass and neither the Rust
//! API nor the C ABI grows a two-phase description. The server-reflexive
//! candidate comes from the mapping the application already made of the same
//! socket before the call, for the `c=` line a peer without ICE reads — the
//! same server, the same question, asked once — and
//! [`IceAgent::add_server_reflexive`] is how that answer becomes a candidate.
//! A relayed candidate comes the same way: the application allocates on its
//! TURN server from the same socket before the call ([`crate::Relays`]), and
//! [`CallMedia::relay`](crate::CallMedia::relay) hands the allocation over.
//! [`IceAgent::add_relayed`] takes it into the agent, which from then on
//! keeps it as one it had gathered itself, and a call that has one keeps the
//! agent it drew rather than rebuilding it — an allocation is live state on
//! a server, not something gathering produces again.
//!
//! **No fallback that is silent.** A peer that does not do ICE, a peer whose
//! candidates are unusable, and a description an ALG rewrote on the way are
//! all the same answer: this call does not use ICE, the agent is dropped, and
//! the stream runs on `c=`/`m=` and symmetric RTP exactly as it did before
//! this module existed. RFC 8445 §2.6 requires it, and without it switching
//! ICE on would turn a working call against an Asterisk with `ice_support=no`
//! — the default — into a call with no audio.
//!
//! # The lite role
//!
//! [`IcePolicy::Lite`] is the other half of `docs/06-nat.md`'s table: a
//! headless agent on a server whose address the world can reach, answering a
//! full-ICE peer — a WebRTC gateway, typically — that will not send media
//! anywhere it has not checked. RFC 8445 Appendix A limits the role to
//! exactly that host, which is why the policy exists only in a build that
//! asks for it: the `ice-lite` feature, or `headless` beside `ice`. The
//! softphone's default build cannot name it, so a softphone behind a NAT
//! cannot advertise it by mistake. `sipral-ffi` turns `ice-lite` on, because
//! the server that wants the role is as often a C, Python or .NET program as
//! a Rust one, and over that ABI `SIPRAL_ICE_LITE` is still a value nothing
//! sets but the application — the socket stays the application's, and
//! nothing of `sipral-headless` comes with it.
//!
//! A lite end writes `a=ice-lite`, its credentials and one host candidate —
//! the address the socket is bound to, or the public address a one-to-one NAT
//! in front of it forwards, which is what most clouds give a server — and
//! then answers checks: authenticated with its short-term credential (a
//! `FINGERPRINT` that does not check out drops the request), signed back with
//! it, `FINGERPRINT` on the answer, and the role rules of RFC 8445 §6.1.1 and
//! §7.3.1.1, under which a lite end facing a full one starts as the
//! controlled side, and leaves it only when a peer claims that role too and
//! this end's tiebreaker is the larger. The pair a check with `USE-CANDIDATE` arrives on is the
//! media path (§7.3.2), reported as [`MediaEvent::PathChosen`] exactly as a
//! full agent's selection is, and nothing leaves before there is one. A
//! consent check (RFC 7675) is an ordinary check to this end, and is
//! answered the same way. A re-offer that changes the peer's credentials is
//! an ICE restart: the answer carries new credentials of this end's own
//! (RFC 8839 §4.4.2.1), and the pair already selected carries the audio, and
//! goes on answering checks under the old ones, until the peer nominates
//! under the new.
//!
//! # Restarts
//!
//! Either end may restart ICE on a call (RFC 8445 §9) by offering new
//! credentials: the peer with a re-offer, this end with
//! [`MediaEngine::restart_ice`]. Both roles answer one with new credentials
//! of their own (RFC 8839 §4.4.2.1), and both follow it only once the
//! exchange is complete, since a re-offer that fails leaves ICE "as if the
//! subsequent offer had never been made" (§4.4). The full agent then flushes
//! its checklist, forms it again from the peer's new description and checks
//! again, on the candidates it still holds, while the pair it had selected
//! goes on carrying the audio until the new session selects one
//! (§4.4.3.1.1).
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
use crate::error::MediaError;

/// What a call does about ICE.
///
/// This lives on [`CodecCatalog`](crate::CodecCatalog) rather than on
/// [`MediaConfig`](crate::MediaConfig) for the reason
/// [`SrtpPolicy`](crate::SrtpPolicy) gives: it decides what goes into an
/// offer, and the catalogue is where the rest of that lives.
///
/// The values describe a posture and not a set of candidate types. A later
/// step that gathers server-reflexive candidates changes what
/// [`IcePolicy::Offered`] puts on the wire without changing what it means,
/// and without spending a number that has already been written into a header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum IcePolicy {
    /// Do not offer it, and do not answer a peer that does.
    ///
    /// The default, and `docs/06-nat.md` argues it at length: ICE costs 143
    /// bytes per candidate in a body that has to fit a datagram, and buys
    /// nothing against a PBX that learns the caller's address from the media
    /// it receives — which is the deployment this stack is aimed at.
    #[default]
    Off,
    /// Offer it, and use it against a peer that offers it back.
    ///
    /// A peer that does not is answered without it and the call runs on
    /// symmetric RTP, which is what makes this safe to turn on against
    /// equipment whose configuration is not ours to change.
    #[cfg(feature = "ice")]
    Offered,
    /// Offer it, and let no stream on this call carry audio without it.
    ///
    /// The mirror of [`SrtpPolicy::Required`](crate::SrtpPolicy::Required):
    /// what a deployment asks for when a call that silently fell back to the
    /// signalled address is worse than no call. A peer that answers without
    /// ICE attributes, or whose description an ALG rewrote, ends the call
    /// with [`MediaError::IceRequired`] rather than carrying audio on a path
    /// nothing checked.
    #[cfg(feature = "ice")]
    Required,
    /// Be an ICE-lite endpoint (RFC 8445 §2.5): write `a=ice-lite` and a host
    /// candidate, answer the connectivity checks a full peer sends, and put
    /// the audio on the pair it nominates.
    ///
    /// Only for a host that is always reachable at the address it advertises
    /// — the socket's own, or [`CallMedia::public_address`] for one behind a
    /// one-to-one NAT — which is the headless agent on a server, and never a
    /// softphone: RFC 8445 Appendix A says ICE "will not function when a lite
    /// implementation is placed behind a NAT", and the peer, told this end is
    /// lite, stops doing the work that would have found another path. So it
    /// exists only with the `ice-lite` feature, or `headless` beside `ice`,
    /// and nothing turns it on but the application asking. A peer that does
    /// no ICE, or is lite itself,
    /// gets the call on `c=`/`m=` and symmetric RTP, as under
    /// [`IcePolicy::Offered`].
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

    /// Whether a call under this policy would rather have no audio than audio
    /// on a path ICE did not check.
    ///
    /// Only the engine's `ice_for` asks, and only where there is an agent to
    /// ask about: without the feature the one value left is `Off`, and a
    /// policy that offers nothing cannot require it either.
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

/// One path a call's ICE agent tried — a candidate pair it checked, or a
/// relay it held — and what became of it: D5's transport and NAT half, the
/// companion of [`CodecCandidate`](crate::CodecCandidate).
///
/// Written down by the agent as each outcome happens, from the transaction
/// that decided it, and never worked out again from what is left: RFC 8445
/// §8.1.2 takes the losing pairs off the checklist the moment a pair is
/// selected, so by the time anyone asks, most of what lost is no longer
/// anywhere else to be read. A restart (RFC 8445 §9) starts the list again
/// with the new session.
#[cfg(feature = "ice")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathCandidate {
    /// A pair or a relay.
    pub kind: PathKind,
    /// For a pair, the local candidate its checks left from: the host
    /// candidate, or the relayed one (a reflexive candidate is paired as its
    /// base, RFC 8445 §6.1.2.4). For a relay, the relayed address, while the
    /// relay has one.
    pub local: Option<SocketAddr>,
    /// What kind of candidate `local` is: [`CandidateKind::Relayed`] for a
    /// relay.
    pub local_kind: CandidateKind,
    /// For a pair, the far end's candidate; for a relay, the TURN server.
    pub remote: SocketAddr,
    /// What kind of candidate `remote` is, when it is one:
    /// [`CandidateKind::PeerReflexive`] for an address the far end's own
    /// checks revealed (RFC 8445 §7.3.1.3). `None` for a relay's server, and
    /// for a lite end's pair, which never learns it.
    pub remote_kind: Option<CandidateKind>,
    /// The pair's priority (RFC 8445 §6.1.2.3), as this end's role computes
    /// it; zero for a relay.
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
    /// The address a NAT maps the host's socket to, as a STUN or TURN
    /// server saw it.
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
    /// The path the call's media takes: the selected pair (RFC 8445
    /// §8.1.2), or the relay it runs through.
    Selected,
    /// A pair whose check succeeded, with nothing selected yet.
    Valid,
    /// Nothing has decided it yet: a pair frozen, waiting its turn or with
    /// its check on the wire; a relay still being allocated.
    Waiting,
    /// A pair whose check succeeded, and a pair of higher priority was
    /// selected over it.
    Outranked,
    /// A pair another was nominated ahead of: its check had not finished
    /// when the selection took it off the checklist (RFC 8445 §8.1.2), or it
    /// succeeded after a nomination of lower priority was already made.
    NominatedElsewhere,
    /// A pair whose check was never answered (RFC 8489 §6.2.1).
    TimedOut,
    /// A pair the far end refused, with this STUN error code (RFC 8445
    /// §7.2.5.2.4).
    Refused(u16),
    /// A pair whose answer came from an address other than the one the check
    /// went to (RFC 8445 §7.2.5.2.1) — a NAT in between rewriting it.
    NotSymmetric,
    /// A pair whose answer named no address to form a valid pair from.
    Unusable,
    /// A relayed pair the relay would not let the far end's address through
    /// for, or a relay whose allocation the server refused, with why (RFC
    /// 8656 §9, §7.3).
    RelayRefused(crate::TurnFailure),
    /// A pair never checked: the pair limit discarded it (RFC 8445
    /// §6.1.2.5), or its checklist ended before its turn came.
    NotChecked,
    /// A relay held, that no selected pair runs through — or none yet.
    Held,
    /// A relay given back: ICE concluded on a pair that does not use it
    /// (RFC 8445 §8.3.1), or this branch of a forked call let go of it.
    Released,
    /// A relay the server took back, with why: a refresh it refused or never
    /// answered (RFC 8656 §8).
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

/// How many `ice-char`s a username fragment this stack draws is long.
///
/// Eight, which is forty-eight bits: RFC 8445 §5.3 asks for "at least 24 bits
/// of output to generate the username fragment", and RFC 8839 §5.4 allows
/// four to thirty-two.
#[cfg(feature = "ice")]
const UFRAG_CHARS: usize = 8;

/// How many `ice-char`s a password this stack draws is long.
///
/// Twenty-four, which is a hundred and forty-four bits: §5.3 asks for "at
/// least 128 bits of random number generator output used to generate the
/// password", and §5.4 allows twenty-two to two hundred and fifty-six.
#[cfg(feature = "ice")]
const PWD_CHARS: usize = 24;

/// The `ice-char` alphabet of RFC 8839 §5.4's grammar, in sixty-four
/// characters, so that six bits of a draw map onto one of them without a
/// modulus and therefore without a bias.
#[cfg(feature = "ice")]
const ICE_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// There is no agent in this build, so there is nothing for a call to settle
/// and no attribute to write.
///
/// The type exists all the same, so that the engine's description writers
/// have one shape rather than two: `Option<LocalIce>` is always `None` here,
/// and the arm that would write something is never reached.
#[cfg(not(feature = "ice"))]
#[derive(Clone, Debug)]
pub(crate) struct LocalIce;

/// What one call has settled about ICE, and goes on saying.
///
/// Kept beside the call's other negotiated state rather than inside the
/// running agent, because RFC 8839 §4.4.1.1.1 wants the credentials and the
/// candidates on *every* description of the session and not only on the first
/// one: a hold re-offer that left them out is a peer reading that ICE has
/// been withdrawn in the middle of a call.
///
/// Cheap to hold and cheap to clone — the password's `Debug` redacts itself,
/// which is why this can derive one.
#[cfg(feature = "ice")]
#[derive(Clone, Debug)]
pub(crate) struct LocalIce {
    credentials: Credentials,
    role: Role,
    tiebreaker: u64,
    /// The address the socket appears at from outside, when the call was
    /// given one: its server-reflexive candidate, kept so that the agent
    /// rebuilt at [`LocalIce::agent`] holds it too. For a lite end it is the
    /// host candidate instead, a one-to-one NAT's public address.
    public: Option<SocketAddr>,
    candidates: Vec<Candidate>,
    /// Whether this end is the lite implementation ([`IcePolicy::Lite`]).
    lite: bool,
}

#[cfg(feature = "ice")]
impl LocalIce {
    /// Draw a call's credentials and tiebreaker, and gather its candidates.
    ///
    /// `we_are_offerer` fixes the role RFC 8445 §6.1.1 gives this end. A peer
    /// that turns out to be lite moves it, and the agent does that itself
    /// inside [`IceAgent::set_remote`].
    ///
    /// `public` is where `address` appears from outside, when the call was
    /// given one: a server-reflexive candidate beside the host one, and the
    /// default candidate RFC 8839 §4.2.1.2 wants in `c=` and `m=`.
    ///
    /// `lite` draws for [`IcePolicy::Lite`]: the role is the controlled one
    /// (§6.1.1 gives a lite end no other against a full peer), and the one
    /// candidate is a host candidate for `public` when there is one and for
    /// `address` when there is not. On a server behind a one-to-one NAT the
    /// public address *is* the host's address as far as any peer is
    /// concerned — the NAT forwards it unchanged, which is what makes the
    /// host fit for the role at all — and a lite end has no reflexive
    /// candidate to put it in (RFC 8445 §5.2 gives it host candidates only).
    ///
    /// # Errors
    ///
    /// [`MediaError::Ice`] when the address the application bound is one RFC
    /// 8445 §5.1.1.1 rules out — a loopback or a link-local address offered
    /// as a candidate is a candidate no peer can reach.
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
            // the same gathering, and so the same §5.1.1.1 refusals, as the
            // full role's, on the one address a peer is to reach; nothing
            // else of that agent is kept
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
        // a peer that is lite is not known until its description arrives, and
        // the agent moves the role itself when it is
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

    /// Draw a call's credentials and tiebreaker in the full role, as
    /// [`LocalIce::draw`] does, and gather its candidates with the relayed
    /// one `relay` stands for beside the host and server-reflexive ones.
    ///
    /// The agent that gathered them is handed back with them and is the one
    /// the call runs: the allocation inside it is live state on a server,
    /// and [`LocalIce::agent`] cannot make another one out of what was
    /// written down.
    ///
    /// # Errors
    ///
    /// As [`LocalIce::draw`], and [`MediaError::Ice`] for a relay of an
    /// address family other than `address`'s, which the engine does not hand
    /// in.
    ///
    /// `relay` is taken out of its slot only once the agent it goes into has
    /// been gathered, so a refusal of `address` leaves it where it was, for
    /// the caller to hand back; `None` when the slot was empty.
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

    /// The agent a branch of a forked call runs: [`LocalIce::agent`], holding
    /// the allocation the fork's one offer named beside every other branch's
    /// agent ([`IceAgent::add_shared_relay`]).
    ///
    /// Every branch was offered the one description, so the agent comes out
    /// holding what that description named: the host and server-reflexive
    /// candidates gathered in the same order, and the relayed one on the same
    /// allocation, at the same address. RFC 8839 §7 runs each answer as "an
    /// independent offer/answer exchange, with its own set of local
    /// candidates, pairs, checklists, states", and RFC 8656 §2 lets one
    /// relayed address serve "multiple peers" for exactly this: the agent
    /// asks the relay to let its own branch's peer through, checks its own
    /// pairs, and lets go of the allocation — which goes back to the server
    /// only when no branch holds it any more — when its branch ends or ICE
    /// concludes on a pair that does not use it (RFC 8445 §8.3.1).
    ///
    /// `None` when the allocation is already gone, or is of another address
    /// family: the branch runs on the rest of the candidates.
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

    /// The same call's ICE after an ICE restart (RFC 8445 §9), whichever end
    /// asked for it: new credentials of this end's own — RFC 8839 §4.4.1.1.1
    /// has an offerer that restarts "change both the "ice-pwd" and the
    /// "ice-ufrag"", and §4.4.2.1 asks the same of an answerer that accepts
    /// one — and the role and tiebreaker as they were, since §9 flushes
    /// everything "excluding the roles of the agents".
    ///
    /// The candidates are `running`'s when the call runs a full agent: the
    /// ones it still holds, which is what §4.4.1.1.1's "some, none, or all
    /// of the previous candidates" comes to for an agent that asks no server
    /// itself — the host and server-reflexive candidates it gathered, and the
    /// relayed one unless ICE gave the allocation back when it concluded on
    /// another pair. `None` keeps the ones written before, which is all a
    /// lite end has: it "MUST NOT add additional host candidates in a
    /// subsequent offer" (§4.4.1.3), and has no other kind to add.
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

    /// Whether `description` names these credentials on its stream: the one
    /// this end wrote with them, as a session change hands it back once the
    /// far end has accepted it.
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
        // six bits index sixty-four characters, so `get` cannot answer
        // `None`; it is written rather than indexed because a panic while
        // a call is being described is worse than any credential
        .map(|byte| {
            ICE_CHARS
                .get(usize::from(byte & 0x3F))
                .copied()
                .unwrap_or(b'A')
        })
        .collect();
    let (ufrag, pwd) = chars.split_at(UFRAG_CHARS);
    // both halves are `ice-char`s by construction, so the only way
    // `Credentials::new` refuses them is a length this file got wrong
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

    /// Whether `data` is a connectivity check the far end sent this call: a
    /// Binding request whose `USERNAME` is this call's fragment, a colon and
    /// one of the far end's (RFC 8445 §7.2.2), signed with this call's
    /// password (RFC 8445 §7.2.2, RFC 8489 §9.1).
    ///
    /// What lets a check be kept for the call before the agent that answers
    /// it exists: nobody who has not read this call's description can make
    /// one, so nobody else can fill what keeps them. The agent authenticates
    /// it again when it gets it, with everything else it checks.
    pub(crate) fn is_check_for(&self, data: &[u8]) -> bool {
        signed_for(data, &self.credentials)
    }

    /// The agent this call runs, built from what was written down.
    ///
    /// Built here rather than kept alive from [`LocalIce::draw`] because
    /// gathering is deterministic: the same address, the same components, the
    /// same public address and no server to ask produce the same candidates
    /// with the same foundations and the same priorities, every time.
    /// `a_rebuilt_agent_gathers_the_candidates_that_were_offered` is what
    /// holds that true.
    ///
    /// `seed` is what the call's own transaction ids are drawn from, and it
    /// comes from the engine's [`KeySource`] rather than from the session's
    /// own `Draws`: that one is a seeded integer mixer for jitter and
    /// scheduling, and RFC 7675 §5.1 makes an id an attacker can guess the
    /// whole of consent.
    ///
    /// # Errors
    ///
    /// As [`LocalIce::draw`].
    ///
    /// A lite end is built from the credentials alone: it has no checklist to
    /// rebuild, sends nothing of its own, and so spends no transaction id.
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

/// One agent on one stream with one component, gathered, with the
/// server-reflexive candidate `public` names when there is one.
#[cfg(feature = "ice")]
fn new_agent(
    credentials: &Credentials,
    role: Role,
    tiebreaker: u64,
    address: SocketAddr,
    public: Option<SocketAddr>,
    now: Instant,
) -> Result<(IceAgent, StreamId), MediaError> {
    // no STUN and no TURN server, which is what makes `gather` below finish
    // before it returns
    let mut agent = IceAgent::new(IceConfig::default(), credentials.clone(), role, tiebreaker)
        .map_err(MediaError::Ice)?;
    // one component, because `IcePolicy::offers` forces `rtcp-mux` on: a
    // second component would need a second address, and this facade knows one
    let stream = agent
        .add_stream(&[(ComponentId::RTP, address)])
        .map_err(MediaError::Ice)?;
    agent.gather(now).map_err(MediaError::Ice)?;
    // no server is named: the call was handed the address, and which server
    // the application asked is not something it carries. Every call has at
    // most one reflexive candidate, so the foundation it would have told
    // apart from a second one has nothing to tell apart
    if let Some(public) = public {
        agent
            .add_server_reflexive(stream, ComponentId::RTP, address, public, None)
            .map_err(MediaError::Ice)?;
    }
    Ok((agent, stream))
}

/// A gathered agent with the allocation in `relay` taken into it as its
/// relayed candidate, running on transaction ids drawn from `keys`; `None`
/// when the slot was empty.
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
    agent
        .add_relayed(stream, ComponentId::RTP, address, server, client, now)
        .map_err(MediaError::Ice)?;
    let mut ice = Ice {
        local: address,
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

/// The running agent, on the media session that owns the socket.
///
/// It is not `Clone` and not `Debug`: it holds the peer's password, and the
/// one thing a running checklist must never do is appear in a log.
#[cfg(feature = "ice")]
pub(crate) struct Ice {
    /// The socket the application bound for this call, which is what every
    /// datagram handed to the agent arrived on.
    local: SocketAddr,
    /// Where application data goes once it is ready for the pair, held rather
    /// than allocated per frame. With a relayed pair it is the frame with the
    /// channel header in front of it; without one it is the frame.
    out: Vec<u8>,
    /// The agent's own datagram — a check, a consent request, a keepalive, a
    /// lite end's answer to a check — held for as long as the caller borrows
    /// it.
    probe: Vec<u8>,
    running: Running,
}

/// Which of the two roles this call plays.
#[cfg(feature = "ice")]
enum Running {
    // both boxed: the two are hundreds of bytes apart, and a session that is
    // not using ICE — most of them — holds neither
    Full(Box<Full>),
    Lite(Box<Lite>),
}

/// The full role: RFC 8445's whole agent.
#[cfg(feature = "ice")]
struct Full {
    agent: IceAgent,
    /// The one stream this call has. `add_stream` names it, and nothing here
    /// ever adds a second: one audio stream per call is what the facade
    /// describes, and `write_answer` says why.
    stream: StreamId,
    /// Where this call's transaction ids come from: a stream of its own,
    /// seeded from the engine's, so that a session can keep the agent's pool
    /// full on the media thread without reaching the engine for every id.
    keys: KeySource,
}

/// The lite role: a STUN server on the media socket and the pair the peer
/// nominated, and nothing else — no checklist, no timer, no transaction id.
#[cfg(feature = "ice")]
struct Lite {
    agent: LiteAgent,
    /// The host candidate this end advertised: the socket's address, or the
    /// public one a one-to-one NAT forwards to it.
    advertised: SocketAddr,
    /// Answers to checks, each to the address its check came from, held to
    /// [`TRANSMIT_CEILING`], and a stranger's refusals to
    /// [`REFUSAL_CEILING`], exactly as the full agent holds its own.
    outbox: VecDeque<(SocketAddr, Vec<u8>)>,
    /// Answers the ceiling kept out of `outbox`.
    dropped: u64,
    /// The pair the peer nominated, as the media path.
    selected: Option<SelectedPair>,
    /// A nomination the session has not been told about yet.
    news: Option<SelectedPair>,
    /// The credentials of a restart this end offered and has not taken up.
    pending: Option<Credentials>,
    /// Checks signed with them, each with where it came from and when, kept
    /// until the restart is taken up: the newest [`AWAITING`].
    awaiting: VecDeque<(SocketAddr, Vec<u8>, Instant)>,
}

/// How many checks signed for an offered restart a lite end keeps, as many
/// as the full agent keeps.
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
    /// Nothing may be sent on this call's path any more: consent was lost or
    /// the checks failed.
    Lost,
}

#[cfg(feature = "ice")]
impl Ice {
    /// Give the agent what the peer said, and say whether ICE is on.
    ///
    /// A lite end has nothing to do with it: it signs every answer with its
    /// own password and checks nothing of its own.
    ///
    /// # Errors
    ///
    /// [`MediaError::Ice`] for credentials outside RFC 8839 §5.4's shape, or
    /// for a peer whose credentials changed without a restart.
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

    /// Take up the credentials a restart gave this call, when they are not
    /// the ones the running agent holds, and the peer's side of the same
    /// exchange, `remote`.
    ///
    /// Reached once the exchange that restarted is complete, whichever end
    /// offered it: the answer this end sent accepting the peer's restart, or
    /// the peer's answer to one this end offered. Not before — "Should a
    /// subsequent offer fail, ICE processing continues as if the subsequent
    /// offer had never been made" (RFC 8839 §4.4) — and from here on the
    /// peer's checks are signed with `local`'s new password.
    ///
    /// The full agent restarts (RFC 8445 §9): its checklist and valid list
    /// are flushed and formed again from `remote`'s candidates, the checks
    /// run again, and the pair it had selected goes on carrying the audio,
    /// and on answering and sending consent checks under the old
    /// credentials, until the new session selects one (RFC 8839
    /// §4.4.3.1.1, RFC 7675 §5.1). The role stays what it was. A lite end
    /// takes the new credentials and keeps its pair until the peer nominates
    /// under them.
    ///
    /// # Errors
    ///
    /// [`MediaError::Ice`] for peer credentials outside RFC 8839 §5.4's
    /// shape. The previous pair still carries the audio then, for as long as
    /// its consent lasts.
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
                    // the checks kept for these credentials are answered
                    // now; any kept for others were for another offer
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

    /// Top the agent's pool of transaction ids up from a cryptographic
    /// source.
    ///
    /// Called immediately before everything that can move the agent. An empty
    /// pool is not an error and does not stall quietly: it puts
    /// [`IceAgent::deadline`] in the past, so a caller polling deadlines spins
    /// while consent runs out on a call that was working. The only way not to
    /// have that happen is to keep the pool full.
    pub(crate) fn top_up(&mut self) {
        let Running::Full(full) = &mut self.running else {
            return;
        };
        let mut wanted = full.agent.transaction_ids_wanted();
        while wanted > 0 {
            // a block is thirty-two bytes and an id is twelve, so two ids come
            // out of each one and the last eight bytes are not stretched into
            // a third
            let block = full.keys.block();
            for chunk in block.chunks_exact(12).take(wanted.min(2)) {
                let mut id = [0_u8; 12];
                id.copy_from_slice(chunk);
                full.agent.supply_transaction_id(TransactionId::new(id));
                wanted -= 1;
            }
        }
    }

    /// Hand in a datagram that arrived on the media socket.
    ///
    /// A lite end answers a check and reads nothing else: anything that is
    /// not STUN is application data, from wherever it came, exactly as the
    /// full agent treats it — receiving is allowed on any candidate (RFC 8445
    /// §12.2), and the session's own latch follows the pair once one is
    /// nominated.
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
                // signed for a restart this end offered and has not taken
                // up: kept for then, rather than refused as a stranger's
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
    /// Answer a check the way RFC 8445 §7.3 has a lite end answer every
    /// check, and take a nomination as the media path.
    fn answer(&mut self, local: SocketAddr, from: SocketAddr, data: &[u8]) {
        if let Some(answer) = self
            .agent
            .answer_binding_request(ComponentId::RTP, local, from, data)
        {
            // every check is answered, a stranger's unsigned one included, so
            // the ceiling is what keeps a flood the application is slow to
            // drain out of memory. The answer being queued gives way, as the
            // full agent's does: to the peer it is a lost datagram, and it
            // checks again. A stranger's refusals stop at half of it, so the
            // peer's nomination and consent checks still find room
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
                // a lite end never learns what kind of candidate the peer
                // checked from; the address is what the path is
                remote_kind: CandidateType::Host,
            };
            if self.selected.map(|held| held.remote) != Some(chosen.remote) {
                self.selected = Some(chosen);
                self.news = Some(chosen);
            }
        }
    }

    /// Answer the checks kept for the restart just taken up; one older than
    /// the peer's whole transaction for it (RFC 8489 §6.2.1's 39.5 seconds)
    /// has nobody waiting for the answer.
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

/// Whether `data` is a Binding request signed with `credentials`: its
/// USERNAME starts with their fragment and a colon, and its
/// MESSAGE-INTEGRITY checks out under their password (RFC 8445 §7.2.2).
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
    /// Take the passing of time. A lite end has no timer.
    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        if let Running::Full(full) = &mut self.running {
            full.agent.handle_timeout(now);
        }
    }

    /// When the agent next has something to do: never, for a lite end, which
    /// only ever answers.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        match &self.running {
            Running::Full(full) => full.agent.deadline(),
            Running::Lite(_) => None,
        }
    }

    /// Take the agent's own next datagram, and say where it goes.
    ///
    /// The bytes stay here, in [`Ice::probe`], and are read back with
    /// [`Ice::probe`]. Two calls rather than one because the caller is a
    /// method that hands out a borrow of the session: an address is `Copy`
    /// and ends the mutable borrow, where a borrow of the bytes would hold it
    /// open for as long as the datagram lives.
    pub(crate) fn take_probe(&mut self) -> Option<SocketAddr> {
        let (destination, data) = match &mut self.running {
            Running::Full(full) => {
                let Transmit {
                    destination, data, ..
                } = full.agent.poll_transmit()?;
                (destination, data)
            }
            Running::Lite(lite) => lite.outbox.pop_front()?,
        };
        self.probe = data;
        Some(destination)
    }

    /// The bytes [`Ice::take_probe`] last took.
    pub(crate) fn probe(&self) -> &[u8] {
        &self.probe
    }

    /// How many of the agent's own datagrams were dropped because
    /// [`TRANSMIT_CEILING`] of them were already waiting for
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
                    // RFC 7675 §5: nothing more may be sent on that pair, and
                    // the same credentials may not be used on it again
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

    /// Where a datagram for this stream would go, without sending one.
    ///
    /// The precondition every producer on the media path asks first. A
    /// producer that borrows one of the session's own buffers cannot find out
    /// by trying: by then it has built a frame it would have to throw away,
    /// or taken a handshake record out of a flight it cannot put back.
    pub(crate) fn route(&self) -> Option<Route> {
        match &self.running {
            Running::Full(full) => full.agent.route(full.stream, ComponentId::RTP).ok(),
            Running::Lite(lite) => lite.selected.map(|pair| Route {
                source: self.local,
                destination: pair.remote,
            }),
        }
    }

    /// Wrap a datagram for the pair the agent picked and say where it goes.
    ///
    /// # Errors
    ///
    /// [`SendError`] when there is no pair to send on, consent is gone, or a
    /// relay refused the data. A lite end has only the first of the three:
    /// until the peer nominates a pair there is nowhere it may send (RFC 8445
    /// §12.1), and a lite end has no consent of its own to lose.
    pub(crate) fn send(
        &mut self,
        data: &[u8],
        now: Instant,
    ) -> Result<(SocketAddr, &[u8]), SendError> {
        self.out.clear();
        let destination = match &mut self.running {
            Running::Full(full) => {
                full.agent
                    .send(full.stream, ComponentId::RTP, data, &mut self.out, now)?
                    .destination
            }
            Running::Lite(lite) => {
                let pair = lite.selected.ok_or(SendError::NoRoute)?;
                self.out.extend_from_slice(data);
                pair.remote
            }
        };
        Ok((destination, &self.out))
    }

    /// Give every relay this call holds back to its server, and hand over
    /// what that takes to send: the Refresh with a lifetime of zero RFC 8656
    /// §8 deletes an allocation with, each with where it goes.
    ///
    /// For the end of a call, and for a call that turned out not to use ICE
    /// at all. Anything else the agent still had queued goes with them — it
    /// was going to the same places from the same socket — and nothing waits
    /// for an answer. A lite end holds no relay and has nothing to give back.
    pub(crate) fn release(&mut self, now: Instant) -> Vec<(SocketAddr, Vec<u8>)> {
        self.top_up();
        let Running::Full(full) = &mut self.running else {
            return Vec::new();
        };
        full.agent.release_relays(now);
        let mut out = Vec::new();
        while let Some(Transmit {
            destination, data, ..
        }) = full.agent.poll_transmit()
        {
            out.push((destination, data));
        }
        out
    }

    /// The relays this agent holds, whole and still live on their servers,
    /// for an agent that will never run: its description was refused before
    /// it left. A lite end holds none.
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

    /// The candidates this agent still holds for its stream: what it
    /// gathered, less a relay ICE gave back when it concluded on another
    /// pair (RFC 8445 §8.3.1). `None` for a lite end, which gathered nothing
    /// of its own.
    ///
    /// What goes into a description comes from [`LocalIce::candidates`],
    /// which is what makes the second and every later description of a call
    /// say what the first one did. This is asked only when a restart writes
    /// a new set ([`LocalIce::restarted`]), since a candidate the agent no
    /// longer holds is one the peer's checks would go to for nothing.
    pub(crate) fn gathered(&self) -> Option<Vec<Candidate>> {
        match &self.running {
            Running::Full(full) => Some(full.agent.local_candidates(full.stream)),
            Running::Lite(_) => None,
        }
    }

    /// The allocation this agent holds, as a handle the agents of the other
    /// branches of a fork can take up ([`LocalIce::shared_agent`]); `None`
    /// for one that holds none, or has let go of it.
    pub(crate) fn shared_relay(&self) -> Option<SharedRelay> {
        match &self.running {
            Running::Full(full) => full.agent.shared_relays().into_iter().next(),
            Running::Lite(_) => None,
        }
    }

    /// Whose a datagram that arrived on this call's socket is, when the
    /// branches of a forked call share the socket: see
    /// [`IceAgent::claims`]. A lite end knows its peer only by the pair it
    /// nominated, and claims what comes from there.
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

    /// Say which credentials a restart this end has offered, or answered,
    /// carries — or, with `None`, that it will not happen — so that the
    /// peer's checks under them, which can arrive before the exchange is
    /// complete, are kept for the moment the restart is taken up
    /// ([`Ice::follow`]) rather than refused. See
    /// [`IceAgent::expect_restart`].
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

    /// Every candidate pair this call's agent formed and every relay it held,
    /// and what became of each (D5, the path's half). A lite end checks
    /// nothing and holds no relay, and has only the pair its peer nominated
    /// to report.
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

    /// [`Ice::gathered`], empty for a lite end, for the tests that compare it
    /// with what was offered.
    #[cfg(test)]
    pub(crate) fn local_candidates(&self) -> Vec<Candidate> {
        self.gathered().unwrap_or_default()
    }
}

/// Written by hand, because a derived one would print the peer's password.
///
/// The agent holds the credentials the far end published, read off the wire
/// in its description, and `KeySource` beside it is where this call's
/// transaction ids come from — RFC 7675 §5.1 makes those as good as the
/// consent they carry. Neither belongs in a `{:?}` of a running call, and
/// `MediaSession` derives its own `Debug`, so without this they would both be
/// in one.
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
        // RFC 8839 §5.4's `ice-char`, which is what `Credentials::new` checks
        // and what this end has to keep producing for it to go on passing
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
        // the whole reason `LocalIce` may keep candidates rather than an
        // agent: what was written into the offer has to be what the agent
        // checking pairs believes it owns, foundation and priority included
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
        // and the agent that runs the checks believes it owns the same two
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
        // bound to its own address: that is the candidate
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
        // behind a one-to-one NAT: the public address is the host candidate,
        // and there is no reflexive one beside it (RFC 8445 §5.2)
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
        // and a restart changes the credentials and nothing else
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
        // N4's claim, which the whole placement of the agent rests on: with
        // no STUN and no TURN server there is nothing to gather from, so
        // nothing leaves this end until a description arrives
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
