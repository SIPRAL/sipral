// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! ICE in the full role, joined to a call.
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
//! TURN is the step after this one, and `docs/06-nat.md` says why it waits.
//!
//! **No fallback that is silent.** A peer that does not do ICE, a peer whose
//! candidates are unusable, and a description an ALG rewrote on the way are
//! all the same answer: this call does not use ICE, the agent is dropped, and
//! the stream runs on `c=`/`m=` and symmetric RTP exactly as it did before
//! this module existed. RFC 8445 §2.6 requires it, and without it switching
//! ICE on would turn a working call against an Asterisk with `ice_support=no`
//! — the default — into a call with no audio.

#[cfg(feature = "ice")]
use std::net::SocketAddr;
#[cfg(feature = "ice")]
use std::time::Instant;

#[cfg(feature = "ice")]
use sipral_core::auth::KeySource;
#[cfg(feature = "ice")]
use sipral_nat::ice::{
    Candidate, ComponentId, Credentials, IceAgent, IceConfig, IceEvent, RemoteIce, Role, Route,
    SelectedPair, SendError, StreamId, Transmit,
};
#[cfg(feature = "ice")]
use sipral_nat::stun::TransactionId;

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
}

impl IcePolicy {
    /// Whether a description written under this policy carries ICE at all.
    #[must_use]
    pub(crate) const fn offers(self) -> bool {
        match self {
            Self::Off => false,
            #[cfg(feature = "ice")]
            Self::Offered | Self::Required => true,
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
            Self::Off => false,
        }
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
    /// rebuilt at [`LocalIce::agent`] holds it too.
    public: Option<SocketAddr>,
    candidates: Vec<Candidate>,
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
        now: Instant,
    ) -> Result<Self, MediaError> {
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
        let credentials = Credentials::new(
            core::str::from_utf8(ufrag).unwrap_or_default(),
            core::str::from_utf8(pwd).unwrap_or_default(),
        )
        .map_err(MediaError::Ice)?;
        let tiebreaker = u64::from_be_bytes(keys.block()[..8].try_into().unwrap_or([0; 8]));
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
        })
    }

    /// The credentials to write into a description.
    pub(crate) const fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// The candidates to write into a description.
    pub(crate) fn candidates(&self) -> &[Candidate] {
        &self.candidates
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
    pub(crate) fn agent(
        &self,
        address: SocketAddr,
        seed: [u8; 32],
        now: Instant,
    ) -> Result<Ice, MediaError> {
        let (agent, stream) = new_agent(
            &self.credentials,
            self.role,
            self.tiebreaker,
            address,
            self.public,
            now,
        )?;
        let mut ice = Ice {
            agent,
            stream,
            local: address,
            keys: KeySource::new(seed),
            out: Vec::new(),
            probe: Vec::new(),
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

/// The running agent, on the media session that owns the socket.
///
/// It is not `Clone` and not `Debug`: it holds the peer's password, and the
/// one thing a running checklist must never do is appear in a log.
#[cfg(feature = "ice")]
pub(crate) struct Ice {
    agent: IceAgent,
    /// The one stream this call has. `add_stream` names it, and nothing here
    /// ever adds a second: one audio stream per call is what the facade
    /// describes, and `write_answer` says why.
    stream: StreamId,
    /// The socket the application bound for this call, which is what every
    /// datagram handed to the agent arrived on.
    local: SocketAddr,
    /// Where this call's transaction ids come from: a stream of its own,
    /// seeded from the engine's, so that a session can keep the agent's pool
    /// full on the media thread without reaching the engine for every id.
    keys: KeySource,
    /// Where [`IceAgent::send`] puts application data, held rather than
    /// allocated per frame. With a relayed pair it is the frame with the
    /// channel header in front of it; without one it is the frame.
    out: Vec<u8>,
    /// The agent's own datagram — a check, a consent request, a keepalive —
    /// held for as long as the caller borrows it.
    probe: Vec<u8>,
}

#[cfg(feature = "ice")]
impl Ice {
    /// Give the agent what the peer said, and say whether ICE is on.
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
        self.agent
            .set_remote(self.stream, remote, now)
            .map_err(MediaError::Ice)
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
        let mut wanted = self.agent.transaction_ids_wanted();
        while wanted > 0 {
            // a block is thirty-two bytes and an id is twelve, so two ids come
            // out of each one and the last eight bytes are not stretched into
            // a third
            let block = self.keys.block();
            for chunk in block.chunks_exact(12).take(wanted.min(2)) {
                let mut id = [0_u8; 12];
                id.copy_from_slice(chunk);
                self.agent.supply_transaction_id(TransactionId::new(id));
                wanted -= 1;
            }
        }
    }

    /// Hand in a datagram that arrived on the media socket.
    pub(crate) fn handle_datagram(
        &mut self,
        from: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> sipral_nat::ice::Received {
        self.agent.handle_datagram(self.local, from, data, now)
    }

    /// Take the passing of time.
    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        self.agent.handle_timeout(now);
    }

    /// When the agent next has something to do.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.agent.deadline()
    }

    /// Take the agent's own next datagram, and say where it goes.
    ///
    /// The bytes stay here, in [`Ice::probe`], and are read back with
    /// [`Ice::probe`]. Two calls rather than one because the caller is a
    /// method that hands out a borrow of the session: an address is `Copy`
    /// and ends the mutable borrow, where a borrow of the bytes would hold it
    /// open for as long as the datagram lives.
    pub(crate) fn take_probe(&mut self) -> Option<SocketAddr> {
        let Transmit {
            destination, data, ..
        } = self.agent.poll_transmit()?;
        self.probe = data;
        Some(destination)
    }

    /// The bytes [`Ice::take_probe`] last took.
    pub(crate) fn probe(&self) -> &[u8] {
        &self.probe
    }

    /// The agent's next event.
    pub(crate) fn poll_event(&mut self) -> Option<IceEvent> {
        self.agent.poll_event()
    }

    /// Where a datagram for this stream would go, without sending one.
    ///
    /// The precondition every producer on the media path asks first. A
    /// producer that borrows one of the session's own buffers cannot find out
    /// by trying: by then it has built a frame it would have to throw away,
    /// or taken a handshake record out of a flight it cannot put back.
    pub(crate) fn route(&self) -> Option<Route> {
        self.agent.route(self.stream, ComponentId::RTP).ok()
    }

    /// Wrap a datagram for the pair the agent picked and say where it goes.
    ///
    /// # Errors
    ///
    /// [`SendError`] when there is no pair to send on, consent is gone, or a
    /// relay refused the data.
    pub(crate) fn send(
        &mut self,
        data: &[u8],
        now: Instant,
    ) -> Result<(SocketAddr, &[u8]), SendError> {
        self.out.clear();
        let route = self
            .agent
            .send(self.stream, ComponentId::RTP, data, &mut self.out, now)?;
        Ok((route.destination, &self.out))
    }

    /// The pair the agent selected, once it has one.
    pub(crate) fn selected_pair(&self) -> Option<SelectedPair> {
        self.agent.selected_pair(self.stream, ComponentId::RTP)
    }

    /// The candidates this agent will advertise for its stream.
    ///
    /// Only a test asks: what goes into a description comes from
    /// [`LocalIce::candidates`], which is what makes the second and every
    /// later description of a call say what the first one did. This is how
    /// that equality is checked.
    #[cfg(test)]
    pub(crate) fn local_candidates(&self) -> Vec<Candidate> {
        self.agent.local_candidates(self.stream)
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
        f.debug_struct("Ice")
            .field("local", &self.local)
            .field("state", &self.agent.state())
            .finish_non_exhaustive()
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
            Instant::now(),
        )
        .expect("an ordinary address gathers");
        assert_eq!(ice.candidates().len(), 1);
    }

    #[test]
    fn an_address_no_peer_could_reach_is_refused_rather_than_offered() {
        let loopback = "127.0.0.1:40000".parse().expect("a literal address");
        let drawn = LocalIce::draw(
            &mut KeySource::new([4; 32]),
            loopback,
            None,
            true,
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
