// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The lite agent: a STUN server that never checks anything itself
//! (RFC 8445 §7.3, §7.3.2, §2.5).
//!
//! A full agent runs a state machine per candidate pair, sends its own
//! Binding requests and decides which pair wins. A lite agent does none of
//! that: it answers whatever request lands on its socket, and if that request
//! carries USE-CANDIDATE, it believes the pair the request arrived on. That is
//! the entire algorithm, which is the point of the role.

use std::net::SocketAddr;

use super::candidate::ComponentId;
use super::server::{self, Verdict};
use crate::stun::{Message, error_code};

/// Which side nominates. RFC 8445 §4: "The controlling agent is responsible
/// for the choice of the final candidate pairs".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// This agent picks the pair and tells the peer with USE-CANDIDATE.
    /// Reachable for a lite agent only as the initial role against a peer
    /// this session believes is lite too (§6.1.1); it is never the outcome
    /// of answering a Binding request; a full peer is always controlling
    /// (§6.1.1), so that answering side never lets a role-conflict message
    /// move this agent into it (see [`super::server::resolve_role`]).
    Controlling,
    /// This agent waits for a nomination and accepts it.
    Controlled,
}

impl Role {
    /// The role before any request has been seen, from what the candidate
    /// exchange said about the peer (RFC 8445 §6.1.1).
    ///
    /// A full peer is always controlling, offerer or not. Between two lite
    /// agents, the offerer is controlling — this agent never gathers beyond
    /// host candidates, so it cannot itself be the reason ICE fails, but it
    /// still has to know which side it plays.
    #[must_use]
    pub const fn initial(we_are_offerer: bool, peer_is_lite: bool) -> Self {
        if peer_is_lite && we_are_offerer {
            Self::Controlling
        } else {
            Self::Controlled
        }
    }

    /// The role a full agent starts in (RFC 8445 §6.1.1).
    ///
    /// Between two full agents "the initiating agent that started the ICE
    /// processing MUST take the controlling role"; against a lite peer "the
    /// full agent MUST take the controlling role" whichever side offered.
    #[must_use]
    pub const fn initial_full(we_are_offerer: bool, peer_is_lite: bool) -> Self {
        if we_are_offerer || peer_is_lite {
            Self::Controlling
        } else {
            Self::Controlled
        }
    }
}

/// A candidate pair this agent has accepted for one component (RFC 8445 §4,
/// "Valid Pair"; here it is also the nominated and therefore the selected
/// pair, since a lite agent never holds one without the other).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidPair {
    /// The address the accepted request arrived on.
    pub local: SocketAddr,
    /// Where it came from.
    pub remote: SocketAddr,
}

/// What a lite agent sends back for a Binding request, told apart by whether
/// the request authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckAnswer {
    /// The answer to a request signed with this session's credential, or
    /// with the one a restart replaced: a success, or a signed error. The
    /// peer's nomination and its consent both wait on one of these.
    Signed(Vec<u8>),
    /// The unsigned refusal of a request that failed authentication
    /// (RFC 8489 §9.1.3), which anybody who can reach the port can have
    /// written. A caller holding answers under a ceiling drops these first.
    Refused(Vec<u8>),
}

impl CheckAnswer {
    /// The datagram to send back, whichever answer it is.
    #[must_use]
    pub fn into_datagram(self) -> Vec<u8> {
        match self {
            Self::Signed(datagram) | Self::Refused(datagram) => datagram,
        }
    }
}

/// A lite ICE agent for one data stream.
///
/// What it keeps is exactly what §7.3.2 gives it to keep: the local
/// credentials it was built with, its role, and a valid pair per component
/// once one has been nominated. No checklist, no timers, no candidate list —
/// a lite agent runs no state machine because RFC 8445 does not give it one.
///
/// The one thing it holds beyond that is the credential of the session a
/// restart replaced, and only until the peer nominates under the new one:
/// see [`LiteAgent::restart`].
pub struct LiteAgent {
    local_ufrag: String,
    local_pwd: String,
    role: Role,
    tiebreaker: u64,
    valid: Vec<(ComponentId, ValidPair)>,
    /// The username fragment and password before the last restart, while the
    /// pair they selected is still the one carrying media.
    previous: Option<(String, String)>,
}

impl LiteAgent {
    /// An agent for one data stream, with the credentials and tiebreaker it
    /// will hold for the life of the session.
    ///
    /// `local_ufrag` and `local_pwd` are the values this agent will also put
    /// in `a=ice-ufrag` and `a=ice-pwd`; RFC 8445 §5.3 asks for at least 24
    /// bits of randomness in the first and 128 in the second, drawn by the
    /// caller, the same way this crate takes every other random value from
    /// outside itself. `tiebreaker` is a random 64-bit number for §7.3.1.1;
    /// it does not need to change unless the caller starts an ICE restart.
    #[must_use]
    pub fn new(local_ufrag: String, local_pwd: String, role: Role, tiebreaker: u64) -> Self {
        Self {
            local_ufrag,
            local_pwd,
            role,
            tiebreaker,
            valid: Vec::new(),
            previous: None,
        }
    }

    /// Start a new ICE session under new credentials (RFC 8445 §9).
    ///
    /// A lite agent restarts because its peer did: RFC 8839 §4.4.2.1 makes
    /// an answerer that accepts a restart "change the SDP "ice-pwd" and
    /// "ice-ufrag" attribute values", and these are the new ones. The pair
    /// the old session selected stays selected — §9 has media keep flowing on
    /// it until the new session selects one — so the old credentials are
    /// kept too, and a check signed with them is still answered: that is the
    /// peer's consent check on the pair still in use (RFC 7675), and refusing
    /// it would withdraw consent from the audio the restart was meant to
    /// keep. They are forgotten the moment the peer nominates under the new
    /// ones. A nomination under the old credentials is answered and not
    /// followed: that session is over.
    pub fn restart(&mut self, local_ufrag: String, local_pwd: String) {
        let old_ufrag = core::mem::replace(&mut self.local_ufrag, local_ufrag);
        let old_pwd = core::mem::replace(&mut self.local_pwd, local_pwd);
        self.previous = Some((old_ufrag, old_pwd));
    }

    /// This agent's username fragment, for `a=ice-ufrag`.
    #[must_use]
    pub fn local_ufrag(&self) -> &str {
        &self.local_ufrag
    }

    /// This agent's password, for `a=ice-pwd`.
    #[must_use]
    pub fn local_pwd(&self) -> &str {
        &self.local_pwd
    }

    /// Controlling or controlled, as of the last request processed.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The pair this agent has accepted for a component, once the peer has
    /// nominated one.
    #[must_use]
    pub fn valid_pair(&self, component: ComponentId) -> Option<ValidPair> {
        self.valid
            .iter()
            .find(|(id, _)| *id == component)
            .map(|(_, pair)| *pair)
    }

    /// Take a datagram that arrived on the socket for one component, already
    /// told apart from media (see [`crate::classify`]).
    ///
    /// Returns the bytes to send back to `peer`, or `None` when the datagram
    /// is not a Binding request this agent answers — the wrong method or
    /// class, a FINGERPRINT that does not check out, or simply not a STUN
    /// message at all. A caller sharing the socket with something else can
    /// treat `None` as "not mine" and move on, the same way
    /// [`crate::stun::BindingClient::on_datagram`] does.
    pub fn handle_binding_request(
        &mut self,
        component: ComponentId,
        local: SocketAddr,
        peer: SocketAddr,
        datagram: &[u8],
    ) -> Option<Vec<u8>> {
        self.answer_binding_request(component, local, peer, datagram)
            .map(CheckAnswer::into_datagram)
    }

    /// [`Self::handle_binding_request`], saying as well whether the answer
    /// went to a request that authenticated: a caller that holds answers
    /// under a ceiling keeps room for those by dropping a stranger's
    /// refusals first.
    pub fn answer_binding_request(
        &mut self,
        component: ComponentId,
        local: SocketAddr,
        peer: SocketAddr,
        datagram: &[u8],
    ) -> Option<CheckAnswer> {
        let message = Message::parse(datagram).ok()?;
        let (sha256, current) = match server::authenticate(
            &message,
            self.local_ufrag.as_bytes(),
            self.local_pwd.as_bytes(),
        ) {
            Verdict::Ignore => return None,
            Verdict::Accept(accepted) => (accepted.sha256, true),
            // not this session's credential; the one a restart replaced
            // answers for the pair it selected until the new one selects
            Verdict::Refuse(reply) => match self.previous.as_ref().map(|(ufrag, pwd)| {
                server::authenticate(&message, ufrag.as_bytes(), pwd.as_bytes())
            }) {
                Some(Verdict::Accept(accepted)) => (accepted.sha256, false),
                _ => return Some(CheckAnswer::Refused(reply)),
            },
        };
        let key = if current {
            self.local_pwd.clone()
        } else {
            self.previous
                .as_ref()
                .map_or_else(String::new, |(_, pwd)| pwd.clone())
        };

        // Past this point the request is authenticated, so a response may be
        // signed with the same credentials the peer just proved it holds.
        //
        // A Binding request only ever reaches a lite agent's answering side
        // when the peer is a full agent (RFC 8445 §8.2: two lite agents
        // exchange no connectivity checks at all, so a lite peer never sends
        // one) — and §6.1.1 makes a full peer's role controlling
        // unconditionally, never controlled. An ICE-CONTROLLED request is
        // therefore never a genuine role conflict here, only a full peer
        // that has it backwards (or is spoofing one): the tiebreaker
        // arithmetic in §7.3.1.1 is not run in this agent's favour, so it
        // cannot move this agent to the controlling role roughly half the
        // time, one it can never act on (no candidate gathering beyond
        // host) and that would leave the call unable to find a path.
        if server::resolve_role(&mut self.role, self.tiebreaker, &message, false) {
            return server::error_signed(
                &message,
                error_code::ROLE_CONFLICT,
                b"role conflict",
                key.as_bytes(),
                sha256,
            )
            .map(CheckAnswer::Signed);
        }

        if current && message.use_candidate() && self.role == Role::Controlled {
            self.nominate(component, local, peer);
            self.previous = None;
        }

        server::success(&message, peer, key.as_bytes(), sha256).map(CheckAnswer::Signed)
    }

    /// Record the peer's nomination as the pair for this component (RFC 8445
    /// §7.3.2). A later nomination for the same component replaces the
    /// earlier one; nothing here ranks one above the other, since a lite
    /// agent has no basis to.
    fn nominate(&mut self, component: ComponentId, local: SocketAddr, peer: SocketAddr) {
        let pair = ValidPair {
            local,
            remote: peer,
        };
        if let Some(slot) = self.valid.iter_mut().find(|(id, _)| *id == component) {
            slot.1 = pair;
        } else {
            self.valid.push((component, pair));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LiteAgent, Role};
    use crate::ice::candidate::ComponentId;
    use crate::stun::{
        AttributeType, Class, Message, MessageBuilder, Method, TransactionId, error_code,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    // RFC 8445 SS7.2.2's own example: "Agent L ... included a username
    // fragment of LFRAG ... Agent R provided a username fragment of RFRAG and
    // a password of RPASS. A connectivity check from L to R utilizes the
    // username RFRAG:LFRAG and a password of RPASS." This agent plays R.
    const LOCAL_UFRAG: &str = "RFRAG";
    const LOCAL_PWD: &str = "RPASSRPASSRPASSRPASSRP";
    const PEER_UFRAG: &str = "LFRAG";

    fn txn(byte: u8) -> TransactionId {
        TransactionId::new([byte; 12])
    }

    fn local() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 9000)
    }

    fn peer() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 44_000)
    }

    fn agent(role: Role) -> LiteAgent {
        LiteAgent::new(LOCAL_UFRAG.to_owned(), LOCAL_PWD.to_owned(), role, 100)
    }

    /// A connectivity check, signed the way SS7.2.2 describes: USERNAME
    /// first, then whatever the caller wants to add, then the credential.
    fn check(build: impl FnOnce(&mut MessageBuilder)) -> Vec<u8> {
        check_as(LOCAL_UFRAG, LOCAL_PWD, build)
    }

    /// The same, against whichever credential the agent is holding.
    fn check_as(ufrag: &str, pwd: &str, build: impl FnOnce(&mut MessageBuilder)) -> Vec<u8> {
        let mut builder = MessageBuilder::new(Class::Request, Method::BINDING, txn(7));
        let username = format!("{ufrag}:{PEER_UFRAG}");
        builder
            .add(AttributeType::USERNAME, username.as_bytes())
            .expect("username fits");
        build(&mut builder);
        builder
            .add_message_integrity(pwd.as_bytes())
            .expect("integrity");
        builder.add_fingerprint().expect("fingerprint");
        builder.finish()
    }

    fn nominating(builder: &mut MessageBuilder) {
        builder
            .add_flag(AttributeType::USE_CANDIDATE)
            .expect("use-candidate");
    }

    const NEW_UFRAG: &str = "NEWFRAG";
    const NEW_PWD: &str = "NEWPASSNEWPASSNEWPASSNE";

    #[test]
    fn a_restart_answers_the_new_credential_and_keeps_the_old_pair() {
        let mut agent = agent(Role::Controlled);
        agent.handle_binding_request(ComponentId::RTP, local(), peer(), &check(nominating));
        agent.restart(NEW_UFRAG.to_owned(), NEW_PWD.to_owned());
        assert_eq!(agent.local_ufrag(), NEW_UFRAG);
        assert_eq!(agent.local_pwd(), NEW_PWD);
        // RFC 8445 SS9: the old session's pair carries the media until the
        // new session selects one
        assert_eq!(
            agent
                .valid_pair(ComponentId::RTP)
                .expect("still selected")
                .remote,
            peer()
        );
        let response = agent
            .handle_binding_request(
                ComponentId::RTP,
                local(),
                peer(),
                &check_as(NEW_UFRAG, NEW_PWD, |_| {}),
            )
            .expect("a reply");
        let message = parsed(&response);
        assert_eq!(message.class(), Class::Success);
        assert_eq!(
            message.verify_integrity(NEW_PWD.as_bytes()),
            crate::stun::Integrity::Valid
        );
    }

    #[test]
    fn the_old_credential_still_answers_consent_until_the_new_session_nominates() {
        let mut agent = agent(Role::Controlled);
        agent.handle_binding_request(ComponentId::RTP, local(), peer(), &check(nominating));
        agent.restart(NEW_UFRAG.to_owned(), NEW_PWD.to_owned());

        // a consent check on the pair still in use (RFC 7675), under the old
        // credential, signed back with the old password
        let response = agent
            .handle_binding_request(ComponentId::RTP, local(), peer(), &check(|_| {}))
            .expect("a reply");
        let message = parsed(&response);
        assert_eq!(message.class(), Class::Success);
        assert_eq!(
            message.verify_integrity(LOCAL_PWD.as_bytes()),
            crate::stun::Integrity::Valid
        );

        // and a nomination under it is answered and not followed: that
        // session is over
        let moved = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 55_000);
        agent.handle_binding_request(ComponentId::RTP, local(), moved, &check(nominating));
        assert_eq!(
            agent.valid_pair(ComponentId::RTP).expect("selected").remote,
            peer()
        );

        // the new session nominates, and the old credential is gone
        agent.handle_binding_request(
            ComponentId::RTP,
            local(),
            moved,
            &check_as(NEW_UFRAG, NEW_PWD, nominating),
        );
        assert_eq!(
            agent.valid_pair(ComponentId::RTP).expect("selected").remote,
            moved
        );
        let refused = agent
            .handle_binding_request(ComponentId::RTP, local(), peer(), &check(|_| {}))
            .expect("an error reply");
        assert_eq!(error_code_of(&refused), error_code::UNAUTHENTICATED);
    }

    #[test]
    fn a_nomination_that_fails_authentication_selects_nothing() {
        // RFC 8445 SS7.3: a check is processed as a STUN request first, and
        // one RFC 8489 SS9.1.3 rejects is answered with the error and nothing
        // else; under either credential, before and after a restart
        let moved = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 55_000);
        let mut agent = agent(Role::Controlled);
        let forged = check_as(LOCAL_UFRAG, "not the password RPASS", nominating);
        let refused = agent
            .handle_binding_request(ComponentId::RTP, local(), moved, &forged)
            .expect("an error reply");
        assert_eq!(error_code_of(&refused), error_code::UNAUTHENTICATED);
        assert!(agent.valid_pair(ComponentId::RTP).is_none());

        agent.handle_binding_request(ComponentId::RTP, local(), peer(), &check(nominating));
        agent.restart(NEW_UFRAG.to_owned(), NEW_PWD.to_owned());
        for forged in [
            check_as(LOCAL_UFRAG, "not the password RPASS", nominating),
            check_as(NEW_UFRAG, "not the password NEWPASS", nominating),
            check_as(NEW_UFRAG, LOCAL_PWD, nominating),
        ] {
            let refused = agent
                .handle_binding_request(ComponentId::RTP, local(), moved, &forged)
                .expect("an error reply");
            assert_eq!(error_code_of(&refused), error_code::UNAUTHENTICATED);
            assert_eq!(
                agent.valid_pair(ComponentId::RTP).expect("selected").remote,
                peer()
            );
        }
    }

    fn parsed(datagram: &[u8]) -> Message<'_> {
        Message::parse(datagram).expect("a well-formed STUN message")
    }

    fn error_code_of(datagram: &[u8]) -> u16 {
        parsed(datagram)
            .error_code()
            .expect("an ERROR-CODE attribute")
            .code()
    }

    #[test]
    fn role_initial_follows_section_6_1_1() {
        // a full peer is always controlling, whichever side offered
        assert_eq!(Role::initial(true, false), Role::Controlled);
        assert_eq!(Role::initial(false, false), Role::Controlled);
        // between two lite agents, whoever offered is controlling
        assert_eq!(Role::initial(true, true), Role::Controlling);
        assert_eq!(Role::initial(false, true), Role::Controlled);
    }

    #[test]
    fn role_initial_full_follows_section_6_1_1() {
        // two full agents: the offerer controls
        assert_eq!(Role::initial_full(true, false), Role::Controlling);
        assert_eq!(Role::initial_full(false, false), Role::Controlled);
        // a full agent facing a lite one controls, offerer or not
        assert_eq!(Role::initial_full(true, true), Role::Controlling);
        assert_eq!(Role::initial_full(false, true), Role::Controlling);
    }

    #[test]
    fn an_authenticated_check_is_answered_with_the_reflexive_address() {
        let mut agent = agent(Role::Controlled);
        let datagram = check(|_| {});
        let response = agent
            .handle_binding_request(ComponentId::RTP, local(), peer(), &datagram)
            .expect("a reply");
        let message = parsed(&response);
        assert_eq!(message.class(), Class::Success);
        assert_eq!(message.transaction_id(), txn(7));
        assert_eq!(message.xor_mapped_address(), Some(peer()));
    }

    #[test]
    fn a_response_is_signed_with_the_algorithm_the_request_used() {
        let mut agent = agent(Role::Controlled);
        let datagram = check(|_| {});
        let response = agent
            .handle_binding_request(ComponentId::RTP, local(), peer(), &datagram)
            .expect("a reply");
        let message = parsed(&response);
        assert_eq!(
            message.verify_integrity(LOCAL_PWD.as_bytes()),
            crate::stun::Integrity::Valid
        );
    }

    #[test]
    fn use_candidate_nominates_the_pair_it_arrived_on() {
        let mut agent = agent(Role::Controlled);
        assert!(agent.valid_pair(ComponentId::RTP).is_none());
        let datagram = check(|builder| {
            builder
                .add_flag(AttributeType::USE_CANDIDATE)
                .expect("use-candidate");
        });
        let response = agent
            .handle_binding_request(ComponentId::RTP, local(), peer(), &datagram)
            .expect("a reply");
        assert_eq!(parsed(&response).class(), Class::Success);
        let pair = agent
            .valid_pair(ComponentId::RTP)
            .expect("the pair is nominated");
        assert_eq!(pair.local, local());
        assert_eq!(pair.remote, peer());
    }

    #[test]
    fn a_later_nomination_replaces_the_earlier_one() {
        let mut agent = agent(Role::Controlled);
        let datagram = check(|builder| {
            builder
                .add_flag(AttributeType::USE_CANDIDATE)
                .expect("use-candidate");
        });
        agent.handle_binding_request(ComponentId::RTP, local(), peer(), &datagram);
        let rebound = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 55_000);
        agent.handle_binding_request(ComponentId::RTP, local(), rebound, &datagram);
        assert_eq!(
            agent
                .valid_pair(ComponentId::RTP)
                .expect("nominated")
                .remote,
            rebound
        );
    }

    #[test]
    fn each_component_keeps_its_own_pair() {
        let mut agent = agent(Role::Controlled);
        let datagram = check(|builder| {
            builder
                .add_flag(AttributeType::USE_CANDIDATE)
                .expect("use-candidate");
        });
        let rtcp_local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 9001);
        let rtcp_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 44_001);
        agent.handle_binding_request(ComponentId::RTP, local(), peer(), &datagram);
        agent.handle_binding_request(ComponentId::RTCP, rtcp_local, rtcp_peer, &datagram);
        assert_eq!(
            agent.valid_pair(ComponentId::RTP).expect("rtp").remote,
            peer()
        );
        assert_eq!(
            agent.valid_pair(ComponentId::RTCP).expect("rtcp").remote,
            rtcp_peer
        );
    }

    #[test]
    fn use_candidate_is_ignored_while_this_agent_is_controlling() {
        // only a controlled agent is meant to receive a nomination (RFC 8445
        // SS7.1.2 lets only the controlling side send USE-CANDIDATE); a peer
        // that sends one to an agent that is itself controlling gets a normal
        // reply and no nomination
        let mut agent = agent(Role::Controlling);
        let datagram = check(|builder| {
            builder
                .add_flag(AttributeType::USE_CANDIDATE)
                .expect("use-candidate");
        });
        let response = agent
            .handle_binding_request(ComponentId::RTP, local(), peer(), &datagram)
            .expect("a reply");
        assert_eq!(parsed(&response).class(), Class::Success);
        assert!(agent.valid_pair(ComponentId::RTP).is_none());
    }

    #[test]
    fn no_username_and_no_integrity_is_a_bad_request() {
        // RFC 8489 SS9.1.3, first bullet
        let mut agent = agent(Role::Controlled);
        let mut builder = MessageBuilder::new(Class::Request, Method::BINDING, txn(1));
        builder.add_fingerprint().expect("fingerprint");
        let datagram = builder.finish();
        let response = agent
            .handle_binding_request(ComponentId::RTP, local(), peer(), &datagram)
            .expect("an error reply");
        assert_eq!(parsed(&response).class(), Class::Error);
        assert_eq!(error_code_of(&response), error_code::BAD_REQUEST);
    }

    #[test]
    fn a_username_naming_a_different_agent_is_unauthenticated() {
        let mut agent = agent(Role::Controlled);
        let mut builder = MessageBuilder::new(Class::Request, Method::BINDING, txn(2));
        builder
            .add(AttributeType::USERNAME, b"someoneelse:LFRAG")
            .expect("username");
        builder
            .add_message_integrity(LOCAL_PWD.as_bytes())
            .expect("integrity");
        builder.add_fingerprint().expect("fingerprint");
        let datagram = builder.finish();
        let response = agent
            .handle_binding_request(ComponentId::RTP, local(), peer(), &datagram)
            .expect("an error reply");
        assert_eq!(error_code_of(&response), error_code::UNAUTHENTICATED);
    }

    #[test]
    fn a_username_that_is_a_prefix_without_the_colon_boundary_is_unauthenticated() {
        // "RFRAGX" starts with the local ufrag "RFRAG" but is not it
        let mut agent = agent(Role::Controlled);
        let mut builder = MessageBuilder::new(Class::Request, Method::BINDING, txn(3));
        builder
            .add(AttributeType::USERNAME, b"RFRAGX")
            .expect("username");
        builder
            .add_message_integrity(LOCAL_PWD.as_bytes())
            .expect("integrity");
        builder.add_fingerprint().expect("fingerprint");
        let datagram = builder.finish();
        let response = agent
            .handle_binding_request(ComponentId::RTP, local(), peer(), &datagram)
            .expect("an error reply");
        assert_eq!(error_code_of(&response), error_code::UNAUTHENTICATED);
    }

    #[test]
    fn the_wrong_password_fails_integrity() {
        let mut agent = agent(Role::Controlled);
        let mut builder = MessageBuilder::new(Class::Request, Method::BINDING, txn(4));
        let username = format!("{LOCAL_UFRAG}:{PEER_UFRAG}");
        builder
            .add(AttributeType::USERNAME, username.as_bytes())
            .expect("username");
        builder
            .add_message_integrity(b"not the password RPASS")
            .expect("integrity");
        builder.add_fingerprint().expect("fingerprint");
        let datagram = builder.finish();
        let response = agent
            .handle_binding_request(ComponentId::RTP, local(), peer(), &datagram)
            .expect("an error reply");
        assert_eq!(error_code_of(&response), error_code::UNAUTHENTICATED);
    }

    #[test]
    fn an_unauthenticated_response_carries_no_username_or_integrity() {
        // RFC 8489 SS9.1.3: "the server cannot determine the shared secret"
        let mut agent = agent(Role::Controlled);
        let mut builder = MessageBuilder::new(Class::Request, Method::BINDING, txn(5));
        let username = format!("{LOCAL_UFRAG}:{PEER_UFRAG}");
        builder
            .add(AttributeType::USERNAME, username.as_bytes())
            .expect("username");
        builder
            .add_message_integrity(b"not the password RPASS")
            .expect("integrity");
        builder.add_fingerprint().expect("fingerprint");
        let datagram = builder.finish();
        let response = agent
            .handle_binding_request(ComponentId::RTP, local(), peer(), &datagram)
            .expect("an error reply");
        let message = parsed(&response);
        assert!(message.username().is_none());
        assert!(!message.has_integrity());
    }

    #[test]
    fn a_broken_fingerprint_gets_no_reply_at_all() {
        let mut agent = agent(Role::Controlled);
        let mut datagram = check(|_| {});
        let last = datagram.len() - 1;
        if let Some(byte) = datagram.get_mut(last) {
            *byte ^= 0xff;
        }
        assert!(
            agent
                .handle_binding_request(ComponentId::RTP, local(), peer(), &datagram)
                .is_none()
        );
    }

    #[test]
    fn a_response_is_not_a_request_and_gets_no_reply() {
        let mut agent = agent(Role::Controlled);
        let mut builder = MessageBuilder::new(Class::Success, Method::BINDING, txn(6));
        builder.add_fingerprint().expect("fingerprint");
        let datagram = builder.finish();
        assert!(
            agent
                .handle_binding_request(ComponentId::RTP, local(), peer(), &datagram)
                .is_none()
        );
    }

    #[test]
    fn something_that_is_not_stun_at_all_gets_no_reply() {
        let mut agent = agent(Role::Controlled);
        assert!(
            agent
                .handle_binding_request(ComponentId::RTP, local(), peer(), &[1, 2, 3])
                .is_none()
        );
    }

    #[test]
    fn an_unknown_comprehension_required_attribute_is_a_420() {
        let mut agent = agent(Role::Controlled);
        let mut builder = MessageBuilder::new(Class::Request, Method::BINDING, txn(8));
        // 0x0002 is reserved (an RFC 3489 attribute), comprehension-required
        // and unknown to this stack
        builder
            .add(AttributeType::new(0x0002), b"exotic")
            .expect("an attribute this stack does not claim to understand");
        builder.add_fingerprint().expect("fingerprint");
        let datagram = builder.finish();
        let response = agent
            .handle_binding_request(ComponentId::RTP, local(), peer(), &datagram)
            .expect("an error reply");
        assert_eq!(error_code_of(&response), error_code::UNKNOWN_ATTRIBUTE);
        let unknown: Vec<_> = parsed(&response).unknown_attributes().collect();
        assert_eq!(unknown, vec![AttributeType::new(0x0002)]);
    }

    #[test]
    fn a_peer_that_agrees_this_agent_is_controlled_is_not_a_conflict() {
        let mut agent = agent(Role::Controlled);
        let datagram = check(|builder| {
            builder
                .add_u64(AttributeType::ICE_CONTROLLING, 500)
                .expect("ice-controlling");
        });
        let response = agent
            .handle_binding_request(ComponentId::RTP, local(), peer(), &datagram)
            .expect("a reply");
        assert_eq!(parsed(&response).class(), Class::Success);
        assert_eq!(agent.role(), Role::Controlled);
    }

    #[test]
    fn a_controlled_lite_agent_never_switches_to_controlling_whatever_the_tiebreaker_says() {
        // a Binding request only ever reaches this code from a full peer
        // (RFC 8445 SS8.2: two lite agents exchange none), and SS6.1.1 makes
        // that peer's role controlling unconditionally — never controlled —
        // so ICE-CONTROLLED naming this agent's role is not the genuine
        // ambiguity SS7.3.1.1's arithmetic exists to settle. Before this
        // defence, a tiebreaker (100, fixed by `agent()`) that happened to
        // be "larger than or equal to" the value the request named would
        // still flip this agent to a role it can never act on — no
        // candidate gathering beyond host — leaving the call unable to find
        // a path about half the time a full peer got the roles backwards.
        for theirs in [0, 50, 100, u64::MAX] {
            let mut agent = agent(Role::Controlled);
            let datagram = check(|builder| {
                builder
                    .add_u64(AttributeType::ICE_CONTROLLED, theirs)
                    .expect("ice-controlled");
            });
            let response = agent
                .handle_binding_request(ComponentId::RTP, local(), peer(), &datagram)
                .expect("a reply");
            assert_eq!(
                error_code_of(&response),
                error_code::ROLE_CONFLICT,
                "theirs = {theirs}"
            );
            assert_eq!(agent.role(), Role::Controlled, "theirs = {theirs}");
        }
    }

    #[test]
    fn a_controlled_agent_that_loses_the_tiebreaker_keeps_its_role_and_answers_487() {
        let mut agent = agent(Role::Controlled);
        let datagram = check(|builder| {
            builder
                .add_u64(AttributeType::ICE_CONTROLLED, 200)
                .expect("ice-controlled");
        });
        let response = agent
            .handle_binding_request(ComponentId::RTP, local(), peer(), &datagram)
            .expect("a reply");
        assert_eq!(error_code_of(&response), error_code::ROLE_CONFLICT);
        assert_eq!(agent.role(), Role::Controlled);
    }

    #[test]
    fn a_controlling_agent_facing_a_larger_tiebreaker_switches_to_controlled() {
        let mut agent = agent(Role::Controlling);
        let datagram = check(|builder| {
            builder
                .add_u64(AttributeType::ICE_CONTROLLING, 200)
                .expect("ice-controlling");
        });
        let response = agent
            .handle_binding_request(ComponentId::RTP, local(), peer(), &datagram)
            .expect("a reply");
        assert_eq!(parsed(&response).class(), Class::Success);
        assert_eq!(agent.role(), Role::Controlled);
    }

    #[test]
    fn a_controlling_agent_facing_an_equal_or_smaller_tiebreaker_keeps_control_and_answers_487() {
        for theirs in [100, 50] {
            let mut agent = agent(Role::Controlling);
            let datagram = check(|builder| {
                builder
                    .add_u64(AttributeType::ICE_CONTROLLING, theirs)
                    .expect("ice-controlling");
            });
            let response = agent
                .handle_binding_request(ComponentId::RTP, local(), peer(), &datagram)
                .expect("a reply");
            assert_eq!(
                error_code_of(&response),
                error_code::ROLE_CONFLICT,
                "theirs = {theirs}"
            );
            assert_eq!(agent.role(), Role::Controlling, "theirs = {theirs}");
        }
    }

    #[test]
    fn a_controlling_agent_facing_ice_controlled_is_not_a_conflict() {
        let mut agent = agent(Role::Controlling);
        let datagram = check(|builder| {
            builder
                .add_u64(AttributeType::ICE_CONTROLLED, 1)
                .expect("ice-controlled");
        });
        let response = agent
            .handle_binding_request(ComponentId::RTP, local(), peer(), &datagram)
            .expect("a reply");
        assert_eq!(parsed(&response).class(), Class::Success);
        assert_eq!(agent.role(), Role::Controlling);
    }
}
