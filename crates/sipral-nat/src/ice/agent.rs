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
use crate::stun::{
    AttributeType, BuildError, Class, Integrity, Message, MessageBuilder, Method, error_code,
};

/// Which side nominates. RFC 8445 §4: "The controlling agent is responsible
/// for the choice of the final candidate pairs".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// This agent picks the pair and tells the peer with USE-CANDIDATE.
    /// Unreachable for a lite agent unless the peer is lite too, since a full
    /// peer is always controlling (§6.1.1) — but this agent still has to hold
    /// the role correctly for the role-conflict arithmetic in §7.3.1.1.
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

/// A lite ICE agent for one data stream.
///
/// What it keeps is exactly what §7.3.2 gives it to keep: the local
/// credentials it was built with, its role, and a valid pair per component
/// once one has been nominated. No checklist, no timers, no candidate list —
/// a lite agent runs no state machine because RFC 8445 does not give it one.
pub struct LiteAgent {
    local_ufrag: String,
    local_pwd: String,
    role: Role,
    tiebreaker: u64,
    valid: Vec<(ComponentId, ValidPair)>,
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
        }
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
    /// told apart from media (see [`crate::demux`]).
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
        let message = Message::parse(datagram).ok()?;
        if message.class() != Class::Request || message.method() != Method::BINDING {
            return None;
        }
        // "The FINGERPRINT mechanism MUST be used for connectivity checks"
        // (RFC 8445 §7.2.4); a message that claims one and fails it is worth
        // no reply at all, the same standard BindingClient holds a response
        // to.
        if message.verify_fingerprint() == Integrity::Invalid {
            return None;
        }

        if let Err(unknown) = message.check_comprehension() {
            return Self::error_unsigned(
                &message,
                error_code::UNKNOWN_ATTRIBUTE,
                b"unknown attribute",
                |builder| builder.add_unknown_attributes(unknown.types()),
            );
        }

        // RFC 8489 §9.1.3, in the order it gives the checks.
        let username = message.username();
        if username.is_none() && !message.has_integrity() {
            return Self::error_unsigned(
                &message,
                error_code::BAD_REQUEST,
                b"missing credentials",
                |_| Ok(()),
            );
        }
        let Some(username) = username else {
            return Self::error_unsigned(
                &message,
                error_code::UNAUTHENTICATED,
                b"missing username",
                |_| Ok(()),
            );
        };
        if !names_this_agent(username, self.local_ufrag.as_bytes()) {
            return Self::error_unsigned(
                &message,
                error_code::UNAUTHENTICATED,
                b"unknown username",
                |_| Ok(()),
            );
        }

        let sha256 = message
            .find(AttributeType::MESSAGE_INTEGRITY_SHA256)
            .is_some();
        let key = self.local_pwd.as_bytes();
        let authentic = if sha256 {
            message.verify_integrity_sha256(key) == Integrity::Valid
        } else {
            message.verify_integrity(key) == Integrity::Valid
        };
        if !authentic {
            return Self::error_unsigned(
                &message,
                error_code::UNAUTHENTICATED,
                b"integrity check failed",
                |_| Ok(()),
            );
        }

        // Past this point the request is authenticated, so a response may be
        // signed with the same credentials the peer just proved it holds
        // (RFC 8489 §9.1.3: "Any response generated by a server to a request
        // that contains a MESSAGE-INTEGRITY... attribute MUST include" one).
        if self.resolve_role(&message) {
            return self.error_signed(
                &message,
                error_code::ROLE_CONFLICT,
                b"role conflict",
                sha256,
            );
        }

        if message.use_candidate() && self.role == Role::Controlled {
            self.nominate(component, local, peer);
        }

        self.success(&message, peer, sha256).ok()
    }

    /// Apply RFC 8445 §7.3.1.1's role-conflict arithmetic to this request.
    ///
    /// `true` means the request loses and gets a 487; the role has already
    /// been flipped in the other case, if that is what the tiebreaker called
    /// for. A request that names the role this agent already holds — an
    /// ICE-CONTROLLING from a controlled peer, or the reverse — is not a
    /// conflict at all and leaves the role untouched.
    fn resolve_role(&mut self, message: &Message<'_>) -> bool {
        if let Some(theirs) = message.ice_controlling() {
            if self.role != Role::Controlling {
                return false;
            }
            if self.tiebreaker >= theirs {
                return true;
            }
            self.role = Role::Controlled;
        } else if let Some(theirs) = message.ice_controlled() {
            if self.role != Role::Controlled {
                return false;
            }
            if self.tiebreaker >= theirs {
                self.role = Role::Controlling;
            } else {
                return true;
            }
        }
        false
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

    fn success(
        &self,
        request: &Message<'_>,
        peer: SocketAddr,
        sha256: bool,
    ) -> Result<Vec<u8>, BuildError> {
        let mut builder =
            MessageBuilder::new(Class::Success, Method::BINDING, request.transaction_id());
        builder.add_xor_address(AttributeType::XOR_MAPPED_ADDRESS, peer)?;
        self.sign(&mut builder, sha256)?;
        builder.add_fingerprint()?;
        Ok(builder.finish())
    }

    fn error_signed(
        &self,
        request: &Message<'_>,
        code: u16,
        reason: &[u8],
        sha256: bool,
    ) -> Option<Vec<u8>> {
        let mut builder =
            MessageBuilder::new(Class::Error, Method::BINDING, request.transaction_id());
        builder.add_error_code(code, reason).ok()?;
        self.sign(&mut builder, sha256).ok()?;
        builder.add_fingerprint().ok()?;
        Some(builder.finish())
    }

    /// An error response built before authentication has been decided, which
    /// RFC 8489 §9.1.3 forbids signing: "the server cannot determine the
    /// shared secret necessary". `extra` adds whatever the specific error
    /// needs beyond ERROR-CODE, such as UNKNOWN-ATTRIBUTES on a 420.
    fn error_unsigned(
        request: &Message<'_>,
        code: u16,
        reason: &[u8],
        extra: impl FnOnce(&mut MessageBuilder) -> Result<(), BuildError>,
    ) -> Option<Vec<u8>> {
        let mut builder =
            MessageBuilder::new(Class::Error, Method::BINDING, request.transaction_id());
        builder.add_error_code(code, reason).ok()?;
        extra(&mut builder).ok()?;
        builder.add_fingerprint().ok()?;
        Some(builder.finish())
    }

    fn sign(&self, builder: &mut MessageBuilder, sha256: bool) -> Result<(), BuildError> {
        let key = self.local_pwd.as_bytes();
        if sha256 {
            builder.add_message_integrity_sha256(key)
        } else {
            builder.add_message_integrity(key)
        }
    }
}

/// Whether USERNAME's first colon-separated value is this agent's ufrag (RFC
/// 8445 §7.3): "the first value is equal to the username fragment generated
/// by the agent". The second half, the peer's own fragment, is not checked —
/// RFC 8445 does not ask for it, and this agent has no candidate exchange
/// state to check it against.
fn names_this_agent(username: &[u8], local_ufrag: &[u8]) -> bool {
    username
        .strip_prefix(local_ufrag)
        .is_some_and(|rest| rest.first() == Some(&b':'))
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
        let mut builder = MessageBuilder::new(Class::Request, Method::BINDING, txn(7));
        let username = format!("{LOCAL_UFRAG}:{PEER_UFRAG}");
        builder
            .add(AttributeType::USERNAME, username.as_bytes())
            .expect("username fits");
        build(&mut builder);
        builder
            .add_message_integrity(LOCAL_PWD.as_bytes())
            .expect("integrity");
        builder.add_fingerprint().expect("fingerprint");
        builder.finish()
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
    fn a_controlled_agent_that_wins_the_tiebreaker_switches_to_controlling() {
        // this agent's tiebreaker is 100; RFC 8445 SS7.3.1.1 gives it the
        // controlling role when its tiebreaker is "larger than or equal to"
        // the peer's, so the boundary (equal) is a win, not a coin flip
        for theirs in [50, 100] {
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
                parsed(&response).class(),
                Class::Success,
                "theirs = {theirs}"
            );
            assert_eq!(agent.role(), Role::Controlling, "theirs = {theirs}");
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
