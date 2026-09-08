// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! ICE-lite: a STUN server that advertises host candidates and answers
//! connectivity checks, and nothing past that (RFC 8445 §2.5, §5.2, §7.3.2;
//! the SDP attributes from RFC 8839, which RFC 8445 leaves to a companion
//! document).
//!
//! This is deliberately not an ICE implementation. A full agent gathers
//! server-reflexive and relayed candidates, forms a checklist, runs pacing
//! timers, sends its own connectivity checks and nominates a pair. None of
//! that is here, and none of it is going to be: RFC 8445 Appendix A calls the
//! lite role "only appropriate for devices that will always be connected to
//! the public Internet and have a public IP address" and warns that "ICE will
//! not function when a lite implementation is placed behind a NAT". A lite
//! agent's whole job is to sit at a known address, say so, and answer
//! whichever full agent decides to check it.
//!
//! What is here: candidate generation restricted to one host candidate per
//! address family (§5.2), the four SDP attributes a lite agent writes and
//! reads, and a server that authenticates a Binding request with the ICE
//! short-term credential, answers with XOR-MAPPED-ADDRESS, and — the one
//! decision this role ever makes — believes a USE-CANDIDATE it accepts.

mod agent;
mod candidate;
mod sdp;

pub use agent::{LiteAgent, Role, ValidPair};
pub use candidate::{Candidate, CandidateType, ComponentId, Foundation, HostAddresses, gather};
pub use sdp::{RemoteIce, parse_remote, write_media, write_session};
