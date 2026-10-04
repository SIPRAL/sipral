// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! ICE, in both roles (RFC 8445; the SDP attributes from RFC 8839, which RFC
//! 8445 leaves to a companion document; consent freshness from RFC 7675).
//!
//! **The lite role** ([`LiteAgent`]) is a STUN server that advertises host
//! candidates and answers connectivity checks, and nothing past that. RFC 8445
//! Appendix A calls it "only appropriate for devices that will always be
//! connected to the public Internet and have a public IP address" and warns
//! that "ICE will not function when a lite implementation is placed behind a
//! NAT". A lite agent's whole job is to sit at a known address, say so, and
//! answer whichever full agent decides to check it.
//!
//! **The full role** ([`IceAgent`]) is for everything else: an endpoint behind
//! a NAT, a phone on a carrier-grade one, a peer that requires ICE. It gathers
//! host, server-reflexive and relayed candidates, forms checklists, paces its
//! own checks, resolves role conflicts, nominates, restarts, and keeps consent
//! on the pair it selected. It is written and tested against itself and
//! against the lite agent over a simulated network; nothing in the facade
//! reaches it yet, and `docs/06-nat.md` says what switching it on costs.
//!
//! Both roles authenticate a check the same way, in one private module both
//! call.

mod agent;
mod candidate;
mod checklist;
mod full;
mod sdp;
mod server;

pub use agent::{CheckAnswer, LiteAgent, Role, ValidPair};
pub use candidate::{
    Candidate, CandidateType, ComponentId, Foundation, HostAddresses, candidate_priority, gather,
};
pub use checklist::{PairState, pair_priority};
pub use full::{
    CONSENT_EXPIRY, Claim, Credentials, DEFAULT_CONSENT_INTERVAL, DEFAULT_KEEPALIVE,
    DEFAULT_MAX_PAIRS, DEFAULT_TA, IceAgent, IceConfig, IceError, IceEvent, IceState, PairOutcome,
    PairReport, REFUSAL_CEILING, Received, RelayOutcome, RelayReport, Route, SelectedPair,
    SendError, SharedRelay, StreamId, TRANSMIT_CEILING, Transmit, TurnServer,
};
pub use sdp::{
    RemoteIce, ice_mismatch, parse_remote, write_media, write_pacing, write_session, write_stream,
};
