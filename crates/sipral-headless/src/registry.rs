// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Many sessions, one process — `docs/07-headless.md`'s Concurrency section:
//! a lookup keyed by call, and nothing shared between the entries it holds.
//!
//! There is no buffer pool here and no thread. Each [`Session`] owns its own
//! queues, so a session nobody is reading from cannot starve or slow down
//! any other entry in the map. What this type adds over a bare `HashMap` is
//! the one invariant a socket-facing layer actually needs: two sessions can
//! never silently share a call ID, one replacing whatever the other had
//! queued.

use core::fmt;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use crate::session::Session;

/// One process's independent sessions, keyed by call ID.
#[derive(Debug, Default)]
pub struct SessionRegistry {
    sessions: HashMap<String, Session>,
}

impl SessionRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `session` under its own call ID.
    ///
    /// # Errors
    /// [`RegistryError::AlreadyOpen`] if a session with that call ID is
    /// already held. Replacing it silently would leak whatever it had
    /// queued, so the caller is told to close the old one first.
    pub fn open(&mut self, session: Session) -> Result<&mut Session, RegistryError> {
        match self.sessions.entry(session.call_id().to_owned()) {
            Entry::Occupied(occupied) => Err(RegistryError::AlreadyOpen(occupied.key().clone())),
            Entry::Vacant(vacant) => Ok(vacant.insert(session)),
        }
    }

    /// The session for `call_id`, if one is open.
    #[must_use]
    pub fn get(&self, call_id: &str) -> Option<&Session> {
        self.sessions.get(call_id)
    }

    /// Mutable access to the session for `call_id`, if one is open.
    pub fn get_mut(&mut self, call_id: &str) -> Option<&mut Session> {
        self.sessions.get_mut(call_id)
    }

    /// Remove and return the session for `call_id`, if one was open.
    pub fn close(&mut self, call_id: &str) -> Option<Session> {
        self.sessions.remove(call_id)
    }

    /// How many sessions are open.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether no sessions are open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

/// Why [`SessionRegistry::open`] refused a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryError {
    /// A session with this call ID was already open.
    AlreadyOpen(String),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyOpen(call_id) => write!(f, "a session for {call_id:?} is already open"),
        }
    }
}

impl core::error::Error for RegistryError {}

#[cfg(test)]
mod tests {
    use super::{RegistryError, SessionRegistry};
    use crate::audio::{AudioConfig, SampleRate};
    use crate::session::Session;

    fn session(call_id: &str) -> Session {
        Session::new(
            call_id.to_owned(),
            AudioConfig::new(SampleRate::Hz8000),
            4,
            4,
        )
    }

    fn frame() -> Vec<u8> {
        vec![
            0_u8;
            usize::from(
                AudioConfig::new(SampleRate::Hz8000)
                    .frame_bytes()
                    .expect("fits")
            )
        ]
    }

    #[test]
    fn a_new_registry_holds_nothing() {
        let registry = SessionRegistry::new();
        assert_eq!(registry.len(), 0);
        assert!(registry.is_empty());
    }

    #[test]
    fn opening_a_session_makes_it_reachable_by_call_id() {
        let mut registry = SessionRegistry::new();
        registry.open(session("call-1")).expect("first open");
        assert_eq!(registry.len(), 1);
        assert!(registry.get("call-1").is_some());
        assert!(registry.get_mut("call-1").is_some());
        assert!(registry.get("call-2").is_none());
    }

    #[test]
    fn opening_a_duplicate_call_id_is_refused() {
        let mut registry = SessionRegistry::new();
        registry.open(session("call-1")).expect("first open");
        let error = registry
            .open(session("call-1"))
            .expect_err("duplicate call id");
        assert_eq!(error, RegistryError::AlreadyOpen("call-1".to_owned()));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn closing_removes_the_session_and_frees_the_call_id() {
        let mut registry = SessionRegistry::new();
        registry.open(session("call-1")).expect("first open");
        assert!(registry.close("call-1").is_some());
        assert!(registry.is_empty());
        assert!(registry.close("call-1").is_none());
        registry
            .open(session("call-1"))
            .expect("call id is free again");
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn two_sessions_are_independent_a_stalled_one_does_not_affect_the_other() {
        let mut registry = SessionRegistry::new();
        registry
            .open(Session::new(
                "stalled".to_owned(),
                AudioConfig::new(SampleRate::Hz8000),
                1,
                1,
            ))
            .expect("first open");
        registry.open(session("healthy")).expect("second open");

        let stalled = registry.get_mut("stalled").expect("just opened");
        stalled.push_capture(frame()).expect("first frame fits");
        stalled
            .push_capture(frame())
            .expect("accepted, evicting the oldest frame");
        assert_eq!(
            stalled.capture_dropped(),
            1,
            "the stalled session's own queue is full and evicting"
        );

        let healthy = registry.get_mut("healthy").expect("just opened");
        assert!(
            healthy.push_capture(frame()).is_ok(),
            "no shared buffer pool means the other session is untouched"
        );
    }
}
