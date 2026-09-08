// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Two stacks, two sockets, one call.
//!
//! Every other test in this workspace drives the stack against a peer written
//! in the same file, which proves it is consistent with itself and nothing
//! else. This one puts two of them on loopback and has one call the other: a
//! real INVITE over a real datagram socket, answered, acknowledged, put on
//! hold and hung up. It is the smallest thing that can be called interop, and
//! it is the shape the container lab will drive.

#![cfg(feature = "reference-loop")]
// a test says what it means; the no-panic discipline is for the library
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "this is a test binary, not the library"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc::{Sender, channel};
use std::thread;
use std::time::{Duration, Instant};

use sipral_ua::{
    Account, AccountId, Control, EndpointConfig, Handler, OutgoingCall, Runtime, TransportId,
    UaEvent, Uri, UserAgent,
};

const OFFER: &[u8] = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\n\
t=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";
const ANSWER: &[u8] = b"v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\n\
t=0 0\r\nm=audio 9000 RTP/AVP 0\r\n";

/// A run that hangs is a run that has to end anyway, so that a failure is a
/// failed assertion rather than a test that never returns.
const PATIENCE: Duration = Duration::from_secs(10);

/// What each side reports back to the test.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Note {
    Ringing,
    Up,
    Held,
    Over,
}

fn uri(text: &str) -> Uri {
    Uri::parse_str(text).expect("a URI")
}

/// The caller: place a call, hold it once it is up, then hang up.
struct Caller {
    notes: Sender<Note>,
    started: Instant,
    account: AccountId,
    dialled: bool,
    done: bool,
}

impl Handler for Caller {
    fn on_event(&mut self, agent: &mut UserAgent, event: UaEvent, now: Instant) {
        match event {
            UaEvent::CallProgress { .. } => self.notes.send(Note::Ringing).ok(),
            UaEvent::CallConfirmed { call, .. } => {
                self.notes.send(Note::Up).ok();
                agent.hold(call, now).expect("the hold goes");
                None
            }
            UaEvent::SessionChanged { call, hold, .. } if hold.local => {
                self.notes.send(Note::Held).ok();
                agent.hangup(call, now).expect("the BYE goes");
                None
            }
            UaEvent::CallEnded { .. } => {
                self.done = true;
                self.notes.send(Note::Over).ok()
            }
            _ => None,
        };
    }

    fn on_tick(&mut self, agent: &mut UserAgent, now: Instant) -> Control {
        if !self.dialled {
            self.dialled = true;
            let call = OutgoingCall::new(uri("sip:bob@example.com")).offer(Arc::from(OFFER));
            agent
                .call(self.account, &call, now)
                .expect("the INVITE goes");
        }
        if self.done || now > self.started + PATIENCE {
            return Control::Stop;
        }
        Control::Continue
    }
}

/// The callee: ring, then answer.
struct Callee {
    notes: Sender<Note>,
    started: Instant,
    done: bool,
}

impl Handler for Callee {
    fn on_event(&mut self, agent: &mut UserAgent, event: UaEvent, now: Instant) {
        match event {
            UaEvent::IncomingCall { call, .. } => {
                agent.ring(call, None, now).expect("180 goes");
                agent
                    .answer(call, Some(Arc::from(ANSWER)), now)
                    .expect("200 goes");
                None
            }
            UaEvent::SessionChanged { hold, .. } if hold.remote => self.notes.send(Note::Held).ok(),
            UaEvent::CallEnded { .. } => {
                self.done = true;
                self.notes.send(Note::Over).ok()
            }
            _ => None,
        };
    }

    fn on_tick(&mut self, _: &mut UserAgent, now: Instant) -> Control {
        if self.done || now > self.started + PATIENCE {
            return Control::Stop;
        }
        Control::Continue
    }
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().expect("a local address")
}

fn account(user: &str, mine: SocketAddr, theirs: SocketAddr, transport: TransportId) -> Account {
    Account::new(
        uri(&format!("sip:{user}@example.com")),
        uri("sip:example.com"),
        uri(&format!("sip:{user}@{mine}")),
        transport,
        theirs,
    )
}

#[test]
fn one_stack_calls_another_over_a_real_socket() {
    let (told, heard) = channel();
    let start = Instant::now();

    let mut answering_end =
        Runtime::bind(EndpointConfig::default(), [7; 32], loopback()).expect("the callee binds");
    let mut dialling_end =
        Runtime::bind(EndpointConfig::default(), [11; 32], loopback()).expect("the caller binds");
    let (here, there) = (dialling_end.local(), answering_end.local());

    let listening = answering_end.transport();
    answering_end
        .agent()
        .add_account(account("bob", there, here, listening));
    let dialling_on = dialling_end.transport();
    let line = dialling_end
        .agent()
        .add_account(account("alice", here, there, dialling_on));

    let answering = told.clone();
    let listener = thread::spawn(move || {
        let mut handler = Callee {
            notes: answering,
            started: start,
            done: false,
        };
        answering_end.run(&mut handler).expect("the answering loop");
    });
    let dialling = told.clone();
    let placer = thread::spawn(move || {
        let mut handler = Caller {
            notes: dialling,
            started: start,
            account: line,
            dialled: false,
            done: false,
        };
        dialling_end.run(&mut handler).expect("the dialling loop");
    });
    drop(told);

    let mut seen = Vec::new();
    while let Ok(note) = heard.recv_timeout(PATIENCE) {
        seen.push(note);
        if seen.iter().filter(|note| **note == Note::Over).count() == 2 {
            break;
        }
    }
    listener.join().expect("the answering thread");
    placer.join().expect("the dialling thread");

    assert!(seen.contains(&Note::Ringing), "180 arrived: {seen:?}");
    assert!(
        seen.iter().filter(|note| **note == Note::Up).count() == 1,
        "the call came up once: {seen:?}"
    );
    assert!(
        seen.iter().filter(|note| **note == Note::Held).count() == 2,
        "both ends know it is held: {seen:?}"
    );
    assert!(
        seen.iter().filter(|note| **note == Note::Over).count() == 2,
        "and both ends know it is over: {seen:?}"
    );
}
