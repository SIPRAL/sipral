// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! An agent with no device anywhere near it: it answers whatever calls it,
//! and repeats back whatever it hears, one twenty-millisecond frame later.
//!
//! No registrar — dial it directly at the address it prints. It still holds
//! one account, never registered, purely so the `Contact` on a call it
//! answers is a real address rather than an empty one (RFC 3261 §12.1.1); a
//! caller that got an empty `Contact` back would have nowhere to send the
//! rest of the dialog and would drop the call rather than complete it.
//!
//! ```text
//! cargo run --example headless-agent -- --host 127.0.0.1 --port 5070
//! ```
//!
//! `--host` names a real, routable address rather than defaulting to a
//! wildcard one: that address is what every call's offer or answer
//! advertises, and a peer handed `0.0.0.0` has nowhere to send anything
//! back to (`crates/sipral/examples/common/udp_endpoint.rs`'s own doc). On a
//! machine reachable from elsewhere, name the interface that is.
//!
//! This is the shape a voice agent embeds: a socket, a
//! [`sipral::UserAgent`], a [`sipral::MediaEngine`], and PCM in `i16` frames
//! that something other than an earpiece is free to read and write —
//! whatever answers here could as well be a model instead of an echo.

// the no-panic discipline is for what ships; the test at the bottom is
// allowed the shortcuts a test is for
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

#[path = "common/media_socket.rs"]
mod media_socket;
#[path = "common/udp_endpoint.rs"]
mod udp_endpoint;

use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::{
    Account, CallHandle, CodecCatalog, EndpointConfig, Event, MediaConfig, MediaEngine, UaEvent,
    Uri, UserAgent, WallClock,
};

use udp_endpoint::Endpoint;

/// One call's worth of what it said last turn, played back this turn.
type Echoes = HashMap<CallHandle, Vec<i16>>;

/// `--host <address>` and `--port <n>`, in either order, each defaulting to
/// loopback and 5070 — a real address either way, never a wildcard one.
fn args_or_defaults() -> (std::net::IpAddr, u16) {
    let mut host = std::net::IpAddr::from([127, 0, 0, 1]);
    let mut port = 5070_u16;
    let mut args = env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--host" => {
                if let Some(value) = args.next().and_then(|text| text.parse().ok()) {
                    host = value;
                }
            }
            "--port" => {
                if let Some(value) = args.next().and_then(|text| text.parse().ok()) {
                    port = value;
                }
            }
            _ => {}
        }
    }
    (host, port)
}

/// Answer whatever just arrived, and let every call's session move one frame:
/// what it said comes back out, and what it says now is kept for the next
/// turn.
fn tick(endpoint: &mut Endpoint, echoes: &mut Echoes, now: Instant) -> bool {
    for event in endpoint.pump(now) {
        match event {
            Event::Signalling(UaEvent::IncomingCall { call, .. }) => {
                if let Ok(local) = endpoint.open_media(call, now) {
                    let _ = endpoint
                        .engine
                        .answer(&mut endpoint.agent, call, local, now);
                }
            }
            Event::Signalling(UaEvent::CallEnded { call, .. }) => {
                echoes.remove(&call);
                // Without this, every call this agent has ever answered
                // keeps its bound RTP socket alive in `endpoint.media` for
                // the rest of the process's life — harmless for the examples
                // that place one call and exit, real for the one that keeps
                // answering (`Endpoint::close_media`'s own doc).
                endpoint.close_media(call);
            }
            _ => {}
        }
    }
    endpoint.run_media(now, |call, media, session, now| {
        // one closure plays what was captured last turn, the other captures
        // what is heard this turn — two different `Vec`s, since both
        // closures exist at once and neither may borrow the same one
        let said_last_turn = echoes.remove(&call).unwrap_or_default();
        let mut said_this_turn = Vec::with_capacity(said_last_turn.len());
        media.turn(
            session,
            now,
            |room| {
                let filled = room.len().min(said_last_turn.len());
                if let Some(dst) = room.get_mut(..filled) {
                    dst.copy_from_slice(said_last_turn.get(..filled).unwrap_or(&[]));
                }
                if let Some(rest) = room.get_mut(filled..) {
                    rest.fill(0);
                }
            },
            |room| said_this_turn.extend_from_slice(room),
        );
        echoes.insert(call, said_this_turn);
    });
    endpoint.timers(now);
    endpoint.read_sip(now)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (host, port) = args_or_defaults();
    let now = Instant::now();
    let agent = UserAgent::new(EndpointConfig::default(), [0x5a; 32])?;
    let engine = MediaEngine::new(
        CodecCatalog::new(),
        MediaConfig::default(),
        WallClock::from_unix(now, 0, 0),
        [0x5b; 32],
    );
    // A real address, not a wildcard: `Endpoint::bind`'s own documentation
    // says why — it becomes what every call's offer or answer advertises,
    // and a peer handed `0.0.0.0` has nowhere to send anything back to.
    let mut endpoint = Endpoint::bind(SocketAddr::new(host, port), agent, engine, now)?;
    let identity = Uri::parse_str(&format!("sip:agent@{}", endpoint.local))?;
    endpoint.add_account(Account::unregistered(
        identity.clone(),
        identity,
        endpoint.transport,
        endpoint.local,
    ));
    println!(
        "listening on {}; dial sip:agent@{}",
        endpoint.local, endpoint.local
    );

    let mut echoes = Echoes::new();
    loop {
        if !tick(&mut endpoint, &mut echoes, Instant::now()) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use sipral::{Account, OutgoingCall, Uri};

    use super::*;

    /// Two stacks on loopback: this crate's own agent answers, and a second
    /// endpoint places a call at it, says something, and hears it again.
    ///
    /// Run more than once before giving up: on a machine doing other heavy
    /// work at the same time (this workspace's own build is run four ways at
    /// once), a real UDP send can sit long enough in the kernel's queue that
    /// the jitter buffer reads the gap as a lost source and reopens RFC
    /// 3550's probation on the very packet meant to prove the round trip.
    /// Each attempt is a full, independent call on its own pair of sockets,
    /// so only a repeated failure to hear anything back fails the test.
    #[test]
    fn echoes_what_it_hears() {
        let mut last_failure = String::new();
        for _ in 0..3 {
            match one_call() {
                Ok(()) => return,
                Err(reason) => last_failure = reason,
            }
        }
        panic!("{last_failure}");
    }

    fn one_call() -> Result<(), String> {
        let now = Instant::now();
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        // G.711 rather than this crate's own default catalogue: it encodes
        // each sample on its own rather than perceptually, so a steady tone
        // survives the round trip recognisably, which is all this test reads.
        let codecs = || CodecCatalog::with_order(&["PCMU", "PCMA"]).unwrap();

        let mut agent_endpoint = Endpoint::bind(
            loopback,
            UserAgent::new(EndpointConfig::default(), [0x11; 32]).unwrap(),
            MediaEngine::new(
                codecs(),
                MediaConfig::default(),
                WallClock::from_unix(now, 0, 0),
                [0x12; 32],
            ),
            now,
        )
        .unwrap();
        let agent_identity =
            Uri::parse_str(&format!("sip:agent@{}", agent_endpoint.local)).unwrap();
        agent_endpoint.add_account(Account::unregistered(
            agent_identity.clone(),
            agent_identity,
            agent_endpoint.transport,
            agent_endpoint.local,
        ));
        let mut echoes = Echoes::new();

        let mut caller_endpoint = Endpoint::bind(
            loopback,
            UserAgent::new(EndpointConfig::default(), [0x21; 32]).unwrap(),
            MediaEngine::new(
                codecs(),
                MediaConfig::default(),
                WallClock::from_unix(now, 0, 0),
                [0x22; 32],
            ),
            now,
        )
        .unwrap();

        let aor = Uri::parse_str("sip:caller@invalid.example").unwrap();
        let contact = Uri::parse_str(&format!("sip:caller@{}", caller_endpoint.local)).unwrap();
        let account = caller_endpoint.add_account(Account::unregistered(
            aor,
            contact,
            caller_endpoint.transport,
            agent_endpoint.local,
        ));
        let target = Uri::parse_str(&format!("sip:agent@{}", agent_endpoint.local)).unwrap();
        let outgoing =
            OutgoingCall::new(target).to_address(caller_endpoint.transport, agent_endpoint.local);
        let call = udp_endpoint::place(&mut caller_endpoint, account, outgoing, now).unwrap();

        // What the caller says once the call is up, and what it heard back —
        // filled and read by the run_media closures below, once the call
        // moves past `CallConfirmed`. The tone starts only once a few silent
        // frames have gone first: RFC 3550 appendix A.1's own source
        // validation drops the very first packet or two of a new SSRC on
        // probation (`MIN_SEQUENTIAL`), and a tone sent only in that first
        // packet would prove nothing but the drop.
        let mut frames_sent = 0_u32;
        let mut heard: Vec<i16> = Vec::new();
        let mut up = false;
        const TONE: i16 = 8_000;
        const WARM_UP_FRAMES: u32 = 5;

        // Runs until the tone has plainly come back, or the deadline says it
        // never will — not until `heard` reaches some fixed length, since the
        // early frames the agent echoes are its own opening silence and only
        // a loud one proves anything.
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline && !(up && heard.iter().any(|sample| sample.abs() > 1_000))
        {
            let turn = Instant::now();
            for event in caller_endpoint.pump(turn) {
                if matches!(
                    event,
                    Event::Signalling(sipral::UaEvent::CallConfirmed { call: this, .. })
                        if this == call
                ) {
                    up = true;
                }
            }
            tick(&mut agent_endpoint, &mut echoes, turn);
            if up {
                caller_endpoint.run_media(turn, |this, media, session, now| {
                    if this != call {
                        return;
                    }
                    media.turn(
                        session,
                        now,
                        |room| {
                            frames_sent += 1;
                            if frames_sent >= WARM_UP_FRAMES {
                                room.fill(TONE);
                            } else {
                                room.fill(0);
                            }
                        },
                        |room| heard.extend_from_slice(room),
                    );
                });
            }
            caller_endpoint.timers(turn);
            agent_endpoint.timers(turn);
            let caller_read = caller_endpoint.read_sip(turn);
            let agent_read = agent_endpoint.read_sip(turn);
            if !caller_read && !agent_read {
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        if !up {
            return Err("the call never reached CallConfirmed".to_owned());
        }
        if !heard.iter().any(|sample| sample.abs() > 1_000) {
            return Err(format!(
                "nothing came back louder than silence in {} samples — the agent did not echo it",
                heard.len()
            ));
        }
        Ok(())
    }
}
