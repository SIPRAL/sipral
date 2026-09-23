// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A minimal reference agent, over the socket path: connects, answers by
//! doing nothing (the application on the other end decides that — see
//! `crates/sipral/examples/headless-socket-agent.rs`'s own doc comment),
//! echoes whatever audio it hears one frame later, and hangs up the moment
//! it hears the digit `#`.
//!
//! Depends on nothing but `sipral-headless` itself and the standard library
//! — no `sipral`, no SIP, no RTP, no audio device — which is the whole pitch
//! of the crate this ships in: whatever answers here could as well be a
//! speech model instead of an echo, and it would still depend on nothing
//! more than this.
//!
//! Deliberately below `Decoder` (`crate::codec`), which needs an
//! [`AudioConfig`](crate::AudioConfig) before it can be built at all: this
//! agent has not been told one when the connection opens — [`SessionOpen`]
//! is the first thing that names it — so it reads frames with
//! [`FrameDecoder`] directly and reads the kind byte itself, exactly the
//! bootstrap `ControlMessage::decode`'s own documentation assumes a caller
//! does before any audio has a rate to be validated against. It never needs
//! one afterwards either: an echo forwards whatever bytes a frame carried,
//! at whatever size they arrived in, without ever decoding them into
//! samples.
//!
//! ```text
//! cargo run --example agent -p sipral-headless -- --addr 127.0.0.1:7001
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::VecDeque;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use sipral_headless::{
    ControlMessage, FrameDecoder, FrameKind, Hangup, MAX_CONTROL_PAYLOAD, write_frame,
};

/// How many frames of delay the echo holds — one, the way
/// `crates/sipral/examples/headless-agent.rs`'s own echo does: what the
/// caller said comes back exactly one frame later, never in the same tick it
/// arrived in.
const ECHO_DELAY: usize = 1;

/// How long this binary keeps retrying the connection before giving up —
/// long enough that the application side of a lab or a compose file can
/// still be starting when this one is.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

fn addr() -> String {
    let mut it = env::args().skip(1);
    while let Some(flag) = it.next() {
        if flag == "--addr"
            && let Some(value) = it.next()
        {
            return value;
        }
    }
    "127.0.0.1:7001".to_owned()
}

fn connect(addr: &str) -> std::io::Result<TcpStream> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => return Ok(stream),
            Err(error) if Instant::now() < deadline => {
                eprintln!("waiting for {addr}: {error}");
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(error) => return Err(error),
        }
    }
}

fn main() -> std::io::Result<()> {
    let target = addr();
    println!("connecting to {target}");
    let mut stream = connect(&target)?;
    println!("connected");

    // A bound generous enough for this session's audio at any rate this
    // protocol allows (48 kHz, 20 ms is 1_920 bytes) and every control
    // message this crate defines; not tied to any one call's own audio,
    // since none has been named yet — see this file's own doc comment.
    let max_payload = u16::try_from(MAX_CONTROL_PAYLOAD.max(4_096)).unwrap_or(u16::MAX);
    let mut frames = FrameDecoder::new(max_payload);
    let mut read_buf = [0_u8; 4_096];
    let mut out = Vec::new();
    let mut echo: VecDeque<Vec<u8>> = VecDeque::new();
    let mut call_id = String::new();

    loop {
        let read = stream.read(&mut read_buf)?;
        if read == 0 {
            println!("the application's socket closed");
            return Ok(());
        }
        frames.push(read_buf.get(..read).unwrap_or_default());

        loop {
            let frame = match frames.next_frame() {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(error) => {
                    eprintln!("malformed frame: {error}");
                    return Ok(());
                }
            };
            let Ok(kind) = FrameKind::try_from(frame.kind()) else {
                continue;
            };
            if kind == FrameKind::Audio {
                echo.push_back(frame.payload().to_vec());
                if echo.len() > ECHO_DELAY
                    && let Some(due) = echo.pop_front()
                {
                    let _ = write_frame(FrameKind::Audio.to_u8(), &due, &mut out);
                }
                continue;
            }
            match ControlMessage::decode(frame.kind(), frame.payload()) {
                Ok(ControlMessage::IncomingCall(incoming)) => {
                    call_id.clone_from(&incoming.call_id);
                    println!("call {call_id} from {}", incoming.caller);
                }
                Ok(ControlMessage::CallState(state)) => {
                    println!("call {} state: {:?}", state.call_id, state.state);
                }
                Ok(ControlMessage::DtmfReceived(received)) => {
                    println!("dtmf {}", received.digit.get());
                    if received.digit.get() == '#' {
                        let hangup = ControlMessage::Hangup(Hangup {
                            call_id: call_id.clone(),
                            reason: Some("agent finished".to_owned()),
                        });
                        if let Ok(bytes) = hangup.to_json_bytes() {
                            let _ = write_frame(hangup.kind().to_u8(), &bytes, &mut out);
                        }
                    }
                }
                Ok(ControlMessage::VoiceActivity(activity)) => {
                    println!(
                        "call {} {}",
                        activity.call_id,
                        if activity.speaking { "speaking" } else { "quiet" }
                    );
                }
                Ok(_) => {}
                Err(error) => eprintln!("malformed control message: {error}"),
            }
        }

        if !out.is_empty() {
            stream.write_all(&out)?;
            out.clear();
        }
    }
}
