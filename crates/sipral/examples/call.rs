// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Dial a public test extension with no account and no configuration, and
//! hear it read digits back.
//!
//! `sip:thetestcall@sip2sip.info` is sip2sip.info's own IVR, published for
//! exactly this: reachable by anyone, no registration needed. Option 2 reads
//! back whatever digits you send it; option 3 is a plain echo. Run this with
//!
//! ```text
//! cargo run --example call
//! ```
//!
//! and it dials it, waits for the greeting, presses 2, sends a short digit
//! string, and plays what comes back through the default output device. On a
//! machine with no audio device — or with `--wav out.wav` on any machine — it
//! writes what it heard into a WAV file instead.
//!
//! What this file is actually demonstrating is the shape every application
//! embedding this stack has: a [`sipral::UserAgent`] and a
//! [`sipral::MediaEngine`] driven over sockets the application owns
//! (`udp_endpoint.rs`), and one call's audio pumped through a socket of its
//! own (`media_socket.rs`) into whatever plays or records it. Nothing here is
//! specific to sip2sip.info beyond the URI and the two digit strings.

#[path = "common/entropy.rs"]
mod entropy;
#[path = "common/media_socket.rs"]
mod media_socket;
#[path = "common/srv.rs"]
mod srv;
#[path = "common/udp_endpoint.rs"]
mod udp_endpoint;
#[path = "common/wav.rs"]
mod wav;

use std::env;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sipral::{
    Account, CodecCatalog, DEFAULT_DIGIT, EndpointConfig, Event, MediaConfig, MediaEngine,
    MediaEvent, OutgoingCall, UaEvent, Uri, UserAgent, WallClock,
};

#[cfg(any(target_os = "macos", target_os = "ios"))]
use sipral_io_coreaudio::{Stream, StreamConfig, StreamFormat};

use udp_endpoint::Endpoint;

/// sip2sip.info's own test extension. No account reaches it because none is
/// needed — see the module doc.
const TARGET: &str = "sip:thetestcall@sip2sip.info";
const SERVER: &str = "sip2sip.info";
const SIP_PORT: u16 = 5060;

/// How long after the call connects before anything is pressed, so the
/// greeting has had a moment to start.
const GREETING: Duration = Duration::from_millis(1_500);

/// The script this example plays into the IVR once it is up: how long after
/// the call connects, and what to send. `"2"` selects "read my digits back";
/// the string after it is what gets read back.
///
/// The digits wait until the IVR has finished asking for them: sent at four
/// and a half seconds they landed in the middle of its own prompt, which it
/// does not listen through, and nothing was ever read back.
const SCRIPT: &[(Duration, &str)] = &[(GREETING, "2"), (Duration::from_millis(8_000), "1234#")];

/// How long this end waits, in total, before hanging up regardless of what
/// the IVR did — long enough to hear the digits read back, short enough that
/// a demo that goes wrong does not sit on the line.
const CEILING: Duration = Duration::from_secs(25);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let wav_path = wav_path_from_args();

    // the domain's SRV record, not its own address, which refuses SIP
    let remote: SocketAddr = srv::resolve(SERVER, "_sip._udp", SIP_PORT)?;
    let bind_addr = SocketAddr::new(udp_endpoint::route_to(remote), 0);
    let now = Instant::now();
    let unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());

    // Both G.711 laws are eight kilohertz, twenty-millisecond frames — the
    // same shape as `StreamFormat::narrowband()` below — so whichever the far
    // end prefers, nothing here has to resample to play or record it.
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"])?;
    let engine = MediaEngine::new(
        catalog,
        MediaConfig::default(),
        WallClock::from_unix(now, unix_seconds, 0),
        entropy::seed()?,
    );
    let agent = UserAgent::new(EndpointConfig::default(), entropy::seed()?)?;
    let mut endpoint = Endpoint::bind(bind_addr, agent, engine, now)?;

    // Nobody at sip2sip.info reads this identity; it exists because every
    // call needs a `From`. `Account::unregistered` is the account for a line
    // that reaches its destination without a binding to keep alive — see its
    // own documentation.
    let aor = Uri::parse_str("sip:sipral-example@invalid.example")?;
    let contact = Uri::parse_str(&format!("sip:sipral-example@{}", endpoint.local))?;
    let account = endpoint.add_account(Account::unregistered(
        aor,
        contact,
        endpoint.transport,
        remote,
    ));

    let outgoing =
        OutgoingCall::new(Uri::parse_str(TARGET)?).to_address(endpoint.transport, remote);
    let call = udp_endpoint::place(&mut endpoint, account, outgoing, now)?;
    println!("calling {TARGET} ...");

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let mut speaker = if wav_path.is_none() {
        let mut stream = Stream::open(StreamConfig::new(StreamFormat::narrowband()))?;
        stream.start()?;
        Some(stream)
    } else {
        None
    };
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let (heard, sample_rate_hz) = converse(&mut endpoint, call, |room| {
        if let Some(stream) = speaker.as_mut() {
            let _ = stream.write(room);
        }
    });
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let (heard, sample_rate_hz) = converse(&mut endpoint, call, |_room| {});

    if let Some(path) = wav_path_or_default(wav_path) {
        wav::write(&path, sample_rate_hz, &heard)?;
        println!("wrote {} samples ({path})", heard.len());
    }
    Ok(())
}

/// The call itself, once it is placed: wait for it to connect, run the
/// [`SCRIPT`] of digits into it, and play or record whatever comes back,
/// through `play`, until the far end hangs up or [`CEILING`] runs out —
/// hanging up from here otherwise. Returns everything heard, and the sample
/// rate it was heard at, for the caller to write into a WAV file.
fn converse(
    endpoint: &mut Endpoint,
    call: sipral::CallHandle,
    mut play: impl FnMut(&[i16]),
) -> (Vec<i16>, u32) {
    let mut heard: Vec<i16> = Vec::new();
    // overwritten as soon as `MediaEvent::Started` gives the real rate; used
    // for the WAV header only if the call ends before that happens
    let mut sample_rate_hz = 8_000_u32;
    let mut confirmed_at: Option<Instant> = None;
    let mut next_step = 0_usize;
    let mut ended = false;
    let deadline = Instant::now() + CEILING;

    while !ended && Instant::now() < deadline {
        let now = Instant::now();
        for event in endpoint.pump(now) {
            match event {
                Event::Signalling(UaEvent::CallConfirmed { call: this, .. }) if this == call => {
                    println!("connected");
                    confirmed_at = Some(now);
                }
                Event::Signalling(UaEvent::CallEnded {
                    call: this, reason, ..
                }) if this == call => {
                    println!("call ended: {reason}");
                    ended = true;
                }
                Event::Media {
                    call: this,
                    event: MediaEvent::Started { codec, .. },
                } if this == call => {
                    println!("media started on {}", codec.encoding_name());
                }
                _ => {}
            }
        }

        next_step = send_scripted_digit(endpoint, call, confirmed_at, next_step, now);

        endpoint.run_media(now, |this, media, session, now| {
            if this != call {
                return;
            }
            sample_rate_hz = session.sample_rate();
            media.turn(
                session,
                now,
                // Nothing is sent from this end beyond the digits above: the
                // point of this call is to hear the IVR, not to speak to it.
                |room| room.fill(0),
                |room| {
                    heard.extend_from_slice(room);
                    play(room);
                },
            );
        });

        endpoint.timers(now);
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    if !ended {
        hang_up_and_drain(endpoint, call);
    }
    (heard, sample_rate_hz)
}

/// The next entry of [`SCRIPT`] due, if the call has connected and its time
/// has come: sent, and the index of the one after it. Otherwise `next_step`
/// unchanged.
fn send_scripted_digit(
    endpoint: &mut Endpoint,
    call: sipral::CallHandle,
    confirmed_at: Option<Instant>,
    next_step: usize,
    now: Instant,
) -> usize {
    let Some(started) = confirmed_at else {
        return next_step;
    };
    let Some((at, digits)) = SCRIPT.get(next_step) else {
        return next_step;
    };
    if now < started + *at {
        return next_step;
    }
    if let Some(mut session) = endpoint.engine.session(call) {
        println!("sending {digits}");
        let _ = session.dial(digits, DEFAULT_DIGIT);
    }
    next_step + 1
}

/// Hang up a call [`converse`] gave up on rather than one the far end ended,
/// and give the BYE a moment to actually leave before the process does.
fn hang_up_and_drain(endpoint: &mut Endpoint, call: sipral::CallHandle) {
    let _ = endpoint.agent.hangup(call, Instant::now());
    let settle = Instant::now() + Duration::from_millis(500);
    while Instant::now() < settle {
        let now = Instant::now();
        endpoint.pump(now);
        endpoint.timers(now);
        if !endpoint.read_sip(now) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// `--wav <path>`, when it was given.
fn wav_path_from_args() -> Option<String> {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--wav" {
            return args.next();
        }
    }
    None
}

/// Where to write the WAV file: what `--wav` named, or, on a target with no
/// audio device to play through instead, `call.wav` — so that "zero
/// configuration" holds everywhere this crate builds, not only on macOS.
fn wav_path_or_default(explicit: Option<String>) -> Option<String> {
    if explicit.is_some() {
        return explicit;
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        None
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        Some("call.wav".to_owned())
    }
}
