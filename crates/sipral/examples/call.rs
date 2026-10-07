// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Dial a public test extension with no account or configuration and hear it read digits back.
//!
//! `sip:thetestcall@sip2sip.info` is sip2sip.info's public IVR, reachable without registration.
//! Option 2 reads back the digits you send; option 3 is an echo. Run
//!
//! ```text
//! cargo run --example call
//! ```
//!
//! It dials, waits for the greeting, presses 2, sends a short digit string, and plays the reply on
//! the default output device, or writes it to a WAV file on a machine without audio or with `--wav
//! out.wav`.
//!
//! It shows the shape of every embedding application: a [`sipral::UserAgent`] and a
//! [`sipral::MediaEngine`] over application-owned sockets (`udp_endpoint.rs`), and one call's audio
//! through its own socket (`media_socket.rs`) into whatever plays or records it. Only the URI and
//! the digit strings are specific to sip2sip.info.

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

/// sip2sip.info's test extension; no account needed (see the module docs).
const TARGET: &str = "sip:thetestcall@sip2sip.info";
const SERVER: &str = "sip2sip.info";
const SIP_PORT: u16 = 5060;

/// How long after the call connects before anything is pressed, so the
/// greeting has had a moment to start.
const GREETING: Duration = Duration::from_millis(1_500);

/// The digits sent to the IVR once the call is up, with their delay after connecting. `"2"` selects
/// "read my digits back"; the next string is what gets read back.
///
/// The digits wait for the prompt to finish: sent at 4.5 s they arrived during the prompt, which
/// the IVR does not listen through.
const SCRIPT: &[(Duration, &str)] = &[(GREETING, "2"), (Duration::from_millis(8_000), "1234#")];

/// Total time before hanging up regardless: enough to hear the digits read back, short enough that
/// a failed demo does not hang on the line.
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

    // both G.711 laws are 8 kHz with 20 ms frames, like `StreamFormat::narrowband()` below, so
    // nothing needs resampling
    let catalog = CodecCatalog::with_order(&["PCMU", "PCMA"])?;
    let engine = MediaEngine::new(
        catalog,
        MediaConfig::default(),
        WallClock::from_unix(now, unix_seconds, 0),
        entropy::seed()?,
    );
    let agent = UserAgent::new(EndpointConfig::default(), entropy::seed()?)?;
    let mut endpoint = Endpoint::bind(bind_addr, agent, engine, now)?;

    // nobody reads this identity; every call needs a `From`. `Account::unregistered` is for lines
    // that need no binding
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

/// Run the placed call: wait for it to connect, send the [`SCRIPT`] digits, and play or record the
/// reply through `play` until the far end hangs up or [`CEILING`] passes, then hang up. Returns
/// everything heard and its sample rate, for the WAV file.
fn converse(
    endpoint: &mut Endpoint,
    call: sipral::CallHandle,
    mut play: impl FnMut(&[i16]),
) -> (Vec<i16>, u32) {
    let mut heard: Vec<i16> = Vec::new();
    // replaced by the real rate on `MediaEvent::Started`; used only if the call ends before that
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
                // nothing is sent beyond the digits: the point is to hear the IVR
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

/// Send the next [`SCRIPT`] entry if the call is up and it is due, returning the next index;
/// otherwise `next_step` unchanged.
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

/// Hang up a call [`converse`] gave up on, and give the BYE a moment to leave before the process
/// exits.
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

/// The WAV path: `--wav`, or `call.wav` on targets with no audio device, so it works without
/// configuration everywhere.
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
