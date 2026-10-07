// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! SIP over a WebSocket the stack opens itself (RFC 7118), straight at
//! Asterisk's `res_http_websocket`.
//!
//! This harness opens a TCP connection to Asterisk's HTTP server and binds
//! it as a `Ws` transport with its far end named; everything after that is
//! the stack's: the handshake asking for `sip` on `/ws`, every message in a
//! masked frame, the `.invalid` host in the `Via` and the `Contact`
//! (the lab Asterisk's own `labuser-ws`, in `interop/asterisk/`). The account
//! registers, a call goes to the echo over the WebSocket with its audio on RTP
//! as any
//! other, the echo is heard, the call is hung up, the binding given back,
//! and the WebSocket closed from this end and answered (RFC 6455 §7.1.2).
//!
//! # Over TLS
//!
//! The `wss` flow is the same call over Asterisk's TLS listener on 8089
//! (`interop/wss/`), as `labuser-wss`. The TLS is the application's, as the
//! stack has it: here a `socat` beside the harness that checks Asterisk's
//! certificate against the lab authority and hands the harness a plain
//! connection on loopback. The harness binds that connection as `Wss` with
//! Asterisk's own address named, and the account names the `Host` and
//! resource (`Account::websocket_target`), the way an application reaching a
//! server by name does.
//!
//! # What fails it
//!
//! The connection refused, the registration never granted, the call never
//! coming up, fewer than [`AUDIBLE_WANTED`] audible frames back from the
//! echo, the BYE never answered, the close not answered, or the stack giving
//! the WebSocket up
//! (`UserAgent::websocket_failure` says why).

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use sipral::{
    Account, CallMedia, Credentials, Event, Input, MediaConfig, MediaEvent, OutgoingCall,
    TransportId, TransportProtocol, UaEvent, WebSocketTarget,
};

/// Where one run of the flow goes.
pub(crate) struct Lab<'a> {
    /// The SIP domain, `asterisk`.
    pub(crate) server: &'a str,
    /// Asterisk's WebSocket listener: the far end the transport is bound to.
    pub(crate) websocket: SocketAddr,
    /// Where the connection is made: `websocket` itself, or the local end
    /// of whatever secures it.
    pub(crate) connect: SocketAddr,
    /// `Ws`, or `Wss` over a connection secured below.
    pub(crate) protocol: TransportProtocol,
    /// The `Host` the account names for the handshake, or `None` to set the
    /// target for the address (`UserAgent::set_websocket_target`).
    pub(crate) host: Option<&'a str>,
    pub(crate) user: &'a str,
    pub(crate) pass: &'a str,
}

use crate::{Endpoint, catalog, place_call, route_to, run_folded, uri};

/// `interop/asterisk/extensions.conf`'s echo.
const ECHO_EXTENSION: &str = "9008";

/// This flow's own endpoint identity (`main.rs`'s
/// `tests::endpoint_identity_constants_are_distinct`).
pub(crate) const SEED: u8 = 226;
pub(crate) const MEDIA_SEED: u8 = 228;

/// The WebSocket's transport, beside the endpoint's own UDP one.
const WS: TransportId = TransportId(2);

const PATIENCE: Duration = Duration::from_secs(20);
const LISTEN: Duration = Duration::from_secs(3);
const ENDING: Duration = Duration::from_secs(5);

/// Audible frames wanted back from the echo: half a second of them.
const AUDIBLE_WANTED: u32 = 25;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stage {
    Registering,
    Calling,
    Listening,
    Ending,
    Unregistering,
    Closing,
}

/// The connection under the WebSocket: what the stack wants written goes on
/// it, and what arrives on it goes to the stack.
struct Connection {
    socket: TcpStream,
    inbox: Vec<u8>,
}

impl Connection {
    /// Everything waiting to go: frames on the WebSocket, datagrams (RTCP is
    /// the media engine's) on the endpoint's own socket.
    fn flush(&mut self, endpoint: &mut Endpoint) -> Result<(), String> {
        while let Some(transmit) = endpoint.agent.poll_transmit() {
            if transmit.transport == WS {
                self.socket
                    .write_all(&transmit.payload)
                    .map_err(|error| format!("the connection would not take a write: {error}"))?;
            } else {
                let _ = endpoint
                    .sip
                    .send_to(&transmit.payload, transmit.destination);
            }
        }
        Ok(())
    }

    /// Hand the stack whatever the connection has; `false` when nothing
    /// was there. Once the WebSocket is over, the connection is only waited
    /// on: the server closes it after its close frame, as §7.1.1 has it.
    fn read(&mut self, endpoint: &mut Endpoint, now: Instant) -> Result<bool, String> {
        if !endpoint.agent.runs_websocket(WS) {
            return Ok(false);
        }
        match self.socket.read(&mut self.inbox) {
            Ok(0) => {
                let _ = endpoint
                    .agent
                    .receive(Input::StreamClosed { transport: WS }, now);
                Err("Asterisk closed the connection".to_owned())
            }
            Ok(read) => {
                let data = self.inbox.get(..read).unwrap_or_default();
                let _ = endpoint.agent.receive(
                    Input::StreamData {
                        transport: WS,
                        data,
                    },
                    now,
                );
                Ok(true)
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(format!("the connection failed: {error}")),
        }
    }
}

/// Register over the WebSocket, call the echo, hear it, hang up, give the
/// binding back.
///
/// # Errors
/// The first thing that was not as it has to be.
#[allow(clippy::too_many_lines)]
pub(crate) fn run(lab: &Lab<'_>) -> Result<String, String> {
    let Lab {
        server,
        websocket,
        connect,
        protocol,
        host,
        user,
        pass,
    } = *lab;
    let now = Instant::now();
    let mut endpoint = Endpoint::bind(
        run_folded([SEED; 32]),
        run_folded([MEDIA_SEED; 32]),
        SocketAddr::new(route_to(websocket), 0),
        catalog(),
        now,
    )
    .map_err(|error| format!("cannot bind: {error}"))?;
    let socket = TcpStream::connect_timeout(&connect, Duration::from_secs(5))
        .map_err(|error| format!("cannot connect to {connect}: {error}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|error| format!("cannot make the connection non-blocking: {error}"))?;
    let _ = socket.set_nodelay(true);
    let local = socket
        .local_addr()
        .map_err(|error| format!("the connection has no address: {error}"))?;
    let mut connection = Connection {
        socket,
        inbox: vec![0_u8; 65_535],
    };

    let scheme = if protocol == TransportProtocol::Wss {
        "wss"
    } else {
        "ws"
    };
    let mut account = Account::new(
        uri(&format!("sip:{user}@{server}"))?,
        uri(&format!("sip:{server};transport={scheme}"))?,
        uri(&format!("sip:{user}@{local}"))?,
        WS,
        websocket,
    )
    .credentials(Credentials::new(user, pass))
    .expires(Duration::from_secs(300));
    if let Some(host) = host {
        account = account
            .websocket_target(Some(host), Some("/ws"))
            .map_err(|error| format!("a target the account refused: {error}"))?;
    } else {
        let target = WebSocketTarget::new(&format!("{server}:{}", websocket.port()), "/ws")
            .map_err(|error| format!("a target the stack refused: {error}"))?;
        endpoint.agent.set_websocket_target(websocket, target);
    }
    let account = endpoint.agent.add_account(account);
    endpoint
        .agent
        .receive(
            Input::TransportBound {
                transport: WS,
                protocol,
                local,
                remote: Some(websocket),
            },
            now,
        )
        .map_err(|error| format!("cannot bind the WebSocket: {error}"))?;
    endpoint
        .agent
        .register(account, now)
        .map_err(|error| format!("cannot register: {error}"))?;

    let target = uri(&format!("sip:{ECHO_EXTENSION}@{server}"))?;
    let mut stage = Stage::Registering;
    let mut call = None;
    let mut since = now;
    let mut heard = 0_u32;
    let mut ended = false;
    let mut story: Vec<String> = Vec::new();

    loop {
        let now = Instant::now();
        // what the last turn queued goes on the connection before the pump
        // below, whose own flush only knows the endpoint's datagram socket
        connection.flush(&mut endpoint)?;
        for event in endpoint.pump(now) {
            match event {
                Event::Signalling(UaEvent::Registered { .. }) if stage == Stage::Registering => {
                    story.push("registered".to_owned());
                    stage = Stage::Calling;
                    since = now;
                    let media = CallMedia::new(catalog(), MediaConfig::default());
                    let outgoing = OutgoingCall::new(target.clone()).to_address(WS, websocket);
                    call = Some(place_call(
                        &mut endpoint,
                        account,
                        outgoing,
                        media,
                        websocket,
                        now,
                    )?);
                }
                Event::Signalling(UaEvent::RegistrationFailed { reason, .. }) => {
                    return Err(format!("the registration failed: {reason:?}"));
                }
                Event::Media {
                    event: MediaEvent::Started { .. },
                    ..
                } if stage == Stage::Calling => {
                    story.push("the call came up".to_owned());
                    stage = Stage::Listening;
                    since = now;
                }
                Event::Signalling(UaEvent::CallEnded { reason, .. }) => {
                    story.push(format!("the call ended {reason}"));
                    ended = true;
                }
                Event::Signalling(UaEvent::Unregistered { .. })
                    if stage == Stage::Unregistering =>
                {
                    story.push("the binding was given back".to_owned());
                    endpoint.agent.close_websocket(WS, now);
                    stage = Stage::Closing;
                    since = now;
                }
                Event::Signalling(UaEvent::Unclaimed(
                    sipral_core::endpoint::Event::FlowFailed { transport },
                )) if transport == WS && stage == Stage::Closing => {
                    let closed = endpoint
                        .agent
                        .websocket_failure(WS)
                        .is_some_and(|(_, why)| why == "closed by this end");
                    if !closed {
                        return Err(format!("the close was not answered [{}]", story.join(", ")));
                    }
                    story.push("the WebSocket closed both ways".to_owned());
                    return Ok(format!(
                        "   ({heard} audible frames back over a {} call; {})",
                        if protocol == TransportProtocol::Wss {
                            "secure WebSocket"
                        } else {
                            "WebSocket"
                        },
                        story.join(", ")
                    ));
                }
                _ => {}
            }
        }
        if let Some((_, why)) = endpoint
            .agent
            .websocket_failure(WS)
            .filter(|_| stage != Stage::Closing)
        {
            return Err(format!(
                "the stack gave the WebSocket up: {why} [{}]",
                story.join(", ")
            ));
        }
        endpoint.run_media(now);
        endpoint.timers(now);
        connection.flush(&mut endpoint)?;

        match stage {
            Stage::Registering | Stage::Calling if now > since + PATIENCE => {
                return Err(format!("stuck {stage:?} [{}]", story.join(", ")));
            }
            Stage::Listening if now >= since + LISTEN => {
                heard = call
                    .and_then(|handle| endpoint.media.get(&handle))
                    .map_or(0, |media| media.heard().audible);
                if heard < AUDIBLE_WANTED {
                    return Err(format!(
                        "only {heard} audible frames came back from the echo [{}]",
                        story.join(", ")
                    ));
                }
                if let Some(handle) = call {
                    let _ = endpoint.agent.hangup(handle, now);
                }
                stage = Stage::Ending;
                since = now;
            }
            Stage::Ending if ended => {
                let _ = endpoint.agent.unregister(account, now);
                stage = Stage::Unregistering;
                since = now;
            }
            Stage::Ending | Stage::Unregistering | Stage::Closing if now > since + ENDING => {
                return Err(format!("stuck {stage:?} [{}]", story.join(", ")));
            }
            _ => {}
        }
        if ended && matches!(stage, Stage::Calling | Stage::Listening) {
            return Err(format!(
                "the call ended part-way through [{}]",
                story.join(", ")
            ));
        }
        let arrived = connection.read(&mut endpoint, Instant::now())?;
        if !endpoint.read_sip(Instant::now()) && !arrived {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
